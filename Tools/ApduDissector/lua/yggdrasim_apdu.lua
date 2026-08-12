-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- YggdraSIM deep APDU dissector for Wireshark and tshark.
--
-- YggdraSIM mirrors every bridged APDU exchange to GSMTAP on UDP 4729
-- (Tools/HilBridge/protocol.py). Wireshark's stock gsm_sim dissector
-- decodes the command header and then hands the data field back as an
-- undecoded blob, which is where troubleshooting stops: a STORE DATA
-- carrying an ES10b request renders as a bare "e2".
--
-- This dissector binds to GSMTAP_TYPE_SIM and decodes the payload
-- properly: the ISO 7816-4 header with its class-byte breakdown and case
-- classification, the status word including the families whose SW2 is a
-- count, the risk class an instruction carries, and -- in the layers
-- built on top of this file -- BER-TLV, FCP templates, CAT/STK,
-- GlobalPlatform and the SGP.22/SGP.32 RSP surface.
--
-- Usage:
--   tshark -X lua_script:/path/to/yggdrasim_apdu.lua -r capture.pcap -V
--
-- Wireshark GUI: copy this file and the yggdrasim_apdu/ directory into
-- the personal plugin folder reported by `tshark -G folders`, or run
-- `python -m Tools.ApduDissector install`.
--
-- NOTE: Wireshark silently refuses -X lua_script: when the process runs
-- as root. If nothing below appears to load, that is why.

-- Wireshark's plugin loader walks its plugin directory recursively and
-- executes every .lua file it finds, so this file can be entered more
-- than once. Proto() raises on a duplicate name, so guard the whole
-- registration.
if _G.YGGDRASIM_APDU_LOADED == true then
    return
end
_G.YGGDRASIM_APDU_LOADED = true

-- -X lua_script: does not put the script's directory on package.path,
-- and neither does the plugin loader. debug.getinfo covers both.
local script_path = debug.getinfo(1, "S").source:sub(2)
local script_dir = script_path:match("^(.*)[/\\]") or "."
package.path = script_dir .. "/?.lua;" .. package.path

local util = require("yggdrasim_apdu.util")
local tables = require("yggdrasim_apdu.tables")
local fields = require("yggdrasim_apdu.fields")
local split = require("yggdrasim_apdu.split")
local iso7816 = require("yggdrasim_apdu.iso7816")

local yapdu = Proto("yapdu", "YggdraSIM APDU")
yapdu.fields = fields.all

-- --------------------------------------------------------------- experts
local experts = {
    too_short = ProtoExpert.new(
        "yapdu.expert.too_short",
        "Payload too short to be an APDU exchange",
        expert.group.MALFORMED,
        expert.severity.WARN
    ),
    split_failed = ProtoExpert.new(
        "yapdu.expert.split_failed",
        "Cannot tell where the command APDU ends",
        expert.group.MALFORMED,
        expert.severity.WARN
    ),
    low_confidence = ProtoExpert.new(
        "yapdu.expert.low_confidence",
        "Command/response split is a guess",
        expert.group.UNDECODED,
        expert.severity.NOTE
    ),
    ambiguous = ProtoExpert.new(
        "yapdu.expert.ambiguous",
        "More than one command/response split fits equally well",
        expert.group.UNDECODED,
        expert.severity.NOTE
    ),
    truncated = ProtoExpert.new(
        "yapdu.expert.truncated",
        "Frame is shorter than its declared length",
        expert.group.MALFORMED,
        expert.severity.WARN
    ),
    destructive = ProtoExpert.new(
        "yapdu.expert.destructive",
        "Command is irreversible on real hardware",
        expert.group.SECURITY,
        expert.severity.WARN
    ),
    status_error = ProtoExpert.new(
        "yapdu.expert.status_error",
        "Card returned an error status word",
        expert.group.RESPONSE_CODE,
        expert.severity.NOTE
    ),
    atr_checksum = ProtoExpert.new(
        "yapdu.expert.atr_checksum",
        "ATR check byte does not match",
        expert.group.CHECKSUM,
        expert.severity.WARN
    ),
}
yapdu.experts = {
    experts.too_short, experts.split_failed, experts.low_confidence,
    experts.ambiguous, experts.truncated, experts.destructive,
    experts.status_error, experts.atr_checksum,
}

-- ----------------------------------------------------------- preferences
yapdu.prefs.chain_gsm_sim = Pref.bool(
    "Also run the stock GSM SIM dissector",
    true,
    "Keep Wireshark's gsm_sim fields populated alongside this dissector. "
        .. "Binding to gsmtap.type would otherwise displace it entirely."
)
yapdu.prefs.set_info_column = Pref.bool(
    "Rewrite the Info column",
    true,
    "Summarise the exchange in the packet list."
)
yapdu.prefs.show_candidates = Pref.bool(
    "Show rejected command/response splits",
    false,
    "Add a subtree listing every split that was considered and its score."
)

-- ----------------------------------------------------------------- render
local function add_cla_subtree(tree, payload, command)
    local item = tree:add(fields.cla, payload(0, 1))
    local decoded = command.cla_decoded
    local subtree = item:add(
        fields.cla_type, payload(0, 1), decoded.proprietary and 1 or 0
    )
    subtree:set_generated()
    item:add(fields.cla_channel, payload(0, 1), decoded.channel):set_generated()
    item:add(
        fields.cla_secure_messaging, payload(0, 1), decoded.secure_messaging
    ):set_generated()
    item:add(fields.cla_chaining, payload(0, 1), decoded.chaining):set_generated()
    if decoded.channel > 0 then
        item:append_text(string.format(" (channel %d)", decoded.channel))
    end
    if decoded.secure_messaging > 0 then
        item:append_text(" (secure messaging)")
    end
end

local function add_command_subtree(tree, payload, command)
    local range = util.safe_range(payload, 0, command.length)
    local item
    if range ~= nil then
        item = tree:add(fields.command, range)
    else
        item = tree:add(fields.command, payload(0, payload:captured_len()))
    end
    item:set_text(string.format(
        "Command APDU: %s (%s)", command.name, util.plural_bytes(command.length)
    ))

    add_cla_subtree(item, payload, command)
    item:add(fields.ins, payload(1, 1))
    item:add(fields.command_name, payload(1, 1), command.name):set_generated()
    if command.source ~= "" then
        item:add(fields.command_source, payload(1, 1), command.source):set_generated()
    end
    item:add(fields.p1, payload(2, 1))
    item:add(fields.p2, payload(3, 1))
    item:add(fields.case, payload(0, 1), command.case):set_generated()
    if command.extended then
        item:add(fields.extended_length, payload(0, 1), true):set_generated()
    end

    if command.lc ~= nil then
        local lc_offset = command.extended and 5 or 4
        local lc_width = command.extended and 3 or 1
        local lc_range = util.safe_range(payload, lc_offset, lc_width)
        if lc_range ~= nil then
            item:add(fields.lc, lc_range, command.lc)
        end
    end
    if command.data_offset ~= nil and command.data_length > 0 then
        local data_range = util.safe_range(
            payload, command.data_offset, command.data_length
        )
        if data_range ~= nil then
            item:add(fields.data, data_range)
        end
    end
    if command.le ~= nil then
        item:add(fields.le, payload(0, 1), command.le):set_generated()
        if command.le_effective ~= nil then
            item:add(
                fields.le_effective, payload(0, 1), command.le_effective
            ):set_generated()
        end
    end

    local risk_item = item:add(fields.risk, payload(1, 1), command.risk):set_generated()
    item:add(fields.risk_name, payload(1, 1), command.risk_name):set_generated()
    if command.risk >= 3 then
        risk_item:add_proto_expert_info(
            experts.destructive,
            string.format("%s: %s", command.name, command.risk_name)
        )
    end
    return item
end

local function add_response_subtree(tree, payload, response)
    local range = util.safe_range(payload, response.offset, response.length)
    local item
    if range ~= nil then
        item = tree:add(fields.response, range)
    else
        item = tree:add(fields.response, payload(0, payload:captured_len()))
    end
    item:set_text(string.format(
        "Response APDU: %04X %s", response.status_word, response.meaning
    ))

    if response.data_length > 0 then
        local data_range = util.safe_range(
            payload, response.data_offset, response.data_length
        )
        if data_range ~= nil then
            item:add(fields.response_data, data_range)
        end
    end

    local sw_range = util.safe_range(payload, response.offset + response.length - 2, 2)
    if sw_range ~= nil then
        local sw_item = item:add(fields.sw, sw_range)
        -- The value string only covers fixed status words. The families
        -- whose SW2 is a count (61XX, 6CXX, 63CX) would otherwise render
        -- as "Unknown", which is exactly backwards: they are the ones
        -- carrying the most information.
        sw_item:set_text(string.format(
            "Status word: %04X - %s", response.status_word, response.meaning
        ))
        sw_item:add(fields.sw1, sw_range(0, 1))
        sw_item:add(fields.sw2, sw_range(1, 1))
        sw_item:add(fields.sw_meaning, sw_range, response.meaning):set_generated()
        sw_item:add(fields.sw_success, sw_range, response.succeeded):set_generated()
        if response.succeeded == false then
            sw_item:add_proto_expert_info(experts.status_error, response.meaning)
        end
    end
    return item
end

local function add_split_subtree(tree, payload, result)
    local item = tree:add(fields.split_command_len, payload(0, 0), result.command_length)
    item:set_generated()
    tree:add(fields.split_response_len, payload(0, 0), result.response_length)
        :set_generated()
    local confidence = tree:add(
        fields.split_confidence, payload(0, 0), result.confidence
    )
    confidence:set_generated()
    tree:add(fields.split_method, payload(0, 0), result.method):set_generated()
    if result.ambiguous then
        tree:add(fields.split_ambiguous, payload(0, 0), true):set_generated()
        confidence:add_proto_expert_info(
            experts.ambiguous,
            "Another split scored within 10 points of the chosen one"
        )
    end
    if result.low_confidence then
        confidence:add_proto_expert_info(
            experts.low_confidence,
            string.format(
                "Best split scored %d, below the confidence floor of %d",
                result.confidence, split.CONFIDENCE_FLOOR
            )
        )
    end
    if yapdu.prefs.show_candidates == true and result.alternatives ~= nil then
        local candidates = tree:add(yapdu, payload(0, 0), "Split candidates")
        candidates:set_generated()
        for index = 1, #result.alternatives do
            local candidate = result.alternatives[index]
            candidates:add(
                fields.split_candidate,
                payload(0, 0),
                string.format(
                    "case %s, command %d bytes, score %d (%s)",
                    candidate.case, candidate.command_length,
                    candidate.score, candidate.method
                )
            ):set_generated()
        end
    end
end

local function add_atr_subtree(tree, payload, atr)
    local item = tree:add(fields.atr, payload(0, payload:captured_len()))
    item:set_text(string.format(
        "Answer To Reset (%s convention, %s)",
        atr.convention, util.plural_bytes(atr.length)
    ))
    item:add(fields.atr_ts, payload(0, 1))
        :append_text(string.format(" (%s convention)", atr.convention))
    item:add(fields.atr_t0, payload(1, 1))
    item:add(fields.atr_historical_count, payload(1, 1), atr.historical_count)
        :set_generated()

    for index = 1, #atr.interface_bytes do
        local interface_byte = atr.interface_bytes[index]
        local range = util.safe_range(payload, interface_byte.offset, 1)
        if range ~= nil then
            item:add(fields.atr_interface, range)
                :append_text(string.format(" (%s)", interface_byte.name))
        end
    end
    for index = 1, #atr.protocols do
        local protocol = atr.protocols[index]
        local range = util.safe_range(payload, protocol.offset, 1)
        if range ~= nil then
            item:add(fields.atr_protocol, range, protocol.value)
                :append_text(string.format(" (T=%d)", protocol.value))
        end
    end
    if atr.historical_count > 0 then
        local range = util.safe_range(
            payload, atr.historical_offset, atr.historical_count
        )
        if range ~= nil then
            item:add(fields.atr_historical, range)
        end
    end
    if atr.tck ~= nil then
        local range = util.safe_range(payload, atr.tck_offset, 1)
        if range ~= nil then
            local tck_item = item:add(fields.atr_tck, range)
            tck_item:add(fields.atr_tck_valid, range, atr.tck_valid):set_generated()
            if atr.tck_valid == false then
                tck_item:add_proto_expert_info(
                    experts.atr_checksum,
                    "XOR over T0 through the last historical byte is non-zero"
                )
            end
        end
    end
    return item
end

-- ------------------------------------------------------------- dissection
local function dissect_atr(payload, pinfo, tree)
    local root = tree:add(yapdu, payload(0, payload:captured_len()), "YggdraSIM APDU")
    root:add(fields.frame_kind, payload(0, 0), "ATR"):set_generated()
    local atr = iso7816.parse_atr(payload)
    if atr == nil then
        root:add(fields.raw, payload(0, payload:captured_len()))
        return
    end
    add_atr_subtree(root, payload, atr)
    if yapdu.prefs.set_info_column == true then
        pinfo.cols.info:set(string.format(
            "ATR (%s convention, %s)",
            atr.convention, util.plural_bytes(atr.length)
        ))
    end
end

local function dissect_exchange(payload, pinfo, tree)
    local root = tree:add(yapdu, payload(0, payload:captured_len()), "YggdraSIM APDU")

    if payload:captured_len() < payload:reported_len() then
        root:add_proto_expert_info(
            experts.truncated,
            string.format(
                "captured %d of %d bytes; decoding what is present",
                payload:captured_len(), payload:reported_len()
            )
        )
    end

    local result = split.split(payload)
    if result.ok == false then
        root:add(fields.frame_kind, payload(0, 0), "undecoded"):set_generated()
        local chosen = experts.split_failed
        if result.reason == "too-short" then
            chosen = experts.too_short
        end
        root:add_proto_expert_info(chosen, result.detail)
        root:add(fields.raw, payload(0, payload:captured_len()))
        if yapdu.prefs.set_info_column == true then
            pinfo.cols.info:set("Undecoded APDU payload (" .. result.detail .. ")")
        end
        return
    end

    root:add(fields.frame_kind, payload(0, 0), "exchange"):set_generated()
    add_split_subtree(root, payload, result)

    local command = iso7816.parse_command(payload, result)
    local response = iso7816.parse_response(payload, result)
    if command == nil or response == nil then
        root:add_proto_expert_info(
            experts.split_failed, "header or status word unreadable"
        )
        root:add(fields.raw, payload(0, payload:captured_len()))
        return
    end

    add_command_subtree(root, payload, command)
    add_response_subtree(root, payload, response)

    root:set_text(string.format(
        "YggdraSIM APDU: %s -> %04X", command.name, response.status_word
    ))

    if yapdu.prefs.set_info_column == true then
        local summary = string.format(
            "%s %02X %02X -> %04X %s",
            command.name, command.p1, command.p2,
            response.status_word, response.meaning
        )
        pinfo.cols.info:set(util.clip(summary, 120))
    end
end

function yapdu.dissector(payload, pinfo, tree)
    if payload:captured_len() == 0 then
        return 0
    end

    -- GSMTAP carries the SIM subtype in its header, but Wireshark 4.2
    -- exposes no gsmtap.sub_type field and this dissector only receives
    -- the payload, so an ATR has to be recognised from its own bytes.
    local is_atr = split.looks_like_atr(payload)

    -- Keep the stock dissector's 242 fields populated. Registering on
    -- gsmtap.type displaces gsm_sim, and the HIL-Bridge summary command
    -- reads _ws.col.Protocol, so silently dropping it would regress the
    -- terminal decode view. Errors are contained: a stock-dissector
    -- failure must not take our tree down with it.
    --
    -- ATR frames are withheld. gsm_sim reads any payload as an APDU, so
    -- on an ATR it invents a class byte and a status word out of the
    -- historical bytes -- the "Unknown status word: 4ba9" the stock
    -- decoder reports today. Chaining it there would carry that defect
    -- forward into our tree.
    if yapdu.prefs.chain_gsm_sim == true and is_atr == false then
        local gsm_sim = Dissector.get("gsm_sim")
        if gsm_sim ~= nil then
            pcall(function()
                gsm_sim:call(payload, pinfo, tree)
            end)
        end
    end

    pinfo.cols.protocol:set("APDU")

    if is_atr then
        dissect_atr(payload, pinfo, tree)
        return payload:captured_len()
    end

    dissect_exchange(payload, pinfo, tree)
    return payload:captured_len()
end

-- ---------------------------------------------------------- registration
-- GSMTAP_TYPE_SIM is 0x04 (Tools/HilBridge/protocol.py:32). The
-- gsmtap.type table is present in Wireshark 4.2 and receives the payload
-- with the GSMTAP header already stripped; see
-- Tools/ApduDissector/WIRESHARK_ENVIRONMENT.md for the measurements.
local registered = false
local table_ok, gsmtap_types = pcall(DissectorTable.get, "gsmtap.type")
if table_ok and gsmtap_types ~= nil then
    gsmtap_types:add(0x04, yapdu)
    registered = true
end

if registered == false then
    -- Older builds without a gsmtap.type table: claim UDP 4729 and let
    -- the stock GSMTAP dissector run first so its header fields survive.
    local udp_port = DissectorTable.get("udp.port")
    if udp_port ~= nil then
        udp_port:add(4729, yapdu)
    end
end
