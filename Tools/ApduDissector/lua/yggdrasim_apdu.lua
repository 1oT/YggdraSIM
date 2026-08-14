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
local tlv = require("yggdrasim_apdu.tlv")
local commands = require("yggdrasim_apdu.commands")
local responses = require("yggdrasim_apdu.responses")
local state = require("yggdrasim_apdu.state")
local gp = require("yggdrasim_apdu.gp")
local cat = require("yggdrasim_apdu.cat")
local rsp = require("yggdrasim_apdu.rsp")
local sm = require("yggdrasim_apdu.sm")

local yapdu = Proto("yapdu", "YggdraSIM APDU")
yapdu.fields = fields.all

--- Cross-frame context. Rebuilt on every dissection run; see state.lua.
local machine = state.new()

--- Whether the frame being rendered is the one advancing the machine,
--- and which frame that is. Set once per frame in dissect_exchange and
--- read by the CAT renderer, which learns BIP channel state deep inside
--- the tree walk and must obey the same rule the rest of the module
--- does: a re-rendered frame observes, it does not mutate.
local frame_advancing = false
local frame_number = 0

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
    sidecar_mismatch = ProtoExpert.new(
        "yapdu.expert.sidecar_mismatch",
        "Sidecar entry does not match this frame",
        expert.group.MALFORMED,
        expert.severity.WARN
    ),
    tls_alert = ProtoExpert.new(
        "yapdu.expert.tls_alert",
        "Fatal TLS alert on a BIP channel",
        expert.group.RESPONSE_CODE,
        expert.severity.WARN
    ),
    bip_failure = ProtoExpert.new(
        "yapdu.expert.bip_failure",
        "Bearer Independent Protocol channel failure",
        expert.group.RESPONSE_CODE,
        expert.severity.WARN
    ),
    reserved_class = ProtoExpert.new(
        "yapdu.expert.reserved_class",
        "Class byte is reserved by ISO/IEC 7816-4",
        expert.group.MALFORMED,
        expert.severity.WARN
    ),
    status_warning = ProtoExpert.new(
        "yapdu.expert.status_warning",
        "Card returned a warning status word",
        expert.group.RESPONSE_CODE,
        expert.severity.NOTE
    ),
    tlv_malformed = ProtoExpert.new(
        "yapdu.expert.tlv_malformed",
        "TLV structure is malformed",
        expert.group.MALFORMED,
        expert.severity.WARN
    ),
    budget = ProtoExpert.new(
        "yapdu.expert.budget_exhausted",
        "Tree node budget exhausted; remainder shown as raw bytes",
        expert.group.UNDECODED,
        expert.severity.NOTE
    ),
    no_context = ProtoExpert.new(
        "yapdu.expert.no_context",
        "Decoded without cross-frame context",
        expert.group.UNDECODED,
        expert.severity.CHAT
    ),
}
yapdu.experts = {
    experts.too_short, experts.split_failed, experts.low_confidence,
    experts.ambiguous, experts.truncated, experts.destructive,
    experts.status_error, experts.atr_checksum, experts.tlv_malformed,
    experts.budget, experts.no_context, experts.sidecar_mismatch,
    experts.tls_alert, experts.bip_failure, experts.reserved_class,
    experts.status_warning,
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
yapdu.prefs.sidecar_path = Pref.string(
    "SCP plaintext sidecar",
    "",
    "Path to a yggdrasim-apdu-sidecar/v1 file produced by "
        .. "`yggdrasim-apdu-dissect sidecar`. Wireshark's Lua has no AES, "
        .. "so decryption happens in Python and the result is read here. "
        .. "Falls back to the YGGDRASIM_APDU_SIDECAR environment variable."
)
yapdu.prefs.show_candidates = Pref.bool(
    "Show rejected command/response splits",
    false,
    "Add a subtree listing every split that was considered and its score."
)

-- ------------------------------------------------------------ TLV render
--- Render one parsed TLV node and its children.
local function add_tlv_node(tree, payload, node, options)
    local total = node.tag_length + node.length_length + node.value_length
    local range = util.safe_range(payload, node.tag_offset, total)
    if range == nil then
        range = util.safe_range(payload, node.tag_offset, 1)
    end
    if range == nil then
        return
    end

    local label
    if node.name ~= "" then
        label = string.format("%s (0x%X)", node.name, node.base_tag)
    else
        label = string.format("Tag 0x%X", node.base_tag)
    end
    if node.constructed then
        label = label .. string.format(", %s", util.plural_bytes(node.value_length))
    end

    local item = tree:add(fields.tlv, range)
    item:set_text(label)
    item:add(fields.tlv_tag, util.safe_range(payload, node.tag_offset, node.tag_length))
    if node.base_tag ~= node.tag then
        item:add(fields.tlv_base_tag, range, node.base_tag):set_generated()
    end
    if node.name ~= "" then
        item:add(fields.tlv_name, range, node.name):set_generated()
    end
    -- COMPREHENSION-TLV has neither a class nor a constructed bit, so
    -- both are nil there. Adding a nil to a uint8 ProtoField raises, and
    -- the pcall around dissection would swallow the traceback and leave
    -- the subtree silently truncated at the first tag.
    if node.class ~= nil then
        item:add(fields.tlv_class, range, node.class):set_generated()
    end
    if node.constructed ~= nil then
        item:add(fields.tlv_constructed, range, node.constructed):set_generated()
    end
    if node.comprehension_required ~= nil then
        item:add(
            fields.tlv_comprehension, range, node.comprehension_required
        ):set_generated()
    end
    item:add(
        fields.tlv_length,
        util.safe_range(payload, node.length_offset, node.length_length),
        node.length
    )
    if node.indefinite then
        item:add(fields.tlv_indefinite, range, true):set_generated()
    end
    if node.clamped then
        item:add_proto_expert_info(
            experts.tlv_malformed,
            string.format(
                "declared length runs past the end of the value; showing %s",
                util.plural_bytes(node.value_length)
            )
        )
    end

    -- Layer-specific detail hangs off the node it describes rather than
    -- being appended as a parallel block, so the tree reads as one
    -- structure instead of the same bytes twice.
    if options ~= nil and options.enrich ~= nil then
        options.enrich(item, node, payload)
    end

    if node.children ~= nil and #node.children > 0 then
        for index = 1, #node.children do
            add_tlv_node(item, payload, node.children[index], options)
        end
        return item
    end

    if node.value_length > 0 then
        local value_range = util.safe_range(
            payload, node.value_offset, node.value_length
        )
        if value_range ~= nil then
            item:add(fields.tlv_value, value_range)
            -- A short primitive value is very often a small integer, and
            -- reading it as one saves an operator converting hex by eye.
            if node.value_length <= 4 then
                local numeric = util.safe_uint(
                    payload, node.value_offset, node.value_length
                )
                if numeric ~= nil then
                    item:add(fields.tlv_uint, value_range, numeric):set_generated()
                end
            end
        end
    end
    return item
end

--- Parse and render a TLV run, returning the parsed nodes.
local function add_tlv_subtree(tree, payload, offset, length, options, budget)
    if length <= 0 then
        return nil
    end
    if not tlv.looks_like_tlv(payload, offset, length) then
        return nil
    end
    local nodes, errors = tlv.parse(payload, offset, length, options, budget, 0)
    if nodes == nil or #nodes == 0 then
        return nil
    end
    for index = 1, #nodes do
        add_tlv_node(tree, payload, nodes[index], options)
    end
    for index = 1, #errors do
        local error_entry = errors[index]
        local range = util.safe_range(payload, error_entry.offset, 1)
        if range ~= nil then
            if error_entry.reason == "tree node budget exhausted" then
                tree:add_proto_expert_info(experts.budget, error_entry.reason)
            else
                tree:add_proto_expert_info(experts.tlv_malformed, error_entry.reason)
            end
        end
    end
    return nodes
end

-- ----------------------------------------------------------------- render
local function add_cla_subtree(tree, payload, command)
    local item = tree:add(fields.cla, payload(0, 1))
    local decoded = command.cla_decoded
    local subtree = item:add(
        fields.cla_type, payload(0, 1), decoded.proprietary and 1 or 0
    )
    subtree:set_generated()
    if decoded.invalid then
        item:append_text(" (invalid)")
        item:add_proto_expert_info(
            experts.reserved_class,
            "CLA 'FF' is reserved by ISO/IEC 7816-4 and is not a valid class"
        )
        return
    end
    if decoded.channel == nil or decoded.secure_messaging == nil then
        -- ISO/IEC 7816-4 clause 5.4.1 assigns no meaning to bits 6 to 1
        -- of a proprietary or reserved class byte, so there is no
        -- channel, no secure-messaging level and no chaining flag to
        -- report. Rendering them anyway states three facts per command
        -- that the specification does not.
        item:append_text(decoded.reserved and " (reserved)" or " (proprietary)")
        return
    end
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

--- Render the instruction-specific reading of P1, P2 and the body.
local function add_command_description(tree, payload, command, description)
    if description.kind == "select" then
        tree:add(fields.select_control, payload(2, 1), command.p1)
            :append_text(" (" .. description.control .. ")")
        tree:add(fields.select_return, payload(3, 1), command.p2)
            :append_text(" (" .. description.return_control .. ")")
        if description.occurrence_name ~= nil then
            -- Enumerating the ISD-Ps that share an AID prefix is done
            -- entirely with "next occurrence", so dropping this loses
            -- the point of the exchange.
            tree:add(
                fields.select_occurrence, payload(3, 1),
                description.occurrence_name
            ):set_generated()
        end
        if description.session_control ~= nil then
            tree:add(
                fields.select_session, payload(3, 1), description.session_control
            ):set_generated()
        end
        if description.reserved_bits_set then
            tree:add_proto_expert_info(
                experts.reserved_class,
                "ETSI TS 102 221 Table 11.2 requires SELECT P2 bits 8 and 5 "
                    .. "to be zero"
            )
        end
        if description.secure_messaged then
            tree:add_proto_expert_info(
                experts.no_context,
                "the command body is secure-messaged, so the selected file "
                    .. "cannot be read from it"
            )
        end
        if description.path_incomplete then
            tree:add_proto_expert_info(
                experts.tlv_malformed,
                "the path body is not a whole number of file identifiers"
            )
        end
        if description.aid_hex ~= nil then
            local range = util.safe_range(
                payload, description.aid_offset, description.aid_length
            )
            if range ~= nil then
                tree:add(fields.select_aid, range)
            end
        elseif description.fid ~= nil then
            local range = util.safe_range(payload, command.data_offset, 2)
            if range ~= nil then
                tree:add(fields.select_fid, range)
            end
        end
        if description.target ~= nil then
            tree:add(fields.select_name, payload(2, 1), description.target)
                :set_generated()
        end
        return
    end

    if description.kind == "binary" then
        tree:add(fields.binary_offset, payload(2, 2), description.offset)
            :set_generated()
        if description.sfi_addressed then
            tree:add(fields.binary_sfi, payload(2, 1), description.sfi)
                :set_generated()
        end
        return
    end

    if description.kind == "record" then
        tree:add(fields.record_number, payload(2, 1), description.record)
        tree:add(fields.record_sfi, payload(3, 1), description.sfi):set_generated()
        tree:add(fields.record_mode, payload(3, 1), description.mode)
            :append_text(" (" .. description.mode_name .. ")")
        return
    end

    if description.kind == "pin" then
        tree:add(fields.pin_reference, payload(3, 1))
            :append_text(" (" .. description.reference_name .. ")")
        tree:add(fields.pin_name, payload(3, 1), description.reference_name)
            :set_generated()
        -- The PIN block itself is deliberately reported by length only.
        -- A capture that contains plaintext PINs should not print them
        -- to anyone who opens the file.
        if description.value_length > 0 then
            tree:add(
                fields.pin_value_len, payload(3, 1), description.value_length
            ):set_generated()
        end
        return
    end

    if description.kind == "channel" then
        tree:add(fields.channel_operation, payload(2, 1), description.operation)
            :set_generated()
        tree:add(fields.channel_number, payload(3, 1), description.channel)
        return
    end

    if description.kind == "data_object" then
        tree:add(fields.data_object_tag, payload(2, 2), description.tag)
            :set_generated()
        if description.name ~= "" then
            tree:add(fields.data_object_name, payload(2, 2), description.name)
                :set_generated()
        end
        return
    end
end

--- Render a DGI-format STORE DATA body.
--
-- GlobalPlatform Amendment A: a two-byte data grouping identifier, then
-- a one-byte length, then the value; a length of 'FF' escapes to a
-- two-byte length. Nothing about it is BER, so the generic walker turns
-- each identifier into an invented tag and reads the length out of the
-- wrong byte.
local function add_dgi_subtree(tree, payload, offset, length)
    local cursor = offset
    local limit = offset + length
    while cursor + 3 <= limit do
        local identifier = util.safe_uint(payload, cursor, 2)
        local first = util.byte_at(payload, cursor + 2)
        if identifier == nil or first == nil then
            return
        end
        local value_offset = cursor + 3
        local value_length = first
        if first == 0xFF then
            value_length = util.safe_uint(payload, cursor + 3, 2)
            if value_length == nil then
                return
            end
            value_offset = cursor + 5
        end
        if value_offset + value_length > limit then
            tree:add_proto_expert_info(
                experts.tlv_malformed,
                string.format(
                    "DGI %04X declares %s, which runs past the command data",
                    identifier, util.plural_bytes(value_length)
                )
            )
            return
        end
        local range = util.safe_range(payload, cursor, value_offset + value_length - cursor)
        if range == nil then
            return
        end
        local item = tree:add(fields.gp_dgi, range)
        item:set_text(string.format(
            "DGI %04X, %s", identifier, util.plural_bytes(value_length)
        ))
        if value_length > 0 then
            local value_range = util.safe_range(payload, value_offset, value_length)
            if value_range ~= nil then
                item:add(fields.gp_dgi_value, value_range)
            end
        end
        cursor = value_offset + value_length
    end
end

--- Render a GlobalPlatform command's positional and bitmap fields.
local function add_gp_description(tree, payload, command, gp_description)
    tree:add(
        fields.gp_variant, payload(1, 1), gp_description.variant
            or gp_description.kind
    ):set_generated()

    if gp_description.kind == "install" and gp_description.install ~= nil then
        local parsed = gp_description.install
        for index = 1, #parsed.fields do
            local entry = parsed.fields[index]
            local range = util.safe_range(payload, entry.offset, entry.length)
            if range ~= nil then
                local field = fields.gp_field
                if entry.name == "Privileges" then
                    field = fields.gp_privileges
                elseif entry.name:find("AID") ~= nil then
                    field = fields.gp_aid
                end
                local item = tree:add(field, range)
                item:set_text(string.format(
                    "%s: %s", entry.name,
                    util.hex(payload, entry.offset, entry.length)
                ))
                if field == fields.gp_aid and entry.length > 0 then
                    local name = commands.aid_name(
                        util.hex(payload, entry.offset, entry.length)
                    )
                    if name ~= "" then
                        item:append_text(" (" .. name .. ")")
                    end
                end
            end
        end
        if gp_description.more_blocks then
            -- GlobalPlatform clause 11.5.2.1 bit 8: the parameters are
            -- continued in the next INSTALL, so a short or unbalanced
            -- positional parse here is expected rather than malformed.
            tree:add(fields.gp_last_block, payload(2, 1), false):set_generated()
        end
        if parsed.complete == false and not gp_description.more_blocks then
            tree:add_proto_expert_info(
                experts.tlv_malformed,
                "the INSTALL data field did not consume exactly; the "
                    .. "positional parse may have lost alignment"
            )
        end
        return
    end

    if gp_description.kind == "load" or gp_description.kind == "store_data" then
        tree:add(fields.gp_block_number, payload(3, 1), gp_description.block_number)
            :set_generated()
        tree:add(fields.gp_last_block, payload(2, 1), gp_description.last_block)
            :set_generated()
        if gp_description.structure ~= nil then
            tree:add(fields.gp_structure, payload(2, 1), gp_description.structure)
                :set_generated()
            tree:add(fields.gp_encryption, payload(2, 1), gp_description.encryption)
                :set_generated()
        end
        return
    end

    if gp_description.kind == "status" then
        tree:add(fields.gp_scope, payload(2, 1), gp_description.scope):set_generated()
        return
    end

    if gp_description.kind == "set_status" then
        tree:add(fields.gp_scope, payload(2, 1), gp_description.scope):set_generated()
        tree:add(fields.gp_lifecycle, payload(3, 1), gp_description.new_state_name)
            :set_generated()
        return
    end

    if gp_description.kind == "external_authenticate" then
        tree:add(fields.gp_security_level, payload(2, 1), gp_description.level)
            :set_generated()
        if command.data_offset ~= nil and command.data_length >= 8 then
            local range = util.safe_range(payload, command.data_offset, 8)
            if range ~= nil then
                tree:add(fields.gp_host_challenge, range)
            end
        end
        return
    end

    if gp_description.kind == "initialize_update" then
        tree:add(fields.gp_key_version, payload(2, 1), gp_description.key_version)
            :set_generated()
        if command.data_offset ~= nil and command.data_length >= 8 then
            local range = util.safe_range(payload, command.data_offset, 8)
            if range ~= nil then
                tree:add(fields.gp_host_challenge, range)
            end
        end
        return
    end

    if gp_description.kind == "put_key" then
        tree:add(fields.gp_key_version, payload(2, 1), gp_description.key_version)
            :set_generated()
        tree:add(
            fields.gp_key_identifier, payload(3, 1), gp_description.key_identifier
        ):set_generated()
        return
    end
end

--- Render the INITIALIZE UPDATE response, which sets up the secure channel.
local function add_initialize_update_response(tree, payload, response)
    local parsed = gp.parse_initialize_update_response(
        payload, response.data_offset, response.data_length
    )
    if parsed == nil then
        return false
    end
    local diversification = util.safe_range(
        payload, parsed.key_diversification_offset, 10
    )
    if diversification ~= nil then
        tree:add(fields.gp_key_diversification, diversification)
    end
    tree:add(fields.gp_scp, payload(0, 1), parsed.scp_name):set_generated()
    if parsed.key_version ~= nil then
        tree:add(fields.gp_key_version, payload(0, 1), parsed.key_version)
            :set_generated()
    end
    if parsed.card_challenge_offset ~= nil then
        local range = util.safe_range(
            payload, parsed.card_challenge_offset, parsed.card_challenge_length
        )
        if range ~= nil then
            tree:add(fields.gp_card_challenge, range)
        end
    end
    if parsed.card_cryptogram_offset ~= nil then
        local range = util.safe_range(
            payload, parsed.card_cryptogram_offset, parsed.card_cryptogram_length
        )
        if range ~= nil then
            tree:add(fields.gp_card_cryptogram, range)
        end
    end
    if parsed.sequence_counter_offset ~= nil then
        local range = util.safe_range(
            payload, parsed.sequence_counter_offset, parsed.sequence_counter_length
        )
        if range ~= nil then
            tree:add(fields.gp_sequence_counter, range)
        end
    end
    return true
end

--- Hand BIP channel data to the dissector that understands it.
--
-- This is where a failed profile download becomes readable. The bytes a
-- terminal sends and receives over a BIP channel are ordinary DNS, TLS
-- or HTTP, and Wireshark already dissects all three -- but nothing hands
-- them over, so both the stock etsi_cat dissector and this one stop at
-- "Channel data: 1503030002022a". Handed to the TLS dissector, the same
-- bytes read as "Alert (Level: Fatal, Description: Bad Certificate)".
local function add_channel_payload(tree, values, range, channel_id, port, pinfo)
    if tree == nil or values == nil or range == nil or #values == 0 then
        return
    end

    local effective_port = port
    local transport = nil
    local opened = state.bip_channel(
        machine, channel_id, frame_number, frame_advancing
    )
    if opened ~= nil then
        if effective_port == nil then
            effective_port = opened.port
        end
        transport = opened.transport
    end

    -- A TLS record split across several channel-data blocks gives the
    -- stock dissector nothing complete to work with, so the header and
    -- any alert are reported here before the handoff is attempted.
    local record = cat.peek_tls_record(values)
    if record ~= nil then
        tree:add(fields.tls_content_type, range, record.content_type_name)
            :set_generated()
        if record.alert_description ~= nil then
            tree:add(fields.tls_alert_level, range, record.alert_level_name)
                :set_generated()
            local alert = tree:add(
                fields.tls_alert, range,
                string.format(
                    "%s (%d)",
                    record.alert_description_name, record.alert_description
                )
            )
            alert:set_generated()
            if record.alert_level == 2 then
                alert:add_proto_expert_info(
                    experts.tls_alert,
                    string.format(
                        "fatal TLS alert %d (%s) on the BIP channel",
                        record.alert_description, record.alert_description_name
                    )
                )
            end
        end
        if record.handshake_type_name ~= nil then
            tree:add(
                fields.tls_handshake_type, range, record.handshake_type_name
            ):set_generated()
        end
        if record.alert_encrypted then
            -- Saying nothing here is the honest answer: the alert code
            -- is inside the ciphertext. Under TLS 1.3 that is every
            -- post-handshake alert, so an operator who does not see a
            -- named alert should not conclude there was none.
            tree:add(fields.tls_alert_encrypted, range, true):set_generated()
        end
        if record.complete == false then
            tree:add(fields.tls_incomplete, range, true):set_generated()
        end
    end

    local wanted, skip = cat.channel_payload_dissector(values, effective_port, transport)
    if wanted == "" then
        return
    end
    tree:add(fields.cat_payload_protocol, range, wanted):set_generated()

    -- Only hand over a complete unit. A partial TLS record makes the
    -- stock dissector report a malformed packet, which is worse than the
    -- header this function already rendered.
    if wanted == "tls" and record ~= nil and record.complete == false then
        return
    end

    -- A DNS-over-TCP payload is handed over past its two-byte length
    -- prefix; skip is 0 for everything else.
    local handoff = range
    if skip ~= nil and skip > 0 then
        if range:len() <= skip then
            return
        end
        handoff = range:range(skip)
    end

    -- Dissector.get is inside the pcall, not before it. Wireshark 4.0
    -- returns nil for an unknown name, but 3.4 -- the stated floor
    -- version -- raises instead, and a raise here would abort the frame
    -- rather than fall back to the raw bytes. A sub-dissector that
    -- raises must not take our tree down with it either.
    pcall(function()
        local handler = Dissector.get(wanted)
        if handler == nil then
            return
        end
        handler:call(handoff:tvb("BIP channel data"), pinfo, tree)
    end)
end

--- Render a CAT proactive command or terminal response.
--
-- The outer 0xD0 Proactive Command tag is plain BER; only its contents
-- are COMPREHENSION-TLV. Parsing the wrapper in comprehension mode would
-- strip its high bit and rename it from "Proactive command" to whatever
-- 0x50 happens to mean, so the wrapper is stepped over first.
local function add_cat_subtree(tree, payload, offset, length, budget, pinfo)
    local content_offset = offset
    local content_length = length
    local envelope_name = nil

    -- 'D0' wraps a proactive command; 'D1' to 'DF' wrap an ENVELOPE body
    -- (ETSI TS 102 223 clause 7.5). Both are plain BER around a
    -- COMPREHENSION-TLV run, so both have to be stepped over first. An
    -- ENVELOPE left unwrapped renders as one opaque node -- which hides
    -- Event download entirely, and Event download is how the terminal
    -- reports that data arrived or that the link went away.
    --
    -- The wrapper byte is matched directly rather than through
    -- tlv.read_tag. ETSI TS 101 220 clause 7.2 allocates these as
    -- single-byte tags, but 'DF' -- ProSe report -- has its low five
    -- bits all set, which is exactly BER's multi-byte tag introducer. A
    -- conforming BER read therefore swallows the length byte into the
    -- tag, the wrapper is never recognised, and the whole envelope
    -- disappears from the tree. 'DF' is the only CAT wrapper that
    -- collides this way, which is what makes it easy to miss.
    local wrapper_value = util.byte_at(payload, offset)
    if wrapper_value ~= nil
        and (wrapper_value == cat.PROACTIVE_COMMAND_TAG
            or cat.is_envelope_tag(wrapper_value)) then
        local wrapper_length = tlv.read_length(payload, offset + 1)
        if wrapper_length ~= nil and wrapper_length.value ~= nil then
            content_offset = offset + 1 + wrapper_length.length
            content_length = wrapper_length.value
            local available = payload:captured_len() - content_offset
            if content_length > available then
                content_length = math.max(0, available)
            end
            local range = util.safe_range(payload, offset, length)
            if range ~= nil then
                tree = tree:add(fields.cat_command, range)
                if wrapper_value == cat.PROACTIVE_COMMAND_TAG then
                    tree:set_text("Proactive command (D0)")
                else
                    envelope_name = cat.envelope_name(wrapper_value)
                    tree:set_text(string.format(
                        "ENVELOPE: %s (%02X)", envelope_name, wrapper_value
                    ))
                    tree:add(
                        fields.cat_envelope, range, envelope_name
                    ):set_generated()
                end
            end
        end
    end

    local nodes = add_tlv_subtree(
        tree, payload, content_offset, content_length, cat.tlv_options(), budget
    )
    if nodes == nil then
        return nil
    end
    offset = content_offset
    -- Pull the command type out of the Command Details TLV so the info
    -- column can name what the card asked the terminal to do.
    local function find_details(node_list)
        for index = 1, #node_list do
            local node = node_list[index]
            if node.base_tag == cat.TAG_COMMAND_DETAILS and node.value_length >= 3 then
                return {
                    number = util.byte_at(payload, node.value_offset),
                    command_type = util.byte_at(payload, node.value_offset + 1),
                    qualifier = util.byte_at(payload, node.value_offset + 2),
                }
            end
            if node.children ~= nil then
                local found = find_details(node.children)
                if found ~= nil then
                    return found
                end
            end
        end
        return nil
    end
    local details = find_details(nodes)
    if details == nil and envelope_name == nil then
        return nil
    end

    -- An ENVELOPE carries no Command Details: the wrapper tag is what
    -- names it. The command-type fields are simply absent there rather
    -- than filled with a placeholder.
    local name = envelope_name or ""
    local command_type = nil
    if details ~= nil and details.command_type ~= nil then
        command_type = details.command_type
        name = cat.command_name(command_type)
        tree:add(fields.cat_type, payload(offset, 1), command_type)
            :set_generated()
        tree:add(fields.cat_type_name, payload(offset, 1), name):set_generated()
        tree:add(fields.cat_number, payload(offset, 1), details.number or 0)
            :set_generated()
        tree:add(
            fields.cat_qualifier_name, payload(offset, 1),
            cat.qualifier_name(command_type, details.qualifier or 0)
        ):set_generated()
    end

    -- Bearer Independent Protocol parameters. These are what an eUICC
    -- profile download actually runs over, so naming the bearer, the
    -- access point and the peer address is most of what a BIP trace is
    -- consulted for.
    local port = nil
    local transport_kind = nil
    local channel_payload = nil
    local channel_payload_offset = nil
    local channel_payload_range = nil
    local channel_data_item = nil
    local channel_id = nil
    local status_channel = nil

    -- OPEN CHANNEL may carry two Other address TLVs -- the local address
    -- first, then the data destination -- or just the destination, since
    -- the local one is optional and usually left to the terminal. The
    -- count decides which reading applies, so it is taken before the
    -- walk rather than guessed at during it.
    local address_seen = 0
    local address_total = 0
    for index = 1, #nodes do
        if nodes[index].base_tag == cat.TAG_OTHER_ADDRESS then
            address_total = address_total + 1
        end
    end

    for index = 1, #nodes do
        local node = nodes[index]
        local range = util.safe_range(payload, node.value_offset, node.value_length)
        if range ~= nil then
            if node.base_tag == cat.TAG_DEVICE_IDENTITIES and node.value_length >= 2 then
                -- Byte 1 is the source and byte 2 the destination. The
                -- direction of a proactive command is not incidental
                -- detail: it is how an operator tells a card asking the
                -- terminal to do something from a terminal reporting
                -- back, and until now it was parsed and dropped.
                local source = util.byte_at(payload, node.value_offset)
                local destination = util.byte_at(payload, node.value_offset + 1)
                if source ~= nil then
                    tree:add(fields.cat_source, range, cat.device_name(source))
                        :set_generated()
                end
                if destination ~= nil then
                    tree:add(
                        fields.cat_destination, range,
                        cat.device_name(destination)
                    ):set_generated()
                end
                -- A BIP command addresses its channel through the
                -- device identity: 0x21 to 0x27 are channels 1 to 7.
                for byte_index = 0, node.value_length - 1 do
                    local found = cat.device_channel(
                        util.byte_at(payload, node.value_offset + byte_index)
                    )
                    if found ~= nil then
                        channel_id = found
                    end
                end
            elseif node.base_tag == cat.TAG_BEARER_DESCRIPTION and node.value_length >= 1 then
                local bearer = util.byte_at(payload, node.value_offset)
                tree:add(fields.cat_bearer, range, cat.bearer_name(bearer))
                    :set_generated()
            elseif node.base_tag == cat.TAG_BUFFER_SIZE and node.value_length == 2 then
                local size = util.safe_uint(payload, node.value_offset, 2)
                if size ~= nil then
                    tree:add(fields.cat_buffer_size, range, size)
                end
            elseif node.base_tag == cat.TAG_NETWORK_ACCESS_NAME then
                local values = util.byte_array(
                    payload, node.value_offset, node.value_length
                )
                local apn = cat.decode_access_name(values)
                if apn ~= "" then
                    tree:add(fields.cat_apn, range, apn):set_generated()
                end
            elseif node.base_tag == cat.TAG_OTHER_ADDRESS then
                -- OPEN CHANNEL carries two of these: the local address
                -- first, then the data destination. Rendering both under
                -- one field name leaves "0.0.0.0,192.0.2.53" with nothing
                -- saying which end is which.
                address_seen = address_seen + 1
                local values = util.byte_array(
                    payload, node.value_offset, node.value_length
                )
                local address = cat.decode_other_address(values)
                if address == "" then
                    address = "not specified (dynamic address requested)"
                end
                local role = "data destination address"
                if address_total >= 2 and address_seen == 1 then
                    role = "local address"
                end
                tree:add(
                    fields.cat_address, range,
                    string.format("%s: %s", role, address)
                ):set_generated()
                -- The typed peer carries the raw bytes, one past the
                -- type octet, so Wireshark reads and filters it as a
                -- real address. Clause 8.58: '21' is a 4-byte IPv4,
                -- '57' a 16-byte IPv6.
                if values ~= nil and values[1] == 0x21 and #values >= 5 then
                    local ipv4 = util.safe_range(payload, node.value_offset + 1, 4)
                    if ipv4 ~= nil then
                        tree:add(fields.cat_address_ipv4, ipv4)
                    end
                elseif values ~= nil and values[1] == 0x57 and #values >= 17 then
                    local ipv6 = util.safe_range(payload, node.value_offset + 1, 16)
                    if ipv6 ~= nil then
                        tree:add(fields.cat_address_ipv6, ipv6)
                    end
                end
            elseif node.base_tag == cat.TAG_TRANSPORT_LEVEL and node.value_length >= 1 then
                local kind = util.byte_at(payload, node.value_offset)
                tree:add(fields.cat_transport, range, cat.transport_name(kind))
                    :set_generated()
                if kind == 0x02 or kind == 0x03 or kind == 0x05 then
                    transport_kind = "tcp"
                elseif kind == 0x01 or kind == 0x04 then
                    transport_kind = "udp"
                end
                if node.value_length >= 3 then
                    port = util.safe_uint(payload, node.value_offset + 1, 2)
                    if port ~= nil then
                        tree:add(fields.cat_port, range, port)
                    end
                end
            elseif node.base_tag == cat.TAG_CHANNEL_STATUS and node.value_length >= 1 then
                local status = cat.parse_channel_status(
                    util.byte_array(payload, node.value_offset, node.value_length)
                )
                if status ~= nil then
                    -- A GET CHANNEL STATUS response carries one Channel
                    -- status object per open channel (ETSI TS 102 223
                    -- clause 6.6.31), so this branch runs several times
                    -- in one frame. Keeping the first means a later
                    -- entry cannot overwrite the identifier the pending
                    -- OPEN CHANNEL is about to be bound to.
                    if status_channel == nil then
                        status_channel = status.identifier
                    end
                    tree:add(
                        fields.cat_channel, range, status.identifier
                    ):set_generated()
                    tree:add(
                        fields.cat_channel_established, range, status.established
                    ):set_generated()
                    if status.further_info_name ~= nil then
                        tree:add(
                            fields.cat_channel_info, range,
                            status.further_info_name
                        ):set_generated()
                    end
                    if status.link_dropped then
                        tree:add_proto_expert_info(
                            experts.bip_failure,
                            string.format(
                                "BIP channel %d reports the link dropped",
                                status.identifier
                            )
                        )
                    elseif status.no_channel then
                        tree:add_proto_expert_info(
                            experts.bip_failure, "no BIP channel available"
                        )
                    end
                end
            elseif node.base_tag == cat.TAG_CHANNEL_DATA_LENGTH
                and node.value_length >= 1 then
                local waiting = util.byte_at(payload, node.value_offset)
                if waiting ~= nil then
                    -- Clause 8.55 gives 'FF' the meaning "at least 255",
                    -- not "exactly 255".
                    tree:add(fields.cat_channel_data_length, range, waiting)
                        :set_generated()
                end
            elseif node.base_tag == cat.TAG_CHANNEL_DATA and node.value_length > 0 then
                channel_payload = util.byte_array(
                    payload, node.value_offset, node.value_length
                )
                channel_payload_offset = node.value_offset
                channel_payload_range = range
                channel_data_item = tree:add(fields.cat_channel_data, range)
            elseif node.base_tag == cat.TAG_RESULT and node.value_length >= 1 then
                local result = util.byte_at(payload, node.value_offset)
                tree:add(fields.cat_result, range, result)
                tree:add(fields.cat_result_name, range, cat.result_name(result))
                    :set_generated()
                -- The second byte is where a BIP failure says what
                -- actually went wrong. Without it every one of the
                -- thirteen causes reads as "bearer independent protocol
                -- error", which names the layer and nothing else.
                local cause = nil
                if node.value_length >= 2 then
                    cause = util.byte_at(payload, node.value_offset + 1)
                end
                local cause_name = cat.result_additional_info(result, cause)
                if cause_name ~= "" then
                    tree:add(fields.cat_result_cause, range, cause_name)
                        :set_generated()
                end
                if result == 0x3A then
                    tree:add_proto_expert_info(
                        experts.bip_failure,
                        string.format(
                            "BIP error: %s",
                            cause_name ~= "" and cause_name or "no cause given"
                        )
                    )
                end
            elseif node.base_tag == cat.TAG_EVENT_LIST then
                for byte_index = 0, node.value_length - 1 do
                    local event = util.byte_at(payload, node.value_offset + byte_index)
                    if event ~= nil then
                        tree:add(
                            fields.cat_event_name, range, cat.event_name(event)
                        ):set_generated()
                    end
                end
            end
        end
    end

    -- Remember what OPEN CHANNEL negotiated. SEND DATA and RECEIVE DATA
    -- carry no transport information of their own, so without this the
    -- channel payload has to be identified by content alone -- which is
    -- enough for TLS and HTTP and not enough for DNS.
    --
    -- Only an advancing frame may write. Rule 1 in state.lua exists
    -- because Wireshark re-dissects out of order, and a "-Y
    -- frame.number==N" detail query would otherwise learn a port from a
    -- frame it never saw.
    if frame_advancing then
        -- Only the TERMINAL RESPONSE to an OPEN CHANNEL allocates the
        -- channel the pending port belongs to. A Channel status TLV also
        -- rides in a GET CHANNEL STATUS response and in an Event
        -- download envelope, and binding on those consumed the pending
        -- OPEN CHANNEL against an unrelated channel -- silently moving
        -- one channel's port onto another, and leaving the real one
        -- with no port at all.
        if command_type == 0x40
            and status_channel ~= nil and status_channel ~= 0 then
            state.bind_bip_channel(machine, status_channel)
        end
        -- The command asks; the terminal's response allocates. The
        -- identifier arrives later, with the Channel status TLV, so the
        -- port is latched here and bound then. The port guard matters:
        -- the TERMINAL RESPONSE echoes command type '40' without a
        -- transport-level TLV, and latching that would replace a real
        -- port with nothing.
        if command_type == 0x40 and port ~= nil then
            state.open_bip_channel(machine, port, transport_kind)
            if channel_id ~= nil then
                -- Some cards name the channel in the OPEN CHANNEL's own
                -- device identities rather than waiting for the
                -- terminal to allocate one. Binding here as well means
                -- the port is learned from whichever form the trace
                -- actually uses.
                state.bind_bip_channel(machine, channel_id)
            end
        end
        if command_type == 0x41 and channel_id ~= nil then
            state.close_bip_channel(machine, channel_id)
        end
        state.record_bip_frame(machine, frame_number)
    end

    add_channel_payload(
        channel_data_item, channel_payload, channel_payload_range,
        channel_id or status_channel, port, pinfo
    )

    return {
        name = name,
        command_type = command_type,
        envelope = envelope_name,
        channel_payload = channel_payload,
        channel_payload_offset = channel_payload_offset,
        port = port,
    }
end

local function add_command_subtree(
    tree, payload, command, description, rsp_description, budget, pinfo
)
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
    if description ~= nil then
        add_command_description(item, payload, command, description)
    end

    local gp_description = gp.describe(payload, command)
    if gp_description ~= nil then
        add_gp_description(item, payload, command, gp_description)
    end

    if command.data_offset ~= nil and command.data_length > 0 then
        local data_range = util.safe_range(
            payload, command.data_offset, command.data_length
        )
        if data_range ~= nil then
            local data_item = item:add(fields.data, data_range)
            -- SELECT and the PIN commands carry positional data that the
            -- description above already broke out, and an INSTALL body is
            -- positional too, so a TLV attempt on either produces noise.
            local positional = command.ins == commands.INS_SELECT
                or (gp_description ~= nil and gp_description.kind == "install")

            -- STORE DATA P1 bits 5 and 4 say what the body is. In DGI
            -- format it is a run of two-byte data grouping identifiers
            -- with a one-byte length, which is not BER-TLV and does not
            -- survive being read as it: the DGI '00 70' becomes a
            -- universal-class tag and the length is taken from the
            -- second identifier byte.
            local dgi = gp_description ~= nil
                and gp_description.kind == "store_data"
                and gp_description.structure == "DGI format"

            if cat.is_terminal_profile(command.cla, command.ins) then
                -- ETSI TS 102 223 clause 5.2: the body is a bit field of
                -- terminal capabilities, not TLV. Running the
                -- comprehension walker over it invents tags out of
                -- capability bits, so the bytes are left as they are.
                data_item:set_text(string.format(
                    "Terminal profile: %s of capability bits",
                    util.plural_bytes(command.data_length)
                ))
            elseif cat.is_cat_instruction(command.cla, command.ins) then
                add_cat_subtree(
                    data_item, payload, command.data_offset,
                    command.data_length, budget, pinfo
                )
            elseif dgi then
                add_dgi_subtree(
                    data_item, payload, command.data_offset, command.data_length
                )
            elseif rsp_description ~= nil then
                data_item:set_text(
                    "Command data: " .. rsp_description.name
                )
                add_tlv_subtree(
                    data_item, payload, command.data_offset,
                    command.data_length, rsp.tlv_options(), budget
                )
            elseif positional == false then
                add_tlv_subtree(
                    data_item,
                    payload,
                    command.data_offset,
                    command.data_length,
                    {},
                    budget
                )
            end
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

--- TLV options that decode an FCP/FCI/FMD template in place.
--
-- Wireshark 4.2 reports this whole structure as a malformed packet, and
-- it is the answer to every SELECT, so it carries most of what a SIM
-- trace has to say about the file system.
local FCP_OPTIONS = {
    resolver = function(tag, _raw, _level, parent)
        return responses.fcp_tag_name(tag, parent)
    end,
    -- ETSI TS 102 221 clause 11.1.1.4.10 fills 'C6' with TLVs even
    -- though BER calls it primitive, so the walker is told to descend.
    constructed = { [0xC6] = true },
    enrich = function(item, node, payload)
        if node.depth == 0 then
            return
        end
        local range = util.safe_range(payload, node.value_offset, node.value_length)
        if range == nil then
            return
        end

        if node.base_tag == 0x82 then
            local descriptor = responses.parse_file_descriptor(
                payload, node.value_offset, node.value_length
            )
            if descriptor == nil then
                return
            end
            item:add(fields.fcp_file_type, range, descriptor.file_type)
                :set_generated()
            item:add(fields.fcp_structure, range, descriptor.structure)
                :set_generated()
            if descriptor.record_length ~= nil then
                item:add(
                    fields.fcp_record_length, range, descriptor.record_length
                ):set_generated()
            end
            if descriptor.record_count ~= nil then
                item:add(
                    fields.fcp_record_count, range, descriptor.record_count
                ):set_generated()
            end
            if descriptor.data_coding ~= nil then
                -- Parsed and then discarded is the same as not parsed.
                local coding = item:add(
                    fields.fcp_data_coding, range, descriptor.data_coding
                )
                coding:set_generated()
                if descriptor.write_behaviour ~= nil then
                    coding:add(
                        fields.fcp_write_behaviour, range,
                        descriptor.write_behaviour
                    ):set_generated()
                end
                coding:add(
                    fields.fcp_erased_value, range, descriptor.erased_value
                ):set_generated()
                coding:add(
                    fields.fcp_data_unit, range, descriptor.data_unit_quartets
                ):set_generated()
            end
            return
        end

        if node.base_tag == 0x83 and node.parent == 0xC6 then
            local reference = util.byte_at(payload, node.value_offset)
            if reference ~= nil then
                item:add(fields.pin_reference, range, reference)
                item:add(
                    fields.pin_name, range, commands.key_reference_name(reference)
                ):set_generated()
            end
            return
        end

        if node.base_tag == 0x83 and node.value_length == 2 then
            local fid = util.safe_uint(payload, node.value_offset, 2)
            if fid == nil then
                return
            end
            item:add(fields.fcp_fid, range, fid):set_generated()
            local path = responses.ef_name(string.format("%04X", fid))
            if path ~= "" then
                item:add(fields.fcp_path, range, path):set_generated()
                item:append_text(" (" .. path .. ")")
            end
            return
        end

        if node.base_tag == 0x84 then
            item:add(fields.fcp_df_name, range):set_generated()
            local name = commands.aid_name(
                util.hex(payload, node.value_offset, node.value_length)
            )
            if name ~= "" then
                item:append_text(" (" .. name .. ")")
            end
            return
        end

        if node.base_tag == 0x80 or node.base_tag == 0x81 then
            local size = util.safe_uint(
                payload, node.value_offset, node.value_length
            )
            if size == nil then
                return
            end
            local field = fields.fcp_file_size
            if node.base_tag == 0x81 then
                field = fields.fcp_total_size
            end
            item:add(field, range, size):set_generated()
            item:append_text(string.format(" (%s)", util.plural_bytes(size)))
            return
        end

        if node.base_tag == 0x88 then
            local sfi = util.byte_at(payload, node.value_offset)
            if sfi ~= nil then
                -- The short file identifier sits in the top five bits.
                item:add(fields.fcp_sfi, range, math.floor(sfi / 8)):set_generated()
            end
            return
        end

        if node.base_tag == 0x8A then
            local lcsi = util.byte_at(payload, node.value_offset)
            if lcsi ~= nil then
                -- The ISO coding, not the GlobalPlatform one: an FCP
                -- '8A' is a life-cycle status integer, and consulting
                -- the GP registry table first reported every ordinary
                -- UICC file as "LOADED".
                local named = responses.lifecycle_name(lcsi)
                item:add(fields.fcp_lcsi, range, lcsi):set_generated()
                item:add(fields.fcp_lcsi_name, range, named):set_generated()
                item:append_text(" (" .. named .. ")")
                if named == "termination state" then
                    item:add_proto_expert_info(
                        experts.status_warning,
                        "the selected file is in the termination state and "
                            .. "cannot be reactivated"
                    )
                end
            end
            return
        end
    end,
}

--- Decode a known elementary file's contents.
local function add_ef_details(tree, payload, response, fid_hex, context)
    if fid_hex == "" or response.data_length == 0 then
        return false
    end
    -- '6F38' is EF.UST under ADF.USIM and EF.SST under DF.GSM, and the
    -- two are encoded differently, so the selected application decides
    -- which reader applies.
    local ef_context = nil
    if context ~= nil and context.context_available == true then
        local aid = context.selected_aid or ""
        local selected = context.selected_fid or ""
        if aid ~= "" then
            ef_context = { application = "usim" }
        elseif selected:sub(1, 4) == "7F20" then
            ef_context = { application = "gsm" }
        end
    end
    local decoded = responses.decode_ef(
        payload, response.data_offset, response.data_length, fid_hex, ef_context
    )
    if decoded == nil then
        return false
    end
    local range = util.safe_range(payload, response.data_offset, response.data_length)
    if range == nil then
        return false
    end
    local name = responses.ef_name(fid_hex)
    if name ~= "" then
        tree:add(fields.ef_name, range, name):set_generated()
    end
    if decoded.kind == "iccid" then
        local item = tree:add(fields.ef_iccid, range, decoded.value)
        if decoded.malformed then
            item:add_proto_expert_info(
                experts.tlv_malformed,
                "these bytes contain a nibble that is not a decimal digit, "
                    .. "so they are not an ICCID"
            )
        end
        if decoded.over_read then
            item:append_text(" (read ran past the 10-byte file)")
        end
        return true
    end
    if decoded.kind == "imsi" then
        tree:add(fields.ef_imsi, range, decoded.value)
        return true
    end
    if decoded.kind == "ust" then
        if decoded.assumed then
            tree:add_proto_expert_info(
                experts.no_context,
                "'6F38' is EF.UST under ADF.USIM and EF.SST under DF.GSM; "
                    .. "with no selected application the USIM reading is assumed"
            )
        end
        for index = 1, #decoded.services do
            tree:add(
                fields.ef_service, range,
                string.format("service %d available", decoded.services[index])
            ):set_generated()
        end
        return true
    end
    if decoded.kind == "sst" then
        for index = 1, #decoded.services do
            local service = decoded.services[index]
            tree:add(
                fields.ef_service, range,
                string.format(
                    "service %d allocated%s", service.number,
                    service.activated and " and activated" or ", not activated"
                )
            ):set_generated()
        end
        return true
    end
    if decoded.kind == "ad" then
        tree:add(fields.ef_operation_mode, range, decoded.operation_mode)
        tree:add(
            fields.ef_operation_mode_name, range, decoded.operation_mode_name
        ):set_generated()
        if decoded.ciphering_indicator ~= nil then
            tree:add(
                fields.ef_ciphering_indicator, range, decoded.ciphering_indicator
            ):set_generated()
        end
        if decoded.mnc_length ~= nil then
            tree:add(fields.ef_mnc_length, range, decoded.mnc_length)
        end
        return true
    end
    return false
end

--- Render a completed chained STORE DATA, and the links to its blocks.
--
-- Nothing here reads a stored Tvb -- a Tvb's lifetime ends with the
-- packet that produced it, so the assembled bytes are kept as hex and a
-- fresh one is built on every visit. See rule 3 in state.lua.
local function add_reassembly_subtree(tree, payload, context, budget)
    if context == nil then
        return
    end
    if context.reassembly_dropped then
        -- Degrades the way the TLV node budget already does: say what
        -- was given up on rather than render a short tree in silence.
        tree:add_proto_expert_info(
            experts.budget,
            string.format(
                "the chained STORE DATA passed %s with no last-block "
                    .. "flag, so the blocks held for it were released",
                util.plural_bytes(state.MAX_REASSEMBLY_BYTES)
            )
        )
        return
    end
    if context.reassembled_in ~= nil and context.reassembled_hex == nil then
        -- A block in the middle of a chain: say where it ends up.
        tree:add(fields.rsp_reassembled_in, payload(0, 0), context.reassembled_in)
            :set_generated()
        return
    end
    local hex = context.reassembled_hex
    if hex == nil or #hex == 0 then
        return
    end
    local frames = context.reassembly_frames or {}
    if #frames < 2 then
        -- A single-block "chain" is just the command, already rendered.
        return
    end

    local item = tree:add(yapdu, payload(0, 0), "Reassembled STORE DATA")
    item:set_generated()
    -- math.floor, not bare '/': Lua 5.3 and later make '/' a float
    -- divide, and a non-integral float handed to a uint32 field
    -- raises rather than rounds -- aborting the frame. The hex is
    -- even-length today only because util.hex produces it.
    item:add(fields.rsp_reassembled_length, payload(0, 0), math.floor(#hex / 2))
        :set_generated()
    item:add(fields.rsp_block_count, payload(0, 0), #frames):set_generated()
    for index = 1, #frames do
        item:add(fields.rsp_reassembly_frame, payload(0, 0), frames[index])
            :set_generated()
    end

    local assembled = ByteArray.new(hex):tvb("Reassembled STORE DATA")
    local ok = pcall(function()
        add_tlv_subtree(
            item, assembled, 0, assembled:len(), rsp.tlv_options(), budget
        )
    end)
    if not ok then
        item:add_proto_expert_info(
            experts.tlv_malformed,
            "the reassembled blocks do not parse as a TLV structure"
        )
    end
end

local function add_response_subtree(
    tree, payload, response, context, command, budget, pinfo
)
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
            local data_item = item:add(fields.response_data, data_range)

            -- Peek at the outermost tag so a file-control template is
            -- parsed with the sub-tag names ETSI TS 102 221 gives it
            -- rather than the generic BER table.
            local options = {}
            local first_tag = tlv.read_tag(payload, response.data_offset)
            local is_template = first_tag ~= nil
                and responses.is_fcp_template(first_tag.value)
            if is_template then
                options = FCP_OPTIONS
                data_item:set_text(
                    "Response data: " .. responses.template_name(first_tag.value)
                )
            elseif first_tag ~= nil and rsp.is_rsp_function(first_tag.value) then
                -- An EUICCInfo2 (BF22) or other RSP structure returned in a
                -- response: name its BFxx / euiccCiPKId / BPP members rather
                -- than leaving A9/AA to the generic context-tag fallback.
                options = rsp.tlv_options()
            end

            -- The INITIALIZE UPDATE response is positional, not TLV.
            if gp.is_gp_class(command.cla)
                and command.ins == gp.INS_INITIALIZE_UPDATE then
                if add_initialize_update_response(data_item, payload, response) then
                    return item
                end
            end

            -- A FETCH answers with a proactive command.
            if cat.is_cat_instruction(command.cla, command.ins)
                and command.ins == 0x12 then
                if add_cat_subtree(
                    data_item, payload, response.data_offset,
                    response.data_length, budget, pinfo
                ) ~= nil then
                    return item
                end
            end

            local fid = state.response_file(context, command)
            if fid == responses.EF_DIR and not is_template then
                -- EF.DIR records are application templates whose tags
                -- are universal-class BER values; the generic table
                -- names them "ASN1_..." which is true and useless.
                options = {
                    resolver = function(tag)
                        return responses.dir_tag_name(tag)
                    end,
                }
            end

            local nodes = add_tlv_subtree(
                data_item, payload, response.data_offset,
                response.data_length, options, budget
            )
            if nodes == nil then
                add_ef_details(data_item, payload, response, fid, context)
            end
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
        -- ISO/IEC 7816-4 clause 5.1.3 has four categories, not two, and
        -- the boolean alone cannot say which. A failed PIN verification
        -- and a wrong-length error are both "not success", but only one
        -- of them consumed a retry.
        sw_item:add(fields.sw_category, sw_range, response.category)
            :set_generated()
        if response.category == "warning" then
            sw_item:add_proto_expert_info(experts.status_warning, response.meaning)
        elseif response.succeeded == false then
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
            local label = interface_byte.name
            if interface_byte.detail ~= nil then
                label = label .. " — " .. interface_byte.detail
            end
            item:add(fields.atr_interface, range)
                :append_text(string.format(" (%s)", label))
        end
    end
    for index = 1, #atr.protocols do
        local protocol = atr.protocols[index]
        local range = util.safe_range(payload, protocol.offset, 1)
        if range ~= nil then
            local proto_item = item:add(fields.atr_protocol, range, protocol.value)
            if protocol.is_global == true then
                proto_item:append_text(
                    " (T=15: global interface bytes indicator, not an offered protocol)"
                )
            else
                proto_item:append_text(
                    string.format(" (offered protocol T=%d)", protocol.value)
                )
            end
        end
    end
    if atr.historical_count > 0 then
        local range = util.safe_range(
            payload, atr.historical_offset, atr.historical_count
        )
        if range ~= nil then
            local hist_item = item:add(fields.atr_historical, range)
            local hist = atr.historical
            if hist ~= nil then
                local cat_range = util.safe_range(payload, atr.historical_offset, 1)
                if cat_range ~= nil then
                    hist_item:add(
                        fields.atr_historical_category, cat_range, hist.category
                    ):append_text(string.format(" (%s)", hist.category_name))
                end
                for oi = 1, #hist.objects do
                    local obj = hist.objects[oi]
                    local span = util.safe_range(
                        payload, obj.offset, obj.value_length + 1
                    )
                    if span ~= nil then
                        hist_item:add(fields.atr_historical_object, span)
                            :append_text(string.format(
                                " (%s, %s)", obj.name,
                                util.plural_bytes(obj.value_length)
                            ))
                    end
                end
            end
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

--- Decode a recovered plaintext command APDU.
--
-- The plaintext is a complete command APDU, so the same header,
-- command-body and payload decoding that ran on the ciphered frame is
-- run again over it. That is the point of recovering it: a ciphered
-- ES10b STORE DATA should read as an ES10b call, not as a blob with a
-- note saying it was decrypted.
local function add_plaintext_command(tree, hex, budget, pinfo)
    if hex == "" then
        return
    end
    local ok, bytes = pcall(ByteArray.new, hex)
    if ok == false or bytes == nil or bytes:len() < 4 then
        return
    end
    local inner = bytes:tvb("Decrypted APDU")
    local item = tree:add(fields.sm_plaintext, inner(0, inner:len()))

    local cla = util.byte_at(inner, 0)
    local ins = util.byte_at(inner, 1)
    if cla == nil or ins == nil then
        return
    end
    local name, source = iso7816.command_name(cla, ins)
    item:set_text(string.format(
        "Decrypted command APDU: %s (%s)", name, util.plural_bytes(inner:len())
    ))
    item:add(fields.command_name, inner(1, 1), name):set_generated()
    if source ~= nil and source ~= "" then
        item:add(fields.command_source, inner(1, 1), source):set_generated()
    end

    -- The plaintext carries no Le, so its body runs from offset 5 to the
    -- end; _build_cleartext_apdu_from_header on the Python side builds
    -- it that way.
    if inner:len() <= 5 then
        return
    end
    local body_length = inner:len() - 5
    local declared = util.byte_at(inner, 4)
    if declared ~= nil and declared < body_length then
        body_length = declared
    end
    local body = inner(5, body_length)
    local data_item = item:add(fields.data, body)

    local inner_command = { ins = ins, cla = cla, data_offset = 5,
                            data_length = body_length }
    local inner_rsp = rsp.describe(inner, inner_command, nil)
    if inner_rsp ~= nil then
        data_item:set_text("Decrypted command data: " .. inner_rsp.name)
        add_tlv_subtree(data_item, inner, 5, body_length, rsp.tlv_options(), budget)
        return
    end
    if cat.is_cat_instruction(cla, ins) then
        add_cat_subtree(data_item, inner, 5, body_length, budget, pinfo)
        return
    end
    add_tlv_subtree(data_item, inner, 5, body_length, {}, budget)
end

--- Break out secure-messaging structure and overlay any recovered plaintext.
local function add_secure_messaging(tree, payload, pinfo, command, response, context, budget)
    local wrapped = sm.describe(payload, command)
    if wrapped == nil then
        return
    end

    local range = util.safe_range(payload, 0, command.length)
    if range == nil then
        return
    end
    local item = tree:add(yapdu, range, "Secure messaging")
    item:add(fields.sm_protocol, payload(0, 1), sm.protocol_name(context))
        :set_generated()

    if wrapped.mac_offset ~= nil then
        local mac_range = util.safe_range(payload, wrapped.mac_offset, wrapped.mac_length)
        if mac_range ~= nil then
            item:add(fields.sm_cmac, mac_range)
        end
        if wrapped.ciphertext_length > 0 then
            local cipher_range = util.safe_range(
                payload, wrapped.ciphertext_offset, wrapped.ciphertext_length
            )
            if cipher_range ~= nil then
                local cipher_item = item:add(fields.sm_ciphertext, cipher_range)
                if wrapped.encrypted == false then
                    cipher_item:set_text(string.format(
                        "Authenticated body, not encrypted: %s",
                        util.plural_bytes(wrapped.ciphertext_length)
                    ))
                end
            end
        end
    end

    local frames, status = sm.sidecar(yapdu.prefs.sidecar_path)
    item:add(fields.sm_status, payload(0, 0), status):set_generated()
    if frames == nil then
        return
    end

    local observed = util.hex(payload, 0, command.length)
    local entry, mismatch = sm.entry_for(frames, pinfo.number, observed)
    if mismatch then
        item:add(fields.sm_sidecar_mismatch, payload(0, 0), true):set_generated()
        item:add_proto_expert_info(
            experts.sidecar_mismatch,
            "the sidecar has an entry for this frame number but its recorded "
                .. "command does not match these bytes, so it was built from a "
                .. "different capture and is being ignored"
        )
        return
    end
    if entry == nil then
        return
    end

    local label = sm.entry_hex(entry, "session_label")
    if label ~= "" then
        item:add(fields.sm_session, payload(0, 0), label):set_generated()
    end
    if entry["mac_ok"] ~= nil then
        item:add(
            fields.sm_mac_verified, payload(0, 0), entry["mac_ok"] == true
        ):set_generated()
    end

    add_plaintext_command(
        item, sm.entry_hex(entry, "command_plaintext"), budget, pinfo
    )

    local response_hex = sm.entry_hex(entry, "response_plaintext")
    if response_hex ~= "" then
        local ok, bytes = pcall(ByteArray.new, response_hex)
        if ok and bytes ~= nil and bytes:len() > 0 then
            local inner = bytes:tvb("Decrypted response")
            item:add(fields.sm_response_plaintext, inner(0, inner:len()))
        end
    end
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

    -- yggdrasim-eum-diag points YGGDRASIM_EUM_SESSION_KEYS at a session
    -- key repository. It is reported, never applied; see sm.eum_keys.
    local eum_entries, eum_status = sm.eum_keys()
    if eum_status ~= "" then
        local keys_item = root:add(yapdu, payload(0, 0), "EUM session keys")
        keys_item:set_generated()
        keys_item:add(fields.sm_status, payload(0, 0), eum_status):set_generated()
        if eum_entries ~= nil then
            for iccid, bundle in pairs(eum_entries) do
                if type(bundle) == "table" then
                    keys_item:add(
                        fields.sm_session, payload(0, 0),
                        "ICCID " .. tostring(iccid)
                    ):set_generated()
                end
            end
        end
    end

    local command = iso7816.parse_command(payload, result)
    local response = iso7816.parse_response(payload, result)
    if command == nil or response == nil then
        root:add_proto_expert_info(
            experts.split_failed, "header or status word unreadable"
        )
        root:add(fields.raw, payload(0, payload:captured_len()))
        return
    end

    local description = commands.describe(payload, command)
    local gp_description = gp.describe(payload, command)

    -- Facts the machine needs that only the payload can supply: the SCP
    -- the card named in its INITIALIZE UPDATE response, the security
    -- level EXTERNAL AUTHENTICATE asked for, and the blocks of a chained
    -- STORE DATA. All three are gathered before the machine advances so
    -- the render path never has to mutate it.
    local extra = {}
    if gp_description ~= nil then
        if gp_description.kind == "initialize_update" and response.data_length > 0 then
            local parsed = gp.parse_initialize_update_response(
                payload, response.data_offset, response.data_length
            )
            if parsed ~= nil then
                extra.scp_name = parsed.scp_name
            end
        elseif gp_description.kind == "external_authenticate" then
            extra.security_level = gp_description.level
        elseif gp_description.kind == "store_data"
            and command.data_offset ~= nil and command.data_length > 0 then
            extra.store_data_hex = util.hex(
                payload, command.data_offset, command.data_length
            )
            extra.store_data_last = gp_description.last_block
        end
    end

    -- Advance the machine only when this frame is genuinely the next one
    -- in capture order; otherwise replay the stored snapshot. See
    -- state.lua for why pinfo.visited alone is not sufficient.
    local context
    frame_number = pinfo.number
    frame_advancing = state.may_advance(machine, pinfo.number, pinfo.visited)
    if frame_advancing then
        context = state.advance(
            machine, pinfo.number, command, response, description, extra
        )
    else
        context = state.snapshot(machine, pinfo.number)
    end

    root:add(
        fields.context_available, payload(0, 0), context.context_available
    ):set_generated()
    if context.context_available ~= true then
        root:add_proto_expert_info(
            experts.no_context,
            "this frame was dissected without the frames before it, so the "
                .. "currently selected file is unknown"
        )
    end

    local budget = tlv.new_budget()
    local rsp_description = rsp.describe(payload, command, context)
    add_command_subtree(
        root, payload, command, description, rsp_description, budget, pinfo
    )
    add_reassembly_subtree(root, payload, context, budget)
    add_response_subtree(
        root, payload, response, context, command, budget, pinfo
    )
    add_secure_messaging(root, payload, pinfo, command, response, context, budget)

    root:set_text(string.format(
        "YggdraSIM APDU: %s -> %04X", command.name, response.status_word
    ))

    -- The most specific reading is what an operator scans for: the ES10
    -- function or GlobalPlatform variant beats the bare command detail.
    -- Surfaced as its own field (so it can be a column) and in Info.
    local detail = commands.summary(description)
    if rsp_description ~= nil then
        detail = rsp_description.name
    else
        local gp_detail = gp.summary(gp_description)
        if gp_detail ~= "" then
            detail = gp_detail
        end
    end

    -- Anchor file operations to the selected file. READ/UPDATE BINARY,
    -- READ/UPDATE RECORD and the GET RESPONSE that follows a SELECT act on
    -- whatever is currently selected and stay about that file until the
    -- next SELECT; state.response_file already resolves which file that is
    -- (including the pending file a GET RESPONSE is fetching). SELECT names
    -- its own target, so it is left as it is.
    local ins = command.ins
    if ins == commands.INS_READ_BINARY or ins == commands.INS_UPDATE_BINARY
        or ins == commands.INS_READ_RECORD or ins == commands.INS_UPDATE_RECORD
        or ins == commands.INS_GET_RESPONSE then
        local fid = state.response_file(context, command)
        local file = ""
        if fid ~= nil and fid ~= "" then
            file = commands.file_name(fid)
        end
        if file ~= "" then
            if detail ~= "" then
                detail = file .. " (" .. detail .. ")"
            else
                detail = file
            end
        end
    end

    if detail ~= "" then
        root:add(fields.detail, payload(0, 0), detail):set_generated()
    end

    if yapdu.prefs.set_info_column == true then
        local summary
        if detail ~= "" then
            summary = string.format(
                "%s %s -> %04X %s",
                command.name, detail, response.status_word, response.meaning
            )
        else
            summary = string.format(
                "%s %02X %02X -> %04X %s",
                command.name, command.p1, command.p2,
                response.status_word, response.meaning
            )
        end
        pinfo.cols.info:set(util.clip(summary, 140))
    end
end

--- Wireshark calls this at the start of every dissection run: file
--- open, reload, filter change and preference change alike. It is the
--- only reliable point at which to discard cross-frame state.
function yapdu.init()
    machine = state.new()
    sm.reset()
    sm.reset_eum_keys()
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
        pcall(function()
            local gsm_sim = Dissector.get("gsm_sim")
            if gsm_sim ~= nil then
                gsm_sim:call(payload, pinfo, tree)
            end
        end)
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
    -- No fallback to udp.port. Registering a Lua proto on UDP 4729 does
    -- not layer on top of GSMTAP, it *displaces* it: the dissector is
    -- then handed the raw UDP payload with the 16-byte GSMTAP header
    -- still attached, and the splitter reads GSMTAP's version and type
    -- bytes as CLA and INS. Every frame in the capture would decode as
    -- something, with a confident-looking split score and no sign that
    -- the header was never stripped -- which is worse than not loading.
    --
    -- packet-gsmtap.c has registered the gsmtap.type table since well
    -- before the 3.4 floor this dissector claims, so reaching here means
    -- the build genuinely cannot support the binding.
    print(
        "yggdrasim_apdu: no gsmtap.type dissector table in this Wireshark "
            .. "build; the APDU dissector will not load."
    )
end
