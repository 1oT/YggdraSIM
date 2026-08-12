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
    item:add(fields.tlv_class, range, node.class):set_generated()
    item:add(fields.tlv_constructed, range, node.constructed):set_generated()
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
        if parsed.complete == false then
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

--- Render a CAT proactive command or terminal response.
--
-- The outer 0xD0 Proactive Command tag is plain BER; only its contents
-- are COMPREHENSION-TLV. Parsing the wrapper in comprehension mode would
-- strip its high bit and rename it from "Proactive command" to whatever
-- 0x50 happens to mean, so the wrapper is stepped over first.
local function add_cat_subtree(tree, payload, offset, length, budget)
    local content_offset = offset
    local content_length = length

    local wrapper = tlv.read_tag(payload, offset)
    if wrapper ~= nil and wrapper.value == cat.PROACTIVE_COMMAND_TAG then
        local wrapper_length = tlv.read_length(payload, offset + wrapper.length)
        if wrapper_length ~= nil and wrapper_length.value ~= nil then
            content_offset = offset + wrapper.length + wrapper_length.length
            content_length = wrapper_length.value
            local available = payload:captured_len() - content_offset
            if content_length > available then
                content_length = math.max(0, available)
            end
            local range = util.safe_range(payload, offset, length)
            if range ~= nil then
                tree = tree:add(fields.cat_command, range)
                tree:set_text("Proactive command (D0)")
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
    if details == nil or details.command_type == nil then
        return nil
    end
    local name = cat.command_name(details.command_type)
    tree:add(fields.cat_type, payload(offset, 1), details.command_type)
        :set_generated()
    tree:add(fields.cat_type_name, payload(offset, 1), name):set_generated()
    tree:add(fields.cat_number, payload(offset, 1), details.number or 0)
        :set_generated()
    tree:add(
        fields.cat_qualifier_name, payload(offset, 1),
        cat.qualifier_name(details.command_type, details.qualifier or 0)
    ):set_generated()

    -- Bearer Independent Protocol parameters. These are what an eUICC
    -- profile download actually runs over, so naming the bearer, the
    -- access point and the peer address is most of what a BIP trace is
    -- consulted for.
    local port = nil
    local channel_payload = nil
    local channel_payload_offset = nil
    for index = 1, #nodes do
        local node = nodes[index]
        local range = util.safe_range(payload, node.value_offset, node.value_length)
        if range ~= nil then
            if node.base_tag == cat.TAG_BEARER_DESCRIPTION and node.value_length >= 1 then
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
                local values = util.byte_array(
                    payload, node.value_offset, node.value_length
                )
                local address = cat.decode_other_address(values)
                if address ~= "" then
                    tree:add(fields.cat_address, range, address):set_generated()
                end
            elseif node.base_tag == cat.TAG_TRANSPORT_LEVEL and node.value_length >= 1 then
                local kind = util.byte_at(payload, node.value_offset)
                tree:add(fields.cat_transport, range, cat.transport_name(kind))
                    :set_generated()
                if node.value_length >= 3 then
                    port = util.safe_uint(payload, node.value_offset + 1, 2)
                    if port ~= nil then
                        tree:add(fields.cat_port, range, port)
                    end
                end
            elseif node.base_tag == cat.TAG_CHANNEL_STATUS and node.value_length >= 1 then
                local status = util.byte_at(payload, node.value_offset)
                tree:add(
                    fields.cat_channel, range, cat.channel_number(status)
                ):set_generated()
            elseif node.base_tag == cat.TAG_CHANNEL_DATA and node.value_length > 0 then
                channel_payload = util.byte_array(
                    payload, node.value_offset, node.value_length
                )
                channel_payload_offset = node.value_offset
                tree:add(fields.cat_channel_data, range)
            elseif node.base_tag == cat.TAG_RESULT and node.value_length >= 1 then
                local result = util.byte_at(payload, node.value_offset)
                tree:add(fields.cat_result, range, result)
                tree:add(fields.cat_result_name, range, cat.result_name(result))
                    :set_generated()
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

    return {
        name = name,
        command_type = details.command_type,
        channel_payload = channel_payload,
        channel_payload_offset = channel_payload_offset,
        port = port,
    }
end

local function add_command_subtree(
    tree, payload, command, description, rsp_description, budget
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

            if cat.is_cat_instruction(command.cla, command.ins) then
                add_cat_subtree(
                    data_item, payload, command.data_offset,
                    command.data_length, budget
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
    resolver = function(tag)
        return responses.fcp_tag_name(tag)
    end,
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
                item:add(fields.fcp_lcsi, range, lcsi):set_generated()
                item:append_text(" (" .. responses.lifecycle_name(lcsi) .. ")")
            end
            return
        end
    end,
}

--- Decode a known elementary file's contents.
local function add_ef_details(tree, payload, response, fid_hex)
    if fid_hex == "" or response.data_length == 0 then
        return false
    end
    local decoded = responses.decode_ef(
        payload, response.data_offset, response.data_length, fid_hex
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
        tree:add(fields.ef_iccid, range, decoded.value)
        return true
    end
    if decoded.kind == "imsi" then
        tree:add(fields.ef_imsi, range, decoded.value)
        return true
    end
    if decoded.kind == "ust" then
        for index = 1, #decoded.services do
            tree:add(
                fields.ef_service, range,
                string.format("service %d available", decoded.services[index])
            ):set_generated()
        end
        return true
    end
    if decoded.kind == "ad" then
        tree:add(fields.ef_operation_mode, range, decoded.operation_mode)
        if decoded.mnc_length ~= nil then
            tree:add(fields.ef_mnc_length, range, decoded.mnc_length)
        end
        return true
    end
    return false
end

local function add_response_subtree(tree, payload, response, context, command, budget)
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
                    response.data_length, budget
                ) ~= nil then
                    return item
                end
            end

            local nodes = add_tlv_subtree(
                data_item, payload, response.data_offset,
                response.data_length, options, budget
            )
            if nodes == nil then
                local fid = state.response_file(context, command)
                add_ef_details(data_item, payload, response, fid)
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

--- Decode a recovered plaintext command APDU.
--
-- The plaintext is a complete command APDU, so the same header,
-- command-body and payload decoding that ran on the ciphered frame is
-- run again over it. That is the point of recovering it: a ciphered
-- ES10b STORE DATA should read as an ES10b call, not as a blob with a
-- note saying it was decrypted.
local function add_plaintext_command(tree, hex, budget)
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
        add_cat_subtree(data_item, inner, 5, body_length, budget)
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

    add_plaintext_command(item, sm.entry_hex(entry, "command_plaintext"), budget)

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

    -- Advance the machine only when this frame is genuinely the next one
    -- in capture order; otherwise replay the stored snapshot. See
    -- state.lua for why pinfo.visited alone is not sufficient.
    local context
    if state.may_advance(machine, pinfo.number, pinfo.visited) then
        context = state.advance(
            machine, pinfo.number, command, response, description
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
        root, payload, command, description, rsp_description, budget
    )
    add_response_subtree(root, payload, response, context, command, budget)
    add_secure_messaging(root, payload, pinfo, command, response, context, budget)

    root:set_text(string.format(
        "YggdraSIM APDU: %s -> %04X", command.name, response.status_word
    ))

    if yapdu.prefs.set_info_column == true then
        local detail = commands.summary(description)
        -- The most specific reading wins the column: naming the ES10
        -- function or the GlobalPlatform variant is what an operator is
        -- scanning the packet list for.
        if rsp_description ~= nil then
            detail = rsp_description.name
        else
            local gp_detail = gp.summary(gp.describe(payload, command))
            if gp_detail ~= "" then
                detail = gp_detail
            end
        end
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
