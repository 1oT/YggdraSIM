-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- ProtoField definitions for the YggdraSIM APDU dissector.
--
-- Kept apart from the entry point so the field set can be read as a
-- whole: these abbreviations are the dissector's public interface, the
-- thing an operator types into a display filter, and renaming one breaks
-- saved filters and the HIL-Bridge TUI's field queries alike.
--
-- Value strings come from yggdrasim_apdu.tables, which is generated from
-- the Python modules the rest of the toolkit already trusts.
--
-- Side-effect free: constructing a ProtoField does not register it. The
-- entry point assigns M.all to proto.fields.

local tables = require("yggdrasim_apdu.tables")

local M = {}

local PREFIX = "yapdu"

--- Build a Wireshark value-string table from a generated name table.
local function value_string(mapping)
    local built = {}
    for key, name in pairs(mapping) do
        built[key] = name
    end
    return built
end

M.ins_names = value_string(tables.INS_NAMES)
M.status_words = value_string(tables.STATUS_WORDS)
M.risk_names = value_string(tables.RISK_CLASS_NAMES)

local CLA_TYPE_NAMES = {
    [0] = "Interindustry",
    [1] = "Proprietary",
}

local SECURE_MESSAGING_NAMES = {
    [0] = "None",
    [1] = "Proprietary",
    [2] = "Command header not authenticated",
    [3] = "Command header authenticated",
}

local CASE_NAMES = {
    ["1"] = "Case 1: no data, no response",
    ["2S"] = "Case 2S: no data, response expected",
    ["3S"] = "Case 3S: data, no response",
    ["4S"] = "Case 4S: data and response",
    ["2E"] = "Case 2E: extended, no data, response expected",
    ["3E"] = "Case 3E: extended, data, no response",
    ["4E"] = "Case 4E: extended, data and response",
}
M.case_names = CASE_NAMES

-- ------------------------------------------------------------ frame level
M.frame_kind = ProtoField.string(PREFIX .. ".frame_kind", "Frame kind")
M.raw = ProtoField.bytes(PREFIX .. ".raw", "Undecoded bytes")
M.context_available = ProtoField.bool(
    PREFIX .. ".context_available",
    "Cross-frame context available"
)

-- ------------------------------------------------------------ split result
M.split_command_len = ProtoField.uint32(
    PREFIX .. ".split.command_len", "Command length", base.DEC
)
M.split_response_len = ProtoField.uint32(
    PREFIX .. ".split.response_len", "Response length", base.DEC
)
M.split_confidence = ProtoField.uint8(
    PREFIX .. ".split.confidence", "Split confidence", base.DEC
)
M.split_method = ProtoField.string(PREFIX .. ".split.method", "Split evidence")
M.split_ambiguous = ProtoField.bool(PREFIX .. ".split.ambiguous", "Split ambiguous")
M.split_candidate = ProtoField.string(PREFIX .. ".split.candidate", "Candidate")

-- ---------------------------------------------------------------- command
M.command = ProtoField.bytes(PREFIX .. ".command", "Command APDU")
M.cla = ProtoField.uint8(PREFIX .. ".cla", "CLA", base.HEX)
M.cla_type = ProtoField.uint8(
    PREFIX .. ".cla.type", "Class type", base.DEC, CLA_TYPE_NAMES
)
M.cla_channel = ProtoField.uint8(
    PREFIX .. ".cla.channel", "Logical channel", base.DEC
)
M.cla_secure_messaging = ProtoField.uint8(
    PREFIX .. ".cla.secure_messaging",
    "Secure messaging",
    base.DEC,
    SECURE_MESSAGING_NAMES
)
M.cla_chaining = ProtoField.bool(PREFIX .. ".cla.chaining", "Command chaining")

M.ins = ProtoField.uint8(PREFIX .. ".ins", "INS", base.HEX, M.ins_names)
M.command_name = ProtoField.string(PREFIX .. ".command_name", "Command")
M.command_source = ProtoField.string(PREFIX .. ".command_source", "Defined by")

M.p1 = ProtoField.uint8(PREFIX .. ".p1", "P1", base.HEX)
M.p2 = ProtoField.uint8(PREFIX .. ".p2", "P2", base.HEX)
M.lc = ProtoField.uint32(PREFIX .. ".lc", "Lc", base.DEC)
M.le = ProtoField.uint32(PREFIX .. ".le", "Le", base.DEC)
M.le_effective = ProtoField.uint32(
    PREFIX .. ".le_effective", "Le (effective)", base.DEC
)
M.data = ProtoField.bytes(PREFIX .. ".data", "Command data")
M.case = ProtoField.string(PREFIX .. ".case", "ISO 7816-4 case")
M.extended_length = ProtoField.bool(
    PREFIX .. ".extended_length", "Extended length fields"
)

M.risk = ProtoField.uint8(PREFIX .. ".risk", "Risk", base.DEC, M.risk_names)
M.risk_name = ProtoField.string(PREFIX .. ".risk_name", "Risk detail")

-- --------------------------------------------------------------- response
M.response = ProtoField.bytes(PREFIX .. ".response", "Response APDU")
M.response_data = ProtoField.bytes(PREFIX .. ".response_data", "Response data")
M.sw = ProtoField.uint16(PREFIX .. ".sw", "Status word", base.HEX, M.status_words)
M.sw1 = ProtoField.uint8(PREFIX .. ".sw1", "SW1", base.HEX)
M.sw2 = ProtoField.uint8(PREFIX .. ".sw2", "SW2", base.HEX)
M.sw_meaning = ProtoField.string(PREFIX .. ".sw_meaning", "Status")
M.sw_success = ProtoField.bool(PREFIX .. ".sw_success", "Succeeded")

-- ------------------------------------------------------------------- ATR
M.atr = ProtoField.bytes(PREFIX .. ".atr", "Answer To Reset")
M.atr_ts = ProtoField.uint8(PREFIX .. ".atr.ts", "TS (convention)", base.HEX)
M.atr_t0 = ProtoField.uint8(PREFIX .. ".atr.t0", "T0 (format byte)", base.HEX)
M.atr_historical_count = ProtoField.uint8(
    PREFIX .. ".atr.historical_count", "Historical byte count", base.DEC
)
M.atr_interface = ProtoField.uint8(
    PREFIX .. ".atr.interface", "Interface byte", base.HEX
)
M.atr_protocol = ProtoField.uint8(
    PREFIX .. ".atr.protocol", "Offered protocol T", base.DEC
)
M.atr_historical = ProtoField.bytes(
    PREFIX .. ".atr.historical", "Historical bytes"
)
M.atr_tck = ProtoField.uint8(PREFIX .. ".atr.tck", "TCK (check byte)", base.HEX)
M.atr_tck_valid = ProtoField.bool(PREFIX .. ".atr.tck_valid", "TCK valid")

-- ------------------------------------------------------------------- TLV
local TAG_CLASS_NAMES = {
    [0] = "Universal",
    [1] = "Application",
    [2] = "Context-specific",
    [3] = "Private",
}

M.tlv = ProtoField.bytes(PREFIX .. ".tlv", "TLV")
M.tlv_tag = ProtoField.uint32(PREFIX .. ".tlv.tag", "Tag", base.HEX)
M.tlv_base_tag = ProtoField.uint32(
    PREFIX .. ".tlv.base_tag", "Tag (comprehension bit cleared)", base.HEX
)
M.tlv_name = ProtoField.string(PREFIX .. ".tlv.name", "Tag name")
M.tlv_class = ProtoField.uint8(
    PREFIX .. ".tlv.class", "Tag class", base.DEC, TAG_CLASS_NAMES
)
M.tlv_constructed = ProtoField.bool(PREFIX .. ".tlv.constructed", "Constructed")
M.tlv_length = ProtoField.uint32(PREFIX .. ".tlv.length", "Length", base.DEC)
M.tlv_indefinite = ProtoField.bool(
    PREFIX .. ".tlv.indefinite", "Indefinite length"
)
M.tlv_value = ProtoField.bytes(PREFIX .. ".tlv.value", "Value")
M.tlv_comprehension = ProtoField.bool(
    PREFIX .. ".tlv.comprehension_required", "Comprehension required"
)
M.tlv_text = ProtoField.string(PREFIX .. ".tlv.text", "Value (text)")
-- uint32, not uint64: a Lua number cannot be handed to a 64-bit field
-- (Wireshark wants a UInt64 userdata), and the renderer only offers an
-- integer reading for values of four bytes or fewer anyway.
M.tlv_uint = ProtoField.uint32(PREFIX .. ".tlv.uint", "Value (integer)", base.DEC)

-- ------------------------------------------------------------- file access
M.select_fid = ProtoField.uint16(PREFIX .. ".select.fid", "File identifier", base.HEX)
M.select_aid = ProtoField.bytes(PREFIX .. ".select.aid", "Application identifier")
M.select_name = ProtoField.string(PREFIX .. ".select.name", "Selected")
M.select_control = ProtoField.uint8(
    PREFIX .. ".select.control", "Selection control", base.HEX
)
M.select_return = ProtoField.uint8(
    PREFIX .. ".select.return", "Return-data control", base.HEX
)

M.binary_offset = ProtoField.uint32(
    PREFIX .. ".binary.offset", "Offset", base.DEC
)
M.binary_sfi = ProtoField.uint8(PREFIX .. ".binary.sfi", "Short file identifier", base.DEC)

M.record_number = ProtoField.uint8(
    PREFIX .. ".record.number", "Record number", base.DEC
)
M.record_sfi = ProtoField.uint8(PREFIX .. ".record.sfi", "Short file identifier", base.DEC)
M.record_mode = ProtoField.uint8(PREFIX .. ".record.mode", "Record mode", base.DEC)

M.pin_reference = ProtoField.uint8(
    PREFIX .. ".pin.reference", "Key reference", base.HEX
)
M.pin_name = ProtoField.string(PREFIX .. ".pin.name", "Key")
M.pin_value_len = ProtoField.uint32(
    PREFIX .. ".pin.value_len", "PIN block length", base.DEC
)
M.pin_retries = ProtoField.uint8(PREFIX .. ".pin.retries", "Retries left", base.DEC)

M.channel_number = ProtoField.uint8(
    PREFIX .. ".channel.number", "Channel number", base.DEC
)
M.channel_operation = ProtoField.string(
    PREFIX .. ".channel.operation", "Channel operation"
)

M.data_object_tag = ProtoField.uint16(
    PREFIX .. ".data_object.tag", "Data object tag", base.HEX
)
M.data_object_name = ProtoField.string(
    PREFIX .. ".data_object.name", "Data object"
)

-- --------------------------------------------------------------- FCP / EF
M.fcp = ProtoField.bytes(PREFIX .. ".fcp", "File control parameters")
M.fcp_file_size = ProtoField.uint32(PREFIX .. ".fcp.file_size", "File size", base.DEC)
M.fcp_total_size = ProtoField.uint32(
    PREFIX .. ".fcp.total_file_size", "Total file size", base.DEC
)
M.fcp_fid = ProtoField.uint16(PREFIX .. ".fcp.fid", "File identifier", base.HEX)
M.fcp_df_name = ProtoField.bytes(PREFIX .. ".fcp.df_name", "DF name (AID)")
M.fcp_sfi = ProtoField.uint8(PREFIX .. ".fcp.sfi", "Short file identifier", base.DEC)
M.fcp_lcsi = ProtoField.uint8(PREFIX .. ".fcp.lcsi", "Life-cycle status", base.HEX)
M.fcp_descriptor = ProtoField.bytes(
    PREFIX .. ".fcp.file_descriptor", "File descriptor"
)
M.fcp_file_type = ProtoField.string(PREFIX .. ".fcp.file_type", "File type")
M.fcp_structure = ProtoField.string(PREFIX .. ".fcp.structure", "EF structure")
M.fcp_record_length = ProtoField.uint32(
    PREFIX .. ".fcp.record_length", "Record length", base.DEC
)
M.fcp_record_count = ProtoField.uint32(
    PREFIX .. ".fcp.record_count", "Record count", base.DEC
)
M.fcp_path = ProtoField.string(PREFIX .. ".fcp.path", "Resolved path")

M.ef_name = ProtoField.string(PREFIX .. ".ef.name", "Elementary file")
M.ef_iccid = ProtoField.string(PREFIX .. ".ef.iccid", "ICCID")
M.ef_imsi = ProtoField.string(PREFIX .. ".ef.imsi", "IMSI")
M.ef_service = ProtoField.string(PREFIX .. ".ef.service", "Service")
M.ef_mnc_length = ProtoField.uint8(
    PREFIX .. ".ef.mnc_length", "MNC length", base.DEC
)
M.ef_operation_mode = ProtoField.uint8(
    PREFIX .. ".ef.operation_mode", "MS operation mode", base.HEX
)

--- Every field, in registration order.
M.all = {
    M.frame_kind, M.raw, M.context_available,
    M.split_command_len, M.split_response_len, M.split_confidence,
    M.split_method, M.split_ambiguous, M.split_candidate,
    M.command, M.cla, M.cla_type, M.cla_channel, M.cla_secure_messaging,
    M.cla_chaining, M.ins, M.command_name, M.command_source,
    M.p1, M.p2, M.lc, M.le, M.le_effective, M.data, M.case,
    M.extended_length, M.risk, M.risk_name,
    M.response, M.response_data, M.sw, M.sw1, M.sw2, M.sw_meaning,
    M.sw_success,
    M.atr, M.atr_ts, M.atr_t0, M.atr_historical_count, M.atr_interface,
    M.atr_protocol, M.atr_historical, M.atr_tck, M.atr_tck_valid,
    M.tlv, M.tlv_tag, M.tlv_base_tag, M.tlv_name, M.tlv_class,
    M.tlv_constructed, M.tlv_length, M.tlv_indefinite, M.tlv_value,
    M.tlv_comprehension, M.tlv_text, M.tlv_uint,
    M.select_fid, M.select_aid, M.select_name, M.select_control,
    M.select_return,
    M.binary_offset, M.binary_sfi,
    M.record_number, M.record_sfi, M.record_mode,
    M.pin_reference, M.pin_name, M.pin_value_len, M.pin_retries,
    M.channel_number, M.channel_operation,
    M.data_object_tag, M.data_object_name,
    M.fcp, M.fcp_file_size, M.fcp_total_size, M.fcp_fid, M.fcp_df_name,
    M.fcp_sfi, M.fcp_lcsi, M.fcp_descriptor, M.fcp_file_type,
    M.fcp_structure, M.fcp_record_length, M.fcp_record_count, M.fcp_path,
    M.ef_name, M.ef_iccid, M.ef_imsi, M.ef_service, M.ef_mnc_length,
    M.ef_operation_mode,
}

return M
