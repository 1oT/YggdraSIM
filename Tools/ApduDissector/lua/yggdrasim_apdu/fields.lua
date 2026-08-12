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
}

return M
