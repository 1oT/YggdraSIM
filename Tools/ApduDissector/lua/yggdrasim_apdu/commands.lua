-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- Per-instruction interpretation of P1, P2 and the command data field.
--
-- P1 and P2 mean nothing on their own; ISO/IEC 7816-4 gives each
-- instruction its own reading. "P1: 0x04" tells an operator nothing,
-- whereas "select by DF name (AID)" tells them what the terminal asked
-- for. This module turns the former into the latter.
--
-- Returns plain description tables. Rendering stays in the entry point
-- so this module remains side-effect free; see util.lua.

local util = require("yggdrasim_apdu.util")
local tables = require("yggdrasim_apdu.tables")

local M = {}

M.INS_SELECT = 0xA4
M.INS_READ_BINARY = 0xB0
M.INS_READ_RECORD = 0xB2
M.INS_UPDATE_BINARY = 0xD6
M.INS_UPDATE_RECORD = 0xDC
M.INS_GET_RESPONSE = 0xC0
M.INS_VERIFY = 0x20
M.INS_CHANGE_PIN = 0x24
M.INS_DISABLE_PIN = 0x26
M.INS_ENABLE_PIN = 0x28
M.INS_UNBLOCK_PIN = 0x2C
M.INS_MANAGE_CHANNEL = 0x70
M.INS_INTERNAL_AUTHENTICATE = 0x88
M.INS_GET_DATA = 0xCA
M.INS_PUT_DATA = 0xDA
M.INS_STATUS = 0xF2

-- ETSI TS 102 221 clause 11.1.1: SELECT P1, selection control.
local SELECT_CONTROL = {
    [0x00] = "by file identifier",
    [0x01] = "child DF of the current DF",
    [0x03] = "parent DF of the current DF",
    [0x04] = "by DF name (AID)",
    [0x08] = "by path from MF",
    [0x09] = "by path from the current DF",
}

-- SELECT P2, bits 3-1 of the return-data control.
local SELECT_RETURN = {
    [0x00] = "FCI template",
    [0x04] = "FCP template",
    [0x08] = "FMD template",
    [0x0C] = "no data returned",
}

-- ETSI TS 102 221 clause 11.1.5: READ RECORD P2, low three bits.
local RECORD_MODE = {
    [0x02] = "next record",
    [0x03] = "previous record",
    [0x04] = "absolute or current record",
    [0x06] = "absolute, SFI-addressed",
}

--- ETSI TS 102 221 clause 9.4.1 key references.
local function key_reference_name(reference)
    local number = reference % 0x20
    local global = reference < 0x80
    if number == 0 then
        return "no key reference given"
    end
    if number >= 0x01 and number <= 0x08 then
        if global then
            return string.format("global PIN %d", number)
        end
        return string.format("application PIN %d", number)
    end
    if number >= 0x0A and number <= 0x0E then
        return string.format("ADM%d", number - 0x09)
    end
    if number == 0x11 then
        return "universal PIN"
    end
    return string.format("key reference 0x%02X", reference)
end

--- Resolve a file identifier to a friendly path when we know it.
function M.file_name(fid_hex)
    local named = tables.FILE_PATHS[fid_hex]
    if named ~= nil then
        return named
    end
    return ""
end

--- Resolve an application identifier to a friendly name.
function M.aid_name(aid_hex)
    local named = tables.AIDS[aid_hex]
    if named ~= nil then
        return named
    end
    named = tables.AID_PATHS[aid_hex]
    if named ~= nil then
        return named
    end
    local prefix = tables.PROFILE_AID_PREFIX
    if prefix ~= nil and #prefix > 0 and aid_hex:sub(1, #prefix) == prefix then
        return "ISD-P (profile)"
    end
    return ""
end

-- ------------------------------------------------------------------ SELECT
local function describe_select(payload, command)
    local control = SELECT_CONTROL[command.p1]
        or string.format("reserved selection control 0x%02X", command.p1)
    local return_control = SELECT_RETURN[command.p2 % 0x10]
        or string.format("reserved return control 0x%02X", command.p2 % 0x10)

    local description = {
        kind = "select",
        control = control,
        return_control = return_control,
    }

    if command.data_length == 0 then
        return description
    end

    if command.p1 == 0x04 then
        description.aid_hex = util.hex(payload, command.data_offset, command.data_length)
        description.aid_offset = command.data_offset
        description.aid_length = command.data_length
        description.target = M.aid_name(description.aid_hex)
        if description.target == "" then
            description.target = "AID " .. description.aid_hex
        end
        return description
    end

    if command.data_length == 2 then
        local fid = util.safe_uint(payload, command.data_offset, 2)
        if fid ~= nil then
            description.fid = fid
            description.fid_hex = string.format("%04X", fid)
            description.target = M.file_name(description.fid_hex)
            if description.target == "" then
                description.target = "FID " .. description.fid_hex
            end
        end
        return description
    end

    -- A path is a run of two-byte identifiers.
    local parts = {}
    local index = 0
    while index + 1 < command.data_length do
        local element = util.safe_uint(payload, command.data_offset + index, 2)
        if element == nil then
            break
        end
        parts[#parts + 1] = string.format("%04X", element)
        index = index + 2
    end
    if #parts > 0 then
        description.path = table.concat(parts, "/")
        description.target = "path " .. description.path
    end
    return description
end

-- ------------------------------------------------------- binary and record
local function describe_binary(command)
    local description = { kind = "binary" }
    -- ETSI TS 102 221 clause 11.1.3: bit 8 of P1 selects the SFI form.
    if command.p1 >= 0x80 then
        description.sfi = command.p1 % 0x20
        description.offset = command.p2
        description.sfi_addressed = true
    else
        description.offset = (command.p1 * 256) + command.p2
        description.sfi_addressed = false
    end
    return description
end

local function describe_record(command)
    local mode = command.p2 % 0x08
    return {
        kind = "record",
        record = command.p1,
        sfi = math.floor(command.p2 / 8) % 0x20,
        mode = mode,
        mode_name = RECORD_MODE[mode]
            or string.format("reserved record mode 0x%02X", mode),
    }
end

-- --------------------------------------------------------------------- PIN
local function describe_pin(command)
    return {
        kind = "pin",
        reference = command.p2,
        reference_name = key_reference_name(command.p2),
        value_length = command.data_length,
    }
end

-- ----------------------------------------------------------------- channel
local function describe_manage_channel(command)
    local operation = "open"
    if command.p1 == 0x80 then
        operation = "close"
    end
    return {
        kind = "channel",
        operation = operation,
        channel = command.p2,
        -- P2 == 0 on an open means "card, pick a channel for me".
        card_allocates = (operation == "open" and command.p2 == 0),
    }
end

-- ------------------------------------------------------------- data object
local function describe_data_object(command)
    local tag = command.p2
    if command.p1 ~= 0 then
        tag = (command.p1 * 256) + command.p2
    end
    local width = tag > 0xFF and 4 or 2
    local key = string.format("%0" .. tostring(width) .. "X", tag)
    return {
        kind = "data_object",
        tag = tag,
        name = tables.BER_TAGS[key] or "",
    }
end

--- Describe the instruction-specific meaning of P1, P2 and the body.
--
-- Returns nil when the instruction has no special reading, in which case
-- the generic header rendering already says everything there is to say.
function M.describe(payload, command)
    local ins = command.ins
    if ins == M.INS_SELECT then
        return describe_select(payload, command)
    end
    if ins == M.INS_READ_BINARY or ins == M.INS_UPDATE_BINARY then
        return describe_binary(command)
    end
    if ins == M.INS_READ_RECORD or ins == M.INS_UPDATE_RECORD then
        return describe_record(command)
    end
    if ins == M.INS_VERIFY or ins == M.INS_CHANGE_PIN or ins == M.INS_DISABLE_PIN
        or ins == M.INS_ENABLE_PIN or ins == M.INS_UNBLOCK_PIN then
        return describe_pin(command)
    end
    if ins == M.INS_MANAGE_CHANNEL then
        return describe_manage_channel(command)
    end
    if ins == M.INS_GET_DATA or ins == M.INS_PUT_DATA then
        return describe_data_object(command)
    end
    return nil
end

--- A short phrase for the info column, or "".
function M.summary(description)
    if description == nil then
        return ""
    end
    if description.kind == "select" then
        return description.target or description.control
    end
    if description.kind == "binary" then
        if description.sfi_addressed then
            return string.format(
                "SFI %d offset %d", description.sfi, description.offset
            )
        end
        return string.format("offset %d", description.offset)
    end
    if description.kind == "record" then
        return string.format(
            "record %d, %s", description.record, description.mode_name
        )
    end
    if description.kind == "pin" then
        return description.reference_name
    end
    if description.kind == "channel" then
        if description.card_allocates then
            return "open, card allocates"
        end
        return string.format("%s channel %d", description.operation, description.channel)
    end
    if description.kind == "data_object" then
        if description.name ~= "" then
            return description.name
        end
        return string.format("tag 0x%04X", description.tag)
    end
    return ""
end

return M
