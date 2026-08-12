-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- GlobalPlatform Card Specification 2.3.1 command bodies.
--
-- These are the commands that install applets, manage the card registry
-- and open a secure channel. Their data fields are mostly *positional*
-- length-prefixed runs rather than TLV, which is why the generic walker
-- cannot read them: INSTALL FOR INSTALL is a sequence of
-- length-then-value fields whose meaning comes from position alone.
--
-- Verb spelling follows the specification exactly, as
-- site-docs/internals/coding-standards.md requires: INSTALL FOR LOAD,
-- INSTALL FOR INSTALL, INSTALL FOR MAKE SELECTABLE.
--
-- Side-effect free; see util.lua.

local util = require("yggdrasim_apdu.util")
local tables = require("yggdrasim_apdu.tables")

local M = {}

M.INS_INITIALIZE_UPDATE = 0x50
M.INS_EXTERNAL_AUTHENTICATE = 0x82
M.INS_INSTALL = 0xE6
M.INS_LOAD = 0xE8
M.INS_DELETE = 0xE4
M.INS_GET_STATUS = 0xF2
M.INS_SET_STATUS = 0xF0
M.INS_PUT_KEY = 0xD8
M.INS_STORE_DATA = 0xE2

--- True when the class byte marks a GlobalPlatform command.
--
-- GP uses 0x80 and 0x84 (the latter with secure messaging), plus the
-- logical-channel variants of both.
function M.is_gp_class(cla)
    local base = cla - (cla % 4)
    return base == 0x80 or base == 0x84
end

-- Table 11-47: INSTALL P1 reference control.
local INSTALL_P1_BITS = {
    { mask = 0x80, name = "more blocks follow" },
    { mask = 0x40, name = "FOR REGISTRY UPDATE" },
    { mask = 0x20, name = "FOR PERSONALIZATION" },
    { mask = 0x10, name = "FOR EXTRADITION" },
    { mask = 0x08, name = "FOR MAKE SELECTABLE" },
    { mask = 0x04, name = "FOR INSTALL" },
    { mask = 0x02, name = "FOR LOAD" },
}

--- Name the INSTALL variant, e.g. "INSTALL FOR INSTALL AND MAKE SELECTABLE".
function M.install_variant(p1)
    local parts = {}
    for index = 1, #INSTALL_P1_BITS do
        local entry = INSTALL_P1_BITS[index]
        if math.floor(p1 / entry.mask) % 2 == 1 then
            parts[#parts + 1] = entry.name
        end
    end
    if #parts == 0 then
        return "INSTALL", parts
    end
    return "INSTALL " .. table.concat(parts, " AND "), parts
end

-- Table 11-36: GET STATUS P1 scope.
local GET_STATUS_SCOPE = {
    [0x80] = "Issuer Security Domain",
    [0x40] = "applications and Supplementary Security Domains",
    [0x20] = "executable load files",
    [0x10] = "executable load files and their modules",
}

function M.get_status_scope(p1)
    return GET_STATUS_SCOPE[p1 % 0xF0]
        or GET_STATUS_SCOPE[p1]
        or string.format("scope 0x%02X", p1)
end

--- Table 11-58: EXTERNAL AUTHENTICATE P1 security level.
function M.security_level(p1)
    if p1 == 0 then
        return "no secure messaging", {}
    end
    local parts = {}
    if math.floor(p1 / 0x20) % 2 == 1 then
        parts[#parts + 1] = "R-ENCRYPTION"
    end
    if math.floor(p1 / 0x10) % 2 == 1 then
        parts[#parts + 1] = "R-MAC"
    end
    if math.floor(p1 / 0x02) % 2 == 1 then
        parts[#parts + 1] = "C-DECRYPTION"
    end
    if p1 % 2 == 1 then
        parts[#parts + 1] = "C-MAC"
    end
    if #parts == 0 then
        return string.format("security level 0x%02X", p1), parts
    end
    return table.concat(parts, " + "), parts
end

--- STORE DATA P1, GlobalPlatform table 11-86.
function M.store_data_control(p1)
    local structure = math.floor(p1 / 8) % 4
    local structure_name = "no general encoding"
    if structure == 1 then
        structure_name = "DGI format"
    elseif structure == 2 then
        structure_name = "BER-TLV format"
    end
    local encryption = math.floor(p1 / 32) % 4
    local encryption_name = "no encryption information"
    if encryption == 1 then
        encryption_name = "application-dependent encryption"
    elseif encryption == 3 then
        encryption_name = "encrypted data"
    end
    return {
        last_block = math.floor(p1 / 128) % 2 == 1,
        structure = structure_name,
        encryption = encryption_name,
        response_expected = p1 % 2 == 1,
    }
end

--- Read a positional length-prefixed field.
--
-- Returns ``value_offset, value_length, next_offset`` or nil. A single
-- length byte covers everything GlobalPlatform puts in an INSTALL, and
-- reading past the command is treated as malformed rather than clamped:
-- a positional parse that has lost alignment produces nonsense, not
-- partial truth.
function M.read_lv(tvb, offset, limit)
    if offset >= limit then
        return nil
    end
    local length = util.byte_at(tvb, offset)
    if length == nil then
        return nil
    end
    local value_offset = offset + 1
    if value_offset + length > limit then
        return nil
    end
    return value_offset, length, value_offset + length
end

--- Parse an INSTALL data field into named positional fields.
function M.parse_install(tvb, offset, length, p1)
    local limit = offset + length
    local variant, parts = M.install_variant(p1)
    local parsed = { variant = variant, parts = parts, fields = {} }

    -- Field order per GlobalPlatform clause 11.5.2.3.
    local names
    if math.floor(p1 / 0x02) % 2 == 1 and math.floor(p1 / 0x04) % 2 == 0 then
        -- FOR LOAD only.
        names = {
            "Load file AID",
            "Security Domain AID",
            "Load file data block hash",
            "Load parameters",
            "Load token",
        }
    else
        names = {
            "Executable load file AID",
            "Executable module AID",
            "Application AID",
            "Privileges",
            "Install parameters",
            "Install token",
        }
    end

    local cursor = offset
    for index = 1, #names do
        local value_offset, value_length, next_offset = M.read_lv(tvb, cursor, limit)
        if value_offset == nil then
            break
        end
        parsed.fields[#parsed.fields + 1] = {
            name = names[index],
            offset = value_offset,
            length = value_length,
        }
        cursor = next_offset
    end
    parsed.consumed = cursor - offset
    parsed.complete = (cursor == limit)
    return parsed
end

--- Parse the INITIALIZE UPDATE response, GlobalPlatform clause 11.5.
--
-- 28 bytes for SCP02, 32 for SCP03 with the pseudo-random challenge
-- variant. The key information block says which.
function M.parse_initialize_update_response(tvb, offset, length)
    if length < 28 then
        return nil
    end
    local parsed = {
        key_diversification_offset = offset,
        key_version = util.byte_at(tvb, offset + 10),
        scp_identifier = util.byte_at(tvb, offset + 11),
    }
    if parsed.scp_identifier == 0x03 then
        parsed.scp_name = "SCP03"
        parsed.i_parameter = util.byte_at(tvb, offset + 12)
        parsed.card_challenge_offset = offset + 13
        parsed.card_challenge_length = 8
        parsed.card_cryptogram_offset = offset + 21
        parsed.card_cryptogram_length = 8
        if length >= 32 then
            parsed.sequence_counter_offset = offset + 29
            parsed.sequence_counter_length = 3
        end
    elseif parsed.scp_identifier == 0x02 then
        parsed.scp_name = "SCP02"
        parsed.sequence_counter_offset = offset + 12
        parsed.sequence_counter_length = 2
        parsed.card_challenge_offset = offset + 14
        parsed.card_challenge_length = 6
        parsed.card_cryptogram_offset = offset + 20
        parsed.card_cryptogram_length = 8
    elseif parsed.scp_identifier == 0x11 then
        parsed.scp_name = "SCP11"
        parsed.card_challenge_offset = offset + 12
        parsed.card_challenge_length = 8
    else
        parsed.scp_name = string.format("SCP 0x%02X", parsed.scp_identifier or 0)
    end
    return parsed
end

--- Name a GlobalPlatform registry life-cycle byte.
function M.lifecycle_name(value)
    local named = tables.GP_LIFECYCLE[value]
    if named ~= nil then
        return named
    end
    return string.format("0x%02X", value)
end

--- Describe a GlobalPlatform command, or nil when the instruction is
--- not one this module handles.
function M.describe(payload, command)
    if not M.is_gp_class(command.cla) then
        return nil
    end
    local ins = command.ins

    if ins == M.INS_INSTALL then
        local parsed = nil
        if command.data_offset ~= nil and command.data_length > 0 then
            parsed = M.parse_install(
                payload, command.data_offset, command.data_length, command.p1
            )
        end
        local variant, parts = M.install_variant(command.p1)
        return {
            kind = "install",
            variant = variant,
            parts = parts,
            install = parsed,
        }
    end

    if ins == M.INS_LOAD then
        return {
            kind = "load",
            last_block = math.floor(command.p1 / 128) % 2 == 1,
            block_number = command.p2,
        }
    end

    if ins == M.INS_STORE_DATA then
        local control = M.store_data_control(command.p1)
        control.kind = "store_data"
        control.block_number = command.p2
        return control
    end

    if ins == M.INS_GET_STATUS or ins == M.INS_SET_STATUS then
        return {
            kind = "status",
            scope = M.get_status_scope(command.p1),
            next_occurrence = (command.p2 % 4) == 2,
        }
    end

    if ins == M.INS_EXTERNAL_AUTHENTICATE then
        local level, parts = M.security_level(command.p1)
        return { kind = "external_authenticate", level = level, parts = parts }
    end

    if ins == M.INS_INITIALIZE_UPDATE then
        return { kind = "initialize_update", key_version = command.p1 }
    end

    if ins == M.INS_PUT_KEY then
        return {
            kind = "put_key",
            key_version = command.p1,
            key_identifier = command.p2 % 0x80,
            multiple = command.p2 >= 0x80,
        }
    end

    if ins == M.INS_DELETE then
        return { kind = "delete", related = command.p2 >= 0x80 }
    end

    return nil
end

--- A short phrase for the info column.
function M.summary(description)
    if description == nil then
        return ""
    end
    if description.kind == "install" then
        -- The info column already carries the instruction name, so
        -- returning the full variant would render "INSTALL INSTALL FOR
        -- LOAD". Only the qualifying half belongs here.
        local parts = description.parts or {}
        if #parts > 0 then
            return table.concat(parts, " AND ")
        end
        return ""
    end
    if description.kind == "load" then
        local suffix = ""
        if description.last_block then
            suffix = ", last"
        end
        return string.format("block %d%s", description.block_number, suffix)
    end
    if description.kind == "store_data" then
        local suffix = ""
        if description.last_block then
            suffix = ", last"
        end
        return string.format("block %d%s", description.block_number, suffix)
    end
    if description.kind == "status" then
        return description.scope
    end
    if description.kind == "external_authenticate" then
        return description.level
    end
    if description.kind == "initialize_update" then
        return string.format("key version %d", description.key_version)
    end
    if description.kind == "put_key" then
        return string.format(
            "key version %d, identifier %d",
            description.key_version, description.key_identifier
        )
    end
    return ""
end

return M
