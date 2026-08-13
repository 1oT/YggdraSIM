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

-- Wireshark's plugin loader executes every .lua file in its plugin
-- directory standalone, in alphabetical order, so this module can run
-- before the entry point that is supposed to require it -- and before
-- anything has put its own directory on package.path. Each module
-- therefore bootstraps the path itself. Prepending is guarded so a
-- normal require by the entry point does not grow package.path on
-- every load.
local _module_dir = debug.getinfo(1, "S").source:sub(2):match("^(.*)[/\\]") or "."
local _package_root = _module_dir .. "/../?.lua"
if package.path:find(_package_root, 1, true) == nil then
    package.path = _package_root .. ";" .. package.path
end

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
-- GlobalPlatform card specification Table 11-1: a GP command carries
-- class '8X' on logical channels 0 to 3 and '6X' on channels 4 to 19,
-- with the low nibble holding the channel and the secure-messaging bit
-- in both forms. Recognising only '80' and '84' rejected every GP
-- command on a channel above 3, which on a populated eUICC is where an
-- ISD-P is opened.
function M.is_gp_class(cla)
    local high = cla - (cla % 16)
    return high == 0x80 or high == 0x60
end

-- Table 11-47: INSTALL P1 reference control, in ascending bit order so
-- the composed name reads the way GlobalPlatform writes it: INSTALL FOR
-- INSTALL AND MAKE SELECTABLE, not the reverse.
local INSTALL_P1_BITS = {
    { mask = 0x02, name = "LOAD" },
    { mask = 0x04, name = "INSTALL" },
    { mask = 0x08, name = "MAKE SELECTABLE" },
    { mask = 0x10, name = "EXTRADITION" },
    { mask = 0x20, name = "PERSONALIZATION" },
    { mask = 0x40, name = "REGISTRY UPDATE" },
}

--- Name the INSTALL variant, e.g. "INSTALL FOR INSTALL AND MAKE SELECTABLE".
--
-- Bit 8 is not a variant: it says more blocks follow. Folding it into
-- the name produced "INSTALL more blocks follow AND FOR LOAD".
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
    return "INSTALL FOR " .. table.concat(parts, " AND "), parts
end

--- True when INSTALL P1 bit 8 says further blocks follow.
function M.install_more_blocks(p1)
    return math.floor(p1 / 0x80) % 2 == 1
end

-- Table 11-36: GET STATUS P1 scope, bits 8 to 5.
local GET_STATUS_SCOPE = {
    [0x80] = "Issuer Security Domain",
    [0x40] = "applications and Supplementary Security Domains",
    [0x20] = "executable load files",
    [0x10] = "executable load files and their modules",
}

--- Name the GET STATUS scope.
--
-- The scope lives in the high nibble, so it has to be masked out with a
-- clear, not a modulo: ``p1 % 0xF0`` leaves '80' as 128 and '90' as 0,
-- which is not what either byte means.
function M.get_status_scope(p1)
    return GET_STATUS_SCOPE[p1 - (p1 % 16)]
        or string.format("scope 0x%02X", p1)
end

-- Table 11-79: SET STATUS P1. It is a state-transition selector, not the
-- GET STATUS scope, and giving it GET STATUS semantics named '60' -- a
-- Security Domain and its applications -- "scope 0x60".
local SET_STATUS_SCOPE = {
    [0x40] = "application or Supplementary Security Domain",
    [0x60] = "Security Domain and its associated applications",
    [0x80] = "Issuer Security Domain",
}

--- Name the SET STATUS target and the state it is moving to.
function M.set_status_scope(p1)
    return SET_STATUS_SCOPE[p1] or string.format("target 0x%02X", p1)
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

    -- Field order per GlobalPlatform clause 11.5.2.3. Every variant
    -- uses the same six positional slots, but they mean different
    -- things and several are sent empty -- so labelling an extradition
    -- or a registry update with the for-install names reports a
    -- Security Domain AID as an "Executable load file AID" and an empty
    -- slot as a zero-length module.
    local names
    local for_load = math.floor(p1 / 0x02) % 2 == 1
    local for_install = math.floor(p1 / 0x04) % 2 == 1
    local for_extradition = math.floor(p1 / 0x10) % 2 == 1
    local for_personalization = math.floor(p1 / 0x20) % 2 == 1
    local for_registry = math.floor(p1 / 0x40) % 2 == 1
    if for_load and not for_install then
        names = {
            "Load file AID",
            "Security Domain AID",
            "Load file data block hash",
            "Load parameters",
            "Load token",
        }
    elseif for_extradition and not for_install then
        names = {
            "Security Domain AID",
            "(empty)",
            "Application AID",
            "(empty)",
            "Extradition parameters",
            "Extradition token",
        }
    elseif for_registry and not for_install then
        names = {
            "Security Domain AID",
            "(empty)",
            "Application AID",
            "Privileges",
            "Registry update parameters",
            "Registry update token",
        }
    elseif for_personalization and not for_install then
        names = {
            "(empty)",
            "(empty)",
            "Application AID",
            "(empty)",
            "(empty)",
            "Token",
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
-- Every variant opens with 10 bytes of key diversification data, then
-- the key version and the SCP identifier. What follows depends on which
-- protocol that identifier names, and the three layouts share almost
-- nothing:
--
--   SCP01/SCP02 (clause E.5.1): 2-byte sequence counter, 6-byte card
--   challenge, 8-byte card cryptogram -- 28 bytes total. The counter is
--   the first two bytes of what SCP01 calls a plain 8-byte challenge, so
--   for SCP01 the whole 8 bytes are reported as the challenge instead.
--
--   SCP03 (clause D.4.3): i-parameter, 8-byte card challenge, 8-byte
--   card cryptogram, and a 3-byte sequence counter present only when the
--   i-parameter says the pseudo-random challenge variant is in use --
--   bit 5 of 'i'. Keying that on the response length instead reads three
--   bytes of whatever follows as a counter on any longer response.
--
--   SCP11 (amendment F): the response is a GlobalPlatform TLV structure,
--   not a positional record, so nothing beyond the identifier is
--   asserted here rather than inventing offsets for it.
function M.parse_initialize_update_response(tvb, offset, length)
    if length < 28 then
        return nil
    end
    local parsed = {
        key_diversification_offset = offset,
        key_diversification_length = 10,
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
        local i_parameter = parsed.i_parameter or 0
        if math.floor(i_parameter / 0x10) % 2 == 1 and length >= 32 then
            parsed.sequence_counter_offset = offset + 29
            parsed.sequence_counter_length = 3
        end
    elseif parsed.scp_identifier == 0x02 then
        parsed.scp_name = "SCP02"
        parsed.sequence_counter_offset = offset + 12
        parsed.sequence_counter_length = 2
        parsed.card_challenge_offset = offset + 12
        parsed.card_challenge_length = 8
        parsed.card_cryptogram_offset = offset + 20
        parsed.card_cryptogram_length = 8
    elseif parsed.scp_identifier == 0x01 then
        parsed.scp_name = "SCP01"
        parsed.card_challenge_offset = offset + 12
        parsed.card_challenge_length = 8
        parsed.card_cryptogram_offset = offset + 20
        parsed.card_cryptogram_length = 8
    elseif parsed.scp_identifier == 0x11 then
        parsed.scp_name = "SCP11"
        parsed.tlv_response = true
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
            more_blocks = M.install_more_blocks(command.p1),
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

    if ins == M.INS_GET_STATUS then
        return {
            kind = "status",
            scope = M.get_status_scope(command.p1),
            -- P2 bit 2 asks for the next occurrence; bit 1 selects the
            -- TLV response format. Testing the pair for equality with 2
            -- misses '03', which is both at once and by far the more
            -- common spelling on an eUICC.
            next_occurrence = math.floor(command.p2 / 2) % 2 == 1,
            tlv_response = command.p2 % 2 == 1,
        }
    end

    if ins == M.INS_SET_STATUS then
        return {
            kind = "set_status",
            scope = M.set_status_scope(command.p1),
            new_state = command.p2,
            new_state_name = M.lifecycle_name(command.p2),
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
            return "FOR " .. table.concat(parts, " AND ")
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
    if description.kind == "set_status" then
        return string.format(
            "%s -> %s", description.scope, description.new_state_name
        )
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
