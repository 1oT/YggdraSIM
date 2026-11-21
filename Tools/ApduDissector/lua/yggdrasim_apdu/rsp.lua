-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- GSMA SGP.22 / SGP.32 Remote SIM Provisioning.
--
-- ES10a, ES10b and ES10c ride inside STORE DATA to the ISD-R. Each
-- function is a BFxx context tag, so the generic TLV walker already
-- produces the structure; what this module adds is the knowledge that a
-- STORE DATA to that AID *is* an ES10 call, the function names, and
-- reassembly of the chains too long for one APDU.
--
-- The BoundProfilePackage (BF36) is the reason the existing EumDiag
-- dissector exists, and the reason it is not enough: that one byte-scans
-- for the tag and dumps the value as a blob. Here the outer structure is
-- a tree even while the segments inside it are still ciphered.
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

M.TAG_BOUND_PROFILE_PACKAGE = 0xBF36

--- ISD-R AID. Looked up from the generated table so the two cannot drift.
function M.isdr_aid()
    for aid_hex, name in pairs(tables.AIDS) do
        if name == "ISD-R" then
            return aid_hex
        end
    end
    return ""
end

--- The hex key the generated tables use for a tag.
local function tag_key(tag)
    if tag > 0xFF then
        return string.format("%04X", tag)
    end
    return string.format("%02X", tag)
end

--- Name an ES10 function from its context tag.
function M.function_name(tag)
    local width = tag > 0xFF and 4 or 2
    local key = string.format("%0" .. tostring(width) .. "X", tag)
    return tables.BER_TAGS[key] or ""
end

--- True when the tag is one of the SGP BFxx function tags.
function M.is_rsp_function(tag)
    if tag < 0xBF00 or tag > 0xBFFF then
        return false
    end
    return M.function_name(tag) ~= ""
end

--- Name a member of an RSP structure, and say what it opens.
--
-- Returns the ASN.1 field name and the type its children belong to, both
-- empty when *structure* does not declare *tag*. The structure is what
-- makes a name safe to give: 'A0' is firstSequenceOf87 in a
-- BoundProfilePackage, profileInfoListOk in a ProfileInfoListResponse
-- and an ordinary constructed context tag in the Type-2 file list of an
-- EF.PBR record, and only the enclosing type tells them apart.
function M.member(structure, tag)
    if structure == nil or structure == "" then
        return "", nil
    end
    local key = tag_key(tag)
    local names = tables.RSP_MEMBERS[structure]
    if names == nil then
        return "", nil
    end
    local opens = tables.RSP_MEMBER_TYPES[structure]
    return names[key] or "", opens ~= nil and opens[key] or nil
end

--- The RSP structure an ES10 function tag opens, or nil.
function M.structure_of(tag)
    if not M.is_rsp_function(tag) then
        return nil
    end
    return tables.RSP_ROOTS[tag_key(tag)]
end

--- TLV walker options that name RSP structures.
--
-- At the top of the payload the function tag names itself and opens its
-- own type; below that every name comes from the enclosing type, so a
-- tag is never named on its own account.
function M.tlv_options()
    return {
        resolver = function(tag, _raw, _level, _parent, structure)
            if structure == nil or structure == "" then
                return M.function_name(tag), M.structure_of(tag)
            end
            local name, opened = M.member(structure, tag)
            if name ~= "" then
                return name, opened
            end
            return M.function_name(tag), M.structure_of(tag)
        end,
    }
end

--- Describe the ES10 call a STORE DATA carries, if any.
--
-- Returns nil when the command is not addressed to the ISD-R or the
-- payload does not begin with a recognised function tag.
function M.describe(payload, command, context)
    if command.data_offset == nil or command.data_length == 0 then
        return nil
    end
    local selected_aid = ""
    if context ~= nil then
        selected_aid = context.selected_aid or ""
    end
    local first = util.byte_at(payload, command.data_offset)
    local second = util.byte_at(payload, command.data_offset + 1)
    if first == nil or second == nil then
        return nil
    end
    local tag = (first * 256) + second
    if not M.is_rsp_function(tag) then
        return nil
    end
    return {
        kind = "rsp",
        tag = tag,
        name = M.function_name(tag),
        is_bpp = (tag == M.TAG_BOUND_PROFILE_PACKAGE),
        addressed_to_isdr = (selected_aid == M.isdr_aid()),
    }
end

return M
