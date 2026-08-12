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

--- SGP.22 clause 2.5.2: the BoundProfilePackage's four sections.
local BPP_SECTIONS = {
    [0xA0] = "initialiseSecureChannelRequest",
    [0xA1] = "firstSequenceOf87",
    [0xA2] = "sequenceOf88",
    [0xA3] = "sequenceOf86",
}

function M.bpp_section_name(tag)
    return BPP_SECTIONS[tag] or ""
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

--- TLV walker options that name RSP structures.
function M.tlv_options()
    return {
        resolver = function(tag)
            local section = M.bpp_section_name(tag)
            if section ~= "" then
                return section
            end
            return M.function_name(tag)
        end,
    }
end

-- ------------------------------------------------------------ reassembly
--- Start or extend a chained STORE DATA reassembly.
--
-- GlobalPlatform splits a payload larger than one APDU across numbered
-- blocks with a last-block flag in P1. A BoundProfilePackage routinely
-- runs to dozens of them, and none of the individual blocks is
-- meaningful on its own.
function M.begin_reassembly(channel_state)
    channel_state.blocks = {}
    channel_state.block_frames = {}
    channel_state.total = 0
end

function M.add_block(channel_state, frame_number, hex)
    if channel_state.blocks == nil then
        M.begin_reassembly(channel_state)
    end
    channel_state.blocks[#channel_state.blocks + 1] = hex
    channel_state.block_frames[#channel_state.block_frames + 1] = frame_number
    channel_state.total = channel_state.total + (#hex / 2)
end

--- Return the assembled hex and the frames that contributed it.
function M.finish_reassembly(channel_state)
    if channel_state.blocks == nil or #channel_state.blocks == 0 then
        return "", {}
    end
    local joined = table.concat(channel_state.blocks)
    local frames = channel_state.block_frames
    channel_state.blocks = nil
    channel_state.block_frames = nil
    channel_state.total = 0
    return joined, frames
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
