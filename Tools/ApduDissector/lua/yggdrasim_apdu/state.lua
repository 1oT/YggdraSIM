-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- Context that only exists across frames.
--
-- A READ BINARY response is just bytes until you know which file was
-- selected three frames earlier. Wireshark gives a dissector no ordering
-- guarantee, so that context has to be computed once, in capture order,
-- and replayed from a per-frame snapshot afterwards.
--
-- Three rules make that correct, and all three are load-bearing:
--
-- 1. ``pinfo.visited`` alone is not enough. A frame can be visited for
--    the first time out of order -- Tools/HilBridge/live_decode_view
--    builds a detail command with "-Y frame.number==N", so the dissector
--    sees frame N having never seen frames 1..N-1. Advancing the machine
--    there would attribute the wrong file to the read. The high-water
--    mark is what actually enforces sequential advancement.
--
-- 2. Snapshots are copies. Storing a reference into the live machine
--    means the second dissection pass renders a tree built from state
--    that has since moved on, which a user sees as the tree changing
--    when they click a different packet.
--
-- 3. No Tvb is ever stored. A Tvb's lifetime ends with the packet that
--    produced it; reassembly keeps hex and rebuilds a Tvb per visit.
--
-- When no snapshot exists the caller renders without context and says
-- so, which is honest. Inventing a "currently selected file" for a
-- single-frame run would be worse than admitting there is none.
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

local M = {}

--- A snapshot with nothing in it, for frames the machine never reached.
M.STATELESS = {
    context_available = false,
    selected_fid = "",
    selected_name = "",
    selected_aid = "",
    channel = 0,
}

--- Build an empty machine. Called from the Proto's init hook, which
--- Wireshark runs at the start of every dissection run: file open,
--- reload, filter change and preference change alike.
function M.new()
    return {
        per_frame = {},
        channels = {},
        -- BIP channels, keyed by the channel identifier in the device
        -- identity. SEND DATA carries no transport information, so the
        -- port has to come from the OPEN CHANNEL that preceded it.
        bip = {},
        -- What an OPEN CHANNEL asked for, held until the terminal says
        -- which channel it got. See open_bip_channel.
        bip_pending = nil,
        -- Rule 2 applies here as much as anywhere: a re-rendered frame
        -- reads the BIP map as it stood then, not as it stands now.
        bip_per_frame = {},
        high_water = 0,
    }
end

local function channel_state(machine, channel)
    local existing = machine.channels[channel]
    if existing ~= nil then
        return existing
    end
    local created = {
        selected_fid = "",
        selected_name = "",
        selected_aid = "",
        aid_name = "",
        pending_get_response = nil,
        -- Chained STORE DATA, keyed by channel because GlobalPlatform
        -- numbers the blocks per channel.
        blocks = nil,
        sm_protocol = "",
    }
    machine.channels[channel] = created
    return created
end

--- Fold one decoded exchange into the machine and return its snapshot.
--
-- *description* is the command-specific table from commands.describe,
-- or nil.
function M.advance(machine, frame_number, command, response, description, extra)
    local channel = 0
    if command ~= nil and command.cla_decoded ~= nil then
        channel = command.cla_decoded.channel or 0
    end
    local channels = channel_state(machine, channel)
    local details = extra or {}

    if description ~= nil and description.kind == "select"
        and description.secure_messaged ~= true then
        -- Only a successful SELECT changes what is selected. A 6A82
        -- leaves the previous selection in place, and treating it as a
        -- move would mis-attribute every following read.
        --
        -- A secure-messaged SELECT is excluded for the same reason: its
        -- body is ciphertext, so whatever "file identifier" was read out
        -- of it is not one. Committing that poisons every following read
        -- in the channel while still reporting context as available.
        if response ~= nil and response.succeeded then
            if description.aid_hex ~= nil then
                channels.selected_aid = description.aid_hex
                channels.aid_name = description.target or ""
                channels.selected_fid = ""
                channels.selected_name = description.target or ""
            elseif description.fid_hex ~= nil then
                channels.selected_fid = description.fid_hex
                channels.selected_name = description.target or ""
            elseif description.path ~= nil then
                -- The last element of a path is the file that ends up
                -- selected.
                local last = description.path:match("([0-9A-F]+)$")
                if last ~= nil then
                    channels.selected_fid = last
                    channels.selected_name = description.target or ""
                end
            end
        end
    end

    if description ~= nil and description.kind == "channel" then
        if description.operation == "close" then
            machine.channels[description.channel] = nil
        end
    end

    -- 61XX means the body is waiting behind a GET RESPONSE, so the file
    -- context has to survive into the next frame.
    if response ~= nil and response.sw1 == 0x61 and command ~= nil then
        channels.pending_get_response = {
            ins = command.ins,
            fid = channels.selected_fid,
            frame = frame_number,
        }
    elseif command ~= nil and command.ins ~= 0xC0 then
        channels.pending_get_response = nil
    end

    -- The SCP in use is only ever stated once, in the INITIALIZE UPDATE
    -- response. Every wrapped command after it is just a class byte with
    -- bit 3 set, so without carrying this forward the tree reports
    -- "SCP03 or SCP11c" on a channel whose protocol the capture already
    -- named unambiguously.
    if details.scp_name ~= nil and details.scp_name ~= "" then
        channels.sm_protocol = details.scp_name
    end
    if details.security_level ~= nil then
        channels.sm_level = details.security_level
    end

    -- Chained STORE DATA. GlobalPlatform clause 11.11 splits a payload
    -- larger than one APDU across numbered blocks with a last-block flag
    -- in P1, and a BoundProfilePackage routinely runs to dozens of them.
    -- None of the blocks means anything on its own, which is why an
    -- unassembled ES8+ chain renders as N unrelated byte strings.
    local reassembled_hex = nil
    local reassembly_frames = nil
    if details.store_data_hex ~= nil then
        if channels.blocks == nil then
            channels.blocks = { parts = {}, frames = {} }
        end
        local blocks = channels.blocks
        blocks.parts[#blocks.parts + 1] = details.store_data_hex
        blocks.frames[#blocks.frames + 1] = frame_number
        if details.store_data_last then
            reassembled_hex = table.concat(blocks.parts)
            reassembly_frames = blocks.frames
            channels.blocks = nil
            -- Point every contributing frame at the one that completes
            -- the chain. Wireshark renders a frame more than once, so an
            -- earlier frame picks the link up on its next visit -- the
            -- same way the built-in reassembly machinery behaves.
            for index = 1, #reassembly_frames do
                local member = machine.per_frame[reassembly_frames[index]]
                if member ~= nil then
                    member.reassembled_in = frame_number
                end
            end
        end
    end

    local snapshot = {
        context_available = true,
        channel = channel,
        selected_fid = channels.selected_fid,
        selected_name = channels.selected_name,
        selected_aid = channels.selected_aid,
        aid_name = channels.aid_name,
        sm_protocol = channels.sm_protocol,
        sm_level = channels.sm_level,
        reassembled_hex = reassembled_hex,
        reassembly_frames = reassembly_frames,
    }
    if reassembled_hex ~= nil then
        snapshot.reassembled_in = frame_number
    end
    if channels.pending_get_response ~= nil then
        snapshot.pending_get_response_frame = channels.pending_get_response.frame
        snapshot.pending_get_response_fid = channels.pending_get_response.fid
    end

    machine.per_frame[frame_number] = snapshot
    if frame_number > machine.high_water then
        machine.high_water = frame_number
    end
    -- Returned as a copy so no caller can reach back into the machine.
    return util.shallow_copy(snapshot)
end

--- Record what an OPEN CHANNEL asked for.
--
-- The channel does not exist yet at this point. ETSI TS 102 223 clause
-- 6.4.27 has OPEN CHANNEL addressed UICC to terminal ('81' to '82'), and
-- it is the terminal that allocates the identifier and reports it back
-- in the Channel status TLV of its TERMINAL RESPONSE. Trying to read a
-- channel number out of the command's own device identities therefore
-- always fails, and nothing is ever recorded -- which is why DNS and
-- plaintext HTTP inside a BIP channel stayed invisible.
function M.open_bip_channel(machine, port, transport)
    machine.bip_pending = { port = port, transport = transport }
end

--- Bind the pending OPEN CHANNEL to the identifier the terminal chose.
function M.bind_bip_channel(machine, channel_id)
    if channel_id == nil or channel_id == 0 then
        return
    end
    local pending = machine.bip_pending
    if pending == nil then
        return
    end
    machine.bip[channel_id] = { port = pending.port, transport = pending.transport }
    machine.bip_pending = nil
end

--- Forget a channel the terminal closed.
function M.close_bip_channel(machine, channel_id)
    if channel_id ~= nil then
        machine.bip[channel_id] = nil
    end
end

--- Freeze the BIP map for *frame_number*.
function M.record_bip_frame(machine, frame_number)
    machine.bip_per_frame[frame_number] = util.deep_copy(machine.bip)
end

--- The BIP map as it stood at *frame_number*.
--
-- An advancing frame reads the live map; any other frame reads its own
-- snapshot, so clicking back through a capture in the GUI cannot show a
-- port learned from a later OPEN CHANNEL.
local function bip_view(machine, frame_number, advancing)
    if advancing then
        return machine.bip
    end
    return machine.bip_per_frame[frame_number] or {}
end

--- What a BIP channel was opened with: ``port`` and ``transport``, or nil.
--
-- Falls back to any single open channel: SEND DATA often addresses the
-- channel through a device identity this decoder has not tied back to
-- the OPEN CHANNEL, and one open channel is the overwhelmingly common
-- case in a profile download.
function M.bip_channel(machine, channel_id, frame_number, advancing)
    local view = bip_view(machine, frame_number, advancing)
    if channel_id ~= nil and view[channel_id] ~= nil then
        return view[channel_id]
    end
    local found = nil
    local count = 0
    for _, entry in pairs(view) do
        count = count + 1
        found = entry
    end
    if count == 1 then
        return found
    end
    return nil
end

--- True when this frame may advance the machine.
--
-- Both conditions are required. See rule 1 above.
function M.may_advance(machine, frame_number, visited)
    if visited then
        return false
    end
    return frame_number > machine.high_water
end

--- The snapshot for a frame, or the stateless placeholder.
--
-- Copied on the way out, like the one M.advance returns. Handing back
-- the stored table -- or the module-global STATELESS -- would let one
-- caller's edit change what every later frame sees, which is the
-- invariant rule 2 depends on.
function M.snapshot(machine, frame_number)
    local found = machine.per_frame[frame_number]
    if found == nil then
        return util.shallow_copy(M.STATELESS)
    end
    return util.shallow_copy(found)
end

--- The file identifier whose contents a response body belongs to.
--
-- For a GET RESPONSE that is the file selected when the 61XX was
-- returned, not whatever is selected now.
function M.response_file(snapshot, command)
    if snapshot == nil or snapshot.context_available ~= true then
        return ""
    end
    if command ~= nil and command.ins == 0xC0 then
        return snapshot.pending_get_response_fid or snapshot.selected_fid or ""
    end
    return snapshot.selected_fid or ""
end

return M
