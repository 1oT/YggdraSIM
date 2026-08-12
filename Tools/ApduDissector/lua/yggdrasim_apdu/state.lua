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
    }
    machine.channels[channel] = created
    return created
end

--- Fold one decoded exchange into the machine and return its snapshot.
--
-- *description* is the command-specific table from commands.describe,
-- or nil.
function M.advance(machine, frame_number, command, response, description)
    local channel = 0
    if command ~= nil and command.cla_decoded ~= nil then
        channel = command.cla_decoded.channel
    end
    local channels = channel_state(machine, channel)

    if description ~= nil and description.kind == "select" then
        -- Only a successful SELECT changes what is selected. A 6A82
        -- leaves the previous selection in place, and treating it as a
        -- move would mis-attribute every following read.
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

    local snapshot = {
        context_available = true,
        channel = channel,
        selected_fid = channels.selected_fid,
        selected_name = channels.selected_name,
        selected_aid = channels.selected_aid,
        aid_name = channels.aid_name,
    }
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
function M.snapshot(machine, frame_number)
    local found = machine.per_frame[frame_number]
    if found == nil then
        return M.STATELESS
    end
    return found
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
