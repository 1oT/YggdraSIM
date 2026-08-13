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

--- Largest chained STORE DATA this will hold before giving up, in bytes.
--
-- GlobalPlatform clause 11.11 ends a chain with the last-block flag in
-- P1, and until it arrives every block is retained. A truncated capture,
-- a dropped final frame, or a card that simply never sets the flag then
-- accumulates without limit -- roughly 1.7 kB per block measured, so a
-- 100 000-block run costs ~166 MB and nothing stops it. A
-- BoundProfilePackage runs to dozens of blocks, not thousands, so a
-- megabyte is far past anything legitimate and well short of harmful.
M.MAX_REASSEMBLY_BYTES = 1024 * 1024

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
        -- The last snapshot that is safe to share, so a run of frames
        -- with identical context stores one table rather than one per
        -- frame; see the dedup in advance. Only a snapshot that no later
        -- backpatch will mutate is ever eligible.
        last_snapshot = nil,
        high_water = 0,
    }
end

--- True when two snapshots carry the same context and neither is one
--- the backpatch may later touch.
--
-- The reassembly fields are checked first: a frame carrying any of them
-- is never shared, because the backpatch in advance mutates its stored
-- table in place. Passing that guard means both snapshots have those
-- keys absent (reassembly_dropped false), so the field-by-field pass
-- below never compares the one table-valued field, reassembly_frames,
-- by identity.
--
-- The comparison iterates the snapshots' own keys rather than a fixed
-- list. A field added to the snapshot later therefore cannot silently
-- fall out of the check and let two frames that differ only in it share
-- a table -- which would render one frame's value on the other, the
-- exact failure rules 1 and 2 above exist to prevent.
local function snapshots_equal(a, b)
    if a == nil or b == nil then
        return false
    end
    if a.reassembled_hex ~= nil or b.reassembled_hex ~= nil
        or a.reassembled_in ~= nil or b.reassembled_in ~= nil
        or a.reassembly_frames ~= nil or b.reassembly_frames ~= nil
        or a.reassembly_dropped or b.reassembly_dropped then
        return false
    end
    for key, value in pairs(a) do
        if b[key] ~= value then
            return false
        end
    end
    for key, value in pairs(b) do
        if a[key] ~= value then
            return false
        end
    end
    return true
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
    local reassembly_dropped = false
    if details.store_data_hex ~= nil then
        if channels.blocks == nil then
            channels.blocks = { parts = {}, frames = {}, bytes = 0 }
        end
        local blocks = channels.blocks
        blocks.parts[#blocks.parts + 1] = details.store_data_hex
        blocks.frames[#blocks.frames + 1] = frame_number
        blocks.bytes = blocks.bytes + math.floor(#details.store_data_hex / 2)
        if blocks.bytes > M.MAX_REASSEMBLY_BYTES and not details.store_data_last then
            -- Drop the chain rather than carry it, and say so. The
            -- alternative is holding every block of a chain whose end
            -- never arrives, which is unbounded by construction.
            channels.blocks = nil
            reassembly_dropped = true
        end
        if details.store_data_last and channels.blocks ~= nil then
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
        reassembly_dropped = reassembly_dropped,
    }
    if reassembled_hex ~= nil then
        snapshot.reassembled_in = frame_number
    end
    if channels.pending_get_response ~= nil then
        snapshot.pending_get_response_frame = channels.pending_get_response.frame
        snapshot.pending_get_response_fid = channels.pending_get_response.fid
    end

    -- Store one table for a run of frames whose context is identical.
    -- selected_fid, selected_aid and sm_protocol change rarely, so on a
    -- long read-heavy or block-heavy capture the overwhelming majority
    -- of frames repeat their predecessor -- roughly 1.7 kB each if every
    -- one is kept. A frame that contributed a STORE DATA block, or whose
    -- snapshot carries a reassembly field, is never shared: the
    -- backpatch above mutates such a frame's stored table in place, and
    -- a shared table would carry that mutation into its neighbours.
    local can_share = details.store_data_hex == nil and reassembled_hex == nil
    local stored = snapshot
    if can_share and snapshots_equal(snapshot, machine.last_snapshot) then
        stored = machine.last_snapshot
    end
    machine.per_frame[frame_number] = stored
    if can_share then
        -- Only a shareable snapshot becomes the anchor, so the backpatch
        -- can never reach one through a later dedup.
        machine.last_snapshot = stored
    end
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
--
-- An empty map is not stored: bip_view falls back to an empty table for
-- a frame with no entry, so the reading is the same either way. Before a
-- channel opens and after the last one closes -- which on most captures
-- is most frames -- this skips a deep_copy of an empty table per frame.
function M.record_bip_frame(machine, frame_number)
    if next(machine.bip) == nil then
        machine.bip_per_frame[frame_number] = nil
        return
    end
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
-- Falls back to any single open channel only when the frame did not name
-- one: SEND DATA often addresses the channel through a device identity
-- this decoder has not tied back to the OPEN CHANNEL, and one open
-- channel is the overwhelmingly common case in a profile download.
--
-- The fallback must not fire when the identifier *is* known and simply
-- has no entry. Letting it through hands a SEND DATA on channel 2 the
-- port channel 1 was opened with, and the port is what decides which
-- dissector the payload goes to -- so the frame is then handed to the
-- wrong one on evidence it never had.
function M.bip_channel(machine, channel_id, frame_number, advancing)
    local view = bip_view(machine, frame_number, advancing)
    if channel_id ~= nil then
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
