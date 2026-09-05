-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- SCP03 / SCP11c secure messaging.
--
-- Two things happen here. The first works with no keys at all: a wrapped
-- APDU has a known shape, so the C-MAC and the ciphertext can be broken
-- out and the security level reported. That alone tells an operator
-- whether the channel is authenticated, encrypted, or both.
--
-- The second needs plaintext, and Wireshark's Lua binding has no AES, no
-- CMAC and no hash, so it cannot produce any. Tools/ApduDissector's
-- sidecar.py does the recovery in Python -- using the same engine the
-- terminal decode view uses -- and writes the result to a file this
-- module reads. That is the difference between this and
-- Tools/EumDiag/dissector.lua, which loads keys it has no way to apply.
--
-- Side-effect free; the sidecar is read lazily on first use, never at
-- module load. See util.lua.

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
local json = require("yggdrasim_apdu.json")
local iso7816 = require("yggdrasim_apdu.iso7816")

local M = {}

M.SIDECAR_FORMAT = "yggdrasim-apdu-sidecar/v1"
M.SIDECAR_ENV_VAR = "YGGDRASIM_APDU_SIDECAR"

--- ISO/IEC 7816-4 clause 5.4.1: CLA bit 3 marks secure messaging.
M.CLA_SECURE_MESSAGING_BIT = 0x04

--- GlobalPlatform: CLA bit 2 additionally marks an encrypted body.
M.CLA_CIPHER_BIT = 0x02

--- SCP03 C-MAC and R-MAC are both truncated to 8 bytes.
M.MAC_LENGTH = 8

local cache = {
    loaded = false,
    path = "",
    frames = nil,
    status = "",
}

--- Discard the cached sidecar. Called from the Proto's init hook so a
--- preference change or a file reload picks up a new file.
function M.reset()
    cache = { loaded = false, path = "", frames = nil, status = "" }
end

--- Load the sidecar named by *preference_path* or the environment.
--
-- Returns ``frames, status``. ``frames`` is nil when nothing usable was
-- found; ``status`` always explains the outcome in one line, because a
-- silent failure here looks exactly like a capture with no secure
-- messaging in it.
function M.sidecar(preference_path)
    local path = preference_path
    if path == nil or path == "" then
        path = os.getenv(M.SIDECAR_ENV_VAR) or ""
    end
    if cache.loaded and cache.path == path then
        return cache.frames, cache.status
    end

    cache = { loaded = true, path = path, frames = nil, status = "" }
    if path == "" then
        cache.status = "no sidecar configured"
        return nil, cache.status
    end

    local document, message = json.read_file(path)
    if document == nil then
        cache.status = "sidecar unreadable: " .. tostring(message)
        return nil, cache.status
    end
    if type(document) ~= "table" then
        cache.status = "sidecar is not a JSON object"
        return nil, cache.status
    end
    if document["format"] ~= M.SIDECAR_FORMAT then
        cache.status = "unsupported sidecar format: " .. tostring(document["format"])
        return nil, cache.status
    end
    local frames = document["frames"]
    if type(frames) ~= "table" then
        cache.status = "sidecar carries no frames"
        return nil, cache.status
    end
    if #frames > 0 then
        -- Frames are keyed by frame number as a string. A JSON array
        -- parses into a table just as happily and then matches nothing,
        -- so without this check the status line reports a successful
        -- load of a sidecar that can never contribute anything.
        cache.status = "sidecar frames is a JSON array, not an object keyed "
            .. "by frame number"
        return nil, cache.status
    end

    local count = 0
    for _ in pairs(frames) do
        count = count + 1
    end
    cache.frames = frames
    cache.status = string.format("loaded %d recovered frame(s) from %s", count, path)
    return cache.frames, cache.status
end

--- The sidecar entry for this frame, if it belongs to this capture.
--
-- The Lua cannot hash, so a sidecar cannot be bound to a capture by
-- digest. Instead each entry carries the on-wire ciphered command, and
-- an entry is used only when those bytes match what is actually in the
-- frame. A sidecar built from a different capture then contributes
-- nothing rather than attributing plaintext to the wrong exchange.
--
-- Returns ``entry, mismatch``.
function M.entry_for(frames, frame_number, observed_command_hex)
    if frames == nil then
        return nil, false
    end
    local entry = frames[tostring(frame_number)]
    if type(entry) ~= "table" then
        return nil, false
    end
    -- Fail closed. An entry with no command_hex cannot be checked, and
    -- an unverifiable entry is exactly the case this test exists for:
    -- accepting it reinstates the "plaintext from another capture" risk
    -- the whole mechanism was built to rule out.
    local expected = tostring(entry["command_hex"] or ""):upper()
    if expected == "" or expected ~= tostring(observed_command_hex):upper() then
        return nil, true
    end
    return entry, false
end

--- Describe the wrapping of a secure-messaging command.
--
-- Returns nil when the class byte says the command is not wrapped.
function M.describe(payload, command)
    -- The class byte is decoded once, by iso7816. Testing bit 3 here
    -- instead disagreed with it in both directions: it missed secure
    -- messaging type '10' (CLA '08' and '88', header not authenticated)
    -- and it invented secure messaging for the further interindustry
    -- classes '44' and '4C', where that bit is part of the channel
    -- number -- carving a phantom eight-byte C-MAC off ordinary data.
    local decoded = command.cla_decoded or iso7816.decode_cla(command.cla)
    if decoded.secure_messaging == nil or decoded.secure_messaging == 0 then
        return nil
    end
    local described = {
        secure_messaging = decoded.secure_messaging,
        -- ISO/IEC 7816-4 Table 3 value '11' is the authenticated-header
        -- form; the payload is enciphered in both '10' and '11'.
        encrypted = decoded.secure_messaging >= 2,
        mac_offset = nil,
        mac_length = 0,
        ciphertext_offset = nil,
        ciphertext_length = 0,
    }
    if command.data_offset ~= nil and command.data_length >= M.MAC_LENGTH then
        described.mac_offset = command.data_offset + command.data_length - M.MAC_LENGTH
        described.mac_length = M.MAC_LENGTH
        described.ciphertext_offset = command.data_offset
        described.ciphertext_length = command.data_length - M.MAC_LENGTH
    end
    return described
end

--- Name the protocol from what INITIALIZE UPDATE reported, if anything.
function M.protocol_name(context)
    if context == nil then
        return "SCP03 or SCP11c"
    end
    local named = context.sm_protocol
    if named ~= nil and named ~= "" then
        return named
    end
    return "SCP03 or SCP11c"
end

-- ------------------------------------------------- EUM session-key bundles
M.EUM_KEYS_FORMAT = "yggdrasim-eum-session-keys/v1"
M.EUM_KEYS_ENV_VAR = "YGGDRASIM_EUM_SESSION_KEYS"

local eum_cache = { loaded = false, entries = nil, status = "" }

function M.reset_eum_keys()
    eum_cache = { loaded = false, entries = nil, status = "" }
end

--- Load an EUM session-key repository, if one is configured.
--
-- ``yggdrasim-eum-diag inject-keys`` writes this file and points the
-- environment at it. The retired Tools/EumDiag/dissector.lua read the
-- same variable, so honouring it here keeps that CLI working.
--
-- The keys are shown, not applied: Wireshark's Lua cannot decrypt. For
-- plaintext, build a sidecar instead. Saying so plainly is the point --
-- the old dissector displayed these bundles beside a BF36 blob in a way
-- that implied it had used them.
function M.eum_keys()
    if eum_cache.loaded then
        return eum_cache.entries, eum_cache.status
    end
    eum_cache = { loaded = true, entries = nil, status = "" }

    local path = os.getenv(M.EUM_KEYS_ENV_VAR) or ""
    if path == "" then
        return nil, ""
    end
    local document, message = json.read_file(path)
    if document == nil then
        eum_cache.status = "EUM key repository unreadable: " .. tostring(message)
        return nil, eum_cache.status
    end
    if type(document) ~= "table" or document["format"] ~= M.EUM_KEYS_FORMAT then
        eum_cache.status = "unsupported EUM key repository format"
        return nil, eum_cache.status
    end
    local entries = document["entries"]
    if type(entries) ~= "table" then
        eum_cache.status = "EUM key repository carries no entries"
        return nil, eum_cache.status
    end
    local count = 0
    for _ in pairs(entries) do
        count = count + 1
    end
    eum_cache.entries = entries
    eum_cache.status = string.format(
        "%d EUM session-key bundle(s) loaded; shown for reference only, "
            .. "Wireshark's Lua cannot decrypt with them. Build a sidecar "
            .. "with `yggdrasim-apdu-dissect sidecar` for plaintext.",
        count
    )
    return eum_cache.entries, eum_cache.status
end

--- Hex from a sidecar entry field, or "".
function M.entry_hex(entry, key)
    if entry == nil then
        return ""
    end
    local value = entry[key]
    if type(value) ~= "string" then
        return ""
    end
    return value
end

return M
