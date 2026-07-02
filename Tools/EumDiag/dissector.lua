-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

-- YggdraSIM EUM Diagnostics — Wireshark/tshark Lua dissector.
--
-- Purpose: annotate Bound Profile Package (BF36) frames with the
-- session keys pulled from an EUM server database so Tier-3 engineers
-- can inspect a failed SGP.22 ES9+ download in the terminal.
--
-- Usage:
--   tshark -X lua_script:/path/to/dissector.lua -r capture.pcap
--
-- The dissector expects the environment variable
-- YGGDRASIM_EUM_SESSION_KEYS to point at a repository JSON file
-- written by ``Tools.EumDiag.session_keys.write_repository_atomic``.
-- When the env var is unset or unreadable, the dissector degrades
-- gracefully to pure TLV annotation (no key labels).
--
-- This script is intentionally defensive: every filesystem and
-- format error is caught and turned into a single informational tree
-- item so tshark stays usable even with a broken keys file.

local eum_proto = Proto("yggdrasim_eum_bpp", "YggdraSIM EUM Bound Profile Package")

local f_iccid = ProtoField.bytes("yggdrasim_eum_bpp.iccid", "ICCID")
local f_shs_enc = ProtoField.string("yggdrasim_eum_bpp.shs_enc", "ShS-ENC (hex)")
local f_shs_mac = ProtoField.string("yggdrasim_eum_bpp.shs_mac", "ShS-MAC (hex)")
local f_dek = ProtoField.string("yggdrasim_eum_bpp.dek", "DEK (hex)")
local f_bpp_offset = ProtoField.uint32("yggdrasim_eum_bpp.bf36_offset", "BF36 offset", base.DEC)
local f_bpp_length = ProtoField.uint32("yggdrasim_eum_bpp.bf36_length", "BF36 length", base.DEC)
local f_bpp_bytes = ProtoField.bytes("yggdrasim_eum_bpp.bf36_bytes", "BF36 raw bytes")
local f_status = ProtoField.string("yggdrasim_eum_bpp.status", "status")

eum_proto.fields = {
    f_iccid,
    f_shs_enc,
    f_shs_mac,
    f_dek,
    f_bpp_offset,
    f_bpp_length,
    f_bpp_bytes,
    f_status,
}

local key_path = os.getenv("YGGDRASIM_EUM_SESSION_KEYS") or ""

-- Minimal JSON parser. We deliberately avoid pulling in a
-- third-party library so the dissector stays drop-in on vanilla
-- tshark installs. The parser only handles the strict subset emitted
-- by ``session_keys.write_repository_atomic`` (objects, strings,
-- numbers, booleans, null).
local function parse_json(text)
    local pos = 1

    local function skip_ws()
        while pos <= #text do
            local c = text:sub(pos, pos)
            if c == " " or c == "\t" or c == "\n" or c == "\r" then
                pos = pos + 1
            else
                return
            end
        end
    end

    local parse_value
    local function parse_string()
        if text:sub(pos, pos) ~= "\"" then
            error("expected '\"' at " .. tostring(pos))
        end
        pos = pos + 1
        local buf = {}
        while pos <= #text do
            local c = text:sub(pos, pos)
            pos = pos + 1
            if c == "\"" then
                return table.concat(buf)
            end
            if c == "\\" then
                local esc = text:sub(pos, pos)
                pos = pos + 1
                if esc == "n" then
                    table.insert(buf, "\n")
                elseif esc == "t" then
                    table.insert(buf, "\t")
                elseif esc == "r" then
                    table.insert(buf, "\r")
                elseif esc == "\"" or esc == "\\" or esc == "/" then
                    table.insert(buf, esc)
                else
                    table.insert(buf, esc)
                end
            else
                table.insert(buf, c)
            end
        end
        error("unterminated string")
    end

    local function parse_object()
        pos = pos + 1 -- skip '{'
        local result = {}
        skip_ws()
        if text:sub(pos, pos) == "}" then
            pos = pos + 1
            return result
        end
        while true do
            skip_ws()
            local key = parse_string()
            skip_ws()
            if text:sub(pos, pos) ~= ":" then
                error("expected ':' after key")
            end
            pos = pos + 1
            skip_ws()
            result[key] = parse_value()
            skip_ws()
            local delim = text:sub(pos, pos)
            if delim == "," then
                pos = pos + 1
            elseif delim == "}" then
                pos = pos + 1
                return result
            else
                error("unexpected character in object: " .. delim)
            end
        end
    end

    local function parse_array()
        pos = pos + 1
        local result = {}
        skip_ws()
        if text:sub(pos, pos) == "]" then
            pos = pos + 1
            return result
        end
        while true do
            skip_ws()
            table.insert(result, parse_value())
            skip_ws()
            local delim = text:sub(pos, pos)
            if delim == "," then
                pos = pos + 1
            elseif delim == "]" then
                pos = pos + 1
                return result
            else
                error("unexpected character in array: " .. delim)
            end
        end
    end

    parse_value = function()
        skip_ws()
        local c = text:sub(pos, pos)
        if c == "\"" then
            return parse_string()
        end
        if c == "{" then
            return parse_object()
        end
        if c == "[" then
            return parse_array()
        end
        if c == "t" and text:sub(pos, pos + 3) == "true" then
            pos = pos + 4
            return true
        end
        if c == "f" and text:sub(pos, pos + 4) == "false" then
            pos = pos + 5
            return false
        end
        if c == "n" and text:sub(pos, pos + 3) == "null" then
            pos = pos + 4
            return nil
        end
        local number_end = pos
        while number_end <= #text do
            local d = text:sub(number_end, number_end)
            if d:match("[%d%-+%.eE]") then
                number_end = number_end + 1
            else
                break
            end
        end
        local number_text = text:sub(pos, number_end - 1)
        pos = number_end
        return tonumber(number_text)
    end

    return parse_value()
end

local function load_repository(path)
    if path == "" then
        return nil, "YGGDRASIM_EUM_SESSION_KEYS not set"
    end
    local handle, err = io.open(path, "rb")
    if handle == nil then
        return nil, "cannot open key repository: " .. tostring(err)
    end
    local text = handle:read("*a")
    handle:close()
    local ok, payload = pcall(parse_json, text)
    if ok == false then
        return nil, "key repository parse error: " .. tostring(payload)
    end
    if type(payload) ~= "table" then
        return nil, "key repository must be an object"
    end
    if payload["format"] ~= "yggdrasim-eum-session-keys/v1" then
        return nil, "unsupported key repository format: " .. tostring(payload["format"])
    end
    return payload["entries"] or {}, nil
end

local repository, load_error = load_repository(key_path)

local function find_tag(buf, offset, tag_high, tag_low)
    for i = offset, buf:len() - 2 do
        if buf(i, 1):uint() == tag_high and buf(i + 1, 1):uint() == tag_low then
            return i
        end
    end
    return nil
end

-- BER length decoder: returns (length, length_of_length_field).
local function decode_ber_length(buf, offset)
    if offset >= buf:len() then
        return 0, 0
    end
    local first = buf(offset, 1):uint()
    if first < 0x80 then
        return first, 1
    end
    local count = first - 0x80
    if count == 0 or offset + count >= buf:len() then
        return 0, 0
    end
    local length_value = 0
    for i = 1, count do
        length_value = length_value * 256 + buf(offset + i, 1):uint()
    end
    return length_value, count + 1
end

local function annotate_bpp(tree, buf, bpp_offset)
    local length_start = bpp_offset + 2
    local length_value, length_of_length = decode_ber_length(buf, length_start)
    if length_of_length == 0 then
        tree:add(f_status, "BF36 found but length decode failed")
        return
    end
    local value_start = length_start + length_of_length
    local value_end = value_start + length_value
    if value_end > buf:len() then
        value_end = buf:len()
    end
    tree:add(f_bpp_offset, bpp_offset)
    tree:add(f_bpp_length, length_value)
    if value_end > value_start then
        tree:add(f_bpp_bytes, buf(value_start, value_end - value_start))
    end
end

local function add_keys_subtree(tree)
    if repository == nil then
        tree:add(f_status, "no key repository loaded: " .. tostring(load_error))
        return
    end
    local known = 0
    for iccid, entry in pairs(repository) do
        if type(entry) == "table" then
            local key_tree = tree:add(eum_proto, nil, "session keys for ICCID " .. tostring(iccid))
            key_tree:add(f_iccid, ByteArray.new(tostring(iccid), true):tvb("iccid")(0, #tostring(iccid) / 2))
            key_tree:add(f_shs_enc, tostring(entry["shs_enc_hex"] or ""))
            key_tree:add(f_shs_mac, tostring(entry["shs_mac_hex"] or ""))
            if entry["dek_hex"] ~= nil and entry["dek_hex"] ~= "" then
                key_tree:add(f_dek, tostring(entry["dek_hex"]))
            end
            known = known + 1
        end
    end
    tree:add(f_status, "loaded " .. tostring(known) .. " session-key bundle(s)")
end

-- Dissector proper: hook into TCP so we can walk HTTP-streamed ES9+
-- responses. Operators who already dissect HTTPS should point this
-- dissector at a decrypted upper-layer via ``tshark --enable-heuristic``
-- or by chaining against the ``http`` post-dissector.
function eum_proto.dissector(buf, pinfo, tree)
    if buf:len() < 2 then
        return
    end
    local root = tree:add(eum_proto, buf(0, 0), "YggdraSIM EUM BPP annotations")
    add_keys_subtree(root)
    local search_from = 0
    while true do
        local bpp_offset = find_tag(buf, search_from, 0xBF, 0x36)
        if bpp_offset == nil then
            break
        end
        local sub = root:add(eum_proto, buf(bpp_offset, 2), "BoundProfilePackage (BF36)")
        annotate_bpp(sub, buf, bpp_offset)
        search_from = bpp_offset + 2
    end
    pinfo.cols.protocol:set("EUM-BPP")
end

-- Register as a post-dissector so we layer on top of whatever already
-- parsed the stream (http, tcp, etc.). Post-dissectors run exactly
-- once per packet which is what we want.
register_postdissector(eum_proto)
