-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- Minimal JSON reader.
--
-- Lifted verbatim from Tools/EumDiag/dissector.lua, which is being
-- retired. Keeping it here means one copy rather than two.
--
-- Deliberately not a third-party library: the dissector has to stay
-- drop-in on a vanilla tshark install, where no Lua rock is available.
-- It handles only the strict subset the tools emit -- objects, arrays,
-- strings, numbers, booleans and null.
--
-- Side-effect free; see util.lua.

local M = {}

--- Deepest nesting the parser will follow.
--
-- The parser is recursive, so a document of 300 000 open brackets
-- overflows the Lua stack. A pcall catches that today, but only because
-- this build happens to grow the stack rather than abort; a cap turns an
-- implementation accident into a stated limit.
M.MAX_DEPTH = 64

--- Largest sidecar this will read, in bytes.
--
-- A sidecar is written by Tools/ApduDissector's own sidecar builder, so
-- 64 MiB is far past anything legitimate. Reading a file of unbounded
-- size into a dissector is how an operator points the preference at the
-- wrong path once and loses the Wireshark session.
M.MAX_BYTES = 64 * 1024 * 1024

function M.parse(text)
    local pos = 1
    local depth = 0

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
                elseif esc == "b" then
                    table.insert(buf, "\b")
                elseif esc == "f" then
                    table.insert(buf, "\f")
                elseif esc == "u" then
                    -- \uXXXX. Falling through to the default and
                    -- inserting the letter "u" turned "\u0041BC" into
                    -- "u0041BC", so a hex string carrying an escape
                    -- silently became a different string -- and then
                    -- reported a sidecar mismatch nobody could explain.
                    local hex = text:sub(pos, pos + 3)
                    if #hex < 4 or hex:match("^%x%x%x%x$") == nil then
                        error("bad \\u escape at " .. tostring(pos))
                    end
                    pos = pos + 4
                    local code = tonumber(hex, 16)
                    if code < 0x80 then
                        table.insert(buf, string.char(code))
                    elseif code < 0x800 then
                        table.insert(buf, string.char(
                            0xC0 + math.floor(code / 64), 0x80 + (code % 64)
                        ))
                    else
                        table.insert(buf, string.char(
                            0xE0 + math.floor(code / 4096),
                            0x80 + (math.floor(code / 64) % 64),
                            0x80 + (code % 64)
                        ))
                    end
                elseif esc == "\"" or esc == "\\" or esc == "/" then
                    table.insert(buf, esc)
                else
                    error("unknown escape \\" .. tostring(esc))
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
        if c == "{" or c == "[" then
            depth = depth + 1
            if depth > M.MAX_DEPTH then
                error("nesting deeper than " .. tostring(M.MAX_DEPTH) .. " levels")
            end
            local value
            if c == "{" then
                value = parse_object()
            else
                value = parse_array()
            end
            depth = depth - 1
            return value
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
        local number = tonumber(number_text)
        if number == nil then
            -- Returning nil here reads as "the key was absent" in an
            -- object and truncates an array, so a corrupt document
            -- parses as a valid but shorter one.
            error("malformed number '" .. number_text .. "' at " .. tostring(pos))
        end
        return number
    end

    return parse_value()
end

--- Parse *text*, returning ``value`` or ``nil, message``.
--
-- Every caller is a dissector reading a file it does not control, so a
-- malformed document must produce a message, never an error.
function M.parse_safe(text)
    local ok, result = pcall(M.parse, text)
    if ok == false then
        return nil, tostring(result)
    end
    return result, nil
end

--- Read and parse a file, returning ``value`` or ``nil, message``.
function M.read_file(path)
    if path == nil or path == "" then
        return nil, "no path given"
    end
    local handle, open_error = io.open(path, "rb")
    if handle == nil then
        return nil, "cannot open " .. tostring(path) .. ": " .. tostring(open_error)
    end
    -- The read itself is inside the pcall, not just the parse. An
    -- oversized file raises out of io.read, and an unprotected raise
    -- here leaves the dissector -- and leaks the handle on the way out.
    local ok, text = pcall(function()
        return handle:read(M.MAX_BYTES + 1)
    end)
    handle:close()
    if ok == false then
        return nil, "cannot read " .. tostring(path) .. ": " .. tostring(text)
    end
    if text == nil then
        return nil, "cannot read " .. tostring(path)
    end
    if #text > M.MAX_BYTES then
        return nil, string.format(
            "%s is larger than the %d-byte limit", tostring(path), M.MAX_BYTES
        )
    end
    return M.parse_safe(text)
end

return M
