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

function M.parse(text)
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
    local text = handle:read("*a")
    handle:close()
    if text == nil then
        return nil, "cannot read " .. tostring(path)
    end
    return M.parse_safe(text)
end

return M
