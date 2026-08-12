-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- Bounds-safe reads and small formatting helpers.
--
-- Every byte this dissector reads came off a wire it does not control
-- and may be truncated, over-long, or hostile. A Lua error inside a
-- dissector aborts the frame and prints a stack trace into tshark's
-- output, so no decoder here is allowed to index past the captured end.
-- These helpers return nil instead, and each caller treats nil as "stop,
-- add the expert info, show the raw bytes".
--
-- This module must stay side-effect free: Wireshark's plugin loader
-- walks its plugin directory recursively and executes every .lua file it
-- finds as a top-level script, so running this one standalone has to be
-- harmless.

local M = {}

--- Bytes still readable at *offset*, clamped at zero.
function M.remaining(tvb, offset)
    if tvb == nil or offset == nil then
        return 0
    end
    local available = tvb:captured_len() - offset
    if available < 0 then
        return 0
    end
    return available
end

--- True when *length* bytes can be read at *offset*.
function M.can_read(tvb, offset, length)
    return offset >= 0 and length >= 0 and M.remaining(tvb, offset) >= length
end

--- A TvbRange, or nil when the read would run past the captured data.
function M.safe_range(tvb, offset, length)
    if not M.can_read(tvb, offset, length) then
        return nil
    end
    local ok, range = pcall(function()
        return tvb(offset, length)
    end)
    if ok == false then
        return nil
    end
    return range
end

--- An unsigned integer, or nil when the read would overrun.
function M.safe_uint(tvb, offset, length)
    local range = M.safe_range(tvb, offset, length)
    if range == nil then
        return nil
    end
    local ok, value = pcall(function()
        return range:uint()
    end)
    if ok == false then
        return nil
    end
    return value
end

--- A single byte, or nil.
function M.byte_at(tvb, offset)
    return M.safe_uint(tvb, offset, 1)
end

--- Uppercase hex for a byte range, or "" when unreadable.
function M.hex(tvb, offset, length)
    local range = M.safe_range(tvb, offset, length)
    if range == nil then
        return ""
    end
    local ok, text = pcall(function()
        return range:bytes():tohex()
    end)
    if ok == false then
        return ""
    end
    return text
end

--- Uppercase hex for a Lua array of byte values.
function M.hex_from_bytes(values)
    local parts = {}
    for index = 1, #values do
        parts[index] = string.format("%02X", values[index] % 256)
    end
    return table.concat(parts)
end

--- Read *length* bytes at *offset* into a plain Lua array, or nil.
function M.byte_array(tvb, offset, length)
    if not M.can_read(tvb, offset, length) then
        return nil
    end
    local values = {}
    for index = 0, length - 1 do
        local value = M.byte_at(tvb, offset + index)
        if value == nil then
            return nil
        end
        values[index + 1] = value
    end
    return values
end

--- Decode swapped-nibble BCD, the encoding EF.ICCID and IMSI digits use.
--
-- Padding nibbles of 0xF are dropped. An odd digit count is normal --
-- a 19-digit ICCID leaves a trailing 0xF -- and must not be treated as
-- an error, which is precisely where Tools/EumDiag/dissector.lua went
-- wrong by dividing the digit count by two.
function M.decode_swapped_bcd(values)
    if values == nil then
        return ""
    end
    local digits = {}
    for index = 1, #values do
        local byte_value = values[index]
        local low = byte_value % 16
        local high = math.floor(byte_value / 16)
        if low ~= 0x0F then
            digits[#digits + 1] = string.format("%X", low)
        end
        if high ~= 0x0F then
            digits[#digits + 1] = string.format("%X", high)
        end
    end
    return table.concat(digits)
end

--- Render a byte count with the right plural, for tree item text.
function M.plural_bytes(count)
    if count == 1 then
        return "1 byte"
    end
    return tostring(count) .. " bytes"
end

--- Look a value up in a generated table, falling back to a hex label.
function M.lookup(mapping, key, width)
    if mapping ~= nil then
        local found = mapping[key]
        if found ~= nil then
            return found
        end
    end
    return string.format("Unknown (0x%0" .. tostring(width or 2) .. "X)", key or 0)
end

--- Trim a string for use in the info column.
function M.clip(text, width)
    local value = tostring(text or "")
    if #value <= width then
        return value
    end
    return value:sub(1, math.max(1, width - 3)) .. "..."
end

--- Shallow-copy a table. Snapshots stored per frame must not alias the
--- running state machine, or a second dissection pass renders a tree
--- built from mutated values.
function M.shallow_copy(source)
    if source == nil then
        return nil
    end
    local copy = {}
    for key, value in pairs(source) do
        copy[key] = value
    end
    return copy
end

--- Deep-copy a table of plain values, arrays and nested tables.
function M.deep_copy(source, depth)
    local level = depth or 0
    if type(source) ~= "table" or level > 8 then
        return source
    end
    local copy = {}
    for key, value in pairs(source) do
        copy[key] = M.deep_copy(value, level + 1)
    end
    return copy
end

return M
