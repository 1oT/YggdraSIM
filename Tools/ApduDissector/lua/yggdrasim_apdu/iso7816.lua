-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- ISO/IEC 7816-4 command and response decoding, plus ISO 7816-3 ATR.
--
-- This is the layer the stock gsm_sim dissector already covers in part;
-- what it adds is the class-byte breakdown, the case classification, the
-- status-word families that carry a count in SW2, and the risk class
-- that makes "show me every destructive command in this capture" a
-- one-line display filter.
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
local fields = require("yggdrasim_apdu.fields")

local M = {}

-- ------------------------------------------------------------------- CLA
--- Decode the class byte per ISO/IEC 7816-4 clause 5.4.1.
--
-- Two logical-channel encodings exist. The first interindustry form
-- carries channels 0-3 in the low two bits; the further form, marked by
-- bits 8-7 being 01, carries channels 4-19 in the low four bits.
function M.decode_cla(cla)
    local decoded = {
        value = cla,
        proprietary = false,
        channel = 0,
        secure_messaging = 0,
        chaining = false,
        extended_channel = false,
    }

    if cla == 0xFF then
        -- Reserved by ISO/IEC 7816-4 as an invalid class byte.
        decoded.invalid = true
        return decoded
    end

    local high = math.floor(cla / 16)
    if high >= 0x0A and high ~= 0x0F then
        decoded.proprietary = true
    elseif high >= 0x08 then
        decoded.proprietary = true
    end

    if math.floor(cla / 64) % 4 == 1 then
        -- 01xxxxxx: further interindustry, channels 4..19.
        decoded.extended_channel = true
        decoded.channel = 4 + (cla % 16)
        decoded.secure_messaging = (math.floor(cla / 32) % 2) == 1 and 3 or 0
        decoded.chaining = (math.floor(cla / 16) % 2) == 1
        return decoded
    end

    decoded.channel = cla % 4
    decoded.secure_messaging = math.floor(cla / 4) % 4
    decoded.chaining = (math.floor(cla / 16) % 2) == 1
    return decoded
end

--- Resolve the command name, mirroring _lookup_apdu_command in
--- Tools/Asn1TlvDecode/main.py: class-qualified first, then the class
--- with its channel and secure-messaging bits masked off, then the bare
--- instruction.
function M.command_name(cla, ins)
    local qualified = tables.CLA_INS_NAMES[(cla * 256) + ins]
    if qualified ~= nil then
        return qualified, tables.CLA_INS_SOURCE[(cla * 256) + ins]
    end
    local masked = (math.floor(cla / 4) * 4)
    qualified = tables.CLA_INS_NAMES[(masked * 256) + ins]
    if qualified ~= nil then
        return qualified, tables.CLA_INS_SOURCE[(masked * 256) + ins]
    end
    local bare = tables.INS_NAMES[ins]
    if bare ~= nil then
        return bare, tables.INS_SOURCE[ins]
    end
    return string.format("INS_%02X", ins), ""
end

--- Risk class for an instruction.
--
-- yggdrasim_common/apdu_risk.py is explicit that an instruction the
-- table has not seen is reported as "write": absence is not evidence of
-- safety. The same default applies here.
function M.risk_for(ins)
    local risk = tables.APDU_RISK[ins]
    if risk == nil then
        return tables.APDU_RISK_DEFAULT, "unrecognised instruction"
    end
    return risk, tables.APDU_RISK_NAME[ins] or ""
end

-- ------------------------------------------------------------ status word
--- Describe SW1SW2, mirroring the resolver in Tools/YggdraMCP/server.py.
--
-- The table is consulted first, then the families whose SW2 is a count
-- rather than a code. Those families are why a plain lookup is not
-- enough: 0x61 0x2B is not a distinct status word, it is "43 bytes
-- available".
function M.describe_status_word(sw1, sw2)
    local status_word = (sw1 * 256) + sw2
    local named = tables.STATUS_WORDS[status_word]
    if named ~= nil then
        return named
    end
    if sw1 == 0x61 then
        return string.format("Success. %d bytes available via GET RESPONSE.", sw2)
    end
    if sw1 == 0x6C then
        return string.format("Wrong Le. Retry with Le = %d.", sw2)
    end
    if sw1 == 0x63 and math.floor(sw2 / 16) == 0x0C then
        return string.format("Verification failed. %d retries left.", sw2 % 16)
    end
    if sw1 == 0x62 then
        return "Warning: state of non-volatile memory unchanged."
    end
    if sw1 == 0x63 then
        return "Warning: state of non-volatile memory changed."
    end
    if sw1 == 0x91 then
        return string.format("Normal ending. %d bytes of proactive data.", sw2)
    end
    if sw1 == 0x92 then
        return string.format("Normal ending after %d internal retries.", sw2)
    end
    if sw1 == 0x9F then
        return string.format("Success. %d bytes available (GSM 11.11).", sw2)
    end
    return string.format("Unknown status word 0x%04X.", status_word)
end

--- True when the status word reports success or a warning, not an error.
function M.status_is_success(sw1)
    return sw1 == 0x90 or sw1 == 0x61 or sw1 == 0x62 or sw1 == 0x63
        or sw1 == 0x91 or sw1 == 0x92 or sw1 == 0x9E or sw1 == 0x9F
end

-- ---------------------------------------------------------------- command
--- Parse the command half into a plain table. Never raises.
function M.parse_command(payload, split_result)
    local cla = util.byte_at(payload, 0)
    local ins = util.byte_at(payload, 1)
    local p1 = util.byte_at(payload, 2)
    local p2 = util.byte_at(payload, 3)
    if cla == nil or ins == nil or p1 == nil or p2 == nil then
        return nil
    end

    local name, source = M.command_name(cla, ins)
    local risk, risk_name = M.risk_for(ins)

    local data_offset = nil
    local data_length = 0
    if split_result.lc ~= nil and split_result.lc > 0 then
        data_offset = split_result.extended and 7 or 5
        data_length = split_result.lc
        if data_offset + data_length > payload:captured_len() then
            data_length = math.max(0, payload:captured_len() - data_offset)
        end
    end

    return {
        cla = cla,
        cla_decoded = M.decode_cla(cla),
        ins = ins,
        p1 = p1,
        p2 = p2,
        lc = split_result.lc,
        le = split_result.le,
        le_effective = split_result.le_effective,
        case = split_result.case,
        extended = split_result.extended,
        name = name,
        source = source or "",
        risk = risk,
        risk_name = risk_name,
        data_offset = data_offset,
        data_length = data_length,
        length = split_result.command_length,
    }
end

--- Parse the response half into a plain table. Never raises.
function M.parse_response(payload, split_result)
    local total = payload:captured_len()
    local start = split_result.command_length
    local sw1 = util.byte_at(payload, total - 2)
    local sw2 = util.byte_at(payload, total - 1)
    if sw1 == nil or sw2 == nil then
        return nil
    end
    local data_length = total - start - 2
    if data_length < 0 then
        data_length = 0
    end
    return {
        offset = start,
        length = total - start,
        data_offset = start,
        data_length = data_length,
        sw1 = sw1,
        sw2 = sw2,
        status_word = (sw1 * 256) + sw2,
        meaning = M.describe_status_word(sw1, sw2),
        succeeded = M.status_is_success(sw1),
    }
end

-- -------------------------------------------------------------------- ATR
--- Parse an ISO/IEC 7816-3 Answer To Reset into a structure table.
--
-- Returns nil when the bytes do not form a well-formed ATR, so the
-- caller can fall back to raw rendering rather than inventing fields.
function M.parse_atr(payload)
    local ts = util.byte_at(payload, 0)
    local t0 = util.byte_at(payload, 1)
    if ts == nil or t0 == nil then
        return nil
    end
    if ts ~= 0x3B and ts ~= 0x3F then
        return nil
    end

    local parsed = {
        ts = ts,
        t0 = t0,
        convention = (ts == 0x3B) and "direct" or "inverse",
        historical_count = t0 % 16,
        interface_bytes = {},
        protocols = {},
    }

    local offset = 2
    local indicator = math.floor(t0 / 16)
    local group = 1
    local uses_checksum = false
    while group <= 8 do
        local next_indicator = nil
        for bit = 0, 3 do
            if math.floor(indicator / (2 ^ bit)) % 2 == 1 then
                local value = util.byte_at(payload, offset)
                if value == nil then
                    return nil
                end
                local label = string.char(string.byte("A") + bit)
                parsed.interface_bytes[#parsed.interface_bytes + 1] = {
                    name = string.format("T%s%d", label, group),
                    offset = offset,
                    value = value,
                }
                if bit == 3 then
                    next_indicator = math.floor(value / 16)
                    local protocol = value % 16
                    parsed.protocols[#parsed.protocols + 1] = {
                        offset = offset,
                        value = protocol,
                    }
                    if protocol ~= 0 then
                        uses_checksum = true
                    end
                end
                offset = offset + 1
            end
        end
        if next_indicator == nil or next_indicator == 0 then
            break
        end
        indicator = next_indicator
        group = group + 1
    end

    parsed.historical_offset = offset
    if offset + parsed.historical_count > payload:captured_len() then
        return nil
    end
    offset = offset + parsed.historical_count

    -- TCK is present whenever any protocol other than T=0 is offered.
    if uses_checksum then
        local tck = util.byte_at(payload, offset)
        if tck == nil then
            return nil
        end
        parsed.tck_offset = offset
        parsed.tck = tck
        local checksum = 0
        for index = 1, offset do
            local value = util.byte_at(payload, index)
            if value == nil then
                return nil
            end
            -- Lua 5.2 has no bitwise xor operator; fold byte by byte.
            local acc = 0
            local left, right, weight = checksum, value, 1
            for _ = 1, 8 do
                local left_bit = left % 2
                local right_bit = right % 2
                if left_bit ~= right_bit then
                    acc = acc + weight
                end
                left = math.floor(left / 2)
                right = math.floor(right / 2)
                weight = weight * 2
            end
            checksum = acc
        end
        parsed.tck_valid = (checksum == 0)
        offset = offset + 1
    end

    parsed.length = offset
    if parsed.length ~= payload:captured_len() then
        return nil
    end
    return parsed
end

return M
