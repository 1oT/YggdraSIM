-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- Split a SIMtrace SIM-APDU record into its command and response halves.
--
-- Tools/HilBridge/protocol.py build_simtrace_apdu_payload concatenates
-- the command APDU and the response APDU into one GSMTAP frame, so a
-- decoder has to work out where the command ends. ISO 7816-4 leaves
-- that genuinely ambiguous: a body of "05 AA BB CC DD EE" reads equally
-- well as case 3S with Lc=5 and no Le, or as case 4S with Lc=5 and a
-- trailing Le of 0xEE.
--
-- The Python decode view resolves this with a hardcoded instruction
-- allowlist (live_decode_state._parse_exchange_from_udp_payload_hex)
-- and returns nothing for anything it does not recognise, so an
-- unfamiliar instruction disappears from the trace entirely. That is the
-- behaviour this module exists to avoid: every candidate split allowed
-- by the structure is enumerated, scored against the evidence, and the
-- best one is reported together with how confident it is. An unknown
-- instruction still decodes, just with a lower score.
--
-- Side-effect free by design; see util.lua.

local util = require("yggdrasim_apdu.util")
local tables = require("yggdrasim_apdu.tables")

local M = {}

--- Below this score the split is reported as low confidence.
M.CONFIDENCE_FLOOR = 45

--- SW1 values a real card can return. ISO 7816-4 clause 5.1.3 reserves
--- 0x60 and forbids 0x6X where X would make the pair meaningless; the
--- 0x9X range carries application-specific words such as GSM 11.11's
--- 0x9E and 0x9F.
local PLAUSIBLE_SW1 = {
    [0x61] = true, [0x62] = true, [0x63] = true, [0x64] = true,
    [0x65] = true, [0x66] = true, [0x67] = true, [0x68] = true,
    [0x69] = true, [0x6A] = true, [0x6B] = true, [0x6C] = true,
    [0x6D] = true, [0x6E] = true, [0x6F] = true,
    [0x90] = true, [0x91] = true, [0x92] = true, [0x93] = true,
    [0x94] = true, [0x98] = true, [0x9E] = true, [0x9F] = true,
}

--- Status words whose SW2 is a count rather than a fixed code.
local function is_counted_family(sw1, sw2)
    if sw1 == 0x61 or sw1 == 0x6C then
        return true
    end
    if sw1 == 0x63 and math.floor(sw2 / 16) == 0x0C then
        return true
    end
    if sw1 == 0x91 or sw1 == 0x92 or sw1 == 0x9F then
        return true
    end
    return false
end

--- Effective Le: a coded zero means the maximum, not "none".
local function effective_le(coded, extended)
    if coded == nil then
        return nil
    end
    if coded ~= 0 then
        return coded
    end
    if extended then
        return 65536
    end
    return 256
end

--- Enumerate every command length ISO 7816-4 allows for this buffer.
--
-- Returns an array of candidate tables. Nothing is rejected here on
-- plausibility grounds; that is the scorer's job.
function M.candidates(payload)
    local total = payload:captured_len()
    local found = {}

    local function add(case_name, command_length, lc, le, extended)
        if command_length < 4 then
            return
        end
        -- A response APDU is at least SW1SW2.
        if total - command_length < 2 then
            return
        end
        found[#found + 1] = {
            case = case_name,
            command_length = command_length,
            lc = lc,
            le = le,
            le_effective = effective_le(le, extended),
            extended = extended and true or false,
        }
    end

    if total < 4 then
        return found
    end

    local body_length = total - 4
    if body_length == 0 then
        add("1", 4, nil, nil, false)
        return found
    end

    add("1", 4, nil, nil, false)

    local first = util.byte_at(payload, 4)
    if first == nil then
        return found
    end

    if body_length >= 1 then
        add("2S", 5, nil, first, false)
    end

    if first ~= 0 then
        -- Short form: P3 is Lc.
        add("3S", 5 + first, first, nil, false)
        local trailing_offset = 5 + first
        add("4S", trailing_offset + 1, first, util.byte_at(payload, trailing_offset), false)
        return found
    end

    -- first == 0: either an extended-length command, or a short case 2
    -- whose Le of 0 means 256 (already added above as 2S).
    if body_length >= 3 then
        local extended_value = util.safe_uint(payload, 5, 2)
        if extended_value ~= nil then
            add("2E", 7, nil, extended_value, true)
            if extended_value > 0 then
                add("3E", 7 + extended_value, extended_value, nil, true)
                local trailing_offset = 7 + extended_value
                add(
                    "4E",
                    trailing_offset + 2,
                    extended_value,
                    util.safe_uint(payload, trailing_offset, 2),
                    true
                )
            end
        end
    end

    return found
end

--- Score one candidate against the bytes.
local function score_candidate(payload, candidate, cla, ins)
    local total = payload:captured_len()
    local response_length = total - candidate.command_length
    local sw1 = util.byte_at(payload, total - 2)
    local sw2 = util.byte_at(payload, total - 1)
    if sw1 == nil or sw2 == nil then
        return -1000, "no-status-word"
    end

    local score = 0
    local method = "structure"

    if PLAUSIBLE_SW1[sw1] == true then
        score = score + 40
    else
        score = score - 60
    end
    if sw1 == 0x00 or sw1 == 0xFF then
        score = score - 50
    end

    local status_word = (sw1 * 256) + sw2
    if tables.STATUS_WORDS[status_word] ~= nil then
        score = score + 30
        method = "sw-table"
    elseif is_counted_family(sw1, sw2) then
        score = score + 30
        method = "sw-family"
    end

    -- The instruction's usual case is the strongest single signal.
    local hint = tables.CLA_INS_CASE_HINT[(cla * 256) + ins]
    if hint == nil then
        hint = tables.CLA_INS_CASE_HINT[(math.floor(cla / 4) * 4 * 256) + ins]
    end
    if hint == nil then
        hint = tables.INS_CASE_HINT[ins]
    end
    if hint ~= nil then
        if hint == candidate.case then
            score = score + 25
            method = "case-hint"
        elseif hint:sub(1, 1) == candidate.case:sub(1, 1) then
            -- Same case number, different length form. The hint table
            -- records the short form because that is what cards use in
            -- practice, but an UPDATE BINARY carrying 256 bytes is still
            -- a case 3 command -- it just had to reach for extended
            -- length to say so. Without this the 2E reading of an
            -- extended case 3 command wins on a coincidental Le match.
            score = score + 15
            method = "case-family"
        end
    end

    local response_data_length = response_length - 2
    if candidate.le_effective ~= nil then
        if response_data_length == candidate.le_effective then
            score = score + 25
            method = "le-match"
        elseif response_data_length > candidate.le_effective then
            -- A card never returns more than was asked for.
            score = score - 30
        end
    end

    -- An error status normally carries no response body, and a command
    -- with no Le should not have produced one either.
    if math.floor(sw1 / 16) == 0x06 and response_data_length == 0 then
        score = score + 15
    end
    if candidate.le_effective == nil and response_data_length == 0 then
        score = score + 10
    end
    if response_length == 2 then
        score = score + 5
    end

    -- 61XX says "response ready, come back with GET RESPONSE", so the
    -- body of this exchange is empty by definition.
    if sw1 == 0x61 and response_data_length ~= 0 then
        score = score - 20
    end

    if tables.CLA_INS_NAMES[(cla * 256) + ins] ~= nil then
        score = score + 10
    elseif tables.INS_NAMES[ins] ~= nil then
        score = score + 5
    end

    return score, method
end

--- Order candidates deterministically when scores tie.
--
-- Preferring the longer command matters for secure messaging, where the
-- MAC inflates Lc and the shorter reading is a coincidence.
local function better(left, right)
    if left.score ~= right.score then
        return left.score > right.score
    end
    if (left.method == "case-hint") ~= (right.method == "case-hint") then
        return left.method == "case-hint"
    end
    if (left.method == "le-match") ~= (right.method == "le-match") then
        return left.method == "le-match"
    end
    return left.command_length > right.command_length
end

--- Split *payload* into command and response.
--
-- Always returns a table. On failure ``ok`` is false and ``reason``
-- explains why; the caller renders the raw bytes and an expert item
-- rather than dropping the frame.
function M.split(payload)
    local total = payload:captured_len()
    if total < 4 then
        return {
            ok = false,
            reason = "too-short",
            detail = "fewer than 4 bytes: not even a command header",
        }
    end
    if total < 6 then
        return {
            ok = false,
            reason = "too-short",
            detail = "fewer than 6 bytes: no room for a header and a status word",
        }
    end

    local cla = util.byte_at(payload, 0)
    local ins = util.byte_at(payload, 1)
    if cla == nil or ins == nil then
        return { ok = false, reason = "truncated", detail = "header unreadable" }
    end

    local candidates = M.candidates(payload)
    if #candidates == 0 then
        return {
            ok = false,
            reason = "no-candidate",
            detail = "no ISO 7816-4 case fits this length",
        }
    end

    local scored = {}
    for index = 1, #candidates do
        local candidate = candidates[index]
        local score, method = score_candidate(payload, candidate, cla, ins)
        candidate.score = score
        candidate.method = method
        scored[#scored + 1] = candidate
    end

    table.sort(scored, better)
    local best = scored[1]

    local confidence = best.score
    if confidence < 0 then
        confidence = 0
    end
    if confidence > 100 then
        confidence = 100
    end
    -- A close runner-up means the evidence did not really decide.
    local ambiguous = false
    if #scored > 1 and (best.score - scored[2].score) <= 10 then
        ambiguous = true
        confidence = math.max(0, confidence - 20)
    end

    return {
        ok = true,
        case = best.case,
        command_length = best.command_length,
        response_length = total - best.command_length,
        lc = best.lc,
        le = best.le,
        le_effective = best.le_effective,
        extended = best.extended,
        method = best.method,
        confidence = confidence,
        ambiguous = ambiguous,
        low_confidence = confidence < M.CONFIDENCE_FLOOR,
        alternatives = scored,
    }
end

--- True when the payload looks like an ISO 7816-3 Answer To Reset.
--
-- GSMTAP carries the SIM subtype in its header, but Wireshark 4.2
-- exposes no gsmtap.sub_type field and a gsmtap.type subdissector only
-- receives the payload, so ATR frames have to be recognised from their
-- own bytes. TS is 0x3B for the direct convention and 0x3F for the
-- inverse one, and nothing else is legal; T0's low nibble then counts
-- the historical bytes, which gives a second, independent check.
function M.looks_like_atr(payload)
    local ts = util.byte_at(payload, 0)
    if ts ~= 0x3B and ts ~= 0x3F then
        return false
    end
    local t0 = util.byte_at(payload, 1)
    if t0 == nil then
        return false
    end

    -- Walk the interface-byte chain and check the declared structure
    -- lands inside the frame.
    local historical_count = t0 % 16
    local offset = 2
    local indicator = math.floor(t0 / 16)
    local guard = 0
    local uses_non_t0 = false
    while guard < 8 do
        guard = guard + 1
        local next_indicator = nil
        for bit = 0, 3 do
            if math.floor(indicator / (2 ^ bit)) % 2 == 1 then
                local value = util.byte_at(payload, offset)
                if value == nil then
                    return false
                end
                if bit == 3 then
                    next_indicator = math.floor(value / 16)
                    if value % 16 ~= 0 then
                        uses_non_t0 = true
                    end
                end
                offset = offset + 1
            end
        end
        if next_indicator == nil or next_indicator == 0 then
            break
        end
        indicator = next_indicator
    end

    local expected = offset + historical_count
    if uses_non_t0 then
        expected = expected + 1
    end
    return expected == payload:captured_len()
end

return M
