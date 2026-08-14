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

    -- An opaque class byte reports nil rather than zero for the three
    -- interindustry fields, so a caller can tell "the specification says
    -- nothing about these bits" from "channel 0, no secure messaging".
    local function opaque()
        decoded.channel = nil
        decoded.secure_messaging = nil
        decoded.chaining = nil
        return decoded
    end

    if cla == 0xFF then
        -- Reserved by ISO/IEC 7816-4 as an invalid class byte.
        decoded.invalid = true
        decoded.proprietary = true
        return opaque()
    end

    if cla >= 0x80 then
        decoded.proprietary = true
        -- ISO/IEC 7816-4 clause 5.4.1 gives '80' to 'FE' to proprietary
        -- use and assigns no meaning to bits 6 to 1 there. Two
        -- proprietary layouts matter enough to decode anyway, and
        -- GlobalPlatform defines both.
        --
        -- The first is the '8X' block (GlobalPlatform Table 11-1),
        -- shaped like the first interindustry form -- bit 3 secure
        -- messaging, bits 2 and 1 the logical channel -- which is what
        -- every GP and ES10 command on channels 0 to 3 uses.
        --
        -- The second is 'C0' to 'FE': the further interindustry shape
        -- with bit 8 set, which is how GlobalPlatform reaches logical
        -- channels 4 to 19. SCP03/crypto/session.py builds exactly this
        -- on the wire -- (cla & 0x80) | 0x60 | (cla & 0x0F) -- so a
        -- secure-messaged GP command on channel 4 arrives as 'E4', not
        -- '84'. Treating it as opaque loses the channel, the
        -- secure-messaging level and the whole GP body decode on the
        -- channel where a populated eUICC opens its ISD-P.
        if cla >= 0xC0 then
            decoded.extended_channel = true
            decoded.channel = 4 + (cla % 16)
            decoded.secure_messaging = (math.floor(cla / 32) % 2) == 1 and 3 or 0
            decoded.chaining = (math.floor(cla / 16) % 2) == 1
            return decoded
        end
        -- '90' to 'BF' really is opaque, and decoding it invents facts
        -- per command: CLA 'AC' is not "secure messaging 3" and CLA 'A3'
        -- is not channel 3.
        if cla > 0x8F then
            return opaque()
        end
    end

    if math.floor(cla / 64) % 4 == 1 then
        -- 01xxxxxx: further interindustry, channels 4..19.
        decoded.extended_channel = true
        decoded.channel = 4 + (cla % 16)
        decoded.secure_messaging = (math.floor(cla / 32) % 2) == 1 and 3 or 0
        decoded.chaining = (math.floor(cla / 16) % 2) == 1
        return decoded
    end

    if cla >= 0x20 and cla <= 0x3F then
        -- '20' to '3F' is reserved by clause 5.4.1. Its bits carry no
        -- defined meaning either.
        decoded.reserved = true
        return opaque()
    end

    decoded.channel = cla % 4
    decoded.secure_messaging = math.floor(cla / 4) % 4
    decoded.chaining = (math.floor(cla / 16) % 2) == 1
    return decoded
end

--- True when the class byte says the command is secure-messaged.
--
-- ISO/IEC 7816-4 Table 3 gives the first interindustry form four secure
-- messaging values in bits 4 and 3: '00' none, '01' proprietary, '10'
-- header not authenticated, '11' header authenticated. Anything other
-- than '00' is secure messaging, including '10' -- the value a test for
-- bit 3 alone misses, and CLA '08' and '88' are exactly that. The
-- further interindustry form uses a single bit instead, which is why
-- reading bit 3 there turns CLA '44' -- logical channel 8, no secure
-- messaging at all -- into a command with an invented C-MAC.
function M.uses_secure_messaging(cla)
    local decoded = M.decode_cla(cla)
    return decoded.secure_messaging ~= nil and decoded.secure_messaging ~= 0
end

--- The channel-independent class byte a lookup table is keyed on, or nil.
--
-- Every table in tables.lua is keyed on the channel-0 spelling of a
-- class: '00' for the interindustry commands and '80' for the
-- GlobalPlatform ones. A command issued on logical channel 4 or above
-- carries neither, because both encodings move the channel into the low
-- nibble and mark themselves in bits 8 and 7 -- '4X' to '7X' for the ISO
-- further interindustry form, 'CX' to 'FX' for the GlobalPlatform one.
-- Masking the low nibble leaves 'E0', which is in no table, so a
-- high-channel STORE DATA lost its name, its risk class and -- through
-- the missing case hint -- its command/response split as well.
function M.base_class(cla)
    if cla >= 0xC0 and cla <= 0xFE then
        -- GlobalPlatform on channels 4 to 19 is the '8X' block reached
        -- through the further interindustry shape.
        return 0x80
    end
    if math.floor(cla / 64) % 4 == 1 then
        -- ISO further interindustry, channels 4 to 19.
        return 0x00
    end
    return nil
end

--- Resolve the command name, mirroring _lookup_apdu_command in
--- Tools/Asn1TlvDecode/main.py: class-qualified first, then the class
--- with its channel bits cleared, then with the whole low nibble
--- cleared, then the channel-independent base, then the bare
--- instruction.
--
-- The third step is the one that names a secure-messaged command. In the
-- first interindustry form the secure-messaging field is bits 4 and 3,
-- which a 0xFC mask cannot reach, so an ISO-SM CREATE FILE ('0C E0') was
-- reported as "INS_E0" with the default risk class. The fourth is what
-- names the same command on a logical channel above 3; see base_class.
function M.command_name(cla, ins)
    local candidates = { cla, cla - (cla % 4), cla - (cla % 16) }
    local base = M.base_class(cla)
    if base ~= nil then
        candidates[#candidates + 1] = base
    end
    for index = 1, #candidates do
        local key = (candidates[index] * 256) + ins
        local qualified = tables.CLA_INS_NAMES[key]
        if qualified ~= nil then
            return qualified, tables.CLA_INS_SOURCE[key]
        end
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
    -- SW2 of zero means 256 in both counted families, per the Le
    -- convention of ISO/IEC 7816-4 clause 5.1. "Retry with Le = 0" reads
    -- as an instruction to send Le=0, which asks for 256 bytes only by
    -- accident and is the opposite of what the card said.
    if sw1 == 0x61 then
        return string.format(
            "Success. %d bytes available via GET RESPONSE.",
            sw2 == 0 and 256 or sw2
        )
    end
    if sw1 == 0x6C then
        return string.format(
            "Wrong Le. Retry with Le = %d.", sw2 == 0 and 256 or sw2
        )
    end
    if sw1 == 0x63 and math.floor(sw2 / 16) == 0x0C then
        if sw2 % 16 == 0 then
            return "Verification failed. No retries left: the key is blocked."
        end
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
        -- GSM 11.11 clause 9.4: '92' '0X' counts internal retries, but
        -- '92' '40' is a memory problem -- a failed write against bad
        -- memory, reported until now as a normal ending after 64 tries.
        if sw2 == 0x40 then
            return "Memory problem: the update did not complete."
        end
        if sw2 < 0x10 then
            return string.format(
                "Update successful after %d internal retries.", sw2
            )
        end
        return string.format("Memory management status 0x%02X.", sw2)
    end
    if sw1 == 0x9E then
        -- TS 51.011 clause 9.4: the response data is available, and the
        -- reason it exists is that the data download failed.
        return string.format(
            "SIM data download error. %d bytes of response data available.", sw2
        )
    end
    if sw1 == 0x9F then
        return string.format(
            "Success. %d bytes available (GSM 11.11).", sw2 == 0 and 256 or sw2
        )
    end
    return string.format("Unknown status word 0x%04X.", status_word)
end

--- Classify a status word per ISO/IEC 7816-4 clause 5.1.3.
--
-- Four categories, not two. Lumping warnings in with success is what
-- made a failed PIN verification report "Succeeded: True" beside the
-- text "Verification failed" -- and made a filter for failures miss
-- every blocked PIN on the card.
function M.status_category(sw1, sw2)
    if sw1 == 0x92 then
        -- GSM 11.11 splits this one: a retry count is a normal ending,
        -- a memory problem is not.
        if sw2 ~= nil and sw2 >= 0x10 then
            return "execution error"
        end
        return "normal"
    end
    if sw1 == 0x9E then
        -- The response data is there, but it is there because the data
        -- download failed. Calling that success hides every failed
        -- SMS-PP download in the capture.
        return "warning"
    end
    if sw1 == 0x90 or sw1 == 0x61 or sw1 == 0x91 or sw1 == 0x9F then
        return "normal"
    end
    if sw1 == 0x62 or sw1 == 0x63 then
        return "warning"
    end
    if sw1 == 0x64 or sw1 == 0x65 or sw1 == 0x66 then
        return "execution error"
    end
    if sw1 >= 0x67 and sw1 <= 0x6F then
        return "checking error"
    end
    return "unknown"
end

--- True only when the card did what was asked.
--
-- Warnings are excluded deliberately. 0x63 Cx is a failed verification
-- with a retry count, 0x62 83 is a selected file in an invalidated
-- state: in neither case did the command achieve what the terminal
-- asked for, so reporting them as success is worse than useless to
-- someone filtering a capture for what went wrong.
function M.status_is_success(sw1, sw2)
    return M.status_category(sw1, sw2) == "normal"
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
        category = M.status_category(sw1, sw2),
        succeeded = M.status_is_success(sw1, sw2),
    }
end

-- -------------------------------------------------------------------- ATR
-- ISO/IEC 7816-3:2006 Table 7: clock-rate conversion integer Fi and the
-- maximum frequency, indexed by the high nibble of TA1.
local ATR_FI = {
    [0] = { fi = 372, f = "4 MHz" },
    [1] = { fi = 372, f = "5 MHz" },
    [2] = { fi = 558, f = "6 MHz" },
    [3] = { fi = 744, f = "8 MHz" },
    [4] = { fi = 1116, f = "12 MHz" },
    [5] = { fi = 1488, f = "16 MHz" },
    [6] = { fi = 1860, f = "20 MHz" },
    [9] = { fi = 512, f = "5 MHz" },
    [10] = { fi = 768, f = "7.5 MHz" },
    [11] = { fi = 1024, f = "10 MHz" },
    [12] = { fi = 1536, f = "15 MHz" },
    [13] = { fi = 2048, f = "20 MHz" },
}

-- ISO/IEC 7816-3:2006 Table 8: baud-rate adjustment integer Di, indexed by
-- the low nibble of TA1.
local ATR_DI = {
    [1] = 1, [2] = 2, [3] = 4, [4] = 8, [5] = 16, [6] = 32,
    [7] = 64, [8] = 12, [9] = 20,
}

-- ISO/IEC 7816-3:2006 clause 8.3: clock-stop indicator (bits 8-7) of the TA
-- byte that follows a T=15 indication.
local ATR_CLOCK_STOP = {
    [0] = "clock stop not supported",
    [1] = "clock stop allowed, state L",
    [2] = "clock stop allowed, state H",
    [3] = "clock stop allowed, no preferred state",
}

-- ISO/IEC 7816-4 compact-TLV historical data objects, keyed by tag number
-- (the high nibble of the object's first byte).
local ATR_COMPACT_TLV = {
    [1] = "Country/issuer indicator",
    [2] = "Issuer identification number",
    [3] = "Card service data",
    [4] = "Initial access data",
    [5] = "Card issuer's data",
    [6] = "Pre-issuing data",
    [7] = "Card capabilities",
    [8] = "Status indicator",
    [15] = "Application identifier",
}

-- ISO/IEC 7816-4 category indicator (the first historical byte).
local ATR_CATEGORY = {
    [0x00] = "compact-TLV, mandatory 3-byte status indicator at end",
    [0x10] = "DIR data reference",
    [0x80] = "compact-TLV data objects",
}

local function atr_describe_ta1(value)
    local fi = ATR_FI[math.floor(value / 16)]
    local di = ATR_DI[value % 16]
    local fi_text = fi ~= nil
        and string.format("Fi=%d (f max %s)", fi.fi, fi.f)
        or "Fi=RFU"
    local di_text = di ~= nil and string.format("Di=%d", di) or "Di=RFU"
    return fi_text .. ", " .. di_text
end

local function atr_describe_t15_ta(value)
    local stop = ATR_CLOCK_STOP[math.floor(value / 64)] or "clock stop RFU"
    local class_bits = value % 64
    local classes = {}
    if class_bits % 2 == 1 then
        classes[#classes + 1] = "A (5V)"
    end
    if math.floor(class_bits / 2) % 2 == 1 then
        classes[#classes + 1] = "B (3V)"
    end
    if math.floor(class_bits / 4) % 2 == 1 then
        classes[#classes + 1] = "C (1.8V)"
    end
    local class_text = (#classes > 0) and table.concat(classes, ", ") or "none"
    return string.format("%s; supported classes %s", stop, class_text)
end

local function atr_describe_t15_tb(value)
    if value >= 128 then
        return string.format("SPU proprietary use 0x%02X", value % 128)
    end
    if value == 0 then
        return "contact C6 (SPU) not used"
    end
    return string.format("SPU standard use 0x%02X", value)
end

-- Interpret one A/B/C interface byte from its letter, 1-based group, and the
-- protocol T governing the group (-1 for the global group 1). Returns a
-- human-readable string, or nil when the byte has no standard meaning here.
local function atr_interface_detail(letter, group, protocol, value)
    if letter == "A" then
        if group == 1 then
            return atr_describe_ta1(value)
        end
        if group == 2 then
            return "specific-mode / negotiable-mode byte"
        end
        if protocol == 1 then
            return string.format("IFSC=%d (T=1 information field size)", value)
        end
        if protocol == 15 then
            return atr_describe_t15_ta(value)
        end
    elseif letter == "B" then
        if group == 1 then
            return "deprecated global byte (Vpp / programming current)"
        end
        if protocol == 1 then
            return string.format(
                "BWI=%d, CWI=%d (T=1 block/character waiting integers)",
                math.floor(value / 16), value % 16
            )
        end
        if protocol == 15 then
            return atr_describe_t15_tb(value)
        end
    elseif letter == "C" then
        if group == 1 then
            if value == 255 then
                return "extra guard time N=255 (minimum inter-byte delay)"
            end
            return string.format("extra guard time N=%d etu", value)
        end
        if protocol == 0 then
            return string.format(
                "WI=%d (T=0 waiting-time integer; WT = 960 x WI x Fi/f)", value
            )
        end
        if protocol == 1 then
            local crc = (value % 2 == 1)
            return crc and "error detection: CRC" or "error detection: LRC"
        end
    end
    return nil
end

--- Decompose the historical bytes into a category indicator and, for the
--- compact-TLV category (0x80), the ISO/IEC 7816-4 data objects it carries.
function M.parse_historical(payload, start, count)
    if count <= 0 then
        return nil
    end
    local category = util.byte_at(payload, start)
    if category == nil then
        return nil
    end
    local result = {
        category = category,
        category_name = ATR_CATEGORY[category] or "proprietary",
        objects = {},
    }
    -- Only 0x80 is a bare compact-TLV list. 0x00 appends a 3-byte status
    -- indicator; the others are reference/proprietary layouts left as raw
    -- bytes.
    if category ~= 0x80 then
        return result
    end
    local pos = start + 1
    local finish = start + count
    while pos < finish do
        local head = util.byte_at(payload, pos)
        if head == nil then
            break
        end
        local tag = math.floor(head / 16)
        local length = head % 16
        if pos + 1 + length > finish then
            break
        end
        result.objects[#result.objects + 1] = {
            tag = tag,
            name = ATR_COMPACT_TLV[tag]
                or string.format("compact-TLV tag %d", tag),
            offset = pos,
            value_offset = pos + 1,
            value_length = length,
        }
        pos = pos + 1 + length
    end
    return result
end

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
    -- The A/B/C bytes of group 1 are global; in later groups they are
    -- governed by the protocol T indicated in the preceding TD byte.
    local group_protocol = -1
    local uses_checksum = false
    while group <= 8 do
        local next_indicator = nil
        local next_protocol = nil
        for bit = 0, 3 do
            if math.floor(indicator / (2 ^ bit)) % 2 == 1 then
                local value = util.byte_at(payload, offset)
                if value == nil then
                    return nil
                end
                local letter = string.char(string.byte("A") + bit)
                local entry = {
                    name = string.format("T%s%d", letter, group),
                    offset = offset,
                    value = value,
                }
                if bit == 3 then
                    next_indicator = math.floor(value / 16)
                    local protocol = value % 16
                    next_protocol = protocol
                    entry.detail = string.format(
                        "protocol T=%d for the next interface-byte group",
                        protocol
                    )
                    parsed.protocols[#parsed.protocols + 1] = {
                        offset = offset,
                        value = protocol,
                        -- T=15 only flags that global interface bytes follow;
                        -- it is not a selectable transmission protocol.
                        is_global = (protocol == 15),
                    }
                    -- TCK presence keys off any non-T=0 indication (T=15
                    -- included); this stays independent of the "offered
                    -- protocols" view, which excludes T=15.
                    if protocol ~= 0 then
                        uses_checksum = true
                    end
                else
                    entry.detail = atr_interface_detail(
                        letter, group, group_protocol, value
                    )
                end
                parsed.interface_bytes[#parsed.interface_bytes + 1] = entry
                offset = offset + 1
            end
        end
        if next_indicator == nil or next_indicator == 0 then
            break
        end
        indicator = next_indicator
        group_protocol = next_protocol
        group = group + 1
    end

    parsed.historical_offset = offset
    if offset + parsed.historical_count > payload:captured_len() then
        return nil
    end
    parsed.historical = M.parse_historical(
        payload, offset, parsed.historical_count
    )
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
