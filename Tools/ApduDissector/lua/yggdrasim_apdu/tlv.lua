-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- Recursive BER-TLV and COMPREHENSION-TLV walker.
--
-- One engine serves every layer above it: FCP templates, CAT proactive
-- commands, GlobalPlatform registry data and the SGP.22/SGP.32 BFxx
-- surface are all TLV, differing only in which table names the tags.
-- Callers supply a resolver; the structure handling stays here.
--
-- Two encodings share the code path because they share the shape:
--
--   BER-TLV (ISO/IEC 8825-1): tag class in bits 8-7, constructed flag in
--   bit 6, multi-byte tags marked by 0x1F in the low five bits. Lengths
--   are short form below 0x80, long form above, and 0x80 means
--   indefinite -- which SIMCARD.utils.read_tlv rejects outright but a
--   dissector cannot, because the bytes exist whether or not the toolkit
--   likes them.
--
--   COMPREHENSION-TLV (ETSI TS 101 220 clause 7.1): bit 8 of the tag is
--   the comprehension-required flag rather than part of the tag number.
--   That is why live_decode_state.py carries tuples like
--   _CHANNEL_STATUS_TAGS = (0x18, 0x38, 0x98, 0xB8) -- four spellings of
--   one tag. Here the base tag is normalised once and both forms are
--   reported.
--
-- Everything is bounds-checked and depth-capped. A malformed length must
-- produce an expert item and raw bytes, never a Lua error and never an
-- unbounded loop.
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

--- Depth cap. The HIL-Bridge PDML reader stops at 64
--- (live_decode_view.MAX_PDML_DEPTH), so anything deeper cannot be
--- displayed there anyway.
M.MAX_DEPTH = 24

--- Node cap per frame, well under live_decode_view.MAX_PDML_NODES.
M.MAX_NODES = 4000

--- Longest tag we will follow before calling the bytes malformed.
M.MAX_TAG_BYTES = 4

M.CLASS_UNIVERSAL = 0
M.CLASS_APPLICATION = 1
M.CLASS_CONTEXT = 2
M.CLASS_PRIVATE = 3

--- A fresh per-frame budget.
function M.new_budget()
    return { nodes = 0, exhausted = false }
end

local function spend(budget)
    if budget == nil then
        return true
    end
    budget.nodes = budget.nodes + 1
    if budget.nodes > M.MAX_NODES then
        budget.exhausted = true
        return false
    end
    return true
end

--- Read a tag at *offset*.
--
-- Returns ``nil`` when the tag runs past the captured data or never
-- terminates within MAX_TAG_BYTES.
function M.read_tag(tvb, offset, mode)
    local first = util.byte_at(tvb, offset)
    if first == nil then
        return nil
    end

    -- COMPREHENSION-TLV is not BER and does not share its tag rules.
    -- TS 101 220 clause 7.1.1 defines exactly two forms: a single byte
    -- in 0x01-0x7E (or 0x81-0xFE with the comprehension bit), and a
    -- three-byte form introduced by 0x7F. There is no 0x1F escape and
    -- no class or constructed field.
    --
    -- Applying BER's rules here corrupts every tag whose low five bits
    -- are all ones -- 0x1F Item icon identifier list, 0x3F Access
    -- technology, and their comprehension-set spellings 0x9F and 0xBF
    -- are all real, deployed TS 102 223 tags. The next byte would be
    -- swallowed as part of the tag and the length read from the value.
    if mode == "comprehension" then
        if first == 0x00 or first == 0xFF then
            return nil
        end
        if first == 0x7F then
            local second = util.byte_at(tvb, offset + 1)
            local third = util.byte_at(tvb, offset + 2)
            if second == nil or third == nil then
                return nil
            end
            return {
                value = (0x7F * 65536) + (second * 256) + third,
                length = 3,
                class = nil,
                constructed = false,
            }
        end
        return { value = first, length = 1, class = nil, constructed = false }
    end

    local class = math.floor(first / 64)
    local constructed = (math.floor(first / 32) % 2) == 1
    local length = 1
    local value = first

    if (first % 32) == 0x1F then
        -- Multi-byte tag: continue while bit 8 is set.
        local index = offset + 1
        while length < M.MAX_TAG_BYTES do
            local continuation = util.byte_at(tvb, index)
            if continuation == nil then
                return nil
            end
            value = (value * 256) + continuation
            length = length + 1
            if continuation < 0x80 then
                return {
                    value = value,
                    length = length,
                    class = class,
                    constructed = constructed,
                }
            end
            index = index + 1
        end
        return nil
    end

    return {
        value = value,
        length = length,
        class = class,
        constructed = constructed,
    }
end

--- Read a BER length at *offset*.
--
-- Returns a table with ``value``, ``length`` and ``indefinite``, or nil.
function M.read_length(tvb, offset, mode)
    local first = util.byte_at(tvb, offset)
    if first == nil then
        return nil
    end
    if first < 0x80 then
        return { value = first, length = 1, indefinite = false }
    end
    -- TS 101 220 clause 7.1.2 defines only 00-7F, 81 xx, 82 xx xx and
    -- 83 xx xx xx. 0x80 is not an indefinite marker here, it is invalid.
    if mode == "comprehension" and (first == 0x80 or first > 0x83) then
        return nil
    end
    if first == 0x80 then
        -- Indefinite length. Legal in BER, but prohibited by DER (X.690
        -- clause 10.1), which SGP.22 and SGP.32 mandate, and unused by
        -- TS 102 221 BER-TLV files. Nothing conforming emits it, so it
        -- is reported rather than guessed at: resolving it means finding
        -- an end-of-contents marker, and a byte scan cannot tell a real
        -- terminator from 00 00 inside a value or a nested construct.
        return { value = nil, length = 1, indefinite = true, rejected = true }
    end
    if first == 0xFF then
        -- Reserved by ISO/IEC 8825-1.
        return nil
    end
    local count = first - 0x80
    if count > 4 then
        return nil
    end
    local value = 0
    for index = 1, count do
        local byte_value = util.byte_at(tvb, offset + index)
        if byte_value == nil then
            return nil
        end
        value = (value * 256) + byte_value
    end
    return { value = value, length = count + 1, indefinite = false }
end

--- Normalise a COMPREHENSION-TLV tag to its base value.
--
-- Bit 8 is the comprehension-required flag. For a multi-byte tag the
-- flag sits in the first byte of the tag number, not the 0x7F marker.
function M.comprehension_base(tag_value)
    if tag_value <= 0xFF then
        return tag_value % 128, tag_value >= 128
    end
    -- 0x7F xx yy form: the CR bit is bit 8 of the first tag-number byte.
    -- The 0x7F marker stays in the base value. Dropping it collapses
    -- '7F 21 81' and '7F A1 81' onto the two-byte value 0x2181, which
    -- can then collide with an unrelated BER tag in the name table.
    local high = math.floor(tag_value / 256) % 256
    local low = tag_value % 256
    local base = (0x7F * 65536) + ((high % 128) * 256) + low
    return base, high >= 128
end

--- Name a BER tag using the generated table.
function M.name_ber_tag(tag_value)
    local width = 2
    if tag_value > 0xFFFFFF then
        width = 8
    elseif tag_value > 0xFFFF then
        width = 6
    elseif tag_value > 0xFF then
        width = 4
    end
    local key = string.format("%0" .. tostring(width) .. "X", tag_value)
    local named = tables.BER_TAGS[key]
    if named ~= nil then
        return named
    end
    if tag_value <= 0xFF then
        local class = math.floor(tag_value / 64)
        if class == M.CLASS_UNIVERSAL then
            local universal = tables.UNIVERSAL_TAGS[tag_value % 32]
            if universal ~= nil then
                return universal
            end
        end
    end
    return ""
end

--- Parse a TLV run into a tree of plain Lua tables.
--
-- ``options.mode`` is "ber" (default) or "comprehension".
-- ``options.resolver`` may name a tag; it wins over the generic table.
--
-- The return value is ``{nodes, errors}``. Parsing stops at the first
-- structural problem and records it rather than raising, so a caller can
-- render what was understood and flag the rest.
function M.parse(tvb, offset, length, options, budget, depth, parent)
    local settings = options or {}
    local level = depth or 0
    local nodes = {}
    local errors = {}

    if level >= M.MAX_DEPTH then
        errors[#errors + 1] = {
            offset = offset,
            reason = string.format("nesting deeper than %d levels", M.MAX_DEPTH),
        }
        return nodes, errors
    end

    local limit = offset + length
    if limit > tvb:captured_len() then
        limit = tvb:captured_len()
    end

    local cursor = offset
    while cursor < limit do
        if not spend(budget) then
            errors[#errors + 1] = {
                offset = cursor,
                reason = "tree node budget exhausted",
            }
            return nodes, errors
        end

        local tag = M.read_tag(tvb, cursor, settings.mode)
        if tag == nil then
            errors[#errors + 1] = { offset = cursor, reason = "unreadable tag" }
            return nodes, errors
        end

        -- ISO/IEC 7816-4 clause 5.2.2 allows 0x00 and 0xFF filler
        -- before, between and after BER-TLV data objects, and 0xFF is
        -- the erased-byte value in a UICC file. Neither is an error, and
        -- 0xFF in particular must not reach the long-form tag reader,
        -- which would chase it to the end of the frame.
        if tag.value == 0 or tag.value == 0xFF then
            return nodes, errors
        end

        local length_info = M.read_length(tvb, cursor + tag.length, settings.mode)
        if length_info == nil then
            errors[#errors + 1] = {
                offset = cursor + tag.length,
                reason = "unreadable or reserved length",
            }
            return nodes, errors
        end

        local value_offset = cursor + tag.length + length_info.length
        local value_length = length_info.value
        local clamped = false

        if length_info.indefinite then
            errors[#errors + 1] = {
                offset = cursor + tag.length,
                reason = "indefinite length, which DER prohibits and no "
                    .. "conforming card emits here; the remainder is not "
                    .. "framed",
            }
            return nodes, errors
        end

        if value_offset + value_length > limit then
            -- The classic hostile shape: a length that over-claims its
            -- body. Show what is there rather than refusing the node.
            value_length = math.max(0, limit - value_offset)
            clamped = true
        end

        local base_tag = tag.value
        local comprehension_required = nil
        local constructed = tag.constructed
        if settings.mode == "comprehension" then
            base_tag, comprehension_required = M.comprehension_base(tag.value)
            -- COMPREHENSION-TLV has no constructed bit. TS 101 220
            -- clause 7.1.1 gives bit 8 to the comprehension-required
            -- flag and the rest to the tag number; every data object is
            -- primitive. Applying BER's bit-6 rule here recurses into
            -- any tag that happens to have it set -- 0x35 Bearer
            -- description, 0x39 Buffer size, 0x3C transport level --
            -- and turns their values into invented sub-tags.
            constructed = nil
        end

        -- A few ETSI tags hold a TLV run while being primitive by BER's
        -- own rule: the PIN Status Template DO is 'C6', whose bit 6 is
        -- clear, so a conforming BER walker stops at it and renders
        -- nine bytes of PIN state as an opaque value. The caller names
        -- the exceptions rather than the walker guessing at them.
        if settings.constructed ~= nil and settings.constructed[base_tag] then
            constructed = true
        end

        local name = ""
        if settings.resolver ~= nil then
            name = settings.resolver(base_tag, tag, level, parent) or ""
        end
        if name == "" and settings.mode ~= "comprehension" then
            -- The BER table is meaningless for a COMPREHENSION-TLV tag:
            -- the two encodings share no numbering, so falling back to
            -- it renames tag '10' Item identifier to "ASN1_SEQUENCE".
            -- An unnamed tag is better than a confidently wrong one.
            name = M.name_ber_tag(base_tag)
        end

        local node = {
            tag = tag.value,
            base_tag = base_tag,
            tag_offset = cursor,
            tag_length = tag.length,
            class = tag.class,
            constructed = constructed,
            length = value_length,
            length_offset = cursor + tag.length,
            length_length = length_info.length,
            indefinite = length_info.indefinite,
            value_offset = value_offset,
            value_length = value_length,
            clamped = clamped,
            comprehension_required = comprehension_required,
            name = name,
            depth = level,
            -- The enclosing constructed tag. Several tags mean one thing
            -- at the top of a template and another inside a nested one:
            -- '83' is a file identifier in an FCP and a key reference
            -- inside the 'C6' PIN status template.
            parent = parent,
        }

        if constructed and value_length > 0 then
            local children, child_errors = M.parse(
                tvb, value_offset, value_length, settings, budget, level + 1,
                base_tag
            )
            node.children = children
            for index = 1, #child_errors do
                errors[#errors + 1] = child_errors[index]
            end
        end

        nodes[#nodes + 1] = node

        local consumed = tag.length + length_info.length + value_length
        if consumed <= 0 then
            -- Defensive: a zero-width node would loop forever.
            errors[#errors + 1] = {
                offset = cursor,
                reason = "zero-length TLV node",
            }
            return nodes, errors
        end
        cursor = cursor + consumed
        if clamped then
            return nodes, errors
        end
    end

    return nodes, errors
end

--- True when the bytes at *offset* plausibly begin a TLV run.
--
-- Used to decide whether to attempt a structured decode of a data field
-- at all. A wrong yes costs an expert item; a wrong no costs the whole
-- subtree, so the check is deliberately permissive but not blind.
function M.looks_like_tlv(tvb, offset, length)
    if length < 2 then
        return false
    end
    local tag = M.read_tag(tvb, offset)
    if tag == nil then
        return false
    end
    local length_info = M.read_length(tvb, offset + tag.length)
    if length_info == nil or length_info.value == nil then
        return false
    end
    local total = tag.length + length_info.length + length_info.value
    return total <= length
end

return M
