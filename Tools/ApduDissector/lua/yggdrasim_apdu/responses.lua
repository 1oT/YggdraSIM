-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- Response-body decoding: FCP/FCI/FMD templates and elementary files.
--
-- This is where the stock dissector gives up. A SELECT answers with a
-- File Control Parameters template describing the file the terminal just
-- selected -- its type, structure, record geometry, life-cycle state and
-- access rules -- and Wireshark 4.2 reports the whole thing as a
-- malformed packet. Reading it is most of the value of a SIM trace.
--
-- Elementary-file contents are decoded for the handful of files whose
-- layout is fixed and whose value an operator is usually chasing. The
-- encoders in SIMCARD/etsi_fs.py are the reference for the byte order.
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

M.TAG_FCP = 0x62
M.TAG_FCI = 0x6F
M.TAG_FMD = 0x64
M.TAG_PROPRIETARY = 0xA5

-- ETSI TS 102 221 clause 11.1.1.3 Table 11.5, FCP sub-tags.
local FCP_TAGS = {
    [0x80] = "File size",
    [0x81] = "Total file size",
    [0x82] = "File descriptor",
    [0x83] = "File identifier",
    [0x84] = "DF name (AID)",
    [0x85] = "Proprietary information",
    [0x86] = "Security attribute (proprietary)",
    [0x87] = "EF FID of the extension",
    [0x88] = "Short file identifier",
    [0x8A] = "Life-cycle status integer",
    [0x8B] = "Security attributes (referenced)",
    [0x8C] = "Security attributes (compact)",
    [0xA5] = "Proprietary information",
    [0xAB] = "Security attributes (expanded)",
    [0xC6] = "PIN status template DO",
}

-- Sub-tags of the PIN Status Template DO, ETSI TS 102 221 clause
-- 11.1.1.4.10. These collide with the FCP tags above: '83' at FCP level
-- is a file identifier, but inside 'C6' it is a key reference. Resolving
-- it without knowing the parent labelled every PIN in the template
-- "File identifier".
local PIN_STATUS_TAGS = {
    [0x90] = "PS_DO (PIN status)",
    [0x95] = "Usage qualifier",
    [0x83] = "Key reference",
}

--- ISO/IEC 7816-4 Table 13, adopted by ETSI TS 102 221 clause 11.1.1.4.9.
--
-- Bit 1 of the operational coding is the activated flag, so '05' and
-- '07' are activated while '04' and '06' are not, and '0C' to '0F' are
-- the termination state. An implementation that reads those ranges the
-- other way round reports a live file as deactivated and -- far worse --
-- a permanently terminated ADF as operational.
local LIFECYCLE = {
    [0x00] = "no information given",
    [0x01] = "creation state",
    [0x03] = "initialisation state",
    [0x04] = "operational, deactivated",
    [0x05] = "operational, activated",
    [0x06] = "operational, deactivated",
    [0x07] = "operational, activated",
    [0x0C] = "termination state",
    [0x0D] = "termination state",
    [0x0E] = "termination state",
    [0x0F] = "termination state",
}

--- Name an FCP sub-tag, or the enclosing template itself.
--
-- *parent* is the base tag of the enclosing constructed node, or nil at
-- template level.
function M.fcp_tag_name(tag, parent)
    local template = M.template_name(tag)
    if template ~= "" then
        return template
    end
    if parent == 0xC6 then
        local nested = PIN_STATUS_TAGS[tag]
        if nested ~= nil then
            return nested
        end
    end
    local named = FCP_TAGS[tag]
    if named ~= nil then
        return named
    end
    return ""
end

--- Name a life-cycle status byte.
--
-- *context* selects the coding. GlobalPlatform reuses the byte with its
-- own card and application life cycles ('01' LOADED, '03' INSTALLED and
-- so on), which apply to a GET STATUS registry entry -- not to an FCP
-- '8A', where the byte is the ISO life-cycle status integer. Consulting
-- the GlobalPlatform table unconditionally made every ordinary UICC file
-- report "LOADED" or "INSTALLED".
function M.lifecycle_name(value, context)
    if context == "globalplatform" then
        local gp = tables.GP_LIFECYCLE[value]
        if gp ~= nil then
            return gp
        end
    end
    local named = LIFECYCLE[value]
    if named ~= nil then
        return named
    end
    -- ISO/IEC 7816-4 Table 13 assigns every other value to proprietary
    -- use rather than leaving it undefined.
    return string.format("proprietary 0x%02X", value)
end

-- ISO/IEC 7816-4 Table 12, file-descriptor byte bits 3 to 1. ETSI
-- TS 102 221 clause 11.1.1.4.3 lists only the subset a UICC uses and
-- defers the rest to ISO.
local EF_STRUCTURE = {
    [0] = "no information given",
    [1] = "transparent",
    [2] = "linear fixed",
    [3] = "linear fixed, SIMPLE-TLV",
    [4] = "linear variable",
    [5] = "linear variable, SIMPLE-TLV",
    [6] = "cyclic",
    [7] = "cyclic, SIMPLE-TLV",
}

-- ETSI TS 102 221 clause 11.1.1.4.3 gives the whole descriptor byte
-- '39' to a BER-TLV structure EF, which does not decompose into the ISO
-- shareable/category/structure fields.
local DESCRIPTOR_BER_TLV = 0x39

-- ISO/IEC 7816-4 Table 12, data-coding byte.
local WRITE_BEHAVIOUR = {
    [0] = "one-time write",
    [1] = "proprietary",
    [2] = "write OR",
    [3] = "write AND",
}

--- Decode tag 0x82, the file descriptor.
--
-- Two to five bytes: descriptor byte, data-coding byte, then an optional
-- big-endian record length and record count.
function M.parse_file_descriptor(tvb, offset, length)
    local descriptor = util.byte_at(tvb, offset)
    if descriptor == nil or length < 1 then
        return nil
    end
    local shareable = (math.floor(descriptor / 64) % 2) == 1
    local category = math.floor(descriptor / 8) % 8
    local structure = descriptor % 8

    local parsed = {
        descriptor = descriptor,
        shareable = shareable,
        structure = EF_STRUCTURE[structure] or string.format("0x%02X", structure),
    }
    if category == 7 then
        parsed.file_type = "DF or ADF"
    elseif category == 0 then
        parsed.file_type = "working EF"
    elseif category == 1 then
        parsed.file_type = "internal EF"
    else
        parsed.file_type = string.format("0x%02X", category)
    end

    if descriptor == DESCRIPTOR_BER_TLV then
        parsed.file_type = "working EF"
        parsed.structure = "BER-TLV"
    end

    if length >= 2 then
        local coding = util.byte_at(tvb, offset + 1)
        parsed.data_coding = coding
        if coding ~= nil then
            -- ISO/IEC 7816-4 data coding byte: b8 EFs of TLV structure
            -- supported, b7b6 the behaviour of write functions, b5 the
            -- value an erased byte reads back as, b4 to b1 the data unit
            -- size in quartets as a power of two. Parsing these and then
            -- discarding them is the same as not parsing them at all, so
            -- all four reach the tree.
            parsed.tlv_structure_supported = (math.floor(coding / 128) % 2) == 1
            parsed.write_behaviour = WRITE_BEHAVIOUR[math.floor(coding / 32) % 4]
            parsed.erased_value = (math.floor(coding / 16) % 2) == 1 and 0xFF or 0x00
            parsed.data_unit_quartets = 2 ^ (coding % 16)
        end
    end
    if length >= 4 then
        parsed.record_length = util.safe_uint(tvb, offset + 2, 2)
    end
    if length >= 5 then
        parsed.record_count = util.byte_at(tvb, offset + 4)
    end
    return parsed
end

-- ---------------------------------------------------------- elementary files
M.EF_ICCID = "2FE2"
M.EF_IMSI = "6F07"
M.EF_UST = "6F38"
M.EF_AD = "6FAD"
M.EF_DIR = "2F00"

--- 3GPP TS 31.102 clause 4.2.8 EF.UST service numbering: one bit per
--- service, service 1 in bit 0 of byte 1.
local function service_numbers(values)
    local services = {}
    for index = 1, #values do
        local byte_value = values[index]
        for bit = 0, 7 do
            if math.floor(byte_value / (2 ^ bit)) % 2 == 1 then
                services[#services + 1] = ((index - 1) * 8) + bit + 1
            end
        end
    end
    return services
end

--- 3GPP TS 51.011 clause 10.3.7 EF.SST service numbering.
--
-- The 2G table is not the 3G one with a different name: it spends two
-- bits per service -- allocated, then activated -- so service N lives at
-- bit pair N-1. Decoding it with the EF.UST reader doubles every service
-- number and reports deallocated services as present.
local function sst_services(values)
    local services = {}
    for index = 1, #values do
        local byte_value = values[index]
        for pair = 0, 3 do
            local bits = math.floor(byte_value / (2 ^ (pair * 2))) % 4
            local number = ((index - 1) * 4) + pair + 1
            if bits % 2 == 1 then
                services[#services + 1] = {
                    number = number,
                    activated = bits >= 2,
                }
            end
        end
    end
    return services
end

--- Decode EF.IMSI: a length byte, then swapped-nibble BCD whose first
--- digit position carries a parity nibble rather than a digit.
--
-- Byte 1 bounds the run. Without it a response that carries padding, or
-- a READ BINARY that over-reads the file, appends the padding as extra
-- digits and produces an IMSI that is simply wrong rather than short.
local function decode_imsi(values)
    if #values < 2 then
        return ""
    end
    local declared = values[1]
    local last = #values
    if declared >= 1 and declared < last then
        last = declared + 1
    end
    local digits = util.decode_swapped_bcd({table.unpack(values, 2, last)})
    -- The first nibble of the packed run is the parity indicator.
    if #digits < 2 then
        return ""
    end
    return digits:sub(2)
end

--- 3GPP TS 31.102 clause 4.2.18 EF.AD operation modes.
local OPERATION_MODE = {
    [0x00] = "normal operation",
    [0x80] = "type approval operations",
    [0x01] = "normal operation, specific facilities",
    [0x81] = "type approval, specific facilities",
    [0x02] = "maintenance (off line)",
    [0x04] = "cell test operation",
}

--- Decode a known elementary file's contents.
--
-- *context* is the snapshot's selected AID, used only where a file
-- identifier is ambiguous between applications. Returns nil when the
-- file is not one we understand, which is the common case and not an
-- error.
function M.decode_ef(tvb, offset, length, fid_hex, context)
    local values = util.byte_array(tvb, offset, length)
    if values == nil or #values == 0 then
        return nil
    end

    if fid_hex == M.EF_ICCID then
        -- Odd digit counts are normal: a 19-digit ICCID leaves a
        -- trailing 0xF padding nibble. Tools/EumDiag/dissector.lua
        -- divides the digit count by two and hands the result to a
        -- TvbRange, which is why it breaks here.
        --
        -- ETSI TS 102 221 clause 13.2 fixes EF.ICCID at ten bytes. A
        -- longer read is a READ BINARY that over-ran the file, and
        -- decoding the surplus appends digits that are not part of the
        -- identifier.
        local iccid_bytes = values
        local over_read = false
        if #values > 10 then
            iccid_bytes = { table.unpack(values, 1, 10) }
            over_read = true
        end
        local digits, clean = util.decode_swapped_bcd(iccid_bytes)
        return {
            kind = "iccid",
            value = digits,
            over_read = over_read,
            malformed = not clean,
        }
    end

    if fid_hex == M.EF_IMSI then
        return { kind = "imsi", value = decode_imsi(values) }
    end

    if fid_hex == M.EF_UST then
        -- '6F38' is EF.UST under ADF.USIM and EF.SST under DF.GSM. The
        -- two use different bit widths, so the selected application
        -- decides which reader applies. With no context the USIM
        -- reading is assumed and said out loud.
        if context ~= nil and context.application == "gsm" then
            return { kind = "sst", services = sst_services(values) }
        end
        return {
            kind = "ust",
            services = service_numbers(values),
            assumed = (context == nil or context.application == nil),
        }
    end

    if fid_hex == M.EF_AD then
        local parsed = {
            kind = "ad",
            operation_mode = values[1],
            operation_mode_name = OPERATION_MODE[values[1]]
                or string.format("reserved 0x%02X", values[1]),
        }
        if #values >= 3 then
            -- Bytes 2 and 3 are additional information, defined per
            -- operation mode; byte 3 bit 1 is the ciphering indicator.
            parsed.additional_info = (values[2] * 256) + values[3]
            parsed.ciphering_indicator = (values[3] % 2) == 1
        end
        if #values >= 4 then
            parsed.mnc_length = values[4] % 16
        end
        return parsed
    end

    return nil
end

-- ETSI TS 102 221 clause 13.1: each EF.DIR record is one application
-- template. Its tags are universal-class BER values that the generic
-- table names uselessly ("ASN1_..."), so they are named here instead.
local DIR_TAGS = {
    [0x61] = "Application template",
    [0x4F] = "Application identifier (AID)",
    [0x50] = "Application label",
    [0x51] = "Path to the application",
    [0x73] = "Discretionary data objects",
}

--- Name a tag inside EF.DIR, or "" when it is not one of ours.
function M.dir_tag_name(tag)
    return DIR_TAGS[tag] or ""
end

--- Name the elementary file a FID refers to.
function M.ef_name(fid_hex)
    return tables.FILE_PATHS[fid_hex] or ""
end

--- True when the tag begins a file-control template.
function M.is_fcp_template(tag)
    return tag == M.TAG_FCP or tag == M.TAG_FCI or tag == M.TAG_FMD
end

function M.template_name(tag)
    if tag == M.TAG_FCP then
        return "File Control Parameters (FCP)"
    end
    if tag == M.TAG_FCI then
        return "File Control Information (FCI)"
    end
    if tag == M.TAG_FMD then
        return "File Management Data (FMD)"
    end
    return ""
end

return M
