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

local util = require("yggdrasim_apdu.util")
local tables = require("yggdrasim_apdu.tables")

local M = {}

M.TAG_FCP = 0x62
M.TAG_FCI = 0x6F
M.TAG_FMD = 0x64
M.TAG_PROPRIETARY = 0xA5

-- ETSI TS 102 221 clause 11.1.1.3 file-descriptor sub-tags.
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
    [0x90] = "PS_DO (PIN status)",
    [0x95] = "Usage qualifier",
    [0x83] = "File identifier",
}

--- ETSI TS 102 221 clause 11.1.1.4.3, life-cycle status integer.
local LIFECYCLE = {
    [0x00] = "no information given",
    [0x01] = "creation state",
    [0x03] = "initialisation state",
    [0x04] = "operational, deactivated",
    [0x05] = "operational, deactivated",
    [0x06] = "operational, deactivated",
    [0x07] = "operational, deactivated",
    [0x08] = "operational, deactivated",
    [0x09] = "operational, deactivated",
    [0x0A] = "operational, deactivated",
    [0x0B] = "operational, deactivated",
    [0x0C] = "operational, activated",
    [0x0D] = "operational, activated",
    [0x0E] = "operational, activated",
    [0x0F] = "operational, activated",
    [0x0C + 0xF0] = "termination state",
}

--- Name an FCP sub-tag, or the enclosing template itself.
function M.fcp_tag_name(tag)
    local template = M.template_name(tag)
    if template ~= "" then
        return template
    end
    local named = FCP_TAGS[tag]
    if named ~= nil then
        return named
    end
    return ""
end

function M.lifecycle_name(value)
    if value >= 0x0C and value <= 0x0F then
        return "operational, activated"
    end
    if value >= 0x04 and value <= 0x0B then
        return "operational, deactivated"
    end
    if value >= 0xFC then
        return "termination state"
    end
    local gp = tables.GP_LIFECYCLE[value]
    if gp ~= nil then
        return "GlobalPlatform: " .. gp
    end
    return LIFECYCLE[value] or string.format("0x%02X", value)
end

-- ETSI TS 102 221 clause 11.1.1.4.3, file-descriptor byte.
local EF_STRUCTURE = {
    [0] = "no information given",
    [1] = "transparent",
    [2] = "linear fixed",
    [6] = "cyclic",
    [7] = "BER-TLV",
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

    if length >= 2 then
        parsed.data_coding = util.byte_at(tvb, offset + 1)
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

--- 3GPP TS 31.102 clause 4.2.8 EF.UST service numbering.
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

--- Decode EF.IMSI: a length byte, then swapped-nibble BCD whose first
--- digit position carries a parity nibble rather than a digit.
local function decode_imsi(values)
    if #values < 2 then
        return ""
    end
    local digits = util.decode_swapped_bcd({table.unpack(values, 2, #values)})
    -- The first nibble of the packed run is the parity indicator.
    if #digits < 2 then
        return ""
    end
    return digits:sub(2)
end

--- Decode a known elementary file's contents.
--
-- Returns nil when the file is not one we understand, which is the
-- common case and not an error.
function M.decode_ef(tvb, offset, length, fid_hex)
    local values = util.byte_array(tvb, offset, length)
    if values == nil or #values == 0 then
        return nil
    end

    if fid_hex == M.EF_ICCID then
        -- Odd digit counts are normal: a 19-digit ICCID leaves a
        -- trailing 0xF padding nibble. Tools/EumDiag/dissector.lua
        -- divides the digit count by two and hands the result to a
        -- TvbRange, which is why it breaks here.
        return { kind = "iccid", value = util.decode_swapped_bcd(values) }
    end

    if fid_hex == M.EF_IMSI then
        return { kind = "imsi", value = decode_imsi(values) }
    end

    if fid_hex == M.EF_UST then
        return { kind = "ust", services = service_numbers(values) }
    end

    if fid_hex == M.EF_AD then
        local parsed = { kind = "ad", operation_mode = values[1] }
        if #values >= 4 then
            parsed.mnc_length = values[4] % 16
        end
        return parsed
    end

    return nil
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
