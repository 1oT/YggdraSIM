-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

-- ETSI TS 102 223 Card Application Toolkit, including BIP.
--
-- FETCH returns a proactive command; TERMINAL RESPONSE and ENVELOPE
-- carry the terminal's side of the conversation. All three are
-- COMPREHENSION-TLV, so the generic walker does the structural work and
-- this module supplies the names and the per-command readings.
--
-- Bearer Independent Protocol matters most in practice: an eUICC that
-- fetches a profile over BIP does it through OPEN CHANNEL, SEND DATA and
-- RECEIVE DATA, and the channel payload is ordinary DNS, TLS or HTTP
-- that Wireshark can already dissect if it is handed the bytes.
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

M.PROACTIVE_COMMAND_TAG = 0xD0

-- TS 101 220 clause 7.2 COMPREHENSION-TLV tag values, base form.
M.TAG_COMMAND_DETAILS = 0x01
M.TAG_DEVICE_IDENTITIES = 0x02
M.TAG_RESULT = 0x03
M.TAG_DURATION = 0x04
M.TAG_ALPHA_IDENTIFIER = 0x05
M.TAG_ADDRESS = 0x06
M.TAG_TEXT_STRING = 0x0D
M.TAG_EVENT_LIST = 0x19
M.TAG_TIMER_IDENTIFIER = 0x24
M.TAG_TIMER_VALUE = 0x25
M.TAG_BEARER_DESCRIPTION = 0x35
M.TAG_CHANNEL_DATA = 0x36
M.TAG_CHANNEL_DATA_LENGTH = 0x37
M.TAG_CHANNEL_STATUS = 0x38
M.TAG_BUFFER_SIZE = 0x39
M.TAG_TRANSPORT_LEVEL = 0x3C
M.TAG_OTHER_ADDRESS = 0x3E
M.TAG_NETWORK_ACCESS_NAME = 0x47

local TAG_NAMES = {
    [0x01] = "Command details",
    [0x02] = "Device identities",
    [0x03] = "Result",
    [0x04] = "Duration",
    [0x05] = "Alpha identifier",
    [0x06] = "Address",
    [0x0B] = "SMS TPDU",
    [0x0D] = "Text string",
    [0x0E] = "Tone",
    [0x0F] = "Item",
    [0x13] = "Location information",
    [0x14] = "IMEI",
    [0x19] = "Event list",
    [0x1C] = "BCCH channel list",
    [0x1D] = "Cause",
    [0x1E] = "Location status",
    [0x24] = "Timer identifier",
    [0x25] = "Timer value",
    [0x26] = "Date-time and time zone",
    [0x2F] = "AID",
    [0x32] = "Access technology",
    [0x35] = "Bearer description",
    [0x36] = "Channel data",
    [0x37] = "Channel data length",
    [0x38] = "Channel status",
    [0x39] = "Buffer size",
    [0x3C] = "UICC/terminal transport level",
    [0x3E] = "Other address",
    [0x3F] = "Access technology",
    [0x47] = "Network access name",
    [0x50] = "Text attribute",
}

-- TS 102 223 clause 8.7 device identities.
local DEVICE_NAMES = {
    [0x01] = "keypad",
    [0x02] = "display",
    [0x03] = "earpiece",
    [0x10] = "channel 1",
    [0x11] = "channel 2",
    [0x12] = "channel 3",
    [0x13] = "channel 4",
    [0x14] = "channel 5",
    [0x15] = "channel 6",
    [0x16] = "channel 7",
    [0x21] = "UICC",
    [0x82] = "UICC",
    [0x81] = "terminal",
    [0x83] = "network",
}

-- TS 102 223 clause 8.12 general result.
local RESULT_NAMES = {
    [0x00] = "command performed successfully",
    [0x01] = "command performed with partial comprehension",
    [0x02] = "command performed with missing information",
    [0x03] = "REFRESH performed with additional EFs read",
    [0x04] = "command performed successfully, limited service",
    [0x05] = "command performed with modification",
    [0x06] = "REFRESH performed but indicated NAA was not active",
    [0x07] = "command performed successfully, tone not played",
    [0x10] = "proactive session terminated by the user",
    [0x11] = "backward move requested by the user",
    [0x12] = "no response from the user",
    [0x13] = "help information required by the user",
    [0x14] = "USSD or SS transaction terminated by the user",
    [0x20] = "terminal currently unable to process the command",
    [0x21] = "network currently unable to process the command",
    [0x22] = "user did not accept the proactive command",
    [0x23] = "user cleared down the call before connection",
    [0x24] = "action in contradiction with the current timer state",
    [0x25] = "interaction with call control by the UICC, transient",
    [0x26] = "launch browser generic error code",
    [0x27] = "MMS temporary problem",
    [0x30] = "command beyond the terminal's capabilities",
    [0x31] = "command type not understood by the terminal",
    [0x32] = "command data not understood by the terminal",
    [0x33] = "command number not known by the terminal",
    [0x34] = "SS return error",
    [0x35] = "SMS RP-ERROR",
    [0x36] = "error, required values are missing",
    [0x37] = "USSD return error",
    [0x38] = "MultipleCard commands error",
    [0x39] = "interaction with call control or SMS control, permanent",
    [0x3A] = "bearer independent protocol error",
    [0x3B] = "access technology unable to process the command",
    [0x3C] = "frames error",
    [0x3D] = "MMS error",
}

-- TS 102 223 clause 8.52 transport protocol type.
local TRANSPORT_NAMES = {
    [0x01] = "UDP, UICC in client mode",
    [0x02] = "TCP, UICC in client mode",
    [0x03] = "TCP, UICC in server mode",
    [0x04] = "UDP, UICC in client mode, remote connection",
    [0x05] = "TCP, UICC in client mode, remote connection",
    [0x06] = "direct communication channel",
}

-- TS 102 223 clause 8.52 bearer type.
local BEARER_NAMES = {
    [0x00] = "CSD",
    [0x01] = "GPRS / UTRAN packet service / E-UTRAN",
    [0x02] = "default bearer for requested transport layer",
    [0x03] = "local link technology independent",
    [0x04] = "Bluetooth",
    [0x05] = "IrDA",
    [0x06] = "RS232",
    [0x07] = "cdma2000 packet data service",
    [0x08] = "UTRAN packet service with extended parameters",
    [0x09] = "I-WLAN",
    [0x0A] = "E-UTRAN / mapped UTRAN packet service",
    [0x0B] = "NG-RAN",
    [0x10] = "USB",
}

function M.tag_name(tag)
    return TAG_NAMES[tag] or ""
end

function M.device_name(value)
    return DEVICE_NAMES[value] or string.format("0x%02X", value)
end

function M.result_name(value)
    return RESULT_NAMES[value] or string.format("result 0x%02X", value)
end

function M.command_name(value)
    return tables.PROACTIVE_COMMANDS[value] or string.format("0x%02X", value)
end

function M.event_name(value)
    return tables.EVENT_NAMES[value] or string.format("event 0x%02X", value)
end

function M.transport_name(value)
    return TRANSPORT_NAMES[value] or string.format("transport 0x%02X", value)
end

function M.bearer_name(value)
    return BEARER_NAMES[value] or string.format("bearer 0x%02X", value)
end

--- Qualifier meaning, which is per command type.
function M.qualifier_name(command_type, qualifier)
    if command_type == 0x01 then
        return tables.REFRESH_QUALIFIERS[qualifier]
            or string.format("0x%02X", qualifier)
    end
    if command_type == 0x26 then
        -- PROVIDE LOCAL INFORMATION, clause 6.4.15.
        local names = {
            [0x00] = "location information",
            [0x01] = "IMEI",
            [0x02] = "network measurement results",
            [0x03] = "date, time and time zone",
            [0x04] = "language setting",
            [0x06] = "access technology",
            [0x07] = "ESN",
            [0x08] = "IMEISV",
            [0x09] = "search mode",
            [0x0A] = "charge state of the battery",
            [0x0B] = "MEID",
        }
        return names[qualifier] or string.format("0x%02X", qualifier)
    end
    return string.format("0x%02X", qualifier)
end

--- Decode a Network Access Name, which is a run of length-prefixed labels.
function M.decode_access_name(values)
    if values == nil or #values == 0 then
        return ""
    end
    local parts = {}
    local index = 1
    while index <= #values do
        local length = values[index]
        if length == 0 or index + length > #values then
            break
        end
        local characters = {}
        for offset = 1, length do
            characters[offset] = string.char(values[index + offset])
        end
        parts[#parts + 1] = table.concat(characters)
        index = index + length + 1
    end
    return table.concat(parts, ".")
end

--- Decode an Other Address: a type byte then an IPv4 or IPv6 literal.
function M.decode_other_address(values)
    if values == nil or #values < 2 then
        return ""
    end
    local kind = values[1]
    if kind == 0x21 and #values >= 5 then
        return string.format("%d.%d.%d.%d", values[2], values[3], values[4], values[5])
    end
    if kind == 0x57 and #values >= 17 then
        local groups = {}
        for index = 2, 17, 2 do
            groups[#groups + 1] = string.format(
                "%02x%02x", values[index], values[index + 1]
            )
        end
        return table.concat(groups, ":")
    end
    return ""
end

--- The channel number a BIP device identity or channel status refers to.
function M.channel_number(value)
    return value % 8
end

-- ------------------------------------------------------ channel payloads
--- TLS record content types (RFC 8446 clause 5.1, RFC 5246 appendix A.1).
local TLS_CONTENT_TYPES = {
    [20] = "change_cipher_spec",
    [21] = "alert",
    [22] = "handshake",
    [23] = "application_data",
    [24] = "heartbeat",
}

--- TLS alert levels (RFC 5246 clause 7.2).
local TLS_ALERT_LEVELS = {
    [1] = "warning",
    [2] = "fatal",
}

--- TLS AlertDescription values.
--
-- These are DECIMAL. bad_certificate is 42, which is 0x2A -- reading it
-- as hex 0x42 gives 66, which is unassigned, so an operator chasing a
-- certificate failure would see nothing. The distinction matters enough
-- to state: every number below is decimal.
local TLS_ALERT_DESCRIPTIONS = {
    [0] = "close_notify",
    [10] = "unexpected_message",
    [20] = "bad_record_mac",
    [21] = "decryption_failed",
    [22] = "record_overflow",
    [30] = "decompression_failure",
    [40] = "handshake_failure",
    [41] = "no_certificate",
    [42] = "bad_certificate",
    [43] = "unsupported_certificate",
    [44] = "certificate_revoked",
    [45] = "certificate_expired",
    [46] = "certificate_unknown",
    [47] = "illegal_parameter",
    [48] = "unknown_ca",
    [49] = "access_denied",
    [50] = "decode_error",
    [51] = "decrypt_error",
    [60] = "export_restriction",
    [70] = "protocol_version",
    [71] = "insufficient_security",
    [80] = "internal_error",
    [86] = "inappropriate_fallback",
    [90] = "user_canceled",
    [100] = "no_renegotiation",
    [109] = "missing_extension",
    [110] = "unsupported_extension",
    [111] = "certificate_unobtainable",
    [112] = "unrecognized_name",
    [113] = "bad_certificate_status_response",
    [114] = "bad_certificate_hash_value",
    [115] = "unknown_psk_identity",
    [116] = "certificate_required",
    [120] = "no_application_protocol",
}

function M.tls_content_type_name(value)
    return TLS_CONTENT_TYPES[value] or string.format("content type %d", value)
end

function M.tls_alert_level_name(value)
    return TLS_ALERT_LEVELS[value] or string.format("level %d", value)
end

function M.tls_alert_description_name(value)
    return TLS_ALERT_DESCRIPTIONS[value]
        or string.format("unassigned alert %d", value)
end

--- Inspect a TLS record header without consuming it.
--
-- Returns nil when the bytes are not a plausible record. The stock TLS
-- dissector handles a complete record far better than anything written
-- here, so this exists for two narrow purposes: deciding whether to hand
-- the bytes over at all, and reporting the alert when a record is split
-- across several channel-data blocks and the stock dissector has nothing
-- complete to work with.
function M.peek_tls_record(values)
    if values == nil or #values < 5 then
        return nil
    end
    local content_type = values[1]
    if TLS_CONTENT_TYPES[content_type] == nil then
        return nil
    end
    -- Record-layer version: 0x0300 through 0x0304.
    if values[2] ~= 0x03 or values[3] > 0x04 then
        return nil
    end
    local length = (values[4] * 256) + values[5]
    local record = {
        content_type = content_type,
        content_type_name = M.tls_content_type_name(content_type),
        major = values[2],
        minor = values[3],
        length = length,
        complete = (#values >= 5 + length),
    }
    if content_type == 21 and #values >= 7 then
        record.alert_level = values[6]
        record.alert_level_name = M.tls_alert_level_name(values[6])
        record.alert_description = values[7]
        record.alert_description_name = M.tls_alert_description_name(values[7])
    end
    return record
end

--- Which stock Wireshark dissector suits a BIP channel payload.
--
-- Handing the bytes to the real dissector beats a hand-rolled decode:
-- Wireshark already knows how to read DNS, TLS and HTTP, and the tree it
-- produces is the one an engineer already knows how to navigate. A
-- single TLS alert record handed to the stock dissector renders as
-- "Alert (Level: Fatal, Description: Bad Certificate)", which is exactly
-- what a failed profile download needs to show.
function M.channel_payload_dissector(values, port)
    if values == nil or #values == 0 then
        return ""
    end
    -- Content evidence first, port second. A channel opened on port 53
    -- can still carry something that is plainly not DNS, and the port
    -- may have been inherited from another channel when the device
    -- identity did not tie this command back to its OPEN CHANNEL. What
    -- the bytes actually say beats what the channel was opened for.
    if M.peek_tls_record(values) ~= nil then
        return "tls"
    end

    local prefix = ""
    for index = 1, math.min(16, #values) do
        local character = values[index]
        if character < 32 or character > 126 then
            break
        end
        prefix = prefix .. string.char(character)
    end
    if prefix:match("^HTTP/1") or prefix:match("^GET ") or prefix:match("^POST ")
        or prefix:match("^PUT ") or prefix:match("^HEAD ")
        or prefix:match("^DELETE ") or prefix:match("^OPTIONS ")
        or prefix:match("^PATCH ") then
        return "http"
    end

    -- DNS over a BIP channel is UDP, so the payload starts at the DNS
    -- header with no length prefix.
    if port == 53 then
        return "dns"
    end
    if port == 80 or port == 8080 then
        return "http"
    end
    if port == 443 or port == 8443 then
        return "tls"
    end
    return ""
end

--- TLV walker options naming COMPREHENSION-TLV tags.
function M.tlv_options()
    return {
        mode = "comprehension",
        resolver = function(tag)
            return M.tag_name(tag)
        end,
    }
end

--- True when this instruction carries CAT content.
function M.is_cat_instruction(cla, ins)
    local base = cla - (cla % 4)
    if base ~= 0x80 then
        return false
    end
    return ins == 0x12 or ins == 0x14 or ins == 0xC2 or ins == 0x10
end

return M
