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

-- ETSI TS 101 220 clause 7.2, the COMPREHENSION-TLV tag allocation
-- shared by TS 102 223, TS 31.111 and TS 102 226. Given in base form:
-- bit 8 is the comprehension-required flag, stripped before lookup.
local TAG_NAMES = {
    [0x01] = "Command details",
    [0x02] = "Device identities",
    [0x03] = "Result",
    [0x04] = "Duration",
    [0x05] = "Alpha identifier",
    [0x06] = "Address",
    [0x07] = "Capability configuration parameters",
    [0x08] = "Subaddress",
    [0x09] = "SS string",
    [0x0A] = "USSD string",
    [0x0B] = "SMS TPDU",
    [0x0C] = "Cell broadcast page",
    [0x0D] = "Text string",
    [0x0E] = "Tone",
    [0x0F] = "Item",
    [0x10] = "Item identifier",
    [0x11] = "Response length",
    [0x12] = "File list",
    [0x13] = "Location information",
    [0x14] = "IMEI",
    [0x15] = "Help request",
    [0x16] = "Network measurement results",
    [0x17] = "Default text",
    [0x18] = "Items next action indicator",
    [0x19] = "Event list",
    [0x1A] = "Cause",
    [0x1B] = "Location status",
    [0x1C] = "Transaction identifier",
    [0x1D] = "BCCH channel list",
    [0x1E] = "Icon identifier",
    [0x1F] = "Item icon identifier list",
    [0x20] = "Card reader status",
    [0x21] = "Card ATR",
    [0x22] = "C-APDU",
    [0x23] = "R-APDU",
    [0x24] = "Timer identifier",
    [0x25] = "Timer value",
    [0x26] = "Date-time and time zone",
    [0x27] = "Call control requested action",
    [0x28] = "AT command",
    [0x29] = "AT response",
    [0x2A] = "BC repeat indicator",
    [0x2B] = "Immediate response",
    [0x2C] = "DTMF string",
    [0x2D] = "Language",
    [0x2E] = "Timing advance",
    [0x2F] = "AID",
    [0x30] = "Browser identity",
    [0x31] = "URL",
    [0x32] = "Bearer",
    [0x33] = "Provisioning reference file",
    [0x34] = "Browser termination cause",
    [0x35] = "Bearer description",
    [0x36] = "Channel data",
    [0x37] = "Channel data length",
    [0x38] = "Channel status",
    [0x39] = "Buffer size",
    [0x3A] = "Card reader identifier",
    [0x3B] = "File update information",
    [0x3C] = "UICC/terminal interface transport level",
    [0x3E] = "Other address",
    [0x3F] = "Access technology",
    [0x40] = "Display parameters",
    [0x41] = "Service record",
    [0x42] = "Device filter",
    [0x43] = "Service search",
    [0x44] = "Attribute information",
    [0x45] = "Service availability",
    [0x46] = "ESN",
    [0x47] = "Network access name",
    [0x48] = "CDMA-SMS TPDU",
    [0x49] = "Remote entity address",
    [0x4A] = "I-WLAN identifier",
    [0x4B] = "I-WLAN access status",
    [0x50] = "Text attribute",
    [0x51] = "Item text attribute list",
    [0x52] = "PDP context activation parameters",
    [0x53] = "Contactless state request",
    [0x54] = "Contactless functionality state",
    [0x55] = "CSG cell selection status",
    [0x56] = "CSG identifier",
    [0x57] = "HNB name",
    [0x60] = "IMEISV",
    [0x61] = "Battery state",
    [0x62] = "Browsing status",
    [0x63] = "Network search mode",
    [0x64] = "Frame layout",
    [0x65] = "Frames information",
    [0x66] = "Frame identifier",
    [0x67] = "UTRAN/E-UTRAN measurement qualifier",
    [0x68] = "Multimedia message reference",
    [0x69] = "Multimedia message identifier",
    [0x6A] = "Multimedia message transfer status",
    [0x6B] = "MEID",
    [0x6C] = "Multimedia message content identifier",
    [0x6D] = "Multimedia message notification",
    [0x6E] = "Last envelope",
    [0x6F] = "Registry application data",
    [0x70] = "PLMN with access technology list",
    [0x71] = "Broadcast network information",
    [0x72] = "ACTIVATE descriptor",
    [0x73] = "EPS PDN connection activation parameters",
    [0x74] = "Tracking area identification",
    [0x75] = "CSG identifier list",
}

-- ETSI TS 102 223 clause 8.7 device identities.
--
-- '81' is the UICC and '82' is the terminal, not the other way round --
-- getting this pair backwards reverses the reported direction of every
-- proactive command and every terminal response in the capture. The
-- channel block starts at '21', not '10'; '10' to '17' are additional
-- card readers.
local DEVICE_NAMES = {
    [0x01] = "keypad",
    [0x02] = "display",
    [0x03] = "earpiece",
    [0x10] = "additional card reader 0",
    [0x11] = "additional card reader 1",
    [0x12] = "additional card reader 2",
    [0x13] = "additional card reader 3",
    [0x14] = "additional card reader 4",
    [0x15] = "additional card reader 5",
    [0x16] = "additional card reader 6",
    [0x17] = "additional card reader 7",
    [0x21] = "channel 1",
    [0x22] = "channel 2",
    [0x23] = "channel 3",
    [0x24] = "channel 4",
    [0x25] = "channel 5",
    [0x26] = "channel 6",
    [0x27] = "channel 7",
    [0x81] = "UICC",
    [0x82] = "terminal",
    [0x83] = "network",
}

-- ETSI TS 102 223 clause 8.12 general result.
--
-- The block from '04' up is easy to shift by two, and the consequence is
-- that a REFRESH which simply could not draw an icon is reported as an
-- inactive NAA. Each entry below is the value the specification assigns.
local RESULT_NAMES = {
    [0x00] = "command performed successfully",
    [0x01] = "command performed with partial comprehension",
    [0x02] = "command performed, with missing information",
    [0x03] = "REFRESH performed with additional EFs read",
    [0x04] = "command performed, but requested icon could not be displayed",
    [0x05] = "command performed, but modified by call control by NAA",
    [0x06] = "command performed successfully, limited service",
    [0x07] = "command performed with modification",
    [0x08] = "REFRESH performed but indicated NAA was not active",
    [0x09] = "command performed successfully, tone not played",
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
    [0x25] = "interaction with call control by NAA, temporary problem",
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

-- ETSI TS 102 223 clause 8.12.3, the second Result byte when the general
-- result is '3A'. This is the byte that says *why* a BIP channel failed,
-- and without it "bearer independent protocol error" covers everything
-- from "the modem rejected the channel identifier" to "the SM-DP+ is
-- unreachable".
local BIP_ADDITIONAL_INFO = {
    [0x00] = "no specific cause given",
    [0x01] = "no channel available",
    [0x02] = "channel closed",
    [0x03] = "channel identifier not valid",
    [0x04] = "requested buffer size not available",
    [0x05] = "security error (unsuccessful authentication)",
    [0x06] = "requested UICC/terminal interface transport level not available",
    [0x07] = "remote device is not reachable",
    [0x08] = "service error",
    [0x09] = "service identifier unknown",
    [0x10] = "port not available",
    [0x11] = "launch parameters missing or incorrect",
    [0x12] = "application launch failed",
}

-- ETSI TS 102 223 clause 8.12.2, the second Result byte when the general
-- result is '20'.
local TERMINAL_ADDITIONAL_INFO = {
    [0x00] = "no specific cause given",
    [0x01] = "screen is busy",
    [0x02] = "terminal currently busy on call",
    [0x03] = "terminal currently busy on SS transaction",
    [0x04] = "no service",
    [0x05] = "access control class bar",
    [0x06] = "radio resource not granted",
    [0x07] = "not in speech call",
    [0x08] = "terminal currently busy on USSD transaction",
    [0x09] = "terminal currently busy on SEND DTMF command",
    [0x0A] = "no NAA active",
}

-- ETSI TS 102 223 clause 8.12.4, general result '26'.
local BROWSER_ADDITIONAL_INFO = {
    [0x00] = "no specific cause given",
    [0x01] = "bearer unavailable",
    [0x02] = "browser unavailable",
    [0x03] = "terminal unable to read the provisioning data",
    [0x04] = "default URL unavailable",
}

-- ETSI TS 102 223 clause 8.59, UICC/terminal interface transport level.
--
-- '01' and '02' are remote connections and '04' and '05' are local ones.
-- Swapping them reports a channel that terminates on the handset itself
-- as a channel to the network.
local TRANSPORT_NAMES = {
    [0x01] = "UDP, UICC in client mode, remote connection",
    [0x02] = "TCP, UICC in client mode, remote connection",
    [0x03] = "TCP, UICC in server mode",
    [0x04] = "UDP, UICC in client mode, local connection",
    [0x05] = "TCP, UICC in client mode, local connection",
    [0x06] = "direct communication channel",
}

-- ETSI TS 102 223 clause 8.52, bearer type.
--
-- The list starts at '01'; '00' is not assigned. Numbering it from zero
-- shifts every entry, which matters here more than most off-by-ones
-- because '03' -- the default packet bearer this repo's own toolkit
-- emits -- then reads as "local link technology independent".
local BEARER_NAMES = {
    [0x01] = "CSD",
    [0x02] = "GPRS / UTRAN packet service / E-UTRAN",
    [0x03] = "default bearer for requested transport layer",
    [0x04] = "local link technology independent",
    [0x05] = "Bluetooth",
    [0x06] = "IrDA",
    [0x07] = "RS232",
    [0x08] = "cdma2000 packet data service",
    [0x09] = "UTRAN packet service with extended parameters",
    [0x0A] = "I-WLAN",
    [0x0B] = "E-UTRAN / mapped UTRAN packet service",
    [0x0C] = "NG-RAN",
    [0x10] = "USB",
}

function M.tag_name(tag)
    return TAG_NAMES[tag] or ""
end

function M.device_name(value)
    return DEVICE_NAMES[value] or string.format("0x%02X", value)
end

--- The BIP channel a device identity refers to, or nil.
--
-- Channel identities are '21' to '27'. Reading a channel number out of
-- '81' or '82' invents a channel that the command never mentioned.
function M.device_channel(value)
    if value ~= nil and value >= 0x21 and value <= 0x27 then
        return value - 0x20
    end
    return nil
end

function M.result_name(value)
    return RESULT_NAMES[value] or string.format("result 0x%02X", value)
end

--- Name the second Result byte, whose meaning depends on the first.
--
-- Returns "" when the general result does not define one, which is the
-- common case: most results carry a single byte.
function M.result_additional_info(result, value)
    if value == nil then
        return ""
    end
    if result == 0x3A then
        return BIP_ADDITIONAL_INFO[value]
            or string.format("BIP cause 0x%02X", value)
    end
    if result == 0x20 then
        return TERMINAL_ADDITIONAL_INFO[value]
            or string.format("cause 0x%02X", value)
    end
    if result == 0x26 then
        return BROWSER_ADDITIONAL_INFO[value]
            or string.format("browser cause 0x%02X", value)
    end
    if result == 0x34 or result == 0x35 or result == 0x37 then
        -- The additional byte is the raw protocol error cause.
        return string.format("protocol error cause 0x%02X", value)
    end
    return ""
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

-- PROVIDE LOCAL INFORMATION, ETSI TS 102 223 clause 6.4.15 with the
-- 3GPP TS 31.111 additions.
local LOCAL_INFORMATION = {
    [0x00] = "location information",
    [0x01] = "IMEI",
    [0x02] = "network measurement results",
    [0x03] = "date, time and time zone",
    [0x04] = "language setting",
    [0x05] = "timing advance",
    [0x06] = "access technology",
    [0x07] = "ESN",
    [0x08] = "IMEISV",
    [0x09] = "search mode",
    [0x0A] = "charge state of the battery",
    [0x0B] = "MEID",
    [0x0D] = "broadcast network information",
    [0x0F] = "H(e)NB IP address",
    [0x10] = "H(e)NB surrounding macrocells",
    [0x11] = "CSG ID list and corresponding HNB name",
}

-- TIMER MANAGEMENT, clause 6.4.21.
local TIMER_OPERATION = {
    [0x00] = "start",
    [0x01] = "deactivate",
    [0x02] = "get current value",
}

-- LAUNCH BROWSER, clause 6.4.20.
local BROWSER_OPERATION = {
    [0x00] = "launch if not already launched",
    [0x02] = "use the existing browser",
    [0x03] = "close the existing session and launch a new browser",
}

-- SET UP CALL, clause 6.4.13.
local CALL_HANDLING = {
    [0x00] = "only if not currently busy on another call",
    [0x01] = "only if not currently busy on another call, with redial",
    [0x02] = "put all other calls on hold",
    [0x03] = "put all other calls on hold, with redial",
    [0x04] = "disconnect all other calls",
    [0x05] = "disconnect all other calls, with redial",
}

--- Collect the set bits of *qualifier* named by *bits*.
--
-- *bits* maps a bit weight to the phrase that applies when it is set.
local function bit_flags(qualifier, bits)
    local parts = {}
    local weights = {}
    for weight in pairs(bits) do
        weights[#weights + 1] = weight
    end
    table.sort(weights)
    for index = 1, #weights do
        local weight = weights[index]
        if math.floor(qualifier / weight) % 2 == 1 then
            parts[#parts + 1] = bits[weight]
        end
    end
    if #parts == 0 then
        return ""
    end
    return table.concat(parts, ", ")
end

--- Qualifier meaning, which is per command type.
--
-- The qualifier is where a proactive command says what it actually
-- wants: whether an OPEN CHANNEL is on-demand or immediate, whether a
-- SEND DATA transmits now or buffers, whether a TIMER MANAGEMENT starts
-- or stops a timer. Rendering it as a bare hex byte throws all of that
-- away on exactly the commands a BIP trace is made of.
function M.qualifier_name(command_type, qualifier)
    if command_type == 0x01 then
        return tables.REFRESH_QUALIFIERS[qualifier]
            or string.format("0x%02X", qualifier)
    end
    if command_type == 0x26 then
        return LOCAL_INFORMATION[qualifier] or string.format("0x%02X", qualifier)
    end
    if command_type == 0x40 then
        -- OPEN CHANNEL, clause 6.4.27.
        local named = bit_flags(qualifier, {
            [1] = "immediate link establishment",
            [2] = "automatic reconnection",
            [4] = "background mode",
            [8] = "DNS server addresses requested",
        })
        if named == "" then
            return "on-demand link establishment"
        end
        return named
    end
    if command_type == 0x43 then
        -- SEND DATA, clause 6.4.30.
        if qualifier % 2 == 1 then
            return "send data immediately"
        end
        return "store data in the Tx buffer"
    end
    if command_type == 0x21 then
        -- DISPLAY TEXT, clause 6.4.1.
        local named = bit_flags(qualifier, {
            [1] = "high priority",
            [128] = "wait for the user to clear the message",
        })
        if named == "" then
            return "normal priority, cleared after a delay"
        end
        return named
    end
    if command_type == 0x13 then
        -- SEND SHORT MESSAGE, clause 6.4.10.
        if qualifier % 2 == 1 then
            return "SMS packing by the terminal required"
        end
        return "packing not required"
    end
    if command_type == 0x27 then
        return TIMER_OPERATION[qualifier % 8]
            or string.format("0x%02X", qualifier)
    end
    if command_type == 0x15 then
        return BROWSER_OPERATION[qualifier % 4]
            or string.format("0x%02X", qualifier)
    end
    if command_type == 0x10 then
        return CALL_HANDLING[qualifier % 8]
            or string.format("0x%02X", qualifier)
    end
    if command_type == 0x22 then
        -- GET INKEY, clause 6.4.2.
        local named = bit_flags(qualifier, {
            [1] = "alphabet set",
            [2] = "UCS2 alphabet",
            [4] = "Yes/No response requested",
            [8] = "immediate digit response",
            [128] = "help information available",
        })
        if named == "" then
            return "digits only"
        end
        return named
    end
    if command_type == 0x23 then
        -- GET INPUT, clause 6.4.3.
        local named = bit_flags(qualifier, {
            [1] = "alphabet set",
            [2] = "UCS2 alphabet",
            [4] = "terminal shall echo the input",
            [8] = "SMS-packed input",
            [128] = "help information available",
        })
        if named == "" then
            return "digits only, hidden input"
        end
        return named
    end
    if command_type == 0x20 then
        -- PLAY TONE, clause 6.4.5.
        if qualifier % 2 == 1 then
            return "vibrate alert"
        end
        return "no vibrate alert"
    end
    if command_type == 0x25 or command_type == 0x24 then
        -- SET UP MENU and SELECT ITEM, clauses 6.4.9 and 6.4.8.
        return bit_flags(qualifier, {
            [1] = "soft key preferred",
            [128] = "help information available",
        })
    end
    if command_type == 0x35 then
        -- LANGUAGE NOTIFICATION, clause 6.4.25.
        if qualifier % 2 == 1 then
            return "specific language notification"
        end
        return "non-specific language notification"
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

--- The channel number a Channel status TLV refers to.
function M.channel_number(value)
    return value % 8
end

-- ETSI TS 102 223 clause 8.56, Channel status byte 2.
local CHANNEL_FURTHER_INFO = {
    [0x00] = "no further information",
    [0x05] = "link dropped",
}

--- Decode the two-byte Channel status TLV.
--
-- Byte 1 bit 8 is the only thing in a BIP trace that distinguishes a
-- channel that came up from one that never did, and byte 2 is where a
-- link that dropped mid-download says so. Reporting the identifier alone
-- makes a dead channel and a healthy one render identically.
function M.parse_channel_status(values)
    if values == nil or #values < 1 then
        return nil
    end
    local first = values[1]
    local identifier = first % 8
    local parsed = {
        identifier = identifier,
        established = math.floor(first / 128) % 2 == 1,
        -- Clause 8.56 gives identifier 0 to "no channel available"
        -- rather than to a channel numbered zero.
        no_channel = (identifier == 0),
    }
    if #values >= 2 then
        parsed.further_info = values[2]
        parsed.further_info_name = CHANNEL_FURTHER_INFO[values[2]]
            or string.format("0x%02X", values[2])
        parsed.link_dropped = (values[2] == 0x05)
    end
    return parsed
end

-- ETSI TS 102 223 clause 7.5 / TS 31.111: the BER tag that wraps an
-- ENVELOPE body. The contents are COMPREHENSION-TLV, but the wrapper
-- itself is not, so it has to be stepped over in BER before the
-- comprehension walker runs -- exactly as the 'D0' proactive wrapper is.
local ENVELOPE_TAGS = {
    [0xD1] = "SMS-PP download",
    [0xD2] = "Cell broadcast download",
    [0xD3] = "Menu selection",
    [0xD4] = "Call control",
    [0xD5] = "MO short message control",
    [0xD6] = "Event download",
    [0xD7] = "Timer expiration",
    [0xD8] = "USSD download",
    [0xD9] = "MMS transfer status",
    [0xDA] = "MMS notification download",
    [0xDB] = "Terminal application",
    [0xDC] = "Geographical location reporting",
    [0xDD] = "Envelope container",
    [0xDE] = "ProSe report",
}

--- Name an ENVELOPE wrapper tag, or "" when the tag is not one.
function M.envelope_name(tag)
    return ENVELOPE_TAGS[tag] or ""
end

--- True when *tag* introduces an ENVELOPE body.
function M.is_envelope_tag(tag)
    return ENVELOPE_TAGS[tag] ~= nil
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

--- TLS handshake message types (RFC 8446 clause 4, RFC 5246 clause 7.4).
--
-- Only needed when a record is split across SEND DATA blocks and the
-- stock dissector has nothing complete to work with; a whole record is
-- always better served by handing it over.
local TLS_HANDSHAKE_TYPES = {
    [0] = "hello_request",
    [1] = "client_hello",
    [2] = "server_hello",
    [3] = "hello_verify_request",
    [4] = "new_session_ticket",
    [5] = "end_of_early_data",
    [8] = "encrypted_extensions",
    [11] = "certificate",
    [12] = "server_key_exchange",
    [13] = "certificate_request",
    [14] = "server_hello_done",
    [15] = "certificate_verify",
    [16] = "client_key_exchange",
    [20] = "finished",
    [21] = "certificate_url",
    [22] = "certificate_status",
    [24] = "key_update",
    [254] = "message_hash",
}

function M.tls_handshake_type_name(value)
    return TLS_HANDSHAKE_TYPES[value]
        or string.format("handshake type %d", value)
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
    -- A plaintext alert is exactly two bytes. An encrypted one is longer,
    -- and reading bytes 6 and 7 out of ciphertext produces a random
    -- alert name -- roughly one time in 128 a fatal-looking one, which
    -- would raise a "fatal TLS alert" expert item over nothing at all.
    -- Under TLS 1.3 every post-handshake alert is wrapped in an
    -- application_data record and never reaches this branch, which is
    -- correct: those bytes genuinely cannot be read here.
    if content_type == 21 and length == 2 and #values >= 7 then
        record.alert_level = values[6]
        record.alert_level_name = M.tls_alert_level_name(values[6])
        record.alert_description = values[7]
        record.alert_description_name = M.tls_alert_description_name(values[7])
    elseif content_type == 21 then
        record.alert_encrypted = true
    end
    if content_type == 22 and #values >= 6 then
        record.handshake_type = values[6]
        record.handshake_type_name = M.tls_handshake_type_name(values[6])
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
function M.channel_payload_dissector(values, port, transport)
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

    -- DNS over a UDP BIP channel starts at the DNS header. Over TCP it
    -- is preceded by a two-byte length, which the stock dns dissector
    -- does not expect on a bare tvb, so it is not handed over: a
    -- malformed-packet complaint would be worse than the raw bytes.
    if port == 53 then
        if transport == "tcp" then
            return ""
        end
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
--
-- CAT rides on class '8X' (ETSI TS 102 221) and on the classic GSM class
-- 'A0' (TS 51.011). Logical channels vary the low two bits and secure
-- messaging bits 4 and 3, so masking only the channel bits rejected
-- '8C' -- a secure-messaged FETCH -- as though it were another command.
function M.is_cat_instruction(cla, ins)
    local base = cla - (cla % 16)
    if base ~= 0x80 and base ~= 0xA0 then
        return false
    end
    -- TERMINAL PROFILE (INS '10') is deliberately absent. Its body is a
    -- bit field per TS 102 223 clause 5.2, not TLV, and handing it to
    -- the comprehension walker invents tags out of capability bits.
    return ins == 0x12 or ins == 0x14 or ins == 0xC2
end

--- True for TERMINAL PROFILE, whose body is a bit field rather than TLV.
function M.is_terminal_profile(cla, ins)
    local base = cla - (cla % 16)
    return (base == 0x80 or base == 0xA0) and ins == 0x10
end

return M
