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
    -- The '60' block is not a dense run. TS 101 220 clause 7.2 leaves
    -- reserved slots inside it, so packing the assigned names together
    -- from '60' shifts all 22 of them: IMEISV is '62', not '60', and
    -- the last five sit at '7A' to '7E' rather than '71' to '75'.
    [0x60] = "MAC",
    [0x62] = "IMEISV",
    [0x63] = "Battery state",
    [0x64] = "Browsing status",
    [0x65] = "Network search mode",
    [0x66] = "Frame layout",
    [0x67] = "Frames information",
    [0x68] = "Frame identifier",
    [0x69] = "UTRAN/E-UTRAN measurement qualifier",
    [0x6A] = "Multimedia message reference",
    [0x6B] = "Multimedia message identifier",
    [0x6C] = "Multimedia message transfer status",
    [0x6D] = "MEID",
    [0x6E] = "Multimedia message content identifier",
    [0x6F] = "Multimedia message notification",
    [0x70] = "Last envelope",
    [0x71] = "Registry application data",
    [0x72] = "PLMN with access technology list",
    [0x7A] = "Broadcast network information",
    [0x7B] = "ACTIVATE descriptor",
    [0x7C] = "EPS PDN connection activation parameters",
    [0x7D] = "Tracking area identification",
    [0x7E] = "CSG identifier list",
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

-- Clause 8.7 also allocates '31' to '3F' to eCAT clients 1 to 15,
-- which is how an eCAT client addresses the UICC.
for _ecat = 0x31, 0x3F do
    DEVICE_NAMES[_ecat] = string.format("eCAT client %d", _ecat - 0x30)
end

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

-- ETSI TS 102 223 clause 8.12.11, the second Result byte when the
-- general result is '3A'. This is the byte that says *why* a BIP channel failed,
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

-- ETSI TS 102 223 clause 8.12.2, the second Result byte when the
-- general result is '20'.
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

-- ETSI TS 102 223 clause 8.12.10, general result '26'.
local BROWSER_ADDITIONAL_INFO = {
    [0x00] = "no specific cause given",
    [0x01] = "bearer unavailable",
    [0x02] = "browser unavailable",
    [0x03] = "terminal unable to read the provisioning data",
    [0x04] = "default URL unavailable",
}

-- Clause 8.12.0 makes a cause byte mandatory for '20', '21', '26',
-- '38', '39', '3A', '3C' and '3D'. Only three of the eight were decoded,
-- so the other five reported the layer and nothing else -- the same
-- defect the BIP table above exists to fix, on five more results.

-- Clause 8.12.3, general result '21' (network unable to process).
local NETWORK_ADDITIONAL_INFO = {
    [0x00] = "no specific cause given",
    [0x01] = "no service",
    [0x02] = "access control class bar",
    [0x03] = "radio resource not granted",
    [0x04] = "not in speech call",
}

-- Clause 8.12.9, general result '38' (MultipleCard commands error).
local MULTIPLE_CARD_ADDITIONAL_INFO = {
    [0x00] = "no specific cause given",
    [0x01] = "card reader removed or not present",
    [0x02] = "card removed or not present",
    [0x03] = "card reader busy",
    [0x04] = "card powered off",
    [0x05] = "C-APDU format error",
    [0x06] = "mute card",
    [0x07] = "transmission error",
    [0x08] = "protocol not supported",
    [0x09] = "specified reader not valid",
}

-- Clause 8.12.8, general result '39' (interaction with call control or
-- SMS control by the NAA, permanent problem).
local CONTROL_ADDITIONAL_INFO = {
    [0x00] = "no specific cause given",
    [0x01] = "action not allowed",
    [0x02] = "the type of request has changed",
}

-- Clause 8.12.12, general result '3C' (frames error).
local FRAMES_ADDITIONAL_INFO = {
    [0x00] = "no specific cause given",
    [0x01] = "frame identifier is not valid",
    [0x02] = "number of frames beyond the terminal's capabilities",
    [0x03] = "no frame defined",
    [0x04] = "requested size not supported",
    [0x05] = "default active frame is not valid",
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
    if result == 0x21 then
        return NETWORK_ADDITIONAL_INFO[value]
            or string.format("network cause 0x%02X", value)
    end
    if result == 0x38 then
        return MULTIPLE_CARD_ADDITIONAL_INFO[value]
            or string.format("card command cause 0x%02X", value)
    end
    if result == 0x39 then
        return CONTROL_ADDITIONAL_INFO[value]
            or string.format("control cause 0x%02X", value)
    end
    if result == 0x3C then
        return FRAMES_ADDITIONAL_INFO[value]
            or string.format("frames cause 0x%02X", value)
    end
    if result == 0x3D then
        -- Clause 8.12.13 defers the MMS cause to the MMS layer, so the
        -- byte is reported rather than named.
        return string.format("MMS error cause 0x%02X", value)
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

-- PROVIDE LOCAL INFORMATION qualifiers, ETSI TS 102 223 clause 8.6
-- with the 3GPP TS 31.111 additions.
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
    -- '0F' and '10' are the multiple-access-technology pair, not the
    -- H(e)NB values -- those sit two slots further on. Placing the
    -- H(e)NB names here reported a terminal asked for its serving-cell
    -- location as one asked for a femtocell's IP address.
    [0x0E] = "multiple access technologies",
    [0x0F] = "location information for multiple access technologies",
    [0x10] = "network measurement results for multiple access technologies",
    [0x11] = "CSG ID list and corresponding HNB name",
    [0x12] = "H(e)NB IP address",
    [0x13] = "H(e)NB surrounding macrocells",
    [0x1A] = "supported radio access technologies",
}

-- TIMER MANAGEMENT, clause 6.4.21. Bits 1 to 2 carry the operation and
-- bits 3 to 8 are RFU, so the mask is two bits wide, not three.
local TIMER_OPERATION = {
    [0x00] = "start",
    [0x01] = "deactivate",
    [0x02] = "get current value",
}

-- LAUNCH BROWSER, clause 6.4.26. A whole-byte enumeration, not a bit
-- field: '01' and '04' are explicitly "not used" and '05' upward is RFU.
local BROWSER_OPERATION = {
    [0x00] = "launch if not already launched",
    [0x02] = "use the existing browser",
    [0x03] = "close the existing session and launch a new browser",
}

-- SET UP CALL, clause 6.4.13. Also a whole-byte enumeration: '06' to
-- 'FF' are reserved.
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
        -- Bits 1 to 2 only; bits 3 to 8 are RFU.
        return TIMER_OPERATION[qualifier % 4]
            or string.format("0x%02X", qualifier)
    end
    if command_type == 0x15 then
        -- A whole-byte enumeration. Masking it folded the "not used"
        -- value '04' onto '00' and reported it as a real operation.
        return BROWSER_OPERATION[qualifier]
            or string.format("0x%02X", qualifier)
    end
    if command_type == 0x10 then
        -- Likewise a whole-byte enumeration: '08' is reserved, not
        -- "only if not currently busy on another call".
        return CALL_HANDLING[qualifier]
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
        -- Bit 3 reads the other way round from the rest: TS 102 223
        -- clause 8.6 gives 0 = "terminal may echo user input" and
        -- 1 = "user input shall not be revealed". Reporting the set bit
        -- as echo turns a PIN prompt into an echoing one, and an
        -- echoing prompt into a hidden one -- backwards in both
        -- directions, on the command that collects PINs.
        local named = bit_flags(qualifier, {
            [1] = "alphabet set",
            [2] = "UCS2 alphabet",
            [4] = "input shall not be revealed",
            [8] = "SMS-packed input",
            [128] = "help information available",
        })
        if named == "" then
            return "digits only, terminal may echo"
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
    if command_type == 0x25 then
        -- SET UP MENU, clause 6.4.8. Bit 1 really is the soft-key
        -- preference here.
        return bit_flags(qualifier, {
            [1] = "soft key preferred",
            [128] = "help information available",
        })
    end
    if command_type == 0x24 then
        -- SELECT ITEM, clause 6.4.9, which does not share SET UP MENU's
        -- bit map: bits 1 and 2 are the presentation type and the soft
        -- key preference is bit 3. Reusing the menu map read a choice of
        -- data values as a soft-key request.
        local parts = {}
        if qualifier % 2 == 1 then
            if math.floor(qualifier / 2) % 2 == 1 then
                parts[#parts + 1] = "presented as a choice of navigation options"
            else
                parts[#parts + 1] = "presented as a choice of data values"
            end
        else
            parts[#parts + 1] = "presentation type not specified"
        end
        if math.floor(qualifier / 4) % 2 == 1 then
            parts[#parts + 1] = "soft key preferred"
        end
        if math.floor(qualifier / 128) % 2 == 1 then
            parts[#parts + 1] = "help information available"
        end
        return table.concat(parts, ", ")
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
        -- 3GPP TS 23.003 clause 9.1 limits a label to the alphabetic
        -- characters, digits and the hyphen, and RFC 1035 clause 2.3.4
        -- caps it at 63 octets. Pushing an unvalidated label into an
        -- FT_STRING lets a NUL truncate the field: '04 69 00 6F ...'
        -- rendered as "i" and silently dropped everything after it.
        if length > 63 then
            return ""
        end
        local characters = {}
        for offset = 1, length do
            local character = values[index + offset]
            if character < 45 or character > 122 then
                return ""
            end
            characters[offset] = string.char(character)
        end
        parts[#parts + 1] = table.concat(characters)
        index = index + length + 1
    end
    return table.concat(parts, ".")
end

--- Decode an Other Address: a type byte then an IPv4 or IPv6 literal.
-- Clause 8.58 gives "request a dynamic address" to Length = '00' with no
-- value part, and nothing else. Returning "" for a truncated IPv4, a
-- truncated IPv6 and an unknown type byte alike made the caller render
-- all three as a dynamic-address request -- a specific claim about what
-- the card asked for, made out of bytes it could not read.
function M.decode_other_address(values)
    if values == nil or #values == 0 then
        return ""
    end
    if #values < 2 then
        return string.format("malformed Other address (%d bytes)", #values)
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
    return string.format(
        "malformed Other address (type 0x%02X, %d bytes)", kind, #values
    )
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

-- ETSI TS 102 223 clause 7.5 / TS 101 220 clause 7.2: the BER tag that
-- wraps an ENVELOPE body. The contents are COMPREHENSION-TLV, but the
-- wrapper itself is not, so it has to be stepped over in BER before the
-- comprehension walker runs -- exactly as the 'D0' proactive wrapper is.
--
-- 'D8' is reserved for intra-UICC communication and carries no ENVELOPE
-- of its own, which is the gap that makes this run easy to number one
-- slot short: 3GPP TS 31.111 clause 9.1 puts USSD download at 'D9',
-- Geographical Location Reporting at 'DD' and ProSe Report at 'DF'.
-- Closing the gap shifts every tag from 'D9' up and drops 'DF' off the
-- end, so a USSD download reports as an MMS transfer status and a ProSe
-- report is not recognised as an ENVELOPE at all.
local ENVELOPE_TAGS = {
    [0xD1] = "SMS-PP download",
    [0xD2] = "Cell broadcast download",
    [0xD3] = "Menu selection",
    [0xD4] = "Call control",
    [0xD5] = "MO short message control",
    [0xD6] = "Event download",
    [0xD7] = "Timer expiration",
    [0xD8] = "reserved for intra-UICC communication",
    [0xD9] = "USSD download",
    [0xDA] = "MMS transfer status",
    [0xDB] = "MMS notification download",
    [0xDC] = "Terminal application",
    [0xDD] = "Geographical location reporting",
    [0xDE] = "Envelope container",
    [0xDF] = "ProSe report",
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
    [52] = "too_many_cids_requested",
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
    [117] = "general_error",
    [120] = "no_application_protocol",
    [121] = "ech_required",
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
    -- RFC 8879 certificate compression. Worth naming here in particular:
    -- an SM-DP+ chain runs to kilobytes across ~236-byte channel-data
    -- blocks, which is exactly the pressure that gets compression turned
    -- on, so this is a likely handshake type on this transport.
    [25] = "compressed_certificate",
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
    -- Record-layer version. RFC 8446 clause 5.1 pins legacy_record_version
    -- to 0x0303 for TLS 1.3 (0x0301 on an initial ClientHello), so the
    -- set that ever reaches the wire is 0x0300 to 0x0303. 0x0304 is a
    -- protocol version, never a record version, and accepting it only
    -- widens the false-positive surface of a five-byte sniff.
    if values[2] ~= 0x03 or values[3] > 0x03 then
        return nil
    end
    local length = (values[4] * 256) + values[5]
    -- RFC 8446 clause 5.1 caps a plaintext record at 2^14 and clause 5.2
    -- a ciphertext one at 2^14 + 256. A larger claim is not a record.
    if length > 16640 then
        return nil
    end
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
    elseif content_type == 21 and length ~= 2 then
        -- A declared length of 2 is the plaintext single-alert shape --
        -- RFC 8446 clause 5.1 forbids fragmenting or coalescing alerts,
        -- so under TLS 1.3 it can be nothing else. Reaching here with
        -- length 2 therefore means the block was cut short, not that the
        -- body is ciphered, and reporting "encrypted" for a record the
        -- decoder merely has not finished reading contradicts the
        -- tls_incomplete flag set alongside it. That case is routine
        -- here: a record split across ~236-byte channel-data blocks.
        record.alert_encrypted = true
    end
    if content_type == 22 and #values >= 6 then
        record.handshake_type = values[6]
        record.handshake_type_name = M.tls_handshake_type_name(values[6])
    end
    return record
end

--- True when the bytes plausibly begin a DNS message.
--
-- RFC 1035 clause 4.1.1 fixes a 12-byte header: a 16-bit identifier,
-- then flags whose Z field (bits 4 to 6 of the second flag byte) is
-- reserved and must be zero and whose OPCODE is 0 to 2, then four
-- 16-bit counts. Clause 4.1.2 follows it with a QNAME, a chain of
-- length-prefixed labels ending in a zero byte, each at most 63 bytes
-- (clause 2.3.4).
--
-- Checking the label chain terminates inside the buffer is what
-- separates a real query from a payload that merely starts with
-- plausible counts.
--
-- *base* is the number of leading bytes to skip -- 0 for a UDP message,
-- 2 for a TCP one, whose RFC 1035 clause 4.2.2 length prefix sits ahead
-- of the header.
function M.looks_like_dns(values, base)
    base = base or 0
    if values == nil or #values < base + 12 then
        return false
    end
    local opcode = math.floor(values[base + 3] / 8) % 16
    if opcode > 2 then
        return false
    end
    if math.floor(values[base + 4] / 16) % 8 ~= 0 then
        return false
    end
    local questions = (values[base + 5] * 256) + values[base + 6]
    if questions < 1 or questions > 16 then
        return false
    end
    -- Walk the first QNAME. A compression pointer (top two bits set) is
    -- legal in a response but never opens a question, so it is not
    -- followed here.
    local index = base + 13
    while index <= #values do
        local label = values[index]
        if label == 0 then
            -- QTYPE and QCLASS follow the terminator.
            return (index + 4) <= #values
        end
        if label > 63 then
            return false
        end
        index = index + label + 1
    end
    return false
end

--- True when the bytes look like a DTLS record.
--
-- DTLS shares the content types and the 0x03 major version but not the
-- header: RFC 6347 clause 4.1 inserts a two-byte epoch and a six-byte
-- sequence number ahead of the length, so the record is 13 bytes and
-- peek_tls_record above reads the length out of the sequence number.
-- The version is the one-s-complement pair 'FE FD' for DTLS 1.2 and
-- 'FE FF' for DTLS 1.0, which is what identifies it.
--
-- Recognising it matters because the port fallback below otherwise
-- hands DTLS to the TLS dissector on a UDP channel opened to 443. That
-- produces a bare Transport Layer Security node with no record layer
-- and no malformed complaint -- a protocol claim that is wrong and
-- silent about being wrong, which is worse than the raw bytes.
function M.is_dtls_record(values)
    if values == nil or #values < 13 then
        return false
    end
    if TLS_CONTENT_TYPES[values[1]] == nil then
        return false
    end
    return values[2] == 0xFE and (values[3] == 0xFD or values[3] == 0xFF)
end

--- Which stock Wireshark dissector suits a BIP channel payload.
--
-- Handing the bytes to the real dissector beats a hand-rolled decode:
-- Wireshark already knows how to read DNS, TLS and HTTP, and the tree it
-- produces is the one an engineer already knows how to navigate. A
-- single TLS alert record handed to the stock dissector renders as
-- "Alert (Level: Fatal, Description: Bad Certificate)", which is exactly
-- what a failed profile download needs to show. That reading is a
-- TLS 1.2-and-earlier one: from the server's first flight onward a
-- TLS 1.3 alert is encrypted and carries outer type 23, so it arrives
-- indistinguishable from application data.
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
    if M.is_dtls_record(values) then
        return "dtls"
    end

    -- RFC 9112 clause 2.2 tells a server to ignore at least one empty
    -- line before the request-line, and a card that sends one would
    -- otherwise break the prefix on its first byte and match nothing.
    local start = 1
    while start <= #values and start <= 3
        and (values[start] == 13 or values[start] == 10) do
        start = start + 1
    end
    local prefix = ""
    for index = start, math.min(start + 15, #values) do
        local character = values[index]
        if character < 32 or character > 126 then
            break
        end
        prefix = prefix .. string.char(character)
    end
    -- RFC 9110 clause 9.3 defines eight methods; PATCH is RFC 5789.
    -- Matching is case-sensitive, which clause 9.1 requires.
    if prefix:match("^HTTP/1") or prefix:match("^GET ") or prefix:match("^POST ")
        or prefix:match("^PUT ") or prefix:match("^HEAD ")
        or prefix:match("^DELETE ") or prefix:match("^OPTIONS ")
        or prefix:match("^PATCH ") or prefix:match("^CONNECT ")
        or prefix:match("^TRACE ") then
        return "http"
    end

    -- DNS over a UDP BIP channel starts at the DNS header. Over TCP it
    -- is preceded by a two-byte length, which the stock dns dissector
    -- does not expect on a bare tvb, so it is not handed over: a
    -- malformed-packet complaint would be worse than the raw bytes.
    if port == 53 then
        if transport == "tcp" then
            -- DNS over TCP prefixes the message with a two-byte length
            -- (RFC 1035 clause 4.2.2). The stock dns dissector expects a
            -- bare message on a channel tvb, so the prefix is stripped
            -- before handoff -- but only when it agrees with the payload
            -- and what follows is actually DNS. A second return value
            -- tells the caller how many bytes to skip; the alternative,
            -- handing the length bytes over as though they were the
            -- header, is the malformed decode this whole gate exists to
            -- avoid.
            if #values >= 2 then
                local declared = (values[1] * 256) + values[2]
                if declared == #values - 2 and M.looks_like_dns(values, 2) then
                    return "dns", 2
                end
            end
            return ""
        end
        -- The port alone is not evidence. A channel opened on 53 still
        -- carries whatever the card sends, and handing a profile-package
        -- fragment to the DNS dissector renders a header invented out of
        -- its length fields -- "Questions: 28576" -- followed by a
        -- malformed-packet complaint. That is the confidently-wrong
        -- output this dissector exists to remove, so the bytes have to
        -- look like a DNS message before they are handed over.
        if not M.looks_like_dns(values) then
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

--- The class byte with its logical channel folded out.
--
-- Channels 0 to 3 sit in the low nibble of '8X', so clearing the nibble
-- is enough. Channels 4 to 19 use the further interindustry shape, which
-- moves the class itself to 'C0'--'FE'; see iso7816.base_class, which
-- this mirrors so cat.lua stays free of that dependency.
local function class_base(cla)
    if cla >= 0xC0 and cla <= 0xFE then
        return 0x80
    end
    return cla - (cla % 16)
end

--- True when this instruction carries CAT content.
--
-- CAT rides on class '8X' (ETSI TS 102 221) and on the classic GSM class
-- 'A0' (TS 51.011). Logical channels vary the low two bits and secure
-- messaging bits 4 and 3, so masking only the channel bits rejected
-- '8C' -- a secure-messaged FETCH -- as though it were another command,
-- and masking the nibble alone still rejects a FETCH issued on a channel
-- above 3.
function M.is_cat_instruction(cla, ins)
    local base = class_base(cla)
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
    local base = class_base(cla)
    return (base == 0x80 or base == 0xA0) and ins == 0x10
end

return M
