# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""TERMINAL PROFILE decoder and builder, ETSI TS 102 223 V18.3.0 §5.2 with 3GPP TS 31.111 V19.4.0 §5.2.

Every bit and count field of bytes 1-39 is one ``Facility``, named in the
TS 102 223 wording; a bit TS 102 223 reserves for 3GPP carries the meaning its
parentheses give, and ``usat`` holds the TS 31.111 wording where the two
read differently. The module imports nothing outside the standard library, so
the same file runs as a stand-alone script (``main``).
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

SPEC = "ETSI TS 102 223 V18.3.0 §5.2, 3GPP TS 31.111 V19.4.0 §5.2"

# What a set bit means.
FACILITY = "facility"  # the terminal supports the facility
COUNT = "count"  # a number spread over the field's bits
NEGATIVE = "negative"  # the terminal lacks something (byte 14 b6, b7)
RFU = "rfu"  # "RFU, bit = 0"
DEPRECATED = "deprecated"  # "Deprecated, bit = 0"
FUTURE = "future"  # "Reserved by 3GPP (for future usage)"
FOREIGN = "foreign"  # bytes 19 and 20, kept for TIA/EIA-136-270 and 3GPP2 CCAT
ECAT_ONLY = "ecat-only"  # byte 32 b7, for an eCAT client profile only

_3GPP = "3GPP"
_3GPP_3GPP2 = "3GPP and 3GPP2"
_CC_BY_USIM = "Bit = 1 if Call Control by USIM is supported"


@dataclass(frozen=True)
class Facility:
    """One bit, or one multi-bit field, of the profile; ``bit`` is the lowest, b1 to b8."""

    byte: int
    bit: int
    name: str
    width: int = 1
    kind: str = FACILITY
    owner: str = ""
    usat: str = ""

    @property
    def address(self) -> str:
        """``byte.bit`` as the specification counts them, ``byte.low-high`` for a field."""
        if self.width == 1:
            return f"{self.byte}.{self.bit}"
        return f"{self.byte}.{self.bit}-{self.bit + self.width - 1}"

    @property
    def mask(self) -> int:
        return ((1 << self.width) - 1) << (self.bit - 1)

    @property
    def largest(self) -> int:
        """The largest legal value; byte 11 reserves 'FF'."""
        if self.byte == 11:
            return 0xFE
        return (1 << self.width) - 1

    def value_in(self, profile: bytes) -> int:
        """The field's value in *profile*; a byte the profile does not reach reads 0."""
        if self.byte > len(profile):
            return 0
        return (profile[self.byte - 1] & self.mask) >> (self.bit - 1)

    def describe(self) -> str:
        """The name with its owner, as one line."""
        if len(self.owner) > 0:
            return f"{self.name} ({self.owner})"
        return self.name


def _f(byte: int, bit: int, name: str, **extra: object) -> Facility:
    return Facility(byte, bit, name, **extra)  # type: ignore[arg-type]


# TS 102 223 V18.3.0 §5.2 pp. 27-35 draw each byte b1 first; TS 31.111 V19.4.0
# §5.2 pp. 23-28 defines the bits TS 102 223 reserves for 3GPP.
FACILITIES: tuple[Facility, ...] = (
    _f(1, 1, "Profile download"),
    _f(1, 2, "SMS-PP data download", owner=_3GPP),
    _f(1, 3, "Cell Broadcast data download", owner=_3GPP),
    _f(1, 4, "Menu selection"),
    _f(1, 5, "SMS-PP data download", owner=_3GPP,
       usat="Bit = 1 if SMS-PP data download is supported"),
    _f(1, 6, "Timer expiration"),
    _f(1, 7, "USSD string data object support in Call Control by USIM", owner=_3GPP_3GPP2,
       usat=_CC_BY_USIM),
    _f(1, 8, "Call Control by NAA", usat=_CC_BY_USIM),
    _f(2, 1, "Command result"),
    _f(2, 2, "Call Control by NAA", usat="Call Control by USIM"),
    _f(2, 3, "Call Control by NAA", usat=_CC_BY_USIM),
    _f(2, 4, "MO short message control support", owner=_3GPP,
       usat="MO short message control by USIM"),
    _f(2, 5, "Call Control by NAA", usat=_CC_BY_USIM),
    _f(2, 6, "UCS2 Entry supported"),
    _f(2, 7, "UCS2 Display supported"),
    _f(2, 8, "Display Text"),
    _f(3, 1, "Proactive UICC: DISPLAY TEXT"),
    _f(3, 2, "Proactive UICC: GET INKEY"),
    _f(3, 3, "Proactive UICC: GET INPUT"),
    _f(3, 4, "Proactive UICC: MORE TIME"),
    _f(3, 5, "Proactive UICC: PLAY TONE"),
    _f(3, 6, "Proactive UICC: POLL INTERVAL"),
    _f(3, 7, "Proactive UICC: POLLING OFF"),
    _f(3, 8, "Proactive UICC: REFRESH"),
    _f(4, 1, "Proactive UICC: SELECT ITEM"),
    _f(4, 2, "Proactive UICC: SEND SHORT MESSAGE with 3GPP-SMS-TPDU", owner=_3GPP,
       usat="Proactive UICC: SEND SHORT MESSAGE"),
    _f(4, 3, "Proactive UICC: SEND SS", owner=_3GPP),
    _f(4, 4, "Proactive UICC: SEND USSD", owner=_3GPP_3GPP2),
    _f(4, 5, "Proactive UICC: SET UP CALL"),
    _f(4, 6, "Proactive UICC: SET UP MENU"),
    _f(4, 7, "Proactive UICC: PROVIDE LOCAL INFORMATION (MCC, MNC, LAC, Cell ID & IMEI)"),
    _f(4, 8, "Proactive UICC: PROVIDE LOCAL INFORMATION (NMR)",
       usat="in 3GPP terms, this indicates support for GERAN"),
    _f(5, 1, "Proactive UICC: SET UP EVENT LIST"),
    _f(5, 2, "Event: MT call"),
    _f(5, 3, "Event: Call connected"),
    _f(5, 4, "Event: Call disconnected"),
    _f(5, 5, "Event: Location status"),
    _f(5, 6, "Event: User activity"),
    _f(5, 7, "Event: Idle screen available"),
    _f(5, 8, "Event: Card reader status"),
    _f(6, 1, "Event: Language selection"),
    _f(6, 2, 'Event: Browser Termination (i.e. class "ac" is supported)'),
    _f(6, 3, "Event: Data available"),
    _f(6, 4, "Event: Channel status"),
    _f(6, 5, "Event: Access Technology Change"),
    _f(6, 6, "Event: Display parameters changed"),
    _f(6, 7, "Event: Local Connection"),
    _f(6, 8, "Event: Network Search Mode Change"),
    _f(7, 1, "Proactive UICC: POWER ON CARD"),
    _f(7, 2, "Proactive UICC: POWER OFF CARD"),
    _f(7, 3, "Proactive UICC: PERFORM CARD APDU"),
    _f(7, 4, "Proactive UICC: GET READER STATUS (Card reader status)"),
    _f(7, 5, "Proactive UICC: GET READER STATUS (Card reader identifier)"),
    _f(7, 6, "RFU, bit = 0", width=3, kind=RFU),
    _f(8, 1, "Proactive UICC: TIMER MANAGEMENT (start, stop)"),
    _f(8, 2, "Proactive UICC: TIMER MANAGEMENT (get current value)"),
    _f(8, 3, "Proactive UICC: PROVIDE LOCAL INFORMATION (date, time and time zone)"),
    _f(8, 4, "GET INKEY"),
    _f(8, 5, "SET UP IDLE MODE TEXT"),
    _f(8, 6, 'RUN AT COMMAND (i.e. class "b" is supported)'),
    _f(8, 7, "SETUP CALL"),
    _f(8, 8, "Call Control by NAA", usat=_CC_BY_USIM),
    _f(9, 1, "DISPLAY TEXT"),
    _f(9, 2, "SEND DTMF command"),
    _f(9, 3, "Proactive UICC: PROVIDE LOCAL INFORMATION (NMR)"),
    _f(9, 4, "Proactive UICC: PROVIDE LOCAL INFORMATION (language)"),
    _f(9, 5, "Proactive UICC: PROVIDE LOCAL INFORMATION, Timing Advance", owner=_3GPP),
    _f(9, 6, "Proactive UICC: LANGUAGE NOTIFICATION"),
    _f(9, 7, 'Proactive UICC: LAUNCH BROWSER (i.e. class "ab" is supported)'),
    _f(9, 8, "Proactive UICC: PROVIDE LOCAL INFORMATION (Access Technology)"),
    _f(10, 1, "Soft keys support for SELECT ITEM"),
    _f(10, 2, "Soft Keys support for SET UP MENU"),
    _f(10, 3, "RFU, bit = 0", width=6, kind=RFU),
    _f(11, 1, "Maximum number of soft keys available ('FF' is reserved)", width=8, kind=COUNT),
    _f(12, 1, "Proactive UICC: OPEN CHANNEL"),
    _f(12, 2, "Proactive UICC: CLOSE CHANNEL"),
    _f(12, 3, "Proactive UICC: RECEIVE DATA"),
    _f(12, 4, "Proactive UICC: SEND DATA"),
    _f(12, 5, "Proactive UICC: GET CHANNEL STATUS"),
    _f(12, 6, "Proactive UICC: SERVICE SEARCH"),
    _f(12, 7, "Proactive UICC: GET SERVICE INFORMATION"),
    _f(12, 8, "Proactive UICC: DECLARE SERVICE"),
    _f(13, 1, "CSD"),
    _f(13, 2, "GPRS"),
    _f(13, 3, "Bluetooth"),
    _f(13, 4, "IrDA"),
    _f(13, 5, "RS232"),
    _f(13, 6, "Number of channels supported by terminal", width=3, kind=COUNT),
    _f(14, 1, "Number of characters supported down the terminal display (clause 5.3.1)",
       width=5, kind=COUNT),
    _f(14, 6, 'No display capability (i.e. class "ND" is indicated)', kind=NEGATIVE),
    _f(14, 7, 'No keypad available (i.e. class "NK" is indicated)', kind=NEGATIVE),
    _f(14, 8, "Screen Sizing Parameters supported as defined in clause 5.3"),
    _f(15, 1, "Number of characters supported across the terminal display (clause 5.3.2)",
       width=7, kind=COUNT),
    _f(15, 8, "Variable size fonts"),
    _f(16, 1, "Display can be resized as defined in clause 5.3.3"),
    _f(16, 2, "Text Wrapping supported as defined in clause 5.3.4"),
    _f(16, 3, "Text Scrolling supported as defined in clause 5.3.5"),
    _f(16, 4, "Text Attributes supported as defined in clause 5.3.7"),
    _f(16, 5, "RFU", kind=RFU),
    _f(16, 6, "Width reduction when in a menu as defined in clause 5.3.6", width=3, kind=COUNT),
    _f(17, 1, "TCP, UICC in client mode, remote connection"),
    _f(17, 2, "UDP, UICC in client mode, remote connection"),
    _f(17, 3, "TCP, UICC in server mode"),
    _f(17, 4, 'TCP, UICC in client mode, local connection (i.e. class "k" is supported)'),
    _f(17, 5, 'UDP, UICC in client mode, local connection (i.e. class "k" is supported)'),
    _f(17, 6, 'Direct communication channel (i.e. class "k" is supported)'),
    _f(17, 7, "E-UTRAN", owner=_3GPP),
    _f(17, 8, "HSDPA", owner=_3GPP),
    _f(18, 1, "Proactive UICC: DISPLAY TEXT (Variable Time out)"),
    _f(18, 2, "Proactive UICC: GET INKEY (help is supported while waiting for immediate "
              "response or variable timeout)"),
    _f(18, 3, 'USB (Bearer Independent protocol supported bearers, class "e")'),
    _f(18, 4, "Proactive UICC: GET INKEY (Variable Timeout)"),
    _f(18, 5, "Proactive UICC: PROVIDE LOCAL INFORMATION (ESN)"),
    _f(18, 6, "Call control on GPRS", owner=_3GPP),
    _f(18, 7, "Proactive UICC: PROVIDE LOCAL INFORMATION (IMEISV)"),
    _f(18, 8, "Proactive UICC: PROVIDE LOCAL INFORMATION (Search Mode change)"),
    _f(19, 1, "Protocol Version support", width=4, kind=FOREIGN, owner="TIA/EIA-136-270"),
    _f(19, 5, "RFU, bit = 0", width=4, kind=RFU),
    _f(20, 1, "Reserved by CCAT", width=8, kind=FOREIGN, owner="3GPP2 C.S0035-B"),
    _f(21, 1, "WML"),
    _f(21, 2, "XHTML"),
    _f(21, 3, "HTML"),
    _f(21, 4, "CHTML"),
    _f(21, 5, "RFU, bit = 0", width=4, kind=RFU),
    _f(22, 1, "Support of UTRAN PS with extended parameters", owner=_3GPP),
    _f(22, 2, 'Proactive UICC: PROVIDE LOCAL INFORMATION (battery state), (i.e. class "g" is '
              'supported)'),
    _f(22, 3, "Proactive UICC: PLAY TONE (Melody tones and Themed tones supported)"),
    _f(22, 4, "Multi-media Calls in SET UP CALL (if class h supported)"),
    _f(22, 5, "Toolkit-initiated GBA", owner=_3GPP),
    _f(22, 6, 'Proactive UICC: RETRIEVE MULTIMEDIA MESSAGE (if class "j" is supported)'),
    _f(22, 7, 'Proactive UICC: SUBMIT MULTIMEDIA MESSAGE (if class "j" is supported)'),
    _f(22, 8, 'Proactive UICC: DISPLAY MULTIMEDIA MESSAGE (if class "j" is supported)'),
    _f(23, 1, 'Proactive UICC: SET FRAMES (i.e. class "i" is supported)'),
    _f(23, 2, 'Proactive UICC: GET FRAMES STATUS (i.e. class "i" is supported)'),
    _f(23, 3, 'MMS notification download (if class "j" is supported)'),
    _f(23, 4, "Alpha Identifier in REFRESH command supported by terminal"),
    _f(23, 5, "Geographical Location Reporting", owner=_3GPP),
    _f(23, 6, "Proactive UICC: PROVIDE LOCAL INFORMATION (MEID)"),
    _f(23, 7, "Proactive UICC: PROVIDE LOCAL INFORMATION (NMR(UTRAN/E-UTRAN/Satellite "
              "E-UTRAN/NG-RAN/Satellite NG-RAN))", owner=_3GPP),
    _f(23, 8, "USSD Data download and application mode", owner=_3GPP_3GPP2),
    _f(24, 1, "Maximum number of frames supported (including frames created in existing "
              "frames)", width=4, kind=COUNT),
    _f(24, 5, "RFU, bit = 0", width=4, kind=RFU),
    _f(25, 1, 'Event: Browsing status (i.e. class "ac" is supported)'),
    _f(25, 2, 'Event: MMS Transfer status (if class "j" is supported)'),
    _f(25, 3, 'Event: Frame Information changed (i.e. class "i" is supported)'),
    _f(25, 4, "Event: I-WLAN Access status", owner=_3GPP),
    _f(25, 5, "Event Network Rejection", owner=_3GPP,
       usat="Event: Network Rejection for GERAN/UTRAN"),
    _f(25, 6, 'Event: HCI connectivity event (i.e. class "m" is supported)'),
    _f(25, 7, "E-UTRAN support in Event Network Rejection", owner=_3GPP,
       usat="Event: Network Rejection for E-UTRAN/Satellite E-UTRAN"),
    _f(25, 8, "Multiple access technologies supported in Event Access Technology Change "
              "and PROVIDE LOCAL INFORMATION"),
    _f(26, 1, "Event: CSG Cell Selection", owner=_3GPP),
    _f(26, 2, 'Event: Contactless state request (if class "r" is supported)'),
    _f(26, 3, "RFU, bit = 0 (for future event indication)", width=6, kind=RFU),
    _f(27, 1, "RFU, bit = 0 (for future event indication)", width=8, kind=RFU),
    _f(28, 1, "Alignment left supported by Terminal"),
    _f(28, 2, "Alignment centre supported by Terminal"),
    _f(28, 3, "Alignment right supported by Terminal"),
    _f(28, 4, "Font size normal supported by Terminal"),
    _f(28, 5, "Font size large supported by Terminal"),
    _f(28, 6, "Font size small supported by Terminal"),
    _f(28, 7, "RFU, bit = 0", width=2, kind=RFU),
    _f(29, 1, "Style normal supported by Terminal"),
    _f(29, 2, "Style bold supported by Terminal"),
    _f(29, 3, "Style italic supported by Terminal"),
    _f(29, 4, "Style underlined supported by Terminal"),
    _f(29, 5, "Style strikethrough supported by Terminal"),
    _f(29, 6, "Style text foreground colour supported by Terminal"),
    _f(29, 7, "Style text background colour supported by Terminal"),
    _f(29, 8, "RFU, bit = 0", kind=RFU),
    _f(30, 1, "I-WLAN bearer support", owner=_3GPP),
    _f(30, 2, "Proactive UICC: PROVIDE LOCAL INFORMATION (WSID of the current I-WLAN "
              "connection)", owner=_3GPP),
    _f(30, 3, 'TERMINAL APPLICATIONS (i.e. class "k" is supported)'),
    _f(30, 4, "Steering of Roaming REFRESH support", owner=_3GPP),
    _f(30, 5, "Proactive UICC: ACTIVATE"),
    _f(30, 6, "Proactive UICC: GEOGRAPHICAL LOCATION REQUEST", owner=_3GPP),
    _f(30, 7, "Proactive UICC: PROVIDE LOCAL INFORMATION (Broadcast Network Information) "
              '(i.e. class "o" is supported)'),
    _f(30, 8, "Steering of Roaming for I-WLAN REFRESH support", owner=_3GPP),
    _f(31, 1, 'Proactive UICC: Contactless State Changed (if class "r" is supported)'),
    _f(31, 2, "Support of CSG cell discovery", owner=_3GPP),
    _f(31, 3, "Confirmation parameters supported for OPEN CHANNEL in Terminal Server Mode "
              '(if classes "e" and "k" are supported)'),
    _f(31, 4, "Communication Control for IMS", owner=_3GPP),
    _f(31, 5, 'Support of CAT over the modem interface (if class "s" is supported)'),
    _f(31, 6, "Support for Incoming IMS Data event", owner=_3GPP),
    _f(31, 7, "Support for IMS Registration event", owner=_3GPP),
    _f(31, 8, "Proactive UICC: Profile Container, Envelope Container, COMMAND CONTAINER and "
              'ENCAPSULATED SESSION CONTROL (if class "u" is supported)'),
    _f(32, 1, "Support of IMS as a bearer for BIP", owner=_3GPP,
       usat='IMS support (if class "e" and "t" are supported)'),
    _f(32, 2, "Support of PROVIDE LOCAL INFORMATION, H(e)NB IP address", owner=_3GPP),
    _f(32, 3, "Support of PROVIDE LOCAL INFORMATION, H(e)NB surrounding macrocells",
       owner=_3GPP),
    _f(32, 4, "Launch parameters supported for OPEN CHANNEL in Terminal Server Mode"),
    _f(32, 5, "Direct communication channel supported for OPEN CHANNEL in Terminal Server "
              "Mode"),
    _f(32, 6, "Proactive UICC: Security for Profile Container, Envelope Container, COMMAND "
              'CONTAINER and ENCAPSULATED SESSION CONTROL (if classes "u" and "x" are '
              'supported)'),
    _f(32, 7, "CAT service list for eCAT client", kind=ECAT_ONLY),
    _f(32, 8, "Support of refresh enforcement policy"),
    _f(33, 1, "Support of DNS server address request for OPEN CHANNEL related to packet data "
              'service bearer (if classes "e" and "aa" are supported)'),
    _f(33, 2, "Support of Network Access Name reuse indication for CLOSE CHANNEL related to "
              'packet data service bearer (if classes "e" and "z" are supported)'),
    _f(33, 3, 'Event: Poll Interval Negotiation (i.e. class "ad" is supported)'),
    _f(33, 4, "ProSe usage information reporting", owner=_3GPP),
    _f(33, 5, "Proactive UICC: PROVIDE LOCAL INFORMATION (Supported Radio Access "
              "Technologies)"),
    _f(33, 6, "Event: WLAN Access status", owner=_3GPP),
    _f(33, 7, "WLAN bearer support", owner=_3GPP),
    _f(33, 8, "Proactive UICC: PROVIDE LOCAL INFORMATION (WLAN identifier of the current WLAN "
              "connection)", owner=_3GPP),
    _f(34, 1, "URI support for SEND SHORT MESSAGE", owner=_3GPP),
    _f(34, 2, "IMS URI supported for SET UP CALL", owner=_3GPP),
    _f(34, 3, 'Media Type "Voice" supported for SET UP CALL and Call Control by USIM',
       owner=_3GPP),
    _f(34, 4, 'Media Type "Video" supported for SET UP CALL and Call Control by USIM',
       owner=_3GPP),
    _f(34, 5, "Proactive UICC: PROVIDE LOCAL INFORMATION (E-UTRAN Timing Advance "
              "Information)", owner=_3GPP),
    _f(34, 6, 'REFRESH with "eUICC Profile State Change" mode'),
    _f(34, 7, "Extended Rejection Cause Code in Event: Network Rejection for E-UTRAN",
       owner=_3GPP),
    _f(34, 8, "Deprecated, bit = 0", kind=DEPRECATED),
    _f(35, 1, "Proactive UICC: GET INPUT (Variable Time out)"),
    _f(35, 2, "Data Connection Status Change Event support - PDP Connection", owner=_3GPP),
    _f(35, 3, "Data Connection Status Change Event support - PDN Connection", owner=_3GPP),
    _f(35, 4, 'REFRESH with "Application Update" mode (i.e. class "af" is supported)'),
    _f(35, 5, 'Proactive UICC: LSI COMMAND with "Proactive session request" (i.e. class "al" '
              'is supported)'),
    _f(35, 6, 'Proactive UICC: LSI COMMAND with "UICC Platform Reset" (i.e. class "am" is '
              'supported)'),
    _f(35, 7, "RFU, bit = 0", width=2, kind=RFU),
    _f(36, 1, "Data Connection Status Change Event support - PDU Connection", owner=_3GPP),
    _f(36, 2, "Event: Network Rejection for NG-RAN", owner=_3GPP),
    _f(36, 3, 'Non-IP Data Delivery support (if class "e" and class "ai" are supported)',
       owner=_3GPP),
    _f(36, 4, "Support of PROVIDE LOCAL INFORMATION, Slice(s) information", owner=_3GPP),
    _f(36, 5, 'REFRESH "Steering of Roaming" SOR-CMCI parameter support', owner=_3GPP),
    _f(36, 6, "Event: Network Rejection for Satellite NG-RAN", owner=_3GPP),
    _f(36, 7, 'Support of CAG feature (if class "ag" is supported)', owner=_3GPP),
    _f(36, 8, 'Event: Slices Status Change (if class "ah" is supported)', owner=_3GPP),
    _f(37, 1, "Support of PROVIDE LOCAL INFORMATION, Rejected Slice(s) Information",
       owner=_3GPP),
    _f(37, 2, "Support of Extended information for PLI (Location Information), Event: "
              "Location Status, Event: Network Rejection", owner=_3GPP),
    _f(37, 3, "Support of chaining of PLI/Envelope commands", owner=_3GPP),
    _f(37, 4, '5G ProSe usage information reporting (used only if class "e" is supported)',
       owner=_3GPP),
    _f(37, 5, "Reserved by 3GPP (for future usage)", width=4, kind=FUTURE, owner=_3GPP),
    _f(38, 1, "Reserved by 3GPP (for future usage)", width=8, kind=FUTURE, owner=_3GPP),
    _f(39, 1, "Proactive UICC: PROVIDE LOCAL INFORMATION (NG-RAN/Satellite NG-RAN Timing "
              "Advance Information)", owner=_3GPP),
    _f(39, 2, "Reserved by 3GPP (for future usage)", width=7, kind=FUTURE, owner=_3GPP),
)

# The last byte with a bit assigned; every later byte is "RFU, bit = 0".
LAST_DEFINED_BYTE = max(facility.byte for facility in FACILITIES)

BYTE_TITLES: dict[int, str] = {
    1: "Download",
    2: "Other",
    3: "Proactive UICC",
    4: "Proactive UICC",
    5: "Event driven information",
    6: "Event driven information extensions",
    7: 'Multiple card proactive commands, class "a"',
    8: "Proactive UICC",
    10: 'Soft keys support, class "d"',
    11: "Soft keys information",
    12: 'Bearer Independent protocol proactive commands, class "e"',
    13: 'Bearer Independent protocol supported bearers, class "e"',
    14: "Screen height",
    15: "Screen width",
    16: "Screen effects",
    17: 'Bearer independent protocol supported transport interface/bearers, class "e"',
    19: "Reserved for TIA/EIA-136-270 facilities",
    20: "Reserved for 3GPP2 C.S0035-B CCAT",
    21: 'Extended Launch Browser Capability, class "ac"',
    24: 'For class "i"',
    25: "Event driven information extensions",
    26: "Event driven information extensions",
    27: "Event driven information extensions",
    28: "Text attributes",
    29: "Text attributes",
}

# TS 31.111 V19.4.0 §5.2 NOTE: "several bits may need to be set to 1 for the
# support of the same facility"; the table names them "Bit = 1 if ... is
# supported".
_SAME_FACILITY_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("SMS-PP data download", ("1.2", "1.5")),
    ("Call Control by USIM", ("2.2", "1.7", "1.8", "2.3", "2.5", "8.8")),
)

# The kinds a maximal profile leaves clear: a coding of 0, a negative claim, and
# the bytes that belong to other systems.
_NEVER_CLAIMED = frozenset({RFU, DEPRECATED, FUTURE, FOREIGN, NEGATIVE, ECAT_ONLY})

# ETSI TS 102 221 V18.4 §11.2.1 TERMINAL PROFILE: INS '10', P1 = P2 = '00';
# CLA 'A0' is the GSM 11.11 form.
_TERMINAL_PROFILE_CLAS = (0x80, 0xA0)
_INS_TERMINAL_PROFILE = 0x10


@dataclass(frozen=True)
class Finding:
    """One remark on a decoded profile; ``severity`` is error, warning or info."""

    severity: str
    text: str
    address: str = ""


@dataclass(frozen=True)
class ProfileDecode:
    """Every facility's value in one profile, plus what is wrong or worth noting."""

    profile: bytes
    values: tuple[tuple[Facility, int], ...]
    findings: tuple[Finding, ...]

    def value(self, address: str) -> int:
        target = resolve(address)
        for facility, value in self.values:
            if facility == target:
                return value
        return 0


def maximal() -> bytes:
    """Every facility claimed, counts at their largest, every 0-coded bit clear."""
    profile = bytearray(LAST_DEFINED_BYTE)
    for facility in FACILITIES:
        if facility.kind in _NEVER_CLAIMED:
            continue
        profile[facility.byte - 1] |= facility.largest << (facility.bit - 1)
    return bytes(profile)


def parse_hex(text: str) -> bytes:
    """Bytes from hex that may carry spaces, colons, commas, line breaks and 0x prefixes."""
    compact = re.sub(r"0[xX]", "", str(text or ""))
    compact = re.sub(r"[\s:,;.\-]", "", compact)
    if len(compact) == 0:
        raise ValueError("no hex digits in the input")
    if re.fullmatch(r"[0-9A-Fa-f]*", compact) is None:
        bad = sorted({char for char in compact if char not in "0123456789abcdefABCDEF"})
        raise ValueError(f"not hex: {''.join(bad)!r}")
    if len(compact) % 2 != 0:
        raise ValueError(f"odd number of hex digits ({len(compact)})")
    return bytes.fromhex(compact)


def split_apdu(data: bytes) -> tuple[bytes, list[Finding]]:
    """The profile out of a whole TERMINAL PROFILE APDU, or *data* as it is.

    The header is taken off only when CLA, INS, P1, P2 and an Lc equal to the
    bytes that follow all fit; a header whose Lc does not fit is reported and the
    input is decoded as it is, since a profile may start with the same bytes.
    """
    looks_like_header = (
        len(data) >= 4
        and data[0] in _TERMINAL_PROFILE_CLAS
        and data[1] == _INS_TERMINAL_PROFILE
        and data[2] == 0x00
        and data[3] == 0x00
    )
    if looks_like_header is False:
        return data, []
    if len(data) >= 5 and data[4] == len(data) - 5:
        note = Finding(
            "info",
            f"TERMINAL PROFILE APDU header {data[:5].hex().upper()} taken off; "
            f"{data[4]} profile bytes follow.",
        )
        return data[5:], [note]
    if len(data) < 5:
        detail = "has no Lc"
    else:
        detail = f"carries Lc '{data[4]:02X}' ({data[4]} bytes) but {len(data) - 5} follow"
    note = Finding(
        "warning",
        f"The input starts like a TERMINAL PROFILE APDU ({data[:4].hex().upper()}) but "
        f"{detail}; decoded as a profile from its first byte.",
    )
    return data, [note]


def decode(profile: bytes) -> ProfileDecode:
    """Read every facility of *profile* and report what its coding breaks."""
    data = bytes(profile)
    values = tuple((facility, facility.value_in(data)) for facility in FACILITIES)
    findings: list[Finding] = []
    for facility, value in values:
        if value == 0:
            continue
        address = facility.address
        if facility.kind == RFU:
            findings.append(Finding(
                "error", f"RFU bits set ({value:#x}); TS 102 223 V18.3.0 §5.2 codes them 0.",
                address,
            ))
        elif facility.kind == DEPRECATED:
            findings.append(Finding("error", "Deprecated, bit = 0, but set.", address))
        elif facility.kind == FUTURE:
            findings.append(Finding(
                "warning", f"Reserved by 3GPP for future usage, set ({value:#x}).", address,
            ))
        elif facility.kind == ECAT_ONLY:
            findings.append(Finding(
                "error",
                "CAT service list for eCAT client is only applicable for an eCAT client "
                "profile; it shall not be set in TERMINAL PROFILE.",
                address,
            ))
        elif facility.kind == NEGATIVE:
            findings.append(Finding("info", f"The terminal declares: {facility.name}.", address))
        elif facility.kind == FOREIGN:
            findings.append(Finding(
                "info", f"{facility.describe()}: {value} ({value:#x}).", address,
            ))
    if len(data) >= 11 and data[10] == 0xFF:
        findings.append(Finding(
            "error", "Maximum number of soft keys 'FF': the value is reserved for future use.",
            "11.1-8",
        ))
    tail = data[LAST_DEFINED_BYTE:]
    if any(tail):
        first = LAST_DEFINED_BYTE + 1 + next(index for index, byte in enumerate(tail) if byte)
        findings.append(Finding(
            "error",
            f"Byte {first} onwards: subsequent bytes are RFU, bit = 0, and "
            f"{tail.hex().upper()} is not all zero.",
        ))
    findings.extend(_group_findings(values, len(data)))
    if _value_of(values, "33.1") == 1 and _value_of(values, "33.2") == 0:
        findings.append(Finding(
            "warning",
            "DNS server address request without Network Access Name reuse indication; "
            "TS 102 223 V18.3.0 §5.2 NOTE: a terminal that supports the first should also "
            "support the second.",
            "33.2",
        ))
    if 0 < len(data) < LAST_DEFINED_BYTE:
        findings.append(Finding(
            "info",
            f"{count_text(len(data), 'byte', 'bytes')}; bytes {len(data) + 1}-"
            f"{LAST_DEFINED_BYTE} are absent and read as 0.",
        ))
    if len(data) == 0:
        findings.append(Finding("info", "Empty profile: no facility is declared."))
    return ProfileDecode(data, values, tuple(findings))


def _value_of(values: Iterable[tuple[Facility, int]], address: str) -> int:
    for facility, value in values:
        if facility.address == address:
            return value
    return 0


def _group_findings(values: Sequence[tuple[Facility, int]], length: int) -> list[Finding]:
    """Bits of one facility set in part; a bit past the profile's end is noted, not faulted."""
    findings: list[Finding] = []
    for label, addresses in _SAME_FACILITY_GROUPS:
        reached = [address for address in addresses if int(address.split(".")[0]) <= length]
        set_bits = [address for address in reached if _value_of(values, address) == 1]
        if len(set_bits) == 0:
            continue
        clear_bits = [address for address in reached if address not in set_bits]
        absent = [address for address in addresses if address not in reached]
        if len(clear_bits) == 0 and len(absent) == 0:
            continue
        parts = [f"{', '.join(set_bits)} set"]
        if len(clear_bits) > 0:
            parts.append(f"{', '.join(clear_bits)} clear")
        if len(absent) > 0:
            parts.append(f"{', '.join(absent)} past the profile's last byte")
        findings.append(Finding(
            "warning" if len(clear_bits) > 0 else "info",
            f"{label} takes {', '.join(addresses)} together (TS 31.111 V19.4.0 §5.2 NOTE); "
            f"{', '.join(parts)}.",
            (clear_bits or absent)[0],
        ))
    return findings


_ADDRESS = re.compile(r"^\s*(\d{1,3})\.(\d)(?:\s*-\s*(\d))?\s*$")


def resolve(item: str) -> Facility:
    """The facility an address (``5.5``, ``13.6-8``) or a piece of its name names."""
    text = str(item or "").strip()
    if len(text) == 0:
        raise ValueError("empty facility")
    match = _ADDRESS.match(text)
    if match is not None:
        byte, low = int(match.group(1)), int(match.group(2))
        high = int(match.group(3)) if match.group(3) else None
        if not 1 <= low <= 8 or (high is not None and not low <= high <= 8):
            raise ValueError(f"{text}: bits run b1 to b8")
        for facility in FACILITIES:
            if facility.byte != byte or facility.bit != low:
                continue
            if high is None or facility.bit + facility.width - 1 == high:
                return facility
        for facility in FACILITIES:
            inside = facility.bit <= low <= facility.bit + facility.width - 1
            if facility.byte == byte and inside:
                raise ValueError(
                    f"{text} is part of {facility.address} ({facility.name}); address the "
                    f"whole field as {facility.address}"
                )
        if byte > LAST_DEFINED_BYTE:
            raise ValueError(f"{text}: byte {byte} is past byte {LAST_DEFINED_BYTE}, RFU")
        raise ValueError(f"{text}: no facility there")
    wanted = text.lower()
    exact = [
        facility for facility in FACILITIES
        if wanted in (facility.name.lower(), facility.usat.lower())
    ]
    if len(exact) == 1:
        return exact[0]
    found = exact or [
        facility for facility in FACILITIES
        if wanted in facility.name.lower() or wanted in facility.usat.lower()
    ]
    if len(found) == 1:
        return found[0]
    if len(found) == 0:
        raise ValueError(f"no facility matches {text!r}")
    listed = "; ".join(f"{facility.address} {facility.name}" for facility in found[:12])
    more = f" and {len(found) - 12} more" if len(found) > 12 else ""
    raise ValueError(f"{len(found)} facilities match {text!r}: {listed}{more}")


def _parse_value(text: str) -> int:
    raw = str(text).strip()
    try:
        return int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
    except ValueError as error:
        raise ValueError(f"{raw!r} is not a number") from error


def build(
    base: bytes = b"",
    *,
    set_items: Iterable[str] = (),
    clear_items: Iterable[str] = (),
    values: Iterable[tuple[str, int]] = (),
    length: Optional[int] = None,
) -> bytes:
    """*base* with facilities set, cleared and given values; grown to the bytes it needs.

    Bits the coding keeps 0 (RFU, deprecated, byte 32 b7) can be set on purpose;
    ``decode`` reports them. *length* pads the result with zero bytes and refuses
    to cut a byte that carries something.
    """
    profile = bytearray(base)

    def write(facility: Facility, value: int) -> None:
        if not 0 <= value <= (1 << facility.width) - 1:
            raise ValueError(
                f"{facility.address} ({facility.name}) holds 0-{(1 << facility.width) - 1}, "
                f"not {value}"
            )
        if facility.byte > len(profile):
            profile.extend(bytes(facility.byte - len(profile)))
        index = facility.byte - 1
        profile[index] = (profile[index] & ~facility.mask & 0xFF) | (value << (facility.bit - 1))

    for item in set_items:
        facility = resolve(item)
        if facility.width > 1:
            raise ValueError(
                f"{facility.address} ({facility.name}) is a {facility.width}-bit field; "
                f"give it a value: {facility.address}=N"
            )
        write(facility, 1)
    for item in clear_items:
        write(resolve(item), 0)
    for item, value in values:
        write(resolve(item), int(value))
    if length is not None:
        if length < 0:
            raise ValueError("length cannot be negative")
        if any(profile[length:]):
            raise ValueError(
                f"length {length} would cut bytes {length + 1}-{len(profile)}, which carry "
                "set bits"
            )
        del profile[length:]
        profile.extend(bytes(length - len(profile)))
    return bytes(profile)


def apply_edits(base: bytes, edits: Iterable[str], length: Optional[int] = None) -> bytes:
    """``build`` from edit tokens, in order: ``+ITEM`` sets, ``-ITEM`` clears, ``ITEM=VALUE`` assigns."""
    profile = bytes(base)
    for token in edits:
        text = str(token).strip()
        if len(text) == 0:
            continue
        if text.startswith("+"):
            profile = build(profile, set_items=(text[1:],))
        elif text.startswith("-"):
            profile = build(profile, clear_items=(text[1:],))
        elif "=" in text:
            item, _, value = text.rpartition("=")
            profile = build(profile, values=((item, _parse_value(value)),))
        else:
            profile = build(profile, set_items=(text,))
    return build(profile, length=length)


def diff(first: bytes, second: bytes) -> list[tuple[Facility, int, int]]:
    """The facilities whose value differs between two profiles."""
    changed = []
    for facility in FACILITIES:
        left, right = facility.value_in(first), facility.value_in(second)
        if left != right:
            changed.append((facility, left, right))
    return changed


def terminal_profile_apdu(profile: bytes, cla: int = 0x80) -> bytes:
    """TERMINAL PROFILE carrying *profile*, ETSI TS 102 221 V18.4 §11.2.1."""
    if len(profile) > 0xFF:
        raise ValueError(f"a {len(profile)}-byte profile does not fit a short Lc")
    return bytes([cla & 0xFF, _INS_TERMINAL_PROFILE, 0x00, 0x00, len(profile)]) + bytes(profile)


# --- text rendering, shared by the command line and the stand-alone script ---


def _mark(facility: Facility, value: int) -> str:
    if facility.width == 1:
        return "[x]" if value else "[ ]"
    return f"={value}"


def render_decode(result: ProfileDecode, *, set_only: bool = False) -> list[str]:
    """The decode as text: one header line per byte, one line per bit or field."""
    data = result.profile
    lines = [f"TERMINAL PROFILE, {count_text(len(data), 'byte', 'bytes')} ({SPEC})"]
    if len(data) > 0:
        lines.append(f"  {data.hex().upper()}")
    by_byte: dict[int, list[tuple[Facility, int]]] = {}
    for facility, value in result.values:
        by_byte.setdefault(facility.byte, []).append((facility, value))
    for byte in sorted(by_byte):
        entries = by_byte[byte]
        if set_only and all(value == 0 for _, value in entries):
            continue
        raw = f"{data[byte - 1]:02X}" if byte <= len(data) else "--"
        title = BYTE_TITLES.get(byte, "")
        lines.append(f"{byte:>3}  {raw}  {title}".rstrip())
        for facility, value in entries:
            if set_only and value == 0:
                continue
            lines.append(f"     {facility.address:<8} {_mark(facility, value):<4} {facility.describe()}")
            if len(facility.usat) > 0:
                lines.append(f"     {'':<8} {'':<4}   TS 31.111: {facility.usat}")
    if len(data) > LAST_DEFINED_BYTE:
        lines.append(f"{LAST_DEFINED_BYTE + 1:>3}+ {data[LAST_DEFINED_BYTE:].hex().upper()}  RFU")
    if len(result.findings) > 0:
        lines.append("Findings")
        for finding in result.findings:
            where = f"{finding.address} " if finding.address else ""
            lines.append(f"  {finding.severity:<8}{where}{finding.text}")
    return lines


def count_text(count: int, singular: str, plural: str) -> str:
    """``1 byte`` / ``2 bytes``."""
    return f"{count} {singular if count == 1 else plural}"


def render_diff(first: bytes, second: bytes) -> list[str]:
    changed = diff(first, second)
    lines = [
        f"A {count_text(len(first), 'byte', 'bytes')}, B {count_text(len(second), 'byte', 'bytes')}: "
        f"{count_text(len(changed), 'facility differs', 'facilities differ')}"
    ]
    for facility, left, right in changed:
        lines.append(f"  {facility.address:<8} A {left:<4} B {right:<4} {facility.describe()}")
    tail_a, tail_b = first[LAST_DEFINED_BYTE:], second[LAST_DEFINED_BYTE:]
    if tail_a != tail_b:
        lines.append(f"  past byte {LAST_DEFINED_BYTE}: A {tail_a.hex().upper() or '-'}, "
                     f"B {tail_b.hex().upper() or '-'}")
    return lines


def render_table(text: str = "") -> list[str]:
    wanted = str(text or "").lower()
    lines = []
    for facility in FACILITIES:
        haystack = f"{facility.address} {facility.name} {facility.usat} {facility.owner}".lower()
        if wanted and wanted not in haystack:
            continue
        kind = "" if facility.kind == FACILITY else f" [{facility.kind}]"
        lines.append(f"{facility.address:<8} {facility.describe()}{kind}")
        if len(facility.usat) > 0:
            lines.append(f"{'':<8}   TS 31.111: {facility.usat}")
    return lines


USAGE = f"""\
TERMINAL PROFILE decoder and builder ({SPEC})

  terminal_profile.py HEX...                decode a profile or a whole TERMINAL PROFILE APDU
  terminal_profile.py decode [-s] HEX...    the same; -s lists only what is set
  terminal_profile.py diff HEX_A HEX_B      the facilities whose value differs
  terminal_profile.py build [--max | --from HEX] [--length N] [-q] EDIT...
  terminal_profile.py list [TEXT]           the facility table, filtered by TEXT

EDIT is +ITEM (set), -ITEM (clear) or ITEM=VALUE (a count field, or 0/1 for a bit).
ITEM is BYTE.BIT as the specification counts them (5.5 = byte 5 b5; a field by its
range, 13.6-8) or a piece of a facility name ('+Event: Location status'). HEX may
carry spaces, colons and 0x; without HEX the input is read from stdin. build -q
prints the profile hex alone.

  terminal_profile.py 8010000003 FFFFFF
  terminal_profile.py build --max -33.1 --length 33
  terminal_profile.py build +3.1 +5.1 +5.5 +12.1 13.6-8=1
  terminal_profile.py diff "$MODEM_TP" "$OUR_TP"
"""


def _read_hex(arguments: Sequence[str]) -> bytes:
    if len(arguments) > 0:
        return parse_hex(" ".join(arguments))
    if sys.stdin is None or sys.stdin.isatty():
        raise ValueError("no profile given")
    return parse_hex(sys.stdin.read())


def _profile_from(arguments: Sequence[str]) -> tuple[bytes, list[Finding]]:
    return split_apdu(_read_hex(arguments))


def _print_decode(arguments: Sequence[str], set_only: bool) -> int:
    profile, notes = _profile_from(arguments)
    result = decode(profile)
    result = ProfileDecode(result.profile, result.values, tuple(notes) + result.findings)
    print("\n".join(render_decode(result, set_only=set_only)))
    return 3 if any(finding.severity == "error" for finding in result.findings) else 0


def _run_build(arguments: Sequence[str]) -> int:
    base = b""
    length: Optional[int] = None
    quiet = False
    edits: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--max":
            base = maximal()
        elif token == "--from":
            index += 1
            if index >= len(arguments):
                raise ValueError("--from needs a profile")
            base, _ = split_apdu(parse_hex(arguments[index]))
        elif token == "--length":
            index += 1
            if index >= len(arguments):
                raise ValueError("--length needs a number")
            length = _parse_value(arguments[index])
        elif token in ("-q", "--quiet"):
            quiet = True
        else:
            edits.append(token)
        index += 1
    profile = apply_edits(base, edits, length)
    if quiet:
        print(profile.hex().upper())
        return 0
    print(f"profile {profile.hex().upper()}")
    print(f"APDU    {terminal_profile_apdu(profile).hex().upper()}")
    print("\n".join(render_decode(decode(profile), set_only=True)))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) == 0 and (sys.stdin is None or sys.stdin.isatty()):
        print(USAGE, file=sys.stderr)
        return 2
    command = arguments[0].lower() if arguments else ""
    try:
        if command in ("-h", "--help", "help"):
            print(USAGE)
            return 0
        if command == "list":
            print("\n".join(render_table(" ".join(arguments[1:]))))
            return 0
        if command == "diff":
            if len(arguments) != 3:
                raise ValueError("diff takes two profiles; quote a profile with spaces")
            first, _ = split_apdu(parse_hex(arguments[1]))
            second, _ = split_apdu(parse_hex(arguments[2]))
            print("\n".join(render_diff(first, second)))
            return 0
        if command == "build":
            return _run_build(arguments[1:])
        if command == "decode":
            rest = arguments[1:]
            set_only = any(token in ("-s", "--set") for token in rest)
            rest = [token for token in rest if token not in ("-s", "--set")]
            return _print_decode(rest, set_only)
        set_only = any(token in ("-s", "--set") for token in arguments)
        rest = [token for token in arguments if token not in ("-s", "--set")]
        return _print_decode(rest, set_only)
    except ValueError as error:
        print(f"terminal_profile: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
