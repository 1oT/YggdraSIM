# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Terminal side of the SIM toolkit bring-up, shared by every shell that sends one.

One TERMINAL PROFILE for the whole toolchain: every facility ETSI TS 102 223
V18.3.0 §5.2 (pp. 27-35) and 3GPP TS 31.111 V19.4.0 §5.2 (bytes 36-39, p. 28)
define is claimed, so no card withholds a service -- or switches a card-resident
application off because a facility it needs, such as PROVIDE LOCAL INFORMATION
(location), was not declared -- for want of a declared capability. What stays clear:
the bits the clause codes "RFU, bit = 0" and "Deprecated, bit = 0", byte 32 b7
(CAT service list for eCAT client: "It shall not be set in the command defined
in this clause"), the two negative bits of byte 14 (no display, no keypad,
which would contradict DISPLAY TEXT and GET INKEY), and bytes 19-20, which
belong to TIA/EIA-136-270 and 3GPP2 C.S0035-B CCAT rather than to a 3GPP
terminal. Count fields carry their largest legal value.

TERMINAL CAPABILITY is deliberately not here: its tags '83' and '84' select the
device-side LPA and IPA, and each shell keeps the declaration its role needs.
"""
from __future__ import annotations

from typing import Callable

MAXIMAL_TERMINAL_PROFILE = bytes.fromhex(
    "FF"  # 1: download (profile download, SMS-PP, CB, menu selection, timer expiration, CC)
    "FF"  # 2: other (command result, call control, MO SM control, UCS2, display text)
    "FF"  # 3: DISPLAY TEXT .. REFRESH
    "FF"  # 4: SELECT ITEM .. PLI (MCC, MNC, LAC, Cell ID & IMEI), PLI (NMR)
    "FF"  # 5: SET UP EVENT LIST, MT call .. Location status .. Card reader status
    "FF"  # 6: Language selection .. Data available, Channel status .. Network Search Mode
    "1F"  # 7: multiple card commands b1-b5; b6-b8 RFU
    "FF"  # 8: TIMER MANAGEMENT, PLI (date, time and time zone) .. Call Control by NAA
    "FF"  # 9: DISPLAY TEXT, SEND DTMF, PLI (NMR, language, TA, access technology) ..
    "03"  # 10: soft keys for SELECT ITEM and SET UP MENU; b3-b8 RFU
    "FE"  # 11: maximum number of soft keys; 'FF' is reserved
    "FF"  # 12: OPEN / CLOSE CHANNEL, RECEIVE / SEND DATA .. DECLARE SERVICE
    "FF"  # 13: CSD, GPRS, Bluetooth, IrDA, RS232; b6-b8 channels (7)
    "9F"  # 14: 31 characters down, b8 screen sizing; b6 no display and b7 no keypad clear
    "FF"  # 15: 127 characters across, b8 variable size fonts
    "EF"  # 16: resize, wrap, scroll, attributes; b5 RFU; b6-b8 width reduction (7)
    "FF"  # 17: TCP/UDP client remote and local, TCP server, direct, E-UTRAN, HSDPA
    "FF"  # 18: variable timeouts, USB, PLI (ESN, IMEISV, search mode change) ..
    "00"  # 19: TIA/EIA-136-270 protocol version; b5-b8 RFU
    "00"  # 20: 3GPP2 C.S0035-B CCAT
    "0F"  # 21: WML, XHTML, HTML, CHTML; b5-b8 RFU
    "FF"  # 22: PLI (battery state) .. DISPLAY MULTIMEDIA MESSAGE
    "FF"  # 23: SET FRAMES .. PLI (MEID), PLI (NMR UTRAN/E-UTRAN/NG-RAN) ..
    "0F"  # 24: maximum number of frames (15); b5-b8 RFU
    "FF"  # 25: Browsing status .. Network Rejection .. multiple access technologies
    "03"  # 26: CSG cell selection, contactless state request; b3-b8 RFU
    "00"  # 27: RFU
    "3F"  # 28: alignment and font size; b7-b8 RFU
    "7F"  # 29: text styles and colours; b8 RFU
    "FF"  # 30: I-WLAN .. ACTIVATE .. PLI (Broadcast Network Information) ..
    "FF"  # 31: Contactless State Changed .. CAT over the modem interface ..
    "BF"  # 32: b7 CAT service list for eCAT client forbidden in this command
    "FF"  # 33: DNS server address request, NAN reuse .. PLI (supported RATs) ..
    "7F"  # 34: .. REFRESH "eUICC Profile State Change"; b8 deprecated
    "3F"  # 35: GET INPUT variable timeout .. LSI COMMAND; b7-b8 RFU
    "FF"  # 36: PDU connection .. Network Rejection NG-RAN .. Slices Status Change
    "0F"  # 37: rejected slices, extended PLI, chaining, 5G ProSe; b5-b8 unassigned
    "00"  # 38: unassigned (TS 31.111 V19.4.0: for future usage)
    "01"  # 39: PLI (NG-RAN timing advance); b2-b8 unassigned
)

# ETSI TS 102 221 V18.4 §11.2.1 TERMINAL PROFILE: INS '10', P1 = P2 = '00'.
_INS_TERMINAL_PROFILE = 0x10
_INS_FETCH = 0x12
_INS_TERMINAL_RESPONSE = 0x14


def terminal_profile_apdu(cla: int = 0x80) -> bytes:
    """TERMINAL PROFILE carrying ``MAXIMAL_TERMINAL_PROFILE``."""
    return (
        bytes([int(cla) & 0xFF, _INS_TERMINAL_PROFILE, 0x00, 0x00, len(MAXIMAL_TERMINAL_PROFILE)])
        + MAXIMAL_TERMINAL_PROFILE
    )


def generic_terminal_response_apdu(fetch_data: bytes, cla: int = 0x80) -> bytes:
    """TERMINAL RESPONSE acknowledging any proactive command as performed.

    TS 102 223 §6.8: the Command details object is echoed, Device identities
    goes from the terminal ('82') to the UICC ('81') under the tag the card
    used for its own (so its comprehension-required convention is kept), and
    the Result is '00' (command performed successfully). A command that cannot
    be parsed still gets a well-formed response, so the proactive cycle never
    stalls on it.
    """
    command_details = bytes.fromhex("8103010000")
    device_identities_tag = 0x82
    data = bytes(fetch_data or b"")
    offset = 0
    if len(data) > 1 and data[0] == 0xD0:
        offset = 2 + (data[1] & 0x7F) if data[1] & 0x80 else 2
    position = offset
    while position + 1 < len(data):
        tag = data[position]
        length = data[position + 1]
        if tag in (0x01, 0x81) and length == 3 and position + 5 <= len(data):
            command_details = data[position:position + 5]
        elif tag in (0x02, 0x82) and length == 2:
            device_identities_tag = tag
        position += 2 + length
    body = (
        command_details
        + bytes([device_identities_tag, 0x02, 0x82, 0x81])
        + bytes.fromhex("830100")
    )
    return bytes([int(cla) & 0xFF, _INS_TERMINAL_RESPONSE, 0x00, 0x00, len(body)]) + body


def drain_proactive_commands(
    exchange: Callable[[bytes, str], tuple[bytes, int, int]],
    sw1: int,
    sw2: int,
    log_name: str,
    *,
    limit: int = 8,
    cla: int = 0x80,
) -> tuple[int, int, int]:
    """FETCH and acknowledge the proactive commands a status word announces.

    A card answering '91 xx' holds a proactive command of xx bytes, and until
    the terminal fetches and answers it the proactive cycle stays open -- an
    eUICC then refuses ES10 STORE DATA with '69 85'. Each command is fetched
    and acknowledged with ``generic_terminal_response_apdu``; the loop stops at
    ``limit`` commands or on a FETCH that fails. Returns the last status word
    and the number of commands answered.
    """
    answered = 0
    while sw1 == 0x91 and sw2 > 0 and answered < limit:
        fetch_data, fetch_sw1, fetch_sw2 = exchange(
            bytes([int(cla) & 0xFF, _INS_FETCH, 0x00, 0x00, sw2]),
            f"{log_name} [FETCH proactive #{answered + 1}]",
        )
        if fetch_sw1 != 0x90 or fetch_sw2 != 0x00:
            return fetch_sw1, fetch_sw2, answered
        _, sw1, sw2 = exchange(
            generic_terminal_response_apdu(fetch_data, cla),
            f"{log_name} [TERMINAL RESPONSE proactive #{answered + 1}]",
        )
        answered += 1
    return sw1, sw2, answered
