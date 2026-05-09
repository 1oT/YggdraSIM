# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""3GPP TS 27.007 §8.17 / §8.18 AT+CSIM and AT+CRSM transcoding.

This module turns ``AT+CSIM=...`` request lines into raw ISO 7816
APDUs (and back) and turns ``AT+CRSM=...`` requests into the
equivalent CLA INS P1 P2 P3 [data] APDU. It is deliberately
transport-agnostic: callers feed in lines from whatever pipe they
have (a serial port emulation, a TCP loop-back, a CLI shell), pass
the resulting APDU bytes through the simulator, and stringify the
response back into AT-format.

Accepted request shapes:

- ``AT+CSIM=<length>,"<hex>"``
- ``AT+CSIM=<length>,<hex>`` (some firmware omits the quotes)
- ``AT+CRSM=<command>,<fileid>,<P1>,<P2>,<P3>``
- ``AT+CRSM=<command>,<fileid>,<P1>,<P2>,<P3>,"<data hex>"``
- ``AT+CRSM=<command>,<fileid>,<P1>,<P2>,<P3>,<data hex>``
- ``AT+CRSM=<command>,<fileid>,<P1>,<P2>,<P3>,"<data hex>","<pathid hex>"``

Response shapes:

- ``+CSIM: <length>,"<hex>"``
- ``+CRSM: <sw1>,<sw2>``  (when there is no response payload)
- ``+CRSM: <sw1>,<sw2>,"<hex>"``

The transcoder returns ``OK`` / ``ERROR`` responses as separate bytes
that the caller appends after the ``+CSIM:`` / ``+CRSM:`` line, just
like a real modem. ``CRSM_COMMAND_INS`` enumerates the commands TS
27.007 §8.18 actually defines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


CRSM_COMMAND_INS = {
    176: 0xB0,  # READ BINARY
    178: 0xB2,  # READ RECORD
    192: 0xC0,  # GET RESPONSE
    214: 0xD6,  # UPDATE BINARY
    220: 0xDC,  # UPDATE RECORD
    242: 0xF2,  # STATUS
}


@dataclass(frozen=True)
class CsimRequest:
    """Decoded ``AT+CSIM=<length>,"<hex>"``."""

    length_chars: int
    apdu: bytes


@dataclass(frozen=True)
class CrsmRequest:
    """Decoded ``AT+CRSM=...``.

    ``select_path`` carries the optional last-parameter path-id when
    present, so the caller can issue MF/DF SELECTs ahead of the
    READ/UPDATE.
    """

    command: int
    file_id: int
    p1: int
    p2: int
    p3: int
    data: bytes
    select_path: bytes


_AT_CSIM_PATTERN = re.compile(
    r"""^\s*AT\+CSIM\s*=\s*           # command and equals
        (?P<length>\d+)\s*,\s*       # decimal length-of-hex-chars
        "?(?P<hex>[0-9A-Fa-f]+)"?    # hex APDU (quotes optional)
        \s*$""",
    re.VERBOSE,
)


_AT_CRSM_PATTERN = re.compile(
    r"""^\s*AT\+CRSM\s*=\s*
        (?P<command>\d+)\s*,\s*
        (?P<fileid>\d+)\s*,\s*
        (?P<p1>\d+)\s*,\s*
        (?P<p2>\d+)\s*,\s*
        (?P<p3>\d+)
        (?:\s*,\s*"?(?P<data>[0-9A-Fa-f]*)"?)?
        (?:\s*,\s*"?(?P<path>[0-9A-Fa-f]*)"?)?
        \s*$""",
    re.VERBOSE,
)


def parse_at_csim_request(line: str) -> Optional[CsimRequest]:
    """Decode a single ``AT+CSIM=...`` line.

    Returns ``None`` if the line does not match the expected shape;
    the caller should answer the modem with ``ERROR`` in that case.
    """
    match = _AT_CSIM_PATTERN.match(str(line or ""))
    if match is None:
        return None
    declared_length = int(match.group("length"))
    hex_string = match.group("hex").upper()
    if declared_length != len(hex_string):
        return None
    if len(hex_string) % 2 != 0:
        return None
    try:
        apdu = bytes.fromhex(hex_string)
    except ValueError:
        return None
    if len(apdu) < 4:
        return None
    return CsimRequest(length_chars=declared_length, apdu=apdu)


def format_at_csim_response(data: bytes, sw1: int, sw2: int) -> str:
    """Build the ``+CSIM: <length>,"<hex>"`` answer.

    ``<hex>`` is response-data || sw1 || sw2 (per §8.17), and
    ``<length>`` is its hex-character count.
    """
    payload = bytes(data or b"") + bytes((int(sw1) & 0xFF, int(sw2) & 0xFF))
    hex_string = payload.hex().upper()
    return f'+CSIM: {len(hex_string)},"{hex_string}"'


def parse_at_crsm_request(line: str) -> Optional[CrsmRequest]:
    """Decode a single ``AT+CRSM=...`` line."""
    match = _AT_CRSM_PATTERN.match(str(line or ""))
    if match is None:
        return None
    command = int(match.group("command"))
    if command not in CRSM_COMMAND_INS:
        return None
    raw_data = match.group("data") or ""
    raw_path = match.group("path") or ""
    if len(raw_data) % 2 != 0 or len(raw_path) % 2 != 0:
        return None
    try:
        data = bytes.fromhex(raw_data) if len(raw_data) > 0 else b""
        select_path = bytes.fromhex(raw_path) if len(raw_path) > 0 else b""
    except ValueError:
        return None
    return CrsmRequest(
        command=command,
        file_id=int(match.group("fileid")),
        p1=int(match.group("p1")),
        p2=int(match.group("p2")),
        p3=int(match.group("p3")),
        data=data,
        select_path=select_path,
    )


def build_apdu_for_crsm(request: CrsmRequest) -> bytes:
    """Translate a ``CrsmRequest`` into an ISO 7816 short APDU.

    READ BINARY / READ RECORD / GET RESPONSE / STATUS are Case 2
    (no command data, ``Le=P3``); UPDATE BINARY / UPDATE RECORD are
    Case 3 (``Lc=P3`` followed by data). 7816 SELECT-by-FID happens
    separately when ``select_path`` is non-empty.
    """
    ins = CRSM_COMMAND_INS[int(request.command)]
    cla = 0x00
    p1 = int(request.p1) & 0xFF
    p2 = int(request.p2) & 0xFF
    if ins in (0xD6, 0xDC):
        body = bytes(request.data or b"")
        if len(body) == 0:
            return bytes((cla, ins, p1, p2, int(request.p3) & 0xFF))
        return bytes((cla, ins, p1, p2, len(body) & 0xFF)) + body
    return bytes((cla, ins, p1, p2, int(request.p3) & 0xFF))


def build_select_apdu_for_crsm(request: CrsmRequest) -> bytes:
    """Build a ``00 A4 00 04 02 <fileid>`` SELECT for AT+CRSM.

    TS 27.007 §8.18 says the modem MAY supply the file id and the
    UICC will SELECT it before issuing the inner command. We expose a
    helper for that case so the bridge can keep the two APDUs
    explicit.
    """
    fid = int(request.file_id) & 0xFFFF
    return bytes((0x00, 0xA4, 0x00, 0x04, 0x02)) + fid.to_bytes(2, "big", signed=False)


def format_at_crsm_response(data: bytes, sw1: int, sw2: int) -> str:
    """Build the ``+CRSM: <sw1>,<sw2>[,"<hex>"]`` answer."""
    payload = bytes(data or b"")
    if len(payload) == 0:
        return f"+CRSM: {int(sw1) & 0xFF},{int(sw2) & 0xFF}"
    return f'+CRSM: {int(sw1) & 0xFF},{int(sw2) & 0xFF},"{payload.hex().upper()}"'
