# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""AT-line decoder overlay for the GUI ``Advanced > Host shell`` tab.

This module sits next to :mod:`yggdrasim_common.gui_server.host_shell`
and is consumed by ``routes/host_shell.py``. The route reads bytes from
the PTY, forwards them to the xterm-side WebSocket as raw frames, and —
when the operator has flipped the *Decode AT lines* toggle — also tee's
a copy through :class:`LineAccumulator`. Each terminated line that
matches an AT-shape known to :mod:`Tools.HilBridge.at_simlink` produces
one ``{"event": "at_decoded", ...}`` JSON frame on the same socket.

Design notes
------------

* The decoder never blocks on the PTY thread. It buffers bytes in a
  bounded :class:`bytearray`, splits on ``\\r`` / ``\\n`` boundaries,
  strips ANSI control sequences, and dispatches each completed line
  through :func:`decode_line`. Lines that don't match an AT shape are
  silently dropped — they already exist verbatim in the xterm output,
  so re-emitting them as JSON would just be noise.
* The dispatch is deliberately additive and tolerant: a malformed
  ``+CSIM:`` line falls through and emits no decoded entry, so partial
  output from a flaky modem cannot crash the bridge.
* The decoder is engine-aware: it pulls the human-readable SW1/SW2
  meaning from :class:`SCP03.core.utils.StatusWordTranslator` and the
  CRSM-command name from :data:`Tools.HilBridge.at_simlink.CRSM_COMMAND_INS`,
  so the side panel doesn't need its own dictionaries.

The wire-level shape of the ``at_decoded`` frame, the recognised AT
shapes, buffer caps, and the SPA-side rendering rules are documented
in :file:`guides/GUI_HOST_SHELL_GUIDE.md` §3.3 and §2.3.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator, Optional


_DEFAULT_BUFFER_LIMIT = 16 * 1024
_DEFAULT_LINE_MAX = 4 * 1024


# ANSI / VT100 control-sequence stripper. Covers the common shapes we
# see in modem dialogues: CSI (\x1b[...) and the rare OSC (\x1b]...).
_ANSI_RE = re.compile(
    rb"\x1b(?:\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    rb"|\][^\x07\x1b]*(?:\x07|\x1b\\)"
    rb"|[@-Z\\-_])"
)


# Forward AT-shape recognisers — the request half is delegated to
# at_simlink which already lives in the repo. The response half is
# parsed inline because at_simlink only formats outgoing responses.
_PLUS_CSIM_RESPONSE_RE = re.compile(
    r"""^\s*\+CSIM:\s*
        (?P<length>\d+)\s*,\s*
        "?(?P<hex>[0-9A-Fa-f]+)"?\s*$""",
    re.VERBOSE,
)


_PLUS_CRSM_RESPONSE_RE = re.compile(
    r"""^\s*\+CRSM:\s*
        (?P<sw1>\d+)\s*,\s*
        (?P<sw2>\d+)
        (?:\s*,\s*"?(?P<hex>[0-9A-Fa-f]*)"?)?
        \s*$""",
    re.VERBOSE,
)


# CRSM command-id → friendly name. Mirrors at_simlink.CRSM_COMMAND_INS
# but adds the human-readable label so the side panel doesn't need to
# look up the INS twice.
_CRSM_COMMAND_LABELS = {
    176: "READ BINARY",
    178: "READ RECORD",
    192: "GET RESPONSE",
    214: "UPDATE BINARY",
    220: "UPDATE RECORD",
    242: "STATUS",
}


# ISO 7816-4 INS labels used when expanding a raw AT+CSIM APDU header.
# Kept tight on purpose — a full table lives elsewhere; this is just
# the set commonly issued through AT+CSIM in practice.
_INS_LABELS = {
    0xA4: "SELECT",
    0xB0: "READ BINARY",
    0xB2: "READ RECORD",
    0xC0: "GET RESPONSE",
    0xC2: "ENVELOPE",
    0xCA: "GET DATA",
    0xCB: "GET DATA (ODD)",
    0xD6: "UPDATE BINARY",
    0xDA: "PUT DATA",
    0xDC: "UPDATE RECORD",
    0xE2: "APPEND RECORD",
    0xE4: "DELETE FILE",
    0xE6: "TERMINATE DF",
    0xF2: "STATUS",
    0x88: "INTERNAL AUTHENTICATE",
    0x20: "VERIFY",
    0x24: "CHANGE REFERENCE DATA",
    0x2C: "RESET RETRY COUNTER",
    0x84: "GET CHALLENGE",
    0x10: "TERMINAL PROFILE",
    0x12: "FETCH",
    0x14: "TERMINAL RESPONSE",
}


# ---------------------------------------------------------------------------
# Line accumulator
# ---------------------------------------------------------------------------


class LineAccumulator:
    """Byte-stream → terminated-line splitter with bounded memory.

    The accumulator keeps a rolling :class:`bytearray` and emits
    decoded ``str`` lines as the stream crosses CR / LF boundaries.
    Maximum buffer size is :data:`_DEFAULT_BUFFER_LIMIT` so a runaway
    binary stream cannot OOM the GUI process; once exceeded the buffer
    is dropped and a single warning entry is yielded so the side panel
    can hint at it. Likewise, a single line longer than
    :data:`_DEFAULT_LINE_MAX` is split at the boundary to keep one
    request from hogging the channel.

    The instance is single-threaded — the route serialises calls in
    the asyncio loop. Wrap externally if needed.
    """

    def __init__(
        self,
        *,
        buffer_limit: int = _DEFAULT_BUFFER_LIMIT,
        line_max: int = _DEFAULT_LINE_MAX,
    ) -> None:
        self._buffer = bytearray()
        self._buffer_limit = int(buffer_limit)
        self._line_max = int(line_max)
        self._dropped_overflow = 0

    @property
    def dropped_overflow_count(self) -> int:
        return self._dropped_overflow

    def feed(self, chunk: bytes) -> Iterator[str]:
        """Append *chunk* and yield each terminated line as :class:`str`.

        Lines are split on ``\\n``; trailing ``\\r`` is stripped. ANSI
        escapes are removed before yielding. Empty lines are skipped
        (they're noise in modem dialogues; the xterm side keeps the
        original byte stream intact).
        """
        if len(chunk) == 0:
            return
        if len(self._buffer) + len(chunk) > self._buffer_limit:
            # Buffer overflow — drop everything we've accumulated and
            # this fragment too. The decoder is best-effort; the user
            # still sees the raw bytes in xterm.
            self._buffer.clear()
            self._dropped_overflow += 1
            return

        self._buffer.extend(chunk)

        while True:
            newline_index = self._buffer.find(b"\n")
            if newline_index < 0:
                # Long line guard: even without a newline, if the buffer
                # has grown past _line_max we need to flush it so we
                # don't sit on it forever.
                if len(self._buffer) > self._line_max:
                    raw_line = bytes(self._buffer)
                    self._buffer.clear()
                    text = self._normalise_line(raw_line)
                    if len(text) > 0:
                        yield text
                return

            raw_line = bytes(self._buffer[:newline_index])
            del self._buffer[: newline_index + 1]
            text = self._normalise_line(raw_line)
            if len(text) > 0:
                yield text

    @staticmethod
    def _normalise_line(raw: bytes) -> str:
        """Strip ANSI, trim CR, decode UTF-8 (replace), drop blanks."""
        no_ansi = _ANSI_RE.sub(b"", raw)
        if no_ansi.endswith(b"\r"):
            no_ansi = no_ansi[:-1]
        text = no_ansi.decode("utf-8", errors="replace").strip("\r\n\t ")
        return text


# ---------------------------------------------------------------------------
# Decoders — each returns either a JSON-serialisable dict or ``None``.
# ---------------------------------------------------------------------------


def decode_line(line: str, direction: str) -> Optional[dict]:
    """Try every known AT-shape; return the first decoded payload.

    *direction* is ``"tx"`` for bytes the operator typed (modem-bound)
    and ``"rx"`` for bytes the modem replied with. The directionality
    is informational — every decoder runs regardless — but the side
    panel uses it to pick the > / < glyph and colour.
    """
    request = _decode_csim_request(line)
    if request is not None:
        return _wrap(line, direction, request)

    request = _decode_crsm_request(line)
    if request is not None:
        return _wrap(line, direction, request)

    response = _decode_csim_response(line)
    if response is not None:
        return _wrap(line, direction, response)

    response = _decode_crsm_response(line)
    if response is not None:
        return _wrap(line, direction, response)

    return None


def _wrap(line: str, direction: str, decoded: dict) -> dict:
    return {
        "event": "at_decoded",
        "direction": str(direction or "?")[:4],
        "raw": str(line),
        "kind": str(decoded.pop("__kind__")),
        "decoded": decoded,
    }


# ---------------------------------------------------------------------------
# Per-shape decoders
# ---------------------------------------------------------------------------


def _decode_csim_request(line: str) -> Optional[dict]:
    from Tools.HilBridge.at_simlink import parse_at_csim_request

    parsed = parse_at_csim_request(line)
    if parsed is None:
        return None
    return _expand_csim_request_payload(parsed.length_chars, parsed.apdu)


def _expand_csim_request_payload(length_chars: int, apdu: bytes) -> dict:
    """Expand a parsed ``AT+CSIM=...`` request into a UI-friendly dict."""
    return {
        "__kind__": "csim_request",
        "length_chars": int(length_chars),
        "apdu_hex": apdu.hex().upper(),
        **_describe_apdu_header(apdu),
    }


def _describe_apdu_header(apdu: bytes) -> dict:
    """Pull CLA / INS / P1 / P2 / Lc / data out of a short-form APDU."""
    if len(apdu) < 4:
        return {"warning": "APDU shorter than 4 bytes"}
    cla = apdu[0]
    ins = apdu[1]
    p1 = apdu[2]
    p2 = apdu[3]
    label = _INS_LABELS.get(ins, "")
    detail: dict[str, object] = {
        "cla_hex": f"{cla:02X}",
        "ins_hex": f"{ins:02X}",
        "ins_label": label,
        "p1_hex": f"{p1:02X}",
        "p2_hex": f"{p2:02X}",
    }
    if len(apdu) == 4:
        detail["case"] = "Case 1"
        detail["data_hex"] = ""
        detail["lc"] = 0
        return detail
    if len(apdu) == 5:
        # Case 2: trailing byte is Le.
        detail["case"] = "Case 2"
        detail["le"] = int(apdu[4])
        detail["data_hex"] = ""
        detail["lc"] = 0
        return detail
    lc = apdu[4]
    body = apdu[5:5 + lc]
    detail["case"] = "Case 3" if 5 + lc == len(apdu) else "Case 4"
    detail["lc"] = int(lc)
    detail["data_hex"] = body.hex().upper()
    if 5 + lc < len(apdu):
        detail["le"] = int(apdu[5 + lc])
    return detail


def _decode_crsm_request(line: str) -> Optional[dict]:
    from Tools.HilBridge.at_simlink import parse_at_crsm_request

    parsed = parse_at_crsm_request(line)
    if parsed is None:
        return None
    label = _CRSM_COMMAND_LABELS.get(int(parsed.command), "")
    return {
        "__kind__": "crsm_request",
        "command_id": int(parsed.command),
        "command_label": label,
        "file_id_hex": f"{int(parsed.file_id) & 0xFFFF:04X}",
        "p1_hex": f"{int(parsed.p1) & 0xFF:02X}",
        "p2_hex": f"{int(parsed.p2) & 0xFF:02X}",
        "p3": int(parsed.p3),
        "data_hex": parsed.data.hex().upper(),
        "select_path_hex": parsed.select_path.hex().upper(),
    }


def _decode_csim_response(line: str) -> Optional[dict]:
    match = _PLUS_CSIM_RESPONSE_RE.match(line)
    if match is None:
        return None
    declared = int(match.group("length"))
    hex_string = match.group("hex").upper()
    if declared != len(hex_string):
        return None
    if len(hex_string) % 2 != 0:
        return None
    if len(hex_string) < 4:
        return None
    try:
        payload = bytes.fromhex(hex_string)
    except ValueError:
        return None
    sw1 = payload[-2]
    sw2 = payload[-1]
    data = payload[:-2]
    return {
        "__kind__": "csim_response",
        "length_chars": declared,
        "data_hex": data.hex().upper(),
        "sw1_hex": f"{sw1:02X}",
        "sw2_hex": f"{sw2:02X}",
        "sw_meaning": _translate_sw(sw1, sw2),
    }


def _decode_crsm_response(line: str) -> Optional[dict]:
    match = _PLUS_CRSM_RESPONSE_RE.match(line)
    if match is None:
        return None
    sw1 = int(match.group("sw1")) & 0xFF
    sw2 = int(match.group("sw2")) & 0xFF
    raw_hex = (match.group("hex") or "").upper()
    if len(raw_hex) % 2 != 0:
        return None
    try:
        payload = bytes.fromhex(raw_hex) if len(raw_hex) > 0 else b""
    except ValueError:
        return None
    return {
        "__kind__": "crsm_response",
        "sw1_hex": f"{sw1:02X}",
        "sw2_hex": f"{sw2:02X}",
        "sw_meaning": _translate_sw(sw1, sw2),
        "data_hex": payload.hex().upper(),
    }


def _translate_sw(sw1: int, sw2: int) -> str:
    """Resolve SW1/SW2 to a human-readable label.

    Defers to the engine's existing translator so the side panel uses
    the same vocabulary as the SCP03 shell. Falls back to a neutral
    placeholder if the import path is unavailable for any reason.
    """
    try:
        from SCP03.core.utils import StatusWordTranslator
    except Exception:
        return ""
    try:
        return str(StatusWordTranslator.translate(int(sw1) & 0xFF, int(sw2) & 0xFF))
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


def feed_and_decode(
    accumulator: LineAccumulator,
    chunk: bytes,
    direction: str,
) -> Iterable[dict]:
    """Convenience wrapper used by the route layer.

    Yields each decoded entry produced by feeding *chunk* into
    *accumulator*. Lines that don't match any AT shape are silently
    consumed.
    """
    for line in accumulator.feed(chunk):
        decoded = decode_line(line, direction)
        if decoded is not None:
            yield decoded


__all__ = [
    "LineAccumulator",
    "decode_line",
    "feed_and_decode",
]
