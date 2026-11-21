# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Modem-side SIM interface log from a Qualcomm DIAG port, mirrored as GSMTAP SIM.

The modem's UIM driver logs every character it sends to and receives from the
card in LOG_UIM_DATA_C (0x1098; LOG_UIM_DS_DATA_C, 0x14CE, on dual-SIM builds).
This module rebuilds T=0 TPDUs from that byte stream and sends them into the
HIL GSMTAP stream in the bridge's frame layout, on GSMTAP antenna 1 and from
127.0.0.2, so Wireshark shows the modem's view beside the bridge or SIMtrace2
view of the same exchanges. What an APDU frame cannot carry -- NULL procedure
bytes and long holds, the PPS exchange, a TPDU cut short by a reset -- goes
out as libosmocore log records on the same antenna.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import signal
import time
from dataclasses import dataclass
from typing import Any, Callable

from .protocol import (
    GSMTAP_COMPAT_MODES,
    GSMTAP_COMPAT_NATIVE,
    GSMTAP_LOG_LEVEL_ERROR,
    GSMTAP_LOG_LEVEL_NOTICE,
    GSMTAP_UDP_PORT,
    GsmtapTap,
)
from .qcdiag import DiagPort, parse_log_packet, qxdm_timestamp_seconds

LOGGER = logging.getLogger(__name__)

LOG_UIM_DATA_C = 0x1098
LOG_UIM_DS_DATA_C = 0x14CE
UIM_LOG_CODES = (LOG_UIM_DATA_C, LOG_UIM_DS_DATA_C)
UIM_TX_MARKER = 0x10
UIM_RX_MARKER = 0x80
UIM_TIMESTAMP_MARKER = 0x01

MODEM_ANTENNA = 1
MODEM_SOURCE_HOST = "127.0.0.2"
LOG_PROCESS_NAME = "modem-diag"
LOG_SUBSYSTEM = "UIM"
DEFAULT_HOLD_NOTE_SECONDS = 0.5
DEFAULT_RETRY_SECONDS = 1.0

NULL_PROCEDURE_BYTE = 0x60
PPS_START_BYTE = 0xFF
ATR_START_BYTES = (0x3B, 0x3F)
# A bound only: an ATR is far shorter, and a run this long is not one.
MAX_ATR_BUFFER = 64
# P3 addresses at most 256 data bytes in one exchange.
MAX_EXCHANGE_DATA = 256

AUTO_DEVICE = "auto"
# The Linux USB serial drivers that turn a Qualcomm modem's interfaces into ttys.
DIAG_SERIAL_DRIVERS = frozenset({"option", "qcserial"})
USB_SYSFS_ROOT = "/sys/bus/usb/devices"


def find_diag_tty(sysfs_root: str = USB_SYSFS_ROOT) -> str:
    """Return the ``/dev/ttyUSBn`` that ``auto`` stands for, or "" when no modem is attached.

    That is the tty of USB interface 0 of the first device whose interface 0
    one of :data:`DIAG_SERIAL_DRIVERS` serves; a modem that puts DIAG on
    another interface needs the explicit path. The tty number moves whenever
    the modem re-enumerates, so the caller looks it up again on every
    (re)connect.
    """
    try:
        entries = sorted(os.listdir(sysfs_root))
    except OSError:
        return ""
    for entry in entries:
        if ":" not in entry or entry.endswith(".0") is False:
            continue
        interface_dir = os.path.join(sysfs_root, entry)
        driver = os.path.basename(os.path.realpath(os.path.join(interface_dir, "driver")))
        if driver not in DIAG_SERIAL_DRIVERS:
            continue
        try:
            ttys = sorted(name for name in os.listdir(interface_dir) if name.startswith("ttyUSB"))
        except OSError:
            continue
        if len(ttys) > 0:
            return f"/dev/{ttys[0]}"
    return ""


def resolve_diag_device(device: str) -> str:
    """The tty to open now: :func:`find_diag_tty` for ``auto``, else *device*."""
    if str(device).strip().lower() == AUTO_DEVICE:
        return find_diag_tty()
    return str(device)


@dataclass(frozen=True, slots=True)
class UimRun:
    """Consecutive bytes in one direction from one record, stamped on the modem clock."""

    direction: str
    data: bytes
    timestamp: float | None
    slot: int = 0


def parse_uim_record(
    code: int,
    payload: bytes,
    *,
    fallback_timestamp: float | None = None,
) -> list[UimRun]:
    """Split one UIM data log record into direction runs.

    Byte 0 counts the bytes that follow. Entries are ``10 xx`` (terminal to
    card), ``80 xx`` (card to terminal) and ``01`` with an 8-byte QXDM
    timestamp; in 0x14CE records a slot byte follows each marker. The layout
    is the one SCAT decodes in ``diag1xlogparser.parse_sim`` and
    ``parse_dual_sim``. The record carries one timestamp entry, written after
    its bytes, and it applies to all of them.
    """
    data = bytes(payload)
    if len(data) == 0:
        raise ValueError("UIM data record is empty.")
    if data[0] != len(data) - 1:
        raise ValueError(
            f"UIM data record claims {data[0]} bytes after its length byte; it carries {len(data) - 1}."
        )
    slot_width = 1 if int(code) == LOG_UIM_DS_DATA_C else 0
    entries: list[tuple[str, int, int]] = []
    stamp = fallback_timestamp
    position = 1
    while position < len(data):
        marker = data[position]
        if marker in (UIM_TX_MARKER, UIM_RX_MARKER):
            end = position + 2 + slot_width
            if end > len(data):
                raise ValueError(f"UIM data record ends inside a byte entry at offset {position}.")
            slot = data[position + 1] if slot_width else 0
            direction = "tx" if marker == UIM_TX_MARKER else "rx"
            entries.append((direction, slot, data[end - 1]))
            position = end
        elif marker == UIM_TIMESTAMP_MARKER:
            end = position + 9 + slot_width
            if end > len(data):
                raise ValueError(f"UIM data record ends inside a timestamp at offset {position}.")
            stamp = qxdm_timestamp_seconds(int.from_bytes(data[end - 8 : end], "little"))
            position = end
        else:
            raise ValueError(f"UIM data record has unknown entry type 0x{marker:02X} at offset {position}.")
    runs: list[UimRun] = []
    current = bytearray()
    current_key: tuple[str, int] | None = None
    for direction, slot, value in entries:
        if current_key != (direction, slot) and current_key is not None:
            runs.append(UimRun(direction=current_key[0], data=bytes(current), timestamp=stamp, slot=current_key[1]))
            current = bytearray()
        current_key = (direction, slot)
        current.append(value)
    if current_key is not None:
        runs.append(UimRun(direction=current_key[0], data=bytes(current), timestamp=stamp, slot=current_key[1]))
    return runs


@dataclass(slots=True)
class UimObservation:
    """What the reassembler saw: an ATR, a PPS exchange, a TPDU, a cut TPDU or stray bytes."""

    kind: str
    command: bytes = b""
    response: bytes = b""
    null_bytes: int = 0
    hold_seconds: float | None = None
    detail: str = ""


def _hex(data: bytes) -> str:
    return bytes(data).hex(" ").upper()


def atr_expected_length(atr: bytes) -> int | None:
    """Length the ATR declares, or None while the bytes so far cannot tell.

    TS and T0, the interface bytes each TDi announces, the historical bytes
    T0 counts, and TCK when a TDi indicates a protocol other than T=0. ETSI
    TS 102 221 V18.4.0 clause 6.3.0 defers the ATR to ISO/IEC 7816-3, which
    the specification library does not carry; this is the structure the
    APDU dissector's ``split.looks_like_atr`` checks.
    """
    data = bytes(atr)
    if len(data) < 2 or data[0] not in ATR_START_BYTES:
        return None
    historical = data[1] & 0x0F
    indicator = data[1] >> 4
    offset = 2
    needs_tck = False
    while True:
        interface_count = bin(indicator & 0x0F).count("1")
        if len(data) < offset + interface_count:
            return None
        offset += interface_count
        if indicator & 0x08 == 0:
            break
        td = data[offset - 1]
        if td & 0x0F != 0:
            needs_tck = True
        indicator = td >> 4
    return offset + historical + (1 if needs_tck else 0)


def _pps_length(pps0: int) -> int:
    # PPSS, PPS0, one byte per PPS1-PPS3 flag (PPS0 bits 5-7), PCK.
    return 3 + bin(int(pps0) & 0x70).count("1")


class T0Reassembler:
    """Rebuild T=0 TPDUs from direction-tagged UIM bytes.

    Procedure bytes follow ETSI TS 102 221 V18.4.0 clause 7.2.2.3.1, table 7.1
    (ACK equal to INS, the INS complement, NULL '60', SW1 '61' / '6C'); status
    bytes follow clause 7.2.2.3.2, table 7.2. The log tags every byte with its
    direction, so the data phase needs no per-INS case table: bytes from the
    terminal after an ACK are command data, bytes from the card response data.
    """

    def __init__(self) -> None:
        self._atr = bytearray()
        self._stray = bytearray()
        self._pps_allowed = False
        self._clear_exchange()

    def _clear_exchange(self) -> None:
        self._state = "idle"
        self._header = bytearray()
        self._command_data = bytearray()
        self._response_data = bytearray()
        self._sw1 = 0
        self._data_direction = ""
        self._data_remaining = 0
        self._null_bytes = 0
        self._last_terminal_stamp: float | None = None
        self._sw_stamp: float | None = None
        self._pps_request = bytearray()
        self._pps_response = bytearray()

    @property
    def state(self) -> str:
        return self._state

    def feed(self, run: UimRun) -> list[UimObservation]:
        observations: list[UimObservation] = []
        for value in run.data:
            if run.direction == "tx":
                self._from_terminal(value, run.timestamp, observations)
            else:
                self._from_card(value, run.timestamp, observations)
        return observations

    def flush(self, reason: str, timestamp: float | None = None) -> list[UimObservation]:
        """Report whatever is pending, e.g. when the DIAG port is lost."""
        observations: list[UimObservation] = []
        self._close_stray(observations)
        self._close_atr(observations)
        if self._state != "idle":
            observations.append(self._cut(reason, timestamp))
        self._clear_exchange()
        return observations

    def _check_data_bound(self, observations: list[UimObservation]) -> None:
        # Single-byte transfers under the INS complement have no count of
        # their own; a stream that keeps sending them is not a TPDU.
        if len(self._command_data) + len(self._response_data) <= MAX_EXCHANGE_DATA:
            return
        observations.append(
            UimObservation(
                kind="stray",
                command=bytes(self._header),
                detail=f"more than {MAX_EXCHANGE_DATA} data bytes in one exchange",
            )
        )
        self._clear_exchange()

    def _close_stray(self, observations: list[UimObservation]) -> None:
        if len(self._stray) == 0:
            return
        observations.append(
            UimObservation(kind="stray", response=bytes(self._stray), detail="card bytes with no command")
        )
        self._stray.clear()

    def _close_atr(self, observations: list[UimObservation]) -> None:
        if len(self._atr) == 0:
            return
        observations.append(UimObservation(kind="atr", response=bytes(self._atr)))
        self._atr.clear()
        self._pps_allowed = True

    def _cut(self, reason: str, timestamp: float | None) -> UimObservation:
        if self._state in ("pps_request", "pps_response"):
            return UimObservation(
                kind="stray",
                command=bytes(self._pps_request),
                response=bytes(self._pps_response),
                detail=f"PPS exchange incomplete before {reason}",
            )
        hold = None
        if timestamp is not None and self._last_terminal_stamp is not None:
            hold = max(0.0, timestamp - self._last_terminal_stamp)
        expected = self._header[4] if len(self._header) == 5 else 0
        return UimObservation(
            kind="cut",
            command=bytes(self._header) + bytes(self._command_data),
            response=bytes(self._response_data),
            null_bytes=self._null_bytes,
            hold_seconds=hold,
            detail=(
                f"no status word before {reason}; "
                f"{len(self._command_data)}/{expected} command data bytes sent"
            ),
        )

    def _from_terminal(self, value: int, stamp: float | None, observations: list[UimObservation]) -> None:
        state = self._state
        if state == "idle":
            self._close_stray(observations)
            self._close_atr(observations)
            if value == PPS_START_BYTE and self._pps_allowed:
                self._pps_allowed = False
                self._pps_request = bytearray((value,))
                self._state = "pps_request"
                return
            self._pps_allowed = False
            self._header = bytearray((value,))
            self._last_terminal_stamp = stamp
            self._state = "header"
            return
        if state == "header":
            self._header.append(value)
            self._last_terminal_stamp = stamp
            if len(self._header) == 5:
                self._state = "procedure"
            return
        if state == "pps_request":
            self._pps_request.append(value)
            if len(self._pps_request) >= 2 and len(self._pps_request) == _pps_length(self._pps_request[1]):
                self._state = "pps_response"
            return
        if state == "data" and self._data_direction in ("", "tx"):
            if self._data_direction == "":
                self._data_direction = "tx"
                self._data_remaining = self._header[4] - len(self._command_data)
            self._command_data.append(value)
            self._last_terminal_stamp = stamp
            self._data_remaining -= 1
            if self._data_remaining <= 0:
                self._state = "procedure"
            return
        if state == "single":
            self._command_data.append(value)
            self._last_terminal_stamp = stamp
            self._state = "procedure"
            self._check_data_bound(observations)
            return
        # The terminal spoke while the card had the line: report the open
        # exchange and read this byte as the start of a new one.
        observations.append(self._cut(f"the terminal sent {value:02X} without a procedure byte", stamp))
        self._clear_exchange()
        self._from_terminal(value, stamp, observations)

    def _from_card(self, value: int, stamp: float | None, observations: list[UimObservation]) -> None:
        state = self._state
        if state == "idle":
            if len(self._atr) == 0 and value not in ATR_START_BYTES:
                # Only TS ('3B' or '3F') opens an ATR; anything else from an
                # idle card is reported rather than read as one.
                self._stray.append(value)
                if len(self._stray) >= MAX_ATR_BUFFER:
                    self._close_stray(observations)
                return
            self._close_stray(observations)
            if len(self._atr) >= MAX_ATR_BUFFER:
                observations.append(
                    UimObservation(kind="stray", response=bytes(self._atr), detail="card bytes with no command")
                )
                self._atr.clear()
            self._atr.append(value)
            # Closed as soon as it is complete, so two resets in a row with no
            # terminal byte between them still give two ATRs.
            if atr_expected_length(self._atr) == len(self._atr):
                self._close_atr(observations)
            return
        if state == "procedure":
            if value == NULL_PROCEDURE_BYTE:
                self._null_bytes += 1
                return
            ins = self._header[1]
            if value == ins:
                self._state = "data"
                self._data_direction = ""
                return
            if value == ins ^ 0xFF:
                self._state = "single"
                return
            if (value & 0xF0) in (0x60, 0x90):
                self._sw1 = value
                self._sw_stamp = stamp
                self._state = "sw2"
                return
            if value in ATR_START_BYTES:
                observations.append(self._cut("a new ATR", stamp))
                self._clear_exchange()
                self._atr = bytearray((value,))
                return
            observations.append(
                UimObservation(
                    kind="stray",
                    command=bytes(self._header),
                    response=bytes((value,)),
                    detail=f"{value:02X} is not a procedure byte for INS {ins:02X}",
                )
            )
            self._clear_exchange()
            return
        if state == "sw2":
            hold = None
            if self._sw_stamp is not None and self._last_terminal_stamp is not None:
                hold = max(0.0, self._sw_stamp - self._last_terminal_stamp)
            observations.append(
                UimObservation(
                    kind="tpdu",
                    command=bytes(self._header) + bytes(self._command_data),
                    response=bytes(self._response_data) + bytes((self._sw1, value)),
                    null_bytes=self._null_bytes,
                    hold_seconds=hold,
                )
            )
            self._clear_exchange()
            return
        if state == "data" and self._data_direction in ("", "rx"):
            if self._data_direction == "":
                self._data_direction = "rx"
                expected = self._header[4] or 256
                self._data_remaining = expected - len(self._response_data)
            self._response_data.append(value)
            self._data_remaining -= 1
            if self._data_remaining <= 0:
                self._state = "procedure"
            return
        if state == "single":
            self._response_data.append(value)
            self._state = "procedure"
            self._check_data_bound(observations)
            return
        if state == "pps_response":
            self._pps_response.append(value)
            if len(self._pps_response) >= 2 and len(self._pps_response) == _pps_length(self._pps_response[1]):
                observations.append(
                    UimObservation(
                        kind="pps", command=bytes(self._pps_request), response=bytes(self._pps_response)
                    )
                )
                self._clear_exchange()
            return
        if value in ATR_START_BYTES:
            observations.append(self._cut("a new ATR", stamp))
            self._clear_exchange()
            self._atr = bytearray((value,))
            return
        observations.append(
            UimObservation(
                kind="stray",
                command=bytes(self._header),
                response=bytes((value,)),
                detail=f"card byte {value:02X} while the terminal had the line ({state})",
            )
        )
        self._clear_exchange()


class ModemSimMirror:
    """Turn reassembler observations into GSMTAP frames on the modem-side antenna."""

    def __init__(
        self,
        tap: Any,
        *,
        hold_note_seconds: float = DEFAULT_HOLD_NOTE_SECONDS,
        notes: bool = True,
    ) -> None:
        self._tap = tap
        self._hold_note_seconds = float(hold_note_seconds)
        self._notes = bool(notes)
        self.send_failures = 0

    def _note(self, text: str, level: int = GSMTAP_LOG_LEVEL_NOTICE) -> None:
        if self._notes:
            self._tap.send_log(text, process=LOG_PROCESS_NAME, subsystem=LOG_SUBSYSTEM, level=level)

    def emit(self, observation: UimObservation) -> None:
        """Send *observation*; a failed send is counted, never raised into the DIAG loop."""
        try:
            self._emit(observation)
        except OSError as error:
            # A refused or unroutable GSMTAP send, or a full disk under
            # --capture-path, must not read as a lost DIAG port.
            self.send_failures += 1
            if self.send_failures == 1:
                LOGGER.warning("Sending modem-side GSMTAP failed: %s (reported once)", error)

    def _emit(self, observation: UimObservation) -> None:
        kind = observation.kind
        if kind == "tpdu":
            self._tap.mirror_exchange(observation.command, observation.response)
            hold = observation.hold_seconds
            long_hold = hold is not None and hold >= self._hold_note_seconds
            if observation.null_bytes > 0 or long_hold:
                held = "" if hold is None else f" after {hold:.3f} s"
                self._note(
                    f"{_hex(observation.command[:5])}: SW {_hex(observation.response[-2:])}{held} "
                    f"on the modem clock, {observation.null_bytes} NULL"
                )
            return
        if kind == "atr":
            self._tap.send_atr(observation.response)
            return
        if kind == "pps":
            outcome = "accepted" if observation.command == observation.response else "answered differently"
            self._note(f"PPS {_hex(observation.command)} -> {_hex(observation.response)} ({outcome})")
            return
        if kind == "cut":
            held = "" if observation.hold_seconds is None else f", {observation.hold_seconds:.3f} s after the terminal's last byte"
            self._note(
                f"{_hex(observation.command[:5])}: {observation.detail}, "
                f"{observation.null_bytes} NULL{held}",
                level=GSMTAP_LOG_LEVEL_ERROR,
            )
            return
        self._note(f"{observation.detail}: {_hex(observation.command)} / {_hex(observation.response)}")


def _resolve_source_host(source_host: str | None, gsmtap_host: str) -> str:
    if source_host is not None:
        return str(source_host).strip()
    try:
        if ipaddress.ip_address(str(gsmtap_host).strip()).is_loopback:
            return MODEM_SOURCE_HOST
    except ValueError:
        return ""
    return ""


def build_parser() -> argparse.ArgumentParser:
    from yggdrasim_common.process_debug import add_debug_argument

    parser = argparse.ArgumentParser(
        prog="yggdrasim-hil-modem-diag",
        description=(
            "Mirror the modem's own SIM interface log (Qualcomm DIAG LOG_UIM_DATA_C) into the "
            "HIL GSMTAP stream, beside the bridge or SIMtrace2 view of the same exchanges."
        ),
    )
    parser.add_argument(
        "--device",
        required=True,
        help=(
            "DIAG tty of the modem, e.g. /dev/serial/by-id/...-if00-port0, or 'auto' for USB "
            "interface 0 of a modem the Linux option or qcserial driver serves, looked up again "
            "on every (re)connect."
        ),
    )
    parser.add_argument("--gsmtap-host", default="127.0.0.1", help="GSMTAP destination host.")
    parser.add_argument("--gsmtap-port", type=int, default=GSMTAP_UDP_PORT, help="GSMTAP destination port.")
    parser.add_argument(
        "--gsmtap-compat",
        choices=sorted(GSMTAP_COMPAT_MODES),
        default=GSMTAP_COMPAT_NATIVE,
        help="Same switch as the bridge; wireshark44 leaves the ATR frames out.",
    )
    parser.add_argument(
        "--source-host",
        default=None,
        help=f"Local address to send from (default {MODEM_SOURCE_HOST} for a loopback destination).",
    )
    parser.add_argument(
        "--antenna",
        type=int,
        default=MODEM_ANTENNA,
        help="GSMTAP antenna number of the modem-side frames (the bridge uses 0).",
    )
    parser.add_argument("--slot", type=int, default=0, help="SIM slot to mirror from 0x14CE records.")
    parser.add_argument("--capture-path", default="", help="Also write the frames to this pcap file.")
    parser.add_argument(
        "--hold-note-seconds",
        type=float,
        default=DEFAULT_HOLD_NOTE_SECONDS,
        help="Add a log note for exchanges the card held at least this long (NULL bytes always get one).",
    )
    parser.add_argument("--no-notes", action="store_true", help="Send APDU and ATR frames only.")
    parser.add_argument(
        "--retry-seconds",
        type=float,
        default=DEFAULT_RETRY_SECONDS,
        help="Wait between attempts while the DIAG port is missing or busy.",
    )
    add_debug_argument(parser, help_text="Enable verbose DIAG logging.")
    return parser


def _mirror_packet(
    packet: bytes,
    codes: set[int],
    slot: int,
    reassembler: T0Reassembler,
    mirror: ModemSimMirror,
) -> None:
    try:
        record = parse_log_packet(packet)
    except ValueError as error:
        LOGGER.debug("Skipping a malformed DIAG log packet: %s", error)
        return
    if record is None or record.code not in codes:
        return
    try:
        runs = parse_uim_record(
            record.code,
            record.payload,
            fallback_timestamp=qxdm_timestamp_seconds(record.timestamp),
        )
    except ValueError as error:
        LOGGER.warning("Skipping a UIM data record: %s", error)
        return
    for run in runs:
        if run.slot != slot:
            continue
        for observation in reassembler.feed(run):
            mirror.emit(observation)


def run_mirror(
    args: argparse.Namespace,
    *,
    port_factory: Callable[[str], Any] = DiagPort,
    tap_factory: Callable[..., Any] = GsmtapTap,
    sleep: Callable[[float], None] = time.sleep,
    device_present: Callable[[str], bool] = os.path.exists,
    should_stop: Callable[[], bool] = lambda: False,
) -> int:
    """Mirror until stopped, reopening the DIAG port whenever the modem re-enumerates."""
    source_host = _resolve_source_host(args.source_host, args.gsmtap_host)
    try:
        tap = tap_factory(
            host=str(args.gsmtap_host),
            port=int(args.gsmtap_port),
            enabled=True,
            compat_mode=str(args.gsmtap_compat),
            capture_path=str(args.capture_path or ""),
            antenna=int(args.antenna),
            source_host=source_host,
        )
    except OSError as error:
        LOGGER.error(
            "Cannot send GSMTAP from %s: %s. Pass --source-host '' to let the system choose.",
            source_host or "the default address",
            error,
        )
        return 2
    mirror = ModemSimMirror(tap, hold_note_seconds=args.hold_note_seconds, notes=not args.no_notes)
    reassembler = T0Reassembler()
    port: Any = None
    retry_seconds = max(0.1, float(args.retry_seconds))
    waiting_reported = False
    reported_error = ""
    try:
        while not should_stop():
            # Resolved on every attempt: an ``auto`` port, or a tty behind a
            # by-id link, moves when the modem re-enumerates.
            device = resolve_diag_device(str(args.device))
            if len(device) == 0 or not device_present(device):
                if not waiting_reported:
                    LOGGER.info("Waiting for the DIAG port %s", args.device)
                    waiting_reported = True
                sleep(retry_seconds)
                continue
            port = port_factory(device)
            try:
                port.open()
                codes = port.configure_logs(UIM_LOG_CODES)
            except (OSError, RuntimeError) as error:
                # Reported once per distinct reason: a busy or booting port
                # would otherwise log every retry.
                if str(error) != reported_error:
                    LOGGER.warning("DIAG port %s is not usable yet: %s", device, error)
                    reported_error = str(error)
                port.close()
                sleep(retry_seconds)
                continue
            reported_error = ""
            if len(codes) == 0:
                LOGGER.error(
                    "The DIAG build on %s takes neither 0x1098 nor 0x14CE; there is no SIM log to mirror.",
                    device,
                )
                return 2
            waiting_reported = False
            LOGGER.info(
                "Mirroring the modem-side SIM log (%s) from %s to %s:%s on antenna %s%s",
                ", ".join(f"0x{code:04X}" for code in sorted(codes)),
                device,
                args.gsmtap_host,
                args.gsmtap_port,
                args.antenna,
                f" from {source_host}" if source_host else "",
            )
            try:
                while not should_stop():
                    for packet in port.read_packets():
                        _mirror_packet(packet, codes, int(args.slot), reassembler, mirror)
            except OSError as error:
                LOGGER.warning("DIAG port %s lost: %s; waiting for it to return.", device, error)
                for observation in reassembler.flush("the DIAG port was lost"):
                    mirror.emit(observation)
                port.close()
                sleep(retry_seconds)
        return 0
    finally:
        if port is not None and port.is_open:
            try:
                port.disable_logs()
            except (OSError, RuntimeError):
                pass
            port.close()
        for observation in reassembler.flush("the mirror stopped"):
            mirror.emit(observation)
        try:
            tap.close()
        except OSError:
            pass


def _stop_on_sigterm(signum: int, frame: Any) -> None:
    raise SystemExit(0)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _stop_on_sigterm)
    try:
        return run_mirror(args)
    except KeyboardInterrupt:
        return 0


def entry() -> int:
    return main()


if __name__ == "__main__":
    raise SystemExit(main())
