# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Qualcomm DIAG over a serial port: HDLC framing, log masks and log records.

A Qualcomm modem exposes DIAG on a vendor-specific USB interface that the
Linux ``option`` or ``qcserial`` driver turns into a tty. A frame carries the
payload, its CRC-16/X-25 in little-endian order, ``0x7D`` escaping and a
``0x7E`` trailer. Opcode and log-config values match osmocom ``osmo-qcdiag``
(``src/protocol/diagcmd.h``) and SCAT (``parsers/qualcomm/diagcmd.py``). Only
one client may hold the port at a time, so the port is opened exclusively.
"""
from __future__ import annotations

import os
import struct
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Iterable

DIAG_LOG_F = 0x10
DIAG_BAD_CMD_F = 0x13
DIAG_BAD_PARM_F = 0x14
DIAG_BAD_LEN_F = 0x15
DIAG_LOG_CONFIG_F = 0x73
DIAG_EXT_MSG_CONFIG_F = 0x7D

LOG_CONFIG_DISABLE_OP = 0
LOG_CONFIG_RETRIEVE_ID_RANGES_OP = 1
LOG_CONFIG_SET_MASK_OP = 3
LOG_CONFIG_SUCCESS_S = 0
LOG_ID_RANGE_COUNT = 16
MSG_EXT_SUBCMD_SET_ALL_RT_MASKS = 5

HDLC_TRAILER = 0x7E
HDLC_ESCAPE = 0x7D
HDLC_ESCAPE_XOR = 0x20

DIAG_BAUD_RATE = 115200
MAX_FRAME_BYTES = 64 * 1024
MAX_PENDING_PACKETS = 4096
_DIAG_ERROR_OPCODES = {
    DIAG_BAD_CMD_F: "bad command",
    DIAG_BAD_PARM_F: "bad parameter",
    DIAG_BAD_LEN_F: "bad length",
}


def _build_crc16_x25_table() -> tuple[int, ...]:
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
        table.append(crc)
    return tuple(table)


_CRC16_X25_TABLE = _build_crc16_x25_table()


def crc16_x25(data: bytes) -> int:
    """CRC-16/X-25: reflected 0x1021, initial value and final XOR 0xFFFF."""
    crc = 0xFFFF
    for byte in bytes(data):
        crc = (crc >> 8) ^ _CRC16_X25_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFF


def hdlc_encode(payload: bytes) -> bytes:
    """Frame one DIAG request: payload, CRC, escaping, trailer."""
    body = bytes(payload) + struct.pack("<H", crc16_x25(payload))
    framed = bytearray()
    for byte in body:
        if byte in (HDLC_TRAILER, HDLC_ESCAPE):
            framed.append(HDLC_ESCAPE)
            framed.append(byte ^ HDLC_ESCAPE_XOR)
        else:
            framed.append(byte)
    framed.append(HDLC_TRAILER)
    return bytes(framed)


class HdlcDeframer:
    """Split a DIAG byte stream into payloads whose CRC checks out."""

    def __init__(self, *, max_frame_bytes: int = MAX_FRAME_BYTES) -> None:
        self._buffer = bytearray()
        self._escaped = False
        self._discarding = False
        self._max_frame_bytes = int(max_frame_bytes)
        self.crc_errors = 0
        self.oversize_frames = 0

    def reset(self) -> None:
        self._buffer.clear()
        self._escaped = False
        self._discarding = False

    def feed(self, data: bytes) -> list[bytes]:
        payloads: list[bytes] = []
        for byte in bytes(data):
            if byte == HDLC_TRAILER:
                frame = bytes(self._buffer)
                discarded = self._discarding
                self.reset()
                if discarded or len(frame) == 0:
                    continue
                if len(frame) < 3 or struct.unpack("<H", frame[-2:])[0] != crc16_x25(frame[:-2]):
                    self.crc_errors += 1
                    continue
                payloads.append(frame[:-2])
                continue
            if self._discarding:
                continue
            if byte == HDLC_ESCAPE:
                self._escaped = True
                continue
            if self._escaped:
                byte ^= HDLC_ESCAPE_XOR
                self._escaped = False
            self._buffer.append(byte)
            if len(self._buffer) > self._max_frame_bytes:
                # A lost trailer would otherwise grow the buffer without end.
                self.oversize_frames += 1
                self._buffer.clear()
                self._discarding = True
        return payloads


@dataclass(frozen=True, slots=True)
class DiagLogRecord:
    code: int
    timestamp: int
    payload: bytes


def parse_log_packet(packet: bytes) -> DiagLogRecord | None:
    """Return the record in a ``DIAG_LOG_F`` packet; None for any other opcode.

    After the opcode come a pending count (1), the outer length (2) and the
    inner header: its length (2, counting the 12 header bytes), the log code
    (2) and the QXDM timestamp (8), followed by the record.
    """
    data = bytes(packet)
    if len(data) == 0 or data[0] != DIAG_LOG_F:
        return None
    if len(data) < 16:
        raise ValueError(f"DIAG log packet of {len(data)} bytes is shorter than its 16-byte header.")
    inner_length, code, timestamp = struct.unpack_from("<HHQ", data, 4)
    if inner_length < 12:
        raise ValueError(f"DIAG log record 0x{code:04X} claims {inner_length} bytes, less than its header.")
    if 4 + inner_length > len(data):
        raise ValueError(
            f"DIAG log record 0x{code:04X} claims {inner_length} bytes; the packet carries {len(data) - 4}."
        )
    return DiagLogRecord(code=int(code), timestamp=int(timestamp), payload=data[16 : 4 + inner_length])


def qxdm_timestamp_seconds(raw: int) -> float:
    """Seconds on the modem clock from a QXDM timestamp.

    The upper 48 bits count 1.25 ms ticks and the lower 16 bits the time since
    the last tick in 1/32-chip units (SCAT ``util.parse_qxdm_ts``). Only
    differences between two stamps are meaningful to callers here.
    """
    value = int(raw) & 0xFFFFFFFFFFFFFFFF
    return (value >> 16) * 0.00125 + (value & 0xFFFF) / 40_960_000.0


def log_mask_bytes(bit_count: int, item_ids: Iterable[int]) -> bytes:
    """Bit *i* of the mask enables item *i* of one equipment ID, LSB first."""
    mask = bytearray((int(bit_count) + 7) // 8)
    for item_id in item_ids:
        item = int(item_id)
        if 0 <= item < int(bit_count):
            mask[item // 8] |= 1 << (item % 8)
    return bytes(mask)


class DiagPort:
    """Synchronous DIAG client on a tty, opened exclusively."""

    def __init__(
        self,
        device: str,
        *,
        serial_factory: Callable[..., Any] | None = None,
        response_timeout_seconds: float = 3.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.device = str(device)
        self._serial_factory = serial_factory
        self._response_timeout_seconds = float(response_timeout_seconds)
        self._monotonic = monotonic
        self._serial: Any = None
        self._deframer = HdlcDeframer()
        self._pending: deque[bytes] = deque(maxlen=MAX_PENDING_PACKETS)

    @property
    def is_open(self) -> bool:
        return self._serial is not None

    @property
    def crc_errors(self) -> int:
        return self._deframer.crc_errors

    def open(self) -> None:
        factory = self._serial_factory
        if factory is None:
            import serial

            factory = serial.Serial
        # A by-id or by-path symlink is resolved on every open: the tty
        # number can change when the modem re-enumerates.
        port = os.path.realpath(self.device)
        self._serial = factory(
            port=port,
            baudrate=DIAG_BAUD_RATE,
            rtscts=True,
            dsrdtr=True,
            timeout=0.2,
            exclusive=True,
        )
        self._deframer.reset()
        self._pending.clear()

    def close(self) -> None:
        handle = self._serial
        self._serial = None
        if handle is None:
            return
        try:
            handle.close()
        except OSError:
            pass

    def _read_frames(self) -> list[bytes]:
        if self._serial is None:
            raise RuntimeError(f"DIAG port {self.device} is not open.")
        data = self._serial.read(4096)
        if not data:
            return []
        return self._deframer.feed(data)

    def request(self, payload: bytes) -> bytes:
        """Send one command and return its response; log frames read meanwhile are kept."""
        if self._serial is None:
            raise RuntimeError(f"DIAG port {self.device} is not open.")
        opcode = bytes(payload)[0]
        self._serial.write(hdlc_encode(payload))
        deadline = self._monotonic() + self._response_timeout_seconds
        while self._monotonic() < deadline:
            response: bytes | None = None
            # One read can hold log frames after the response as well as
            # before it; every one of them is kept for read_packets().
            for frame in self._read_frames():
                if len(frame) == 0:
                    continue
                if response is None and frame[0] == opcode:
                    response = frame
                    continue
                if response is None and frame[0] in _DIAG_ERROR_OPCODES:
                    raise RuntimeError(
                        f"DIAG rejected opcode 0x{opcode:02X} ({_DIAG_ERROR_OPCODES[frame[0]]})."
                    )
                self._pending.append(frame)
            if response is not None:
                return response
        raise RuntimeError(
            f"DIAG on {self.device} did not answer opcode 0x{opcode:02X} within "
            f"{self._response_timeout_seconds:.1f} s."
        )

    def read_packets(self) -> list[bytes]:
        """Return the packets that arrived since the last call (blocks up to 0.2 s)."""
        packets = list(self._pending)
        self._pending.clear()
        packets.extend(self._read_frames())
        return packets

    def _log_config(self, operation: int, extra: bytes = b"") -> bytes:
        response = self.request(struct.pack("<B3xI", DIAG_LOG_CONFIG_F, operation) + extra)
        if len(response) < 12:
            raise RuntimeError(f"DIAG log-config answer of {len(response)} bytes is too short.")
        answered_operation, status = struct.unpack_from("<II", response, 4)
        if answered_operation != operation or status != LOG_CONFIG_SUCCESS_S:
            raise RuntimeError(
                f"DIAG log-config operation {operation} failed (operation {answered_operation}, status {status})."
            )
        return response

    def configure_logs(self, codes: Iterable[int]) -> set[int]:
        """Silence F3 messages and every log, then enable *codes*; return those the modem accepts.

        A code whose item number lies beyond its equipment ID's range is left
        out of the result rather than requested.
        """
        try:
            self.request(struct.pack("<BBxxI", DIAG_EXT_MSG_CONFIG_F, MSG_EXT_SUBCMD_SET_ALL_RT_MASKS, 0))
        except RuntimeError:
            # Not every build takes the F3 mask command; silencing it only
            # keeps a previous client's message flood off the port.
            pass
        self._log_config(LOG_CONFIG_DISABLE_OP)
        ranges_answer = self._log_config(LOG_CONFIG_RETRIEVE_ID_RANGES_OP)
        if len(ranges_answer) < 12 + 4 * LOG_ID_RANGE_COUNT:
            raise RuntimeError("DIAG log-config ID ranges answer is truncated.")
        bit_counts = struct.unpack_from(f"<{LOG_ID_RANGE_COUNT}I", ranges_answer, 12)
        by_equipment: dict[int, set[int]] = {}
        for code in codes:
            equipment_id = (int(code) >> 12) & 0x0F
            item_id = int(code) & 0x0FFF
            if item_id < bit_counts[equipment_id]:
                by_equipment.setdefault(equipment_id, set()).add(item_id)
        enabled: set[int] = set()
        for equipment_id, item_ids in sorted(by_equipment.items()):
            bit_count = bit_counts[equipment_id]
            self._log_config(
                LOG_CONFIG_SET_MASK_OP,
                struct.pack("<II", equipment_id, bit_count) + log_mask_bytes(bit_count, item_ids),
            )
            enabled.update((equipment_id << 12) | item_id for item_id in item_ids)
        return enabled

    def disable_logs(self) -> None:
        self._log_config(LOG_CONFIG_DISABLE_OP)
