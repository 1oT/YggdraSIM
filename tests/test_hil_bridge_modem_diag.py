# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import socket
import struct
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from Tools.HilBridge.modem_diag import (
    LOG_UIM_DATA_C,
    LOG_UIM_DS_DATA_C,
    MODEM_SOURCE_HOST,
    ModemSimMirror,
    T0Reassembler,
    UimObservation,
    UimRun,
    _resolve_source_host,
    atr_expected_length,
    build_parser,
    find_diag_tty,
    parse_uim_record,
    resolve_diag_device,
    run_mirror,
)
from Tools.HilBridge.protocol import (
    GSMTAP_LOG_LEVEL_ERROR,
    GSMTAP_LOG_LEVEL_NOTICE,
    GSMTAP_SIM_APDU,
    GSMTAP_SIM_ATR,
    GSMTAP_TYPE_OSMOCORE_LOG,
    GsmtapTap,
    build_gsmtap_log_packet,
    build_gsmtap_packet,
)
from Tools.HilBridge.qcdiag import (
    DIAG_BAD_CMD_F,
    DIAG_EXT_MSG_CONFIG_F,
    DIAG_LOG_CONFIG_F,
    DIAG_LOG_F,
    DiagPort,
    HdlcDeframer,
    crc16_x25,
    hdlc_encode,
    log_mask_bytes,
    parse_log_packet,
    qxdm_timestamp_seconds,
)

# Synthetic ATR: TA1 96, TD1 80 (T=0), TD2 1F (T=15), TA3 C7, five
# historical bytes, TCK (XOR of T0 .. the last historical byte).
_ATR_BODY = bytes.fromhex("3B 95 96 80 1F C7 80 31 E0 73 00")


def _with_tck(atr_without_tck: bytes) -> bytes:
    check = 0
    for value in atr_without_tck[1:]:
        check ^= value
    return atr_without_tck + bytes((check,))


SYNTHETIC_ATR = _with_tck(_ATR_BODY)


def _uim_record(entries: list[tuple[str, bytes]], ticks: int = 0, *, slot: int | None = None) -> bytes:
    body = bytearray()
    slot_bytes = b"" if slot is None else bytes((slot,))
    for direction, data in entries:
        marker = 0x10 if direction == "tx" else 0x80
        for value in data:
            body += bytes((marker,)) + slot_bytes + bytes((value,))
    body += b"\x01" + slot_bytes + (int(ticks) << 16).to_bytes(8, "little")
    return bytes((len(body),)) + bytes(body)


def _log_packet(code: int, payload: bytes, timestamp: int = 0) -> bytes:
    inner = struct.pack("<HHQ", 12 + len(payload), code, timestamp) + payload
    return struct.pack("<BBH", DIAG_LOG_F, 0, len(inner)) + inner


def _feed(reassembler: T0Reassembler, *steps: tuple[str, str, float | None]) -> list[UimObservation]:
    observations: list[UimObservation] = []
    for direction, hex_data, stamp in steps:
        observations += reassembler.feed(UimRun(direction=direction, data=bytes.fromhex(hex_data), timestamp=stamp))
    return observations


class HdlcFramingTests(unittest.TestCase):
    def test_crc16_x25_check_value(self) -> None:
        self.assertEqual(crc16_x25(b"123456789"), 0x906E)

    def test_encode_matches_reference_frames(self) -> None:
        # Reference frames produced once with QCSuper's HdlcMixin.hdlc_encapsulate.
        vectors = {
            "00": "0078f07e",
            "7300000001000000": "7300000001000000619d7e",
            "7d5e7e00": "7d5d5e7d5e0038d47e",
            "7d0500000000": "7d5d050000000005217e",
        }
        for payload_hex, frame_hex in vectors.items():
            with self.subTest(payload=payload_hex):
                self.assertEqual(hdlc_encode(bytes.fromhex(payload_hex)).hex(), frame_hex)

    def test_deframer_reassembles_frames_split_anywhere(self) -> None:
        payloads = [b"\x00", bytes.fromhex("7d5e7e00"), bytes(range(40))]
        stream = b"\x7e" + b"".join(hdlc_encode(payload) for payload in payloads)
        for split in range(1, len(stream)):
            with self.subTest(split=split):
                deframer = HdlcDeframer()
                received = deframer.feed(stream[:split]) + deframer.feed(stream[split:])
                self.assertEqual(received, payloads)

    def test_deframer_drops_a_frame_with_a_bad_crc(self) -> None:
        damaged = bytearray(hdlc_encode(b"\x73\x00"))
        damaged[0] ^= 0x01
        deframer = HdlcDeframer()
        self.assertEqual(deframer.feed(bytes(damaged) + hdlc_encode(b"\x60")), [b"\x60"])
        self.assertEqual(deframer.crc_errors, 1)

    def test_deframer_discards_an_oversize_frame_until_its_trailer(self) -> None:
        deframer = HdlcDeframer(max_frame_bytes=8)
        received = deframer.feed(bytes(20) + b"\x7e" + hdlc_encode(b"\x10\x01"))
        self.assertEqual(received, [b"\x10\x01"])
        self.assertEqual(deframer.oversize_frames, 1)


class DiagLogPacketTests(unittest.TestCase):
    def test_parses_code_timestamp_and_payload(self) -> None:
        record = parse_log_packet(_log_packet(LOG_UIM_DATA_C, b"\x01\x02\x03", timestamp=0x1234))
        self.assertIsNotNone(record)
        self.assertEqual(record.code, LOG_UIM_DATA_C)
        self.assertEqual(record.timestamp, 0x1234)
        self.assertEqual(record.payload, b"\x01\x02\x03")

    def test_other_opcodes_and_empty_input_are_not_log_records(self) -> None:
        self.assertIsNone(parse_log_packet(b""))
        self.assertIsNone(parse_log_packet(b"\x73\x00\x00\x00"))

    def test_decode_boundaries_raise_value_error(self) -> None:
        packet = _log_packet(LOG_UIM_DATA_C, b"\x01\x02")
        over_claiming = packet[:4] + struct.pack("<H", 40) + packet[6:]
        under_header = packet[:4] + struct.pack("<H", 4) + packet[6:]
        for bad in (b"\x10", packet[:15], over_claiming, under_header):
            with self.subTest(packet=bad.hex()):
                with self.assertRaises(ValueError):
                    parse_log_packet(bad)

    def test_qxdm_timestamp_units(self) -> None:
        self.assertAlmostEqual(qxdm_timestamp_seconds(1 << 16), 0.00125)
        self.assertAlmostEqual(qxdm_timestamp_seconds(800 << 16), 1.0)
        self.assertAlmostEqual(qxdm_timestamp_seconds(40960), 0.001)

    def test_log_mask_sets_one_bit_per_item(self) -> None:
        mask = log_mask_bytes(0x500, {0x098, 0x4CE, 0x9999})
        self.assertEqual(len(mask), 0xA0)
        self.assertEqual(mask[0x098 // 8], 1 << (0x098 % 8))
        self.assertEqual(mask[0x4CE // 8], 1 << (0x4CE % 8))
        self.assertEqual(sum(bin(value).count("1") for value in mask), 2)


class _FakeDiagTty:
    """A DIAG tty that answers the configuration requests DiagPort sends."""

    def __init__(
        self,
        *,
        bit_counts: dict[int, int],
        reject_f3: bool = False,
        preface: bytes = b"",
        after_set_mask: bytes = b"",
    ) -> None:
        self.requests: list[bytes] = []
        self.open_kwargs: dict[str, object] = {}
        self.closed = False
        self._bit_counts = bit_counts
        self._reject_f3 = reject_f3
        self._after_set_mask = after_set_mask
        self._deframer = HdlcDeframer()
        self._outbox = bytearray(preface)

    def __call__(self, **kwargs: object) -> "_FakeDiagTty":
        self.open_kwargs = dict(kwargs)
        return self

    def write(self, data: bytes) -> None:
        for request in self._deframer.feed(data):
            self.requests.append(request)
            self._outbox += hdlc_encode(self._answer(request))
            if request[0] == DIAG_LOG_CONFIG_F and request[4] == 3:
                self._outbox += self._after_set_mask

    def read(self, size: int) -> bytes:
        chunk = bytes(self._outbox[:size])
        del self._outbox[:size]
        return chunk

    def close(self) -> None:
        self.closed = True

    def _answer(self, request: bytes) -> bytes:
        if request[0] == DIAG_EXT_MSG_CONFIG_F:
            if self._reject_f3:
                return bytes((DIAG_BAD_CMD_F,)) + request
            return request
        operation = struct.unpack_from("<I", request, 4)[0]
        answer = struct.pack("<B3xII", DIAG_LOG_CONFIG_F, operation, 0)
        if operation == 1:
            answer += struct.pack("<16I", *(self._bit_counts.get(index, 0) for index in range(16)))
        return answer


class DiagPortTests(unittest.TestCase):
    def test_configure_logs_enables_only_codes_inside_the_range(self) -> None:
        tty = _FakeDiagTty(bit_counts={1: 0x200})
        port = DiagPort("/dev/null", serial_factory=tty)
        port.open()
        enabled = port.configure_logs((LOG_UIM_DATA_C, LOG_UIM_DS_DATA_C))
        self.assertEqual(enabled, {LOG_UIM_DATA_C})
        self.assertTrue(tty.open_kwargs["exclusive"])
        self.assertTrue(tty.open_kwargs["rtscts"])
        set_mask = [request for request in tty.requests if request[0] == DIAG_LOG_CONFIG_F and request[4] == 3]
        self.assertEqual(len(set_mask), 1)
        equipment_id, bit_count = struct.unpack_from("<II", set_mask[0], 8)
        self.assertEqual((equipment_id, bit_count), (1, 0x200))
        self.assertEqual(set_mask[0][16:], log_mask_bytes(0x200, {0x098}))

    def test_configure_logs_tolerates_a_rejected_message_mask(self) -> None:
        tty = _FakeDiagTty(bit_counts={1: 0x500}, reject_f3=True)
        port = DiagPort("/dev/null", serial_factory=tty)
        port.open()
        self.assertEqual(port.configure_logs((LOG_UIM_DATA_C, LOG_UIM_DS_DATA_C)), {LOG_UIM_DATA_C, LOG_UIM_DS_DATA_C})

    def test_log_frames_read_during_a_request_are_kept_for_read_packets(self) -> None:
        early = _log_packet(LOG_UIM_DATA_C, _uim_record([("tx", b"\x00")]))
        tty = _FakeDiagTty(bit_counts={1: 0x200}, preface=hdlc_encode(early))
        port = DiagPort("/dev/null", serial_factory=tty)
        port.open()
        port.configure_logs((LOG_UIM_DATA_C,))
        self.assertEqual(port.read_packets(), [early])

    def test_log_frames_behind_the_response_in_the_same_read_are_kept(self) -> None:
        records = [
            _log_packet(LOG_UIM_DATA_C, _uim_record([("rx", bytes.fromhex("3B00"))])),
            _log_packet(LOG_UIM_DATA_C, _uim_record([("tx", bytes.fromhex("00A4000402"))])),
        ]
        tty = _FakeDiagTty(bit_counts={1: 0x200}, after_set_mask=b"".join(hdlc_encode(record) for record in records))
        port = DiagPort("/dev/null", serial_factory=tty)
        port.open()
        port.configure_logs((LOG_UIM_DATA_C,))
        self.assertEqual(port.read_packets(), records)

    def test_unanswered_request_raises_after_the_timeout(self) -> None:
        class Silent(_FakeDiagTty):
            def write(self, data: bytes) -> None:
                return None

        clock = iter(float(second) for second in range(100))
        port = DiagPort(
            "/dev/null",
            serial_factory=Silent(bit_counts={}),
            response_timeout_seconds=3.0,
            monotonic=lambda: next(clock),
        )
        port.open()
        with self.assertRaises(RuntimeError):
            port.configure_logs((LOG_UIM_DATA_C,))


class UimRecordTests(unittest.TestCase):
    def test_runs_follow_direction_changes_and_carry_the_record_stamp(self) -> None:
        record = _uim_record([("tx", bytes.fromhex("80F2000C")), ("tx", b"\x00"), ("rx", bytes.fromhex("9000"))], ticks=800)
        runs = parse_uim_record(LOG_UIM_DATA_C, record)
        self.assertEqual([(run.direction, run.data.hex()) for run in runs], [("tx", "80f2000c00"), ("rx", "9000")])
        self.assertTrue(all(abs(run.timestamp - 1.0) < 1e-9 for run in runs))

    def test_dual_sim_records_carry_the_slot(self) -> None:
        record = _uim_record([("rx", bytes.fromhex("3B00"))], slot=1)
        runs = parse_uim_record(LOG_UIM_DS_DATA_C, record)
        self.assertEqual([(run.slot, run.data.hex()) for run in runs], [(1, "3b00")])

    def test_a_record_without_entries_is_empty(self) -> None:
        self.assertEqual(parse_uim_record(LOG_UIM_DATA_C, b"\x00"), [])

    def test_decode_boundaries_raise_value_error(self) -> None:
        good = _uim_record([("tx", b"\xa4")])
        cases = {
            "empty": b"",
            "one byte claiming more": b"\x05",
            "over-claiming length": bytes((len(good),)) + good[1:],
            "truncated byte entry": b"\x01\x10",
            "truncated timestamp": b"\x05\x01\x00\x00\x00\x00",
            "unknown entry type": b"\x02\x42\x00",
        }
        for name, payload in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    parse_uim_record(LOG_UIM_DATA_C, payload)


def _usb_interface(root: str, name: str, driver: str | None, ttys: tuple[str, ...]) -> None:
    """One ``<device>:<config>.<interface>`` entry of a sysfs tree, with its driver link and ttys."""
    directory = Path(root, name)
    directory.mkdir(parents=True)
    for tty in ttys:
        Path(directory, tty).mkdir()
    if driver is not None:
        target = Path(root, "drivers", driver)
        target.mkdir(parents=True, exist_ok=True)
        Path(directory, "driver").symlink_to(target)


class AutoDeviceTests(unittest.TestCase):
    def test_takes_interface_0_of_a_modem_and_ignores_other_serial_devices(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            # Sorted ahead of the modem: a USB-serial adapter and an unbound interface 0.
            _usb_interface(root, "1-1:1.0", "ftdi_sio", ("ttyUSB1",))
            _usb_interface(root, "3-1.1:1.0", None, ("ttyUSB2",))
            _usb_interface(root, "3-1.3.2:1.0", "option", ("ttyUSB4",))
            _usb_interface(root, "3-1.3.2:1.2", "option", ("ttyUSB6",))
            self.assertEqual(find_diag_tty(root), "/dev/ttyUSB4")

    def test_a_qcserial_modem_is_found_too(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _usb_interface(root, "2-1:1.0", "qcserial", ("ttyUSB0",))
            _usb_interface(root, "2-1:1.2", "qcserial", ("ttyUSB2",))
            self.assertEqual(find_diag_tty(root), "/dev/ttyUSB0")

    def test_a_modem_interface_0_without_a_tty_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _usb_interface(root, "1-1:1.0", "option", ())
            _usb_interface(root, "1-2:1.0", "option", ("ttyUSB3",))
            self.assertEqual(find_diag_tty(root), "/dev/ttyUSB3")

    def test_nothing_attached_or_no_sysfs(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(find_diag_tty(root), "")
            _usb_interface(root, "1-1:1.0", "ftdi_sio", ("ttyUSB0",))
            self.assertEqual(find_diag_tty(root), "")
            self.assertEqual(find_diag_tty(str(Path(root, "missing"))), "")

    def test_an_explicit_device_is_kept(self) -> None:
        self.assertEqual(resolve_diag_device("/dev/serial/by-id/x-if00-port0"), "/dev/serial/by-id/x-if00-port0")


class AtrLengthTests(unittest.TestCase):
    def test_minimal_atr(self) -> None:
        self.assertEqual(atr_expected_length(bytes.fromhex("3B00")), 2)

    def test_structured_atr_counts_interface_historical_and_tck(self) -> None:
        self.assertEqual(atr_expected_length(SYNTHETIC_ATR), len(SYNTHETIC_ATR))
        self.assertEqual(len(SYNTHETIC_ATR), 12)

    def test_undecided_or_foreign_bytes(self) -> None:
        self.assertIsNone(atr_expected_length(b"\x3b"))
        self.assertIsNone(atr_expected_length(SYNTHETIC_ATR[:3]))
        self.assertIsNone(atr_expected_length(bytes.fromhex("9000")))


class T0ReassemblerTests(unittest.TestCase):
    def test_select_with_ack_null_and_get_response(self) -> None:
        observations = _feed(
            T0Reassembler(),
            ("rx", SYNTHETIC_ATR.hex(), 0.0),
            ("tx", "00A4000402", 1.0),
            ("rx", "A4", 1.01),
            ("tx", "3F00", 1.02),
            ("rx", "606136", 1.50),
            ("tx", "00C0000036", 1.60),
            ("rx", "C0" + "AB" * 0x36 + "9000", 1.70),
        )
        self.assertEqual([obs.kind for obs in observations], ["atr", "tpdu", "tpdu"])
        self.assertEqual(observations[0].response, SYNTHETIC_ATR)
        select, get_response = observations[1], observations[2]
        self.assertEqual(select.command.hex(), "00a40004023f00")
        self.assertEqual(select.response.hex(), "6136")
        self.assertEqual(select.null_bytes, 1)
        self.assertAlmostEqual(select.hold_seconds, 0.48)
        self.assertEqual(get_response.command.hex(), "00c0000036")
        self.assertEqual(get_response.response, b"\xab" * 0x36 + b"\x90\x00")

    def test_single_byte_transfers_under_the_ins_complement(self) -> None:
        observations = _feed(
            T0Reassembler(),
            ("tx", "80AA000002", None),
            ("rx", "55", None),
            ("tx", "A9", None),
            ("rx", "55", None),
            ("tx", "00", None),
            ("rx", "9000", None),
        )
        self.assertEqual([obs.kind for obs in observations], ["tpdu"])
        self.assertEqual(observations[0].command.hex(), "80aa000002a900")

    def test_status_word_without_data(self) -> None:
        observations = _feed(T0Reassembler(), ("tx", "00B0000000", None), ("rx", "6A82", None))
        self.assertEqual((observations[0].command.hex(), observations[0].response.hex()), ("00b0000000", "6a82"))

    def test_p3_zero_on_outgoing_data_means_256_bytes(self) -> None:
        observations = _feed(
            T0Reassembler(),
            ("tx", "00B0000000", None),
            ("rx", "B0" + "11" * 256 + "9000", None),
        )
        self.assertEqual(len(observations[0].response), 258)

    def test_6c_answer_and_repeated_header_are_two_exchanges(self) -> None:
        observations = _feed(
            T0Reassembler(),
            ("tx", "00B2010400", None),
            ("rx", "6C1C", None),
            ("tx", "00B201041C", None),
            ("rx", "B2" + "22" * 0x1C + "9000", None),
        )
        self.assertEqual([obs.response[-2:].hex() for obs in observations], ["6c1c", "9000"])

    def test_reset_while_the_card_holds_reports_a_cut_exchange(self) -> None:
        observations = _feed(
            T0Reassembler(),
            ("tx", "801400000C", 10.0),
            ("rx", "14", 10.01),
            ("tx", "810301260082028281830100", 10.02),
            ("rx", "606060", 11.0),
            ("rx", "3B00", 15.52),
        )
        self.assertEqual([obs.kind for obs in observations], ["cut", "atr"])
        cut = observations[0]
        self.assertEqual(cut.command[:5].hex(), "801400000c")
        self.assertEqual(cut.null_bytes, 3)
        self.assertAlmostEqual(cut.hold_seconds, 5.5)
        self.assertIn("12/12 command data bytes sent", cut.detail)
        self.assertEqual(observations[1].response.hex(), "3b00")

    def test_pps_after_the_atr_then_an_ordinary_exchange(self) -> None:
        observations = _feed(
            T0Reassembler(),
            ("rx", SYNTHETIC_ATR.hex(), None),
            ("tx", "FF109679", None),
            ("rx", "FF109679", None),
            ("tx", "80F2000C00", None),
            ("rx", "9000", None),
        )
        self.assertEqual([obs.kind for obs in observations], ["atr", "pps", "tpdu"])
        self.assertEqual(observations[1].command, observations[1].response)

    def test_idle_card_bytes_without_ts_are_stray_not_an_atr(self) -> None:
        observations = _feed(
            T0Reassembler(),
            ("rx", "9000", None),
            ("rx", "3B00", None),
            ("tx", "80F2000C00", None),
            ("rx", "9000", None),
        )
        self.assertEqual([obs.kind for obs in observations], ["stray", "atr", "tpdu"])
        self.assertEqual(observations[0].response.hex(), "9000")
        self.assertEqual(observations[1].response.hex(), "3b00")

    def test_two_resets_in_a_row_give_two_atrs(self) -> None:
        observations = _feed(T0Reassembler(), ("rx", "3B00", None), ("rx", "3B00", None))
        self.assertEqual([obs.kind for obs in observations], ["atr", "atr"])

    def test_endless_single_byte_transfers_are_cut_off(self) -> None:
        steps = [("tx", "80AA000001", None)]
        for _ in range(300):
            steps += [("rx", "55", None), ("tx", "00", None)]
        observations = _feed(T0Reassembler(), *steps)
        self.assertEqual([obs.kind for obs in observations][:1], ["stray"])
        self.assertIn("more than 256 data bytes", observations[0].detail)

    def test_a_byte_that_is_no_procedure_byte_is_reported(self) -> None:
        observations = _feed(T0Reassembler(), ("tx", "00A4000402", None), ("rx", "42", None))
        self.assertEqual([obs.kind for obs in observations], ["stray"])
        self.assertIn("42 is not a procedure byte", observations[0].detail)

    def test_terminal_byte_while_the_card_has_the_line(self) -> None:
        reassembler = T0Reassembler()
        observations = _feed(reassembler, ("tx", "00A4000402", None), ("tx", "80", None))
        self.assertEqual([obs.kind for obs in observations], ["cut"])
        self.assertEqual(reassembler.state, "header")

    def test_flush_reports_the_pending_exchange(self) -> None:
        reassembler = T0Reassembler()
        _feed(reassembler, ("tx", "8012000010", 1.0), ("rx", "6060", 1.5))
        observations = reassembler.flush("the DIAG port was lost", 3.0)
        self.assertEqual([obs.kind for obs in observations], ["cut"])
        self.assertIn("the DIAG port was lost", observations[0].detail)
        self.assertAlmostEqual(observations[0].hold_seconds, 2.0)
        self.assertEqual(reassembler.state, "idle")


class _RecordingTap:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.calls: list[tuple] = []
        self.closed = False

    def mirror_exchange(self, command: bytes, response: bytes) -> None:
        self.calls.append(("apdu", command, response))

    def send_atr(self, payload: bytes) -> None:
        self.calls.append(("atr", payload))

    def send_log(self, text: str, *, process: str, subsystem: str, level: int) -> None:
        self.calls.append(("log", text, level))

    def close(self) -> None:
        self.closed = True


class ModemSimMirrorTests(unittest.TestCase):
    def test_exchange_frames_and_notes(self) -> None:
        tap = _RecordingTap()
        mirror = ModemSimMirror(tap, hold_note_seconds=1.0)
        mirror.emit(UimObservation(kind="tpdu", command=bytes.fromhex("80F2000C00"), response=b"\x90\x00", hold_seconds=0.1))
        mirror.emit(UimObservation(kind="tpdu", command=bytes.fromhex("801000001E"), response=b"\x91\x11", null_bytes=2, hold_seconds=1.25))
        mirror.emit(UimObservation(kind="atr", response=bytes.fromhex("3B00")))
        mirror.emit(UimObservation(kind="pps", command=bytes.fromhex("FF109679"), response=bytes.fromhex("FF109679")))
        mirror.emit(UimObservation(kind="cut", command=bytes.fromhex("801400000C"), null_bytes=3, hold_seconds=5.5, detail="no status word before a new ATR; 12/12 command data bytes sent"))
        kinds = [call[0] for call in tap.calls]
        self.assertEqual(kinds, ["apdu", "apdu", "log", "atr", "log", "log"])
        self.assertIn("SW 91 11 after 1.250 s", tap.calls[2][1])
        self.assertIn("2 NULL", tap.calls[2][1])
        self.assertEqual(tap.calls[2][2], GSMTAP_LOG_LEVEL_NOTICE)
        self.assertIn("(accepted)", tap.calls[4][1])
        self.assertEqual(tap.calls[5][2], GSMTAP_LOG_LEVEL_ERROR)
        self.assertIn("5.500 s after the terminal's last byte", tap.calls[5][1])

    def test_a_failing_send_is_counted_not_raised(self) -> None:
        class RefusingTap(_RecordingTap):
            def mirror_exchange(self, command: bytes, response: bytes) -> None:
                raise OSError(101, "Network is unreachable")

        mirror = ModemSimMirror(RefusingTap())
        for _ in range(3):
            mirror.emit(UimObservation(kind="tpdu", command=bytes.fromhex("80F2000C00"), response=b"\x90\x00"))
        self.assertEqual(mirror.send_failures, 3)

    def test_notes_can_be_switched_off(self) -> None:
        tap = _RecordingTap()
        ModemSimMirror(tap, notes=False).emit(
            UimObservation(kind="tpdu", command=bytes.fromhex("801000001E"), response=b"\x91\x11", null_bytes=2)
        )
        self.assertEqual([call[0] for call in tap.calls], ["apdu"])


class GsmtapFrameTests(unittest.TestCase):
    def test_default_header_is_unchanged(self) -> None:
        packet = build_gsmtap_packet(b"\x01\x02", subtype=GSMTAP_SIM_APDU, uplink=True)
        # version 2, 4 header words, type SIM, uplink ARFCN flag, antenna 0
        self.assertEqual(packet.hex(), "02040400400000000000000000000000" + "0102")

    def test_antenna_byte(self) -> None:
        packet = build_gsmtap_packet(b"\x3b\x00", subtype=GSMTAP_SIM_ATR, antenna=1)
        self.assertEqual((packet[12], packet[13]), (GSMTAP_SIM_ATR, 1))

    def test_log_record_layout(self) -> None:
        packet = build_gsmtap_log_packet(
            "held", process="modem-diag", subsystem="UIM", level=GSMTAP_LOG_LEVEL_ERROR, timestamp=100.5, antenna=1
        )
        self.assertEqual((packet[2], packet[13]), (GSMTAP_TYPE_OSMOCORE_LOG, 1))
        log = packet[16:]
        self.assertEqual(struct.unpack_from("!II", log, 0), (100, 500000))
        self.assertEqual(log[8:24].rstrip(b"\x00"), b"modem-diag")
        self.assertEqual(log[28], GSMTAP_LOG_LEVEL_ERROR)
        self.assertEqual(log[32:48].rstrip(b"\x00"), b"UIM")
        self.assertEqual(log[84:], b"held\x00")

    def test_tap_sends_from_the_source_host_on_its_antenna(self) -> None:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.settimeout(2.0)
        receiver.bind(("127.0.0.1", 0))
        try:
            try:
                tap = GsmtapTap(port=receiver.getsockname()[1], antenna=1, source_host=MODEM_SOURCE_HOST)
            except OSError:
                self.skipTest(f"{MODEM_SOURCE_HOST} cannot be bound on this host")
            try:
                tap.mirror_exchange(bytes.fromhex("80F2000C00"), b"\x90\x00")
                data, address = receiver.recvfrom(2048)
            finally:
                tap.close()
        finally:
            receiver.close()
        self.assertEqual(address[0], MODEM_SOURCE_HOST)
        self.assertEqual(data[13], 1)
        self.assertEqual(data[16:], bytes.fromhex("80F2000C009000"))

    def test_source_host_defaults(self) -> None:
        self.assertEqual(_resolve_source_host(None, "127.0.0.1"), MODEM_SOURCE_HOST)
        self.assertEqual(_resolve_source_host(None, "192.0.2.4"), "")
        self.assertEqual(_resolve_source_host(None, "wireshark.example.test"), "")
        self.assertEqual(_resolve_source_host("", "127.0.0.1"), "")


class _FakeMirrorPort:
    def __init__(self, batches: list[list[bytes]]) -> None:
        self.batches = list(batches)
        self.is_open = False
        self.opened = 0
        self.lost = False

    def open(self) -> None:
        self.is_open = True
        self.opened += 1

    def close(self) -> None:
        self.is_open = False

    def configure_logs(self, codes: object) -> set[int]:
        return {LOG_UIM_DATA_C}

    def read_packets(self) -> list[bytes]:
        if len(self.batches) == 0:
            self.lost = True
            raise OSError("device reports readiness to read but returned no data")
        return self.batches.pop(0)

    def disable_logs(self) -> None:
        return None


class RunMirrorTests(unittest.TestCase):
    def _args(self, **overrides: object) -> Namespace:
        args = build_parser().parse_args(["--device", "/dev/serial/by-id/test-if00-port0"])
        for key, value in overrides.items():
            setattr(args, key, value)
        return args

    def test_frames_reach_the_tap_and_a_lost_port_reports_the_open_exchange(self) -> None:
        port = _FakeMirrorPort(
            [
                [_log_packet(LOG_UIM_DATA_C, _uim_record([("rx", bytes.fromhex("3B00"))], ticks=10))],
                [
                    _log_packet(LOG_UIM_DATA_C, _uim_record([("tx", bytes.fromhex("80F2000C00"))], ticks=20)),
                    _log_packet(LOG_UIM_DATA_C, _uim_record([("rx", bytes.fromhex("9000"))], ticks=30)),
                    _log_packet(LOG_UIM_DATA_C, _uim_record([("tx", bytes.fromhex("8012000010"))], ticks=40)),
                    _log_packet(0x1234, b"\x00"),
                ],
            ]
        )
        taps: list[_RecordingTap] = []

        def tap_factory(**kwargs: object) -> _RecordingTap:
            taps.append(_RecordingTap(**kwargs))
            return taps[-1]

        result = run_mirror(
            self._args(),
            port_factory=lambda device: port,
            tap_factory=tap_factory,
            sleep=lambda seconds: None,
            device_present=lambda device: True,
            should_stop=lambda: port.lost,
        )
        self.assertEqual(result, 0)
        tap = taps[0]
        self.assertEqual(tap.kwargs["antenna"], 1)
        self.assertEqual(tap.kwargs["source_host"], MODEM_SOURCE_HOST)
        self.assertEqual(
            [call[:2] for call in tap.calls[:2]],
            [("atr", bytes.fromhex("3B00")), ("apdu", bytes.fromhex("80F2000C00"))],
        )
        self.assertEqual(tap.calls[2][0], "log")
        self.assertIn("the DIAG port was lost", tap.calls[2][1])
        self.assertTrue(tap.closed)

    def test_a_build_without_the_uim_log_fails_closed(self) -> None:
        class NoUimPort(_FakeMirrorPort):
            def configure_logs(self, codes: object) -> set[int]:
                return set()

        tap = _RecordingTap()
        result = run_mirror(
            self._args(),
            port_factory=lambda device: NoUimPort([]),
            tap_factory=lambda **kwargs: tap,
            sleep=lambda seconds: None,
            device_present=lambda device: True,
        )
        self.assertEqual(result, 2)
        self.assertTrue(tap.closed)

    def test_an_unusable_source_address_fails_with_exit_code_2(self) -> None:
        def failing_tap(**kwargs: object) -> _RecordingTap:
            raise OSError(99, "Cannot assign requested address")

        result = run_mirror(
            self._args(),
            port_factory=lambda device: _FakeMirrorPort([]),
            tap_factory=failing_tap,
            sleep=lambda seconds: None,
            device_present=lambda device: True,
        )
        self.assertEqual(result, 2)

    def test_capture_path_and_compat_reach_the_tap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            capture = str(Path(directory) / "modem.pcap")
            taps: list[_RecordingTap] = []
            run_mirror(
                self._args(capture_path=capture, gsmtap_compat="wireshark44", gsmtap_host="192.0.2.4"),
                port_factory=lambda device: _FakeMirrorPort([]),
                tap_factory=lambda **kwargs: taps.append(_RecordingTap(**kwargs)) or taps[-1],
                sleep=lambda seconds: None,
                device_present=lambda device: False,
                should_stop=iter([False, True]).__next__,
            )
        self.assertEqual(taps[0].kwargs["capture_path"], capture)
        self.assertEqual(taps[0].kwargs["compat_mode"], "wireshark44")
        self.assertEqual(taps[0].kwargs["source_host"], "")


if __name__ == "__main__":
    unittest.main()
