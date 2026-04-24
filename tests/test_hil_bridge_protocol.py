from __future__ import annotations

import os
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from Tools.HilBridge.protocol import (
    GSMTAP_ARFCN_F_UPLINK,
    GSMTAP_COMPAT_WIRESHARK44,
    GSMTAP_HDR_LEN_WORDS,
    GSMTAP_SIM_APDU,
    GSMTAP_TYPE_SIM,
    GSMTAP_VERSION,
    GsmtapPcapWriter,
    GsmtapTap,
    IPA_EXT_RSPRO,
    IPA_MSGT_PONG,
    IPA_PROTO_CCM,
    IPA_PROTO_OSMO,
    build_simtrace_apdu_payload,
    IpaFrameParser,
    build_gsmtap_packet,
    build_ipa_frame,
    build_ipa_pong,
    build_ip_choice,
    build_pcap_global_header,
)


class _FakeSocket:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def close(self) -> None:
        return

    def sendto(self, packet: bytes, address: tuple[str, int]) -> None:
        self.sent.append((packet, address))


class HilBridgeProtocolTests(unittest.TestCase):
    def test_ipa_parser_reassembles_fragmented_extended_frame(self) -> None:
        parser = IpaFrameParser()
        frame = build_ipa_frame(IPA_PROTO_OSMO, b"\x30\x00\xAA", ext=IPA_EXT_RSPRO)

        self.assertEqual(parser.feed(frame[:2]), [])
        self.assertEqual(parser.feed(frame[2:5]), [])

        frames = parser.feed(frame[5:])
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].proto, IPA_PROTO_OSMO)
        self.assertEqual(frames[0].ext, IPA_EXT_RSPRO)
        self.assertEqual(frames[0].payload, b"\x30\x00\xAA")

    def test_ipa_parser_handles_back_to_back_frames(self) -> None:
        parser = IpaFrameParser()
        combined = build_ipa_pong() + build_ipa_frame(IPA_PROTO_OSMO, b"ABC", ext=IPA_EXT_RSPRO)

        frames = parser.feed(combined)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0].proto, IPA_PROTO_CCM)
        self.assertEqual(frames[0].ext, IPA_MSGT_PONG)
        self.assertEqual(frames[0].payload, b"")
        self.assertEqual(frames[1].proto, IPA_PROTO_OSMO)
        self.assertEqual(frames[1].ext, IPA_EXT_RSPRO)
        self.assertEqual(frames[1].payload, b"ABC")

    def test_build_gsmtap_packet_uses_v2_sim_header(self) -> None:
        packet = build_gsmtap_packet(b"\x00\xA4\x04\x00", subtype=GSMTAP_SIM_APDU, uplink=True)
        self.assertEqual(len(packet), 20)

        header = packet[:16]
        payload = packet[16:]
        unpacked = struct.unpack("!BBBBHbbIBBBB", header)

        self.assertEqual(unpacked[0], GSMTAP_VERSION)
        self.assertEqual(unpacked[1], GSMTAP_HDR_LEN_WORDS)
        self.assertEqual(unpacked[2], GSMTAP_TYPE_SIM)
        self.assertEqual(unpacked[4], GSMTAP_ARFCN_F_UPLINK)
        self.assertEqual(unpacked[8], GSMTAP_SIM_APDU)
        self.assertEqual(payload, b"\x00\xA4\x04\x00")

    def test_build_simtrace_apdu_payload_concatenates_command_and_response(self) -> None:
        payload = build_simtrace_apdu_payload(b"\x00\xA4\x04\x00", b"\x61\x19")
        self.assertEqual(payload, b"\x00\xA4\x04\x00\x61\x19")

    def test_gsmtap_native_mode_emits_single_combined_packet(self) -> None:
        tap = GsmtapTap(enabled=False)
        fake_socket = _FakeSocket()
        tap._socket = fake_socket

        tap.mirror_exchange(b"\x00\xA4\x04\x00", b"\x61\x19")

        self.assertEqual(len(fake_socket.sent), 1)
        packet, address = fake_socket.sent[0]
        self.assertEqual(address, ("127.0.0.1", 4729))
        unpacked = struct.unpack("!BBBBHbbIBBBB", packet[:16])
        self.assertEqual(unpacked[0], GSMTAP_VERSION)
        self.assertEqual(unpacked[1], GSMTAP_HDR_LEN_WORDS)
        self.assertEqual(unpacked[2], GSMTAP_TYPE_SIM)
        self.assertEqual(unpacked[4], GSMTAP_ARFCN_F_UPLINK)
        self.assertEqual(unpacked[8], GSMTAP_SIM_APDU)
        self.assertEqual(packet[16:], b"\x00\xA4\x04\x00\x61\x19")

    def test_gsmtap_wireshark44_mode_emits_single_combined_packet(self) -> None:
        tap = GsmtapTap(enabled=False, compat_mode=GSMTAP_COMPAT_WIRESHARK44)
        fake_socket = _FakeSocket()
        tap._socket = fake_socket

        tap.mirror_exchange(b"\x00\xA4\x04\x00", b"\x61\x19")
        tap.send_atr(b"\x3B\x00")

        self.assertEqual(len(fake_socket.sent), 1)
        packet, address = fake_socket.sent[0]
        self.assertEqual(address, ("127.0.0.1", 4729))
        unpacked = struct.unpack("!BBBBHbbIBBBB", packet[:16])
        self.assertEqual(unpacked[0], GSMTAP_VERSION)
        self.assertEqual(unpacked[1], GSMTAP_HDR_LEN_WORDS)
        self.assertEqual(unpacked[2], GSMTAP_TYPE_SIM)
        self.assertEqual(unpacked[4], GSMTAP_ARFCN_F_UPLINK)
        self.assertEqual(unpacked[8], GSMTAP_SIM_APDU)
        self.assertEqual(packet[16:], b"\x00\xA4\x04\x00\x61\x19")

    def test_gsmtap_capture_path_writes_pcap_with_udp_wrapped_packet(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            tap = GsmtapTap(enabled=False, capture_path=str(capture_path))
            tap.mirror_exchange(b"\x00\xA4\x04\x00", b"\x61\x19")
            tap.close()

            payload = capture_path.read_bytes()

        self.assertGreaterEqual(len(payload), 40)
        magic, major, minor, _tz, _sigfigs, snaplen, linktype = struct.unpack("<IHHIIII", payload[:24])
        self.assertEqual(magic, 0xA1B2C3D4)
        self.assertEqual((major, minor), (2, 4))
        self.assertEqual(snaplen, 65535)
        self.assertEqual(linktype, 1)

        _ts_sec, _ts_usec, incl_len, orig_len = struct.unpack("<IIII", payload[24:40])
        self.assertEqual(incl_len, orig_len)
        frame = payload[40 : 40 + incl_len]
        self.assertEqual(frame[12:14], b"\x08\x00")
        expected_packet = build_gsmtap_packet(
            build_simtrace_apdu_payload(b"\x00\xA4\x04\x00", b"\x61\x19"),
            subtype=GSMTAP_SIM_APDU,
            uplink=True,
        )
        self.assertEqual(frame[-len(expected_packet) :], expected_packet)

    def test_gsmtap_pcap_writer_mirrors_header_and_record_into_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            fifo_path = Path(temp_dir) / "live_capture.fifo"
            os.mkfifo(str(fifo_path))

            collected_bytes = bytearray()
            reader_done = threading.Event()

            def reader_thread() -> None:
                try:
                    with open(str(fifo_path), "rb") as stream:
                        while True:
                            chunk = stream.read(4096)
                            if chunk is None or len(chunk) == 0:
                                break
                            collected_bytes.extend(chunk)
                finally:
                    reader_done.set()

            reader = threading.Thread(target=reader_thread, daemon=True)
            reader.start()

            writer = GsmtapPcapWriter(
                path=str(capture_path),
                mirror_fifo_path=str(fifo_path),
            )
            payload = build_gsmtap_packet(
                build_simtrace_apdu_payload(b"\x00\xA4\x04\x00", b"\x61\x19"),
                subtype=GSMTAP_SIM_APDU,
                uplink=True,
            )
            writer.write_gsmtap_packet(payload, timestamp=1_700_000_000.123456)
            writer.write_gsmtap_packet(payload, timestamp=1_700_000_000.234567)
            writer.close()

            reader.join(timeout=2.0)
            self.assertTrue(reader_done.is_set())

        self.assertGreaterEqual(len(collected_bytes), 24 + 16 + 1)
        mirrored_header = bytes(collected_bytes[:24])
        self.assertEqual(mirrored_header, build_pcap_global_header())
        magic, major, minor, _tz, _sigfigs, snaplen, linktype = struct.unpack(
            "<IHHIIII",
            mirrored_header,
        )
        self.assertEqual(magic, 0xA1B2C3D4)
        self.assertEqual((major, minor), (2, 4))
        self.assertEqual(snaplen, 65535)
        self.assertEqual(linktype, 1)

        first_record_header = bytes(collected_bytes[24:40])
        _ts_sec, _ts_usec, incl_len, orig_len = struct.unpack("<IIII", first_record_header)
        self.assertEqual(incl_len, orig_len)
        self.assertGreater(incl_len, 0)

    def test_gsmtap_pcap_writer_survives_missing_fifo_reader(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            fifo_path = Path(temp_dir) / "live_capture.fifo"
            os.mkfifo(str(fifo_path))

            writer = GsmtapPcapWriter(
                path=str(capture_path),
                mirror_fifo_path=str(fifo_path),
            )
            payload = build_gsmtap_packet(
                build_simtrace_apdu_payload(b"\x00\xA4\x04\x00", b"\x61\x19"),
                subtype=GSMTAP_SIM_APDU,
                uplink=True,
            )
            writer.write_gsmtap_packet(payload, timestamp=1_700_000_000.111111)
            writer.write_gsmtap_packet(payload, timestamp=1_700_000_000.222222)
            writer.close()

            captured_bytes = capture_path.read_bytes()

        self.assertEqual(captured_bytes[:4], b"\xD4\xC3\xB2\xA1")
        self.assertGreater(len(captured_bytes), 24)

    def test_build_ip_choice_encodes_ipv4_and_ipv6(self) -> None:
        ipv4_choice = build_ip_choice("127.0.0.1")
        ipv6_choice = build_ip_choice("::1")

        self.assertEqual(ipv4_choice, ("ipv4", b"\x7F\x00\x00\x01"))
        self.assertEqual(ipv6_choice[0], "ipv6")
        self.assertEqual(len(ipv6_choice[1]), 16)


if __name__ == "__main__":
    unittest.main()
