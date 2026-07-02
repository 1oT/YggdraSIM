# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ETSI TS 102 223 §6.4.27 .. §6.4.31 BIP queueables.

Verifies the simulator-side BIP command queueables (OPEN CHANNEL,
CLOSE CHANNEL, SEND DATA, RECEIVE DATA, GET CHANNEL STATUS) emit
parseable proactive commands, drive the bookkeeping in
``state.toolkit`` correctly when the modem responds via TERMINAL
RESPONSE, and update the open-channel state on event downloads.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.toolkit import (
    CLOSE_CHANNEL_COMMAND,
    GET_CHANNEL_STATUS_COMMAND,
    OPEN_CHANNEL_COMMAND,
    RECEIVE_DATA_COMMAND,
    SEND_DATA_COMMAND,
)


def _make_engine() -> SimulatedSimCardEngine:
    td = tempfile.mkdtemp()
    store_root = Path(td) / "simcard"
    store_root.mkdir(parents=True, exist_ok=True)
    (store_root / "euicc").mkdir(parents=True, exist_ok=True)
    profile_store = store_root / "profile_store"
    profile_store.mkdir(parents=True, exist_ok=True)
    return SimulatedSimCardEngine(
        euicc_store_root=str(store_root),
        profile_store_path=str(profile_store),
    )


def _last_queued(engine: SimulatedSimCardEngine) -> bytes:
    queue = engine.state.pending_fetch_queue
    return bytes(queue[-1]) if len(queue) > 0 else b""


def _parse(engine: SimulatedSimCardEngine, payload: bytes) -> dict:
    return engine.toolkit._parse_proactive_command(payload)


class OpenChannelEmitsAllRequiredTLVs(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()

    def test_default_tcp_client_remote_open_channel_round_trip(self) -> None:
        result = self.engine.toolkit.queue_open_channel(
            remote_address="192.0.2.42",
            remote_port=8443,
            transport_protocol_type=0x02,
            network_access_name="iot.example.com",
            buffer_size=0x0400,
        )
        self.assertEqual(result["mode"], "open-channel")
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], OPEN_CHANNEL_COMMAND)
        self.assertEqual(parsed["qualifier"], 0x00)
        self.assertEqual(parsed["transport_protocol_type"], 0x02)
        self.assertEqual(parsed["transport_port"], 8443)
        self.assertEqual(parsed["remote_address"], "192.0.2.42")
        self.assertEqual(parsed["network_access_name"], "iot.example.com")
        self.assertEqual(parsed["buffer_size"], 0x0400)

    def test_immediate_qualifier_bit_is_set(self) -> None:
        self.engine.toolkit.queue_open_channel(
            remote_address="192.0.2.1",
            remote_port=443,
            transport_protocol_type=0x02,
            immediate=True,
        )
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["qualifier"] & 0x01, 0x01)

    def test_automatic_reconnect_qualifier_bit_is_set(self) -> None:
        # ETSI TS 102 223 §6.4.27 Table 6.40: OPEN CHANNEL qualifier
        # bit b2 (mask 0x02) is "automatic reconnection". Earlier
        # simulator builds incorrectly used bit b8 (0x80); the real
        # bit is b2 and the reference modem trace confirms it.
        self.engine.toolkit.queue_open_channel(
            remote_address="192.0.2.1",
            remote_port=443,
            transport_protocol_type=0x02,
            automatic_reconnect=True,
        )
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["qualifier"] & 0x02, 0x02)


class CloseAndStatusBuildersAreSpecCompliant(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()

    def test_close_channel_minimal_envelope(self) -> None:
        self.engine.toolkit.queue_close_channel()
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], CLOSE_CHANNEL_COMMAND)
        self.assertEqual(parsed["qualifier"], 0x00)

    def test_get_channel_status_minimal_envelope(self) -> None:
        self.engine.toolkit.queue_get_channel_status()
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], GET_CHANNEL_STATUS_COMMAND)
        self.assertEqual(parsed["qualifier"], 0x00)


class SendDataAndReceiveDataAreSpecCompliant(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()

    def test_send_data_immediate_includes_payload_under_36(self) -> None:
        payload = bytes.fromhex("DEADBEEFCAFE")
        self.engine.toolkit.queue_send_data(payload, immediate=True)
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], SEND_DATA_COMMAND)
        self.assertEqual(parsed["qualifier"], 0x01)
        self.assertEqual(bytes(parsed["channel_data"]), payload)

    def test_send_data_buffered_clears_qualifier_bit_zero(self) -> None:
        self.engine.toolkit.queue_send_data(b"\x00\x01\x02", immediate=False)
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["qualifier"], 0x00)

    def test_receive_data_clamps_request_length_to_byte(self) -> None:
        self.engine.toolkit.queue_receive_data(0x1234)
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], RECEIVE_DATA_COMMAND)
        self.assertEqual(parsed["channel_length"], 0xFF)


class TerminalResponsesUpdateOpenChannelBookkeeping(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()
        self.engine.transmit(bytes.fromhex("8010000003010203"))
        self.engine.state.pending_fetch_queue.clear()
        self.engine.state.toolkit.active_proactive_command = b""

    def _drain_proactive(self, command: bytes) -> dict:
        self.engine.toolkit._enqueue_command(command)
        _, sw1, sw2 = self.engine.transmit(bytes.fromhex("80F2000000"))
        self.assertEqual(sw1, 0x91)
        data, sw1, sw2 = self.engine.transmit(bytes([0x80, 0x12, 0x00, 0x00, sw2]))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return _parse(self.engine, data)

    def test_open_channel_success_terminal_response_records_endpoint(self) -> None:
        self.engine.toolkit.queue_open_channel(
            remote_address="192.0.2.10",
            remote_port=4443,
            transport_protocol_type=0x02,
        )
        parsed = self._drain_proactive(self.engine.state.pending_fetch_queue.pop(0))
        details = bytes(parsed["command_details_tlv"])
        # Result success (0x00) + Channel Status (channel 1 active, 0x00) wrapped under 0x38.
        body = (
            details
            + bytes.fromhex("82028281")
            + bytes.fromhex("030100")
            + bytes.fromhex("38028100")
        )
        terminal_response = bytes([0x80, 0x14, 0x00, 0x00, len(body)]) + body
        _, sw1, _ = self.engine.transmit(terminal_response)
        self.assertEqual(sw1, 0x90)
        self.assertTrue(self.engine.state.toolkit.open_channel_active)
        self.assertEqual(
            self.engine.state.toolkit.open_channel_endpoint,
            "192.0.2.10:4443",
        )

    def test_close_channel_terminal_response_clears_open_state(self) -> None:
        self.engine.state.toolkit.open_channel_active = True
        self.engine.state.toolkit.open_channel_endpoint = "192.0.2.1:443"
        self.engine.toolkit.queue_close_channel()
        parsed = self._drain_proactive(self.engine.state.pending_fetch_queue.pop(0))
        details = bytes(parsed["command_details_tlv"])
        body = (
            details
            + bytes.fromhex("82028281")
            + bytes.fromhex("030100")
        )
        terminal_response = bytes([0x80, 0x14, 0x00, 0x00, len(body)]) + body
        self.engine.transmit(terminal_response)
        self.assertFalse(self.engine.state.toolkit.open_channel_active)
        self.assertEqual(self.engine.state.toolkit.open_channel_endpoint, "")

    def test_event_download_data_available_drives_open_channel_flag(self) -> None:
        # ENVELOPE: D6 ... 99 01 09 (DATA-AVAILABLE) + 38 02 81 00 + 37 01 04
        envelope_body = (
            bytes.fromhex("99010A")
            + bytes.fromhex("38028100")
            + bytes.fromhex("370104")
        )
        envelope = (
            bytes([0x80, 0xC2, 0x00, 0x00, len(envelope_body) + 2])
            + bytes.fromhex("D6") + bytes((len(envelope_body),)) + envelope_body
        )
        self.engine.transmit(envelope)
        self.assertTrue(self.engine.state.toolkit.open_channel_active)


if __name__ == "__main__":
    unittest.main()
