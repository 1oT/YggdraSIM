"""Seventeenth-pass gap-coverage suite for SIMCARD event-download surfaces.

Round-17 wires up the following spec-anchored event downloads that
were parsed but never reached the apply layer:

* ETSI TS 102 223 §7.4.4 ``Location Status`` event (code ``0x03``).
  TLV ``0x9B`` carries a 1-byte status (0=normal, 1=limited, 2=no
  service) -- the simulator latches the latest reading and a
  monotonic transition counter.
* ETSI TS 102 223 §7.4.7 ``Card Reader Status`` event (code
  ``0x06``). TLV ``0xA0`` packs reader-present / powered flags +
  reader id; the simulator caches both halves and bumps a counter.
* ETSI TS 102 223 §7.4.10 ``Data Available`` event reused under
  the simulator's existing ``0x09`` slot. The TLV ``0x37`` Channel
  Data Length and TLV ``0x38`` Channel Status are latched without
  disturbing the existing browser-termination-cause path.
* ETSI TS 102 223 §7.4.16 ``Frames Information Change`` event
  (code ``0x10``). TLV ``0x49`` carries the new frames layout; the
  simulator stashes the blob into ``last_frames_information`` and
  bumps a transition counter.
"""

from __future__ import annotations

import os
import tempfile
import unittest

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.state import SimCardState
from SIMCARD.toolkit import ToolkitLogic
from SIMCARD.utils import tlv


def _envelope(*body: bytes) -> bytes:
    joined = b"".join(body)
    return bytes((0xD6, len(joined))) + joined


def _fallback(payload: bytes) -> tuple[bytes, int, int]:
    del payload
    return b"", 0x90, 0x00


class _ToolkitHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.state = SimCardState(
            atr=b"",
            eid="89049032123451234512345678901234",
            iccid="8949000000000000001",
            imsi="999990000000001",
            default_dp_address="",
            root_ci_pkid=b"",
        )
        self.toolkit = ToolkitLogic(self.state)
        self._td = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self._td.cleanup()


class LocationStatusEventTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.4.4 Location Status Event (0x03)."""

    def test_normal_service_latches_zero(self) -> None:
        envelope = _envelope(
            tlv("99", b"\x03"),
            tlv("9B", b"\x00"),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_event_code, 0x03)
        self.assertEqual(toolkit.last_location_status, 0x00)
        self.assertEqual(toolkit.location_status_changes, 1)

    def test_limited_to_no_service_increments_counter(self) -> None:
        first = _envelope(tlv("99", b"\x03"), tlv("9B", b"\x01"))
        self.toolkit.handle_envelope(first, _fallback)
        second = _envelope(tlv("99", b"\x03"), tlv("9B", b"\x02"))
        self.toolkit.handle_envelope(second, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_location_status, 0x02)
        self.assertEqual(toolkit.location_status_changes, 2)

    def test_repeated_value_still_bumps_counter(self) -> None:
        # The counter is "events received" semantics, mirroring
        # display_parameters_changes / access_technology_changes:
        # repeated readings still record the fact that the network
        # reasserted the status.
        envelope = _envelope(tlv("99", b"\x03"), tlv("9B", b"\x01"))
        self.toolkit.handle_envelope(envelope, _fallback)
        self.toolkit.handle_envelope(envelope, _fallback)
        self.assertEqual(self.state.toolkit.location_status_changes, 2)


class CardReaderStatusEventTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.4.7 Card Reader Status Event (0x06)."""

    def test_card_present_powered_reader_two(self) -> None:
        # Bit 7 = present, bit 6 = powered, bits 0..3 = reader id 2.
        status_byte = bytes((0xC0 | 0x02,))
        envelope = _envelope(
            tlv("99", b"\x06"),
            tlv("A0", status_byte),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_event_code, 0x06)
        self.assertEqual(toolkit.last_card_reader_status, 0xC2)
        self.assertEqual(toolkit.last_card_reader_id, 2)
        self.assertEqual(toolkit.card_reader_status_events, 1)

    def test_card_eject_resets_present_flag(self) -> None:
        present = _envelope(tlv("99", b"\x06"), tlv("A0", b"\xC1"))
        self.toolkit.handle_envelope(present, _fallback)
        ejected = _envelope(tlv("99", b"\x06"), tlv("A0", b"\x01"))
        self.toolkit.handle_envelope(ejected, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_card_reader_status, 0x01)
        self.assertEqual(toolkit.last_card_reader_id, 1)
        self.assertEqual(toolkit.card_reader_status_events, 2)


class DataAvailableEventTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.4.10 Data Available Event under 0x09."""

    def test_channel_length_latches_and_counter_bumps(self) -> None:
        envelope = _envelope(
            tlv("99", b"\x09"),
            tlv("38", b"\x81\x00"),
            tlv("37", b"\x40"),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_event_code, 0x09)
        self.assertEqual(toolkit.last_data_available_channel_length, 0x40)
        self.assertEqual(toolkit.last_data_available_channel_status, b"\x81\x00")
        self.assertEqual(toolkit.data_available_events, 1)

    def test_browser_termination_path_still_works(self) -> None:
        envelope = _envelope(
            tlv("99", b"\x09"),
            tlv("34", b"\x01"),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_browser_termination_cause, 0x01)
        self.assertEqual(toolkit.data_available_events, 0)

    def test_combined_envelope_latches_both_paths(self) -> None:
        envelope = _envelope(
            tlv("99", b"\x09"),
            tlv("34", b"\x00"),
            tlv("37", b"\x10"),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_browser_termination_cause, 0x00)
        self.assertEqual(toolkit.last_data_available_channel_length, 0x10)
        self.assertEqual(toolkit.data_available_events, 1)


class FramesInformationChangeEventTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.4.16 Frames Information Change Event (0x10)."""

    def test_layout_blob_latches_and_counter_bumps(self) -> None:
        layout = b"\x02\x10\x08\x10\x18"
        envelope = _envelope(
            tlv("99", b"\x10"),
            tlv("49", layout),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_event_code, 0x10)
        self.assertEqual(toolkit.last_frames_information, layout)
        self.assertEqual(toolkit.frames_information_changes, 1)

    def test_repeated_event_increments_counter(self) -> None:
        layout_a = b"\x02\x10\x08\x10\x18"
        layout_b = b"\x03\x10\x08\x10\x18\x20\x18"
        first = _envelope(tlv("99", b"\x10"), tlv("49", layout_a))
        second = _envelope(tlv("99", b"\x10"), tlv("49", layout_b))
        self.toolkit.handle_envelope(first, _fallback)
        self.toolkit.handle_envelope(second, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_frames_information, layout_b)
        self.assertEqual(toolkit.frames_information_changes, 2)

    def test_event_without_payload_still_bumps_counter(self) -> None:
        envelope = _envelope(tlv("99", b"\x10"))
        self.toolkit.handle_envelope(envelope, _fallback)
        self.assertEqual(self.state.toolkit.frames_information_changes, 1)


if __name__ == "__main__":
    unittest.main()
