# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tenth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-10 closes the following:

* ETSI TS 102 222 §6.3 CREATE FILE (`INS 0xE0`) and §6.4 RESIZE
  FILE (`INS 0xD4`). Both are admin commands gated behind an
  authenticated SCP03 session. CREATE FILE accepts a TS 102 221
  §11.1.1.4 FCP TLV (root tag ``62``) and supports transparent
  EFs, linear-fixed EFs and cyclic EFs.
* ETSI TS 102 223 §6.4.36 SET FRAMES (proactive type ``0x60``)
  and §6.4.37 GET FRAMES STATUS (``0x61``). The TR-side latch
  caches the negotiated frame layout and the Frames Information
  TLV (``49`` / ``C9``) into ``state.toolkit``.
* ETSI TS 102 223 §7.4.20 Contactless State Request (event
  ``0x16``) plus 3GPP TS 31.111 §7.5.16 IMS Registration (event
  ``0x18``) and §7.5.17 IMS Incoming Data (event ``0x19``)
  decoders. All three latch into ``state.toolkit``.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    GET_FRAMES_STATUS_COMMAND,
    SET_FRAMES_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import tlv


def _terminal_response(
    *,
    command_number: int,
    command_type: int,
    qualifier: int,
    extra: bytes = b"",
    result_code: int = 0x00,
) -> bytes:
    return (
        tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, qualifier & 0xFF)))
        + tlv("82", bytes((0x82, 0x81)))
        + tlv("83", bytes((result_code & 0xFF,)))
        + bytes(extra or b"")
    )


class _AdminEngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        root = Path(self._td.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(root / "missing_quirks.py"),
            isdr_config_path=str(root / "missing_isdr.json"),
            sim_eim_identity_path=str(root / "missing_eim_identity.json"),
            euicc_store_root=str(root / "euicc"),
            profile_store_path=str(root / "profile_store"),
        )
        self.engine.state.scp03_session.authenticated = True

    def tearDown(self) -> None:
        self._td.cleanup()

    def _select_mf(self) -> None:
        apdu = bytes.fromhex("00A40004023F00")
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class CreateFileTests(_AdminEngineHarness):
    """ETSI TS 102 222 §6.3 CREATE FILE."""

    def _create_transparent(self, fid: str, size: int) -> tuple[bytes, int, int]:
        descriptor = bytes((0x82, 0x02, 0x01, 0x21))
        fid_tlv = bytes((0x83, 0x02)) + bytes.fromhex(fid)
        size_tlv = bytes((0x80, 0x02)) + size.to_bytes(2, "big")
        fcp_body = descriptor + fid_tlv + size_tlv
        body = bytes((0x62, len(fcp_body))) + fcp_body
        apdu = bytes([0x00, 0xE0, 0x00, 0x00, len(body)]) + body
        return self.engine.transmit(apdu)

    def test_create_transparent_ef_under_mf(self) -> None:
        self._select_mf()
        _data, sw1, sw2 = self._create_transparent("7777", 16)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertIn("7777", self.engine.state.nodes)
        new_node = self.engine.state.nodes["7777"]
        self.assertEqual(new_node.kind, "ef")
        self.assertEqual(new_node.structure, "transparent")
        self.assertEqual(len(new_node.data), 16)
        self.assertTrue(all(byte == 0xFF for byte in new_node.data))

    def test_create_file_rejected_without_scp03(self) -> None:
        self.engine.state.scp03_session.authenticated = False
        self._select_mf()
        descriptor = bytes((0x82, 0x02, 0x01, 0x21))
        fid_tlv = bytes((0x83, 0x02, 0x99, 0x99))
        size_tlv = bytes((0x80, 0x02, 0x00, 0x10))
        fcp_body = descriptor + fid_tlv + size_tlv
        body = bytes((0x62, len(fcp_body))) + fcp_body
        apdu = bytes([0x00, 0xE0, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x69, 0x82))

    def test_create_file_duplicate_fid_returns_6a89(self) -> None:
        self._select_mf()
        _, sw1, sw2 = self._create_transparent("7771", 8)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _, sw1, sw2 = self._create_transparent("7771", 8)
        self.assertEqual((sw1, sw2), (0x6A, 0x89))

    def test_create_file_malformed_fcp_returns_6a80(self) -> None:
        self._select_mf()
        # Empty body / bad root tag.
        _, sw1, sw2 = self.engine.transmit(bytes.fromhex("00E0000001AA"))
        self.assertEqual((sw1, sw2), (0x6A, 0x80))

    def test_create_linear_fixed_ef_with_records(self) -> None:
        self._select_mf()
        # File descriptor: 0x02 linear-fixed, 0x21 0x21 padding,
        # record length = 0x10, record count = 0x04.
        descriptor = bytes((0x82, 0x06, 0x02, 0x21, 0x21, 0x00, 0x10, 0x04))
        fid_tlv = bytes((0x83, 0x02, 0x77, 0x73))
        size_tlv = bytes((0x80, 0x02, 0x00, 0x40))
        fcp_body = descriptor + fid_tlv + size_tlv
        body = bytes((0x62, len(fcp_body))) + fcp_body
        apdu = bytes([0x00, 0xE0, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        node = self.engine.state.nodes["7773"]
        self.assertEqual(node.structure, "linear-fixed")
        self.assertEqual(len(node.records), 4)
        self.assertEqual(node.record_length, 16)


class ResizeFileTests(_AdminEngineHarness):
    """ETSI TS 102 222 §6.4 RESIZE FILE."""

    def setUp(self) -> None:
        super().setUp()
        self._select_mf()
        descriptor = bytes((0x82, 0x02, 0x01, 0x21))
        fid_tlv = bytes((0x83, 0x02, 0x77, 0x80))
        size_tlv = bytes((0x80, 0x02, 0x00, 0x10))
        fcp_body = descriptor + fid_tlv + size_tlv
        body = bytes((0x62, len(fcp_body))) + fcp_body
        apdu = bytes([0x00, 0xE0, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_resize_grow_pads_with_ff(self) -> None:
        body = bytes.fromhex("83027780") + bytes.fromhex("80020030")
        apdu = bytes([0x00, 0xD4, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        node = self.engine.state.nodes["7780"]
        self.assertEqual(len(node.data), 0x30)
        self.assertEqual(node.data[-16:], b"\xFF" * 16)

    def test_resize_shrink_truncates(self) -> None:
        body = bytes.fromhex("83027780") + bytes.fromhex("80020008")
        apdu = bytes([0x00, 0xD4, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        node = self.engine.state.nodes["7780"]
        self.assertEqual(len(node.data), 0x08)

    def test_resize_unknown_fid_falls_back_to_current_ef(self) -> None:
        # Selecting the EF first puts it as current; resize without
        # tag 83 then targets the current node.
        select = bytes.fromhex("00A40004027780")
        _, sw1, sw2 = self.engine.transmit(select)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        body = bytes.fromhex("80020020")
        apdu = bytes([0x00, 0xD4, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        node = self.engine.state.nodes["7780"]
        self.assertEqual(len(node.data), 0x20)


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


class SetFramesTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.36 SET FRAMES (proactive 0x60)."""

    def test_set_frames_caches_layout_and_default_id(self) -> None:
        layout = bytes.fromhex("00010A0F")
        result = self.toolkit.queue_set_frames(
            frame_identifier=0x01,
            frame_layout=layout,
            default_frame_identifier=0x01,
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SET_FRAMES_COMMAND,
            qualifier=0x00,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_set_frames_layout, layout)
        self.assertEqual(self.state.toolkit.last_set_frames_default_id, 0x01)

    def test_set_frames_failure_leaves_cache_untouched(self) -> None:
        self.state.toolkit.last_set_frames_layout = b"\xAA"
        result = self.toolkit.queue_set_frames(
            frame_identifier=0x02,
            frame_layout=bytes.fromhex("00020A0F"),
            default_frame_identifier=0x02,
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SET_FRAMES_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_set_frames_layout, b"\xAA")

    def test_empty_layout_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.toolkit.queue_set_frames(
                frame_identifier=0x00,
                frame_layout=b"",
            )


class GetFramesStatusTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.37 GET FRAMES STATUS (proactive 0x61)."""

    def test_get_frames_status_latches_information_blob(self) -> None:
        result = self.toolkit.queue_get_frames_status()
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        info = bytes.fromhex("0201020F")
        tr = _terminal_response(
            command_number=cmd,
            command_type=GET_FRAMES_STATUS_COMMAND,
            qualifier=0x00,
            extra=tlv("49", info),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_frames_information, info)

    def test_failed_status_keeps_previous_value(self) -> None:
        self.state.toolkit.last_frames_information = b"\xCC\xCC"
        result = self.toolkit.queue_get_frames_status()
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=GET_FRAMES_STATUS_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_frames_information, b"\xCC\xCC")


class EventDownloadGap10Tests(_ToolkitHarness):
    """Round-10 event-download decoders (Contactless / IMS)."""

    def _envelope(self, *body: bytes) -> bytes:
        joined = b"".join(body)
        return bytes((0xD6, len(joined))) + joined

    def _fallback(self, payload: bytes) -> tuple[bytes, int, int]:
        del payload
        return b"", 0x90, 0x00

    def test_contactless_state_request_activate(self) -> None:
        envelope = self._envelope(
            tlv("99", b"\x16"),
            tlv("40", b"\x80"),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertTrue(self.state.toolkit.contactless_active)
        self.assertEqual(self.state.toolkit.last_event_code, 0x16)

    def test_contactless_state_request_deactivate(self) -> None:
        self.state.toolkit.contactless_active = True
        envelope = self._envelope(
            tlv("99", b"\x16"),
            tlv("40", b"\x00"),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertFalse(self.state.toolkit.contactless_active)

    def test_ims_registration_event_sets_status_and_payload(self) -> None:
        uri = b"sip:user@example.com"
        envelope = self._envelope(
            tlv("99", b"\x18"),
            tlv("B9", b"\x01"),
            tlv("BA", uri),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertTrue(self.state.toolkit.ims_registered)
        self.assertEqual(self.state.toolkit.last_ims_event_data, uri)

    def test_ims_registration_deregister_clears_flag(self) -> None:
        self.state.toolkit.ims_registered = True
        envelope = self._envelope(
            tlv("99", b"\x18"),
            tlv("B9", b"\x00"),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertFalse(self.state.toolkit.ims_registered)

    def test_ims_incoming_data_caches_payload(self) -> None:
        payload = bytes.fromhex("4D45535341474520626F6479")
        envelope = self._envelope(
            tlv("99", b"\x19"),
            tlv("BA", payload),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.last_ims_event_data, payload)
        self.assertEqual(self.state.toolkit.last_event_code, 0x19)


if __name__ == "__main__":
    unittest.main()
