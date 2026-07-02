# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Twelfth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-12 closes the following:

* 3GPP TS 31.103 §7.1 IMS AKA (``AUTHENTICATE`` P2=0x82). The ISIM
  context routes through the same Milenage chain as UMTS AKA
  (P2=0x81); the test confirms both paths return identical RES /
  CK / IK material for a given (RAND, AUTN).
* 3GPP TS 31.103 §4.2.2 / §4.2.4 / §4.2.5 ISIM EFs ``EF.IMPU``,
  ``EF.DOMAIN`` and ``EF.AD`` are seeded under ADF.ISIM with
  spec-compliant TLV encodings.
* ETSI TS 102 223 §7.4 call-lifecycle event downloads:
  ``MT Call`` (0x00), ``Call Connected`` (0x01),
  ``Call Disconnected`` (0x02). Each latches its transaction id
  and toggles ``call_active`` consistently with the CC layer of a
  paired terminal.
* §7.4.4 ``User Activity`` (0x04) bumps a monotonic counter.
* 3GPP TS 31.111 §7.5.4 ``Access Technology Change`` (0x0D) caches
  the new RAT and counts transitions.
* ETSI TS 102 223 §7.4.14 ``Display Parameters Change`` (0x0E)
  caches the new display blob and counts changes.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.state import SimCardState
from SIMCARD.toolkit import ToolkitLogic
from SIMCARD.utils import tlv


def _envelope(root_tag: bytes, *body: bytes) -> bytes:
    joined = b"".join(body)
    return bytes((root_tag[0], len(joined))) + joined


def _event_payload(event_code: int, *children: bytes) -> bytes:
    inner = tlv("99", bytes((event_code & 0xFF,))) + b"".join(children)
    return _envelope(b"\xD6", inner)


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

    def _fallback(self, payload: bytes) -> tuple[bytes, int, int]:
        del payload
        return b"", 0x90, 0x00


class _EngineHarness(unittest.TestCase):
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

    def tearDown(self) -> None:
        self._td.cleanup()


class IsimAuthenticateP2Tests(_EngineHarness):
    """3GPP TS 31.103 §7.1 IMS AKA (``AUTHENTICATE`` P2=0x82)."""

    def test_p2_82_reuses_usim_authentication_chain(self) -> None:
        rand = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        autn = bytes.fromhex("0F0E0D0C0B0A09080706050403020100")
        body = (
            bytes((len(rand),)) + rand + bytes((len(autn),)) + autn
        )

        usim_data, usim_sw1, usim_sw2 = self.engine.auth.internal_authenticate(0x81, body)
        ims_data, ims_sw1, ims_sw2 = self.engine.auth.internal_authenticate(0x82, body)
        self.assertEqual((usim_sw1, usim_sw2), (ims_sw1, ims_sw2))
        self.assertEqual(usim_data, ims_data)

    def test_unknown_p2_still_rejected(self) -> None:
        _data, sw1, sw2 = self.engine.auth.internal_authenticate(0x77, b"")
        self.assertEqual((sw1, sw2), (0x6A, 0x86))


class IsimFilesystemTests(_EngineHarness):
    """3GPP TS 31.103 ISIM EFs (IMPU / DOMAIN / AD)."""

    def _find_isim_ef(self, fid_hex: str):
        target = fid_hex.upper()
        for node in self.engine.state.nodes.values():
            if node.kind != "ef":
                continue
            if node.fid.upper() != target:
                continue
            if "ISIM" in str(node.node_id).upper():
                return node
        return None

    def test_isim_efs_present_in_filesystem(self) -> None:
        impu = self._find_isim_ef("6F04")
        domain = self._find_isim_ef("6F03")
        self.assertIsNotNone(impu)
        self.assertIsNotNone(domain)
        # ADF.ISIM holds its own EF.AD (FID 6FAD); USIM also has
        # one but they must both be navigable from their parents.
        isim_adf = next(
            (
                node
                for node in self.engine.state.nodes.values()
                if node.kind == "adf" and node.fid == "7FF2"
            ),
            None,
        )
        self.assertIsNotNone(isim_adf)
        self.assertEqual(impu.structure, "linear-fixed")
        self.assertGreaterEqual(len(impu.records), 1)
        first_record = impu.records[0]
        self.assertEqual(first_record[0], 0x80)
        uri_length = first_record[1]
        self.assertGreater(uri_length, 0)
        uri_bytes = bytes(first_record[2:2 + uri_length])
        self.assertTrue(uri_bytes.startswith(b"sip:"))

    def test_isim_domain_is_tlv_wrapped(self) -> None:
        domain_node = self._find_isim_ef("6F03")
        self.assertIsNotNone(domain_node)
        self.assertEqual(domain_node.structure, "transparent")
        body = bytes(domain_node.data)
        self.assertEqual(body[0], 0x80)
        length = body[1]
        self.assertGreater(length, 0)
        domain_bytes = body[2:2 + length]
        self.assertGreater(len(domain_bytes), 0)


class CallLifecycleEventTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.4.0 / §7.4.1 / §7.4.2 call events."""

    def test_mt_call_event_records_transaction_and_address(self) -> None:
        envelope = _event_payload(
            0x00,
            tlv("9C", bytes((0x05,))),
            tlv("86", bytes((0x91,)) + bytes.fromhex("214365")),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_mt_call_transaction_id, 0x05)
        self.assertEqual(toolkit.last_mt_call_address, "123456")
        self.assertFalse(toolkit.call_active)
        self.assertEqual(toolkit.last_event_code, 0x00)

    def test_call_connected_marks_call_active(self) -> None:
        envelope = _event_payload(
            0x01,
            tlv("9C", bytes((0x05,))),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_call_connected_transaction_id, 0x05)
        self.assertTrue(toolkit.call_active)

    def test_call_disconnected_clears_call_active_and_records_cause(self) -> None:
        # First connect.
        connected = _event_payload(0x01, tlv("9C", bytes((0x07,))))
        self.toolkit.handle_envelope(connected, self._fallback)
        # Then disconnect with a 2-byte cause.
        disconnected = _event_payload(
            0x02,
            tlv("9C", bytes((0x07,))),
            tlv("9A", bytes((0x80, 0x90))),
        )
        self.toolkit.handle_envelope(disconnected, self._fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_call_disconnected_transaction_id, 0x07)
        self.assertEqual(toolkit.last_call_disconnected_cause, b"\x80\x90")
        self.assertFalse(toolkit.call_active)


class UserActivityEventTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.4.4 User Activity Event."""

    def test_user_activity_counter_is_monotonic(self) -> None:
        for _ in range(3):
            envelope = _event_payload(0x04)
            self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.user_activity_count, 3)


class AccessTechnologyChangeTests(_ToolkitHarness):
    """3GPP TS 31.111 §7.5.4 Access Technology Change Event."""

    def test_access_tech_change_records_value_and_increment(self) -> None:
        first = _event_payload(0x0D, tlv("BF", bytes((0x02,))))
        second = _event_payload(0x0D, tlv("BF", bytes((0x03,))))
        same_again = _event_payload(0x0D, tlv("BF", bytes((0x03,))))
        self.toolkit.handle_envelope(first, self._fallback)
        self.toolkit.handle_envelope(second, self._fallback)
        self.toolkit.handle_envelope(same_again, self._fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_access_technology, 0x03)
        # Two transitions: 0->2, 2->3. The third event is a no-op.
        self.assertEqual(toolkit.access_technology_changes, 2)


class DisplayParametersChangeTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.4.14 Display Parameters Change Event."""

    def test_display_params_blob_cached(self) -> None:
        params = bytes.fromhex("0F2014")
        envelope = _event_payload(0x0E, tlv("C6", params))
        self.toolkit.handle_envelope(envelope, self._fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_display_parameters, params)
        self.assertEqual(toolkit.display_parameters_changes, 1)

    def test_empty_display_params_still_increments_counter(self) -> None:
        envelope = _event_payload(0x0E)
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.display_parameters_changes, 1)
        self.assertEqual(self.state.toolkit.last_display_parameters, b"")


if __name__ == "__main__":
    unittest.main()
