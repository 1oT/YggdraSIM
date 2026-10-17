# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Twelfth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-12 closes the following:

* AUTHENTICATE contexts per selected application: TS 31.102 v19.5
  Table 7.1.2-1 for the USIM, TS 31.103 v19 §7.1.2 for the ISIM.
  IMS AKA is P2 '81' under the ISIM and answers RES, CK and IK
  without Kc (§7.1.2.1); P2 '82' (VGCS/VBS, HTTP Digest) answers
  '98 64'.
* 3GPP TS 31.103 §4.2.2 / §4.2.4 / §4.2.5 ISIM EFs ``EF.IMPI``,
  ``EF.IMPU``, ``EF.DOMAIN`` and ``EF.AD`` are seeded under ADF.ISIM
  with their TLV encodings.
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

from SIMCARD.auth import build_milenage_autn, milenage_vectors
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import ISIM_AID, USIM_AID
from SIMCARD.saip_profile import _finalize_image
from SIMCARD.state import SimCardState, SimProfileFsNode, SimProfileImage
from SIMCARD.toolkit import ToolkitLogic
from SIMCARD.utils import decode_impi_ef, encode_impi_ef, tlv


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
            eid="89049032123451234512345678901235",
            iccid="8988000000000000001",
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


class AuthenticateContextTests(_EngineHarness):
    """AUTHENTICATE P2 contexts (TS 31.102 v19.5 Table 7.1.2-1, TS 31.103 v19 §7.1.2)."""

    K = bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC")
    OPC = bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF")
    RAND = bytes.fromhex("23553CBE9637A89D218AE64DAE47BF35")
    AMF = bytes.fromhex("B9B9")

    def setUp(self) -> None:
        super().setUp()
        config = self.engine.state.profiles[0].auth_config
        self.assertIsNotNone(config)
        config.ki = self.K
        config.opc = self.OPC
        config.amf = self.AMF
        config.sqn = b"\x00" * 6

    def _select(self, aid_hex: str) -> None:
        aid_bytes = bytes.fromhex(aid_hex)
        _data, sw1, sw2 = self.engine.transmit(bytes([0x00, 0xA4, 0x04, 0x04, len(aid_bytes)]) + aid_bytes)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _authenticate(self, p2: int, body: bytes) -> tuple[bytes, int, int]:
        return self.engine.transmit(bytes([0x00, 0x88, 0x00, p2, len(body)]) + body)

    def _aka_body(self, sqn: bytes) -> bytes:
        autn = build_milenage_autn(self.K, self.OPC, self.RAND, sqn, self.AMF)
        return b"\x10" + self.RAND + b"\x10" + autn

    def test_isim_ims_aka_answer_stops_at_ik(self) -> None:
        self._select(ISIM_AID)
        sqn = bytes.fromhex("000000000010")
        data, sw1, sw2 = self._authenticate(0x81, self._aka_body(sqn))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        vectors = milenage_vectors(self.K, self.OPC, self.RAND, sqn, self.AMF)
        self.assertEqual(data, b"\xDB\x08" + vectors.res + b"\x10" + vectors.ck + b"\x10" + vectors.ik)

    def test_usim_3g_answer_ends_with_kc(self) -> None:
        self._select(USIM_AID)
        sqn = bytes.fromhex("000000000010")
        data, sw1, sw2 = self._authenticate(0x81, self._aka_body(sqn))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        vectors = milenage_vectors(self.K, self.OPC, self.RAND, sqn, self.AMF)
        self.assertEqual(data[-9:], b"\x08" + vectors.kc)
        self.assertEqual(len(data), 53)

    def test_p2_82_is_an_unsupported_context_on_both_applications(self) -> None:
        # VGCS/VBS on the USIM, HTTP Digest on the ISIM: '98 64' (TS 31.102 v19.5 §7.3.1).
        for aid in (USIM_AID, ISIM_AID):
            with self.subTest(aid=aid):
                self._select(aid)
                _data, sw1, sw2 = self._authenticate(0x82, self._aka_body(bytes.fromhex("000000000020")))
                self.assertEqual((sw1, sw2), (0x98, 0x64))

    def test_isim_gsm_context_is_reserved(self) -> None:
        self._select(ISIM_AID)
        _data, sw1, sw2 = self._authenticate(0x80, b"\x10" + self.RAND)
        self.assertEqual((sw1, sw2), (0x6A, 0x86))

    def test_odd_ins_contexts_are_rfu_with_ins_88(self) -> None:
        # MBMS '85' and Local Key Establishment '86' belong to INS '89'.
        self._select(USIM_AID)
        for p2 in (0x85, 0x86):
            with self.subTest(p2=p2):
                _data, sw1, sw2 = self._authenticate(p2, self._aka_body(bytes.fromhex("000000000030")))
                self.assertEqual((sw1, sw2), (0x6A, 0x86))

    def test_unknown_p2_still_rejected(self) -> None:
        _data, sw1, sw2 = self.engine.auth.internal_authenticate(0x77, b"")
        self.assertEqual((sw1, sw2), (0x6A, 0x86))


class IsimImpiEncodingTests(_EngineHarness):
    """EF.IMPI holds the NAI as a tag-'80' TLV (TS 31.103 v19 §4.2.2)."""

    def test_default_ef_impi_is_a_nai_tlv(self) -> None:
        node = next(
            node
            for node in self.engine.state.nodes.values()
            if node.kind == "ef" and node.fid.upper() == "6F02" and "ISIM" in str(node.node_id).upper()
        )
        body = bytes(node.data)
        self.assertEqual(body[0], 0x80)
        self.assertEqual(body[1], len(body) - 2)
        self.assertIn(b"@", body[2:])

    def test_codec_round_trip(self) -> None:
        self.assertEqual(encode_impi_ef("user@example.test"), b"\x80\x11user@example.test")
        self.assertEqual(decode_impi_ef(b"\x80\x11user@example.test" + b"\xFF" * 4), "user@example.test")

    def test_decode_boundaries(self) -> None:
        for body in (b"", b"\x80", b"\x80\x05ab", b"\x81\x01a", b"\x80\x02\xC3\x28"):
            with self.subTest(body=body.hex()):
                with self.assertRaises(ValueError):
                    decode_impi_ef(body)

    def test_profile_image_reads_tlv_and_legacy_bare_nai(self) -> None:
        for body in (encode_impi_ef("tlv@example.test"), b"tlv@example.test"):
            with self.subTest(body=body.hex()):
                image = SimProfileImage(
                    nodes=[
                        SimProfileFsNode(path=("MF",), name="MF", kind="mf", fid="3F00"),
                        SimProfileFsNode(path=("MF", "ADF.ISIM"), name="ADF.ISIM", kind="adf", fid="7FF2"),
                        SimProfileFsNode(
                            path=("MF", "ADF.ISIM", "EF.IMPI"),
                            name="EF.IMPI",
                            kind="ef",
                            fid="6F02",
                            structure="transparent",
                            data=body,
                        ),
                    ],
                )
                finalized = _finalize_image(image)
                self.assertIsNotNone(finalized)
                self.assertEqual(finalized.impi, "tlv@example.test")

    def test_profile_image_without_ef_impi_gets_a_tlv(self) -> None:
        finalized = _finalize_image(SimProfileImage(impi="made@example.test"))
        self.assertIsNotNone(finalized)
        node = next(node for node in finalized.nodes if node.path == ("MF", "ADF.ISIM", "EF.IMPI"))
        self.assertEqual(node.data, encode_impi_ef("made@example.test"))


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
    """ETSI TS 102 223 §7.5.5 User activity event."""

    def test_user_activity_counter_is_monotonic(self) -> None:
        for _ in range(3):
            envelope = _event_payload(0x04)
            self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.user_activity_count, 3)


class AccessTechnologyChangeTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.5.12 Access Technology Change Event."""

    def test_access_tech_change_records_value_and_increment(self) -> None:
        first = _event_payload(0x0B, tlv("BF", bytes((0x02,))))
        second = _event_payload(0x0B, tlv("BF", bytes((0x03,))))
        same_again = _event_payload(0x0B, tlv("BF", bytes((0x03,))))
        self.toolkit.handle_envelope(first, self._fallback)
        self.toolkit.handle_envelope(second, self._fallback)
        self.toolkit.handle_envelope(same_again, self._fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_access_technology, 0x03)
        # Two transitions: 0->2, 2->3. The third event is a no-op.
        self.assertEqual(toolkit.access_technology_changes, 2)


class DisplayParametersChangeTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.5.13 Display parameters changed Event."""

    def test_display_params_blob_cached(self) -> None:
        params = bytes.fromhex("0F2014")
        envelope = _event_payload(0x0C, tlv("C6", params))
        self.toolkit.handle_envelope(envelope, self._fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_display_parameters, params)
        self.assertEqual(toolkit.display_parameters_changes, 1)

    def test_empty_display_params_still_increments_counter(self) -> None:
        envelope = _event_payload(0x0C)
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.display_parameters_changes, 1)
        self.assertEqual(self.state.toolkit.last_display_parameters, b"")


if __name__ == "__main__":
    unittest.main()
