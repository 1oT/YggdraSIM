# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Ninth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-9 closes the following:

* ETSI TS 102 221 §11.1.14 RETRIEVE DATA (`INS 0xCB`) and
  §11.1.15 SET DATA (`INS 0xDB`) with a card-side data-object
  registry seeded with Card Capabilities (tag 0x0066), Application
  Identifier (0x004F), Card Service Data (0x0043) and Extended
  Card Resources (0xFF21).
* AUTHENTICATE in the GBA context (P2 '84'), Bootstrapping Mode
  ('DD') and NAF Derivation Mode ('DE') on the ISIM and the USIM:
  TS 31.102 v19.5 §7.1.1.4 / §7.1.1.5 / §7.1.2.3 / §7.1.2.4,
  TS 31.103 v19 §7.1.1.2 / §7.1.1.3 / §7.1.2.3 / §7.1.2.4, keys per
  TS 33.220 v19.1 §5.3.2 and Annex B.
* ETSI TS 102 223 §6.4.16 RUN AT COMMAND (proactive 0x34)
  terminal-response latching: the AT Response TLV (``A9``) is
  captured into ``state.toolkit.last_at_response`` and decoded
  into ``last_at_response_text`` for log-side correlation.
* ETSI TS 102 223 §7.4.13 HCI Connectivity Event (event 0x13)
  decode; the high nibble of TLV ``40`` toggles
  ``state.toolkit.hci_connectivity_active``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.auth import (
    _ef_gbabp_b_tid,
    _gbanl_record_naf_id,
    _parse_length_prefixed_fields,
    build_milenage_autn,
    build_milenage_auts,
    milenage_vectors,
)
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import ISIM_AID, USIM_AID
from SIMCARD.state import SimCardState, SimFileNode
from SIMCARD.toolkit import (
    RUN_AT_COMMAND,
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
    body = (
        tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, qualifier & 0xFF)))
        + tlv("82", bytes((0x82, 0x81)))
        + tlv("83", bytes((result_code & 0xFF,)))
        + bytes(extra or b"")
    )
    return body


class _EngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self._root = Path(self._td.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(self._root / "missing_quirks.py"),
            isdr_config_path=str(self._root / "missing_isdr.json"),
            sim_eim_identity_path=str(self._root / "missing_eim_identity.json"),
            euicc_store_root=str(self._root / "euicc"),
            profile_store_path=str(self._root / "profile_store"),
        )

    def tearDown(self) -> None:
        self._td.cleanup()


class RetrieveDataTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.14 RETRIEVE DATA dispatch."""

    def test_retrieve_data_returns_card_capabilities_tlv(self) -> None:
        # Tag 0x0066 (Card Capabilities). P1=0x00, P2=0x66, Le=0.
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00CB006600"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Single-byte tag + length + value (TS 102 221 §10.1.2).
        self.assertEqual(data[0], 0x66)
        self.assertGreater(len(data), 2)

    def test_retrieve_data_unknown_tag_returns_6a88(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00CB123400"))
        self.assertEqual((sw1, sw2), (0x6A, 0x88))

    def test_retrieve_data_two_byte_tag(self) -> None:
        # Tag 0xFF21 (Extended Card Resources). P1=0xFF, P2=0x21.
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00CBFF2100"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data[0], 0xFF)
        self.assertEqual(data[1], 0x21)


class SetDataTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.15 SET DATA dispatch."""

    def test_set_data_writes_then_retrieves_back(self) -> None:
        # Force the registry to seed first so SET DATA replaces an
        # existing tag rather than creating a fresh one.
        self.engine.transmit(bytes.fromhex("00CB006600"))
        payload = bytes.fromhex("AABBCCDD")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xDB, 0x00, 0x66, len(payload)]) + payload
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00CB006600"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Stored tag + length + value.
        self.assertEqual(data, b"\x66\x04" + payload)

    def test_set_data_empty_body_deletes_entry(self) -> None:
        self.engine.transmit(bytes.fromhex("00CB006600"))
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xDB, 0x00, 0x66, 0x00])
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00CB006600"))
        self.assertEqual((sw1, sw2), (0x6A, 0x88))


def _gba_autn_star(k: bytes, opc: bytes, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
    """AUTN* = SQN xor AK || AMF || MAC*, MAC* = MAC xor the first 64 bits of
    SHA-256(IK) (TS 33.220 v19.1 §5.3.2 step 2), built here rather than with
    the card's own helpers."""
    vectors = milenage_vectors(k, opc, rand, sqn, amf)
    mask = hashlib.sha256(vectors.ik).digest()[:8]
    mac_star = bytes(left ^ right for left, right in zip(vectors.mac_a, mask))
    concealed_sqn = bytes(left ^ right for left, right in zip(sqn, vectors.ak))
    return concealed_sqn + amf + mac_star


def _naf_key(ks: bytes, label: bytes, rand: bytes, impi: bytes, naf_id: bytes) -> bytes:
    """TS 33.220 v19.1 Annex B.2.0 / B.3: HMAC-SHA-256(Ks, 01 || P0 L0 || RAND L1 || IMPI L2 || NAF_ID L3)."""
    message = bytearray(b"\x01")
    for parameter in (label, rand, impi, naf_id):
        message += parameter + len(parameter).to_bytes(2, "big")
    return hmac.new(ks, bytes(message), hashlib.sha256).digest()


class _GbaHarness(_EngineHarness):
    K = bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC")
    OPC = bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF")
    RAND = bytes.fromhex("23553CBE9637A89D218AE64DAE47BF35")
    AMF = bytes.fromhex("B9B9")
    # NAF_Id = NAF FQDN || five-octet Ua security protocol identifier
    # (TS 33.220 v19.1 §5.3.2 step 9); the card treats it as opaque.
    NAF_ID = b"naf.example.test" + bytes.fromhex("0100000002")

    def setUp(self) -> None:
        super().setUp()
        config = self.engine.state.profiles[0].auth_config
        self.assertIsNotNone(config)
        config.ki = self.K
        config.opc = self.OPC
        config.amf = self.AMF
        config.sqn = b"\x00" * 6
        self.engine.state.profiles[0].auth_config = config

    def _select(self, aid_hex: str) -> None:
        aid_bytes = bytes.fromhex(aid_hex)
        _data, sw1, sw2 = self.engine.transmit(bytes([0x00, 0xA4, 0x04, 0x04, len(aid_bytes)]) + aid_bytes)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _authenticate(self, body: bytes, p2: int = 0x84) -> tuple[bytes, int, int]:
        return self.engine.transmit(bytes([0x00, 0x88, 0x00, p2, len(body)]) + body)

    def _bootstrap(self, sqn: bytes, rand: bytes | None = None) -> tuple[bytes, int, int]:
        challenge = self.RAND if rand is None else rand
        autn_star = _gba_autn_star(self.K, self.OPC, challenge, sqn, self.AMF)
        return self._authenticate(b"\xDD\x10" + challenge + b"\x10" + autn_star)

    def _application_ef(self, application: str, fid: str) -> SimFileNode:
        for node in self.engine.state.nodes.values():
            parent = self.engine.state.nodes.get(node.parent_id)
            if node.kind == "ef" and node.fid.upper() == fid and parent is not None and parent.name == application:
                return node
        self.fail(f"{fid} not found under {application}")

    def _isim_impi(self) -> bytes:
        body = self._application_ef("ADF.ISIM", "6F02").data
        # TS 31.103 v19 §4.2.2: '80' L NAI.
        self.assertEqual(body[0], 0x80)
        return body[2 : 2 + body[1]]


class IsimGbaBootstrapTests(_GbaHarness):
    """GBA_U Bootstrapping Mode on the ISIM (TS 31.103 v19 §7.1.1.2 / §7.1.2.3)."""

    def test_bootstrap_answers_flipped_res_and_keeps_ks(self) -> None:
        self._select(ISIM_AID)
        sqn = bytes.fromhex("000000000010")
        data, sw1, sw2 = self._bootstrap(sqn)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        vectors = milenage_vectors(self.K, self.OPC, self.RAND, sqn, self.AMF)
        flipped = vectors.res[:-1] + bytes((vectors.res[-1] ^ 0x01,))
        # 'DB' L RES, RES with its least significant bit flipped; no CK / IK.
        self.assertEqual(data, b"\xDB\x08" + flipped)
        material = self.engine.state.gba_key_material["ADF.ISIM"]
        self.assertEqual(material.ks, vectors.ck + vectors.ik)
        self.assertEqual(material.rand, self.RAND)

    def test_bootstrap_writes_rand_field_of_ef_gbabp(self) -> None:
        self._select(ISIM_AID)
        gbabp = self._application_ef("ADF.ISIM", "6FD5")
        size = len(gbabp.data)
        _data, sw1, sw2 = self._bootstrap(bytes.fromhex("000000000010"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # TS 31.103 v19 §4.2.9: L RAND, RAND, then empty B-TID and lifetime
        # fields for the ME; the file keeps its size.
        expected = b"\x10" + self.RAND + b"\x00\x00"
        self.assertEqual(gbabp.data, expected + b"\xFF" * (size - len(expected)))

    def test_unmodified_mac_is_refused(self) -> None:
        self._select(ISIM_AID)
        autn = build_milenage_autn(self.K, self.OPC, self.RAND, bytes.fromhex("000000000020"), self.AMF)
        _data, sw1, sw2 = self._authenticate(b"\xDD\x10" + self.RAND + b"\x10" + autn)
        self.assertEqual((sw1, sw2), (0x98, 0x62))
        self.assertNotIn("ADF.ISIM", self.engine.state.gba_key_material)

    def test_stale_sqn_answers_auts(self) -> None:
        self._select(ISIM_AID)
        self.engine.state.profiles[0].auth_config.sqn = bytes.fromhex("000000000100")
        data, sw1, sw2 = self._bootstrap(bytes.fromhex("000000000040"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        auts = build_milenage_auts(self.K, self.OPC, self.RAND, bytes.fromhex("000000000100"))
        self.assertEqual(data, b"\xDC\x0E" + auts)

    def test_unknown_mode_tag_is_an_unsupported_context(self) -> None:
        self._select(ISIM_AID)
        _data, sw1, sw2 = self._authenticate(b"\xDF\x01\x00")
        self.assertEqual((sw1, sw2), (0x98, 0x64))

    def test_malformed_bootstrapping_data_is_wrong_length(self) -> None:
        self._select(ISIM_AID)
        autn_star = _gba_autn_star(self.K, self.OPC, self.RAND, bytes.fromhex("000000000010"), self.AMF)
        for body in (
            b"\xDD",
            b"\xDD\x10",
            b"\xDD\x10" + self.RAND[:5],
            b"\xDD\x10" + self.RAND + b"\x10" + autn_star[:15],
            b"\xDD\xFF" + self.RAND + b"\x10" + autn_star,
            b"\xDD\x10" + self.RAND + b"\x10" + autn_star + b"\x00",
        ):
            with self.subTest(body=body.hex()):
                _data, sw1, sw2 = self._authenticate(body)
                self.assertEqual((sw1, sw2), (0x67, 0x00))
        self.assertNotIn("ADF.ISIM", self.engine.state.gba_key_material)

    def test_untagged_layout_is_an_unsupported_context(self) -> None:
        # RAND and AUTN without the 'DD' mode tag: the first byte names no mode.
        self._select(ISIM_AID)
        autn_star = _gba_autn_star(self.K, self.OPC, self.RAND, bytes.fromhex("000000000010"), self.AMF)
        _data, sw1, sw2 = self._authenticate(b"\x10" + self.RAND + b"\x10" + autn_star)
        self.assertEqual((sw1, sw2), (0x98, 0x64))


class IsimGbaNafDerivationTests(_GbaHarness):
    """GBA_U NAF Derivation Mode on the ISIM (TS 31.103 v19 §7.1.1.3 / §7.1.2.4)."""

    B_TID = base64.b64encode(_GbaHarness.RAND) + b"@bsf.example.test"
    LIFETIME = bytes.fromhex("00015180")

    def _bootstrap_and_store_b_tid(self) -> None:
        self._select(ISIM_AID)
        _data, sw1, sw2 = self._bootstrap(bytes.fromhex("000000000030"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # The ME writes the B-TID and lifetime the BSF sent (TS 31.103 v19 §7.1.1.2).
        body = (
            b"\x10" + self.RAND
            + bytes((len(self.B_TID),)) + self.B_TID
            + bytes((len(self.LIFETIME),)) + self.LIFETIME
        )
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00A40004026FD5"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _data, sw1, sw2 = self.engine.transmit(bytes([0x00, 0xD6, 0x00, 0x00, len(body)]) + body)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self._select(ISIM_AID)

    def _derive(self, naf_id: bytes) -> tuple[bytes, int, int]:
        return self._authenticate(b"\xDE" + bytes((len(naf_id),)) + naf_id)

    def test_derivation_returns_ks_ext_naf_over_ef_impi(self) -> None:
        self._bootstrap_and_store_b_tid()
        data, sw1, sw2 = self._derive(self.NAF_ID)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        ks = self.engine.state.gba_key_material["ADF.ISIM"].ks
        expected = _naf_key(ks, b"gba-me", self.RAND, self._isim_impi(), self.NAF_ID)
        self.assertEqual(data, b"\xDB\x20" + expected)

    def test_derivation_keeps_ks_int_naf_and_fills_ef_gbanl(self) -> None:
        self._bootstrap_and_store_b_tid()
        _data, sw1, sw2 = self._derive(self.NAF_ID)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        material = self.engine.state.gba_key_material["ADF.ISIM"]
        ks_int_naf = _naf_key(material.ks, b"gba-u", self.RAND, self._isim_impi(), self.NAF_ID)
        self.assertEqual(material.naf_keys[self.NAF_ID.hex().upper()], (ks_int_naf, self.B_TID))
        gbanl = self._application_ef("ADF.ISIM", "6FD7")
        # TS 31.103 v19 §4.2.10: '80' NAF_ID, '81' B-TID, unused bytes 'FF'.
        expected = tlv("80", self.NAF_ID) + tlv("81", self.B_TID)
        self.assertEqual(gbanl.records[0], expected + b"\xFF" * (len(gbanl.records[0]) - len(expected)))
        self.assertEqual(set(gbanl.records[1]), {0xFF})

    def test_same_naf_id_reuses_its_record(self) -> None:
        self._bootstrap_and_store_b_tid()
        for _ in range(2):
            _data, sw1, sw2 = self._derive(self.NAF_ID)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
        gbanl = self._application_ef("ADF.ISIM", "6FD7")
        self.assertEqual(gbanl.records[0][2 : 2 + len(self.NAF_ID)], self.NAF_ID)
        self.assertEqual(set(gbanl.records[1]), {0xFF})

    def test_full_list_overwrites_least_recently_derived_record(self) -> None:
        self._bootstrap_and_store_b_tid()
        first, second, third = (b"naf%d.example.test" % index + bytes(5) for index in (1, 2, 3))
        for naf_id in (first, second, third):
            _data, sw1, sw2 = self._derive(naf_id)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
        gbanl = self._application_ef("ADF.ISIM", "6FD7")
        stored = [record[2 : 2 + record[1]] for record in gbanl.records]
        # Two records: the third NAF_ID replaces the first, derived longest ago.
        self.assertEqual(stored, [third, second])

    def test_derivation_without_bootstrap_returns_6985(self) -> None:
        self._select(ISIM_AID)
        _data, sw1, sw2 = self._derive(self.NAF_ID)
        self.assertEqual((sw1, sw2), (0x69, 0x85))

    def test_b_tid_of_another_bootstrap_is_not_recorded(self) -> None:
        self._bootstrap_and_store_b_tid()
        stale = bytes(self._application_ef("ADF.ISIM", "6FD5").data)
        other_rand = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        _data, sw1, sw2 = self._bootstrap(bytes.fromhex("000000000050"), rand=other_rand)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # The ME puts the previous bootstrap's RAND and B-TID back.
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00A40004026FD5"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _data, sw1, sw2 = self.engine.transmit(bytes([0x00, 0xD6, 0x00, 0x00, len(stale)]) + stale)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self._select(ISIM_AID)
        _data, sw1, sw2 = self._derive(self.NAF_ID)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        material = self.engine.state.gba_key_material["ADF.ISIM"]
        # That B-TID belongs to other key material, so none is recorded.
        self.assertEqual(material.naf_keys[self.NAF_ID.hex().upper()][1], b"")

    def test_malformed_naf_derivation_data_is_wrong_length(self) -> None:
        self._bootstrap_and_store_b_tid()
        for body in (b"\xDE", b"\xDE\x00", b"\xDE\x05abc", b"\xDE\x01a\x01b"):
            with self.subTest(body=body.hex()):
                _data, sw1, sw2 = self._authenticate(body)
                self.assertEqual((sw1, sw2), (0x67, 0x00))


class UsimGbaTests(_GbaHarness):
    """GBA_U on the USIM (TS 31.102 v19.5 §7.1.1.4 / §7.1.1.5 / §7.1.2.3 / §7.1.2.4)."""

    IMPI = b"999990000000001@ims.mnc999.mcc999.3gppnetwork.org"

    def _enable_usim_gba(self) -> None:
        # Service n°68 in EF_UST, EF_GBABP '6FD6' and EF_GBANL '6FDA' under ADF.USIM.
        state = self.engine.state
        usim = next(node for node in state.nodes.values() if node.kind == "adf" and node.name == "ADF.USIM")
        ust = self._application_ef("ADF.USIM", "6F38")
        data = bytearray(ust.data)
        data[67 // 8] |= 1 << (67 % 8)
        ust.data = bytes(data)
        for name, fid, structure in (("EF.GBABP", "6FD6", "transparent"), ("EF.GBANL", "6FDA", "linear-fixed")):
            node = SimFileNode(
                node_id=f"test-{fid}",
                name=name,
                kind="ef",
                fid=fid,
                parent_id=usim.node_id,
                structure=structure,
                data=b"\xFF" * 64 if structure == "transparent" else b"",
                records=[b"\xFF" * 96] if structure == "linear-fixed" else [],
            )
            state.nodes[node.node_id] = node
            usim.children.append(node.node_id)

    def test_default_usim_without_service_68_refuses_gba(self) -> None:
        self._select(USIM_AID)
        _data, sw1, sw2 = self._bootstrap(bytes.fromhex("000000000010"))
        self.assertEqual((sw1, sw2), (0x98, 0x64))

    def test_usim_derivation_takes_impi_from_the_command(self) -> None:
        self._enable_usim_gba()
        self._select(USIM_AID)
        _data, sw1, sw2 = self._bootstrap(bytes.fromhex("000000000010"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        body = b"\xDE" + bytes((len(self.NAF_ID),)) + self.NAF_ID + bytes((len(self.IMPI),)) + self.IMPI
        data, sw1, sw2 = self._authenticate(body)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        ks = self.engine.state.gba_key_material["ADF.USIM"].ks
        self.assertEqual(data, b"\xDB\x20" + _naf_key(ks, b"gba-me", self.RAND, self.IMPI, self.NAF_ID))
        # The USIM layout carries IMPI: the ISIM layout (NAF_ID alone) is short.
        _data, sw1, sw2 = self._authenticate(b"\xDE" + bytes((len(self.NAF_ID),)) + self.NAF_ID)
        self.assertEqual((sw1, sw2), (0x67, 0x00))

    def test_usim_key_material_is_not_the_isim_s(self) -> None:
        self._enable_usim_gba()
        self._select(USIM_AID)
        _data, sw1, sw2 = self._bootstrap(bytes.fromhex("000000000010"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self._select(ISIM_AID)
        _data, sw1, sw2 = self._authenticate(b"\xDE" + bytes((len(self.NAF_ID),)) + self.NAF_ID)
        self.assertEqual((sw1, sw2), (0x69, 0x85))


class GbaDataParserBoundaryTests(unittest.TestCase):
    """Decode boundaries of the GBA command and file parsers."""

    def test_length_prefixed_fields(self) -> None:
        self.assertIsNone(_parse_length_prefixed_fields(b"", 1))
        self.assertIsNone(_parse_length_prefixed_fields(b"\x02", 1))
        self.assertIsNone(_parse_length_prefixed_fields(b"\x02a", 1))
        self.assertIsNone(_parse_length_prefixed_fields(b"\xFFabc", 1))
        self.assertIsNone(_parse_length_prefixed_fields(b"\x01a\x00", 1))
        self.assertEqual(_parse_length_prefixed_fields(b"\x01a\x00", 2), [b"a", b""])

    def test_ef_gbabp_b_tid(self) -> None:
        rand = bytes(range(16))
        self.assertEqual(_ef_gbabp_b_tid(b"", rand), b"")
        self.assertEqual(_ef_gbabp_b_tid(b"\x10", rand), b"")
        self.assertEqual(_ef_gbabp_b_tid(b"\xFF" * 128, rand), b"")
        self.assertEqual(_ef_gbabp_b_tid(b"\x10" + rand + b"\x09abc", rand), b"")
        self.assertEqual(_ef_gbabp_b_tid(b"\x10" + rand + b"\x03abc\x00", bytes(16)), b"")
        self.assertEqual(_ef_gbabp_b_tid(b"\x10" + rand + b"\x03abc\x00", rand), b"abc")

    def test_gbanl_record_naf_id(self) -> None:
        self.assertIsNone(_gbanl_record_naf_id(b""))
        self.assertIsNone(_gbanl_record_naf_id(b"\x80"))
        self.assertIsNone(_gbanl_record_naf_id(b"\x80\x05ab"))
        self.assertIsNone(_gbanl_record_naf_id(b"\x81\x01a"))
        self.assertEqual(_gbanl_record_naf_id(b"\x80\x01a\x81\x00\xFF"), b"a")


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


class RunAtCommandResponseLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.16 RUN AT COMMAND TR latch."""

    def test_terminal_response_latches_at_response_bytes_and_text(self) -> None:
        result = self.toolkit.queue_run_at_command(at_command="AT+CGSN")
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        at_response = b"\r\n+CGSN: 123456789012345\r\nOK\r\n"
        tr = _terminal_response(
            command_number=cmd,
            command_type=RUN_AT_COMMAND,
            qualifier=0x00,
            extra=tlv("A9", at_response),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_at_response, at_response)
        self.assertIn("123456789012345", self.state.toolkit.last_at_response_text)

    def test_failed_response_leaves_previous_at_response_untouched(self) -> None:
        self.state.toolkit.last_at_response = b"\r\nOK\r\n"
        self.state.toolkit.last_at_response_text = "\r\nOK\r\n"
        result = self.toolkit.queue_run_at_command(at_command="AT+CIMI")
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=RUN_AT_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_at_response, b"\r\nOK\r\n")


class HciConnectivityEventTests(_ToolkitHarness):
    """3GPP TS 31.111 §7.5.x HCI Connectivity Event (0x13)."""

    def _envelope(self, *body: bytes) -> bytes:
        joined = b"".join(body)
        return bytes((0xD6, len(joined))) + joined

    def _fallback(self, payload: bytes) -> tuple[bytes, int, int]:
        del payload
        return b"", 0x90, 0x00

    def test_hci_event_sets_active_when_high_nibble_eight(self) -> None:
        envelope = self._envelope(
            tlv("99", b"\x13"),
            tlv("40", b"\x80"),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertTrue(self.state.toolkit.hci_connectivity_active)
        self.assertEqual(self.state.toolkit.last_event_code, 0x13)

    def test_hci_event_clears_active_on_disconnect(self) -> None:
        self.state.toolkit.hci_connectivity_active = True
        envelope = self._envelope(
            tlv("99", b"\x13"),
            tlv("40", b"\x00"),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertFalse(self.state.toolkit.hci_connectivity_active)


if __name__ == "__main__":
    unittest.main()
