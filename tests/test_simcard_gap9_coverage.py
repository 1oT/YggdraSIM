"""Ninth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-9 closes the following:

* ETSI TS 102 221 §11.1.14 RETRIEVE DATA (`INS 0xCB`) and
  §11.1.15 SET DATA (`INS 0xDB`) with a card-side data-object
  registry seeded with Card Capabilities (tag 0x0066), Application
  Identifier (0x004F), Card Service Data (0x0043) and Extended
  Card Resources (0xFF21).
* 3GPP TS 31.102 §7.1.2.1.2 / §7.1.2.1.3 AUTHENTICATE GBA
  Bootstrap (P2=0x84) and GBA NAF derivation (P2=0x85). The
  bootstrap caches Ks = CK||IK and a synthesised B-TID; the NAF
  command derives Ks_(ext)NAF via TS 33.220 §B.0.
* ETSI TS 102 223 §6.4.16 RUN AT COMMAND (proactive 0x34)
  terminal-response latching: the AT Response TLV (``A9``) is
  captured into ``state.toolkit.last_at_response`` and decoded
  into ``last_at_response_text`` for log-side correlation.
* ETSI TS 102 223 §7.4.13 HCI Connectivity Event (event 0x13)
  decode; the high nibble of TLV ``40`` toggles
  ``state.toolkit.hci_connectivity_active``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.auth import build_milenage_autn
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.state import SimCardState
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


class GbaBootstrapTests(_EngineHarness):
    """3GPP TS 31.102 §7.1.2.1.2 AUTHENTICATE P2=0x84."""

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
        self.engine.state.profiles[0].auth_config = config

    def _select_usim(self) -> None:
        aid_bytes = bytes.fromhex(USIM_AID)
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(aid_bytes)]) + aid_bytes
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _autn(self, sqn: bytes) -> bytes:
        return build_milenage_autn(self.K, self.OPC, self.RAND, sqn, self.AMF)

    def test_bootstrap_caches_ks_and_btid(self) -> None:
        self._select_usim()
        autn = self._autn(bytes.fromhex("000000000010"))
        payload = b"\x10" + self.RAND + b"\x10" + autn
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x88, 0x00, 0x84, len(payload)]) + payload
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Response shape: DB || 0x08 RES || 0x10 CK || 0x10 IK (no Kc).
        self.assertEqual(data[0], 0xDB)
        self.assertEqual(data[1], 0x08)
        ck = data[2 + 8 + 1 : 2 + 8 + 1 + 16]
        ik = data[2 + 8 + 1 + 16 + 1 : 2 + 8 + 1 + 16 + 1 + 16]
        self.assertEqual(self.engine.state.gba_ks, ck + ik)
        self.assertTrue(self.engine.state.gba_b_tid.endswith("@bsf.simulator"))
        self.assertEqual(self.engine.state.gba_key_lifetime, 86400)

    def test_bootstrap_bad_mac_returns_9862(self) -> None:
        self._select_usim()
        autn = bytearray(self._autn(bytes.fromhex("000000000020")))
        autn[-1] ^= 0xFF
        payload = b"\x10" + self.RAND + b"\x10" + bytes(autn)
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x88, 0x00, 0x84, len(payload)]) + payload
        )
        self.assertEqual((sw1, sw2), (0x98, 0x62))


class GbaNafDerivationTests(_EngineHarness):
    """3GPP TS 31.102 §7.1.2.1.3 AUTHENTICATE P2=0x85."""

    K = GbaBootstrapTests.K
    OPC = GbaBootstrapTests.OPC
    RAND = GbaBootstrapTests.RAND
    AMF = GbaBootstrapTests.AMF

    def setUp(self) -> None:
        super().setUp()
        config = self.engine.state.profiles[0].auth_config
        config.ki = self.K
        config.opc = self.OPC
        config.amf = self.AMF
        config.sqn = b"\x00" * 6
        self.engine.state.profiles[0].auth_config = config

    def _bootstrap(self) -> None:
        aid_bytes = bytes.fromhex(USIM_AID)
        self.engine.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(aid_bytes)]) + aid_bytes
        )
        autn = build_milenage_autn(
            self.K,
            self.OPC,
            self.RAND,
            bytes.fromhex("000000000030"),
            self.AMF,
        )
        payload = b"\x10" + self.RAND + b"\x10" + autn
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x88, 0x00, 0x84, len(payload)]) + payload
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _expected_ks_naf(self, naf_id: bytes, impi: bytes) -> bytes:
        ks = self.engine.state.gba_ks
        rand = self.RAND
        # Reproduce TS 33.220 §B.0 KDF inline so the test guards the
        # implementation rather than the implementation's own helper.
        p0 = b"gba-me"
        payload = bytearray()
        payload.append(0x01)
        payload += p0 + len(p0).to_bytes(2, "big")
        payload += rand + len(rand).to_bytes(2, "big")
        payload += impi + len(impi).to_bytes(2, "big")
        payload += naf_id + len(naf_id).to_bytes(2, "big")
        return hmac.new(ks, bytes(payload), hashlib.sha256).digest()

    def test_naf_derivation_matches_reference_kdf(self) -> None:
        self._bootstrap()
        naf_id = b"http://naf.example.com"
        impi = b"impu@example.com"
        body = bytes((len(naf_id),)) + naf_id + bytes((len(impi),)) + impi
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x88, 0x00, 0x85, len(body)]) + body
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data[0], 0xDB)
        self.assertEqual(data[1], 0x20)
        self.assertEqual(data[2:], self._expected_ks_naf(naf_id, impi))

    def test_naf_without_bootstrap_returns_6985(self) -> None:
        aid_bytes = bytes.fromhex(USIM_AID)
        self.engine.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(aid_bytes)]) + aid_bytes
        )
        body = bytes.fromhex("01AA01BB")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x88, 0x00, 0x85, len(body)]) + body
        )
        self.assertEqual((sw1, sw2), (0x69, 0x85))

    def test_naf_malformed_input_returns_6700(self) -> None:
        self._bootstrap()
        body = bytes.fromhex("FF")  # zero-length NAF specifier
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x88, 0x00, 0x85, len(body)]) + body
        )
        self.assertEqual((sw1, sw2), (0x67, 0x00))


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
