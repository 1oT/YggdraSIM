"""Coverage for SIMCARD surfaces beyond ES10:

* ETSI TS 102 221 PIN lifecycle commands (CHANGE / DISABLE / ENABLE PIN
  -- INS 0x24 / 0x26 / 0x28). Only VERIFY (0x20) and UNBLOCK (0x2C)
  were wired before.
* ETSI TS 102 221 §11.1.7 GET CHALLENGE (INS 0x84). Modems and OTA
  bootstrappers use this to obtain freshness for SCP03 cryptograms.
* GP Card Spec v2.3.1 GET DATA tags universally probed by management
  tools: CPLC (9F7F), Card Recognition Data (00 66), IIN (00 42),
  CIN (00 45).
* 3GPP TS 31.111 / TS 102 223 envelope dispatch by tag. The previous
  router treated every non-Event-Download envelope as SMS-PP; D2/D3/D4
  /D5/D7/D8 now follow their spec-defined response shapes.
* SAIP profileHeader.connectivityParameters → SimProfileEntry. The
  bytes flow from the SAIP image into the entry so SGP.32 §5.9.24
  GetConnectivityParameters returns the same TLV stream a real card
  would emit after profile install.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.gp import GpLogic
from SIMCARD.saip_profile import _consume_profile_element
from SIMCARD.state import SimCardState, SimProfileImage, SimScp03Session
from SIMCARD.toolkit import ToolkitLogic
from SIMCARD.utils import read_tlv


def _padded_pin(text: str) -> bytes:
    raw = text.encode("ascii")[:8]
    return raw + (b"\xFF" * (8 - len(raw)))


class _EngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        temp_root = Path(self._temp_dir.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(temp_root / "missing_quirks.py"),
            isdr_config_path=str(temp_root / "missing_isdr.json"),
            sim_eim_identity_path=str(temp_root / "missing_eim_identity.json"),
            euicc_store_root=str(temp_root / "euicc_store"),
            profile_store_path=str(temp_root / "profile_store"),
        )
        self._select_usim_adf()

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

    def _select_usim_adf(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex(f"00A4040010{USIM_AID}")
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _retries(self, reference: int) -> int:
        state = self.engine.state.chv_references.get(int(reference) & 0xFF)
        self.assertIsNotNone(state)
        assert state is not None
        return int(state.retries_remaining)


class ChangePinTests(_EngineHarness):
    def test_change_pin_happy_path_updates_value_and_resets_retries(self) -> None:
        wrong = _padded_pin("0000")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x20, 0x00, 0x01, 0x08]) + wrong
        )
        self.assertEqual((sw1, sw2 & 0xF0), (0x63, 0xC0))
        self.assertLess(self._retries(0x01), 3)

        old_pin = _padded_pin("1234")
        new_pin = _padded_pin("4321")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x24, 0x00, 0x01, 0x10]) + old_pin + new_pin
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._retries(0x01), 3)

        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x20, 0x00, 0x01, 0x08]) + new_pin
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_change_pin_rejects_wrong_old_value(self) -> None:
        bogus_old = _padded_pin("9999")
        new_pin = _padded_pin("4321")
        before = self._retries(0x01)
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x24, 0x00, 0x01, 0x10]) + bogus_old + new_pin
        )
        self.assertEqual((sw1, sw2 & 0xF0), (0x63, 0xC0))
        self.assertLess(self._retries(0x01), before)

    def test_change_pin_rejects_short_payload_without_consuming_retry(self) -> None:
        before = self._retries(0x01)
        short = b"\x12\x34\x43\x21"
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x24, 0x00, 0x01, len(short)]) + short
        )
        self.assertEqual((sw1, sw2), (0x67, 0x00))
        self.assertEqual(self._retries(0x01), before)

    def test_change_pin_returns_referenced_data_invalidated_when_disabled(self) -> None:
        old_pin = _padded_pin("1234")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x26, 0x00, 0x01, 0x08]) + old_pin
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        new_pin = _padded_pin("9999")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x24, 0x00, 0x01, 0x10]) + old_pin + new_pin
        )
        self.assertEqual((sw1, sw2), (0x69, 0x84))


class DisableEnablePinTests(_EngineHarness):
    def test_disable_pin_then_enable_pin_round_trip(self) -> None:
        pin = _padded_pin("1234")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x26, 0x00, 0x01, 0x08]) + pin
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertFalse(self.engine.state.chv_references[0x01].enabled)

        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x28, 0x00, 0x01, 0x08]) + pin
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertTrue(self.engine.state.chv_references[0x01].enabled)

    def test_disable_pin_with_wrong_value_decrements_retries(self) -> None:
        before = self._retries(0x01)
        bad = _padded_pin("0000")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x26, 0x00, 0x01, 0x08]) + bad
        )
        self.assertEqual((sw1, sw2 & 0xF0), (0x63, 0xC0))
        self.assertLess(self._retries(0x01), before)
        self.assertTrue(self.engine.state.chv_references[0x01].enabled)

    def test_enable_pin_when_already_enabled_with_correct_value_returns_9000(self) -> None:
        pin = _padded_pin("1234")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x28, 0x00, 0x01, 0x08]) + pin
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class GetChallengeTests(_EngineHarness):
    def test_get_challenge_returns_requested_length_and_persists_value(self) -> None:
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0084000010"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(len(data), 16)
        self.assertEqual(self.engine.state.last_challenge_bytes, data)

    def test_get_challenge_le_zero_returns_256_bytes(self) -> None:
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0084000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(len(data), 256)

    def test_get_challenge_subsequent_calls_yield_distinct_values(self) -> None:
        data_a, _, _ = self.engine.transmit(bytes.fromhex("0084000020"))
        data_b, _, _ = self.engine.transmit(bytes.fromhex("0084000020"))
        self.assertEqual(len(data_a), 32)
        self.assertEqual(len(data_b), 32)
        self.assertNotEqual(data_a, data_b)

    def test_get_challenge_rejects_non_zero_p1_p2(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0084010008"))
        self.assertEqual((sw1, sw2), (0x6A, 0x86))
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0084000208"))
        self.assertEqual((sw1, sw2), (0x6A, 0x86))


class GetDataExtendedTagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = SimCardState(
            atr=b"",
            eid="89049032123451234512345678901235",
            iccid="8949000000000000001",
            imsi="999990000000001",
            default_dp_address="testsmdpplus.example.com",
            root_ci_pkid=b"",
        )
        self.state.scp03_session = SimScp03Session(key_version=0x30)
        self.gp = GpLogic(self.state)

    def test_iin_returns_first_four_eid_bytes_under_tag_42(self) -> None:
        data, sw1, sw2 = self.gp.handle_get_data(0x00, 0x42)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        tag, value, _raw, _next = read_tlv(data, 0)
        self.assertEqual(tag, b"\x42")
        self.assertEqual(value, bytes.fromhex("89049032"))

    def test_cin_returns_full_eid_under_tag_45(self) -> None:
        data, sw1, sw2 = self.gp.handle_get_data(0x00, 0x45)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        tag, value, _raw, _next = read_tlv(data, 0)
        self.assertEqual(tag, b"\x45")
        self.assertEqual(value.hex().upper(), self.state.eid)

    def test_card_recognition_data_carries_required_oids(self) -> None:
        data, sw1, sw2 = self.gp.handle_get_data(0x00, 0x66)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value, _raw, _next = read_tlv(data, 0)
        self.assertEqual(outer_tag, b"\x66")
        inner_tag, inner_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(inner_tag, b"\x73")
        offset = 0
        seen_tags: list[bytes] = []
        while offset < len(inner_value):
            tag, _value, _raw, offset = read_tlv(inner_value, offset)
            seen_tags.append(tag)
        for required in (b"\x06", b"\x60", b"\x63", b"\x64"):
            self.assertIn(required, seen_tags)

    def test_cplc_returns_42_byte_blob_under_tag_9f7f(self) -> None:
        data, sw1, sw2 = self.gp.handle_get_data(0x9F, 0x7F)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        tag, value, _raw, _next = read_tlv(data, 0)
        self.assertEqual(tag, b"\x9F\x7F")
        self.assertEqual(len(value), 42)

    def test_unknown_tag_still_returns_6a88(self) -> None:
        _data, sw1, sw2 = self.gp.handle_get_data(0x12, 0x34)
        self.assertEqual((sw1, sw2), (0x6A, 0x88))


class EnvelopeDispatchTests(unittest.TestCase):
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
        # Disable IPA-poll and timer auto-rearm so D7 TIMER
        # EXPIRATION is acknowledged with bare 9000 instead of 9113
        # (proactive pending) -- the proactive paths are exercised
        # by ``test_simcard_ipa_poll_*`` and
        # ``test_simcard_stk_timer_management_bringup`` instead.
        self.toolkit.state.toolkit.ipa_poll_enabled = False
        self.toolkit.state.toolkit.timer_management_auto_rearm = False
        self.fallback_called: list[bytes] = []

        def _fallback(payload: bytes) -> tuple[bytes, int, int]:
            self.fallback_called.append(payload)
            return b"", 0x90, 0x00

        self._fallback = _fallback

    def test_d1_sms_pp_envelope_routes_to_fallback(self) -> None:
        envelope = bytes.fromhex("D102 0000".replace(" ", ""))
        _data, sw1, sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(len(self.fallback_called), 1)

    def test_d2_cell_broadcast_envelope_returns_9000_without_fallback(self) -> None:
        envelope = bytes.fromhex("D204 ABCDEF00".replace(" ", ""))
        data, sw1, sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual((data, sw1, sw2), (b"", 0x90, 0x00))
        self.assertEqual(len(self.fallback_called), 0)
        self.assertEqual(self.state.toolkit.envelope_history[-1], envelope)

    def test_d3_menu_selection_returns_9000(self) -> None:
        envelope = bytes.fromhex("D303 9001 02".replace(" ", ""))
        data, sw1, sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual((data, sw1, sw2), (b"", 0x90, 0x00))
        self.assertEqual(len(self.fallback_called), 0)

    def test_d4_call_control_returns_allowed_no_modification(self) -> None:
        envelope = bytes.fromhex("D403 8602 1234".replace(" ", ""))
        data, sw1, sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        tag, value, _raw, _next = read_tlv(data, 0)
        self.assertEqual(tag, b"\x80")
        self.assertEqual(value, b"\x00")

    def test_d5_mo_short_message_control_returns_allowed_no_modification(self) -> None:
        envelope = bytes.fromhex("D503 8602 4321".replace(" ", ""))
        data, sw1, sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        tag, value, _raw, _next = read_tlv(data, 0)
        self.assertEqual(tag, b"\x80")
        self.assertEqual(value, b"\x00")

    def test_d7_timer_expiration_returns_9000(self) -> None:
        envelope = bytes.fromhex("D703 A40101".replace(" ", ""))
        data, sw1, sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual((data, sw1, sw2), (b"", 0x90, 0x00))
        self.assertEqual(len(self.fallback_called), 0)

    def test_d8_ussd_download_returns_allowed_response(self) -> None:
        envelope = bytes.fromhex("D803 0F02 41".replace(" ", ""))
        data, sw1, sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        tag, value, _raw, _next = read_tlv(data, 0)
        self.assertEqual(tag, b"\x80")
        self.assertEqual(value, b"\x00")


class SaipConnectivityParametersTests(unittest.TestCase):
    """`profileHeader.connectivityParameters` flows into the image."""

    def test_consume_header_records_connectivity_bytes(self) -> None:
        image = SimProfileImage()
        decoded = {
            "profileType": "Test Profile",
            "iccid": bytes.fromhex("8949000000000000001F"),
            "connectivityParameters": bytes.fromhex(
                "A118350702000003000002470D085465726D696E616C0361706E"
            ),
        }
        _consume_profile_element(image, "header", decoded)
        self.assertEqual(image.profile_name, "Test Profile")
        self.assertTrue(image.iccid.startswith("89490000"))
        self.assertEqual(
            image.connectivity_params_http,
            bytes.fromhex(
                "A118350702000003000002470D085465726D696E616C0361706E"
            ),
        )

    def test_consume_header_without_connectivity_parameters_keeps_empty(self) -> None:
        image = SimProfileImage()
        decoded = {
            "profileType": "Test Profile",
            "iccid": bytes.fromhex("8949000000000000001F"),
        }
        _consume_profile_element(image, "header", decoded)
        self.assertEqual(image.connectivity_params_http, b"")


if __name__ == "__main__":
    unittest.main()
