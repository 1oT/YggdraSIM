# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SIMCARD/scp03.py Scp03CardLogic public methods.

Exercises is_wrapped_command, key_template, handle_initialize_update
(happy-path and error paths), handle_external_authenticate (bad-session guard),
and unwrap_command (unauthenticated pass-through).
"""

from __future__ import annotations

import unittest

from SIMCARD.scp03 import Scp03CardLogic
from SIMCARD.state import SimCardState


def _make_state() -> SimCardState:
    return SimCardState(
        atr=bytes(33),
        eid="8904903200000000000000000000000000",
        iccid="89882012345678901234",
        imsi="001010000000001",
        default_dp_address="smdp.example.test",
        root_ci_pkid=bytes(20),
    )


# ---------------------------------------------------------------------------
# is_wrapped_command
# ---------------------------------------------------------------------------

class IsWrappedCommandTests(unittest.TestCase):

    def setUp(self) -> None:
        self.logic = Scp03CardLogic(_make_state())

    def test_short_apdu_not_wrapped(self) -> None:
        self.assertFalse(self.logic.is_wrapped_command(bytes([0x84, 0xCA])))

    def test_unauthenticated_session_not_wrapped(self) -> None:
        # Default state has no active session.
        apdu = bytes([0x84, 0xCA, 0x00, 0x00])
        self.assertFalse(self.logic.is_wrapped_command(apdu))

    def test_initialize_update_ins_not_wrapped(self) -> None:
        # Even with bit 0x04 set, INS 0x50 (INITIALIZE UPDATE) is never wrapped.
        self.logic.state.scp03_session.authenticated = True
        apdu = bytes([0x84, 0x50, 0x00, 0x00])
        self.assertFalse(self.logic.is_wrapped_command(apdu))

    def test_external_authenticate_ins_not_wrapped(self) -> None:
        self.logic.state.scp03_session.authenticated = True
        apdu = bytes([0x84, 0x82, 0x00, 0x00])
        self.assertFalse(self.logic.is_wrapped_command(apdu))

    def test_empty_bytes_not_wrapped(self) -> None:
        self.assertFalse(self.logic.is_wrapped_command(b""))


# ---------------------------------------------------------------------------
# key_template
# ---------------------------------------------------------------------------

class KeyTemplateTests(unittest.TestCase):

    def test_returns_bytes(self) -> None:
        logic = Scp03CardLogic(_make_state())
        result = logic.key_template()
        self.assertIsInstance(result, bytes)

    def test_three_entries_18_bytes(self) -> None:
        # Each entry is 6 bytes: C0 04 key_id kvn 88 10 → 3 × 6 = 18
        logic = Scp03CardLogic(_make_state())
        result = logic.key_template()
        self.assertEqual(len(result), 18)

    def test_all_entries_start_with_c0(self) -> None:
        logic = Scp03CardLogic(_make_state())
        data = logic.key_template()
        for offset in (0, 6, 12):
            self.assertEqual(data[offset], 0xC0)

    def test_key_ids_are_1_2_3(self) -> None:
        logic = Scp03CardLogic(_make_state())
        data = logic.key_template()
        self.assertEqual(data[2], 1)
        self.assertEqual(data[8], 2)
        self.assertEqual(data[14], 3)


# ---------------------------------------------------------------------------
# handle_initialize_update
# ---------------------------------------------------------------------------

class HandleInitializeUpdateTests(unittest.TestCase):

    def setUp(self) -> None:
        self.logic = Scp03CardLogic(_make_state())

    def test_wrong_challenge_length_returns_6700(self) -> None:
        _, sw1, sw2 = self.logic.handle_initialize_update(0x00, b"\x00" * 7)
        self.assertEqual((sw1, sw2), (0x67, 0x00))

    def test_unknown_kvn_returns_6a88(self) -> None:
        _, sw1, sw2 = self.logic.handle_initialize_update(0xFF, b"\x00" * 8)
        self.assertEqual((sw1, sw2), (0x6A, 0x88))

    def test_correct_kvn_returns_9000(self) -> None:
        kvn = self.logic.state.scp03_keys.kvn
        _, sw1, sw2 = self.logic.handle_initialize_update(kvn, b"\x00" * 8)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_wildcard_kvn_0x00_accepted(self) -> None:
        _, sw1, sw2 = self.logic.handle_initialize_update(0x00, b"\x01" * 8)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_response_contains_card_challenge(self) -> None:
        kvn = self.logic.state.scp03_keys.kvn
        response, sw1, _ = self.logic.handle_initialize_update(kvn, b"\xAB" * 8)
        self.assertEqual(sw1, 0x90)
        # Response layout: 10 bytes DP | 3 key_info | 8 card_challenge | 8 cryptogram
        self.assertGreaterEqual(len(response), 29)


# ---------------------------------------------------------------------------
# handle_external_authenticate — no active session guard
# ---------------------------------------------------------------------------

class HandleExternalAuthenticateTests(unittest.TestCase):

    def test_no_session_keys_returns_6985(self) -> None:
        logic = Scp03CardLogic(_make_state())
        _, sw1, sw2 = logic.handle_external_authenticate(0x03, bytes(16))
        self.assertEqual((sw1, sw2), (0x69, 0x85))

    def test_short_payload_returns_6700(self) -> None:
        logic = Scp03CardLogic(_make_state())
        # Force some session keys to bypass the first guard.
        logic._session_keys = {"s_mac": bytes(16), "s_enc": bytes(16), "s_rmac": bytes(16)}
        logic.state.scp03_session.host_challenge = bytes(8)
        _, sw1, sw2 = logic.handle_external_authenticate(0x03, bytes(8))
        self.assertEqual((sw1, sw2), (0x67, 0x00))


# ---------------------------------------------------------------------------
# unwrap_command — unauthenticated pass-through
# ---------------------------------------------------------------------------

class UnwrapCommandTests(unittest.TestCase):

    def test_unauthenticated_passes_apdu_through(self) -> None:
        logic = Scp03CardLogic(_make_state())
        apdu = bytes([0x80, 0xCA, 0x00, 0x66, 0x00])
        plain, error = logic.unwrap_command(apdu)
        self.assertIsNone(error)
        self.assertEqual(plain, apdu)

    def test_authenticated_short_data_returns_error(self) -> None:
        logic = Scp03CardLogic(_make_state())
        logic.state.scp03_session.authenticated = True
        logic._session_keys = {"s_mac": bytes(16), "s_enc": bytes(16), "s_rmac": bytes(16)}
        # 4-byte header + 3-byte data — too short for C-MAC (needs >= 8 bytes of data)
        apdu = bytes([0x84, 0xE2, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC])
        plain, error = logic.unwrap_command(apdu)
        self.assertIsNone(plain)
        self.assertIsNotNone(error)


if __name__ == "__main__":
    unittest.main()
