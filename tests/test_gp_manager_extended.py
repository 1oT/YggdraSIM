# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``SCP03.logic.gp.GlobalPlatformManager`` methods not covered
by test_gp_manager_utils.py.

Covers: verify_adm, get_keys_info_data, get_registry_data.
Transport is replaced with a MagicMock; no physical card is required.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from SCP03.logic.gp import GlobalPlatformManager


def _make_manager(*, transmit_return=(b"", 0x90, 0x00)) -> GlobalPlatformManager:
    tp = MagicMock()
    tp.session = None
    tp.transmit.return_value = transmit_return
    mgr = GlobalPlatformManager.__new__(GlobalPlatformManager)
    mgr.tp = tp
    mgr.raw_keys = {}
    mgr.target_aid = bytes.fromhex("A000000151000000")
    mgr.active_scp_protocol = "SCP03"
    return mgr


class VerifyAdmTests(unittest.TestCase):

    def test_no_key_skips_transmit(self) -> None:
        mgr = _make_manager()
        mgr.verify_adm(None)
        mgr.tp.transmit.assert_not_called()

    def test_key_from_raw_keys_used(self) -> None:
        mgr = _make_manager()
        mgr.raw_keys = {"adm": "41424344454647484142434445464748"}
        mgr.verify_adm()
        # Expects at least two APDU calls: SELECT MF + VERIFY.
        self.assertGreaterEqual(mgr.tp.transmit.call_count, 2)

    def test_explicit_key_sent(self) -> None:
        mgr = _make_manager()
        mgr.verify_adm("41424344454647484142434445464748")
        calls = [str(c) for c in mgr.tp.transmit.call_args_list]
        verify_call = any("0020" in c.upper() for c in calls)
        self.assertTrue(verify_call)

    def test_active_session_reset_before_verify(self) -> None:
        mgr = _make_manager()
        mgr.tp.session = MagicMock()
        mgr.tp.session.is_authenticated = True
        mgr.verify_adm("41424344454647484142434445464748")
        mgr.tp.reset_session_state.assert_called_once()

    def test_verify_apdu_contains_key_bytes(self) -> None:
        key = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"
        mgr = _make_manager()
        mgr.verify_adm(key)
        raw_calls = [str(c) for c in mgr.tp.transmit.call_args_list]
        apdu_with_key = any("DEADBEEF" in c.upper() for c in raw_calls)
        self.assertTrue(apdu_with_key)


class GetKeysInfoDataTests(unittest.TestCase):

    def _make_with_key_response(self) -> GlobalPlatformManager:
        # C0 08 88 01 88 02 81 88 18 01 — two AES key entries
        payload = bytes.fromhex("C00888018802818818018801880281881801")
        mgr = _make_manager(transmit_return=(payload, 0x90, 0x00))
        return mgr

    def test_returns_dict(self) -> None:
        mgr = self._make_with_key_response()
        result = mgr.get_keys_info_data()
        self.assertIsInstance(result, dict)

    def test_status_field_present(self) -> None:
        mgr = self._make_with_key_response()
        result = mgr.get_keys_info_data()
        self.assertIn("status", result)

    def test_raw_hex_field_present(self) -> None:
        mgr = self._make_with_key_response()
        result = mgr.get_keys_info_data()
        self.assertIn("raw_hex", result)

    def test_entries_parsed_on_9000(self) -> None:
        mgr = self._make_with_key_response()
        result = mgr.get_keys_info_data()
        self.assertIn("entries", result)

    def test_no_entries_on_failure_sw(self) -> None:
        mgr = _make_manager(transmit_return=(b"", 0x6A, 0x82))
        result = mgr.get_keys_info_data()
        self.assertNotIn("entries", result)

    def test_target_aid_select_when_no_session(self) -> None:
        mgr = self._make_with_key_response()
        mgr.tp.session = None
        mgr.get_keys_info_data()
        # Two calls: SELECT target AID + GET KEY INFO.
        self.assertGreaterEqual(mgr.tp.transmit.call_count, 2)

    def test_explicit_aid_triggers_select(self) -> None:
        mgr = self._make_with_key_response()
        mgr.get_keys_info_data(target_aid_hex="A000000151000000")
        first_call = str(mgr.tp.transmit.call_args_list[0])
        self.assertIn("A000000151000000", first_call.upper())


class GetRegistryDataTests(unittest.TestCase):

    def _make_single_page(self) -> GlobalPlatformManager:
        mgr = _make_manager(transmit_return=(b"\xE3\x02\x84\x00", 0x90, 0x00))
        return mgr

    def test_returns_dict(self) -> None:
        mgr = self._make_single_page()
        result = mgr.get_registry_data()
        self.assertIsInstance(result, dict)

    def test_kind_preserved(self) -> None:
        mgr = self._make_single_page()
        self.assertEqual(mgr.get_registry_data("PACKAGES")["kind"], "PACKAGES")

    def test_pages_counted(self) -> None:
        mgr = self._make_single_page()
        result = mgr.get_registry_data()
        self.assertEqual(result["pages"], 1)

    def test_status_field_present(self) -> None:
        mgr = self._make_single_page()
        result = mgr.get_registry_data()
        self.assertIn("status", result)
        self.assertEqual(result["status"], "9000")

    def test_raw_hex_present(self) -> None:
        mgr = self._make_single_page()
        result = mgr.get_registry_data()
        self.assertIn("raw_hex", result)

    def test_pagination_increments_pages(self) -> None:
        mgr = _make_manager()
        responses = iter([
            (b"\xE3\x02\x84\x01", 0x63, 0x10),
            (b"\xE3\x02\x84\x02", 0x90, 0x00),
        ])
        mgr.tp.transmit.side_effect = lambda *a, **kw: next(responses)
        result = mgr.get_registry_data("SD")
        self.assertEqual(result["pages"], 2)

    def test_error_sw_returns_zero_count(self) -> None:
        mgr = _make_manager(transmit_return=(b"", 0x6F, 0x00))
        result = mgr.get_registry_data()
        self.assertEqual(result["count"], 0)

    def test_default_kind_is_apps(self) -> None:
        mgr = self._make_single_page()
        result = mgr.get_registry_data()
        self.assertEqual(result["kind"], "APPS")


if __name__ == "__main__":
    unittest.main()
