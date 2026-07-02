# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``SCP03.logic.gp.GlobalPlatformManager`` methods not covered
by test_gp_manager_utils.py.

Covers: verify_adm, get_keys_info_data, get_registry_data.
Transport is replaced with a MagicMock; no physical card is required.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from SCP03.core.cap import CapFileParser
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

    def test_get_status_shortcut_includes_case4_le(self) -> None:
        mgr = self._make_single_page()
        mgr.get_registry_data("APPS")

        apdu = mgr.tp.transmit.call_args.args[0].upper()

        self.assertEqual(apdu, "80F24000024F0000")

    def test_list_registry_shortcut_includes_case4_le(self) -> None:
        mgr = _make_manager(transmit_return=(b"", 0x90, 0x00))

        mgr.list_registry("PACKAGES")

        apdu = mgr.tp.transmit.call_args.args[0].upper()
        self.assertEqual(apdu, "80F22000024F0000")

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

    def test_compact_registry_accepts_non_a0_aid(self) -> None:
        raw = bytes.fromhex("05F0000000010100")
        mgr = _make_manager(transmit_return=(raw, 0x90, 0x00))

        result = mgr.get_registry_data("PACKAGES")

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["entries"][0]["aid"], "F000000001")
        self.assertEqual(result["entries"][0]["state"], "OP_READY")

    def test_fcp_template_is_not_parsed_as_compact_registry(self) -> None:
        raw = bytes.fromhex(
            "62298202782183023F00A50C800171830400051DE08701018A01058B032F0601"
            "C60990014083010183010A"
        )
        mgr = _make_manager(transmit_return=(raw, 0x90, 0x00))

        result = mgr.get_registry_data("APPS")

        self.assertEqual(result["status"], "9000")
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["entries"], [])

    def test_compact_registry_ignores_e3_inside_aid(self) -> None:
        raw = bytes.fromhex(
            "10A0000000871002FF34FF0789312E30FF0700"
            "06F000000001010700"
        )
        mgr = _make_manager(transmit_return=(raw, 0x90, 0x00))

        result = mgr.get_registry_data("APPS")

        self.assertEqual(result["count"], 2)
        self.assertEqual(result["entries"][0]["aid"], "A0000000871002FF34FF0789312E30FF")
        self.assertEqual(result["entries"][1]["aid"], "F00000000101")
        self.assertEqual(result["entries"][1]["state"], "SELECTABLE")


class InstallCommandEncodingTests(unittest.TestCase):
    def test_send_install_cmd_uses_extended_lc_for_large_payload(self) -> None:
        mgr = _make_manager()
        mgr.tp.transmit.return_value = (b"", 0x90, 0x00)

        result = mgr._send_install_cmd(0x40, b"\x00" * 256, "Registry Update")

        self.assertTrue(result)
        cmd = mgr.tp.transmit.call_args.args[0].upper()
        self.assertTrue(cmd.startswith("80E64000000100"))


def _component(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + len(payload).to_bytes(2, "big") + payload


class InstallCapWithSuppliedApduTests(unittest.TestCase):
    PACKAGE_AID = bytes.fromhex("A000000151")
    APPLET_AID = bytes.fromhex("A00000015101")

    @staticmethod
    def _write_ijc(directory: Path, package_aid: bytes, applet_aid: bytes) -> Path:
        header_payload = (b"\x00" * 9) + bytes([len(package_aid)]) + package_aid
        applet_payload = bytes([1, len(applet_aid)]) + applet_aid + b"\x00\x00"
        component_blob = _component(0x01, header_payload) + _component(0x03, applet_payload)
        load_block = CapFileParser._wrap_load_file_block(component_blob)
        path = directory / "sample.ijc"
        path.write_bytes(load_block)
        return path

    @staticmethod
    def _install_apdu(package_aid: bytes, module_aid: bytes, applet_aid: bytes) -> str:
        body = (
            bytes([len(package_aid)]) + package_aid
            + bytes([len(module_aid)]) + module_aid
            + bytes([len(applet_aid)]) + applet_aid
            + b"\x01\x00"
            + b"\x00"
            + b"\x00"
        )
        return (bytes([0x80, 0xE6, 0x0C, 0x00, len(body)]) + body).hex().upper()

    def _make_authenticated_manager(self) -> GlobalPlatformManager:
        mgr = _make_manager()
        mgr.tp.session = MagicMock()
        mgr.tp.session.is_authenticated = True
        mgr.tp.session.sec_level = 0
        mgr.tp.transmit.return_value = (b"", 0x90, 0x00)
        return mgr

    def test_loads_cap_then_sends_supplied_install_apdu(self) -> None:
        mgr = self._make_authenticated_manager()
        install_apdu = self._install_apdu(
            self.PACKAGE_AID,
            self.APPLET_AID,
            self.APPLET_AID,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = self._write_ijc(Path(temp_dir), self.PACKAGE_AID, self.APPLET_AID)
            result = mgr.install_cap_file_with_install_apdu(str(ijc_path), install_apdu)

        self.assertTrue(result)
        calls = [call.args[0].upper() for call in mgr.tp.transmit.call_args_list]
        self.assertEqual(len(calls), 3)
        self.assertTrue(calls[0].startswith("80E60200"))
        self.assertTrue(calls[1].startswith("80E88000"))
        self.assertEqual(calls[2], install_apdu)

    def test_mismatched_load_file_aid_refuses_before_transmit(self) -> None:
        mgr = self._make_authenticated_manager()
        install_apdu = self._install_apdu(
            bytes.fromhex("A000000152"),
            self.APPLET_AID,
            self.APPLET_AID,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = self._write_ijc(Path(temp_dir), self.PACKAGE_AID, self.APPLET_AID)
            result = mgr.install_cap_file_with_install_apdu(str(ijc_path), install_apdu)

        self.assertFalse(result)
        mgr.tp.transmit.assert_not_called()

    def test_odd_nibble_install_apdu_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            GlobalPlatformManager._normalize_install_for_install_apdu("80E60C000")

    def test_install_for_load_builds_explicit_lv_payload(self) -> None:
        mgr = self._make_authenticated_manager()

        mgr.install_for_load(
            "F000000001",
            "A000000151000000",
            "AABB",
            "C900",
            "1122",
        )

        mgr.tp.transmit.assert_called_once()
        call_args = mgr.tp.transmit.call_args
        self.assertEqual(
            call_args.args[0].upper(),
            "80E602001805F00000000108A00000015100000002AABB02C900021122",
        )
        self.assertEqual(call_args.kwargs, {"silent": True})


if __name__ == "__main__":
    unittest.main()
