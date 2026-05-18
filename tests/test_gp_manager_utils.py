# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``SCP03.logic.gp.GlobalPlatformManager`` utility methods.

Covers: get_config_key_fields_for_protocol, _parse_key_template_entries,
print_tlv_data, get_cplc_data, get_data_raw.
The card transport is replaced with a MagicMock so no physical or
simulated card is required.
"""

from __future__ import annotations

import io
import contextlib
import unittest
from unittest.mock import MagicMock

from SCP03.logic.gp import GlobalPlatformManager


def _make_manager() -> GlobalPlatformManager:
    mock_tp = MagicMock()
    mock_tp.session = None
    return GlobalPlatformManager(transport=mock_tp, config_keys={})


class GetConfigKeyFieldsTests(unittest.TestCase):

    def test_scp03_fields(self) -> None:
        mgr = _make_manager()
        fields = mgr.get_config_key_fields_for_protocol("SCP03")
        self.assertEqual(fields, ("scp03_kenc", "scp03_kmac", "scp03_dek", "scp03_kvn"))

    def test_scp02_fields(self) -> None:
        mgr = _make_manager()
        fields = mgr.get_config_key_fields_for_protocol("SCP02")
        self.assertEqual(fields, ("scp02_enc", "scp02_mac", "scp02_dek", "scp02_kvn"))

    def test_none_defaults_to_active_protocol(self) -> None:
        mgr = _make_manager()
        mgr.active_scp_protocol = "SCP02"
        fields = mgr.get_config_key_fields_for_protocol(None)
        self.assertEqual(fields[0], "scp02_enc")

    def test_returns_four_element_tuple(self) -> None:
        mgr = _make_manager()
        fields = mgr.get_config_key_fields_for_protocol()
        self.assertIsInstance(fields, tuple)
        self.assertEqual(len(fields), 4)


class ParseKeyTemplateEntriesTests(unittest.TestCase):

    def test_single_aes_entry(self) -> None:
        # C0 04  kid=01  kver=01  ktype=0x88(AES)  klen=16
        raw = bytes([0xC0, 0x04, 0x01, 0x01, 0x88, 0x10])
        entries = _make_manager()._parse_key_template_entries(raw)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["type"], "AES")
        self.assertEqual(entries[0]["id"], "01")
        self.assertEqual(entries[0]["version"], "01")
        self.assertEqual(entries[0]["length"], 16)

    def test_single_des_entry(self) -> None:
        # ktype=0x80 → "DES"
        raw = bytes([0xC0, 0x04, 0x02, 0xFF, 0x80, 0x08])
        entries = _make_manager()._parse_key_template_entries(raw)
        self.assertEqual(entries[0]["type"], "DES")

    def test_unknown_type_formatted_hex(self) -> None:
        raw = bytes([0xC0, 0x04, 0x01, 0x01, 0x77, 0x10])
        entries = _make_manager()._parse_key_template_entries(raw)
        self.assertEqual(entries[0]["type"], "77")

    def test_two_entries(self) -> None:
        entry = bytes([0xC0, 0x04, 0x01, 0x01, 0x88, 0x10])
        entries = _make_manager()._parse_key_template_entries(entry + entry)
        self.assertEqual(len(entries), 2)

    def test_empty_bytes_returns_empty_list(self) -> None:
        self.assertEqual(_make_manager()._parse_key_template_entries(b""), [])

    def test_garbage_returns_empty_list(self) -> None:
        # No 0xC0 tag → parser skips every byte.
        entries = _make_manager()._parse_key_template_entries(b"\xAA\xBB\xCC\xDD\xEE\xFF")
        self.assertEqual(entries, [])


class PrintTlvDataTests(unittest.TestCase):

    def _capture(self, tlv_dict: dict) -> str:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _make_manager().print_tlv_data(tlv_dict)
        return buf.getvalue()

    def test_bytes_value_printed(self) -> None:
        out = self._capture({0x84: b"\x01\x02"})
        self.assertIn("84", out)
        self.assertIn("0102", out.lower())

    def test_nested_dict_value(self) -> None:
        out = self._capture({0x20: {0x30: b"\xAB"}})
        self.assertIn("20", out)
        self.assertIn("30", out)

    def test_list_of_bytes_printed(self) -> None:
        out = self._capture({0x01: [b"\xCA\xFE"]})
        self.assertIn("01", out)
        self.assertIn("cafe", out.lower())

    def test_ascii_safe_string_appended(self) -> None:
        # A value that decodes to a safe ASCII sequence gets appended.
        out = self._capture({0x01: b"hello"})
        self.assertIn("hello", out)

    def test_four_digit_tag_hex(self) -> None:
        # Tags > 0xFF should render as 4-digit hex.
        out = self._capture({0x1234: b"\x00"})
        self.assertIn("1234", out)


class GetCplcDataTests(unittest.TestCase):

    def test_success_returns_bytes(self) -> None:
        mgr = _make_manager()
        mgr.tp.transmit.return_value = (b"\xAA" * 40, 0x90, 0x00)
        data, sw1, sw2 = mgr.get_cplc_data()
        self.assertIsNotNone(data)
        self.assertEqual(sw1, 0x90)
        self.assertEqual(sw2, 0x00)

    def test_failure_returns_none_data(self) -> None:
        mgr = _make_manager()
        mgr.tp.transmit.return_value = (b"", 0x69, 0x85)
        data, sw1, sw2 = mgr.get_cplc_data()
        self.assertIsNone(data)
        self.assertEqual(sw1, 0x69)

    def test_sends_correct_apdu(self) -> None:
        mgr = _make_manager()
        mgr.tp.transmit.return_value = (b"", 0x6A, 0x88)
        mgr.get_cplc_data()
        cmd = mgr.tp.transmit.call_args[0][0]
        self.assertIn("9F7F", cmd.upper())


class GetDataRawTests(unittest.TestCase):

    def test_2f00_uses_extended_command(self) -> None:
        mgr = _make_manager()
        mgr.tp.transmit.return_value = (b"\x01\x02", 0x90, 0x00)
        mgr.get_data_raw(0x2F, 0x00)
        cmd = mgr.tp.transmit.call_args[0][0]
        # Spec-mandated 5C-length-tag form for EF.DIR list
        self.assertIn("5C00", cmd.upper())

    def test_other_tag_uses_short_command(self) -> None:
        mgr = _make_manager()
        mgr.tp.transmit.return_value = (b"\xAB", 0x90, 0x00)
        mgr.get_data_raw(0x9F, 0x7F)
        cmd = mgr.tp.transmit.call_args[0][0]
        self.assertTrue(cmd.upper().startswith("80CA9F7F"))

    def test_returns_three_tuple(self) -> None:
        mgr = _make_manager()
        mgr.tp.transmit.return_value = (b"", 0x90, 0x00)
        result = mgr.get_data_raw(0x9F, 0x7F)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)


if __name__ == "__main__":
    unittest.main()
