# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Regression tests for SCP03 wizard APDU builders."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from SCP03.core.cap import CapFileParser
from SCP03.interface.wizards import InteractiveWizards


def _component(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + len(payload).to_bytes(2, "big") + payload


def _write_ijc(directory: Path, package_aid: bytes, applet_aid: bytes) -> Path:
    header_payload = (b"\x00" * 9) + bytes([len(package_aid)]) + package_aid
    applet_payload = bytes([1, len(applet_aid)]) + applet_aid + b"\x00\x00"
    component_blob = _component(0x01, header_payload) + _component(0x03, applet_payload)
    load_block = CapFileParser._wrap_load_file_block(component_blob)
    path = directory / "sample.ijc"
    path.write_bytes(load_block)
    return path


class WizardInstallParameterBuilderTests(unittest.TestCase):
    def test_full_empty_c9_tlv_is_preserved(self) -> None:
        result = InteractiveWizards._coerce_c9_install_parameter("C900")
        self.assertEqual(result.hex().upper(), "C900")

    def test_full_non_empty_c9_tlv_is_preserved(self) -> None:
        result = InteractiveWizards._coerce_c9_install_parameter("C9020102")
        self.assertEqual(result.hex().upper(), "C9020102")

    def test_raw_c9_value_is_wrapped(self) -> None:
        result = InteractiveWizards._coerce_c9_install_parameter("0102")
        self.assertEqual(result.hex().upper(), "C9020102")

    def test_lv_field_over_255_bytes_does_not_truncate(self) -> None:
        result = InteractiveWizards._build_lv_field("AA" * 256)
        self.assertEqual(result, b"\x00")

    def test_store_data_p1_must_be_one_byte(self) -> None:
        with self.assertRaises(ValueError):
            InteractiveWizards._build_store_data_with_params("CAFE", "9000", "00")

    def test_oversized_ber_length_raises(self) -> None:
        with self.assertRaises(ValueError):
            InteractiveWizards._encode_ber_tlv_length(0x10000)


class CapInstallWizardExecutionTests(unittest.TestCase):
    def test_execute_uses_generated_install_apdu(self) -> None:
        package_aid = bytes.fromhex("F000000001")
        applet_aid = bytes.fromhex("F00000000101")
        expected_install_apdu = (
            "80E60C001A"
            "05F000000001"
            "06F00000000101"
            "06F00000000101"
            "0100"
            "02C900"
            "00"
        )

        class FakeGp:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, int | None]] = []

            def authenticate(self) -> bool:
                return True

            def install_cap_file_with_install_apdu(
                self,
                filename: str,
                install_apdu: str,
                load_chunk_size: int | None = None,
            ) -> bool:
                self.calls.append((filename, install_apdu, load_chunk_size))
                return True

        fake_gp = FakeGp()
        answers = iter(["", "", "", "N", "", "N", "", "Y"])

        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(Path(temp_dir), package_aid, applet_aid)
            output = io.StringIO()
            with patch("builtins.input", lambda _prompt="": next(answers)):
                with contextlib.redirect_stdout(output):
                    InteractiveWizards.build_install_apdu(None, str(ijc_path), fake_gp)

        self.assertIn(expected_install_apdu, output.getvalue())
        self.assertEqual(len(fake_gp.calls), 1)
        self.assertEqual(fake_gp.calls[0][1], expected_install_apdu)
        self.assertEqual(fake_gp.calls[0][2], 240)


if __name__ == "__main__":
    unittest.main()
