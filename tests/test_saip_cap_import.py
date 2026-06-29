# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``saip_cap_import`` — CAP / IJC AID extraction."""

from __future__ import annotations

import io
import struct
import unittest
import zipfile

from Tools.ProfilePackage import saip_cap_import as I


def _component(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + struct.pack(">H", len(payload)) + payload


def _header_payload(package_aid_hex: str) -> bytes:
    aid = bytes.fromhex(package_aid_hex)
    return (
        b"\xDE\xCA\xFF\xED"
        + bytes([0, 2, 0, 2, 1])
        + bytes([len(aid)])
        + aid
    )


def _applet_payload(applet_aid_hexes: list[str]) -> bytes:
    out = bytearray([len(applet_aid_hexes)])
    for aid_hex in applet_aid_hexes:
        aid = bytes.fromhex(aid_hex)
        out.append(len(aid))
        out += aid
        out += b"\x00\x10"  # install_method_offset placeholder
    return bytes(out)


def _import_payload(import_aid_hexes: list[str]) -> bytes:
    out = bytearray([len(import_aid_hexes)])
    for aid_hex in import_aid_hexes:
        out += bytes([0, 2])  # package_minor / package_major
        aid = bytes.fromhex(aid_hex)
        out.append(len(aid))
        out += aid
    return bytes(out)


class IjcParsingTests(unittest.TestCase):

    def test_flat_ijc_extracts_all_aids(self) -> None:
        ijc = (
            _component(1, _header_payload("A000000087100201"))
            + _component(3, _applet_payload(["A000000087100201AB"]))
            + _component(4, _import_payload(["A0000000620201"]))
        )
        result = I.parse_cap_or_ijc(ijc)
        self.assertEqual(result["format"], "ijc")
        self.assertEqual(result["package_aid_hex"], "A000000087100201")
        self.assertEqual(result["applet_aids"], ["A000000087100201AB"])
        self.assertEqual(result["import_aids"], ["A0000000620201"])

    def test_ijc_missing_header(self) -> None:
        ijc = _component(3, _applet_payload(["A000000087100201AB"]))
        result = I.parse_cap_or_ijc(ijc)
        self.assertIn("Header component missing", " ".join(result["warnings"]))
        self.assertEqual(result["package_aid_hex"], "")
        self.assertEqual(result["applet_aids"], ["A000000087100201AB"])


class CapJarTests(unittest.TestCase):

    def test_cap_archive_extracts_aids(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("foo/Header.cap", _component(1, _header_payload("A000000087100202")))
            zf.writestr("foo/Applet.cap", _component(3, _applet_payload(["A000000087100202CD"])))
            zf.writestr("foo/Import.cap", _component(4, _import_payload(["A0000000620202"])))
        result = I.parse_cap_or_ijc(buf.getvalue())
        self.assertEqual(result["format"], "cap")
        self.assertEqual(result["package_aid_hex"], "A000000087100202")
        self.assertEqual(result["applet_aids"], ["A000000087100202CD"])
        self.assertEqual(result["import_aids"], ["A0000000620202"])


class InputValidationTests(unittest.TestCase):

    def test_empty_payload_rejected(self) -> None:
        with self.assertRaises(ValueError):
            I.parse_cap_or_ijc(b"")

    def test_non_bytes_rejected(self) -> None:
        with self.assertRaises(ValueError):
            I.parse_cap_or_ijc("not-bytes")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
