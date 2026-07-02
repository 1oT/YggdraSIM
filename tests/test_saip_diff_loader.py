# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for ``Tools.ProfilePackage.saip_diff_loader``.

The loader is the entry point used by both the SAIP shell ``DIFF``
command and the diff TUI. It needs to accept exactly the same inputs
the inspector accepts via ``OPEN`` / ``USE``: transcode JSON, simulator
manifest JSON, raw DER, and hex-dump ``*.txt`` / ``*.hex`` / ``*.varder``
profiles.
The hex branch is the one that motivated this test module — the
shell previously reported ``"not recognised as transcode JSON ... and
DER decode failed"`` for hex-text inputs because the loader fed ASCII
hex directly into ``ProfileElementSequence.from_der``.

These tests stub out :mod:`pySim` (via the ``_decode_der_bytes`` shim)
so they run on a bare CI environment with no SAIP toolchain installed.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from Tools.ProfilePackage import saip_diff_loader as loader_module
from Tools.ProfilePackage.saip_diff_loader import (
    LoadedDocument,
    SaipDiffLoadError,
    _decode_hex_text_payload,
    _looks_like_ascii_hex,
    load_profile_document,
)


class HexHeuristicTests(unittest.TestCase):
    def test_recognises_uppercase_hex(self) -> None:
        self.assertTrue(_looks_like_ascii_hex("DEADBEEFDEADBEEF"))

    def test_recognises_lowercase_hex(self) -> None:
        self.assertTrue(_looks_like_ascii_hex("deadbeefdeadbeef"))

    def test_recognises_mixed_case(self) -> None:
        self.assertTrue(_looks_like_ascii_hex("DeAdBeEfDeAdBeEf"))

    def test_accepts_whitespace_and_newlines(self) -> None:
        text = "DE AD BE EF\n   DE\tAD BE EF"
        self.assertTrue(_looks_like_ascii_hex(text))

    def test_rejects_text_with_non_hex_letters(self) -> None:
        self.assertFalse(_looks_like_ascii_hex("hello world this is text"))

    def test_rejects_text_with_g(self) -> None:
        self.assertFalse(_looks_like_ascii_hex("DEADBEEFG0"))

    def test_rejects_too_short(self) -> None:
        self.assertFalse(_looks_like_ascii_hex("DE"))

    def test_rejects_only_whitespace(self) -> None:
        self.assertFalse(_looks_like_ascii_hex("   \t\n   \r\n  "))

    def test_rejects_empty_string(self) -> None:
        self.assertFalse(_looks_like_ascii_hex(""))


class HexDecodeTests(unittest.TestCase):
    _SOURCE = Path("/tmp/example.txt")

    def test_decodes_uppercase_hex(self) -> None:
        result_bytes, records = _decode_hex_text_payload("DEADBEEF", source=self._SOURCE)
        self.assertEqual(result_bytes, b"\xde\xad\xbe\xef")
        self.assertEqual(records, [])

    def test_decodes_lowercase_hex(self) -> None:
        result_bytes, records = _decode_hex_text_payload("deadbeef", source=self._SOURCE)
        self.assertEqual(result_bytes, b"\xde\xad\xbe\xef")
        self.assertEqual(records, [])

    def test_normalises_whitespace_and_newlines(self) -> None:
        text = "DE AD\nBE\tEF\r\n CA FE BA BE"
        result_bytes, records = _decode_hex_text_payload(text, source=self._SOURCE)
        self.assertEqual(result_bytes, b"\xde\xad\xbe\xef\xca\xfe\xba\xbe")
        self.assertEqual(records, [])

    def test_records_typed_placeholders(self) -> None:
        text = "DEADBEEF{probe:TEST:4:tail}CAFEBABE"
        result_bytes, records = _decode_hex_text_payload(text, source=self._SOURCE)
        self.assertEqual(len(result_bytes), 12)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].variable_name, "probe")
        self.assertEqual(records[0].byte_length, 4)
        self.assertEqual(records[0].modifier, "tail")

    def test_empty_payload_raises(self) -> None:
        with self.assertRaises(SaipDiffLoadError) as ctx:
            _decode_hex_text_payload("   \n\t  ", source=self._SOURCE)
        self.assertIn("empty", str(ctx.exception))

    def test_odd_length_payload_raises(self) -> None:
        with self.assertRaises(SaipDiffLoadError) as ctx:
            _decode_hex_text_payload("DEADBEE", source=self._SOURCE)
        self.assertIn("odd-length", str(ctx.exception))

    def test_non_hex_character_raises(self) -> None:
        with self.assertRaises(SaipDiffLoadError) as ctx:
            _decode_hex_text_payload("DEADBEEFXX", source=self._SOURCE)
        self.assertIn("non-hex", str(ctx.exception))


class _LoaderFixture(unittest.TestCase):
    """Common workspace + DER-stub plumbing for end-to-end loader tests."""

    def setUp(self) -> None:
        self._tempdir = TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.workspace_root = Path(self._tempdir.name).resolve()

    def _stub_der_decode(self) -> tuple[Any, list[bytes]]:
        """Return a context-manager that intercepts the DER decode step.

        The interceptor records every byte string handed to it and
        produces a tiny synthetic ``LoadedDocument`` so the rest of the
        loader machinery can be exercised without pySim. Returning the
        list lets the test assert exactly what bytes the hex branch
        produced.
        """
        observed: list[bytes] = []

        def fake_decode(
            path,
            der_bytes,
            workspace_root,
            *,
            shape="saip-der",
            placeholder_records=None,
        ):
            observed.append(bytes(der_bytes))
            return LoadedDocument(
                source_path=path,
                shape=shape,
                document={
                    "intro": [f"stubbed decode of {path.name}"],
                    "sections": {"length": len(der_bytes)},
                },
            )

        return fake_decode, observed


class LoadHexTextProfileTests(_LoaderFixture):
    _DER_HEX = "BF223080800101810400000000820100"

    def test_txt_extension_routes_through_hex_branch(self) -> None:
        path = self.workspace_root / "profile.txt"
        path.write_text(self._DER_HEX, encoding="utf-8")
        fake_decode, observed = self._stub_der_decode()
        with patch.object(loader_module, "_decode_der_bytes", fake_decode):
            loaded = load_profile_document(path, workspace_root=self.workspace_root)
        self.assertEqual(loaded.shape, "saip-hex")
        self.assertEqual(observed, [bytes.fromhex(self._DER_HEX)])

    def test_hex_extension_routes_through_hex_branch(self) -> None:
        path = self.workspace_root / "profile.hex"
        path.write_text(self._DER_HEX, encoding="utf-8")
        fake_decode, observed = self._stub_der_decode()
        with patch.object(loader_module, "_decode_der_bytes", fake_decode):
            loaded = load_profile_document(path, workspace_root=self.workspace_root)
        self.assertEqual(loaded.shape, "saip-hex")
        self.assertEqual(observed, [bytes.fromhex(self._DER_HEX)])

    def test_varder_extension_routes_through_hex_branch_and_strips_bom(self) -> None:
        path = self.workspace_root / "profile.varder"
        path.write_text(self._DER_HEX, encoding="utf-8-sig")
        fake_decode, observed = self._stub_der_decode()
        with patch.object(loader_module, "_decode_der_bytes", fake_decode):
            loaded = load_profile_document(path, workspace_root=self.workspace_root)
        self.assertEqual(loaded.shape, "saip-hex")
        self.assertEqual(observed, [bytes.fromhex(self._DER_HEX)])

    def test_extensionless_ascii_hex_is_sniffed(self) -> None:
        path = self.workspace_root / "profile_dump"
        path.write_text(self._DER_HEX, encoding="utf-8")
        fake_decode, observed = self._stub_der_decode()
        with patch.object(loader_module, "_decode_der_bytes", fake_decode):
            loaded = load_profile_document(path, workspace_root=self.workspace_root)
        self.assertEqual(loaded.shape, "saip-hex")
        self.assertEqual(observed, [bytes.fromhex(self._DER_HEX)])

    def test_multiline_hex_dump_is_normalised(self) -> None:
        body = "\n".join(self._DER_HEX[i : i + 8] for i in range(0, len(self._DER_HEX), 8))
        path = self.workspace_root / "profile.txt"
        path.write_text(body + "\n", encoding="utf-8")
        fake_decode, observed = self._stub_der_decode()
        with patch.object(loader_module, "_decode_der_bytes", fake_decode):
            loaded = load_profile_document(path, workspace_root=self.workspace_root)
        self.assertEqual(loaded.shape, "saip-hex")
        self.assertEqual(observed, [bytes.fromhex(self._DER_HEX)])

    def test_lowercase_hex_in_txt_is_accepted(self) -> None:
        path = self.workspace_root / "profile.txt"
        path.write_text(self._DER_HEX.lower(), encoding="utf-8")
        fake_decode, observed = self._stub_der_decode()
        with patch.object(loader_module, "_decode_der_bytes", fake_decode):
            loaded = load_profile_document(path, workspace_root=self.workspace_root)
        self.assertEqual(loaded.shape, "saip-hex")
        self.assertEqual(observed, [bytes.fromhex(self._DER_HEX)])

    def test_odd_length_hex_in_txt_raises_clear_error(self) -> None:
        path = self.workspace_root / "profile.txt"
        path.write_text("DEADBEE", encoding="utf-8")
        with self.assertRaises(SaipDiffLoadError) as ctx:
            load_profile_document(path, workspace_root=self.workspace_root)
        message = str(ctx.exception)
        self.assertIn("odd-length", message)
        self.assertNotIn("not recognised as transcode JSON", message)

    def test_non_hex_in_txt_raises_clear_error(self) -> None:
        path = self.workspace_root / "profile.txt"
        path.write_text("DEADBEEFZZ", encoding="utf-8")
        with self.assertRaises(SaipDiffLoadError) as ctx:
            load_profile_document(path, workspace_root=self.workspace_root)
        message = str(ctx.exception)
        self.assertIn("non-hex", message)
        self.assertNotIn("not recognised as transcode JSON", message)


class LoadProfileDocumentRoutingTests(_LoaderFixture):
    """Ensure pre-existing JSON / DER routing isn't broken by the hex branch."""

    def test_transcode_json_is_routed_unchanged(self) -> None:
        payload = {
            "intro": ["round-trip canonical"],
            "sections": {"profileHeader": {"iccid": "8988300000046631124"}},
        }
        path = self.workspace_root / "profile.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        loaded = load_profile_document(path, workspace_root=self.workspace_root)
        self.assertEqual(loaded.shape, "transcode-json")
        self.assertIn("intro", loaded.document)

    def test_simulator_manifest_is_routed_unchanged(self) -> None:
        payload = {
            "profile_name": "demo-profile",
            "iccid": "8988300000046631124",
            "imsi": "001010000004663",
            "nodes": [],
        }
        path = self.workspace_root / "profile_image.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        loaded = load_profile_document(path, workspace_root=self.workspace_root)
        self.assertEqual(loaded.shape, "simcard-manifest")
        self.assertEqual(loaded.document["sections"]["profileHeader"]["iccid"], payload["iccid"])

    def test_binary_der_extension_skips_hex_branch(self) -> None:
        path = self.workspace_root / "profile.der"
        binary_blob = b"\x30\x82\x00\x10" + b"\x00" * 16
        path.write_bytes(binary_blob)
        fake_decode, observed = self._stub_der_decode()
        with patch.object(loader_module, "_decode_der_bytes", fake_decode):
            loaded = load_profile_document(path, workspace_root=self.workspace_root)
        self.assertEqual(loaded.shape, "saip-der")
        self.assertEqual(observed, [binary_blob])

    def test_random_text_with_extensionless_path_falls_through_to_combined_error(self) -> None:
        # A short non-hex file shouldn't trigger the sniff and should
        # therefore land in the legacy combined-error path so existing
        # callers / users keep their familiar wording. We mock the DER
        # decoder so the expectation holds regardless of whether
        # pySim is installed in the test environment.
        path = self.workspace_root / "junk"
        path.write_text("hello", encoding="utf-8")

        def fail_decode(
            decoded_path,
            der_bytes,
            workspace_root,
            *,
            shape="saip-der",
            placeholder_records=None,
        ):
            raise SaipDiffLoadError(
                f"{decoded_path}: DER decode failed: stub bypass for unit test"
            )

        with patch.object(loader_module, "_decode_der_bytes", fail_decode):
            with self.assertRaises(SaipDiffLoadError) as ctx:
                load_profile_document(path, workspace_root=self.workspace_root)
        message = str(ctx.exception)
        self.assertIn("not recognised as transcode JSON", message)
        self.assertIn("DER decode failed", message)

    def test_missing_file_reports_clearly(self) -> None:
        path = self.workspace_root / "no-such-file.txt"
        with self.assertRaises(SaipDiffLoadError) as ctx:
            load_profile_document(path, workspace_root=self.workspace_root)
        self.assertIn("file not found", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
