# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Personalisation-data CSV interop for the token sidecar.

These tests exercise ``parse_csv_personalisation``, ``load_sidecar_from_csv``
and ``dump_sidecar_to_csv`` against the TCA SAIP personalisation-data
file layout (a plain two-column ``name,hex`` CSV with optional ``#``
comment lines separating per-package blocks).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_token_sidecar import (
    TokenSidecarError,
    dump_sidecar_to_csv,
    load_sidecar_from_csv,
    parse_csv_personalisation,
)


_SINGLE_BLOCK_CSV = """\
ICCID,8988201234567890123F
IMSI,001011234567801F
pinAppl1,30303030
"""

_MULTI_BLOCK_CSV = """\
# Profile Package 1
ICCID,8988201234567890123F
IMSI,001011234567801F
pinAppl1,30303030

# Profile Package 2
ICCID,8988201234567890124F
IMSI,001011234567802F
pinAppl1,31313131
"""


class CsvParserTests(unittest.TestCase):
    """``parse_csv_personalisation`` block accounting and shape validation."""

    def test_parses_single_block(self) -> None:
        blocks = parse_csv_personalisation(_SINGLE_BLOCK_CSV)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(
            sorted(blocks[0].keys()), ["ICCID", "IMSI", "pinAppl1"]
        )
        self.assertEqual(blocks[0]["ICCID"], {"hex": "8988201234567890123F"})

    def test_splits_on_comment_lines(self) -> None:
        blocks = parse_csv_personalisation(_MULTI_BLOCK_CSV)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0]["ICCID"]["hex"], "8988201234567890123F")
        self.assertEqual(blocks[1]["ICCID"]["hex"], "8988201234567890124F")
        self.assertEqual(blocks[1]["pinAppl1"]["hex"], "31313131")

    def test_accepts_0x_prefix_and_spaces(self) -> None:
        blocks = parse_csv_personalisation("ICCID,0x 89 88 20 12 34\n")
        self.assertEqual(blocks[0]["ICCID"]["hex"], "8988201234")

    def test_rejects_odd_length_hex(self) -> None:
        with self.assertRaises(TokenSidecarError):
            parse_csv_personalisation("ICCID,ABC\n")

    def test_rejects_duplicate_name_within_block(self) -> None:
        csv_text = "ICCID,8988201234567890123F\nICCID,8988201234567890124F\n"
        with self.assertRaises(TokenSidecarError):
            parse_csv_personalisation(csv_text)

    def test_rejects_missing_comma(self) -> None:
        with self.assertRaises(TokenSidecarError):
            parse_csv_personalisation("ICCID 8988201234567890123F\n")


class CsvRoundTripTests(unittest.TestCase):
    """``load_sidecar_from_csv`` → ``dump_sidecar_to_csv`` round trip."""

    def test_single_block_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            base = Path(raw_dir)
            (base / "in.csv").write_text(_SINGLE_BLOCK_CSV, encoding="utf-8")
            sidecars = load_sidecar_from_csv(base / "in.csv")
            self.assertEqual(len(sidecars), 1)
            self.assertEqual(
                sidecars[0]["__ygg_placeholder_style__"], "brace"
            )
            dump_sidecar_to_csv(base / "out.csv", sidecars[0])
            rebuilt = parse_csv_personalisation(
                (base / "out.csv").read_text(encoding="utf-8")
            )
            self.assertEqual(
                rebuilt[0]["IMSI"]["hex"], "001011234567801F"
            )

    def test_multi_block_round_trip_preserves_count(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            base = Path(raw_dir)
            (base / "in.csv").write_text(_MULTI_BLOCK_CSV, encoding="utf-8")
            sidecars = load_sidecar_from_csv(base / "in.csv")
            self.assertEqual(len(sidecars), 2)
            dump_sidecar_to_csv(
                base / "out.csv",
                sidecars,
                block_labels=["Profile A", "Profile B"],
            )
            text = (base / "out.csv").read_text(encoding="utf-8")
            self.assertIn("# Profile A", text)
            self.assertIn("# Profile B", text)
            rebuilt = parse_csv_personalisation(text)
            self.assertEqual(len(rebuilt), 2)
            self.assertEqual(
                rebuilt[1]["pinAppl1"]["hex"], "31313131"
            )

    def test_dump_skips_pattern_only_defs(self) -> None:
        sidecar = {
            "__ygg_placeholder_style__": "brace",
            "__ygg_token_defs__": {
                "ICCID": {"hex": "8988201234567890123F"},
                "OPC_PATTERN": {"pattern_hex": "11", "byte_len": 16},
            },
            "__ygg_sidecar_meta__": {"schema": "ygg.token_sidecar.v1"},
        }
        with tempfile.TemporaryDirectory() as raw_dir:
            path = Path(raw_dir) / "out.csv"
            dump_sidecar_to_csv(path, sidecar)
            text = path.read_text(encoding="utf-8")
            self.assertIn("ICCID,", text)
            self.assertNotIn("OPC_PATTERN", text)


if __name__ == "__main__":
    unittest.main()
