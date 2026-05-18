# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``saip_arr_record_picker``."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_arr_record_picker as A


class ReferenceCodecTests(unittest.TestCase):

    def test_long_reference_round_trip(self) -> None:
        encoded = A.encode_arr_reference("2F06", 1)
        self.assertEqual(encoded, "2F0601")
        decoded = A.decode_arr_reference(encoded)
        self.assertEqual(decoded["kind"], "long")
        self.assertEqual(decoded["file_id"], "2F06")
        self.assertEqual(decoded["record_index"], 1)

    def test_short_reference_decodes_sfi_and_rec(self) -> None:
        decoded = A.decode_arr_reference("0B")
        self.assertEqual(decoded["kind"], "short")
        self.assertEqual(decoded["short_efid"], 1)
        self.assertEqual(decoded["record_index"], 3)

    def test_invalid_record_index(self) -> None:
        with self.assertRaises(ValueError):
            A.encode_arr_reference("2F06", 0)
        with self.assertRaises(ValueError):
            A.encode_arr_reference("2F06", 255)

    def test_invalid_fid_length(self) -> None:
        with self.assertRaises(ValueError):
            A.encode_arr_reference("2F", 1)


class ProjectionTests(unittest.TestCase):

    def _records(self) -> list[dict]:
        return [
            {
                "record": 1,
                "decoded": {
                    "summary": "admin",
                    "ruleCount": 1,
                    "rules": [{"accessModes": ["READ", "UPDATE"]}],
                },
                "raw_hex": "8001019000",
            },
            {
                "record": 2,
                "decoded": {
                    "summary": "read-only",
                    "ruleCount": 1,
                    "rules": [{"accessModes": ["READ"]}],
                },
                "raw_hex": "80010100",
            },
            {"record": 3, "empty": True, "raw_hex": "FFFFFF"},
        ]

    def test_project_flags_empty_record(self) -> None:
        rows = A.project_records(self._records())
        self.assertEqual(rows[2]["empty"], True)
        self.assertEqual(rows[2]["rule_count"], 0)

    def test_find_match_require_modes(self) -> None:
        rows = A.project_records(self._records())
        self.assertEqual(A.find_matching_record(rows, require_modes=["READ"]), 1)

    def test_find_match_forbid_modes(self) -> None:
        rows = A.project_records(self._records())
        self.assertEqual(
            A.find_matching_record(rows, require_modes=["READ"], forbid_modes=["UPDATE"]),
            2,
        )

    def test_find_match_no_hit_returns_none(self) -> None:
        rows = A.project_records(self._records())
        self.assertIsNone(
            A.find_matching_record(rows, require_modes=["DELETE"]),
        )


if __name__ == "__main__":
    unittest.main()
