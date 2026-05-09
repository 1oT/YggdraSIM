# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SCP11/local_access/payload_diff.py public functions.

Covers: compute_diff_spans, describe_offset, slice_hex, format_analysis,
        decode_payload_bytes (indirectly via read_payload_file).
"""

from __future__ import annotations

import unittest

try:
    from SCP11.local_access.payload_diff import (
        compute_diff_spans,
        decode_payload_bytes,
        describe_offset,
        format_analysis,
        slice_hex,
    )
    _IMPORT_OK = True
except (ImportError, ModuleNotFoundError):
    _IMPORT_OK = False


_SKIP = unittest.skipUnless(_IMPORT_OK, "asn1crypto / SCP11 deps not installed")


# ---------------------------------------------------------------------------
# decode_payload_bytes
# ---------------------------------------------------------------------------

@_SKIP
class DecodePayloadBytesTests(unittest.TestCase):

    def test_plain_hex_ascii_decoded(self) -> None:
        result = decode_payload_bytes(b"DEADBEEF")
        self.assertEqual(result, bytes.fromhex("DEADBEEF"))

    def test_hex_with_whitespace_decoded(self) -> None:
        result = decode_payload_bytes(b"DE AD BE EF\n")
        self.assertEqual(result, bytes.fromhex("DEADBEEF"))

    def test_raw_binary_returned_as_is(self) -> None:
        payload = bytes(range(16))
        result = decode_payload_bytes(payload)
        self.assertEqual(result, payload)

    def test_odd_length_hex_returned_as_is(self) -> None:
        result = decode_payload_bytes(b"ABC")
        self.assertEqual(result, b"ABC")

    def test_non_hex_characters_returned_as_is(self) -> None:
        result = decode_payload_bytes(b"hello world")
        self.assertEqual(result, b"hello world")


# ---------------------------------------------------------------------------
# compute_diff_spans
# ---------------------------------------------------------------------------

@_SKIP
class ComputeDiffSpansTests(unittest.TestCase):

    def test_identical_returns_empty_list(self) -> None:
        data = bytes([0x01, 0x02, 0x03])
        self.assertEqual(compute_diff_spans(data, data), [])

    def test_single_byte_diff(self) -> None:
        left = bytes([0x01, 0x02, 0x03])
        right = bytes([0x01, 0xFF, 0x03])
        spans = compute_diff_spans(left, right)
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0], (1, 2))

    def test_length_difference_adds_trailing_span(self) -> None:
        left = bytes([0x01, 0x02, 0x03, 0x04])
        right = bytes([0x01, 0x02])
        spans = compute_diff_spans(left, right)
        # trailing length span should be included
        self.assertTrue(any(end >= 3 for _, end in spans))

    def test_entirely_different(self) -> None:
        left = bytes([0xAA, 0xBB])
        right = bytes([0x11, 0x22])
        spans = compute_diff_spans(left, right)
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0], (0, 2))

    def test_empty_sequences_no_spans(self) -> None:
        self.assertEqual(compute_diff_spans(b"", b""), [])


# ---------------------------------------------------------------------------
# describe_offset
# ---------------------------------------------------------------------------

@_SKIP
class DescribeOffsetTests(unittest.TestCase):

    def _ranges(self) -> list:
        return [(0, 4, "header"), (4, 8, "body"), (8, 12, "footer")]

    def test_offset_in_first_range(self) -> None:
        result = describe_offset(0, self._ranges())
        self.assertIn("header", result)

    def test_offset_in_middle_range(self) -> None:
        result = describe_offset(5, self._ranges())
        self.assertIn("body", result)

    def test_offset_beyond_all_ranges(self) -> None:
        result = describe_offset(100, self._ranges())
        self.assertIn("no top-level", result)

    def test_empty_ranges_returns_no_match(self) -> None:
        result = describe_offset(0, [])
        self.assertIn("no top-level", result)


# ---------------------------------------------------------------------------
# slice_hex
# ---------------------------------------------------------------------------

@_SKIP
class SliceHexTests(unittest.TestCase):

    def test_returns_uppercase_hex(self) -> None:
        result = slice_hex(bytes([0xDE, 0xAD, 0xBE, 0xEF]), 0)
        self.assertEqual(result, "DEADBEEF")

    def test_slice_from_offset(self) -> None:
        result = slice_hex(bytes([0x01, 0x02, 0x03, 0x04]), 2, 2)
        self.assertEqual(result, "0304")

    def test_size_capped_at_data_end(self) -> None:
        result = slice_hex(bytes([0xAA, 0xBB]), 0, 100)
        self.assertEqual(result, "AABB")

    def test_empty_bytes_returns_empty_string(self) -> None:
        self.assertEqual(slice_hex(b"", 0), "")


# ---------------------------------------------------------------------------
# format_analysis
# ---------------------------------------------------------------------------

@_SKIP
class FormatAnalysisTests(unittest.TestCase):

    def _make_equal_analysis(self, payload: bytes) -> dict:
        import hashlib
        h = hashlib.sha256(payload).hexdigest().upper()
        return {
            "left_len": len(payload),
            "right_len": len(payload),
            "left_sha256": h,
            "right_sha256": h,
            "equal": True,
            "diff_spans": [],
            "first_diff": None,
            "left_ranges": [],
            "right_ranges": [],
        }

    def _make_diff_analysis(self, left: bytes, right: bytes) -> dict:
        import hashlib
        spans = compute_diff_spans(left, right)
        first_diff = spans[0][0] if spans else None
        return {
            "left_len": len(left),
            "right_len": len(right),
            "left_sha256": hashlib.sha256(left).hexdigest().upper(),
            "right_sha256": hashlib.sha256(right).hexdigest().upper(),
            "equal": left == right,
            "diff_spans": spans,
            "first_diff": first_diff,
            "left_ranges": [],
            "right_ranges": [],
        }

    def test_equal_payloads_reports_no_diff(self) -> None:
        payload = bytes([0x01, 0x02, 0x03])
        analysis = self._make_equal_analysis(payload)
        result = format_analysis(analysis, payload, payload, "left.bin", "right.bin")
        self.assertIn("No differing spans", result)

    def test_diff_payloads_reports_offset(self) -> None:
        left = bytes([0x01, 0x02, 0x03])
        right = bytes([0x01, 0xFF, 0x03])
        analysis = self._make_diff_analysis(left, right)
        result = format_analysis(analysis, left, right, "left.bin", "right.bin")
        self.assertIn("first_diff_offset", result)

    def test_output_includes_filenames(self) -> None:
        payload = bytes([0x00])
        analysis = self._make_equal_analysis(payload)
        result = format_analysis(analysis, payload, payload, "a.bin", "b.bin")
        self.assertIn("a.bin", result)
        self.assertIn("b.bin", result)


if __name__ == "__main__":
    unittest.main()
