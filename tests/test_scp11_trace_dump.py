# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
from __future__ import annotations

import unittest

from SCP11.shared.trace_dump import split_tlv_aware_chunks, summarize_eim_package_wrapper


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _tlv(tag_hex: str, value: bytes) -> bytes:
    return bytes.fromhex(tag_hex) + _encode_length(len(value)) + value


class Scp11TraceDumpTests(unittest.TestCase):
    def test_summarize_eim_package_wrapper_reports_outer_signed_fields(self) -> None:
        signed = _tlv(
            "30",
            b"".join(
                [
                    _tlv("80", b"1.3.6.1.4.1.53775.0.5"),
                    _tlv("5A", bytes.fromhex("89033023931110000000074959384263")),
                    _tlv("81", bytes.fromhex("010E")),
                    _tlv("82", bytes.fromhex("0000000000008ED3")),
                    _tlv("A1", _tlv("A8", _tlv("82", b"\x01"))),
                ]
            ),
        )
        payload = _tlv("BF51", signed + _tlv("5F37", b"\xAA" * 64))

        summary = summarize_eim_package_wrapper(payload)

        self.assertEqual(summary["root_tag"], "BF51")
        self.assertEqual(summary["complete"], "yes")
        self.assertEqual(summary["outer_eim_id"], "1.3.6.1.4.1.53775.0.5")
        self.assertEqual(summary["eid"], "89033023931110000000074959384263")
        self.assertEqual(summary["counter"], "270 (010E)")
        self.assertEqual(summary["eim_transaction_id"], "0000000000008ED3")
        self.assertEqual(summary["inner_choice"], "A1")
        self.assertEqual(summary["inner_card_request"], "A8")
        self.assertEqual(summary["signature_present"], "yes")
        self.assertEqual(summary["signature_len"], "64")

    def test_split_tlv_aware_chunks_prefers_tlv_boundaries(self) -> None:
        first = _tlv("80", b"aaaa")
        second = _tlv("81", b"bbbb")
        third = _tlv("82", b"cccc")
        payload = first + second + third

        chunks = split_tlv_aware_chunks(payload, 10)

        self.assertEqual(chunks, [first, second, third])
        self.assertEqual(b"".join(chunks), payload)
        self.assertTrue(all(len(chunk) <= 10 for chunk in chunks))

    def test_split_tlv_aware_chunks_splits_oversized_primitive(self) -> None:
        payload = _tlv("80", b"a" * 10)

        chunks = split_tlv_aware_chunks(payload, 6)

        self.assertEqual([len(chunk) for chunk in chunks], [6, 6])
        self.assertEqual(b"".join(chunks), payload)


if __name__ == "__main__":
    unittest.main()
