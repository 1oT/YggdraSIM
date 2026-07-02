# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest import mock

from SCP11.shared.trace_dump import (
    colorize_tlv_decode_line,
    format_hex_dump,
    format_tlv_decode,
    print_store_data_chunk_plan,
    split_tlv_aware_chunks,
    summarize_eim_package_wrapper,
)
from yggdrasim_common.nord_palette import NORD


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _tlv(tag_hex: str, value: bytes) -> bytes:
    return bytes.fromhex(tag_hex) + _encode_length(len(value)) + value


class Scp11TraceDumpTests(unittest.TestCase):
    def test_format_hex_dump_omits_offsets_by_default(self) -> None:
        lines = format_hex_dump(bytes(range(34)), width=16)

        self.assertEqual(lines[0], "    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
        self.assertFalse(any("000000:" in line for line in lines))

    def test_format_hex_dump_can_keep_offsets_when_requested(self) -> None:
        lines = format_hex_dump(bytes(range(2)), width=16, show_offsets=True)

        self.assertEqual(lines, ["    000000: 00 01"])

    def test_print_store_data_chunk_plan_is_compact_by_default(self) -> None:
        output = io.StringIO()

        with mock.patch.dict(os.environ, {"YGGDRASIM_GLOBAL_DEBUG": "0"}, clear=False):
            with contextlib.redirect_stdout(output):
                print_store_data_chunk_plan(
                    "TEST",
                    b"aaabbbbcc",
                    cla=0x81,
                    ins=0xE2,
                    final_p1=0x91,
                    p2_start=0,
                    chunk_size=4,
                    chunks=[b"aaa", b"bbbb", b"cc"],
                )

        rendered = output.getvalue()
        self.assertIn("[*] STORE DATA chunks for TEST:", rendered)
        self.assertIn("total_bytes=9", rendered)
        self.assertIn("Chunk 1/3 (3B) -> Chunk 2/3 (4B) -> Chunk 3/3 (2B)", rendered)
        self.assertNotIn("full payload", rendered)
        self.assertNotIn("offset=0", rendered)
        self.assertNotIn("boundary=tlv", rendered)

    def test_print_store_data_chunk_plan_uses_same_shape_for_single_chunk(self) -> None:
        output = io.StringIO()

        with mock.patch.dict(os.environ, {"YGGDRASIM_GLOBAL_DEBUG": "0"}, clear=False):
            with contextlib.redirect_stdout(output):
                print_store_data_chunk_plan(
                    "TEST",
                    b"abc",
                    cla=0x81,
                    ins=0xE2,
                    final_p1=0x91,
                    p2_start=0,
                    chunk_size=255,
                    chunks=[b"abc"],
                )

        rendered = output.getvalue()
        self.assertIn("[*] STORE DATA chunks for TEST:", rendered)
        self.assertIn("chunks=1", rendered)
        self.assertIn("Chunk 1/1 (3B)", rendered)
        self.assertNotIn("full payload", rendered)
        self.assertNotIn("offset=0", rendered)

    def test_print_store_data_chunk_plan_keeps_verbose_detail_under_debug(self) -> None:
        output = io.StringIO()

        with mock.patch.dict(os.environ, {"YGGDRASIM_GLOBAL_DEBUG": "1"}, clear=False):
            with contextlib.redirect_stdout(output):
                print_store_data_chunk_plan(
                    "TEST",
                    b"abc",
                    cla=0x81,
                    ins=0xE2,
                    final_p1=0x91,
                    p2_start=0,
                    chunk_size=255,
                    chunks=[b"abc"],
                )

        rendered = output.getvalue()
        self.assertIn("[*] STORE DATA chunk plan for TEST:", rendered)
        self.assertIn("[*] TEST full payload: 3 bytes", rendered)
        self.assertIn("offset=0", rendered)
        self.assertIn("boundary=tlv", rendered)

    def test_format_tlv_decode_names_and_decodes_eim_fields(self) -> None:
        payload = _tlv(
            "BF51",
            _tlv(
                "30",
                _tlv("80", b"1.3.6.1.4.1.53775.1.5.1.1")
                + _tlv("5A", bytes.fromhex("89033023931110000000074959384263"))
                + _tlv("81", bytes.fromhex("04"))
                + _tlv("82", bytes.fromhex("0000000000000AD8"))
                + _tlv(
                    "A1",
                    _tlv(
                        "A8",
                        _tlv("80", b"1.3.6.1.4.1.53775.0.5.1.1")
                        + _tlv("81", b"eim.t")
                        + _tlv("82", b"\x01")
                        + _tlv("83", b"\x02")
                        + _tlv("84", b"\x16")
                        + _tlv("87", bytes.fromhex("0780"))
                        + _tlv("89", b""),
                    ),
                ),
            )
            + _tlv("5F37", b"\xAA" * 64),
        )

        decoded = "\n".join(format_tlv_decode(payload))

        self.assertIn("BF51 EuiccPackageRequest/Result", decoded)
        self.assertIn('80 eimId len=25 value="1.3.6.1.4.1.53775.1.5.1.1"', decoded)
        self.assertIn("5A eidValue len=16 value=89033023931110000000074959384263", decoded)
        self.assertIn("81 counterValue len=1 value=4 (04)", decoded)
        self.assertIn('81 eimFqdn len=5 value="eim.t"', decoded)
        self.assertIn("82 eimIdType len=1 value=eimIdTypeOid (01)", decoded)
        self.assertIn("83 counterValue len=1 value=2 (02)", decoded)
        self.assertIn("84 associationToken len=1 value=22 (16)", decoded)
        self.assertIn("87 eimSupportedProtocol len=2 value=eimRetrieveHttps (0780)", decoded)
        self.assertIn("89 indirectProfileDownload len=0", decoded)
        self.assertIn("SEQUENCE len=111", decoded)
        self.assertIn("5F37 signature len=64 value=64B ECDSA-rs", decoded)
        self.assertNotIn("primitive", decoded)
        self.assertNotIn("constructed", decoded)
        self.assertNotIn("context [", decoded)

    def test_format_tlv_decode_names_direct_bf58_add_eim_fields(self) -> None:
        payload = _tlv(
            "BF58",
            _tlv(
                "A0",
                _tlv(
                    "30",
                    _tlv("80", b"1.3.6.1.4.1.53775.0.5.1.1")
                    + _tlv("81", b"eim.t")
                    + _tlv("82", b"\x01")
                    + _tlv("83", b"\x02"),
                ),
            ),
        )

        decoded = "\n".join(format_tlv_decode(payload))

        self.assertIn('81 eimFqdn len=5 value="eim.t"', decoded)
        self.assertIn("82 eimIdType len=1 value=eimIdTypeOid (01)", decoded)
        self.assertIn("83 counterValue len=1 value=2 (02)", decoded)
        self.assertNotIn("82 eimTransactionId len=1 value=01", decoded)

    def test_format_tlv_decode_names_profile_info_fields(self) -> None:
        profile_info = _tlv(
            "E3",
            _tlv("5A", bytes.fromhex("98640283900000000068"))
            + _tlv("4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
            + _tlv("9F70", b"\x01")
            + _tlv("91", b"Example")
            + _tlv("92", b"1oT Example")
            + _tlv("95", b"\x02")
            + _tlv("9F7B", b"\x00")
            + _tlv("9F67", b"\xFF"),
        )
        payload = _tlv("BF2D", _tlv("A0", profile_info))

        decoded = "\n".join(format_tlv_decode(payload))

        self.assertIn("E3 ProfileInfo len=", decoded)
        self.assertIn("5A ICCID len=10 value=89462038090000000086", decoded)
        self.assertIn("4F isdpAid len=16 value=A0000005591010FFFFFFFF8900001100", decoded)
        self.assertIn("9F70 profileState len=1 value=enabled (01)", decoded)
        self.assertIn('91 serviceProviderName len=7 value="Example"', decoded)
        self.assertIn('92 profileName len=11 value="1oT Example"', decoded)
        self.assertIn("95 profileClass len=1 value=operational (02)", decoded)
        self.assertIn("9F7B eCallIndication len=1 value=false (00)", decoded)
        self.assertIn("9F67 fallbackAllowed len=1 value=255 (FF)", decoded)

    def test_format_tlv_decode_renders_package_data_semantically(self) -> None:
        ecdsa_sha256_oid = bytes.fromhex("2A8648CE3D040302")
        ec_public_key_oid = bytes.fromhex("2A8648CE3D0201")
        prime256v1_oid = bytes.fromhex("2A8648CE3D030107")
        certificate = _tlv(
            "30",
            _tlv("A0", _tlv("02", b"\x02"))
            + _tlv("02", b"\x01")
            + _tlv("30", _tlv("06", ecdsa_sha256_oid))
            + _tlv("30", _tlv("0C", b"Example EUM"))
            + _tlv("30", _tlv("17", b"260101000000Z") + _tlv("17", b"270101000000Z"))
            + _tlv(
                "30",
                _tlv("06", ec_public_key_oid)
                + _tlv("06", prime256v1_oid)
                + _tlv("03", b"\x00\x04" + (b"\x11" * 64)),
            )
            + _tlv("30", _tlv("06", ecdsa_sha256_oid))
            + _tlv("03", b"\x00" + _tlv("30", _tlv("02", b"\x01") + _tlv("02", b"\x02"))),
        )
        euicc_info1 = _tlv(
            "BF20",
            _tlv("82", bytes.fromhex("020500"))
            + _tlv("A9", _tlv("04", b"\xAA" * 20))
            + _tlv("AA", _tlv("04", b"\xBB" * 20)),
        )
        euicc_info2 = _tlv(
            "BF22",
            _tlv("81", bytes.fromhex("020301"))
            + _tlv("82", bytes.fromhex("020500"))
            + _tlv("83", bytes.fromhex("931110"))
            + _tlv("8B", b"\x02")
            + _tlv("90", b"\x00")
            + _tlv("B4", _tlv("A0", _tlv("04", bytes.fromhex("010200"))) + _tlv("81", b"")),
        )
        response = _tlv(
            "BF52",
            _tlv(
                "A0",
                _tlv("A0", b"")
                + _tlv("81", b"dpp.example.test")
                + _tlv("A2", b"")
                + euicc_info1
                + euicc_info2
                + _tlv("83", b"lpa.example.test")
                + _tlv("84", b"\x15")
                + _tlv("A5", certificate),
            ),
        )

        decoded = "\n".join(format_tlv_decode(response))

        self.assertIn("BF52 PackageData len=", decoded)
        self.assertIn("A0 packageDataResponse len=", decoded)
        self.assertIn("[+] RetrieveNotificationsList", decoded)
        self.assertIn("Notification Entries", decoded)
        self.assertIn("[+] EuiccConfiguredData", decoded)
        self.assertIn("SM-DP+ Address", decoded)
        self.assertIn("dpp.example.test", decoded)
        self.assertIn("Root SM-DS Address", decoded)
        self.assertIn("lpa.example.test", decoded)
        self.assertIn("[+] EuiccInfo1", decoded)
        self.assertIn("Ver Supported", decoded)
        self.assertIn("v2.5.0 (020500)", decoded)
        self.assertIn("[+] EuiccInfo2", decoded)
        self.assertIn("Profile Version", decoded)
        self.assertIn("v2.3.1 (020301)", decoded)
        self.assertIn("[+] IPA/eIM Link Data", decoded)
        self.assertIn("Association Token", decoded)
        self.assertIn("21 (15)", decoded)
        self.assertIn("[+] GetCerts", decoded)
        self.assertIn("EUM Certificate", decoded)
        self.assertIn("Public Key Entries", decoded)
        self.assertIn("Object Identifiers", decoded)
        self.assertNotIn("counterValue", decoded)
        self.assertNotIn("eimTransactionId", decoded)
        self.assertNotIn("SEQUENCE len", decoded)

    def test_colorize_tlv_decode_line_does_not_treat_fallback_allowed_as_warning(self) -> None:
        line = "    9F67 fallbackAllowed len=1 value=255 (FF)"

        with mock.patch(
            "SCP11.shared.trace_dump.should_use_color",
            return_value=True,
        ):
            rendered = colorize_tlv_decode_line(line)

        self.assertIn(f"{NORD.HEADER}fallbackAllowed{NORD.RESET}", rendered)
        self.assertNotIn(f"{NORD.WARNING}9F67 fallbackAllowed", rendered)
        self.assertNotEqual(rendered, f"{NORD.WARNING}{line}{NORD.RESET}")

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
