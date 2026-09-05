# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for structural and header lint rules.

Covers: YRL-DOC-001, YRL-SEQ-001..004, YRL-ICC-001/010,
        YRL-IMS-001..007, YRL-SVC-001, YRL-HDR-001,
        YRL-UST-001, YRL-UST-002.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.lint_engine import SaipProfileLinter

# ---------------------------------------------------------------------------
# Minimal document factories
# ---------------------------------------------------------------------------

_GOOD_ICCID_HEX = "89882012345678901230"
# ICCID above, nibble-swapped for EF.ICCID fillFileContent
_GOOD_ICCID_EF_HEX = "9888021054637281092300"[:20]  # computed below; keep in sync

# Compute the swapped form programmatically so we don't have to maintain it manually.
def _swap_nibbles(h: str) -> str:
    out = []
    for i in range(0, len(h), 2):
        pair = h[i : i + 2]
        out.append(pair[1] + pair[0])
    return "".join(out)


_GOOD_ICCID_EF_HEX = _swap_nibbles(_GOOD_ICCID_HEX)

# A valid 15-digit IMSI (001010000000001) encoded as EF.IMSI.
# TS 31.102 §4.2.2: length byte 0x08, then parity byte = (first_digit<<4)|parity_nibble
# where parity_nibble = 0x1 for odd digit count, 0x9 for even.
# 15 digits (odd), first digit 0 -> parity byte 0x01; remaining 14 digits nibble-swapped.
_GOOD_IMSI_HEX = "080110100000000010"


def _minimal_doc(*section_keys_and_types: tuple[str, str]) -> dict:
    """Build a minimal profile document from (key, type) pairs."""
    sections: dict = {}
    for idx, (key, pe_type) in enumerate(section_keys_and_types):
        sections[key] = {"identification": idx, "type": pe_type}
    return {"sections": sections}


def _standard_doc(extra_sections: dict | None = None) -> dict:
    """Minimal well-formed 4-PE profile with header/mf/end."""
    sections: dict = {
        "header": {
            "iccid": {"hex": _GOOD_ICCID_HEX},
            "eUICC-Mandatory-services": {},
            "profileType": "telecom",
            "identification": 0,
            "type": "header",
        },
        "mf": {"identification": 1, "type": "mf"},
        "end": {"identification": 2, "type": "end"},
    }
    if extra_sections:
        sections.update(extra_sections)
    return {"sections": sections}


def _doc_with_usim(imsi_hex: str | None = None, ust_hex: str | None = None) -> dict:
    """Standard doc plus a minimal USIM section, with end kept last."""
    usim: dict = {
        "identification": 10,
        "type": "usim",
        "choices": [
            {
                "ef-imsi": {
                    "file": {
                        "fileManagementCMD": [
                            {"@": ["createFCP", {"fillFileContent": {"hex": imsi_hex or _GOOD_IMSI_HEX}}]}
                        ]
                    }
                }
            }
        ],
    }
    if ust_hex is not None:
        usim["choices"].append(
            {
                "ef-ust": {
                    "file": {
                        "fileManagementCMD": [
                            {"@": ["createFCP", {"fillFileContent": {"hex": ust_hex}}]}
                        ]
                    }
                }
            }
        )
    doc = _standard_doc()
    # Insert usim before end so the sequence is header/mf/usim/end.
    sections = dict(doc["sections"])
    end = sections.pop("end")
    sections["usim"] = usim
    sections["end"] = end
    return {"sections": sections}


def _lint(doc: dict) -> list:
    linter = SaipProfileLinter(strict=False)
    report = linter.lint_decoded_document(
        decoded_document=doc,
        profile_label="test.der",
        check_return_code=None,
        check_stderr="",
        emit_missing_check_finding=False,
    )
    return report.findings


def _codes(doc: dict) -> list[str]:
    return [f.code for f in _lint(doc)]


# ---------------------------------------------------------------------------
# YRL-DOC-001 — empty section list
# ---------------------------------------------------------------------------

class DocEmptyTests(unittest.TestCase):
    """YRL-DOC-001: no decoded PEs found."""

    def test_empty_sections_fails(self) -> None:
        codes = _codes({"sections": {}})
        self.assertIn("YRL-DOC-001", codes)

    def test_non_empty_passes(self) -> None:
        codes = _codes(_standard_doc())
        self.assertNotIn("YRL-DOC-001", codes)


# ---------------------------------------------------------------------------
# YRL-SEQ-001..004 — PE sequence structure
# ---------------------------------------------------------------------------

class PeSequenceTests(unittest.TestCase):
    """YRL-SEQ-001..004: structural position checks."""

    def test_seq001_fewer_than_3_pes(self) -> None:
        doc = _minimal_doc(("header", "header"), ("end", "end"))
        codes = _codes(doc)
        self.assertIn("YRL-SEQ-001", codes)

    def test_seq002_first_pe_not_header(self) -> None:
        doc = _minimal_doc(
            ("mf", "mf"), ("header", "header"), ("usim", "usim"), ("end", "end")
        )
        codes = _codes(doc)
        self.assertIn("YRL-SEQ-002", codes)

    def test_seq003_second_pe_not_mf(self) -> None:
        doc = _minimal_doc(
            ("header", "header"), ("usim", "usim"), ("end", "end")
        )
        codes = _codes(doc)
        self.assertIn("YRL-SEQ-003", codes)

    def test_seq004_last_pe_not_end(self) -> None:
        doc = _minimal_doc(
            ("header", "header"), ("mf", "mf"), ("usim", "usim")
        )
        codes = _codes(doc)
        self.assertIn("YRL-SEQ-004", codes)

    def test_correct_order_produces_no_seq_fail(self) -> None:
        codes = _codes(_standard_doc())
        for rule in ("YRL-SEQ-001", "YRL-SEQ-002", "YRL-SEQ-003", "YRL-SEQ-004"):
            self.assertNotIn(rule, codes)


# ---------------------------------------------------------------------------
# YRL-ICC-001 — ICCID missing from header
# ---------------------------------------------------------------------------

class IccidMissingTests(unittest.TestCase):
    """YRL-ICC-001: ICCID absent from profile header."""

    def test_icc001_missing_iccid(self) -> None:
        doc = {
            "sections": {
                "header": {
                    "eUICC-Mandatory-services": {},
                    "identification": 0,
                    "type": "header",
                },
                "mf": {"identification": 1, "type": "mf"},
                "end": {"identification": 2, "type": "end"},
            }
        }
        codes = _codes(doc)
        self.assertIn("YRL-ICC-001", codes)

    def test_icc001_not_triggered_with_valid_iccid(self) -> None:
        codes = _codes(_standard_doc())
        self.assertNotIn("YRL-ICC-001", codes)


# ---------------------------------------------------------------------------
# YRL-ICC-010 — ICCID mismatch between header and EF.ICCID
# ---------------------------------------------------------------------------

class IccidConsistencyTests(unittest.TestCase):
    """YRL-ICC-010: header.iccid vs EF.ICCID fillFileContent mismatch."""

    def _doc_with_ef_iccid(self, ef_hex: str) -> dict:
        return {
            "sections": {
                "header": {
                    "iccid": {"hex": _GOOD_ICCID_HEX},
                    "eUICC-Mandatory-services": {},
                    "identification": 0,
                    "type": "header",
                },
                "mf": {
                    "identification": 1,
                    "type": "mf",
                    "ef-iccid": {
                        "file": {
                            "fileManagementCMD": [
                                {"@": ["createFCP", {"fillFileContent": {"hex": ef_hex}}]}
                            ]
                        }
                    },
                },
                "end": {"identification": 2, "type": "end"},
            }
        }

    def test_matching_iccids_pass(self) -> None:
        codes = _codes(self._doc_with_ef_iccid(_GOOD_ICCID_EF_HEX))
        self.assertNotIn("YRL-ICC-010", codes)

    def test_mismatched_iccids_fail(self) -> None:
        bad_ef_hex = _swap_nibbles("89882099999999991230")
        codes = _codes(self._doc_with_ef_iccid(bad_ef_hex))
        self.assertIn("YRL-ICC-010", codes)


# ---------------------------------------------------------------------------
# YRL-IMS-001..007 — EF.IMSI encoding checks
# ---------------------------------------------------------------------------

class ImsiEncodingTests(unittest.TestCase):
    """YRL-IMS-001..007: EF.IMSI byte-level validation."""

    def test_ims001_wrong_byte_count(self) -> None:
        # 8 bytes instead of 9
        codes = _codes(_doc_with_usim("08911000000000F0"))
        self.assertIn("YRL-IMS-001", codes)

    def test_ims002_bad_length_byte(self) -> None:
        # 9 bytes, length byte is 0x07 (should be 0x08)
        codes = _codes(_doc_with_usim("07911000000000F000"))
        self.assertIn("YRL-IMS-002", codes)

    def test_ims003_bad_parity_nibble(self) -> None:
        # parity nibble is 0x5 (neither 0x1 nor 0x9)
        codes = _codes(_doc_with_usim("08051000000000F000"))
        self.assertIn("YRL-IMS-003", codes)

    def test_ims004_non_bcd_digit(self) -> None:
        # 0xA in a BCD digit position
        codes = _codes(_doc_with_usim("0891A00000000000F0"))
        self.assertIn("YRL-IMS-004", codes)

    def test_ims005_parity_mismatch(self) -> None:
        # 14-digit IMSI (even count), but parity nibble = 0x1 (only valid for odd).
        # TS 31.102 §4.2.2: even count -> parity nibble 0x9.
        codes = _codes(_doc_with_usim("0801101000000000f0"))
        self.assertIn("YRL-IMS-005", codes)

    def test_ims006_too_few_digits(self) -> None:
        # 5 digits (< 6 minimum), parity nibble 0x1 (correct for odd 5):
        # 0x08 len, 0x01 parity, then 2 digit-pair bytes, then 5 filler bytes.
        codes = _codes(_doc_with_usim("08011010ffffffffff"))
        self.assertIn("YRL-IMS-006", codes)

    def test_good_imsi_passes(self) -> None:
        codes = _codes(_doc_with_usim(_GOOD_IMSI_HEX))
        for rule in ("YRL-IMS-001", "YRL-IMS-002", "YRL-IMS-003",
                     "YRL-IMS-004", "YRL-IMS-005", "YRL-IMS-006"):
            self.assertNotIn(rule, codes)


# ---------------------------------------------------------------------------
# YRL-SVC-001 — mandatory services absent from header
# ---------------------------------------------------------------------------

class MandatoryServicesTests(unittest.TestCase):
    """YRL-SVC-001: eUICC-Mandatory-services missing."""

    def test_svc001_missing_mandatory_services(self) -> None:
        doc = {
            "sections": {
                "header": {
                    "iccid": {"hex": _GOOD_ICCID_HEX},
                    "identification": 0,
                    "type": "header",
                },
                "mf": {"identification": 1, "type": "mf"},
                "end": {"identification": 2, "type": "end"},
            }
        }
        codes = _codes(doc)
        self.assertIn("YRL-SVC-001", codes)

    def test_svc001_not_triggered_when_present(self) -> None:
        codes = _codes(_standard_doc())
        self.assertNotIn("YRL-SVC-001", codes)


# ---------------------------------------------------------------------------
# YRL-HDR-001 — profile header missing mandatory field
# ---------------------------------------------------------------------------

class HeaderFieldTests(unittest.TestCase):
    """YRL-HDR-001: mandatory header field absent."""

    def test_hdr001_missing_identification(self) -> None:
        doc = {
            "sections": {
                "header": {
                    "iccid": {"hex": _GOOD_ICCID_HEX},
                    "eUICC-Mandatory-services": {},
                    "type": "header",
                    # identification intentionally absent
                },
                "mf": {"identification": 1, "type": "mf"},
                "end": {"identification": 2, "type": "end"},
            }
        }
        codes = _codes(doc)
        self.assertIn("YRL-HDR-001", codes)

    def test_hdr001_not_triggered_when_present(self) -> None:
        codes = _codes(_standard_doc())
        self.assertNotIn("YRL-HDR-001", codes)


# ---------------------------------------------------------------------------
# YRL-UST-001 / YRL-UST-002 — UST service-to-file coherence
# ---------------------------------------------------------------------------


def _fill_file_hex(fid_hex: str, content_hex: str) -> dict:
    return {
        "file": {
            "fileManagementCMD": [
                {
                    "@": [
                        "createFCP",
                        {
                            "fileID": {"hex": fid_hex},
                            "fillFileContent": {"hex": content_hex},
                        },
                    ]
                }
            ]
        }
    }


def _ust_hex_with_services(*service_numbers: int, octets: int = 16) -> str:
    value = bytearray(octets)
    for service_number in service_numbers:
        byte_index = (service_number - 1) // 8
        bit_index = (service_number - 1) % 8
        if byte_index >= len(value):
            raise ValueError(f"service {service_number} does not fit in {octets} octets")
        value[byte_index] |= 1 << bit_index
    return value.hex().upper()


def _add_usim_ef(doc: dict, marker: str, fid_hex: str = "6FFF") -> None:
    doc["sections"]["usim"]["choices"].append({marker: _fill_file_hex(fid_hex, "FF")})


class UstCoherenceTests(unittest.TestCase):
    """YRL-UST-001 / YRL-UST-002: UST service bit vs related EF presence."""

    # A UST value with service 10 (SMS, bit 9) set, byte 1 bit 1 = 0x02
    # Bit numbering: service N is (byte (N-1)//8), bit (N-1)%8.
    # Service 10 → byte 1, bit 1 → 0x02.  UST: 00 02 00 00 00 00 00 ...
    _UST_SVC10_SET = "00" + "02" + "00" * 14  # 16 bytes, svc 10 set

    # A UST with no service bits set (all zeros) but EF.MSISDN (svc 21) present
    _UST_ALL_ZERO = "00" * 16

    def test_ust001_service_bit_set_but_ef_missing(self) -> None:
        # TS 31.102 §§4.2.25 and 4.2.28 require EF.SMS and EF.SMSS for
        # service 10; neither file is present.
        doc = _doc_with_usim(ust_hex=self._UST_SVC10_SET)
        codes = _codes(doc)
        self.assertIn("YRL-UST-001", codes)

    def test_ust001_service_5_requires_ext3_not_lnd(self) -> None:
        # TS 31.102 §4.2.31 binds service 5 to EF.EXT3.  EF.LND is not
        # that service's required file.
        doc = _doc_with_usim(ust_hex=_ust_hex_with_services(5))
        _add_usim_ef(doc, "ef-lnd")

        findings = [
            finding
            for finding in _lint(doc)
            if finding.code == "YRL-UST-001" and finding.path.endswith(".service.5")
        ]

        self.assertEqual(len(findings), 1)
        self.assertIn("ef-ext3", findings[0].message)
        self.assertNotIn("ef-lnd", findings[0].message)

    def test_ust001_service_5_accepts_decoded_ext3_marker(self) -> None:
        doc = _doc_with_usim(ust_hex=_ust_hex_with_services(5))
        _add_usim_ef(doc, "ef-ext3", "6F4C")

        findings = [
            finding
            for finding in _lint(doc)
            if finding.code == "YRL-UST-001" and finding.path.endswith(".service.5")
        ]

        self.assertEqual(findings, [])

    def test_ust001_service_13_uses_decoded_acmax_marker(self) -> None:
        # The standard calls the file EF.ACMmax (§4.2.7), while the decoded
        # SAIP ProfileElement member is named ef-acmax.
        doc = _doc_with_usim(ust_hex=_ust_hex_with_services(13))
        _add_usim_ef(doc, "ef-acmax", "6F37")
        _add_usim_ef(doc, "ef-acm", "6F39")
        _add_usim_ef(doc, "ef-puct", "6F41")

        findings = [
            finding
            for finding in _lint(doc)
            if finding.code == "YRL-UST-001" and finding.path.endswith(".service.13")
        ]

        self.assertEqual(findings, [])

    def test_ust001_service_45_requires_pnn_not_old_duplicate_targets(self) -> None:
        # TS 31.102 §4.2.58 binds service 45 only to EF.PNN.  EF.CBMIR and
        # EF.CFIS belong to services 16 and 49 respectively.
        doc = _doc_with_usim(ust_hex=_ust_hex_with_services(45))
        _add_usim_ef(doc, "ef-cbmir", "6F50")
        _add_usim_ef(doc, "ef-cfis", "6FCB")

        missing = [
            finding
            for finding in _lint(doc)
            if finding.code == "YRL-UST-001" and finding.path.endswith(".service.45")
        ]
        self.assertEqual(len(missing), 1)
        self.assertIn("ef-pnn", missing[0].message)

        _add_usim_ef(doc, "ef-pnn", "6FC5")
        resolved = [
            finding
            for finding in _lint(doc)
            if finding.code == "YRL-UST-001" and finding.path.endswith(".service.45")
        ]
        self.assertEqual(resolved, [])

    def test_ust001_service_95_requires_uicciari_not_5gs_files(self) -> None:
        # TS 31.102 §4.2.95 binds service 95 to EF.UICCIARI.
        doc = _doc_with_usim(ust_hex=_ust_hex_with_services(95))
        _add_usim_ef(doc, "ef-5gloci")
        _add_usim_ef(doc, "ef-5gnsc")

        missing = [
            finding
            for finding in _lint(doc)
            if finding.code == "YRL-UST-001" and finding.path.endswith(".service.95")
        ]
        self.assertEqual(len(missing), 1)
        self.assertIn("ef-uicciari", missing[0].message)

        _add_usim_ef(doc, "ef-uicciari", "6FE7")

        findings = [
            finding
            for finding in _lint(doc)
            if finding.code == "YRL-UST-001" and finding.path.endswith(".service.95")
        ]

        self.assertEqual(findings, [])

    def test_ust001_service_122_requires_all_four_5gs_mobility_files(self) -> None:
        # TS 31.102 §§4.4.11.2-4.4.11.5 assign the four 5GS mobility
        # files to service 122.
        doc = _doc_with_usim(ust_hex=_ust_hex_with_services(122))
        for marker in (
            "ef-5gs3gpploci",
            "ef-5gsn3gpploci",
            "ef-5gs3gppnsc",
            "ef-5gsn3gppnsc",
        ):
            _add_usim_ef(doc, marker)

        findings = [
            finding
            for finding in _lint(doc)
            if finding.code == "YRL-UST-001" and finding.path.endswith(".service.122")
        ]

        self.assertEqual(findings, [])

    def test_ust002_ef_present_but_service_bit_not_set(self) -> None:
        # ef-msisdn present but UST service 21 not set
        base = _doc_with_usim(ust_hex=self._UST_ALL_ZERO)
        # Add ef-msisdn to the usim section
        msisdn_hex = "FF" * 14  # 14-byte minimal ADN record
        base["sections"]["usim"]["choices"].append(
            {"ef-msisdn": _fill_file_hex("6F40", msisdn_hex)}
        )
        codes = _codes(base)
        self.assertIn("YRL-UST-002", codes)

    def test_ust002_presence_hints_use_corrected_service_numbers(self) -> None:
        cases = (
            ("ef-ext3", "6F4C", 5),
            ("ef-ext5", "6F4E", 44),
            ("ef-mwis", "6FCA", 48),
            ("ef-uicciari", "6FE7", 95),
            ("ef-5gs3gpploci", "4F01", 122),
        )
        for marker, fid_hex, expected_service in cases:
            with self.subTest(marker=marker):
                doc = _doc_with_usim(ust_hex=self._UST_ALL_ZERO)
                _add_usim_ef(doc, marker, fid_hex)
                matching = [
                    finding
                    for finding in _lint(doc)
                    if finding.code == "YRL-UST-002"
                    and finding.path.endswith(f".service.{expected_service}")
                ]
                self.assertEqual(len(matching), 1)
                self.assertIn(marker, matching[0].message)

    def test_ust001_not_triggered_when_service_disabled(self) -> None:
        # UST all zero — no services set, no UST-001 should fire
        doc = _doc_with_usim(ust_hex=self._UST_ALL_ZERO)
        codes = _codes(doc)
        self.assertNotIn("YRL-UST-001", codes)

    def test_ust_coherence_is_deferred_while_ust_token_is_unresolved(self) -> None:
        doc = _doc_with_usim(ust_hex="FF" * 16)
        report = SaipProfileLinter(strict=True).lint_decoded_document(
            doc,
            profile_label="parameterized-template",
            placeholder_paths=frozenset({"usim.ef-ust.fillFileContent"}),
        )
        coherence = [finding for finding in report.findings if finding.code.startswith("YRL-UST-")]

        self.assertTrue(coherence)
        self.assertTrue(all(finding.code.endswith("/TEMPLATE") for finding in coherence))
        self.assertTrue(all(finding.severity == "INFO" for finding in coherence))
        self.assertTrue(
            all(
                finding.path.startswith("usim.ef-ust.fillFileContent.service.")
                for finding in coherence
            )
        )
