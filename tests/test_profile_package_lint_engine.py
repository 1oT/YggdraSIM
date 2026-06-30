# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import unittest

from Tools.ProfilePackage.lint_engine import SaipProfileLinter


class SaipProfileLinterTests(unittest.TestCase):
    def test_lint_detects_missing_mandatory_usim(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "iccid": "8944501234567890123F",
                    "profileType": "test-profile",
                    "eUICC-Mandatory-services": {
                        "usim": True,
                    },
                    "identification": 1,
                },
                "mf": {
                    "identification": 2,
                },
                "end": {
                    "identification": 3,
                },
            },
        }
        linter = SaipProfileLinter(strict=False)

        report = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label="demo.der",
            check_return_code=0,
            check_stderr="",
        )

        fail_codes = [item.code for item in report.findings if item.severity == "FAIL"]
        self.assertIn("YRL-SVC-MIS-USIM", fail_codes)

    def test_strict_mode_escalates_selected_warnings(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "iccid": "8944501234567890123F",
                    "profileType": "test-profile",
                    "identification": 1,
                },
                "mf": {
                    "identification": 2,
                },
                "end": {
                    "identification": 3,
                },
            },
        }
        linter = SaipProfileLinter(strict=True)

        report = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label="demo.der",
            check_return_code=0,
            check_stderr="",
        )

        target = [item for item in report.findings if item.code == "YRL-SVC-001"]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0].severity, "FAIL")

    def test_metadata_operator_digits_validation(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "iccid": "8944501234567890123F",
                    "profileType": "test-profile",
                    "eUICC-Mandatory-services": {},
                    "identification": 1,
                },
                "mf": {
                    "identification": 2,
                },
                "end": {
                    "identification": 3,
                },
            },
        }
        metadata = {
            "profile": {"iccid": "8944501234567890123F"},
            "operator": {"mcc": "9A9", "mnc": "9"},
        }
        linter = SaipProfileLinter(strict=False)

        report = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label="demo.der",
            check_return_code=0,
            check_stderr="",
            metadata=metadata,
        )

        fail_codes = {item.code for item in report.findings if item.severity == "FAIL"}
        self.assertIn("YRL-MET-010", fail_codes)
        self.assertIn("YRL-MET-011", fail_codes)

    def test_dependency_order_df5gs_before_usim_is_failure(self) -> None:
        decoded_document = {
            "intro": ["Read 4 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {"identification": 1, "iccid": "8944501234567890123F", "profileType": "x"},
                "mf": {"identification": 2},
                "df-5gs": {"identification": 3},
                "usim": {"identification": 4},
                "end": {"identification": 5},
            },
        }
        linter = SaipProfileLinter(strict=False)
        report = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label="demo.der",
            check_return_code=0,
        )

        fail_codes = [item.code for item in report.findings if item.severity == "FAIL"]
        self.assertIn("YRL-DEP-5GS-001", fail_codes)

    def test_fs_core_short_efid_low_bits_violation(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {"identification": 1, "iccid": "8944501234567890123F", "profileType": "x"},
                "mf": {"identification": 2},
                "usim": {
                    "identification": 3,
                    "fileManagementCMD": [
                        {
                            "createFCP": {
                                "fileDescriptor": "4121",
                                "fileID": "6F38",
                                "efFileSize": "11",
                                "shortEFID": "21",
                                "securityAttributesReferenced": "0A",
                            }
                        }
                    ],
                },
                "end": {"identification": 4},
            },
        }
        linter = SaipProfileLinter(strict=False)
        report = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label="demo.der",
            check_return_code=0,
        )

        fail_codes = [item.code for item in report.findings if item.severity == "FAIL"]
        self.assertIn("YRL-FIL-019", fail_codes)

    def test_application_security_domain_aid_reference_failure(self) -> None:
        decoded_document = {
            "intro": ["Read 5 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {"identification": 1, "iccid": "8944501234567890123F", "profileType": "x"},
                "mf": {"identification": 2},
                "securityDomain": {
                    "identification": 3,
                    "instance": {"instanceAID": "A000000151000000"},
                },
                "application": {
                    "identification": 4,
                    "loadBlock": {
                        "loadPackageAID": "A000000151414243",
                        "securityDomainAID": "A000000151DEADBEEF",
                    },
                    "instanceList": [],
                },
                "end": {"identification": 5},
            },
        }
        linter = SaipProfileLinter(strict=False)
        report = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label="demo.der",
            check_return_code=0,
        )

        fail_codes = [item.code for item in report.findings if item.severity == "FAIL"]
        self.assertIn("YRL-JCA-010", fail_codes)

    def test_service_mapping_warns_when_service_enabled_without_related_file(self) -> None:
        decoded_document = {
            "intro": ["Read 4 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {"identification": 1, "iccid": "8944501234567890123F", "profileType": "x"},
                "mf": {"identification": 2},
                "usim": {
                    "identification": 3,
                    "ef-ust": [("fillFileContent", "0200000000000000000000000000000000")],
                },
                "end": {"identification": 4},
            },
        }
        linter = SaipProfileLinter(strict=False)
        report = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label="demo.der",
            check_return_code=0,
        )

        info_codes = [item.code for item in report.findings if item.severity == "INFO"]
        self.assertIn("YRL-UST-001", info_codes)

    def test_gate_by_prefix_and_min_score(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "identification": 1,
                    "iccid": "8944501234567890123F",
                    "profileType": "x",
                    "eUICC-Mandatory-services": {"usim": True},
                },
                "mf": {"identification": 2},
                "end": {"identification": 3},
            },
        }
        linter = SaipProfileLinter(strict=False)
        report = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label="demo.der",
            check_return_code=0,
        )
        gate = linter.evaluate_gate(
            report=report,
            min_score=95,
            fail_on_warn=False,
            fail_prefixes=["YRL-SVC"],
            fail_codes=[],
        )
        self.assertFalse(gate["passed"])
        self.assertGreaterEqual(gate["trigger_count"], 1)
        self.assertIsNotNone(report.gate)

    # ------------------------------------------------------------------
    # ICCID cross-PE consistency (header.iccid vs MF/EF.ICCID
    # fillFileContent) — TS 102 221 §13.2.
    # ------------------------------------------------------------------

    def _profile_with_iccid_fields(
        self,
        header_iccid: bytes | str,
        ef_iccid_content: bytes | None,
    ) -> dict:
        ef_iccid_choices = []
        if ef_iccid_content is not None:
            ef_iccid_choices.append(("fillFileContent", ef_iccid_content))
        return {
            "intro": ["t"],
            "sections": {
                "header": {
                    "iccid": header_iccid,
                    "profileType": "x",
                    "eUICC-Mandatory-services": {"usim": True},
                    "identification": 1,
                },
                "mf": {
                    "identification": 2,
                    "ef-iccid": ef_iccid_choices,
                },
                "usim": {"identification": 3},
                "end": {"identification": 4},
            },
        }

    def test_iccid_consistency_fail_on_mismatch(self) -> None:
        # Header is printable-order BCD. EF.ICCID is nibble-swapped BCD
        # but pointing at a *different* digit string — same length,
        # different identity.
        doc = self._profile_with_iccid_fields(
            header_iccid=bytes.fromhex("8988081111111111112F"),
            ef_iccid_content=bytes.fromhex("19283711111111111121"),
        )
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        hits = [f for f in report.findings if f.code == "YRL-ICC-010"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "FAIL")
        self.assertEqual(hits[0].path, "mf.ef-iccid.fillFileContent")
        self.assertIn("header_iccid_digits", hits[0].evidence)
        self.assertIn("ef_iccid_digits", hits[0].evidence)
        self.assertNotEqual(
            hits[0].evidence["header_iccid_digits"],
            hits[0].evidence["ef_iccid_digits"],
        )

    def test_iccid_consistency_pass_on_match(self) -> None:
        # Header bytes 89460811...12 (printable BCD) and EF bytes
        # 98648011...21 (nibble-swapped BCD) decode to the same
        # printable digit string — this is the canonical SAIP
        # arrangement.
        doc = self._profile_with_iccid_fields(
            header_iccid=bytes.fromhex("89460811111111111112"),
            ef_iccid_content=bytes.fromhex("98648011111111111121"),
        )
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        hits = [f for f in report.findings if f.code == "YRL-ICC-010"]
        self.assertEqual(len(hits), 0)

    def test_iccid_consistency_skip_when_ef_iccid_absent(self) -> None:
        doc = self._profile_with_iccid_fields(
            header_iccid=bytes.fromhex("89460811111111111112"),
            ef_iccid_content=None,
        )
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        # No fillFileContent → check is a no-op (no false positive).
        hits = [f for f in report.findings if f.code == "YRL-ICC-010"]
        self.assertEqual(len(hits), 0)

    def test_iccid_consistency_tolerates_filler_nibble(self) -> None:
        # 19-digit ICCID: header carries printable + 'F' filler in the
        # trailing nibble; EF carries nibble-swapped + 'F' filler in
        # the **leading** nibble of the last byte. Both decode to the
        # same 19-digit string, so the consistency check must pass.
        doc = self._profile_with_iccid_fields(
            header_iccid=bytes.fromhex("8946081111111111111F"),
            ef_iccid_content=bytes.fromhex("986480111111111111F1"),
        )
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        hits = [f for f in report.findings if f.code == "YRL-ICC-010"]
        self.assertEqual(len(hits), 0)

    # ------------------------------------------------------------------
    # EF.IMSI encoding (3GPP TS 31.102 §4.2.2).
    # ------------------------------------------------------------------

    def _profile_with_ef_imsi(self, content: bytes) -> dict:
        return {
            "intro": ["t"],
            "sections": {
                "header": {
                    "iccid": "8988081111111111112F",
                    "profileType": "x",
                    "eUICC-Mandatory-services": {"usim": True},
                    "identification": 1,
                },
                "mf": {"identification": 2},
                "usim": {
                    "identification": 3,
                    "ef-imsi": [("fillFileContent", content)],
                },
                "end": {"identification": 4},
            },
        }

    def test_imsi_well_formed_15_digit_passes(self) -> None:
        # 15-digit IMSI "001010000000001": parity=1, first digit=0.
        # Body: 08 01 10 10 00 00 00 00 10
        doc = self._profile_with_ef_imsi(bytes.fromhex("080110100000000010"))
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        ims_findings = [
            f for f in report.findings
            if f.code.startswith("YRL-IMS-") and f.severity in ("FAIL", "WARN")
        ]
        self.assertEqual(len(ims_findings), 0, ims_findings)

    def test_imsi_wrong_total_length_fails(self) -> None:
        doc = self._profile_with_ef_imsi(bytes.fromhex("0801101010"))  # too short
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        hits = [f for f in report.findings if f.code == "YRL-IMS-001"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "FAIL")

    def test_imsi_wrong_length_byte_fails(self) -> None:
        # Right total length but length-byte != 0x08.
        doc = self._profile_with_ef_imsi(bytes.fromhex("070110100000000010"))
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        hits = [f for f in report.findings if f.code == "YRL-IMS-002"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "FAIL")

    def test_imsi_missing_parity_nibble_fails(self) -> None:
        # parity nibble = 0x0 (should be 0x1 or 0x9).
        doc = self._profile_with_ef_imsi(bytes.fromhex("0800101010101010F1"))
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        hits = [f for f in report.findings if f.code == "YRL-IMS-003"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "FAIL")
        self.assertIn("parity", hits[0].message.lower())

    def test_imsi_non_decimal_first_digit_fails(self) -> None:
        # parity_byte = 0xA1: high nibble 0xA is not a decimal digit.
        doc = self._profile_with_ef_imsi(bytes.fromhex("08A1101010101010F0"))
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        hits = [f for f in report.findings if f.code == "YRL-IMS-004"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "FAIL")

    def test_imsi_parity_mismatch_fails(self) -> None:
        # 15 actual digits but parity=9 (which would mean even count).
        doc = self._profile_with_ef_imsi(bytes.fromhex("080910101010101010"))
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        hits = [f for f in report.findings if f.code == "YRL-IMS-005"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "FAIL")
        self.assertEqual(hits[0].evidence["digit_count"], 15)
        self.assertEqual(hits[0].evidence["expected_parity"], "0x1")

    def test_imsi_short_imsi_emits_info(self) -> None:
        # 8-digit IMSI: digit_count=8 (even), parity=9.
        # Body: 08 91 10 10 10 FF FF FF FF — wait, lots of filler.
        # Easier: 7 digits "0123456" → first_digit=0, then 6 digits "123456".
        # Actually let's go with 8 digits: "01234567" → parity=9 (even).
        # first_digit=0, parity=9 → parity_byte=0x09.
        # rest 7 digits "1234567" → pad to "1234567F" (8 nibbles, 4 bytes).
        # swap pairs: "21436587" then "F7" → wait let me just do it.
        # Pairs of "1234567F": (1,2)→"21", (3,4)→"43", (5,6)→"65", (7,F)→"F7"
        # So body = 08 09 21 43 65 F7 + 3 bytes filler FF FF FF
        # = 0809214365F7FFFFFF
        doc = self._profile_with_ef_imsi(bytes.fromhex("0809214365F7FFFFFF"))
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=doc, profile_label="t",
        )
        # Should be no FAIL / WARN, but an INFO YRL-IMS-007 for unusual length.
        info_hits = [f for f in report.findings if f.code == "YRL-IMS-007"]
        fail_hits = [
            f for f in report.findings
            if f.code.startswith("YRL-IMS-") and f.severity in ("FAIL", "WARN")
        ]
        self.assertEqual(len(info_hits), 1, info_hits)
        self.assertEqual(len(fail_hits), 0, fail_hits)

    def test_emit_missing_check_finding_can_be_suppressed(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "identification": 1,
                    "iccid": "8944501234567890123F",
                    "profileType": "x",
                    "eUICC-Mandatory-services": {},
                },
                "mf": {"identification": 2},
                "end": {"identification": 3},
            },
        }
        linter = SaipProfileLinter(strict=False)
        report = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label="demo.der",
            check_return_code=None,
            check_stderr="",
            emit_missing_check_finding=False,
        )
        codes = [item.code for item in report.findings]
        self.assertNotIn("YRL-CHK-001", codes)

if __name__ == "__main__":
    unittest.main()
