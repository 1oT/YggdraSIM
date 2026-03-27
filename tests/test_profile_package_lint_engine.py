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
