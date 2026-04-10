import builtins
import json
import unittest
from unittest import mock

from Tools.ProfilePackage.saip_asn1_decode import (
    build_inspector_report_for_subtree,
    build_profile_asn1_report,
)
from Tools.ProfilePackage.saip_json_codec import _TAG_BYTES, _TAG_TUPLE
from Tools.ProfilePackage.saip_transcode_inspect import build_transcode_inspector_text


class SaipAsn1DecodeTests(unittest.TestCase):
    def test_profile_report_decodes_iccid_without_scp03_or_pysim_imports(self) -> None:
        document = {
            "intro": [],
            "sections": {
                "mf": {
                    "ef-iccid": [
                        {
                            _TAG_TUPLE: [
                                "fillFileContent",
                                {
                                    _TAG_BYTES: "988812010000400310F0",
                                },
                            ]
                        }
                    ]
                }
            },
        }

        original_import = builtins.__import__

        def guarded_import(
            name: str,
            globals_arg: object | None = None,
            locals_arg: object | None = None,
            fromlist: tuple[str, ...] = (),
            level: int = 0,
        ):
            if name.startswith("SCP03") or name.startswith("pySim"):
                raise AssertionError(f"Unexpected import: {name}")
            return original_import(name, globals_arg, locals_arg, fromlist, level)

        with mock.patch("builtins.__import__", side_effect=guarded_import):
            text = build_profile_asn1_report(document)

        self.assertIn("EF payload", text)
        self.assertIn("iccid", text.lower())
        self.assertIn("8988211000000430010", text)

    def test_profile_report_decodes_generic_ber_sequence(self) -> None:
        document = {
            "intro": [],
            "sections": {
                "securityDomain": {
                    "certificateCandidate": {
                        _TAG_BYTES: "30060201050101FF",
                    }
                }
            },
        }

        text = build_profile_asn1_report(document)

        self.assertIn("ASN.1 / BER", text)
        self.assertIn("SEQUENCE", text)
        self.assertIn("INTEGER", text)
        self.assertIn("BOOLEAN", text)
        self.assertIn("True", text)

    def test_subtree_report_decodes_connectivity_parameters_with_named_fields(self) -> None:
        subtree = {
            "connectivityParameters": {
                _TAG_BYTES: "A118350702000003000002470D085465726D696E616C0361706EA00F0607918406010092F88101008201F6",
            }
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "header",
            focus_path_hint=["connectivityParameters"],
        )

        self.assertIn("Field semantics", text)
        self.assertIn("Transport / Remote Parameters", text)
        self.assertIn("Network Access Name", text)
        self.assertIn("Terminal.apn", text)

    def test_subtree_report_decodes_application_specific_parameters_c9(self) -> None:
        subtree = {
            "instance": {
                "applicationSpecificParametersC9": {
                    _TAG_BYTES: "81028000810203708201F08701F0",
                }
            }
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "securityDomain",
            focus_path_hint=["instance", "applicationSpecificParametersC9"],
        )

        self.assertIn("UICC SCP", text)
        self.assertIn("SCP80", text)
        self.assertIn("SCP03", text)
        self.assertIn("[7, 6, 5, 4]", text)

    def test_subtree_report_decodes_toolkit_parameters(self) -> None:
        subtree = {
            "applicationParameters": {
                "uiccToolkitApplicationSpecificParametersField": {
                    _TAG_BYTES: "0100010100000202011606B2010000000000",
                }
            }
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "securityDomain",
            focus_path_hint=[
                "applicationParameters",
                "uiccToolkitApplicationSpecificParametersField",
            ],
        )

        self.assertIn("ETSI TS 102 226 toolkit app specific parameters", text)
        self.assertIn("accessDomain", text)
        self.assertIn("minimumSecurityLevelDecimal", text)
        self.assertIn("tarInferred", text)
        self.assertIn("B20100", text)

    def test_subtree_report_decodes_security_domain_scalar_fields(self) -> None:
        subtree = {
            "applicationPrivileges": "82DC20",
            "lifeCycleState": "0F",
            "keyList": [
                {
                    "keyUsageQualifier": "38",
                    "keyAccess": "01",
                    "keyIdentifier": "01",
                    "keyVersionNumber": "30",
                    "keyCounterValue": "0000000000",
                    "keyComponents": [
                        {
                            "keyType": "88",
                        }
                    ],
                }
            ],
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "securityDomain",
            focus_path_hint=["securityDomain"],
        )

        self.assertIn("GlobalPlatform key type", text)
        self.assertIn("0x88 (AES)", text)
        self.assertIn("Security Domain only", text)
        self.assertIn("SCP03", text)
        self.assertIn("Personalized", text)
        self.assertIn("Secure Messaging Command", text)
        self.assertIn("Security Domain", text)

    def test_subtree_report_is_not_capped_at_legacy_16_hit_limit(self) -> None:
        subtree = {
            "keyList": [
                {
                    "keyComponents": [
                        {
                            "keyType": "88",
                        }
                    ]
                }
                for _ in range(20)
            ]
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "securityDomain",
            focus_path_hint=["securityDomain"],
        )

        self.assertEqual(text.count("GlobalPlatform key type"), 20)

    def test_profile_report_is_not_capped_at_legacy_section_or_hit_limits(self) -> None:
        document = {
            "intro": [],
            "sections": {
                f"securityDomain_{index}": {
                    "lifeCycleState": "0F",
                }
                for index in range(130)
            },
        }

        text = build_profile_asn1_report(document)

        self.assertEqual(text.count("GlobalPlatform life cycle state"), 130)
        self.assertNotIn("[truncated:", text)

    def test_transcode_inspector_accepts_profile_asn1_mode(self) -> None:
        document = {
            "intro": [],
            "sections": {
                "mf": {
                    "ef-iccid": [
                        {
                            _TAG_TUPLE: [
                                "fillFileContent",
                                {
                                    _TAG_BYTES: "988812010000400310F0",
                                },
                            ]
                        }
                    ]
                }
            },
        }

        editor_text = json.dumps(document, indent=2)
        text = build_transcode_inspector_text(
            editor_text,
            0,
            0,
            left_mode="profile_asn1",
        )

        self.assertIn("iccid", text.lower())
        self.assertIn("8988211000000430010", text)


if __name__ == "__main__":
    unittest.main()
