import builtins
import json
import unittest
from unittest import mock

import pytest

from Tools.ProfilePackage.saip_asn1_decode import (
    build_inspector_report_for_subtree,
    build_profile_asn1_report,
)
from Tools.ProfilePackage.saip_json_codec import _TAG_BYTES, _TAG_TUPLE, humanize_saip_display_name
from Tools.ProfilePackage.saip_transcode_inspect import (
    build_template_defaults_report,
    build_transcode_inspector_text,
)


def _pysim_saip_templates_available() -> bool:
    """Probe for the pySim SAIP template registry.

    Tests that resolve profile-template OIDs (e.g. the ARR rule summary
    pass-through) rely on ``pySim.esim.saip.templates``. That module loads
    only when either an on-disk ``pysim/`` clone is present at the repo
    root or the PyPI ``pySim`` wheel is installed. When neither is
    reachable we skip rather than fail so a lean "clean" checkout still
    passes this file's decoder-only coverage.
    """
    try:
        from pySim.esim.saip import templates  # noqa: F401
    except Exception:
        return False
    return True


_PYSIM_TEMPLATES_AVAILABLE = _pysim_saip_templates_available()


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

    def test_subtree_report_decodes_pin_and_puk_retry_counters(self) -> None:
        subtree = {
            "pinCodes": {
                _TAG_TUPLE: [
                    "pinconfig",
                    [
                        {
                            "maxNumOfAttemps-retryNumLeft": 0x33,
                        }
                    ],
                ]
            },
            "pukCodes": [
                {
                    "maxNumOfAttemps-retryNumLeft": 0xAA,
                }
            ],
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "mf",
            focus_path_hint=["mf"],
        )

        self.assertIn("PIN/PUK retry counters", text)
        self.assertIn("maxAttempts", text)
        self.assertIn("remainingAttempts", text)
        self.assertIn("3 remaining of 3", text)
        self.assertIn("10 remaining of 10", text)

    def test_subtree_report_decodes_tagged_security_domain_scalar_fields(self) -> None:
        subtree = {
            "applicationPrivileges": {_TAG_BYTES: "82DC20"},
            "lifeCycleState": {_TAG_BYTES: "0F"},
            "keyList": [
                {
                    "keyUsageQualifier": {_TAG_BYTES: "38"},
                    "keyAccess": {_TAG_BYTES: "01"},
                    "keyIdentifier": {_TAG_BYTES: "01"},
                    "keyVersionNumber": {_TAG_BYTES: "30"},
                    "keyCounterValue": {_TAG_BYTES: "0000000000"},
                    "keyComponents": [
                        {
                            "keyType": {_TAG_BYTES: "88"},
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

        self.assertIn("GlobalPlatform application privileges", text)
        self.assertIn("Authorized Management", text)
        self.assertIn("Personalized", text)
        self.assertIn("Security Domain only", text)
        self.assertIn("SCP03", text)
        self.assertIn("0x88 (AES)", text)

    def test_subtree_report_decodes_header_iccid_and_key_material(self) -> None:
        subtree = {
            "iccid": {_TAG_BYTES: "89460811111111111112"},
            "keyData": {_TAG_BYTES: "1122334455667788AABBCCDDEEFF0011"},
            "macLength": 8,
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "header",
            focus_path_hint=["header"],
        )

        self.assertIn("Profile ICCID", text)
        self.assertIn("89460811111111111112", text)
        self.assertIn("Security domain key material", text)
        self.assertIn("128-bit key material", text)
        self.assertIn("MAC length", text)
        self.assertIn("8 byte(s)", text)

    def test_subtree_report_decodes_profile_policy_and_memory_limits(self) -> None:
        subtree = {
            "pol": {_TAG_BYTES: "04"},
            "nonVolatileCodeLimitC6": {_TAG_BYTES: "0100"},
            "volatileDataLimitC7": {_TAG_BYTES: "00010000"},
            "nonVolatileDataLimitC8": {_TAG_BYTES: "0001"},
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "header",
            focus_path_hint=["header"],
        )

        self.assertIn("Profile policy rules", text)
        self.assertIn("ppr2-delete-not-allowed", text)
        self.assertIn("Non-volatile code limit", text)
        self.assertIn("256 byte(s)", text)
        self.assertIn("Volatile data limit", text)
        self.assertIn("65536 byte(s)", text)
        self.assertIn("Non-volatile data limit", text)
        self.assertIn("1 byte(s)", text)

    def test_subtree_report_decodes_aka_parameter_fields(self) -> None:
        subtree = {
            "algorithmID": 1,
            "algorithmOptions": {_TAG_BYTES: "01"},
            "key": {_TAG_BYTES: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"},
            "opc": {_TAG_BYTES: "11111111111111111111111111111111"},
            "authCounterMax": {_TAG_BYTES: "FFFFFF"},
            "rotationConstants": {_TAG_BYTES: "4000204060"},
            "xoringConstants": {
                _TAG_BYTES: (
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000001"
                    "00000000000000000000000000000002"
                    "00000000000000000000000000000004"
                    "00000000000000000000000000000008"
                )
            },
            "numberOfKeccak": 1,
            "sqnOptions": {_TAG_BYTES: "0E"},
            "sqnDelta": {_TAG_BYTES: "000010000000"},
            "sqnAgeLimit": {_TAG_BYTES: "000010000000"},
            "sqnInit": [
                {_TAG_BYTES: "000000000000"},
                {_TAG_BYTES: "000000000001"},
            ],
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "akaParameter",
            focus_path_hint=["akaParameter"],
        )

        self.assertIn("AKA algorithm identifier", text)
        self.assertIn("milenage", text)
        self.assertIn("AKA algorithm options", text)
        self.assertIn("AKA secret key material", text)
        self.assertIn("AKA operator variant key", text)
        self.assertIn("AKA authentication counter max", text)
        self.assertIn("16777215", text)
        self.assertIn("Milenage rotation constants", text)
        self.assertIn("r1", text)
        self.assertIn("Milenage XOR constants", text)
        self.assertIn("c5", text)
        self.assertIn("TUAK Keccak iterations", text)
        self.assertIn("SQN options", text)
        self.assertIn("SQN delta", text)
        self.assertIn("SQN age limit", text)
        self.assertIn("SQN initial value", text)

    def test_subtree_report_decodes_filesystem_reference_and_proprietary_fields(self) -> None:
        subtree = {
            "fileID": {_TAG_BYTES: "6F38"},
            "filePath": {_TAG_BYTES: "7F10"},
            "securityAttributesReferenced": {_TAG_BYTES: "6F0603"},
            "linkPath": {_TAG_BYTES: "7F106F38"},
            "specialFileInformation": {_TAG_BYTES: "C0"},
            "fillPattern": {_TAG_BYTES: "FF"},
            "fileDetails": {_TAG_BYTES: "01"},
            "repeatPattern": {_TAG_BYTES: "4142"},
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "mf",
            focus_path_hint=["mf"],
        )

        self.assertIn("File Identifier", text)
        self.assertIn("EF.UST", text)
        self.assertIn("File path", text)
        self.assertIn("Referenced security attributes", text)
        self.assertIn("recordNumber", text)
        self.assertIn("Link path", text)
        self.assertIn("DF.TELECOM", text)
        self.assertIn("Special file information", text)
        self.assertIn("high update activity", text)
        self.assertIn("readAndUpdateWhenDeactivated", text)
        self.assertIn("Fill pattern", text)
        self.assertIn("byteValue", text)
        self.assertIn("BER-TLV file details", text)
        self.assertIn("DER coding", text)
        self.assertIn("Repeat pattern", text)

    def test_subtree_report_decodes_generic_fill_content_using_preceding_create_fcp(self) -> None:
        subtree = {
            "fileManagementCMD": [
                [
                    {
                        _TAG_TUPLE: [
                            "filePath",
                            {
                                _TAG_BYTES: "7F10",
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "6F07"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "089999990000000000",
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "6F46"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "014A4D4120576972656C657373",
                            },
                        ]
                    },
                ]
            ]
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "genericFileManagement_1",
            focus_path_hint=["genericFileManagement_1"],
        )

        self.assertIn("File path", text)
        self.assertIn("DF.TELECOM", text)
        self.assertIn("EF payload", text)
        self.assertIn("imsi", text.lower())
        self.assertIn("JMA Wireless", text)

    def test_subtree_report_decodes_additional_known_ef_payloads(self) -> None:
        subtree = {
            "ef-dir": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "61184F10A0000000871002FF34FF0789312E30FF50045553494D",
                        },
                    ]
                }
            ],
            "ef-pl": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "656E6465FFFF",
                        },
                    ]
                }
            ],
            "ef-li": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "656E",
                        },
                    ]
                }
            ],
            "ef-est": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "07",
                        },
                    ]
                }
            ],
            "ef-start-hfn": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "F00000F00000",
                        },
                    ]
                }
            ],
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "opt-usim",
            focus_path_hint=["opt-usim"],
        )

        self.assertIn("Application Template", text)
        self.assertIn("Application Label", text)
        self.assertIn("USIM", text)
        self.assertIn("languages", text)
        self.assertIn("en", text)
        self.assertIn("de", text)
        self.assertIn("Fixed Dialling Numbers", text)
        self.assertIn("Barred Dialling Numbers", text)
        self.assertIn("APN Control List", text)
        self.assertIn("startCs", text)
        self.assertIn("15728640", text)

    def test_subtree_report_decodes_more_scp03_style_file_payloads(self) -> None:
        subtree = {
            "ef-ad": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "00000002",
                        },
                    ]
                }
            ],
            "ef-fdn": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "069121436587F9FFFFFFFFFFFF01",
                        },
                    ]
                }
            ],
            "ef-puct": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "4555521200",
                        },
                    ]
                }
            ],
            "ef-ecc": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "11F1FF",
                        },
                    ]
                }
            ],
            "fileManagementCMD": [
                [
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "6F06"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "8001019000800102A406830101950108800158A40683010A950108",
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "6F31"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "05",
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "6F3C"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "03AABB",
                            },
                        ]
                    },
                ]
            ],
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "usim",
            focus_path_hint=["usim"],
        )

        self.assertIn("administrativeMode", text)
        self.assertIn("Normal", text)
        self.assertIn("numberLength", text)
        self.assertIn("123456789", text)
        self.assertIn("pricePerUnitFormula", text)
        self.assertIn("EUR", text)
        self.assertIn("emergencyCodes", text)
        self.assertIn("111", text)
        self.assertIn("EF.ARR access rules", text)
        self.assertIn("PIN1", text)
        self.assertIn("ADM1", text)
        self.assertIn("recordState", text)
        self.assertIn("Received unread", text)
        self.assertIn("interval", text)

    def test_subtree_report_decodes_pkcs15_and_additional_telecom_payloads(self) -> None:
        subtree = {
            "ef-pnn": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "43074578616D706C6545024578",
                        },
                    ]
                }
            ],
            "ef-opl": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "1300620001006401",
                        },
                    ]
                }
            ],
            "ef-spdi": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "A3058003130062",
                        },
                    ]
                }
            ],
            "ef-epsnsc": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "0122222222222222222222222222222222AABB",
                        },
                    ]
                }
            ],
            "fileManagementCMD": [
                [
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "5031"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "A706300404025207",
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "5207"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "A1293000300F0C0D4750205345204163632043746CA1143012060A2A864886FC6B81480102300404024200",
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "4200"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "3010040800000000000000AA300404024300",
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "4310"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "302204205904E846CD5D54018003FB684D15C7F494F5C3759D68DB2F236F18EE3707DB2C",
                            },
                        ]
                    },
                ]
            ],
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "genericFileManagement_2",
            focus_path_hint=["genericFileManagement_2"],
        )

        self.assertIn("PLMN Network Name", text)
        self.assertIn("Example", text)
        self.assertIn("Operator PLMN List record", text)
        self.assertIn("pnnRecordIdentifier", text)
        self.assertIn("310-260", text)
        self.assertIn("Service Provider Display Information", text)
        self.assertIn("serviceProviderPlmnList", text)
        self.assertIn("EPS NAS security context", text)
        self.assertIn("kasmeFirst16Bytes", text)
        self.assertIn("PKCS#15 Object Directory File", text)
        self.assertIn("5207", text)
        self.assertIn("PKCS#15 Data Object Directory File", text)
        self.assertIn("GP SE Acc Ctl", text)
        self.assertIn("4200", text)
        self.assertIn("PKCS#15 Access Control Main File", text)
        self.assertIn("acrfPath", text)
        self.assertIn("4300", text)
        self.assertIn("PKCS#15 Access Control Conditions File", text)
        self.assertIn("sha256", text)

    def test_subtree_report_decodes_isim_gba_and_plmn_payloads(self) -> None:
        subtree = {
            "ef-impi": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "800F7461676765644073696D2E74657374",
                        },
                    ]
                }
            ],
            "ef-domain": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "800B696D732E6578616D706C65",
                        },
                    ]
                }
            ],
            "ef-impu": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "80137369703A7461676765644073696D2E74657374",
                        },
                    ]
                }
            ],
            "ef-ist": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "7100000000000000000000000000",
                        },
                    ]
                }
            ],
            "ef-pcscf": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "800501C0A80C22",
                        },
                    ]
                }
            ],
            "ef-smsr": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "01AABB",
                        },
                    ]
                }
            ],
            "ef-ehplmn": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "130062",
                        },
                    ]
                }
            ],
            "ef-ehplmnpi": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "02",
                        },
                    ]
                }
            ],
            "ef-gbanl": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "80024142810401020304",
                        },
                    ]
                }
            ],
            "ef-nafkca": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "800B6E61662E6578616D706C65",
                        },
                    ]
                }
            ],
            "fileManagementCMD": [
                [
                    {
                        _TAG_TUPLE: [
                            "createFCP",
                            {
                                "fileDescriptor": {_TAG_BYTES: "4121"},
                                "fileID": {_TAG_BYTES: "6F60"},
                            },
                        ]
                    },
                    {
                        _TAG_TUPLE: [
                            "fillFileContent",
                            {
                                _TAG_BYTES: "1300628000",
                            },
                        ]
                    },
                ]
            ],
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "isim",
            focus_path_hint=["isim"],
        )

        self.assertIn("ISIM private user identity", text)
        self.assertIn("tagged@sim.test", text)
        self.assertIn("ISIM home network domain", text)
        self.assertIn("ims.example", text)
        self.assertIn("ISIM public user identity", text)
        self.assertIn("sip:tagged@sim.test", text)
        self.assertIn("ISIM service table", text)
        self.assertIn("P-CSCF address", text)
        self.assertIn("activeCount", text)
        self.assertIn("ISIM P-CSCF address", text)
        self.assertIn("192.168.12.34", text)
        self.assertIn("recordIdentifier", text)
        self.assertIn("AABB", text)
        self.assertIn("Equivalent HPLMN presentation indication", text)
        self.assertIn("display_all", text)
        self.assertIn("GBA NAF List", text)
        self.assertIn("nafId", text)
        self.assertIn("01020304", text)
        self.assertIn("NAF Key Centre Address", text)
        self.assertIn("naf.example", text)
        self.assertIn("UTRAN", text)

    def test_subtree_report_decodes_counter_and_acl_payloads(self) -> None:
        subtree = {
            "ef-acmax": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "000102",
                        },
                    ]
                }
            ],
            "ef-acm": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "000005",
                        },
                    ]
                }
            ],
            "ef-acl": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "00",
                        },
                    ]
                }
            ],
            "ef-ict": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "0000A0",
                        },
                    ]
                }
            ],
            "ef-oct": [
                {
                    _TAG_TUPLE: [
                        "fillFileContent",
                        {
                            _TAG_BYTES: "0000B0",
                        },
                    ]
                }
            ],
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "telecom",
            focus_path_hint=["telecom"],
        )

        self.assertIn("Accumulated call meter maximum", text)
        self.assertIn("acmMax", text)
        self.assertIn("258", text)
        self.assertIn("Accumulated call meter", text)
        self.assertIn("Access Point Name Control List", text)
        self.assertIn("apnCount", text)
        self.assertIn("Incoming call timer", text)
        self.assertIn("Outgoing call timer", text)
        self.assertIn("160", text)
        self.assertIn("176", text)

    def test_subtree_report_decodes_filesystem_and_secret_fields(self) -> None:
        subtree = {
            "fileDescriptor": {_TAG_BYTES: "42210026"},
            "efFileSize": {_TAG_BYTES: "04BA"},
            "shortEFID": {_TAG_BYTES: "10"},
            "lcsi": {_TAG_BYTES: "05"},
            "pinValue": {_TAG_BYTES: "31323334FFFFFFFF"},
            "pukValue": {_TAG_BYTES: "3132333435363738"},
            "fillFileOffset": 0,
            "unblockingPINReference": 1,
            "instanceAID": {_TAG_BYTES: "A000000151000000"},
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "mf",
            focus_path_hint=["mf"],
        )

        self.assertIn("ETSI TS 102 221 file descriptor", text)
        self.assertIn("linear_fixed", text)
        self.assertIn("recordLength", text)
        self.assertIn("EF file size", text)
        self.assertIn("1210 byte(s)", text)
        self.assertIn("Short EF Identifier", text)
        self.assertIn("SFI 2", text)
        self.assertIn("operational_activated", text)
        self.assertIn("PIN/PUK value", text)
        self.assertIn("1234", text)
        self.assertIn("12345678", text)
        self.assertIn("File content offset", text)
        self.assertIn("PUK key reference", text)
        self.assertIn("pukAppl1", text)
        self.assertIn("Application Identifier", text)
        self.assertIn("RID", text)

    def test_subtree_report_decodes_pin_policy_and_rfm_fields(self) -> None:
        subtree = {
            "keyReference": 10,
            "pinAttributes": 6,
            "pinStatusTemplateDO": {_TAG_BYTES: "010A"},
            "tarList": [{_TAG_BYTES: "B00001"}],
            "minimumSecurityLevel": {_TAG_BYTES: "16"},
            "uiccAccessDomain": {_TAG_BYTES: "02030104"},
            "adfAccessDomain": {_TAG_BYTES: "02030104"},
        }

        text = build_inspector_report_for_subtree(
            subtree,
            "rfm",
            focus_path_hint=["rfm"],
        )

        self.assertIn("PIN/PUK/ADM key reference", text)
        self.assertIn("adm1", text)
        self.assertIn("PIN attributes", text)
        self.assertIn("setBits", text)
        self.assertIn("PIN status template DO", text)
        self.assertIn("statusBytes", text)
        self.assertIn("Toolkit Application Reference", text)
        self.assertIn("B00001", text)
        self.assertIn("Minimum security level", text)
        self.assertIn("0x16", text)
        self.assertIn("Access domain", text)
        self.assertIn("bytes", text)
        self.assertIn("0x02", text)

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

    @pytest.mark.skipif(
        _PYSIM_TEMPLATES_AVAILABLE is False,
        reason=(
            "pySim SAIP templates unavailable; clone "
            "https://gitlab.com/osmocom/pysim.git into the repo root "
            "or `pip install pySim` to re-enable this case."
        ),
    )
    def test_transcode_inspector_shows_template_defaults_without_explicit_json_fields(self) -> None:
        document = {
            "intro": [],
            "sections": {
                "usim": {
                    "templateID": "2.23.143.1.2.4.2",
                    "ef-imsi": [
                        {
                            _TAG_TUPLE: [
                                "fillFileContent",
                                {
                                    _TAG_BYTES: "082940808023551096",
                                },
                            ]
                        }
                    ],
                }
            },
        }

        editor_text = json.dumps(document, indent=2)
        sel = editor_text.index("082940808023551096")
        text = build_transcode_inspector_text(
            editor_text,
            sel,
            sel,
            left_mode="selection",
            pe_key_hint="usim",
            focus_key_hint="ef-imsi",
        )

        self.assertNotIn("Template defaults", text)
        template_text = build_template_defaults_report(
            document,
            pe_key="usim",
            focus_key_hint="ef-imsi",
        )
        self.assertIsNotNone(template_text)
        self.assertIn("Template defaults", template_text)
        self.assertIn("Template OID: 2.23.143.1.2.4.2", template_text)
        self.assertIn("Selected file: EF.IMSI (6F07) [TR]", template_text)
        self.assertIn("Implicit here because the JSON omits them:", template_text)
        self.assertIn("fileID 6F07", template_text)
        self.assertIn("shortEFID 07", template_text)
        self.assertIn("securityAttributesReferenced record 2", template_text)

    @pytest.mark.skipif(
        _PYSIM_TEMPLATES_AVAILABLE is False,
        reason=(
            "pySim SAIP templates unavailable; clone "
            "https://gitlab.com/osmocom/pysim.git into the repo root "
            "or `pip install pySim` to re-enable this case."
        ),
    )
    def test_transcode_inspector_resolves_template_arr_rule_summary(self) -> None:
        arr_record = "8001019000800102A406830101950108"
        document = {
            "intro": [],
            "sections": {
                "usim": {
                    "templateID": "2.23.143.1.2.4.2",
                    "ef-arr": [
                        {
                            _TAG_TUPLE: [
                                "fileDescriptor",
                                {
                                    "fileDescriptor": {
                                        _TAG_BYTES: "4221001010",
                                    },
                                    "efFileSize": {
                                        _TAG_BYTES: "0100",
                                    },
                                    "shortEFID": {
                                        _TAG_BYTES: "06",
                                    },
                                    "lcsi": {
                                        _TAG_BYTES: "05",
                                    },
                                },
                            ]
                        },
                        {
                            _TAG_TUPLE: [
                                "fillFileOffset",
                                0,
                            ]
                        },
                        {
                            _TAG_TUPLE: [
                                "fillFileContent",
                                {
                                    _TAG_BYTES: arr_record * 16,
                                },
                            ]
                        },
                    ],
                    "ef-imsi": [
                        {
                            _TAG_TUPLE: [
                                "fillFileContent",
                                {
                                    _TAG_BYTES: "082940808023551096",
                                },
                            ]
                        }
                    ],
                }
            },
        }

        editor_text = json.dumps(document, indent=2)
        sel = editor_text.index("082940808023551096")
        text = build_transcode_inspector_text(
            editor_text,
            sel,
            sel,
            left_mode="selection",
            pe_key_hint="usim",
            focus_key_hint="ef-imsi",
        )

        self.assertIn("securityAttributesReferenced record 2:", text)
        self.assertIn("Always", text)
        self.assertIn("PIN1", text)

    def test_transcode_inspector_subtree_override_decodes_grouped_gfm_file(self) -> None:
        grouped_file = [
            {
                _TAG_TUPLE: [
                    "createFCP",
                    {
                        "fileID": {
                            _TAG_BYTES: "2FE2",
                        }
                    },
                ]
            },
            {
                _TAG_TUPLE: [
                    "fillFileContent",
                    {
                        _TAG_BYTES: "988812010000400310F0",
                    },
                ]
            },
        ]
        document = {
            "intro": [],
            "sections": {
                "genericFileManagement": {
                    "fileManagementCMD": [
                        grouped_file,
                    ]
                }
            },
        }

        editor_text = json.dumps(document, indent=2)
        text = build_transcode_inspector_text(
            editor_text,
            0,
            0,
            left_mode="selection",
            pe_key_hint="genericFileManagement",
            subtree_override=grouped_file,
        )

        self.assertIn(humanize_saip_display_name("fillFileContent"), text)
        self.assertIn("iccid", text.lower())
        self.assertIn("8988211000000430010", text)


if __name__ == "__main__":
    unittest.main()
