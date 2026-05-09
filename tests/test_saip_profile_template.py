import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_profile_template import (
    apply_placeholder_overrides_to_loaded_document,
    batch_output_stem,
    build_placeholder_template_document,
    encode_iccid_ef_hex,
    encode_iccid_header_hex,
    encode_imsi_ef_hex,
    extract_template_placeholder_names,
    load_batch_placeholder_records,
    parse_placeholder_assignment_tokens,
    validate_batch_record_assignments,
)


class SaipProfileTemplateTests(unittest.TestCase):
    def test_parse_placeholder_assignment_tokens_accepts_wrapped_names(self) -> None:
        assignments = parse_placeholder_assignment_tokens(
            [
                "{ICCID}=89881111111111111112",
                "[IMSI]=1234567812345678",
            ]
        )

        self.assertEqual(assignments["ICCID"], "89881111111111111112")
        self.assertEqual(assignments["IMSI"], "1234567812345678")

    def test_encode_iccid_helpers(self) -> None:
        self.assertEqual(
            encode_iccid_header_hex("89881111111111111112"),
            "89881111111111111112",
        )
        self.assertEqual(
            encode_iccid_ef_hex("89881111111111111112"),
            "98881111111111111121",
        )

    def test_encode_imsi_helper_accepts_even_digit_count(self) -> None:
        self.assertEqual(
            encode_imsi_ef_hex("1234567812345678"),
            "091132547618325476F8",
        )

    def test_build_placeholder_template_document_injects_iccid_and_imsi(self) -> None:
        document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "iccid": bytes.fromhex("89881111111111111112"),
                },
                "mf": {
                    "ef-iccid": [
                        ("fillFileContent", bytes.fromhex("98881111111111111121")),
                    ],
                },
                "usim": {
                    "ef-imsi": [
                        ("fillFileContent", bytes.fromhex("091132547618325476F8")),
                    ],
                },
            },
        }

        tagged, summaries = build_placeholder_template_document(
            document,
            {
                "ICCID": "89881111111111111112",
                "IMSI": "1234567812345678",
            },
        )

        self.assertIn("ICCID", tagged["__ygg_token_defs__"])
        self.assertIn("ICCID_EF", tagged["__ygg_token_defs__"])
        self.assertIn("IMSI", tagged["__ygg_token_defs__"])
        self.assertEqual(tagged["__ygg_token_defs__"]["ICCID"]["hex"], "89881111111111111112")
        self.assertEqual(tagged["__ygg_token_defs__"]["ICCID_EF"]["hex"], "98881111111111111121")
        self.assertEqual(tagged["__ygg_token_defs__"]["IMSI"]["hex"], "091132547618325476F8")
        self.assertEqual(tagged["__ygg_placeholder_style__"], "brace")
        self.assertEqual(tagged["sections"]["header"]["iccid"]["hex"], "{ICCID}")
        self.assertEqual(
            tagged["sections"]["mf"]["ef-iccid"][0]["@"][1]["hex"],
            "{ICCID_EF}",
        )
        self.assertEqual(
            tagged["sections"]["usim"]["ef-imsi"][0]["@"][1]["hex"],
            "{IMSI}",
        )
        self.assertEqual(len(summaries), 2)

    def test_apply_placeholder_overrides_derives_known_tokens_and_keeps_custom_hex(self) -> None:
        loaded = {
            "intro": ["Template"],
            "sections": {
                "header": {
                    "iccid": {"hex": "{ICCID}"},
                },
            },
            "__ygg_token_defs__": {
                "PAYLOAD": {"hex": "ABCD"},
            },
        }

        summaries = apply_placeholder_overrides_to_loaded_document(
            loaded,
            {
                "ICCID": "89881111111111111112",
                "PAYLOAD": "FEED",
            },
        )

        self.assertEqual(loaded["__ygg_token_defs__"]["ICCID"]["hex"], "89881111111111111112")
        self.assertEqual(loaded["__ygg_token_defs__"]["ICCID_EF"]["hex"], "98881111111111111121")
        self.assertEqual(loaded["__ygg_token_defs__"]["PAYLOAD"]["hex"], "FEED")
        self.assertEqual(loaded["__ygg_placeholder_style__"], "brace")
        self.assertIn("ICCID override -> ICCID + ICCID_EF", summaries)
        self.assertIn("PAYLOAD override -> PAYLOAD", summaries)

    def test_extract_template_placeholder_names_finds_nested_tokens(self) -> None:
        loaded = {
            "sections": {
                "header": {"iccid": {"hex": "{ICCID}"}},
                "mf": {
                    "ef-iccid": [
                        {
                            "@": [
                                "fillFileContent",
                                {"hex": "{ICCID_EF}"},
                            ]
                        }
                    ],
                },
                "usim": {
                    "ef-imsi": [
                        {
                            "@": [
                                "fillFileContent",
                                {"hex": "{IMSI}"},
                            ]
                        }
                    ],
                },
            }
        }

        names = extract_template_placeholder_names(loaded)

        self.assertEqual(names, {"ICCID", "ICCID_EF", "IMSI"})

    def test_validate_batch_record_assignments_accepts_typed_iccid_mapping(self) -> None:
        assignments = validate_batch_record_assignments(
            {"ICCID": "89881111111111111112", "IMSI": "1234567812345678"},
            template_placeholders={"ICCID", "ICCID_EF", "IMSI"},
            template_token_defs={},
        )

        self.assertEqual(assignments["ICCID"], "89881111111111111112")
        self.assertEqual(assignments["IMSI"], "1234567812345678")

    def test_load_batch_placeholder_records_csv(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_path = Path(temp_dir) / "batch.csv"
            data_path.write_text(
                "ICCID,IMSI\n"
                "89881111111111111112,1234567812345678\n"
                "89881111111111111113,1234567812345679\n",
                encoding="utf-8",
            )

            records = load_batch_placeholder_records(data_path)

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].label, "csv row 2")
        self.assertEqual(records[0].values["ICCID"], "89881111111111111112")
        self.assertEqual(records[1].values["IMSI"], "1234567812345679")

    def test_batch_output_stem_prefers_iccid(self) -> None:
        stem = batch_output_stem(
            {"ICCID": "89881111111111111112", "IMSI": "1234567812345678"},
            index=7,
        )

        self.assertEqual(stem, "profile_iccid_89881111111111111112")


if __name__ == "__main__":
    unittest.main()
