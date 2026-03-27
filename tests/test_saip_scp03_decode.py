import unittest

from Tools.ProfilePackage.saip_json_codec import _TAG_BYTES, _TAG_TUPLE
from Tools.ProfilePackage.saip_scp03_decode import (
    build_inspector_report_for_subtree,
    build_scp03_decode_report,
)


class SaipScp03DecodeTests(unittest.TestCase):
    def test_iccid_under_mf_fill_file_content(self) -> None:
        doc = {
            "intro": [],
            "sections": {
                "mf": {
                    "ef-iccid": [
                        {
                            "__ygg_saip_tuple__": [
                                "fillFileContent",
                                {
                                    "__ygg_saip_bytes__": (
                                        "9897012345678901F0F0F0F0F0F0F0FF"
                                    ),
                                },
                            ],
                        },
                    ],
                },
            },
        }
        text = build_scp03_decode_report(doc, max_sections=8, max_hits_per_doc=20)
        self.assertIn("mf ::", text)
        self.assertIn("iccid", text.lower())

    def test_security_domain_tlv_fallback(self) -> None:
        doc = {
            "intro": [],
            "sections": {
                "securityDomain": {
                    "instance": {
                        "applicationSpecificParametersC9": {
                            "__ygg_saip_bytes__": "8201F0"
                        },
                    },
                },
            },
        }
        text = build_scp03_decode_report(doc, max_sections=8, max_hits_per_doc=20)
        self.assertIn("securityDomain", text)

    def test_subtree_decode_uses_ef_hint(self) -> None:
        subtree = [
            {
                _TAG_TUPLE: [
                    "fillFileContent",
                    {
                        _TAG_BYTES: "9897012345678901F0F0F0F0F0F0F0FF",
                    },
                ],
            },
        ]
        text = build_inspector_report_for_subtree(
            subtree,
            "mf",
            focus_path_hint=["ef-iccid"],
            last_ef_key="ef-iccid",
        )
        self.assertIn("iccid", text.lower())

    def test_tlv_fallback_is_rendered_compactly(self) -> None:
        subtree = {
            "unknown-ef": {
                _TAG_BYTES: "8201F0",
            },
        }
        text = build_inspector_report_for_subtree(subtree, "mf")
        self.assertIn("TLV map (no EF FID)", text)
        self.assertIn("| TLV", text)
        self.assertIn("| 82", text)
        self.assertNotIn("{\n", text)


if __name__ == "__main__":
    unittest.main()
