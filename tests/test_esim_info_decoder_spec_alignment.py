# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""EUICCInfo1 / EUICCInfo2 fields that had drifted from their ASN.1 definition.

The reference is the EUICCInfo2 SEQUENCE in SGP.22 v3.1 §4.3 (mirrored by
SGP.32 v1.2 §6.3.1), both carried under ``docs/tel-docs/converted``. The module
is AUTOMATIC TAGS, so a member's tag is its context number with the
constructed bit set for the SEQUENCE OF members and clear for the primitives.
"""

from __future__ import annotations

import unittest

from SCP03.logic.euicc_info2 import EUICC_INFO2_TAG_NAMES
from SCP03.logic.euicc_info2 import build_euicc_info2_detail_lines
from SCP03.logic.euicc_info2 import decode_euicc_info2_value
from SCP03.logic.euicc_info2 import decode_ipa_mode
from SCP03.logic.sgp32_decode import decode_euicc_info1_summary


def _tlv(tag_hex: str, value_hex: str) -> bytes:
    """Build one short-form BER-TLV."""

    tag = bytes.fromhex(tag_hex)
    value = bytes.fromhex(value_hex)
    if len(value) > 0x7F:
        raise ValueError("test vectors stay inside short-form lengths")
    return tag + bytes([len(value)]) + value


def _euicc_info2(body: bytes) -> bytes:
    return bytes.fromhex("BF22") + bytes([len(body)]) + body


def _labelled(response: bytes) -> dict[str, str]:
    """Map label to rendered value for the depth-0 detail lines."""

    return {
        name: value
        for depth, name, value in build_euicc_info2_detail_lines(response)
        if depth == 0
    }


class TreFieldTests(unittest.TestCase):
    """``treProperties`` [13] and ``treProductReference`` [14] are BF22 children.

    The bit-name branch used to key on 0x8D as a *parent* tag, which a
    primitive member never is, so both fields reached the view as raw hex.
    """

    def test_tre_properties_names_its_bits(self) -> None:
        response = _euicc_info2(_tlv("8D", "0060"))
        rendered = _labelled(response)["TRE Properties"]
        self.assertIn("isIntegrated", rendered)
        self.assertIn("usesRemoteMemory", rendered)
        self.assertNotIn("isDiscrete", rendered)

    def test_tre_properties_discrete_only(self) -> None:
        response = _euicc_info2(_tlv("8D", "0080"))
        self.assertIn("isDiscrete", _labelled(response)["TRE Properties"])

    def test_tre_product_reference_is_utf8_not_hex(self) -> None:
        # GlobalPlatform DLOA Platform_Label, carried as UTF8String.
        response = _euicc_info2(_tlv("8E", "5452452D5052442D3031"))
        self.assertEqual(
            _labelled(response)["TRE Product Reference"], '"TRE-PRD-01"'
        )

    def test_non_utf8_product_reference_falls_back_to_hex(self) -> None:
        response = _euicc_info2(_tlv("8E", "FFFE"))
        self.assertEqual(_labelled(response)["TRE Product Reference"], "FFFE")


class SigningV3ListTagTests(unittest.TestCase):
    """``euiccCiPKIdListForSigningV3`` is [17] SEQUENCE OF, so its tag is 'B1'.

    The table carried the primitive form '91', which no eUICC emits for a
    SEQUENCE OF member. [9] and [10] were already correct at 'A9' and 'AA'.
    """

    def test_tag_is_context_constructed(self) -> None:
        self.assertEqual(
            EUICC_INFO2_TAG_NAMES.get(0xB1), "CI PKId List For Signing V3"
        )
        self.assertNotIn(0x91, EUICC_INFO2_TAG_NAMES)

    def test_list_members_are_enumerated(self) -> None:
        body = _tlv("B1", _tlv("04", "AABBCCDD").hex() + _tlv("04", "11223344").hex())
        lines = build_euicc_info2_detail_lines(_euicc_info2(body))
        self.assertIn((0, "CI PKId List For Signing V3", "2 item(s)"), lines)
        self.assertIn((1, "CI PKId 1", "AABBCCDD"), lines)
        self.assertIn((1, "CI PKId 2", "11223344"), lines)

    def test_child_decodes_like_the_other_key_id_lists(self) -> None:
        self.assertEqual(
            decode_euicc_info2_value(0x04, bytes.fromhex("AABB"), 0xB1), "AABB"
        )


class IpaModeTests(unittest.TestCase):
    """``IpaMode ::= INTEGER { ipad(0), ipae(1) }`` (SGP.32 v1.2 §6.3.1).

    SGP.22 spells the same member ``lpaMode`` with ``lpad(0)``/``lpae(1)``.
    Value 1 was reported as "Mode 1", which names neither.
    """

    def test_ipad(self) -> None:
        self.assertEqual(decode_ipa_mode(b"\x00"), "IPAd active (0)")

    def test_ipae(self) -> None:
        self.assertEqual(decode_ipa_mode(b"\x01"), "IPAe active (1)")

    def test_unassigned_value_is_reported_verbatim(self) -> None:
        self.assertIn("2", decode_ipa_mode(b"\x02"))


class UnknownTagSurfacingTests(unittest.TestCase):
    """The module is EXTENSIBILITY IMPLIED, so unnamed tags still get reported.

    The detail view walked a fixed tag list and dropped everything else, which
    made a response from a newer eUICC look shorter than it was.
    """

    def test_unnamed_tag_reaches_the_view(self) -> None:
        response = _euicc_info2(_tlv("95", "DEADBEEF"))
        self.assertEqual(_labelled(response)["Unknown Tag 95"], "DEADBEEF")

    def test_named_tags_are_not_duplicated_as_unknown(self) -> None:
        response = _euicc_info2(_tlv("90", "01"))
        labels = list(_labelled(response))
        self.assertIn("LPA/IPA Mode", labels)
        self.assertFalse([name for name in labels if name.startswith("Unknown Tag")])

    def test_every_repeat_of_an_unnamed_tag_is_reported(self) -> None:
        # A tag-keyed map collapses repeats to the first occurrence, so the
        # unknown pass walks the nodes instead.
        body = _tlv("95", "AA") + _tlv("90", "01") + _tlv("95", "BB")
        lines = build_euicc_info2_detail_lines(_euicc_info2(body))
        self.assertIn((0, "Unknown Tag 95", "AA"), lines)
        self.assertIn((0, "Unknown Tag 95", "BB"), lines)

    def test_unnamed_tags_keep_wire_order(self) -> None:
        body = _tlv("96", "CC") + _tlv("95", "AA")
        reported = [
            value
            for _depth, name, value in build_euicc_info2_detail_lines(
                _euicc_info2(body)
            )
            if name.startswith("Unknown Tag")
        ]
        self.assertEqual(reported, ["CC", "AA"])


class EuiccInfo1FieldTests(unittest.TestCase):
    """EUICCInfo1 (SGP.22 v3.1 §4.3) has six members; three went unreported.

    ``euiccRspCapability`` [8], ``euiccCiPKIdListForSigningV3`` [17] and
    ``highestSvn`` [19] are all optional, so a summary that omits them cannot
    be told apart from a card that does not send them.
    """

    def _response(self) -> bytes:
        body = (
            _tlv("82", "030100")
            + _tlv("A9", _tlv("04", "AABB").hex())
            + _tlv("AA", _tlv("04", "CCDD").hex())
            + _tlv("B1", _tlv("04", "EEFF").hex() + _tlv("04", "1122").hex())
            + _tlv("88", "0086")
            + _tlv("93", "030200")
        )
        return bytes.fromhex("BF20") + bytes([len(body)]) + body

    def test_existing_fields_are_unchanged(self) -> None:
        summary = decode_euicc_info1_summary(self._response())
        self.assertEqual(summary["svn"], "v3.1.0 (030100)")
        self.assertEqual(summary["ci_pk_verify_entries"], 1)
        self.assertEqual(summary["ci_pk_sign_entries"], 1)

    def test_signing_v3_list_is_counted(self) -> None:
        summary = decode_euicc_info1_summary(self._response())
        self.assertEqual(summary["ci_pk_sign_v3_entries"], 2)

    def test_highest_svn_is_reported(self) -> None:
        summary = decode_euicc_info1_summary(self._response())
        self.assertEqual(summary["highest_svn"], "v3.2.0 (030200)")

    def test_rsp_capability_bits_are_named(self) -> None:
        # 0x86 is 1000 0110 read MSB-first: bits 0, 5 and 6.
        summary = decode_euicc_info1_summary(self._response())
        self.assertEqual(summary["rsp_capability_hex"], "0086")
        self.assertEqual(
            summary["rsp_capability"],
            [
                "additionalProfile",
                "serviceSpecificDataSupport",
                "hriServerAddressSupport",
            ],
        )

    def test_absent_optionals_stay_absent(self) -> None:
        body = _tlv("82", "030100")
        response = bytes.fromhex("BF20") + bytes([len(body)]) + body
        summary = decode_euicc_info1_summary(response)
        self.assertNotIn("highest_svn", summary)
        self.assertNotIn("rsp_capability", summary)
        self.assertEqual(summary["ci_pk_sign_v3_entries"], 0)

    def test_malformed_capability_still_reports_its_bytes(self) -> None:
        # Non-zero padding bits: the bytes are reported, the names withheld.
        body = _tlv("82", "030100") + _tlv("88", "0701")
        response = bytes.fromhex("BF20") + bytes([len(body)]) + body
        summary = decode_euicc_info1_summary(response)
        self.assertEqual(summary["rsp_capability_hex"], "0701")
        self.assertEqual(summary["rsp_capability"], [])


if __name__ == "__main__":
    unittest.main()
