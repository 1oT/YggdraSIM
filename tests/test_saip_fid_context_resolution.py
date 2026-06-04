"""
Regression tests for parent-context-aware FID label resolution.

Covers the ``fid_name`` / ``_decode_file_identifier`` / GFM tree-pane path
that fixes the "EF.MSISDN shown alongside EF.CSIM-MDN" bug reported for
FID 6F40 (ADF.USIM vs ADF.CSIM). The same machinery disambiguates every
FID collision enumerated in ``_FID_TO_PARENTED_NAMES``.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _FID_TO_NAME,
    _FID_TO_PARENTED_NAMES,
    _decode_file_identifier,
    _decode_file_path,
    _decode_known_ef_payload,
    _decode_security_attributes_referenced,
    _normalize_parent_hint,
    _parent_hint_from_path,
    _resolve_ef_key_for_fid,
    fid_candidates,
    fid_name,
    parent_token_for_container_fid,
    parent_token_from_file_path_hex,
)
from yggdrasim_common.gui_server.actions.saip import _saip_reverse_fid_friendly


class ParentHintNormalisationTests(unittest.TestCase):
    def test_pe_section_keys_normalise_to_parent_token(self) -> None:
        self.assertEqual(_normalize_parent_hint("usim"), "adf-usim")
        self.assertEqual(_normalize_parent_hint("USIM"), "adf-usim")
        self.assertEqual(_normalize_parent_hint("usim_2"), "adf-usim")
        self.assertEqual(_normalize_parent_hint("csim_3"), "adf-csim")
        self.assertEqual(_normalize_parent_hint("telecom"), "df-telecom")
        self.assertEqual(_normalize_parent_hint("wlan"), "df-wlan")
        self.assertEqual(_normalize_parent_hint("mcs"), "df-mcs")
        self.assertEqual(_normalize_parent_hint("v2x"), "df-v2x")

    def test_tokens_are_accepted_verbatim(self) -> None:
        self.assertEqual(_normalize_parent_hint("adf-usim"), "adf-usim")
        self.assertEqual(_normalize_parent_hint("ADF-USIM"), "adf-usim")
        self.assertEqual(_normalize_parent_hint("df-5gs"), "df-5gs")

    def test_empty_or_generic_fm_returns_none(self) -> None:
        self.assertIsNone(_normalize_parent_hint(None))
        self.assertIsNone(_normalize_parent_hint(""))
        self.assertIsNone(_normalize_parent_hint("genericFileManagement"))


class FidNameResolutionTests(unittest.TestCase):
    def test_msisdn_vs_csim_mdn_disambiguated_by_parent(self) -> None:
        self.assertEqual(fid_name("6F40", parent_hint="usim"), "EF.MSISDN")
        self.assertEqual(fid_name("6F40", parent_hint="csim"), "EF.CSIM-MDN")

    def test_imsi_vs_ist_disambiguated(self) -> None:
        self.assertEqual(fid_name("6F07", parent_hint="usim"), "EF.IMSI")
        self.assertEqual(fid_name("6F07", parent_hint="isim"), "EF.IST")

    def test_4f01_collision_resolves_with_specific_parent(self) -> None:
        self.assertEqual(
            fid_name("4F01", parent_hint="adf-usim"),
            "EF.SUCI-CALC-INFO-USIM",
        )
        self.assertEqual(
            fid_name("4F01", parent_hint="df-5gs"),
            "EF.5GS3GPPLOCI",
        )
        self.assertEqual(
            fid_name("4F01", parent_hint="df-mcs"),
            "EF.MST",
        )
        self.assertEqual(
            fid_name("4F01", parent_hint="df-v2x"),
            "EF.VST",
        )
        self.assertEqual(
            fid_name("4F01", parent_hint="adf-v2x"),
            "EF.V2X-CFG",
        )

    def test_manual_service_table_fids_resolve_by_parent(self) -> None:
        self.assertEqual(_resolve_ef_key_for_fid("6F32", "adf-csim"), "ef-csim-st")
        self.assertEqual(_resolve_ef_key_for_fid("4F10", "df-prose"), "ef-pst")
        self.assertEqual(_resolve_ef_key_for_fid("4F01", "df-5gprose"), "ef-5g-prose-st")
        self.assertEqual(_resolve_ef_key_for_fid("4F01", "df-mcs"), "ef-mst")
        self.assertEqual(_resolve_ef_key_for_fid("4F01", "df-v2x"), "ef-vst")
        self.assertEqual(_resolve_ef_key_for_fid("6FE0", "df-telecom"), "ef-ice-dn")

    def test_df_graphics_dynamic_fids_resolve_by_parent(self) -> None:
        self.assertEqual(fid_name("4F01", parent_hint="df-graphics"), "EF.LAUNCH_SCWS")
        self.assertEqual(fid_name("4F20", parent_hint="df-graphics"), "EF.IMG")
        self.assertEqual(fid_name("4F21", parent_hint="df-graphics"), "EF.ICE_GRAPHICS")
        for fid in ("4F40", "4F59", "4F60", "4F61", "4F67", "4F7F"):
            self.assertEqual(fid_name(fid, parent_hint="df-graphics"), "EF.IIDF", fid)

    def test_gui_reverse_lookup_prefers_df_graphics_context(self) -> None:
        parent = "3F00/7F10/5F50"
        self.assertEqual(
            _saip_reverse_fid_friendly("4F20", parent_fid_hex=parent),
            "EF.IMG",
        )
        self.assertEqual(
            _saip_reverse_fid_friendly("4F21", parent_fid_hex=parent),
            "EF.ICE_GRAPHICS",
        )
        self.assertEqual(
            _saip_reverse_fid_friendly("4F61", parent_fid_hex=parent),
            "EF.IIDF",
        )
        self.assertEqual(
            _saip_reverse_fid_friendly("4F67", parent_fid_hex=parent),
            "EF.IIDF",
        )

    def test_unknown_parent_falls_back_to_disambiguated_label(self) -> None:
        combined = fid_name("6F40")
        self.assertEqual(
            combined,
            "EF.MSISDN (ADF.USIM) / EF.CSIM-MDN (ADF.CSIM)",
        )
        self.assertEqual(
            fid_name("6F40", parent_hint="genericFileManagement"),
            combined,
        )

    def test_non_colliding_labels_are_unchanged(self) -> None:
        self.assertEqual(fid_name("6F08"), "EF.KEYS")
        self.assertEqual(fid_name("6FB7"), "EF.ECC")
        self.assertEqual(fid_name("7FF0"), "ADF.USIM")

    def test_same_parent_aliases_keep_combined_form(self) -> None:
        # ef-ust and ef-ust-service-table both live under ADF.USIM.
        self.assertEqual(
            _FID_TO_NAME.get("6F38"),
            "EF.UST / EF.UST-SERVICE-TABLE",
        )

    def test_fid_candidates_exposes_parent_pairs(self) -> None:
        candidates = fid_candidates("6F40")
        self.assertIn(("adf-usim", "EF.MSISDN"), candidates)
        self.assertIn(("adf-csim", "EF.CSIM-MDN"), candidates)

    def test_every_collision_has_a_unique_parent_set(self) -> None:
        # At least one FID must legitimately collide. If a future edit
        # accidentally makes every entry unique this test starts failing and
        # prompts maintenance of the _EF_KEY_TO_PARENT_TOKEN table.
        collisions = [
            fid
            for fid, entries in _FID_TO_PARENTED_NAMES.items()
            if len(entries) > 1
        ]
        self.assertGreater(len(collisions), 0)


class DecodeFileIdentifierTests(unittest.TestCase):
    def test_parent_hint_selects_msisdn_under_usim(self) -> None:
        decoded = _decode_file_identifier(bytes.fromhex("6F40"), parent_hint="usim")
        assert decoded is not None
        self.assertEqual(decoded["hex"], "6F40")
        self.assertEqual(decoded["name"], "EF.MSISDN")
        self.assertEqual(decoded["parent"], "ADF.USIM")
        self.assertEqual(decoded["summary"], "6F40 (EF.MSISDN)")

    def test_parent_hint_selects_csim_mdn_under_csim(self) -> None:
        decoded = _decode_file_identifier(bytes.fromhex("6F40"), parent_hint="csim")
        assert decoded is not None
        self.assertEqual(decoded["name"], "EF.CSIM-MDN")
        self.assertEqual(decoded["parent"], "ADF.CSIM")

    def test_no_parent_hint_returns_disambiguated_combined_label(self) -> None:
        decoded = _decode_file_identifier(bytes.fromhex("6F40"))
        assert decoded is not None
        self.assertEqual(
            decoded["name"],
            "EF.MSISDN (ADF.USIM) / EF.CSIM-MDN (ADF.CSIM)",
        )
        self.assertNotIn("parent", decoded)

    def test_non_colliding_fid_remains_stable(self) -> None:
        decoded = _decode_file_identifier(bytes.fromhex("6FB7"), parent_hint="usim")
        assert decoded is not None
        self.assertEqual(decoded["name"], "EF.ECC")
        self.assertNotIn("parent", decoded)


class DecodeFilePathTests(unittest.TestCase):
    def test_file_path_labels_respect_parent_hint(self) -> None:
        decoded = _decode_file_path(bytes.fromhex("3F007FF06F40"), parent_hint="usim")
        assert decoded is not None
        segments = decoded.get("segments")
        assert isinstance(segments, list)
        leaf = segments[-1]
        self.assertEqual(leaf["fid"], "6F40")
        self.assertEqual(leaf["name"], "EF.MSISDN")
        self.assertEqual(decoded["summary"], "MF / ADF.USIM / EF.MSISDN")


class DecodeSecurityAttributesReferencedTests(unittest.TestCase):
    def test_arr_file_name_uses_parent_hint(self) -> None:
        # FID 6F06 is the standard EF.ARR in every DF, so the parent hint is
        # orthogonal. The test simply guards that the kw-arg plumbing works.
        decoded = _decode_security_attributes_referenced(
            bytes.fromhex("6F0607"),
            parent_hint="usim",
        )
        assert decoded is not None
        self.assertEqual(decoded["arrFileId"], "6F06")
        self.assertEqual(decoded["arrFileName"], "EF.ARR")
        self.assertEqual(decoded["recordNumber"], 7)


class ContainerFidAndPathHelpersTests(unittest.TestCase):
    def test_container_fid_to_parent_token(self) -> None:
        self.assertEqual(parent_token_for_container_fid("3F00"), "mf")
        self.assertEqual(parent_token_for_container_fid("7FF0"), "adf-usim")
        self.assertEqual(parent_token_for_container_fid("7FF2"), "adf-isim")
        self.assertEqual(parent_token_for_container_fid("7FF3"), "adf-csim")
        self.assertEqual(parent_token_for_container_fid("7F10"), "df-telecom")
        self.assertEqual(parent_token_for_container_fid("5F50"), "df-graphics")
        self.assertIsNone(parent_token_for_container_fid("6F40"))

    def test_parent_token_from_file_path_prefers_trailing_container(self) -> None:
        self.assertEqual(parent_token_from_file_path_hex("3F007FF0"), "adf-usim")
        self.assertEqual(parent_token_from_file_path_hex("3F007FF3"), "adf-csim")
        self.assertEqual(
            parent_token_from_file_path_hex("3F007FF05FC0"),
            "df-5gs",
        )
        self.assertIsNone(parent_token_from_file_path_hex(""))
        self.assertIsNone(parent_token_from_file_path_hex(None))


class ParentHintFromWalkerStateTests(unittest.TestCase):
    def test_last_ef_key_wins_over_pe_type(self) -> None:
        hint = _parent_hint_from_path(
            pe_section_key="telecom",
            last_ef_key="ef-msisdn",
        )
        self.assertEqual(hint, "adf-usim")

    def test_pe_section_key_used_when_ef_unknown(self) -> None:
        hint = _parent_hint_from_path(
            pe_section_key="csim_2",
            last_ef_key=None,
        )
        self.assertEqual(hint, "adf-csim")

    def test_generic_file_management_returns_none(self) -> None:
        hint = _parent_hint_from_path(
            pe_section_key="genericFileManagement",
            last_ef_key=None,
        )
        self.assertIsNone(hint)


class DecodeKnownEfPayloadParentHintTests(unittest.TestCase):
    """
    ``_decode_known_ef_payload`` picks the correct decoder lane when only the
    FID is known, using ``parent_hint`` to resolve cross-ADF collisions. The
    explicit ef-key path already wins without the hint; these cases cover the
    GFM flow where the walker only carries SELECT-derived containers.
    """

    def test_msisdn_resolved_via_parent_hint(self) -> None:
        # 14-byte MSISDN record filled with 0xFF is the empty / wiped state.
        decoded = _decode_known_ef_payload(
            ef_key=None,
            fid="6F40",
            hex_clean="FF" * 14,
            parent_hint="usim",
        )
        self.assertIsNotNone(decoded)
        # MSISDN decoder returns dict with ``number`` / ``tonNpi``.
        self.assertIn("tonNpi", decoded)

    def test_csim_mdn_resolved_via_parent_hint(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key=None,
            fid="6F40",
            hex_clean="00" * 10,
            parent_hint="csim",
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.get("format"), "CSIM MDN")

    def test_impdf_vs_csim_curr_sidnid_disambiguated(self) -> None:
        # 6F27 collides between ADF.ISIM (EF.IMPDF) and ADF.CSIM
        # (EF.CSIM-CURR-SIDNID). Without the hint the dispatcher cannot
        # pick a lane; with the hint it must.
        impdf = _decode_known_ef_payload(
            ef_key=None,
            fid="6F27",
            hex_clean="80020102",
            parent_hint="isim",
        )
        self.assertIsNotNone(impdf)
        # Anything that routed to CSIM opaque would carry a CSIM format;
        # IMPDF routes to the generic TLV decoder.
        self.assertNotIn("CSIM", str(impdf.get("format", "")))

        csim = _decode_known_ef_payload(
            ef_key=None,
            fid="6F27",
            hex_clean="00" * 4,
            parent_hint="csim",
        )
        self.assertIsNotNone(csim)
        self.assertIn("CSIM", str(csim.get("format", "")))

    def test_resolver_picks_canonical_key(self) -> None:
        self.assertEqual(_resolve_ef_key_for_fid("6F40", "adf-usim"), "ef-msisdn")
        self.assertEqual(
            _resolve_ef_key_for_fid("6F40", "adf-csim"),
            "ef-csim-mdn",
        )
        self.assertEqual(_resolve_ef_key_for_fid("6F27", "adf-isim"), "ef-impdf")
        self.assertEqual(
            _resolve_ef_key_for_fid("6F27", "adf-csim"),
            "ef-csim-curr-sidnid",
        )
        self.assertEqual(_resolve_ef_key_for_fid("4F20", "df-graphics"), "ef-img")
        self.assertEqual(
            _resolve_ef_key_for_fid("4F21", "df-graphics"),
            "ef-ice-graphics",
        )
        self.assertEqual(_resolve_ef_key_for_fid("4F61", "df-graphics"), "ef-iidf")
        self.assertEqual(_resolve_ef_key_for_fid("4F67", "df-graphics"), "ef-iidf")
        self.assertIsNone(_resolve_ef_key_for_fid("6F40", "df-telecom"))
        self.assertIsNone(_resolve_ef_key_for_fid("", "adf-usim"))

    def test_explicit_ef_key_still_wins_without_hint(self) -> None:
        # When the caller knows the token, parent_hint is redundant.
        decoded = _decode_known_ef_payload(
            ef_key="ef-msisdn",
            fid="6F40",
            hex_clean="FF" * 14,
        )
        self.assertIsNotNone(decoded)
        self.assertIn("tonNpi", decoded)


class UriEfFidCorrectionTests(unittest.TestCase):
    """Regression guards around the FDNURI/BDNURI/SDNURI re-anchoring."""

    def test_fdn_uri_anchored_at_6fed(self) -> None:
        self.assertEqual(fid_name("6FED"), "EF.FDNURI")

    def test_bdn_uri_anchored_at_6fee(self) -> None:
        self.assertEqual(fid_name("6FEE"), "EF.BDNURI")

    def test_sdn_uri_anchored_at_6fef(self) -> None:
        self.assertEqual(fid_name("6FEF"), "EF.SDNURI")

    def test_pws_not_shadowed_by_sdn_uri(self) -> None:
        # 6FEC used to carry a "EF.SDN URI / EF.PWS" combined label because
        # both tokens claimed the same FID. It now cleanly resolves to PWS.
        self.assertEqual(fid_name("6FEC"), "EF.PWS")


class UriPayloadClassificationTests(unittest.TestCase):
    """Round-4 Pass 2 guards around ``_decode_uri_record`` RFC 3986 split."""

    def _build(self, uri: str) -> str:
        payload = uri.encode("utf-8")
        return f"80{len(payload):02X}{payload.hex().upper()}"

    def test_sip_authority_split(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-vsuri",
            fid="6FE9",
            hex_clean=self._build("sip:voicemail@ims.example.com:5060"),
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.get("scheme"), "sip")
        # ``sip:`` is an opaque-scheme URI, not ``sip://host``, so the
        # authority regex does not match and we expose the opaque tail.
        self.assertEqual(
            decoded.get("opaque"),
            "voicemail@ims.example.com:5060",
        )
        self.assertTrue(decoded.get("rfc3986Compliant"))
        self.assertEqual(decoded.get("reference"), "TS 31.102 §4.2.68")

    def test_https_full_authority(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-muddomain",
            fid="6FDF",
            hex_clean=self._build(
                "https://mud.example.com/iot?ver=1#frag"
            ),
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.get("scheme"), "https")
        self.assertEqual(decoded.get("host"), "mud.example.com")
        self.assertEqual(decoded.get("path"), "/iot")
        self.assertEqual(decoded.get("query"), "ver=1")
        self.assertEqual(decoded.get("fragment"), "frag")
        self.assertTrue(decoded.get("rfc3986Compliant"))

    def test_percent_decoding(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-fdnuri",
            fid="6FED",
            hex_clean=self._build("https://ex.com/p%20a%3Fth"),
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.get("percentDecoded"), "https://ex.com/p a?th")

    def test_malformed_uri_flagged(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-lnduri",
            fid="6FEA",
            hex_clean=self._build("not-a-uri"),
        )
        self.assertIsNotNone(decoded)
        self.assertFalse(decoded.get("rfc3986Compliant"))


if __name__ == "__main__":
    unittest.main()
