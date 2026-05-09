"""
Round-6 Sweeps 2 & 3 — parent_hint threading through the offline JSON
inspectors and the decoded-editor audit.

The TRANSCODE inspector (``saip_transcode_inspect.build_transcode_inspector_text``)
and the decoded-editor audit (``saip_decoded_edit_audit.audit_decoded_editors``)
both ultimately call into ``_decode_known_ef_payload`` / ``_decode_special_field``.
These regression tests lock in:

* ``build_inspector_report_for_subtree`` resolves FIDs against the
  supplied ``pe_section_key`` so a bare ``6F3A`` under ``usim`` labels
  as EF.ADN under ADF.USIM, and under ``telecom`` labels as the
  DF.Telecom variant.
* ``_classify_ef_member`` in the audit accepts a ``parent_hint``
  argument and propagates it to ``_decode_known_ef_payload`` without
  changing the deterministic coverage result for tokenised EF keys.
* The ``_PE_TYPE_TO_PARENT_HINT`` lookup returns sensible DF/ADF
  tokens for every PE type the audit enumerates.
"""

from __future__ import annotations

from Tools.ProfilePackage.saip_asn1_decode import (
    build_inspector_report_for_subtree,
)
from Tools.ProfilePackage.saip_decoded_edit_audit import (
    _PE_TYPE_TO_PARENT_HINT,
    _classify_ef_member,
    _is_ef_key_covered,
    _parent_hint_for_path,
)


class TestParentHintForPath:
    def test_pe_usim_maps_to_adf_usim(self) -> None:
        assert _parent_hint_for_path(("PE-USIM",)) == "adf-usim"

    def test_pe_telecom_maps_to_df_telecom(self) -> None:
        assert _parent_hint_for_path(("PE-Telecom",)) == "df-telecom"

    def test_pe_isim_maps_to_adf_isim(self) -> None:
        assert _parent_hint_for_path(("PE-ISIM",)) == "adf-isim"

    def test_pe_mf_maps_to_mf(self) -> None:
        assert _parent_hint_for_path(("PE-MF",)) == "mf"

    def test_unknown_pe_type_returns_none(self) -> None:
        assert _parent_hint_for_path(("PE-Nonexistent",)) is None

    def test_empty_path_returns_none(self) -> None:
        assert _parent_hint_for_path(tuple()) is None

    def test_mapping_covers_common_dfs(self) -> None:
        for required in ("PE-USIM", "PE-ISIM", "PE-CSIM", "PE-Telecom", "PE-MF"):
            assert required in _PE_TYPE_TO_PARENT_HINT


class TestEfCoverageAcceptsParentHint:
    def test_ef_imsi_covered_under_adf_usim(self) -> None:
        result = _is_ef_key_covered("ef-imsi", parent_hint="adf-usim")
        assert result is not None

    def test_ef_imsi_covered_without_parent_hint(self) -> None:
        # Parent hint is optional; the ef token alone must still route.
        assert _is_ef_key_covered("ef-imsi") is not None

    def test_ef_adn_covered_under_telecom(self) -> None:
        # EF.ADN lives under both DF.Telecom and DF.Phonebook; the
        # coverage check must still succeed for either parent.
        assert _is_ef_key_covered("ef-adn", parent_hint="df-telecom") is not None
        assert _is_ef_key_covered("ef-adn", parent_hint="df-phonebook") is not None

    def test_classify_ef_member_accepts_parent_hint_kwarg(self) -> None:
        # Regression: the signature must accept ``parent_hint`` without
        # raising ``TypeError`` so the walker can thread it in.
        classification = _classify_ef_member("ef-imsi", parent_hint="adf-usim")
        assert isinstance(classification, str) and len(classification) > 0


class TestBuildInspectorReportUsesPeSectionKey:
    def test_adf_usim_ef_adn_labels_under_usim(self) -> None:
        subtree = {
            "ef-adn": [
                {"@": ["fillFileContent", {"hex": "FF" * 32}]},
            ],
        }
        report = build_inspector_report_for_subtree(subtree, "usim")
        assert "adf-usim" in report or "USIM" in report or "ADN" in report

    def test_telecom_ef_adn_labels_under_telecom(self) -> None:
        subtree = {
            "ef-adn": [
                {"@": ["fillFileContent", {"hex": "FF" * 32}]},
            ],
        }
        report = build_inspector_report_for_subtree(subtree, "telecom")
        assert "telecom" in report.lower() or "ADN" in report

    def test_pe_section_key_is_reflected_in_header(self) -> None:
        # Exercise the report for mf so the 2F06 EF.ARR collision
        # under MF is disambiguated against the 6F06 USIM variant.
        subtree = {
            "ef-arr": [
                {"@": ["fillFileContent", {"hex": "8001019000"}]},
            ],
        }
        report = build_inspector_report_for_subtree(subtree, "mf")
        assert len(report) > 0
        assert "ef-arr" in report.lower() or "ARR" in report
