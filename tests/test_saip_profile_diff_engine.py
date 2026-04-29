"""Coverage for the semantic SAIP profile-diff engine.

The engine in ``Tools/ProfilePackage/saip_profile_diff.py`` layers
context-aware classification on top of the raw structural walker
(``Tools/ProfilePackage/saip_diff_engine.py``). These tests pin down:

* category + severity assignment for the well-known leaves (ICCID,
  IMSI, AID, Ki/OPc, lifecycle, etc.);
* PE-sequence add/remove vs. PE-internal field changes;
* section reorder detection;
* the JSON-friendly serialisation used by the GUI dispatcher.

Reference: SGP.22 §2.5.3, ETSI TS 102 221 §13, GP 2.3 §11.1.1.
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_diff_engine import (
    DIFF_OP_ADDED,
    DIFF_OP_CHANGED,
    DIFF_OP_REMOVED,
    DiffEntry,
)
from Tools.ProfilePackage.saip_profile_diff import (
    CATEGORIES,
    CATEGORY_APPLICATIONS,
    CATEGORY_FILES,
    CATEGORY_IDENTITY,
    CATEGORY_INTRO,
    CATEGORY_LIFECYCLE,
    CATEGORY_OTHER,
    CATEGORY_PE_SEQUENCE,
    CATEGORY_SECURITY,
    CATEGORY_VARIABLES,
    SEVERITIES,
    SEVERITY_CRITICAL,
    SEVERITY_INFO,
    SEVERITY_NOTE,
    SEVERITY_WARNING,
    ProfileDiffEntry,
    ProfileDiffReport,
    classify_diff_entry,
    compute_profile_diff,
    format_profile_diff_text,
)


# ---------------------------------------------------------------------------
# Fixtures — minimal jsonified SAIP documents
# ---------------------------------------------------------------------------


def _baseline_document() -> dict:
    return {
        "intro": ["Profile A", "Vendor=ACME"],
        "sections": {
            "header": {
                "iccid": "8901001234567890123F",
                "profile_name": "Baseline",
            },
            "mf": {
                "efIccid": {"body": {"iccid": "8901001234567890123F"}},
                "efDir": {"body": {"raw": "DEADBEEF"}},
            },
            "usim": {
                "aid": "A0000000871002FFFFFFFF8902F1FFFFFFFF",
                "efImsi": {"body": {"imsi": "234561111111111"}},
                "efKeys": {"body": {"ki": "00112233445566778899AABBCCDDEEFF"}},
            },
            "akaParameter": {
                "body": {"opc": "00112233445566778899AABBCCDDEEFF"},
            },
        },
        "__ygg_token_defs__": {
            "ICCID": {"length": 10, "kind": "iccid"},
        },
    }


# ---------------------------------------------------------------------------
# Identity classifier
# ---------------------------------------------------------------------------


class TestIdentityClassification:
    def test_iccid_change_in_header_is_critical_identity(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["header"]["iccid"] = "8901001234567890999F"
        report = compute_profile_diff(left, right)
        identity_hits = report.filter(categories=[CATEGORY_IDENTITY])
        assert any(
            entry.severity == SEVERITY_CRITICAL
            and entry.section_key == "header"
            and "iccid" in entry.summary.lower()
            for entry in identity_hits
        )

    def test_imsi_change_under_usim_is_critical_identity(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["usim"]["efImsi"]["body"]["imsi"] = "234569999999999"
        report = compute_profile_diff(left, right)
        identity_hits = [
            entry for entry in report.entries
            if entry.category == CATEGORY_IDENTITY and "imsi" in entry.summary.lower()
        ]
        assert len(identity_hits) == 1
        assert identity_hits[0].severity == SEVERITY_CRITICAL
        assert identity_hits[0].section_key == "usim"

    def test_profile_name_change_is_identity(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["header"]["profile_name"] = "Renamed"
        report = compute_profile_diff(left, right)
        identity_hits = report.filter(categories=[CATEGORY_IDENTITY])
        assert any("profile_name" in entry.summary.lower() for entry in identity_hits)


# ---------------------------------------------------------------------------
# Security classifier
# ---------------------------------------------------------------------------


class TestSecurityClassification:
    def test_ki_change_is_critical_security(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["usim"]["efKeys"]["body"]["ki"] = (
            "FFEEDDCCBBAA99887766554433221100"
        )
        report = compute_profile_diff(left, right)
        security_hits = report.filter(categories=[CATEGORY_SECURITY])
        assert len(security_hits) >= 1
        assert security_hits[0].severity == SEVERITY_CRITICAL
        assert "ki" in security_hits[0].summary.lower()

    def test_opc_change_inside_aka_pe_is_critical_security(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["akaParameter"]["body"]["opc"] = (
            "FFEEDDCCBBAA99887766554433221100"
        )
        report = compute_profile_diff(left, right)
        security_hits = report.filter(categories=[CATEGORY_SECURITY])
        assert len(security_hits) >= 1
        assert security_hits[0].severity == SEVERITY_CRITICAL


# ---------------------------------------------------------------------------
# PE-sequence classifier
# ---------------------------------------------------------------------------


class TestPESequenceClassification:
    def test_pe_added_is_warning(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["isim"] = {
            "aid": "A0000000871004FFFFFFFF8902F1FFFFFFFF",
        }
        report = compute_profile_diff(left, right)
        pe_hits = report.filter(categories=[CATEGORY_PE_SEQUENCE])
        assert any(entry.op == DIFF_OP_ADDED for entry in pe_hits)
        assert all(entry.severity == SEVERITY_WARNING for entry in pe_hits if entry.op == DIFF_OP_ADDED)

    def test_pe_removed_is_critical(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        del right["sections"]["akaParameter"]
        report = compute_profile_diff(left, right)
        pe_hits = report.filter(categories=[CATEGORY_PE_SEQUENCE])
        removals = [entry for entry in pe_hits if entry.op == DIFF_OP_REMOVED]
        assert len(removals) == 1
        assert removals[0].severity == SEVERITY_CRITICAL
        assert removals[0].section_key == "akaParameter"

    def test_section_reorder_recorded_on_report(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        # Pop and re-insert akaParameter so the dict order changes.
        right["sections"] = {
            "akaParameter": right["sections"].pop("akaParameter"),
            **right["sections"],
        }
        report = compute_profile_diff(left, right)
        # Order should differ; the report captures both sides for the
        # renderer to compare side by side.
        assert tuple(report.section_reorder_a) != tuple(report.section_reorder_b)
        assert "akaParameter" in report.section_reorder_a
        assert "akaParameter" in report.section_reorder_b


# ---------------------------------------------------------------------------
# Files classifier
# ---------------------------------------------------------------------------


class TestFilesClassification:
    def test_value_change_inside_mf_is_files_info(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["mf"]["efDir"]["body"]["raw"] = "CAFEBABE"
        report = compute_profile_diff(left, right)
        file_hits = report.filter(categories=[CATEGORY_FILES])
        assert any(
            entry.section_key == "mf" and entry.severity == SEVERITY_INFO
            for entry in file_hits
        )


# ---------------------------------------------------------------------------
# Applications classifier
# ---------------------------------------------------------------------------


class TestApplicationsClassification:
    def test_aid_change_under_usim_is_critical_application(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["usim"]["aid"] = "A0000000871002FFFFFFFF8902F2FFFFFFFF"
        report = compute_profile_diff(left, right)
        app_hits = report.filter(categories=[CATEGORY_APPLICATIONS])
        # AID rotation is an identity-affecting change for the app.
        assert len(app_hits) >= 1
        assert any(entry.severity == SEVERITY_CRITICAL for entry in app_hits)
        assert any(entry.section_key == "usim" for entry in app_hits)


# ---------------------------------------------------------------------------
# Intro / metadata / variables
# ---------------------------------------------------------------------------


class TestTopLevelClassification:
    def test_intro_addition_is_note(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["intro"].append("Issued: 2026-04-28")
        report = compute_profile_diff(left, right)
        intro_hits = report.filter(categories=[CATEGORY_INTRO])
        assert len(intro_hits) == 1
        assert intro_hits[0].severity == SEVERITY_NOTE

    def test_token_def_change_is_variables(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["__ygg_token_defs__"]["IMSI"] = {"length": 8, "kind": "imsi"}
        report = compute_profile_diff(left, right)
        var_hits = report.filter(categories=[CATEGORY_VARIABLES])
        assert len(var_hits) >= 1
        assert all(entry.severity in (SEVERITY_INFO, SEVERITY_NOTE) for entry in var_hits)


# ---------------------------------------------------------------------------
# Empty / identity
# ---------------------------------------------------------------------------


class TestEmptyAndIdentity:
    def test_identical_documents_produce_empty_report(self) -> None:
        left = _baseline_document()
        report = compute_profile_diff(left, _baseline_document())
        assert report.is_empty is True
        assert report.total == 0
        assert report.has_critical is False

    def test_format_text_handles_empty_report(self) -> None:
        report = compute_profile_diff(_baseline_document(), _baseline_document())
        rendered = format_profile_diff_text(report)
        assert "no semantic differences" in rendered

    def test_format_text_emits_summary_lines(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["header"]["iccid"] = "8901001234567890999F"
        report = compute_profile_diff(left, right, label_a="A", label_b="B")
        rendered = format_profile_diff_text(report)
        assert "'A'" in rendered and "'B'" in rendered
        assert "critical=" in rendered
        assert "iccid" in rendered.lower()


# ---------------------------------------------------------------------------
# Sorting + filter helpers
# ---------------------------------------------------------------------------


class TestSortingAndFilter:
    def test_entries_sort_by_severity_first(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["intro"].append("note line")
        right["sections"]["header"]["iccid"] = "8901001234567890999F"
        report = compute_profile_diff(left, right)
        # Critical (identity) must come before note (intro) regardless
        # of insertion order.
        ranks = [entry.severity for entry in report.entries]
        assert ranks.index(SEVERITY_CRITICAL) < ranks.index(SEVERITY_NOTE)

    def test_filter_by_category_returns_subset(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["header"]["iccid"] = "8901001234567890999F"
        right["intro"].append("note line")
        report = compute_profile_diff(left, right)
        identity_only = report.filter(categories=[CATEGORY_IDENTITY])
        assert all(entry.category == CATEGORY_IDENTITY for entry in identity_only)
        assert len(identity_only) >= 1

    def test_filter_by_severity_returns_subset(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["intro"].append("note line")
        report = compute_profile_diff(left, right)
        notes_only = report.filter(severities=[SEVERITY_NOTE])
        assert all(entry.severity == SEVERITY_NOTE for entry in notes_only)


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------


class TestSerialisation:
    def test_to_dict_round_trip_keeps_required_fields(self) -> None:
        left = _baseline_document()
        right = _baseline_document()
        right["sections"]["header"]["iccid"] = "8901001234567890999F"
        report = compute_profile_diff(left, right, label_a="A", label_b="B")
        payload = report.to_dict()
        assert payload["label_a"] == "A"
        assert payload["label_b"] == "B"
        assert payload["total"] == report.total
        assert "entries" in payload
        assert "structural" in payload
        first_entry = payload["entries"][0]
        for required_key in ("category", "severity", "op", "path", "summary"):
            assert required_key in first_entry

    def test_to_dict_serialises_bytes_as_hex_envelope(self) -> None:
        # Construct an entry with raw bytes to make sure the serialiser
        # round-trips it cleanly (the GUI transport is JSON).
        entry = classify_diff_entry(
            DiffEntry(
                path="sections.usim.efKeys.body.ki",
                op=DIFF_OP_CHANGED,
                value_a=b"\x00\x11\x22",
                value_b=b"\xff\xee\xdd",
            )
        )
        payload = entry.to_dict()
        assert payload["before"] == {"__hex__": "001122", "length": 3}
        assert payload["after"] == {"__hex__": "FFEEDD", "length": 3}


# ---------------------------------------------------------------------------
# Type guards
# ---------------------------------------------------------------------------


class TestArgumentValidation:
    def test_rejects_non_dict_left(self) -> None:
        with pytest.raises(TypeError):
            compute_profile_diff([], {"sections": {}})  # type: ignore[arg-type]

    def test_rejects_non_dict_right(self) -> None:
        with pytest.raises(TypeError):
            compute_profile_diff({"sections": {}}, "not-a-dict")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Sanity — every category and severity constant is also in the public tuple.
# ---------------------------------------------------------------------------


class TestPublicConstants:
    def test_all_categories_present_in_public_tuple(self) -> None:
        for category in (
            CATEGORY_IDENTITY,
            CATEGORY_PE_SEQUENCE,
            CATEGORY_FILES,
            CATEGORY_APPLICATIONS,
            CATEGORY_SECURITY,
            CATEGORY_LIFECYCLE,
            CATEGORY_VARIABLES,
            CATEGORY_INTRO,
            CATEGORY_OTHER,
        ):
            assert category in CATEGORIES

    def test_all_severities_present_in_public_tuple(self) -> None:
        for severity in (
            SEVERITY_CRITICAL,
            SEVERITY_WARNING,
            SEVERITY_INFO,
            SEVERITY_NOTE,
        ):
            assert severity in SEVERITIES
