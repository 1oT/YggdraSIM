# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Regression guard for the SAIP decoded-editor coverage audit.

The test exercises ``Tools.ProfilePackage.saip_decoded_edit_audit`` against
the live pySim SAIP spec and diffs the result against a version-keyed
golden baseline stored under ``tests/data/``.

Policy (per YggdraSIM maintainer decision, 2026-04):

- **Version awareness**: the audit reads the pySim-shipped
  ``PE_Definitions-<version>.asn`` filename and writes that version into
  the report. The baseline file name carries the same version
  (``saip_decoded_edit_audit_baseline_<version>.json``). Upgrading pySim
  picks up a new baseline path, so the previous version's baseline stays
  pinned and the new version starts as an explicit add.
- **Hard-diff**: any drift in classification (new missing decoder,
  gained coverage, reordered fields) fails the test. The failure
  message dumps the first divergence and points the maintainer at the
  baseline file to update.

Baseline regeneration (when a drift is *intentional*)::

    /path/to/pysim-aware-venv/bin/python -c "\
    import json, sys; sys.path.insert(0, '.');\
    from Tools.ProfilePackage.saip_decoded_edit_audit import \
        audit_decoded_editors, report_to_baseline_dict;\
    r = audit_decoded_editors();\
    v = r.spec_version.replace('.', '_');\
    path = f'tests/data/saip_decoded_edit_audit_baseline_{v}.json';\
    open(path, 'w').write(json.dumps(report_to_baseline_dict(r), indent=2));\
    print('wrote', path)"

No compound statements. No silent skips — when pySim is unavailable the
conftest gate (``_PYSIM_DEPENDENT_TEST_BASENAMES``) marks the test
``skipped`` with an actionable install hint.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from Tools.ProfilePackage.saip_decoded_edit_audit import (
    CLASS_MISSING,
    AuditUnavailableError,
    audit_decoded_editors,
    format_audit_report,
    report_to_baseline_dict,
)


_BASELINE_DIR = Path(__file__).resolve().parent / "data"


def _baseline_path_for(version: str) -> Path:
    safe_version = str(version or "unknown").replace(".", "_")
    return _BASELINE_DIR / f"saip_decoded_edit_audit_baseline_{safe_version}.json"


def _build_report_or_skip():
    try:
        return audit_decoded_editors()
    except AuditUnavailableError as error:
        pytest.skip(f"pySim SAIP spec unavailable: {error}")


def test_audit_report_has_stable_top_level_shape():
    """Shape contract: every report carries version, totals, and groups."""

    report = _build_report_or_skip()
    assert isinstance(report.spec_version, str)
    assert len(report.spec_version) > 0
    assert len(report.groups) > 0
    totals = report.totals()
    assert isinstance(totals, dict)
    # We always expect at least one PE (e.g. ProfileHeader) with a
    # roundtrip_scalar leaf (the header ``identification`` UInt15).
    assert totals.get("roundtrip_scalar", 0) > 0


def test_profile_element_coverage_matches_baseline():
    """Hard-diff against the pinned baseline for the active pySim spec."""

    report = _build_report_or_skip()
    baseline_path = _baseline_path_for(report.spec_version)
    if baseline_path.is_file() is False:
        pytest.fail(
            "No decoded-editor audit baseline for pySim SAIP spec "
            f"{report.spec_version} (expected at {baseline_path}). "
            "This is an intentional pySim version bump; regenerate the "
            "baseline using the command documented in the module docstring."
        )
    with baseline_path.open("r", encoding="utf-8") as handle:
        expected = json.load(handle)
    actual = report_to_baseline_dict(report)
    if actual == expected:
        return

    # On drift, surface the first divergence so the maintainer knows
    # exactly what to investigate / update in the baseline.
    mismatch_reason = _format_first_mismatch(expected=expected, actual=actual)
    pytest.fail(
        "SAIP decoded-editor audit drifted from baseline "
        f"{baseline_path.name}.\n\n"
        f"First divergence:\n{mismatch_reason}\n\n"
        "If the drift is intentional (newly-added decoder, pySim bump), "
        "regenerate the baseline — see the regeneration snippet in "
        "tests/test_saip_decoded_edit_audit.py module docstring."
    )


def test_missing_entries_are_exposed_through_helper():
    """The convenience helper must enumerate every ``missing`` record."""

    report = _build_report_or_skip()
    missing_helper = report.missing_entries()
    missing_scan = [
        record
        for group in report.groups
        for record in group.fields
        if record.classification == CLASS_MISSING
    ]
    assert len(missing_helper) == len(missing_scan)
    helper_paths = {tuple(record.path) for record in missing_helper}
    scan_paths = {tuple(record.path) for record in missing_scan}
    assert helper_paths == scan_paths


def test_format_audit_report_renders_text():
    """``format_audit_report`` must emit a non-empty deterministic string."""

    report = _build_report_or_skip()
    full_text = format_audit_report(report)
    assert isinstance(full_text, str)
    assert "SAIP decoded-editor audit" in full_text
    assert report.spec_version in full_text

    missing_only = format_audit_report(report, show_only_missing=True)
    assert isinstance(missing_only, str)
    assert "SAIP decoded-editor audit" in missing_only


def _format_first_mismatch(*, expected: dict, actual: dict) -> str:
    expected_version = expected.get("saip_spec_version")
    actual_version = actual.get("saip_spec_version")
    if expected_version != actual_version:
        return (
            f"  saip_spec_version differs: "
            f"expected={expected_version!r}, actual={actual_version!r}"
        )

    expected_totals = expected.get("totals", {}) or {}
    actual_totals = actual.get("totals", {}) or {}
    if expected_totals != actual_totals:
        return (
            "  totals differ:\n"
            f"    expected: {dict(sorted(expected_totals.items()))}\n"
            f"    actual  : {dict(sorted(actual_totals.items()))}"
        )

    expected_groups = expected.get("groups", {}) or {}
    actual_groups = actual.get("groups", {}) or {}
    expected_keys = sorted(expected_groups.keys())
    actual_keys = sorted(actual_groups.keys())
    if expected_keys != actual_keys:
        missing_from_actual = [k for k in expected_keys if k not in actual_groups]
        extra_in_actual = [k for k in actual_keys if k not in expected_groups]
        return (
            "  PE group set differs:\n"
            f"    in baseline but missing now: {missing_from_actual}\n"
            f"    new in report:               {extra_in_actual}"
        )

    for group_key in expected_keys:
        expected_group = expected_groups[group_key]
        actual_group = actual_groups[group_key]
        expected_fields = expected_group.get("fields", []) or []
        actual_fields = actual_group.get("fields", []) or []
        if expected_fields == actual_fields:
            continue
        if len(expected_fields) != len(actual_fields):
            return (
                f"  [{group_key}] field count differs: "
                f"expected={len(expected_fields)}, actual={len(actual_fields)}"
            )
        for index, expected_field in enumerate(expected_fields):
            actual_field = actual_fields[index]
            if expected_field == actual_field:
                continue
            return (
                f"  [{group_key}] field #{index} differs:\n"
                f"    expected: {expected_field}\n"
                f"    actual  : {actual_field}"
            )
    return "  (no structural diff found but dict equality failed)"
