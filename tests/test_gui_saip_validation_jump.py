# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for SA-G5 validation finding enrichment (click-to-jump support).

Covers:

- ``_build_validation_jump_indexes`` produces a section→pe_index map
  keyed by lowercase section name and a (section_key, field_path)
  set for every file row in the package.
- ``_resolve_finding_target`` recognises the linter's path
  conventions:

  * ``""`` / ``"sections"`` / ``"PE-order"`` / ``"document"`` /
    ``"summary"`` — non-routable, returns ``{}``.
  * ``"service:<name>"`` — non-routable rollup.
  * ``"<section>"`` — anchors on the matching PE.
  * ``"<section>.<field>"`` — anchors on the matching PE; if the
    (section, field) tuple is a known file row the route also
    surfaces the file path so the GUI can land on the File System
    tab directly.
  * ``"<section>::<field>"`` — explicit file key (forward-compat for
    a future linter emission style).
  * Multi-segment dotted paths (``a.b.c``) anchor on the first
    segment.

- Integration: ``saip.validate`` enriches findings with
  ``pe_index`` / ``section_key`` / ``field_path`` keys whenever the
  path resolves to a known PE / file in the in-tree reference
  profile, and leaves those keys absent for non-routable findings.
"""

from __future__ import annotations

import pathlib

import pytest

from yggdrasim_common.gui_server.actions.saip import (
    _build_validation_jump_indexes,
    _dispatch_validate,
    _load_package_from_path,
    _resolve_finding_target,
)
from yggdrasim_common.gui_server.sessions import get_manager


_REFERENCE_PROFILE = pathlib.Path(
    "Workspace/SAIP/profile/transcoded/1oT_test_profile.transcode.der"
)


@pytest.fixture
def saip_handle():
    if not _REFERENCE_PROFILE.exists():
        pytest.skip(f"reference profile not present: {_REFERENCE_PROFILE}")
    return _load_package_from_path(_REFERENCE_PROFILE)


@pytest.fixture
def saip_session(saip_handle):
    session = get_manager().open(kind="saip", handle=saip_handle, close=lambda: None)
    yield session
    get_manager().close(session.id)


# ---------------------------------------------------------------------
# Index builders
# ---------------------------------------------------------------------


class TestBuildValidationJumpIndexes:
    def test_section_index_keyed_lowercase(self, saip_handle) -> None:
        pe_idx_by_section, _ = _build_validation_jump_indexes(saip_handle)
        # Every section key must be lowercase so case-style drift in
        # the linter (``Header`` vs ``header``) doesn't break lookups.
        for key in pe_idx_by_section.keys():
            assert key == key.lower()

    def test_section_index_includes_canonical_pe_types(self, saip_handle) -> None:
        pe_idx_by_section, _ = _build_validation_jump_indexes(saip_handle)
        for required in ("header", "mf", "usim", "telecom", "rfm"):
            assert required in pe_idx_by_section, f"missing section: {required}"
        # ``header`` must resolve to PE #0 in the reference profile.
        assert pe_idx_by_section["header"] == 0

    def test_file_keys_carry_canonical_case(self, saip_handle) -> None:
        _, file_keys = _build_validation_jump_indexes(saip_handle)
        # Reference profile has 71 file definitions across 5 sections.
        assert len(file_keys) > 50
        assert ("mf", "ef-iccid") in file_keys
        assert ("usim", "ef-imsi") in file_keys


# ---------------------------------------------------------------------
# Path resolver
# ---------------------------------------------------------------------


class TestResolveFindingTarget:
    @pytest.fixture
    def indexes(self, saip_handle):
        return _build_validation_jump_indexes(saip_handle)

    def test_empty_path_is_non_routable(self, indexes) -> None:
        pe_idx, file_keys = indexes
        assert _resolve_finding_target(
            path_text="",
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        ) == {}

    @pytest.mark.parametrize(
        "path",
        ["sections", "PE-order", "document", "summary", "Sections", "pe-order"],
    )
    def test_well_known_non_routable_paths(self, indexes, path) -> None:
        pe_idx, file_keys = indexes
        assert _resolve_finding_target(
            path_text=path,
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        ) == {}

    def test_service_rollup_path_is_non_routable(self, indexes) -> None:
        pe_idx, file_keys = indexes
        assert _resolve_finding_target(
            path_text="service:usim",
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        ) == {}

    def test_bare_section_resolves_to_pe_index(self, indexes) -> None:
        pe_idx, file_keys = indexes
        target = _resolve_finding_target(
            path_text="header",
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        )
        assert target.get("pe_index") == 0
        assert target.get("section_key") == "header"
        # No ``field_path`` because the bare section doesn't refer to a file.
        assert "field_path" not in target

    def test_section_dot_field_resolves_to_pe_only_when_file_unknown(
        self,
        indexes,
    ) -> None:
        pe_idx, file_keys = indexes
        target = _resolve_finding_target(
            path_text="header.iccid",
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        )
        # ``header.iccid`` anchors on the header PE; the (header, iccid)
        # tuple is *not* a file row in the reference profile (ICCID is
        # a header field, not a separate FS entry under that section
        # name) so the field_path key is absent.
        assert target["pe_index"] == 0
        assert target["section_key"] == "header"
        assert "field_path" not in target

    def test_section_dot_field_surfaces_file_route_when_match(
        self,
        indexes,
    ) -> None:
        pe_idx, file_keys = indexes
        target = _resolve_finding_target(
            path_text="usim.ef-imsi",
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        )
        # USIM PE + EF.IMSI file — both routes available.
        assert "pe_index" in target
        assert target["section_key"] == "usim"
        assert target["field_path"] == "ef-imsi"

    def test_explicit_section_double_colon_field_form(self, indexes) -> None:
        pe_idx, file_keys = indexes
        target = _resolve_finding_target(
            path_text="mf::ef-iccid",
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        )
        assert target["section_key"] == "mf"
        assert target["field_path"] == "ef-iccid"
        assert "pe_index" in target

    def test_multi_segment_dotted_path_anchors_on_first_segment(self, indexes) -> None:
        pe_idx, file_keys = indexes
        target = _resolve_finding_target(
            path_text="header.connectivityParameters.spnDisplayCondition",
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        )
        assert target["pe_index"] == 0
        assert target["section_key"] == "header"
        # The (header, connectivityParameters.spnDisplayCondition) tuple
        # is not a file row, so no field_path is set.
        assert "field_path" not in target

    def test_unknown_section_falls_through(self, indexes) -> None:
        pe_idx, file_keys = indexes
        target = _resolve_finding_target(
            path_text="totally-unknown-section.field",
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        )
        assert target == {}

    def test_path_case_is_normalised_for_section_lookup(self, indexes) -> None:
        pe_idx, file_keys = indexes
        target = _resolve_finding_target(
            path_text="HEADER",
            pe_index_by_section=pe_idx,
            file_keys=file_keys,
        )
        assert target.get("pe_index") == 0


# ---------------------------------------------------------------------
# Dispatcher integration
# ---------------------------------------------------------------------


class TestValidateEnrichesFindings:
    def test_iccid_findings_carry_pe_index(self, saip_session) -> None:
        # The reference profile may carry a fully-valid ICCID (no
        # YRL-ICC-* findings emitted) once the linter normalises bytes
        # input correctly. When findings *do* fire — for example on a
        # hand-edited profile where the ICCID was truncated — every
        # one of them must enrich with the header PE coordinates so
        # the click-to-jump UI lands on the right pane.
        result = _dispatch_validate(None, session_id=saip_session.id, strict=False)
        iccid = [f for f in result["findings"] if f["code"].startswith("YRL-ICC-")]
        if len(iccid) == 0:
            pytest.skip(
                "reference profile is fully ICCID-valid — enrichment "
                "behaviour for ICCID findings is asserted indirectly "
                "by TestResolveFindingTarget."
            )
        for f in iccid:
            # YRL-ICC-010 (cross-PE consistency) anchors on the EF
            # under MF, not on the header. All other YRL-ICC-* codes
            # anchor on header.iccid. Both shapes must enrich.
            section_key = f.get("section_key")
            assert section_key in ("header", "mf")
            assert isinstance(f.get("pe_index"), int)

    def test_pe_order_findings_have_no_jump_target(self, saip_session) -> None:
        result = _dispatch_validate(None, session_id=saip_session.id, strict=False)
        order = [f for f in result["findings"] if f["path"] == "PE-order"]
        assert len(order) >= 1
        for f in order:
            assert "pe_index" not in f
            assert "section_key" not in f
            assert "field_path" not in f

    def test_service_findings_have_no_jump_target(self, saip_session) -> None:
        result = _dispatch_validate(None, session_id=saip_session.id, strict=False)
        services = [f for f in result["findings"] if f["path"].startswith("service:")]
        assert len(services) >= 1
        for f in services:
            assert "pe_index" not in f
            assert "field_path" not in f

    def test_finding_keys_are_minimal(self, saip_session) -> None:
        # Only emit pe_index / section_key / field_path when they
        # actually resolve to a target; a non-routable finding must
        # leave those keys absent rather than ``None``.
        result = _dispatch_validate(None, session_id=saip_session.id, strict=False)
        for f in result["findings"]:
            for key in ("pe_index", "section_key", "field_path"):
                if key in f:
                    assert f[key] not in (None, ""), f"empty enrichment value: {f}"
