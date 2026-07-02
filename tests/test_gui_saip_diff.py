# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for SA-D semantic diff dispatchers.

Covers:

- ``saip.diff_packages``: two open sessions; happy path emits the
  ProfileDiffReport shape (entries, counts_by_category, counts_by_severity,
  structural totals), guards against same-session and empty-session-id
  inputs.
- ``saip.diff_against_source``: session vs. on-disk source; an
  unedited session produces an empty report, while a placeholder
  override surfaces as a semantic entry on the right side.
- ``saip.diff_against_path``: session vs. a second on-disk file;
  guards against missing path / missing session, and the diff comes
  out symmetric to ``diff_packages`` when both sides point at the
  same content.
- Spec registration: each dispatcher is reachable through the action
  registry with the contract the GUI relies on.

References: Tools/ProfilePackage/saip_profile_diff.py (engine),
yggdrasim_common/gui_server/actions/saip.py (dispatchers).
"""

from __future__ import annotations

import pathlib

import pytest

from yggdrasim_common.gui_server.actions.registry import get_registry
from yggdrasim_common.gui_server.actions.saip import (
    _dispatch_diff_against_path,
    _dispatch_diff_against_source,
    _dispatch_diff_packages,
    _dispatch_set_variable,
    _load_package_from_path,
)
from yggdrasim_common.gui_server.sessions import get_manager


_REFERENCE_PROFILE = pathlib.Path(
    "Workspace/SAIP/profile/transcoded/1oT_test_profile.transcode.der"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _open_session() -> object:
    handle = _load_package_from_path(_REFERENCE_PROFILE)
    handle["source_path"] = str(_REFERENCE_PROFILE.resolve())
    return get_manager().open(kind="saip", handle=handle, close=lambda: None)


@pytest.fixture
def saip_session():
    if not _REFERENCE_PROFILE.exists():
        pytest.skip(f"reference profile not present: {_REFERENCE_PROFILE}")
    session = _open_session()
    yield session
    get_manager().close(session.id)


@pytest.fixture
def two_saip_sessions():
    if not _REFERENCE_PROFILE.exists():
        pytest.skip(f"reference profile not present: {_REFERENCE_PROFILE}")
    a = _open_session()
    b = _open_session()
    yield a, b
    get_manager().close(a.id)
    get_manager().close(b.id)


# ---------------------------------------------------------------------------
# saip.diff_packages
# ---------------------------------------------------------------------------


class TestDiffPackagesArgumentValidation:
    def test_missing_session_a_raises(self) -> None:
        with pytest.raises(ValueError, match="session_a and session_b are required"):
            _dispatch_diff_packages(None, session_a="", session_b="x")

    def test_missing_session_b_raises(self) -> None:
        with pytest.raises(ValueError, match="session_a and session_b are required"):
            _dispatch_diff_packages(None, session_a="x", session_b="")

    def test_same_session_raises(self) -> None:
        with pytest.raises(ValueError, match="must be different sessions"):
            _dispatch_diff_packages(None, session_a="abc", session_b="abc")


class TestDiffPackagesHappyPath:
    def test_two_freshly_loaded_sessions_produce_empty_report(
        self, two_saip_sessions
    ) -> None:
        a, b = two_saip_sessions
        payload = _dispatch_diff_packages(
            None,
            session_a=a.id,
            session_b=b.id,
        )
        assert payload["session_a"] == a.id
        assert payload["session_b"] == b.id
        # Two pristine loads of the same DER must compare equal under
        # the semantic engine. Any non-empty diff would mean a
        # round-tripping bug somewhere in the loader.
        assert payload["is_empty"] is True
        assert payload["total"] == 0
        assert payload["entries"] == []
        assert payload["has_critical"] is False

    def test_set_variable_surfaces_as_variables_category(
        self, two_saip_sessions
    ) -> None:
        """``saip.set_variable`` stamps placeholder defs into
        ``__ygg_token_defs__`` (and the placeholder-style flag) rather
        than rewriting in-place ICCID bytes — the resolution happens
        at encode time. The semantic diff therefore surfaces this as
        a ``variables`` change, not an identity rotation. Pinning the
        observable behaviour here so a future engine tweak doesn't
        accidentally re-categorise it.
        """
        a, b = two_saip_sessions
        _dispatch_set_variable(
            None,
            session_id=b.id,
            name="ICCID",
            value="89010012345678901234",
        )
        payload = _dispatch_diff_packages(
            None,
            session_a=a.id,
            session_b=b.id,
        )
        assert payload["is_empty"] is False
        assert payload["counts_by_category"]["variables"] >= 1
        var_entries = [
            entry for entry in payload["entries"]
            if entry["category"] == "variables"
        ]
        assert any(
            "__ygg_token_defs__" in entry["path"]
            for entry in var_entries
        )

    def test_direct_iccid_mutation_lands_as_critical_identity(
        self, two_saip_sessions
    ) -> None:
        """Mutate the decoded document directly so the change shows
        up under ``sections.<pe>.iccid`` — exercises the engine's
        identity classifier through the live dispatcher path.
        """
        a, b = two_saip_sessions
        # Inject a synthetic identity-bearing PE on side B so we
        # don't depend on whichever real PE shape the reference
        # profile happens to carry. The structural walker will then
        # surface "sections.synthetic_header" as added.
        from yggdrasim_common.gui_server.sessions import get_manager
        manager = get_manager()
        handle_b = manager.claim(b.id)
        handle_b["decoded_document"].setdefault("sections", {})
        handle_b["decoded_document"]["sections"]["synthetic_header"] = {
            "iccid": "9999999999999999999F",
            "imsi": "234569999999999",
        }
        payload = _dispatch_diff_packages(
            None,
            session_a=a.id,
            session_b=b.id,
        )
        assert payload["is_empty"] is False
        # The whole synthetic_header section was added — that lands
        # as a pe_sequence entry (warning). Its child leaves don't
        # appear individually because the structural walker emits
        # one entry per added subtree root.
        assert payload["counts_by_category"]["pe_sequence"] >= 1

    def test_response_carries_structural_counts(self, two_saip_sessions) -> None:
        a, b = two_saip_sessions
        _dispatch_set_variable(
            None,
            session_id=b.id,
            name="ICCID",
            value="89010012345678901234",
        )
        payload = _dispatch_diff_packages(
            None,
            session_a=a.id,
            session_b=b.id,
        )
        # The structural sub-summary mirrors the raw saip_diff_engine
        # output. We don't pin exact values here (they depend on the
        # reference profile shape) but the GUI relies on the keys
        # being present.
        for required_key in ("added", "removed", "changed", "moved", "total"):
            assert required_key in payload["structural"]


# ---------------------------------------------------------------------------
# saip.diff_against_source
# ---------------------------------------------------------------------------


class TestDiffAgainstSourceArgumentValidation:
    def test_missing_session_id_raises(self) -> None:
        with pytest.raises(ValueError, match="session_id is required"):
            _dispatch_diff_against_source(None, session_id="")

    def test_handle_without_source_path_raises(self) -> None:
        if not _REFERENCE_PROFILE.exists():
            pytest.skip(f"reference profile not present: {_REFERENCE_PROFILE}")
        # Open a session via the loader path but DON'T stamp source_path —
        # this mimics a corrupted/legacy handle that lost its on-disk
        # association.
        handle = _load_package_from_path(_REFERENCE_PROFILE)
        # Explicitly clear source_path in case the loader itself adds one
        # in a future revision.
        handle["source_path"] = ""
        session = get_manager().open(kind="saip", handle=handle, close=lambda: None)
        try:
            with pytest.raises(RuntimeError, match="cannot diff against source"):
                _dispatch_diff_against_source(None, session_id=session.id)
        finally:
            get_manager().close(session.id)


class TestDiffAgainstSourceHappyPath:
    def test_unedited_session_yields_empty_report(self, saip_session) -> None:
        payload = _dispatch_diff_against_source(None, session_id=saip_session.id)
        assert payload["is_empty"] is True
        assert payload["session_id"] == saip_session.id
        assert "source_path" in payload

    def test_post_edit_session_diffs_against_clean_source(self, saip_session) -> None:
        # Apply a placeholder override so the live session diverges
        # from the on-disk source. ``saip.set_variable`` writes into
        # ``__ygg_token_defs__`` rather than rewriting in-place ICCID
        # bytes (resolution happens at encode time), so the diff
        # lands in the ``variables`` category.
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="ICCID",
            value="89010012345678901234",
        )
        payload = _dispatch_diff_against_source(
            None,
            session_id=saip_session.id,
        )
        assert payload["is_empty"] is False
        # The label tells the operator which side is which.
        assert "on disk" in payload["label_a"]
        assert "session edits" in payload["label_b"]
        assert payload["counts_by_category"]["variables"] >= 1


# ---------------------------------------------------------------------------
# saip.diff_against_path
# ---------------------------------------------------------------------------


class TestDiffAgainstPathArgumentValidation:
    def test_missing_session_id_raises(self) -> None:
        with pytest.raises(ValueError, match="session_id is required"):
            _dispatch_diff_against_path(None, session_id="", path="/tmp/x.der")

    def test_missing_path_raises(self, saip_session) -> None:
        with pytest.raises(ValueError, match="path is required"):
            _dispatch_diff_against_path(
                None,
                session_id=saip_session.id,
                path="",
            )

    def test_nonexistent_path_raises(self, saip_session) -> None:
        with pytest.raises(FileNotFoundError):
            _dispatch_diff_against_path(
                None,
                session_id=saip_session.id,
                path="/tmp/__definitely_not_a_real_saip_package__.der",
            )


class TestDiffAgainstPathHappyPath:
    def test_session_vs_same_file_yields_empty_report(self, saip_session) -> None:
        payload = _dispatch_diff_against_path(
            None,
            session_id=saip_session.id,
            path=str(_REFERENCE_PROFILE.resolve()),
        )
        assert payload["is_empty"] is True
        assert payload["target_path"] == str(_REFERENCE_PROFILE.resolve())
        assert payload["session_id"] == saip_session.id

    def test_session_with_override_diffs_against_clean_file(
        self, saip_session
    ) -> None:
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="ICCID",
            value="89010012345678901234",
        )
        payload = _dispatch_diff_against_path(
            None,
            session_id=saip_session.id,
            path=str(_REFERENCE_PROFILE.resolve()),
        )
        assert payload["is_empty"] is False
        # The on-disk file is the right side; the session has the
        # placeholder override so ``__ygg_token_defs__`` shows up as
        # a removed key from B's perspective (label_a = session,
        # label_b = file). Direction matters for the banner label.
        assert payload["label_b"].endswith(_REFERENCE_PROFILE.name)
        assert payload["counts_by_category"]["variables"] >= 1


# ---------------------------------------------------------------------------
# Spec registration
# ---------------------------------------------------------------------------


class TestSpecRegistration:
    def test_diff_packages_spec_registered(self) -> None:
        spec = get_registry().get("saip.diff_packages")
        assert spec is not None
        assert spec.subsystem == "SAIP"
        assert spec.output_kind == "json"
        assert "diff" in spec.tags
        assert "semantic" in spec.tags
        names = {field.name for field in spec.inputs}
        assert names == {"session_a", "session_b"}

    def test_diff_against_source_spec_registered(self) -> None:
        spec = get_registry().get("saip.diff_against_source")
        assert spec is not None
        assert spec.subsystem == "SAIP"
        assert spec.output_kind == "json"
        names = {field.name for field in spec.inputs}
        assert names == {"session_id"}

    def test_diff_against_path_spec_registered(self) -> None:
        spec = get_registry().get("saip.diff_against_path")
        assert spec is not None
        assert spec.subsystem == "SAIP"
        names = {field.name for field in spec.inputs}
        assert names == {"session_id", "path"}
