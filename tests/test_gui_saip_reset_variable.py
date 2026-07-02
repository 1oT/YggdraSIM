# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for SA-G6 ``saip.reset_variable`` per-variable rollback dispatcher.

Covers:

- Argument validation: missing session_id / missing name raises
  ``ValueError`` with a helpful message.
- No-op semantics: resetting a variable that was never overridden
  returns ``removed=False`` + a friendly summary, leaves
  ``applied_overrides`` untouched, and does NOT reload the source.
- Single-override rollback: after setting + resetting one variable
  the ``applied_overrides`` map is empty and the document mirrors
  a freshly opened package.
- Multi-override rollback: resetting one of N overrides keeps the
  remaining (N-1) overrides applied (replayed from the reloaded
  source).
- Spec registration: ``RESET_VARIABLE_SPEC`` is reachable through
  the action registry and matches the contract the GUI relies on
  (id / subsystem / output kind / required fields / tags).
"""

from __future__ import annotations

import pathlib

import pytest

from yggdrasim_common.gui_server.actions.saip import (
    _dispatch_list_variables,
    _dispatch_reset_variable,
    _dispatch_set_variable,
    _load_package_from_path,
)
from yggdrasim_common.gui_server.actions.registry import get_registry
from yggdrasim_common.gui_server.sessions import get_manager


_REFERENCE_PROFILE = pathlib.Path(
    "Workspace/SAIP/profile/transcoded/1oT_test_profile.transcode.der"
)


@pytest.fixture
def saip_session():
    if not _REFERENCE_PROFILE.exists():
        pytest.skip(f"reference profile not present: {_REFERENCE_PROFILE}")
    handle = _load_package_from_path(_REFERENCE_PROFILE)
    # ``_dispatch_open_package`` is normally what stamps source_path
    # into the handle; we bypass it so the test can drive the
    # dispatcher directly. Mirror the production shape here.
    handle["source_path"] = str(_REFERENCE_PROFILE.resolve())
    session = get_manager().open(kind="saip", handle=handle, close=lambda: None)
    yield session
    get_manager().close(session.id)


# ---------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------


class TestArgumentValidation:
    def test_missing_session_id_raises(self) -> None:
        with pytest.raises(ValueError, match="session_id is required"):
            _dispatch_reset_variable(None, session_id="", name="ICCID")

    def test_missing_name_raises(self, saip_session) -> None:
        with pytest.raises(ValueError, match="name is required"):
            _dispatch_reset_variable(None, session_id=saip_session.id, name="")

    def test_whitespace_only_name_raises(self, saip_session) -> None:
        with pytest.raises(ValueError, match="name is required"):
            _dispatch_reset_variable(None, session_id=saip_session.id, name="   ")


# ---------------------------------------------------------------------
# No-op semantics
# ---------------------------------------------------------------------


class TestNoOpReset:
    def test_unknown_variable_is_noop(self, saip_session) -> None:
        # No overrides have been applied, so resetting anything is a no-op.
        result = _dispatch_reset_variable(
            None,
            session_id=saip_session.id,
            name="DOES_NOT_EXIST",
        )
        assert result["removed"] is False
        assert result["overrides_applied"] == {}
        # The summary string makes the no-op self-documenting.
        assert any(
            "not overridden" in s.lower()
            for s in result.get("summaries", [])
        )

    def test_noop_does_not_touch_other_overrides(self, saip_session) -> None:
        # Set a real override, then try to reset a *different* name.
        # The unrelated reset must leave the existing override intact.
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="ICCID",
            value="89880000000000000007",
        )
        before = _dispatch_list_variables(
            None,
            session_id=saip_session.id,
        )["overrides_applied"]
        result = _dispatch_reset_variable(
            None,
            session_id=saip_session.id,
            name="MCC_MNC",
        )
        assert result["removed"] is False
        assert result["overrides_applied"] == before


# ---------------------------------------------------------------------
# Single-override rollback
# ---------------------------------------------------------------------


class TestSingleOverrideRollback:
    def test_resets_iccid_back_to_source(self, saip_session) -> None:
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="ICCID",
            value="89880000000000000007",
        )
        result = _dispatch_reset_variable(
            None,
            session_id=saip_session.id,
            name="ICCID",
        )
        assert result["removed"] is True
        assert result["overrides_applied"] == {}
        assert any("reset to source" in s.lower() for s in result["summaries"])

        listing = _dispatch_list_variables(None, session_id=saip_session.id)
        assert listing["overrides_applied"] == {}

    def test_resets_imsi_back_to_source(self, saip_session) -> None:
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="IMSI",
            value="001010000000007",
        )
        result = _dispatch_reset_variable(
            None,
            session_id=saip_session.id,
            name="IMSI",
        )
        assert result["removed"] is True
        assert result["overrides_applied"] == {}

    def test_strips_brace_wrapping_around_name(self, saip_session) -> None:
        # ``normalize_placeholder_name`` accepts both bare names and
        # the brace / bracket forms so operators can paste straight
        # from the template (``{ICCID}`` works just as well as
        # ``ICCID``). Reset must follow the same rule.
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="ICCID",
            value="89880000000000000007",
        )
        result = _dispatch_reset_variable(
            None,
            session_id=saip_session.id,
            name="{ICCID}",
        )
        assert result["removed"] is True
        assert result["name"] == "ICCID"
        assert result["overrides_applied"] == {}


# ---------------------------------------------------------------------
# Multi-override rollback
# ---------------------------------------------------------------------


class TestMultiOverrideRollback:
    def test_keeps_remaining_overrides(self, saip_session) -> None:
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="ICCID",
            value="89880000000000000007",
        )
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="IMSI",
            value="001010000000007",
        )
        # Reset only ICCID; IMSI must remain.
        result = _dispatch_reset_variable(
            None,
            session_id=saip_session.id,
            name="ICCID",
        )
        assert result["removed"] is True
        remaining = result["overrides_applied"]
        assert "ICCID" not in remaining
        assert remaining.get("IMSI") == "001010000000007"

        listing = _dispatch_list_variables(None, session_id=saip_session.id)
        assert listing["overrides_applied"].get("IMSI") == "001010000000007"
        assert "ICCID" not in listing["overrides_applied"]

    def test_can_reset_all_overrides_one_by_one(self, saip_session) -> None:
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="ICCID",
            value="89880000000000000007",
        )
        _dispatch_set_variable(
            None,
            session_id=saip_session.id,
            name="IMSI",
            value="001010000000007",
        )
        _dispatch_reset_variable(None, session_id=saip_session.id, name="ICCID")
        result = _dispatch_reset_variable(
            None,
            session_id=saip_session.id,
            name="IMSI",
        )
        assert result["removed"] is True
        assert result["overrides_applied"] == {}


# ---------------------------------------------------------------------
# Spec registration
# ---------------------------------------------------------------------


class TestSpecRegistration:
    def test_registry_lookup(self) -> None:
        spec = get_registry().get("saip.reset_variable")
        assert spec is not None
        assert spec.subsystem == "SAIP"
        assert spec.output_kind == "json"
        assert spec.requires_card is False

    def test_required_inputs(self) -> None:
        spec = get_registry().get("saip.reset_variable")
        names = {field.name for field in spec.inputs}
        assert "session_id" in names
        assert "name" in names

    def test_tags_advertise_write_intent(self) -> None:
        spec = get_registry().get("saip.reset_variable")
        # Tags drive UI affordances ("write" actions get a confirmation
        # path); they must include the subsystem + the variables tag +
        # an explicit write marker.
        assert "saip" in spec.tags
        assert "variables" in spec.tags
        assert "write" in spec.tags
