# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Coverage for SCP11/shared/profile_actions.py.

The shared helpers underpin the harmonised ENABLE / DISABLE / DELETE
contract used by the SCP11 shells (eSIM Management, Local SMDP+, Local
eIM). The tests below pin down the auto-disable
sequencing, idempotency short-circuits, and PPR1 guard so we don't
regress the cross-shell behaviour an operator now relies on.

References:
- SGP.22 §5.7.16 (EnableProfile)
- SGP.22 §5.7.17 (DisableProfile)
- SGP.22 §5.7.18 (DeleteProfile)
"""

from __future__ import annotations

import pytest
from dataclasses import dataclass
from typing import Any, Optional

from SCP11.shared import profile_actions


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@dataclass
class FakeProfile:
    iccid: str = ""
    aid: str = ""
    nickname: str = ""
    profile_name: str = ""
    state: str = "DISABLED"


class _Recorder:
    """Capture every adapter callback the helpers fire.

    Lets each test assert (a) which sequence of card commands ran, and
    (b) the order they ran in, without spinning up a real ES10 transport.
    """

    def __init__(self, *, enable_ok: bool = True, disable_ok: bool = True, delete_ok: bool = True):
        self.calls: list[tuple[str, Any]] = []
        self._enable_ok = enable_ok
        self._disable_ok = disable_ok
        self._delete_ok = delete_ok
        self.info_messages: list[str] = []
        self.warn_messages: list[str] = []
        self.error_messages: list[str] = []

    def enable(self, target: Any) -> Any:
        self.calls.append(("enable", target))
        return b"\x90\x00" if self._enable_ok else b""

    def disable(self, target: Any) -> Any:
        self.calls.append(("disable", target))
        return b"\x90\x00" if self._disable_ok else b""

    def delete(self, target: Any) -> Any:
        self.calls.append(("delete", target))
        return b"\x90\x00" if self._delete_ok else b""

    def info(self, message: str) -> None:
        self.info_messages.append(message)

    def warn(self, message: str) -> None:
        self.warn_messages.append(message)

    def error(self, message: str) -> None:
        self.error_messages.append(message)


def _adapter_from_recorder(
    recorder: _Recorder,
    *,
    policy_allow: Optional[bool] = None,
) -> profile_actions.ProfileActionAdapter:
    policy_callback = None
    if policy_allow is not None:
        policy_callback = lambda _active, _target: bool(policy_allow)  # noqa: E731
    return profile_actions.ProfileActionAdapter(
        enable_profile=recorder.enable,
        disable_profile=recorder.disable,
        delete_profile=recorder.delete,
        policy_allow_auto_disable=policy_callback,
        describe_profile=lambda profile: f"{profile.nickname} ({profile.iccid})",
        profile_identifier=lambda profile: profile.iccid or profile.aid or profile.nickname,
        info=recorder.info,
        warn=recorder.warn,
        error=recorder.error,
    )


# ---------------------------------------------------------------------------
# Profile-row helpers
# ---------------------------------------------------------------------------


class TestRowHelpers:
    """``find_profile`` / ``find_enabled_profile`` / ``is_enabled``."""

    def test_is_enabled_handles_case_and_whitespace(self) -> None:
        assert profile_actions.is_enabled(FakeProfile(state="ENABLED")) is True
        assert profile_actions.is_enabled(FakeProfile(state="enabled")) is True
        assert profile_actions.is_enabled(FakeProfile(state=" Enabled ")) is True
        assert profile_actions.is_enabled(FakeProfile(state="DISABLED")) is False
        assert profile_actions.is_enabled(FakeProfile(state="")) is False

    def test_find_profile_matches_iccid_aid_or_nickname(self) -> None:
        rows = [
            FakeProfile(iccid="8901234567890123450F", nickname="HomeNet", aid="A0000000871002"),
            FakeProfile(iccid="9999999999999999999F", nickname="Travel", aid="A0000000871003"),
        ]
        assert profile_actions.find_profile(rows, "8901234567890123450F").nickname == "HomeNet"
        assert profile_actions.find_profile(rows, "Travel").iccid.startswith("9999")
        assert profile_actions.find_profile(rows, "a0000000871003").nickname == "Travel"
        assert profile_actions.find_profile(rows, "missing") is None

    def test_find_profile_tolerates_trailing_F_filler(self) -> None:
        rows = [FakeProfile(iccid="89012345678901234500", nickname="A")]
        match = profile_actions.find_profile(rows, "89012345678901234500F")
        assert match is rows[0]

    def test_find_profile_returns_none_for_blank_identifier(self) -> None:
        rows = [FakeProfile(iccid="89012345678901234500", nickname="A")]
        assert profile_actions.find_profile(rows, "") is None
        assert profile_actions.find_profile(rows, "   ") is None

    def test_find_enabled_profile_returns_none_when_all_disabled(self) -> None:
        rows = [FakeProfile(state="DISABLED"), FakeProfile(state="DISABLED")]
        assert profile_actions.find_enabled_profile(rows) is None

    def test_find_enabled_profile_excludes_target(self) -> None:
        target = FakeProfile(iccid="111F", state="ENABLED", nickname="A")
        other = FakeProfile(iccid="222F", state="ENABLED", nickname="B")
        # Only one ENABLED profile is allowed at a time, but the helper
        # still defends against a transient "two enabled" inventory by
        # excluding the target. The other ENABLED row should be the one
        # we return.
        rows = [target, other]
        result = profile_actions.find_enabled_profile(rows, exclude=target)
        assert result is other


# ---------------------------------------------------------------------------
# ENABLE
# ---------------------------------------------------------------------------


class TestRunEnableProfile:
    """``run_enable_profile`` sequencing + auto-disable logic."""

    def test_short_circuits_when_target_already_enabled(self) -> None:
        rec = _Recorder()
        rows = [FakeProfile(iccid="111F", nickname="A", state="ENABLED")]
        ok = profile_actions.run_enable_profile(_adapter_from_recorder(rec), rows, "111F")
        assert ok is True
        assert rec.calls == []
        assert any("already enabled" in m for m in rec.info_messages)

    def test_auto_disables_active_then_enables_target(self) -> None:
        rec = _Recorder()
        rows = [
            FakeProfile(iccid="111F", nickname="A", state="ENABLED"),
            FakeProfile(iccid="222F", nickname="B", state="DISABLED"),
        ]
        ok = profile_actions.run_enable_profile(_adapter_from_recorder(rec), rows, "222F")
        assert ok is True
        assert rec.calls == [("disable", "111F"), ("enable", "222F")]

    def test_aborts_when_policy_refuses_auto_disable(self) -> None:
        rec = _Recorder()
        rows = [
            FakeProfile(iccid="111F", nickname="A", state="ENABLED"),
            FakeProfile(iccid="222F", nickname="B", state="DISABLED"),
        ]
        ok = profile_actions.run_enable_profile(
            _adapter_from_recorder(rec, policy_allow=False),
            rows,
            "222F",
        )
        assert ok is False
        assert rec.calls == []

    def test_aborts_when_auto_disable_card_command_fails(self) -> None:
        rec = _Recorder(disable_ok=False)
        rows = [
            FakeProfile(iccid="111F", nickname="A", state="ENABLED"),
            FakeProfile(iccid="222F", nickname="B", state="DISABLED"),
        ]
        ok = profile_actions.run_enable_profile(_adapter_from_recorder(rec), rows, "222F")
        assert ok is False
        assert rec.calls == [("disable", "111F")]
        assert any("auto-disable" in m for m in rec.error_messages)

    def test_enables_directly_when_no_active_profile(self) -> None:
        rec = _Recorder()
        rows = [FakeProfile(iccid="222F", nickname="B", state="DISABLED")]
        ok = profile_actions.run_enable_profile(_adapter_from_recorder(rec), rows, "222F")
        assert ok is True
        assert rec.calls == [("enable", "222F")]

    def test_falls_back_to_raw_identifier_when_target_unknown(self) -> None:
        rec = _Recorder()
        rows: list[FakeProfile] = []
        ok = profile_actions.run_enable_profile(_adapter_from_recorder(rec), rows, "RAW-AID")
        assert ok is True
        assert rec.calls == [("enable", "RAW-AID")]


# ---------------------------------------------------------------------------
# DISABLE
# ---------------------------------------------------------------------------


class TestRunDisableProfile:
    """``run_disable_profile`` short-circuit + happy path."""

    def test_short_circuits_when_target_already_disabled(self) -> None:
        rec = _Recorder()
        rows = [FakeProfile(iccid="111F", nickname="A", state="DISABLED")]
        ok = profile_actions.run_disable_profile(_adapter_from_recorder(rec), rows, "111F")
        assert ok is True
        assert rec.calls == []
        assert any("already disabled" in m for m in rec.info_messages)

    def test_disables_when_target_enabled(self) -> None:
        rec = _Recorder()
        rows = [FakeProfile(iccid="111F", nickname="A", state="ENABLED")]
        ok = profile_actions.run_disable_profile(_adapter_from_recorder(rec), rows, "111F")
        assert ok is True
        assert rec.calls == [("disable", "111F")]


# ---------------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------------


class TestRunDeleteProfile:
    """``run_delete_profile`` auto-disable-before-delete contract."""

    def test_deletes_disabled_target_directly(self) -> None:
        rec = _Recorder()
        rows = [FakeProfile(iccid="111F", nickname="A", state="DISABLED")]
        ok = profile_actions.run_delete_profile(_adapter_from_recorder(rec), rows, "111F")
        assert ok is True
        assert rec.calls == [("delete", "111F")]

    def test_auto_disables_enabled_target_before_delete(self) -> None:
        rec = _Recorder()
        rows = [FakeProfile(iccid="111F", nickname="A", state="ENABLED")]
        ok = profile_actions.run_delete_profile(_adapter_from_recorder(rec), rows, "111F")
        assert ok is True
        # Order matters: the disable must land before the delete so the
        # card never sees a delete-while-enabled APDU.
        assert rec.calls == [("disable", "111F"), ("delete", "111F")]

    def test_aborts_when_auto_disable_fails(self) -> None:
        rec = _Recorder(disable_ok=False)
        rows = [FakeProfile(iccid="111F", nickname="A", state="ENABLED")]
        ok = profile_actions.run_delete_profile(_adapter_from_recorder(rec), rows, "111F")
        assert ok is False
        assert rec.calls == [("disable", "111F")]
        assert any("auto-disable failed" in m for m in rec.error_messages)

    def test_respects_ppr1_guard(self) -> None:
        rec = _Recorder()
        rows = [FakeProfile(iccid="111F", nickname="A", state="ENABLED")]
        ok = profile_actions.run_delete_profile(
            _adapter_from_recorder(rec, policy_allow=False),
            rows,
            "111F",
        )
        assert ok is False
        assert rec.calls == []

    def test_falls_back_to_raw_identifier_when_target_unknown(self) -> None:
        rec = _Recorder()
        rows: list[FakeProfile] = []
        ok = profile_actions.run_delete_profile(_adapter_from_recorder(rec), rows, "RAW-AID")
        assert ok is True
        assert rec.calls == [("delete", "RAW-AID")]
