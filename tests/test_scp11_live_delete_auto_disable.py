"""Regression coverage for the harmonised DELETE auto-disable flow.

After SCP11 command harmonisation (matches Local SMDP+/eIM and the
shared profile_actions helpers), eSIM Live and eSIM Test now
auto-disable an ENABLED target before issuing the delete instead of
silently forcing a delete-while-enabled APDU. SGP.22 §5.7.18 forbids
the latter; the auto-disable is the only safe path on cards that
honour the spec strictly.

The tests below exercise ``SCP11Console._run_delete_profile_state_command``
in isolation: we stub ``_execute_profile_state_command`` /
``_allow_auto_disable_for_enable`` so the
test never needs an actual transport.
"""

from __future__ import annotations

from typing import Any

import pytest

from SCP11.live.console import ProfileMetadataView, SCP11Console


def _make_console_stub() -> SCP11Console:
    console = SCP11Console.__new__(SCP11Console)
    console._executed: list[tuple] = []  # type: ignore[attr-defined]
    console._allow_auto_disable_calls: list[tuple[Any, Any]] = []  # type: ignore[attr-defined]

    class _Style:
        yellow = ""
        red = ""
        green = ""
        end = ""

    console._style = _Style()  # type: ignore[attr-defined]

    def fake_execute(resolved, tag, label):
        console._executed.append((resolved, tag, label))
        return getattr(console, "_execute_result", True)

    def fake_allow(active, target):
        console._allow_auto_disable_calls.append((active, target))
        return getattr(console, "_allow_result", True)

    console._execute_profile_state_command = fake_execute  # type: ignore[attr-defined]
    console._allow_auto_disable_for_enable = fake_allow  # type: ignore[attr-defined]
    console._describe_profile_metadata = lambda meta: meta.nickname  # type: ignore[attr-defined]
    return console


def _make_profile_view(state: str = "ENABLED") -> ProfileMetadataView:
    return ProfileMetadataView(
        iccid="89012345678901234500",
        aid="A0000000871002",
        state=state,
        profile_class="OPER",
        nickname="HomeNet",
        service_provider="ACME",
        profile_name="HomeNet",
        profile_policy_rules_hex="",
    )


class TestDeleteProfileAutoDisable:
    def test_disabled_target_deleted_directly(self) -> None:
        console = _make_console_stub()
        view = _make_profile_view(state="DISABLED")
        SCP11Console._run_delete_profile_state_command(
            console,
            (1, "01"),
            view,
        )
        labels = [entry[2] for entry in console._executed]
        assert labels == ["DeleteProfile"]

    def test_enabled_target_auto_disables_before_delete(self) -> None:
        console = _make_console_stub()
        view = _make_profile_view(state="ENABLED")
        SCP11Console._run_delete_profile_state_command(
            console,
            (1, "01"),
            view,
        )
        labels = [entry[2] for entry in console._executed]
        assert labels == ["DisableProfile", "DeleteProfile"]

    def test_aborts_when_ppr1_guard_refuses(self) -> None:
        console = _make_console_stub()
        console._allow_result = False  # type: ignore[attr-defined]
        view = _make_profile_view(state="ENABLED")
        SCP11Console._run_delete_profile_state_command(
            console,
            (1, "01"),
            view,
        )
        assert console._executed == []

    def test_aborts_when_auto_disable_command_fails(self) -> None:
        console = _make_console_stub()
        view = _make_profile_view(state="ENABLED")
        # The first call (auto-disable) returns False; subsequent calls
        # would still pretend success but the helper must abort.
        original_execute = console._execute_profile_state_command

        def selective_execute(resolved, tag, label):
            console._executed.append((resolved, tag, label))
            if label == "DisableProfile":
                return False
            return True

        console._execute_profile_state_command = selective_execute  # type: ignore[attr-defined]

        SCP11Console._run_delete_profile_state_command(
            console,
            (1, "01"),
            view,
        )
        labels = [entry[2] for entry in console._executed]
        assert labels == ["DisableProfile"]

    def test_handles_missing_target_metadata_safely(self) -> None:
        console = _make_console_stub()
        SCP11Console._run_delete_profile_state_command(
            console,
            (1, "01"),
            None,
        )
        labels = [entry[2] for entry in console._executed]
        assert labels == ["DeleteProfile"]
