# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for host cards, and for the two paths agreeing about one host.

A card describes a box rather than a run, which is what collapses the
Remote Bridge action from twenty-two inputs to one choice. The SSH half
of a card is deliberately local: an invite hands a colleague an agent and
a token, never this operator's login or private key path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from yggdrasim_common.gui_server.actions.card_bridge import (
    _check_host_bench_free,
    _coalesce,
    _host_card_defaults,
)
from yggdrasim_common.remote_lab.registry import (
    export_invite,
    import_invite,
    load_registry,
    update_device,
)


def _import_host(tmp_path: Path) -> None:
    import_invite(
        {
            "schema": "yggdrasim.remoteLabInvite.v1",
            "device": {"id": "rpi-a", "name": "Bench Pi", "location": "TestLocality"},
            "agent": {"host": "rig.example.test", "control_port": 8700},
            "stream": {"transport": "http-card-bridge"},
            "auth": {"mode": "bearer", "token": "opaque-token"},
        }
    )


def test_a_card_stores_the_ssh_half_and_reads_it_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    _import_host(tmp_path)
    update_device(
        "rpi-a",
        {
            "ssh_target": "esim@rig.example.test",
            "ssh_identity_file": "~/.ssh/id_ed25519",
            "remote_workdir": "/home/esim/YggdraSIM",
            "remote_python": "/home/esim/YggdraSIM/.venv/bin/python",
            "hil_service_name": "yggdrasim-hil-supervisor.service",
        },
    )
    stored = load_registry()["rpi-a"]
    assert stored.ssh_target == "esim@rig.example.test"
    assert stored.remote_workdir == "/home/esim/YggdraSIM"
    assert stored.has_ssh is True
    assert stored.has_agent is True


def test_the_ssh_half_never_travels_in_an_invite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invite is what you hand a colleague; your login is not theirs."""
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    _import_host(tmp_path)
    update_device(
        "rpi-a",
        {"ssh_target": "esim@rig.example.test", "ssh_identity_file": "~/.ssh/secret"},
    )
    invite = export_invite("rpi-a")
    rendered = str(invite)
    assert "esim@rig.example.test" not in rendered
    assert "~/.ssh/secret" not in rendered
    assert "access" not in invite


def test_a_card_with_no_ssh_half_reports_only_the_agent_door(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    _import_host(tmp_path)
    stored = load_registry()["rpi-a"]
    assert stored.has_agent is True
    assert stored.has_ssh is False
    assert stored.card_reachability == "tunnel"


def test_direct_reachability_requires_a_card_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Otherwise the host is told to read a card from nowhere."""
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    _import_host(tmp_path)
    with pytest.raises(ValueError, match="needs card_url"):
        update_device("rpi-a", {"card_reachability": "direct"})
    update_device(
        "rpi-a",
        {
            "card_reachability": "direct",
            "card_url": "http://workstation.example.test:8642/apdu",
        },
    )
    assert load_registry()["rpi-a"].card_reachability == "direct"


def test_an_unknown_reachability_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    _import_host(tmp_path)
    with pytest.raises(ValueError, match="tunnel.*direct"):
        update_device("rpi-a", {"card_reachability": "carrier-pigeon"})


def test_naming_a_card_fills_the_action_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    _import_host(tmp_path)
    update_device(
        "rpi-a",
        {
            "ssh_target": "esim@rig.example.test",
            "remote_workdir": "/home/esim/YggdraSIM",
            "hil_service_name": "custom.service",
        },
    )
    defaults = _host_card_defaults("rpi-a")
    assert defaults["ssh_target"] == "esim@rig.example.test"
    assert defaults["remote_workdir"] == "/home/esim/YggdraSIM"
    assert defaults["service_name"] == "custom.service"
    assert defaults["device"].id == "rpi-a"


def test_naming_no_card_changes_nothing() -> None:
    assert _host_card_defaults("") == {}
    assert _host_card_defaults(None) == {}


def test_an_explicit_value_beats_the_card() -> None:
    """The card fills blanks; it does not override a typed answer."""
    assert _coalesce("typed@host", "card@host") == "typed@host"
    assert _coalesce("", "card@host") == "card@host"
    assert _coalesce("   ", "card@host") == "card@host"
    assert _coalesce(None, "card@host") == "card@host"


class _Device:
    """A host card stand-in with just the fields the check reads."""

    def __init__(self, *, has_agent: bool = True, token_file: str = "") -> None:
        self.has_agent = has_agent
        self.token_file = token_file
        self.id = "rpi-a"
        self.remote_rig_id = "rpi-a"
        self.control_base_url = "http://rig.example.test:8700"


_ACCESS_FORM_KEYS = {
    "ssh_target",
    "ssh_identity_file",
    "remote_workdir",
    "remote_python",
    "hil_service_name",
    "card_reachability",
    "card_url",
}


def test_the_registry_accepts_every_field_the_form_offers() -> None:
    """A field that renders and never saves is worse than an absent one."""
    from yggdrasim_common.remote_lab.registry import EDITABLE_DEVICE_FIELDS

    assert _ACCESS_FORM_KEYS <= set(EDITABLE_DEVICE_FIELDS)


def test_the_update_route_carries_every_field_the_form_offers() -> None:
    """The registry taking a key is not enough; the request model gates it.

    Pydantic drops what it does not declare, so a key missing here is
    silently discarded between the form and the registry.
    """
    from yggdrasim_common.gui_server.routes.remote_lab import UpdateDeviceRequest

    assert _ACCESS_FORM_KEYS <= set(UpdateDeviceRequest.model_fields)


def test_the_update_route_saves_an_ssh_target_onto_a_stored_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Picking a host in Remote Bridge writes back the target already typed."""
    from yggdrasim_common.gui_server.routes.remote_lab import (
        UpdateDeviceRequest,
        update_device_route,
    )

    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    _import_host(tmp_path)
    result = update_device_route(
        "rpi-a",
        UpdateDeviceRequest(ssh_target="esim@rig.example.test"),
    )
    assert result["ok"] is True
    assert result["device"]["access"]["ssh_target"] == "esim@rig.example.test"
    assert load_registry()["rpi-a"].has_ssh is True


def test_a_host_can_be_stored_before_it_has_an_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bootstrap case: an invite needs an agent this host has not got.

    Requiring one would mean standing up the agent you were about to
    install in order to record where to install it.
    """
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    from yggdrasim_common.remote_lab.registry import create_ssh_host

    device = create_ssh_host(
        device_id="bench-pi",
        name="Bench Pi",
        ssh_target="esim@rig.example.test",
        remote_workdir="/home/esim/YggdraSIM",
    )
    assert device.has_ssh is True
    assert device.has_agent is False
    stored = load_registry()["bench-pi"]
    assert stored.ssh_target == "esim@rig.example.test"
    assert stored.remote_workdir == "/home/esim/YggdraSIM"


def test_a_host_with_neither_door_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    from yggdrasim_common.remote_lab.registry import create_ssh_host

    with pytest.raises(ValueError, match="ssh_target is required"):
        create_ssh_host(device_id="nowhere", name="Nowhere", ssh_target="")


def test_half_an_agent_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A host with no port would build a control URL nobody can call."""
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    from yggdrasim_common.remote_lab.registry import RemoteLabDevice, _validate_device

    half = RemoteLabDevice(
        id="half",
        name="Half",
        rig_id="half",
        agent_host="rig.example.test",
        agent_control_port=0,
        ssh_target="esim@rig.example.test",
    )
    with pytest.raises(ValueError, match="host and control_port, or neither"):
        _validate_device(half)


def test_an_ssh_only_host_reports_its_own_state_not_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Calling it offline would read as a fault rather than a kind."""
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    from yggdrasim_common.gui_server.routes.remote_lab import device_status
    from yggdrasim_common.remote_lab.registry import create_ssh_host

    create_ssh_host(
        device_id="bench-pi", name="Bench Pi", ssh_target="esim@rig.example.test"
    )
    payload = device_status("bench-pi")
    assert payload["status"] == "ssh-only"
    assert payload["ssh_target"] == "esim@rig.example.test"


def test_an_invite_still_requires_an_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sharing a rig means sharing an agent; an SSH login is not shareable."""
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    with pytest.raises(ValueError):
        import_invite(
            {
                "schema": "yggdrasim.remoteLabInvite.v1",
                "device": {"id": "no-agent", "name": "No agent"},
                "stream": {"transport": "http-card-bridge"},
                "auth": {"mode": "bearer", "token": "opaque-token"},
            }
        )


def test_a_host_with_no_agent_is_not_an_error() -> None:
    """The single-operator case this action was written for."""
    result = _check_host_bench_free(_Device(has_agent=False))
    assert result["ok"] is True
    assert result["checked"] is False


def test_no_card_at_all_is_not_an_error() -> None:
    result = _check_host_bench_free(None)
    assert result["ok"] is True
    assert result["checked"] is False


def test_a_host_with_no_stored_token_is_not_an_error() -> None:
    result = _check_host_bench_free(_Device(token_file=""))
    assert result["ok"] is True
    assert result["checked"] is False


def test_a_reserved_host_stops_the_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "agent.token"
    token_file.write_text("opaque-token\n", encoding="utf-8")

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def status(self, rig_id: str) -> dict:
            return {"status": "busy", "locked_by": "alice"}

    monkeypatch.setattr(
        "yggdrasim_common.remote_lab.client.RemoteLabAgentClient", _Client
    )
    result = _check_host_bench_free(_Device(token_file=str(token_file)))
    assert result["ok"] is False
    assert result["locked_by"] == "alice"
    assert result["state"] == "busy"


def test_a_free_host_passes_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "agent.token"
    token_file.write_text("opaque-token\n", encoding="utf-8")

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def status(self, rig_id: str) -> dict:
            return {"status": "available"}

    monkeypatch.setattr(
        "yggdrasim_common.remote_lab.client.RemoteLabAgentClient", _Client
    )
    result = _check_host_bench_free(_Device(token_file=str(token_file)))
    assert result["ok"] is True
    assert result["checked"] is True
    assert result["state"] == "available"


def test_a_host_already_running_a_hil_rig_is_reported_not_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Starting a rig is what this action does.

    A host that already has one is the normal state to arrive in, not a
    collision, and refusing left the tool unable to restart the rig it
    had started itself. It is reported so the operator knows what is
    about to be replaced.
    """
    token_file = tmp_path / "agent.token"
    token_file.write_text("opaque-token\n", encoding="utf-8")

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def status(self, rig_id: str) -> dict:
            return {
                "status": "available",
                "host": {
                    "hil_rig": "running",
                    "hil_card_source": "remote",
                    "hil_card_url": "http://127.0.0.1:8908/apdu",
                },
            }

    monkeypatch.setattr(
        "yggdrasim_common.remote_lab.client.RemoteLabAgentClient", _Client
    )
    result = _check_host_bench_free(_Device(token_file=str(token_file)))
    assert result["ok"] is True
    assert result["state"] == "hil-running"
    assert "8908" in result["note"]
    assert "replaces it" in result["note"]


def test_a_host_with_a_stopped_hil_rig_is_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "agent.token"
    token_file.write_text("opaque-token\n", encoding="utf-8")

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def status(self, rig_id: str) -> dict:
            return {"status": "available", "host": {"hil_rig": "stopped"}}

    monkeypatch.setattr(
        "yggdrasim_common.remote_lab.client.RemoteLabAgentClient", _Client
    )
    result = _check_host_bench_free(_Device(token_file=str(token_file)))
    assert result["ok"] is True


def test_an_unreachable_agent_does_not_block_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rig being prepared may well not be answering yet."""
    token_file = tmp_path / "agent.token"
    token_file.write_text("opaque-token\n", encoding="utf-8")

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def status(self, rig_id: str) -> dict:
            raise OSError("connection refused")

    monkeypatch.setattr(
        "yggdrasim_common.remote_lab.client.RemoteLabAgentClient", _Client
    )
    result = _check_host_bench_free(_Device(token_file=str(token_file)))
    assert result["ok"] is True
    assert result["checked"] is False
