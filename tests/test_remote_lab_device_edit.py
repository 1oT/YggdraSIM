# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Editing a registered Remote Lab device in place.

Before this existed the only ways to change a device were re-importing its
invite or hand-editing ``Workspace/RemoteLab/registry.json`` -- which is how a
rig repointed from an SSH tunnel to a VPN address had to be done.

Two behaviours carry real risk and are pinned here:

* **Omission means "leave alone."** A form that posts only ``name`` must not
  blank the notes beside it. An explicitly sent empty string still clears.
* **The host is stored normalised.** ``_validate_device`` only calls
  ``_normalize_host`` to raise and throws the canonical value away, so an
  update that skipped normalisation would store whatever case or trailing dot
  the operator typed -- and the reader bar matches reader names by exact
  string.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from yggdrasim_common.remote_lab.registry import (
    EDITABLE_DEVICE_FIELDS,
    get_device,
    import_invites,
    update_device,
)


def _invite(local_id: str = "rig-a", host: str = "127.0.0.1") -> dict[str, Any]:
    return {
        "schema": "yggdrasim.remoteLabInvite.v1",
        "device": {
            "id": local_id,
            "name": local_id,
            "notes": "original notes",
            "location": "bench",
            "tags": ["pcsc"],
        },
        "agent": {"host": host, "control_port": 8700},
        "stream": {"transport": "http-card-bridge"},
        "auth": {"mode": "bearer", "token": "opaque-token"},
    }


@pytest.fixture()
def registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    import_invites(_invite())


def test_rename_keeps_every_field_the_caller_did_not_send(registry: None) -> None:
    update_device("rig-a", {"name": "Bench rig A"})
    device = get_device("rig-a")
    assert device.name == "Bench rig A"
    # The whole point: a name-only edit leaves the rest intact.
    assert device.notes == "original notes"
    assert device.location == "bench"
    assert device.tags == ("pcsc",)
    assert device.agent_control_port == 8700


def test_an_explicit_empty_string_clears_a_free_text_field(registry: None) -> None:
    update_device("rig-a", {"notes": ""})
    assert get_device("rig-a").notes == ""
    assert get_device("rig-a").name == "rig-a"


def test_host_is_stored_normalised(registry: None) -> None:
    update_device("rig-a", {"agent_host": "ESIM-RaspberryPi.INT.1ot.mobi."})
    device = get_device("rig-a")
    assert device.agent_host == "esim-raspberrypi.int.1ot.mobi"
    assert device.control_base_url == "http://esim-raspberrypi.int.1ot.mobi:8700"


def test_repointing_host_and_port_together(registry: None) -> None:
    update_device(
        "rig-a",
        {"agent_host": "rig.internal.example", "agent_control_port": 9100},
    )
    assert get_device("rig-a").control_base_url == "http://rig.internal.example:9100"


def test_tags_accept_a_string_or_a_list(registry: None) -> None:
    update_device("rig-a", {"tags": "pcsc, esim"})
    assert get_device("rig-a").tags == ("pcsc", "esim")
    update_device("rig-a", {"tags": ["one", " ", "two"]})
    assert get_device("rig-a").tags == ("one", "two")


def test_updated_at_moves(registry: None) -> None:
    before = get_device("rig-a").updated_at
    update_device("rig-a", {"location": "rack 4"})
    assert get_device("rig-a").updated_at >= before


def test_created_at_survives_an_edit(registry: None) -> None:
    before = get_device("rig-a").created_at
    update_device("rig-a", {"name": "renamed"})
    assert get_device("rig-a").created_at == before


def test_token_file_is_untouched_by_an_edit(registry: None) -> None:
    before = get_device("rig-a").token_file
    update_device("rig-a", {"name": "renamed"})
    assert get_device("rig-a").token_file == before


# --- what must be refused ----------------------------------------------


def test_rig_id_is_not_editable(registry: None) -> None:
    # It is the id the agent matches and it is baked into the remote-reader
    # binding, the session metadata and the per-reader localStorage key.
    with pytest.raises(ValueError, match="not editable"):
        update_device("rig-a", {"rig_id": "something-else"})


@pytest.mark.parametrize("field", ["id", "token_file", "stream_transport", "created_at"])
def test_identity_and_credential_fields_are_refused(registry: None, field: str) -> None:
    with pytest.raises(ValueError, match="not editable"):
        update_device("rig-a", {field: "x"})


def test_unknown_field_is_refused_rather_than_ignored(registry: None) -> None:
    with pytest.raises(ValueError, match="not editable"):
        update_device("rig-a", {"nonsense": 1})


def test_empty_name_is_refused(registry: None) -> None:
    with pytest.raises(ValueError):
        update_device("rig-a", {"name": "   "})


def test_bad_host_is_refused_and_nothing_is_written(registry: None) -> None:
    with pytest.raises(ValueError):
        update_device("rig-a", {"agent_host": "http://nope/path"})
    assert get_device("rig-a").agent_host == "127.0.0.1"


def test_bad_port_is_refused(registry: None) -> None:
    with pytest.raises(ValueError):
        update_device("rig-a", {"agent_control_port": 70000})


def test_bad_scheme_is_refused(registry: None) -> None:
    with pytest.raises(ValueError):
        update_device("rig-a", {"agent_scheme": "ftp"})


def test_unknown_device_raises_key_error(registry: None) -> None:
    with pytest.raises(KeyError):
        update_device("no-such-rig", {"name": "x"})


def test_editable_set_excludes_identity_and_credentials() -> None:
    for forbidden in ("id", "rig_id", "token_file", "stream_transport", "created_at"):
        assert forbidden not in EDITABLE_DEVICE_FIELDS


# --- the HTTP layer ------------------------------------------------------
#
# Called directly rather than through TestClient, matching the convention in
# tests/test_gui_card_bridge_actions_http.py and friends.

pytest.importorskip("fastapi")

from yggdrasim_common.gui_server.routes import remote_lab as routes  # noqa: E402


def test_route_forwards_only_the_fields_the_caller_sent(registry: None) -> None:
    # The model has nine optional fields; a body naming one must not arrive at
    # the registry as eight Nones. This is the exclude_unset contract.
    body = routes.UpdateDeviceRequest(**{"name": "From the GUI"})
    result = routes.update_device_route("rig-a", body)
    assert result["ok"] is True
    assert result["device"]["name"] == "From the GUI"
    assert get_device("rig-a").notes == "original notes"
    assert get_device("rig-a").location == "bench"


def test_route_clears_a_field_when_the_caller_sends_an_empty_string(registry: None) -> None:
    body = routes.UpdateDeviceRequest(**{"notes": ""})
    routes.update_device_route("rig-a", body)
    assert get_device("rig-a").notes == ""


def test_route_response_never_carries_the_token_file(registry: None) -> None:
    body = routes.UpdateDeviceRequest(**{"name": "x"})
    result = routes.update_device_route("rig-a", body)
    assert "token_file" not in result["device"]["auth"]
    assert result["device"]["auth"]["token_present"] is True


def test_route_rejects_an_empty_body(registry: None) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        routes.update_device_route("rig-a", routes.UpdateDeviceRequest())
    assert caught.value.status_code == 422


def test_route_404s_for_an_unknown_device(registry: None) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        routes.update_device_route("nope", routes.UpdateDeviceRequest(**{"name": "x"}))
    assert caught.value.status_code == 404


def test_route_422s_on_a_bad_host(registry: None) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        routes.update_device_route(
            "rig-a", routes.UpdateDeviceRequest(**{"agent_host": "http://nope/x"})
        )
    assert caught.value.status_code == 422
    assert get_device("rig-a").agent_host == "127.0.0.1"


def test_route_accepts_tags_as_a_comma_separated_string(registry: None) -> None:
    # The GUI shows tags as one text field. A list-only model rejected that
    # with 422 before update_device (which splits strings) ever ran.
    body = routes.UpdateDeviceRequest(**{"tags": "pcsc, esim, lab"})
    routes.update_device_route("rig-a", body)
    assert get_device("rig-a").tags == ("pcsc", "esim", "lab")


def test_route_still_accepts_tags_as_a_list(registry: None) -> None:
    body = routes.UpdateDeviceRequest(**{"tags": ["one", "two"]})
    routes.update_device_route("rig-a", body)
    assert get_device("rig-a").tags == ("one", "two")


# --- frontend guards -----------------------------------------------------

_CORE_JS = Path(__file__).resolve().parents[1] / "gui_frontend/src/js/core.js"


def _core() -> str:
    return _CORE_JS.read_text(encoding="utf-8")


def test_edit_is_disabled_while_a_session_is_live() -> None:
    body = _core()
    start = body.index('editBtn.textContent = "Edit";')
    window = body[start : start + 600]
    # A rename or repoint mid-session strands the remote-reader binding, the
    # session metadata reader_name and the per-reader localStorage key.
    assert "editBtn.disabled = !!activeSession;" in window


def test_edit_form_offers_no_field_the_registry_refuses() -> None:
    body = _core()
    start = body.index("var REMOTE_LAB_EDIT_FIELDS")
    window = body[start : body.index("function remoteLabEditValueFor")]
    for forbidden in ("rig_id", "token_file", "stream_transport"):
        assert forbidden not in window


def test_edit_form_covers_every_field_it_claims_to_send() -> None:
    body = _core()
    payload = body[body.index("async function remoteLabSaveEdit") :][:1400]
    for key in ("name", "agent_host", "agent_scheme", "location", "owner", "tags", "notes"):
        assert f"{key}:" in payload
