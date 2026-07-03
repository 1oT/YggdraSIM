# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest

from Tools.HilBridge.apdu_relay import ApduRelayConfig, HilBridgeApduRelayService
from yggdrasim_common.card_backend import RelayCardConnection
from yggdrasim_common.remote_lab.agent import RemoteLabAgentService
from yggdrasim_common.remote_lab.client import RemoteLabAgentClient, RemoteLabClientError
from yggdrasim_common.remote_lab.config import parse_config
from yggdrasim_common.remote_lab.registry import export_invite, import_invite, load_registry
from yggdrasim_common.remote_lab.security import hash_token
from yggdrasim_common.remote_lab.sessions import LabSessionManager, RigBusyError


_CONFIG_PORT_COUNTER = 18000


def _config_port() -> int:
    global _CONFIG_PORT_COUNTER
    _CONFIG_PORT_COUNTER += 1
    return _CONFIG_PORT_COUNTER


def _free_loopback_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])
    except PermissionError as exc:
        pytest.skip(f"loopback sockets are unavailable in this sandbox: {exc}")


def _base_config(
    *,
    upstream_url: str = "http://127.0.0.1:1/apdu",
    port_factory: Any = _config_port,
) -> dict:
    return {
        "agent": {
            "id": "test-agent",
            "name": "Test Agent",
            "bind_host": "127.0.0.1",
            "control_port": port_factory(),
            "public_host": "127.0.0.1",
        },
        "security": {
            "access_tokens": [
                {
                    "id": "team",
                    "token_hash": hash_token("team-token"),
                    "role": "user",
                },
                {
                    "id": "admin",
                    "token_hash": hash_token("admin-token"),
                    "role": "admin",
                },
            ]
        },
        "defaults": {
            "reservation_timeout_seconds": 30,
            "heartbeat_timeout_seconds": 60,
            "max_session_seconds": 3600,
        },
        "rigs": [
            {
                "id": "rig-a",
                "name": "Rig A",
                "stream_proxy": {
                    "bind_host": "127.0.0.1",
                    "external_port": port_factory(),
                },
                "upstream": {
                    "url": upstream_url,
                    "token": "upstream-token",
                },
                "locks": ["rig:rig-a", "card:shared"],
            },
            {
                "id": "rig-b",
                "name": "Rig B",
                "stream_proxy": {
                    "bind_host": "127.0.0.1",
                    "external_port": port_factory(),
                },
                "upstream": {
                    "url": upstream_url,
                    "token": "upstream-token",
                },
                "locks": ["rig:rig-b", "card:shared"],
            },
        ],
    }


def test_config_rejects_duplicate_relay_port() -> None:
    payload = _base_config()
    port = payload["rigs"][0]["stream_proxy"]["external_port"]
    payload["rigs"][1]["stream_proxy"]["external_port"] = port
    with pytest.raises(ValueError, match="duplicate stream proxy"):
        parse_config(payload)


def test_config_rejects_stream_port_that_overlaps_control_port() -> None:
    payload = _base_config()
    control_port = payload["agent"]["control_port"]
    payload["rigs"][0]["stream_proxy"]["external_port"] = control_port
    with pytest.raises(ValueError, match="conflicts with agent control port"):
        parse_config(payload)


def test_lock_manager_blocks_shared_card_resource() -> None:
    config = parse_config(_base_config())
    manager = LabSessionManager(config.rigs, config.defaults)
    first = manager.create_session("rig-a", user="alice")
    with pytest.raises(RigBusyError) as ctx:
        manager.create_session("rig-b", user="bob")
    assert ctx.value.payload["held_resource"] == "card:shared"
    manager.release(first.id, first.token)
    second = manager.create_session("rig-b", user="bob")
    assert second.rig_id == "rig-b"


def test_invite_import_stores_token_file_not_registry_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    invite = {
        "schema": "yggdrasim.remoteLabInvite.v1",
        "device": {
            "id": "rig-a",
            "name": "Rig A",
            "location": "Lab",
            "tags": ["ec25"],
        },
        "agent": {"host": "10.0.0.42", "control_port": 8700},
        "stream": {"transport": "http-card-bridge"},
        "auth": {"mode": "bearer", "token": "opaque-token"},
    }
    device = import_invite(invite)
    registry = load_registry()
    assert "rig-a" in registry
    assert Path(device.token_file).is_file()
    assert "opaque-token" not in Path(tmp_path, "Workspace", "RemoteLab", "registry.json").read_text()
    exported = export_invite("rig-a")
    assert exported["auth"]["token"] == "opaque-token"
    duplicate = dict(invite)
    duplicate["auth"] = {"mode": "bearer", "token": "replacement-token"}
    with pytest.raises(ValueError, match="device already exists"):
        import_invite(duplicate, replace=False)
    assert Path(device.token_file).read_text(encoding="utf-8").strip() == "opaque-token"


def _get(url: str, *, token: str = "") -> tuple[int, dict]:
    req = urllib_request.Request(url, method="GET")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib_request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read().decode() or "{}")
    except urllib_error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def test_agent_relay_requires_session_and_proxies_apdus() -> None:
    exchanges: list[bytes] = []
    upstream = HilBridgeApduRelayService(
        ApduRelayConfig(
            host="127.0.0.1",
            port=0,
            enabled=True,
            auth_token="upstream-token",
        ),
        exchange_callback=lambda apdu, *, session_id="": (
            exchanges.append(bytes(apdu)) or bytes.fromhex("CAFE"),
            0x90,
            0x00,
        ),
        status_callback=lambda: {"reader": "fake upstream", "atr": "3B9F"},
    )
    try:
        upstream.start()
    except PermissionError as exc:
        pytest.skip(f"loopback sockets are unavailable in this sandbox: {exc}")
    service = None
    thread = None
    try:
        config = parse_config(_base_config(upstream_url=upstream.apdu_url, port_factory=_free_loopback_port))
        service = RemoteLabAgentService(config)
        try:
            service.start()
        except PermissionError as exc:
            pytest.skip(f"loopback sockets are unavailable in this sandbox: {exc}")
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()

        client = RemoteLabAgentClient(
            f"http://127.0.0.1:{config.agent.control_port}",
            "team-token",
        )
        grant = client.create_session("rig-a", user="alice")
        stream = grant["stream"]

        status, payload = _get(stream["status_url"])
        assert status == 401
        assert "error" in payload

        connection = RelayCardConnection(stream["url"], auth_token=grant["session_token"])
        connection.connect()
        data, sw1, sw2 = connection.transmit(bytes.fromhex("00A40400"))
        assert bytes(data) == bytes.fromhex("CAFE")
        assert (sw1, sw2) == (0x90, 0x00)
        assert exchanges == [bytes.fromhex("00A40400")]

        with pytest.raises(RemoteLabClientError) as busy:
            client.create_session("rig-a", user="bob")
        assert busy.value.status == 423

        with pytest.raises(RemoteLabClientError) as shared_busy:
            client.create_session("rig-b", user="bob")
        assert shared_busy.value.status == 423

        client.release(grant["session_id"], grant["session_token"])
        second = client.create_session("rig-b", user="bob")
        assert second["rig_id"] == "rig-b"
    finally:
        if service is not None:
            service.stop()
        if thread is not None:
            thread.join(timeout=2.0)
        upstream.stop()


def test_frontend_remote_lab_surface_is_wired() -> None:
    root = Path(__file__).resolve().parents[1]
    html = (root / "yggdrasim_common/gui_server/static/index.html").read_text()
    js = (root / "yggdrasim_common/gui_server/static/app.js").read_text()
    assert 'data-view="remote_lab"' in html
    assert "loadRemoteLab()" in js
    assert 'inspectView: "remote_lab"' in js
    assert "/api/remote-lab/devices/" in js
    assert "/api/remote-lab/sessions" in js
    assert "stream_port" in js


def test_frontend_remote_host_onboarding_surface_is_reframed() -> None:
    root = Path(__file__).resolve().parents[1]
    html = (root / "yggdrasim_common/gui_server/static/index.html").read_text()
    js = (root / "yggdrasim_common/gui_server/static/app.js").read_text()
    assert "<h1>Remote host onboarding</h1>" in html
    assert 'id="cb-rig-port-plan"' in html
    assert "Remote Host Onboarding" in js
    assert "cbRigSuggestedPortsForTarget" in js
    assert "cbRigDefaultTokenFileForPort" in js
