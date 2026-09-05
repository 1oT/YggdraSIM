# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import json
import multiprocessing
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any
from unittest import mock
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest

from Tools.HilBridge.apdu_relay import ApduRelayConfig, HilBridgeApduRelayService
from yggdrasim_common.card_backend import RelayCardConnection
from yggdrasim_common.remote_lab.agent import RemoteLabAgentService
from yggdrasim_common.remote_lab.client import (
    RemoteLabAgentClient,
    RemoteLabClientError,
    _json_request,
)
from yggdrasim_common.remote_lab.config import parse_config
from yggdrasim_common.remote_lab.registry import (
    INVITE_BUNDLE_SCHEMA,
    RemoteLabDevice,
    export_invite,
    import_invite,
    import_invites,
    load_registry,
)
from yggdrasim_common.remote_lab.security import hash_token
from yggdrasim_common.remote_lab.sessions import LabSessionManager, RigBusyError


_CONFIG_PORT_COUNTER = 18000


def _import_invite_worker(
    runtime_root: str,
    invite: dict[str, Any],
    start_event: Any,
    result_queue: Any,
) -> None:
    import os

    os.environ["YGGDRASIM_RUNTIME_ROOT"] = runtime_root
    try:
        start_event.wait(10)
        imported = import_invite(invite)
        result_queue.put(("ok", imported.id))
    except Exception as exc:  # pragma: no cover - reported to parent process
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


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


def test_config_rejects_wildcard_relay_port_overlap() -> None:
    payload = _base_config()
    port = payload["rigs"][0]["stream_proxy"]["external_port"]
    payload["rigs"][0]["stream_proxy"]["bind_host"] = "0.0.0.0"
    payload["rigs"][1]["stream_proxy"]["bind_host"] = "127.0.0.1"
    payload["rigs"][1]["stream_proxy"]["external_port"] = port
    with pytest.raises(ValueError, match="duplicate stream proxy"):
        parse_config(payload)


def test_config_accepts_https_public_relay_base() -> None:
    payload = _base_config()
    payload["rigs"][0]["stream_proxy"]["public_base_url"] = (
        "https://lab.example.test/relay/rig-a/"
    )
    config = parse_config(payload)
    assert (
        config.rigs[0].stream_proxy.public_base_url
        == "https://lab.example.test/relay/rig-a"
    )


def test_config_formats_unbracketed_ipv6_upstream_host() -> None:
    payload = _base_config()
    payload["rigs"][0]["upstream"] = {
        "host": "::1",
        "port": 8642,
        "scheme": "http",
    }
    config = parse_config(payload)
    assert config.rigs[0].upstream.url == "http://[::1]:8642/apdu"


def test_agent_relay_url_supports_https_public_base_and_ipv6_host() -> None:
    public_payload = _base_config()
    public_payload["rigs"][0]["stream_proxy"]["public_base_url"] = (
        "https://relay.example.test/rig-a"
    )
    public_service = RemoteLabAgentService(parse_config(public_payload))
    handler = mock.Mock()
    handler.headers = {"Host": "[::1]:8700"}
    assert (
        public_service.relay_base_url(handler, public_service.config.rigs[0])
        == "https://relay.example.test/rig-a"
    )

    ipv6_payload = _base_config()
    ipv6_payload["agent"]["public_host"] = "::1"
    ipv6_service = RemoteLabAgentService(parse_config(ipv6_payload))
    assert (
        ipv6_service.relay_base_url(handler, ipv6_service.config.rigs[0])
        == f"http://[::1]:{ipv6_service.config.rigs[0].stream_proxy.external_port}"
    )


def test_agent_start_tracks_each_relay_once_and_stop_closes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common.remote_lab import agent as agent_module

    config = parse_config(_base_config())
    relay_servers: list[Any] = []

    class FakeServer:
        def __init__(self, *_args: Any) -> None:
            self.shutdown_calls = 0
            self.close_calls = 0

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            self.shutdown_calls += 1

        def server_close(self) -> None:
            self.close_calls += 1

    def relay_factory(*args: Any) -> FakeServer:
        server = FakeServer(*args)
        relay_servers.append(server)
        return server

    class FakeThread:
        def __init__(self, *, target: Any, name: str, daemon: bool) -> None:
            self.target = target
            self.name = name
            self.daemon = daemon

        def start(self) -> None:
            return

        def join(self, timeout: float | None = None) -> None:
            return

    monkeypatch.setattr(agent_module, "_RelayServer", relay_factory)
    monkeypatch.setattr(agent_module, "_ControlServer", FakeServer)
    monkeypatch.setattr(agent_module.threading, "Thread", FakeThread)

    service = RemoteLabAgentService(config)
    service.start()
    assert service._relay_servers == relay_servers
    assert len(service._relay_servers) == len(config.rigs)
    service.stop()
    assert all(server.shutdown_calls == 1 for server in relay_servers)
    assert all(server.close_calls == 1 for server in relay_servers)


def test_agent_start_closes_bound_relays_when_later_bind_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common.remote_lab import agent as agent_module

    config = parse_config(_base_config())

    class FirstServer:
        close_calls = 0

        def server_close(self) -> None:
            self.close_calls += 1

    first_server = FirstServer()
    calls = 0

    def relay_factory(*_args: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            return first_server
        raise OSError("simulated bind collision")

    monkeypatch.setattr(agent_module, "_RelayServer", relay_factory)
    service = RemoteLabAgentService(config)
    with pytest.raises(OSError, match="bind collision"):
        service.start()
    assert first_server.close_calls == 1
    assert service._relay_servers == []
    assert service._control_server is None


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


def _invite_for(
    *,
    local_id: str,
    rig_id: str = "",
    host: str = "127.0.0.1",
    token: str = "opaque-token",
) -> dict[str, Any]:
    device: dict[str, Any] = {"id": local_id, "name": local_id}
    if rig_id:
        device["rig_id"] = rig_id
    return {
        "schema": "yggdrasim.remoteLabInvite.v1",
        "device": device,
        "agent": {"host": host, "control_port": 8700},
        "stream": {"transport": "http-card-bridge"},
        "auth": {"mode": "bearer", "token": token},
    }


def test_batch_invite_import_is_atomic_and_supports_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    bundle = {
        "schema": INVITE_BUNDLE_SCHEMA,
        "invites": [
            _invite_for(local_id="site-a-rig", rig_id="rig-a", token="token-a"),
            _invite_for(
                local_id="site-b-rig",
                rig_id="rig-a",
                host="lab-b.example.test",
                token="token-b",
            ),
        ],
    }
    imported = import_invites(bundle)
    assert [device.id for device in imported] == ["site-a-rig", "site-b-rig"]
    assert {device.remote_rig_id for device in imported} == {"rig-a"}
    assert set(load_registry()) == {"site-a-rig", "site-b-rig"}

    invalid_batch = [
        _invite_for(local_id="site-c-rig"),
        _invite_for(local_id="site-d-rig", host="http://invalid/path"),
    ]
    with pytest.raises(ValueError, match="agent host"):
        import_invites(invalid_batch)
    assert set(load_registry()) == {"site-a-rig", "site-b-rig"}


def test_import_rejects_case_insensitive_device_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    import_invite(_invite_for(local_id="Lab-A"))
    with pytest.raises(ValueError, match="case-insensitively"):
        import_invite(_invite_for(local_id="lab-a"))


def test_windows_reserved_device_id_gets_safe_token_filename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    device = import_invite(_invite_for(local_id="CON"))
    assert Path(device.token_file).name.startswith("device-CON.")
    assert Path(device.token_file).is_file()


def test_ipv6_control_url_is_bracketed() -> None:
    device = RemoteLabDevice(
        id="ipv6-rig",
        name="IPv6 rig",
        agent_host="fe80::1%en0",
        agent_control_port=8700,
    )
    assert device.control_base_url == "http://[fe80::1%25en0]:8700"


def test_registry_read_modify_write_is_serialized_across_spawned_processes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_import_invite_worker,
            args=(
                str(tmp_path),
                _invite_for(local_id=f"device-{index}", token=f"token-{index}"),
                start_event,
                result_queue,
            ),
        )
        for index in range(2)
    ]
    try:
        for process in processes:
            process.start()
        start_event.set()
        for process in processes:
            process.join(timeout=20)
        results = [result_queue.get(timeout=2) for _process in processes]
        assert results == [("ok", "device-0"), ("ok", "device-1")] or results == [
            ("ok", "device-1"),
            ("ok", "device-0"),
        ]
        assert all(process.exitcode == 0 for process in processes)
        assert set(load_registry()) == {"device-0", "device-1"}
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=2)
        result_queue.close()


def test_registry_lock_uses_windows_msvcrt_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common.remote_lab import registry as registry_module

    calls: list[tuple[int, int, int]] = []

    class FakeMsvcrt:
        LK_NBLCK = 1
        LK_UNLCK = 2

        @staticmethod
        def locking(descriptor: int, operation: int, length: int) -> None:
            calls.append((descriptor, operation, length))

    lock_path = tmp_path / "lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.write(descriptor, b"\0")
        monkeypatch.setitem(sys.modules, "msvcrt", FakeMsvcrt)
        monkeypatch.setattr(registry_module.os, "name", "nt")
        registry_module._lock_registry_descriptor(descriptor)
        registry_module._unlock_registry_descriptor(descriptor)
    finally:
        os.close(descriptor)
    assert [operation for _descriptor, operation, _length in calls] == [1, 2]
    assert all(length == 1 for _descriptor, _operation, length in calls)


class _FakeHttpResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        content_length: str | None = None,
    ) -> None:
        self.payload = payload
        self.headers = {
            "Content-Length": (
                str(len(payload)) if content_length is None else content_length
            )
        }

    def __enter__(self) -> "_FakeHttpResponse":
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self.payload if limit < 0 else self.payload[:limit]


def test_remote_client_quotes_rig_id_and_bounds_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_urls: list[str] = []

    def fake_urlopen(request: Any, **_kwargs: Any) -> _FakeHttpResponse:
        captured_urls.append(request.full_url)
        return _FakeHttpResponse(b'{"status":"available"}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = RemoteLabAgentClient("https://[::1]:8700", "token")
    assert client.status("rig/a b")["status"] == "available"
    assert captured_urls == ["https://[::1]:8700/api/v1/rigs/rig%2Fa%20b/status"]

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: _FakeHttpResponse(
            b"",
            content_length=str(1024 * 1024 + 1),
        ),
    )
    with pytest.raises(RemoteLabClientError, match="1 MiB"):
        _json_request("https://lab.example.test/api/v1/info")


def test_remote_client_maps_timeout_to_client_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise TimeoutError("timed out")

    monkeypatch.setattr("urllib.request.urlopen", raise_timeout)
    with pytest.raises(RemoteLabClientError, match="timed out"):
        _json_request("https://lab.example.test/api/v1/info")


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


def test_remote_lab_headless_api_surface_is_registered() -> None:
    from yggdrasim_common.gui_server.routes.remote_lab import router

    registered = {
        (route.path, method)
        for route in router.routes
        for method in getattr(route, "methods", set())
    }
    expected = {
        ("/api/remote-lab/devices", "GET"),
        ("/api/remote-lab/import", "POST"),
        ("/api/remote-lab/devices/{device_id}/export", "GET"),
        ("/api/remote-lab/devices/{device_id}", "DELETE"),
        ("/api/remote-lab/devices/{device_id}/status", "GET"),
        ("/api/remote-lab/status", "GET"),
        ("/api/remote-lab/sessions", "GET"),
        ("/api/remote-lab/devices/{device_id}/connect", "POST"),
        ("/api/remote-lab/devices/{device_id}/release", "POST"),
        ("/api/remote-lab/devices/{device_id}/force-release", "POST"),
    }
    assert expected <= registered


def test_remote_lab_headless_api_import_export_delete_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common.gui_server.routes.remote_lab import (
        ImportInviteRequest,
        delete_device,
        devices,
        export_device,
        import_device,
    )

    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    invite = {
        "schema": "yggdrasim.remoteLabInvite.v1",
        "device": {
            "id": "neutral-rig",
            "name": "Neutral Rig",
            "location": "Integration Lab",
            "tags": ["simulator"],
        },
        "agent": {
            "scheme": "https",
            "host": "rig.example.test",
            "control_port": 8700,
        },
        "stream": {"transport": "http-card-bridge"},
        "auth": {"mode": "bearer", "token": "opaque-test-token"},
    }

    created = import_device(ImportInviteRequest(invite=invite, replace=True))
    assert created["ok"] is True
    assert created["device"]["id"] == "neutral-rig"
    assert created["device"]["auth"] == {
        "mode": "bearer",
        "token_present": True,
    }

    listed = devices()
    assert listed["count"] == 1
    assert listed["devices"][0]["id"] == "neutral-rig"

    exported = export_device("neutral-rig", include_token=False)
    assert exported["auth"] == {"mode": "bearer"}
    assert exported["agent"]["host"] == "rig.example.test"

    removed = delete_device("neutral-rig", remove_token_file=True)
    assert removed == {"ok": True, "removed": "neutral-rig"}
    assert devices() == {"count": 0, "devices": []}


def test_status_and_force_release_use_remote_rig_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common.gui_server.routes import remote_lab as routes

    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    import_invite(_invite_for(local_id="site-a", rig_id="rig-a"))

    class FakeClient:
        def __init__(self) -> None:
            self.status_ids: list[str] = []
            self.release_ids: list[str] = []

        def status(self, rig_id: str) -> dict[str, Any]:
            self.status_ids.append(rig_id)
            return {"id": rig_id, "status": "available"}

        def force_release(
            self,
            rig_id: str,
            *,
            admin_token: str,
            reason: str,
        ) -> dict[str, Any]:
            self.release_ids.append(rig_id)
            return {"status": "released"}

    client = FakeClient()
    monkeypatch.setattr(routes, "_client_for_device", lambda *_args, **_kwargs: client)
    status = routes.device_status("site-a")
    assert status == {"id": "site-a", "rig_id": "rig-a", "status": "available"}
    routes.force_release_device(
        "site-a",
        routes.ForceReleaseRequest(admin_token="admin", reason="test"),
    )
    assert client.status_ids == ["rig-a"]
    assert client.release_ids == ["rig-a"]


def test_all_status_probes_multiple_devices_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common.gui_server.routes import remote_lab as routes

    state_lock = threading.Lock()
    active = 0
    peak = 0

    def fake_status(device_id: str) -> dict[str, Any]:
        nonlocal active, peak
        with state_lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with state_lock:
            active -= 1
        return {"id": device_id, "status": "available"}

    monkeypatch.setattr(
        routes,
        "load_registry",
        lambda: {"device-b": mock.sentinel.b, "device-a": mock.sentinel.a},
    )
    monkeypatch.setattr(routes, "device_status", fake_status)
    result = routes.all_status()
    assert [row["id"] for row in result["devices"]] == ["device-a", "device-b"]
    assert peak == 2


def test_remote_attach_uses_remote_rig_and_idempotent_heartbeat_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common import card_backend
    from yggdrasim_common.gui_server.actions import scp03 as scp03_actions
    from yggdrasim_common.gui_server.routes import remote_lab as routes

    device = RemoteLabDevice(
        id="site-a",
        name="Site A",
        rig_id="rig-a",
        agent_host="lab.example.test",
        agent_control_port=8700,
    )

    class FakeClient:
        timeout_seconds = 0.1

        def __init__(self) -> None:
            self.create_ids: list[str] = []
            self.release_calls = 0
            self.heartbeat_calls = 0

        def create_session(self, rig_id: str, **_kwargs: Any) -> dict[str, Any]:
            self.create_ids.append(rig_id)
            return {
                "session_id": "remote-session",
                "session_token": "remote-token",
                "heartbeat_interval_seconds": 1,
                "stream": {"url": "https://relay.example.test/apdu"},
            }

        def heartbeat(self, *_args: Any) -> dict[str, Any]:
            self.heartbeat_calls += 1
            return {"status": "ok"}

        def release(self, *_args: Any) -> dict[str, Any]:
            self.release_calls += 1
            return {"status": "released"}

    class FakeConnection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.connected = False

        def connect(self) -> None:
            self.connected = True

        def disconnect(self) -> None:
            self.connected = False

        def getATR(self) -> list[int]:
            return [0x3B, 0x00]

    client = FakeClient()
    callbacks: list[Any] = []

    def fake_scan(_transporter: Any, **kwargs: Any) -> dict[str, Any]:
        callbacks.append(kwargs["close_callback"])
        return {
            "session_id": "local-session",
            "reader_name": kwargs["reader_label"],
            "atr_hex": "3B00",
        }

    monkeypatch.setattr(routes, "get_device", lambda _device_id: device)
    monkeypatch.setattr(routes, "_client_for_device", lambda *_args, **_kwargs: client)
    monkeypatch.setattr(card_backend, "RelayCardConnection", FakeConnection)
    monkeypatch.setattr(scp03_actions, "_scan_transporter_to_session", fake_scan)
    close_transporter = mock.Mock()
    monkeypatch.setattr(scp03_actions, "_close_transporter", close_transporter)

    result = routes._open_remote_lab_scp03_session(
        device_id="site-a",
        user="tester",
        requested_ttl_seconds=120,
    )
    assert client.create_ids == ["rig-a"]
    assert result["remote_lab"]["rig_id"] == "rig-a"
    assert len(callbacks) == 1

    callbacks[0]()
    callbacks[0]()
    assert client.release_calls == 1
    close_transporter.assert_called_once()
    assert not any(
        thread.name == "remote-lab-heartbeat-site-a" and thread.is_alive()
        for thread in threading.enumerate()
    )


def test_scp03_adoption_closes_transport_when_setup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from SCP03.config import Config as Scp03Config
    from yggdrasim_common.gui_server.actions.scp03 import (
        _scan_transporter_to_session,
    )

    closed: list[bool] = []

    def fail_workspace_setup() -> None:
        raise RuntimeError("workspace unavailable")

    monkeypatch.setattr(
        Scp03Config,
        "initialize_workspace",
        staticmethod(fail_workspace_setup),
    )
    with pytest.raises(RuntimeError, match="workspace unavailable"):
        _scan_transporter_to_session(
            object(),
            reader_index=-1,
            reader_label="Remote Lab",
            close_callback=lambda: closed.append(True),
        )
    assert closed == [True]


def test_failed_remote_attach_releases_without_starting_heartbeat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common import card_backend
    from yggdrasim_common.gui_server.routes import remote_lab as routes

    device = RemoteLabDevice(
        id="site-a",
        name="Site A",
        rig_id="rig-a",
        agent_host="lab.example.test",
        agent_control_port=8700,
    )

    class FakeClient:
        timeout_seconds = 0.1

        def __init__(self) -> None:
            self.release_calls = 0
            self.heartbeat_calls = 0

        def create_session(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {
                "session_id": "remote-session",
                "session_token": "remote-token",
                "heartbeat_interval_seconds": 1,
                "stream": {"url": "https://relay.example.test/apdu"},
            }

        def heartbeat(self, *_args: Any) -> dict[str, Any]:
            self.heartbeat_calls += 1
            return {"status": "ok"}

        def release(self, *_args: Any) -> dict[str, Any]:
            self.release_calls += 1
            return {"status": "released"}

    class FailedConnection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            return

        def connect(self) -> None:
            raise ConnectionError("relay unavailable")

    client = FakeClient()
    monkeypatch.setattr(routes, "get_device", lambda _device_id: device)
    monkeypatch.setattr(routes, "_client_for_device", lambda *_args, **_kwargs: client)
    monkeypatch.setattr(card_backend, "RelayCardConnection", FailedConnection)

    with pytest.raises(ConnectionError, match="relay unavailable"):
        routes._open_remote_lab_scp03_session(
            device_id="site-a",
            user="tester",
            requested_ttl_seconds=120,
        )
    assert client.release_calls == 1
    assert client.heartbeat_calls == 0


REMOTE_LAB_HOWTO = (
    Path(__file__).resolve().parents[1]
    / "site-docs"
    / "how-to"
    / "run-a-remote-lab-agent.md"
)


def _documented_example_config() -> dict[str, Any]:
    """Return the first YAML block from the Remote Lab how-to page."""

    import re

    import yaml

    text = REMOTE_LAB_HOWTO.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^```yaml\n(?P<body>.*?)^```\s*$", text)
    assert match is not None, "how-to page no longer carries a YAML example"
    return yaml.safe_load(match.group("body"))


def test_documented_example_config_parses_and_matches_its_field_table() -> None:
    """The how-to page is the only Remote Lab config schema reference."""

    config = parse_config(_documented_example_config())

    assert config.agent.id == "lab-01"
    assert config.agent.bind_host == "127.0.0.1"
    assert config.agent.control_port == 8700
    assert config.defaults.reservation_timeout_seconds == 30
    assert config.defaults.heartbeat_timeout_seconds == 60
    assert config.defaults.max_session_seconds == 14_400

    roles = {token.id: token.role for token in config.access_tokens}
    assert roles == {"alice": "user", "lab-admin": "admin"}

    assert len(config.rigs) == 1
    rig = config.rigs[0]
    assert rig.id == "bench-a"
    assert rig.enabled is True
    assert rig.stream_proxy.external_port == 8801
    assert rig.upstream.url == "http://127.0.0.1:8642/apdu"
    # The page documents this default rather than spelling it in the example.
    assert rig.locks == ("rig:bench-a",)


def test_documented_example_config_rejects_a_port_collision() -> None:
    """The page claims the loader refuses an agent/rig port overlap."""

    payload = _documented_example_config()
    payload["rigs"][0]["stream_proxy"]["external_port"] = payload["agent"][
        "control_port"
    ]
    with pytest.raises(ValueError, match="conflicts with agent control port"):
        parse_config(payload)
