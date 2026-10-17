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
from yggdrasim_common.remote_lab.config import (
    RIG_KIND_CARD,
    RIG_KIND_MODEM,
    ConsumerConfig,
    ModemConfig,
    parse_config,
)
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


def _modem_rig(rig_id: str = "modem-a") -> dict:
    """A rig that offers a modem and expects the operator to supply the card."""
    return {
        "id": rig_id,
        "name": "Modem A",
        "kind": RIG_KIND_MODEM,
        "modem": {"label": "Test modem", "simtrace_vidpid": "1d50:60e3"},
        "consumer": {"enabled": True, "simtrace_reset": "usb-reset"},
        "locks": ["bench:shared"],
    }


def test_config_without_a_kind_key_still_parses_as_a_card_rig() -> None:
    """A config written before modem rigs existed must be unaffected."""
    payload = _base_config()
    parsed = parse_config(payload)
    for rig, raw in zip(parsed.rigs, payload["rigs"], strict=True):
        assert rig.kind == RIG_KIND_CARD
        assert rig.serves_card is True
        assert rig.consumes_card is False
        assert rig.modem == ModemConfig()
        assert rig.consumer == ConsumerConfig()
        assert rig.consumer.enabled is False
        # The fields that existed before are untouched by the new branch.
        assert rig.stream_proxy.external_port == raw["stream_proxy"]["external_port"]
        assert rig.upstream.url == raw["upstream"]["url"]


def test_modem_rig_needs_neither_a_stream_port_nor_an_upstream() -> None:
    payload = _base_config()
    payload["rigs"].append(_modem_rig())
    parsed = parse_config(payload)
    modem = parsed.rigs[-1]
    assert modem.kind == RIG_KIND_MODEM
    assert modem.consumes_card is True
    assert modem.serves_card is False
    assert modem.stream_proxy.external_port == 0
    assert modem.upstream.url == ""
    assert modem.modem.label == "Test modem"
    assert modem.consumer.enabled is True
    assert modem.consumer.simtrace_reset == "usb-reset"


def test_modem_rig_shares_a_lock_with_the_card_rig_on_the_same_bench() -> None:
    """Sharing a lock name is how one bench refuses two simultaneous sessions."""
    payload = _base_config()
    payload["rigs"][0]["locks"] = ["rig:rig-a", "bench:shared"]
    payload["rigs"].append(_modem_rig())
    parsed = parse_config(payload)
    card_locks = set(parsed.rigs[0].locks)
    modem_locks = set(parsed.rigs[-1].locks)
    assert "bench:shared" in card_locks & modem_locks


def test_config_rejects_an_upstream_on_a_modem_rig() -> None:
    payload = _base_config()
    rig = _modem_rig()
    rig["upstream"] = {"url": "http://127.0.0.1:1/apdu"}
    payload["rigs"].append(rig)
    with pytest.raises(ValueError, match="not valid for a modem rig"):
        parse_config(payload)


def test_config_rejects_modem_blocks_on_a_card_rig() -> None:
    payload = _base_config()
    payload["rigs"][0]["consumer"] = {"enabled": True}
    with pytest.raises(ValueError, match="only valid for a modem rig"):
        parse_config(payload)


def test_config_rejects_an_unknown_rig_kind() -> None:
    payload = _base_config()
    payload["rigs"][0]["kind"] = "reader"
    with pytest.raises(ValueError, match="kind must be one of"):
        parse_config(payload)


def test_config_rejects_an_unknown_simtrace_reset_mode() -> None:
    payload = _base_config()
    rig = _modem_rig()
    rig["consumer"]["simtrace_reset"] = "power-cycle"
    payload["rigs"].append(rig)
    with pytest.raises(ValueError, match="simtrace_reset must be one of"):
        parse_config(payload)


def test_modem_rig_still_validates_a_stream_port_it_declares() -> None:
    """Optional does not mean unchecked: a declared port keeps its checks."""
    payload = _base_config()
    rig = _modem_rig()
    rig["stream_proxy"] = {
        "bind_host": "127.0.0.1",
        "external_port": payload["rigs"][0]["stream_proxy"]["external_port"],
    }
    payload["rigs"].append(rig)
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


def test_an_unset_public_host_answers_each_caller_with_their_own_address() -> None:
    """One config, every route: the stream URL follows the caller.

    A pinned name that resolves to an address a caller cannot route is
    the worst case, because the control port answers while every stream
    URL points somewhere unreachable.
    """
    from yggdrasim_common.remote_lab.agent import RemoteLabAgentService

    payload = _base_config()
    payload["agent"].pop("public_host", None)
    config = parse_config(payload)
    service = RemoteLabAgentService(config)
    rig = config.rigs[0]
    port = rig.stream_proxy.external_port

    class _Handler:
        def __init__(self, host: str) -> None:
            self.headers = {"Host": host}

    by_name = service.relay_base_url(_Handler("rig.example.test:8700"), rig)
    by_address = service.relay_base_url(_Handler("198.51.100.7:8700"), rig)
    assert by_name == f"http://rig.example.test:{port}"
    assert by_address == f"http://198.51.100.7:{port}"


def test_a_pinned_public_host_still_wins_over_the_caller() -> None:
    from yggdrasim_common.remote_lab.agent import RemoteLabAgentService

    payload = _base_config()
    payload["agent"]["public_host"] = "pinned.example.test"
    config = parse_config(payload)
    service = RemoteLabAgentService(config)
    rig = config.rigs[0]

    class _Handler:
        headers = {"Host": "198.51.100.7:8700"}

    resolved = service.relay_base_url(_Handler(), rig)
    assert resolved.startswith("http://pinned.example.test:")


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


def test_agent_binds_no_stream_listener_for_a_modem_rig(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A modem rig serves no card, so it must not take a port."""
    from yggdrasim_common.remote_lab import agent as agent_module

    payload = _base_config()
    payload["rigs"].append(_modem_rig())
    config = parse_config(payload)
    bound: list[tuple[Any, ...]] = []

    class FakeServer:
        def __init__(self, *args: Any) -> None:
            bound.append(args)

        def serve_forever(self) -> None:
            return

        def shutdown(self) -> None:
            return

        def server_close(self) -> None:
            return

    class FakeThread:
        def __init__(self, *, target: Any, name: str, daemon: bool) -> None:
            self.name = name

        def start(self) -> None:
            return

        def join(self, timeout: float | None = None) -> None:
            return

    monkeypatch.setattr(agent_module, "_RelayServer", FakeServer)
    monkeypatch.setattr(agent_module, "_ControlServer", FakeServer)
    monkeypatch.setattr(agent_module.threading, "Thread", FakeThread)

    service = RemoteLabAgentService(config)
    service.start()
    try:
        card_rigs = [rig for rig in config.rigs if rig.serves_card is True]
        assert len(config.rigs) == len(card_rigs) + 1
        assert len(service._relay_servers) == len(card_rigs)
        # The control server is the one extra bind, never the modem rig.
        relay_binds = [args[0] for args in bound[: len(card_rigs)]]
        assert all(address[1] != 0 for address in relay_binds)
    finally:
        service.stop()


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


def test_a_name_that_will_not_resolve_says_to_check_the_network() -> None:
    """DNS failure and a refused port read alike and need opposite fixes."""
    import socket

    from yggdrasim_common.remote_lab.client import _unreachable_message

    message = _unreachable_message(
        socket.gaierror(-3, "Temporary failure in name resolution")
    )
    assert "did not resolve" in message
    assert "private network" in message
    assert "IP address" in message


def test_a_refused_port_says_the_host_answered() -> None:
    from yggdrasim_common.remote_lab.client import _unreachable_message

    message = _unreachable_message(ConnectionRefusedError(111, "Connection refused"))
    assert "refused" in message
    assert "nothing is" in message


def test_an_unclassified_reason_is_passed_through() -> None:
    from yggdrasim_common.remote_lab.client import _unreachable_message

    assert _unreachable_message("network is down") == "agent unreachable: network is down"


def test_remote_client_maps_timeout_to_client_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise TimeoutError("timed out")

    monkeypatch.setattr("urllib.request.urlopen", raise_timeout)
    with pytest.raises(RemoteLabClientError, match="timed out"):
        _json_request("https://lab.example.test/api/v1/info")


def _upstream_apdu(upstream: Any, lease_token: str) -> int:
    """POST an APDU straight at the upstream relay and return the status."""
    request = urllib_request.Request(
        upstream.apdu_url,
        data=json.dumps({"apdu": "00A40400"}).encode("utf-8"),
        method="POST",
    )
    request.add_header("Authorization", "Bearer upstream-token")
    request.add_header("Content-Type", "application/json")
    if len(lease_token) > 0:
        request.add_header("X-Card-Lease", lease_token)
    try:
        with urllib_request.urlopen(request, timeout=5) as response:
            return int(response.status)
    except urllib_error.HTTPError as exc:
        return int(exc.code)


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


def test_agent_holds_the_upstream_card_lease_for_the_session() -> None:
    """A reserved rig locks its card against consumers the agent cannot see."""
    upstream = HilBridgeApduRelayService(
        ApduRelayConfig(
            host="127.0.0.1",
            port=0,
            enabled=True,
            auth_token="upstream-token",
        ),
        exchange_callback=lambda apdu, *, session_id="": (
            bytes.fromhex("CAFE"),
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
        config = parse_config(
            _base_config(
                upstream_url=upstream.apdu_url, port_factory=_free_loopback_port
            )
        )
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

        # Before anyone reserves, a local tool reaches the card freely.
        assert _upstream_apdu(upstream, "") == 200

        grant = client.create_session("rig-a", user="alice")
        assert grant["card_lease"]["held"] is True

        # A tool on the rig host is now refused, naming the session.
        assert _upstream_apdu(upstream, "") == 409
        lease_state = upstream.lease.state()
        assert lease_state.held is True
        assert lease_state.holder == f"remote-lab:{grant['session_id']}"

        # The reserved operator still reaches the card through the agent,
        # because the agent presents the lease when it forwards.
        connection = RelayCardConnection(
            grant["stream"]["url"], auth_token=grant["session_token"]
        )
        connection.connect()
        data, sw1, sw2 = connection.transmit(bytes.fromhex("00A40400"))
        assert bytes(data) == bytes.fromhex("CAFE")
        assert (sw1, sw2) == (0x90, 0x00)
        connection.disconnect()

        client.release(grant["session_id"], grant["session_token"])
        assert upstream.lease.state().held is False
        assert _upstream_apdu(upstream, "") == 200
    finally:
        if service is not None:
            service.stop()
        if thread is not None:
            thread.join(timeout=2.0)
        upstream.stop()


def test_agent_refuses_a_reservation_when_the_card_is_already_leased() -> None:
    """The rig lock and the card lock are different locks."""
    upstream = HilBridgeApduRelayService(
        ApduRelayConfig(
            host="127.0.0.1",
            port=0,
            enabled=True,
            auth_token="upstream-token",
        ),
        exchange_callback=lambda apdu, *, session_id="": (b"", 0x90, 0x00),
        status_callback=lambda: {"reader": "fake upstream", "atr": "3B9F"},
    )
    try:
        upstream.start()
    except PermissionError as exc:
        pytest.skip(f"loopback sockets are unavailable in this sandbox: {exc}")
    service = None
    thread = None
    try:
        # Something else on the rig host took the card first.
        upstream.lease.claim(holder="hil:modem-a", ttl_seconds=300.0)

        config = parse_config(
            _base_config(
                upstream_url=upstream.apdu_url, port_factory=_free_loopback_port
            )
        )
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
        with pytest.raises(RemoteLabClientError) as refused:
            client.create_session("rig-a", user="alice")
        assert refused.value.status == 423
        assert refused.value.payload.get("error") == "card_leased"

        # The rig lock was handed back, so the rig is not stuck busy.
        assert client.status("rig-a")["status"] == "available"
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
    from yggdrasim_common import card_backend, remote_readers
    from yggdrasim_common.gui_server.routes import remote_lab as routes
    from yggdrasim_common.gui_server.sessions import get_manager

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

        def connect(self, protocol: Any = None) -> None:
            del protocol
            self.connected = True

        def disconnect(self) -> None:
            self.connected = False

        def getATR(self) -> list[int]:
            return [0x3B, 0x00]

    remote_readers.clear_remote_readers()
    client = FakeClient()
    monkeypatch.setattr(routes, "get_device", lambda _device_id: device)
    monkeypatch.setattr(routes, "_client_for_device", lambda *_args, **_kwargs: client)
    monkeypatch.setattr(card_backend, "RelayCardConnection", FakeConnection)

    result = routes._open_remote_lab_link(
        device_id="site-a",
        user="tester",
        requested_ttl_seconds=120,
    )
    try:
        assert client.create_ids == ["rig-a"]
        assert result["remote_lab"]["rig_id"] == "rig-a"
        assert result["reader_name"] == "Remote Lab: Site A"
        assert result["atr_hex"] == "3B00"
        # The link is the session; no card session was opened at connect.
        link = get_manager().get(result["session_id"])
        assert link.kind == routes.LINK_SESSION_KIND
        assert remote_readers.lookup_remote_reader("Remote Lab: Site A") is not None
    finally:
        # Closing twice must release the agent session exactly once.
        link.close()
        link.close()
        get_manager().close(result["session_id"])
        remote_readers.clear_remote_readers()
    assert client.release_calls == 1
    assert remote_readers.lookup_remote_reader("Remote Lab: Site A") is None
    deadline = time.time() + 3.0
    while time.time() < deadline and any(
        thread.name == "remote-lab-heartbeat-site-a" and thread.is_alive()
        for thread in threading.enumerate()
    ):
        time.sleep(0.05)
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
        routes._open_remote_lab_link(
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


# -- Remote reader registry ------------------------------------------------
#
# A Remote Lab card is reached over a relay, so it never appears in a PC/SC
# enumeration. These pin the contract that lets the scp03 workbench reopen
# such a card: the name resolves to the remote sentinel while the binding is
# registered, and goes back to raising once it is not.


@pytest.fixture()
def _clean_remote_readers():
    from yggdrasim_common.remote_readers import clear_remote_readers

    clear_remote_readers()
    yield
    clear_remote_readers()


def test_registered_remote_reader_resolves_to_the_sentinel_index(
    _clean_remote_readers,
) -> None:
    from yggdrasim_common.gui_server.actions.scp03 import _resolve_reader_binding
    from yggdrasim_common.remote_readers import (
        REMOTE_READER_INDEX,
        register_remote_reader,
    )

    name = "Remote Lab: bench rig"
    register_remote_reader(
        name,
        relay_url="http://127.0.0.1:8801/apdu",
        auth_token="session-token",
        origin="remote-lab",
        device_id="bench-a",
    )

    assert _resolve_reader_binding(name) == (REMOTE_READER_INDEX, name)


def test_unregistered_remote_reader_name_still_raises(_clean_remote_readers) -> None:
    from yggdrasim_common.gui_server.actions.scp03 import _resolve_reader_binding
    from yggdrasim_common.remote_readers import (
        register_remote_reader,
        unregister_remote_reader,
    )

    name = "Remote Lab: bench rig"
    register_remote_reader(name, relay_url="http://127.0.0.1:8801/apdu")
    assert unregister_remote_reader(name) is True

    # Releasing the session must restore the old behaviour rather than
    # leaving a name bound to a relay whose session token is gone. The
    # PC/SC list is stubbed: a Windows runner has no Smart Card service,
    # and pyscard raises there before any name is compared.
    with mock.patch("smartcard.System.readers", return_value=[]):
        with pytest.raises(RuntimeError, match="reader not found"):
            _resolve_reader_binding(name)


def test_remote_binding_never_exposes_its_bearer_token(_clean_remote_readers) -> None:
    from yggdrasim_common.remote_readers import register_remote_reader

    binding = register_remote_reader(
        "Remote Lab: bench rig",
        relay_url="http://127.0.0.1:8801/apdu",
        auth_token="session-token",
    )
    payload = binding.redacted_dict()

    assert payload["token_present"] is True
    assert "session-token" not in json.dumps(payload)


def test_remote_reader_registry_is_bounded(_clean_remote_readers) -> None:
    from yggdrasim_common.remote_readers import (
        MAX_REMOTE_READERS,
        RemoteReaderError,
        register_remote_reader,
    )

    for index in range(MAX_REMOTE_READERS):
        register_remote_reader(
            f"Remote Lab: rig {index}", relay_url="http://127.0.0.1:8801/apdu"
        )
    with pytest.raises(RemoteReaderError, match="too many remote readers"):
        register_remote_reader(
            "Remote Lab: one too many", relay_url="http://127.0.0.1:8801/apdu"
        )


def test_named_remote_reader_outranks_ambient_relay_configuration(
    _clean_remote_readers, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-request reader wins over the process-wide relay env var."""

    from yggdrasim_common import card_backend
    from yggdrasim_common.remote_readers import register_remote_reader

    name = "Remote Lab: bench rig"
    register_remote_reader(name, relay_url="http://127.0.0.1:8801/apdu")
    monkeypatch.setenv("YGGDRASIM_CARD_RELAY_URL", "http://127.0.0.1:9999/apdu")

    opened: list[str] = []

    class _StubRelay:
        def __init__(self, url: str, auth_token: str = "") -> None:
            opened.append(url)

        def connect(self, protocol: Any = None) -> None:
            return None

    monkeypatch.setattr(card_backend, "RelayCardConnection", _StubRelay)
    card_backend.create_card_connection(reader_index=-1, reader_name=name)

    assert opened == ["http://127.0.0.1:8801/apdu"]


def test_named_remote_reader_failure_never_falls_back_to_a_local_reader(
    _clean_remote_readers, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dead relay must raise, not silently bind the operator's own card."""

    from yggdrasim_common import card_backend
    from yggdrasim_common.remote_readers import register_remote_reader

    name = "Remote Lab: bench rig"
    register_remote_reader(name, relay_url="http://127.0.0.1:8801/apdu")

    class _DeadRelay:
        def __init__(self, url: str, auth_token: str = "") -> None:
            pass

        def connect(self, protocol: Any = None) -> None:
            raise RuntimeError("relay unreachable")

    def _unexpected_readers():  # pragma: no cover - must never be reached
        raise AssertionError("local PC/SC enumeration must not be consulted")

    monkeypatch.setattr(card_backend, "RelayCardConnection", _DeadRelay)
    with pytest.raises(RuntimeError, match="relay unreachable"):
        card_backend.create_card_connection(
            reader_index=-1, reader_name=name, readers_func=_unexpected_readers
        )


def test_scp03_opens_a_relay_transporter_for_a_registered_remote_reader(
    _clean_remote_readers, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The workbench path resolves the name and connects to that rig's relay.

    This is the wiring the ``reader not found`` failure used to break: the
    scan re-resolves the reader name on every call, so the resolver and the
    connection factory have to agree about a reader with no PC/SC ordinal.
    """

    from yggdrasim_common import card_backend
    from yggdrasim_common.gui_server.actions.scp03 import (
        _open_card_transporter,
        _resolve_reader_binding,
    )
    from yggdrasim_common.remote_readers import (
        REMOTE_READER_INDEX,
        register_remote_reader,
    )

    name = "Remote Lab: bench rig"
    register_remote_reader(
        name, relay_url="http://127.0.0.1:8801/apdu", auth_token="session-token"
    )

    seen: dict[str, str] = {}

    class _StubRelay:
        def __init__(self, url: str, auth_token: str = "") -> None:
            seen["url"] = url
            seen["token"] = auth_token

        def connect(self, protocol: Any = None) -> None:
            return None

    monkeypatch.setattr(card_backend, "RelayCardConnection", _StubRelay)

    reader_index, resolved_name = _resolve_reader_binding(name)
    assert (reader_index, resolved_name) == (REMOTE_READER_INDEX, name)

    transporter = _open_card_transporter(reader_index, resolved_name)

    assert seen == {"url": "http://127.0.0.1:8801/apdu", "token": "session-token"}
    assert transporter.connection is not None


def _lab_session_manager(kind: str = "modem"):
    """A one-rig manager on a clock the test drives."""
    from yggdrasim_common.remote_lab.config import RemoteLabDefaults, RigConfig
    from yggdrasim_common.remote_lab.sessions import LabSessionManager

    now = {"t": 1000.0}
    rig = RigConfig(id="rig-a", name="Rig A", kind=kind, locks=("bench-a",))
    defaults = RemoteLabDefaults()
    manager = LabSessionManager([rig], defaults, clock=lambda: now["t"])
    return manager, rig, defaults, now


def test_a_consuming_rig_leaves_the_reservation_window() -> None:
    """A modem rig serves no APDU stream of its own.

    Nothing calls mark_stream_use for it, so the session stayed
    "reserved" and the reservation timeout reaped it seconds after it was
    granted -- mid-stream, while its heartbeats were still succeeding and
    reporting an hour left.
    """
    manager, rig, defaults, now = _lab_session_manager("modem")
    session = manager.create_session(rig.id, requested_ttl_seconds=3600)
    assert session.state == "reserved"

    manager.mark_consumer_started(session)
    assert session.state == "busy"

    # Past the reservation window, well short of the session TTL.
    now["t"] += defaults.reservation_timeout_seconds + 5
    assert manager.expire_stale() == []
    assert manager.get(session.id) is not None


def test_a_reservation_nobody_uses_is_still_reaped() -> None:
    """The window still has to close on a session that never started."""
    manager, rig, defaults, now = _lab_session_manager("modem")
    session = manager.create_session(rig.id, requested_ttl_seconds=3600)
    now["t"] += defaults.reservation_timeout_seconds + 5
    assert [s.id for s in manager.expire_stale()] == [session.id]


def test_a_session_reaped_by_a_read_path_still_reaches_teardown() -> None:
    """expire_stale_locked runs on six read paths that discard its result.

    Whichever one noticed an expiry first popped the session and freed the
    rig lock, and the cleanup loop -- the only caller that runs teardown --
    then saw nothing to do. The consumer's supervisor kept running with no
    session behind it, or a card rig's upstream lease stayed held.
    """
    manager, rig, defaults, now = _lab_session_manager("modem")
    session = manager.create_session(rig.id, requested_ttl_seconds=3600)
    now["t"] += defaults.reservation_timeout_seconds + 5

    # A status poll from the GUI lands before the cleanup tick and reaps it.
    state, _held = manager.status_for_rig(rig.id)
    assert state == "available"
    assert manager.locks() == {}

    # The cleanup loop must still be handed the session to tear down.
    assert [s.id for s in manager.expire_stale()] == [session.id]
    # And only once.
    assert manager.expire_stale() == []


def test_the_offer_card_path_leaves_the_reservation_window() -> None:
    """Exercise the handler the GUI's offer-card route actually reaches.

    The GUI posts to the agent's ``/api/v1/rigs/<id>/sessions`` with a
    card offer, which lands in ``create_session_payload``. Calling
    ``mark_consumer_started`` directly proves the manager, not that this
    path reaches it -- and a modem rig that stays ``reserved`` is reaped
    by the reservation timeout seconds after it is granted, mid-stream.
    """
    from unittest import mock

    from yggdrasim_common.remote_lab.agent import RemoteLabAgentService

    payload = _base_config()
    payload["rigs"] = [
        {
            "id": "modem-a",
            "name": "Modem A",
            "kind": "modem",
            "locks": ["bench:modem-a"],
            "modem": {"at_device": "/dev/ttyUSB2"},
            "consumer": {"enabled": True},
        }
    ]
    config = parse_config(payload)
    service = RemoteLabAgentService(config)
    rig = config.rigs[0]

    class _Handler:
        headers = {"Host": "127.0.0.1:8700"}

    body = {
        "requested_ttl_seconds": 3600,
        "card_offer": {
            "url": "http://127.0.0.1:8908/apdu",
            "token": "operator-token",
        },
    }
    with mock.patch.object(service.consumers, "start") as start:
        with mock.patch.object(service, "validate_card_offer"):
            result = service.create_session_payload(_Handler(), rig, body)

    assert start.call_count == 1
    assert result["status"] == "busy", (
        "the session must leave the reservation window when the consumer "
        "starts, or the reaper takes it ~30s in while heartbeats succeed"
    )
    session = service.sessions.get(result["session_id"])
    assert session is not None and session.state == "busy"


def test_a_late_teardown_does_not_stop_the_rigs_new_consumer() -> None:
    """Teardown runs a tick after the session was reaped.

    Half of it is session-scoped (the card lease) and safe whoever holds
    the rig now; the other half stops the rig's consumer and would end a
    newcomer's session. Dropping the whole queued entry instead loses the
    safe half too, and loses it exactly in the window where the newcomer
    holds the rig but has not yet taken over the consumer.
    """
    from unittest import mock

    from yggdrasim_common.remote_lab.agent import RemoteLabAgentService

    payload = _base_config()
    payload["rigs"] = [
        {
            "id": "modem-a",
            "name": "Modem A",
            "kind": "modem",
            "locks": ["bench:modem-a"],
            "modem": {"at_device": "/dev/ttyUSB2"},
            "consumer": {"enabled": True},
        }
    ]
    service = RemoteLabAgentService(parse_config(payload))
    rig = service.config.rigs[0]

    reaped = service.sessions.create_session(rig.id, requested_ttl_seconds=3600)
    service.sessions.release(reaped.id, force=True)

    # Nobody holds the rig: both halves run.
    with mock.patch.object(service, "release_card_lease") as lease:
        with mock.patch.object(service.consumers, "stop") as stop:
            service.release_session_resources(reaped)
    assert lease.call_count == 1
    assert stop.call_count == 1

    # A newcomer holds the rig: the lease still goes back, the consumer
    # stop is withheld so the newcomer keeps streaming.
    newcomer = service.sessions.create_session(rig.id, requested_ttl_seconds=3600)
    assert newcomer.id != reaped.id
    with mock.patch.object(service, "release_card_lease") as lease:
        with mock.patch.object(service.consumers, "stop") as stop:
            service.release_session_resources(reaped)
    assert lease.call_count == 1, "the session's own lease must always go back"
    assert stop.call_count == 0, "stopping the rig would end the newcomer's session"


def test_every_reaped_session_reaches_the_cleanup_loop() -> None:
    """The queue must not filter: the caller decides what teardown applies."""
    manager, rig, defaults, now = _lab_session_manager("modem")
    session = manager.create_session(rig.id, requested_ttl_seconds=3600)
    now["t"] += defaults.reservation_timeout_seconds + 5

    # A status poll reaps it, then a newcomer takes the rig.
    manager.status_for_rig(rig.id)
    replacement = manager.create_session(rig.id, requested_ttl_seconds=3600)

    drained = [s.id for s in manager.expire_stale()]
    assert session.id in drained, "the reaped session still needs its lease released"
    assert manager.active_session_for_rig(rig.id) is not None
    assert manager.active_session_for_rig(rig.id).id == replacement.id
