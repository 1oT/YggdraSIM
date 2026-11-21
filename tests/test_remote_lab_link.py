# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The Remote Lab link: a module-neutral owner of the rig session.

Connect used to open an SCP03 session that scanned the card and owned the
relay's heartbeat and release. Any other module (eSIM management, the local
SM-DP+, SCP80) reaching the same rig had no path to it, and closing that one
session tore the rig down for everyone. The link replaces it: connect
reserves the rig, publishes the reader name and reads the ATR; every module
opens its own card channel through the name; the link alone releases.

Fakes stand in for the agent client and the relay connection, following
``tests/test_remote_lab.py``. No network, no card.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from yggdrasim_common import remote_readers
from yggdrasim_common.remote_lab.client import RemoteLabClientError
from yggdrasim_common.remote_lab.registry import RemoteLabDevice

pytest.importorskip("fastapi")

from yggdrasim_common.gui_server.routes import remote_lab as routes  # noqa: E402
from yggdrasim_common.gui_server.sessions import get_manager  # noqa: E402


DEVICE = RemoteLabDevice(
    id="site-a",
    name="Site A",
    rig_id="rig-a",
    agent_host="lab.example.test",
    agent_control_port=8700,
)
READER = "Remote Lab: Site A"


class FakeClient:
    timeout_seconds = 0.1

    def __init__(self, *, heartbeat_error: Exception | None = None) -> None:
        self.create_ids: list[str] = []
        self.release_calls = 0
        self.heartbeat_calls = 0
        self.heartbeat_error = heartbeat_error

    def create_session(self, rig_id: str, **_kwargs: Any) -> dict[str, Any]:
        self.create_ids.append(rig_id)
        return {
            "session_id": "remote-session",
            "session_token": "remote-token",
            "heartbeat_interval_seconds": 1,
            "expires_at": "2026-09-15T18:00:00Z",
            "stream": {"url": "https://relay.example.test/apdu"},
        }

    def heartbeat(self, *_args: Any) -> dict[str, Any]:
        self.heartbeat_calls += 1
        if self.heartbeat_error is not None:
            raise self.heartbeat_error
        return {"status": "ok"}

    def release(self, *_args: Any) -> dict[str, Any]:
        self.release_calls += 1
        return {"status": "released"}


class FakeRelay:
    """Enough of RelayCardConnection for the link's ATR probe and a channel."""

    instances: list["FakeRelay"] = []

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.connected = False
        self.disconnects = 0
        self.sent: list[bytes] = []
        FakeRelay.instances.append(self)

    def connect(self, protocol: Any = None) -> None:
        del protocol
        self.connected = True

    def disconnect(self) -> None:
        self.connected = False
        self.disconnects += 1

    def getATR(self) -> list[int]:  # noqa: N802 -- pyscard API name
        return [0x3B, 0x9F, 0x96]

    def transmit(self, apdu: Any) -> tuple[list[int], int, int]:
        self.sent.append(bytes(apdu))
        return [0x01, 0x02], 0x90, 0x00


@pytest.fixture()
def linked(monkeypatch: pytest.MonkeyPatch):
    """Open a link against fakes; close it and clear the registry afterwards."""
    from yggdrasim_common import card_backend

    remote_readers.clear_remote_readers()
    FakeRelay.instances.clear()
    client = FakeClient()
    monkeypatch.setattr(routes, "get_device", lambda _device_id: DEVICE)
    monkeypatch.setattr(routes, "_client_for_device", lambda *_a, **_k: client)
    monkeypatch.setattr(card_backend, "RelayCardConnection", FakeRelay)
    result = routes._open_remote_lab_link(device_id="site-a", user="tester", requested_ttl_seconds=120)
    yield client, result
    get_manager().close(result["session_id"])
    remote_readers.clear_remote_readers()
    _wait_for_no_heartbeat()


def _wait_for_no_heartbeat(timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not any(t.name == "remote-lab-heartbeat-site-a" and t.is_alive() for t in threading.enumerate()):
            return
        time.sleep(0.05)


# --- what connect now does, and does not do --------------------------------


def test_connect_reserves_publishes_and_reads_the_atr_without_a_scan(linked) -> None:
    client, result = linked
    assert client.create_ids == ["rig-a"]
    assert result["kind"] == routes.LINK_SESSION_KIND
    assert result["reader_name"] == READER
    assert result["reader_index"] == remote_readers.REMOTE_READER_INDEX
    assert result["atr_hex"] == "3B9F96"
    assert result["remote_lab"]["rig_id"] == "rig-a"
    # No tree: the card was not scanned. Modules do that on demand.
    assert "tree" not in result
    # The ATR probe was one connection, used once and not kept open.
    assert len(FakeRelay.instances) == 1


def test_connect_registers_a_binding_carrying_the_link_identity(linked) -> None:
    binding = remote_readers.lookup_remote_reader(READER)
    assert binding is not None
    assert binding.device_id == "site-a"
    assert binding.rig_id == "rig-a"
    assert binding.remote_session_id == "remote-session"
    assert binding.session_metadata()["remote_lab_device_id"] == "site-a"


def test_link_is_protected_from_the_idle_sweep(linked) -> None:
    _client, result = linked
    session = get_manager().get(result["session_id"])
    assert session.kind == routes.LINK_SESSION_KIND
    assert session.is_auto_close_protected()
    assert session.metadata["remote_lab_link"] is True
    assert session.metadata["reader_name"] == READER
    assert session.metadata["atr_hex"] == "3B9F96"


def test_sessions_route_lists_the_link_and_nothing_else(linked) -> None:
    _client, result = linked
    # A module session opened through the binding is the link's child and
    # must not appear as a second rig.
    child = get_manager().open(
        kind="scp03",
        handle={},
        close=lambda: None,
        metadata={"remote_lab": True, "remote_lab_device_id": "site-a", "reader_name": READER},
    )
    try:
        rows = routes.active_sessions()["sessions"]
        assert [row["session_id"] for row in rows] == [result["session_id"]]
        assert rows[0]["kind"] == routes.LINK_SESSION_KIND
        assert rows[0]["reader_name"] == READER
        assert rows[0]["atr_hex"] == "3B9F96"
    finally:
        get_manager().close(child.id)


# --- release ---------------------------------------------------------------


def test_release_closes_the_children_then_the_link_and_drops_the_binding(linked) -> None:
    client, result = linked
    closed: list[str] = []
    child = get_manager().open(
        kind="scp03",
        handle={},
        close=lambda: closed.append("child"),
        metadata={"remote_lab": True, "remote_lab_device_id": "site-a", "reader_name": READER},
    )
    out = routes.release_device_session("site-a", routes.ReleaseRequest(session_id=result["session_id"]))
    assert out["released"] == result["session_id"]
    assert out["closed_sessions"] == 1
    assert closed == ["child"]
    assert not get_manager().has(child.id)
    assert not get_manager().has(result["session_id"])
    assert remote_readers.lookup_remote_reader(READER) is None
    assert client.release_calls == 1
    _wait_for_no_heartbeat()
    assert not any(t.name == "remote-lab-heartbeat-site-a" and t.is_alive() for t in threading.enumerate())


def test_release_accepts_a_child_session_id_or_none(linked) -> None:
    _client, result = linked
    child = get_manager().open(
        kind="scp03",
        handle={},
        close=lambda: None,
        metadata={"remote_lab": True, "remote_lab_device_id": "site-a", "reader_name": READER},
    )
    out = routes.release_device_session("site-a", routes.ReleaseRequest(session_id=child.id))
    assert out["released"] == result["session_id"]
    assert not get_manager().has(result["session_id"])


def test_release_with_no_link_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        routes.release_device_session("nobody", routes.ReleaseRequest())
    assert caught.value.status_code == 404


def test_release_is_idempotent_on_the_agent(linked) -> None:
    client, result = linked
    manager = get_manager()
    session = manager.get(result["session_id"])
    session.close()  # direct close callback, as the manager would call it
    session.close()
    assert client.release_calls == 1


# --- the heartbeat -------------------------------------------------------


def test_a_gone_session_on_the_agent_tears_the_link_down(monkeypatch: pytest.MonkeyPatch) -> None:
    from yggdrasim_common import card_backend

    remote_readers.clear_remote_readers()
    client = FakeClient(heartbeat_error=RemoteLabClientError("gone", status=404))
    monkeypatch.setattr(routes, "get_device", lambda _device_id: DEVICE)
    monkeypatch.setattr(routes, "_client_for_device", lambda *_a, **_k: client)
    monkeypatch.setattr(card_backend, "RelayCardConnection", FakeRelay)
    result = routes._open_remote_lab_link(device_id="site-a", user="tester", requested_ttl_seconds=120)
    link_id = result["session_id"]
    try:
        deadline = time.time() + 4.0
        while time.time() < deadline and get_manager().has(link_id):
            time.sleep(0.05)
        assert not get_manager().has(link_id), "link survived a 404 heartbeat"
        assert remote_readers.lookup_remote_reader(READER) is None
        assert client.release_calls == 1
    finally:
        get_manager().close(link_id)
        remote_readers.clear_remote_readers()
        _wait_for_no_heartbeat()


def test_a_transient_heartbeat_failure_keeps_the_link(monkeypatch: pytest.MonkeyPatch) -> None:
    from yggdrasim_common import card_backend

    remote_readers.clear_remote_readers()
    client = FakeClient(heartbeat_error=RemoteLabClientError("flap", status=503))
    monkeypatch.setattr(routes, "get_device", lambda _device_id: DEVICE)
    monkeypatch.setattr(routes, "_client_for_device", lambda *_a, **_k: client)
    monkeypatch.setattr(card_backend, "RelayCardConnection", FakeRelay)
    result = routes._open_remote_lab_link(device_id="site-a", user="tester", requested_ttl_seconds=120)
    link_id = result["session_id"]
    try:
        deadline = time.time() + 2.5
        while time.time() < deadline and client.heartbeat_calls < 2:
            time.sleep(0.05)
        assert client.heartbeat_calls >= 2
        assert get_manager().has(link_id)
        assert remote_readers.lookup_remote_reader(READER) is not None
    finally:
        get_manager().close(link_id)
        remote_readers.clear_remote_readers()
        _wait_for_no_heartbeat()


def test_failed_atr_probe_releases_without_a_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    from yggdrasim_common import card_backend

    remote_readers.clear_remote_readers()

    class DeadRelay:
        def __init__(self, *_a: Any, **_k: Any) -> None:
            return

        def connect(self, protocol: Any = None) -> None:
            raise ConnectionError("relay unavailable")

    client = FakeClient()
    monkeypatch.setattr(routes, "get_device", lambda _device_id: DEVICE)
    monkeypatch.setattr(routes, "_client_for_device", lambda *_a, **_k: client)
    monkeypatch.setattr(card_backend, "RelayCardConnection", DeadRelay)
    with pytest.raises(ConnectionError, match="relay unavailable"):
        routes._open_remote_lab_link(device_id="site-a", user="tester", requested_ttl_seconds=120)
    assert client.release_calls == 1
    assert client.heartbeat_calls == 0
    assert remote_readers.lookup_remote_reader(READER) is None


# --- the reader row sees the link ------------------------------------------


def test_reader_row_shows_the_link_atr_before_any_module_session(linked) -> None:
    from yggdrasim_common.gui_server.routes import live

    atrs = live._session_atr_by_reader_name()
    assert atrs[READER] == "3B9F96"
    rows = live._registered_remote_reader_rows(atrs)
    assert [r.name for r in rows] == [READER]
    assert rows[0].atr_hex == "3B9F96"
    assert rows[0].session_backed is True
    assert "card present" in rows[0].status


# --- modules open their channels through the name --------------------------


def test_every_module_resolver_maps_the_name_to_the_remote_index(linked) -> None:
    from yggdrasim_common.gui_server.actions import scp03, scp11_live, scp11_local, scp80

    idx = remote_readers.REMOTE_READER_INDEX
    assert scp03._resolve_reader_binding(READER) == (idx, READER)
    assert scp11_local._resolve_reader_index(READER) == idx
    assert scp11_live._resolve_reader_index(READER) == idx

    class Cfg:
        data: dict[str, str] = {}

    cfg = Cfg()
    assert scp80._apply_reader_choice(READER, None, cfg) == idx
    assert cfg.data["reader_idx"] == str(idx)
    assert cfg.data["reader_name"] == READER


def test_relay_channel_drives_the_card_through_the_binding(linked, monkeypatch: pytest.MonkeyPatch) -> None:
    from SCP11.transport import RemoteApduChannel
    from yggdrasim_common import card_backend

    monkeypatch.delenv("YGGDRASIM_CARD_BACKEND", raising=False)
    monkeypatch.setattr(card_backend, "is_simulated_card_backend", lambda: False)
    before = len(FakeRelay.instances)
    channel = RemoteApduChannel(READER, quiet_apdu_logging=True)
    relay = FakeRelay.instances[-1]
    assert len(FakeRelay.instances) == before + 1
    assert channel.is_connected()
    data, sw1, sw2 = channel.exchange(bytes.fromhex("00A4040000"), "SELECT")
    assert (bytes(data), sw1, sw2) == (b"\x01\x02", 0x90, 0x00)
    assert relay.sent == [bytes.fromhex("00A4040000")]
    # Transactions are no-ops: the relay is serialised by the agent's lock.
    channel.begin_transaction()
    channel.end_transaction()
    channel.disconnect()
    assert not channel.is_connected()
    assert relay.disconnects == 1
    # Disconnecting a channel never released the rig: the link still stands.
    assert remote_readers.lookup_remote_reader(READER) is not None


def test_relay_channel_refuses_a_name_with_no_link(monkeypatch: pytest.MonkeyPatch) -> None:
    from SCP11.transport import RemoteApduChannel
    from yggdrasim_common import card_backend

    remote_readers.clear_remote_readers()
    monkeypatch.delenv("YGGDRASIM_CARD_BACKEND", raising=False)
    monkeypatch.setattr(card_backend, "is_simulated_card_backend", lambda: False)
    monkeypatch.setattr(card_backend, "RelayCardConnection", FakeRelay)
    with pytest.raises(Exception):
        RemoteApduChannel("Remote Lab: nobody", quiet_apdu_logging=True)


def test_local_smdp_builds_the_relay_channel_for_a_remote_reader(linked, monkeypatch: pytest.MonkeyPatch) -> None:
    from SCP11.transport import RemoteApduChannel
    from yggdrasim_common import card_backend
    from yggdrasim_common.gui_server.actions import scp11_local

    monkeypatch.delenv("YGGDRASIM_CARD_BACKEND", raising=False)
    monkeypatch.setattr(card_backend, "is_simulated_card_backend", lambda: False)
    session, channel = scp11_local._build_session(remote_readers.REMOTE_READER_INDEX, READER)
    try:
        assert isinstance(channel, RemoteApduChannel)
        assert session is not None
    finally:
        channel.disconnect()


def test_scp03_scan_through_the_binding_carries_the_link_identity(linked, monkeypatch: pytest.MonkeyPatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    seen: dict[str, Any] = {}

    def fake_open(reader_index: int, reader_name: str = "") -> object:
        seen["open"] = (reader_index, reader_name)
        return object()

    def fake_scan(_transporter: Any, **kwargs: Any) -> dict[str, Any]:
        seen["metadata_extra"] = kwargs.get("metadata_extra")
        return {"session_id": "child", "reader_name": kwargs["reader_label"], "atr_hex": "3B9F96"}

    monkeypatch.setattr(scp03, "_open_card_transporter", fake_open)
    monkeypatch.setattr(scp03, "_scan_transporter_to_session", fake_scan)
    result = scp03._dispatch_scan(None, reader=READER)
    assert seen["open"] == (remote_readers.REMOTE_READER_INDEX, READER)
    assert seen["metadata_extra"]["remote_lab_device_id"] == "site-a"
    assert seen["metadata_extra"]["remote_lab"] is True
    assert result["remote_lab"]["device_id"] == "site-a"
    assert result["remote_lab"]["remote_session_id"] == "remote-session"
