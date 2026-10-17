# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for a rig that consumes a card instead of serving one.

A modem rig reverses the direction: the operator holds the card and the
rig's modem drives it. Reserving one therefore starts a process on the
rig, which is the largest thing a reservation has ever been allowed to
do, so the tests here are weighted toward what bounds that.
"""

from __future__ import annotations

import threading

import pytest

from Tools.HilBridge.apdu_relay import ApduRelayConfig, HilBridgeApduRelayService
from yggdrasim_common.remote_lab.agent import RemoteLabAgentService
from yggdrasim_common.remote_lab.client import (
    RemoteLabAgentClient,
    RemoteLabClientError,
)
from yggdrasim_common.remote_lab.config import RIG_KIND_MODEM, parse_config
from yggdrasim_common.remote_lab.consumer import (
    CardOffer,
    CardOfferError,
    ConsumerManager,
    ConsumerProcess,
)
from yggdrasim_common.remote_lab.security import hash_token

from tests.test_remote_lab import _base_config, _free_loopback_port


class _FakeChild:
    def __init__(self, command, **kwargs) -> None:
        self.command = list(command)
        self.kwargs = dict(kwargs)
        self.pid = 4242
        self.terminated = False
        self._returncode = None

    def poll(self):
        return self._returncode

    def terminate(self) -> None:
        self.terminated = True
        self._returncode = 0

    def kill(self) -> None:
        self.terminated = True
        self._returncode = -9

    def wait(self, timeout=None):
        self._returncode = 0
        return 0


def test_offer_requires_a_url() -> None:
    with pytest.raises(CardOfferError, match="url is required"):
        CardOffer.from_payload({})


def test_offer_rejects_a_non_http_scheme() -> None:
    with pytest.raises(CardOfferError, match="http or https"):
        CardOffer.from_payload({"url": "file:///etc/passwd"})


def test_offer_rejects_embedded_credentials() -> None:
    with pytest.raises(CardOfferError, match="no credentials"):
        CardOffer.from_payload({"url": "http://user:pass@127.0.0.1:8642/apdu"})


def test_offer_rejects_a_query_string() -> None:
    with pytest.raises(CardOfferError, match="no query string"):
        CardOffer.from_payload({"url": "http://127.0.0.1:8642/apdu?x=1"})


def test_offer_normalises_a_bare_base_url() -> None:
    offer = CardOffer.from_payload({"url": "http://127.0.0.1:8642"})
    assert offer.url == "http://127.0.0.1:8642/apdu"


def test_offer_never_renders_its_token() -> None:
    offer = CardOffer.from_payload(
        {"url": "http://127.0.0.1:8642/apdu", "token": "secret-token"}
    )
    assert "secret-token" not in str(offer.redacted())


def _modem_rig_config(**consumer_overrides):
    payload = _base_config()
    rig = {
        "id": "modem-a",
        "name": "Modem A",
        "kind": RIG_KIND_MODEM,
        "modem": {"label": "Test modem", "simtrace_vidpid": "1d50:60e3"},
        "consumer": {"enabled": True, **consumer_overrides},
        "locks": ["bench:shared"],
    }
    payload["rigs"].append(rig)
    return parse_config(payload)


def test_consumer_command_comes_from_config_not_from_the_request() -> None:
    """A reservation picks a configured rig; it does not choose a command."""
    config = _modem_rig_config(supervisor="my-supervisor", bridge_port=9998)
    rig = config.rigs[-1]
    offer = CardOffer.from_payload(
        {"url": "http://127.0.0.1:8642/apdu", "token": "secret-token"}
    )
    process = ConsumerProcess(rig=rig, offer=offer, popen_factory=_FakeChild)
    command = process.build_command()
    assert command[0].endswith("my-supervisor")
    assert "--remote-card-url" in command
    assert "http://127.0.0.1:8642/apdu" in command
    assert "9998" in command
    assert "1d50:60e3" in command


def test_the_offered_token_never_reaches_a_command_line(tmp_path, monkeypatch) -> None:
    """A command line is readable by every process on the host."""
    monkeypatch.setattr(
        "yggdrasim_common.remote_lab.consumer.runtime_path",
        lambda *parts: str(tmp_path.joinpath(*parts[1:])),
    )
    config = _modem_rig_config()
    rig = config.rigs[-1]
    offer = CardOffer.from_payload(
        {"url": "http://127.0.0.1:8642/apdu", "token": "secret-token"}
    )
    process = ConsumerProcess(rig=rig, offer=offer, popen_factory=_FakeChild)
    process.start()
    try:
        command = process._child.command
        assert "secret-token" not in " ".join(command)
        assert "--remote-card-token-file" in command
        token_path = command[command.index("--remote-card-token-file") + 1]
        assert tmp_path.joinpath("remote_lab_card_modem-a.token").exists()
        with open(token_path, "r", encoding="utf-8") as handle:
            assert handle.read().strip() == "secret-token"
    finally:
        process.stop()
    # Stopping removes the staged token rather than leaving it on disk.
    assert tmp_path.joinpath("remote_lab_card_modem-a.token").exists() is False


def test_a_rig_that_has_not_opted_in_refuses_to_start_anything() -> None:
    config = _modem_rig_config(enabled=False)
    rig = config.rigs[-1]
    offer = CardOffer.from_payload({"url": "http://127.0.0.1:8642/apdu"})
    process = ConsumerProcess(rig=rig, offer=offer, popen_factory=_FakeChild)
    with pytest.raises(CardOfferError, match="not configured to consume"):
        process.start()


def test_starting_a_second_consumer_replaces_the_first() -> None:
    config = _modem_rig_config()
    rig = config.rigs[-1]
    manager = ConsumerManager(popen_factory=_FakeChild)
    offer = CardOffer.from_payload({"url": "http://127.0.0.1:8642/apdu"})
    first = manager.start(rig, offer)
    manager.start(rig, offer)
    assert first.is_running() is False
    manager.stop_all()


def _serve(service: RemoteLabAgentService) -> threading.Thread:
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    return thread


class _ModemRigHarness:
    """An agent publishing one modem rig, with a stub card to offer it."""

    def __init__(self) -> None:
        self.card = HilBridgeApduRelayService(
            ApduRelayConfig(
                host="127.0.0.1", port=0, enabled=True, auth_token="card-token"
            ),
            exchange_callback=lambda apdu, *, session_id="": (b"", 0x90, 0x00),
            status_callback=lambda: {"reader": "operator reader", "atr": "3B9F"},
        )
        self.card.start()
        payload = _base_config(port_factory=_free_loopback_port)
        payload["rigs"].append(
            {
                "id": "modem-a",
                "name": "Modem A",
                "kind": RIG_KIND_MODEM,
                "modem": {"label": "Test modem"},
                "consumer": {"enabled": True},
                "locks": ["bench:shared"],
            }
        )
        self.config = parse_config(payload)
        self.service = RemoteLabAgentService(self.config)
        self.service.consumers = ConsumerManager(popen_factory=_FakeChild)
        self.service.start()
        self.thread = _serve(self.service)
        self.client = RemoteLabAgentClient(
            f"http://127.0.0.1:{self.config.agent.control_port}", "team-token"
        )

    def close(self) -> None:
        self.service.stop()
        self.thread.join(timeout=2.0)
        self.card.stop()


@pytest.fixture
def modem_rig():
    try:
        harness = _ModemRigHarness()
    except PermissionError as exc:
        pytest.skip(f"loopback sockets are unavailable in this sandbox: {exc}")
    try:
        yield harness
    finally:
        harness.close()


def test_a_modem_rig_advertises_that_it_needs_a_card(modem_rig) -> None:
    status = modem_rig.client.status("modem-a")
    assert status["kind"] == RIG_KIND_MODEM
    assert status["requires_card_offer"] is True
    assert status["status"] == "available"


def test_reserving_a_modem_rig_without_a_card_is_refused(modem_rig) -> None:
    with pytest.raises(RemoteLabClientError) as refused:
        modem_rig.client.create_session("modem-a", user="alice")
    assert refused.value.status == 400
    assert "card_offer" in str(refused.value.payload)


def test_an_unreachable_card_fails_at_reservation_and_frees_the_rig(
    modem_rig,
) -> None:
    """The alternative is dead air once the modem powers up."""
    with pytest.raises(RemoteLabClientError) as refused:
        modem_rig.client.create_session(
            "modem-a",
            user="alice",
            card_offer={"url": "http://127.0.0.1:1/apdu", "token": "x"},
        )
    assert refused.value.status == 400
    assert "cannot reach" in str(refused.value.payload)
    assert modem_rig.client.status("modem-a")["status"] == "available"


def test_reserving_a_modem_rig_starts_a_consumer_and_returns_no_stream(
    modem_rig,
) -> None:
    grant = modem_rig.client.create_session(
        "modem-a",
        user="alice",
        card_offer={"url": modem_rig.card.apdu_url, "token": "card-token"},
    )
    assert grant["rig_kind"] == RIG_KIND_MODEM
    assert "stream" not in grant
    assert grant["consumer"]["running"] is True
    # The token the operator offered is never echoed back.
    assert "card-token" not in str(grant)
    assert modem_rig.client.status("modem-a")["status"] in ("reserved", "busy")

    modem_rig.client.release(grant["session_id"], grant["session_token"])
    assert modem_rig.service.consumers.state_for("modem-a")["running"] is False


def test_releasing_a_modem_rig_stops_its_consumer(modem_rig) -> None:
    grant = modem_rig.client.create_session(
        "modem-a",
        user="alice",
        card_offer={"url": modem_rig.card.apdu_url, "token": "card-token"},
    )
    assert modem_rig.service.consumers.state_for("modem-a")["running"] is True
    modem_rig.client.release(grant["session_id"], grant["session_token"])
    assert modem_rig.service.consumers.state_for("modem-a")["running"] is False


def test_the_shared_bench_lock_blocks_the_card_rig_while_the_modem_runs(
    modem_rig,
) -> None:
    """One bench, one session, whichever kind of rig is taken first."""
    grant = modem_rig.client.create_session(
        "modem-a",
        user="alice",
        card_offer={"url": modem_rig.card.apdu_url, "token": "card-token"},
    )
    with pytest.raises(RemoteLabClientError) as busy:
        modem_rig.client.create_session("modem-a", user="bob")
    assert busy.value.status in (400, 423)
    modem_rig.client.release(grant["session_id"], grant["session_token"])


def test_a_card_offer_held_elsewhere_is_refused_before_anything_starts(
    modem_rig,
) -> None:
    modem_rig.card.lease.claim(holder="someone-else", ttl_seconds=300.0)
    with pytest.raises(RemoteLabClientError) as refused:
        modem_rig.client.create_session(
            "modem-a",
            user="alice",
            card_offer={"url": modem_rig.card.apdu_url, "token": "card-token"},
        )
    assert refused.value.status == 423
    assert refused.value.payload.get("error") == "card_leased"
    assert modem_rig.service.consumers.state_for("modem-a")["running"] is False


def test_stopping_the_agent_stops_every_consumer(modem_rig) -> None:
    modem_rig.client.create_session(
        "modem-a",
        user="alice",
        card_offer={"url": modem_rig.card.apdu_url, "token": "card-token"},
    )
    assert modem_rig.service.consumers.state_for("modem-a")["running"] is True
    modem_rig.service.stop()
    assert modem_rig.service.consumers.state_for("modem-a")["running"] is False


def test_hash_token_is_still_the_config_contract() -> None:
    """Guards the harness above: the base config mints hashed tokens."""
    assert hash_token("team-token").startswith("sha256:")


def test_an_empty_reader_name_closes_no_module_sessions() -> None:
    """A modem rig registers no reader, so its teardown must match nothing.

    Matching on an empty name would match every session carrying no reader
    name and close all of them.
    """
    from yggdrasim_common.gui_server.routes.remote_lab import (
        _close_module_sessions_for_reader,
    )
    from yggdrasim_common.gui_server.sessions import get_manager

    manager = get_manager()
    session = manager.open(
        kind="unrelated-module",
        handle={},
        close=lambda: None,
        metadata={"nothing": "to do with readers"},
    )
    try:
        assert _close_module_sessions_for_reader("") == 0
        assert _close_module_sessions_for_reader("   ") == 0
        assert manager.get(session.id) is not None
    finally:
        manager.close(session.id)


def test_the_documented_modem_rig_example_parses() -> None:
    """The how-to page is the only schema reference operators have."""
    import re

    import yaml

    from tests.test_remote_lab import REMOTE_LAB_HOWTO

    text = REMOTE_LAB_HOWTO.read_text(encoding="utf-8")
    blocks = re.findall(r"(?ms)^```yaml\n(?P<body>.*?)^```\s*$", text)
    modem_blocks = [block for block in blocks if "kind: modem" in block]
    assert len(modem_blocks) == 1, "the page must show exactly one modem rig"

    payload = _base_config()
    payload["rigs"] = yaml.safe_load(modem_blocks[0])["rigs"]
    config = parse_config(payload)

    rig = config.rigs[0]
    assert rig.kind == RIG_KIND_MODEM
    assert rig.consumes_card is True
    assert rig.consumer.enabled is True
    assert rig.consumer.simtrace_reset == "usb-reset"
    assert rig.modem.simtrace_vidpid == "1d50:60e3"
    # The page says a modem rig omits both; the loader has to agree.
    assert rig.stream_proxy.external_port == 0
    assert rig.upstream.url == ""
