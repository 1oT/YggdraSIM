# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""eSIM Live verbs ADD-INITIAL-EIM (wizard, then eUICCMemoryReset + AddInitialEim) and EIM-CERT-STORE."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from SCP11.live.console import SCP11Console as LiveConsole
from SCP11.live.console import SessionPolicy
from SCP11.shared import eim_builder_store as store
from tests.eim_builder_support import TEST_EIM_FQDN, TEST_EIM_ID, der, make_certificate, pem

# Wizard answers for a store holding one certificate; each test then answers
# the save-as-configuration prompt (Enter skips it) and the send confirmation.
WIZARD = ["1", "", TEST_EIM_ID, "", TEST_EIM_FQDN, "", "y", "", "", "", ""]


class _Cfg:
    RSP_SERVER_URL = "rsp.example.com"
    ES9_BASE_URL = "https://rsp.example.com"
    ES9_VERIFY_TLS = True
    ES9_CA_BUNDLE_PATH = ""


def _console() -> LiveConsole:
    provider = SimpleNamespace(
        set_base_url=lambda value: None,
        set_verify_tls=lambda enabled: None,
        set_ca_bundle_path=lambda path: None,
    )
    client = SimpleNamespace(cfg=_Cfg(), apdu_channel=None, orchestrator=SimpleNamespace(profile_provider=provider))
    return LiveConsole(client)


@pytest.fixture()
def stocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(store.STORE_DIR_ENV, str(tmp_path))
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="eim-signing")
    return tmp_path


class _Card:
    """Records what the console sends and answers with canned ES10 responses."""

    def __init__(self, reset_answer: str = "BF6406800100810101", add_answer: str = "BF5705A003840101") -> None:
        self.events: list[str] = []
        self.answers = {b"\xBF\x64": bytes.fromhex(reset_answer), b"\xBF\x57": bytes.fromhex(add_answer)}

    def connect(self, reason: str) -> None:
        self.events.append(f"connect {reason}")

    def send(self, payload: bytes, log_name: str) -> bytes:
        self.events.append(payload[:2].hex().upper())
        answer = self.answers[payload[:2]]
        if isinstance(answer, Exception):
            raise answer
        return answer


def _run_add_initial_eim(console: LiveConsole, card: _Card, answers: list[str]) -> str:
    console._connect_card_for_command = card.connect
    console._send_store_data_with_logical_fallback = card.send
    pending = list(answers)

    def scripted(_prompt: str = "") -> str:
        if not pending:
            raise EOFError()
        return pending.pop(0)

    output = io.StringIO()
    with mock.patch("builtins.input", scripted), contextlib.redirect_stdout(output):
        assert console._cmd_add_initial_eim("") is True
    return output.getvalue()


def test_verbs_are_registered_with_their_session_policies() -> None:
    console = _console()
    add = console._commands["ADD-INITIAL-EIM"]
    # SHARED: no card transport is held while the wizard waits on the operator.
    assert (add.session_policy, add.section) == (SessionPolicy.SHARED, console.HELP_SECTION_IPAD)
    assert console._commands["EIM-CERT-STORE"].session_policy == SessionPolicy.SHARED


def test_a_confirmed_run_connects_then_resets_then_adds(stocked: Path) -> None:
    card = _Card()
    output = _run_add_initial_eim(_console(), card, WIZARD + ["", "y"])
    assert card.events == ["connect ADD-INITIAL-EIM", "BF64", "BF57"]
    assert "81E2910007BF640482020106" in output
    assert "resetEimResult: nothingToDelete (1)" in output
    assert "addInitialEimOk (associationToken 1)" in output
    assert store.load_values()["eim_fqdn"] == [TEST_EIM_FQDN]


def test_the_transport_opens_only_after_the_confirmation(stocked: Path) -> None:
    console, card = _console(), _Card()
    console._can_rebuild_command_transport = lambda: True
    console._reset_card_transport_for_command = lambda reason: card.events.append("rebuild")
    console._disconnect_card_transport_after_command = lambda reason: card.events.append("release")
    console._connect_card_for_command = card.connect
    console._send_store_data_with_logical_fallback = card.send
    pending = WIZARD + ["", "y"]

    def answer(_prompt: str = "") -> str:
        card.events.append("answer")
        return pending.pop(0)

    with mock.patch("builtins.input", answer), contextlib.redirect_stdout(io.StringIO()):
        console._cmd_add_initial_eim("")
    last_answer = len(card.events) - 1 - card.events[::-1].index("answer")
    assert card.events[last_answer + 1 :] == ["rebuild", "connect ADD-INITIAL-EIM", "BF64", "BF57", "release"]
    assert card.events.count("answer") == len(WIZARD) + 2


def test_s_prints_the_full_script_before_the_answer(stocked: Path) -> None:
    card = _Card()
    output = _run_add_initial_eim(_console(), card, WIZARD + ["", "s", "n"])
    assert card.events == []
    assert "[+] APDU script" in output
    assert "MANAGE CHANNEL answers channel 01" in output
    assert "[+] APDU sequence" in output
    # The request again as one STORE DATA, after the script.
    assert "[+] AddInitialEim as one APDU" in output
    assert "STORE DATA: AddInitialEim in one APDU" in output


def test_declining_sends_nothing(stocked: Path) -> None:
    card = _Card()
    output = _run_add_initial_eim(_console(), card, WIZARD + ["", "n"])
    assert card.events == []
    assert "Nothing was sent" in output


def test_a_cancelled_wizard_never_touches_the_card(stocked: Path) -> None:
    card = _Card()
    output = _run_add_initial_eim(_console(), card, ["1", "CANCEL"])
    assert card.events == []
    assert "cancelled" in output


def test_a_refused_reset_stops_before_add_initial_eim(stocked: Path) -> None:
    card = _Card(reset_answer="BF6403800105")
    output = _run_add_initial_eim(_console(), card, WIZARD + ["", "y"])
    assert card.events == ["connect ADD-INITIAL-EIM", "BF64"]
    assert "resetResult: catBusy (5)" in output
    assert "AddInitialEim was not sent" in output


def test_a_failed_reset_apdu_stops_before_add_initial_eim(stocked: Path) -> None:
    card = _Card()
    card.answers[b"\xBF\x64"] = OSError("APDU Failed: 6A88")
    output = _run_add_initial_eim(_console(), card, WIZARD + ["", "y"])
    assert card.events == ["connect ADD-INITIAL-EIM", "BF64"]
    assert "APDU Failed: 6A88" in output


def test_an_add_initial_eim_error_is_named(stocked: Path) -> None:
    card = _Card(add_answer="BF5703810102")
    output = _run_add_initial_eim(_console(), card, WIZARD + ["", "y"])
    assert "addInitialEimError associatedEimAlreadyExists (2)" in output


def _send_hex(console: LiveConsole, card: _Card, argument: str) -> str:
    console._send_store_data_with_logical_fallback = card.send
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert console._send_add_initial_eim_hex(argument) is True
    return output.getvalue()


def test_the_gui_handler_sends_the_reset_then_the_request(stocked: Path) -> None:
    from SCP11.shared.eim_builder import BuilderInputs, build_add_initial_eim

    request = build_add_initial_eim(BuilderInputs(eim_id=TEST_EIM_ID, eim_certificate="eim-signing")).request
    console, card = _console(), _Card()
    output = _send_hex(console, card, request.hex())
    assert card.events == ["BF64", "BF57"]
    assert console._add_initial_eim_succeeded is True
    assert "addInitialEimOk" in output
    refused = _Card(add_answer="BF5703810102")
    _send_hex(console, refused, request.hex())
    assert console._add_initial_eim_succeeded is False


@pytest.mark.parametrize("argument", ["", "BF57", "ZZ", "BF6400"])
def test_the_gui_handler_sends_nothing_that_is_not_a_request(stocked: Path, argument: str) -> None:
    console, card = _console(), _Card()
    output = _send_hex(console, card, argument)
    assert card.events == []
    assert console._add_initial_eim_succeeded is False
    assert "Not an AddInitialEimRequest" in output


def test_add_initial_eim_takes_no_argument(stocked: Path) -> None:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        _console()._cmd_add_initial_eim("now")
    assert "Usage: ADD-INITIAL-EIM" in output.getvalue()


def _store_command(console: LiveConsole, argument: str) -> str:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert console._cmd_eim_cert_store(argument) is True
    return output.getvalue()


def test_eim_cert_store_verb(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(store.STORE_DIR_ENV, str(tmp_path / "store"))
    certificate, _ = make_certificate("eIM TLS Test CA", ca=True)
    source = tmp_path / "tls ca.pem"
    source.write_bytes(pem(certificate))
    console = _console()
    assert "no certificate stored" in _store_command(console, "")
    assert "Stored tls-ca" in _store_command(console, f'IMPORT "{source}" tls-ca')
    assert "already uses" in _store_command(console, f'IMPORT "{source}" tls-ca')
    assert "Stored tls-ca" in _store_command(console, f'IMPORT "{source}" tls-ca --overwrite')
    assert "tls-ca" in _store_command(console, "LIST")
    store.remember_values({"eim_fqdn": TEST_EIM_FQDN})
    assert TEST_EIM_FQDN in _store_command(console, "VALUES")
    assert "Forgot" in _store_command(console, f"FORGET eim_fqdn {TEST_EIM_FQDN}")
    assert "Removed tls-ca" in _store_command(console, "REMOVE tls-ca")
    assert "No stored certificate" in _store_command(console, "REMOVE tls-ca")
    assert "Usage: EIM-CERT-STORE" in _store_command(console, "SHRED everything")


def test_a_configuration_is_saved_and_offered_on_the_next_run(stocked: Path) -> None:
    card = _Card()
    _run_add_initial_eim(_console(), card, WIZARD + ["test-config", "n"])
    assert store.load_configurations()["test-config"]["eim_fqdn"] == TEST_EIM_FQDN
    # The next run starts from it: Enter at every step keeps its values.
    output = _run_add_initial_eim(_console(), card, ["test-config"] + [""] * 11 + ["", "n"])
    assert "Starting from configuration test-config" in output
    assert "eimFqdn                   : eim.example.test" in output
    assert "associationToken          : -1" in output


def test_eim_cert_store_edits_in_place(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(store.STORE_DIR_ENV, str(tmp_path))
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="old-name")
    store.remember_values({"eim_id": "wrong", "eim_certificate": "old-name"})
    store.save_configuration("cfg", {"eim_id": TEST_EIM_ID, "eim_certificate": "old-name"})
    console = _console()
    assert "configurations updated: cfg" in _store_command(console, "RENAME old-name new-name")
    assert store.load_configurations()["cfg"]["eim_certificate"] == "new-name"
    assert store.load_values()["eim_certificate"] == ["new-name"]
    assert "Changed eim_id 'wrong'" in _store_command(console, f"EDIT eim_id wrong {TEST_EIM_ID}")
    assert store.load_last_build()["eim_id"] == TEST_EIM_ID
    assert "cfg" in _store_command(console, "CONFIGS")
    assert "Renamed configuration cfg to cfg2" in _store_command(console, "CONFIG-RENAME cfg cfg2")
    assert "Deleted configuration cfg2" in _store_command(console, "CONFIG-DELETE cfg2")
    assert store.load_configurations() == {}
