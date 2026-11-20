# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The eSIM Management console holds its reader across processes per card command.

A card command rebuilds the transport (a card reset) and releases it at the
end (a power-down), so the console holds the reader's lock
(``yggdrasim_common.reader_locks``) from before the rebuild to after the
release. A command marked long-running (a continuous watch) makes another process give up
at once; one the reader is refused to is not started and says who holds it.
The console names the reader the way the GUI and the HIL bridge do, so a
GUI claim and a console command meet on one lock.
"""

from __future__ import annotations

import time
import types
from types import SimpleNamespace

import pytest

from SCP11.live import console as live_console
from tests.reader_lock_support import READER, OtherProcess, probe
from yggdrasim_common import card_backend, reader_claims, reader_locks


class _Channel:
    def __init__(self) -> None:
        self.disconnects = 0

    def disconnect(self) -> None:
        self.disconnects += 1

    def is_connected(self) -> bool:
        return self.disconnects == 0


class _Reader:
    def __init__(self, name: str) -> None:
        self.name = name

    def __str__(self) -> str:
        return self.name


@pytest.fixture
def lock_dir(tmp_path, monkeypatch):
    directory = tmp_path / "reader-locks"
    monkeypatch.setattr(reader_locks, "_DIRECTORY", directory)
    return directory


@pytest.fixture
def local_reader(monkeypatch):
    """One local PC/SC reader, index 0, and the reader backend selected."""
    system = pytest.importorskip("smartcard.System")
    monkeypatch.setattr(system, "readers", lambda: [_Reader(READER)])
    monkeypatch.setattr(card_backend, "is_simulated_card_backend", lambda: False)


@pytest.fixture
def others():
    started: list[OtherProcess] = []
    yield started
    for other in started:
        other.close()


def _console(*, reader_name: str = ""):
    builds: list[object] = []

    def _build(cfg):
        channel = _Channel()
        builds.append(channel)
        return channel

    client = SimpleNamespace(
        cfg=SimpleNamespace(
            READER_INDEX=0,
            READER_NAME=reader_name,
            RSP_SERVER_URL="rsp.example.test",
            ES9_BASE_URL="https://rsp.example.test",
            ES9_VERIFY_TLS=True,
            ES9_CA_BUNDLE_PATH="",
        ),
        apdu_channel=_Channel(),
        orchestrator=None,
        _build_apdu_channel=_build,
    )
    console = live_console.SCP11Console(client)
    console._style = live_console.ConsoleStyle("", "", "", "", "", "", "")
    console._builds = builds
    return console


def _add(console, name: str, handler, *, policy=live_console.SessionPolicy.HARD_RESET, long_running: bool = False):
    console._add_command(
        name,
        name,
        "test verb",
        handler,
        session_policy=policy,
        runs_own_connect=True,
        long_running=long_running,
    )


def test_a_card_command_holds_the_reader_from_rebuild_to_release(lock_dir, local_reader):
    console = _console()
    seen: list[dict] = []
    _add(console, "TESTCMD", lambda argument: seen.append(probe(lock_dir)) or True)

    assert console._execute_command("TESTCMD", "") is True

    assert len(console._builds) == 1
    assert seen[0]["holder"].startswith("TESTCMD in the eSIM Management console (pid ")
    assert probe(lock_dir) == {"held": True}


def test_a_long_running_command_turns_others_away_at_once(lock_dir, local_reader):
    console = _console()
    took: list[float] = []
    answers: list[dict] = []

    def _handler(argument: str) -> bool:
        started = time.monotonic()
        answers.append(probe(lock_dir, wait_s=10.0))
        took.append(time.monotonic() - started)
        return True

    _add(console, "LONGRUN", _handler, long_running=True)
    console._execute_command("LONGRUN", "")

    assert answers[0]["holder"].startswith("LONGRUN in the eSIM Management console (pid ")
    assert took[0] < 5.0


def test_a_command_is_not_started_while_another_process_holds_the_reader(lock_dir, local_reader, others, capsys):
    other = OtherProcess(lock_dir, long_running=True, holder="HIL bridge")
    others.append(other)
    console = _console()
    ran: list[str] = []
    _add(console, "TESTCMD", lambda argument: ran.append(argument) or True)

    assert console._execute_command("TESTCMD", "x") is True

    assert ran == []
    assert console._builds == []
    printed = capsys.readouterr().out
    assert f"[!] TESTCMD not started: reader busy: HIL bridge (pid {other.pid}) has held {READER!r} since " in printed
    other.release()


def test_a_shared_command_takes_no_hold(lock_dir, local_reader):
    console = _console()
    seen: list[dict] = []
    _add(console, "LOOK", lambda argument: seen.append(probe(lock_dir)) or True, policy=live_console.SessionPolicy.SHARED)

    console._execute_command("LOOK", "")

    assert seen == [{"held": True}]


def test_a_remote_reader_and_the_simulated_card_take_no_hold(lock_dir, local_reader, monkeypatch):
    remote = _console(reader_name="Remote Lab rig 1")
    seen: list[dict] = []
    _add(remote, "TESTCMD", lambda argument: seen.append(probe(lock_dir)) or True)
    remote._execute_command("TESTCMD", "")

    monkeypatch.setattr(card_backend, "is_simulated_card_backend", lambda: True)
    simulated = _console()
    _add(simulated, "TESTCMD", lambda argument: seen.append(probe(lock_dir)) or True)
    simulated._execute_command("TESTCMD", "")

    assert seen == [{"held": True}, {"held": True}]


def test_a_gui_claim_and_a_console_command_meet_on_one_lock(lock_dir, local_reader):
    """The console names the reader by index the way the GUI names it by field."""
    console = _console()
    seen: list[dict] = []
    _add(console, "TESTCMD", lambda argument: seen.append(probe(lock_dir)) or True)
    token = reader_claims.claim(READER, "Card overview")
    try:
        console._execute_command("TESTCMD", "")
        assert seen[0]["holder"].startswith("Card overview in the GUI (pid ")
        assert "busy" in probe(lock_dir)
    finally:
        reader_claims.release(READER, token)
    assert probe(lock_dir) == {"held": True}


def test_the_test_console_holds_the_same_way():
    test_console = pytest.importorskip("SCP11.test.console")
    assert isinstance(test_console.SCP11Console._hold_reader_for_command, types.FunctionType)
    assert test_console.SCP11Console.READER_HOLDER_LABEL == "eSIM Management console"


def test_a_gui_claim_on_another_reader_leaves_the_console_free(lock_dir, monkeypatch):
    """Two names are two locks, both this process's: no refusal, both given back."""
    system = pytest.importorskip("smartcard.System")
    other_reader = "Reader B"
    monkeypatch.setattr(system, "readers", lambda: [_Reader(other_reader)])
    monkeypatch.setattr(card_backend, "is_simulated_card_backend", lambda: False)
    console = _console()
    seen: list[tuple[dict, dict]] = []
    _add(console, "TESTCMD", lambda argument: seen.append((probe(lock_dir), probe(lock_dir, other_reader))) or True)
    token = reader_claims.claim(READER, "Card overview")
    try:
        console._execute_command("TESTCMD", "")
    finally:
        reader_claims.release(READER, token)
    gui_side, console_side = seen[0]
    assert gui_side["holder"].startswith("Card overview in the GUI (pid ")
    assert console_side["holder"].startswith("TESTCMD in the eSIM Management console (pid ")
    assert probe(lock_dir) == {"held": True}
    assert probe(lock_dir, other_reader) == {"held": True}
