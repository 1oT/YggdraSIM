# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""One card operation at a time per reader (``yggdrasim_common.reader_claims``).

A claim held by a short operation is waited for, blocking rather than
spinning or failing; one held by a long-running operation is refused at once
with a message naming the holder and the reader. A release with a stale token
changes nothing, and the map holds only the readers held right now.
"""

from __future__ import annotations

import sys
import threading
import time
import types

import pytest

from yggdrasim_common import reader_claims
from yggdrasim_common.card_backend import SIMULATED_READER_NAME


@pytest.fixture(autouse=True)
def _no_claims_left():
    yield
    assert reader_claims.claimed_readers() == {}


def test_a_second_claim_waits_for_a_short_operation_then_proceeds() -> None:
    first = reader_claims.claim("R", "Read EF")
    acquired = threading.Event()
    tokens: list[object] = []

    def second() -> None:
        tokens.append(reader_claims.claim("R", "Get profiles info", wait_s=5.0))
        acquired.set()

    worker = threading.Thread(target=second)
    worker.start()
    assert not acquired.wait(0.2)
    assert reader_claims.claimed_readers() == {"R": "Read EF"}
    reader_claims.release("R", first)
    assert acquired.wait(2.0)
    worker.join(2.0)
    assert reader_claims.claimed_readers() == {"R": "Get profiles info"}
    reader_claims.release("R", tokens[0])


def test_a_long_running_holder_is_refused_at_once_naming_holder_and_reader() -> None:
    token = reader_claims.claim("YggdraSIM Simulator", "Download profile", long_running=True)
    started = time.monotonic()
    try:
        with pytest.raises(reader_claims.ReaderBusyError) as raised:
            reader_claims.claim("YggdraSIM Simulator", "Get profiles info", wait_s=5.0)
    finally:
        reader_claims.release("YggdraSIM Simulator", token)
    assert time.monotonic() - started < 0.5
    message = str(raised.value)
    assert message.startswith("reader busy: Download profile has held 'YggdraSIM Simulator' since ")
    assert raised.value.holder == "Download profile"


def test_a_wait_that_runs_out_is_refused() -> None:
    token = reader_claims.claim("R", "Scan")
    try:
        with pytest.raises(reader_claims.ReaderBusyError, match="reader busy: Scan has held 'R'"):
            reader_claims.claim("R", "Read EF", wait_s=0.05)
    finally:
        reader_claims.release("R", token)


def test_a_stale_token_leaves_the_claim_in_place() -> None:
    stale = reader_claims.claim("R", "Scan")
    reader_claims.release("R", stale)
    current = reader_claims.claim("R", "Read EF")
    reader_claims.release("R", stale)
    assert reader_claims.claimed_readers() == {"R": "Read EF"}
    reader_claims.release("R", current)


def test_held_gives_the_reader_back_when_the_body_raises() -> None:
    with pytest.raises(ValueError):
        with reader_claims.held("R", "Scan"):
            assert reader_claims.claimed_readers() == {"R": "Scan"}
            raise ValueError("card answered 6A82")
    assert reader_claims.claimed_readers() == {}


def test_readers_are_claimed_independently() -> None:
    first = reader_claims.claim("R1", "Scan", long_running=True)
    second = reader_claims.claim("R2", "Scan", long_running=True)
    assert reader_claims.claimed_readers() == {"R1": "Scan", "R2": "Scan"}
    reader_claims.release("R1", first)
    reader_claims.release("R2", second)


def test_the_sim_backend_has_one_key(monkeypatch) -> None:
    monkeypatch.setenv("YGGDRASIM_CARD_BACKEND", "sim")
    assert reader_claims.reader_key("") == SIMULATED_READER_NAME
    assert reader_claims.reader_key("Example USB Reader 0") == SIMULATED_READER_NAME


def test_the_reader_backend_keys_a_name_and_names_the_default(monkeypatch) -> None:
    monkeypatch.setenv("YGGDRASIM_CARD_BACKEND", "reader")
    smartcard_pkg = types.ModuleType("smartcard")
    smartcard_system = types.ModuleType("smartcard.System")
    smartcard_system.readers = lambda: ["Example USB Reader 0", "Example USB Reader 1"]
    smartcard_pkg.System = smartcard_system
    monkeypatch.setitem(sys.modules, "smartcard", smartcard_pkg)
    monkeypatch.setitem(sys.modules, "smartcard.System", smartcard_system)
    assert reader_claims.reader_key(" Example USB Reader 1 ") == "Example USB Reader 1"
    assert reader_claims.reader_key("") == "Example USB Reader 0"
    smartcard_system.readers = lambda: []
    assert reader_claims.reader_key("") == ""
