# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""One holder per reader across processes (``yggdrasim_common.reader_locks``).

The second process here is a real one: a holder started with ``python -c``
that takes the reader's lock in the test's scratch directory and lets go when
told, or a probe that tries once and reports. A long-running holder is
refused at once by name and pid, a short one is waited for, a lock dies with
its process, nested holds in one process share the lock, and a child process
started while the lock is held does not keep it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from tests.reader_lock_support import CONSOLE_HOLDER, READER, OtherProcess, probe
from yggdrasim_common import reader_claims, reader_locks
from yggdrasim_common.card_backend import SIMULATED_READER_NAME


@pytest.fixture
def lock_dir(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "reader-locks"
    monkeypatch.setattr(reader_locks, "_DIRECTORY", directory)
    return directory


@pytest.fixture
def holders():
    started: list[OtherProcess] = []
    yield started
    for holder in started:
        holder.close()


def test_a_hold_keeps_another_process_off_until_released(lock_dir):
    hold = reader_locks.acquire(READER, "Discover in the GUI")
    try:
        answer = probe(lock_dir, READER)
        assert answer["holder"] == f"Discover in the GUI (pid {os.getpid()})"
        assert answer["busy"].startswith("reader busy: Discover in the GUI (pid ")
        assert f"has held {READER!r} since " in answer["busy"]
    finally:
        hold.release()
    assert probe(lock_dir, READER) == {"held": True}


def test_holds_nest_within_a_process(lock_dir):
    outer = reader_locks.acquire(READER, "Discover in the GUI")
    inner = reader_locks.acquire(READER, "DISCOVER in the eSIM Management console")
    assert outer.guarded and inner.guarded
    outer.release()
    assert "busy" in probe(lock_dir, READER)
    inner.release()
    inner.release()
    assert probe(lock_dir, READER) == {"held": True}


def test_padding_around_a_reader_name_names_the_same_reader(lock_dir):
    hold = reader_locks.acquire(f"  {READER}\n", "Discover in the GUI")
    try:
        assert "busy" in probe(lock_dir, READER)
    finally:
        hold.release()


def test_a_long_running_holder_is_refused_at_once(lock_dir, holders):
    holder = OtherProcess(lock_dir, READER, long_running=True)
    holders.append(holder)
    started = time.monotonic()
    with pytest.raises(reader_locks.ReaderBusyError) as refusal:
        reader_locks.acquire(READER, "HIL bridge", wait_s=10.0)
    assert time.monotonic() - started < 2.0
    assert refusal.value.holder == f"{CONSOLE_HOLDER} (pid {holder.pid})"
    assert str(refusal.value).startswith(f"reader busy: {CONSOLE_HOLDER} (pid {holder.pid}) has held {READER!r} since ")
    holder.release()
    hold = reader_locks.acquire(READER, "HIL bridge", wait_s=0.0)
    hold.release()


def test_a_short_holder_is_waited_for(lock_dir, holders):
    holder = OtherProcess(lock_dir, READER, long_running=False, holder="Discover in the GUI")
    holders.append(holder)
    letting_go = threading.Timer(0.6, holder.release)
    letting_go.start()
    waits: list[reader_locks.HolderRecord | None] = []
    started = time.monotonic()
    try:
        hold = reader_locks.acquire(READER, "DISCOVER in the eSIM Management console", wait_s=10.0, on_wait=waits.append)
    finally:
        letting_go.join()
    elapsed = time.monotonic() - started
    hold.release()
    assert 0.4 <= elapsed < 5.0
    assert len(waits) == 1
    assert waits[0] is not None
    assert (waits[0].holder, waits[0].pid, waits[0].long_running) == ("Discover in the GUI", holder.pid, False)


def test_a_wait_that_runs_out_names_the_holder(lock_dir, holders):
    holder = OtherProcess(lock_dir, READER, long_running=False, holder="Discover in the GUI")
    holders.append(holder)
    started = time.monotonic()
    with pytest.raises(reader_locks.ReaderBusyError) as refusal:
        reader_locks.acquire(READER, "probe", wait_s=0.5)
    assert time.monotonic() - started >= 0.4
    assert refusal.value.holder == f"Discover in the GUI (pid {holder.pid})"
    holder.release()


def test_the_lock_dies_with_its_process(lock_dir, holders):
    holder = OtherProcess(lock_dir, READER, long_running=True)
    holders.append(holder)
    holder.kill()
    hold = reader_locks.acquire(READER, "HIL bridge", wait_s=0.0)
    try:
        assert hold.guarded
    finally:
        hold.release()


def test_a_record_left_by_a_dead_holder_holds_nothing(lock_dir):
    finished = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True, text=True)
    dead_pid = int(finished.stdout.strip())
    _, record_path = reader_locks._paths(READER)
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(
        json.dumps({"holder": CONSOLE_HOLDER, "pid": dead_pid, "since": time.time(), "long_running": True}),
        encoding="utf-8",
    )
    hold = reader_locks.acquire(READER, "HIL bridge", wait_s=0.0)
    hold.release()
    assert record_path.exists() is False


def test_a_child_process_started_under_a_hold_does_not_keep_it(lock_dir):
    hold = reader_locks.acquire(READER, "HIL bridge", long_running=True)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        hold.release()
        assert probe(lock_dir, READER) == {"held": True}
    finally:
        child.kill()
        child.wait(timeout=10)


def test_holder_of_names_another_process_and_nobody_else(lock_dir, holders):
    assert reader_locks.holder_of(READER) is None
    holder = OtherProcess(lock_dir, READER, long_running=True)
    holders.append(holder)
    record = reader_locks.holder_of(READER)
    assert record is not None
    assert (record.holder, record.pid, record.long_running) == (CONSOLE_HOLDER, holder.pid, True)
    holder.release()
    assert reader_locks.holder_of(READER) is None
    with reader_locks.held(READER, "HIL bridge"):
        assert reader_locks.holder_of(READER) is None


def test_an_empty_reader_name_holds_nothing(lock_dir):
    hold = reader_locks.acquire("  ", "probe")
    assert hold.guarded is False
    hold.release()
    assert lock_dir.exists() is False


def test_no_writable_directory_lets_the_work_go_ahead_and_says_so(tmp_path, monkeypatch, capsys):
    blocker = tmp_path / "a-file"
    blocker.write_text("", encoding="utf-8")
    monkeypatch.setattr(reader_locks, "_DIRECTORY", blocker / "reader-locks")
    monkeypatch.setattr(reader_locks, "_WARNED", False)
    first = reader_locks.acquire(READER, "probe")
    second = reader_locks.acquire(READER, "probe")
    assert (first.guarded, second.guarded) == (False, False)
    first.release()
    second.release()
    warnings = capsys.readouterr().err
    assert warnings.count("reader locks unavailable") == 1


def test_a_gui_claim_takes_the_process_lock(lock_dir):
    token = reader_claims.claim(READER, "Card overview")
    try:
        answer = probe(lock_dir, READER)
        assert answer["holder"].startswith("Card overview in the GUI (pid ")
    finally:
        reader_claims.release(READER, token)
    assert probe(lock_dir, READER) == {"held": True}


def test_a_gui_claim_is_refused_by_a_process_that_runs_until_stopped(lock_dir, holders):
    holder = OtherProcess(lock_dir, READER, long_running=True)
    holders.append(holder)
    with pytest.raises(reader_claims.ReaderBusyError) as refusal:
        reader_claims.claim(READER, "Card overview")
    assert refusal.value.holder == f"{CONSOLE_HOLDER} (pid {holder.pid})"
    assert reader_claims.claimed_readers() == {}
    holder.release()


def test_the_simulated_reader_takes_no_process_lock(lock_dir):
    token = reader_claims.claim(SIMULATED_READER_NAME, "Card overview")
    try:
        assert lock_dir.exists() is False
    finally:
        reader_claims.release(SIMULATED_READER_NAME, token)


def test_a_gui_claim_given_back_under_a_nested_hold_leaves_the_reader_held(lock_dir):
    token = reader_claims.claim(READER, "Card overview")
    nested = reader_locks.acquire(READER, "DISCOVER in the eSIM Management console")
    reader_claims.release(READER, token)
    try:
        assert "busy" in probe(lock_dir)
    finally:
        nested.release()
    assert probe(lock_dir) == {"held": True}
