# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Card actions from the GUI take turns on their reader.

The action routes claim the reader a call drives (its reader field, or the
reader of the SCP03 session it targets) for as long as the call runs, before
the session lock. Two calls on one reader never overlap; a call on a reader a
stream or a profile download holds is refused with the holder's name instead
of waiting behind it.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from yggdrasim_common import reader_claims  # noqa: E402
from yggdrasim_common.gui_server.actions.registry import ActionField, ActionSpec  # noqa: E402
from yggdrasim_common.gui_server.routes import actions as actions_routes  # noqa: E402
from yggdrasim_common.gui_server.routes import live as live_routes  # noqa: E402


def _run(coro):
    """Run *coro* on a loop with its own worker threads, shut down after it.

    ``asyncio.run`` on Python 3.13 can stall while it tears down the default
    executor ``asyncio.to_thread`` created (see test_gui_actions).
    """
    loop = asyncio.new_event_loop()
    executor = ThreadPoolExecutor(max_workers=4)
    loop.set_default_executor(executor)
    try:
        return loop.run_until_complete(coro)
    finally:
        executor.shutdown(wait=True)
        loop.close()


@pytest.fixture(autouse=True)
def _reader_backend(monkeypatch):
    monkeypatch.setenv("YGGDRASIM_CARD_BACKEND", "reader")
    yield
    assert reader_claims.claimed_readers() == {}


def _spec(dispatcher, *, title: str = "Get profiles info", reader_field: bool = True) -> ActionSpec:
    inputs = (ActionField(name="reader", label="Reader", kind="reader"),) if reader_field else ()
    return ActionSpec(
        id="test.reader_claims",
        subsystem="eSIM Management",
        title=title,
        description="A card action for the claim tests.",
        inputs=inputs,
        dispatcher=dispatcher,
    )


def test_the_reader_comes_from_the_reader_field_or_the_session() -> None:
    with_field = _spec(lambda ctx, **kw: None)
    without_field = _spec(lambda ctx, **kw: None, reader_field=False)
    scp03_session = SimpleNamespace(metadata={"reader_name": "Example USB Reader 1"})
    saip_session = SimpleNamespace(metadata={"package": "profile.der"})
    assert actions_routes._action_reader(with_field, {"reader": "Example USB Reader 0"}, None) == (
        "Example USB Reader 0"
    )
    assert actions_routes._action_reader(without_field, {}, scp03_session) == "Example USB Reader 1"
    assert actions_routes._action_reader(without_field, {}, saip_session) is None
    assert actions_routes._action_reader(without_field, {}, None) is None


def test_two_calls_on_one_reader_do_not_overlap() -> None:
    spans: list[tuple[float, float]] = []
    spans_lock = threading.Lock()

    def dispatcher(ctx, *, reader: str = "") -> dict:
        start = time.monotonic()
        time.sleep(0.2)
        with spans_lock:
            spans.append((start, time.monotonic()))
        return {"ok": True}

    spec = _spec(dispatcher)

    async def both():
        return await asyncio.gather(
            actions_routes._invoke_dispatcher(spec, None, {"reader": "R"}),
            actions_routes._invoke_dispatcher(spec, None, {"reader": "R"}),
        )

    _run(both())
    first, second = sorted(spans)
    assert second[0] >= first[1]


def test_a_session_call_holds_the_reader_while_it_runs(monkeypatch) -> None:
    session = SimpleNamespace(metadata={"reader_name": "R"}, _lock=threading.RLock())
    monkeypatch.setattr(actions_routes, "_session_for_serialisation", lambda coerced: session)
    seen: list[dict[str, str]] = []

    def dispatcher(ctx, *, session_id: str = "") -> dict:
        seen.append(reader_claims.claimed_readers())
        return {"ok": True}

    spec = _spec(dispatcher, title="Read EF", reader_field=False)
    _run(actions_routes._invoke_dispatcher(spec, None, {"session_id": "s1"}))
    assert seen == [{"R": "Read EF"}]


def test_a_call_on_a_reader_a_stream_holds_is_refused_with_its_name(monkeypatch) -> None:
    calls: list[str] = []
    spec = _spec(lambda ctx, *, reader="": calls.append(reader) or {"ok": True})
    monkeypatch.setattr(
        actions_routes, "ensure_builtin_actions_loaded", lambda: SimpleNamespace(get=lambda _id: spec)
    )
    token = reader_claims.claim("R", "Download profile", long_running=True)
    started = time.monotonic()
    try:
        response = _run(
            actions_routes.run_action(spec.id, actions_routes.RunRequest(inputs={"reader": "R"}))
        )
    finally:
        reader_claims.release("R", token)
    assert time.monotonic() - started < 2.0
    assert response.ok is False
    assert response.error.startswith("reader busy: Download profile has held 'R' since ")
    assert calls == []


def test_a_stream_holds_its_reader_until_it_ends() -> None:
    source = inspect.getsource(actions_routes.stream_action)
    assert "_claim_reader, spec, coerced, _session_for_serialisation(coerced), long_running=True" in source
    assert "await _run_stream(websocket, spec, action_id, coerced)\n    finally:\n        _release_reader(claimed)" in source


def test_a_profile_download_on_a_held_reader_is_refused() -> None:
    token = reader_claims.claim("R", "Discover", long_running=True)

    async def scenario():
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        ctx = live_routes.FlowContext(
            reader="R", activation_code="LPA:1$smdp.example.test$MATCH", dry_run=True
        )
        await asyncio.to_thread(live_routes._run_flow_worker, ctx, loop, queue)
        for _ in range(20):
            await asyncio.sleep(0)
        events = []
        while not queue.empty():
            events.append(queue.get_nowait())
        return events

    try:
        events = _run(scenario())
    finally:
        reader_claims.release("R", token)
    levels = [(event["level"], event["message"]) for event in events]
    assert levels[-1] == ("done", "flow aborted.")
    assert levels[-2][0] == "error"
    assert levels[-2][1].startswith("reader busy: Discover has held 'R' since ")
    assert all("connecting to reader" not in message for _level, message in levels)
