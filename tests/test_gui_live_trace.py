# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Live operation trace (``yggdrasim_common.gui_server.live_trace``).

A dispatcher's sink keeps returning its text and also publishes each line
of the run it belongs to; a GUI card channel prints one line per command,
or every exchange in hex under the global debug flag; the action route
tags the run with the page's trace id.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any

import pytest

from SCP11 import transport
from yggdrasim_common.gui_server import live_trace
from yggdrasim_common.gui_server.actions.registry import ActionSpec
from yggdrasim_common.gui_server.routes import actions as actions_routes
from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV

REPO = Path(__file__).resolve().parents[1]
SEGMENT = bytes(range(256)) * 2 + b"\x01"


class _Connection:
    def __init__(self, sw: tuple[int, int] = (0x90, 0x00)) -> None:
        self.sw = sw

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        return [], self.sw[0], self.sw[1]


def _channel(sw: tuple[int, int] = (0x90, 0x00)) -> Any:
    channel = transport.PcscApduChannel.__new__(transport.PcscApduChannel)
    channel._conn = _Connection(sw)
    channel._raw_apdu_logging = False
    channel._quiet_apdu_logging = True
    channel._milestone_apdu_logging = False
    channel._last_milestone_label = ""
    return channel


def _load(channel: Any) -> None:
    channel.exchange(bytes.fromhex("00A4040000"), "SELECT ISD-R")
    for segment in (1, 2):
        channel.send_chunked(0x80, 0xE2, 0x91, 0, SEGMENT, f"LoadBoundProfilePackage [{segment}/2]")


async def _run_published(work: Any, trace_id: str = "t-1") -> tuple[live_trace.TraceRun, str, list[dict[str, Any]]]:
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=live_trace.QUEUE_CAP)
    detach = live_trace.get_bus().attach(queue, asyncio.get_running_loop())
    run, token = live_trace.begin_run("demo.action", trace_id)
    try:
        text = await asyncio.to_thread(work)
    finally:
        live_trace.end_run(token)
        await asyncio.sleep(0.05)
        detach()
    frames = []
    while not queue.empty():
        frames.append(queue.get_nowait())
    return run, text, frames


def _captured(channel_sw: tuple[int, int] = (0x90, 0x00)) -> str:
    channel = live_trace.configure_channel_trace(_channel(channel_sw))
    sink = live_trace.live_trace_sink()
    with contextlib.redirect_stdout(sink):
        _load(channel)
    return sink.getvalue()


def test_default_trace_is_one_line_per_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(GLOBAL_DEBUG_ENV, "0")
    run, text, frames = asyncio.run(_run_published(_captured))
    assert [frame["line"] for frame in frames] == [
        "[*] SELECT ISD-R",
        "[*] LoadBoundProfilePackage [1/2]",
        "[*] LoadBoundProfilePackage [2/2]",
    ]
    assert {frame["trace_id"] for frame in frames} == {"t-1"}
    assert {frame["action"] for frame in frames} == {"demo.action"}
    assert run.published == 3
    assert text.splitlines() == [frame["line"] for frame in frames]


def test_debug_trace_carries_every_byte(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(GLOBAL_DEBUG_ENV, "1")
    _run, text, frames = asyncio.run(_run_published(_captured))
    lines = [frame["line"] for frame in frames]
    assert "[SELECT ISD-R] > 00A4040000" in lines
    # Three STORE DATA blocks per segment, each with its command bytes.
    blocks = [line for line in lines if "] > 80E2" in line]
    assert len(blocks) == 6
    sent = "".join(line.split("> ", 1)[1][10:] for line in blocks)
    assert sent == (SEGMENT.hex().upper()) * 2
    assert "\x1b" not in "".join(lines)
    assert len(text) > 0


def test_failing_status_word_prints_in_milestone_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(GLOBAL_DEBUG_ENV, "0")
    channel = live_trace.configure_channel_trace(_channel((0x69, 0x85)))
    sink = live_trace.live_trace_sink()
    with contextlib.redirect_stdout(sink):
        channel.exchange(bytes.fromhex("80E2910000"), "GetEuiccInfo")
    assert sink.getvalue().splitlines() == ["[*] GetEuiccInfo", "    -> SW 6985 len=0"]


def test_sink_without_a_run_or_listener_is_a_plain_buffer() -> None:
    sink = live_trace.live_trace_sink()
    sink.write("alone\n")
    assert sink.getvalue() == "alone\n"

    async def _no_listener() -> live_trace.TraceRun:
        run, token = live_trace.begin_run("demo.action", "t-2")
        try:
            inner = live_trace.live_trace_sink()
            inner.write("nobody listens\n")
            assert inner.getvalue() == "nobody listens\n"
        finally:
            live_trace.end_run(token)
        return run

    assert asyncio.run(_no_listener()).published == 0


def test_sink_publishes_the_last_redraw_and_the_tail() -> None:
    def work() -> str:
        sink = live_trace.live_trace_sink()
        sink.write("\x1b[32mstep 1\x1b[0m\n\n10%\r55%\r100%")
        sink.write("x" * (live_trace.MAX_LINE_CHARS + 10) + "\n")
        return sink.getvalue()

    _run, _text, frames = asyncio.run(_run_published(work))
    lines = [frame["line"] for frame in frames]
    assert lines[0] == "step 1"
    assert lines[1].startswith("100%x")
    assert lines[1].endswith("chars]")
    assert len(lines) == 2


def test_a_full_queue_drops_lines_and_a_closed_loop_is_skipped() -> None:
    async def scenario() -> int:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=2)
        detach = live_trace.get_bus().attach(queue, asyncio.get_running_loop())
        for index in range(5):
            live_trace.get_bus().publish({"event": "trace", "line": str(index)})
        await asyncio.sleep(0.05)
        detach()
        return queue.qsize()

    assert asyncio.run(scenario()) == 2

    dead_loop = asyncio.new_event_loop()
    dead_loop.close()
    detach = live_trace.get_bus().attach(asyncio.Queue(), dead_loop)
    try:
        assert live_trace.get_bus().publish({"event": "trace", "line": "late"}) == 0
    finally:
        detach()
    assert live_trace.get_bus().subscriber_count() == 0


def test_run_action_tags_the_lines_of_its_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def dispatcher(ctx: Any) -> dict[str, Any]:
        sink = live_trace.live_trace_sink()
        with contextlib.redirect_stdout(sink):
            print("[*] step one")
        return {"trace": sink.getvalue()}

    spec = ActionSpec(
        id="demo.live_trace",
        subsystem="Demo",
        title="Demo",
        description="Prints one line.",
        inputs=(),
        output_kind="json",
        dispatcher=dispatcher,
    )

    class _Registry:
        def get(self, action_id: str) -> ActionSpec:
            return spec

    monkeypatch.setattr(actions_routes, "ensure_builtin_actions_loaded", lambda: _Registry())

    async def scenario() -> tuple[Any, Any, list[dict[str, Any]]]:
        silent = await actions_routes.run_action(spec.id, actions_routes.RunRequest(inputs={}))
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=8)
        detach = live_trace.get_bus().attach(queue, asyncio.get_running_loop())
        try:
            live = await actions_routes.run_action(
                spec.id, actions_routes.RunRequest(inputs={}, trace_id="page-7")
            )
            await asyncio.sleep(0.05)
        finally:
            detach()
        frames = []
        while not queue.empty():
            frames.append(queue.get_nowait())
        return silent, live, frames

    silent, live, frames = asyncio.run(scenario())
    assert silent.ok and silent.data == {"trace": "[*] step one\n"}
    assert live.ok and live.data == silent.data
    assert [(frame["trace_id"], frame["line"]) for frame in frames] == [("page-7", "[*] step one")]


def test_trace_id_is_a_plain_token() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        actions_routes.RunRequest(inputs={}, trace_id="<script>")
    with pytest.raises(ValidationError):
        actions_routes.RunRequest(inputs={}, trace_id="x" * 65)


def test_trace_socket_is_registered_and_token_gated() -> None:
    app_source = (REPO / "yggdrasim_common" / "gui_server" / "app.py").read_text(encoding="utf-8")
    assert "app.include_router(trace_event_routes.router)" in app_source
    route_source = (
        REPO / "yggdrasim_common" / "gui_server" / "routes" / "trace_events.py"
    ).read_text(encoding="utf-8")
    assert '@router.websocket("/api/events/trace")' in route_source
    assert route_source.index("compare_tokens(expected, provided)") < route_source.index("websocket.accept(")


def test_page_shows_live_lines_and_loads_a_dropped_profile() -> None:
    source = REPO / "gui_frontend" / "src" / "js"
    trailing = (source / "trailing.js").read_text(encoding="utf-8")
    center = (source / "command-center.js").read_text(encoding="utf-8")
    assert '"/api/events/trace"' in trailing
    assert center.count("trace_id: liveTrace.id") == 2
    assert center.count("liveTrace.end();") == 2
    assert "ccLiveTraceTakeDelivered(actionId)" in center
    assert "function ccLiveTraceTakeDelivered(" in trailing
    panel = center[center.index("function _buildLocalSmdpOverviewPanel"):center.index("function _buildLocalEimOverviewPanel")]
    assert "enablePanelFileDrop(panel," in panel
    assert panel.count('runLocalSmdpAction("scp11_local.load_profile"') == 1
    load = panel[panel.index("async function loadProfile()"):panel.index("addTool(\"import\", \"Load profile\"")]
    assert "refreshOverviewAfterLoad();" in load
    assert "ccCardOverviewSkipReason(scopedReader)" in panel
    assert "Drop one profile package at a time." in panel
