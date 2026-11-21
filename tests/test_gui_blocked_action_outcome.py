# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Source contract for actions that answer HTTP 200 after refusing to produce."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMAND_JS = ROOT / "gui_frontend/src/js/command-center.js"
APP_JS = ROOT / "yggdrasim_common/gui_server/static/app.js"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _sources() -> tuple[str, str]:
    return (_read(COMMAND_JS), _read(APP_JS))


def test_every_refusing_materialization_state_is_recognised() -> None:
    # The generator returns before writing an artifact or opening a session,
    # so each of these must reach the operator as a refusal rather than as a
    # completed run with an empty result.
    for js in _sources():
        block = js.split("CC_BLOCKED_MATERIALIZATION_STAGES = {", 1)[1].split("};", 1)[0]
        for state in (
            "NO_COMPATIBLE_FILESYSTEM_LAYOUT",
            "BLOCKED_BY_INTENT",
            "BLOCKED_BY_PLAN",
            "BLOCKED_BY_COMPILATION",
        ):
            assert state in block, f"unhandled refusal state: {state}"


def test_a_refused_run_reports_blocked_rather_than_completed() -> None:
    for js in _sources():
        assert 'ccSetActionStatus(statusEl, refused ? "blocked" : "success")' in js
        assert 'resultEl.dataset.state = refused ? "error" : "success"' in js
        assert 'level: refused ? "warn" : "info"' in js


def test_blocking_diagnostics_are_summarised_above_the_raw_result() -> None:
    for js in _sources():
        summary = js.split("function ccRenderBlockedActionSummary(", 1)[1].split(
            "function renderActionResult(", 1
        )[0]
        # Grouped by code with the cells that raised it, so 38 identical plan
        # errors stay one readable line instead of flooding the panel.
        assert "group.code" in summary
        assert "group.cells.slice(0, 8)" in summary
        assert "container.appendChild(block)" in summary

    collect = _read(COMMAND_JS).split("function ccCollectBlockingDiagnostics(", 1)[1]
    collect = collect.split("function ccRenderBlockedActionSummary(", 1)[0]
    assert '"filesystem_intent", "filesystem_plan"' in collect
    assert 'String(item.severity || "") !== "ERROR"' in collect


def test_the_summary_builds_dom_nodes_rather_than_markup() -> None:
    # The page CSP forbids inline script and eval'd markup.
    summary = _read(COMMAND_JS).split("function ccRenderBlockedActionSummary(", 1)[1]
    summary = summary.split("function renderActionResult(", 1)[0]
    assert "innerHTML" not in summary
    assert "createElement" in summary
    assert "textContent" in summary
