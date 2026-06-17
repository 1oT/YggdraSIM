"""Static contract for reader-as-session plumbing (Task 2 of the v1.1 sweep).

The operator-visible promise is that activating a top-bar reader pill
turns every subsequently launched module — both Command Center actions
and CLI/PTY shells — into a session that operates on that exact reader.
The wiring spans three layers and must stay coherent across silent
refactors:

  1. ``readerBarActivate`` must mirror its argument into the legacy
     ``YggdraSimReaderStore`` so the action-form prefill path picks the
     right default. Without this bridge the action card's reader
     dropdown silently falls back to "(default / first reader)".
  2. ``runActionFromForm`` must run ``applyActiveReaderDefault`` so any
     reader-kind input that the operator left blank is filled in from
     the active pill at submit time. This covers cards opened *before*
     the operator picked a pill.
  3. The PTY launcher (``startTerminal``) must forward the active pill
     name as ``?reader=<name>`` so the backend can export
     ``YGGDRASIM_READER`` into the spawned shell's environment, where
     ``yggdrasim_common.card_backend.create_card_connection`` resolves
     it to the matching PC/SC reader index.

Pure file-read assertions; no FastAPI / browser surface required.
"""

from __future__ import annotations

from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"
ROUTES = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "routes"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# Frontend wiring
# ----------------------------------------------------------------------


def test_reader_bar_activate_bridges_to_reader_store() -> None:
    js = _read(STATIC / "app.js")
    activate_start = js.index("function readerBarActivate(readerName)")
    activate_window = js[activate_start : activate_start + 4000]
    assert "YggdraSimReaderStore" in activate_window, (
        "readerBarActivate must mirror the active pill into the legacy "
        "reader store so action forms inherit the choice on prefill."
    )
    assert "setSelected(" in activate_window, (
        "readerBarActivate must call YggdraSimReaderStore.setSelected()."
    )


def test_run_action_form_fills_blank_reader_input() -> None:
    js = _read(STATIC / "app.js")
    helper_start = js.index("function applyActiveReaderDefault(action, inputs)")
    helper_window = js[helper_start : helper_start + 2500]
    assert 'field.kind !== "reader"' in helper_window, (
        "applyActiveReaderDefault must skip non-reader inputs."
    )
    assert "commandState.readerBar" in helper_window, (
        "applyActiveReaderDefault must read the active pill from "
        "commandState.readerBar.activeReader."
    )

    run_start = js.index("async function runActionFromForm(action, form")
    run_window = js[run_start : run_start + 1500]
    assert "applyActiveReaderDefault(action, inputs)" in run_window, (
        "runActionFromForm must apply the active reader default before "
        "dispatching the run/stream payload."
    )


def test_pty_launcher_forwards_active_reader_query_param() -> None:
    js = _read(STATIC / "app.js")
    start_idx = js.index("function startTerminal()")
    start_window = js[start_idx : start_idx + 4000]
    assert "commandState.readerBar.activeReader" in start_window, (
        "startTerminal must read the active reader from commandState.readerBar."
    )
    assert '"&reader=" + encodeURIComponent(activeReader)' in start_window, (
        "startTerminal must append &reader=<name> to the WebSocket URL "
        "when an active reader pill is selected."
    )


# ----------------------------------------------------------------------
# Backend PTY route wiring
# ----------------------------------------------------------------------


def test_terminal_route_exports_yggdrasim_reader_env() -> None:
    py = _read(ROUTES / "terminal.py")
    assert 'websocket.query_params.get("reader")' in py, (
        "terminal route must read the ?reader= query parameter."
    )
    assert 'YGGDRASIM_READER' in py, (
        "terminal route must export YGGDRASIM_READER into the PTY child "
        "environment so spawned shells inherit the active reader."
    )
    # PtyStartSpec.env is the only legitimate channel — anything else
    # would mean the env var was applied to the host process, which is
    # a footgun across concurrent tabs.
    assert "env=spec_env" in py, (
        "terminal route must thread the reader env through PtyStartSpec.env, "
        "not via os.environ."
    )
