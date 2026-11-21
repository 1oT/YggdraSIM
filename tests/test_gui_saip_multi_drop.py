# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Several files dropped on the SAIP workbench all open, and stay open.

Source-level pins on the canonical frontend (the served bundle is rebuilt
from it): the shared drop extractor returns every path a drop carries,
the workbench walks every dropped file through its single open pipeline,
and the sessions behind the drawer are touched while the page lives so a
package left open never reaches the backend's idle ceiling.
"""

from __future__ import annotations

import re
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_WORKBENCH = _ROOT / "gui_frontend/src/js/saip-workbench.js"
_TRAILING = _ROOT / "gui_frontend/src/js/trailing.js"
_SHELL_CSS = _ROOT / "gui_frontend/src/css/views/saip/workbench-shell.css"


def _between(body: str, start_marker: str, end_marker: str) -> str:
    start = body.index(start_marker)
    end = body.index(end_marker, start)
    return body[start:end]


def test_drop_extractor_returns_every_path_and_the_single_path_helper_delegates() -> None:
    js = _TRAILING.read_text(encoding="utf-8")
    plural = _between(
        js,
        "  function extractPathsFromDrop(event) {",
        "\n  function extractPathFromDrop(event) {",
    )
    assert "for (var i = 0; i < dt.files.length; i += 1)" in plural
    assert "paths.push(f.path);" in plural
    assert 'getData("text/uri-list")' in plural
    assert "if (decoded) paths.push(decoded);" in plural
    assert 'getData("text/plain")' in plural
    assert "return [txt.trim()];" in plural

    single = _between(js, "  function extractPathFromDrop(event) {", "\n  }\n")
    assert "extractPathsFromDrop(event)" in single
    assert 'paths.length > 0 ? paths[0] : ""' in single
    assert "window.YggdraSimExtractPathsFromDrop = extractPathsFromDrop;" in js
    assert "window.YggdraSimExtractPathFromDrop = extractPathFromDrop;" in js


def test_workbench_drop_walks_every_dropped_file_in_drop_order() -> None:
    body = _WORKBENCH.read_text(encoding="utf-8")
    css = _SHELL_CSS.read_text(encoding="utf-8")
    assert "saipFirstDroppedFile" not in body

    files_fn = _between(body, "  function saipDroppedFiles(event) {", "\n  }\n")
    assert "for (var i = 0; i < dt.files.length; i += 1)" in files_fn
    assert "if (f && f.name) files.push(f);" in files_fn

    drop = _between(
        body,
        "  function wireSaipWorkbenchDrop(wb) {",
        "\n  // Open every entry of one drop",
    )
    assert "window.YggdraSimExtractPathsFromDrop" in drop
    assert "var files = saipDroppedFiles(event);" in drop
    assert "entries.then(saipOpenDroppedEntries)" in drop

    batch = _between(
        body,
        "  async function saipOpenDroppedEntries(entries) {",
        "\n  function renderSaipWorkbench(",
    )
    assert "for (var i = 0; i < entries.length; i += 1)" in batch
    assert "await saipOpenPackageByPath(" in batch
    assert "await saipOpenPackageByDroppedFile(" in batch
    assert "commandState.saipWorkbench.activePackageId = openedIds[0];" in batch
    assert "one drop routes a single workbook to the generator" in batch

    # The operator-facing copy says so too.
    assert "You can also drop one or more files anywhere in this workspace." in body
    assert 'content: "Drop SAIP packages here to load them";' in css


def test_open_sessions_are_touched_while_the_page_lives() -> None:
    body = _WORKBENCH.read_text(encoding="utf-8")
    beat = _between(
        body,
        "  function saipKeepOpenSessionsAlive() {",
        "\n  function saipStartSessionKeepalive() {",
    )
    assert "if (!pkg || !pkg.sessionId || pkg.sessionUnavailable) continue;" in beat
    assert "pending.push(saipRefreshDirty(pkg));" in beat

    start = _between(body, "  function saipStartSessionKeepalive() {", "\n  }\n")
    assert "if (_saipKeepaliveTimer !== null) return;" in start
    assert "window.setInterval(" in start
    assert "SAIP_SESSION_KEEPALIVE_MS" in start
    assert 'document.visibilityState === "visible"' in start

    # Every surface that opens a package funnels through the shared
    # pipeline, so that is where the beat starts.
    activate = _between(
        body,
        "  function saipActivateOpenedPackage(",
        "\n  async function saipOpenPackageByPath(",
    )
    assert "saipStartSessionKeepalive();" in activate


def test_keepalive_beat_sits_well_inside_the_backend_idle_ceiling() -> None:
    body = _WORKBENCH.read_text(encoding="utf-8")
    match = re.search(r"var SAIP_SESSION_KEEPALIVE_MS = (\d+) \* 60 \* 1000;", body)
    assert match is not None
    beat_s = int(match.group(1)) * 60

    from yggdrasim_common.gui_server.actions import saip as saip_actions

    ceiling_s = int(saip_actions._AUTHORING_SESSION_IDLE_TIMEOUT_S)
    # A dozen missed beats (a window hidden with throttled timers) still
    # leave the session alive.
    assert beat_s * 12 <= ceiling_s
