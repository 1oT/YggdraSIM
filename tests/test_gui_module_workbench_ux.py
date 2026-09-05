# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Static contracts for coherent module-workbench interaction styling."""

from __future__ import annotations

import re
from pathlib import Path


VIEWS = (
    Path(__file__).resolve().parents[1]
    / "gui_frontend"
    / "src"
    / "css"
    / "views"
)


def _css(name: str) -> str:
    return (VIEWS / name).read_text(encoding="utf-8")


def _block(source: str, selector: str) -> str:
    match = re.search(
        re.escape(selector) + r"\s*\{(?P<body>[^}]+)\}",
        source,
    )
    assert match is not None, f"missing CSS selector: {selector}"
    return match.group("body")


def test_remote_lab_uses_themed_responsive_surfaces() -> None:
    css = _css("remote-lab.css")

    assert css.count("SPDX-License-Identifier") == 1
    assert "var(--panel)" not in css
    assert "background: var(--bg-elev);" in _block(css, ".remote-lab-card")
    assert "background: var(--bg-elev);" in _block(
        css, ".remote-lab-import-panel"
    )
    assert "minmax(min(100%, 280px), 1fr)" in css
    assert ".remote-lab-import-panel textarea:focus-visible" in css
    assert "@media (max-width: 640px)" in css


def test_remote_lab_statuses_share_semantic_theme_colours() -> None:
    css = _css("remote-lab.css")

    for token in ("--ok-soft", "--warn-soft", "--fail-soft"):
        assert f"var({token})" in css
    for token in ("--ok", "--warn", "--fail"):
        assert f"var({token})" in css
    assert "text-transform: uppercase;" in _block(css, ".remote-lab-status")
    assert ".remote-lab-status::before" in css
    assert "--remote-lab-status-color: var(--ok);" in css
    assert "color: var(--fg);" in _block(
        css, ".remote-lab-status--available"
    )


def test_remote_bridge_status_rows_are_independent_grids() -> None:
    css = _css("misc-trailing.css")
    status_grid = _block(css, ".cb-status-grid")
    status_row = _block(css, ".cb-status-row")

    assert "display: flex;" in status_grid
    assert "flex-direction: column;" in status_grid
    assert "display: contents;" not in status_row
    assert "display: grid;" in status_row
    assert "minmax(0, 1fr)" in status_row
    assert ".cb-status-label {\n    grid-column: 1 / -1;" in css


def test_remote_bridge_cards_collapse_without_horizontal_overflow() -> None:
    css = _css("misc-trailing.css")

    for minimum in ("190px", "160px", "180px"):
        assert f"minmax(min(100%, {minimum}), 1fr)" in css
    assert ".cb-override summary:focus-visible" in css
    assert "font-family: var(--font-mono);" in _block(css, ".cb-mono")
    assert "background: var(--cb-badge-status);" in _block(
        css, ".cb-badge::before"
    )
    assert "color: var(--fg);" in _block(css, ".cb-badge-fail")


def test_record_disclosures_have_hover_focus_and_direction_cues() -> None:
    css = _css("records-viewer.css")

    assert '.cc-record-head::before {\n  content: "▸";' in css
    assert ".cc-record[open] > .cc-record-head::before" in css
    assert ".cc-record-head:hover" in css
    assert ".cc-record-head:focus-visible" in css
    assert ".cc-payload-update-btn:focus-visible" in css
    assert "@media (max-width: 560px)" in css
    assert "grid-template-columns: 1fr;" in css


def test_scp03_disclosures_and_search_have_keyboard_focus_cues() -> None:
    bulk = _css("scp03-bulk.css")
    trace = _css("scp03-datasheet-decoded.css")
    datasheet = _css("scp03-datasheet-chip.css")
    no_card = _css("scp03-fcp-builder.css")

    for selector, source in (
        (".cc-stage-context-summary:focus-visible", bulk),
        (".cc-pv-collapsible-head:focus-visible", bulk),
        (".cc-svc-stage-search:focus-visible", bulk),
        (".cc-action-datasheet-trace > summary:focus-visible", trace),
        (".cc-action-datasheet-raw.cc-details > summary:focus-visible", datasheet),
        (".cc-no-card-notice details summary:focus-visible", no_card),
    ):
        assert selector in source


def test_scp03_apdu_panel_is_usable_at_narrow_widths() -> None:
    css = _css("scp11-live.css")

    assert "width: min(320px, 100%);" in _block(
        css, ".scp03-apdu-preset-select"
    )
    assert "overflow-x: auto;" in _block(css, ".scp03-apdu-breakdown")
    assert "flex-wrap: wrap;" in _block(css, ".scp03-apdu-actions")
    assert "@media (max-width: 640px)" in css
    assert ".scp03-apdu-actions .btn {\n    flex: 1 1 130px;" in css
    assert "color: var(--fg);" in _block(css, ".scp03-apdu-sw-chip--ok")


def test_scp03_tables_and_fs_wizards_keep_content_reachable() -> None:
    popout = _css("scp03-popout-kvl.css")
    wizard = _css("eim-local.css")

    assert "overflow-x: auto;" in _block(
        popout, ".cc-action-datasheet-main"
    )
    assert "overflow-x: auto;" in _block(wizard, ".cc-fs-mode-bar")
    assert "overflow-x: auto;" in _block(
        wizard, ".cc-fs-breakdown-wrap"
    )
    assert "min-width: 440px;" in _block(wizard, ".cc-fs-breakdown")
