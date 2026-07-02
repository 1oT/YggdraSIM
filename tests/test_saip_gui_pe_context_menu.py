# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Static GUI contracts for the SAIP PE-list context menu."""

from __future__ import annotations

from pathlib import Path


_APP_JS = Path("yggdrasim_common/gui_server/static/app.js")


def _read_app_js() -> str:
    return _APP_JS.read_text(encoding="utf-8")


def test_pe_cards_open_action_context_menu() -> None:
    js = _read_app_js()
    assert 'card.addEventListener("contextmenu"' in js
    assert "function saipShowPeContextMenu(" in js
    assert "saip-pe-context-menu" in js


def test_pe_context_menu_reuses_ribbon_actions() -> None:
    js = _read_app_js()
    for needle in (
        'label: "Add PE above"',
        'label: "Add PE below"',
        'label: "Import PE below"',
        'label: "Export PE"',
        'label: "Move up"',
        'label: "Move down"',
        'label: "Reference card"',
        'label: anchor ? "Delete PE (anchor)" : "Delete PE"',
        'saipRibbonAddPe(pkg, "above"',
        'saipRibbonDeletePe(pkg, peList, detail, validation)',
    ):
        assert needle in js
