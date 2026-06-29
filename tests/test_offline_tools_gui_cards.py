# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relpath: str) -> str:
    return (ROOT / relpath).read_text(encoding="utf-8")


def test_topbar_uses_yggdrasil_mark() -> None:
    index = _read("gui_frontend/src/index.html")
    shell_css = _read("gui_frontend/src/css/layout/shell.css")

    assert '<span class="brand-mark">YS</span>' not in index
    assert "brand-mark-svg" in index
    assert "brand-ring" in index
    assert "brand-core" in index
    assert ".brand-mark-svg" in shell_css
    assert "border-radius: 50%;" in shell_css


def test_offline_tools_action_rail_has_card_hooks() -> None:
    command_js = _read("gui_frontend/src/js/command-center.js")
    compact_css = _read("gui_frontend/src/css/views/command-center-compact-pane.css")

    assert "CC_OFFLINE_TOOLS_HIDDEN_ACTIONS" in command_js
    assert '"tool.euicc_info2.decode": true' in command_js
    assert '"tool.saip.lint": true' in command_js
    assert '"suci.status": true' in command_js
    assert '"tool.tlv.decode": true' in command_js
    assert 'subsystem === "Offline Tools"' in command_js
    assert "cc-workbench--offline-tools" in command_js
    assert "cc-compact-rbtn-desc" in command_js
    assert "cc-compact-rbtn-meta" in command_js
    assert "cc-inline-action-pane" in command_js
    assert "_openInlineActionPane(action)" in command_js
    assert "currentInlineActionPane" in command_js
    assert ".cc-workbench--offline-tools .cc-compact-rbtn" in compact_css
    assert "grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));" in compact_css
    assert ".cc-inline-action-pane" in compact_css
    assert ".cc-inline-action-form" in compact_css


def test_built_static_contains_offline_tools_cards_and_brand() -> None:
    static_index = _read("yggdrasim_common/gui_server/static/index.html")
    static_js = _read("yggdrasim_common/gui_server/static/app.js")
    static_css = _read("yggdrasim_common/gui_server/static/app.css")

    assert "brand-mark-svg" in static_index
    assert "brand-ring" in static_index
    assert "CC_OFFLINE_TOOLS_HIDDEN_ACTIONS" in static_js
    assert '"tool.euicc_info2.decode": true' in static_js
    assert '"tool.saip.lint": true' in static_js
    assert '"suci.status": true' in static_js
    assert '"tool.tlv.decode": true' in static_js
    assert "cc-workbench--offline-tools" in static_js
    assert "cc-compact-rbtn-meta" in static_js
    assert "cc-inline-action-pane" in static_js
    assert "_openInlineActionPane(action)" in static_js
    assert "currentInlineActionPane" in static_js
    assert ".cc-workbench--offline-tools .cc-compact-rbtn" in static_css
    assert ".cc-inline-action-pane" in static_css
    assert ".cc-inline-action-form" in static_css
