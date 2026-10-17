# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Token editor dock contracts against the built bundle.

The token editor is a docked panel in the third column of the workbench
grid, not a modal: it carries no backdrop, no blur over the workbench
and no focus trap, so the profile stays editable while values are
bound. It repaints only when the data it shows changed, keeps the
mounted form while the variable listing reloads, and shares one
``list_variables`` request between the surfaces that ask for it. The
variables table folds into stacked rows for the dock's width; its state
chips wrap and the list column clips instead of scrolling.
"""

from __future__ import annotations

import re
from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _css() -> str:
    return (STATIC / "app.css").read_text(encoding="utf-8")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _rule(css: str, selector: str) -> str:
    """Declarations of the rule whose selector list is exactly *selector*."""
    match = re.search(r"(?:^|\n)" + re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert match is not None, selector
    return match.group(1)


def _between(body: str, start: str, end: str) -> str:
    begin = body.index(start)
    return body[begin : body.index(end, begin)]


def test_state_chips_wrap_inside_the_list_column() -> None:
    css = _css()
    state = _rule(css, ".saip-vars-state")
    assert "white-space: normal" in state
    assert "nowrap" not in state
    # Wrapped chips need vertical breathing room between lines.
    assert "margin: 1px 4px 1px 0" in _rule(css, ".saip-vars-state-chip")


def test_kind_chip_stays_on_one_line() -> None:
    assert "white-space: nowrap" in _rule(_css(), ".saip-vars-kind")


def test_list_column_clips_instead_of_scrolling() -> None:
    """``clip`` keeps the table inside the dock; ``auto`` would turn the
    column into a second scroll container inside the dock body."""
    column = _rule(_css(), ".saip-token-col--list")
    assert "overflow-x: clip" in column
    assert "auto" not in column


def test_dock_is_a_grid_column_not_a_floating_surface() -> None:
    css = _css()
    dock = _rule(css, ".saip-token-dock")
    assert "position: relative" in dock
    assert "fixed" not in dock
    assert "backdrop-filter" not in _between(css, ".saip-token-dock {", ".saip-token-bind-card {")
    assert "var(--saip-token-dock-width)" in _rule(css, ".saip-layout--token-dock")
    assert "var(--saip-token-dock-width)" in _rule(
        css, ".saip-layout--drawer-collapsed.saip-layout--token-dock"
    )
    # The single-column breakpoints must still win over the dock modifier.
    narrow = css[css.index("@media (max-width: 1100px)") :]
    assert ".saip-layout.saip-layout--token-dock," in narrow
    assert ".saip-layout.saip-layout--drawer-collapsed.saip-layout--token-dock" in narrow


def test_variable_rows_fold_for_the_dock_width() -> None:
    css = _css()
    row = _rule(css, ".saip-token-dock .saip-token-table tr")
    assert "display: grid" in row
    assert '"name kind actions"' in row
    assert '"value value value"' in row
    assert '"state state state"' in row
    value = _rule(css, ".saip-token-dock .saip-token-table .saip-vars-val")
    assert "white-space: normal" in value
    assert "overflow-wrap: anywhere" in value
    head = _rule(css, ".saip-token-dock .saip-token-table thead")
    assert "clip: rect(0 0 0 0)" in head
    assert "display: none" not in head


def test_dock_is_not_a_modal() -> None:
    js = _js()
    dock = _between(js, "  function renderSaipTokenDock() {", "\n  // SA-G1: ``renderSaipPeList``")
    assert "aria-modal" not in dock
    assert "saip-modal-backdrop" not in dock
    assert 'ev.key !== "Tab"' not in dock
    assert "saip-token-modal" not in js
    assert "Close token editor (same as Esc)." not in js
    assert 'tokenDock.className = "saip-token-dock"' in js
    assert "layout.appendChild(tokenDock)" in js
    assert 'layout.classList.toggle("saip-layout--token-dock", open)' in js


def test_escape_closes_the_dock_only_from_inside_it() -> None:
    shortcuts = _between(
        _js(),
        "  function saipShortcutHandler(evt) {",
        "\n    // Ctrl+Shift+V -- Validate.",
    )
    assert "dockEl.contains(evt.target)" in shortcuts
    assert "closeSaipTokenDock();" in shortcuts
    assert "toggleSaipTokenDock(pkg.id, true);" in shortcuts


def test_ribbon_button_toggles_and_reports_the_dock_state() -> None:
    ribbon = _between(
        _js(), '    var varsGrp = mkGroup("Tokens");', "\n    // -- Lint commands"
    )
    assert "toggleSaipTokenDock(pkg.id, false);" in ribbon
    assert 'tokenEditorBtn.setAttribute("data-saip-ribbon", "token-editor");' in ribbon
    assert '"aria-pressed"' in ribbon


def test_dock_repaints_only_when_its_data_changed() -> None:
    js = _js()
    dock = _between(js, "  function renderSaipTokenDock() {", "\n  // SA-G1: ``renderSaipPeList``")
    assert "saipTokenDockKeyEquals(host.__saipDockKey, key)" in dock
    assert 'host.setAttribute("aria-busy", "true");' in dock
    assert "saipTokenDockRestoreDraft(host, draft);" in dock
    assert "saipTokenDockConsumeFocus(host);" in dock
    active_slots = _between(
        js, "  function renderSaipActiveSlots(", "\n  function renderSaipTabBody("
    )
    assert "renderSaipTokenDock();" in active_slots
    # The pane no longer grabs focus on every paint.
    pane = _between(js, "  function renderSaipVariablesPane(", "\n  function saipTokenExportBaseName(")
    assert "setTimeout(function () { nameInp.focus(); }, 0);" not in pane
    # The Set form comes before the variable list in the dock.
    assert pane.index('"saip-token-col saip-token-col--bind"') < pane.index(
        '"saip-token-col saip-token-col--list"'
    )


def test_variable_listing_requests_are_shared_and_never_land_stale() -> None:
    loader = _between(
        _js(), "  async function saipLoadVariables(pkg) {", "\n  function saipDrawerEl() {"
    )
    assert "pkg.variablesRequestGeneration === generation" in loader
    assert "return pkg.variablesRequest;" in loader
    assert "if ((pkg.variablesGeneration || 0) !== generation) return;" in loader
    js = _js()
    assert "pkg.variables = null;" not in js.replace(
        _between(js, "  function saipInvalidateVariables(pkg) {", "\n  async function saipLoadVariables("),
        "",
    )
    assert "pkg.variablesGeneration = (pkg.variablesGeneration || 0) + 1;" in js


def test_set_keeps_the_name_and_clears_the_value_only_on_success() -> None:
    pane = _between(
        _js(), "  function renderSaipVariablesPane(", "\n  function saipTokenExportBaseName("
    )
    assert "if (secret || stored) valInp.value = \"\";" in pane
    assert "if (stored && form.isConnected) {" in pane
    assert "nameInp.select();" in pane
    apply = _between(_js(), "  async function saipApplyVariable(", "\n  // SA-4 compare pane")
    assert apply.count("return false;") == 3
    assert "return true;" in apply
