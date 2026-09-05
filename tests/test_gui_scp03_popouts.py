# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the inline action-panel system.

Background
----------
Action output used to spawn floating ``.cc-popout`` windows: draggable,
resizable, maximizable, ``position: fixed``, anchored to a global
``#cc-popout-host`` outside the tab body so a rerender could not touch
them. That made them persistent across tab-body renders, which was the
point, but it also meant a session accumulated windows the operator had
to close by hand, stacked over the surface they came from.

Action output now renders as ``.cc-panel`` sections in normal document
flow, stacked in the surface that opened them. Nothing is positioned
against the viewport and nothing outlives its host: leaving the tab or
the subsystem takes the panel with it. The contract the 68 callers rely
on -- "I get back an element I append children to" -- is unchanged;
``scp03BuildExtrasCard`` and ``_ccBuildCompactPopout`` both return a
panel body.

Because ``scp03RenderTabBody`` wipes the tab body on every render, the
panel elements are owned by the tab object and re-mounted afterwards.
That is what scopes them per tab now that nothing floats.

All tests are static-bundle contracts against ``app.js`` / ``app.css``.
"""

from __future__ import annotations

import re
from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def _function_source(js: str, signature: str) -> str:
    """Source of one top-level helper, up to the next top-level function.

    Nested callbacks contain ``function (`` too, so the window has to end
    on the two-space indent the bundle uses for top-level helpers.
    """
    start = js.index(signature)
    match = re.search(r"\n  function ", js[start + len(signature):])
    end = len(js) if match is None else start + len(signature) + match.start()
    return js[start:end]


def _strip_css_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


# ----------------------------------------------------------------------
# Panel primitive surface.
# ----------------------------------------------------------------------


def test_panel_helpers_defined() -> None:
    """The panel system ships as a cohesive set of helpers."""
    js = _read("app.js")
    for helper in (
        "function ccPanelStack(",
        "function ccPanelMarkLatest(",
        "function ccPanelRestoreFocus(",
        "function ccPanelRemove(",
        "function ccPanelCloseLast(",
        "function ccPanelEscapeBootstrap(",
        "function ccInlinePanel(",
        "function ccPanelScrollIntoView(",
    ):
        assert helper in js, helper


def test_floating_window_machinery_is_gone() -> None:
    """No drag, no maximize, no z-order, no viewport anchoring."""
    js = _read("app.js")
    for symbol in (
        "scp03PopoutInstallDrag",
        "scp03PopoutToggleMaximize",
        "scp03PopoutBringToFront",
        "scp03PopoutHost",
        "scp03PopoutNextZ",
        "scp03PopoutComputeOrigin",
        "scp03PopoutDefaultSize",
        "ccPopoutUsableBottom",
        "ccPopoutRefreshViewportBounds",
        "_ccCompactPopoutMap",
        "cc-popout",
    ):
        assert symbol not in js, symbol


def test_escape_closes_the_last_panel_and_defers_to_modals() -> None:
    js = _read("app.js")
    start = js.index("function ccPanelEscapeBootstrap(")
    window = js[start : js.index("function ccInlinePanel(", start)]
    assert 'ev.key !== "Escape"' in window
    # A true modal owns Escape while it is open.
    assert '[role="dialog"][aria-modal="true"]' in window
    assert "if (modalOpen) return;" in window
    assert "ccPanelCloseLast()" in window


def test_escape_handler_bootstraps_at_init() -> None:
    js = _read("app.js")
    assert "scp03PopoutEscapeBootstrap" in js
    start = js.index("function scp03PopoutEscapeBootstrap(")
    body = js[start : js.index("}", js.index("{", start)) + 1]
    assert "ccPanelEscapeBootstrap()" in body


# ----------------------------------------------------------------------
# A panel is a region in flow, not a dialog.
# ----------------------------------------------------------------------


def test_panel_is_a_labelled_region_not_a_dialog() -> None:
    js = _read("app.js")
    start = js.index("function ccInlinePanel(")
    window = js[start : js.index("function ccPanelScrollIntoView(", start)]
    assert 'panel.setAttribute("role", "region")' in window
    assert 'panel.setAttribute("aria-labelledby", titleEl.id)' in window
    assert "aria-modal" not in window
    # The panel is not focusable and traps nothing; the heading takes
    # focus on open so the result is announced.
    assert 'panel.setAttribute("tabindex"' not in window
    assert 'titleEl.setAttribute("tabindex", "-1")' in window


def test_opening_a_panel_announces_it_without_stealing_form_focus() -> None:
    js = _read("app.js")
    window = _function_source(js, "function ccPanelFocusHeading(")
    assert '.cc-panel-title' in window
    # An action form moves focus to its first field instead.
    assert 'if (panel.querySelector("form")) return;' in window


def test_panel_dedupes_by_key_within_its_stack() -> None:
    js = _read("app.js")
    start = js.index("function ccInlinePanel(")
    window = js[start : js.index("function ccPanelScrollIntoView(", start)]
    assert 'data-panel-key' in window
    assert "reuseBody.innerHTML = \"\"" in window


def test_close_button_runs_the_owner_teardown() -> None:
    """``onClose`` is how an owner drops its bookkeeping entry."""
    js = _read("app.js")
    window = _function_source(js, "function ccPanelRemove(")
    assert 'typeof panel.__onClose === "function"' in window
    assert "panel.__onClose()" in window


# ----------------------------------------------------------------------
# Builder contracts: both return a body element.
# ----------------------------------------------------------------------


def test_build_extras_card_returns_a_panel_body() -> None:
    js = _read("app.js")
    window = _function_source(js, "function scp03BuildExtrasCard(")
    assert "ccInlinePanel(scp03PanelHost()" in window
    assert "return body;" in window


def test_build_extras_card_registers_on_active_tab() -> None:
    js = _read("app.js")
    window = _function_source(js, "function scp03BuildExtrasCard(")
    assert "tab.popouts[key] = body.closest(\".cc-panel\")" in window
    assert "delete tab.popouts[key]" in window


def test_compact_builder_docks_into_the_active_workbench() -> None:
    js = _read("app.js")
    window = _function_source(js, "function ccCompactPanelHost(")
    for selector in (".cc-hil-body", ".cc-workbench--compact", ".cc-workbench"):
        assert selector in window, selector
    assert "section.view.view-active" in window


def test_create_empty_tab_seeds_panel_state() -> None:
    js = _read("app.js")
    assert "popouts: {}," in js
    # The floating-only cursors are gone.
    assert "popoutZCursor" not in js
    assert "popoutCascadeIdx" not in js


def test_close_tab_tears_down_panels() -> None:
    js = _read("app.js")
    window = _function_source(js, "function scp03PopoutCloseAllForTab(")
    assert "ccPanelRemove(panel, false)" in window
    assert "tab.popouts = {};" in window


def test_tab_render_remounts_the_active_tab_panels() -> None:
    js = _read("app.js")
    window = _function_source(js, "function scp03RemountPanels(")
    assert "ccPanelStack(host)" in window
    assert "stack.appendChild(panel)" in window

    sync_window = _function_source(
        js, "function scp03PopoutSyncVisibilityToActiveTab("
    )
    assert "scp03RemountPanels(active)" in sync_window
    # Visibility is no longer juggled with ``hidden``.
    assert "popout.hidden" not in sync_window


# ----------------------------------------------------------------------
# CSS contract.
# ----------------------------------------------------------------------


def test_css_defines_panel_selectors() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-panel-stack",
        ".cc-panel {",
        ".cc-panel-titlebar",
        ".cc-panel-title",
        ".cc-panel-actions",
        ".cc-panel-btn",
        ".cc-panel-body",
    ):
        assert selector in css, selector


def test_css_never_positions_a_panel_against_the_viewport() -> None:
    css = _strip_css_comments(_read("app.css"))
    start = css.index(".cc-panel-stack")
    end = css.index(".cc-panel.is-collapsed")
    block = css[start:end]
    assert "position: fixed" not in block
    assert "position: absolute" not in block
    assert "z-index" not in block
    assert "resize:" not in block


def test_css_hides_legacy_extras_strip() -> None:
    """The old ``.cc-wb-extras`` strip is retained in the DOM for the
    defensive cleanup sites (cancelled prompts), but is ``display: none``
    so it doesn't reserve vertical real estate under the tree."""
    css = _read("app.css")
    block = css.split(".cc-wb-extras {", 1)[1].split("}", 1)[0]
    assert "display: none" in block


def test_no_inline_extras_card_creation_left() -> None:
    """Every SCP03 action must go through ``scp03BuildExtrasCard``."""
    js = _read("app.js")
    pattern = re.compile(
        r"""document\.createElement\(\s*["']div["']\s*\)\s*;[^;]*?\n[^\n]*cc-wb-extras-card""",
        re.MULTILINE,
    )
    matches = pattern.findall(js)
    assert len(matches) == 0, (
        "Found inline cc-wb-extras-card creation -- convert to scp03BuildExtrasCard: "
        + repr(matches)
    )
