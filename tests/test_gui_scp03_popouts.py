# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the SCP03 floating-popout window system.

Background
----------
Before this pass every SCP03 action button rendered its output inline
in the ``.cc-wb-extras`` strip below the tree + preview layout. On a
busy session (card_info + GP status + key-info + cert_info + …) the
strip grew into a vertically-stacked tower that hid the file tree and
pushed the fold down screen-fulls. Operator request verbatim:

    "when the user presses a function or action button the module for
    that action is placed below the etsi file tree, can we make these
    action button spawn in a pop-out window instead?"

The fix rewires ``scp03BuildExtrasCard`` to spawn a floating,
draggable, resizable ``.cc-popout`` window instead. The contract the
60+ callers rely on — "I get back an element I append children to" —
is preserved: the helper now returns the popout's body element. Tests
here pin that contract + the surrounding registry behaviour so a
refactor can't silently regress the UX back to the inline tower.

All tests are static-bundle contracts against ``app.js`` / ``app.css``.
The popout is pure frontend JavaScript; Playwright covers the live
drag / resize / focus UX separately (future CI lane).
"""

from __future__ import annotations

import re
from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# Popout primitive surface.
# ----------------------------------------------------------------------


def test_popout_helpers_defined() -> None:
    """The popout system ships as a cohesive set of helpers."""
    js = _read("app.js")
    assert "function scp03PopoutHost(" in js
    assert "function scp03PopoutNextZ(" in js
    assert "function scp03PopoutComputeOrigin(" in js
    assert "function scp03PopoutKey(" in js
    assert "function scp03PopoutBringToFront(" in js
    assert "function scp03PopoutClose(" in js
    assert "function scp03PopoutCloseAllForTab(" in js
    assert "function scp03PopoutSyncVisibilityToActiveTab(" in js
    assert "function scp03PopoutInstallDrag(" in js
    assert "function scp03PopoutToggleMaximize(" in js
    assert "function scp03PopoutEscapeBootstrap(" in js


def test_popout_constants_declared() -> None:
    """Sizing and z-stack constants must live next to the helpers so a
    future tweak doesn't have to grep for magic numbers. Default width
    and height are derived from ``scp03PopoutDefaultSize()`` from the
    viewport (no fixed pixel constants)."""
    js = _read("app.js")
    assert "SCP03_POPOUT_Z_BASE = 7500" in js
    assert "function scp03PopoutDefaultSize(" in js
    assert "SCP03_POPOUT_CASCADE_STEP = 28" in js
    assert "SCP03_POPOUT_MIN_WIDTH = 320" in js
    assert "SCP03_POPOUT_MIN_HEIGHT = 200" in js


def test_escape_closes_topmost_popout() -> None:
    """Esc must close the visible topmost floating popout window."""
    js = _read("app.js")
    bootstrap = js.split("function scp03PopoutEscapeBootstrap()", 1)[1]
    bootstrap = bootstrap.split("var SCP03_POPOUT_CASCADE_STEP", 1)[0]
    assert 'document.addEventListener("keydown", function (ev)' in bootstrap
    assert 'if (ev.key !== "Escape") return;' in bootstrap
    assert "scp03PopoutCloseTopmostVisible()" in bootstrap
    assert "ev.preventDefault()" in bootstrap
    assert "ev.stopPropagation()" in bootstrap

    topmost = js.split("function scp03PopoutTopmostVisible()", 1)[1]
    topmost = topmost.split("function scp03PopoutCloseElement", 1)[0]
    assert 'document.querySelectorAll(".cc-popout")' in topmost
    assert "scp03PopoutIsVisible(popout)" in topmost
    assert "parseInt(popout.style.zIndex" in topmost

    close = js.split("function scp03PopoutCloseElement(popout)", 1)[1]
    close = close.split("function scp03PopoutCloseTopmostVisible", 1)[0]
    assert 'popout.querySelector(".cc-popout-close")' in close
    assert 'new MouseEvent("click"' in close


def test_escape_popout_handler_bootstraps_at_init() -> None:
    js = _read("app.js")
    init_start = js.index("function init()")
    init_body = js[init_start : init_start + 2000]
    assert "scp03PopoutEscapeBootstrap()" in init_body


# ----------------------------------------------------------------------
# Builder contract — backward-compatible with the 60+ call sites.
# ----------------------------------------------------------------------


def _extract_build_extras_card_body(js: str) -> str:
    """Slice the full body of ``scp03BuildExtrasCard`` from the bundle.

    The function is long enough that a crude byte-slice misses the
    registration / return statements at the bottom. We instead pull
    from the signature up to the next top-level ``function `` declaration
    (there are no inner functions declared at that scope), which gives
    us the complete body without importing a JS parser.
    """
    marker = "function scp03BuildExtrasCard(title)"
    tail = js.split(marker, 1)[1]
    # Next top-level function declaration ends this body.
    next_fn = re.search(r"\n  (?:async\s+)?function\s", tail)
    if next_fn is None:
        return tail
    return tail[: next_fn.start()]


def test_build_extras_card_returns_popout_body() -> None:
    """``scp03BuildExtrasCard`` still exists, but now returns the popout
    body (not the old inline card). This preserves the append-children
    contract all call sites rely on."""
    js = _read("app.js")
    assert "function scp03BuildExtrasCard(title)" in js
    assert 'className = "cc-popout card"' in js or 'className="cc-popout card"' in js
    body_section = _extract_build_extras_card_body(js)
    assert 'className = "cc-popout-body"' in body_section
    assert "return body;" in body_section


def test_build_extras_card_dedupes_on_repeat_click() -> None:
    """Clicking the same action twice must bring the existing window
    forward and replace its body contents — not stack a duplicate."""
    js = _read("app.js")
    block = _extract_build_extras_card_body(js)
    # Dedupe logic must consult the active tab's popouts map.
    assert "tab.popouts[key]" in block
    # When a popout with this key already exists we reuse it:
    assert "existing.querySelector" in block
    assert 'if (body) body.innerHTML = ""' in block


def test_build_extras_card_registers_on_active_tab() -> None:
    """New popouts must be tracked on the active tab so close + visibility
    sync can reach them later."""
    js = _read("app.js")
    block = _extract_build_extras_card_body(js)
    assert "tab.popouts[key] = popout" in block
    assert "scp03PopoutBringToFront(tab, popout)" in block


# ----------------------------------------------------------------------
# Per-tab registry lifecycle.
# ----------------------------------------------------------------------


def test_create_empty_tab_seeds_popout_state() -> None:
    """``scp03CreateEmptyTab`` factory must initialise the popout
    registry fields so the first ``scp03BuildExtrasCard`` call doesn't
    NPE on ``tab.popouts[key]``."""
    js = _read("app.js")
    factory = js.split("function scp03CreateEmptyTab()", 1)[1].split("function scp03FindTab")[0]
    assert "popouts: {}" in factory
    assert "popoutZCursor: 0" in factory
    assert "popoutCascadeIdx: 0" in factory


def test_close_tab_tears_down_popouts() -> None:
    """Closing a session tab (the pill ``×`` button) must destroy every
    popout bound to it — operator's explicit ``forget this session``
    gesture."""
    js = _read("app.js")
    block = js.split("async function scp03CloseTab(", 1)[1].split("function ")[0]
    assert "scp03PopoutCloseAllForTab(tab)" in block


def test_tab_switch_syncs_visibility() -> None:
    """``renderScp03Tabs`` must call the visibility-sync helper so
    popouts owned by sibling tabs vanish when the active tab flips."""
    js = _read("app.js")
    assert "scp03PopoutSyncVisibilityToActiveTab()" in js
    # Called from the render path:
    render_block = js.split("function renderScp03Tabs(", 1)[1].split("function scp03RenderTabBody")[0]
    assert "scp03PopoutSyncVisibilityToActiveTab()" in render_block


def test_subsystem_switch_hides_popouts() -> None:
    """Leaving the SCP03 subsystem (e.g. navigating to SAIP) must hide
    every popout — they're contextually SCP03-only. Returning to SCP03
    restores the popouts for whichever session tab is active."""
    js = _read("app.js")
    # openCommandSubsystem consults the sync hook.
    block = js.split("function openCommandSubsystem(", 1)[1].split("function renderCommandSubsystem")[0]
    assert "scp03PopoutSyncForSubsystem" in block
    # The subsystem guard lives in the sync function itself.
    sync_block = js.split("function scp03PopoutSyncVisibilityToActiveTab(", 1)[1].split("function scp03PopoutSyncForSubsystem")[0]
    assert 'activeSubsystem === "SCP03"' in sync_block
    assert "shouldShow" in sync_block


# ----------------------------------------------------------------------
# Drag + maximize + focus behaviour.
# ----------------------------------------------------------------------


def test_drag_uses_pointer_events_with_capture() -> None:
    """Pointer-capture is what makes long drags survive a fast cursor
    leaving the titlebar — the v1 mousedown/move/up scheme was
    flaky on HiDPI tracks. Pin the contract so a "simplification"
    can't re-break it."""
    js = _read("app.js")
    block = js.split("function scp03PopoutInstallDrag(", 1)[1].split("function scp03PopoutToggleMaximize")[0]
    assert "pointerdown" in block
    assert "pointermove" in block
    assert "pointerup" in block
    assert "setPointerCapture" in block
    assert "releasePointerCapture" in block
    # Drag must clamp inside the viewport so the titlebar can't go
    # off-screen — re-centering is otherwise a tab-close-and-reopen
    # dance.
    assert "window.innerWidth" in block
    assert "window.innerHeight" in block


def test_titlebar_dblclick_toggles_maximize() -> None:
    """Operators already learned to double-click for maximize from
    ``installMaximizable``; the popout titlebar honours the same
    gesture so muscle memory still applies."""
    js = _read("app.js")
    block = _extract_build_extras_card_body(js)
    assert 'titlebar.addEventListener("dblclick"' in block
    assert "scp03PopoutToggleMaximize(popout)" in block


def test_pointerdown_in_popout_brings_to_front() -> None:
    """Any click inside the popout — body, titlebar, button — focuses
    that window so the z-stack is always "whatever the operator is
    currently working with"."""
    js = _read("app.js")
    block = _extract_build_extras_card_body(js)
    assert 'popout.addEventListener("pointerdown"' in block
    assert "scp03PopoutBringToFront(tab, popout)" in block


def test_toggle_maximize_caches_prev_geometry() -> None:
    """Restore-from-maximize must replay the pre-maximize geometry —
    otherwise the popout "forgets" where the operator put it."""
    js = _read("app.js")
    block = js.split("function scp03PopoutToggleMaximize(", 1)[1].split("function scp03BuildExtrasCard")[0]
    assert "popout.__prevGeom" in block
    assert "popout.classList.remove" in block
    assert "popout.classList.add" in block


# ----------------------------------------------------------------------
# CSS contract.
# ----------------------------------------------------------------------


def test_css_defines_popout_selectors() -> None:
    css = _read("app.css")
    assert ".cc-popout-host" in css
    assert ".cc-popout {" in css
    assert ".cc-popout.is-focused" in css
    assert ".cc-popout.is-dragging" in css
    assert ".cc-popout.is-maximized" in css
    assert ".cc-popout-titlebar" in css
    assert ".cc-popout-title " in css or ".cc-popout-title{" in css
    assert ".cc-popout-actions" in css
    assert ".cc-popout-btn" in css
    assert ".cc-popout-close:hover" in css
    assert ".cc-popout-body" in css


def test_css_uses_fixed_positioning_for_popouts() -> None:
    """``position: fixed`` is load-bearing — popouts must survive page
    scroll and live above the tree + preview layout irrespective of the
    workbench's scroll position."""
    css = _read("app.css")
    block = css.split(".cc-popout {", 1)[1].split("}", 1)[0]
    assert "position: fixed" in block
    assert "resize: both" in block


def test_css_hides_legacy_extras_strip() -> None:
    """The old ``.cc-wb-extras`` strip is retained in the DOM for the
    four defensive cleanup sites (cancelled prompts), but is now
    ``display: none`` so it doesn't reserve vertical real estate under
    the tree."""
    css = _read("app.css")
    block = css.split(".cc-wb-extras {", 1)[1].split("}", 1)[0]
    assert "display: none" in block


# ----------------------------------------------------------------------
# Removed inline ``.cc-wb-extras-card`` usage.
# ----------------------------------------------------------------------


def test_no_inline_extras_card_creation_left() -> None:
    """Every SCP03 action must go through ``scp03BuildExtrasCard`` (the
    popout bridge). Leftover ``document.createElement`` + ``cc-wb-extras-card``
    patterns would render inline, bypassing the popout system."""
    js = _read("app.js")
    # The builder itself creates the popout shell with ``cc-popout card``,
    # not ``cc-wb-extras-card`` any more. A search for the legacy inline
    # creation pattern must return 0 matches.
    pattern = re.compile(
        r"""document\.createElement\(\s*["']div["']\s*\)\s*;[^;]*?\n[^\n]*cc-wb-extras-card""",
        re.MULTILINE,
    )
    matches = pattern.findall(js)
    assert len(matches) == 0, (
        "Found inline cc-wb-extras-card creation — convert to scp03BuildExtrasCard: "
        + repr(matches)
    )
