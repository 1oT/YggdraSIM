# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Source contracts for shared GUI interaction and accessibility behavior."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMAND_JS = ROOT / "gui_frontend/src/js/command-center.js"
CORE_JS = ROOT / "gui_frontend/src/js/core.js"
TRAILING_JS = ROOT / "gui_frontend/src/js/trailing.js"
INDEX_HTML = ROOT / "gui_frontend/src/index.html"
CSS_ROOT = ROOT / "gui_frontend/src/css/views"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _function(body: str, start: str, end: str) -> str:
    return body.split(start, 1)[1].split(end, 1)[0]


def test_action_forms_have_consistent_busy_status_and_result_feedback() -> None:
    js = _read(COMMAND_JS)
    prepare = _function(
        js,
        "function ccPrepareActionFeedback(",
        "function ccSetActionStatus(",
    )
    busy = _function(
        js,
        "function ccSetActionFormBusy(",
        "function ccFocusActionResult(",
    )

    assert 'form.setAttribute("aria-busy", "false")' in prepare
    assert 'statusEl.setAttribute("role", "status")' in prepare
    assert 'statusEl.setAttribute("aria-live", "polite")' in prepare
    assert 'resultEl.setAttribute("role", "region")' in prepare
    assert "resultEl.tabIndex = -1" in prepare
    assert 'form.dataset.actionRunning = isBusy ? "true" : "false"' in busy
    assert 'control.disabled = true' in busy
    assert "ccFocusActionResult(resultEl" in js


def test_destructive_actions_require_deliberate_acknowledgement() -> None:
    js = _read(COMMAND_JS)
    block = _function(
        js,
        "function ccEnsureDestructiveAcknowledgement(",
        "function ccPrepareActionFeedback(",
    )

    assert 'tags.indexOf("destructive")' in js
    assert 'acknowledgeInput.type = "checkbox"' in block
    assert "acknowledgeInput.required = true" in block
    assert "acknowledgeInput.dataset.ccDestructiveAcknowledge" in block
    assert 'form.elements.namedItem("confirm")' in block
    assert "acknowledgeInput.name" not in block


def test_secret_action_values_are_masked_redacted_and_cleared() -> None:
    js = _read(COMMAND_JS)

    assert 'input.type = field.secret ? "password" : "text"' in js
    assert 'input.setAttribute("autocomplete", "new-password")' in js
    assert 'reveal.setAttribute("aria-controls", fid)' in js
    assert "function ccRedactActionError(" in js
    assert "function ccRedactActionResult(" in js
    assert "function ccClearCollectedSecretValues(" in js
    assert 'inputs[field.name] = ""' in js


def test_floating_action_windows_restore_focus_and_respect_log_dock() -> None:
    js = _read(COMMAND_JS)
    css = _read(CSS_ROOT / "floating-action-popouts.css")

    assert "function ccPopoutRestoreFocus(" in js
    assert "popout.__returnFocus = document.activeElement" in js
    assert 'popout.setAttribute("role", "dialog")' in js
    assert 'popout.setAttribute("aria-modal", "false")' in js
    assert 'popout.setAttribute("aria-labelledby", titleEl.id)' in js
    assert "function ccPopoutUsableBottom(" in js
    assert 'document.getElementById("log-dock")' in js
    assert 'typeof ResizeObserver === "function"' in js
    assert "--cc-popout-usable-bottom" in css
    assert "@media (prefers-reduced-motion: reduce)" in css


def test_reader_controls_use_sibling_buttons_and_restore_anchor_focus() -> None:
    js = _read(COMMAND_JS)
    css = _read(CSS_ROOT / "reader-pill.css")

    assert 'pillGroup.className = "topbar-reader-pill-group"' in js
    assert 'var pill = document.createElement("button")' in js
    assert 'var close = document.createElement("button")' in js
    assert "pillGroup.appendChild(pill)" in js
    assert "pillGroup.appendChild(close)" in js
    assert 'pill.setAttribute("aria-haspopup", "dialog")' in js
    assert 'pill.setAttribute("aria-expanded", "false")' in js
    assert "readerBarClosePopover({ restoreFocus: true })" in js
    assert 'data-reader-popover-action="connect"' in js
    assert ".topbar-reader-pill-group" in css


def test_dynamic_navigation_is_semantic_and_mobile_overlay_closes() -> None:
    command = _read(COMMAND_JS)
    trailing = _read(TRAILING_JS)
    html = _read(INDEX_HTML)

    assert 'item.className = "cc-nav-leaf-item"' in command
    assert 'var li = document.createElement("button")' in command
    assert "li.type = \"button\"" in command
    assert "window.YggdraSimSidebar.closeOverlayAfterNavigation()" in command
    assert "if (value === null) return null" in trailing
    assert 'window.matchMedia("(max-width: 760px)")' in trailing
    assert "storedPreference === null ? _isNarrow() : storedPreference" in trailing
    assert "closeOverlayAfterNavigation: function ()" in trailing
    assert 'aria-controls="module-navigation"' in html
    assert 'id="module-navigation"' in html


def test_fallback_file_explorer_is_keyboard_accessible_and_race_safe() -> None:
    js = _read(TRAILING_JS)
    explorer = _function(js, "function openFsExplorer(", "function openFilePicker(")

    assert 'overlay.setAttribute("role", "dialog")' in explorer
    assert 'overlay.setAttribute("aria-modal", "true")' in explorer
    assert 'overlay.setAttribute("aria-labelledby", titleEl.id)' in explorer
    assert 'listingEl.setAttribute("role", "listbox")' in explorer
    assert 'li.setAttribute("role", "option")' in explorer
    assert 'li.setAttribute("aria-selected", "false")' in explorer
    assert 'if (ev.key !== "Tab")' in explorer
    assert 'ev.key === "ArrowDown"' in explorer
    assert 'ev.key === "Home"' in explorer
    assert "requestId !== state.loadRequest || settled" in explorer
    assert "returnFocus.focus" in explorer


def test_document_viewer_has_modal_focus_contract_and_stale_load_guard() -> None:
    js = _read(TRAILING_JS)
    html = _read(INDEX_HTML)
    css = _read(CSS_ROOT / "guides-modal.css")

    assert 'aria-modal="true"' in html
    assert 'aria-labelledby="doc-modal-title"' in html
    assert 'aria-label="Close document viewer"' in html
    assert "function docViewerFocusableElements(" in js
    assert "docViewerState.returnFocus" in js
    assert 'if (ev.key !== "Tab") return' in js
    assert "requestId !== docViewerState.requestId" in js
    assert 'bodyEl.setAttribute("aria-busy", "true")' in js
    assert 'role="alert"' in js
    assert ".cc-doc-modal-btn:focus-visible" in css


def test_scp03_ribbon_uses_roving_tabs_and_arrow_navigation() -> None:
    js = _read(COMMAND_JS)
    ribbon = _function(
        js,
        "function scp03BuildRibbon(",
        "function scp03RepaintRibbon(",
    )

    assert 'strip.setAttribute("role", "tablist")' in ribbon
    assert 'btn.setAttribute("role", "tab")' in ribbon
    assert 'btn.setAttribute("aria-selected"' in ribbon
    assert 'btn.setAttribute("aria-controls", panelId)' in ribbon
    assert "btn.tabIndex = ribTab.id === activeId ? 0 : -1" in ribbon
    assert 'event.key === "ArrowRight"' in ribbon
    assert 'event.key === "ArrowLeft"' in ribbon
    assert 'event.key === "Home"' in ribbon
    assert 'section.setAttribute("role", "tabpanel")' in ribbon


def test_remote_lab_and_bridge_surface_status_and_inline_errors() -> None:
    core = _read(CORE_JS)
    html = _read(INDEX_HTML)

    assert "function remoteLabSetImportPanel(" in core
    assert 'importBtn.setAttribute("aria-expanded"' in core
    assert "function remoteLabSetImportError(" in core
    assert 'error.setAttribute("role", "alert")' in core
    assert "function cbSetSemanticStatus(" in core
    assert 'element.setAttribute("role", "status")' in core
    assert 'element.setAttribute("aria-live", "polite")' in core
    assert "<h1>Remote Bridge</h1>" in html
    assert "<h2>Bridge connection</h2>" in html
    assert "Remote host service settings" in html
    assert "Open remote GUI" in html
    assert "RPi service settings" not in html
    assert "Open RPi GUI" not in html


def test_shared_controls_have_theme_focus_target_and_motion_styles() -> None:
    forms = _read(CSS_ROOT / "command-center-compact-pane.css")
    status = _read(CSS_ROOT / "command-center-drag-drop.css")
    explorer = _read(CSS_ROOT / "key-value-swatches.css")
    reader = _read(CSS_ROOT / "misc-trailing.css")

    assert ".cc-form-row > textarea" in forms
    assert "background: var(--bg-elev-2, var(--bg-elev))" in forms
    assert "min-height: 36px" in forms
    assert ":focus" in forms
    assert '.cc-action-status[data-state="success"]' in status
    assert '.cc-action-status[data-state="error"]' in status
    assert "@media (prefers-reduced-motion: reduce)" in status
    assert "@media (prefers-reduced-motion: reduce)" in explorer
    assert "@media (prefers-reduced-motion: reduce)" in reader


def test_glyph_only_shell_controls_have_accessible_names() -> None:
    html = _read(INDEX_HTML)

    assert 'id="host-shell-device-refresh"' in html
    assert 'aria-label="Refresh serial devices"' in html
    assert 'id="doc-modal-close"' in html
    assert 'aria-label="Close document viewer"' in html
