# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Static assertions for the top-bar reader strip (Phase C UX pivot).

Operators asked for the reader selector to move out of the sidebar
and into the top-bar runtime controls: one pill per PC/SC reader,
with a traffic-light status dot (green = active session, yellow =
card present / no session, red = empty / no session). Pills behave
like session tabs — the reader picked in the top bar is pre-set
across every subsystem for that session.

Because the reader strip is pure frontend wiring (HTML markup + a
JavaScript state machine + CSS colour tokens), the cheapest
regression gate is to pin the contract of the static bundle rather
than spin up Playwright. These assertions protect against silent
refactors that would:

  * drop the top-bar markup (``#topbar-readers``, ``#topbar-readers-scroll``,
    ``#topbar-readers-refresh``);
  * move suite health back out of the top bar;
  * reintroduce the legacy sidebar Readers section;
  * rename the ``readerBar*`` helpers that SCP03 flows hook into;
  * lose the traffic-light palette classes
    (``.topbar-reader-pill-dot--green/yellow/red``).

These checks are file-read-only and run in <100 ms; they sit in the
same family as ``test_gui_scp03_send_apdu.py``'s static symbol pins.
"""

from __future__ import annotations

from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# HTML contract
# ----------------------------------------------------------------------


def test_topbar_readers_markup_present() -> None:
    html = _read("index.html")
    assert 'id="topbar-readers"' in html, "top-bar reader strip container missing"
    assert 'id="topbar-readers-scroll"' in html, "horizontal scroll inner missing"
    assert 'id="topbar-readers-refresh"' in html, "refresh button missing"
    assert 'class="topbar-readers"' in html


def test_topbar_reader_strip_lives_inside_topbar_header() -> None:
    html = _read("index.html")
    head_start = html.index('<header class="topbar">')
    head_end = html.index("</header>", head_start)
    inside = html[head_start:head_end]
    assert 'id="topbar-readers"' in inside, "strip must be inside <header class='topbar'>"
    assert "brand-name" in inside, "brand must still live in the topbar"
    cluster_start = inside.index('<div class="status-cluster">')
    cluster_end = inside.index('id="topbar-collapse-toggle"', cluster_start)
    cluster = inside[cluster_start:cluster_end]
    assert 'id="topbar-readers"' in cluster, "strip must live with the runtime controls"


def test_topbar_backend_switch_markup_present() -> None:
    html = _read("index.html")
    assert 'class="topbar-backend-switch"' in html
    assert 'id="topbar-backend-reader"' in html
    assert 'id="topbar-backend-sim"' in html
    assert 'data-backend="reader"' in html
    assert 'data-backend="sim"' in html


def test_topbar_suite_health_markup_present() -> None:
    html = _read("index.html")
    assert 'id="topbar-suite-health"' in html
    assert 'id="topbar-suite-version"' in html
    assert 'id="topbar-suite-active"' in html
    assert 'id="badge-mode"' not in html
    assert 'id="badge-flavor"' not in html


def test_app_close_button_lives_at_topbar_right_edge() -> None:
    html = _read("index.html")
    css = _read("app.css")
    js = _read("app.js")
    head_start = html.index('<header class="topbar">')
    head_end = html.index("</header>", head_start)
    inside = html[head_start:head_end]

    assert 'id="app-close-button"' in inside
    assert inside.index('id="topbar-collapse-toggle"') < inside.index('id="app-close-button"')
    assert ".app-close-button" in css
    assert ":not(.app-close-button)" in css
    assert "function appCloseBootstrap()" in js
    assert "window.pywebview.api.close_app" in js


def test_overview_suite_health_card_retired() -> None:
    html = _read("index.html")
    assert "<h3>Suite health</h3>" not in html
    assert 'id="overview-health"' not in html
    assert 'id="overview-refresh"' not in html


def test_sidebar_readers_section_retired() -> None:
    html = _read("index.html")
    # The whole legacy sidebar "Readers" title + pane moved to the top
    # bar. These IDs must no longer exist in index.html.
    assert 'id="reader-pane-list"' not in html
    assert 'id="reader-pane-filter"' not in html
    assert 'id="reader-pane-note"' not in html
    assert 'id="reader-pane-refresh"' not in html
    assert 'class="sidebar-title sidebar-title-readers"' not in html


# ----------------------------------------------------------------------
# JavaScript contract
# ----------------------------------------------------------------------


def test_reader_bar_state_in_command_state() -> None:
    js = _read("app.js")
    assert "readerBar: {" in js, "commandState.readerBar missing"
    # Core state fields that the render/polling helpers depend on.
    for field in ("readers", "activeReader", "pollTimerId", "pollIntervalMs"):
        assert field in js, f"commandState.readerBar.{field} field missing"


def test_load_health_updates_topbar_suite_badge_only() -> None:
    js = _read("app.js")
    start = js.index("async function loadHealth()")
    window = js[start:start + 900]
    assert 'setText("topbar-suite-version"' in window
    assert 'setText("topbar-suite-active"' in window
    assert "formatUptime(data.uptime_seconds)" in window
    assert "overview-version" not in window
    assert "badge-mode" not in window


def test_reader_bar_public_helpers_defined() -> None:
    js = _read("app.js")
    for symbol in (
        "function readerBarBootstrap",
        "function readerBarStartPolling",
        "function readerBarStopPolling",
        "async function readerBarRefresh",
        "function readerBarDeriveStatus",
        "function readerBarReaderScopedBoundName",
        "function readerBarRender",
        "function readerBarBuildPill",
        "function readerBarActivate",
        "function readerBarSyncToScp03Tab",
        "async function readerBarCloseSessionFor",
        "function readerBarNotifySessionChanged",
    ):
        assert symbol in js, f"reader-bar symbol missing: {symbol}"


def test_reader_bar_bootstraps_at_init() -> None:
    js = _read("app.js")
    # init() must kick the reader bar so the pills appear on page load.
    init_start = js.index("function init()")
    init_end = js.index("}", init_start + js[init_start:].index("{"))
    # Widen to the whole init body — the braces nested inside catch
    # blocks mean a naive index('}') would return early. Scan forward
    # until we reach a line containing 'logBus.emit' at init-level.
    init_body = js[init_start : init_start + 2000]
    assert "readerBarBootstrap()" in init_body, "init() must call readerBarBootstrap()"


def test_scp03_rescan_notifies_reader_bar() -> None:
    js = _read("app.js")
    rescan = js.index("async function scp03Rescan")
    # Scan forward to the function close. scp03Rescan is ~60 lines; 4k
    # chars is a safe upper bound.
    window = js[rescan : rescan + 4000]
    assert "readerBarNotifySessionChanged" in window, (
        "scp03Rescan must repaint the top-bar pill after a session opens/fails"
    )


def test_scp03_close_tab_notifies_reader_bar() -> None:
    js = _read("app.js")
    # Match ``scp03CloseTab(`` exactly so we land on the dispatcher
    # rather than ``scp03CloseTabSessionOnly`` which is unrelated.
    close_tab = js.index("async function scp03CloseTab(tabId")
    window = js[close_tab : close_tab + 2500]
    assert "readerBarNotifySessionChanged" in window, (
        "scp03CloseTab must repaint the top-bar pill after a session closes"
    )


def test_reader_bar_traffic_light_logic() -> None:
    js = _read("app.js")
    # The derive-status function must enumerate the three primary
    # status tokens so the renderer's dot colour class comes out right.
    derive_start = js.index("function readerBarDeriveStatus")
    window = js[derive_start : derive_start + 2500]
    for token in ('"green"', '"yellow"', '"red"'):
        assert token in window, (
            f"readerBarDeriveStatus must return the {token} status token"
        )
    assert "readerBarReaderScopedBoundName()" in window, (
        "readerBarDeriveStatus must treat reader-scoped eSIM modules as "
        "active reader sessions."
    )
    assert "atr.length > 0 && (hasRealSession || hasReaderScopedBinding)" in window, (
        "reader-scoped modules must not stay green after the reader reports no ATR."
    )
    assert "readerBarPruneEmptyReaderBindings()" in js, (
        "reader polling must release stale active-reader bindings when a card disappears."
    )


def test_reader_bar_activate_repaints_reader_scoped_pills() -> None:
    js = _read("app.js")
    activate_start = js.index("function readerBarActivate(readerName)")
    activate_window = js[activate_start : activate_start + 5000]
    assert "readerBarNotifySessionChanged()" in activate_window, (
        "readerBarActivate must repaint the top-bar pills after eSIM reader "
        "selection so the active/in-use state updates immediately."
    )


def test_reader_bar_render_keeps_reader_scoped_orphan_pill() -> None:
    js = _read("app.js")
    render_start = js.index("function readerBarRender()")
    render_window = js[render_start : render_start + 5000]
    assert "var scopedName = readerBarReaderScopedBoundName()" in render_window
    assert 'readers.concat([{ name: scopedName, atr_hex: "", status: "orphan" }])' in render_window


# ----------------------------------------------------------------------
# CSS contract
# ----------------------------------------------------------------------


def test_topbar_reader_pill_css_tokens() -> None:
    css = _read("app.css")
    # Core selectors the renderer depends on — removing any of these
    # would silently break the top-bar visuals.
    for selector in (
        ".topbar-readers",
        ".topbar-readers-scroll",
        ".topbar-readers-refresh",
        ".topbar-reader-pill",
        ".topbar-reader-pill-dot",
        ".topbar-reader-pill-label",
        ".topbar-reader-pill-close",
        ".topbar-backend-switch",
        ".topbar-backend-option",
        ".topbar-backend-option.is-active",
        ".topbar-suite-health",
        ".topbar-suite-version",
        ".topbar-suite-active",
    ):
        assert selector in css, f"CSS selector missing: {selector}"


def test_topbar_reader_traffic_light_classes() -> None:
    css = _read("app.css")
    for cls in (
        ".topbar-reader-pill-dot--green",
        ".topbar-reader-pill-dot--yellow",
        ".topbar-reader-pill-dot--red",
    ):
        assert cls in css, f"traffic-light class missing: {cls}"


def test_legacy_scp03_reader_pane_hidden() -> None:
    css = _read("app.css")
    # The per-SCP03-tab left reader pane is retired; it must be hidden
    # via the stylesheet so stray DOM (from older tab states) does not
    # steal width.
    assert ".scp03-shell > .scp03-reader-pane" in css
    assert "display: none !important" in css
