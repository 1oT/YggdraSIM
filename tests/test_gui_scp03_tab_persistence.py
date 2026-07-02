# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the SCP03 per-reader tab persistence layer.

Background
----------
Operators asked for SCP03 sessions to survive page reloads so they
can bounce back to where they left off on each reader. The top-bar
reader strip keyed tabs by reader name, which unlocked this cleanly:
we persist each tab's state under ``ygg.scp03.tab.<readerName>`` in
``localStorage`` and hydrate on the first pill click for that reader.

Two tied-in fixes live next door and are pinned here as well:

* ``scp03OpenSessionForTab`` must NOT early-return on an empty
  ``pendingReader`` — the welcome panel's "Open default reader"
  button needs to dispatch ``scp03.scan`` with ``reader=""``.
* ``readerBarActivate`` auto-opens the session for yellow pills
  (card present, no live session, no persisted cache) so pill
  clicks feel like "switch session" instead of a two-click dance
  through the welcome panel.

All tests here are static-bundle contracts against ``app.js`` /
``app.css`` — the persistence layer is pure frontend JavaScript
(no backend surface), so we pin the symbols + wiring rather than
round-tripping through a live browser. Playwright covers the
end-to-end UX separately.
"""

from __future__ import annotations

import re
from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# Persistence helper surface.
# ----------------------------------------------------------------------


def test_persist_helpers_defined() -> None:
    """All localStorage helpers must be declared in app.js."""
    js = _read("app.js")
    assert "function scp03PersistKey(" in js
    assert "function scp03PersistTab(" in js
    assert "function scp03LoadPersisted(" in js
    assert "function scp03HydrateTabFromPersisted(" in js
    assert "function scp03PurgePersisted(" in js
    assert "function scp03HasPersistedState(" in js


def test_persist_key_uses_scoped_prefix() -> None:
    """Keys must namespace under ``ygg.scp03.tab.`` to avoid collisions."""
    js = _read("app.js")
    assert 'SCP03_PERSIST_PREFIX = "ygg.scp03.tab."' in js
    assert "SCP03_PERSIST_VERSION = 1" in js
    # The cap keeps a single oversized scan tree from blowing the
    # 5 MB localStorage quota. Anything 20-100 is defensible.
    match = re.search(r"SCP03_PERSIST_MAX_CACHE\s*=\s*(\d+)", js)
    assert match is not None, "SCP03_PERSIST_MAX_CACHE must be set"
    cap = int(match.group(1))
    assert 20 <= cap <= 200, f"fcpCache cap looks off: {cap}"


def test_persist_tab_reads_expected_fields() -> None:
    """``scp03PersistTab`` must read the exact fields we document."""
    js = _read("app.js")
    # Locate the function body so we don't match hits elsewhere in the
    # file.
    start = js.index("function scp03PersistTab(")
    end = js.index("function scp03LoadPersisted(")
    body = js[start:end]
    # Fields we commit to persisting — if any get renamed, hydration
    # needs to follow.
    for field in [
        "readerName",
        "atrHex",
        "scanData",
        "selectedPath",
        "previewCache",
        "fcpCache",
        "activeRibbonTab",
        "apduInputHex",
        "apduFollow61",
        "apduRetry6C",
        "apduHistory",
    ]:
        assert field + ":" in body or "tab." + field in body, (
            f"scp03PersistTab is missing {field!r}"
        )
    # Must NOT persist sessionId / status / pendingReader — those
    # are ephemeral and re-deriving them on load is safer than
    # trusting stale values.
    assert "sessionId:" not in body, "sessionId must not be persisted"
    assert "tab.sessionId" not in body, "sessionId must not be persisted"


def test_persist_tab_caps_fcp_cache() -> None:
    """Oversized fcpCache must be trimmed to the newest N entries."""
    js = _read("app.js")
    start = js.index("function scp03PersistTab(")
    end = js.index("function scp03LoadPersisted(")
    body = js[start:end]
    assert "SCP03_PERSIST_MAX_CACHE" in body
    assert "capturedAt" in body, (
        "scp03PersistTab must sort by capturedAt when pruning"
    )


def test_persist_tab_is_quota_safe() -> None:
    """localStorage.setItem must be wrapped in a try/catch — quota errors
    and private-mode writes must not surface to the user."""
    js = _read("app.js")
    start = js.index("function scp03PersistTab(")
    end = js.index("function scp03LoadPersisted(")
    body = js[start:end]
    assert "localStorage.setItem" in body
    assert "try {" in body, "setItem must be wrapped in try/catch"
    assert "catch" in body, "setItem must be wrapped in try/catch"


def test_hydrate_clears_ephemeral_fields() -> None:
    """Hydration must NOT restore sessionId / status / error — those are
    backend-owned and go stale across reloads."""
    js = _read("app.js")
    start = js.index("function scp03HydrateTabFromPersisted(")
    end = js.index("function scp03PurgePersisted(")
    body = js[start:end]
    assert "tab.sessionId = null" in body
    assert 'tab.status = "idle"' in body
    assert "tab.error = null" in body


def test_has_persisted_state_requires_tree() -> None:
    """``scp03HasPersistedState`` must gate on scanData.tree — an empty
    tree is useless to the welcome panel."""
    js = _read("app.js")
    start = js.index("function scp03HasPersistedState(")
    end = js.index("}", js.index("return ", start))
    body = js[start:end]
    assert "sessionId" in body, "must short-circuit when sessionId is live"
    assert "scanData" in body
    assert "tree" in body


# ----------------------------------------------------------------------
# Hydration wiring.
# ----------------------------------------------------------------------


def test_reader_bar_sync_hydrates_new_tabs() -> None:
    """When ``readerBarSyncToScp03Tab`` creates a new tab for a reader,
    it must try to hydrate from localStorage first."""
    js = _read("app.js")
    start = js.index("function readerBarSyncToScp03Tab(")
    # Slice up to the next top-level "function " declaration.
    remainder = js[start + len("function readerBarSyncToScp03Tab("):]
    next_fn = remainder.index("\n  function ")
    body = js[start:start + len("function readerBarSyncToScp03Tab(") + next_fn]
    assert "scp03LoadPersisted(readerName)" in body
    assert "scp03HydrateTabFromPersisted(tab, persisted)" in body


def test_welcome_panel_shows_resume_state() -> None:
    """``scp03BuildWelcomePanel`` must render a Resume button + hint
    when the tab was hydrated from persistence."""
    js = _read("app.js")
    start = js.index("function scp03BuildWelcomePanel(")
    remainder = js[start:]
    next_fn = remainder.index("\n  function ")
    body = remainder[:next_fn]
    assert "scp03HasPersistedState(tab)" in body
    assert "Resume" in body, "welcome panel must advertise 'Resume' for persisted tabs"
    assert "Forget cached state" in body, "must offer a Forget button too"
    assert "scp03PurgePersisted" in body


def test_read_selected_persists_on_success() -> None:
    """``readSelectedForTab`` must persist after successful fresh reads
    AND after successful retry-after-recovery reads."""
    js = _read("app.js")
    start = js.index("async function readSelectedForTab(")
    # Walk to the next top-level "function " declaration.
    remainder = js[start:]
    next_fn = remainder.index("\n  // -- ")
    body = remainder[:next_fn]
    # Fresh read path.
    assert body.count("scp03PersistTab(tab)") >= 2, (
        "readSelectedForTab must persist on both fresh + recovered paths"
    )
    # Sanity: also updates selectedPath so the next reload lands on
    # the right file in the tree.
    assert "tab.selectedPath = path" in body


def test_recover_session_persists_on_rewalk() -> None:
    """When ``scp03RecoverSession`` gets a fresh tree back from the
    backend, it must persist so a reload after a successful recovery
    lands on the post-reset tree."""
    js = _read("app.js")
    start = js.index("async function scp03RecoverSession(")
    remainder = js[start:]
    next_fn = remainder.index("\n  async function ")
    body = remainder[:next_fn]
    assert "scp03PersistTab(tab)" in body


def test_rescan_persists_fresh_tree() -> None:
    """``scp03Rescan`` must persist after successful scan so reloads
    show the freshly walked tree."""
    js = _read("app.js")
    start = js.index("async function scp03Rescan(")
    remainder = js[start:]
    next_fn = remainder.index("\n  async function ")
    body = remainder[:next_fn]
    assert "scp03PersistTab(tab)" in body


def test_close_tab_purges_persistence() -> None:
    """Closing a tab is the explicit 'forget this reader' gesture —
    localStorage must be wiped so the next pill click starts fresh."""
    js = _read("app.js")
    start = js.index("async function scp03CloseTab(tabId")
    remainder = js[start:]
    next_fn = remainder.index("\n  // -- ")
    body = remainder[:next_fn]
    assert "scp03PurgePersisted(tab.readerName)" in body


def test_ribbon_tab_switch_persists() -> None:
    """Switching ribbon tabs (Home / Files / APDU / Admin) must persist
    so a reload restores the last-used tab."""
    js = _read("app.js")
    # The ribbon tab click handler lives inside scp03BuildRibbon; we
    # pin the specific tab.activeRibbonTab assignment + persist chain.
    assert "tab.activeRibbonTab = ribTab.id" in js
    tail = js[js.index("tab.activeRibbonTab = ribTab.id"):]
    assert "scp03PersistTab(tab)" in tail[:400], (
        "ribbon switch must trigger persistence"
    )


# ----------------------------------------------------------------------
# Reader-bar regression fixes (pill auto-open + default reader).
# ----------------------------------------------------------------------


def test_open_session_handles_empty_reader() -> None:
    """The welcome panel's 'Open default reader' button used to silently
    no-op because ``scp03OpenSessionForTab`` early-returned on an empty
    ``pendingReader``. That early return must be gone."""
    js = _read("app.js")
    start = js.index("async function scp03OpenSessionForTab(")
    remainder = js[start:]
    next_fn = remainder.index("\n  // -- ")
    body = remainder[:next_fn]
    # We keep the ``target = tab.pendingReader || ""`` line, but the
    # early return must be absent.
    assert 'var target = tab.pendingReader || "";' in body
    assert "if (!target) return;" not in body, (
        "empty pendingReader must fall through to backend (reader index 0)"
    )
    # Dispatches scan regardless of target.
    assert '"/api/actions/scp03.scan/run"' in body


def test_open_session_persists_on_success() -> None:
    """Successful scan must persist so the newly opened tab's tree
    survives a reload."""
    js = _read("app.js")
    start = js.index("async function scp03OpenSessionForTab(")
    remainder = js[start:]
    next_fn = remainder.index("\n  // -- ")
    body = remainder[:next_fn]
    assert "scp03PersistTab(tab)" in body


def test_reader_bar_activate_auto_opens_yellow_pill() -> None:
    """Clicking a card-present reader with no SCP03 session must auto-open
    the scan even though SCP03 is now a reader-scoped module."""
    js = _read("app.js")
    start = js.index("function readerBarActivate(")
    remainder = js[start:]
    next_fn = remainder.index("\n  function ")
    body = remainder[:next_fn]
    assert 'commandState.activeSubsystem === "SCP03"' in body
    assert "readerBarProbeHasCard(readerName)" in body
    assert "!readerBarHasScp03Session(readerName)" in body
    assert 'document.querySelector(".cc-wb-tabs.scp03-topbar")' in body
    assert 'document.querySelector(".cc-wb-body")' in body
    assert "scp03OpenSessionForTab(tab, tabBar, tabBody)" in body


def test_reader_bar_activate_respects_persisted_state() -> None:
    """A hydrated tab (persisted scanData, no live sessionId) must NOT
    auto-open — the operator should see the Resume button and click it
    deliberately so a stale tree is never silently trusted."""
    js = _read("app.js")
    start = js.index("function readerBarActivate(")
    remainder = js[start:]
    next_fn = remainder.index("\n  function ")
    body = remainder[:next_fn]
    assert "scp03HasPersistedState(tab)" in body
    # The guard clauses bail before scp03OpenSessionForTab fires:
    assert "if (tab.sessionId) return" in body
    assert 'if (tab.status === "scanning") return' in body


def test_open_session_notifies_reader_bar() -> None:
    """After a scan finishes, the reader bar must repaint so the green
    dot lights up on the correct pill immediately — not on the next 5 s
    poll tick."""
    js = _read("app.js")
    start = js.index("async function scp03OpenSessionForTab(")
    remainder = js[start:]
    next_fn = remainder.index("\n  // -- ")
    body = remainder[:next_fn]
    assert "readerBarNotifySessionChanged" in body


# ----------------------------------------------------------------------
# Logging surface (operators chase "why didn't this read resolve?"
# via the log dock).
# ----------------------------------------------------------------------


def test_read_selected_failures_log_to_bus() -> None:
    """Both the fresh-read and retry-after-recovery failure paths must
    emit to logBus so operators can diagnose a stuck read from the log
    dock without digging into the network tab."""
    js = _read("app.js")
    start = js.index("async function readSelectedForTab(")
    remainder = js[start:]
    next_fn = remainder.index("\n  // -- ")
    body = remainder[:next_fn]
    assert "logBus.emit" in body
    assert "fresh read failed" in body
    assert "retry after recovery failed" in body


def test_scan_failure_logs_to_bus() -> None:
    """Failed scans must log a human-readable error to the log dock."""
    js = _read("app.js")
    start = js.index("async function scp03OpenSessionForTab(")
    remainder = js[start:]
    next_fn = remainder.index("\n  // -- ")
    body = remainder[:next_fn]
    assert "logBus.emit" in body
    assert "scan failed on" in body or "scan threw on" in body


# ----------------------------------------------------------------------
# Initial state contract (new fields on each empty tab).
# ----------------------------------------------------------------------


def test_empty_tab_tracks_persisted_timestamp() -> None:
    """Hydrated tabs need a ``persistedAt`` field so the welcome panel
    can show 'saved 15s ago'. This must be wired in hydration, and the
    field is implicitly declared (JS is forgiving) — but the consumer
    path in ``scp03BuildWelcomePanel`` must read it."""
    js = _read("app.js")
    assert "tab.persistedAt" in js, (
        "welcome panel / hydration must reference persistedAt"
    )
    # Hydration source of the value.
    start = js.index("function scp03HydrateTabFromPersisted(")
    end = js.index("function scp03PurgePersisted(")
    body = js[start:end]
    assert "tab.persistedAt" in body
    assert "persisted.savedAt" in body
