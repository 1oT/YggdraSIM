# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the FCP cache + auto-recovery contract.

Background
----------
The "filesystem → other AID → filesystem" state-drift bug kept
resurfacing even after we added the raw-APDU MF pre-restore in
``_dispatch_read_selected``. On a handful of cards, some loaders
park the card in a state where SELECT-by-FID returns 6A82 until
the card is cold-reset. Rather than pile more pre-restore retries
on the backend, we added two things:

1. **Backend**: ``scp03.recover_session`` — cold-reset the card,
   drop the secure-channel state, re-instantiate the
   ``FileSystemController``, walk MF, and swap the fresh controller
   into the session handle.

2. **Frontend**: per-path FCP cache on each session tab
   (``tab.fcpCache``). ``readSelectedForTab`` now renders cached
   data optimistically, fires the fresh read underneath, and
   auto-fires a recovery + retry if the fresh read fails.

These tests pin the contract of both halves — the backend is a
pure-Python unit test (no PC/SC, no pySim), the frontend is a
static-bundle pin of the state / helper / wiring symbols.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# Backend fakes (shared surface with test_gui_scp03_fs_state_restore.py,
# kept inline so this file is self-contained — easier to read the
# dispatcher contract without hopping across files).
# ----------------------------------------------------------------------


class _FakeTransporter:
    """Scripted PC/SC transporter: records APDUs + reset() calls."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.reset_called = 0
        self.reset_session_called = 0
        self.script: dict[str, tuple[bytes, int, int]] = {}
        self.default_reply: tuple[bytes, int, int] = (b"", 0x90, 0x00)
        self._atr = bytes.fromhex("3B9F96801FC38073C8211308000055A76A")

    def transmit(self, cmd: str, silent: bool = False) -> tuple[bytes, int, int]:
        cmd_up = str(cmd).upper()
        self.calls.append(cmd_up)
        if cmd_up in self.script:
            return self.script[cmd_up]
        return self.default_reply

    def reset(self) -> bool:
        self.reset_called += 1
        # Pretend the ATR changed on cold reset so the dispatcher's
        # ``atr_changed`` field has something to report.
        self._atr = bytes.fromhex("3B9F96801FC38073C8211308000055A76B")
        return True

    def reset_session_state(self) -> None:
        self.reset_session_called += 1

    def get_atr_bytes(self) -> bytes:
        return self._atr


class _DriftedFsController:
    """FS controller whose ``current_fid`` is pointing at ISD-R."""

    def __init__(self) -> None:
        self.current_fid: str = "A000000559"
        self.current_path_hint: str = "ISD-R"
        self.current_fcp: dict[str, Any] = {}
        self.scan_calls: int = 0

    def scan_tree(self, return_tree: bool = False) -> dict[str, Any]:
        self.scan_calls += 1
        if return_tree is False:
            return {}
        return {
            "tree": [
                {"name": "MF", "fid": "3F00", "path": "MF", "children": []},
            ],
            "scan_cache": {"0": "MF"},
        }


class _FakeSession:
    def __init__(self, transporter: _FakeTransporter, fs: _DriftedFsController) -> None:
        self.kind = "scp03"
        self.handle = {"transporter": transporter, "fs": fs}
        self.id = "sess-fake"


class _FakeManager:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    def get(self, sid: str) -> _FakeSession:
        assert sid == self._session.id
        return self._session


def _install_fakes(monkeypatch, session: _FakeSession) -> None:
    """Stub out the session manager and pin the ``FileSystemController``
    import inside the dispatcher to a fake constructor.
    """
    from yggdrasim_common.gui_server import sessions as sessions_mod
    monkeypatch.setattr(sessions_mod, "get_manager", lambda: _FakeManager(session))

    # ``_dispatch_recover_session`` does a local ``from SCP03.logic.fs
    # import FileSystemController`` — patch the real module's attribute
    # so the dispatcher gets our drift-aware fake. The fake matches the
    # dispatcher's constructor signature (``(transporter)``).
    from SCP03.logic import fs as fs_mod

    def _fake_ctor(transporter: Any) -> _DriftedFsController:
        # Fresh fake per call so we can verify the dispatcher swaps the
        # instance into ``session.handle["fs"]``.
        return _DriftedFsController()

    monkeypatch.setattr(fs_mod, "FileSystemController", _fake_ctor)


# ----------------------------------------------------------------------
# Backend — ``scp03.recover_session`` dispatcher contract
# ----------------------------------------------------------------------


def test_recover_session_calls_cold_reset(monkeypatch) -> None:
    """The dispatcher MUST issue ``transporter.reset()`` before walking."""
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _DriftedFsController()
    sess = _FakeSession(tp, fs)
    _install_fakes(monkeypatch, sess)

    result = mod._dispatch_recover_session(ctx=object(), session_id=sess.id)

    assert tp.reset_called == 1, "cold reset skipped — state won't recover"
    assert tp.reset_session_called == 1, \
        "secure-channel state must be dropped alongside the cold reset"
    assert result["reset_ok"] is True
    assert result["session_id"] == sess.id


def test_recover_session_swaps_fresh_fs_controller(monkeypatch) -> None:
    """A fresh FileSystemController MUST replace the drifted one.

    If we reused the old controller, its stale ``current_fid`` +
    ``current_fcp`` bookkeeping would silently confuse the next
    ``_dispatch_read_selected`` call — defeating the whole point
    of recovery.
    """
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    drifted = _DriftedFsController()
    sess = _FakeSession(tp, drifted)
    _install_fakes(monkeypatch, sess)

    before = sess.handle["fs"]
    mod._dispatch_recover_session(ctx=object(), session_id=sess.id)
    after = sess.handle["fs"]

    assert after is not before, \
        "drifted FS controller was not replaced with a fresh instance"
    assert isinstance(after, _DriftedFsController)
    assert after.scan_calls == 1, "fresh controller's scan_tree was not invoked"


def test_recover_session_returns_scan_shape(monkeypatch) -> None:
    """Return value MUST mirror ``scp03.scan`` so the GUI can drop-in
    the refreshed tree without a special-case renderer."""
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _DriftedFsController()
    sess = _FakeSession(tp, fs)
    _install_fakes(monkeypatch, sess)

    result = mod._dispatch_recover_session(ctx=object(), session_id=sess.id)

    for key in ("session_id", "reset_ok", "scan_ok", "atr_before_hex",
                "atr_after_hex", "atr_changed", "tree", "scan_cache"):
        assert key in result, f"response missing key: {key}"
    assert result["scan_ok"] is True
    assert isinstance(result["tree"], list)
    assert isinstance(result["scan_cache"], dict)
    assert result["atr_changed"] is True, \
        "cold reset should have flipped the ATR (our fake mutates it)"


def test_recover_session_survives_scan_failure(monkeypatch) -> None:
    """If ``scan_tree`` raises, the dispatcher MUST still return — the
    cold reset succeeded and is useful on its own."""
    from yggdrasim_common.gui_server.actions import scp03 as mod
    from SCP03.logic import fs as fs_mod

    tp = _FakeTransporter()
    fs = _DriftedFsController()
    sess = _FakeSession(tp, fs)
    _install_fakes(monkeypatch, sess)

    class _ExplodingFs:
        def __init__(self, transporter: Any) -> None:
            self._tp = transporter

        def scan_tree(self, return_tree: bool = False) -> dict[str, Any]:
            raise RuntimeError("SIM walker blew up")

    monkeypatch.setattr(fs_mod, "FileSystemController", _ExplodingFs)

    result = mod._dispatch_recover_session(ctx=object(), session_id=sess.id)

    assert result["reset_ok"] is True, \
        "scan failure must not mask the successful cold reset"
    assert result["scan_ok"] is False
    assert "SIM walker blew up" in result["scan_error"]
    assert result["tree"] == []
    assert result["scan_cache"] == {}


def test_recover_session_requires_session_id() -> None:
    from yggdrasim_common.gui_server.actions import scp03 as mod

    try:
        mod._dispatch_recover_session(ctx=object(), session_id="")
    except ValueError as error:
        assert "session_id is required" in str(error).lower()
    else:
        raise AssertionError("empty session_id must raise")


def test_recover_session_spec_registered() -> None:
    """The spec MUST exist and point at the new dispatcher."""
    from yggdrasim_common.gui_server.actions import scp03 as mod

    assert mod.RECOVER_SESSION_SPEC.id == "scp03.recover_session"
    assert mod.RECOVER_SESSION_SPEC.dispatcher is mod._dispatch_recover_session
    assert mod.RECOVER_SESSION_SPEC.requires_card is True
    assert "recovery" in mod.RECOVER_SESSION_SPEC.tags


# ----------------------------------------------------------------------
# Frontend — static contract of the cache + recovery flow
# ----------------------------------------------------------------------


def test_tab_fcp_cache_wired_on_empty_tab() -> None:
    """Each fresh tab owns an ``fcpCache`` map + ``lastRecoverAt`` stamp."""
    js = _read("app.js")
    # The empty-tab factory defines the cache slot.
    tab_factory_idx = js.index("function scp03CreateEmptyTab()")
    # Pull a window large enough to contain the factory's return literal.
    factory_block = js[tab_factory_idx:tab_factory_idx + 2400]
    assert "fcpCache: {}" in factory_block, \
        "new tabs must own their own FCP cache"
    assert "lastRecoverAt: 0" in factory_block, \
        "new tabs must own their recovery timestamp"


def test_cache_cleared_on_session_close() -> None:
    """``scp03CloseTabSessionOnly`` MUST wipe the cache on session loss."""
    js = _read("app.js")
    close_idx = js.index("async function scp03CloseTabSessionOnly(tab)")
    close_end = js.index("refreshSessionStatusMetric();", close_idx)
    close_block = js[close_idx:close_end]
    assert "tab.fcpCache = {}" in close_block, \
        "closing a session must clear its FCP cache (different card coming in)"


def test_cache_cleared_on_rescan() -> None:
    """``scp03Rescan`` MUST wipe the cache alongside scanData / selectedPath."""
    js = _read("app.js")
    rescan_idx = js.index("async function scp03Rescan(tab")
    rescan_window = js[rescan_idx:rescan_idx + 1800]
    assert "tab.fcpCache = {}" in rescan_window, \
        "rescan must drop the cache — the card may be different"


def test_frontend_helpers_present() -> None:
    """The cache + recovery helpers the new flow relies on."""
    js = _read("app.js")
    for fn in (
        "function scp03CacheStore(tab, path, data)",
        "function scp03CacheLookup(tab, path)",
        "function scp03BuildCacheBanner(kind, label)",
        "function scp03RenderFromCache(tab, path, previewEl, kind, label)",
        "async function scp03DoReadSelected(tab, path)",
        "async function scp03RecoverSession(tab)",
    ):
        assert fn in js, f"missing helper: {fn}"


def test_read_selected_flow_calls_recovery_on_failure() -> None:
    """``readSelectedForTab`` MUST wire recovery + retry on failed reads."""
    js = _read("app.js")
    fn_idx = js.index("async function readSelectedForTab(tab, path, previewEl)")
    # 12k is generous — covers the whole phased flow. If this ever
    # shrinks we'll catch it fast because the recovery call would
    # drop out of the substring.
    block = js[fn_idx:fn_idx + 12000]
    # Phase 1: optimistic cache render before the wire read.
    assert "scp03RenderFromCache(" in block, \
        "optimistic cache render missing — preview will flicker on click"
    # Phase 2: fresh read.
    assert "scp03DoReadSelected(tab, path)" in block, \
        "read-selected helper call missing"
    # Phase 3: recovery on failure.
    assert "scp03RecoverSession(tab)" in block, \
        "no recovery call — reads that fail will never retry"
    # Phase 4: retry after recovery.
    second_hit = block.count("scp03DoReadSelected(tab, path)")
    assert second_hit >= 2, \
        "post-recovery retry missing — the whole point of the recovery flow"


def test_recovery_updates_scan_tree_in_place() -> None:
    """``scp03RecoverSession`` must graft the refreshed tree onto ``tab.scanData``."""
    js = _read("app.js")
    fn_idx = js.index("async function scp03RecoverSession(tab)")
    fn_block = js[fn_idx:fn_idx + 2000]
    assert "tab.scanData = Object.assign" in fn_block, \
        "refreshed tree must update tab.scanData (tree view would stay stale otherwise)"
    assert "data.tree" in fn_block, \
        "recovery response's tree field not read back into tab.scanData"
    assert "tab.lastRecoverAt" in fn_block, \
        "recovery timestamp not stamped — banner age display goes blank"


# ----------------------------------------------------------------------
# CSS — status banner visual contract
# ----------------------------------------------------------------------


def test_cache_banner_css_present() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-stale-chip",
        ".cc-stale-chip--refresh",
        ".cc-stale-chip--recover",
        ".cc-stale-chip--stale",
        ".cc-stale-chip-spinner",
        "@keyframes cc-stale-chip-spin",
    ):
        assert selector in css, f"CSS missing: {selector}"
