# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the FS-state restore contract.

Pinned bug: after the operator loaded the file-system (scan tree + read
on load), then invoked any action that SELECTed a different AID — e.g.
Card info (ICCID + EID probe -> ECASD + ISD-R), Cert info (ECASD),
SELECT... prompt against an arbitrary AID, ISD-R profile actions —
the card's current DF drifted away from MF. A subsequent file-tree
click arrived at ``_dispatch_read_selected`` with the card sitting on
ISD-R / ECASD / ADF-X, and although ``fs_controller.select()`` does a
best-effort ``_select_single("MF")`` for slash-rooted paths, on some
cards that relative-SELECT failed once the card had been pushed
several layers deep.

User-visible symptom:
    "Read filesystem -> SELECT any other AID -> click a file again,
    file can not be read anymore."

Fix contract (what these tests pin):

1. ``_dispatch_read_selected`` MUST call ``_restore_fs_root_best_effort``
   before invoking ``fs_controller.select`` whenever the incoming path
   is slash-rooted (i.e. normalised to MF/...). Bare hex FIDs stay
   card-state-aware on purpose (CLI parity for advanced operators).

2. ``_dispatch_select_only`` MUST honour the same pre-restore contract.

3. ``_dispatch_card_info`` MUST call ``_restore_fs_root_best_effort`` in
   a finally-block so the ICCID / EID probe (which punches through to
   EF.ICCID, ECASD and ISD-R via raw SELECT-by-AID) can't leave the FS
   view stale — regardless of whether the dispatcher succeeds or raises.

4. ``_dispatch_cert_info`` MUST call ``_restore_fs_root_best_effort`` in
   a finally-block for the same reason (it SELECTs ECASD and then GET-
   DATAs each cert tag).

Tests are dependency-free: no PC/SC, no pySim, no real card. Fakes
reproduce the contract surface the dispatchers touch.
"""

from __future__ import annotations

from typing import Any


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


class _FakeTransporter:
    """Records every ``transmit(...)`` call; returns a scripted reply."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.reset_called = False
        # Scripted replies keyed by the APDU hex string.
        self.script: dict[str, tuple[bytes, int, int]] = {}
        # Default reply (SW=9000, empty body) for any APDU we didn't
        # pre-script — keeps the dispatchers unblocked.
        self.default_reply: tuple[bytes, int, int] = (b"", 0x90, 0x00)

    def transmit(self, cmd: str, silent: bool = False) -> tuple[bytes, int, int]:
        cmd_up = str(cmd).upper()
        self.calls.append(cmd_up)
        if cmd_up in self.script:
            return self.script[cmd_up]
        return self.default_reply

    def reset(self) -> bool:
        self.reset_called = True
        return True

    def reset_session_state(self) -> None:
        pass

    def get_atr_bytes(self) -> bytes:
        return bytes.fromhex("3B9F96801FC38073C8211308000055A76A")


class _FakeFsController:
    """Just enough surface for the pre-restore and select path."""

    def __init__(self) -> None:
        self.current_fid: str = "A000000559"  # drifted to ISD-R
        self.current_path_hint: str = "ISD-R"
        self.current_fcp: dict[str, Any] = {}
        self.select_calls: list[str] = []
        self.select_result: bool = True
        self.post_select_fid: str = "2FE2"
        self.post_select_fcp: dict[str, Any] = {
            "structure": "Transparent",
            "size": 10,
            "rec_len": 0,
        }

    def select(self, path: str, silent: bool = False) -> bool:
        self.select_calls.append(path)
        if self.select_result:
            self.current_fid = self.post_select_fid
            self.current_path_hint = path
            self.current_fcp = dict(self.post_select_fcp)
        return self.select_result


class _FakeSession:
    def __init__(self, transporter: _FakeTransporter, fs: _FakeFsController) -> None:
        self.kind = "scp03"
        self.handle = {"transporter": transporter, "fs": fs}
        self.id = "sess-fake"


class _FakeManager:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    def get(self, sid: str) -> _FakeSession:
        assert sid == self._session.id
        return self._session


def _install_fake_manager(monkeypatch, session: _FakeSession) -> None:
    """Make ``get_manager()`` return a fake that hands out *session*."""
    from yggdrasim_common.gui_server import sessions as sessions_mod

    monkeypatch.setattr(sessions_mod, "get_manager", lambda: _FakeManager(session))


# ----------------------------------------------------------------------
# _dispatch_read_selected — pre-restore guarantees
# ----------------------------------------------------------------------


def test_read_selected_preselects_mf_for_slash_rooted_path(monkeypatch):
    """Slash-rooted path must trigger a raw 00A40004023F00 BEFORE select()."""
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    _install_fake_manager(monkeypatch, sess)

    # Prime: at this point the card is "sitting on ISD-R" per the fake.
    # We expect the dispatcher to fire an explicit SELECT MF via the
    # restore helper BEFORE handing control to fs_controller.select.
    class _Ctx:
        pass

    mod._dispatch_read_selected(_Ctx(), session_id=sess.id, path="MF/EF.ICCID")

    assert "00A40004023F00" in tp.calls, (
        "expected an explicit SELECT MF before fs_controller.select() — "
        f"transporter calls were {tp.calls!r}"
    )
    mf_idx = tp.calls.index("00A40004023F00")
    # fs_controller.select was called exactly once
    assert len(fs.select_calls) == 1
    assert fs.select_calls[0] == "MF/EF.ICCID"
    # And the select() happened AFTER the pre-restore APDU — the fake
    # fs controller doesn't touch the transporter, so the only trace we
    # have is that the pre-restore APDU landed and fs_controller.select
    # then ran. The presence of the APDU in the calls list before any
    # other APDU is what we're guarding.
    assert mf_idx == 0, (
        "pre-restore SELECT MF must be the FIRST APDU issued by the "
        "dispatcher; got call order " + repr(tp.calls)
    )
    # fs_controller bookkeeping must be re-synced to MF by the restore
    # helper, even though fs_controller.select then moves it to 2FE2.
    assert fs.current_fid == "2FE2"
    assert fs.current_path_hint == "MF/EF.ICCID"


def test_read_selected_skips_preselect_for_bare_hex(monkeypatch):
    """Bare hex FIDs stay card-state-aware — no pre-restore."""
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    _install_fake_manager(monkeypatch, sess)

    class _Ctx:
        pass

    mod._dispatch_read_selected(_Ctx(), session_id=sess.id, path="2FE2")

    # No raw SELECT MF should be issued for bare hex.
    assert "00A40004023F00" not in tp.calls, (
        "pre-restore must not fire for bare hex FIDs — CLI parity "
        "relies on relative SELECT semantics"
    )
    assert fs.select_calls == ["2FE2"]


def test_read_selected_skips_preselect_for_bare_aid(monkeypatch):
    """Bare AIDs (long hex) are globally resolved; pre-restore wasteful."""
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    _install_fake_manager(monkeypatch, sess)

    class _Ctx:
        pass

    mod._dispatch_read_selected(
        _Ctx(),
        session_id=sess.id,
        path="A0000000871002FFFFFFFF8907090000",
    )

    assert "00A40004023F00" not in tp.calls


# ----------------------------------------------------------------------
# _dispatch_select_only — pre-restore mirror
# ----------------------------------------------------------------------


def test_select_only_preselects_mf_for_slash_rooted_path(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    _install_fake_manager(monkeypatch, sess)

    class _Ctx:
        pass

    mod._dispatch_select_only(_Ctx(), session_id=sess.id, path="MF/ADF_USIM/EF_IMSI")

    assert tp.calls[0] == "00A40004023F00", (
        "select_only must also anchor to MF before path-walk; got "
        + repr(tp.calls)
    )
    assert fs.select_calls == ["MF/ADF_USIM/EF_IMSI"]


def test_select_only_skips_preselect_for_bare_hex(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    _install_fake_manager(monkeypatch, sess)

    class _Ctx:
        pass

    mod._dispatch_select_only(_Ctx(), session_id=sess.id, path="7FFF")

    assert "00A40004023F00" not in tp.calls


# ----------------------------------------------------------------------
# _dispatch_card_info — finally-block restore
# ----------------------------------------------------------------------


def test_card_info_restores_mf_after_icc_and_eid_probe(monkeypatch):
    """Card info drifts to ISD-R; restore must fire after the probe."""
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    _install_fake_manager(monkeypatch, sess)

    # Scripted replies: make the ICCID + EID probes succeed "enough"
    # to exercise the full happy path. The probes fall back gracefully
    # on any non-0x90 reply, so a default 9000 is fine; what we really
    # care about is the trailing restore APDU.
    class _Ctx:
        pass

    mod._dispatch_card_info(_Ctx(), session_id=sess.id)

    # The final APDU MUST be an explicit SELECT MF — that's the
    # finally-block restore. Without it, the next FS click lands on a
    # drifted card.
    assert tp.calls, "expected at least one transmit call"
    assert tp.calls[-1] == "00A40004023F00", (
        "card_info must end on SELECT MF — transporter calls: "
        + repr(tp.calls)
    )
    # fs controller bookkeeping snapped back to MF too.
    assert fs.current_fid == "3F00"
    assert fs.current_path_hint == "MF"


def test_card_info_restores_mf_even_if_probe_raises(monkeypatch):
    """finally-block runs on any exception inside the body."""
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    _install_fake_manager(monkeypatch, sess)

    # Force _probe_iccid to raise so we hit the exception path.
    def _boom(_transporter):
        raise RuntimeError("simulated ICCID probe failure")

    monkeypatch.setattr(mod, "_probe_iccid", _boom)

    class _Ctx:
        pass

    raised = False
    try:
        mod._dispatch_card_info(_Ctx(), session_id=sess.id)
    except RuntimeError:
        raised = True
    assert raised, "injected failure must bubble up"

    # Even on exception the restore ran.
    assert tp.calls[-1] == "00A40004023F00"


# ----------------------------------------------------------------------
# _dispatch_cert_info — finally-block restore
# ----------------------------------------------------------------------


def test_cert_info_restores_mf_after_ecasd_walk(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    _install_fake_manager(monkeypatch, sess)

    # Default reply returns SW=9000 with empty data for every GET DATA
    # tag lookup — the dispatcher records them as "present=True, hex=''".
    # We only care about the trailing restore APDU here.
    class _Ctx:
        pass

    mod._dispatch_cert_info(_Ctx(), session_id=sess.id)

    assert tp.calls, "expected ECASD SELECT + GET-DATAs + final restore"
    # First APDU: SELECT ECASD. Last APDU: SELECT MF (restore).
    ecasd_select = "00A40400" + "10" + "A0000005591010FFFFFFFF8900000200"
    assert tp.calls[0] == ecasd_select, (
        "expected the dispatcher to open with SELECT ECASD; got "
        + repr(tp.calls[0])
    )
    assert tp.calls[-1] == "00A40004023F00", (
        "cert_info must end on SELECT MF — transporter calls: "
        + repr(tp.calls)
    )
    assert fs.current_fid == "3F00"
    assert fs.current_path_hint == "MF"
