# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

from yggdrasim_common.gui_server.sessions import (
    AUTO_CLOSE_PROTECTION_HANDLE_KEY,
    SessionManager,
)


def test_idle_reaper_skips_dynamically_protected_authoring_session() -> None:
    manager = SessionManager(default_idle_timeout_s=60.0)
    closed: list[str] = []
    protected = manager.open(
        kind="saip",
        handle={AUTO_CLOSE_PROTECTION_HANDLE_KEY: True},
        close=lambda: closed.append("protected"),
    )
    disposable = manager.open(
        kind="demo",
        handle={},
        close=lambda: closed.append("disposable"),
    )
    protected.last_used_at = 0.0
    protected.idle_timeout_s = 0.0
    disposable.last_used_at = 0.0
    disposable.idle_timeout_s = 0.0

    assert manager.reap_idle() == 1
    assert manager.has(protected.id)
    assert manager.has(disposable.id) is False
    assert closed == ["disposable"]


def test_session_cap_evicts_oldest_unprotected_peer() -> None:
    manager = SessionManager(max_sessions=2, default_idle_timeout_s=600.0)
    closed: list[str] = []
    protected = manager.open(
        kind="saip",
        handle={AUTO_CLOSE_PROTECTION_HANDLE_KEY: True},
        close=lambda: closed.append("protected"),
    )
    disposable = manager.open(
        kind="demo",
        handle={},
        close=lambda: closed.append("disposable"),
    )
    protected.last_used_at = 1.0
    disposable.last_used_at = 2.0

    newcomer = manager.open(
        kind="demo",
        handle={},
        close=lambda: closed.append("newcomer"),
    )

    assert manager.has(protected.id)
    assert manager.has(disposable.id) is False
    assert manager.has(newcomer.id)
    assert closed == ["disposable"]


def test_session_cap_refuses_to_discard_only_protected_work() -> None:
    manager = SessionManager(max_sessions=1, default_idle_timeout_s=600.0)
    closed: list[str] = []
    protected = manager.open(
        kind="saip",
        handle={},
        close=lambda: closed.append("protected"),
        protect_from_auto_close=True,
    )

    try:
        manager.open(kind="demo", handle={}, close=lambda: closed.append("new"))
    except RuntimeError as error:
        assert "save or close a session" in str(error)
    else:  # pragma: no cover - makes the failure message explicit
        raise AssertionError("opening over protected work should fail")

    assert manager.has(protected.id)
    assert protected.to_dict()["protect_from_auto_close"] is True
    assert closed == []


def test_scoped_reap_leaves_other_subsystems_alone() -> None:
    """A subsystem's housekeeping must not decide another's lifetimes.

    The Remote Lab session listing used to sweep the whole store, and the
    GUI polls it every 10 s from boot whether or not a rig is configured,
    so it closed idle SAIP authoring sessions behind the operator's back.
    """
    manager = SessionManager(default_idle_timeout_s=60.0)
    closed: list[str] = []
    lab = manager.open(
        kind="scp03",
        handle={},
        close=lambda: closed.append("lab"),
        metadata={"remote_lab": True},
    )
    authoring = manager.open(
        kind="saip",
        handle={},
        close=lambda: closed.append("authoring"),
    )
    for session in (lab, authoring):
        session.last_used_at = 0.0
        session.idle_timeout_s = 0.0

    reaped = manager.reap_idle(
        select=lambda entry: bool(entry.metadata.get("remote_lab")),
    )

    assert reaped == 1
    assert manager.has(lab.id) is False
    assert manager.has(authoring.id)
    assert closed == ["lab"]


def test_unscoped_reap_still_sweeps_every_kind() -> None:
    """``open()`` reaps without a predicate and must keep doing so."""
    manager = SessionManager(default_idle_timeout_s=60.0)
    closed: list[str] = []
    card = manager.open(
        kind="scp03",
        handle={},
        close=lambda: closed.append("scp03"),
    )
    authoring = manager.open(
        kind="saip",
        handle={},
        close=lambda: closed.append("saip"),
    )
    # Age both only after the last open(), which reaps on entry.
    for session in (card, authoring):
        session.last_used_at = 0.0
        session.idle_timeout_s = 0.0

    assert manager.reap_idle() == 2
    assert sorted(closed) == ["saip", "scp03"]


def test_kind_ceiling_refuses_instead_of_evicting_and_stays_out_of_the_shared_cap() -> None:
    """A kind with a ceiling of its own is bounded on its own.

    The shared cap bounds sessions holding a reader and evicts the oldest
    clean one to admit a newcomer. A kind that names ``max_of_kind`` is
    counted against that ceiling alone and refused there -- a clean
    package the operator loaded on purpose must not vanish to make room
    -- and however many of it are open, a card session still finds the
    shared cap untouched and evicts only its own peers.
    """
    manager = SessionManager(max_sessions=1, default_idle_timeout_s=600.0)
    closed: list[str] = []
    first = manager.open(
        kind="saip", handle={}, close=lambda: closed.append("first"), max_of_kind=2
    )
    second = manager.open(
        kind="saip", handle={}, close=lambda: closed.append("second"), max_of_kind=2
    )

    try:
        manager.open(
            kind="saip", handle={}, close=lambda: closed.append("third"), max_of_kind=2
        )
    except RuntimeError as error:
        assert "saip session ceiling reached (2 open)" in str(error)
    else:  # pragma: no cover - makes the failure message explicit
        raise AssertionError("opening above the kind ceiling should fail")

    card = manager.open(kind="scp03", handle={}, close=lambda: closed.append("card"))
    assert manager.has(first.id) and manager.has(second.id) and manager.has(card.id)
    assert closed == []

    replacement = manager.open(
        kind="scp03", handle={}, close=lambda: closed.append("replacement")
    )
    assert closed == ["card"]
    assert manager.has(replacement.id)
    assert manager.has(first.id) and manager.has(second.id)
    assert first.to_dict()["max_of_kind"] == 2
    assert card.to_dict()["max_of_kind"] is None
