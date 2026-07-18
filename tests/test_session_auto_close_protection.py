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
