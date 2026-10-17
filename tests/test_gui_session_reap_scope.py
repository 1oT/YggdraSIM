# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Which route owns the session idle sweep.

The GUI polls ``/api/remote-lab/sessions`` every 10 s from boot whether
or not a rig is configured, and that listing used to reap the whole
session store. A SAIP package the operator was reading -- clean, so
unprotected -- died at the 180 s default of the day, and the next click
in the FS tree failed with ``unknown session``. Reader liveness moved to the
route that already owns it: ``/api/live/readers`` closes sessions whose
card has left, and now applies the idle timeout to card-holding kinds.
"""

from __future__ import annotations

from yggdrasim_common.gui_server.routes import live as live_routes
from yggdrasim_common.gui_server.routes import remote_lab as remote_lab_routes
from yggdrasim_common.gui_server.sessions import get_manager


def _open(kind: str, closed: list[str], **metadata: object):
    return get_manager().open(
        kind=kind,
        handle={},
        close=lambda: closed.append(kind),
        metadata=dict(metadata),
    )


def _age(*sessions: object) -> None:
    """Expire sessions only after the last open().

    ``open()`` reaps the whole store on entry, so ageing a session before
    opening its peer would have the peer's admission do the closing.
    """
    for session in sessions:
        session.last_used_at = 0.0
        session.idle_timeout_s = 0.0


def test_remote_lab_listing_leaves_authoring_sessions_open() -> None:
    manager = get_manager()
    closed: list[str] = []
    authoring = _open("saip", closed)
    lab = _open("scp03", closed, remote_lab=True, remote_lab_device_id="dev-1")
    _age(authoring, lab)
    try:
        payload = remote_lab_routes.active_sessions()

        assert manager.has(authoring.id)
        assert manager.has(lab.id) is False
        assert closed == ["scp03"]
        assert payload["count"] == 0
    finally:
        manager.close(authoring.id)
        manager.close(lab.id)


def test_reader_poll_releases_idle_card_sessions_only() -> None:
    manager = get_manager()
    closed: list[str] = []
    authoring = _open("saip", closed)
    card = _open("scp03", closed, reader_name="(default)")
    _age(authoring, card)
    try:
        assert live_routes._reap_idle_card_sessions() == 1

        assert manager.has(card.id) is False
        assert manager.has(authoring.id)
        assert closed == ["scp03"]
    finally:
        manager.close(authoring.id)
        manager.close(card.id)
