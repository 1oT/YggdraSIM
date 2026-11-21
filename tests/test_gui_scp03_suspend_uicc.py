# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""GUI ``scp03.fs_suspend_uicc`` sends the TS 102 221 v18.4 §11.1.22 form.

SUSPEND UICC with P1 '00' carries the proposed minimum and maximum
suspension duration (Lc '04') and Le '0A'; the card answers with the
negotiated duration and an 8-byte resume token. The dispatcher used to send
a bare ``80 76 00 00 00``, which a compliant card rejects with '6700'.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest


class _Transport:
    def __init__(self, responses: list[tuple[bytes, int, int]]) -> None:
        self.session = SimpleNamespace(is_authenticated=True)
        self.sent: list[str] = []
        self._responses = list(responses)

    def transmit(self, apdu_hex: str, silent: bool = False):
        self.sent.append(apdu_hex.upper())
        return self._responses.pop(0)


def _dispatch(monkeypatch, transport, **kwargs):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    monkeypatch.setattr(mod, "_get_scp03_session", lambda _sid: (None, transport, "gui-1"))
    return mod._dispatch_fs_suspend_uicc(None, session_id="gui-1", **kwargs)


def test_suspend_sends_durations_and_le_and_returns_token(monkeypatch) -> None:
    token = bytes.fromhex("0102030405060708")
    transport = _Transport([(bytes.fromhex("0201") + token, 0x90, 0x00)])

    result = _dispatch(monkeypatch, transport, confirm="SUSPEND")

    # Lc '04': min 00 01 (one second), max 02 01 (one hour); Le '0A'.
    assert transport.sent == ["8076000004000102010A"]
    assert result["ok"] is True
    assert result["apdu"] == "8076000004000102010A"
    assert result["negotiated_duration"] == "0201"
    assert result["resume_token"] == "0102030405060708"


def test_suspend_requires_confirmation_and_sends_nothing(monkeypatch) -> None:
    transport = _Transport([])

    with pytest.raises(ValueError):
        _dispatch(monkeypatch, transport, confirm="")

    assert transport.sent == []
