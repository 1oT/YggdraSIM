# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Where a card session's idle ceiling comes from.

The manager is a module singleton built at import, so a ceiling bound in
``__init__`` would freeze whatever the process started with. These pin
the resolution order instead: a dispatcher's own value, then a
caller-chosen manager default, then the operator's flag, then the
shipped ceiling -- and the flag reaching a session without anything
having called ``apply_persisted_env_overrides``, which the GUI console
scripts do not.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from yggdrasim_common.gui_server.sessions import (
    CARD_SESSION_IDLE_ENV,
    DEFAULT_CARD_SESSION_IDLE_S,
    SessionManager,
)


def _ceiling(manager: SessionManager, **kwargs: Any) -> float:
    session = manager.open(kind="scp03", handle={}, close=lambda: None, **kwargs)
    try:
        return session.idle_timeout_s
    finally:
        manager.close(session.id)


@pytest.fixture(autouse=True)
def _isolated_flag(tmp_path, monkeypatch) -> None:
    """Keep the check off the operator's env and overrides file."""
    monkeypatch.delenv(CARD_SESSION_IDLE_ENV, raising=False)
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))


def _persist(tmp_path, value: str) -> None:
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "env_overrides.json").write_text(
        json.dumps({CARD_SESSION_IDLE_ENV: value}),
        encoding="utf-8",
    )


def test_shipped_ceiling_applies_when_nothing_is_set() -> None:
    assert _ceiling(SessionManager()) == DEFAULT_CARD_SESSION_IDLE_S


def test_ceiling_covers_reading_a_file_not_clicking_the_tree() -> None:
    """The workbench renders a decoded file from its own cache.

    Reading one never reaches the backend, so the clock is not refreshed
    while the operator works. A ceiling under a few minutes closes the
    session under them and the next click fails with ``unknown session``.
    """
    assert DEFAULT_CARD_SESSION_IDLE_S >= 600.0


def test_operator_flag_moves_the_ceiling(monkeypatch) -> None:
    monkeypatch.setenv(CARD_SESSION_IDLE_ENV, "2400")
    assert _ceiling(SessionManager()) == 2400.0


def test_persisted_value_reaches_a_session_without_an_apply_call(tmp_path) -> None:
    """``yggdrasim-gui`` never calls ``apply_persisted_env_overrides``.

    The value is read from the file directly for that reason; a
    resolution that only consulted ``os.environ`` would leave the GUI's
    Environment -> Configuration view silently without effect on the
    next launch.
    """
    _persist(tmp_path, "3600")
    assert _ceiling(SessionManager()) == 3600.0


@pytest.mark.parametrize("bad", ["not-a-number", "-5", "0", ""])
def test_unusable_flag_values_fall_back_to_the_shipped_ceiling(monkeypatch, bad) -> None:
    monkeypatch.setenv(CARD_SESSION_IDLE_ENV, bad)
    assert _ceiling(SessionManager()) == DEFAULT_CARD_SESSION_IDLE_S


def test_caller_chosen_default_outranks_the_flag(monkeypatch) -> None:
    """A test manager asking for immediate reaping must still get it."""
    monkeypatch.setenv(CARD_SESSION_IDLE_ENV, "3600")
    assert _ceiling(SessionManager(default_idle_timeout_s=0.0)) == 0.0


def test_dispatcher_value_outranks_everything(monkeypatch) -> None:
    """SAIP authoring asks for hours and holds no reader."""
    monkeypatch.setenv(CARD_SESSION_IDLE_ENV, "60")
    assert _ceiling(SessionManager(), idle_timeout_s=28800.0) == 28800.0
