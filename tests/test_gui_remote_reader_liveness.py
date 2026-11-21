# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression guards for how the GUI decides a card went away.

A Remote Lab reader row is published by a live session, not probed from a
PC/SC reader, and that route caches the ATR lazily -- so the row can carry
an empty ``atr_hex`` while the card behind it is perfectly present. The
reader bar used to read any empty ATR as "card removed", which wiped the
session, dropped the tree + FCP cache and bounced the operator back to the
reader picker on every 5 s poll tick.

``session_backed`` is the discriminator: True for a row a live session
publishes, False for anything probed (including a remote *bridge* row,
whose empty ATR really does mean no card).

These checks target the canonical modular source; the release bundle is
rebuilt from it by the frontend build step.
"""

from __future__ import annotations

import importlib
import unittest
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_COMMAND_CENTER = _ROOT / "gui_frontend/src/js/command-center.js"
_CORE = _ROOT / "gui_frontend/src/js/core.js"

try:
    _live_module = importlib.import_module(
        "yggdrasim_common.gui_server.routes.live"
    )
except Exception:  # pragma: no cover -- optional FastAPI/Pydantic deps
    _live_module = None


def _between(body: str, start_marker: str, end_marker: str) -> str:
    start = body.index(start_marker)
    end = body.index(end_marker, start)
    return body[start:end]


def _prune_body() -> str:
    return _between(
        _COMMAND_CENTER.read_text(encoding="utf-8"),
        "function readerBarPruneEmptyReaderBindings()",
        "function readerBarIsDuplicateRemoteReader(",
    )


# --- backend: the row carries the discriminator -------------------------


@pytest.mark.skipif(_live_module is None, reason="live route deps missing")
class RemoteReaderRowTest(unittest.TestCase):
    def test_reader_info_defaults_to_probed(self) -> None:
        row = _live_module.ReaderInfo(name="r", atr_hex="", status="s")
        self.assertFalse(row.session_backed)

    def test_registered_remote_rows_are_session_backed(self) -> None:
        from yggdrasim_common import remote_readers

        remote_readers.clear_remote_readers()
        self.addCleanup(remote_readers.clear_remote_readers)
        remote_readers.register_remote_reader(
            "Remote Lab: rig", relay_url="http://127.0.0.1:1/apdu"
        )
        rows = _live_module._registered_remote_reader_rows({})
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].session_backed)
        # The ATR is genuinely absent here; the row must still not read
        # as an empty reader to the frontend.
        self.assertEqual(rows[0].atr_hex, "")

    def test_cached_session_atr_reaches_the_row(self) -> None:
        from yggdrasim_common import remote_readers

        remote_readers.clear_remote_readers()
        self.addCleanup(remote_readers.clear_remote_readers)
        remote_readers.register_remote_reader(
            "Remote Lab: rig", relay_url="http://127.0.0.1:1/apdu"
        )
        rows = _live_module._registered_remote_reader_rows(
            {"Remote Lab: rig": "3B9F96"}
        )
        self.assertEqual(rows[0].atr_hex, "3B9F96")
        self.assertTrue(rows[0].session_backed)


# --- frontend: liveness is the binding, not the ATR ---------------------


def test_prune_skips_session_backed_rows() -> None:
    body = _prune_body()
    assert "if (reader && reader.session_backed) return;" in body


def test_prune_still_drops_a_reader_that_left_the_enumeration() -> None:
    body = _prune_body()
    assert "return anyProbed && !knownReaders[name];" in body


def test_prune_guards_against_a_transient_empty_enumeration() -> None:
    body = _prune_body()
    assert "var anyProbed = probed.length > 0;" in body


def test_prune_purges_the_persisted_cache_for_a_lost_reader() -> None:
    body = _prune_body()
    assert "scp03PurgePersisted(bound)" in body


def test_status_treats_a_session_backed_row_as_card_present() -> None:
    body = _between(
        _COMMAND_CENTER.read_text(encoding="utf-8"),
        "function readerBarDeriveStatus(readerName)",
        "function readerBarRender()",
    )
    assert 'var hasCard = atr.length > 0 || !!probe.session_backed;' in body


# --- frontend: releasing a remote session clears its cache --------------


def test_release_purges_before_the_reader_name_is_cleared() -> None:
    body = _between(
        _CORE.read_text(encoding="utf-8"),
        "function remoteLabDetachLocalSession(sessionRow)",
        "async function remoteLabConnect(",
    )
    # The name must be captured before it is blanked, or the purge (like
    # the scp03PersistTab call it replaced) silently does nothing.
    assert body.index("var previousReader = tab.readerName") < body.index(
        'tab.readerName = "";'
    )
    assert "scp03PurgePersisted(previousReader)" in body


def _connect_and_adopt() -> str:
    body = _CORE.read_text(encoding="utf-8")
    return _between(
        body, "async function remoteLabConnect(", "async function remoteLabLoadInviteFiles("
    )


def test_remote_connect_never_navigates_away() -> None:
    # Connecting a remote rig used to open the SCP03 file-system module on
    # the operator, mid-task. A local reader is bound in place; so is this.
    assert "openCommandSubsystem(" not in _connect_and_adopt()


def test_remote_connect_never_paints_the_workbench_scanning() -> None:
    # The workbench must not show "Scanning..." (or anything) for a connect
    # that happens on the Remote Lab view; the scan the route runs is the
    # route's business, not a panel.
    connect = _between(
        _CORE.read_text(encoding="utf-8"),
        "async function remoteLabConnect(",
        "async function remoteLabDisconnect(",
    )
    assert 'status = "scanning"' not in connect
    assert "renderScp03Tabs" not in connect


def test_remote_connect_repaints_the_card_before_reloading() -> None:
    # loadRemoteLab declines to run while another load is in flight, so a
    # repaint that depends on it can be lost; the card is painted from the
    # state already in hand first.
    connect = _between(
        _CORE.read_text(encoding="utf-8"),
        "async function remoteLabConnect(",
        "async function remoteLabDisconnect(",
    )
    finally_block = connect[connect.index("} finally {") :]
    assert finally_block.index("renderRemoteLab();") < finally_block.index("await loadRemoteLab();")


def test_bind_marks_the_pill_active_without_a_session_on_the_tab() -> None:
    # Connect no longer returns a card session; it publishes a reader name.
    # The tab is bound the way a local reader is bound, and nothing is
    # scanned or navigated.
    bind = _between(
        _CORE.read_text(encoding="utf-8"),
        "function remoteLabBindReader(data)",
        "async function remoteLabLoadInviteFiles(",
    )
    assert "readerBarSyncToScp03Tab(readerName)" in bind
    assert "readerBarSetActiveReaderOnly(readerName)" in bind
    assert "tab.sessionId =" not in bind
    assert "openCommandSubsystem(" not in bind
    assert "renderScp03Tabs" not in bind


def test_detach_matches_tabs_by_the_published_reader_name() -> None:
    # Tabs hold module session ids, never the link's, so a release must find
    # them by the name the link published.
    detach = _between(
        _CORE.read_text(encoding="utf-8"),
        "function remoteLabDetachLocalSession(sessionRow)",
        "async function remoteLabConnect(",
    )
    assert "readerBarBoundName(tab)" in detach
    assert "scp03PurgePersisted(previousReader)" in detach


def test_load_coalesces_a_request_made_while_one_is_in_flight() -> None:
    load = _between(
        _CORE.read_text(encoding="utf-8"),
        "async function loadRemoteLab()",
        "function renderRemoteLab()",
    )
    assert "remoteLabState.loadAgain = true;" in load
    assert "loadRemoteLab();" in load[load.index("} finally {") :]
