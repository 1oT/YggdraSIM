# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The HIL bridge holds its local reader across processes for its whole life.

The bridge resets the card for every modem session, so it takes the reader's
lock (``yggdrasim_common.reader_locks``) before its first PC/SC connect and
keeps it across its own reconnects and resets, until the channel is closed.
A reader another process keeps (a console command, a GUI read) refuses the bridge at once
instead of after five connect attempts, and the supervisor does not start a
session at all while it is held: a start resets the SIMtrace2 and pulses the
modem's reset, both for nothing then.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

import pytest

from Tools.HilBridge import router
from Tools.HilBridge.pcsc import PcscBridgeError
from Tools.HilBridge.router import BridgeConfig
from Tools.HilBridge.supervisor import (
    HilBridgeSupervisor,
    HilBridgeSupervisorConfig,
    UsbDeviceLocator,
    UsbPresenceSnapshot,
)
from tests.reader_lock_support import CONSOLE_HOLDER, READER, OtherProcess, probe
from yggdrasim_common import reader_locks


class _FakeChannel:
    """Stands in for PcscCardChannel: names its reader, counts what it is asked."""

    built: list[_FakeChannel] = []
    fail_connect = False

    def __init__(self, reader_index: int = 0, reader_name: str = "") -> None:
        self.reader_label = READER
        self.connects = 0
        self.reconnects = 0
        self.resets = 0
        self.disconnects = 0
        _FakeChannel.built.append(self)

    def selected_reader_name(self) -> str:
        return READER

    def connect(self) -> None:
        self.connects += 1
        if _FakeChannel.fail_connect:
            raise PcscBridgeError("Failed to open reader in SCARD_SHARE_EXCLUSIVE mode.")

    def reconnect(self) -> None:
        self.reconnects += 1

    def reset_card(self) -> dict:
        self.resets += 1
        return {"mode": "pcsc-reconnect-unpower"}

    def disconnect(self) -> None:
        self.disconnects += 1


@pytest.fixture
def lock_dir(tmp_path, monkeypatch):
    directory = tmp_path / "reader-locks"
    monkeypatch.setattr(reader_locks, "_DIRECTORY", directory)
    return directory


@pytest.fixture
def fake_pcsc(monkeypatch):
    _FakeChannel.built = []
    _FakeChannel.fail_connect = False
    monkeypatch.setattr(router, "PcscCardChannel", _FakeChannel)
    monkeypatch.setattr(router, "is_simulated_card_backend", lambda: False)
    monkeypatch.setattr(router.time, "sleep", lambda seconds: None)
    monkeypatch.delenv("YGGDRASIM_HIL_REMOTE_CARD_URL", raising=False)
    return _FakeChannel


@pytest.fixture
def others():
    started: list[OtherProcess] = []
    yield started
    for other in started:
        other.close()


def test_the_bridge_holds_its_reader_across_reconnects_and_resets(lock_dir, fake_pcsc):
    backend = router.BackendCardChannel(reader_index=0)
    backend.connect()
    assert probe(lock_dir)["holder"].startswith("HIL bridge (pid ")

    backend.reconnect()
    backend.reset_card()
    assert probe(lock_dir)["holder"].startswith("HIL bridge (pid ")
    assert (fake_pcsc.built[0].reconnects, fake_pcsc.built[0].resets) == (1, 1)

    backend.disconnect()
    assert probe(lock_dir) == {"held": True}


def test_a_reader_another_process_keeps_refuses_the_bridge_at_once(lock_dir, fake_pcsc, others):
    other = OtherProcess(lock_dir, long_running=True)
    others.append(other)
    backend = router.BackendCardChannel(reader_index=0)

    with pytest.raises(PcscBridgeError) as refusal:
        backend.connect()

    assert str(refusal.value).startswith(f"reader busy: {CONSOLE_HOLDER} (pid {other.pid}) has held {READER!r} since ")
    # One channel built, never connected: the refusal is not retried.
    assert len(fake_pcsc.built) == 1
    assert fake_pcsc.built[0].connects == 0
    other.release()


def test_a_bridge_that_never_connects_gives_the_reader_back(lock_dir, fake_pcsc):
    fake_pcsc.fail_connect = True
    backend = router.BackendCardChannel(reader_index=0)

    with pytest.raises(PcscBridgeError):
        backend.connect()

    assert len(fake_pcsc.built) == 5
    assert probe(lock_dir) == {"held": True}


def _snapshot() -> UsbPresenceSnapshot:
    return UsbPresenceSnapshot(
        source="test",
        present=True,
        matches=("Bus 003 Device 099: ID 1d50:60e3 SIMtrace 2",),
        devices=(UsbDeviceLocator(vendor_id="1d50", product_id="60e3", bus=3, address=99),),
    )


class _Monitor:
    def snapshot(self) -> UsbPresenceSnapshot:
        return _snapshot()

    def wait_for_change(self, timeout_seconds: float) -> None:
        del timeout_seconds


class _NamedReader:
    def __init__(self, reader_index: int = 0, reader_name: str = "") -> None:
        del reader_index, reader_name

    def selected_reader_name(self) -> str:
        return READER


class SupervisorReaderGateTests(unittest.TestCase):
    """No session start while another process holds the bridge's reader."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.lock_dir = os.path.join(directory.name, "reader-locks")
        self.state_path = os.path.join(directory.name, "supervisor.json")
        patches = (
            mock.patch.object(reader_locks, "_DIRECTORY", self.lock_dir),
            mock.patch("Tools.HilBridge.supervisor.PcscCardChannel", _NamedReader),
            mock.patch.object(HilBridgeSupervisor, "_sim_backend_active", return_value=False),
            mock.patch.object(HilBridgeSupervisor, "_reconcile_modem_diag"),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.reset = mock.patch.object(
            HilBridgeSupervisor, "_reset_device_before_session", side_effect=lambda snapshot: snapshot
        ).start()
        self.addCleanup(mock.patch.stopall)
        self.start = mock.patch.object(HilBridgeSupervisor, "_start_bridge_child").start()
        self.supervisor = HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(bridge=BridgeConfig(), state_path=self.state_path),
            usb_monitor=_Monitor(),
            monotonic=lambda: 100.0,
        )

    def _state(self) -> dict:
        with open(self.state_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def test_a_held_reader_starts_nothing_and_says_who_holds_it(self) -> None:
        other = OtherProcess(self.lock_dir, long_running=True)
        self.addCleanup(other.close)
        with mock.patch("Tools.HilBridge.supervisor.LOGGER") as logger:
            self.supervisor.reconcile()
            self.supervisor.reconcile()
        self.start.assert_not_called()
        self.reset.assert_not_called()
        state = self._state()
        self.assertEqual(state["status"], "reader-busy")
        self.assertIn(f"held by {CONSOLE_HOLDER} (pid {other.pid}) since ", state["reason"])
        # Said once, not on every pass of the loop.
        self.assertEqual(logger.warning.call_count, 1)

        other.release()
        self.supervisor.reconcile()
        self.reset.assert_called_once()
        self.start.assert_called_once()

    def test_a_free_reader_starts_the_session(self) -> None:
        self.supervisor.reconcile()
        self.reset.assert_called_once()
        self.start.assert_called_once()


if __name__ == "__main__":
    unittest.main()


def test_a_missing_pcsc_service_reads_as_no_reader() -> None:
    """The lookup the supervisor makes before a session must not crash on a host without pcscd."""
    from smartcard.pcsc.PCSCExceptions import EstablishContextException

    from Tools.HilBridge import pcsc

    def _no_service() -> list[object]:
        raise EstablishContextException(0x8010001D)

    runtime = (_no_service, None, None, None, None, None, PcscBridgeError)
    with mock.patch.object(pcsc, "_load_smartcard_runtime", lambda: runtime):
        with pytest.raises(PcscBridgeError, match="PC/SC is not available"):
            pcsc.PcscCardChannel(reader_index=0, reader_name="").selected_reader_name()
