from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from Tools.HilBridge.router import BridgeConfig
from Tools.HilBridge.supervisor import (
    HilBridgeSupervisor,
    HilBridgeSupervisorConfig,
    LsusbPresenceMonitor,
    PyudevPresenceMonitor,
    UsbPresenceSnapshot,
    create_usb_presence_monitor,
)
from yggdrasim_common.card_backend import CARD_RELAY_MARKER_FILENAME


class _MutableUsbMonitor:
    def __init__(self, snapshot: UsbPresenceSnapshot) -> None:
        self.snapshot_value = snapshot
        self.wait_calls: list[float] = []

    def snapshot(self) -> UsbPresenceSnapshot:
        return self.snapshot_value

    def wait_for_change(self, timeout_seconds: float) -> None:
        self.wait_calls.append(float(timeout_seconds))


class _FakeChildProcess:
    def __init__(self, pid: int) -> None:
        self.pid = int(pid)
        self.returncode: int | None = None
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_calls: list[float] = []
        self.wait_effects: list[object] = []

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1
        self.returncode = 0

    def kill(self) -> None:
        self.kill_calls += 1
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls.append(float(timeout or 0.0))
        if len(self.wait_effects) > 0:
            effect = self.wait_effects.pop(0)
            if isinstance(effect, BaseException):
                raise effect
            if effect is not None:
                self.returncode = int(effect)
                return int(self.returncode)
        if self.returncode is None:
            self.returncode = 0
        return int(self.returncode)


class HilBridgeSupervisorTests(unittest.TestCase):
    def test_lsusb_monitor_detects_simtrace_presence(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["lsusb"],
            returncode=0,
            stdout="Bus 001 Device 010: ID 1d50:60e3 sysmocom SIMtrace 2\n",
            stderr="",
        )
        with mock.patch("Tools.HilBridge.supervisor.subprocess.run", return_value=completed):
            monitor = LsusbPresenceMonitor(
                match_terms=("simtrace", "sysmocom"),
                vidpids=("dead:beef",),
            )
            snapshot = monitor.snapshot()

        self.assertTrue(snapshot.present)
        self.assertEqual(snapshot.source, "lsusb")
        self.assertEqual(
            snapshot.matches,
            ("Bus 001 Device 010: ID 1d50:60e3 sysmocom SIMtrace 2",),
        )

    def test_create_usb_presence_monitor_falls_back_to_lsusb_when_pyudev_is_unavailable(self) -> None:
        with mock.patch.object(PyudevPresenceMonitor, "create", side_effect=ImportError("no pyudev")):
            monitor = create_usb_presence_monitor(
                match_terms=("simtrace",),
                vidpids=(),
                prefer_pyudev=True,
                lsusb_path="lsusb",
            )

        self.assertIsInstance(monitor, LsusbPresenceMonitor)

    def test_supervisor_starts_bridge_child_when_usb_is_present(self) -> None:
        monitor = _MutableUsbMonitor(
            UsbPresenceSnapshot(
                source="lsusb",
                present=True,
                matches=("Bus 001 Device 010: ID 1d50:60e3 sysmocom SIMtrace 2",),
            )
        )
        spawned: list[tuple[list[str], dict, _FakeChildProcess]] = []

        def popen_factory(command: list[str], **kwargs):
            process = _FakeChildProcess(pid=4100 + len(spawned))
            spawned.append((list(command), dict(kwargs), process))
            return process

        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state" / "hil_bridge_supervisor.json"
            config = HilBridgeSupervisorConfig(
                bridge=BridgeConfig(reader_index=1, listen_port=9997),
                debug_enabled=True,
                bridge_python="/usr/bin/python3",
                state_path=str(state_path),
            )
            supervisor = HilBridgeSupervisor(
                config=config,
                usb_monitor=monitor,
                popen_factory=popen_factory,
                monotonic=lambda: 10.0,
            )
            with mock.patch.dict(os.environ, {"YGGDRASIM_RUNTIME_ROOT": temp_dir}, clear=False):
                supervisor.reconcile()

                self.assertEqual(len(spawned), 2)
                bridge_command, bridge_kwargs, bridge_process = spawned[0]
                remsim_command, remsim_kwargs, remsim_process = spawned[1]
                self.assertEqual(bridge_command[:3], ["/usr/bin/python3", "-m", "Tools.HilBridge.main"])
                self.assertIn("--debug", bridge_command)
                self.assertEqual(bridge_kwargs["stdin"], subprocess.DEVNULL)
                self.assertTrue(bool(bridge_kwargs["start_new_session"]))
                self.assertEqual(bridge_process.pid, 4100)
                self.assertEqual(
                    remsim_command,
                    [
                        "osmo-remsim-client-st2",
                        "-i",
                        "127.0.0.1",
                        "-p",
                        "9997",
                        "-c",
                        "0",
                        "-n",
                        "0",
                        "-V",
                        "0x1d50",
                        "-P",
                        "0x60e3",
                        "-A",
                        "10",
                        "-C",
                        "1",
                        "-I",
                        "0",
                        "-S",
                        "0",
                    ],
                )
                self.assertEqual(remsim_kwargs["stdin"], subprocess.DEVNULL)
                self.assertTrue(bool(remsim_kwargs["start_new_session"]))
                self.assertEqual(remsim_process.pid, 4101)

                state_payload = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(state_payload["status"], "running")
        self.assertTrue(bool(state_payload["usbPresent"]))
        self.assertEqual(state_payload["bridgePid"], 4100)
        self.assertEqual(state_payload["remsimClientPid"], 4101)
        self.assertTrue(bool(state_payload["remsimClientRunning"]))
        self.assertEqual(state_payload["readerIndex"], 1)

    def test_build_bridge_command_forwards_no_gsmtap_when_disabled(self) -> None:
        monitor = _MutableUsbMonitor(UsbPresenceSnapshot(source="test", present=False))
        config = HilBridgeSupervisorConfig(
            bridge=BridgeConfig(reader_index=0, listen_port=9997, gsmtap_enabled=False),
        )
        supervisor = HilBridgeSupervisor(
            config=config,
            usb_monitor=monitor,
        )

        command = supervisor._build_bridge_command()

        self.assertIn("--no-gsmtap", command)

    def test_build_bridge_command_forwards_gsmtap_capture_path(self) -> None:
        monitor = _MutableUsbMonitor(UsbPresenceSnapshot(source="test", present=False))
        config = HilBridgeSupervisorConfig(
            bridge=BridgeConfig(
                reader_index=0,
                listen_port=9997,
                gsmtap_capture_path="/tmp/live_capture.pcap",
            ),
        )
        supervisor = HilBridgeSupervisor(
            config=config,
            usb_monitor=monitor,
        )

        command = supervisor._build_bridge_command()

        self.assertIn("--gsmtap-capture-path", command)
        self.assertIn("/tmp/live_capture.pcap", command)

    def test_supervisor_stops_bridge_child_and_cleans_marker_when_usb_disappears(self) -> None:
        monitor = _MutableUsbMonitor(
            UsbPresenceSnapshot(
                source="lsusb",
                present=True,
                matches=("Bus 001 Device 010: ID 1d50:60e3 sysmocom SIMtrace 2",),
            )
        )
        spawned: list[tuple[list[str], _FakeChildProcess]] = []

        def popen_factory(command: list[str], **kwargs):
            del kwargs
            process = _FakeChildProcess(pid=5200 + len(spawned))
            spawned.append((list(command), process))
            return process

        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state" / "hil_bridge_supervisor.json"
            marker_path = Path(temp_dir) / "state" / CARD_RELAY_MARKER_FILENAME
            marker_path.parent.mkdir(parents=True, exist_ok=True)
            config = HilBridgeSupervisorConfig(
                bridge=BridgeConfig(reader_index=0, listen_port=9997),
                state_path=str(state_path),
            )
            # This case exercises the *reader-mode* supervisor path:
            # USB-disappears → bridge child stops → relay marker is
            # cleaned. The session-wide default is ``YGGDRASIM_CARD_BACKEND=sim``
            # (see tests/conftest.py) because most of the suite has no
            # hardware to talk to. Opt back into reader mode explicitly
            # so ``_sim_backend_active()`` returns False and the
            # USB-gate kicks in.
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": temp_dir,
                    "YGGDRASIM_CARD_BACKEND": "reader",
                },
                clear=False,
            ):
                supervisor = HilBridgeSupervisor(
                    config=config,
                    usb_monitor=monitor,
                    popen_factory=popen_factory,
                    monotonic=lambda: 20.0,
                )
                signal_calls: list[tuple[int, int]] = []
                with mock.patch.object(
                    HilBridgeSupervisor,
                    "_signal_child_process_group",
                    autospec=True,
                    side_effect=lambda self, pid, signal_number: signal_calls.append((pid, signal_number)) or True,
                ):
                    supervisor.reconcile()
                    marker_path.write_text(
                        json.dumps(
                            {
                                "pid": spawned[0][1].pid,
                                "url": "http://127.0.0.1:12345/apdu",
                            }
                        ),
                        encoding="utf-8",
                    )
                    monitor.snapshot_value = UsbPresenceSnapshot(source="lsusb", present=False)

                    supervisor.reconcile()
                    state_payload = json.loads(state_path.read_text(encoding="utf-8"))

            self.assertFalse(marker_path.exists())

        self.assertEqual(
            signal_calls,
            [
                (spawned[1][1].pid, signal.SIGTERM),
                (spawned[0][1].pid, signal.SIGTERM),
            ],
        )
        self.assertEqual(spawned[0][1].terminate_calls, 0)
        self.assertEqual(spawned[1][1].terminate_calls, 0)
        self.assertEqual(state_payload["status"], "waiting-usb")
        self.assertFalse(bool(state_payload["bridgeRunning"]))
        self.assertFalse(bool(state_payload["remsimClientRunning"]))

    def test_supervisor_restarts_bridge_after_unexpected_child_exit(self) -> None:
        monitor = _MutableUsbMonitor(
            UsbPresenceSnapshot(
                source="lsusb",
                present=True,
                matches=("Bus 001 Device 010: ID 1d50:60e3 sysmocom SIMtrace 2",),
            )
        )
        spawned: list[_FakeChildProcess] = []
        current_time = {"value": 0.0}

        def popen_factory(command: list[str], **kwargs):
            del kwargs
            del command
            process = _FakeChildProcess(pid=6100 + len(spawned))
            spawned.append(process)
            return process

        with tempfile.TemporaryDirectory() as temp_dir:
            config = HilBridgeSupervisorConfig(
                bridge=BridgeConfig(),
                restart_backoff_seconds=1.0,
                state_path=str(Path(temp_dir) / "state" / "hil_bridge_supervisor.json"),
            )
            with mock.patch.dict(os.environ, {"YGGDRASIM_RUNTIME_ROOT": temp_dir}, clear=False):
                supervisor = HilBridgeSupervisor(
                    config=config,
                    usb_monitor=monitor,
                    popen_factory=popen_factory,
                    monotonic=lambda: float(current_time["value"]),
                )
                with mock.patch.object(
                    HilBridgeSupervisor,
                    "_signal_child_process_group",
                    autospec=True,
                    return_value=True,
                ):
                    supervisor.reconcile()
                    self.assertEqual(len(spawned), 2)

                    spawned[0].returncode = 3
                    current_time["value"] = 0.5
                    supervisor.reconcile()
                    self.assertEqual(len(spawned), 2)
                    self.assertEqual(spawned[1].returncode, 0)

                    current_time["value"] = 1.6
                    supervisor.reconcile()

        self.assertEqual(len(spawned), 4)

    def test_supervisor_restarts_remsim_after_unexpected_client_exit(self) -> None:
        monitor = _MutableUsbMonitor(
            UsbPresenceSnapshot(
                source="lsusb",
                present=True,
                matches=("Bus 001 Device 010: ID 1d50:60e3 sysmocom SIMtrace 2",),
            )
        )
        spawned: list[_FakeChildProcess] = []
        current_time = {"value": 0.0}

        def popen_factory(command: list[str], **kwargs):
            del command
            del kwargs
            process = _FakeChildProcess(pid=8100 + len(spawned))
            spawned.append(process)
            return process

        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state" / "hil_bridge_supervisor.json"
            config = HilBridgeSupervisorConfig(
                bridge=BridgeConfig(),
                restart_backoff_seconds=1.0,
                state_path=str(state_path),
            )
            supervisor = HilBridgeSupervisor(
                config=config,
                usb_monitor=monitor,
                popen_factory=popen_factory,
                monotonic=lambda: float(current_time["value"]),
            )
            with mock.patch.dict(os.environ, {"YGGDRASIM_RUNTIME_ROOT": temp_dir}, clear=False):
                supervisor.reconcile()
                self.assertEqual(len(spawned), 2)

                spawned[1].returncode = 7
                current_time["value"] = 0.5
                supervisor.reconcile()
                state_payload = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual(state_payload["status"], "client-restart-pending")
                self.assertEqual(len(spawned), 2)

                current_time["value"] = 1.6
                supervisor.reconcile()

        self.assertEqual(len(spawned), 3)

    def test_supervisor_starts_bridge_in_sim_mode_without_usb_or_remsim(self) -> None:
        # Sim-backend gate: even with USB absent and the lsusb monitor
        # reporting "no SIMtrace2 device", the bridge child must come
        # up and the REMSIM client must stay down.
        monitor = _MutableUsbMonitor(UsbPresenceSnapshot(source="lsusb", present=False))
        spawned: list[tuple[list[str], _FakeChildProcess]] = []

        def popen_factory(command: list[str], **kwargs):
            del kwargs
            process = _FakeChildProcess(pid=9100 + len(spawned))
            spawned.append((list(command), process))
            return process

        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state" / "hil_bridge_supervisor.json"
            config = HilBridgeSupervisorConfig(
                bridge=BridgeConfig(reader_index=0, listen_port=9997),
                state_path=str(state_path),
            )
            supervisor = HilBridgeSupervisor(
                config=config,
                usb_monitor=monitor,
                popen_factory=popen_factory,
                monotonic=lambda: 30.0,
            )
            with mock.patch.dict(
                os.environ,
                {"YGGDRASIM_RUNTIME_ROOT": temp_dir, "YGGDRASIM_CARD_BACKEND": "sim"},
                clear=False,
            ):
                supervisor.reconcile()
                state_payload = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(len(spawned), 1)
        bridge_command, _ = spawned[0]
        self.assertEqual(bridge_command[:3], [config.bridge_python, "-m", "Tools.HilBridge.main"])
        self.assertEqual(state_payload["status"], "running")
        self.assertEqual(state_payload["cardBackendGate"], "sim")
        self.assertFalse(bool(state_payload["usbPresent"]))
        self.assertEqual(state_payload["usbSource"], "lsusb")
        self.assertTrue(bool(state_payload["bridgeRunning"]))
        self.assertEqual(state_payload["bridgePid"], 9100)
        self.assertFalse(bool(state_payload["remsimClientRunning"]))
        self.assertTrue(bool(state_payload["remsimClientEnabled"]))
        self.assertIn("Simulated card backend", state_payload["reason"])

    def test_supervisor_keeps_remsim_running_when_backend_toggles_to_sim_with_usb_present(self) -> None:
        # Modem-in-the-loop sim mode: SIMtrace2 cable is plugged in
        # and the operator picks the simulated card. The bridge swaps
        # to the simulator transparently, but the REMSIM client MUST
        # stay alive so the modem keeps getting answers from the
        # bridge.
        monitor = _MutableUsbMonitor(
            UsbPresenceSnapshot(
                source="lsusb",
                present=True,
                matches=("Bus 001 Device 010: ID 1d50:60e3 sysmocom SIMtrace 2",),
            )
        )
        spawned: list[_FakeChildProcess] = []

        def popen_factory(command: list[str], **kwargs):
            del command
            del kwargs
            process = _FakeChildProcess(pid=9300 + len(spawned))
            spawned.append(process)
            return process

        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state" / "hil_bridge_supervisor.json"
            config = HilBridgeSupervisorConfig(
                bridge=BridgeConfig(reader_index=0, listen_port=9997),
                state_path=str(state_path),
            )
            supervisor = HilBridgeSupervisor(
                config=config,
                usb_monitor=monitor,
                popen_factory=popen_factory,
                monotonic=lambda: 40.0,
            )
            with mock.patch.dict(
                os.environ,
                {"YGGDRASIM_RUNTIME_ROOT": temp_dir},
                clear=False,
            ):
                with mock.patch.object(
                    HilBridgeSupervisor,
                    "_signal_child_process_group",
                    autospec=True,
                    return_value=True,
                ):
                    supervisor.reconcile()
                    self.assertEqual(len(spawned), 2)
                    bridge_process, remsim_process = spawned
                    self.assertIsNone(bridge_process.returncode)
                    self.assertIsNone(remsim_process.returncode)

                    with mock.patch.dict(
                        os.environ,
                        {"YGGDRASIM_CARD_BACKEND": "sim"},
                        clear=False,
                    ):
                        supervisor.reconcile()
                        state_payload = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(len(spawned), 2)
        self.assertEqual(state_payload["cardBackendGate"], "sim")
        self.assertTrue(bool(state_payload["bridgeRunning"]))
        self.assertTrue(bool(state_payload["remsimClientRunning"]))
        self.assertTrue(bool(state_payload["remsimClientEnabled"]))
        self.assertTrue(bool(state_payload["usbPresent"]))

    def test_supervisor_drops_remsim_in_sim_mode_when_usb_disappears_but_keeps_bridge(self) -> None:
        # Cable yank in sim mode: bridge keeps serving the simulator
        # to the YggdraSIM-side relay (no modem on the bus right now)
        # but REMSIM is shut down because there is no SIMtrace2 to
        # attach to.
        monitor = _MutableUsbMonitor(
            UsbPresenceSnapshot(
                source="lsusb",
                present=True,
                matches=("Bus 001 Device 010: ID 1d50:60e3 sysmocom SIMtrace 2",),
            )
        )
        spawned: list[_FakeChildProcess] = []
        signal_calls: list[tuple[int, int]] = []

        def popen_factory(command: list[str], **kwargs):
            del command
            del kwargs
            process = _FakeChildProcess(pid=9500 + len(spawned))
            spawned.append(process)
            return process

        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state" / "hil_bridge_supervisor.json"
            config = HilBridgeSupervisorConfig(
                bridge=BridgeConfig(reader_index=0, listen_port=9997),
                state_path=str(state_path),
            )
            supervisor = HilBridgeSupervisor(
                config=config,
                usb_monitor=monitor,
                popen_factory=popen_factory,
                monotonic=lambda: 50.0,
            )
            with mock.patch.dict(
                os.environ,
                {"YGGDRASIM_RUNTIME_ROOT": temp_dir, "YGGDRASIM_CARD_BACKEND": "sim"},
                clear=False,
            ):
                with mock.patch.object(
                    HilBridgeSupervisor,
                    "_signal_child_process_group",
                    autospec=True,
                    side_effect=lambda self, pid, signal_number: signal_calls.append((pid, signal_number)) or True,
                ):
                    supervisor.reconcile()
                    self.assertEqual(len(spawned), 2)
                    bridge_process, remsim_process = spawned

                    monitor.snapshot_value = UsbPresenceSnapshot(source="lsusb", present=False)
                    supervisor.reconcile()
                    state_payload = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertIn((remsim_process.pid, signal.SIGTERM), signal_calls)
        self.assertNotIn((bridge_process.pid, signal.SIGTERM), signal_calls)
        self.assertTrue(bool(state_payload["bridgeRunning"]))
        self.assertFalse(bool(state_payload["remsimClientRunning"]))
        self.assertEqual(state_payload["cardBackendGate"], "sim")

    def test_supervisor_forces_group_kill_when_bridge_child_does_not_exit(self) -> None:
        monitor = _MutableUsbMonitor(UsbPresenceSnapshot(source="lsusb", present=False))
        process = _FakeChildProcess(pid=7200)
        process.wait_effects = [
            subprocess.TimeoutExpired(cmd="python -m Tools.HilBridge.main", timeout=5.0),
            0,
        ]
        signal_calls: list[tuple[int, int]] = []

        with tempfile.TemporaryDirectory() as temp_dir:
            config = HilBridgeSupervisorConfig(
                bridge=BridgeConfig(),
                state_path=str(Path(temp_dir) / "state" / "hil_bridge_supervisor.json"),
            )
            supervisor = HilBridgeSupervisor(
                config=config,
                usb_monitor=monitor,
                popen_factory=lambda *args, **kwargs: process,
                monotonic=lambda: 0.0,
            )
            supervisor._child = process
            with mock.patch.dict(os.environ, {"YGGDRASIM_RUNTIME_ROOT": temp_dir}, clear=False):
                with mock.patch.object(
                    HilBridgeSupervisor,
                    "_signal_child_process_group",
                    autospec=True,
                    side_effect=lambda self, pid, signal_number: signal_calls.append((pid, signal_number)) or True,
                ):
                    supervisor._stop_bridge_child("synthetic deactivation")

        self.assertEqual(
            signal_calls,
            [
                (process.pid, signal.SIGTERM),
                (process.pid, signal.SIGKILL),
            ],
        )
        self.assertEqual(process.kill_calls, 0)


if __name__ == "__main__":
    unittest.main()
