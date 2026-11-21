# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for pure helpers in ``Tools.HilBridge.supervisor``.

Covers: normalize_usb_vidpid, UsbDeviceLocator.usable_for_remsim.
No USB hardware, lsusb, or subprocess invocation is made.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from Tools.HilBridge.device_reset import (
    RESET_MODE_OFF,
    RESET_MODE_USB_RESET,
    SimtraceResetConfig,
    SimtraceResetOutcome,
)
from Tools.HilBridge.router import BridgeConfig
from Tools.HilBridge.supervisor import (
    HilBridgeSupervisor,
    HilBridgeSupervisorConfig,
    RemsimClientConfig,
    UsbDeviceLocator,
    UsbPresenceSnapshot,
    _plausible_atr_hex,
    normalize_usb_vidpid,
)


class NormalizeUsbVidpidTests(unittest.TestCase):

    def test_uppercase_converted_to_lower(self) -> None:
        self.assertEqual(normalize_usb_vidpid("04E6:5116"), "04e6:5116")

    def test_already_lowercase_unchanged(self) -> None:
        self.assertEqual(normalize_usb_vidpid("04e6:5116"), "04e6:5116")

    def test_empty_string_returns_empty(self) -> None:
        self.assertEqual(normalize_usb_vidpid(""), "")

    def test_no_colon_returns_empty(self) -> None:
        self.assertEqual(normalize_usb_vidpid("04e65116"), "")

    def test_missing_vendor_id_returns_empty(self) -> None:
        self.assertEqual(normalize_usb_vidpid(":5116"), "")

    def test_missing_product_id_returns_empty(self) -> None:
        self.assertEqual(normalize_usb_vidpid("04e6:"), "")

    def test_non_hex_vendor_id_returns_empty(self) -> None:
        self.assertEqual(normalize_usb_vidpid("ZZZZ:5116"), "")

    def test_non_hex_product_id_returns_empty(self) -> None:
        self.assertEqual(normalize_usb_vidpid("04e6:WXYZ"), "")

    def test_whitespace_stripped(self) -> None:
        self.assertEqual(normalize_usb_vidpid("  04e6:5116  "), "04e6:5116")

    def test_returns_string(self) -> None:
        self.assertIsInstance(normalize_usb_vidpid("04e6:5116"), str)

    def test_single_char_components_accepted(self) -> None:
        # Any non-empty hex sequence on each side is valid.
        self.assertEqual(normalize_usb_vidpid("a:b"), "a:b")


class UsbDeviceLocatorUsableTests(unittest.TestCase):

    def test_complete_device_is_usable(self) -> None:
        dev = UsbDeviceLocator(vendor_id="04e6", product_id="5116", address=5, bus=1)
        self.assertTrue(dev.usable_for_remsim)

    def test_address_zero_not_usable(self) -> None:
        dev = UsbDeviceLocator(vendor_id="04e6", product_id="5116", address=0, bus=1)
        self.assertFalse(dev.usable_for_remsim)

    def test_short_vendor_id_not_usable(self) -> None:
        dev = UsbDeviceLocator(vendor_id="04e", product_id="5116", address=5, bus=1)
        self.assertFalse(dev.usable_for_remsim)

    def test_short_product_id_not_usable(self) -> None:
        dev = UsbDeviceLocator(vendor_id="04e6", product_id="511", address=5, bus=1)
        self.assertFalse(dev.usable_for_remsim)

    def test_empty_vendor_id_not_usable(self) -> None:
        dev = UsbDeviceLocator(vendor_id="", product_id="5116", address=5, bus=1)
        self.assertFalse(dev.usable_for_remsim)

    def test_returns_bool(self) -> None:
        dev = UsbDeviceLocator()
        self.assertIsInstance(dev.usable_for_remsim, bool)


class _IdleMonitor:
    def snapshot(self):
        raise AssertionError("snapshot is not needed for command construction")

    def wait_for_change(self, timeout_seconds: float) -> None:
        del timeout_seconds


class _ExitedChild:
    pid = 12345

    def __init__(self, return_code: int) -> None:
        self.return_code = return_code

    def poll(self) -> int:
        return self.return_code


class BridgeCommandTests(unittest.TestCase):
    def test_bridge_command_forwards_remote_card_and_timeout(self) -> None:
        supervisor = HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(
                    remote_card_url="http://127.0.0.1:8642/apdu",
                    remote_card_token_file="/tmp/card-bridge.token",
                    apdu_timeout_ms=30000,
                    card_trace_enabled=True,
                ),
                remsim_client=RemsimClientConfig(enabled=False),
                bridge_python="python3",
            ),
            usb_monitor=_IdleMonitor(),
        )

        command = supervisor._build_bridge_command()

        self.assertIn("--remote-card-url", command)
        self.assertIn("http://127.0.0.1:8642/apdu", command)
        self.assertIn("--remote-card-token-file", command)
        self.assertIn("/tmp/card-bridge.token", command)
        self.assertIn("--apdu-timeout-ms", command)
        self.assertEqual(command[command.index("--apdu-timeout-ms") + 1], "30000")
        self.assertIn("--card-trace", command)


class BridgeRestartBackoffTests(unittest.TestCase):
    def test_remote_card_child_exit_uses_calmer_backoff(self) -> None:
        supervisor = HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(remote_card_url="http://127.0.0.1:8642/apdu"),
                restart_backoff_seconds=1.0,
                remote_card_restart_backoff_seconds=15.0,
            ),
            usb_monitor=_IdleMonitor(),
            monotonic=lambda: 100.0,
        )
        supervisor._child = _ExitedChild(return_code=1)

        with mock.patch.object(HilBridgeSupervisor, "_cleanup_stale_bridge_marker"):
            supervisor._reconcile_child_exit(100.0)

        self.assertEqual(supervisor._next_start_not_before, 115.0)
        self.assertIn(
            "Remote card relay is configured",
            supervisor._bridge_restart_pending_reason(15.0),
        )

    def test_local_child_exit_keeps_standard_restart_backoff(self) -> None:
        supervisor = HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(),
                restart_backoff_seconds=1.0,
                remote_card_restart_backoff_seconds=15.0,
            ),
            usb_monitor=_IdleMonitor(),
            monotonic=lambda: 100.0,
        )
        supervisor._child = _ExitedChild(return_code=1)

        with mock.patch.object(HilBridgeSupervisor, "_cleanup_stale_bridge_marker"):
            supervisor._reconcile_child_exit(100.0)

        self.assertEqual(supervisor._next_start_not_before, 101.0)
        self.assertNotIn(
            "Remote card relay",
            supervisor._bridge_restart_pending_reason(1.0),
        )


def _present_snapshot(*, bus: int, address: int) -> UsbPresenceSnapshot:
    return UsbPresenceSnapshot(
        source="test",
        present=True,
        matches=(f"Bus {bus:03d} Device {address:03d}: ID 1d50:60e3 SIMtrace 2",),
        devices=(
            UsbDeviceLocator(vendor_id="1d50", product_id="60e3", bus=bus, address=address),
        ),
    )


class _ScriptedMonitor:
    """USB monitor that walks a fixed list of snapshots, then repeats the last."""

    def __init__(self, snapshots) -> None:
        self.snapshots = list(snapshots)
        self.calls = 0

    def snapshot(self) -> UsbPresenceSnapshot:
        index = min(self.calls, len(self.snapshots) - 1)
        self.calls += 1
        return self.snapshots[index]

    def wait_for_change(self, timeout_seconds: float) -> None:
        del timeout_seconds


class _RunningChild:
    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid

    def poll(self):
        return None


def _reset_supervisor(
    monitor,
    *,
    reset_config: SimtraceResetConfig,
    state_path: str,
    monotonic=lambda: 0.0,
) -> HilBridgeSupervisor:
    return HilBridgeSupervisor(
        config=HilBridgeSupervisorConfig(
            bridge=BridgeConfig(),
            remsim_client=RemsimClientConfig(enabled=True),
            device_reset=reset_config,
            state_path=state_path,
        ),
        usb_monitor=monitor,
        monotonic=monotonic,
    )


class DeviceResetBeforeSessionTests(unittest.TestCase):
    """The supervisor's stand-in for the SIMtrace2 reset button."""

    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)
        self.state_path = os.path.join(self._temp_dir.name, "supervisor.json")

    def test_reset_uses_pre_reset_address_and_returns_the_refreshed_snapshot(self) -> None:
        before = _present_snapshot(bus=1, address=7)
        after = _present_snapshot(bus=1, address=9)
        monitor = _ScriptedMonitor([after])
        supervisor = _reset_supervisor(
            monitor,
            reset_config=SimtraceResetConfig(mode=RESET_MODE_USB_RESET),
            state_path=self.state_path,
        )
        seen: dict = {}

        def _fake_reset(**kwargs):
            seen.update(kwargs)
            return SimtraceResetOutcome(
                performed=True,
                mode=RESET_MODE_USB_RESET,
                detail="reset",
                reenumerated=True,
            )

        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fake_reset):
            refreshed = supervisor._reset_device_before_session(before)

        # The board is addressed by its pre-reset bus/address...
        self.assertEqual(seen["bus"], 1)
        self.assertEqual(seen["address"], 7)
        # ...but everything downstream must use the new address, because
        # osmo-remsim-client-st2 is pinned to it with -A.
        self.assertEqual(refreshed.devices[0].address, 9)
        self.assertEqual(supervisor._device_reset_count, 1)

    def test_disabled_reset_is_a_no_op(self) -> None:
        snapshot = _present_snapshot(bus=1, address=7)
        supervisor = _reset_supervisor(
            _ScriptedMonitor([snapshot]),
            reset_config=SimtraceResetConfig(mode=RESET_MODE_OFF),
            state_path=self.state_path,
        )

        def _fail(**_kwargs):
            self.fail("reset must not run when the mode is off")

        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fail):
            self.assertIs(supervisor._reset_device_before_session(snapshot), snapshot)
        self.assertEqual(supervisor._device_reset_count, 0)

    def test_absent_hardware_is_never_reset(self) -> None:
        snapshot = UsbPresenceSnapshot(source="test", present=False)
        supervisor = _reset_supervisor(
            _ScriptedMonitor([snapshot]),
            reset_config=SimtraceResetConfig(),
            state_path=self.state_path,
        )

        def _fail(**_kwargs):
            self.fail("reset must not run without a board on the bus")

        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fail):
            self.assertIs(supervisor._reset_device_before_session(snapshot), snapshot)

    def test_min_interval_throttles_a_crash_restart_loop(self) -> None:
        snapshot = _present_snapshot(bus=1, address=7)
        clock = {"value": 0.0}
        supervisor = _reset_supervisor(
            _ScriptedMonitor([snapshot]),
            reset_config=SimtraceResetConfig(min_interval_seconds=30.0),
            state_path=self.state_path,
            monotonic=lambda: clock["value"],
        )
        calls: list[int] = []

        def _fake_reset(**_kwargs):
            calls.append(1)
            return SimtraceResetOutcome(performed=True, mode=RESET_MODE_USB_RESET, reenumerated=True)

        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fake_reset):
            supervisor._reset_device_before_session(snapshot)
            clock["value"] = 5.0
            supervisor._reset_device_before_session(snapshot)
            self.assertEqual(len(calls), 1)
            clock["value"] = 40.0
            supervisor._reset_device_before_session(snapshot)

        self.assertEqual(len(calls), 2)

    def test_failed_reset_keeps_the_original_snapshot(self) -> None:
        snapshot = _present_snapshot(bus=1, address=7)
        supervisor = _reset_supervisor(
            _ScriptedMonitor([_present_snapshot(bus=1, address=9)]),
            reset_config=SimtraceResetConfig(),
            state_path=self.state_path,
        )

        def _fake_reset(**_kwargs):
            return SimtraceResetOutcome(performed=False, error="Permission denied")

        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fake_reset):
            self.assertIs(supervisor._reset_device_before_session(snapshot), snapshot)
        self.assertEqual(supervisor._device_reset_count, 0)

    def test_remsim_client_is_stopped_before_the_bus_is_reset(self) -> None:
        snapshot = _present_snapshot(bus=1, address=7)
        supervisor = _reset_supervisor(
            _ScriptedMonitor([snapshot]),
            reset_config=SimtraceResetConfig(),
            state_path=self.state_path,
        )
        supervisor._remsim_child = _RunningChild()
        order: list[str] = []

        def _fake_reset(**_kwargs):
            order.append("reset")
            return SimtraceResetOutcome(performed=True, mode=RESET_MODE_USB_RESET, reenumerated=True)

        def _fake_stop(_self, reason: str) -> None:
            order.append("stop-remsim")
            _self._remsim_child = None

        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fake_reset):
            with mock.patch.object(HilBridgeSupervisor, "_stop_remsim_child", _fake_stop):
                supervisor._reset_device_before_session(snapshot)

        self.assertEqual(order, ["stop-remsim", "reset"])

    def test_reconcile_resets_before_starting_the_bridge_child(self) -> None:
        before = _present_snapshot(bus=1, address=7)
        after = _present_snapshot(bus=1, address=9)
        monitor = _ScriptedMonitor([before, after])
        supervisor = _reset_supervisor(
            monitor,
            reset_config=SimtraceResetConfig(),
            state_path=self.state_path,
        )
        order: list[str] = []

        def _fake_reset(**_kwargs):
            order.append("reset")
            return SimtraceResetOutcome(performed=True, mode=RESET_MODE_USB_RESET, reenumerated=True)

        remsim_commands: list[list[str]] = []

        def _popen(command, *_args, **_kwargs):
            if "osmo-remsim-client-st2" in str(command[0]):
                order.append("start-remsim")
                remsim_commands.append(list(command))
            else:
                order.append("start-bridge")
            return _RunningChild()

        supervisor.popen_factory = _popen
        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fake_reset):
            with mock.patch.object(HilBridgeSupervisor, "_sim_backend_active", lambda _self: False):
                with mock.patch.object(HilBridgeSupervisor, "_cleanup_stale_bridge_marker"):
                    # The reader lookup asks the host's PC/SC service.
                    with mock.patch.object(HilBridgeSupervisor, "_local_reader_holder", lambda _self, _sim: None):
                        supervisor.reconcile()

        self.assertEqual(order, ["reset", "start-bridge", "start-remsim"])
        # The REMSIM client must be pinned to the post-reset USB address.
        self.assertIn("-A", remsim_commands[0])
        self.assertEqual(remsim_commands[0][remsim_commands[0].index("-A") + 1], "9")
        with open(self.state_path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        self.assertEqual(state["simtraceReset"]["mode"], RESET_MODE_USB_RESET)
        self.assertEqual(state["simtraceReset"]["count"], 1)
        self.assertTrue(state["simtraceReset"]["last"]["ok"])

    def test_state_payload_reports_a_disabled_reset(self) -> None:
        supervisor = _reset_supervisor(
            _ScriptedMonitor([UsbPresenceSnapshot(source="test", present=False)]),
            reset_config=SimtraceResetConfig(mode=RESET_MODE_OFF),
            state_path=self.state_path,
        )
        payload = supervisor._device_reset_state_payload()
        self.assertFalse(payload["enabled"])
        self.assertEqual(payload["mode"], RESET_MODE_OFF)
        self.assertNotIn("last", payload)



class RemsimAtrSeedingTests(unittest.TestCase):
    """The REMSIM client is handed the real ATR before it attaches.

    osmo-remsim-client presents '3B00' until bankd sends a setAtrReq, and
    it activates the modem the moment it attaches -- so a modem that was
    already powered latches the stub and reports no SIM. The router's
    setAtrReq is driven by a modem slot-status edge, which that modem
    never produces, so the seed is what makes the first activation right.
    """

    def _supervisor(self, *, remote_card_url: str, extra_args: tuple[str, ...] = ()):
        return HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(remote_card_url=remote_card_url),
                remsim_client=RemsimClientConfig(extra_args=extra_args),
            ),
            usb_monitor=_IdleMonitor(),
        )

    def test_atr_read_from_the_relay_reaches_the_command_line(self) -> None:
        supervisor = self._supervisor(remote_card_url="http://127.0.0.1:8642/apdu")
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={"atr": "3b9f96803f87828031e073fe211f67455475323008653d"},
        ) as relay_call, mock.patch(
            "Tools.HilBridge.supervisor.resolve_remote_card_token",
            return_value="token",
        ):
            self.assertEqual(
                supervisor.refresh_remote_card_atr(),
                "3B9F96803F87828031E073FE211F67455475323008653D",
            )

        self.assertEqual(relay_call.call_args.args[0], "http://127.0.0.1:8642/status")
        command = supervisor._build_remsim_command()
        self.assertIn("-a", command)
        self.assertEqual(
            command[command.index("-a") + 1],
            "3B9F96803F87828031E073FE211F67455475323008653D",
        )

    def test_an_operator_supplied_atr_flag_is_not_duplicated(self) -> None:
        supervisor = self._supervisor(
            remote_card_url="http://127.0.0.1:8642/apdu",
            extra_args=("-a", "3B00"),
        )
        supervisor._client_seed_atr_hex = "3B9F9680"
        command = supervisor._build_remsim_command()
        self.assertEqual(command.count("-a"), 1)
        self.assertNotIn("3B9F9680", command)

    def test_a_relay_that_reports_no_usable_atr_leaves_the_client_unseeded(self) -> None:
        supervisor = self._supervisor(remote_card_url="http://127.0.0.1:8642/apdu")
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={"atr": ""},
        ), mock.patch(
            "Tools.HilBridge.supervisor.resolve_remote_card_token",
            return_value="token",
        ):
            self.assertEqual(supervisor.refresh_remote_card_atr(), "")
        self.assertNotIn("-a", supervisor._build_remsim_command())

    def test_an_unreachable_relay_leaves_the_client_unseeded(self) -> None:
        supervisor = self._supervisor(remote_card_url="http://127.0.0.1:8642/apdu")
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            side_effect=OSError("connection refused"),
        ), mock.patch(
            "Tools.HilBridge.supervisor.resolve_remote_card_token",
            return_value="token",
        ):
            self.assertEqual(supervisor.refresh_remote_card_atr(), "")
        self.assertNotIn("-a", supervisor._build_remsim_command())

    def test_a_local_reader_bridge_never_calls_the_relay(self) -> None:
        supervisor = self._supervisor(remote_card_url="")
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json"
        ) as relay_call:
            self.assertEqual(supervisor.refresh_remote_card_atr(), "")
        relay_call.assert_not_called()


class PlausibleAtrHexTests(unittest.TestCase):
    """TS is '3B' or '3F' (ETSI TS 102 221 V18.4.0 Annex D)."""

    def test_direct_convention_accepted(self) -> None:
        self.assertEqual(_plausible_atr_hex("3b9f96"), "3B9F96")

    def test_inverse_convention_accepted(self) -> None:
        self.assertEqual(_plausible_atr_hex("3F9F96"), "3F9F96")

    def test_foreign_initial_character_rejected(self) -> None:
        self.assertEqual(_plausible_atr_hex("419F96"), "")

    def test_odd_length_rejected(self) -> None:
        self.assertEqual(_plausible_atr_hex("3B9F9"), "")

    def test_non_hex_rejected(self) -> None:
        self.assertEqual(_plausible_atr_hex("3BZZ"), "")

    def test_empty_rejected(self) -> None:
        self.assertEqual(_plausible_atr_hex(""), "")

if __name__ == "__main__":
    unittest.main()


class ModemRefreshOnReconnectTests(unittest.TestCase):
    """A reconnect is a connect, so the modem has to be told to look again.

    The supervisor brings the card path back on its own after a network
    interruption, but a modem that stayed powered has nothing to re-read:
    it keeps answering "no SIM" while the supervisor reports running with
    the lease held, and nothing else will ever send the refresh.
    """

    def _supervisor(self, **overrides):
        config = HilBridgeSupervisorConfig(
            bridge=BridgeConfig(
                remote_card_url="http://127.0.0.1:8908/apdu",
                remote_card_token_file="/tmp/card-bridge.token",
            ),
            remsim_client=RemsimClientConfig(enabled=False),
            bridge_python="python3",
            modem_at_device=overrides.pop("modem_at_device", "/dev/ttyUSB2"),
        )
        return HilBridgeSupervisor(config=config, usb_monitor=_IdleMonitor())

    def test_the_refresh_waits_for_the_card_path_to_settle(self) -> None:
        """Sent at spawn time the modem finds no SIM and settles on none."""
        from Tools.HilBridge import supervisor as sup

        supervisor = self._supervisor()
        clock = {"t": 100.0}
        supervisor.monotonic = lambda: clock["t"]
        supervisor._pending_modem_refresh_at = clock["t"] + sup.MODEM_REFRESH_SETTLE_SECONDS

        sent = []
        with mock.patch.object(
            HilBridgeSupervisor,
            "_refresh_modem_sim_interface",
            lambda _self: sent.append(clock["t"]),
        ):
            with mock.patch.object(
                HilBridgeSupervisor, "_bridge_is_running", lambda _self: True
            ):
                with mock.patch.object(
                    HilBridgeSupervisor, "_remsim_is_running", lambda _self: True
                ):
                    # Too early: nothing is sent.
                    supervisor._service_pending_modem_refresh(clock["t"])
                    self.assertEqual(sent, [])

                    clock["t"] += sup.MODEM_REFRESH_SETTLE_SECONDS
                    supervisor._service_pending_modem_refresh(clock["t"])
                    self.assertEqual(len(sent), 1)

                    # And only once per arming.
                    supervisor._service_pending_modem_refresh(clock["t"] + 60)
                    self.assertEqual(len(sent), 1)

    def test_a_path_that_fell_over_again_is_not_refreshed(self) -> None:
        """Refreshing a modem with nothing behind it just loses the SIM again."""
        supervisor = self._supervisor()
        supervisor._pending_modem_refresh_at = 1.0

        sent = []
        with mock.patch.object(
            HilBridgeSupervisor,
            "_refresh_modem_sim_interface",
            lambda _self: sent.append(True),
        ):
            with mock.patch.object(
                HilBridgeSupervisor, "_bridge_is_running", lambda _self: True
            ):
                with mock.patch.object(
                    HilBridgeSupervisor, "_remsim_is_running", lambda _self: False
                ):
                    supervisor._service_pending_modem_refresh(500.0)
        self.assertEqual(sent, [])
        self.assertEqual(supervisor._pending_modem_refresh_at, 0.0)

    def test_no_device_configured_means_no_refresh(self) -> None:
        """An unset AT port leaves the behaviour exactly as it was."""
        supervisor = self._supervisor(modem_at_device="")
        with mock.patch.object(
            HilBridgeSupervisor, "_bridge_uses_remote_card", lambda _self: True
        ):
            with mock.patch("subprocess.run") as runner:
                supervisor._refresh_modem_sim_interface()
        self.assertEqual(runner.call_count, 0)


class _ModemDiagChild:
    """A fake mirror process: running until told an exit code, stoppable."""

    def __init__(self, pid: int = 0) -> None:
        self.pid = pid
        self.return_code = None
        self.terminated = False

    def poll(self):
        return self.return_code

    def terminate(self) -> None:
        self.terminated = True
        self.return_code = -15

    def wait(self, timeout=None):
        return self.return_code

    def kill(self) -> None:
        self.return_code = -9


class ModemDiagMirrorChildTests(unittest.TestCase):
    """The modem-side DIAG mirror is optional and must never touch the bridge.

    It runs as its own child for the supervisor's lifetime, restarts on its own
    backoff, and none of its failures reach the bridge, the REMSIM client or
    the state's status and reason.
    """

    def _supervisor(self, *, device: str = "auto", gsmtap_enabled: bool = True, popen=None, clock=None):
        self.started: list[list[str]] = []
        self.children: list[_ModemDiagChild] = []

        def default_popen(command, **kwargs):
            self.started.append(list(command))
            self.children.append(_ModemDiagChild())
            return self.children[-1]

        self.state_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.state_dir.cleanup)
        # Reader mode with no SIMtrace2: the bridge stays down, so every
        # process started here is the mirror.
        backend = mock.patch.object(HilBridgeSupervisor, "_sim_backend_active", lambda _self: False)
        backend.start()
        self.addCleanup(backend.stop)
        return HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(gsmtap_enabled=gsmtap_enabled),
                remsim_client=RemsimClientConfig(enabled=False),
                bridge_python="python3",
                state_path=os.path.join(self.state_dir.name, "state.json"),
                modem_diag_device=device,
            ),
            usb_monitor=_ScriptedMonitor([UsbPresenceSnapshot(source="test", present=False)]),
            popen_factory=popen or default_popen,
            monotonic=clock or (lambda: 0.0),
        )

    def _state(self, supervisor) -> dict:
        with open(supervisor.config.state_path, encoding="utf-8") as handle:
            return json.load(handle)

    def test_nothing_starts_without_a_device(self) -> None:
        supervisor = self._supervisor(device="")
        supervisor.reconcile()
        self.assertEqual(self.started, [])
        self.assertEqual(self._state(supervisor)["modemDiag"]["enabled"], False)

    def test_nothing_starts_when_the_bridge_sends_no_gsmtap(self) -> None:
        supervisor = self._supervisor(gsmtap_enabled=False)
        supervisor.reconcile()
        self.assertEqual(self.started, [])

    def test_the_mirror_follows_the_bridge_gsmtap_destination(self) -> None:
        supervisor = self._supervisor()
        supervisor.reconcile()
        self.assertEqual(len(self.started), 1)
        command = self.started[0]
        self.assertIn("Tools.HilBridge.modem_diag", command)
        self.assertEqual(command[command.index("--device") + 1], "auto")
        self.assertEqual(command[command.index("--gsmtap-port") + 1], "4729")
        self.assertEqual(command[command.index("--gsmtap-host") + 1], "127.0.0.1")
        self.assertTrue(self._state(supervisor)["modemDiag"]["running"])

    def test_the_session_state_reads_the_same_with_and_without_the_mirror(self) -> None:
        without = self._supervisor(device="")
        without.reconcile()
        expected = self._state(without)
        with_mirror = self._supervisor()
        with_mirror.reconcile()
        actual = self._state(with_mirror)
        for key in ("status", "reason", "bridgeRunning", "remsimClientRunning", "usbPresent"):
            self.assertEqual(actual[key], expected[key], key)

    def test_an_exit_waits_for_the_backoff_and_a_permanent_one_waits_longer(self) -> None:
        from Tools.HilBridge import supervisor as sup

        clock = {"t": 0.0}
        supervisor = self._supervisor(clock=lambda: clock["t"])
        supervisor.reconcile()
        self.children[0].return_code = 1
        supervisor.reconcile()
        self.assertEqual(len(self.started), 1)
        clock["t"] = sup.MODEM_DIAG_RESTART_BACKOFF_SECONDS - 1
        supervisor.reconcile()
        self.assertEqual(len(self.started), 1)
        clock["t"] = sup.MODEM_DIAG_RESTART_BACKOFF_SECONDS
        supervisor.reconcile()
        self.assertEqual(len(self.started), 2)

        self.children[1].return_code = sup.MODEM_DIAG_PERMANENT_EXIT_CODE
        supervisor.reconcile()
        clock["t"] += sup.MODEM_DIAG_RESTART_BACKOFF_SECONDS
        supervisor.reconcile()
        self.assertEqual(len(self.started), 2)
        clock["t"] += sup.MODEM_DIAG_PERMANENT_BACKOFF_SECONDS
        supervisor.reconcile()
        self.assertEqual(len(self.started), 3)
        self.assertEqual(self._state(supervisor)["status"], "waiting-usb")

    def test_a_start_failure_is_contained(self) -> None:
        def failing_popen(command, **kwargs):
            raise OSError(2, "No such file or directory")

        supervisor = self._supervisor(popen=failing_popen)
        supervisor.reconcile()
        state = self._state(supervisor)
        self.assertEqual(state["status"], "waiting-usb")
        self.assertFalse(state["modemDiag"]["running"])
        self.assertIn("No such file", state["modemDiag"]["lastError"])

    def test_an_unexpected_error_is_contained(self) -> None:
        def exploding_popen(command, **kwargs):
            raise KeyError("not an OSError at all")

        supervisor = self._supervisor(popen=exploding_popen)
        supervisor.reconcile()
        self.assertEqual(self._state(supervisor)["status"], "waiting-usb")

    def test_shutdown_stops_the_mirror(self) -> None:
        supervisor = self._supervisor()
        supervisor.reconcile()
        with mock.patch.object(HilBridgeSupervisor, "_signal_child_process_group", lambda _self, pid, sig: False):
            supervisor._stop_modem_diag_child_quietly("supervisor shutdown")
        self.assertTrue(self.children[0].terminated)
        self.assertIsNone(supervisor._modem_diag_child)


class LocalReaderAtrSeedingTests(unittest.TestCase):
    """A local reader's ATR seeds the REMSIM client too.

    Unseeded, the client puts its '3B 00' placeholder on the board at start-up
    and on every bankd reconnect, and a modem activating in that gap reads the
    placeholder instead of the card.
    """

    CARD_ATR = "3B9F96803FC7828031E073FE211367274000B4000001A8"

    def _supervisor(self, *, extra_args: tuple[str, ...] = ()) -> HilBridgeSupervisor:
        supervisor = HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(),
                remsim_client=RemsimClientConfig(enabled=True, extra_args=extra_args),
                bridge_python="python3",
            ),
            usb_monitor=_IdleMonitor(),
        )
        supervisor._child = _RunningChild(pid=4321)
        return supervisor

    def _markers(self, *markers):
        sequence = iter(markers)
        last = {"value": {}}

        def read():
            last["value"] = next(sequence, last["value"])
            return last["value"]

        return mock.patch("Tools.HilBridge.supervisor.read_card_relay_marker", side_effect=read)

    def test_the_bridge_childs_published_atr_reaches_the_command_line(self) -> None:
        supervisor = self._supervisor()
        with self._markers({"pid": 4321, "atr": self.CARD_ATR}):
            self.assertEqual(supervisor.refresh_local_card_atr(), self.CARD_ATR)
        command = supervisor._build_remsim_command()
        self.assertEqual(command[command.index("-a") + 1], self.CARD_ATR)

    def test_waits_for_the_marker_of_the_current_bridge_child(self) -> None:
        supervisor = self._supervisor()
        with self._markers({}, {"pid": 999, "atr": "3B00"}, {"pid": 4321, "atr": self.CARD_ATR}):
            with mock.patch.object(supervisor._stop_event, "wait", return_value=False) as waits:
                self.assertEqual(supervisor.refresh_local_card_atr(), self.CARD_ATR)
        self.assertEqual(waits.call_count, 2)

    def test_no_marker_in_time_leaves_the_client_unseeded(self) -> None:
        supervisor = self._supervisor()
        with self._markers({}):
            with mock.patch.object(supervisor._stop_event, "wait", return_value=False):
                self.assertEqual(supervisor.refresh_local_card_atr(), "")
        self.assertNotIn("-a", supervisor._build_remsim_command())

    def test_an_implausible_atr_leaves_the_client_unseeded(self) -> None:
        supervisor = self._supervisor()
        with self._markers({"pid": 4321, "atr": "9000"}):
            self.assertEqual(supervisor.refresh_local_card_atr(), "")
        self.assertNotIn("-a", supervisor._build_remsim_command())

    def test_an_operator_supplied_atr_flag_is_not_duplicated(self) -> None:
        supervisor = self._supervisor(extra_args=("-a", "3B00"))
        with self._markers({"pid": 4321, "atr": self.CARD_ATR}):
            supervisor.refresh_local_card_atr()
        command = supervisor._build_remsim_command()
        self.assertEqual(command.count("-a"), 1)
        self.assertNotIn(self.CARD_ATR, command)

    def test_a_remote_card_bridge_is_left_to_the_relay_path(self) -> None:
        supervisor = HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(remote_card_url="http://127.0.0.1:8642/apdu"),
                remsim_client=RemsimClientConfig(enabled=True),
                bridge_python="python3",
            ),
            usb_monitor=_IdleMonitor(),
        )
        supervisor._child = _RunningChild(pid=4321)
        with self._markers({"pid": 4321, "atr": self.CARD_ATR}) as reader:
            self.assertEqual(supervisor.refresh_local_card_atr(), "")
        self.assertEqual(reader.call_count, 0)

    def test_the_client_start_uses_the_local_seed(self) -> None:
        supervisor = self._supervisor()
        started: list[list[str]] = []

        def popen(command, **kwargs):
            started.append(list(command))
            return _RunningChild(pid=5555)

        supervisor.popen_factory = popen
        with tempfile.TemporaryDirectory() as state_dir:
            supervisor.config = HilBridgeSupervisorConfig(
                bridge=BridgeConfig(),
                remsim_client=RemsimClientConfig(enabled=True),
                bridge_python="python3",
                state_path=os.path.join(state_dir, "state.json"),
            )
            with self._markers({"pid": 4321, "atr": self.CARD_ATR}):
                with mock.patch.object(HilBridgeSupervisor, "_sim_backend_active", lambda _self: False):
                    supervisor._start_remsim_child(_present_snapshot(bus=3, address=19))
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0][started[0].index("-a") + 1], self.CARD_ATR)
