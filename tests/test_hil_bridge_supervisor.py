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
        supervisor._remote_card_atr_hex = "3B9F9680"
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
