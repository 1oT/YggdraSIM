# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for ``Tools.HilBridge.device_reset``.

The module is the remote replacement for the SIMtrace2 reset button.
Every test here drives it through injected fakes: no USB device node is
opened, no ``uhubctl`` process is spawned, and no wall-clock time is
spent settling.
"""

from __future__ import annotations

import subprocess
import unittest

from Tools.HilBridge.device_reset import (
    DEFAULT_RESET_MODE,
    RESET_MODE_AUTO,
    RESET_MODE_OFF,
    RESET_MODE_PORT_POWER,
    RESET_MODE_USB_RESET,
    USBDEVFS_RESET,
    SimtraceResetConfig,
    SimtraceResetError,
    SimtraceResetOutcome,
    build_reset_config_from_args,
    build_uhubctl_command,
    issue_usbdevfs_reset,
    normalize_reset_mode,
    reset_simtrace_device,
    resolve_reset_mode_from_env,
    run_port_power_cycle,
    usb_device_node_path,
    wait_for_device_return,
)


class NormalizeResetModeTests(unittest.TestCase):

    def test_known_modes_pass_through(self) -> None:
        for mode in (RESET_MODE_OFF, RESET_MODE_USB_RESET, RESET_MODE_PORT_POWER, RESET_MODE_AUTO):
            self.assertEqual(normalize_reset_mode(mode), mode)

    def test_empty_value_falls_back_to_default(self) -> None:
        self.assertEqual(normalize_reset_mode(""), DEFAULT_RESET_MODE)

    def test_falsey_env_spellings_disable(self) -> None:
        for value in ("0", "false", "no", "OFF", "disabled"):
            self.assertEqual(normalize_reset_mode(value), RESET_MODE_OFF)

    def test_truthy_env_spellings_select_default(self) -> None:
        for value in ("1", "true", "YES", "on", "enabled"):
            self.assertEqual(normalize_reset_mode(value), DEFAULT_RESET_MODE)

    def test_booleans_are_accepted(self) -> None:
        self.assertEqual(normalize_reset_mode(True), DEFAULT_RESET_MODE)
        self.assertEqual(normalize_reset_mode(False), RESET_MODE_OFF)

    def test_underscore_spelling_is_tolerated(self) -> None:
        self.assertEqual(normalize_reset_mode("port_power"), RESET_MODE_PORT_POWER)

    def test_unknown_value_falls_back_rather_than_raising(self) -> None:
        # A typo in a systemd unit must not take the rig down.
        self.assertEqual(normalize_reset_mode("usbreset!"), DEFAULT_RESET_MODE)

    def test_explicit_default_is_honoured(self) -> None:
        self.assertEqual(normalize_reset_mode("", default=RESET_MODE_OFF), RESET_MODE_OFF)


class ResolveResetModeFromEnvTests(unittest.TestCase):

    def test_explicit_value_wins_over_environment(self) -> None:
        mode = resolve_reset_mode_from_env(
            RESET_MODE_PORT_POWER,
            environ={"YGGDRASIM_HIL_SIMTRACE_RESET": "off"},
        )
        self.assertEqual(mode, RESET_MODE_PORT_POWER)

    def test_environment_is_used_when_value_is_blank(self) -> None:
        mode = resolve_reset_mode_from_env(
            "",
            environ={"YGGDRASIM_HIL_SIMTRACE_RESET": "off"},
        )
        self.assertEqual(mode, RESET_MODE_OFF)

    def test_missing_environment_key_uses_default(self) -> None:
        self.assertEqual(resolve_reset_mode_from_env("", environ={}), DEFAULT_RESET_MODE)


class UsbDeviceNodePathTests(unittest.TestCase):

    def test_numbers_are_zero_padded(self) -> None:
        self.assertEqual(usb_device_node_path(1, 7), "/dev/bus/usb/001/007")

    def test_three_digit_numbers_are_unpadded(self) -> None:
        self.assertEqual(usb_device_node_path(12, 123), "/dev/bus/usb/012/123")

    def test_zero_bus_is_rejected(self) -> None:
        self.assertEqual(usb_device_node_path(0, 7), "")

    def test_zero_address_is_rejected(self) -> None:
        self.assertEqual(usb_device_node_path(1, 0), "")

    def test_non_numeric_values_are_rejected(self) -> None:
        self.assertEqual(usb_device_node_path("bus", "device"), "")

    def test_custom_root_is_honoured(self) -> None:
        self.assertEqual(usb_device_node_path(1, 7, root="/fake/usb/"), "/fake/usb/001/007")


class SimtraceResetConfigTests(unittest.TestCase):

    def test_default_config_is_enabled(self) -> None:
        self.assertTrue(SimtraceResetConfig().enabled)

    def test_off_mode_disables(self) -> None:
        self.assertFalse(SimtraceResetConfig(mode=RESET_MODE_OFF).enabled)

    def test_port_power_needs_a_hub_location(self) -> None:
        self.assertFalse(SimtraceResetConfig().port_power_available)
        self.assertTrue(SimtraceResetConfig(uhubctl_location="1-1").port_power_available)


class IssueUsbdevfsResetTests(unittest.TestCase):

    def test_ioctl_is_issued_and_descriptor_closed(self) -> None:
        calls: list[tuple] = []

        def _opener(path: str, flags: int) -> int:
            calls.append(("open", path, flags))
            return 9

        def _ioctl(descriptor: int, request: int, argument: int) -> int:
            calls.append(("ioctl", descriptor, request, argument))
            return 0

        def _closer(descriptor: int) -> None:
            calls.append(("close", descriptor))

        issue_usbdevfs_reset(
            "/dev/bus/usb/001/007",
            opener=_opener,
            closer=_closer,
            ioctl_func=_ioctl,
        )

        self.assertEqual(calls[0][0:2], ("open", "/dev/bus/usb/001/007"))
        self.assertEqual(calls[1], ("ioctl", 9, USBDEVFS_RESET, 0))
        self.assertEqual(calls[2], ("close", 9))

    def test_blank_node_path_is_rejected(self) -> None:
        with self.assertRaises(SimtraceResetError):
            issue_usbdevfs_reset("", opener=lambda *_a, **_k: 0, ioctl_func=lambda *_a: 0)

    def test_permission_error_mentions_udev(self) -> None:
        def _opener(_path: str, _flags: int) -> int:
            raise PermissionError(13, "Permission denied")

        with self.assertRaises(SimtraceResetError) as ctx:
            issue_usbdevfs_reset(
                "/dev/bus/usb/001/007",
                opener=_opener,
                ioctl_func=lambda *_a: 0,
            )
        self.assertIn("udev", str(ctx.exception))

    def test_descriptor_is_closed_when_ioctl_fails(self) -> None:
        closed: list[int] = []

        def _ioctl(_descriptor: int, _request: int, _argument: int) -> int:
            raise OSError(19, "No such device")

        with self.assertRaises(SimtraceResetError):
            issue_usbdevfs_reset(
                "/dev/bus/usb/001/007",
                opener=lambda *_a, **_k: 4,
                closer=closed.append,
                ioctl_func=_ioctl,
            )
        self.assertEqual(closed, [4])


class UhubctlCommandTests(unittest.TestCase):

    def test_command_includes_location_port_and_action(self) -> None:
        config = SimtraceResetConfig(uhubctl_location="1-1", uhubctl_port="2")
        self.assertEqual(
            build_uhubctl_command(config, action="off"),
            ["uhubctl", "-l", "1-1", "-p", "2", "-a", "off"],
        )

    def test_port_is_omitted_when_unset(self) -> None:
        config = SimtraceResetConfig(uhubctl_location="1-1")
        self.assertEqual(
            build_uhubctl_command(config, action="on"),
            ["uhubctl", "-l", "1-1", "-a", "on"],
        )

    def test_missing_location_is_rejected(self) -> None:
        with self.assertRaises(SimtraceResetError):
            build_uhubctl_command(SimtraceResetConfig(), action="off")


class _CompletedProcess:
    def __init__(self, returncode: int = 0, stderr: str = "", stdout: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


class RunPortPowerCycleTests(unittest.TestCase):

    def test_power_is_cut_then_restored(self) -> None:
        commands: list[list[str]] = []
        slept: list[float] = []

        def _runner(command, **_kwargs):
            commands.append(list(command))
            return _CompletedProcess()

        run_port_power_cycle(
            SimtraceResetConfig(uhubctl_location="1-1", port_power_off_seconds=3.0),
            runner=_runner,
            sleeper=slept.append,
        )

        self.assertEqual(commands[0][-1], "off")
        self.assertEqual(commands[1][-1], "on")
        self.assertEqual(slept, [3.0])

    def test_missing_binary_is_reported(self) -> None:
        def _runner(_command, **_kwargs):
            raise FileNotFoundError(2, "No such file")

        with self.assertRaises(SimtraceResetError) as ctx:
            run_port_power_cycle(
                SimtraceResetConfig(uhubctl_location="1-1"),
                runner=_runner,
                sleeper=lambda _seconds: None,
            )
        self.assertIn("uhubctl", str(ctx.exception))

    def test_non_zero_exit_is_reported(self) -> None:
        def _runner(_command, **_kwargs):
            return _CompletedProcess(returncode=1, stderr="No compatible devices")

        with self.assertRaises(SimtraceResetError) as ctx:
            run_port_power_cycle(
                SimtraceResetConfig(uhubctl_location="1-1"),
                runner=_runner,
                sleeper=lambda _seconds: None,
            )
        self.assertIn("No compatible devices", str(ctx.exception))

    def test_timeout_is_reported(self) -> None:
        def _runner(command, **_kwargs):
            raise subprocess.TimeoutExpired(cmd=command, timeout=1.0)

        with self.assertRaises(SimtraceResetError):
            run_port_power_cycle(
                SimtraceResetConfig(uhubctl_location="1-1"),
                runner=_runner,
                sleeper=lambda _seconds: None,
            )


class WaitForDeviceReturnTests(unittest.TestCase):

    def test_returns_true_once_the_board_is_back(self) -> None:
        answers = iter([False, False, True])
        self.assertTrue(
            wait_for_device_return(
                lambda: next(answers),
                SimtraceResetConfig(settle_poll_seconds=0.1, settle_timeout_seconds=10.0),
                sleeper=lambda _seconds: None,
                monotonic=lambda: 0.0,
            )
        )

    def test_returns_false_when_the_settle_budget_expires(self) -> None:
        clock = iter([0.0, 5.0, 10.0, 30.0, 30.0])
        self.assertFalse(
            wait_for_device_return(
                lambda: False,
                SimtraceResetConfig(settle_poll_seconds=0.1, settle_timeout_seconds=10.0),
                sleeper=lambda _seconds: None,
                monotonic=lambda: next(clock),
            )
        )

    def test_probe_exceptions_do_not_abort_the_wait(self) -> None:
        attempts: list[int] = []

        def _probe() -> bool:
            attempts.append(1)
            if len(attempts) < 3:
                raise OSError("transient enumeration error")
            return True

        self.assertTrue(
            wait_for_device_return(
                _probe,
                SimtraceResetConfig(settle_poll_seconds=0.1, settle_timeout_seconds=10.0),
                sleeper=lambda _seconds: None,
                monotonic=lambda: 0.0,
            )
        )

    def test_missing_probe_sleeps_once_and_reports_unknown(self) -> None:
        slept: list[float] = []
        self.assertFalse(
            wait_for_device_return(
                None,
                SimtraceResetConfig(settle_poll_seconds=0.25),
                sleeper=slept.append,
            )
        )
        self.assertEqual(slept, [0.25])


class ResetSimtraceDeviceTests(unittest.TestCase):

    def test_disabled_mode_does_nothing(self) -> None:
        outcome = reset_simtrace_device(
            config=SimtraceResetConfig(mode=RESET_MODE_OFF),
            bus=1,
            address=7,
            usb_reset=lambda _node: self.fail("usb reset must not run when disabled"),
        )
        self.assertFalse(outcome.performed)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.mode, RESET_MODE_OFF)

    def test_usb_reset_targets_the_device_node(self) -> None:
        seen: list[str] = []
        outcome = reset_simtrace_device(
            config=SimtraceResetConfig(mode=RESET_MODE_USB_RESET),
            bus=3,
            address=42,
            presence_probe=lambda: True,
            usb_reset=seen.append,
            sleeper=lambda _seconds: None,
        )
        self.assertEqual(seen, ["/dev/bus/usb/003/042"])
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.reenumerated)
        self.assertEqual(outcome.mode, RESET_MODE_USB_RESET)
        self.assertEqual(outcome.device_node, "/dev/bus/usb/003/042")

    def test_usb_reset_failure_is_reported_not_raised(self) -> None:
        def _usb_reset(_node: str) -> None:
            raise SimtraceResetError("Permission denied")

        outcome = reset_simtrace_device(
            config=SimtraceResetConfig(mode=RESET_MODE_USB_RESET),
            bus=1,
            address=7,
            usb_reset=_usb_reset,
        )
        self.assertFalse(outcome.performed)
        self.assertFalse(outcome.ok)
        self.assertIn("Permission denied", outcome.error)

    def test_auto_mode_falls_back_to_port_power(self) -> None:
        def _usb_reset(_node: str) -> None:
            raise SimtraceResetError("usbfs node is not writable")

        outcome = reset_simtrace_device(
            config=SimtraceResetConfig(mode=RESET_MODE_AUTO, uhubctl_location="1-1"),
            bus=1,
            address=7,
            presence_probe=lambda: True,
            usb_reset=_usb_reset,
            power_cycle=lambda _config: "VBUS cycled",
            sleeper=lambda _seconds: None,
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.mode, RESET_MODE_PORT_POWER)
        self.assertEqual(outcome.device_node, "")

    def test_auto_mode_without_hub_location_stays_on_usb_reset(self) -> None:
        outcome = reset_simtrace_device(
            config=SimtraceResetConfig(mode=RESET_MODE_AUTO),
            bus=1,
            address=7,
            usb_reset=lambda _node: None,
            power_cycle=lambda _config: self.fail("port-power needs a hub location"),
            presence_probe=lambda: True,
            sleeper=lambda _seconds: None,
        )
        self.assertEqual(outcome.mode, RESET_MODE_USB_RESET)

    def test_auto_mode_reports_both_failures(self) -> None:
        def _usb_reset(_node: str) -> None:
            raise SimtraceResetError("node missing")

        def _power_cycle(_config: SimtraceResetConfig) -> str:
            raise SimtraceResetError("hub refused")

        outcome = reset_simtrace_device(
            config=SimtraceResetConfig(mode=RESET_MODE_AUTO, uhubctl_location="1-1"),
            bus=1,
            address=7,
            usb_reset=_usb_reset,
            power_cycle=_power_cycle,
        )
        self.assertIn("node missing", outcome.error)
        self.assertIn("hub refused", outcome.error)

    def test_port_power_works_without_a_known_device_node(self) -> None:
        # A board that is present but whose bus/address could not be
        # parsed still gets a VBUS cycle.
        outcome = reset_simtrace_device(
            config=SimtraceResetConfig(mode=RESET_MODE_PORT_POWER, uhubctl_location="1-1"),
            bus=0,
            address=0,
            presence_probe=lambda: True,
            power_cycle=lambda _config: "VBUS cycled",
            sleeper=lambda _seconds: None,
        )
        self.assertTrue(outcome.ok)

    def test_board_that_does_not_return_is_flagged(self) -> None:
        outcome = reset_simtrace_device(
            config=SimtraceResetConfig(settle_timeout_seconds=1.0, settle_poll_seconds=0.1),
            bus=1,
            address=7,
            presence_probe=lambda: False,
            usb_reset=lambda _node: None,
            sleeper=lambda _seconds: None,
            monotonic=iter([0.0, 99.0, 99.0]).__next__,
        )
        self.assertTrue(outcome.performed)
        self.assertFalse(outcome.reenumerated)
        self.assertIn("did not re-appear", outcome.detail)


class ResetOutcomeStatePayloadTests(unittest.TestCase):

    def test_payload_carries_every_field(self) -> None:
        payload = SimtraceResetOutcome(
            performed=True,
            mode=RESET_MODE_USB_RESET,
            detail="USBDEVFS_RESET issued on /dev/bus/usb/001/007.",
            device_node="/dev/bus/usb/001/007",
            reenumerated=True,
        ).as_state_payload()
        self.assertEqual(payload["mode"], RESET_MODE_USB_RESET)
        self.assertEqual(payload["deviceNode"], "/dev/bus/usb/001/007")
        self.assertTrue(payload["performed"])
        self.assertTrue(payload["reenumerated"])
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["error"], "")

    def test_failed_outcome_is_not_ok(self) -> None:
        payload = SimtraceResetOutcome(performed=True, error="boom").as_state_payload()
        self.assertFalse(payload["ok"])


class BuildResetConfigFromArgsTests(unittest.TestCase):

    def _parse(self, argv: list[str]):
        import argparse

        from Tools.HilBridge.device_reset import add_reset_arguments

        parser = argparse.ArgumentParser()
        add_reset_arguments(parser)
        return parser.parse_args(argv)

    def test_defaults_enable_usb_reset(self) -> None:
        config = build_reset_config_from_args(self._parse([]), environ={})
        self.assertEqual(config.mode, RESET_MODE_USB_RESET)
        self.assertTrue(config.enabled)

    def test_no_simtrace_reset_flag_disables(self) -> None:
        config = build_reset_config_from_args(self._parse(["--no-simtrace-reset"]), environ={})
        self.assertFalse(config.enabled)

    def test_no_flag_beats_an_enabling_environment(self) -> None:
        config = build_reset_config_from_args(
            self._parse(["--no-simtrace-reset"]),
            environ={"YGGDRASIM_HIL_SIMTRACE_RESET": "auto"},
        )
        self.assertFalse(config.enabled)

    def test_environment_supplies_the_mode_when_the_flag_is_absent(self) -> None:
        config = build_reset_config_from_args(
            self._parse([]),
            environ={"YGGDRASIM_HIL_SIMTRACE_RESET": "port-power"},
        )
        self.assertEqual(config.mode, RESET_MODE_PORT_POWER)

    def test_uhubctl_settings_come_from_the_environment(self) -> None:
        config = build_reset_config_from_args(
            self._parse([]),
            environ={
                "YGGDRASIM_HIL_UHUBCTL_BINARY": "/opt/bin/uhubctl",
                "YGGDRASIM_HIL_UHUBCTL_LOCATION": "1-1",
                "YGGDRASIM_HIL_UHUBCTL_PORT": "4",
            },
        )
        self.assertEqual(config.uhubctl_binary, "/opt/bin/uhubctl")
        self.assertEqual(config.uhubctl_location, "1-1")
        self.assertEqual(config.uhubctl_port, "4")

    def test_explicit_flags_beat_the_environment(self) -> None:
        config = build_reset_config_from_args(
            self._parse(["--uhubctl-location", "2-1", "--simtrace-reset", "auto"]),
            environ={
                "YGGDRASIM_HIL_UHUBCTL_LOCATION": "1-1",
                "YGGDRASIM_HIL_SIMTRACE_RESET": "off",
            },
        )
        self.assertEqual(config.uhubctl_location, "2-1")
        self.assertEqual(config.mode, RESET_MODE_AUTO)

    def test_timing_knobs_are_clamped(self) -> None:
        config = build_reset_config_from_args(
            self._parse(
                [
                    "--simtrace-reset-settle-poll",
                    "0.0",
                    "--simtrace-reset-min-interval",
                    "-5",
                    "--uhubctl-power-off-seconds",
                    "0",
                ]
            ),
            environ={},
        )
        self.assertGreaterEqual(config.settle_poll_seconds, 0.05)
        self.assertEqual(config.min_interval_seconds, 0.0)
        self.assertGreaterEqual(config.port_power_off_seconds, 0.1)


if __name__ == "__main__":
    unittest.main()
