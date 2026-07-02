# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for pure helpers in ``Tools.HilBridge.supervisor``.

Covers: normalize_usb_vidpid, UsbDeviceLocator.usable_for_remsim.
No USB hardware, lsusb, or subprocess invocation is made.
"""

from __future__ import annotations

import unittest
from unittest import mock

from Tools.HilBridge.router import BridgeConfig
from Tools.HilBridge.supervisor import (
    HilBridgeSupervisor,
    HilBridgeSupervisorConfig,
    RemsimClientConfig,
    UsbDeviceLocator,
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


if __name__ == "__main__":
    unittest.main()
