# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for pure helpers in ``Tools.HilBridge.supervisor``.

Covers: normalize_usb_vidpid, UsbDeviceLocator.usable_for_remsim.
No USB hardware, lsusb, or subprocess invocation is made.
"""

from __future__ import annotations

import unittest

from Tools.HilBridge.supervisor import UsbDeviceLocator, normalize_usb_vidpid


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


if __name__ == "__main__":
    unittest.main()
