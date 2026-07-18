# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regressions for strict SCP03 decoder-adjacent producers.

These checks keep the ProfilePackage EF.PUCT codec and the simulator's
SGP.22/SGP.32 notification producer aligned with their strict consumers.
"""

from __future__ import annotations

import unittest

from SCP03.logic.sgp32_decode import decode_notification_entry
from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.state import SimNotificationEntry
from SIMCARD.utils import encode_iccid_ef, read_tlv, tlv
from Tools.ProfilePackage.saip_asn1_decode import _decode_puct
from Tools.ProfilePackage.saip_asn1_encode import encode_ef_puct


class PuctExponentLayoutTests(unittest.TestCase):
    def test_exponent_boundaries_use_b5_sign_and_b6_to_b8_magnitude(self) -> None:
        cases = (
            (-7, 0xF),
            (-1, 0x3),
            (0, 0x0),
            (1, 0x2),
            (7, 0xE),
        )
        for exponent, expected_nibble in cases:
            with self.subTest(exponent=exponent):
                encoded = encode_ef_puct(
                    {
                        "currency": "EUR",
                        "eppu": 0xABC,
                        "exponent": exponent,
                    }
                )
                self.assertEqual(encoded, b"EUR" + bytes((0xAB, expected_nibble << 4 | 0x0C)))
                decoded = _decode_puct(encoded.hex())
                self.assertIsNotNone(decoded)
                self.assertEqual(decoded["eppu"], 0xABC)
                self.assertEqual(decoded["exponent"], exponent)

    def test_decode_boundary_nibbles_roundtrips_without_layout_drift(self) -> None:
        for raw, exponent in (
            (b"USD\x12\xE4", 7),
            (b"USD\x12\xF4", -7),
        ):
            with self.subTest(raw=raw.hex()):
                decoded = _decode_puct(raw.hex())
                self.assertIsNotNone(decoded)
                self.assertEqual(decoded["exponent"], exponent)
                self.assertEqual(
                    encode_ef_puct(dict(decoded), target_length=len(raw)),
                    raw,
                )


class NotificationBitStringProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        self.logic = SgpLogic(self.state)
        self.profile = self.state.profiles[0]

    @staticmethod
    def _metadata_values(response: bytes) -> list[bytes]:
        root_tag, root_value, _root_raw, root_end = read_tlv(response, 0)
        if root_tag != bytes.fromhex("BF28") or root_end != len(response):
            raise AssertionError("response is not one complete BF28 value")
        choice_tag, choice_value, _choice_raw, choice_end = read_tlv(root_value, 0)
        if choice_tag != b"\xA0" or choice_end != len(root_value):
            return []
        values: list[bytes] = []
        offset = 0
        while offset < len(choice_value):
            tag, value, _raw, offset = read_tlv(choice_value, offset)
            if tag != bytes.fromhex("BF2F"):
                raise AssertionError(f"unexpected metadata tag {tag.hex()}")
            values.append(value)
        return values

    def test_each_lifecycle_event_is_a_valid_named_bit_string(self) -> None:
        cases = (
            (SgpLogic.NOTIF_INSTALL, b"\x07\x80", "notificationInstall"),
            (SgpLogic.NOTIF_ENABLE, b"\x06\x40", "notificationEnable"),
            (SgpLogic.NOTIF_DISABLE, b"\x05\x20", "notificationDisable"),
            (SgpLogic.NOTIF_DELETE, b"\x04\x10", "notificationDelete"),
        )
        for operation, expected_value, expected_label in cases:
            with self.subTest(operation=operation):
                raw_metadata = self.logic._notification_metadata_tlv(
                    seq_number=1,
                    operation=operation,
                    iccid=self.profile.iccid,
                    notification_address="notify.example.test",
                )
                tag, value, _raw, end = read_tlv(raw_metadata, 0)
                self.assertEqual(tag, bytes.fromhex("BF2F"))
                self.assertEqual(end, len(raw_metadata))

                offset = 0
                operation_value = b""
                while offset < len(value):
                    field_tag, field_value, _field_raw, offset = read_tlv(value, offset)
                    if field_tag == b"\x81":
                        operation_value = field_value
                self.assertEqual(operation_value, expected_value)

                decoded = decode_notification_entry(value)
                self.assertIn(expected_label, decoded["operation"])

    def test_list_filter_selects_only_named_events(self) -> None:
        self.state.notifications = [
            SimNotificationEntry(
                seq_number=index,
                operation=operation,
                address="notify.example.test",
                iccid=self.profile.iccid,
            )
            for index, operation in enumerate(
                (
                    SgpLogic.NOTIF_INSTALL,
                    SgpLogic.NOTIF_ENABLE,
                    SgpLogic.NOTIF_DISABLE,
                    SgpLogic.NOTIF_DELETE,
                ),
                start=1,
            )
        ]
        # NotificationEvent { notificationEnable(1), notificationDelete(3) }:
        # four significant bits, payload 0101xxxx.
        request = tlv("BF28", tlv("81", b"\x04\x50"))

        response, sw1, sw2 = self.logic.handle_store_data(request)
        metadata_values = self._metadata_values(response)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(len(metadata_values), 2)
        labels = [
            decode_notification_entry(value)["operation"]
            for value in metadata_values
        ]
        self.assertIn("notificationEnable", labels[0])
        self.assertIn("notificationDelete", labels[1])

    def test_absent_filter_lists_all_but_empty_filter_lists_none(self) -> None:
        self.state.notifications = [
            SimNotificationEntry(
                seq_number=1,
                operation=SgpLogic.NOTIF_INSTALL,
                address="notify.example.test",
                iccid=self.profile.iccid,
            )
        ]

        all_response = self.logic._build_notification_list_response(
            bytes.fromhex("BF2800")
        )
        helper_default_response = self.logic._build_notification_list_response()
        none_response = self.logic._build_notification_list_response(
            tlv("BF28", tlv("81", b"\x00"))
        )

        self.assertEqual(len(self._metadata_values(all_response)), 1)
        self.assertEqual(len(self._metadata_values(helper_default_response)), 1)
        self.assertEqual(self._metadata_values(none_response), [])

    def test_malformed_filter_returns_undefined_error_without_touching_queue(self) -> None:
        self.state.notifications = [
            SimNotificationEntry(
                seq_number=1,
                operation=SgpLogic.NOTIF_DELETE,
                address="notify.example.test",
                iccid=self.profile.iccid,
            )
        ]
        malformed_values = (
            b"\x08\x80",  # unused-bit count outside 0..7
            b"\x04\x11",  # non-zero padding
            b"\x04",      # old raw enum: no BIT STRING payload
        )
        for malformed_value in malformed_values:
            with self.subTest(value=malformed_value.hex()):
                response, sw1, sw2 = self.logic.handle_store_data(
                    tlv("BF28", tlv("81", malformed_value))
                )
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(response, bytes.fromhex("BF280381017F"))
                self.assertEqual(len(self.state.notifications), 1)


class NotificationConfigurationUtf8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        self.logic = SgpLogic(self.state)
        self.profile = self.state.profiles[0]

    def _store_metadata(self, address: bytes) -> bytes:
        notification_config = tlv(
            "B6",
            tlv(
                "30",
                tlv("81", b"\x07\x80")
                + tlv("0C", address),
            ),
        )
        return tlv(
            "BF25",
            tlv("5A", encode_iccid_ef(self.profile.iccid))
            + tlv("91", b"Provider")
            + tlv("92", b"Profile")
            + notification_config,
        )

    def test_valid_utf8_notification_address_is_preserved(self) -> None:
        address = "münchen.example".encode("utf-8")

        parsed = self.logic._parse_store_metadata_request(
            self._store_metadata(address)
        )

        self.assertEqual(parsed["notification_address"], "münchen.example")

    def test_invalid_utf8_rejects_request_and_preserves_profile_state(self) -> None:
        previous_address = self.profile.notification_address

        response, sw1, sw2 = self.logic.handle_store_data(
            self._store_metadata(b"notify.\xFFexample")
        )

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response, bytes.fromhex("BF2503800101"))
        self.assertEqual(self.profile.notification_address, previous_address)


if __name__ == "__main__":
    unittest.main()
