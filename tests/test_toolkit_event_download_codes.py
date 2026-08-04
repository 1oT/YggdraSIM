# SPDX-License-Identifier: GPL-3.0-or-later
"""Event-download dispatch against the ETSI TS 102 223 §8.25 event list.

Each case sends one ENVELOPE (EVENT DOWNLOAD) and asserts that the code
the specification assigns to that event is the code that drives the
matching ``state.toolkit`` field. The neighbouring codes are asserted
inert so a future shift cannot pass by landing on the wrong branch.

The §8.59 transport protocol type values are carried here too: both
sides of the simulator name them from the same table.
"""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SCP03.logic.stk import StkController
from SIMCARD.state import SimCardState
from SIMCARD.toolkit import ToolkitLogic


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag, len(value))) + value


def _envelope(*body: bytes) -> bytes:
    joined = b"".join(body)
    return bytes((0xD6, len(joined))) + joined


def _event(code: int, *children: bytes) -> bytes:
    return _envelope(_tlv(0x99, bytes((code,))), *children)


def _fallback(payload: bytes) -> tuple[bytes, int, int]:
    del payload
    return b"", 0x90, 0x00


# ETSI TS 102 223 §8.25, extended by the values 3GPP TS 31.111 §8.25 adds.
EVENT_LIST_CODES = {
    "MT call": 0x00,
    "Call connected": 0x01,
    "Call disconnected": 0x02,
    "Location status": 0x03,
    "User activity": 0x04,
    "Idle screen available": 0x05,
    "Card reader status": 0x06,
    "Language selection": 0x07,
    "Browser termination": 0x08,
    "Data available": 0x09,
    "Channel status": 0x0A,
    "Access Technology Change (single)": 0x0B,
    "Display parameters changed": 0x0C,
    "Local connection": 0x0D,
    "Network Search Mode Change": 0x0E,
    "Browsing status": 0x0F,
    "Frames Information Change": 0x10,
    "(I-)WLAN Access Status": 0x11,
    "Network Rejection": 0x12,
    "HCI connectivity event": 0x13,
    "Access Technology Change (multiple)": 0x14,
    "CSG cell selection": 0x15,
    "Contactless state request": 0x16,
    "IMS Registration": 0x17,
    "Incoming IMS data": 0x18,
    "Profile Container": 0x19,
    "Secured Profile Container": 0x1B,
    "Poll Interval Negotiation": 0x1C,
}


class _Harness(unittest.TestCase):
    def setUp(self) -> None:
        self.state = SimCardState(
            atr=b"",
            eid="89049032123451234512345678901235",
            iccid="8988000000000000001",
            imsi="999990000000001",
            default_dp_address="",
            root_ci_pkid=b"",
        )
        self.toolkit = ToolkitLogic(self.state)

    def send(self, code: int, *children: bytes) -> None:
        self.toolkit.handle_envelope(_event(code, *children), _fallback)


class EventCodeDispatchTests(_Harness):
    def test_idle_screen_available_is_05(self) -> None:
        self.send(EVENT_LIST_CODES["Idle screen available"])
        self.assertTrue(self.state.toolkit.idle_screen_available)

    def test_language_selection_does_not_flag_idle_screen(self) -> None:
        self.send(EVENT_LIST_CODES["Language selection"])
        self.assertFalse(self.state.toolkit.idle_screen_available)

    def test_browser_termination_is_08(self) -> None:
        self.send(EVENT_LIST_CODES["Browser termination"], _tlv(0x34, b"\x01"))
        self.assertEqual(self.state.toolkit.last_browser_termination_cause, 0x01)
        self.assertEqual(self.state.toolkit.data_available_events, 0)

    def test_data_available_is_09(self) -> None:
        self.send(
            EVENT_LIST_CODES["Data available"],
            _tlv(0x38, b"\x81\x00"),
            _tlv(0x37, b"\x20"),
        )
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_data_available_channel_length, 0x20)
        self.assertEqual(toolkit.data_available_events, 1)
        self.assertEqual(toolkit.last_browser_termination_cause, 0x00)

    def test_access_technology_change_is_0b(self) -> None:
        self.send(
            EVENT_LIST_CODES["Access Technology Change (single)"],
            _tlv(0xBF, b"\x03"),
        )
        self.assertEqual(self.state.toolkit.last_access_technology, 0x03)
        self.assertEqual(self.state.toolkit.access_technology_changes, 1)

    def test_display_parameters_changed_is_0c(self) -> None:
        self.send(
            EVENT_LIST_CODES["Display parameters changed"],
            _tlv(0xC6, bytes.fromhex("0F2014")),
        )
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_display_parameters, bytes.fromhex("0F2014"))
        self.assertEqual(toolkit.display_parameters_changes, 1)

    def test_local_connection_is_0d(self) -> None:
        self.send(EVENT_LIST_CODES["Local connection"], _tlv(0x40, b"\x80"))
        self.assertTrue(self.state.toolkit.local_connection_active)

    def test_network_rejection_is_12(self) -> None:
        self.send(
            EVENT_LIST_CODES["Network Rejection"],
            _tlv(0xCA, bytes.fromhex("020003")),
        )
        self.assertEqual(
            self.state.toolkit.last_network_rejection_cause,
            bytes.fromhex("020003"),
        )

    def test_hci_connectivity_is_13(self) -> None:
        self.send(EVENT_LIST_CODES["HCI connectivity event"], _tlv(0x40, b"\x80"))
        self.assertTrue(self.state.toolkit.hci_connectivity_active)

    def test_contactless_state_request_is_16(self) -> None:
        self.send(EVENT_LIST_CODES["Contactless state request"], _tlv(0x40, b"\x80"))
        self.assertTrue(self.state.toolkit.contactless_active)

    def test_ims_registration_is_17(self) -> None:
        uri = b"sip:user@example.com"
        self.send(
            EVENT_LIST_CODES["IMS Registration"],
            _tlv(0xB9, b"\x01"),
            _tlv(0xBA, uri),
        )
        self.assertTrue(self.state.toolkit.ims_registered)
        self.assertEqual(self.state.toolkit.last_ims_event_data, uri)

    def test_incoming_ims_data_is_18(self) -> None:
        payload = bytes.fromhex("4D45535341474520626F6479")
        self.send(EVENT_LIST_CODES["Incoming IMS data"], _tlv(0xBA, payload))
        self.assertEqual(self.state.toolkit.last_ims_event_data, payload)
        self.assertFalse(self.state.toolkit.ims_registered)


class NeighbourCodesAreInertTests(_Harness):
    """A code the simulator does not act on must not act on anything."""

    def test_channel_status_does_not_land_on_access_technology(self) -> None:
        self.send(EVENT_LIST_CODES["Channel status"], _tlv(0xBF, b"\x03"))
        self.assertEqual(self.state.toolkit.access_technology_changes, 0)

    def test_browsing_status_does_not_latch_a_rejection_cause(self) -> None:
        self.send(
            EVENT_LIST_CODES["Browsing status"],
            _tlv(0xCA, bytes.fromhex("020003")),
        )
        self.assertEqual(self.state.toolkit.last_network_rejection_cause, b"")

    def test_network_search_mode_change_does_not_latch_display_parameters(self) -> None:
        self.send(
            EVENT_LIST_CODES["Network Search Mode Change"],
            _tlv(0xC6, bytes.fromhex("0F2014")),
        )
        self.assertEqual(self.state.toolkit.display_parameters_changes, 0)

    def test_profile_container_does_not_latch_ims_data(self) -> None:
        self.send(EVENT_LIST_CODES["Profile Container"], _tlv(0xBA, b"payload"))
        self.assertEqual(self.state.toolkit.last_ims_event_data, b"")


class ControllerAndCardAgreeTests(_Harness):
    """The host-side name map and the card-side dispatch are one wire."""

    def test_controller_event_names_resolve_to_the_spec_codes(self) -> None:
        for name, code in StkController.EVENT_NAME_MAP.items():
            self.assertIn(code, set(EVENT_LIST_CODES.values()), name)

    def test_controller_idle_screen_reaches_the_card_latch(self) -> None:
        self.send(StkController.EVENT_NAME_MAP["IDLE-SCREEN"])
        self.assertTrue(self.state.toolkit.idle_screen_available)

    def test_controller_data_available_reaches_the_card_counter(self) -> None:
        self.send(
            StkController.EVENT_NAME_MAP["DATA-AVAILABLE"],
            _tlv(0x38, b"\x81\x00"),
            _tlv(0x37, b"\x04"),
        )
        self.assertEqual(self.state.toolkit.data_available_events, 1)


class TransportProtocolTypeTests(unittest.TestCase):
    """ETSI TS 102 223 §8.59 UICC/terminal interface transport level."""

    # The six values §8.59 defines; all others are reserved.
    SPEC_VALUES = (0x01, 0x02, 0x03, 0x04, 0x05, 0x06)

    def _card_side(self, value: int) -> str:
        state = SimCardState(
            atr=b"",
            eid="89049032123451234512345678901235",
            iccid="8988000000000000001",
            imsi="999990000000001",
            default_dp_address="",
            root_ci_pkid=b"",
        )
        return ToolkitLogic(state)._transport_protocol_name(value)

    def test_every_defined_value_has_a_name(self) -> None:
        for value in self.SPEC_VALUES:
            with self.subTest(value=value):
                self.assertNotIn("0x", self._card_side(value))
                self.assertNotIn("0x", StkController._transport_protocol_name(value))

    def test_reserved_values_fall_back_to_hex(self) -> None:
        for value in (0x00, 0x07, 0xFF):
            with self.subTest(value=value):
                self.assertEqual(self._card_side(value), f"0x{value:02X}")

    def test_both_sides_name_a_value_identically(self) -> None:
        for value in self.SPEC_VALUES:
            with self.subTest(value=value):
                self.assertEqual(
                    self._card_side(value),
                    StkController._transport_protocol_name(value),
                )


if __name__ == "__main__":
    unittest.main()
