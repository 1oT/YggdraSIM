# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Spec conformance of the SCP03 STK controller.

Every test pins one clause the controller deviated from, read from the
library copies of ETSI TS 102 223 V18.3.0, ETSI TS 101 220 V19.0.0,
3GPP TS 31.111 V19.4.0, 3GPP TS 24.008 V19.5.0 and 3GPP TS 23.003 V19.7.0:

* §5.2 TERMINAL PROFILE bits coded "RFU, bit = 0" and the reserved 'FF'
  soft-key count.
* TS 101 220 §7.1.1 CR flag and three-byte COMPREHENSION-TLV tags.
* §6.8.0 / §6.8.4 Duration in the POLL INTERVAL response.
* §6.4.21 / §6.8.0 Timer identifier and Timer value in TIMER MANAGEMENT
  responses.
* §6.8.0 Bearer description and Buffer size in the OPEN CHANNEL response.
* §6.8.7 local information objects, '30' for unserved qualifiers.
* §7.5.4.2 Location information only for Normal service.
* §7.5.2.2 / §7.5.3.2 mandatory Transaction identifier.
* §6.4.7 UICC Reset: no TERMINAL RESPONSE, new card session.
* §6.4.7 / §8.6 '09' eUICC Profile State Change: TERMINAL RESPONSE sent,
  then TERMINAL PROFILE again without a card reset.
"""

from __future__ import annotations

import time
import unittest

from SCP03.logic.stk import StkController, _encode_imeisv_bcd
from yggdrasim_common.stk_terminal import terminal_profile_apdu
from SIMCARD.state import MAX_HISTORY_ENTRIES


class _Connection:
    def __init__(self, responses: list[tuple[bytes, int, int]]) -> None:
        self.responses = list(responses)
        self.calls: list[str] = []

    def transmit(self, apdu):
        self.calls.append(bytes(apdu).hex().upper())
        if len(self.responses) == 0:
            raise AssertionError(f"Unexpected APDU: {bytes(apdu).hex().upper()}")
        data, sw1, sw2 = self.responses.pop(0)
        return list(data), sw1, sw2


class _Transport:
    def __init__(self, responses: list[tuple[bytes, int, int]]) -> None:
        self.connection = _Connection(responses)
        self.reset_calls = 0
        self.reset_session_calls = 0

    def reset(self) -> bool:
        self.reset_calls += 1
        return True

    def reset_session_state(self) -> None:
        self.reset_session_calls += 1

    def connect(self) -> bool:
        return True


def _proactive(command_hex: str) -> bytes:
    return bytes.fromhex(command_hex.replace(" ", ""))


def _run_chain(fetch_data: bytes) -> tuple[StkController, _Transport]:
    """Send one APDU that the card answers with a single proactive command."""
    transport = _Transport(
        [
            (b"", 0x91, len(fetch_data)),
            (fetch_data, 0x90, 0x00),
            (b"", 0x90, 0x00),
        ]
    )
    controller = StkController(transport)
    controller.send_apdu("80CA000000")
    return controller, transport


def _terminal_response(transport: _Transport) -> str:
    return transport.connection.calls[-1]


class TerminalProfileTests(unittest.TestCase):
    """The controller presents the toolchain's one TERMINAL PROFILE.

    ETSI TS 102 223 V18.3.0 §5.2 bit by bit is pinned in
    ``tests/test_stk_terminal.py``; here only what the controller relies on.
    """

    def test_the_controller_sends_the_shared_profile(self) -> None:
        self.assertEqual(StkController.TERMINAL_PROFILE, terminal_profile_apdu())
        self.assertEqual(
            StkController.TERMINAL_PROFILE[4], len(StkController.TERMINAL_PROFILE) - 5
        )

    def test_served_provide_local_information_modes_stay_claimed(self) -> None:
        """§5.2 bits for the PLI modes the controller answers read 1."""

        byte = {
            index + 1: value
            for index, value in enumerate(StkController.TERMINAL_PROFILE[5:])
        }
        # Byte 4 b7 PLI (MCC, MNC, LAC, Cell ID & IMEI).
        self.assertEqual(byte[4] & 0x40, 0x40)
        # Byte 8 b3 PLI (date, time and time zone).
        self.assertEqual(byte[8] & 0x04, 0x04)
        # Byte 9 b4 PLI (language) and b8 PLI (Access Technology).
        self.assertEqual(byte[9] & 0x88, 0x88)
        # Byte 18 b7 PLI (IMEISV).
        self.assertEqual(byte[18] & 0x40, 0x40)
        # Byte 22 b2 PLI (battery state), class "g".
        self.assertEqual(byte[22] & 0x02, 0x02)

    def test_refresh_euicc_profile_state_change_is_declared(self) -> None:
        """§5.2 byte 34 b6: REFRESH with "eUICC Profile State Change" mode."""

        profile = StkController.TERMINAL_PROFILE[5:]
        self.assertEqual(profile[34 - 1] & 0x20, 0x20)
        self.assertEqual(
            StkController.REFRESH_QUALIFIER_EUICC_PROFILE_STATE_CHANGE, 0x09
        )


class ComprehensionTlvTagTests(unittest.TestCase):
    """ETSI TS 101 220 §7.1.1.2 three-byte tag format."""

    def test_three_byte_tag_consumes_exactly_two_bytes(self) -> None:
        tag, value, raw, end = StkController._read_tlv(bytes.fromhex("7F008001AA"), 0)
        self.assertEqual(tag, bytes.fromhex("7F0080"))
        self.assertEqual(value, b"\xAA")
        self.assertEqual(raw, bytes.fromhex("7F008001AA"))
        self.assertEqual(end, 5)

    def test_three_byte_tag_with_cr_flag(self) -> None:
        tag, value, _raw, end = StkController._read_tlv(bytes.fromhex("7F800101BB"), 0)
        self.assertEqual(tag, bytes.fromhex("7F8001"))
        self.assertEqual(value, b"\xBB")
        self.assertEqual(end, 5)

    def test_three_byte_tag_value_zero_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            StkController._read_tlv(bytes.fromhex("7F000001AA"), 0)

    def test_truncated_three_byte_tag_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            StkController._read_tlv(bytes.fromhex("7F00"), 0)

    def test_single_byte_tag_still_parses(self) -> None:
        tag, value, _raw, end = StkController._read_tlv(bytes.fromhex("8101AA"), 0)
        self.assertEqual(tag, b"\x81")
        self.assertEqual(value, b"\xAA")
        self.assertEqual(end, 3)


class ProactiveCommandParserTests(unittest.TestCase):
    """ETSI TS 101 220 §7.1.1.1: the CR flag does not change the object."""

    def test_open_channel_objects_match_with_cr_set(self) -> None:
        controller = StkController(transport=None)
        command = _proactive(
            "D0 1C 81 03 01 40 01 82 02 81 82"
            " B5 01 03"
            " B9 02 05 78"
            " BC 03 02 1F 90"
            " BE 05 21 C0 00 02 01"
        )

        command_type, qualifier, fields = controller._parse_proactive_command(command)

        self.assertEqual((command_type, qualifier), (0x40, 0x01))
        self.assertEqual(fields["bearer_description"], b"\x03")
        self.assertEqual(fields["buffer_size"], 0x0578)
        self.assertEqual(fields["transport_protocol_type"], 0x02)
        self.assertEqual(fields["transport_port"], 8080)
        self.assertEqual(fields["remote_address"], "192.0.2.1")

    def test_objects_match_with_cr_clear(self) -> None:
        controller = StkController(transport=None)
        set_up_event_list = _proactive("D0 0D 01 03 01 05 00 02 02 81 82 19 02 03 09")
        receive_data = _proactive("D0 0C 81 03 01 42 00 82 02 81 82 37 01 10")

        _type, _qualifier, event_fields = controller._parse_proactive_command(set_up_event_list)
        _type, _qualifier, receive_fields = controller._parse_proactive_command(receive_data)

        self.assertEqual(event_fields["event_list"], [0x03, 0x09])
        self.assertEqual(receive_fields["channel_data_length"], 0x10)

    def test_timer_objects_are_decoded(self) -> None:
        controller = StkController(transport=None)
        command = _proactive("D0 11 81 03 01 27 00 82 02 81 82 A4 01 01 A5 03 10 20 30")

        _type, _qualifier, fields = controller._parse_proactive_command(command)

        self.assertEqual(fields["timer_identifier"], 0x01)
        # §8.38 semi-octets: 01 h 02 min 03 s.
        self.assertEqual(fields["timer_value_seconds"], 3600 + 120 + 3)


class PollIntervalResponseTests(unittest.TestCase):
    """ETSI TS 102 223 §6.8.4: the response states the interval in use."""

    def test_terminal_response_carries_the_duration(self) -> None:
        controller, transport = _run_chain(
            _proactive("D0 0D 81 03 01 03 00 82 02 81 82 84 02 00 01")
        )

        self.assertEqual(
            _terminal_response(transport),
            "8014000010" "8103010300" "02028281" "030100" "04020001",
        )
        self.assertEqual(controller.state.poll_interval_seconds, 60)

    def test_missing_duration_is_a_required_value_error(self) -> None:
        _controller, transport = _run_chain(_proactive("D0 09 81 03 01 03 00 82 02 81 82"))

        self.assertEqual(
            _terminal_response(transport),
            "801400000C" "8103010300" "02028281" "030136",
        )


class TimerManagementTests(unittest.TestCase):
    """ETSI TS 102 223 §6.4.21 actions and §6.8.0 response objects."""

    def test_start_echoes_the_timer_identifier(self) -> None:
        controller, transport = _run_chain(
            _proactive("D0 11 81 03 01 27 00 82 02 81 82 A4 01 01 A5 03 00 10 00")
        )

        self.assertEqual(
            _terminal_response(transport),
            "801400000F" "8103012700" "02028281" "030100" "240101",
        )
        self.assertIn(0x01, controller.state.timers)
        self.assertEqual(controller.state.timers[0x01][0], 60)

    def test_get_current_value_returns_the_remaining_time(self) -> None:
        fetch_data = _proactive("D0 0C 81 03 01 27 02 82 02 81 82 A4 01 02")
        transport = _Transport(
            [(b"", 0x91, len(fetch_data)), (fetch_data, 0x90, 0x00), (b"", 0x90, 0x00)]
        )
        controller = StkController(transport)
        controller.state.timers[0x02] = (3600 + 5, time.monotonic())

        controller.send_apdu("80CA000000")

        self.assertEqual(
            _terminal_response(transport),
            "8014000014" "8103012702" "02028281" "030100" "240102" "2503100050",
        )
        self.assertIn(0x02, controller.state.timers)

    def test_deactivate_removes_a_running_timer(self) -> None:
        fetch_data = _proactive("D0 0C 81 03 01 27 01 82 02 81 82 A4 01 03")
        transport = _Transport(
            [(b"", 0x91, len(fetch_data)), (fetch_data, 0x90, 0x00), (b"", 0x90, 0x00)]
        )
        controller = StkController(transport)
        controller.state.timers[0x03] = (30, time.monotonic())

        controller.send_apdu("80CA000000")

        self.assertEqual(
            _terminal_response(transport),
            "8014000014" "8103012701" "02028281" "030100" "240103" "2503000003",
        )
        self.assertNotIn(0x03, controller.state.timers)

    def test_deactivate_on_an_inactive_timer_contradicts_the_timer_state(self) -> None:
        _controller, transport = _run_chain(
            _proactive("D0 0C 81 03 01 27 01 82 02 81 82 A4 01 03")
        )

        self.assertEqual(
            _terminal_response(transport),
            "801400000F" "8103012701" "02028281" "030124" "240103",
        )

    def test_rfu_action_is_command_data_not_understood(self) -> None:
        _controller, transport = _run_chain(
            _proactive("D0 0C 81 03 01 27 03 82 02 81 82 A4 01 01")
        )

        self.assertEqual(
            _terminal_response(transport),
            "801400000F" "8103012703" "02028281" "030132" "240101",
        )

    def test_reserved_timer_identifier_is_command_data_not_understood(self) -> None:
        _controller, transport = _run_chain(
            _proactive("D0 11 81 03 01 27 00 82 02 81 82 A4 01 09 A5 03 00 10 00")
        )

        self.assertEqual(
            _terminal_response(transport),
            "801400000F" "8103012700" "02028281" "030132" "240109",
        )


class OpenChannelResponseTests(unittest.TestCase):
    """ETSI TS 102 223 §6.8.0: Channel status, Bearer description, Buffer size."""

    def test_terminal_response_echoes_bearer_description_and_buffer_size(self) -> None:
        controller, transport = _run_chain(
            _proactive(
                "D0 1C 81 03 01 40 01 82 02 81 82"
                " 35 01 03 39 02 05 78 3C 03 02 1F 90 3E 05 21 C0 00 02 01"
            )
        )

        self.assertEqual(
            _terminal_response(transport),
            "8014000017" "8103014001" "02028281" "030100" "38028100" "350103" "39020578",
        )
        self.assertTrue(controller.state.open_channel_active)
        self.assertEqual(controller.state.open_channel_endpoint, "192.0.2.1:8080")


class BipDataResponseTests(unittest.TestCase):
    """ETSI TS 102 223 §6.6.29 / §6.6.30 minimum sets and §8.54 coding."""

    def test_send_data_reports_free_tx_space(self) -> None:
        _controller, transport = _run_chain(
            _proactive("D0 0F 81 03 01 43 01 82 02 81 82 B6 04 DE AD BE EF")
        )

        self.assertEqual(
            _terminal_response(transport),
            "801400000F" "8103014301" "02028281" "030100" "3701FF",
        )

    def test_send_data_without_channel_data_is_a_required_value_error(self) -> None:
        _controller, transport = _run_chain(_proactive("D0 09 81 03 01 43 01 82 02 81 82"))

        self.assertEqual(
            _terminal_response(transport),
            "801400000C" "8103014301" "02028281" "030136",
        )

    def test_receive_data_without_length_is_a_required_value_error(self) -> None:
        _controller, transport = _run_chain(_proactive("D0 09 81 03 01 42 00 82 02 81 82"))

        self.assertEqual(
            _terminal_response(transport),
            "801400000C" "8103014200" "02028281" "030136",
        )


class ProvideLocalInformationTests(unittest.TestCase):
    """ETSI TS 102 223 §6.8.7 local information objects."""

    @staticmethod
    def _response(qualifier: int) -> bytes:
        controller = StkController(transport=None)
        command_details = bytes([0x81, 0x03, 0x01, 0x26, qualifier])
        return controller._build_terminal_response(
            0x26, qualifier, {"command_details_tlv": command_details}
        )

    def test_access_technology_is_reported(self) -> None:
        # §8.61: '00' = GSM, matching the 7-byte GERAN location layout.
        self.assertEqual(
            self._response(0x06).hex().upper(),
            "801400000F" "8103012606" "02028281" "030100" "3F0100",
        )

    def test_imeisv_is_reported(self) -> None:
        # TS 23.003 §6.2.2: TAC + SNR of the default IMEI, SVN "00";
        # TS 24.008 §10.5.1.4: type of identity 011, even count, '1111' end mark.
        self.assertEqual(
            self._response(0x08).hex().upper(),
            "8014000017" "8103012608" "02028281" "030100" "6209" "036845235456340 2F0".replace(" ", ""),
        )

    def test_battery_state_is_not_powered_by_a_battery(self) -> None:
        # §8.76: 'FE' = status not applicable, not powered by a battery.
        self.assertEqual(
            self._response(0x0A).hex().upper(),
            "801400000F" "810301260A" "02028281" "030100" "6301FE",
        )

    def test_unserved_qualifier_is_beyond_terminal_capabilities(self) -> None:
        # §8.12 '30' rather than a success result without the object.
        self.assertEqual(
            self._response(0x02).hex().upper(),
            "801400000C" "8103012602" "02028281" "030130",
        )

    def test_location_information_and_imei_still_served(self) -> None:
        location = self._response(0x00).hex().upper()
        imei = self._response(0x01).hex().upper()
        self.assertIn("030100" "1307", location)
        self.assertIn("030100" "1408", imei)


class ImeisvEncodingTests(unittest.TestCase):
    """3GPP TS 24.008 §10.5.1.4 layout for an even digit count."""

    def test_sixteen_digits_pack_into_nine_bytes(self) -> None:
        encoded = _encode_imeisv_bcd("086543245654321", "07")
        self.assertEqual(len(encoded), 9)
        self.assertEqual(encoded[0], 0x03)
        self.assertEqual(encoded[-1], 0xF7)

    def test_bad_inputs_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _encode_imeisv_bcd("0865432456543", "00")
        with self.assertRaises(ValueError):
            _encode_imeisv_bcd("086543245654321", "7")


class LocationStatusEventTests(unittest.TestCase):
    """ETSI TS 102 223 §7.5.4.2 conditional Location information."""

    def test_normal_service_carries_location_information(self) -> None:
        transport = _Transport([(b"", 0x90, 0x00)])
        controller = StkController(transport)

        controller.send_location_status(status_value=0x00)

        self.assertEqual(
            transport.connection.calls,
            ["80C2000015" "D613" "990103" "02028281" "9B0100" "930700F110000100 01".replace(" ", "")],
        )

    def test_no_service_omits_location_information(self) -> None:
        transport = _Transport([(b"", 0x90, 0x00)])
        controller = StkController(transport)

        controller.send_location_status(status_value=0x02)

        self.assertEqual(
            transport.connection.calls,
            ["80C200000C" "D60A" "990103" "02028281" "9B0102"],
        )

    def test_limited_service_omits_location_information(self) -> None:
        transport = _Transport([(b"", 0x90, 0x00)])
        controller = StkController(transport)

        controller.send_location_status(status_value=0x01)

        self.assertNotIn("9307", transport.connection.calls[0])


class CallEventTransactionIdentifierTests(unittest.TestCase):
    """ETSI TS 102 223 §7.5.2.2 / §7.5.3.2 and 3GPP TS 31.111 §8.28."""

    def test_call_connected_carries_a_transaction_identifier(self) -> None:
        transport = _Transport([(b"", 0x90, 0x00)])
        controller = StkController(transport)

        controller.simulate_call_connected()

        self.assertEqual(
            transport.connection.calls,
            ["80C200000C" "D60A" "990101" "02028281" "9C0180"],
        )

    def test_call_disconnected_carries_a_transaction_identifier(self) -> None:
        transport = _Transport([(b"", 0x90, 0x00)])
        controller = StkController(transport)

        controller.simulate_call_disconnected()

        self.assertEqual(
            transport.connection.calls,
            ["80C200000C" "D60A" "990102" "02028281" "9C0180"],
        )

    def test_caller_supplied_identifier_is_kept(self) -> None:
        transport = _Transport([(b"", 0x90, 0x00)])
        controller = StkController(transport)

        controller.simulate_call_connected(extra_tlvs_hex="1C0190")

        self.assertEqual(
            transport.connection.calls,
            ["80C200000C" "D60A" "990101" "02028281" "1C0190"],
        )


class RefreshUiccResetTests(unittest.TestCase):
    """ETSI TS 102 223 §6.4.7 UICC Reset mode."""

    def test_no_terminal_response_and_the_session_restarts(self) -> None:
        fetch_data = _proactive("D0 09 81 03 01 01 04 82 02 81 82")
        transport = _Transport(
            [
                (b"", 0x91, len(fetch_data)),
                (fetch_data, 0x90, 0x00),
                (b"", 0x90, 0x00),
            ]
        )
        controller = StkController(transport)
        controller.state.event_list = [0x03, 0x09]
        controller.state.timers[0x01] = (60, time.monotonic())
        controller.queue_channel_data("AA")

        _data, sw1, sw2 = controller.send_apdu("80CA000000")

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(
            transport.connection.calls,
            [
                "80CA000000",
                "801200000B",
                StkController.TERMINAL_PROFILE.hex().upper(),
            ],
        )
        self.assertEqual(transport.reset_calls, 1)
        self.assertEqual(transport.reset_session_calls, 1)
        self.assertEqual(controller.state.event_list, [])
        self.assertEqual(controller.state.timers, {})
        self.assertFalse(controller.state.open_channel_active)
        self.assertTrue(
            any("UICC Reset" in line for line in controller.state.flow_events)
        )

    def test_other_refresh_modes_still_get_a_terminal_response(self) -> None:
        # Qualifier '02' = NAA Initialization and File Change Notification.
        _controller, transport = _run_chain(_proactive("D0 09 81 03 01 01 02 82 02 81 82"))

        self.assertEqual(
            _terminal_response(transport),
            "801400000C" "8103010102" "02028281" "030100",
        )


class RefreshEuiccProfileStateChangeTests(unittest.TestCase):
    """ETSI TS 102 223 §6.4.7 eUICC Profile State Change mode (§8.6 '09')."""

    def test_terminal_response_is_sent_and_the_profile_is_downloaded_again(self) -> None:
        fetch_data = _proactive("D0 09 81 03 01 01 09 82 02 81 82")
        transport = _Transport(
            [
                (b"", 0x91, len(fetch_data)),
                (fetch_data, 0x90, 0x00),
                (b"", 0x90, 0x00),
                (b"", 0x90, 0x00),
            ]
        )
        controller = StkController(transport)
        controller.state.event_list = [0x03, 0x09]
        controller.state.timers[0x01] = (60, time.monotonic())
        controller.queue_channel_data("AA")

        _data, sw1, sw2 = controller.send_apdu("80CA000000")

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(
            transport.connection.calls,
            [
                "80CA000000",
                "801200000B",
                "801400000C" "8103010109" "02028281" "030100",
                StkController.TERMINAL_PROFILE.hex().upper(),
            ],
        )
        # §6.4.7: the card resets itself, so no ATR-level reset is issued,
        # while the secure channel bound to the card session is dropped.
        self.assertEqual(transport.reset_calls, 0)
        self.assertEqual(transport.reset_session_calls, 1)
        self.assertEqual(controller.state.event_list, [])
        self.assertEqual(controller.state.timers, {})
        self.assertFalse(controller.state.open_channel_active)
        self.assertTrue(
            any(
                "eUICC Profile State Change" in line
                for line in controller.state.flow_events
            )
        )


class HistoryBoundTests(unittest.TestCase):
    def test_flow_events_are_bounded(self) -> None:
        controller = StkController(transport=None)
        for index in range(MAX_HISTORY_ENTRIES + 50):
            controller._record_flow_event(f"event {index}")
        self.assertEqual(len(controller.state.flow_events), MAX_HISTORY_ENTRIES)
        self.assertEqual(controller.state.flow_events[-1], f"event {MAX_HISTORY_ENTRIES + 49}")


if __name__ == "__main__":
    unittest.main()
