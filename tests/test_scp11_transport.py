# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from SCP11.transport import PcscApduChannel


class FakePcscConnection:
    def __init__(self, response_data, sw1, sw2):
        self._response_data = list(response_data)
        self._sw1 = int(sw1)
        self._sw2 = int(sw2)
        self.calls = []

    def transmit(self, apdu):
        self.calls.append(list(apdu))
        return list(self._response_data), self._sw1, self._sw2


class ScriptedPcscConnection:
    """PC/SC connection stub that replays a scripted response list.

    Each entry is a ``(response_bytes, sw1, sw2)`` tuple consumed in
    order, so we can exercise the 61xx / 6Cxx continuation flows that
    the concise-mode log filter is supposed to hide.
    """

    def __init__(self, script):
        self._script = list(script)
        self.calls = []

    def transmit(self, apdu):
        self.calls.append(list(apdu))
        if len(self._script) == 0:
            raise RuntimeError("No scripted PC/SC responses remaining")
        response_bytes, sw1, sw2 = self._script.pop(0)
        return list(response_bytes), int(sw1), int(sw2)


class PcscApduChannelLoggingTests(unittest.TestCase):
    def test_cardbridge_relay_transport_is_not_exported(self):
        import SCP11.transport as transport

        self.assertFalse(hasattr(transport, "RelayApduChannel"))
        self.assertFalse(hasattr(transport, "RelayHttpClientJsonHex"))

    def test_pcsc_connect_bypasses_relay_marker_auto_detection(self):
        channel = PcscApduChannel.__new__(PcscApduChannel)
        direct_connection = object()

        with mock.patch("SCP11.transport.is_simulated_card_backend", return_value=False):
            with mock.patch("SCP11.transport.create_card_connection") as create_connection:
                with mock.patch.object(
                    PcscApduChannel,
                    "_connect_after_power_cycle",
                    return_value=direct_connection,
                ) as direct_connect:
                    result = channel._connect(0)

        self.assertIs(result, direct_connection)
        direct_connect.assert_called_once_with(0)
        create_connection.assert_not_called()

    def test_pcsc_connect_keeps_explicit_simulator_backend(self):
        channel = PcscApduChannel.__new__(PcscApduChannel)
        simulated_connection = object()

        with mock.patch("SCP11.transport.is_simulated_card_backend", return_value=True):
            with mock.patch(
                "SCP11.transport.create_card_connection",
                return_value=simulated_connection,
            ) as create_connection:
                with mock.patch.object(PcscApduChannel, "_connect_after_power_cycle") as direct_connect:
                    result = channel._connect(0)

        self.assertIs(result, simulated_connection)
        create_connection.assert_called_once_with(reader_index=0)
        direct_connect.assert_not_called()

    def test_send_logs_compact_hex_without_spaces(self):
        channel = PcscApduChannel.__new__(PcscApduChannel)
        channel._conn = FakePcscConnection(response_data=b"\xDE\xAD", sw1=0x90, sw2=0x00)
        channel._raw_apdu_logging = True

        output = io.StringIO()
        with redirect_stdout(output):
            response = channel.send(bytes.fromhex("00A4040000"), "TEST")

        rendered = output.getvalue()
        self.assertEqual(response, b"\xDE\xAD")
        self.assertIn("[TEST] > 00A4040000", rendered)
        self.assertIn("[TEST] < SW: 9000 Data: DEAD", rendered)
        self.assertNotIn("00 A4 04 00 00", rendered)
        self.assertNotIn("DE AD", rendered)

    def test_send_concise_mode_omits_success_status_line(self):
        channel = PcscApduChannel.__new__(PcscApduChannel)
        channel._conn = FakePcscConnection(response_data=b"\xDE\xAD", sw1=0x90, sw2=0x00)
        channel._raw_apdu_logging = False

        output = io.StringIO()
        with redirect_stdout(output):
            response = channel.send(bytes.fromhex("00A4040000"), "TEST")

        rendered = output.getvalue()
        self.assertEqual(response, b"\xDE\xAD")
        self.assertIn("[*] TEST", rendered)
        self.assertNotIn("SW 9000", rendered)

    def test_send_concise_mode_keeps_failure_status_line(self):
        channel = PcscApduChannel.__new__(PcscApduChannel)
        channel._conn = FakePcscConnection(response_data=b"", sw1=0x6A, sw2=0x82)
        channel._raw_apdu_logging = False

        output = io.StringIO()
        with redirect_stdout(output):
            with self.assertRaises(IOError):
                channel.send(bytes.fromhex("00A4040000"), "TEST")

        rendered = output.getvalue()
        self.assertIn("[*] TEST", rendered)
        self.assertIn("SW 6A82 len=0", rendered)

    def test_send_concise_mode_silences_61xx_continuation_and_get_response(self):
        # Initial 61xx continuation resolved by a follow-up GET RESPONSE
        # that returns 9000; concise mode should print the command label
        # once and emit no SW line and no GET RESPONSE label.
        channel = PcscApduChannel.__new__(PcscApduChannel)
        channel._conn = ScriptedPcscConnection(
            [
                (b"", 0x61, 0x1A),
                (b"\xDE\xAD", 0x90, 0x00),
            ]
        )
        channel._raw_apdu_logging = False

        output = io.StringIO()
        with redirect_stdout(output):
            response = channel.send(bytes.fromhex("00A4040000"), "LOCAL: Select ECASD")

        rendered = output.getvalue()
        self.assertEqual(response, b"\xDE\xAD")
        self.assertIn("[*] LOCAL: Select ECASD", rendered)
        self.assertNotIn("[GET RESPONSE]", rendered)
        self.assertNotIn("SW 611A", rendered)

    def test_send_concise_mode_silences_6cxx_length_correction(self):
        # 6Cxx triggers an internal Le retry; the retry SW is the one
        # the operator cares about so the intermediate 6Cxx must be
        # hidden in concise mode.
        channel = PcscApduChannel.__new__(PcscApduChannel)
        channel._conn = ScriptedPcscConnection(
            [
                (b"", 0x6C, 0x12),
                (b"\xCA\xFE", 0x90, 0x00),
            ]
        )
        channel._raw_apdu_logging = False

        output = io.StringIO()
        with redirect_stdout(output):
            response = channel.send(bytes.fromhex("80E2910000"), "LOCAL: GetEID")

        rendered = output.getvalue()
        self.assertEqual(response, b"\xCA\xFE")
        self.assertIn("[*] LOCAL: GetEID", rendered)
        self.assertNotIn("SW 6C12", rendered)

    def test_raw_mode_still_surfaces_continuation_swords(self):
        # Developers that enable raw logging want the full chaining
        # visible (including GET RESPONSE follow-ups and 61xx lines).
        channel = PcscApduChannel.__new__(PcscApduChannel)
        channel._conn = ScriptedPcscConnection(
            [
                (b"", 0x61, 0x02),
                (b"\xAA\xBB", 0x90, 0x00),
            ]
        )
        channel._raw_apdu_logging = True

        output = io.StringIO()
        with redirect_stdout(output):
            response = channel.send(bytes.fromhex("00A4040000"), "LOCAL: Select ECASD")

        rendered = output.getvalue()
        self.assertEqual(response, b"\xAA\xBB")
        self.assertIn("[LOCAL: Select ECASD] > 00A4040000", rendered)
        self.assertIn("SW: 6102", rendered)
        self.assertIn("[LOCAL: Select ECASD [GET RESPONSE]] >", rendered)
        self.assertIn("SW: 9000", rendered)


if __name__ == "__main__":
    unittest.main()
