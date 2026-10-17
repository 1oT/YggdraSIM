# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from SCP11.transport import (
    PcscApduChannel,
    print_apdu_trace_note,
    set_apdu_trace_note_renderer,
    set_apdu_trace_renderer,
)
from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV


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
    def setUp(self):
        # The renderer slot is process-wide: a plugin an earlier test loaded
        # must not decide what these exchanges print.
        self._previous_renderer = set_apdu_trace_renderer(None)

    def tearDown(self):
        set_apdu_trace_renderer(self._previous_renderer)

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

    def test_raw_logging_prints_on_a_quiet_channel(self):
        # The eSIM management relay opens its channel quiet; a command's
        # --debug turns raw logging on and has to show every exchange.
        script = [
            (b"", 0x61, 0x02),
            (b"\xAA\xBB", 0x90, 0x00),
        ]
        apdu = bytes.fromhex("80E2910003BF5500")
        channel = PcscApduChannel.__new__(PcscApduChannel)
        channel._quiet_apdu_logging = True
        channel._raw_apdu_logging = False
        channel._conn = ScriptedPcscConnection(script)

        quiet_output = io.StringIO()
        with redirect_stdout(quiet_output):
            channel.send(apdu, "EIM: GetEimConfigurationData")
        self.assertEqual(quiet_output.getvalue(), "")

        channel._raw_apdu_logging = True
        channel._conn = ScriptedPcscConnection(script)
        raw_output = io.StringIO()
        with redirect_stdout(raw_output):
            response = channel.send(apdu, "EIM: GetEimConfigurationData")

        rendered = raw_output.getvalue()
        self.assertEqual(response, b"\xAA\xBB")
        self.assertIn("[EIM: GetEimConfigurationData] > 80E2910003BF5500", rendered)
        self.assertIn("SW: 6102", rendered)
        self.assertIn("[EIM: GetEimConfigurationData [GET RESPONSE]] > 00C0000002", rendered)
        self.assertIn("SW: 9000 Data: AABB", rendered)


class ApduTraceRendererTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self._previous_renderer = set_apdu_trace_renderer(None)

    def tearDown(self):
        set_apdu_trace_renderer(self._previous_renderer)

    def _record(self, label, apdu, response, sw1, sw2):
        self.calls.append((label, apdu, response, sw1, sw2))

    @staticmethod
    def _channel(connection, *, raw):
        channel = PcscApduChannel.__new__(PcscApduChannel)
        channel._conn = connection
        channel._raw_apdu_logging = raw
        channel._quiet_apdu_logging = False
        return channel

    def test_a_raw_exchange_prints_through_the_renderer_alone(self):
        set_apdu_trace_renderer(self._record)
        channel = self._channel(FakePcscConnection(b"\xDE\xAD", 0x90, 0x00), raw=True)

        output = io.StringIO()
        with redirect_stdout(output):
            channel.send(bytes.fromhex("00A4040000"), "TEST")

        self.assertEqual(
            self.calls,
            [("TEST", bytes.fromhex("00A4040000"), b"\xDE\xAD", 0x90, 0x00)],
        )
        self.assertEqual(output.getvalue(), "")

    def test_concise_lines_never_reach_the_renderer(self):
        set_apdu_trace_renderer(self._record)
        channel = self._channel(FakePcscConnection(b"", 0x6A, 0x82), raw=False)

        output = io.StringIO()
        with redirect_stdout(output):
            channel.exchange(bytes.fromhex("00A4040000"), "TEST")

        self.assertEqual(self.calls, [])
        self.assertIn("[*] TEST", output.getvalue())
        self.assertIn("SW 6A82", output.getvalue())

    def test_a_failing_renderer_leaves_the_exchange_to_the_raw_lines(self):
        def undecodable(*_):
            raise ValueError("undecodable")

        set_apdu_trace_renderer(undecodable)
        channel = self._channel(FakePcscConnection(b"\xDE\xAD", 0x90, 0x00), raw=True)

        output = io.StringIO()
        with redirect_stdout(output):
            answer = channel.exchange(bytes.fromhex("00A4040000"), "TEST")

        self.assertEqual(answer, (b"\xDE\xAD", 0x90, 0x00))
        self.assertIn("[TEST] > 00A4040000", output.getvalue())
        self.assertIn("[TEST] < SW: 9000 Data: DEAD", output.getvalue())

    def test_installing_a_renderer_hands_back_the_one_it_replaces(self):
        self.assertIsNone(set_apdu_trace_renderer(self._record))
        self.assertEqual(set_apdu_trace_renderer(None), self._record)

    def test_chunked_store_data_leaves_the_block_label_to_the_renderer(self):
        set_apdu_trace_renderer(self._record)
        channel = self._channel(FakePcscConnection(b"", 0x90, 0x00), raw=True)
        payload = bytes.fromhex("BF3682012C") + bytes(300)

        output = io.StringIO()
        with redirect_stdout(output):
            channel.send_chunked(0x80, 0xE2, 0x91, 0x00, payload, "STORE")

        self.assertNotIn("> Block", output.getvalue())
        labels = [call[0] for call in self.calls]
        self.assertGreater(len(labels), 1)
        self.assertEqual(labels, [f"STORE [Block {index}]" for index in range(len(labels))])


class ApduTraceNoteTests(unittest.TestCase):
    def setUp(self):
        self.notes = []
        self._previous_note_renderer = set_apdu_trace_note_renderer(None)

    def tearDown(self):
        set_apdu_trace_note_renderer(self._previous_note_renderer)

    def _record(self, text):
        self.notes.append(text)

    @staticmethod
    def _printed(text, *, heading=False, debug="1"):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: debug}), redirect_stdout(output):
            print_apdu_trace_note(text, heading=heading)
        return output.getvalue()

    def test_without_a_renderer_a_note_prints_its_built_in_line(self):
        self.assertEqual(
            self._printed("ES10b logical channel active: CH1."),
            "[*] ES10b logical channel active: CH1.\n",
        )
        self.assertEqual(self._printed("Phase: Connect", heading=True), "\n[*] Phase: Connect\n")

    def test_a_note_prints_through_the_renderer_alone(self):
        set_apdu_trace_note_renderer(self._record)

        self.assertEqual(self._printed("Phase: Connect", heading=True), "")
        self.assertEqual(self.notes, ["Phase: Connect"])

    def test_with_the_debug_flag_off_no_note_prints_or_reaches_the_renderer(self):
        self.assertEqual(self._printed("Phase: Connect", heading=True, debug="0"), "")
        set_apdu_trace_note_renderer(self._record)
        self.assertEqual(self._printed("Phase: Connect", heading=True, debug="0"), "")
        self.assertEqual(self.notes, [])

    def test_a_failing_note_renderer_leaves_the_line_to_the_built_in_form(self):
        def undecodable(_):
            raise ValueError("undecodable")

        set_apdu_trace_note_renderer(undecodable)
        self.assertEqual(self._printed("Phase: Connect", heading=True), "\n[*] Phase: Connect\n")

    def test_installing_a_note_renderer_hands_back_the_one_it_replaces(self):
        self.assertIsNone(set_apdu_trace_note_renderer(self._record))
        self.assertEqual(set_apdu_trace_note_renderer(None), self._record)


class _ProtocolScriptedConnection(ScriptedPcscConnection):
    """Scripted connection that also reports the negotiated protocol, as pyscard does."""

    def __init__(self, script, protocol):
        super().__init__(script)
        self._protocol = protocol

    def getProtocol(self):
        return self._protocol


# pyscard CardConnection.T0_protocol / T1_protocol.
_T0 = 0x00000001
_T1 = 0x00000002
# A FETCHed proactive command: D0 { command details, device identities }.
_FETCHED_PROACTIVE_COMMAND = bytes.fromhex("D009810301050082028182")
# ES10 STORE DATA, P1 '91': last block, BER-TLV, ISO case 4.
_CASE_4_STORE_DATA = bytes.fromhex("80E2910006BF3E035C015A")


def _quiet_channel(script, protocol=None):
    channel = PcscApduChannel.__new__(PcscApduChannel)
    if protocol is None:
        channel._conn = ScriptedPcscConnection(script)
    else:
        channel._conn = _ProtocolScriptedConnection(script, protocol)
    channel._raw_apdu_logging = False
    channel._quiet_apdu_logging = True
    return channel


def _sent(channel):
    return [bytes(call) for call in channel._conn.calls]


class PcscApduChannelResponseCompletionTests(unittest.TestCase):
    def test_store_data_answered_91xx_collects_the_waiting_response_before_fetch(self):
        result = bytes.fromhex("BF5103800100")
        channel = _quiet_channel(
            [
                (b"", 0x91, 0x0B),
                (result, 0x91, 0x0B),
                (_FETCHED_PROACTIVE_COMMAND, 0x90, 0x00),
                (b"", 0x90, 0x00),
            ],
            protocol=_T0,
        )

        response = channel.send(_CASE_4_STORE_DATA, "ES10")

        self.assertEqual(response, result)
        sent = _sent(channel)
        self.assertEqual(len(sent), 4)
        self.assertEqual(sent[1], bytes.fromhex("00C0000000"))
        self.assertEqual(sent[2], bytes.fromhex("801200000B"))
        self.assertEqual(sent[3][:2], bytes.fromhex("8014"))

    def test_91xx_with_nothing_waiting_keeps_the_status_and_still_drains(self):
        channel = _quiet_channel(
            [
                (b"", 0x91, 0x0B),
                (b"", 0x6F, 0x00),
                (_FETCHED_PROACTIVE_COMMAND, 0x90, 0x00),
                (b"", 0x90, 0x00),
            ],
        )

        response = channel.send(_CASE_4_STORE_DATA, "ES10")

        self.assertEqual(response, b"")
        self.assertEqual(_sent(channel)[1:3], [bytes.fromhex("00C0000000"), bytes.fromhex("801200000B")])

    def test_waiting_response_announced_with_6cxx_is_fetched_with_its_length(self):
        result = bytes.fromhex("BF5103800100")
        channel = _quiet_channel(
            [
                (b"", 0x91, 0x0B),
                (b"", 0x6C, len(result)),
                (result, 0x90, 0x00),
                (_FETCHED_PROACTIVE_COMMAND, 0x90, 0x00),
                (b"", 0x90, 0x00),
            ],
            protocol=_T0,
        )

        response = channel.send(_CASE_4_STORE_DATA, "ES10")

        self.assertEqual(response, result)
        self.assertEqual(
            _sent(channel)[1:4],
            [bytes.fromhex("00C0000000"), bytes.fromhex("00C0000006"), bytes.fromhex("801200000B")],
        )

    def test_t1_link_does_not_look_behind_91xx(self):
        channel = _quiet_channel(
            [
                (b"", 0x91, 0x0B),
                (_FETCHED_PROACTIVE_COMMAND, 0x90, 0x00),
                (b"", 0x90, 0x00),
            ],
            protocol=_T1,
        )

        self.assertEqual(channel.send(_CASE_4_STORE_DATA, "ES10"), b"")
        self.assertEqual(_sent(channel)[1], bytes.fromhex("801200000B"))

    def test_case_3_commands_answered_91xx_are_not_followed_by_get_response(self):
        terminal_capability = bytes.fromhex("80AA000005A903840101")
        case_3_store_data = bytes.fromhex("80E2900003BF5500")
        for command in (terminal_capability, case_3_store_data):
            with self.subTest(command=command.hex().upper()):
                channel = _quiet_channel(
                    [
                        (b"", 0x91, 0x0B),
                        (_FETCHED_PROACTIVE_COMMAND, 0x90, 0x00),
                        (b"", 0x90, 0x00),
                    ],
                    protocol=_T0,
                )

                channel.send(command, "CMD")

                self.assertEqual(_sent(channel)[1], bytes.fromhex("801200000B"))

    def test_6cxx_to_a_case_3_command_appends_le_and_keeps_the_data(self):
        command = bytes.fromhex("80E2910003BF5500")
        channel = _quiet_channel([(b"", 0x6C, 0x12), (b"\xCA\xFE", 0x90, 0x00)])

        self.assertEqual(channel.send(command, "ES10"), b"\xCA\xFE")
        self.assertEqual(_sent(channel)[1], command + b"\x12")

    def test_6cxx_to_a_case_4_command_replaces_its_le(self):
        channel = _quiet_channel([(b"", 0x6C, 0x1A), (b"\x62\x00", 0x90, 0x00)])

        channel.send(bytes.fromhex("00A40400023F0000"), "SELECT")

        self.assertEqual(_sent(channel)[1], bytes.fromhex("00A40400023F001A"))

    def test_6cxx_to_a_get_response_resends_the_get_response_not_the_command(self):
        command = bytes.fromhex("80E2910003BF5500")
        channel = _quiet_channel(
            [
                (b"", 0x61, 0x10),
                (b"", 0x6C, 0x08),
                (b"\x01" * 8, 0x90, 0x00),
            ]
        )

        self.assertEqual(channel.send(command, "ES10"), b"\x01" * 8)
        self.assertEqual(
            _sent(channel),
            [command, bytes.fromhex("00C0000010"), bytes.fromhex("00C0000008")],
        )

    def test_a_second_6cxx_to_the_command_fails_instead_of_looping(self):
        channel = _quiet_channel([(b"", 0x6C, 0x12), (b"", 0x6C, 0x12)])

        with self.assertRaises(IOError) as raised:
            channel.send(bytes.fromhex("80CA005A00"), "GET DATA")

        self.assertIn("6C12", str(raised.exception))
        self.assertEqual(len(_sent(channel)), 2)

    def test_empty_fetch_answer_ends_the_drain_without_failing_the_command(self):
        channel = _quiet_channel([(b"\xAA", 0x91, 0x05), (b"", 0x90, 0x00)])

        self.assertEqual(channel.send(bytes.fromhex("80CA005A00"), "GET DATA"), b"\xAA")

    def test_resend_with_le_refuses_shapes_without_a_short_le(self):
        from SCP11.transport import resend_with_le

        self.assertIsNone(resend_with_le(bytes.fromhex("80E2"), 0x10))
        self.assertIsNone(resend_with_le(bytes.fromhex("80E20000000003AABBCC"), 0x10))
        self.assertIsNone(resend_with_le(bytes.fromhex("80E2910004BF55"), 0x10))
        self.assertEqual(resend_with_le(bytes.fromhex("80CA005A00"), 0x10), bytes.fromhex("80CA005A10"))


class _ScriptedExchangeChannel:
    def __init__(self, script):
        self._script = list(script)
        self.sent = []

    def exchange(self, apdu, log_name):
        self.sent.append(bytes(apdu))
        return self._script.pop(0)


class RelayAdapterLengthCorrectionTests(unittest.TestCase):
    """The SCP03 relay adapters of the live and local-access shells share the transport's rules."""

    def test_6cxx_keeps_a_case_3_command_intact_and_corrects_a_get_response(self):
        from SCP11.live.console import _SCP03RelayTransportAdapter
        from SCP11.local_access.main import _LocalAccessTransportAdapter

        command = bytes.fromhex("80E2910003BF5500")
        for adapter_cls in (_SCP03RelayTransportAdapter, _LocalAccessTransportAdapter):
            with self.subTest(adapter=adapter_cls.__name__):
                channel = _ScriptedExchangeChannel(
                    [
                        (b"", 0x6C, 0x20),
                        (b"", 0x61, 0x10),
                        (b"", 0x6C, 0x08),
                        (b"\x01" * 8, 0x90, 0x00),
                    ]
                )

                answer = adapter_cls(channel).transmit(command.hex().upper())

                self.assertEqual(answer, (b"\x01" * 8, 0x90, 0x00))
                self.assertEqual(
                    channel.sent,
                    [
                        command,
                        command + b"\x20",
                        bytes.fromhex("00C0000010"),
                        bytes.fromhex("00C0000008"),
                    ],
                )


class _ScriptedConnectConnection:
    """PC/SC connection stub whose connect() replays scripted outcomes.

    Each entry is ``None`` (the connect succeeds) or an exception instance to
    raise, consumed in order.
    """

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.disposition = None

    def connect(self, *args, **kwargs):
        self.connect_calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome

    def disconnect(self, *args, **kwargs):
        self.disconnect_calls += 1

    def transmit(self, apdu):
        return [], 0x90, 0x00


class _FakeReader:
    def __init__(self, connection):
        self._connection = connection

    def createConnection(self):
        return self._connection

    def __str__(self):
        return "Fake Reader 00 00"


def _unresponsive_card():
    from smartcard.Exceptions import CardConnectionException
    from smartcard.scard import SCARD_W_UNRESPONSIVE_CARD

    return CardConnectionException(
        "Unable to connect with protocol: T0 or T1. Card is unresponsive.",
        hresult=SCARD_W_UNRESPONSIVE_CARD,
    )


class PcscApduChannelReconnectTests(unittest.TestCase):
    """The cold boot at every command boundary is repeated on a transient PC/SC status."""

    def _connect(self, connection, platform="linux"):
        channel = PcscApduChannel.__new__(PcscApduChannel)
        with mock.patch("smartcard.System.readers", return_value=[_FakeReader(connection)]):
            with mock.patch("SCP11.transport.time.sleep") as sleep_mock:
                with mock.patch("SCP11.transport.sys.platform", platform):
                    result = channel._connect_after_power_cycle(0)
        return result, sleep_mock

    def test_connect_repeats_while_the_card_reports_unresponsive(self):
        connection = _ScriptedConnectConnection([_unresponsive_card(), _unresponsive_card(), None])

        result, sleep_mock = self._connect(connection)

        self.assertEqual(connection.connect_calls, 3)
        self.assertEqual([call.args[0] for call in sleep_mock.call_args_list], [0.25, 0.5])
        self.assertTrue(callable(getattr(result, "transmit", None)))

    def test_connect_gives_up_naming_the_reader_attempts_and_last_status(self):
        outcomes = [_unresponsive_card() for _ in range(6)]
        connection = _ScriptedConnectConnection(outcomes)

        with self.assertRaises(RuntimeError) as raised:
            self._connect(connection)

        self.assertEqual(connection.connect_calls, 6)
        message = str(raised.exception)
        self.assertIn("'Fake Reader 00 00' (index 0) failed 6 times over", message)
        self.assertIn("Card is unresponsive", message)
        self.assertNotIn("useIFDCCID", message)
        self.assertIs(raised.exception.__cause__, outcomes[-1])

    def test_connect_exhaustion_names_the_libccid_switch_on_macos(self):
        connection = _ScriptedConnectConnection([_unresponsive_card() for _ in range(6)])

        with self.assertRaises(RuntimeError) as raised:
            self._connect(connection, platform="darwin")

        self.assertIn("useIFDCCID -bool yes", str(raised.exception))

    def test_connect_does_not_repeat_on_an_empty_reader(self):
        from smartcard.Exceptions import NoCardException
        from smartcard.scard import SCARD_E_NO_SMARTCARD

        connection = _ScriptedConnectConnection(
            [NoCardException("Unable to connect", hresult=SCARD_E_NO_SMARTCARD)]
        )

        with self.assertRaises(NoCardException):
            self._connect(connection)

        self.assertEqual(connection.connect_calls, 1)

    def test_reset_leaves_the_channel_disconnected_when_the_reconnect_fails(self):
        channel = PcscApduChannel.__new__(PcscApduChannel)
        channel._conn = _ScriptedConnectConnection([])
        channel._reader_index = 0
        channel._raw_apdu_logging = False
        channel._quiet_apdu_logging = True
        self.assertTrue(channel.is_connected())

        with mock.patch.object(
            PcscApduChannel,
            "_connect_after_power_cycle",
            side_effect=RuntimeError("PC/SC connect to reader 'Fake Reader 00 00' (index 0) failed 6 times"),
        ):
            with mock.patch("SCP11.transport.time.sleep"):
                with self.assertRaises(RuntimeError):
                    channel.reset()

        self.assertFalse(channel.is_connected())
        with self.assertRaises(IOError):
            channel.exchange(bytes.fromhex("00A4040000"), "SELECT")


if __name__ == "__main__":
    unittest.main()
