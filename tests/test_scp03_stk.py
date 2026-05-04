import contextlib
import io
import unittest
from types import SimpleNamespace

from SCP03.interface.stk_shell import StkShell
from SCP03.logic.stk import StkController


class FakeConnection:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[str] = []

    def transmit(self, apdu):
        self.calls.append(bytes(apdu).hex().upper())
        if len(self.responses) == 0:
            raise AssertionError(f"Unexpected APDU: {bytes(apdu).hex().upper()}")
        data, sw1, sw2 = self.responses.pop(0)
        return list(data), sw1, sw2


class FakeTransport:
    def __init__(self, responses):
        self.connection = FakeConnection(responses)
        self.debug = False
        self.reset_calls = 0
        self.reset_session_calls = 0

    def reset(self):
        self.reset_calls += 1
        return True

    def reset_session_state(self):
        self.reset_session_calls += 1

    def connect(self):
        return True


class StkControllerTests(unittest.TestCase):
    def test_initialize_bootstraps_terminal_profile_and_tracks_event_list(self):
        fetch_data = bytes.fromhex("D00D81030105008202818299020309")
        transport = FakeTransport(
            [
                (b"", 0x91, 0x0F),
                (fetch_data, 0x90, 0x00),
                (b"", 0x90, 0x00),
            ]
        )
        controller = StkController(transport)

        controller.initialize()

        self.assertTrue(controller.state.initialized)
        self.assertEqual(controller.state.event_list, [0x03, 0x09])
        self.assertEqual(transport.reset_calls, 1)
        self.assertEqual(transport.reset_session_calls, 1)
        self.assertEqual(
            transport.connection.calls,
            [
                "8010000015FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00",
                "801200000F",
                "801400000C810301050002028281030100",
            ],
        )

    def test_send_sms_pp_wraps_tpdu_in_envelope(self):
        transport = FakeTransport([(b"", 0x90, 0x00)])
        controller = StkController(transport)

        controller.send_sms_pp("001122")

        self.assertEqual(
            transport.connection.calls,
            ["80C200000FD10D02028281060280018B03001122"],
        )

    def test_send_data_available_event_uses_virtual_channel_length(self):
        transport = FakeTransport([(b"", 0x90, 0x00)])
        controller = StkController(transport)
        controller.queue_channel_data("DEADBEEF")

        controller.send_data_available_event()

        self.assertTrue(controller.state.open_channel_active)
        self.assertEqual(
            transport.connection.calls,
            ["80C2000010D60E9901090202828138028100370104"],
        )

    def test_send_apdu_drains_proactive_chain_and_consumes_queued_bytes(self):
        fetch_data = bytes.fromhex("D00C810301420082028182B70102")
        transport = FakeTransport(
            [
                (b"", 0x91, 0x0E),
                (fetch_data, 0x90, 0x00),
                (b"", 0x90, 0x00),
            ]
        )
        controller = StkController(transport)
        controller.queue_channel_data("DEADBEEF")

        controller.send_apdu("80CA000000")

        self.assertEqual(
            transport.connection.calls,
            [
                "80CA000000",
                "801200000E",
                "80140000138103014200020282810301003602DEAD370102",
            ],
        )
        self.assertEqual(controller.state.pending_channel_data, bytes.fromhex("BEEF"))


class _DummyStkController:
    def __init__(self):
        self.debug = False
        self.initialized_calls = 0
        self.queue_calls: list[str] = []
        self.data_available_calls = 0
        self.state = SimpleNamespace(
            initialized=False,
            open_channel_active=False,
            command_history=[],
            flow_events=[],
        )

    def set_debug(self, enabled: bool) -> None:
        self.debug = bool(enabled)

    def initialize(self) -> None:
        self.initialized_calls += 1
        self.state.initialized = True

    def queue_channel_data(self, payload_hex: str) -> int:
        self.queue_calls.append(payload_hex)
        return len(bytes.fromhex(payload_hex))

    def send_data_available_event(self):
        self.data_available_calls += 1
        return b"", 0x90, 0x00

    def format_state_lines(self):
        return ["Initialized       : True"]

    def format_history_lines(self):
        return ["Proactive Commands:", "  (none)", "Triggers:", "  (none)", "Flow Events:", "  (none)"]


class StkShellTests(unittest.TestCase):
    def test_run_commands_auto_initializes_before_data_command(self):
        shell = StkShell(transport=SimpleNamespace(), debug=False)
        shell.controller = _DummyStkController()

        with contextlib.redirect_stdout(io.StringIO()):
            shell.run_commands("DATA DEADBEEF")

        self.assertEqual(shell.controller.initialized_calls, 1)
        self.assertEqual(shell.controller.queue_calls, ["DEADBEEF"])
        self.assertEqual(shell.controller.data_available_calls, 1)


if __name__ == "__main__":
    unittest.main()
