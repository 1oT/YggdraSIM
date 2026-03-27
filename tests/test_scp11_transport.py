import io
import unittest
from contextlib import redirect_stdout

from SCP11.transport import PcscApduChannel, RelayApduChannel


class FakeRelayClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def send_apdu(self, apdu: bytes, session_id: str = ""):
        self.calls.append((apdu, session_id))
        if len(self.responses) == 0:
            raise RuntimeError("No fake responses remaining")
        return self.responses.pop(0)


class FakePcscConnection:
    def __init__(self, response_data, sw1, sw2):
        self._response_data = list(response_data)
        self._sw1 = int(sw1)
        self._sw2 = int(sw2)
        self.calls = []

    def transmit(self, apdu):
        self.calls.append(list(apdu))
        return list(self._response_data), self._sw1, self._sw2


class RelayApduChannelTests(unittest.TestCase):
    def test_reset_reports_unsupported(self):
        relay = FakeRelayClient([])
        channel = RelayApduChannel(relay_client=relay, session_id="S1")

        self.assertFalse(channel.reset())

    def test_handles_61_chaining(self):
        relay = FakeRelayClient(
            [
                (b"\xAA", 0x61, 0x02),
                (b"\xBB\xCC", 0x90, 0x00),
            ]
        )
        channel = RelayApduChannel(relay_client=relay, session_id="S1")

        result = channel.send(bytes.fromhex("00A4040000"), "TEST")

        self.assertEqual(result, b"\xAA\xBB\xCC")
        self.assertEqual(relay.calls[1][0], bytes.fromhex("00C0000002"))
        self.assertEqual(relay.calls[0][1], "S1")
        self.assertEqual(relay.calls[1][1], "S1")

    def test_handles_6c_length_correction(self):
        relay = FakeRelayClient(
            [
                (b"", 0x6C, 0x10),
                (b"\xDE\xAD", 0x90, 0x00),
            ]
        )
        channel = RelayApduChannel(relay_client=relay)

        result = channel.send(bytes.fromhex("00B0000000"), "TEST")

        self.assertEqual(result, b"\xDE\xAD")
        self.assertEqual(relay.calls[1][0], bytes.fromhex("00B0000010"))

    def test_raises_on_error_status(self):
        relay = FakeRelayClient(
            [
                (b"", 0x69, 0x82),
            ]
        )
        channel = RelayApduChannel(relay_client=relay)

        with self.assertRaises(IOError):
            channel.send(bytes.fromhex("80E2910000"), "TEST")


class PcscApduChannelLoggingTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
