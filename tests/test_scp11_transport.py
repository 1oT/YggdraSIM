import unittest

from SCP11.transport import RelayApduChannel


class FakeRelayClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def send_apdu(self, apdu: bytes, session_id: str = ""):
        self.calls.append((apdu, session_id))
        if len(self.responses) == 0:
            raise RuntimeError("No fake responses remaining")
        return self.responses.pop(0)


class RelayApduChannelTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
