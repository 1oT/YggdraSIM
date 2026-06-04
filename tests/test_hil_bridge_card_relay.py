from __future__ import annotations

import json
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock
from urllib import request as urllib_request

from Tools.HilBridge.apdu_relay import (
    HilBridgeApduRelayService,
    ApduRelayConfig,
    _APDU_RELAY_MAX_BODY_BYTES,
)
from Tools.HilBridge.pcsc import PcscCardChannel
from Tools.HilBridge.router import BackendCardChannel, HilBridgeServer
from yggdrasim_common.card_backend import CARD_BACKEND_ENV, create_card_connection


def _read_json(url: str) -> dict:
    with urllib_request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json(url: str, payload: dict) -> dict:
    request = urllib_request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib_request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


class _FakeReaderConnection:
    def __init__(self) -> None:
        self.connected = False
        self.connect_protocol = None
        self.connect_mode = None
        self.disconnect_args = ()
        self.disconnect_kwargs = {}

    def connect(self, protocol=None, mode=None) -> None:
        self.connected = True
        self.connect_protocol = protocol
        self.connect_mode = mode

    def disconnect(self, *args, **kwargs) -> None:
        self.connected = False
        self.disconnect_args = args
        self.disconnect_kwargs = dict(kwargs)

    def getATR(self):
        return [0x3B, 0x00]

    def transmit(self, apdu):
        return [0xCA, 0xFE], 0x90, 0x00


class _FakeReader:
    def __init__(self, connection: _FakeReaderConnection) -> None:
        self._connection = connection

    def createConnection(self) -> _FakeReaderConnection:
        return self._connection


class _FakeConnectionDecorator:
    def __init__(self, component: _FakeReaderConnection) -> None:
        self.component = component

    def connect(self, protocol=None, mode=None, disposition=None) -> None:
        self.component.connect(protocol=protocol, mode=mode)

    def disconnect(self) -> None:
        raise AssertionError("reset must unpower the wrapped PC/SC component directly")

    def getATR(self):
        return self.component.getATR()

    def transmit(self, apdu):
        return self.component.transmit(apdu)


class _FakePcscChannel:
    def __init__(self) -> None:
        self.reader_label = "Mock PCSC Reader"
        self.connect_calls = 0
        self.reconnect_calls = 0
        self.reset_card_calls = 0
        self.disconnect_calls = 0
        self.last_apdu = b""

    def connect(self) -> None:
        self.connect_calls += 1

    def reconnect(self) -> None:
        self.reconnect_calls += 1

    def reset_card(self) -> None:
        self.reset_card_calls += 1

    def disconnect(self) -> None:
        self.disconnect_calls += 1

    def get_atr(self) -> bytes:
        return bytes.fromhex("3B00")

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        self.last_apdu = bytes(apdu)
        return bytes.fromhex("CAFE"), 0x90, 0x00


class _FakeSimulatedConnection:
    def __init__(self) -> None:
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.last_apdu = b""

    def connect(self, protocol=None) -> None:
        del protocol
        self.connect_calls += 1

    def disconnect(self) -> None:
        self.disconnect_calls += 1

    def getATR(self):
        return [0x3B, 0x9F]

    def transmit(self, apdu):
        self.last_apdu = bytes(apdu)
        return [0xBE, 0xEF], 0x91, 0x00


class _FakeSimulatedWrapper:
    def __init__(self, connection: _FakeSimulatedConnection) -> None:
        self._connection = connection
        self.queued_modes: list[str] = []

    def disconnect(self) -> None:
        self._connection.disconnect()

    def get_atr(self) -> bytes:
        return bytes.fromhex("3B9F")

    def queue_refresh(self, mode: str | int = "euicc-profile-state-change", *, source: str = "") -> dict[str, object]:
        normalized_mode = str(mode)
        self.queued_modes.append(normalized_mode)
        return {
            "status": "queued",
            "mode": normalized_mode,
            "qualifier": "00",
            "commandNumber": len(self.queued_modes),
            "pendingCount": len(self.queued_modes),
            "queuedModes": list(self.queued_modes),
            "activeMode": "",
            "activeQualifier": "",
            "description": normalized_mode,
            "deliveryHint": f"queued by {source}",
        }

    def proactive_status_payload(self) -> dict[str, object]:
        return {
            "pendingCount": len(self.queued_modes),
            "queuedCount": len(self.queued_modes),
            "activeMode": "",
            "activeQualifier": "",
            "queuedModes": list(self.queued_modes),
            "openChannelActive": False,
            "openChannelEndpoint": "",
            "eimPollStage": "idle",
            "deliveryHint": "simulated",
        }

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        data, sw1, sw2 = self._connection.transmit(apdu)
        return bytes(data), sw1, sw2


class HilBridgeCardRelayTests(unittest.TestCase):
    def test_backend_card_channel_uses_pcsc_channel_when_backend_is_reader(self) -> None:
        fake_pcsc = _FakePcscChannel()
        with mock.patch("Tools.HilBridge.router.is_simulated_card_backend", return_value=False):
            with mock.patch("Tools.HilBridge.router.PcscCardChannel", return_value=fake_pcsc) as mocked_pcsc:
                channel = BackendCardChannel(reader_index=2, reader_name="Alpha")
                channel.connect()
                atr = channel.get_atr()
                data, sw1, sw2 = channel.transmit(bytes.fromhex("00A4040000"))
                channel.reconnect()
                channel.disconnect()

        mocked_pcsc.assert_called_once_with(reader_index=2, reader_name="Alpha")
        self.assertEqual(channel.backend_name, "reader")
        self.assertEqual(channel.reader_label, "Mock PCSC Reader")
        self.assertEqual(atr, bytes.fromhex("3B00"))
        self.assertEqual(data, bytes.fromhex("CAFE"))
        self.assertEqual(sw1, 0x90)
        self.assertEqual(sw2, 0x00)
        self.assertEqual(fake_pcsc.connect_calls, 1)
        self.assertEqual(fake_pcsc.reconnect_calls, 1)
        self.assertEqual(fake_pcsc.reset_card_calls, 0)
        self.assertEqual(fake_pcsc.disconnect_calls, 1)
        self.assertEqual(fake_pcsc.last_apdu, bytes.fromhex("00A4040000"))

    def test_pcsc_card_channel_reset_unpowers_card_slot(self) -> None:
        first_connection = _FakeReaderConnection()
        second_connection = _FakeReaderConnection()
        reader = mock.Mock()
        reader.createConnection.side_effect = [first_connection, second_connection]
        unpower_disposition = object()

        with mock.patch(
            "Tools.HilBridge.pcsc._load_smartcard_runtime",
            return_value=(lambda: [reader], "exclusive", unpower_disposition, "leave", None, RuntimeError),
        ):
            with mock.patch("Tools.HilBridge.pcsc.time.sleep") as sleep_mock:
                channel = PcscCardChannel()
                channel.connect()
                channel.reset_card()

        self.assertFalse(first_connection.connected)
        self.assertIs(first_connection.disposition, unpower_disposition)
        self.assertEqual(first_connection.disconnect_args, ())
        self.assertEqual(first_connection.disconnect_kwargs, {})
        self.assertTrue(second_connection.connected)
        self.assertEqual(second_connection.connect_mode, "exclusive")
        sleep_mock.assert_called_once_with(0.2)

    def test_pcsc_card_channel_reset_unwraps_exclusive_connection_decorator(self) -> None:
        first_connection = _FakeReaderConnection()
        second_connection = _FakeReaderConnection()
        reader = mock.Mock()
        reader.createConnection.side_effect = [first_connection, second_connection]
        unpower_disposition = object()

        def _wrap(connection):
            return _FakeConnectionDecorator(connection)

        with mock.patch(
            "Tools.HilBridge.pcsc._load_smartcard_runtime",
            return_value=(lambda: [reader], "exclusive", unpower_disposition, "leave", _wrap, RuntimeError),
        ):
            with mock.patch("Tools.HilBridge.pcsc.time.sleep"):
                channel = PcscCardChannel()
                channel.connect()
                channel.reset_card()

        self.assertFalse(first_connection.connected)
        self.assertIs(first_connection.disposition, unpower_disposition)
        self.assertEqual(first_connection.disconnect_args, ())
        self.assertTrue(second_connection.connected)

    def test_backend_card_channel_reset_uses_pcsc_power_cycle(self) -> None:
        fake_pcsc = _FakePcscChannel()
        with mock.patch("Tools.HilBridge.router.is_simulated_card_backend", return_value=False):
            with mock.patch("Tools.HilBridge.router.PcscCardChannel", return_value=fake_pcsc):
                channel = BackendCardChannel()
                channel.connect()
                channel.reset_card()

        self.assertEqual(fake_pcsc.reset_card_calls, 1)
        self.assertEqual(fake_pcsc.reconnect_calls, 0)

    def test_backend_card_channel_uses_simulated_connection_when_backend_is_sim(self) -> None:
        fake_sim = _FakeSimulatedConnection()
        fake_wrapper = _FakeSimulatedWrapper(fake_sim)

        with mock.patch("Tools.HilBridge.router.is_simulated_card_backend", return_value=True):
            with mock.patch("Tools.HilBridge.router.describe_card_backend", return_value="sim [profile_store]"):
                with mock.patch("Tools.HilBridge.router._create_simulated_card_connection", return_value=fake_sim):
                    with mock.patch("Tools.HilBridge.router.SimulatedModemCardChannel", return_value=fake_wrapper):
                        channel = BackendCardChannel()
                        channel.connect()
                        atr = channel.get_atr()
                        data, sw1, sw2 = channel.transmit(bytes.fromhex("80CA005A00"))
                        channel.reconnect()
                        channel.disconnect()

        self.assertEqual(channel.backend_name, "sim")
        self.assertEqual(channel.reader_label, "sim [profile_store]")
        self.assertEqual(atr, bytes.fromhex("3B9F"))
        self.assertEqual(data, bytes.fromhex("BEEF"))
        self.assertEqual(sw1, 0x91)
        self.assertEqual(sw2, 0x00)
        self.assertEqual(fake_sim.connect_calls, 0)
        self.assertEqual(fake_sim.last_apdu, bytes.fromhex("80CA005A00"))
        self.assertEqual(fake_sim.disconnect_calls, 2)

    def test_apdu_relay_service_handles_status_and_exchange(self) -> None:
        exchanges: list[tuple[str, bytes]] = []

        def exchange_callback(apdu: bytes, *, session_id: str = "") -> tuple[bytes, int, int]:
            exchanges.append((session_id, apdu))
            return bytes.fromhex("DEADBEEF"), 0x90, 0x00

        def status_callback() -> dict[str, str]:
            return {
                "reader": "Mock Reader",
                "atr": "3B00",
            }

        relay = HilBridgeApduRelayService(
            ApduRelayConfig(host="127.0.0.1", port=0, enabled=True),
            exchange_callback=exchange_callback,
            status_callback=status_callback,
        )
        relay.start()
        try:
            status_payload = _read_json(relay.status_url)
            self.assertEqual(status_payload["reader"], "Mock Reader")
            self.assertEqual(status_payload["atr"], "3B00")
            self.assertEqual(status_payload["url"], relay.apdu_url)

            response_payload = _post_json(
                relay.apdu_url,
                {
                    "sessionId": "scp11-test",
                    "apdu": "00A4040000",
                },
            )
        finally:
            relay.stop()

        self.assertEqual(
            response_payload,
            {
                "data": "DEADBEEF",
                "sw1": "90",
                "sw2": "00",
            },
        )
        self.assertEqual(exchanges, [("scp11-test", bytes.fromhex("00A4040000"))])

    def test_hil_bridge_server_resets_reader_for_card_reset_relay_request(self) -> None:
        card = types.SimpleNamespace(
            backend_name="reader",
            reset_card=mock.Mock(return_value={"mode": "pcsc-reconnect-unpower"}),
            get_atr=mock.Mock(return_value=bytes.fromhex("3B9F")),
            reader_label="PCSC test reader",
        )
        worker = types.SimpleNamespace(drain=mock.Mock())
        proactive = types.SimpleNamespace(
            reset=mock.Mock(),
            queue_refresh=mock.Mock(side_effect=AssertionError("uicc-reset must not queue proactive REFRESH")),
        )

        server = object.__new__(HilBridgeServer)
        server._card_lock = threading.RLock()
        server._proactive_lock = threading.Lock()
        server._card = card
        server._card_worker = worker
        server._session = types.SimpleNamespace(
            proactive=proactive,
            atr_bytes=b"",
            control=None,
            bankd=None,
        )
        server._apdu_relay = types.SimpleNamespace(
            card_reset_url="http://127.0.0.1:44215/card/reset",
        )

        reset_payload = server._handle_relay_card_reset(session_id="scp11-test")

        worker.drain.assert_called_once_with(timeout=5.0)
        card.reset_card.assert_called_once_with()
        card.get_atr.assert_called_once_with()
        proactive.reset.assert_called_once_with()
        proactive.queue_refresh.assert_not_called()
        self.assertEqual(server._session.atr_bytes, bytes.fromhex("3B9F"))
        self.assertEqual(reset_payload["status"], "reset")
        self.assertEqual(reset_payload["sessionId"], "scp11-test")
        self.assertEqual(reset_payload["atr"], "3B9F")
        self.assertEqual(reset_payload["reset"]["mode"], "pcsc-reconnect-unpower")

    def test_create_card_connection_uses_bridge_marker_when_present(self) -> None:
        def exchange_callback(apdu: bytes, *, session_id: str = "") -> tuple[bytes, int, int]:
            self.assertEqual(session_id, "")
            self.assertEqual(apdu, bytes.fromhex("80CA005A00"))
            return bytes.fromhex("11223344"), 0x90, 0x00

        def status_callback() -> dict[str, str]:
            return {
                "reader": "Bridge Reader",
                "atr": "3B8F8001",
            }

        relay = HilBridgeApduRelayService(
            ApduRelayConfig(host="127.0.0.1", port=0, enabled=True),
            exchange_callback=exchange_callback,
            status_callback=status_callback,
        )
        relay.start()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                marker_path = Path(temp_dir) / "state" / "hil_bridge_card_relay.json"
                marker_path.parent.mkdir(parents=True, exist_ok=True)
                marker_path.write_text(
                    json.dumps(
                        {
                            "url": relay.apdu_url,
                        }
                    ),
                    encoding="utf-8",
                )
                with mock.patch.dict(
                    "os.environ",
                    {
                        "YGGDRASIM_RUNTIME_ROOT": temp_dir,
                        CARD_BACKEND_ENV: "reader",
                    },
                    clear=False,
                ):
                    def _should_not_use_readers():
                        raise AssertionError("Direct readers() path should not be used while bridge relay is active.")

                    connection = create_card_connection(reader_index=0, readers_func=_should_not_use_readers)
                    self.assertEqual(connection.__class__.__name__, "RelayCardConnection")
                    self.assertEqual(connection.getATR(), [0x3B, 0x8F, 0x80, 0x01])
                    data, sw1, sw2 = connection.transmit(list(bytes.fromhex("80CA005A00")))
        finally:
            relay.stop()

        self.assertEqual(data, [0x11, 0x22, 0x33, 0x44])
        self.assertEqual(sw1, 0x90)
        self.assertEqual(sw2, 0x00)

    def test_apdu_relay_rejects_oversized_request_body(self) -> None:
        def exchange_callback(apdu: bytes, *, session_id: str = "") -> tuple[bytes, int, int]:
            raise AssertionError(
                "exchange_callback must not be reached when a body-size "
                "rejection happens before the JSON is parsed."
            )

        def status_callback() -> dict[str, str]:
            return {"reader": "Mock Reader", "atr": "3B00"}

        relay = HilBridgeApduRelayService(
            ApduRelayConfig(host="127.0.0.1", port=0, enabled=True),
            exchange_callback=exchange_callback,
            status_callback=status_callback,
        )
        relay.start()
        try:
            oversized = _APDU_RELAY_MAX_BODY_BYTES + 1
            payload = b"x" * oversized
            request = urllib_request.Request(
                relay.apdu_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib_request.urlopen(request, timeout=5)
            except urllib_request.HTTPError as http_error:
                status_code = http_error.code
            else:
                self.fail("Oversized request body was accepted.")
        finally:
            relay.stop()

        self.assertEqual(status_code, 400)

    def test_create_card_connection_falls_back_to_direct_reader_when_marker_is_stale(self) -> None:
        fake_connection = _FakeReaderConnection()
        fake_reader = _FakeReader(fake_connection)

        with tempfile.TemporaryDirectory() as temp_dir:
            marker_path = Path(temp_dir) / "state" / "hil_bridge_card_relay.json"
            marker_path.parent.mkdir(parents=True, exist_ok=True)
            marker_path.write_text(
                json.dumps(
                    {
                        "url": "http://127.0.0.1:1/apdu",
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                "os.environ",
                {
                    "YGGDRASIM_RUNTIME_ROOT": temp_dir,
                    CARD_BACKEND_ENV: "reader",
                },
                clear=False,
            ):
                connection = create_card_connection(reader_index=0, readers_func=lambda: [fake_reader])

        self.assertIs(connection, fake_connection)
        self.assertTrue(fake_connection.connected)
        self.assertIsNone(fake_connection.connect_protocol)


if __name__ == "__main__":
    unittest.main()
