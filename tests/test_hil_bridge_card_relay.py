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

    def connect(self, protocol=None) -> None:
        self.connected = True
        self.connect_protocol = protocol

    def disconnect(self) -> None:
        self.connected = False

    def getATR(self):
        return [0x3B, 0x00]

    def transmit(self, apdu):
        return [0xCA, 0xFE], 0x90, 0x00


class _FakeReader:
    def __init__(self, connection: _FakeReaderConnection) -> None:
        self._connection = connection

    def createConnection(self) -> _FakeReaderConnection:
        return self._connection


class _FakePcscChannel:
    def __init__(self) -> None:
        self.reader_label = "Mock PCSC Reader"
        self.connect_calls = 0
        self.reconnect_calls = 0
        self.disconnect_calls = 0
        self.last_apdu = b""

    def connect(self) -> None:
        self.connect_calls += 1

    def reconnect(self) -> None:
        self.reconnect_calls += 1

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
        self.assertEqual(fake_pcsc.disconnect_calls, 1)
        self.assertEqual(fake_pcsc.last_apdu, bytes.fromhex("00A4040000"))

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

    def test_backend_card_channel_exposes_simulator_refresh_controls(self) -> None:
        fake_sim = _FakeSimulatedConnection()
        fake_wrapper = _FakeSimulatedWrapper(fake_sim)

        with mock.patch("Tools.HilBridge.router.is_simulated_card_backend", return_value=True):
            with mock.patch("Tools.HilBridge.router.describe_card_backend", return_value="sim [profile_store]"):
                with mock.patch("Tools.HilBridge.router._create_simulated_card_connection", return_value=fake_sim):
                    with mock.patch("Tools.HilBridge.router.SimulatedModemCardChannel", return_value=fake_wrapper):
                        channel = BackendCardChannel()
                        channel.connect()
                        queue_payload = channel.queue_modem_refresh("euicc-profile-state-change", source="relay-test")
                        status_payload = channel.proactive_status_payload()

        self.assertEqual(queue_payload["status"], "queued")
        self.assertEqual(queue_payload["mode"], "euicc-profile-state-change")
        self.assertEqual(queue_payload["pendingCount"], 1)
        self.assertEqual(status_payload["pendingCount"], 1)
        self.assertEqual(status_payload["queuedModes"], ["euicc-profile-state-change"])

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

    def test_hil_bridge_server_uses_simulator_queue_for_modem_refresh(self) -> None:
        queue_modem_refresh = mock.Mock(
            return_value={
                "status": "queued",
                "mode": "euicc-profile-state-change",
                "qualifier": "00",
                "pendingCount": 1,
            }
        )
        proactive_queue_refresh = mock.Mock(side_effect=AssertionError("bridge proactive broker should not be used"))

        server = object.__new__(HilBridgeServer)
        server._card_lock = threading.RLock()
        server._card = types.SimpleNamespace(
            backend_name="sim",
            queue_modem_refresh=queue_modem_refresh,
            reader_label="sim [profile_store]",
            proactive_status_payload=lambda: {
                "pendingCount": 1,
                "queuedCount": 1,
                "activeMode": "",
                "activeQualifier": "",
                "queuedModes": ["euicc-profile-state-change"],
                "openChannelActive": True,
                "openChannelEndpoint": "8.8.8.8:53",
                "eimPollStage": "dns-await-response",
                "deliveryHint": "Simulator proactive queue is announced on modem STATUS and served on FETCH.",
            },
        )
        server._session = types.SimpleNamespace(
            proactive=types.SimpleNamespace(queue_refresh=proactive_queue_refresh),
            atr_bytes=bytes.fromhex("3B9F"),
            control=None,
            bankd=None,
        )
        server._apdu_relay = types.SimpleNamespace(
            modem_refresh_url="http://127.0.0.1:44215/modem-refresh",
            apdu_url="http://127.0.0.1:44215/apdu",
            status_url="http://127.0.0.1:44215/status",
        )
        server._config = types.SimpleNamespace(listen_host="127.0.0.1", listen_port=9997)

        refresh_payload = server._handle_relay_modem_refresh("euicc-profile-state-change", session_id="scp11-test")
        status_payload = server._build_relay_status_payload()

        queue_modem_refresh.assert_called_once_with("euicc-profile-state-change", source="scp11-test")
        proactive_queue_refresh.assert_not_called()
        self.assertEqual(refresh_payload["mode"], "euicc-profile-state-change")
        self.assertEqual(refresh_payload["modemRefreshUrl"], "http://127.0.0.1:44215/modem-refresh")
        self.assertEqual(status_payload["cardBackend"], "sim")
        self.assertEqual(status_payload["pendingCount"], 1)
        self.assertEqual(status_payload["openChannelEndpoint"], "8.8.8.8:53")
        self.assertEqual(status_payload["eimPollStage"], "dns-await-response")

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
            # Two outcomes legitimately mean "server rejected the
            # oversized body before it ever entered the JSON parser",
            # and which one materialises is platform / TCP-buffer
            # dependent on a localhost loopback:
            #
            # 1. The server reads the ``Content-Length`` header,
            #    immediately responds with ``400 Bad Request``, and
            #    closes the connection. The client's ``urlopen`` raises
            #    ``HTTPError`` with ``.code == 400`` (the documented
            #    contract this test pins).
            # 2. The server closes the socket while the client is still
            #    streaming the 1 MiB+1 body. The client's ``send()``
            #    half-write trips ``BrokenPipeError`` / ``ConnectionResetError``
            #    (wrapped in ``URLError``) before it ever sees the
            #    ``400`` response. This is a pure timing race against
            #    the TCP send buffer; on a fast loopback runner it is
            #    in fact the *more likely* outcome.
            #
            # Either path satisfies the contract -- the
            # ``exchange_callback`` ``AssertionError`` above guards the
            # real invariant (the relay never decoded JSON / dispatched
            # an APDU). Accept both, but still fail loudly if the
            # server actually accepted the request and returned 200.
            status_code: int | None = None
            try:
                urllib_request.urlopen(request, timeout=5)
            except urllib_request.HTTPError as http_error:
                status_code = http_error.code
            except (urllib_request.URLError, BrokenPipeError, ConnectionResetError):
                status_code = None
            else:
                self.fail("Oversized request body was accepted.")
        finally:
            relay.stop()

        if status_code is not None:
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
