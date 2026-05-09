# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge APDU router: dispatches incoming C-APDUs to the registered handler (relay, recorder, or simulated card)."""
from __future__ import annotations

import json
import logging
import os
import selectors
import socket
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from yggdrasim_common.card_backend import describe_card_backend, is_simulated_card_backend
from yggdrasim_common.runtime_paths import ensure_runtime_dir, runtime_path

from .apdu_relay import ApduRelayConfig, HilBridgeApduRelayService
from .pcsc import PcscBridgeError, PcscCardChannel
from .proactive import ProactiveRefreshBroker
from .sim_modem import SimulatedModemCardChannel
from .protocol import (
    COMPONENT_REMSIM_BANKD,
    COMPONENT_REMSIM_SERVER,
    GSMTAP_COMPAT_NATIVE,
    GsmtapTap,
    IpaFrame,
    IpaFrameParser,
    IPA_EXT_RSPRO,
    IPA_MSGT_PING,
    IPA_MSGT_PONG,
    IPA_PROTO_CCM,
    IPA_PROTO_OSMO,
    build_client_slot,
    build_component_identity,
    build_config_client_bank_req,
    build_config_client_id_req,
    build_connect_client_res,
    build_ipa_frame,
    build_ipa_pong,
    build_reset_state_res,
    build_set_atr_req,
    build_tpdu_card_to_modem,
    decode_rspro_pdu,
    encode_rspro_pdu,
    ensure_bytes,
    get_pdu_message_body,
    get_pdu_message_name,
    get_pdu_tag,
    load_rspro_codec,
)

LOGGER = logging.getLogger(__name__)
CARD_RELAY_MARKER_FILENAME = "hil_bridge_card_relay.json"


class ConnectionRole(str, Enum):
    CONTROL = "control"
    BANKD = "bankd"


def _create_simulated_card_connection() -> Any:
    from SIMCARD.connection import SimulatedCardConnection

    connection = SimulatedCardConnection()
    connection.connect()
    return connection


@dataclass(slots=True)
class BackendCardChannel:
    reader_index: int = 0
    reader_name: str = ""
    _backend_name: str = field(default="", init=False, repr=False)
    _channel: Any = field(default=None, init=False, repr=False)
    _reader_label: str = field(default="", init=False, repr=False)

    @property
    def backend_name(self) -> str:
        if len(self._backend_name) > 0:
            return self._backend_name
        if is_simulated_card_backend():
            return "sim"
        return "reader"

    @property
    def reader_label(self) -> str:
        return self._reader_label

    def connect(self) -> None:
        """Open the WebSocket connection to the HIL-Bridge relay server."""
        backend_name = self.backend_name
        if backend_name == "sim":
            connection = _create_simulated_card_connection()
            self._channel = SimulatedModemCardChannel(connection)
            self._backend_name = "sim"
            self._reader_label = describe_card_backend()
            return

        channel = PcscCardChannel(reader_index=self.reader_index, reader_name=self.reader_name)
        channel.connect()
        self._channel = channel
        self._backend_name = "reader"
        self._reader_label = str(channel.reader_label or "").strip() or "PC/SC reader"

    def reconnect(self) -> None:
        """Close and re-open the WebSocket connection."""
        channel = self._require_channel()
        if self.backend_name == "reader" and hasattr(channel, "reconnect"):
            channel.reconnect()
            self._reader_label = str(channel.reader_label or "").strip() or "PC/SC reader"
            return
        self.disconnect()
        self.connect()

    def disconnect(self) -> None:
        """Close the WebSocket connection."""
        channel = self._channel
        self._channel = None
        if channel is None:
            return
        try:
            channel.disconnect()
        except (OSError, RuntimeError):
            pass

    def get_atr(self) -> bytes:
        channel = self._require_channel()
        if hasattr(channel, "get_atr"):
            return bytes(channel.get_atr())
        return bytes(channel.getATR())

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        channel = self._require_channel()
        response_data, sw1, sw2 = channel.transmit(bytes(apdu))
        return bytes(response_data), int(sw1), int(sw2)

    def queue_modem_refresh(self, mode: str | int, *, source: str = "") -> dict[str, Any]:
        channel = self._require_channel()
        queue_method = getattr(channel, "queue_refresh", None)
        if callable(queue_method) is False:
            raise PcscBridgeError("Configured card backend does not support simulator REFRESH queueing.")
        return dict(queue_method(mode, source=source))

    def proactive_status_payload(self) -> dict[str, Any]:
        channel = self._require_channel()
        status_method = getattr(channel, "proactive_status_payload", None)
        if callable(status_method) is False:
            return {}
        return dict(status_method())

    def _require_channel(self) -> Any:
        if self._channel is None:
            raise PcscBridgeError("Configured card backend is not connected.")
        return self._channel


@dataclass(slots=True)
class BridgeConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 9997
    advertise_host: str = "127.0.0.1"
    apdu_relay_host: str = "127.0.0.1"
    apdu_relay_port: int = 0
    apdu_relay_enabled: bool = True
    reader_index: int = 0
    reader_name: str = ""
    client_id: int = 0
    client_slot: int = 0
    bank_id: int = 1
    bank_slot: int = 0
    bridge_name: str = "yggdrasim-hil-bridge"
    bridge_software: str = "YggdraSIM HIL bridge"
    bridge_version: str = "0.1"
    gsmtap_host: str = "127.0.0.1"
    gsmtap_port: int = 4729
    gsmtap_enabled: bool = True
    gsmtap_compat_mode: str = GSMTAP_COMPAT_NATIVE
    gsmtap_capture_path: str = ""
    gsmtap_capture_mirror_fifo_path: str = ""


@dataclass(slots=True)
class ConnectionContext:
    sock: socket.socket
    address: tuple[str, int]
    parser: IpaFrameParser = field(default_factory=IpaFrameParser)
    send_buffer: bytearray = field(default_factory=bytearray)
    role: ConnectionRole | None = None
    closed: bool = False

    @property
    def label(self) -> str:
        if self.role is None:
            return f"pending@{self.address[0]}:{self.address[1]}"
        return f"{self.role.value}@{self.address[0]}:{self.address[1]}"


@dataclass(slots=True)
class BridgeSession:
    config: BridgeConfig
    card: BackendCardChannel
    gsmtap: GsmtapTap
    control: ConnectionContext | None = None
    bankd: ConnectionContext | None = None
    control_stage: str = "idle"
    atr_sent: bool = False
    atr_bytes: bytes = b""
    next_tag: int = 1
    proactive: ProactiveRefreshBroker = field(default_factory=ProactiveRefreshBroker)
    client_slot: dict[str, Any] = field(init=False)
    bank_slot: dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        self.client_slot = build_client_slot(self.config.client_id, self.config.client_slot)
        self.bank_slot = {
            "bankId": int(self.config.bank_id),
            "slotNr": int(self.config.bank_slot),
        }

    def allocate_tag(self) -> int:
        tag = self.next_tag
        self.next_tag += 1
        return tag

    def reset_runtime_state(self) -> None:
        self.control = None
        self.bankd = None
        self.control_stage = "idle"
        self.atr_sent = False

    def server_identity(self) -> dict[str, Any]:
        """Return the server identity string (URL + session token) for logging purposes."""
        return build_component_identity(
            COMPONENT_REMSIM_SERVER,
            name=self.config.bridge_name,
            software=self.config.bridge_software,
            sw_version=self.config.bridge_version,
        )

    def bankd_identity(self) -> dict[str, Any]:
        """Return the RSPRO ComponentIdentity dict for the bank-daemon role."""
        return build_component_identity(
            COMPONENT_REMSIM_BANKD,
            name=f"{self.config.bridge_name}-bankd",
            software=self.config.bridge_software,
            sw_version=self.config.bridge_version,
        )


class HilBridgeServer:
    def __init__(self, config: BridgeConfig) -> None:
        self._config = config
        load_rspro_codec()
        self._card_lock = threading.RLock()

        self._selector = selectors.DefaultSelector()
        self._listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_socket.bind((config.listen_host, config.listen_port))
        self._listen_socket.listen(8)
        self._listen_socket.setblocking(False)
        self._selector.register(self._listen_socket, selectors.EVENT_READ, None)

        self._card = BackendCardChannel(reader_index=config.reader_index, reader_name=config.reader_name)
        self._card.connect()

        self._gsmtap = GsmtapTap(
            host=config.gsmtap_host,
            port=config.gsmtap_port,
            enabled=config.gsmtap_enabled,
            compat_mode=config.gsmtap_compat_mode,
            capture_path=config.gsmtap_capture_path,
            capture_mirror_fifo_path=config.gsmtap_capture_mirror_fifo_path,
        )
        self._session = BridgeSession(config=config, card=self._card, gsmtap=self._gsmtap)
        self._refresh_card(reconnect=False)
        self._apdu_relay = HilBridgeApduRelayService(
            ApduRelayConfig(
                host=config.apdu_relay_host,
                port=config.apdu_relay_port,
                enabled=config.apdu_relay_enabled,
            ),
            exchange_callback=self._handle_relay_apdu,
            status_callback=self._build_relay_status_payload,
            modem_refresh_callback=self._handle_relay_modem_refresh,
        )
        self._apdu_relay.start()
        self._publish_card_relay_marker()

        LOGGER.info(
            "Listening on %s:%d and advertising bankd at %s:%d",
            config.listen_host,
            config.listen_port,
            config.advertise_host,
            config.listen_port,
        )
        if config.apdu_relay_enabled:
            LOGGER.info("Card relay available at %s", self._apdu_relay.apdu_url)

    def serve_forever(self, *, stop_event: threading.Event | None = None) -> None:
        """Accept connections and route RSPRO messages until the stop event fires."""
        while True:
            if stop_event is not None:
                if stop_event.is_set():
                    return
            for key, mask in self._selector.select(timeout=1.0):
                if key.fileobj is self._listen_socket:
                    self._accept_connection()
                    continue

                context = key.data
                if isinstance(context, ConnectionContext) is False or context.closed:
                    continue
                self._service_connection(context, mask)

    def close(self) -> None:
        """Signal the router to stop and close all managed connections."""
        self._remove_card_relay_marker()
        self._apdu_relay.stop()
        self._reset_session("server shutdown", refresh_card=False)
        try:
            self._selector.unregister(self._listen_socket)
        except (KeyError, ValueError, OSError):
            pass
        try:
            self._listen_socket.close()
        except OSError:
            pass
        self._selector.close()
        self._gsmtap.close()
        self._card.disconnect()

    def _accept_connection(self) -> None:
        client_socket, address = self._listen_socket.accept()
        client_socket.setblocking(False)
        context = ConnectionContext(sock=client_socket, address=address)
        self._selector.register(client_socket, selectors.EVENT_READ, context)
        LOGGER.info("Accepted TCP connection from %s:%d", address[0], address[1])

    def _service_connection(self, context: ConnectionContext, mask: int) -> None:
        if mask & selectors.EVENT_READ:
            self._read_from_connection(context)
        if context.closed:
            return
        if mask & selectors.EVENT_WRITE:
            self._flush_connection(context)

    def _read_from_connection(self, context: ConnectionContext) -> None:
        try:
            payload = context.sock.recv(65535)
        except BlockingIOError:
            return
        except OSError as exc:
            self._handle_connection_loss(context, f"socket read failed: {exc}")
            return

        if len(payload) == 0:
            self._handle_connection_loss(context, "peer closed socket")
            return

        try:
            frames = context.parser.feed(payload)
        except ValueError as exc:
            self._handle_connection_loss(context, f"IPA parser error: {exc}")
            return

        for frame in frames:
            if context.closed:
                break
            self._handle_ipa_frame(context, frame)

    def _flush_connection(self, context: ConnectionContext) -> None:
        if len(context.send_buffer) == 0:
            self._update_selector_interest(context)
            return

        try:
            sent = context.sock.send(context.send_buffer)
        except BlockingIOError:
            return
        except OSError as exc:
            self._handle_connection_loss(context, f"socket write failed: {exc}")
            return

        if sent <= 0:
            self._handle_connection_loss(context, "socket write returned zero bytes")
            return

        del context.send_buffer[:sent]
        self._update_selector_interest(context)

    def _update_selector_interest(self, context: ConnectionContext) -> None:
        if context.closed:
            return
        events = selectors.EVENT_READ
        if len(context.send_buffer) > 0:
            events |= selectors.EVENT_WRITE
        self._selector.modify(context.sock, events, context)

    def _handle_ipa_frame(self, context: ConnectionContext, frame: IpaFrame) -> None:
        if frame.proto == IPA_PROTO_CCM:
            self._handle_ccm_frame(context, frame)
            return

        if frame.proto != IPA_PROTO_OSMO or frame.ext != IPA_EXT_RSPRO:
            self._handle_connection_loss(context, f"unsupported IPA frame proto={frame.proto} ext={frame.ext}")
            return

        try:
            pdu = decode_rspro_pdu(frame.payload)
        except Exception as exc:
            self._handle_connection_loss(context, f"RSPRO decode failed: {exc}")
            return

        self._handle_rspro_pdu(context, pdu)

    def _handle_ccm_frame(self, context: ConnectionContext, frame: IpaFrame) -> None:
        if frame.ext == IPA_MSGT_PING:
            LOGGER.debug("Rx IPA PING from %s", context.label)
            self._queue_raw_frame(context, build_ipa_pong())
            return

        if frame.ext == IPA_MSGT_PONG:
            LOGGER.debug("Rx IPA PONG from %s", context.label)
            return

        LOGGER.debug("Ignoring unsupported IPA CCM message type 0x%02x from %s", frame.ext, context.label)

    def _handle_rspro_pdu(self, context: ConnectionContext, pdu: dict[str, Any]) -> None:
        message_name = get_pdu_message_name(pdu)
        LOGGER.debug("Rx %s on %s", message_name, context.label)

        if context.role is None:
            self._classify_connection(context, message_name)
            if context.closed:
                return

        if context.role == ConnectionRole.CONTROL:
            self._handle_control_pdu(context, pdu)
            return
        if context.role == ConnectionRole.BANKD:
            self._handle_bankd_pdu(context, pdu)
            return

        self._handle_connection_loss(context, "connection role could not be determined")

    def _classify_connection(self, context: ConnectionContext, message_name: str) -> None:
        if message_name != "connectClientReq":
            self._handle_connection_loss(context, f"first PDU was not connectClientReq: {message_name}")
            return

        if self._session.control is None:
            context.role = ConnectionRole.CONTROL
            self._session.control = context
            LOGGER.info("Assigned %s as control connection", context.label)
            self._publish_card_relay_marker()
            return

        if self._session.bankd is None:
            context.role = ConnectionRole.BANKD
            self._session.bankd = context
            LOGGER.info("Assigned %s as bankd connection", context.label)
            self._publish_card_relay_marker()
            return

        self._handle_connection_loss(context, "unexpected third RSPRO connection")

    def _handle_control_pdu(self, context: ConnectionContext, pdu: dict[str, Any]) -> None:
        message_name = get_pdu_message_name(pdu)

        if message_name == "connectClientReq":
            self._queue_rspro_pdu(
                context,
                build_connect_client_res(
                    tag=get_pdu_tag(pdu),
                    component_identity=self._session.server_identity(),
                ),
            )
            self._queue_rspro_pdu(
                context,
                build_config_client_id_req(
                    tag=self._session.allocate_tag(),
                    client_slot=self._session.client_slot,
                ),
            )
            self._session.control_stage = "await_config_id_res"
            return

        if message_name == "configClientIdRes":
            body = get_pdu_message_body(pdu)
            result = str(body.get("result", ""))
            if result != "ok":
                self._reset_session(f"configClientIdRes rejected: {result}")
                return
            self._queue_rspro_pdu(
                context,
                build_config_client_bank_req(
                    tag=self._session.allocate_tag(),
                    bank_slot=self._session.bank_slot,
                    bank_host=self._config.advertise_host,
                    bank_port=self._config.listen_port,
                ),
            )
            self._session.control_stage = "await_config_bank_res"
            return

        if message_name == "configClientBankRes":
            body = get_pdu_message_body(pdu)
            result = str(body.get("result", ""))
            if result != "ok":
                self._reset_session(f"configClientBankRes rejected: {result}")
                return
            self._session.control_stage = "configured"
            LOGGER.info("Control connection configured; waiting for bankd connect")
            return

        if message_name == "resetStateReq":
            self._queue_rspro_pdu(
                context,
                build_reset_state_res(tag=get_pdu_tag(pdu)),
            )
            self._close_bankd_side("peer requested resetState on control channel")
            return

        LOGGER.warning("Ignoring unsupported control PDU %s", message_name)

    def _handle_bankd_pdu(self, context: ConnectionContext, pdu: dict[str, Any]) -> None:
        message_name = get_pdu_message_name(pdu)

        if message_name == "connectClientReq":
            self._queue_rspro_pdu(
                context,
                build_connect_client_res(
                    tag=get_pdu_tag(pdu),
                    component_identity=self._session.bankd_identity(),
                ),
            )
            return

        if message_name == "clientSlotStatusInd":
            if self._session.atr_sent is False:
                self._queue_rspro_pdu(
                    context,
                    build_set_atr_req(
                        tag=self._session.allocate_tag(),
                        client_slot=self._session.client_slot,
                        atr=self._session.atr_bytes,
                    ),
                )
                self._session.gsmtap.send_atr(self._session.atr_bytes)
                self._session.atr_sent = True
                LOGGER.info("Sent ATR %s", self._session.atr_bytes.hex().upper())
            return

        if message_name == "setAtrRes":
            body = get_pdu_message_body(pdu)
            result = str(body.get("result", ""))
            if result != "ok":
                self._reset_session(f"setAtrRes rejected: {result}")
            return

        if message_name == "tpduModemToCard":
            try:
                self._handle_apdu_exchange(context, pdu)
            except PcscBridgeError as exc:
                self._reset_session(f"PC/SC bridge failure: {exc}")
            except Exception as exc:
                self._reset_session(f"APDU relay failure: {exc}")
            return

        if message_name == "resetStateReq":
            self._queue_rspro_pdu(
                context,
                build_reset_state_res(tag=get_pdu_tag(pdu)),
            )
            self._session.atr_sent = False
            return

        LOGGER.warning("Ignoring unsupported bankd PDU %s", message_name)

    def _handle_apdu_exchange(self, context: ConnectionContext, pdu: dict[str, Any]) -> None:
        body = get_pdu_message_body(pdu)
        request_data = ensure_bytes(body.get("data", b""))
        if len(request_data) == 0:
            raise PcscBridgeError("Received empty tpduModemToCard payload.")

        LOGGER.info("Modem -> bridge APDU %s", request_data.hex().upper())

        with self._card_lock:
            proactive_decision = None
            if self._card.backend_name != "sim":
                proactive_decision = self._session.proactive.handle_apdu(request_data)
            if proactive_decision is None:
                response_data, sw1, sw2 = self._card.transmit(request_data)
                full_response = response_data + bytes((sw1, sw2))
            else:
                full_response = proactive_decision.response

        if proactive_decision is None:
            LOGGER.info("Card -> modem APDU %s", full_response.hex().upper())
        else:
            LOGGER.info(
                "Bridge -> modem proactive %s (%s, %d bytes)",
                proactive_decision.action,
                proactive_decision.command.mode_name,
                len(full_response),
            )
        self._session.gsmtap.mirror_exchange(request_data, full_response)

        reply_bank_slot = body.get("toBankSlot", self._session.bank_slot)
        reply_client_slot = body.get("fromClientSlot", self._session.client_slot)
        self._queue_rspro_pdu(
            context,
            build_tpdu_card_to_modem(
                tag=get_pdu_tag(pdu),
                bank_slot=reply_bank_slot,
                client_slot=reply_client_slot,
                data=full_response,
            ),
        )

    def _handle_relay_apdu(self, apdu: bytes, *, session_id: str = "") -> tuple[bytes, int, int]:
        if len(apdu) == 0:
            raise PcscBridgeError("Received empty relay APDU payload.")

        if len(session_id) > 0:
            LOGGER.info("Relay[%s] -> card APDU %s", session_id, apdu.hex().upper())
        else:
            LOGGER.info("Relay -> card APDU %s", apdu.hex().upper())

        with self._card_lock:
            response_data, sw1, sw2 = self._card.transmit(apdu)

        full_response = response_data + bytes((sw1, sw2))
        if len(session_id) > 0:
            LOGGER.info("Card -> relay[%s] APDU %s", session_id, full_response.hex().upper())
        else:
            LOGGER.info("Card -> relay APDU %s", full_response.hex().upper())
        return response_data, sw1, sw2

    def _handle_relay_modem_refresh(self, mode: str, *, session_id: str = "") -> dict[str, Any]:
        with self._card_lock:
            if self._card.backend_name == "sim":
                payload = self._card.queue_modem_refresh(mode, source=session_id)
            else:
                payload = self._session.proactive.queue_refresh(mode, source=session_id)
        LOGGER.info(
            "Queued modem REFRESH mode=%s qualifier=%s pending=%s",
            payload.get("mode", ""),
            payload.get("qualifier", ""),
            payload.get("pendingCount", 0),
        )
        payload = dict(payload)
        payload["modemRefreshUrl"] = self._apdu_relay.modem_refresh_url
        return payload

    def _build_relay_status_payload(self) -> dict[str, Any]:
        payload = {
            "status": "ok",
            "url": self._apdu_relay.apdu_url,
            "apduUrl": self._apdu_relay.apdu_url,
            "statusUrl": self._apdu_relay.status_url,
            "modemRefreshUrl": self._apdu_relay.modem_refresh_url,
            "cardBackend": self._card.backend_name,
            "reader": self._card.reader_label,
            "atr": self._session.atr_bytes.hex().upper(),
            "controlConnected": self._session.control is not None and self._session.control.closed is False,
            "bankdConnected": self._session.bankd is not None and self._session.bankd.closed is False,
            "bridgeHost": self._config.listen_host,
            "bridgePort": self._config.listen_port,
        }
        if self._card.backend_name == "sim":
            payload.update(self._card.proactive_status_payload())
        else:
            payload.update(self._session.proactive.status_payload())
        return payload

    def _card_relay_marker_path(self) -> str:
        ensure_runtime_dir("state")
        return runtime_path("state", CARD_RELAY_MARKER_FILENAME)

    def _publish_card_relay_marker(self) -> None:
        if self._config.apdu_relay_enabled is False:
            return

        marker_payload = self._build_relay_status_payload()
        marker_payload["pid"] = os.getpid()
        marker_path = self._card_relay_marker_path()
        with open(marker_path, "w", encoding="utf-8") as handle:
            json.dump(marker_payload, handle, indent=2, sort_keys=True)
            handle.write("\n")

    def _remove_card_relay_marker(self) -> None:
        marker_path = self._card_relay_marker_path()
        if os.path.isfile(marker_path) is False:
            return

        try:
            with open(marker_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            payload = {}

        if isinstance(payload, dict):
            marker_pid = int(payload.get("pid", 0) or 0)
            if marker_pid not in (0, os.getpid()):
                return

        try:
            os.remove(marker_path)
        except OSError:
            pass

    def _queue_rspro_pdu(self, context: ConnectionContext, pdu: dict[str, Any]) -> None:
        message_name = get_pdu_message_name(pdu)
        encoded = encode_rspro_pdu(pdu)
        frame = build_ipa_frame(IPA_PROTO_OSMO, encoded, IPA_EXT_RSPRO)
        self._queue_raw_frame(context, frame)
        LOGGER.debug("Tx %s on %s", message_name, context.label)

    def _queue_raw_frame(self, context: ConnectionContext, frame: bytes) -> None:
        context.send_buffer.extend(frame)
        self._update_selector_interest(context)

    def _handle_connection_loss(self, context: ConnectionContext, reason: str) -> None:
        LOGGER.warning("Closing %s: %s", context.label, reason)
        if context is self._session.control or context is self._session.bankd:
            self._reset_session(reason)
            return
        self._close_socket(context)

    def _close_bankd_side(self, reason: str) -> None:
        LOGGER.warning("Closing bankd side: %s", reason)
        bankd = self._session.bankd
        self._session.bankd = None
        self._session.atr_sent = False
        if bankd is not None:
            self._close_socket(bankd)
        self._publish_card_relay_marker()

    def _reset_session(self, reason: str, *, refresh_card: bool = True) -> None:
        LOGGER.warning("Resetting bridge session: %s", reason)
        control = self._session.control
        bankd = self._session.bankd
        self._session.reset_runtime_state()
        if control is not None:
            self._close_socket(control)
        if bankd is not None and bankd is not control:
            self._close_socket(bankd)
        if refresh_card:
            self._refresh_card(reconnect=True)

    def _close_socket(self, context: ConnectionContext) -> None:
        if context.closed:
            return
        context.closed = True
        try:
            self._selector.unregister(context.sock)
        except (KeyError, ValueError, OSError):
            pass
        try:
            context.sock.close()
        except OSError:
            pass

    def _refresh_card(self, *, reconnect: bool) -> None:
        with self._card_lock:
            if reconnect:
                self._card.reconnect()
            self._session.atr_bytes = self._card.get_atr()
        LOGGER.info(
            "Reader %s ATR %s",
            self._card.reader_label,
            self._session.atr_bytes.hex().upper(),
        )
        if hasattr(self, "_apdu_relay"):
            self._publish_card_relay_marker()
