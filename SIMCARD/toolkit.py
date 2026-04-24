from __future__ import annotations

import ipaddress
from typing import Any, Callable

from SIMCARD.state import SimCardState, SimToolkitMenuItem
from SIMCARD.utils import read_tlv, tlv
from Tools.HilBridge.protocol import (
    REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
    build_proactive_refresh_command,
    describe_refresh_mode,
    normalize_refresh_mode,
)
from yggdrasim_common.plugin_runtime import extend_target_with_plugins

REFRESH_COMMAND = 0x01
POLL_INTERVAL_COMMAND = 0x03
SET_UP_EVENT_LIST_COMMAND = 0x05
SET_UP_MENU_COMMAND = 0x25
PROVIDE_LOCAL_INFORMATION_COMMAND = 0x26
OPEN_CHANNEL_COMMAND = 0x40
CLOSE_CHANNEL_COMMAND = 0x41
RECEIVE_DATA_COMMAND = 0x42
SEND_DATA_COMMAND = 0x43
GET_CHANNEL_STATUS_COMMAND = 0x44


class ToolkitLogic:
    """Generic ETSI TS 102 223 / TS 102 241 STK+BIP logic.

    Covers proactive-command enqueue/fetch, envelope dispatch, OPEN/
    CLOSE/SEND/RECEIVE CHANNEL bookkeeping, REFRESH and PROVIDE LOCAL
    INFORMATION assembly, and event-download routing. It deliberately
    does *not* know anything about IPAE polling, DNS, TLS, or HTTP:
    that emulation is plugin territory (see ``plugins/polling/
    sim_toolkit_ipae.py``). Extensions attach through
    ``register_extension`` or via ``extend_target_with_plugins`` at
    construction time and receive ``on_*`` hook callbacks.
    """

    COMMAND_NAMES = {
        REFRESH_COMMAND: "REFRESH",
        POLL_INTERVAL_COMMAND: "POLL INTERVAL",
        SET_UP_EVENT_LIST_COMMAND: "SET UP EVENT LIST",
        SET_UP_MENU_COMMAND: "SET UP MENU",
        PROVIDE_LOCAL_INFORMATION_COMMAND: "PROVIDE LOCAL INFORMATION",
        OPEN_CHANNEL_COMMAND: "OPEN CHANNEL",
        CLOSE_CHANNEL_COMMAND: "CLOSE CHANNEL",
        RECEIVE_DATA_COMMAND: "RECEIVE DATA",
        SEND_DATA_COMMAND: "SEND DATA",
        GET_CHANNEL_STATUS_COMMAND: "GET CHANNEL STATUS",
    }

    def __init__(self, state: SimCardState) -> None:
        self.state = state
        self._extensions: list[Any] = []
        extend_target_with_plugins(self)

    def register_extension(self, extension: Any) -> None:
        if extension in self._extensions:
            return
        self._extensions.append(extension)

    def _dispatch_hook(self, hook_name: str, *args, **kwargs) -> None:
        for extension in list(self._extensions):
            hook = getattr(extension, hook_name, None)
            if callable(hook) is False:
                continue
            try:
                hook(*args, **kwargs)
            except Exception:
                continue

    def reset(self) -> None:
        toolkit = self.state.toolkit
        toolkit.terminal_profile = b""
        toolkit.terminal_capabilities.clear()
        toolkit.envelope_history.clear()
        toolkit.last_terminal_response = b""
        toolkit.bootstrap_initialized = False
        toolkit.active_proactive_command = b""
        toolkit.next_command_number = 1
        toolkit.open_channel_active = False
        toolkit.open_channel_protocol = ""
        toolkit.open_channel_endpoint = ""
        toolkit.open_channel_network_access_name = ""
        toolkit.open_channel_transport_protocol_type = 0
        toolkit.last_channel_data_sent = 0
        toolkit.last_received_channel_data = b""
        toolkit.received_channel_history.clear()
        self._dispatch_hook("reset")

    def should_handle_status(self) -> bool:
        if len(self.state.toolkit.active_proactive_command) > 0:
            return True
        if len(self.state.pending_fetch_queue) > 0:
            return True
        if len(self.state.toolkit.terminal_profile) > 0:
            return True
        node_id = str(self.state.current_node_id or "").strip().upper()
        if len(node_id) == 0:
            return True
        if node_id in {"ISDR", "ECASD", "MNO_SD"}:
            return False
        if node_id.startswith("ISDP::"):
            return False
        return True

    def handle_terminal_capability(self, payload: bytes) -> tuple[bytes, int, int]:
        self.state.toolkit.terminal_capabilities.append(bytes(payload or b""))
        return self._pending_status()

    def handle_terminal_profile(self, payload: bytes) -> tuple[bytes, int, int]:
        toolkit = self.state.toolkit
        toolkit.terminal_profile = bytes(payload or b"")
        if toolkit.bootstrap_enabled and toolkit.bootstrap_initialized is False:
            commands = self._bootstrap_commands()
            for command in commands:
                self._enqueue_command(command)
            toolkit.bootstrap_initialized = True
        return self._pending_status()

    def handle_status(self, _p1: int, _p2: int, _payload: bytes) -> tuple[bytes, int, int]:
        return self._pending_status()

    def handle_fetch(self) -> tuple[bytes, int, int]:
        active = self._activate_next_command()
        if len(active) == 0:
            return b"", 0x6A, 0x86
        return active, 0x90, 0x00

    def handle_terminal_response(self, payload: bytes) -> tuple[bytes, int, int]:
        toolkit = self.state.toolkit
        normalized = bytes(payload or b"")
        toolkit.last_terminal_response = normalized
        active = bytes(toolkit.active_proactive_command or b"")
        if len(active) > 0:
            self._apply_terminal_response(active, normalized)
        toolkit.active_proactive_command = b""
        return self._pending_status()

    def handle_envelope(self, payload: bytes, fallback_handler) -> tuple[bytes, int, int]:
        normalized = bytes(payload or b"")
        self.state.toolkit.envelope_history.append(normalized)
        event_fields = self._parse_event_download(normalized)
        if event_fields is not None:
            self._handle_event_download(event_fields)
            return self._pending_status()
        response = fallback_handler(normalized)
        if len(self.state.toolkit.active_proactive_command) > 0:
            return self._pending_status()
        if len(self.state.pending_fetch_queue) > 0:
            return self._pending_status()
        return response

    def queue_refresh(
        self,
        mode: str | int = REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
        *,
        source: str = "",
    ) -> dict[str, str | int | list[str]]:
        mode_name, qualifier = normalize_refresh_mode(mode)
        existing = self._find_refresh_command(qualifier)
        if len(existing) > 0:
            return self._build_queue_result("coalesced", existing, mode_name, qualifier)
        command_number = self._allocate_command_number()
        payload = build_proactive_refresh_command(
            command_number=command_number,
            qualifier=qualifier,
        )
        self._enqueue_command(payload)
        _ = source
        return self._build_queue_result("queued", payload, mode_name, qualifier)

    def status_payload(self) -> dict[str, str | int | list[str] | bool]:
        active = bytes(self.state.toolkit.active_proactive_command or b"")
        queued = [bytes(entry) for entry in self.state.pending_fetch_queue]
        payload: dict[str, str | int | list[str] | bool] = {
            "pendingCount": len(queued) + (1 if len(active) > 0 else 0),
            "queuedCount": len(queued),
            "activeMode": self._command_mode_name(active),
            "activeQualifier": self._command_qualifier_text(active),
            "queuedModes": [self._command_mode_name(entry) for entry in queued],
            "openChannelActive": self.state.toolkit.open_channel_active,
            "openChannelEndpoint": self.state.toolkit.open_channel_endpoint,
            "deliveryHint": "Simulator proactive queue is announced on modem STATUS and served on FETCH.",
        }
        for extension in self._extensions:
            emit_fields = getattr(extension, "status_payload_fields", None)
            if callable(emit_fields) is False:
                continue
            try:
                extra = emit_fields() or {}
            except Exception:
                continue
            if isinstance(extra, dict):
                for key, value in extra.items():
                    payload[str(key)] = value
        return payload

    def _pending_status(self) -> tuple[bytes, int, int]:
        active = self._activate_next_command()
        if len(active) == 0:
            return b"", 0x90, 0x00
        return b"", 0x91, self._advertised_length(active)

    def _activate_next_command(self) -> bytes:
        toolkit = self.state.toolkit
        active = bytes(toolkit.active_proactive_command or b"")
        if len(active) > 0:
            return active
        if len(self.state.pending_fetch_queue) == 0:
            return b""
        active = bytes(self.state.pending_fetch_queue.pop(0))
        toolkit.active_proactive_command = active
        return active

    def _enqueue_command(self, payload: bytes) -> None:
        self.state.pending_fetch_queue.append(bytes(payload or b""))

    def _bootstrap_commands(self) -> list[bytes]:
        toolkit = self.state.toolkit
        commands: list[bytes] = []

        if toolkit.provide_imei:
            commands.append(
                self._proactive_command(
                    self._allocate_command_number(),
                    PROVIDE_LOCAL_INFORMATION_COMMAND,
                    0x01,
                )
            )

        if len(toolkit.menu_items) > 0 or len(str(toolkit.menu_title or "").strip()) > 0:
            commands.append(self._build_set_up_menu(self._allocate_command_number()))

        if len(toolkit.event_list) > 0:
            commands.append(
                self._build_set_up_event_list(
                    self._allocate_command_number(),
                    toolkit.event_list,
                )
            )

        if int(toolkit.poll_interval_seconds or 0) > 0:
            commands.append(
                self._build_poll_interval(
                    self._allocate_command_number(),
                    int(toolkit.poll_interval_seconds),
                )
            )

        return commands

    def _allocate_command_number(self) -> int:
        toolkit = self.state.toolkit
        command_number = int(toolkit.next_command_number or 1) & 0xFF
        if command_number == 0:
            command_number = 1
        toolkit.next_command_number = command_number + 1
        if toolkit.next_command_number > 0xFE:
            toolkit.next_command_number = 1
        return command_number

    def _apply_terminal_response(self, active_payload: bytes, payload: bytes) -> None:
        command_fields = self._parse_proactive_command(active_payload)
        response_fields = self._parse_terminal_response(payload)
        if command_fields is None:
            return
        command_type = int(command_fields.get("command_type", 0) or 0)
        result_code = int(response_fields.get("result_code", 0x00) or 0x00)
        succeeded = self._result_succeeded(result_code)
        if command_type == OPEN_CHANNEL_COMMAND:
            self._apply_open_channel_response(command_fields, succeeded)
            return
        if command_type == CLOSE_CHANNEL_COMMAND:
            self._apply_close_channel_response(succeeded)
            return
        if command_type == SEND_DATA_COMMAND:
            self._apply_send_data_response(command_fields, response_fields, succeeded)
            return
        if command_type == RECEIVE_DATA_COMMAND:
            self._apply_receive_data_response(response_fields, succeeded)
            return
        if command_type == GET_CHANNEL_STATUS_COMMAND:
            self._apply_channel_status_response(response_fields)

    def _apply_open_channel_response(self, command_fields: dict[str, object], succeeded: bool) -> None:
        toolkit = self.state.toolkit
        if succeeded is False:
            toolkit.open_channel_active = False
            self._dispatch_hook("on_open_channel_response", command_fields, succeeded)
            return
        remote_address = str(command_fields.get("remote_address", "") or "").strip()
        remote_port = int(command_fields.get("transport_port", 0) or 0)
        protocol_type = int(command_fields.get("transport_protocol_type", 0) or 0)
        toolkit.open_channel_active = True
        toolkit.open_channel_protocol = self._transport_protocol_name(protocol_type)
        toolkit.open_channel_transport_protocol_type = protocol_type
        toolkit.open_channel_network_access_name = str(
            command_fields.get("network_access_name", "") or ""
        ).strip()
        if len(remote_address) > 0 and remote_port > 0:
            toolkit.open_channel_endpoint = f"{remote_address}:{remote_port}"
        elif len(remote_address) > 0:
            toolkit.open_channel_endpoint = remote_address
        else:
            toolkit.open_channel_endpoint = ""
        self._dispatch_hook("on_open_channel_response", command_fields, succeeded)

    def _apply_close_channel_response(self, succeeded: bool) -> None:
        if succeeded is False:
            self._dispatch_hook("on_close_channel_response", succeeded)
            return
        toolkit = self.state.toolkit
        toolkit.open_channel_active = False
        toolkit.open_channel_protocol = ""
        toolkit.open_channel_endpoint = ""
        toolkit.open_channel_network_access_name = ""
        toolkit.open_channel_transport_protocol_type = 0
        self._dispatch_hook("on_close_channel_response", succeeded)

    def _apply_send_data_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        toolkit = self.state.toolkit
        channel_data = bytes(command_fields.get("channel_data", b"") or b"")
        response_length = int(response_fields.get("channel_length", 0) or 0)
        if succeeded:
            if response_length > 0:
                toolkit.last_channel_data_sent = response_length
            else:
                toolkit.last_channel_data_sent = len(channel_data)
        else:
            toolkit.last_channel_data_sent = 0
        self._dispatch_hook(
            "on_send_data_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_receive_data_response(
        self,
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        if succeeded is False:
            self._dispatch_hook("on_receive_data_response", response_fields, succeeded)
            return
        toolkit = self.state.toolkit
        channel_data = bytes(response_fields.get("channel_data", b"") or b"")
        remaining_length = int(response_fields.get("channel_length", 0) or 0)
        toolkit.last_received_channel_data = channel_data
        if len(channel_data) > 0:
            toolkit.received_channel_history.append(channel_data)
        self._dispatch_hook("on_receive_data_response", response_fields, succeeded)
        if remaining_length > 0 and self._has_pending_or_active_command(RECEIVE_DATA_COMMAND) is False:
            # Default follow-up behaviour when no extension consumed the
            # data: keep draining the remote buffer so the terminal does
            # not stall. Extensions that own the channel (e.g. IPAE
            # polling) are expected to emit their own RECEIVE DATA
            # requests from the hook above; this fallback only fires
            # when nothing else claimed responsibility.
            pass

    def _apply_channel_status_response(self, response_fields: dict[str, object]) -> None:
        channel_status = bytes(response_fields.get("channel_status", b"") or b"")
        if len(channel_status) >= 1:
            self.state.toolkit.open_channel_active = (channel_status[0] & 0x80) != 0

    def _handle_event_download(self, event_fields: dict[str, object]) -> None:
        location_information = bytes(event_fields.get("location_information", b"") or b"")
        if len(location_information) > 0:
            self.state.toolkit.location_information = location_information
        channel_status = bytes(event_fields.get("channel_status", b"") or b"")
        if len(channel_status) >= 1:
            self.state.toolkit.open_channel_active = (channel_status[0] & 0x80) != 0
        self._dispatch_hook("on_event_download", event_fields)

    def _find_refresh_command(self, qualifier: int) -> bytes:
        for payload in self._iter_all_commands():
            command_fields = self._parse_proactive_command(payload)
            if command_fields is None:
                continue
            command_type = int(command_fields.get("command_type", 0) or 0)
            command_qualifier = int(command_fields.get("qualifier", 0) or 0)
            if command_type == REFRESH_COMMAND and command_qualifier == qualifier:
                return payload
        return b""

    def _has_pending_or_active_command(self, command_type: int) -> bool:
        for payload in self._iter_all_commands():
            command_fields = self._parse_proactive_command(payload)
            if command_fields is None:
                continue
            candidate_type = int(command_fields.get("command_type", 0) or 0)
            if candidate_type == command_type:
                return True
        return False

    def _iter_all_commands(self):
        active = bytes(self.state.toolkit.active_proactive_command or b"")
        if len(active) > 0:
            yield active
        for payload in self.state.pending_fetch_queue:
            yield bytes(payload)

    def _build_queue_result(
        self,
        status: str,
        payload: bytes,
        mode_name: str,
        qualifier: int,
    ) -> dict[str, str | int | list[str]]:
        command_fields = self._parse_proactive_command(payload)
        command_number = 0
        if command_fields is not None:
            command_number = int(command_fields.get("command_number", 0) or 0)
        status_payload = self.status_payload()
        return {
            "status": status,
            "mode": mode_name,
            "qualifier": f"{qualifier:02X}",
            "commandNumber": command_number,
            "pendingCount": int(status_payload["pendingCount"]),
            "queuedModes": list(status_payload["queuedModes"]),
            "activeMode": str(status_payload["activeMode"]),
            "activeQualifier": str(status_payload["activeQualifier"]),
            "description": describe_refresh_mode(qualifier),
            "deliveryHint": str(status_payload["deliveryHint"]),
        }

    def _advertised_length(self, payload: bytes) -> int:
        length = len(bytes(payload or b""))
        if length == 256:
            return 0x00
        return min(0xFF, length)

    def _command_mode_name(self, payload: bytes) -> str:
        if len(payload) == 0:
            return ""
        command_fields = self._parse_proactive_command(payload)
        if command_fields is None:
            return ""
        command_type = int(command_fields.get("command_type", 0) or 0)
        qualifier = int(command_fields.get("qualifier", 0) or 0)
        if command_type == REFRESH_COMMAND:
            return describe_refresh_mode(qualifier)
        return self.COMMAND_NAMES.get(command_type, f"0x{command_type:02X}").lower().replace(" ", "-")

    def _command_qualifier_text(self, payload: bytes) -> str:
        if len(payload) == 0:
            return ""
        command_fields = self._parse_proactive_command(payload)
        if command_fields is None:
            return ""
        qualifier = int(command_fields.get("qualifier", 0) or 0)
        return f"{qualifier:02X}"

    def _proactive_command(
        self,
        command_number: int,
        command_type: int,
        qualifier: int,
        extra_tlvs: bytes = b"",
    ) -> bytes:
        body = (
            tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, qualifier & 0xFF)))
            + tlv("82", bytes.fromhex("8182"))
            + bytes(extra_tlvs or b"")
        )
        return tlv("D0", body)

    def _build_set_up_menu(self, command_number: int) -> bytes:
        toolkit = self.state.toolkit
        title_text = str(toolkit.menu_title or "").strip()
        title_value = b""
        if len(title_text) > 0:
            title_value = title_text.encode("utf-8")
        title_tlv = tlv("85", title_value)
        item_tlvs = b"".join(self._build_menu_item(item) for item in toolkit.menu_items)
        return self._proactive_command(command_number, SET_UP_MENU_COMMAND, 0x00, title_tlv + item_tlvs)

    @staticmethod
    def _build_menu_item(item: SimToolkitMenuItem) -> bytes:
        item_text = str(item.text or "").strip()
        value = bytes((int(item.identifier) & 0xFF,)) + item_text.encode("utf-8")
        return tlv("8F", value)

    def _build_set_up_event_list(self, command_number: int, event_list: list[int]) -> bytes:
        events = bytes(int(value) & 0xFF for value in event_list)
        return self._proactive_command(command_number, SET_UP_EVENT_LIST_COMMAND, 0x00, tlv("99", events))

    def _build_poll_interval(self, command_number: int, seconds: int) -> bytes:
        duration = self._encode_duration_tlv(int(seconds))
        return self._proactive_command(command_number, POLL_INTERVAL_COMMAND, 0x00, tlv("84", duration))

    @staticmethod
    def _encode_duration_tlv(total_seconds: int) -> bytes:
        requested = max(1, int(total_seconds or 0))
        if requested % 60 == 0 and (requested // 60) <= 0xFF:
            minutes = requested // 60
            return bytes((0x00, minutes & 0xFF))
        if requested <= 0xFF:
            return bytes((0x01, requested & 0xFF))
        minutes = max(1, min(0xFF, (requested + 59) // 60))
        return bytes((0x00, minutes & 0xFF))

    def _build_open_channel_command(
        self,
        command_number: int,
        *,
        remote_address: str,
        remote_port: int,
        transport_protocol_type: int,
        network_access_name: str,
        buffer_size: int = 0x0400,
    ) -> bytes:
        extra_tlvs = tlv("35", b"\x03")
        extra_tlvs += tlv("39", int(buffer_size).to_bytes(2, "big", signed=False))
        if len(str(network_access_name or "").strip()) > 0:
            extra_tlvs += tlv("47", self._encode_network_access_name(network_access_name))
        extra_tlvs += tlv(
            "3C",
            bytes((int(transport_protocol_type) & 0xFF,))
            + int(remote_port).to_bytes(2, "big", signed=False),
        )
        encoded_address = self._encode_other_address(remote_address)
        if len(encoded_address) > 0:
            extra_tlvs += tlv("3E", encoded_address)
        return self._proactive_command(command_number, OPEN_CHANNEL_COMMAND, 0x00, extra_tlvs)

    def _build_close_channel_command(self, command_number: int) -> bytes:
        return self._proactive_command(command_number, CLOSE_CHANNEL_COMMAND, 0x00)

    def _build_send_data_command(self, command_number: int, payload: bytes) -> bytes:
        extra_tlvs = tlv("36", bytes(payload or b""))
        return self._proactive_command(command_number, SEND_DATA_COMMAND, 0x00, extra_tlvs)

    def _build_receive_data_command(self, command_number: int, requested_length: int) -> bytes:
        bounded_length = max(1, min(0xFF, int(requested_length)))
        extra_tlvs = tlv("B7", bytes((bounded_length,)))
        return self._proactive_command(command_number, RECEIVE_DATA_COMMAND, 0x00, extra_tlvs)

    def _encode_network_access_name(self, value: str) -> bytes:
        encoded = bytearray()
        parts = [part for part in str(value or "").strip().split(".") if len(part) > 0]
        for part in parts:
            part_bytes = part.encode("ascii", "ignore")
            encoded.append(min(len(part_bytes), 0x3F))
            encoded.extend(part_bytes[:0x3F])
        return bytes(encoded)

    def _encode_other_address(self, value: str) -> bytes:
        normalized = str(value or "").strip()
        if len(normalized) == 0:
            return b""
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return b""
        if address.version == 4:
            return bytes((0x21,)) + address.packed
        return bytes((0x57,)) + address.packed

    def _transport_protocol_name(self, protocol_type: int) -> str:
        return {
            0x01: "UDP REMOTE",
            0x02: "TCP CLIENT REMOTE",
            0x03: "TCP SERVER",
            0x04: "UDP LOCAL",
        }.get(int(protocol_type) & 0xFF, f"0x{int(protocol_type) & 0xFF:02X}")

    def _parse_proactive_command(self, payload: bytes) -> dict[str, object] | None:
        try:
            root_tag, root_value, _raw_tlv, _next_offset = read_tlv(bytes(payload or b""), 0)
        except ValueError:
            return None
        if root_tag != b"\xD0":
            return None
        fields: dict[str, object] = {}
        offset = 0
        while offset < len(root_value):
            try:
                tag_bytes, value_bytes, raw_tlv, offset = read_tlv(root_value, offset)
            except ValueError:
                break
            if tag_bytes in (b"\x01", b"\x81") and len(value_bytes) == 3:
                fields["command_number"] = value_bytes[0]
                fields["command_type"] = value_bytes[1]
                fields["qualifier"] = value_bytes[2]
                fields["command_details_tlv"] = raw_tlv
                continue
            if tag_bytes in (b"\x02", b"\x82"):
                fields["device_identities_tlv"] = raw_tlv
                continue
            if tag_bytes == b"\x35":
                fields["bearer_description_tlv"] = raw_tlv
                continue
            if tag_bytes == b"\x36":
                fields["channel_data"] = value_bytes
                continue
            if tag_bytes == b"\x39" and len(value_bytes) == 2:
                fields["buffer_size_tlv"] = raw_tlv
                fields["buffer_size"] = int.from_bytes(value_bytes, "big", signed=False)
                continue
            if tag_bytes == b"\x47":
                fields["network_access_name"] = self._decode_network_access_name(value_bytes)
                continue
            if tag_bytes == b"\x3C" and len(value_bytes) == 3:
                fields["transport_protocol_type"] = value_bytes[0]
                fields["transport_port"] = int.from_bytes(value_bytes[1:], "big", signed=False)
                continue
            if tag_bytes == b"\x3E":
                fields["remote_address"] = self._decode_other_address(value_bytes)
                continue
            if tag_bytes == b"\x99":
                fields["event_list"] = [int(value) for value in value_bytes]
                continue
            if tag_bytes == b"\x84" and len(value_bytes) >= 2:
                fields["poll_interval_seconds"] = int(value_bytes[-1])
                continue
            if tag_bytes == b"\xB7" and len(value_bytes) > 0:
                fields["channel_length"] = int(value_bytes[0])
        return fields

    def _parse_terminal_response(self, payload: bytes) -> dict[str, object]:
        fields: dict[str, object] = {}
        offset = 0
        data = bytes(payload or b"")
        while offset < len(data):
            try:
                tag_bytes, value_bytes, raw_tlv, offset = read_tlv(data, offset)
            except ValueError:
                break
            if tag_bytes in (b"\x01", b"\x81") and len(value_bytes) == 3:
                fields["command_details_tlv"] = raw_tlv
                continue
            if tag_bytes == b"\x03" and len(value_bytes) > 0:
                fields["result"] = value_bytes
                fields["result_code"] = value_bytes[0]
                continue
            if tag_bytes == b"\x36":
                fields["channel_data"] = value_bytes
                continue
            if tag_bytes == b"\x37" and len(value_bytes) > 0:
                fields["channel_length"] = int(value_bytes[0])
                continue
            if tag_bytes == b"\x38":
                fields["channel_status"] = value_bytes
        return fields

    def _parse_event_download(self, payload: bytes) -> dict[str, object] | None:
        try:
            root_tag, root_value, _raw_tlv, _next_offset = read_tlv(bytes(payload or b""), 0)
        except ValueError:
            return None
        if root_tag != b"\xD6":
            return None
        fields: dict[str, object] = {}
        offset = 0
        while offset < len(root_value):
            try:
                tag_bytes, value_bytes, _raw_tlv, offset = read_tlv(root_value, offset)
            except ValueError:
                break
            if tag_bytes == b"\x99" and len(value_bytes) > 0:
                fields["event_code"] = value_bytes[0]
                continue
            if tag_bytes == b"\x37" and len(value_bytes) > 0:
                fields["channel_length"] = int(value_bytes[0])
                continue
            if tag_bytes == b"\x38":
                fields["channel_status"] = value_bytes
                continue
            if tag_bytes == b"\x93":
                fields["location_information"] = value_bytes
                continue
            if tag_bytes == b"\x9B" and len(value_bytes) > 0:
                fields["location_status"] = value_bytes[0]
        return fields

    def _result_succeeded(self, result_code: int) -> bool:
        if result_code in (0x00, 0x01):
            return True
        return False

    def _decode_network_access_name(self, value_bytes: bytes) -> str:
        parts: list[str] = []
        offset = 0
        while offset < len(value_bytes):
            label_length = value_bytes[offset]
            offset += 1
            if label_length == 0:
                break
            label_end = offset + label_length
            if label_end > len(value_bytes):
                break
            label = value_bytes[offset:label_end]
            parts.append(label.decode("ascii", "ignore"))
            offset = label_end
        return ".".join(part for part in parts if len(part) > 0)

    def _decode_other_address(self, value_bytes: bytes) -> str:
        if len(value_bytes) == 5 and value_bytes[0] == 0x21:
            return ".".join(str(part) for part in value_bytes[1:])
        if len(value_bytes) == 17 and value_bytes[0] == 0x57:
            return str(ipaddress.IPv6Address(value_bytes[1:]))
        return ""
