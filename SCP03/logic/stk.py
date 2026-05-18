# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SIM Toolkit logic: proactive command encoding/decoding and TERMINAL RESPONSE handling (ETSI TS 102 223)."""
from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Optional


def _encode_imei_bcd(imei_digits: str) -> bytes:
    """Encode a 15-digit IMEI per ETSI TS 102 223 §8.20.

    The byte layout follows 3GPP TS 24.008 §10.5.1.4 (Mobile Identity):

    - Byte 1 high nibble: first IMEI digit; low nibble = ``0xA``
      (type-of-identity ``010`` for IMEI, parity bit ``1`` for the
      odd 15-digit count).
    - Bytes 2-8: BCD nibble-swapped digit pairs (digits 2-15).

    The output is always 8 bytes.
    """
    digits = "".join(ch for ch in str(imei_digits or "") if ch.isdigit())
    if len(digits) != 15:
        raise ValueError("IMEI must be exactly 15 decimal digits.")
    out = bytearray(8)
    out[0] = ((int(digits[0]) & 0x0F) << 4) | 0x0A
    for index in range(1, 8):
        low_digit = int(digits[2 * index - 1]) & 0x0F
        high_digit = int(digits[2 * index]) & 0x0F
        out[index] = (high_digit << 4) | low_digit
    return bytes(out)


def _encode_location_information_gsm(
    mcc: str,
    mnc: str,
    lac: int,
    cell_id: int,
) -> bytes:
    """Encode a 2G/3G Location Information value per ETSI TS 102 223 §8.19.

    Layout (7 bytes):

    - 3 bytes: MCC + MNC packed BCD per 3GPP TS 24.008 §10.5.1.3.
    - 2 bytes: LAC big-endian (or RAC + LAC for GPRS contexts).
    - 2 bytes: Cell ID big-endian.

    For 2-digit MNCs the high nibble of byte 2 is set to ``0xF``.
    """
    mcc_digits = str(mcc or "").strip()
    mnc_digits = str(mnc or "").strip()
    if len(mcc_digits) != 3 or any(not ch.isdigit() for ch in mcc_digits):
        raise ValueError("MCC must be exactly three decimal digits.")
    if len(mnc_digits) not in (2, 3) or any(not ch.isdigit() for ch in mnc_digits):
        raise ValueError("MNC must be two or three decimal digits.")

    mcc1 = int(mcc_digits[0])
    mcc2 = int(mcc_digits[1])
    mcc3 = int(mcc_digits[2])
    if len(mnc_digits) == 2:
        mnc3 = 0xF
        mnc2 = int(mnc_digits[1])
        mnc1 = int(mnc_digits[0])
    else:
        mnc3 = int(mnc_digits[2])
        mnc2 = int(mnc_digits[1])
        mnc1 = int(mnc_digits[0])

    plmn = bytes(
        [
            (mcc2 << 4) | mcc1,
            (mnc3 << 4) | mcc3,
            (mnc2 << 4) | mnc1,
        ]
    )
    if not 0 <= int(lac) <= 0xFFFF:
        raise ValueError("LAC must fit in two bytes.")
    if not 0 <= int(cell_id) <= 0xFFFF:
        raise ValueError("Cell ID must fit in two bytes.")
    return plmn + int(lac).to_bytes(2, "big") + int(cell_id).to_bytes(2, "big")


@dataclass
class StkState:
    initialized: bool = False
    event_list: list[int] = field(default_factory=list)
    command_history: list[str] = field(default_factory=list)
    flow_events: list[str] = field(default_factory=list)
    generic_ack_history: list[str] = field(default_factory=list)
    trigger_history: list[str] = field(default_factory=list)
    poll_interval_seconds: int = 0
    polling_off: bool = False
    # ETSI TS 102 223 §8.19 GSM Location Information value:
    # MCC=001, MNC=01 (3GPP TS 23.003 §2.2 test PLMN),
    # LAC=0x0001, Cell ID=0x0001. Layout: 3 bytes packed-BCD PLMN +
    # 2 byte LAC + 2 byte Cell ID = 7 bytes.
    location_information: bytes = field(
        default_factory=lambda: _encode_location_information_gsm("001", "01", 0x0001, 0x0001)
    )
    # ETSI TS 102 223 §8.20 IMEI: 8-byte BCD encoding of a 15-digit
    # IMEI. The default is "086543245654321" (Type Allocation Code
    # 086543245 reserved by 3GPP TS 23.003 for test purposes).
    imei: bytes = field(default_factory=lambda: _encode_imei_bcd("086543245654321"))
    last_proactive_command: bytes = b""
    open_channel_active: bool = False
    open_channel_protocol: str = ""
    open_channel_endpoint: str = ""
    pending_channel_queue: list[bytes] = field(default_factory=list)
    pending_channel_data: bytes = b""
    last_channel_data_sent: int = 0
    last_status_word: str = ""


class StkController:
    TERMINAL_PROFILE = bytes.fromhex("8010000015FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00")

    DEVICE_IDENTITIES_TERMINAL_TO_UICC = bytes.fromhex("02028281")
    DEVICE_IDENTITIES_UICC_TO_TERMINAL = bytes.fromhex("82028182")
    SMS_PP_PREFIX = bytes.fromhex("0202828106028001")

    # Event List values per ETSI TS 102 223 §8.25 (table "Event list").
    # Keep the dict literal sparse so future additions are deliberate;
    # missing event codes still fall through to "0xNN" via _stk_event_name.
    EVENT_NAME_MAP = {
        "MT-CALL": 0x00,
        "CALL-CONNECTED": 0x01,
        "CALL-DISCONNECTED": 0x02,
        "LOCATION-STATUS": 0x03,
        "USER-ACTIVITY": 0x04,
        "IDLE-SCREEN": 0x05,
        "CARD-READER-STATUS": 0x06,
        "LANGUAGE-SELECTION": 0x07,
        "BROWSER-TERMINATION": 0x08,
        "DATA-AVAILABLE": 0x09,
        "CHANNEL-STATUS": 0x0A,
        "ACCESS-TECHNOLOGY-CHANGE": 0x0B,
        "DISPLAY-PARAMETERS-CHANGED": 0x0C,
        "LOCAL-CONNECTION": 0x0D,
        "NETWORK-SEARCH-MODE-CHANGE": 0x0E,
        "BROWSING-STATUS": 0x0F,
        "FRAMES-INFORMATION-CHANGE": 0x10,
        "I-WLAN-ACCESS-STATUS-CHANGE": 0x11,
        "NETWORK-REJECTION": 0x12,
        "HCI-CONNECTIVITY": 0x13,
        "ACCESS-TECHNOLOGY-CHANGE-MULTI": 0x14,
        "CSG-CELL-SELECTION": 0x15,
        "CONTACTLESS-STATE-REQUEST": 0x16,
        "IMS-REGISTRATION": 0x17,
        "IMS-INCOMING-DATA": 0x18,
        "PROFILE-CONTAINER": 0x19,
        "USAT-APPLICATION": 0x1A,
        "DATA-CONNECTION-STATUS-CHANGE": 0x1B,
    }

    # Proactive command codes per ETSI TS 102 223 §6.6 (Type of Command).
    # Includes the SET UP MENU (0x25) which the simulator emits during
    # bootstrap, and the broader 0x10..0x16 / 0x20..0x28 / 0x45..0x73
    # ranges so traces are no longer rendered as "UNKNOWN 0x..".
    PROACTIVE_NAME_MAP = {
        0x01: "REFRESH",
        0x02: "MORE TIME",
        0x03: "POLL INTERVAL",
        0x04: "POLLING OFF",
        0x05: "SET UP EVENT LIST",
        0x10: "SET UP CALL",
        0x11: "SEND SS",
        0x12: "SEND USSD",
        0x13: "SEND SHORT MESSAGE",
        0x14: "SEND DTMF",
        0x15: "LAUNCH BROWSER",
        0x16: "GEOGRAPHICAL LOCATION REQUEST",
        0x20: "PLAY TONE",
        0x21: "DISPLAY TEXT",
        0x22: "GET INKEY",
        0x23: "GET INPUT",
        0x24: "SELECT ITEM",
        0x25: "SET UP MENU",
        0x26: "PROVIDE LOCAL INFORMATION",
        0x27: "TIMER MANAGEMENT",
        0x28: "SET UP IDLE MODE TEXT",
        0x30: "PERFORM CARD APDU",
        0x31: "POWER ON CARD",
        0x32: "POWER OFF CARD",
        0x33: "GET READER STATUS",
        0x34: "RUN AT COMMAND",
        0x35: "LANGUAGE NOTIFICATION",
        0x40: "OPEN CHANNEL",
        0x41: "CLOSE CHANNEL",
        0x42: "RECEIVE DATA",
        0x43: "SEND DATA",
        0x44: "GET CHANNEL STATUS",
        0x45: "SERVICE SEARCH",
        0x46: "GET SERVICE INFORMATION",
        0x47: "DECLARE SERVICE",
        0x60: "SET FRAMES",
        0x61: "GET FRAMES STATUS",
        0x70: "RETRIEVE MULTIMEDIA MESSAGE",
        0x71: "SUBMIT MULTIMEDIA MESSAGE",
        0x72: "DISPLAY MULTIMEDIA MESSAGE",
        0x73: "ACTIVATE",
        0x81: "ESTABLISH NETWORK ACCESS",
    }

    def __init__(self, transport, debug: bool = False) -> None:
        self.tp = transport
        self.debug = bool(debug)
        self.state = StkState()

    def set_debug(self, enabled: bool) -> None:
        self.debug = bool(enabled)

    @staticmethod
    def _clean_hex(value: str) -> str:
        return str(value or "").strip().replace(" ", "").upper()

    @staticmethod
    def _encode_der_length(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        if length <= 0xFF:
            return bytes([0x81, length])
        if length <= 0xFFFF:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        raise ValueError("DER length exceeds supported range.")

    @classmethod
    def _wrap_tlv(cls, tag: bytes, value: bytes) -> bytes:
        return bytes(tag) + cls._encode_der_length(len(value)) + bytes(value)

    @staticmethod
    def _read_tlv(data: bytes, offset: int) -> tuple[bytes, bytes, bytes, int]:
        if offset >= len(data):
            raise ValueError("TLV offset out of range.")
        tag_start = offset
        offset += 1
        if data[tag_start] & 0x1F == 0x1F:
            while offset < len(data):
                current = data[offset]
                offset += 1
                if (current & 0x80) == 0:
                    break
            else:
                raise ValueError("Invalid multi-octet TLV tag.")
        tag_bytes = data[tag_start:offset]
        if offset >= len(data):
            raise ValueError("Missing TLV length.")
        length_byte = data[offset]
        offset += 1
        if length_byte & 0x80:
            octet_count = length_byte & 0x7F
            if octet_count == 0 or octet_count > 2 or offset + octet_count > len(data):
                raise ValueError("Invalid TLV length.")
            length_value = 0
            for _ in range(octet_count):
                length_value = (length_value << 8) | data[offset]
                offset += 1
        else:
            length_value = length_byte
        value_end = offset + length_value
        if value_end > len(data):
            raise ValueError("TLV value exceeds input length.")
        raw_tlv = data[tag_start:value_end]
        return tag_bytes, data[offset:value_end], raw_tlv, value_end

    def _record_flow_event(self, text: str) -> None:
        self.state.flow_events.append(str(text or "").strip())

    def _record_status_word(self, sw1: int, sw2: int) -> None:
        self.state.last_status_word = f"{sw1:02X}{sw2:02X}"

    def _ensure_connection(self):
        connection = getattr(self.tp, "connection", None)
        if connection is not None:
            return connection
        connect_method = getattr(self.tp, "connect", None)
        if callable(connect_method):
            if connect_method() is False:
                raise RuntimeError("No card connection available.")
        connection = getattr(self.tp, "connection", None)
        if connection is None:
            raise RuntimeError("No card connection available.")
        return connection

    def _print_apdu_debug(
        self,
        direction: str,
        payload: bytes,
        sw1: Optional[int] = None,
        sw2: Optional[int] = None,
        log_name: str = "",
    ) -> None:
        if self.debug is False:
            return
        title = str(log_name or "").strip()
        if len(title) > 0:
            title = f"{title} "
        if direction == "tx":
            print(f"[STK] {title}> {payload.hex().upper()}")
            return
        if sw1 is None or sw2 is None:
            print(f"[STK] {title}< {payload.hex().upper()}")
            return
        print(f"[STK] {title}< {payload.hex().upper()} {sw1:02X}{sw2:02X}")

    def _raw_transmit(self, apdu: bytes, log_name: str) -> tuple[bytes, int, int]:
        connection = self._ensure_connection()
        tx_apdu = bytes(apdu)
        self._print_apdu_debug("tx", tx_apdu, log_name=log_name)
        try:
            data, sw1, sw2 = connection.transmit(list(tx_apdu))
        except Exception as error:
            raise RuntimeError(f"{log_name} transmit failed: {error}") from error
        payload = bytes(data)
        self._print_apdu_debug("rx", payload, sw1, sw2, log_name=log_name)

        if sw1 == 0x6C and len(tx_apdu) >= 4:
            corrected = tx_apdu[:-1] + bytes([sw2])
            return self._raw_transmit(corrected, f"{log_name} [LE RETRY]")

        if sw1 in (0x61, 0x9F):
            accumulated = bytearray(payload)
            get_response_cla = tx_apdu[0] & 0x03 if len(tx_apdu) > 0 else 0x00
            while sw1 in (0x61, 0x9F):
                get_response = bytes([get_response_cla, 0xC0, 0x00, 0x00, sw2])
                self._print_apdu_debug("tx", get_response, log_name=f"{log_name} [GET RESPONSE]")
                try:
                    chunk, sw1, sw2 = connection.transmit(list(get_response))
                except Exception as error:
                    raise RuntimeError(f"{log_name} GET RESPONSE failed: {error}") from error
                chunk_bytes = bytes(chunk)
                self._print_apdu_debug(
                    "rx",
                    chunk_bytes,
                    sw1,
                    sw2,
                    log_name=f"{log_name} [GET RESPONSE]",
                )
                accumulated.extend(chunk_bytes)
            payload = bytes(accumulated)

        self._record_status_word(sw1, sw2)
        return payload, sw1, sw2

    def _exchange_with_proactive_chain(self, apdu: bytes, log_name: str) -> tuple[bytes, int, int]:
        data, sw1, sw2 = self._raw_transmit(apdu, log_name)
        sw1, sw2 = self._drain_proactive_chain(log_name, sw1, sw2)
        self._record_status_word(sw1, sw2)
        return data, sw1, sw2

    @staticmethod
    def _is_success(sw1: int, sw2: int) -> bool:
        return sw1 == 0x90 and sw2 == 0x00

    def _assert_success(self, sw1: int, sw2: int, label: str) -> None:
        if self._is_success(sw1, sw2):
            return
        raise RuntimeError(f"{label} failed with SW {sw1:02X}{sw2:02X}.")

    def _queued_pending_length(self) -> int:
        total = 0
        for chunk in self.state.pending_channel_queue:
            total += len(chunk)
        return total

    def _append_pending_channel_data(self, payload: bytes) -> None:
        if len(payload) == 0:
            return
        self.state.pending_channel_queue.append(bytes(payload))
        self.state.pending_channel_data = b"".join(self.state.pending_channel_queue)

    def _consume_pending_channel_data(self, chunk_limit: int) -> bytes:
        remaining_limit = max(0, int(chunk_limit))
        if remaining_limit == 0 or len(self.state.pending_channel_queue) == 0:
            return b""
        out = bytearray()
        while remaining_limit > 0 and len(self.state.pending_channel_queue) > 0:
            next_chunk = self.state.pending_channel_queue[0]
            if len(next_chunk) <= remaining_limit:
                out.extend(next_chunk)
                remaining_limit -= len(next_chunk)
                del self.state.pending_channel_queue[0]
                continue
            out.extend(next_chunk[:remaining_limit])
            self.state.pending_channel_queue[0] = next_chunk[remaining_limit:]
            remaining_limit = 0
        self.state.pending_channel_data = b"".join(self.state.pending_channel_queue)
        return bytes(out)

    def _clear_pending_channel_data(self) -> None:
        self.state.pending_channel_queue = []
        self.state.pending_channel_data = b""

    @staticmethod
    def _transport_protocol_name(protocol_type: int) -> str:
        return {
            0x01: "UDP REMOTE",
            0x02: "TCP CLIENT REMOTE",
            0x03: "TCP SERVER",
            0x04: "UDP LOCAL",
        }.get(int(protocol_type) & 0xFF, f"0x{int(protocol_type) & 0xFF:02X}")

    @staticmethod
    def _decode_network_access_name(value_bytes: bytes) -> str:
        parts: list[str] = []
        offset = 0
        while offset < len(value_bytes):
            label_len = value_bytes[offset]
            offset += 1
            label_end = offset + label_len
            if label_end > len(value_bytes):
                break
            label = value_bytes[offset:label_end]
            try:
                parts.append(label.decode("ascii", "ignore"))
            except Exception:
                parts.append(label.hex().upper())
            offset = label_end
        return ".".join(part for part in parts if len(part) > 0)

    @staticmethod
    def _decode_other_address(value_bytes: bytes) -> str:
        if len(value_bytes) == 5 and value_bytes[0] == 0x21:
            return ".".join(str(part) for part in value_bytes[1:])
        if len(value_bytes) == 17 and value_bytes[0] == 0x57:
            groups = []
            for offset in range(1, len(value_bytes), 2):
                groups.append(f"{int.from_bytes(value_bytes[offset:offset + 2], 'big'):04X}")
            return ":".join(groups)
        return value_bytes.hex().upper()

    def _open_virtual_channel(self, fields: Optional[dict[str, Any]] = None, source: str = "manual") -> None:
        info = dict(fields or {})
        protocol_type = int(info.get("transport_protocol_type", 0) or 0)
        protocol_name = "VIRTUAL"
        if protocol_type > 0:
            protocol_name = self._transport_protocol_name(protocol_type)
        remote_address = str(info.get("remote_address", "") or "").strip()
        remote_port = int(info.get("transport_port", 0) or 0)
        endpoint = ""
        if len(remote_address) > 0 and remote_port > 0:
            endpoint = f"{remote_address}:{remote_port}"
        elif len(remote_address) > 0:
            endpoint = remote_address
        else:
            endpoint = str(source or "manual").strip() or "manual"
        self.state.open_channel_active = True
        self.state.open_channel_protocol = protocol_name
        self.state.open_channel_endpoint = endpoint
        self._record_flow_event(f"OPEN CHANNEL active via {protocol_name} ({endpoint}).")

    def _close_virtual_channel(self) -> None:
        if self.state.open_channel_active:
            self._record_flow_event("OPEN CHANNEL closed.")
        self.state.open_channel_active = False
        self.state.open_channel_protocol = ""
        self.state.open_channel_endpoint = ""
        self.state.last_channel_data_sent = 0
        self._clear_pending_channel_data()

    def initialize(self) -> None:
        """Reset the STK session state and synchronise the event-list from the terminal profile."""
        self.state = StkState()
        reset_session_state = getattr(self.tp, "reset_session_state", None)
        if callable(reset_session_state):
            reset_session_state()
        reset_method = getattr(self.tp, "reset", None)
        if callable(reset_method):
            if reset_method() is False:
                raise RuntimeError("Card reset failed before STK initialization.")
        _data, sw1, sw2 = self._exchange_with_proactive_chain(
            self.TERMINAL_PROFILE,
            "STK INIT: TERMINAL PROFILE",
        )
        self._assert_success(sw1, sw2, "STK initialization")
        self.state.initialized = True
        self._record_flow_event("STK initialization completed.")

    def send_apdu(self, apdu_hex: str) -> tuple[bytes, int, int]:
        """Send one STK-formatted APDU hex string through the transport and return (data, SW1, SW2)."""
        cleaned = self._clean_hex(apdu_hex)
        if len(cleaned) == 0:
            raise ValueError("APDU hex is empty.")
        try:
            apdu = bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError("APDU hex is invalid.") from error
        return self._exchange_with_proactive_chain(apdu, "STK RAW APDU")

    def _build_envelope_apdu(self, body: bytes) -> bytes:
        if len(body) <= 0xFF:
            return bytes([0x80, 0xC2, 0x00, 0x00, len(body)]) + bytes(body)
        if len(body) > 0xFFFF:
            raise ValueError("Envelope exceeds extended APDU size.")
        return bytes(
            [
                0x80,
                0xC2,
                0x00,
                0x00,
                0x00,
                (len(body) >> 8) & 0xFF,
                len(body) & 0xFF,
            ]
        ) + bytes(body)

    def _build_event_download_apdu(self, event_code: int, extra_tlvs: bytes = b"") -> bytes:
        event_body = (
            self._wrap_tlv(b"\x99", bytes([event_code & 0xFF]))
            + self.DEVICE_IDENTITIES_TERMINAL_TO_UICC
            + bytes(extra_tlvs or b"")
        )
        envelope = self._wrap_tlv(b"\xD6", event_body)
        return self._build_envelope_apdu(envelope)

    def _parse_extra_tlvs(self, tlvs_hex: str) -> bytes:
        cleaned = self._clean_hex(tlvs_hex)
        if len(cleaned) == 0:
            return b""
        try:
            return bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError("Extra TLV hex is invalid.") from error

    def resolve_event_code(self, event_token: str) -> int:
        """Resolve an event-name token (e.g. 'MT-CALL') to its ETSI TS 102 223 §8.25 event-code byte."""
        cleaned = str(event_token or "").strip().upper().replace("_", "-")
        if len(cleaned) == 0:
            raise ValueError("Event name is required.")
        if cleaned in self.EVENT_NAME_MAP:
            return self.EVENT_NAME_MAP[cleaned]
        if cleaned.startswith("0X"):
            cleaned = cleaned[2:]
        if len(cleaned) <= 2:
            try:
                return int(cleaned, 16)
            except ValueError as error:
                raise ValueError(f"Unknown STK event '{event_token}'.") from error
        raise ValueError(f"Unknown STK event '{event_token}'.")

    def send_event(self, event_token: str, extra_tlvs_hex: str = "") -> tuple[bytes, int, int]:
        """Queue and dispatch a DOWNLOAD-ENVELOPE event (ETSI TS 102 221 §11.1.11)."""
        event_code = self.resolve_event_code(event_token)
        extra_tlvs = self._parse_extra_tlvs(extra_tlvs_hex)
        self.state.trigger_history.append(f"EVENT {self._stk_event_name(event_code)}")
        apdu = self._build_event_download_apdu(event_code, extra_tlvs=extra_tlvs)
        return self._exchange_with_proactive_chain(
            apdu,
            f"STK EVENT DOWNLOAD [{self._stk_event_name(event_code)}]",
        )

    def send_location_status(
        self,
        status_value: int = 0x00,
        location_hex: str = "",
    ) -> tuple[bytes, int, int]:
        """Send a LOCATION-STATUS envelope (ETSI TS 102 223 §8.17) with optional LAI / cell-identity."""
        location_value = self.state.location_information
        cleaned_location = self._clean_hex(location_hex)
        if len(cleaned_location) > 0:
            try:
                location_value = bytes.fromhex(cleaned_location)
            except ValueError as error:
                raise ValueError("Location hex is invalid.") from error
            self.state.location_information = location_value
        extra_tlvs = self._wrap_tlv(b"\x9B", bytes([status_value & 0xFF])) + self._wrap_tlv(
            b"\x93",
            location_value,
        )
        self.state.trigger_history.append("LOCATION STATUS")
        apdu = self._build_event_download_apdu(0x03, extra_tlvs=extra_tlvs)
        return self._exchange_with_proactive_chain(apdu, "STK EVENT DOWNLOAD [Location status]")

    def simulate_call_connected(self, extra_tlvs_hex: str = "") -> tuple[bytes, int, int]:
        return self.send_event("CALL-CONNECTED", extra_tlvs_hex=extra_tlvs_hex)

    def simulate_call_disconnected(self, extra_tlvs_hex: str = "") -> tuple[bytes, int, int]:
        return self.send_event("CALL-DISCONNECTED", extra_tlvs_hex=extra_tlvs_hex)

    def queue_channel_data(self, payload_hex: str) -> int:
        """Buffer *payload_hex* for the next DATA-AVAILABLE event and return total queued length."""
        cleaned = self._clean_hex(payload_hex)
        if len(cleaned) == 0:
            raise ValueError("Channel payload hex is empty.")
        try:
            payload = bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError("Channel payload hex is invalid.") from error
        if self.state.open_channel_active is False:
            self._open_virtual_channel(source="queued-data")
        self._append_pending_channel_data(payload)
        self._record_flow_event(f"Queued {len(payload)} byte(s) for RECEIVE DATA.")
        return self._queued_pending_length()

    def send_data_available_event(self) -> tuple[bytes, int, int]:
        """Dispatch a DATA-AVAILABLE envelope (ETSI TS 102 223 §7.5.16) for the queued channel payload."""
        available_length = self._queued_pending_length()
        if available_length <= 0:
            raise RuntimeError("No queued channel data is available.")
        if self.state.open_channel_active is False:
            self._open_virtual_channel(source="data-available")
        channel_status = bytes.fromhex("38028100")
        data_length = self._wrap_tlv(b"\x37", bytes([min(available_length, 0xFF)]))
        extra_tlvs = channel_status + data_length
        self.state.trigger_history.append("DATA AVAILABLE")
        apdu = self._build_event_download_apdu(0x09, extra_tlvs=extra_tlvs)
        return self._exchange_with_proactive_chain(apdu, "STK EVENT DOWNLOAD [Data available]")

    def send_sms_pp(self, tpdu_hex: str) -> tuple[bytes, int, int]:
        """Deliver a raw SMS-PP TPDU as an SMS-PP-DOWNLOAD envelope (ETSI TS 102 223 §7.5.2)."""
        cleaned = self._clean_hex(tpdu_hex)
        if len(cleaned) == 0:
            raise ValueError("SMS TPDU hex is empty.")
        try:
            tpdu = bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError("SMS TPDU hex is invalid.") from error
        sms_body = self.SMS_PP_PREFIX + self._wrap_tlv(b"\x8B", tpdu)
        envelope = self._wrap_tlv(b"\xD1", sms_body)
        self.state.trigger_history.append("SMS-PP DOWNLOAD")
        apdu = self._build_envelope_apdu(envelope)
        return self._exchange_with_proactive_chain(apdu, "STK SMS-PP DOWNLOAD")

    def _drain_proactive_chain(self, log_name: str, sw1: int, sw2: int) -> tuple[int, int]:
        while sw1 == 0x91 and sw2 > 0:
            fetch_apdu = bytes([0x80, 0x12, 0x00, 0x00, sw2])
            fetch_data, fetch_sw1, fetch_sw2 = self._raw_transmit(fetch_apdu, f"{log_name} [FETCH]")
            if self._is_success(fetch_sw1, fetch_sw2) is False:
                raise RuntimeError(
                    f"{log_name} FETCH failed with SW {fetch_sw1:02X}{fetch_sw2:02X}."
                )
            self.state.last_proactive_command = fetch_data
            command_type, qualifier, fields = self._parse_proactive_command(fetch_data)
            self._record_proactive_command(command_type, qualifier)
            self._handle_proactive_command(command_type, qualifier, fields)
            terminal_response = self._build_terminal_response(command_type, qualifier, fields)
            _tr_data, sw1, sw2 = self._raw_transmit(
                terminal_response,
                f"{log_name} [TERMINAL RESPONSE]",
            )
        return sw1, sw2

    def _record_proactive_command(self, command_type: Optional[int], qualifier: int) -> None:
        if command_type is None:
            self.state.command_history.append("UNKNOWN [unparsed]")
            self._record_flow_event("Encountered an unparsed proactive command.")
            return
        name = self._proactive_command_name(command_type)
        text = f"{name} [0x{qualifier:02X}]"
        self.state.command_history.append(text)
        self._record_flow_event(f"Proactive command observed: {text}")

    def _handle_proactive_command(
        self,
        command_type: Optional[int],
        qualifier: int,
        fields: dict[str, Any],
    ) -> None:
        if command_type is None:
            return
        if command_type == 0x05:
            event_list = fields.get("event_list", [])
            if isinstance(event_list, list):
                self.state.event_list = [int(value) & 0xFF for value in event_list]
                event_names = ", ".join(self._stk_event_name(value) for value in self.state.event_list)
                if len(event_names) > 0:
                    self._record_flow_event(f"SET UP EVENT LIST armed: {event_names}.")
            return
        if command_type == 0x03:
            poll_interval = int(fields.get("poll_interval_seconds", 0) or 0)
            if poll_interval > 0:
                self.state.poll_interval_seconds = poll_interval
                self.state.polling_off = False
                self._record_flow_event(f"POLL INTERVAL requested: {poll_interval}s.")
            return
        if command_type == 0x04:
            self.state.polling_off = True
            self._record_flow_event("POLLING OFF requested by card.")
            return
        if command_type == 0x40:
            self._open_virtual_channel(fields, source="proactive-open-channel")
            return
        if command_type == 0x41:
            self._close_virtual_channel()
            return
        if command_type == 0x43:
            payload = bytes(fields.get("channel_data", b""))
            self.state.last_channel_data_sent = len(payload)
            if len(payload) > 0:
                self._record_flow_event(
                    f"SEND DATA received {len(payload)} byte(s): {payload.hex().upper()}"
                )
            else:
                self._record_flow_event("SEND DATA arrived without payload bytes.")
            return
        if command_type == 0x42:
            requested = int(fields.get("channel_data_length", 0) or 0)
            self._record_flow_event(f"RECEIVE DATA requested {requested} byte(s).")
            return
        if command_type == 0x44:
            self._record_flow_event("GET CHANNEL STATUS requested.")
            return
        if command_type == 0x26:
            self._record_flow_event(
                f"PROVIDE LOCAL INFORMATION requested with qualifier 0x{qualifier:02X}."
            )
            return
        if command_type == 0x01:
            self._record_flow_event("REFRESH acknowledged without transport reset.")

    def _build_terminal_response(
        self,
        command_type: Optional[int],
        qualifier: int,
        fields: dict[str, Any],
    ) -> bytes:
        command_details_tlv = bytes(fields.get("command_details_tlv", b""))
        if len(command_details_tlv) == 0:
            raise RuntimeError("Terminal response could not locate command details.")

        result_tlv = bytes.fromhex("030100")
        response_payload = self._build_terminal_response_payload(command_type, qualifier, fields)
        body = command_details_tlv + self.DEVICE_IDENTITIES_TERMINAL_TO_UICC + result_tlv + response_payload
        if command_type is not None:
            self.state.generic_ack_history.append(self._proactive_command_name(command_type))
        return bytes([0x80, 0x14, 0x00, 0x00, len(body)]) + body

    def _build_terminal_response_payload(
        self,
        command_type: Optional[int],
        qualifier: int,
        fields: dict[str, Any],
    ) -> bytes:
        if command_type == 0x40:
            if self.state.open_channel_active is False:
                return b""
            payload = bytes.fromhex("38028100")
            buffer_size_tlv = bytes(fields.get("buffer_size_tlv", b""))
            if len(buffer_size_tlv) > 0:
                payload += buffer_size_tlv
            return payload
        if command_type == 0x43:
            if self.state.last_channel_data_sent > 0:
                return bytes.fromhex("3701FF")
            return bytes.fromhex("370100")
        if command_type == 0x42:
            requested_length = int(fields.get("channel_data_length", 0) or 0)
            chunk_limit = 237
            if requested_length > 0:
                chunk_limit = min(chunk_limit, requested_length)
            chunk = self._consume_pending_channel_data(chunk_limit)
            remaining = self._queued_pending_length()
            payload = b""
            if len(chunk) > 0:
                payload += self._wrap_tlv(b"\x36", chunk)
            payload += self._wrap_tlv(b"\x37", bytes([min(remaining, 0xFF)]))
            self._record_flow_event(
                f"RECEIVE DATA returned {len(chunk)} byte(s), {remaining} byte(s) remaining."
            )
            return payload
        if command_type == 0x44:
            if self.state.open_channel_active:
                return bytes.fromhex("38028100")
            return bytes.fromhex("38020100")
        if command_type != 0x26:
            return b""
        if qualifier == 0x00:
            return self._wrap_tlv(b"\x13", self.state.location_information)
        if qualifier == 0x01:
            return self._wrap_tlv(b"\x14", self.state.imei)
        if qualifier == 0x03:
            current_time = time.localtime()
            date_time_tz = bytes(
                [
                    self._encode_bcd(current_time.tm_year % 100),
                    self._encode_bcd(current_time.tm_mon),
                    self._encode_bcd(current_time.tm_mday),
                    self._encode_bcd(current_time.tm_hour),
                    self._encode_bcd(current_time.tm_min),
                    self._encode_bcd(current_time.tm_sec),
                    0xFF,
                ]
            )
            return self._wrap_tlv(b"\x26", date_time_tz)
        if qualifier == 0x04:
            return self._wrap_tlv(b"\x2D", b"en")
        return b""

    @staticmethod
    def _encode_bcd(value: int) -> int:
        bounded = max(0, min(99, int(value)))
        return ((bounded % 10) << 4) | (bounded // 10)

    @staticmethod
    def _duration_tlv_to_seconds(unit: int, value: int) -> int:
        """Resolve ETSI TS 102 223 §8.8 Duration TLV to whole seconds.

        Tenths-of-seconds round up so a (0x02, 0x05) duration ("0.5s")
        still surfaces as 1s in trace output rather than collapsing to
        zero. Unknown units fall back to ``value`` so the caller still
        gets a non-zero number to render.
        """
        unit_byte = int(unit) & 0xFF
        value_byte = int(value) & 0xFF
        if unit_byte == 0x00:
            return value_byte * 60
        if unit_byte == 0x01:
            return value_byte
        if unit_byte == 0x02:
            return (value_byte + 9) // 10
        return value_byte

    def _parse_proactive_command(
        self,
        fetch_data: bytes,
    ) -> tuple[Optional[int], int, dict[str, Any]]:
        fields: dict[str, Any] = {}
        try:
            root_tag, root_value, _, _ = self._read_tlv(fetch_data, 0)
        except Exception:
            return None, 0, fields
        if root_tag != b"\xD0":
            return None, 0, fields
        command_type = None
        qualifier = 0
        offset = 0
        while offset < len(root_value):
            try:
                tag_bytes, value_bytes, raw_tlv, next_offset = self._read_tlv(root_value, offset)
            except Exception:
                return command_type, qualifier, fields
            if tag_bytes in (b"\x01", b"\x81") and len(value_bytes) == 3:
                command_type = value_bytes[1]
                qualifier = value_bytes[2]
                fields["command_details_tlv"] = raw_tlv
            elif tag_bytes in (b"\x02", b"\x82") and len(value_bytes) == 2:
                fields["device_identities_tlv"] = raw_tlv
            elif tag_bytes == b"\x99":
                fields["event_list"] = [int(value) for value in value_bytes]
            elif tag_bytes == b"\x84" and len(value_bytes) >= 2:
                # ETSI TS 102 223 §8.8 Duration TLV.
                # Byte 0: time unit (0x00=minutes, 0x01=seconds,
                #                    0x02=tenths-of-seconds).
                # Byte 1: value (1..255). Earlier revisions of this
                # parser treated the two bytes as a big-endian seconds
                # count, which under-reported a 1-minute POLL INTERVAL
                # as "1s" in the trace.
                fields["duration_unit"] = value_bytes[0]
                fields["duration_value"] = value_bytes[1]
                fields["poll_interval_seconds"] = self._duration_tlv_to_seconds(
                    value_bytes[0], value_bytes[1]
                )
            elif tag_bytes == b"\x35":
                fields["bearer_description_tlv"] = raw_tlv
            elif tag_bytes == b"\x36":
                fields["channel_data"] = value_bytes
            elif tag_bytes == b"\x39" and len(value_bytes) == 2:
                fields["buffer_size"] = int.from_bytes(value_bytes, "big", signed=False)
                fields["buffer_size_tlv"] = raw_tlv
            elif tag_bytes == b"\x47":
                fields["network_access_name"] = self._decode_network_access_name(value_bytes)
            elif tag_bytes == b"\x3C" and len(value_bytes) == 3:
                fields["transport_protocol_type"] = value_bytes[0]
                fields["transport_port"] = int.from_bytes(value_bytes[1:], "big", signed=False)
            elif tag_bytes == b"\x3E":
                fields["remote_address"] = self._decode_other_address(value_bytes)
            elif tag_bytes == b"\xB7" and len(value_bytes) == 1:
                fields["channel_data_length"] = value_bytes[0]
            offset = next_offset
        return command_type, qualifier, fields

    def _proactive_command_name(self, command_type: int) -> str:
        return self.PROACTIVE_NAME_MAP.get(command_type, f"UNKNOWN 0x{command_type:02X}")

    def _stk_event_name(self, event_code: int) -> str:
        for name, code in self.EVENT_NAME_MAP.items():
            if code == event_code:
                return name.replace("-", " ").title()
        return f"0x{event_code:02X}"

    def format_state_lines(self) -> list[str]:
        """Return a list of human-readable lines summarising the current STK session state."""
        event_names = [self._stk_event_name(value) for value in self.state.event_list]
        open_channel = "NO"
        if self.state.open_channel_active:
            open_channel = "YES"
        return [
            f"Initialized       : {self.state.initialized}",
            f"Last SW           : {self.state.last_status_word or '(none)'}",
            f"Event List        : {', '.join(event_names) if event_names else '(empty)'}",
            f"Poll Interval     : {self.state.poll_interval_seconds or 0}s",
            f"Polling Off       : {self.state.polling_off}",
            f"Open Channel      : {open_channel}",
            f"Channel Protocol  : {self.state.open_channel_protocol or '(none)'}",
            f"Channel Endpoint  : {self.state.open_channel_endpoint or '(none)'}",
            f"Queued RX Bytes   : {self._queued_pending_length()}",
            f"Last Card TX Bytes: {self.state.last_channel_data_sent}",
            f"Last Proactive    : {self.state.last_proactive_command.hex().upper() or '(none)'}",
        ]

    def format_history_lines(self, limit: int = 12) -> list[str]:
        """Return a list of recent command and trigger history lines for the STK debug view."""
        out: list[str] = []
        command_history = self.state.command_history[-max(1, int(limit)) :]
        trigger_history = self.state.trigger_history[-max(1, int(limit)) :]
        flow_events = self.state.flow_events[-max(1, int(limit)) :]
        out.append("Proactive Commands:")
        if len(command_history) == 0:
            out.append("  (none)")
        else:
            for item in command_history:
                out.append(f"  {item}")
        out.append("Triggers:")
        if len(trigger_history) == 0:
            out.append("  (none)")
        else:
            for item in trigger_history:
                out.append(f"  {item}")
        out.append("Flow Events:")
        if len(flow_events) == 0:
            out.append("  (none)")
        else:
            for item in flow_events:
                out.append(f"  {item}")
        return out
