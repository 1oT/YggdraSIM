# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SIM Toolkit logic: proactive command encoding/decoding and TERMINAL RESPONSE handling (ETSI TS 102 223)."""
from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Optional

from yggdrasim_common.stk_terminal import terminal_profile_apdu


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


def _decode_imei_digits(imei_bytes: bytes) -> str:
    """Recover the 15 IMEI digits from the 3GPP TS 24.008 §10.5.1.4 layout."""
    raw = bytes(imei_bytes or b"")
    if len(raw) != 8:
        raise ValueError("Encoded IMEI must be exactly 8 bytes.")
    digits = [str(raw[0] >> 4)]
    for byte in raw[1:]:
        digits.append(str(byte & 0x0F))
        digits.append(str(byte >> 4))
    return "".join(digits)


def _encode_imeisv_bcd(imei_digits: str, software_version: str) -> bytes:
    """Encode an IMEISV per ETSI TS 102 223 §8.74 / 3GPP TS 24.008 §10.5.1.4.

    3GPP TS 23.003 §6.2.2 composes the IMEISV as TAC (8) + SNR (6) + SVN (2),
    so the check digit of the 15-digit IMEI is dropped. Sixteen digits are an
    even count: octet 3 carries type of identity ``011`` with the odd/even
    bit clear, and the high nibble of the last octet is the ``1111`` end
    mark. The output is always 9 bytes.
    """
    digits = "".join(ch for ch in str(imei_digits or "") if ch.isdigit())
    svn = "".join(ch for ch in str(software_version or "") if ch.isdigit())
    if len(digits) != 15:
        raise ValueError("IMEI must be exactly 15 decimal digits.")
    if len(svn) != 2:
        raise ValueError("Software version number must be exactly two decimal digits.")
    imeisv = digits[:14] + svn
    out = bytearray()
    out.append(((int(imeisv[0]) & 0x0F) << 4) | 0x03)
    for index in range(1, 15, 2):
        low_digit = int(imeisv[index]) & 0x0F
        high_digit = int(imeisv[index + 1]) & 0x0F
        out.append((high_digit << 4) | low_digit)
    out.append(0xF0 | (int(imeisv[15]) & 0x0F))
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
    # MCC=001, MNC=01 (the default test USIM PLMN, 3GPP TS 31.124 v18.7 §27.22.2A),
    # LAC=0x0001, Cell ID=0x0001. Layout: 3 bytes packed-BCD PLMN +
    # 2 byte LAC + 2 byte Cell ID = 7 bytes.
    location_information: bytes = field(
        default_factory=lambda: _encode_location_information_gsm("001", "01", 0x0001, 0x0001)
    )
    # ETSI TS 102 223 §8.20 IMEI: 8-byte BCD encoding of a 15-digit
    # IMEI. The default is "086543245654321" (Type Allocation Code
    # 086543245 reserved by 3GPP TS 23.003 for test purposes).
    imei: bytes = field(default_factory=lambda: _encode_imei_bcd("086543245654321"))
    # 3GPP TS 23.003 §6.2.2: IMEISV = TAC + SNR + SVN. The software version
    # is the only element the IMEI above does not already carry.
    software_version: str = "00"
    # ETSI TS 102 223 §8.61 value answered to PROVIDE LOCAL INFORMATION
    # '06'. '00' (GSM) pairs with the 7-byte GERAN layout of
    # ``location_information`` (3GPP TS 31.111 §8.19.1).
    access_technology: int = 0x00
    # ETSI TS 102 223 §6.4.21: up to eight terminal timers keyed by the
    # §8.37 identifier; value = (duration in seconds, monotonic start time).
    timers: dict[int, tuple[int, float]] = field(default_factory=dict)
    last_proactive_command: bytes = b""
    open_channel_active: bool = False
    open_channel_protocol: str = ""
    open_channel_endpoint: str = ""
    pending_channel_queue: list[bytes] = field(default_factory=list)
    pending_channel_data: bytes = b""
    last_channel_data_sent: int = 0
    last_status_word: str = ""


class StkController:
    MAX_PROACTIVE_COMMANDS = 64

    # The toolchain's one TERMINAL PROFILE (yggdrasim_common.stk_terminal):
    # every facility ETSI TS 102 223 V18.3.0 §5.2 defines is claimed, so no
    # card withholds a service -- or disables an applet -- for want of a
    # declared capability. The PROVIDE LOCAL INFORMATION modes
    # ``_provide_local_information_response`` does not serve (NMR, Timing
    # Advance, ESN, MEID, Search Mode, Broadcast Network Information,
    # Supported Radio Access Technologies, ...) are claimed too and still
    # answered with §8.12 '30' (beyond terminal's capabilities).
    TERMINAL_PROFILE = terminal_profile_apdu()

    DEVICE_IDENTITIES_TERMINAL_TO_UICC = bytes.fromhex("02028281")
    DEVICE_IDENTITIES_UICC_TO_TERMINAL = bytes.fromhex("82028182")
    # ENVELOPE (SMS-PP DOWNLOAD) carries a message that arrived from the
    # network, so 3GPP TS 31.111 §7.1.1.2 sets the source to Network
    # ('83'), unlike the terminal-sourced envelopes above.
    SMS_PP_PREFIX = bytes.fromhex("0202838106028001")

    # ETSI TS 102 223 §8.27 Location status values.
    LOCATION_STATUS_NORMAL_SERVICE = 0x00
    # ETSI TS 102 223 §8.6 REFRESH command qualifiers.
    REFRESH_QUALIFIER_UICC_RESET = 0x04
    REFRESH_QUALIFIER_EUICC_PROFILE_STATE_CHANGE = 0x09
    # 3GPP TS 31.111 §8.28: bits 5-7 TI value, bit 8 TI flag. A near-end
    # (MT) call connect carries TI flag 1, TI value 0.
    DEFAULT_TRANSACTION_IDENTIFIER_TLV = bytes.fromhex("9C0180")
    # ETSI TS 102 223 §8.76: 'FE' = not powered by a battery.
    BATTERY_STATE_NOT_POWERED_BY_BATTERY = 0xFE
    # ETSI TS 102 223 §8.12 general results used by the terminal responses.
    GENERAL_RESULT_OK = 0x00
    GENERAL_RESULT_TIMER_STATE_CONTRADICTION = 0x24
    GENERAL_RESULT_BEYOND_CAPABILITIES = 0x30
    GENERAL_RESULT_DATA_NOT_UNDERSTOOD = 0x32
    GENERAL_RESULT_VALUES_MISSING = 0x36
    # ETSI TS 102 223 §8.6 PROVIDE LOCAL INFORMATION qualifiers.
    PLI_LOCATION_INFORMATION = 0x00
    PLI_IMEI = 0x01
    PLI_DATE_TIME_TIME_ZONE = 0x03
    PLI_LANGUAGE = 0x04
    PLI_ACCESS_TECHNOLOGY = 0x06
    PLI_IMEISV = 0x08
    PLI_BATTERY_STATE = 0x0A

    # Event List values per ETSI TS 102 223 §8.25. '1A' is Void in every
    # release of that clause, so nothing is named onto it.
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
        "SECURED-PROFILE-CONTAINER": 0x1B,
        "POLL-INTERVAL-NEGOTIATION": 0x1C,
    }

    # Type of Command values, ETSI TS 102 223 table 9.4. '81' is not a
    # command: it is the "end of the proactive UICC session" value that
    # table allows for Next Action Indicator coding only.
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
        0x50: "SET FRAMES",
        0x51: "GET FRAMES STATUS",
        0x60: "RETRIEVE MULTIMEDIA MESSAGE",
        0x61: "SUBMIT MULTIMEDIA MESSAGE",
        0x62: "DISPLAY MULTIMEDIA MESSAGE",
        0x70: "ACTIVATE",
        0x71: "CONTACTLESS STATE CHANGED",
        0x72: "COMMAND CONTAINER",
        0x73: "ENCAPSULATED SESSION CONTROL",
        0x79: "LSI COMMAND",
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
        if data[tag_start] == 0x7F:
            # ETSI TS 101 220 §7.1.1.2: '7F' opens the three-byte
            # COMPREHENSION-TLV tag. Exactly two bytes follow, the CR flag in
            # b8 of the first and a 15-bit tag value from '0001' to '7FFF'.
            offset += 2
            if offset > len(data):
                raise ValueError("Truncated three-byte COMPREHENSION-TLV tag.")
            three_byte_value = ((data[tag_start + 1] & 0x7F) << 8) | data[tag_start + 2]
            if three_byte_value == 0:
                raise ValueError("Invalid three-byte COMPREHENSION-TLV tag value.")
        elif data[tag_start] & 0x1F == 0x1F:
            first_high_tag_octet = True
            while offset < len(data):
                current = data[offset]
                offset += 1
                if first_high_tag_octet and (current & 0x7F) == 0:
                    raise ValueError("Invalid high-tag-number TLV encoding.")
                first_high_tag_octet = False
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
            if data[offset] == 0x00:
                raise ValueError("Non-minimal TLV length.")
            length_value = 0
            for _ in range(octet_count):
                length_value = (length_value << 8) | data[offset]
                offset += 1
            if length_value < 0x80:
                raise ValueError("Non-minimal TLV length.")
        else:
            length_value = length_byte
        value_end = offset + length_value
        if value_end > len(data):
            raise ValueError("TLV value exceeds input length.")
        raw_tlv = data[tag_start:value_end]
        return tag_bytes, data[offset:value_end], raw_tlv, value_end

    @staticmethod
    def _append_history(target: list[str], value: str) -> None:
        from SIMCARD.state import append_bounded

        append_bounded(target, value)

    def _record_flow_event(self, text: str) -> None:
        self._append_history(self.state.flow_events, str(text or "").strip())

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

    def _raw_transmit(
        self,
        apdu: bytes,
        log_name: str,
        *,
        _allow_le_retry: bool = True,
    ) -> tuple[bytes, int, int]:
        connection = self._ensure_connection()
        tx_apdu = bytes(apdu)
        self._print_apdu_debug("tx", tx_apdu, log_name=log_name)
        try:
            data, sw1, sw2 = connection.transmit(list(tx_apdu))
        except Exception as error:
            raise RuntimeError(f"{log_name} transmit failed: {error}") from error
        payload = bytes(data)
        self._print_apdu_debug("rx", payload, sw1, sw2, log_name=log_name)

        if sw1 == 0x6C:
            if _allow_le_retry is False:
                raise RuntimeError(
                    f"{log_name} returned repeated wrong-length status 6C{sw2:02X}."
                )
            from SCP03.transport.card import CardTransporter

            corrected = bytes(
                CardTransporter._correct_apdu_le(list(tx_apdu), sw2)
            )
            return self._raw_transmit(
                corrected,
                f"{log_name} [LE RETRY]",
                _allow_le_retry=False,
            )

        if sw1 in (0x61, 0x9F):
            accumulated = bytearray(payload)
            from SCP03.transport.card import CardTransporter

            get_response_cla = (
                CardTransporter._get_response_cla(tx_apdu[0])
                if len(tx_apdu) > 0
                else 0x00
            )
            followups = 0
            while sw1 in (0x61, 0x9F):
                followups += 1
                if followups > 64:
                    raise RuntimeError(
                        f"{log_name} returned too many GET RESPONSE continuations."
                    )
                get_response = bytes([get_response_cla, 0xC0, 0x00, 0x00, sw2])
                self._print_apdu_debug("tx", get_response, log_name=f"{log_name} [GET RESPONSE]")
                try:
                    chunk, sw1, sw2 = connection.transmit(list(get_response))
                except Exception as error:
                    raise RuntimeError(f"{log_name} GET RESPONSE failed: {error}") from error
                if sw1 == 0x6C:
                    corrected_get_response = bytes(
                        CardTransporter._correct_apdu_le(list(get_response), sw2)
                    )
                    try:
                        chunk, sw1, sw2 = connection.transmit(
                            list(corrected_get_response)
                        )
                    except Exception as error:
                        raise RuntimeError(
                            f"{log_name} corrected GET RESPONSE failed: {error}"
                        ) from error
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
            0x05: "TCP CLIENT LOCAL",
            0x06: "DIRECT CHANNEL",
        }.get(int(protocol_type) & 0xFF, f"0x{int(protocol_type) & 0xFF:02X}")

    @staticmethod
    def _decode_network_access_name(value_bytes: bytes) -> str:
        parts: list[str] = []
        offset = 0
        while offset < len(value_bytes):
            label_len = value_bytes[offset]
            offset += 1
            if label_len == 0:
                raise ValueError("Network Access Name contains an empty label.")
            label_end = offset + label_len
            if label_end > len(value_bytes):
                raise ValueError(
                    "Network Access Name label exceeds the available value bytes."
                )
            label = value_bytes[offset:label_end]
            try:
                parts.append(label.decode("ascii"))
            except UnicodeDecodeError as error:
                raise ValueError("Network Access Name label is not ASCII.") from error
            offset = label_end
        return ".".join(parts)

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

    def drain_pending(self, sw1: int, sw2: int) -> tuple[int, int]:
        """Fetch and answer the proactive commands a '91 XX' announces (SCP03 STK mode).

        The transport calls this after any command, so it never raises: a drain
        that fails leaves the '91 XX' the command ended with, and says why.
        """
        try:
            drained_sw1, drained_sw2 = self._drain_proactive_chain("STK MODE", sw1, sw2)
        except RuntimeError as error:
            self._record_flow_event(f"STK mode left the proactive cycle open: {error}")
            print(f"[STK] proactive command left pending: {error}")
            return sw1, sw2
        self._record_status_word(drained_sw1, drained_sw2)
        return drained_sw1, drained_sw2

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

    def _extended_length_declared(self) -> bool:
        """Report whether the transport's card declares extended Lc and Le."""
        checker = getattr(self.tp, "supports_extended_length", None)
        if callable(checker) is False:
            return False
        return bool(checker())

    def _build_envelope_apdu(self, body: bytes) -> bytes:
        """Build the ENVELOPE C-APDU of ETSI TS 102 221 v18.4 §11.2.2.

        That clause gives Lc as "length of the subsequent data field" and
        table 10.1 sizes Lc at 0 or 1 bytes, so the three-byte extended form
        is available only when the card declares "Extended Lc and Le fields"
        in the card-capabilities data object of its ATR historical bytes
        (§6.3.1, tag '73'). Without that declaration a body above 255 bytes
        is refused rather than sent in a form the card will reject.
        """
        if len(body) <= 0xFF:
            return bytes([0x80, 0xC2, 0x00, 0x00, len(body)]) + bytes(body)
        if self._extended_length_declared() is False:
            raise ValueError(
                f"Envelope body is {len(body)} bytes: TS 102 221 §11.2.2 carries it in a "
                "one-byte Lc, and the card does not declare extended Lc and Le fields "
                "in its ATR card-capabilities data object."
            )
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
            encoded = bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError("Extra TLV hex is invalid.") from error
        offset = 0
        try:
            while offset < len(encoded):
                _tag, _value, _raw, offset = self._read_tlv(encoded, offset)
        except ValueError as error:
            raise ValueError(f"Extra TLV data is malformed: {error}") from error
        return encoded

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
        """Dispatch an ENVELOPE (EVENT DOWNLOAD) per ETSI TS 102 223 §7.5 over TS 102 221 §11.2.2."""
        event_code = self.resolve_event_code(event_token)
        extra_tlvs = self._parse_extra_tlvs(extra_tlvs_hex)
        self._append_history(self.state.trigger_history, f"EVENT {self._stk_event_name(event_code)}")
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
        """Send an EVENT DOWNLOAD (Location status) envelope per ETSI TS 102 223 §7.5.4.2.

        The Location information object (§8.19) is only carried for
        Normal service (§8.27 '00'); §7.5.4.2 forbids it for the other
        service states.
        """
        location_value = self.state.location_information
        cleaned_location = self._clean_hex(location_hex)
        if len(cleaned_location) > 0:
            try:
                location_value = bytes.fromhex(cleaned_location)
            except ValueError as error:
                raise ValueError("Location hex is invalid.") from error
            self.state.location_information = location_value
        extra_tlvs = self._wrap_tlv(b"\x9B", bytes([status_value & 0xFF]))
        if (status_value & 0xFF) == self.LOCATION_STATUS_NORMAL_SERVICE:
            extra_tlvs += self._wrap_tlv(b"\x93", location_value)
        self._append_history(self.state.trigger_history, "LOCATION STATUS")
        apdu = self._build_event_download_apdu(0x03, extra_tlvs=extra_tlvs)
        return self._exchange_with_proactive_chain(apdu, "STK EVENT DOWNLOAD [Location status]")

    def _with_transaction_identifier(self, extra_tlvs_hex: str) -> str:
        """Prepend the §8.28 Transaction identifier unless the caller supplied one.

        ETSI TS 102 223 §7.5.2.2 / §7.5.3.2 make the object mandatory in
        the call connected and call disconnected envelopes, right after the
        Device identities.
        """
        encoded = self._parse_extra_tlvs(extra_tlvs_hex)
        offset = 0
        while offset < len(encoded):
            tag_bytes, _value, _raw, offset = self._read_tlv(encoded, offset)
            if len(tag_bytes) == 1 and (tag_bytes[0] & 0x7F) == 0x1C:
                return encoded.hex().upper()
        return self.DEFAULT_TRANSACTION_IDENTIFIER_TLV.hex().upper() + encoded.hex().upper()

    def simulate_call_connected(self, extra_tlvs_hex: str = "") -> tuple[bytes, int, int]:
        """Send EVENT DOWNLOAD (Call connected) for a near-end (MT) connect, ETSI TS 102 223 §7.5.2.2."""
        return self.send_event(
            "CALL-CONNECTED",
            extra_tlvs_hex=self._with_transaction_identifier(extra_tlvs_hex),
        )

    def simulate_call_disconnected(self, extra_tlvs_hex: str = "") -> tuple[bytes, int, int]:
        """Send EVENT DOWNLOAD (Call disconnected) for a near-end release, ETSI TS 102 223 §7.5.3.2."""
        return self.send_event(
            "CALL-DISCONNECTED",
            extra_tlvs_hex=self._with_transaction_identifier(extra_tlvs_hex),
        )

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
        """Dispatch an EVENT DOWNLOAD (Data available) envelope (ETSI TS 102 223 §7.5.10.2) for the queued payload."""
        available_length = self._queued_pending_length()
        if available_length <= 0:
            raise RuntimeError("No queued channel data is available.")
        if self.state.open_channel_active is False:
            self._open_virtual_channel(source="data-available")
        channel_status = bytes.fromhex("38028100")
        data_length = self._wrap_tlv(b"\x37", bytes([min(available_length, 0xFF)]))
        extra_tlvs = channel_status + data_length
        self._append_history(self.state.trigger_history, "DATA AVAILABLE")
        apdu = self._build_event_download_apdu(0x09, extra_tlvs=extra_tlvs)
        return self._exchange_with_proactive_chain(apdu, "STK EVENT DOWNLOAD [Data available]")

    def send_sms_pp(self, tpdu_hex: str) -> tuple[bytes, int, int]:
        """Deliver a raw SMS TPDU as an ENVELOPE (SMS-PP DOWNLOAD), 3GPP TS 31.111 §7.1.1.2."""
        cleaned = self._clean_hex(tpdu_hex)
        if len(cleaned) == 0:
            raise ValueError("SMS TPDU hex is empty.")
        try:
            tpdu = bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError("SMS TPDU hex is invalid.") from error
        sms_body = self.SMS_PP_PREFIX + self._wrap_tlv(b"\x8B", tpdu)
        envelope = self._wrap_tlv(b"\xD1", sms_body)
        self._append_history(self.state.trigger_history, "SMS-PP DOWNLOAD")
        apdu = self._build_envelope_apdu(envelope)
        return self._exchange_with_proactive_chain(apdu, "STK SMS-PP DOWNLOAD")

    def _drain_proactive_chain(self, log_name: str, sw1: int, sw2: int) -> tuple[int, int]:
        command_count = 0
        while sw1 == 0x91 and sw2 > 0:
            command_count += 1
            if command_count > self.MAX_PROACTIVE_COMMANDS:
                raise RuntimeError(
                    f"{log_name} exceeded {self.MAX_PROACTIVE_COMMANDS} proactive commands."
                )
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
            if command_type == 0x01 and qualifier == self.REFRESH_QUALIFIER_UICC_RESET:
                sw1, sw2 = self._perform_uicc_reset(log_name)
                continue
            terminal_response = self._build_terminal_response(command_type, qualifier, fields)
            _tr_data, sw1, sw2 = self._raw_transmit(
                terminal_response,
                f"{log_name} [TERMINAL RESPONSE]",
            )
            if (
                command_type == 0x01
                and qualifier == self.REFRESH_QUALIFIER_EUICC_PROFILE_STATE_CHANGE
            ):
                sw1, sw2 = self._perform_profile_state_change(log_name)
        return sw1, sw2

    def _perform_uicc_reset(self, log_name: str) -> tuple[int, int]:
        """Run the REFRESH "UICC Reset" mode of ETSI TS 102 223 §6.4.7.

        No TERMINAL RESPONSE is sent; the reset is the implicit response.
        The event list (§6.4.16) and the timers (§6.4.21) do not survive a
        reset, the card session's channel closes with it, and the new
        session starts with the profile download of §5.1.
        """
        self._record_flow_event(
            "REFRESH (UICC Reset): TERMINAL RESPONSE withheld, card session restarted."
        )
        self.state.event_list = []
        self.state.timers = {}
        self.state.poll_interval_seconds = 0
        self.state.polling_off = False
        self._close_virtual_channel()
        reset_method = getattr(self.tp, "reset", None)
        if callable(reset_method) is False:
            raise RuntimeError(
                f"{log_name} REFRESH (UICC Reset) needs a transport that can reset the card."
            )
        reset_session_state = getattr(self.tp, "reset_session_state", None)
        if callable(reset_session_state):
            reset_session_state()
        if reset_method() is False:
            raise RuntimeError(f"{log_name} card reset failed during REFRESH (UICC Reset).")
        _data, sw1, sw2 = self._raw_transmit(
            self.TERMINAL_PROFILE,
            f"{log_name} [TERMINAL PROFILE after UICC reset]",
        )
        return sw1, sw2

    def _perform_profile_state_change(self, log_name: str) -> tuple[int, int]:
        """Complete the REFRESH "eUICC Profile State Change" mode of ETSI TS 102 223 §6.4.7.

        Unlike UICC Reset this mode does send the TERMINAL RESPONSE, and the
        caller has already sent it. The card then closes every logical
        channel except channel 0, returns to the state defined for "default
        state after UICC activation and ATR" in ETSI TS 102 221 §14.5.1 and
        clears the PIN status, so no ATR-level reset is performed here and
        any secure channel bound to the card session is gone. §6.4.7 also
        requires the proactive UICC session to end on the TERMINAL RESPONSE
        and forbids a new one before TERMINAL PROFILE runs again.
        """
        self._record_flow_event(
            "REFRESH (eUICC Profile State Change): TERMINAL RESPONSE sent, "
            "profile session restarted without a card reset."
        )
        self.state.event_list = []
        self.state.timers = {}
        self.state.poll_interval_seconds = 0
        self.state.polling_off = False
        self._close_virtual_channel()
        reset_session_state = getattr(self.tp, "reset_session_state", None)
        if callable(reset_session_state):
            reset_session_state()
        _data, sw1, sw2 = self._raw_transmit(
            self.TERMINAL_PROFILE,
            f"{log_name} [TERMINAL PROFILE after eUICC Profile State Change]",
        )
        return sw1, sw2

    def _record_proactive_command(self, command_type: Optional[int], qualifier: int) -> None:
        if command_type is None:
            self._append_history(self.state.command_history, "UNKNOWN [unparsed]")
            self._record_flow_event("Encountered an unparsed proactive command.")
            return
        name = self._proactive_command_name(command_type)
        text = f"{name} [0x{qualifier:02X}]"
        self._append_history(self.state.command_history, text)
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
        if command_type == 0x01 and qualifier == self.REFRESH_QUALIFIER_EUICC_PROFILE_STATE_CHANGE:
            # §6.4.7: the terminal discards its cached copy of the Profile,
            # EF_ICCID and EF_DIR included, before answering.
            self._record_flow_event(
                "REFRESH (eUICC Profile State Change): cached profile values discarded."
            )
            return
        if command_type == 0x01 and qualifier != self.REFRESH_QUALIFIER_UICC_RESET:
            self._record_flow_event(
                f"REFRESH mode 0x{qualifier:02X} acknowledged; no card reset in this mode."
            )

    def _build_terminal_response(
        self,
        command_type: Optional[int],
        qualifier: int,
        fields: dict[str, Any],
    ) -> bytes:
        """Build the TERMINAL RESPONSE of ETSI TS 102 223 §6.8 (TS 102 221 §11.2.4 header).

        Command details are echoed as received (§6.8.1), the device
        identities are terminal to UICC (§6.8.2), and every conditional
        object carries a cleared CR flag (§6.8.0).
        """
        command_details_tlv = bytes(fields.get("command_details_tlv", b""))
        if len(command_details_tlv) == 0:
            raise RuntimeError("Terminal response could not locate command details.")

        general_result, response_payload = self._build_terminal_response_result_and_payload(
            command_type, qualifier, fields
        )
        result_tlv = self._wrap_tlv(b"\x03", bytes([general_result & 0xFF]))
        body = command_details_tlv + self.DEVICE_IDENTITIES_TERMINAL_TO_UICC + result_tlv + response_payload
        if command_type is not None:
            self._append_history(self.state.generic_ack_history, self._proactive_command_name(command_type))
        return bytes([0x80, 0x14, 0x00, 0x00, len(body)]) + body

    def _build_terminal_response_payload(
        self,
        command_type: Optional[int],
        qualifier: int,
        fields: dict[str, Any],
    ) -> bytes:
        _result, payload = self._build_terminal_response_result_and_payload(
            command_type, qualifier, fields
        )
        return payload

    def _build_terminal_response_result_and_payload(
        self,
        command_type: Optional[int],
        qualifier: int,
        fields: dict[str, Any],
    ) -> tuple[int, bytes]:
        """Return the §8.12 general result and the command-specific objects of §6.8.0."""
        if command_type == 0x03:
            # §6.8.4: the response to POLL INTERVAL states the interval the
            # terminal will use; the requested one is accepted as-is.
            if "duration_unit" not in fields or "duration_value" not in fields:
                return self.GENERAL_RESULT_VALUES_MISSING, b""
            duration = bytes([int(fields["duration_unit"]) & 0xFF, int(fields["duration_value"]) & 0xFF])
            return self.GENERAL_RESULT_OK, self._wrap_tlv(b"\x04", duration)
        if command_type == 0x27:
            return self._timer_management_response(qualifier, fields)
        if command_type == 0x40:
            if self.state.open_channel_active is False:
                return self.GENERAL_RESULT_OK, b""
            # §6.8.0: Channel status, then the Bearer description actually
            # used and the Buffer size offered, all with CR cleared.
            payload = bytes.fromhex("38028100")
            bearer_description = fields.get("bearer_description")
            if isinstance(bearer_description, (bytes, bytearray)):
                payload += self._wrap_tlv(b"\x35", bytes(bearer_description))
            buffer_size = fields.get("buffer_size")
            if isinstance(buffer_size, int):
                payload += self._wrap_tlv(b"\x39", int(buffer_size).to_bytes(2, "big"))
            return self.GENERAL_RESULT_OK, payload
        if command_type == 0x43:
            if "channel_data" not in fields:
                # §6.6.30: Channel data is the command's minimum set.
                return self.GENERAL_RESULT_VALUES_MISSING, b""
            # §8.54: the Tx buffer space; 'FF' = more than 255 bytes free.
            return self.GENERAL_RESULT_OK, bytes.fromhex("3701FF")
        if command_type == 0x42:
            if "channel_data_length" not in fields:
                # §6.6.29: Channel data length is the command's minimum set.
                return self.GENERAL_RESULT_VALUES_MISSING, b""
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
            return self.GENERAL_RESULT_OK, payload
        if command_type == 0x44:
            # §6.8.18: a successful GET CHANNEL STATUS response carries one
            # Channel status object per available channel. §8.56 codes byte 3
            # bits 1-3 as the channel identifier with 0 meaning "No channel
            # available", and byte 4 '00' as "No further info can be given",
            # so a session with no open channel answers '38 02 00 00' rather
            # than claiming channel 1 exists with its link down.
            if self.state.open_channel_active:
                return self.GENERAL_RESULT_OK, bytes.fromhex("38028100")
            return self.GENERAL_RESULT_OK, bytes.fromhex("38020000")
        if command_type != 0x26:
            return self.GENERAL_RESULT_OK, b""
        return self._provide_local_information_response(qualifier)

    def _provide_local_information_response(self, qualifier: int) -> tuple[int, bytes]:
        """Answer PROVIDE LOCAL INFORMATION per ETSI TS 102 223 §6.8.7.

        A qualifier this terminal cannot serve gets "command beyond
        terminal's capabilities" (§8.12 '30', §6.7) instead of a success
        result without the mandatory local information object.
        """
        if qualifier == self.PLI_LOCATION_INFORMATION:
            return self.GENERAL_RESULT_OK, self._wrap_tlv(b"\x13", self.state.location_information)
        if qualifier == self.PLI_IMEI:
            return self.GENERAL_RESULT_OK, self._wrap_tlv(b"\x14", self.state.imei)
        if qualifier == self.PLI_DATE_TIME_TIME_ZONE:
            current_time = time.localtime()
            # §8.39 / TS 23.040 §9.2.3.11 semi-octets; 'FF' = time zone unknown (§6.4.15).
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
            return self.GENERAL_RESULT_OK, self._wrap_tlv(b"\x26", date_time_tz)
        if qualifier == self.PLI_LANGUAGE:
            # §8.45: ISO 639 pair in the SMS default alphabet with b8 = 0.
            return self.GENERAL_RESULT_OK, self._wrap_tlv(b"\x2D", b"en")
        if qualifier == self.PLI_ACCESS_TECHNOLOGY:
            return self.GENERAL_RESULT_OK, self._wrap_tlv(
                b"\x3F", bytes([int(self.state.access_technology) & 0xFF])
            )
        if qualifier == self.PLI_IMEISV:
            imeisv = _encode_imeisv_bcd(
                _decode_imei_digits(self.state.imei), self.state.software_version
            )
            return self.GENERAL_RESULT_OK, self._wrap_tlv(b"\x62", imeisv)
        if qualifier == self.PLI_BATTERY_STATE:
            return self.GENERAL_RESULT_OK, self._wrap_tlv(
                b"\x63", bytes([self.BATTERY_STATE_NOT_POWERED_BY_BATTERY])
            )
        self._record_flow_event(
            f"PROVIDE LOCAL INFORMATION qualifier 0x{qualifier:02X} is not served; "
            "answered beyond terminal's capabilities."
        )
        return self.GENERAL_RESULT_BEYOND_CAPABILITIES, b""

    def _timer_management_response(
        self,
        qualifier: int,
        fields: dict[str, Any],
    ) -> tuple[int, bytes]:
        """Run TIMER MANAGEMENT per ETSI TS 102 223 §6.4.21 and answer per §6.8.0.

        The Timer identifier (§8.37) is echoed in every response; deactivate
        and get-current-value add the remaining Timer value (§8.38) when
        the timer runs and fail with "action in contradiction with the
        current timer state" (§8.12 '24') when it does not.
        """
        timer_id = fields.get("timer_identifier")
        if not isinstance(timer_id, int):
            return self.GENERAL_RESULT_VALUES_MISSING, b""
        identifier_tlv = self._wrap_tlv(b"\x24", bytes([timer_id & 0xFF]))
        if not 1 <= timer_id <= 8:
            # §8.37: identifiers outside '01'..'08' are reserved.
            return self.GENERAL_RESULT_DATA_NOT_UNDERSTOOD, identifier_tlv
        action = qualifier & 0x03
        if action == 0x03:
            # §8.6: bits 1-2 = 11 is RFU.
            return self.GENERAL_RESULT_DATA_NOT_UNDERSTOOD, identifier_tlv
        if action == 0x00:
            seconds = fields.get("timer_value_seconds")
            if not isinstance(seconds, int):
                return self.GENERAL_RESULT_VALUES_MISSING, identifier_tlv
            self.state.timers[timer_id] = (int(seconds), time.monotonic())
            self._record_flow_event(f"TIMER MANAGEMENT started timer {timer_id} for {seconds}s.")
            return self.GENERAL_RESULT_OK, identifier_tlv
        running = self.state.timers.get(timer_id)
        if running is None:
            self._record_flow_event(
                f"TIMER MANAGEMENT on inactive timer {timer_id}; answered timer-state contradiction."
            )
            return self.GENERAL_RESULT_TIMER_STATE_CONTRADICTION, identifier_tlv
        remaining = max(0, int(running[0]) - int(time.monotonic() - running[1]))
        if action == 0x01:
            del self.state.timers[timer_id]
            self._record_flow_event(f"TIMER MANAGEMENT deactivated timer {timer_id}.")
        return (
            self.GENERAL_RESULT_OK,
            identifier_tlv + self._wrap_tlv(b"\x25", self._encode_timer_value(remaining)),
        )

    @staticmethod
    def _decode_timer_value_seconds(value: bytes) -> int:
        """Decode the §8.38 hour/minute/second semi-octets (TS 23.040 §9.2.3.11) to seconds."""
        parts: list[int] = []
        for byte in bytes(value)[:3]:
            parts.append((byte & 0x0F) * 10 + (byte >> 4))
        return parts[0] * 3600 + parts[1] * 60 + parts[2]

    def _encode_timer_value(self, seconds: int) -> bytes:
        """Encode seconds as the §8.38 Timer value; §6.4.21 bounds a timer to 24 h."""
        bounded = max(0, min(int(seconds), 24 * 3600))
        hours, remainder = divmod(bounded, 3600)
        minutes, secs = divmod(remainder, 60)
        return bytes([self._encode_bcd(hours), self._encode_bcd(minutes), self._encode_bcd(secs)])

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
            root_tag, root_value, _, next_root_offset = self._read_tlv(fetch_data, 0)
        except ValueError as error:
            fields["parse_error"] = str(error)
            return None, 0, fields
        if root_tag != b"\xD0":
            fields["parse_error"] = (
                f"Expected proactive-command tag D0, received {root_tag.hex().upper()}."
            )
            return None, 0, fields
        if next_root_offset != len(fetch_data):
            fields["parse_error"] = (
                f"Proactive command contains {len(fetch_data) - next_root_offset} "
                "trailing byte(s)."
            )
            return None, 0, fields
        command_type = None
        qualifier = 0
        offset = 0
        while offset < len(root_value):
            try:
                tag_bytes, value_bytes, raw_tlv, next_offset = self._read_tlv(root_value, offset)
            except ValueError as error:
                fields["parse_error"] = f"Inner TLV at offset {offset}: {error}"
                return command_type, qualifier, fields
            # ETSI TS 101 220 §7.1.1.1: b8 of a single-byte tag is the CR
            # flag, so an object matches on bits 1-7 however the UICC set it.
            tag_id = -1
            if len(tag_bytes) == 1:
                tag_id = tag_bytes[0] & 0x7F
            if tag_id == 0x01 and len(value_bytes) == 3:
                command_type = value_bytes[1]
                qualifier = value_bytes[2]
                fields["command_details_tlv"] = raw_tlv
            elif tag_id == 0x02 and len(value_bytes) == 2:
                fields["device_identities_tlv"] = raw_tlv
            elif tag_id == 0x19:
                fields["event_list"] = [int(value) for value in value_bytes]
            elif tag_id == 0x04 and len(value_bytes) >= 2:
                # ETSI TS 102 223 §8.8 Duration: time unit ('00' minutes,
                # '01' seconds, '02' tenths of seconds) then the interval.
                fields["duration_unit"] = value_bytes[0]
                fields["duration_value"] = value_bytes[1]
                fields["poll_interval_seconds"] = self._duration_tlv_to_seconds(
                    value_bytes[0], value_bytes[1]
                )
            elif tag_id == 0x24 and len(value_bytes) == 1:
                fields["timer_identifier"] = value_bytes[0]
            elif tag_id == 0x25 and len(value_bytes) == 3:
                fields["timer_value"] = bytes(value_bytes)
                fields["timer_value_seconds"] = self._decode_timer_value_seconds(value_bytes)
            elif tag_id == 0x35:
                fields["bearer_description_tlv"] = raw_tlv
                fields["bearer_description"] = bytes(value_bytes)
            elif tag_id == 0x36:
                fields["channel_data"] = value_bytes
            elif tag_id == 0x39 and len(value_bytes) == 2:
                fields["buffer_size"] = int.from_bytes(value_bytes, "big", signed=False)
                fields["buffer_size_tlv"] = raw_tlv
            elif tag_id == 0x47:
                try:
                    fields["network_access_name"] = self._decode_network_access_name(value_bytes)
                except ValueError as error:
                    fields["network_access_name_raw"] = value_bytes.hex().upper()
                    fields["parse_error"] = str(error)
            elif tag_id == 0x3C and len(value_bytes) == 3:
                fields["transport_protocol_type"] = value_bytes[0]
                fields["transport_port"] = int.from_bytes(value_bytes[1:], "big", signed=False)
            elif tag_id == 0x3E:
                fields["remote_address"] = self._decode_other_address(value_bytes)
            elif tag_id == 0x37 and len(value_bytes) == 1:
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
