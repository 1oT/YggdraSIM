# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 Hampus Hellsberg and contributors
# -----------------------------------------------------------------------------

import json
import ssl
import urllib.error
import urllib.request
from typing import Optional, Protocol, Tuple

from smartcard.System import readers


def _encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _wrap_tlv(tag: bytes, value: bytes) -> bytes:
    return tag + _encode_der_length(len(value)) + value


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
        num_octets = length_byte & 0x7F
        if num_octets == 0 or num_octets > 2 or offset + num_octets > len(data):
            raise ValueError("Invalid TLV long-form length.")
        length_value = 0
        for _ in range(num_octets):
            length_value = (length_value << 8) | data[offset]
            offset += 1
    else:
        length_value = length_byte
    value_end = offset + length_value
    if value_end > len(data):
        raise ValueError("TLV value exceeds input length.")
    raw_tlv = data[tag_start:value_end]
    return tag_bytes, data[offset:value_end], raw_tlv, value_end


def _build_terminal_response_for_proactive_command(fetch_data: bytes) -> tuple[bytes, bool]:
    root_value = fetch_data
    tag_bytes, value, _, _ = _read_tlv(fetch_data, 0)
    if tag_bytes == b"\xD0":
        root_value = value
    command_details_tlv = b""
    command_type = None
    device_identities_tlv = bytes.fromhex("82028281")
    offset = 0
    while offset < len(root_value):
        tag_bytes, value, raw_tlv, offset = _read_tlv(root_value, offset)
        if tag_bytes in (b"\x01", b"\x81") and len(value) == 3 and len(command_details_tlv) == 0:
            command_details_tlv = raw_tlv
            command_type = value[1]
            continue
        if tag_bytes in (b"\x02", b"\x82") and len(value) == 2:
            device_identities_tlv = _wrap_tlv(tag_bytes, bytes.fromhex("8281"))
    if len(command_details_tlv) == 0 or command_type is None:
        raise ValueError("FETCH data does not contain command details.")
    body = command_details_tlv + device_identities_tlv + bytes.fromhex("830100")
    return bytes([0x80, 0x14, 0x00, 0x00, len(body)]) + body, command_type == 0x01


class ApduChannel(Protocol):
    def send(self, apdu: bytes, log_name: str) -> bytes:
        pass

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        pass

    def reset(self) -> bool:
        pass

    def bootstrap_stk(self) -> bool:
        pass

    def send_chunked(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2_start: int,
        payload: bytes,
        log_name: str,
        chunk_size: int = 250,
    ) -> bytes:
        pass


class RelayHttpClientJsonHex:
    """HTTP JSON relay client for APDU round-trips."""

    def __init__(self, endpoint: str, timeout_seconds: int = 30, verify_tls: bool = True):
        self._endpoint = endpoint
        self._timeout_seconds = timeout_seconds
        self._verify_tls = verify_tls

    def send_apdu(self, apdu: bytes, session_id: str = "") -> Tuple[bytes, int, int]:
        request_json = {
            "sessionId": session_id,
            "apdu": apdu.hex().upper(),
        }
        payload = json.dumps(request_json).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        ssl_context = None
        if self._endpoint.lower().startswith("https://"):
            if self._verify_tls:
                ssl_context = ssl.create_default_context()
            else:
                ssl_context = ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds, context=ssl_context) as response:
                response_body = response.read().decode("utf-8")
        except urllib.error.URLError as error:
            raise IOError(f"Relay transport error: {error}") from error

        try:
            response_json = json.loads(response_body)
        except json.JSONDecodeError as error:
            raise IOError(f"Invalid relay JSON response: {response_body}") from error

        data_hex = str(response_json.get("data", ""))
        sw1_hex = str(response_json.get("sw1", ""))
        sw2_hex = str(response_json.get("sw2", ""))

        if len(sw1_hex) == 0:
            raise IOError("Relay response missing sw1")
        if len(sw2_hex) == 0:
            raise IOError("Relay response missing sw2")

        try:
            data = bytes.fromhex(data_hex) if len(data_hex) > 0 else b""
            sw1 = int(sw1_hex, 16)
            sw2 = int(sw2_hex, 16)
        except ValueError as error:
            raise IOError(f"Relay response contained invalid hex fields: {response_json}") from error

        return data, sw1, sw2


class PcscApduChannel:
    """Local PC/SC APDU channel with SW handling."""

    def __init__(self, reader_index: int = 0):
        self._reader_index = reader_index
        self._conn = self._connect(reader_index)

    def _connect(self, index: int):
        reader_list = readers()
        if len(reader_list) == 0:
            raise RuntimeError("No smart card readers found.")
        connection = reader_list[index].createConnection()
        connection.connect()
        return connection

    def reset(self) -> bool:
        try:
            self._conn.disconnect()
        except Exception:
            pass
        self._conn = self._connect(self._reader_index)
        return True

    def bootstrap_stk(self) -> bool:
        terminal_profile = bytes.fromhex("8010000015FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00")
        response, sw1, sw2 = self._conn.transmit(list(terminal_profile))
        while sw1 == 0x91:
            fetch_apdu = [0x80, 0x12, 0x00, 0x00, sw2]
            fetch_data, fetch_sw1, fetch_sw2 = self._conn.transmit(fetch_apdu)
            if fetch_sw1 != 0x90 or fetch_sw2 != 0x00:
                raise IOError(f"APDU Failed: {fetch_sw1:02X}{fetch_sw2:02X}")
            terminal_response_body = bytes(fetch_data) + bytes.fromhex("81830100")
            terminal_response = [0x80, 0x14, 0x00, 0x00, len(terminal_response_body)] + list(terminal_response_body)
            response, sw1, sw2 = self._conn.transmit(terminal_response)
        if sw1 != 0x90 or sw2 != 0x00:
            raise IOError(f"APDU Failed: {sw1:02X}{sw2:02X}")
        return True

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        print(f"\n[{log_name}] > {apdu.hex().upper()}")
        response, sw1, sw2 = self._conn.transmit(list(apdu))
        status_hex = f"{sw1:02X}{sw2:02X}"
        print(f"[{log_name}] < SW: {status_hex} Data: {bytes(response).hex().upper()}")
        return bytes(response), sw1, sw2

    def send(self, apdu: bytes, log_name: str) -> bytes:
        response, sw1, sw2 = self.exchange(apdu, log_name)

        while sw1 == 0x61:
            get_response_cla = 0x00
            if len(apdu) > 0:
                get_response_cla = apdu[0] & 0x03
            ext, sw1, sw2 = self.exchange(
                bytes([get_response_cla, 0xC0, 0x00, 0x00, sw2]),
                f"{log_name} [GET RESPONSE]",
            )
            response += ext

        response = self._handle_proactive_refresh(response, sw1, sw2, log_name)
        if sw1 == 0x91 and sw2 > 0:
            return bytes(response)

        if sw1 == 0x6C:
            corrected_apdu = apdu[:-1] + bytes([sw2])
            return self.send(corrected_apdu, log_name)

        status_hex = f"{sw1:02X}{sw2:02X}"
        if status_hex not in ("9000", "9100"):
            raise IOError(f"APDU Failed: {status_hex}")

        return bytes(response)

    def _handle_proactive_refresh(self, response: bytes, sw1: int, sw2: int, log_name: str) -> bytes:
        if sw1 != 0x91 or sw2 <= 0:
            return response
        fetch_data, fetch_sw1, fetch_sw2 = self.exchange(
            bytes([0x80, 0x12, 0x00, 0x00, sw2]),
            f"{log_name} [FETCH]",
        )
        if fetch_sw1 != 0x90 or fetch_sw2 != 0x00:
            raise IOError(f"APDU Failed: {fetch_sw1:02X}{fetch_sw2:02X}")
        terminal_response, is_refresh = _build_terminal_response_for_proactive_command(fetch_data)
        if is_refresh is False:
            raise IOError("APDU Failed: proactive command is not supported (expected REFRESH)")
        _, tr_sw1, tr_sw2 = self.exchange(
            terminal_response,
            f"{log_name} [TERMINAL RESPONSE]",
        )
        if tr_sw1 != 0x90 or tr_sw2 != 0x00:
            raise IOError(f"APDU Failed: {tr_sw1:02X}{tr_sw2:02X}")
        print("[*] Proactive REFRESH acknowledged; resetting card transport.")
        self.reset()
        return response

    def send_chunked(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2_start: int,
        payload: bytes,
        log_name: str,
        chunk_size: int = 250,
    ) -> bytes:
        total = len(payload)
        offset = 0
        block = p2_start
        response = b""

        print(f"\n--- Transmitting {log_name} ({total} bytes) ---")
        while offset < total:
            end_offset = offset + chunk_size
            chunk = payload[offset:end_offset]
            is_last_chunk = end_offset >= total
            current_p1 = p1
            if not is_last_chunk:
                current_p1 = 0x11
            apdu = bytes([cla, ins, current_p1, block, len(chunk)]) + chunk
            print(f"  > Block {block:02X} (Len={len(chunk)}) P1={current_p1:02X}")
            response = self.send(apdu, f"{log_name} [Block {block}]")
            offset += chunk_size
            block += 1

        return response


class RelayApduChannel:
    """Relay-backed APDU channel using HTTP JSON transport."""

    def __init__(self, relay_client: RelayHttpClientJsonHex, session_id: str = ""):
        self._relay_client = relay_client
        self._session_id = session_id

    def reset(self) -> bool:
        return False

    def bootstrap_stk(self) -> bool:
        terminal_profile = bytes.fromhex("8010000015FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00")
        response, sw1, sw2 = self._relay_client.send_apdu(terminal_profile, session_id=self._session_id)
        while sw1 == 0x91:
            fetch_apdu = bytes([0x80, 0x12, 0x00, 0x00, sw2])
            fetch_data, fetch_sw1, fetch_sw2 = self._relay_client.send_apdu(fetch_apdu, session_id=self._session_id)
            if fetch_sw1 != 0x90 or fetch_sw2 != 0x00:
                raise IOError(f"APDU Failed: {fetch_sw1:02X}{fetch_sw2:02X}")
            terminal_response_body = fetch_data + bytes.fromhex("81830100")
            terminal_response = bytes([0x80, 0x14, 0x00, 0x00, len(terminal_response_body)]) + terminal_response_body
            response, sw1, sw2 = self._relay_client.send_apdu(terminal_response, session_id=self._session_id)
        if sw1 != 0x90 or sw2 != 0x00:
            raise IOError(f"APDU Failed: {sw1:02X}{sw2:02X}")
        return True

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        print(f"\n[{log_name}] > {apdu.hex().upper()}")
        response, sw1, sw2 = self._relay_client.send_apdu(apdu, session_id=self._session_id)
        status_hex = f"{sw1:02X}{sw2:02X}"
        print(f"[{log_name}] < SW: {status_hex} Data: {response.hex().upper()}")
        return response, sw1, sw2

    def send(self, apdu: bytes, log_name: str) -> bytes:
        response, sw1, sw2 = self.exchange(apdu, log_name)

        while sw1 == 0x61:
            get_response = bytes([0x00, 0xC0, 0x00, 0x00, sw2])
            ext, sw1, sw2 = self.exchange(get_response, f"{log_name} [GET RESPONSE]")
            response += ext

        response = self._handle_proactive_refresh(response, sw1, sw2, log_name)
        if sw1 == 0x91 and sw2 > 0:
            return response

        if sw1 == 0x6C:
            corrected_apdu = apdu[:-1] + bytes([sw2])
            return self.send(corrected_apdu, log_name)

        status_hex = f"{sw1:02X}{sw2:02X}"
        if status_hex not in ("9000", "9100"):
            raise IOError(f"APDU Failed: {status_hex}")

        return response

    def _handle_proactive_refresh(self, response: bytes, sw1: int, sw2: int, log_name: str) -> bytes:
        if sw1 != 0x91 or sw2 <= 0:
            return response
        fetch_data, fetch_sw1, fetch_sw2 = self.exchange(
            bytes([0x80, 0x12, 0x00, 0x00, sw2]),
            f"{log_name} [FETCH]",
        )
        if fetch_sw1 != 0x90 or fetch_sw2 != 0x00:
            raise IOError(f"APDU Failed: {fetch_sw1:02X}{fetch_sw2:02X}")
        terminal_response, is_refresh = _build_terminal_response_for_proactive_command(fetch_data)
        if is_refresh is False:
            raise IOError("APDU Failed: proactive command is not supported (expected REFRESH)")
        _, tr_sw1, tr_sw2 = self.exchange(
            terminal_response,
            f"{log_name} [TERMINAL RESPONSE]",
        )
        if tr_sw1 != 0x90 or tr_sw2 != 0x00:
            raise IOError(f"APDU Failed: {tr_sw1:02X}{tr_sw2:02X}")
        print("[*] Proactive REFRESH acknowledged; resetting card transport.")
        self.reset()
        return response

    def send_chunked(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2_start: int,
        payload: bytes,
        log_name: str,
        chunk_size: int = 250,
    ) -> bytes:
        total = len(payload)
        offset = 0
        block = p2_start
        response = b""

        print(f"\n--- Transmitting {log_name} ({total} bytes) ---")
        while offset < total:
            end_offset = offset + chunk_size
            chunk = payload[offset:end_offset]
            is_last_chunk = end_offset >= total
            current_p1 = p1
            if not is_last_chunk:
                current_p1 = 0x11
            apdu = bytes([cla, ins, current_p1, block, len(chunk)]) + chunk
            print(f"  > Block {block:02X} (Len={len(chunk)}) P1={current_p1:02X}")
            response = self.send(apdu, f"{log_name} [Block {block}]")
            offset += chunk_size
            block += 1

        return response


class SGP22Transport:
    """
    Compatibility transport wrapper.
    Defaults to local PC/SC, can be switched to relay mode.
    """

    def __init__(
        self,
        reader_index: int = 0,
        relay_client: Optional[RelayHttpClientJsonHex] = None,
        relay_session_id: str = "",
    ):
        if relay_client is None:
            self._channel: ApduChannel = PcscApduChannel(reader_index=reader_index)
        else:
            self._channel = RelayApduChannel(relay_client=relay_client, session_id=relay_session_id)

    def send(self, apdu: bytes, log_name: str) -> bytes:
        return self._channel.send(apdu, log_name)

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        return self._channel.exchange(apdu, log_name)

    def reset(self) -> bool:
        reset_method = getattr(self._channel, "reset", None)
        if callable(reset_method):
            return bool(reset_method())
        return False

    def bootstrap_stk(self) -> bool:
        bootstrap_method = getattr(self._channel, "bootstrap_stk", None)
        if callable(bootstrap_method):
            return bool(bootstrap_method())
        return False

    def send_chunked(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2_start: int,
        payload: bytes,
        log_name: str,
        chunk_size: int = 250,
    ) -> bytes:
        return self._channel.send_chunked(
            cla=cla,
            ins=ins,
            p1=p1,
            p2_start=p2_start,
            payload=payload,
            log_name=log_name,
            chunk_size=chunk_size,
        )
