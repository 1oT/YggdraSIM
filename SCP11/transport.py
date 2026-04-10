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

from yggdrasim_common.session_recording import emit_apdu_trace_event
from yggdrasim_common.card_backend import create_card_connection


_TRACE_RESET = "\033[0m"
_TRACE_LOCAL = "\033[38;2;147;247;255m"
_TRACE_EIM = "\033[38;2;95;220;203m"
_TRACE_SMDP = "\033[38;2;138;167;255m"
_TRACE_OK = "\033[38;2;141;255;141m"
_TRACE_FAIL = "\033[38;2;255;154;154m"
_TRACE_INFO = "\033[38;2;247;252;255m"


def _trace_label_color(log_name: str) -> str:
    label = str(log_name or "").strip()
    if label.startswith("[eIM]"):
        return _TRACE_EIM
    if label.startswith("[SM-DP+]"):
        return _TRACE_SMDP
    if label.startswith("LOCAL:"):
        return _TRACE_LOCAL
    return _TRACE_INFO


def _trace_status_color(sw1: int, sw2: int) -> str:
    status_hex = f"{sw1:02X}{sw2:02X}"
    if status_hex in ("9000", "9100"):
        return _TRACE_OK
    return _TRACE_FAIL


def _print_apdu_exchange(
    log_name: str,
    apdu: bytes,
    response: bytes,
    sw1: int,
    sw2: int,
    *,
    raw: bool,
) -> None:
    label = str(log_name or "").strip() or "APDU"
    label_color = _trace_label_color(label)
    status_hex = f"{sw1:02X}{sw2:02X}"
    if raw:
        status_color = _trace_status_color(sw1, sw2)
        print(f"\n{label_color}[{label}] > {apdu.hex().upper()}{_TRACE_RESET}")
        print(
            f"{status_color}[{label}] < SW: {status_hex} Data: "
            f"{bytes(response).hex().upper()}{_TRACE_RESET}"
        )
        return
    print(f"\n{label_color}[*] {label}{_TRACE_RESET}")
    if status_hex in ("9000", "9100"):
        return
    status_color = _trace_status_color(sw1, sw2)
    print(f"{status_color}    -> SW {status_hex} len={len(response)}{_TRACE_RESET}")


def _print_chunk_banner(log_name: str, total: int, *, raw: bool) -> None:
    label = str(log_name or "").strip() or "APDU"
    label_color = _trace_label_color(label)
    if raw:
        print(f"\n{label_color}--- Transmitting {label} ({total} bytes) ---{_TRACE_RESET}")
        return
    print(f"\n{label_color}[*] {label} total_bytes={total}{_TRACE_RESET}")


class ApduChannel(Protocol):
    def send(self, apdu: bytes, log_name: str) -> bytes:
        pass

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        pass

    def reset(self) -> bool:
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

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        pass

    def get_raw_apdu_logging(self) -> bool:
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
        self._raw_apdu_logging = False

    def _connect(self, index: int):
        return create_card_connection(reader_index=index)

    def reset(self) -> bool:
        try:
            self._conn.disconnect()
        except Exception:
            pass
        self._conn = self._connect(self._reader_index)
        return True

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        response, sw1, sw2 = self._conn.transmit(list(apdu))
        payload = bytes(response)
        _print_apdu_exchange(
            log_name,
            apdu,
            payload,
            sw1,
            sw2,
            raw=bool(self._raw_apdu_logging),
        )
        emit_apdu_trace_event(
            log_name=log_name,
            apdu=apdu,
            response=payload,
            sw1=sw1,
            sw2=sw2,
            transport=self.__class__.__name__,
        )
        return payload, sw1, sw2

    def send(self, apdu: bytes, log_name: str) -> bytes:
        response, sw1, sw2 = self.exchange(apdu, log_name)

        while sw1 == 0x61:
            ext, sw1, sw2 = self.exchange(
                bytes([0x00, 0xC0, 0x00, 0x00, sw2]),
                f"{log_name} [GET RESPONSE]",
            )
            response += ext

        if sw1 == 0x6C:
            corrected_apdu = apdu[:-1] + bytes([sw2])
            return self.send(corrected_apdu, log_name)

        status_hex = f"{sw1:02X}{sw2:02X}"
        if status_hex not in ("9000", "9100"):
            raise IOError(f"APDU Failed: {status_hex}")

        return bytes(response)

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

        _print_chunk_banner(log_name, total, raw=bool(self._raw_apdu_logging))
        while offset < total:
            end_offset = offset + chunk_size
            chunk = payload[offset:end_offset]
            is_last_chunk = end_offset >= total
            current_p1 = p1
            if not is_last_chunk:
                current_p1 = 0x11
            apdu = bytes([cla, ins, current_p1, block, len(chunk)]) + chunk
            if self._raw_apdu_logging:
                print(f"  > Block {block:02X} (Len={len(chunk)}) P1={current_p1:02X}")
            response = self.send(apdu, f"{log_name} [Block {block}]")
            offset += chunk_size
            block += 1

        return response

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        self._raw_apdu_logging = bool(enabled)

    def get_raw_apdu_logging(self) -> bool:
        return bool(self._raw_apdu_logging)


class RelayApduChannel:
    """Relay-backed APDU channel using HTTP JSON transport."""

    def __init__(self, relay_client: RelayHttpClientJsonHex, session_id: str = ""):
        self._relay_client = relay_client
        self._session_id = session_id
        self._raw_apdu_logging = False

    def reset(self) -> bool:
        return False

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        response, sw1, sw2 = self._relay_client.send_apdu(apdu, session_id=self._session_id)
        _print_apdu_exchange(
            log_name,
            apdu,
            response,
            sw1,
            sw2,
            raw=bool(self._raw_apdu_logging),
        )
        emit_apdu_trace_event(
            log_name=log_name,
            apdu=apdu,
            response=response,
            sw1=sw1,
            sw2=sw2,
            transport=self.__class__.__name__,
        )
        return response, sw1, sw2

    def send(self, apdu: bytes, log_name: str) -> bytes:
        response, sw1, sw2 = self.exchange(apdu, log_name)

        while sw1 == 0x61:
            ext, sw1, sw2 = self.exchange(
                bytes([0x00, 0xC0, 0x00, 0x00, sw2]),
                f"{log_name} [GET RESPONSE]",
            )
            response += ext

        if sw1 == 0x6C:
            corrected_apdu = apdu[:-1] + bytes([sw2])
            return self.send(corrected_apdu, log_name)

        status_hex = f"{sw1:02X}{sw2:02X}"
        if status_hex not in ("9000", "9100"):
            raise IOError(f"APDU Failed: {status_hex}")

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

        _print_chunk_banner(log_name, total, raw=bool(self._raw_apdu_logging))
        while offset < total:
            end_offset = offset + chunk_size
            chunk = payload[offset:end_offset]
            is_last_chunk = end_offset >= total
            current_p1 = p1
            if not is_last_chunk:
                current_p1 = 0x11
            apdu = bytes([cla, ins, current_p1, block, len(chunk)]) + chunk
            if self._raw_apdu_logging:
                print(f"  > Block {block:02X} (Len={len(chunk)}) P1={current_p1:02X}")
            response = self.send(apdu, f"{log_name} [Block {block}]")
            offset += chunk_size
            block += 1

        return response

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        self._raw_apdu_logging = bool(enabled)

    def get_raw_apdu_logging(self) -> bool:
        return bool(self._raw_apdu_logging)


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
        exchange_method = getattr(self._channel, "exchange", None)
        if callable(exchange_method):
            return exchange_method(apdu, log_name)
        response = self._channel.send(apdu, log_name)
        return response, 0x90, 0x00

    def reset(self) -> bool:
        reset_method = getattr(self._channel, "reset", None)
        if callable(reset_method):
            return bool(reset_method())
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

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        setter = getattr(self._channel, "set_raw_apdu_logging", None)
        if callable(setter):
            setter(bool(enabled))

    def get_raw_apdu_logging(self) -> bool:
        getter = getattr(self._channel, "get_raw_apdu_logging", None)
        if callable(getter):
            return bool(getter())
        return True
