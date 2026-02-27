import json
import ssl
import urllib.error
import urllib.request
from typing import Optional, Protocol, Tuple

from smartcard.System import readers
from smartcard.util import toHexString


class ApduChannel(Protocol):
    def send(self, apdu: bytes, log_name: str) -> bytes:
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
        self._conn = self._connect(reader_index)

    def _connect(self, index: int):
        reader_list = readers()
        if len(reader_list) == 0:
            raise RuntimeError("No smart card readers found.")
        connection = reader_list[index].createConnection()
        connection.connect()
        return connection

    def send(self, apdu: bytes, log_name: str) -> bytes:
        print(f"\n[{log_name}] > {toHexString(list(apdu))}")
        response, sw1, sw2 = self._conn.transmit(list(apdu))

        while sw1 == 0x61:
            ext, sw1, sw2 = self._conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            response += ext

        if sw1 == 0x6C:
            corrected_apdu = apdu[:-1] + bytes([sw2])
            return self.send(corrected_apdu, log_name)

        status_hex = f"{sw1:02X}{sw2:02X}"
        print(f"[{log_name}] < SW: {status_hex} Data: {toHexString(response)}")

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

    def send(self, apdu: bytes, log_name: str) -> bytes:
        print(f"\n[{log_name}] > {apdu.hex().upper()}")
        response, sw1, sw2 = self._relay_client.send_apdu(apdu, session_id=self._session_id)

        while sw1 == 0x61:
            get_response = bytes([0x00, 0xC0, 0x00, 0x00, sw2])
            ext, sw1, sw2 = self._relay_client.send_apdu(get_response, session_id=self._session_id)
            response += ext

        if sw1 == 0x6C:
            corrected_apdu = apdu[:-1] + bytes([sw2])
            return self.send(corrected_apdu, log_name)

        status_hex = f"{sw1:02X}{sw2:02X}"
        print(f"[{log_name}] < SW: {status_hex} Data: {response.hex().upper()}")
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
