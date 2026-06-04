# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-test transport: BPP STORE-DATA framing dispatched through the in-process simulated card channel."""
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
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

import time
from typing import Protocol, Tuple

from yggdrasim_common.session_recording import emit_apdu_trace_event
from yggdrasim_common.card_backend import create_card_connection, is_simulated_card_backend
from yggdrasim_common.apdu_recorder import wrap_connection


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
        """Send an APDU and follow GET RESPONSE chaining (SW 61xx) to retrieve the full response."""
        pass

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        """Send one APDU and return (response_bytes, SW1, SW2), logging the exchange under *log_name*."""
        pass

    def reset(self) -> bool:
        """Disconnect and re-connect the underlying card channel, clearing any active session state."""
        pass

    def disconnect(self) -> None:
        """Release the underlying card channel without sending any card-side APDUs."""
        pass

    def bootstrap_stk(self) -> bool:
        """Send the STK OPEN-CHANNEL bootstrap command sequence to establish the BIP data channel."""
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
        """Fragment *data* into STORE-DATA chunks and dispatch each via ``exchange`` (SGP.22 §3.1.3)."""
        pass


class PcscApduChannel:
    """Local PC/SC APDU channel with SW handling."""

    def __init__(self, reader_index: int = 0):
        self._reader_index = reader_index
        self._conn = self._connect(reader_index)

    def _connect(self, index: int):
        if is_simulated_card_backend():
            return create_card_connection(reader_index=index)
        return self._connect_after_power_cycle(index)

    def _connect_after_power_cycle(self, index: int):
        from smartcard.System import readers

        reader_list = readers()
        if index < 0 or index >= len(reader_list):
            raise RuntimeError(
                f"Reader index {index} is out of range. Detected readers: {len(reader_list)}."
            )
        connection = reader_list[index].createConnection()
        try:
            from smartcard.scard import SCARD_UNPOWER_CARD
        except Exception:
            SCARD_UNPOWER_CARD = None
        if SCARD_UNPOWER_CARD is None:
            connection.connect()
        else:
            try:
                connection.connect(disposition=SCARD_UNPOWER_CARD)
            except TypeError:
                connection.connect()
                try:
                    connection.disposition = SCARD_UNPOWER_CARD
                except Exception:
                    pass
        self._reset_connected_card(connection)
        try:
            reader_name = str(reader_list[index]) or f"pcsc#{index}"
        except Exception:
            reader_name = f"pcsc#{index}"
        return wrap_connection(connection, source=reader_name)

    def _reset_connected_card(self, connection) -> None:
        try:
            from smartcard.scard import (
                SCARD_PROTOCOL_T0,
                SCARD_PROTOCOL_T1,
                SCARD_RESET_CARD,
                SCARD_S_SUCCESS,
                SCARD_SHARE_SHARED,
                SCardReconnect,
            )
        except Exception:
            return
        hcard = getattr(connection, "hcard", None)
        if hcard is None:
            return
        protocol = getattr(connection, "protocol", None)
        if protocol is None:
            get_protocol = getattr(connection, "getProtocol", None)
            if callable(get_protocol):
                try:
                    protocol = get_protocol()
                except Exception:
                    protocol = None
        if not protocol:
            protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1
        try:
            result, active_protocol = SCardReconnect(
                hcard,
                SCARD_SHARE_SHARED,
                protocol,
                SCARD_RESET_CARD,
            )
        except Exception:
            return
        if result == SCARD_S_SUCCESS:
            set_protocol = getattr(connection, "setProtocol", None)
            if callable(set_protocol):
                try:
                    set_protocol(active_protocol)
                except Exception:
                    pass

    def begin_transaction(self) -> None:
        try:
            from smartcard.scard import SCardBeginTransaction
            SCardBeginTransaction(self._conn.hcard)
        except Exception:
            pass

    def end_transaction(self) -> None:
        try:
            from smartcard.scard import SCARD_LEAVE_CARD, SCardEndTransaction
            SCardEndTransaction(self._conn.hcard, SCARD_LEAVE_CARD)
        except Exception:
            pass

    def reset(self) -> bool:
        """Power-cycle and reconnect the card channel, clearing selected application state."""
        self.disconnect()
        time.sleep(0.2)
        self._conn = self._connect_after_power_cycle(self._reader_index)
        return True

    def disconnect(self) -> None:
        """Release the PC/SC handle and unpower the card so the next connect starts cleanly."""
        conn = getattr(self, "_conn", None)
        if conn is None:
            return
        try:
            from smartcard.scard import SCARD_UNPOWER_CARD
        except Exception:
            SCARD_UNPOWER_CARD = None

        disconnect_error = None
        try:
            if SCARD_UNPOWER_CARD is not None:
                try:
                    conn.disposition = SCARD_UNPOWER_CARD
                except Exception:
                    pass
            try:
                conn.disconnect()
                return
            except TypeError as error:
                disconnect_error = error
            if SCARD_UNPOWER_CARD is not None:
                try:
                    conn.disconnect(SCARD_UNPOWER_CARD)
                    return
                except TypeError as error:
                    disconnect_error = error
                try:
                    conn.disconnect(disposition=SCARD_UNPOWER_CARD)
                    return
                except TypeError as error:
                    disconnect_error = error
        except Exception as error:
            disconnect_error = error
        finally:
            self._conn = None

        if disconnect_error is not None:
            raise RuntimeError(f"PC/SC disconnect failed: {disconnect_error}") from disconnect_error

    def bootstrap_stk(self) -> bool:
        """Send the STK OPEN-CHANNEL bootstrap command sequence to establish the BIP data channel."""
        terminal_profile = bytes.fromhex("8010000015FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00")
        _, sw1, sw2 = self.exchange(terminal_profile, "STK INIT: TERMINAL PROFILE")
        while sw1 == 0x91:
            fetch_data, fetch_sw1, fetch_sw2 = self.exchange(
                bytes([0x80, 0x12, 0x00, 0x00, sw2]),
                "STK INIT: FETCH",
            )
            if fetch_sw1 != 0x90 or fetch_sw2 != 0x00:
                raise IOError(f"APDU Failed: {fetch_sw1:02X}{fetch_sw2:02X}")
            terminal_response_body = bytes(fetch_data) + bytes.fromhex("81830100")
            terminal_response = bytes(
                [0x80, 0x14, 0x00, 0x00, len(terminal_response_body)]
            ) + terminal_response_body
            _, sw1, sw2 = self.exchange(
                terminal_response,
                "STK INIT: TERMINAL RESPONSE",
            )
        if sw1 != 0x90 or sw2 != 0x00:
            raise IOError(f"APDU Failed: {sw1:02X}{sw2:02X}")
        return True

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        """Send one APDU and return (response_bytes, SW1, SW2), logging the exchange under *log_name*."""
        if self._conn is None:
            raise IOError("PC/SC channel is disconnected.")
        print(f"\n[{log_name}] > {apdu.hex().upper()}")
        response, sw1, sw2 = self._conn.transmit(list(apdu))
        status_hex = f"{sw1:02X}{sw2:02X}"
        print(f"[{log_name}] < SW: {status_hex} Data: {bytes(response).hex().upper()}")
        payload = bytes(response)
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
        """Send an APDU and follow GET RESPONSE chaining (SW 61xx) to retrieve the full response."""
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
        """Fragment *data* into STORE-DATA chunks and dispatch each via ``exchange`` (SGP.22 §3.1.3)."""
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
    Uses direct PC/SC only.
    """

    def __init__(
        self,
        reader_index: int = 0,
    ):
        self._channel: ApduChannel = PcscApduChannel(reader_index=reader_index)

    def send(self, apdu: bytes, log_name: str) -> bytes:
        """Send an APDU and follow GET RESPONSE chaining (SW 61xx) to retrieve the full response."""
        return self._channel.send(apdu, log_name)

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        """Send one APDU and return (response_bytes, SW1, SW2), logging the exchange under *log_name*."""
        return self._channel.exchange(apdu, log_name)

    def reset(self) -> bool:
        """Disconnect and re-connect the underlying card channel, clearing any active session state."""
        reset_method = getattr(self._channel, "reset", None)
        if callable(reset_method):
            return bool(reset_method())
        return False

    def bootstrap_stk(self) -> bool:
        """Send the STK OPEN-CHANNEL bootstrap command sequence to establish the BIP data channel."""
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
        """Fragment *data* into STORE-DATA chunks and dispatch each via ``exchange`` (SGP.22 §3.1.3)."""
        return self._channel.send_chunked(
            cla=cla,
            ins=ins,
            p1=p1,
            p2_start=p2_start,
            payload=payload,
            log_name=log_name,
            chunk_size=chunk_size,
        )
