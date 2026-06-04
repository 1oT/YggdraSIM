# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 transport: selects and initialises the direct PC/SC card-side bearer."""
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
from yggdrasim_common.nord_palette import NORD


# Trace colour roles, anchored to the canonical Nord palette so the
# SCP11 transcript matches the launcher banner and the doctor output.
_TRACE_RESET = NORD.RESET
_TRACE_LOCAL = NORD.CYAN     # frost-1 -- on-card / local card chatter
_TRACE_EIM = NORD.HEADER     # frost-0 -- eIM dialogue
_TRACE_SMDP = NORD.BLUE      # frost-2 -- SM-DP+ dialogue
_TRACE_OK = NORD.GREEN       # aurora-green -- 9000 / success swatches
_TRACE_FAIL = NORD.RED       # aurora-red   -- non-success status words
_TRACE_INFO = NORD.WHITE     # snow-2  -- neutral informational text


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
    # Concise mode: the outer send() loop resolves ISO 7816 continuation
    # status words (61xx / 6Cxx) via GET RESPONSE / Le correction before
    # returning to the caller. Those intermediate exchanges are
    # implementation detail - only the initial command label and the
    # final SW are operator-relevant.
    if label.endswith("[GET RESPONSE]"):
        return
    print(f"\n{label_color}[*] {label}{_TRACE_RESET}")
    if status_hex in ("9000", "9100"):
        return
    if sw1 in (0x61, 0x6C):
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

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        pass

    def get_raw_apdu_logging(self) -> bool:
        pass

    def set_quiet_apdu_logging(self, enabled: bool) -> None:
        pass

    def get_quiet_apdu_logging(self) -> bool:
        pass


class PcscApduChannel:
    """Local PC/SC APDU channel with SW handling."""

    def __init__(self, reader_index: int = 0):
        self._reader_index = reader_index
        self._conn = self._connect(reader_index)
        self._raw_apdu_logging = False
        self._quiet_apdu_logging = False

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

    def exchange(self, apdu: bytes, log_name: str) -> Tuple[bytes, int, int]:
        """Send one APDU and return (response_bytes, SW1, SW2), logging the exchange under *log_name*."""
        if self._conn is None:
            raise IOError("PC/SC channel is disconnected.")
        response, sw1, sw2 = self._conn.transmit(list(apdu))
        payload = bytes(response)
        if bool(getattr(self, "_quiet_apdu_logging", False)) is False:
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
        """Send an APDU and follow GET RESPONSE chaining (SW 61xx) to retrieve the full response."""
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
        """Fragment *data* into STORE-DATA chunks and dispatch each via ``exchange`` (SGP.22 §3.1.3)."""
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

    def set_quiet_apdu_logging(self, enabled: bool) -> None:
        self._quiet_apdu_logging = bool(enabled)

    def get_quiet_apdu_logging(self) -> bool:
        return bool(self._quiet_apdu_logging)


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
        exchange_method = getattr(self._channel, "exchange", None)
        if callable(exchange_method):
            return exchange_method(apdu, log_name)
        response = self._channel.send(apdu, log_name)
        return response, 0x90, 0x00

    def reset(self) -> bool:
        """Disconnect and re-connect the underlying card channel, clearing any active session state."""
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

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        setter = getattr(self._channel, "set_raw_apdu_logging", None)
        if callable(setter):
            setter(bool(enabled))

    def get_raw_apdu_logging(self) -> bool:
        getter = getattr(self._channel, "get_raw_apdu_logging", None)
        if callable(getter):
            return bool(getter())
        return True

    def set_quiet_apdu_logging(self, enabled: bool) -> None:
        setter = getattr(self._channel, "set_quiet_apdu_logging", None)
        if callable(setter):
            setter(bool(enabled))

    def get_quiet_apdu_logging(self) -> bool:
        getter = getattr(self._channel, "get_quiet_apdu_logging", None)
        if callable(getter):
            return bool(getter())
        return False
