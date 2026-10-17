# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 transport: the direct PC/SC card-side bearer shared by every SCP11 shell."""
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

import re
import sys
import threading
import time
from typing import Callable, Optional, Protocol, Tuple

from yggdrasim_common.session_recording import emit_apdu_trace_event
from yggdrasim_common.card_backend import create_card_connection, is_simulated_card_backend
from yggdrasim_common.apdu_recorder import wrap_connection
from yggdrasim_common.nord_palette import NORD
from yggdrasim_common.process_debug import debug_print, is_global_debug_enabled
from SCP11.shared.trace_dump import print_store_data_chunk_plan, split_tlv_aware_chunks


# Trace colour roles, read from the active palette so the SCP11
# transcript matches the launcher banner and the doctor output under
# whichever theme YGGDRASIM_CLI_THEME selects. Read per call rather
# than snapshotted at import: a module constant would pin whichever
# theme was active when this module first loaded.


def _trace_reset() -> str:
    return NORD.RESET


def _trace_label_color(log_name: str) -> str:
    label = str(log_name or "").strip()
    if label.startswith("[eIM]"):
        return NORD.HEADER      # frost-0 -- eIM dialogue
    if label.startswith("[SM-DP+]"):
        return NORD.BLUE        # frost-2 -- SM-DP+ dialogue
    if label.startswith("LOCAL:"):
        return NORD.CYAN        # frost-1 -- on-card / local card chatter
    return NORD.WHITE           # snow-2  -- neutral informational text


def _trace_status_color(sw1: int, sw2: int) -> str:
    status_hex = f"{sw1:02X}{sw2:02X}"
    if status_hex in ("9000", "9100"):
        return NORD.GREEN       # aurora-green -- 9000 / success swatches
    return NORD.RED             # aurora-red   -- non-success status words


# A raw-mode (--debug) exchange goes to the renderer a plugin installs, which
# prints it in its own form; None keeps the two lines below. The slot is
# process-wide like session_recording's APDU trace listener, because every SCP11
# shell builds its channels here.
ApduTraceRenderer = Callable[[str, bytes, bytes, int, int], None]

_APDU_TRACE_RENDERER: Optional[ApduTraceRenderer] = None
_APDU_TRACE_RENDERER_LOCK = threading.Lock()


def set_apdu_trace_renderer(
    renderer: Optional[ApduTraceRenderer],
) -> Optional[ApduTraceRenderer]:
    """Print raw-mode exchanges through *renderer* (label, command, response, SW1, SW2).

    Returns the renderer it replaces, so a caller can put that one back.
    """
    global _APDU_TRACE_RENDERER
    with _APDU_TRACE_RENDERER_LOCK:
        previous = _APDU_TRACE_RENDERER
        _APDU_TRACE_RENDERER = renderer
    return previous


def _apdu_trace_renderer() -> Optional[ApduTraceRenderer]:
    with _APDU_TRACE_RENDERER_LOCK:
        return _APDU_TRACE_RENDERER


# The lines a flow prints between those exchanges under the debug flag (a phase
# heading, the logical channel ES10b settled on) go to a second renderer, so a
# plugin prints them in the same form; None keeps the "[*] " line.
ApduTraceNoteRenderer = Callable[[str], None]

_APDU_TRACE_NOTE_RENDERER: Optional[ApduTraceNoteRenderer] = None


def set_apdu_trace_note_renderer(
    renderer: Optional[ApduTraceNoteRenderer],
) -> Optional[ApduTraceNoteRenderer]:
    """Print the debug trace's narrative lines through *renderer* (the line's text).

    Returns the renderer it replaces, so a caller can put that one back.
    """
    global _APDU_TRACE_NOTE_RENDERER
    with _APDU_TRACE_RENDERER_LOCK:
        previous = _APDU_TRACE_NOTE_RENDERER
        _APDU_TRACE_NOTE_RENDERER = renderer
    return previous


def _apdu_trace_note_renderer() -> Optional[ApduTraceNoteRenderer]:
    with _APDU_TRACE_RENDERER_LOCK:
        return _APDU_TRACE_NOTE_RENDERER


def print_apdu_trace_note(text: str, *, heading: bool = False) -> None:
    """Print one narrative line of the debug trace, silent while the global debug flag is off.

    A *heading* opens a phase; the built-in form puts a blank line above it.
    """
    if is_global_debug_enabled() is False:
        return
    renderer = _apdu_trace_note_renderer()
    if renderer is not None:
        try:
            renderer(str(text))
            return
        except Exception:
            # As with an exchange: the line prints in the built-in form below.
            pass
    debug_print(("\n" if heading else "") + f"[*] {text}")


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
        renderer = _apdu_trace_renderer()
        if renderer is not None:
            try:
                renderer(label, bytes(apdu), bytes(response), int(sw1), int(sw2))
                return
            except Exception:
                # The trace decorates a live exchange: when the renderer
                # fails, this exchange prints as the raw hex below.
                pass
        status_color = _trace_status_color(sw1, sw2)
        print(f"\n{label_color}[{label}] > {apdu.hex().upper()}{_trace_reset()}")
        print(
            f"{status_color}[{label}] < SW: {status_hex} Data: "
            f"{bytes(response).hex().upper()}{_trace_reset()}"
        )
        return
    # Concise mode: the outer send() loop resolves ISO 7816 continuation
    # status words (61xx / 6Cxx) via GET RESPONSE / Le correction before
    # returning to the caller. Those intermediate exchanges are
    # implementation detail - only the initial command label and the
    # final SW are operator-relevant.
    if label.endswith("[GET RESPONSE]"):
        return
    print(f"\n{label_color}[*] {label}{_trace_reset()}")
    if status_hex in ("9000", "9100"):
        return
    if sw1 in (0x61, 0x6C):
        return
    status_color = _trace_status_color(sw1, sw2)
    print(f"{status_color}    -> SW {status_hex} len={len(response)}{_trace_reset()}")


def _print_chunk_banner(log_name: str, total: int, *, raw: bool) -> None:
    label = str(log_name or "").strip() or "APDU"
    label_color = _trace_label_color(label)
    if raw:
        print(f"\n{label_color}--- Transmitting {label} ({total} bytes) ---{_trace_reset()}")
        return
    print(f"\n{label_color}[*] {label} total_bytes={total}{_trace_reset()}")


def _encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    octets = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


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
    try:
        root_tag, inner_value, _, _ = _read_tlv(fetch_data, 0)
    except Exception as error:
        raise ValueError(f"Could not parse FETCH data: {error}") from error
    if root_tag == b"\xD0":
        root_value = inner_value
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


def _build_proactive_terminal_response(fetch_data: bytes) -> bytes:
    """Build a generic TERMINAL RESPONSE that echoes the proactive command details."""
    root_value = fetch_data
    tag_bytes, value, _, _ = _read_tlv(fetch_data, 0)
    if tag_bytes == b"\xD0":
        root_value = value
    command_details_tlv = b""
    device_identities_tlv = bytes.fromhex("02028281")
    offset = 0
    while offset < len(root_value):
        tag_bytes, value, raw_tlv, offset = _read_tlv(root_value, offset)
        if tag_bytes in (b"\x01", b"\x81") and len(value) == 3 and len(command_details_tlv) == 0:
            command_details_tlv = raw_tlv
            continue
        if tag_bytes in (b"\x02", b"\x82") and len(value) == 2:
            device_identities_tlv = _wrap_tlv(b"\x02", bytes.fromhex("8281"))
    if len(command_details_tlv) == 0:
        return bytes.fromhex("801400000D810301240001028281030100")
    body = command_details_tlv + device_identities_tlv + bytes.fromhex("030100")
    return bytes([0x80, 0x14, 0x00, 0x00, len(body)]) + body


# 256 GET RESPONSE rounds of at most 256 bytes each: far above any ES10 or
# GP answer, low enough that a card which never stops announcing data
# cannot hold the shell.
_MAX_GET_RESPONSE_ROUNDS = 256

# pyscard CardConnection.T1_protocol, the same value as PC/SC SCARD_PROTOCOL_T1.
_CARD_PROTOCOL_T1 = 0x00000002

ApduExchange = Callable[[bytes, str], Tuple[bytes, int, int]]


def resend_with_le(command: bytes, le: int) -> Optional[bytes]:
    """Return *command* with its Le set to *le*, as a '6Cxx' answer asks.

    TS 102 221 v18.4 7.3.1.1.5.0: '6Cxx' tells the terminal to resend the
    previous command header with P3 = 'xx'. The short-APDU case decides where
    Le goes: a 5-byte command carries it as P3, a case 3 command gains one and
    a case 4 command has its last byte replaced. Rewriting the last byte of a
    case 3 command would change its data instead. An extended-length or
    malformed command returns None.
    """
    data = bytes(command)
    value = int(le) & 0xFF
    if len(data) < 4:
        return None
    if len(data) == 4:
        return data + bytes([value])
    if len(data) == 5:
        return data[:4] + bytes([value])
    lc = data[4]
    if lc == 0:
        return None
    if len(data) == 5 + lc:
        return data + bytes([value])
    if len(data) == 6 + lc:
        return data[:-1] + bytes([value])
    return None


def exchange_with_length_correction(
    exchange: ApduExchange,
    apdu: bytes,
    log_name: str,
) -> Tuple[bytes, bytes, int, int]:
    """Send *apdu* and resend it once with Le = 'xx' when the card answers '6Cxx'.

    Returns the command that was answered, its response data and status. A
    second '6Cxx', or one to a command whose Le cannot be placed, is returned
    to the caller unchanged.
    """
    command = bytes(apdu)
    response, sw1, sw2 = exchange(command, log_name)
    if sw1 != 0x6C:
        return command, bytes(response), sw1, sw2
    corrected = resend_with_le(command, sw2)
    if corrected is None:
        return command, bytes(response), sw1, sw2
    response, sw1, sw2 = exchange(corrected, log_name)
    return corrected, bytes(response), sw1, sw2


def complete_response_data(
    exchange: ApduExchange,
    command: bytes,
    response: bytes,
    sw1: int,
    sw2: int,
    log_name: str,
    *,
    continuation_sw1: Tuple[int, ...] = (0x61,),
    answered_get_response: bool = False,
) -> Tuple[bytes, int, int]:
    """Collect the response data a '61xx' (or '9Fxx') answer announced.

    Each GET RESPONSE asks for the length the card announced. A '6Cxx' answer
    to a GET RESPONSE is resent once with P3 = 'xx' (TS 102 221 v18.4
    7.3.1.1.5.0). A '6Cxx' to the command itself is the caller's to resolve:
    it enters here as a final status unless *answered_get_response* says the
    caller's own GET RESPONSE drew it.
    """
    cla = (command[0] & 0x03) if len(command) > 0 else 0x00
    label = f"{log_name} [GET RESPONSE]"
    collected = bytes(response)
    may_correct_length = bool(answered_get_response)
    for _ in range(_MAX_GET_RESPONSE_ROUNDS):
        if sw1 in continuation_sw1:
            may_correct_length = True
        elif sw1 == 0x6C and may_correct_length:
            may_correct_length = False
        else:
            return collected, sw1, sw2
        chunk, sw1, sw2 = exchange(bytes([cla, 0xC0, 0x00, 0x00, sw2 & 0xFF]), label)
        collected += bytes(chunk)
    raise IOError(f"{log_name}: GET RESPONSE chain exceeded {_MAX_GET_RESPONSE_ROUNDS} rounds.")


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
        chunk_size: int = 0xFF,
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


# PC/SC status codes after which SCardConnect is worth repeating: the card
# is still powering down or up (SCARD_W_UNPOWERED_CARD, SCARD_W_RESET_CARD),
# the handle that just released it has not let go yet
# (SCARD_E_SHARING_VIOLATION), or the driver got no ATR this time
# (SCARD_W_UNRESPONSIVE_CARD, which Apple's bundled CCID driver returns for
# a card that is powered). An empty reader (SCARD_E_NO_SMARTCARD,
# SCARD_W_REMOVED_CARD) is not in the set: waiting on it helps nobody.
_PCSC_TRANSIENT_CONNECT_STATUS = frozenset(
    {
        0x8010000B,  # SCARD_E_SHARING_VIOLATION
        0x80100066,  # SCARD_W_UNRESPONSIVE_CARD
        0x80100067,  # SCARD_W_UNPOWERED_CARD
        0x80100068,  # SCARD_W_RESET_CARD
    }
)
# Pause before each repeated SCardConnect, in seconds: six attempts in all.
_PCSC_CONNECT_RETRY_DELAYS = (0.25, 0.5, 1.0, 1.5, 2.0)
_PCSC_STATUS_IN_MESSAGE = re.compile(r"0x([0-9A-Fa-f]{8})")
_MACOS_CCID_HINT = (
    "On macOS, Apple's bundled CCID driver is known to answer SCardConnect "
    "with 'Card is unresponsive' for a powered card; enabling the libccid "
    "driver works around it: sudo defaults write "
    "/Library/Preferences/com.apple.security.smartcard useIFDCCID -bool yes"
)


def _pcsc_status_code(error: BaseException) -> Optional[int]:
    """Return the PC/SC status behind a pyscard exception, or None when it carries none."""
    hresult = getattr(error, "hresult", None)
    if isinstance(hresult, int) and hresult != -1:
        return hresult & 0xFFFFFFFF
    match = _PCSC_STATUS_IN_MESSAGE.search(str(error))
    if match is None:
        return None
    return int(match.group(1), 16)


def _is_transient_connect_error(error: BaseException) -> bool:
    return _pcsc_status_code(error) in _PCSC_TRANSIENT_CONNECT_STATUS


class PcscApduChannel:
    """Local PC/SC APDU channel with SW handling."""

    def __init__(self, reader_index: int = 0, *, quiet_apdu_logging: bool = False):
        self._reader_index = reader_index
        self._conn = self._connect(reader_index)
        self._raw_apdu_logging = False
        # Concise per-APDU trace lines are on by default for the local
        # shells; the eSIM management relay and the GUI open the channel
        # quiet and narrate progress themselves. Raw logging is an explicit
        # request (a command's --debug, the global debug flag) and prints
        # every exchange on a quiet channel too.
        self._quiet_apdu_logging = bool(quiet_apdu_logging)

    def _connect(self, index: int):
        if is_simulated_card_backend():
            return create_card_connection(reader_index=index)
        return self._connect_after_power_cycle(index)

    def _connect_after_power_cycle(self, index: int):
        """Power the card up and return the wrapped connection.

        Every command boundary unpowers the card, so this is a cold boot each
        time. A connect that fails with one of the transient PC/SC statuses is
        repeated on a growing pause; any other failure, an empty reader
        included, is raised as pyscard reports it. Exhausting the attempts
        raises a RuntimeError naming the reader, the attempt count and the
        last PC/SC status, so the caller never has to guess from a later
        "channel is disconnected".
        """
        from smartcard.System import readers

        reader_list = readers()
        if index < 0 or index >= len(reader_list):
            raise RuntimeError(
                f"Reader index {index} is out of range. Detected readers: {len(reader_list)}."
            )
        reader = reader_list[index]
        try:
            reader_name = str(reader) or f"pcsc#{index}"
        except Exception:
            reader_name = f"pcsc#{index}"
        connection = reader.createConnection()
        attempts = 0
        last_error: Optional[Exception] = None
        for delay in (0.0,) + _PCSC_CONNECT_RETRY_DELAYS:
            if delay > 0:
                time.sleep(delay)
            attempts += 1
            try:
                self._open_pcsc_connection(connection)
            except Exception as error:
                if _is_transient_connect_error(error) is False:
                    raise
                last_error = error
                continue
            self._reset_connected_card(connection)
            return wrap_connection(connection, source=reader_name)
        message = (
            f"PC/SC connect to reader {reader_name!r} (index {index}) failed "
            f"{attempts} times over {sum(_PCSC_CONNECT_RETRY_DELAYS):.1f} s; "
            f"last error: {last_error}"
        )
        if sys.platform == "darwin":
            message = f"{message}. {_MACOS_CCID_HINT}"
        raise RuntimeError(message) from last_error

    @staticmethod
    def _open_pcsc_connection(connection) -> None:
        """SCardConnect with the unpower disposition pinned for the later disconnect."""
        try:
            from smartcard.scard import SCARD_UNPOWER_CARD
        except Exception:
            SCARD_UNPOWER_CARD = None
        if SCARD_UNPOWER_CARD is None:
            connection.connect()
            return
        try:
            connection.connect(disposition=SCARD_UNPOWER_CARD)
        except TypeError:
            connection.connect()
            try:
                connection.disposition = SCARD_UNPOWER_CARD
            except Exception:
                pass

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

    def is_connected(self) -> bool:
        """True while a card handle is held; False after disconnect() or a failed reconnect."""
        return getattr(self, "_conn", None) is not None

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
        raw_logging = bool(getattr(self, "_raw_apdu_logging", False))
        if raw_logging or bool(getattr(self, "_quiet_apdu_logging", False)) is False:
            _print_apdu_exchange(
                log_name,
                apdu,
                payload,
                sw1,
                sw2,
                raw=raw_logging,
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
        """Send an APDU, collect its whole response and drain a pending proactive command.

        TS 102 221 v18.4 7.3.1.1.5.0: '61xx' asks for a GET RESPONSE of up to
        'xx' bytes and '6Cxx' for the same command header again with P3 =
        'xx'. 7.3.1.1.4 step 4b: a T=0 case 4 command answered with an
        application status other than '9000' still holds its response data,
        which a GET RESPONSE with Le = '00' collects. '91xx' (proactive
        command pending) is the one such status an ES10 command ends normally
        with, so it is the one completed here; a warning ('62xx' / '63xx')
        still fails the command, as it does when T=1 carries the data in the
        same block. The proactive command is fetched afterwards, on the basic
        channel (TS 102 221 v18.4 7.4.2.1).
        """
        command, response, sw1, sw2 = exchange_with_length_correction(self.exchange, apdu, log_name)
        announced_proactive_length = 0
        answered_get_response = False
        if sw1 == 0x91 and sw2 > 0 and len(response) == 0 and self._response_may_wait_behind_91xx(command):
            announced_proactive_length = sw2
            waiting, waiting_sw1, waiting_sw2 = self.exchange(
                bytes([command[0] & 0x03, 0xC0, 0x00, 0x00, 0x00]),
                f"{log_name} [GET RESPONSE after 91{sw2:02X}]",
            )
            # An error with no data means nothing was waiting: the command's
            # own '91xx' stands.
            if len(waiting) > 0 or waiting_sw1 in (0x61, 0x6C):
                response, sw1, sw2 = bytes(waiting), waiting_sw1, waiting_sw2
                answered_get_response = True
        response, sw1, sw2 = complete_response_data(
            self.exchange,
            command,
            response,
            sw1,
            sw2,
            log_name,
            answered_get_response=answered_get_response,
        )

        if sw1 == 0x91 and sw2 > 0:
            self._handle_proactive_refresh(response, sw1, sw2, log_name)
            return bytes(response)
        if announced_proactive_length > 0 and (sw1, sw2) == (0x90, 0x00):
            # The GET RESPONSE ended on '9000'; the proactive command the
            # command's '91xx' announced is still pending.
            self._handle_proactive_refresh(response, 0x91, announced_proactive_length, log_name)
            return bytes(response)

        status_hex = f"{sw1:02X}{sw2:02X}"
        if status_hex not in ("9000", "9100"):
            raise IOError(f"APDU Failed: {status_hex}")

        return bytes(response)

    def _response_may_wait_behind_91xx(self, command: bytes) -> bool:
        """True for a case 4 STORE DATA on a link that is not known to run T=1."""
        if len(command) < 6 or command[1] != 0xE2:
            return False
        # GPC v2.3.1 11.11.2.1 Table 11-89: STORE DATA P1 b1 = 1 declares ISO case 4.
        if (command[2] & 0x01) == 0:
            return False
        get_protocol = getattr(self._conn, "getProtocol", None)
        if callable(get_protocol) is False:
            return True
        try:
            protocol = get_protocol()
        except Exception:
            return True
        return protocol != _CARD_PROTOCOL_T1

    def _handle_proactive_refresh(self, response: bytes, sw1: int, sw2: int, log_name: str) -> bytes:
        drain_attempts = 0
        while sw1 == 0x91 and sw2 > 0 and drain_attempts < 8:
            drain_attempts += 1
            fetch_data, fetch_sw1, fetch_sw2 = self.exchange(
                bytes([0x80, 0x12, 0x00, 0x00, sw2]),
                f"{log_name} [FETCH]",
            )
            if fetch_sw1 == 0x91 and fetch_sw2 > 0:
                sw1, sw2 = fetch_sw1, fetch_sw2
                continue
            if fetch_sw1 != 0x90 or fetch_sw2 != 0x00 or len(fetch_data) == 0:
                break
            try:
                terminal_response = _build_proactive_terminal_response(fetch_data)
            except ValueError:
                break
            _, tr_sw1, tr_sw2 = self.exchange(
                terminal_response,
                f"{log_name} [TERMINAL RESPONSE]",
            )
            sw1, sw2 = tr_sw1, tr_sw2
        return response

    def send_chunked(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2_start: int,
        payload: bytes,
        log_name: str,
        chunk_size: int = 0xFF,
    ) -> bytes:
        """Fragment *data* into STORE-DATA chunks and dispatch each via ``exchange`` (SGP.22 §3.1.3)."""
        total = len(payload)
        block = p2_start
        response = b""
        chunks = split_tlv_aware_chunks(payload, chunk_size)

        _print_chunk_banner(log_name, total, raw=bool(self._raw_apdu_logging))
        print_store_data_chunk_plan(
            log_name,
            payload,
            cla=cla,
            ins=ins,
            final_p1=p1,
            p2_start=p2_start,
            chunk_size=chunk_size,
            chunks=chunks,
        )
        for chunk_index, chunk in enumerate(chunks, start=1):
            is_last_chunk = chunk_index == len(chunks)
            current_p1 = p1
            if not is_last_chunk:
                current_p1 = 0x11
            # GPCS v2.3.1 STORE DATA block numbers run 00..FF and wrap.
            apdu = bytes([cla, ins, current_p1, block & 0xFF, len(chunk)]) + chunk
            # A renderer names the block in the exchange it prints.
            if self._raw_apdu_logging and _apdu_trace_renderer() is None:
                print(f"  > Block {block:02X} (Len={len(chunk)}) P1={current_p1:02X}")
            response = self.send(apdu, f"{log_name} [Block {block}]")
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



class RemoteApduChannel(PcscApduChannel):
    """APDU channel over a registered remote reader's relay.

    Everything above the transport -- SW handling, GET RESPONSE chaining, the
    proactive-command drain, STORE DATA chunking -- is inherited unchanged
    from :class:`PcscApduChannel`; only the four methods that touch PC/SC are
    replaced. The connection comes from ``card_backend.create_card_connection``
    resolving *reader_name* against the remote-reader registry, which is the
    same path the SCP03 workbench uses, so a Remote Lab card serves the
    eSIM-management and local SM-DP+ surfaces exactly as it serves the file
    system. The relay session itself is owned by the Remote Lab link, never
    by this channel: ``disconnect`` posts the relay's command boundary and
    releases nothing.
    """

    def __init__(self, reader_name: str, *, quiet_apdu_logging: bool = False):
        from yggdrasim_common.remote_readers import REMOTE_READER_INDEX

        cleaned = str(reader_name or "").strip()
        if len(cleaned) == 0:
            raise ValueError("remote reader name is required")
        # Set before the base initialiser runs: it calls ``_connect`` at once.
        self._reader_name = cleaned
        super().__init__(reader_index=REMOTE_READER_INDEX, quiet_apdu_logging=quiet_apdu_logging)

    def _connect(self, index: int):
        # ``create_card_connection`` refuses to fall back to a local reader
        # when the binding is gone, so a released link surfaces as a clear
        # error here rather than as APDUs landing on the operator's own card.
        return create_card_connection(reader_index=index, reader_name=self._reader_name)

    def _connect_after_power_cycle(self, index: int):
        # ``reset`` has already called ``disconnect``, whose relay boundary
        # is where the bridge resets the card; a fresh connection re-reads
        # the ATR from the relay's status endpoint.
        return self._connect(index)

    def begin_transaction(self) -> None:
        # The agent grants one exclusive session per rig, so the relay is
        # already serialised; there is no PC/SC handle to lock.
        return None

    def end_transaction(self) -> None:
        return None

    def is_connected(self) -> bool:
        return self._conn is not None

    def disconnect(self) -> None:
        connection = self._conn
        self._conn = None
        if connection is None:
            return
        try:
            connection.disconnect()
        except Exception:  # noqa: BLE001 -- teardown must not raise
            pass

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

    def is_connected(self) -> bool:
        """Report whether the underlying card channel still holds its handle."""
        is_connected = getattr(self._channel, "is_connected", None)
        if callable(is_connected):
            return bool(is_connected())
        return True

    def send_chunked(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2_start: int,
        payload: bytes,
        log_name: str,
        chunk_size: int = 0xFF,
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
