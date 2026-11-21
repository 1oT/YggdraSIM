# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP80 transport: wraps the pySim OTA keyset and dispatches APDU envelopes over the active card connection."""
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

from typing import Tuple, Optional, Dict, Any, List
from yggdrasim_common import secured_packet
from yggdrasim_common.stk_terminal import terminal_profile_apdu
from yggdrasim_common.card_backend import (
    create_card_connection,
    is_simulated_card_backend,
)

if __package__:
    from .config import ConfigManager
    from .utils import Utils, Colors
else:
    from config import ConfigManager
    from utils import Utils, Colors

try:
    from smartcard.CardConnection import CardConnection
    from smartcard.ATR import ATR

    PYSCRARD_AVAIL = True
except ImportError:
    PYSCRARD_AVAIL = False
    ATR = None

    class CardConnection:  # type: ignore[no-redef]
        T0_protocol = 0
        T1_protocol = 1
        RAW_protocol = 2


# Bounds the SET UP EVENT LIST commands answered behind one PoR, so a card that
# kept raising them could not hold the shell.
_EVENT_LIST_ANSWER_LIMIT = 8


class Transport:
    def __init__(self, config: ConfigManager):
        self.cfg = config
        self.conn: Optional[CardConnection] = None
        self.active_protocol = None
        self._stk_bootstrap_trace: List[Dict[str, Any]] = []
        self._stk_bootstrap_trace_printed = False

    def connect(self, protocol=None, verbose: bool = False) -> bool:
        """Connect to the reader or simulated card backend; return True on success."""
        if not PYSCRARD_AVAIL and not is_simulated_card_backend():
            print(f"{Colors.FAIL}[!] pyscard library missing.{Colors.ENDC}")
            return False
        try:
            idx = self.cfg.get_int("reader_idx")
            # ``reader_name`` is set beside ``reader_idx`` when the operator
            # picked a registered remote reader; it has no PC/SC ordinal, so
            # the name is what selects its relay.
            data = getattr(self.cfg, "data", None)
            reader_name = str(data.get("reader_name", "") if isinstance(data, dict) else "")
            if reader_name and idx < 0:
                from yggdrasim_common.remote_readers import is_remote_reader

                # The name outlived its link (a persisted config, or a rig
                # released elsewhere). Say so, rather than letting a -1 index
                # fall through to PC/SC and read as "reader out of range".
                if not is_remote_reader(reader_name):
                    raise RuntimeError(
                        f"remote reader {reader_name!r} is not connected; "
                        "connect it from Remote Lab first"
                    )
            self.conn = create_card_connection(
                reader_index=idx, protocol=protocol, reader_name=reader_name
            )
            try:
                self.active_protocol = self.conn.getProtocol()
            except Exception:
                self.active_protocol = protocol
            self._stk_bootstrap(verbose=verbose)
            return True
        except Exception as e:
            print(f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")
            return False

    def disconnect(self):
        if self.conn:
            try:
                self.conn.disconnect()
            except Exception:
                pass
        self.conn = None
        self.active_protocol = None
        self._stk_bootstrap_trace = []
        self._stk_bootstrap_trace_printed = False

    def reset_connection(self, verbose: bool = False):
        print(
            f"{Colors.CYAN}[RESET] Reconnecting and re-initializing STK...{Colors.ENDC}"
        )
        self.disconnect()
        self.connect(verbose=verbose)

    @staticmethod
    def _decode_iccid_bytes(data: bytes) -> str:
        hex_value = bytes(data).hex().upper()
        digits = []
        for index in range(0, len(hex_value), 2):
            pair = hex_value[index : index + 2]
            if len(pair) < 2:
                continue
            digits.append(pair[1])
            digits.append(pair[0])
        return "".join(digits).replace("F", "")

    def read_iccid(self) -> str:
        """Read and return the ICCID from EF.ICCID via the active connection."""
        if self.conn is None:
            if not self.connect():
                return ""
        self.transmit("00A40004023F00", silent=True, log_tx=False, log_rx=False)
        self.transmit("00A40004022FE2", silent=True, log_tx=False, log_rx=False)
        data, sw = self.transmit("00B000000A", silent=True, log_tx=False, log_rx=False)
        if sw != 0x9000:
            return ""
        return self._decode_iccid_bytes(data)

    @staticmethod
    def _requires_extended_apdu(apdu_hex: str) -> bool:
        return len(Utils.to_bytes(apdu_hex)) > 261

    @staticmethod
    def _protocol_name(protocol) -> str:
        if protocol == CardConnection.T0_protocol:
            return "T=0"
        if protocol == CardConnection.T1_protocol:
            return "T=1"
        if protocol == CardConnection.RAW_protocol:
            return "RAW"
        if protocol is None:
            return "UNKNOWN"
        return str(protocol)

    def get_protocol_summary(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict summarising the current card connection and ATR."""
        info = {
            "available": False,
            "atr_hex": None,
            "supported_protocols": {},
            "supports_t1": False,
            "active_protocol": None,
            "error": None,
        }
        if not PYSCRARD_AVAIL:
            info["error"] = "pyscard library missing."
            return info

        if self.conn is None:
            if not self.connect():
                info["error"] = "Reader connection unavailable."
                return info

        try:
            atr_bytes = bytes(self.conn.getATR())
            info["atr_hex"] = atr_bytes.hex().upper()
            if ATR is not None:
                parsed_atr = ATR(list(atr_bytes))
                info["supported_protocols"] = parsed_atr.getSupportedProtocols()
                info["supports_t1"] = bool(info["supported_protocols"].get("T=1"))
            info["active_protocol"] = self._protocol_name(self.active_protocol)
            info["available"] = True
        except Exception as e:
            info["error"] = str(e)
        return info

    def _ensure_reader_protocol(
        self, apdu_hex_list: List[str], verbose: bool = False
    ) -> bool:
        needs_extended = False
        for apdu_hex in apdu_hex_list:
            if self._requires_extended_apdu(apdu_hex):
                needs_extended = True
                break

        if not needs_extended:
            if self.conn is None:
                return self.connect(verbose=verbose)
            return True

        if self.conn is not None and self.active_protocol == CardConnection.T1_protocol:
            return True

        self.disconnect()
        return self.connect(CardConnection.T1_protocol, verbose=verbose)

    def transmit(
        self,
        apdu_hex: str,
        silent: bool = False,
        log_tx: bool = True,
        log_rx: bool = True,
        label: str = "",
    ) -> Tuple[bytes, int]:
        """Send one APDU hex string and return (response_bytes, status_word) as an int.

        *label* names the command on the logged line, as the replayed
        bootstrap trace does.
        """
        if not self.conn:
            return b"", 0x6F00
        raw = Utils.to_bytes(apdu_hex)
        if not silent and log_tx:
            suffix = f" ({label})" if label else ""
            print(f"  {Colors.WARNING}[ -> ]{Colors.ENDC} {apdu_hex}{suffix}")
        data, sw1, sw2 = self.conn.transmit(list(raw))
        sw = (sw1 << 8) | sw2
        if not silent and log_rx:
            print(
                f"  {Colors.GREEN}[ <- ]{Colors.ENDC} SW: {sw:04X} Data: {Utils.to_hex(bytes(data))}"
            )
        return bytes(data), sw

    def _stk_bootstrap(self, verbose: bool = False) -> None:
        self._stk_bootstrap_trace = []
        self._stk_bootstrap_trace_printed = False
        tp_apdu = terminal_profile_apdu().hex().upper()
        if verbose:
            print(f"{Colors.CYAN}[STK]{Colors.ENDC} Bootstrap")
        _, sw = self.transmit(
            tp_apdu,
            silent=not verbose,
            log_tx=verbose,
            log_rx=verbose,
            label="TERMINAL PROFILE",
        )
        self._record_stk_bootstrap_exchange("TERMINAL PROFILE", tp_apdu, b"", sw)
        while (sw >> 8) == 0x91:
            length = sw & 0xFF
            fetch_apdu = f"80120000{length:02X}"
            data, sw = self.transmit(
                fetch_apdu,
                silent=not verbose,
                log_tx=verbose,
                log_rx=verbose,
                label="FETCH",
            )
            self._record_stk_bootstrap_exchange("FETCH", fetch_apdu, data, sw)
            terminal_response = self._terminal_response_for_proactive(data)
            if terminal_response is None:
                break
            _, sw = self.transmit(
                terminal_response,
                silent=not verbose,
                log_tx=verbose,
                log_rx=verbose,
                label="TERMINAL RESPONSE",
            )
            self._record_stk_bootstrap_exchange(
                "TERMINAL RESPONSE", terminal_response, b"", sw
            )
        if verbose:
            self._stk_bootstrap_trace_printed = True

    def _record_stk_bootstrap_exchange(
        self, label: str, apdu_hex: str, data: bytes, sw: int
    ) -> None:
        self._stk_bootstrap_trace.append(
            {
                "label": label,
                "apdu": apdu_hex,
                "data": Utils.to_hex(bytes(data or b"")),
                "sw": f"{int(sw) & 0xFFFF:04X}",
            }
        )

    def print_stk_bootstrap_trace(self) -> None:
        if self._stk_bootstrap_trace_printed:
            return
        if len(self._stk_bootstrap_trace) == 0:
            return
        print(f"{Colors.CYAN}[STK]{Colors.ENDC} Bootstrap (connection init)")
        for entry in self._stk_bootstrap_trace:
            print(
                f"  {Colors.WARNING}[ -> ]{Colors.ENDC} {entry.get('apdu')} ({entry.get('label')})"
            )
            print(
                f"  {Colors.GREEN}[ <- ]{Colors.ENDC} SW: {entry.get('sw')} Data: {entry.get('data')}"
            )
        self._stk_bootstrap_trace_printed = True

    def _send_single_ota_apdu(
        self, apdu_hex: str, verbose: bool = False, require_por: bool = True
    ) -> Dict[str, Any]:
        result = {
            "sw": None,
            "por": None,
            "por_decoded": None,
            "pending_proactive": None,
            "answered_event_lists": [],
            "delivered": False,
            "error": None,
        }
        data, sw = self.transmit(
            apdu_hex, log_tx=verbose, log_rx=verbose, label="ENVELOPE"
        )
        result["sw"] = f"{sw:04X}"

        if (sw >> 8) == 0x91 or (sw >> 8) == 0x61:
            # Under T=1 the response data and a '91 xx' arrive together.
            por_data, pending = self._collect_por(sw, verbose, initial_data=data)
            self._settle_pending_proactive(result, pending, verbose)
            if por_data:
                result["por"] = por_data.hex().upper()
                result["por_decoded"] = self.decode_por(por_data, sw)
                result["delivered"] = True
                return result
            if require_por:
                result["error"] = "No POR body received after proactive fetch."
                return result
            result["delivered"] = True
            return result

        if (sw >> 8) in (0x62, 0x63):
            # TS 102 221 v18.4 §7.4.2.2: response data beside '62 XX' or
            # '63 XX' is a negative acknowledgement, and the PoR is that data.
            # Under T=0 the status comes alone and §7.3.1.1.4 step 4b fetches
            # the data with GET RESPONSE, Le = '00'.
            after_sw = 0x9000
            if len(data) == 0:
                data, after_sw = self._read_warning_response_data(verbose)
            por_data, pending = self._collect_por(after_sw, verbose, initial_data=data)
            self._settle_pending_proactive(result, pending, verbose)
            result["delivered"] = True
            if por_data:
                result["por"] = por_data.hex().upper()
                result["por_decoded"] = self.decode_por(por_data, sw)
            elif require_por:
                result["error"] = (
                    f"No POR returned by card (ENVELOPE answered {sw:04X}, "
                    f"GET RESPONSE {after_sw:04X})."
                )
            return result

        if sw == 0x9000:
            if data:
                result["por"] = data.hex().upper()
                result["por_decoded"] = self.decode_por(data, sw)
                result["delivered"] = True
                return result
            if require_por:
                result["error"] = (
                    "No POR returned by card (SW 9000 confirms the ENVELOPE reached the Security Domain)."
                )
            result["delivered"] = True
            return result

        result["error"] = f"Unexpected transport status {sw:04X} without POR."
        return result

    def send_ota_sequence(
        self, apdu_hex_list: List[str], verbose: bool = False
    ) -> Dict[str, Any]:
        """Send a list of SCP80 OTA APDUs in sequence and return a result dict with SW and POR."""
        result = {
            "sw": None,
            "por": None,
            "por_decoded": None,
            "pending_proactive": None,
            "answered_event_lists": [],
            "delivered": False,
            "error": None,
            "segment_count": len(apdu_hex_list),
            "segment_results": [],
            "failed_segment": None,
        }
        if len(apdu_hex_list) == 0:
            result["error"] = "No OTA APDUs to send."
            return result

        if self.cfg.get("transport") != "reader":
            for apdu_hex in apdu_hex_list:
                print(f"\n{Colors.WARNING}[PRINT ONLY]{Colors.ENDC} {apdu_hex}")
            self.cfg.increment_counter()
            result["delivered"] = True
            return result

        if not self._ensure_reader_protocol(apdu_hex_list, verbose=verbose):
            needs_extended = False
            for apdu_hex in apdu_hex_list:
                if self._requires_extended_apdu(apdu_hex):
                    needs_extended = True
                    break
            if needs_extended:
                result["error"] = (
                    "Reader transport requires T=1 for extended ENVELOPE delivery, but this card/reader path rejected T=1."
                )
            else:
                result["error"] = "Reader connection unavailable."
            return result

        if verbose:
            self.print_stk_bootstrap_trace()
            # Heads the exchanges below so they do not read as part of the
            # bootstrap block replayed above.
            print(f"{Colors.CYAN}[OTA]{Colors.ENDC} SMS-PP data download")

        last_index = len(apdu_hex_list) - 1
        spi_expects_por = self._spi_expects_por()
        for index, apdu_hex in enumerate(apdu_hex_list):
            require_por = (index == last_index) and spi_expects_por
            segment_result = self._send_single_ota_apdu(
                apdu_hex,
                verbose=verbose,
                require_por=require_por,
            )
            result["segment_results"].append(segment_result)
            result["sw"] = segment_result.get("sw")
            result["por"] = segment_result.get("por")
            result["por_decoded"] = segment_result.get("por_decoded")
            result["pending_proactive"] = segment_result.get("pending_proactive")
            result["answered_event_lists"].extend(
                segment_result.get("answered_event_lists") or []
            )
            if segment_result.get("error"):
                result["error"] = segment_result.get("error")
            if not segment_result.get("delivered"):
                result["failed_segment"] = index + 1
                result["error"] = segment_result.get("error")
                return result

        self.cfg.increment_counter()
        result["delivered"] = True
        return result

    def send_ota(self, apdu_hex: str, verbose: bool = False) -> Dict[str, Any]:
        return self.send_ota_sequence([apdu_hex], verbose=verbose)

    def _collect_por(
        self, initial_sw: int, verbose: bool = False, initial_data: bytes = b""
    ) -> Tuple[bytes, bytes]:
        """Return ``(por, pending)`` for the card's answer to an SMS-PP ENVELOPE.

        SPI2 b6 picks the carrier (TS 31.115 v19 §4.2). A PoR sent by
        SMS-DELIVER-REPORT is the ENVELOPE's own response data, the UICC
        Acknowledgement of TS 31.111 v19.4 §7.1.1.2; one sent by SMS-SUBMIT
        is the TPDU of the SEND SHORT MESSAGE the card raises next. A
        proactive command behind the response data carries the PoR only when
        that data is empty or answers '0B' (TS 31.115 v19 clause 7); any other
        comes back unanswered as *pending* (``_settle_pending_proactive``).

        A PoR concatenated over several SMS-SUBMIT messages (TS 31.115 v19
        §4.5) arrives as one SEND SHORT MESSAGE per segment, each raised after
        the TERMINAL RESPONSE to the one before, so the segments are fetched
        until the message is whole. Left behind, a segment would answer the
        next ENVELOPE as if it were that command's PoR.
        """
        response_data, sw = self._read_response_chain(
            bytes(initial_data or b""), initial_sw, verbose
        )
        if (sw >> 8) != 0x91:
            return response_data, b""
        fetch_body, _ = self._fetch_proactive(sw, verbose)
        carries_por = len(response_data) == 0
        if not carries_por:
            hands_over = self._acknowledgement_status(response_data) == 0x0B
            carries_por = hands_over and self._proactive_has_sms_tpdu(fetch_body)
        if not carries_por:
            return response_data, fetch_body
        collected = fetch_body
        sw = self._acknowledge_sms_por(fetch_body, verbose)
        while sw is not None and (sw >> 8) == 0x91:
            following, _ = self._fetch_proactive(sw, verbose)
            segment = self._proactive_has_sms_tpdu(following)
            if not segment or not self._por_segments_missing(collected):
                return collected, following
            collected += following
            sw = self._acknowledge_sms_por(following, verbose)
        return collected, b""

    def _settle_pending_proactive(
        self, result: Dict[str, Any], pending: bytes, verbose: bool = False
    ) -> None:
        """Answer the SET UP EVENT LIST commands behind a PoR; record the rest.

        TS 102 241 V18.1 §6.7.1.2 has the CAT Runtime send SET UP EVENT LIST
        whenever the registered event list changes, so an OTA command that
        switches a toolkit applet on or off draws one right behind its PoR.
        The bootstrap accepts the list, and TS 102 223 V18.3 §6.4.16 answers
        an accepted list with TERMINAL RESPONSE (OK); left unanswered it holds
        the proactive session open on the connection the next send reuses.
        The first other command stays unanswered in ``pending_proactive``,
        since the shell cannot honour it.
        """
        answered: List[str] = []
        while len(pending) > 0 and len(answered) < _EVENT_LIST_ANSWER_LIMIT:
            events = self._set_up_event_list_events(pending)
            if events is None:
                break
            _, sw = self.transmit(
                self._terminal_response_for_proactive(pending),
                silent=not verbose,
                log_tx=verbose,
                log_rx=verbose,
                label="TERMINAL RESPONSE",
            )
            answered.append(events.hex().upper())
            pending = b""
            if (sw >> 8) == 0x91:
                pending, _ = self._fetch_proactive(sw, verbose)
        result["answered_event_lists"] = answered
        if len(pending) > 0:
            result["pending_proactive"] = pending.hex().upper()

    def _fetch_proactive(self, sw: int, verbose: bool = False) -> Tuple[bytes, int]:
        body, fetch_sw = self.transmit(
            f"80120000{sw & 0xFF:02X}", log_tx=verbose, log_rx=verbose, label="FETCH"
        )
        return self._read_response_chain(body, fetch_sw, verbose)

    def _read_warning_response_data(self, verbose: bool = False) -> Tuple[bytes, int]:
        """GET RESPONSE after a T=0 warning, as TS 102 221 v18.4 annex C.1.7 runs it.

        Le '00' draws '6C Luicc', and the header is sent again with P3 = Luicc.
        """
        data, sw = self.transmit(
            "00C0000000", log_tx=verbose, log_rx=verbose, label="GET RESPONSE"
        )
        if (sw >> 8) == 0x6C:
            data, sw = self.transmit(
                f"00C00000{sw & 0xFF:02X}",
                log_tx=verbose,
                log_rx=verbose,
                label="GET RESPONSE",
            )
        return self._read_response_chain(data, sw, verbose)

    def _read_response_chain(
        self, data: bytes, sw: int, verbose: bool = False
    ) -> Tuple[bytes, int]:
        """Append the data of every '61 xx' GET RESPONSE that follows *sw*."""
        while (sw >> 8) == 0x61:
            more, sw = self.transmit(
                f"00C00000{sw & 0xFF:02X}",
                log_tx=verbose,
                log_rx=verbose,
                label="GET RESPONSE",
            )
            data += more
        return data, sw

    def _acknowledge_sms_por(
        self, fetch_body: bytes, verbose: bool = False
    ) -> Optional[int]:
        """Answer a SEND SHORT MESSAGE; return the card's status, None if not one."""
        terminal_response = self._terminal_response_for_sms_por(fetch_body)
        if terminal_response is None:
            return None
        _, sw = self.transmit(
            terminal_response,
            silent=not verbose,
            log_tx=verbose,
            log_rx=verbose,
            label="TERMINAL RESPONSE",
        )
        return sw

    @classmethod
    def decode_por(cls, fetch_body: bytes, fetch_sw=None) -> Dict[str, Any]:
        decoded = {
            "valid": False,
            "fetch_sw": cls._format_sw(fetch_sw),
            "status_code": None,
            "status_meaning": None,
            "tar": None,
            "cntr": None,
            "pcntr": None,
            "command_count": None,
            "command_response": None,
            "command_sw": None,
            "por_carrier": None,
            "error": None,
        }
        raw = bytes(fetch_body or b"")
        response_packet = None
        if raw[:1] != b"\xd0":
            response_packet = cls._acknowledgement_response_packet(raw)
        if response_packet is not None:
            decoded["por_carrier"] = "ENVELOPE response"
        else:
            tpdus = cls._proactive_sms_tpdus(raw)
            if len(tpdus) == 0:
                decoded["error"] = (
                    "PoR is neither a SEND SHORT MESSAGE with an SMS TPDU nor "
                    "an ENVELOPE response opening with the RPI '71'."
                )
                return decoded
            decoded["por_carrier"] = "SEND SHORT MESSAGE"
            decoded["sms_tpdu"] = Utils.to_hex(tpdus[0])
            if len(tpdus) > 1:
                decoded["sms_segments"] = len(tpdus)
            response_packet, problem = cls._submit_response_packet(tpdus)
            if response_packet is None:
                decoded["error"] = problem
                return decoded
        decoded["response_packet"] = Utils.to_hex(response_packet)
        if len(response_packet) < 13:
            decoded["error"] = (
                "03.48 response packet shorter than RPL/RHL/TAR/CNTR/PCNTR/status."
            )
            return decoded

        rpl = int.from_bytes(response_packet[0:2], "big")
        rhl = response_packet[2] & 0xFF
        header_end = 3 + rhl
        if rhl < 10 or len(response_packet) < header_end:
            decoded["error"] = (
                "03.48 response packet has an unsupported response header length."
            )
            return decoded

        status_code = response_packet[12] & 0xFF
        response_data = response_packet[header_end:]
        decoded.update(
            {
                "valid": True,
                "rpl": f"{rpl:04X}",
                "rpl_expected": f"{max(len(response_packet) - 2, 0):04X}",
                "rpl_matches": rpl == len(response_packet) - 2,
                "rhl": f"{rhl:02X}",
                "tar": Utils.to_hex(response_packet[3:6]),
                "cntr": Utils.to_hex(response_packet[6:11]),
                "pcntr": f"{response_packet[11] & 0xFF:02X}",
                "status_code": f"{status_code:02X}",
                "status_meaning": cls._por_status_meaning(status_code),
                "response_data": Utils.to_hex(response_data),
            }
        )
        if status_code == 0x00 and len(response_data) > 0:
            # TS 102 226 table 5.1: one octet counting the commands the
            # script executed, then the two status octets of the last one,
            # then its response data. The status comes before the data, so
            # reading it off the tail only agrees when there is no data --
            # which is never the case after a READ BINARY, a READ RECORD or
            # a GET RESPONSE, the commands that produce any.
            command_count = response_data[0] & 0xFF
            body = response_data[1:]
            decoded["command_count"] = command_count
            if len(body) >= 2:
                decoded["command_sw"] = Utils.to_hex(body[0:2])
                decoded["command_response"] = Utils.to_hex(body[2:])
            else:
                decoded["command_response"] = Utils.to_hex(body)
        return decoded

    @staticmethod
    def _format_sw(sw) -> str:
        if sw is None:
            return None
        if isinstance(sw, str):
            return sw.upper()
        try:
            return f"{int(sw) & 0xFFFF:04X}"
        except Exception:
            return str(sw)

    @staticmethod
    def _por_status_meaning(status_code: int) -> str:
        """The name of a response status code, from the table every surface reads (TS 102 225 V19.0.0 Table 5)."""
        return secured_packet.response_status_name(status_code)

    @classmethod
    def _proactive_sms_tpdu(cls, fetch_body: bytes) -> bytes:
        for tag, value, _raw in cls._iter_proactive_tlvs(fetch_body):
            if len(tag) == 1 and (tag[0] & 0x7F) == 0x0B:
                return value
        return None

    @classmethod
    def _proactive_commands(cls, data: bytes) -> List[bytes]:
        """Split the proactive commands ('D0') fetched one after another for a PoR."""
        raw = bytes(data or b"")
        commands: List[bytes] = []
        offset = 0
        while offset < len(raw):
            parsed = cls._read_ber_tlv(raw, offset)
            if parsed is None or parsed[0] != b"\xd0":
                return [raw]
            commands.append(parsed[2])
            offset = parsed[3]
        if len(commands) == 0:
            return [raw]
        return commands

    @classmethod
    def _proactive_sms_tpdus(cls, data: bytes) -> List[bytes]:
        tpdus: List[bytes] = []
        for command in cls._proactive_commands(data):
            tpdu = cls._proactive_sms_tpdu(command)
            if tpdu is not None:
                tpdus.append(tpdu)
        return tpdus

    @staticmethod
    def _user_data_header(ud: bytes) -> Optional[Tuple[List[Tuple[int, bytes]], bytes]]:
        """Split TP-UD into its information elements and the data behind them.

        TS 23.040 v19 §9.2.3.24: UDHL, then IEI, IEDL and IED per element.
        """
        raw = bytes(ud or b"")
        if len(raw) == 0:
            return None
        udh_end = 1 + raw[0]
        if udh_end > len(raw):
            return None
        elements: List[Tuple[int, bytes]] = []
        offset = 1
        while offset < udh_end:
            if offset + 2 > udh_end:
                return None
            iei = raw[offset]
            start = offset + 2
            end = start + raw[offset + 1]
            if end > udh_end:
                return None
            elements.append((iei, raw[start:end]))
            offset = end
        return elements, raw[udh_end:]

    @classmethod
    def _sms_udh_elements(cls, sms_tpdu: bytes) -> List[Tuple[int, bytes]]:
        raw = bytes(sms_tpdu or b"")
        if len(raw) == 0 or not raw[0] & 0x40:
            return []
        ud = cls._sms_tpdu_user_data(raw)
        parsed = cls._user_data_header(ud) if ud else None
        if parsed is None:
            return []
        return parsed[0]

    @classmethod
    def _concatenation_element(cls, sms_tpdu: bytes) -> Optional[Tuple[int, int, int]]:
        """Return ``(reference, total, sequence)`` of a concatenated SM segment.

        TS 23.040 v19 §9.2.3.24.1 ('00', 8-bit reference) and §9.2.3.24.8
        ('08', 16-bit reference); an element with a zero total, or a sequence
        of zero or above the total, is ignored, as the receiver must.
        """
        for iei, data in cls._sms_udh_elements(sms_tpdu):
            if iei == 0x00 and len(data) == 3:
                reference, total, sequence = data[0], data[1], data[2]
            elif iei == 0x08 and len(data) == 4:
                reference, total, sequence = (data[0] << 8) | data[1], data[2], data[3]
            else:
                continue
            if total == 0 or sequence == 0 or sequence > total:
                return None
            return reference, total, sequence
        return None

    @classmethod
    def _por_segments_missing(cls, commands: bytes) -> bool:
        tpdus = cls._proactive_sms_tpdus(commands)
        if len(tpdus) == 0:
            return False
        first = cls._concatenation_element(tpdus[0])
        if first is None:
            return False
        reference, total, _ = first
        received = set()
        for tpdu in tpdus:
            element = cls._concatenation_element(tpdu)
            if element is not None and element[:2] == (reference, total):
                received.add(element[2])
        return len(received) < total

    @classmethod
    def _submit_response_packet(cls, tpdus: List[bytes]) -> Tuple[Optional[bytes], str]:
        """Return the Response Packet SEND SHORT MESSAGE TPDUs carry, or why not.

        TS 31.115 v19 §4.5: the first segment of a concatenated PoR holds the
        concatenation element and the RPI, every later one the concatenation
        element alone.
        """
        unreadable = "SMS TPDU does not contain a parseable 03.48 response packet."
        first = cls._concatenation_element(tpdus[0])
        if first is None:
            packet = cls._sms_tpdu_response_packet(tpdus[0])
            if packet is None:
                return None, unreadable
            return packet, ""
        reference, total, _ = first
        parts: Dict[int, bytes] = {}
        segment_one = b""
        for tpdu in tpdus:
            element = cls._concatenation_element(tpdu)
            if element is None or element[:2] != (reference, total):
                return None, "PoR segments belong to different concatenated messages."
            part = cls._sms_tpdu_response_packet(tpdu)
            if part is None:
                return None, unreadable
            parts[element[2]] = part
            if element[2] == 1:
                segment_one = tpdu
        missing = [str(number) for number in range(1, total + 1) if number not in parts]
        if missing:
            return None, (
                f"Concatenated PoR {reference:02X} lacks segment(s) "
                f"{', '.join(missing)} of {total}; segments without the first one "
                "are left over from an earlier command, and 'reset' drains them."
            )
        if not any(iei == 0x71 for iei, _ in cls._sms_udh_elements(segment_one)):
            return None, "Segment 1 of the concatenated PoR carries no RPI '71'."
        return b"".join(parts[number] for number in range(1, total + 1)), ""

    @classmethod
    def _acknowledgement_response_packet(cls, data: bytes) -> Optional[bytes]:
        """Return the Response Packet an SMS-PP ENVELOPE answered with.

        TS 31.111 v19.4 §7.1.1.2 returns a UICC Acknowledgement that the ME
        relays in its SMS-DELIVER-REPORT. TS 31.115 v19 §4.4 opens it with a
        UDH holding the RPI '71', and §4.1 has the Sending Entity read it as
        if UDHI were set, because the UICC cannot set that bit.
        """
        parsed = cls._user_data_header(data)
        if parsed is None:
            return None
        elements, remainder = parsed
        if not any(iei == 0x71 for iei, _ in elements):
            return None
        return remainder

    @classmethod
    def _acknowledgement_status(cls, data: bytes) -> Optional[int]:
        packet = cls._acknowledgement_response_packet(data)
        # RPL (2), RHL (1), TAR (3), CNTR (5) and PCNTR (1) precede the status.
        if packet is None or len(packet) < 13:
            return None
        return packet[12]

    @classmethod
    def _sms_tpdu_response_packet(cls, sms_tpdu: bytes) -> bytes:
        tp_ud = cls._sms_tpdu_user_data(sms_tpdu)
        if tp_ud is None:
            return None
        if len(tp_ud) == 0:
            return None
        first_octet = bytes(sms_tpdu or b"")[0] & 0xFF
        if first_octet & 0x40:
            udhl = tp_ud[0] & 0xFF
            if len(tp_ud) < 1 + udhl:
                return None
            return tp_ud[1 + udhl :]
        return tp_ud

    @staticmethod
    def _sms_tpdu_user_data(sms_tpdu: bytes) -> bytes:
        raw = bytes(sms_tpdu or b"")
        if len(raw) < 4:
            return None
        first_octet = raw[0] & 0xFF
        mti = first_octet & 0x03
        if mti == 0x01:
            if len(raw) < 4:
                return None
            addr_digits = raw[2] & 0xFF
            addr_bytes = (addr_digits + 1) // 2
            cursor = 4 + addr_bytes
            if len(raw) < cursor + 3:
                return None
            cursor += 2
            vpf = (first_octet >> 3) & 0x03
            if vpf == 0x02:
                cursor += 1
            elif vpf in (0x01, 0x03):
                cursor += 7
            if len(raw) <= cursor:
                return None
            tp_udl = raw[cursor] & 0xFF
            cursor += 1
        elif mti == 0x00:
            addr_digits = raw[1] & 0xFF
            addr_bytes = (addr_digits + 1) // 2
            cursor = 3 + addr_bytes + 2 + 7
            if len(raw) <= cursor:
                return None
            tp_udl = raw[cursor] & 0xFF
            cursor += 1
        else:
            return None
        end = cursor + tp_udl
        if end > len(raw):
            return None
        return raw[cursor:end]

    @classmethod
    def _terminal_response_for_sms_por(cls, fetch_body: bytes) -> str:
        command_details = cls._proactive_command_details_tlv(fetch_body)
        if command_details is None:
            return None
        command_details_raw, command_details_value = command_details
        if len(command_details_value) != 3:
            return None
        command_type = command_details_value[1] & 0xFF
        if command_type != 0x13:
            return None
        if not cls._proactive_has_sms_tpdu(fetch_body):
            return None
        return cls._terminal_response_for_proactive(fetch_body)

    @classmethod
    def _terminal_response_for_proactive(cls, fetch_body: bytes) -> str:
        command_details = cls._proactive_command_details_tlv(fetch_body)
        if command_details is None:
            return None
        command_details_raw, command_details_value = command_details
        if len(command_details_value) != 3:
            return None
        tr_body = command_details_raw + bytes.fromhex("82028281030100")
        return f"80140000{len(tr_body):02X}" + Utils.to_hex(tr_body)

    @classmethod
    def _proactive_command_details_tlv(cls, fetch_body: bytes) -> tuple:
        for tag, value, raw in cls._iter_proactive_tlvs(fetch_body):
            if len(tag) == 1 and (tag[0] & 0x7F) == 0x01:
                return raw, value
        return None

    @classmethod
    def _set_up_event_list_events(cls, fetch_body: bytes) -> Optional[bytes]:
        """The Event list of a SET UP EVENT LIST command; None for any other.

        TS 102 223 V18.3 §9.4 codes the command type '05'; the Event list
        object is tag '19' (TS 101 220 V19.0.0 table 7.23). An empty list
        removes every event and is still an Event list.
        """
        command_details = cls._proactive_command_details_tlv(fetch_body)
        if command_details is None:
            return None
        _details_raw, details_value = command_details
        if len(details_value) != 3 or details_value[1] != 0x05:
            return None
        for tag, value, _raw in cls._iter_proactive_tlvs(fetch_body):
            if len(tag) == 1 and (tag[0] & 0x7F) == 0x19:
                return bytes(value)
        return None

    @classmethod
    def _proactive_has_sms_tpdu(cls, fetch_body: bytes) -> bool:
        for tag, _value, _raw in cls._iter_proactive_tlvs(fetch_body):
            if len(tag) == 1 and (tag[0] & 0x7F) == 0x0B:
                return True
        return False

    @classmethod
    def _iter_proactive_tlvs(cls, fetch_body: bytes):
        root = cls._read_ber_tlv(bytes(fetch_body or b""), 0)
        if root is None:
            return
        root_tag, root_value, _root_raw, _root_next = root
        if root_tag == b"\xd0":
            body = root_value
        else:
            body = bytes(fetch_body or b"")
        offset = 0
        while offset < len(body):
            parsed = cls._read_ber_tlv(body, offset)
            if parsed is None:
                return
            tag, value, raw, offset = parsed
            yield tag, value, raw

    @staticmethod
    def _read_ber_tlv(data: bytes, offset: int) -> tuple:
        raw = bytes(data or b"")
        start = int(offset)
        if start < 0 or start >= len(raw):
            return None
        cursor = start + 1
        if raw[start] & 0x1F == 0x1F:
            while cursor < len(raw):
                current = raw[cursor]
                cursor += 1
                if current & 0x80 == 0:
                    break
        tag_end = cursor
        if cursor >= len(raw):
            return None
        first_len = raw[cursor]
        cursor += 1
        if first_len & 0x80:
            count = first_len & 0x7F
            if count == 0 or cursor + count > len(raw):
                return None
            length = int.from_bytes(raw[cursor : cursor + count], "big")
            cursor += count
        else:
            length = first_len
        end = cursor + length
        if end > len(raw):
            return None
        return raw[start:tag_end], raw[cursor:end], raw[start:end], end

    def _spi_expects_por(self) -> bool:
        """Return True when the active SPI requests a PoR from the card.

        ETSI TS 102 225 v19 §5.1.1 coding of the SPI -- second octet, b2-b1:
          00 = No PoR reply
          01 = PoR always required
          10 = PoR required on error (treat as required so errors surface)
          11 = Reserved (treat as required defensively)
        """
        spi_hex = self.cfg.get("spi")
        if not spi_hex:
            return True
        try:
            spi_bytes = Utils.to_bytes(spi_hex)
        except ValueError:
            return True
        if len(spi_bytes) < 2:
            return True
        por_field = spi_bytes[1] & 0x03
        return por_field != 0x00
