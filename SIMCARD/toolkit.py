from __future__ import annotations

import ipaddress
from typing import Any

from SIMCARD import ipa_poll_dns
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
MORE_TIME_COMMAND = 0x02
POLL_INTERVAL_COMMAND = 0x03
POLLING_OFF_COMMAND = 0x04
SET_UP_EVENT_LIST_COMMAND = 0x05
TIMER_MANAGEMENT_COMMAND = 0x27
DECLARE_SERVICE_COMMAND = 0x47
SERVICE_SEARCH_COMMAND = 0x45
GET_SERVICE_INFORMATION_COMMAND = 0x46
PERFORM_CARD_APDU_COMMAND = 0x30
POWER_OFF_CARD_COMMAND = 0x31
POWER_ON_CARD_COMMAND = 0x32
GET_READER_STATUS_COMMAND = 0x33
SET_FRAMES_COMMAND = 0x60
GET_FRAMES_STATUS_COMMAND = 0x61
SET_UP_CALL_COMMAND = 0x10
SEND_SS_COMMAND = 0x11
SEND_USSD_COMMAND = 0x12
SEND_SHORT_MESSAGE_COMMAND = 0x13
SEND_DTMF_COMMAND = 0x14
PLAY_TONE_COMMAND = 0x20
DISPLAY_TEXT_COMMAND = 0x21
GET_INKEY_COMMAND = 0x22
GET_INPUT_COMMAND = 0x23
SELECT_ITEM_COMMAND = 0x24
SET_UP_MENU_COMMAND = 0x25
PROVIDE_LOCAL_INFORMATION_COMMAND = 0x26
SET_UP_IDLE_MODE_TEXT_COMMAND = 0x28
LAUNCH_BROWSER_COMMAND = 0x15
RUN_AT_COMMAND = 0x34
LANGUAGE_NOTIFICATION_COMMAND = 0x35
OPEN_CHANNEL_COMMAND = 0x40
CLOSE_CHANNEL_COMMAND = 0x41
RECEIVE_DATA_COMMAND = 0x42
SEND_DATA_COMMAND = 0x43
GET_CHANNEL_STATUS_COMMAND = 0x44

# 3GPP TS 24.008 §10.5.4.7 Called-party-BCD digit map. Hex digits map
# directly; '*'=0xA, '#'=0xB; 'a'/'b'/'c' are kept for the rare DTMF
# extension case (TS 102 223 §8.13).
TOOLKIT_DIGIT_NIBBLES = {
    "0": 0x0,
    "1": 0x1,
    "2": 0x2,
    "3": 0x3,
    "4": 0x4,
    "5": 0x5,
    "6": 0x6,
    "7": 0x7,
    "8": 0x8,
    "9": 0x9,
    "*": 0xA,
    "#": 0xB,
    "A": 0xC,
    "B": 0xD,
    "C": 0xE,
}


def _encode_timer_value_bcd(seconds: int) -> bytes:
    """ETSI TS 102 223 §8.38 Timer Value -- 3-byte BCD HH/MM/SS.

    Each byte is a swapped-nibble BCD pair: bits 8-5 hold the units
    digit, bits 4-1 the tens digit. Negative or out-of-range inputs
    are clamped to ``[0, 0x4F4F4F]`` (99h:99m:99s) which is the
    maximum representable value.
    """
    total = max(0, int(seconds))
    hours = min(99, total // 3600)
    remainder = total - hours * 3600
    minutes = min(99, remainder // 60)
    secs = min(99, remainder - minutes * 60)

    def _bcd_swap(value: int) -> int:
        units = value % 10
        tens = (value // 10) % 10
        return ((units & 0x0F) << 4) | (tens & 0x0F)

    return bytes((_bcd_swap(hours), _bcd_swap(minutes), _bcd_swap(secs)))


def _decode_timer_value_bcd(value: bytes) -> int:
    """Inverse of :func:`_encode_timer_value_bcd`.

    Truncated buffers are read as zero for the missing fields.
    """
    if len(value) < 3:
        value = bytes(value) + b"\x00" * (3 - len(value))

    def _bcd_unswap(byte_value: int) -> int:
        units = (byte_value >> 4) & 0x0F
        tens = byte_value & 0x0F
        if units > 9 or tens > 9:
            return 0
        return tens * 10 + units

    hours = _bcd_unswap(value[0])
    minutes = _bcd_unswap(value[1])
    secs = _bcd_unswap(value[2])
    return hours * 3600 + minutes * 60 + secs


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
        MORE_TIME_COMMAND: "MORE TIME",
        POLL_INTERVAL_COMMAND: "POLL INTERVAL",
        POLLING_OFF_COMMAND: "POLLING OFF",
        SET_UP_EVENT_LIST_COMMAND: "SET UP EVENT LIST",
        TIMER_MANAGEMENT_COMMAND: "TIMER MANAGEMENT",
        DECLARE_SERVICE_COMMAND: "DECLARE SERVICE",
        SERVICE_SEARCH_COMMAND: "SERVICE SEARCH",
        GET_SERVICE_INFORMATION_COMMAND: "GET SERVICE INFORMATION",
        PERFORM_CARD_APDU_COMMAND: "PERFORM CARD APDU",
        POWER_OFF_CARD_COMMAND: "POWER OFF CARD",
        POWER_ON_CARD_COMMAND: "POWER ON CARD",
        GET_READER_STATUS_COMMAND: "GET READER STATUS",
        SET_FRAMES_COMMAND: "SET FRAMES",
        GET_FRAMES_STATUS_COMMAND: "GET FRAMES STATUS",
        SET_UP_CALL_COMMAND: "SET UP CALL",
        SEND_SS_COMMAND: "SEND SS",
        SEND_USSD_COMMAND: "SEND USSD",
        SEND_SHORT_MESSAGE_COMMAND: "SEND SHORT MESSAGE",
        SEND_DTMF_COMMAND: "SEND DTMF",
        PLAY_TONE_COMMAND: "PLAY TONE",
        DISPLAY_TEXT_COMMAND: "DISPLAY TEXT",
        GET_INKEY_COMMAND: "GET INKEY",
        GET_INPUT_COMMAND: "GET INPUT",
        SELECT_ITEM_COMMAND: "SELECT ITEM",
        SET_UP_MENU_COMMAND: "SET UP MENU",
        PROVIDE_LOCAL_INFORMATION_COMMAND: "PROVIDE LOCAL INFORMATION",
        SET_UP_IDLE_MODE_TEXT_COMMAND: "SET UP IDLE MODE TEXT",
        LAUNCH_BROWSER_COMMAND: "LAUNCH BROWSER",
        RUN_AT_COMMAND: "RUN AT COMMAND",
        LANGUAGE_NOTIFICATION_COMMAND: "LANGUAGE NOTIFICATION",
        OPEN_CHANNEL_COMMAND: "OPEN CHANNEL",
        CLOSE_CHANNEL_COMMAND: "CLOSE CHANNEL",
        RECEIVE_DATA_COMMAND: "RECEIVE DATA",
        SEND_DATA_COMMAND: "SEND DATA",
        GET_CHANNEL_STATUS_COMMAND: "GET CHANNEL STATUS",
    }

    def __init__(self, state: SimCardState) -> None:
        self.state = state
        self._extensions: list[Any] = []
        # Callable[[bytes], tuple[bytes, int, int]] — invoked for each
        # EuiccPackage parsed out of an eIM RECEIVE DATA payload during
        # an active IPA-poll session. Wired by ``SimulatedSimCardEngine``
        # to ``self.sgp.handle_store_data`` so the IPA can act as a
        # proper SGP.32 in-card agent: the eIM speaks ESipa/EuiccPackages
        # over BIP, the IPA forwards each package as STORE DATA on
        # ISD-R. Defaults to ``None`` so unit tests that build a
        # toolkit in isolation are not coupled to the SGP layer.
        self._eim_package_dispatcher: Any = None
        extend_target_with_plugins(self)

    def set_eim_package_dispatcher(self, dispatcher: Any) -> None:
        """Wire the IPA's ESipa-package fan-out target. See SGP.32 §6.5."""
        if dispatcher is not None and callable(dispatcher) is False:
            raise TypeError("eIM package dispatcher must be callable or None.")
        self._eim_package_dispatcher = dispatcher

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
        """ETSI TS 102 221 §11.1.19 TERMINAL CAPABILITY (INS=0xAA).

        The body is a (possibly empty) sequence of single-byte
        COMPREHENSION-TLV objects describing optional terminal
        features. Round-13 decodes the well-known tags into
        ``state.toolkit`` so a paired applet / test can answer
        "does the terminal advertise extended logical channels?"
        without walking the raw blob list.

        Tags handled:

        - ``0x80`` Terminal Power Supply Capability (1 byte).
        - ``0x81`` Extended Logical Channels Support (1 byte: max
          number of additional channels, ``0xFF`` = at least 19).
        - ``0x83`` Additional Interfaces Support (variable).
        - ``0x87`` eUICC related capabilities (variable, per
          SGP.22 §3.4.2 -- e.g. RSP version + SVN).
        - ``0xA9`` E-UTRAN secure-channel keyset hint (some MNOs
          piggy-back a key reference here).

        The raw blob is still appended to ``terminal_capabilities``
        so existing tests / introspection paths keep working.
        """
        normalized = bytes(payload or b"")
        toolkit = self.state.toolkit
        toolkit.terminal_capabilities.append(normalized)
        offset = 0
        while offset + 2 <= len(normalized):
            tag = normalized[offset]
            length = normalized[offset + 1]
            value_start = offset + 2
            value_end = value_start + length
            if value_end > len(normalized):
                break
            value = normalized[value_start:value_end]
            if tag == 0x80 and len(value) >= 1:
                toolkit.terminal_power_supply = int(value[0]) & 0xFF
            elif tag == 0x81 and len(value) >= 1:
                toolkit.terminal_extended_logical_channels = int(value[0]) & 0xFF
            elif tag == 0x83:
                toolkit.terminal_additional_interfaces = bytes(value)
            elif tag == 0x87 or tag == 0xA1:
                # SGP.22 §3.4.2 wraps the eUICC capabilities under
                # tag ``A1`` on some platforms and ``87`` on
                # others. Accept both and keep the raw payload so
                # the upper layer can decode the SVN / RSP fields.
                toolkit.terminal_euicc_capabilities = bytes(value)
            elif tag == 0xA9:
                toolkit.terminal_eutran_secure_channel = bytes(value)
            offset = value_end
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
        """ETSI TS 102 223 §7.1 / 3GPP TS 31.111 §7.1 ENVELOPE dispatch.

        Real cards distinguish between BER-TLV envelopes by their root
        tag and respond with very different shapes; the simulator now
        mirrors that:

        ``D1`` SMS-PP Download              → SCP80 / SMS-PP path.
        ``D2`` Cell Broadcast Download      → recorded; SW=9000.
        ``D3`` Menu Selection               → recorded; SW=9000.
        ``D4`` Call Control by USIM         → spec-shaped Allowed reply.
        ``D5`` MO Short Message Control     → spec-shaped Allowed reply.
        ``D6`` Event Download               → handled locally (existing).
        ``D7`` Timer Expiration             → recorded; SW=9000.
        ``D8`` USSD Download                → spec-shaped Allowed reply.

        Anything else falls through to the legacy SCP80 handler so
        plaintext OTA flows keep working.
        """
        normalized = bytes(payload or b"")
        self.state.toolkit.envelope_history.append(normalized)
        envelope_tag = normalized[:1] if len(normalized) > 0 else b""

        if envelope_tag == b"\xD6":
            event_fields = self._parse_event_download(normalized)
            if event_fields is not None:
                self._handle_event_download(event_fields)
                return self._pending_status()

        if envelope_tag == b"\xD1":
            response = fallback_handler(normalized)
            if len(self.state.toolkit.active_proactive_command) > 0:
                return self._pending_status()
            if len(self.state.pending_fetch_queue) > 0:
                return self._pending_status()
            return response

        if envelope_tag == b"\xD7":
            # 3GPP TS 31.111 §7.5.6 Timer Expiration envelope. The
            # body carries the matching timer-id (and optionally the
            # final timer value). Latch the id so an STK applet can
            # decide whether to re-arm the timer; remove the entry
            # from ``timer_table`` because the timer is no longer
            # running.
            self._apply_timer_expiration(normalized)
            if len(self.state.pending_fetch_queue) > 0:
                return self._pending_status()
            return b"", 0x90, 0x00

        if envelope_tag == b"\xD2":
            # 3GPP TS 23.041 §9.4.1 Cell Broadcast Download. The
            # CB page TLV (tag 0x8C) carries a fixed 88-byte
            # structure. Decode it into ``state.toolkit`` so an
            # STK applet can correlate the message-id without
            # walking ``envelope_history``.
            self._apply_cell_broadcast_download(normalized)
            if len(self.state.pending_fetch_queue) > 0:
                return self._pending_status()
            return b"", 0x90, 0x00

        if envelope_tag == b"\xD3":
            # ETSI TS 102 223 §7.5.6 Menu Selection. Decodes the
            # user-selected item identifier (TLV 0x90) and the
            # optional help-request flag from the device-identities
            # qualifier byte; both are latched into
            # ``state.toolkit`` for STK applets to consume.
            self._apply_menu_selection(normalized)
            if len(self.state.pending_fetch_queue) > 0:
                return self._pending_status()
            return b"", 0x90, 0x00

        if envelope_tag == b"\xD4":
            # 3GPP TS 31.111 §7.3.1 Call Control by USIM. The body
            # carries dialled digits / sub-address / location info
            # which round-19 now decodes into ``state.toolkit``;
            # the reply remains the canned "Allowed, no
            # modification" Result TLV because the simulator does
            # not host operator-specific call-control logic.
            self._apply_call_control_envelope(normalized)
            response = bytes.fromhex("8001 00".replace(" ", ""))
            if len(self.state.pending_fetch_queue) > 0:
                return self._pending_status()
            return response, 0x90, 0x00

        if envelope_tag == b"\xD5":
            # 3GPP TS 31.111 §7.3.2 MO Short Message Control. Body
            # carries RP-DA + RP-OA Address TLVs and the
            # calling-area Location Information; round 19 now
            # decodes them into ``state.toolkit``. Reply still
            # echoes "Allowed, no modification".
            self._apply_mo_sms_control_envelope(normalized)
            response = bytes.fromhex("80 01 00".replace(" ", ""))
            if len(self.state.pending_fetch_queue) > 0:
                return self._pending_status()
            return response, 0x90, 0x00

        if envelope_tag == b"\xD8":
            # 3GPP TS 31.111 §7.3.3 USSD Download. Body carries
            # the network-side USSD String (TLV 8A = DCS + text);
            # round 19 decodes both halves into ``state.toolkit``.
            # The reply remains "Allowed, no modification".
            self._apply_ussd_download_envelope(normalized)
            response = bytes.fromhex("80 01 00".replace(" ", ""))
            if len(self.state.pending_fetch_queue) > 0:
                return self._pending_status()
            return response, 0x90, 0x00

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

    # ------------------------------------------------------------------
    # Voice / SMS / data / UI proactive queueables (ETSI TS 102 223 §6.6).
    #
    # Each helper allocates a command number, composes the spec-defined
    # info-object TLVs, and appends the resulting D0 envelope to
    # ``state.pending_fetch_queue`` so the next STATUS announces 91xx and
    # the next FETCH delivers it. Tag values follow the comprehension-
    # required forms used by commercial UICCs (see TS 102 223 Annex A).
    # ------------------------------------------------------------------

    def queue_setup_call(
        self,
        called_number: str,
        *,
        alpha_identifier: str = "",
        qualifier: int = 0x00,
        capability_config: bytes = b"",
        sub_address: bytes = b"",
        duration_seconds: int = 0,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.13 SET UP CALL."""
        extra = self._build_alpha_id_tlv(alpha_identifier)
        extra += self._build_address_tlv(called_number)
        if len(capability_config) > 0:
            extra += tlv("87", bytes(capability_config))
        if len(sub_address) > 0:
            extra += tlv("88", bytes(sub_address))
        if duration_seconds > 0:
            extra += tlv("84", self._encode_duration_tlv(int(duration_seconds)))
        return self._enqueue_named(SET_UP_CALL_COMMAND, qualifier, extra)

    def queue_send_ss(self, ss_string: str, *, qualifier: int = 0x00) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.11 SEND SS / 3GPP TS 31.111 §6.4.11."""
        extra = tlv("89", self._encode_dialled_digits(ss_string, ton_npi=0x91))
        return self._enqueue_named(SEND_SS_COMMAND, qualifier, extra)

    def queue_send_ussd(
        self,
        ussd_text: str,
        *,
        dcs: int = 0x0F,
        qualifier: int = 0x00,
        alpha_identifier: str = "",
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.12 SEND USSD."""
        extra = self._build_alpha_id_tlv(alpha_identifier)
        encoded = bytes((int(dcs) & 0xFF,)) + str(ussd_text or "").encode("ascii", "ignore")
        extra += tlv("8A", encoded)
        return self._enqueue_named(SEND_USSD_COMMAND, qualifier, extra)

    def queue_send_short_message(
        self,
        *,
        tpdu: bytes = b"",
        destination: str = "",
        text: str = "",
        alpha_identifier: str = "",
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.10 SEND SHORT MESSAGE.

        Either supply a raw 3GPP TS 23.040 SMS-SUBMIT ``tpdu`` (most
        flexible) or the convenience pair ``destination`` + ``text``,
        which builds a minimal SMS-SUBMIT with default 7-bit packing.
        """
        body = self._build_alpha_id_tlv(alpha_identifier)
        if len(destination) > 0 and len(tpdu) == 0:
            body += self._build_address_tlv(destination)
        encoded_tpdu = bytes(tpdu or b"")
        if len(encoded_tpdu) == 0:
            encoded_tpdu = self._build_minimal_sms_submit_tpdu(destination, text)
        body += tlv("8B", encoded_tpdu)
        return self._enqueue_named(SEND_SHORT_MESSAGE_COMMAND, qualifier, body)

    def queue_send_dtmf(
        self,
        digits: str,
        *,
        qualifier: int = 0x00,
        alpha_identifier: str = "",
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.24 SEND DTMF."""
        extra = self._build_alpha_id_tlv(alpha_identifier)
        extra += tlv("AC", self._encode_dtmf_digits(digits))
        return self._enqueue_named(SEND_DTMF_COMMAND, qualifier, extra)

    def queue_play_tone(
        self,
        *,
        tone: int = 0x01,
        duration_seconds: int = 1,
        alpha_identifier: str = "",
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.5 PLAY TONE."""
        extra = self._build_alpha_id_tlv(alpha_identifier)
        extra += tlv("8E", bytes((int(tone) & 0xFF,)))
        extra += tlv("84", self._encode_duration_tlv(int(duration_seconds)))
        return self._enqueue_named(PLAY_TONE_COMMAND, qualifier, extra)

    def queue_display_text(
        self,
        text: str,
        *,
        high_priority: bool = False,
        wait_for_user_clear: bool = False,
        prefer_ucs2: bool = False,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.1 DISPLAY TEXT."""
        qualifier = 0x00
        if high_priority:
            qualifier |= 0x01
        if wait_for_user_clear:
            qualifier |= 0x80
        extra = self._build_text_string_tlv(text, prefer_ucs2=prefer_ucs2)
        return self._enqueue_named(DISPLAY_TEXT_COMMAND, qualifier, extra)

    def queue_get_inkey(
        self,
        prompt: str,
        *,
        digit_only: bool = False,
        ucs2: bool = False,
        yes_no: bool = False,
        help_available: bool = False,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.2 GET INKEY."""
        qualifier = 0x00
        if ucs2:
            qualifier |= 0x01
        if digit_only:
            qualifier |= 0x02
        if yes_no:
            qualifier |= 0x04
        if help_available:
            qualifier |= 0x80
        extra = self._build_text_string_tlv(prompt, prefer_ucs2=ucs2)
        return self._enqueue_named(GET_INKEY_COMMAND, qualifier, extra)

    def queue_get_input(
        self,
        prompt: str,
        *,
        min_length: int = 0,
        max_length: int = 0xFF,
        digit_only: bool = False,
        ucs2: bool = False,
        echo_input: bool = True,
        unpacked: bool = True,
        default_text: str = "",
        help_available: bool = False,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.3 GET INPUT."""
        qualifier = 0x00
        if ucs2:
            qualifier |= 0x01
        if digit_only:
            qualifier |= 0x02
        if echo_input is False:
            qualifier |= 0x04
        if unpacked is False:
            qualifier |= 0x08
        if help_available:
            qualifier |= 0x80
        bounded_min = max(0, min(0xFF, int(min_length)))
        bounded_max = max(bounded_min, min(0xFF, int(max_length)))
        extra = self._build_text_string_tlv(prompt, prefer_ucs2=ucs2)
        extra += tlv("91", bytes((bounded_min, bounded_max)))
        if len(str(default_text or "")) > 0:
            extra += tlv("97", self._encode_default_text_value(default_text, prefer_ucs2=ucs2))
        return self._enqueue_named(GET_INPUT_COMMAND, qualifier, extra)

    def queue_select_item(
        self,
        items: list[SimToolkitMenuItem] | list[tuple[int, str]],
        *,
        title: str = "",
        qualifier: int = 0x00,
        default_item_identifier: int | None = None,
        help_available: bool = False,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.9 SELECT ITEM."""
        effective_qualifier = int(qualifier) & 0xFF
        if help_available:
            effective_qualifier |= 0x80
        normalized_items = [self._normalize_menu_item(item) for item in (items or [])]
        extra = self._build_alpha_id_tlv(title)
        extra += b"".join(self._build_menu_item(item) for item in normalized_items)
        if default_item_identifier is not None:
            extra += tlv("90", bytes((int(default_item_identifier) & 0xFF,)))
        return self._enqueue_named(SELECT_ITEM_COMMAND, effective_qualifier, extra)

    def queue_setup_menu(
        self,
        items: list[SimToolkitMenuItem] | list[tuple[int, str]] | None = None,
        *,
        title: str | None = None,
        remove_menu: bool = False,
        help_available: bool = False,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.8 SET UP MENU.

        When ``items`` / ``title`` are omitted the active simulator
        menu (``state.toolkit.menu_items`` / ``menu_title``) is used,
        matching the bootstrap helper.
        """
        toolkit = self.state.toolkit
        if title is not None:
            toolkit.menu_title = str(title)
        if items is not None:
            toolkit.menu_items = [self._normalize_menu_item(entry) for entry in items]
        qualifier = 0x80 if help_available else 0x00
        if remove_menu:
            qualifier |= 0x01
        command_number = self._allocate_command_number()
        if remove_menu:
            payload = self._proactive_command(command_number, SET_UP_MENU_COMMAND, qualifier)
        else:
            payload = self._build_set_up_menu_with_qualifier(command_number, qualifier)
        self._enqueue_command(payload)
        return self._build_queue_result(
            "queued",
            payload,
            self._command_name_token(SET_UP_MENU_COMMAND),
            qualifier,
        )

    def queue_provide_local_information(
        self,
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.15 PROVIDE LOCAL INFORMATION.

        Common qualifiers per §6.6.15:
        ``0x00`` location-info, ``0x01`` IMEI, ``0x03`` date/time/zone,
        ``0x04`` language, ``0x06`` access-technology.
        """
        return self._enqueue_named(PROVIDE_LOCAL_INFORMATION_COMMAND, qualifier, b"")

    def queue_setup_idle_mode_text(self, text: str) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.18 SET UP IDLE MODE TEXT."""
        extra = self._build_text_string_tlv(text)
        return self._enqueue_named(SET_UP_IDLE_MODE_TEXT_COMMAND, 0x00, extra)

    def queue_launch_browser(
        self,
        url: str,
        *,
        browser_identity: int = 0x00,
        alpha_identifier: str = "",
        qualifier: int = 0x02,
        gateway_proxy: str = "",
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.26 LAUNCH BROWSER.

        Default ``qualifier=0x02`` selects "use the default URL"; pass
        ``0x03`` to force "open URL in the existing browser session"
        per §6.6.26. The TLVs follow Annex A:

        - ``30`` Browser Identity (1 byte; 0x00 default browser).
        - ``31`` URL (UTF-8 octets).
        - ``85`` Alpha Identifier (optional).
        - ``32`` Bearer description / gateway-proxy text (optional).

        Returns the same enqueue-result dict as the other proactive
        helpers so a polling tool can correlate the command number
        with the next FETCH.
        """
        extra = tlv("30", bytes((int(browser_identity) & 0xFF,)))
        extra += tlv("31", str(url or "").encode("utf-8"))
        extra += self._build_alpha_id_tlv(alpha_identifier)
        gateway_text = str(gateway_proxy or "").strip()
        if len(gateway_text) > 0:
            extra += tlv("32", gateway_text.encode("utf-8"))
        return self._enqueue_named(LAUNCH_BROWSER_COMMAND, qualifier, extra)

    def queue_run_at_command(
        self,
        at_command: str,
        *,
        alpha_identifier: str = "",
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.26 RUN AT COMMAND.

        Drives the modem's AT parser from the SIM side. Common test
        vectors include ``AT+CGMM`` (model query) and ``AT+CSQ``
        (signal quality).
        """
        extra = self._build_alpha_id_tlv(alpha_identifier)
        extra += tlv("A8", str(at_command or "").encode("ascii", "ignore"))
        return self._enqueue_named(RUN_AT_COMMAND, 0x00, extra)

    def queue_language_notification(
        self,
        language: str,
        *,
        specific: bool = True,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.27 LANGUAGE NOTIFICATION."""
        qualifier = 0x01 if specific else 0x00
        extra = b""
        if specific:
            iso_code = str(language or "").strip().lower()[:2]
            extra = tlv("AD", iso_code.encode("ascii", "ignore"))
        return self._enqueue_named(LANGUAGE_NOTIFICATION_COMMAND, qualifier, extra)

    def queue_setup_event_list(
        self,
        events: list[int] | list[str],
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.16 SET UP EVENT LIST."""
        codes = bytes(self._coerce_event_code(entry) for entry in (events or []))
        self.state.toolkit.event_list = list(codes)
        command_number = self._allocate_command_number()
        payload = self._build_set_up_event_list(command_number, list(codes))
        self._enqueue_command(payload)
        return self._build_queue_result(
            "queued",
            payload,
            self._command_name_token(SET_UP_EVENT_LIST_COMMAND),
            0x00,
        )

    def queue_polling_off(self) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.7 POLLING OFF."""
        command_number = self._allocate_command_number()
        payload = self._proactive_command(command_number, POLLING_OFF_COMMAND, 0x00)
        self._enqueue_command(payload)
        return self._build_queue_result(
            "queued",
            payload,
            self._command_name_token(POLLING_OFF_COMMAND),
            0x00,
        )

    def queue_more_time(self) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.2 MORE TIME.

        Issued by an STK applet that needs to extend the response
        window of the currently executing command (e.g. a long-running
        SELECT or VERIFY). The proactive command body carries only
        Command Details + Device Identities; the qualifier is reserved
        as 0x00.
        """
        return self._enqueue_named(MORE_TIME_COMMAND, 0x00, b"")

    def queue_timer_management(
        self,
        *,
        timer_id: int,
        qualifier: int,
        timer_value_seconds: int = 0,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.27 TIMER MANAGEMENT.

        ``qualifier`` selects the sub-function per §6.6.27:

        - 0x00 start the timer with the supplied ``timer_value_seconds``
          (encoded as the BCD HH/MM/SS triple in TLV 0x25).
        - 0x01 deactivate the timer; the value TLV is omitted.
        - 0x02 get the timer's current value; the value TLV is omitted.

        ``timer_id`` is 1..8 per spec; values outside that range are
        clamped because real cards reject them with 6A86 but the
        helper keeps the surface forgiving for tests.

        TLV tags are emitted comprehension-clear (24 / 25) so picky
        modems that drop the CR-set form (A4 / A5) can still parse the
        proactive command -- this matches what reference IPA cards
        emit during the SGP.32 IPA-poll cycle.
        """
        normalized_id = int(timer_id) & 0xFF
        if normalized_id < 0x01 or normalized_id > 0x08:
            normalized_id = 0x01
        normalized_qualifier = int(qualifier) & 0xFF
        extra = tlv("24", bytes((normalized_id,)))
        if normalized_qualifier == 0x00:
            extra += tlv("25", _encode_timer_value_bcd(int(timer_value_seconds)))
            # Cache the requested setpoint so the TR-side latch can
            # populate ``timer_table`` even when the terminal omits
            # the echo TLV. Only mutate the table for "start" so a
            # deactivate/get-value queue does not zero an entry that
            # a previous start had populated.
            self.state.toolkit.timer_table[normalized_id] = max(0, int(timer_value_seconds))
        return self._enqueue_named(TIMER_MANAGEMENT_COMMAND, normalized_qualifier, extra)

    def queue_declare_service(
        self,
        *,
        service_record: bytes,
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.34 DECLARE SERVICE.

        ``service_record`` is the raw service-record TLV (TS 102 223
        §8.66) and is appended to ``state.toolkit.declared_services``
        on enqueue so subsequent SERVICE SEARCH / GET SERVICE
        INFORMATION commands can advertise the registration.
        """
        record = bytes(service_record or b"")
        if len(record) > 0:
            self.state.toolkit.declared_services.append(record)
        extra = tlv("61", record) if len(record) > 0 else b""
        return self._enqueue_named(DECLARE_SERVICE_COMMAND, int(qualifier) & 0xFF, extra)

    def queue_service_search(
        self,
        *,
        service_record: bytes,
        device_filter: bytes = b"",
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.32 SERVICE SEARCH.

        ``service_record`` (TLV ``61``) is the pattern the terminal
        compares against the previously declared services.
        ``device_filter`` (TLV ``63``) optionally restricts the search
        to a specific device class (handset, USB, etc.). Successful
        SERVICE SEARCH replies carry a Service Record TLV in the
        terminal response; ``_apply_service_search_response`` latches
        the matching blob into ``state.toolkit.last_service_search_result``.
        """
        record = bytes(service_record or b"")
        extra = tlv("61", record)
        if len(device_filter) > 0:
            extra += tlv("63", bytes(device_filter))
        return self._enqueue_named(SERVICE_SEARCH_COMMAND, int(qualifier) & 0xFF, extra)

    def queue_get_service_information(
        self,
        *,
        service_record: bytes,
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.33 GET SERVICE INFORMATION.

        ``service_record`` is the service identifier whose detailed
        information should be retrieved. The terminal replies with a
        Service Information TLV (``62`` / ``E2`` -- TS 102 223 §8.66);
        the simulator latches the blob into
        ``state.toolkit.last_service_information``.
        """
        record = bytes(service_record or b"")
        extra = tlv("61", record)
        return self._enqueue_named(
            GET_SERVICE_INFORMATION_COMMAND,
            int(qualifier) & 0xFF,
            extra,
        )

    def queue_perform_card_apdu(
        self,
        *,
        card_apdu: bytes,
        reader_id: int = 0,
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.11 PERFORM CARD APDU.

        Encapsulates a standard ISO 7816-4 command APDU
        (``card_apdu``) the terminal must forward to another
        smart-card reader. ``reader_id`` is encoded as the C-APDU
        device identity per §8.7. The terminal response carries the
        R-APDU under TLV ``A4`` / ``24``; on success the blob is
        latched into ``state.toolkit.last_card_apdu_response``.
        """
        if int(reader_id) & 0xFF == 0:
            device_pair = bytes((0x82, 0x81))
        else:
            device_pair = bytes((0x82, int(reader_id) & 0xFF))
        # The default device-identities pair (UICC -> terminal) is
        # rewritten in ``_proactive_command``; here we override with
        # an inline TLV that targets the additional reader.
        extra = tlv("82", device_pair) + tlv("A4", bytes(card_apdu or b""))
        return self._enqueue_named(
            PERFORM_CARD_APDU_COMMAND,
            int(qualifier) & 0xFF,
            extra,
        )

    def queue_power_off_card(
        self,
        *,
        reader_id: int = 1,
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.12 POWER OFF CARD."""
        normalized_reader = int(reader_id) & 0xFF
        if normalized_reader == 0:
            normalized_reader = 0x01
        extra = tlv("82", bytes((0x82, normalized_reader)))
        return self._enqueue_named(
            POWER_OFF_CARD_COMMAND,
            int(qualifier) & 0xFF,
            extra,
        )

    def queue_power_on_card(
        self,
        *,
        reader_id: int = 1,
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.13 POWER ON CARD."""
        normalized_reader = int(reader_id) & 0xFF
        if normalized_reader == 0:
            normalized_reader = 0x01
        extra = tlv("82", bytes((0x82, normalized_reader)))
        return self._enqueue_named(
            POWER_ON_CARD_COMMAND,
            int(qualifier) & 0xFF,
            extra,
        )

    def queue_set_frames(
        self,
        *,
        frame_identifier: int,
        frame_layout: bytes,
        default_frame_identifier: int = 0,
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.36 SET FRAMES (proactive type 0x60).

        Builds the proactive command body with:

        - Frame Identifier (TLV ``47``, 1 byte) -- frame being set.
        - Frame Layout (TLV ``48``) -- structured layout (display
          dimensions / position) per §8.80.
        - Default Frame Identifier (TLV ``49``, 1 byte) -- which
          frame the terminal should render in if no further SET
          FRAMES qualifies a different one.

        The TLV tags carried here do NOT collide with the SS-string
        / USSD-string tags (``89`` / ``8A``) used by the envelope
        path: TS 102 223 §8.79 reuses the lower nibble but selects
        the comprehension-required form ``47`` / ``48`` / ``49``
        explicitly.
        """
        layout = bytes(frame_layout or b"")
        if len(layout) == 0:
            raise ValueError("SET FRAMES requires a non-empty frame layout.")
        extra = (
            tlv("47", bytes((int(frame_identifier) & 0xFF,)))
            + tlv("48", layout)
            + tlv("49", bytes((int(default_frame_identifier) & 0xFF,)))
        )
        return self._enqueue_named(
            SET_FRAMES_COMMAND,
            int(qualifier) & 0xFF,
            extra,
        )

    def queue_get_frames_status(
        self,
        *,
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.37 GET FRAMES STATUS (type 0x61).

        Empty body. The terminal returns a Frames Information TLV
        (``49`` / ``C9``) carrying the negotiated frames count and
        active frame; the apply layer caches it into
        ``state.toolkit.last_frames_information``.
        """
        return self._enqueue_named(
            GET_FRAMES_STATUS_COMMAND,
            int(qualifier) & 0xFF,
            b"",
        )

    def queue_get_reader_status(
        self,
        *,
        qualifier: int = 0x00,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.14 GET READER STATUS.

        ``qualifier`` selects the requested information per §6.6.14:

        - ``0x00`` reader identifier list (terminal returns a series
          of TLV ``E0`` reader-information records).
        - ``0x01`` card status of a specific reader (the reader id is
          carried in the device-identities TLV; here we always target
          the default terminal reader).
        """
        return self._enqueue_named(
            GET_READER_STATUS_COMMAND,
            int(qualifier) & 0xFF,
            b"",
        )


    def queue_poll_interval(self, seconds: int) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.6 POLL INTERVAL."""
        command_number = self._allocate_command_number()
        payload = self._build_poll_interval(command_number, max(1, int(seconds)))
        self._enqueue_command(payload)
        return self._build_queue_result(
            "queued",
            payload,
            self._command_name_token(POLL_INTERVAL_COMMAND),
            0x00,
        )

    # ------------------------------------------------------------------
    # BIP queueables (ETSI TS 102 223 §6.6.27 .. §6.6.31).
    # ------------------------------------------------------------------

    def queue_open_channel(
        self,
        *,
        remote_address: str,
        remote_port: int,
        transport_protocol_type: int = 0x02,
        network_access_name: str = "",
        buffer_size: int = 0x0400,
        immediate: bool = False,
        automatic_reconnect: bool = False,
        alpha_identifier: str = "",
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.27 OPEN CHANNEL.

        Defaults to TCP-client-remote (``transport_protocol_type=0x02``)
        with a 1024-byte buffer. ``immediate=True`` flips bit 0 of the
        qualifier so the terminal links the bearer up before returning;
        ``automatic_reconnect=True`` flips bit 1 so the modem keeps the
        bearer up even if the remote drops it.
        """
        qualifier = 0x00
        if immediate:
            qualifier |= 0x01
        if automatic_reconnect:
            qualifier |= 0x02
        command_number = self._allocate_command_number()
        body = self._build_open_channel_command(
            command_number,
            remote_address=remote_address,
            remote_port=remote_port,
            transport_protocol_type=transport_protocol_type,
            network_access_name=network_access_name,
            buffer_size=buffer_size,
            qualifier=qualifier,
            alpha_identifier=alpha_identifier,
        )
        self._enqueue_command(body)
        return self._build_queue_result(
            "queued",
            body,
            self._command_name_token(OPEN_CHANNEL_COMMAND),
            qualifier,
        )

    def queue_close_channel(self) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.28 CLOSE CHANNEL."""
        command_number = self._allocate_command_number()
        payload = self._build_close_channel_command(command_number)
        self._enqueue_command(payload)
        return self._build_queue_result(
            "queued",
            payload,
            self._command_name_token(CLOSE_CHANNEL_COMMAND),
            0x00,
        )

    def queue_send_data(
        self,
        channel_data: bytes,
        *,
        immediate: bool = True,
    ) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.29 SEND DATA.

        ``immediate=True`` (default) sets qualifier bit 0 so the
        terminal flushes the channel buffer right after the TLV is
        consumed; ``False`` leaves the bytes accumulated for later
        flushing.
        """
        qualifier = 0x01 if immediate else 0x00
        command_number = self._allocate_command_number()
        payload = self._build_send_data_command_with_qualifier(
            command_number,
            qualifier,
            bytes(channel_data or b""),
        )
        self._enqueue_command(payload)
        return self._build_queue_result(
            "queued",
            payload,
            self._command_name_token(SEND_DATA_COMMAND),
            qualifier,
        )

    def queue_receive_data(self, requested_length: int) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.30 RECEIVE DATA."""
        command_number = self._allocate_command_number()
        payload = self._build_receive_data_command(command_number, max(1, int(requested_length)))
        self._enqueue_command(payload)
        return self._build_queue_result(
            "queued",
            payload,
            self._command_name_token(RECEIVE_DATA_COMMAND),
            0x00,
        )

    def queue_get_channel_status(self) -> dict[str, str | int | list[str]]:
        """ETSI TS 102 223 §6.4.31 GET CHANNEL STATUS."""
        command_number = self._allocate_command_number()
        payload = self._proactive_command(command_number, GET_CHANNEL_STATUS_COMMAND, 0x00)
        self._enqueue_command(payload)
        return self._build_queue_result(
            "queued",
            payload,
            self._command_name_token(GET_CHANNEL_STATUS_COMMAND),
            0x00,
        )

    # ------------------------------------------------------------------
    # Internal builders for the proactive helpers above.
    # ------------------------------------------------------------------

    def _enqueue_named(
        self,
        command_type: int,
        qualifier: int,
        extra_tlvs: bytes,
    ) -> dict[str, str | int | list[str]]:
        command_number = self._allocate_command_number()
        payload = self._proactive_command(
            command_number,
            int(command_type) & 0xFF,
            int(qualifier) & 0xFF,
            bytes(extra_tlvs or b""),
        )
        self._enqueue_command(payload)
        return self._build_queue_result(
            "queued",
            payload,
            self._command_name_token(command_type),
            int(qualifier) & 0xFF,
        )

    def _command_name_token(self, command_type: int) -> str:
        raw_name = self.COMMAND_NAMES.get(int(command_type) & 0xFF, f"0x{int(command_type) & 0xFF:02X}")
        return raw_name.lower().replace(" ", "-")

    @staticmethod
    def _normalize_menu_item(item) -> SimToolkitMenuItem:
        if isinstance(item, SimToolkitMenuItem):
            return item
        if isinstance(item, dict):
            return SimToolkitMenuItem(
                identifier=int(item.get("identifier", 0)) & 0xFF,
                text=str(item.get("text", "")),
            )
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            return SimToolkitMenuItem(identifier=int(item[0]) & 0xFF, text=str(item[1]))
        raise TypeError(f"Cannot coerce {type(item)!r} to SimToolkitMenuItem.")

    @staticmethod
    def _coerce_event_code(value) -> int:
        if isinstance(value, int):
            return int(value) & 0xFF
        normalized = str(value or "").strip()
        if normalized.lower().startswith("0x"):
            return int(normalized, 16) & 0xFF
        if normalized.isdigit():
            return int(normalized) & 0xFF
        raise ValueError(f"Unknown event code: {value!r}")

    @staticmethod
    def _build_alpha_id_tlv(text: str) -> bytes:
        cleaned = str(text or "")
        return tlv("85", cleaned.encode("utf-8")) if len(cleaned) > 0 else b""

    def _build_address_tlv(self, number: str, *, ton_npi: int = 0x91) -> bytes:
        encoded = self._encode_dialled_digits(number, ton_npi=ton_npi)
        if len(encoded) == 0:
            return b""
        return tlv("86", encoded)

    @staticmethod
    def _encode_dialled_digits(number: str, *, ton_npi: int = 0x91) -> bytes:
        digits = "".join(ch for ch in str(number or "") if ch in "0123456789*#abcABC")
        if len(digits) == 0:
            return b""
        # 3GPP TS 24.008 §10.5.4.7 packs 2 digits per byte, low nibble
        # first, with 0xF padding the last nibble for odd counts.
        packed = bytearray()
        for index in range(0, len(digits), 2):
            low = TOOLKIT_DIGIT_NIBBLES.get(digits[index].upper(), 0xF)
            if index + 1 < len(digits):
                high = TOOLKIT_DIGIT_NIBBLES.get(digits[index + 1].upper(), 0xF)
            else:
                high = 0xF
            packed.append((high << 4) | (low & 0x0F))
        return bytes((int(ton_npi) & 0xFF,)) + bytes(packed)

    @staticmethod
    def _encode_dtmf_digits(digits: str) -> bytes:
        return ToolkitLogic._encode_dialled_digits(digits, ton_npi=0x80)[1:] or b""

    @staticmethod
    def _build_text_string_tlv(text: str, *, prefer_ucs2: bool = False) -> bytes:
        raw = str(text or "")
        if prefer_ucs2 or any(ord(ch) > 0x7F for ch in raw):
            return tlv("8D", b"\x08" + raw.encode("utf-16-be"))
        return tlv("8D", b"\x04" + raw.encode("ascii", "ignore"))

    @staticmethod
    def _encode_default_text_value(text: str, *, prefer_ucs2: bool = False) -> bytes:
        raw = str(text or "")
        if prefer_ucs2 or any(ord(ch) > 0x7F for ch in raw):
            return b"\x08" + raw.encode("utf-16-be")
        return b"\x04" + raw.encode("ascii", "ignore")

    def _build_minimal_sms_submit_tpdu(self, destination: str, text: str) -> bytes:
        # 3GPP TS 23.040 §9.2.2.2 SMS-SUBMIT, default for tests:
        #   First octet:  0x01 (MTI=01, no TP-VPF, no TP-RD/SRR/UDHI/RP)
        #   TP-MR:        0x00
        #   TP-DA:        length-of-digits || TON/NPI || packed BCD
        #   TP-PID:       0x00
        #   TP-DCS:       0x00 (GSM 7-bit, no message class)
        #   TP-UDL:       length of unpacked septets
        #   TP-UD:        7-bit packed user data
        digits = "".join(ch for ch in str(destination or "") if ch.isdigit())
        if len(digits) == 0:
            return b""
        body = self._encode_dialled_digits(digits)
        ton_npi = body[:1]
        bcd = body[1:]
        tp_da = bytes((len(digits),)) + ton_npi + bcd
        body_text = str(text or "")
        ud_septets = bytes(ord(ch) & 0x7F for ch in body_text)
        packed_ud = self._pack_gsm_7bit_septets(ud_septets)
        return (
            b"\x01"
            + b"\x00"
            + tp_da
            + b"\x00"
            + b"\x00"
            + bytes((len(ud_septets) & 0xFF,))
            + packed_ud
        )

    @staticmethod
    def _pack_gsm_7bit_septets(septets: bytes) -> bytes:
        out = bytearray()
        bit_buffer = 0
        bit_count = 0
        for septet in septets:
            bit_buffer |= (int(septet) & 0x7F) << bit_count
            bit_count += 7
            while bit_count >= 8:
                out.append(bit_buffer & 0xFF)
                bit_buffer >>= 8
                bit_count -= 8
        if bit_count > 0:
            out.append(bit_buffer & 0xFF)
        return bytes(out)

    def _build_set_up_menu_with_qualifier(self, command_number: int, qualifier: int) -> bytes:
        toolkit = self.state.toolkit
        title_text = str(toolkit.menu_title or "").strip()
        title_value = b""
        if len(title_text) > 0:
            title_value = title_text.encode("utf-8")
        title_tlv = tlv("85", title_value)
        item_tlvs = b"".join(self._build_menu_item(item) for item in toolkit.menu_items)
        return self._proactive_command(
            command_number,
            SET_UP_MENU_COMMAND,
            int(qualifier) & 0xFF,
            title_tlv + item_tlvs,
        )

    def _build_send_data_command_with_qualifier(
        self,
        command_number: int,
        qualifier: int,
        payload: bytes,
    ) -> bytes:
        extra_tlvs = tlv("36", bytes(payload or b""))
        return self._proactive_command(
            command_number,
            SEND_DATA_COMMAND,
            int(qualifier) & 0xFF,
            extra_tlvs,
            device_pair=self._bip_followup_device_pair(),
        )

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

        # SGP.32 §3.5 IPA-poll trigger: prefer TIMER MANAGEMENT START
        # so the modem will emit an ENVELOPE (Timer Expiration / D7)
        # at the cadence we set, instead of the bare STATUS heartbeats
        # POLL INTERVAL produces. ``poll_strategy`` decides which path
        # to wire up at TERMINAL PROFILE time; "both" keeps the legacy
        # POLL INTERVAL active alongside the timer for defensive
        # bring-up in mixed terminals.
        strategy = str(toolkit.poll_strategy or "timer").strip().lower()
        if strategy not in {"timer", "poll_interval", "both", "off"}:
            strategy = "timer"
        timer_seconds = int(toolkit.timer_management_seconds or 0)
        poll_seconds = int(toolkit.poll_interval_seconds or 0)

        if strategy in {"timer", "both"} and timer_seconds > 0:
            commands.append(
                self._build_timer_management_start(
                    self._allocate_command_number(),
                    int(toolkit.timer_management_id or 1) or 1,
                    timer_seconds,
                )
            )

        if strategy in {"poll_interval", "both"} and poll_seconds > 0:
            commands.append(
                self._build_poll_interval(
                    self._allocate_command_number(),
                    poll_seconds,
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
            self._apply_open_channel_response(command_fields, response_fields, succeeded)
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
            return
        if command_type == PROVIDE_LOCAL_INFORMATION_COMMAND:
            # Round 18: latch the result-code + qualifier echo
            # ahead of the rich payload handler so a polling tool
            # can confirm "I asked for X and the terminal answered
            # with X" without diffing every individual cache.
            self.state.toolkit.last_provide_local_information_result = int(
                response_fields.get("result_code", 0x00) or 0x00
            ) & 0xFF
            self.state.toolkit.last_provide_local_information_qualifier = int(
                command_fields.get("qualifier", 0) or 0
            ) & 0xFF
            self._apply_provide_local_information_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == TIMER_MANAGEMENT_COMMAND:
            # Round 18: latch the result-code so a polling applet
            # can tell "terminal accepted start" (0x00) from
            # "terminal busy" (0x20) without inspecting
            # timer_table; the timer-id / value handler still runs.
            self.state.toolkit.last_timer_management_result = int(
                response_fields.get("result_code", 0x00) or 0x00
            ) & 0xFF
            self._apply_timer_management_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == POLLING_OFF_COMMAND:
            # Round 18: record the result-code on every TR (success
            # or failure) so a polling applet can tell whether the
            # terminal actually disabled polling. The
            # ``polling_off_active`` flag is preserved as the
            # binary "did it stick?" signal.
            self.state.toolkit.last_polling_off_result = int(
                response_fields.get("result_code", 0x00) or 0x00
            ) & 0xFF
            if succeeded:
                self.state.toolkit.polling_off_active = True
            return
        if command_type == MORE_TIME_COMMAND:
            # ETSI TS 102 223 §6.4.2 MORE TIME. The terminal only
            # acknowledges with a result code; success means the
            # additional time slice was granted, so an STK applet
            # that polled for the latch can re-arm its work loop.
            self.state.toolkit.last_more_time_result = int(
                response_fields.get("result_code", 0x00) or 0x00
            ) & 0xFF
            return
        if command_type == POLL_INTERVAL_COMMAND:
            # ETSI TS 102 223 §6.4.3 POLL INTERVAL. The TR carries
            # the negotiated duration under TLV ``04`` (seconds-only
            # form ``unit + length`` per §8.8). The simulator caches
            # both the raw blob and a best-effort decoded second
            # count so a polling applet can confirm the cadence the
            # terminal actually accepted.
            self._apply_poll_interval_response(response_fields, succeeded)
            return
        if command_type == SERVICE_SEARCH_COMMAND:
            self._apply_service_search_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == GET_SERVICE_INFORMATION_COMMAND:
            self._apply_get_service_information_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == PERFORM_CARD_APDU_COMMAND:
            self._apply_perform_card_apdu_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == POWER_OFF_CARD_COMMAND:
            self._apply_power_card_response(
                command_fields,
                response_fields,
                succeeded,
                power_on=False,
            )
            return
        if command_type == POWER_ON_CARD_COMMAND:
            self._apply_power_card_response(
                command_fields,
                response_fields,
                succeeded,
                power_on=True,
            )
            return
        if command_type == GET_READER_STATUS_COMMAND:
            self._apply_get_reader_status_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == RUN_AT_COMMAND:
            self._apply_run_at_command_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == SEND_SS_COMMAND:
            self._apply_send_ss_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == SEND_USSD_COMMAND:
            self._apply_send_ussd_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == SEND_SHORT_MESSAGE_COMMAND:
            self._apply_simple_proactive_result(
                "last_send_short_message_result",
                response_fields,
                succeeded,
            )
            return
        if command_type == SEND_DTMF_COMMAND:
            self._apply_simple_proactive_result(
                "last_send_dtmf_result",
                response_fields,
                succeeded,
            )
            return
        if command_type == PLAY_TONE_COMMAND:
            self._apply_simple_proactive_result(
                "last_play_tone_result",
                response_fields,
                succeeded,
            )
            return
        if command_type == LANGUAGE_NOTIFICATION_COMMAND:
            self._apply_simple_proactive_result(
                "last_language_notification_result",
                response_fields,
                succeeded,
            )
            return
        if command_type == LAUNCH_BROWSER_COMMAND:
            # ETSI TS 102 223 §6.6.21 LAUNCH BROWSER terminal
            # response only carries Command Details / Device
            # Identities / Result. The follow-on browser-termination
            # cause arrives as a separate envelope (event 0x07) and
            # already latches into ``last_browser_termination_cause``.
            self._apply_simple_proactive_result(
                "last_launch_browser_result",
                response_fields,
                succeeded,
            )
            return
        if command_type == REFRESH_COMMAND:
            # ETSI TS 102 223 §6.6.5 REFRESH. The TR carries only
            # the result code; the simulator caches it together with
            # the refresh-mode the terminal acknowledged so an STK
            # applet can reason about a "refresh denied" / "refresh
            # in progress" outcome without scraping the queue.
            self._apply_refresh_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == SET_UP_CALL_COMMAND:
            # ETSI TS 102 223 §6.6.13 SET UP CALL. The TR carries
            # the result byte; on rejection the network cause may
            # arrive in TLV ``1A`` / ``9A`` Additional Information.
            self._apply_set_up_call_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == DISPLAY_TEXT_COMMAND:
            # ETSI TS 102 223 §6.6.1 DISPLAY TEXT. TR carries only
            # a result byte (e.g. 0x00 = command performed, 0x11 =
            # backward move pressed by user, 0x12 = no response,
            # 0x13 = help requested).
            self._apply_simple_proactive_result(
                "last_display_text_result",
                response_fields,
                succeeded,
            )
            return
        if command_type == GET_INKEY_COMMAND:
            # ETSI TS 102 223 §6.6.2 GET INKEY. TR carries the
            # user-typed character (TLV ``0D`` / ``8D``) along with
            # the result code.
            self._apply_get_inkey_response(response_fields, succeeded)
            return
        if command_type == GET_INPUT_COMMAND:
            # ETSI TS 102 223 §6.6.3 GET INPUT. TR carries the
            # entered string in TLV ``0D`` / ``8D``.
            self._apply_get_input_response(response_fields, succeeded)
            return
        if command_type == SELECT_ITEM_COMMAND:
            # ETSI TS 102 223 §6.6.4 SELECT ITEM. TR carries the
            # chosen item identifier in TLV ``10`` / ``90``.
            self._apply_select_item_response(response_fields, succeeded)
            return
        if command_type == SET_UP_MENU_COMMAND:
            # ETSI TS 102 223 §6.6.5 SET UP MENU. TR carries only
            # a result code; the menu items themselves are echoed
            # back via the MENU SELECTION envelope (D3) which is
            # already wired through round-11 latches.
            self._apply_simple_proactive_result(
                "last_set_up_menu_result",
                response_fields,
                succeeded,
            )
            return
        if command_type == SET_UP_IDLE_MODE_TEXT_COMMAND:
            # ETSI TS 102 223 §6.6.20 SET UP IDLE MODE TEXT. TR
            # carries only a result code.
            self._apply_simple_proactive_result(
                "last_set_up_idle_mode_text_result",
                response_fields,
                succeeded,
            )
            return
        if command_type == SET_UP_EVENT_LIST_COMMAND:
            # ETSI TS 102 223 §6.6.16 SET UP EVENT LIST. TR carries
            # only a result code (§8.12). The applet that issued
            # the command typically polls this latch to confirm the
            # terminal honoured the new event subscription before
            # arming follow-on event-download handlers.
            self._apply_simple_proactive_result(
                "last_set_up_event_list_result",
                response_fields,
                succeeded,
            )
            return
        if command_type == SET_FRAMES_COMMAND:
            self._apply_set_frames_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if command_type == GET_FRAMES_STATUS_COMMAND:
            self._apply_get_frames_status_response(
                command_fields,
                response_fields,
                succeeded,
            )
            return

    def _apply_provide_local_information_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """Latch PROVIDE LOCAL INFORMATION TR data into toolkit state.

        Per TS 102 223 §6.4.15 / §6.6.15 the terminal response carries
        the requested datum keyed off the proactive qualifier:

        - 0x00 location info (TLV 0x13)
        - 0x01 IMEI (TLV 0x14)
        - 0x03 date / time / timezone (TLV 0x26)
        - 0x04 language (TLV 0x2D)
        - 0x06 access technology (qualifier byte echoed; no TLV)
        - 0x08 IMEISV (TLV 0x62)
        - 0x0D battery state (TLV 0x5C)

        On a non-zero result code we skip the latch so partial /
        terminal-busy responses don't clobber a previously known good
        value -- the caller's hook still fires.
        """
        if succeeded is False:
            self._dispatch_hook(
                "on_provide_local_information_response",
                command_fields,
                response_fields,
                succeeded,
            )
            return
        toolkit = self.state.toolkit
        qualifier = int(command_fields.get("qualifier", 0) or 0)
        location_info = bytes(response_fields.get("location_information", b"") or b"")
        if len(location_info) > 0:
            toolkit.location_information = location_info
        imei_value = bytes(response_fields.get("imei", b"") or b"")
        if len(imei_value) > 0:
            toolkit.imei = imei_value
        date_time = bytes(response_fields.get("date_time_timezone", b"") or b"")
        if len(date_time) > 0:
            toolkit.date_time_timezone = date_time
        language_value = str(response_fields.get("language", "") or "")
        if len(language_value) > 0:
            toolkit.language = language_value.encode("ascii", "ignore")
        imeisv_value = bytes(response_fields.get("imeisv", b"") or b"")
        if len(imeisv_value) > 0:
            toolkit.imeisv = imeisv_value
        battery_state_value = response_fields.get("battery_state", None)
        if battery_state_value is not None:
            toolkit.battery_state = int(battery_state_value) & 0xFF
        if qualifier == 0x06:
            # §6.6.15 access-technology variant: terminals reply with
            # an additional Result TLV that we don't parse but the
            # qualifier itself disambiguates the request, so cache the
            # qualifier as the technology hint when the TR carries no
            # explicit access-tech TLV.
            toolkit.access_technology = qualifier
        self._dispatch_hook(
            "on_provide_local_information_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_timer_management_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """Latch TIMER MANAGEMENT TR data into ``state.toolkit``.

        The terminal echoes the timer-id (TLV ``A4``) and, on
        get-current-value, the remaining timer value (TLV ``A5`` BCD
        HH/MM/SS). Sub-functions (qualifier):

        - ``0x00`` start  -- terminal accepted the start; timer-table
          entry retains the requested setpoint.
        - ``0x01`` deactivate -- timer-table entry is removed.
        - ``0x02`` get current value -- timer-table entry is updated
          with the remaining seconds.
        """
        if succeeded is False:
            self._dispatch_hook(
                "on_timer_management_response",
                command_fields,
                response_fields,
                succeeded,
            )
            return
        toolkit = self.state.toolkit
        qualifier = int(command_fields.get("qualifier", 0) or 0)
        timer_id = int(
            response_fields.get("timer_id", command_fields.get("timer_id", 0)) or 0
        )
        if timer_id == 0:
            self._dispatch_hook(
                "on_timer_management_response",
                command_fields,
                response_fields,
                succeeded,
            )
            return
        if qualifier == 0x01:
            toolkit.timer_table.pop(timer_id, None)
        elif qualifier == 0x02:
            remaining = response_fields.get("timer_value_seconds", None)
            if remaining is not None:
                toolkit.timer_table[timer_id] = max(0, int(remaining))
        else:
            value = response_fields.get(
                "timer_value_seconds",
                command_fields.get("timer_value_seconds", None),
            )
            if value is not None:
                toolkit.timer_table[timer_id] = max(0, int(value))
        self._dispatch_hook(
            "on_timer_management_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_service_search_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        toolkit = self.state.toolkit
        if succeeded:
            blob = bytes(response_fields.get("service_record", b"") or b"")
            toolkit.last_service_search_result = blob
        else:
            toolkit.last_service_search_result = b""
        self._dispatch_hook(
            "on_service_search_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_get_service_information_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        toolkit = self.state.toolkit
        if succeeded:
            blob = bytes(response_fields.get("service_information", b"") or b"")
            toolkit.last_service_information = blob
        self._dispatch_hook(
            "on_get_service_information_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_perform_card_apdu_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        toolkit = self.state.toolkit
        if succeeded:
            blob = bytes(response_fields.get("card_apdu_response", b"") or b"")
            toolkit.last_card_apdu_response = blob
            # Extract the targeted reader from the originating command
            # device-identities pair (TLV 82 carries [source, dest]).
            device_pair = bytes(command_fields.get("device_identities_tlv", b"") or b"")
            if len(device_pair) >= 4:
                toolkit.last_card_apdu_reader = int(device_pair[3])
        self._dispatch_hook(
            "on_perform_card_apdu_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_power_card_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
        *,
        power_on: bool,
    ) -> None:
        toolkit = self.state.toolkit
        if succeeded is False:
            self._dispatch_hook(
                "on_power_card_response",
                command_fields,
                response_fields,
                succeeded,
            )
            return
        device_pair = bytes(command_fields.get("device_identities_tlv", b"") or b"")
        reader_id = 0
        if len(device_pair) >= 4:
            reader_id = int(device_pair[3])
        if reader_id == 0:
            return
        if power_on:
            toolkit.powered_card_readers.add(reader_id)
        else:
            toolkit.powered_card_readers.discard(reader_id)
        self._dispatch_hook(
            "on_power_card_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_get_reader_status_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        toolkit = self.state.toolkit
        if succeeded:
            blob = bytes(response_fields.get("reader_status_records", b"") or b"")
            toolkit.last_reader_status = blob
        self._dispatch_hook(
            "on_get_reader_status_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_send_ss_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.11 SEND SS terminal-response latch.

        The terminal forwards the network's SS-Reply (mapped from
        a Map_RegisterReturn / Map_EraseSSReturn etc) inside TLV
        ``89`` (raw SS-string, BCD-encoded). Cause information
        from the modem is carried in TLV ``1A`` Additional
        Information. Both are stashed unconditionally; the result
        code is captured separately so callers can still tell
        success from failure.
        """
        toolkit = self.state.toolkit
        toolkit.last_send_ss_result = int(
            response_fields.get("result_code", 0x00) or 0x00
        ) & 0xFF
        if succeeded:
            response_blob = bytes(response_fields.get("ss_response_raw", b"") or b"")
            if len(response_blob) > 0:
                toolkit.last_send_ss_response = response_blob
        toolkit.last_send_ss_additional = bytes(
            response_fields.get("additional_information", b"") or b""
        )
        self._dispatch_hook(
            "on_send_ss_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_send_ussd_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.12 SEND USSD terminal-response latch.

        Captures the USSD reply text (TLV ``8A`` byte 0 = DCS,
        bytes 1.. = text) plus the result code. On a failed TR
        the previously latched response is cleared so a stale
        success does not bleed into the next exchange.
        """
        toolkit = self.state.toolkit
        toolkit.last_send_ussd_result = int(
            response_fields.get("result_code", 0x00) or 0x00
        ) & 0xFF
        if succeeded:
            text_value = response_fields.get("ussd_response_text", "")
            toolkit.last_send_ussd_response_text = str(text_value or "")
            toolkit.last_send_ussd_response_dcs = int(
                response_fields.get("ussd_response_dcs", 0) or 0
            ) & 0xFF
        else:
            toolkit.last_send_ussd_response_text = ""
            toolkit.last_send_ussd_response_dcs = 0
        self._dispatch_hook(
            "on_send_ussd_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_simple_proactive_result(
        self,
        attribute_name: str,
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """Generic latch for proactives whose only TR-side payload
        is the result byte.

        Used by SEND SHORT MESSAGE / SEND DTMF / PLAY TONE /
        LANGUAGE NOTIFICATION. The simulator records the result
        code regardless of success so a subsequent test can
        distinguish a 0x00 (command performed successfully) from
        a 0x20+ (terminal-side failure).
        """
        del succeeded  # success is implicit in the result byte
        result = int(response_fields.get("result_code", 0x00) or 0x00) & 0xFF
        setattr(self.state.toolkit, attribute_name, result)

    def _apply_refresh_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.5 REFRESH TR latch.

        Modes are encoded in the proactive qualifier byte:

        - 0x00 NAA Initialisation and Full File Change Notification
        - 0x01 File Change Notification
        - 0x02 NAA Initialisation and File Change Notification
        - 0x03 NAA Initialisation
        - 0x04 UICC Reset
        - 0x05 NAA Application Reset
        - 0x06 NAA Session Reset
        - 0x07 Steering of Roaming
        - 0x08 Steering of Roaming for I-WLAN

        The simulator increments ``refresh_attempts`` on every TR
        regardless of outcome so a polling tool can confirm the TR
        actually fired even when the terminal returns a non-zero
        result (e.g. 0x32 "Command beyond ME's capabilities").
        """
        toolkit = self.state.toolkit
        toolkit.last_refresh_result = int(
            response_fields.get("result_code", 0x00) or 0x00
        ) & 0xFF
        toolkit.last_refresh_mode = int(
            command_fields.get("qualifier", 0) or 0
        ) & 0xFF
        toolkit.refresh_attempts = int(toolkit.refresh_attempts or 0) + 1
        del succeeded  # the result byte already conveys success/failure

    def _apply_get_inkey_response(
        self,
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.2 GET INKEY TR latch.

        On success the terminal returns a single user-input unit
        carried by TLV ``0D`` / ``8D``: byte 0 is the DCS, byte 1
        (or two for UCS-2) is the actual character. On failure
        (e.g. user pressed BACK -> result 0x11, or no response
        within timeout -> 0x12) only the result byte is present.
        The latch records the result regardless and stores the
        character only when present, so a previous good value is
        not clobbered by a no-response retry.
        """
        toolkit = self.state.toolkit
        toolkit.last_get_inkey_result = int(
            response_fields.get("result_code", 0x00) or 0x00
        ) & 0xFF
        text = str(response_fields.get("text_string", "") or "")
        if len(text) > 0:
            toolkit.last_get_inkey_text = text
            toolkit.last_get_inkey_dcs = int(
                response_fields.get("text_string_dcs", 0) or 0
            ) & 0xFF
        del succeeded

    def _apply_get_input_response(
        self,
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.3 GET INPUT TR latch.

        Same TLV shape as GET INKEY (``0D`` / ``8D``) but the
        payload may be multiple characters. Empty inputs (user
        pressed OK on a blank prompt) set the text to an empty
        string explicitly so the latch reflects the latest
        response rather than a stale prior value.
        """
        toolkit = self.state.toolkit
        toolkit.last_get_input_result = int(
            response_fields.get("result_code", 0x00) or 0x00
        ) & 0xFF
        # GET INPUT explicitly conveys an empty input as a TLV
        # with DCS only; treat presence of ``text_string_raw`` (not
        # the decoded text) as "the user replied" so the cache
        # tracks blank inputs faithfully.
        if "text_string_raw" in response_fields:
            toolkit.last_get_input_text = str(
                response_fields.get("text_string", "") or ""
            )
            toolkit.last_get_input_dcs = int(
                response_fields.get("text_string_dcs", 0) or 0
            ) & 0xFF
        del succeeded

    def _apply_select_item_response(
        self,
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.4 SELECT ITEM TR latch.

        On success the chosen item identifier is in TLV ``10`` /
        ``90`` (single byte). On failure (back / help / no
        response) the TLV is omitted; the latch records the
        result code in either case.
        """
        toolkit = self.state.toolkit
        toolkit.last_select_item_result = int(
            response_fields.get("result_code", 0x00) or 0x00
        ) & 0xFF
        if "item_identifier" in response_fields:
            toolkit.last_select_item_id = int(
                response_fields.get("item_identifier", 0) or 0
            ) & 0xFF
        del succeeded

    def _apply_set_up_call_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.13 SET UP CALL TR latch.

        Captures:

        - the result code (always),
        - the dialled-number echoed by the proactive command (TLV
          ``86`` -- only present when the terminal accepted the
          request, but the simulator latches it eagerly so a busy
          response doesn't hide which number was attempted), and
        - any Additional Information TLV (``1A`` / ``9A``)
          describing the network-side rejection cause.
        """
        toolkit = self.state.toolkit
        toolkit.last_set_up_call_result = int(
            response_fields.get("result_code", 0x00) or 0x00
        ) & 0xFF
        address_digits = str(command_fields.get("address_digits", "") or "")
        if len(address_digits) > 0:
            toolkit.last_set_up_call_address = address_digits
        additional = bytes(
            response_fields.get("additional_information", b"") or b""
        )
        toolkit.last_set_up_call_additional = additional
        del succeeded  # success implied by result_code

    def _apply_poll_interval_response(
        self,
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.3 POLL INTERVAL TR latch.

        The TR carries the negotiated duration the terminal will
        actually use. The simulator stores both the raw 2-byte
        TLV value (so the upper layer can re-emit it verbatim)
        and a normalized seconds count derived from the unit
        byte (0x00 minutes / 0x01 seconds / 0x02 tenths-of-second).
        """
        toolkit = self.state.toolkit
        toolkit.last_poll_interval_result = int(
            response_fields.get("result_code", 0x00) or 0x00
        ) & 0xFF
        if succeeded is False:
            toolkit.last_poll_interval_negotiated_seconds = 0
            toolkit.last_poll_interval_negotiated_raw = b""
            return
        raw_blob = bytes(response_fields.get("duration_raw", b"") or b"")
        toolkit.last_poll_interval_negotiated_raw = raw_blob
        unit = int(response_fields.get("duration_unit", 0) or 0) & 0xFF
        value = int(response_fields.get("duration_value", 0) or 0) & 0xFF
        if unit == 0x00:
            toolkit.last_poll_interval_negotiated_seconds = value * 60
        elif unit == 0x01:
            toolkit.last_poll_interval_negotiated_seconds = value
        elif unit == 0x02:
            toolkit.last_poll_interval_negotiated_seconds = max(0, value // 10)
        else:
            toolkit.last_poll_interval_negotiated_seconds = 0

    def _apply_set_frames_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.36 SET FRAMES TR latch.

        Successful TRs cache both the frame layout originally pushed
        by the card (so repeated SET FRAMES with the same geometry
        do not incur a second proactive round-trip) and the default
        frame identifier; failed TRs leave the cache untouched.
        """
        toolkit = self.state.toolkit
        if succeeded:
            layout = bytes(command_fields.get("frame_layout", b"") or b"")
            if len(layout) > 0:
                toolkit.last_set_frames_layout = layout
            default_id = command_fields.get("default_frame_identifier", None)
            if default_id is not None:
                toolkit.last_set_frames_default_id = int(default_id) & 0xFF
        self._dispatch_hook(
            "on_set_frames_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_get_frames_status_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.37 GET FRAMES STATUS TR latch.

        Successful TRs cache the Frames Information TLV (§8.81)
        verbatim into ``state.toolkit.last_frames_information``; a
        failed TR leaves the previous value untouched.
        """
        toolkit = self.state.toolkit
        if succeeded:
            blob = bytes(response_fields.get("frames_information", b"") or b"")
            if len(blob) > 0:
                toolkit.last_frames_information = blob
        self._dispatch_hook(
            "on_get_frames_status_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_run_at_command_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        """ETSI TS 102 223 §6.4.16 / §6.6.16 RUN AT COMMAND TR latch.

        The terminal reports the AT response under TLV ``A9`` (AT
        Response). Successful runs cache both the raw bytes and a
        utf-8 decode for log / test introspection. Failed runs leave
        the previous value untouched so a polling applet can keep
        the last-known good response.
        """
        toolkit = self.state.toolkit
        if succeeded:
            response_blob = bytes(
                response_fields.get("at_response", b"") or b""
            )
            toolkit.last_at_response = response_blob
            try:
                toolkit.last_at_response_text = response_blob.decode("utf-8", "ignore")
            except (UnicodeDecodeError, AttributeError):
                toolkit.last_at_response_text = ""
        self._dispatch_hook(
            "on_run_at_command_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _apply_open_channel_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        toolkit = self.state.toolkit
        if succeeded is False:
            toolkit.open_channel_active = False
            toolkit.open_channel_id = 0
            # SGP.32 §3.5 / TS 102 223 §6.4.27: when OPEN CHANNEL fails
            # the SEND DATA / RECEIVE DATA / CLOSE CHANNEL the IPA
            # already enqueued behind it have nothing to talk to. Drain
            # them so the modem does not have to FETCH four guaranteed
            # failures (3A03 "channel id not valid") before the timer
            # re-arm. The drain also resets the IPA-poll session flag
            # so the next D7 timer expiration starts a clean cycle.
            self._drain_ipa_poll_followups()
            toolkit.ipa_poll_session_active = False
            toolkit.ipa_poll_followup_emitted = False
            toolkit.ipa_poll_pending_result_payload = b""
            if str(toolkit.ipa_poll_phase or "") in {"dns_open", "eim_open"}:
                toolkit.ipa_poll_phase = "idle"
                toolkit.ipa_poll_phase_history = (
                    list(toolkit.ipa_poll_phase_history or []) + ["aborted"]
                )[-16:]
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
        # ETSI TS 102 223 §8.56 channel-status TLV: byte 0 bits 0..2 are
        # the channel identifier the terminal assigned to the freshly
        # opened bearer. Capture it so the SEND/RECEIVE/CLOSE follow-ups
        # can address that channel via device identities (0x20 + ch_id)
        # rather than the generic terminal identifier.
        channel_status_blob = bytes(response_fields.get("channel_status", b"") or b"")
        if len(channel_status_blob) >= 1:
            assigned_channel_id = int(channel_status_blob[0]) & 0x07
            if assigned_channel_id > 0:
                toolkit.open_channel_id = assigned_channel_id
                self._patch_pending_bip_followups(assigned_channel_id)
        if len(remote_address) > 0 and remote_port > 0:
            toolkit.open_channel_endpoint = f"{remote_address}:{remote_port}"
        elif len(remote_address) > 0:
            toolkit.open_channel_endpoint = remote_address
        else:
            toolkit.open_channel_endpoint = ""
        # Phase advance: OPEN CHANNEL TR success transitions either
        # dns_open -> dns_query, or eim_open -> (eim_tls_handshake when
        # TLS is enabled, else eim_request for the legacy plain-HTTP
        # path).
        current_phase = str(toolkit.ipa_poll_phase or "")
        if current_phase == "dns_open":
            toolkit.ipa_poll_phase = "dns_query"
        elif current_phase == "eim_open":
            if bool(toolkit.ipa_poll_tls_enabled):
                toolkit.ipa_poll_phase = "eim_tls_handshake"
                fqdn = self._resolve_ipa_poll_fqdn()
                self._create_ipa_poll_tls_client(fqdn)
                self._pump_ipa_poll_tls_engine()
            else:
                toolkit.ipa_poll_phase = "eim_request"
        if toolkit.ipa_poll_phase != current_phase:
            toolkit.ipa_poll_phase_history = (
                list(toolkit.ipa_poll_phase_history or []) + [str(toolkit.ipa_poll_phase)]
            )[-16:]
        self._dispatch_hook("on_open_channel_response", command_fields, succeeded)

    def _apply_close_channel_response(self, succeeded: bool) -> None:
        toolkit = self.state.toolkit
        toolkit.open_channel_active = False
        toolkit.open_channel_protocol = ""
        toolkit.open_channel_endpoint = ""
        toolkit.open_channel_network_access_name = ""
        toolkit.open_channel_transport_protocol_type = 0
        toolkit.open_channel_id = 0
        # SGP.32 §3.5: CLOSE CHANNEL closes the IPA cycle whether or not
        # the modem ack succeeded -- the bearer is torn down either way.
        # The phase machine then either chains DNS -> eIM (if a resolved
        # IP was extracted from the DNS responses) or returns to idle.
        previous_phase = str(toolkit.ipa_poll_phase or "")
        chain_to_eim = False
        resolved_ip = str(toolkit.ipa_poll_resolved_ip or "").strip()
        if previous_phase in {"dns_query", "dns_recv", "dns_close"} and len(resolved_ip) > 0:
            chain_to_eim = True
        toolkit.ipa_poll_pending_result_payload = b""
        toolkit.ipa_poll_followup_emitted = False
        toolkit.ipa_poll_tls_state = None
        toolkit.ipa_poll_tls_inbound_buffer = b""
        toolkit.ipa_poll_tls_idle_receives = 0
        if chain_to_eim:
            toolkit.ipa_poll_phase = "eim_open"
            toolkit.ipa_poll_phase_history = (
                list(toolkit.ipa_poll_phase_history or []) + ["chain_to_eim"]
            )[-16:]
            fqdn = self._resolve_ipa_poll_fqdn()
            if len(fqdn) > 0:
                self._queue_ipa_poll_eim_phase(fqdn, resolved_ip)
            else:
                toolkit.ipa_poll_session_active = False
                toolkit.ipa_poll_phase = "idle"
        else:
            toolkit.ipa_poll_session_active = False
            toolkit.ipa_poll_phase = "idle"
            toolkit.ipa_poll_cycle_count = int(toolkit.ipa_poll_cycle_count or 0) + 1
            toolkit.ipa_poll_phase_history = (
                list(toolkit.ipa_poll_phase_history or []) + ["idle"]
            )[-16:]
        self._dispatch_hook("on_close_channel_response", succeeded)

    def _drain_ipa_poll_followups(self, *, keep_close: bool = False) -> None:
        """Strip any queued SEND/RECEIVE/TIMER/CLOSE that belong to the failed cycle.

        Called from ``_apply_open_channel_response`` when the OPEN
        CHANNEL TR signals failure (and from the abort/error paths).
        The simulator enqueues the full
        OPEN/SEND/.../TIMER/RECV/.../TIMER/CLOSE batch up-front for the
        linear DNS and plain-HTTP eIM legs, so the orderly unwind
        happens by removing the still-pending entries.

        ``keep_close`` is set by the SEND/RECEIVE TR-failure path: a
        BIP error on a data command does not invalidate the bearer
        itself, so we want to drop any pending SEND/RECV/TIMER but
        leave the trailing CLOSE CHANNEL alone so the modem still
        gets a clean tear-down. The walk stops at the first non-IPA
        entry to avoid eating unrelated commands queued by an
        extension.
        """

        queue = self.state.pending_fetch_queue
        if len(queue) == 0:
            return
        # Worst-case follow-up count for the DNS leg is now 7 entries:
        # SEND + SEND + TIMER(start) + RECV + RECV + TIMER(stop) + CLOSE
        # after OPEN CHANNEL has already been popped.
        max_drain = 8
        drained = 0
        accepted = {
            SEND_DATA_COMMAND,
            RECEIVE_DATA_COMMAND,
            TIMER_MANAGEMENT_COMMAND,
        }
        if keep_close is False:
            accepted = accepted | {CLOSE_CHANNEL_COMMAND}
        while drained < max_drain and len(queue) > 0:
            head = bytes(queue[0] or b"")
            command_type = self._peek_proactive_command_type(head)
            if command_type not in accepted:
                break
            queue.pop(0)
            drained += 1
        # Drained TIMER MANAGEMENT entries no longer arm the watchdog,
        # so reset the bookkeeping flag when we drain the entire cycle.
        # When ``keep_close`` is True we leave the flag alone so the
        # caller can queue a fresh deactivate just before CLOSE CHANNEL.
        toolkit = self.state.toolkit
        if keep_close is False:
            toolkit.ipa_poll_wait_timer_armed = False

    def _record_ipa_poll_bip_failure(
        self,
        origin: str,
        response_fields: dict[str, object],
    ) -> None:
        """Bookkeep an SGP.32 IPA-poll BIP failure for diagnostics + back-off.

        Called from ``_apply_send_data_response`` /
        ``_apply_receive_data_response`` when the modem returns a
        non-success TR (general result 0x3A "Bearer Independent
        Protocol error" is the common case for misbehaving UDP/TCP
        stacks). The handler:

        1. Increments ``ipa_poll_consecutive_failures`` so an upper
           layer can suppress the next cycle if the bearer is hosed.
        2. Records a ``phase|origin|result|info`` summary into
           ``ipa_poll_last_cycle_error`` for status renderers.
        3. Drains any still-queued SEND/RECEIVE/TIMER follow-ups so
           the modem does not have to FETCH guaranteed-failure
           commands. The trailing CLOSE CHANNEL is preserved so the
           bearer is still torn down cleanly.
        4. Re-queues a fresh TIMER MANAGEMENT (deactivate) ahead of
           the CLOSE when the cycle had armed the watchdog -- the
           original deactivate may have been part of the drained
           batch.
        """

        toolkit = self.state.toolkit
        toolkit.ipa_poll_consecutive_failures = (
            int(toolkit.ipa_poll_consecutive_failures or 0) + 1
        )
        result_bytes = bytes(response_fields.get("result", b"") or b"")
        result_code = int(response_fields.get("result_code", 0) or 0) & 0xFF
        additional = 0
        if len(result_bytes) >= 2:
            additional = int(result_bytes[1]) & 0xFF
        toolkit.ipa_poll_last_cycle_error = (
            f"phase={toolkit.ipa_poll_phase or 'idle'}|origin={origin}"
            f"|result=0x{result_code:02X}|info=0x{additional:02X}"
        )
        timer_was_armed = bool(toolkit.ipa_poll_wait_timer_armed)
        self._drain_ipa_poll_followups(keep_close=True)
        # If the watchdog timer was armed and its deactivate just got
        # drained, re-queue a fresh deactivate before the trailing
        # CLOSE CHANNEL so the modem reports the elapsed wait and the
        # timer-table latch stays clean. ``_disarm_ipa_poll_wait_timer``
        # honours the flag and is a no-op when the timer was never
        # armed.
        if timer_was_armed:
            queue = self.state.pending_fetch_queue
            close_pending = (
                len(queue) > 0
                and self._peek_proactive_command_type(bytes(queue[0])) == CLOSE_CHANNEL_COMMAND
            )
            if close_pending:
                close_payload = queue.pop(0)
                self._disarm_ipa_poll_wait_timer()
                queue.append(close_payload)
            else:
                self._disarm_ipa_poll_wait_timer()

    def _patch_pending_bip_followups(self, channel_id: int) -> None:
        """Rewrite the destination device byte on queued BIP follow-ups.

        The IPA-poll cycle queues OPEN/SEND/.../TIMER/RECV/.../TIMER/
        CLOSE up-front so the FETCH order is locked before the OPEN
        CHANNEL TR returns; the destination device on those
        follow-ups was therefore encoded as 0x82 (Terminal) rather
        than the channel-id-derived device identifier (ETSI TS 102
        223 §8.7). Once the terminal reports the assigned channel id
        in the OPEN CHANNEL channel-status TLV, walk the queue once
        and patch the destination byte of every still-pending
        SEND DATA / RECEIVE DATA / CLOSE CHANNEL command.

        TIMER MANAGEMENT and other non-BIP proactives that the cycle
        interleaves between SEND and RECEIVE bursts are left
        untouched -- their destination is correctly 0x82 (Terminal)
        per TS 102 223 §6.6.21 -- but the walk does NOT stop at them
        so the BIP commands queued *after* a TIMER MANAGEMENT still
        get their destination byte rewritten. Truly unrelated
        traffic queued by an extension (anything that is not a BIP
        follow-up or a TIMER MANAGEMENT) terminates the walk.
        """

        ch_id = int(channel_id) & 0x07
        if ch_id == 0:
            return
        target_dest = 0x20 + ch_id
        bip_types = (SEND_DATA_COMMAND, RECEIVE_DATA_COMMAND, CLOSE_CHANNEL_COMMAND)
        traversable = bip_types + (TIMER_MANAGEMENT_COMMAND,)
        for index, raw in enumerate(list(self.state.pending_fetch_queue)):
            payload = bytes(raw or b"")
            # Minimum BIP follow-up wire size is 11 bytes
            # (D0 LL 81 03 NUM TYPE QUAL 82 02 SRC DST), matching a
            # bare CLOSE CHANNEL with no extra TLVs.
            if len(payload) < 11 or payload[0] != 0xD0:
                break
            command_type = self._peek_proactive_command_type(payload)
            if command_type not in traversable:
                break
            if command_type not in bip_types:
                # Skip over the TIMER MANAGEMENT entries that the
                # IPA-poll watchdog inserts between SEND and RECEIVE.
                # Their destination is the Terminal, not the bearer
                # channel, so leave them alone but keep walking.
                continue
            offset = 2
            if payload[1] & 0x80:
                offset = 2 + (payload[1] & 0x7F)
            # Layout after outer tag/length: 81 03 NUM TYPE QUAL 82 02 SRC DST
            dev_id_offset = offset + 5
            if dev_id_offset + 4 > len(payload):
                break
            if payload[dev_id_offset] != 0x82 or payload[dev_id_offset + 1] != 0x02:
                break
            dest_offset = dev_id_offset + 3
            if payload[dest_offset] == target_dest:
                continue
            patched = bytearray(payload)
            patched[dest_offset] = target_dest
            self.state.pending_fetch_queue[index] = bytes(patched)

    @staticmethod
    def _peek_proactive_command_type(payload: bytes) -> int:
        """Return the proactive command type byte from a queued FETCH body.

        The encoded structure starts with ``D0 LL 81 03 num type qual``;
        we hop past the outer tag/length and the command-details TLV
        header to read ``type`` directly. Returns ``0`` if the buffer
        is too short or malformed -- callers treat that as "unknown,
        do not touch".
        """

        body = bytes(payload or b"")
        if len(body) < 6:
            return 0
        if body[0] != 0xD0:
            return 0
        # Skip outer tag (1) + length (1, multi-byte BER allowed)
        offset = 2
        if body[1] & 0x80:
            length_octets = body[1] & 0x7F
            offset = 2 + length_octets
        if offset + 5 > len(body):
            return 0
        if body[offset] != 0x81 or body[offset + 1] != 0x03:
            return 0
        return int(body[offset + 3]) & 0xFF

    def _apply_send_data_response(
        self,
        command_fields: dict[str, object],
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        toolkit = self.state.toolkit
        channel_data = bytes(command_fields.get("channel_data", b"") or b"")
        response_length = int(response_fields.get("channel_length", 0) or 0)
        if succeeded is False and bool(toolkit.ipa_poll_session_active):
            self._record_ipa_poll_bip_failure("send_data", response_fields)
        if succeeded:
            if response_length > 0:
                toolkit.last_channel_data_sent = response_length
            else:
                toolkit.last_channel_data_sent = len(channel_data)
            current_phase = str(toolkit.ipa_poll_phase or "")
            if current_phase == "dns_query":
                # Two AAAA/A queries are queued back to back. Once both
                # SEND DATA TRs have come back we flip to dns_recv so
                # the next RECEIVE DATA payload is interpreted as a
                # DNS answer.
                if len(toolkit.ipa_poll_dns_pending_questions) > 0:
                    toolkit.ipa_poll_dns_pending_questions = list(
                        toolkit.ipa_poll_dns_pending_questions
                    )[1:]
                if len(toolkit.ipa_poll_dns_pending_questions) == 0:
                    toolkit.ipa_poll_phase = "dns_recv"
                    toolkit.ipa_poll_phase_history = (
                        list(toolkit.ipa_poll_phase_history or []) + ["dns_recv"]
                    )[-16:]
            elif current_phase in {"eim_tls_handshake", "eim_request"}:
                if self._ipa_poll_tls_active():
                    # TLS path: another SEND DATA chunk may already be
                    # queued for the same flight. Only pump when the
                    # queue has drained so we don't double up.
                    if self._next_pending_send_data() is None:
                        self._pump_ipa_poll_tls_engine()
                elif current_phase == "eim_request":
                    # Legacy plain-HTTP path advance.
                    toolkit.ipa_poll_phase = "eim_recv"
                    toolkit.ipa_poll_phase_history = (
                        list(toolkit.ipa_poll_phase_history or []) + ["eim_recv"]
                    )[-16:]
        else:
            toolkit.last_channel_data_sent = 0
        self._dispatch_hook(
            "on_send_data_response",
            command_fields,
            response_fields,
            succeeded,
        )

    def _next_pending_send_data(self) -> bytes | None:
        for entry in self.state.pending_fetch_queue:
            payload = bytes(entry or b"")
            if self._peek_proactive_command_type(payload) == SEND_DATA_COMMAND:
                return payload
        return None

    def _apply_receive_data_response(
        self,
        response_fields: dict[str, object],
        succeeded: bool,
    ) -> None:
        if succeeded is False:
            if bool(self.state.toolkit.ipa_poll_session_active):
                self._record_ipa_poll_bip_failure("receive_data", response_fields)
            self._dispatch_hook("on_receive_data_response", response_fields, succeeded)
            return
        toolkit = self.state.toolkit
        channel_data = bytes(response_fields.get("channel_data", b"") or b"")
        remaining_length = int(response_fields.get("channel_length", 0) or 0)
        toolkit.last_received_channel_data = channel_data
        if len(channel_data) > 0:
            toolkit.received_channel_history.append(channel_data)
        current_phase = str(toolkit.ipa_poll_phase or "")
        if current_phase in {"dns_query", "dns_recv"} and len(channel_data) > 0:
            self._absorb_dns_response_chunk(channel_data)
            self._dispatch_hook("on_receive_data_response", response_fields, succeeded)
            return
        # TLS path: the bytes in channel_data are TLS records, NOT
        # SGP.32 TLVs. Buffer them, decide whether to keep draining or
        # to feed the engine, and let ``_pump_ipa_poll_tls_engine`` /
        # ``_consume_ipa_poll_tls_response_chunk`` handle the next
        # action.
        if self._ipa_poll_tls_phase_active():
            if len(channel_data) > 0:
                toolkit.ipa_poll_tls_inbound_buffer = (
                    bytes(toolkit.ipa_poll_tls_inbound_buffer or b"") + channel_data
                )
                toolkit.ipa_poll_tls_idle_receives = 0
            if remaining_length > 0:
                # Modem still has bytes buffered for us; drain them
                # before invoking the TLS engine so the engine sees a
                # complete flight in one feed.
                receive_size = max(1, min(0xFF, int(toolkit.ipa_poll_receive_size or 0xFA)))
                self._enqueue_command(
                    self._build_receive_data_command(
                        self._allocate_command_number(),
                        receive_size,
                    )
                )
            else:
                if current_phase == "eim_recv":
                    self._consume_ipa_poll_tls_response_chunk()
                else:
                    self._pump_ipa_poll_tls_engine()
            self._dispatch_hook("on_receive_data_response", response_fields, succeeded)
            return
        # SGP.32 §6.5 IPA dispatch. When the simulator's IPA owns
        # this BIP channel (an IPA-poll cycle is in flight), the
        # bytes the modem just handed back are the eIM's ESipa
        # response. Parse them out to EuiccPackages and forward each
        # into ISD-R via STORE DATA. This mirrors what a production
        # in-card SGP.32 IPA does after a poll round-trip.
        if bool(toolkit.ipa_poll_session_active) and len(channel_data) > 0:
            toolkit.ipa_poll_last_response_payload = (
                bytes(toolkit.ipa_poll_last_response_payload or b"") + channel_data
            )
            self._dispatch_eim_response_packages(channel_data)
        self._dispatch_hook("on_receive_data_response", response_fields, succeeded)

    def _consume_ipa_poll_tls_response_chunk(self) -> None:
        """Process buffered TLS application data after a RECEIVE DATA TR.

        Called from ``_apply_receive_data_response`` once the modem
        signalled "buffer drained" (channel_data_length=0). The buffer
        is fed to the TLS engine, the plaintext fragments are appended
        to ``ipa_poll_tls_decrypted_payload``, and any newly recovered
        SGP.32 packages are dispatched to ISD-R as if the bearer had
        delivered them in plaintext (Stage-1 path).

        After dispatch we either:

        * keep listening (queue another RECEIVE DATA) when no
          plaintext is yet available -- the encrypted record may have
          been split across multiple modem chunks, or
        * close the bearer when we have a non-empty decrypted payload.

        ``ipa_poll_followup_emitted`` from the dispatcher takes
        precedence: when a BF50 ProvideEimPackageResult was injected
        the cycle keeps the channel open until the eIM acks the
        result, mirroring what real IPAs do.
        """

        from SIMCARD import ipa_tls

        toolkit = self.state.toolkit
        tls_state = toolkit.ipa_poll_tls_state
        if tls_state is None:
            return
        inbound = bytes(toolkit.ipa_poll_tls_inbound_buffer or b"")
        if len(inbound) > 0:
            ipa_tls.feed_inbound(tls_state, inbound)
            toolkit.ipa_poll_tls_inbound_buffer = b""
        plaintext = ipa_tls.decrypt_application_data(tls_state)
        if len(plaintext) > 0:
            toolkit.ipa_poll_tls_decrypted_payload = (
                bytes(toolkit.ipa_poll_tls_decrypted_payload or b"") + plaintext
            )
            toolkit.ipa_poll_last_response_payload = (
                bytes(toolkit.ipa_poll_last_response_payload or b"") + plaintext
            )
            self._dispatch_eim_response_packages(plaintext)
            # Close the channel once the response has been processed
            # and any follow-up SEND DATA the dispatcher injected has
            # been tail-queued. The ``_dispatch_eim_response_packages``
            # path queues its own SEND DATA + RECEIVE DATA pair when
            # ``ipa_poll_followup_emitted`` flips, so we only enqueue
            # CLOSE CHANNEL here when no follow-up is pending.
            if bool(toolkit.ipa_poll_followup_emitted) is False:
                toolkit.ipa_poll_phase = "eim_close"
                toolkit.ipa_poll_phase_history = (
                    list(toolkit.ipa_poll_phase_history or []) + ["eim_close"]
                )[-16:]
                # Tear the watchdog timer down before CLOSE CHANNEL so
                # the modem reports the elapsed wait back in the Timer
                # Value (25) TLV and the timer-table latch stays clean.
                self._disarm_ipa_poll_wait_timer()
                self._enqueue_command(
                    self._build_close_channel_command(self._allocate_command_number())
                )
            return
        # No plaintext yet -- the eIM's response may be split across
        # multiple modem chunks. Idle counter limits how many empty
        # RECEIVE DATAs we tolerate before tearing the cycle down.
        toolkit.ipa_poll_tls_idle_receives = int(toolkit.ipa_poll_tls_idle_receives or 0) + 1
        if int(toolkit.ipa_poll_tls_idle_receives) > int(
            toolkit.ipa_poll_tls_max_idle_receives or 16
        ):
            self._abort_ipa_poll_cycle("tls response idle cap exceeded")
            return
        receive_size = max(1, min(0xFF, int(toolkit.ipa_poll_receive_size or 0xFA)))
        self._enqueue_command(
            self._build_receive_data_command(
                self._allocate_command_number(),
                receive_size,
            )
        )

    def _absorb_dns_response_chunk(self, chunk: bytes) -> None:
        """Decode an inbound DNS answer slice and update resolution state.

        The modem may split a single DNS reply across two RECEIVE DATA
        TRs, so the simulator buffers fragments until ``decode_dns_answer``
        accepts the accumulated bytes. The buffer is purged once a
        successful reply is parsed; the first usable A-record wins and
        is cached in ``ipa_poll_resolved_ip`` for the eIM phase to pick
        up. AAAA answers are tracked for diagnostics but do not (yet)
        feed the eIM IPv6 path -- TS 102 223 §8.59 supports IPv6 via
        type 0x57 in tag 3E, and a follow-up change can flip the
        preference.
        """

        toolkit = self.state.toolkit
        toolkit.ipa_poll_dns_response_buffer = (
            bytes(toolkit.ipa_poll_dns_response_buffer or b"") + bytes(chunk or b"")
        )
        decoded = ipa_poll_dns.decode_dns_answer(toolkit.ipa_poll_dns_response_buffer)
        if len(decoded.error) > 0 and len(toolkit.ipa_poll_dns_response_buffer) < 1024:
            # Not yet a complete payload -- wait for the next chunk.
            return
        toolkit.ipa_poll_dns_response_buffer = b""
        if len(decoded.error) > 0:
            toolkit.ipa_poll_last_resolution_error = decoded.error
            return
        if int(decoded.rcode) != 0:
            toolkit.ipa_poll_last_resolution_error = (
                f"DNS RCODE {int(decoded.rcode)}"
            )
        if len(decoded.aaaa_records) > 0:
            toolkit.ipa_poll_dns_aaaa_pending = False
        if len(decoded.a_records) > 0:
            toolkit.ipa_poll_dns_a_pending = False
            chosen = str(decoded.a_records[0]).strip()
            if len(chosen) > 0 and len(str(toolkit.ipa_poll_resolved_ip or "").strip()) == 0:
                toolkit.ipa_poll_resolved_ip = chosen
                toolkit.ipa_poll_resolved_ip_family = 4
        if (
            toolkit.ipa_poll_dns_a_pending is False
            and toolkit.ipa_poll_dns_aaaa_pending is False
        ):
            toolkit.ipa_poll_phase = "dns_close"
            toolkit.ipa_poll_phase_history = (
                list(toolkit.ipa_poll_phase_history or []) + ["dns_close"]
            )[-16:]
        else:
            toolkit.ipa_poll_phase = "dns_recv"

    def _dispatch_eim_response_packages(self, payload: bytes) -> None:
        """Forward each top-level EuiccPackage in ``payload`` to ISD-R.

        SGP.32 §6.5 ESipa polling responses carry zero or more
        ``EuiccPackage`` TLVs concatenated at the application layer
        (after any HTTP framing the modem strips for us). The IPA's
        contract is to deliver each package to ISD-R as a STORE DATA
        body, which is exactly what ``SgpLogic.handle_store_data``
        accepts. Anything that is not a recognised SGP.32 outer tag
        is ignored -- this keeps the dispatcher robust to HTTP
        envelopes, status lines, or empty-keepalive responses that
        the bearer may smuggle through.
        """

        dispatcher = self._eim_package_dispatcher
        toolkit = self.state.toolkit
        if dispatcher is None:
            return
        try:
            packages = self._extract_eim_response_packages(payload)
        except Exception:
            return
        per_package_responses: list[bytes] = []
        per_package_failures: list[int] = []
        for package_tlv in packages:
            outer_tag = self._read_eim_response_outer_tag(package_tlv)
            try:
                response_data, sw1, sw2 = dispatcher(package_tlv)
            except Exception:
                # SGP.32 §6.5.2.1 EimPackageResultErrorCode 127
                # (undefinedError) is the catch-all the spec uses
                # when the IPA cannot finish dispatching a package.
                per_package_failures.append(127)
                if len(outer_tag) > 0:
                    toolkit.ipa_poll_failed_packages = list(
                        toolkit.ipa_poll_failed_packages
                    ) + [(outer_tag, 127)]
                continue
            if (sw1, sw2) == (0x90, 0x00):
                if len(outer_tag) > 0:
                    toolkit.ipa_poll_dispatched_packages = list(
                        toolkit.ipa_poll_dispatched_packages
                    ) + [outer_tag]
                per_package_responses.append(bytes(response_data or b""))
                # A package made it all the way through ISD-R, so the
                # bearer is healthy this cycle. Reset the consecutive
                # failure tally + last-error string so the upper layer
                # does not gate the next cycle on stale telemetry.
                toolkit.ipa_poll_consecutive_failures = 0
                toolkit.ipa_poll_last_cycle_error = ""
            else:
                # SW != 9000. Per SGP.32 §6.5.2.1 map the SW pair to
                # an EimPackageResultErrorCode: 6A80/6A82/6985 -> 1
                # (invalidPackageFormat), 6A88 -> 2 (unknownPackage),
                # everything else -> 127 (undefinedError).
                error_code = self._sw_to_eim_package_error_code(sw1, sw2)
                per_package_failures.append(error_code)
                if len(outer_tag) > 0:
                    toolkit.ipa_poll_failed_packages = list(
                        toolkit.ipa_poll_failed_packages
                    ) + [(outer_tag, error_code)]

        if len(per_package_responses) == 0 and len(per_package_failures) == 0:
            return
        toolkit.ipa_poll_dispatched_responses = list(
            toolkit.ipa_poll_dispatched_responses
        ) + per_package_responses
        # SGP.32 §6.5.2.1 ProvideEimPackageResult follow-up. Build a
        # BF50 body wrapping each per-package result and inject a
        # fresh SEND DATA in front of the still-pending CLOSE CHANNEL
        # so the eIM sees execution results within the same BIP
        # cycle. Real cards also send a final RECEIVE DATA to drain
        # any acknowledgement / next-package the eIM ships back; we
        # mirror that to keep the conversation symmetric.
        # ``ipa_poll_followup_emitted`` is the latch that prevents a
        # cascading injection if the eIM's ack itself contains BF50
        # bytes -- real eIMs reply to BF50 with an empty body or a
        # single ack TLV, which the IPA forwards once but does not
        # re-mirror.
        if bool(toolkit.ipa_poll_followup_emitted):
            return
        result_body = self._build_provide_eim_package_result_payload(
            per_package_responses,
            per_package_failures,
        )
        if len(result_body) == 0:
            return
        toolkit.ipa_poll_pending_result_payload = result_body
        toolkit.ipa_poll_last_result_payload = result_body
        toolkit.ipa_poll_followup_emitted = True
        self._inject_followup_send_receive(result_body)

    @staticmethod
    def _sw_to_eim_package_error_code(sw1: int, sw2: int) -> int:
        """Map a card SW pair to SGP.32 §6.5.2.1 EimPackageResultErrorCode.

        Codes: 1=invalidPackageFormat, 2=unknownPackage, 127=undefined.
        """

        sw_word = ((int(sw1) & 0xFF) << 8) | (int(sw2) & 0xFF)
        if sw_word in (0x6A80, 0x6A82, 0x6985):
            return 1
        if sw_word == 0x6A88:
            return 2
        return 127

    def _build_provide_eim_package_result_payload(
        self,
        per_package_responses: list[bytes],
        per_package_failures: list[int] | None = None,
    ) -> bytes:
        """SGP.32 §6.5.2.1 ProvideEimPackageResult (BF50) outgoing body.

        Wraps each ISD-R response in a BF50 envelope, prefixed by
        the EID under tag ``5A`` and an HTTP/1.1 POST framing line
        so the bearer can route it to ``/gsma/rsp2/asn1`` exactly
        like the initial GetEimPackageRequest. Bare BF51/BF54
        responses are passed through unchanged; anything else is
        wrapped in BF51 (LoadEuiccPackage result) per SGP.32 v1.2
        §6.5.2.1 default-CHOICE rules. When no per-package response
        was successful but at least one failure was recorded, the
        body switches to the ``80`` EimPackageResultErrorCode CHOICE
        carrying the worst-severity error code seen this cycle.

        Pending notifications stored on the eUICC are also drained
        and stitched into the body as a ``BF2B`` retrieve-all chunk
        so the eIM gets cross-cycle notification telemetry without
        having to issue a separate retrieve.
        """

        failures = list(per_package_failures or [])
        eid_hex = str(self.state.eid or "").strip()
        if len(eid_hex) != 32:
            return b""
        try:
            eid_bytes = bytes.fromhex(eid_hex)
        except ValueError:
            return b""

        body_parts: list[bytes] = [tlv("5A", eid_bytes)]
        success_count = 0
        for raw in per_package_responses:
            payload = bytes(raw or b"")
            if len(payload) == 0:
                continue
            if (
                payload.startswith(bytes.fromhex("BF51"))
                or payload.startswith(bytes.fromhex("BF52"))
                or payload.startswith(bytes.fromhex("BF54"))
            ):
                body_parts.append(payload)
            else:
                body_parts.append(tlv("BF51", payload))
            success_count += 1

        notification_tlv = self._collect_pending_notifications_tlv()
        if len(notification_tlv) > 0:
            body_parts.append(notification_tlv)

        if success_count == 0 and len(failures) > 0:
            # SGP.32 §6.5.2.1 EimPackageResult CHOICE: switch to the
            # ``80`` errorCode branch. Pick the most severe code
            # (numerically largest) so the eIM sees the strongest
            # signal -- 127 (undefined) trumps 1/2.
            error_code = max(failures) & 0xFF
            inner_seq = bytes([0x30, 0x03, 0x02, 0x01, error_code])
            body_parts = [
                tlv("5A", eid_bytes),
                bytes([0x80, len(inner_seq)]) + inner_seq,
            ]
        elif success_count == 0 and len(notification_tlv) == 0:
            return b""

        bf50 = tlv("BF50", b"".join(body_parts))
        toolkit = self.state.toolkit
        host = str(toolkit.ipa_poll_eim_fqdn or "").strip()
        if len(host) == 0:
            host = self._resolve_ipa_poll_fqdn()
        envelope = (
            f"POST /gsma/rsp2/asn1 HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Admin-Protocol: gsma/rsp/v2.2.0\r\n"
            f"Content-Type: application/x-gsma-rsp-asn1\r\n"
            f"User-Agent: yggdrasim-ipa/1.0\r\n"
            f"Content-Length: {len(bf50)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")
        return envelope + bf50

    def _collect_pending_notifications_tlv(self) -> bytes:
        """SGP.22 §5.7.10 / SGP.32 §6.5 PendingNotification piggyback.

        Drain ``state.notifications`` into a ``BF2B`` retrieve-all
        chunk so the eIM gets cross-cycle telemetry without having
        to issue a separate retrieve in the next round-trip. The
        notifications themselves are NOT removed from the eUICC --
        the eIM is expected to acknowledge them via a follow-up
        ``RemoveNotificationFromList`` (BF30) before they go away.
        That mirrors a real card: notifications stay pinned until
        explicitly cleared.
        """

        if len(self.state.notifications) == 0:
            return b""
        body = b"".join(
            bytes(notification.payload) for notification in self.state.notifications
        )
        if len(body) == 0:
            return b""
        return tlv("BF2B", tlv("A0", body))

    def _inject_followup_send_receive(self, payload: bytes) -> None:
        """Insert SEND DATA + RECEIVE DATA before any pending CLOSE CHANNEL.

        Walks ``state.pending_fetch_queue`` to find the first
        CLOSE CHANNEL command and inserts the new pair right before
        it. If no CLOSE CHANNEL is queued (shouldn't happen mid
        cycle, but be defensive) the pair is appended.
        """

        send_data_cmd = self._build_send_data_command_with_qualifier(
            self._allocate_command_number(),
            0x01,
            payload,
        )
        receive_size = max(
            1,
            min(0xFF, int(self.state.toolkit.ipa_poll_receive_size or 0xFA)),
        )
        receive_data_cmd = self._build_receive_data_command(
            self._allocate_command_number(),
            receive_size,
        )
        queue = self.state.pending_fetch_queue
        insert_at = len(queue)
        for index, command in enumerate(queue):
            kind = self._safe_proactive_kind(command)
            if kind == CLOSE_CHANNEL_COMMAND:
                insert_at = index
                break
        queue.insert(insert_at, receive_data_cmd)
        queue.insert(insert_at, send_data_cmd)

    @staticmethod
    def _safe_proactive_kind(payload: bytes) -> int:
        """Return the proactive command-type byte from a D0 frame, or -1."""
        if len(payload) < 4 or payload[0] != 0xD0:
            return -1
        body_offset = 2 if payload[1] < 0x80 else (2 + (payload[1] & 0x7F))
        if body_offset >= len(payload):
            return -1
        if payload[body_offset] != 0x81:
            return -1
        length = payload[body_offset + 1] if body_offset + 1 < len(payload) else 0
        cd_start = body_offset + 2
        if cd_start + 1 >= len(payload) or length < 3:
            return -1
        return payload[cd_start + 1]

    @staticmethod
    def _read_eim_response_outer_tag(package_tlv: bytes) -> bytes:
        if len(package_tlv) == 0:
            return b""
        first_octet = package_tlv[0]
        if first_octet & 0x1F == 0x1F:
            if len(package_tlv) < 2:
                return b""
            return bytes(package_tlv[:2])
        return bytes(package_tlv[:1])

    @staticmethod
    def _extract_eim_response_packages(payload: bytes) -> list[bytes]:
        """Return the SGP.32 EuiccPackage TLVs embedded in ``payload``.

        The simulator's modem layer strips TLS but leaves any HTTP
        framing intact for the IPA to ignore. ESipa bodies always
        start with a recognisable SGP.32 outer tag, so we scan the
        payload for the first valid TLV whose tag is one of the
        known constructed-class application tags and consume from
        there. If none is found, an empty list is returned.
        """

        raw = bytes(payload or b"")
        if len(raw) == 0:
            return []
        # Find the body start past any HTTP envelope.
        offset = 0
        crlf_double = raw.find(b"\r\n\r\n")
        if crlf_double != -1 and (raw.startswith(b"HTTP/") or raw.startswith(b"POST ")):
            offset = crlf_double + 4
        body = raw[offset:]
        # SGP.32 / SGP.22 outer tags the IPA cares about. The IPA
        # accepts every eIM-side EuiccPackage tag that
        # ``SgpLogic.handle_store_data`` knows how to dispatch -- the
        # IPA's contract is to be a transparent forwarder for this
        # range. Add any new tag here when the SGP layer grows a
        # new STORE DATA handler.
        allowed_outer_tags = {
            # Profile lifecycle (ES10b/ES10c)
            bytes.fromhex("BF21"),  # PrepareDownload
            bytes.fromhex("BF25"),  # StoreMetadata
            bytes.fromhex("BF29"),  # SetNickname
            bytes.fromhex("BF2A"),  # UpdateMetadata
            bytes.fromhex("BF2B"),  # ListNotifications / RetrieveAll
            bytes.fromhex("BF2D"),  # GetProfilesInfo
            bytes.fromhex("BF2E"),  # GetEuiccChallenge
            bytes.fromhex("BF30"),  # RemoveNotificationFromList
            bytes.fromhex("BF31"),  # EnableProfile
            bytes.fromhex("BF32"),  # DisableProfile
            bytes.fromhex("BF33"),  # DeleteProfile
            bytes.fromhex("BF34"),  # eUICCMemoryReset (ES10c)
            bytes.fromhex("BF35"),  # LoadCRL (SGP.22 §5.7.13)
            bytes.fromhex("BF36"),  # BoundProfilePackage
            bytes.fromhex("BF38"),  # AuthenticateServer
            bytes.fromhex("BF3C"),  # GetEuiccConfiguredData
            bytes.fromhex("BF3F"),  # SetDefaultDpAddress
            bytes.fromhex("BF41"),  # CancelSession
            bytes.fromhex("BF45"),  # EuiccPackage envelope (SGP.32)
            # ESipa command/response
            bytes.fromhex("BF50"),  # ProvideEimPackageResult
            bytes.fromhex("BF51"),  # EuiccPackageResult / LoadEuiccPackage
            bytes.fromhex("BF52"),  # NoMoreEuiccPackages
            bytes.fromhex("BF53"),  # EimAcknowledgements
            bytes.fromhex("BF54"),  # ProfileDownloadTrigger / Result
            bytes.fromhex("BF55"),  # GetEimConfigurationData
            bytes.fromhex("BF56"),  # GetCerts
            bytes.fromhex("BF57"),  # AddInitialEim
            bytes.fromhex("BF58"),  # AddEim / ProfileRollback
            bytes.fromhex("BF59"),  # DeleteEim / ConfigureImmediateEnable
            bytes.fromhex("BF5A"),  # ImmediateEnable
            bytes.fromhex("BF5B"),  # EnableEmergencyProfile
            bytes.fromhex("BF5C"),  # DisableEmergencyProfile
            bytes.fromhex("BF5D"),  # ExecuteFallbackMechanism
            bytes.fromhex("BF5E"),  # ReturnFromFallback
            bytes.fromhex("BF5F"),  # GetConnectivityParameters
            bytes.fromhex("BF64"),  # eUICCMemoryReset (SGP.32)
            bytes.fromhex("BF65"),  # SetDefaultDpAddress (ES10b)
        }

        # Scan forward to the first allowed outer tag, then
        # consume contiguous TLVs from there.
        scan = 0
        first_tlv_start = -1
        while scan + 1 < len(body):
            candidate = body[scan : scan + 2]
            if candidate in allowed_outer_tags:
                first_tlv_start = scan
                break
            scan += 1
        if first_tlv_start < 0:
            return []
        chain = body[first_tlv_start:]
        results: list[bytes] = []
        cursor = 0
        while cursor < len(chain):
            try:
                tag_bytes, _value, raw_tlv, next_offset = read_tlv(chain, cursor)
            except (ValueError, IndexError):
                break
            if tag_bytes not in allowed_outer_tags:
                break
            results.append(bytes(raw_tlv))
            cursor = next_offset
        return results

    def _apply_channel_status_response(self, response_fields: dict[str, object]) -> None:
        channel_status = bytes(response_fields.get("channel_status", b"") or b"")
        if len(channel_status) >= 1:
            self.state.toolkit.open_channel_active = (channel_status[0] & 0x80) != 0

    def _handle_event_download(self, event_fields: dict[str, object]) -> None:
        toolkit = self.state.toolkit
        location_information = bytes(event_fields.get("location_information", b"") or b"")
        if len(location_information) > 0:
            toolkit.location_information = location_information
        channel_status = bytes(event_fields.get("channel_status", b"") or b"")
        if len(channel_status) >= 1:
            toolkit.open_channel_active = (channel_status[0] & 0x80) != 0
        # TS 102 223 §7.4 event bookkeeping. The event_code is the
        # primary key for follow-up actions; we cache it plus event-
        # specific data so STK applets can react via polling and tests
        # can introspect the latched values.
        event_code = event_fields.get("event_code", None)
        if event_code is not None:
            code_int = int(event_code) & 0xFF
            toolkit.last_event_code = code_int
            toolkit.event_history.append(code_int)
            if code_int == 0x07:
                # §7.4.7 Idle Screen Available -- the modem signals
                # the home screen is idle, so SET UP IDLE MODE TEXT
                # can run.
                toolkit.idle_screen_available = True
            elif code_int == 0x09:
                # §7.4.9 Browser Termination -- cache the cause so an
                # STK applet can decide whether to re-launch. The
                # same opcode is reused by some vendors for §7.4.10
                # Data Available; that path is signalled by the
                # presence of TLV 0x37 (Channel Data Length) instead
                # of the browser-termination-cause TLV. Both TLVs
                # are accepted on the same envelope so neither side
                # of the dispatch fights the other.
                cause_value = event_fields.get("browser_termination_cause", None)
                if cause_value is not None:
                    toolkit.last_browser_termination_cause = int(cause_value) & 0xFF
                channel_length_value = event_fields.get("channel_length", None)
                if channel_length_value is not None:
                    toolkit.last_data_available_channel_length = int(channel_length_value) & 0xFF
                    toolkit.data_available_events += 1
                    channel_status_blob = bytes(
                        event_fields.get("channel_status", b"") or b""
                    )
                    if len(channel_status_blob) > 0:
                        toolkit.last_data_available_channel_status = channel_status_blob
            elif code_int == 0x0F:
                # 3GPP TS 31.111 §7.5.13 Network Rejection event
                # download. The cause-bytes blob is stashed for later
                # OTA-side correlation.
                cause_blob = bytes(
                    event_fields.get("network_rejection_cause", b"") or b""
                )
                if len(cause_blob) > 0:
                    toolkit.last_network_rejection_cause = cause_blob
            elif code_int == 0x0A:
                # ETSI TS 102 223 §7.4.10 SS event download. The
                # body carries the SS-string sent by the network in
                # TLV 0x89 (Called-party-BCD-Number, TS 31.111
                # §10.3.27); the simulator stores the raw value
                # bytes for an applet to inspect.
                ss_blob = bytes(event_fields.get("ss_event_data", b"") or b"")
                if len(ss_blob) > 0:
                    toolkit.last_ss_event_data = ss_blob
            elif code_int == 0x0B:
                # ETSI TS 102 223 §7.4.10 USSD event download. The
                # body carries the USSD-string under TLV 0x8A (raw
                # DCS + text); the simulator caches both fields.
                ussd_blob = bytes(event_fields.get("ussd_event_data", b"") or b"")
                ussd_dcs = int(event_fields.get("ussd_event_dcs", 0) or 0)
                if len(ussd_blob) > 0:
                    toolkit.last_ussd_event_data = ussd_blob
                    toolkit.last_ussd_event_dcs = ussd_dcs & 0xFF
            elif code_int == 0x0C:
                # ETSI TS 102 223 §7.4.12 Local Connection event
                # download. The status byte (TLV 0x40 channel-status
                # high nibble) tells whether the connection was
                # established (0x8X) or terminated (0x0X).
                status_value = int(
                    event_fields.get("local_connection_status", 0) or 0
                )
                toolkit.local_connection_active = (status_value & 0x80) != 0
            elif code_int == 0x13:
                # 3GPP TS 31.111 §7.5.x / TS 102 223 §7.4.13 HCI
                # Connectivity Event. Reuses TLV 0x40 to carry the
                # connection state (0x80 = gate connected, 0x00 =
                # gate disconnected).
                status_value = int(
                    event_fields.get("hci_connectivity_status", 0) or 0
                )
                toolkit.hci_connectivity_active = (status_value & 0x80) != 0
            elif code_int == 0x16:
                # ETSI TS 102 223 §7.4.20 Contactless State Request.
                # The contactless front-end signals activation /
                # deactivation via the same TLV 0x40 status byte
                # used for Local Connection / HCI Connectivity. The
                # high nibble distinguishes activated (0x80) from
                # deactivated (0x00).
                status_value = int(
                    event_fields.get("contactless_status", 0) or 0
                )
                toolkit.contactless_active = (status_value & 0x80) != 0
            elif code_int == 0x18:
                # 3GPP TS 31.111 §7.5.16 IMS Registration Event.
                # The status byte is carried in TLV 0xB9 (registered
                # = 0x01, deregistered = 0x00); the optional
                # payload (TLV 0xBA) carries the registered URI.
                status_value = int(
                    event_fields.get("ims_registration_status", 0) or 0
                )
                toolkit.ims_registered = (status_value & 0x01) != 0
                payload_blob = bytes(
                    event_fields.get("ims_registration_data", b"") or b""
                )
                if len(payload_blob) > 0:
                    toolkit.last_ims_event_data = payload_blob
            elif code_int == 0x19:
                # 3GPP TS 31.111 §7.5.17 IMS Incoming Data Event.
                # The data blob (TLV 0xBA) carries the SIP/IMS
                # payload that triggered the notification; the
                # simulator caches it for an applet to inspect.
                payload_blob = bytes(
                    event_fields.get("ims_incoming_data", b"") or b""
                )
                if len(payload_blob) > 0:
                    toolkit.last_ims_event_data = payload_blob
            elif code_int == 0x00:
                # ETSI TS 102 223 §7.4.0 MT Call Event Download.
                # The terminal forwards the calling-party number
                # (TLV 06/86), the optional sub-address (TLV 08/88)
                # and a transaction identifier (TLV 1C/9C). The
                # simulator latches each so an STK applet can react
                # without scraping the envelope history.
                toolkit.last_mt_call_transaction_id = int(
                    event_fields.get("transaction_identifier", 0) or 0
                ) & 0xFF
                address_digits = str(
                    event_fields.get("call_address_digits", "") or ""
                )
                if len(address_digits) > 0:
                    toolkit.last_mt_call_address = address_digits
                toolkit.last_mt_call_subaddress = bytes(
                    event_fields.get("call_subaddress", b"") or b""
                )
                toolkit.call_active = False
            elif code_int == 0x01:
                # §7.4.1 Call Connected Event. The terminal signals
                # that the previously notified call has reached the
                # connected phase; we flip ``call_active`` to True
                # so a polling applet sees the same state as a real
                # CC layer would expose.
                toolkit.last_call_connected_transaction_id = int(
                    event_fields.get("transaction_identifier", 0) or 0
                ) & 0xFF
                toolkit.call_active = True
            elif code_int == 0x02:
                # §7.4.2 Call Disconnected Event. The terminal may
                # carry a cause TLV (1B / 9B); when present it is
                # cached so an applet can decide whether the call
                # tear-down was network-initiated or user-initiated.
                toolkit.last_call_disconnected_transaction_id = int(
                    event_fields.get("transaction_identifier", 0) or 0
                ) & 0xFF
                cause_blob = bytes(
                    event_fields.get("call_disconnect_cause", b"") or b""
                )
                if len(cause_blob) > 0:
                    toolkit.last_call_disconnected_cause = cause_blob
                toolkit.call_active = False
            elif code_int == 0x04:
                # §7.4.4 User Activity Event. No payload of interest
                # in the simulator -- we just bump a monotonic
                # counter so periodic polling can derive a delta.
                toolkit.user_activity_count += 1
            elif code_int == 0x0D:
                # 3GPP TS 31.111 §7.5.4 Access Technology Change
                # Event. The 1-byte indicator (TLV 0x3F / 0xBF)
                # marks the new RAT; the simulator records both the
                # current value and a count of transitions.
                tech_value = int(
                    event_fields.get("access_technology", 0) or 0
                ) & 0xFF
                if tech_value != toolkit.last_access_technology:
                    toolkit.access_technology_changes += 1
                toolkit.last_access_technology = tech_value
            elif code_int == 0x0E:
                # ETSI TS 102 223 §7.4.14 Display Parameters Change
                # Event. The TLV payload (0x46 / 0xC6) carries the
                # new display parameters; the simulator stashes the
                # raw blob plus a counter to support polling.
                blob = bytes(
                    event_fields.get("display_parameters", b"") or b""
                )
                if len(blob) > 0:
                    toolkit.last_display_parameters = blob
                toolkit.display_parameters_changes += 1
            elif code_int == 0x03:
                # ETSI TS 102 223 §7.4.4 Location Status Event. The
                # 1-byte status (TLV 0x9B / 0x1B) flags whether the
                # MS has full, limited or no service. The simulator
                # latches the latest reading and bumps an events-
                # received counter on every envelope. Repeats of
                # the same value still count as a fresh event so
                # polling applets can detect "the network told us
                # again" even when the literal value is unchanged.
                status_value = event_fields.get("location_status", None)
                if status_value is not None:
                    toolkit.last_location_status = int(status_value) & 0xFF
                    toolkit.location_status_changes += 1
            elif code_int == 0x10:
                # ETSI TS 102 223 §7.4.16 Frames Information Change
                # Event. The terminal raises this when the user
                # reshapes the display frames; the new layout is
                # carried under TLV 0x49 (Frames Information). The
                # simulator stores the raw blob in the same field
                # populated by SET FRAMES TR responses and bumps a
                # counter so a polling applet can react without
                # re-parsing the envelope.
                blob = bytes(
                    event_fields.get("frames_information", b"") or b""
                )
                if len(blob) > 0:
                    toolkit.last_frames_information = blob
                toolkit.frames_information_changes += 1
            elif code_int == 0x06:
                # ETSI TS 102 223 §7.4.7 Card Reader Status Event
                # (multi-card terminals). The 1-byte status TLV
                # (0xA0 / 0x20) packs reader-present / powered flags
                # together with the affected reader id; the
                # simulator caches both and bumps a counter so a
                # poll-style applet can detect insert / eject events
                # without consulting event_history.
                status_value = event_fields.get("card_reader_status", None)
                if status_value is not None:
                    toolkit.last_card_reader_status = int(status_value) & 0xFF
                    toolkit.last_card_reader_id = int(
                        event_fields.get("card_reader_id", 0) or 0
                    ) & 0x0F
                    toolkit.card_reader_status_events += 1
        self._dispatch_hook("on_event_download", event_fields)

    def _apply_cell_broadcast_download(self, payload: bytes) -> None:
        """3GPP TS 23.041 §9.4.1 Cell Broadcast Download decoder.

        Walks the ``D2`` envelope, extracts the CB Page TLV (tag
        ``8C``) and parses its 88-byte payload into the spec
        fields:

        - bytes 0..1  Serial Number (TS 23.041 §9.4.1.2.1).
        - bytes 2..3  Message Identifier (§9.4.1.2.2).
        - byte 4      Data Coding Scheme (§9.4.1.2.3).
        - byte 5      Page Parameter (high nibble = total pages,
          low nibble = current page; §9.4.1.2.4).
        - bytes 6..87 Content (82 bytes; padded with carriage
          return ``0x0D`` per §9.4.2.2 when shorter).

        Pages with a length other than 88 bytes are accepted (a
        few embedded modems forward the trimmed payload after
        stripping trailing CR padding); the simulator records
        whatever the page actually contained.
        """
        try:
            outer_tag, outer_value, _raw, _next = read_tlv(
                bytes(payload or b""), 0
            )
        except ValueError:
            return
        if outer_tag != b"\xD2":
            return
        toolkit = self.state.toolkit
        toolkit.cb_pages_received += 1
        offset = 0
        page_blob = b""
        while offset < len(outer_value):
            try:
                tag_bytes, value_bytes, _raw_inner, offset = read_tlv(
                    outer_value,
                    offset,
                )
            except ValueError:
                break
            if tag_bytes in (b"\x0C", b"\x8C"):
                page_blob = value_bytes
                break
        if len(page_blob) == 0:
            return
        toolkit.last_cb_page_raw = page_blob
        if len(page_blob) >= 6:
            toolkit.last_cb_serial_number = int.from_bytes(
                page_blob[0:2],
                "big",
                signed=False,
            )
            toolkit.last_cb_message_id = int.from_bytes(
                page_blob[2:4],
                "big",
                signed=False,
            )
            toolkit.last_cb_dcs = int(page_blob[4]) & 0xFF
            toolkit.last_cb_page_parameter = int(page_blob[5]) & 0xFF
            toolkit.last_cb_content = bytes(page_blob[6:])
        self._dispatch_hook("on_cell_broadcast_download", page_blob)

    def _apply_menu_selection(self, payload: bytes) -> None:
        """ETSI TS 102 223 §7.5.6 Menu Selection envelope decoder.

        Walks the ``D3`` envelope and extracts the Item Identifier
        TLV (``10`` / ``90``) plus the optional help-request flag
        from the Device Identities qualifier byte (TLV ``02`` /
        ``82`` byte 1 bit 0 set => help request). Both fields are
        latched into ``state.toolkit`` and the selection is
        appended to ``menu_selections`` so an applet can replay
        the user-interaction history.
        """
        try:
            outer_tag, outer_value, _raw, _next = read_tlv(
                bytes(payload or b""), 0
            )
        except ValueError:
            return
        if outer_tag != b"\xD3":
            return
        item_id = 0
        help_request = False
        offset = 0
        while offset < len(outer_value):
            try:
                tag_bytes, value_bytes, _raw_inner, offset = read_tlv(
                    outer_value,
                    offset,
                )
            except ValueError:
                break
            if tag_bytes in (b"\x10", b"\x90") and len(value_bytes) >= 1:
                item_id = int(value_bytes[0]) & 0xFF
                continue
            if tag_bytes in (b"\x15", b"\x95"):
                # TS 102 223 §8.21 Help Request TLV (zero-length).
                # Some terminals encode the flag explicitly rather
                # than via the Device Identities qualifier.
                help_request = True
                continue
        toolkit = self.state.toolkit
        if item_id > 0:
            toolkit.last_menu_item_id = item_id
            toolkit.menu_selections.append(item_id)
        toolkit.last_menu_help_request = help_request
        self._dispatch_hook("on_menu_selection", item_id, help_request)

    def _apply_timer_expiration(self, payload: bytes) -> None:
        """3GPP TS 31.111 §7.5.6 TIMER EXPIRATION envelope decoder.

        Walks the BTLV body (already known to be tagged ``D7``) and
        extracts the timer-id / timer-value TLVs (``A4`` / ``A5``).
        The matching entry is removed from
        ``state.toolkit.timer_table`` and ``last_expired_timer_id``
        is updated so polling tools can react.
        """
        try:
            outer_tag, outer_value, _raw, _next = read_tlv(bytes(payload or b""), 0)
        except ValueError:
            return
        if outer_tag != b"\xD7":
            return
        timer_id = 0
        offset = 0
        while offset < len(outer_value):
            try:
                tag_bytes, value_bytes, _raw_inner, offset = read_tlv(outer_value, offset)
            except ValueError:
                break
            if tag_bytes in (b"\x24", b"\xA4") and len(value_bytes) >= 1:
                timer_id = int(value_bytes[0])
                continue
            # Timer Value TLV (A5) is optional in the envelope and
            # carries the final value at expiration -- always 00 00 00
            # in practice. We don't consume it because the simulator
            # interprets expiration as "remove the timer".
        toolkit = self.state.toolkit
        if timer_id > 0:
            toolkit.last_expired_timer_id = timer_id
            toolkit.timer_table.pop(timer_id, None)
            # SGP.32 §3.5 IPA polling cadence: each D7 expiry first
            # drives the BIP IPA-poll sequence (so the modem actually
            # contacts the eIM) and only then re-arms the timer for
            # the next cycle. The order here is load-bearing: queueing
            # the rearm before the poll sequence would let the next
            # FETCH consume the rearm before the modem ever sees the
            # OPEN CHANNEL request.
            strategy = str(toolkit.poll_strategy or "timer").strip().lower()
            timer_strategy_active = strategy in {"timer", "both"}

            if timer_strategy_active and bool(toolkit.ipa_poll_enabled):
                self._queue_ipa_poll_sequence()

            rearm_seconds = int(toolkit.timer_management_seconds or 0)
            if (
                bool(toolkit.timer_management_auto_rearm)
                and timer_strategy_active
                and rearm_seconds > 0
            ):
                rearm_id = int(toolkit.timer_management_id or timer_id) or timer_id
                self._enqueue_command(
                    self._build_timer_management_start(
                        self._allocate_command_number(),
                        rearm_id,
                        rearm_seconds,
                    )
                )
        self._dispatch_hook("on_timer_expiration", timer_id)

    def _queue_ipa_poll_sequence(self) -> None:
        """Enqueue the SGP.32 §3.5 IPA-poll BIP exchange.

        The terminal services the bearer (DNS / TLS / HTTP) so the
        simulator only needs to publish the four proactive commands:

        1. OPEN CHANNEL    (TS 102 223 §6.4.27)
        2. SEND DATA       (TS 102 223 §6.4.29)
        3. RECEIVE DATA    (TS 102 223 §6.4.30)
        4. CLOSE CHANNEL   (TS 102 223 §6.4.28)

        The eIM FQDN resolution order mirrors what
        ``SimEimEntry`` does on cold boot:

        1. ``state.toolkit.ipa_poll_eim_fqdn`` (operator override)
        2. The first ``state.eim_entries[*].eim_fqdn`` that is set
        3. The empty string -- in which case we skip the sequence
           rather than emit a malformed OPEN CHANNEL.
        """
        toolkit = self.state.toolkit
        fqdn = self._resolve_ipa_poll_fqdn()
        if len(fqdn) == 0:
            return
        # Reset per-cycle bookkeeping up-front so the queueing helpers
        # below can latch new state without confusing inspectors that
        # observed the previous cycle.
        toolkit.ipa_poll_session_active = True
        toolkit.ipa_poll_last_response_payload = b""
        toolkit.ipa_poll_dispatched_packages = []
        toolkit.ipa_poll_dispatched_responses = []
        toolkit.ipa_poll_failed_packages = []
        toolkit.ipa_poll_pending_result_payload = b""
        toolkit.ipa_poll_followup_emitted = False
        toolkit.ipa_poll_last_resolution_error = ""
        # If we already resolved the eIM IP in a previous cycle and the
        # cache is still valid, skip the DNS phase and dive straight
        # into the ESipa exchange.
        cached_ip = str(toolkit.ipa_poll_resolved_ip or "").strip()
        if len(cached_ip) > 0:
            self._queue_ipa_poll_eim_phase(fqdn, cached_ip)
            return
        self._queue_ipa_poll_dns_phase(fqdn)

    def _queue_ipa_poll_dns_phase(self, fqdn: str) -> None:
        """Queue the SGP.32 DNS-over-BIP leg for the eIM FQDN.

        Mirrors what reference IPA implementations emit when their
        resolved-IP cache is empty:

        1. OPEN CHANNEL UDP_REMOTE to ``ipa_poll_dns_server:53`` with
           the configured APN. Qualifier ``0x03`` (immediate +
           automatic reconnection) so the modem keeps the resolver
           socket warm across the question/answer round trip.
        2. SEND DATA × 2 carrying AAAA then A questions (RFC 1035
           dual-stack pattern). Both questions reuse the same channel
           id once OPEN CHANNEL TR succeeds.
        3. RECEIVE DATA × 2 (one per outstanding answer).
        4. CLOSE CHANNEL once the resolver has answered.
        """

        toolkit = self.state.toolkit
        dns_server = str(toolkit.ipa_poll_dns_server or "").strip() or "8.8.8.8"
        dns_port = max(1, min(0xFFFF, int(toolkit.ipa_poll_dns_port or 53)))
        buffer_size = max(0x40, min(0xFFFF, int(toolkit.ipa_poll_buffer_size or 0x0400)))
        receive_size = max(1, min(0xFF, int(toolkit.ipa_poll_receive_size or 0xFA)))
        apn = str(toolkit.ipa_poll_apn or "").strip()

        toolkit.ipa_poll_phase = "dns_open"
        toolkit.ipa_poll_phase_history = (
            list(toolkit.ipa_poll_phase_history or []) + ["dns_open"]
        )[-16:]
        toolkit.ipa_poll_dns_response_buffer = b""
        toolkit.ipa_poll_dns_a_pending = True
        toolkit.ipa_poll_dns_aaaa_pending = True
        toolkit.ipa_poll_dns_query_id = (int(toolkit.ipa_poll_dns_query_id or 0) + 1) & 0xFFFF

        aaaa_query = ipa_poll_dns.encode_dns_query(
            fqdn,
            ipa_poll_dns.QTYPE_AAAA,
            transaction_id=int(toolkit.ipa_poll_dns_query_id),
        )
        a_query = ipa_poll_dns.encode_dns_query(
            fqdn,
            ipa_poll_dns.QTYPE_A,
            transaction_id=(int(toolkit.ipa_poll_dns_query_id) + 1) & 0xFFFF,
        )
        toolkit.ipa_poll_dns_query_id = (int(toolkit.ipa_poll_dns_query_id) + 1) & 0xFFFF
        toolkit.ipa_poll_dns_pending_questions = [
            (str(fqdn), int(ipa_poll_dns.QTYPE_AAAA)),
            (str(fqdn), int(ipa_poll_dns.QTYPE_A)),
        ]

        open_dns = self._build_open_channel_command(
            self._allocate_command_number(),
            remote_address=dns_server,
            remote_port=dns_port,
            transport_protocol_type=0x01,
            network_access_name=apn,
            buffer_size=buffer_size,
            qualifier=0x03,
            alpha_identifier="",
        )
        send_aaaa = self._build_send_data_command_with_qualifier(
            self._allocate_command_number(),
            0x01,
            aaaa_query,
        )
        send_a = self._build_send_data_command_with_qualifier(
            self._allocate_command_number(),
            0x01,
            a_query,
        )
        receive_aaaa = self._build_receive_data_command(
            self._allocate_command_number(),
            receive_size,
        )
        receive_a = self._build_receive_data_command(
            self._allocate_command_number(),
            receive_size,
        )
        # Reference IPA cards arm timer 02 with a ~65 s watchdog after
        # the SEND DATA burst and deactivate it before CLOSE CHANNEL.
        # The proactive yield gives the modem a polling window to
        # actually receive the DNS answer from the network before the
        # eUICC issues RECEIVE DATA -- skipping it is what made our
        # modem reject RECEIVE DATA with general result 0x3A
        # ("Bearer Independent Protocol error") and additional info
        # 0x00 ("no specific cause").
        wait_timer_id = int(toolkit.ipa_poll_wait_timer_id or 2) & 0xFF
        wait_seconds = max(1, int(toolkit.ipa_poll_wait_timer_seconds or 65))
        timer_start = self._build_timer_management_start(
            self._allocate_command_number(),
            wait_timer_id,
            wait_seconds,
        )
        timer_stop = self._build_timer_management_deactivate(
            self._allocate_command_number(),
            wait_timer_id,
        )
        close_dns = self._build_close_channel_command(self._allocate_command_number())

        self._enqueue_command(open_dns)
        self._enqueue_command(send_aaaa)
        self._enqueue_command(send_a)
        self._enqueue_command(timer_start)
        self._enqueue_command(receive_aaaa)
        self._enqueue_command(receive_a)
        self._enqueue_command(timer_stop)
        self._enqueue_command(close_dns)

    def _queue_ipa_poll_eim_phase(self, fqdn: str, resolved_ip: str) -> None:
        """Queue the SGP.32 ESipa-over-BIP leg using the resolved eIM IP.

        Two paths share this entry point:

        * **TLS-in-card path** (default; ``ipa_poll_tls_enabled`` is
          ``True``). Only the OPEN CHANNEL is enqueued up-front. After
          the bearer comes up the toolkit's TR handlers drive a
          reactive SEND/RECEIVE DATA loop that runs the TLS-1.2
          handshake, ships the encrypted ESipa request, decrypts the
          response and finally queues CLOSE CHANNEL. This mirrors what
          a real eUICC does -- the modem stays a transparent byte pipe.
        * **Plain-HTTP fallback** (``ipa_poll_tls_enabled`` is
          ``False``). The legacy four-command queue (OPEN / SEND /
          RECEIVE / CLOSE) is built up-front. The IPA-dispatch tests
          opt into this so they can exercise the SGP.32 envelope wiring
          without a TLS server.
        """

        toolkit = self.state.toolkit
        port = max(1, min(0xFFFF, int(toolkit.ipa_poll_eim_port or 443)))
        transport_type = int(toolkit.ipa_poll_transport_type or 0x02) & 0xFF
        buffer_size = max(0x40, min(0xFFFF, int(toolkit.ipa_poll_buffer_size or 0x0400)))
        apn = str(toolkit.ipa_poll_apn or "").strip()
        request_payload = bytes(toolkit.ipa_poll_request_payload or b"") or self._default_ipa_poll_request(fqdn)

        toolkit.ipa_poll_phase = "eim_open"
        toolkit.ipa_poll_phase_history = (
            list(toolkit.ipa_poll_phase_history or []) + ["eim_open"]
        )[-16:]
        toolkit.ipa_poll_last_request_payload = bytes(request_payload)
        toolkit.ipa_poll_tls_inbound_buffer = b""
        toolkit.ipa_poll_tls_idle_receives = 0
        toolkit.ipa_poll_tls_last_error = ""
        toolkit.ipa_poll_tls_decrypted_payload = b""
        toolkit.ipa_poll_tls_state = None

        open_eim = self._build_open_channel_command(
            self._allocate_command_number(),
            remote_address=resolved_ip,
            remote_port=port,
            transport_protocol_type=transport_type,
            network_access_name=apn,
            buffer_size=buffer_size,
            qualifier=0x01,
            alpha_identifier="",
        )
        self._enqueue_command(open_eim)
        if bool(toolkit.ipa_poll_tls_enabled):
            return
        # Plain-HTTP fallback path: queue the rest of the cycle now.
        receive_size = max(1, min(0xFF, int(toolkit.ipa_poll_receive_size or 0xFA)))
        send_data = self._build_send_data_command_with_qualifier(
            self._allocate_command_number(),
            0x01,
            request_payload,
        )
        receive_data = self._build_receive_data_command(
            self._allocate_command_number(),
            receive_size,
        )
        wait_timer_id = int(toolkit.ipa_poll_wait_timer_id or 2) & 0xFF
        wait_seconds = max(1, int(toolkit.ipa_poll_wait_timer_seconds or 65))
        timer_start = self._build_timer_management_start(
            self._allocate_command_number(),
            wait_timer_id,
            wait_seconds,
        )
        timer_stop = self._build_timer_management_deactivate(
            self._allocate_command_number(),
            wait_timer_id,
        )
        close_eim = self._build_close_channel_command(self._allocate_command_number())
        self._enqueue_command(send_data)
        self._enqueue_command(timer_start)
        self._enqueue_command(receive_data)
        self._enqueue_command(timer_stop)
        self._enqueue_command(close_eim)

    # ------------------------------------------------------------------
    # In-card TLS-1.2 driving (Stage 2). The helpers below own the
    # reactive SEND/RECEIVE DATA loop that runs the TLS handshake and
    # the encrypted ESipa exchange entirely inside the card. They
    # depend on ``ipa_poll_tls_enabled`` being set; the legacy plain-
    # HTTP fallback path keeps the linear queue from Stage 1.
    # ------------------------------------------------------------------

    _IPA_POLL_TLS_SEND_CHUNK: int = 240

    def _ipa_poll_tls_active(self) -> bool:
        toolkit = self.state.toolkit
        if bool(toolkit.ipa_poll_tls_enabled) is False:
            return False
        return toolkit.ipa_poll_tls_state is not None

    def _ipa_poll_tls_phase_active(self) -> bool:
        toolkit = self.state.toolkit
        return str(toolkit.ipa_poll_phase or "") in {
            "eim_tls_handshake",
            "eim_request",
            "eim_recv",
        } and self._ipa_poll_tls_active()

    def _create_ipa_poll_tls_client(self, fqdn: str):
        """Instantiate the per-cycle ``CardTlsClient``.

        Trust anchor priority:

        1. ``state.eim_entries[*].trusted_tls_public_key_data`` (DER,
           seeded by ``_load_sim_eim_certificate_der`` from the eIM
           identity JSON).
        2. ``state.toolkit.ipa_poll_tls_ca_cert_path`` if the toolkit
           was given an explicit override path.
        3. None -- the engine falls back to ``CERT_NONE`` so the
           handshake still emits valid wire bytes for diagnostics.
        """

        from SIMCARD import ipa_tls

        toolkit = self.state.toolkit
        ca_paths: list[str] = []
        ca_der = b""
        for entry in getattr(self.state, "eim_entries", []) or []:
            blob = bytes(getattr(entry, "trusted_tls_public_key_data", b"") or b"")
            if len(blob) > 0:
                ca_der = blob
                break
        config = ipa_tls.CardTlsClientConfig(
            server_hostname=str(fqdn or ""),
            ca_certificate_paths=ca_paths,
            ca_certificate_der=ca_der,
            insecure_skip_verify=False,
        )
        toolkit.ipa_poll_tls_state = ipa_tls.create_card_tls_client(config)
        toolkit.ipa_poll_tls_inbound_buffer = b""
        toolkit.ipa_poll_tls_idle_receives = 0
        toolkit.ipa_poll_tls_decrypted_payload = b""
        toolkit.ipa_poll_tls_last_error = ""

    def _pump_ipa_poll_tls_engine(self) -> None:
        """Advance the TLS state machine and queue the next SEND/RECEIVE.

        Called from the OPEN CHANNEL / SEND DATA / RECEIVE DATA TR
        handlers whenever the eIM phase is in flight under the TLS
        path. The order of operations:

        1. If the inbound buffer has any bytes, hand them to the TLS
           engine and clear the buffer. Idle counter resets.
        2. If the handshake is still in progress, advance it. The
           engine pushes any new outbound bytes (handshake records,
           CCS, Finished, etc.) into ``outgoing``.
        3. If the handshake just completed and the encrypted ESipa
           request has not been emitted yet, encrypt the configured
           request payload now so it lands in ``outgoing`` alongside
           the final Finished record.
        4. Drain ``outgoing``. If non-empty, queue a SEND DATA chunk;
           otherwise queue a RECEIVE DATA so the modem can hand back
           more eIM bytes.
        5. If we drained the response, decrypted the plaintext, the
           caller (the RECEIVE DATA handler) will tell us to close
           the channel instead of re-pumping.

        Phases drive the action selector:

        * ``eim_tls_handshake`` -- handshake bytes still flowing.
        * ``eim_request``       -- encrypted request being shipped.
        * ``eim_recv``          -- encrypted response being drained.
        """

        from SIMCARD import ipa_tls

        toolkit = self.state.toolkit
        tls_state = toolkit.ipa_poll_tls_state
        if tls_state is None:
            return

        inbound = bytes(toolkit.ipa_poll_tls_inbound_buffer or b"")
        if len(inbound) > 0:
            ipa_tls.feed_inbound(tls_state, inbound)
            toolkit.ipa_poll_tls_inbound_buffer = b""
            toolkit.ipa_poll_tls_idle_receives = 0

        if bool(getattr(tls_state, "handshake_complete", False)) is False:
            ipa_tls.drive_handshake(tls_state)
            if len(str(getattr(tls_state, "handshake_error", "") or "")) > 0:
                toolkit.ipa_poll_tls_last_error = str(tls_state.handshake_error)
                self._abort_ipa_poll_cycle("tls handshake failure")
                return

        outgoing = ipa_tls.drain_outbound(tls_state)

        if (
            bool(getattr(tls_state, "handshake_complete", False))
            and str(toolkit.ipa_poll_phase or "") == "eim_tls_handshake"
        ):
            request_payload = bytes(toolkit.ipa_poll_last_request_payload or b"")
            if len(request_payload) == 0:
                request_payload = self._default_ipa_poll_request(
                    self._resolve_ipa_poll_fqdn()
                )
                toolkit.ipa_poll_last_request_payload = request_payload
            encrypted_request = ipa_tls.encrypt_application_data(
                tls_state,
                request_payload,
            )
            outgoing = outgoing + encrypted_request
            toolkit.ipa_poll_phase = "eim_request"
            toolkit.ipa_poll_phase_history = (
                list(toolkit.ipa_poll_phase_history or []) + ["eim_request"]
            )[-16:]

        if len(outgoing) > 0:
            # Transitioning back into a SEND DATA flight; tear down the
            # watchdog timer that was guarding the previous RECEIVE so
            # the timer-table latch sees a clean deactivate before the
            # next arm.
            self._disarm_ipa_poll_wait_timer()
            self._queue_ipa_poll_tls_send_chunks(outgoing)
            return

        if str(toolkit.ipa_poll_phase or "") == "eim_request":
            # Encrypted request shipped but no further bytes pending;
            # transition to receive phase to drain the eIM's response.
            toolkit.ipa_poll_phase = "eim_recv"
            toolkit.ipa_poll_phase_history = (
                list(toolkit.ipa_poll_phase_history or []) + ["eim_recv"]
            )[-16:]

        # No bytes to send. Either the handshake needs more inbound or
        # we are waiting for the eIM's encrypted response. Either way,
        # ask the modem for more bytes.
        toolkit.ipa_poll_tls_idle_receives = int(toolkit.ipa_poll_tls_idle_receives or 0) + 1
        if int(toolkit.ipa_poll_tls_idle_receives) > int(
            toolkit.ipa_poll_tls_max_idle_receives or 16
        ):
            self._abort_ipa_poll_cycle("tls idle receive cap exceeded")
            return
        # Arm the watchdog timer right before yielding for the modem's
        # network round-trip; reference cards rely on this proactive
        # yield to actually receive bytes before the next RECEIVE DATA.
        self._arm_ipa_poll_wait_timer()
        receive_size = max(1, min(0xFF, int(toolkit.ipa_poll_receive_size or 0xFA)))
        self._enqueue_command(
            self._build_receive_data_command(
                self._allocate_command_number(),
                receive_size,
            )
        )

    def _arm_ipa_poll_wait_timer(self) -> None:
        """Queue a TIMER MANAGEMENT (start) before the next RECEIVE DATA.

        Reference IPA cards arm timer 02 with a ~65 s watchdog every
        time they yield for a network response inside an IPA-poll
        cycle. The proactive yield gives the modem its FETCH/STATUS
        polling window so bytes from the network actually land in the
        bearer buffer before the eUICC issues RECEIVE DATA. Skipping
        the yield -- the bug we are fixing here -- makes the modem
        return general result 0x3A (Bearer Independent Protocol
        error) on every RECEIVE DATA. The flag stops us from arming
        the same timer twice during an interleaved SEND/RECV burst.
        """
        toolkit = self.state.toolkit
        if bool(toolkit.ipa_poll_wait_timer_armed):
            return
        timer_id = int(toolkit.ipa_poll_wait_timer_id or 2) & 0xFF
        seconds = max(1, int(toolkit.ipa_poll_wait_timer_seconds or 65))
        self._enqueue_command(
            self._build_timer_management_start(
                self._allocate_command_number(),
                timer_id,
                seconds,
            )
        )
        toolkit.ipa_poll_wait_timer_armed = True

    def _disarm_ipa_poll_wait_timer(self) -> None:
        """Queue a TIMER MANAGEMENT (deactivate) once a RECEIVE DATA flight ends.

        The terminal echoes the remaining timer value back in the
        Timer Value (25) TLV, which lets the IPA log how long the
        actual wait was. The deactivate must run before CLOSE CHANNEL
        (or before the next SEND DATA flight in the TLS reactive path)
        so the timer-table bookkeeping stays clean across cycles.
        """
        toolkit = self.state.toolkit
        if bool(toolkit.ipa_poll_wait_timer_armed) is False:
            return
        timer_id = int(toolkit.ipa_poll_wait_timer_id or 2) & 0xFF
        self._enqueue_command(
            self._build_timer_management_deactivate(
                self._allocate_command_number(),
                timer_id,
            )
        )
        toolkit.ipa_poll_wait_timer_armed = False

    def _queue_ipa_poll_tls_send_chunks(self, payload: bytes) -> None:
        """Split ``payload`` into SEND DATA chunks and enqueue them.

        Each SEND DATA carries up to ``_IPA_POLL_TLS_SEND_CHUNK`` bytes
        under TLV ``36`` so the channel data length stays inside the
        single-octet BER length form (and well below any reasonable
        modem buffer). The qualifier on every chunk except the final
        one carries bit 1 (more data follows); the last chunk uses
        qualifier ``0x01`` (last segment of a single message).
        """

        body = bytes(payload or b"")
        if len(body) == 0:
            return
        chunk_size = max(1, int(self._IPA_POLL_TLS_SEND_CHUNK))
        offset = 0
        while offset < len(body):
            slice_end = min(len(body), offset + chunk_size)
            chunk = body[offset:slice_end]
            qualifier = 0x01 if slice_end >= len(body) else 0x00
            self._enqueue_command(
                self._build_send_data_command_with_qualifier(
                    self._allocate_command_number(),
                    qualifier,
                    chunk,
                )
            )
            offset = slice_end

    def _abort_ipa_poll_cycle(self, reason: str) -> None:
        """Tear the IPA-poll cycle down after an unrecoverable TLS error.

        Drains any queued SEND/RECEIVE/CLOSE commands so the modem
        does not have to FETCH guaranteed-failure follow-ups, then
        queues a single CLOSE CHANNEL so the bearer is shut cleanly.
        ``ipa_poll_tls_last_error`` carries ``reason`` for operators /
        tests; the phase machine returns to ``idle`` once the modem
        acks the CLOSE CHANNEL.
        """

        toolkit = self.state.toolkit
        toolkit.ipa_poll_tls_last_error = (
            str(toolkit.ipa_poll_tls_last_error or "") or str(reason)
        )
        self._drain_ipa_poll_followups()
        toolkit.ipa_poll_phase = "eim_close"
        toolkit.ipa_poll_phase_history = (
            list(toolkit.ipa_poll_phase_history or []) + ["abort"]
        )[-16:]
        # Tear down any watchdog timer the cycle armed so the modem
        # does not keep an orphan timer running after CLOSE CHANNEL.
        self._disarm_ipa_poll_wait_timer()
        self._enqueue_command(
            self._build_close_channel_command(self._allocate_command_number())
        )

    def _resolve_ipa_poll_fqdn(self) -> str:
        toolkit = self.state.toolkit
        configured = str(toolkit.ipa_poll_eim_fqdn or "").strip()
        if len(configured) > 0:
            return configured
        for entry in getattr(self.state, "eim_entries", []) or []:
            entry_fqdn = str(getattr(entry, "eim_fqdn", "") or "").strip()
            if len(entry_fqdn) > 0:
                return entry_fqdn
        return ""

    def _default_ipa_poll_request(self, fqdn: str) -> bytes:
        # SGP.32 v1.2 §6.5.2.1 ESipa.GetEimPackageRequest. The IPA
        # polls the eIM with a ``BF4F`` body carrying the eUICC EID
        # under tag ``5A`` (16 BCD bytes). Optional fields:
        # ``80`` notifyStateChange flag (omitted by default),
        # ``81`` stateChangeCause INTEGER (omitted by default),
        # ``82`` rPlmn 3 byte BCD (omitted by default).
        #
        # The body travels over HTTPS as ``application/x-gsma-rsp-asn1``;
        # the modem terminates TLS so the simulator emits a plain
        # HTTP/1.1 envelope and lets the bearer layer add encryption.
        # Custom request payloads can still be injected via
        # ``state.toolkit.ipa_poll_request_payload`` -- this default
        # is what fires when no override is set.
        host = str(fqdn or "").strip()
        body = self._build_get_eim_package_request_tlv()
        request = (
            f"POST /gsma/rsp2/asn1 HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Admin-Protocol: gsma/rsp/v2.2.0\r\n"
            f"Content-Type: application/x-gsma-rsp-asn1\r\n"
            f"User-Agent: yggdrasim-ipa/1.0\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        return request.encode("utf-8") + body

    def _build_get_eim_package_request_tlv(
        self,
        *,
        notify_state_change: bool = False,
        state_change_cause: int | None = None,
        rplmn_bcd: bytes = b"",
    ) -> bytes:
        """SGP.32 §6.5.2.1 GetEimPackageRequest (BF4F) TLV.

        Carries the EID under tag ``5A`` plus the optional bearer
        hints the IPA may report. Returns an empty body if the EID
        is missing/malformed because shipping a BF4F without an EID
        would be rejected by every conformant eIM.
        """

        eid_hex = str(self.state.eid or "").strip()
        if len(eid_hex) != 32:
            return b""
        try:
            eid_bytes = bytes.fromhex(eid_hex)
        except ValueError:
            return b""
        inner = tlv("5A", eid_bytes)
        if notify_state_change:
            inner += tlv("80", b"")
        if state_change_cause is not None:
            cause_value = int(state_change_cause) & 0xFF
            if 0 <= cause_value <= 0x7F:
                inner += tlv("81", bytes((cause_value,)))
        if len(rplmn_bcd) > 0:
            inner += tlv("82", bytes(rplmn_bcd))
        return tlv("BF4F", inner)


    def _apply_call_control_envelope(self, payload: bytes) -> None:
        """3GPP TS 31.111 §7.3.1.1 Call Control by USIM decoder.

        Walks the ``D4`` envelope body and extracts:

        - Address TLV (``06`` / ``86``): TON/NPI byte plus the
          BCD-encoded dialled digits.
        - Sub-Address TLV (``08`` / ``88``): optional, kept raw.
        - Capability Configuration Parameters 1 TLV (``07`` /
          ``87``): optional, kept raw -- contents are operator
          specific.
        - Location Information TLV (``13`` / ``93``): MCC/MNC/LAC/CI
          captured at the moment the call was placed.

        The envelope reply ("Allowed, no modification") is emitted
        by the caller; this decoder only updates ``state.toolkit``
        and bumps ``cc_envelopes_received`` so polling tools can
        detect MO call attempts without scraping
        ``envelope_history``.
        """
        try:
            outer_tag, outer_value, _raw, _next = read_tlv(
                bytes(payload or b""), 0
            )
        except ValueError:
            return
        if outer_tag != b"\xD4":
            return
        toolkit = self.state.toolkit
        toolkit.cc_envelopes_received += 1
        offset = 0
        address_seen = False
        while offset < len(outer_value):
            try:
                tag_bytes, value_bytes, _raw_inner, offset = read_tlv(
                    outer_value,
                    offset,
                )
            except ValueError:
                break
            if (
                tag_bytes in (b"\x06", b"\x86")
                and len(value_bytes) >= 1
                and address_seen is False
            ):
                # First Address TLV is the dialled number.
                toolkit.last_cc_address_ton_npi = int(value_bytes[0]) & 0xFF
                toolkit.last_cc_address = self._decode_dialled_digits(
                    value_bytes[1:]
                )
                address_seen = True
                continue
            if tag_bytes in (b"\x07", b"\x87"):
                toolkit.last_cc_capability_params = bytes(value_bytes)
                continue
            if tag_bytes in (b"\x08", b"\x88"):
                toolkit.last_cc_subaddress = bytes(value_bytes)
                continue
            if tag_bytes in (b"\x13", b"\x93"):
                toolkit.last_cc_location_information = bytes(value_bytes)
                continue
        self._dispatch_hook("on_call_control_envelope", toolkit.last_cc_address)

    def _apply_mo_sms_control_envelope(self, payload: bytes) -> None:
        """3GPP TS 31.111 §7.3.2.1 MO Short Message Control decoder.

        Walks the ``D5`` envelope body and extracts the two
        Address TLVs (the first is the destination RP-DA, the
        second is the SC RP-OA per §7.3.2.2) plus the
        calling-area Location Information. Each is latched into
        ``state.toolkit``; the canned reply is emitted by the
        caller.
        """
        try:
            outer_tag, outer_value, _raw, _next = read_tlv(
                bytes(payload or b""), 0
            )
        except ValueError:
            return
        if outer_tag != b"\xD5":
            return
        toolkit = self.state.toolkit
        toolkit.mo_sms_envelopes_received += 1
        offset = 0
        address_index = 0
        while offset < len(outer_value):
            try:
                tag_bytes, value_bytes, _raw_inner, offset = read_tlv(
                    outer_value,
                    offset,
                )
            except ValueError:
                break
            if tag_bytes in (b"\x06", b"\x86") and len(value_bytes) >= 1:
                ton_npi = int(value_bytes[0]) & 0xFF
                digits = self._decode_dialled_digits(value_bytes[1:])
                if address_index == 0:
                    toolkit.last_mo_sms_destination_address = digits
                    toolkit.last_mo_sms_destination_ton_npi = ton_npi
                elif address_index == 1:
                    toolkit.last_mo_sms_sc_address = digits
                    toolkit.last_mo_sms_sc_ton_npi = ton_npi
                address_index += 1
                continue
            if tag_bytes in (b"\x13", b"\x93"):
                toolkit.last_mo_sms_location_information = bytes(value_bytes)
                continue
        self._dispatch_hook(
            "on_mo_sms_control_envelope",
            toolkit.last_mo_sms_destination_address,
            toolkit.last_mo_sms_sc_address,
        )

    def _apply_ussd_download_envelope(self, payload: bytes) -> None:
        """3GPP TS 31.111 §7.3.3 USSD Download envelope decoder.

        Walks the ``D8`` envelope and extracts the USSD String
        TLV (``8A`` / ``0A``). Byte 0 is the GSM-7 / UCS-2 DCS
        per TS 23.038; bytes 1.. carry the encoded text. The
        simulator latches the DCS, the raw bytes, and a
        best-effort decoded string (delegating to
        ``_decode_text_string``).
        """
        try:
            outer_tag, outer_value, _raw, _next = read_tlv(
                bytes(payload or b""), 0
            )
        except ValueError:
            return
        if outer_tag != b"\xD8":
            return
        toolkit = self.state.toolkit
        toolkit.ussd_downloads_received += 1
        offset = 0
        while offset < len(outer_value):
            try:
                tag_bytes, value_bytes, _raw_inner, offset = read_tlv(
                    outer_value,
                    offset,
                )
            except ValueError:
                break
            if tag_bytes in (b"\x8A", b"\x0A") and len(value_bytes) >= 1:
                toolkit.last_ussd_download_dcs = int(value_bytes[0]) & 0xFF
                toolkit.last_ussd_download_raw = bytes(value_bytes[1:])
                toolkit.last_ussd_download_text = self._decode_text_string(
                    int(value_bytes[0]) & 0xFF,
                    value_bytes[1:],
                )
                continue
        self._dispatch_hook(
            "on_ussd_download_envelope",
            toolkit.last_ussd_download_text,
        )

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
        *,
        device_pair: bytes | None = None,
    ) -> bytes:
        # ETSI TS 102 223 §8.7 — Device Identities (TLV 0x82) carries
        # [source, destination]. Default is UICC->Terminal (0x81 0x82);
        # BIP follow-ups override this to UICC->channel-id where the
        # destination device is encoded as 0x20 + channel_id (channel 1
        # = 0x21, ..., channel 7 = 0x27).
        pair_bytes = bytes(device_pair) if device_pair is not None else bytes.fromhex("8182")
        if len(pair_bytes) != 2:
            pair_bytes = bytes.fromhex("8182")
        body = (
            tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, qualifier & 0xFF)))
            + tlv("82", pair_bytes)
            + bytes(extra_tlvs or b"")
        )
        return tlv("D0", body)

    def _bip_followup_device_pair(self) -> bytes | None:
        """Return ``[0x81, 0x20+ch_id]`` for SEND/RECEIVE/CLOSE channel.

        Returns ``None`` when no BIP channel is currently open, in
        which case the caller falls back to the default UICC->Terminal
        pair. ETSI TS 102 223 §6.6.27/28/29 require the destination
        device on these proactive commands to identify the channel
        opened by the matching OPEN CHANNEL; sending the generic
        terminal identifier (0x82) instead causes the modem to
        respond with general result 0x3A / additional info 0x03
        ("Channel identifier not valid").
        """

        channel_id = int(self.state.toolkit.open_channel_id or 0) & 0x07
        if channel_id == 0:
            return None
        return bytes((0x81, 0x20 + channel_id))

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

    def _build_timer_management_start(
        self,
        command_number: int,
        timer_id: int,
        seconds: int,
    ) -> bytes:
        """ETSI TS 102 223 §6.6.21 TIMER MANAGEMENT (start).

        Builds a proactive command that arms timer ``timer_id`` with the
        BCD HH/MM/SS value corresponding to ``seconds``. Qualifier 0x00
        means "start"; the device responds with a TERMINAL RESPONSE and,
        when the timer subsequently expires, sends an ENVELOPE (Timer
        Expiration, tag D7) carrying the same Timer Identifier TLV (A4).
        The simulator latches the requested setpoint into
        ``state.toolkit.timer_table`` so the TR side of the bookkeeping
        keeps working even if the terminal omits the optional Timer
        Value echo.
        """
        normalized_id = max(1, min(8, int(timer_id)))
        normalized_seconds = max(0, int(seconds))
        # ETSI TS 102 223 §8.38 / §8.39 -- Timer Identifier (24) and
        # Timer Value (25). Reference cards emit the comprehension-clear
        # form (no CR bit set); some modems are picky and silently drop
        # the proactive when the CR bit is on, so we mirror that.
        body = tlv("24", bytes((normalized_id,))) + tlv(
            "25",
            _encode_timer_value_bcd(normalized_seconds),
        )
        self.state.toolkit.timer_table[normalized_id] = normalized_seconds
        return self._proactive_command(
            command_number,
            TIMER_MANAGEMENT_COMMAND,
            0x00,
            body,
        )

    def _build_timer_management_deactivate(
        self,
        command_number: int,
        timer_id: int,
    ) -> bytes:
        """ETSI TS 102 223 §6.6.21 TIMER MANAGEMENT (qualifier 0x01).

        Stops a previously armed timer. Reference IPA cards arm a
        long-running watchdog timer right before yielding for a
        RECEIVE DATA flight and then deactivate it once the response
        has been drained, so the modem reports the elapsed wait back
        in the Timer Value (25) TLV. The body carries only the Timer
        Identifier (24) -- the value TLV is reserved for the start
        sub-function.
        """
        normalized_id = max(1, min(8, int(timer_id)))
        body = tlv("24", bytes((normalized_id,)))
        return self._proactive_command(
            command_number,
            TIMER_MANAGEMENT_COMMAND,
            0x01,
            body,
        )

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
        qualifier: int = 0x01,
        alpha_identifier: str = "",
        emit_empty_alpha: bool = True,
        bearer_description: bytes = b"\x03",
    ) -> bytes:
        """ETSI TS 102 223 §6.4.27 OPEN CHANNEL builder.

        TLV order matches what reference IPA implementations emit:

        * ``05`` Alpha identifier (always present so the modem can label
          the BIP session in its UI; empty body when the IPA does not
          want a user-visible string).
        * ``35`` Bearer description -- one byte for the bearer type
          (0x03 = default packet bearer) is the SGP.32 IPA-poll norm.
        * ``39`` Buffer size (16-bit, big endian).
        * ``47`` Network Access Name -- the cellular APN, label-list
          encoded per §8.70. Omitted when no APN is supplied so the
          modem falls back to its currently active PDP context.
        * ``3C`` UICC/terminal interface transport level -- protocol
          type byte (0x01 UDP_REMOTE, 0x02 TCP_CLIENT_REMOTE, ...) plus
          the destination port.
        * ``3E`` Other address (data destination) -- literal IPv4 (type
          0x21) or IPv6 (type 0x57). The IPA must resolve the eIM FQDN
          before it gets here; the public-resolver leg of the
          DNS-over-BIP cycle owns that translation.

        ``qualifier`` carries the OPEN CHANNEL P2 byte (bit 0 = immediate
        link establishment, bit 1 = automatic reconnection). Reference
        cards set 0x03 for the DNS leg (immediate + reconnect because
        the DNS UDP socket is volatile) and 0x01 for the eIM leg
        (immediate, single-shot).
        """

        extra_tlvs = b""
        alpha_text = str(alpha_identifier or "")
        if len(alpha_text) > 0 or emit_empty_alpha:
            extra_tlvs += tlv("05", alpha_text.encode("utf-8"))
        extra_tlvs += tlv("35", bytes(bearer_description or b"\x03"))
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
        return self._proactive_command(
            command_number,
            OPEN_CHANNEL_COMMAND,
            int(qualifier) & 0xFF,
            extra_tlvs,
        )

    def _build_close_channel_command(self, command_number: int) -> bytes:
        return self._proactive_command(
            command_number,
            CLOSE_CHANNEL_COMMAND,
            0x00,
            device_pair=self._bip_followup_device_pair(),
        )

    def _build_send_data_command(self, command_number: int, payload: bytes) -> bytes:
        extra_tlvs = tlv("36", bytes(payload or b""))
        return self._proactive_command(
            command_number,
            SEND_DATA_COMMAND,
            0x00,
            extra_tlvs,
            device_pair=self._bip_followup_device_pair(),
        )

    def _build_receive_data_command(self, command_number: int, requested_length: int) -> bytes:
        bounded_length = max(1, min(0xFF, int(requested_length)))
        # ETSI TS 102 223 §8.41 -- Channel Data Length tag (37). Plain
        # comprehension-clear form mirrors what reference IPA cards emit
        # on RECEIVE DATA; some modems return general result 0x3A when
        # the CR-set form (B7) is used.
        extra_tlvs = tlv("37", bytes((bounded_length,)))
        return self._proactive_command(
            command_number,
            RECEIVE_DATA_COMMAND,
            0x00,
            extra_tlvs,
            device_pair=self._bip_followup_device_pair(),
        )

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
                # Tag 0x47 is multiplexed in TS 102 223: §8.70
                # Network Access Name (label-encoded, multi-byte) and
                # §8.79 Frame Identifier (single byte). Both fields
                # are stashed so the apply layer can disambiguate by
                # command type (OPEN CHANNEL vs. SET FRAMES).
                fields["network_access_name"] = self._decode_network_access_name(value_bytes)
                if len(value_bytes) == 1:
                    fields["frame_identifier"] = int(value_bytes[0])
                continue
            if tag_bytes == b"\x48":
                # TS 102 223 §8.80 Frame Layout. Carried in SET FRAMES.
                fields["frame_layout"] = value_bytes
                continue
            if tag_bytes == b"\x49":
                # TS 102 223 §8.81 Frames Information. In a proactive
                # body it doubles as the Default Frame Identifier
                # carrier (1 byte) per §6.6.36.
                if len(value_bytes) == 1:
                    fields["default_frame_identifier"] = int(value_bytes[0])
                else:
                    fields["frames_information"] = value_bytes
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
                # ETSI TS 102 223 §8.8 Duration TLV. Byte 0 is the
                # time unit (0x00=minutes, 0x01=seconds,
                # 0x02=tenths-of-seconds), byte 1 is the value.
                # The previous shortcut took the value byte alone and
                # silently assumed seconds, which folded a 1-minute
                # POLL INTERVAL into a 1-second one in the simulator
                # trace.
                duration_unit = int(value_bytes[0]) & 0xFF
                duration_value = int(value_bytes[1]) & 0xFF
                fields["duration_unit"] = duration_unit
                fields["duration_value"] = duration_value
                if duration_unit == 0x00:
                    fields["poll_interval_seconds"] = duration_value * 60
                elif duration_unit == 0x02:
                    fields["poll_interval_seconds"] = (duration_value + 9) // 10
                else:
                    fields["poll_interval_seconds"] = duration_value
                continue
            if tag_bytes in (b"\x37", b"\xB7") and len(value_bytes) > 0:
                # ETSI TS 102 223 §8.41 Channel Data Length. Reference
                # IPA cards emit the comprehension-clear form (37) on
                # RECEIVE DATA; the simulator's older builder used the
                # CR-set form (B7). Accept both so the parser is
                # symmetric with what the emitter and a wire trace
                # may carry.
                fields["channel_length"] = int(value_bytes[0])
                continue
            if tag_bytes == b"\x85":
                fields["alpha_identifier"] = value_bytes.decode("utf-8", "ignore")
                continue
            if tag_bytes == b"\x86" and len(value_bytes) >= 1:
                fields["address_ton_npi"] = int(value_bytes[0])
                fields["address_digits"] = self._decode_dialled_digits(value_bytes[1:])
                continue
            if tag_bytes == b"\x88":
                fields["sub_address"] = value_bytes
                continue
            if tag_bytes == b"\x87":
                fields["capability_config"] = value_bytes
                continue
            if tag_bytes == b"\x89":
                fields["ss_string"] = self._decode_dialled_digits(value_bytes[1:])
                continue
            if tag_bytes == b"\x8A" and len(value_bytes) >= 1:
                fields["ussd_dcs"] = int(value_bytes[0])
                fields["ussd_text"] = value_bytes[1:].decode("ascii", "ignore")
                continue
            if tag_bytes == b"\x8B":
                fields["sms_tpdu"] = value_bytes
                continue
            if tag_bytes == b"\x8D" and len(value_bytes) >= 1:
                fields["text_dcs"] = int(value_bytes[0])
                fields["text_string"] = self._decode_text_string(int(value_bytes[0]), value_bytes[1:])
                continue
            if tag_bytes == b"\x8E" and len(value_bytes) >= 1:
                fields["tone"] = int(value_bytes[0])
                continue
            if tag_bytes == b"\x90" and len(value_bytes) >= 1:
                fields["default_item_identifier"] = int(value_bytes[0])
                continue
            if tag_bytes == b"\x91" and len(value_bytes) >= 2:
                fields["min_response_length"] = int(value_bytes[0])
                fields["max_response_length"] = int(value_bytes[1])
                continue
            if tag_bytes == b"\x97" and len(value_bytes) >= 1:
                fields["default_text_dcs"] = int(value_bytes[0])
                fields["default_text"] = self._decode_text_string(int(value_bytes[0]), value_bytes[1:])
                continue
            if tag_bytes == b"\xA8":
                fields["at_command"] = value_bytes.decode("ascii", "ignore")
                continue
            if tag_bytes == b"\xAC":
                fields["dtmf_string"] = self._decode_dialled_digits(value_bytes)
                continue
            if tag_bytes == b"\xAD":
                fields["language"] = value_bytes.decode("ascii", "ignore")
                continue
            if tag_bytes == b"\x30" and len(value_bytes) >= 1:
                fields["browser_identity"] = int(value_bytes[0])
                continue
            if tag_bytes == b"\x31":
                fields["browser_url"] = value_bytes.decode("utf-8", "ignore")
                continue
            if tag_bytes == b"\x32":
                fields["browser_gateway_proxy"] = value_bytes.decode("utf-8", "ignore")
                continue
            if tag_bytes in (b"\x24", b"\xA4") and len(value_bytes) >= 1:
                # TS 102 223 §8.38 Timer Identifier (1..8). Echoed
                # back in the matching TR / TIMER EXPIRATION envelope.
                fields["timer_id"] = int(value_bytes[0])
                continue
            if tag_bytes in (b"\x25", b"\xA5") and len(value_bytes) >= 3:
                # TS 102 223 §8.38 Timer Value -- 3-byte BCD HH/MM/SS.
                fields["timer_value_seconds"] = _decode_timer_value_bcd(value_bytes[:3])
                fields["timer_value_raw"] = value_bytes[:3]
                continue
            if tag_bytes == b"\x61":
                # TS 102 223 §8.66 Service Record TLV (DECLARE SERVICE).
                fields["service_record"] = value_bytes
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
            if tag_bytes in (b"\x03", b"\x83") and len(value_bytes) > 0:
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
                continue
            if tag_bytes in (b"\x04", b"\x84") and len(value_bytes) >= 2:
                # ETSI TS 102 223 §8.8 Duration TLV. Byte 0 is the
                # time unit (0x00 minutes / 0x01 seconds / 0x02
                # tenths-of-second), byte 1 is the count. POLL
                # INTERVAL echoes the negotiated duration here on
                # the TR side so the apply layer can confirm what
                # cadence the terminal accepted.
                fields["duration_unit"] = int(value_bytes[0]) & 0xFF
                fields["duration_value"] = int(value_bytes[1]) & 0xFF
                fields["duration_raw"] = bytes(value_bytes[:2])
                continue
            # PROVIDE LOCAL INFORMATION terminal-response items.
            # Tags below cover TS 102 223 §8.19 (Location Info),
            # §8.20 (IMEI), §8.39 (Date-Time-Timezone), §8.45
            # (Language), §8.66 (IMEISV) and §8.108 (Battery State).
            # Both the comprehension-required (bit 8 set) and
            # comprehension-clear forms are accepted because some
            # terminals strip the CR bit.
            if tag_bytes in (b"\x13", b"\x93"):
                fields["location_information"] = value_bytes
                continue
            if tag_bytes in (b"\x14", b"\x94"):
                fields["imei"] = value_bytes
                continue
            if tag_bytes in (b"\x26", b"\xA6"):
                fields["date_time_timezone"] = value_bytes
                continue
            if tag_bytes in (b"\x2D", b"\xAD"):
                fields["language"] = value_bytes.decode("ascii", "ignore")
                continue
            if tag_bytes in (b"\x62", b"\xE2"):
                # 0x62/0xE2 multiplexes IMEISV (PROVIDE LOCAL
                # INFORMATION qualifier 0x08) and Service
                # Information (GET SERVICE INFORMATION). Stash both
                # interpretations; the apply layer picks the right
                # field based on the originating command.
                fields["imeisv"] = value_bytes
                fields["service_information"] = value_bytes
                continue
            if tag_bytes in (b"\x5C", b"\xDC") and len(value_bytes) > 0:
                fields["battery_state"] = int(value_bytes[0])
                continue
            if tag_bytes in (b"\x24", b"\xA4") and len(value_bytes) >= 1:
                # Disambiguate: PERFORM CARD APDU encodes the R-APDU
                # under the same primitive tag in the response. The
                # parser flags both interpretations; the apply layer
                # picks the right one based on the originating command.
                fields["timer_id"] = int(value_bytes[0])
                fields["card_apdu_response"] = value_bytes
                continue
            if tag_bytes in (b"\x25", b"\xA5") and len(value_bytes) >= 3:
                fields["timer_value_seconds"] = _decode_timer_value_bcd(value_bytes[:3])
                fields["timer_value_raw"] = value_bytes[:3]
                continue
            if tag_bytes in (b"\x61", b"\xE1"):
                # TS 102 223 §8.65 Service Record TLV (echoed in
                # SERVICE SEARCH terminal responses).
                fields["service_record"] = value_bytes
                continue
            if tag_bytes in (b"\x63", b"\xE3") and len(value_bytes) >= 1:
                # TS 102 223 §8.67 Device Filter (search-side hint).
                fields["device_filter"] = value_bytes
                continue
            if tag_bytes in (b"\x29", b"\xA9"):
                # TS 102 223 §8.46 AT Response (TR side of RUN AT
                # COMMAND). The terminal emits the raw modem reply
                # (e.g. ``\r\n+CGSN: ...\r\nOK\r\n``) which the apply
                # layer caches verbatim.
                fields["at_response"] = value_bytes
                continue
            if tag_bytes in (b"\xE0",):
                # Reader Identifier TLV used by GET READER STATUS
                # responses (TS 102 223 §8.69). Multiple records are
                # concatenated by the terminal; we keep the raw blob
                # for the apply layer to scan.
                existing_blob = bytes(fields.get("reader_status_records", b"") or b"")
                fields["reader_status_records"] = existing_blob + raw_tlv
                continue
            if tag_bytes in (b"\x09", b"\x89"):
                # TS 102 223 §8.13 SS String, echoed back in a
                # SEND SS terminal response when the network
                # returned a USS / SS reply.
                fields["ss_response_raw"] = value_bytes
                if len(value_bytes) > 0:
                    fields["ss_response_string"] = self._decode_dialled_digits(
                        value_bytes[1:]
                    )
                continue
            if tag_bytes in (b"\x0A", b"\x8A") and len(value_bytes) >= 1:
                # TS 102 223 §8.14 USSD String (TR side of SEND
                # USSD): byte 0 = DCS, bytes 1.. = encoded text.
                fields["ussd_response_dcs"] = int(value_bytes[0]) & 0xFF
                fields["ussd_response_text"] = self._decode_text_string(
                    int(value_bytes[0]) & 0xFF,
                    value_bytes[1:],
                )
                continue
            if tag_bytes in (b"\x1A", b"\x9A"):
                # TS 102 223 §8.27 Additional Information.  Used as
                # a cause-code carrier in many terminal responses
                # (notably SEND SS / SEND USSD) and as a free-form
                # diagnostic for SEND SHORT MESSAGE.
                fields["additional_information"] = value_bytes
                continue
            if tag_bytes in (b"\x49", b"\xC9"):
                # TS 102 223 §8.81 Frames Information (TR side of
                # GET FRAMES STATUS / SET FRAMES). Carries the
                # frames-count + active-frame descriptor.
                fields["frames_information"] = value_bytes
                continue
            if tag_bytes in (b"\x0D", b"\x8D") and len(value_bytes) >= 1:
                # TS 102 223 §8.15 Text String. Used in TRs for
                # GET INKEY / GET INPUT to carry the user-typed
                # character (single GSM-7 / UCS-2 / 8-bit unit) or
                # the dialled string. Byte 0 = DCS, bytes 1.. =
                # encoded text.
                fields["text_string_dcs"] = int(value_bytes[0]) & 0xFF
                fields["text_string_raw"] = bytes(value_bytes[1:])
                fields["text_string"] = self._decode_text_string(
                    int(value_bytes[0]) & 0xFF,
                    value_bytes[1:],
                )
                continue
            if tag_bytes in (b"\x10", b"\x90") and len(value_bytes) >= 1:
                # TS 102 223 §8.10 Item Identifier. Used in the
                # SELECT ITEM TR to carry the identifier byte the
                # user picked. The proactive parser also handles
                # this tag (as ``default_item_identifier``); on the
                # TR side we expose it as ``item_identifier`` so the
                # apply layer can disambiguate.
                fields["item_identifier"] = int(value_bytes[0]) & 0xFF
                continue
        return fields

    def _parse_event_download(self, payload: bytes) -> dict[str, object] | None:
        try:
            root_tag, root_value, _raw_tlv, _next_offset = read_tlv(bytes(payload or b""), 0)
        except ValueError:
            return None
        if root_tag != b"\xD6":
            return None
        fields: dict[str, object] = {}
        # ETSI TS 101 220 §7.1.1 Access Technology TLV (tag 3F /
        # BF) is a COMPREHENSION-TLV whose first byte hits the
        # ``bottom-5-bits == 0x1F`` ambiguity in BER. The generic
        # BER walker below would mis-parse it as a multi-byte
        # tag, so detect and lift out the single-byte access-tech
        # TLV before the loop runs.
        access_tech_value = self._extract_simple_tlv(root_value, (0x3F, 0xBF))
        if access_tech_value is not None and len(access_tech_value) >= 1:
            fields["access_technology"] = int(access_tech_value[0]) & 0xFF
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
                continue
            if tag_bytes in (b"\x34", b"\xB4") and len(value_bytes) > 0:
                # TS 102 223 §8.55 Browser Termination Cause. 0x00 =
                # user, 0x01 = error.
                fields["browser_termination_cause"] = int(value_bytes[0])
                continue
            if tag_bytes in (b"\x4A", b"\xCA"):
                # 3GPP TS 31.111 §8.95 EMM/MM/GMM cause envelope for
                # network-rejection events. Stored verbatim.
                fields["network_rejection_cause"] = value_bytes
                continue
            if tag_bytes == b"\x89":
                # TS 102 223 §8.13 SS-string sent in an SS event
                # download. Kept raw because the digit decode is
                # already handled by ``_decode_dialled_digits``.
                fields["ss_event_data"] = value_bytes
                continue
            if tag_bytes == b"\x8A" and len(value_bytes) >= 1:
                # TS 102 223 §8.10 USSD-string. Byte 0 is the DCS,
                # bytes 1.. are the encoded text (GSM-7, UCS-2, ..).
                fields["ussd_event_dcs"] = int(value_bytes[0])
                fields["ussd_event_data"] = value_bytes[1:]
                continue
            if tag_bytes == b"\x40" and len(value_bytes) >= 1:
                # TS 102 223 §8.56 Local Connection status doubles
                # as the HCI Connectivity / Contactless State byte
                # for events 0x13 and 0x16. All three
                # interpretations are stashed so the apply layer
                # can pick the right one based on the event code;
                # the high nibble of byte 0 is 0x80 when the
                # connection / gate is up, 0x00 when down.
                fields["local_connection_status"] = int(value_bytes[0])
                fields["hci_connectivity_status"] = int(value_bytes[0])
                fields["contactless_status"] = int(value_bytes[0])
                continue
            if tag_bytes == b"\xB9" and len(value_bytes) >= 1:
                # 3GPP TS 31.111 §8.103 IMS Registration Status (TLV
                # 0xB9). 1 byte: 0x00 deregistered, 0x01 registered.
                fields["ims_registration_status"] = int(value_bytes[0])
                continue
            if tag_bytes == b"\xBA":
                # 3GPP TS 31.111 §8.104 IMS Data (TLV 0xBA). Carries
                # the SIP / IMS payload for both IMS Registration
                # (event 0x18) and IMS Incoming Data (event 0x19).
                # The apply layer routes the same blob into the
                # right cache based on the event code.
                fields["ims_registration_data"] = value_bytes
                fields["ims_incoming_data"] = value_bytes
                continue
            if tag_bytes in (b"\x1C", b"\x9C") and len(value_bytes) >= 1:
                # ETSI TS 102 223 §8.50 Transaction Identifier
                # carried by MT Call / Call Connected / Call
                # Disconnected events. The first byte is sufficient
                # for the simulator to correlate phases.
                fields["transaction_identifier"] = int(value_bytes[0])
                continue
            if tag_bytes in (b"\x06", b"\x86") and len(value_bytes) >= 1:
                # TS 102 223 §8.4 Address TLV: byte 0 is TON/NPI,
                # bytes 1.. are BCD digits. The CR-set form 0x86 is
                # what ME-> card uses for MT Call notifications.
                fields["call_address_ton_npi"] = int(value_bytes[0])
                fields["call_address_digits"] = self._decode_dialled_digits(
                    value_bytes[1:]
                )
                continue
            if tag_bytes in (b"\x08", b"\x88"):
                # TS 102 223 §8.6 Sub Address. Some MT-Call
                # notifications carry the calling sub-address even
                # when the MS does not display it.
                fields["call_subaddress"] = value_bytes
                continue
            if tag_bytes in (b"\x1A", b"\x9A"):
                # 3GPP TS 24.008 Annex H / TS 102 223 §8.18 Cause
                # TLV. Call Disconnected (event 0x02) carries the
                # network-side disconnect cause as a multi-byte
                # blob; the simulator stashes it verbatim so an
                # applet can correlate the tear-down without
                # parsing the cause sub-fields.
                fields["call_disconnect_cause"] = value_bytes
                continue
            if tag_bytes in (b"\x46", b"\xC6"):
                # TS 102 223 §8.86 Display Parameters. Carried by
                # the §7.4.x Display Parameters Change event; the
                # simulator stashes the raw TLV value because the
                # internal structure (rows / columns / chars) varies
                # across vendors.
                fields["display_parameters"] = value_bytes
                continue
            if tag_bytes in (b"\x49", b"\xC9"):
                # TS 102 223 §8.81 Frames Information carried by the
                # §7.4.16 Frames Information Change Event. The TLV
                # body lays out the new frame partitioning chosen by
                # the user; we keep the raw bytes because vendors
                # encode the layout differently and the apply layer
                # only needs the blob plus a transition counter.
                fields["frames_information"] = value_bytes
                continue
            if tag_bytes in (b"\xA0", b"\x20") and len(value_bytes) >= 1:
                # TS 102 223 §8.34 Card Reader Status TLV (carried
                # by the §7.4.7 Card Reader Status event for multi
                # card terminals). Byte 0 packs:
                #   bits 7..6  card present / powered flags
                #   bits 3..0  reader identifier (1..7; 0 = the ME)
                # The simulator latches the raw byte plus the
                # decoded reader id so an STK applet can decide
                # whether to re-issue PERFORM CARD APDU.
                fields["card_reader_status"] = int(value_bytes[0]) & 0xFF
                fields["card_reader_id"] = int(value_bytes[0]) & 0x0F
                continue
        return fields

    def _result_succeeded(self, result_code: int) -> bool:
        if result_code in (0x00, 0x01):
            return True
        return False

    @staticmethod
    def _extract_simple_tlv(
        payload: bytes,
        tag_candidates: tuple[int, ...],
    ) -> bytes | None:
        """Lightweight COMPREHENSION-TLV scanner.

        ETSI TS 101 220 §7.1.1.1 single-byte tags include values
        whose bottom-5 bits are ``11111`` (e.g. ``0x3F`` Access
        Technology). The generic BER walker treats those as the
        first byte of a multi-byte tag and so cannot match them.
        This helper does a strict left-to-right walk over the
        payload assuming a 1-byte tag and a 1-byte length, which
        is sufficient for the simple event-download TLVs that hit
        the ambiguity. Returns the value bytes for the first
        matching tag, or ``None`` if none of the candidates were
        found / the payload was malformed.
        """
        offset = 0
        data = bytes(payload or b"")
        while offset < len(data):
            tag = data[offset]
            if offset + 1 >= len(data):
                return None
            length = data[offset + 1]
            value_start = offset + 2
            value_end = value_start + length
            if value_end > len(data):
                return None
            if tag in tag_candidates:
                return data[value_start:value_end]
            offset = value_end
        return None

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

    @staticmethod
    def _decode_dialled_digits(payload: bytes) -> str:
        reverse = {value: key for key, value in TOOLKIT_DIGIT_NIBBLES.items()}
        out: list[str] = []
        for byte in bytes(payload or b""):
            low = byte & 0x0F
            high = (byte >> 4) & 0x0F
            if low in reverse:
                out.append(reverse[low])
            elif low != 0xF:
                out.append(f"{low:X}")
            if high in reverse:
                out.append(reverse[high])
            elif high == 0xF:
                continue
            else:
                out.append(f"{high:X}")
        return "".join(out)

    @staticmethod
    def _decode_text_string(dcs: int, payload: bytes) -> str:
        raw = bytes(payload or b"")
        normalized_dcs = int(dcs) & 0xFF
        if normalized_dcs == 0x08 and len(raw) % 2 == 0:
            try:
                return raw.decode("utf-16-be")
            except UnicodeDecodeError:
                return ""
        if normalized_dcs in (0x04, 0x00):
            return raw.decode("ascii", "ignore")
        try:
            return raw.decode("utf-8", "ignore")
        except UnicodeDecodeError:
            return ""
