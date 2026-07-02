# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SMS-PP / SCP80 secured command execution inside the simulator."""

from __future__ import annotations

import logging
from collections.abc import Callable

from SIMCARD.state import SimCardState
from SIMCARD.utils import read_tlv, split_apdu_sequence, tlv

_LOGGER = logging.getLogger(__name__)

ApduResult = tuple[bytes, int, int]
TransmitFn = Callable[[bytes], ApduResult]

_SMS_PP_D0_STATIC = bytes.fromhex("810301130082028183050086028001")
_SINGLE_SMS_TP_PREFIX = bytes.fromhex("4005811250F341F62222222222222225027000")
_CONCAT_SMS_TP_PREFIX = bytes.fromhex("4005811250F341F6222222222222222502")
_CONCAT_UDH_PREFIX = bytes.fromhex("050003")
_GET_RESPONSE_MAX_ROUNDS = 64
_TPDU_PID_OFFSET = 6
_TPDU_DCS_OFFSET = 7


class Scp80Logic:
    """TS 102 225 secured packets carried inside SMS-PP (ENVELOPE D1)."""

    def __init__(self, state: SimCardState, transmit: TransmitFn) -> None:
        self.state = state
        self._transmit = transmit
        self._concat_asm_key: tuple[int, int] | None = None
        self._concat_asm_parts: dict[int, bytes] = {}

    def handle_envelope(self, payload: bytes) -> ApduResult:
        """Handle an OTA ENVELOPE command (ETSI TS 102 225 §7.2) and return (data, SW1, SW2)."""
        self.state.ota_history.append(payload.hex().upper())
        envelope = bytes(payload or b"")
        fetch_body: bytes
        try:
            d1_value = self._d1_envelope_value(envelope)
            tpdu = self._sms_tpdu_from_d1(d1_value)
            block = self._resolve_0348_block(tpdu)
            if block is None:
                return b"", 0x90, 0x00
            sec = self.state.scp80_security
            inner, param_data, cntr_bytes = self._decrypt_block(
                block, bytes(sec.key_enc), bytes(sec.key_mac)
            )
            if len(inner) == 0:
                raise ValueError("empty OTA command payload")
            rapdu_chain = self._run_command_sequence(inner)
            response_plain = bytes([0x00]) + rapdu_chain
            response_block = self._encrypt_response(
                response_plain,
                param_data=param_data,
                cntr_bytes=cntr_bytes,
                k_enc=bytes(sec.key_enc),
                k_mac=bytes(sec.key_mac),
            )
            response_tpdu = self._response_tpdu(response_block)
            fetch_body = tlv(b"\xD0", _SMS_PP_D0_STATIC + tlv(b"\x8B", response_tpdu))
        except (TypeError, ValueError) as exc:
            self._reset_sms_reassembly()
            _LOGGER.warning(
                "scp80: SMS-PP secured command could not be executed (%s: %s); using stub PoR.",
                exc.__class__.__name__,
                exc,
            )
            fetch_body = bytes.fromhex("D00C8103011300820281828B0100")
        self.state.pending_fetch_queue.append(fetch_body)
        return b"", 0x91, len(fetch_body)

    def _reset_sms_reassembly(self) -> None:
        self._concat_asm_key = None
        self._concat_asm_parts.clear()

    def _resolve_0348_block(self, tpdu: bytes) -> bytes | None:
        raw = bytes(tpdu or b"")
        single = self._strip_single_segment_0348(raw)
        if single is not None:
            self._reset_sms_reassembly()
            return single
        return self._feed_concat_sms_segment(raw)

    def _strip_single_segment_0348(self, tpdu: bytes) -> bytes | None:
        if len(tpdu) <= len(_SINGLE_SMS_TP_PREFIX):
            return None
        if self._tpdu_prefix_matches(tpdu, _SINGLE_SMS_TP_PREFIX) is False:
            return None
        return tpdu[len(_SINGLE_SMS_TP_PREFIX) :]

    def _feed_concat_sms_segment(self, tpdu: bytes) -> bytes | None:
        prefix = _CONCAT_SMS_TP_PREFIX
        if len(tpdu) < len(prefix) + 1:
            raise ValueError("concat SMS TPDU shorter than minimum prefix")
        if self._tpdu_prefix_matches(tpdu, prefix) is False:
            raise ValueError("unsupported SMS TPDU layout")
        tp_len = tpdu[len(prefix)]
        end = len(prefix) + 1 + int(tp_len)
        if end > len(tpdu):
            raise ValueError("truncated TP-UD length in concat SMS")
        tp_ud = tpdu[len(prefix) + 1 : end]
        if len(tp_ud) < 6:
            raise ValueError("concat TP-UD shorter than UDH header")
        if tp_ud[0 : len(_CONCAT_UDH_PREFIX)] != _CONCAT_UDH_PREFIX:
            raise ValueError("TP-UD is not 8-bit concatenated SMS UDH")
        ref = int(tp_ud[3]) & 0xFF
        total = int(tp_ud[4]) & 0xFF
        seq = int(tp_ud[5]) & 0xFF
        frag = tp_ud[6:]
        if total < 1 or seq < 1 or seq > total:
            raise ValueError("invalid concat SMS sequence counters")
        key = (ref, total)
        if self._concat_asm_key is not None and self._concat_asm_key != key:
            self._reset_sms_reassembly()
        self._concat_asm_key = key
        self._concat_asm_parts[seq] = frag
        if len(self._concat_asm_parts) < total:
            return None
        for index in range(1, total + 1):
            if index not in self._concat_asm_parts:
                return None
        block = b"".join(self._concat_asm_parts[i] for i in range(1, total + 1))
        self._reset_sms_reassembly()
        return block

    @staticmethod
    def _tpdu_prefix_matches(tpdu: bytes, prefix: bytes) -> bool:
        raw = bytes(tpdu or b"")
        expected = bytes(prefix or b"")
        if len(raw) < len(expected):
            return False
        for index, value in enumerate(expected):
            if index in (_TPDU_PID_OFFSET, _TPDU_DCS_OFFSET):
                continue
            if raw[index] != value:
                return False
        return True

    @staticmethod
    def _d1_envelope_value(envelope: bytes) -> bytes:
        tag, value, _raw, _next_off = read_tlv(envelope, 0)
        if tag != b"\xD1":
            raise ValueError("envelope root is not D1")
        return value

    @staticmethod
    def _sms_tpdu_from_d1(d1_value: bytes) -> bytes:
        offset = 0
        raw = bytes(d1_value or b"")
        while offset < len(raw):
            tag, val, _blob, next_off = read_tlv(raw, offset)
            if tag == b"\x8B":
                return val
            offset = next_off
        raise ValueError("D1 value missing SMS TPDU tag 8B")

    @staticmethod
    def _decrypt_block(block: bytes, k_enc: bytes, k_mac: bytes) -> tuple[bytes, bytes, bytes]:
        from SCP80.crypto import CryptoEngine

        return CryptoEngine.decrypt_0348_command_block(block, k_enc, k_mac)

    @staticmethod
    def _encrypt_response(
        response_plain: bytes,
        *,
        param_data: bytes,
        cntr_bytes: bytes,
        k_enc: bytes,
        k_mac: bytes,
    ) -> bytes:
        from SCP80.crypto import CryptoEngine

        return CryptoEngine.build_0348_response_block(
            response_plain,
            param_data=param_data,
            cntr_bytes=cntr_bytes,
            k_enc=k_enc,
            k_mac=k_mac,
        )

    def _run_command_sequence(self, inner: bytes) -> bytes:
        rapdu_acc = b""
        for segment in split_apdu_sequence(inner):
            rapdu_acc += self._transmit_with_get_response_chain(segment)
        return rapdu_acc

    def _transmit_with_get_response_chain(self, apdu: bytes) -> bytes:
        apdu_b = bytes(apdu or b"")
        data, sw1, sw2 = self._transmit(apdu_b)
        out = bytes(data or b"")
        rounds = 0
        while int(sw1) == 0x61:
            rounds += 1
            if rounds > _GET_RESPONSE_MAX_ROUNDS:
                raise RuntimeError("GET RESPONSE chain exceeded configured maximum")
            le_byte = int(sw2) & 0xFF
            if le_byte == 0:
                le_byte = 256
            gr_le = min(le_byte, 256)
            if gr_le == 256:
                encoded_le = 0x00
            else:
                encoded_le = gr_le & 0xFF
            cla = apdu_b[0] & 0xFF if len(apdu_b) > 0 else 0x00
            gr_cmd = bytes([cla, 0xC0, 0x00, 0x00, encoded_le])
            chunk, sw1, sw2 = self._transmit(gr_cmd)
            out += bytes(chunk or b"")
        out += bytes((int(sw1) & 0xFF, int(sw2) & 0xFF))
        return out

    @staticmethod
    def _response_tpdu(response_block: bytes) -> bytes:
        return _SINGLE_SMS_TP_PREFIX + bytes(response_block)
