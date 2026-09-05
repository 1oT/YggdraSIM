# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP03 card-side crypto: INITIALIZE-UPDATE / EXTERNAL AUTHENTICATE response and per-APDU MAC+ENC envelope (GlobalPlatform Card Specification v2.3)."""
from __future__ import annotations

import hmac
import os
from typing import Any

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from SCP03.config import Config
from SIMCARD.state import SimCardState, SimScp03Session
from SIMCARD.utils import parse_apdu


def _decode_hex_key(value: Any, fallback: str) -> bytes:
    text = str(value or "").strip().replace(" ", "")
    if len(text) == 0:
        text = fallback
    return bytes.fromhex(text)


class Scp03CardLogic:
    def __init__(self, state: SimCardState) -> None:
        self.state = state
        self._static_keys = self._load_static_keys()
        self._session_keys: dict[str, bytes] = {}
        self._authenticated_channel: int | None = None
        self._last_command_ins: int | None = None
        self._last_command_channel: int | None = None

    def reset(self) -> None:
        """Clear active SCP03 session state and reload static keys from ``state.scp03_keys``."""
        # Re-read the static keys on every reset so a profile switch
        # (SGP.22 enableProfile / disableProfile, BPP install) that
        # rewrites ``state.scp03_keys`` via ``rebuild_runtime_filesystem``
        # actually takes effect on the next INITIALIZE UPDATE. Without
        # this refresh ``_static_keys`` would still hold the keyset
        # captured at engine boot.
        self._static_keys = self._load_static_keys()
        self.state.scp03_session = SimScp03Session(key_version=self._static_keys["kvn"])
        self._session_keys = {}
        self._authenticated_channel = None
        self._last_command_ins = None
        self._last_command_channel = None

    def is_wrapped_command(self, apdu: bytes) -> bool:
        """Return True when *apdu* carries a GP SCP03 security-level header (CLA bit 0x04 set)."""
        command = bytes(apdu or b"")
        if len(command) < 4:
            return False
        session = self.state.scp03_session
        if session.authenticated is False:
            return False
        ins = command[1]
        if ins in (0x50, 0x82):
            return False
        if command[0] & 0x40:
            return bool(command[0] & 0x20)
        return bool(command[0] & 0x04)

    def handle_initialize_update(self, kvn: int, host_challenge: bytes) -> tuple[bytes, int, int]:
        """GP Card Spec v2.3.1 §7.1 INITIALIZE UPDATE — derives session keys and returns card challenge.

        Selects key-version-number *kvn* from the static key set, generates an 8-byte
        card challenge, and writes the derived session keys into ``state.scp03_session``.
        """
        if len(host_challenge) != 8:
            return b"", 0x67, 0x00
        # GP Card Spec v2.3.1 §7.1: INITIALIZE UPDATE is the place to
        # latch the active keyset for the upcoming session. Refresh
        # from ``state.scp03_keys`` here so a runtime profile change
        # (e.g. enabling a BPP whose securityDomain PE supplied new
        # baseline keys) is honoured without re-instantiating the
        # engine.
        self._static_keys = self._load_static_keys()
        expected_kvn = int(self._static_keys["kvn"])
        if kvn not in (0x00, expected_kvn):
            return b"", 0x6A, 0x88

        card_challenge = os.urandom(8)
        s_enc, s_mac, s_rmac = self._derive_session_keys(host_challenge, card_challenge)
        self._session_keys = {
            "s_enc": s_enc,
            "s_mac": s_mac,
            "s_rmac": s_rmac,
        }
        self.state.scp03_session = SimScp03Session(
            key_version=expected_kvn,
            host_challenge=bytes(host_challenge),
            card_challenge=card_challenge,
            selected_aid=self._selected_aid_hex(),
        )
        self._authenticated_channel = None
        card_cryptogram = self._gen_crypto(constant=0x00)
        # b7/b6=11 declares R-MAC and R-ENC support; b5=0 declares the
        # random challenge generated above (SCP03 Amendment D, Table 5-1).
        i_parameter = 0x60
        key_info = bytes([expected_kvn, 0x03, i_parameter])
        response = (b"\x00" * 10) + key_info + card_challenge + card_cryptogram 
        if (i_parameter & 0x10) != 0:
            self.state.scp03_sequence_counter = (self.state.scp03_sequence_counter + 1) & 0xFFFFFF
            response += self.state.scp03_sequence_counter.to_bytes(3, "big")
        return response, 0x90, 0x00

    def handle_external_authenticate(self, security_level: int, payload: bytes) -> tuple[bytes, int, int]:
        """GP Card Spec v2.3.1 §7.1 EXTERNAL AUTHENTICATE — verifies host cryptogram and opens session.

        Checks the host C-MAC against the session S-MAC key; on success marks
        ``session.authenticated = True`` and records the negotiated security level.
        """
        session = self.state.scp03_session
        if len(self._session_keys) == 0 or len(session.host_challenge) == 0:
            return b"", 0x69, 0x85
        if len(payload) != 16:
            return b"", 0x67, 0x00
        if security_level not in (0x00, 0x01, 0x03, 0x11, 0x13, 0x33):
            return b"", 0x6A, 0x86

        host_cryptogram = payload[:8]
        host_mac = payload[8:16]
        expected_cryptogram = self._gen_crypto(constant=0x01)
        if not hmac.compare_digest(host_cryptogram, expected_cryptogram):
            self.reset()
            return b"", 0x69, 0x82

        header = bytes([0x84, 0x82, security_level & 0xFF, 0x00, 0x10])
        full_mac = self._cmac(self._session_keys["s_mac"], session.chaining_value + header + host_cryptogram)
        if not hmac.compare_digest(host_mac, full_mac[:8]):
            self.reset()
            return b"", 0x69, 0x82

        session.chaining_value = full_mac
        session.security_level = security_level & 0xFF
        session.authenticated = True
        session.ssc = 1
        self._authenticated_channel = 0
        return b"", 0x90, 0x00

    def unwrap_command(self, apdu: bytes) -> tuple[bytes | None, tuple[bytes, int, int] | None]:
        """Verify and strip the SCP03 C-MAC/C-ENC envelope from *apdu*.

        Returns ``(plain_apdu, None)`` on success, or ``(None, error_sw_tuple)`` when
        the MAC verification fails or the session is not yet authenticated.
        """
        session = self.state.scp03_session
        if session.authenticated is False:
            return bytes(apdu or b""), None

        protected_apdu = bytes(apdu or b"")
        parsed = parse_apdu(protected_apdu)
        command_data = bytes(parsed["data"] or b"")
        if len(command_data) < 8:
            self.reset()
            return None, (b"", 0x69, 0x88)

        cla = int(parsed["cla"])
        ins = int(parsed["ins"])
        p1 = int(parsed["p1"])
        p2 = int(parsed["p2"])
        command_channel = 4 + (cla & 0x0F) if cla & 0x40 else cla & 0x03
        if (
            self._authenticated_channel is None
            or command_channel != self._authenticated_channel
        ):
            self.reset()
            return None, (b"", 0x69, 0x85)
        mac_value = command_data[-8:]
        protected_payload = command_data[:-8]

        # SCP03 Amendment D §6.2.4 authenticates a five-byte short APDU
        # header. GlobalPlatform APDUs do not use extended Lc/Le.
        is_extended = len(protected_apdu) >= 7 and protected_apdu[4] == 0x00
        if is_extended:
            self.reset()
            return None, (b"", 0x67, 0x00)
        if cla & 0x40:
            mac_cla = (cla & 0x80) | 0x04
        else:
            mac_cla = (cla & 0xF0) | 0x04
        header = bytes([mac_cla, ins, p1, p2, len(command_data)])
        expected_full_mac = self._cmac(
            self._session_keys["s_mac"],
            session.chaining_value + header + protected_payload,
        )
        if not hmac.compare_digest(mac_value, expected_full_mac[:8]):
            self.reset()
            return None, (b"", 0x69, 0x88)
        session.chaining_value = expected_full_mac

        plain_payload = protected_payload
        encryption_counter: int | None = None
        if session.security_level & 0x02:
            encryption_counter = session.ssc if session.ssc > 0 else 1
            session.ssc = encryption_counter + 1
        if len(protected_payload) > 0 and (session.security_level & 0x02):
            assert encryption_counter is not None
            try:
                iv = self._generate_iv(encryption_counter.to_bytes(16, "big"))
                plain_payload = self._cbc_decrypt(
                    self._session_keys["s_enc"], iv, protected_payload
                )
                plain_payload = self._remove_iso_padding(plain_payload)
            except (ValueError, TypeError):
                self.reset()
                return None, (b"", 0x69, 0x88)

        original_cla = cla & (0xDF if cla & 0x40 else 0xFB)
        le = parsed["le"]
        rebuilt = bytearray([original_cla, ins, p1, p2])
        use_extended = is_extended or len(plain_payload) > 0xFF or (
            le is not None and int(le) > 0x100
        )
        if len(plain_payload) == 0:
            if le is not None:
                if use_extended:
                    encoded_le = 0 if int(le) == 65536 else int(le)
                    rebuilt.append(0x00)
                    rebuilt.extend(encoded_le.to_bytes(2, "big"))
                else:
                    encoded_le = 0 if int(le) == 256 else int(le)
                    rebuilt.append(encoded_le & 0xFF)
        elif use_extended:
            rebuilt.append(0x00)
            rebuilt.extend(len(plain_payload).to_bytes(2, "big"))
            rebuilt.extend(plain_payload)
            if le is not None:
                encoded_le = 0 if int(le) == 65536 else int(le)
                rebuilt.extend(encoded_le.to_bytes(2, "big"))
        else:
            rebuilt.append(len(plain_payload))
            rebuilt.extend(plain_payload)
            if le is not None:
                encoded_le = 0 if int(le) == 256 else int(le)
                rebuilt.append(encoded_le & 0xFF)
        self._last_command_ins = ins
        self._last_command_channel = command_channel
        return bytes(rebuilt), None

    def wrap_response(self, data: bytes, sw1: int, sw2: int) -> bytes:
        """Apply SCP03 R-MAC/R-ENC protection to a command response when an authenticated session is active."""
        session = self.state.scp03_session
        response = bytes(data or b"")
        if session.authenticated is False:
            return response
        protected_status = sw1 == 0x90 or sw1 in (0x62, 0x63)
        if protected_status is False:
            # SCP03 §6.2.5: error responses carry only the status word.
            wire_response = b""
        elif (session.security_level & 0x10) == 0:
            wire_response = response
        else:
            protected_response = response
            if len(response) > 0 and (session.security_level & 0x20):
                iv_counter = session.ssc - 1
                if iv_counter < 1:
                    raise RuntimeError(
                        "R-ENC response has no matching command encryption counter."
                    )
                iv_input = bytearray(iv_counter.to_bytes(16, "big"))
                iv_input[0] = 0x80
                iv = self._generate_iv(bytes(iv_input))
                padded = self._add_iso_padding(response)
                protected_response = self._cbc_encrypt(
                    self._session_keys["s_enc"], iv, padded
                )
            response_mac = self._cmac(
                self._session_keys["s_rmac"],
                session.chaining_value
                + protected_response
                + bytes([sw1 & 0xFF, sw2 & 0xFF]),
            )
            wire_response = protected_response + response_mac[:8]

        if (
            (sw1, sw2) == (0x90, 0x00)
            and self._last_command_ins == 0xA4
            and self._last_command_channel == self._authenticated_channel
        ):
            # Selecting another application on the channel terminates the
            # associated Application Session and its Secure Channel Session.
            self.reset()
        return wire_response

    def key_template(self) -> bytes:
        kvn = int(self._static_keys["kvn"]) & 0xFF
        entries = []
        for key_id in (1, 2, 3):
            entries.append(bytes([0xC0, 0x04, key_id, kvn, 0x88, 0x10]))
        return b"".join(entries)

    def _selected_aid_hex(self) -> str:
        current_node = self.state.nodes.get(self.state.current_node_id)
        if current_node is None:
            return ""
        return str(current_node.aid or "").strip().upper()

    def _load_static_keys(self) -> dict[str, Any]:
        keys = self.state.scp03_keys
        return {
            "kenc": bytes(getattr(keys, "kenc", b""))
            or _decode_hex_key(Config.DEFAULT_KEYS["scp03_kenc"], Config.DEFAULT_KEYS["scp03_kenc"]),
            "kmac": bytes(getattr(keys, "kmac", b""))
            or _decode_hex_key(Config.DEFAULT_KEYS["scp03_kmac"], Config.DEFAULT_KEYS["scp03_kmac"]),
            "dek": bytes(getattr(keys, "dek", b""))
            or _decode_hex_key(Config.DEFAULT_KEYS["scp03_dek"], Config.DEFAULT_KEYS["scp03_dek"]),
            "kvn": int(getattr(keys, "kvn", int(Config.DEFAULT_KEYS["scp03_kvn"], 16))),
        }

    def _derive_session_keys(self, host_challenge: bytes, card_challenge: bytes) -> tuple[bytes, bytes, bytes]:
        context = bytes(host_challenge) + bytes(card_challenge)
        k_enc = self._static_keys["kenc"]
        k_mac = self._static_keys["kmac"]
        # Amd D §6.2.1: L is the session key length, so it follows the
        # static key rather than being fixed at AES-128.
        s_enc = self._kdf(k_enc, 0x04, context, len(k_enc) * 8)
        s_mac = self._kdf(k_mac, 0x06, context, len(k_mac) * 8)
        s_rmac = self._kdf(k_mac, 0x07, context, len(k_mac) * 8)
        return s_enc, s_mac, s_rmac

    def _kdf(self, key: bytes, constant: int, context: bytes, bit_len: int) -> bytes:
        # NIST SP 800-108 counter mode. The PRF gives 16 bytes a call, so
        # anything above AES-128 needs a second round with the counter
        # incremented; a single round silently returned a short key.
        prefix = (b"\x00" * 11) + bytes([constant & 0xFF]) + b"\x00" + bit_len.to_bytes(2, "big")
        out = b""
        counter = 1
        while len(out) < bit_len // 8:
            out += self._cmac(bytes(key), prefix + bytes([counter]) + context)
            counter += 1
        return out[: bit_len // 8]

    def _gen_crypto(self, constant: int) -> bytes:
        session = self.state.scp03_session
        context = session.host_challenge + session.card_challenge
        payload = (b"\x00" * 11) + bytes([constant & 0xFF]) + b"\x00\x00\x40\x01" + context
        return self._cmac(self._session_keys["s_mac"], payload)[:8]

    @staticmethod
    def _cmac(key: bytes, payload: bytes) -> bytes:
        mac = cmac.CMAC(algorithms.AES(bytes(key)))
        mac.update(bytes(payload))
        return mac.finalize()

    def _generate_iv(self, iv_input: bytes) -> bytes:
        return self._ecb_encrypt(self._session_keys["s_enc"], bytes(iv_input))

    @staticmethod
    def _ecb_encrypt(key: bytes, payload: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(bytes(key)), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(bytes(payload)) + encryptor.finalize()

    @staticmethod
    def _cbc_encrypt(key: bytes, iv: bytes, payload: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(bytes(key)), modes.CBC(bytes(iv)))
        encryptor = cipher.encryptor()
        return encryptor.update(bytes(payload)) + encryptor.finalize()

    @staticmethod
    def _cbc_decrypt(key: bytes, iv: bytes, payload: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(bytes(key)), modes.CBC(bytes(iv)))
        decryptor = cipher.decryptor()
        return decryptor.update(bytes(payload)) + decryptor.finalize()

    @staticmethod
    def _add_iso_padding(payload: bytes) -> bytes:
        data = bytes(payload)
        pad_len = 16 - (len(data) % 16)
        if pad_len == 0:
            pad_len = 16
        return data + b"\x80" + (b"\x00" * (pad_len - 1))

    @staticmethod
    def _remove_iso_padding(payload: bytes) -> bytes:
        index = payload.rfind(b"\x80")
        if index == -1:
            raise ValueError("SCP03 encrypted command padding marker is missing.")
        if any(byte != 0x00 for byte in payload[index + 1 :]):
            raise ValueError("SCP03 encrypted command padding is invalid.")
        return bytes(payload[:index])
