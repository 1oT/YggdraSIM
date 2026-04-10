from __future__ import annotations

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

    def reset(self) -> None:
        self.state.scp03_session = SimScp03Session(key_version=self._static_keys["kvn"])
        self._session_keys = {}

    def is_wrapped_command(self, apdu: bytes) -> bool:
        command = bytes(apdu or b"")
        if len(command) < 4:
            return False
        session = self.state.scp03_session
        if session.authenticated is False:
            return False
        ins = command[1]
        if ins in (0x50, 0x82):
            return False
        return bool(command[0] & 0x04)

    def handle_initialize_update(self, kvn: int, host_challenge: bytes) -> tuple[bytes, int, int]:
        if len(host_challenge) != 8:
            return b"", 0x67, 0x00
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
        card_cryptogram = self._gen_crypto(constant=0x00)
        response = (b"\x00" * 10) + bytes([expected_kvn, 0x03, 0x03]) + card_challenge + card_cryptogram
        return response, 0x90, 0x00

    def handle_external_authenticate(self, security_level: int, payload: bytes) -> tuple[bytes, int, int]:
        session = self.state.scp03_session
        if len(self._session_keys) == 0 or len(session.host_challenge) == 0:
            return b"", 0x69, 0x85
        if len(payload) < 16:
            return b"", 0x67, 0x00

        host_cryptogram = payload[:8]
        host_mac = payload[8:16]
        expected_cryptogram = self._gen_crypto(constant=0x01)
        if host_cryptogram != expected_cryptogram:
            self.reset()
            return b"", 0x69, 0x82

        header = bytes([0x84, 0x82, security_level & 0xFF, 0x00, 0x10])
        full_mac = self._cmac(self._session_keys["s_mac"], session.chaining_value + header + host_cryptogram)
        if host_mac != full_mac[:8]:
            self.reset()
            return b"", 0x69, 0x82

        session.chaining_value = full_mac
        session.security_level = security_level & 0xFF
        session.authenticated = True
        session.ssc = 1
        return b"", 0x90, 0x00

    def unwrap_command(self, apdu: bytes) -> tuple[bytes | None, tuple[bytes, int, int] | None]:
        session = self.state.scp03_session
        if session.authenticated is False:
            return bytes(apdu or b""), None

        parsed = parse_apdu(bytes(apdu or b""))
        command_data = bytes(parsed["data"] or b"")
        if len(command_data) < 8:
            return None, (b"", 0x69, 0x88)

        cla = int(parsed["cla"])
        ins = int(parsed["ins"])
        p1 = int(parsed["p1"])
        p2 = int(parsed["p2"])
        mac_value = command_data[-8:]
        protected_payload = command_data[:-8]

        session.ssc += 1
        header = bytes([cla, ins, p1, p2, len(command_data)])
        expected_full_mac = self._cmac(
            self._session_keys["s_mac"],
            session.chaining_value + header + protected_payload,
        )
        if mac_value != expected_full_mac[:8]:
            return None, (b"", 0x69, 0x88)
        session.chaining_value = expected_full_mac

        plain_payload = protected_payload
        if len(protected_payload) > 0 and (session.security_level & 0x02):
            iv = self._generate_iv((session.ssc - 1).to_bytes(16, "big"))
            plain_payload = self._cbc_decrypt(self._session_keys["s_enc"], iv, protected_payload)
            plain_payload = self._remove_iso_padding(plain_payload)

        original_cla = cla & 0xFB
        le = parsed["le"]
        rebuilt = bytearray([original_cla, ins, p1, p2])
        if len(plain_payload) > 0:
            if len(plain_payload) > 0xFF:
                rebuilt.extend([0x00, (len(plain_payload) >> 8) & 0xFF, len(plain_payload) & 0xFF])
            else:
                rebuilt.append(len(plain_payload))
            rebuilt.extend(plain_payload)
        if le is not None:
            if le == 65536:
                rebuilt.extend(b"\x00\x00")
            elif le == 256:
                rebuilt.append(0x00)
            elif le <= 0xFF:
                rebuilt.append(le & 0xFF)
            else:
                rebuilt.extend(le.to_bytes(2, "big"))
        return bytes(rebuilt), None

    def wrap_response(self, data: bytes, sw1: int, sw2: int) -> bytes:
        session = self.state.scp03_session
        response = bytes(data or b"")
        if session.authenticated is False:
            return response
        if len(response) == 0:
            return response
        if (session.security_level & 0x20) == 0:
            return response

        iv_counter = session.ssc - 1
        if iv_counter < 0:
            iv_counter = 0
        iv_input = bytearray(iv_counter.to_bytes(16, "big"))
        iv_input[0] = 0x80
        iv = self._generate_iv(bytes(iv_input))
        padded = self._add_iso_padding(response)
        encrypted = self._cbc_encrypt(self._session_keys["s_enc"], iv, padded)
        # Host-side simulator transport currently ignores response MAC bytes,
        # but keeping the trailer preserves the expected SCP03 wire shape.
        response_mac = self._cmac(
            self._session_keys["s_rmac"],
            session.chaining_value + encrypted + bytes([sw1 & 0xFF, sw2 & 0xFF]),
        )
        return encrypted + response_mac[:8]

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
        s_enc = self._kdf(self._static_keys["kenc"], 0x04, context, 128)
        s_mac = self._kdf(self._static_keys["kmac"], 0x06, context, 128)
        s_rmac = self._kdf(self._static_keys["kmac"], 0x07, context, 128)
        return s_enc, s_mac, s_rmac

    def _kdf(self, key: bytes, constant: int, context: bytes, bit_len: int) -> bytes:
        payload = (b"\x00" * 11) + bytes([constant & 0xFF]) + b"\x00" + bit_len.to_bytes(2, "big") + b"\x01" + context
        return self._cmac(bytes(key), payload)[: bit_len // 8]

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
            return bytes(payload)
        if any(byte != 0x00 for byte in payload[index + 1 :]):
            return bytes(payload)
        return bytes(payload[:index])
