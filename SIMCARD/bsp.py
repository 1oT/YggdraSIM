# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""BSP (Bearer-Service Profile) crypto layer: key derivation and AES-CBC+MAC for SCP11 BPP channel protection."""
from __future__ import annotations

from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

from SIMCARD.utils import encode_length, read_tlv_header


MAX_SEGMENT_SIZE = 1020


class BspCryptoError(Exception):
    pass


def bsp_key_derivation(
    shared_secret: bytes,
    key_type: int,
    key_length: int,
    host_id: bytes,
    eid: bytes,
    length: int = 16,
) -> tuple[bytes, bytes, bytes]:
    """Derive BSP session keys (S-ENC, S-MAC, initial MCV) via X9.63 KDF (SGP.22 §3.1.4).

    Returns the three key materials needed to initialise a ``BspInstance``.
    """
    shared_info = (
        bytes([key_type & 0xFF, key_length & 0xFF])
        + encode_length(len(host_id))
        + bytes(host_id)
        + encode_length(len(eid))
        + bytes(eid)
    )
    kdf = X963KDF(algorithm=hashes.SHA256(), length=length * 3, sharedinfo=shared_info)
    material = kdf.derive(bytes(shared_secret))
    initial_mcv = material[:length]
    s_enc = material[length : length * 2]
    s_mac = material[length * 2 : length * 3]
    return s_enc, s_mac, initial_mcv


class _BspCipher:
    blocksize = 16

    def __init__(self, s_enc: bytes) -> None:
        self.s_enc = bytes(s_enc)
        self.block_nr = 1

    def encrypt(self, data: bytes) -> bytes:
        padded = self._pad(bytes(data))
        cipher = Cipher(algorithms.AES(self.s_enc), modes.CBC(self._next_icv()))
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def decrypt(self, data: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.s_enc), modes.CBC(self._next_icv()))
        decryptor = cipher.decryptor()
        padded = decryptor.update(bytes(data)) + decryptor.finalize()
        return self._unpad(padded)

    def _next_icv(self) -> bytes:
        block = self.block_nr.to_bytes(self.blocksize, "big", signed=False)
        self.block_nr += 1
        cipher = Cipher(algorithms.AES(self.s_enc), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(block) + encryptor.finalize()

    @staticmethod
    def _pad(data: bytes) -> bytes:
        pad_len = 16 - ((len(data) + 1) % 16)
        if pad_len == 16:
            pad_len = 0
        return bytes(data) + b"\x80" + (b"\x00" * pad_len)

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        stripped = bytes(data).rstrip(b"\x00")
        if len(stripped) == 0 or stripped[-1] != 0x80:
            raise BspCryptoError("Invalid BSP padding.")
        return stripped[:-1]


class _BspMac:
    mac_length = 8

    def __init__(self, s_mac: bytes, initial_mcv: bytes) -> None:
        self.s_mac = bytes(s_mac)
        self.mac_chain = bytes(initial_mcv)

    def auth(self, tag: int, data: bytes) -> bytes:
        raw_without_mac = bytes([tag & 0xFF]) + encode_length(len(data) + self.mac_length) + bytes(data)
        full_mac = self._cmac(self.mac_chain + raw_without_mac)
        self.mac_chain = full_mac
        return raw_without_mac + full_mac[: self.mac_length]

    def verify(self, protected_tlv: bytes) -> bytes:
        """Verify the trailing AES-CMAC truncation on *protected_tlv* and return the payload without MAC.

        Raises ``BspCryptoError`` when the MAC does not match.
        """
        raw = bytes(protected_tlv)
        if len(raw) < self.mac_length + 2:
            raise ValueError("Protected BSP TLV is too short.")
        raw_without_mac = raw[: -self.mac_length]
        received_mac = raw[-self.mac_length :]
        full_mac = self._cmac(self.mac_chain + raw_without_mac)
        self.mac_chain = full_mac
        expected_mac = full_mac[: self.mac_length]
        if received_mac != expected_mac:
            raise BspCryptoError("BSP MAC verification failed.")
        return raw_without_mac

    def _cmac(self, data: bytes) -> bytes:
        mac = cmac.CMAC(algorithms.AES(self.s_mac))
        mac.update(bytes(data))
        return mac.finalize()


class BspInstance:
    def __init__(self, s_enc: bytes, s_mac: bytes, initial_mcv: bytes) -> None:
        self.c_algo = _BspCipher(bytes(s_enc))
        self.m_algo = _BspMac(bytes(s_mac), bytes(initial_mcv))
        tag_len = 1
        len_len = len(encode_length(MAX_SEGMENT_SIZE))
        self.max_payload_size = MAX_SEGMENT_SIZE - tag_len - len_len - self.m_algo.mac_length

    @classmethod
    def from_kdf(
        cls,
        shared_secret: bytes,
        key_type: int,
        key_length: int,
        host_id: bytes,
        eid: bytes,
    ) -> "BspInstance":
        """Construct a ``BspInstance`` from a raw ECDH shared secret via ``bsp_key_derivation``."""
        s_enc, s_mac, initial_mcv = bsp_key_derivation(
            shared_secret=bytes(shared_secret),
            key_type=int(key_type),
            key_length=int(key_length),
            host_id=bytes(host_id),
            eid=bytes(eid),
        )
        return cls(s_enc=s_enc, s_mac=s_mac, initial_mcv=initial_mcv)

    def encrypt_and_mac_one(self, tag: int, plaintext: bytes) -> bytes:
        encrypted = self.c_algo.encrypt(bytes(plaintext))
        return self.m_algo.auth(int(tag), encrypted)

    def encrypt_and_mac(self, tag: int, plaintext: bytes) -> list[bytes]:
        """Segment *plaintext* into BSP-sized chunks, AES-CBC-encrypt each, and append AES-CMAC."""
        chunks: list[bytes] = []
        remainder = bytes(plaintext)
        while len(remainder) > 0:
            chunk = remainder[: self.max_payload_size]
            remainder = remainder[self.max_payload_size :]
            chunks.append(self.encrypt_and_mac_one(tag, chunk))
        return chunks

    def mac_only_one(self, tag: int, plaintext: bytes) -> bytes:
        protected = self.m_algo.auth(int(tag), bytes(plaintext))
        self.c_algo.block_nr += 1
        return protected

    def mac_only(self, tag: int, plaintext: bytes) -> list[bytes]:
        """Segment *plaintext* into BSP-sized chunks and append AES-CMAC without encryption."""
        chunks: list[bytes] = []
        remainder = bytes(plaintext)
        while len(remainder) > 0:
            chunk = remainder[: self.max_payload_size]
            remainder = remainder[self.max_payload_size :]
            chunks.append(self.mac_only_one(tag, chunk))
        return chunks

    def demac_and_decrypt_one(self, protected_tlv: bytes) -> bytes:
        raw_without_mac = self.m_algo.verify(bytes(protected_tlv))
        _, _, header_length, _ = read_tlv_header(raw_without_mac, 0)
        value = raw_without_mac[header_length:]
        return self.c_algo.decrypt(value)

    def demac_and_decrypt(self, protected_tlvs: list[bytes]) -> bytes:
        return b"".join(self.demac_and_decrypt_one(item) for item in protected_tlvs)

    def demac_only_one(self, protected_tlv: bytes) -> bytes:
        raw_without_mac = self.m_algo.verify(bytes(protected_tlv))
        _, _, header_length, _ = read_tlv_header(raw_without_mac, 0)
        value = raw_without_mac[header_length:]
        self.c_algo.block_nr += 1
        return value

    def demac_only(self, protected_tlvs: list[bytes]) -> bytes:
        return b"".join(self.demac_only_one(item) for item in protected_tlvs)
