from Crypto.Cipher import AES, DES3
from Crypto.Hash import CMAC
from utils import Utils

class CryptoEngine:
    @staticmethod
    def get_algo_type(byte_hex: str) -> str:
        try:
            val = int(byte_hex, 16) & 0x0F
            if val == 0x02: return "AES"
            if val == 0x05: return "3DES2"
            if val == 0x09: return "3DES3"
            return "3DES2"
        except: return "3DES2"
        
    @staticmethod
    def describe_keyset(byte_hex: str) -> str:
        try:
            val = int(byte_hex, 16)
            algo = val & 0x0F
            keyset = (val >> 4) & 0x0F
            
            algo_name = "Unknown"
            if algo == 0x00: algo_name = "Implicit"
            elif algo == 0x01: algo_name = "DES"
            elif algo == 0x02: algo_name = "AES"
            elif algo == 0x05: algo_name = "3DES (2-key)"
            elif algo == 0x09: algo_name = "3DES (3-key)"
            
            return f"{byte_hex} ({algo_name}, Keyset {keyset})"
        except:
            return byte_hex

    @staticmethod
    def compute_pcntr(payload_len: int, block_size: int, cc_len: int = 8) -> int:
        base_len = 5 + 1 + cc_len + payload_len
        limit = 16 if block_size == 16 else 8
        for p in range(limit):
            if (base_len + p) % block_size == 0: return p
        raise ValueError("PCNTR alignment failed")

    @staticmethod
    def compute_cc(algo: str, key: bytes, data: bytes) -> bytes:
        if algo == "AES":
            c = CMAC.new(key, ciphermod=AES)
            c.update(data)
            return c.digest()[:8]
        else:
            key_eff = Utils.pad_key_3des(key)
            pad_len = (-len(data)) % 8
            if pad_len: data += b'\x00' * pad_len
            cipher = DES3.new(key_eff, DES3.MODE_CBC, iv=b'\x00'*8)
            return cipher.encrypt(data)[-8:]

    @staticmethod
    def encrypt_ct(algo: str, key: bytes, data: bytes) -> bytes:
        if algo == "AES":
            pad_len = (-len(data)) % 16
            if pad_len: data += b'\x00' * pad_len
            cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
            return cipher.encrypt(data)
        else:
            key_eff = Utils.pad_key_3des(key)
            pad_len = (-len(data)) % 8
            if pad_len: data += b'\x00' * pad_len
            cipher = DES3.new(key_eff, DES3.MODE_CBC, iv=b'\x00'*8)
            return cipher.encrypt(data)