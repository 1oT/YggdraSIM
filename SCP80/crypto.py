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

from Crypto .Cipher import AES ,DES3 
from Crypto .Hash import CMAC 
if __package__ :
    from .utils import Utils 
else :
    from utils import Utils 

class CryptoEngine :
    @staticmethod 
    def get_algo_type (byte_hex :str )->str :
        try :
            val =int (byte_hex ,16 )&0x0F 
            if val ==0x02 :return "AES"
            if val ==0x05 :return "3DES2"
            if val ==0x09 :return "3DES3"
            return "3DES2"
        except Exception :return "3DES2"

    @staticmethod 
    def describe_keyset (byte_hex :str )->str :
        try :
            val =int (byte_hex ,16 )
            algo =val &0x0F 
            keyset =(val >>4 )&0x0F 

            algo_name ="Unknown"
            if algo ==0x00 :algo_name ="Implicit"
            elif algo ==0x01 :algo_name ="DES"
            elif algo ==0x02 :algo_name ="AES"
            elif algo ==0x05 :algo_name ="3DES (2-key)"
            elif algo ==0x09 :algo_name ="3DES (3-key)"

            return f"{byte_hex} ({algo_name}, Keyset {keyset})"
        except Exception :
            return byte_hex 

    @staticmethod 
    def compute_pcntr (payload_len :int ,block_size :int ,cc_len :int =8 )->int :
        base_len =5 +1 +cc_len +payload_len 
        limit =16 if block_size ==16 else 8 
        for p in range (limit ):
            if (base_len +p )%block_size ==0 :return p 
        raise ValueError ("PCNTR alignment failed")

    @staticmethod 
    def compute_cc (algo :str ,key :bytes ,data :bytes )->bytes :
        if algo =="AES":
            c =CMAC .new (key ,ciphermod =AES )
            c .update (data )
            return c .digest ()[:8 ]
        else :
            key_eff =Utils .pad_key_3des (key )
            pad_len =(-len (data ))%8 
            if pad_len :data +=b'\x00'*pad_len 
            cipher =DES3 .new (key_eff ,DES3 .MODE_CBC ,iv =b'\x00'*8 )
            return cipher .encrypt (data )[-8 :]

    @staticmethod 
    def encrypt_ct (algo :str ,key :bytes ,data :bytes )->bytes :
        if algo =="AES":
            pad_len =(-len (data ))%16 
            if pad_len :data +=b'\x00'*pad_len 
            cipher =AES .new (key ,AES .MODE_CBC ,iv =b'\x00'*16 )
            return cipher .encrypt (data )
        else :
            key_eff =Utils .pad_key_3des (key )
            pad_len =(-len (data ))%8 
            if pad_len :data +=b'\x00'*pad_len 
            cipher =DES3 .new (key_eff ,DES3 .MODE_CBC ,iv =b'\x00'*8 )
            return cipher .encrypt (data )

    @staticmethod
    def decrypt_ct(algo: str, key: bytes, data: bytes) -> bytes:
        if algo == "AES":
            cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
            return cipher.decrypt(data)
        key_eff = Utils.pad_key_3des(key)
        cipher = DES3.new(key_eff, DES3.MODE_CBC, iv=b"\x00" * 8)
        return cipher.decrypt(data)

    @staticmethod
    def decrypt_0348_command_block(
        block: bytes,
        k_enc: bytes,
        k_mac: bytes,
    ) -> tuple[bytes, bytes, bytes]:
        """Unpack a §5.1 Command Packet built by ``OtaPacketBuilder`` / TS 102 225.

        Returns ``(inner_command_bytes, param_data, cntr_bytes)`` where
        *param_data* is SPI, KIc, KID, TAR (7 octets).
        """
        raw = bytes(block or b"")
        if len(raw) < 10:
            raise ValueError("secured packet shorter than header+cipher stub")
        header_blob = raw[0:3]
        param_data = raw[3:10]
        ct = raw[10:]
        kic_b = param_data[2]
        kid_b = param_data[3]
        cipher_mode = CryptoEngine.get_algo_type(f"{kic_b:02X}")
        mac_mode = CryptoEngine.get_algo_type(f"{kid_b:02X}")
        pt = CryptoEngine.decrypt_ct(cipher_mode, k_enc, ct)
        if len(pt) < 14:
            raise ValueError("decrypted payload shorter than CNTR+PCNTR+CC")
        cntr_bytes = pt[0:5]
        pcntr = pt[5] & 0xFF
        if pcntr < 0 or pcntr > 15:
            raise ValueError("invalid PCNTR")
        cc_recv = pt[6:14]
        secured_tail = pt[14:]
        if len(secured_tail) < pcntr:
            raise ValueError("truncated secured application data")
        payload_padded = secured_tail
        inner = payload_padded[:-pcntr] if pcntr else payload_padded
        mac_input = header_blob + param_data + cntr_bytes + bytes([pcntr]) + payload_padded
        cc_calc = CryptoEngine.compute_cc(mac_mode, k_mac, mac_input)
        if cc_calc != cc_recv:
            raise ValueError("secured packet cryptographic checksum mismatch")
        return inner, param_data, cntr_bytes

    @staticmethod
    def build_0348_response_block(
        response_plain: bytes,
        *,
        param_data: bytes,
        cntr_bytes: bytes,
        k_enc: bytes,
        k_mac: bytes,
    ) -> bytes:
        """Build a §5.2 Response Packet using the same shell layout as ``OtaPacketBuilder``."""
        body = bytes(response_plain or b"")
        kic_b = param_data[2]
        kid_b = param_data[3]
        cipher_mode = CryptoEngine.get_algo_type(f"{kic_b:02X}")
        mac_mode = CryptoEngine.get_algo_type(f"{kid_b:02X}")
        block_size = 16 if cipher_mode == "AES" else 8
        chi_byte = b"\x00"
        chl_byte = b"\x15"
        pcntr = CryptoEngine.compute_pcntr(len(body), block_size, 8)
        body_padded = body + b"\x00" * pcntr
        ct_len = 5 + 1 + 8 + len(body_padded)
        cpl_val = len(chl_byte) + len(param_data) + ct_len
        cpl_byte = bytes([cpl_val])
        header_blob = chi_byte + cpl_byte + chl_byte
        mac_input = header_blob + param_data + cntr_bytes + bytes([pcntr]) + body_padded
        cc = CryptoEngine.compute_cc(mac_mode, k_mac, mac_input)
        enc_input = cntr_bytes + bytes([pcntr]) + cc + body_padded
        ct = CryptoEngine.encrypt_ct(cipher_mode, k_enc, enc_input)
        return header_blob + param_data + ct