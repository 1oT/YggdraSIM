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

"""SCP03 key derivation and command/response secure messaging.

The wire rules implemented here are from GlobalPlatform SCP03 Amendment D
v1.1.2, sections 6.2.4 through 6.2.7.  In particular, response integrity is
verified over the *ciphertext* before optional R-ENC decryption.
"""

from dataclasses import dataclass
import hmac
from typing import Dict, List, Optional, Sequence

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# GPC v2.3 Amd D §4.1.5 SCP03 KDF and §6.2.2.2/§6.2.2.3 cryptogram
# derivation are delegated to pySim.global_platform.scp.scp03_key_derivation
# so the spec citation lives upstream. We resolve the function lazily —
# pySim.global_platform.__init__ pulls in pySim.filesystem (and through
# it the real pyscard ``smartcard.util``), which a few tests install
# only as a partial stub. Keeping the import inside ``_resolve_kdf``
# means importing ``Scp03Session`` itself is inert; the chain fires only
# the first time a key derivation actually runs.
_PYSIM_SCP03_KDF =None 


class Scp03Error(RuntimeError):
    """Base class for local SCP03 processing failures."""


class Scp03ApduFormatError(ValueError, Scp03Error):
    """Raised when a command APDU is structurally invalid or unsupported."""


class Scp03ResponseProtectionError(Scp03Error):
    """Raised when an authenticated response cannot be trusted."""


@dataclass(frozen=True)
class ParsedCommandApdu:
    """A validated ISO/IEC 7816 command APDU."""

    raw: bytes
    case: int
    extended: bool
    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes
    le: Optional[int]


def parse_command_apdu(apdu: Sequence[int]) -> ParsedCommandApdu:
    """Parse a short or extended command APDU without accepting a prefix.

    ``Le`` is returned as its semantic value (256 for short ``00`` and
    65536 for extended ``0000``).  The parser deliberately rejects malformed
    or trailing bytes rather than silently truncating the command data.
    """

    try:
        raw = bytes(apdu)
    except (TypeError, ValueError) as exc:
        raise Scp03ApduFormatError(
            "Command APDU must contain byte values in the range 00..FF."
        ) from exc

    if len(raw) < 4:
        raise Scp03ApduFormatError(
            "Command APDU must contain at least CLA, INS, P1, and P2."
        )

    cla, ins, p1, p2 = raw[:4]
    if len(raw) == 4:
        return ParsedCommandApdu(raw, 1, False, cla, ins, p1, p2, b"", None)

    first_length = raw[4]
    if len(raw) == 5:
        le = 256 if first_length == 0 else first_length
        return ParsedCommandApdu(raw, 2, False, cla, ins, p1, p2, b"", le)

    if first_length != 0:
        lc = first_length
        data_end = 5 + lc
        if len(raw) == data_end:
            return ParsedCommandApdu(
                raw, 3, False, cla, ins, p1, p2, raw[5:data_end], None
            )
        if len(raw) == data_end + 1:
            encoded_le = raw[data_end]
            le = 256 if encoded_le == 0 else encoded_le
            return ParsedCommandApdu(
                raw, 4, False, cla, ins, p1, p2, raw[5:data_end], le
            )
        if len(raw) < data_end:
            raise Scp03ApduFormatError(
                f"Short APDU declares {lc} data byte(s), but only "
                f"{max(0, len(raw) - 5)} are present."
            )
        raise Scp03ApduFormatError("Short APDU contains trailing bytes after Le.")

    if len(raw) < 7:
        raise Scp03ApduFormatError(
            "Extended APDU is truncated before its two-byte length field."
        )
    extended_length = int.from_bytes(raw[5:7], "big")
    if len(raw) == 7:
        le = 65536 if extended_length == 0 else extended_length
        return ParsedCommandApdu(raw, 2, True, cla, ins, p1, p2, b"", le)
    if extended_length == 0:
        raise Scp03ApduFormatError("Extended Lc must not be zero.")

    data_end = 7 + extended_length
    if len(raw) == data_end:
        return ParsedCommandApdu(
            raw, 3, True, cla, ins, p1, p2, raw[7:data_end], None
        )
    if len(raw) == data_end + 2:
        encoded_le = int.from_bytes(raw[data_end : data_end + 2], "big")
        le = 65536 if encoded_le == 0 else encoded_le
        return ParsedCommandApdu(
            raw, 4, True, cla, ins, p1, p2, raw[7:data_end], le
        )
    if len(raw) < data_end:
        raise Scp03ApduFormatError(
            f"Extended APDU declares {extended_length} data byte(s), but only "
            f"{max(0, len(raw) - 7)} are present."
        )
    raise Scp03ApduFormatError(
        "Extended APDU must contain either no Le or exactly two Le bytes."
    )


def _resolve_kdf ():
    global _PYSIM_SCP03_KDF 
    if _PYSIM_SCP03_KDF is None :
        from pySim .global_platform .scp import scp03_key_derivation 
        _PYSIM_SCP03_KDF =scp03_key_derivation 
    return _PYSIM_SCP03_KDF 


class Scp03Session :
    def __init__ (self ,static_keys :Dict [str ,bytes ]):
        self .k_enc =static_keys ['kenc']
        self .k_mac =static_keys ['kmac']
        self .dek =static_keys .get ('dek',b'')
        self .s_enc =None 
        self .s_mac =None 
        self .s_rmac =None 
        self .chaining_value =b'\x00'*16 
        self .ssc =0 
        self ._is_authenticated =False
        self .authenticated_channel :Optional [int ]=None
        self .card_challenge =b''
        self .host_challenge =b''
        self .i_parameter =0
        self .sec_level =0x33 
        self .proprietary_iv =None 
        self .last_cmd_header =b''
        self .last_encryption_counter :Optional [int ]=None
        self .protocol_name ="SCP03"

    @property
    def is_authenticated (self )->bool :
        return self ._is_authenticated

    @is_authenticated .setter
    def is_authenticated (self ,value :bool )->None :
        self ._is_authenticated =bool (value )
        if self ._is_authenticated and self .authenticated_channel is None :
            # Existing authentication code uses the basic channel.  Callers
            # authenticating on a supplementary channel can bind it
            # explicitly before marking the session authenticated.
            self .authenticated_channel =0

    def bind_logical_channel (self ,channel :int )->None :
        """Bind this Secure Channel Session to one ISO logical channel."""
        channel =int (channel )
        if not 0 <=channel <=19 :
            raise Scp03Error ("SCP03 logical channel must be in range 0..19.")
        if (
            self .is_authenticated
            and self .authenticated_channel is not None
            and self .authenticated_channel !=channel
        ):
            raise Scp03Error (
            "Cannot move an active SCP03 session to a different logical channel."
            )
        self .authenticated_channel =channel

    @staticmethod
    def logical_channel_from_cla (cla :int )->int :
        """Decode the ISO logical channel number carried in a CLA byte."""
        cla =int (cla )&0xFF
        if cla &0x40 :
            return 4 +(cla &0x0F )
        return cla &0x03

    def reset_state (self )->None :
        """Clear the chaining value, SSC counter, and authentication flag to a clean pre-session state."""
        self .chaining_value =b'\x00'*16 
        self .ssc =0 
        self .is_authenticated =False 
        self .card_challenge =b''
        self .host_challenge =b''
        self .i_parameter =0
        self .proprietary_iv =None 
        self .last_cmd_header =b''
        self .last_encryption_counter =None
        self .authenticated_channel =None
        self .s_enc =None
        self .s_mac =None
        self .s_rmac =None

    def derive_keys (self ,host_challenge :bytes ,card_response :bytes ):
        """Derive SCP03 session keys from *host_challenge* and *card_response* (GP Card Spec v2.3.1 §7.1.2)."""
        host_challenge =bytes (host_challenge )
        card_response =bytes (card_response )
        if len (host_challenge )!=8 :
            raise Scp03Error ("SCP03 host challenge must be exactly 8 bytes.")
        if len (card_response )not in (29 ,32 ):
            raise Scp03Error (
            "SCP03 INITIALIZE UPDATE response must be 29 bytes, or 32 "
            "bytes when the optional sequence counter is present."
            )
        if card_response [11 ]!=0x03 :
            raise Scp03Error (
            f"INITIALIZE UPDATE selected SCP{card_response[11]:02X}, not SCP03."
            )
        i_parameter =card_response [12 ]
        if i_parameter &0x8F or (i_parameter &0x60 )==0x40 :
            raise Scp03Error (
            f"INITIALIZE UPDATE returned invalid SCP03 i parameter "
            f"0x{i_parameter:02X}."
            )
        expected_response_length =32 if i_parameter &0x10 else 29
        if len (card_response )!=expected_response_length :
            raise Scp03Error (
            "INITIALIZE UPDATE sequence-counter presence does not match the "
            "SCP03 i parameter."
            )
        for label ,key in (("Key-ENC",self .k_enc ),("Key-MAC",self .k_mac )):
            if len (key )not in (16 ,24 ,32 ):
                raise Scp03Error (f"{label} must be a 16, 24, or 32 byte AES key.")

        self .host_challenge =host_challenge
        self .card_challenge =card_response [13 :21 ]
        self .i_parameter =i_parameter
        card_cryptogram =card_response [21 :29 ]
        self .ssc =0 
        self .last_encryption_counter =None
        context =self .host_challenge +self .card_challenge 
        self .s_enc =self ._kdf (self .k_enc ,b'\x04',context ,128 )
        self .s_mac =self ._kdf (self .k_mac ,b'\x06',context ,128 )
        self .s_rmac =self ._kdf (self .k_mac ,b'\x07',context ,128 )
        expected =self ._gen_crypto (b'\x00')
        if not hmac .compare_digest (expected ,card_cryptogram ):
            self .reset_state ()
            raise Scp03ResponseProtectionError ("Card cryptogram verification failed.")
        self .proprietary_iv =None 

    def calculate_host_cryptogram (self )->bytes :
        return self ._gen_crypto (b'\x01')

    def _kdf (self ,key :bytes ,constant :bytes ,context :bytes ,bit_len :int )->bytes :
        # GPC v2.3 Amd D §4.1.5 — NIST SP 800-108 counter-mode KDF with
        # AES-CMAC PRF. Delegated to pySim so the constant/label encoding
        # stays spec-anchored (12-byte label = 11 0x00 bytes + 1-byte
        # derivation constant; 1-byte separator; 2-byte L; 1-byte counter).
        return _resolve_kdf ()(constant ,context ,key ,bit_len )

    def _gen_crypto (self ,constant :bytes )->bytes :
        # GPC v2.3 Amd D §6.2.2.2 / §6.2.2.3 — host & card cryptograms
        # are 8-byte (l=64) outputs of the §4.1.5 KDF keyed with S-MAC.
        context =self .host_challenge +self .card_challenge 
        return self ._kdf (self .s_mac ,constant ,context ,64 )

    def _generate_iv_from_bytes (self ,iv_input :bytes )->bytes :
        if self .s_enc is None :
            raise Scp03Error ("SCP03 session encryption key is not derived.")
        if len (iv_input )!=16 :
            raise Scp03Error ("SCP03 ICV input must be exactly 16 bytes.")
        cipher =Cipher (algorithms .AES (self .s_enc ),modes .ECB ())
        encryptor =cipher .encryptor ()
        return encryptor .update (iv_input )+encryptor .finalize ()

    @staticmethod
    def _secure_messaging_cla (cla :int )->tuple [int ,int ]:
        """Return ``(MAC CLA, wire CLA)`` for GP secure messaging.

        The command's logical channel is deliberately excluded from the C-MAC
        input and restored only on the wire, as required by SCP03 §6.2.4.
        """
        cla =int (cla )&0xFF
        if cla &0x40 :
            # Further interindustry coding: b7 marks channels 4..19 and b6 is
            # the secure-messaging indication.
            mac_cla =(cla &0x80 )|0x04
            wire_cla =(cla &0x80 )|0x60 |(cla &0x0F )
            return mac_cla ,wire_cla

        # First interindustry coding: b1..b2 carry channels 0..3 and b3 is
        # the GlobalPlatform proprietary secure-messaging indication.
        channel =cla &0x03
        mac_cla =(cla &0xF0 )|0x04
        return mac_cla ,mac_cla |channel

    @staticmethod
    def _pad80 (data :bytes )->bytes :
        padding_length =16 -(len (data )%16 )
        return data +b"\x80"+(b"\x00"*(padding_length -1 ))

    @staticmethod
    def _unpad80 (data :bytes )->bytes :
        if len (data )==0 or len (data )%16 !=0 :
            raise Scp03ResponseProtectionError (
            "R-ENC ciphertext did not decrypt to complete AES blocks."
            )
        marker =data .rfind (b"\x80")
        if marker <0 or any (byte !=0 for byte in data [marker +1 :]):
            raise Scp03ResponseProtectionError ("R-ENC response padding is invalid.")
        return data [:marker ]

    def _validate_security_level (self )->None :
        if (self .sec_level &0x02 )and not (self .sec_level &0x01 ):
            raise Scp03Error ("C-ENC cannot be enabled without C-MAC.")
        if (self .sec_level &0x20 )and not (self .sec_level &0x10 ):
            raise Scp03Error ("R-ENC cannot be enabled without R-MAC.")
        response_capabilities =self .i_parameter &0x60
        if (self .sec_level &0x10 )and response_capabilities ==0 :
            raise Scp03Error (
            "The selected SCP03 key set does not advertise R-MAC support."
            )
        if (self .sec_level &0x20 )and response_capabilities !=0x60 :
            raise Scp03Error (
            "The selected SCP03 key set does not advertise R-ENC support."
            )

    @staticmethod
    def _response_status_is_protected (sw1 :int ,sw2 :int )->bool :
        del sw2
        return sw1 ==0x90 or sw1 in (0x62 ,0x63 )

    def response_requires_rmac (self ,sw1 :int ,sw2 :int )->bool :
        """Return whether the current response must carry an R-MAC."""
        if not self .is_authenticated or not (self .sec_level &0x10 ):
            return False
        if len (self .last_cmd_header )>=2 and self .last_cmd_header [1 ]==0x82 :
            return False
        return self ._response_status_is_protected (int (sw1 ),int (sw2 ))

    def wrap_apdu (self ,apdu :List [int ])->List [int ]:
        """Apply SCP03 C-MAC (and optionally C-ENC) protection to a plain APDU command list (GP Card Spec v2.3.1 §7.2)."""
        try :
            command =list (bytes (apdu ))
        except (TypeError ,ValueError )as exc :
            raise Scp03ApduFormatError (
            "Command APDU must contain byte values in the range 00..FF."
            )from exc
        if not self .is_authenticated :
            return command

        parsed =parse_command_apdu (command )
        command_channel =self .logical_channel_from_cla (parsed .cla )
        if self .authenticated_channel is None :
            raise Scp03Error (
            "Authenticated SCP03 session is not bound to a logical channel."
            )
        if command_channel !=self .authenticated_channel :
            raise Scp03Error (
            f"SCP03 session is bound to logical channel "
            f"{self.authenticated_channel}, but the command targets channel "
            f"{command_channel}. Authenticate separately on that channel."
            )
        if not (self .sec_level &0x01 ):
            return command
        self ._validate_security_level ()
        if self .s_mac is None :
            raise Scp03Error ("SCP03 session MAC key is not derived.")
        if parsed .extended :
            # GPCS §11.1.5 defines GlobalPlatform APDUs with one-byte Lc/Le,
            # and SCP03 Amendment D §6.2.4 authenticates a five-byte header.
            raise Scp03ApduFormatError (
            "Extended-length APDUs cannot be SCP03-wrapped: the applicable "
            "GlobalPlatform wire format requires one-byte Lc and Le. Split "
            "the command using the command-specific chaining mechanism."
            )

        is_external_authenticate =parsed .ins ==0x82
        encrypted_payload =parsed .data
        padded_payload :Optional [bytes ]=None
        if (
            len (parsed .data )>0
            and (self .sec_level &0x02 )
            and not is_external_authenticate
        ):
            padded_payload =self ._pad80 (parsed .data )

        protected_payload_length =(
            len (padded_payload )if padded_payload is not None else len (parsed .data )
        )
        if protected_payload_length +8 >0xFF :
            raise Scp03ApduFormatError (
            "SCP03 wrapping would exceed the one-byte Lc limit; split the "
            "command using the command-specific chaining mechanism."
            )

        encryption_counter :Optional [int ]=None
        if (self .sec_level &0x02 )and not is_external_authenticate :
            encryption_counter =self .ssc if self .ssc >0 else 1
            if padded_payload is not None :
                iv =self ._generate_iv_from_bytes (
                encryption_counter .to_bytes (16 ,"big")
                )
                cipher =Cipher (algorithms .AES (self .s_enc ),modes .CBC (iv ))
                encryptor =cipher .encryptor ()
                encrypted_payload =(
                encryptor .update (padded_payload )+encryptor .finalize ()
                )

        mac_cla ,wire_cla =self ._secure_messaging_cla (parsed .cla )
        protected_lc =len (encrypted_payload )+8
        mac_header =bytes (
        [mac_cla ,parsed .ins ,parsed .p1 ,parsed .p2 ,protected_lc ]
        )
        wire_header =bytes (
        [wire_cla ,parsed .ins ,parsed .p1 ,parsed .p2 ,protected_lc ]
        )

        calculator =cmac .CMAC (algorithms .AES (self .s_mac ))
        calculator .update (self .chaining_value +mac_header +encrypted_payload )
        new_chaining_value =calculator .finalize ()

        final_apdu =wire_header +encrypted_payload +new_chaining_value [:8 ]
        if parsed .case in (2 ,4 ):
            # Le is not included in C-MAC. Preserve its short encoding; GP
            # callers normally use 00 to request all available response data.
            final_apdu +=parsed .raw [-1 :]

        self .chaining_value =new_chaining_value
        self .last_cmd_header =parsed .raw [:4 ]
        self .last_encryption_counter =encryption_counter
        if encryption_counter is not None :
            self .ssc =encryption_counter +1
        elif is_external_authenticate and self .ssc ==0 :
            # EXTERNAL AUTHENTICATE itself is not counted for C-ENC; the
            # first following command uses counter 1.
            self .ssc =1
        return list (final_apdu )

    def unwrap_response (self ,data :bytes ,sw1 :int ,sw2 :int )->bytes :
        """Strip and verify the SCP03 R-MAC from a card response (GP Card Spec v2.3.1 §7.3)."""
        response =bytes (data )
        sw1 =int (sw1 )
        sw2 =int (sw2 )
        if not 0 <=sw1 <=0xFF or not 0 <=sw2 <=0xFF :
            raise Scp03ResponseProtectionError ("Response status bytes are invalid.")
        if not self .is_authenticated :
            return response
        self ._validate_security_level ()

        # SCP03 §6.2.5: EXTERNAL AUTHENTICATE never returns an R-MAC.
        if len (self .last_cmd_header )>=2 and self .last_cmd_header [1 ]==0x82 :
            return response

        protected_status =self ._response_status_is_protected (sw1 ,sw2 )
        if not protected_status :
            # For an error status the specification permits only the SW.  Any
            # unprotected data would otherwise be handed to the caller as if
            # it had integrity protection.
            if (self .sec_level &0x10 )and len (response )>0 :
                self .reset_state ()
                raise Scp03ResponseProtectionError (
                "SCP03 error response contained unprotected data."
                )
            return response

        if not (self .sec_level &0x10 ):
            return response
        if self .s_rmac is None :
            raise Scp03Error ("SCP03 response MAC key is not derived.")
        if len (response )<8 :
            self .reset_state ()
            raise Scp03ResponseProtectionError (
            "SCP03 response is missing its required 8-byte R-MAC."
            )

        protected_payload =response [:-8 ]
        received_rmac =response [-8 :]
        calculator =cmac .CMAC (algorithms .AES (self .s_rmac ))
        calculator .update (
        self .chaining_value
        +protected_payload
        +bytes ([sw1 ,sw2 ])
        )
        expected_rmac =calculator .finalize ()[:8 ]
        if not hmac .compare_digest (received_rmac ,expected_rmac ):
            self .reset_state ()
            raise Scp03ResponseProtectionError ("SCP03 R-MAC verification failed.")

        if not (self .sec_level &0x20 ):
            return protected_payload
        if len (protected_payload )==0 :
            return b""
        if self .last_encryption_counter is None :
            self .reset_state ()
            raise Scp03ResponseProtectionError (
            "R-ENC response has no matching command encryption counter."
            )
        if len (protected_payload )%16 !=0 :
            self .reset_state ()
            raise Scp03ResponseProtectionError (
            "R-ENC ciphertext length is not a multiple of the AES block size."
            )

        iv_input =bytearray (
        self .last_encryption_counter .to_bytes (16 ,"big")
        )
        iv_input [0 ]=0x80
        iv =self ._generate_iv_from_bytes (bytes (iv_input ))
        cipher =Cipher (algorithms .AES (self .s_enc ),modes .CBC (iv ))
        decryptor =cipher .decryptor ()
        padded_plaintext =(
        decryptor .update (protected_payload )+decryptor .finalize ()
        )
        try :
            return self ._unpad80 (padded_plaintext )
        except Scp03ResponseProtectionError :
            self .reset_state ()
            raise

    def encrypt_key_data (self ,key_bytes :bytes )->bytes :
        """Encrypt key data with the DEK session key for use in a PUT KEY payload (GP Card Spec v2.3.1 §11.8)."""
        import binascii 

        target_dek =None 

        dek_names =['dek','k_dek','kdek','key_dek','static_dek']
        for name in dek_names :
            has_attr =False 
            if hasattr (self ,name ):
                has_attr =True 

            if has_attr :
                val =getattr (self ,name )

                is_valid =False 
                if val is not None :
                    is_valid =True 

                if is_valid :
                    target_dek =val 
                    break 

        is_missing =False 
        if target_dek is None :
            is_missing =True 

        if is_missing :
            from SCP03 .config import load_scp03_runtime_parser 
            config =load_scp03_runtime_parser ()

            has_keys_section =False 
            if 'KEYS'in config :
                has_keys_section =True 

            if has_keys_section :
                has_dek_entry =False 
                if 'dek'in config ['KEYS']:
                    has_dek_entry =True 

                if has_dek_entry :
                    target_dek =config ['KEYS']['dek'].strip ()
                    is_missing =False 

        if is_missing :
            raise RuntimeError ("DEK attribute is missing from the active SCP03 SQLite state.")

        is_string =False 
        if isinstance (target_dek ,str ):
            is_string =True 

        if is_string :
            target_dek =binascii .unhexlify (target_dek )

        iv =b'\x00'*16 
        cipher =Cipher (algorithms .AES (target_dek ),modes .CBC (iv ))
        encryptor =cipher .encryptor ()

        encrypted_chunk =encryptor .update (key_bytes )
        encrypted_final =encryptor .finalize ()

        result =bytearray ()
        result .extend (encrypted_chunk )
        result .extend (encrypted_final )

        return bytes (result )
