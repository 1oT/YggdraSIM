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

"""Security logic: PIN management, AKA authentication, and OTA key-update procedures (3GPP TS 31.102)."""
from dataclasses import dataclass
from typing import Optional 
from SCP03 .config import Config 
from SCP03 .core .utils import TlvParser 

try :
    from cryptography .hazmat .primitives .ciphers import Cipher ,algorithms ,modes 
    from cryptography .hazmat .backends import default_backend 
    _AES_AVAILABLE =True 
except ImportError :
    _AES_AVAILABLE =False 


AUTH_TEST_VECTOR ={
"RAND":"23553CBE9637A89D218AE64DAE47BF35",
"Ki":"465B5CE8B199B49FAA5F0A2EE238A6BC",
"OP":"CDC202D5123E20F62B6D676AC72CB318",
"OPc":"CD63CB71954A9F4E48A5994E37A02BAF",
"SQN":"000000000001",
"AMF":"8000",
"AUTN":"AA689C6483718000F48B60145BEACF8E",
"RES":"A54211D5E3BA50BF",
"CK":"B40BA9A3C58B2A05BBF0D987B21BF8CB",
"IK":"F769BCD751044604127672711C6D3441",
"Kc":"EAE4BE823AF9A08B",
"USIM_AUTH_APDU":"00880081221023553CBE9637A89D218AE64DAE47BF3510AA689C6483718000F48B60145BEACF8E00",
"USIM_AUTH_RESPONSE":"DB08A54211D5E3BA50BF10B40BA9A3C58B2A05BBF0D987B21BF8CB10F769BCD751044604127672711C6D344108EAE4BE823AF9A08B",
}


@dataclass(frozen=True)
class OfflineAuthVector:
    rand :str
    ki :str
    op :str
    opc :str
    res :str
    ck :str
    ik :str
    kc :str


@dataclass(frozen=True)
class OfflineUsimAuthExchange:
    rand :str
    autn :str
    amf :str
    current_sqn :str
    recovered_sqn :str
    next_sqn :str
    command_payload :str
    command_apdu :str
    response_payload :str
    response_apdu :str
    status_word :str
    result :str
    res :str
    ck :str
    ik :str
    kc :str
    auts :str =""


def _load_milenage_vectors_helper ():
    try :
        from SIMCARD .auth import milenage_vectors 
    except Exception as error :
        raise RuntimeError ("SIMCARD Milenage helpers unavailable") from error 
    return milenage_vectors 


def _load_usim_auth_helpers ():
    try :
        from SIMCARD .auth import build_milenage_autn ,build_milenage_auts ,milenage_vectors 
    except Exception as error :
        raise RuntimeError ("SIMCARD auth helpers unavailable") from error 
    return milenage_vectors ,build_milenage_autn ,build_milenage_auts 


class SecurityController :

    def __init__ (self ,transport ,fs_ctrl =None ):
        self .tp =transport 
        self .fs =fs_ctrl 

    def _pad_pin (self ,pin_str :str )->str :
        """Pads numeric PIN string to 8 bytes with 0xFF (ISO 7816-4)."""
        pin_bytes =str (pin_str ).encode ('ascii')
        if len (pin_bytes )>8 :return pin_bytes [:8 ].hex ().upper ()
        padding =b'\xFF'*(8 -len (pin_bytes ))
        return (pin_bytes +padding ).hex ().upper ()

    def verify_pin (self ,pin_ref :str ,pin_value :str ):
        """Send VERIFY PIN (ISO 7816-4 §7.5.6) for *pin_ref* and *pin_value*."""
        try :
            ref_byte =int (str (pin_ref ),16 )if len (str (pin_ref ))>1 else int (str (pin_ref ))
            hex_data =self ._pad_pin (pin_value )
            cmd =f"002000{ref_byte:02X}08{hex_data}"
            print (f"{Config.Colors.CYAN}[*] Verifying PIN (Ref: {ref_byte:02X})...{Config.Colors.ENDC}")
            _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )

            if sw1 ==0x90 :print (f"{Config.Colors.GREEN}[+] PIN Verified.{Config.Colors.ENDC}")
            elif sw1 ==0x63 :print (f"{Config.Colors.FAIL}[-] Failed. {sw2 & 0x0F} attempts remaining.{Config.Colors.ENDC}")
            elif sw1 ==0x69 and sw2 ==0x83 :print (f"{Config.Colors.FAIL}[-] PIN Blocked.{Config.Colors.ENDC}")
            elif sw1 ==0x69 and sw2 ==0x84 :print (f"{Config.Colors.FAIL}[-] PIN Blocked (Ref Invalidated).{Config.Colors.ENDC}")
            else :print (f"{Config.Colors.FAIL}[-] Error: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e :print (f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")


    def change_pin (self ,pin_ref :str ,old_pin :str ,new_pin :str ):
        """Send CHANGE REFERENCE DATA (ISO 7816-4 §7.5.7) for *pin_ref*."""
        try :
            ref_byte =int (str (pin_ref ),16 )if len (str (pin_ref ))>1 else int (str (pin_ref ))
            payload =self ._pad_pin (old_pin )+self ._pad_pin (new_pin )
            cmd =f"002400{ref_byte:02X}10{payload}"
            print (f"{Config.Colors.CYAN}[*] Changing PIN (Ref: {ref_byte:02X})...{Config.Colors.ENDC}")
            _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )
            if sw1 ==0x90 :print (f"{Config.Colors.GREEN}[+] PIN Changed.{Config.Colors.ENDC}")
            elif sw1 ==0x63 :print (f"{Config.Colors.FAIL}[-] Failed. {sw2 & 0x0F} attempts remaining.{Config.Colors.ENDC}")
            else :print (f"{Config.Colors.FAIL}[-] Error: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e :print (f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    def disable_pin (self ,pin_ref :str ,pin_value :str ):
        """Send DISABLE VERIFICATION REQUIREMENT (ISO 7816-4 §7.5.9) for *pin_ref*."""
        try :
            ref_byte =int (str (pin_ref ),16 )if len (str (pin_ref ))>1 else int (str (pin_ref ))
            hex_data =self ._pad_pin (pin_value )
            cmd =f"002600{ref_byte:02X}08{hex_data}"
            _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )
            if sw1 ==0x90 :print (f"{Config.Colors.GREEN}[+] PIN Disabled.{Config.Colors.ENDC}")
            else :print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e :print (f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    def enable_pin (self ,pin_ref :str ,pin_value :str ):
        """Send ENABLE VERIFICATION REQUIREMENT (ISO 7816-4 §7.5.9) for *pin_ref*."""
        try :
            ref_byte =int (str (pin_ref ),16 )if len (str (pin_ref ))>1 else int (str (pin_ref ))
            hex_data =self ._pad_pin (pin_value )
            cmd =f"002800{ref_byte:02X}08{hex_data}"
            _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )
            if sw1 ==0x90 :print (f"{Config.Colors.GREEN}[+] PIN Enabled.{Config.Colors.ENDC}")
            else :print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e :print (f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    def unblock_pin (self ,pin_ref :str ,puk :str ,new_pin :str ):
        """Send RESET RETRY COUNTER / UNBLOCK PIN (ISO 7816-4 §7.5.10) using the PUK."""
        try :
            ref_byte =int (str (pin_ref ),16 )if len (str (pin_ref ))>1 else int (str (pin_ref ))
            payload =self ._pad_pin (puk )+self ._pad_pin (new_pin )
            cmd =f"002C00{ref_byte:02X}10{payload}"
            print (f"{Config.Colors.CYAN}[*] Unblocking PIN (Ref: {ref_byte:02X})...{Config.Colors.ENDC}")
            _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )
            if sw1 ==0x90 :print (f"{Config.Colors.GREEN}[+] PIN Unblocked.{Config.Colors.ENDC}")
            else :print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e :print (f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    @staticmethod 
    def derive_opc (ki_hex :str ,op_hex :str )->str :
        """
        Derive OPc from Ki and OP per 3GPP TS 35.206:
        OPc = AES-128(Ki, OP) XOR OP.
        ki_hex, op_hex: 32 hex chars (16 bytes). Returns 32 hex chars OPc.
        """
        if not _AES_AVAILABLE :
            raise RuntimeError ("cryptography required for OPc derivation")
        ki_hex =ki_hex .replace (" ","").upper ()
        op_hex =op_hex .replace (" ","").upper ()
        if len (ki_hex )!=32 or len (op_hex )!=32 :
            raise ValueError ("Ki and OP must be 32 hex chars (16 bytes) each")
        key =bytes .fromhex (ki_hex )
        plain =bytes .fromhex (op_hex )
        cipher =Cipher (algorithms .AES (key ),modes .ECB (),backend =default_backend ())
        encryptor =cipher .encryptor ()
        enc =encryptor .update (plain )+encryptor .finalize ()
        opc =bytes (a ^b for a ,b in zip (enc ,plain ))
        return opc .hex ().upper ()

    @staticmethod
    def _normalize_hex_input (value :str ,expected_chars :int ,label :str )->str :
        text =str (value or "").replace (" ","").replace (":","").replace ("-","").upper ()
        if len (text )!=expected_chars :
            raise ValueError (f"{label} must be {expected_chars} hex chars")
        return text 

    @staticmethod
    def _normalize_even_hex (value :str ,label :str )->str :
        text =str (value or "").replace (" ","").replace (":","").replace ("-","").upper ()
        if len (text )==0 :
            raise ValueError (f"{label} must not be empty")
        if len (text )%2 !=0 :
            raise ValueError (f"{label} must contain an even number of hex chars")
        return text 

    @staticmethod
    def _resolve_offline_auth_material (
        ki_hex :str ,
        *,
        op_hex :str ="",
        opc_hex :str ="",
    )->tuple [str ,str ,str ]:
        normalized_ki =SecurityController ._normalize_hex_input (ki_hex ,32 ,"Ki")
        normalized_op =str (op_hex or "").replace (" ","").replace (":","").replace ("-","").upper ()
        normalized_opc =str (opc_hex or "").replace (" ","").replace (":","").replace ("-","").upper ()
        if len (normalized_opc )==0 :
            normalized_op =SecurityController ._normalize_hex_input (normalized_op ,32 ,"OP")
            normalized_opc =SecurityController .derive_opc (normalized_ki ,normalized_op )
        else :
            normalized_opc =SecurityController ._normalize_hex_input (normalized_opc ,32 ,"OPc")
        return normalized_ki ,normalized_op ,normalized_opc 

    @staticmethod
    def derive_gsm_kc (ck_hex :str ,ik_hex :str )->str :
        """Derive the GSM Kc from Milenage CK and IK (3GPP TS 33.102 Annex B.4)."""
        normalized_ck =SecurityController ._normalize_hex_input (ck_hex ,32 ,"CK")
        normalized_ik =SecurityController ._normalize_hex_input (ik_hex ,32 ,"IK")
        ck =bytes .fromhex (normalized_ck )
        ik =bytes .fromhex (normalized_ik )
        kc =bytes (
        left ^right ^third ^fourth
        for left ,right ,third ,fourth in zip (ck [:8 ],ck [8 :],ik [:8 ],ik [8 :])
        )
        return kc .hex ().upper ()

    @staticmethod
    def compute_offline_milenage_vector (
        rand_hex :str ,
        ki_hex :str ,
        *,
        op_hex :str ="",
        opc_hex :str ="",
    )->OfflineAuthVector :
        """Compute a full Milenage authentication vector offline from RAND, Ki, and OP/OPc."""
        normalized_rand =SecurityController ._normalize_hex_input (rand_hex ,32 ,"RAND")
        normalized_ki ,normalized_op ,normalized_opc =SecurityController ._resolve_offline_auth_material (
        ki_hex ,
        op_hex =op_hex ,
        opc_hex =opc_hex ,
        )
        milenage_vectors =_load_milenage_vectors_helper ()
        vectors =milenage_vectors (
        bytes .fromhex (normalized_ki ),
        bytes .fromhex (normalized_opc ),
        bytes .fromhex (normalized_rand ),
        b"\x00"*6 ,
        b"\x00\x00",
        )
        ck_value =vectors .ck .hex ().upper ()
        ik_value =vectors .ik .hex ().upper ()
        return OfflineAuthVector (
        rand =normalized_rand ,
        ki =normalized_ki ,
        op =normalized_op ,
        opc =normalized_opc ,
        res =vectors .res .hex ().upper (),
        ck =ck_value ,
        ik =ik_value ,
        kc =SecurityController .derive_gsm_kc (ck_value ,ik_value ),
        )

    @staticmethod
    def build_usim_auth_payload (rand_hex :str ,autn_hex :str )->str :
        normalized_rand =SecurityController ._normalize_hex_input (rand_hex ,32 ,"RAND")
        normalized_autn =SecurityController ._normalize_hex_input (autn_hex ,32 ,"AUTN")
        return f"10{normalized_rand}10{normalized_autn}"

    @staticmethod
    def build_usim_auth_apdu (rand_hex :str ,autn_hex :str ,cla_hex :str ="00")->str :
        normalized_cla =SecurityController ._normalize_hex_input (cla_hex ,2 ,"CLA")
        payload =SecurityController .build_usim_auth_payload (rand_hex ,autn_hex )
        payload_len =len (payload )//2
        return f"{normalized_cla}880081{payload_len:02X}{payload}00"

    @staticmethod
    def build_usim_auth_response_payload (
        res_hex :str ,
        ck_hex :str ,
        ik_hex :str ,
        kc_hex :str ,
    )->str :
        """Build the USIM AUTHENTICATE 3G response TLV payload (ETSI TS 102 221 §11.1.2)."""
        normalized_res =SecurityController ._normalize_even_hex (res_hex ,"RES")
        normalized_ck =SecurityController ._normalize_even_hex (ck_hex ,"CK")
        normalized_ik =SecurityController ._normalize_even_hex (ik_hex ,"IK")
        normalized_kc =SecurityController ._normalize_even_hex (kc_hex ,"Kc")
        return (
        "DB"
        +f"{len (normalized_res )//2:02X}{normalized_res}"
        +f"{len (normalized_ck )//2:02X}{normalized_ck}"
        +f"{len (normalized_ik )//2:02X}{normalized_ik}"
        +f"{len (normalized_kc )//2:02X}{normalized_kc}"
        )

    @staticmethod
    def build_usim_auth_response_apdu (
        res_hex :str ,
        ck_hex :str ,
        ik_hex :str ,
        kc_hex :str ,
        status_word :str ="9000",
    )->str :
        """Construct the full AUTHENTICATE command APDU with the USIM response payload."""
        normalized_sw =SecurityController ._normalize_hex_input (status_word ,4 ,"Status word")
        payload =SecurityController .build_usim_auth_response_payload (res_hex ,ck_hex ,ik_hex ,kc_hex )
        return payload +normalized_sw 

    @staticmethod
    def _parse_usim_auth_command_payload (payload :bytes )->tuple [str ,str ]:
        normalized_payload =bytes (payload or b"")
        if len (normalized_payload )==32 :
            rand =normalized_payload [:16 ].hex ().upper ()
            autn =normalized_payload [16 :32 ].hex ().upper ()
            return rand ,autn 
        if len (normalized_payload )!=34 :
            raise ValueError ("USIM auth payload must be 32 or 34 bytes")
        if normalized_payload [0 ]!=0x10 :
            raise ValueError ("USIM auth payload missing RAND length tag")
        if normalized_payload [17 ]!=0x10 :
            raise ValueError ("USIM auth payload missing AUTN length tag")
        rand =normalized_payload [1 :17 ].hex ().upper ()
        autn =normalized_payload [18 :34 ].hex ().upper ()
        return rand ,autn 

    @staticmethod
    def _parse_usim_auth_apdu (command_apdu_hex :str )->tuple [str ,str ,str ,str ]:
        normalized_apdu =SecurityController ._normalize_even_hex (command_apdu_hex ,"Command APDU")
        raw_apdu =bytes .fromhex (normalized_apdu )
        if len (raw_apdu )<5 :
            raise ValueError ("Command APDU must be at least 5 bytes")
        ins =raw_apdu [1 ]
        p2 =raw_apdu [3 ]
        if ins !=0x88 or p2 !=0x81 :
            raise ValueError ("Command APDU must be INTERNAL AUTHENTICATE with P2=81")
        lc =raw_apdu [4 ]
        payload_start =5 
        payload_end =payload_start +lc 
        if len (raw_apdu )not in (payload_end ,payload_end +1 ):
            raise ValueError ("Command APDU length does not match Lc")
        payload =raw_apdu [payload_start :payload_end ]
        rand_hex ,autn_hex =SecurityController ._parse_usim_auth_command_payload (payload )
        return normalized_apdu ,payload .hex ().upper (),rand_hex ,autn_hex 

    @staticmethod
    def validate_offline_usim_auth_apdu (
        command_apdu_hex :str ,
        ki_hex :str ,
        *,
        current_sqn_hex :str ="",
        op_hex :str ="",
        opc_hex :str ="",
    )->OfflineUsimAuthExchange :
        """Verify a captured AUTHENTICATE command APDU against offline Milenage vectors."""
        normalized_ki ,normalized_op ,normalized_opc =SecurityController ._resolve_offline_auth_material (
        ki_hex ,
        op_hex =op_hex ,
        opc_hex =opc_hex ,
        )
        normalized_command_apdu ,command_payload ,rand_hex ,autn_hex =SecurityController ._parse_usim_auth_apdu (
        command_apdu_hex
        )
        normalized_current_sqn =str (current_sqn_hex or "").strip ()
        if len (normalized_current_sqn )>0 :
            normalized_current_sqn =SecurityController ._normalize_hex_input (
            normalized_current_sqn ,
            12 ,
            "Current SQN",
            )
        milenage_vectors ,_build_milenage_autn ,build_milenage_auts =_load_usim_auth_helpers ()
        del _build_milenage_autn
        rand =bytes .fromhex (rand_hex )
        autn =bytes .fromhex (autn_hex )
        amf =autn [6 :8 ]
        concealed_sqn =autn [:6 ]
        initial_vectors =milenage_vectors (
        bytes .fromhex (normalized_ki ),
        bytes .fromhex (normalized_opc ),
        rand ,
        b"\x00"*6 ,
        amf ,
        )
        recovered_sqn_bytes =bytes (
        left ^right
        for left ,right in zip (concealed_sqn ,initial_vectors .ak )
        )
        recovered_sqn =recovered_sqn_bytes .hex ().upper ()
        vectors =milenage_vectors (
        bytes .fromhex (normalized_ki ),
        bytes .fromhex (normalized_opc ),
        rand ,
        recovered_sqn_bytes ,
        amf ,
        )
        res_hex =vectors .res .hex ().upper ()
        ck_hex =vectors .ck .hex ().upper ()
        ik_hex =vectors .ik .hex ().upper ()
        kc_hex =vectors .kc .hex ().upper ()
        if vectors .mac_a !=autn [8 :16 ]:
            return OfflineUsimAuthExchange (
            rand =rand_hex ,
            autn =autn_hex ,
            amf =amf .hex ().upper (),
            current_sqn =normalized_current_sqn ,
            recovered_sqn =recovered_sqn ,
            next_sqn =normalized_current_sqn or recovered_sqn ,
            command_payload =command_payload ,
            command_apdu =normalized_command_apdu ,
            response_payload ="",
            response_apdu ="9862",
            status_word ="9862",
            result ="mac_failure",
            res =res_hex ,
            ck =ck_hex ,
            ik =ik_hex ,
            kc =kc_hex ,
            auts ="",
            )
        effective_current_sqn =normalized_current_sqn or recovered_sqn 
        effective_current_sqn_value =int (effective_current_sqn ,16 )
        recovered_sqn_value =int (recovered_sqn ,16 )
        if recovered_sqn_value <effective_current_sqn_value :
            auts =build_milenage_auts (
            bytes .fromhex (normalized_ki ),
            bytes .fromhex (normalized_opc ),
            rand ,
            bytes .fromhex (effective_current_sqn ),
            ).hex ().upper ()
            response_payload ="DC0E"+auts 
            return OfflineUsimAuthExchange (
            rand =rand_hex ,
            autn =autn_hex ,
            amf =amf .hex ().upper (),
            current_sqn =effective_current_sqn ,
            recovered_sqn =recovered_sqn ,
            next_sqn =effective_current_sqn ,
            command_payload =command_payload ,
            command_apdu =normalized_command_apdu ,
            response_payload =response_payload ,
            response_apdu =response_payload +"9000",
            status_word ="9000",
            result ="sync_failure",
            res =res_hex ,
            ck =ck_hex ,
            ik =ik_hex ,
            kc =kc_hex ,
            auts =auts ,
            )
        next_sqn =f"{max (effective_current_sqn_value ,recovered_sqn_value )+1:012X}"
        response_payload =SecurityController .build_usim_auth_response_payload (
        res_hex ,
        ck_hex ,
        ik_hex ,
        kc_hex ,
        )
        return OfflineUsimAuthExchange (
        rand =rand_hex ,
        autn =autn_hex ,
        amf =amf .hex ().upper (),
        current_sqn =effective_current_sqn ,
        recovered_sqn =recovered_sqn ,
        next_sqn =next_sqn ,
        command_payload =command_payload ,
        command_apdu =normalized_command_apdu ,
        response_payload =response_payload ,
        response_apdu =response_payload +"9000",
        status_word ="9000",
        result ="success",
        res =res_hex ,
        ck =ck_hex ,
        ik =ik_hex ,
        kc =kc_hex ,
        auts ="",
        )

    @staticmethod
    def compute_offline_usim_auth_exchange (
        rand_hex :str ,
        ki_hex :str ,
        sqn_hex :str ,
        amf_hex :str ,
        *,
        op_hex :str ="",
        opc_hex :str ="",
        current_sqn_hex :str ="",
    )->OfflineUsimAuthExchange :
        """Run a complete offline USIM AKA exchange from RAND/Ki/SQN/AMF and return the full exchange record."""
        normalized_ki ,normalized_op ,normalized_opc =SecurityController ._resolve_offline_auth_material (
        ki_hex ,
        op_hex =op_hex ,
        opc_hex =opc_hex ,
        )
        normalized_rand =SecurityController ._normalize_hex_input (rand_hex ,32 ,"RAND")
        normalized_sqn =SecurityController ._normalize_hex_input (sqn_hex ,12 ,"SQN")
        normalized_amf =SecurityController ._normalize_hex_input (amf_hex ,4 ,"AMF")
        _milenage_vectors ,build_milenage_autn ,_build_milenage_auts =_load_usim_auth_helpers ()
        del _milenage_vectors
        del _build_milenage_auts
        autn =build_milenage_autn (
        bytes .fromhex (normalized_ki ),
        bytes .fromhex (normalized_opc ),
        bytes .fromhex (normalized_rand ),
        bytes .fromhex (normalized_sqn ),
        bytes .fromhex (normalized_amf ),
        ).hex ().upper ()
        command_apdu =SecurityController .build_usim_auth_apdu (normalized_rand ,autn )
        return SecurityController .validate_offline_usim_auth_apdu (
        command_apdu ,
        normalized_ki ,
        current_sqn_hex =current_sqn_hex or normalized_sqn ,
        op_hex =normalized_op ,
        opc_hex =normalized_opc ,
        )

    @staticmethod
    def build_auth_test_vector_report ()->OfflineAuthVector :
        return SecurityController .compute_offline_milenage_vector (
        AUTH_TEST_VECTOR ["RAND"],
        AUTH_TEST_VECTOR ["Ki"],
        op_hex =AUTH_TEST_VECTOR ["OP"],
        )

    @staticmethod
    def build_auth_test_usim_exchange ()->OfflineUsimAuthExchange :
        """Run a fixed test-vector USIM AKA exchange for self-test purposes."""
        return SecurityController .compute_offline_usim_auth_exchange (
        AUTH_TEST_VECTOR ["RAND"],
        AUTH_TEST_VECTOR ["Ki"],
        AUTH_TEST_VECTOR ["SQN"],
        AUTH_TEST_VECTOR ["AMF"],
        op_hex =AUTH_TEST_VECTOR ["OP"],
        current_sqn_hex =AUTH_TEST_VECTOR ["SQN"],
        )

    def run_auth_test_vector (self ):
        """
        Run offline authentication validation using 3GPP TS 35.207 style values.
        """
        print (f"{Config.Colors.HEADER}=== Milenage Test Vector (3GPP TS 35.207) ==={Config.Colors.ENDC}")
        print (f"  RAND: {AUTH_TEST_VECTOR['RAND']}")
        print (f"  Ki:   {AUTH_TEST_VECTOR['Ki']}")
        print (f"  OP:   {AUTH_TEST_VECTOR['OP']}")
        try :
            report =self .build_auth_test_vector_report ()
            print (f"  OPc (derived): {report.opc}")
            print (f"  OPc (expected): {AUTH_TEST_VECTOR['OPc']}")
            match ="OK"if report .opc ==AUTH_TEST_VECTOR ["OPc"]else "MISMATCH"
            print (f"  OPc check: {Config.Colors.GREEN if match == 'OK' else Config.Colors.FAIL}{match}{Config.Colors.ENDC}")
            print (f"  RES (derived): {report.res}")
            print (f"  RES (expected): {AUTH_TEST_VECTOR['RES']}")
            match ="OK"if report .res ==AUTH_TEST_VECTOR ["RES"]else "MISMATCH"
            print (f"  RES check: {Config.Colors.GREEN if match == 'OK' else Config.Colors.FAIL}{match}{Config.Colors.ENDC}")
            print (f"  CK  (derived): {report.ck}")
            print (f"  CK  (expected): {AUTH_TEST_VECTOR['CK']}")
            match ="OK"if report .ck ==AUTH_TEST_VECTOR ["CK"]else "MISMATCH"
            print (f"  CK  check: {Config.Colors.GREEN if match == 'OK' else Config.Colors.FAIL}{match}{Config.Colors.ENDC}")
            print (f"  IK  (derived): {report.ik}")
            print (f"  IK  (expected): {AUTH_TEST_VECTOR['IK']}")
            match ="OK"if report .ik ==AUTH_TEST_VECTOR ["IK"]else "MISMATCH"
            print (f"  IK  check: {Config.Colors.GREEN if match == 'OK' else Config.Colors.FAIL}{match}{Config.Colors.ENDC}")
            print (f"  Kc  (derived): {report.kc}")
            print (f"  Kc  (expected): {AUTH_TEST_VECTOR['Kc']}")
            match ="OK"if report .kc ==AUTH_TEST_VECTOR ["Kc"]else "MISMATCH"
            print (f"  Kc  check: {Config.Colors.GREEN if match == 'OK' else Config.Colors.FAIL}{match}{Config.Colors.ENDC}")
            exchange =self .build_auth_test_usim_exchange ()
            print (f"  SQN:  {AUTH_TEST_VECTOR['SQN']}")
            print (f"  AMF:  {AUTH_TEST_VECTOR['AMF']}")
            print (f"  AUTN (derived): {exchange.autn}")
            print (f"  AUTN (expected): {AUTH_TEST_VECTOR['AUTN']}")
            match ="OK"if exchange .autn ==AUTH_TEST_VECTOR ["AUTN"]else "MISMATCH"
            print (f"  AUTN check: {Config.Colors.GREEN if match == 'OK' else Config.Colors.FAIL}{match}{Config.Colors.ENDC}")
            print (f"  00 88 APDU (derived): {exchange.command_apdu}")
            print (f"  00 88 APDU (expected): {AUTH_TEST_VECTOR['USIM_AUTH_APDU']}")
            match ="OK"if exchange .command_apdu ==AUTH_TEST_VECTOR ["USIM_AUTH_APDU"]else "MISMATCH"
            print (f"  APDU check: {Config.Colors.GREEN if match == 'OK' else Config.Colors.FAIL}{match}{Config.Colors.ENDC}")
            print (f"  Response payload (derived): {exchange.response_payload}")
            print (f"  Response payload (expected): {AUTH_TEST_VECTOR['USIM_AUTH_RESPONSE']}")
            match ="OK"if exchange .response_payload ==AUTH_TEST_VECTOR ["USIM_AUTH_RESPONSE"]else "MISMATCH"
            print (f"  Response check: {Config.Colors.GREEN if match == 'OK' else Config.Colors.FAIL}{match}{Config.Colors.ENDC}")
            print (f"  Response APDU (derived): {exchange.response_apdu}")
            print (f"{Config.Colors.CYAN}[*] Offline vector check complete. Use RUN-AUTH for live APDU execution.{Config.Colors.ENDC}")
        except Exception as e :
            print (f"  Offline vector check: {Config.Colors.FAIL}{e}{Config.Colors.ENDC}")

    def _smart_select_app (self ,target_type :str )->bool :

        self .tp .transmit ("00A40004023F00",silent =True )
        data ,sw1 ,sw2 =self .tp .transmit ("00A40004022F00",silent =True )
        if sw1 !=0x90 and sw1 !=0x61 :return False 


        found_aid =None 
        for r in range (1 ,30 ):
            cmd =f"00B2{r:02X}0400"
            data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
            if sw1 ==0x6C :
                data ,sw1 ,sw2 =self .tp .transmit (f"00B2{r:02X}04{sw2:02X}",silent =True )
            if sw1 !=0x90 :break 

            clean_data =data .rstrip (b'\xff')
            if not clean_data :continue 

            try :
                rec =TlvParser .parse (clean_data )
                if 0x61 in rec :
                    inner_data =rec [0x61 ]
                    inner =TlvParser .parse (inner_data )if isinstance (inner_data ,bytes )else inner_data 

                    aid =inner .get (0x4F ,b'').hex ().upper ()
                    label =inner .get (0x50 ,b'').decode ('ascii','ignore')if inner .get (0x50 )else "Unknown"

                    is_match =False 
                    if target_type =="USIM"and aid .startswith ("A000000087")and "1002"in aid :is_match =True 
                    elif target_type =="ISIM"and aid .startswith ("A000000087")and "1004"in aid :is_match =True 
                    elif target_type =="GSM"and (aid .startswith ("A000000009")or "GSM"in label ):is_match =True 

                    if is_match :
                        print (f"{Config.Colors.CYAN}[*] Found {target_type} App: {label} ({aid}){Config.Colors.ENDC}")
                        found_aid =aid 
                        break 
            except Exception :continue 


        if found_aid :
             if self .fs :
                 print (f"{Config.Colors.CYAN}[*] Auto-selecting AID...{Config.Colors.ENDC}")

                 return self .fs .select (found_aid ,silent =True )
             else :
                 _ ,sw1 ,sw2 =self .tp .transmit (f"00A40400{len(found_aid)//2:02X}{found_aid}")
                 return (sw1 ==0x90 or sw1 ==0x61 )
        return False 

    def run_auth (self ,rand :str ,autn :Optional [str ]=None ,app_context :str ="USIM"):
        """Send the AUTHENTICATE command with the given RAND/AUTN and print the decoded response."""
        try :
            rand_hex =rand .replace (" ","").upper ()
            if len (rand_hex )!=32 :print (f"{Config.Colors.FAIL}[!] RAND must be 32 hex chars.{Config.Colors.ENDC}");return 

            if autn :
                autn_hex =autn .replace (" ","").upper ()
                if len (autn_hex )!=32 :print (f"{Config.Colors.FAIL}[!] AUTN must be 32 hex chars.{Config.Colors.ENDC}");return 
                payload =f"10{rand_hex}10{autn_hex}"
                cmd =f"00880081{len(payload)//2:02X}{payload}00"
                msg =app_context 
            else :
                cmd =f"0088008010{rand_hex}00"
                msg ="GSM"

            print (f"{Config.Colors.CYAN}[*] Running {msg} Authentication...{Config.Colors.ENDC}")
            data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )


            if sw1 ==0x69 and sw2 ==0x85 :
                if self ._smart_select_app (msg ):

                    print (f"{Config.Colors.CYAN}[*] Authenticating...{Config.Colors.ENDC}")
                    data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )
                else :
                    print (f"{Config.Colors.FAIL}[-] No {msg} Application found.{Config.Colors.ENDC}")
                    print (f"{Config.Colors.FAIL}[-] Auth Failed: 6985{Config.Colors.ENDC}")
                    return 


            if sw1 ==0x90 or sw1 ==0x61 :
                self ._parse_auth_response (data )
            elif sw1 ==0x98 and sw2 ==0x62 :
                print (f"{Config.Colors.FAIL}[-] Auth Error: MAC verification failed (Key Mismatch?){Config.Colors.ENDC}")
            elif sw1 ==0xDC :
                print (f"{Config.Colors.WARNING}[!] Sync Failure (AUTS returned){Config.Colors.ENDC}")
            else :
                print (f"{Config.Colors.FAIL}[-] Auth Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    def _parse_auth_response (self ,data :bytes ):
        if not data :return 
        if data [0 ]==0xDC :
            print (f"{Config.Colors.WARNING}[!] Synchronization Failure (AUTS returned){Config.Colors.ENDC}")
            if len (data )>2 :print (f"    AUTS: {data[2:].hex().upper()}")
            return 

        if data [0 ]==0xDB :
            print (f"{Config.Colors.GREEN}[+] Authentication Successful{Config.Colors.ENDC}")
            idx =1 
            if idx <len (data )and data [idx ]>0x80 :idx +=1 
            elif idx <len (data ):idx +=1 

            try :

                if idx <len (data ):
                    res_len =data [idx ];idx +=1 
                    print (f"    RES : {Config.Colors.GREEN}{data[idx:idx+res_len].hex().upper()}{Config.Colors.ENDC}")
                    idx +=res_len 

                if idx <len (data ):
                    ck_len =data [idx ];idx +=1 
                    print (f"    CK  : {Config.Colors.GREEN}{data[idx:idx+ck_len].hex().upper()}{Config.Colors.ENDC}")
                    idx +=ck_len 

                if idx <len (data ):
                    ik_len =data [idx ];idx +=1 
                    print (f"    IK  : {Config.Colors.GREEN}{data[idx:idx+ik_len].hex().upper()}{Config.Colors.ENDC}")
                    idx +=ik_len 

                if idx <len (data ):
                    kc_len =data [idx ];idx +=1 
                    print (f"    Kc  : {Config.Colors.GREEN}{data[idx:idx+kc_len].hex().upper()}{Config.Colors.ENDC}")
            except Exception :
                print (f"{Config.Colors.WARNING}[!] Output truncated{Config.Colors.ENDC}")

        elif len (data )>=12 :
             print (f"    SRES: {Config.Colors.GREEN}{data[:4].hex().upper()}{Config.Colors.ENDC}")
             print (f"    Kc  : {Config.Colors.GREEN}{data[4:12].hex().upper()}{Config.Colors.ENDC}")