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

"""GlobalPlatform card administration: INSTALL, LOAD, DELETE, PUT KEY, and status commands (GP Card Spec v2.3.1)."""
import os 
import math 
from typing import Optional ,List ,Dict ,Any ,Tuple 

from SCP03 .config import Config ,enforce_demo_key_policy 
from SCP03 .core .utils import HexUtils ,TlvParser 
from SCP03 .core .decoders import AdvancedDecoders 
from SCP03 .core .cap import CapFileParser 
from SCP03 .crypto .session import Scp03Session 
from SCP03 .crypto .scp02_session import Scp02SessionAdapter 
from SCP03 .logic .sgp22 import Sgp22Manager 
from yggdrasim_common .card_backend import is_simulated_card_backend
from cryptography .hazmat .primitives .ciphers import algorithms 
from cryptography .hazmat .primitives import cmac 

class GlobalPlatformManager :
    MAX_GET_STATUS_PAGES =256

    def __init__ (self ,transport ,config_keys ):
        self .tp =transport 
        self .raw_keys =config_keys 
        self .scp03_keys ={
        'kenc':HexUtils .to_bytes (config_keys .get ('scp03_kenc',Config .DEFAULT_KEYS ['scp03_kenc'])),
        'kmac':HexUtils .to_bytes (config_keys .get ('scp03_kmac',Config .DEFAULT_KEYS ['scp03_kmac'])),
        'dek':HexUtils .to_bytes (config_keys .get ('scp03_dek',Config .DEFAULT_KEYS ['scp03_dek']))
        }
        self .scp02_keys ={
        'enc':HexUtils .to_bytes (config_keys .get ('scp02_enc',Config .DEFAULT_KEYS ['scp02_enc'])),
        'mac':HexUtils .to_bytes (config_keys .get ('scp02_mac',Config .DEFAULT_KEYS ['scp02_mac'])),
        'dek':HexUtils .to_bytes (config_keys .get ('scp02_dek',Config .DEFAULT_KEYS ['scp02_dek']))
        }
        self .target_aid =HexUtils .to_bytes (config_keys .get ('aid',Config .DEFAULT_KEYS ['aid']))
        self .scp03_kvn =int (config_keys .get ('scp03_kvn',Config .DEFAULT_KEYS ['scp03_kvn']),16 )
        self .scp02_kvn =int (config_keys .get ('scp02_kvn',Config .DEFAULT_KEYS ['scp02_kvn']),16 )
        self .active_scp_protocol ="SCP03"

        backend_label ="sim"if is_simulated_card_backend ()else "reader"
        # ``enforce_demo_key_policy`` used to stderr-write synchronously,
        # which got wiped by the shell's screen-clear redraw. It now
        # returns the banner text (or None) so the caller decides when
        # to surface it; the dispatcher flushes after the banner is drawn.
        self .pending_demo_keys_warning =enforce_demo_key_policy (
        config_keys ,backend_label =backend_label ,
        )

        self .sgp22 =Sgp22Manager (transport )

    def get_active_protocol_name (self )->str :
        return self .active_scp_protocol 

    def get_active_kvn_hex (self )->str :
        if self .active_scp_protocol =="SCP02":
            return f"{self.scp02_kvn:02X}"
        return f"{self.scp03_kvn:02X}"

    @staticmethod
    def _encode_apdu_lc (data_len :int )->str :
        if data_len <=0xFF :
            return f"{data_len:02X}"
        if data_len <=0xFFFF :
            return f"00{data_len:04X}"
        raise ValueError ("APDU data field exceeds extended length capability.")

    @staticmethod
    def _build_case3_apdu (cla :int ,ins :int ,p1 :int ,p2 :int ,data :bytes )->str :
        lc_hex =GlobalPlatformManager ._encode_apdu_lc (len (data ))
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc_hex}{data.hex()}"

    def get_config_key_fields_for_protocol (self ,protocol_name :str =None )->Tuple [str ,str ,str ,str ]:
        """Return (ENC-key-hex, MAC-key-hex, DEK-key-hex, KVN-hex) from the keyset config for *protocol_name*."""
        protocol =self .active_scp_protocol 
        if protocol_name is not None :
            protocol =str (protocol_name ).strip ().upper ()
        if protocol =="SCP02":
            return ("scp02_enc","scp02_mac","scp02_dek","scp02_kvn")
        return ("scp03_kenc","scp03_kmac","scp03_dek","scp03_kvn")

    def verify_adm (self ,key_hex :Optional [str ]=None ):
        """Send VERIFY ADM (GP Card Spec v2.3 §11.10) with the configured or supplied key hex."""
        target_key =key_hex 
        if not target_key :
            target_key =self .raw_keys .get ('adm')

        if not target_key :
            print (f"{Config.Colors.FAIL}[-] Error: No ADM key provided.{Config.Colors.ENDC}")
            return

        target_key =target_key .replace (' ','')
        if len (target_key )!=16 :
            print (f"{Config.Colors.WARNING}[!] Warning: ADM key should be 16 hex digits.{Config.Colors.ENDC}")

        if self .tp .session and self .tp .session .is_authenticated :
            active_protocol =getattr (self .tp .session ,'protocol_name',"SCP")
            print (f"{Config.Colors.WARNING}[!] Warning: Switching to MF will terminate {active_protocol} session.{Config.Colors.ENDC}")
            self .tp .reset_session_state ()

        print (f"{Config.Colors.CYAN}[*] Selecting MF (3F00)...{Config.Colors.ENDC}")
        self .tp .transmit ("00A40004023F00",silent =True )

        cmd =f"0020000A{len(target_key)//2:02X}{target_key}"
        print (f"{Config.Colors.CYAN}[*] Verifying ADM...{Config.Colors.ENDC}")
        _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )

        if sw1 ==0x90 :
            print (f"{Config.Colors.GREEN}[+] ADM Verified Successfully.{Config.Colors.ENDC}")
        elif sw1 ==0x63 :
            retries =sw2 &0x0F 
            print (f"{Config.Colors.FAIL}[-] ADM Failed: Wrong code. Retries remaining: {retries}{Config.Colors.ENDC}")
        elif sw1 ==0x69 and sw2 ==0x83 :
            print (f"{Config.Colors.FAIL}[-] ADM Failed: Key Blocked.{Config.Colors.ENDC}")
        else :
            print (f"{Config.Colors.FAIL}[-] ADM Failed: SW {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def authenticate (self ,protocol_name :str ="SCP03")->bool :
        protocol =str (protocol_name ).strip ().upper ()
        if protocol =="SCP02":
            return self .authenticate_scp02 ()
        return self .authenticate_scp03 ()

    @staticmethod
    def _preferred_scp03_security_level (i_parameter :int )->int :
        """Choose the strongest security level advertised by SCP03 ``i``."""
        response_mode =int (i_parameter )&0x60
        if response_mode ==0x40 :
            raise ValueError ("SCP03 i parameter uses the reserved response mode 10b.")
        security_level =0x03  # C-MAC + C-DECRYPTION
        if response_mode in (0x20 ,0x60 ):
            security_level |=0x10  # R-MAC
        if response_mode ==0x60 :
            security_level |=0x20  # R-ENCRYPTION
        return security_level

    def authenticate_scp03 (self )->bool :
        """Run INITIALIZE-UPDATE + EXTERNAL-AUTHENTICATE to open an SCP03 admin session; return True on success."""
        if self .tp .session :
            self .tp .reset_session_state ()

        target_hex =self .target_aid .hex ().upper ()
        print (f"{Config.Colors.CYAN}[*] Authenticating to Security Domain via SCP03: {target_hex}...{Config.Colors.ENDC}")

        self .tp .transmit (f"00A40400{len(self.target_aid):02X}{target_hex}",silent =True )

        attempted_kvns =[self .scp03_kvn ]
        if self .scp03_kvn !=0 :
            attempted_kvns .append (0 )

        data =b''
        sw1 =0x6F 
        sw2 =0x00 
        host_challenge =b''
        used_kvn =self .scp03_kvn 
        for kvn_candidate in attempted_kvns :
            host_challenge =os .urandom (8 )
            cmd =f"8050{kvn_candidate:02X}0008{host_challenge.hex()}"
            data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
            if sw1 ==0x90 :
                used_kvn =kvn_candidate 
                break 

        if sw1 !=0x90 :
            print (f"{Config.Colors.FAIL}[-] INITIALIZE UPDATE Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False 

        try :
            self .tp .session =Scp03Session (self .scp03_keys )
            self .tp .session .derive_keys (host_challenge ,data )
            security_level =self ._preferred_scp03_security_level (
            self .tp .session .i_parameter
            )
            self .tp .session .sec_level =security_level
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Key Derivation Failed: {e}{Config.Colors.ENDC}")
            return False 

        host_crypto =self .tp .session .calculate_host_cryptogram ()
        self .tp .session .chaining_value =b'\x00'*16 

        header =bytes ([0x84 ,0x82 ,security_level ,0x00 ,0x10 ])

        c_mac =cmac .CMAC (algorithms .AES (self .tp .session .s_mac ))
        c_mac .update (self .tp .session .chaining_value +header +host_crypto )
        full_mac =c_mac .finalize ()
        self .tp .session .chaining_value =full_mac 

        cmd_bytes =list (header )+list (host_crypto )+list (full_mac [:8 ])
        data ,sw1 ,sw2 =self .tp .connection .transmit (cmd_bytes )

        if sw1 ==0x90 :
            self .scp03_kvn =used_kvn 
            self .active_scp_protocol ="SCP03"
            self .tp .session .ssc =1 
            self .tp .session .is_authenticated =True 
            print (f"{Config.Colors.GREEN}[+] SCP03 Authenticated (Level 0x{security_level:02X}, KVN 0x{used_kvn:02X}){Config.Colors.ENDC}")
            self .get_keys_info (silent =True )
            return True 
        self .tp .reset_session_state ()
        print (f"{Config.Colors.FAIL}[-] EXTERNAL AUTH Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        return False 

    def authenticate_scp02 (self )->bool :
        """Run INITIALIZE-UPDATE + EXTERNAL-AUTHENTICATE to open an SCP02 admin session; return True on success."""
        if self .tp .session :
            self .tp .reset_session_state ()

        target_hex =self .target_aid .hex ().upper ()
        print (f"{Config.Colors.CYAN}[*] Authenticating to Security Domain via SCP02: {target_hex}...{Config.Colors.ENDC}")

        self .tp .transmit (f"00A40400{len(self.target_aid):02X}{target_hex}",silent =True )

        if is_simulated_card_backend ():
            from SIMCARD .gp import SimulatedSecureSession

            self .tp .session =SimulatedSecureSession ("SCP02")
            self .active_scp_protocol ="SCP02"
            print (f"{Config.Colors.GREEN}[+] SCP02 simulated session activated (plaintext simulator mode).{Config.Colors.ENDC}")
            return True 

        session =Scp02SessionAdapter (
        self .scp02_keys ['enc'],
        self .scp02_keys ['mac'],
        self .scp02_keys ['dek'],
        self .scp02_kvn 
        )
        host_challenge =os .urandom (8 )
        init_apdu =session .gen_init_update_apdu (host_challenge )
        data ,sw1 ,sw2 =self .tp .connection .transmit (list (init_apdu ))
        if sw1 !=0x90 :
            print (f"{Config.Colors.FAIL}[-] INITIALIZE UPDATE Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False 

        try :
            session .parse_init_update_resp (bytes (data ))
            ext_auth_apdu =session .gen_ext_auth_apdu (0x03 )
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] SCP02 Session Setup Failed: {e}{Config.Colors.ENDC}")
            return False 

        _ ,sw1 ,sw2 =self .tp .connection .transmit (list (ext_auth_apdu ))
        if sw1 !=0x90 :
            print (f"{Config.Colors.FAIL}[-] EXTERNAL AUTH Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False 

        session .is_authenticated =True 
        self .tp .session =session 
        self .active_scp_protocol ="SCP02"
        print (f"{Config.Colors.GREEN}[+] SCP02 Authenticated (Level 0x03, KVN 0x{self.scp02_kvn:02X}){Config.Colors.ENDC}")
        self .get_keys_info (silent =True )
        return True 

    def store_data (self ,data_hex :str ,p1 :Optional [int ]=None ,p2 :Optional [int ]=None ):
        """
        GlobalPlatform STORE DATA (GPCS 11.11).
        Features automatic chunking if P1/P2 are not provided manually.
        """
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return

        payload =HexUtils .to_bytes (data_hex )

        if p1 is not None and p2 is not None :
            print (f"{Config.Colors.CYAN}[*] STORE DATA (P1={p1:02X}, P2={p2:02X}) Len={len(payload)}...{Config.Colors.ENDC}")
            cmd =f"80E2{p1:02X}{p2:02X}{len(payload):02X}{payload.hex()}"
            _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
            if sw1 ==0x90 :
                print (f"{Config.Colors.GREEN}[+] STORE DATA Success.{Config.Colors.ENDC}")
            else :
                print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return 

        print (f"{Config.Colors.CYAN}[*] STORE DATA (Auto-chunking {len(payload)} bytes)...{Config.Colors.ENDC}")
        chunk_size =240 
        total_chunks =math .ceil (len (payload )/chunk_size )
        block_num =0 

        for i in range (total_chunks ):
            start =i *chunk_size 
            end =min (start +chunk_size ,len (payload ))
            chunk =payload [start :end ]

            p1_byte =0x80 
            if i >=total_chunks -1 :
                p1_byte =0x00 

            p2_byte =block_num %256 

            cmd =f"80E2{p1_byte:02X}{p2_byte:02X}{len(chunk):02X}{chunk.hex()}"
            _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )

            print (f"\r    Sending Block {i+1}/{total_chunks} [P1={p1_byte:02X} P2={p2_byte:02X}]...",end ='',flush =True )

            if sw1 !=0x90 :
                print (f"\n{Config.Colors.FAIL}[-] Failed at block {i+1}: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                return 

            block_num +=1 

        print (f"\n{Config.Colors.GREEN}[+] STORE DATA Success ({total_chunks} blocks).{Config.Colors.ENDC}")

    def put_key (self ,old_kvn :int ,key_id :int ,new_kvn :int ,new_keys :list ,key_type :int =0x88 )->bool :
        """Send PUT KEY (GP Card Spec v2.3 §11.8) to install or replace a keyset entry."""
        from cryptography .hazmat .primitives .ciphers import Cipher ,algorithms ,modes 
        from SCP03 .core .utils import HexUtils 

        payload =bytearray ()
        payload .append (new_kvn )

        for i in range (len (new_keys )):
            key_hex =new_keys [i ]
            raw_key =HexUtils .to_bytes (key_hex )

            valid_len =False 
            if len (raw_key )==16 :
                valid_len =True 
            if len (raw_key )==24 :
                valid_len =True 
            if len (raw_key )==32 :
                valid_len =True 

            if valid_len ==False :
                print (f"[-] Error: Key {i+1} length invalid for crypto operations.")
                return False

            encrypted_key =raw_key 

            has_session =False 
            if hasattr (self .tp ,'session'):
                has_session =True 

            is_active =False 
            if has_session :
                if self .tp .session is not None :
                    is_active =True 

            if is_active :
                try :
                    encrypted_key =self .tp .session .encrypt_key_data (raw_key )
                except Exception as e :
                    print (f"[-] Encryption Error: {e}")
                    return False 

            kcv_check =b'\x00\x00\x00'

            is_aes =False 
            if key_type ==0x88 :
                is_aes =True 

            if is_aes :
                cipher =Cipher (algorithms .AES (raw_key ),modes .ECB ())
                encryptor =cipher .encryptor ()
                kcv_check =encryptor .update (b'\x01'*16 )[:3 ]

            is_des =False 
            if key_type ==0x81 :
                is_des =True 
            if key_type ==0x82 :
                is_des =True 
            if key_type ==0x83 :
                is_des =True 

            if is_des :
                cipher =Cipher (algorithms .TripleDES (raw_key ),modes .ECB ())
                encryptor =cipher .encryptor ()
                kcv_check =encryptor .update (b'\x00'*8 )[:3 ]

            payload .append (key_type )
            payload .append (len (encrypted_key ))
            payload .extend (encrypted_key )
            payload .append (len (kcv_check ))
            payload .extend (kcv_check )

        p1 =old_kvn 
        p2 =key_id 

        has_multiple =False 
        if len (new_keys )>1 :
            has_multiple =True 

        if has_multiple :
            p2 =p2 |0x80 

        cmd =f"80D8{p1:02X}{p2:02X}{len(payload):02X}{payload.hex().upper()}"
        res ,sw1 ,sw2 =self .tp .transmit (cmd )

        is_success =False 
        if sw1 ==0x90 :
            is_success =True 

        if is_success :
            print (f"[+] PUT KEY (Type 0x{key_type:02X}) Successful.")
            return True 

        print (f"[-] PUT KEY Failed: {sw1:02X}{sw2:02X}")
        return False 

    def _parse_cap_file_for_install (self ,filename :str ):
        if not os .path .exists (filename ):
            print (f"{Config.Colors.FAIL}[!] File not found: {filename}{Config.Colors.ENDC}")
            return None

        print (f"{Config.Colors.CYAN}[*] Parsing CAP file: {filename}...{Config.Colors.ENDC}")
        try :
            parsed_cap =CapFileParser .parse_with_metadata (filename )
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Parse Error: {e}{Config.Colors.ENDC}")
            return None

        return parsed_cap

    def _load_cap_file_to_card (self ,parsed_cap ,load_chunk_size :Optional [int ]=None )->bool :
        """Run INSTALL [for load] and LOAD for a parsed CAP/IJC package."""

        load_data =parsed_cap .load_block 
        pkg_aid =parsed_cap .package_aid 

        print (f"    Package AID: {pkg_aid.hex().upper()}")
        print (f"    Size: {len(load_data)} bytes")

        print (f"\n{Config.Colors.CYAN}[*] INSTALL [for load]...{Config.Colors.ENDC}")
        install_load_data =bytearray ()
        install_load_data .append (len (pkg_aid ))
        install_load_data .extend (pkg_aid )
        install_load_data .extend (b'\x00\x00\x00\x00')

        cmd_hex =f"80E60200{len(install_load_data):02X}{install_load_data.hex()}"
        _ ,sw1 ,sw2 =self .tp .transmit (cmd_hex ,silent =True )

        if sw1 !=0x90 :
            print (f"{Config.Colors.FAIL}[-] Install [for load] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False

        print (f"{Config.Colors.CYAN}[*] Loading {len(load_data)} bytes...{Config.Colors.ENDC}")
        chunk_size =240 
        if load_chunk_size is not None :
            if load_chunk_size >0 :
                chunk_size =load_chunk_size 

        is_secure_load =False 
        if self .tp .session :
            if self .tp .session .is_authenticated :
                if self .tp .session .sec_level &0x02 :
                    is_secure_load =True 

        if is_secure_load :
            if chunk_size >239 :
                chunk_size =239 
        try :
            load_chunks =CapFileParser .plan_load_chunks (parsed_cap ,chunk_size )
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Chunk Plan Error: {e}{Config.Colors.ENDC}")
            return False

        total_chunks =len (load_chunks )

        for i ,chunk_info in enumerate (load_chunks ):
            chunk =chunk_info .payload 

            p1 =0x00 
            if i >=total_chunks -1 :
                p1 =0x80 

            p2 =i %256 

            cmd =f"80E8{p1:02X}{p2:02X}{len(chunk):02X}{chunk.hex()}"
            _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )

            print (f"\r    Sending Block {i+1}/{total_chunks}...",end ='',flush =True )

            if sw1 !=0x90 :
                print (f"\n{Config.Colors.FAIL}[-] LOAD Failed at block {i}: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                return False

        print (f"\n{Config.Colors.GREEN}[+] Load Complete.{Config.Colors.ENDC}")
        return True

    @staticmethod
    def _extract_install_apdu_data (apdu :bytes )->bytes :
        if len (apdu )<5 :
            raise ValueError ("INSTALL APDU must include CLA INS P1 P2 Lc.")

        lc_byte =apdu [4 ]
        data_offset =5
        data_len =lc_byte
        max_trailing =1

        if lc_byte ==0x00 :
            if len (apdu )<7 :
                raise ValueError ("Extended-length INSTALL APDU is missing the two-byte Lc.")
            data_len =int .from_bytes (apdu [5 :7 ],"big")
            data_offset =7
            max_trailing =2

        data_end =data_offset +data_len
        if len (apdu )<data_end :
            raise ValueError ("INSTALL APDU Lc exceeds the supplied APDU length.")

        trailing_len =len (apdu )-data_end
        if trailing_len >max_trailing :
            raise ValueError ("INSTALL APDU has extra bytes after the data field.")

        return apdu [data_offset :data_end ]

    @staticmethod
    def _first_lv_value (data :bytes ,field_name :str )->bytes :
        if len (data )<1 :
            raise ValueError (f"INSTALL APDU data is missing {field_name} length.")

        value_len =data [0 ]
        value_end =1 +value_len
        if len (data )<value_end :
            raise ValueError (f"INSTALL APDU {field_name} LV overruns the data field.")

        return data [1 :value_end ]

    @staticmethod
    def _normalize_install_for_install_apdu (install_apdu :str )->Tuple [str ,bytes ]:
        try :
            apdu =HexUtils .to_bytes (install_apdu )
        except ValueError :
            raise ValueError ("INSTALL APDU is not valid hexadecimal data.")

        if len (apdu )<5 :
            raise ValueError ("INSTALL APDU must include CLA INS P1 P2 Lc.")

        if apdu [1 ]!=0xE6 :
            raise ValueError ("Supplied APDU must use INSTALL instruction E6.")

        if apdu [2 ]not in (0x04 ,0x0C ):
            raise ValueError ("Supplied APDU must be INSTALL [for install] P1=04 or P1=0C.")

        if apdu [3 ]!=0x00 :
            raise ValueError ("Supplied INSTALL APDU must use P2=00.")

        data =GlobalPlatformManager ._extract_install_apdu_data (apdu )
        load_file_aid =GlobalPlatformManager ._first_lv_value (data ,"Load File AID")
        return apdu .hex ().upper (),load_file_aid

    def install_cap_file_with_install_apdu (self ,filename :str ,install_apdu :str ,load_chunk_size :Optional [int ]=None )->bool :
        """Load a CAP/IJC package and send a caller-supplied INSTALL [for install] APDU."""
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated (AUTH) first.{Config.Colors.ENDC}")
            return False

        try :
            final_apdu ,install_load_file_aid =self ._normalize_install_for_install_apdu (install_apdu )
        except ValueError as e :
            print (f"{Config.Colors.FAIL}[!] Invalid INSTALL APDU: {e}{Config.Colors.ENDC}")
            return False

        parsed_cap =self ._parse_cap_file_for_install (filename )
        if parsed_cap is None :
            return False

        pkg_aid =parsed_cap .package_aid
        if install_load_file_aid !=pkg_aid :
            print (
            f"{Config.Colors.FAIL}[!] INSTALL APDU Load File AID "
            f"{install_load_file_aid.hex().upper()} does not match CAP package AID "
            f"{pkg_aid.hex().upper()}.{Config.Colors.ENDC}"
            )
            return False

        loaded =self ._load_cap_file_to_card (parsed_cap ,load_chunk_size =load_chunk_size )
        if loaded ==False :
            return False

        print (f"{Config.Colors.CYAN}[*] INSTALL [for install] from supplied APDU...{Config.Colors.ENDC}")
        _ ,sw1 ,sw2 =self .tp .transmit (final_apdu ,silent =True )

        if sw1 ==0x90 :
            print (f"{Config.Colors.GREEN}[+] Applet Installed Successfully.{Config.Colors.ENDC}")
            return True

        print (f"{Config.Colors.FAIL}[-] Install Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        return False

    def install_cap_file (self ,filename :str ,privileges :str ="00",install_params :str ="C900",instantiate :bool =True ,target_app_aid :str =None ,target_module_aid :str =None ,load_chunk_size :Optional [int ]=None ):
        """
        GlobalPlatform INSTALL (GPCS 11.5).
        Handles INSTALL [for load], LOAD (80 E8), and INSTALL [for install].
        """
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated (AUTH) first.{Config.Colors.ENDC}")
            return

        parsed_cap =self ._parse_cap_file_for_install (filename )
        if parsed_cap is None :
            return

        pkg_aid =parsed_cap .package_aid
        app_aids =parsed_cap .applet_aids

        loaded =self ._load_cap_file_to_card (parsed_cap ,load_chunk_size =load_chunk_size )
        if loaded ==False :
            return

        if not instantiate :
            print (f"{Config.Colors.CYAN}[*] Skipping instantiation (LOAD only mode).{Config.Colors.ENDC}")
            return

        if not app_aids and not target_app_aid :
            print (f"{Config.Colors.GREEN}[+] Library Loaded (No Applets to install).{Config.Colors.ENDC}")
            return

        applet_aid =app_aids [0 ]
        if target_app_aid :
            applet_aid =HexUtils .to_bytes (target_app_aid )

        module_aid =applet_aid 
        if target_module_aid :
            module_aid =HexUtils .to_bytes (target_module_aid )

        print (f"{Config.Colors.CYAN}[*] INSTALL [for install] Applet: {applet_aid.hex().upper()}...{Config.Colors.ENDC}")
        print (f"    Module    : {module_aid.hex().upper()}")
        print (f"    Privileges: {privileges}")
        print (f"    Params    : {install_params}")

        priv_bytes =HexUtils .to_bytes (privileges )
        param_bytes =HexUtils .to_bytes (install_params )

        install_data =bytearray ()
        install_data .append (len (pkg_aid ))
        install_data .extend (pkg_aid )
        install_data .append (len (module_aid ))
        install_data .extend (module_aid )
        install_data .append (len (applet_aid ))
        install_data .extend (applet_aid )

        install_data .append (len (priv_bytes ))
        install_data .extend (priv_bytes )
        install_data .append (len (param_bytes ))
        install_data .extend (param_bytes )
        install_data .append (0x00 )

        cmd =self ._build_case3_apdu (0x80 ,0xE6 ,0x0C ,0x00 ,bytes (install_data ))
        _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )

        if sw1 ==0x90 :
            print (f"{Config.Colors.GREEN}[+] Applet Installed Successfully.{Config.Colors.ENDC}")
        else :
            print (f"{Config.Colors.FAIL}[-] Install Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def get_keys_info (self ,target_aid_hex :Optional [str ]=None ,silent =False ):
        """Print the installed key information from GET KEY INFORMATION DATA for the active or target SD."""
        if target_aid_hex :
            if not silent :
                print (f"{Config.Colors.CYAN}[*] Selecting AID: {target_aid_hex}...{Config.Colors.ENDC}")
            self .tp .transmit (f"00A40400{len(target_aid_hex)//2:02X}{target_aid_hex}",silent =True )
        else :
            if not self .tp .session or not self .tp .session .is_authenticated :
                aid_hex =self .target_aid .hex ().upper ()
                self .tp .transmit (f"00A40400{len(self.target_aid):02X}{aid_hex}",silent =True )

        if not silent :
            print (f"{Config.Colors.CYAN}[*] Retrieving Key Information Template...{Config.Colors.ENDC}")

        data ,sw1 ,sw2 =self .tp .transmit ("80CA00E000",silent =silent )

        if sw1 ==0x90 and not silent :
            self ._decode_key_template (data )
        elif sw1 !=0x90 and not silent :
            print (f"{Config.Colors.FAIL}[-] Error: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def _parse_key_template_entries (self ,data :bytes )->List [Dict [str ,Any ]]:
        """Decode GP Key Information Template (E0/C0) entries.

        A basic C0 value starts with KID/KVN and may contain more than one
        key-type/key-length component pair.  The previous byte scanner only
        recognized ``C0 04`` and could also false-match C0 bytes inside an
        unrelated value.
        """
        try :
            parsed =TlvParser .parse (bytes (data ))
        except ValueError :
            return []

        template =parsed
        if 0xE0 in parsed :
            template =parsed [0xE0 ]
            if isinstance (template ,bytes ):
                try :
                    template =TlvParser .parse (template )
                except ValueError :
                    return []
        if not isinstance (template ,dict ):
            return []

        raw_c0_values =template .get (0xC0 ,[])
        if isinstance (raw_c0_values ,bytes ):
            raw_c0_values =[raw_c0_values ]
        if not isinstance (raw_c0_values ,list ):
            return []

        type_map ={
        0x80 :"DES",
        0x85 :"TLS PSK",
        0x88 :"AES",
        0x89 :"SM4",
        0xA0 :"RSA public exponent",
        0xA1 :"RSA public modulus",
        0xB0 :"ECC public",
        0xB1 :"ECC private",
        0xB8 :"SM2 public",
        0xB9 :"SM2 private",
        0xF0 :"ECC parameters reference",
        }
        entries :List [Dict [str ,Any ]]=[]
        for raw_value in raw_c0_values :
            if not isinstance (raw_value ,(bytes ,bytearray ,memoryview )):
                return []
            value =bytes (raw_value )
            if len (value )<4 :
                return []

            kid =value [0 ]
            kver =value [1 ]
            components :List [Dict [str ,Any ]]=[]
            usage_qualifier =b""
            access_condition =b""
            if value [2 ]==0xFF :
                cursor =2
                while cursor +4 <=len (value )and value [cursor ]==0xFF :
                    extended_type =f"FF{value[cursor +1]:02X}"
                    extended_length =int .from_bytes (
                    value [cursor +2 :cursor +4 ],"big"
                    )
                    if extended_length <1 or extended_length >0x7FFF :
                        return []
                    components .append (
                    {
                    "type":extended_type ,
                    "type_code":extended_type ,
                    "length":extended_length ,
                    }
                    )
                    cursor +=4
                if len (components )==0 or cursor >=len (value ):
                    return []
                usage_length =value [cursor ]
                cursor +=1
                if usage_length >2 or cursor +usage_length >len (value ):
                    return []
                usage_qualifier =value [cursor :cursor +usage_length ]
                cursor +=usage_length
                if cursor >=len (value ):
                    return []
                access_length =value [cursor ]
                cursor +=1
                if access_length >1 or cursor +access_length !=len (value ):
                    return []
                access_condition =value [cursor :cursor +access_length ]
                entry_format ="extended"
            else :
                component_data =value [2 :]
                if len (component_data )%2 !=0 :
                    return []
                for offset in range (0 ,len (component_data ),2 ):
                    key_type =component_data [offset ]
                    key_length =component_data [offset +1 ]
                    if key_type ==0xFF :
                        return []
                    component :Dict [str ,Any ]={
                    "type":type_map .get (key_type ,f"{key_type:02X}"),
                    "type_code":f"{key_type:02X}",
                    "length":">=256"if key_length ==0 else key_length ,
                    }
                    if key_length ==0 :
                        component ["length_code"]="00"
                        component ["minimum_length"]=256
                    if key_type ==0x80 :
                        component ["deprecated"]=True
                    components .append (component )
                entry_format ="basic"

            first_component =components [0 ]
            entries .append (
            {
            "version":f"{kver:02X}",
            "id":f"{kid:02X}",
            "type":first_component ["type"],
            "length":first_component ["length"],
            "format":entry_format ,
            "components":components ,
            "key_usage_qualifier":usage_qualifier .hex ().upper (),
            "key_access_condition":access_condition .hex ().upper (),
            "raw_hex":value .hex ().upper (),
            }
            )
        return entries 

    def get_keys_info_data (self ,target_aid_hex :Optional [str ]=None )->Dict [str ,Any ]:
        """Return a dict of installed key information from GET KEY INFORMATION DATA."""
        if target_aid_hex :
            self .tp .transmit (f"00A40400{len(target_aid_hex)//2:02X}{target_aid_hex}",silent =True )
        else :
            has_session =False 
            if self .tp .session :
                has_session =True 
            is_auth =False 
            if has_session :
                if self .tp .session .is_authenticated :
                    is_auth =True 
            if is_auth ==False :
                aid_hex =self .target_aid .hex ().upper ()
                self .tp .transmit (f"00A40400{len(self.target_aid):02X}{aid_hex}",silent =True )

        data ,sw1 ,sw2 =self .tp .transmit ("80CA00E000",silent =True )
        out :Dict [str ,Any ]={
        "status":f"{sw1:02X}{sw2:02X}",
        "raw_hex":data .hex ().upper ()
        }
        if sw1 ==0x90 :
            out ["entries"]=self ._parse_key_template_entries (data )
        return out 

    def list_registry (self ,kind ='APPS'):
        """Print the GET STATUS application/package/SD registry for *kind* (APPS, PACKAGES, or SD)."""
        p1_map ={'APPS':0x40 ,'PACKAGES':0x20 ,'SD':0x80 }

        kind =str (kind ).strip ().upper ()
        if kind not in p1_map :
            raise ValueError ("Registry kind must be APPS, PACKAGES, or SD.")
        p1 =p1_map .get (kind ,0x40 )
        p2 =0x00 
        full_data =bytearray ()
        pages =0

        while True :
            pages +=1
            cmd =f"80F2{p1:02X}{p2:02X}024F0000"
            data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )

            if (sw1 ==0x90 or sw1 ==0x63 )and data :
                full_data .extend (data )

            if sw1 ==0x90 :
                break 
            elif sw1 ==0x63 and sw2 ==0x10 :
                if pages >=self .MAX_GET_STATUS_PAGES :
                    print (
                    f"{Config.Colors.FAIL}[-] Registry response exceeded "
                    f"{self.MAX_GET_STATUS_PAGES} pages; stopping.{Config.Colors.ENDC}"
                    )
                    break
                p2 =0x01
            elif sw1 ==0x6A and sw2 ==0x88 :
                if not full_data :
                    print (f"[-] No {kind} found in registry.")
                break 
            else :
                print (f"{Config.Colors.FAIL}[-] Error listing registry: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                break 

        if full_data :
            self ._parse_registry_response (full_data ,kind )

    def _parse_registry_response (self ,data ,kind ):
        last_col ="Privileges"
        if kind =='PACKAGES':
            last_col ="Assoc SD"

        print (f"\n{Config.Colors.HEADER}--- GlobalPlatform Registry ({kind}) ---{Config.Colors.ENDC}")
        print (f"{'AID':<34} | {'State':<12} | {last_col}")
        print ("-"*65 )

        rows =self ._registry_rows_from_data (bytes (data ),kind )
        if not rows :
            if len (data )>0 and data [0 ]==0x62 :
                print (f"{Config.Colors.WARNING}[!] Response is an FCP template, not a GP registry response.{Config.Colors.ENDC}")
            else :
                print (f"{Config.Colors.WARNING}[!] No GP registry entries decoded from response.{Config.Colors.ENDC}")
            return

        for aid ,state_byte ,extra in rows :
            self ._print_registry_row (aid ,state_byte ,extra )

    def _print_registry_row (self ,aid ,lcs_byte ,extra ):
        state_map ={
        0x00 :"LOADED",
        0x01 :"OP_READY",
        0x03 :"INSTALLED",
        0x07 :"SELECTABLE",
        0x0F :"PERSONALIZED",
        0x80 :"LOCKED",
        0x83 :"TERMINATED"
        }

        state_str =state_map .get (lcs_byte ,f"0x{lcs_byte:02X}")
        print (f"{aid:<34} | {state_str:<12} | {extra}")

    def _state_to_string (self ,lcs_byte :int )->str :
        state_map ={
        0x00 :"LOADED",
        0x01 :"OP_READY",
        0x03 :"INSTALLED",
        0x07 :"SELECTABLE",
        0x0F :"PERSONALIZED",
        0x80 :"LOCKED",
        0x83 :"TERMINATED"
        }
        return state_map .get (lcs_byte ,f"0x{lcs_byte:02X}")

    @staticmethod
    def _compact_registry_entry_at (data :bytes ,offset :int ,kind :str )->Optional [Tuple [str ,int ,str ,int ]]:
        if offset >=len (data ):
            return None

        aid_len =data [offset ]
        if not (5 <=aid_len <=16 ):
            return None

        aid_start =offset +1
        aid_end =aid_start +aid_len
        min_end =aid_end +2
        if min_end >len (data ):
            return None

        state_byte =data [aid_end ]
        known_states ={0x00 ,0x01 ,0x03 ,0x07 ,0x0F ,0x80 ,0x83 }
        if state_byte not in known_states :
            return None

        extra_byte =data [aid_end +1 ]
        next_offset =aid_end +2
        extra =f"{extra_byte:02X}"

        if kind =='PACKAGES'and extra_byte >0 :
            if extra_byte >16 :
                return None
            if next_offset +extra_byte >len (data ):
                return None
            extra =data [next_offset :next_offset +extra_byte ].hex ().upper ()
            next_offset +=extra_byte

        aid =data [aid_start :aid_end ].hex ().upper ()
        return aid ,state_byte ,extra ,next_offset

    @staticmethod
    def _registry_ber_length_at (data :bytes ,offset :int )->Tuple [int ,int ]:
        if offset >=len (data ):
            raise ValueError ("Registry TLV is missing its length.")
        first =data [offset ]
        offset +=1
        if first <0x80 :
            return first ,offset
        count =first &0x7F
        if count ==0 :
            raise ValueError ("Registry TLV uses an indefinite BER length.")
        if count >4 or offset +count >len (data ):
            raise ValueError ("Registry TLV has a truncated BER length.")
        if data [offset ]==0x00 :
            raise ValueError ("Registry TLV uses a non-minimal BER length.")
        length =int .from_bytes (data [offset :offset +count ],"big")
        if length <0x80 :
            raise ValueError ("Registry TLV uses a non-minimal BER length.")
        return length ,offset +count

    @staticmethod
    def _registry_first_bytes (value :Any )->Optional [bytes ]:
        if isinstance (value ,list ):
            if len (value )==0 :
                return None
            value =value [0 ]
        if isinstance (value ,(bytes ,bytearray ,memoryview )):
            return bytes (value )
        return None

    def _registry_rows_from_data (self ,data :bytes ,kind :str )->List [Tuple [str ,int ,str ]]:
        rows :List [Tuple [str ,int ,str ]]=[]
        if len (data )>0 and data [0 ]==0xE3 :
            i =0 
            while i <len (data ):
                if data [i ]!=0xE3 :
                    return []
                try :
                    tag_len ,value_offset =self ._registry_ber_length_at (data ,i +1 )
                except ValueError :
                    return []
                end =value_offset +tag_len
                if end >len (data ):
                    return []
                entry =data [value_offset :end ]
                i =end 
                try :
                    parsed =TlvParser .parse (entry )
                except ValueError :
                    return []

                aid_value =self ._registry_first_bytes (parsed .get (0x4F ))
                lcs_value =self ._registry_first_bytes (parsed .get (0x9F70 ))
                if aid_value is None or not (5 <=len (aid_value )<=16 ):
                    return []
                if lcs_value is None or len (lcs_value )!=1 :
                    return []
                aid =aid_value .hex ().upper ()
                lcs_byte =lcs_value [0 ]

                extra =""
                extra_value =self ._registry_first_bytes (parsed .get (0xC5 ))
                if extra_value is not None :
                    extra =extra_value .hex ().upper ()

                rows .append ((aid ,lcs_byte ,extra ))
            return rows 

        i =0 
        while i <len (data ):
            entry =self ._compact_registry_entry_at (data ,i ,kind )
            if entry is None :
                return []

            aid ,lcs_byte ,extra ,next_i =entry
            rows .append ((aid ,lcs_byte ,extra ))
            i =next_i
        return rows 

    def _registry_entries_from_data (self ,data :bytes ,kind :str )->List [Dict [str ,Any ]]:
        entries :List [Dict [str ,Any ]]=[]
        for aid ,lcs_byte ,extra in self ._registry_rows_from_data (data ,kind ):
            entries .append (
            {
            "aid":aid ,
            "state":self ._state_to_string (lcs_byte ),
            "extra":extra
            }
            )
        return entries 

    def get_registry_data (self ,kind :str ='APPS')->Dict [str ,Any ]:
        """Return a dict of GET STATUS registry entries for *kind* (APPS, PACKAGES, or SD)."""
        p1_map ={'APPS':0x40 ,'PACKAGES':0x20 ,'SD':0x80 }
        kind =str (kind ).strip ().upper ()
        if kind not in p1_map :
            raise ValueError ("Registry kind must be APPS, PACKAGES, or SD.")
        p1 =p1_map .get (kind ,0x40 )
        p2 =0x00 
        full_data =bytearray ()
        pages =0 
        last_sw1 =0x6F 
        last_sw2 =0x00 
        truncated =False

        while True :
            cmd =f"80F2{p1:02X}{p2:02X}024F0000"
            data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
            last_sw1 =sw1 
            last_sw2 =sw2 
            pages +=1 

            has_chunk =False 
            if sw1 ==0x90 or sw1 ==0x63 :
                if len (data )>0 :
                    has_chunk =True 
            if has_chunk :
                full_data .extend (data )

            is_done =False 
            if sw1 ==0x90 :
                is_done =True 
            if is_done :
                break 

            has_more =False 
            if sw1 ==0x63 :
                if sw2 ==0x10 :
                    has_more =True 
            if has_more :
                if pages >=self .MAX_GET_STATUS_PAGES :
                    truncated =True
                    break
                p2 =0x01
                continue 
            break 

        entries =self ._registry_entries_from_data (bytes (full_data ),kind )
        return {
        "kind":kind ,
        "status":f"{last_sw1:02X}{last_sw2:02X}",
        "pages":pages ,
        "truncated":truncated ,
        "count":len (entries ),
        "entries":entries ,
        "raw_hex":bytes (full_data ).hex ().upper ()
        }

    def _decode_key_template (self ,data :bytes ):
        from SCP03 .config import Config 
        print (f"\n{Config.Colors.HEADER}--- Card Key Registry ---{Config.Colors.ENDC}")
        print (f"{'Version':<10} | {'ID':<10} | {'Type':<12} | {'Length'}")
        print ("-"*50 )
        entries =self ._parse_key_template_entries (data )
        for entry in entries :
            version =str (entry .get ("version","00"))
            key_id =str (entry .get ("id","00"))
            components =entry .get ("components",[])
            if not isinstance (components ,list ):
                components =[]
            for component_index ,component in enumerate (components ):
                if not isinstance (component ,dict ):
                    continue
                type_text =str (component .get ("type","Unknown"))
                length =component .get ("length","Unknown")
                version_text =f"0x{version}"if component_index ==0 else ""
                id_text =f"0x{key_id}"if component_index ==0 else ""
                print (f"{version_text:<10} | {id_text:<10} | {type_text:<12} | {length}")

        if not entries :
            print ("  (No valid keys detected or parsing failed)")
        print ("-"*50 +"\n")

    def get_cplc (self ):
        """Send GET DATA 9F7F to retrieve and print the Card Production Life-Cycle (CPLC) data."""
        cmd ="80CA9F7F00"
        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )
        if sw1 ==0x90 :
            AdvancedDecoders .print_cplc (data )
        else :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def get_cplc_data (self )->Tuple [Optional [bytes ],int ,int ]:
        """Return CPLC data and status without printing. For use in export/report."""
        cmd ="80CA9F7F00"
        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
        return (data if sw1 ==0x90 else None ,sw1 ,sw2 )

    def get_data_raw (self ,p1 :int ,p2 :int )->Tuple [bytes ,int ,int ]:
        if p1 ==0x2F and p2 ==0x00 :
            cmd =f"80CA{p1:02X}{p2:02X}025C0000"
        else :
            cmd =f"80CA{p1:02X}{p2:02X}00"
        return self .tp .transmit (cmd ,silent =True )

    def get_data (self ,p1 :int ,p2 :int ):
        """Send GET DATA for the given P1/P2 tag pair and print the decoded response."""
        print (f"{Config.Colors.CYAN}[*] GET DATA Tag: {p1:02X}{p2:02X}...{Config.Colors.ENDC}")

        if p1 ==0x2F and p2 ==0x00 :
            cmd =f"80CA{p1:02X}{p2:02X}025C0000"
        else :
            cmd =f"80CA{p1:02X}{p2:02X}00"

        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )

        if sw1 ==0x90 :
            try :
                parsed =TlvParser .parse (data )
                self .print_tlv_data (parsed )
            except Exception :
                pass 
        else :
            err_map ={
            0x6A88 :"Referenced Data Not Found (Tag not supported or empty)",
            0x6A81 :"Function Not Supported",
            0x6982 :"Security Status Unsatisfied",
            0x6985 :"Conditions Not Satisfied"
            }
            sw_full =(sw1 <<8 )|sw2 
            err_msg =err_map .get (sw_full ,"Unknown Error")
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X} -> {err_msg}{Config.Colors.ENDC}")

    def print_tlv_data (self ,tlv_dict :Dict [int ,Any ],indent :int =0 ):
        """Recursively print a tag→value dict as an indented TLV tree."""
        indent_str ="  "*indent 
        for tag ,val in tlv_dict .items ():
            tag_hex =f"{tag:02X}"if tag <=0xFF else f"{tag:04X}"

            if isinstance (val ,list ):
                for item in val :
                    if isinstance (item ,dict ):
                        print (f"{indent_str}{Config.Colors.BOLD}Tag {tag_hex}:{Config.Colors.ENDC}")
                        self .print_tlv_data (item ,indent +1 )
                    elif isinstance (item ,bytes ):
                        item_hex =item .hex ().upper ()
                        print (f"{indent_str}Tag {tag_hex} (L={len(item)}): {item_hex}")
                continue 
            if isinstance (val ,dict ):
                print (f"{indent_str}{Config.Colors.BOLD}Tag {tag_hex}:{Config.Colors.ENDC}")
                self .print_tlv_data (val ,indent +1 )
            elif isinstance (val ,bytes ):
                val_hex =val .hex ().upper ()
                ascii_str =""
                try :
                    s =val .decode ('utf-8')
                    safe_chars =set ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.:/,")
                    if len (s )>1 and all (c in safe_chars for c in s ):
                        ascii_str =f" ('{s}')"
                except UnicodeDecodeError :
                    pass 

                print (f"{indent_str}Tag {tag_hex} (L={len(val)}): {val_hex}{ascii_str}")

    def set_status (self ,target_aid ,state_byte :int ,status_type :int =0x40 ):
        """Send SET STATUS (GPCS 2.3.1 §11.10) to transition a life-cycle state.

        P1 carries the Status Type of Table 11-86, not zero: '80' for the
        Issuer Security Domain, '40' for an Application or Supplementary
        Security Domain, '60' for a Security Domain and its associated
        Applications. Callers targeting an application AID want '40',
        which is the default here.
        """
        target =HexUtils .to_bytes (target_aid )
        state_name =f"{state_byte:02X}"
        if state_byte ==0x80 :
            state_name ="LOCKED"
        elif state_byte ==0x07 :
            state_name ="SELECTABLE"

        print (f"{Config.Colors.CYAN}[*] Setting Status of {target.hex().upper()} to {state_name}...{Config.Colors.ENDC}")
        cmd =f"80F0{status_type:02X}{state_byte:02X}{len(target):02X}{target.hex()}"
        _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
        if sw1 ==0x90 :
            print (f"{Config.Colors.GREEN}[+] Status Updated.{Config.Colors.ENDC}")
        else :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def delete_object (self ,target_aid ,recursive =True ):
        """Send DELETE (GP Card Spec v2.3 §11.2) to remove an application or load-file by AID."""
        target =HexUtils .to_bytes (target_aid )
        p2 =0x00 
        if recursive :
            p2 =0x80 

        tlv =f"4F{len(target):02X}{target.hex()}"
        cmd =f"80E400{p2:02X}{len(bytes.fromhex(tlv)):02X}{tlv}"
        print (f"{Config.Colors.WARNING}[!] Deleting {target.hex()}...{Config.Colors.ENDC}")
        _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
        if sw1 ==0x90 :
            print (f"{Config.Colors.GREEN}[+] Deleted.{Config.Colors.ENDC}")
        else :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def _send_install_cmd (self ,p1 :int ,data :bytes ,description :str )->bool :
        """Generic helper for INSTALL commands."""
        print (f"{Config.Colors.CYAN}[*] INSTALL [{description}]...{Config.Colors.ENDC}")
        cmd =self ._build_case3_apdu (0x80 ,0xE6 ,p1 ,0x00 ,data )
        _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )

        if sw1 ==0x90 :
            print (f"{Config.Colors.GREEN}[+] Success.{Config.Colors.ENDC}")
            return True 
        else :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False 

    def install_for_load (self ,load_file_aid_hex :str ,security_domain_aid_hex :str ="",load_file_hash_hex :str ="",params :str ="",token :str =""):
        """GP INSTALL [for load] (P1=0x02) with explicit LV fields."""
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return

        load_file_aid =HexUtils .to_bytes (load_file_aid_hex )
        security_domain_aid =b''
        if security_domain_aid_hex :
            security_domain_aid =HexUtils .to_bytes (security_domain_aid_hex )
        load_file_hash =b''
        if load_file_hash_hex :
            load_file_hash =HexUtils .to_bytes (load_file_hash_hex )
        param_bytes =b''
        if params :
            param_bytes =HexUtils .to_bytes (params )
        token_bytes =b''
        if token :
            token_bytes =HexUtils .to_bytes (token )

        payload =bytearray ()
        payload .append (len (load_file_aid ))
        payload .extend (load_file_aid )
        payload .append (len (security_domain_aid ))
        payload .extend (security_domain_aid )
        payload .append (len (load_file_hash ))
        payload .extend (load_file_hash )
        payload .append (len (param_bytes ))
        payload .extend (param_bytes )
        payload .append (len (token_bytes ))
        payload .extend (token_bytes )

        self ._send_install_cmd (0x02 ,payload ,"For Load")

    def install_make_selectable (self ,aid_hex :str ,privileges :str ="00",params :str ="",token :str =""):
        """GP INSTALL [for make selectable] (P1=0x08)."""
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return 

        aid_bytes =HexUtils .to_bytes (aid_hex )
        priv_bytes =HexUtils .to_bytes (privileges )
        param_bytes =b''
        if params :
            param_bytes =HexUtils .to_bytes (params )
        token_bytes =b''
        if token :
            token_bytes =HexUtils .to_bytes (token )

        payload =bytearray ()
        payload .append (0x00 )
        payload .append (len (aid_bytes ))
        payload .extend (aid_bytes )
        payload .append (len (priv_bytes ))
        payload .extend (priv_bytes )
        payload .append (len (param_bytes ))
        payload .extend (param_bytes )
        payload .append (len (token_bytes ))
        payload .extend (token_bytes )

        self ._send_install_cmd (0x08 ,payload ,"Make Selectable")

    def install_extradition (self ,aid_hex :str ,sd_aid_hex :str ,token :str =""):
        """GP INSTALL [for extradition] (P1=0x10)."""
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return 

        aid_bytes =HexUtils .to_bytes (aid_hex )
        sd_bytes =HexUtils .to_bytes (sd_aid_hex )
        token_bytes =b''
        if token :
            token_bytes =HexUtils .to_bytes (token )

        payload =bytearray ()
        payload .append (len (sd_bytes ))
        payload .extend (sd_bytes )
        payload .append (0x00 )
        payload .append (len (aid_bytes ))
        payload .extend (aid_bytes )
        payload .append (len (token_bytes ))
        payload .extend (token_bytes )
        payload .append (0x00 )

        self ._send_install_cmd (0x10 ,payload ,"Extradition")

    def install_personalization (self ,aid_hex :str ):
        """GP INSTALL [for personalization] (P1=0x20)."""
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return 

        aid_bytes =HexUtils .to_bytes (aid_hex )

        payload =bytearray ()
        payload .append (0x00 )
        payload .append (len (aid_bytes ))
        payload .extend (aid_bytes )
        payload .append (0x00 )
        payload .append (0x00 )
        payload .append (0x00 )

        self ._send_install_cmd (0x20 ,payload ,"Personalization")

    def get_ecasd_data (self ):
        """Retrieves SGP.02/SGP.22 metadata from ECASD."""
        ECASD_AID ="A0000005591010FFFFFFFF8900000200"

        print (f"{Config.Colors.CYAN}[*] Selecting ECASD...{Config.Colors.ENDC}")
        self .tp .transmit (f"00A40400{len(ECASD_AID)//2:02X}{ECASD_AID}",silent =True )

        queries ={
        "EID (5A)":"5A",
        "CIN (45)":"45",
        "IIN (42)":"42",
        "CPLC (9F7F)":"9F7F",
        "Key Info (E0)":"E0"
        }

        print (f"{Config.Colors.HEADER}--- ECASD Data (SGP.02/22) ---{Config.Colors.ENDC}")

        for label ,tag in queries .items ():
            cmd =f"80CA{tag}00"
            if len (tag )>2 :
                cmd =f"80CA{tag}00"

            data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
            if sw1 ==0x90 or sw1 ==0x61 :
                hex_val =data .hex ().upper ()
                parsed =TlvParser .parse (data )

                tag_int =int (tag ,16 )
                if tag_int in parsed :
                     val =parsed [tag_int ]
                     if isinstance (val ,bytes ):
                         hex_val =val .hex ().upper ()

                print (f"{label:<15}: {hex_val}")
            else :
                print (f"{label:<15}: {Config.Colors.FAIL}Not Found / Error {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def install_app (self ,pkg_aid_hex :str ,app_aid_hex :str ,mod_aid_hex :Optional [str ]=None ,privileges :str ="00",params :str ="C900",make_selectable :bool =True ):
        """GP INSTALL [for install] / [for install and make selectable] (P1=0x04 / 0x0C)."""
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return 

        pkg_bytes =HexUtils .to_bytes (pkg_aid_hex )
        app_bytes =HexUtils .to_bytes (app_aid_hex )

        mod_bytes =app_bytes 
        if mod_aid_hex :
            mod_bytes =HexUtils .to_bytes (mod_aid_hex )

        priv_bytes =HexUtils .to_bytes (privileges )
        param_bytes =HexUtils .to_bytes (params )

        payload =bytearray ()
        payload .append (len (pkg_bytes ))
        payload .extend (pkg_bytes )
        payload .append (len (mod_bytes ))
        payload .extend (mod_bytes )
        payload .append (len (app_bytes ))
        payload .extend (app_bytes )
        payload .append (len (priv_bytes ))
        payload .extend (priv_bytes )
        payload .append (len (param_bytes ))
        payload .extend (param_bytes )
        payload .append (0x00 )

        p1 =0x04 
        desc ="Install"
        if make_selectable :
            p1 =0x0C 
            desc ="Install and Make Selectable"

        self ._send_install_cmd (p1 ,payload ,desc )

    def install_registry_update (self ,aid_hex :str ,privileges :str ="00",params :str =""):
        """GP INSTALL [for registry update] (P1=0x40)."""
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return 

        aid_bytes =HexUtils .to_bytes (aid_hex )
        priv_bytes =HexUtils .to_bytes (privileges )
        param_bytes =b''
        if params :
            param_bytes =HexUtils .to_bytes (params )

        payload =bytearray ()
        payload .append (0x00 )
        payload .append (0x00 )
        payload .append (len (aid_bytes ))
        payload .extend (aid_bytes )
        payload .append (len (priv_bytes ))
        payload .extend (priv_bytes )
        payload .append (len (param_bytes ))
        payload .extend (param_bytes )
        payload .append (0x00 )

        self ._send_install_cmd (0x40 ,payload ,"Registry Update")
