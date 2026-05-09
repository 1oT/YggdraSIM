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
            self .tp .session .sec_level =0x33 
            self .tp .session .derive_keys (host_challenge ,data )
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Key Derivation Failed: {e}{Config.Colors.ENDC}")
            return False 

        host_crypto =self .tp .session .calculate_host_cryptogram ()
        self .tp .session .chaining_value =b'\x00'*16 

        header =bytes ([0x84 ,0x82 ,0x33 ,0x00 ,0x10 ])

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
            print (f"{Config.Colors.GREEN}[+] SCP03 Authenticated (Level 0x33, KVN 0x{used_kvn:02X}){Config.Colors.ENDC}")
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

    def install_cap_file (self ,filename :str ,privileges :str ="00",install_params :str ="C900",instantiate :bool =True ,target_app_aid :str =None ,target_module_aid :str =None ,load_chunk_size :Optional [int ]=None ):
        """
        GlobalPlatform INSTALL (GPCS 11.5).
        Handles INSTALL [for load], LOAD (80 E8), and INSTALL [for install].
        """
        if not self .tp .session or not self .tp .session .is_authenticated :
            print (f"{Config.Colors.FAIL}[!] Error: Must be authenticated (AUTH) first.{Config.Colors.ENDC}")
            return 

        if not os .path .exists (filename ):
            print (f"{Config.Colors.FAIL}[!] File not found: {filename}{Config.Colors.ENDC}")
            return 

        print (f"{Config.Colors.CYAN}[*] Parsing CAP file: {filename}...{Config.Colors.ENDC}")
        try :
            parsed_cap =CapFileParser .parse_with_metadata (filename )
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Parse Error: {e}{Config.Colors.ENDC}")
            return 

        load_data =parsed_cap .load_block 
        pkg_aid =parsed_cap .package_aid 
        app_aids =parsed_cap .applet_aids 

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
            return 

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
            return 

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
                return 

        print (f"\n{Config.Colors.GREEN}[+] Load Complete.{Config.Colors.ENDC}")

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

        cmd =f"80E60C00{len(install_data):02X}{install_data.hex()}"
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
        entries :List [Dict [str ,Any ]]=[]
        i =0 
        while i <len (data )-5 :
            has_c0 =False 
            if data [i ]==0xC0 :
                if data [i +1 ]==0x04 :
                    has_c0 =True 
            if has_c0 :
                kid =data [i +2 ]
                kver =data [i +3 ]
                ktype =data [i +4 ]
                klen =data [i +5 ]
                type_map ={
                0x80 :"DES",
                0x81 :"DES",
                0x88 :"AES",
                0xFF :"Ext"
                }
                entries .append (
                {
                "version":f"{kver:02X}",
                "id":f"{kid:02X}",
                "type":type_map .get (ktype ,f"{ktype:02X}"),
                "length":klen 
                }
                )
                i +=6 
                continue 
            i +=1 
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

        p1 =p1_map .get (kind ,0x40 )
        p2 =0x00 
        full_data =bytearray ()

        while True :
            cmd =f"80F2{p1:02X}{p2:02X}024F00"
            data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =False )

            if (sw1 ==0x90 or sw1 ==0x63 )and data :
                full_data .extend (data )

            if sw1 ==0x90 :
                break 
            elif sw1 ==0x63 and sw2 ==0x10 :
                p2 +=1 
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

        if any (b ==0xE3 for b in data ):
            i =0 
            while i <len (data ):
                if data [i ]!=0xE3 :
                    i +=1 
                    continue 
                tag_len =data [i +1 ]
                entry =data [i +2 :i +2 +tag_len ]
                i +=2 +tag_len 
                parsed =TlvParser .parse (entry )

                aid =""
                if 0x4F in parsed :
                    aid =parsed [0x4F ].hex ().upper ()

                lcs_byte =0 
                if 0x9F70 in parsed :
                    lcs_byte =parsed [0x9F70 ][0 ]

                privs =""
                if 0xC5 in parsed :
                    privs =parsed [0xC5 ].hex ().upper ()

                self ._print_registry_row (aid ,lcs_byte ,privs )
            return 

        i =0 
        while i <len (data ):
            try :
                if i <len (data )-1 :
                    length_byte =data [i ]
                    next_byte =data [i +1 ]
                    if not ((5 <=length_byte <=16 )and (next_byte ==0xA0 )):
                        i +=1 
                        continue 

                aid_len =data [i ]
                i +=1 
                if i +aid_len >len (data ):
                    break 
                aid =data [i :i +aid_len ].hex ().upper ()
                i +=aid_len 

                state_byte =0 
                if i <len (data ):
                    state_byte =data [i ]
                i +=1 

                extra_byte =0 
                if i <len (data ):
                    extra_byte =data [i ]
                i +=1 

                extra_str =f"{extra_byte:02X}"

                if kind =='PACKAGES'and extra_byte >0 :
                    extra_str =f"Len={extra_byte}"
                    i +=extra_byte 

                self ._print_registry_row (aid ,state_byte ,extra_str )
            except IndexError :
                break 

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

    def _registry_entries_from_data (self ,data :bytes ,kind :str )->List [Dict [str ,Any ]]:
        entries :List [Dict [str ,Any ]]=[]
        if any (b ==0xE3 for b in data ):
            i =0 
            while i <len (data ):
                is_e3 =False 
                if data [i ]==0xE3 :
                    is_e3 =True 
                if is_e3 ==False :
                    i +=1 
                    continue 
                has_len =False 
                if i +1 <len (data ):
                    has_len =True 
                if has_len ==False :
                    break 
                tag_len =data [i +1 ]
                end =i +2 +tag_len 
                in_range =False 
                if end <=len (data ):
                    in_range =True 
                if in_range ==False :
                    break 
                entry =data [i +2 :end ]
                i =end 
                parsed =TlvParser .parse (entry )

                aid =""
                if 0x4F in parsed :
                    aid =parsed [0x4F ].hex ().upper ()

                lcs_byte =0 
                if 0x9F70 in parsed :
                    lcs_byte =parsed [0x9F70 ][0 ]

                extra =""
                if 0xC5 in parsed :
                    extra =parsed [0xC5 ].hex ().upper ()

                entries .append (
                {
                "aid":aid ,
                "state":self ._state_to_string (lcs_byte ),
                "extra":extra 
                }
                )
            return entries 

        i =0 
        while i <len (data ):
            try :
                has_pair =False 
                if i <len (data )-1 :
                    has_pair =True 
                if has_pair :
                    length_byte =data [i ]
                    next_byte =data [i +1 ]
                    valid_prefix =False 
                    if 5 <=length_byte <=16 :
                        if next_byte ==0xA0 :
                            valid_prefix =True 
                    if valid_prefix ==False :
                        i +=1 
                        continue 

                aid_len =data [i ]
                i +=1 
                if i +aid_len >len (data ):
                    break 
                aid =data [i :i +aid_len ].hex ().upper ()
                i +=aid_len 

                lcs_byte =0 
                if i <len (data ):
                    lcs_byte =data [i ]
                i +=1 

                extra_byte =0 
                if i <len (data ):
                    extra_byte =data [i ]
                i +=1 

                extra =f"{extra_byte:02X}"
                is_pkg =False 
                if kind =='PACKAGES':
                    is_pkg =True 
                if is_pkg :
                    if extra_byte >0 :
                        extra =f"Len={extra_byte}"
                        i +=extra_byte 

                entries .append (
                {
                "aid":aid ,
                "state":self ._state_to_string (lcs_byte ),
                "extra":extra 
                }
                )
            except Exception :
                break 
        return entries 

    def get_registry_data (self ,kind :str ='APPS')->Dict [str ,Any ]:
        """Return a dict of GET STATUS registry entries for *kind* (APPS, PACKAGES, or SD)."""
        p1_map ={'APPS':0x40 ,'PACKAGES':0x20 ,'SD':0x80 }
        p1 =p1_map .get (kind ,0x40 )
        p2 =0x00 
        full_data =bytearray ()
        pages =0 
        last_sw1 =0x6F 
        last_sw2 =0x00 

        while True :
            cmd =f"80F2{p1:02X}{p2:02X}024F00"
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
                p2 +=1 
                continue 
            break 

        entries =self ._registry_entries_from_data (bytes (full_data ),kind )
        return {
        "kind":kind ,
        "status":f"{last_sw1:02X}{last_sw2:02X}",
        "pages":pages ,
        "count":len (entries ),
        "entries":entries ,
        "raw_hex":bytes (full_data ).hex ().upper ()
        }

    def _decode_key_template (self ,data :bytes ):
        from SCP03 .config import Config 
        print (f"\n{Config.Colors.HEADER}--- Card Key Registry ---{Config.Colors.ENDC}")
        print (f"{'Version':<10} | {'ID':<10} | {'Type':<12} | {'Length'}")
        print ("-"*50 )
        found =False 
        i =0 
        while i <len (data )-5 :
            if data [i ]==0xC0 and data [i +1 ]==0x04 :
                kid =data [i +2 ]
                kver =data [i +3 ]
                ktype =data [i +4 ]
                klen =data [i +5 ]
                type_map ={
                0x80 :"DES",
                0x81 :"DES",
                0x88 :"AES",
                0xFF :"Ext"
                }

                t_str =type_map .get (ktype ,f"0x{ktype:02X}")
                print (f"0x{kver:02X} ({kver:<3}) | 0x{kid:02X} ({kid:<3}) | {t_str:<12} | {klen}")
                found =True 
                i +=6 
            else :
                i +=1 

        if not found :
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
                    s =val .decode ('utf-8','ignore')
                    safe_chars =set ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.:/,")
                    if len (s )>1 and all (c in safe_chars for c in s ):
                        ascii_str =f" ('{s}')"
                except Exception :
                    pass 

                print (f"{indent_str}Tag {tag_hex} (L={len(val)}): {val_hex}{ascii_str}")

    def set_status (self ,target_aid ,state_byte :int ):
        """Send SET STATUS (GP Card Spec v2.3 §11.9) to transition the target application life-cycle state."""
        target =HexUtils .to_bytes (target_aid )
        state_name =f"{state_byte:02X}"
        if state_byte ==0x80 :
            state_name ="LOCKED"
        elif state_byte ==0x07 :
            state_name ="SELECTABLE"

        print (f"{Config.Colors.CYAN}[*] Setting Status of {target.hex().upper()} to {state_name}...{Config.Colors.ENDC}")
        cmd =f"80F000{state_byte:02X}{len(target):02X}{target.hex()}"
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
        cmd =f"80E6{p1:02X}00{len(data):02X}{data.hex()}"
        _ ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )

        if sw1 ==0x90 :
            print (f"{Config.Colors.GREEN}[+] Success.{Config.Colors.ENDC}")
            return True 
        else :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False 

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