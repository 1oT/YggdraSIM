import os
import math
from typing import Optional, List, Dict, Any

from SCP03.config import Config
from SCP03.core.utils import HexUtils, TlvParser
from SCP03.core.decoders import AdvancedDecoders
from SCP03.core.cap import CapFileParser
from SCP03.crypto.session import Scp03Session
from SCP03.logic.sgp22 import Sgp22Manager
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import cmac

class GlobalPlatformManager:
    def __init__(self, transport, config_keys):
        self.tp = transport
        self.raw_keys = config_keys 
        self.keys = {
            'kenc': HexUtils.to_bytes(config_keys.get('kenc', Config.DEFAULT_KEYS['kenc'])),
            'kmac': HexUtils.to_bytes(config_keys.get('kmac', Config.DEFAULT_KEYS['kmac'])),
            'dek':  HexUtils.to_bytes(config_keys.get('dek',  Config.DEFAULT_KEYS['dek']))
        }
        self.target_aid = HexUtils.to_bytes(config_keys.get('aid', Config.DEFAULT_KEYS['aid']))
        self.kvn = int(config_keys.get('kvn', Config.DEFAULT_KEYS['kvn']), 16)
        
        self.sgp22 = Sgp22Manager(transport)

    def verify_adm(self, key_hex: Optional[str] = None):
        target_key = key_hex
        if not target_key:
            target_key = self.raw_keys.get('adm')

        if not target_key:
            print(f"{Config.Colors.FAIL}[-] Error: No ADM key provided.{Config.Colors.ENDC}")
            return

        target_key = target_key.replace(' ', '')
        if len(target_key) != 16:
            print(f"{Config.Colors.WARNING}[!] Warning: ADM key should be 16 hex digits.{Config.Colors.ENDC}")

        if self.tp.session and self.tp.session.is_authenticated:
            print(f"{Config.Colors.WARNING}[!] Warning: Switching to MF will terminate SCP03 session.{Config.Colors.ENDC}")
            self.tp.session.is_authenticated = False

        print(f"{Config.Colors.CYAN}[*] Selecting MF (3F00)...{Config.Colors.ENDC}")
        self.tp.transmit("00A40004023F00", silent=True)

        cmd = f"0020000A{len(target_key)//2:02X}{target_key}"
        print(f"{Config.Colors.CYAN}[*] Verifying ADM...{Config.Colors.ENDC}")
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)

        if sw1 == 0x90:
            print(f"{Config.Colors.GREEN}[+] ADM Verified Successfully.{Config.Colors.ENDC}")
        elif sw1 == 0x63:
            retries = sw2 & 0x0F
            print(f"{Config.Colors.FAIL}[-] ADM Failed: Wrong code. Retries remaining: {retries}{Config.Colors.ENDC}")
        elif sw1 == 0x69 and sw2 == 0x83:
            print(f"{Config.Colors.FAIL}[-] ADM Failed: Key Blocked.{Config.Colors.ENDC}")
        else:
            print(f"{Config.Colors.FAIL}[-] ADM Failed: SW {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def authenticate(self) -> bool:
        """SCP03 Handshake."""
        if self.tp.session:
            self.tp.session.is_authenticated = False

        target_hex = self.target_aid.hex().upper()
        print(f"{Config.Colors.CYAN}[*] Authenticating to Security Domain: {target_hex}...{Config.Colors.ENDC}")
        
        self.tp.transmit(f"00A40400{len(self.target_aid):02X}{target_hex}", silent=True)

        host_challenge = os.urandom(8)
        cmd = f"8050000008{host_challenge.hex()}"
        data, sw1, sw2 = self.tp.transmit(cmd, silent=True)

        if sw1 != 0x90:
            print(f"{Config.Colors.FAIL}[-] INITIALIZE UPDATE Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False

        try:
            self.tp.session = Scp03Session(self.keys)
            self.tp.session.sec_level = 0x33 
            self.tp.session.derive_keys(host_challenge, data)
        except Exception as e:
            print(f"{Config.Colors.FAIL}[-] Key Derivation Failed: {e}{Config.Colors.ENDC}")
            return False

        host_crypto = self.tp.session.calculate_host_cryptogram()
        self.tp.session.chaining_value = b'\x00' * 16
        
        header = bytes([0x84, 0x82, 0x33, 0x00, 0x10])
        
        c_mac = cmac.CMAC(algorithms.AES(self.tp.session.s_mac))
        c_mac.update(self.tp.session.chaining_value + header + host_crypto)
        full_mac = c_mac.finalize()
        self.tp.session.chaining_value = full_mac 
        
        cmd_bytes = list(header) + list(host_crypto) + list(full_mac[:8])
        data, sw1, sw2 = self.tp.connection.transmit(cmd_bytes)
        
        if sw1 == 0x90:
            self.tp.session.ssc = 1
            self.tp.session.is_authenticated = True
            print(f"{Config.Colors.GREEN}[+] SCP03 Authenticated (Level 0x33){Config.Colors.ENDC}")
            self.get_keys_info(silent=True)
            return True
        else:
            self.tp.session.is_authenticated = False
            print(f"{Config.Colors.FAIL}[-] EXTERNAL AUTH Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False

    def store_data(self, data_hex: str, p1: Optional[int] = None, p2: Optional[int] = None):
        """
        GlobalPlatform STORE DATA (GPCS 11.11).
        Features automatic chunking if P1/P2 are not provided manually.
        """
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return

        payload = HexUtils.to_bytes(data_hex)
        
        if p1 is not None and p2 is not None:
            print(f"{Config.Colors.CYAN}[*] STORE DATA (P1={p1:02X}, P2={p2:02X}) Len={len(payload)}...{Config.Colors.ENDC}")
            cmd = f"80E2{p1:02X}{p2:02X}{len(payload):02X}{payload.hex()}"
            _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            if sw1 == 0x90:
                print(f"{Config.Colors.GREEN}[+] STORE DATA Success.{Config.Colors.ENDC}")
            else:
                print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return

        print(f"{Config.Colors.CYAN}[*] STORE DATA (Auto-chunking {len(payload)} bytes)...{Config.Colors.ENDC}")
        chunk_size = 240
        total_chunks = math.ceil(len(payload) / chunk_size)
        block_num = 0
        
        for i in range(total_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, len(payload))
            chunk = payload[start:end]
            
            p1_byte = 0x80
            if i >= total_chunks - 1:
                p1_byte = 0x00
                
            p2_byte = block_num % 256
            
            cmd = f"80E2{p1_byte:02X}{p2_byte:02X}{len(chunk):02X}{chunk.hex()}"
            _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            
            print(f"\r    Sending Block {i+1}/{total_chunks} [P1={p1_byte:02X} P2={p2_byte:02X}]...", end='', flush=True)
            
            if sw1 != 0x90:
                print(f"\n{Config.Colors.FAIL}[-] Failed at block {i+1}: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                return
                
            block_num += 1
            
        print(f"\n{Config.Colors.GREEN}[+] STORE DATA Success ({total_chunks} blocks).{Config.Colors.ENDC}")

    def put_key(self, old_kvn: int, key_id_start: int, new_kvn: int, new_keys: List[str]):
        """
        GlobalPlatform PUT KEY (GPCS 11.8).
        Rotates keys by encrypting the new key values with the current session's DEK.
        """
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return

        if len(new_keys) != 3:
            print(f"{Config.Colors.FAIL}[!] Error: PUT KEY requires 3 keys (ENC, MAC, DEK).{Config.Colors.ENDC}")
            return

        print(f"{Config.Colors.CYAN}[*] Rotating Keys (Replace KVN: {old_kvn:02X} -> New KVN: {new_kvn:02X})...{Config.Colors.ENDC}")
        
        payload = bytearray()
        payload.append(new_kvn) 
        
        for i, key_hex in enumerate(new_keys):
            raw_key = HexUtils.to_bytes(key_hex)
            if len(raw_key) != 16:
                print(f"{Config.Colors.FAIL}[!] Error: Key {i+1} must be 16 bytes (AES-128).{Config.Colors.ENDC}")
                return
            
            try:
                encrypted_key = self.tp.session.encrypt_key_data(raw_key)
            except Exception as e:
                print(f"{Config.Colors.FAIL}[!] DEK Encryption Failed: {e}{Config.Colors.ENDC}")
                return

            kcv_check = Cipher(algorithms.AES(raw_key), modes.ECB()).encryptor().update(b'\x00'*16)[:3]

            payload.append(0x88)
            payload.append(len(encrypted_key))
            payload.extend(encrypted_key)
            payload.append(len(kcv_check))
            payload.extend(kcv_check)

        cmd = f"80D8{old_kvn:02X}{key_id_start:02X}{len(payload):02X}{payload.hex()}"
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)

        if sw1 == 0x90:
            print(f"{Config.Colors.GREEN}[+] PUT KEY Success. New Keys active on next session.{Config.Colors.ENDC}")
        else:
            print(f"{Config.Colors.FAIL}[-] PUT KEY Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def install_cap_file(self, filename: str, privileges: str = "00", install_params: str = "C900", instantiate: bool = True, target_app_aid: str = None, target_module_aid: str = None):
        """
        GlobalPlatform INSTALL (GPCS 11.5).
        Handles INSTALL [for load], LOAD (80 E8), and INSTALL [for install].
        """
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(f"{Config.Colors.FAIL}[!] Error: Must be authenticated (AUTH) first.{Config.Colors.ENDC}")
            return

        if not os.path.exists(filename):
            print(f"{Config.Colors.FAIL}[!] File not found: {filename}{Config.Colors.ENDC}")
            return

        print(f"{Config.Colors.CYAN}[*] Parsing CAP file: {filename}...{Config.Colors.ENDC}")
        try:
            load_data, pkg_aid, app_aids = CapFileParser.parse(filename)
        except Exception as e:
            print(f"{Config.Colors.FAIL}[-] Parse Error: {e}{Config.Colors.ENDC}")
            return

        print(f"    Package AID: {pkg_aid.hex().upper()}")
        print(f"    Size: {len(load_data)} bytes")
        
        print(f"\n{Config.Colors.CYAN}[*] INSTALL [for load]...{Config.Colors.ENDC}")
        install_load_data = bytearray()
        install_load_data.append(len(pkg_aid))
        install_load_data.extend(pkg_aid)
        install_load_data.extend(b'\x00\x00\x00\x00') 

        cmd_hex = f"80E60200{len(install_load_data):02X}{install_load_data.hex()}"
        _, sw1, sw2 = self.tp.transmit(cmd_hex, silent=True)
        
        if sw1 != 0x90:
            print(f"{Config.Colors.FAIL}[-] Install [for load] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return

        print(f"{Config.Colors.CYAN}[*] Loading {len(load_data)} bytes...{Config.Colors.ENDC}")
        chunk_size = 240
        total_chunks = math.ceil(len(load_data) / chunk_size)
        
        for i in range(total_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, len(load_data))
            chunk = load_data[start:end]
            
            p1 = 0x00
            if i < total_chunks - 1:
                p1 = 0x80

            p2 = i % 256
            
            cmd = f"80E8{p1:02X}{p2:02X}{len(chunk):02X}{chunk.hex()}"
            _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            
            print(f"\r    Sending Block {i+1}/{total_chunks}...", end='', flush=True)
            
            if sw1 != 0x90:
                print(f"\n{Config.Colors.FAIL}[-] LOAD Failed at block {i}: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                return

        print(f"\n{Config.Colors.GREEN}[+] Load Complete.{Config.Colors.ENDC}")

        if not instantiate:
            print(f"{Config.Colors.CYAN}[*] Skipping instantiation (LOAD only mode).{Config.Colors.ENDC}")
            return

        if not app_aids and not target_app_aid:
            print(f"{Config.Colors.GREEN}[+] Library Loaded (No Applets to install).{Config.Colors.ENDC}")
            return

        applet_aid = app_aids[0]
        if target_app_aid:
            applet_aid = HexUtils.to_bytes(target_app_aid)

        module_aid = applet_aid
        if target_module_aid:
            module_aid = HexUtils.to_bytes(target_module_aid)

        print(f"{Config.Colors.CYAN}[*] INSTALL [for install] Applet: {applet_aid.hex().upper()}...{Config.Colors.ENDC}")
        print(f"    Module    : {module_aid.hex().upper()}")
        print(f"    Privileges: {privileges}")
        print(f"    Params    : {install_params}")

        priv_bytes = HexUtils.to_bytes(privileges)
        param_bytes = HexUtils.to_bytes(install_params)

        install_data = bytearray()
        install_data.append(len(pkg_aid))
        install_data.extend(pkg_aid)
        install_data.append(len(module_aid))
        install_data.extend(module_aid)
        install_data.append(len(applet_aid))
        install_data.extend(applet_aid)
        
        install_data.append(len(priv_bytes))
        install_data.extend(priv_bytes)
        install_data.append(len(param_bytes))
        install_data.extend(param_bytes)
        install_data.append(0x00)

        cmd = f"80E60C00{len(install_data):02X}{install_data.hex()}"
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)

        if sw1 == 0x90:
            print(f"{Config.Colors.GREEN}[+] Applet Installed Successfully.{Config.Colors.ENDC}")
        else:
            print(f"{Config.Colors.FAIL}[-] Install Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def get_keys_info(self, target_aid_hex: Optional[str] = None, silent=False):
        if target_aid_hex:
            if not silent: 
                print(f"{Config.Colors.CYAN}[*] Selecting AID: {target_aid_hex}...{Config.Colors.ENDC}")
            self.tp.transmit(f"00A40400{len(target_aid_hex)//2:02X}{target_aid_hex}", silent=True)
        else:
            if not self.tp.session or not self.tp.session.is_authenticated:
                aid_hex = self.target_aid.hex().upper()
                self.tp.transmit(f"00A40400{len(self.target_aid):02X}{aid_hex}", silent=True)

        if not silent: 
            print(f"{Config.Colors.CYAN}[*] Retrieving Key Information Template...{Config.Colors.ENDC}")
        
        data, sw1, sw2 = self.tp.transmit("80CA00E000", silent=silent)

        if sw1 == 0x90 and not silent:
            self._decode_key_template(data)
        elif sw1 != 0x90 and not silent:
            print(f"{Config.Colors.FAIL}[-] Error: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def list_registry(self, kind='APPS'):
        p1_map = {'APPS': 0x40, 'PACKAGES': 0x20, 'SD': 0x80}
        
        p1 = p1_map.get(kind, 0x40)
        p2 = 0x00
        full_data = bytearray()
        
        while True:
            cmd = f"80F2{p1:02X}{p2:02X}024F00"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=False)
            
            if (sw1 == 0x90 or sw1 == 0x63) and data:
                full_data.extend(data)
            
            if sw1 == 0x90:
                break
            elif sw1 == 0x63 and sw2 == 0x10:
                p2 += 1
            elif sw1 == 0x6A and sw2 == 0x88:
                if not full_data:
                    print(f"[-] No {kind} found in registry.")
                break
            else:
                print(f"{Config.Colors.FAIL}[-] Error listing registry: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                break
        
        if full_data:
            self._parse_registry_response(full_data, kind)

    def _parse_registry_response(self, data, kind):
        last_col = "Privileges"
        if kind == 'PACKAGES':
            last_col = "Assoc SD"
            
        print(f"\n{Config.Colors.HEADER}--- GlobalPlatform Registry ({kind}) ---{Config.Colors.ENDC}")
        print(f"{'AID':<34} | {'State':<12} | {last_col}")
        print("-" * 65)

        if any(b == 0xE3 for b in data):
            i = 0
            while i < len(data):
                if data[i] != 0xE3:
                    i += 1
                    continue
                tag_len = data[i+1]
                entry = data[i+2 : i+2+tag_len]
                i += 2 + tag_len
                parsed = TlvParser.parse(entry)
                
                aid = ""
                if 0x4F in parsed:
                    aid = parsed[0x4F].hex().upper()
                    
                lcs_byte = 0
                if 0x9F70 in parsed:
                    lcs_byte = parsed[0x9F70][0]
                    
                privs = ""
                if 0xC5 in parsed:
                    privs = parsed[0xC5].hex().upper()
                    
                self._print_registry_row(aid, lcs_byte, privs)
            return

        i = 0
        while i < len(data):
            try:
                if i < len(data) - 1:
                    length_byte = data[i]
                    next_byte = data[i+1]
                    if not ((5 <= length_byte <= 16) and (next_byte == 0xA0)):
                        i += 1
                        continue
                
                aid_len = data[i]
                i += 1
                if i + aid_len > len(data):
                    break
                aid = data[i : i + aid_len].hex().upper()
                i += aid_len
                
                state_byte = 0
                if i < len(data):
                    state_byte = data[i]
                i += 1
                
                extra_byte = 0
                if i < len(data):
                    extra_byte = data[i]
                i += 1
                
                extra_str = f"{extra_byte:02X}"
                
                if kind == 'PACKAGES' and extra_byte > 0:
                    extra_str = f"Len={extra_byte}"
                    i += extra_byte
                
                self._print_registry_row(aid, state_byte, extra_str)
            except IndexError:
                break

    def _print_registry_row(self, aid, lcs_byte, extra):
        state_map = {
            0x00: "LOADED",
            0x01: "OP_READY",
            0x03: "INSTALLED",
            0x07: "SELECTABLE",
            0x0F: "PERSONALIZED",
            0x80: "LOCKED",
            0x83: "TERMINATED"
        }
        
        state_str = state_map.get(lcs_byte, f"0x{lcs_byte:02X}")
        print(f"{aid:<34} | {state_str:<12} | {extra}")

    def _decode_key_template(self, data: bytes):
        from SCP03.config import Config
        print(f"\n{Config.Colors.HEADER}--- Card Key Registry ---{Config.Colors.ENDC}")
        print(f"{'Version':<10} | {'ID':<10} | {'Type':<12} | {'Length'}")
        print("-" * 50)
        found = False
        i = 0
        while i < len(data) - 5:
            if data[i] == 0xC0 and data[i+1] == 0x04:
                kid = data[i+2]
                kver = data[i+3]
                ktype = data[i+4]
                klen = data[i+5]
                type_map = {
                    0x80: "DES",
                    0x81: "DES",
                    0x88: "AES",
                    0xFF: "Ext"
                }
                
                t_str = type_map.get(ktype, f"0x{ktype:02X}")
                print(f"0x{kver:02X} ({kver:<3}) | 0x{kid:02X} ({kid:<3}) | {t_str:<12} | {klen}")
                found = True
                i += 6 
            else:
                i += 1
        
        if not found:
            print("  (No valid keys detected or parsing failed)")
        print("-" * 50 + "\n")

    def get_cplc(self):
        cmd = "80CA9F7F00"
        data, sw1, sw2 = self.tp.transmit(cmd, silent=False)
        if sw1 == 0x90: 
            AdvancedDecoders.print_cplc(data)
        else:
             print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def get_data(self, p1: int, p2: int):
        print(f"{Config.Colors.CYAN}[*] GET DATA Tag: {p1:02X}{p2:02X}...{Config.Colors.ENDC}")
        
        if p1 == 0x2F and p2 == 0x00:
            cmd = f"80CA{p1:02X}{p2:02X}025C0000"
        else:
            cmd = f"80CA{p1:02X}{p2:02X}00"
        
        data, sw1, sw2 = self.tp.transmit(cmd, silent=False)
        
        if sw1 == 0x90:
            try:
                parsed = TlvParser.parse(data)
                self.print_tlv_data(parsed)
            except Exception as e:
                pass
        else:
            err_map = {
                0x6A88: "Referenced Data Not Found (Tag not supported or empty)",
                0x6A81: "Function Not Supported",
                0x6982: "Security Status Unsatisfied",
                0x6985: "Conditions Not Satisfied"
            }
            sw_full = (sw1 << 8) | sw2
            err_msg = err_map.get(sw_full, "Unknown Error")
            print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X} -> {err_msg}{Config.Colors.ENDC}")

    def print_tlv_data(self, tlv_dict: Dict[int, Any], indent: int = 0):
        indent_str = "  " * indent
        for tag, val in tlv_dict.items():
            tag_hex = f"{tag:02X}" if tag <= 0xFF else f"{tag:04X}"
            
            if isinstance(val, dict):
                print(f"{indent_str}{Config.Colors.BOLD}Tag {tag_hex}:{Config.Colors.ENDC}")
                self.print_tlv_data(val, indent + 1)
            elif isinstance(val, bytes):
                val_hex = val.hex().upper()
                ascii_str = ""
                try:
                    s = val.decode('utf-8', 'ignore')
                    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.:/,")
                    if len(s) > 1 and all(c in safe_chars for c in s):
                        ascii_str = f" ('{s}')"
                except:
                    pass
                
                print(f"{indent_str}Tag {tag_hex} (L={len(val)}): {val_hex}{ascii_str}")

    def set_status(self, target_aid, state_byte: int):
        target = HexUtils.to_bytes(target_aid)
        state_name = f"{state_byte:02X}"
        if state_byte == 0x80:
            state_name = "LOCKED"
        elif state_byte == 0x07:
            state_name = "SELECTABLE"
            
        print(f"{Config.Colors.CYAN}[*] Setting Status of {target.hex().upper()} to {state_name}...{Config.Colors.ENDC}")
        cmd = f"80F000{state_byte:02X}{len(target):02X}{target.hex()}"
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        if sw1 == 0x90:
            print(f"{Config.Colors.GREEN}[+] Status Updated.{Config.Colors.ENDC}")
        else:
            print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def delete_object(self, target_aid, recursive=True):
        target = HexUtils.to_bytes(target_aid)
        p2 = 0x00
        if recursive:
            p2 = 0x80
            
        tlv = f"4F{len(target):02X}{target.hex()}"
        cmd = f"80E400{p2:02X}{len(bytes.fromhex(tlv)):02X}{tlv}"
        print(f"{Config.Colors.WARNING}[!] Deleting {target.hex()}...{Config.Colors.ENDC}")
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        if sw1 == 0x90:
            print(f"{Config.Colors.GREEN}[+] Deleted.{Config.Colors.ENDC}")
        else:
            print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def _send_install_cmd(self, p1: int, data: bytes, description: str) -> bool:
        """Generic helper for INSTALL commands."""
        print(f"{Config.Colors.CYAN}[*] INSTALL [{description}]...{Config.Colors.ENDC}")
        cmd = f"80E6{p1:02X}00{len(data):02X}{data.hex()}"
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        
        if sw1 == 0x90:
            print(f"{Config.Colors.GREEN}[+] Success.{Config.Colors.ENDC}")
            return True
        else:
            print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False

    def install_make_selectable(self, aid_hex: str, privileges: str = "00"):
        """GP INSTALL [for make selectable] (P1=0x08)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return

        aid_bytes = HexUtils.to_bytes(aid_hex)
        priv_bytes = HexUtils.to_bytes(privileges)

        payload = bytearray()
        payload.append(0x00) 
        payload.append(len(aid_bytes))
        payload.extend(aid_bytes) 
        payload.append(len(priv_bytes))
        payload.extend(priv_bytes) 
        payload.append(0x00) 
        payload.append(0x00) 

        self._send_install_cmd(0x08, payload, "Make Selectable")

    def install_extradition(self, aid_hex: str, sd_aid_hex: str):
        """GP INSTALL [for extradition] (P1=0x10)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return

        aid_bytes = HexUtils.to_bytes(aid_hex)
        sd_bytes = HexUtils.to_bytes(sd_aid_hex)

        payload = bytearray()
        payload.append(len(sd_bytes))
        payload.extend(sd_bytes) 
        payload.append(0x00) 
        payload.append(len(aid_bytes))
        payload.extend(aid_bytes) 
        payload.append(0x00)
        payload.append(0x00)

        self._send_install_cmd(0x10, payload, "Extradition")

    def install_personalization(self, aid_hex: str):
        """GP INSTALL [for personalization] (P1=0x20)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return
            
        aid_bytes = HexUtils.to_bytes(aid_hex)
        
        payload = bytearray()
        payload.append(0x00)
        payload.append(len(aid_bytes))
        payload.extend(aid_bytes)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)

        self._send_install_cmd(0x20, payload, "Personalization")

    def get_ecasd_data(self):
        """Retrieves SGP.02/SGP.22 metadata from ECASD."""
        ECASD_AID = "A0000005591010FFFFFFFF8900000200"
        
        print(f"{Config.Colors.CYAN}[*] Selecting ECASD...{Config.Colors.ENDC}")
        self.tp.transmit(f"00A40400{len(ECASD_AID)//2:02X}{ECASD_AID}", silent=True)
        
        queries = {
            "EID (5A)": "5A",
            "CIN (45)": "45",
            "IIN (42)": "42",
            "CPLC (9F7F)": "9F7F",
            "Key Info (E0)": "E0" 
        }

        print(f"{Config.Colors.HEADER}--- ECASD Data (SGP.02/22) ---{Config.Colors.ENDC}")
        
        for label, tag in queries.items():
            cmd = f"80CA{tag}00"
            if len(tag) > 2:
                cmd = f"80CA{tag}00"
            
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            if sw1 == 0x90 or sw1 == 0x61:
                hex_val = data.hex().upper()
                parsed = TlvParser.parse(data)
                
                tag_int = int(tag, 16)
                if tag_int in parsed:
                     val = parsed[tag_int]
                     if isinstance(val, bytes):
                         hex_val = val.hex().upper()
                
                print(f"{label:<15}: {hex_val}")
            else:
                print(f"{label:<15}: {Config.Colors.FAIL}Not Found / Error {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def install_app(self, pkg_aid_hex: str, app_aid_hex: str, mod_aid_hex: Optional[str] = None, privileges: str = "00", params: str = "C900", make_selectable: bool = True):
        """GP INSTALL [for install] / [for install and make selectable] (P1=0x04 / 0x0C)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return

        pkg_bytes = HexUtils.to_bytes(pkg_aid_hex)
        app_bytes = HexUtils.to_bytes(app_aid_hex)
        
        mod_bytes = app_bytes
        if mod_aid_hex:
            mod_bytes = HexUtils.to_bytes(mod_aid_hex)
            
        priv_bytes = HexUtils.to_bytes(privileges)
        param_bytes = HexUtils.to_bytes(params)

        payload = bytearray()
        payload.append(len(pkg_bytes))
        payload.extend(pkg_bytes)
        payload.append(len(mod_bytes))
        payload.extend(mod_bytes)
        payload.append(len(app_bytes))
        payload.extend(app_bytes)
        payload.append(len(priv_bytes))
        payload.extend(priv_bytes)
        payload.append(len(param_bytes))
        payload.extend(param_bytes)
        payload.append(0x00)

        p1 = 0x04
        desc = "Install"
        if make_selectable:
            p1 = 0x0C
            desc = "Install and Make Selectable"

        self._send_install_cmd(p1, payload, desc)

    def install_registry_update(self, aid_hex: str, privileges: str = "00", params: str = ""):
        """GP INSTALL [for registry update] (P1=0x40)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}")
            return

        aid_bytes = HexUtils.to_bytes(aid_hex)
        priv_bytes = HexUtils.to_bytes(privileges)
        param_bytes = b''
        if params:
            param_bytes = HexUtils.to_bytes(params)

        payload = bytearray()
        payload.append(0x00) 
        payload.append(0x00) 
        payload.append(len(aid_bytes))
        payload.extend(aid_bytes)
        payload.append(len(priv_bytes))
        payload.extend(priv_bytes)
        payload.append(len(param_bytes))
        payload.extend(param_bytes)
        payload.append(0x00) 

        self._send_install_cmd(0x40, payload, "Registry Update")