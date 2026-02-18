from typing import List, Dict, Optional, Tuple
from SCP03.config import Config
from SCP03.core.utils import HexUtils, TlvParser

class Sgp22Manager:
    """
    Implements GSMA SGP.22 ES10c (Local Profile Management).
    Target: ISD-R (A0000005591010FFFFFFFF8900000100)
    """
    AID_ISD_R = "A0000005591010FFFFFFFF8900000100"
    
    # Tags
    TAG_GET_PROFILES_INFO = 0xBF2D
    TAG_ENABLE_PROFILE    = 0xBF31
    TAG_DISABLE_PROFILE   = 0xBF32
    TAG_DELETE_PROFILE    = 0xBF33
    TAG_RESULT            = 0x80
    
    # Identifiers
    TAG_CTX_0    = 0xA0 # ProfileId Choice
    TAG_CTX_1    = 0xA1 # Refresh Flag (Context 1)
    TAG_AID      = 0x4F 
    TAG_ICCID    = 0x5A 
    
    # Profile Info
    TAG_E3       = 0xE3 # ProfileInfo Sequence
    TAG_STATE    = 0x9F70
    TAG_NICKNAME = 0x90
    TAG_SP_NAME  = 0x91 
    TAG_NAME     = 0x92 
    TAG_CLASS    = 0x95
    TAG_BOOLEAN  = 0x01

    def __init__(self, transport):
        self.tp = transport
        self.profile_cache: Dict[str, Tuple[int, str]] = {} 

    def _select_isd_r(self):
        print(f"{Config.Colors.CYAN}[*] Selecting ISD-R (SGP.22)...{Config.Colors.ENDC}")
        cmd = f"00A40400{len(self.AID_ISD_R)//2:02X}{self.AID_ISD_R}"
        self.tp.transmit(cmd, silent=True)

    def list_profiles(self):
        self._select_isd_r()
        # GetProfilesInfo (BF 2D 00)
        payload = "BF2D00"
        cmd = f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        
        print(f"{Config.Colors.CYAN}[*] Retrieving Profile List (ES10c)...{Config.Colors.ENDC}")
        data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        
        # Consistent [<--] Format
        print(f"{Config.Colors.BLUE}[<--]{Config.Colors.ENDC} {data.hex().upper()} {sw1:02X}{sw2:02X}")
        
        if sw1 != 0x90:
            print(f"{Config.Colors.FAIL}[-] GetProfilesInfo Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return

        self._parse_profile_list(data)

    def _swap_nibbles(self, s: str) -> str:
        if not s: return ""
        res = []
        for i in range(0, len(s), 2):
            if i+1 < len(s): res.append(s[i+1] + s[i])
            else: res.append(s[i])
        return "".join(res).replace('F', '')

    def _parse_profile_list(self, data: bytes):
        print(f"\n{Config.Colors.HEADER}--- eSIM Profiles (SGP.22) ---{Config.Colors.ENDC}")
        print(f"{'State':<9} | {'Class':<5} | {'ICCID':<20} | {'Name / Provider':<25} | {'AID'}")
        print("-" * 115)

        self.profile_cache = {} 
        
        i = 0
        while i < len(data):
            if data[i] == 0xE3:
                length = data[i+1]
                offset = 2
                if length & 0x80:
                    n = length & 0x7F
                    length = int.from_bytes(data[i+2:i+2+n], 'big')
                    offset = 2 + n
                
                profile_blob = data[i+offset : i+offset+length]
                self._print_single_profile(profile_blob)
                i += offset + length
            else:
                i += 1

    def _print_single_profile(self, data: bytes):
        info = TlvParser.parse(data)
        
        aid_bytes = info.get(self.TAG_AID) or info.get(self.TAG_CTX_0)
        iccid_bytes = info.get(self.TAG_ICCID)
        
        aid_hex = aid_bytes.hex().upper() if isinstance(aid_bytes, bytes) else ""
        iccid_raw = iccid_bytes.hex().upper() if isinstance(iccid_bytes, bytes) else ""
        iccid_display = self._swap_nibbles(iccid_raw)

        state_val = info.get(self.TAG_STATE, b'\x00')
        state_int = int.from_bytes(state_val, 'big') if isinstance(state_val, bytes) else 0
        state_str = f"{Config.Colors.GREEN}ENABLED  {Config.Colors.ENDC}" if state_int == 1 else "DISABLED "

        class_val = info.get(self.TAG_CLASS, b'\x02')
        class_int = int.from_bytes(class_val, 'big') if isinstance(class_val, bytes) else 2
        class_map = {0: 'TEST ', 1: 'PROV ', 2: 'OPER '}
        class_str = class_map.get(class_int, 'UNK  ')

        name_bytes = info.get(self.TAG_NICKNAME) or info.get(self.TAG_NAME) or info.get(self.TAG_SP_NAME)
        name_str = "Unknown"
        if isinstance(name_bytes, bytes):
            try: name_str = name_bytes.decode('utf-8', 'ignore').strip()
            except: name_str = name_bytes.hex()
        
        if name_str == "Unknown" and iccid_display:
            name_str = f"ICCID-{iccid_display[-4:]}"

        print(f"{state_str} | {class_str} | {iccid_display:<20} | {name_str:<25} | {aid_hex}")

        if aid_hex:
            entry = (self.TAG_AID, aid_hex)
            self.profile_cache[name_str.upper()] = entry
            self.profile_cache[aid_hex] = entry
        elif iccid_raw:
            entry = (self.TAG_ICCID, iccid_raw)
            self.profile_cache[name_str.upper()] = entry

        if iccid_raw:
            self.profile_cache[iccid_display] = (self.TAG_ICCID, iccid_raw)

    def enable_profile(self, identifier: str) -> bool:
        return self._send_cmd(identifier, self.TAG_ENABLE_PROFILE, "Enabling")

    def disable_profile(self, identifier: str) -> bool:
        return self._send_cmd(identifier, self.TAG_DISABLE_PROFILE, "Disabling")

    def delete_profile(self, identifier: str) -> bool:
        return self._send_cmd(identifier, self.TAG_DELETE_PROFILE, "Deleting")

    def _send_cmd(self, identifier: str, func_tag: int, action_str: str) -> bool:
        resolved = self._resolve_target(identifier)
        if not resolved: return False
        
        tag_type, value_hex = resolved
        type_lbl = "ICCID" if tag_type == self.TAG_ICCID else "AID"
        print(f"{Config.Colors.CYAN}[*] {action_str} Profile ({type_lbl}): {value_hex}...{Config.Colors.ENDC}")
        
        self._select_isd_r()
        
        val_bytes = bytes.fromhex(value_hex)
        
        tlv_id = bytes([tag_type, len(val_bytes)]) + val_bytes
        tlv_choice = bytes([self.TAG_CTX_0, len(tlv_id)]) + tlv_id
        
        # Refresh Flag (False) -> Implicit [81]
        tlv_refresh = bytes([self.TAG_CTX_1, 0x01, 0x00])
        
        inner = tlv_choice + tlv_refresh
        payload = bytes([func_tag >> 8, func_tag & 0xFF, len(inner)]) + inner
        
        cmd = f"80E29100{len(payload):02X}{payload.hex()}"
        
        # Consistent [<--] is handled inside _check_result or explicitly here? 
        # Commands like Enable/Disable return STATUS mainly, so we might not want huge dumps unless error.
        # But user said "everything incoming".
        data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        print(f"{Config.Colors.BLUE}[<--]{Config.Colors.ENDC} {data.hex().upper()} {sw1:02X}{sw2:02X}")
        
        return self._check_result(data, sw1, sw2, func_tag)

    def _check_result(self, data, sw1, sw2, outer_tag) -> bool:
        if sw1 != 0x90 and sw1 != 0x91:
            print(f"{Config.Colors.FAIL}[-] APDU Transport Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False
            
        if sw1 == 0x91:
            print(f"{Config.Colors.WARNING}[*] Proactive Command Pending (SW=91{sw2:02X}) - Assuming Success.{Config.Colors.ENDC}")

        parsed = TlvParser.parse(data)
        outer = parsed.get(outer_tag)
        content = outer if isinstance(outer, dict) else (TlvParser.parse(outer) if isinstance(outer, bytes) else parsed)

        if self.TAG_RESULT in content:
            val = content[self.TAG_RESULT]
            res_code = int.from_bytes(val, 'big') if isinstance(val, bytes) else 0
            
            if res_code == 0:
                print(f"{Config.Colors.GREEN}[+] Operation Successful.{Config.Colors.ENDC}")
                return True
            else:
                errs = {1: "Profile Not Found", 2: "Already in State", 7: "Command Error (Struct)", 127: "Generic/Refresh Error"}
                print(f"{Config.Colors.FAIL}[-] SGP.22 Error 0x{res_code:02X}: {errs.get(res_code, 'Unknown')}{Config.Colors.ENDC}")
                return False
        
        print(f"{Config.Colors.GREEN}[+] APDU Success (No ES10c Result Code).{Config.Colors.ENDC}")
        return True

    def _resolve_target(self, identifier: str) -> Optional[Tuple[int, str]]:
        clean = identifier.strip().upper()
        
        if clean in self.profile_cache: return self.profile_cache[clean]
        
        if clean.startswith("A0") and len(clean) >= 10: return (self.TAG_AID, clean)
        
        if (clean.startswith("89") or clean.startswith("98")) and len(clean) >= 18:
            if clean.startswith("89"):
                return (self.TAG_ICCID, self._swap_nibbles(clean))
            else:
                return (self.TAG_ICCID, clean)

        print(f"{Config.Colors.FAIL}[!] Unknown Profile: '{identifier}'. Run LIST first.{Config.Colors.ENDC}")
        return None