# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

from typing import List, Dict, Optional, Tuple, Any
from SCP03.config import Config
from SCP03.core.utils import HexUtils, TlvParser

class Sgp22Manager:
    """
    Implements GSMA SGP.22/SGP.32 data retrieval and local profile state (list, enable, disable, delete).
    Supports ES10c/ES10b retrieval: GetProfilesInfo, GetRAT, RetrieveNotificationsList,
    GetEimConfigurationData (SGP.32 IoT), EuiccInfo1/2, EuiccConfiguredData.
    Does NOT authenticate to ISD-R for provisioning (StoreMetadata, LoadProfile, PrepareDownload, etc.);
    that is planned for the SCP11 module.
    """
    AID_ISD_R = "A0000005591010FFFFFFFF8900000100"
    
    # --- Tag Constants ---
    TAG_GET_PROFILES_INFO = 0xBF2D
    TAG_ENABLE_PROFILE    = 0xBF31
    TAG_DISABLE_PROFILE   = 0xBF32
    TAG_DELETE_PROFILE    = 0xBF33
    TAG_RESULT            = 0x80
    
    # Context specific tags
    TAG_CTX_0    = 0xA0 
    TAG_CTX_1    = 0xA1 
    TAG_AID      = 0x4F 
    TAG_ICCID    = 0x5A 
    TAG_STATE    = 0x9F70
    TAG_NICKNAME = 0x90
    TAG_SP_NAME  = 0x91 
    TAG_NAME     = 0x92 
    TAG_CLASS    = 0x95

    # --- Scanning Sequences ---
    SEQUENCE_SGP22 = [
        ("0070000001", "OPEN CHANNEL"),
        ("01A4040010A0000005591010FFFFFFFF8900000200", "Select ECASD"),
        ("01CA005A00", "EID"),
        ("01A4040010A0000005591010FFFFFFFF8900000100", "Select ISDR"),
        ("81E2910003BF2D00", "List Profiles"),
        ("81E2910003BF3C00", "EuiccConfiguredData"),
        ("81E2910003BF2000", "EuiccInfo1"),
        ("81E2910003BF2200", "EuiccInfo2"),
        ("81CA00E000", "Key Information Template"),
        ("81CA006600", "Security Domain Mgmt Data"),
        ("0070800100", "CLOSE CHANNEL")
    ]

    SEQUENCE_SGP02 = [
        ("0070000001", "OPEN CHANNEL"),
        ("01A4040010A0000005591010FFFFFFFF8900000200", "Select eCASD"),
        ("01CA005A00", "EID (SGP.02)"),
        ("01A4040010A0000005591010FFFFFFFF8900000100", "Select ISDR"),
        ("81CABF30035C0166", "ECASD Recognition Data"),
        ("81CABF30045C027F21", "ECASD Certificate Store"),
        ("81F2400000", "List Profiles (SGP.02)"),
        ("81CA00E000", "Key Information Template"),
        ("81CA006600", "Security Domain Mgmt Data"),
        ("81CA006700", "Card Capability Info"),
        ("81CA2F00025C0000", "List Apps in SD"),
        ("0070800100", "CLOSE CHANNEL")
    ]

    def __init__(self, transport):
        self.tp = transport
        self.profile_cache: Dict[str, Tuple[int, str]] = {} 

    # --- Scanning Logic ---

    def run_sgp22_scan(self):
        """Executes the custom SGP.22/SGP.32 scanning sequence."""
        self._execute_sequence(self.SEQUENCE_SGP22, "SGP.22/SGP.32 Scan")

    def run_sgp02_scan(self):
        """Executes the custom SGP.02 scanning sequence."""
        self._execute_sequence(self.SEQUENCE_SGP02, "SGP.02 Scan")

    def get_euicc_report(self) -> Dict[str, Any]:
        """
        Runs SGP.22 sequence and returns structured data for export (no print).
        Returns dict with: profiles, eid, euicc_info1, euicc_info2, euicc_configured_data,
        key_info, sd_mgmt_data (hex strings where applicable).
        """
        collected = self._run_sequence_collect(self.SEQUENCE_SGP22)
        report = {
            "profiles": [],
            "eid": collected.get("EID", ""),
            "euicc_info1": collected.get("EuiccInfo1", ""),
            "euicc_info2": collected.get("EuiccInfo2", ""),
            "euicc_configured_data": collected.get("EuiccConfiguredData", ""),
            "key_info": collected.get("Key Information Template", ""),
            "sd_mgmt_data": collected.get("Security Domain Mgmt Data", ""),
        }
        list_hex = collected.get("List Profiles", "")
        if list_hex:
            try:
                data = bytes.fromhex(list_hex)
                report["profiles"] = self._profile_list_to_dicts(data)
            except Exception:
                report["profiles"] = []
        return report

    def _profile_list_to_dicts(self, data: bytes) -> List[Dict]:
        """Parse BF2D profile list response into list of dicts."""
        out = []
        i = 0
        while i < len(data):
            if data[i] == 0xE3:
                length = data[i + 1]
                offset = 2
                if length & 0x80:
                    n = length & 0x7F
                    length = int.from_bytes(data[i + 2 : i + 2 + n], "big")
                    offset = 2 + n
                blob = data[i + offset : i + offset + length]
                entry = self._single_profile_to_dict(blob)
                if entry:
                    out.append(entry)
                i += offset + length
            else:
                i += 1
        return out

    def _single_profile_to_dict(self, data: bytes) -> Optional[Dict]:
        """Convert one profile TLV blob to dict."""
        try:
            info = TlvParser.parse(data)
            aid_bytes = info.get(self.TAG_AID) or info.get(self.TAG_CTX_0)
            iccid_bytes = info.get(self.TAG_ICCID)
            if isinstance(aid_bytes, list) and len(aid_bytes) > 0:
                aid_bytes = aid_bytes[0]
            if isinstance(iccid_bytes, list) and len(iccid_bytes) > 0:
                iccid_bytes = iccid_bytes[0]
            aid_hex = aid_bytes.hex().upper() if isinstance(aid_bytes, bytes) else ""
            iccid_raw = iccid_bytes.hex().upper() if isinstance(iccid_bytes, bytes) else ""
            iccid_display = self._swap_nibbles(iccid_raw)
            state_val = info.get(self.TAG_STATE, b"\x00")
            state_int = int.from_bytes(state_val, "big") if isinstance(state_val, bytes) else 0
            state_str = "ENABLED" if state_int == 1 else "DISABLED"
            class_val = info.get(self.TAG_CLASS, b"\x02")
            class_int = int.from_bytes(class_val, "big") if isinstance(class_val, bytes) else 2
            class_map = {0: "TEST", 1: "PROV", 2: "OPER"}
            class_str = class_map.get(class_int, "OPER")
            name_bytes = info.get(self.TAG_NICKNAME) or info.get(self.TAG_NAME) or info.get(self.TAG_SP_NAME)
            name_str = "Unknown"
            if isinstance(name_bytes, bytes):
                try:
                    name_str = name_bytes.decode("utf-8", "ignore").strip()
                except Exception:
                    name_str = name_bytes.hex()
            if name_str == "Unknown" and iccid_display:
                name_str = f"ICCID-{iccid_display[-4:]}"
            return {
                "state": state_str,
                "class": class_str,
                "iccid": iccid_display,
                "name": name_str,
                "aid": aid_hex,
            }
        except Exception:
            return None

    def _run_sequence_collect(self, sequence: List[Tuple[str, str]]) -> Dict[str, str]:
        """Run sequence and return dict of description -> response hex (successful only)."""
        channel_id = 0
        result = {}
        for apdu_hex, desc in sequence:
            if desc == "OPEN CHANNEL":
                resp, sw1, sw2 = self.tp.transmit(apdu_hex, silent=True)
                if sw1 == 0x90 and len(resp) >= 1:
                    channel_id = resp[0]
                else:
                    return result
                continue
            cmd_bytes = bytearray(HexUtils.to_bytes(apdu_hex))
            if desc == "CLOSE CHANNEL":
                if len(cmd_bytes) >= 4:
                    cmd_bytes[3] = channel_id
            elif channel_id > 0:
                if not (cmd_bytes[0] == 0x00 and cmd_bytes[1] == 0x70):
                    cmd_bytes[0] = (cmd_bytes[0] & 0xF0) | channel_id
            resp, sw1, sw2 = self.tp.transmit(cmd_bytes.hex().upper(), silent=True)
            if sw1 == 0x90 or sw1 == 0x61:
                if resp:
                    result[desc] = resp.hex().upper()
        return result

    def _execute_sequence(self, sequence, title):
        print(f"\n{Config.Colors.HEADER}=== Running {title} ==={Config.Colors.ENDC}")
        channel_id = 0
        
        for i, (apdu_hex, desc) in enumerate(sequence):
            is_admin = any(x in desc.upper() for x in ["OPEN CHANNEL", "CLOSE CHANNEL", "SELECT "])
            
            if desc == "OPEN CHANNEL":
                resp, sw1, sw2 = self.tp.transmit(apdu_hex, silent=True)
                if sw1 == 0x90 and len(resp) >= 1: channel_id = resp[0]
                else: 
                    print(f"{Config.Colors.FAIL}[!] OPEN CHANNEL Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                    return 
                continue

            # Patch Channel
            cmd_bytes = bytearray(HexUtils.to_bytes(apdu_hex))
            if desc == "CLOSE CHANNEL":
                if len(cmd_bytes) >= 4: cmd_bytes[3] = channel_id
            elif channel_id > 0:
                if not (cmd_bytes[0] == 0x00 and cmd_bytes[1] == 0x70):
                    cmd_bytes[0] = (cmd_bytes[0] & 0xF0) | channel_id
            
            resp, sw1, sw2 = self.tp.transmit(cmd_bytes.hex().upper(), silent=True)
            
            if is_admin:
                if sw1 != 0x90 and sw1 != 0x61:
                    print(f"{Config.Colors.FAIL}[-] {desc} Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                continue 

            print(f"\n{Config.Colors.BOLD}[+] {desc}{Config.Colors.ENDC}")
            
            if sw1 == 0x90 or sw1 == 0x61: 
                if "List Profiles" in desc and "SGP.02" not in desc:
                    self._parse_profile_list(resp)
                elif "EID" in desc:
                     print(f"    | {resp.hex().upper()}")
                elif resp:
                    try:
                        # Determine root context
                        root_tag = None
                        if "EuiccConfiguredData" in desc: root_tag = 0xBF3C
                        elif "EuiccInfo1" in desc: root_tag = 0xBF20
                        elif "EuiccInfo2" in desc: root_tag = 0xBF22
                        elif "Key Information" in desc: root_tag = 0xE0
                        elif "Security Domain" in desc: root_tag = 0x66
                        elif "Card Capability" in desc: root_tag = 0x67
                        
                        parsed = TlvParser.parse(resp)
                        self._print_tlv_tree(parsed, indent=1, parent_tag=root_tag)
                    except:
                         print(f"    | {resp.hex().upper()}")
                else:
                    print("    | (Empty)")
            else:
                print(f"    | {Config.Colors.FAIL}Status: {sw1:02X}{sw2:02X} (Not Found / Error){Config.Colors.ENDC}")

    # --- Refined Decoders ---

    def _resolve_tag_name(self, tag: int, parent: Optional[int]) -> str:
        """Context-aware tag naming for SGP.22 & GlobalPlatform."""
        
        # Context: EuiccConfiguredData (BF3C)
        if parent == 0xBF3C:
            if tag == 0x80: return "SM-DP+ Address"
            if tag == 0x81: return "SM-DS Address"

        # Context: Extended Card Resources (84)
        if parent == 0x84:
            if tag == 0x81: return "Installed Apps"
            if tag == 0x82: return "Free NVM"
            if tag == 0x83: return "Free RAM"

        # Context: EuiccInfo1/2 (BF20/BF22) and children
        if parent in [0xBF20, 0xBF22, 0xA9, 0xAA, 0xB4, 0xAF, 0xA0]:
            if tag == 0x82: return "Ver Supported"
            if tag == 0x81: return "Profile Version"
            if tag == 0x83: return "Firmware Ver"
            if tag == 0x84: return "Ext Card Res"
            if tag == 0x85: return "UICC Cap"
            if tag == 0x86: return "TSCP Base"
            if tag == 0x87: return "eUICC Category"
            if tag == 0x88: return "PP Rules"
            if tag == 0x99: return "PP Version"
            if tag == 0x0C: return "SAS Accr No"
            if tag == 0xA9: return "CI PK (Verif)"
            if tag == 0xAA: return "CI PK (Sign)"
            if tag == 0x04: return "Value"
            if tag == 0xAF: return "Forbidden Rules"
            if tag == 0x90: return "Nickname"
            if tag == 0xB4: return "Device Capability"
            if tag == 0xA0: return "GSM/LTE Cap" 
            if tag == 0x89: return "12V Support"

        # Context: Key Info
        if parent == 0xE0:
            if tag == 0xC0: return "Key Info"

        # Context: Security Domain Management (Recursively inside 66/73/60/63/64)
        if parent in [0x66, 0x73, 0x60, 0x63, 0x64]:
            if tag == 0x73: return "SD Mgmt Data"
            if tag == 0x06: return "OID"
            if tag == 0x60: return "Card Mgmt"
            if tag == 0x63: return "Content Mgmt"
            if tag == 0x64: return "Security Mgmt"
            if tag == 0x65: return "App Lifecycle"
            if tag == 0x66: return "Card Lifecycle"

        # Global / Fallbacks
        if tag == 0x5A: return "EID/ICCID"
        if tag == 0x4F: return "AID"
        if tag == 0xBF20: return "EuiccInfo1"
        if tag == 0xBF22: return "EuiccInfo2"
        if tag == 0xBF3C: return "EuiccConfiguredData"
        if tag == 0xBF43: return "RAT (Rules Authorisation Table)"
        if tag == 0xBF2B: return "NotificationsList"
        if tag == 0xBF55: return "EimConfigurationData"
        if tag == 0xE0: return "Key Info Template"
        if tag == 0x66: return "SD Mgmt Data"
        if tag == 0x67: return "Card Cap Info"

        common = {
            0x9F70: "State", 0x90: "Nickname", 0x91: "Svc Provider",
            0x92: "Profile Name", 0x95: "Profile Class"
        }
        return common.get(tag, f"{tag:02X}")

    def _decode_value(self, tag: int, val: bytes, parent_tag: Optional[int]) -> str:
        """Heuristic value decoder."""
        hex_str = val.hex().upper()
        
        # 1. Integers (Memory/Count in Ext Card Res)
        if parent_tag == 0x84 and tag in [0x81, 0x82, 0x83]:
            int_val = int.from_bytes(val, 'big')
            if tag == 0x81: return str(int_val)
            # Format bytes
            if int_val < 1024: return f"{int_val} B"
            return f"{int_val/1024:.1f} KB"

        # 2. Version Numbers (3 bytes)
        # 81 (ProfVer), 82 (VerSup), 86 (TSCP), 87 (Category), 88 (PPrules), 99 (PPver)
        is_version_tag = tag in [0x81, 0x82, 0x86, 0x87, 0x88, 0x99]
        if len(val) == 3 and (is_version_tag or (tag == 0x04 and parent_tag == 0xA0)):
            return f"v{val[0]}.{val[1]}.{val[2]} ({hex_str})"

        # 3. Key Info (C0)
        if tag == 0xC0 and len(val) == 4:
            k_type_map = {0x88: 'AES', 0x80: 'DES', 0x81: '3DES', 0x82: 'RSA'}
            k_type = k_type_map.get(val[2], f"{val[2]:02X}")
            return f"ID:{val[0]:02X} Ver:{val[1]:02X} Type:{k_type} Len:{val[3]}"

        # 4. OID (06)
        if tag == 0x06:
            oids = {
                "2A864886FC6B01": "GlobalPlatform",
                "2A864886FC6B02": "GP SCP02",
                "2A864886FC6B020202": "GP SCP02",
                "2A864886FC6B03": "GP SCP03",
                "2A864886FC6B04": "GP Content Mgmt",
                "2A864886FC6B040370": "GP Content Mgmt",
                "2A864886FC6B05": "GP Security",
            }
            for oid, name in oids.items():
                if hex_str.startswith(oid): return f"{name} ({hex_str})"

        # 5. ASCII check
        if len(val) > 2 and all(0x20 <= c <= 0x7E for c in val):
             return f"\"{val.decode('ascii')}\""

        return hex_str

    def _print_tlv_tree(self, tlv_dict: Dict[int, any], indent: int = 0, parent_tag: Optional[int] = None):
        """Recursive pretty printer with inline flattening."""
        
        for tag, val in tlv_dict.items():
            name = self._resolve_tag_name(tag, parent_tag)
            prefix = "    " * indent + "| "

            # Duplicate tags are preserved as lists; print each occurrence.
            if isinstance(val, list):
                print(f"{prefix}{Config.Colors.CYAN}{name}{Config.Colors.ENDC}")
                for idx, item in enumerate(val, start=1):
                    idx_prefix = "    " * (indent + 1) + "| "
                    print(f"{idx_prefix}{Config.Colors.BOLD}#{idx}{Config.Colors.ENDC}")
                    if isinstance(item, dict):
                        self._print_tlv_tree(item, indent + 2, parent_tag=tag)
                    elif isinstance(item, bytes):
                        decoded_item = self._decode_value(tag, item, parent_tag)
                        print(f"{'    ' * (indent + 2)}| {decoded_item}")
                    else:
                        print(f"{'    ' * (indent + 2)}| {str(item)}")
                continue
            
            # --- Inline Optimization ---
            # If the value is a dict with exactly 1 primitive child, print "Parent : ChildValue" inline
            # e.g. "Card Mgmt : GP SCP02" instead of nested pipe
            if isinstance(val, dict) and len(val) == 1:
                sub_tag = list(val.keys())[0]
                sub_val = val[sub_tag]
                # Only apply if sub-value is bytes (primitive)
                if isinstance(sub_val, bytes) and len(sub_val) > 0:
                    decoded_sub = self._decode_value(sub_tag, sub_val, tag)
                    # If child is "OID" or "Value", omit the child name and just show value
                    if sub_tag in [0x06, 0x04]:
                        print(f"{prefix}{name:<20} : {decoded_sub}")
                        continue
            
            # --- Recursive Nested TLV Detection (Raw Bytes -> TLV) ---
            if isinstance(val, bytes) and tag in [0x84, 0xAF, 0xA0]:
                try:
                    nested = TlvParser.parse(val)
                    if nested:
                        print(f"{prefix}{Config.Colors.CYAN}{name}{Config.Colors.ENDC}")
                        self._print_tlv_tree(nested, indent + 1, parent_tag=tag)
                        continue
                except: pass

            # --- Standard Printing ---
            if isinstance(val, dict):
                # Skip wrapper label if it matches parent
                if indent == 1 and tag == parent_tag:
                    self._print_tlv_tree(val, indent, parent_tag=tag)
                else:
                    print(f"{prefix}{Config.Colors.CYAN}{name}{Config.Colors.ENDC}")
                    self._print_tlv_tree(val, indent + 1, parent_tag=tag)
            
            elif isinstance(val, bytes):
                if len(val) == 0:
                    print(f"{prefix}{name:<20} : (Empty)")
                else:
                    decoded = self._decode_value(tag, val, parent_tag)
                    if len(decoded) > 50 and " " not in decoded and "." not in decoded:
                        decoded = decoded[:50] + "..."
                    print(f"{prefix}{name:<20} : {decoded}")

    def _swap_nibbles(self, s: str) -> str:
        if not s: return ""
        res = []
        for i in range(0, len(s), 2):
            if i+1 < len(s): res.append(s[i+1] + s[i])
            else: res.append(s[i])
        return "".join(res).replace('F', '')

    def _parse_profile_list(self, data: bytes):
        """Decodes BF2D (GetProfilesInfo) into a readable table."""
        print(f"    {'State':<9} | {'Class':<5} | {'ICCID':<20} | {'Name / Provider':<25} | {'AID'}")
        print("    " + "-" * 105)
        
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
        print("")

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

        print(f"    {state_str} | {class_str} | {iccid_display:<20} | {name_str:<25} | {aid_hex}")

        if aid_hex:
            entry = (self.TAG_AID, aid_hex)
            self.profile_cache[name_str.upper()] = entry
            self.profile_cache[aid_hex] = entry
        elif iccid_raw:
            entry = (self.TAG_ICCID, iccid_raw)
            self.profile_cache[name_str.upper()] = entry
            
    # --- Standard ES10c Wrappers (Direct Access) ---

    def _select_isd_r(self):
        cmd = f"00A40400{len(self.AID_ISD_R)//2:02X}{self.AID_ISD_R}"
        self.tp.transmit(cmd, silent=True)

    def list_profiles(self):
        self._select_isd_r()
        payload = "BF2D00"
        cmd = f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        print(f"{Config.Colors.CYAN}[*] Retrieving Profile List (ES10c/ES10b.GetProfilesInfo)...{Config.Colors.ENDC}")
        data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        if sw1 == 0x90:
            self._parse_profile_list(data)
        else:
            print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def get_rat(self) -> None:
        """ES10b.GetRAT (SGP.22/32) – Rules Authorisation Table. Retrieval only."""
        self._select_isd_r()
        payload = "BF4300"
        cmd = f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        print(f"{Config.Colors.CYAN}[*] GetRAT (Rules Authorisation Table)...{Config.Colors.ENDC}")
        data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        if sw1 == 0x90 and data:
            print(f"{Config.Colors.HEADER}--- RAT ---{Config.Colors.ENDC}")
            try:
                parsed = TlvParser.parse(data)
                self._print_tlv_tree(parsed, indent=1, parent_tag=0xBF43)
            except Exception:
                print(f"    {data.hex().upper()}")
        elif sw1 != 0x90:
            print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        else:
            print("    (Empty)")

    def get_notifications_list(self) -> None:
        """ES10b.RetrieveNotificationsList (SGP.22/32) – Pending notifications. Retrieval only."""
        self._select_isd_r()
        payload = "BF2B00"
        cmd = f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        print(f"{Config.Colors.CYAN}[*] RetrieveNotificationsList (pending notifications)...{Config.Colors.ENDC}")
        data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        if sw1 == 0x90 and data:
            print(f"{Config.Colors.HEADER}--- Notifications / eUICC Package Results ---{Config.Colors.ENDC}")
            try:
                parsed = TlvParser.parse(data)
                self._print_tlv_tree(parsed, indent=1, parent_tag=0xBF2B)
            except Exception:
                print(f"    {data.hex().upper()}")
        elif sw1 != 0x90:
            print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        else:
            print("    (Empty)")

    def get_eim_configuration_data(self) -> None:
        """ES10b.GetEimConfigurationData (SGP.32 IoT) – eIM configuration data. Retrieval only."""
        self._select_isd_r()
        payload = "BF5500"
        cmd = f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        print(f"{Config.Colors.CYAN}[*] GetEimConfigurationData (eIM config, SGP.32)...{Config.Colors.ENDC}")
        data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        if sw1 == 0x90 and data:
            print(f"{Config.Colors.HEADER}--- eIM Configuration Data ---{Config.Colors.ENDC}")
            try:
                parsed = TlvParser.parse(data)
                self._print_tlv_tree(parsed, indent=1, parent_tag=0xBF55)
            except Exception:
                print(f"    {data.hex().upper()}")
        elif sw1 != 0x90:
            print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        else:
            print("    (Empty)")

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
        tlv_refresh = bytes([0x81, 0x01, 0x00]) # RefreshFlag = False
        
        inner = tlv_choice + tlv_refresh
        payload = bytes([func_tag >> 8, func_tag & 0xFF, len(inner)]) + inner
        
        cmd = f"80E29100{len(payload):02X}{payload.hex()}"
        data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        
        return self._check_result(data, sw1, sw2, func_tag)

    def _check_result(self, data, sw1, sw2, outer_tag) -> bool:
        if sw1 != 0x90 and sw1 != 0x91:
            print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False
            
        if sw1 == 0x91:
            print(f"{Config.Colors.WARNING}[*] Proactive Command Pending (SW=91xx).{Config.Colors.ENDC}")

        parsed = TlvParser.parse(data)
        outer = parsed.get(outer_tag)
        if isinstance(outer, list) and len(outer) > 0:
            outer = outer[0]
        content = outer if isinstance(outer, dict) else (TlvParser.parse(outer) if isinstance(outer, bytes) else parsed)

        if self.TAG_RESULT in content:
            val = content[self.TAG_RESULT]
            res_code = int.from_bytes(val, 'big') if isinstance(val, bytes) else 0
            if res_code == 0:
                print(f"{Config.Colors.GREEN}[+] Success.{Config.Colors.ENDC}")
                return True
            else:
                errs = {1: "Profile Not Found", 2: "Already in State", 7: "Command Error (Struct)", 127: "Undefined Error"}
                print(f"{Config.Colors.FAIL}[-] Error 0x{res_code:02X}: {errs.get(res_code, 'Unknown')}{Config.Colors.ENDC}")
                return False
        
        print(f"{Config.Colors.GREEN}[+] Success (No Result Code).{Config.Colors.ENDC}")
        return True

    def _resolve_target(self, identifier: str) -> Optional[Tuple[int, str]]:
        clean = identifier.strip().upper()
        if clean in self.profile_cache: return self.profile_cache[clean]
        if clean.startswith("A0") and len(clean) >= 10: return (self.TAG_AID, clean)
        if (clean.startswith("89") or clean.startswith("98")) and len(clean) >= 18:
            return (self.TAG_ICCID, self._swap_nibbles(clean) if clean.startswith("89") else clean)
        print(f"{Config.Colors.FAIL}[!] Unknown Profile: '{identifier}'. Run LIST first.{Config.Colors.ENDC}")
        return None