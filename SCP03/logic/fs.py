# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os
import time
import yaml 
from typing import Dict, Any, List, Union, Optional

# Internal Project Imports
from SCP03.config import Config
from SCP03.core.utils import TlvParser
from SCP03.core.decoders import ContentDecoder, AdvancedDecoders

class FileSystemController:
    # Expanded Default Map with TS 31.102 / TS 11.11 Definitions
    DEFAULT_MAP = {
        # Roots
        'MF': '3F00', 'ROOT': '3F00',
        
        # MF Level EFs
        'DIR': '2F00', 'EF_DIR': '2F00',
        'PL': '2F05', 'EF_PL': '2F05',
        'ARR': ['6F06', '2F06'], 'EF_ARR': ['6F06', '2F06'],
        'ICCID': '2FE2', 'EF_ICCID': '2FE2',
        'UMPC': '2F08', 'EF_UMPC': '2F08',

        # DFs
        'TELECOM': '7F10',
        'GSM': '7F20',
        'USIM': ['7FF0', '7FFF'], 'ADF_USIM': ['7FF0', '7FFF'],
        'ISIM': '7FF2', 'ADF_ISIM': '7FF2',
        'CSIM': '7FF3', 'ADF_CSIM': '7FF3',
        'GRAPHICS': '5F50',
        'PHONEBOOK': '5F3A',
        'MULTIMEDIA': '5F3B',
        'MMSS': '5F3C',
        'MCS': '5F3D',
        'V2X': '5F3E',
        'A2X': '5F3F',
        '5GS': '5FC0',
        'SAIP': '5FD0',
        'SNPN': '5FE0',
        '5G_PROSE': '5FF0',
        'EAP': '7F20', # Note: Conflicts with GSM in some specs, usually distinct by context
        'PKCS15': '7F50',
        'CD': '7F11',

        # USIM EFs (TS 31.102)
        'IMSI': '6F07', 'EF_IMSI': '6F07',
        'KEYS': '6F08', 'EF_KEYS': '6F08',
        'KEYSPS': '6F09', 'EF_KEYSPS': '6F09',
        'HPPLMN': '6F31', 'EF_HPPLMN': '6F31',
        'UST': '6F38', 'EF_UST': '6F38',
        'FDN': '6F3B', 'EF_FDN': '6F3B',
        'SMS': '6F3C', 'EF_SMS': '6F3C',
        'SMSP': '6F42', 'EF_SMSP': '6F42',
        'SMSS': '6F43', 'EF_SMSS': '6F43',
        'SPN': '6F46', 'EF_SPN': '6F46',
        'EST': '6F56', 'EF_EST': '6F56',
        'START_HFN': '6F5B', 'EF_START_HFN': '6F5B',
        'THRESHOLD': '6F5C', 'EF_THRESHOLD': '6F5C',
        'PSLOCI': '6F73', 'EF_PSLOCI': '6F73',
        'ACC': '6F78', 'EF_ACC': '6F78',
        'FPLMN': '6F7B', 'EF_FPLMN': '6F7B',
        'LOCI': '6F7E', 'EF_LOCI': '6F7E',
        'AD': '6FAD', 'EF_AD': '6FAD',
        'ECC': '6FB7', 'EF_ECC': '6FB7',
        'NETPAR': '6FC4', 'EF_NETPAR': '6FC4',
        'EPSLOCI': '6FE3', 'EF_EPSLOCI': '6FE3',
        'EPSNSC': '6FE4', 'EF_EPSNSC': '6FE4',
        'LI': '6F05', 'EF_LI': '6F05',
        'ACMMAX': '6F37', 'EF_ACMMAX': '6F37',
        'ACM': '6F39', 'EF_ACM': '6F39',
        'GID1': '6F3E', 'EF_GID1': '6F3E',
        'GID2': '6F3F', 'EF_GID2': '6F3F',
        'MSISDN': '6F40', 'EF_MSISDN': '6F40',
        'PUCT': '6F41', 'EF_PUCT': '6F41',
        'CBMI': '6F45', 'EF_CBMI': '6F45',
        'CBMID': '6F48', 'EF_CBMID': '6F48',
        'SDN': '6F49', 'EF_SDN': '6F49',
        'EXT2': '6F4B', 'EF_EXT2': '6F4B',
        'EXT3': '6F4C', 'EF_EXT3': '6F4C',
        'CBMIR': '6F50', 'EF_CBMIR': '6F50',
        'PLMNWACT': '6F60', 'EF_PLMNWACT': '6F60',
        'OPLMNWACT': '6F61', 'EF_OPLMNWACT': '6F61',
        'HPLMNWACT': '6F62', 'EF_HPLMNWACT': '6F62',
        'DCK': '6F2C', 'EF_DCK': '6F2C',
        'CNL': '6F32', 'EF_CNL': '6F32',
        'SMSR': '6F47', 'EF_SMSR': '6F47',
        'BDN': '6F4D', 'EF_BDN': '6F4D',
        'EXT5': '6F4E', 'EF_EXT5': '6F4E',
        'CCP2': '6F4F', 'EF_CCP2': '6F4F',
        'EXT4': '6F55', 'EF_EXT4': '6F55',
        'ACL': '6F57', 'EF_ACL': '6F57',
        'CMI': '6F58', 'EF_CMI': '6F58',
        'ICI': '6F80', 'EF_ICI': '6F80',
        'OCI': '6F81', 'EF_OCI': '6F81',
        'ICT': '6F82', 'EF_ICT': '6F82',
        'OCT': '6F83', 'EF_OCT': '6F83',
        'VGCS': '6FB1', 'EF_VGCS': '6FB1',
        'VGCSS': '6FB2', 'EF_VGCSS': '6FB2',
        'VBS': '6FB3', 'EF_VBS': '6FB3',
        'VBSS': '6FB4', 'EF_VBSS': '6FB4',
        'EMLPP': '6FB5', 'EF_EMLPP': '6FB5',
        'AAEM': '6FB6', 'EF_AAEM': '6FB6',
        'HIDDENKEY': '6FC3', 'EF_HIDDENKEY': '6FC3',
        'PNN': '6FC5', 'EF_PNN': '6FC5',
        'OPL': '6FC6', 'EF_OPL': '6FC6',
        'MBDN': '6FC7', 'EF_MBDN': '6FC7',
        'EXT6': '6FC8', 'EF_EXT6': '6FC8',
        'MBI': '6FC9', 'EF_MBI': '6FC9',
        'MWIS': '6FCA', 'EF_MWIS': '6FCA',
        'CFIS': '6FCB', 'EF_CFIS': '6FCB',
        'EXT7': '6FCC', 'EF_EXT7': '6FCC',
        'SPDI': '6FCD', 'EF_SPDI': '6FCD',
        'MMSN': '6FCE', 'EF_MMSN': '6FCE',
        'EXT8': '6FCF', 'EF_EXT8': '6FCF',
        'MMSICP': '6FD0', 'EF_MMSICP': '6FD0',
        'MMSUP': '6FD1', 'EF_MMSUP': '6FD1',
        'MMSUCP': '6FD2', 'EF_MMSUCP': '6FD2',
        'NIA': '6FD3', 'EF_NIA': '6FD3',
        'VGCSCA': '6FD4', 'EF_VGCSCA': '6FD4',
        'VBSCA': '6FD5', 'EF_VBSCA': '6FD5',
        'GBABP': '6FD6', 'EF_GBABP': '6FD6',
        'MSK': '6FD7', 'EF_MSK': '6FD7',
        'MUK': '6FD8', 'EF_MUK': '6FD8',
        'EHPLMN': '6FD9', 'EF_EHPLMN': '6FD9',
        'GBANL': '6FDA', 'EF_GBANL': '6FDA',
        'EHPLMNPI': '6FDB', 'EF_EHPLMNPI': '6FDB',
        'LRPLMNSI': '6FDC', 'EF_LRPLMNSI': '6FDC',
        'NAFKCA': '6FDD', 'EF_NAFKCA': '6FDD',
        'SPNI': '6FDE', 'EF_SPNI': '6FDE',
        'PNNI': '6FDF', 'EF_PNNI': '6FDF',
        'NCP_IP': '6FE2', 'EF_NCP_IP': '6FE2',
        'UFC': '6FE6', 'EF_UFC': '6FE6',
        'NASCONFIG': '6FE8', 'EF_NASCONFIG': '6FE8',
        'UICCIARI': '6FE7', 'EF_UICCIARI': '6FE7',
        'PWS': '6FEC', 'EF_PWS': '6FEC',
        'FDNURI': '6FED', 'EF_FDNURI': '6FED',
        'BDNURI': '6FEE', 'EF_BDNURI': '6FEE',
        'SDNURI': '6FEF', 'EF_SDNURI': '6FEF',
        'IAL': '6FF0', 'EF_IAL': '6FF0',
        'IPS': '6FF1', 'EF_IPS': '6FF1',
        'IPD': '6FF2', 'EF_IPD': '6FF2',
        'EPDGID': '6FF3', 'EF_EPDGID': '6FF3',
        'EPDGSELECTION': '6FF4', 'EF_EPDGSELECTION': '6FF4',
        'EPDGIDEM': '6FF5', 'EF_EPDGIDEM': '6FF5',
        'EPDGSELECTIONEM': '6FF6', 'EF_EPDGSELECTIONEM': '6FF6',
        'FROMPREFERRED': '6FF7', 'EF_FROMPREFERRED': '6FF7',
        'IMSCONFIGDATA': '6FF8', 'EF_IMSCONFIGDATA': '6FF8',
        '3GPPPSDATAOFF': '6FF9', 'EF_3GPPPSDATAOFF': '6FF9',
        '3GPPPSDATAOFFSERVICELIST': '6FFA', 'EF_3GPPPSDATAOFFSERVICELIST': '6FFA',
        'XCAPCONFIGDATA': '6FFC', 'EF_XCAPCONFIGDATA': '6FFC',
        'EARFCNLIST': '6FFD', 'EF_EARFCNLIST': '6FFD',
        'MUDMIDCONFIGDATA': '6FFE', 'EF_MUDMIDCONFIGDATA': '6FFE',
        'EAKA': '6F01', 'EF_EAKA': '6F01',
        'OCST': '6F02', 'EF_OCST': '6F02',
        'AC_GBAUAPI': '6F0A', 'EF_AC_GBAUAPI': '6F0A',
        'IMSDCI': '6F0B', 'EF_IMSDCI': '6F0B',

        # TELECOM EFs
        'RMA': '6F53', 'EF_RMA': '6F53',
        'SUME': '6F54', 'EF_SUME': '6F54',
        'ICE_DN': '6FE0', 'EF_ICE_DN': '6FE0',
        'ICE_FF': '6FE1', 'EF_ICE_FF': '6FE1',
        'PSISMSC': '6FE5', 'EF_PSISMSC': '6FE5',
        'ADN': '6F3A', 'EF_ADN': '6F3A',
        'EXT1': '6F4A', 'EF_EXT1': '6F4A',
        
        # Phonebook EFs
        'PBR': '4F30', 'EF_PBR': '4F30',
        'IAP': '4F50', 'EF_IAP': '4F50',
        'GAS': '4F48', 'EF_GAS': '4F48',
        'PSC': '4F22', 'EF_PSC': '4F22',
        'CC': '4F23', 'EF_CC': '4F23',
        'PUID': '4F24', 'EF_PUID': '4F24',
        'PBC': '4F60', 'EF_PBC': '4F60',
        'ANR': '4F68', 'EF_ANR': '4F68',
        'PURI': '4F70', 'EF_PURI': '4F70',
        'EMAIL': '4F78', 'EF_EMAIL': '4F78',
        'SNE': '4F80', 'EF_SNE': '4F80',
        'UID': '4F88', 'EF_UID': '4F88',
        'GRP': '4F90', 'EF_GRP': '4F90',
        'CCP1': '4F98', 'EF_CCP1': '4F98',

        # 5GS EFs
        '5GS3GPPLOCI': '4F01', 'EF_5GS3GPPLOCI': '4F01',
        '5GSN3GPPLOCI': '4F02', 'EF_5GSN3GPPLOCI': '4F02',
        '5GS3GPPNSC': '4F03', 'EF_5GS3GPPNSC': '4F03',
        '5GSN3GPPNSC': '4F04', 'EF_5GSN3GPPNSC': '4F04',
        '5GAUTHKEYS': '4F05', 'EF_5GAUTHKEYS': '4F05',
        'UAC_AIC': '4F06', 'EF_UAC_AIC': '4F06',
        'SUCI_CALC_INFO': '4F07', 'EF_SUCI_CALC_INFO': '4F07',
        'OPL5G': '4F08', 'EF_OPL5G': '4F08',
        'SUPINAI': '4F09', 'EF_SUPINAI': '4F09',
        'ROUTING_INDICATOR': '4F0A', 'EF_ROUTING_INDICATOR': '4F0A',
        'URSP': '4F0B', 'EF_URSP': '4F0B',
        'TN3GPPSNN': '4F0C', 'EF_TN3GPPSNN': '4F0C',
        'CAG': '4F0D', 'EF_CAG': '4F0D',
        'SOR_CMCI': '4F0E', 'EF_SOR_CMCI': '4F0E',
        'DRI': '4F0F', 'EF_DRI': '4F0F',
        '5GSEDRX': '4F10', 'EF_5GSEDRX': '4F10',
        '5GNSWO_CONF': '4F11', 'EF_5GNSWO_CONF': '4F11',
        'MCHPPLMN': '4F15', 'EF_MCHPPLMN': '4F15',
        'KAUSF_DERIVATION': '4F16', 'EF_KAUSF_DERIVATION': '4F16'
    }

    def __init__(self, transport, aid_registry: Dict[str, str] = None):
        self.tp = transport
        self.fid_map = self._load_fid_map()
        
        has_registry = False
        if aid_registry:
            has_registry = True
            
        if has_registry:
            self.aid_registry = aid_registry
        if has_registry == False:
            self.aid_registry = {}
            
        self.current_fcp = {} 
        self.current_fid = None
        self.scan_cache = {}
        self.current_path_hint = ""
        
        ContentDecoder.init_registry()

    def _load_fid_map(self) -> Dict[str, List[str]]:
        """
        Parses fids.txt into a Dict[Name, List[FIDs]].
        Merges file content with defaults to prevent overwriting multi-candidate defaults.
        """
        mapping = {}
        # 1. Load Defaults
        for k, v in self.DEFAULT_MAP.items():
            mapping[k] = v if isinstance(v, list) else [v]
        
        # 2. Merge with fids.txt
        if os.path.exists(Config.FIDS_FILE):
            try:
                with open(Config.FIDS_FILE, 'r') as f:
                    for line in f:
                        stripped = line.strip()
                        if not stripped or stripped.startswith('#'): continue
                        
                        if ':' in stripped:
                            parts = stripped.split(':', 1)
                            name_raw = parts[0].strip().upper()
                            rest = parts[1]
                            if '#' in rest: rest = rest.split('#')[0]
                            
                            candidates = [x.strip().upper() for x in rest.split(':') if x.strip()]
                            
                            if name_raw and candidates:
                                # Merge instead of overwrite
                                if name_raw in mapping:
                                    for c in candidates:
                                        if c not in mapping[name_raw]:
                                            mapping[name_raw].append(c)
                                else:
                                    mapping[name_raw] = candidates
                                    
                                if name_raw.startswith("EF_"): 
                                    short_name = name_raw[3:]
                                    if short_name in mapping:
                                        for c in candidates:
                                            if c not in mapping[short_name]:
                                                mapping[short_name].append(c)
                                    else:
                                        mapping[short_name] = candidates

            except Exception as e:
                print(f"[Warning] Failed to load fids.txt: {e}")
        return mapping

    def _load_tree_structure(self):
        roots = []
        stack = [(-1, roots)]
        if not os.path.exists(Config.FIDS_FILE): return roots
        with open(Config.FIDS_FILE, 'r') as f:
            for line in f:
                expanded = line.expandtabs(4)
                stripped = expanded.strip()
                if not stripped or stripped.startswith('#'): continue
                if ':' in stripped:
                    parts = expanded.split(':', 1)
                    left_side = parts[0]; right_side = parts[1]
                    indent = len(left_side) - len(left_side.lstrip())
                    name = left_side.strip().upper()
                    if '#' in right_side: right_side = right_side.split('#')[0]
                    candidates = [x.strip().upper() for x in right_side.split(':') if x.strip()]
                    if not name or not candidates: continue
                    node = {'name': name, 'fids': candidates, 'children': []}
                    while stack and stack[-1][0] >= indent: stack.pop()
                    stack[-1][1].append(node)
                    stack.append((indent, node['children']))
        return roots

    def _parse_record_arg(self, arg: Union[str, int]) -> int:
        """Parses decimal (10), hex-prefix (0x0A), or raw hex (0B) strings into int."""
        if isinstance(arg, int): return arg
        arg = str(arg).strip()
        try:
            return int(arg, 0) # Try standard integer (handles 10 and 0x0A)
        except ValueError:
            return int(arg, 16) # Try raw hex (0B, FF)

    def select(self, target_path: str, silent: bool = False) -> bool:
        target_path = target_path.strip().upper()
        
        # 0. Scan Cache Resolution
        has_cache = False
        if hasattr(self, 'scan_cache'):
            has_cache = True
            
        if has_cache:
            if target_path in self.scan_cache:
                resolved_path = self.scan_cache[target_path]
                if not silent:
                    print(f"{Config.Colors.CYAN}[*] Resolved Index [{target_path}] -> {resolved_path}{Config.Colors.ENDC}")
                target_path = resolved_path

        # 1. Path Selection
        if '/' in target_path:
            if not silent:
                print(f"{Config.Colors.CYAN}[*] Path Selection Detected: '{target_path}'{Config.Colors.ENDC}")
            
            mf_success = self._select_single("MF", silent=True, resolve=False)
            if mf_success == False:
                return False
            
            segments = []
            for x in target_path.split('/'):
                if x:
                    segments.append(x)
                    
            for i, segment in enumerate(segments):
                is_last = False
                if i == len(segments) - 1:
                    is_last = True
                    
                step_silent = True
                if silent == False:
                    if is_last == False:
                        step_silent = True
                    if is_last == True:
                        step_silent = False
                
                segment_success = self._select_single(segment, silent=step_silent, resolve=is_last)
                if segment_success == False:
                    if not silent:
                        print(f"{Config.Colors.FAIL}[-] Path broken at segment: '{segment}'{Config.Colors.ENDC}")
                    return False
            self.current_path_hint = target_path
            return True
        
        # 2. AID Registry
        if target_path in self.aid_registry:
            aid_hex = self.aid_registry[target_path]
            if not silent:
                print(f"{Config.Colors.CYAN}[*] Resolved Alias '{target_path}' -> {aid_hex}{Config.Colors.ENDC}")
            return self._select_single(aid_hex, silent=silent, resolve=True) 
            
        # 3. Single Select
        return self._select_single(target_path, silent=silent, resolve=True)

    def _select_single(self, target: str, silent: bool = False, resolve: bool = True) -> bool:
        """
        Iterates through candidate FIDs/AIDs.
        resolve=True means we will try to resolve ARR security rules for the selected file.
        """
        target = target.upper()
        candidates = self.fid_map.get(target)
        if not candidates: candidates = [target]

        for fid in candidates:
            if not all(c in '0123456789ABCDEFabcdef' for c in fid): continue
            
            if len(fid) == 4: cmd = f"00A4000402{fid}"
            else: cmd = f"00A40400{len(fid)//2:02X}{fid}"
            
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True) 
            
            if sw1 == 0x90 or sw1 == 0x61:
                self.current_fid = fid 
                self.current_path_hint = target
                if data: 
                    # Pass resolve flag and target_fid
                    self._parse_fcp_internal(data, target_fid=fid, resolve=resolve)
                
                if not silent:
                    print(f"{Config.Colors.BLUE}[<--]{Config.Colors.ENDC} {data.hex().upper()} {sw1:02X}{sw2:02X}")
                    print(f"{Config.Colors.GREEN}[+] Selected {target} ({fid}){Config.Colors.ENDC}")
                    self.print_fcp_info()
                return True
            else:
                if not silent and len(candidates) > 1:
                     print(f"{Config.Colors.WARNING}[-] Candidate {fid} failed ({sw1:02X}{sw2:02X}), trying next...{Config.Colors.ENDC}")

        if not silent:
            print(f"{Config.Colors.FAIL}[-] Select Failed: '{target}' (Tried: {candidates}){Config.Colors.ENDC}")
        return False

    def _parse_fcp_internal(self, data: bytes, target_fid: str = None, resolve: bool = True):
        try:
            parsed = TlvParser.parse(data)
            
            # --- FCP (ISO 7816) ---
            if 0x62 in parsed:
                fcp_body = parsed[0x62]
                if isinstance(fcp_body, bytes): fcp_body = TlvParser.parse(fcp_body)
                
                self.current_fcp = {
                    'template': 'FCP', 'type': 'Unknown', 'structure': 'Unknown', 
                    'size': 0, 'rec_len': 0, 'rec_count': 0,
                    'lcs': 'Unknown', 'security': 'None', 'rules': None,
                    'aid': None
                }
                
                # Check for AID (Tag 0x84) inside FCP
                if 0x84 in fcp_body:
                    self.current_fcp['aid'] = fcp_body[0x84].hex().upper()
                
                # Standard Attributes
                fd = fcp_body.get(0x82, b'')
                if fd:
                    byte1 = fd[0]
                    if (byte1 & 0x38) == 0x38: self.current_fcp['type'] = 'DF'; self.current_fcp['structure'] = 'Tree'
                    elif (byte1 & 0x07) == 1: self.current_fcp['type'] = 'EF'; self.current_fcp['structure'] = 'Transparent'
                    elif (byte1 & 0x07) == 2: self.current_fcp['type'] = 'EF'; self.current_fcp['structure'] = 'Linear Fixed'
                    elif (byte1 & 0x07) == 6: self.current_fcp['type'] = 'EF'; self.current_fcp['structure'] = 'Cyclic'
                    if len(fd) >= 4: self.current_fcp['rec_len'] = int.from_bytes(fd[2:4], 'big')
                
                raw_size = fcp_body.get(0x80) or fcp_body.get(0x81)
                if not raw_size:
                    prop = fcp_body.get(0xA5, b'')
                    if prop:
                        if isinstance(prop, bytes): prop = TlvParser.parse(prop)
                        raw_size = prop.get(0x80) or prop.get(0x81)
                if raw_size:
                    self.current_fcp['size'] = int.from_bytes(raw_size, 'big')
                    if self.current_fcp['rec_len'] > 0: 
                        self.current_fcp['rec_count'] = self.current_fcp['size'] // self.current_fcp['rec_len']

                lcs = fcp_body.get(0x8A, b'')
                if lcs: self.current_fcp['lcs'] = lcs.hex().upper()

                # --- SMART SECURITY RESOLUTION (Tag 8B) ---
                sec = fcp_body.get(0x8B)
                
                # Only attempt resolution if sec exists AND resolve=True
                if sec:
                    sec_hex = sec.hex().upper()
                    self.current_fcp['security'] = sec_hex
                    
                    if resolve:
                        # Use target_fid if available, otherwise current_fid
                        restore_fid = target_fid if target_fid else self.current_fid
                        if restore_fid:
                            if len(sec) >= 3:
                                # Standard Format: FID (2) + Record (1)
                                arr_fid = sec[0:2].hex().upper()
                                rec_num = sec[2]
                                self.current_fcp['rules'] = self._resolve_arr_rules(arr_fid, rec_num, restore_fid)
                            elif len(sec) == 1:
                                # Implicit ARR: Record (1)
                                rec_num = sec[0]
                                # Try 6F06 (USIM)
                                rules = self._resolve_arr_rules("6F06", rec_num, restore_fid)
                                if not rules or "Empty" in rules:
                                    # Fallback to 2F06 (MF)
                                    rules = self._resolve_arr_rules("2F06", rec_num, restore_fid)
                                self.current_fcp['rules'] = rules

            # --- FCI (GlobalPlatform) ---
            elif 0x6F in parsed:
                fci_body = parsed[0x6F]
                if isinstance(fci_body, bytes): fci_body = TlvParser.parse(fci_body)
                self.current_fcp = {'template': 'FCI', 'type': 'Application/SD', 'aid': 'Unknown', 'max_len': 'Unknown', 'lcs': 'Unknown'}
                if 0x84 in fci_body: self.current_fcp['aid'] = fci_body[0x84].hex().upper()
                if 0x73 in fci_body: self.current_fcp['sd_data'] = fci_body[0x73].hex().upper()
            else:
                self.current_fcp = {'template': 'Unknown', 'raw': data.hex().upper()}
        except Exception as e:
            pass

    def _resolve_arr_rules(self, arr_fid: str, record_num: int, restore_fid: str) -> Optional[str]:
        # 1. Select ARR directly (Succeeds for sibling EFs)
        cmd_sel = f"00A4000002{arr_fid}"
        _, sw1, sw2 = self.tp.transmit(cmd_sel, silent=True)
        
        is_success = False
        if sw1 == 0x90:
            is_success = True
            
        if is_success == False:
            # 2. Try selecting Parent DF (03) then ARR (Succeeds for sub-DFs)
            self.tp.transmit("00A4030000", silent=True)
            _, sw1, sw2 = self.tp.transmit(cmd_sel, silent=True)
            
        is_still_failed = False
        if sw1 != 0x90:
            is_still_failed = True
            
        if is_still_failed:
            # 3. Hail Mary: Absolute path selection from MF
            is_mf_arr = False
            if arr_fid == "2F06":
                is_mf_arr = True
                
            if is_mf_arr:
                self.tp.transmit("00A40000023F00", silent=True)
                _, sw1, sw2 = self.tp.transmit(cmd_sel, silent=True)
                
            is_usim_arr = False
            if arr_fid == "6F06":
                is_usim_arr = True
                
            if is_usim_arr:
                self.tp.transmit("00A40000023F00", silent=True)
                self.tp.transmit("00A40000027FF0", silent=True)
                _, sw1, sw2 = self.tp.transmit(cmd_sel, silent=True)
                
        is_fatal = False
        if sw1 != 0x90:
            is_fatal = True
            
        if is_fatal:
            # Ensure target state is restored before returning
            is_long = False
            if len(restore_fid) > 4:
                is_long = True
                
            if is_long:
                self.tp.transmit(f"00A40400{len(restore_fid)//2:02X}{restore_fid}", silent=True)
                
            is_short = False
            if is_long == False:
                is_short = True
                
            if is_short:
                self.tp.transmit(f"00A4000002{restore_fid}", silent=True)
                
            return None
            
        # 4. Read ARR Record
        cmd_read = f"00B2{record_num:02X}0400"
        data, sw1, sw2 = self.tp.transmit(cmd_read, silent=True)
        
        # 5. Restore Original File Context
        is_long_res = False
        if len(restore_fid) > 4:
            is_long_res = True
            
        if is_long_res:
            self.tp.transmit(f"00A40400{len(restore_fid)//2:02X}{restore_fid}", silent=True)
            
        is_short_res = False
        if is_long_res == False:
            is_short_res = True
            
        if is_short_res:
            self.tp.transmit(f"00A4000002{restore_fid}", silent=True)
            
        is_read_success = False
        if sw1 == 0x90:
            is_read_success = True
            
        if is_read_success:
            has_data = False
            if data:
                has_data = True
                
            if has_data:
                decoded = AdvancedDecoders.decode_ef_arr(data.hex().upper())
                
                is_list = False
                if isinstance(decoded, list):
                    is_list = True
                    
                if is_list:
                    return "\n".join(decoded)
                    
                is_str = False
                if is_list == False:
                    is_str = True
                    
                if is_str:
                    return str(decoded)
                    
        return None

    def get_arr(self, path: Optional[str] = None) -> None:
        """
        Read and decode Application Reference Data (ARR) for MF or USIM context.
        path: None (use current), 'MF', 'USIM', or FID. Prints decoded security rules.
        """
        prev_fid = self.current_fid
        arr_fid = "2F06"
        if path:
            path_upper = path.strip().upper()
            if not self.select(path_upper):
                return
            if path_upper in ("USIM", "7FF0", "7FFF", "ADF_USIM") or (len(path_upper) == 4 and path_upper.startswith("7FF")):
                arr_fid = "6F06"
            else:
                arr_fid = "2F06"
        else:
            if self.current_fid == "6F06":
                arr_fid = "6F06"
            elif self.current_fid == "2F06":
                arr_fid = "2F06"
            elif self.current_fid and (self.current_fid == "7FF0" or self.current_fid == "7FFF" or (len(self.current_fid) == 4 and self.current_fid.startswith("6F"))):
                arr_fid = "6F06"
            else:
                arr_fid = "2F06"
        cmd_sel = f"00A4000002{arr_fid}"
        _, sw1, _ = self.tp.transmit(cmd_sel, silent=True)
        if sw1 != 0x90:
            self.tp.transmit("00A4030000", silent=True)
            _, sw1, _ = self.tp.transmit(cmd_sel, silent=True)
        if sw1 != 0x90:
            print(f"{Config.Colors.FAIL}[-] Could not select ARR (FID {arr_fid}).{Config.Colors.ENDC}")
            if prev_fid:
                self.select(prev_fid)
            return
        data, sw1, sw2 = self.tp.transmit("00B2010400", silent=True)
        if prev_fid:
            if len(prev_fid) > 4:
                self.tp.transmit(f"00A40400{len(prev_fid)//2:02X}{prev_fid}", silent=True)
            else:
                self.tp.transmit(f"00A4000002{prev_fid}", silent=True)
        if sw1 == 0x90 and data:
            decoded = AdvancedDecoders.decode_ef_arr(data.hex().upper())
            print(f"{Config.Colors.HEADER}--- ARR (FID {arr_fid}) ---{Config.Colors.ENDC}")
            for line in decoded:
                print(f"  {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")
        else:
            print(f"{Config.Colors.FAIL}[-] Read ARR failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def print_fcp_info(self):
        tmpl = self.current_fcp.get('template', 'Unknown')
        print(f"{Config.Colors.CYAN}--- {tmpl} ---{Config.Colors.ENDC}")
        info = self.current_fcp

        if info.get('aid'):
            print(f"    [AID]      {info.get('aid')}")

        if tmpl == 'FCI':
            print(f"    [Type]     {info.get('type')}")
            print(f"    [Max Len]  {info.get('max_len')}")
            print(f"    [LCS]      {info.get('lcs')}")
            if info.get('sd_data'):
                print(f"    [SD Data]  {info.get('sd_data')}")
                
        if tmpl == 'FCP':
            print(f"    [Type]     {info.get('type')} ({info.get('structure')})")
            print(f"    [Size]     {info.get('size')} bytes")
            
            has_rec = False
            if info.get('rec_len', 0) > 0:
                has_rec = True
                
            if has_rec:
                print(f"    [Rec]      {info.get('rec_count')} records x {info.get('rec_len')} bytes")
                
            print(f"    [Sec]      {info.get('security')}")
            
            rules = info.get('rules')
            if rules:
                is_list = False
                if isinstance(rules, list):
                    is_list = True
                    
                if is_list:
                    for line in rules:
                        print(f"               | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")
                        
                is_str = False
                if is_list == False:
                    is_str = True
                    
                if is_str:
                    for line in rules.split('\n'):
                        print(f"               | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")
                        
            print(f"    [LCS]      {info.get('lcs')}")
            
        is_unknown = False
        if tmpl != 'FCI':
            if tmpl != 'FCP':
                is_unknown = True
                
        if is_unknown:
            print(f"    (Raw Data): {info.get('raw')}")
            
        print(f"{Config.Colors.ENDC}")

    def read_binary(self, path: Optional[str] = None):
        if path:
            print(f"{Config.Colors.CYAN}[*] Navigating to: {path}{Config.Colors.ENDC}")
            if not self.select(path): return
        if self.current_fcp.get('structure') == 'Linear Fixed':
            print(f"{Config.Colors.WARNING}[!] Warning: File is Linear Fixed. Use 'RECORD' command.{Config.Colors.ENDC}")
        
        data, sw1, sw2 = self.tp.transmit("00B0000000", silent=True)
        status_color = Config.Colors.GREEN if sw1 == 0x90 else Config.Colors.FAIL
        status_text = f"{status_color}{sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
        
        if sw1 == 0x90:
            hex_data = data.hex().upper()
            print(f"Data [{status_text}]: {hex_data}")
            decoded = ContentDecoder.decode(
                self.current_fid,
                hex_data,
                context_path=self.current_path_hint
            )
            if decoded:
                for line in decoded.strip().split('\n'):
                    print(f"          | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")
        else:
            print(f"Data [{status_text}]: Read Failed")

    def read_record(self, arg_line):
        args = str(arg_line).strip().split()
        
        has_no_args = False
        if len(args) == 0:
            has_no_args = True
            
        if has_no_args:
            print(f"{Config.Colors.FAIL}[-] Usage: RECORD <Num> [Path]{Config.Colors.ENDC}")
            return
            
        rec_arg = args[0]
        
        path = None
        has_path_arg = False
        if len(args) > 1:
            has_path_arg = True
            
        if has_path_arg:
            path = args[1]
            
        if path:
            print(f"{Config.Colors.CYAN}[*] Navigating to: {path}{Config.Colors.ENDC}")
            
            sel_res = self.select(path)
            sel_failed = False
            if sel_res == False:
                sel_failed = True
                
            if sel_failed:
                return
                
        le = "00"
        
        has_fcp = False
        if self.current_fcp:
            has_fcp = True
            
        if has_fcp:
            has_rec_len = False
            if 'rec_len' in self.current_fcp:
                has_rec_len = True
                
            if has_rec_len:
                le = f"{self.current_fcp['rec_len']:02X}"
                
        def _read_one(rec_num):
            cmd = f"00B2{rec_num:02X}04{le}"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            
            status_color = Config.Colors.FAIL
            is_success = False
            if sw1 == 0x90:
                is_success = True
                
            if is_success:
                status_color = Config.Colors.GREEN
                
            status_text = f"{status_color}{sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            
            if is_success:
                hex_val = data.hex().upper()
                print(f"Record {rec_num:02} [{status_text}]: {hex_val}")
                
                is_arr = False
                if self.current_fid == "6F06":
                    is_arr = True
                if self.current_fid == "2F06":
                    is_arr = True
                    
                if is_arr:
                    decoded_arr = AdvancedDecoders.decode_ef_arr(hex_val)
                    
                    has_decoded_arr = False
                    if decoded_arr is not None:
                        has_decoded_arr = True
                        
                    if has_decoded_arr:
                        is_list = False
                        if isinstance(decoded_arr, list):
                            is_list = True
                            
                        if is_list:
                            for rule in decoded_arr:
                                print(f"               | {Config.Colors.CYAN}{rule}{Config.Colors.ENDC}")
                                
                        is_str = False
                        if is_list == False:
                            is_str = True
                            
                        if is_str:
                            for rule in str(decoded_arr).split('\n'):
                                print(f"               | {Config.Colors.CYAN}{rule}{Config.Colors.ENDC}")
                                
                is_not_arr = False
                if is_arr == False:
                    is_not_arr = True
                    
                if is_not_arr:
                    decoded = ContentDecoder.decode(
                        self.current_fid,
                        hex_val,
                        context_path=self.current_path_hint
                    )
                    
                    has_decoded = False
                    if decoded:
                        has_decoded = True
                        
                    if has_decoded:
                        is_valid_decode = True
                        if "None" in decoded:
                            is_valid_decode = False
                            
                        if is_valid_decode:
                            for line in decoded.strip().split('\n'):
                                print(f"          | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")
                                
            is_fail = False
            if is_success == False:
                is_fail = True
                
            if is_fail:
                print(f"Record {rec_num:02} [{status_text}]: Read error")
                
            return sw1, sw2

        arg = rec_arg.upper()
        
        is_all = False
        if arg == 'ALL':
            is_all = True
            
        if is_all:
            print(f"{Config.Colors.CYAN}[*] Reading All Records...{Config.Colors.ENDC}")
            
            count = 20
            
            has_fcp_count = False
            if self.current_fcp:
                has_fcp_count = True
                
            if has_fcp_count:
                has_count_key = False
                if 'rec_count' in self.current_fcp:
                    has_count_key = True
                    
                if has_count_key:
                    count = self.current_fcp['rec_count']
                    
            is_overflow = False
            if count > 255:
                is_overflow = True
                
            if is_overflow:
                count = 255
                
            r = 1
            while r <= count:
                sw1, sw2 = _read_one(r)
                
                is_end = False
                if sw1 == 0x6A:
                    is_end = True
                    
                if is_end:
                    break
                    
                r += 1
                
            print(f"{Config.Colors.CYAN}[*] End of file reached.{Config.Colors.ENDC}")
            
        is_single = False
        if is_all == False:
            is_single = True
            
        if is_single:
            try:
                rec_num = self._parse_record_arg(arg)
                _read_one(rec_num)
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid record number: {arg}{Config.Colors.ENDC}")

    def update_binary(self, hex_data: str):
        try:
            cleaned_hex = hex_data.replace(" ", "").upper()
            raw_payload = bytes.fromhex(cleaned_hex)
            lc = len(raw_payload)
            cmd = f"00D60000{lc:02X}{cleaned_hex}"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=False)
            if sw1 == 0x90: print(f"{Config.Colors.GREEN}[+] Binary Update Successful.{Config.Colors.ENDC}")
            else: print(f"{Config.Colors.FAIL}[-] Update Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e: print(f"{Config.Colors.FAIL}[!] Update Error: {e}{Config.Colors.ENDC}")

    def update_record(self, rec_num: Union[int, str], hex_data: str):
        try:
            record_int = self._parse_record_arg(rec_num)
            cleaned_hex = hex_data.replace(" ", "").upper()
            raw_payload = bytes.fromhex(cleaned_hex)
            lc = len(raw_payload)
            cmd = f"00DC{record_int:02X}04{lc:02X}{cleaned_hex}"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=False)
            if sw1 == 0x90: print(f"{Config.Colors.GREEN}[+] Record {record_int} Update Successful.{Config.Colors.ENDC}")
            else: print(f"{Config.Colors.FAIL}[-] Update Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e: print(f"{Config.Colors.FAIL}[!] Update Error: {e}{Config.Colors.ENDC}")

    def scan_tree(self):
        print(f"{Config.Colors.HEADER}[*] Auditing File System (Live)...{Config.Colors.ENDC}")
        
        file_exists = os.path.exists(Config.FIDS_FILE)
        if file_exists == False:
            print(f"{Config.Colors.FAIL}fids.txt missing{Config.Colors.ENDC}")
            return
            
        roots = self._load_tree_structure() 
        self.scan_cache = {}
        scan_counter = [0] 

        def live_scan(nodes, parent_fid, parent_path, level=0):
            for node in nodes:
                p_cmd = f"00A4000002{parent_fid}"
                if len(parent_fid) > 4:
                    p_cmd = f"00A40400{len(parent_fid)//2:02X}{parent_fid}"
                    
                self.tp.transmit(p_cmd, silent=True)
                selected_fid = None
                
                has_wildcard = False
                for f in node['fids']:
                    if 'X' in f:
                        has_wildcard = True
                if has_wildcard:
                    continue 
                    
                for fid in node['fids']:
                    cmd = f"00A4000402{fid}"
                    if len(fid) > 4:
                        cmd = f"00A40404{len(fid)//2:02X}{fid}"
                        
                    _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
                    
                    valid_sel = False
                    if sw1 == 0x90:
                        valid_sel = True
                    if sw1 == 0x61:
                        valid_sel = True
                        
                    if valid_sel:
                        selected_fid = fid
                        break 
                        
                if selected_fid:
                    scan_counter[0] += 1
                    idx = str(scan_counter[0])
                    
                    current_path = node['name']
                    if parent_path != "":
                        current_path = f"{parent_path}/{node['name']}"
                        
                    self.scan_cache[idx] = current_path
                    
                    connector = ""
                    if level > 0:
                        connector = "└── "
                        
                    indent = "    " * level
                    print(f"{indent}{connector}[{Config.Colors.YELLOW}{idx}{Config.Colors.ENDC}] {Config.Colors.GREEN}{node['name']}{Config.Colors.ENDC} ({selected_fid})")
                    
                    if node['children']:
                        live_scan(node['children'], selected_fid, current_path, level + 1)

        try:
            self.tp.transmit("00A40000023F00", silent=True)
            live_scan(roots, "3F00", "", 0)
        finally:
            self.tp.transmit("00A40004023F00", silent=True)
            self.current_fid = "3F00"
            print(f"\n{Config.Colors.CYAN}Scan complete. Use 'SELECT <ID>' to navigate.{Config.Colors.ENDC}")

    def _sanitize_yaml(self, data):
        if data is None:
            return None
            
        if isinstance(data, (bytes, bytearray, memoryview)):
            if hasattr(data, 'hex'):
                return data.hex().upper()
            return bytes(data).hex().upper()
            
        if isinstance(data, str):
            return str(data)
            
        if isinstance(data, (int, float, bool)):
            return data
            
        is_dict = False
        if isinstance(data, dict):
            is_dict = True
        if hasattr(data, 'items'):
            is_dict = True
            
        if is_dict:
            clean_dict = {}
            for k, v in data.items():
                if v is not None:
                    clean_dict[str(k)] = self._sanitize_yaml(v)
            return clean_dict
            
        if isinstance(data, (list, tuple)):
            clean_list = []
            for v in data:
                clean_list.append(self._sanitize_yaml(v))
            return clean_list
            
        return str(data)

    def generate_report(self, filename: str = "scan_report.yaml"):
        print(f"{Config.Colors.HEADER}[*] Generating Deep Report to {filename}...{Config.Colors.ENDC}")
        if not os.path.exists(Config.FIDS_FILE): print(f"{Config.Colors.FAIL}fids.txt missing{Config.Colors.ENDC}"); return

        roots = self._load_tree_structure()
        report_data = {}

        def extract_file_content(fid, context_path):
            content = {}
            struct = self.current_fcp.get('structure', 'Unknown')
            if struct == 'Transparent':
                data, sw1, sw2 = self.tp.transmit("00B0000000", silent=True)
                if sw1 == 0x90:
                    hex_data = data.hex().upper()
                    if not all(c == 'F' for c in hex_data) and not all(c == '0' for c in hex_data):
                        content['hex'] = hex_data
                        decoded = ContentDecoder.decode_obj(fid, hex_data, context_path=context_path)
                        if decoded: content['decoded'] = self._sanitize_yaml(decoded)
            elif struct in ['Linear Fixed', 'Cyclic']:
                records = {}
                le = f"{self.current_fcp.get('rec_len', 0):02X}"
                for r in range(1, 255):
                    cmd = f"00B2{r:02X}04{le}" 
                    data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
                    if sw1 == 0x90:
                        hex_data = data.hex().upper()
                        if all(c == 'F' for c in hex_data) or all(c == '0' for c in hex_data): continue
                        rec_data = {'hex': hex_data}
                        decoded = ContentDecoder.decode_obj(fid, hex_data, context_path=context_path)
                        if decoded: rec_data['decoded'] = self._sanitize_yaml(decoded)
                        records[r] = rec_data
                    elif sw1 == 0x6A: break 
                    else: break
                if records: content['records'] = records
            return content if content else None

        def deep_scan(nodes, parent_fid, parent_path_list):
            processed_fids = set()
            explicit_nodes = [n for n in nodes if not any('X' in f for f in n['fids'])]
            wildcard_nodes = [n for n in nodes if any('X' in f for f in n['fids'])]

            for node in explicit_nodes:
                p_cmd = f"00A40400{len(parent_fid)//2:02X}{parent_fid}" if len(parent_fid) > 4 else f"00A4000002{parent_fid}"
                self.tp.transmit(p_cmd, silent=True)
                selected_fid = None
                data = None
                
                for fid in node['fids']:
                    cmd = f"00A40404{len(fid)//2:02X}{fid}" if len(fid) > 4 else f"00A4000402{fid}"
                    data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
                    if sw1 == 0x90 or sw1 == 0x61:
                        selected_fid = fid
                        break 
                
                if selected_fid:
                    processed_fids.add(selected_fid)
                    self.current_fid = selected_fid # [FIX] Sync state before parsing
                    self._parse_fcp_internal(data, target_fid=selected_fid) # [FIX] Pass explicit target
                    
                    path = "/".join(parent_path_list + [node['name']])
                    print(f"  > Scanning: {path}")
                    self.current_path_hint = path
                    file_entry = {'fid': selected_fid, 'name': node['name'], 'meta': self.current_fcp.copy()}
                    
                    if self.current_fcp.get('type') == 'EF':
                        content = extract_file_content(selected_fid, path)
                        if content: file_entry.update(content)
                        
                    report_data[path] = file_entry
                    if node['children']: deep_scan(node['children'], selected_fid, parent_path_list + [node['name']])
                else:
                    path = "/".join(parent_path_list + [node['name']])
                    print(f"  [-] Skipped: {path} (None of {node['fids']} found)")

            for wc in wildcard_nodes:
                template = wc['fids'][0]; prefix = template.replace('X', '')
                for i in range(256):
                    target_fid = f"{prefix}{i:02X}"
                    if target_fid in processed_fids: continue
                    
                    p_cmd = f"00A40400{len(parent_fid)//2:02X}{parent_fid}" if len(parent_fid) > 4 else f"00A4000002{parent_fid}"
                    self.tp.transmit(p_cmd, silent=True)
                    
                    cmd = f"00A4000402{target_fid}"
                    data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
                    
                    if sw1 == 0x90 or sw1 == 0x61:
                        self.current_fid = target_fid # [FIX] Sync state
                        self._parse_fcp_internal(data, target_fid=target_fid) # [FIX] Pass explicit target
                        
                        name = f"UNKNOWN_{target_fid}"; path = "/".join(parent_path_list + [name])
                        print(f"  > Found Wildcard: {path}")
                        self.current_path_hint = path
                        file_entry = {'fid': target_fid, 'name': name, 'meta': self.current_fcp.copy()}
                        if self.current_fcp.get('type') == 'EF':
                            content = extract_file_content(target_fid, path)
                            if content: file_entry.update(content)
                        report_data[path] = file_entry

        try:
            self.tp.transmit("00A40000023F00", silent=True)
            deep_scan(roots, "3F00", [])
            clean_data = self._sanitize_yaml(report_data)
            with open(filename, 'w') as outfile: yaml.dump(clean_data, outfile, default_flow_style=False, sort_keys=False)
            print(f"{Config.Colors.GREEN}[+] Report saved to {filename}{Config.Colors.ENDC}")
        except Exception as e: print(f"{Config.Colors.FAIL}[!] Report Generation Failed: {e}{Config.Colors.ENDC}")
        finally: self.tp.transmit("00A40004023F00", silent=True); self.current_fid = "3F00"

    def dump_fs_to_yaml(self, filename: str = "fs_report.yaml"):
        """
        Backward-compatible wrapper used by REPORT wizards.
        Produces a full deep file system YAML report.
        """
        self.generate_report(filename)

    def _get_live_iccid(self) -> str:
        self.tp.transmit("00A40000023F00", silent=True)
        data, sw1, sw2 = self.tp.transmit("00A40004022FE2", silent=True)
        
        valid_select = False
        if sw1 == 0x90:
            valid_select = True
        if sw1 == 0x61:
            valid_select = True
            
        if valid_select == False:
            return "UNKNOWN_ICCID"
            
        data, sw1, sw2 = self.tp.transmit("00B000000A", silent=True)
        if sw1 != 0x90:
            return "UNKNOWN_ICCID"
            
        hex_str = data.hex().upper()
        remainder = len(hex_str) % 2
        
        if remainder != 0:
            hex_str = hex_str + "F"
            
        decoded_iccid = ""
        for i in range(0, len(hex_str), 2):
            nibble1 = hex_str[i]
            nibble2 = hex_str[i+1]
            decoded_iccid += nibble2 + nibble1
            
        return decoded_iccid.rstrip("F")

    def dump_live_fs(self, output_dir: str):
        import shutil
        from pathlib import Path
        import yaml
        
        print(f"{Config.Colors.HEADER}[*] Initiating Deep Live File System Dump...{Config.Colors.ENDC}")
        
        file_exists = os.path.exists(Config.FIDS_FILE)
        if file_exists == False:
            print(f"{Config.Colors.FAIL}fids.txt missing. Tree navigation impossible.{Config.Colors.ENDC}")
            return

        iccid_val = self._get_live_iccid()
        root_dir = Path(output_dir).resolve() / iccid_val
        
        dir_exists = root_dir.exists()
        if dir_exists:
            shutil.rmtree(root_dir)
            
        root_dir.mkdir(parents=True, exist_ok=True)
        roots = self._load_tree_structure()

        def _write_ef_content(fid: str, file_path_base: Path):
            struct = self.current_fcp.get('structure', 'Unknown')
            content_file = file_path_base.with_suffix('.txt')
            
            with open(content_file, 'w') as f:
                f.write(f"--- File Metadata ---\n")
                f.write(f"FID: {fid}\n")
                f.write(f"Type: {self.current_fcp.get('type')} ({struct})\n\n")
                f.write(f"--- FCP Data ---\n")
                yaml.dump(self._sanitize_yaml(self.current_fcp), f, default_flow_style=False, sort_keys=False)
                f.write(f"\n--- File Data ---\n")

                if struct == 'Transparent':
                    data, sw1, sw2 = self.tp.transmit("00B0000000", silent=True)
                    if sw1 == 0x90:
                        hex_data = data.hex().upper()
                        f.write(f"Raw: {hex_data}\n")
                        decoded = ContentDecoder.decode_obj(
                            fid,
                            hex_data,
                            context_path=self.current_path_hint
                        )
                        if decoded:
                            yaml.dump(self._sanitize_yaml(decoded), f, default_flow_style=False, sort_keys=False)
                    if sw1 != 0x90:
                        f.write(f"Read Error: {sw1:02X}{sw2:02X}\n")

                if struct == 'Linear Fixed':
                    _read_records(fid, f)
                    
                if struct == 'Cyclic':
                    _read_records(fid, f)

        def _read_records(fid: str, file_handle):
            le = f"{self.current_fcp.get('rec_len', 0):02X}"
            for r in range(1, 255):
                cmd = f"00B2{r:02X}04{le}" 
                data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
                
                if sw1 == 0x90:
                    hex_data = data.hex().upper()
                    file_handle.write(f"Record {r:02X}: Raw: {hex_data}\n")
                    decoded = ContentDecoder.decode_obj(
                        fid,
                        hex_data,
                        context_path=self.current_path_hint
                    )
                    if decoded:
                        yaml.dump(self._sanitize_yaml(decoded), file_handle, default_flow_style=False, sort_keys=False)
                        file_handle.write("\n")
                        
                if sw1 == 0x6A:
                    break
                if sw1 != 0x90:
                    if sw1 != 0x6A:
                        break

        def _live_deep_scan(nodes, parent_fid, current_path: Path):
            processed_fids = set()
            
            explicit_nodes = []
            for n in nodes:
                has_wildcard = False
                for f in n['fids']:
                    if 'X' in f:
                        has_wildcard = True
                if has_wildcard == False:
                    explicit_nodes.append(n)

            wildcard_nodes = []
            for n in nodes:
                has_wildcard = False
                for f in n['fids']:
                    if 'X' in f:
                        has_wildcard = True
                if has_wildcard:
                    wildcard_nodes.append(n)

            for node in explicit_nodes:
                if len(parent_fid) > 4:
                    p_cmd = f"00A40400{len(parent_fid)//2:02X}{parent_fid}"
                if len(parent_fid) <= 4:
                    p_cmd = f"00A4000002{parent_fid}"
                    
                self.tp.transmit(p_cmd, silent=True)
                
                selected_fid = None
                last_data = None
                
                for fid in node['fids']:
                    if len(fid) > 4:
                        cmd = f"00A40404{len(fid)//2:02X}{fid}"
                    if len(fid) <= 4:
                        cmd = f"00A4000402{fid}"
                        
                    data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
                    
                    valid_sel = False
                    if sw1 == 0x90:
                        valid_sel = True
                    if sw1 == 0x61:
                        valid_sel = True
                        
                    if valid_sel:
                        selected_fid = fid
                        last_data = data
                        break 
                
                if selected_fid:
                    processed_fids.add(selected_fid)
                    self.current_fid = selected_fid
                    self._parse_fcp_internal(last_data, target_fid=selected_fid)
                    
                    node_dir = current_path
                    if self.current_fcp.get('type') == 'DF':
                        node_dir = current_path / node['name']
                        node_dir.mkdir(parents=True, exist_ok=True)
                        
                    if self.current_fcp.get('type') == 'EF':
                        file_base = current_path / node['name']
                        print(f"  > Dumping: {file_base}")
                        self.current_path_hint = str(file_base)
                        _write_ef_content(selected_fid, file_base)
                    
                    if node['children']:
                        _live_deep_scan(node['children'], selected_fid, node_dir)

            for wc in wildcard_nodes:
                template = wc['fids'][0]
                prefix = template.replace('X', '')
                
                for i in range(256):
                    target_fid = f"{prefix}{i:02X}"
                    
                    is_processed = False
                    if target_fid in processed_fids:
                        is_processed = True
                    if is_processed:
                        continue
                    
                    if len(parent_fid) > 4:
                        p_cmd = f"00A40400{len(parent_fid)//2:02X}{parent_fid}"
                    if len(parent_fid) <= 4:
                        p_cmd = f"00A4000002{parent_fid}"
                        
                    self.tp.transmit(p_cmd, silent=True)
                    
                    cmd = f"00A4000402{target_fid}"
                    data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
                    
                    valid_wc_sel = False
                    if sw1 == 0x90:
                        valid_wc_sel = True
                    if sw1 == 0x61:
                        valid_wc_sel = True
                        
                    if valid_wc_sel:
                        self.current_fid = target_fid
                        self._parse_fcp_internal(data, target_fid=target_fid)
                        
                        name = f"UNKNOWN_{target_fid}"
                        file_base = current_path / name
                        print(f"  > Found & Dumping Wildcard: {file_base}")
                        self.current_path_hint = str(file_base)
                        
                        if self.current_fcp.get('type') == 'EF':
                            _write_ef_content(target_fid, file_base)

        try:
            self.tp.transmit("00A40000023F00", silent=True)
            _live_deep_scan(roots, "3F00", root_dir)
            print(f"{Config.Colors.GREEN}[+] Live dump complete. Output saved to {root_dir}{Config.Colors.ENDC}")
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Dump Execution Failed: {e}{Config.Colors.ENDC}")
        finally:
            self.tp.transmit("00A40004023F00", silent=True)
            self.current_fid = "3F00"

    def activate_file(self, fid: str = "") -> None:
        """TS 102 221: Activate File (0044)."""
        apdu = "00440000"
        has_fid = False
        if len(fid) > 0:
            has_fid = True
        
        if has_fid:
            apdu = f"0044000002{fid}"
            
        self.tp.transmit(apdu)

    def deactivate_file(self, fid: str = "") -> None:
        """TS 102 221: Deactivate File (0004)."""
        apdu = "00040000"
        has_fid = False
        if len(fid) > 0:
            has_fid = True
            
        if has_fid:
            apdu = f"0004000002{fid}"
            
        self.tp.transmit(apdu)

    def suspend_uicc(self) -> None:
        """TS 102 221: Suspend UICC (8076)."""
        # P1=00: Minimum duration, P2=00: Suggested duration
        self.tp.transmit("8076000000")

    def search_record(self, search_hex: str) -> None:
        """TS 102 221: Search Record (00A2)."""
        # P2=04: Forward search from the beginning
        apdu = f"00A20104{len(search_hex)//2:02X}{search_hex}"
        self.tp.transmit(apdu)

    def create_file(self, data_hex: str) -> None:
        """TS 102 222: Create File (00E0)."""
        apdu = f"00E00000{len(data_hex)//2:02X}{data_hex}"
        self.tp.transmit(apdu)

    def delete_file(self, fid: str) -> None:
        """TS 102 222: Delete File (00E4)."""
        apdu = f"00E4000002{fid}"
        self.tp.transmit(apdu)

    def terminate_df(self, fid: str) -> None:
        """TS 102 222: Terminate DF (00E6)."""
        apdu = f"00E6000002{fid}"
        self.tp.transmit(apdu)

    def terminate_ef(self, fid: str) -> None:
        """TS 102 222: Terminate EF (00E8)."""
        apdu = f"00E8000002{fid}"
        self.tp.transmit(apdu)

    def resize_file(self, data_hex: str) -> None:
        """TS 102 222: Resize File (80D4)."""
        apdu = f"80D40000{len(data_hex)//2:02X}{data_hex}"
        self.tp.transmit(apdu)