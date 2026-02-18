import binascii
from typing import Dict, Any, List, Optional

# Internal Project Imports
from SCP03.core.utils import TlvParser

class AdvancedDecoders:
    @staticmethod
    def decode_ef_arr(data_hex: str) -> str:
        if not data_hex or data_hex.startswith('FF'): return "Empty/Invalid Rule"
        try: data = bytes.fromhex(data_hex)
        except: return "Hex Decode Error"
        output = []; i = 0; current_am_str = ""
        while i < len(data):
            try:
                tag = data[i]; length = data[i+1]; value = data[i+2 : i+2+length]; total_len = 2 + length
                if tag == 0x80: # AM Byte
                    am_byte = value[0]; modes = []
                    if am_byte & 0x01: modes.append("READ")
                    if am_byte & 0x02: modes.append("UPDATE")
                    if am_byte & 0x04: modes.append("APPEND")
                    if am_byte & 0x08: modes.append("DEACTIVATE")
                    if am_byte & 0x10: modes.append("ACTIVATE")
                    if am_byte & 0x40: modes.append("TERMINATE")
                    current_am_str = "/".join(modes) if modes else f"Proprietary(0x{am_byte:02X})"
                elif tag == 0x90: output.append(f"{current_am_str}: Always")
                elif tag == 0x97: output.append(f"{current_am_str}: Never")
                elif tag == 0xA4: # SC
                    sc_info = TlvParser.parse(value); key_ref = sc_info.get(0x83); cond_str = "Unknown SC"
                    if key_ref:
                        ref_val = key_ref[0]
                        if ref_val == 0x01: cond_str = "PIN1"
                        elif ref_val == 0x81: cond_str = "PIN1 (Global)"
                        elif ref_val == 0x0A: cond_str = "ADM1"
                        else: cond_str = f"ADM(0x{ref_val:02X})"
                    if current_am_str: output.append(f"{current_am_str}: {cond_str}")
                i += total_len
                if total_len == 0: break
            except IndexError: break
        return "\n".join(output) if output else "No Rules"

    @staticmethod
    def decode_plmn_list(data_hex: str) -> str:
        """Decodes PLMNwAcT, OPLMNwAcT, FPLMN lists."""
        if not data_hex or all(c == 'F' for c in data_hex): return "Empty List"
        try:
            data = bytes.fromhex(data_hex)
            entries = []
            step = 3
            if len(data) % 5 == 0: step = 5
            
            for i in range(0, len(data), step):
                if i + 3 > len(data): break
                plmn_bytes = data[i:i+3]
                if plmn_bytes == b'\xFF\xFF\xFF': continue
                
                b1, b2, b3 = plmn_bytes[0], plmn_bytes[1], plmn_bytes[2]
                mcc = f"{b1 & 0x0F}{b1 >> 4}{b2 & 0x0F}"
                mnc = f"{b3 & 0x0F}{b3 >> 4}"
                if (b2 & 0xF0) != 0xF0: mnc = f"{b2 >> 4}{mnc}"
                
                entry_str = f"MCC: {mcc}, MNC: {mnc}"
                if step == 5:
                    act_bytes = int.from_bytes(data[i+3:i+5], 'big')
                    acts = []
                    if act_bytes & 0x8000: acts.append("UTRAN")
                    if act_bytes & 0x4000: acts.append("E-UTRAN")
                    if act_bytes & 0x0080: acts.append("GSM")
                    if act_bytes & 0x0008: acts.append("NG-RAN")
                    entry_str += f" | AcT: {', '.join(acts) if acts else 'None'}"
                entries.append(entry_str)
            return "\n".join(entries) if entries else "No Valid Entries"
        except: return "PLMN Decode Error"

    @staticmethod
    def decode_loci(data_hex: str) -> str:
        """Decodes EF_LOCI (Location Information)."""
        try:
            data = bytes.fromhex(data_hex)
            if len(data) < 11: return f"Invalid LOCI Length ({len(data)})"
            tmsi = data[0:4].hex().upper()
            mcc_mnc_bytes = data[4:7]
            b1, b2, b3 = mcc_mnc_bytes[0], mcc_mnc_bytes[1], mcc_mnc_bytes[2]
            mcc = f"{b1 & 0x0F}{b1 >> 4}{b2 & 0x0F}"
            mnc = f"{b3 & 0x0F}{b3 >> 4}"
            if (b2 & 0xF0) != 0xF0: mnc = f"{b2 >> 4}{mnc}"
            lac = int.from_bytes(data[7:9], 'big')
            status_byte = data[10]
            status_map = {0: "Updated", 1: "Not Updated", 2: "PLMN Not Allowed", 3: "Loc Not Allowed"}
            return f"TMSI: {tmsi}\nLAI: {mcc}-{mnc} (LAC: {lac})\nStatus: {status_map.get(status_byte & 0x03, 'Unknown')}"
        except: return "LOCI Decode Error"

    @staticmethod
    def decode_ust(data_hex: str) -> str:
        """Decodes EF_UST (USIM Service Table) per 3GPP TS 31.102."""
        if not data_hex: return "Empty"
        try:
            data = bytes.fromhex(data_hex)
            services = []
            # Complete 3GPP TS 31.102 UST Mapping
            ust_map = {
                1: "Local Phone Book", 2: "FDN", 3: "Extension 2", 4: "SDN", 5: "Extension 3", 
                6: "SMS", 7: "BDN", 8: "OCI", 9: "ICI", 10: "SMS-PP Download", 
                11: "SMS-CB Download", 12: "Call Control by USIM", 13: "MO-SMS Control", 
                14: "RUN AT COMMAND", 15: "Ignored", 16: "Enabled Services Table", 17: "ACL", 
                18: "Depersonalisation Keys", 19: "Co-operative Network List", 20: "GSM Access", 
                21: "OPLMNwAcT", 22: "LOCI", 23: "PSLOCI", 24: "SMSS", 25: "SPN", 26: "ECC", 
                27: "MCC", 28: "Extension 5", 29: "HPLMNwAcT", 30: "CPBCCH", 31: "Inv Scan", 
                32: "MexE", 33: "RPLMNAcT", 34: "HPLMN", 35: "Extension 6", 36: "Extension 7", 
                37: "Extension 8", 38: "Call Control on GPRS", 39: "MMS", 40: "Extension 8", 
                41: "MMS UCP", 42: "NIA", 43: "VGCS/VBS Group ID", 44: "VGCS/VBS Service ID", 
                45: "VGCS Security", 46: "VBS Security", 50: "TIA/EIA-136", 52: "GBA", 
                53: "MMS Prefs", 54: "GBA", 55: "MBMS Security", 56: "USSD Data Download", 
                57: "Equivalent HPLMN", 58: "Terminal Profile", 59: "EHPLMN PI", 60: "Last RPLMN Sel", 
                61: "OMA BCAST", 62: "GBA-PUSH", 63: "PWS Config", 64: "FDN URI", 65: "BDN URI", 
                66: "SDN URI", 67: "OCI URI", 68: "ICI URI", 69: "IAL URI", 70: "IPS URI", 
                71: "IPD URI", 72: "ePDG Config (3GPP)", 73: "ePDG Config (Non-3GPP)", 
                74: "IMS Config Data", 75: "3GPP PS Data Off", 76: "3GPP PS Data Off List", 
                77: "XCAP Config", 78: "EARFCN List", 79: "MuD/MiD Config", 80: "EAKA", 81: "OCST", 
                82: "AC_GBAUAPI", 83: "IMS DCI", 84: "From Preferred", 85: "UICC Access to IMS", 
                86: "Extended LOCI", 87: "Extended PSLOCI", 88: "5GS 3GPP LOCI", 89: "5GS N3GPP LOCI", 
                90: "5GS 3GPP NSC", 91: "5GS N3GPP NSC", 92: "5G Auth Keys", 93: "UAC AIC", 
                94: "SUCI Calc Info", 95: "OPL5G", 96: "SUPI NAI", 97: "Routing Indicator", 
                98: "URSP", 99: "TN3GPPSNN", 100: "CAG", 101: "SOR-CMCI", 102: "DRI", 
                103: "5G SE-DRX", 104: "5G NSWO Conf", 105: "MCHPPLMN", 106: "KAUSF Derivation",
                113: "5G Parameters"
            }
            
            for byte_idx, byte_val in enumerate(data):
                for bit_idx in range(8):
                    service_num = (byte_idx * 8) + bit_idx + 1
                    if byte_val & (1 << bit_idx):
                        name = ust_map.get(service_num, f"Service {service_num}")
                        services.append(f"{service_num}: {name}")
            
            return "Active Services:\n" + "\n".join(services) if services else "No Services Active"
        except: return "UST Decode Error"

class ContentDecoder:
    _registry = {}

    @classmethod
    def init_registry(cls):
        """Initializes the mapping of FIDs to decoding methods."""
        cls._registry = {
            # --- MF Level ---
            '2FE2': cls.decode_iccid,
            '2F00': cls.decode_dir,
            '2F06': AdvancedDecoders.decode_ef_arr,
            '2F05': lambda x: f"Preferred Languages: {x}", 

            # --- USIM (7FF0) ---
            '6F07': cls.decode_imsi,
            '6FAD': cls.decode_ad,
            '6F06': AdvancedDecoders.decode_ef_arr,
            '6F08': lambda x: f"Ciphering Keys (Raw): {x}", 
            '6F78': cls.decode_acc, 
            '6F31': lambda x: f"HPPLMN Search Interval: {int(x, 16)}", 
            '6F38': AdvancedDecoders.decode_ust, # EF_UST
            '6F40': cls.decode_msisdn,
            '6F46': lambda x: f"SPN: {bytes.fromhex(x)[1:].decode('utf-8','ignore')}" if x and len(x)>2 else "Invalid SPN",
            
            # Networking
            '6F7B': AdvancedDecoders.decode_plmn_list, # FPLMN
            '6F60': AdvancedDecoders.decode_plmn_list, # PLMNwAcT
            '6F61': AdvancedDecoders.decode_plmn_list, # OPLMNwAcT
            '6F62': AdvancedDecoders.decode_plmn_list, # HPLMNwAcT
            '6FD9': AdvancedDecoders.decode_plmn_list, # EHPLMN
            
            # Location
            '6F7E': AdvancedDecoders.decode_loci, # LOCI
            '6F73': AdvancedDecoders.decode_loci, # PSLOCI
            '6FE3': AdvancedDecoders.decode_loci, # EPSLOCI
            
            # 5GS
            '4F01': AdvancedDecoders.decode_loci, # 5GS3GPPLOCI
            
            # SMS
            '6F42': cls.decode_sms_params,
            '6F3C': lambda x: f"SMS Record: {x[:30]}...", 
            
            # Misc
            '6F5B': lambda x: f"START-HFN: {x}",
            '6F5C': lambda x: f"Threshold: {x}",
            '6F05': lambda x: f"LI: {x}",
            '6F37': lambda x: f"ACM Max: {x}",
            '6F39': lambda x: f"ACM: {x}",
            '6F3E': lambda x: f"GID1: {x}",
            '6F3F': lambda x: f"GID2: {x}",
            '6F56': AdvancedDecoders.decode_ust, # EF_EST
        }

    @classmethod
    def decode(cls, fid: str, hex_data: str) -> Optional[str]:
        if not fid: return None
        fid = fid.upper()
        if not cls._registry: cls.init_registry()
        
        handler = cls._registry.get(fid)
        if handler: return handler(hex_data)
        return None

    @staticmethod
    def decode_acc(hex_str: str) -> str:
        try:
            val = int(hex_str, 16)
            classes = []
            for i in range(16):
                if val & (1 << i): classes.append(str(i))
            return f"Access Control Classes: {', '.join(classes)}"
        except: return "ACC Decode Error"

    @staticmethod
    def decode_dir(hex_str: str) -> str:
        try:
            if all(c == 'F' for c in hex_str): return "Empty Record"
            data = bytes.fromhex(hex_str)
            if not data: return ""
            parsed = TlvParser.parse(data)
            app = parsed.get(0x61)
            if app:
                inner = TlvParser.parse(app) if isinstance(app, bytes) else app
                aid = inner.get(0x4F, b'').hex().upper()
                label = inner.get(0x50, b'').decode('ascii', 'ignore').strip()
                return f"AID: {aid} | Label: {label}"
            return f"Raw DIR Data: {hex_str} (No Tag 0x61)"
        except Exception as e: return f"DIR Decode Error: {e}"

    @staticmethod
    def decode_msisdn(hex_str: str) -> str:
        try:
            if all(c == 'F' for c in hex_str): return "Empty Record"
            data = bytes.fromhex(hex_str)
            if len(data) < 14: return f"Invalid Length ({len(data)})"
            
            footer_len = 14
            alpha_len = len(data) - footer_len
            alpha_id = data[:alpha_len].decode('utf-8', 'ignore').strip() if alpha_len > 0 else ""
            
            footer = data[alpha_len:]
            ton_npi = footer[1]
            bcd_data = footer[2:12].hex().upper()
            digits = [bcd_data[i+1] + bcd_data[i] for i in range(0, len(bcd_data), 2)]
            dial_num = "".join(digits).replace('F', '')
            
            out = []
            if alpha_id: out.append(f"Alpha ID: {alpha_id}")
            out.append(f"Dialing Number: {dial_num}")
            out.append(f"TON/NPI: {ton_npi:02X}")
            return "\n".join(out)
        except Exception as e: return f"MSISDN Decode Error: {e}"

    @staticmethod
    def decode_iccid(hex_str: str) -> str:
        try:
            res = [hex_str[i+1] + hex_str[i] for i in range(0, len(hex_str), 2)]
            return f"iccid: {''.join(res).replace('F', '')}"
        except: return f"iccid: {hex_str} (raw)"

    @staticmethod
    def decode_imsi(hex_str: str) -> str:
        try:
            imsi_hex = hex_str[2:]
            res = [imsi_hex[1]] + [imsi_hex[i+1] + imsi_hex[i] for i in range(2, len(imsi_hex), 2)]
            return f"imsi: {''.join(res).replace('F', '')}"
        except: return f"imsi: {hex_str} (raw)"

    @staticmethod
    def decode_ad(hex_str: str) -> str:
        try:
            mode = int(hex_str[0:2], 16)
            m_map = {0: "Normal", 1: "Type Approval", 2: "Normal/Internal", 4: "Normal/Internal", 128: "Proprietary"}
            return f"Administrative Mode: {m_map.get(mode, f'0x{mode:02X}')}"
        except: return None

    @staticmethod
    def decode_sms_params(hex_str: str) -> str:
        return f"SMS Params (Raw): {hex_str[:20]}..."

    @classmethod
    def decode_obj(cls, fid: str, hex_data: str) -> Optional[Dict[str, Any]]:
        val = cls.decode(fid, hex_data)
        if val: return {'description': val}
        return None