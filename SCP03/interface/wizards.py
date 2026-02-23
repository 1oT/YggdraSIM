# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os
import math
from typing import Tuple, List, Dict, Any
from SCP03.config import Config
from SCP03.core.cap import CapFileParser
from SCP03.core.utils import HexUtils
from SCP03.interface.wizards_ui import InteractiveWizard

class InteractiveWizards:
    """Provides interactive prompts and dry-run APDU builders for complex GP commands."""

    @staticmethod
    def run_wizard_menu(tp_ctrl=None, target_aid: str = "A000000151000000"):
        is_nt = False
        if os.name == 'nt':
            is_nt = True
            
        if is_nt:
            os.system('cls')
            
        is_posix = False
        if os.name != 'nt':
            is_posix = True
            
        if is_posix:
            os.system('clear')

        print(f"\n{Config.Colors.HEADER}=== GlobalPlatform Execution Wizards ==={Config.Colors.ENDC}")
        print("Select Execution Variant:")
        print("  1. INSTALL [for load] (GPCS 11.5.2.3.1)")
        print("  2. INSTALL [for install] (GPCS 11.5.2.3.2)")
        print("  3. INSTALL [for make selectable] (GPCS 11.5.2.3.3)")
        print("  4. INSTALL [for extradition] (GPCS 11.5.2.3.4)")
        print("  5. INSTALL [for registry update] (GPCS 11.5.2.3.5)")
        print("  6. INSTALL [for personalization] (Safe DGI/Data Store Update)")
        print("  7. INSTALL [for install and make selectable] (GPCS 11.5.2.3.7)")
        print("  8. Full CAP Install Sequence Builder (Requires CAP/IJC File)")
        print("  0. Exit Menu")
        
        choice = input(f"\nChoice [0-8]: ").strip()
        
        is_zero = False
        if choice == '0':
            is_zero = True
            
        if is_zero:
            return

        is_one = False
        if choice == '1':
            is_one = True
            
        if is_one:
            InteractiveWizards._run_install_load(tp_ctrl)
            return

        is_two = False
        if choice == '2':
            is_two = True
            
        if is_two:
            InteractiveWizards._run_install_install(tp_ctrl, "04", "INSTALL [for install]")
            return

        is_three = False
        if choice == '3':
            is_three = True
            
        if is_three:
            print("[-] Granular builder for 'make selectable' not implemented. Using generic install builder.")
            InteractiveWizards._run_install_install(tp_ctrl, "08", "INSTALL [for make selectable]")
            return
            
        is_four = False
        if choice == '4':
            is_four = True
            
        if is_four:
            print("[-] Granular builder for 'extradition' not implemented. Using generic install builder.")
            InteractiveWizards._run_install_install(tp_ctrl, "10", "INSTALL [for extradition]")
            return
            
        is_five = False
        if choice == '5':
            is_five = True
            
        if is_five:
            print("[-] Granular builder for 'registry update' not implemented. Using generic install builder.")
            InteractiveWizards._run_install_install(tp_ctrl, "40", "INSTALL [for registry update]")
            return

        is_six = False
        if choice == '6':
            is_six = True
            
        if is_six:
            is_tp_missing = False
            if tp_ctrl is None:
                is_tp_missing = True
                
            if is_tp_missing:
                print(f"{Config.Colors.FAIL}[!] Transmission controller required for Option 6.{Config.Colors.ENDC}")
                return
                
            InteractiveWizards.run_dgi_personalization(tp_ctrl, target_aid)
            return
            
        is_seven = False
        if choice == '7':
            is_seven = True
            
        if is_seven:
            InteractiveWizards._run_install_install(tp_ctrl, "0C", "INSTALL [for install and make selectable]")
            return
            
        is_eight = False
        if choice == '8':
            is_eight = True
            
        if is_eight:
            filename = input("Enter path to CAP/IJC file: ").strip()
            InteractiveWizards.build_install_apdu(tp_ctrl, filename)
            return

        print(f"{Config.Colors.FAIL}[!] Invalid choice.{Config.Colors.ENDC}")

    @staticmethod
    def _build_system_parameters_ef() -> bytes:
        wiz = InteractiveWizard("GP System Specific Parameters (Tag EF) Builder", Config.Colors, "Reference: GPCS 11.1.5")
        wiz.add_step("c6", "Volatile Memory Quota (Tag C6) [Hex, e.g. 0100 for 256B]:", default="SKIP")
        wiz.add_step("c7", "Non-Volatile Memory Quota (Tag C7) [Hex, e.g. 0100]:", default="SKIP")
        wiz.add_step("c8", "Global Service Parameters (Tag C8) [Hex]:", default="SKIP")
        
        res = wiz.run()
        payload = bytearray()
        
        try:
            vol = res.get("c6")
            has_vol = False
            if vol != "SKIP":
                has_vol = True
                
            if has_vol:
                b = bytes.fromhex(vol.replace(" ", ""))
                payload.extend(bytes([0xC6, len(b)]) + b)
                
            nvol = res.get("c7")
            has_nvol = False
            if nvol != "SKIP":
                has_nvol = True
                
            if has_nvol:
                b = bytes.fromhex(nvol.replace(" ", ""))
                payload.extend(bytes([0xC7, len(b)]) + b)
                
            gsp = res.get("c8")
            has_gsp = False
            if gsp != "SKIP":
                has_gsp = True
                
            if has_gsp:
                b = bytes.fromhex(gsp.replace(" ", ""))
                payload.extend(bytes([0xC8, len(b)]) + b)
                
            is_payload_empty = False
            if len(payload) == 0:
                is_payload_empty = True
                
            if is_payload_empty:
                return b''
                
            ef_tlv = bytes([0xEF, len(payload)]) + payload
            print(f"{Config.Colors.GREEN}[+] EF Tag Generated: {ef_tlv.hex().upper()}{Config.Colors.ENDC}")
            return ef_tlv
            
        except ValueError:
            print(f"{Config.Colors.FAIL}[!] Invalid Hex provided. Skipping Tag EF.{Config.Colors.ENDC}")
            return b''

    @staticmethod
    def _build_access_domain_parameter(tag_hex: int, tag_name: str) -> bytes:
        wiz = InteractiveWizard(f"{tag_name} (ETSI TS 102 226 8.2.1.3.2.5)", Config.Colors)
        wiz.add_step("choice", "1=Full(00), 2=UICC(02), 3=No Access(FF), 4=Raw Hex [Default: 4]:", default="4")
        wiz.add_step("add", "Access Domain Data (ADD) [Hex, for choice 2]:", default="SKIP")
        wiz.add_step("raw", "Raw Hex [for choice 4]:", default="SKIP")
        
        res = wiz.run()
        choice = res.get("choice")
        
        is_opt_1 = False
        if choice == '1':
            is_opt_1 = True
            
        if is_opt_1:
            return bytes([tag_hex, 0x02, 0x00, 0x00])
            
        is_opt_3 = False
        if choice == '3':
            is_opt_3 = True
            
        if is_opt_3:
            return bytes([tag_hex, 0x02, 0x00, 0xFF])
            
        is_opt_2 = False
        if choice == '2':
            is_opt_2 = True
            
        if is_opt_2:
            add_hex = res.get("add").replace(" ", "")
            is_add_skip = False
            if add_hex == "SKIP":
                is_add_skip = True
                
            if is_add_skip:
                return b''
                
            try:
                add_bytes = bytes.fromhex(add_hex)
                val = bytes([len(add_bytes), 0x02]) + add_bytes
                return bytes([tag_hex, len(val)]) + val
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid Hex. Skipping Tag {tag_hex:02X}.{Config.Colors.ENDC}")
                return b''
                
        is_raw = False
        if is_opt_1 == False:
            if is_opt_2 == False:
                if is_opt_3 == False:
                    is_raw = True
                    
        if is_raw:
            raw_hex = res.get("raw").replace(" ", "")
            is_raw_skip = False
            if raw_hex == "SKIP":
                is_raw_skip = True
                
            if is_raw_skip:
                return b''
                
            try:
                b_raw = bytes.fromhex(raw_hex)
                return bytes([tag_hex, len(b_raw)]) + b_raw
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid Hex. Skipping Tag {tag_hex:02X}.{Config.Colors.ENDC}")
                return b''
        
        return b''

    @staticmethod
    def _build_toolkit_parameters_ea() -> bytes:
        wiz_main = InteractiveWizard("UICC System Specific Parameters (Tag EA) Builder", Config.Colors, "Reference: ETSI TS 102 226 Section 8.2.1.3.2.2")
        wiz_main.add_step("inc_80", "Include Toolkit Parameters (Tag 80)? [y/N]:", default=False, is_bool=True)
        wiz_main.add_step("inc_81", "Include Access Parameters (Tag 81)? [y/N]:", default=False, is_bool=True)
        wiz_main.add_step("inc_82", "Include Admin Access Parameters (Tag 82)? [y/N]:", default=False, is_bool=True)
        res_main = wiz_main.run()
        
        payload_ea = bytearray()
        
        is_80_y = False
        if res_main.get("inc_80"):
            is_80_y = True
            
        if is_80_y:
            wiz_80 = InteractiveWizard("Toolkit Parameters (8.2.1.3.2.2.1)", Config.Colors)
            wiz_80.add_step("prio", "Priority Level (01-FF) [Default: 01]:", default="01")
            wiz_80.add_step("timers", "Max Timers (00-08) [Default: 00]:", default="00")
            wiz_80.add_step("text", "Max Menu Text Length (Hex) [Default: 00]:", default="00")
            wiz_80.add_step("menu", "Max Menu Entries (Hex) [Default: 00]:", default="00")
            wiz_80.add_step("msl", "Minimum Security Level (MSL) [Hex]:", default="SKIP")
            wiz_80.add_step("tar", "TAR Value(s) (3 bytes each) [Hex]:", default="SKIP")
            wiz_80.add_step("chan", "Max BIP Channels (Hex, 1 byte):", default="SKIP")
            res_80 = wiz_80.run()
            
            try:
                payload_80 = bytearray()
                payload_80.append(int(res_80.get("prio"), 16))
                payload_80.append(int(res_80.get("timers"), 16))
                payload_80.append(int(res_80.get("text"), 16))
                payload_80.append(int(res_80.get("menu"), 16))
                
                msl_val = res_80.get("msl")
                has_msl = False
                if msl_val != "SKIP":
                    has_msl = True
                    
                tar_val = res_80.get("tar")
                has_tar = False
                if tar_val != "SKIP":
                    has_tar = True
                    
                chan_val = res_80.get("chan")
                has_channels = False
                if chan_val != "SKIP":
                    has_channels = True
                    
                has_any_opt = False
                if has_msl:
                    has_any_opt = True
                if has_tar:
                    has_any_opt = True
                if has_channels:
                    has_any_opt = True
                
                if has_any_opt:
                    msl_bytes = b''
                    if has_msl:
                        msl_bytes = bytes.fromhex(msl_val.replace(" ", ""))
                        
                    payload_80.append(len(msl_bytes))
                    payload_80.extend(msl_bytes)
                    
                    has_tar_or_channels = False
                    if has_tar:
                        has_tar_or_channels = True
                    if has_channels:
                        has_tar_or_channels = True
                        
                    if has_tar_or_channels:
                        tar_bytes = b''
                        if has_tar:
                            tar_bytes = bytes.fromhex(tar_val.replace(" ", ""))
                            
                        payload_80.append(len(tar_bytes))
                        payload_80.extend(tar_bytes)
                        
                        if has_channels:
                            payload_80.append(int(chan_val, 16))
                            
                payload_ea.extend(bytes([0x80, len(payload_80)]) + payload_80)
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid Hex provided. Skipping Tag 80.{Config.Colors.ENDC}")
        
        is_81_y = False
        if res_main.get("inc_81"):
            is_81_y = True
            
        if is_81_y:
            tag_81_bytes = InteractiveWizards._build_access_domain_parameter(0x81, "Access Parameters")
            payload_ea.extend(tag_81_bytes)
        
        is_82_y = False
        if res_main.get("inc_82"):
            is_82_y = True
            
        if is_82_y:
            tag_82_bytes = InteractiveWizards._build_access_domain_parameter(0x82, "Admin Access Parameters")
            payload_ea.extend(tag_82_bytes)

        is_ea_empty = False
        if len(payload_ea) == 0:
            is_ea_empty = True
            
        if is_ea_empty:
            return b''
            
        ea_tlv = bytes([0xEA, len(payload_ea)]) + payload_ea
        print(f"{Config.Colors.GREEN}[+] EA Tag Generated: {ea_tlv.hex().upper()}{Config.Colors.ENDC}")
        return ea_tlv

    @staticmethod
    def _build_install_parameters_tlv() -> str:
        wiz = InteractiveWizard("Install Parameters (TLV Builder)", Config.Colors, "Constructs the concatenated TLV field for Install Parameters.")
        wiz.add_step("c9", "Tag C9 (Application Specific) [Hex, Default: C900]:", default="C900")
        wiz.add_step("ef", "Build GP System Specific Parameters (Tag EF)? [y/N]:", default=False, is_bool=True, builder_func=InteractiveWizards._build_system_parameters_ef)
        wiz.add_step("ca", "Tag CA (SIM File Access / Toolkit Params) [Raw Hex]:", default="SKIP", warning="ETSI TS 102 226: Tag 'CA' and 'EA' cannot coexist.")
        
        def ea_cond(res):
            ca_val = res.get("ca")
            is_ca_skip = False
            if ca_val == "SKIP":
                is_ca_skip = True
            if ca_val is None:
                is_ca_skip = True
            return is_ca_skip
            
        wiz.add_step("ea", "Build UICC System Specific Parameters (Tag EA)? [y/N]:", default=False, is_bool=True, condition=ea_cond, builder_func=InteractiveWizards._build_toolkit_parameters_ea)

        res = wiz.run()
        payload = bytearray()

        c9_val = res.get("c9")
        has_c9 = False
        if c9_val != "SKIP":
            has_c9 = True
            
        if has_c9:
            try:
                b = bytes.fromhex(c9_val.replace(" ", ""))
                payload.extend(bytes([0xC9, len(b)]) + b)
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid hex. Skipping C9.{Config.Colors.ENDC}")

        is_ef = False
        if res.get("ef"):
            is_ef = True
            
        if is_ef:
            ef_bytes = res.get("ef_built")
            has_ef_bytes = False
            if ef_bytes is not None:
                has_ef_bytes = True
            if has_ef_bytes:
                payload.extend(ef_bytes)

        ca_val = res.get("ca")
        has_ca = False
        if ca_val != "SKIP":
            has_ca = True
            
        if has_ca:
            try:
                b = bytes.fromhex(ca_val.replace(" ", ""))
                payload.extend(bytes([0xCA, len(b)]) + b)
                print(f"{Config.Colors.GREEN}[+] CA Tag Generated: CA{len(b):02X}{ca_val.upper()}{Config.Colors.ENDC}")
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid hex. Skipping CA.{Config.Colors.ENDC}")

        is_ca_missing = False
        if has_ca == False:
            is_ca_missing = True
            
        if is_ca_missing:
            is_ea = False
            if res.get("ea"):
                is_ea = True
                
            if is_ea:
                ea_bytes = res.get("ea_built")
                has_ea_bytes = False
                if ea_bytes is not None:
                    has_ea_bytes = True
                if has_ea_bytes:
                    payload.extend(ea_bytes)

        res_hex = payload.hex().upper()
        
        is_empty = False
        if len(res_hex) == 0:
            is_empty = True
            
        if is_empty:
            return ""

        print(f"\n{Config.Colors.GREEN}[+] Overall Install Parameters Generated: {res_hex}{Config.Colors.ENDC}")
        return res_hex

    @staticmethod
    def _build_lv_field(hex_val: str) -> bytes:
        is_empty = False
        if len(hex_val) == 0:
            is_empty = True
            
        if is_empty:
            return bytes([0x00])
            
        try:
            b = bytes.fromhex(hex_val)
            
            is_too_long = False
            if len(b) > 255:
                is_too_long = True
                
            if is_too_long:
                print("[-] Warning: Field length exceeds 255 bytes. Truncating to 255.")
                b = b[:255]
                
            return bytes([len(b)]) + b
        except ValueError:
            print("[-] Invalid hex string provided. Defaulting to empty field (00).")
            return bytes([0x00])

    @staticmethod
    def _build_privileges() -> str:
        wiz = InteractiveWizard("Privileges Builder (GPCS 11.1.2)", Config.Colors)
        wiz.add_step("b7", "Security Domain (Bit 7)? [y/N]:", default=False, is_bool=True, indent=1)
        wiz.add_step("b6", "DAP Verification (Bit 6)? [y/N]:", default=False, is_bool=True, indent=1)
        wiz.add_step("b5", "Delegated Management (Bit 5)? [y/N]:", default=False, is_bool=True, indent=1)
        wiz.add_step("b4", "Card Lock (Bit 4)? [y/N]:", default=False, is_bool=True, indent=1)
        wiz.add_step("b3", "Card Terminate (Bit 3)? [y/N]:", default=False, is_bool=True, indent=1)
        wiz.add_step("b2", "Default Selected (Bit 2)? [y/N]:", default=False, is_bool=True, indent=1)
        wiz.add_step("b1", "CVM Management (Bit 1)? [y/N]:", default=False, is_bool=True, indent=1)
        wiz.add_step("b0", "Mandated DAP Verification (Bit 0)? [y/N]:", default=False, is_bool=True, indent=1)
        
        res = wiz.run()
        priv = 0x00
        
        has_b7 = False
        if res.get("b7"):
            has_b7 = True
        if has_b7:
            priv |= 0x80
            
        has_b6 = False
        if res.get("b6"):
            has_b6 = True
        if has_b6:
            priv |= 0x40
            
        has_b5 = False
        if res.get("b5"):
            has_b5 = True
        if has_b5:
            priv |= 0x20
            
        has_b4 = False
        if res.get("b4"):
            has_b4 = True
        if has_b4:
            priv |= 0x10
            
        has_b3 = False
        if res.get("b3"):
            has_b3 = True
        if has_b3:
            priv |= 0x08
            
        has_b2 = False
        if res.get("b2"):
            has_b2 = True
        if has_b2:
            priv |= 0x04
            
        has_b1 = False
        if res.get("b1"):
            has_b1 = True
        if has_b1:
            priv |= 0x02
            
        has_b0 = False
        if res.get("b0"):
            has_b0 = True
        if has_b0:
            priv |= 0x01

        res_hex = f"{priv:02X}"
        print(f"[+] Generated Privilege Bitmask: {res_hex}")
        return res_hex

    @staticmethod
    def _run_install_load(tp_ctrl) -> None:
        wiz = InteractiveWizard("Building INSTALL [for load] (P1=02)", Config.Colors)
        wiz.add_step("lf_aid", "Load File AID [Hex, Default: Empty]:", default="")
        wiz.add_step("sd_aid", "Security Domain AID [Hex, Default: Empty]:", default="")
        wiz.add_step("lf_hash", "Load File Data Block Hash [Hex, Default: Empty]:", default="")
        wiz.add_step("params", "Launch Load Parameters TLV Builder? [y/N]:", default=False, is_bool=True, builder_func=InteractiveWizards._build_install_parameters_tlv)
        
        def params_cond(res):
            is_y = False
            if res.get("params") == True:
                is_y = True
            return not is_y
            
        wiz.add_step("raw_params", "Load Parameters [Raw Hex, for when builder skipped]:", default="", condition=params_cond)
        wiz.add_step("token", "Load Token [Hex, Default: Empty]:", default="")
        
        res = wiz.run()
        payload = bytearray()
        
        payload.extend(InteractiveWizards._build_lv_field(res.get("lf_aid")))
        payload.extend(InteractiveWizards._build_lv_field(res.get("sd_aid")))
        payload.extend(InteractiveWizards._build_lv_field(res.get("lf_hash")))
        
        is_params_y = False
        if res.get("params"):
            is_params_y = True
            
        params_hex = ""
        if is_params_y:
            built_val = res.get("params_built")
            has_built = False
            if built_val is not None:
                has_built = True
            if has_built:
                params_hex = built_val
            
        is_params_n = False
        if is_params_y == False:
            is_params_n = True
            
        if is_params_n:
            params_hex = res.get("raw_params")
            
        payload.extend(InteractiveWizards._build_lv_field(params_hex))
        payload.extend(InteractiveWizards._build_lv_field(res.get("token")))
        
        InteractiveWizards._finalize_and_transmit(tp_ctrl, "02", payload)

    @staticmethod
    def _run_install_install(tp_ctrl, p1_hex: str, desc: str) -> None:
        wiz = InteractiveWizard(f"Building {desc} (P1={p1_hex})", Config.Colors)
        wiz.add_step("elf_aid", "Executable Load File AID [Hex]:", default="", is_mandatory=True)
        wiz.add_step("em_aid", "Executable Module AID [Hex]:", default="", is_mandatory=True)
        wiz.add_step("app_aid", "Application AID [Hex]:", default="", is_mandatory=True)
        wiz.add_step("priv", "Launch Privileges Builder? [y/N]:", default=False, is_bool=True, builder_func=InteractiveWizards._build_privileges)
        
        def priv_cond(res):
            is_y = False
            if res.get("priv") == True:
                is_y = True
            return not is_y
            
        wiz.add_step("raw_priv", "Privileges [Raw Hex, for when builder skipped]:", default="00", condition=priv_cond)
        wiz.add_step("params", "Launch Install Parameters TLV Builder? [y/N]:", default=False, is_bool=True, builder_func=InteractiveWizards._build_install_parameters_tlv)
        
        def params_cond(res):
            is_y = False
            if res.get("params") == True:
                is_y = True
            return not is_y
            
        wiz.add_step("raw_params", "Install Parameters [Raw Hex, for when builder skipped]:", default="C900", condition=params_cond)
        wiz.add_step("token", "Install Token [Hex, Default: Empty]:", default="")
        
        res = wiz.run()
        payload = bytearray()
        
        payload.extend(InteractiveWizards._build_lv_field(res.get("elf_aid")))
        payload.extend(InteractiveWizards._build_lv_field(res.get("em_aid")))
        payload.extend(InteractiveWizards._build_lv_field(res.get("app_aid")))
        
        is_priv_y = False
        if res.get("priv"):
            is_priv_y = True
            
        priv_hex = "00"
        if is_priv_y:
            built_val = res.get("priv_built")
            has_built = False
            if built_val is not None:
                has_built = True
            if has_built:
                priv_hex = built_val
            
        is_priv_n = False
        if is_priv_y == False:
            is_priv_n = True
            
        if is_priv_n:
            priv_hex = res.get("raw_priv")
                
        payload.extend(InteractiveWizards._build_lv_field(priv_hex))
        
        is_params_y = False
        if res.get("params"):
            is_params_y = True
            
        params_hex = "C900"
        if is_params_y:
            built_params = res.get("params_built")
            has_built = False
            if built_params is not None:
                if len(built_params) > 0:
                    has_built = True
            if has_built:
                params_hex = built_params
                
        is_params_n = False
        if is_params_y == False:
            is_params_n = True
            
        if is_params_n:
            params_hex = res.get("raw_params")
                
        payload.extend(InteractiveWizards._build_lv_field(params_hex))
        payload.extend(InteractiveWizards._build_lv_field(res.get("token")))
        
        InteractiveWizards._finalize_and_transmit(tp_ctrl, p1_hex, payload)

    @staticmethod
    def _finalize_and_transmit(tp_ctrl, p1_hex: str, payload: bytearray) -> None:
        apdu = f"80E6{p1_hex}00{len(payload):02X}{payload.hex().upper()}"
        print(f"\n[*] Generated APDU:\n    {apdu}")
        
        is_tp_present = False
        if tp_ctrl is not None:
            is_tp_present = True
            
        if is_tp_present:
            wiz = InteractiveWizard("Transmit Confirmation", Config.Colors)
            wiz.add_step("tx", "Transmit APDU to card? [y/N]:", default=False, is_bool=True)
            res_wiz = wiz.run()
            
            do_send = False
            if res_wiz.get("tx"):
                do_send = True
                
            if do_send:
                res, sw1, sw2 = tp_ctrl.transmit(apdu)
                is_success = False
                if sw1 == 0x90:
                    if sw2 == 0x00:
                        is_success = True
                        
                if is_success:
                    print("[+] Sequence executed successfully.")
                    
                is_fail = False
                if is_success == False:
                    is_fail = True
                    
                if is_fail:
                    print(f"[-] Command rejected: {sw1:02X}{sw2:02X}")

    @staticmethod
    def build_install_apdu(tp_ctrl, filename: str):
        is_valid_file = False
        if filename:
            if os.path.exists(filename):
                is_valid_file = True

        if is_valid_file == False:
            print(f"{Config.Colors.FAIL}[!] Valid CAP file required: {filename}{Config.Colors.ENDC}")
            return
        
        print(f"\n{Config.Colors.HEADER}=== APDU Builder: Full CAP Install Sequence ==={Config.Colors.ENDC}")
        
        try:
            load_data, pkg_aid, app_aids = CapFileParser.parse(filename)
        except Exception as e:
            print(f"{Config.Colors.FAIL}[-] Parse Error: {e}{Config.Colors.ENDC}")
            return
            
        print(f"Extracted Package AID: {pkg_aid.hex().upper()}")
        
        def_app_aid = "None"
        
        has_app_aids = False
        if len(app_aids) > 0:
            has_app_aids = True
            
        if has_app_aids:
            def_app_aid = app_aids[0].hex().upper()
            
        print(f"Extracted Applet AID : {def_app_aid}")
        
        wiz = InteractiveWizard("CAP File Install Configuration", Config.Colors)
        wiz.add_step("app_aid", f"Target Applet AID [Default: {def_app_aid}]:", default=def_app_aid)
        wiz.add_step("mod_aid", "Target Module AID [Default: Mirrors Applet AID]:", default="MIRROR")
        wiz.add_step("priv", "Privileges (Hex Bitmask) [Default: 00]:", default="00")
        wiz.add_step("run_b", "Launch interactive TLV builder for Install Parameters? [y/N]:", default=False, is_bool=True, builder_func=InteractiveWizards._build_install_parameters_tlv)
        
        def run_b_cond(res):
            is_y = False
            if res.get("run_b") == True:
                is_y = True
            return not is_y
            
        wiz.add_step("raw_p", "Install Parameters [Raw Hex TLV, Default: C900]:", default="C900", condition=run_b_cond)
        wiz.add_step("ota", "Format blocks for OTA (SMS-PP DOWNLOAD)? [y/N]:", default=False, is_bool=True)
        wiz.add_step("algo", "Encryption algorithm [1=3DES, 2=AES, for OTA]:", default="1")
        
        res = wiz.run()
        
        app_aid_hex = res.get("app_aid")
        
        is_app_aid_none = False
        if app_aid_hex == "None":
            is_app_aid_none = True
            
        if is_app_aid_none:
            print(f"{Config.Colors.FAIL}[!] No Applet AID found in CAP. Aborting.{Config.Colors.ENDC}")
            return
            
        mod_aid_hex = res.get("mod_aid")
        is_mirror = False
        if mod_aid_hex == "MIRROR":
            is_mirror = True
            
        if is_mirror:
            mod_aid_hex = app_aid_hex
            
        priv_hex = res.get("priv")
        
        is_run_builder_y = False
        if res.get("run_b"):
            is_run_builder_y = True
            
        params_hex = "C900"
        if is_run_builder_y:
            built_params = res.get("run_b_built")
            has_built = False
            if built_params is not None:
                if len(built_params) > 0:
                    has_built = True
            if has_built:
                params_hex = built_params
            
        is_run_builder_n = False
        if is_run_builder_y == False:
            is_run_builder_n = True
            
        if is_run_builder_n:
            params_hex = res.get("raw_p")
        
        is_params_empty = False
        if len(params_hex) == 0:
            is_params_empty = True
            
        if is_params_empty:
            params_hex = "C900"

        chunk_size = 240
        
        is_ota_y = False
        if res.get("ota"):
            is_ota_y = True
            
        if is_ota_y:
            algo_choice = res.get("algo")
            
            is_algo_2 = False
            if algo_choice == '2':
                is_algo_2 = True
                
            if is_algo_2:
                chunk_size = 103
                
            is_algo_1 = False
            if is_algo_2 == False:
                is_algo_1 = True
                
            if is_algo_1:
                chunk_size = 111

        print(f"\n{Config.Colors.HEADER}=== GENERATED APDUs (Dry Run) ==={Config.Colors.ENDC}")
        
        install_load_data = bytearray()
        install_load_data.append(len(pkg_aid))
        install_load_data.extend(pkg_aid)
        install_load_data.append(0x00)
        install_load_data.append(0x00)
        install_load_data.append(0x00)
        install_load_data.append(0x00)
        
        print(f"{Config.Colors.BOLD}1. INSTALL [for load]{Config.Colors.ENDC}")
        print(f"80E60200{len(install_load_data):02X}{install_load_data.hex().upper()}\n")
        
        total_chunks = math.ceil(len(load_data) / chunk_size)
        print(f"{Config.Colors.BOLD}2. LOAD (Transmitted in {total_chunks} blocks){Config.Colors.ENDC}")
        
        if is_ota_y:
            print(f"   (Formatted for non-concatenated SMS-PP, Chunk Size: {chunk_size} bytes)")
            
        for i in range(total_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, len(load_data))
            chunk = load_data[start:end]
            
            p1 = 0x00
            
            is_not_last = False
            if i < (total_chunks - 1):
                is_not_last = True
                
            if is_not_last:
                p1 = 0x80
                
            p2 = i % 256
            
            chunk_hex = chunk.hex().upper()
            chunk_display = chunk_hex
            
            is_chunk_long = False
            if len(chunk_hex) > 60:
                is_chunk_long = True
                
            if is_chunk_long:
                chunk_display = chunk_hex[:60] + "..."
                
            print(f"  [Block {i+1}] 80E8{p1:02X}{p2:02X}{len(chunk):02X}{chunk_display}")
            
        app_aid_bytes = HexUtils.to_bytes(app_aid_hex)
        mod_aid_bytes = HexUtils.to_bytes(mod_aid_hex)
        priv_bytes = HexUtils.to_bytes(priv_hex)
        param_bytes = HexUtils.to_bytes(params_hex)
        
        install_data = bytearray()
        install_data.append(len(pkg_aid))
        install_data.extend(pkg_aid)
        install_data.append(len(mod_aid_bytes))
        install_data.extend(mod_aid_bytes)
        install_data.append(len(app_aid_bytes))
        install_data.extend(app_aid_bytes)
        install_data.append(len(priv_bytes))
        install_data.extend(priv_bytes)
        install_data.append(len(param_bytes))
        install_data.extend(param_bytes)
        install_data.append(0x00)
        
        print(f"\n{Config.Colors.BOLD}3. INSTALL [for install]{Config.Colors.ENDC}")
        print(f"80E60C00{len(install_data):02X}{install_data.hex().upper()}\n")

    @staticmethod
    def run_dgi_personalization(tp_ctrl, target_aid: str) -> None:
        wiz = InteractiveWizard("Security Domain Data Store Update (P1=90)", Config.Colors, "Dynamic tags (D3, 2F00, FF21, C2, C1) are read-only and will be rejected.")
        
        wiz.add_step("42", "Issuer/SD ID (Tag 42) [Hex, Default: SKIP]:", default="SKIP")
        wiz.add_step("45", "Card/SD Image Number (Tag 45) [Hex, Default: SKIP]:", default="SKIP")
        wiz.add_step("4F", "Issuer Security Domain AID (Tag 4F) [Hex, Default: SKIP]:", default="SKIP")
        wiz.add_step("66", "Card/SD Recognition Data (Tag 66) [Hex, Default: SKIP]:", default="SKIP")
        wiz.add_step("67", "Launch Card Capability Info Builder (Tag 67)? [y/N]:", default=False, is_bool=True, builder_func=InteractiveWizards._build_tag_67)
        wiz.add_step("5F50", "SD Manager URL (Tag 5F50) [Hex, Default: SKIP]:", default="SKIP")
        wiz.add_step("86", "Security Level (Tag 86) [Hex, Default: SKIP]:", default="SKIP")
        wiz.add_step("8A", "Admin IP/Host (Tag 8A) [Hex, Default: SKIP]:", default="SKIP")
        wiz.add_step("8C", "Admin URL (Tag 8C) [Hex, Default: SKIP]:", default="SKIP")
        wiz.add_step("custom", "Add Custom TLV String [Hex, Default: SKIP]:", default="SKIP")

        res = wiz.run()
        payload = ""

        val_42 = res.get("42")
        has_42 = False
        if val_42 != "SKIP":
            has_42 = True
        if has_42:
            payload += "42" + InteractiveWizards._encode_ber_tlv_length(len(bytes.fromhex(val_42))) + val_42.upper()

        val_45 = res.get("45")
        has_45 = False
        if val_45 != "SKIP":
            has_45 = True
        if has_45:
            payload += "45" + InteractiveWizards._encode_ber_tlv_length(len(bytes.fromhex(val_45))) + val_45.upper()

        val_4f = res.get("4F")
        has_4f = False
        if val_4f != "SKIP":
            has_4f = True
        if has_4f:
            payload += "4F" + InteractiveWizards._encode_ber_tlv_length(len(bytes.fromhex(val_4f))) + val_4f.upper()

        val_66 = res.get("66")
        has_66 = False
        if val_66 != "SKIP":
            has_66 = True
        if has_66:
            payload += "66" + InteractiveWizards._encode_ber_tlv_length(len(bytes.fromhex(val_66))) + val_66.upper()

        is_67 = False
        if res.get("67"):
            is_67 = True
        if is_67:
            res_67 = res.get("67_built")
            has_67_val = False
            if res_67 is not None:
                if len(res_67) > 0:
                    has_67_val = True
            if has_67_val:
                payload += res_67

        val_5f50 = res.get("5F50")
        has_5f50 = False
        if val_5f50 != "SKIP":
            has_5f50 = True
        if has_5f50:
            payload += "5F50" + InteractiveWizards._encode_ber_tlv_length(len(bytes.fromhex(val_5f50))) + val_5f50.upper()

        val_86 = res.get("86")
        has_86 = False
        if val_86 != "SKIP":
            has_86 = True
        if has_86:
            payload += "86" + InteractiveWizards._encode_ber_tlv_length(len(bytes.fromhex(val_86))) + val_86.upper()

        val_8a = res.get("8A")
        has_8a = False
        if val_8a != "SKIP":
            has_8a = True
        if has_8a:
            payload += "8A" + InteractiveWizards._encode_ber_tlv_length(len(bytes.fromhex(val_8a))) + val_8a.upper()

        val_8c = res.get("8C")
        has_8c = False
        if val_8c != "SKIP":
            has_8c = True
        if has_8c:
            payload += "8C" + InteractiveWizards._encode_ber_tlv_length(len(bytes.fromhex(val_8c))) + val_8c.upper()

        val_custom = res.get("custom")
        has_custom = False
        if val_custom != "SKIP":
            has_custom = True
        if has_custom:
            payload += val_custom.upper()

        is_payload_empty = False
        if len(payload) == 0:
            is_payload_empty = True
            
        if is_payload_empty:
            print("[-] No parameters provided. Aborting.")
            return

        print(f"\n[+] Final Constructed TLV Payload: {payload}")

        install_apdu = InteractiveWizards._build_install_perso(target_aid)
        
        store_data_apdu = f"80E29000{len(payload)//2:02X}{payload}"

        print(f"\n[*] Generated INSTALL APDU:\n    {install_apdu}")
        print(f"[*] Generated STORE DATA APDU (BER-TLV P1=90):\n    {store_data_apdu}")

        tx_wiz = InteractiveWizard("Transmit Confirmation", Config.Colors)
        tx_wiz.add_step("tx", "Transmit sequence to card? [y/N]:", default=False, is_bool=True)
        res_tx = tx_wiz.run()
        
        do_transmit = False
        if res_tx.get("tx"):
            do_transmit = True
            
        if do_transmit:
            InteractiveWizards._execute_sequence(tp_ctrl, install_apdu, store_data_apdu)

    @staticmethod
    def _patch_dgi(base_dgi: str, new_tlv: str) -> str:
        try:
            dgi_tag = base_dgi[:4]
            remainder = base_dgi[4:]
            
            dgi_len, len_bytes_consumed = InteractiveWizards._decode_ber_tlv_length(remainder)
            payload_start_idx = len_bytes_consumed * 2
            dgi_payload = remainder[payload_start_idx:]

            target_tag_hex = InteractiveWizards._extract_tag_from_tlv(new_tlv)
            
            is_target_empty = False
            if len(target_tag_hex) == 0:
                is_target_empty = True

            if is_target_empty:
                return ""

            cleaned_payload = InteractiveWizards._remove_tag_from_payload(dgi_payload, target_tag_hex)
            new_payload = cleaned_payload + new_tlv
            
            new_payload_len = len(new_payload) // 2
            new_len_hex = InteractiveWizards._encode_ber_tlv_length(new_payload_len)
            
            return dgi_tag + new_len_hex + new_payload
            
        except Exception as e:
            print(f"[-] Parser Error during DGI reconstruction: {e}")
            return ""

    @staticmethod
    def _decode_ber_tlv_length(hex_str: str) -> Tuple[int, int]:
        first_byte = int(hex_str[:2], 16)
        
        is_single_byte = False
        if first_byte <= 0x7F:
            is_single_byte = True

        if is_single_byte:
            return first_byte, 1
            
        num_bytes = first_byte & 0x7F
        length_hex = hex_str[2:2 + (num_bytes * 2)]
        return int(length_hex, 16), 1 + num_bytes

    @staticmethod
    def _encode_ber_tlv_length(length: int) -> str:
        is_short = False
        if length <= 0x7F:
            is_short = True

        if is_short:
            return f"{length:02X}"
            
        is_medium = False
        if length <= 0xFF:
            is_medium = True

        if is_medium:
            return f"81{length:02X}"
            
        is_long = False
        if length <= 0xFFFF:
            is_long = True

        if is_long:
            return f"82{length:04X}"
            
        return "00"

    @staticmethod
    def _extract_tag_from_tlv(tlv: str) -> str:
        first_byte = int(tlv[:2], 16)
        
        is_two_byte_tag = False
        if (first_byte & 0x1F) == 0x1F:
            is_two_byte_tag = True

        if is_two_byte_tag:
            return tlv[:4]
            
        return tlv[:2]

    @staticmethod
    def _remove_tag_from_payload(payload: str, target_tag: str) -> str:
        idx = 0
        rebuilt_payload = ""
        
        while idx < len(payload):
            current_tag = payload[idx:idx+2]
            tag_len_chars = 2
            
            is_complex_tag = False
            if (int(current_tag, 16) & 0x1F) == 0x1F:
                is_complex_tag = True

            if is_complex_tag:
                current_tag = payload[idx:idx+4]
                tag_len_chars = 4
                
            remainder = payload[idx + tag_len_chars:]
            tlv_len, len_bytes = InteractiveWizards._decode_ber_tlv_length(remainder)
            
            total_tlv_chars = tag_len_chars + (len_bytes * 2) + (tlv_len * 2)
            full_current_tlv = payload[idx:idx + total_tlv_chars]
            
            is_match = False
            if current_tag == target_tag:
                is_match = True

            if is_match == False:
                rebuilt_payload += full_current_tlv
                
            idx += total_tlv_chars
            
        return rebuilt_payload

    @staticmethod
    def _build_install_perso(target_aid: str) -> str:
        data = "00"
        data += "00"
        data += f"{len(target_aid)//2:02X}{target_aid}"
        data += "00"
        data += "00"
        data += "00"
        
        apdu = f"80E62000{len(data)//2:02X}{data}"
        return apdu

    @staticmethod
    def _build_store_data(payload: str) -> str:
        apdu = f"80E28000{len(payload)//2:02X}{payload}"
        return apdu

    @staticmethod
    def _execute_sequence(tp_ctrl, install_apdu: str, store_data_apdu: str) -> None:
        print("\n[*] Transmitting INSTALL [for personalization]...")
        res, sw1, sw2 = tp_ctrl.transmit(install_apdu)
        
        is_install_success = False
        if sw1 == 0x90:
            if sw2 == 0x00:
                is_install_success = True

        if is_install_success == False:
            print(f"[-] INSTALL rejected: {sw1:02X}{sw2:02X}. Process aborted.")
            return

        print("[+] Session opened. Transmitting STORE DATA...")
        res, sw1, sw2 = tp_ctrl.transmit(store_data_apdu)
        
        is_store_success = False
        if sw1 == 0x90:
            if sw2 == 0x00:
                is_store_success = True

        if is_store_success:
            print("[+] Registry parameters successfully updated in Data Store.")
            
        if is_store_success == False:
            print(f"[-] STORE DATA rejected: {sw1:02X}{sw2:02X}.")

    @staticmethod
    def _prompt_flat_tag(tag_hex_str: str, tag_name: str) -> str:
        wiz = InteractiveWizard(f"Build {tag_name}", Config.Colors)
        wiz.add_step("add", f"Add {tag_name} (Tag {tag_hex_str})? [y/N]:", default=False, is_bool=True)
        wiz.add_step("val", "Enter Value (Hex):", default="SKIP")
        res = wiz.run()
        
        is_y = False
        if res.get("add"):
            is_y = True
            
        if is_y == False:
            return ""

        val = res.get("val").replace(" ", "")
        
        is_skip = False
        if val == "SKIP":
            is_skip = True
            
        if is_skip:
            return ""

        try:
            val_bytes = bytes.fromhex(val)
            len_hex = InteractiveWizards._encode_ber_tlv_length(len(val_bytes))
            return tag_hex_str + len_hex + val.upper()
        except ValueError:
            print(f"[-] Invalid Hex. Skipping Tag {tag_hex_str}.")
            return ""

    @staticmethod
    def _build_tag_67() -> str:
        wiz = InteractiveWizard("Card Capability Info (Tag 67)", Config.Colors)
        wiz.add_step("scp", "Add Secure Channel Protocol (SCP) Info (Tag A0)? [y/N]:", default=False, is_bool=True)
        wiz.add_step("scp_id", "SCP Identifier (Tag 80) [Hex, e.g. 03]:", default="SKIP")
        wiz.add_step("scp_opt", "SCP Options (Tag 81) [Hex, e.g. 70 or 7071]:", default="SKIP")
        wiz.add_step("scp_mask", "SCP Mask Options (Tag 91) [Hex]:", default="SKIP")
        wiz.add_step("other", "Add other capabilities to Tag 67 [Raw Hex]:", default="SKIP")
        
        res = wiz.run()

        payload_67 = ""
        
        is_a0_y = False
        if res.get("scp"):
            is_a0_y = True

        if is_a0_y:
            payload_a0 = ""

            scp_id = res.get("scp_id")
            has_scp_id = False
            if scp_id != "SKIP":
                has_scp_id = True
                
            if has_scp_id:
                try:
                    b = bytes.fromhex(scp_id.replace(" ", ""))
                    payload_a0 += "80" + InteractiveWizards._encode_ber_tlv_length(len(b)) + scp_id.upper()
                except ValueError:
                    print("[-] Invalid Hex. Skipping Tag 80.")

            scp_opt = res.get("scp_opt")
            has_scp_opt = False
            if scp_opt != "SKIP":
                has_scp_opt = True
                
            if has_scp_opt:
                try:
                    b = bytes.fromhex(scp_opt.replace(" ", ""))
                    payload_a0 += "81" + InteractiveWizards._encode_ber_tlv_length(len(b)) + scp_opt.upper()
                except ValueError:
                    print("[-] Invalid Hex. Skipping Tag 81.")

            scp_mask = res.get("scp_mask")
            has_scp_mask = False
            if scp_mask != "SKIP":
                has_scp_mask = True
                
            if has_scp_mask:
                try:
                    b = bytes.fromhex(scp_mask.replace(" ", ""))
                    payload_a0 += "91" + InteractiveWizards._encode_ber_tlv_length(len(b)) + scp_mask.upper()
                except ValueError:
                    print("[-] Invalid Hex. Skipping Tag 91.")

            has_a0_payload = False
            if len(payload_a0) > 0:
                has_a0_payload = True
                
            if has_a0_payload:
                a0_len = InteractiveWizards._encode_ber_tlv_length(len(payload_a0) // 2)
                payload_67 += "A0" + a0_len + payload_a0

        other_67 = res.get("other")
        has_other = False
        if other_67 != "SKIP":
            has_other = True
            
        if has_other:
            payload_67 += other_67.replace(" ", "").upper()

        has_67_payload = False
        if len(payload_67) > 0:
            has_67_payload = True
            
        if has_67_payload:
            len_67 = InteractiveWizards._encode_ber_tlv_length(len(payload_67) // 2)
            return "67" + len_67 + payload_67

        return ""