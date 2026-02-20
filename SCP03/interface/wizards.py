import os
import math
from typing import Tuple, List, Dict, Any
from SCP03.config import Config
from SCP03.core.cap import CapFileParser
from SCP03.core.utils import HexUtils

class InteractiveWizards:
    """Provides interactive prompts and dry-run APDU builders for complex GP commands."""

    @staticmethod
    def _build_system_parameters_ef() -> bytes:
        print(f"\n{Config.Colors.CYAN}--- GP System Specific Parameters (Tag EF) Builder ---{Config.Colors.ENDC}")
        print("Reference: GPCS 11.1.5")
        
        payload = bytearray()
        try:
            vol = input("Volatile Memory Quota (Tag C6) [Hex, e.g. 0100 for 256B] [Default: Skip]: ").strip().replace(" ", "")
            
            has_vol = False
            if len(vol) > 0:
                has_vol = True
                
            if has_vol:
                b = bytes.fromhex(vol)
                payload.extend(bytes([0xC6, len(b)]) + b)
                
            nvol = input("Non-Volatile Memory Quota (Tag C7) [Hex, e.g. 0100] [Default: Skip]: ").strip().replace(" ", "")
            
            has_nvol = False
            if len(nvol) > 0:
                has_nvol = True
                
            if has_nvol:
                b = bytes.fromhex(nvol)
                payload.extend(bytes([0xC7, len(b)]) + b)
                
            gsp = input("Global Service Parameters (Tag C8) [Hex] [Default: Skip]: ").strip().replace(" ", "")
            
            has_gsp = False
            if len(gsp) > 0:
                has_gsp = True
                
            if has_gsp:
                b = bytes.fromhex(gsp)
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
        print(f"  {Config.Colors.CYAN}--- {tag_name} (ETSI TS 102 226 8.2.1.3.2.5) ---{Config.Colors.ENDC}")
        print("  1. Full access to File System (00)")
        print("  2. UICC access mechanism (02)")
        print("  3. No access to File System (FF)")
        print("  4. Raw Hex Input")
        
        choice = input("  Choice [1-4, Default: 4]: ").strip()
        
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
            add_hex = input("  Enter Access Domain Data (ADD) [Hex, e.g. 7F0A01]: ").strip().replace(" ", "")
            try:
                add_bytes = bytes.fromhex(add_hex)
                len_add = len(add_bytes)
                val = bytes([len_add, 0x02]) + add_bytes
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
            raw_hex = input(f"  {tag_name} [Raw Hex]: ").strip().replace(" ", "")
            
            has_raw_hex = False
            if len(raw_hex) > 0:
                has_raw_hex = True
                
            if has_raw_hex:
                try:
                    b_raw = bytes.fromhex(raw_hex)
                    return bytes([tag_hex, len(b_raw)]) + b_raw
                except ValueError:
                    print(f"{Config.Colors.FAIL}[!] Invalid Hex. Skipping Tag {tag_hex:02X}.{Config.Colors.ENDC}")
                    return b''
            return b''

    @staticmethod
    def _build_toolkit_parameters_ea() -> bytes:
        print(f"\n{Config.Colors.CYAN}--- UICC System Specific Parameters (Tag EA) Builder ---{Config.Colors.ENDC}")
        print("Reference: ETSI TS 102 226 Section 8.2.1.3.2.2")
        
        payload_ea = bytearray()
        
        ans_80 = input("\nInclude Toolkit Parameters (Tag 80)? [y/N]: ").strip().lower()
        
        is_ans_80_y = False
        if ans_80 == 'y':
            is_ans_80_y = True
            
        if is_ans_80_y:
            try:
                print(f"  {Config.Colors.CYAN}--- Toolkit Parameters (8.2.1.3.2.2.1) ---{Config.Colors.ENDC}")
                priority = input("  Priority Level (01-FF) [Default: 01]: ").strip()
                
                is_prio_empty = False
                if len(priority) == 0:
                    is_prio_empty = True
                    
                if is_prio_empty:
                    priority = "01"
                
                timers = input("  Max Timers (00-08) [Default: 00]: ").strip()
                
                is_timers_empty = False
                if len(timers) == 0:
                    is_timers_empty = True
                    
                if is_timers_empty:
                    timers = "00"
                    
                text_len = input("  Max Menu Text Length (Hex) [Default: 00]: ").strip()
                
                is_text_empty = False
                if len(text_len) == 0:
                    is_text_empty = True
                    
                if is_text_empty:
                    text_len = "00"
                    
                menu_entries = input("  Max Menu Entries (Hex) [Default: 00]: ").strip()
                
                is_menu_empty = False
                if len(menu_entries) == 0:
                    is_menu_empty = True
                    
                if is_menu_empty:
                    menu_entries = "00"
                
                msl = input("  Minimum Security Level (MSL) [Hex, Default: Empty]: ").strip().replace(" ", "")
                tar = input("  TAR Value(s) (3 bytes each) [Hex, Default: Empty]: ").strip().replace(" ", "")
                channels = input("  Max BIP Channels (Hex, 1 byte) [Default: Empty]: ").strip()
                
                payload_80 = bytearray()
                payload_80.append(int(priority, 16))
                payload_80.append(int(timers, 16))
                payload_80.append(int(text_len, 16))
                payload_80.append(int(menu_entries, 16))
                
                has_msl = False
                if len(msl) > 0:
                    has_msl = True
                    
                has_tar = False
                if len(tar) > 0:
                    has_tar = True
                    
                has_channels = False
                if len(channels) > 0:
                    has_channels = True
                    
                has_any_opt = False
                if has_msl:
                    has_any_opt = True
                if has_tar:
                    has_any_opt = True
                if has_channels:
                    has_any_opt = True
                
                if has_any_opt:
                    if has_msl:
                        msl_bytes = bytes.fromhex(msl)
                    
                    is_msl_missing = False
                    if has_msl == False:
                        is_msl_missing = True
                        
                    if is_msl_missing:
                        msl_bytes = b''
                        
                    payload_80.append(len(msl_bytes))
                    payload_80.extend(msl_bytes)
                    
                    has_tar_or_channels = False
                    if has_tar:
                        has_tar_or_channels = True
                    if has_channels:
                        has_tar_or_channels = True
                        
                    if has_tar_or_channels:
                        if has_tar:
                            tar_bytes = bytes.fromhex(tar)
                            
                        is_tar_missing = False
                        if has_tar == False:
                            is_tar_missing = True
                            
                        if is_tar_missing:
                            tar_bytes = b''
                            
                        payload_80.append(len(tar_bytes))
                        payload_80.extend(tar_bytes)
                        
                        if has_channels:
                            payload_80.append(int(channels, 16))
                            
                payload_ea.extend(bytes([0x80, len(payload_80)]) + payload_80)
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid Hex provided. Skipping Tag 80.{Config.Colors.ENDC}")
        
        ans_81 = input("\nInclude Access Parameters (Tag 81)? [y/N]: ").strip().lower()
        
        is_ans_81_y = False
        if ans_81 == 'y':
            is_ans_81_y = True
            
        if is_ans_81_y:
            tag_81_bytes = InteractiveWizards._build_access_domain_parameter(0x81, "Access Parameters")
            payload_ea.extend(tag_81_bytes)
        
        ans_82 = input("\nInclude Admin Access Parameters (Tag 82)? [y/N]: ").strip().lower()
        
        is_ans_82_y = False
        if ans_82 == 'y':
            is_ans_82_y = True
            
        if is_ans_82_y:
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
        print(f"\n{Config.Colors.CYAN}--- Install Parameters (TLV Builder) ---{Config.Colors.ENDC}")
        print("Constructs the concatenated TLV field for Install Parameters.")
        
        payload = bytearray()
        
        c9_val = input("\nTag C9 (Application Specific Params) [Raw Hex Value, Default: 00 (Empty), 'SKIP' to omit]: ").strip().replace(" ", "")
        
        is_c9_empty = False
        if len(c9_val) == 0:
            is_c9_empty = True
            
        if is_c9_empty:
            c9_val = "00"
            
        is_skip = False
        if c9_val.upper() == "SKIP":
            is_skip = True
            
        if is_skip == False:
            try:
                b = bytes.fromhex(c9_val)
                payload.extend(bytes([0xC9, len(b)]) + b)
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid hex. Skipping C9.{Config.Colors.ENDC}")

        run_ef = input("\nBuild GP System Specific Parameters (Tag EF)? [y/N]: ").strip().lower()
        
        is_run_ef_y = False
        if run_ef == 'y':
            is_run_ef_y = True
            
        if is_run_ef_y:
            ef_bytes = InteractiveWizards._build_system_parameters_ef()
            payload.extend(ef_bytes)

        print(f"\n{Config.Colors.WARNING}[!] ETSI TS 102 226: Tag 'CA' (2G SIM) and Tag 'EA' (3G/4G UICC) cannot coexist.{Config.Colors.ENDC}")
        
        has_ca = False
        ca_val = input("Tag CA (SIM File Access / Toolkit Params) [Raw Hex, Default: Skip]: ").strip().replace(" ", "")
        
        is_ca_val_present = False
        if len(ca_val) > 0:
            is_ca_val_present = True
            
        if is_ca_val_present:
            try:
                b = bytes.fromhex(ca_val)
                payload.extend(bytes([0xCA, len(b)]) + b)
                has_ca = True
                print(f"{Config.Colors.GREEN}[+] CA Tag Generated: CA{len(b):02X}{ca_val.upper()}{Config.Colors.ENDC}")
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid hex. Skipping CA.{Config.Colors.ENDC}")

        if has_ca:
            print(f"{Config.Colors.WARNING}[*] Tag CA is present. Skipping Tag EA to comply with ETSI 102 226.{Config.Colors.ENDC}")
            
        is_ca_missing = False
        if has_ca == False:
            is_ca_missing = True
            
        if is_ca_missing:
            run_ea = input("\nBuild UICC System Specific Parameters (Tag EA)? [y/N]: ").strip().lower()
            
            is_run_ea_y = False
            if run_ea == 'y':
                is_run_ea_y = True
                
            if is_run_ea_y:
                ea_bytes = InteractiveWizards._build_toolkit_parameters_ea()
                payload.extend(ea_bytes)

        res = payload.hex().upper()
        
        is_res_empty = False
        if len(res) == 0:
            is_res_empty = True
            
        if is_res_empty:
            return ""
            
        print(f"\n{Config.Colors.GREEN}[+] Overall Install Parameters Generated: {res}{Config.Colors.ENDC}")
        return res

    @staticmethod
    def run_wizard_menu(tp_ctrl=None, target_aid: str = "A000000151000000"):
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
            
        is_eight = False
        if choice == '8':
            is_eight = True
            
        if is_eight:
            filename = input("Enter path to CAP/IJC file: ").strip()
            InteractiveWizards.build_install_apdu(tp_ctrl, filename)
            return
            
        layouts = {
            '1': ('02', 'INSTALL [for load]', [
                ('Load File AID', '', False),
                ('Security Domain AID', '', False),
                ('Load File Data Block Hash', '', False),
                ('Load Parameters (TLV)', '', True),
                ('Load Token', '', False)
            ]),
            '2': ('04', 'INSTALL [for install]', [
                ('Executable Load File AID', '', False),
                ('Executable Module AID', '', False),
                ('Application AID', '', False),
                ('Privileges (Hex Bitmask)', '00', False),
                ('Install Parameters (TLV)', 'C900', True),
                ('Install Token', '', False)
            ]),
            '3': ('08', 'INSTALL [for make selectable]', [
                ('Executable Load File AID', '', False),
                ('Executable Module AID', '', False),
                ('Application AID', '', False),
                ('Privileges (Hex Bitmask)', '00', False),
                ('Make Selectable Parameters', '', False),
                ('Make Selectable Token', '', False)
            ]),
            '4': ('10', 'INSTALL [for extradition]', [
                ('Security Domain AID', '', False),
                ('Executable Module AID (Must be empty)', '', False),
                ('Application / Load File AID', '', False),
                ('Privileges (Must be empty)', '', False),
                ('Extradition Parameters (Must be empty)', '', False),
                ('Extradition Token', '', False)
            ]),
            '5': ('40', 'INSTALL [for registry update]', [
                ('Executable Load File AID', '', False),
                ('Executable Module AID (Must be empty)', '', False),
                ('Application AID', '', False),
                ('Privileges (Hex Bitmask)', '00', False),
                ('Registry Update Parameters', '', False),
                ('Registry Update Token', '', False)
            ]),
            '7': ('0C', 'INSTALL [for install and make selectable]', [
                ('Executable Load File AID', '', False),
                ('Executable Module AID', '', False),
                ('Application AID', '', False),
                ('Privileges (Hex Bitmask)', '00', False),
                ('Install Parameters (TLV)', 'C900', True),
                ('Install Token', '', False)
            ])
        }

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
        
        is_valid_choice = False
        if choice in layouts:
            is_valid_choice = True
            
        if is_valid_choice == False:
            print(f"{Config.Colors.FAIL}[!] Invalid choice.{Config.Colors.ENDC}")
            return
            
        p1, desc, fields = layouts[choice]
        print(f"\n{Config.Colors.CYAN}--- Building {desc} ---{Config.Colors.ENDC}")
        print(f"{Config.Colors.WARNING}Leave blank for default/empty (Length = 00). Provide all values in Hex.{Config.Colors.ENDC}\n")
        
        payload = bytearray()
        
        for name, default, is_builder in fields:
            while True:
                if is_builder:
                    run_b = input(f"Launch TLV Builder for {name}? [y/N]: ").strip().lower()
                    
                    is_run_b_y = False
                    if run_b == 'y':
                        is_run_b_y = True
                        
                    if is_run_b_y:
                        val_hex = InteractiveWizards._build_install_parameters_tlv()
                        
                    is_run_b_n = False
                    if is_run_b_y == False:
                        is_run_b_n = True
                        
                    if is_run_b_n:
                        val_hex = input(f"{name} [Raw Hex, Default: {default}]: ").strip()
                else:
                    is_default_present = False
                    if len(default) > 0:
                        is_default_present = True
                        
                    if is_default_present:
                        prompt_str = f"{name} [Default: {default}]: "
                        
                    is_default_missing = False
                    if is_default_present == False:
                        is_default_missing = True
                        
                    if is_default_missing:
                        prompt_str = f"{name} [Default: <Empty>]: "
                        
                    val_hex = input(prompt_str).strip()
                
                is_val_empty = False
                if len(val_hex) == 0:
                    is_val_empty = True
                    
                if is_val_empty:
                    val_hex = default
                    
                val_hex = val_hex.replace(" ", "")
                
                try:
                    has_val_hex = False
                    if len(val_hex) > 0:
                        has_val_hex = True
                        
                    if has_val_hex:
                        val_bytes = bytes.fromhex(val_hex)
                        
                    is_val_hex_missing = False
                    if has_val_hex == False:
                        is_val_hex_missing = True
                        
                    if is_val_hex_missing:
                        val_bytes = b''
                    
                    is_len_invalid = False
                    if len(val_bytes) > 255:
                        is_len_invalid = True
                        
                    if is_len_invalid:
                        print(f"{Config.Colors.FAIL}[!] Field length exceeds 255 bytes.{Config.Colors.ENDC}")
                        continue
                        
                    payload.append(len(val_bytes))
                    payload.extend(val_bytes)
                    break
                except ValueError:
                    print(f"{Config.Colors.FAIL}[!] Invalid Hex string.{Config.Colors.ENDC}")
                    
        print(f"\n{Config.Colors.HEADER}=== GENERATED APDU ==={Config.Colors.ENDC}")
        apdu = f"80E6{p1}00{len(payload):02X}{payload.hex().upper()}"
        print(f"{Config.Colors.GREEN}{apdu}{Config.Colors.ENDC}")

        is_tp_present = False
        if tp_ctrl is not None:
            is_tp_present = True
            
        if is_tp_present:
            ans = input("\n[?] Send to card? [y/N]: ").strip().lower()
            
            do_send = False
            if ans == 'y':
                do_send = True
                
            if do_send:
                print("[*] Transmitting APDU...")
                res, sw1, sw2 = tp_ctrl.transmit(apdu)
                
                is_success = False
                if sw1 == 0x90:
                    if sw2 == 0x00:
                        is_success = True
                        
                if is_success:
                    print("[+] Command executed successfully.")
                    
                if is_success == False:
                    print(f"[-] Command failed: {sw1:02X}{sw2:02X}")

    @staticmethod
    def build_install_apdu(filename: str):
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
        
        print(f"\n{Config.Colors.CYAN}--- AIDs & Overrides ---{Config.Colors.ENDC}")
        app_aid_input = input(f"Target Applet AID [Default: {def_app_aid}]: ").strip()
        app_aid_hex = def_app_aid
        
        has_app_input = False
        if len(app_aid_input) > 0:
            has_app_input = True
            
        if has_app_input:
            app_aid_hex = app_aid_input
        
        mod_aid_input = input(f"Target Module AID [Default: {app_aid_hex}]: ").strip()
        mod_aid_hex = app_aid_hex
        
        has_mod_input = False
        if len(mod_aid_input) > 0:
            has_mod_input = True
            
        if has_mod_input:
            mod_aid_hex = mod_aid_input
        
        is_app_aid_none = False
        if app_aid_hex == "None":
            is_app_aid_none = True
            
        if is_app_aid_none:
            print(f"{Config.Colors.FAIL}[!] No Applet AID found in CAP. Aborting.{Config.Colors.ENDC}")
            return
            
        print(f"\n{Config.Colors.CYAN}--- Configuration ---{Config.Colors.ENDC}")
        priv_input = input("Privileges (Hex Bitmask) [Default: 00]: ").strip()
        priv_hex = "00"
        
        has_priv_input = False
        if len(priv_input) > 0:
            has_priv_input = True
            
        if has_priv_input:
            priv_hex = priv_input
        
        run_builder = input("Launch interactive TLV builder for Install Parameters? [y/N]: ").strip().lower()
        params_hex = "C900"
        
        is_run_builder_y = False
        if run_builder == 'y':
            is_run_builder_y = True
            
        if is_run_builder_y:
            params_hex = InteractiveWizards._build_install_parameters_tlv()
            
        is_run_builder_n = False
        if is_run_builder_y == False:
            is_run_builder_n = True
            
        if is_run_builder_n:
            params_input = input("Install Parameters (Raw Hex TLV) [Default: C900]: ").strip()
            
            has_params_input = False
            if len(params_input) > 0:
                has_params_input = True
                
            if has_params_input:
                params_hex = params_input
        
        is_params_empty = False
        if len(params_hex) == 0:
            is_params_empty = True
            
        if is_params_empty:
            params_hex = "C900"

        print(f"\n{Config.Colors.CYAN}--- Transport Formatting ---{Config.Colors.ENDC}")
        ota_prompt = input("Format blocks for OTA (SMS-PP DOWNLOAD)? [y/N]: ").strip().lower()
        
        chunk_size = 240
        
        is_ota_y = False
        if ota_prompt == 'y':
            is_ota_y = True
            
        if is_ota_y:
            print("  Select encryption algorithm (dictates MAC size and available payload):")
            print("  1. 3DES (8-byte MAC, Max Payload: 111 bytes)")
            print("  2. AES  (16-byte MAC, Max Payload: 103 bytes)")
            
            algo_choice = input("  Choice [1-2, Default: 1]: ").strip()
            
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
        print("\n--- INSTALL [for personalization] & STORE DATA Wizard ---")
        print("This wizard safely updates the Security Domain Data Store (DGI).")
        
        base_dgi = input("Enter FULL baseline DGI (Hex) [Mandatory]: ").strip().upper()
        
        is_empty_dgi = False
        if len(base_dgi) == 0:
            is_empty_dgi = True
            
        if is_empty_dgi:
            print("[-] Baseline DGI is required to prevent card corruption. Aborting.")
            return

        print("\n--- Parameter Update Selection ---")
        print("Leave field blank to keep existing value from the baseline DGI.")
        print("Provide full TLV (Tag + Length + Value) for any field you wish to update.")
        
        # GPCS Standard Tags
        tag_42 = input("Issuer/SD ID (Tag 42) [e.g. 4204...]: ").strip().upper()
        tag_45 = input("Card/SD Image Number (Tag 45) [e.g. 4504...]: ").strip().upper()
        tag_66 = input("Card/SD Recognition Data (Tag 66) [e.g. 6604...]: ").strip().upper()
        tag_67 = input("Card Capability Info (Tag 67) [e.g. 6704...]: ").strip().upper()
        tag_5f50 = input("SD Manager URL (Tag 5F50) [e.g. 5F5008...]: ").strip().upper()
        
        # MNO/Telecom Specific Tags
        scp_ef = input("System Params for SCP (Tag EF) [e.g. EF04...]: ").strip().upper()
        sec_level = input("Security Level (Tag 86) [e.g. 8607...]: ").strip().upper()
        admin_ip = input("Admin IP/Host (Tag 8A) [e.g. 8A0D...]: ").strip().upper()
        admin_url = input("Admin URL (Tag 8C) [e.g. 8C10...]: ").strip().upper()
        custom_tlv = input("Custom/Other TLV to insert [e.g. 8B05...]: ").strip().upper()
        
        updated_dgi = base_dgi

        has_tag_42 = False
        if len(tag_42) > 0:
            has_tag_42 = True
            
        if has_tag_42:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, tag_42)

        has_tag_45 = False
        if len(tag_45) > 0:
            has_tag_45 = True
            
        if has_tag_45:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, tag_45)

        has_tag_66 = False
        if len(tag_66) > 0:
            has_tag_66 = True
            
        if has_tag_66:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, tag_66)

        has_tag_67 = False
        if len(tag_67) > 0:
            has_tag_67 = True
            
        if has_tag_67:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, tag_67)

        has_tag_5f50 = False
        if len(tag_5f50) > 0:
            has_tag_5f50 = True
            
        if has_tag_5f50:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, tag_5f50)
        
        has_scp = False
        if len(scp_ef) > 0:
            has_scp = True
            
        if has_scp:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, scp_ef)
            
        has_sec = False
        if len(sec_level) > 0:
            has_sec = True
            
        if has_sec:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, sec_level)
            
        has_ip = False
        if len(admin_ip) > 0:
            has_ip = True
            
        if has_ip:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, admin_ip)
            
        has_url = False
        if len(admin_url) > 0:
            has_url = True
            
        if has_url:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, admin_url)
            
        has_custom = False
        if len(custom_tlv) > 0:
            has_custom = True
            
        if has_custom:
            updated_dgi = InteractiveWizards._patch_dgi(updated_dgi, custom_tlv)
            
        is_patch_failed = False
        if len(updated_dgi) == 0:
            is_patch_failed = True
            
        if is_patch_failed:
            print("[-] DGI patching failed due to parser error. Aborting.")
            return

        print(f"\n[+] Final Constructed DGI: {updated_dgi}")

        install_apdu = InteractiveWizards._build_install_perso(target_aid)
        store_data_apdu = InteractiveWizards._build_store_data(updated_dgi)

        print(f"\n[*] Generated INSTALL APDU:\n    {install_apdu}")
        print(f"[*] Generated STORE DATA APDU:\n    {store_data_apdu}")

        ans = input("\n[?] Transmit sequence to card? [yes/NO]: ").strip().lower()
        
        do_transmit = False
        if ans == "yes":
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