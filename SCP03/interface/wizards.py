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
        """Interactive builder for GP System Specific Parameters (Tag EF)."""
        print(f"\n{Config.Colors.CYAN}--- GP System Specific Parameters (Tag EF) Builder ---{Config.Colors.ENDC}")
        print("Reference: GPCS 11.1.5")
        
        payload = bytearray()
        try:
            vol = input("Volatile Memory Quota (Tag C6) [Hex, e.g. 0100 for 256B] [Default: Skip]: ").strip().replace(" ", "")
            if vol:
                b = bytes.fromhex(vol)
                payload.extend(bytes([0xC6, len(b)]) + b)
                
            nvol = input("Non-Volatile Memory Quota (Tag C7) [Hex, e.g. 0100] [Default: Skip]: ").strip().replace(" ", "")
            if nvol:
                b = bytes.fromhex(nvol)
                payload.extend(bytes([0xC7, len(b)]) + b)
                
            gsp = input("Global Service Parameters (Tag C8) [Hex] [Default: Skip]: ").strip().replace(" ", "")
            if gsp:
                b = bytes.fromhex(gsp)
                payload.extend(bytes([0xC8, len(b)]) + b)
                
            if not payload:
                return b''
                
            ef_tlv = bytes([0xEF, len(payload)]) + payload
            print(f"{Config.Colors.GREEN}[+] EF Tag Generated: {ef_tlv.hex().upper()}{Config.Colors.ENDC}")
            return ef_tlv
        except ValueError:
            print(f"{Config.Colors.FAIL}[!] Invalid Hex provided. Skipping Tag EF.{Config.Colors.ENDC}")
            return b''

    @staticmethod
    def _build_access_domain_parameter(tag_hex: int, tag_name: str) -> bytes:
        """Helper to build ADP TLVs for Tag 81 and Tag 82."""
        print(f"  {Config.Colors.CYAN}--- {tag_name} (ETSI TS 102 226 8.2.1.3.2.5) ---{Config.Colors.ENDC}")
        print("  1. Full access to File System (00)")
        print("  2. UICC access mechanism (02)")
        print("  3. No access to File System (FF)")
        print("  4. Raw Hex Input")
        
        choice = input("  Choice [1-4, Default: 4]: ").strip()
        
        if choice == '1':
            return bytes([tag_hex, 0x02, 0x00, 0x00])
        elif choice == '3':
            return bytes([tag_hex, 0x02, 0x00, 0xFF])
        elif choice == '2':
            add_hex = input("  Enter Access Domain Data (ADD) [Hex, e.g. 7F0A01]: ").strip().replace(" ", "")
            try:
                add_bytes = bytes.fromhex(add_hex)
                len_add = len(add_bytes)
                val = bytes([len_add, 0x02]) + add_bytes
                return bytes([tag_hex, len(val)]) + val
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid Hex. Skipping Tag {tag_hex:02X}.{Config.Colors.ENDC}")
                return b''
        else:
            raw_hex = input(f"  {tag_name} [Raw Hex]: ").strip().replace(" ", "")
            if raw_hex:
                try:
                    b_raw = bytes.fromhex(raw_hex)
                    return bytes([tag_hex, len(b_raw)]) + b_raw
                except ValueError:
                    print(f"{Config.Colors.FAIL}[!] Invalid Hex. Skipping Tag {tag_hex:02X}.{Config.Colors.ENDC}")
                    return b''
            return b''

    @staticmethod
    def _build_toolkit_parameters_ea() -> bytes:
        """Interactive builder for ETSI TS 102 226 UICC System Specific Parameters (Tag EA)."""
        print(f"\n{Config.Colors.CYAN}--- UICC System Specific Parameters (Tag EA) Builder ---{Config.Colors.ENDC}")
        print("Reference: ETSI TS 102 226 Section 8.2.1.3.2.2")
        
        payload_ea = bytearray()
        
        ans_80 = input("\nInclude Toolkit Parameters (Tag 80)? [y/N]: ").strip().lower()
        if ans_80 == 'y':
            try:
                print(f"  {Config.Colors.CYAN}--- Toolkit Parameters (8.2.1.3.2.2.1) ---{Config.Colors.ENDC}")
                priority = input("  Priority Level (01-FF) [Default: 01]: ").strip()
                if not priority:
                    priority = "01"
                
                timers = input("  Max Timers (00-08) [Default: 00]: ").strip()
                if not timers:
                    timers = "00"
                    
                text_len = input("  Max Menu Text Length (Hex) [Default: 00]: ").strip()
                if not text_len:
                    text_len = "00"
                    
                menu_entries = input("  Max Menu Entries (Hex) [Default: 00]: ").strip()
                if not menu_entries:
                    menu_entries = "00"
                
                msl = input("  Minimum Security Level (MSL) [Hex, Default: Empty]: ").strip().replace(" ", "")
                tar = input("  TAR Value(s) (3 bytes each) [Hex, Default: Empty]: ").strip().replace(" ", "")
                channels = input("  Max BIP Channels (Hex, 1 byte) [Default: Empty]: ").strip()
                
                payload_80 = bytearray()
                payload_80.append(int(priority, 16))
                payload_80.append(int(timers, 16))
                payload_80.append(int(text_len, 16))
                payload_80.append(int(menu_entries, 16))
                
                if msl or tar or channels:
                    if msl:
                        msl_bytes = bytes.fromhex(msl)
                    else:
                        msl_bytes = b''
                        
                    payload_80.append(len(msl_bytes))
                    payload_80.extend(msl_bytes)
                    
                    if tar or channels:
                        if tar:
                            tar_bytes = bytes.fromhex(tar)
                        else:
                            tar_bytes = b''
                            
                        payload_80.append(len(tar_bytes))
                        payload_80.extend(tar_bytes)
                        
                        if channels:
                            payload_80.append(int(channels, 16))
                            
                payload_ea.extend(bytes([0x80, len(payload_80)]) + payload_80)
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid Hex provided. Skipping Tag 80.{Config.Colors.ENDC}")
        
        ans_81 = input("\nInclude Access Parameters (Tag 81)? [y/N]: ").strip().lower()
        if ans_81 == 'y':
            tag_81_bytes = InteractiveWizards._build_access_domain_parameter(0x81, "Access Parameters")
            payload_ea.extend(tag_81_bytes)
        
        ans_82 = input("\nInclude Admin Access Parameters (Tag 82)? [y/N]: ").strip().lower()
        if ans_82 == 'y':
            tag_82_bytes = InteractiveWizards._build_access_domain_parameter(0x82, "Admin Access Parameters")
            payload_ea.extend(tag_82_bytes)

        if not payload_ea:
            return b''
            
        ea_tlv = bytes([0xEA, len(payload_ea)]) + payload_ea
        print(f"{Config.Colors.GREEN}[+] EA Tag Generated: {ea_tlv.hex().upper()}{Config.Colors.ENDC}")
        return ea_tlv

    @staticmethod
    def _build_install_parameters_tlv() -> str:
        """
        Interactive builder for the overall Install Parameters field.
        Constructs the concatenated C9, EF, CA, and EA tags.
        """
        print(f"\n{Config.Colors.CYAN}--- Install Parameters (TLV Builder) ---{Config.Colors.ENDC}")
        print("Constructs the concatenated TLV field for Install Parameters.")
        
        payload = bytearray()
        
        c9_val = input("\nTag C9 (Application Specific Params) [Raw Hex Value, Default: 00 (Empty), 'SKIP' to omit]: ").strip().replace(" ", "")
        if not c9_val:
            c9_val = "00"
            
        if c9_val.upper() != "SKIP":
            try:
                b = bytes.fromhex(c9_val)
                payload.extend(bytes([0xC9, len(b)]) + b)
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid hex. Skipping C9.{Config.Colors.ENDC}")

        run_ef = input("\nBuild GP System Specific Parameters (Tag EF)? [y/N]: ").strip().lower()
        if run_ef == 'y':
            ef_bytes = InteractiveWizards._build_system_parameters_ef()
            payload.extend(ef_bytes)

        print(f"\n{Config.Colors.WARNING}[!] ETSI TS 102 226: Tag 'CA' (2G SIM) and Tag 'EA' (3G/4G UICC) cannot coexist.{Config.Colors.ENDC}")
        
        has_ca = False
        ca_val = input("Tag CA (SIM File Access / Toolkit Params) [Raw Hex, Default: Skip]: ").strip().replace(" ", "")
        if ca_val:
            try:
                b = bytes.fromhex(ca_val)
                payload.extend(bytes([0xCA, len(b)]) + b)
                has_ca = True
                print(f"{Config.Colors.GREEN}[+] CA Tag Generated: CA{len(b):02X}{ca_val.upper()}{Config.Colors.ENDC}")
            except ValueError:
                print(f"{Config.Colors.FAIL}[!] Invalid hex. Skipping CA.{Config.Colors.ENDC}")

        if has_ca:
            print(f"{Config.Colors.WARNING}[*] Tag CA is present. Skipping Tag EA to comply with ETSI 102 226.{Config.Colors.ENDC}")
        else:
            run_ea = input("\nBuild UICC System Specific Parameters (Tag EA)? [y/N]: ").strip().lower()
            if run_ea == 'y':
                ea_bytes = InteractiveWizards._build_toolkit_parameters_ea()
                payload.extend(ea_bytes)

        res = payload.hex().upper()
        if not res:
            return ""
            
        print(f"\n{Config.Colors.GREEN}[+] Overall Install Parameters Generated: {res}{Config.Colors.ENDC}")
        return res

    @staticmethod
    def run_install_wizard():
        print(f"\n{Config.Colors.HEADER}=== GPCS INSTALL Command Builder ==={Config.Colors.ENDC}")
        print("Select INSTALL variant (GPCS 11.5.2.3):")
        print("  1. INSTALL [for load] (11.5.2.3.1, P1=0x02)")
        print("  2. INSTALL [for install] (11.5.2.3.2, P1=0x04)")
        print("  3. INSTALL [for make selectable] (11.5.2.3.3, P1=0x08)")
        print("  4. INSTALL [for extradition] (11.5.2.3.4, P1=0x10)")
        print("  5. INSTALL [for registry update] (11.5.2.3.5, P1=0x40)")
        print("  6. INSTALL [for personalization] (11.5.2.3.6, P1=0x20)")
        print("  7. INSTALL [for install and make selectable] (11.5.2.3.7, P1=0x0C)")
        
        choice = input(f"\nChoice [1-7]: ").strip()
        
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
            '6': ('20', 'INSTALL [for personalization]', [
                ('Executable Load File AID (Must be empty)', '', False),
                ('Executable Module AID (Must be empty)', '', False),
                ('Application AID', '', False),
                ('Privileges (Must be empty)', '', False),
                ('Personalization Parameters (Must be empty)', '', False),
                ('Personalization Token', '', False)
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
        
        if choice not in layouts:
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
                    if run_b == 'y':
                        val_hex = InteractiveWizards._build_install_parameters_tlv()
                    else:
                        val_hex = input(f"{name} [Raw Hex, Default: {default}]: ").strip()
                else:
                    prompt_str = f"{name} [Default: {default}]: " if default else f"{name} [Default: <Empty>]: "
                    val_hex = input(prompt_str).strip()
                
                if not val_hex:
                    val_hex = default
                    
                val_hex = val_hex.replace(" ", "")
                
                try:
                    if val_hex:
                        val_bytes = bytes.fromhex(val_hex)
                    else:
                        val_bytes = b''
                    
                    if len(val_bytes) > 255:
                        print(f"{Config.Colors.FAIL}[!] Field length exceeds 255 bytes.{Config.Colors.ENDC}")
                        continue
                        
                    payload.append(len(val_bytes))
                    payload.extend(val_bytes)
                    break
                except ValueError:
                    print(f"{Config.Colors.FAIL}[!] Invalid Hex string.{Config.Colors.ENDC}")
                    
        print(f"\n{Config.Colors.HEADER}=== GENERATED APDU (Dry Run) ==={Config.Colors.ENDC}")
        apdu = f"80E6{p1}00{len(payload):02X}{payload.hex().upper()}"
        print(f"{Config.Colors.GREEN}{apdu}{Config.Colors.ENDC}")
        print("To execute, you can paste this directly into the prompt.")

    @staticmethod
    def build_install_apdu(filename: str):
        if not filename or not os.path.exists(filename):
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
        if app_aids:
            def_app_aid = app_aids[0].hex().upper()
            
        print(f"Extracted Applet AID : {def_app_aid}")
        
        print(f"\n{Config.Colors.CYAN}--- AIDs & Overrides ---{Config.Colors.ENDC}")
        app_aid_input = input(f"Target Applet AID [Default: {def_app_aid}]: ").strip()
        app_aid_hex = def_app_aid
        if app_aid_input:
            app_aid_hex = app_aid_input
        
        mod_aid_input = input(f"Target Module AID [Default: {app_aid_hex}]: ").strip()
        mod_aid_hex = app_aid_hex
        if mod_aid_input:
            mod_aid_hex = mod_aid_input
        
        if app_aid_hex == "None":
            print(f"{Config.Colors.FAIL}[!] No Applet AID found in CAP. Aborting.{Config.Colors.ENDC}")
            return
            
        print(f"\n{Config.Colors.CYAN}--- Configuration ---{Config.Colors.ENDC}")
        priv_input = input("Privileges (Hex Bitmask) [Default: 00]: ").strip()
        priv_hex = "00"
        if priv_input:
            priv_hex = priv_input
        
        run_builder = input("Launch interactive TLV builder for Install Parameters? [y/N]: ").strip().lower()
        params_hex = "C900"
        if run_builder == 'y':
            params_hex = InteractiveWizards._build_install_parameters_tlv()
        else:
            params_input = input("Install Parameters (Raw Hex TLV) [Default: C900]: ").strip()
            if params_input:
                params_hex = params_input
        
        if not params_hex:
            params_hex = "C900"

        print(f"\n{Config.Colors.CYAN}--- Transport Formatting ---{Config.Colors.ENDC}")
        ota_prompt = input("Format blocks for OTA (SMS-PP DOWNLOAD)? [y/N]: ").strip().lower()
        
        chunk_size = 240
        if ota_prompt == 'y':
            print("  Select encryption algorithm (dictates MAC size and available payload):")
            print("  1. 3DES (8-byte MAC, Max Payload: 111 bytes)")
            print("  2. AES  (16-byte MAC, Max Payload: 103 bytes)")
            
            algo_choice = input("  Choice [1-2, Default: 1]: ").strip()
            if algo_choice == '2':
                chunk_size = 103
            else:
                chunk_size = 111

        print(f"\n{Config.Colors.HEADER}=== GENERATED APDUs (Dry Run) ==={Config.Colors.ENDC}")
        
        # 1. INSTALL for Load
        install_load_data = bytearray()
        install_load_data.append(len(pkg_aid))
        install_load_data.extend(pkg_aid)
        install_load_data.append(0x00)
        install_load_data.append(0x00)
        install_load_data.append(0x00)
        install_load_data.append(0x00)
        
        print(f"{Config.Colors.BOLD}1. INSTALL [for load]{Config.Colors.ENDC}")
        print(f"80E60200{len(install_load_data):02X}{install_load_data.hex().upper()}\n")
        
        # 2. LOAD Blocks
        total_chunks = math.ceil(len(load_data) / chunk_size)
        print(f"{Config.Colors.BOLD}2. LOAD (Transmitted in {total_chunks} blocks){Config.Colors.ENDC}")
        if ota_prompt == 'y':
            print(f"   (Formatted for non-concatenated SMS-PP, Chunk Size: {chunk_size} bytes)")
            
        for i in range(total_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, len(load_data))
            chunk = load_data[start:end]
            
            p1 = 0x00
            if i < total_chunks - 1:
                p1 = 0x80
                
            p2 = i % 256
            
            chunk_hex = chunk.hex().upper()
            chunk_display = chunk_hex
            if len(chunk_hex) > 60:
                chunk_display = chunk_hex[:60] + "..."
                
            print(f"  [Block {i+1}] 80E8{p1:02X}{p2:02X}{len(chunk):02X}{chunk_display}")
            
        # 3. INSTALL for Install
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