# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os
import configparser
from SCP03.config import Config

class ShellInteractiveWizards:

    @staticmethod
    def run_put_key_wizard(shell) -> None:
        print(f"\n{Config.Colors.FAIL}!!! WARNING: CRITICAL CRYPTOGRAPHIC OPERATION !!!{Config.Colors.ENDC}")
        print(f"{Config.Colors.FAIL}Executing PUT KEY overwrites the active session keys for the Security Domain.{Config.Colors.ENDC}")
        print(f"{Config.Colors.FAIL}Loss of the new keys or incorrect KVN assignment will permanently cryptographic-lock the card.{Config.Colors.ENDC}")
        print(f"{Config.Colors.WARNING}Ensure backup of the new ENC, MAC, and DEK keys in your configuration before proceeding.{Config.Colors.ENDC}")
        
        print("\n--- GP PUT KEY Command (GPCS 11.8) ---")
        print("Select Action:")
        print("  1. Add New Key Set (Add)")
        print("  2. Rotate Existing Key Set (Replace KeyID 01)")
        print("  3. Replace Specific Keys (Advanced)")
        
        choice = input("Choice [1-3]: ").strip()
        
        is_one = False
        if choice == '1':
            is_one = True
            
        is_two = False
        if choice == '2':
            is_two = True
            
        is_three = False
        if choice == '3':
            is_three = True
            
        is_invalid = False
        if is_one == False:
            if is_two == False:
                if is_three == False:
                    is_invalid = True
                    
        if is_invalid:
            print("[-] Invalid selection. Aborting.")
            return

        old_kvn = 0
        key_id = 0
        
        if is_one:
            old_kvn = 0
            
            kid_input = input("Enter new Key ID [Hex, e.g. 01, 02]: ").strip()
            
            is_kid_empty = False
            if len(kid_input) == 0:
                is_kid_empty = True
                
            if is_kid_empty:
                print("[-] Key ID required. Aborting.")
                return
                
            key_id = int(kid_input, 16)

        if is_two:
            key_id = 1
            kvn_val = getattr(shell, 'current_kvn', None)
            
            is_kvn_missing = False
            if kvn_val is None:
                is_kvn_missing = True
                
            if is_kvn_missing:
                has_keys_config = False
                if 'KEYS' in shell.config:
                    has_keys_config = True
                    
                if has_keys_config:
                    has_kvn_key = False
                    if 'kvn' in shell.config['KEYS']:
                        has_kvn_key = True
                        
                    if has_kvn_key:
                        kvn_val = shell.config['KEYS']['kvn']
                        
            is_still_missing = False
            if kvn_val is None:
                is_still_missing = True
                
            if is_still_missing:
                print("[-] Error: Current KVN unknown. Aborting.")
                return
                
            old_kvn = int(str(kvn_val), 16)
            print(f"[*] Sourced current KVN: {old_kvn:02X}")
            
        if is_three:
            okvn_input = input("Enter Old KVN to replace [Hex]: ").strip()
            
            is_okvn_empty = False
            if len(okvn_input) == 0:
                is_okvn_empty = True
                
            if is_okvn_empty:
                print("[-] Old KVN required. Aborting.")
                return
                
            old_kvn = int(okvn_input, 16)
            
            kid_input = input("Enter Key ID to replace [Hex]: ").strip()
            
            is_kid_empty = False
            if len(kid_input) == 0:
                is_kid_empty = True
                
            if is_kid_empty:
                print("[-] Key ID required. Aborting.")
                return
                
            key_id = int(kid_input, 16)

        nkvn_input = input("Enter New KVN [Hex]: ").strip()
        
        is_nkvn_empty = False
        if len(nkvn_input) == 0:
            is_nkvn_empty = True
            
        if is_nkvn_empty:
            print("[-] New KVN required. Aborting.")
            return
            
        new_kvn = int(nkvn_input, 16)
        
        enc = input("Enter ENC Key [Hex, 16 bytes]: ").strip().replace(" ", "")
        
        is_enc_empty = False
        if len(enc) == 0:
            is_enc_empty = True
            
        if is_enc_empty:
            print("[-] ENC key required. Aborting.")
            return
            
        mac = input("Enter MAC Key [Hex, 16 bytes]: ").strip().replace(" ", "")
        
        is_mac_empty = False
        if len(mac) == 0:
            is_mac_empty = True
            
        if is_mac_empty:
            print("[-] MAC key required. Aborting.")
            return
            
        dek = input("Enter DEK Key [Hex, 16 bytes]: ").strip().replace(" ", "")
        
        is_dek_empty = False
        if len(dek) == 0:
            is_dek_empty = True
            
        if is_dek_empty:
            print("[-] DEK key required. Aborting.")
            return
            
        algo = input("Enter Algorithm [AES/3DES, Default: AES]: ").strip().upper()
        
        is_algo_empty = False
        if len(algo) == 0:
            is_algo_empty = True
            
        if is_algo_empty:
            algo = "AES"

        ans = input("\n[?] Execute PUT KEY? [y/N]: ").strip().lower()
        
        do_execute = False
        if ans == "yes":
            do_execute = True
            
        if ans == "y":
            do_execute = True
            
        if do_execute:
            keys = [enc, mac, dek]
            print("\n[*] Executing PUT KEY...")
            ShellInteractiveWizards._exec_put_key(shell, old_kvn, key_id, new_kvn, keys, algo)
            
        is_aborted = False
        if do_execute == False:
            is_aborted = True
            
        if is_aborted:
            print("[-] Execution aborted by user.")

    @staticmethod
    def _exec_put_key(shell, old_kvn, key_id, new_kvn, keys, algo):
        key_type = 0x88
        
        is_des = False
        if algo == "3DES":
            is_des = True
            
        if algo == "DES":
            is_des = True
            
        if is_des:
            key_type = 0x82
            
        is_hex = False
        if algo.startswith("0X"):
            is_hex = True
            
        if is_hex:
            key_type = int(algo, 16)

        success = shell.gp_ctrl.put_key(old_kvn, key_id, new_kvn, keys, key_type)
        
        is_success = False
        if success:
            is_success = True
            
        if is_success:
            print("[+] PUT KEY operation completed successfully.")
            ShellInteractiveWizards._prompt_config_update(shell, new_kvn, keys[0], keys[1], keys[2])
            
        is_failed = False
        if is_success == False:
            is_failed = True
            
        if is_failed:
            print("[-] PUT KEY operation failed.")

    @staticmethod
    def _prompt_config_update(shell, new_kvn: int, enc: str, mac: str, dek: str) -> None:
        print()
        ans = input(f"Update {Config.INI_FILE} with these new keys? [Y/n]: ").strip().upper()

        do_update = False
        if ans == "Y":
            do_update = True
        if ans == "":
            do_update = True

        if do_update:
            kvn_str = f"{new_kvn:02X}"
            shell.current_kvn = kvn_str
            
            config = configparser.ConfigParser()
            
            is_exists = False
            if os.path.exists(Config.INI_FILE):
                is_exists = True
                
            if is_exists:
                config.read(Config.INI_FILE)

            has_keys = False
            if 'KEYS' in config:
                has_keys = True
                
            is_missing_keys = False
            if has_keys == False:
                is_missing_keys = True
                
            if is_missing_keys:
                config['KEYS'] = {}

            config['KEYS']['kvn'] = kvn_str
            config['KEYS']['enc'] = enc
            config['KEYS']['mac'] = mac
            config['KEYS']['dek'] = dek
            
            has_kenc = False
            if 'kenc' in config['KEYS']:
                has_kenc = True
                
            if has_kenc:
                del config['KEYS']['kenc']
                
            has_kmac = False
            if 'kmac' in config['KEYS']:
                has_kmac = True
                
            if has_kmac:
                del config['KEYS']['kmac']

            with open(Config.INI_FILE, 'w') as f:
                config.write(f)

            print(f"[+] {Config.INI_FILE} updated. KVN is now {kvn_str}.")

    @staticmethod
    def run_manage_pin_wizard(shell) -> None:
        print("\n--- GP PIN Management Command ---")
        print("Select Action:")
        print("  1. Verify PIN")
        print("  2. Change PIN")
        print("  3. Disable PIN")
        print("  4. Enable PIN")
        print("  5. Unblock PIN")
        
        choice = input("Choice [1-5]: ").strip()
        
        is_one = False
        if choice == '1':
            is_one = True
            
        is_two = False
        if choice == '2':
            is_two = True
            
        is_three = False
        if choice == '3':
            is_three = True
            
        is_four = False
        if choice == '4':
            is_four = True
            
        is_five = False
        if choice == '5':
            is_five = True
            
        is_valid = False
        if is_one:
            is_valid = True
        if is_two:
            is_valid = True
        if is_three:
            is_valid = True
        if is_four:
            is_valid = True
        if is_five:
            is_valid = True
            
        if is_valid == False:
            print("[-] Invalid selection. Aborting.")
            return

        pin_id = input("Enter PIN ID [Hex, Default: 01 (CHV1)]: ").strip().upper()
        if len(pin_id) == 0:
            pin_id = "01"

        need_current = False
        if is_one:
            need_current = True
        if is_two:
            need_current = True
        if is_three:
            need_current = True
        if is_four:
            need_current = True

        need_new = False
        if is_two:
            need_new = True
        if is_five:
            need_new = True

        need_puk = False
        if is_five:
            need_puk = True

        current_pin = ""
        if need_current:
            current_pin = input("Enter Current PIN [ASCII]: ").strip()
            if len(current_pin) == 0:
                print("[-] Current PIN required. Aborting.")
                return

        puk_val = ""
        if need_puk:
            puk_val = input("Enter PUK [ASCII]: ").strip()
            if len(puk_val) == 0:
                print("[-] PUK required. Aborting.")
                return

        new_pin = ""
        if need_new:
            new_pin = input("Enter New PIN [ASCII]: ").strip()
            if len(new_pin) == 0:
                print("[-] New PIN required. Aborting.")
                return

        print("\n[*] Executing PIN Command...")
        if is_one:
            shell.sec_ctrl.verify_pin(pin_id, current_pin)
        if is_two:
            shell.sec_ctrl.change_pin(pin_id, current_pin, new_pin)
        if is_three:
            shell.sec_ctrl.disable_pin(pin_id, current_pin)
        if is_four:
            shell.sec_ctrl.enable_pin(pin_id, current_pin)
        if is_five:
            shell.sec_ctrl.unblock_pin(pin_id, puk_val, new_pin)

    @staticmethod
    def run_manage_profile_wizard(shell) -> None:
        print("\n--- eSIM Profile Management ---")
        print("Select Target Specification:")
        print("  1. SGP.22 / SGP.32 (Consumer & IoT)")
        print("  2. SGP.02 (M2M)")
        
        spec_choice = input("Choice [1-2]: ").strip()
        
        is_cons = False
        if spec_choice == '1':
            is_cons = True
            
        is_m2m = False
        if spec_choice == '2':
            is_m2m = True
            
        is_invalid_spec = False
        if is_cons == False:
            if is_m2m == False:
                is_invalid_spec = True
                
        if is_invalid_spec:
            print("[-] Invalid specification. Aborting.")
            return

        if is_cons:
            print("\n--- SGP.22/32 Profile Actions ---")
            print("  1. List Profiles (ISD-R)")
            print("  2. Scan eUICC Info (EID, ECASD, etc.)")
            print("  3. Enable Profile")
            print("  4. Disable Profile")
            print("  5. Delete Profile")
            
            act_choice = input("Choice [1-5]: ").strip()
            
            is_one = False
            if act_choice == '1':
                is_one = True
                
            if is_one:
                shell.gp_ctrl.sgp22.list_profiles()
                return
                
            is_two = False
            if act_choice == '2':
                is_two = True
                
            if is_two:
                shell.gp_ctrl.sgp22.run_sgp22_scan()
                return
                
            is_three = False
            if act_choice == '3':
                is_three = True
                
            is_four = False
            if act_choice == '4':
                is_four = True
                
            is_five = False
            if act_choice == '5':
                is_five = True
                
            needs_target = False
            if is_three:
                needs_target = True
            if is_four:
                needs_target = True
            if is_five:
                needs_target = True
                
            if needs_target:
                target = input("Enter Profile AID, ICCID, or Alias: ").strip()
                
                is_target_empty = False
                if len(target) == 0:
                    is_target_empty = True
                    
                if is_target_empty:
                    print("[-] Target required. Aborting.")
                    return
                    
                resolved_target = shell._resolve_mixed_aid(target)
                
                print("\n[*] Executing Profile Command...")
                if is_three:
                    res = shell.gp_ctrl.sgp22.enable_profile(resolved_target)
                    is_res = False
                    if res:
                        is_res = True
                    if is_res:
                        print(f"{Config.Colors.WARNING}[*] Performing automated card reset...{Config.Colors.ENDC}")
                        shell._handle_reset()
                        
                if is_four:
                    res = shell.gp_ctrl.sgp22.disable_profile(resolved_target)
                    is_res = False
                    if res:
                        is_res = True
                    if is_res:
                        print(f"{Config.Colors.WARNING}[*] Performing automated card reset...{Config.Colors.ENDC}")
                        shell._handle_reset()
                        
                if is_five:
                    res = shell.gp_ctrl.sgp22.delete_profile(resolved_target)
                    is_res = False
                    if res:
                        is_res = True
                    if is_res:
                        print(f"{Config.Colors.WARNING}[*] Performing automated card reset...{Config.Colors.ENDC}")
                        shell._handle_reset()
                return
                
            print("[-] Invalid action. Aborting.")

        if is_m2m:
            print("\n--- SGP.02 Profile Actions ---")
            print("  1. Scan eUICC / ECASD")
            
            act_choice = input("Choice [1]: ").strip()
            
            is_one_m2m = False
            if act_choice == '1':
                is_one_m2m = True
                
            if is_one_m2m:
                shell.gp_ctrl.sgp22.run_sgp02_scan()
                return
                
            print("[-] Invalid action. Aborting.")

    @staticmethod
    def run_auth_wizard(shell) -> None:
        print("\n--- Telecom Authentication Command ---")
        print("Select Application Context:")
        print("  1. GSM")
        print("  2. USIM")
        print("  3. ISIM")
        
        choice = input("Choice [1-3]: ").strip()
        
        is_gsm = False
        if choice == '1':
            is_gsm = True
            
        is_usim = False
        if choice == '2':
            is_usim = True
            
        is_isim = False
        if choice == '3':
            is_isim = True
            
        is_invalid = False
        if is_gsm == False:
            if is_usim == False:
                if is_isim == False:
                    is_invalid = True
                    
        if is_invalid:
            print("[-] Invalid selection. Aborting.")
            return

        context = "GSM"
        if is_usim:
            context = "USIM"
        if is_isim:
            context = "ISIM"

        rand_val = input("Enter RAND [Hex]: ").strip().replace(" ", "")
        
        is_rand_empty = False
        if len(rand_val) == 0:
            is_rand_empty = True
            
        if is_rand_empty:
            print("[-] RAND is required. Aborting.")
            return

        need_autn = False
        if is_usim:
            need_autn = True
        if is_isim:
            need_autn = True

        autn_val = ""
        if need_autn:
            autn_val = input("Enter AUTN [Hex]: ").strip().replace(" ", "")
            
            is_autn_empty = False
            if len(autn_val) == 0:
                is_autn_empty = True
                
            if is_autn_empty:
                print(f"[-] AUTN is required for {context}. Aborting.")
                return

        print(f"\n[*] Executing {context} AUTH...")
        if is_gsm:
            shell.sec_ctrl.run_auth(rand_val, app_context="GSM")
            
        is_not_gsm = False
        if is_gsm == False:
            is_not_gsm = True
            
        if is_not_gsm:
            shell.sec_ctrl.run_auth(rand_val, autn_val, app_context=context)

    @staticmethod
    def run_config_wizard(shell) -> None:
        print("\n--- Environment Configuration ---")
        print("Select parameter to update:")
        print("  1. ENC Key (enc/kenc)")
        print("  2. MAC Key (mac/kmac)")
        print("  3. DEK Key (dek)")
        print("  4. Key Version Number (kvn)")
        print("  5. ADM Key (adm)")
        print("  6. Target AID (aid)")
        
        choice = input("Choice [1-6]: ").strip()
        
        is_one = False
        if choice == '1':
            is_one = True
            
        is_two = False
        if choice == '2':
            is_two = True
            
        is_three = False
        if choice == '3':
            is_three = True
            
        is_four = False
        if choice == '4':
            is_four = True
            
        is_five = False
        if choice == '5':
            is_five = True
            
        is_six = False
        if choice == '6':
            is_six = True
            
        is_valid = False
        if is_one:
            is_valid = True
        if is_two:
            is_valid = True
        if is_three:
            is_valid = True
        if is_four:
            is_valid = True
        if is_five:
            is_valid = True
        if is_six:
            is_valid = True
            
        is_invalid = False
        if is_valid == False:
            is_invalid = True
            
        if is_invalid:
            print("[-] Invalid selection. Aborting.")
            return

        key_name = ""
        if is_one:
            key_name = "kenc"
        if is_two:
            key_name = "kmac"
        if is_three:
            key_name = "dek"
        if is_four:
            key_name = "kvn"
        if is_five:
            key_name = "adm"
        if is_six:
            key_name = "aid"

        val = input(f"Enter new value for {key_name} [Hex]: ").strip().replace(" ", "").upper()
        
        is_empty = False
        if len(val) == 0:
            is_empty = True
            
        if is_empty:
            print("[-] Value is required. Aborting.")
            return

        print(f"\n[*] Updating configuration...")
        shell._update_config(key_name, val)

    @staticmethod
    def run_get_data_wizard(shell) -> None:
        print("\n--- GP GET DATA Command (GPCS 11.3) ---")
        print("Select Data to Retrieve:")
        print("  1. List Applications")
        print("  2. List Executable Load Files (Packages)")
        print("  3. List Security Domains")
        print("  4. Card Production Life Cycle (CPLC - Tag 9F7F)")
        print("  5. Custom GET DATA (Raw P1/P2)")
        
        choice = input("Choice [1-5]: ").strip()
        
        is_one = False
        if choice == '1':
            is_one = True
            
        is_two = False
        if choice == '2':
            is_two = True
            
        is_three = False
        if choice == '3':
            is_three = True
            
        is_four = False
        if choice == '4':
            is_four = True
            
        is_five = False
        if choice == '5':
            is_five = True
            
        is_valid = False
        if is_one:
            is_valid = True
        if is_two:
            is_valid = True
        if is_three:
            is_valid = True
        if is_four:
            is_valid = True
        if is_five:
            is_valid = True
            
        is_invalid = False
        if is_valid == False:
            is_invalid = True
            
        if is_invalid:
            print("[-] Invalid selection. Aborting.")
            return

        print("\n[*] Retrieving Data from Card...")

        if is_one:
            shell.gp_ctrl.list_registry('APPS')
            return
            
        if is_two:
            shell.gp_ctrl.list_registry('PACKAGES')
            return
            
        if is_three:
            shell.gp_ctrl.list_registry('SD')
            return
            
        if is_four:
            shell.gp_ctrl.get_cplc()
            return
            
        if is_five:
            p1_str = input("Enter P1 [Hex, e.g. 00, 9F, BF]: ").strip().upper()
            
            is_p1_empty = False
            if len(p1_str) == 0:
                is_p1_empty = True
                
            if is_p1_empty:
                print("[-] P1 is required. Aborting.")
                return
                
            p2_str = input("Enter P2 [Hex, e.g. 66, 7F]: ").strip().upper()
            
            is_p2_empty = False
            if len(p2_str) == 0:
                is_p2_empty = True
                
            if is_p2_empty:
                print("[-] P2 is required. Aborting.")
                return
                
            try:
                p1 = int(p1_str, 16)
                p2 = int(p2_str, 16)
                shell.gp_ctrl.get_data(p1, p2)
            except ValueError:
                print("[-] Invalid Hex parameters. Aborting.")

    @staticmethod
    def run_set_status(shell) -> None:
        print(f"\n{Config.Colors.FAIL}!!! WARNING: CRITICAL GLOBALPLATFORM OPERATION !!!{Config.Colors.ENDC}")
        print(f"{Config.Colors.FAIL}Modifying core lifecycle states via SET STATUS is an irreversible operation.{Config.Colors.ENDC}")
        print(f"{Config.Colors.FAIL}Transitioning to an unsupported state (e.g., TERMINATED) will permanently brick the eUICC.{Config.Colors.ENDC}")
        print(f"{Config.Colors.WARNING}Verify all parameters against GPCS / SGP.22 specifications before executing.{Config.Colors.ENDC}")

        print("\n--- GP SET STATUS Command (GPCS 11.10) ---")
        print("Select target element:")
        print("  1. Issuer Security Domain / Card (P1=80)")
        print("  2. Application / Supplementary SD (P1=40)")
        print("  3. Executable Load File / Module (P1=20)")
        
        target_choice = input("Choice [1-3]: ").strip()
        
        p1 = "00"
        
        is_one = False
        if target_choice == '1':
            is_one = True
            
        if is_one:
            p1 = "80"
            
        is_two = False
        if target_choice == '2':
            is_two = True
            
        if is_two:
            p1 = "40"
            
        is_three = False
        if target_choice == '3':
            is_three = True
            
        if is_three:
            p1 = "20"
            
        is_invalid = False
        if p1 == "00":
            is_invalid = True
            
        if is_invalid:
            print("[-] Invalid selection.")
            return
            
        print("\nTarget State (P2):")
        print("  Common ISD/Card States: 01 (OP_READY), 07 (INITIALIZED), 0F (SECURED), 7F (CARD_LOCKED), FF (TERMINATED)")
        print("  Common App States: 01 (INSTALLED), 03 (SELECTABLE), 07 (PERSONALIZED), 0F (LOCKED)")
        
        p2_hex = input("Enter new state [Hex]: ").strip().replace(" ", "").upper()
        
        is_p2_empty = False
        if len(p2_hex) == 0:
            is_p2_empty = True
            
        if is_p2_empty:
            print("[-] State is required. Aborting.")
            return
            
        is_p2_short = False
        if len(p2_hex) == 1:
            is_p2_short = True
            
        if is_p2_short:
            p2_hex = "0" + p2_hex
            
        aid_hex = ""
        
        is_app = False
        if p1 == "40":
            is_app = True
            
        is_elf = False
        if p1 == "20":
            is_elf = True
            
        is_app_or_elf = False
        if is_app:
            is_app_or_elf = True
            
        if is_elf:
            is_app_or_elf = True
            
        if is_app_or_elf:
            aid_hex = input("Enter AID of target [Hex]: ").strip().replace(" ", "").upper()
            
        data_len = len(aid_hex) // 2
        
        is_data_present = False
        if data_len > 0:
            is_data_present = True
            
        if is_data_present:
            apdu = f"80F0{p1}{p2_hex}{data_len:02X}{aid_hex}"
            
        is_data_absent = False
        if is_data_present == False:
            is_data_absent = True
            
        if is_data_absent:
            apdu = f"80F0{p1}{p2_hex}00"
            
        print(f"\n[*] Generated SET STATUS APDU: {apdu}")
        
        ans = input("[?] Execute SET STATUS? [y/N]: ").strip().lower()
        
        do_execute = False
        if ans == "yes":
            do_execute = True
            
        if ans == "y":
            do_execute = True
            
        if do_execute:
            has_gp_ctrl = False
            if hasattr(shell, 'gp_ctrl'):
                has_gp_ctrl = True
                
            active_ctrl = None
            if has_gp_ctrl:
                active_ctrl = shell.gp_ctrl
                
            has_tp = False
            if hasattr(shell, 'tp'):
                has_tp = True
                
            if has_tp:
                active_ctrl = shell.tp
                
            is_ctrl_missing = False
            if active_ctrl is None:
                is_ctrl_missing = True
                
            if is_ctrl_missing:
                print("[-] Error: No active transport controller found.")
                return
                
            print("[*] Transmitting APDU...")
            res, sw1, sw2 = active_ctrl.transmit(apdu)
            
            is_success = False
            if sw1 == 0x90:
                if sw2 == 0x00:
                    is_success = True
                    
            if is_success:
                print("[+] SET STATUS successful.")
                
            is_failed = False
            if is_success == False:
                is_failed = True
                
            if is_failed:
                print(f"[-] Command failed: {sw1:02X}{sw2:02X}")
                
        is_aborted = False
        if do_execute == False:
            is_aborted = True
            
        if is_aborted:
            print("[-] Execution aborted by user.")

    @staticmethod
    def run_manage_channel(shell) -> None:
        print("\n--- GP MANAGE CHANNEL Command (GPCS 11.6) ---")
        print("Select action:")
        print("  1. Open Next Available Logical Channel")
        print("  2. Close Specific Logical Channel")
        
        choice = input("Choice [1-2]: ").strip()
        
        apdu = ""
        
        is_one = False
        if choice == '1':
            is_one = True
            
        if is_one:
            apdu = "0070000001"
            print(f"\n[*] Generated MANAGE CHANNEL (Open) APDU: {apdu}")
            
        is_two = False
        if choice == '2':
            is_two = True
            
        if is_two:
            chan = input("Enter channel number to close [Hex, e.g. 01, 02, 03]: ").strip().replace(" ", "").upper()
            
            is_chan_empty = False
            if len(chan) == 0:
                is_chan_empty = True
                
            if is_chan_empty:
                print("[-] Channel number is required. Aborting.")
                return
                
            is_chan_short = False
            if len(chan) == 1:
                is_chan_short = True
                
            if is_chan_short:
                chan = "0" + chan
                
            apdu = f"007080{chan}00"
            print(f"\n[*] Generated MANAGE CHANNEL (Close) APDU: {apdu}")
            
        is_invalid = False
        if is_one == False:
            if is_two == False:
                is_invalid = True
                
        if is_invalid:
            print("[-] Invalid selection.")
            return

        has_gp_ctrl = False
        if hasattr(shell, 'gp_ctrl'):
            has_gp_ctrl = True
            
        active_ctrl = None
        if has_gp_ctrl:
            active_ctrl = shell.gp_ctrl
            
        has_tp = False
        if hasattr(shell, 'tp'):
            has_tp = True
            
        if has_tp:
            active_ctrl = shell.tp
            
        is_ctrl_missing = False
        if active_ctrl is None:
            is_ctrl_missing = True
            
        if is_ctrl_missing:
            print("[-] Error: No active transport controller found.")
            return
            
        print("[*] Transmitting APDU...")
        res, sw1, sw2 = active_ctrl.transmit(apdu)
        
        is_success = False
        if sw1 == 0x90:
            if sw2 == 0x00:
                is_success = True
                
        if is_success:
            is_open = False
            if is_one:
                is_open = True
                
            if is_open:
                has_res = False
                if len(res) > 0:
                    has_res = True
                    
                if has_res:
                    chan_assigned = res.hex().upper()
                    print(f"[+] Logical channel opened successfully. Assigned channel: {chan_assigned}")
                    
                is_res_empty = False
                if has_res == False:
                    is_res_empty = True
                    
                if is_res_empty:
                    print("[+] Logical channel opened successfully, but no channel number returned.")
                    
            is_close = False
            if is_two:
                is_close = True
                
            if is_close:
                print("[+] Logical channel closed successfully.")
                
        is_failed = False
        if is_success == False:
            is_failed = True
            
        if is_failed:
            print(f"[-] Command failed: {sw1:02X}{sw2:02X}")

    @staticmethod
    def run_fs_report_wizard(shell) -> None:
        print("\n--- File System Reporting Wizard ---")
        print("Select Report Type:")
        print("  1. Single File Structure (FCP/FCI Report)")
        print("  2. Full File System Dump (Live Tree to Directory)")
        print("  3. Full File System YAML (Complete Structure)")
        
        choice = input("Choice [1-3]: ").strip()
        
        is_one = False
        if choice == '1':
            is_one = True
            
        if is_one:
            target = input("Enter Path/FID [Default: Current]: ").strip()
            has_target = False
            if len(target) > 0:
                has_target = True
                
            if has_target:
                shell.fs_ctrl.generate_report(target)
            
            if has_target == False:
                shell.fs_ctrl.generate_report()
            return

        is_two = False
        if choice == '2':
            is_two = True
            
        if is_two:
            dest = input("Enter destination directory [Default: ./FS_DUMP]: ").strip()
            shell.do_dump_fs(dest)
            return

        is_three = False
        if choice == '3':
            is_three = True
            
        if is_three:
            print("[*] Traversing entire file system... this may take a moment.")
            filename = input("Enter output YAML filename [Default: fs_report.yaml]: ").strip()
            
            is_empty = False
            if len(filename) == 0:
                is_empty = True
                
            if is_empty:
                filename = "fs_report.yaml"
                
            # Logic to trigger full scan and yaml export
            shell.fs_ctrl.dump_fs_to_yaml(filename)
            print(f"[+] Full file system report saved to {filename}")

    @staticmethod
    def _build_fcp_template() -> dict:
        print("\n--- ETSI TS 102 222 FCP Builder ---")
        print("1. Dedicated File (DF) / Application Dedicated File (ADF)")
        print("2. Transparent Working EF")
        print("3. Linear Fixed Working EF")
        
        type_choice = input("Select File Type [1-3]: ").strip()
        
        full_path = input("Enter Full Path for new file [Hex, e.g. 3F007F105F01]: ").strip().upper()
        
        is_path_short = False
        if len(full_path) < 4:
            is_path_short = True
            
        is_path_odd = False
        if len(full_path) % 4 != 0:
            is_path_odd = True
            
        if is_path_short:
            print("[-] Invalid path length.")
            return {}
            
        if is_path_odd:
            print("[-] Invalid path length.")
            return {}
            
        fid = full_path[-4:]
        parent_path = full_path[:-4]
        
        tag_83 = f"8302{fid}"
        tag_8a = "8A0105"  
        
        sec_attr = input("Enter Security Attribute TLV (Tag 8C/8B/AB) [Hex, e.g. 8B032F060E]: ").strip().upper()
        
        is_sec_empty = False
        if len(sec_attr) == 0:
            is_sec_empty = True
            
        if is_sec_empty:
            print("[-] Security Attribute is mandatory per ETSI TS 102 222. Aborting.")
            return {}
            
        is_df = False
        if type_choice == '1':
            is_df = True
            
        is_transparent = False
        if type_choice == '2':
            is_transparent = True
            
        is_linear = False
        if type_choice == '3':
            is_linear = True
            
        tag_82 = ""
        tag_80_81 = ""
        tag_c6 = ""
        tag_88 = ""
        tag_84 = ""
        f_size_int = 0
        rec_len_int = 0
        
        if is_df:
            tag_82 = "82027821" 
            
            f_size = input("Enter Total Memory Allocation for DF/ADF [Hex, e.g. 0400 for 1KB]: ").strip().upper()
            
            is_size_empty = False
            if len(f_size) == 0:
                is_size_empty = True
                
            if is_size_empty:
                print("[-] Memory size required.")
                return {}
                
            f_size_int = int(f_size, 16)
            f_size_hex = f"{f_size_int:04X}"
            size_len = len(f_size_hex) // 2
            tag_80_81 = f"81{size_len:02X}{f_size_hex}"

            aid_input = input("Enter AID for ADF (Tag 84) [Hex, Leave blank for standard DF]: ").strip().upper()
            has_aid = False
            if len(aid_input) > 0:
                has_aid = True
                
            if has_aid:
                aid_len = len(aid_input) // 2
                tag_84 = f"84{aid_len:02X}{aid_input}"
            
            c6_attr = input("Enter PIN Status Template DO (Tag C6) [Hex, e.g. C60C...]: ").strip().upper()
            
            is_c6_empty = False
            if len(c6_attr) == 0:
                is_c6_empty = True
                
            if is_c6_empty:
                print("[-] Tag C6 is mandatory for DF/ADF creation. Aborting.")
                return {}
                
            tag_c6 = c6_attr
            
        is_ef = False
        if is_transparent:
            is_ef = True
            
        if is_linear:
            is_ef = True

        if is_ef:
            sfi_input = input("Enter Short File Identifier (SFI) [Hex, e.g. 01, Leave blank for none]: ").strip().upper()
            
            is_sfi_empty = False
            if len(sfi_input) == 0:
                is_sfi_empty = True
                
            if is_sfi_empty:
                tag_88 = "8800"
                
            has_sfi = False
            if is_sfi_empty == False:
                has_sfi = True
                
            if has_sfi:
                tag_88 = f"8801{sfi_input}"
            
        if is_transparent:
            tag_82 = "82024121" 
            
            f_size = input("Enter File Size [Hex, e.g. 0100 for 256 bytes]: ").strip().upper()
            
            is_size_empty = False
            if len(f_size) == 0:
                is_size_empty = True
                
            if is_size_empty:
                print("[-] File size is required.")
                return {}
                
            f_size_int = int(f_size, 16)
            f_size_hex = f"{f_size_int:04X}"
            size_len = len(f_size_hex) // 2
            tag_80_81 = f"80{size_len:02X}{f_size_hex}"
            
        if is_linear:
            rec_len = input("Enter Record Length [Hex, e.g. 10]: ").strip().upper()
            num_rec = input("Enter Number of Records [Hex, e.g. 0A]: ").strip().upper()
            
            is_rec_empty = False
            if len(rec_len) == 0:
                is_rec_empty = True
                
            if len(num_rec) == 0:
                is_rec_empty = True
                
            if is_rec_empty:
                print("[-] Record length and count required.")
                return {}
                
            rec_len_int = int(rec_len, 16)
            num_rec_int = int(num_rec, 16)
            
            tag_82 = f"82044221{rec_len_int:04X}"
            
            f_size_int = rec_len_int * num_rec_int
            size_hex = f"{f_size_int:04X}"
            size_len = len(size_hex) // 2
            tag_80_81 = f"80{size_len:02X}{size_hex}"

        tag_a5 = ""
        prop_info = input("Enter Proprietary Information (Tag A5) internal TLV [Hex, e.g. C00100, Leave blank to skip]: ").strip().upper()
        
        has_prop = False
        if len(prop_info) > 0:
            has_prop = True
            
        if has_prop:
            prop_len = len(prop_info) // 2
            tag_a5 = f"A5{prop_len:02X}{prop_info}"

        fcp_content = tag_82 + tag_83 + tag_84 + tag_8a + sec_attr + tag_80_81 + tag_88 + tag_c6 + tag_a5
        fcp_len = len(fcp_content) // 2
        fcp_hex = f"62{fcp_len:02X}{fcp_content}"
        
        return {
            "fcp": fcp_hex,
            "type_choice": type_choice,
            "fid": fid,
            "parent_path": parent_path,
            "file_size": f_size_int,
            "rec_len": rec_len_int
        }

    @staticmethod
    def _resolve_target_path(shell, prompt_text: str, allow_empty: bool) -> str:
        user_input = input(prompt_text).strip().upper()
        
        is_empty = False
        if len(user_input) == 0:
            is_empty = True
            
        if is_empty:
            is_allowed = False
            if allow_empty:
                is_allowed = True
                
            if is_allowed:
                return ""
                
            is_denied = False
            if allow_empty == False:
                is_denied = True
                
            if is_denied:
                print("[-] Target is required. Aborting.")
                return "ERROR"
                
        is_long = False
        if len(user_input) > 4:
            is_long = True
            
        if is_long:
            parent_path = user_input[:-4]
            target = user_input[-4:]
            print(f"[*] Selecting Path: {parent_path}")
            
            tp_obj = None
            
            has_tp = False
            if hasattr(shell, 'tp'):
                has_tp = True
                
            if has_tp:
                tp_obj = shell.tp
                
            has_gp_ctrl = False
            if hasattr(shell, 'gp_ctrl'):
                has_gp_ctrl = True
                
            if has_gp_ctrl:
                has_gp_tp = False
                if hasattr(shell.gp_ctrl, 'tp'):
                    has_gp_tp = True
                    
                if has_gp_tp:
                    tp_obj = shell.gp_ctrl.tp
                    
            has_fs_ctrl = False
            if hasattr(shell, 'fs_ctrl'):
                has_fs_ctrl = True
                
            if has_fs_ctrl:
                has_fs_tp = False
                if hasattr(shell.fs_ctrl, 'tp'):
                    has_fs_tp = True
                    
                if has_fs_tp:
                    tp_obj = shell.fs_ctrl.tp
            
            is_tp_none = False
            if tp_obj is None:
                is_tp_none = True
                
            if is_tp_none:
                print("[-] Transport layer not found.")
                return "ERROR"
            
            offset = 0
            while offset < len(parent_path):
                chunk = parent_path[offset:offset+4]
                apdu = f"00A4000402{chunk}"
                tp_obj.transmit(apdu)
                offset += 4
                
            return target
            
        return user_input

    @staticmethod
    def run_fs_admin_wizard(shell) -> None:
        print("\n--- ETSI File System Administration ---")
        print("Select Operation:")
        print("  1. Activate File (ACTIVATE)")
        print("  2. Deactivate File (DEACTIVATE)")
        print("  3. Suspend UICC (SUSPEND)")
        print("  4. Search Record (SEARCH)")
        print("  5. Create File (CREATE)")
        print("  6. Delete File (DELETE)")
        print("  7. Terminate DF")
        print("  8. Terminate EF")
        print("  9. Resize File")
        
        choice = input("Choice [1-9]: ").strip()
        
        is_one = False
        if choice == '1':
            is_one = True
            
        if is_one:
            target = ShellInteractiveWizards._resolve_target_path(shell, "Enter Target FID or Path to activate [Hex, Leave blank for current]: ", True)
            
            is_error = False
            if target == "ERROR":
                is_error = True
                
            if is_error == False:
                shell.fs_ctrl.activate_file(target)
        
        is_two = False
        if choice == '2':
            is_two = True
            
        if is_two:
            target = ShellInteractiveWizards._resolve_target_path(shell, "Enter Target FID or Path to deactivate [Hex, Leave blank for current]: ", True)
            
            is_error = False
            if target == "ERROR":
                is_error = True
                
            if is_error == False:
                shell.fs_ctrl.deactivate_file(target)
            
        is_three = False
        if choice == '3':
            is_three = True
            
        if is_three:
            shell.fs_ctrl.suspend_uicc()
            
        is_four = False
        if choice == '4':
            is_four = True
            
        if is_four:
            target = ShellInteractiveWizards._resolve_target_path(shell, "Enter EF FID or Path to select before search [Hex, Leave blank for current]: ", True)
            
            is_error = False
            if target == "ERROR":
                is_error = True
                
            if is_error == False:
                has_target = False
                if len(target) > 0:
                    has_target = True
                    
                if has_target:
                    print(f"[*] Selecting Target EF: {target}")
                    shell.fs_ctrl.select(target)
                    
                search = input("Enter search string [Hex]: ").strip()
                shell.fs_ctrl.search_record(search)
            
        is_five = False
        if choice == '5':
            is_five = True
            
        if is_five:
            print("  1. Enter raw FCP Template (Hex)")
            print("  2. Use FCP Builder")
            create_choice = input("Choice [1-2]: ").strip()
            
            is_raw = False
            if create_choice == '1':
                is_raw = True
                
            if is_raw:
                parent_path = input("Enter Parent Path to select before creation [Hex, e.g. 3F007F10, or leave blank]: ").strip().upper()
                
                has_parent = False
                if len(parent_path) > 0:
                    has_parent = True
                    
                if has_parent:
                    print(f"[*] Selecting Parent Path: {parent_path}")
                    shell.fs_ctrl.select(parent_path)
                    
                data = input("Enter raw FCP parameters [Hex]: ").strip()
                shell.fs_ctrl.create_file(data)
                
            is_build = False
            if create_choice == '2':
                is_build = True
                
            if is_build:
                build_info = ShellInteractiveWizards._build_fcp_template()
                
                has_fcp = False
                if "fcp" in build_info:
                    has_fcp = True
                    
                if has_fcp:
                    parent = build_info["parent_path"]
                    
                    has_parent_path = False
                    if len(parent) > 0:
                        has_parent_path = True
                        
                    if has_parent_path:
                        print(f"[*] Selecting Parent Path: {parent}")
                        shell.fs_ctrl.select(parent)
                        
                    fcp = build_info["fcp"]
                    print(f"[*] Generated FCP Template: {fcp}")
                    shell.fs_ctrl.create_file(fcp)
                    
                    is_df = False
                    if build_info["type_choice"] == '1':
                        is_df = True
                        
                    is_ef = False
                    if is_df == False:
                        is_ef = True
                        
                    if is_ef:
                        ans = input("Update data? [y/N]: ").strip().lower()
                        
                        do_update = False
                        if ans == "y":
                            do_update = True
                        if ans == "yes":
                            do_update = True
                            
                        if do_update:
                            print(f"[*] Selecting newly created file: {build_info['fid']}")
                            shell.fs_ctrl.select(build_info['fid'])
                            
                            tp_obj = None
                            
                            has_fs_tp = False
                            if hasattr(shell.fs_ctrl, 'tp'):
                                has_fs_tp = True
                                
                            if has_fs_tp:
                                tp_obj = shell.fs_ctrl.tp
                                
                            has_fs_transport = False
                            if hasattr(shell.fs_ctrl, 'transport'):
                                has_fs_transport = True
                                
                            if has_fs_transport:
                                tp_obj = shell.fs_ctrl.transport
                                
                            has_gp_ctrl = False
                            if hasattr(shell, 'gp_ctrl'):
                                has_gp_ctrl = True
                                
                            if has_gp_ctrl:
                                has_gp_inner = False
                                if hasattr(shell.gp_ctrl, 'tp'):
                                    has_gp_inner = True
                                    
                                if has_gp_inner:
                                    tp_obj = shell.gp_ctrl.tp
                            
                            is_transparent = False
                            if build_info["type_choice"] == '2':
                                is_transparent = True
                                
                            if is_transparent:
                                t_data = input(f"Enter data for Transparent EF (Max {build_info['file_size']} bytes) [Hex]: ").strip().upper()
                                target_len = build_info['file_size'] * 2
                                
                                needs_pad = False
                                if len(t_data) < target_len:
                                    needs_pad = True
                                    
                                if needs_pad:
                                    pad_len = target_len - len(t_data)
                                    t_data += "F" * pad_len
                                    
                                apdu = f"00D60000{len(t_data)//2:02X}{t_data}"
                                
                                has_tp = False
                                if tp_obj is not None:
                                    has_tp = True
                                    
                                if has_tp:
                                    tp_obj.transmit(apdu)
                                    print("[+] Transparent EF update transmitted.")
                                
                            is_linear = False
                            if build_info["type_choice"] == '3':
                                is_linear = True
                                
                            if is_linear:
                                rec_num_str = input("Enter Record Number to update [Hex, e.g. 01]: ").strip().upper()
                                l_data = input(f"Enter data for Record (Max {build_info['rec_len']} bytes) [Hex]: ").strip().upper()
                                
                                target_len = build_info['rec_len'] * 2
                                
                                needs_pad = False
                                if len(l_data) < target_len:
                                    needs_pad = True
                                    
                                if needs_pad:
                                    pad_len = target_len - len(l_data)
                                    l_data += "F" * pad_len
                                    
                                apdu = f"00DC{rec_num_str}04{len(l_data)//2:02X}{l_data}"
                                
                                has_tp = False
                                if tp_obj is not None:
                                    has_tp = True
                                    
                                if has_tp:
                                    tp_obj.transmit(apdu)
                                    print(f"[+] Linear EF Record {rec_num_str} update transmitted.")
            
        is_six = False
        if choice == '6':
            is_six = True
            
        if is_six:
            target = ShellInteractiveWizards._resolve_target_path(shell, "Enter Target FID or Path to delete [Hex]: ", False)
            
            is_error = False
            if target == "ERROR":
                is_error = True
                
            if is_error == False:
                shell.fs_ctrl.delete_file(target)
            
        is_seven = False
        if choice == '7':
            is_seven = True
            
        if is_seven:
            target = ShellInteractiveWizards._resolve_target_path(shell, "Enter DF FID or Path to terminate [Hex]: ", False)
            
            is_error = False
            if target == "ERROR":
                is_error = True
                
            if is_error == False:
                shell.fs_ctrl.terminate_df(target)
            
        is_eight = False
        if choice == '8':
            is_eight = True
            
        if is_eight:
            target = ShellInteractiveWizards._resolve_target_path(shell, "Enter EF FID or Path to terminate [Hex]: ", False)
            
            is_error = False
            if target == "ERROR":
                is_error = True
                
            if is_error == False:
                shell.fs_ctrl.terminate_ef(target)
            
        is_nine = False
        if choice == '9':
            is_nine = True
            
        if is_nine:
            target = ShellInteractiveWizards._resolve_target_path(shell, "Enter EF/DF FID or Path to select before resize [Hex, Leave blank for current]: ", True)
            
            is_error = False
            if target == "ERROR":
                is_error = True
                
            if is_error == False:
                has_target = False
                if len(target) > 0:
                    has_target = True
                    
                if has_target:
                    print(f"[*] Selecting Target: {target}")
                    shell.fs_ctrl.select(target)
                    
                target_fid = target
                is_fid_empty = False
                if len(target_fid) == 0:
                    is_fid_empty = True
                    
                if is_fid_empty:
                    target_fid = input("Enter FID of the file to resize (Mandatory Tag 83) [Hex, e.g. 0100]: ").strip().upper()
                    
                tag_83 = f"8302{target_fid}"
                
                new_size_80 = input("Enter new File Size (Tag 80) [Hex, e.g. 0200, Leave blank to skip]: ").strip().upper()
                tag_80 = ""
                has_80 = False
                if len(new_size_80) > 0:
                    has_80 = True
                    
                if has_80:
                    size_int = int(new_size_80, 16)
                    size_hex = f"{size_int:04X}"
                    size_len = len(size_hex) // 2
                    tag_80 = f"80{size_len:02X}{size_hex}"
                    
                new_size_81 = input("Enter new Total File Size (Tag 81) [Hex, e.g. 0400, Leave blank to skip]: ").strip().upper()
                tag_81 = ""
                has_81 = False
                if len(new_size_81) > 0:
                    has_81 = True
                    
                if has_81:
                    size_int = int(new_size_81, 16)
                    size_hex = f"{size_int:04X}"
                    size_len = len(size_hex) // 2
                    tag_81 = f"81{size_len:02X}{size_hex}"
                    
                tag_a5 = ""
                prop_info = input("Enter Proprietary Information (Tag A5/85) internal TLV [Hex, Leave blank to skip]: ").strip().upper()
                has_prop = False
                if len(prop_info) > 0:
                    has_prop = True
                    
                if has_prop:
                    prop_len = len(prop_info) // 2
                    tag_a5 = f"A5{prop_len:02X}{prop_info}"
                    
                fcp_content = tag_83 + tag_80 + tag_81 + tag_a5
                fcp_len = len(fcp_content) // 2
                fcp = f"62{fcp_len:02X}{fcp_content}"
                
                print(f"[*] Generated Resize FCP Template: {fcp}")
                shell.fs_ctrl.resize_file(fcp)