# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os
import sys
import configparser

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, '../../'))
is_missing = False
if root_dir not in sys.path:
    is_missing = True
if is_missing:
    sys.path.insert(0, root_dir)

from SCP03.config import Config
from SCP03.interface.wizards_ui import InteractiveWizard

class ShellInteractiveWizards:

    @staticmethod
    def run_put_key_wizard(shell) -> None:
        wiz = InteractiveWizard("GP PUT KEY Command (GPCS 11.8)", Config.Colors, "WARNING: CRITICAL CRYPTOGRAPHIC OPERATION\nExecuting PUT KEY overwrites the active session keys. Loss of keys bricks the card.")
        wiz.add_step("action", "Action [1=Add New, 2=Rotate (ID 01), 3=Replace Specific]:", default="1")
        wiz.add_step("okvn", "Old KVN to replace [Hex, SKIP for Add/Rotate]:", default="SKIP")
        wiz.add_step("okid", "Key ID to replace [Hex, SKIP for Add/Rotate]:", default="SKIP")
        wiz.add_step("nkid", "New Key ID [Hex, SKIP for Rotate]:", default="SKIP")
        wiz.add_step("nkvn", "New KVN [Hex]:", default="")
        wiz.add_step("enc", "New ENC Key [Hex, 16 bytes]:", default="")
        wiz.add_step("mac", "New MAC Key [Hex, 16 bytes]:", default="")
        wiz.add_step("dek", "New DEK Key [Hex, 16 bytes]:", default="")
        wiz.add_step("algo", "Algorithm [AES/3DES, Default: AES]:", default="AES")
        wiz.add_step("exec", "Execute PUT KEY? [y/N]:", default=False, is_bool=True)

        res = wiz.run()

        is_exec = False
        if res.get("exec"):
            is_exec = True

        if is_exec == False:
            print("[-] Execution aborted by user.")
            return

        action = res.get("action")
        is_one = False
        if action == "1":
            is_one = True
        is_two = False
        if action == "2":
            is_two = True
        is_three = False
        if action == "3":
            is_three = True

        old_kvn = 0
        key_id = 0

        if is_one:
            kid_input = res.get("nkid")
            is_skip = False
            if kid_input == "SKIP":
                is_skip = True
            if is_skip:
                print("[-] Key ID required for Add. Aborting.")
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
            okvn_input = res.get("okvn")
            is_okvn_skip = False
            if okvn_input == "SKIP":
                is_okvn_skip = True
            if is_okvn_skip:
                print("[-] Old KVN required for Replace. Aborting.")
                return
            old_kvn = int(okvn_input, 16)

            okid_input = res.get("okid")
            is_okid_skip = False
            if okid_input == "SKIP":
                is_okid_skip = True
            if is_okid_skip:
                print("[-] Key ID required for Replace. Aborting.")
                return
            key_id = int(okid_input, 16)

        nkvn_input = res.get("nkvn")
        is_nkvn_empty = False
        if len(nkvn_input) == 0:
            is_nkvn_empty = True
        if is_nkvn_empty:
            print("[-] New KVN required. Aborting.")
            return
        new_kvn = int(nkvn_input, 16)

        enc = res.get("enc").replace(" ", "")
        mac = res.get("mac").replace(" ", "")
        dek = res.get("dek").replace(" ", "")
        algo = res.get("algo").upper()

        keys = [enc, mac, dek]
        print("\n[*] Executing PUT KEY...")
        ShellInteractiveWizards._exec_put_key(shell, old_kvn, key_id, new_kvn, keys, algo)

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
        wiz = InteractiveWizard("Configuration Synchronization", Config.Colors)
        wiz.add_step("upd", f"Update keys.ini with new keys? [y/N]:", default=False, is_bool=True)
        res = wiz.run()

        is_upd = False
        if res.get("upd"):
            is_upd = True

        if is_upd:
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
    def run_manage_pin_wizard(shell, arg_str="") -> None:
        has_args = False
        if len(arg_str.strip()) > 0:
            has_args = True
            
        if has_args:
            parts = arg_str.strip().split()
            action = parts[0].lower()
            
            pin_id = "01"
            if len(parts) > 1:
                pin_id = parts[1].upper()
                
            print("\n[*] Executing PIN Command via Macro...")
            
            is_verify = False
            if action == "verify":
                is_verify = True
                
            if is_verify:
                pin = ""
                if len(parts) > 2:
                    pin = parts[2]
                shell.sec_ctrl.verify_pin(pin_id, pin)
                return
                
            is_change = False
            if action == "change":
                is_change = True
                
            if is_change:
                curr = ""
                new_pin = ""
                if len(parts) > 2:
                    curr = parts[2]
                if len(parts) > 3:
                    new_pin = parts[3]
                shell.sec_ctrl.change_pin(pin_id, curr, new_pin)
                return
                
            is_disable = False
            if action == "disable":
                is_disable = True
                
            if is_disable:
                curr = ""
                if len(parts) > 2:
                    curr = parts[2]
                shell.sec_ctrl.disable_pin(pin_id, curr)
                return
                
            is_enable = False
            if action == "enable":
                is_enable = True
                
            if is_enable:
                curr = ""
                if len(parts) > 2:
                    curr = parts[2]
                shell.sec_ctrl.enable_pin(pin_id, curr)
                return
                
            is_unblock = False
            if action == "unblock":
                is_unblock = True
                
            if is_unblock:
                puk = ""
                new_pin = ""
                if len(parts) > 2:
                    puk = parts[2]
                if len(parts) > 3:
                    new_pin = parts[3]
                shell.sec_ctrl.unblock_pin(pin_id, puk, new_pin)
                return
                
            print("[-] Unknown action for MANAGE-PIN macro.")
            return

        wiz = InteractiveWizard("GP PIN Management Command", Config.Colors)
        wiz.add_step("action", "Action [1=Verify, 2=Change, 3=Disable, 4=Enable, 5=Unblock]:", default="1")
        wiz.add_step("pin_id", "PIN ID [Hex, Default: 01]:", default="01")
        
        def curr_cond(res):
            action = res.get("action")
            is_unblock = False
            if action == '5':
                is_unblock = True
            return not is_unblock
            
        wiz.add_step("curr", "Enter PIN [ASCII]:", default="SKIP", condition=curr_cond)
        
        def new_cond(res):
            action = res.get("action")
            is_change_or_unblock = False
            if action == '2':
                is_change_or_unblock = True
            if action == '5':
                is_change_or_unblock = True
            return is_change_or_unblock
            
        wiz.add_step("new", "New PIN [ASCII]:", default="SKIP", condition=new_cond)
        
        def puk_cond(res):
            action = res.get("action")
            is_unblock = False
            if action == '5':
                is_unblock = True
            return is_unblock
            
        wiz.add_step("puk", "PUK [ASCII]:", default="SKIP", condition=puk_cond)

        res = wiz.run()
        choice = res.get("action")

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

        pin_id = res.get("pin_id").upper()
        
        curr = res.get("curr")
        is_curr_skip = False
        if curr == "SKIP":
            is_curr_skip = True
        if is_curr_skip:
            curr = ""
            
        new_pin = res.get("new")
        is_new_skip = False
        if new_pin == "SKIP":
            is_new_skip = True
        if is_new_skip:
            new_pin = ""
            
        puk = res.get("puk")
        is_puk_skip = False
        if puk == "SKIP":
            is_puk_skip = True
        if is_puk_skip:
            puk = ""

        print("\n[*] Executing PIN Command...")
        if is_one:
            shell.sec_ctrl.verify_pin(pin_id, curr)
        if is_two:
            shell.sec_ctrl.change_pin(pin_id, curr, new_pin)
        if is_three:
            shell.sec_ctrl.disable_pin(pin_id, curr)
        if is_four:
            shell.sec_ctrl.enable_pin(pin_id, curr)
        if is_five:
            shell.sec_ctrl.unblock_pin(pin_id, puk, new_pin)

    @staticmethod
    def run_manage_profile_wizard(shell) -> None:
        wiz = InteractiveWizard("eSIM Profile Management", Config.Colors)
        wiz.add_step("spec", "Target Spec [1=SGP.22/32, 2=SGP.02]:", default="1")
        
        def action_cond(res):
            spec = res.get("spec")
            is_sgp22 = False
            if spec == '1':
                is_sgp22 = True
            return is_sgp22
            
        wiz.add_step("action", "Action [1=List, 2=Scan, 3=Enable, 4=Disable, 5=Delete]:", default="1", condition=action_cond)
        
        def target_cond(res):
            action = res.get("action")
            is_req = False
            if action == '3':
                is_req = True
            if action == '4':
                is_req = True
            if action == '5':
                is_req = True
            return is_req
            
        wiz.add_step("target", "Target Profile AID/ICCID/Alias:", default="SKIP", condition=target_cond)

        res = wiz.run()

        is_cons = False
        if res.get("spec") == '1':
            is_cons = True

        is_m2m = False
        if res.get("spec") == '2':
            is_m2m = True

        action = res.get("action")
        target = res.get("target")

        if is_cons:
            is_one = False
            if action == '1':
                is_one = True
                
            if is_one:
                shell.gp_ctrl.sgp22.list_profiles()
                return

            is_two = False
            if action == '2':
                is_two = True
                
            if is_two:
                shell.gp_ctrl.sgp22.run_sgp22_scan()
                return

            is_three = False
            if action == '3':
                is_three = True
            is_four = False
            if action == '4':
                is_four = True
            is_five = False
            if action == '5':
                is_five = True

            needs_target = False
            if is_three:
                needs_target = True
            if is_four:
                needs_target = True
            if is_five:
                needs_target = True

            if needs_target:
                is_skip = False
                if target == "SKIP":
                    is_skip = True
                    
                if is_skip:
                    print("[-] Target required. Aborting.")
                    return

                resolved_target = shell._resolve_mixed_aid(target)

                if is_three:
                    r = shell.gp_ctrl.sgp22.enable_profile(resolved_target)
                    is_r = False
                    if r:
                        is_r = True
                    if is_r:
                        shell._handle_reset()
                if is_four:
                    r = shell.gp_ctrl.sgp22.disable_profile(resolved_target)
                    is_r = False
                    if r:
                        is_r = True
                    if is_r:
                        shell._handle_reset()
                if is_five:
                    r = shell.gp_ctrl.sgp22.delete_profile(resolved_target)
                    is_r = False
                    if r:
                        is_r = True
                    if is_r:
                        shell._handle_reset()

        if is_m2m:
            is_one_m2m = False
            if action == '1':
                is_one_m2m = True
                
            if is_one_m2m:
                shell.gp_ctrl.sgp22.run_sgp02_scan()

    @staticmethod
    def run_auth_wizard(shell) -> None:
        wiz = InteractiveWizard("Telecom Authentication Command", Config.Colors)
        wiz.add_step("ctx", "Context [1=GSM, 2=USIM, 3=ISIM]:", default="1")
        wiz.add_step("rand", "RAND [Hex]:", default="")
        
        def autn_cond(res):
            ctx = res.get("ctx")
            is_gsm = False
            if ctx == '1':
                is_gsm = True
            return not is_gsm
            
        wiz.add_step("autn", "AUTN [Hex]:", default="SKIP", condition=autn_cond)

        res = wiz.run()
        ctx = res.get("ctx")

        is_gsm = False
        if ctx == '1':
            is_gsm = True
        is_usim = False
        if ctx == '2':
            is_usim = True
        is_isim = False
        if ctx == '3':
            is_isim = True

        context = "GSM"
        if is_usim:
            context = "USIM"
        if is_isim:
            context = "ISIM"

        rand_val = res.get("rand").replace(" ", "")
        autn_val = res.get("autn").replace(" ", "")

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
        wiz = InteractiveWizard("Environment Configuration", Config.Colors)
        wiz.add_step("key", "Update [1=ENC, 2=MAC, 3=DEK, 4=KVN, 5=ADM, 6=AID]:", default="1")
        wiz.add_step("val", "New Value [Hex]:", default="")

        res = wiz.run()
        choice = res.get("key")
        val = res.get("val").replace(" ", "")

        key_name = ""
        is_one = False
        if choice == '1':
            is_one = True
        if is_one:
            key_name = "kenc"
            
        is_two = False
        if choice == '2':
            is_two = True
        if is_two:
            key_name = "kmac"
            
        is_three = False
        if choice == '3':
            is_three = True
        if is_three:
            key_name = "dek"
            
        is_four = False
        if choice == '4':
            is_four = True
        if is_four:
            key_name = "kvn"
            
        is_five = False
        if choice == '5':
            is_five = True
        if is_five:
            key_name = "adm"
            
        is_six = False
        if choice == '6':
            is_six = True
        if is_six:
            key_name = "aid"

        print(f"\n[*] Updating configuration...")
        shell._update_config(key_name, val)

    @staticmethod
    def run_get_data_wizard(shell) -> None:
        wiz = InteractiveWizard("GP GET DATA Command (GPCS 11.3)", Config.Colors)
        wiz.add_step("choice", "Action [1=Apps, 2=Pkgs, 3=SDs, 4=CPLC, 5=Custom]:", default="1")
        wiz.add_step("p1", "Custom P1 [Hex, SKIP for 1-4]:", default="SKIP")
        wiz.add_step("p2", "Custom P2 [Hex, SKIP for 1-4]:", default="SKIP")

        res = wiz.run()
        choice = res.get("choice")

        print("\n[*] Retrieving Data from Card...")

        is_one = False
        if choice == '1':
            is_one = True
        if is_one:
            shell.gp_ctrl.list_registry('APPS')
            return
            
        is_two = False
        if choice == '2':
            is_two = True
        if is_two:
            shell.gp_ctrl.list_registry('PACKAGES')
            return
            
        is_three = False
        if choice == '3':
            is_three = True
        if is_three:
            shell.gp_ctrl.list_registry('SD')
            return
            
        is_four = False
        if choice == '4':
            is_four = True
        if is_four:
            shell.gp_ctrl.get_cplc()
            return
            
        is_five = False
        if choice == '5':
            is_five = True
        if is_five:
            p1_str = res.get("p1").replace(" ", "").upper()
            p2_str = res.get("p2").replace(" ", "").upper()
            
            try:
                p1 = int(p1_str, 16)
                p2 = int(p2_str, 16)
                shell.gp_ctrl.get_data(p1, p2)
            except ValueError:
                print("[-] Invalid Hex parameters. Aborting.")

    @staticmethod
    def run_set_status(shell) -> None:
        wiz = InteractiveWizard("GP SET STATUS Command (GPCS 11.10)", Config.Colors, "WARNING: Irreversible operation.")
        wiz.add_step("target", "Target [1=ISD, 2=App, 3=ELF]:", default="1")
        wiz.add_step("state", "New State [Hex, e.g. 0F]:", default="")
        wiz.add_step("aid", "Target AID [Hex, SKIP for ISD]:", default="SKIP")
        wiz.add_step("exec", "Execute SET STATUS? [y/N]:", default=False, is_bool=True)

        res = wiz.run()
        
        is_exec = False
        if res.get("exec"):
            is_exec = True
            
        if is_exec == False:
            print("[-] Execution aborted by user.")
            return

        target_choice = res.get("target")
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

        p2_hex = res.get("state").replace(" ", "").upper()
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
            raw_aid = res.get("aid").replace(" ", "").upper()
            is_valid_aid = False
            if raw_aid != "SKIP":
                is_valid_aid = True
            if is_valid_aid:
                aid_hex = raw_aid
            
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
        r, sw1, sw2 = active_ctrl.transmit(apdu)
        
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

    @staticmethod
    def run_manage_channel(shell) -> None:
        wiz = InteractiveWizard("GP MANAGE CHANNEL Command (GPCS 11.6)", Config.Colors)
        wiz.add_step("choice", "Action [1=Open, 2=Close]:", default="1")
        wiz.add_step("chan", "Channel to close [Hex, SKIP for Open]:", default="SKIP")
        
        res = wiz.run()
        choice = res.get("choice")
        
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
            chan = res.get("chan").replace(" ", "").upper()
            is_chan_short = False
            if len(chan) == 1:
                is_chan_short = True
            if is_chan_short:
                chan = "0" + chan
                
            apdu = f"007080{chan}00"
            print(f"\n[*] Generated MANAGE CHANNEL (Close) APDU: {apdu}")
            
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
        r, sw1, sw2 = active_ctrl.transmit(apdu)
        
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
                if len(r) > 0:
                    has_res = True
                    
                if has_res:
                    chan_assigned = r.hex().upper()
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

    @staticmethod
    def run_fs_report_wizard(shell) -> None:
        wiz = InteractiveWizard("File System Reporting Wizard", Config.Colors)
        wiz.add_step("choice", "Report [1=Single FCP, 2=Live Tree, 3=YAML Dump]:", default="1")
        wiz.add_step("target", "Target FID/Path [SKIP for current]:", default="SKIP")
        wiz.add_step("dest", "Destination Dir [SKIP for FS_DUMP]:", default="SKIP")
        wiz.add_step("yaml", "YAML Filename [SKIP for fs_report.yaml]:", default="SKIP")
        
        res = wiz.run()
        choice = res.get("choice")

        is_one = False
        if choice == '1':
            is_one = True
            
        if is_one:
            target = res.get("target")
            has_target = False
            if target != "SKIP":
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
            dest = res.get("dest")
            is_dest_skip = False
            if dest == "SKIP":
                is_dest_skip = True
                
            if is_dest_skip:
                dest = ""
                
            shell.do_dump_fs(dest)
            return

        is_three = False
        if choice == '3':
            is_three = True
            
        if is_three:
            print("[*] Traversing entire file system... this may take a moment.")
            filename = res.get("yaml")
            is_filename_skip = False
            if filename == "SKIP":
                is_filename_skip = True
                
            if is_filename_skip:
                filename = "fs_report.yaml"
                
            shell.fs_ctrl.dump_fs_to_yaml(filename)
            print(f"[+] Full file system report saved to {filename}")

    @staticmethod
    def _build_fcp_template() -> dict:
        wiz = InteractiveWizard("ETSI TS 102 222 FCP Builder", Config.Colors)
        wiz.add_step("type", "File Type [1=DF/ADF, 2=Transparent EF, 3=Linear Fixed EF]:", default="1")
        wiz.add_step("path", "Full Path for new file [Hex, e.g. 3F007F105F01]:", default="")
        wiz.add_step("sec", "Security Attribute TLV (Tag 8C/8B/AB) [Hex]:", default="")
        wiz.add_step("size", "File Size / DF Memory [Hex]:", default="")
        wiz.add_step("aid", "ADF AID (Tag 84) [Hex, SKIP for DF/EF]:", default="SKIP")
        wiz.add_step("c6", "PIN Status Template DO (Tag C6) [Hex, SKIP for EF]:", default="SKIP")
        wiz.add_step("sfi", "Short File Identifier [Hex, SKIP for DF/None]:", default="SKIP")
        wiz.add_step("reclen", "Record Length [Hex, SKIP for DF/Transparent]:", default="SKIP")
        wiz.add_step("numrec", "Number of Records [Hex, SKIP for DF/Transparent]:", default="SKIP")
        wiz.add_step("prop", "Proprietary Info (Tag A5) [Hex, SKIP to omit]:", default="SKIP")

        res = wiz.run()
        type_choice = res.get("type")
        full_path = res.get("path").upper()
        sec_attr = res.get("sec").upper()

        is_path_short = False
        if len(full_path) < 4:
            is_path_short = True

        is_path_odd = False
        if len(full_path) % 4 != 0:
            is_path_odd = True

        if is_path_short:
            return {}

        if is_path_odd:
            return {}

        fid = full_path[-4:]
        parent_path = full_path[:-4]

        tag_83 = f"8302{fid}"
        tag_8a = "8A0105"

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

            f_size = res.get("size")
            is_size_empty = False
            if len(f_size) == 0:
                is_size_empty = True

            if is_size_empty:
                return {}

            f_size_int = int(f_size, 16)
            f_size_hex = f"{f_size_int:04X}"
            size_len = len(f_size_hex) // 2
            tag_80_81 = f"81{size_len:02X}{f_size_hex}"

            aid_input = res.get("aid")
            has_aid = False
            if aid_input != "SKIP":
                has_aid = True

            if has_aid:
                aid_len = len(aid_input) // 2
                tag_84 = f"84{aid_len:02X}{aid_input}"

            c6_attr = res.get("c6")
            is_c6_empty = False
            if c6_attr == "SKIP":
                is_c6_empty = True

            if is_c6_empty:
                return {}

            tag_c6 = c6_attr

        is_ef = False
        if is_transparent:
            is_ef = True

        if is_linear:
            is_ef = True

        if is_ef:
            sfi_input = res.get("sfi")
            is_sfi_empty = False
            if sfi_input == "SKIP":
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

            f_size = res.get("size")
            is_size_empty = False
            if len(f_size) == 0:
                is_size_empty = True

            if is_size_empty:
                return {}

            f_size_int = int(f_size, 16)
            f_size_hex = f"{f_size_int:04X}"
            size_len = len(f_size_hex) // 2
            tag_80_81 = f"80{size_len:02X}{f_size_hex}"

        if is_linear:
            rec_len = res.get("reclen")
            num_rec = res.get("numrec")

            is_rec_empty = False
            if rec_len == "SKIP":
                is_rec_empty = True

            if num_rec == "SKIP":
                is_rec_empty = True

            if is_rec_empty:
                return {}

            rec_len_int = int(rec_len, 16)
            num_rec_int = int(num_rec, 16)

            tag_82 = f"82044221{rec_len_int:04X}"

            f_size_int = rec_len_int * num_rec_int
            size_hex = f"{f_size_int:04X}"
            size_len = len(size_hex) // 2
            tag_80_81 = f"80{size_len:02X}{size_hex}"

        tag_a5 = ""
        prop_info = res.get("prop")
        has_prop = False
        if prop_info != "SKIP":
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
    def _select_path(shell, target: str) -> str:
        is_long = False
        if len(target) > 4:
            is_long = True

        if is_long:
            parent_path = target[:-4]
            target_fid = target[-4:]

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

            return target_fid

        return target

    @staticmethod
    def run_fs_admin_wizard(shell) -> None:
        wiz = InteractiveWizard("ETSI File System Administration", Config.Colors)
        wiz.add_step("action", "Operation [1=ACTIVATE, 2=DEACT, 3=SUSPEND, 4=SEARCH, 5=CREATE, 6=DELETE, 7=TERM DF, 8=TERM EF, 9=RESIZE]:", default="1")
        wiz.add_step("target", "Target FID/Path [SKIP for current/Suspend/Create]:", default="SKIP")
        wiz.add_step("search", "Search string [Hex, for SEARCH]:", default="SKIP")
        wiz.add_step("create", "Creation Mode [1=Raw FCP, 2=Builder, SKIP for non-CREATE]:", default="SKIP")
        wiz.add_step("raw_fcp", "Raw FCP Template [Hex, for mode 1]:", default="SKIP")
        wiz.add_step("parent", "Parent Path to select [Hex, SKIP for current]:", default="SKIP")
        wiz.add_step("resize83", "Target FID for Resize (Tag 83) [Hex, SKIP for non-RESIZE]:", default="SKIP")
        wiz.add_step("resize80", "New File Size (Tag 80) [Hex, SKIP for non-RESIZE]:", default="SKIP")
        wiz.add_step("resize81", "New Total Size (Tag 81) [Hex, SKIP for non-RESIZE]:", default="SKIP")
        
        res = wiz.run()
        choice = res.get("action")
        raw_target = res.get("target")

        target = ""
        is_target_skip = False
        if raw_target != "SKIP":
            is_target_skip = True
            
        if is_target_skip:
            target = ShellInteractiveWizards._select_path(shell, raw_target)
            
        is_error = False
        if target == "ERROR":
            is_error = True
            
        if is_error:
            return

        is_one = False
        if choice == '1':
            is_one = True
            
        if is_one:
            shell.fs_ctrl.activate_file(target)
        
        is_two = False
        if choice == '2':
            is_two = True
            
        if is_two:
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
            has_target = False
            if len(target) > 0:
                has_target = True
                
            if has_target:
                print(f"[*] Selecting Target EF: {target}")
                shell.fs_ctrl.select(target)
                
            search = res.get("search")
            shell.fs_ctrl.search_record(search)
            
        is_five = False
        if choice == '5':
            is_five = True
            
        if is_five:
            create_choice = res.get("create")
            
            is_raw = False
            if create_choice == '1':
                is_raw = True
                
            if is_raw:
                parent_path = res.get("parent")
                has_parent = False
                if parent_path != "SKIP":
                    has_parent = True
                    
                if has_parent:
                    print(f"[*] Selecting Parent Path: {parent_path}")
                    shell.fs_ctrl.select(parent_path)
                    
                data = res.get("raw_fcp")
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
                        ans_wiz = InteractiveWizard("EF Initialization", Config.Colors)
                        ans_wiz.add_step("upd", "Update data? [y/N]:", default=False, is_bool=True)
                        ans_res = ans_wiz.run()
                        
                        do_update = False
                        if ans_res.get("upd"):
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
                                input_wiz = InteractiveWizard("EF Data Update", Config.Colors)
                                input_wiz.add_step("t_data", f"Data for Transparent EF (Max {build_info['file_size']} bytes) [Hex]:", default="")
                                t_res = input_wiz.run()
                                t_data = t_res.get("t_data").upper()
                                
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
                                input_wiz = InteractiveWizard("EF Data Update", Config.Colors)
                                input_wiz.add_step("rec", "Record Number to update [Hex, e.g. 01]:", default="01")
                                input_wiz.add_step("l_data", f"Data for Record (Max {build_info['rec_len']} bytes) [Hex]:", default="")
                                l_res = input_wiz.run()
                                
                                rec_num_str = l_res.get("rec").upper()
                                l_data = l_res.get("l_data").upper()
                                
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
            shell.fs_ctrl.delete_file(target)
            
        is_seven = False
        if choice == '7':
            is_seven = True
            
        if is_seven:
            shell.fs_ctrl.terminate_df(target)
            
        is_eight = False
        if choice == '8':
            is_eight = True
            
        if is_eight:
            shell.fs_ctrl.terminate_ef(target)
            
        is_nine = False
        if choice == '9':
            is_nine = True
            
        if is_nine:
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
                target_fid = res.get("resize83")
                
            tag_83 = f"8302{target_fid}"
            
            new_size_80 = res.get("resize80")
            tag_80 = ""
            has_80 = False
            if new_size_80 != "SKIP":
                has_80 = True
                
            if has_80:
                size_int = int(new_size_80, 16)
                size_hex = f"{size_int:04X}"
                size_len = len(size_hex) // 2
                tag_80 = f"80{size_len:02X}{size_hex}"
                
            new_size_81 = res.get("resize81")
            tag_81 = ""
            has_81 = False
            if new_size_81 != "SKIP":
                has_81 = True
                
            if has_81:
                size_int = int(new_size_81, 16)
                size_hex = f"{size_int:04X}"
                size_len = len(size_hex) // 2
                tag_81 = f"81{size_len:02X}{size_hex}"
                
            fcp_content = tag_83 + tag_80 + tag_81
            fcp_len = len(fcp_content) // 2
            fcp = f"62{fcp_len:02X}{fcp_content}"
            
            print(f"[*] Generated Resize FCP Template: {fcp}")
            shell.fs_ctrl.resize_file(fcp)