# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import sys
import os
import configparser
import atexit
import io
import re
import datetime
from typing import Dict, Optional

try:
    import readline
except ImportError:
    readline = None

from SCP03.config import Config
from SCP03.core.utils import HexUtils, TlvParser, StatusWordTranslator
from SCP03.core.decoders import ContentDecoder
from SCP03.transport.card import CardTransporter
from SCP03.logic.gp import GlobalPlatformManager
from SCP03.logic.fs import FileSystemController
from SCP03.logic.security import SecurityController
from SCP03.interface.guides import ShellGuides
from SCP03.interface.commands import CommandRegistry
from SCP03.interface.help_menu import HelpMenu
from SCP03.interface.wizards import InteractiveWizards

class ShellDispatcher:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self._load_config_file()
        self.aid_registry = self._load_aid_registry()
        self.aid_lookup = {bytes.fromhex(v): k for k, v in self.aid_registry.items()}
        
        self.debug_mode = False
        
        self.transport = None
        try:
            self.transport = CardTransporter()
            self._patch_transport()
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Critical: {e}{Config.Colors.ENDC}")

        self._initialize_controllers()
        self.prompt_str = ""
        self._update_prompt_state() 
        
        self.guide_topics = ['GP', 'ETSI', 'GSMA', 'INSTALL']

        self.command_map = CommandRegistry.build(self)
        self.commands = {k: v[0] for k, v in self.command_map.items()}
        
        self.hidden_commands = {'DEBUG', 'VERBOSE'}
        self.visible_commands = []
        for cmd in self.commands.keys():
            if cmd not in self.hidden_commands:
                self.visible_commands.append(cmd)
        
        self._setup_readline()

    def _patch_transport(self):
        """Monkey-patches the transport layer to log outgoing APDUs and decode SW responses."""
        from SCP03.core.utils import StatusWordTranslator
        
        if not self.transport:
            return
            
        if not hasattr(self.transport, '_original_transmit'):
            self.transport._original_transmit = self.transport.transmit
            
        def _verbose_transmit(cmd, silent=False):
            actual_silent = silent
            if self.debug_mode:
                actual_silent = False
                
                display_cmd = ""
                if isinstance(cmd, str):
                    display_cmd = cmd.upper()
                elif isinstance(cmd, bytes):
                    display_cmd = cmd.hex().upper()
                elif isinstance(cmd, bytearray):
                    display_cmd = cmd.hex().upper()
                elif isinstance(cmd, list):
                    display_cmd = bytes(cmd).hex().upper()
                else:
                    display_cmd = str(cmd)
                    
                print(f"{Config.Colors.YELLOW}[-->] {display_cmd}{Config.Colors.ENDC}")
                
            data, sw1, sw2 = self.transport._original_transmit(cmd, silent=actual_silent)
            
            if not actual_silent:
                sw_str = StatusWordTranslator.translate(sw1, sw2)
                color = Config.Colors.GREEN
                if sw1 != 0x90 and sw1 != 0x61:
                    color = Config.Colors.FAIL
                print(f"      {color}=> {sw_str}{Config.Colors.ENDC}")
                
            return data, sw1, sw2
            
        self.transport.transmit = _verbose_transmit

    def _handle_decode(self, arg_line: str):
        if not arg_line:
            print(f"{Config.Colors.FAIL}[-] Usage: DECODE <Hex>{Config.Colors.ENDC}")
            return
            
        hex_data = arg_line.replace(" ", "")
        
        try:
            data = bytes.fromhex(hex_data)
            parsed = TlvParser.parse(data)
            self.gp_ctrl.print_tlv_data(parsed)
        except ValueError:
            print(f"{Config.Colors.FAIL}[!] Invalid Hex string provided.{Config.Colors.ENDC}")
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Decode Error: {e}{Config.Colors.ENDC}")

    def _handle_dump_fs(self, arg_line: str = ""):
        target = "ALL"
        if arg_line:
            target = arg_line.strip()
            
        self.fs_ctrl.dump_fs(target)

    def _toggle_debug(self):
        self.debug_mode = not self.debug_mode
        state = "ON"
        if not self.debug_mode:
            state = "OFF"
            
        print(f"{Config.Colors.WARNING}[*] VERBOSE / DEBUG Mode is now {state}.{Config.Colors.ENDC}")

    def _setup_readline(self):
        if readline is None:
            return
            
        self.hist_file = os.path.join(os.path.expanduser("~"), ".yggdrasim_history")
        try:
            if os.path.exists(self.hist_file):
                readline.read_history_file(self.hist_file)
            readline.set_history_length(1000)
        except:
            pass
            
        atexit.register(self._save_history)
        readline.set_completer(self._completer)
        readline.set_completer_delims(' \t\n')
        
        if 'libedit' in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
            
        try:
            readline.parse_and_bind("set show-all-if-ambiguous on")
        except:
            pass

    def _save_history(self):
        if readline:
            try:
                readline.write_history_file(self.hist_file)
            except:
                pass

    def _completer(self, text, state):
        line_buffer = readline.get_line_buffer().lstrip()
        
        if ' ' not in line_buffer:
            options = []
            for cmd in self.visible_commands:
                if cmd.startswith(text.upper()):
                    options.append(cmd)
                    
            if state < len(options):
                if len(options) == 1:
                    return options[0] + " "
                return options[state]
        else:
            first_space_idx = line_buffer.index(' ')
            cmd = line_buffer[:first_space_idx].upper()
            arg_typed = text.upper()
            
            if cmd == 'GUIDE':
                options = []
                for topic in self.guide_topics:
                    if topic.startswith(arg_typed):
                        options.append(topic)
                        
                if state < len(options):
                    if len(options) == 1:
                        return options[0] + " "
                    return options[state]
                    
            elif cmd == 'UPDATE':
                options = []
                for sub in ['BINARY', 'RECORD']:
                    if sub.startswith(arg_typed):
                        options.append(sub)
                        
                if state < len(options):
                    if len(options) == 1:
                        return options[0] + " "
                    return options[state]

        return None

    def _handle_guide(self, arg_line: str = ""):
        topic = arg_line.strip().upper()
        
        if not topic:
            ShellGuides.print_guide("WIZARD")
            return
            
        if topic == "WIZARD":
            ShellGuides.print_guide("WIZARD")
            return
            
        if topic in self.guide_topics:
            ShellGuides.print_guide(topic)
        else:
            print(f"{Config.Colors.FAIL}[!] Unknown topic. Available: {', '.join(self.guide_topics)}{Config.Colors.ENDC}")

    def _handle_install_file(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 1:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-INSTALL <cap/ijc> [Privileges] [Params] [AppletAID] [ModuleAID]{Config.Colors.ENDC}")
            return
            
        f = parts[0]
        
        p = "00"
        if len(parts) > 1:
            p = parts[1]
            
        par = "C900"
        if len(parts) > 2:
            par = parts[2]
            
        app_aid = None
        if len(parts) > 3:
            app_aid = parts[3]
            
        mod_aid = None
        if len(parts) > 4:
            mod_aid = parts[4]
            
        self.gp_ctrl.install_cap_file(f, privileges=p, install_params=par, target_app_aid=app_aid, target_module_aid=mod_aid, instantiate=True)

    def _handle_install_wizard(self, arg: str = "") -> None:
        target_aid = "A000000151000000"
        
        has_config = False
        if hasattr(self, 'config'):
            has_config = True
            
        if has_config:
            has_keys = False
            if 'KEYS' in self.config:
                has_keys = True
                
            if has_keys:
                has_aid_key = False
                if 'aid' in self.config['KEYS']:
                    has_aid_key = True
                    
                if has_aid_key:
                    target_aid = self.config['KEYS']['aid']

        active_ctrl = None
        
        has_tp = False
        if hasattr(self, 'tp'):
            has_tp = True
            
        if has_tp:
            active_ctrl = self.tp
            
        is_ctrl_missing = False
        if active_ctrl is None:
            is_ctrl_missing = True
            
        if is_ctrl_missing:
            has_gp_ctrl = False
            if hasattr(self, 'gp_ctrl'):
                has_gp_ctrl = True
                
            if has_gp_ctrl:
                active_ctrl = self.gp_ctrl
                
        is_ctrl_still_missing = False
        if active_ctrl is None:
            is_ctrl_still_missing = True
            
        if is_ctrl_still_missing:
            print("[-] Error: No active transport controller found in shell.")
            return

        InteractiveWizards.run_wizard_menu(active_ctrl, target_aid)

    def _handle_install_app(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 2:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-APP <PkgAID> <AppAID> [ModAID] [Priv] [Params]{Config.Colors.ENDC}")
            return
            
        pkg = parts[0]
        app = parts[1]
        
        mod = app
        if len(parts) > 2:
            mod = parts[2]
            
        priv = "00"
        if len(parts) > 3:
            priv = parts[3]
            
        param = "C900"
        if len(parts) > 4:
            param = parts[4]
            
        self.gp_ctrl.install_app(pkg, app, mod, priv, param, make_selectable=True)

    def _handle_install_registry(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 1:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-REGISTRY <AID> [Priv] [Params]{Config.Colors.ENDC}")
            return
            
        aid = parts[0]
        
        priv = "00"
        if len(parts) > 1:
            priv = parts[1]
            
        param = ""
        if len(parts) > 2:
            param = parts[2]
            
        self.gp_ctrl.install_registry_update(aid, priv, param)

    def _handle_store_data(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 1:
            print(f"{Config.Colors.FAIL}Usage: STORE-DATA <HexData> [P1] [P2]{Config.Colors.ENDC}")
            return
            
        data = parts[0]
        
        p1 = None
        if len(parts) > 1:
            p1 = int(parts[1], 16)
            
        p2 = None
        if len(parts) > 2:
            p2 = int(parts[2], 16)
            
        self.gp_ctrl.store_data(data, p1, p2)

    def _update_prompt_state(self):
        is_auth = False
        if self.transport:
            if self.transport.session:
                if self.transport.session.is_authenticated:
                    is_auth = True
        
        if not is_auth:
            self.prompt_str = f"\n{Config.Colors.CYAN}[APDU] > {Config.Colors.ENDC}"
        else:
            current_aid = self.gp_ctrl.target_aid 
            name = self.aid_lookup.get(current_aid)
            
            display = current_aid.hex().upper()
            if name:
                display = name
                
            self.prompt_str = f"\n{Config.Colors.GREEN}[{display}] > {Config.Colors.ENDC}"

    def _handle_auth(self):
        if self.gp_ctrl.authenticate():
            self._update_prompt_state()

    def _handle_logout(self):
        self.logout()
        self._update_prompt_state()

    def _resolve_mixed_aid(self, arg: str) -> str:
        if not arg:
            return ""
            
        clean = arg.strip().upper()
        if clean in self.aid_registry:
            print(f"{Config.Colors.CYAN}[*] Resolved '{clean}' -> {self.aid_registry[clean]}{Config.Colors.ENDC}")
            return self.aid_registry[clean]
            
        return arg
    
    def _handle_install_selectable(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 1:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-SELECTABLE <AID> [Privileges]{Config.Colors.ENDC}")
            return
            
        aid = parts[0]
        
        privs = "00"
        if len(parts) > 1:
            privs = parts[1]
            
        self.gp_ctrl.install_make_selectable(aid, privs)

    def _handle_install_extradition(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 2:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-EXTRADITION <App_AID> <SD_AID>{Config.Colors.ENDC}")
            return
            
        self.gp_ctrl.install_extradition(parts[0], parts[1])

    def _handle_keys(self, arg: Optional[str] = None):
        target = None
        if arg:
            target = self._resolve_mixed_aid(arg)
            
        self.gp_ctrl.get_keys_info(target_aid_hex=target)

    def _handle_reset(self):
        print(f"{Config.Colors.WARNING}[*] Resetting card...{Config.Colors.ENDC}")
        was_authenticated = False
        
        if self.transport.session:
            if self.transport.session.is_authenticated:
                was_authenticated = True
                print(f"{Config.Colors.CYAN}[*] Secure Session is active. Will auto-restore.{Config.Colors.ENDC}")
        
        if self.transport.reset():
            if self.transport.session:
                self.transport.session.is_authenticated = False
                self.transport.session.chaining_value = b'\x00' * 16
            
            print(f"{Config.Colors.GREEN}[+] Reset Successful.{Config.Colors.ENDC}")
            
            if was_authenticated: 
                if self.gp_ctrl.authenticate():
                    self._update_prompt_state()
            else:
                self._update_prompt_state()
        else:
            print(f"{Config.Colors.FAIL}[-] Card Reset Failed.{Config.Colors.ENDC}")

    def _handle_update(self, arg_line: str):
        parts = arg_line.strip().split()
        if not parts:
            print(f"{Config.Colors.FAIL}[-] Usage: UPDATE BINARY [Hex] or UPDATE RECORD [Num] [Hex]{Config.Colors.ENDC}")
            return

        sub_cmd = parts[0].upper()

        if sub_cmd == "BINARY":
            if len(parts) < 2:
                print(f"{Config.Colors.FAIL}[-] Usage: UPDATE BINARY [Hex]{Config.Colors.ENDC}")
                return
            hex_val = "".join(parts[1:])
            self.fs_ctrl.update_binary(hex_val)

        elif sub_cmd == "RECORD":
            if len(parts) < 3:
                print(f"{Config.Colors.FAIL}[-] Usage: UPDATE RECORD [Num] [Hex]{Config.Colors.ENDC}")
                return
            rec_str = parts[1]
            hex_val = "".join(parts[2:])
            self.fs_ctrl.update_record(rec_str, hex_val)
        else:
            hex_val = "".join(parts)
            self.fs_ctrl.update_binary(hex_val)

    def _print_help(self):
        HelpMenu.print_help()

    def run_script(self, arg_line: str):
        parts = arg_line.split()
        if not parts:
            print(f"{Config.Colors.FAIL}[!] Usage: RUN <script_file> [output.yaml]{Config.Colors.ENDC}")
            return

        filename = parts[0]
        
        yaml_out = None
        if len(parts) > 1:
            yaml_out = parts[1]
        
        if not os.path.exists(filename):
            print(f"{Config.Colors.FAIL}[!] Script not found: {filename}{Config.Colors.ENDC}")
            return

        print(f"{Config.Colors.CYAN}[*] Running script: {filename}{Config.Colors.ENDC}")
        if yaml_out:
            print(f"{Config.Colors.CYAN}[*] Recording output to: {yaml_out}{Config.Colors.ENDC}")

        results = []

        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                if line.startswith('#'):
                    continue
                
                print(f"\n{Config.Colors.YELLOW}[SCRIPT:{i+1}] > {line}{Config.Colors.ENDC}")
                
                captured_output = ""
                if yaml_out:
                    old_stdout = sys.stdout
                    sys.stdout = mystdout = io.StringIO()
                    try:
                        self._exec_line(line)
                    except Exception as e:
                        print(f"Error: {e}")
                    finally:
                        sys.stdout = old_stdout
                        captured_output = mystdout.getvalue()
                        print(captured_output, end="") 
                else:
                    self._exec_line(line)

                if yaml_out:
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    clean_text = ansi_escape.sub('', captured_output).strip()
                    results.append({'command': line, 'output': clean_text})

        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Script Error: {e}{Config.Colors.ENDC}")

        if yaml_out:
            if results:
                try:
                    with open(yaml_out, 'w') as f:
                        f.write(f"# YggdraSIM Script Report\n")
                        f.write(f"# Date: {datetime.datetime.now()}\n")
                        f.write(f"# Script: {filename}\n\n")
                        f.write("steps:\n")
                        for step in results:
                            f.write(f"  - command: \"{step['command']}\"\n")
                            f.write("    output: |\n")
                            for out_line in step['output'].split('\n'):
                                f.write(f"      {out_line}\n")
                    print(f"{Config.Colors.GREEN}[+] Report saved to {yaml_out}{Config.Colors.ENDC}")
                except Exception as e:
                    print(f"{Config.Colors.FAIL}[!] Failed to write YAML: {e}{Config.Colors.ENDC}")

    def _exec_line(self, line: str):
        if not line:
            return
        if line.startswith('#'):
            return
            
        parts = line.split(None, 1)
        cmd = parts[0].upper()
        
        arg = ""
        if len(parts) > 1:
            arg = parts[1]

        if cmd in self.commands:
            args_required, args_optional = CommandRegistry.get_arg_requirements()
            try:
                if cmd in args_required:
                    if not arg: 
                        print(f"{Config.Colors.WARNING}[!] Argument required for {cmd}{Config.Colors.ENDC}")
                    else: 
                        self.commands[cmd](arg)
                elif cmd in args_optional:
                    if arg: 
                        self.commands[cmd](arg)
                    else: 
                        self.commands[cmd]()
                else: 
                    self.commands[cmd]()
            except Exception as e: 
                print(f"{Config.Colors.FAIL}[!] Command Execution Error: {e}{Config.Colors.ENDC}")
        elif len(cmd) >= 4 and all(c in '0123456789ABCDEFabcdef' for c in cmd):
            if self.transport:
                apdu_bytes = HexUtils.to_bytes(line)
                data, sw1, sw2 = self.transport.transmit(line, silent=False)
                if sw1 == 0x90 or sw1 == 0x61: 
                    self._sync_manual_command(apdu_bytes, data)
            else: 
                print("No card reader connected.")
        else: 
            print(f"{Config.Colors.FAIL}Unknown command: {cmd}{Config.Colors.ENDC}")

    def _sync_manual_command(self, apdu: bytes, data: bytes):
        if len(apdu) < 4:
            return
            
        ins = apdu[1]
        
        if ins == 0xA4:
            selected_hex = None
            if len(apdu) > 5:
                lc = apdu[4]
                if len(apdu) >= 5 + lc:
                    selected_hex = apdu[5 : 5+lc].hex().upper()
                    self.fs_ctrl.current_fid = selected_hex
            if data:
                self.fs_ctrl._parse_fcp_internal(data, selected_hex)
                self.fs_ctrl.print_fcp_info()
        
        elif ins == 0xB0 and data:
            decoded = ContentDecoder.decode(self.fs_ctrl.current_fid, data.hex())
            if decoded:
                print(f"{Config.Colors.GREEN}{decoded}{Config.Colors.ENDC}")

        elif ins == 0xB2 and data:
            decoded = ContentDecoder.decode(self.fs_ctrl.current_fid, data.hex())
            if decoded:
                if "None" not in decoded:
                    for line in decoded.strip().split('\n'):
                        print(f"          | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")

        elif ins == 0xCA and data:
            try:
                parsed = TlvParser.parse(data)
                self.gp_ctrl.print_tlv_data(parsed)
            except:
                pass

    def _print_card_info(self):
        print(f"\n{Config.Colors.HEADER}=== CARD INFO ==={Config.Colors.ENDC}")
        if not self.transport: 
            print(f"{Config.Colors.FAIL}[-] No reader connected.{Config.Colors.ENDC}")
            return
        
        reset_ok = self.transport.reset()
        if reset_ok:
            try: 
                atr = self.transport.connection.getATR()
            except Exception: 
                pass
                
        if reset_ok == False: 
            print(f"{Config.Colors.FAIL}[-] Card Reset Failed.{Config.Colors.ENDC}")
            return
            
        iccid = "Unknown"
        self.transport.transmit("00A40004023F00", silent=True)
        self.transport.transmit("00A40004022FE2", silent=True)
        data, sw1, sw2 = self.transport.transmit("00B000000A", silent=True)
        
        if sw1 == 0x90:
            def swap_nibbles(s):
                res = []
                for i in range(0, len(s), 2):
                    if i+1 < len(s): 
                        res.append(s[i+1] + s[i])
                    else: 
                        res.append(s[i])
                return "".join(res).replace('F', '')
            iccid = swap_nibbles(data.hex().upper())
            
        print(f"{Config.Colors.BOLD}ICCID :{Config.Colors.ENDC} {iccid}")
        
        eid = None
        std = "Legacy UICC"
        
        ecasd_aid = "A0000005591010FFFFFFFF8900000200"
        isdr_aid = "A0000005591010FFFFFFFF8900000100"
        
        is_sgp22_confirmed = False
        res_sel, sw1_sel, sw2_sel = self.transport.transmit(f"00A4040010{ecasd_aid}", silent=True)
        
        valid_ecasd = False
        if sw1_sel == 0x90:
            valid_ecasd = True
        if sw1_sel == 0x61:
            valid_ecasd = True
            
        if valid_ecasd:
            res_ca, sw1_ca, sw2_ca = self.transport.transmit("00CA005A00", silent=True)
            if sw1_ca == 0x90:
                eid = res_ca.hex().upper()
                try:
                    from SCP03.core.utils import TlvParser
                    parsed = TlvParser.parse(res_ca)
                    if 0x5A in parsed:
                        eid = parsed[0x5A].hex().upper()
                except Exception:
                    pass

            payload = "BF3E035C015A"
            res, sw1_e2, sw2_e2 = self.transport.transmit(f"80E2910006{payload}", silent=True)
            
            if sw1_e2 == 0x90:
                if b'\x5A' in res: 
                    std = f"{Config.Colors.GREEN}SGP.22/32 (Consumer/IoT){Config.Colors.ENDC}"
                    is_sgp22_confirmed = True
            if sw1_e2 == 0x69:
                if sw2_e2 == 0x82: 
                    std = f"{Config.Colors.GREEN}SGP.22/32 (Consumer/IoT){Config.Colors.ENDC}"
                    is_sgp22_confirmed = True
                    
        if is_sgp22_confirmed == False:
            res_sel_m2m, sw1_m2m, sw2_m2m = self.transport.transmit(f"00A4040010{isdr_aid}", silent=True)
            
            valid_isdr = False
            if sw1_m2m == 0x90:
                valid_isdr = True
            if sw1_m2m == 0x61:
                valid_isdr = True
                
            if valid_isdr:
                std = f"{Config.Colors.BLUE}SGP.02 (M2M){Config.Colors.ENDC}"
                
                is_eid_missing = False
                if eid is None:
                    is_eid_missing = True
                    
                if is_eid_missing:
                    res_ca, sw1_ca, sw2_ca = self.transport.transmit("80CA005A00", silent=True)
                    
                    ca_success = False
                    if sw1_ca == 0x90:
                        ca_success = True
                        
                    if ca_success == False:
                        res_ca, sw1_ca, sw2_ca = self.transport.transmit("00CA005A00", silent=True)
                        if sw1_ca == 0x90:
                            ca_success = True
                            
                    if ca_success:
                        eid = res_ca.hex().upper()
                        try:
                            from SCP03.core.utils import TlvParser
                            parsed = TlvParser.parse(res_ca)
                            if 0x5A in parsed:
                                eid = parsed[0x5A].hex().upper()
                        except Exception:
                            pass
        
        if eid: 
            print(f"{Config.Colors.BOLD}eID   :{Config.Colors.ENDC} {eid}")
            
        print(f"{Config.Colors.BOLD}Spec  :{Config.Colors.ENDC} {std}")
        self.transport.reset()
        self.fs_ctrl.current_fid = "3F00"
        print("="*40 + "\n")

    def _load_config_file(self):
        import os
        
        file_exists = False
        if os.path.exists(Config.INI_FILE):
            file_exists = True
            
        if file_exists:
            self.config.read(Config.INI_FILE)
            
        has_keys = False
        if 'KEYS' in self.config:
            has_keys = True
            
        if has_keys == False:
            self.config['KEYS'] = {}
            
        has_kenc = False
        if 'kenc' in self.config['KEYS']:
            has_kenc = True
            
        if has_kenc:
            has_enc = False
            if 'enc' in self.config['KEYS']:
                has_enc = True
                
            if has_enc == False:
                self.config['KEYS']['enc'] = self.config['KEYS']['kenc']
                
        has_kmac = False
        if 'kmac' in self.config['KEYS']:
            has_kmac = True
            
        if has_kmac:
            has_mac = False
            if 'mac' in self.config['KEYS']:
                has_mac = True
                
            if has_mac == False:
                self.config['KEYS']['mac'] = self.config['KEYS']['kmac']

        has_kvn = False
        if 'kvn' in self.config['KEYS']:
            has_kvn = True
            
        if has_kvn:
            self.current_kvn = self.config['KEYS']['kvn']

    def _load_aid_registry(self) -> Dict[str, str]:
        registry = {}
        if os.path.exists(Config.AID_FILE):
            try:
                with open(Config.AID_FILE, 'r') as f:
                    for line in f:
                        line = line.split('#')[0].strip()
                        if ':' in line:
                            parts = line.split(':')
                            name = parts[0].strip().upper()
                            aid = parts[1].strip().upper()
                            registry[name] = aid
            except Exception as e:
                print(f"{Config.Colors.FAIL}[-] aid.txt error: {e}{Config.Colors.ENDC}")
        else:
            registry = {'ISDR': 'A0000005591010FFFFFFFF8900000100'}
            
        return registry

    def _initialize_controllers(self):
        keys = Config.DEFAULT_KEYS.copy()
        if 'KEYS' in self.config: 
            keys.update(dict(self.config['KEYS']))
            
        self.gp_ctrl = GlobalPlatformManager(self.transport, keys)
        self.fs_ctrl = FileSystemController(self.transport, self.aid_registry)
        self.sec_ctrl = SecurityController(self.transport, self.fs_ctrl)

    def _update_config(self, key: str, value: Optional[str]):
        if not value:
            print(f"{Config.Colors.FAIL}[-] Usage: SET-{key.upper()} <VALUE>{Config.Colors.ENDC}")
            return
            
        self.config['KEYS'][key] = value.strip().upper()
        
        try:
            with open(Config.INI_FILE, 'w') as configfile:
                self.config.write(configfile)
        except Exception as e:
            print(f"{Config.Colors.FAIL}[-] IO Error: {e}{Config.Colors.ENDC}")
            
        print(f"{Config.Colors.GREEN}[+] {key.upper()} updated.{Config.Colors.ENDC}")
        self._initialize_controllers()
        self._update_prompt_state()

    def _set_defaults(self):
        print(f"{Config.Colors.WARNING}[!] Resetting configuration to defaults...{Config.Colors.ENDC}")
        self.config['KEYS'] = Config.DEFAULT_KEYS.copy()
        
        if 'adm' not in self.config['KEYS']:
            self.config['KEYS']['adm'] = '0000000000000000'
        
        self._save_to_disk()
        self._initialize_controllers()
        print(f"{Config.Colors.GREEN}[+] Reset complete.{Config.Colors.ENDC}")
        self._update_prompt_state()

    def _save_to_disk(self):
        try:
            with open(Config.INI_FILE, 'w') as configfile:
                self.config.write(configfile)
        except Exception as e:
            print(f"{Config.Colors.FAIL}[-] IO Error: {e}{Config.Colors.ENDC}")

    def show_config(self):
        print(f"{Config.Colors.HEADER}--- Configuration (keys.ini) ---{Config.Colors.ENDC}")
        for section in self.config.sections():
            print(f"[{section}]")
            for key, value in self.config.items(section):
                print(f"  {key} = {value}")

    def list_aids(self):
        print(f"{Config.Colors.HEADER}--- AID Registry (aid.txt) ---{Config.Colors.ENDC}")
        if not self.aid_registry:
            print("  (Registry is empty)")
            return
            
        for name, aid in sorted(self.aid_registry.items()):
            print(f"  {name:<10} : {aid}")

    def _set_aid_alias(self, arg_line: Optional[str]):
        if not arg_line:
            print(f"{Config.Colors.FAIL}[-] Usage: SET-AID-ALIAS <NAME> <AID_HEX>{Config.Colors.ENDC}")
            return
            
        parts = arg_line.split()
        if len(parts) < 2:
            print(f"{Config.Colors.FAIL}[-] Usage: SET-AID-ALIAS <NAME> <AID_HEX>{Config.Colors.ENDC}")
            return
            
        name = parts[0].strip().upper()
        aid_hex = parts[1].strip().replace(' ', '').upper()
        
        self.aid_registry[name] = aid_hex
        self.aid_lookup = {bytes.fromhex(v): k for k, v in self.aid_registry.items()}
        try:
            with open(Config.AID_FILE, 'w') as f:
                for n, a in sorted(self.aid_registry.items()):
                    f.write(f"{n}:{a}\n")
            print(f"{Config.Colors.GREEN}[+] AID alias '{name}' saved.{Config.Colors.ENDC}")
        except Exception as e:
            print(f"{Config.Colors.FAIL}[-] Failed to save aid.txt: {e}{Config.Colors.ENDC}")

    def set_prompt(self, name: str):
        if name == "ISD-SECURE":
            self.prompt_str = f"\n[{Config.Colors.GREEN}ISD-SECURE{Config.Colors.ENDC}] > "
        else:
            self.prompt_str = f"\n[{Config.Colors.GREEN}{name}{Config.Colors.ENDC}] > "

    def logout(self):
        if not self.transport:
            print(f"{Config.Colors.WARNING}[!] No reader connected.{Config.Colors.ENDC}")
            return
            
        was_active = self.transport.logout()
        if was_active:
            print(f"{Config.Colors.GREEN}[+] Secure session closed.{Config.Colors.ENDC}")
        else:
            print(f"{Config.Colors.WARNING}[!] No active secure session.{Config.Colors.ENDC}")

    def _exit(self):
        if self.transport:
            self.transport.disconnect()
            
        self._save_history()
        sys.exit(0)

    def _run_scp80_tool(self):
        print(f"{Config.Colors.HEADER}=== Switching to SCP80 OTA Tool ==={Config.Colors.ENDC}")
        print(f"{Config.Colors.WARNING}[*] Releasing Card Reader...{Config.Colors.ENDC}")
        
        if self.transport:
            self.transport.disconnect()
            
        try:
            print(f"{Config.Colors.CYAN}[*] Starting SCP80 Module...{Config.Colors.ENDC}")
            import sys
            import importlib.util
            current_dir = os.path.dirname(os.path.abspath(__file__))
            scp80_root = os.path.abspath(os.path.join(current_dir, '../../SCP80'))
            
            if scp80_root not in sys.path:
                sys.path.insert(0, scp80_root)

            import main as scp80_entry
            scp80_entry.run_standalone()

        except SystemExit:
            pass 
        except ImportError as e:
            print(f"{Config.Colors.FAIL}[!] Import Error: {e}{Config.Colors.ENDC}")
        except AttributeError:
             print(f"{Config.Colors.FAIL}[!] Error: SCP80/main.py has no 'run_standalone()' function.{Config.Colors.ENDC}")
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] SCP80 Tool Crashed: {e}{Config.Colors.ENDC}")
        
        print(f"\n{Config.Colors.HEADER}=== Returning to SCP03 Shell ==={Config.Colors.ENDC}")
        print(f"{Config.Colors.WARNING}[*] Re-acquiring Card Reader...{Config.Colors.ENDC}")
        
        try:
            if scp80_root in sys.path:
                sys.path.remove(scp80_root)

            self.transport = CardTransporter()
            self._patch_transport()
            self.gp_ctrl.tp = self.transport
            self.fs_ctrl.tp = self.transport
            self.sec_ctrl.tp = self.transport
            
            self.transport.reset()
            print(f"{Config.Colors.GREEN}[+] Card Reader Re-connected.{Config.Colors.ENDC}")
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Failed to reconnect reader: {e}{Config.Colors.ENDC}")

        self._update_prompt_state()

    def do_dump_fs(self, arg: str = "") -> None:
        """
        Executes a live structured dump of the filesystem using tree scanning and decoders.
        Usage: dump_fs [optional_output_directory]
        """
        import os
        from pathlib import Path
        
        output_dir = arg.strip()
        
        is_empty = False
        if output_dir == "":
            is_empty = True
            
        if is_empty:
            prompt_msg = "Enter destination path (default: ~/Documents): "
            user_input = input(prompt_msg).strip()
            
            input_empty = False
            if user_input == "":
                input_empty = True
                
            if input_empty:
                default_docs = os.path.expanduser("~/Documents")
                output_dir = str(Path(default_docs) / "FS_DUMP")
                
            if input_empty == False:
                expanded_input = os.path.expanduser(user_input)
                output_dir = str(Path(expanded_input) / "FS_DUMP")
                
        if is_empty == False:
            expanded_arg = os.path.expanduser(output_dir)
            output_dir = str(Path(expanded_arg) / "FS_DUMP")
            
        try:
            self.fs_ctrl.dump_live_fs(output_dir)
        except Exception as error:
            print(f"[!] Command Execution Error: {error}")

    def run(self):
        print(f"{Config.Colors.HEADER}")
        print(r" __   __               _               ____ ___ __  __ ")
        print(r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print(r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print(r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print(r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print(r"      |___/  |___/                                     ")
        print(f"")
        print(f"=== YggdraSIM Shell ===")
        print(f"Created and maintained as Open Source under MPL.2.0 license.")
        print(f"Hampus Hellsberg 2026")
        print(f"{Config.Colors.ENDC}")
        
        has_transport = False
        if self.transport:
            has_transport = True
            
        if has_transport:
            try:
                self._print_card_info()
            except Exception as e:
                print(f"{Config.Colors.FAIL}[!] Startup Check Failed: {e}{Config.Colors.ENDC}")
        
        self._update_prompt_state()
        
        while True:
            try:
                line = input(self.prompt_str).strip()
                self._exec_line(line)
            except KeyboardInterrupt:
                print("\nType 'exit' to quit.")
            except Exception as e:
                print(f"{Config.Colors.FAIL}[-] Critical Error: {e}{Config.Colors.ENDC}")