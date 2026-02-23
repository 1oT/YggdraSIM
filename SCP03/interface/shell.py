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
import yaml
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
        
        self.guide_topics = ['GP', 'ETSI', 'GSMA', 'INSTALL', 'SECURITY', 'OTA']

        self.command_map = CommandRegistry.build(self)
        self.commands = {}
        for k, v in self.command_map.items():
            self.commands[k] = v[0]
        
        self.hidden_commands = {'DEBUG', 'VERBOSE'}
        self.visible_commands = []
        for cmd in self.commands.keys():
            is_hidden = False
            if cmd in self.hidden_commands:
                is_hidden = True
                
            if is_hidden == False:
                self.visible_commands.append(cmd)
        
        self._setup_readline()

    def _init_binder(self):
        from SCP03.interface.custom_binds import CommandBinder
        binds_file = Config.BINDS_FILE
        self.binder = CommandBinder(filepath=binds_file)

    def do_manage_binds(self, arg_line: str = ""):
        from SCP03.interface.custom_binds import manage_binds_wizard
        
        has_binder = False
        if hasattr(self, 'binder'):
            has_binder = True
            
        if has_binder:
            manage_binds_wizard(Config.Colors, self.binder)
            
        is_missing = False
        if has_binder == False:
            is_missing = True
            
        if is_missing:
            print(f"{Config.Colors.FAIL}[!] Binder engine not initialized.{Config.Colors.ENDC}")

    def _patch_transport(self):
        has_tp = False
        if self.transport:
            has_tp = True
            
        if has_tp == False:
            return
            
        has_orig = False
        if hasattr(self.transport, '_original_transmit'):
            has_orig = True
            
        if has_orig == False:
            self.transport._original_transmit = self.transport.transmit
            
        def _verbose_transmit(cmd, silent=False):
            actual_silent = silent
            is_debug = False
            if self.debug_mode:
                is_debug = True
                
            if is_debug:
                actual_silent = False
                
                display_cmd = ""
                is_str = False
                if isinstance(cmd, str):
                    is_str = True
                if is_str:
                    display_cmd = cmd.upper()
                    
                is_bytes = False
                if isinstance(cmd, bytes):
                    is_bytes = True
                if is_bytes:
                    display_cmd = cmd.hex().upper()
                    
                is_ba = False
                if isinstance(cmd, bytearray):
                    is_ba = True
                if is_ba:
                    display_cmd = cmd.hex().upper()
                    
                is_list = False
                if isinstance(cmd, list):
                    is_list = True
                if is_list:
                    display_cmd = bytes(cmd).hex().upper()
                    
                is_other = False
                if is_str == False:
                    if is_bytes == False:
                        if is_ba == False:
                            if is_list == False:
                                is_other = True
                if is_other:
                    display_cmd = str(cmd)
                    
                print(f"{Config.Colors.YELLOW}[-->] {display_cmd}{Config.Colors.ENDC}")
                
            data, sw1, sw2 = self.transport._original_transmit(cmd, silent=actual_silent)
            
            is_silent = False
            if actual_silent:
                is_silent = True
                
            if is_silent == False:
                sw_str = StatusWordTranslator.translate(sw1, sw2)
                color = Config.Colors.GREEN
                
                is_90 = False
                if sw1 == 0x90:
                    is_90 = True
                is_61 = False
                if sw1 == 0x61:
                    is_61 = True
                    
                is_ok = False
                if is_90:
                    is_ok = True
                if is_61:
                    is_ok = True
                    
                is_fail = False
                if is_ok == False:
                    is_fail = True
                    
                if is_fail:
                    color = Config.Colors.FAIL
                    
                print(f"      {color}=> {sw_str}{Config.Colors.ENDC}")
                
            return data, sw1, sw2
            
        self.transport.transmit = _verbose_transmit

    def _handle_decode(self, arg_line: str):
        is_empty = False
        if len(arg_line) == 0:
            is_empty = True
            
        if is_empty:
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
        has_arg = False
        if len(arg_line) > 0:
            has_arg = True
            
        if has_arg:
            target = arg_line.strip()
            
        self.fs_ctrl.dump_fs(target)

    def _toggle_debug(self):
        is_debug = False
        if self.debug_mode:
            is_debug = True
            
        if is_debug:
            self.debug_mode = False
            
        if is_debug == False:
            self.debug_mode = True
            
        state = "ON"
        is_off = False
        if self.debug_mode == False:
            is_off = True
            
        if is_off:
            state = "OFF"

        # Keep transport debug flag in sync for downstream decoders/helpers.
        has_tp = False
        if self.transport:
            has_tp = True
        if has_tp:
            try:
                self.transport.debug = self.debug_mode
            except Exception:
                pass
            
        print(f"{Config.Colors.WARNING}[*] VERBOSE / DEBUG Mode is now {state}.{Config.Colors.ENDC}")

    def _setup_readline(self):
        is_none = False
        if readline is None:
            is_none = True
            
        if is_none:
            return
            
        self.hist_file = os.path.join(os.path.expanduser("~"), ".yggdrasim_history")
        try:
            has_file = False
            if os.path.exists(self.hist_file):
                has_file = True
                
            if has_file:
                readline.read_history_file(self.hist_file)
            readline.set_history_length(1000)
        except:
            pass
            
        atexit.register(self._save_history)
        readline.set_completer(self._completer)
        readline.set_completer_delims(' \t\n')
        
        has_libedit = False
        if 'libedit' in readline.__doc__:
            has_libedit = True
            
        if has_libedit:
            readline.parse_and_bind("bind ^I rl_complete")
            
        is_gnu = False
        if has_libedit == False:
            is_gnu = True
            
        if is_gnu:
            readline.parse_and_bind("tab: complete")
            
        try:
            readline.parse_and_bind("set show-all-if-ambiguous on")
        except:
            pass

    def _save_history(self):
        has_readline = False
        if readline:
            has_readline = True
            
        if has_readline:
            try:
                readline.write_history_file(self.hist_file)
            except:
                pass

    def _completer(self, text, state):
        line_buffer = readline.get_line_buffer().lstrip()
        
        has_space = False
        if ' ' in line_buffer:
            has_space = True
            
        is_no_space = False
        if has_space == False:
            is_no_space = True
            
        if is_no_space:
            options = []
            for cmd in self.visible_commands:
                is_match = False
                if cmd.startswith(text.upper()):
                    is_match = True
                if is_match:
                    options.append(cmd)
                    
            is_valid_state = False
            if state < len(options):
                is_valid_state = True
                
            if is_valid_state:
                is_single = False
                if len(options) == 1:
                    is_single = True
                    
                if is_single:
                    return options[0] + " "
                    
                is_multi = False
                if is_single == False:
                    is_multi = True
                    
                if is_multi:
                    return options[state]
                    
        if has_space:
            first_space_idx = line_buffer.index(' ')
            cmd = line_buffer[:first_space_idx].upper()
            arg_typed = text.upper()
            
            is_select = False
            if cmd == 'SELECT':
                is_select = True
            if is_select:
                options = []
                try:
                    for path_name in self.fs_ctrl.fid_map.keys():
                        if path_name.upper().startswith(arg_typed):
                            options.append(path_name)
                    options.sort(key=lambda x: x.upper())
                except Exception:
                    pass
                if state < len(options):
                    return options[state] + " "
                return None

            is_guide = False
            if cmd == 'GUIDE':
                is_guide = True
                
            if is_guide:
                options = []
                for topic in self.guide_topics:
                    is_match = False
                    if topic.startswith(arg_typed):
                        is_match = True
                    if is_match:
                        options.append(topic)
                        
                is_valid_state = False
                if state < len(options):
                    is_valid_state = True
                    
                if is_valid_state:
                    is_single = False
                    if len(options) == 1:
                        is_single = True
                        
                    if is_single:
                        return options[0] + " "
                        
                    is_multi = False
                    if is_single == False:
                        is_multi = True
                        
                    if is_multi:
                        return options[state]
                        
            is_update = False
            if cmd == 'UPDATE':
                is_update = True
                
            if is_update:
                options = []
                for sub in ['BINARY', 'RECORD']:
                    is_match = False
                    if sub.startswith(arg_typed):
                        is_match = True
                    if is_match:
                        options.append(sub)
                        
                is_valid_state = False
                if state < len(options):
                    is_valid_state = True
                    
                if is_valid_state:
                    is_single = False
                    if len(options) == 1:
                        is_single = True
                        
                    if is_single:
                        return options[0] + " "
                        
                    is_multi = False
                    if is_single == False:
                        is_multi = True
                        
                    if is_multi:
                        return options[state]

        return None

    def _handle_guide(self, arg_line: str = ""):
        topic = arg_line.strip().upper()
        
        is_empty = False
        if len(topic) == 0:
            is_empty = True
            
        if is_empty:
            ShellGuides.print_guide("WIZARD")
            return
            
        is_wiz = False
        if topic == "WIZARD":
            is_wiz = True
            
        if is_wiz:
            ShellGuides.print_guide("WIZARD")
            return
            
        is_known = False
        if topic in self.guide_topics:
            is_known = True
            
        if is_known:
            ShellGuides.print_guide(topic)
            
        is_unknown = False
        if is_known == False:
            is_unknown = True
            
        if is_unknown:
            print(f"{Config.Colors.FAIL}[!] Unknown topic. Available: {', '.join(self.guide_topics)}{Config.Colors.ENDC}")

    def _handle_install_file(self, arg_line):
        parts = arg_line.split()
        is_short = False
        if len(parts) < 1:
            is_short = True
            
        if is_short:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-INSTALL <cap/ijc> [Privileges] [Params] [AppletAID] [ModuleAID]{Config.Colors.ENDC}")
            return
            
        f = parts[0]
        
        p = "00"
        has_p = False
        if len(parts) > 1:
            has_p = True
        if has_p:
            p = parts[1]
            
        par = "C900"
        has_par = False
        if len(parts) > 2:
            has_par = True
        if has_par:
            par = parts[2]
            
        app_aid = None
        has_app = False
        if len(parts) > 3:
            has_app = True
        if has_app:
            app_aid = parts[3]
            
        mod_aid = None
        has_mod = False
        if len(parts) > 4:
            has_mod = True
        if has_mod:
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
        is_short = False
        if len(parts) < 2:
            is_short = True
            
        if is_short:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-APP <PkgAID> <AppAID> [ModAID] [Priv] [Params]{Config.Colors.ENDC}")
            return
            
        pkg = parts[0]
        app = parts[1]
        
        mod = app
        has_mod = False
        if len(parts) > 2:
            has_mod = True
        if has_mod:
            mod = parts[2]
            
        priv = "00"
        has_priv = False
        if len(parts) > 3:
            has_priv = True
        if has_priv:
            priv = parts[3]
            
        param = "C900"
        has_param = False
        if len(parts) > 4:
            has_param = True
        if has_param:
            param = parts[4]
            
        self.gp_ctrl.install_app(pkg, app, mod, priv, param, make_selectable=True)

    def _handle_install_registry(self, arg_line):
        parts = arg_line.split()
        is_short = False
        if len(parts) < 1:
            is_short = True
            
        if is_short:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-REGISTRY <AID> [Priv] [Params]{Config.Colors.ENDC}")
            return
            
        aid = parts[0]
        
        priv = "00"
        has_priv = False
        if len(parts) > 1:
            has_priv = True
        if has_priv:
            priv = parts[1]
            
        param = ""
        has_param = False
        if len(parts) > 2:
            has_param = True
        if has_param:
            param = parts[2]
            
        self.gp_ctrl.install_registry_update(aid, priv, param)

    def _handle_store_data(self, arg_line):
        parts = arg_line.split()
        is_short = False
        if len(parts) < 1:
            is_short = True
            
        if is_short:
            print(f"{Config.Colors.FAIL}Usage: STORE-DATA <HexData> [P1] [P2]{Config.Colors.ENDC}")
            return
            
        data = parts[0]
        
        p1 = None
        has_p1 = False
        if len(parts) > 1:
            has_p1 = True
        if has_p1:
            p1 = int(parts[1], 16)
            
        p2 = None
        has_p2 = False
        if len(parts) > 2:
            has_p2 = True
        if has_p2:
            p2 = int(parts[2], 16)
            
        self.gp_ctrl.store_data(data, p1, p2)

    def _update_prompt_state(self):
        is_auth = False
        has_tp = False
        if self.transport:
            has_tp = True
            
        if has_tp:
            has_sess = False
            if self.transport.session:
                has_sess = True
                
            if has_sess:
                is_auth_flag = False
                if self.transport.session.is_authenticated:
                    is_auth_flag = True
                    
                if is_auth_flag:
                    is_auth = True
        
        is_not_auth = False
        if is_auth == False:
            is_not_auth = True
            
        if is_not_auth:
            self.prompt_str = f"\n{Config.Colors.CYAN}[APDU] > {Config.Colors.ENDC}"
            
        if is_auth:
            current_aid = self.gp_ctrl.target_aid 
            name = self.aid_lookup.get(current_aid)
            
            display = current_aid.hex().upper()
            
            has_name = False
            if name:
                has_name = True
                
            if has_name:
                display = name
                
            self.prompt_str = f"\n{Config.Colors.GREEN}[{display}] > {Config.Colors.ENDC}"

    def _handle_auth(self):
        is_success = False
        if self.gp_ctrl.authenticate():
            is_success = True
            
        if is_success:
            self._update_prompt_state()

    def _handle_logout(self):
        self.logout()
        self._update_prompt_state()

    def _resolve_mixed_aid(self, arg: str) -> str:
        is_empty = False
        if len(arg) == 0:
            is_empty = True
            
        if is_empty:
            return ""
            
        clean = arg.strip().upper()
        
        is_known = False
        if clean in self.aid_registry:
            is_known = True
            
        if is_known:
            print(f"{Config.Colors.CYAN}[*] Resolved '{clean}' -> {self.aid_registry[clean]}{Config.Colors.ENDC}")
            return self.aid_registry[clean]
            
        return arg
    
    def _handle_install_selectable(self, arg_line):
        parts = arg_line.split()
        is_short = False
        if len(parts) < 1:
            is_short = True
            
        if is_short:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-SELECTABLE <AID> [Privileges]{Config.Colors.ENDC}")
            return
            
        aid = parts[0]
        
        privs = "00"
        has_privs = False
        if len(parts) > 1:
            has_privs = True
            
        if has_privs:
            privs = parts[1]
            
        self.gp_ctrl.install_make_selectable(aid, privs)

    def _handle_install_extradition(self, arg_line):
        parts = arg_line.split()
        is_short = False
        if len(parts) < 2:
            is_short = True
            
        if is_short:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-EXTRADITION <App_AID> <SD_AID>{Config.Colors.ENDC}")
            return
            
        self.gp_ctrl.install_extradition(parts[0], parts[1])

    def _handle_keys(self, arg: Optional[str] = None):
        target = None
        has_arg = False
        if arg:
            has_arg = True
            
        if has_arg:
            target = self._resolve_mixed_aid(arg)
            
        self.gp_ctrl.get_keys_info(target_aid_hex=target)

    def _handle_export_euicc(self, arg: str = ""):
        """Single-command eUICC report: profiles, EuiccInfo, CPLC to YAML."""
        out_path = (arg.strip() if arg else "euicc_report.yaml").strip()
        if not out_path:
            out_path = "euicc_report.yaml"
        if not out_path.endswith(".yaml") and not out_path.endswith(".yml"):
            out_path = out_path + ".yaml"
        print(f"{Config.Colors.CYAN}[*] Generating eUICC report...{Config.Colors.ENDC}")
        try:
            report = self.gp_ctrl.sgp22.get_euicc_report()
            cplc_data, sw1, sw2 = self.gp_ctrl.get_cplc_data()
            if cplc_data and sw1 == 0x90:
                report["cplc_hex"] = cplc_data.hex().upper()
            report["generated"] = datetime.datetime.now().isoformat()
            with open(out_path, "w") as f:
                yaml.dump(report, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"{Config.Colors.GREEN}[+] Report written to {out_path}{Config.Colors.ENDC}")
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Export failed: {e}{Config.Colors.ENDC}")

    def _handle_arr(self, arg: str = ""):
        """Decode Application Reference Data (security attributes) for MF or USIM."""
        path = arg.strip() if arg else None
        self.fs_ctrl.get_arr(path=path)

    def _handle_derive_opc(self, arg: str):
        """Derive OPc from Ki and OP (3GPP TS 35.206). Usage: DERIVE-OPC <Ki_hex> <OP_hex>."""
        parts = arg.split()
        if len(parts) < 2:
            print(f"{Config.Colors.FAIL}[!] Usage: DERIVE-OPC <Ki_hex> <OP_hex> (32 hex chars each){Config.Colors.ENDC}")
            return
        try:
            opc = self.sec_ctrl.derive_opc(parts[0], parts[1])
            print(f"{Config.Colors.GREEN}OPc: {opc}{Config.Colors.ENDC}")
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] {e}{Config.Colors.ENDC}")

    def _handle_cert_info(self):
        """Decode ECASD/card certificates (subject, issuer, validity)."""
        from SCP03.core.decoders import AdvancedDecoders
        from SCP03.core.utils import TlvParser
        ECASD_AID = "A0000005591010FFFFFFFF8900000200"
        print(f"{Config.Colors.CYAN}[*] Selecting ECASD...{Config.Colors.ENDC}")
        self.transport.transmit(f"00A40400{len(ECASD_AID)//2:02X}{ECASD_AID}", silent=True)
        cert_tags = [("5A", "EID"), ("45", "CIN"), ("42", "IIN"), ("E0", "Key Info"), ("7F21", "Certificate")]
        print(f"{Config.Colors.HEADER}--- ECASD / Certificate Info ---{Config.Colors.ENDC}")
        for tag_hex, label in cert_tags:
            cmd = f"80CA{tag_hex}00"
            data, sw1, sw2 = self.transport.transmit(cmd, silent=True)
            if sw1 != 0x90 and sw1 != 0x61:
                print(f"  {label}: Not found ({sw1:02X}{sw2:02X})")
                continue
            if not data:
                print(f"  {label}: (empty)")
                continue
            raw = data
            try:
                parsed = TlvParser.parse(data)
                tag_int = int(tag_hex, 16)
                extracted = TlvParser.get_first(parsed, tag_int)
                if isinstance(extracted, bytes):
                    raw = extracted
            except Exception:
                pass

            debug_enabled = bool(self.debug_mode)
            if debug_enabled:
                try:
                    parsed_full = TlvParser.parse(data)
                    print(f"  {label}:")
                    self.gp_ctrl.sgp22._print_tlv_tree(parsed_full, indent=2, parent_tag=None)
                    continue
                except Exception:
                    print(f"  {label}: {raw.hex().upper()}")
                    continue

            if len(raw) >= 4 and raw[0] == 0x30:
                info = AdvancedDecoders.decode_cert_der(raw)
                if info:
                    print(f"  {label}:")
                    for k, v in info.items():
                        print(f"    {k}: {v}")
                else:
                    print(f"  {label}: {raw.hex().upper()[:64]}...")
            else:
                print(f"  {label}: {raw.hex().upper()}")

    def _handle_reset(self):
        print(f"{Config.Colors.WARNING}[*] Resetting card...{Config.Colors.ENDC}")
        was_authenticated = False
        
        has_tp = False
        if self.transport:
            has_tp = True
            
        if has_tp:
            has_sess = False
            if self.transport.session:
                has_sess = True
                
            if has_sess:
                is_auth_flag = False
                if self.transport.session.is_authenticated:
                    is_auth_flag = True
                    
                if is_auth_flag:
                    was_authenticated = True
                    print(f"{Config.Colors.CYAN}[*] Secure Session is active. Will auto-restore.{Config.Colors.ENDC}")
        
        is_reset_ok = False
        if self.transport.reset():
            is_reset_ok = True
            
        if is_reset_ok:
            has_sess = False
            if self.transport.session:
                has_sess = True
                
            if has_sess:
                self.transport.session.is_authenticated = False
                self.transport.session.chaining_value = b'\x00' * 16
            
            print(f"{Config.Colors.GREEN}[+] Reset Successful.{Config.Colors.ENDC}")
            
            if was_authenticated:
                is_auth_success = False
                if self.gp_ctrl.authenticate():
                    is_auth_success = True
                    
                if is_auth_success:
                    self._update_prompt_state()
                    
            is_not_auth = False
            if was_authenticated == False:
                is_not_auth = True
                
            if is_not_auth:
                self._update_prompt_state()
                
        is_fail = False
        if is_reset_ok == False:
            is_fail = True
            
        if is_fail:
            print(f"{Config.Colors.FAIL}[-] Card Reset Failed.{Config.Colors.ENDC}")

    def _handle_update(self, arg_line: str):
        parts = arg_line.strip().split()
        
        is_empty = False
        if len(parts) == 0:
            is_empty = True
            
        if is_empty:
            print(f"{Config.Colors.FAIL}[-] Usage: UPDATE BINARY [Hex] or UPDATE RECORD [Num] [Hex]{Config.Colors.ENDC}")
            return

        sub_cmd = parts[0].upper()

        is_binary = False
        if sub_cmd == "BINARY":
            is_binary = True
            
        if is_binary:
            is_short = False
            if len(parts) < 2:
                is_short = True
                
            if is_short:
                print(f"{Config.Colors.FAIL}[-] Usage: UPDATE BINARY [Hex]{Config.Colors.ENDC}")
                return
                
            hex_val = "".join(parts[1:])
            self.fs_ctrl.update_binary(hex_val)

        is_record = False
        if sub_cmd == "RECORD":
            is_record = True
            
        if is_record:
            is_short = False
            if len(parts) < 3:
                is_short = True
                
            if is_short:
                print(f"{Config.Colors.FAIL}[-] Usage: UPDATE RECORD [Num] [Hex]{Config.Colors.ENDC}")
                return
                
            rec_str = parts[1]
            hex_val = "".join(parts[2:])
            self.fs_ctrl.update_record(rec_str, hex_val)
            
        is_unknown = False
        if is_binary == False:
            if is_record == False:
                is_unknown = True
                
        if is_unknown:
            hex_val = "".join(parts)
            self.fs_ctrl.update_binary(hex_val)

    def _print_help(self):
        HelpMenu.print_help()

    def run_commands(self, cmd_line: str, yaml_out: Optional[str] = None):
        """
        Execute semicolon-separated commands (e.g. "AUTH-SD; LIST") without interactive loop.
        If yaml_out is set, capture each command output and write to YAML file.
        """
        commands = [c.strip() for c in cmd_line.split(";") if c.strip()]
        results = []
        for line in commands:
            if line.startswith("#"):
                continue
            if yaml_out:
                old_stdout = sys.stdout
                sys.stdout = mystdout = io.StringIO()
                try:
                    self._exec_line(line)
                except Exception as e:
                    print(f"Error: {e}")
                finally:
                    sys.stdout = old_stdout
                captured = mystdout.getvalue()
                ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
                clean = ansi_escape.sub("", captured).strip()
                results.append({"command": line, "output": clean})
                print(captured, end="")
            else:
                self._exec_line(line)
        if yaml_out and results:
            try:
                with open(yaml_out, "w") as f:
                    f.write("# YggdraSIM CLI Report\n")
                    f.write(f"# Date: {datetime.datetime.now()}\n\n")
                    f.write("steps:\n")
                    for step in results:
                        f.write(f"  - command: \"{step['command']}\"\n")
                        f.write("    output: |\n")
                        for ln in step["output"].split("\n"):
                            f.write(f"      {ln}\n")
            except Exception as e:
                print(f"{Config.Colors.FAIL}[!] Failed to write YAML: {e}{Config.Colors.ENDC}")

    def run_script(self, arg_line: str):
        parts = arg_line.split()
        
        is_empty = False
        if len(parts) == 0:
            is_empty = True
            
        if is_empty:
            print(f"{Config.Colors.FAIL}[!] Usage: RUN <script_file> [output.yaml]{Config.Colors.ENDC}")
            return

        filename = parts[0]
        
        yaml_out = None
        has_yaml = False
        if len(parts) > 1:
            has_yaml = True
            
        if has_yaml:
            yaml_out = parts[1]
        
        is_exists = False
        if os.path.exists(filename):
            is_exists = True
            
        if is_exists == False:
            print(f"{Config.Colors.FAIL}[!] Script not found: {filename}{Config.Colors.ENDC}")
            return

        print(f"{Config.Colors.CYAN}[*] Running script: {filename}{Config.Colors.ENDC}")
        
        has_out = False
        if yaml_out:
            has_out = True
            
        if has_out:
            print(f"{Config.Colors.CYAN}[*] Recording output to: {yaml_out}{Config.Colors.ENDC}")

        results = []

        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines):
                line = line.strip()
                
                is_line_empty = False
                if len(line) == 0:
                    is_line_empty = True
                    
                if is_line_empty:
                    continue
                    
                is_comment = False
                if line.startswith('#'):
                    is_comment = True
                    
                if is_comment:
                    continue
                
                print(f"\n{Config.Colors.YELLOW}[SCRIPT:{i+1}] > {line}{Config.Colors.ENDC}")
                
                captured_output = ""
                is_yaml_present = False
                if yaml_out:
                    is_yaml_present = True
                    
                if is_yaml_present:
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
                        
                is_no_yaml = False
                if is_yaml_present == False:
                    is_no_yaml = True
                    
                if is_no_yaml:
                    self._exec_line(line)

                if is_yaml_present:
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    clean_text = ansi_escape.sub('', captured_output).strip()
                    results.append({'command': line, 'output': clean_text})

        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Script Error: {e}{Config.Colors.ENDC}")

        is_write_yaml = False
        if yaml_out:
            is_write_yaml = True
            
        if is_write_yaml:
            has_res = False
            if len(results) > 0:
                has_res = True
                
            if has_res:
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
        is_empty = False
        if len(line) == 0:
            is_empty = True
            
        if is_empty:
            return
            
        is_comment = False
        if line.startswith('#'):
            is_comment = True
            
        if is_comment:
            return
            
        parts = line.split(None, 1)
        cmd = parts[0].upper()
        
        arg = ""
        has_arg = False
        if len(parts) > 1:
            has_arg = True
            
        if has_arg:
            arg = parts[1]

        is_known = False
        if cmd in self.commands:
            is_known = True
            
        if is_known:
            args_required, args_optional = CommandRegistry.get_arg_requirements()
            try:
                is_req = False
                if cmd in args_required:
                    is_req = True
                    
                if is_req:
                    is_arg_missing = False
                    if len(arg) == 0:
                        is_arg_missing = True
                        
                    if is_arg_missing:
                        print(f"{Config.Colors.WARNING}[!] Argument required for {cmd}{Config.Colors.ENDC}")
                        
                    has_argument = False
                    if is_arg_missing == False:
                        has_argument = True
                        
                    if has_argument:
                        self.commands[cmd](arg)
                        
                is_opt = False
                if cmd in args_optional:
                    is_opt = True
                    
                if is_opt:
                    has_argument = False
                    if len(arg) > 0:
                        has_argument = True
                        
                    if has_argument:
                        self.commands[cmd](arg)
                        
                    is_arg_missing = False
                    if has_argument == False:
                        is_arg_missing = True
                        
                    if is_arg_missing:
                        self.commands[cmd]()
                        
                is_none = False
                if is_req == False:
                    if is_opt == False:
                        is_none = True
                        
                if is_none:
                    self.commands[cmd]()
            except Exception as e: 
                print(f"{Config.Colors.FAIL}[!] Command Execution Error: {e}{Config.Colors.ENDC}")
                
        is_unknown = False
        if is_known == False:
            is_unknown = True
            
        if is_unknown:
            is_apdu = False
            is_long_enough = False
            if len(cmd) >= 4:
                is_long_enough = True
                
            if is_long_enough:
                is_valid_hex = True
                for c in cmd:
                    is_hex_char = False
                    if c in '0123456789ABCDEFabcdef':
                        is_hex_char = True
                    if is_hex_char == False:
                        is_valid_hex = False
                if is_valid_hex:
                    is_apdu = True
                    
            if is_apdu:
                has_tp = False
                if self.transport:
                    has_tp = True
                    
                if has_tp:
                    apdu_bytes = HexUtils.to_bytes(line)
                    data, sw1, sw2 = self.transport.transmit(line, silent=False)
                    
                    is_success = False
                    if sw1 == 0x90:
                        is_success = True
                    if sw1 == 0x61:
                        is_success = True
                        
                    if is_success:
                        self._sync_manual_command(apdu_bytes, data)
                        
                is_no_tp = False
                if has_tp == False:
                    is_no_tp = True
                    
                if is_no_tp:
                    print("No card reader connected.")
                    
            is_invalid = False
            if is_apdu == False:
                is_invalid = True
                
            if is_invalid:
                print(f"{Config.Colors.FAIL}Unknown command: {cmd}{Config.Colors.ENDC}")

    def _sync_manual_command(self, apdu: bytes, data: bytes):
        is_short = False
        if len(apdu) < 4:
            is_short = True
            
        if is_short:
            return
            
        ins = apdu[1]
        
        is_a4 = False
        if ins == 0xA4:
            is_a4 = True
            
        if is_a4:
            selected_hex = None
            has_len = False
            if len(apdu) > 5:
                has_len = True
                
            if has_len:
                lc = apdu[4]
                has_payload = False
                if len(apdu) >= 5 + lc:
                    has_payload = True
                    
                if has_payload:
                    selected_hex = apdu[5 : 5+lc].hex().upper()
                    self.fs_ctrl.current_fid = selected_hex
                    
            has_data = False
            if data:
                has_data = True
                
            if has_data:
                self.fs_ctrl._parse_fcp_internal(data, selected_hex)
                self.fs_ctrl.print_fcp_info()
        
        is_b0 = False
        if ins == 0xB0:
            is_b0 = True
            
        if is_b0:
            has_data = False
            if data:
                has_data = True
                
            if has_data:
                decoded = ContentDecoder.decode(self.fs_ctrl.current_fid, data.hex())
                has_decoded = False
                if decoded:
                    has_decoded = True
                    
                if has_decoded:
                    print(f"{Config.Colors.GREEN}{decoded}{Config.Colors.ENDC}")

        is_b2 = False
        if ins == 0xB2:
            is_b2 = True
            
        if is_b2:
            has_data = False
            if data:
                has_data = True
                
            if has_data:
                decoded = ContentDecoder.decode(self.fs_ctrl.current_fid, data.hex())
                has_decoded = False
                if decoded:
                    has_decoded = True
                    
                if has_decoded:
                    is_valid = False
                    if "None" not in decoded:
                        is_valid = True
                        
                    if is_valid:
                        for line in decoded.strip().split('\n'):
                            print(f"          | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")

        is_ca = False
        if ins == 0xCA:
            is_ca = True
            
        if is_ca:
            has_data = False
            if data:
                has_data = True
                
            if has_data:
                try:
                    parsed = TlvParser.parse(data)
                    self.gp_ctrl.print_tlv_data(parsed)
                except:
                    pass

    def _print_card_info(self):
        print(f"\n{Config.Colors.HEADER}=== CARD INFO ==={Config.Colors.ENDC}")
        has_tp = False
        if self.transport:
            has_tp = True
            
        is_no_tp = False
        if has_tp == False:
            is_no_tp = True
            
        if is_no_tp:
            print(f"{Config.Colors.FAIL}[-] No reader connected.{Config.Colors.ENDC}")
            return
        
        reset_ok = self.transport.reset()
        is_reset_ok = False
        if reset_ok:
            is_reset_ok = True
            
        if is_reset_ok:
            try: 
                atr = self.transport.connection.getATR()
            except Exception: 
                pass
                
        is_fail = False
        if is_reset_ok == False:
            is_fail = True
            
        if is_fail:
            print(f"{Config.Colors.FAIL}[-] Card Reset Failed.{Config.Colors.ENDC}")
            return
            
        iccid = "Unknown"
        self.transport.transmit("00A40004023F00", silent=True)
        self.transport.transmit("00A40004022FE2", silent=True)
        data, sw1, sw2 = self.transport.transmit("00B000000A", silent=True)
        
        is_success = False
        if sw1 == 0x90:
            is_success = True
            
        if is_success:
            def swap_nibbles(s):
                res = []
                for i in range(0, len(s), 2):
                    has_next = False
                    if i+1 < len(s):
                        has_next = True
                        
                    if has_next:
                        res.append(s[i+1] + s[i])
                        
                    is_last = False
                    if has_next == False:
                        is_last = True
                        
                    if is_last:
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
            
            is_ca_success = False
            if sw1_ca == 0x90:
                is_ca_success = True
                
            if is_ca_success:
                eid = res_ca.hex().upper()
                try:
                    from SCP03.core.utils import TlvParser
                    parsed = TlvParser.parse(res_ca)
                    has_5a = False
                    if 0x5A in parsed:
                        has_5a = True
                    if has_5a:
                        eid = parsed[0x5A].hex().upper()
                except Exception:
                    pass

            payload = "BF3E035C015A"
            res, sw1_e2, sw2_e2 = self.transport.transmit(f"80E2910006{payload}", silent=True)
            
            is_e2_90 = False
            if sw1_e2 == 0x90:
                is_e2_90 = True
                
            if is_e2_90:
                has_5a_byte = False
                if b'\x5A' in res:
                    has_5a_byte = True
                    
                if has_5a_byte:
                    std = f"{Config.Colors.GREEN}SGP.22/32 (Consumer/IoT){Config.Colors.ENDC}"
                    is_sgp22_confirmed = True
                    
            is_e2_69 = False
            if sw1_e2 == 0x69:
                is_e2_69 = True
                
            if is_e2_69:
                is_e2_82 = False
                if sw2_e2 == 0x82:
                    is_e2_82 = True
                    
                if is_e2_82:
                    std = f"{Config.Colors.GREEN}SGP.22/32 (Consumer/IoT){Config.Colors.ENDC}"
                    is_sgp22_confirmed = True
                    
        is_unconfirmed = False
        if is_sgp22_confirmed == False:
            is_unconfirmed = True
            
        if is_unconfirmed:
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
                        
                    is_ca_fail = False
                    if ca_success == False:
                        is_ca_fail = True
                        
                    if is_ca_fail:
                        res_ca, sw1_ca, sw2_ca = self.transport.transmit("00CA005A00", silent=True)
                        if sw1_ca == 0x90:
                            ca_success = True
                            
                    if ca_success:
                        eid = res_ca.hex().upper()
                        try:
                            from SCP03.core.utils import TlvParser
                            parsed = TlvParser.parse(res_ca)
                            has_5a_tag = False
                            if 0x5A in parsed:
                                has_5a_tag = True
                            if has_5a_tag:
                                eid = parsed[0x5A].hex().upper()
                        except Exception:
                            pass
        
        has_eid = False
        if eid:
            has_eid = True
            
        if has_eid:
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
            
        is_no_keys = False
        if has_keys == False:
            is_no_keys = True
            
        if is_no_keys:
            self.config['KEYS'] = {}
            
        has_kenc = False
        if 'kenc' in self.config['KEYS']:
            has_kenc = True
            
        if has_kenc:
            has_enc = False
            if 'enc' in self.config['KEYS']:
                has_enc = True
                
            is_no_enc = False
            if has_enc == False:
                is_no_enc = True
                
            if is_no_enc:
                self.config['KEYS']['enc'] = self.config['KEYS']['kenc']
                
        has_kmac = False
        if 'kmac' in self.config['KEYS']:
            has_kmac = True
            
        if has_kmac:
            has_mac = False
            if 'mac' in self.config['KEYS']:
                has_mac = True
                
            is_no_mac = False
            if has_mac == False:
                is_no_mac = True
                
            if is_no_mac:
                self.config['KEYS']['mac'] = self.config['KEYS']['kmac']

        has_kvn = False
        if 'kvn' in self.config['KEYS']:
            has_kvn = True
            
        if has_kvn:
            self.current_kvn = self.config['KEYS']['kvn']

    def _load_aid_registry(self) -> Dict[str, str]:
        registry = {}
        is_exists = False
        if os.path.exists(Config.AID_FILE):
            is_exists = True
            
        if is_exists:
            try:
                with open(Config.AID_FILE, 'r') as f:
                    for line in f:
                        line = line.split('#')[0].strip()
                        has_colon = False
                        if ':' in line:
                            has_colon = True
                            
                        if has_colon:
                            parts = line.split(':')
                            name = parts[0].strip().upper()
                            aid = parts[1].strip().upper()
                            registry[name] = aid
            except Exception as e:
                print(f"{Config.Colors.FAIL}[-] aid.txt error: {e}{Config.Colors.ENDC}")
                
        is_missing = False
        if is_exists == False:
            is_missing = True
            
        if is_missing:
            registry = {'ISDR': 'A0000005591010FFFFFFFF8900000100'}
            
        return registry

    def _initialize_controllers(self):
        keys = Config.DEFAULT_KEYS.copy()
        
        has_keys = False
        if 'KEYS' in self.config:
            has_keys = True
            
        if has_keys:
            keys.update(dict(self.config['KEYS']))
            
        self.gp_ctrl = GlobalPlatformManager(self.transport, keys)
        self.fs_ctrl = FileSystemController(self.transport, self.aid_registry)
        self.sec_ctrl = SecurityController(self.transport, self.fs_ctrl)

    def _update_config(self, key: str, value: Optional[str]):
        is_empty = False
        if not value:
            is_empty = True
            
        if is_empty:
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
        
        has_adm = False
        if 'adm' in self.config['KEYS']:
            has_adm = True
            
        is_no_adm = False
        if has_adm == False:
            is_no_adm = True
            
        if is_no_adm:
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
        
        has_items = False
        if self.aid_registry:
            has_items = True
            
        is_empty = False
        if has_items == False:
            is_empty = True
            
        if is_empty:
            print("  (Registry is empty)")
            return
            
        for name, aid in sorted(self.aid_registry.items()):
            print(f"  {name:<10} : {aid}")

    def _set_aid_alias(self, arg_line: Optional[str]):
        is_empty = False
        if not arg_line:
            is_empty = True
            
        if is_empty:
            print(f"{Config.Colors.FAIL}[-] Usage: SET-AID-ALIAS <NAME> <AID_HEX>{Config.Colors.ENDC}")
            return
            
        parts = arg_line.split()
        
        is_short = False
        if len(parts) < 2:
            is_short = True
            
        if is_short:
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
        is_isd = False
        if name == "ISD-SECURE":
            is_isd = True
            
        if is_isd:
            self.prompt_str = f"\n[{Config.Colors.GREEN}ISD-SECURE{Config.Colors.ENDC}] > "
            
        is_other = False
        if is_isd == False:
            is_other = True
            
        if is_other:
            self.prompt_str = f"\n[{Config.Colors.GREEN}{name}{Config.Colors.ENDC}] > "

    def logout(self):
        has_tp = False
        if self.transport:
            has_tp = True
            
        is_no_tp = False
        if has_tp == False:
            is_no_tp = True
            
        if is_no_tp:
            print(f"{Config.Colors.WARNING}[!] No reader connected.{Config.Colors.ENDC}")
            return
            
        was_active = self.transport.logout()
        
        is_active = False
        if was_active:
            is_active = True
            
        if is_active:
            print(f"{Config.Colors.GREEN}[+] Secure session closed.{Config.Colors.ENDC}")
            
        is_inactive = False
        if is_active == False:
            is_inactive = True
            
        if is_inactive:
            print(f"{Config.Colors.WARNING}[!] No active secure session.{Config.Colors.ENDC}")

    def _exit(self):
        has_tp = False
        if self.transport:
            has_tp = True
            
        if has_tp:
            self.transport.disconnect()
            
        self._save_history()
        sys.exit(0)

    def _run_scp80_tool(self):
        print(f"{Config.Colors.HEADER}=== Switching to SCP80 OTA Tool ==={Config.Colors.ENDC}")
        print(f"{Config.Colors.WARNING}[*] Releasing Card Reader...{Config.Colors.ENDC}")
        
        has_tp = False
        if self.transport:
            has_tp = True
            
        if has_tp:
            self.transport.disconnect()
            
        try:
            print(f"{Config.Colors.CYAN}[*] Starting SCP80 Module...{Config.Colors.ENDC}")
            import sys
            import os
            import importlib

            current_dir = os.path.dirname(os.path.abspath(__file__))
            scp80_root = os.path.abspath(os.path.join(current_dir, '../../SCP80'))
            
            is_missing = False
            if scp80_root not in sys.path:
                is_missing = True
                
            if is_missing:
                sys.path.insert(0, scp80_root)

            import main as scp80_main
            importlib.reload(scp80_main)
            
            scp80_main.run_standalone()

        except SystemExit:
            pass
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] SCP80 Switch Failed: {e}{Config.Colors.ENDC}")
        
        is_nt = False
        if os.name == 'nt':
            is_nt = True
            
        if is_nt:
            os.system('cls')
        
        is_posix = False
        if is_nt == False:
            is_posix = True
            
        if is_posix:
            os.system('clear')

        print(f"{Config.Colors.HEADER}")
        print(r" __   __               _               ____ ___ __  __ ")
        print(r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print(r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print(r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print(r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print(r"      |___/  |___/                                     ")
        print(r"             _    ____  __  __ ___ _   _ ")
        print(r"            / \  |  _ \|  \/  |_ _| \ | |")
        print(r"           / _ \ | | | | |\/| || ||  \| |")
        print(r"          / ___ \| |_| | |  | || || |\  |")
        print(r"         /_/   \_\____/|_|  |_|___|_| \_|")
        print(f"")
        print(f"=== YggdraSIM Administration Shell ===")
        print(f" [ GlobalPlatform | ETSI FS | SGP.22 eUICC | Telecom Auth ]")
        print(f" Created and maintained by Hampus Hellsberg")
        print(f"{Config.Colors.ENDC}")
        
        print(f"\n{Config.Colors.HEADER}=== Returning to SCP03 Shell ==={Config.Colors.ENDC}")
        print(f"{Config.Colors.WARNING}[*] Re-acquiring Card Reader...{Config.Colors.ENDC}")
        
        try:
            self.transport = CardTransporter()
            self._patch_transport()
            
            self.gp_ctrl.tp = self.transport
            self.fs_ctrl.tp = self.transport
            self.sec_ctrl.tp = self.transport
            
            self.transport.reset()
            print(f"{Config.Colors.GREEN}[+] Card Reader Re-connected.{Config.Colors.ENDC}")
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Failed to reconnect reader: {e}{Config.Colors.ENDC}")

        self._print_card_info() 
        self._update_prompt_state()

    def do_dump_fs(self, arg: str = "") -> None:
        import os
        from pathlib import Path
        
        output_dir = arg.strip()
        
        is_empty = False
        if len(output_dir) == 0:
            is_empty = True
            
        if is_empty:
            prompt_msg = "Enter destination path (default: ~/Documents): "
            user_input = input(prompt_msg).strip()
            
            input_empty = False
            if len(user_input) == 0:
                input_empty = True
                
            if input_empty:
                default_docs = os.path.expanduser("~/Documents")
                output_dir = str(Path(default_docs) / "FS_DUMP")
                
            has_input = False
            if input_empty == False:
                has_input = True
                
            if has_input:
                expanded_input = os.path.expanduser(user_input)
                output_dir = str(Path(expanded_input) / "FS_DUMP")
                
        has_arg = False
        if is_empty == False:
            has_arg = True
            
        if has_arg:
            expanded_arg = os.path.expanduser(output_dir)
            output_dir = str(Path(expanded_arg) / "FS_DUMP")
            
        try:
            self.fs_ctrl.dump_live_fs(output_dir)
        except Exception as error:
            print(f"[!] Command Execution Error: {error}")

    def run(self):
        self._init_binder()
        
        is_nt = False
        if os.name == 'nt':
            is_nt = True
            
        if is_nt:
            os.system('cls')
            
        is_posix = False
        if is_nt == False:
            is_posix = True
            
        if is_posix:
            os.system('clear')
            
        print(f"{Config.Colors.HEADER}")
        print(r" __   __               _               ____ ___ __  __ ")
        print(r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print(r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print(r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print(r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print(r"      |___/  |___/                                     ")
        print(r"             _    ____  __  __ ___ _   _ ")
        print(r"            / \  |  _ \|  \/  |_ _| \ | |")
        print(r"           / _ \ | | | | |\/| || ||  \| |")
        print(r"          / ___ \| |_| | |  | || || |\  |")
        print(r"         /_/   \_\____/|_|  |_|___|_| \_|")
        print(f"")
        print(f"=== YggdraSIM Administration Shell ===")
        print(f" [ GlobalPlatform | ETSI FS | SGP.22 eUICC | Telecom Auth ]")
        print(f" Created and maintained by Hampus Hellsberg")
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
        
        is_running = True
        while is_running:
            try:
                line = input(self.prompt_str).strip()
                
                is_empty = False
                if len(line) == 0:
                    is_empty = True
                    
                if is_empty:
                    continue
                    
                resolved_commands = self.binder.resolve(line)
                
                for cmd in resolved_commands:
                    is_modified = False
                    if cmd != line:
                        is_modified = True
                        
                    if is_modified:
                        print(f"{Config.Colors.CYAN}[*] Expanded Macro -> {cmd}{Config.Colors.ENDC}")
                        
                    self._exec_line(cmd)
                    
            except KeyboardInterrupt:
                print("\nType 'exit' to quit.")
            except Exception as e:
                print(f"{Config.Colors.FAIL}[-] Critical Error: {e}{Config.Colors.ENDC}")