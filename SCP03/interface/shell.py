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

    def _handle_put_key(self, arg: str) -> None:
        args = arg.split()
        if len(args) < 6:
            print("[-] Usage: PUT-KEY <OldKVN> <KeyID> <NewKVN> <ENC> <MAC> <DEK> [Algo]")
            return

        try:
            old_kvn = int(args[0], 16)
            key_id = int(args[1], 16)
            new_kvn = int(args[2], 16)
            keys = [args[3], args[4], args[5]]
            algo = args[6].upper() if len(args) == 7 else "AES"
            
            self._exec_put_key(old_kvn, key_id, new_kvn, keys, algo)
        except ValueError:
            print("[-] Error: Parameters must be hex bytes.")

    def _handle_put_key_rotate(self, arg: str) -> None:
        args = arg.split()
        if len(args) < 4:
            print("[-] Usage: PUT-KEY-ROTATE <NewKVN> <ENC> <MAC> <DEK> [Algo]")
            return

        # Resolve current KVN from memory or config
        kvn_val = getattr(self, 'current_kvn', None)
        if not kvn_val:
            if 'KEYS' in self.config and 'kvn' in self.config['KEYS']:
                kvn_val = self.config['KEYS']['kvn']

        if not kvn_val:
            print("[-] Error: Current KVN unknown. Use manual PUT-KEY or set-kvn first.")
            return

        try:
            old_kvn = int(str(kvn_val), 16)
            new_kvn = int(args[0], 16)
            keys = [args[1], args[2], args[3]]
            algo = args[4].upper() if len(args) == 5 else "AES"
            
            # Rotation usually targets KeyID 01
            self._exec_put_key(old_kvn, 1, new_kvn, keys, algo)
        except ValueError:
            print("[-] Error: Parameters must be hex bytes.")

    def _handle_put_key_new(self, arg: str) -> None:
        args = arg.split()
        if len(args) < 5:
            print("[-] Usage: PUT-KEY-NEW <KeyID> <NewKVN> <ENC> <MAC> <DEK> [Algo]")
            return

        try:
            key_id = int(args[0], 16)
            new_kvn = int(args[1], 16)
            keys = [args[2], args[3], args[4]]
            algo = args[5].upper() if len(args) == 6 else "AES"
            
            # New keys always use OldKVN 00 (Add mode)
            self._exec_put_key(0, key_id, new_kvn, keys, algo)
        except ValueError:
            print("[-] Error: Parameters must be hex bytes.")

    def _exec_put_key(self, old_kvn, key_id, new_kvn, keys, algo):
        key_type = 0x82 if algo in ["3DES", "DES"] else 0x88
        if algo.startswith("0X"):
            key_type = int(algo, 16)

        success = self.gp_ctrl.put_key(old_kvn, key_id, new_kvn, keys, key_type)
        if success:
            self._prompt_config_update(new_kvn, keys[0], keys[1], keys[2])


    def _prompt_config_update(self, new_kvn: int, enc: str, mac: str, dek: str) -> None:
        import configparser
        import os

        print()
        ans = input(f"Update {Config.INI_FILE} with these new keys? [Y/n]: ").strip().upper()

        do_update = False
        if ans == "Y":
            do_update = True
        if ans == "":
            do_update = True

        if do_update:
            kvn_str = f"{new_kvn:02X}"
            self.current_kvn = kvn_str
            
            config = configparser.ConfigParser()
            if os.path.exists(Config.INI_FILE):
                config.read(Config.INI_FILE)

            if 'KEYS' not in config:
                config['KEYS'] = {}

            # Save using harmonized nomenclature
            config['KEYS']['kvn'] = kvn_str
            config['KEYS']['enc'] = enc
            config['KEYS']['mac'] = mac
            config['KEYS']['dek'] = dek
            
            # Clean up legacy entries if they exist
            for legacy in ['kenc', 'kmac']:
                if legacy in config['KEYS']:
                    del config['KEYS'][legacy]

            with open(Config.INI_FILE, 'w') as f:
                config.write(f)

            print(f"[+] {Config.INI_FILE} updated. KVN is now {kvn_str}.")

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

    def _handle_enable(self, arg: str):
        if self.gp_ctrl.sgp22.enable_profile(self._resolve_mixed_aid(arg)):
            print(f"{Config.Colors.WARNING}[*] Performing automated card reset...{Config.Colors.ENDC}")
            self._handle_reset()

    def _handle_disable(self, arg: str):
        if self.gp_ctrl.sgp22.disable_profile(self._resolve_mixed_aid(arg)):
            print(f"{Config.Colors.WARNING}[*] Performing automated card reset...{Config.Colors.ENDC}")
            self._handle_reset()

    def _handle_delete_profile(self, arg: str):
        if self.gp_ctrl.sgp22.delete_profile(self._resolve_mixed_aid(arg)):
            print(f"{Config.Colors.WARNING}[*] Performing automated card reset...{Config.Colors.ENDC}")
            self._handle_reset()

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
            
    def _handle_pin_cmd(self, func, arg_line, required_args, usage_msg):
        if not arg_line:
            print(f"{Config.Colors.FAIL}[-] Usage: {usage_msg}{Config.Colors.ENDC}")
            return
            
        parts = arg_line.split()
        if len(parts) < required_args:
            print(f"{Config.Colors.FAIL}[-] Usage: {usage_msg}{Config.Colors.ENDC}")
            return
            
        func(*parts)

    def _handle_auth_general(self, arg_line, context):
        parts = []
        if arg_line:
            parts = arg_line.split()
            
        if len(parts) != 2:
            print(f"{Config.Colors.FAIL}[-] Usage: AUTH-{context} <RAND> <AUTN>{Config.Colors.ENDC}")
            return
            
        self.sec_ctrl.run_auth(parts[0], parts[1], app_context=context)

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

    def _handle_set_status(self) -> None:
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
            if hasattr(self, 'gp_ctrl'):
                has_gp_ctrl = True
                
            active_ctrl = None
            if has_gp_ctrl:
                active_ctrl = self.gp_ctrl
                
            has_tp = False
            if hasattr(self, 'tp'):
                has_tp = True
                
            if has_tp:
                active_ctrl = self.tp
                
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

    def _handle_manage_channel(self) -> None:
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

        ans = input("[?] Execute MANAGE CHANNEL? [y/N]: ").strip().lower()
        
        do_execute = False
        if ans == "yes":
            do_execute = True
            
        if ans == "y":
            do_execute = True
            
        if do_execute:
            has_gp_ctrl = False
            if hasattr(self, 'gp_ctrl'):
                has_gp_ctrl = True
                
            active_ctrl = None
            if has_gp_ctrl:
                active_ctrl = self.gp_ctrl
                
            has_tp = False
            if hasattr(self, 'tp'):
                has_tp = True
                
            if has_tp:
                active_ctrl = self.tp
                
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
                
        is_aborted = False
        if do_execute == False:
            is_aborted = True
            
        if is_aborted:
            print("[-] Execution aborted by user.")

    def _handle_put_key_wizard(self) -> None:
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
            kvn_val = getattr(self, 'current_kvn', None)
            
            is_kvn_missing = False
            if kvn_val is None:
                is_kvn_missing = True
                
            if is_kvn_missing:
                has_keys_config = False
                if 'KEYS' in self.config:
                    has_keys_config = True
                    
                if has_keys_config:
                    has_kvn_key = False
                    if 'kvn' in self.config['KEYS']:
                        has_kvn_key = True
                        
                    if has_kvn_key:
                        kvn_val = self.config['KEYS']['kvn']
                        
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
            self._exec_put_key(old_kvn, key_id, new_kvn, keys, algo)
            
        is_aborted = False
        if do_execute == False:
            is_aborted = True
            
        if is_aborted:
            print("[-] Execution aborted by user.")

    def _exec_put_key(self, old_kvn, key_id, new_kvn, keys, algo):
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

        success = self.gp_ctrl.put_key(old_kvn, key_id, new_kvn, keys, key_type)
        
        is_success = False
        if success:
            is_success = True
            
        if is_success:
            print("[+] PUT KEY operation completed successfully.")
            self._prompt_config_update(new_kvn, keys[0], keys[1], keys[2])
            
        is_failed = False
        if is_success == False:
            is_failed = True
            
        if is_failed:
            print("[-] PUT KEY operation failed.")

    def _handle_manage_pin_wizard(self) -> None:
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
            
        is_invalid = False
        if is_valid == False:
            is_invalid = True
            
        if is_invalid:
            print("[-] Invalid selection. Aborting.")
            return

        pin_id = input("Enter PIN ID [Hex, Default: 01 (CHV1)]: ").strip().upper()
        
        is_id_empty = False
        if len(pin_id) == 0:
            is_id_empty = True
            
        if is_id_empty:
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
            
            is_cur_empty = False
            if len(current_pin) == 0:
                is_cur_empty = True
                
            if is_cur_empty:
                print("[-] Current PIN required. Aborting.")
                return

        puk_val = ""
        if need_puk:
            puk_val = input("Enter PUK [ASCII]: ").strip()
            
            is_puk_empty = False
            if len(puk_val) == 0:
                is_puk_empty = True
                
            if is_puk_empty:
                print("[-] PUK required. Aborting.")
                return

        new_pin = ""
        if need_new:
            new_pin = input("Enter New PIN [ASCII]: ").strip()
            
            is_new_empty = False
            if len(new_pin) == 0:
                is_new_empty = True
                
            if is_new_empty:
                print("[-] New PIN required. Aborting.")
                return

        ans = input("\n[?] Execute PIN operation? [y/N]: ").strip().lower()
        
        do_execute = False
        if ans == "yes":
            do_execute = True
            
        if ans == "y":
            do_execute = True
            
        if do_execute:
            print("\n[*] Executing PIN Command...")
            if is_one:
                self.sec_ctrl.verify_pin(pin_id, current_pin)
            if is_two:
                self.sec_ctrl.change_pin(pin_id, current_pin, new_pin)
            if is_three:
                self.sec_ctrl.disable_pin(pin_id, current_pin)
            if is_four:
                self.sec_ctrl.enable_pin(pin_id, current_pin)
            if is_five:
                self.sec_ctrl.unblock_pin(pin_id, puk_val, new_pin)
                
        is_aborted = False
        if do_execute == False:
            is_aborted = True
            
        if is_aborted:
            print("[-] Execution aborted by user.")

    def _handle_manage_profile_wizard(self) -> None:
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
                self.gp_ctrl.sgp22.list_profiles()
                return
                
            is_two = False
            if act_choice == '2':
                is_two = True
                
            if is_two:
                self.gp_ctrl.sgp22.run_sgp22_scan()
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
                    
                resolved_target = self._resolve_mixed_aid(target)
                
                ans = input(f"\n[?] Execute action on {resolved_target}? [y/N]: ").strip().lower()
                
                do_execute = False
                if ans == "yes":
                    do_execute = True
                    
                if ans == "y":
                    do_execute = True
                    
                if do_execute:
                    print("\n[*] Executing Profile Command...")
                    if is_three:
                        self._handle_enable(resolved_target)
                    if is_four:
                        self._handle_disable(resolved_target)
                    if is_five:
                        self._handle_delete_profile(resolved_target)
                        
                is_aborted = False
                if do_execute == False:
                    is_aborted = True
                    
                if is_aborted:
                    print("[-] Execution aborted by user.")
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
                self.gp_ctrl.sgp22.run_sgp02_scan()
                return
                
            print("[-] Invalid action. Aborting.")

    def _handle_run_auth_wizard(self) -> None:
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

        ans = input(f"\n[?] Execute {context} Authentication? [y/N]: ").strip().lower()
        
        do_execute = False
        if ans == "yes":
            do_execute = True
            
        if ans == "y":
            do_execute = True
            
        if do_execute:
            print(f"\n[*] Executing {context} AUTH...")
            if is_gsm:
                self.sec_ctrl.run_auth(rand_val, app_context="GSM")
                
            is_not_gsm = False
            if is_gsm == False:
                is_not_gsm = True
                
            if is_not_gsm:
                self.sec_ctrl.run_auth(rand_val, autn_val, app_context=context)
                
        is_aborted = False
        if do_execute == False:
            is_aborted = True
            
        if is_aborted:
            print("[-] Execution aborted by user.")

    def _handle_config_wizard(self) -> None:
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

        ans = input(f"\n[?] Update {key_name} to {val}? [y/N]: ").strip().lower()
        
        do_execute = False
        if ans == "yes":
            do_execute = True
            
        if ans == "y":
            do_execute = True
            
        if do_execute:
            print(f"\n[*] Updating configuration...")
            self._update_config(key_name, val)
            
        is_aborted = False
        if do_execute == False:
            is_aborted = True
            
        if is_aborted:
            print("[-] Configuration update aborted by user.")

    def _handle_get_data_wizard(self) -> None:
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
            self.gp_ctrl.list_registry('APPS')
            return
            
        if is_two:
            self.gp_ctrl.list_registry('PACKAGES')
            return
            
        if is_three:
            self.gp_ctrl.list_registry('SD')
            return
            
        if is_four:
            self.gp_ctrl.get_cplc()
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
                self.gp_ctrl.get_data(p1, p2)
            except ValueError:
                print("[-] Invalid Hex parameters. Aborting.")

    def run(self):
        print(f"{Config.Colors.HEADER}--- YggdraSIM Shell ---{Config.Colors.ENDC}")
        
        if self.transport:
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