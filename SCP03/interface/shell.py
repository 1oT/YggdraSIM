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
from SCP03.core.utils import HexUtils, TlvParser
from SCP03.core.decoders import ContentDecoder
from SCP03.transport.card import CardTransporter
from SCP03.logic.gp import GlobalPlatformManager
from SCP03.logic.fs import FileSystemController
from SCP03.logic.security import SecurityController
from SCP03.interface.guides import ShellGuides
from SCP03.interface.commands import CommandRegistry
from SCP03.interface.help_menu import HelpMenu

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
        """Monkey-patches the transport layer to override silent flags dynamically and log outgoing APDUs."""
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
                
            return self.transport._original_transmit(cmd, silent=actual_silent)
            
        self.transport.transmit = _verbose_transmit

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

    def _handle_put_key(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 6:
            print(f"{Config.Colors.FAIL}Usage: PUT-KEY <OldKVN> <KeyID> <NewKVN> <K-ENC> <K-MAC> <K-DEK>{Config.Colors.ENDC}")
            return
            
        try:
            old_kvn = int(parts[0], 16)
            kid = int(parts[1], 16)
            new_kvn = int(parts[2], 16)
            keys = parts[3:6]
            self.gp_ctrl.put_key(old_kvn, kid, new_kvn, keys)
        except ValueError:
            print(f"{Config.Colors.FAIL}[!] Invalid integer args.{Config.Colors.ENDC}")

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
        
        if self.transport.reset():
            try: 
                atr = self.transport.connection.getATR()
            except: 
                pass
        else: 
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
        std = "Unknown / Legacy UICC"
        channel_data, sw1, sw2 = self.transport.transmit("0070000001", silent=True)
        
        if sw1 == 0x90:
            if len(channel_data) > 0:
                log_chan = channel_data[0]
                ecasd_aid = "A0000005591010FFFFFFFF8900000200"
                
                def send_chan(cla, ins, p1, p2, data=""):
                    cla_byte = int(cla, 16) | log_chan
                    cmd = f"{cla_byte:02X}{ins}{p1}{p2}00"
                    if data:
                        cmd = f"{cla_byte:02X}{ins}{p1}{p2}{len(data)//2:02X}{data}"
                    return self.transport.transmit(cmd, silent=True)
                
                send_chan("00", "A4", "04", "00", ecasd_aid) 
                payload = "BF3E035C015A"
                res, sw1, sw2 = send_chan("80", "E2", "91", "00", payload)
                is_sgp22_confirmed = False
                
                if sw1 == 0x90:
                    if b'\x5A' in res: 
                        std = f"{Config.Colors.GREEN}SGP.22/32 (Consumer/IoT){Config.Colors.ENDC}"
                        is_sgp22_confirmed = True
                elif sw1 == 0x69:
                    if sw2 == 0x82: 
                        std = f"{Config.Colors.GREEN}SGP.22/32 (Consumer/IoT) - [Locked]{Config.Colors.ENDC}"
                        is_sgp22_confirmed = True
                
                if not eid:
                    res, sw1, sw2 = send_chan("00", "CA", "00", "5A") 
                    if sw1 == 0x90: 
                        eid = res.hex().upper()
                        if not is_sgp22_confirmed:
                            std = f"{Config.Colors.BLUE}SGP.02 (M2M){Config.Colors.ENDC}"
                        else:
                            std += " (Read via Legacy mode)"
                
                self.transport.transmit(f"007080{log_chan:02X}", silent=True)
        
        if eid: 
            print(f"{Config.Colors.BOLD}eID   :{Config.Colors.ENDC} {eid}")
            
        print(f"{Config.Colors.BOLD}Spec  :{Config.Colors.ENDC} {std}")
        self.transport.reset()
        self.fs_ctrl.current_fid = "3F00"
        print("="*40 + "\n")

    def _load_config_file(self):
        if os.path.exists(Config.INI_FILE):
            self.config.read(Config.INI_FILE)
            
        if 'KEYS' not in self.config:
            self.config['KEYS'] = {}

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
                print(f"{Config.Colors.CYAN}AIDs loaded ({len(registry)}){Config.Colors.ENDC}")
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

    def run(self):
        if self.transport:
            try:
                self._print_card_info()
            except Exception as e:
                print(f"{Config.Colors.FAIL}[!] Startup Check Failed: {e}{Config.Colors.ENDC}")
        
        self._update_prompt_state()
        print(f"{Config.Colors.HEADER}--- YggdraSIM SCP03 Shell ---{Config.Colors.ENDC}")
        print(f"Type 'help' for commands, 'aids' for known AIDs, 'exit' to quit.")
        
        while True:
            try:
                line = input(self.prompt_str).strip()
                self._exec_line(line)
            except KeyboardInterrupt:
                print("\nType 'exit' to quit.")
            except Exception as e:
                print(f"{Config.Colors.FAIL}[-] Critical Error: {e}{Config.Colors.ENDC}")