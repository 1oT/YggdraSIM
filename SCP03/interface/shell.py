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

class ShellDispatcher:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self._load_config_file()
        self.aid_registry = self._load_aid_registry()
        self.aid_lookup = {bytes.fromhex(v): k for k, v in self.aid_registry.items()}
        self.transport = None
        try:
            self.transport = CardTransporter()
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Critical: {e}{Config.Colors.ENDC}")

        self._initialize_controllers()
        self.prompt_str = ""
        self._update_prompt_state() 
        
        self.command_map = {
            # Session
            'AUTH-SD': (self._handle_auth, ""),
            'RESET': (self._handle_reset, ""),
            'INFO': (self._print_card_info, ""),
            'KEYS': (self._handle_keys, "[AID]"),
            'CPLC': (self.gp_ctrl.get_cplc, ""),
            'LOGOUT': (self._handle_logout, ""),
            'CLS': (lambda: os.system('cls' if os.name=='nt' else 'clear'), ""),
            'OTA': (self._run_scp80_tool, ""),
            
            # SGP.22 (Consumer)
            'LIST-CONS': (self.gp_ctrl.sgp22.list_profiles, ""),
            'GET-CONS': (self.gp_ctrl.sgp22.run_sgp22_scan, ""),
            'ENABLE-CONS': (self._handle_enable, "<AID/ICCID>"),
            'DISABLE-CONS': (self._handle_disable, "<AID/ICCID>"),
            'DELETE-CONS': (self._handle_delete_profile, "<AID/ICCID>"),

            # SGP.32 (IoT)
            'LIST-IOT': (self.gp_ctrl.sgp22.list_profiles, ""),
            'GET-IOT': (self.gp_ctrl.sgp22.run_sgp22_scan, ""),
            'ENABLE-IOT': (self._handle_enable, "<AID/ICCID>"),
            'DISABLE-IOT': (self._handle_disable, "<AID/ICCID>"),
            'DELETE-IOT': (self._handle_delete_profile, "<AID/ICCID>"),
            
            # SGP.02 (M2M)
            'GET-M2M': (self.gp_ctrl.sgp22.run_sgp02_scan, ""),
            'GET-ECASD': (self.gp_ctrl.sgp22.run_sgp02_scan, ""),
            
            # GlobalPlatform Registry
            'APPS': (lambda: self.gp_ctrl.list_registry('APPS'), ""),
            'PKGS': (lambda: self.gp_ctrl.list_registry('PACKAGES'), ""),
            'SD': (lambda: self.gp_ctrl.list_registry('SD'), ""),
            
            # Lifecycle
            'LOCK': (lambda x: self.gp_ctrl.set_status(x, 0x80), "<AID>"),
            'UNLOCK': (lambda x: self.gp_ctrl.set_status(x, 0x07), "<AID>"),
            'DEL': (lambda x: self.gp_ctrl.delete_object(x, True), "<AID>"),
            'ADM': (self.gp_ctrl.verify_adm, "[Key]"),
            'STORE-DATA': (self._handle_store_data, "<Hex> [P1] [P2]"), # New
            'PUT-KEY': (self._handle_put_key, "<KVN> <KeyID> <K1> <K2> <K3>"), # New

            # Applet Loading (Renamed INSTALL -> INSTALL-INSTALL)
            'INSTALL-INSTALL': (self._handle_install_file, "<CAP> [Priv] [Params]"),
            'LOAD': (lambda x: self.gp_ctrl.install_cap_file(x, instantiate=False), "<CAP>"),
            'INSTALL-SELECTABLE': (self._handle_install_selectable, "<AID> [Priv]"),
            'INSTALL-EXTRADITION': (self._handle_install_extradition, "<App> <SD>"),
            'INSTALL-PERSO': (lambda x: self.gp_ctrl.install_personalization(x), "<AID>"),

            # File System
            'SCAN': (self.fs_ctrl.scan_tree, ""),
            'REPORT': (lambda x=None: self.fs_ctrl.generate_report(x) if x else self.fs_ctrl.generate_report(), "[File]"),
            'SELECT': (lambda x: self.fs_ctrl.select(x), "<Path/FID>"),
            'READ': (self.fs_ctrl.read_binary, "[Path]"),
            'RECORD': (self.fs_ctrl.read_record, "<N/All> [Path]"),
            'UPDATE': (self._handle_update, "BINARY/RECORD <Data>"),
            'GET': (lambda x: self.gp_ctrl.get_data(*[int(i, 16) for i in x.split()[:2]]) if len(x.split()) >= 2 else print("Usage: GET <P1> <P2>"), "<P1> <P2>"),

            # Security
            'VERIFY': (lambda x: self._handle_pin_cmd(self.sec_ctrl.verify_pin, x, 2, "VERIFY <ID> <PIN>"), "<ID> <PIN>"),
            'CHANGE-PIN': (lambda x: self._handle_pin_cmd(self.sec_ctrl.change_pin, x, 3, "CHANGE-PIN <ID> <OLD> <NEW>"), "<ID> <Old> <New>"),
            'DISABLE-PIN': (lambda x: self._handle_pin_cmd(self.sec_ctrl.disable_pin, x, 2, "DISABLE-PIN <ID> <PIN>"), "<ID> <PIN>"),
            'ENABLE-PIN': (lambda x: self._handle_pin_cmd(self.sec_ctrl.enable_pin, x, 2, "ENABLE-PIN <ID> <PIN>"), "<ID> <PIN>"),
            'UNBLOCK': (lambda x: self._handle_pin_cmd(self.sec_ctrl.unblock_pin, x, 3, "UNBLOCK <ID> <PUK> <NEW_PIN>"), "<ID> <PUK> <New>"),

            # Auth
            'AUTH-GSM': (lambda x: self.sec_ctrl.run_auth(x, app_context="GSM") if x else print("Usage: AUTH-GSM <RAND>"), "<RAND>"),
            'AUTH-USIM': (lambda x: self._handle_auth_general(x, "USIM"), "<R> <AUTN>"),
            'AUTH-ISIM': (lambda x: self._handle_auth_general(x, "ISIM"), "<R> <AUTN>"),

            # Config
            'SHOW': (self.show_config, ""),
            'AIDS': (self.list_aids, ""),
            'SET-AID-ALIAS': (self._set_aid_alias, "<Name> <AID>"),
            'SET-KENC': (lambda x: self._update_config('kenc', x), "<Key>"),
            'SET-KMAC': (lambda x: self._update_config('kmac', x), "<Key>"),
            'SET-DEK': (lambda x: self._update_config('dek', x), "<Key>"), # New
            'SET-AID':  (lambda x: self._update_config('aid', x), "<AID>"),
            'SET-KVN':  (lambda x: self._update_config('kvn', x), "<Val>"),
            'SET-ADM':  (lambda x: self._update_config('adm', x), "<Key>"),
            'SET-DEFAULT': (self._set_defaults, ""),
            
            # System
            'OTA': (self._run_scp80_tool, ""),
            'RUN': (self.run_script, "<File> [Out.yaml]"),
            'SCRIPT': (self.run_script, "<File>"),
            'HELP': (self._print_help, ""),
            'EXIT': (self._exit, ""),
            'Q': (self._exit, "")
        }
        
        self.commands = {k: v[0] for k, v in self.command_map.items()}
        self._setup_readline()

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

    def _save_history(self):
        if readline:
            try:
                readline.write_history_file(self.hist_file)
            except:
                pass

    def _completer(self, text, state):
        line_buffer = readline.get_line_buffer().lstrip()
        if ' ' not in line_buffer:
            options = [cmd for cmd in self.commands.keys() if cmd.startswith(text.upper())]
            if state < len(options):
                return options[state]
        return None

    def _handle_install_file(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 1:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-INSTALL <File> [Privileges] [Params]{Config.Colors.ENDC}")
            return
        f = parts[0]
        p = parts[1] if len(parts) > 1 else "00"
        par = parts[2] if len(parts) > 2 else "C900"
        self.gp_ctrl.install_cap_file(f, privileges=p, install_params=par, instantiate=True)

    def _handle_store_data(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 1:
            print(f"{Config.Colors.FAIL}Usage: STORE-DATA <HexData> [P1=00] [P2=00]{Config.Colors.ENDC}")
            return
        data = parts[0]
        p1 = int(parts[1], 16) if len(parts) > 1 else 0x00
        p2 = int(parts[2], 16) if len(parts) > 2 else 0x00
        self.gp_ctrl.store_data(data, p1, p2)

    def _handle_put_key(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 5:
            print(f"{Config.Colors.FAIL}Usage: PUT-KEY <NewKVN> <KeyID_Start> <K-ENC> <K-MAC> <K-DEK>{Config.Colors.ENDC}")
            return
        try:
            kvn = int(parts[0], 16)
            kid = int(parts[1], 16)
            keys = parts[2:5]
            self.gp_ctrl.put_key(kvn, kid, keys)
        except ValueError:
            print(f"{Config.Colors.FAIL}[!] Invalid integer args.{Config.Colors.ENDC}")

    def _update_prompt_state(self):
        is_auth = False
        if self.transport and self.transport.session and self.transport.session.is_authenticated:
            is_auth = True
        
        if not is_auth:
            self.prompt_str = f"\n{Config.Colors.CYAN}[APDU] > {Config.Colors.ENDC}"
        else:
            current_aid = self.gp_ctrl.target_aid 
            name = self.aid_lookup.get(current_aid)
            display = name if name else current_aid.hex().upper()
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
        privs = parts[1] if len(parts) > 1 else "00"
        self.gp_ctrl.install_make_selectable(aid, privs)

    def _handle_install_extradition(self, arg_line):
        parts = arg_line.split()
        if len(parts) < 2:
            print(f"{Config.Colors.FAIL}Usage: INSTALL-EXTRADITION <App_AID> <SD_AID>{Config.Colors.ENDC}")
            return
        self.gp_ctrl.install_extradition(parts[0], parts[1])

    def _handle_keys(self, arg: Optional[str] = None):
        target = self._resolve_mixed_aid(arg) if arg else None
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
        if self.transport.session and self.transport.session.is_authenticated:
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
        parts = arg_line.split() if arg_line else []
        if len(parts) != 2:
            print(f"{Config.Colors.FAIL}[-] Usage: AUTH-{context} <RAND> <AUTN>{Config.Colors.ENDC}")
            return
        self.sec_ctrl.run_auth(parts[0], parts[1], app_context=context)

    def _print_help(self):
        """Prints help with links and structure."""
        def link(text, url):
            if not url: return text
            return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"

        structure = [
            {
                "label": "GlobalPlatform",
                "url": "https://globalplatform.org/wp-content/uploads/2025/05/GPC_CardSpecification_v2.3.1.49_PublicRvw.pdf",
                "subgroups": [
                    {
                        "label": "Session (SCP03)", "url": None,
                        "cmds": [
                            ("AUTH-SD", "", "Authenticate"),
                            ("RESET", "", "Cold Reset"),
                            ("INFO", "", "Card Info"),
                            ("CPLC", "", "Get CPLC"),
                            ("KEYS", "[AID]", "Get Keys"),
                            ("LOGOUT", "", "Close Session")
                        ]
                    },
                    {
                        "label": "Registry", "url": None,
                        "cmds": [
                            ("APPS", "", "List Applets"),
                            ("PKGS", "", "List Packages"),
                            ("SD", "", "List SDs"),
                            ("GET", "<P1><P2>", "Get Data"),
                            ("STORE-DATA", "<Hex>", "Store Data") # Added
                        ]
                    },
                    {
                        "label": "Lifecycle", "url": None,
                        "cmds": [
                            ("INSTALL-INSTALL", "<Cap>", "Install CAP"),
                            ("LOAD", "<Cap>", "Load CAP"),
                            ("INSTALL-SELECTABLE", "", "Make Selectable"),
                            ("INSTALL-EXTRADITION", "", "Extradition"),
                            ("LOCK/UNLOCK/DEL", "", "Mgmt Object"),
                            ("PUT-KEY", "<KVN>", "Rotate Keys") # Added
                        ]
                    }
                ]
            },
            {
                "label": "GSMA",
                "url": "https://www.gsma.com/esim",
                "subgroups": [
                    {
                        "label": "GSMA SGP.02 (M2M)", 
                        "url": "https://www.gsma.com/solutions-and-impact/technologies/esim/gsma_resources/sgp-02-v4-3/",
                        "cmds": [
                            ("GET-M2M", "", "Scan SGP.02"),
                            ("GET-ECASD", "", "Scan ECASD")
                        ]
                    },
                    {
                        "label": "GSMA SGP.22 (Consumer)", 
                        "url": "https://www.gsma.com/esim/wp-content/uploads/2020/06/SGP.22-v2.2.2.pdf",
                        "cmds": [
                            ("LIST-CONS", "", "List Profiles"),
                            ("ENABLE/DISABLE-CONS", "", "State Mgmt"),
                            ("DELETE-CONS", "", "Delete"),
                            ("GET-CONS", "", "Scan SGP.22")
                        ]
                    },
                    {
                        "label": "GSMA SGP.32 (IoT)", 
                        "url": "https://www.gsma.com/solutions-and-impact/technologies/esim/gsma_resources/sgp-32-v1-2/",
                        "cmds": [
                            ("LIST-IOT", "", "List Profiles"),
                            ("ENABLE/DISABLE-IOT", "", "State Mgmt"),
                            ("DELETE-IOT", "", "Delete"),
                            ("GET-IOT", "", "Scan SGP.32")
                        ]
                    }
                ]
            },
            {
                "label": "ETSI / 3GPP",
                "url": "https://www.etsi.org",
                "subgroups": [
                    {
                        "label": "File System", "url": None,
                        "cmds": [
                            ("SELECT", "<Path>", "Select File"),
                            ("READ", "", "Read Binary"),
                            ("RECORD", "", "Read Record"),
                            ("UPDATE", "", "Update File"),
                            ("SCAN", "", "Scan FS"),
                            ("REPORT", "", "Gen Report")
                        ]
                    },
                    {
                        "label": "Security", "url": None,
                        "cmds": [
                            ("VERIFY", "", "Verify PIN"),
                            ("CHANGE-PIN", "", "Change PIN"),
                            ("UNBLOCK", "", "Unblock PIN")
                        ]
                    },
                    {
                        "label": "Auth", "url": None,
                        "cmds": [
                            ("AUTH-GSM", "", "GSM Auth"),
                            ("AUTH-USIM", "", "USIM Auth"),
                            ("AUTH-ISIM", "", "ISIM Auth")
                        ]
                    }
                ]
            },
            {
                "label": "System", "url": None,
                "subgroups": [
                    {
                        "label": "General", "url": None,
                        "cmds": [
                            ("SHOW", "", "Config"),
                            ("SET-AID", "", "Set Target"),
                            ("SET-DEK", "<Key>", "Set DEK Key"), # Added
                            ("OTA", "", "SCP80 Tool"),
                            ("RUN", "<File>", "Run Script"),
                            ("HELP", "", "Help"),
                            ("EXIT", "", "Exit")
                        ]
                    }
                ]
            }
        ]
        
        print(f"\n{Config.Colors.HEADER}=== YggdraSIM SCP03 Help ==={Config.Colors.ENDC}")
        for section in structure:
            print(f"\n{Config.Colors.BOLD}{link(section['label'], section['url'])}{Config.Colors.ENDC}")
            for i, grp in enumerate(section["subgroups"]):
                print(f"  {Config.Colors.CYAN}{link(grp['label'], grp['url'])}:{Config.Colors.ENDC}")
                for c, a, d in grp["cmds"]:
                    print(f"    {Config.Colors.GREEN}{c:<24}{Config.Colors.ENDC} {a:<10} : {d}")
                
                if i < len(section["subgroups"]) - 1:
                    print("")
        print("")

    def run_script(self, arg_line: str):
        """Runs a script file. Usage: RUN <script.txt> [output.yaml]"""
        parts = arg_line.split()
        if not parts:
            print(f"{Config.Colors.FAIL}[!] Usage: RUN <script_file> [output.yaml]{Config.Colors.ENDC}")
            return

        filename = parts[0]
        yaml_out = parts[1] if len(parts) > 1 else None
        
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
                if not line or line.startswith('#'):
                    continue
                
                print(f"\n{Config.Colors.YELLOW}[SCRIPT:{i+1}] > {line}{Config.Colors.ENDC}")
                
                # Capture output if YAML requested
                captured_output = ""
                if yaml_out:
                    # Redirect stdout to capture output of the command
                    old_stdout = sys.stdout
                    sys.stdout = mystdout = io.StringIO()
                    
                    try:
                        self._exec_line(line)
                    except Exception as e:
                        print(f"Error: {e}")
                    finally:
                        sys.stdout = old_stdout
                        captured_output = mystdout.getvalue()
                        print(captured_output, end="") # Echo back to console
                else:
                    self._exec_line(line)

                if yaml_out:
                    # Clean ANSI codes for YAML
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    clean_text = ansi_escape.sub('', captured_output).strip()
                    results.append({'command': line, 'output': clean_text})

        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Script Error: {e}{Config.Colors.ENDC}")

        if yaml_out and results:
            try:
                with open(yaml_out, 'w') as f:
                    f.write(f"# YggdraSIM Script Report\n")
                    f.write(f"# Date: {datetime.datetime.now()}\n")
                    f.write(f"# Script: {filename}\n\n")
                    f.write("steps:\n")
                    for step in results:
                        f.write(f"  - command: \"{step['command']}\"\n")
                        # Indent multiline strings for YAML block literal
                        f.write("    output: |\n")
                        for out_line in step['output'].split('\n'):
                            f.write(f"      {out_line}\n")
                print(f"{Config.Colors.GREEN}[+] Report saved to {yaml_out}{Config.Colors.ENDC}")
            except Exception as e:
                print(f"{Config.Colors.FAIL}[!] Failed to write YAML: {e}{Config.Colors.ENDC}")

    def _exec_line(self, line: str):
        if not line or line.startswith('#'):
            return
        parts = line.split(None, 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in self.commands:
            # [FIXED] Updated args requirement list
            args_required = [
                'SET-KENC', 'SET-KMAC', 'SET-AID', 'SET-KVN', 'SET-ADM', 'SET-AID-ALIAS', 'SET-DEK', # Added SET-DEK
                'SELECT', 'UPDATE', 'GET', 'LOCK', 'UNLOCK', 'DEL', 'SCRIPT', 
                'INSTALL-INSTALL', 'LOAD', 'STORE-DATA', 'PUT-KEY', # Added
                'ENABLE-CONS', 'DISABLE-CONS', 'DELETE-CONS',
                'ENABLE-IOT', 'DISABLE-IOT', 'DELETE-IOT',
                'VERIFY', 'CHANGE-PIN', 'ENABLE-PIN', 'DISABLE-PIN', 'UNBLOCK', 
                'AUTH-GSM', 'AUTH-USIM', 'AUTH-ISIM', 
                'INSTALL-SELECTABLE', 'INSTALL-EXTRADITION', 'INSTALL-PERSO'
            ]
            args_optional = ['REPORT', 'ADM', 'KEYS', 'READ', 'RECORD', 'RUN']
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
            if decoded and "None" not in decoded:
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
        if sw1 == 0x90 and len(channel_data) > 0:
            log_chan = channel_data[0]; ecasd_aid = "A0000005591010FFFFFFFF8900000200"
            def send_chan(cla, ins, p1, p2, data=""):
                cla_byte = int(cla, 16) | log_chan
                cmd = f"{cla_byte:02X}{ins}{p1}{p2}{len(data)//2:02X}{data}" if data else f"{cla_byte:02X}{ins}{p1}{p2}00"
                return self.transport.transmit(cmd, silent=True)
            
            send_chan("00", "A4", "04", "00", ecasd_aid) 
            payload = "BF3E035C015A"
            res, sw1, sw2 = send_chan("80", "E2", "91", "00", payload)
            is_sgp22_confirmed = False
            
            if sw1 == 0x90:
                if b'\x5A' in res: 
                    std = f"{Config.Colors.GREEN}SGP.22/32 (Consumer/IoT){Config.Colors.ENDC}"
                    is_sgp22_confirmed = True
            elif sw1 == 0x69 and sw2 == 0x82: 
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
                            name, aid = parts[0].strip().upper(), parts[1].strip().upper()
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
        if not arg_line or len(arg_line.split()) < 2:
            print(f"{Config.Colors.FAIL}[-] Usage: SET-AID-ALIAS <NAME> <AID_HEX>{Config.Colors.ENDC}")
            return
        name, aid_hex = arg_line.split(None, 1)
        name = name.strip().upper()
        aid_hex = aid_hex.strip().replace(' ', '').upper()
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
        # Ensure history is saved on manual exit
        self._save_history()
        sys.exit(0)

    def _run_scp80_tool(self):
        print(f"{Config.Colors.HEADER}=== Switching to SCP80 OTA Tool ==={Config.Colors.ENDC}")
        print(f"{Config.Colors.WARNING}[*] Releasing Card Reader...{Config.Colors.ENDC}")
        
        # 1. Disconnect SCP03 Session
        if self.transport:
            self.transport.disconnect()
            
        try:
            print(f"{Config.Colors.CYAN}[*] Starting SCP80 Module...{Config.Colors.ENDC}")
            
            # --- CONTEXT SWITCH ---
            import sys
            import importlib.util

            # 1. Get path to SCP80/main.py
            current_dir = os.path.dirname(os.path.abspath(__file__))
            scp80_root = os.path.abspath(os.path.join(current_dir, '../../SCP80'))
            
            # 2. Add SCP80 to sys.path so it can resolve its own 'import cli'
            if scp80_root not in sys.path:
                sys.path.insert(0, scp80_root)

            # 3. Dynamic Import of SCP80.main
            # We use import_module to ensure we get the module defined in that directory
            import main as scp80_entry
            
            # 4. Run the correct entry point function
            # [FIXED] Call run_standalone() instead of main()
            scp80_entry.run_standalone()
            # ---------------------------

        except SystemExit:
            pass # Clean exit from OTA tool
        except ImportError as e:
            print(f"{Config.Colors.FAIL}[!] Import Error: {e}{Config.Colors.ENDC}")
            print(f"{Config.Colors.FAIL}[!] Check if 'SCP80/main.py' and 'cli.py' exist.{Config.Colors.ENDC}")
        except AttributeError:
             print(f"{Config.Colors.FAIL}[!] Error: SCP80/main.py has no 'run_standalone()' function.{Config.Colors.ENDC}")
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] SCP80 Tool Crashed: {e}{Config.Colors.ENDC}")
        
        # 3. Restore SCP03 Context
        print(f"\n{Config.Colors.HEADER}=== Returning to SCP03 Shell ==={Config.Colors.ENDC}")
        print(f"{Config.Colors.WARNING}[*] Re-acquiring Card Reader...{Config.Colors.ENDC}")
        
        try:
            # Clean up sys.path to avoid pollution (optional)
            if scp80_root in sys.path:
                sys.path.remove(scp80_root)

            self.transport = CardTransporter()
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