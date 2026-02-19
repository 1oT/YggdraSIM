import os
from typing import Dict, Tuple, Callable
from SCP03.interface.wizards import InteractiveWizards

class CommandRegistry:
    """Centralized registry for shell commands and their argument mappings."""

    @staticmethod
    def build(shell) -> Dict[str, Tuple[Callable, str]]:
        """Builds the main command map, binding commands to shell instance methods."""
        return {
            # Session
            'AUTH-SD': (shell._handle_auth, ""),
            'RESET': (shell._handle_reset, ""),
            'INFO': (shell._print_card_info, ""),
            'KEYS': (shell._handle_keys, "[AID]"),
            'CPLC': (shell.gp_ctrl.get_cplc, ""),
            'LOGOUT': (shell._handle_logout, ""),
            'CLS': (lambda: os.system('cls' if os.name == 'nt' else 'clear'), ""),
            'OTA': (shell._run_scp80_tool, ""),
            
            # SGP.22 (Consumer)
            'LIST-CONS': (shell.gp_ctrl.sgp22.list_profiles, ""),
            'GET-CONS': (shell.gp_ctrl.sgp22.run_sgp22_scan, ""),
            'ENABLE-CONS': (shell._handle_enable, "<AID/ICCID>"),
            'DISABLE-CONS': (shell._handle_disable, "<AID/ICCID>"),
            'DELETE-CONS': (shell._handle_delete_profile, "<AID/ICCID>"),

            # SGP.32 (IoT)
            'LIST-IOT': (shell.gp_ctrl.sgp22.list_profiles, ""),
            'GET-IOT': (shell.gp_ctrl.sgp22.run_sgp22_scan, ""),
            'ENABLE-IOT': (shell._handle_enable, "<AID/ICCID>"),
            'DISABLE-IOT': (shell._handle_disable, "<AID/ICCID>"),
            'DELETE-IOT': (shell._handle_delete_profile, "<AID/ICCID>"),
            
            # SGP.02 (M2M)
            'GET-M2M': (shell.gp_ctrl.sgp22.run_sgp02_scan, ""),
            'GET-ECASD': (shell.gp_ctrl.sgp22.run_sgp02_scan, ""),
            
            # GlobalPlatform Registry
            'APPS': (lambda: shell.gp_ctrl.list_registry('APPS'), ""),
            'PKGS': (lambda: shell.gp_ctrl.list_registry('PACKAGES'), ""),
            'SD': (lambda: shell.gp_ctrl.list_registry('SD'), ""),
            
            # Lifecycle
            'LOCK': (lambda x: shell.gp_ctrl.set_status(x, 0x80), "<AID>"),
            'UNLOCK': (lambda x: shell.gp_ctrl.set_status(x, 0x07), "<AID>"),
            'DEL': (lambda x: shell.gp_ctrl.delete_object(x, True), "<AID>"),
            'VERIFY-ADM': (shell.gp_ctrl.verify_adm, "[Key]"),
            'STORE-DATA': (shell._handle_store_data, "<Hex> [P1] [P2]"),
            'PUT-KEY': (shell._handle_put_key, "<KVN> <KeyID> <K1> <K2> <K3>"),

            # Applet Loading & Installation
            'INSTALL-INSTALL': (shell._handle_install_file, "<cap/ijc> [Priv] [Par] [App] [Mod]"),
            'INSTALL-LOAD': (lambda x: shell.gp_ctrl.install_cap_file(x, instantiate=False), "<cap/ijc>"),
            'INSTALL-APP': (shell._handle_install_app, "<Pkg> <App> [Mod] [Priv] [Par]"),
            'INSTALL-SELECTABLE': (shell._handle_install_selectable, "<AID> [Priv]"),
            'INSTALL-EXTRADITION': (shell._handle_install_extradition, "<AppAID> <SDAID>"),
            'INSTALL-REGISTRY': (shell._handle_install_registry, "<AID> [Priv] [Par]"),
            'INSTALL-PERSO': (lambda x: shell.gp_ctrl.install_personalization(x), "<AID>"),

            # Wizards / Builders
            'INSTALL-WIZARD-SD': (lambda: InteractiveWizards.run_install_wizard(), ""),
            'INSTALL-WIZARD-APDU': (lambda x: InteractiveWizards.build_install_apdu(x), "<cap/ijc>"),

            # File System
            'SCAN': (shell.fs_ctrl.scan_tree, ""),
            'REPORT': (lambda x=None: shell.fs_ctrl.generate_report(x) if x else shell.fs_ctrl.generate_report(), "[File]"),
            'SELECT': (lambda x: shell.fs_ctrl.select(x), "<Path/FID>"),
            'READ': (shell.fs_ctrl.read_binary, "[Path]"),
            'RECORD': (shell.fs_ctrl.read_record, "<N/ALL> [Path]"),
            'UPDATE': (shell._handle_update, "BINARY/RECORD <Data>"),
            'GET': (lambda x: shell.gp_ctrl.get_data(*[int(i, 16) for i in x.split()[:2]]) if len(x.split()) >= 2 else print("Usage: GET <P1> <P2>"), "<P1> <P2>"),

            # Security
            'VERIFY-PIN': (lambda x: shell._handle_pin_cmd(shell.sec_ctrl.verify_pin, x, 2, "VERIFY-PIN <ID> <PIN>"), "<ID> <PIN>"),
            'CHANGE-PIN': (lambda x: shell._handle_pin_cmd(shell.sec_ctrl.change_pin, x, 3, "CHANGE-PIN <ID> <OLD> <NEW>"), "<ID> <Old> <New>"),
            'DISABLE-PIN': (lambda x: shell._handle_pin_cmd(shell.sec_ctrl.disable_pin, x, 2, "DISABLE-PIN <ID> <PIN>"), "<ID> <PIN>"),
            'ENABLE-PIN': (lambda x: shell._handle_pin_cmd(shell.sec_ctrl.enable_pin, x, 2, "ENABLE-PIN <ID> <PIN>"), "<ID> <PIN>"),
            'UNBLOCK': (lambda x: shell._handle_pin_cmd(shell.sec_ctrl.unblock_pin, x, 3, "UNBLOCK <ID> <PUK> <NEW_PIN>"), "<ID> <PUK> <New>"),

            # Auth
            'AUTH-GSM': (lambda x: shell.sec_ctrl.run_auth(x, app_context="GSM") if x else print("Usage: AUTH-GSM <RAND>"), "<RAND>"),
            'AUTH-USIM': (lambda x: shell._handle_auth_general(x, "USIM"), "<R> <AUTN>"),
            'AUTH-ISIM': (lambda x: shell._handle_auth_general(x, "ISIM"), "<R> <AUTN>"),

            # Config
            'SHOW': (shell.show_config, ""),
            'AIDS': (shell.list_aids, ""),
            'SET-AID-ALIAS': (shell._set_aid_alias, "<Name> <AID>"),
            'SET-KENC': (lambda x: shell._update_config('kenc', x), "<Key>"),
            'SET-KMAC': (lambda x: shell._update_config('kmac', x), "<Key>"),
            'SET-DEK': (lambda x: shell._update_config('dek', x), "<Key>"),
            'SET-AID':  (lambda x: shell._update_config('aid', x), "<AID>"),
            'SET-KVN':  (lambda x: shell._update_config('kvn', x), "<Val>"),
            'SET-ADM':  (lambda x: shell._update_config('adm', x), "<Key>"),
            'SET-DEFAULT': (shell._set_defaults, ""),
            
            # Hidden / Developer
            'DEBUG': (shell._toggle_debug, ""),
            'VERBOSE': (shell._toggle_debug, ""),
            
            # System
            'GUIDE': (shell._handle_guide, "[Topic]"),
            'OTA': (shell._run_scp80_tool, ""),
            'RUN': (shell.run_script, "<File> [Out.yaml]"),
            'SCRIPT': (shell.run_script, "<File>"),
            'HELP': (shell._print_help, ""),
            'EXIT': (shell._exit, ""),
            'Q': (shell._exit, "")
        }

    @staticmethod
    def get_arg_requirements():
        """Returns tuples of commands that require mandatory or optional arguments."""
        args_required = [
            'SET-KENC', 'SET-KMAC', 'SET-AID', 'SET-KVN', 'SET-ADM', 'SET-AID-ALIAS', 'SET-DEK',
            'SELECT', 'UPDATE', 'GET', 'LOCK', 'UNLOCK', 'DEL', 'SCRIPT', 
            'INSTALL-INSTALL', 'LOAD', 'STORE-DATA', 'PUT-KEY',
            'INSTALL-WIZARD-APDU', 'INSTALL-APP', 'INSTALL-REGISTRY',
            'ENABLE-CONS', 'DISABLE-CONS', 'DELETE-CONS',
            'ENABLE-IOT', 'DISABLE-IOT', 'DELETE-IOT',
            'VERIFY-PIN', 'CHANGE-PIN', 'ENABLE-PIN', 'DISABLE-PIN', 'UNBLOCK', 
            'AUTH-GSM', 'AUTH-USIM', 'AUTH-ISIM', 
            'INSTALL-SELECTABLE', 'INSTALL-EXTRADITION', 'INSTALL-PERSO'
        ]
        args_optional = ['REPORT', 'VERIFY-ADM', 'KEYS', 'READ', 'RECORD', 'RUN', 'GUIDE', 'DEBUG', 'VERBOSE']
        
        return args_required, args_optional