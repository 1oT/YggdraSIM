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
            'LOGOUT': (shell._handle_logout, ""),
            'CLS': (lambda: os.system('cls' if os.name == 'nt' else 'clear'), ""),
            'OTA': (shell._run_scp80_tool, ""),
            
            # eSIM Profile Management
            'MANAGE-PROFILE': (shell._handle_manage_profile_wizard, ""),
            
            # GlobalPlatform Registry & Data
            'GET-DATA': (shell._handle_get_data_wizard, ""),
            
            # Lifecycle
            'LOCK': (lambda x: shell.gp_ctrl.set_status(x, 0x80), "<AID>"),
            'UNLOCK': (lambda x: shell.gp_ctrl.set_status(x, 0x07), "<AID>"),
            'DEL': (lambda x: shell.gp_ctrl.delete_object(x, True), "<AID>"),
            'VERIFY-ADM': (shell.gp_ctrl.verify_adm, "[Key]"),
            'STORE-DATA': (shell._handle_store_data, "<Hex> [P1] [P2]"),
            'PUT-KEY': (shell._handle_put_key_wizard, ""),
            'SET-STATUS': (lambda: shell._handle_set_status(), ""),
            'MANAGE-CHANNEL': (lambda: shell._handle_manage_channel(), ""),

            # Wizards / Builders
            'WIZARD': (lambda: shell._handle_install_wizard(), ""),

            # File System
            'SCAN': (shell.fs_ctrl.scan_tree, ""),
            'REPORT': (lambda x=None: shell.fs_ctrl.generate_report(x) if x else shell.fs_ctrl.generate_report(), "[File]"),
            'SELECT': (lambda x: shell.fs_ctrl.select(x), "<Path/FID>"),
            'READ': (shell.fs_ctrl.read_binary, "[Path]"),
            'RECORD': (shell.fs_ctrl.read_record, "<N/ALL> [Path]"),
            'UPDATE': (shell._handle_update, "BINARY/RECORD <Data>"),
            'GET-DATA': (lambda x: shell.gp_ctrl.get_data(*[int(i, 16) for i in x.split()[:2]]) if len(x.split()) >= 2 else print("Usage: GET <P1> <P2>"), "<P1> <P2>"),
            'DUMP-FS': (shell.do_dump_fs, "[OutputDir]"),

            # Security
            'MANAGE-PIN': (shell._handle_manage_pin_wizard, ""),

            # Auth
            'RUN-AUTH': (shell._handle_run_auth_wizard, ""),

            # Config
            'SHOW': (shell.show_config, ""),
            'AIDS': (shell.list_aids, ""),
            'SET-AID-ALIAS': (shell._set_aid_alias, "<Name> <AID>"),
            'SET-DEFAULT': (shell._set_defaults, ""),
            'CONFIG': (shell._handle_config_wizard, ""),
            
            # Hidden / Developer
            'DEBUG': (shell._toggle_debug, ""),
            'VERBOSE': (shell._toggle_debug, ""),
            'DECODE': (shell._handle_decode, "<Hex>"),
            
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
            'SELECT', 'UPDATE', 'LOCK', 'UNLOCK', 'DEL', 'SCRIPT', 
            'INSTALL-INSTALL', 'LOAD', 'STORE-DATA',
            'INSTALL-WIZARD-APDU', 'INSTALL-APP', 'INSTALL-REGISTRY',
            'INSTALL-SELECTABLE', 'INSTALL-EXTRADITION', 'INSTALL-PERSO', 'DECODE'
        ]
        args_optional = ['REPORT', 'VERIFY-ADM', 'KEYS', 'READ', 'RECORD', 'RUN', 'GUIDE', 'DEBUG', 'VERBOSE', 'DUMP-FS', 'PUT-KEY',]
        
        return args_required, args_optional