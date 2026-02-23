# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os
from typing import Dict, Tuple, Callable
from SCP03.interface.wizards import InteractiveWizards
from SCP03.interface.shell_wizards import ShellInteractiveWizards

class CommandRegistry:
    """Centralized registry for shell commands and their argument mappings."""

    @staticmethod
    def _clear_screen() -> None:
        is_nt = False
        if os.name == 'nt':
            is_nt = True
            
        if is_nt:
            os.system('cls')
            
        is_posix = False
        if os.name != 'nt':
            is_posix = True
            
        if is_posix:
            os.system('clear')

    @staticmethod
    def _run_report(shell, x=None) -> None:
        has_x = False
        if x is not None:
            has_x = True
            
        if has_x:
            shell.fs_ctrl.generate_report(x)
            
        is_x_missing = False
        if x is None:
            is_x_missing = True
            
        if is_x_missing:
            shell.fs_ctrl.generate_report()

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
            'CLS': (lambda: CommandRegistry._clear_screen(), ""),
            'OTA': (shell._run_scp80_tool, ""),
            
            # eSIM Profile Management
            'MANAGE-PROFILE': (lambda: ShellInteractiveWizards.run_manage_profile_wizard(shell), ""),
            
            # GlobalPlatform Registry & Data
            'APPS': (lambda: shell.gp_ctrl.list_registry('APPS'), ""),
            'PKGS': (lambda: shell.gp_ctrl.list_registry('PACKAGES'), ""),
            'SD': (lambda: shell.gp_ctrl.list_registry('SD'), ""),
            'GET-DATA': (lambda: ShellInteractiveWizards.run_get_data_wizard(shell), ""),
            
            # Lifecycle
            'LOCK': (lambda x: shell.gp_ctrl.set_status(x, 0x80), "<AID>"),
            'UNLOCK': (lambda x: shell.gp_ctrl.set_status(x, 0x07), "<AID>"),
            'DEL': (lambda x: shell.gp_ctrl.delete_object(x, True), "<AID>"),
            'STORE-DATA': (shell._handle_store_data, "<Hex> [P1] [P2]"),
            'PUT-KEY': (lambda: ShellInteractiveWizards.run_put_key_wizard(shell), ""),
            'SET-STATUS': (lambda: ShellInteractiveWizards.run_set_status(shell), ""),
            'MANAGE-CHANNEL': (lambda: ShellInteractiveWizards.run_manage_channel(shell), ""),

            # Wizards / Builders
            'WIZARD': (lambda: InteractiveWizards.run_wizard_menu(shell.transport, "A000000151000000"), ""),

            # File System
            'FS-ADMIN': (lambda: ShellInteractiveWizards.run_fs_admin_wizard(shell), ""),
            'SCAN': (shell.fs_ctrl.scan_tree, ""),
            'REPORT': (lambda: ShellInteractiveWizards.run_fs_report_wizard(shell), ""),
            'SELECT': (lambda x: shell.fs_ctrl.select(x), "<Path/FID>"),
            'READ': (shell.fs_ctrl.read_binary, "[Path]"),
            'RECORD': (shell.fs_ctrl.read_record, "<N/ALL> [Path]"),
            'UPDATE': (shell._handle_update, "BINARY/RECORD <Data>"),
            'DUMP-FS': (shell.do_dump_fs, "[OutputDir]"),

            # Security
            'MANAGE-PIN': (lambda x="": ShellInteractiveWizards.run_manage_pin_wizard(shell, x), "[Args]"),
            
            # Auth
            'RUN-AUTH': (lambda: ShellInteractiveWizards.run_auth_wizard(shell), ""),

            # Config
            'SHOW': (shell.show_config, ""),
            'AIDS': (shell.list_aids, ""),
            'SET-AID-ALIAS': (shell._set_aid_alias, "<Name> <AID>"),
            'SET-DEFAULT': (shell._set_defaults, ""),
            'CONFIG': (lambda: ShellInteractiveWizards.run_config_wizard(shell), ""),
            
            # Hidden / Developer
            'DEBUG': (shell._toggle_debug, ""),
            'VERBOSE': (shell._toggle_debug, ""),
            'DECODE': (shell._handle_decode, "<Hex>"),
            
            # System
            'GUIDE': (shell._handle_guide, "[Topic]"),
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
            'SET-AID-ALIAS', 'SELECT', 'UPDATE', 'LOCK', 'UNLOCK', 'DEL', 'SCRIPT', 
            'STORE-DATA', 'DECODE'
        ]
        args_optional = ['REPORT', 'KEYS', 'READ', 'RECORD', 'RUN', 'GUIDE', 'DEBUG', 'VERBOSE', 'DUMP-FS', 'MANAGE-PIN']
        
        return args_required, args_optional