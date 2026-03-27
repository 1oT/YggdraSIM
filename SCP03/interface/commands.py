# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 Hampus Hellsberg and contributors
# -----------------------------------------------------------------------------

import os 
from typing import Dict ,Tuple ,Callable 
from SCP03 .interface .wizards import InteractiveWizards 
from SCP03 .interface .shell_wizards import ShellInteractiveWizards 

class CommandRegistry :
    """Centralized registry for shell commands and their argument mappings."""

    @staticmethod 
    def _clear_screen ()->None :
        is_nt =False 
        if os .name =='nt':
            is_nt =True 

        if is_nt :
            os .system ('cls')

        is_posix =False 
        if os .name !='nt':
            is_posix =True 

        if is_posix :
            os .system ('clear')

    @staticmethod 
    def build (shell )->Dict [str ,Tuple [Callable ,str ]]:
        """Builds the main command map, binding commands to shell instance methods."""
        return {

        'AUTH-SD':(shell ._handle_auth_scp03 ,""),
        'SCP03-SD':(shell ._handle_auth_scp03 ,""),
        'SCP02-SD':(shell ._handle_auth_scp02 ,""),
        'RESET':(shell ._handle_reset ,""),
        'INFO':(shell ._print_card_info ,""),
        'ATR':(shell ._print_atr_details ,""),
        'KEYS':(shell ._handle_keys ,"[AID]"),
        'LOGOUT':(shell ._handle_logout ,""),
        'CLS':(lambda :CommandRegistry ._clear_screen (),""),
        'OTA':(shell ._run_scp80_tool ,""),


        'MANAGE-PROFILE':(lambda :ShellInteractiveWizards .run_manage_profile_wizard (shell ),""),
        'LIST':(lambda :shell .gp_ctrl .sgp22 .list_profiles (),""),
        'LIST-IOT':(lambda :shell .gp_ctrl .sgp22 .list_profiles (),""),
        'GET-IOT':(lambda :shell .gp_ctrl .sgp22 .run_sgp22_scan (),""),


        'APPS':(lambda :shell .gp_ctrl .list_registry ('APPS'),""),
        'PKGS':(lambda :shell .gp_ctrl .list_registry ('PACKAGES'),""),
        'SD':(lambda :shell .gp_ctrl .list_registry ('SD'),""),
        'GET-DATA':(lambda :ShellInteractiveWizards .run_get_data_wizard (shell ),""),


        'LOCK':(lambda x :shell .gp_ctrl .set_status (x ,0x80 ),"<AID>"),
        'UNLOCK':(lambda x :shell .gp_ctrl .set_status (x ,0x07 ),"<AID>"),
        'DEL':(lambda x :shell .gp_ctrl .delete_object (x ,True ),"<AID>"),
        'STORE-DATA':(shell ._handle_store_data ,"<Hex> [P1] [P2]"),
        'PUT-KEY':(lambda :ShellInteractiveWizards .run_put_key_wizard (shell ),""),
        'SET-STATUS':(lambda :ShellInteractiveWizards .run_set_status (shell ),""),
        'MANAGE-CHANNEL':(lambda :ShellInteractiveWizards .run_manage_channel (shell ),""),


        'WIZARD':(lambda :shell ._handle_install_wizard (),""),


        'FS-ADMIN':(lambda :ShellInteractiveWizards .run_fs_admin_wizard (shell ),""),
        'SCAN':(shell .fs_ctrl .scan_tree ,""),
        'REPORT':(lambda :ShellInteractiveWizards .run_fs_report_wizard (shell ),""),
        'SELECT':(shell ._handle_select ,"<Path/FID>"),
        'READ':(shell .fs_ctrl .read_binary ,"[Path]"),
        'RECORD':(shell .fs_ctrl .read_record ,"<N/ALL/Start-End> [Path]"),
        'UPDATE':(shell ._handle_update ,"BINARY/RECORD <Data>"),
        'DUMP-FS':(shell .do_dump_fs ,"[OutputDir]"),
        'VALIDATE':(shell ._handle_validate ,"[ALL|MF|USIM|ISIM] [ProfileDump.yaml|ProfileDump.json]"),


        'MANAGE-PIN':(lambda x ="":ShellInteractiveWizards .run_manage_pin_wizard (shell ,x ),"[Args]"),


        'RUN-AUTH':(lambda :ShellInteractiveWizards .run_auth_wizard (shell ),""),
        'RUN-AUTH-TEST':(lambda :shell .sec_ctrl .run_auth_test_vector (),""),
        'DERIVE-OPC':(shell ._handle_derive_opc ,"<Ki_hex> <OP_hex>"),


        'SHOW':(shell .show_config ,""),
        'AIDS':(shell .list_aids ,""),
        'SET-AID-ALIAS':(shell ._set_aid_alias ,"<Name> <AID>"),
        'SET-DEFAULT':(shell ._set_defaults ,""),
        'CONFIG':(lambda :ShellInteractiveWizards .run_config_wizard (shell ),""),
        'BINDS':(shell .do_manage_binds ,""),


        'DEBUG':(shell ._toggle_debug ,""),
        'VERBOSE':(shell ._toggle_debug ,""),
        'DECODE':(shell ._handle_decode ,"<Hex>"),


        'EXPORT-EUICC':(shell ._handle_export_euicc ,"[OutputPath.yaml]"),

        'SET-GOLD-PROFILE':(
        shell ._handle_set_gold_profile ,
        "<path> [SGP.32|SGP.22|SGP.02] [AUTH=Y|AUTH=N]",
        ),
        'GOLD-PROFILE':(shell ._handle_show_gold_profile ,""),
        'CLEAR-GOLD-PROFILE':(shell ._handle_clear_gold_profile ,""),
        'PROFILE-DIFF':(
        shell ._handle_profile_diff ,
        "[gold.yaml] [STANDARD] [AUTH=Y|AUTH=N]",
        ),

        'ARR':(shell ._handle_arr ,"[Path]"),


        'CERT-INFO':(shell ._handle_cert_info ,""),


        'GUIDE':(shell ._handle_guide ,"[Topic]"),
        'RUN':(shell .run_script ,"<File> [Out.yaml]"),
        'SCRIPT':(shell .run_script ,"<File>"),
        'HELP':(shell ._print_help ,""),
        'EXIT':(shell ._exit ,""),
        'QA':(shell ._quit_all ,""),
        'Q':(shell ._exit ,"")
        }

    @staticmethod 
    def get_arg_requirements ():
        """Returns tuples of commands that require mandatory or optional arguments."""
        args_required =[
        'SET-AID-ALIAS',
        'SELECT',
        'UPDATE',
        'LOCK',
        'UNLOCK',
        'DEL',
        'SCRIPT',
        'STORE-DATA',
        'DECODE',
        'DERIVE-OPC',
        'SET-GOLD-PROFILE',
        ]
        args_optional =[
        'REPORT',
        'KEYS',
        'READ',
        'RECORD',
        'RUN',
        'GUIDE',
        'DEBUG',
        'VERBOSE',
        'DUMP-FS',
        'MANAGE-PIN',
        'EXPORT-EUICC',
        'ARR',
        'VALIDATE',
        'GOLD-PROFILE',
        'CLEAR-GOLD-PROFILE',
        'PROFILE-DIFF',
        ]

        return args_required ,args_optional 