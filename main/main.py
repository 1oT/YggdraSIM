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

import atexit
import sys 
import os 
import importlib 
import shutil

try :
    import readline
except ImportError :
    readline =None


CURRENT_DIR =os .path .dirname (os .path .abspath (__file__ ))
PROJECT_ROOT =None 

if getattr (sys ,'frozen',False )and hasattr (sys ,'_MEIPASS'):
    PROJECT_ROOT =sys ._MEIPASS 
else :

    possible_roots =[
    CURRENT_DIR ,
    os .path .dirname (CURRENT_DIR ),
    os .path .dirname (os .path .dirname (CURRENT_DIR ))
    ]

    for candidate in possible_roots :
        if os .path .exists (os .path .join (candidate ,"SCP03")):
            PROJECT_ROOT =candidate 
            break 

if PROJECT_ROOT is None :
    PROJECT_ROOT =CURRENT_DIR 

if PROJECT_ROOT not in sys .path :
    sys .path .insert (0 ,PROJECT_ROOT )

from yggdrasim_common.plugin_runtime import ensure_plugins_loaded
from yggdrasim_common.card_backend import (
    describe_card_backend,
    get_card_backend,
    get_card_backend_source,
    get_default_sim_eim_identity_path,
    get_default_sim_euicc_store_root,
    get_default_sim_isdr_config_path,
    get_sim_eim_identity_path,
    get_sim_eim_identity_source,
    get_sim_euicc_store_root,
    get_sim_euicc_store_root_source,
    get_sim_isdr_config_path,
    get_sim_isdr_config_source,
    get_default_sim_quirks_path,
    get_sim_profile_store_path,
    get_sim_profile_store_path_source,
    get_sim_quirks_path,
    get_sim_quirks_source,
    set_card_backend,
    set_sim_eim_identity_path,
    set_sim_euicc_store_root,
    set_sim_isdr_config_path,
    set_sim_profile_store_path,
    set_sim_quirks_path,
)
from yggdrasim_common.process_debug import add_debug_argument, set_global_debug
from yggdrasim_common.quit_control import QuitAllRequested

ensure_plugins_loaded ()


DIRS ={
"LICENSE":os .path .join (PROJECT_ROOT ,"LICENSE")
}

MAIN_HISTORY_FILE =os .path .join (os .path .expanduser ("~"),".yggdrasim_main_history")

class Colors :
    """ANSI terminal colors derived from hex palette values."""

    @staticmethod
    def _hex_to_ansi (hex_color ):
        hex_value =hex_color .lstrip ('#')
        red =int (hex_value [0 :2 ],16 )
        green =int (hex_value [2 :4 ],16 )
        blue =int (hex_value [4 :6 ],16 )
        return f'\033[38;2;{red};{green};{blue}m'

    HEADER_HEX ='#5FDCCB'
    BLUE_HEX ='#8AA7FF'
    CYAN_HEX ='#93F7FF'
    GREEN_HEX ='#8DFF8D'
    WARNING_HEX ='#FFF08F'
    FAIL_HEX ='#FF9A9A'
    BROWN_HEX ='#C99749'
    WHITE_HEX ='#F7FCFF'

    HEADER =_hex_to_ansi .__func__ (HEADER_HEX )
    BLUE =_hex_to_ansi .__func__ (BLUE_HEX )
    CYAN =_hex_to_ansi .__func__ (CYAN_HEX )
    GREEN =_hex_to_ansi .__func__ (GREEN_HEX )
    WARNING =_hex_to_ansi .__func__ (WARNING_HEX )
    FAIL =_hex_to_ansi .__func__ (FAIL_HEX )
    BROWN =_hex_to_ansi .__func__ (BROWN_HEX )
    WHITE =_hex_to_ansi .__func__ (WHITE_HEX )
    ENDC ='\033[0m'
    BOLD ='\033[1m'

def setup_paths ():
    """Ensures PROJECT_ROOT is in sys.path."""
    if PROJECT_ROOT not in sys .path :
        sys .path .insert (0 ,PROJECT_ROOT )


def setup_history ():
    if readline is None :
        return
    try :
        if os .path .exists (MAIN_HISTORY_FILE ):
            readline .read_history_file (MAIN_HISTORY_FILE )
        readline .set_history_length (1000 )
    except Exception :
        pass
    atexit .register (save_history )

    try :
        if readline .__doc__ is not None and "libedit"in readline .__doc__ :
            readline .parse_and_bind ("bind ^I rl_complete")
        else :
            readline .parse_and_bind ("tab: complete")
    except Exception :
        pass


def save_history ():
    if readline is None :
        return
    try :
        readline .write_history_file (MAIN_HISTORY_FILE )
    except Exception :
        pass

def clear_screen ():
    os .system ('cls'if os .name =='nt'else 'clear')

def pause ():
    input (f"\n{Colors.CYAN}Press Enter to return to menu...{Colors.ENDC}")


def _display_sim_profile_store_override ()->str :
    current_override =get_sim_profile_store_path ()
    if len (current_override )>0 :
        return current_override
    return "(derived from eUICC store root + active EID)"


def _format_value_source (value_text :str ,source_text :str )->str :
    normalized_value =str (value_text or "").strip ()
    normalized_source =str (source_text or "").strip ()
    if len (normalized_source )==0 :
        return normalized_value
    return f"{normalized_value} [{normalized_source}]"


def _build_active_backend_banner_lines ()->list [str ]:
    backend_summary =describe_card_backend ()
    backend_color =Colors .CYAN if get_card_backend ()=="sim" else Colors .WARNING
    backend_display =_format_value_source (backend_summary ,get_card_backend_source ())
    lines =[
    f" {Colors.BOLD}{Colors.WHITE}Active card backend:{Colors.ENDC} "
    f"{Colors.BOLD}{backend_color}{backend_display}{Colors.ENDC}"
    ]
    if get_card_backend ()=="sim":
        isdr_display =_format_value_source (
        get_sim_isdr_config_path ()or '(workspace default unavailable)',
        get_sim_isdr_config_source (),
        )
        quirks_display =_format_value_source (
        get_sim_quirks_path ()or '(workspace default unavailable)',
        get_sim_quirks_source (),
        )
        eim_identity_display =_format_value_source (
        get_sim_eim_identity_path ()or '(workspace default unavailable)',
        get_sim_eim_identity_source (),
        )
        euicc_display =_format_value_source (
        get_sim_euicc_store_root ()or get_default_sim_euicc_store_root (),
        get_sim_euicc_store_root_source (),
        )
        profile_display =_format_value_source (
        _display_sim_profile_store_override (),
        get_sim_profile_store_path_source (),
        )
        lines .extend ([
        f"   ISDR config          : {isdr_display}",
        f"   Quirks file          : {quirks_display}",
        f"   eIM identity         : {eim_identity_display}",
        f"   eUICC store root     : {euicc_display}",
        f"   Profile store        : {profile_display}",
        ])
    return lines


def _apply_runtime_path_override (user_input :str ,setter ,success_label :str ,cleared_label :str )->None :
    normalized_input =str (user_input or "").strip ()
    if normalized_input .upper ()=="NONE":
        setter ("")
        print (f"\n{Colors.GREEN}[+] {cleared_label}{Colors.ENDC}")
        return
    setter (normalized_input )
    print (f"\n{Colors.GREEN}[+] {success_label}: {normalized_input}{Colors.ENDC}")


def _normalized_runtime_path (path_text :str )->str :
    return os .path .abspath (os .path .expanduser (str (path_text or "").strip ()))


def _path_is_same_or_child (candidate_path :str ,parent_path :str )->bool :
    candidate =str (candidate_path or "").strip ()
    parent =str (parent_path or "").strip ()
    if len (candidate )==0 or len (parent )==0 :
        return False
    try :
        return os .path .commonpath ([_normalized_runtime_path (candidate ),_normalized_runtime_path (parent )])==_normalized_runtime_path (parent )
    except Exception :
        return False


def _remove_runtime_target (path_text :str )->bool :
    normalized =str (path_text or "").strip ()
    if len (normalized )==0 :
        return False
    absolute_path =_normalized_runtime_path (normalized )
    if absolute_path in ("",os .path .sep ):
        return False
    if os .path .isdir (absolute_path ):
        shutil .rmtree (absolute_path ,ignore_errors =False )
        return True
    if os .path .exists (absolute_path ):
        os .remove (absolute_path )
        return True
    return False


def _reset_simulator_baseline ()->None :
    selected_euicc_store_root =get_sim_euicc_store_root ()
    selected_profile_store_override =get_sim_profile_store_path ()
    selected_eim_identity =get_sim_eim_identity_path ()
    default_isdr_config =get_default_sim_isdr_config_path ()
    default_quirks =get_default_sim_quirks_path ()
    default_eim_identity =get_default_sim_eim_identity_path ()
    print (f"\n{Colors.WARNING}[!] This will delete simulator state and restore workspace personality defaults.{Colors.ENDC}")
    print (f"    eUICC store root     : {selected_euicc_store_root}")
    if len (selected_profile_store_override )>0 :
        print (f"    Profile store override: {selected_profile_store_override}")
    if _normalized_runtime_path (selected_eim_identity )!=_normalized_runtime_path (default_eim_identity ):
        print (f"    eIM identity override: {selected_eim_identity}")
    print (f"    Workspace ISDR config : {default_isdr_config}")
    print (f"    Workspace quirks file : {default_quirks}")
    print (f"    Workspace eIM identity: {default_eim_identity}")
    confirm =input ("Type Y to continue: ").strip ().upper ()
    if confirm not in ("Y","YES"):
        print (f"\n{Colors.WARNING}[*] Simulator baseline reset cancelled.{Colors.ENDC}")
        return
    try :
        profile_store_removed =False
        if len (selected_profile_store_override )>0 and _path_is_same_or_child (
        selected_profile_store_override ,
        selected_euicc_store_root ,
        )is False :
            profile_store_removed =_remove_runtime_target (selected_profile_store_override )
        euicc_store_removed =_remove_runtime_target (selected_euicc_store_root )
        isdr_removed =_remove_runtime_target (default_isdr_config )
        quirks_removed =_remove_runtime_target (default_quirks )
        eim_identity_removed =_remove_runtime_target (default_eim_identity )
        set_card_backend ("sim")
        set_sim_isdr_config_path ("")
        set_sim_quirks_path ("")
        set_sim_eim_identity_path ("")
        set_sim_euicc_store_root ("")
        set_sim_profile_store_path ("")
        reseeded_isdr_config =get_default_sim_isdr_config_path ()
        reseeded_quirks =get_default_sim_quirks_path ()
        reseeded_eim_identity =get_default_sim_eim_identity_path ()
        fresh_euicc_store_root =get_default_sim_euicc_store_root ()
        print (f"\n{Colors.GREEN}[+] Simulator baseline reset complete.{Colors.ENDC}")
        print (f"    Removed eUICC store  : {'yes'if euicc_store_removed else 'already empty / missing'}")
        if len (selected_profile_store_override )>0 :
            print (f"    Removed profile store: {'yes'if profile_store_removed else 'not needed / missing'}")
        print (f"    Reset ISDR config    : {'yes'if isdr_removed else 'reseeded from template'}")
        print (f"    Reset quirks file    : {'yes'if quirks_removed else 'reseeded from template'}")
        print (f"    Reset eIM identity   : {'yes'if eim_identity_removed else 'reseeded from template'}")
        print (f"    Active backend       : {describe_card_backend ()}")
        print (f"    Fresh eUICC root     : {fresh_euicc_store_root}")
        print (f"    Workspace ISDR config: {reseeded_isdr_config}")
        print (f"    Workspace quirks file: {reseeded_quirks}")
        print (f"    Workspace eIM identity: {reseeded_eim_identity}")
    except Exception as e :
        print (f"\n{Colors.FAIL}[!] Simulator baseline reset failed: {e}{Colors.ENDC}")


def _import_simulator_profile (artifact_path :str ,enable_profile :bool ,persist_backend :bool =True )->int :
    normalized_path =str (artifact_path or "").strip ()
    if len (normalized_path )==0 :
        print (f"{Colors.FAIL}[!] Simulator profile import path was empty.{Colors.ENDC}")
        return 1
    if get_card_backend ()!="sim":
        set_card_backend ("sim",persist =persist_backend )
    try :
        from SIMCARD.engine import SimulatedSimCardEngine
        from SIMCARD.profile_import import import_profile_artifact
        engine =SimulatedSimCardEngine (
        quirks_path =get_sim_quirks_path (),
        isdr_config_path =get_sim_isdr_config_path (),
        euicc_store_root =get_sim_euicc_store_root (),
        profile_store_path =get_sim_profile_store_path (),
        )
        import_result =import_profile_artifact (
        normalized_path ,
        engine .state .profile_store_path ,
        enable =bool (enable_profile ),
        )
        print (
        f"{Colors.GREEN}[+] Imported simulator profile:{Colors.ENDC} "
        f"{import_result.profile_name} "
        f"(ICCID {import_result.iccid}, AID {import_result.aid}, source {import_result.profile_source})"
        )
        print (f"    Store path: {import_result.store_path}")
        return 0
    except Exception as e :
        print (f"{Colors.FAIL}[!] Simulator profile import failed: {e}{Colors.ENDC}")
        return 1


def configure_card_backend ():
    while True :
        clear_screen ()
        current_backend =get_card_backend ()
        current_isdr_config =get_sim_isdr_config_path ()
        default_isdr_config =get_default_sim_isdr_config_path ()
        current_quirks =get_sim_quirks_path ()
        default_quirks =get_default_sim_quirks_path ()
        current_eim_identity =get_sim_eim_identity_path ()
        default_eim_identity =get_default_sim_eim_identity_path ()
        current_euicc_store_root =get_sim_euicc_store_root ()
        default_euicc_store_root =get_default_sim_euicc_store_root ()
        print (f"{Colors.HEADER}=== Card Backend / Simulator Settings ==={Colors.ENDC}\n")
        backend_display =_format_value_source (describe_card_backend (),get_card_backend_source ())
        isdr_display =_format_value_source (current_isdr_config or '(workspace default unavailable)',get_sim_isdr_config_source ())
        quirks_display =_format_value_source (current_quirks or '(workspace default unavailable)',get_sim_quirks_source ())
        eim_identity_display =_format_value_source (current_eim_identity or '(workspace default unavailable)',get_sim_eim_identity_source ())
        euicc_display =_format_value_source (current_euicc_store_root or default_euicc_store_root ,get_sim_euicc_store_root_source ())
        profile_display =_format_value_source (_display_sim_profile_store_override (),get_sim_profile_store_path_source ())
        print (f"Active backend       : {Colors.BOLD}{backend_display}{Colors.ENDC}")
        print (f"ISDR config          : {isdr_display}")
        print (f"Quirks file          : {quirks_display}")
        print (f"eIM identity         : {eim_identity_display}")
        print (f"eUICC store root     : {euicc_display}")
        print (f"Profile store        : {profile_display}")
        print ("")
        print (f"  {Colors.GREEN}[1]{Colors.ENDC} Use physical card reader")
        print (f"  {Colors.CYAN}[2]{Colors.ENDC} Use simulated SIM card")
        print (f"  {Colors.CYAN}[3]{Colors.ENDC} Set / clear ISDR config path")
        print (f"  {Colors.CYAN}[4]{Colors.ENDC} Set / clear quirks file path")
        print (f"  {Colors.CYAN}[E]{Colors.ENDC} Set / clear eIM identity path")
        print (f"  {Colors.CYAN}[5]{Colors.ENDC} Set / clear eUICC store root")
        print (f"  {Colors.CYAN}[6]{Colors.ENDC} Set / clear profile store override")
        print (f"  {Colors.CYAN}[7]{Colors.ENDC} Import simulator profile artifact")
        print (f"  {Colors.CYAN}[8]{Colors.ENDC} Reset simulator overrides to workspace defaults")
        print (f"  {Colors.WARNING}[9]{Colors.ENDC} Reset simulator state + workspace personality to baseline")
        print (f"  {Colors.WHITE}[Q]{Colors.ENDC} Return to main menu")
        choice =input ("\nSelect action: ").strip ().upper ()
        if choice in ("Q",""):
            return
        if choice =='1':
            set_card_backend ("reader")
            print (f"\n{Colors.GREEN}[+] Card backend set to physical reader.{Colors.ENDC}")
            pause ()
            continue
        if choice =='2':
            set_card_backend ("sim")
            print (f"\n{Colors.GREEN}[+] Card backend set to simulated SIM card.{Colors.ENDC}")
            print (f"    Backend summary: {describe_card_backend ()}")
            pause ()
            continue
        if choice =='3':
            user_input =input (
            "Enter ISDR config path "
            f"[blank=keep current, NONE=use workspace default, default hint={default_isdr_config}]: "
            ).strip ()
            if len (user_input )>0 :
                _apply_runtime_path_override (
                user_input ,
                set_sim_isdr_config_path ,
                "ISDR config override set",
                "ISDR config override cleared; workspace default will be used if present",
                )
            pause ()
            continue
        if choice =='4':
            user_input =input (
            "Enter quirks override path "
            f"[blank=keep current, NONE=use workspace default, default hint={default_quirks}]: "
            ).strip ()
            if len (user_input )>0 :
                _apply_runtime_path_override (
                user_input ,
                set_sim_quirks_path ,
                "Quirks override set",
                "Quirks override cleared; workspace default will be used if present",
                )
            pause ()
            continue
        if choice =='E':
            user_input =input (
            "Enter eIM identity path "
            f"[blank=keep current, NONE=use workspace default, default hint={default_eim_identity}]: "
            ).strip ()
            if len (user_input )>0 :
                _apply_runtime_path_override (
                user_input ,
                set_sim_eim_identity_path ,
                "eIM identity override set",
                "eIM identity override cleared; workspace default will be used if present",
                )
            pause ()
            continue
        if choice =='5':
            user_input =input (
            "Enter eUICC store root "
            f"[blank=keep current, NONE=use workspace default, default hint={default_euicc_store_root}]: "
            ).strip ()
            if len (user_input )>0 :
                _apply_runtime_path_override (
                user_input ,
                set_sim_euicc_store_root ,
                "eUICC store root set",
                "eUICC store root override cleared; workspace default will be used",
                )
            pause ()
            continue
        if choice =='6':
            user_input =input (
            "Enter profile store override "
            "[blank=keep current, NONE=use derived EID-scoped store under the selected eUICC root]: "
            ).strip ()
            if len (user_input )>0 :
                _apply_runtime_path_override (
                user_input ,
                set_sim_profile_store_path ,
                "Profile store override set",
                "Profile store override cleared; derived EID-scoped store will be used",
                )
            pause ()
            continue
        if choice =='7':
            artifact_path =input (
            "Enter profile path (.der/.bin/.txt/.hex/tagged SAIP JSON/profile_image.json): "
            ).strip ()
            enable_input =input ("Enable imported profile immediately? [Y/n]: ").strip ().lower ()
            enable_profile =enable_input not in ("n","no","0")
            _import_simulator_profile (artifact_path ,enable_profile )
            pause ()
            continue
        if choice =='8':
            set_card_backend ("sim")
            set_sim_isdr_config_path ("")
            set_sim_quirks_path ("")
            set_sim_eim_identity_path ("")
            set_sim_euicc_store_root ("")
            set_sim_profile_store_path ("")
            print (f"\n{Colors.GREEN}[+] Simulator overrides reset to workspace defaults / derived paths.{Colors.ENDC}")
            pause ()
            continue
        if choice =='9':
            _reset_simulator_baseline ()
            pause ()
            continue
        print (f"\n{Colors.FAIL}[!] Invalid backend selection.{Colors.ENDC}")
        pause ()



def run_scp03 ():
    """Wrapper for SCP03 Package."""
    try :
        import SCP03 .main as scp03_entry 
        importlib .reload (scp03_entry )
        scp03_entry .entry ()
    except SystemExit :
        pass 
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP03 Error: {e}{Colors.ENDC}")
        pause ()

def run_scp03_script ():
    """Wrapper for SCP03 Script Execution."""
    clear_screen ()
    print (f"{Colors.HEADER}=== SCP03 Script Execution ==={Colors.ENDC}")
    script_path =input ("Enter path to script file: ").strip ()
    if not script_path :
        return 
    try :
        import SCP03 .main as scp03_entry 
        importlib .reload (scp03_entry )
        scp03_entry .run_script (script_path )
        pause ()
    except SystemExit :
        pass 
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP03 Script Error: {e}{Colors.ENDC}")
        pause ()

def run_scp03_report ():
    """Wrapper for SCP03 Report & DUMP-FS."""
    try :
        import SCP03 .main as scp03_entry 
        importlib .reload (scp03_entry )
        scp03_entry .run_report_wizard ()
        pause ()
    except SystemExit :
        pass 
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP03 Report Error: {e}{Colors.ENDC}")
        pause ()

def run_scp80 ():
    """Wrapper for modularized SCP80 Package."""

    scp80_path =os .path .join (PROJECT_ROOT ,"SCP80")
    if scp80_path not in sys .path :
        sys .path .insert (0 ,scp80_path )

    try :

        import SCP80 
        importlib .reload (SCP80 )

        if hasattr (SCP80 ,'shell'):
            SCP80 .shell ()
        else :

            from SCP80 .cli import OtaShell 
            OtaShell ().run ()

    except SystemExit :
        pass 
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP80 Error: {e}{Colors.ENDC}")
        pause ()

def run_scp80_script ():
    """Wrapper for SCP80 Script Execution."""
    clear_screen ()
    print (f"{Colors.CYAN}=== SCP80 OTA Script Execution ==={Colors.ENDC}")
    script_path =input ("Enter path to script file: ").strip ()
    if not script_path :
        return 

    scp80_path =os .path .join (PROJECT_ROOT ,"SCP80")
    if scp80_path not in sys .path :
        sys .path .insert (0 ,scp80_path )

    try :
        import SCP80 
        importlib .reload (SCP80 )

        from SCP80 .cli import OtaShell 
        app =OtaShell ()
        app .do_script (script_path )
        pause ()
    except SystemExit :
        pass 
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP80 Script Error: {e}{Colors.ENDC}")
        pause ()

def run_scp11_live ():
    """Wrapper for SCP11 live relay package."""
    try :
        import SCP11 .live .main as scp11_entry
        importlib .reload (scp11_entry )
        client =scp11_entry .SGP22Client ()
        client .run_shell ()
    except SystemExit :
        pass 
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP11 Live Error: {e}{Colors.ENDC}")
        pause ()

def run_scp11_test ():
    """Wrapper for SCP11 test relay package."""
    try :
        import SCP11 .test .main as scp11_entry
        importlib .reload (scp11_entry )
        client =scp11_entry .SGP22Client ()
        client .run_shell ()
    except SystemExit :
        pass 
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP11 Test Error: {e}{Colors.ENDC}")
        pause ()

def run_scp11_local ():
    """Wrapper for the Local SMDPP shell."""
    try :
        import SCP11 .local_access .main as scp11_local_entry
        importlib .reload (scp11_local_entry )
        scp11_local_entry .entry ()
    except SystemExit :
        pass
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP11 Local SMDPP Error: {e}{Colors.ENDC}")
        pause ()

def run_scp11_eim_local ():
    """Wrapper for the Local eIM shell."""
    try :
        import SCP11 .eim_local .main as eim_local_entry
        importlib .reload (eim_local_entry )
        eim_local_entry .entry ()
    except SystemExit :
        pass
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP11 Local eIM Error: {e}{Colors.ENDC}")
        pause ()

def run_profile_package ():
    """Wrapper for SAIP profile package tooling."""
    try :
        import Tools .ProfilePackage .main as profile_package_entry
        importlib .reload (profile_package_entry )
        profile_package_entry .entry ()
    except SystemExit :
        pass
    except Exception as e :
        print (f"{Colors.FAIL}[!] SAIP Tool Error: {e}{Colors.ENDC}")
        pause ()

def run_suci_tool ():
    """Wrapper for SUCI key tooling."""
    try :
        import Tools .SuciTool .main as suci_tool_entry
        importlib .reload (suci_tool_entry )
        suci_tool_entry .entry ()
    except SystemExit :
        pass
    except Exception as e :
        print (f"{Colors.FAIL}[!] SUCI Tool Error: {e}{Colors.ENDC}")
        pause ()

def show_license ():
    clear_screen ()

    print (f"{Colors.HEADER}")
    print (r" __   __               _               ____ ___ __  __ ")
    print (r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
    print (r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
    print (r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
    print (r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
    print (r"      |___/  |___/                                     ")
    print (r"            _     ___ ____ _____ _   _ ____  _____     ")
    print (r"           | |   |_ _/ ___| ____| \ | / ___|| ____|    ")
    print (r"           | |    | | |   |  _| |  \| \___ \|  _|      ")
    print (r"           | |___ | | |___| |___| |\  |___) | |___     ")
    print (r"           |_____|___\____|_____|_| \_|____/|_____|    ")
    print (f"{Colors.ENDC}")

    print (f"{Colors.HEADER}=== GPLv3 LICENSE ==={Colors.ENDC}\n")
    license_path =DIRS ["LICENSE"]

    if os .path .exists (license_path ):
        with open (license_path ,'r')as f :
            lines =f .readlines ()
            for i ,line in enumerate (lines ):
                print (line ,end ='')

                if (i +1 )%20 ==0 :
                    input (f"\n{Colors.CYAN}-- More ({i+1}/{len(lines)}) - Press Enter to continue --{Colors.ENDC}")
    else :
        print (f"{Colors.FAIL}License file not found at: {license_path}{Colors.ENDC}")

    pause ()

def _show_text_document (title :str ,relative_path :str ):
    clear_screen ()
    print (f"{Colors.HEADER}=== {title} ==={Colors.ENDC}\n")
    print (f"{Colors.CYAN}Path:{Colors.ENDC} {relative_path}\n")
    full_path =os .path .join (PROJECT_ROOT ,relative_path )

    if os .path .exists (full_path )==False :
        print (f"{Colors.FAIL}Document not found: {relative_path}{Colors.ENDC}")
        pause ()
        return

    try :
        with open (full_path ,'r',encoding ='utf-8')as handle :
            lines =handle .readlines ()
    except Exception as e :
        print (f"{Colors.FAIL}Could not open document: {e}{Colors.ENDC}")
        pause ()
        return

    if len (lines )==0 :
        print (f"{Colors.WARNING}(Document is empty){Colors.ENDC}")
        pause ()
        return

    for index ,line in enumerate (lines ):
        print (line ,end ='')
        if (index +1 )%20 ==0 and (index +1 )<len (lines ):
            input (f"\n{Colors.CYAN}-- More ({index+1}/{len(lines)}) - Press Enter to continue --{Colors.ENDC}")

    pause ()

def _load_shell_guides ():
    try :
        from SCP03 .interface .guides import ShellGuides
        return ShellGuides
    except Exception as e :
        clear_screen ()
        print (f"{Colors.FAIL}Could not load the SCP03 guide renderer: {e}{Colors.ENDC}")
        pause ()
        return None

def _show_shell_guide_wizard ():
    guides =_load_shell_guides ()
    if guides is None :
        return
    guides .print_guide ("WIZARD")

def _show_shell_guide_topic (topic :str ):
    guides =_load_shell_guides ()
    if guides is None :
        return

    topic_name =str (topic or "").strip ().upper ()
    topic_map ={
    "OTA":guides ._print_ota_guide ,
    "SAIP":guides ._print_saip_guide ,
    "SUCI":guides ._print_suci_guide ,
    }
    printer =topic_map .get (topic_name )
    if printer is None :
        clear_screen ()
        print (f"{Colors.FAIL}Unknown guide topic: {topic_name}{Colors.ENDC}")
        pause ()
        return

    clear_screen ()
    printer ()
    pause ()

def show_guides ():
    while True :
        clear_screen ()
        print (f"{Colors.HEADER}")
        print ("  ____       _     _             ____       _     _      ")
        print (" / ___|_   _(_) __| | ___  ___  / ___|_   _(_) __| | ___ ")
        print ("| |  _| | | | |/ _` |/ _ \\/ __| |  _| | | | |/ _` |/ _ \\")
        print ("| |_| | |_| | | (_| |  __/\\__ \\ |_| | |_| | | (_| |  __/")
        print (" \\____|\\__,_|_|\\__,_|\\___||___/\\____|\\__,_|_|\\__,_|\\___|")
        print (f"{Colors.ENDC}")
        print (f"{Colors.HEADER}=== Suite Guides & Documentation ==={Colors.ENDC}\n")
        print ("Select a module-specific guide or reference document:")
        print (f"  {Colors.GREEN}[1]{Colors.ENDC} Admin Shell guide topics")
        print (f"  {Colors.CYAN}[2]{Colors.ENDC} OTA Simulator guide")
        print (f"  {Colors.HEADER}[3]{Colors.ENDC} eSIM Relay Live guide")
        print (f"  {Colors.HEADER}[4]{Colors.ENDC} eSIM Relay Test guide")
        print (f"  {Colors.HEADER}[5]{Colors.ENDC} Local SMDPP guide")
        print (f"  {Colors.HEADER}[5C]{Colors.ENDC} Local SMDPP certificate override guide")
        print (f"  {Colors.HEADER}[6]{Colors.ENDC} Local eIM overview")
        print (f"  {Colors.HEADER}[6D]{Colors.ENDC} Local eIM detailed guide")
        print (f"  {Colors.HEADER}[6T]{Colors.ENDC} Local eIM package template guide")
        print (f"  {Colors.BLUE}[7]{Colors.ENDC} SAIP Tool guide")
        print (f"  {Colors.BLUE}[8]{Colors.ENDC} SUCI Tool guide")
        print ("")
        print (f"{Colors.BOLD}Suite references:{Colors.ENDC}")
        print (f"  {Colors.WHITE}[R]{Colors.ENDC} Root README")
        print (f"  {Colors.WHITE}[H]{Colors.ENDC} Architecture")
        print (f"  {Colors.WHITE}[N]{Colors.ENDC} NOTICE")
        print (f"  {Colors.WHITE}[Q]{Colors.ENDC} Return to main menu")

        choice =input ("\nSelect guide: ").strip ().upper ()

        if choice =='Q':
            return
        if choice =='1':
            _show_shell_guide_wizard ()
            continue
        if choice =='2':
            _show_shell_guide_topic ("OTA")
            continue
        if choice =='3':
            _show_text_document ("SCP11 Live Relay Guide","SCP11/live/README.md")
            continue
        if choice =='4':
            _show_text_document ("SCP11 Test Relay Guide","SCP11/test/README.md")
            continue
        if choice =='5':
            _show_text_document ("SCP11 Local SMDPP Guide","SCP11/local_access/README.md")
            continue
        if choice =='5C':
            _show_text_document ("SCP11 Local SMDPP Certificate Override Guide","SCP11/local_access/certs/README.md")
            continue
        if choice =='6':
            _show_text_document ("SCP11 Local eIM Overview","SCP11/eim_local/README.md")
            continue
        if choice =='6D':
            _show_text_document ("SCP11 Local eIM Detailed Guide","SCP11/eim_local/GUIDE.md")
            continue
        if choice =='6T':
            _show_text_document ("SCP11 Local eIM Package Template Guide","SCP11/eim_local/eim_packages/templates/README.md")
            continue
        if choice =='7':
            _show_shell_guide_topic ("SAIP")
            continue
        if choice =='8':
            _show_shell_guide_topic ("SUCI")
            continue
        if choice =='R':
            _show_text_document ("YggdraSIM README","README.md")
            continue
        if choice =='H':
            _show_text_document ("YggdraSIM Architecture","ARCHITECTURE.md")
            continue
        if choice =='N':
            _show_text_document ("YggdraSIM NOTICE","NOTICE")
            continue

        print (f"{Colors.FAIL}[!] Invalid guide selection.{Colors.ENDC}")
        input (f"\n{Colors.CYAN}[Press Enter to continue]{Colors.ENDC}")

def show_about ():
    clear_screen ()
    print (f"{Colors.HEADER}")
    print (r" __   __               _               ____ ___ __  __ ")
    print (r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
    print (r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
    print (r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
    print (r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
    print (r"      |___/  |___/                                     ")
    print (r"                _    ____   ___  _   _ _____           ")
    print (r"               / \  | __ ) / _ \| | | |_   _|          ")
    print (r"              / _ \ |  _ \| | | | | | | | |            ")
    print (r"             / ___ \| |_) | |_| | |_| | | |            ")
    print (r"            /_/   \_\____/ \___/ \___/  |_|            ")
    print (f"{Colors.ENDC}")
    print (f"""
    {Colors.BOLD}YggdraSIM Suite v2.0{Colors.ENDC}
    Copyright (C) 2026 Hampus Hellsberg and contributors
    
    YggdraSIM is a specialized research and security auditing toolkit 
    designed for deep interaction with SIM, USIM, and eUICC platforms. 
    The suite facilitates lower-layer communication to analyze secure 
    element behavior and protocol compliance.

    {Colors.WARNING}Feature coverage differs by module. SCP03, SCP80, SCP11 relay, SCP11 Local SMDPP, the Local eIM shell, SAIP tooling, and SUCI key tooling now have separate command surfaces, data roots, and operational limits.{Colors.ENDC}

    {Colors.BOLD}Core Sub-Systems:{Colors.ENDC}
    
    * {Colors.CYAN}SCP03 Admin Shell (Local Management):{Colors.ENDC}
      A high-privilege administrative interface utilizing GlobalPlatform 
      Secure Channel Protocol 03. It enables direct ETSI TS 102 221/222 
      file system operations, security attribute (ARR) decoding, AID alias
      management, registry inspection, and spec-aware wizard flows for
      GlobalPlatform, SGP.22, and telecom administration tasks.

    * {Colors.CYAN}SCP80 OTA Simulator (Remote Management):{Colors.ENDC}
      Implements Remote File Management (RFM) and Over-The-Air (OTA) 
      payload generation with build, wrap, preview, send, raw APDU, and
      script execution paths. It allows auditing 3GPP TS 31.115 and
      ETSI TS 102 225 security layering without requiring a live network core.

    * {Colors.CYAN}SCP11 Client (eSIM Management - Relay):{Colors.ENDC}
      Split relay shells for live-default and test-default certificate work.
      Both expose grouped `LPAd`, `IPAd`, and `IPAe` commands, compact
      discovery, profile state control, `POLL` / `EIM-POLL`, ES9 URL/TLS/CA
      controls, and expert / compatibility commands behind `HELP EXPERT`.

    * {Colors.CYAN}SCP11 Local SMDPP:{Colors.ENDC}
      Direct SCP11 bring-up against ISD-R with `DISCOVER`, `LOAD-PROFILE`,
      `ENABLE-PROFILE`, `DISABLE-PROFILE`, `DELETE-PROFILE`, metadata encode
      and send commands, dedicated certificate override storage, and default
      mutable assets centralized under `Workspace/LocalSMDPP`.

    * {Colors.CYAN}SCP11 Local eIM:{Colors.ENDC}
      Isolated local eIM shell for `ADD-INITIAL-EIM`, `ADD-EIM`,
      `GET-EIM-CONFIG`, `DELETE-EIM`, hotfolder and poll campaigns, direct
      BF36 relay, indirect SM-DP+ handover, BF50 result serialization, and
      identity / certificate defaults centralized under `Workspace/LocalEIM`.

    * {Colors.CYAN}SAIP Tool:{Colors.ENDC}
      A dedicated shell for working with SAIP / profile package files through
      `saip-tool`, including `info`, `tree`, `check`, `dump`, `lint`,
      `INSPECT` (legacy alias `TRANSCODE-TUI`), tagged JSON re-encode, `split`, `extract-apps`, and raw
      subcommand passthrough. Default editable assets now live under the
      top-level `Workspace/SAIP` folder to keep day-to-day profile handling centralized.

    * {Colors.CYAN}SUCI Key Tool:{Colors.ENDC}
      A focused shell for generating SUCI key pairs and exporting public keys
      with `suci-keytool`, including support for `secp256r1` and `curve25519`
      through a workspace-confined `USE` / `GENERATE` / `DUMP` workflow.

    {Colors.BOLD}Acknowledgements:{Colors.ENDC}
    With a big-hearted thank you to the Osmocom community, the `pySim`
    maintainers and contributors, and Martin Paljak, author of
    `GlobalPlatformPro`. Their open tooling and published
    operator references have made practical card work, relay analysis,
    and profile-package handling substantially better.

    {Colors.BOLD}Philosophy:{Colors.ENDC}
    As Yggdrasil connects the Nine Realms in Norse mythology, this 
    suite connects the various layers of secure element communication. 
    It acts as the central conduit between local hardware, remote 
    file systems, and asymmetric provisioning realms.
    """)
    pause ()



def main_menu ():
    setup_paths ()
    setup_history ()
    while True :
        clear_screen ()

        print (f"{Colors.HEADER}")
        print (r" __   __               _               ____ ___ __  __ ")
        print (r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print (r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print (r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print (r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print (r"      |___/  |___/                                     ")
        print (r"        __  __       _        __  __                  ")
        print (r"       |  \/  | __ _(_)_ __  |  \/  | ___ _ __  _   _ ")
        print (r"       | |\/| |/ _` | | '_ \ | |\/| |/ _ \ '_ \| | | |")
        print (r"       | |  | | (_| | | | | || |  | |  __/ | | | |_| |")
        print (r"       |_|  |_|\__,_|_|_| |_||_|  |_|\___|_| |_|\__,_|")
        print (f"")
        print (f"=== Unified Secure Element Research & Auditing Suite ===")
        print (f" [ Admin Shell | OTA Simulator | eSIM Relay Live/Test | Local SMDPP | Local eIM | SAIP Tool | SUCI Tool ]")
        print (f" Created and maintained by Hampus Hellsberg and contributors")
        print ("\n".join (_build_active_backend_banner_lines ()))
        print (f"{Colors.ENDC}")

        menu_lines =[
        f"{Colors.HEADER}==============================={Colors.ENDC}",
        f"{Colors.GREEN}--- Administration ---{Colors.ENDC}",
        f"{Colors.GREEN} [1] Admin Shell - Local Management{Colors.ENDC}",
        f"{Colors.CYAN} [2] OTA Simulator - Remote Management{Colors.ENDC}",
        "",
        f"{Colors.HEADER}--- eSIM / eIM Management ---{Colors.ENDC}",
        f"{Colors.HEADER} [3A] eSIM Management Relay (Live Certificates){Colors.ENDC}",
        f"{Colors.HEADER} [3B] eSIM Management Relay (Test Certificates){Colors.ENDC}",
        f"{Colors.HEADER} [3C] Local SMDPP{Colors.ENDC}",
        f"{Colors.HEADER} [3D] Local eIM{Colors.ENDC}",
        "",
        f"{Colors.BLUE}--- Profile & Key Tools ---{Colors.ENDC}",
        f"{Colors.BLUE} [7] SAIP Tool{Colors.ENDC}",
        f"{Colors.BLUE} [8] SUCI Key Tool{Colors.ENDC}",
        "",
        f"{Colors.WARNING}--- Automation ---{Colors.ENDC}",
        f"{Colors.WARNING} [9A] Admin Shell - Script Execution{Colors.ENDC}",
        f"{Colors.WARNING} [9B] Admin Shell - Report & DUMP-FS{Colors.ENDC}",
        f"{Colors.WARNING} [9C] OTA Simulator - Script Execution{Colors.ENDC}",
        "",
        f"{Colors.CYAN}--- Runtime ---{Colors.ENDC}",
        f"{Colors.CYAN} [C] Card Backend / Simulator Settings{Colors.ENDC}",
        "",
        f"{Colors.WHITE}--- Reference ---{Colors.ENDC}",
        f"{Colors.WHITE} [G] Guides & Documentation{Colors.ENDC}",
        f"{Colors.WHITE} [A] About{Colors.ENDC}",
        f"{Colors.WHITE} [L] License (GPLv3){Colors.ENDC}",
        f"{Colors.WHITE} [Q] Quit{Colors.ENDC}",
        f"{Colors.HEADER}==============================={Colors.ENDC}"
        ]
        print ("\n".join (menu_lines ))

        choice =input ("\nSelect module: ").strip ().upper ()
        _dispatch_main_menu_choice (choice )

def _dispatch_main_menu_choice (choice :str )->None :
    normalized_choice =str (choice or "").strip ().upper ()
    legacy_choice_map ={
    '3':'3A',
    '4':'3B',
    '5':'3C',
    '6':'3D',
    '9':'9A',
    '10':'9B',
    '11':'9C',
    }
    if normalized_choice in legacy_choice_map :
        normalized_choice =legacy_choice_map [normalized_choice ]
    if normalized_choice =='1':
        run_scp03 ()
        return
    if normalized_choice =='2':
        run_scp80 ()
        return
    if normalized_choice =='3A':
        run_scp11_live ()
        return
    if normalized_choice =='3B':
        run_scp11_test ()
        return
    if normalized_choice =='3C':
        run_scp11_local ()
        return
    if normalized_choice =='3D':
        run_scp11_eim_local ()
        return
    if normalized_choice =='7':
        run_profile_package ()
        return
    if normalized_choice =='8':
        run_suci_tool ()
        return
    if normalized_choice =='9A':
        run_scp03_script ()
        return
    if normalized_choice =='9B':
        run_scp03_report ()
        return
    if normalized_choice =='9C':
        run_scp80_script ()
        return
    if normalized_choice =='C':
        configure_card_backend ()
        return
    if normalized_choice =='G':
        show_guides ()
        return
    if normalized_choice =='A':
        show_about ()
        return
    if normalized_choice =='L':
        show_license ()
        return
    if normalized_choice in ('Q','QA'):
        sys .exit (0 )

def run_scp03_cmd (cmd_line :str ,yaml_out :str =None ):
    """Run SCP03 commands non-interactively (for --cmd entrypoint)."""
    try :
        import SCP03 .main as scp03_entry 
        scp03_entry .entry_cmd (cmd_line ,yaml_out =yaml_out )
    except SystemExit :
        pass 
    except Exception as e :
        print (f"{Colors.FAIL}[!] SCP03 Error: {e}{Colors.ENDC}")
        raise 


def _build_cli_parser ():
    import argparse
    parser =argparse .ArgumentParser (description ="YggdraSIM Suite")
    parser .add_argument ("--scp03",action ="store_true",help ="Use SCP03 Admin Shell")
    parser .add_argument ("--cmd",type =str ,help ="Semicolon-separated commands (non-interactive, use with --scp03)")
    parser .add_argument ("--out",type =str ,help ="Output YAML file for --cmd")
    parser .add_argument (
    "--card-backend",
    choices =["reader","sim"],
    default =None,
    help ="Select whether card-facing modules use the physical reader or the simulated SIM backend. When omitted, the last saved selection is reused.",
    )
    parser .add_argument (
    "--sim-isdr-config",
    type =str ,
    help ="Optional JSON config file that seeds the simulated ISD-R/eUICC personality.",
    )
    parser .add_argument (
    "--sim-quirks",
    type =str ,
    help ="Optional Python quirks override file for the simulated SIM backend.",
    )
    parser .add_argument (
    "--sim-eim-identity",
    type =str ,
    help ="Optional JSON file that defines the simulated card's default BF55 eIM identity.",
    )
    parser .add_argument (
    "--sim-euicc-store",
    type =str ,
    help ="Optional directory root for persistent EID-scoped simulated eUICC state.",
    )
    parser .add_argument (
    "--sim-profile-store",
    type =str ,
    help ="Optional directory for persisted simulated-profile artifacts.",
    )
    parser .add_argument (
    "--sim-import-profile",
    type =str ,
    help ="Import a simulated profile from DER/BIN, hex-text DER (.txt/.hex), tagged SAIP JSON, or simulator profile-image JSON before launch.",
    )
    parser .add_argument (
    "--sim-import-enable",
    action ="store_true",
    help ="Enable the imported simulator profile immediately.",
    )
    add_debug_argument (
    parser ,
    help_text ="Enable global debug across modules launched from the wrapper. Without it, per-module debug stays opt-in.",
    )
    return parser


def run_cli (argv =None ):
    parser =_build_cli_parser ()
    args =parser .parse_args (argv )
    global_debug_enabled =bool (getattr (args ,"debug",False ))
    # Only the wrapper flag promotes debug to a process-global default.
    set_global_debug (global_debug_enabled )
    card_backend_value =getattr (args ,"card_backend",None )
    if card_backend_value is None :
        set_card_backend (get_card_backend (),persist =False )
    else :
        set_card_backend (card_backend_value ,persist =False )
    sim_isdr_config_value =getattr (args ,"sim_isdr_config",None )
    if sim_isdr_config_value is not None :
        set_sim_isdr_config_path (sim_isdr_config_value ,persist =False )
    sim_euicc_store_value =getattr (args ,"sim_euicc_store",None )
    if sim_euicc_store_value is not None :
        set_sim_euicc_store_root (sim_euicc_store_value ,persist =False )
    sim_quirks_value =getattr (args ,"sim_quirks",None )
    if sim_quirks_value is not None :
        set_sim_quirks_path (sim_quirks_value ,persist =False )
    sim_eim_identity_value =getattr (args ,"sim_eim_identity",None )
    if sim_eim_identity_value is not None :
        set_sim_eim_identity_path (sim_eim_identity_value ,persist =False )
    sim_profile_store_value =getattr (args ,"sim_profile_store",None )
    if sim_profile_store_value is not None :
        set_sim_profile_store_path (sim_profile_store_value ,persist =False )
    sim_import_profile_value =str (getattr (args ,"sim_import_profile","")or "").strip ()
    if len (sim_import_profile_value )>0 :
        if _import_simulator_profile (
        sim_import_profile_value ,
        bool (getattr (args ,"sim_import_enable",False )),
        persist_backend =False ,
        )!=0 :
            return 1
    if args .scp03 and args .cmd :
        run_scp03_cmd (args .cmd ,yaml_out =args .out )
        return 0
    try :
        main_menu ()
    except QuitAllRequested :
        return 0
    except KeyboardInterrupt :
        return 0
    return 0


if __name__ =="__main__":
    sys .exit (run_cli ())