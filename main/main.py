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
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

# PEP 563: stringify annotations so optional imports such as
# ``hil_bridge_runtime`` (set to ``None`` in the clean bundle) do not
# blow up at module import time when their types are only referenced in
# function signatures. Without this, ``from yggdrasim_main (clean)`` dies
# with ``AttributeError: 'NoneType' object has no attribute 'HilBridgeUserServiceOptions'``
# at the first annotated def.
from __future__ import annotations

import atexit
import sys 
import os 
import importlib 
import shutil
import subprocess
import threading
import time
from pathlib import Path

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

from yggdrasim_common.plugin_runtime import ensure_plugins_loaded ,plugin_load_errors 
from yggdrasim_common.card_backend import (
    CARD_BACKEND_ENV,
    SIM_EIM_IDENTITY_ENV,
    SIM_EUICC_STORE_ENV,
    SIM_ISDR_CONFIG_ENV,
    SIM_PROFILE_STORE_ENV,
    SIM_QUIRKS_ENV,
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
    is_sim_quirks_disabled,
    set_card_backend,
    set_sim_eim_identity_path,
    set_sim_euicc_store_root,
    set_sim_isdr_config_path,
    set_sim_profile_store_path,
    set_sim_quirks_path,
)
from yggdrasim_common.process_debug import (
    add_debug_argument,
    install_noisy_warning_filters,
    set_global_debug,
)
from yggdrasim_common.quit_control import QuitAllRequested
from yggdrasim_common.remote_card_args import (
    add_remote_card_arguments as _add_remote_card_arguments,
    apply_remote_card_arguments as _apply_remote_card_arguments,
    describe_remote_card_state as _describe_remote_card_state,
)
from yggdrasim_common import flavor as yggdrasim_flavor
from yggdrasim_common import env_flags as yggdrasim_env_flags
from yggdrasim_common.nord_palette import NordHex as _NordHex
try :
    from yggdrasim_common import hil_bridge_runtime
except ImportError :
    hil_bridge_runtime =None

# Persisted YGGDRASIM_* overrides must land in os.environ before the
# plugin loader runs, because YGGDRASIM_ALLOW_PLUGINS /
# YGGDRASIM_DISALLOW_PLUGINS are both consumed by ensure_plugins_loaded().
# Any value already set in the environment (e.g. from the shell, systemd,
# or an argparse --flag in run_cli) is left untouched so explicit
# invocations keep priority.
_APPLIED_PERSISTED_OVERRIDES =yggdrasim_env_flags .apply_persisted_env_overrides ()

ensure_plugins_loaded ()


DIRS ={
"LICENSE":os .path .join (PROJECT_ROOT ,"LICENSE")
}

MAIN_HISTORY_FILE =os .path .join (os .path .expanduser ("~"),".yggdrasim_main_history")


_PLUGIN_LOAD_BANNER_EMITTED =False 


def _emit_plugin_load_banner (stream =None )->None :
    """Surface plugin load errors once per process on launcher start.

    Errors stored by :class:`PluginManager` are opaque to downstream
    callers. Without a startup banner, operators see silently missing
    capabilities (SCP11 polling, HIL bridge helpers, etc) and cannot
    tell whether the plugin file threw at import time or whether the
    gate env flag was simply off.
    """
    global _PLUGIN_LOAD_BANNER_EMITTED 
    if _PLUGIN_LOAD_BANNER_EMITTED :
        return 
    _PLUGIN_LOAD_BANNER_EMITTED =True 
    try :
        errors =plugin_load_errors ()
    except (RuntimeError ,OSError ):
        return 
    if not errors :
        return 
    target =stream if stream is not None else sys .stderr 
    try :
        target .write ("[plugins] one or more entries did not load:\n")
        for key ,message in sorted (errors .items ()):
            if key =="__gate__":
                target .write (f"  - gate: {message}\n")
                continue 
            target .write (f"  - {key}: {message}\n")
    except (OSError ,ValueError ):
        pass 

class Colors :
    """ANSI terminal colours sourced from the canonical Nord palette.

    Hex constants and the ``_hex_to_ansi`` helper stay on the class so
    third-party launchers that introspect ``main.Colors`` keep working;
    the values themselves now flow from
    :mod:`yggdrasim_common.nord_palette`.
    """

    @staticmethod
    def _hex_to_ansi (hex_color ):
        hex_value =hex_color .lstrip ('#')
        red =int (hex_value [0 :2 ],16 )
        green =int (hex_value [2 :4 ],16 )
        blue =int (hex_value [4 :6 ],16 )
        return f'\033[38;2;{red};{green};{blue}m'

    HEADER_HEX =_NordHex .FROST_TEAL
    BLUE_HEX =_NordHex .FROST_BLUE
    CYAN_HEX =_NordHex .FROST_CYAN
    GREEN_HEX =_NordHex .AURORA_GREEN
    WARNING_HEX =_NordHex .AURORA_YELLOW
    FAIL_HEX =_NordHex .AURORA_RED
    BROWN_HEX =_NordHex .AURORA_ORANGE
    WHITE_HEX =_NordHex .SNOW_2

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
    except OSError :
        pass
    atexit .register (save_history )

    try :
        if readline .__doc__ is not None and "libedit"in readline .__doc__ :
            readline .parse_and_bind ("bind ^I rl_complete")
        else :
            readline .parse_and_bind ("tab: complete")
    except OSError :
        pass


def save_history ():
    if readline is None :
        return
    try :
        readline .write_history_file (MAIN_HISTORY_FILE )
    except OSError :
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


def _quirks_value_display ()->str :
    # When the operator has explicitly opted out the resolver returns
    # the empty string AND flags the source as "disabled". Rendering
    # "(workspace default unavailable)" on that path would be
    # misleading, so we surface the opt-out intent literally.
    if is_sim_quirks_disabled ():
        return "(none - simulator runs with empty quirks registry)"
    current =get_sim_quirks_path ()
    if len (current )>0 :
        return current
    return "(workspace default unavailable)"


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
        _quirks_value_display (),
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
    except (ValueError ,OSError ):
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
        current_isdr_config =get_sim_isdr_config_path ()
        default_isdr_config =get_default_sim_isdr_config_path ()
        default_quirks =get_default_sim_quirks_path ()
        current_eim_identity =get_sim_eim_identity_path ()
        default_eim_identity =get_default_sim_eim_identity_path ()
        current_euicc_store_root =get_sim_euicc_store_root ()
        default_euicc_store_root =get_default_sim_euicc_store_root ()
        print (f"{Colors.HEADER}=== Card Backend / Simulator Settings ==={Colors.ENDC}\n")
        backend_display =_format_value_source (describe_card_backend (),get_card_backend_source ())
        isdr_display =_format_value_source (current_isdr_config or '(workspace default unavailable)',get_sim_isdr_config_source ())
        quirks_display =_format_value_source (_quirks_value_display (),get_sim_quirks_source ())
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
        if is_sim_quirks_disabled ():
            print (f"  {Colors.CYAN}[D]{Colors.ENDC} Re-enable simulator quirks (resolve workspace default)")
        else :
            print (f"  {Colors.CYAN}[D]{Colors.ENDC} Disable simulator quirks (run with empty registry)")
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
        if choice =='D':
            if is_sim_quirks_disabled ():
                set_sim_quirks_path ("")
                print (
                f"\n{Colors.GREEN}[+] Simulator quirks re-enabled. "
                f"The workspace default at {default_quirks} will be used if present.{Colors.ENDC}"
                )
            else :
                set_sim_quirks_path ("none")
                print (
                f"\n{Colors.GREEN}[+] Simulator quirks disabled. "
                f"Loader will skip {default_quirks} and boot with an empty registry.{Colors.ENDC}"
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



def _hil_bridge_service_state_text (service_state :dict )->str :
    error_text =str (service_state .get ("error","")or "").strip ()
    load_state =str (service_state .get ("loadState","")or "").strip ()
    unit_file_state =str (service_state .get ("unitFileState","")or "").strip ()
    active_state =str (service_state .get ("activeState","")or "").strip ()
    sub_state =str (service_state .get ("subState","")or "").strip ()
    if len (error_text )>0 and len (load_state )==0 and len (active_state )==0 :
        return f"Unavailable ({error_text})"
    display_parts =[]
    if len (load_state )>0 :
        display_parts .append (f"load={load_state}")
    if len (unit_file_state )>0 :
        display_parts .append (f"unit={unit_file_state}")
    if len (active_state )>0 :
        display_parts .append (f"active={active_state}")
    if len (sub_state )>0 :
        display_parts .append (f"sub={sub_state}")
    if len (display_parts )==0 :
        if len (error_text )>0 :
            return error_text
        return "unknown"
    return ", ".join (display_parts )


_HIL_BRIDGE_VIEW_MODE_RAW ="raw"
_HIL_BRIDGE_VIEW_MODE_RAW_WIRESHARK ="raw_wireshark"
_HIL_BRIDGE_VIEW_MODE_TERMSHARK ="termshark"
_HIL_BRIDGE_CAPTURE_INTERFACE_ENV ="YGGDRASIM_HIL_CAPTURE_INTERFACE"
_HIL_BRIDGE_WIRESHARK_BIN_ENV ="YGGDRASIM_HIL_WIRESHARK_BIN"
_HIL_BRIDGE_TERMSHARK_BIN_ENV ="YGGDRASIM_HIL_TERMSHARK_BIN"
_HIL_BRIDGE_TERMSHARK_WARMUP_ENV ="YGGDRASIM_HIL_TERMSHARK_WARMUP_SECONDS"


def _normalize_hil_bridge_view_mode (value_text :str )->str :
    normalized_value =str (value_text or "").strip ().lower ()
    if normalized_value in ("1","raw","raw-apdu","raw_apdu"):
        return _HIL_BRIDGE_VIEW_MODE_RAW
    if normalized_value in ("2","raw+wireshark","raw_wireshark","wireshark"):
        return _HIL_BRIDGE_VIEW_MODE_RAW_WIRESHARK
    if normalized_value in ("3","termshark"):
        return _HIL_BRIDGE_VIEW_MODE_TERMSHARK
    return ""


def _hil_bridge_view_mode_label (view_mode :str )->str :
    normalized_mode =_normalize_hil_bridge_view_mode (view_mode )
    if normalized_mode ==_HIL_BRIDGE_VIEW_MODE_RAW_WIRESHARK :
        return "Raw APDU stream + Wireshark"
    if normalized_mode ==_HIL_BRIDGE_VIEW_MODE_TERMSHARK :
        return "Decoded APDU view in terminal"
    return "Raw APDU stream only"


def _hil_bridge_view_mode_uses_gsmtap (view_mode :str )->bool :
    normalized_mode =_normalize_hil_bridge_view_mode (view_mode )
    return normalized_mode !=_HIL_BRIDGE_VIEW_MODE_RAW


def _hil_bridge_capture_interface ()->str :
    override_value =str (os .environ .get (_HIL_BRIDGE_CAPTURE_INTERFACE_ENV ,"")or "").strip ()
    if len (override_value )>0 :
        return override_value
    if sys .platform =="darwin":
        return "lo0"
    return "lo"


def _hil_bridge_gsmtap_capture_filter ()->str :
    return "udp port 4729"


def _hil_bridge_capture_binary_path (default_name :str ,env_name :str )->str :
    override_value =str (os .environ .get (env_name ,"")or "").strip ()
    if len (override_value )>0 :
        resolved_override =shutil .which (override_value )
        if resolved_override is not None :
            return resolved_override
        expanded_override =os .path .abspath (os .path .expanduser (override_value ))
        if os .path .isfile (expanded_override ):
            return expanded_override
        return ""
    resolved_default =shutil .which (default_name )
    if resolved_default is None :
        return ""
    return resolved_default


def _hil_bridge_wireshark_binary_path ()->str :
    return _hil_bridge_capture_binary_path ("wireshark",_HIL_BRIDGE_WIRESHARK_BIN_ENV )


def _hil_bridge_termshark_binary_path ()->str :
    return _hil_bridge_capture_binary_path ("termshark",_HIL_BRIDGE_TERMSHARK_BIN_ENV )


def _hil_bridge_tshark_binary_path ()->str :
    resolved_binary =shutil .which ("tshark")
    if resolved_binary is None :
        return ""
    return resolved_binary


def _hil_bridge_termshark_runtime_root ()->str :
    return os .path .join (PROJECT_ROOT ,"state","hil_termshark")


def _hil_bridge_termshark_config_home ()->str :
    return os .path .join (_hil_bridge_termshark_runtime_root (),"config")


def _hil_bridge_termshark_cache_home ()->str :
    return os .path .join (_hil_bridge_termshark_runtime_root (),"cache")


def _hil_bridge_termshark_capture_path ()->str :
    return os .path .join (_hil_bridge_termshark_runtime_root (),"live_capture.pcap")


def _hil_bridge_termshark_capture_pcap_wrapper_path ()->str :
    return os .path .join (PROJECT_ROOT ,"Tools","HilBridge","termshark_capture_pcap.py")


def _hil_bridge_termshark_capture_mirror_path ()->str :
    return os .path .join (PROJECT_ROOT ,"Tools","HilBridge","termshark_capture_mirror.py")


def _hil_bridge_termshark_capture_command ()->str :
    capture_wrapper_path =_hil_bridge_termshark_capture_pcap_wrapper_path ()
    if os .path .isfile (capture_wrapper_path ):
        return capture_wrapper_path
    tshark_binary =shutil .which ("tshark")
    if tshark_binary is not None :
        return tshark_binary
    dumpcap_binary =shutil .which ("dumpcap")
    if dumpcap_binary is not None :
        return dumpcap_binary
    return "tshark"


def _hil_bridge_termshark_dumpcap_command ()->str :
    dumpcap_binary =shutil .which ("dumpcap")
    if dumpcap_binary is not None :
        return dumpcap_binary
    tshark_binary =shutil .which ("tshark")
    if tshark_binary is not None :
        return tshark_binary
    return "dumpcap"


def _hil_bridge_live_capture_command ()->str :
    dumpcap_binary =shutil .which ("dumpcap")
    if dumpcap_binary is not None :
        return dumpcap_binary
    tshark_binary =shutil .which ("tshark")
    if tshark_binary is not None :
        return tshark_binary
    return "dumpcap"


def _hil_bridge_terminfo_supports (term_name :str )->bool :
    normalized_term =str (term_name or "").strip ()
    if len (normalized_term )==0 :
        return False
    infocmp_binary =shutil .which ("infocmp")
    if infocmp_binary is None :
        return normalized_term in {
        "screen-256color",
        "tmux-256color",
        "xterm-256color",
        "xterm",
        }
    try :
        completed =subprocess .run (
        [infocmp_binary ,normalized_term ],
        stdout =subprocess .DEVNULL ,
        stderr =subprocess .DEVNULL ,
        check =False ,
        timeout =1 ,
        )
    except (OSError ,subprocess .SubprocessError ):
        return False
    return completed .returncode ==0 


def _hil_bridge_termshark_term_value ()->str :
    current_term =str (os .environ .get ("TERM","")or "").strip ()
    normalized_current =current_term .lower ()
    if len (current_term )>0 and normalized_current !="dumb":
        if "256"in normalized_current or "truecolor"in normalized_current :
            if _hil_bridge_terminfo_supports (current_term ):
                return current_term
    for candidate in ("screen-256color","tmux-256color","xterm-256color","xterm"):
        if _hil_bridge_terminfo_supports (candidate ):
            return candidate
    if len (current_term )>0 and normalized_current !="dumb":
        return current_term
    return "xterm"


def _hil_bridge_termshark_config_toml (term_value :str )->str :
    normalized_term =str (term_value or "").strip ()
    capture_command =_hil_bridge_termshark_capture_command ()
    dumpcap_command =_hil_bridge_termshark_dumpcap_command ()
    return (
    "[main]\n"
    "  colors = false\n"
    f'  capture-command = "{capture_command}"\n'
    f'  dumpcap = "{dumpcap_command}"\n'
    "  ignore-base16-colors = true\n"
    "  respect-colorterm = true\n"
    '  tshark-args = ["-d", "udp.port==4729,gsmtap"]\n'
    f'  term = "{normalized_term}"\n'
    )


def _ensure_hil_bridge_termshark_profile (term_value :str )->tuple [str ,str ]:
    config_home =_hil_bridge_termshark_config_home ()
    cache_home =_hil_bridge_termshark_cache_home ()
    termshark_config_dir =os .path .join (config_home ,"termshark")
    os .makedirs (termshark_config_dir ,exist_ok =True )
    os .makedirs (cache_home ,exist_ok =True )
    config_path =os .path .join (termshark_config_dir ,"termshark.toml")
    with open (config_path ,"w",encoding ="utf-8")as handle :
        handle .write (_hil_bridge_termshark_config_toml (term_value ))
    return config_home ,cache_home


def _hil_bridge_termshark_environment ()->dict [str ,str ]:
    term_value =_hil_bridge_termshark_term_value ()
    config_home ,cache_home =_ensure_hil_bridge_termshark_profile (term_value )
    environment =dict (os .environ )
    environment ["TERM"]=term_value 
    environment ["COLORTERM"]="truecolor"
    environment ["XDG_CONFIG_HOME"]=config_home 
    environment ["XDG_CACHE_HOME"]=cache_home 
    return environment


def _hil_bridge_termshark_warmup_seconds ()->float :
    raw_value =str (os .environ .get (_HIL_BRIDGE_TERMSHARK_WARMUP_ENV ,"")or "").strip ()
    if len (raw_value )==0 :
        return 2.0
    try :
        parsed_value =float (raw_value )
    except (TypeError ,ValueError ):
        return 2.0
    return max (0.0 ,min (10.0 ,parsed_value ))


def _hil_bridge_termshark_log_path ()->str :
    return os .path .join (_hil_bridge_termshark_cache_home (),"termshark","termshark.log")


def _hil_bridge_termshark_cache_pcaps_root ()->str :
    return os .path .join (_hil_bridge_termshark_cache_home (),"termshark","pcaps")


def _hil_bridge_read_text_file_tail (path_text :str ,max_bytes :int =16384 )->str :
    normalized_path =str (path_text or "").strip ()
    if len (normalized_path )==0 :
        return ""
    read_limit =16384
    try :
        parsed_limit =int (max_bytes or 16384 )
    except (TypeError ,ValueError ):
        parsed_limit =16384
    if parsed_limit >0 :
        read_limit =parsed_limit
    try :
        with open (normalized_path ,"rb")as handle :
            handle .seek (0 ,os .SEEK_END )
            file_size =handle .tell ()
            if file_size <=0 :
                return ""
            read_size =min (read_limit ,file_size )
            if file_size >read_size :
                handle .seek (-read_size ,os .SEEK_END )
            else :
                handle .seek (0 )
            payload =handle .read ()
    except OSError :
        return ""
    try :
        return payload .decode ("utf-8",errors ="ignore")
    except (UnicodeDecodeError ,AttributeError ):
        return ""


def _hil_bridge_existing_file_size (path_text :str )->int :
    normalized_path =str (path_text or "").strip ()
    if len (normalized_path )==0 :
        return -1
    try :
        return int (os .path .getsize (normalized_path ))
    except OSError :
        return -1


def _hil_bridge_latest_termshark_cache_pcap_path ()->str :
    pcaps_root =_hil_bridge_termshark_cache_pcaps_root ()
    try :
        candidate_names =os .listdir (pcaps_root )
    except OSError :
        return ""
    candidate_paths =[]
    for raw_name in candidate_names :
        current_path =os .path .join (pcaps_root ,str (raw_name or ""))
        if os .path .isfile (current_path )==False :
            continue
        candidate_paths .append (current_path )
    if len (candidate_paths )==0 :
        return ""
    candidate_paths .sort (key =os .path .getmtime ,reverse =True )
    return str (candidate_paths [0 ]or "")


def _hil_bridge_wait_for_termshark_log_marker (
    marker_text :str ,
    timeout_seconds :float ,
    cancel_event =None ,
)->bool :
    normalized_marker =str (marker_text or "").strip ()
    if len (normalized_marker )==0 :
        return False
    wait_budget =max (0.0 ,float (timeout_seconds or 0.0 ))
    deadline =time .monotonic ()+wait_budget
    while True :
        if cancel_event is not None and cancel_event .is_set ():
            return False
        current_log_tail =_hil_bridge_read_text_file_tail (_hil_bridge_termshark_log_path ())
        if normalized_marker in current_log_tail :
            return True
        if time .monotonic ()>=deadline :
            return False
        time .sleep (0.1)


def _hil_bridge_wait_for_termshark_capture_bytes (
    timeout_seconds :float ,
    cancel_event =None ,
)->bool :
    wait_budget =max (0.0 ,float (timeout_seconds or 0.0 ))
    deadline =time .monotonic ()+wait_budget
    external_capture_path =_hil_bridge_termshark_capture_path ()
    while True :
        if cancel_event is not None and cancel_event .is_set ():
            return False
        latest_cache_pcap_path =_hil_bridge_latest_termshark_cache_pcap_path ()
        cache_path_ready =len (str (latest_cache_pcap_path or "").strip ())>0 
        cache_pcap_size =_hil_bridge_existing_file_size (latest_cache_pcap_path )
        external_capture_size =_hil_bridge_existing_file_size (external_capture_path )
        if cache_pcap_size >24 :
            return True
        if cache_path_ready ==False and external_capture_size >24 :
            return True
        if time .monotonic ()>=deadline :
            return False
        time .sleep (0.1)


def _hil_bridge_clear_termshark_cache_pcaps ()->None :
    pcaps_root =_hil_bridge_termshark_cache_pcaps_root ()
    try :
        candidate_names =os .listdir (pcaps_root )
    except OSError :
        return
    for raw_name in candidate_names :
        current_path =os .path .join (pcaps_root ,str (raw_name or ""))
        if os .path .isfile (current_path )==False :
            continue
        try :
            os .remove (current_path )
        except OSError :
            pass


def _hil_bridge_send_termshark_wake_packet (cancel_event =None )->None :
    import socket
    from Tools.HilBridge.protocol import GSMTAP_SIM_APDU ,build_gsmtap_packet ,build_simtrace_apdu_payload

    wake_payload =build_simtrace_apdu_payload (b"\x00\xA4\x04\x00",b"\x90\x00")
    packet =build_gsmtap_packet (wake_payload ,subtype =GSMTAP_SIM_APDU ,uplink =True )
    wake_socket =socket .socket (socket .AF_INET ,socket .SOCK_DGRAM )
    try :
        for _ in range (2 ):
            if cancel_event is not None and cancel_event .is_set ():
                return
            wake_socket .sendto (packet ,("127.0.0.1",4729 ))
            time .sleep (0.15)
    finally :
        wake_socket .close ()


def _hil_bridge_prime_termshark_for_bridge_start (
    base_wait_seconds :float ,
    cancel_event =None ,
)->None :
    wait_budget =max (0.0 ,float (base_wait_seconds or 0.0 ))
    iface_wait_seconds =max (0.5 ,min (3.0 ,wait_budget if wait_budget >0.0 else 1.0 ))
    capture_wait_seconds =max (1.0 ,wait_budget )
    _hil_bridge_wait_for_termshark_log_marker (
    "Started Iface command",
    iface_wait_seconds ,
    cancel_event =cancel_event ,
    )
    if cancel_event is not None and cancel_event .is_set ():
        return
    _hil_bridge_send_termshark_wake_packet (cancel_event =cancel_event )
    if cancel_event is not None and cancel_event .is_set ():
        return
    _hil_bridge_wait_for_termshark_capture_bytes (
    capture_wait_seconds ,
    cancel_event =cancel_event ,
    )
    if cancel_event is not None and cancel_event .is_set ():
        return
    time .sleep (0.4)


def _hil_bridge_command_uses_gsmtap (command_value )->bool |None :
    if isinstance (command_value ,list )==False :
        return None
    if len (command_value )==0 :
        return None
    for raw_value in command_value :
        if str (raw_value or "").strip ()=="--no-gsmtap":
            return False
    return True


def _hil_bridge_command_capture_path (command_value )->str |None :
    if isinstance (command_value ,list )==False :
        return None
    capture_flag ="--gsmtap-capture-path"
    for index ,raw_value in enumerate (command_value ):
        current_value =str (raw_value or "").strip ()
        if current_value ==capture_flag :
            if index +1 >=len (command_value ):
                return ""
            return str (command_value [index +1 ]or "").strip ()
        if current_value .startswith (f"{capture_flag}="):
            return current_value .split ("=",1 )[1 ].strip ()
    return ""


def _hil_bridge_capture_path_for_view_mode (view_mode :str )->str :
    normalized_mode =_normalize_hil_bridge_view_mode (view_mode )
    if normalized_mode !=_HIL_BRIDGE_VIEW_MODE_TERMSHARK :
        return ""
    return _hil_bridge_termshark_capture_path ()


def _prompt_hil_bridge_view_mode ()->str :
    while True :
        clear_screen ()
        print (f"{Colors.HEADER}=== HIL Bridge Start Mode ==={Colors.ENDC}\n")
        print ("Choose how the live session should attach after the bridge starts:\n")
        print (f"  {Colors.CYAN}[1]{Colors.ENDC} Raw APDU flow only")
        print (f"  {Colors.CYAN}[2]{Colors.ENDC} Raw APDU flow + launch Wireshark")
        print (f"  {Colors.CYAN}[3]{Colors.ENDC} Decoded APDU view inside the terminal (replaces raw APDU view)")
        print (f"  {Colors.WHITE}[Q]{Colors.ENDC} Back")
        choice =input ("\nSelect start mode: ").strip ().upper ()
        if choice in ("Q",""):
            return ""
        normalized_mode =_normalize_hil_bridge_view_mode (choice )
        if len (normalized_mode )>0 :
            return normalized_mode
        print (f"\n{Colors.FAIL}[!] Invalid HIL bridge start mode.{Colors.ENDC}")
        pause ()


def _resolve_supervisor_quirks_env ()->tuple [str ,str ]:
    """Resolve the ``(YGGDRASIM_SIM_QUIRKS, YGGDRASIM_ALLOW_QUIRKS)`` pair
    that should be propagated to the HIL bridge supervisor unit.

    The bridge child enforces the same ``YGGDRASIM_ALLOW_QUIRKS`` gate
    as every other simulator entry point (``SIMCARD/quirks.py``).
    Without an explicit opt-in, ``load_quirk_registry`` raises
    ``PermissionError`` whenever a quirks file is resolvable on disk —
    which crashes the supervisor child immediately and traps the
    wizard in a restart-backoff loop. We therefore mirror the
    launcher's quirks env state into the unit:

    * If the launcher has ``YGGDRASIM_ALLOW_QUIRKS=<value>`` exported,
      forward both that value and the resolved quirks path so the
      supervisor honours the operator's existing decision.
    * If the launcher does not have the gate set, deliberately fall
      back to ``YGGDRASIM_SIM_QUIRKS=none`` so the bridge child boots
      with an empty quirks registry instead of crash-looping. This
      keeps the supervisor safe-by-default — operators who want
      quirks in the supervisor must opt in just like everywhere else.
    """
    allow_value =str (os .environ .get ("YGGDRASIM_ALLOW_QUIRKS","")or "").strip ()
    quirks_path =get_sim_quirks_path ()
    if len (allow_value )>0 :
        return (quirks_path ,allow_value )
    if len (quirks_path )==0 :
        return ("","")
    return ("none","")


def _build_hil_bridge_service_options (
    gsmtap_enabled :bool =True ,
    gsmtap_capture_path :str ="",
)->hil_bridge_runtime .HilBridgeUserServiceOptions :
    supervisor_state =hil_bridge_runtime .read_supervisor_state ()
    python_executable =hil_bridge_runtime .guess_bridge_python_executable (
    supervisor_state ,
    fallback =sys .executable ,
    )
    reader_index =0 
    raw_reader_index =supervisor_state .get ("readerIndex",0 )
    try :
        reader_index =int (raw_reader_index or 0 )
    except (TypeError ,ValueError ):
        reader_index =0 
    bridge_port =9997 
    raw_bridge_port =supervisor_state .get ("bridgePort",9997 )
    try :
        bridge_port =int (raw_bridge_port or 9997 )
    except (TypeError ,ValueError ):
        bridge_port =9997 
    remsim_args =hil_bridge_runtime .extract_remsim_extra_args_from_supervisor_state (supervisor_state )
    documentation_path =os .path .join (PROJECT_ROOT ,"guides","HIL_BRIDGE_GUIDE.md")
    quirks_env_value ,allow_quirks_env_value =_resolve_supervisor_quirks_env ()
    environment_overrides =[
    (CARD_BACKEND_ENV ,get_card_backend ()),
    (SIM_ISDR_CONFIG_ENV ,get_sim_isdr_config_path ()),
    (SIM_QUIRKS_ENV ,quirks_env_value ),
    (SIM_EIM_IDENTITY_ENV ,get_sim_eim_identity_path ()),
    (SIM_EUICC_STORE_ENV ,get_sim_euicc_store_root ()),
    ]
    if len (allow_quirks_env_value )>0 :
        environment_overrides .append (("YGGDRASIM_ALLOW_QUIRKS",allow_quirks_env_value ))
    current_profile_store_override =get_sim_profile_store_path ()
    if len (current_profile_store_override )>0 :
        environment_overrides .append ((SIM_PROFILE_STORE_ENV ,current_profile_store_override ))
    return hil_bridge_runtime .HilBridgeUserServiceOptions (
    python_executable =python_executable ,
    working_directory =PROJECT_ROOT ,
    reader_index =reader_index ,
    host ="127.0.0.1",
    port =bridge_port ,
    advertise_host ="127.0.0.1",
    usb_vidpid =hil_bridge_runtime .DEFAULT_USB_VIDPID ,
    gsmtap_enabled =bool (gsmtap_enabled ),
    gsmtap_capture_path =str (gsmtap_capture_path or "").strip (),
    remsim_args =remsim_args ,
    documentation_path =documentation_path ,
    environment_overrides =tuple (environment_overrides ),
    )


def _ensure_hil_bridge_user_service (
    gsmtap_enabled :bool =True ,
    gsmtap_capture_path :str ="",
)->tuple [str ,bool ]:
    options =_build_hil_bridge_service_options (
    gsmtap_enabled =gsmtap_enabled ,
    gsmtap_capture_path =gsmtap_capture_path ,
    )
    unit_text =hil_bridge_runtime .render_user_service_unit (options )
    written_path ,unit_changed =hil_bridge_runtime .write_user_service_if_changed (
    unit_text ,
    service_name =options .service_name ,
    )
    if unit_changed :
        hil_bridge_runtime .daemon_reload_user_services ()
    try :
        hil_bridge_runtime .disable_user_service (options .service_name )
    except (OSError ,RuntimeError ):
        pass
    return written_path ,unit_changed 


def _hil_bridge_log_line_is_apdu_related (line_text :str )->bool :
    normalized_line =str (line_text or "").strip ()
    if len (normalized_line )==0 :
        return False
    apdu_markers =(
    "Modem -> bridge APDU",
    "Card -> modem APDU",
    "Relay -> card APDU",
    "Card -> relay APDU",
    "Bridge -> modem proactive",
    )
    for marker in apdu_markers :
        if marker in normalized_line :
            return True
    return False


def _launch_hil_bridge_wireshark ()->None :
    wireshark_binary =_hil_bridge_wireshark_binary_path ()
    if len (wireshark_binary )==0 :
        raise RuntimeError (
        "Wireshark is not available. Install `wireshark` or set "
        f"{_HIL_BRIDGE_WIRESHARK_BIN_ENV}."
        )
    capture_interface =_hil_bridge_capture_interface ()
    command =[
    wireshark_binary ,
    "-k",
    "-i",
    capture_interface ,
    "-f",
    _hil_bridge_gsmtap_capture_filter (),
    "-style",
    "Adwaita-Dark",
    ]
    subprocess .Popen (
    command ,
    stdin =subprocess .DEVNULL ,
    stdout =subprocess .DEVNULL ,
    stderr =subprocess .DEVNULL ,
    start_new_session =True ,
    )


def _stop_hil_bridge_service_quietly (service_name :str )->None :
    normalized_service_name =str (service_name or hil_bridge_runtime .DEFAULT_SERVICE_NAME )
    try :
        hil_bridge_runtime .stop_user_service (normalized_service_name )
    except (OSError ,RuntimeError ):
        pass


def _activate_hil_bridge_service (
    *,
    active_before :bool ,
    needs_restart :bool ,
    service_name :str ="",
)->dict :
    normalized_service_name =str (service_name or hil_bridge_runtime .DEFAULT_SERVICE_NAME )
    try :
        if active_before ==False :
            hil_bridge_runtime .clear_supervisor_state ()
            hil_bridge_runtime .clear_card_relay_state ()
            hil_bridge_runtime .start_user_service (normalized_service_name )
        elif needs_restart :
            hil_bridge_runtime .clear_supervisor_state ()
            hil_bridge_runtime .clear_card_relay_state ()
            hil_bridge_runtime .restart_user_service (normalized_service_name )
        return hil_bridge_runtime .wait_for_bridge_ready ()
    except Exception :
        if active_before ==False :
            _stop_hil_bridge_service_quietly (normalized_service_name )
        raise 


def _stop_hil_bridge_from_attached_view (service_name :str ,reason_text :str )->None :
    print (f"\n{Colors.WARNING}[*] {reason_text}{Colors.ENDC}")
    try :
        hil_bridge_runtime .stop_user_service (service_name )
    except Exception as e :
        print (f"{Colors.FAIL}[!] Could not stop HIL session: {e}{Colors.ENDC}")
    else :
        print (f"{Colors.GREEN}[+] HIL session stopped.{Colors.ENDC}")
        print ("    Supervisor, bridge, and REMSIM subprocesses were stopped together.")


def _cleanup_hil_bridge_attached_process (process )->None :
    if process is None :
        return
    process_running =True
    try :
        if hasattr (process ,"poll"):
            process_running =process .poll ()is None
    except (OSError ,ValueError ):
        process_running =True
    if process_running :
        try :
            process .terminate ()
        except (OSError ,ProcessLookupError ):
            pass
    try :
        process .wait (timeout =1.0 )
    except (subprocess .TimeoutExpired ,OSError ):
        try :
            process .kill ()
        except (OSError ,ProcessLookupError ):
            pass


def _view_hil_bridge_termshark_stream (
    service_name :str ,
    *,
    startup_callback =None ,
    startup_delay_seconds :float =0.0 ,
)->None :
    from Tools.HilBridge.live_decode_tui import run_live_decode_tui
    from Tools.HilBridge.live_decode_view import resolve_tshark_binary

    normalized_service_name =str (service_name or hil_bridge_runtime .DEFAULT_SERVICE_NAME )
    tshark_binary =resolve_tshark_binary ()
    if len (tshark_binary )==0 :
        print (
        f"\n{Colors.FAIL}[!] tshark is not available. Install `tshark` to use the "
        f"in-terminal decoded HIL view.{Colors.ENDC}"
        )
        pause ()
        return
    capture_filter =_hil_bridge_gsmtap_capture_filter ()
    capture_path =_hil_bridge_termshark_capture_path ()
    runtime_root =_hil_bridge_termshark_runtime_root ()
    os .makedirs (runtime_root ,exist_ok =True )
    if startup_callback is not None :
        try :
            os .remove (capture_path )
        except FileNotFoundError :
            pass
    startup_cancel =threading .Event ()
    startup_thread =None 
    startup_state ={
    "activation_attempted":False ,
    "activation_complete":startup_callback is None ,
    "error":"",
    }

    def _run_startup_after_warmup ()->None :
        wait_budget =max (0.0 ,float (startup_delay_seconds or 0.0 ))
        if wait_budget >0.0 :
            deadline =time .monotonic ()+wait_budget
            while True :
                if startup_cancel .is_set ():
                    return
                remaining =deadline -time .monotonic ()
                if remaining <=0.0 :
                    break
                time .sleep (min (0.1 ,remaining ))
        if startup_cancel .is_set ():
            return
        startup_state ["activation_attempted"]=True 
        try :
            startup_callback ()
        except Exception as e :
            startup_state ["error"]=str (e )
            return
        startup_state ["activation_complete"]=True 

    try :
        if startup_callback is not None :
            startup_thread =threading .Thread (
            target =_run_startup_after_warmup ,
            daemon =True ,
            )
            startup_thread .start ()
        run_live_decode_tui (
        capture_path ,
        service_name =normalized_service_name ,
        capture_filter =capture_filter ,
        startup_state =startup_state ,
        tshark_binary =tshark_binary ,
        )
        startup_cancel .set ()
        if startup_thread is not None :
            startup_thread .join (timeout =0.2 )
        if len (str (startup_state .get ("error","")or "").strip ())>0 :
            print (
            f"\n{Colors.FAIL}[!] Could not start HIL session after decoded-view warm-up: "
            f"{startup_state ['error']}{Colors.ENDC}"
            )
            return
        if startup_callback is not None :
            if bool (startup_state .get ("activation_complete",False ))==False :
                if bool (startup_state .get ("activation_attempted",False )):
                    _stop_hil_bridge_service_quietly (normalized_service_name )
                return
        _stop_hil_bridge_from_attached_view (
        normalized_service_name ,
        "Terminal decode view exited. Stopping the HIL session..." ,
        )
    except KeyboardInterrupt :
        startup_cancel .set ()
        _stop_hil_bridge_from_attached_view (
        normalized_service_name ,
        "Ctrl+C received. Stopping the HIL session..." ,
        )
    except Exception as e :
        startup_cancel .set ()
        print (f"\n{Colors.FAIL}[!] Could not open the terminal decode view: {e}{Colors.ENDC}")
    finally :
        startup_cancel .set ()
        if startup_thread is not None :
            startup_thread .join (timeout =0.2 )
        pause ()


def _view_hil_bridge_live_stream (service_name :str ,gsmtap_enabled :bool =True )->None :
    normalized_service_name =str (service_name or hil_bridge_runtime .DEFAULT_SERVICE_NAME )
    clear_screen ()
    print (f"{Colors.HEADER}=== Live HIL APDU Stream ==={Colors.ENDC}\n")
    print (f"Service   : {normalized_service_name}")
    print ("Source    : systemd user journal")
    if gsmtap_enabled :
        print ("Feed      : raw APDU log lines + GSMTAP to Wireshark")
    else :
        print ("Feed      : raw APDU log lines only")
    print ("Stop      : Ctrl+C")
    print ("")
    print (f"{Colors.WARNING}[*] Waiting for modem/card traffic...{Colors.ENDC}")
    command =[
    "journalctl",
    "--user",
    "-u",
    normalized_service_name ,
    "-f",
    "-n",
    "0",
    "-o",
    "cat",
    ]
    process =None
    try :
        process =subprocess .Popen (
        command ,
        stdout =subprocess .PIPE ,
        stderr =subprocess .STDOUT ,
        text =True ,
        bufsize =1 ,
        )
        if process .stdout is None :
            raise RuntimeError ("journalctl did not provide a readable stdout stream.")
        for raw_line in process .stdout :
            line_text =str (raw_line or "").rstrip ("\n")
            if _hil_bridge_log_line_is_apdu_related (line_text )==False :
                continue
            print (line_text )
    except KeyboardInterrupt :
        _stop_hil_bridge_from_attached_view (
        normalized_service_name ,
        "Ctrl+C received. Stopping the HIL session..." ,
        )
    except Exception as e :
        print (f"\n{Colors.FAIL}[!] Could not attach to the HIL live stream: {e}{Colors.ENDC}")
    finally :
        _cleanup_hil_bridge_attached_process (process )
        pause ()


def _start_hil_bridge_session (view_mode :str ="")->None :
    requested_view_mode =_normalize_hil_bridge_view_mode (view_mode )
    if len (requested_view_mode )==0 :
        requested_view_mode =_prompt_hil_bridge_view_mode ()
    if len (requested_view_mode )==0 :
        return
    effective_view_mode =requested_view_mode
    if effective_view_mode ==_HIL_BRIDGE_VIEW_MODE_RAW_WIRESHARK and len (_hil_bridge_wireshark_binary_path ())==0 :
        print (
        f"\n{Colors.WARNING}[*] Wireshark is not available. Falling back to raw APDU flow only.{Colors.ENDC}"
        )
        effective_view_mode =_HIL_BRIDGE_VIEW_MODE_RAW
    if effective_view_mode ==_HIL_BRIDGE_VIEW_MODE_TERMSHARK and len (_hil_bridge_tshark_binary_path ())==0 :
        print (
        f"\n{Colors.WARNING}[*] tshark is not available. Falling back to raw APDU flow only.{Colors.ENDC}"
        )
        effective_view_mode =_HIL_BRIDGE_VIEW_MODE_RAW
    gsmtap_enabled =_hil_bridge_view_mode_uses_gsmtap (effective_view_mode )
    requested_capture_path =_hil_bridge_capture_path_for_view_mode (effective_view_mode )
    supervisor_state =hil_bridge_runtime .read_supervisor_state ()
    service_state =hil_bridge_runtime .query_user_service_state ()
    active_before =str (service_state .get ("activeState","")or "").strip ()=="active"
    active_gsmtap_enabled =_hil_bridge_command_uses_gsmtap (supervisor_state .get ("bridgeCommand",[]))
    active_capture_path =_hil_bridge_command_capture_path (supervisor_state .get ("bridgeCommand",[]))
    try :
        written_path ,unit_changed =_ensure_hil_bridge_user_service (
        gsmtap_enabled =gsmtap_enabled ,
        gsmtap_capture_path =requested_capture_path ,
        )
    except Exception as e :
        print (f"\n{Colors.FAIL}[!] Could not start HIL session: {e}{Colors.ENDC}")
        pause ()
        return
    needs_restart =(
    active_before
    and (
    unit_changed 
    or (
    active_gsmtap_enabled is not None 
    and bool (active_gsmtap_enabled )!=bool (gsmtap_enabled )
    )
    or str (active_capture_path or "").strip ()!=str (requested_capture_path or "").strip ()
    )
    )
    if effective_view_mode ==_HIL_BRIDGE_VIEW_MODE_TERMSHARK and (active_before ==False or needs_restart ):
        warmup_seconds =_hil_bridge_termshark_warmup_seconds ()

        def _start_hil_after_termshark_warmup ()->dict :
            return _activate_hil_bridge_service (
            active_before =active_before ,
            needs_restart =needs_restart ,
            service_name =hil_bridge_runtime .DEFAULT_SERVICE_NAME ,
            )

        if active_before and needs_restart :
            print (f"\n{Colors.GREEN}[+] HIL session will restart after decoded-view warm-up.{Colors.ENDC}")
        else :
            print (f"\n{Colors.GREEN}[+] HIL session will start after decoded-view warm-up.{Colors.ENDC}")
        print (f"    User service path: {written_path}")
        print (f"    View mode        : {_hil_bridge_view_mode_label (effective_view_mode )}")
        print ("    GSMTAP mirror    : UDP 4729")
        print (f"    Warm-up delay    : {warmup_seconds :.1f}s")
        print ("    The decoded terminal view will open first, then the bridge will start.")
        _view_hil_bridge_termshark_stream (
        hil_bridge_runtime .DEFAULT_SERVICE_NAME ,
        startup_callback =_start_hil_after_termshark_warmup ,
        startup_delay_seconds =warmup_seconds ,
        )
        return
    try :
        status_payload =_activate_hil_bridge_service (
        active_before =active_before ,
        needs_restart =needs_restart ,
        service_name =hil_bridge_runtime .DEFAULT_SERVICE_NAME ,
        )
    except Exception as e :
        print (f"\n{Colors.FAIL}[!] Could not start HIL session: {e}{Colors.ENDC}")
        pause ()
        return
    if active_before and needs_restart :
        print (f"\n{Colors.GREEN}[+] HIL session was restarted to apply the requested capture mode and env overrides.{Colors.ENDC}")
    elif active_before :
        print (f"\n{Colors.GREEN}[+] HIL session is already active.{Colors.ENDC}")
    else :
        print (f"\n{Colors.GREEN}[+] HIL session started.{Colors.ENDC}")
    print (f"    User service path: {written_path}")
    print (f"    View mode        : {_hil_bridge_view_mode_label (effective_view_mode )}")
    print (f"    APDU relay URL   : {status_payload .get ('apduUrl','')}")
    card_backend =str (status_payload .get ("cardBackend","")or "").strip ()
    if len (card_backend )>0 :
        print (f"    Card backend     : {card_backend}")
    card_source =str (status_payload .get ("reader","")or "").strip ()
    if len (card_source )>0 :
        print (f"    Card source      : {card_source}")
    atr_hex =str (status_payload .get ("atr","")or "").strip ()
    if len (atr_hex )>0 :
        print (f"    ATR              : {atr_hex}")
    if gsmtap_enabled :
        print ("    GSMTAP mirror    : UDP 4729")
    else :
        print ("    GSMTAP mirror    : disabled for raw-only mode")
    print ("    Starting HIL also launches the bridge and REMSIM subprocesses.")
    print ("    After changing simulator/backend settings, stop and start HIL to rebind the card side.")
    if effective_view_mode ==_HIL_BRIDGE_VIEW_MODE_RAW_WIRESHARK :
        print ("    Launching Wireshark for live GSMTAP decode...")
        try :
            _launch_hil_bridge_wireshark ()
        except Exception as e :
            print (f"{Colors.WARNING}[*] Could not launch Wireshark: {e}{Colors.ENDC}")
        print ("    Press Ctrl+C in the live APDU view to stop the HIL session.")
        print ("    Attaching to the live APDU stream view...")
        _view_hil_bridge_live_stream (hil_bridge_runtime .DEFAULT_SERVICE_NAME ,gsmtap_enabled =True )
        return
    if effective_view_mode ==_HIL_BRIDGE_VIEW_MODE_TERMSHARK :
        print ("    The decoded APDU view will replace the raw APDU stream in this terminal.")
        _view_hil_bridge_termshark_stream (hil_bridge_runtime .DEFAULT_SERVICE_NAME )
        return
    print ("    Press Ctrl+C in the live APDU view to stop the HIL session.")
    print ("    Attaching to the live APDU stream view...")
    _view_hil_bridge_live_stream (hil_bridge_runtime .DEFAULT_SERVICE_NAME ,gsmtap_enabled =gsmtap_enabled )


def _open_hil_bridge_pcap_offline (pcap_path :str ,*,keybag_path :str ="")->int :
    """Open a saved pcap in the HIL decode TUI without starting the bridge.

    Offline review mode reuses `run_live_decode_tui` with `live_capture=False`
    so no FIFO is created, no `tshark -i` subprocess is spawned, and the
    systemd HIL service is left untouched. The pcap is read via
    `tshark -r`. When a keybag JSON path is provided (or a sibling file
    named `<pcap>.keys.json` is found) the TUI annotator layers SCP03 /
    SCP11c plaintext views on top of ciphered APDUs.
    """
    from Tools.HilBridge.live_decode_tui import run_live_decode_tui 
    from Tools.HilBridge.live_decode_view import resolve_tshark_binary 

    normalized_pcap =str (pcap_path or "").strip ()
    if len (normalized_pcap )==0 :
        print (f"\n{Colors.FAIL}[!] No pcap path was provided.{Colors.ENDC}")
        return 1 
    pcap_abs_path =os .path .abspath (os .path .expanduser (normalized_pcap ))
    if os .path .isfile (pcap_abs_path )==False :
        print (f"\n{Colors.FAIL}[!] pcap file not found: {pcap_abs_path}{Colors.ENDC}")
        return 1 
    tshark_binary =resolve_tshark_binary ()
    if len (tshark_binary )==0 :
        print (
        f"\n{Colors.FAIL}[!] tshark is not available. Install `tshark` to use "
        f"the offline HIL decode view.{Colors.ENDC}"
        )
        return 1 

    resolved_keybag =str (keybag_path or "").strip ()
    if len (resolved_keybag )==0 :
        sidecar_candidate =pcap_abs_path +".keys.json"
        if os .path .isfile (sidecar_candidate ):
            resolved_keybag =sidecar_candidate 
        else :
            stem_candidate =os .path .splitext (pcap_abs_path )[0 ]+".keys.json"
            if os .path .isfile (stem_candidate ):
                resolved_keybag =stem_candidate 

    capture_filter =_hil_bridge_gsmtap_capture_filter ()
    print (f"\n{Colors.GREEN}[+] Opening pcap in offline HIL decode view.{Colors.ENDC}")
    print (f"    Pcap file   : {pcap_abs_path}")
    if len (resolved_keybag )>0 :
        print (f"    Keybag file : {resolved_keybag}")
    else :
        print ("    Keybag file : (none — ciphered APDUs will stay wrapped)")
    print ("    Mode        : offline review (no bridge, no live FIFO)")
    try :
        run_live_decode_tui (
        pcap_abs_path ,
        service_name ="offline-review",
        capture_filter =capture_filter ,
        startup_state ={"activation_complete":True },
        tshark_binary =tshark_binary ,
        live_capture =False ,
        keybag_path =resolved_keybag ,
        )
    except KeyboardInterrupt :
        pass 
    except Exception as e :
        print (f"\n{Colors.FAIL}[!] Offline HIL decode view error: {e}{Colors.ENDC}")
        return 1 
    return 0 


def _stop_hil_bridge_session ()->None :
    service_state =hil_bridge_runtime .query_user_service_state ()
    active_state =str (service_state .get ("activeState","")or "").strip ()
    if active_state !="active":
        print (f"\n{Colors.GREEN}[+] HIL session is already stopped.{Colors.ENDC}")
        pause ()
        return
    try :
        hil_bridge_runtime .stop_user_service ()
    except Exception as e :
        print (f"\n{Colors.FAIL}[!] Could not stop HIL session: {e}{Colors.ENDC}")
        pause ()
        return
    print (f"\n{Colors.GREEN}[+] HIL session stopped.{Colors.ENDC}")
    print ("    Supervisor, bridge, and REMSIM subprocesses were stopped together.")
    pause ()


def manage_hil_bridge ()->None :
    while True :
        clear_screen ()
        supervisor_state =hil_bridge_runtime .read_supervisor_state ()
        relay_state =hil_bridge_runtime .read_card_relay_state ()
        service_state =hil_bridge_runtime .query_user_service_state ()
        live_status ={}
        live_status_error =""
        status_url =str (relay_state .get ("statusUrl","")or "").strip ()
        if str (service_state .get ("activeState","")or "").strip ()=="active"and len (status_url )>0 :
            try :
                live_status =hil_bridge_runtime .read_bridge_status ()
            except Exception as e :
                live_status_error =str (e )
        print (f"{Colors.HEADER}=== HIL Bridge Session ==={Colors.ENDC}\n")
        print ("Manual HIL mode: start only when you explicitly need live modem/card tracing.")
        print ("Start mode now lets you choose raw APDU only, raw APDU + Wireshark, or the decoded in-terminal view.\n")
        print (f"Service             : {_hil_bridge_service_state_text (service_state )}")
        fragment_path =str (service_state .get ("fragmentPath","")or "").strip ()
        if len (fragment_path )>0 :
            print (f"Service unit path   : {fragment_path}")
        print (f"Supervisor status   : {supervisor_state .get ('status','unknown')}")
        print (f"USB present         : {supervisor_state .get ('usbPresent',False)}")
        print (f"Bridge running      : {supervisor_state .get ('bridgeRunning',False)}")
        print (f"REMSIM running      : {supervisor_state .get ('remsimClientRunning',False)}")
        reason_text =str (supervisor_state .get ("reason","")or "").strip ()
        if len (reason_text )>0 :
            print (f"Supervisor reason   : {reason_text}")
        relay_status ="missing"
        if len (live_status )>0 :
            relay_status =str (live_status .get ("status","ok")or "").strip ()or "ok"
        elif len (relay_state )>0 :
            relay_status =str (relay_state .get ("status","ok")or "").strip ()or "ok"
        print (f"Relay status        : {relay_status}")
        relay_url =str (live_status .get ("apduUrl",relay_state .get ("apduUrl",""))or "").strip ()
        if len (relay_url )>0 :
            print (f"Relay APDU URL      : {relay_url}")
        card_backend =str (live_status .get ("cardBackend",relay_state .get ("cardBackend",""))or "").strip ()
        if len (card_backend )>0 :
            print (f"Card backend        : {card_backend}")
        card_source =str (live_status .get ("reader",relay_state .get ("reader",""))or "").strip ()
        if len (card_source )>0 :
            print (f"Card source         : {card_source}")
        atr_hex =str (live_status .get ("atr",relay_state .get ("atr",""))or "").strip ()
        if len (atr_hex )>0 :
            print (f"ATR                 : {atr_hex}")
        print (f"Control connected   : {live_status .get ('controlConnected',relay_state .get ('controlConnected',False ))}")
        print (f"Bankd connected     : {live_status .get ('bankdConnected',relay_state .get ('bankdConnected',False ))}")
        if len (live_status_error )>0 :
            print (f"Live status note    : {live_status_error}")
        print ("")
        print (f"  {Colors.CYAN}[1]{Colors.ENDC} Start HIL session (choose raw / raw+Wireshark / decoded view)")
        print (f"  {Colors.CYAN}[2]{Colors.ENDC} Stop HIL session")
        print (f"  {Colors.CYAN}[3]{Colors.ENDC} Open saved .pcap (offline review, no bridge)")
        print (f"  {Colors.WHITE}[R]{Colors.ENDC} Refresh status")
        print (f"  {Colors.WHITE}[Q]{Colors.ENDC} Return to main menu")
        choice =input ("\nSelect action: ").strip ().upper ()
        if choice in ("Q",""):
            return
        if choice =='1':
            _start_hil_bridge_session ()
            continue
        if choice =='2':
            _stop_hil_bridge_session ()
            continue
        if choice =='3':
            _prompt_open_hil_bridge_pcap_offline ()
            continue
        if choice =='R':
            continue
        print (f"\n{Colors.FAIL}[!] Invalid HIL bridge selection.{Colors.ENDC}")
        pause ()


def _prompt_open_hil_bridge_pcap_offline ()->None :
    try :
        from Tools.HilBridge.live_decode_tui import pick_capture_file_path 
    except Exception as e :
        print (f"\n{Colors.FAIL}[!] Could not load capture file picker: {e}{Colors.ENDC}")
        pause ()
        return 
    default_dir =_hil_bridge_termshark_runtime_root ()
    selected_path =""
    try :
        picked =pick_capture_file_path (last_open_directory =default_dir )
        if picked is not None :
            selected_path =str (picked )
    except RuntimeError as e :
        print (f"\n{Colors.WARNING}[*] Native picker unavailable: {e}{Colors.ENDC}")
    except Exception as e :
        print (f"\n{Colors.WARNING}[*] Native picker failed: {e}{Colors.ENDC}")
    if len (selected_path )==0 :
        print ("\nEnter the path to a saved .pcap / .pcapng (blank to cancel).")
        prompted =input ("pcap path: ").strip ()
        if len (prompted )==0 :
            return 
        selected_path =prompted 
    print ("\nOptionally, enter the path to a keybag JSON for SCP03/SCP11c unwrap.")
    print ("Leave blank to auto-discover `<pcap>.keys.json` in the same directory.")
    keybag_input =input ("keybag path: ").strip ()
    exit_code =_open_hil_bridge_pcap_offline (selected_path ,keybag_path =keybag_input )
    if exit_code !=0 :
        pause ()


def manage_env_flags ()->None :
    """Launch the YGGDRASIM_* environment flag editor.

    ``main/`` is not a Python package at runtime (``main.py`` runs as
    ``__main__`` and there is no ``main/__init__.py``), so we load the
    sibling ``env_flags_ui`` module by file path rather than via
    ``import main.env_flags_ui``. The theme + blocking helpers used by
    the editor are passed in explicitly so the editor module does not
    have to reach back into ``__main__``.
    """
    try :
        import importlib .util 
        module_path =os .path .join (CURRENT_DIR ,"env_flags_ui.py")
        module_spec =importlib .util .spec_from_file_location (
        "yggdrasim_env_flags_ui",module_path ,
        )
        if module_spec is None or module_spec .loader is None :
            raise RuntimeError (f"Could not locate env_flags_ui at {module_path}")
        env_flags_ui_module =importlib .util .module_from_spec (module_spec )
        # Expose the module under sys.modules so any relative imports it
        # grows later can still resolve the symbolic name we used above.
        sys .modules [module_spec .name ]=env_flags_ui_module 
        module_spec .loader .exec_module (env_flags_ui_module )
        env_flags_ui_module .run (Colors ,clear_screen ,pause )
    except Exception as e :
        print (f"{Colors.FAIL}[!] Environment Flags editor error: {e}{Colors.ENDC}")
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
        with open (license_path ,'r',encoding ='utf-8')as f :
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
            _show_text_document ("YggdraSIM Architecture","guides/ARCHITECTURE.md")
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
    Copyright (C) 2026 1oT OÜ. All rights reserved.
    Creator, architect, developer, and maintainer: Hampus Hellsberg.

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
        print ("")
        print (f"{Colors.HEADER}=== Unified Secure Element Research & Auditing Suite ==={Colors.ENDC}")
        print (f"{Colors.CYAN}-------------------- Active Surfaces ---------------------{Colors.ENDC}")
        print (
            f"{Colors.WHITE} [ {Colors.GREEN}Admin Shell{Colors.WHITE} | "
            f"{Colors.CYAN}OTA Simulator{Colors.WHITE} | "
            f"{Colors.HEADER}eSIM Relay Live/Test{Colors.WHITE} |{Colors.ENDC}"
        )
        print (
            f"{Colors.WHITE}   {Colors.HEADER}Local SMDPP{Colors.WHITE} | "
            f"{Colors.HEADER}Local eIM{Colors.WHITE} | "
            f"{Colors.BLUE}SAIP Tool{Colors.WHITE} | "
            f"{Colors.BLUE}SUCI Tool{Colors.WHITE} ]{Colors.ENDC}"
        )
        print (f"{Colors.BROWN}---------------------- Authorship ------------------------{Colors.ENDC}")
        print (
            f"{Colors.WARNING} Authored and maintained by "
            f"{Colors.BOLD}{Colors.WHITE}1oT eSIM Engineering team{Colors.ENDC}"
        )
        print (f"{Colors.HEADER}----------------------- Runtime --------------------------{Colors.ENDC}")
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
        f"{Colors.CYAN} [E] Environment Flags (YGGDRASIM_*){Colors.ENDC}",
        ]
        if yggdrasim_flavor .is_hil_bridge_included ()and yggdrasim_flavor .is_hil_bridge_supported_platform ():
            menu_lines .append (f"{Colors.CYAN} [B] HIL Bridge Session{Colors.ENDC}")
        elif yggdrasim_flavor .is_hil_bridge_included ():
            menu_lines .append (f"{Colors.BROWN} [B] HIL Bridge Session (Linux only — hidden on {sys.platform}){Colors.ENDC}")
        else :
            menu_lines .append (f"{Colors.BROWN} [B] HIL Bridge Session (not bundled in clean build){Colors.ENDC}")
        menu_lines .extend ([
        "",
        f"{Colors.WHITE}--- Reference ---{Colors.ENDC}",
        f"{Colors.WHITE} [G] Guides & Documentation{Colors.ENDC}",
        f"{Colors.WHITE} [A] About{Colors.ENDC}",
        f"{Colors.WHITE} [L] License (GPLv3){Colors.ENDC}",
        f"{Colors.WHITE} [Q] Quit{Colors.ENDC}",
        f"{Colors.HEADER}==============================={Colors.ENDC}",
        ])
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
    if normalized_choice =='E':
        manage_env_flags ()
        return
    if normalized_choice =='B':
        reason =yggdrasim_flavor .hil_bridge_unavailable_reason ()
        if len (reason )>0 or hil_bridge_runtime is None :
            clear_screen ()
            print (f"{Colors.HEADER}=== HIL Bridge Session ==={Colors.ENDC}\n")
            if len (reason )>0 :
                print (f"{Colors.WARNING}[*] {reason}{Colors.ENDC}")
            else :
                print (f"{Colors.WARNING}[*] HIL bridge runtime is not available in this build.{Colors.ENDC}")
            print (f"\n{Colors.CYAN}Install paths that ship the HIL bridge:{Colors.ENDC}")
            print ("  - clean builds never include it (see guides/INSTALL_CLEAN.md)")
            print ("  - full builds bundle it on Linux (see guides/INSTALL_FULL.md)")
            print ("  - source checkouts enable it after `pip install -e '.[hil]'`")
            print ("  - flashing SIMtrace2 with cardem: guides/SIMTRACE2_CARDEM_GUIDE.md")
            pause ()
            return
        manage_hil_bridge ()
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
    from yggdrasim_common.__about__ import __version__

    flavor_label =yggdrasim_flavor .describe_flavor ()
    epilog =(
        "Examples:\n"
        "  python main/main.py\n"
        "  python main/main.py --version\n"
        "  python main/main.py --doctor\n"
        "  python main/main.py --card-backend sim\n"
        "  python main/main.py --scp03 --cmd 'HELP; EXIT'\n"
        "\n"
        "Environment variables:\n"
        "  YGGDRASIM_RUNTIME_ROOT   Force the frozen-runtime writable root.\n"
        "  YGGDRASIM_CARD_BACKEND   Preselect reader|sim when no --card-backend is passed.\n"
        "  YGGDRASIM_FLAVOR         Force clean|full|source when probing from a shared tree.\n"
        "  (launcher menu [E] lists and edits all supported YGGDRASIM_* flags)\n"
        "\n"
        f"Active build flavor: {flavor_label}\n"
    )
    parser =argparse .ArgumentParser (
        description ="YggdraSIM Suite",
        epilog =epilog ,
        formatter_class =argparse .RawDescriptionHelpFormatter ,
    )
    parser .add_argument (
        "--version",
        action ="version",
        version =f"YggdraSIM {__version__} ({flavor_label})",
    )
    parser .add_argument (
        "--doctor",
        action ="store_true",
        help ="Run a preflight environment check (Python, dependencies, pySim tree, reader, SQLite) and exit.",
    )
    parser .add_argument ("--scp03",action ="store_true",help ="Use SCP03 Admin Shell")
    parser .add_argument ("--cmd",type =str ,help ="Semicolon-separated commands (non-interactive, use with --scp03)")
    parser .add_argument ("--out",type =str ,help ="Output YAML file for --cmd")
    parser .add_argument (
    "--open-pcap",
    dest ="open_pcap",
    type =str ,
    default =None ,
    help ="Open a saved .pcap/.pcapng in the HIL decode TUI (offline review, no bridge).",
    )
    parser .add_argument (
    "--keybag",
    dest ="keybag",
    type =str ,
    default =None ,
    help ="Optional keybag JSON with SCP03/SCP11c session keys (for --open-pcap offline unwrap).",
    )
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
    _add_gui_arguments (parser )
    _add_remote_card_arguments (parser )
    return parser 


def _add_gui_arguments (parser ):
    """Attach the universal GUI argparse surface.

    Both `--gui` and `--web-server` are off by default. Neither flag
    imports FastAPI / uvicorn / pywebview until the corresponding
    dispatch path runs, so the baseline `pip install yggdrasim`
    install remains lean.
    """
    group =parser .add_argument_group ("GUI (experimental)")
    group .add_argument (
    "--gui",
    action ="store_true",
    help ="Launch the desktop GUI (FastAPI on loopback + pywebview native window).",
    )
    group .add_argument (
    "--web-server",
    dest ="web_server",
    action ="store_true",
    help ="Launch the remote-lab GUI API (FastAPI, no pywebview; requires an explicit bearer token).",
    )
    group .add_argument (
    "--host",
    type =str ,
    default =None ,
    help ="Override the GUI API bind host (default: 127.0.0.1 for --gui, 0.0.0.0 for --web-server).",
    )
    group .add_argument (
    "--port",
    type =int ,
    default =None ,
    help ="Override the GUI API bind port (default: 27853 desktop / 27854 server).",
    )
    group .add_argument (
    "--token-file",
    dest ="token_file",
    type =str ,
    default =None ,
    help ="Path to a file containing the bearer token (required for --web-server).",
    )
    group .add_argument (
    "--tls-cert",
    dest ="tls_cert",
    type =str ,
    default =None ,
    help ="TLS certificate path (PEM) for --web-server.",
    )
    group .add_argument (
    "--tls-key",
    dest ="tls_key",
    type =str ,
    default =None ,
    help ="TLS private key path (PEM) for --web-server.",
    )
    group .add_argument (
    "--tls-self-signed",
    dest ="tls_self_signed",
    action ="store_true",
    help ="Generate / reuse a self-signed TLS pair under state/gui_tls/ for --web-server.",
    )
    group .add_argument (
    "--allow-origin",
    dest ="allow_origin",
    action ="append",
    default =[],
    help ="Additional CORS origin for --web-server (repeatable; wildcards refused).",
    )
    return parser 


def _route_gui_modes (args ):
    """Dispatch --gui / --web-server to the GUI server layer.

    Returns ``None`` when neither flag is set so the caller continues
    with the legacy CLI path. When a GUI flag is set but its optional
    dependency stack is missing, this returns a non-zero exit code
    with a pointer at the correct `pip install yggdrasim[...]` extra.
    """
    gui_enabled =bool (getattr (args ,"gui",False ))
    web_server_enabled =bool (getattr (args ,"web_server",False ))
    if gui_enabled and web_server_enabled :
        print (f"{Colors.FAIL}[-] --gui and --web-server are mutually exclusive.{Colors.ENDC}")
        return 2 
    if not (gui_enabled or web_server_enabled ):
        return None 
    try :
        from yggdrasim_common .gui_server .app import run_desktop ,run_web_server 
    except ImportError as import_error :
        extra ="gui"if gui_enabled else "gui-server"
        print (
        f"{Colors.FAIL}[-] {('--gui'if gui_enabled else '--web-server')} needs the optional dependency stack. "
        f"Install it with: pip install 'yggdrasim[{extra}]' "
        f"(underlying import error: {type(import_error).__name__}: {import_error}){Colors.ENDC}"
        )
        return 3 
    if gui_enabled :
        return int (run_desktop (args )or 0 )
    return int (run_web_server (args )or 0 )


def _apply_remote_card_arguments_with_log (args )->None :
    """Apply --remote-card-url / --remote-card-token-file and surface state.

    A bridge banner only prints when something is actually configured —
    we don't want every YggdraSIM invocation to grow a noisy "remote
    card bridge: not configured" line.
    """
    state =_apply_remote_card_arguments (args )
    if len (state .get ("url")or "")>0 :
        print (f"{Colors.CYAN}[i] {_describe_remote_card_state(state)}{Colors.ENDC}")


def run_cli (argv =None ):
    parser =_build_cli_parser ()
    args =parser .parse_args (argv )
    _emit_plugin_load_banner ()
    # Mirror --remote-card-url / --remote-card-token-file into the env
    # before any card backend is touched, so the existing
    # YGGDRASIM_CARD_RELAY_* resolution chain in card_backend picks the
    # values up transparently downstream.
    _apply_remote_card_arguments_with_log (args )
    if bool (getattr (args ,"doctor",False )):
        from yggdrasim_common.doctor import run_doctor
        return run_doctor (Path (PROJECT_ROOT )if PROJECT_ROOT else None )
    gui_exit =_route_gui_modes (args )
    if gui_exit is not None :
        return int (gui_exit )
    # When --debug is passed, promote to a process-global default and
    # persist it.  When omitted, leave any previously persisted value
    # in place so debug state survives across sessions.
    if bool (getattr (args ,"debug",False )):
        set_global_debug (True )
    install_noisy_warning_filters ()
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
    open_pcap_value =str (getattr (args ,"open_pcap",None )or "").strip ()
    if len (open_pcap_value )>0 :
        keybag_value =str (getattr (args ,"keybag",None )or "").strip ()
        return _open_hil_bridge_pcap_offline (open_pcap_value ,keybag_path =keybag_value )
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
