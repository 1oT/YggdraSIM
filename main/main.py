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
      and send commands, dedicated certificate override storage, and local
      debug artifacts kept outside the profile folder.

    * {Colors.CYAN}SCP11 Local eIM:{Colors.ENDC}
      Isolated local eIM shell for `ADD-INITIAL-EIM`, `ADD-EIM`,
      `GET-EIM-CONFIG`, `DELETE-EIM`, hotfolder and poll campaigns, direct
      BF36 relay, indirect SM-DP+ handover, BF50 result serialization, and
      identity / certificate defaults driven by `eim_identity.json`.

    * {Colors.CYAN}SAIP Tool:{Colors.ENDC}
      A dedicated shell for working with SAIP / profile package files through
      `saip-tool`, including `info`, `tree`, `check`, `dump`, `lint`,
      `TRANSCODE-TUI`, tagged JSON re-encode, `split`, `extract-apps`, and raw
      subcommand passthrough. Transcode sidecars are written under the
      dedicated `Tools/ProfilePackage/transcode` folder to keep source inputs clean.

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


if __name__ =="__main__":
    import argparse 
    parser =argparse .ArgumentParser (description ="YggdraSIM Suite")
    parser .add_argument ("--scp03",action ="store_true",help ="Use SCP03 Admin Shell")
    parser .add_argument ("--cmd",type =str ,help ="Semicolon-separated commands (non-interactive, use with --scp03)")
    parser .add_argument ("--out",type =str ,help ="Output YAML file for --cmd")
    args =parser .parse_args ()
    if args .scp03 and args .cmd :
        run_scp03_cmd (args .cmd ,yaml_out =args .out )
        sys .exit (0 )
    try :
        main_menu ()
    except QuitAllRequested :
        sys .exit (0 )
    except KeyboardInterrupt :
        sys .exit (0 )