# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import sys
import os
import importlib

# --- 1. DYNAMIC PATH CONFIGURATION ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = None

# Scan up to 2 levels up to find the project root
possible_roots = [
    CURRENT_DIR,
    os.path.dirname(CURRENT_DIR),
    os.path.dirname(os.path.dirname(CURRENT_DIR))
]

for candidate in possible_roots:
    if os.path.exists(os.path.join(candidate, "SCP03")):
        PROJECT_ROOT = candidate
        break

if PROJECT_ROOT is None:
    PROJECT_ROOT = CURRENT_DIR

# Define module paths
DIRS = {
    "LICENSE": os.path.join(PROJECT_ROOT, "LICENSE")
}

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BROWN = '\033[38;5;94m' 
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def setup_paths():
    """Ensures PROJECT_ROOT is in sys.path."""
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    input(f"\n{Colors.CYAN}Press Enter to return to menu...{Colors.ENDC}")

# --- 2. TOOL WRAPPERS ---

def run_scp03():
    """Wrapper for SCP03 Package."""
    try:
        import SCP03.main as scp03_entry
        importlib.reload(scp03_entry)
        scp03_entry.entry()
    except SystemExit:
        pass 
    except Exception as e:
        print(f"{Colors.FAIL}[!] SCP03 Error: {e}{Colors.ENDC}")
        pause()

def run_scp03_script():
    """Wrapper for SCP03 Script Execution."""
    clear_screen()
    print(f"{Colors.HEADER}=== SCP03 Script Execution ==={Colors.ENDC}")
    script_path = input("Enter path to script file: ").strip()
    if not script_path:
        return
    try:
        import SCP03.main as scp03_entry
        importlib.reload(scp03_entry)
        scp03_entry.run_script(script_path)
        pause()
    except SystemExit:
        pass 
    except Exception as e:
        print(f"{Colors.FAIL}[!] SCP03 Script Error: {e}{Colors.ENDC}")
        pause()

def run_scp03_report():
    """Wrapper for SCP03 Report & DUMP-FS."""
    try:
        import SCP03.main as scp03_entry
        importlib.reload(scp03_entry)
        scp03_entry.run_report_wizard()
        pause()
    except SystemExit:
        pass 
    except Exception as e:
        print(f"{Colors.FAIL}[!] SCP03 Report Error: {e}{Colors.ENDC}")
        pause()

def run_scp80():
    """Wrapper for modularized SCP80 Package."""
    # Inject SCP80 directory into path to allow absolute imports (cli, config, etc)
    scp80_path = os.path.join(PROJECT_ROOT, "SCP80")
    if scp80_path not in sys.path:
        sys.path.insert(0, scp80_path)
    
    try:
        # Import the package (calls __init__.py)
        import SCP80
        importlib.reload(SCP80)
        
        if hasattr(SCP80, 'shell'):
            SCP80.shell()
        else:
            # Fallback if __init__.py is empty or missing shell()
            from cli import OtaShell
            OtaShell().run()
            
    except SystemExit:
        pass
    except Exception as e:
        print(f"{Colors.FAIL}[!] SCP80 Error: {e}{Colors.ENDC}")
        pause()

def run_scp80_script():
    """Wrapper for SCP80 Script Execution."""
    clear_screen()
    print(f"{Colors.CYAN}=== SCP80 OTA Script Execution ==={Colors.ENDC}")
    script_path = input("Enter path to script file: ").strip()
    if not script_path:
        return
        
    scp80_path = os.path.join(PROJECT_ROOT, "SCP80")
    if scp80_path not in sys.path:
        sys.path.insert(0, scp80_path)
    
    try:
        import SCP80
        importlib.reload(SCP80)
        
        from cli import OtaShell
        app = OtaShell()
        app.do_script(script_path)
        pause()
    except SystemExit:
        pass
    except Exception as e:
        print(f"{Colors.FAIL}[!] SCP80 Script Error: {e}{Colors.ENDC}")
        pause()

def run_scp11():
    """Wrapper for SCP11."""
    try:
        import SCP11.main as scp11_client
        importlib.reload(scp11_client)
        client = scp11_client.SGP22Client()
        client.run_flow()
        pause()
    except SystemExit:
        pass
    except Exception as e:
        print(f"{Colors.FAIL}[!] SCP11 Error: {e}{Colors.ENDC}")
        pause()

def show_license():
    clear_screen()
    # Fleshed out License Header
    print(f"{Colors.HEADER}")
    print(r" __   __               _               ____ ___ __  __ ")
    print(r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
    print(r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
    print(r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
    print(r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
    print(r"      |___/  |___/                                     ")
    print(r"            _     ___ ____ _____ _   _ ____  _____     ")
    print(r"           | |   |_ _/ ___| ____| \ | / ___|| ____|    ")
    print(r"           | |    | | |   |  _| |  \| \___ \|  _|      ")
    print(r"           | |___ | | |___| |___| |\  |___) | |___     ")
    print(r"           |_____|___\____|_____|_| \_|____/|_____|    ")
    print(f"{Colors.ENDC}")

    print(f"{Colors.HEADER}=== MPL 2.0 LICENSE ==={Colors.ENDC}\n")
    license_path = DIRS["LICENSE"]
    
    if os.path.exists(license_path):
        with open(license_path, 'r') as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                print(line, end='')
                # Pause every 20 lines to prevent auto-scrolling to the bottom
                if (i + 1) % 20 == 0:
                    input(f"\n{Colors.CYAN}-- More ({i+1}/{len(lines)}) - Press Enter to continue --{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}License file not found at: {license_path}{Colors.ENDC}")
    
    pause()

def show_about():
    clear_screen()
    print(f"{Colors.HEADER}")
    print(r" __   __               _               ____ ___ __  __ ")
    print(r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
    print(r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
    print(r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
    print(r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
    print(r"      |___/  |___/                                     ")
    print(r"                _    ____   ___  _   _ _____           ")
    print(r"               / \  | __ ) / _ \| | | |_   _|          ")
    print(r"              / _ \ |  _ \| | | | | | | | |            ")
    print(r"             / ___ \| |_) | |_| | |_| | | |            ")
    print(r"            /_/   \_\____/ \___/ \___/  |_|            ")
    print(f"{Colors.ENDC}")
    print(f"""
    {Colors.BOLD}YggdraSIM Suite v2.0{Colors.ENDC}
    Copyright (C) 2026 Hampus Hellsberg
    
    YggdraSIM is a specialized research and security auditing toolkit 
    designed for deep interaction with SIM, USIM, and eUICC platforms. 
    The suite facilitates lower-layer communication to analyze secure 
    element behavior and protocol compliance.

    {Colors.BOLD}Core Sub-Systems:{Colors.ENDC}
    
    * {Colors.CYAN}SCP03 Admin Shell (Local Management):{Colors.ENDC}
      A high-privilege administrative interface utilizing GlobalPlatform 
      Secure Channel Protocol 03. It enables direct ETSI TS 102 221/222 
      file system operations, security attribute (ARR) decoding, and 
      eUICC interaction via SGP.22 logic.

    * {Colors.CYAN}SCP80 OTA Simulator (Remote Management):{Colors.ENDC}
      Implements Remote File Management (RFM) and Over-The-Air (OTA) 
      payload generation. It allows for auditing card security via 
      3GPP TS 31.115 and ETSI TS 102 225 security layering without 
      requiring a live network core.

    * {Colors.CYAN}SCP11 Client (eUICC Provisioning - BETA):{Colors.ENDC}
      {Colors.WARNING}[UNDER CONSTRUCTION]{Colors.ENDC}
      This module simulates an SM-DP+ locally to load profiles from 
      disk directly to the eUICC. It functions as a standalone 
      simulator that handles communication between the SIM and PC 
      with zero reliance on internet or production SM-DP+ servers.

    {Colors.BOLD}Philosophy:{Colors.ENDC}
    As Yggdrasil connects the Nine Realms in Norse mythology, this 
    suite connects the various layers of secure element communication. 
    It acts as the central conduit between local hardware, remote 
    file systems, and asymmetric provisioning realms.
    """)
    pause()

# --- 3. MAIN MENU LOOP ---

def main_menu():
    setup_paths()
    while True:
        clear_screen()

        print(f"{Colors.HEADER}")
        print(r" __   __               _               ____ ___ __  __ ")
        print(r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print(r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print(r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print(r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print(r"      |___/  |___/                                     ")
        print(r"        __  __       _        __  __                  ")
        print(r"       |  \/  | __ _(_)_ __  |  \/  | ___ _ __  _   _ ")
        print(r"       | |\/| |/ _` | | '_ \ | |\/| |/ _ \ '_ \| | | |")
        print(r"       | |  | | (_| | | | | || |  | |  __/ | | | |_| |")
        print(r"       |_|  |_|\__,_|_|_| |_||_|  |_|\___|_| |_|\__,_|")
        print(f"")
        print(f"=== Unified Secure Element Research & Auditing Suite ===")
        print(f" [ Admin Shell | OTA Simulator | Local SM-DP+ Simulation ]")
        print(f" Created and maintained by Hampus Hellsberg")
        print(f"{Colors.ENDC}")
        
        menu_lines = [
            f"{Colors.HEADER}==============================={Colors.ENDC}",
            f"{Colors.GREEN} [1] Admin Shell (SCP03) - Local Management{Colors.ENDC}",
            f"{Colors.GREEN} [2] Admin Shell (SCP03) - Script Execution{Colors.ENDC}",
            f"{Colors.GREEN} [3] Admin Shell (SCP03) - Report & DUMP-FS{Colors.ENDC}",
            f"{Colors.CYAN} [4] OTA Simulator (SCP80) - Remote Management{Colors.ENDC}",
            f"{Colors.CYAN} [5] OTA Simulator (SCP80) - Script Execution{Colors.ENDC}",
            f" {Colors.WARNING}[6] eSIM Management (SCP11) - eUICC Provisioning (BETA){Colors.ENDC}",
            "",
            " [A] About",
            " [L] License (MPL 2.0)",
            " [Q] Quit",
            f"{Colors.HEADER}==============================={Colors.ENDC}"
        ]
        print("\n".join(menu_lines))

        choice = input("\nSelect module: ").strip().upper()

        if choice == '1':
            run_scp03()
        elif choice == '2':
            run_scp03_script()
        elif choice == '3':
            run_scp03_report()
        elif choice == '4':
            run_scp80()
        elif choice == '5':
            run_scp80_script()
        elif choice == '6':
            run_scp11()
        elif choice == 'A':
            show_about()
        elif choice == 'L':
            show_license()
        elif choice == 'Q':
            sys.exit(0)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        sys.exit(0)