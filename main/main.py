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
    print(f"{Colors.HEADER}=== GPL LICENSE ==={Colors.ENDC}\n")
    license_path = DIRS["LICENSE"]
    if os.path.exists(license_path):
        with open(license_path, 'r') as f:
            print(f.read())
    else:
        print(f"{Colors.FAIL}License file not found at: {license_path}{Colors.ENDC}")
    pause()

def show_about():
    clear_screen()
    print(f"{Colors.HEADER}=== ABOUT YGGDRASIM ==={Colors.ENDC}")
    print(f"""
    {Colors.BOLD}YggdraSIM Suite v2.0{Colors.ENDC}
    Copyright (C) 2026 Hampus Hellsberg
    
    A comprehensive toolkit for SIM/eUICC research.
    As Yggdrasil connects the Nine Realms, this suite 
    connects the layers of secure element communication.
    """)
    pause()

# --- 3. MAIN MENU LOOP ---

def main_menu():
    setup_paths()

    tree_art = [
        f"      {Colors.GREEN}.--.  .--.  .--.{Colors.ENDC}",
        f"    {Colors.GREEN}.(          )  )  ).{Colors.ENDC}",
        f"  {Colors.GREEN}(                      ){Colors.ENDC}",
        f"   {Colors.GREEN}'._  .  ..  ..  ..  _.'{Colors.ENDC}",
        f"       {Colors.BROWN}| \\  ||  / |{Colors.ENDC}",
        f"       {Colors.BROWN}|  \\ || /  |{Colors.ENDC}",
        f"       {Colors.BROWN}|   \\||/   |{Colors.ENDC}",
        f"       {Colors.BROWN}|    ||    |{Colors.ENDC}",
        f"       {Colors.BROWN}|    ||    |{Colors.ENDC}",
        f"  {Colors.BROWN}/\\__/\\____||____/\\__/\\{Colors.ENDC}",
        f" {Colors.BROWN}/                      \\{Colors.ENDC}"
    ]

    while True:
        clear_screen()
        
        menu_lines = [
            f"{Colors.GREEN}==============================={Colors.ENDC}",
            f"{Colors.BOLD}   YGGDRASIM - CORE WRAPPER    {Colors.ENDC}",
            f"{Colors.GREEN}==============================={Colors.ENDC}",
            " [1] SCP03 Shell",
            " [2] SCP80 OTA Simulator",
            " [3] SCP11 Client",
            "",
            " [A] About",
            " [L] License (GPL)",
            " [Q] Quit",
            f"{Colors.GREEN}-------------------------------{Colors.ENDC}"
        ]

        max_idx = max(len(menu_lines), len(tree_art))

        for i in range(max_idx):
            menu_part = menu_lines[i] if i < len(menu_lines) else ""
            raw_len = len(menu_part.replace(Colors.CYAN, "").replace(Colors.GREEN, "").replace(Colors.ENDC, "").replace(Colors.BOLD, "").replace(Colors.HEADER, "").replace(Colors.BROWN, "").replace(Colors.WARNING, "").replace(Colors.FAIL, ""))
            padding = " " * (35 - raw_len)
            tree_part = tree_art[i] if i < len(tree_art) else ""
            print(f"{menu_part}{padding}{tree_part}")

        choice = input("\nSelect module: ").strip().upper()

        if choice == '1':
            run_scp03()
        elif choice == '2':
            run_scp80()
        elif choice == '3':
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