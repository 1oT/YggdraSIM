# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

from SCP03.config import Config

class HelpMenu:
    @staticmethod
    def print_help() -> None:
        print(f"\n{Config.Colors.HEADER}=== YggdraSIM Command Reference ==={Config.Colors.ENDC}")
        
        print(f"\n{Config.Colors.CYAN}[ Session & Card Info ]{Config.Colors.ENDC}")
        print("  AUTH-SD        : Authenticate with Security Domain (SCP03).")
        print("  RESET          : Reset the card connection (ATR).")
        print("  INFO           : Print card specifications (ICCID, eID, SGP version).")
        print("  KEYS [AID]     : Retrieve key information for current or specified AID.")
        print("  LOGOUT         : Close the secure session.")
        print("  CLS            : Clear the terminal screen.")
        print("  OTA            : Switch to SCP80 Over-The-Air toolkit.")
        
        print(f"\n{Config.Colors.CYAN}[ GlobalPlatform Execution Wizards ]{Config.Colors.ENDC}")
        print("  WIZARD         : Unified installer for Applets, Packages, and Extradition.")
        print("  PUT-KEY        : Rotate, add, or replace cryptographic keys.")
        print("  SET-STATUS     : Modify lifecycle state of Card, Applet, or Load File.")
        print("  MANAGE-CHANNEL : Open or close logical channels.")
        print("  GET-DATA       : Retrieve registry (APPS/PKGS/SD), CPLC, or custom tags.")
        print("  APPS           : Shortcut to retrieve Applications registry.")
        print("  PKGS           : Shortcut to retrieve Packages registry.")
        print("  SD             : Shortcut to retrieve Security Domains registry.")
        print("  LOCK <AID>     : Shortcut to set state to LOCKED (0x80).")
        print("  UNLOCK <AID>   : Shortcut to set state to SELECTABLE (0x07).")
        print("  DEL <AID>      : Shortcut to delete an object.")
        print("  STORE-DATA     : <Hex> [P1] [P2] - Send raw STORE DATA payload.")
        
        print(f"\n{Config.Colors.CYAN}[ Telecom & eSIM (SGP.22 / SGP.32 / SGP.02) ]{Config.Colors.ENDC}")
        print("  MANAGE-PROFILE : Unified wizard for Listing, Scanning, Enabling, and Deleting profiles.")
        print("  RUN-AUTH       : Execute GSM, USIM, or ISIM authentication algorithms.")
        
        print(f"\n{Config.Colors.CYAN}[ Security & PIN Management ]{Config.Colors.ENDC}")
        print("  MANAGE-PIN     : Unified wizard to Verify, Change, Enable, Disable, or Unblock PINs.")
        
        print(f"\n{Config.Colors.CYAN}[ Environment Configuration ]{Config.Colors.ENDC}")
        print("  CONFIG         : Wizard to update Keys (ENC/MAC/DEK), KVN, ADM, or Target AID.")
        print("  SHOW           : Display current `keys.ini` configuration.")
        print("  AIDS           : List registered AID aliases from `aid.txt`.")
        print("  SET-AID-ALIAS  : <Name> <AID> - Map a friendly name to an AID.")
        print("  SET-DEFAULT    : Factory reset configuration to default test keys.")
        print("  BINDS          : Manage custom macro commands and parameters.")
        
        print(f"\n{Config.Colors.CYAN}[ File System Operations ]{Config.Colors.ENDC}")
        print("  SCAN           : Traverse and discover the UICC file tree.")
        print("  REPORT         : Unified wizard for Single File, Tree Dump, or Full YAML reports.")
        print("  SELECT         : <Path/FID> - Select a DF or EF.")
        print("  READ [Path]    : Read binary data from the selected EF.")
        print("  RECORD         : <N/ALL> [Path] - Read record(s) from a linear fixed/cyclic EF.")
        print("  UPDATE         : BINARY <Hex> | RECORD <N> <Hex> - Write data to an EF.")
        print("  DUMP-FS [Dir]  : Export the file system tree to a local directory.")
        print("  FS-ADMIN       : Administrative tasks (Activate, Delete, Create, Terminate, Resize).")
        
        print(f"\n{Config.Colors.CYAN}[ System & Developer ]{Config.Colors.ENDC}")
        print("  GUIDE [Topic]  : Show documentation (Topics: GP, ETSI, GSMA, INSTALL, SECURITY).")
        print("  DECODE         : <Hex> - Parse and decode a raw BER-TLV string.")
        print("  RUN / SCRIPT   : <File> [Out.yaml] - Execute a batch script of APDU commands.")
        print("  DEBUG/VERBOSE  : Toggle raw APDU hex transmission logging.")
        print("  HELP           : Display this menu.")
        print("  EXIT / Q       : Disconnect reader and exit.")
        print(f"{Config.Colors.HEADER}=========================================={Config.Colors.ENDC}\n")