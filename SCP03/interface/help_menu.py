# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

from SCP03 .config import Config 

class HelpMenu :
    @staticmethod 
    def print_help ()->None :
        print (f"\n{Config.Colors.HEADER}=== YggdraSIM Command Reference ==={Config.Colors.ENDC}")
        print (f"{Config.Colors.WARNING}Note: Some commands are experimental and have not been fully tested on all card types.{Config.Colors.ENDC}")
        print (f"\n{Config.Colors.CYAN}[ Session & Card Info ]{Config.Colors.ENDC}")
        print ("  AUTH-SD        : Authenticate with Security Domain (SCP03).")
        print ("  RESET          : Reset the card connection (ATR).")
        print ("  INFO           : Print card specifications (ICCID, eID, SGP version).")
        print ("  KEYS [AID]     : Retrieve key information for current or specified AID.")
        print ("  LOGOUT         : Close the secure session.")
        print ("  CLS            : Clear the terminal screen.")
        print ("  OTA            : Switch to SCP80 Over-The-Air toolkit.")

        print (f"\n{Config.Colors.CYAN}[ GlobalPlatform Execution Wizards ]{Config.Colors.ENDC}")
        print ("  WIZARD         : Unified installer for Applets, Packages, and Extradition.")
        print ("  PUT-KEY        : Rotate, add, or replace cryptographic keys.")
        print ("  SET-STATUS     : Modify lifecycle state of Card, Applet, or Load File.")
        print ("  MANAGE-CHANNEL : Open or close logical channels.")
        print ("  GET-DATA       : Retrieve registry (APPS/PKGS/SD), CPLC, or custom tags.")
        print ("  APPS           : Shortcut to retrieve Applications registry.")
        print ("  PKGS           : Shortcut to retrieve Packages registry.")
        print ("  SD             : Shortcut to retrieve Security Domains registry.")
        print ("  LOCK <AID>     : Shortcut to set state to LOCKED (0x80).")
        print ("  UNLOCK <AID>   : Shortcut to set state to SELECTABLE (0x07).")
        print ("  DEL <AID>      : Shortcut to delete an object.")
        print ("  STORE-DATA     : <Hex> [P1] [P2] - Send raw STORE DATA payload.")

        print (f"\n{Config.Colors.CYAN}[ Telecom & eSIM (SGP.22 / SGP.32 / SGP.02) – retrieval + local profile state ]{Config.Colors.ENDC}")
        print ("  LIST           : List eSIM profiles (GetProfilesInfo, SGP.22/SGP.32).")
        print ("  MANAGE-PROFILE : Spec-aware wizard with separate SGP.22, SGP.32, and SGP.02 command sets.")
        print ("  RUN-AUTH       : Execute GSM, USIM, or ISIM authentication algorithms.")
        print ("  RUN-AUTH-TEST  : Run 3GPP TS 35.207 test vector (OPc derivation + card auth).")
        print ("  DERIVE-OPC     : <Ki_hex> <OP_hex> - Derive OPc per 3GPP TS 35.206.")

        print (f"\n{Config.Colors.CYAN}[ Security & PIN Management ]{Config.Colors.ENDC}")
        print ("  MANAGE-PIN     : Unified wizard to Verify, Change, Enable, Disable, or Unblock PINs.")

        print (f"\n{Config.Colors.CYAN}[ Environment Configuration ]{Config.Colors.ENDC}")
        print ("  CONFIG         : Wizard to update Keys (ENC/MAC/DEK), KVN, ADM, or Target AID.")
        print ("  SHOW           : Display current `keys.ini` configuration.")
        print ("  AIDS           : List registered AID aliases from `aid.txt`.")
        print ("  SET-AID-ALIAS  : <Name> <AID> - Map a friendly name to an AID.")
        print ("  SET-DEFAULT    : Factory reset configuration to default test keys.")
        print ("  BINDS          : Manage custom macro commands and parameters.")

        print (f"\n{Config.Colors.CYAN}[ File System Operations ]{Config.Colors.ENDC}")
        print ("  SCAN           : Traverse and discover the UICC file tree.")
        print ("  REPORT         : Unified report wizard (FS dump, FS YAML, eUICC YAML, or combined FS+eUICC YAML).")
        print ("  SELECT         : <Path/FID> - Select a DF or EF.")
        print ("  READ [Path]    : Read binary data from the selected EF.")
        print ("  RECORD         : <N/ALL/Start-End> [Path] - Read record(s) from a linear fixed/cyclic EF.")
        print ("  UPDATE         : BINARY <Hex> | RECORD <N> <Hex> - Write data to an EF.")
        print ("  FS-ADMIN       : Administrative tasks (Activate, Delete, Create, Terminate, Resize).")

        print (f"\n{Config.Colors.CYAN}[ System & Developer ]{Config.Colors.ENDC}")
        print ("  GUIDE [Topic]  : Show documentation (Topics: GP, ETSI, GSMA, INSTALL, SECURITY, OTA, CONFIG).")
        print ("  DECODE         : <Hex> - Parse and decode a raw BER-TLV string.")
        print ("  RUN / SCRIPT   : <File> [Out.yaml] - Execute a batch script of APDU commands.")
        print ("  DEBUG/VERBOSE  : Toggle raw APDU hex transmission logging.")
        print ("  HELP           : Display this menu.")
        print ("  EXIT / Q       : Disconnect reader and exit.")
        print (f"{Config.Colors.HEADER}=========================================={Config.Colors.ENDC}\n")