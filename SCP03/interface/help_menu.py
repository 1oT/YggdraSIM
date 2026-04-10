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

from SCP03 .config import Config 

class HelpMenu :
    @staticmethod 
    def print_help ()->None :
        print (f"\n{Config.Colors.HEADER}=== YggdraSIM Command Reference ==={Config.Colors.ENDC}")
        print (f"{Config.Colors.WARNING}Note: Admin secure channel support now includes SCP03 and SCP02 for Security Domain authentication. SCP11 provisioning and relay flows live in the dedicated SCP11 modules.{Config.Colors.ENDC}")
        print (f"\n{Config.Colors.CYAN}[ Session & Card Info ]{Config.Colors.ENDC}")
        print ("  AUTH-SD        : Legacy alias for SCP03-SD.")
        print ("  SCP03-SD       : Authenticate with Security Domain using SCP03.")
        print ("  SCP02-SD       : Authenticate with Security Domain using SCP02.")
        print ("  RESET          : Reset the card connection (ATR).")
        print ("  INFO           : Print card specifications (ATR, ICCID, eID, SGP version).")
        print ("  ATR            : Reset and print a parsed ATR breakdown.")
        print ("  KEYS [AID]     : Retrieve key information for current or specified AID.")
        print ("  LOGOUT         : Close the secure session.")
        print ("  CLS            : Clear the terminal screen.")
        print ("  OTA            : Switch to SCP80 Over-The-Air toolkit.")
        print ("  STK [Commands] : Enter the SCP03 STK subsystem (INIT/SMS/CALL/DATA simulation shell).")

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

        print (f"\n{Config.Colors.CYAN}[ Telecom & eSIM (SGP.22 / SGP.32 / SGP.02) - retrieval + local profile state ]{Config.Colors.ENDC}")
        print ("  LIST           : List eSIM profiles (GetProfilesInfo, SGP.22/SGP.32).")
        print ("  MANAGE-PROFILE : Spec-aware wizard with separate SGP.22, SGP.32, and SGP.02 command sets.")
        print ("                   Local STORE DATA reads retry via base channel, then logical channel 1, then STK mode.")
        print ("  RUN-AUTH       : Execute GSM, USIM, or ISIM authentication algorithms.")
        print ("  RUN-AUTH-TEST  : Run 3GPP TS 35.207 test vector (OPc derivation + card auth).")
        print ("  DERIVE-OPC     : <Ki_hex> <OP_hex> - Derive OPc per 3GPP TS 35.206.")

        print (f"\n{Config.Colors.CYAN}[ SCP11 module map ]{Config.Colors.ENDC}")
        print ("  Main menu [3]  : SCP11 live relay shell (LPAd/IPAd/IPAe).")
        print ("  Main menu [4]  : SCP11 test relay shell (LPAd/IPAd).")
        print ("  Main menu [5]  : SCP11 local access shell (LOAD-PROFILE workflow).")

        print (f"\n{Config.Colors.CYAN}[ Security & PIN Management ]{Config.Colors.ENDC}")
        print ("  MANAGE-PIN     : Unified wizard to Verify, Change, Enable, Disable, or Unblock PINs.")

        print (f"\n{Config.Colors.CYAN}[ Environment Configuration ]{Config.Colors.ENDC}")
        print ("  CONFIG         : Wizard to update SCP03 keys, SCP02 keys, ADM, or Target AID.")
        print ("  SHOW           : Display current SQLite-backed SCP03 configuration.")
        print ("  AIDS           : List registered AID aliases from `Workspace/SCP03/aid.txt`.")
        print ("  SET-AID-ALIAS  : <Name> <AID> - Map a friendly name to an AID.")
        print ("  SET-DEFAULT    : Factory reset configuration to default test keys.")
        print ("  BINDS          : Manage custom macro commands and parameters.")

        print (f"\n{Config.Colors.CYAN}[ File System Operations ]{Config.Colors.ENDC}")
        print ("  SCAN           : Traverse and discover the UICC file tree.")
        print ("  REPORT         : Unified report wizard (FS dump, FS YAML, eUICC YAML, or combined FS+eUICC YAML).")
        print ("  SET-GOLD-PROFILE: <path> [SGP.32|SGP.22|SGP.02] [AUTH=Y|N] - Persist gold combined YAML path in SQLite state for PROFILE-DIFF.")
        print ("  GOLD-PROFILE   : Show persisted gold path, GSMA standard, and SD-auth flag.")
        print ("  CLEAR-GOLD-PROFILE: Clear the persisted path (keeps standard/auth keys).")
        print ("  PROFILE-DIFF   : [gold.yaml] [STANDARD] [AUTH=Y|N] - Capture live FS+eUICC+MNO-SD and diff vs gold (timestamps stripped).")
        print ("  VALIDATE       : [ALL|MF|USIM|ISIM] [ProfileDump.yaml|ProfileDump.json] - Validate active profile FS structure against the profile interoperability spec.")
        print ("  SELECT         : <Path/FID> - Select a DF or EF.")
        print ("  READ [Path]    : Read binary data from the selected EF.")
        print ("  RECORD         : <N/ALL/Start-End> [Path] - Read record(s) from a linear fixed/cyclic EF.")
        print ("  UPDATE         : BINARY <Hex> | RECORD <N> <Hex> - Write data to an EF.")
        print ("  FS-ADMIN       : Administrative tasks (Activate, Delete, Create, Terminate, Resize).")

        print (f"\n{Config.Colors.CYAN}[ System & Developer ]{Config.Colors.ENDC}")
        print ("  GUIDE [Topic]  : Show documentation (Topics: GP, ETSI, GSMA, INSTALL, SECURITY, OTA, CONFIG, SAIP, SUCI, CLI).")
        print ("  DECODE         : <Hex> - Parse and decode a raw BER-TLV string.")
        print ("  RUN / SCRIPT   : <File> [Out.yaml] - Execute a batch script of APDU commands.")
        print ("  DEBUG/VERBOSE  : Toggle raw APDU hex transmission logging.")
        print ("  HELP           : Display this menu.")
        print ("  EXIT / Q       : Disconnect reader and leave SCP03 shell.")
        print ("  QA             : Disconnect reader and exit YggdraSIM.")
        print (f"{Config.Colors.HEADER}=========================================={Config.Colors.ENDC}\n")