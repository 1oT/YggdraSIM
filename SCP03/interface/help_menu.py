from SCP03.config import Config

class HelpMenu:
    """Manages the visual layout and content of the HELP command."""

    @staticmethod
    def print_help():
        print(f"""
{Config.Colors.HEADER}=== YggdraSIM SCP03 Help ==={Config.Colors.ENDC}

{Config.Colors.BOLD}GlobalPlatform{Config.Colors.ENDC}
  {Config.Colors.CYAN}Session (SCP03):{Config.Colors.ENDC}
    {Config.Colors.GREEN}AUTH-SD{Config.Colors.ENDC}                                                     : Authenticate
    {Config.Colors.GREEN}RESET{Config.Colors.ENDC}                                                       : Cold Reset
    {Config.Colors.GREEN}INFO{Config.Colors.ENDC}                                                        : Card Info
    {Config.Colors.GREEN}CPLC{Config.Colors.ENDC}                                                        : Get CPLC
    {Config.Colors.GREEN}KEYS{Config.Colors.ENDC}                     [AID]                              : Get Keys
    {Config.Colors.GREEN}LOGOUT{Config.Colors.ENDC}                                                      : Close Session

  {Config.Colors.CYAN}Registry:{Config.Colors.ENDC}
    {Config.Colors.GREEN}APPS{Config.Colors.ENDC}                                                        : List Applets
    {Config.Colors.GREEN}PKGS{Config.Colors.ENDC}                                                        : List Packages
    {Config.Colors.GREEN}SD{Config.Colors.ENDC}                                                          : List SDs
    {Config.Colors.GREEN}GET{Config.Colors.ENDC}                      <P1><P2>                           : Get Data
    {Config.Colors.GREEN}STORE-DATA{Config.Colors.ENDC}               <Hex> [P1] [P2]                    : Store Data (Auto-chunks)

  {Config.Colors.CYAN}Lifecycle:{Config.Colors.ENDC}
    {Config.Colors.GREEN}INSTALL-INSTALL{Config.Colors.ENDC}          <cap/ijc> [Priv] [Par] [App] [Mod] : Install CAP
    {Config.Colors.GREEN}INSTALL-LOAD{Config.Colors.ENDC}             <cap/ijc>                          : Load CAP
    {Config.Colors.GREEN}INSTALL-APP{Config.Colors.ENDC}              <Pkg> <App> [Mod] [Priv] [Par]     : Instantiate Applet
    {Config.Colors.GREEN}INSTALL-SELECTABLE{Config.Colors.ENDC}       <AID> [Priv]                       : Make Selectable
    {Config.Colors.GREEN}INSTALL-EXTRADITION{Config.Colors.ENDC}      <AppAID> <SDAID>                   : Extradition
    {Config.Colors.GREEN}INSTALL-REGISTRY{Config.Colors.ENDC}         <AID> [Priv] [Par]                 : Registry Update
    {Config.Colors.GREEN}INSTALL-PERSO{Config.Colors.ENDC}            <AID>                              : Personalize Applet
    {Config.Colors.GREEN}LOCK/UNLOCK/DEL{Config.Colors.ENDC}          <AID>                              : Mgmt Object
    {Config.Colors.GREEN}PUT-KEY{Config.Colors.ENDC}                  <OKVN> <ID> <NKVN> <E> <M> <D>     : Rotate Keys

{Config.Colors.BOLD}GSMA{Config.Colors.ENDC}
  {Config.Colors.CYAN}GSMA SGP.02 (M2M):{Config.Colors.ENDC}
    {Config.Colors.GREEN}GET-M2M{Config.Colors.ENDC}                                                     : Scan SGP.02
    {Config.Colors.GREEN}GET-ECASD{Config.Colors.ENDC}                                                   : Scan ECASD

  {Config.Colors.CYAN}GSMA SGP.22 (Consumer):{Config.Colors.ENDC}
    {Config.Colors.GREEN}LIST-CONS{Config.Colors.ENDC}                                                   : List Profiles
    {Config.Colors.GREEN}ENABLE/DISABLE-CONS{Config.Colors.ENDC}      <AID/ID>                           : State Mgmt
    {Config.Colors.GREEN}DELETE-CONS{Config.Colors.ENDC}              <AID/ID>                           : Delete Profile
    {Config.Colors.GREEN}GET-CONS{Config.Colors.ENDC}                                                    : Scan SGP.22

  {Config.Colors.CYAN}GSMA SGP.32 (IoT):{Config.Colors.ENDC}
    {Config.Colors.GREEN}LIST-IOT{Config.Colors.ENDC}                                                    : List Profiles
    {Config.Colors.GREEN}ENABLE/DISABLE-IOT{Config.Colors.ENDC}       <AID/ID>                           : State Mgmt
    {Config.Colors.GREEN}DELETE-IOT{Config.Colors.ENDC}               <AID/ID>                           : Delete Profile
    {Config.Colors.GREEN}GET-IOT{Config.Colors.ENDC}                                                     : Scan SGP.32

{Config.Colors.BOLD}ETSI / 3GPP{Config.Colors.ENDC}
  {Config.Colors.CYAN}File System:{Config.Colors.ENDC}
    {Config.Colors.GREEN}SELECT{Config.Colors.ENDC}                   <Path>                             : Select File
    {Config.Colors.GREEN}READ{Config.Colors.ENDC}                     [Path]                             : Read Binary
    {Config.Colors.GREEN}RECORD{Config.Colors.ENDC}                   <N/ALL> [Path]                     : Read Record
    {Config.Colors.GREEN}UPDATE BINARY{Config.Colors.ENDC}            <Hex>                              : Update Transparent EF
    {Config.Colors.GREEN}UPDATE RECORD{Config.Colors.ENDC}            <N> <Hex>                          : Update Linear Fixed EF
    {Config.Colors.GREEN}SCAN{Config.Colors.ENDC}                                                        : Scan FS
    {Config.Colors.GREEN}REPORT{Config.Colors.ENDC}                   [File]                             : Gen Report
    {Config.Colors.GREEN}DUMP-FS{Config.Colors.ENDC}                  [Dir]                              : Dump EFs to Local Disk

  {Config.Colors.CYAN}Security:{Config.Colors.ENDC}
    {Config.Colors.GREEN}VERIFY-ADM{Config.Colors.ENDC}               [Key]                              : Verify ADM Key
    {Config.Colors.GREEN}VERIFY-PIN{Config.Colors.ENDC}               <ID> <PIN>                         : Verify PIN
    {Config.Colors.GREEN}CHANGE-PIN{Config.Colors.ENDC}               <ID> <Old> <New>                   : Change PIN
    {Config.Colors.GREEN}ENABLE/DISABLE-PIN{Config.Colors.ENDC}       <ID> <PIN>                         : Toggle PIN State
    {Config.Colors.GREEN}UNBLOCK-PIN{Config.Colors.ENDC}              <ID> <PUK> <New>                   : Unblock PIN

  {Config.Colors.CYAN}Auth:{Config.Colors.ENDC}
    {Config.Colors.GREEN}AUTH-GSM{Config.Colors.ENDC}                 <RAND>                             : GSM Auth
    {Config.Colors.GREEN}AUTH-USIM{Config.Colors.ENDC}                <RAND> <AUTN>                      : USIM Auth
    {Config.Colors.GREEN}AUTH-ISIM{Config.Colors.ENDC}                <RAND> <AUTN>                      : ISIM Auth

{Config.Colors.BOLD}System & Tools{Config.Colors.ENDC}
  {Config.Colors.CYAN}Interactive Wizards:{Config.Colors.ENDC}
    {Config.Colors.GREEN}INSTALL-WIZARD-SD{Config.Colors.ENDC}                                           : GPCS Install APDU Wizard
    {Config.Colors.GREEN}INSTALL-WIZARD-APDU{Config.Colors.ENDC}        <cap/ijc>                        : Dry-run CAP APDUs
    {Config.Colors.GREEN}GUIDE{Config.Colors.ENDC}                      [Topic]                          : Open User Guide

  {Config.Colors.CYAN}Configuration:{Config.Colors.ENDC}
    {Config.Colors.GREEN}SHOW{Config.Colors.ENDC}                                                        : View Active Config
    {Config.Colors.GREEN}AIDS{Config.Colors.ENDC}                                                        : List Saved AIDs
    {Config.Colors.GREEN}SET-AID-ALIAS{Config.Colors.ENDC}             <Name> <AID>                      : Save New AID Alias
    {Config.Colors.GREEN}SET-AID{Config.Colors.ENDC}                   <AID>                             : Set Target AID
    {Config.Colors.GREEN}SET-KENC{Config.Colors.ENDC}                  <Key>                             : Set K-ENC
    {Config.Colors.GREEN}SET-KMAC{Config.Colors.ENDC}                  <Key>                             : Set K-MAC
    {Config.Colors.GREEN}SET-DEK{Config.Colors.ENDC}                   <Key>                             : Set DEK
    {Config.Colors.GREEN}SET-KVN{Config.Colors.ENDC}                   <Val>                             : Set KVN
    {Config.Colors.GREEN}SET-ADM{Config.Colors.ENDC}                   <Key>                             : Set ADM Key
    {Config.Colors.GREEN}SET-DEFAULT{Config.Colors.ENDC}                                                 : Reset to Defaults

  {Config.Colors.CYAN}General:{Config.Colors.ENDC}
    {Config.Colors.GREEN}DECODE{Config.Colors.ENDC}                    <Hex>                             : Standalone TLV Decoder
    {Config.Colors.GREEN}OTA{Config.Colors.ENDC}                                                         : Launch SCP80 Tool
    {Config.Colors.GREEN}RUN / SCRIPT{Config.Colors.ENDC}              <File> [Out.yaml]                 : Execute Script
    {Config.Colors.GREEN}CLS{Config.Colors.ENDC}                                                         : Clear Screen
    {Config.Colors.GREEN}HELP{Config.Colors.ENDC}                                                        : Show Help Menu
    {Config.Colors.GREEN}EXIT / Q{Config.Colors.ENDC}                                                    : Exit YggdraSIM
""")