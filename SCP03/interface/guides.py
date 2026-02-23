# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os
from SCP03.config import Config

class ShellGuides:
    """Manages detailed interactive documentation and usage guides."""

    @staticmethod
    def _link(text: str, url: str) -> str:
        if not url: 
            return text
        return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"

    @classmethod
    def print_guide(cls, topic: str = ""):
        original_topic = topic.upper().strip()

        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            current_topic = original_topic

            if not current_topic or current_topic == 'WIZARD':
                print(f"\n{Config.Colors.HEADER}=== YggdraSIM Guide Wizard ==={Config.Colors.ENDC}")
                print("Select a topic to explore:")
                print(f"  {Config.Colors.CYAN}1.{Config.Colors.ENDC} GlobalPlatform Architecture (GP)")
                print(f"  {Config.Colors.CYAN}2.{Config.Colors.ENDC} ETSI / 3GPP File System (ETSI)")
                print(f"  {Config.Colors.CYAN}3.{Config.Colors.ENDC} GSMA eSIM & eUICC (GSMA)")
                print(f"  {Config.Colors.CYAN}4.{Config.Colors.ENDC} Installation & APDU Chaining (INSTALL)")
                print(f"  {Config.Colors.CYAN}5.{Config.Colors.ENDC} Cryptography & Security (SECURITY)")
                print(f"  {Config.Colors.CYAN}6.{Config.Colors.ENDC} SCP80 / OTA Remote Management (OTA)")
                print(f"  {Config.Colors.CYAN}7.{Config.Colors.ENDC} Configuration Files & Persistence (CONFIG)")
                print(f"  {Config.Colors.CYAN}q.{Config.Colors.ENDC} Return to Shell")
                
                choice = input(f"\nChoice [1-7, q]: ").strip().lower()
                if choice == 'q':
                    break
                elif choice == 'exit':
                    break
                elif choice == '1': 
                    current_topic = 'GP'
                elif choice == '2': 
                    current_topic = 'ETSI'
                elif choice == '3': 
                    current_topic = 'GSMA'
                elif choice == '4': 
                    current_topic = 'INSTALL'
                elif choice == '5': 
                    current_topic = 'SECURITY'
                elif choice == '6': 
                    current_topic = 'OTA'
                elif choice == '7':
                    current_topic = 'CONFIG'
                else:
                    print(f"{Config.Colors.FAIL}[!] Invalid choice.{Config.Colors.ENDC}")
                    input(f"\n{Config.Colors.CYAN}[Press Enter to continue]{Config.Colors.ENDC}")
                    continue

            os.system('cls' if os.name == 'nt' else 'clear')

            if current_topic == 'GP':
                cls._print_gp_guide()
            elif current_topic == 'ETSI':
                cls._print_etsi_guide()
            elif current_topic == 'GSMA':
                cls._print_gsma_guide()
            elif current_topic == 'INSTALL':
                cls._print_install_guide()
            elif current_topic == 'SECURITY':
                cls._print_security_guide()
            elif current_topic == 'OTA':
                cls._print_ota_guide()
            elif current_topic == 'CONFIG':
                cls._print_config_guide()
            else:
                print(f"{Config.Colors.FAIL}[!] Unknown guide topic: {current_topic}{Config.Colors.ENDC}")
                break

            prompt_msg = f"\n{Config.Colors.CYAN}[Press Enter to return to menu, or 'q' to exit to shell]{Config.Colors.ENDC}: "
            if original_topic:
                if original_topic != 'WIZARD':
                    prompt_msg = f"\n{Config.Colors.CYAN}[Press Enter to return to shell]{Config.Colors.ENDC}: "

            exit_choice = input(prompt_msg).strip().lower()
            
            if original_topic:
                if original_topic != 'WIZARD':
                    break
                    
            if exit_choice == 'q':
                break
            if exit_choice == 'exit':
                break

    @classmethod
    def _print_gp_guide(cls):
        spec_url = "https://globalplatform.org/wp-content/uploads/2025/05/GPC_CardSpecification_v2.3.1.49_PublicRvw.pdf"
        print(f"""
{Config.Colors.HEADER}=== GlobalPlatform Architecture & APDU Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("GPC Card Specification v2.3.1", spec_url)}

{Config.Colors.CYAN}1. Security Domain (SD) Architecture (GPCS 2.2, 11.1){Config.Colors.ENDC}
   The Issuer Security Domain (ISD) is the primary root of trust, possessing Token Verification and
   Authorized Management privileges. Supplementary Security Domains (SSD) govern provisioning for
   Application Providers or Controlling Authorities.
   - {Config.Colors.BOLD}SELECT (00 A4 04 00):{Config.Colors.ENDC} `00 A4 04 00 <Lc> <AID>`. Standard GP ISD AID: `A0 00 00 01 51 00 00 00`.
     Selecting an SD routes subsequent APDUs to its SCP handler (e.g. INITIALIZE UPDATE, EXTERNAL AUTH).
   - {Config.Colors.BOLD}Privilege Bitmask (Tag C5):{Config.Colors.ENDC} 0x80=Security Domain, 0x40=DAP Verification, 0x20=Delegated Management,
     0x10=Card Lock, 0x08=Card Terminate, 0x04=Default Selected, 0x02=CVM Management.

{Config.Colors.CYAN}2. SCP03 Handshake: INITIALIZE UPDATE (80 50) & EXTERNAL AUTHENTICATE (84 82){Config.Colors.ENDC}
   The secure channel is established before any protected GP commands.
   - {Config.Colors.BOLD}INITIALIZE UPDATE:{Config.Colors.ENDC} `80 50 00 00 08 <Host_Challenge(8)>`. Sent in clear. Card returns:
     Key Version Number (1), Key Identifier (1), Key Diversification Data (10), Card Challenge (8), Card Cryptogram (8).
     Session keys (S-ENC, S-MAC, S-RMAC) are derived via NIST SP 800-108 KDF from static K-ENC/K-MAC and Host+Card challenges.
   - {Config.Colors.BOLD}EXTERNAL AUTHENTICATE:{Config.Colors.ENDC} `84 82 <SecLevel> 00 10 <Host_Cryptogram(8)> <MAC(8)>`. CLA 84 = secure messaging.
     Host Cryptogram = CMAC(S-MAC, derivation_data). Card verifies cryptogram; on success the channel is opened (e.g. SecLevel 0x33 = C-MAC + C-DECRYPT + R-MAC + R-ENCRYPT).

{Config.Colors.CYAN}3. Registry Discovery (GET STATUS - 80 F2) (GPCS 11.3){Config.Colors.ENDC}
   The GP Registry maps Executable Load Files (ELF), Executable Modules (EM), and Applications to lifecycles.
   - {Config.Colors.BOLD}APDU:{Config.Colors.ENDC} `80 F2 <P1> <P2> <Lc> <Search_Criteria>`. Search_Criteria often Tag 4F (AID) with length 00 for first/next.
   - {Config.Colors.YELLOW}P1 (Target):{Config.Colors.ENDC} 0x80 = Issuer Security Domain / Card, 0x40 = Applications, 0x20 = Load File Data, 0x10 = Executable Load File and Executable Module.
   - {Config.Colors.YELLOW}P2 (Sequence):{Config.Colors.ENDC} 0x00 = initial block; 0x01 (or next) = subsequent block. SW 63 10 = more data (increment P2).
   - {Config.Colors.BOLD}Response (Tag E3):{Config.Colors.ENDC} Per-entry: AID (Tag 4F), Lifecycle State (Tag 9F70), Privileges (Tag C5). State: 00=LOADED, 01=OP_READY, 03=INSTALLED, 07=SELECTABLE, 0F=PERSONALIZED, 80=LOCKED, 83=TERMINATED.

{Config.Colors.CYAN}4. GET DATA (80 CA) vs GET STATUS{Config.Colors.ENDC}
   GET DATA retrieves data objects from the current application/SD; GET STATUS retrieves registry entries.
   - {Config.Colors.BOLD}GET DATA:{Config.Colors.ENDC} `80 CA <P1> <P2> [<Lc> <Tag_List>]`. P1|P2 = tag (e.g. 00 E0 = Key Information Template, 9F 7F = CPLC).
   - Key Information Template (00 E0): returns key version, ID, type, length for each key in the SD.

{Config.Colors.CYAN}5. Object State Transitions (SET STATUS - 80 F0) (GPCS 11.10){Config.Colors.ENDC}
   Transitions lifecycle state of registry objects. Some transitions are irreversible (e.g. TERMINATED).
   - {Config.Colors.BOLD}APDU:{Config.Colors.ENDC} `80 F0 <P1> <P2> <Lc> [Target_AID]`. P1 = target: 0x80 (ISD/Card), 0x40 (Application), 0x20 (Load File). P2 = new state (e.g. 0x07 Selectable, 0x80 Locked).

{Config.Colors.CYAN}6. Key Rotation & Wrapping (PUT KEY - 80 D8) (GPCS 11.8){Config.Colors.ENDC}
   Static keys in the SD are updated via PUT KEY. Key material is encrypted (wrapped) so it is never sent in clear.
   - {Config.Colors.BOLD}APDU:{Config.Colors.ENDC} `80 D8 <P1_Old_KVN> <P2_Key_ID> <Lc> <KeyData>`. P1=00 provisions a new KVN.
   - {Config.Colors.YELLOW}Key block (per key):{Config.Colors.ENDC} Key Type (88=AES, 81/82/83=DES), Key Length (10/18/20 for AES), Encrypted Key (DEK-wrapped), KCV Length (03), KCV (e.g. first 3 bytes of AES-ECB(key, 0x01..01)).
   - {Config.Colors.YELLOW}DEK:{Config.Colors.ENDC} The Data Encryption Key (K-DEK) is used to wrap key material (e.g. AES-ECB per GPCS). Session keys are derived from K-ENC/K-MAC only.

{Config.Colors.CYAN}7. Data Personalization (STORE DATA - 80 E2) (GPCS 11.11){Config.Colors.ENDC}
   Pushes Data Grouping Identifiers (DGIs) or TLVs into the SD/Application. Multi-block: use P2 block number.
   - {Config.Colors.BOLD}APDU:{Config.Colors.ENDC} `80 E2 <P1> <P2> <Lc> <Data>`. P1: 0x00 = more blocks, 0x80 = last block. P2 = block number (00, 01, 02...).
   - {Config.Colors.BOLD}DGI (Tag 90):{Config.Colors.ENDC} Personalization data in TLV form; e.g. Tag 4F (ISD AID), Tag 66 (Card Recognition Data).

{Config.Colors.CYAN}8. Logical Channels (MANAGE CHANNEL - 00 70) (ISO 7816-4){Config.Colors.ENDC}
   Multiple applications can be active without closing the secure channel. Basic channel = 0.
   - {Config.Colors.BOLD}Open:{Config.Colors.ENDC} `00 70 00 00 01`. Response data contains the new channel number.
   - {Config.Colors.BOLD}Close:{Config.Colors.ENDC} `00 70 80 <Channel_Number> 00`.
   - {Config.Colors.YELLOW}CLA:{Config.Colors.ENDC} For extended length and channel: CLA = 0x00 | (channel & 0x03). Commands on that channel use this CLA.
""")

    @classmethod
    def _print_etsi_guide(cls):
        spec_url = "https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/16.00.00_60/ts_102221v160000p.pdf"
        print(f"""
{Config.Colors.HEADER}=== ETSI / 3GPP File System & Access Control Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("ETSI TS 102 221 (UICC)", spec_url)}

{Config.Colors.CYAN}1. File Hierarchy & Selection (TS 102 221){Config.Colors.ENDC}
   UICC file tree: MF (root) -> DF/ADF (directories) -> EF (elementary files). Selection by 2-byte FID or path.
   - {Config.Colors.BOLD}SELECT (00 A4 00 04):{Config.Colors.ENDC} `00 A4 00 04 02 <FID>` or `00 A4 04 00 <Lc> <Path>` (path = concatenated FIDs).
   - {Config.Colors.BOLD}MF:{Config.Colors.ENDC} FID 3F00. Root. Contains EF-DIR (2F00), EF-ICCID (2FE2), EF-ARR (6F06), etc.
   - {Config.Colors.BOLD}ADF-USIM:{Config.Colors.ENDC} Typically 7FFF or 7FF0. Contains EF-IMSI (6F07), EF-Keys (6F08), EF-LOCI (6F7E), etc. (3GPP TS 31.102).
   - {Config.Colors.BOLD}FCP (Tag 62):{Config.Colors.ENDC} Returned in response. Tag 82 = File Descriptor (78=DF, 41=Transparent EF, 42=Linear Fixed, 43=Cyclic). Tag 83 = File ID (2 bytes). Tag 80 = File size (transparent). Tag 8A = Life Cycle (01/03/04/05). Tag 8B/8C/AB = Access conditions (read/update/admin).

{Config.Colors.CYAN}2. Transparent EF — READ BINARY / UPDATE BINARY{Config.Colors.ENDC}
   - {Config.Colors.BOLD}READ BINARY:{Config.Colors.ENDC} `00 B0 <P1> <P2> <Le>`. P1|P2 = 2-byte offset (P1 high byte, P2 low byte). Le = number of bytes to read (00 = max).
   - {Config.Colors.BOLD}UPDATE BINARY:{Config.Colors.ENDC} `00 D6 <P1> <P2> <Lc> <Data>`. Same offset encoding. Short EF: single command; long EF: multiple commands with increasing offset.

{Config.Colors.CYAN}3. Linear Fixed / Cyclic EF — Records{Config.Colors.ENDC}
   - {Config.Colors.BOLD}READ RECORD:{Config.Colors.ENDC} `00 B2 <RecNbr> <Mode> <Le>`. Mode: 02=next, 03=previous, 04=absolute (RecNbr = record number).
   - {Config.Colors.BOLD}UPDATE RECORD:{Config.Colors.ENDC} `00 DC <RecNbr> <Mode> <Lc> <Data>`.
   - {Config.Colors.BOLD}SEARCH RECORD:{Config.Colors.ENDC} `00 A2 <RecNbr> <Mode> <Lc> <Search_Pattern>`. Mode 04 = from record 1. Used for FDN, SMS, etc.

{Config.Colors.CYAN}4. Administrative File Management (FS-ADMIN){Config.Colors.ENDC}
   Requires ADM (Administrative) privilege; typically VERIFY (00 20) with ADM key before CREATE/DELETE/ACTIVATE/DEACTIVATE.
   - {Config.Colors.BOLD}CREATE FILE (00 E0):{Config.Colors.ENDC} `00 E0 00 00 <Lc> <FCP_Template>`. Creates DF or EF under current DF. FCP defines type, size, access.
   - {Config.Colors.BOLD}DELETE FILE (00 E4):{Config.Colors.ENDC} `00 E4 00 00 02 <FID>`. Deletes immediate child of current DF.
   - {Config.Colors.BOLD}RESIZE (80 D4):{Config.Colors.ENDC} Proprietary; resizes transparent or linear fixed EF when supported.

{Config.Colors.CYAN}5. File Life Cycle & Activation{Config.Colors.ENDC}
   - {Config.Colors.BOLD}DEACTIVATE FILE (00 04):{Config.Colors.ENDC} `00 04 00 00 00`. Life cycle 04 = Deactivated; read/update may be denied by ARR.
   - {Config.Colors.BOLD}ACTIVATE FILE (00 44):{Config.Colors.ENDC} `00 44 00 00 00`. Life cycle 05 = Operational (activated).
""")

    @classmethod
    def _print_gsma_guide(cls):
        main_url = "https://www.gsma.com/solutions-and-impact/technologies/esim/esim-specification/"
        print(f"""
{Config.Colors.HEADER}=== GSMA eSIM & eUICC Provisioning Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("GSMA SGP.22 / SGP.02 / SGP.32", main_url)}

{Config.Colors.WARNING}Scope (this tool):{Config.Colors.ENDC} Data retrieval only. We do NOT authenticate to ISD-R for provisioning (that is planned for the SCP11 module). Supported: LIST, Enable/Disable/Delete profile, GET DATA, GetProfilesInfo, GetRAT, RetrieveNotificationsList, GetEimConfigurationData (SGP.32), EuiccInfo1/2, EuiccConfiguredData. NOT supported: StoreMetadata, UpdateMetadata, LoadProfile, PrepareDownload, LoadBoundProfilePackage, AuthenticateServer, or any ES10b provisioning flow.

{Config.Colors.CYAN}1. Consumer eUICC Architecture (SGP.22){Config.Colors.ENDC}
   Profiles are downloaded and managed via the Local Profile Assistant (LPA) over the ES10c interface (APDU to ISD-R).
   - {Config.Colors.BOLD}ISD-R (Issuer Security Domain Root):{Config.Colors.ENDC} Management application. AID: `A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 01 00`. Select with 00 A4 04 00 Lc AID; then ES10c commands via STORE DATA (80 E2) with BER-TLV.
   - {Config.Colors.BOLD}ISD-P (Issuer Security Domain Profile):{Config.Colors.ENDC} One Profile per ISD-P; contains MNO subscription (network apps, files, keys).
   - {Config.Colors.BOLD}ECASD (eUICC Controlling Authority SD):{Config.Colors.ENDC} Root of trust: CI key, EUM certificates, EID (eUICC ID). EID is a 32-digit (20-byte BCD) identifier.

{Config.Colors.CYAN}2. ES10c — Local Profile Management (STORE DATA to ISD-R){Config.Colors.ENDC}
   All ES10c requests are STORE DATA (80 E2) with P1=91 (reference), data = BER-TLV. Response in response data or 91 xx (proactive).
   - {Config.Colors.BOLD}GetProfilesInfo (BF 2D):{Config.Colors.ENDC} `80 E2 91 00 03 BF 2D 00`. Returns list of Profiles: ICCID, state (Enabled/Disabled), Profile nickname, MNO name.
   - {Config.Colors.BOLD}EnableProfile (BF 31):{Config.Colors.ENDC} `80 E2 91 00 <Lc> BF 31 <Len> [A0 | A1 <ICCID>]`. Enables the Profile. Only one Enabled at a time unless MEP.
   - {Config.Colors.BOLD}DisableProfile (BF 32):{Config.Colors.ENDC} `80 E2 91 00 <Lc> BF 32 <Len> [A0 | A1 <ICCID>]`. Disables the current or specified Profile.
   - {Config.Colors.BOLD}DeleteProfile (BF 33):{Config.Colors.ENDC} `80 E2 91 00 <Lc> BF 33 <Len> [A0 | A1 <ICCID>]`. Permanently deletes the ISD-P and Profile.
   - {Config.Colors.YELLOW}SW 91 xx:{Config.Colors.ENDC} Proactive command pending; terminal should perform REFRESH (01) so EF-DIR and network state are updated.

{Config.Colors.CYAN}3. eUICC Information (ES10b/ES10c){Config.Colors.ENDC}
   - {Config.Colors.BOLD}EuiccInfo1 (BF 20):{Config.Colors.ENDC} `80 E2 91 00 03 BF 20 00`. Returns eUICC firmware version (e.g. SVN).
   - {Config.Colors.BOLD}EuiccInfo2 (BF 22):{Config.Colors.ENDC} `80 E2 91 00 03 BF 22 00`. Returns capabilities (ExtExtCardResource, supported crypto, default SM-DP+ address list).
   - {Config.Colors.BOLD}EID:{Config.Colors.ENDC} Retrieved via GET DATA (00 CA 00 5A 00) from ECASD context or from EuiccInfo2; 20-byte BCD EID.

{Config.Colors.CYAN}4. SGP.32 IoT retrieval (ES10b, no auth){Config.Colors.ENDC}
   - {Config.Colors.BOLD}GetRAT (BF 43):{Config.Colors.ENDC} Rules Authorisation Table. Command: GET-RAT.
   - {Config.Colors.BOLD}RetrieveNotificationsList (BF 2B):{Config.Colors.ENDC} Pending notifications. Command: GET-NOTIFICATIONS.
   - {Config.Colors.BOLD}GetEimConfigurationData (BF 55):{Config.Colors.ENDC} eIM configuration (SGP.32 only). Command: GET-EIM-CONFIG.

{Config.Colors.CYAN}5. Legacy M2M (SGP.02){Config.Colors.ENDC}
   No LPA on device; SM-SR pushes Profiles via SCP03/SCP80 remote scripts. MANAGE-PROFILE in YggdraSIM can scan/list Profiles via ETSI SELECT and registry read to the ISD-R, without using SGP.22 STORE DATA tags.
""")

    @classmethod
    def _print_install_guide(cls):
        print(f"""
{Config.Colors.HEADER}=== Install Wizard & APDU Builder Guide ==={Config.Colors.ENDC}

{Config.Colors.CYAN}1. INSTALL Command Overview (GPCS 11.5){Config.Colors.ENDC}
   INSTALL [for load] creates a Load File container; LOAD (80 E8) sends the CAP/IJC bytes; INSTALL [for install] or [for install and make selectable] instantiates the applet with AID and privileges.

{Config.Colors.CYAN}2. Wizard Options (WIZARD menu){Config.Colors.ENDC}
   - {Config.Colors.BOLD}1 — INSTALL [for load] (GPCS 11.5.2.3.1):{Config.Colors.ENDC} P1=02. Registers a new Executable Load File (ELF) in the registry. Data: Load File AID (LV).
   - {Config.Colors.BOLD}2 — INSTALL [for install] (11.5.2.3.2):{Config.Colors.ENDC} P1=04. Instantiates an applet from a loaded module. Requires Load File AID, Module AID, Applet AID, privileges, optional install params.
   - {Config.Colors.BOLD}3 — INSTALL [for make selectable] (11.5.2.3.3):{Config.Colors.ENDC} Makes an installed applet selectable (assigns application AID, optional params).
   - {Config.Colors.BOLD}4 — INSTALL [for extradition] (11.5.2.3.4):{Config.Colors.ENDC} Transfers control of an SSD to another CA (extradition token).
   - {Config.Colors.BOLD}5 — INSTALL [for registry update] (11.5.2.3.5):{Config.Colors.ENDC} Updates registry metadata (e.g. AID, privileges) without re-loading.
   - {Config.Colors.BOLD}6 — INSTALL [for personalization] (11.5.2.3.6):{Config.Colors.ENDC} DGI-based personalization; sends STORE DATA / personalization TLVs to the selected SD (requires transport).
   - {Config.Colors.BOLD}7 — INSTALL [for install and make selectable] (11.5.2.3.7):{Config.Colors.ENDC} P1=0C. Single step: install applet and make it selectable.
   - {Config.Colors.BOLD}8 — Full CAP Install Sequence:{Config.Colors.ENDC} Parses a CAP/IJC file, extracts Package/Applet AIDs, builds INSTALL [for load], LOAD (chunked), INSTALL [for install]. Supports OTA chunk sizes (e.g. SMS-PP block limits).

{Config.Colors.CYAN}3. APDU Structure (80 E6){Config.Colors.ENDC}
   `80 E6 <P1> 00 <Lc> <LoadFileAID_LV> <ModuleAID_LV> <AppletAID_LV> <Priv_LV> <Params_LV> <Token_LV>`. Mandatory empty fields encoded as length 00 (no value).

{Config.Colors.CYAN}4. Applet Privileges (Priv_LV bitmask){Config.Colors.ENDC}
   0x80=Security Domain, 0x40=DAP Verification, 0x20=Delegated Management, 0x10=Card Lock, 0x08=Card Terminate, 0x04=Default Selected, 0x02=CVM Management.

{Config.Colors.CYAN}5. Install Parameters (TLV){Config.Colors.ENDC}
   - {Config.Colors.BOLD}C9 (Application Specific):{Config.Colors.ENDC} Passed to applet install().
   - {Config.Colors.BOLD}EF (GP System):{Config.Colors.ENDC} C6/C7=Memory Quotas, C8=Global Service, C9=Implicit Selection, CA/CB=Reserved Memory.
   - {Config.Colors.BOLD}EA (UICC System, TS 102 226):{Config.Colors.ENDC} 80=Toolkit, 81=Access, 82=Admin, 83=Update, C3=DAP. ADP: 00=Full, 02=UICC, FF=None.
   - {Config.Colors.BOLD}CA (SIM File Access):{Config.Colors.ENDC} Legacy 2G. ETSI TS 102 226 forbids CA and EA in the same install parameters; wizard enforces this.
""")

    @classmethod
    def _print_security_guide(cls):
        print(f"""
{Config.Colors.HEADER}=== Cryptography & Security Guide ==={Config.Colors.ENDC}

{Config.Colors.CYAN}1. Secure Channel Protocol 03 (SCP03){Config.Colors.ENDC}
   SCP03 provides confidentiality (C-DECRYPT/R-ENCRYPT) and integrity (C-MAC/R-MAC) over APDU payloads. Keys in `keys.ini`: K-ENC, K-MAC, K-DEK.
   - {Config.Colors.BOLD}Session key derivation (NIST SP 800-108 KDF):{Config.Colors.ENDC} Context = Host Challenge (8) || Card Challenge (8) from INITIALIZE UPDATE response. S-ENC = KDF(K-ENC, 0x04, context, 128); S-MAC = KDF(K-MAC, 0x06, context, 128); S-RMAC = KDF(K-MAC, 0x07, context, 128). Key data = 11 bytes zero || constant || 0x00 || 0x00 0x40 || 0x01 || context; SessionKey = first 16 bytes of CMAC(StaticKey, key_data).
   - {Config.Colors.BOLD}K-ENC / K-MAC:{Config.Colors.ENDC} Used only for derivation. S-ENC encrypts/decrypts payloads (AES-CBC, IV from SSC). S-MAC/S-RMAC for command/response MAC (8 bytes).
   - {Config.Colors.BOLD}K-DEK:{Config.Colors.ENDC} Not derived. Used to wrap key material in PUT KEY (e.g. AES-ECB or AES-CBC per implementation). Session keys are not used to wrap keys.

{Config.Colors.CYAN}2. Key Rotation & Wrapping (PUT KEY - 80 D8){Config.Colors.ENDC}
   New static keys are sent encrypted (wrapped) so they never appear in clear. Payload: New KVN (1 byte) then per key: Key Type (88=AES), Key Length, Encrypted Key (DEK-wrapped), KCV Length (3), KCV. KCV = first 3 bytes of AES-ECB(key, 0x01 repeated 16). KVN identifies the active key set on the card.

{Config.Colors.CYAN}3. PIN & ADM (ISO 7816-4){Config.Colors.ENDC}
   - {Config.Colors.BOLD}Padding:{Config.Colors.ENDC} PIN 8 bytes; shorter PINs right-padded with FF. Example: "1234" -> 31 32 33 34 FF FF FF FF.
   - {Config.Colors.BOLD}VERIFY (00 20):{Config.Colors.ENDC} `00 20 00 <Ref> 08 <Padded_PIN>`. Ref: 0x00=CHV1, 0x0A=ADM, etc.
   - {Config.Colors.BOLD}CHANGE REFERENCE (00 24):{Config.Colors.ENDC} `00 24 00 <Ref> 10 <Padded_Old> <Padded_New>`.
   - {Config.Colors.YELLOW}SW 63 CX:{Config.Colors.ENDC} X = retries left. SW 69 83 = reference blocked.

{Config.Colors.CYAN}4. Network Authentication (RUN-AUTH, 00 88){Config.Colors.ENDC}
   INTERNAL AUTHENTICATE: card runs USIM/ISIM or GSM algorithm.
   - {Config.Colors.BOLD}USIM/ISIM (MILENAGE/TUAK):{Config.Colors.ENDC} Input: RAND (16), AUTN (16). Card verifies SQN/MAC; returns RES, CK, IK (and possibly other keys).
   - {Config.Colors.BOLD}GSM (COMP128):{Config.Colors.ENDC} Input: RAND (16). Returns SRES (4), Kc (8).
""")

    @classmethod
    def _print_config_guide(cls):
        print(f"""
{Config.Colors.HEADER}=== Configuration Files & Persistence Guide ==={Config.Colors.ENDC}

{Config.Colors.CYAN}1. Config Directory (CONFIG_DIR){Config.Colors.ENDC}
   - {Config.Colors.BOLD}Source (Python):{Config.Colors.ENDC} Config files are read/written under the module directory (e.g. SCP03/keys.ini, SCP03/aid.txt, SCP03/fids.txt, SCP03/binds.json). SCP80 uses SCP80/ota_config.ini.
   - {Config.Colors.BOLD}Frozen executable:{Config.Colors.ENDC} CONFIG_DIR = directory of the executable. All config files are read from and saved to that directory so changes persist. Default fids.txt, aid.txt, binds.json are copied there on first run if missing.

{Config.Colors.CYAN}2. SCP03 Configuration Files{Config.Colors.ENDC}
   - {Config.Colors.BOLD}keys.ini:{Config.Colors.ENDC} [KEYS] section: kenc, kmac, dek (32/48/64 hex chars for AES-128/192/256), kvn (hex), aid (default SD AID), adm (ADM key for ETSI VERIFY). CONFIG wizard or WIZARD > Update Keys can rotate and save.
   - {Config.Colors.BOLD}aid.txt:{Config.Colors.ENDC} One line per alias: `Name: AID` (hex, no spaces). Enables `SELECT Name` in the shell (e.g. ISD-R, USIM).
   - {Config.Colors.BOLD}fids.txt:{Config.Colors.ENDC} Maps path names to FIDs: `Path: FID` (e.g. USIM: 7FFF, USIM/IMSI: 6F07). Used by file system navigator and TREE/SCAN.
   - {Config.Colors.BOLD}binds.json:{Config.Colors.ENDC} Custom command macros. Keys = command names; values = shell input(s). Use {{0}}, {{1}} for arguments; `;` for multiple commands. Example: "adm": "manage-pin verify 0a {{0}}".

{Config.Colors.CYAN}3. SCP80 OTA Configuration{Config.Colors.ENDC}
   - {Config.Colors.BOLD}ota_config.ini:{Config.Colors.ENDC} In SCP80 module folder. [ota]: tar (3-byte hex), spi, key_enc, key_mac (KIC/KID keys), transport (SMS/HTTP), etc.

{Config.Colors.CYAN}4. SCP11 / SM-DP+ Simulation{Config.Colors.ENDC}
   Certificates (e.g. CERT.DPauth.ECDSA.der, SK.DPauth.ECDSA.pem, CERT.DPpb.ECDSA.der, SK.DPpb.ECDSA.pem) are read from CONFIG_DIR when using local SM-DP+ simulation. Replace with test certs for custom provisioning.
""")

    @classmethod
    def _print_ota_guide(cls):
        print(f"""
{Config.Colors.HEADER}=== SCP80 OTA (Remote Management) Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} ETSI TS 102 225 (Secured Packet Structure), 3GPP TS 31.115 (OTA)

{Config.Colors.CYAN}1. OTA Architecture (SCP80){Config.Colors.ENDC}
   Remote servers send Secured Packets (SMS-PP, HTTP, or CAT_TP) to the UICC. The packet is deciphered and verified by the card using keys identified by KIC/KID; the inner APDU is then executed (e.g. by RFM or RAM).
   - {Config.Colors.BOLD}TAR (Toolkit Application Reference):{Config.Colors.ENDC} 3-byte identifier. Routes the packet to the correct handler (e.g. Remote File Manager, Remote Applet Manager). Example: B00000, B00010.
   - {Config.Colors.BOLD}SPI (Security Parameter Indicator):{Config.Colors.ENDC} Encodes whether the payload is ciphered and/or cryptographically checksummed (CC). Algorithm (DES/3DES/AES) and CC presence are profile-dependent.
   - {Config.Colors.BOLD}KIC / KID:{Config.Colors.ENDC} Key identifiers for ciphering and CC. Reference keys stored in the OTA Security Domain (or equivalent) for the given TAR.

{Config.Colors.CYAN}2. Secured Packet Structure (ETSI TS 102 225){Config.Colors.ENDC}
   Command Header List (CHL): SPI (1), KIC (1), KID (1), TAR (3), CNTR (5, counter), PCNTR (1, padding counter). Optional CC (e.g. 8 bytes) after payload; payload (and optionally CC) may be encrypted per SPI. Full packet is often sent in an Envelope (80 C2 00 00 Lc <Secured_Packet>) to the card.

{Config.Colors.CYAN}3. Supported OTA Operations in YggdraSIM{Config.Colors.ENDC}
   - {Config.Colors.BOLD}READ/UPDATE:{Config.Colors.ENDC} Remote file read (00 B0) / update (00 D6) wrapped in a secured packet.
   - {Config.Colors.BOLD}INSTALL / DELETE:{Config.Colors.ENDC} Remote Applet/Package management (RAM).
   - {Config.Colors.BOLD}STORE DATA:{Config.Colors.ENDC} Multi-block or large payloads; chunking for SMS-PP size limits.

{Config.Colors.CYAN}4. Configuration{Config.Colors.ENDC}
   Configure TAR, SPI, KIC, KID, and keys in `ota_config.ini` (SCP80 module). Cipher and CC algorithm must match the card profile.
""")