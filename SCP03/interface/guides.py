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

{Config.Colors.CYAN}1. Security Domain (SD) Architecture{Config.Colors.ENDC}
   The Issuer Security Domain (ISD) is the primary root of trust on the card, possessing the `Token Verification` 
   and `Authorized Management` privileges. Supplementary Security Domains (SSD) govern application provisioning 
   for Application Providers (APs) or Controlling Authorities (CAs).
   - {Config.Colors.BOLD}ISD Selection:{Config.Colors.ENDC} `00 A4 04 00 <Lc> <AID>`. Standard GP ISD is `A0 00 00 01 51 00 00 00`. 
     Selecting an SD routes subsequent APDUs (e.g., `80 50`, `80 82`) to its internal SCP handler.
   - {Config.Colors.BOLD}Privilege Bitmask (Tag C5):{Config.Colors.ENDC} Determines SD capabilities.
     `0x80` = Security Domain, `0x40` = DAP Verification, `0x20` = Delegated Management, `0x10` = Card Lock, `0x08` = Card Terminate, `0x04` = Default Selected, `0x02` = CVM Management.

{Config.Colors.CYAN}2. Registry Discovery (GET STATUS - 80 F2){Config.Colors.ENDC}
   The GP Registry maps Executable Load Files (ELF), Executable Modules (EM), and Applications (Applets) 
   to their respective lifecycles.
   - {Config.Colors.BOLD}APDU:{Config.Colors.ENDC} `80 F2 <P1> <P2> <Lc> <Search_Criteria>`. 
     - {Config.Colors.YELLOW}P1 (Target):{Config.Colors.ENDC} 80 (ISD/SD), 40 (Applications), 20 (Load Files), 10 (Modules).
     - {Config.Colors.YELLOW}P2 (Control):{Config.Colors.ENDC} 00 (Initial Block), 01 (Next Block). `xxxxxx0x` bits indicate return format.
   - {Config.Colors.BOLD}Response (Tag E3 - GlobalPlatform Registry Data):{Config.Colors.ENDC} 
     Format per entry: `[Length] [AID_Len] [AID] [Lifecycle_State] [Privileges_Bitmask]`.
     - {Config.Colors.YELLOW}State Mappings:{Config.Colors.ENDC} `01` (LOADED), `03` (INSTALLED), `07` (SELECTABLE), `0F` (PERSONALIZED), `80` (LOCKED).

{Config.Colors.CYAN}3. Object State Transitions (SET STATUS - 80 F0){Config.Colors.ENDC}
   Transitions object states in the registry. Irreversible states include `TERMINATED` (0F for Applets, FF for Card).
   - {Config.Colors.BOLD}APDU:{Config.Colors.ENDC} `80 F0 <P1> <P2> <Lc> [Target_AID]`.
     - {Config.Colors.YELLOW}P1 (Target Component):{Config.Colors.ENDC} 80 (ISD/Card State), 40 (Application), 20 (Load File).
     - {Config.Colors.YELLOW}P2 (State):{Config.Colors.ENDC} E.g., `80` locks an Applet. `07` restores Selectable state.

{Config.Colors.CYAN}4. Key Rotation & Wrapping (PUT KEY - 80 D8){Config.Colors.ENDC}
   Static keys inside an SD must be rotated via secure wrapping. SCP03 enforces DEK wrapping for key material.
   - {Config.Colors.BOLD}APDU:{Config.Colors.ENDC} `80 D8 <Old_KVN> <Key_ID> <Lc> <KeyData>`.
   - {Config.Colors.YELLOW}Old KVN (P1):{Config.Colors.ENDC} Target Key Version Number to rotate. `00` provisions a new KVN.
   - {Config.Colors.YELLOW}Key Format Structure:{Config.Colors.ENDC} For AES, the payload iterates: 
     `[Key Type (88)] [Key Length (10/18/20)] [AES-ECB Encrypted Key Data] [KCV Length (03)] [KCV Data]`.
   - {Config.Colors.YELLOW}Cryptographic Note:{Config.Colors.ENDC} Key Data must be padded to block sizes and encrypted using the Session-DEK key. The KCV is computed as the first 3 bytes of `AES-ECB(Target_Key, '0101...01')`.

{Config.Colors.CYAN}5. Data Personalization (STORE DATA - 80 E2){Config.Colors.ENDC}
   Used for pushing Data Grouping Identifiers (DGIs) or generic TLVs into an SD/Application.
   - {Config.Colors.BOLD}APDU:{Config.Colors.ENDC} `80 E2 <P1> <P2> <Lc> <Data>`.
   - {Config.Colors.YELLOW}P1 (Control Reference):{Config.Colors.ENDC} `80` (Last block), `00` (More blocks to follow).
   - {Config.Colors.YELLOW}P2 (Block Number):{Config.Colors.ENDC} Increments `00, 01, 02...` per sequential STORE DATA command.
   - {Config.Colors.BOLD}DGI Parsing (Tag 90):{Config.Colors.ENDC} When personalizing SDs via P1=90, the data expects a Tag-Length-Value format. YggdraSIM utilizes this to update tags like `4F` (ISD AID) and `66` (Card Recognition Data).

{Config.Colors.CYAN}6. APDU Transmission via Logical Channels (MANAGE CHANNEL - 00 70){Config.Colors.ENDC}
   GlobalPlatform supports interacting with multiple applications simultaneously without interrupting SCP03 sessions.
   - {Config.Colors.BOLD}Open Channel:{Config.Colors.ENDC} `00 70 00 00 01`. Returns the newly assigned channel ID in the Response Data.
   - {Config.Colors.BOLD}Close Channel:{Config.Colors.ENDC} `00 70 80 <Channel_ID> 00`.
   - {Config.Colors.YELLOW}CLA Byte Modification:{Config.Colors.ENDC} Once opened, the channel ID is embedded in the Class Byte. 
     (e.g., `00` -> Basic Channel, `01` -> Channel 1, `02` -> Channel 2).
""")

    @classmethod
    def _print_etsi_guide(cls):
        spec_url = "https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/16.00.00_60/ts_102221v160000p.pdf"
        print(f"""
{Config.Colors.HEADER}=== ETSI / 3GPP File System & Access Control Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("ETSI TS 102 221 (UICC)", spec_url)}

{Config.Colors.CYAN}1. Hierarchy & Selection (FCP Templates){Config.Colors.ENDC}
   The UICC mimics a hierarchical file tree, rooted at the Master File (MF).
   - {Config.Colors.BOLD}MF (3F00):{Config.Colors.ENDC} Master File. Absolute root.
   - {Config.Colors.BOLD}DF / ADF:{Config.Colors.ENDC} Dedicated Files (Folders). Contains Sub-DFs or EFs. Example: ADF-USIM is usually 7FFF.
   - {Config.Colors.BOLD}EF:{Config.Colors.ENDC} Elementary Files (Data). Example: EF-IMSI is 6F07.

   {Config.Colors.BOLD}SELECT (00 A4 00 04):{Config.Colors.ENDC} Returns a File Control Parameter (FCP) template (Tag 62).
   - {Config.Colors.YELLOW}Tag 82 (File Descriptor):{Config.Colors.ENDC} Indicates if it's a DF (78), Transparent EF (41), or Linear Fixed EF (42).
   - {Config.Colors.YELLOW}Tag 83 (File Identifier):{Config.Colors.ENDC} The 2-byte Hex FID (e.g., 3F00).
   - {Config.Colors.YELLOW}Tag 8A (Life Cycle Status):{Config.Colors.ENDC} 01 (Creation), 03 (Initialization), 05 (Operational - Activated).
   - {Config.Colors.YELLOW}Tag 8C / 8B / AB (Security Attributes):{Config.Colors.ENDC} Defines the Access Rule Reference (ARR) for reading, updating, and administrative actions.

{Config.Colors.CYAN}2. Elementary File (EF) Structures & I/O{Config.Colors.ENDC}
   - {Config.Colors.BOLD}Transparent EF (Binary):{Config.Colors.ENDC} A flat byte-array with an absolute size (Tag 80).
     - {Config.Colors.YELLOW}READ BINARY:{Config.Colors.ENDC} `00 B0 <OffsetHigh> <OffsetLow> <Le>`.
     - {Config.Colors.YELLOW}UPDATE BINARY:{Config.Colors.ENDC} `00 D6 <OffsetHigh> <OffsetLow> <Lc> <Data>`.
   
   - {Config.Colors.BOLD}Linear Fixed / Cyclic EF (Record):{Config.Colors.ENDC} A list of fixed-length blocks.
     - {Config.Colors.YELLOW}Tag 82 Detail:{Config.Colors.ENDC} Includes the fixed record length (e.g., `82 05 42 21 00 10 05` -> 16 bytes per record, 5 records).
     - {Config.Colors.YELLOW}READ RECORD:{Config.Colors.ENDC} `00 B2 <Record_Num> <Mode> <Le>`. Mode 04 = Absolute record number. Mode 02 = Next record.
     - {Config.Colors.YELLOW}UPDATE RECORD:{Config.Colors.ENDC} `00 DC <Record_Num> <Mode> <Lc> <Data>`.
     - {Config.Colors.YELLOW}SEARCH RECORD:{Config.Colors.ENDC} `00 A2 <Record_Num> <Mode> <Lc> <Pattern>`. Mode 04 = Forward search from record 1.

{Config.Colors.CYAN}3. Administrative File Management (FS-ADMIN){Config.Colors.ENDC}
   Administrative actions require ADM (Administrative) privilege.
   - {Config.Colors.BOLD}CREATE FILE (00 E0):{Config.Colors.ENDC} `00 E0 00 00 <Lc> <FCP_Template>`. Creates a DF/EF under the currently selected DF.
   - {Config.Colors.BOLD}DELETE FILE (00 E4):{Config.Colors.ENDC} `00 E4 00 00 02 <FID>`. Deletes an immediate child of the current DF.
   - {Config.Colors.BOLD}RESIZE FILE (80 D4):{Config.Colors.ENDC} (Proprietary GP command) Resizes a Transparent/Linear Fixed EF.

{Config.Colors.CYAN}4. Operational File States{Config.Colors.ENDC}
   - {Config.Colors.BOLD}DEACTIVATE FILE (00 04):{Config.Colors.ENDC} `00 04 00 00 00`. Sets state to 'Deactivated' (04). Disables Read/Update unless the ARR specifically allows it.
   - {Config.Colors.BOLD}ACTIVATE FILE (00 44):{Config.Colors.ENDC} `00 44 00 00 00`. Restores state to 'Operational' (05).
""")

    @classmethod
    def _print_gsma_guide(cls):
        main_url = "https://www.gsma.com/solutions-and-impact/technologies/esim/esim-specification/"
        print(f"""
{Config.Colors.HEADER}=== GSMA eSIM & eUICC Provisioning Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("GSMA SGP.22 / SGP.02 / SGP.32", main_url)}

{Config.Colors.CYAN}1. Consumer eUICC Architecture (SGP.22){Config.Colors.ENDC}
   Profiles are downloaded and managed via the Local Profile Assistant (LPA) interacting with the eUICC.
   - {Config.Colors.BOLD}ISD-R (Issuer Security Domain Root):{Config.Colors.ENDC} The management application for the LPA. Selected via `A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 01 00`.
   - {Config.Colors.BOLD}ISD-P (Issuer Security Domain Profile):{Config.Colors.ENDC} An independent container hosting a single Profile (a virtual SIM card).
   - {Config.Colors.BOLD}ECASD (eUICC Controlling Authority SD):{Config.Colors.ENDC} Contains the cryptographic root of trust (eUICC certs/keys).

{Config.Colors.CYAN}2. ES10c Operations (Local Profile Management){Config.Colors.ENDC}
   Commands to the ISD-R use the STORE DATA (80 E2) APDU with specific BER-TLV formatting.
   - {Config.Colors.BOLD}GetProfilesInfo (Tag BF2D):{Config.Colors.ENDC} `80 E2 91 00 03 BF 2D 00`. Parses the Tag E3 registry to return ICCID, State (Enabled/Disabled), Profile Name, and Service Provider.
   - {Config.Colors.BOLD}EnableProfile (Tag BF31):{Config.Colors.ENDC} `80 E2 91 00 <Lc> BF 31 <Len> [A0 | A1 <Target>]`. Activates an ISD-P. Only one Profile can be Enabled at a time unless Multiple Enabled Profiles (MEP) is supported.
   - {Config.Colors.BOLD}DisableProfile (Tag BF32):{Config.Colors.ENDC} `80 E2 91 00 <Lc> BF 32 <Len> [A0 | A1 <Target>]`. Deactivates the Profile.
   - {Config.Colors.BOLD}DeleteProfile (Tag BF33):{Config.Colors.ENDC} `80 E2 91 00 <Lc> BF 33 <Len> [A0 | A1 <Target>]`. Permanently removes the ISD-P and its contents.
   
   {Config.Colors.YELLOW}Note:{Config.Colors.ENDC} State changes (Enable/Disable/Delete) always return a Proactive Command Pending (SW `91 xx`), instructing the baseband to perform a REFRESH (01) to re-read the active EF-DIR.

{Config.Colors.CYAN}3. eUICC Information (ES10b / ES10c){Config.Colors.ENDC}
   - {Config.Colors.BOLD}EuiccInfo1 (Tag BF20):{Config.Colors.ENDC} `80 E2 91 00 03 BF 20 00`. Returns OS version and SVN.
   - {Config.Colors.BOLD}EuiccInfo2 (Tag BF22):{Config.Colors.ENDC} `80 E2 91 00 03 BF 22 00`. Returns complex capability data (ExtExtCardResource, supported cryptography, SM-DP+ addresses).
   - {Config.Colors.BOLD}EID (Tag 5A):{Config.Colors.ENDC} The 32-digit serial number. Extracted directly from the ECASD via `00 CA 00 5A 00`.

{Config.Colors.CYAN}4. Legacy M2M (SGP.02){Config.Colors.ENDC}
   - Profiles are "pushed" by a backend SM-SR (Subscription Manager - Secure Routing) using remote SCP03/SCP80 scripts rather than an on-device LPA.
   - {Config.Colors.BOLD}Scanning (MANAGE-PROFILE):{Config.Colors.ENDC} Reads the Profile registry natively via ETSI logical channels to the ISD-R rather than using SGP.22 STORE DATA abstractions.
""")

    @classmethod
    def _print_install_guide(cls):
        print(f"""
{Config.Colors.HEADER}=== Install Wizard & APDU Builder Guide ==={Config.Colors.ENDC}

{Config.Colors.CYAN}1. Overview (GPCS 11.5){Config.Colors.ENDC}
   YggdraSIM provides interactive tools to dynamically build complex INSTALL APDUs 
   without manually calculating Hex TLVs or bitmasks.
   - {Config.Colors.BOLD}INSTALL [for load] (P1=02):{Config.Colors.ENDC} Creates a Load File container in the registry.
   - {Config.Colors.BOLD}LOAD (80 E8):{Config.Colors.ENDC} Transmits the actual Executable Load File (CAP/IJC) in blocks.
   - {Config.Colors.BOLD}INSTALL [for install] (P1=04 / 0C):{Config.Colors.ENDC} Instantiates an Applet from the loaded module, assigning it an AID and privileges.

{Config.Colors.CYAN}2. Interactive Builders{Config.Colors.ENDC}
   - {Config.Colors.GREEN}WIZARD (Option 1-7):{Config.Colors.ENDC} Craft an individual APDU.
     The INSTALL structure strictly follows this Length-Value sequence:
     `80 E6 <P1> 00 <Lc> <LoadFileAID_LV> <ModuleAID_LV> <AppletAID_LV> <Priv_LV> <Params_LV> <Token_LV>`
     - {Config.Colors.YELLOW}Zero-Length Fields:{Config.Colors.ENDC} A mandatory field left blank must still be encoded as `00`.
   - {Config.Colors.GREEN}WIZARD (Option 8):{Config.Colors.ENDC} Full CAP/IJC sequence builder.
     Automatically parses a binary file, extracts Package/Applet AIDs, and builds the full LOAD/INSTALL sequence. Supports OTA chunking for SMS-PP downloading (AES/3DES block limits).

{Config.Colors.CYAN}3. Applet Privileges (Hex Bitmask){Config.Colors.ENDC}
   The `Priv_LV` defines the application's rights within the OS:
   - {Config.Colors.YELLOW}0x80:{Config.Colors.ENDC} Security Domain (Capable of cryptographic key management).
   - {Config.Colors.YELLOW}0x40:{Config.Colors.ENDC} DAP Verification (Can verify Load File signatures).
   - {Config.Colors.YELLOW}0x20:{Config.Colors.ENDC} Delegated Management (Can install packages via pre-authorized tokens).
   - {Config.Colors.YELLOW}0x10:{Config.Colors.ENDC} Card Lock (Can lock the entire UICC).
   - {Config.Colors.YELLOW}0x08:{Config.Colors.ENDC} Card Terminate (Can kill the UICC permanently).
   - {Config.Colors.YELLOW}0x04:{Config.Colors.ENDC} Default Selected (Auto-selected when the interface opens).
   - {Config.Colors.YELLOW}0x02:{Config.Colors.ENDC} CVM Management (Can verify/change Global PINs).

{Config.Colors.CYAN}4. Install Parameters (TLV Builder){Config.Colors.ENDC}
   - {Config.Colors.BOLD}Tag C9 (Application Specific):{Config.Colors.ENDC} Passed directly to the applet's `install()` method.
   - {Config.Colors.BOLD}Tag EF (GP System Specific):{Config.Colors.ENDC} Defines Memory Quotas (Tag C6/C7) and Global Service Parameters (Tag C8).
   - {Config.Colors.BOLD}Tag EA (UICC System Specific):{Config.Colors.ENDC} Defined in ETSI TS 102 226. Configures Toolkit Parameters (Tag 80), Access Parameters (Tag 81), and Admin Access (Tag 82).
     - The Access Domain Parameter (ADP) defines access conditions (00=Full, 02=UICC, FF=None).
   - {Config.Colors.BOLD}Tag CA (SIM File Access):{Config.Colors.ENDC} Legacy 2G parameter. 
     {Config.Colors.WARNING}Note:{Config.Colors.ENDC} ETSI TS 102 226 strictly forbids Tags CA and EA from coexisting. The wizard automatically enforces this rule.
""")

    @classmethod
    def _print_security_guide(cls):
        print(f"""
{Config.Colors.HEADER}=== Cryptography & Security Guide ==={Config.Colors.ENDC}

{Config.Colors.CYAN}1. Secure Channel Protocol 03 (SCP03){Config.Colors.ENDC}
   SCP03 uses AES-128/192/256 to ensure Confidentiality (Encryption) and Integrity (MAC).
   - {Config.Colors.BOLD}Key Set:{Config.Colors.ENDC} Requires 3 static keys configured in `keys.ini`.
     - {Config.Colors.YELLOW}K-ENC (Data Encryption):{Config.Colors.ENDC} Derives the Session-ENC key for encrypting APDU payloads (C-DECRYPT/R-DECRYPT) using AES-CBC.
     - {Config.Colors.YELLOW}K-MAC (Data Authentication):{Config.Colors.ENDC} Derives the Session-MAC key for generating CMAC signatures (C-MAC/R-MAC) over the APDU header + payload.
     - {Config.Colors.YELLOW}K-DEK (Data Encryption Key):{Config.Colors.ENDC} Used directly (no derivation) to encrypt sensitive data (like new keys in PUT KEY) using AES-ECB.
   - {Config.Colors.BOLD}Session Derivation (NIST SP 800-108):{Config.Colors.ENDC} 
     `SessionKey = CMAC(StaticKey, DerivationData)`. 
     DerivationData uses the Host Challenge + Card Challenge returned from `INITIALIZE UPDATE`.

{Config.Colors.CYAN}2. Key Rotation & Wrapping (PUT KEY){Config.Colors.ENDC}
   - Updating keys (`PUT-KEY`) requires sending the new static keys to the ISD over SCP03.
   - Because raw keys are sensitive, they are padded to 16/32 bytes and encrypted individually using the K-DEK key before transmission.
   - A KVN (Key Version Number) identifies the active key set. Rotating keys creates a new KVN.

{Config.Colors.CYAN}3. PIN & ADM Formatting{Config.Colors.ENDC}
   - {Config.Colors.BOLD}ISO 7816-4 PIN Pad:{Config.Colors.ENDC} PINs must be 8 bytes long. Shorter PINs are padded with `FF`.
     Example: PIN `1234` (ASCII `31 32 33 34`) is transmitted as `31 32 33 34 FF FF FF FF`.
   - {Config.Colors.BOLD}Verification (00 20):{Config.Colors.ENDC} `00 20 00 <Ref> 08 <Padded_PIN>`.
   - {Config.Colors.BOLD}Change PIN (00 24):{Config.Colors.ENDC} `00 24 00 <Ref> 10 <Padded_Old> <Padded_New>`.
   - {Config.Colors.YELLOW}SW 63 CX:{Config.Colors.ENDC} Verification failed, `X` attempts remaining. If X=0, state moves to `69 83` (Blocked).

{Config.Colors.CYAN}4. Network Authentication Algorithms (RUN-AUTH){Config.Colors.ENDC}
   Simulates Baseband (Modem) authentication procedures via `00 88` (INTERNAL AUTHENTICATE).
   - {Config.Colors.BOLD}3G/4G/5G Context (USIM/ISIM):{Config.Colors.ENDC} Uses MILENAGE or TUAK.
     - Inputs: `RAND` (16 bytes) and `AUTN` (16 bytes).
     - The UICC computes the SQN (Sequence Number) and MAC to verify the network (AUTN).
     - If successful, it calculates and returns `RES`, `CK` (Cipher Key), and `IK` (Integrity Key).
   - {Config.Colors.BOLD}2G Context (GSM):{Config.Colors.ENDC} Uses COMP128.
     - Inputs: `RAND` (16 bytes) only. No network verification (AUTN).
     - Returns `SRES` and `Kc`.
""")

    @classmethod
    def _print_config_guide(cls):
        print(f"""
{Config.Colors.HEADER}=== Configuration Files & Persistence Guide ==={Config.Colors.ENDC}

{Config.Colors.CYAN}1. Standalone Executable vs Source Code{Config.Colors.ENDC}
   YggdraSIM handles configuration files differently depending on how it is launched:
   - {Config.Colors.BOLD}Source Code (Python):{Config.Colors.ENDC} Config files are read from and saved to their respective 
     module directories (e.g., `SCP03/keys.ini`, `SCP03/aid.txt`, `SCP80/ota_config.ini`).
   - {Config.Colors.BOLD}Standalone Executable (.exe / Linux binary):{Config.Colors.ENDC} The executable extracts and reads 
     configuration files from the {Config.Colors.YELLOW}same directory as the executable{Config.Colors.ENDC}. This ensures 
     that your changes are persistent and not lost when the temporary bundle closes.

{Config.Colors.CYAN}2. Modifying Configuration Files{Config.Colors.ENDC}
   If you run the executable for the first time, default versions of the required files 
   will automatically be copied to your current directory. You can open them in any text editor.

   - {Config.Colors.BOLD}keys.ini:{Config.Colors.ENDC} Contains static GlobalPlatform keys (K-ENC, K-MAC, K-DEK). 
     You can manually edit the hex strings, or use the `WIZARD` > `UPDATE KEYS` command in 
     the shell to securely rotate and auto-save the new keys here.
     {Config.Colors.YELLOW}Syntax Example:{Config.Colors.ENDC}
       [KEYS]
       kenc = 404142434445464748494A4B4C4D4E4F
       kmac = 404142434445464748494A4B4C4D4E4F
       dek  = 404142434445464748494A4B4C4D4E4F
       kvn  = 20
       
   - {Config.Colors.BOLD}aid.txt:{Config.Colors.ENDC} A registry mapping Applet IDs (AIDs) to human-readable names. 
     Add your custom AIDs to quickly select them in the shell (e.g., `SELECT MyCustomApplet`).
     {Config.Colors.YELLOW}Syntax Example:{Config.Colors.ENDC}
       ISD-R: A0000005591010FFFFFFFF8900000100
       MyApp: 112233445566
       
   - {Config.Colors.BOLD}fids.txt:{Config.Colors.ENDC} Maps File IDs (FIDs) to their telecom file paths (e.g., `USIM/IMSI`).
     The internal file system navigator uses this to build the `TREE` map.
     {Config.Colors.YELLOW}Syntax Example:{Config.Colors.ENDC}
       USIM: 7FFF
       USIM/IMSI: 6F07
       
   - {Config.Colors.BOLD}ota_config.ini:{Config.Colors.ENDC} Used exclusively by the SCP80 OTA module. Configures 
     Transport settings (SMS/HTTP), TAR, SPI, KIC, and KID for remote management.
     {Config.Colors.YELLOW}Syntax Example:{Config.Colors.ENDC}
       [ota]
       tar = B00000
       spi = 1621
       key_enc = 1111111111111111
       key_mac = 1111111111111111

{Config.Colors.CYAN}3. SCP11 Certificates (.pem / .der){Config.Colors.ENDC}
   The Local SM-DP+ Simulation (SCP11) relies on cryptographic certificates:
   - {Config.Colors.BOLD}CERT.DPauth.ECDSA.der / SK.DPauth.ECDSA.pem{Config.Colors.ENDC}
   - {Config.Colors.BOLD}CERT.DPpb.ECDSA.der / SK.DPpb.ECDSA.pem{Config.Colors.ENDC}
   These are also extracted next to the executable. You can replace them with your own 
   test certificates to simulate custom provisioning scenarios.
""")

    @classmethod
    def _print_ota_guide(cls):
        print(f"""
{Config.Colors.HEADER}=== SCP80 OTA (Remote Management) Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} ETSI TS 102 225 / 3GPP TS 31.115

{Config.Colors.CYAN}1. OTA Architecture Overview{Config.Colors.ENDC}
   Over-The-Air (OTA) allows remote servers (OTA servers) to securely push commands to a SIM card.
   Commands are structured as Secured Packets (SMS-PP, HTTP, or CAT_TP), utilizing the Secure Channel 
   Protocol 80 (SCP80).
   - {Config.Colors.BOLD}SPI (Security Parameter Indicator):{Config.Colors.ENDC} Determines if payloads are ciphered (encrypted) and/or 
     appended with a CC (Cryptographic Checksum/MAC).
   - {Config.Colors.BOLD}KIC / KID:{Config.Colors.ENDC} Key Identifier parameters. They point to specific OTA keys located inside the 
     card's OTA Security Domain (e.g., TAR `000000` or `B00010`).
   - {Config.Colors.BOLD}TAR (Toolkit Application Reference):{Config.Colors.ENDC} 3-byte hex routing ID. Defines which application 
     or Remote File Manager (RFM) processes the payload.

{Config.Colors.CYAN}2. Supported OTA Operations in YggdraSIM{Config.Colors.ENDC}
   - {Config.Colors.BOLD}READ/UPDATE:{Config.Colors.ENDC} Modifies files remotely. Wraps `00 B0` or `00 D6` inside the secured command packet.
   - {Config.Colors.BOLD}INSTALL / DELETE:{Config.Colors.ENDC} Manages Applets and Packages via the Remote Applet Manager (RAM).
   - {Config.Colors.BOLD}STORE DATA:{Config.Colors.ENDC} Push large or multi-block payloads over SMS (via chunking) or HTTP.

{Config.Colors.CYAN}3. Configuration & Key Management{Config.Colors.ENDC}
   OTA Security requires KIC (Encryption) and KID (MAC/CC) keys. 
   - Ensure the OTA keys are properly configured in `ota_config.ini` in the `SCP80` module folder.
   - The ciphering algorithm (DES, 3DES, AES) and CC algorithm must match the profile loaded on the SIM.

{Config.Colors.CYAN}4. APDU Packaging (Command Packet){Config.Colors.ENDC}
   The OTA module takes standard APDUs (e.g., `00 A4...`) and packages them:
   1. Appends Command Headers (CHL, SPI, KIC, KID, TAR, CNTR, PCNTR).
   2. Computes the CC over the header + payload using the KID.
   3. Encrypts the payload + CC (if required by SPI) using the KIC.
   4. Sends the final block wrapped in an Envelope command (`80 C2 00 00 <Len> <Secured_Packet>`).
""")