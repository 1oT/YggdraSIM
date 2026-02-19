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
                print(f"  {Config.Colors.CYAN}1.{Config.Colors.ENDC} GlobalPlatform (GP)")
                print(f"  {Config.Colors.CYAN}2.{Config.Colors.ENDC} ETSI / 3GPP File System (ETSI)")
                print(f"  {Config.Colors.CYAN}3.{Config.Colors.ENDC} GSMA eSIM Architecture (GSMA)")
                print(f"  {Config.Colors.CYAN}4.{Config.Colors.ENDC} Install Wizard & APDU Builder (INSTALL)")
                print(f"  {Config.Colors.CYAN}q.{Config.Colors.ENDC} Return to Shell")
                
                choice = input(f"\nChoice [1-4, q]: ").strip().lower()
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
{Config.Colors.HEADER}=== GlobalPlatform Usage Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("GPC Card Specification v2.3.1", spec_url)}

{Config.Colors.CYAN}1. Secure Channel Protocol (SCP03){Config.Colors.ENDC}
   YggdraSIM utilizes SCP03 (AES-based) for establishing a secure tunnel.
   - {Config.Colors.BOLD}Handshake:{Config.Colors.ENDC} Initiated via {Config.Colors.GREEN}AUTH-SD{Config.Colors.ENDC}. It sends INITIALIZE UPDATE (80 50) and EXTERNAL AUTHENTICATE (84 82).
   - {Config.Colors.BOLD}Keys:{Config.Colors.ENDC} Pulled from 'keys.ini'. 
     - K-ENC: Derives Session-ENC (Payload Encryption).
     - K-MAC: Derives Session-MAC (CMAC validation).
     - K-DEK: Used exclusively for encrypting static keys during PUT KEY.

{Config.Colors.CYAN}2. Registry & Content{Config.Colors.ENDC}
   The card maintains an internal registry of its objects.
   - {Config.Colors.GREEN}APPS / PKGS / SD{Config.Colors.ENDC}: Wrappers for GET STATUS (80 F2). Returns TLV blocks describing the lifecycle state (e.g. LOADED, INSTALLED, LOCKED) and privileges.
   - {Config.Colors.GREEN}DELETE-CONS <AID>{Config.Colors.ENDC}: Sends DELETE (80 E4). If deleting a Package, all instantiated applets must be deleted first unless a recursive flag (P2=80) is used.

{Config.Colors.CYAN}3. Applet Installation (Lifecycle - GPCS 11.5){Config.Colors.ENDC}
   Installation requires precise APDU chaining, handled natively by {Config.Colors.GREEN}INSTALL-INSTALL{Config.Colors.ENDC}.
   It accepts both standard ZIP-compressed `.cap` files and pre-linked `.ijc` binaries.
   
   {Config.Colors.BOLD}Lifecycle Commands:{Config.Colors.ENDC}
   - {Config.Colors.GREEN}INSTALL-INSTALL <cap/ijc>{Config.Colors.ENDC}: Executes the full [for load] and [for install] sequence.
   - {Config.Colors.GREEN}INSTALL-LOAD <cap/ijc>{Config.Colors.ENDC}: Loads the package into memory without instantiating it.
   - {Config.Colors.GREEN}INSTALL-APP <Pkg> <App>{Config.Colors.ENDC}: Instantiates an applet from an already loaded package.
   - {Config.Colors.GREEN}INSTALL-REGISTRY <AID>{Config.Colors.ENDC}: Updates the registry parameters for a specific AID.
   - {Config.Colors.GREEN}INSTALL-PERSO <AID>{Config.Colors.ENDC}: Transitions an application to the personalization state.

   {Config.Colors.BOLD}Interactive Tooling:{Config.Colors.ENDC}
   - {Config.Colors.GREEN}INSTALL-WIZARD-SD{Config.Colors.ENDC}: Interactive CLI for crafting all 7 GPCS 11.5 INSTALL variants.
   - {Config.Colors.GREEN}INSTALL-WIZARD-APDU <cap/ijc>{Config.Colors.ENDC}: Parses the binary offline and builds the 80E6 / 80E8 chain for manual debugging.

{Config.Colors.CYAN}4. Data & Keys (GPCS 11.11 & 11.8){Config.Colors.ENDC}
   - {Config.Colors.GREEN}STORE-DATA <Hex>{Config.Colors.ENDC}: The 80 E2 command. Required for pushing personalization data (like DGI structures). YggdraSIM auto-chunks data > 240 bytes.
   - {Config.Colors.GREEN}PUT-KEY{Config.Colors.ENDC}: Safely rolls the SD keys (80 D8), enforcing DEK wrapping.
""")

    @classmethod
    def _print_etsi_guide(cls):
        spec_url = "https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/16.00.00_60/ts_102221v160000p.pdf"
        print(f"""
{Config.Colors.HEADER}=== ETSI / 3GPP File System Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("ETSI TS 102 221 (UICC)", spec_url)}

{Config.Colors.CYAN}1. Hierarchy & Selection{Config.Colors.ENDC}
   The UICC mimics a traditional file tree.
   - {Config.Colors.BOLD}MF (3F00){Config.Colors.ENDC}: Master File. The absolute root.
   - {Config.Colors.BOLD}DF / ADF{Config.Colors.ENDC}: Dedicated Files (Folders). Example: ADF-USIM is usually 7FFF.
   - {Config.Colors.BOLD}EF{Config.Colors.ENDC}: Elementary Files (Data). Example: EF-IMSI is 6F07.

   {Config.Colors.GREEN}SELECT <Path/FID>{Config.Colors.ENDC} translates to APDU `00 A4 00 04 02 <FID>`. 
   Selecting a file returns an FCP (File Control Parameter) template (Tag 62), which YggdraSIM parses to show access conditions and structure.

{Config.Colors.CYAN}2. File Structures & I/O{Config.Colors.ENDC}
   - {Config.Colors.BOLD}Transparent EF (Binary):{Config.Colors.ENDC} A flat array of bytes.
     - {Config.Colors.GREEN}READ [Path]{Config.Colors.ENDC} -> `00 B0 00 00 <Len>`
     - {Config.Colors.GREEN}UPDATE BINARY <Hex>{Config.Colors.ENDC} -> `00 D6 00 00 <Len> <Hex>`
   
   - {Config.Colors.BOLD}Linear Fixed EF (Record):{Config.Colors.ENDC} A list of fixed-length blocks (like a CSV).
     - {Config.Colors.GREEN}RECORD <N | ALL>{Config.Colors.ENDC} -> `00 B2 <N> 04 <Len>` (04 = Absolute Mode).
     - {Config.Colors.GREEN}UPDATE RECORD <N> <Hex>{Config.Colors.ENDC} -> `00 DC <N> 04 <Len> <Hex>`

{Config.Colors.CYAN}3. Security (Access Conditions){Config.Colors.ENDC}
   Operations are gated by Security Conditions evaluated against PIN or ADM states.
   - {Config.Colors.GREEN}VERIFY-ADM [Key]{Config.Colors.ENDC}: Validates the Administrative key (usually mapped to ID 0A) configured in keys.ini.
   - {Config.Colors.GREEN}VERIFY-PIN <ID> <PIN>{Config.Colors.ENDC}: Validates the secret against `00 20 00 <ID> <Len> <PIN>`. ID 01 is Global PIN1.
   - {Config.Colors.GREEN}UNBLOCK <ID> <PUK> <New>{Config.Colors.ENDC}: `00 2C 00 <ID>`. Replaces the blocked PIN.

{Config.Colors.CYAN}4. Network Authentication{Config.Colors.ENDC}
   - {Config.Colors.GREEN}AUTH-USIM <RAND> <AUTN>{Config.Colors.ENDC}: Executes APDU `00 88 00 81` (3G context).
   - Returns RES, CK, IK if successful, or AUTS in the event of a sequence number synchronization failure (SQN desync).
""")

    @classmethod
    def _print_gsma_guide(cls):
        main_url = "https://www.gsma.com/solutions-and-impact/technologies/esim/esim-specification/"
        print(f"""
{Config.Colors.HEADER}=== GSMA eSIM Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("GSMA eSIM Specs", main_url)}

{Config.Colors.CYAN}1. Consumer eSIM (SGP.22){Config.Colors.ENDC}
   Designed for User-Equipment (Phones, Tablets) driven by an LPA (Local Profile Assistant).
   - {Config.Colors.BOLD}Architecture:{Config.Colors.ENDC} Managed via the ISD-R (Issuer Security Domain Root).
   - {Config.Colors.GREEN}LIST-CONS{Config.Colors.ENDC}: Triggers `ES10c.GetProfilesInfo`. Reads the profile registry.
   - {Config.Colors.GREEN}ENABLE/DISABLE-CONS <AID>{Config.Colors.ENDC}: Alters the state of an ISD-P (Profile). State changes trigger a REFRESH command to the baseband.
   - {Config.Colors.GREEN}GET-CONS{Config.Colors.ENDC}: Dumps eUICC properties (EuiccInfo1 & Info2), OS version, and SM-DP+ configurations.

{Config.Colors.CYAN}2. IoT eSIM (SGP.32){Config.Colors.ENDC}
   Designed for constrained devices, leveraging an eIM (eSIM IoT Remote Manager) to act on behalf of the device.
   - {Config.Colors.BOLD}Architecture:{Config.Colors.ENDC} Managed via the IoT Profile Assistant (IPA).
   - {Config.Colors.GREEN}GET-IOT{Config.Colors.ENDC} & {Config.Colors.GREEN}LIST-IOT{Config.Colors.ENDC}: Functions similar to SGP.22 but scoped to the constraints and tag definitions of SGP.32.

{Config.Colors.CYAN}3. M2M eSIM (SGP.02){Config.Colors.ENDC}
   The legacy push-model where profiles are deployed by backend servers (SM-SR).
   - {Config.Colors.BOLD}Architecture:{Config.Colors.ENDC} ISD-R coordinates with the SM-SR via SCP03/SCP80/SCP81.
   - {Config.Colors.GREEN}GET-ECASD{Config.Colors.ENDC}: Selects the ECASD (A0000005591010FFFFFFFF8900000200) to retrieve immutable cryptographic properties:
     - {Config.Colors.YELLOW}EID (Tag 5A){Config.Colors.ENDC}: The 32-digit serial number of the chip.
     - {Config.Colors.YELLOW}Certificates (Tag E0 / 7F21){Config.Colors.ENDC}: Extract public keys for DP/SR authentication.
""")

    @classmethod
    def _print_install_guide(cls):
        print(f"""
{Config.Colors.HEADER}=== Install Wizard & APDU Builder Guide ==={Config.Colors.ENDC}

{Config.Colors.CYAN}1. Overview{Config.Colors.ENDC}
   YggdraSIM provides interactive tools to dynamically build complex GPCS 11.5 INSTALL APDUs 
   without manually calculating Hex TLVs or bitmasks. These are dry-run tools and will not 
   transmit data to the card automatically.

{Config.Colors.CYAN}2. INSTALL-WIZARD-SD (Command Builder){Config.Colors.ENDC}
   Run {Config.Colors.GREEN}INSTALL-WIZARD-SD{Config.Colors.ENDC} to craft a specific INSTALL command variant.
   - Supports all 7 variants (e.g., [for load], [for install], [for extradition]).
   - Automatically prompts for the required AIDs, Privileges, and Parameters based on your choice.
   - Enforces correct Length-Value (LV) formatting and mandatory zero-length boundaries.

{Config.Colors.CYAN}3. INSTALL-WIZARD-APDU <cap/ijc> (Sequence Builder){Config.Colors.ENDC}
   Run {Config.Colors.GREEN}INSTALL-WIZARD-APDU <filename>{Config.Colors.ENDC} to generate the full installation sequence:
   1. Parses the CAP/IJC file to extract the Package and Applet AIDs.
   2. Generates the `INSTALL [for load]` APDU.
   3. Chunks the binary into `LOAD` APDUs (Supports chunking for OTA 3DES/AES limits).
   4. Generates the `INSTALL [for install]` APDU.

{Config.Colors.CYAN}4. Install Parameters (TLV Builder){Config.Colors.ENDC}
   Both tools allow you to launch the Interactive TLV Builder for Install Parameters:
   - {Config.Colors.BOLD}Tag C9 (Application Specific):{Config.Colors.ENDC} Passed directly to the applet's `install()` method.
   - {Config.Colors.BOLD}Tag EF (GP System Specific):{Config.Colors.ENDC} Defines Memory Quotas (Tag C6/C7) and Global Service Parameters (Tag C8).
   - {Config.Colors.BOLD}Tag EA (UICC System Specific):{Config.Colors.ENDC} Defined in ETSI TS 102 226. Configures Toolkit Parameters (Tag 80), Access Parameters (Tag 81), and Admin Access (Tag 82).
     - The wizard includes the Access Domain Parameter (ADP) constructor (00 = Full, 02 = UICC, FF = None).
   - {Config.Colors.BOLD}Tag CA (SIM File Access):{Config.Colors.ENDC} Legacy 2G parameter. 
     {Config.Colors.WARNING}Note:{Config.Colors.ENDC} ETSI TS 102 226 strictly forbids Tags CA and EA from coexisting. The wizard automatically enforces this rule.
""")