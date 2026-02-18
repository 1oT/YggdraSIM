import os
from SCP03.config import Config

class ShellGuides:
    """
    Manages detailed interactive documentation and usage guides.
    """

    @staticmethod
    def _link(text: str, url: str) -> str:
        """Generates an OSC 8 clickable hyperlink."""
        if not url: 
            return text
        return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"

    @classmethod
    def print_guide(cls, topic: str):
        os.system('cls' if os.name == 'nt' else 'clear')
        topic = topic.upper()
        if topic == 'GP':
            cls._print_gp_guide()
        elif topic == 'ETSI':
            cls._print_etsi_guide()
        elif topic == 'GSMA':
            cls._print_gsma_guide()
        else:
            print(f"{Config.Colors.FAIL}[!] Unknown guide topic: {topic}{Config.Colors.ENDC}")

    @classmethod
    def _print_gp_guide(cls):
        spec_url = "https://globalplatform.org/wp-content/uploads/2025/05/GPC_CardSpecification_v2.3.1.49_PublicRvw.pdf"
        print(f"""
{Config.Colors.HEADER}=== GlobalPlatform Usage Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("GPC Card Specification v2.3.1", spec_url)}

{Config.Colors.CYAN}1. Secure Channel Protocol (SCP03){Config.Colors.ENDC}
   YggdraSIM uses SCP03 (AES) for mutual authentication and session encryption.
   - {Config.Colors.GREEN}AUTH-SD{Config.Colors.ENDC}: Initiates the handshake (INITIALIZE UPDATE + EXTERNAL AUTHENTICATE).
     It uses the static keys defined in {Config.Colors.YELLOW}keys.ini{Config.Colors.ENDC} (K-ENC, K-MAC, DEK).
     Successful auth promotes the session security level to {Config.Colors.BOLD}0x33{Config.Colors.ENDC} (C-ENC + C-MAC + R-MAC).

{Config.Colors.CYAN}2. Content Management (Registry){Config.Colors.ENDC}
   - {Config.Colors.GREEN}APPS{Config.Colors.ENDC} / {Config.Colors.GREEN}PKGS{Config.Colors.ENDC} / {Config.Colors.GREEN}SD{Config.Colors.ENDC}:
     These commands run {Config.Colors.YELLOW}GET STATUS (80 F2){Config.Colors.ENDC} to list Executable Load Files (Packages),
     Applications, or Security Domains present in the registry.
   
   - {Config.Colors.GREEN}DELETE-CONS <AID>{Config.Colors.ENDC}:
     Sends {Config.Colors.YELLOW}DELETE (80 E4){Config.Colors.ENDC}. If the object is a Package, all associated Applets are also removed.

{Config.Colors.CYAN}3. Applet Installation (Lifecycle){Config.Colors.ENDC}
   Installation is a multi-step process handled automatically by {Config.Colors.GREEN}INSTALL-INSTALL{Config.Colors.ENDC}:
   1. {Config.Colors.BOLD}INSTALL [for load]{Config.Colors.ENDC}: Prepares the SD to receive the CAP file.
   2. {Config.Colors.BOLD}LOAD{Config.Colors.ENDC}: Transmits the CAP file bytecode in blocks (80 E8).
   3. {Config.Colors.BOLD}INSTALL [for install]{Config.Colors.ENDC}: Instantiates an applet from the loaded package.
   
   {Config.Colors.BOLD}Arguments:{Config.Colors.ENDC}
   - {Config.Colors.YELLOW}Privileges{Config.Colors.ENDC}: Bitmask defining applet rights (e.g., 0x04 = Default Selected).
   - {Config.Colors.YELLOW}Install Params (C9){Config.Colors.ENDC}: Application Specific Parameters passed to the Applet's `install()` method.

{Config.Colors.CYAN}4. Key Rotation{Config.Colors.ENDC}
   - {Config.Colors.GREEN}PUT-KEY <KVN> <ID> <K1> <K2> <K3>{Config.Colors.ENDC}:
     Replaces the keys in the connected Security Domain.
     New keys are encrypted using the current session's {Config.Colors.YELLOW}DEK{Config.Colors.ENDC} before transmission.
     *Warning*: Incorrect usage will lock you out of the card.

{Config.Colors.CYAN}5. Raw Data{Config.Colors.ENDC}
   - {Config.Colors.GREEN}STORE-DATA <Hex>{Config.Colors.ENDC}: Sends raw TLV objects to the ISD (80 E2).
""")

    @classmethod
    def _print_etsi_guide(cls):
        spec_url = "https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/16.00.00_60/ts_102221v160000p.pdf"
        print(f"""
{Config.Colors.HEADER}=== ETSI / 3GPP File System Guide ==={Config.Colors.ENDC}
{Config.Colors.BOLD}Standard:{Config.Colors.ENDC} {cls._link("ETSI TS 102 221 (UICC)", spec_url)}

{Config.Colors.CYAN}1. File System Hierarchy{Config.Colors.ENDC}
   The UICC file system is tree-based:
   - {Config.Colors.BOLD}MF (3F00){Config.Colors.ENDC}: Master File (Root).
   - {Config.Colors.BOLD}DF{Config.Colors.ENDC}: Dedicated File (Directory), e.g., ADF-USIM (7FFF).
   - {Config.Colors.BOLD}EF{Config.Colors.ENDC}: Elementary File (Data), containing the actual bytes.

{Config.Colors.CYAN}2. Addressing & Navigation{Config.Colors.ENDC}
   - {Config.Colors.GREEN}SELECT <Path>{Config.Colors.ENDC}:
     Supports standard IDs (e.g., '3F00') or named paths (e.g., 'USIM/IMSI').
     The tool parses the returned {Config.Colors.YELLOW}FCP (File Control Parameters){Config.Colors.ENDC} to show
     file size, type, and security attributes (PIN requirements).

{Config.Colors.CYAN}3. EF Types & I/O{Config.Colors.ENDC}
   - {Config.Colors.BOLD}Transparent EF:{Config.Colors.ENDC} A flat sequence of bytes.
     - {Config.Colors.GREEN}READ{Config.Colors.ENDC}: Uses `READ BINARY (00 B0)`.
     - {Config.Colors.GREEN}UPDATE BINARY{Config.Colors.ENDC}: Overwrites data.
   
   - {Config.Colors.BOLD}Linear Fixed EF:{Config.Colors.ENDC} A list of fixed-length records.
     - {Config.Colors.GREEN}RECORD <N>{Config.Colors.ENDC}: Uses `READ RECORD (00 B2)`.
     - {Config.Colors.GREEN}UPDATE RECORD <N>{Config.Colors.ENDC}: Overwrites specific record.

{Config.Colors.CYAN}4. Security (PINs){Config.Colors.ENDC}
   - {Config.Colors.GREEN}VERIFY{Config.Colors.ENDC}: Checks PIN1 (ID 01) or PIN2 (ID 81).
   - {Config.Colors.GREEN}UNBLOCK{Config.Colors.ENDC}: Uses PUK to reset the Retry Counter and set a new PIN.
   - Status words like {Config.Colors.FAIL}63C3{Config.Colors.ENDC} indicate "Verification Failed, 3 retries left".
""")

    @classmethod
    def _print_gsma_guide(cls):
        sgp22_url = "https://www.gsma.com/esim/wp-content/uploads/2020/06/SGP.22-v2.2.2.pdf"
        sgp32_url = "https://www.gsma.com/solutions-and-impact/technologies/esim/gsma_resources/sgp-32-v1-2/"
        sgp02_url = "https://www.gsma.com/solutions-and-impact/technologies/esim/gsma_resources/sgp-02-v4-3/"
        
        print(f"""
{Config.Colors.HEADER}=== GSMA eSIM Guide ==={Config.Colors.ENDC}

{Config.Colors.CYAN}1. Consumer eSIM (SGP.22){Config.Colors.ENDC}
   {cls._link("Standard: SGP.22 Spec", sgp22_url)}
   The {Config.Colors.BOLD}ISD-R{Config.Colors.ENDC} acts as the root for Profile Management.
   - {Config.Colors.GREEN}LIST-CONS{Config.Colors.ENDC}: Calls `ES10c.GetProfilesInfo` to list installed profiles.
   - {Config.Colors.GREEN}ENABLE/DISABLE-CONS{Config.Colors.ENDC}: Toggles profile state. Enabling a profile triggers a
     {Config.Colors.YELLOW}REFRESH{Config.Colors.ENDC} proactive command, forcing the OS to re-read the USIM.
   - {Config.Colors.GREEN}GET-CONS{Config.Colors.ENDC}: A full diagnostic scan of the eUICC (EuiccInfo1, Info2, ConfiguredData).

{Config.Colors.CYAN}2. IoT eSIM (SGP.32){Config.Colors.ENDC}
   {cls._link("Standard: SGP.32 Spec", sgp32_url)}
   Designed for constrained devices (eIM).
   - {Config.Colors.GREEN}GET-IOT{Config.Colors.ENDC}: Similar to SGP.22 scan but interprets tags specific to IoT eUICC configuration.
   - {Config.Colors.GREEN}LIST-IOT{Config.Colors.ENDC}: Lists profiles managed by the IPA (IoT Profile Assistant).

{Config.Colors.CYAN}3. M2M (SGP.02){Config.Colors.ENDC}
   {cls._link("Standard: SGP.02 Spec", sgp02_url)}
   The legacy M2M standard managed by SM-SR/SM-DP.
   - {Config.Colors.GREEN}GET-ECASD{Config.Colors.ENDC}: Selects the Security Domain of the ECASD to read:
     - {Config.Colors.BOLD}EID (Tag 5A){Config.Colors.ENDC}: The unique eUICC Identifier.
     - {Config.Colors.BOLD}CERT.ECASD{Config.Colors.ENDC}: The root certificate for the eUICC.
""")