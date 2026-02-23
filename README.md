```
 __   __               _               ____ ___ __  __ 
 \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |
  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |
   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |
   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|
      |___/  |___/
      An eSIM Management Suite
```

**YggdraSIM** is a comprehensive, Python-based toolkit for interacting with, analyzing, and managing SIM, USIM, and eUICC (eSIM) cards. It provides a robust interactive shell for GlobalPlatform management, GSMA eSIM profile handling (Consumer, IoT, and M2M), and low-level file system operations via PC/SC smart card readers.

## 🚀 Key Features

### 🌐 GlobalPlatform & Lifecycle
* **Secure Channels:** Full support for **SCP03** (GlobalPlatform) authentication, session management and and **SCP80** (OTA).
* **Registry Management:** List installed Applets, Packages, and Security Domains (`APPS`, `PKGS`, `SD`).
* **Lifecycle Management:** Install (`LOAD`, `INSTALL`), Lock, Unlock, and Delete applications.
* **Key Management:** Retrieve CPLC data and Key Information Templates.

### 📱 GSMA eSIM (SGP.22 / SGP.32 / SGP.02)
* **Profile Management:** List, Enable, Disable, and Delete eSIM profiles via ISD-R.
* **SGP.22 (Consumer):** Full support for retrieving and decoding `EuiccInfo1`, `EuiccInfo2`, and `EuiccConfiguredData`.
* **SGP.32 (IoT):** Dedicated commands for the new IoT eSIM standard (`LIST-IOT`, `GET-IOT`).
* **SGP.02 (M2M):** Support for ECASD data retrieval and M2M specific tags.
* **Crisp Decoding:** Automatic, context-aware decoding of complex TLV structures (e.g., Extended Card Resources, Capabilities).

### 📂 ETSI / 3GPP File System
* **Navigation:** Browse the file system (`SELECT`) by Path (e.g., `USIM/IMSI`) or FID.
* **I/O Operations:** `READ` and `UPDATE` Transparent (Binary) and Linear Fixed (Record) EFs.
* **FCP Analysis:** Detailed decoding of File Control Parameters (File Type, Size, Access Conditions).
* **Tree Scan:** Recursively scan and map the file system.

### 🔐 Security & Auth
* **PIN Management:** Verify, Change, Disable, Enable, and Unblock PINs.
* **Network Auth:** Execute Authentication algorithms (Milenage) for GSM (2G), USIM (3G/4G), and ISIM contexts.

---

## 🛠️ Installation

1.  **Prerequisites:**
    * Python 3.8+
    * A PC/SC compatible Smart Card Reader.

2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: Primarily requires `pyscard`, `cryptography`, `click`, `requests`)*

## ⚡ Usage

Run the interactive shell:

```bash
python SCP03/main.py
```

### 🎮 The Interactive Shell
YggdraSIM features a persistent shell with **tab completion** and **command history**.

**Example Session:**
```text
[APDU] > AUTH-SD              # Authenticate via SCP03
[A0...00] > APPS              # List installed applets
[A0...00] > LIST              # List eSIM profiles (SGP.22)
[A0...00] > GET-IOT           # Deep scan of IoT eUICC settings
[A0...00] > SELECT USIM/IMSI  # Select IMSI file
[A0...00] > READ              # Read binary content
```

### 📜 Scripting & Reporting
You can automate tasks using script files and export results to YAML.

```bash
[APDU] > RUN scripts/setup_card.txt output_report.yaml
```
* **Input:** A text file with one command per line.
* **Output:** A structured YAML file containing the command execution log and decoded outputs.

**Non-interactive CLI (one-shot commands):**
```bash
python main/main.py --scp03 --cmd "AUTH-SD; LIST; GET-IOT" --out report.yaml
python SCP03/main.py --cmd "AUTH-SD; APPS" --out report.yaml
```

**Single-command eUICC report:**
```bash
[APDU] > EXPORT-EUICC euicc_report.yaml
```
Writes profiles, EuiccInfo1/2, EuiccConfiguredData, CPLC, and key info to a YAML file.

---

## ⚙️ Configuration

### Standalone Executable vs Source Source Code
When running YggdraSIM from the source code, configuration files are read from and saved to their respective module directories (e.g. `SCP03/keys.ini`, `SCP03/aid.txt`, `SCP80/ota_config.ini`).

When using the compiled single-file executable (built with PyInstaller), the configuration files are located in the **same directory as the executable**. If you are running the executable for the first time, it will automatically extract the default configuration files (such as `aid.txt`, `fids.txt`, and certificates) into the directory where the executable is located, allowing you to modify them easily.

### Keys (`keys.ini`)
To perform authenticated GlobalPlatform operations (`AUTH-SD`), you must define your keys in `keys.ini` (located in `SCP03/keys.ini` or next to the executable). If the file does not exist, the tool will create a default one.

```ini
[KEYS]
# Static Keys (Hex)
kenc = 404142434445464748494A4B4C4D4E4F
kmac = 404142434445464748494A4B4C4D4E4F
dek  = 404142434445464748494A4B4C4D4E4F
# Key Version Number (usually 0x20 or 0x30)
kvn  = 20
```

### AID Registry (`aid.txt`)
Map AIDs to friendly names for easier navigation. Located in `SCP03/aid.txt` or next to the executable.
```text
ISD-R: A0000005591010FFFFFFFF8900000100
ECASD: A0000005591010FFFFFFFF8900000200
```

### File Identifier (FID) Paths (`fids.txt`)
Contains predefined File IDs mapping to textual paths for tree navigation. This file is copied to the executable directory on first run and can be modified.

### Custom Macros/Keybinds (`binds.json`)
Defines custom command aliases for the interactive shell. You can chain commands using semicolons (`;`) and pass arguments using `{0}`, `{1}`. Located in `SCP03/interface/binds.json` or next to the executable.
```json
{
    "adm": "manage-pin verify 0a {0}",
    "init": "auth-sd; select usim"
}
```

### SCP11 Certificates
Certificates used by the SCP11 module (`CERT.DPauth.ECDSA.der`, `SK.DPauth.ECDSA.pem`, etc.) are also copied alongside the executable. They can be modified by replacing them with your own certificates of the same name.

---

## 📂 Project Structure

* **`SCP03/`**: Core logic for GlobalPlatform, SGP.22, and the interactive shell.
    * `logic/`: Business logic for GP, FS, Security, and eSIM (SGP.22).
    * `interface/`: Shell dispatcher and CLI handling.
    * `transport/`: PC/SC card abstraction.
* **`SCP80/`**: OTA/SMS secure channel tools.

**CAP / Load File Install:** Full CAP install from file is supported: WIZARD option 8 builds the APDU sequence (dry run); for live install, `gp.install_cap_file()` in `SCP03/logic/gp.py` implements INSTALL [for load], LOAD (chunked), and INSTALL [for install]. No further change needed unless you need different CAP formats or OTA-specific chunking.

---

## ⚖️ License
[MIT License](LICENSE) - Free to use and modify.