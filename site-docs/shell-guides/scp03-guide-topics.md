<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Guide Topics

This page mirrors the topic-oriented `GUIDE [Topic]` surface from the SCP03
admin shell. In the shell, `GUIDE` opens a wizard and `GUIDE <topic>` jumps
straight to one topic.

## Topic map

| Topic | Focus |
| --- | --- |
| `GP` | GlobalPlatform security domains, SCP03, registry operations, and lifecycle handling |
| `ETSI` | ETSI TS 102 221 and 3GPP-style file hierarchy and file access |
| `GSMA` | eUICC and profile retrieval paths, ES10c operations, and SGP scope split |
| `INSTALL` | GlobalPlatform install wizard structure and install-parameter handling |
| `SECURITY` | SCP03 derivation, key wrapping, PIN handling, and network auth |
| `OTA` | SCP80 OTA secured packet structure and configuration model |
| `CONFIG` | workspace configuration files, persistence, and runtime-root behavior |
| `SAIP` | SAIP package inspection and wrapper workflow |
| `SUCI` | SUCI key tool workflow and supported curves |
| `CLI` | launcher versus direct module entry points, `--cmd`, piping, and output redirection |

## GP

Reference: [GlobalPlatform Card Specification v2.3.1](https://globalplatform.org/wp-content/uploads/2025/05/GPC_CardSpecification_v2.3.1.49_PublicRvw.pdf)

### Security domain architecture

- the issuer security domain is the primary root of trust
- supplementary security domains can be used for delegated management and application-provider roles
- selecting a security domain routes subsequent APDUs to its secure-channel handler

Representative select form:

```text
00 A4 04 00 <Lc> <AID>
```

### SCP03 handshake

The shell guide centers the SCP03 flow around:

1. `INITIALIZE UPDATE` (`80 50`)
2. `EXTERNAL AUTHENTICATE` (`84 82`)

Key points:

- host and card challenges provide the session context
- `S-ENC`, `S-MAC`, and `S-RMAC` are derived from the static key set
- the secure channel must be established before protected GlobalPlatform commands are sent

### Registry discovery and object lifecycle

- `GET STATUS` retrieves registry entries such as applications, load files, and security domains
- `GET DATA` retrieves application or security-domain data objects such as the key information template or CPLC
- `SET STATUS` changes lifecycle state and can perform irreversible transitions on some objects
- `PUT KEY` rotates or adds keys using wrapped key material
- `STORE DATA` pushes DGI or TLV personalization payloads

### Logical channels

The guide also covers `MANAGE CHANNEL` as the ISO 7816 mechanism for opening and
closing additional logical channels without tearing down the overall environment.

## ETSI

Reference: [ETSI TS 102 221](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/16.00.00_60/ts_102221v160000p.pdf)

### File hierarchy and selection

- the UICC file tree is modeled as `MF -> DF/ADF -> EF`
- `MF` is `3F00`
- ADFs such as `ADF-USIM` host application-specific files such as `EF-IMSI`
- `SELECT` returns an FCP template with file descriptor, file ID, size, lifecycle, and access-condition data

Representative forms:

```text
00 A4 00 04 02 <FID>
00 A4 04 00 <Lc> <Path>
```

### Transparent and record EFs

- `READ BINARY` and `UPDATE BINARY` operate on transparent EFs
- `READ RECORD`, `UPDATE RECORD`, and `SEARCH RECORD` operate on linear-fixed or cyclic EFs

### Administrative file handling

The in-shell guide places filesystem administration under explicit admin
privilege:

- `CREATE FILE`
- `DELETE FILE`
- vendor-specific resize paths when supported
- `DEACTIVATE FILE`
- `ACTIVATE FILE`

## GSMA

Reference: [GSMA eSIM specification portal](https://www.gsma.com/solutions-and-impact/technologies/esim/esim-specification/)

### Scope split

The shell guide explicitly distinguishes SCP03 from SCP11:

- `SCP03` covers retrieval, local profile state control, GlobalPlatform access, and read-oriented eUICC inspection
- SCP11 provisioning and relay flows live in the dedicated `SCP11/live`, `SCP11/test`, and `SCP11/local_access` modules

### Consumer eUICC architecture

- `ISD-R` is the management application used for ES10c operations
- `ISD-P` holds one profile context
- `ECASD` holds the eUICC trust-root material and the `EID`

### ES10c local profile management

The guide highlights these profile-management tags:

- `GetProfilesInfo` `BF2D`
- `EnableProfile` `BF31`
- `DisableProfile` `BF32`
- `DeleteProfile` `BF33`

It also notes that YggdraSIM retries local `STORE DATA` reads through:

1. the base channel
2. logical channel 1 after reset
3. STK mode after another reset

### eUICC information and SGP.32 retrieval

The SCP03 guide maps the retrieval surface to ES10b and ES10c style reads:

- `EuiccInfo1` `BF20`
- `EuiccInfo2` `BF22`
- `GetRAT` `BF43`
- `RetrieveNotificationsList` `BF2B`
- `GetEimConfigurationData` `BF55`
- `GetEID`
- `GetCerts`

### Retrieval matrix

The wizard-oriented mapping in the in-shell guide ties retrieval actions to spec
families and request tags so the operator can connect menu actions to protocol
objects instead of treating them as opaque shell verbs.

## INSTALL

### Install wizard scope

The install guide frames `INSTALL` around the full GlobalPlatform object
lifecycle:

- `INSTALL [for load]`
- `LOAD`
- `INSTALL [for install]`
- `INSTALL [for make selectable]`
- `INSTALL [for install and make selectable]`
- extradition
- registry update
- personalization

### Wizard options

The shell guide calls out the main wizard choices:

1. install for load
2. install for install
3. install for make selectable
4. install for extradition
5. install for registry update
6. install for personalization
7. install and make selectable
8. full CAP install sequence

### One-shot CAP install

`INSTALL <cap/ijc> <INSTALL-for-install APDU>` parses the CAP/IJC, sends
`INSTALL [for load]` and `LOAD`, then sends the supplied `INSTALL [for install]`
or `INSTALL [for install and make selectable]` APDU unchanged. The command
checks that the APDU Load File AID matches the CAP package AID before loading.

`INSTALL-CAP <cap/ijc> --privs 00 --params C900 --applet <AID> --module <AID>`
builds the complete CAP load and instantiate sequence from command arguments.
The command also accepts positional compatibility:
`INSTALL-CAP <cap/ijc> [Priv] [Params] [AppletAID] [ModuleAID]`.

Direct scriptable INSTALL verbs are available for the remaining GP variants:

- `LOAD <cap/ijc>`
- `INSTALL-LOAD <LoadFileAID> [SecurityDomainAID] [LoadFileHash] [Params] [Token]`
- `INSTALL-APP <PkgAID> <AppAID> [ModAID] [Priv] [Params]`
- `INSTALL-INSTANCE <PkgAID> <AppAID> [ModAID] [Priv] [Params]`
- `MAKE-SELECTABLE <AID> [Priv] [Params] [Token]`
- `EXTRADITE <App_AID> <SD_AID> [Token]`
- `REGISTRY-UPDATE <AID> [Priv] [Params]`
- `PERSONALIZE <AID>`

### APDU structure and privileges

Representative structure:

```text
80 E6 <P1> 00 <Lc> <LoadFileAID_LV> <ModuleAID_LV> <AppletAID_LV> <Priv_LV> <Params_LV> <Token_LV>
```

Privilege handling in the guide includes:

- security domain
- DAP verification
- delegated management
- card lock
- card terminate
- default selected
- CVM management

### Install parameters

The in-shell guide distinguishes:

- application-specific parameters such as `C9`
- GP system parameters such as `EF`
- ETSI UICC system parameters such as `EA`
- legacy SIM file-access parameters such as `CA`

It also notes that `CA` and `EA` must not be mixed in the same install
parameter set. The install-parameter builder accepts `C900` or any other
complete `C9` TLV unchanged, and wraps non-TLV C9 values as `C9`.

## SECURITY

### SCP03 cryptographic model

The security guide ties the shell behavior to:

- static `K-ENC`, `K-MAC`, and `K-DEK`
- NIST SP 800-108 KDF-derived session keys
- `S-ENC` for confidentiality
- `S-MAC` and `S-RMAC` for command and response integrity

### Key rotation and wrapping

`PUT KEY` is described as a wrapped-key path:

- new static keys are not sent in clear
- `K-DEK` protects transported key material
- key check values are used for validation

### PIN and ADM handling

The guide documents:

- FF padding to 8 bytes
- `VERIFY`
- `CHANGE REFERENCE DATA`
- retry counter behavior such as `63 CX`
- blocked-reference behavior such as `69 83`

### Network authentication

The in-shell notes also cover:

- USIM and ISIM style authentication with `RAND` and `AUTN`
- GSM style authentication with `RAND`

## OTA

Reference focus: ETSI TS 102 225 and 3GPP TS 31.115

### OTA architecture

- remote servers send secured packets toward the UICC
- `TAR` selects the target remote-management function
- `SPI` defines confidentiality and integrity behavior
- `KIC` and `KID` identify the relevant OTA keys

### Secured packet structure

The guide outlines the command header list and the typical fields that precede
the inner APDU payload:

- `SPI`
- `KIC`
- `KID`
- `TAR`
- `CNTR`
- `PCNTR`
- optional cryptographic checksum
- optionally encrypted payload

### Supported OTA operations

- remote read and update
- remote install and delete
- `STORE DATA`
- chunked payload delivery for SMS-PP limits

### Configuration

The shell guide points operators to `ota_config.ini` for `TAR`, `SPI`, `KIC`,
`KID`, transport, and key material.

## CONFIG

### Runtime-root model

The guide distinguishes source runs from frozen executables:

- source runs read and write workspace files directly
- frozen builds use a writable runtime root
- `YGGDRASIM_RUNTIME_ROOT` can override that writable root

### SCP03 configuration files

- `Workspace/SCP03/keys.ini`
- `Workspace/SCP03/aid.txt`
- `Workspace/SCP03/fids.txt`
- `Workspace/SCP03/binds.json`

### SCP80 and SCP11 split

- `SCP80/ota_config.ini` holds the OTA runtime configuration
- `SCP11/live` is the live relay shell
- `SCP11/test` is the test relay shell
- `SCP11/local_access` is the local `AuthenticateServer` and `LOAD-PROFILE` path

## SAIP

Reference: [pySim SAIP tool manual](https://downloads.osmocom.org/docs/pysim/master/html/saip-tool.html)

### Scope

The shell guide frames the SAIP tool wrapper around inspection and
transformation of SAIP and UPP profile packages.

### Recommended read flow

The suggested low-risk sequence is:

1. `USE`
2. `INFO`
3. `TREE`
4. `DUMP ALL DECODED`
5. `CHECK`

### Hex input support

The guide notes that `.txt` and `.hex` inputs can be interpreted as hex-encoded
DER, normalized, validated, and cached as DER before the backend tool is
invoked.

### Write and export operations

- `SPLIT`
- `EXTRACT-APPS`
- `REMOVE-NAA`
- `RAW`

## SUCI

Reference: [pySim SUCI key tool manual](https://downloads.osmocom.org/docs/pysim/master/html/suci-keytool.html)

### Scope and workflow

The SUCI shell guide focuses on:

- selecting a target key path with `USE`
- generating a key pair with `GENERATE`
- exporting public-key material with `DUMP`
- using `DUMP COMPRESSED` where the compressed form is needed

### Supported curves

- `SECP256R1`
- `CURVE25519`

## CLI

### Launcher versus direct module entry

The in-shell CLI guide highlights two main launch models:

- unified launcher: `python3 main/main.py`
- direct module form: `python3 -m <module>`

### Verified entry points

The guide explicitly calls out:

- `python3 -m SCP03`
- `python3 -m SCP80`
- `python3 -m Tools.ProfilePackage`
- `python3 -m Tools.SuciTool`
- `python3 -m SCP11`
- `python3 -m SCP11.live`
- `python3 -m SCP11.test`
- `python3 -m SCP11.relay`
- `python3 -m SCP11.local_access`
- `python3 -m SCP11.eim_local`

### Non-interactive execution and piping

The shell guide documents:

- `--cmd` for semicolon-separated command execution
- stdin-driven command streams for automation
- stdout redirection
- native report export paths where modules support them

Representative examples:

```bash
python3 -m SCP03 --cmd "SCP03-SD; LIST" --out report.yaml
python3 -m SCP03 --cmd "SCP03-SD; INSTALL-CAP app.cap --privs 00 --params C900; APPS; PKGS"
printf 'SCP03-SD\nINSTALL-CAP app.cap --privs 00 --params C900\nAPPS\nQ\n' | python3 -m SCP03
printf 'HELP\nQ\n' | python3 -m SCP03
python3 -m Tools.ProfilePackage --cmd "USE reference_test_profile.txt; INFO" > saip_stdout.txt
```

## Related docs

- Use [Command Reference](scp03-command-reference.md) for the grouped `HELP` surface.
- Use [Source Library](../source-library.md) for the mirrored authored Markdown docs exposed from the main wrapper guides menu.
