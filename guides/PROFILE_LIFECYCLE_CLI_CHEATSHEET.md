# Profile Lifecycle CLI Cheatsheet

Replace anything inside `[ENTER ... HERE]` before you run it. That can be an
ICCID, AID, FID, matching ID, path, hex value, output file, or other runtime
value.

Examples below use the installed `yggdrasim-*` commands. If you prefer the repo
root form, replace them with the matching `python -m ...` command.

## One-Time Setup

```bash
python -m pip install -e [ENTER PATH TO YggdraSIM HERE]
```

If your environment uses `python3` instead of `python`, use `python3 -m pip`.

## Installed Launch Commands

```text
yggdrasim-scp03
yggdrasim-scp80
yggdrasim-scp11
yggdrasim-scp11-live
yggdrasim-scp11-test
yggdrasim-scp11-relay
yggdrasim-scp11-local-access
yggdrasim-scp11-eim-local
yggdrasim-profile-package
yggdrasim-suci-tool
```

Use `yggdrasim-scp11-live`, `yggdrasim-scp11-test`, or
`yggdrasim-scp11-relay` for relay-first work.

Use `yggdrasim-scp11-local-access` for direct local card work.

Use `yggdrasim-scp11-eim-local` for local eIM, queue, handover, and localized
polling work.

Use `yggdrasim-profile-package` when the profile package itself needs to be
checked before card work.

Use `yggdrasim-scp03` for GlobalPlatform admin, file-system, card inspection,
and STK work.

Use `yggdrasim-scp80` for OTA wrap/build/send work and SCP80 reader or print
transport testing.

## How To Sequence Commands

- Use `--cmd "A; B; C; EXIT"` for short runs.
- Use `--stdin` for longer runs with one command per line.
- Commands run left to right in `--cmd` and top to bottom in `--stdin`.
- End scripted runs with `EXIT`.
- Start with `DISCOVER`, `STATUS`, `LIST`, or `HELP` when you do not know the
  current state.
- Set context first. Typical context setters are `PROFILE`, `METADATA`,
  `HOTFOLDER`, and `EIM-PACKAGE`.
- Do the action second. Typical actions are `LOAD-PROFILE`,
  `DOWNLOAD-PROFILE`, `DOWNLOAD`, `ENABLE-PROFILE`, `DISABLE-PROFILE`,
  `DELETE-PROFILE`, `IPAE-DOWNLOAD`, and `POLL-CAMPAIGN`.
- Verify third. Typical verification commands are `STATUS`, `LIST`,
  `HANDOVER-STATUS`, `RESP-LOG`, and `COUNTERS`.

Typical order:

```text
Relay LPAd: DISCOVER -> STATUS -> LIST -> DOWNLOAD-PROFILE -> STATUS -> LIST
Relay IPAd: DISCOVER -> DOWNLOAD -> STATUS -> LIST
Profile state change: LIST -> ENABLE-PROFILE / DISABLE-PROFILE / DELETE-PROFILE -> STATUS -> LIST
Local load: PROFILE -> METADATA -> LOAD-PROFILE -> STATUS -> LIST
Local metadata update: METADATA-LINT -> STORE-METADATA or UPDATE-METADATA -> STATUS
Localized IPAE: IPAE-AUTHENTICATE or HANDOVER-SET -> HANDOVER-STATUS -> IPAE-DOWNLOAD -> RESP-LOG
Queue campaign: PATHS -> HOTFOLDER-LIST -> HOTFOLDER-FETCH or POLL-CAMPAIGN -> RESP-LOG -> COUNTERS -> NOTIF-HYGIENE
Profile package triage: USE -> INFO -> TREE -> CHECK -> DUMP or LINT
SCP03 admin: INFO -> SHOW -> SCP03-SD / SCP02-SD -> APPS / PKGS / SD -> SELECT / READ / RECORD
SCP80 OTA: ICCID -> SHOW -> BUILD -> SEND / OTA -> HISTORY
```

## Available Shell Commands

### SCP03 Admin Shell

Use these with `yggdrasim-scp03`.

Top-level SCP03 commands:

```text
AUTH-SD
SCP03-SD
SCP02-SD
RESET
INFO
ATR
KEYS [AID]
LOGOUT
CLS
OTA
STK [single-command]
WIZARD
PUT-KEY
SET-STATUS
MANAGE-CHANNEL
GET-DATA
APPS
PKGS
SD
LOCK <aid>
UNLOCK <aid>
DEL <aid>
STORE-DATA <hex> [p1] [p2]
LIST
LIST-IOT
GET-IOT
MANAGE-PROFILE
RUN-AUTH
RUN-AUTH-TEST
DERIVE-OPC <kiHex> <opHex>
MANAGE-PIN [args]
CONFIG
SHOW
AIDS
SET-AID-ALIAS <name> <aid>
SET-DEFAULT
BINDS
SCAN
REPORT
SET-GOLD-PROFILE <path> [SGP.32|SGP.22|SGP.02] [AUTH=Y|AUTH=N]
GOLD-PROFILE
CLEAR-GOLD-PROFILE
PROFILE-DIFF [gold.yaml] [STANDARD] [AUTH=Y|AUTH=N]
SELECT <path|fid>
READ [path]
RECORD <n|ALL|start-end> [path]
UPDATE BINARY <hex>
UPDATE RECORD <n> <hex>
FS-ADMIN
VALIDATE [ALL|MF|USIM|ISIM] [profileDump.yaml|profileDump.json]
EXPORT-EUICC [outputPath.yaml]
EXPORT-KEYBAG [outputPath.keys.json] [label]
ARR [path]
CERT-INFO
GUIDE [topic]
DECODE <hex>
RUN <file> [out.yaml]
SCRIPT <file>
DEBUG
VERBOSE
HELP
EXIT
QA
Q
```

SCP03 STK subsystem commands:

```text
HELP
INIT
RESET
APDU <hex>
SMS <tpduHex>
QUEUE <hex>
DATA [hex]
EVENT <name|hex> [tlvs]
CALL CONNECTED [tlvs]
CALL DISCONNECTED [tlvs]
LOCATION [status] [locationHex]
STATE
HISTORY
DEBUG
VERBOSE
EXIT
BACK
Q
QA
```

SCP03 aliases:

```text
AUTH-SD -> SCP03-SD
Q -> EXIT
```

### SCP80 OTA Shell

Use these with `yggdrasim-scp80`.

Pure hex input with no command name is treated the same as `OTA <hex>`.

```text
HELP
<hex string>
OTA <hex>
BUILD [-v] [hex]
SEND [-v] [hex]
SENDRAW <hex>
RESET
ICCID [decimalIccid]
SHOW
SET <key> <value>
SCRIPT <file>
HISTORY
ADMIN
QUIT
EXIT
Q
QA
```

Common SCP80 `SET` keys:

```text
cntr
header
spi
kic
kid
tar
key_enc
key_mac
cla
transport
reader_idx
sender
concat_sms
tp_ud_max
payload
```

### Relay Shells

Use these with `yggdrasim-scp11-live`, `yggdrasim-scp11-test`, or
`yggdrasim-scp11-relay`.

Built-in relay commands:

```text
HELP
HELP-ALL
SCAN
RESET
STATUS
LIST
DOWNLOAD-PROFILE <activation>
ENABLE-PROFILE <iccid-or-aid>
DISABLE-PROFILE <iccid-or-aid>
DELETE-PROFILE <iccid-or-aid>
METADATA <id|aid|alias>
DISCOVER
DOWNLOAD [matchingId]
EXIT
QA
```

Relay expert and diagnostics commands:

```text
GET-EID
GET-SMDP
GET-ES9
SET-ES9 [--persist] <url>
SET-ES9-TLS [--persist] <on|off>
SET-ES9-CA [--persist] <pemPath|NONE>
ES9-CERT-INFO
SET-SMDP <address>
VERIFY-SCP11 [matchingId]
FLOW [matchingId]
GET-EUICC-INFO1
GET-EUICC-INFO2
GET-RAT
GET-NOTIFICATIONS
REMOVE-NOTIFICATION <seq>
CLEAR-NOTIFICATIONS
AIDS
READ-METADATA [22|32]
GET-POL <id|aid|alias>
SET-POL <id|aid|alias> <hex>
STORE-METADATA <id|aid|alias> <hex>
GET-CERTS
GET-EIM-CONFIG
GET-ALL-DATA
EIM-AUTHENTICATE [matchingId]
```

Relay optional plugin commands:

```text
POLL [attempts] [timer-window] [-t 20s] [-s 5] [--debug]
```

Relay aliases:

```text
H, ? -> HELP
INFO -> SCAN
DOWNLOAD-AC -> DOWNLOAD-PROFILE
GET-METADATA -> METADATA
EIM-DISCOVER -> DISCOVER
EIM-DOWNLOAD -> DOWNLOAD
EIM-POLL -> POLL
QUIT, Q -> EXIT
```

### Local Card Shell

Use these with `yggdrasim-scp11-local-access`.

```text
HELP
CERTS [--json|--yaml]
DISCOVER
EXPLAIN-LAST [--json|--yaml]
STATUS
PROFILE [path]
PROFILE-CLEAR
METADATA [path]
METADATA-LINT [path] [--json|--yaml]
METADATA-CLEAR
LOAD-PROFILE [path]
ENABLE-PROFILE <id>
DISABLE-PROFILE <id>
DELETE-PROFILE <id>
STORE-METADATA [path]
UPDATE-METADATA [path]
STORE-METADATA-CUSTOM <tag> [path]
STORE-METADATA-CUSTOM-ALL [path]
RECORD [STATUS|START [outputPath]|STOP [outputPath]|CANCEL]
EXPORT-KEYBAG [outputPath.keys.json] [label]
EXIT
QA
```

Local card aliases:

```text
SMDP-CERTS -> CERTS
INFO -> DISCOVER
ENABLE -> ENABLE-PROFILE
DISABLE -> DISABLE-PROFILE
DELETE -> DELETE-PROFILE
PROFILE-RESET -> PROFILE-CLEAR
METADATA-RESET -> METADATA-CLEAR
QUIT, Q -> EXIT
```

### Local eIM Shell

Use these with `yggdrasim-scp11-eim-local`.

Core local eIM commands:

```text
HELP [command]
PATHS
RECORD [STATUS|START [outputPath]|STOP [outputPath]|CANCEL]
STATUS
LIST
DISCOVER
PROFILE [profilePath]
PROFILE-CLEAR
METADATA [metadataPath]
METADATA-CLEAR
METADATA-LINT [metadataPath]
LOAD-PROFILE [profilePath]
ENABLE-PROFILE <iccid|aid|alias>
DISABLE-PROFILE <iccid|aid|alias>
DELETE-PROFILE <iccid|aid|alias>
STORE-METADATA [metadataPath]
UPDATE-METADATA [metadataPath]
EXIT
QA
```

Direct eIM and ISD-R commands:

```text
GET-EIM-CONFIG
DELETE-EIM <eimId>
EUICC-MEMORY-RESET [packagePath]
ISDR-GET-EIM-CONFIG
ISDR-DELETE-EIM <eimId>
LOAD-EIM-PACKAGE [packagePath] [certPath]
```

IPAd and handover commands:

```text
IPAD-DISCOVER [packagePath]
IPAD-LIVE [matchingId] [--debug]
IPAD-TEST [matchingId] [--debug]
IPAE-AUTHENTICATE [matchingId]
HANDOVER-SET <transactionIdHex> [matchingId]
HANDOVER-STATUS [--json|--yaml]
IPAE-DOWNLOAD [profilePath] [matchingId]
EIM-ACKNOWLEDGE [transactionIdHex] [matchingId]
```

Package and certificate commands:

```text
EIM-PACKAGE [packagePath]
EIM-PACKAGE-CLEAR
EIM-PACKAGE-LINT [packagePath] [--strict-exec] [--json|--yaml]
EIM-PACKAGE-EXPLAIN [packagePath] [--strict-exec] [--json|--yaml]
EIM-PACKAGE-ISSUE [packagePath]
EIM-PACKAGE-ISSUE-ALL [directory]
EIM-CERTS [--json|--yaml] [packagePath] [certPath]
ADD-INITIAL-EIM [package|isdr] [certPath] [packagePath]
ADD-EIM [package|isdr] [certPath] [packagePath]
ISDR-ADD-INITIAL-EIM [certPath] [packagePath]
ISDR-ADD-EIM [certPath] [packagePath]
ERROR-CODES [SGP.02|SGP.22|SGP.32|ALL]
ERROR-CODE-SET <family> <code|name> [packagePath]
```

Queue, polling, and audit commands:

```text
HOTFOLDER [directory]
HOTFOLDER-CLEAR
HOTFOLDER-LIST [directory] [--json|--yaml]
HOTFOLDER-POLL [directory] [--json|--yaml]
HOTFOLDER-FETCH [directory] [--json|--yaml]
POLL-CAMPAIGN [cycles] [intervalMs] [hotfolderDir] [--until-empty] [--max-cycles <n>] [--json|--yaml]
POLL-EXPORT [cycles] [intervalMs] [hotfolderDir] [--until-empty] [--max-cycles <n>] [outputPath]
POLL-AGGREGATE [reportsDir] [--json|--yaml] [--export [outputPath]]
COUNTERS
COUNTER <eimId> [set <n>]
NOTIF-HYGIENE [maxPending]
RESP-LOG [n] [--json|--yaml]
RESP-LOG-FILTER <query> [n] [--json|--yaml]
RESP-LOG-CLEAR
```

Local eIM optional plugin commands:

```text
IPAE-LIVE [attempts] [timer-window] [-t 20s] [-s 5] [--debug]
IPAE-TEST [attempts] [timer-window] [-t 20s] [-s 5] [--debug]
```

Local eIM aliases:

```text
INFO -> DISCOVER
ENABLE -> ENABLE-PROFILE
DISABLE -> DISABLE-PROFILE
DELETE -> DELETE-PROFILE
EIM-ACK -> EIM-ACKNOWLEDGE
ISDR-PACKAGE -> LOAD-EIM-PACKAGE
ISDR-LOAD-PACKAGE -> LOAD-EIM-PACKAGE
RESPONSE-LOG -> RESP-LOG
ISDR-EUICC-MEMORY-RESET -> EUICC-MEMORY-RESET
? -> HELP
QUIT, Q -> EXIT
```

### Profile Package Shell

Use these with `yggdrasim-profile-package`.

```text
HELP
USE <file>
OPEN [file]
STATUS
PROFILE-DIR [dir]
TRANSCODE-DIR [dir]
TOOL [command]
INFO [APPS]
TREE
CHECK
LINT [options] [> output_file]
DUMP [ALL|TYPE|NAA] [DECODED] [> output_file]
INSPECT
TUI
ENCODE-JSON <in.json> <out.der>
GENERATE-TEMPLATE <out.json> [ICCID=<digits>] [IMSI=<digits>]
GENERATE-PROFILE <template.json> <out.der> [NAME=value ...]
GENERATE-BATCH <template.json> <data_file> <out_dir>
LIST-AKA
PROVISION-AKA <out.der | IN-PLACE> [ALGORITHM=..] [KI=..] [OPC=..] [NUMBER-OF-KECCAK=..] [AUTH-COUNTER-MAX=..] [SQN-INIT=..]
RANDOMIZE-AKA <out.der | IN-PLACE> [ALGORITHM=..] [INCLUDE-AUTH-COUNTER-MAX] [INCLUDE-SQN-INIT]
SPLIT [output_prefix]
EXTRACT-APPS [dir] [CAP|IJC]
REMOVE-NAA <USIM|ISIM|CSIM> <output_file>
RAW <subcommand args...>
PWD
EXIT
QA
```

Profile package aliases:

```text
OPEN -> select profile and launch INSPECT
TUI -> INSPECT
TRANSCODE-TUI -> TUI
QUIT, Q -> EXIT
```

## Ready-To-Paste Commands

### SCP03 Admin

```bash
yggdrasim-scp03 --cmd "INFO; SHOW; AIDS; HELP; EXIT"

yggdrasim-scp03 --cmd "SCP03-SD; APPS; PKGS; SD; EXIT"

yggdrasim-scp03 --cmd "LIST; EXIT"

yggdrasim-scp03 --cmd "SELECT [ENTER PATH / FID HERE]; READ; EXIT"

yggdrasim-scp03 --cmd "RECORD [ENTER RECORD / ALL / START-END HERE] [ENTER PATH HERE]; EXIT"

yggdrasim-scp03 --cmd "STK HELP; EXIT"

yggdrasim-scp03 --cmd "GUIDE CLI; EXIT"

yggdrasim-scp03 --cmd "RUN [ENTER SCRIPT PATH HERE]; EXIT"

yggdrasim-scp03 --cmd "SCP03-SD; EXPORT-KEYBAG [ENTER PATH.keys.json HERE] [ENTER LABEL HERE]; EXIT"

cat <<'EOF' | yggdrasim-scp03 --stdin
SHOW
AIDS
HELP
EXIT
EOF
```

### SCP80 OTA

```bash
yggdrasim-scp80 --cmd "HELP; SHOW; EXIT"

yggdrasim-scp80 --cmd "ICCID [ENTER DECIMAL ICCID HERE]; SHOW; EXIT"

yggdrasim-scp80 --cmd "SET transport [ENTER print OR reader HERE]; SHOW; EXIT"

yggdrasim-scp80 --cmd "BUILD [ENTER OTA PAYLOAD HEX HERE]; EXIT"

yggdrasim-scp80 --cmd "SEND [ENTER OTA PAYLOAD HEX HERE]; EXIT"

yggdrasim-scp80 --cmd "OTA [ENTER OTA PAYLOAD HEX HERE]; EXIT"

yggdrasim-scp80 --cmd "SENDRAW [ENTER RAW APDU HEX HERE]; EXIT"

yggdrasim-scp80 --cmd "SCRIPT [ENTER SCRIPT PATH HERE]; EXIT"

cat <<'EOF' | yggdrasim-scp80 --stdin
[ENTER OTA PAYLOAD HEX HERE]
EXIT
EOF
```

### Live Relay

```bash
yggdrasim-scp11-live --cmd "DISCOVER; STATUS; LIST; EXIT"

yggdrasim-scp11-live --cmd "DOWNLOAD-PROFILE [ENTER ACTIVATION CODE HERE]; STATUS; LIST; EXIT"

yggdrasim-scp11-live --cmd "DISCOVER; DOWNLOAD [ENTER MATCHING ID HERE]; STATUS; LIST; EXIT"

yggdrasim-scp11-live --cmd "ENABLE-PROFILE [ENTER ICCID / AID HERE]; EXIT"

yggdrasim-scp11-live --cmd "DISABLE-PROFILE [ENTER ICCID / AID HERE]; EXIT"

yggdrasim-scp11-live --cmd "DELETE-PROFILE [ENTER ICCID / AID HERE]; EXIT"

yggdrasim-scp11-live --cmd "POLL; EXIT"

yggdrasim-scp11-live --cmd "POLL [ENTER ATTEMPTS HERE] [ENTER TIMER WINDOW HERE] --debug; EXIT"

yggdrasim-scp11-live --cmd "DISCOVER; STATUS; LIST; EXIT" | tee "[ENTER OUTPUT PATH HERE]"
```

### Test Relay

```bash
yggdrasim-scp11-test --cmd "DISCOVER; STATUS; LIST; EXIT"

yggdrasim-scp11-test --cmd "DOWNLOAD-PROFILE [ENTER ACTIVATION CODE HERE]; STATUS; LIST; EXIT"

yggdrasim-scp11-test --cmd "DISCOVER; DOWNLOAD [ENTER MATCHING ID HERE]; STATUS; LIST; EXIT"

yggdrasim-scp11-test --cmd "ENABLE-PROFILE [ENTER ICCID / AID HERE]; EXIT"

yggdrasim-scp11-test --cmd "DISABLE-PROFILE [ENTER ICCID / AID HERE]; EXIT"

yggdrasim-scp11-test --cmd "DELETE-PROFILE [ENTER ICCID / AID HERE]; EXIT"

yggdrasim-scp11-test --cmd "POLL; EXIT"

yggdrasim-scp11-test --cmd "POLL [ENTER ATTEMPTS HERE] [ENTER TIMER WINDOW HERE] --debug; EXIT"

yggdrasim-scp11-test --cmd "DISCOVER; STATUS; LIST; EXIT" | tee "[ENTER OUTPUT PATH HERE]"
```

### Local Card

```bash
yggdrasim-scp11-local-access --cmd "DISCOVER; STATUS; CERTS; EXIT"

yggdrasim-scp11-local-access --cmd "PROFILE [ENTER PROFILE PATH HERE]; EXIT"

yggdrasim-scp11-local-access --cmd "PROFILE-CLEAR; EXIT"

yggdrasim-scp11-local-access --cmd "METADATA [ENTER METADATA PATH HERE]; EXIT"

yggdrasim-scp11-local-access --cmd "METADATA-CLEAR; EXIT"

yggdrasim-scp11-local-access --cmd "LOAD-PROFILE [ENTER PROFILE PATH HERE]; STATUS; EXIT"

cat <<'EOF' | yggdrasim-scp11-local-access --stdin
PROFILE [ENTER PROFILE PATH HERE]
METADATA [ENTER METADATA PATH HERE]
LOAD-PROFILE
STATUS
EXIT
EOF

yggdrasim-scp11-local-access --cmd "ENABLE-PROFILE [ENTER ICCID / AID / ALIAS HERE]; EXIT"

yggdrasim-scp11-local-access --cmd "DISABLE-PROFILE [ENTER ICCID / AID / ALIAS HERE]; EXIT"

yggdrasim-scp11-local-access --cmd "DELETE-PROFILE [ENTER ICCID / AID / ALIAS HERE]; EXIT"

yggdrasim-scp11-local-access --cmd "METADATA-LINT [ENTER METADATA PATH HERE]; EXIT"

yggdrasim-scp11-local-access --cmd "STORE-METADATA [ENTER METADATA PATH HERE]; EXIT"

yggdrasim-scp11-local-access --cmd "UPDATE-METADATA [ENTER METADATA PATH HERE]; EXIT"

yggdrasim-scp11-local-access --cmd "LOAD-PROFILE" --dump-keybag "[ENTER PATH.keys.json HERE]"

yggdrasim-scp11-local-access --dump-keybag "[ENTER PATH.keys.json HERE]"

yggdrasim-scp11-local-access --cmd "DISCOVER; STATUS; CERTS; EXIT" | tee "[ENTER OUTPUT PATH HERE]"
```

### Local eIM

```bash
yggdrasim-scp11-eim-local --cmd "STATUS; PATHS; LIST; DISCOVER; EXIT"

yggdrasim-scp11-eim-local --cmd "PROFILE [ENTER PROFILE PATH HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "PROFILE-CLEAR; EXIT"

yggdrasim-scp11-eim-local --cmd "METADATA [ENTER METADATA PATH HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "METADATA-CLEAR; EXIT"

yggdrasim-scp11-eim-local --cmd "LOAD-PROFILE [ENTER PROFILE PATH HERE]; STATUS; EXIT"

cat <<'EOF' | yggdrasim-scp11-eim-local --stdin
PROFILE [ENTER PROFILE PATH HERE]
METADATA [ENTER METADATA PATH HERE]
LOAD-PROFILE
ENABLE-PROFILE [ENTER ICCID / AID / ALIAS HERE]
STATUS
EXIT
EOF

yggdrasim-scp11-eim-local --cmd "ENABLE-PROFILE [ENTER ICCID / AID / ALIAS HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "DISABLE-PROFILE [ENTER ICCID / AID / ALIAS HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "DELETE-PROFILE [ENTER ICCID / AID / ALIAS HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "IPAD-DISCOVER [ENTER PACKAGE PATH HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "IPAD-LIVE [ENTER MATCHING ID HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "IPAD-LIVE [ENTER MATCHING ID HERE] --debug; EXIT"

yggdrasim-scp11-eim-local --cmd "IPAD-TEST [ENTER MATCHING ID HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "IPAE-AUTHENTICATE [ENTER MATCHING ID HERE]; HANDOVER-STATUS; EXIT"

yggdrasim-scp11-eim-local --cmd "HANDOVER-SET [ENTER TXID HEX HERE] [ENTER MATCHING ID HERE]; HANDOVER-STATUS; EXIT"

yggdrasim-scp11-eim-local --cmd "IPAE-DOWNLOAD [ENTER PROFILE PATH HERE] [ENTER MATCHING ID HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "HOTFOLDER [ENTER HOTFOLDER DIR HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "HOTFOLDER-CLEAR; EXIT"

yggdrasim-scp11-eim-local --cmd "HOTFOLDER-LIST [ENTER HOTFOLDER DIR HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "HOTFOLDER-FETCH [ENTER HOTFOLDER DIR HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "POLL-CAMPAIGN --until-empty --max-cycles [ENTER MAX CYCLES HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "POLL-EXPORT --until-empty --max-cycles [ENTER MAX CYCLES HERE] [ENTER OUTPUT PATH HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "POLL-AGGREGATE [ENTER REPORTS DIR HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "RESP-LOG [ENTER COUNT HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "RESP-LOG-FILTER [ENTER QUERY HERE] [ENTER COUNT HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "RESP-LOG-CLEAR; EXIT"

yggdrasim-scp11-eim-local --cmd "COUNTERS; EXIT"

yggdrasim-scp11-eim-local --cmd "COUNTER [ENTER EIM ID HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "COUNTER [ENTER EIM ID HERE] set [ENTER COUNTER VALUE HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "NOTIF-HYGIENE [ENTER MAX PENDING HERE]; EXIT"

yggdrasim-scp11-eim-local --cmd "STATUS; PATHS; HOTFOLDER-LIST; RESP-LOG [ENTER COUNT HERE]; EXIT" | tee "[ENTER OUTPUT PATH HERE]"
```

### Profile Package

```bash
yggdrasim-profile-package --cmd "USE [ENTER PROFILE PACKAGE PATH HERE]; INFO; EXIT"

yggdrasim-profile-package --cmd "USE [ENTER PROFILE PACKAGE PATH HERE]; TREE; EXIT"

yggdrasim-profile-package --cmd "USE [ENTER PROFILE PACKAGE PATH HERE]; CHECK; EXIT"

yggdrasim-profile-package --cmd "USE [ENTER PROFILE PACKAGE PATH HERE]; LINT; EXIT"

yggdrasim-profile-package --cmd "USE [ENTER PROFILE PACKAGE PATH HERE]; DUMP ALL DECODED > [ENTER OUTPUT PATH HERE]; EXIT"

yggdrasim-profile-package --cmd "USE [ENTER PROFILE PACKAGE PATH HERE]; LIST-AKA; EXIT"

yggdrasim-profile-package --cmd "USE [ENTER PROFILE PACKAGE PATH HERE]; PROVISION-AKA [ENTER OUTPUT PATH HERE] ALGORITHM=milenage KI=[ENTER 32-HEX-CHAR KI HERE] OPC=[ENTER 32-HEX-CHAR OPC HERE]; EXIT"

yggdrasim-profile-package --cmd "USE [ENTER PROFILE PACKAGE PATH HERE]; PROVISION-AKA IN-PLACE ALGORITHM=tuak KI=[ENTER 32-OR-64-HEX-CHAR KI HERE] OPC=[ENTER 64-HEX-CHAR TOPc HERE] NUMBER-OF-KECCAK=1; EXIT"

yggdrasim-profile-package --cmd "USE [ENTER PROFILE PACKAGE PATH HERE]; RANDOMIZE-AKA [ENTER OUTPUT PATH HERE] ALGORITHM=tuak INCLUDE-AUTH-COUNTER-MAX; EXIT"
```

### Wrapper Diagnostics

```bash
python main/main.py --version

python main/main.py --doctor
```
