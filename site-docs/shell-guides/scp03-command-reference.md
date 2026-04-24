# Command Reference

This page mirrors the grouped `HELP` surface from the SCP03 admin shell.

## Session and card info

- `AUTH-SD`: legacy alias for `SCP03-SD`
- `SCP03-SD`: authenticate with the security domain using SCP03
- `SCP02-SD`: authenticate with the security domain using SCP02
- `RESET`: reset the card connection and print the ATR path again
- `INFO`: print card specifications such as ATR, ICCID, EID, and SGP version
- `ATR`: reset and print a parsed ATR breakdown
- `KEYS [AID]`: retrieve key information for the current or specified AID
- `LOGOUT`: close the secure session
- `CLS`: clear the terminal screen
- `OTA`: switch into the SCP80 over-the-air toolkit
- `STK [Commands]`: enter the SCP03 STK subsystem

## GlobalPlatform execution wizards

- `WIZARD`: unified installer for applets, packages, and extradition
- `PUT-KEY`: rotate, add, or replace cryptographic keys
- `SET-STATUS`: modify the lifecycle state of a card, applet, or load file
- `MANAGE-CHANNEL`: open or close logical channels
- `GET-DATA`: retrieve registry objects, CPLC, or custom tags
- `APPS`: shortcut for the applications registry
- `PKGS`: shortcut for the packages registry
- `SD`: shortcut for the security domains registry
- `LOCK <AID>`: set state to locked
- `UNLOCK <AID>`: set state to selectable
- `DEL <AID>`: delete an object
- `STORE-DATA <hex> [P1] [P2]`: send a raw `STORE DATA` payload

## Telecom and eSIM retrieval

- `LIST`: list eSIM profiles through `GetProfilesInfo`
- `MANAGE-PROFILE`: spec-aware wizard for SGP.22, SGP.32, and SGP.02 command sets
- `RUN-AUTH`: execute GSM, USIM, or ISIM authentication algorithms
- `RUN-AUTH-TEST`: run offline 3GPP TS 35.207 Milenage vector validation
- `DERIVE-OPC <Ki_hex> <OP_hex>`: derive `OPc` per 3GPP TS 35.206

`MANAGE-PROFILE` retrieval reads retry through:

1. the base channel
2. logical channel 1
3. STK mode

## SCP11 module map

The SCP03 help surface points operators toward the dedicated SCP11 modules:

- main menu `3`: SCP11 live relay shell
- main menu `4`: SCP11 test relay shell
- main menu `5`: SCP11 local access shell

Use the mirrored docs in [Source Library](../source-library.md) for the full
SCP11 README pages.

## Security and PIN management

- `MANAGE-PIN`: unified wizard to verify, change, enable, disable, or unblock PINs

## Environment configuration

- `CONFIG`: update SCP03 keys, SCP02 keys, ADM, or target AID
- `SHOW`: display current SQLite-backed SCP03 configuration
- `AIDS`: list registered AID aliases from `Workspace/SCP03/aid.txt`
- `SET-AID-ALIAS <Name> <AID>`: map a friendly name to an AID
- `SET-DEFAULT`: factory reset configuration to default test keys
- `BINDS`: manage custom macro commands and parameters

## File system operations

- `SCAN`: traverse and discover the UICC file tree
- `REPORT`: unified report wizard for filesystem and eUICC export paths
- `SET-GOLD-PROFILE <path> [SGP.32|SGP.22|SGP.02] [AUTH=Y|N]`: persist a gold combined YAML path
- `GOLD-PROFILE`: show persisted gold path and metadata
- `CLEAR-GOLD-PROFILE`: clear the persisted gold path
- `PROFILE-DIFF [gold.yaml] [STANDARD] [AUTH=Y|N]`: capture live FS and eUICC data and diff it against gold
- `VALIDATE [ALL|MF|USIM|ISIM] [ProfileDump.yaml|ProfileDump.json]`: validate active profile filesystem structure
- `SELECT <Path/FID>`: select a DF or EF
- `READ [Path]`: read binary data from the selected EF
- `RECORD <N/ALL/Start-End> [Path]`: read one or more records
- `UPDATE BINARY <Hex>`: write binary data to an EF
- `UPDATE RECORD <N> <Hex>`: write a record to an EF
- `FS-ADMIN`: administrative activate, delete, create, terminate, and resize tasks

## System and developer

- `GUIDE [Topic]`: show in-shell documentation for `GP`, `ETSI`, `GSMA`, `INSTALL`, `SECURITY`, `OTA`, `CONFIG`, `SAIP`, `SUCI`, or `CLI`
- `DECODE <Hex>`: parse and decode a raw BER-TLV string
- `RUN` or `SCRIPT <File> [Out.yaml]`: execute a batch script of APDU commands
- `DEBUG` or `VERBOSE`: toggle raw APDU logging
- `EXPORT-KEYBAG [Path.keys.json] [Label]`: dump the active SCP03 session keys (S-ENC, S-MAC, S-RMAC, SSC, chaining value) and the target AID into a keybag JSON for offline HIL pcap decryption; refuses cleanly when no authenticated session is present
- `HELP`: display the grouped command help
- `EXIT` or `Q`: disconnect the reader and leave the SCP03 shell
- `QA`: disconnect the reader and exit YggdraSIM

## Practical cross-reference

- Use [Guide Topics](scp03-guide-topics.md) for the deeper background material behind these commands.
- Use [Source Library](../source-library.md) for the mirrored README and guide files that the wrapper menu also exposes.
- Use [HIL Bridge — offline pcap replay](../subsystems/hil-bridge.md#offline-pcap-replay) and
  [Replay a HIL pcap offline](../how-to/replay-hil-pcap-offline.md) for the
  `EXPORT-KEYBAG` consumer side.
