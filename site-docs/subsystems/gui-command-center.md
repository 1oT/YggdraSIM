---
title: Universal GUI Command Center
tags:
  - subsystems
  - gui
  - apdu
  - remote
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Universal GUI Command Center

The Universal GUI Command Center is the browser/desktop surface for the
same registry-backed actions exposed by the CLI modules. It is useful when
an operator needs a persistent workbench: reader selection, SCP03 filesystem
state, SAIP package inspection, eSIM relay actions, remote-card diagnostics,
and live APDU visibility in one window.

The GUI is optional. A source install needs either the desktop extra or the
headless server extra:

```bash
python -m pip install -e '.[gui]'        # desktop pywebview window
python -m pip install -e '.[gui-server]' # browser / remote lab server
```

Release builds publish paired CLI and desktop-GUI executables for the clean
flavor on Windows, macOS, Linux, and Raspberry Pi arm64, and for the full
flavor on supported Linux targets. Source installs remain the most flexible
path for GUI lab development.

## Launch modes

=== "Desktop"

    ```bash
    python main/main.py --gui
    ```

    Desktop mode binds a local FastAPI server, opens a pywebview window,
    generates an in-process bearer token, and tears down GUI-owned helpers
    on shutdown.

    The window's page zoom is adjustable: Ctrl+plus, Ctrl+minus and
    Ctrl+0 (or Ctrl+wheel) step it through the browser ladder (0.5 to
    3), and the chosen factor is remembered across launches as the
    `YGGDRASIM_GUI_ZOOM` env flag, which the Configuration view edits
    as well. `1` (default) is the native size the layout is drawn for;
    `auto` fits the layout to the window instead. A browser tab on
    `--web-server` uses the browser's own zoom.

=== "Headless / remote lab"

    ```bash
    install -m 600 /dev/null ~/.config/yggdrasim/gui.token
    python - <<'PY' > ~/.config/yggdrasim/gui.token
    import secrets
    print(secrets.token_urlsafe(32))
    PY

    python main/main.py --web-server \
      --host 127.0.0.1 \
      --port 8765 \
      --token-file ~/.config/yggdrasim/gui.token
    ```

    `--web-server` requires an explicit bearer token. Keep the bind on
    `127.0.0.1` and reach it through SSH unless you have a separate TLS
    and access-control plan:

    ```bash
    ssh -fN -L 8765:127.0.0.1:8765 user@lab-host
    ```

## Views

The left rail switches between views; the reader strip and the live APDU dock
stay with you across all of them.

| View | Purpose |
| --- | --- |
| Overview | Module picker, plus the active card backend and where that selection came from. |
| Command Center | The registry-backed action forms, grouped by subsystem into tabs. |
| Remote Lab | Rig inventory, invites, sessions, and card offers against a [Remote Lab](remote-lab.md) agent. |
| Plugin console | One view for every console a loaded plugin registers: its start form, action buttons, command line and live tables, or a run form with its current run and history, each console a leaf under *Plugin consoles*, a group shown only while a console is registered. See [Plugin Contract](../internals/plugin-contract.md#plugin-consoles). |
| Registry browser | Introspection over `yggdrasim_common.registry`: subsystems, CLI modules, symbol lookups. |
| Environment | Configuration (every `YGGDRASIM_*` flag, see [Environment Flags](../reference/env-flags.md)) and the loaded-plugin list. |
| Terminal | A PTY running `python -m <module>`, restricted to the registry's CLI module allow-list. |
| Host shell | Opt-in PTY on the operator's login shell. Hidden unless `YGGDRASIM_GUI_HOST_SHELL=1`. |
| Card Bridge | Local bridge control plus the Remote Bridge onboarding for a stored host. See [Card Bridge](card-bridge.md). |
| About | What this build is, and an in-app reader for the guides the release ships (`/api/guides`). |

Within those views:

| Area | Purpose |
| --- | --- |
| Reader strip | Lists local PC/SC readers and remote-card bridge rows from `/api/live/readers`. |
| SCP03 workbench | Card session tabs, filesystem navigation, FCP/ARR display, records, binary reads, and custom APDUs. |
| SAIP workbench | Profile-package inspection and editing: PE tree, hex pane, template placeholders, PE export and import. |
| Command Center actions | Registry-backed forms for SCP03, SCP11, SCP80, SAIP, simulator, diagnostics, and HIL actions. |
| Live APDU dock | WebSocket-fed APDU stream from the process-wide recorder, capped for long sessions. |
| Card bridge panel | Remote-card bridge configuration, live probe, token posture, latency history, and remote HIL rig control. |
| HIL module | Local/remote HIL health, decoded pcap snapshots, modem shell helper, GSMTAP capture review. |

## Inside the workbenches

### SAIP workbench

Profile-package work happens on a PE tree beside a hex pane. Beyond opening,
editing and saving a package, two actions move a single profile element
between packages:

- **Export PE** (`saip.export_pe`) writes one PE as a PE document
  (`.pe.json`, schema `ygg.pe_document.v1`): the PE type and the tagged
  decoded tree a saved package uses, and nothing about the package it came
  from. A PE-Application therefore travels with its load block, the applet
  bytes and every instance. The dialog names the file after the PE, and the
  destination's extension picks DER or hex instead. In a template session you
  choose whether the placeholder literals travel or the stored values are
  substituted.
- **Import PE** (`saip.import_pe`) puts one back into any package. It also
  reads a tagged single-section document, the plain decoded JSON of one PE,
  and DER or hex text. The tree has to encode before it reaches the sequence,
  the DER an earlier release's document recorded is reported when it no
  longer matches its tree, and the copy takes the next free identification so
  the other PEs keep theirs.
- **Save PE** (`saip.save_pe`) keeps the selected PE in the operator's PE
  library under a name, as the same PE document, so a standardised element
  (a PE-SD with its key set and privileges, say) is one click away in any
  package; **PE library** (`saip.list_pe_library`, `saip.load_pe`,
  `saip.delete_saved_pe`) lists the entries and loads one at a chosen
  index or deletes it. The library is `~/.yggdrasim/saip_pe_library/`
  (`YGGDRASIM_SAIP_PE_LIBRARY`), outside every checkout. A saved template
  PE keeps its placeholder literals and registers them in the package it is
  loaded into, answered from the test-value lists where they can be.

**Add above** / **Add below** open the *Insert profile element* dialog:
every `ProfileElement` type the SAIP module in use can carry
(`saip.list_pe_types`, schema order, with a filter box), the presets of a
type that has several, and the saved PEs of the PE library, inserted at
the index the dialog shows. The Decoded view keeps its scroll offset, open
folds and chosen tab per package and element, so switching between open
packages and back lands where the operator left off, and a link path
clicked in a PE-GFM entry opens the referenced file in the FS tree with the
top tab following. The FCP editor of a GFM entry carries every `Fcp`
member, `dfName` for an ADF included; for a link, EF size and the
proprietary info rows are the conditional parameters that turn the link
into an independent file.

**Save as** names the format and the destination in one dialog: DER, HEX
(`.hex` / `.txt`), ASN.1 value notation (`.asn`), tagged JSON (`.json`) and,
for a template session, varder; a destination extension still names the
format itself. The PE-SD card decodes each `sdPersoData` record into its
DGI blocks under the raw hex and takes a new record (**Add DGI record**),
which the server accepts only as whole DGI, length, value blocks.

The Profile Header editor carries **Sync from EF.ICCID** and **Sync from
EF.SMSP**: each copies a file's value into the header field that mirrors it --
`iccid`, and the SMSC address of the SMS-PP bearer -- and applies it.

### SCP03 workbench

The Install tab's **Install script** button (`scp03.build_install_script`)
builds the CAP install sequence without a card and offers a save-as picker
with an overwrite switch. It is the same builder as the shell's Wizard 8
(Full CAP Install Sequence) and writes a byte-identical file: the source CAP
and the format as `#` comments, one APDU per line. An OTA-formatted file runs
in the SCP80 shell with `script <file>`, an ISO-formatted one in the SCP03
shell with `RUN <file>`.

### Offline Tools

Offline Tools lists seven entries under the Offline Tools leaf of the
navigation, shown while Offline Tools is open, and one entry fills the page
at a time, with no card grid. Tools that share an input or a store are one
entry with a tab per tool: Decoder (the Decoder and the ASN.1/TLV decode),
TERMINAL PROFILE (Decode, Build), AddInitialEim (Build, Send, Configurations,
Certificate store, Saved values) and SUCI keys (Use key file, Generate, Dump
public key, under a line with the key file and the `suci-keytool` command in
use; that command is set with `YGGDRASIM_SUCI_TOOL` under Environment >
Configuration). eIM package
lint, TUAK -- derive TOPc and the GSMA error-code reference stand alone, and
any other tool (a plugin's, for example) follows by title. A tab keeps what
was typed into it while another tab is open, and reads the saved names and
values again when it is shown.

The Offline Tools
leaf opens the Decoder, a context-aware decoder (`tool.decoder.context`). One
paste box takes an APDU, a response, a bare TLV, a status word or a whole exchange trace;
each command is classified by its CLA/INS pair and the payload decoded
against the specification that governs it -- TS 102 221 SELECT parameters and
FCP templates, TS 102 223 / TS 101 220 proactive commands, envelopes and
terminal responses, GPC v2.3.1 GET STATUS entries, INSTALL, DELETE, STORE
DATA and GET DATA, SCP03 INITIALIZE UPDATE, ES10 requests and responses named
from their BF tag, and TS 31.102 AUTHENTICATE. A trace carries state: the
selected file names READ BINARY content, and a `61 xx` word chains GET
RESPONSE onto its command. A ProfileInstallationResult, or the EUICCResponse
inside it pasted on its own, is headed by its outcome: every PE ok, or the
failing PE with its status and offset (TCA eUICC Profile Package V3.4.1
section 8.11). The EUICCInfo2 of an IoT eUICC carries the SGP.32 check as a
note (GSMA SGP.32 v1.3 §5.9.2). The Decoder stands in for the separate TLV
parse, status-word lookup, EUICCInfo2 decode and SIMa response decode
actions, which are gone.

Several commands go in at once, one per row: paste them, or use **Open file**
(or drop the file on the box) to read a script file into it. The file is read
in the page and reaches the decoder as text, like a paste; the server is given
no path. A script file is what the SCP03 shell's `RUN` and the SCP80 shell's
`script` read: a row that starts with `#` is a comment, a row of hex is one
command (the decoder and the SCP80 `script` also drop a `#` comment after the
hex; `RUN` in the SCP03 shell does not take one). Each row is decoded as its
own command with the trace state carried along, and its card shows the row it
stands on when comments make the two counts part. The panel decodes the first
1000 exchanges of an input and says how many it holds; Open file takes up to 1
MiB. Rows may also be exchanges, a command with its answer on the row below or
on the same row after ` | `, ` ; ` or a tab. A marker (`>`, `<`, `C:`, `R:`,
`sw=XXXX`) says what a row is; without one, a row that is a well-formed
command of a known instruction starts a new exchange, and any other row
answers the command above it. The Command APDU context takes every row as a
command and the Response context every row as an answer, whatever the row
looks like. A row that holds no hex, such as a shell verb, is left unread and
counted by row number in a note under the banner; it is never mined for hex
and never quoted.

Hex is the form the Decoder reads first, and apart from those rows nothing it
already reads into a domain is read differently. Around it:

- `AT+CSIM`, `AT+CRSM`, `AT+CGLA` and `AT+CRLA` lines with their answers
  (3GPP TS 27.007 V19.6 §8.17, §8.18, §8.43, §8.44) are read as exchanges; a
  restricted-access line names its file, so the content it returns is decoded
  without a SELECT in the trace.
- A paste that is not hex is tried as PEM (certificates are read, a key block
  is left unread), a JSON body whose base64 members are RSP objects, base64,
  an EID, ICCID or IMSI in digits with its check digits, an ATR and TLS
  records. Four bytes that are a PC/SC return code are named, with a note on
  what the same bytes say as an APDU.
- A plain BER tree is replaced by the certificate or the profile package it
  is; the Raw BER-TLV context keeps the tree.
- The EF content context reads one file's content: the file identifier on the
  first line (`ADF_USIM/6F07`), the content below.

Inside a trace it reads further than the object's name: the SMS TPDU of an
SMS-PP download or a SEND SHORT MESSAGE with the secured command or response
packet in it (ETSI TS 102 225 V19.0.0 §5.1 and §5.2), the channel data of SEND
DATA and RECEIVE DATA followed across the trace as one stream per channel (TLS
records and handshake messages, a record cut across data blocks read once it
is whole, DNS messages, HTTP request and status lines), the PUT KEY data field and the Key
Information Template (GlobalPlatform Card Specification v2.4 §11.8.2.3 and
§11.3.3.1), TERMINAL CAPABILITY with the LPAd and IPAd bits, the SUCI that GET
IDENTITY returns (3GPP TS 31.102 V19.5 §7.5.2.1), and the SCP11 commands
PERFORM SECURITY OPERATION, MUTUAL AUTHENTICATE and INTERNAL AUTHENTICATE
(GlobalPlatform Amendment F v1.2 §6.4 to §6.6). An ES10 data field under
secure messaging is shown as the protected block it is. Not read: CPLC (its
layout is in none of the documents the decoder is built from), a certificate
of PERFORM SECURITY OPERATION that is split over chained commands, and a CAP
file.

The same engine backs `python -m Tools.Asn1TlvDecode --context` and the
`context_decode` MCP tool, so a decode reads the same from the GUI, a
terminal and an agent. The ASN.1/TLV decode action (`tool.asn1_tlv.decode`)
shows the same schema reading of a GSMA RSP object as its notation; the BER
structure stays in its decoded TLV tree.

The two tabs of the TERMINAL PROFILE entry decode and build a profile against
ETSI TS 102 223 V18.3.0 clause 5.2 and the 3GPP bits of TS 31.111 V19.4.0 clause 5.2.
TERMINAL PROFILE decode (`tool.tp.decode`) lists every bit and count field
by byte, adds the TS 31.111 reading where the two specifications word a bit
differently, and reports the bits the coding keeps 0; given a second profile
it lists only the facilities that differ. TERMINAL PROFILE build
(`tool.tp.build`) starts from the maximal profile every YggdraSIM shell sends,
from an empty one or from a pasted one, and takes facilities by `byte.bit`
(`5.5`), count fields by their bit range (`13.6-8=1`) or a facility by a
piece of its name. The context decoder names the facilities of a TERMINAL
PROFILE APDU from the same table, and
`python -m yggdrasim_common.terminal_profile` decodes, compares, builds and
lists in a terminal.

AddInitialEim build (`tool.eim_builder.add_initial_eim`) composes the
ES10b.AddInitialEimRequest of GSMA SGP.32 v1.3 §5.9.4. The eIM and TLS
certificates come from the eIM certificate store
(`tool.eim_builder.certificates`: import a PEM, DER, base64 or hex
certificate, list, remove; a private key block in the source is dropped,
never stored);
eimId, eimFqdn and euiccCiPKId are typed, and every build saves them so
the next form offers them as suggestions (`tool.eim_builder.saved_values`
lists, edits or forgets one; a certificate renames in place and the saved
values and configurations follow it). Every build or send also keeps its
whole form, settings and ticks included, as the last build
(`last_configuration.json` in the store): the build and send forms open with
it, and a field changed before the store answers keeps what was typed. A
configuration is a named copy of the whole form: tick Save with a
Configuration name and a request that builds is stored under it; picking a
configuration fills every field, so testing another set of values is a pick
rather than a retype (`tool.eim_builder.configurations` lists, renames or
deletes them). The result is
the request, read back member by member before it is shown, and the APDU
script of the run: TERMINAL CAPABILITY declaring the IPAd, MANAGE CHANNEL,
SELECT ISD-R, eUICCMemoryReset with resetEimConfigData and
resetImmediateEnableConfig (§5.9.5; AddInitialEim is refused while any eIM
Configuration Data is stored), then AddInitialEim in 255-byte STORE DATA
blocks. Copy takes the commands alone, one per line, for the SCP03 shell's
`RUN`. AddInitialEim as one APDU shows the same request in a single STORE DATA,
with an extended Lc past 255 bytes, for a reader and card that take one or a
console that chains it into the blocks above. The store lives outside the checkout
(`YGGDRASIM_EIM_BUILDER_STORE`, default `~/.yggdrasim/eim_builder/`) and
is never tracked. The build touches no card. AddInitialEim send, the tab next
to it (`tool.eim_builder.send`) and again in the SGP.32 IoT (IPA-d) tab of
eSIM Management (`scp11_live.add_initial_eim`), takes the same form plus a
reader and the confirm checkbox, builds the request before it touches the
card, then runs the connect phase, the reset and the request and streams
both decoded answers. In a terminal, the eSIM
Live shell's `ADD-INITIAL-EIM` asks for the same members one at a time
and holds no card transport while it waits; once confirmed it sends the
reset and the request and decodes both answers. `EIM-CERT-STORE` manages
the same store.

## Live APDU stream

Every card connection created through the shared card backend is wrapped by
the APDU recorder. The recorder stores a bounded ring buffer and streams
new exchanges to the GUI over `/api/events/apdu`.

What appears in the APDU dock:

- command APDU hex
- response data hex
- status word or `ERR`
- elapsed time
- source label such as `pcsc`, `relay`, or simulator-backed actions

The stream is diagnostic. It does not replace keybag capture for decrypting
secure-channel traffic. For SCP03/SCP11c plaintext replay, export a keybag
from the shell that derived the session keys and use the HIL pcap replay
workflow.

## Remote-card bridge controls

The Card bridge view wraps the same `Tools.CardBridge` and HIL remote-card
workflow documented in [Card Bridge over SSH](../how-to/remote-apdu-streaming.md).
It is designed for the common lab topology:

```text
PC reader -> local CardBridge -> SSH tunnel -> Raspberry Pi HIL rig -> SIMtrace2 -> modem
```

The GUI can:

- start or stop the local PC-side Card Bridge
- open or close SSH forwards to a rig
- sync the bearer token to the rig with mode `0600`
- install or restart the rig-side `systemd --user` HIL supervisor service
- verify the remote bridge, HIL service, SIMtrace2 path, and RemSIM binary
- pull remote HIL captures back into the local GUI for decoded review

SSH key login must already work from the account that launched the GUI. The
actions use `BatchMode=yes` and will not pause for an interactive password.

## Security posture

- `--web-server` refuses to start without a bearer token.
- Wildcard CORS origins are refused.
- Loopback bind plus SSH tunnel is the default remote-access model.
- `--tls-cert`/`--tls-key` or `--tls-self-signed` are available for lab
  environments that cannot rely on SSH tunnelling alone.
- The host shell is disabled by default and must be explicitly enabled with
  `YGGDRASIM_GUI_HOST_SHELL=1`.
- Remote-card bearer tokens are never echoed in GUI responses; only short
  fingerprints are shown.
- The file picker lists only the directories it offers (home, working
  dir, workspace, Documents, Downloads, Desktop) when running
  `--web-server`, because that mode is reachable off-host and the token
  holder need not own the machine. `--gui` is unrestricted: it is bound
  to loopback on the operator's own machine. Override either default
  with `YGGDRASIM_GUI_FS_ROOTS` (an `os.pathsep`-separated list). The
  endpoint returns names, sizes, and timestamps only -- there is no
  route that reads file contents by path.

## Common launch recipes

### Local desktop with a physical reader

```bash
python -m pip install -e '.[gui]'
python main/main.py --gui
```

### Remote browser connected to a lab host

```bash
# lab host
python -m pip install -e '.[gui-server,hil]'
python main/main.py --web-server \
  --host 127.0.0.1 \
  --port 8765 \
  --token-file ~/.config/yggdrasim/gui.token

# workstation
ssh -fN -L 8765:127.0.0.1:8765 lab-host
```

### Remote card plus remote HIL rig

1. Start the GUI on the workstation with `[gui]`.
2. Open the Card bridge view.
3. Fill in the local reader selector, SSH target, rig repo path, rig
   Python, RemSIM binary, SIMtrace2 VID:PID, and HIL port.
4. Run **Start full rig**.
5. Watch the live APDU dock and HIL decoded views.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `--web-server` exits with a token error | no token supplied | pass `--token-file`, `YGGDRASIM_GUI_TOKEN_FILE`, or `YGGDRASIM_GUI_TOKEN` |
| browser opens but actions return 401 | stale token in URL/local storage | reload from the printed URL or clear the browser tab state |
| no APDUs appear | action did not use the shared card backend, or no card traffic happened yet | run a reader-backed action and check `/api/live/readers` |
| Host shell is hidden | host shell intentionally disabled | set `YGGDRASIM_GUI_HOST_SHELL=1` and restart |
| the desktop window's interface is too small or too large | page zoom remembered from an earlier session, or `YGGDRASIM_GUI_ZOOM` set in the environment | press Ctrl+0 in the window for the native size, or set the flag in Configuration |
| file picker says a path is "outside the directories this server may browse" | `--web-server` limits listing to the picker's roots | add the directory to `YGGDRASIM_GUI_FS_ROOTS` and restart |
| remote rig action hangs at SSH | key login not configured | verify `ssh -o BatchMode=yes <target> true` outside the GUI |

## Related pages

- [Card Bridge](card-bridge.md)
- [Remote Lab](remote-lab.md)
- [Card Bridge over SSH](../how-to/remote-apdu-streaming.md)
- [Install RemSIM / APDU Streaming](../how-to/install-remsim-apdu-streaming.md)
- [HIL Bridge](hil-bridge.md)
- [Run a HIL Capture](../how-to/run-hil-capture.md)
