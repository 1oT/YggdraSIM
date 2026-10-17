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

Offline Tools opens on a context-aware decoder (`tool.decoder.context`). One
paste box takes an APDU, a response, a bare TLV or a whole exchange trace;
each command is classified by its CLA/INS pair and the payload decoded
against the specification that governs it -- TS 102 221 SELECT parameters and
FCP templates, TS 102 223 / TS 101 220 proactive commands, envelopes and
terminal responses, GPC v2.3.1 GET STATUS entries, INSTALL, DELETE, STORE
DATA and GET DATA, SCP03 INITIALIZE UPDATE, ES10 requests and responses named
from their BF tag, and TS 31.102 AUTHENTICATE. A trace carries state: the
selected file names READ BINARY content, and a `61 xx` word chains GET
RESPONSE onto its command.

The same engine backs `python -m Tools.Asn1TlvDecode --context` and the
`context_decode` MCP tool, so a decode reads the same from the GUI, a
terminal and an agent.

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
