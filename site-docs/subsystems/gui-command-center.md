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

The clean and full PyInstaller flavors do not include the GUI dependency
stack by default. Source installs are the recommended path for GUI lab work.

## Launch modes

=== "Desktop"

    ```bash
    python main/main.py --gui
    ```

    Desktop mode binds a local FastAPI server, opens a pywebview window,
    generates an in-process bearer token, and tears down GUI-owned helpers
    on shutdown.

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

## Workbench areas

| Area | Purpose |
| --- | --- |
| Reader strip | Lists local PC/SC readers and remote-card bridge rows from `/api/live/readers`. |
| SCP03 workbench | Card session tabs, filesystem navigation, FCP/ARR display, records, binary reads, and custom APDUs. |
| Command Center actions | Registry-backed forms for SCP03, SCP11, SCP80, SAIP, simulator, diagnostics, and HIL actions. |
| Live APDU dock | WebSocket-fed APDU stream from the process-wide recorder, capped for long sessions. |
| Card bridge panel | Remote-card bridge configuration, live probe, token posture, latency history, and remote HIL rig control. |
| HIL module | Local/remote HIL health, decoded pcap snapshots, modem shell helper, GSMTAP capture review. |
| Host shell | Opt-in PTY panel for lab hosts. Disabled unless `YGGDRASIM_GUI_HOST_SHELL=1`. |

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
workflow documented in [Remote APDU Streaming](../how-to/remote-apdu-streaming.md).
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
| remote rig action hangs at SSH | key login not configured | verify `ssh -o BatchMode=yes <target> true` outside the GUI |

## Related pages

- [Remote APDU Streaming](../how-to/remote-apdu-streaming.md)
- [Install RemSIM / APDU Streaming](../how-to/install-remsim-apdu-streaming.md)
- [HIL Bridge](hil-bridge.md)
- [Run a HIL Capture](../how-to/run-hil-capture.md)
