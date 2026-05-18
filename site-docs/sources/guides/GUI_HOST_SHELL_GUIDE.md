# GUI Host Shell Guide

The **Advanced > Host shell** tab in the YggdraSIM Universal GUI gives
the operator a free-form interactive OS shell over a WebSocket-backed
PTY. It is intended for ad-hoc modem CLI workflows — `tio`, `minicom`,
`socat`, `screen`, `cu`, plain `cat /dev/ttyUSB*` — that the more
constrained **Advanced > Shell** tab cannot reach because that tab is
locked to `python -m <module>` against a fixed allow-list.

| Property | **Shell** (existing) | **Host shell** (new) |
| --- | --- | --- |
| Sidebar entry | `Advanced > Shell` | `Advanced > Host shell` |
| Backing route | `WS /api/terminal/{module}` | `WS /api/host-shell` |
| argv shape | `python -m <module>` | `<resolved $SHELL> -i` |
| argv allow-list | `yggdrasim_common.registry.CLI_MODULES` | none |
| Default | **on** in both `--gui` and `--web-server` | **off** — opt-in only |
| Trust posture | Allow-listed Python modules | RCE-class — equivalent to SSH |
| Companion REST | `/api/terminal/modules` | `/api/host-shell/{capabilities,devices}` |
| AT-decode overlay | n/a | yes (per-session toggle) |

> **Threat model summary.** When Host shell is enabled, anyone who
> holds the GUI bearer token gets a shell-equivalent capability on the
> machine that launched `yggdrasim`. Treat the token like an SSH
> private key: rotate it, restrict who reads the token file, and prefer
> an SSH tunnel over a public `--web-server` bind. Do not enable Host
> shell on a publicly bound `--web-server` instance unless you have
> wrapped it in TLS plus a tight network ACL.

---

## 1. Enabling the tab

Host shell is gated behind a single environment flag:

```bash
export YGGDRASIM_GUI_HOST_SHELL=1
yggdrasim --gui            # desktop launcher
# or
yggdrasim --web-server     # remote / lab launcher
```

The flag is read at launch time. Flipping it inside an already-running
process has no effect — restart the launcher.

Accepted truthy values: `1`, `true`, `yes`, `on` (case-insensitive).
Anything else (including unset, `0`, empty string) leaves the surface
disabled.

When disabled:

- The `Advanced > Host shell` sidebar entry still renders so the tab is
  discoverable, but selecting it shows a disabled notice with the
  enable instruction.
- `GET /api/host-shell/capabilities` returns 200 with
  `{"enabled": false, "shell": null, "reason": "..."}`. The SPA reads
  this on every tab activation, so the notice always reflects the
  current process state.
- `GET /api/host-shell/devices` is harmless and remains reachable —
  it has no side effects and only enumerates `/dev/tty*`. It returns
  the same payload regardless of the env flag.
- `WS /api/host-shell` accepts the handshake, sends one
  `{"event": "error", "message": "Host shell is disabled. ..."}`
  text frame, and closes with code `1008` (policy violation).

When enabled:

- The capability snapshot reports the resolved shell path
  (typically `/bin/bash`) so the tab can show the operator which
  binary will be spawned.
- The `Start session` button connects the WebSocket and the xterm
  view goes live.

---

## 2. UI walkthrough

The tab is divided into three rows plus an optional side panel.

```
┌──────────────────────────────────────────────────────────────────┐
│ [Start session] [Stop]                            status: idle … │
├──────────────────────────────────────────────────────────────────┤
│ Serial device [/dev/serial/by-id/usb-... ▼] [↻] [Insert path]    │
│                                          ☐ Decode AT lines       │
├──────────────────────────────────────────────────────────────────┤
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ xterm.js host                                                │ │
│ │  $                                                           │ │
│ └──────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│ AT decode                                            [Clear]     │
│  > csim request   AT+CSIM=14,"00A40004023F00"                    │
│  < csim response  +CSIM: 4,"9000"                                │
└──────────────────────────────────────────────────────────────────┘
```

### 2.1 Session controls

- `Start session` — opens a WebSocket to `/api/host-shell`, forks the
  resolved shell inside a fresh PTY, and pipes the byte stream to the
  xterm view. The status pill shows `running · pid=… · /bin/bash`
  once the server has confirmed the spawn.
- `Stop` — cleanly closes the WebSocket; the server reaps the child.
  The xterm history is preserved in the DOM until the operator
  navigates away or starts another session.

### 2.2 Serial device picker

- Dropdown — populated from `GET /api/host-shell/devices` on tab
  activation. Sources scanned (in order): `/dev/serial/by-id/*`,
  `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/ttyS*`. Devices that resolve
  to the same canonical path are de-duplicated; `by-id` entries win
  because their names are stable across reboots and reseatings.
- `↻` — re-runs the enumeration. Useful after plugging or unplugging a
  USB-serial adapter without leaving the tab.
- `Insert path` — sends the highlighted device path as raw stdin into
  the running shell. Combine with the cursor position in xterm to
  splice the path into a `tio`, `socat`, or `minicom` invocation
  without retyping.
- The path validator rejects anything that does not match
  `/dev/(ttyUSB|ttyACM|ttyS)\d+` or
  `/dev/serial/by-id/[A-Za-z0-9._:\-+]+`, with a 256-character cap. The
  server-side picker therefore cannot be used to splice
  `; rm -rf ~` into the prompt; if you want to type something else,
  type it normally — the PTY transport itself is byte-for-byte
  transparent, exactly like SSH.

### 2.3 AT decode overlay

- Checkbox `☐ Decode AT lines` — enables the per-session decoder.
  When toggled on, the route tee's the byte stream through
  `yggdrasim_common.gui_server.at_decoder` and emits a structured JSON
  frame for every line that matches a known AT shape.
- Side panel — three-column rows:

  | Column | Content |
  | --- | --- |
  | Glyph | `>` for `tx` (operator → modem), `<` for `rx` (modem → operator). Colour follows the theme accent palette. |
  | Kind | `csim request`, `csim response`, `crsm request`, `crsm response`. |
  | Raw line | The original AT line as it crossed the wire, ANSI-stripped. |

  Hovering a row expands a JSON detail block with the parsed APDU
  header (CLA / INS / P1 / P2 / Lc / data), the friendly INS label
  (e.g. `SELECT`, `READ BINARY`), and — for response lines — the
  human-readable status word from
  `SCP03.core.utils.StatusWordTranslator` (e.g. `9000` →
  `Success`).

- Click a row to copy the raw APDU hex (request rows) or the response
  hex (response rows) to the system clipboard. Useful for pasting into
  the SCP03 shell's `SEND` command for cross-checking.
- The xterm output is unchanged whether the toggle is on or off — the
  decoder is strictly additive.

The overlay is bounded:

- Buffer cap — 16 KiB rolling buffer per direction. A runaway binary
  stream is dropped wholesale rather than tying up RAM. The xterm
  output is unaffected; the decoder simply skips that fragment.
- Long-line cap — single lines longer than 4 KiB are flushed at the
  cap to keep one bad request from monopolising the channel.
- Row cap — the side panel keeps the most recent 250 entries; older
  rows are evicted as new ones arrive.

---

## 3. HTTP and WebSocket reference

All endpoints sit behind the same bearer-token auth as the rest of the
GUI surface (`Authorization: Bearer <token>` for HTTP; query parameter
`?t=<token>`, `Authorization` header, or `Sec-WebSocket-Protocol:
bearer.<token>` for the WebSocket).

### 3.1 Capability probe

```
GET /api/host-shell/capabilities

200 OK
Content-Type: application/json

{
  "supported": true,
  "enabled":   false,
  "shell":     null,
  "reason":    "Host shell is opt-in. Set YGGDRASIM_GUI_HOST_SHELL=1 to enable; restart yggdrasim --gui / --web-server afterwards."
}
```

| Field | Meaning |
| --- | --- |
| `supported` | False on platforms where the underlying PTY bridge cannot run (currently any non-POSIX target). When false, `enabled` is also false and `reason` explains. |
| `enabled` | Tracks `YGGDRASIM_GUI_HOST_SHELL` truthiness, re-read on every call. |
| `shell` | Resolved shell path (the binary that will be `execvpe`'d) when enabled. `null` when disabled or when no usable shell could be found. |
| `reason` | Operator-facing explanation when disabled. `null` when enabled. |

### 3.2 Device enumeration

```
GET /api/host-shell/devices

200 OK
Content-Type: application/json

{
  "count": 2,
  "devices": [
    {
      "path":        "/dev/serial/by-id/usb-Quectel_EG25-G-if02-port0",
      "link_target": "/dev/ttyUSB2",
      "label":       "by-id · usb-Quectel_EG25-G-if02-port0"
    },
    {
      "path":        "/dev/ttyUSB3",
      "link_target": null,
      "label":       "USB-serial"
    }
  ]
}
```

The endpoint is read-only; it does not open the device, does not
probe baud rates, and does not require the shell session to be
running. Use it for live device pickers in custom UIs.

### 3.3 WebSocket framing

URL: `ws://<host>:<port>/api/host-shell?t=<token>&rows=<rows>&cols=<cols>`
(`wss://` when the GUI is fronted by TLS or `--tls-self-signed`).

`rows` and `cols` are clamped to `[1, 500]` and `[1, 1000]`
respectively.

Two frame directions, two encodings:

| Direction | Encoding | Meaning |
| --- | --- | --- |
| client → server | binary | Raw stdin bytes (xterm.js typed input, paste, etc.). |
| client → server | text (JSON) | Control message, see below. |
| server → client | binary | Raw stdout / stderr bytes from the PTY master. xterm.js writes these straight into the screen buffer. |
| server → client | text (JSON) | Lifecycle event — see below. |

#### 3.3.1 Client control frames

```jsonc
// stdin pulled out as a JSON envelope. Equivalent to sending the
// literal bytes as a binary frame; useful when the client cannot
// generate a binary WebSocket frame.
{ "type": "stdin", "data": "AT+CSIM=14,\"00A40004023F00\"\r" }

// Forwarded to the PTY via TIOCSWINSZ.
{ "type": "resize", "rows": 30, "cols": 120 }

// Sends a control byte to the foreground process. Currently
// understood: SIGINT (Ctrl+C / 0x03) and SIGQUIT (Ctrl+\ / 0x1c).
// Unknown names are silently ignored to keep the contract
// forward-compatible.
{ "type": "signal", "name": "SIGINT" }

// Toggle the AT decode tee. When enabled, the server emits an
// {"event": "at_decoded"} text frame for every matched line. When
// disabled, only the raw binary stream flows.
{ "type": "at_decode", "enabled": true }
```

Unknown `type` values are silently dropped so newer clients and
older servers (or vice versa) interoperate without a hard break.

#### 3.3.2 Server lifecycle events

```jsonc
// Sent once after the PTY child has been forked.
{ "event": "spawned", "pid": 12345, "shell": "/bin/bash" }

// Sent once after the child exits or the WS is closing.
{ "event": "exit", "status": 0 }

// Sent before close on any spawn / handshake error path.
{ "event": "error", "message": "Host shell is disabled. ..." }

// Emitted only when the AT decode overlay is enabled. One frame per
// recognised line. See §3.3.3 for the payload shapes.
{ "event": "at_decoded", "direction": "tx", "kind": "csim_request",
  "raw": "AT+CSIM=14,\"00A40004023F00\"",
  "decoded": { "...": "..." } }
```

#### 3.3.3 `at_decoded` payload shapes

| `kind` | `decoded` keys |
| --- | --- |
| `csim_request` | `length_chars`, `apdu_hex`, `cla_hex`, `ins_hex`, `ins_label`, `p1_hex`, `p2_hex`, `case`, `lc`, `data_hex`, optional `le` |
| `csim_response` | `length_chars`, `data_hex`, `sw1_hex`, `sw2_hex`, `sw_meaning` |
| `crsm_request` | `command_id`, `command_label`, `file_id_hex`, `p1_hex`, `p2_hex`, `p3`, `data_hex`, `select_path_hex` |
| `crsm_response` | `sw1_hex`, `sw2_hex`, `sw_meaning`, `data_hex` |

`sw_meaning` is the string returned by
`SCP03.core.utils.StatusWordTranslator.translate` so it stays in
sync with the SCP03 shell vocabulary.

`command_label` is `READ BINARY` / `READ RECORD` / `GET RESPONSE` /
`UPDATE BINARY` / `UPDATE RECORD` / `STATUS` — the six commands TS
27.007 §8.18 lets `AT+CRSM` carry.

`ins_label` is populated for the common ISO 7816 / UICC / STK INS
codes used over `AT+CSIM` in practice (`SELECT`, `READ BINARY`, …,
`TERMINAL PROFILE`, `FETCH`, `TERMINAL RESPONSE`); unknown INS
values produce an empty label rather than a guess.

---

## 4. Recipes

These all assume the Host shell session is open and the operator's
shell has whatever helpers (`tio`, `socat`, `minicom`, `picocom`,
`screen`, `cu`) installed.

### 4.1 One-shot `socat` AT command

```bash
echo 'AT+ICCID' | socat -t1 - /dev/ttyUSB2,raw,b115200,echo=0
```

Pair with the AT decode toggle to get the `+CCID:` response decoded
into the side panel.

### 4.2 Interactive `tio` session

```bash
tio -b 115200 -e -m INLCRNL,ONLCRNL /dev/ttyUSB2
```

`-e` enables local echo, `-m INLCRNL,ONLCRNL` makes line endings sane
on a host that hands the modem `\n`-only.

### 4.3 `minicom` against a `by-id` symlink

```bash
minicom -D /dev/serial/by-id/usb-Quectel_EG25-G-if02-port0 -b 115200 -8 -o
```

`-o` skips the modem init string so the first byte sent is exactly
what the operator types.

### 4.4 GSMTAP-mirrored capture with `socat` + `tcpdump`

```bash
socat -d -d /dev/ttyUSB2,raw,b115200,echo=0 \
  SYSTEM:'tee /tmp/modem.log | nc -u 127.0.0.1 4729' &
tcpdump -i lo -n udp port 4729 -w /tmp/modem.pcap
```

Useful when sharing a live modem trace with the SIMtrace2 / HIL
bridge stack — see `HIL_BRIDGE_GUIDE.md` for the full topology.

### 4.5 Pasting an APDU back into SCP03

1. Toggle `Decode AT lines` on.
2. Issue `AT+CSIM=14,"00A40004023F00"` against the modem.
3. Click the matching `csim request` row in the side panel — the APDU
   hex is now on the clipboard.
4. Switch to the `Advanced > Shell` tab and paste it into a running
   `python -m SCP03` session as `SEND 00A40004023F00`.

---

## 5. Operational caveats

### 5.1 Process ownership

The shell is `execvpe`'d as the same UID/GID that launched
`yggdrasim`. There is no `chroot`, no `setuid` drop, and no cgroup
isolation. The operator's environment (`HOME`, `PATH`, `XDG_*`, the
process's argv-derived `_=`) is inherited by default; only `TERM` is
overridden to `xterm-256color` so xterm interactive features come
through before the shell's rc files run.

### 5.2 Resize plumbing

The xterm.js side issues `resize` control frames on the browser-window
`resize` event. The server forwards them to the PTY master via
`TIOCSWINSZ`, so curses applications (`htop`, `vim`, `tmux`) reflow
correctly.

### 5.3 Lifecycle and cleanup

Closing the WebSocket — either via `Stop`, navigating away, the
browser tab closing, or a network error — always tears down the
child:

1. The reader task is cancelled.
2. The PTY master fd is closed.
3. The child receives `SIGHUP` from the PTY hangup.
4. The route logs `gui.host_shell.closed peer=<addr>:<port>`.

A long-running process started inside the shell (`tio`, `tail -f`)
inherits the hangup. If the operator wants the process to outlive the
session, they need to `nohup` / `disown` / `setsid` it themselves —
the same constraint as a real SSH session.

### 5.4 Concurrent sessions

Each browser tab opens its own WebSocket and its own PTY child. There
is no cross-tab serialisation; opening the Host shell tab on two
machines pointing at the same `--web-server` instance gives both
operators independent shells. Keep this in mind when sharing a token.

### 5.5 Logging

Every Host shell event is emitted to the standard logging surface
under `yggdrasim.gui.host_shell.route` and
`yggdrasim.gui.host_shell`:

| Logger record | When |
| --- | --- |
| `gui.host_shell.opened token=<id> peer=<addr>:<port> rows=… cols=…` | Successful WS handshake (after token validation, after the env-flag check). Logged at `WARNING` to surface in default log destinations. |
| `gui.host_shell.spawned shell=<path> pid=<pid> rows=… cols=…` | After `pty.fork()` succeeds. Logged at `INFO`. |
| `gui.host_shell.closed peer=<addr>:<port>` | After cleanup. Logged at `INFO`. |
| `gui.host_shell.auth_rejected peer=<addr>:<port>` | Bearer-token mismatch / missing. Logged at `INFO`. |
| `gui.host_shell.spawn_failed err=<msg> peer=<addr>:<port>` | Spawn errored after auth passed. Logged at `WARNING`. |

Keep at least one log destination in production so post-incident
forensics can answer "who got a shell, when, and from where".

---

## 6. Hardening checklist

If Host shell is enabled in `--web-server` mode, walk this list:

1. Bind to `127.0.0.1` and use SSH tunnelling (`ssh -L
   <port>:localhost:<port> user@host`) instead of binding `0.0.0.0`.
2. If a public bind is unavoidable, terminate TLS — either with
   `--tls-self-signed` for one-off use (the SHA-256 fingerprint is
   printed on launch; pin it manually) or with operator certificates
   via `YGGDRASIM_GUI_TLS_CERT` / `YGGDRASIM_GUI_TLS_KEY`.
3. Store the bearer token in a `chmod 600` file referenced by
   `YGGDRASIM_GUI_TOKEN_FILE`. Never inline it via
   `YGGDRASIM_GUI_TOKEN` on a multi-user host — the env block is
   visible to any process the operator can read.
4. Rotate the token whenever it could plausibly have been observed
   (shared screen, terminal screenshot, mistyped paste).
5. If multiple operators share a host, give each one their own
   account, their own token file, and their own GUI process — one
   shared token means shared blame.
6. Monitor the GUI process logs (§5.5) and pipe them through your
   existing SIEM / journald aggregator. The
   `gui.host_shell.opened` line carries the token id and the peer
   address; correlate against access expectations.
7. When you no longer need the surface, unset the env flag and
   restart. The route fails closed on the next handshake without any
   client-side change required.

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Tab shows the disabled notice. | `YGGDRASIM_GUI_HOST_SHELL` is unset / falsey, or set after the launcher started. | Export the flag and restart the launcher. |
| WS opens then immediately closes with `event=error: Host shell is disabled`. | Same as above; the route refuses late-flipped config. | Same as above. |
| Notice says "PTY bridge is not supported on this platform." | Running on a non-POSIX target — currently Windows native. | Use the `--gui` desktop launcher on a Linux/macOS host, or run YggdraSIM under WSL2 / a Linux container and tunnel back. |
| Notice says "Could not resolve a usable login shell." | `$SHELL` points outside `/etc/shells` and neither `/bin/bash` nor `/bin/sh` is on disk (extremely stripped container). | Point `SHELL` at a real entry in `/etc/shells` before launching, or install `bash` / `sh` in the container. |
| `Insert path` does nothing. | No session is running, or no device is selected. | Start the session first; refresh the device list with `↻`. |
| Decoder side panel never shows rows. | `Decode AT lines` is off, or the modem dialogue isn't using `AT+CSIM` / `AT+CRSM`. | Toggle the decoder; verify with `echo 'AT+CSIM=14,"00A40004023F00"' | socat -t1 - /dev/ttyUSB2,raw,b115200,echo=0` to inject a known-good line. |
| Decoder shows a row but `decoded.sw_meaning` is empty. | The status word is not in `SCP03.core.utils.StatusWordTranslator.SW_MAP`, and not in the parametric `61xx` / `6Cxx` ranges. | Treat the empty meaning as "unrecognised SW" — the SW1/SW2 hex pair is still authoritative. |
| Long binary output (e.g. `cat /dev/random`) makes the side panel stop updating. | The line accumulator dropped the buffer to protect the GUI process from OOM. | Stop the runaway producer; the decoder resumes on the next terminated line. The xterm output is unaffected. |
| Shell sessions disconnect after `YGGDRASIM_GUI_IDLE_SECONDS`. | The idle cutoff applies to all GUI shell sessions (Shell + Host shell) so a left-open tab does not pin a child forever. | Increase `YGGDRASIM_GUI_IDLE_SECONDS`, or set it to `0` on a desktop bind. Not recommended for `--web-server`. |

---

## 8. References

| Topic | Path |
| --- | --- |
| Env flag registration | `yggdrasim_common/env_flags.py` (`YGGDRASIM_GUI_HOST_SHELL`) |
| Backend module | `yggdrasim_common/gui_server/host_shell.py` |
| AT decoder | `yggdrasim_common/gui_server/at_decoder.py` |
| FastAPI route | `yggdrasim_common/gui_server/routes/host_shell.py` |
| Frontend (canonical) | `yggdrasim_common/gui_server/static/index.html`, `app.js`, `app.css` |
| Frontend source tree | `gui_frontend/src/index.html`, `app.js`, `app.css` |
| AT request parser (re-used) | `Tools/HilBridge/at_simlink.py` |
| Status-word translator (re-used) | `SCP03/core/utils.py` |
| Existing PTY route (sibling) | `yggdrasim_common/gui_server/routes/terminal.py` |
| HIL bridge guide | `guides/HIL_BRIDGE_GUIDE.md` |
| CLI piping recipes | `guides/CLI_AND_PIPING_GUIDE.md` |
