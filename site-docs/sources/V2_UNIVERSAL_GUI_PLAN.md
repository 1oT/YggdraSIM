# V2 Universal GUI — Implementation Plan

Design doc for the two-mode, API-backed GUI surface that sits on top of
the existing YggdraSIM CLI / shell core. Written as a standalone plan so
it can be reviewed in isolation and then graduated into `V2_ROADMAP.md`
as `R2-004` once accepted. Nothing below is implemented yet.

- **Status**: draft / review
- **Target roadmap slot**: `R2-004` (new)
- **Priority**: Medium
- **Depends on**: nothing in `V2_ROADMAP.md` today. Plays well with
  `R2-001` (HSM signer seam) because both only touch integration
  surfaces.

---

## 1. Summary

Ship a single web-based frontend that talks to a thin FastAPI layer
wrapping the existing YggdraSIM core. The same frontend can be launched
in two modes from one entry point:

- `yggdrasim --gui` — desktop mode. Spawns FastAPI on loopback, opens
  the frontend inside a native `pywebview` window. Zero browser, zero
  exposed port, zero Electron-class RAM hit.
- `yggdrasim --web-server` — lab server mode. Spawns the same FastAPI
  layer bound to a routable interface with mandatory token auth and
  strongly recommended TLS / SSH-tunnel. No `pywebview` window.

The engine stays headless. Every existing CLI, shell, and console
script keeps working byte-for-byte. The GUI is a pure additive surface.

## 2. Motivation

- The CLI / shell surface is excellent for day-to-day card work but
  it does not scale to:
  - demoing profile lifecycle flows to non-operators,
  - concurrent multi-operator access to a lab rig,
  - remote review of HIL-bridge captures across a facility,
  - low-friction onboarding (ETSI / GSMA newcomers stall on the menu
    tree).
- `pywebview` gives us a native shell without dragging Chromium in, so
  the desktop mode stays lean enough to bundle into the existing
  PyInstaller flavors.
- FastAPI gives us a single, testable integration boundary for the
  CLI, for automation, and for the GUI. Anything built for the GUI
  becomes scriptable from `curl` for free.

## 3. Non-goals

- Replacing the CLI / shell. The CLI remains the supported operator
  surface and the source of truth for command semantics.
- Shipping a second, duplicate "admin UI" for each subsystem. The GUI
  is a **navigation and visualisation** layer over the existing
  subsystems; it does not reimplement SCP03 / SCP11 / SAIP logic.
- Multi-user RBAC. The token model below is a single-secret bearer
  gate, matching the operator-owned security posture of the rest of
  the suite.
- Remote-first web hosting. `--web-server` is a **lab** surface. Public
  internet exposure is explicitly out of scope and discouraged.
- Realtime simulator replacement. The HIL bridge, live SCP11 sessions,
  and the APDU fuzzer continue to own their own TUIs / log surfaces.
  The GUI wraps them; it does not replace them.

## 4. Architecture overview

```
+------------------------------------------------------------------+
|                   Frontend (single SPA bundle)                   |
|  HTML + JS (plain, or Vue / Svelte), served as static assets     |
|  by FastAPI. Talks to the API over fetch() + WebSocket.          |
+---------------------------+--------------------------------------+
                            |  fetch() / WebSocket (JSON)
+---------------------------v--------------------------------------+
|  FastAPI app (`yggdrasim_common.gui_server`)                     |
|  - REST endpoints wrap subsystem entry points (via registry)     |
|  - WebSocket endpoints stream shell output / HIL log lines       |
|  - Bearer-token auth middleware (opt-in for --gui, on for --web) |
|  - Uses asyncio + threadpool to avoid blocking on PC/SC I/O      |
+---------------------------+--------------------------------------+
                            |  in-process calls
+---------------------------v--------------------------------------+
|  Existing YggdraSIM engine (unchanged)                           |
|  - main/, SCP03/, SCP11/, SCP80/, SIMCARD/, Tools/HilBridge/ ... |
|  - yggdrasim_common.registry resolves subsystem entry points     |
+------------------------------------------------------------------+
```

The FastAPI layer never duplicates engine logic. It adapts
`yggdrasim_common.registry.get(<symbol>)` resolutions, and for
interactive shells it pipes stdout/stderr through a PTY-backed
WebSocket so `cmd2`-based shells stay whole.

## 5. Host and port policy (collision-safe defaults)

The rest of the suite already binds these loopback endpoints:

| Subsystem                                  | Default bind         |
| ------------------------------------------ | -------------------- |
| HIL bridge (`Tools/HilBridge/router.py`)   | `127.0.0.1:9997`     |
| SCP11 relay URL (`SCP11/*/config.py`)      | `127.0.0.1:8080`     |
| GSMTAP mirror                              | `127.0.0.1:4729/udp` |
| eIM poll bridge DNS stub                   | `127.0.0.1:15353`    |
| eIM poll bridge eIM TLS                    | `127.0.0.1:18443`    |
| eIM poll bridge SM-DP+ TLS                 | `127.0.0.1:19443`    |

To stay clear of all of those (including their typical neighbours for
the HIL card-relay status port), the GUI picks:

- `GUI_API_PORT_DESKTOP` default: **27853**
- `GUI_API_PORT_SERVER`  default: **27854**
- `GUI_API_HOST_DESKTOP` default: **`127.0.0.1`**
- `GUI_API_HOST_SERVER`  default: **`0.0.0.0`** (operator-chosen; see §9)

Collision handling:

- On startup the API tries the configured port. If the bind fails with
  `EADDRINUSE`, it falls back to an OS-assigned ephemeral port
  (`port=0`) and reports the chosen port in stdout and in the desktop
  `pywebview` URL. For server mode the fallback is refused (operators
  expect a stable URL); the process exits with a clear error.
- Optional loopback-isolation mode (Linux / macOS only): set
  `YGGDRASIM_GUI_HOST=127.0.0.7` to move the desktop API off the shared
  `127.0.0.1` alias entirely. Windows cannot bind `127.0.0.2+` without
  `netsh interface ip add address`, so the default stays `127.0.0.1`
  and this mode is documented, not forced.
- `pywebview` loads the resolved URL dynamically, so port fallback is
  transparent to the end user.

## 6. FastAPI layer

### 6.1 Module layout

```
yggdrasim_common/
  gui_server/
    __init__.py
    app.py               # FastAPI instance, lifespan, middleware
    auth.py              # bearer-token check + constant-time compare
    config.py            # GuiServerConfig dataclass + env/arg merge
    routes/
      __init__.py
      health.py          # /api/health (version, flavor, uptime)
      registry.py        # /api/registry/* (introspect SUBSYSTEMS)
      card_backend.py    # /api/backend/* (wraps set/get_card_backend)
      scp03.py           # /api/scp03/* (AUTH-SD, APPS, LIST, READ, ...)
      scp11.py           # /api/scp11/{live,test,local,eim_local}/*
      saip.py            # /api/saip/* (info/tree/check/lint/transcode)
      hil_bridge.py      # /api/hil/* (start/stop/status/pcap-open)
      sessions.py        # /api/sessions/* (shell PTY sessions)
    sockets/
      __init__.py
      shell.py           # WebSocket endpoint for cmd2 shells
      hil_stream.py      # WebSocket for HIL APDU stream
    static/              # built frontend bundle (SPA assets)
```

Nothing inside `gui_server/` owns business logic. Every route
resolves an engine symbol via `yggdrasim_common.registry.get(...)` or
calls an explicit helper from the subsystem's public module (same rule
the `console_scripts` already follow).

### 6.2 Asyncio posture

- PC/SC I/O, `saip-tool` subprocess calls, and `journalctl -f` tails
  are blocking. Every blocking call is dispatched via
  `asyncio.to_thread(...)` (FastAPI supports both `async` and `def`
  routes; we lean on the `def` path with the threadpool for blocking
  work, reserving `async` for WebSockets and the streaming endpoints).
- Long-running shells (SCP03, SCP11, SAIP) run in a background
  `ShellSession` worker thread. The worker owns a PTY pair and
  exchanges bytes with a WebSocket client using a line-framed JSON
  protocol: `{type: "stdin"|"stdout"|"stderr"|"exit", data: ...}`.
- The existing `quit_control.QuitAllRequested` cooperative exit
  mechanism is honoured; the GUI treats it as a normal session-close
  event.

### 6.3 Public REST surface (illustrative, not exhaustive)

```
GET  /api/health
GET  /api/registry/subsystems
GET  /api/registry/symbol/{key}
GET  /api/backend/state
POST /api/backend/card            body: {"backend": "reader"|"sim"}
POST /api/scp03/cmd               body: {"commands": "HELP; EXIT"}
GET  /api/saip/packages
POST /api/saip/lint               body: {"path": "/abs/profile.der"}
POST /api/saip/decoded/enumerate  body: {"path": "...", "pe_key": "..."}
POST /api/saip/decoded/preview    body: {"path": "...", "pe_key": "...",
                                         "field_path": [...]}
POST /api/saip/decoded/apply      body: {"path": "...", "pe_key": "...",
                                         "document": {...}}
GET  /api/saip/decoded/enums      (enum registry descriptors)
POST /api/hil/start               body: {"view_mode": "raw"|"wireshark"|"termshark"}
POST /api/hil/stop
GET  /api/hil/status
POST /api/hil/pcap/open           body: {"path": "...", "keybag": "..."}
WS   /api/sessions/scp03
WS   /api/sessions/scp11/live
WS   /api/sessions/hil/stream
```

Each route has a pydantic model for its body and response, so the
OpenAPI schema becomes the machine-readable contract automatically.

### 6.4 Safety rails

- No endpoint accepts a raw arbitrary shell command. Every endpoint is
  a narrow wrapper around an engine call. Shell sessions are bounded
  to `cmd2` shells that already sanitise their own input.
- Path-taking endpoints (`/api/saip/lint`, `/api/hil/pcap/open`)
  refuse paths outside an operator-configurable allow-list that
  defaults to `runtime_root`, the eUICC store root, and the current
  working directory.
- No endpoint ever returns a private key, a PIN, a session key, or the
  content of files under `state/` that are flagged sensitive by the
  existing inventory-encryption layer.

## 7. Frontend

### 7.1 Framework

Single-page app, no build step required to be runtime-present. Ship
the **built bundle** as static assets under `gui_server/static/`; the
source tree lives under `gui_frontend/` at the repo root and is a
Vite + Vue 3 or Vite + Svelte project (final choice during Phase A).
Rationale:

- Vite keeps the build graph tiny and produces a plain static bundle
  that PyInstaller can copy wholesale.
- Vue / Svelte both have mature routing + reactive-store stories
  without the React JSX toolchain cost.
- No Node.js at runtime. Node is only needed during `npm run build`,
  which is the maintainer's job, not the operator's.

### 7.2 Layout

- Left rail: subsystem selector (SCP03 shell, SCP80, SCP11 live / test
  / local / eIM, SAIP tools, HIL bridge, Card backend settings, Env
  flags). Driven by `/api/registry/subsystems`.
- Main pane: subsystem-specific view — for shells, an xterm.js
  terminal bound to the shell WebSocket. For SAIP, a tree / hex
  viewer fed by `/api/saip/*`. For HIL, a live APDU table fed by the
  HIL stream WebSocket.
- Top bar: build flavor, active card backend, active profile ICCID,
  connection status badge (green when the API is healthy), token
  icon in server mode.
- Status bar: last operator action, last error, runtime-root override
  state.

### 7.3 Terminal

- `xterm.js` + `xterm-addon-attach` (or the FastAPI-specific attach
  helper). Gives us copy/paste, resize, readline, colour, and works
  over a single WebSocket without reinventing the wheel.
- The sidebar exposes two PTY surfaces under **Advanced**:
  1. **Shell** (`/api/terminal/{module}`) — registered CLI module
     allow-list (`yggdrasim_common.registry.CLI_MODULES`). Default-on
     in both desktop and web-server modes. The xterm bridge spawns
     `python -m <module>` inside a forked PTY; argv is constrained
     and sandboxing relies on the module being safe to expose.
  2. **Host shell** (`/api/host-shell`) — free-form interactive
     login shell (resolved `$SHELL`, validated against
     `/etc/shells`, fallback `/bin/bash` / `/bin/sh`). Off by
     default; **opt-in via `YGGDRASIM_GUI_HOST_SHELL=1`**. The
     bearer token then grants shell-equivalent capability over the
     WebSocket — treat as RCE-class and prefer an SSH tunnel over a
     public `--web-server` bind. Companion endpoints:
     - `GET /api/host-shell/capabilities` — capability snapshot
       (`enabled`, `supported`, `shell`, `reason`). Always 200; the
       SPA hides the sidebar leaf when `enabled` is false.
     - `GET /api/host-shell/devices` — best-effort enumeration of
       `/dev/ttyUSB*` / `/dev/ttyACM*` / `/dev/ttyS*` /
       `/dev/serial/by-id/*` for the *Insert at cursor* affordance.
     - `WS  /api/host-shell` — same framing as `/api/terminal/...`
       (binary frames carry raw PTY bytes, JSON text frames carry
       `stdin` / `resize` / `signal` / `at_decode` controls).
  3. **AT decode overlay** — when the operator flips the
     `at_decode` toggle on a Host shell session, the route tee's
     the byte stream through
     `yggdrasim_common.gui_server.at_decoder` (line accumulator +
     `Tools.HilBridge.at_simlink` + `SCP03.core.utils.StatusWordTranslator`).
     Recognised `AT+CSIM=` / `AT+CRSM=` requests and `+CSIM:` /
     `+CRSM:` responses surface as `{"event": "at_decoded"}` JSON
     frames alongside the raw modem dialogue, with the SPA
     rendering them in a side panel keyed off the WebSocket. The
     overlay is additive — the xterm output is unchanged whether
     the toggle is on or off.

> **Operator guide.** Full walkthrough — enabling the env flag,
> sidebar UX, capability / device / WebSocket reference,
> `at_decoded` payload shapes, modem-CLI recipes, hardening
> checklist, troubleshooting matrix — lives in
> [`guides/GUI_HOST_SHELL_GUIDE.md`](guides/GUI_HOST_SHELL_GUIDE.md).

### 7.4 Offline posture

All frontend assets are served from `gui_server/static/` (same origin
as the API). No CDN calls, no telemetry. CSP is locked to `self`
only.

### 7.5 SAIP Decoded Editor (graduated from v1 TUI)

Status: **design reserved for v2**, no v1 TUI implementation. The v1
`saip_transcode_tui` ships with a read-only Decoded pane only; any
attempt to edit decoded fields was removed from the TUI because a
textual-framework modal cannot give the layout and validation
experience the feature needs. The full design below moves into the
GUI as the owning surface.

Goals:

- Let an operator edit decoded values of a selected Profile Element
  (PE) as an entire structured document, rather than one hex blob at
  a time.
- For filesystem PEs (`ef-*`), scope edits to the currently-selected
  EF to keep the blast radius obvious.
- For application / security-domain PEs and other non-filesystem PEs,
  offer a whole-PE form so the operator can edit every decoded field
  in that PE in one round-trip.
- Guard all enum-shaped fields with a pick-list so edits cannot fail
  due to spelling (e.g. `lowUpdateActivity` vs `LOW`).
- Never touch SAIP JSON scaffolding (`@`, `hex`, `__ygg_saip_*`
  markers) — the operator only sees the decoded nested document.

Backing helpers (already implemented in v1 and kept available for
the GUI):

- `Tools/ProfilePackage/saip_decoded_edit.py`
  - `enumerate_pe_decodable_fields(pe_value)` — walks a PE JSON value
    and returns the list of decodable fields with their editor kind
    (hand-written structured editor, roundtrip model, raw hex, or
    read-only view), target length, rel path, and decoded payload.
  - `build_pe_form_document(entries)` — assembles a nested JSON
    document that mirrors the decoded-pane layout, one entry per
    decodable field, without JSON scaffolding markers.
  - `extract_pe_form_entry_payload(document, insertion_path)` — the
    inverse: pulls the edited payload back out for re-encoding.
  - `enumerate_pe_form_unknown_paths(document, expected_paths)` —
    detects operator-added stray keys that would otherwise be
    silently dropped.
  - `format_form_path_for_display(path)` — renders an insertion path
    for error messages.
  - `get_enum_choices_for_key(key)`, `list_known_enum_payload_keys()`,
    `normalize_enum_choice_for_key(key, value)` — enum registry
    consumed by the pick-list component.
  - `build_decoded_value_editor_model` / `_roundtrip_model` /
    `_readonly_view` / `_raw_hex_model` — per-field editor model
    builders; the GUI reuses them verbatim.

REST contract (see 6.3):

- `POST /api/saip/decoded/enumerate` → returns the decodable field
  list for the targeted PE (or EF within a filesystem PE), including
  each field's editor kind and read-only flag.
- `POST /api/saip/decoded/preview` → returns the initial form
  document assembled by `build_pe_form_document`.
- `POST /api/saip/decoded/apply` → accepts the edited document, runs
  `extract_pe_form_entry_payload` per entry, re-encodes each changed
  field with the correct editor model, splices the new hex / JSON
  payloads back into the source SAIP JSON, and returns a diff plus
  the updated JSON text. Stray paths and read-only edits are
  rejected with a 409 and the offending path.
- `GET /api/saip/decoded/enums` → returns the enum registry so the
  frontend can build its pick-list without round-tripping per key.

Frontend component split:

- `SaipDecodedEditor.vue` (or `.svelte`) — owns the nested document
  view and routes each row into the correct sub-editor based on
  `editor_kind`.
- `SaipDecodedEnumPicker.vue` — pick-list keyed off the enum
  registry; triggered by clicking / tabbing into an enum field.
- `SaipDecodedServiceTable.vue` — bit-toggle grid for UST / EST /
  IST style service tables.
- `SaipDecodedRawHexField.vue` — single-line hex editor with target
  length enforcement and live length + parity hints.
- `SaipDecodedReadOnlyView.vue` — read-only rendering for fields
  that have a decoder but no safe encoder yet.

UX contract:

- Field labels and the nested layout match the Decoded pane 1:1. An
  operator should be able to glance at the read-only pane, hit
  "Edit", and see the same shape with fields now focusable.
- Enum fields render as a `<select>`-equivalent backed by the enum
  registry; free-text entry is blocked for known enum keys.
- Invalid edits are surfaced inline per-field, not in a blocking
  modal, so the operator can correct one field without losing work
  on others.
- The editor is scoped per selection: for an EF, only that EF's
  fields are editable; for an application / domain PE, every
  decodable field in that PE is editable in one form.
- JSON scaffolding is never exposed. The nested document the
  operator sees is a clean mirror of the decoded tree.

Non-goals inherited from the v1 TUI attempt:

- No attempt at a single-line "quick edit" cursor flow — the
  whole-PE / whole-EF form is the only edit path.
- No inline editing inside the Decoded pane itself. The Decoded
  pane stays a pure viewer; editing is always a deliberate opt-in
  action from the operator.

Testing strategy:

- The existing `tests/test_saip_decoded_edit.py` unit tests stay as
  the contract check for the helpers; the GUI layer adds its own
  integration tests against the four `/api/saip/decoded/*` routes.
- A Playwright / similar end-to-end test validates the round trip:
  enumerate → preview → edit one enum + one hex field → apply →
  re-enumerate → diff is exactly the two touched fields.

## 8. Mode 1: `--gui` (desktop)

### 8.1 Lifecycle

1. Parse `--gui` in `_build_cli_parser()` / `run_cli()` inside
   `main/main.py`.
2. Resolve `GuiServerConfig`:
   - host: `YGGDRASIM_GUI_HOST` or `127.0.0.1`
   - port: `YGGDRASIM_GUI_PORT` or `27853` (fallback to `0` on
     `EADDRINUSE`)
   - auth: `token` mode, token generated as a fresh 32-byte URL-safe
     random string and scoped to this process only (never persisted)
3. Start uvicorn in a background thread with the bearer middleware
   enabled.
4. Wait for the server to report `ready` via an internal
   `asyncio.Event` + health probe; fail fast with a clear message if
   readiness does not arrive within 5 seconds.
5. Launch `pywebview.create_window(...)` pointed at
   `http://<host>:<port>/?t=<token>`. The token query-string is
   stripped after the first page load and stored in sessionStorage so
   every subsequent fetch sends `Authorization: Bearer <token>`.
6. On window close, cooperatively shut down uvicorn (send
   `lifespan.shutdown`, then `Server.should_exit = True`) and return
   to the CLI.

### 8.2 pywebview integration

- `gui = webview.create_window(title="YggdraSIM", url=url, ...)`
- `webview.start(gui_starter, debug=False)` where `gui_starter` is the
  thread that started uvicorn; pywebview owns the main thread to keep
  the native event loop happy.
- Backend selection: prefer the system default
  (`edgechromium` on Windows, `cocoa` on macOS, `gtk` or `qt` on
  Linux). Fall back to the first successful backend; exit cleanly if
  none are available and point the operator at `--web-server`.

### 8.3 Security posture

- Bind only to the configured loopback host.
- Token is process-scoped, never written to disk, never logged.
- No CORS origins allowed; same-origin is enforced because the SPA is
  served by the same FastAPI app that owns the API.
- No open TCP port from the operating system's firewall perspective
  beyond what the kernel already has for loopback. The surface is
  equivalent to an IPC endpoint.

## 9. Mode 2: `--web-server` (remote lab)

### 9.1 Lifecycle

1. Parse `--web-server` plus `--host`, `--port`, `--token-file`,
   `--tls-cert`, `--tls-key`, `--allow-origin`.
2. Resolve `GuiServerConfig`:
   - host: `YGGDRASIM_GUI_SERVER_HOST` / `--host` / default `0.0.0.0`
   - port: `YGGDRASIM_GUI_SERVER_PORT` / `--port` / default `27854`
     (no ephemeral fallback; bind failure exits non-zero)
   - token: required. Read from `--token-file`, else
     `YGGDRASIM_GUI_TOKEN`, else prompted once at startup via
     `getpass.getpass`. Process refuses to start without one.
   - TLS: optional but **strongly recommended**. Accepted forms:
     - operator-provided cert/key pair via `--tls-cert` / `--tls-key`
     - self-signed on first run via `--tls-self-signed` (writes a
       one-time pair into `state/gui_tls/`). Self-signed mode prints
       a big warning and the SHA-256 fingerprint so the operator can
       pin it.
   - CORS: default deny. `--allow-origin https://host` adds an
     explicit origin. Wildcards refused.
3. Start uvicorn directly (no `pywebview`). Print the full URL,
   fingerprint (if TLS), and a one-line SSH-tunnel hint:
   `ssh -L 27854:localhost:27854 user@lab-host` for operators who
   prefer tunnelling over TLS termination.

### 9.2 Security posture

- Token auth is mandatory. Empty / default / weak tokens refused (min
  32 chars, must decode as URL-safe base64 or contain >= 128 bits of
  entropy per `yggdrasim_common.secrets_policy` — new helper).
- Bind-host `0.0.0.0` prints a banner recommending `--host 127.0.0.1`
  plus SSH tunnelling as the safer default.
- TLS or loopback-tunnel is strictly documented as required for any
  non-trusted network. The guide makes this a hard runbook prereq.
- Rate-limit bearer checks to 5 failures per minute per source IP
  using an in-process token bucket. Further failures return 429 and
  get logged to `state/gui_access.log`.
- No file-system routes allow writes outside the configured allow-
  list. Upload endpoints (profile artifacts, keybags) land in a
  configurable quarantine directory and require a second
  `POST /api/uploads/commit` that the operator must explicitly call.

### 9.3 Session semantics

- Exactly one WebSocket shell session per subsystem per token. A
  second attach either attaches read-only (if the first is still open)
  or takes over with an explicit `?takeover=1` query param. Takeover
  emits an audit log line.
- Idle disconnect after `YGGDRASIM_GUI_IDLE_SECONDS` (default 1800)
  of no WebSocket traffic. Configurable per deployment.

## 10. CLI / argparse changes

Extensions to `main/main.py::_build_cli_parser()`:

```python
def _add_gui_arguments(parser):
    """Add GUI-related argparse options. Both modes are off by default."""
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the desktop GUI (pywebview + loopback API).",
    )
    parser.add_argument(
        "--web-server",
        action="store_true",
        help="Launch the remote lab API (no pywebview).",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Override the GUI API bind host.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override the GUI API bind port.",
    )
    parser.add_argument(
        "--token-file",
        type=str,
        default=None,
        help="Path to a file containing the bearer token (required for --web-server).",
    )
    parser.add_argument(
        "--tls-cert",
        type=str,
        default=None,
        help="TLS certificate path for --web-server (PEM).",
    )
    parser.add_argument(
        "--tls-key",
        type=str,
        default=None,
        help="TLS private key path for --web-server (PEM).",
    )
    parser.add_argument(
        "--tls-self-signed",
        action="store_true",
        help="Generate a one-time self-signed TLS pair in state/gui_tls/.",
    )
    parser.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        help="Additional CORS origin for --web-server (repeatable; deny by default).",
    )
    return parser
```

`run_cli(argv)` grows a mutually-exclusive check:

```python
def _route_cli_modes(args):
    """Dispatch --gui / --web-server / legacy CLI in a single place."""
    if bool(args.gui) and bool(args.web_server):
        raise SystemExit("--gui and --web-server are mutually exclusive.")
    if bool(args.gui):
        from yggdrasim_common.gui_server.app import run_desktop
        return run_desktop(args)
    if bool(args.web_server):
        from yggdrasim_common.gui_server.app import run_web_server
        return run_web_server(args)
    return None
```

If neither flag is set, the existing CLI / menu path runs unchanged.

New env flags under `yggdrasim_common.env_flags` (category
`CATEGORY_GUI` — add new constant; `applies=APPLIES_STARTUP`):

| Flag                                   | Kind       | Default        |
| -------------------------------------- | ---------- | -------------- |
| `YGGDRASIM_GUI_HOST`                   | string     | `127.0.0.1`    |
| `YGGDRASIM_GUI_PORT`                   | int        | `27853`        |
| `YGGDRASIM_GUI_SERVER_HOST`            | string     | `0.0.0.0`      |
| `YGGDRASIM_GUI_SERVER_PORT`            | int        | `27854`        |
| `YGGDRASIM_GUI_TOKEN`                  | string     | unset          |
| `YGGDRASIM_GUI_TOKEN_FILE`             | path       | unset          |
| `YGGDRASIM_GUI_TLS_CERT`               | path       | unset          |
| `YGGDRASIM_GUI_TLS_KEY`                | path       | unset          |
| `YGGDRASIM_GUI_ALLOW_ORIGIN`           | string     | unset (deny)   |
| `YGGDRASIM_GUI_IDLE_SECONDS`           | int        | `1800`         |
| `YGGDRASIM_GUI_PATH_ALLOWLIST`         | string (:) | runtime_root   |
| `YGGDRASIM_GUI_WEBVIEW_DEBUG`          | bool       | `0`            |

## 11. Packaging / dependency impact

New optional extras in `pyproject.toml`:

```
[project.optional-dependencies]
gui = [
    "fastapi>=0.110,<1.0",
    "uvicorn[standard]>=0.27,<1.0",
    "pywebview>=5.0,<6.0",
    "websockets>=12.0,<14.0",
    "itsdangerous>=2.1,<3.0",
]
gui-server = [
    "fastapi>=0.110,<1.0",
    "uvicorn[standard]>=0.27,<1.0",
    "websockets>=12.0,<14.0",
    "itsdangerous>=2.1,<3.0",
]
```

- `gui` pulls `pywebview`; `gui-server` intentionally does not, so a
  headless lab server never needs GTK / Qt / WebKit on the host.
- `full` gains `fastapi`, `uvicorn`, `pywebview`, `websockets` so the
  HIL-capable Linux bundle covers both modes.
- `clean` does **not** pull `pywebview` by default; operators who want
  the desktop GUI install `yggdrasim[gui]` explicitly. The launcher
  detects the absence and shows a clear "install `yggdrasim[gui]` to
  enable --gui" message.
- PyInstaller:
  - add a hook (`scripts/pyinstaller/hook-yggdrasim_gui.py`) that
    bundles the frontend static assets under
    `gui_server/static/` plus the OS-native pywebview backend
    (`webview.platforms.*`).
  - builds stay per-flavor: `clean` omits GUI, `full` includes it on
    Linux x86_64 / Pi, Windows / macOS builds get the desktop GUI but
    skip HIL.
- Docker: the existing `Dockerfile` gains a `--build-arg YGGDRASIM_GUI=1`
  flag that installs `yggdrasim[gui-server]` and exposes port 27854.
  Base image stays unchanged otherwise.
- Frontend build: add `gui_frontend/` with `package.json`, `vite.config.ts`,
  `src/`. `npm run build` emits `gui_frontend/dist/` and a maintainer
  script (`scripts/build_gui_frontend.sh`) copies `dist/` into
  `yggdrasim_common/gui_server/static/` as part of the release
  workflow. `.gitignore` excludes `gui_frontend/node_modules/` and
  `gui_frontend/dist/`; the committed static bundle lives under
  `yggdrasim_common/gui_server/static/` so the wheel ships it without a
  build step on operator machines.

## 12. Doctor and observability integration

`yggdrasim_common.doctor` gains a `_probe_gui_stack` function that:

- Reports `ok` if `fastapi`, `uvicorn`, `websockets` import cleanly and
  at least one `pywebview` backend reports available (desktop-capable
  hosts).
- Reports `info` if only `gui-server` deps are present (headless lab
  server).
- Reports `warn` if the configured GUI port is already in use at probe
  time.
- Reports `fail` if `YGGDRASIM_GUI_TLS_CERT` is set but unreadable.

Access log:

- Every API request gets a structured log line via
  `logging.getLogger("yggdrasim.gui")`:
  `ts=... method=GET path=/api/health status=200 token_id=<first8> ms=3.2`.
- `token_id` is `hashlib.sha256(token).hexdigest()[:8]`. The raw
  token never appears in any log line.
- WebSocket connect / disconnect emits a single line each.

## 13. Testing strategy

Unit tests (no network, no pywebview):

- `tests/test_gui_config.py` — host / port / token / TLS arg parsing,
  env-flag overlay, mutually-exclusive `--gui` / `--web-server`.
- `tests/test_gui_auth.py` — bearer middleware accepts correct token,
  rejects others, constant-time compare used, rate-limit triggers at
  the correct threshold.
- `tests/test_gui_routes_health.py` — health/registry/backend routes
  against a `TestClient` with the engine mocked at the registry
  layer.
- `tests/test_gui_routes_hil.py` — HIL start / stop / status routes
  against a stubbed `hil_bridge_runtime`; validates that the GUI
  endpoints only call the existing helpers.
- `tests/test_gui_shell_session.py` — shell WebSocket echoes stdin /
  stdout through a fake `cmd2` shell instance; verifies framing,
  exit, and takeover semantics.
- `tests/test_gui_port_fallback.py` — pre-bind `27853`, assert desktop
  mode falls back to a fresh port; pre-bind `27854`, assert server
  mode exits non-zero with a clear error.

Integration tests (Linux only, skipped elsewhere):

- `tests/test_gui_desktop_smoke.py` — start desktop mode in
  `pywebview.start(gui=..., private_mode=True, debug=False)`, hit
  `/api/health`, assert 200, quit cleanly. Skipped when
  `webview.platforms.any_available()` is False.
- `tests/test_gui_server_tls.py` — start server mode with
  `--tls-self-signed`, verify TLS handshake completes with the
  printed fingerprint, verify unauthenticated request returns 401.

All pytest invocations follow the workspace rules: single-file scope,
`-q --tb=short --disable-warnings --no-header --maxfail=1`, 90 s
timeout ceiling.

## 14. Documentation surface

New guides under `guides/`:

- `guides/GUI_OVERVIEW.md` — user-facing concepts, mode comparison,
  screenshot tour.
- `guides/GUI_DESKTOP.md` — `--gui` flow, pywebview backends, common
  failure modes.
- `guides/GUI_REMOTE_SERVER.md` — `--web-server` flow, token
  management, TLS / SSH-tunnel recipes, access-log format.
- `guides/GUI_DEVELOPMENT.md` — how to rebuild the frontend bundle,
  how to add a new subsystem view, how the registry plus REST map.

Updates to existing guides:

- `README.md` — one paragraph + link to `guides/GUI_OVERVIEW.md`.
- `guides/ARCHITECTURE.md` — add the FastAPI + frontend layer to the
  diagram.
- `guides/INSTALL_CLEAN.md` / `INSTALL_FULL.md` — note the `[gui]` /
  `[gui-server]` extras and show the minimal install.
- `guides/BUILD_AND_PACKAGING.md` — document the frontend build step
  inside the release procedure.
- `site-docs/reference/runtime-root.md` — list the new `YGGDRASIM_GUI_*`
  flags.

## 15. Phased delivery

Phase A — API scaffolding, no UI. **[landed]**

1. Add `yggdrasim_common/gui_server/` with health / registry / backend
   routes and pydantic models.
2. Wire `--gui` / `--web-server` parse path in `main/main.py`; both
   print a "GUI backend not yet implemented" banner and exit cleanly.
3. Add env-flag registry rows under a new `CATEGORY_GUI` constant.
4. Add unit tests for config + auth + health routes.
5. Document the API contract in `guides/GUI_DEVELOPMENT.md`.

Phase B — Desktop mode end-to-end. **[landed]**

1. Ship the minimal SPA (subsystem rail, backend selector, health
   badge) under `gui_frontend/` + built bundle in
   `yggdrasim_common/gui_server/static/`.
2. Implement `run_desktop(args)` — uvicorn in a thread, `pywebview`
   on the main thread, graceful shutdown.
3. Add desktop smoke test.
4. Ship `guides/GUI_DESKTOP.md`.

Milestone B-1 — Engine panels (pure functions). **[landed]**

1. Implement `/api/tools/*` router wrapping the 6 existing helpers:
   TLV parse, SW translate, EUICCInfo2 decode, SAIP lint (editor JSON
   path), eIM package lint, GSMA result-code table.
2. Surface each in the SPA as a dedicated sidebar entry under "Engine
   panels".
3. Narrow test file (`tests/test_gui_tools.py`) gated on
   `pytest.importorskip("fastapi")`.

Milestone B-2 — Interactive shell terminal. **[landed]**

1. `yggdrasim_common/gui_server/terminal.py` — POSIX PTY session with
   async read/write, SIGTERM/SIGKILL escalation, TIOCSWINSZ bridging.
2. `routes/terminal.py` — WebSocket at `/api/terminal/{module}` with
   explicit bearer-token check (BaseHTTPMiddleware does not see WS
   scope) and a CLI-module allow-list sourced from
   `yggdrasim_common.registry.CLI_MODULES`.
3. Vendor xterm.js 5.3.0 + xterm-addon-fit 0.8.0 under
   `static/vendor/xterm/` with a NOTICE file so the CSP stays strict
   `script-src 'self'`.
4. "Shell terminal" SPA panel with module picker, live output, and
   resize-on-window-resize.

Milestone B-3 — Live orchestration. **[landed]**

1. `routes/live.py` — `/api/live/readers` and `/api/live/atr` wrap
   `smartcard.System.readers()` with graceful fallback when pyscard
   is missing.
2. `/api/flows/download-profile` WebSocket spawns the existing
   `SGP22Orchestrator.run_flow` on a background thread and tees
   stdout/stderr into JSON-framed events (`info` / `warn` / `error` /
   `done`).
3. SPA "Download profile" wizard (reader picker + activation code +
   optional dry-run) streams the event log into a level-styled pane
   that auto-scrolls.
4. `tests/test_gui_live.py` — pyscard is stubbed in-process so the
   reader route is exercisable without hardware.

Phase C — Command Center + remaining integrations. **[in-progress]**

1. Command Center action framework. **[landed]**
   * Typed `ActionSpec` / `ActionField` registry
     (`yggdrasim_common/gui_server/actions/`).
   * HTTP routes `GET /api/actions`, `POST /api/actions/{id}/run`,
     `WS /api/actions/{id}/stream`.
   * Thread-safe in-process card-session manager
     (`yggdrasim_common/gui_server/sessions.py`) with idle-reaper and
     LRU-style eviction. Lists/closes at `/api/sessions`.
2. Flagship actions (B-3 retrofit to task-oriented surface). **[landed]**
   * `scp03.scan` → live file-system walk, structured tree + session id.
     Requires a minor `FileSystemController.scan_tree(return_tree=True)`
     opt-in (default-False kwarg; CLI path is byte-identical).
   * `scp03.read_selected` → SELECT + FCP + READ BINARY / READ RECORD,
     keyed by the session id returned from `scp03.scan`.
   * `scp11.download_profile` → form-schema only; streaming delegates to
     the existing `/api/flows/download-profile` WS from B-3.
   * `eim_local.poll_campaign` → streaming dispatcher wrapping
     `EimLocalSession.poll_hotfolder_campaign`; final event carries the
     full structured report for the UI summary table.
3. Command Center SPA surface. **[landed]**
   * Dedicated left-nav group rendered from the live catalogue.
   * Per-subsystem action cards with auto-rendered forms, typed inputs
     (reader / hex / int / bool / enum / text), run / start buttons, and
     per-card status pill.
   * Purpose-built result renderers: scan-tree + click-to-read (FCP +
     hex dump + ASCII panel), JSON / hex fallback, structured log-stream
     with level-coloured rows, report-summary table.
4. Command Center action breadth (second slice). **[landed]**
   * **Engine-tool actions** (pure-function, no hardware):
     `tool.tlv.decode`, `tool.sw.lookup`, `tool.euicc_info2.decode`,
     `tool.saip.lint`, `tool.eim.lint`, `tool.gsma.codes`. Each wraps the
     same helpers that back `/api/tools/*` so there is one authoritative
     implementation per task.
   * **Session-based SCP03 extensions**: `scp03.select` (free-form
     SELECT without reading), `scp03.list_apps` (EF.DIR application
     dump), `scp03.close_session` (explicit teardown).
   * **eim_local helpers**: `eim_local.list_fixtures` (fixed fixture
     enumeration), `eim_local.hotfolder_metadata` (queue depth + next
     package + response-meta snapshot), `eim_local.issue_package`
     (single-shot issue of the next queued package).
   * **Purpose-built result renderers**: `tlv_tree` (collapsible BER-TLV
     tree), `findings` (severity-pilled SAIP lint findings with path
     and recommendation), `key_value_lines` (indented label / value for
     EUICCInfo2 detail + validation).
5. Command Center action breadth (third slice — SCP11 live + HIL). **[landed]**
   * **SCP11 live read-only actions** (no session persistence: each
     action opens a short-lived PC/SC channel, runs through
     `SGP22Orchestrator`, and disconnects in a `finally` block):
     `scp11_live.get_eid` (ECASD tag 5A → BCD / stripped), `scp11_live.list_profiles`
     (BF2D00 → ICCID / state / class / nickname table), `scp11_live.get_smdp`
     (BF3C00 → default SM-DP+ / SM-DS address + OID lines),
     `scp11_live.list_notifications` (BF2800 → pending notification queue),
     `scp11_live.euicc_info2` (BF2200 → shared detail-lines renderer; complements
     the offline `tool.euicc_info2.decode` which accepts pasted hex).
     TLV decoding is shared with `SCP03.core.utils.TlvParser`; the
     profile-row decoder is ported from `SCP11/live/console.py` so the
     live action surface matches the interactive shell byte-for-byte.
   * **HIL bridge surfaces** (read-only; supervisor process is still
     launched out of band via systemd / setup wizard): `hil.supervisor_status`
     (snapshot of `runtime/state/hil_bridge_supervisor.json` → key/value lines),
     `hil.bridge_status` (HTTP probe of the relay status URL published in
     `hil_bridge_card_relay.json`), `hil.watch_supervisor` (streaming:
     polls the supervisor state at a fixed cadence and emits one diff
     event per cycle; the interactive UI can show the bridge coming
     up / dropping out without reloading the page).
   * **Pre-existing bug fix**: the `scp11.download_profile` flow was
     calling non-existent `card_backend.connect_card_backend` /
     `SCP11.live.config.ensure_live_config`. Replaced with direct
     `PcscApduChannel(reader_index=…)` + `dataclasses.replace(SGPConfig(), READER_INDEX=…)`;
     the flow now actually runs when invoked from the Command Center.
   * **Tests**: `TestHilSupervisorHelpers`, `TestHilDispatchers`,
     `TestHilWatchSupervisorStream` and `TestScp11LiveDecoders`/`TestScp11LiveRegistration`
     in `tests/test_gui_actions.py` cover the pure helpers,
     dispatcher shapes, and streaming-event sequencing. No hardware
     needed — the supervisor snapshot and relay HTTP probe are
     `monkeypatch`-injected.
6. SCP03 Workbench — layout (G slices). **[landed]**
   * **G-1**: workbench shell with reader pane, status bar, bottom log
     dock, and per-tab event-bus wired against `/api/readers`.
   * **G-2**: ribbon-grouped action bar replacing the inline action
     cards inside each SCP03 tab; dispatchers + `scp03.*` ids unchanged.
   * **G-3**: scan-tree breadcrumb + reader-pane context menu; double
     click on a reader opens a new SCP03 tab against that reader.
   * **G-4**: APDU trace piped into the bottom-log "APDU" tab via the
     `scp11_live.*` trace sinks; visual in-flight state for ribbon
     actions.
7. SAIP Workbench (SA slices). **[SA-1..SA-4 landed; SA-G1..SA-G6 landed; SA-D1..SA-D2 landed]**
   * **SA-1 (backend, read-only)**: `saip.open_package` /
     `saip.list_pes` / `saip.show_pe` / `saip.list_files` /
     `saip.show_file` / `saip.validate` / `saip.close_package`. Stateful
     SAIP package sessions live alongside SCP03 sessions in the same
     `SessionManager`.
   * **SA-2 (frontend shell)**: package drawer + numbered PE list +
     main-area tabs + bottom validation dock.
   * **SA-3 (editor + save)**: `saip.update_file_field` + `saip.save_package`
     with dirty-state tracking per PE and a dirty-list (`saip.get_dirty`)
     for the unsaved-changes gate on close. `saip.revert_changes`
     restores to the on-disk baseline per PE.
   * **SA-4 (compare + variables)**: `saip.compare` over two package
     sessions (PE / FS / field-level diff); `saip.list_variables` +
     `saip.set_variable` for the placeholder editor backed by
     `saip_profile_template.py`.
   * **SA-G1 (layout shell rework — Comprion-inspired)**: ribbon
     command bar above the workbench (Profile Package / Profile
     Element / File System / Variables / Validation / Help groups);
     three sibling top-level tabs (`Profile Elements` / `File System`
     / `Applications`) replace the old in-pane "PEs | Files |
     Variables" sub-tab strip; the Variable editor moves into a
     ribbon-launched modal; Applications tab ships as a derived
     placeholder until SA-G4 lands the dedicated `saip.list_applications`
     dispatcher. Pure layout slice — every existing SAIP backend
     action is unchanged and every existing renderer (`renderSaipPeList`,
     `renderSaipDetail`, `renderSaipFileDetail`, `renderSaipVariablesPane`,
     `renderSaipCompareDetail`, `renderSaipValidation`) is reused
     verbatim under the new shell.
   * **SA-G2 (typed PE editors — read-only first cut)**: PE list
     replaces the 6-column table with a vertical card list (icon /
     friendly name / type sub-label / FS·APP·dirty chips /
     identification badge); icon glyphs are colour-coded per PE
     family (template / domain / security / auth / file-system /
     remote / metadata / access / app / default) so a 50-PE
     package is scannable at a glance. The detail view gains a
     `PE-<Type> Editor` tab as the new default, with `ASN.1 Value
     Notation` and `JSON tree` riding along as alternates. Six
     typed editors land in this slice — Profile Header, USIM /
     ISIM / CSIM (incl. their OPT-* siblings), SecurityDomain
     family (incl. MNO-SD / SSD), PIN/PUK Codes, AKA Parameter,
     Generic File Management — each rendering as a stack of
     `.saip-edit-card` blocks (Header → type-specific cards). Any
     unsupported PE type falls through to a typed `Untyped`
     fallback that points the operator at the JSON tree / value
     notation tabs. Editors are read-only in SA-G2; write hooks
     route through the existing
     `saip.update_file_field` / `saip.apply_decoded_edit` actions
     in a follow-up slice.
   * **SA-G3 (File System hierarchical tree + General/Data/Access
     sub-tabs — read-only first cut)**: the flat 3-column file
     table is replaced with a hierarchical tree (sections like
     `MF` / `DF.TELECOM` / `ADF.USIM` / `ADF.OPT-USIM` / `DF.GSM-
     ACCESS` at depth 0; container rows like `mf` / `df-*` /
     `adf-*` at depth 1; EFs under their nearest container at
     depth 2) with caret-based expand/collapse memory on
     `pkg.fileTreeCollapsed`. The file detail gains three sub-tabs:
     `General` (the existing FCP-metadata table + decoded-edit
     panel, unchanged), `Data` (a hex dump reconstructed from the
     file's `fillFileOffset` / `fillFileContent` choice list with
     `--` placeholders for issuer-personalised gaps), and
     `Access rules` (TLV breakdown of `securityAttributesReferenced`
     into ARR FID + record number for the canonical 1-byte and
     3-byte forms, falling back to a raw-bytes view for
     unrecognised payloads). All read-only in this slice — typed
     ARR / record write-back lands in a follow-up.
   * **SA-G4 (Applications backend + tab body)**: a new
     `saip.list_applications` action enumerates every
     application-instance-bearing PE — Security Domains
     (`securityDomain`), MNO-SDs (`mnoSD` / `mno-sd`), Supplementary
     SDs (`ssd`), JavaCard applications (`application`), and the
     remote management surfaces (`rfm` / `ram`). Each row carries
     the GP install bookkeeping (Instance / Class / Load Package
     AIDs), the decoded `applicationPrivileges` flag list (per GP
     Card Spec 2.3 §6 Table 6-1, all 20 known bits), the decoded
     lifecycle state (per GP §11.1.1, dual SD / Application
     tables), the `applicationSpecificParametersC9` blob, the
     nested `applicationParameters` slots, the RFM / RAM TAR list
     (per ETSI TS 102 226 §5.1.1), and the `keyList` size. The
     Applications tab body is rebuilt around this payload —
     placeholder PE-row table is replaced with a card list, one
     card per application, with a colour-coded lifecycle chip
     (PERSONALIZED / INSTALLED / SELECTABLE / LOCKED), a
     `Privileges (N)` chip strip, an AID block, an RFM/RAM TAR
     chip strip, and a footer with the key count + C9 hex + app
     parameter slot count. Read-only in this slice — typed
     application-edit hooks land later.
   * **SA-G5 (validation bottom dock with click-to-jump)**: the
     existing validation surface is restructured as a
     collapsible bottom dock — header (always visible) carries the
     score, four severity summary chips, Validate / Re-validate +
     strict toggle controls; body (visible when expanded) carries
     four severity filter pills (FAIL / WARN / INFO / PASS — PASS
     hidden by default since operators usually want to see what's
     wrong, not what's right) and a findings table with a per-row
     Jump column. Backend `_dispatch_validate` enriches each
     finding with optional `pe_index` / `section_key` /
     `field_path` keys whenever the linter's `path` string
     resolves to a known PE / file in the loaded package
     (`<section>` / `<section>.<field>` / `<section>::<field>`
     forms — `service:` rollups + document-level paths stay
     unrouted by design). The Jump button routes to either the
     Profile Elements tab (PE jumps) or the File System tab (file
     jumps) using the existing `saipLoadShowPe` / `saipLoadShowFile`
     pipelines, expanding any collapsed parent containers along the
     way so the target stays visible. Auto-validate on first paint
     + after edits via `pkg.valAutoRunPending` so the dock stays
     honest with the package's current state.
   * **SA-G6 (Variable editor polish + ribbon keyboard shortcuts)**:
     a new `saip.reset_variable` backend action enables per-row
     rollback of a single placeholder override (re-loads the source
     document, drops the named override from the session, replays
     every other override that was still in effect — a per-variable
     analogue of `saip.revert_changes`). The variable editor modal
     is rebuilt around this: header carries an override-count chip
     + style chip + total-count chip and a "Reset all (N)" button
     that chains `reset_variable` calls sequentially through the
     queued overrides; the variables table gains a Kind column with
     family-coloured chips (ICCID / IMSI / hex / bcd / text), a
     State column with composable chips (override / defined / used)
     and an Actions column with a per-row Reset button when an
     override is currently applied; the form below uses a
     `<datalist>` for placeholder-name autocomplete + auto-fills
     the value box when the operator picks an existing override
     from the dropdown, submits on Enter, and shows a quick hint
     about the keyboard shortcuts. Ribbon shortcuts: a single
     document-level capture-phase keydown listener (installed once
     via `installSaipKeyboardShortcuts`) routes Ctrl/Cmd+O to focus
     the Open path input, Ctrl/Cmd+S to focus the Save destination
     input, Ctrl/Cmd+E to open the Variable editor modal,
     Ctrl/Cmd+Shift+V to run the linter, Ctrl/Cmd+. to toggle the
     validation dock collapse, and Esc to close the variable
     modal. Shortcuts only fire while the SAIP view is the active
     workbench (DOM check on `section.view-active .saip-workbench`)
     so they don't interfere with sibling workbenches. Ribbon
     button tooltips updated with the bound shortcut hints.
   * **SA-D1 (Semantic profile-diff engine)**: a new
     `Tools/ProfilePackage/saip_profile_diff.py` layers
     context-aware classification on top of the pre-existing
     structural walker in `saip_diff_engine`. Each
     `DiffEntry` is mapped to a `ProfileDiffEntry` with one of
     ten categories (`identity` / `pe_sequence` / `files` /
     `applications` / `security` / `lifecycle` / `variables` /
     `structure` / `intro` / `other`), one of four severities
     (`critical` / `warning` / `info` / `note`), a section_key
     + friendly section_label sourced from a curated
     `_SECTION_LABELS` map (USIM Application / DF.TELECOM /
     Security Domain / RFM / RAM / etc.), and a one-line
     human-readable summary built by `_format_summary`.
     Identity leaves (ICCID / IMSI / IMPI / EID / MCC / MNC /
     MSISDN / SPN / profile_name) and security leaves (Ki / OPc
     / KIC / KID / KIK / SCP02/03/11 keysets / PUK / PIN ADM /
     PPR1) are matched case-insensitively and lifted to
     `critical`; AID rotations under USIM / ISIM / CSIM PEs lift
     to `applications` / `critical`; `akaParameter` / `5gAuthParameter`
     / `cdmaParameter` PEs default to `security` / `critical`
     even when the leaf name is generic. PE-sequence
     additions are `warning`; PE-sequence removals are
     `critical` (semantic loss). Output is a
     `ProfileDiffReport` with `entries`, `counts_by_category`,
     `counts_by_severity`, the original `structural_summary`
     pass-through, and `section_reorder_a` / `_b` tuples when
     the top-level dict ordering differs. `to_dict()` emits a
     JSON-friendly payload (bytes are encoded as
     `{"__hex__": "...", "length": N}` envelopes). Plain-text
     renderer (`format_profile_diff_text`) groups entries by
     severity for terminal / test / CI use. Coverage:
     `tests/test_saip_profile_diff_engine.py` (24 cases —
     identity / security / PE sequence / files / applications /
     intro+variables / sorting / filter / serialisation / type
     guards). The engine has zero GUI dependency and is
     reusable from CLI tools or future SA-D3 frontend.
   * **SA-D2 (Semantic-diff dispatchers)**: three new actions
     hang off the SA-D1 engine. `saip.diff_packages` —
     diffs two open sessions; same input shape as the legacy
     `saip.compare` (left in place for back-compat) but
     returns the categorised `ProfileDiffReport` payload.
     `saip.diff_against_source` — single `session_id` input;
     re-loads the on-disk source via `_load_package_from_path`
     (so unsaved edits + applied overrides on the live session
     surface as the right side) and runs the engine. Banner
     labels are `"<filename> (on disk)"` / `"<filename>
     (session edits)"` so the operator never has to guess
     direction. `saip.diff_against_path` — `(session_id, path)`
     input; loads any DER / hex-text / JSON the
     `_load_package_from_path` ingestor handles and diffs the
     session against it. All three jsonify the decoded
     document via `saip_json_codec.jsonify_document` before
     handing it to the engine, so shape parity is automatic.
     Total SAIP inventory now 23 actions (was 20 after SA-G6).
     Coverage: `tests/test_gui_saip_diff.py` (19 cases —
     argument validation, two-pristine-sessions empty-report
     contract, `set_variable` lands as `variables` (not
     identity — the override stamps `__ygg_token_defs__`,
     resolution happens at encode time), direct decoded-document
     mutation lands as `pe_sequence`, `diff_against_source`
     handle-without-source-path guard, `diff_against_path`
     missing-path / nonexistent-path guards, spec
     registration). SA-D3 (Frontend ribbon Compare button +
     modal + results pane) is the next slice — pending operator
     sign-off on this phase.
8. SCP03 module-parity slices (C slices) — port the Scp03Shell
   command surface onto the workbench so daily card workflows no
   longer need the raw terminal. **[landed]**
   * **C-1 — Read-only card telemetry (8 actions)**: `scp03.atr`,
     `scp03.card_info`, `scp03.reset`, `scp03.decode`, `scp03.read_binary`,
     `scp03.read_record`, `scp03.arr`, `scp03.dump_fs`. Mirrors the
     shell's INFO / ATR / DECODE / READ-BINARY / READ-RECORD / ARR /
     DUMP-FS commands. `dump_fs` writes into a folder picked via the
     pywebview directory dialog.
   * **C-2 — Auth + GP registry + profile telemetry (10 actions)**:
     `scp03.auth_scp03` / `scp03.auth_scp02` / `scp03.logout` /
     `scp03.keys`; `scp03.registry_apps` / `scp03.registry_pkgs` /
     `scp03.registry_sd` / `scp03.get_data` / `scp03.list_aids`;
     `scp03.list_profiles` / `scp03.profile_scan`. The
     `GlobalPlatformManager` is lazily built per session and cached on
     `session.handle["gp"]`; key material is read from the inventory
     (`scp03_config` module-state) on first build.
   * **C-3 — Mutation + validation + exports (11 actions)**:
     `scp03.set_status` / `scp03.lock` / `scp03.unlock` /
     `scp03.delete` / `scp03.store_data`; `scp03.update_binary` /
     `scp03.update_record`; `scp03.validate` / `scp03.cert_info`;
     `scp03.export_euicc` / `scp03.export_keybag`. All mutations check
     `_require_auth_session` and surface a destructive banner on the
     UI; `delete` adds a typed-back confirmation field.
   * **C-4 — eUICC telemetry, lifecycle, snapshots, crypto, admin
     (16 actions)**:
     - **eUICC**: `scp03.get_eid` / `scp03.get_euicc_certs` /
       `scp03.get_euicc_configured_data` / `scp03.get_sgp32_all_data`;
       `scp03.enable_profile` / `scp03.disable_profile` /
       `scp03.delete_profile` (typed-back confirm).
     - **Snapshots / gold profile**: `scp03.set_gold_profile` /
       `scp03.show_gold_profile` / `scp03.clear_gold_profile` /
       `scp03.profile_diff`. Persistence reuses the inventory
       `scp03_config` module-state, so the shell's GOLD-PROFILE
       wizard and the GUI read the same baseline. Diff scope is
       eUICC-only in this first pass; combined-scope (FS + MNO-SD)
       is deferred until the shell helpers can be lifted out
       standalone.
     - **Crypto (offline, no card)**: `scp03.derive_opc` /
       `scp03.run_auth_test_vector`. The latter compares the
       3GPP TS 35.207 Milenage vector against derived OPc / RES /
       CK / IK / Kc / AUTN / USIM-AUTH-APDU / USIM-AUTH-RESPONSE.
     - **Tier-3 admin (offline, no card)**: `scp03.show_config`
       (KEYS + GOLD_PROFILE + AID registry, with `mask_secrets`
       toggle), `scp03.set_aid_alias` (add / update / delete in
       aid.txt), `scp03.set_defaults` (RESET-confirmed key wipe;
       invalidates cached GP managers on live SCP03 sessions).
   * **Native pickers**: fields with `kind="path"`, `"directory"`,
     `"save_path"` open the matching pywebview dialog
     (`window.pywebview.api.pick_file` / `pick_folder` /
     `save_file`) on Browse… click or input double-click. The
     backend treats all three as plain strings via `coerce_input`.
   * **C-5 — Mutation depth (16 actions)**: `scp03.put_key`;
     `scp03.install_cap` / `install_app` / `install_make_selectable` /
     `install_extradition` / `install_personalization` /
     `install_registry_update`; `scp03.fs_create_file` /
     `fs_delete_file` / `fs_resize` / `fs_lifecycle` /
     `fs_search_record` / `fs_suspend_uicc`; `scp03.manage_pin` /
     `manage_channel`; `scp03.run_auth_live`. Added three new ribbon
     groups ("Install", "FS-Admin", "Live AAA") with typed-back
     confirmations on every destructive path. `scp03BuildInlineForm`
     was extended to support `"select"` / `"bool"` / `"textarea"` /
     `"number"` field kinds so each action can be rendered with a
     single form helper. Guard coverage: 20 in-process HTTP smoke
     cases, all passing.
   * **C-6 — Sub-shell handoffs (2 shortcuts)**: `scp03.stk_shell`
     and `scp03.ota_shell` ribbon buttons under a new "Sub-shells"
     group reuse the B-2 PTY bridge: they switch to the Terminal
     view, pre-select the right module in `#terminal-module`, and
     (for STK) inject `STK-SHELL\r` into the PTY once the child's
     "spawned" event arrives. No backend action; the terminal bridge
     only accepts modules listed in
     `yggdrasim_common.registry.CLI_MODULES`. Full per-tab embedded
     xterm terminals remain deferred.
   * **C-7 — Quality of life + adjacent (7 actions)**: SCP03 side —
     `scp03.run_script` (file or inline commands driven through
     `entry_cmd`), `scp03.fs_report` (YAML deep-scan via
     `FileSystemController.generate_report`), `scp03.guide_list` and
     `scp03.guide_show` (captured rendering of the ShellGuides
     topics without the interactive prompt). SIMCARD-adjacent side —
     `simcard.quirks_status`, `simcard.profile_store_list`,
     `simcard.euicc_store_list`, `simcard.tuak_derive_topc` (a new
     `SIMCARD` subsystem surfaced in the left-nav automatically).
     Guard coverage: 15 in-process smoke cases, all passing.
9. Remaining CLI shells (SCP11 test/relay/local_access, SCP80) through
   the terminal bridge from B-2 and progressively as first-class
   Command Center actions. SCP11 live is fully wrapped (38 actions);
   SCP11 relay is a pure re-export of `SCP11Console` so live wraps
   apply directly. SCP11 local_access (the offline SM-DP+ flow) is
   the next subsystem-tab candidate.
10. HIL live APDU stream view (tshark + GSMTAP → SAIP decode pipeline —
    still deferred; the `hil.watch_supervisor` stream covers the
    operator-level situational awareness in the interim).
11. SAIP Decoded Editor per 7.5 (nested form, enum pick-list,
    service-table grid, raw-hex field). The SA-1..SA-4 slices land the
    package-level editor; the per-record decoded form-builder remains
    deferred (it sits on top of `Tools/ProfilePackage/saip_decoded_edit.py`).
12. Integration tests for each.

Phase D — Remote lab mode.

1. Implement `run_web_server(args)` with token enforcement, TLS
   loader, rate-limiter, access log.
2. Self-signed TLS helper under `state/gui_tls/` with fingerprint
   print-out.
3. Tests for token / TLS / rate-limit.
4. Ship `guides/GUI_REMOTE_SERVER.md`.

Phase E — Packaging and doctor polish.

1. PyInstaller hook for the desktop flavor.
2. Docker build-arg for the server flavor.
3. Doctor probe `_probe_gui_stack`.
4. Final documentation pass + `mkdocs build --strict` verification.

## 16. Acceptance criteria

1. `python main/main.py --gui` opens a native window without touching
   the system browser, with no port visible outside loopback.
2. `python main/main.py --web-server --token-file ./tok` refuses to
   start without a strong token, honours `--tls-cert` / `--tls-key`,
   and never exposes the token in logs.
3. `python main/main.py` (no flags) behaves identically to today.
4. Ports `4729 / 8080 / 9997 / 15353 / 18443 / 19443 / 44215` remain
   free after the GUI is up in either mode; the GUI never binds a
   port below `1024` or inside the existing modules' claimed set.
5. `pip install yggdrasim` (no extras) keeps working and the CLI does
   not import `fastapi`, `uvicorn`, or `pywebview` at module load
   time. The imports are deferred to `run_desktop` / `run_web_server`.
6. `yggdrasim --doctor` reports the GUI stack state accurately in both
   installed and uninstalled shapes.
7. All existing tests remain green. The new GUI test files pass in
   isolation under the workspace 90 s / narrow-scope pytest policy.
8. The frontend bundle shipped inside the wheel is byte-reproducible
   from `gui_frontend/` via the documented `npm ci && npm run build`
   recipe.
9. `mkdocs build --strict` passes with the new guides in the nav.
10. The Linux x86_64 `full` PyInstaller bundle launches `--gui` on a
    stock Ubuntu 22.04 host without extra GTK / QT packages beyond
    what PyWebView auto-pulls via `python3-gi` / `python3-webkit2`.

## 17. Risks and mitigations

- **Risk**: pywebview backend parity across OSes (WebKitGTK on Linux
  versus Edge on Windows versus WKWebView on macOS). Some CSS / JS
  features differ.
  - **Mitigation**: target ES2020 + evergreen CSS, validate the SPA in
    all three WebView engines during Phase B, document minimum OS
    levels in `guides/GUI_DESKTOP.md`.
- **Risk**: uvicorn in a background thread plus pywebview event loop
  can deadlock on shutdown if the API is holding a blocking call.
  - **Mitigation**: every blocking engine call has a per-request
    timeout (configurable, default 60 s) and runs inside
    `asyncio.to_thread`; the shutdown path cancels the threadpool
    before it calls `Server.should_exit`.
- **Risk**: bearer-token leakage via logs or referer headers.
  - **Mitigation**: log only `token_id` (first 8 chars of SHA-256),
    strip the `t=` query string in the frontend bootstrap before the
    first navigation event, set `Referrer-Policy: no-referrer` on all
    responses.
- **Risk**: remote surface exploited against an operator lab.
  - **Mitigation**: `--web-server` requires an explicit opt-in flag, a
    strong token, and documents TLS / SSH-tunnel as non-optional for
    any untrusted network; default host is documented but the guide
    recommends `127.0.0.1 + SSH tunnel`.
- **Risk**: PyInstaller bundle bloat.
  - **Mitigation**: build the SPA once, ship the static bundle only;
    pywebview itself is small; fastapi / uvicorn add ~5 MB. Verify
    the delta stays under 20 MB against the current `full` bundle
    size before Phase E ships.
- **Risk**: accidental port collision with a future subsystem.
  - **Mitigation**: register `27853 / 27854` in `guides/ARCHITECTURE.md`
    under a "loopback port map" section so it becomes a documented
    reservation that future subsystems are expected to respect.

## 18. Open questions

- Final frontend framework (Vue 3 vs Svelte). Both acceptable; Vue 3
  has the broader hiring pool, Svelte has the smaller bundle. Decide
  during Phase A prototype.
- Whether to co-opt an existing xterm.js-over-FastAPI wrapper (there
  are several MIT-licensed ones) or write a minimal adapter against
  our shell protocol. Leaning minimal adapter — the protocol is
  narrow enough that a third-party wrapper is not obviously a win.
- Whether `--web-server` should default to `127.0.0.1` rather than
  `0.0.0.0`. Arguments both ways: `127.0.0.1` is safer out of the box
  and forces the operator to think about their tunnel; `0.0.0.0` is
  what lab operators will want 80 % of the time. Current draft
  defaults to `0.0.0.0` with a banner. Open for review.
- Whether to support a third mode, `--gui --web-server` combined
  (local pywebview + remote API bound to a LAN interface). Useful for
  demos, but adds a matrix we have to test. Parked as a follow-up
  under a future `R2-00X`.
- Whether to integrate the existing `yggdrasim-apdu-fuzzer` safety
  gate into a GUI-only "big red button". Attractive but expands the
  attack surface of the GUI; parked.

## 19. Estimated effort

| Phase | Scope                                       | Effort     |
| ----- | ------------------------------------------- | ---------- |
| A     | API scaffolding, config, auth, tests         | 3 days     |
| B     | Desktop mode + minimal SPA                  | 4 days     |
| C     | Shell streaming + SAIP + HIL views          | 5 days     |
| C.1   | SAIP Decoded Editor (7.5): routes + UI      | 3 days     |
| D     | Remote server mode + TLS + rate-limit       | 3 days     |
| E     | Packaging + doctor + docs                   | 2 days     |
| Total |                                             | **20 days** |

Assumes no vendor-specific pywebview blockers and that the frontend
can stay on the plain Vite + Vue / Svelte toolchain.

## 20. Change log

| Date       | Change                              |
| ---------- | ----------------------------------- |
| 2026-04-21 | Initial draft for review (this doc) |
| 2026-04-21 | Add section 7.5 (SAIP Decoded Editor). Feature was prototyped in the v1 `saip_transcode_tui` but a textual modal cannot deliver the required layout / validation UX. Edit surface removed from the TUI; the Decoded pane remains a read-only viewer. Helper module `Tools/ProfilePackage/saip_decoded_edit.py` kept intact for the GUI to reuse. |
| 2026-04-23 | Phase C: G-1..G-4 (SCP03 Workbench layout), SA-1..SA-4 (SAIP Workbench: read-only → editor + save → compare + variables), and C-1..C-4 (SCP03 module-parity slices: 8 + 10 + 11 + 16 actions). Native file / folder pickers wired through `pywebview.api`. Total Command Center inventory: 117 actions across SCP03 (51) / eSIM Live (38) / SAIP (14) / Tools (6) / Local eIM (4) / HIL (3) / SCP11 (1). |
| 2026-04-23 | Phase C continued: C-5 (SCP03 mutation depth — PUT KEY, INSTALL family, FS-Admin, PIN / Channel / AUTH — 16 actions), C-6 (STK + OTA sub-shell ribbon handoffs through the B-2 PTY bridge, no per-tab xterm yet), and C-7 (scripts / fs_report / guides + SIMCARD-adjacent quirks / profile_store / euicc_store / TUAK helpers — 7 new actions across SCP03 and a new `SIMCARD` subsystem). Total Command Center inventory: 141 actions across SCP03 (71) / eSIM Live (38) / SAIP (14) / Tools (6) / SIMCARD (4) / Local eIM (4) / HIL (3) / SCP11 (1). |
| 2026-04-23 | **Pre-C-5 carry-overs cleared.** New **SCP11 Local** subsystem (7 read-only actions wrapping `SCP11.local_access.session.LocalIsdrSession`): `scp11_local.get_eid`, `list_profiles`, `get_euicc_info2`, `get_configured_data`, `list_notifications`, `get_certs_inventory`, `discover`. Mirrors the `scp11_live` pattern (short-lived PC/SC channel per call, stdout tee → `trace`, structured `note`, shared EUICCInfo2 detail-line renderer). Write / mutation actions (enable / disable / delete / metadata) stay deferred pending a confirmation-gate pass. **Per-tab xterm** — the B-2 terminal view is now multi-tab: each `.terminal-pane` hosts its own `Terminal` + `FitAddon` + WebSocket, with a pill-style tab strip above the host for switching / closing. `terminalState.pendingInit` is promoted to a top-level `terminalPendingBootstrap` so C-6 sub-shell handoffs always seed the next-spawned tab, regardless of which tab is focused. **Playwright smoke** — `tests/test_gui_playwright_smoke.py` ships a self-skipping end-to-end smoke that spins uvicorn on a loopback port, drives the SPA with headless Chromium, and asserts the Command Center nav renders the new SCP11 Local subsystem with its 7 action cards. Cleanly skips when `playwright` or the Chromium binary is missing, so CI stays green until the headless lane is added. Total Command Center inventory: 148 actions across SCP03 (71) / eSIM Live (38) / SAIP (14) / SCP11 Local (7) / Tools (6) / SIMCARD (4) / Local eIM (4) / HIL (3) / SCP11 (1). |
| 2026-04-23 | **SCP03 Workbench v2 — structural overhaul.** Session tabs promoted to a top strip so each session owns the full viewport; a dedicated **reader sidebar** on the left exposes live `/api/live/readers` data and binds the current tab to the clicked reader (confirm gate on switch; best-effort close before re-scan). The flat 19-group ribbon is replaced with an 8-tab **ribbon-v2** (Home / Diagnostics / Auth / Registry / Install / Files / eUICC / Admin) — only the active tab's groups paint, keeping the toolbar under one row at 1280 px. Trace output no longer dumps as a terminal-style `<pre>`: `scp03RenderTextLines` now detects `Key: value` lines and section headings and renders them as structured KV blocks; `scp03RenderTrace` and the residual free-form text drop into a collapsed `<details class="cc-trace-block">` so cards stop looking like terminal pastes. The Playwright smoke was extended to assert the new skeleton (`.scp03-topbar`, `.scp03-shell .scp03-reader-pane`, `.scp03-session-welcome`). No action-registry deltas; this is a pure frontend / UX pass. |
| 2026-04-23 | **SCP03 Workbench v2 — polish pass.** `.cc-actions > .cc-workbench` now spans the whole grid row (`grid-column: 1 / -1`), so the SCP03 / SAIP workbenches fill the viewport instead of getting squeezed into half a column on ≥ 1200 px. Record cards from `renderSingleRecord` start fully collapsed — the summary row (record #, SW, length, empty badge) is enough to scan a linear-fixed file at a glance, and individual records expand on demand. `scp03Rescan` now (a) invalidates `scanData` / `selectedPath` / `previewCache` and repaints **before** the network call, so the user gets instant feedback instead of staring at a frozen tree; (b) closes the previous session via `scp03.close_session` best-effort before opening a new one, so the PC/SC handle is released cleanly. `scp03Reset` gets a follow-up chain: after a successful cold reset it auto-invokes `scp03Rescan` so the tree, FCP preview, and secure-channel state re-sync with the now-pristine card instead of silently using stale, pre-reset data. Pure frontend; action registry unchanged. |
| 2026-04-23 | **SCP03 scan tree — fully qualified paths.** Clicking an EF directly under MF (e.g. `EF.ICCID`, `EF.DIR`) failed on the first click whenever the card's current DF had drifted to an ADF: the scan walker emitted bare names, the no-slash branch of `FileSystemController.select()` issued a direct `00A4000402<FID>` against the wrong DF, and ETSI TS 102 221 selection-by-FID scope rejected it with 6A82 — users worked around it by clicking MF first. `scan_tree` now seeds its traversal with `parent_path="MF"` so every descendant carries a fully qualified path (`MF/EF.ICCID`, `MF/ADF_USIM/EF_IMSI`, …), which routes through `select()`'s path-walk branch — that branch explicitly pre-selects MF before walking segments. A belt-and-suspenders `_normalise_fs_path` helper in the GUI dispatcher promotes any stale bare name (stale cache, hand-typed "Select by path", older tree payloads) to `MF/<name>`, while leaving hex FIDs, AIDs, scan-cache indices, and already-anchored paths untouched. Covered by `tests/test_gui_scp03_path_normalise.py`. No CLI semantics change (CLI indices still resolve through `scan_cache`; the scan tree print line is `display_name`, not `path`). |
| 2026-04-23 | **SCP03 Files admin — guided wizards replace the raw-hex forms.** The Files ribbon tab's six FS-admin actions (CREATE, DELETE, RESIZE, Lifecycle, SEARCH RECORD, SUSPEND UICC) previously asked operators to hand-craft full ETSI TS 102 222 FCP templates and raw FID strings — a usability cliff for anyone who hadn't memorised tag layouts. They now expose the same step-by-step wizard the CLI has (`SCP03/interface/shell_wizards.py::run_fs_admin_wizard`). **CREATE FILE** gets the biggest lift: a two-step Guided flow that first picks the file type (DF/ADF, Transparent EF, Linear Fixed EF) and renders only the fields that type needs, then hits a new offline `scp03.fs_build_fcp` dispatcher which composes the TLV wire and returns a per-tag breakdown (tag / hex / meaning) for an annotated preview panel. A "Raw FCP" mode toggle keeps the v1 flat form available for scripted / pasted templates. The backend builder `_build_fcp_template_fields` is a faithful port of the CLI wizard's `_build_fcp_template` — byte-for-byte wire parity is pinned by a `test_wire_matches_cli_wizard_for_transparent_ef` regression + 14 other cases (`tests/test_gui_scp03_fs_fcp_builder.py`, 15 total). Short-form BER length overflow (>127 bytes) now errors cleanly instead of silently emitting a broken template. **DELETE / RESIZE** auto-fill FID + parent path from the tab's current selection via a new `scp03FsPickFromSelection` helper (falls back to a muted "select a file first" hint). **RESIZE** adds live decimal mirrors for tag 80 / 81 so operators don't have to mentally convert `0x0040 → 64`. **Lifecycle** collapses the 4 operations into a select + per-op explanation card (description, irreversibility warning, conditional confirm-token requirement — only ACTIVATE/DEACTIVATE skip the confirm). **SEARCH RECORD** mirrors the hex needle as ASCII in real time (`"3034"` → `ASCII: 04`). **SUSPEND UICC** carries a dedicated danger-tinted hint explaining the PC/SC session drop. New CSS (`.cc-fs-wizard`, `.cc-fs-breakdown`, `.cc-fs-op-hint`, `.cc-fs-mirror`) gives the wizards a consistent bordered-panel look matched to the SGP.32 section cards. |
| 2026-04-23 | **SCP03 action traces — inline by default, hex stays collapsed.** `scp03RenderTrace` previously wrapped every captured stdout trace in a `<details class="cc-trace-block">` with a "Show trace (N lines)" summary; operators had to expand one-by-one to read what the compact printers emitted, even though that text is the primary human-readable read-out. The helper now emits `<pre class="cc-log cc-log-inline">` directly into the action card body — no disclosure, no click, CLI-parity at a glance. New `.cc-log-inline` CSS gives the inline block a bordered/padded box with `max-height: 520px; overflow: auto` so long traces can scroll without pushing siblings off-screen, plus a tight `margin` variant (`.cc-sgp32-section > .cc-log-inline`) to avoid nested-panel double borders. Raw hex disclosures (`<details>` inside each `SectionCard` + record card) are untouched — hex is an audit aid, not the primary read-out, so keeping it behind a click matches operator intent. For the SGP.32 bulk report the consolidated "full merged trace" footer is rebuilt inline as its own explicit `<details>` (collapsed) — per-section cards already inline their own traces, so the merged dump is reserved for bug-report copying only. Every SCP03 dispatcher that returns a `trace` field (ATR, GP inventory, file read/write, set-status, sgp22 telemetry, etc.) inherits the inline-by-default rendering automatically. |
| 2026-04-23 | **SCP03 FS context — pre-restore MF on every file read / select.** Bug report: "go into the file-system, read a file, SELECT any other AID, click a file in the tree — it can not be read anymore." Root cause: dispatchers such as `scp03.card_info` (ATR + ICCID + EID probe, which punches through to `EF.ICCID`, `ECASD` and `ISD-R` via raw SELECT-by-AID) and `scp03.cert_info` (ECASD walk + GET DATA 5A/45/42/E0/7F21) returned without re-anchoring the card to MF. The next FS-tree click landed at `_dispatch_read_selected` with the card sitting on ISD-R / ECASD / ADF-X; `FileSystemController.select()`'s path-walk branch does a best-effort `_select_single("MF")` for slash-rooted paths, but on a handful of cards we saw that relative SELECT 3F00 fail once the card had been pushed several layers deep. Fix is belt-and-suspenders: (1) `_dispatch_read_selected` + `_dispatch_select_only` now invoke `_restore_fs_root_best_effort(session)` **before** calling `fs_controller.select(...)` whenever the walked path is slash-rooted (MF-anchored) — cheap 1 APDU, guarantees clean-slate entry; bare hex FIDs / scan-cache indices / bare AIDs skip the pre-restore so CLI-parity relative selects still work for advanced operators. (2) `_dispatch_card_info` and `_dispatch_cert_info` now wrap their bodies in a `try: … finally: _restore_fs_root_best_effort(session)` so even an exception mid-probe leaves the FS view consistent. Plus a stray frontend bug: `scp03PromptSelect` was sending `identifier: <hex>` to `/api/actions/scp03.select/run`, but the action-spec's input name is `path` — it now sends `path: <hex>` and surfaces the `fcp.template_hex` preview in the log bus. Covered by `tests/test_gui_scp03_fs_state_restore.py` (8 cases: pre-restore fires for slash-rooted paths in both dispatchers; skipped for bare FIDs / AIDs; card_info + cert_info restore MF even when the probe raises). |
| 2026-04-23 | **SCP03 APDU console — raw APDU tab in the ribbon.** Operator request: "add a tab where the user can issue plain apdus on their own." The ribbon-v2 gains a dedicated **APDU** tab that renders a full-width workbench panel in place of the usual icon-strip (new `panel: fn` hook on `ribbonTabs`, new `.scp03-ribbon-section--panel` layout branch). The panel is a three-row stack: (1) preset picker (SELECT MF / EF.ICCID / EF.DIR, READ BINARY, GET DATA for EID / IIN / CIN / Key-Info / CPLC, GET STATUS ISDs / Apps, SELECT ISD-R / ECASD) plus follow-61 / retry-6C toggles; (2) the hex input with a live breakdown table (CLA / INS / P1 / P2 / Lc / Data / Le / case / byte-count) and an ASCII mirror of the data portion — fully pure-JS (`scp03NormaliseApduInput`, `scp03BreakdownApdu`, `scp03HexToAscii`), no server round-trip per keystroke; (3) the result card + a 20-slot per-tab history list with re-send / copy buttons. Ctrl/Cmd-Enter sends, Clear wipes the input, the panel's state (input text, toggles, last result, history) lives on the session tab so switching ribbon tabs doesn't wipe it. New backend action `scp03.send_apdu` (dispatcher `_dispatch_send_apdu` + spec `SEND_APDU_SPEC`, total inventory now 142) transmits the APDU verbatim via `transporter.transmit(..., silent=True)`, then auto-chains: `61xx` issues `00C00000<sw2>` GET RESPONSE until SW changes (bounded to 16 follow-ups) and concatenates the returned bytes; `6Cxx` retries once with the card-suggested Le via `_apdu_with_corrected_le` (which replaces the trailing Le for case-2/4 and appends for case-1/3). Response is returned as `{ apdu, breakdown, response_hex, response_length, response_ascii, sw, sw1, sw2, sw_meaning, ok, chain }` — `sw_meaning` via `StatusWordTranslator.translate` so 9000 / 6A82 / 6Cxx / 61xx all render inline. Crucially the dispatcher does **not** call `_restore_fs_root_best_effort` — the whole point is to leave the card wherever the operator's APDU put it; the next Files-tab click pre-restores MF via the existing `_dispatch_read_selected` guard. Covered by `tests/test_gui_scp03_send_apdu.py` (23 cases: hex normaliser edge cases, ISO 7816-4 case classification, Le-retry rule for each case, single / multi-step 61xx chaining, 6Cxx retry, follow_61=False / retry_6c=False toggles, ASCII preview, no-MF-restore assertion against a raw SELECT-by-AID for ISD-R, spec registration). |
| 2026-04-23 | **Top-bar reader strip — sessions live next to the brand.** Operator request: "move the readers to the top bar next to YggdraSIM — pick a reader there and the reader is pre-set in all modules, so you can have 15 readers and toggle between sessions easily; the sessions are tied to the reader instead of the module." The per-SCP03-tab left sidebar reader pane and the duplicate `Readers` section in the global left sidebar are retired (the CSS now hides `.cc-wb-tabs.scp03-topbar` and `.scp03-shell > .scp03-reader-pane`, and the SCP03 shell grid collapses to `1fr` so the workbench spans the full viewport). They are replaced with a new `#topbar-readers` strip inserted into `<header class="topbar">` between the brand and breadcrumbs: a horizontally-scrollable pill list (one pill per `/api/live/readers` entry, plus any orphan readers still holding a session) with a refresh spinner button on the right. Each pill renders a **traffic-light dot** via `readerBarDeriveStatus(readerName)` — **green** when any SCP03 tab has `sessionId` bound to that reader, **yellow** when the reader's probe reports a non-empty `atr_hex` (card present, no session), **red** for plugged-in / no card / no session, **gray** for offline orphans. Clicking a pill runs `readerBarActivate(name)`, which promotes that reader to `commandState.readerBar.activeReader`, finds-or-creates the matching `scp03Workbench` tab via `readerBarSyncToScp03Tab` (reusing a truly-empty first tab before stacking a new one), and auto-navigates into `openCommandSubsystem("SCP03")` **only** from the Overview or when already on SCP03 — we deliberately do not yank the operator out of the SAIP workbench or the raw terminal. The pill's `×` button closes the bound session (`scp03.close_session` best-effort + `scp03CloseTab`). Polling runs every 5 s while the page is visible (`document.visibilitychange` pauses on hide, resumes with an immediate fetch), and the SCP03 flows (`scp03Rescan`, `scp03CloseTab`) call `readerBarNotifySessionChanged()` so pill colours flip the moment a session opens / closes — no wait for the next poll tick. CSS adds `.topbar-readers{…}`, `.topbar-reader-pill{…}` (with `.is-active` accent-coloured focus ring), `.topbar-reader-pill-dot--green/yellow/red/gray` (explicit vivid palette, not semantic tokens, so all themes render the same traffic-light), and retires `.cc-wb-tabs.scp03-topbar` / `.scp03-reader-pane` via `display: none !important`. Reader names are shortened via `readerBarShortName` (strips trailing `NN NN` port-slot indices and `[CCID Interface]`-style bracket suffixes, truncates >26 chars) so a 15-reader bench fits on a 13" laptop without each pill being a novella. Covered by `tests/test_gui_topbar_readers.py` (12 cases: HTML markup contract, sidebar retirement, `commandState.readerBar` fields, public helpers, init-wiring, SCP03 hook-in, traffic-light tokens, CSS selectors, legacy-pane hide rule). |
| 2026-04-23 | **SCP03 FS-view — optimistic FCP cache + auto-recovery.** Operator report: "the state-not-recovering when moving from filesystem to different AID to filesystem again still persists — can we use a cache system so we can still display the data and, underneath, reset and rescan the card?" The belt-and-suspenders pre-restore in `_dispatch_read_selected` (raw `00A40004023F00` before every slash-rooted read) wasn't enough on a handful of loaders — the card gets parked in a state where SELECT-by-FID returns 6A82 until it's cold-reset. Backend gains a new dispatcher `scp03.recover_session` (`_dispatch_recover_session` + `RECOVER_SESSION_SPEC`, inventory now 143) that cold-resets via `transporter.reset()`, drops any secure-channel bookkeeping via `transporter.reset_session_state()`, re-instantiates `FileSystemController`, rewalks MF with `scan_tree(return_tree=True)` into a stdout sink, and swaps the fresh controller into `session.handle["fs"]` so subsequent `_dispatch_read_selected` calls bind the refreshed state — all without invalidating the `session_id` the GUI is holding. Returns a `scp03.scan`-shaped payload (`tree` / `scan_cache` / `atr_before_hex` / `atr_after_hex` / `scan_ok` / `scan_error`) so the frontend can graft the refreshed tree straight into `tab.scanData`. Failure isolation: if `scan_tree` raises, the dispatcher still returns with `reset_ok=true, scan_ok=false` so the cold reset isn't masked by a walker hiccup. Frontend adds `tab.fcpCache` (per-path map keyed by scan-tree path), wiped on `scp03CloseTabSessionOnly` / `scp03Rescan` / tab close (different card coming in), populated on every successful `scp03.read_selected`. `readSelectedForTab` was rewritten into a five-phase optimistic flow: (1) render cached data *immediately* with a "showing cached data — refreshing" accent banner so the preview never goes blank during an eUICC → Files context switch; (2) fire the fresh read; (3) on `ok=false` or `selected=false` flip the banner to amber "resetting card + rescanning tree" and call `scp03RecoverSession(tab)` which drives the new dispatcher; (4) retry the read — on success promote the refreshed tree into `tab.scanData`, update the cache, and leave a subtle "card was reset + rescanned to recover this read" banner above the preview; (5) if the retry still fails, keep the cached render visible under a red "stale" banner + error block so operators see "yes, this is stale" instead of a blank pane. Helpers `scp03CacheStore` / `scp03CacheLookup` / `scp03FormatAge` / `scp03BuildCacheBanner` / `scp03RenderFromCache` / `scp03DoReadSelected` / `scp03RecoverSession` encapsulate the flow so it can be unit-pinned from a static bundle. CSS adds `.cc-stale-chip` with `--refresh` / `--recover` / `--stale` tint variants + a CSS-keyframe-spun reload-arrow glyph (`@keyframes cc-stale-chip-spin`) so the banner animates while the wire op is in flight. Covered by `tests/test_gui_scp03_recover_session.py` (13 cases: dispatcher calls cold-reset + session-state drop, swaps fresh FS controller into `session.handle`, returns scan-shaped payload, survives scan-tree exceptions without masking the reset, rejects empty session_id, spec registration; plus static contract pins for `tab.fcpCache` wiring in `scp03CreateEmptyTab`, cache-clear on session close + rescan, frontend helper presence, recovery-call wiring in `readSelectedForTab`, scan-tree promotion into `tab.scanData`, banner CSS contract). |
| 2026-04-23 | **SCP03 FS-Admin — contextual action bar next to the `fid:` badge.** Operator request: "move the file actions down from the tab/action list and to the file module, can put them next to the fid badge — and make it stateful so that when I press an EF I cant create a file from there but need to select MF/DF/ADF etc, likewise I cant update record on a transparent file." The legacy **Files** ribbon tab is retired (the `fsAdminGroup` factory and its `{ id: "files", … }` ribbon-tabs entry are gone; a stale `tab.activeRibbonTab === "files"` falls back to `"home"` via the existing unknown-id guard in `scp03BuildRibbon`). In its place, `renderFcpResult` now emits a contextual `.cc-fs-actions` strip inside the FCP preview header — same row as the `path:` / `fid:` chips — that renders CREATE / DELETE / RESIZE / Lifecycle / SEARCH RECORD as pill buttons, plus a separately-grouped SUSPEND UICC (card-wide, visually set off with the danger-soft background so it can't be fat-fingered while clicking file-scoped actions). Gating is driven by two new helpers: `scp03ClassifyFile(data)` maps the `read_selected` payload to one of `df / application / transparent / linear / cyclic / unknown` (FCP `template`/`type`/`structure` first, `payload.kind` as a fallback when the FCP parser returned `'Unknown'`), and `scp03FsActionAvailability(kind)` returns a per-slot `{enabled, reason}` map per ETSI TS 102 222 §6.3–§6.5 / TS 102 221 §11.1.11 scoping — CREATE FILE only on DF / ADF / MF, RESIZE only on EFs, SEARCH RECORD only on linear / cyclic, TERMINATE-EF only on EFs, TERMINATE-DF only on DFs, ACTIVATE / DEACTIVATE on both. Disabled buttons stay in the DOM (greyed via `.cc-fs-action-btn.is-disabled`) with the `reason` string as their `title` tooltip — they double as a discovery aid so operators learn *why* a button is not available ("CREATE FILE is issued under a DF — select MF / a DF / an ADF first") instead of hunting a removed ribbon. A new `.cc-fs-kind` chip echoes the classifier label (`DF`, `EF · transparent`, `EF · linear fixed`, `EF · cyclic`, `ADF · application`) next to the existing chips so the selected-file type is scannable at a glance. `renderFcpResult` gains an optional `tab` parameter — the two SCP03 call sites (preview click + cached repaint) pass it, the generic action-result dispatch (kind='fcp') still calls with no tab and skips the action bar, preserving back-compat. Each pill still hands off to the same existing wizard (`scp03ShowFsCreateFile(tab)`, `scp03ShowFsDeleteFile(tab)`, …) which renders into the `.cc-wb-extras` slot below the tree / preview layout — only the entry point moved, the ASN.1 wire-building and confirm-gates are unchanged. Covered by `tests/test_gui_scp03_fs_actions_contextual.py` (8 cases: classifier kind-emission pin, availability matrix slot pin, builder wiring into `renderFcpResult`, `tab` parameter plumbing, ribbon-tab retirement, wizard-entry preservation, two operator-verbatim gating rules — "EF can't CREATE" + "transparent can't SEARCH RECORD", CSS token contract). |
| 2026-04-23 | **SGP.32 bulk telemetry — structured sections, no more terminal dump.** `scp03.get_sgp32_all_data` previously captured `sgp22.get_sgp32_all_data()`'s ANSI-coloured stdout into a single `trace` string; the GUI rendered it through `scp03RenderTrace` which put the whole sweep behind one green-on-black `<pre>`. The dispatcher now drives the five retrievals individually (`run_sgp22_scan` + `BF4300` RAT + `BF2B00` NotificationsList + `BF5500` eIM-Config + `BF5600` GetCerts), captures each printer's stdout into its own buffer, grabs the raw TLV bytes alongside, and returns a `sections[*]` array with `{ key, title, es10_tag, status, hex, lines, trace, note }` plus a `summary` rollup of `{ total, ok, empty, error }`. The legacy `trace` blob is still emitted (audit / debug), but the GUI prefers the structured payload. Frontend gains `scp03RenderSgp32BulkReport` + `scp03BuildSgp32SectionCard`: one titled sub-card per ES10 step (two-column grid ≥ 1100 px, one-column below), KV-aware body via `scp03RenderTextLines`, a status-coloured left edge (`--ok` / `--warn` / `--err`), and a collapsed hex view + collapsed per-section trace so nothing looks like a terminal paste. New `_sgp32_run_section` isolates per-step capture so a failing printer / retrieve never aborts the whole sweep — it tags the affected section `error` / `empty` and the others still render. Covered by `tests/test_gui_scp03_sgp32_bulk.py` (8 cases: trace-line normaliser + ok / empty / retrieve-error / printer-error / unknown-parser-mode paths). |
| 2026-04-24 | **SCP03 record view — filter walker terminator sentinel.** Operator feedback: "I also see that the 'end record scan' is presented, lets not present these for the file system." ``_read_file_body`` walks records 1..254 for linear-fixed / cyclic files and, on the first non-``9000`` status word, appends a synthetic record carrying ``ok=False`` + ``length=0`` + the terminating SW so CLI / JSON consumers can audit *why* the walker stopped (typically ``6A83`` = record-not-found per ETSI TS 102 221 §10.1.2). The frontend was rendering that sentinel as a regular row — a 2-record EF showed up as ``#1 · SW 9000 · 38 B · EMPTY`` + ``#2 · SW 6A83 · 0 B · EMPTY``, which read as noise next to the real content and inflated the header's ``records: 2`` count. Fix is UI-only: new helper ``scp03IsRecordTerminator(rec)`` matches ``ok:false`` + ``length:0`` + ``6A*`` SW (or any ``ok:false`` zero-byte record — the walker only appends one sentinel and it's always at the end, so the heuristic is safe), and ``renderRecordsPayload`` filters via it before counting + rendering. The header ``records: N`` chip now reflects the *displayed* count, not the raw array length, so the summary can't off-by-one. ``non_empty_count`` still comes from the backend (which already only counts ``ok:true`` records, never the sentinel) so API parity is preserved. When the filter leaves zero records (e.g. the very first READ RECORD returned ``6A83`` so the file has no readable content), the empty-state now surfaces the stop reason explicitly ("no readable records (stop: record_not_found)") instead of rendering a blank. Backend payload is untouched — the sentinel stays in ``payload.records`` so CLI dumps and external consumers keep byte-level parity. Covered by ``tests/test_gui_scp03_record_terminator_filter.py`` (7 cases: helper defined, ok:true short-circuit, length gate, 6A* SW match, renderer applies filter, header counts displayed rows, empty-display surfaces stop reason, non-empty count sourced from backend payload not filtered list). |
| 2026-04-23 | **SCP03 action outputs — floating popout windows, not an inline tower.** Operator request verbatim: "when the user presses a function or action button the module for that action is placed below the etsi file tree, can we make these action button spawn in a pop-out window instead?" — motivated by the `.cc-wb-extras` strip growing into a vertical tower (card_info + GP status + key-info + cert_info + EF.DIR + ATR-details + …) that hid the file tree and pushed the fold several screen-fulls down on a typical 13" laptop. The fix rewires `scp03BuildExtrasCard(title)` to mint a **floating, draggable, resizable `.cc-popout` window** anchored to a lazy-created `#cc-popout-host` under `<body>` (`position: fixed`, so it floats above the tree + preview layout regardless of scroll position). The builder's call contract is preserved at all 60+ call sites — it still returns an element callers `.appendChild(...)` into — but the returned element is now the popout **body** instead of an inline card. Back-compat was a hard design constraint: a handful of action dispatchers call the builder twice (loading placeholder → real payload) so the helper also **dedupes by title**: the second call on the same `(tabId, title)` key reuses the existing popout, clears its body, and bumps its z-index, instead of stacking a clone. **Lifecycle**: each tab's `tab.popouts = {}` + `popoutZCursor` + `popoutCascadeIdx` live on `scp03CreateEmptyTab`, wiped on `scp03CloseTab` (pill `×` — the operator's explicit "forget this session" gesture tears down the bound popouts alongside the session + persisted cache). Tab switch hides non-active-tab popouts via `display: none` (state preserved; windows reappear on return). Subsystem switch hides the whole set (popouts are contextually SCP03-only; leaving to SAIP / eSIM Live / Tools cloaks them, returning to SCP03 re-runs the visibility sync). **Drag** uses pointer-events with `setPointerCapture` so fast cursor motion doesn't lose the titlebar; viewport clamping keeps the titlebar reachable even after a wild drag; the `touch-action: none` CSS hint stops the browser from claiming the gesture for scroll. **Resize** uses native CSS `resize: both` on the shell with `overflow: hidden` (scrollbars inside the body honour the rounded corners). **Maximize** is a toggle with cached prior geometry — `.is-maximized` owns size via `!important` so the inline `left` / `top` don't need to be cleared, and restore replays the cached coordinates. **Focus**: any `pointerdown` anywhere in the popout bumps it above siblings on the same tab, and adds `.is-focused` (accent-coloured border + stronger shadow); sibling popouts on the same tab lose the ring. **Cascade**: new popouts open offset 28 px from the last, resetting to base when they would push off the visible area — stops "everything stacks at origin" on a busy session. **Legacy `.cc-wb-extras` strip** stays in the DOM (four defensive `.innerHTML = ""` cleanup sites on cancelled prompts still work) but is now `display: none` so the preview panel reclaims the vertical real estate. The single remaining inline `.cc-wb-extras-card` creation site (`scp03ListApps`) was converted to the popout helper. Covered by `tests/test_gui_scp03_popouts.py` (17 cases: helper surface, sizing constants, builder returns body, dedupe on repeat click, registers on active tab, tab factory seeds popout state, close-tab tears down, render + subsystem sync call visibility helper, drag uses pointer capture + viewport clamp, titlebar dblclick toggles maximize, pointerdown brings-to-front, toggle-maximize caches prior geometry, CSS selectors declared, fixed-position + resize contract, legacy strip hidden, no leftover inline extras-card creations). |
| 2026-04-23 | **Reader-bar poll no longer power-cycles the card.** Root cause for the persistent "every file click fails, has to rescan the entire card" regression, which the operator correctly diagnosed as "the tool is dropping the connection to the card, not the card dropping the connection." pyscard's `PCSCCardConnection.connect()` defaults `disposition` to `SCARD_UNPOWER_CARD`, and `disconnect()` reads that stashed value back into `SCardDisconnect(hcard, disposition)`. The 5 s reader-bar poll (`/api/live/readers` → `_probe_reader`) opened a *second* `SCARD_SHARE_SHARED` handle to every reader, grabbed the ATR, and disconnected with `SCARD_UNPOWER_CARD` — which pcscd honours even while a sibling handle (our live scp03 scan session) is still open: the card cold-resets between polls, the scan session's `current_fid` points at a DF that's no longer selected, and the *next* click in the file tree fails with 6A82. The auto-recovery pass (`scp03.recover_session`) then masked the cause by cold-resetting + rescanning on every click, making every interaction take ~2 s and making the tree look like it "rescans on every click." **Two-pronged fix** in `yggdrasim_common/gui_server/routes/live.py`: (1) `_probe_reader` now passes `disposition=SCARD_LEAVE_CARD` to `connection.connect(...)` (with a `TypeError` fallback for older pyscard releases that lack the kwarg — the fallback still sets `connection.disposition` before the `finally: disconnect()` runs, so either path honours LEAVE_CARD). (2) New `_session_atr_by_reader_name()` walks the `SessionManager`'s `kind="scp03"` entries and returns `{reader_name: atr_hex}`; `list_readers` / `probe_single_atr` look up each reader there first, and when a cached ATR exists `_probe_reader(reader, cached_atr=…)` **short-circuits the entire PC/SC round-trip** — zero second handles opened on readers with live sessions, so the poll is a pure HTTP operation for the happy-path case. Also hardened `yggdrasim_common/card_backend.create_card_connection` so the *primary* scp03 transporter connects with `SCARD_LEAVE_CARD` too — future session closures (eviction, tab close) no longer power-cycle the card out from under any sibling session sharing the same reader. Covered by `tests/test_gui_live.py::TestProbeLeavesCardPowered` (2 cases: disposition kwarg, legacy-pyscard TypeError fallback) + `TestProbeShortCircuitsOnCachedAtr` (2 cases: cached-ATR no-PC/SC path, empty-cache falls through) + `TestSessionAtrLookup` (1 case: scp03-only filter, `(default)` sentinel skip, empty-ATR skip). `tests/test_gui_scp03_recover_session.py` (13 cases) still green — the recovery dispatcher is retained as a belt-and-suspenders safety net for genuinely stuck cards, but should now almost never fire in normal use. |
| 2026-04-28 | **SAIP Workbench SA-G1 — Comprion-inspired layout shell rework.** Operator brief: take Comprion's eUICC Profile Creator screenshots as inspiration for layout / functions / features without copying assets or copy. Slice 1 of 6 lands the structural rework: (a) a new ribbon command bar (`.saip-ribbon`) above the workbench with grouped buttons (Profile Package / Profile Element / File System / Variables / Validation / Help) — wired-up commands (Open / Close / Save / Compare / Validate / Variable editor / Manual) light up green-on-hover; future-slice stubs (New / Batch / Add above / Add below / Delete / Undo / Redo / Find / Sync / Save report / PE info) render desaturated with explanatory tooltips so the topology is locked in for SA-G2..SA-G6; (b) the in-pane "PEs | Files | Variables" sub-tab strip (`.saip-pane-tabs`) is retired; in its place sits a workbench-level **top-tab strip** (`.saip-top-tabs`) with three sibling tabs — `Profile Elements`, `File System`, `Applications` — that swap the entire main viewport, complete with per-tab badge counts (`peRows.length` / `fileRows.length` / app-bearing PE count); (c) Variables moved out of the left pane into a ribbon-launched **modal** (`.saip-modal-host` / `.saip-modal-card`) that re-uses `renderSaipVariablesPane` verbatim — opening from the ribbon, closing via backdrop / × / package close, surviving package switches by re-targeting; (d) the layout grid drops from 3 columns (drawer | peList | detail) to 2 (drawer | main) — the PE list and detail are nested inside `.saip-tab-body > .saip-split--<tab>` so the file-system tab gets full-width breathing room; (e) Applications tab ships as a derived placeholder showing every PE with `has_apps=true` and a "Open in PE tab" jump button — the dedicated `saip.list_applications` dispatcher and ISD/state badges land in SA-G4. State delta is minimal: `pkg.activeDetailTab` (`"pe" | "file" | "vars"`) → `pkg.activeTopTab` (`"profile_elements" | "file_system" | "applications"`); `commandState.saipWorkbench` gains `variableModalOpen` + `variableModalPackageId` for the modal lifecycle. Every existing SAIP backend action (open / list_pes / show_pe / list_files / show_file / validate / update_file_field / list_decoded_fields / apply_decoded_edit / save_package / revert_changes / compare / list_variables / set_variable / lint_path / decode_to_json / get_dirty / close_package — 18 specs) is unchanged; every existing renderer (`renderSaipPeList`, `renderSaipDetail`, `renderSaipFileDetail`, `renderSaipVariablesPane`, `renderSaipCompareDetail`, `renderSaipValidation`, `renderSaipPeDetail`) is reused under the new shell. CSS adds `.saip-ribbon{…}`, `.saip-ribbon-group{…}` (column-flex with bottom-aligned uppercase group label), `.saip-ribbon-btn{…}` (icon-over-label, `.saip-ribbon-btn--primary` accents the Open command, `.saip-ribbon-btn--stub` greys disabled affordances), `.saip-top-tabs{…}` (raised tab strip with `--accent` ring on the active tab + accent-filled badge), `.saip-apps-host{…}` / `.saip-apps-table{…}` for the placeholder, and `.saip-modal-host{…}` / `.saip-modal-backdrop{…}` / `.saip-modal-card{…}` for the variable modal — every selector uses the existing `--accent` / `--accent-soft` / `--accent-fg` / `--surface` / `--surface-alt` / `--border` / `--fg` / `--fg-muted` tokens so all five themes (Nord dark/light, 1oT dark/light, Matrix) inherit the styling without per-theme overrides. The legacy `.saip-pane-tabs` / `.saip-pane-tab` selectors are removed so any rogue caller fails loudly. JS syntax `node --check` clean; backend smoke (`yggdrasim_common.gui_server.actions.saip` + `yggdrasim_common.gui_server.app`) imports clean; existing GUI-SAIP backend tests (`tests/test_gui_saip_tolerant_loader.py` 19 cases, `tests/test_gui_saip_decoded_edit.py` 19 cases, `tests/test_gui_saip_pysim_compat.py` 6 cases) all green. Slices SA-G2 (typed PE editors per type — PE-USIM template + file checkboxes, PE-SecurityDomain parameter tree, …), SA-G3 (File System hierarchical tree with General / Data sub-tabs + ARR access-mode editor + record hex viewer), SA-G4 (`saip.list_applications` backend + Applications tab body), SA-G5 (validation bottom dock with click-to-jump), and SA-G6 (variable editor polish + ribbon shortcuts) are queued. |
| 2026-04-28 | **SAIP Workbench SA-G2 — typed PE editors, first cut.** Slice 2 of 6 swaps the legacy 6-column PE table for a vertical card list and adds a third detail-view tab — `PE-<Type> Editor` — that becomes the default landing pane next to the existing `ASN.1 Value Notation` and `JSON tree` siblings. **Card list (`renderSaipPeListPane`)**: `<table class="saip-pe-table">` is replaced with `<ul class="saip-pe-cards" role="listbox">`; each `.saip-pe-card` is a 3-column grid (icon · body · identification badge) that surfaces (a) a colour-coded glyph keyed by PE family — `template` / `domain` / `security` / `auth` / `fs` / `remote` / `meta` / `access` / `app` / `default` (10 families, all sourced from a single `SAIP_PE_REGISTRY` map with permissive `dash` / `lower-case` / `no-dash` / `df-*` / `adf-*` fallbacks); (b) the friendly type name (`USIM`, `OPT-USIM`, `Profile Header`, `MNO Security Domain`, `Generic File Mgmt`, …); (c) the type sub-label (`row.label || row.type`, monospace); (d) per-card chips for `FS` / `APP` / dirty-pulse (`●`); (e) a right-aligned identification badge (`row.index`) that flips to the accent token when the card is active. Dirty PEs gain a 3 px warning-tinted left border (`--warning` with safe fallback) so unsaved edits read at a glance without consulting the ribbon. **Detail head (`renderSaipPeDetail`)**: the chip strip is wrapped in a flex row that places the type icon (large variant — `.saip-pe-icon--lg`) in front of the existing PE-index / type / label chips, mirroring the card list so the operator's eye doesn't have to retrain when jumping between the list and the detail view. **Tab strip**: the binary `JSON tree` / `Value notation` toggle becomes a three-tab strip — `PE-<Friendly> Editor` (active by default) → `ASN.1 Value Notation` → `JSON tree`. The Editor tab title is parameterised through `saipPeFriendlyName(data.type)` so the operator always sees the right label per selection. **Editor router (`renderSaipPeEditor`)** dispatches by lowered + dash-normalised type onto seven concrete renderers: `saipEditorRenderProfileHeader` (top-level `header` PE — SAIP version, profile type, ICCID hex + BCD-decoded digits, mandatory services, mandatory GFSTE list, connectivity parameters); `saipEditorRenderHeaderCard` (per-PE `*-header` sub-card with `mandated` / `identification`); `saipEditorRenderTemplateCard` + `saipEditorRenderFilesCard` (USIM / ISIM / CSIM family + `OPT-*` siblings — template OID, ADF FID + DF Name (AID) + LCSI + PIN status template DO, plus an at-a-glance file table with FID / sFID / Descriptor / EF size / link path columns; clicking a row jumps into the File System tab and seeds `pkg.selectedFileKey` + `saipLoadShowFile` so the right-hand pane lands on the matching `EF`); `saipEditorRenderInstanceCard` + `saipEditorRenderKeyListCard` + `saipEditorRenderPersoCard` (`securityDomain` / `MNO-SD` / `SSD` — Application Load Package AID, Class AID, Instance AID, Application privileges, Lifecycle state, Application-Specific-Parameters C9 hex, sub-rows for `applicationParameters.uiccToolkitApplicationSpecificParametersField` and friends; key-list as a 6-column table with `Usage` / `ID` / `Version` / per-component `keyType · NN B · MAC NN` / `Access`; persoData lists raw STORE DATA blocks); `saipEditorRenderPinPukCard` (`pinCodes` / `pukCodes` — one nested card per slot, surfaces whatever fields pySim emits without hard-coding a schema since slot keys vary across SAIP releases); `saipEditorRenderAkaCard` (`akaParameter` / `akaParameterCsim` — algorithm choice + parameters, SQN options / delta / age limit, sqnInit slot count); `saipEditorRenderGfmCard` (`genericFileManagement` / `gfm` — fileManagementCMD list as one nested card per command, walking choice-tuple ops `('filePath', …)` / `('createFCP', {...})` / `('writeRecord', …)` and rendering each as `Command N → tag → field` rows); plus `saipEditorRenderUntyped` for any PE type that doesn't yet have a typed editor — surfaces the type / index / label + top-level-keys list and explicitly points the operator at the JSON tree / value notation tabs above. **Helpers**: `saipFindHeaderEntry` (regex-locates `*-header` / `*-Header` sub-keys regardless of case-style); `saipChoiceTuple` (decodes pySim's `{"@": [name, payload]}` envelope); `saipExtractHex` (handles bytes envelope `{"hex": …, "label": …}`, plain string, or null); `saipFormatHexPretty` (groups bytes as `XX XX XX XX` for legibility); `saipBcdToDigits` (ICCID nibble-swap → digit string with trailing `F` stripping). **State**: every editor is read-only in SA-G2 — write-back routes through the existing `saip.update_file_field` (file-shape paths) and `saip.apply_decoded_edit` (free-form JSON patches) actions and lands in a follow-up slice. **CSS additions** (no theme-specific overrides — every selector references the existing `--accent` / `--accent-soft` / `--accent-fg` / `--surface` / `--surface-alt` / `--border` / `--fg` / `--fg-muted` / `--mono` tokens so all five themes inherit the styling for free): `.saip-pe-cards`, `.saip-pe-card{…}` (with `.is-active` accent ring + `.is-dirty` warning border), `.saip-pe-icon{…}` (32×32 base, 38×38 large variant `.saip-pe-icon--lg`) plus 6 family-coloured variants (`--template`, `--domain`, `--security`, `--auth`, `--fs`, `--remote`, `--meta`, `--app`, `--access`, `--default` — the four neutral families share the same default tint by design), `.saip-pe-card-name`, `.saip-pe-card-sub`, `.saip-pe-card-chips`, `.saip-pe-chip{…}` with `--fs` / `--app` / `--dirty` flavours, `.saip-pe-card-id` (mono badge that flips to the accent token when active), `.saip-detail-head-chips` (flex wrap), `.saip-editor`, `.saip-edit-card{…}` (with nested-card support so the SecurityDomain Instance card can host a sub-card per `applicationParameters.*` slot without double borders), `.saip-edit-card-title`, `.saip-edit-card-hint` (italic, muted — explanatory copy under each card title), `.saip-edit-kv{…}` (label / value 2-col grid with mono + muted modifiers), `.saip-editor-files{…}` + `.saip-editor-files-row` (clickable hover state), `.saip-editor-keylist{…}` + `.saip-editor-keylist-comps` (whitespace-pre-wrap monospace cell so `keyType · NN B · MAC NN` summaries wrap cleanly across columns). **Verification**: `node --check` clean on `app.js` (≈14 200 lines); backend smoke (`yggdrasim_common.gui_server.actions.saip` + `yggdrasim_common.gui_server.app`) imports clean; existing GUI-SAIP backend tests all green (`tests/test_gui_saip_tolerant_loader.py` 19 cases, `tests/test_gui_saip_decoded_edit.py` 19 cases, `tests/test_gui_saip_pysim_compat.py` 6 cases). Slice exercised against the in-tree reference profile (`Workspace/SAIP/profile/transcoded/1oT_test_profile.transcode.der`, 17 PEs spanning 13 unique types — header / mf / pukCodes / pinCodes / telecom / genericFileManagement / usim / opt-usim / gsm-access / akaParameter / securityDomain / rfm / end). Slices SA-G3 (File System hierarchical tree with General / Data sub-tabs + ARR access-mode editor + record hex viewer), SA-G4 (`saip.list_applications` backend + Applications tab body), SA-G5 (validation bottom dock with click-to-jump), and SA-G6 (variable editor polish + ribbon shortcuts) are queued. Write-hook follow-up (SA-G2.5) — wiring `Mandated` / `Identification` / template OID / FID / link-path / lifecycle-state edits through the existing `apply_decoded_edit` endpoint — is queued as the next chunk. |
| 2026-04-28 | **SAIP Workbench SA-G3 — File System hierarchical tree + General / Data / Access sub-tabs.** Slice 3 of 6 lands the File System tab's structural overhaul. **Tree view (`renderSaipFileListPane`)**: the 3-column `<table class="saip-pe-table">` is retired; in its place sits `<ul class="saip-file-tree saip-file-tree--root" role="tree">` with three depth tiers — section roots (`MF` / `DF.TELECOM` / `ADF.USIM` / `ADF.OPT-USIM` / `DF.GSM-ACCESS` / …) at depth 0, container rows (`mf` / `df-*` / `adf-*`) at depth 1, EFs at depth 2 (or depth 1 in container-less sections like `opt-usim`). Hierarchy is inferred client-side from the linter's emission order: `saipBuildFileTree(rows)` walks each section and re-buckets EFs under the most recent container. Expand / collapse state lives on `pkg.fileTreeCollapsed[node.id]` so it survives row refreshes from edits / saves / reverts; node ids are deterministic (`section::<sk>` / `node::<sk>::<fp>`). Each row carries a caret button (`▶` / `▼`) when it has children, a kind-coloured glyph (`⌂` section / `▣` MF / `◆` ADF / `▼` DF / `•` EF), the friendly name (`saipFileFriendlyName` rewrites `ef-keys` → `EF.KEYS`, `df-phonebook` → `DF.PHONEBOOK`, `adf-usim` → `ADF.USIM`), an optional FID badge (FCP tag 83 — uppercase mono), and an optional sFID badge (FCP tag 88 — accent-tinted to stand out from the FID). The active row picks up the same `--accent` outline + accent-soft fill the PE cards use, so the eye doesn't retrain when bouncing between the Profile Elements and File System tabs. **File detail (`renderSaipFileDetail`)**: the 2-card `.saip-file-grid` (FCP-edit | Payload) becomes a tab strip with three sub-tabs — `General` (default), `Data`, `Access rules`. The detail head gains a large `FS` icon next to the existing FID / sEFID / size chips plus a new `path:` chip surfacing the `<section> / <field>` route so the operator always knows which dictionary entry they're editing. Active sub-tab persists on `pkg.activeFileTab`. **`General` tab body** (`saipFileRenderGeneral`) ports the existing `_SAIP_EDIT_FIELDS` table (FCP file ID, short EFID, descriptor, EF size, max size, security attrs, link path, PIN status template DO) + the JSON payload card + the decoded-edit panel (`saipRenderDecodedEditPanel`) verbatim — no behavioural change. **`Data` tab body** (`saipFileRenderData`) reconstructs a virtual file image by walking the payload's choice tuples (`saipBuildVirtualFileImage`) — `('fillFileOffset', N)` repositions a write head, `('fillFileContent', {hex})` deposits bytes from the head, `('fillFileContents', …)` is treated as a defensive plural-form alias. The reconstructed image is rendered as a 16-byte-per-row hex dump (offset / 8-byte hex group / 8-byte hex group / `|ASCII|`); gaps where the payload skips ahead via `fillFileOffset` without filling surface as `--` placeholder bytes so the operator can see issuer-personalised regions at a glance. A summary card above the dump prints the reconstructed length + content-span count + the FCP-declared EF size (tag 80) so divergence between encoded length and declared length is obvious. Files with no inline content (metadata-only / fill-from-template / `doNotCreate`) skip the dump and render an explanatory hint card instead. **`Access rules` tab body** (`saipFileRenderAccess`) decodes the `securityAttributesReferenced` value bytes per TS 102 221 §9.2.4 — 3 bytes are parsed as `<ARR-FID-2-bytes><record-id>` (referenced form), 1 byte as `<record-id>` (default ARR form, with a hint pointing the operator at `2F06` / `6F06` for the canonical default ARRs); other lengths fall through to a raw-bytes view. When the bytes still carry their tag wrapper (some hand-rolled SAIPs do this — `8B 03 …` / `8C 03 …`) a TLV breakdown card is added below with explicit Tag / Length / Value rows. Files without a `securityAttributesReferenced` entry render an alternative-SCDOs hint card explaining the FCP tag 8C / card-default fallback model. **Helpers added**: `saipBuildFileTree`, `saipBuildFileTreeNode`, `saipFileSectionLabel` (handles MF / TELECOM / USIM / OPT-USIM / ISIM / OPT-ISIM / CSIM / OPT-CSIM / GSM-ACCESS), `saipFileFriendlyName`, `saipFileGlyph`, `saipBuildVirtualFileImage`, `saipFileRenderGeneral`, `saipFileRenderData`, `saipFileRenderAccess`, `saipHexBytes`. **State delta**: `commandState.saipWorkbench.<package>` gains `activeFileTab` (default `"general"`) + `fileTreeCollapsed` (`{}` keyed by node id). **CSS additions** (every selector references existing tokens — Nord dark/light, 1oT dark/light, Matrix all inherit for free): `.saip-file-tree{…}` + `.saip-file-tree--root` (font / gap), `.saip-file-node{…}`, `.saip-file-node-row{…}` (with `.is-active` accent ring), `.saip-file-caret{…}` (with `.saip-file-caret--leaf` invisible spacer), `.saip-file-glyph{…}` + 5 family-coloured variants (`--section`, `--mf`, `--adf`, `--df`, `--ef`), `.saip-file-label`, `.saip-file-fid` (mono FCP-tag-83 badge), `.saip-file-sfid` (accent-tinted FCP-tag-88 badge), `.saip-hexdump{…}` (mono 11 px / 1.5 line height / max-height 480 px scroller / surface-tinted background) — sized so a 480-byte EF.IMSI dump fits without scrolling on a 13" laptop. **Verification**: `node --check` clean on `app.js` (~14 700 lines); backend smoke (`yggdrasim_common.gui_server.actions.saip` + `yggdrasim_common.gui_server.app`) imports clean; existing GUI-SAIP backend tests all green (`tests/test_gui_saip_tolerant_loader.py` 19 cases, `tests/test_gui_saip_decoded_edit.py` 19 cases, `tests/test_gui_saip_pysim_compat.py` 6 cases). Tree heuristic exercised against `Workspace/SAIP/profile/transcoded/1oT_test_profile.transcode.der` (71 file rows across 5 sections) — produces the expected MF/EF.* + DF.TELECOM/{EF.*, DF.PHONEBOOK/EF.*} + ADF.USIM/EF.* + ADF.OPT-USIM/EF.* (no container row, EFs land directly under the synthetic section root) + DF.GSM-ACCESS/EF.* hierarchy with no ordering or attribution surprises. All editors remain read-only in this slice; SA-G3.5 — typed ARR record edits + `securityAttributesReferenced` write-back — is queued. Slices SA-G4 (`saip.list_applications` backend + Applications tab body), SA-G5 (validation bottom dock with click-to-jump), and SA-G6 (variable editor polish + ribbon shortcuts) are queued. |
| 2026-04-28 | **SAIP Workbench SA-G4 — `saip.list_applications` backend + Applications tab body.** Slice 4 of 6 lands the dedicated Applications surface so the tab stops being the SA-G1 placeholder. **Backend**: a new `saip.list_applications` action (`_dispatch_list_applications` + `LIST_APPLICATIONS_SPEC`, total SAIP inventory now 19) enumerates every application-instance-bearing PE — Security Domains (`securityDomain`), MNO-SDs (`mnoSD` / `mno-sd`), Supplementary SDs (`ssd`), JavaCard applications (`application`), and the remote management surfaces (`rfm` / `ram`). PE-type membership is consulted via `_APP_PE_TYPES` (lowercase frozenset; PE types are case-folded before lookup so `securityDomain`, `securitydomain`, and `MNO-SD` are all recognised — a regression I caught + tested for after the first integration sweep). For each row we surface (a) Instance / Class / Load Package AIDs — looked up under `instance.<field>` for SD / Application PEs and falling back to the top-level `<field>` for RFM / RAM (which flatten the bookkeeping per ETSI TS 102 226); (b) the decoded `applicationPrivileges` flag list — `_decode_gp_privileges` walks the 20 known bits per GP Card Spec 2.3 §6 Table 6-1 (Security Domain / DAP Verification / Delegated Management / Card Lock / Card Terminate / Card Reset / CVM Management / Mandated DAP Verification / Trusted Path / Authorized Management / Token Verification / Global Delete / Global Lock / Global Registry / Final Application / Global Service / Receipt Generation / Ciphered Load File Data Block / Contactless Activation / Contactless Self-Activation), tolerating embedded whitespace + dash separators in the hex input; (c) the decoded lifecycle state — `_decode_gp_lifecycle` picks the SD or Application table per GP §11.1.1 based on the parent PE type (SD: INSTALLED 0x01 / SELECTABLE 0x07 / PERSONALIZED 0x0F / LOCKED 0x83 / TERMINATED 0xFF; App: INSTALLED 0x03 / SELECTABLE 0x07 / PERSONALIZED 0x0F / LOCKED 0x83 / TERMINATED 0xFF); (d) the `applicationSpecificParametersC9` blob (full-fidelity hex); (e) the nested `applicationParameters` map (UICC toolkit / CRS / EAC slots — surfaced verbatim so the GUI can render whichever flavour the package carries); (f) the RFM / RAM TAR list (`tarList[*]` decoded into 3-byte uppercase TAR chips per ETSI TS 102 226 §5.1.1); (g) the `keyList` size; (h) `is_security_domain` flag for the colour treatment. Hex values traverse a single extractor `_hex_value(value)` that handles pySim's `{"hex": ..., "label": ...}` envelope, plain strings, raw bytes / bytearrays, and `None` so callers don't have to special-case which variant they got. **Frontend**: `renderSaipApplicationsTab` is rebuilt around `pkg.applications` (cached row array from the new dispatcher; first paint triggers `saipLoadApplications` + a re-render once the fetch resolves; subsequent tab switches are instant). The placeholder 5-column table is replaced with a vertical card list (`.saip-apps-cards > .saip-app-card`), one card per application. Each card carries (1) a header line with the type icon (large variant via `.saip-pe-icon--lg`, family-coloured per the SAIP_PE_REGISTRY), the friendly type name (Security Domain / MNO Security Domain / Supplementary SD / Application / Remote File Mgmt / Remote App Mgmt), the PE index + raw type sub-label, a colour-coded lifecycle chip (`.is-personalized` / `.is-installed` / `.is-locked` / `.is-unknown` — fixed traffic-light tints, not the workbench accent, so the semantic is preserved across all five themes), and a per-card `Open in PE tab` jump button; (2) an AID grid (Instance / Class / Load Package, monospace + `saipFormatHexPretty` byte-grouping for legibility); (3) a `Privileges (N)` chip strip when the privilege byte set yielded any flags, with the raw hex shown in subdued mono next to the strip; (4) a `TARs (N)` chip strip when the row carries RFM / RAM TARs, with each chip tinted in the template-blue family (different from privileges so the RFM/RAM context reads at a glance); (5) a footer chip strip with the key count (`🔑 N keys`), the C9 hex blob, and the application-parameter slot count (slot names + hex revealed in the chip's title). The whole card is clickable and routes to the matching PE in the Profile Elements tab — clicks bubble through `pkg.activeTopTab="profile_elements"` + `pkg.selectedPeIndex=row.pe_index` + `saipLoadShowPe` + `renderSaipActiveSlots`. **Refresh button** in the tab header drops `pkg.applications=null` and re-runs the dispatcher so post-edit views re-fetch from the backend; the four cache-reset sites (revert, update_file_field, raw decoded edit, structured decoded edit) all clear `pkg.applications` + `pkg.applicationsError` alongside `peRows` / `fileRows` / `validation` so the Applications tab badge count stays in sync after edits. **Top-tab badge** (`saipApplicationsCount`) prefers the backend row count once the cache is populated; falls back to the SA-G1 `peRows.has_apps` heuristic until the first fetch resolves so the badge always shows a sensible number. **State delta**: `commandState.saipWorkbench.<package>` gains `applications` (cached row array, `null` until first fetch) + `applicationsError` (last error message, `null` on success). **CSS additions**: `.saip-apps-cards`, `.saip-app-card{…}` (with `.saip-app-card--sd` 3 px green left border for Security Domain rows), `.saip-app-card-head` / `.saip-app-card-title` / `.saip-app-card-type` / `.saip-app-card-sub`, `.saip-app-lifecycle{…}` with four flavour modifiers, `.saip-app-aid-grid` (CSS `display: contents` rows so the 2-column label/value grid stays hard-aligned without nested wrappers), `.saip-app-privs{…}` / `.saip-app-tars{…}` / `.saip-app-priv{…}` (with `.saip-app-priv--tar` template-blue tint), `.saip-app-foot-chip{…}` (with `.saip-app-foot-chip--mono` for the C9 hex chip). Every selector uses the existing `--accent` / `--surface` / `--surface-alt` / `--border` / `--fg` / `--fg-muted` / `--mono` tokens — Nord dark/light, 1oT dark/light, and Matrix all inherit the styling for free; the lifecycle / TAR family colours intentionally use fixed tints (rgba literals) since they encode semantic state that must read identically across themes. **Tests** — `tests/test_gui_saip_list_applications.py` (31 cases): hex extractor (None / string / dict envelope / dict-without-hex / bytes / bytearray / unrecognised input), privilege decoder (empty / odd-length / single-byte SD / single-byte Card Lock + Terminate / 3-byte ISD canonical 82DC20 / case normalisation / whitespace tolerance), lifecycle decoder (empty / SD-PERSONALIZED / App-SELECTABLE / unknown-value / PE-type case normalisation / Application-PE coverage), type registry contract (lowercase guarantee for SD set, App set coverage, friendly map coverage, label examples), dispatcher integration against the in-tree reference profile (session-id required, 2 rows for `1oT_test_profile.transcode.der`, SD row shape with `82DC20` privilege expansion + 12-key keylist + PERSONALIZED lifecycle, RFM row falls back to top-level `instanceAID` + reads `tarList: [B00001]` + friendly type "Remote File Mgmt", determinism on repeated calls), spec registration (registry lookup, id / subsystem / output-kind / requires-card / tag contract). **Verification**: `node --check` clean on `app.js` (~14 940 lines); backend smoke (`yggdrasim_common.gui_server.actions.saip` + `yggdrasim_common.gui_server.app`) imports clean; `tests/test_gui_saip_tolerant_loader.py` 19 cases, `tests/test_gui_saip_decoded_edit.py` 19 cases, `tests/test_gui_saip_pysim_compat.py` 6 cases, plus the new 31 cases all green (75 cases total across the four GUI-SAIP backend test files). Slices SA-G5 (validation bottom dock with click-to-jump) and SA-G6 (variable editor polish + ribbon shortcuts) are queued. |
| 2026-04-28 | **SAIP Workbench SA-G5 — validation bottom dock with click-to-jump.** Slice 5 of 6 graduates the validation surface from a always-visible static panel into a proper Comprion-inspired collapsible bottom dock with severity filtering and per-finding click-to-jump. **Backend**: `_dispatch_validate` is extended with two helpers — `_build_validation_jump_indexes(handle)` returns a `pe_index_by_section` map (every PE registered under both its lowercase `type` and any `section_key` / `section` / `key` attribute it carries — case-folded so the linter's `Header` / `header` drift doesn't break lookups) plus a `file_keys` frozenset of `(section_key, field_path)` tuples sourced from `_file_definitions(decoded_document)`; and `_resolve_finding_target(path_text, pe_index_by_section, file_keys)` which maps the linter's `path` strings onto optional `pe_index` / `section_key` / `field_path` enrichments. Recognised path conventions: `""` / `"sections"` / `"PE-order"` / `"document"` / `"summary"` (case-insensitive) → non-routable, `{}` returned; `"service:<name>"` → non-routable rollup, `{}` returned; `"<section>"` → anchors on the matching PE (`pe_index` + `section_key`); `"<section>.<field>"` → anchors on the PE, and if the (section, field) tuple matches a known file row also surfaces the file route (`field_path`); `"<section>::<field>"` → explicit file-key form (forward-compat for a future linter emission style) — both routes when known; multi-segment dotted paths (`a.b.c`) anchor on the first segment so paths like `header.connectivityParameters.spnDisplayCondition` still land on the header PE. The minimal-key contract (only emit `pe_index` / `section_key` / `field_path` when they actually resolve to a target — never `None` / `""`) keeps the frontend's "is this clickable?" check a one-liner: `finding.pe_index !== undefined`. **Frontend**: `renderSaipValidation` is rebuilt around a single `.saip-val-dock` element. The header (`.saip-val-dock-header`, a full-width `<button>` so keyboard users get the toggle for free) is always visible and carries (a) a caret glyph (`▼` expanded / `▶` collapsed) + the static "Validation" title; (b) a score chip (`score N` / `running…` / `not run yet` / `error`); (c) the four-severity summary chip strip (`FAIL N` / `WARN N` / `INFO N` / `PASS N` — visible in both states so a glance tells the operator if anything is on fire); (d) a tools span (Validate / Re-validate button + strict toggle) with `event.stopPropagation()` on every interactive child so clicks don't accidentally collapse the dock. Clicking the header anywhere else flips `pkg.valDockCollapsed` and re-renders. The body (`.saip-val-dock-body`, only rendered when expanded) carries: (1) a severity filter row (`.saip-val-filters` — four `.saip-val-filter` toggle pills, one per severity, with per-severity counts pulled from the linter summary; default is `fail/warn/info=on, pass=off` since operators usually want to see what's wrong, not what's right; clicking a pill flips its state and re-renders); (2) the findings table — same 5-column layout as before (Severity / Code / Spec / Path / Message) plus a **6th Jump column** that surfaces a `Jump → PE` or `Jump → file` button per finding when `saipFindingJumpKind(finding)` resolves the target. **Click-to-jump** routing: file targets flip `pkg.activeTopTab="file_system"` + seed `pkg.selectedFileKey="<section>::<field>"` + force-expand the parent section in `pkg.fileTreeCollapsed` + dispatch `saipLoadShowFile` + re-render so the operator lands on the General sub-tab of the matching file; PE targets flip `pkg.activeTopTab="profile_elements"` + seed `pkg.selectedPeIndex` + dispatch `saipLoadShowPe` + re-render. **Auto-validate**: `pkg.valAutoRunPending` is set to `true` on package open and on every cache reset (revert / update_file_field / decoded edit — three sites in total) so the dock self-fires `saip.validate` on the first paint where `pkg.validation` is `null`; the flag is cleared as soon as the request is dispatched so re-renders during the in-flight roundtrip don't pile on duplicate calls. **State delta**: `commandState.saipWorkbench.<package>` gains `valDockCollapsed: false` (default expanded), `valSeverityFilter: { fail: true, warn: true, info: true, pass: false }`, and `valAutoRunPending: true`; the "is the linter running?" status is implied by `(!pkg.validation && !pkg.validationError && !pkg.valAutoRunPending)` so we don't need a separate flag. **CSS additions**: `.saip-val-dock` (border + radius + flex column, `.is-collapsed` drops the header bottom border for a flush look), `.saip-val-dock-header{…}` (full-width button styled to look like a toolbar header — hover tint via `--surface`), `.saip-val-dock-caret`, `.saip-val-dock-title`, `.saip-val-dock-spacer` (flex-grow to push tools to the right), `.saip-val-dock-body{…}` (flex column with 10 px gap), `.saip-val-filters{…}` + `.saip-val-filters-label` + `.saip-val-filter{…}` (pill button with `.is-on` opacity flip and per-severity tinted background — fail / warn / info / pass each get a 16% rgba background + matching coloured border when on, neutral surface when off), `.saip-val-jump-col` (auto-width column header), `.saip-val-jump-cell` (right-aligned cell), `.saip-val-jump` (smaller padding for inline use). The score chip gains a `.is-err` modifier (red fail-tint) for the error state. Existing `.saip-val-summary` / `.saip-val-chip` / `.saip-val-table` / `.saip-val-row` / `.saip-val-sev` / `.saip-val-clean` / `.saip-val-strict` styles are reused verbatim — every selector references the existing `--accent` / `--surface` / `--surface-alt` / `--border` / `--fg` / `--fg-muted` tokens so all five themes (Nord dark/light, 1oT dark/light, Matrix) inherit for free. **Tests** — `tests/test_gui_saip_validation_jump.py` (22 cases): `_build_validation_jump_indexes` (lowercase-key guarantee, canonical PE-type coverage, file-key canonical-case + `mf::ef-iccid` + `usim::ef-imsi` presence), `_resolve_finding_target` (empty path, well-known non-routable paths via parametrize — `sections` / `PE-order` / `document` / `summary` / case variants, `service:` rollups, bare section, `<section>.<field>` PE-only resolution when file unknown, `<section>.<field>` dual PE+file resolution when file known, explicit `<section>::<field>` form, multi-segment dotted paths anchoring on first segment, unknown section fall-through, case normalisation), dispatcher integration against the in-tree reference profile (ICCID findings carry `pe_index=0` + `section_key="header"`, `PE-order` findings have no jump target, `service:` findings have no jump target, minimal-key contract — no `None` / `""` enrichments). **Verification**: `node --check` clean on `app.js` (~15 100 lines); backend smoke (`yggdrasim_common.gui_server.actions.saip` + `yggdrasim_common.gui_server.app`) imports clean; `tests/test_gui_saip_tolerant_loader.py` 19 cases, `tests/test_gui_saip_decoded_edit.py` 19 cases, `tests/test_gui_saip_pysim_compat.py` 6 cases, `tests/test_gui_saip_list_applications.py` 31 cases, plus the new 22 cases all green (97 cases total across the five GUI-SAIP backend test files). Slice SA-G6 (variable editor polish + ribbon shortcuts) is queued. |
| 2026-04-28 | **SAIP Workbench SA-G6 — variable editor polish + ribbon keyboard shortcuts.** Slice 6 of 6 — the final SA-G slice — promotes the variable surface from a one-way set form to a full per-override edit-and-rollback experience and ships the keyboard accelerators that snap the ribbon's most-used commands onto the operator's fingertips. **Backend** — a new `saip.reset_variable` action (`_dispatch_reset_variable` + `RESET_VARIABLE_SPEC`, total SAIP inventory now 20) takes a single `(session_id, name)` pair, normalises the name through `Tools.ProfilePackage.saip_profile_template.normalize_placeholder_name` (handles brace / bracket wrapping like `{ICCID}` / `[IMSI]`), looks the override up in `handle["applied_overrides"]`, and reloads the on-disk source via `_reload_source_into_handle` (which already wipes `dirty_pes` + `applied_overrides`). The remaining overrides — every other key/value that was in `applied_overrides` before the reset — are then replayed against the freshly reloaded document via `apply_placeholder_overrides_to_loaded_document` and the session's `applied_overrides` map is rebuilt to mirror that exact set, the `pes` sequence is rebuilt via `build_profile_sequence_from_document`, and `_mark_dirty(handle, -1)` flags the whole sequence so the GUI's cache-clearing flows still trigger. A no-op path returns `removed=False` + a friendly summary when the named variable was never overridden, so a sibling-tab race doesn't surface as an error. Re-encode failures after the replay are reported via a `warnings` list on the response (the document mutation is preserved so the operator can still see what happened). Spec is registered with `tags=("saip", "variables", "write")` so the GUI's confirmation flow knows it's a write operation. **Frontend variable editor** — `renderSaipVariablesPane` is rewritten around three sections: (1) a header strip that carries a "Reset all (N)" button when there are overrides currently applied — chains `saip.reset_variable` calls *sequentially* (not concurrent — the backend's reload-then-replay would race the `applied_overrides` map otherwise), behind a `window.confirm` so the operator doesn't lose work to a misclick; (2) the variables table — five columns (Name / Value / Kind / State / Actions). Kind cells get colour-coded chips: ICCID → green-tint "ICCID (BCD)", IMSI → blue-tint "IMSI (BCD)", hex / bcd → accent-tint, text → warn-tint, anything else → neutral. State cells stack three optional chips: `override` (warn-tint, only when `applied_overrides` contains the row's name), `defined` (accent-tint, when the row appears in `__ygg_token_defs__`), `used` (success-tint, when the placeholder appears in the document body). Rows that carry an override get a 2 px warn-tinted left border + a faint warm background so they read at a glance. Actions cell carries a per-row "Reset" button whenever the row is currently overridden — wired to `saipResetVariable` which calls `saip.reset_variable`, drops the same caches the apply path drops (peRows / fileRows / showPeCache / showFileCache / validation / variables / applications + flips `valAutoRunPending=true`), refreshes the dirty markers, re-renders the drawer + active slots + modal host, and emits the backend `summaries` / `warnings` to the log dock; (3) the set-/-update form — a real `<form>` element so Enter submits cleanly, with a `<datalist id="saip-vars-name-list">` populated from the variable rows so the name input gets free autocomplete from the placeholder set, an `input` listener on the name field that auto-fills the value box from `overrides_applied` when the operator picks an already-overridden name, and a one-line hint that surfaces the three relevant shortcuts ("⏎ to apply · Esc to close · Ctrl+E to reopen"). The name field receives focus on first paint via `setTimeout(focus, 0)` so a Ctrl+E lands the operator straight in the input. The pane also handles the orphan case where a variable lives only in `applied_overrides` and not in the document scan — those rows are spliced into the table after the document-driven rows so the operator sees every override regardless of provenance. **Modal header polish** — the `Variable editor` modal title row gains a `.saip-modal-title-wrap` flex container that hosts three new chips next to the package filename: an override count (`N override(s)`, accent-coloured), the placeholder style (mono, `brace` / `bracket`), and the total placeholder count (muted). Close button tooltip now reads `Close (Esc)` so the binding is self-documenting. **Ribbon keyboard shortcuts** — a single document-level capture-phase keydown handler (installed once via `installSaipKeyboardShortcuts`, idempotent through a `document.__saipShortcutsInstalled` sentinel so re-renders don't pile up duplicates) routes the following bindings while the SAIP workbench is the active visible view (gated on `section.view.view-active .saip-workbench` to avoid sibling-workbench cross-talk): **Ctrl/Cmd+O** focuses the Open path input in the drawer (delegates to `saipFocusOpenForm`); **Ctrl/Cmd+S** focuses the Save destination input (delegates to `saipFocusSaveForm`); **Ctrl/Cmd+E** opens the Variable editor modal; **Ctrl/Cmd+Shift+V** runs the linter against the active package; **Ctrl/Cmd+.** toggles the SA-G5 validation dock collapse; **Esc** closes the variable modal when it's open (passes through otherwise so toast / popover dismissal stays intact). The handler short-circuits when the SAIP view isn't visible, when there's no active package for the action that needs one, or when the matching DOM element doesn't exist (so a future layout that drops a form fails open rather than swallowing the keystroke). Ribbon button tooltips updated to advertise the bindings — Open: "(Ctrl+O)", Save: "(Ctrl+S)", Variable editor: "(Ctrl+E)", Validate: "(Ctrl+Shift+V)". **State delta** — none beyond the existing `pkg.variables` cache; `applied_overrides` is now sourced from the backend response (`payload["overrides_applied"]` from `saip.list_variables`) instead of being inferred client-side. **CSS additions** — `.saip-vars-head-tools{…}` (right-aligned button strip in the header), `.saip-vars-reset-all{…}` (small bulk-reset button with smaller padding for inline density), `.saip-vars-row.is-overridden{…}` (warm background + 2 px warn-tinted left border on the first cell so overridden rows read at a glance), `.saip-vars-kind{…}` + four family-coloured modifiers (`.saip-vars-kind--iccid` green, `.saip-vars-kind--imsi` blue, `.saip-vars-kind--hex` / `.saip-vars-kind--bcd` accent, `.saip-vars-kind--text` warn — pill-shaped 10 px / weight 600 / 0.04em letter-spacing), `.saip-vars-state{…}` + `.saip-vars-state-chip{…}` with three semantic flavour modifiers (`.is-override` warn-tint, `.is-defined` accent, `.is-used` success), `.saip-vars-actions-col{…}` / `.saip-vars-actions-cell{…}` (auto-width right-aligned action column), `.saip-vars-reset{…}` (per-row reset button, smaller density), `.saip-vars-actions{…}` (form submit row, gap 10 px), `.saip-vars-hint{…}` (italic muted shortcut hint). Modal header gains `.saip-modal-title-wrap{…}` (flex-grow wrapper) + `.saip-modal-stats{…}` + `.saip-modal-stat-chip{…}` with two modifiers (`.saip-modal-stat-chip--mono` for the style chip, `.saip-modal-stat-chip--muted` for the total-count chip). Every selector references the existing `--accent` / `--accent-soft` / `--surface` / `--surface-alt` / `--border` / `--fg` / `--fg-muted` / `--mono` tokens so all five themes (Nord dark/light, 1oT dark/light, Matrix) inherit the styling for free; the kind / state colour families intentionally use fixed rgba tints (warn / success / info) since they encode semantic state that must read identically across themes. **Tests** — `tests/test_gui_saip_reset_variable.py` (13 cases): argument validation (missing session_id, missing name, whitespace-only name — all three raise `ValueError` with explicit messages), no-op semantics (unknown variable → `removed=False` + friendly summary, no-op leaves other overrides intact), single-override rollback (ICCID / IMSI / brace-wrapped names — every form lands on the same canonical key after `normalize_placeholder_name`), multi-override rollback (two overrides set → reset one → other remains; cascade reset both back to clean state), spec registration (registry lookup, required inputs, write-tag advertisement). **Verification** — `node --check` clean on `app.js` (~21 015 lines); backend smoke (`yggdrasim_common.gui_server.actions.saip` + registry lookup of `saip.reset_variable` + `yggdrasim_common.gui_server.app`) imports clean; `tests/test_gui_saip_tolerant_loader.py` 19 cases, `tests/test_gui_saip_decoded_edit.py` 19 cases, `tests/test_gui_saip_pysim_compat.py` 6 cases, `tests/test_gui_saip_list_applications.py` 31 cases, `tests/test_gui_saip_validation_jump.py` 22 cases, plus the new 13 cases all green (110 cases total across the six GUI-SAIP backend test files). The SAIP workbench redesign (SA-G1..SA-G6) is now feature-complete and ready for operator feedback ahead of the V1.6 release. |
| 2026-04-23 | **SCP03 per-reader persistence + pill-click session resume.** Two operator reports landed together: (1) "with the new reader layout/structure SCP03 no longer resolves the GUI/data — files are now not found/read", and (2) "make the GUI remember the state of each reader so when you toggle between them you are returned to where you left off." Root cause of (1) was `scp03OpenSessionForTab`'s `if (!target) return;` guard — the welcome panel's "Open default reader" button dispatched with `pendingReader = ""` and the function silently no-op'd, so after the top-bar strip started creating unbound tabs the only way to actually open a session was to click a specific reader pill (the old left-sidebar UX was "click any reader → scan starts", which the pill strip dropped). The guard is gone — `scp03.scan` is dispatched unconditionally, empty `reader` falls through to backend index 0 (which is how the CLI path works too). Pill clicks now also auto-open the session for **yellow** pills (card present, no session, no hydrated cache, not already scanning) via a `setTimeout(..., 0)` after `readerBarActivate` repaints — mirrors the old sidebar's "click a reader = scan starts" snap-back. (2) ships as a proper per-reader `localStorage` layer: new helpers `scp03PersistTab(tab)` (writes `ygg.scp03.tab.<readerName>` — `readerName` / `atrHex` / `scanData` / `selectedPath` / `previewCache` / `fcpCache` capped at `SCP03_PERSIST_MAX_CACHE=50` newest-first by `capturedAt` / `activeRibbonTab` / per-tab APDU-console state — explicitly **not** `sessionId` / `status` / `error` because those are backend-owned and go stale on reload), `scp03LoadPersisted(readerName)` (version-pinned at `SCP03_PERSIST_VERSION = 1`; mismatched payloads are dropped silently so schema bumps don't crash old clients), `scp03HydrateTabFromPersisted(tab, persisted)` (restores the frozen fields and resets `sessionId=null` / `status="idle"` so the welcome panel re-appears in resume mode), `scp03PurgePersisted` (on explicit tab close), and `scp03HasPersistedState(tab)` (gate for the resume UI — requires a non-empty `scanData.tree` since fcpCache alone is useless to the welcome panel). Hydration hooks into `readerBarSyncToScp03Tab` right after `pendingReader` is set so a pill click on a remembered reader lands on the hydrated tab instead of a blank slate. Welcome panel gains a resume variant: when `scp03HasPersistedState(tab)` is true, the heading flips to "Cached session on this reader", the body copy announces "restored from last session on 'X' — N root nodes, M cached files (saved Ys ago)", the primary button becomes "Resume 'X'" (auto-sets `pendingReader` from `readerName` before dispatching scan), and a secondary "Forget cached state" button wipes `localStorage` + the in-memory scan / fcp / APDU caches. Save hooks fire on every state-changing path: successful `scp03.scan` (both `scp03OpenSessionForTab` and `scp03Rescan`), every successful `scp03.read_selected` (fresh + retry-after-recovery — `tab.selectedPath` updates alongside so reloads land on the right file), successful `scp03.recover_session` (the refreshed tree survives the reload), and ribbon tab switches (Home / Files / APDU / Admin — single-field delta, debounce-cheap). Purge hook fires only on explicit `scp03CloseTab` (pill `×` button) — "close tab" is the user's deliberate "forget this reader" gesture, whereas a page reload deliberately keeps state. Regression fallout fix: `readSelectedForTab` now emits to `logBus` on every failure path (fresh read fail, retry-after-recovery fail) with the path + backend error string so operators diagnosing a stuck read don't have to open the network tab. `scp03OpenSessionForTab` also emits on scan success / failure so the log dock shows "session ABCD1234 opened on 'Reader X' — N roots" immediately when a pill click auto-opens. Quota / private-mode safety: every `localStorage.setItem` lives inside try/catch so a `QuotaExceededError` or denied write silently drops that save round — persistence is a nicety, never a correctness gate. Covered by `tests/test_gui_scp03_tab_persistence.py` (22 cases: helper surface, key namespacing, `SCP03_PERSIST_MAX_CACHE` range check, persisted-field contract, session-ephemeral-field exclusion, fcpCache sort-and-cap, quota-safe setItem, hydration clears `sessionId` / `status` / `error`, resume gate requires non-empty tree, `readerBarSyncToScp03Tab` hydrates on tab creation, welcome panel renders Resume + Forget UI, read_selected persists on fresh + retry paths, recover_session persists refreshed tree, rescan persists, scp03CloseTab purges, ribbon tab switches persist, `scp03OpenSessionForTab` no-early-return on empty reader, scan dispatch still fires, `readerBarActivate` auto-opens yellow pills, hydrated tabs skip auto-open so operators click Resume, reader-bar repaint on session open, log-dock surfaces for failed reads + scans, `persistedAt` timestamp wiring). |
| 2026-04-28 | **SAIP Workbench SA-D1 + SA-D2 — semantic context-aware profile diff (engine + dispatchers).** Operator brief: "add a smart and context aware diffing function to the SAIP Tool so that we can compare profiles and get a semantic humanreadable contextaware output". Phase A of the SA-D series — engine + backend-only — lands ahead of the SA-D3 GUI surface to lock the data shape down. **Engine (`Tools/ProfilePackage/saip_profile_diff.py`, ~590 lines)** layers a semantic classifier on top of the pre-existing structural walker (`saip_diff_engine.diff_saip_documents`). Each raw `DiffEntry` (jq-style path + op + value_a/b) is mapped to a `ProfileDiffEntry` carrying one of ten categories — `identity` / `pe_sequence` / `files` / `applications` / `security` / `lifecycle` / `variables` / `structure` / `intro` / `other` — and one of four severities — `critical` / `warning` / `info` / `note` — alongside a friendly `section_label` (sourced from the curated `_SECTION_LABELS` map covering USIM Application / DF.TELECOM / Security Domain / RFM / RAM / etc.) and a one-line human-readable `summary` built by `_format_summary` ("USIM Application: imsi changed: 234561111111111 -> 234562222222222"). Classifier order matters: top-level paths (`intro` / `__ygg_token_defs__` / `sections.<name>` whole-PE add/remove) are caught first by `_classify_top_level_path`; then leaf-key heuristics — `_IDENTITY_LEAF_KEYS` (iccid / imsi / impi / impu / msisdn / eid / profile_name / mcc / mnc / mccmnc / homePlmn / spn) and `_SECURITY_LEAF_KEYS` (ki / k / opc / op / kic / kid / kik / kvn / scp02Key / scp03Key / scp11Key / puk1 / puk2 / ppr1 / pinAdm / adm / isdpAid) match case-insensitively and lift to `critical`; `_LIFECYCLE_LEAF_KEYS` (lifecycle / lcs / pinStatus / pin1 / pin2 / pukStatus / lifeCycleStatus) lift to `warning`. PE-section context fills the rest: AID rotations under USIM / ISIM / CSIM PEs lift to `applications` / `critical`; `akaParameter` / `5gAuthParameter` / `cdmaParameter` PEs default to `security` / `critical` even when the leaf key is generic (e.g. `sqn`); file-management PEs (`mf` / `cd` / `telecom` / `phonebook` / `df-eap` / `df-5gs` / `df-saip` / `df-tetra` / `genericFileManagement`) default to `files` / `info` (or `warning` for top-level add/remove). PE-sequence additions are `warning`; PE-sequence removals lift to `critical` because losing a whole PE is a semantic loss. Output is a `ProfileDiffReport` with `entries` (sorted critical-first / category / path so two diffs of the same documents always render byte-identical for golden-file CI), `counts_by_category` and `counts_by_severity` lookups, `structural_summary` pass-through (so callers that need raw walker output don't re-run it), and `section_reorder_a` / `_b` tuples populated when the top-level dict ordering differs (only — equal-order skips them). `to_dict()` emits a JSON-friendly payload with bytes encoded as `{"__hex__": "...", "length": N}` envelopes so the GUI transport stays JSON. `format_profile_diff_text(report)` renders a plain-text block (severity counts, category counts, section reorder banner if any, then one line per entry with op-glyph + category tag + summary + jq-path for grep-ability) for terminal / test / CI use. **Dispatchers (`yggdrasim_common/gui_server/actions/saip.py`, +~190 lines)** ship three new actions hung off the engine. `saip.diff_packages` mirrors the legacy `saip.compare` input shape (two `session_id`s) but returns the categorised payload — the legacy action stays in place so callers depending on its raw PE/file row shape don't break. `saip.diff_against_source` takes a single `session_id`, re-loads the on-disk source via `_load_package_from_path` (so unsaved edits + applied placeholder overrides on the live session show up as the right side), and labels the banners `"<filename> (on disk)"` / `"<filename> (session edits)"` so the operator never has to guess direction. `saip.diff_against_path` takes `(session_id, path)` and accepts the same DER / hex-text / JSON inputs as `saip.open_package` — useful for comparing the current edits to a known-good vendor DER. All three jsonify the decoded document via `saip_json_codec.jsonify_document` before handing it to the engine so shape parity with both sides of any comparison is automatic. Total SAIP inventory now 23 actions (was 20 after SA-G6); registry-listed in the existing block right after `COMPARE_PACKAGES_SPEC`. **Tests** — `tests/test_saip_profile_diff_engine.py` (24 cases): identity classifier (ICCID change in header / IMSI change under USIM / profile_name → identity), security classifier (Ki under USIM / OPc inside akaParameter PE → critical security), PE-sequence classifier (added → warning / removed → critical / section reorder captured on report), files classifier (mf value change → files info), applications classifier (AID change under USIM → critical applications), top-level classifier (intro addition → note / token_def change → variables), empty-and-identity contracts (identical documents → empty report / `format_text` empty-banner / `format_text` summary lines with both labels + critical severity + iccid in summary), sorting + filter helpers (severity-first sort regardless of insertion order / category filter intersection / severity filter intersection), serialisation (round-trip keeps required keys / bytes serialise as `__hex__` envelope), type guards (rejects non-dict left / non-dict right), public-constants sanity. Plus `tests/test_gui_saip_diff.py` (19 cases): `saip.diff_packages` argument validation (missing session_a / missing session_b / same session) + happy path (two pristine sessions → empty report / `set_variable` lands as variables-category — pinned because the override stamps `__ygg_token_defs__` instead of rewriting in-place ICCID bytes, resolution happens at encode time / direct decoded-document mutation lands as pe_sequence — exercises the engine through the live dispatcher path / response carries structural counts); `saip.diff_against_source` argument validation (missing session_id / handle-without-source-path → RuntimeError) + happy path (unedited session → empty report / post-edit session → variables diff with "on disk" / "session edits" labels); `saip.diff_against_path` argument validation (missing session_id / missing path / nonexistent path → FileNotFoundError) + happy path (session vs. same file → empty report / session-with-override vs. clean file → variables diff with target filename in label_b); spec registration (all three reachable through registry, correct subsystem / output_kind / tag set / required input fields). 43 new test cases total, all green; existing `test_gui_saip_reset_variable.py` (13 cases) + `test_gui_saip_validation_jump.py` (22 cases) re-run clean. **Verification** — engine import smoke (`compute_profile_diff` + `format_profile_diff_text` + `classify_diff_entry` + all CATEGORIES + SEVERITIES) clean; dispatcher smoke (`_dispatch_diff_packages` + `_dispatch_diff_against_source` + `_dispatch_diff_against_path` + their three SPEC objects via `get_registry().get(...)`) clean; legacy `saip.compare` action and existing SA-G6 tests untouched. **SA-D3 (Frontend ribbon Compare button + modal source picker + collapsible diff results pane with severity / category chips and click-to-jump to the matching PE / file in the workbench)** is the next slice and is queued pending operator sign-off — the SA-D1 + SA-D2 surface is operator-callable today via the action registry / Command Center / CLI for headless / CI use. |

| 2026-04-28 | **Card Bridge CB-1 + CB-2 — remote PC/SC over SSH-tunnelled HTTP relay.** Operator brief: "since we are adding an HTTP-server support in v2, can we also make it so that we can pipe card data over that bridge? Meaning that I can have the tool running on my raspberrypi for example, plug the card into the pcsc slot in my PC and it will stream the transactions over the bridge?" — followed by an explicit security gate ("once security is green, ie we handle the stream encryption with ssh keys then we are good to implement"). The deployment topology is therefore deliberately *SSH-tunnel-first*: the Card Bridge daemon binds to `127.0.0.1` on the reader-side machine, an SSH `LocalForward` (`ssh -fN -L 8642:127.0.0.1:8642 <pc-host>`) carries the stream, and OpenSSH owns confidentiality / integrity / peer authentication. The bridge's own bearer token then layers belt-and-braces authorization on top so a multi-user PC scenario can't sidestep the SSH gate via a sibling account on loopback. **CB-1 (`Tools/CardBridge/`)** ships the standalone daemon — `python -m Tools.CardBridge …` — built on top of the existing `Tools/HilBridge/apdu_relay.HilBridgeApduRelayService` and `Tools/HilBridge/pcsc.PcscCardChannel`. CLI flags cover bind host (default `127.0.0.1`, refuses anything else without a token), TCP port (default 8642), reader index / name, token file (auto-generated 0600 under `${XDG_CONFIG_HOME:-~/.config}/yggdrasim/card_bridge/<port>.token` if absent), `--no-token` for the back-compat loopback path, audit toggles (`--audit` / `--audit-full-apdu`), and audit-logger naming. The daemon prints a redacted startup banner (token fingerprint only — never the token), wires `SIGINT` / `SIGTERM` for clean teardown, and exits non-zero with an explicit usage message on misconfiguration. **CB-2** ships the auth + audit + throttle hardening shared by both the standalone daemon and the in-tree HilBridge relay. New shared utilities live in `yggdrasim_common/card_bridge_auth.py` (~210 lines) — `generate_token()` (32 byte URL-safe base64), `fingerprint()` (6-char SHA-256 truncation), `compare()` (constant-time via `hmac.compare_digest`), `parse_bearer_header()`, `default_token_file_for_port()` / `write_token_file()` / `read_token_file()` (open-truncate-write-chmod dance honouring inherited umasks), `resolve_token_from_environment()` (env var → token file precedence), `is_loopback_host()` (handles `127.0.0.0/8` + `::1` + `localhost` aliases). `Tools/HilBridge/apdu_relay.py` is extended with: an `ApduRelayConfig.auth_token` field plus the per-peer throttle parameters (`auth_lockout_failures` / `auth_lockout_window_seconds` / `auth_lockout_duration_seconds`) and audit knobs (`audit_enabled` / `audit_full_apdu` / `audit_logger_name`); a `_PeerThrottle` thread-safe sliding-window throttle keyed by client IP (3 failures inside 30 s → 60 s lockout, success clears the failure log); a hardened `_ApduRelayHandler._enforce_authorization()` that runs `is_locked` → expected-token-empty (loopback-only) → bearer parse → constant-time compare → success / 401 / 429 — applied uniformly to `/apdu`, `/status`, `/modem/refresh` (the `/ping` liveness route stays open since it returns no card data); a `HilBridgeApduRelayService.start()` hard refusal when `host` is non-loopback **and** `auth_token` is empty (no `--unsafe-bind` escape hatch by design — the rule cannot be bypassed); a `record_apdu_audit` emitter that produces a structured per-APDU log record carrying `peer / session / cla / ins / p1 / p2 / lc / sw / latMs / respLen` (header bytes only — never APDU data or response bodies, those require an explicit `audit_full_apdu` opt-in with a startup banner warning); and a `status_payload` extension that surfaces `authRequired` + `tokenFingerprint` so SSH-tunnelled consumers can verify they're hitting a daemon that requires a token without ever seeing the token itself. Client side, `yggdrasim_common/card_backend.RelayCardConnection` gains an optional `auth_token` constructor argument that propagates to every outbound HTTP call as `Authorization: Bearer <token>`; `_resolve_card_relay_token()` resolves the token from `YGGDRASIM_CARD_RELAY_TOKEN` (raw value), `YGGDRASIM_CARD_RELAY_TOKEN_FILE` (preferred — keeps the token out of `ps` output), or — when sourced from the existing runtime marker (`hil_bridge_card_relay.json`) — its optional `token` / `tokenFile` fields. `create_card_connection()` and `trigger_card_relay_modem_refresh()` both consult the resolver so all in-tree consumers (HilBridge auto-discovery + explicit `YGGDRASIM_CARD_RELAY_URL` setups + the new SSH-tunnelled deployment) inherit the bearer plumbing transparently. **Security posture** (operator-facing summary, also captured in `guides/CARD_BRIDGE_GUIDE.md`): confidentiality + integrity + mutual auth → OpenSSH transport (ChaCha20-Poly1305 / AES-GCM); authorization → bridge bearer token (32 bytes, 0600 file, fingerprint in logs only); network exposure → loopback-only by default, refuses non-loopback bind without a token; replay protection → SSH sequence numbers per session; DoS resistance → per-peer auth-failure rate limit + 60 s lockout; audit → header-only structured log on the bridge + SSH `sshd` access log; secrets in logs → token never logged beyond fingerprint, APDU bodies redacted unless `--audit-full-apdu` is explicitly enabled (with a banner-level warning). **Tests** — four new files, 67 cases total: `tests/test_card_bridge_auth.py` (31 cases — token gen / fingerprint / constant-time compare / bearer header parse / token file read+write+permissions / XDG-aware default location / env resolution precedence / loopback host classifier across IPv4 / IPv6 / `127.0.0.0/8`); `tests/test_hil_bridge_apdu_relay_auth.py` (12 cases — non-loopback-without-token startup refusal / unauth POST → 401 / wrong token → 401 / correct token → 200 with response body / status endpoint also requires bearer / status payload exposes `authRequired` + `tokenFingerprint` / ping stays unauthenticated / per-peer throttle locks after threshold / sliding window evicts stale failures / success resets failure log / audit record carries header bytes only / `--audit-full-apdu` includes APDU + response hex); `tests/test_card_backend_relay_token.py` (8 cases — `RelayCardConnection.transmit` attaches `Authorization: Bearer …` when token configured / omits header when absent / `_request_card_relay_json` lower-level helper sets header correctly / `_resolve_card_relay_token` env precedence / file-based env / marker token field consulted only when allow_marker / marker tokenFile field followed / empty when no source); `tests/test_card_bridge_server.py` (8 cases — `--no-token` on loopback yields empty token / `--no-token` on non-loopback refuses / token file generated on first run with mode 0600 / second run reads same token / `XDG_CONFIG_HOME` honoured / invalid port rejected / round-trip APDU through fake card channel + bearer token via running daemon / unauth request → 401 against running daemon / startup banner shows fingerprint not token). Plus regression: the historical `tests/test_hil_bridge_card_relay.py` (8 cases — loopback + no token + no auth headers, the existing single-machine HilBridge deployment) re-runs clean to pin the back-compat contract. **Documentation** — `Tools/CardBridge/README.md` (quick-reference: topology diagram, two-step quick start with the `ssh -fN -L` recipe, security posture table, CLI flag reference, wire-protocol table) + `guides/CARD_BRIDGE_GUIDE.md` (operator guide: full topology, SSH config snippets, env-var setup for `YGGDRASIM_CARD_RELAY_URL` / `YGGDRASIM_CARD_RELAY_TOKEN_FILE`, verification recipes via `curl`, audit logging walkthrough, troubleshooting table for the seven most likely operator-reported failure modes, compatibility note vs. the in-tree HilBridge marker workflow). Slice CB-3 (consumer-side ergonomics: `--remote-card-url` / `--remote-card-token-file` flags on YggdraSIM CLIs that consume cards, GUI reader-picker entry `🌐 Remote (host:port)`, doctor check for relay reachability) and CB-4 (mounting the same routes inside the v2 GUI host server with a Card Bridge panel for start / stop + clipboard URL+token + live latency) are queued. |

| 2026-04-28 | **Card Bridge CB-3 + CB-4 backend — consumer ergonomics, doctor probe, GUI surface.** Operator brief: continue the Card Bridge series with consumer-side ergonomics so YggdraSIM CLIs and the GUI can talk to a remote bridge without the operator manually exporting env vars before every invocation. **CB-3** ships in three pieces. (1) `yggdrasim_common/remote_card_args.py` (~150 lines) wraps the env knobs in argparse: `add_remote_card_arguments(parser)` registers `--remote-card-url` / `--remote-card-token-file` under their own help group, `apply_remote_card_arguments(namespace, environment=…)` mirrors the parsed values into the running process's environment so the existing `card_backend._resolve_card_relay_url` / `_resolve_card_relay_token` chain picks them up transparently downstream (no consumer-side rewrite — the flag/env transparency is by design), `describe_remote_card_state(state)` returns a one-liner banner (`remote card bridge: http://127.0.0.1:8642/apdu; token file (flag): /path/to/token`). Empty-string flag values clear the corresponding env entry so operators can override an inherited stale env from the command line, and a `--remote-card-token-file` automatically clears any leftover raw `YGGDRASIM_CARD_RELAY_TOKEN` so the file form wins. `main/main.py` wires the helper into `_build_cli_parser` + `run_cli` (with a one-line cyan startup banner emitted only when a remote bridge is actually configured). (2) `yggdrasim_common/doctor.py:_probe_card_relay()` (~120 lines) probes the configured bridge with `urllib.request` and a 2 s timeout, walking through `/ping` then `/status` with the resolved bearer token. The decision tree distinguishes seven outcomes: not configured (`info`), unreachable (`warn`), `/ping` non-200 (`warn`), `/status` 401 / token rejected (`warn`), token required but absent (`warn`), auth disabled on a non-loopback host (`warn` — refuse to use), reachable + auth ok (`ok`, with a one-liner including base URL + auth posture + token fingerprint + `audit on/off`). The probe never logs the raw token, only the 6-char fingerprint via `card_bridge_auth.fingerprint`. (3) `yggdrasim_common/gui_server/routes/live.py` extends `ReaderInfo` with `kind: str = "local"` + `source_url: str = ""` and adds `_probe_remote_bridge_reader()` which surfaces a `🌐 remote@<base-url>` row alongside local PC/SC readers in `GET /api/live/readers`. The row carries the bridge-reported ATR + reader name when reachable, or a descriptive `status` string (`remote bridge unreachable: TimeoutError`, `remote bridge online but token rejected (HTTP 401)`, `remote bridge online (no card / ATR not reported)`) so operators see *why* the bridge isn't usable without leaving the GUI. When `pyscard` is missing locally but a remote bridge is configured, `list_readers` flips to `backend="remote-only"` and returns just the remote row — the lean Raspberry Pi consumer install no longer needs `pyscard` at all. **CB-4 backend** ships `yggdrasim_common/gui_server/actions/card_bridge.py` (~330 lines) with two read-only Command Center actions: `card_bridge.status` (zero-network introspection — returns `configured` / `url` / `base_url` / `url_source` / `has_token` / `token_fingerprint` / `token_source` plus a human summary, raw token never echoed) and `card_bridge.probe` (live `/ping` + `/status` against a configured or operator-supplied URL+token, returns `ok` / `reason` / `ping_status` + `ping_latency_ms` / `status_status` + `status_latency_ms` / `auth_required` / `auth_posture` (one of `no-token-required` / `token-accepted` / `token-rejected` / `token-required-but-missing` / `auth-disabled-non-loopback`) / `token_fingerprint` + `bridge_token_fingerprint` + `fingerprint_match` (so operators can confirm the right token wired up) / `bind_host` / `audit_enabled` / `reader` / `atr_hex` / `used_configured_url` + `used_configured_token` (so the GUI can highlight when fallback resolved values were in play). 2 s timeout on the GETs caps the worst case; 64 KiB cap on the response body protects against accidental misconfigurations. The `token` form field is marked `secret=True`. The dispatcher hard-treats HTTP 401 as `auth_required=True` regardless of body content because some older relays return 401 without a JSON body. Both actions register at module-import time and `registry._load_all_action_modules` autoloads them after the `hil` actions. Local-subprocess management (start/stop a bridge from the GUI) is deliberately out of scope for this backend slice — operators run the bridge over SSH on the remote host. **Tests** — four new files, 55 cases total: `tests/test_remote_card_args.py` (25 cases — flag registration / dest names / help-group label / URL+token-file mirroring / env preservation when no flags / empty-string clearing / token-file path expansion via `~` / raw-vs-file token source attribution / regression that the parser doesn't collide with unrelated flags / round-trip against real `os.environ` via monkeypatch / state-key exhaustiveness / whitespace stripping); `tests/test_doctor_card_relay_probe.py` (9 cases — unconfigured → info / unreachable → warn / `/ping` 503 → warn / token-rejected → warn / token accepted with audit on → ok / unauthenticated non-loopback → warn / loopback no auth → ok / `/apdu` suffix stripping / completely invalid URL doesn't raise — uses `http.server.ThreadingHTTPServer` stub); `tests/test_gui_live_remote_reader.py` (6 cases, `unittest.skipUnless(fastapi)` clean — unconfigured returns None / configured online with ATR / token rejected returns 401 status text / unreachable returns descriptive status / `/apdu` suffix stripped from `source_url` / `remote-only` backend when pyscard import fails); `tests/test_gui_card_bridge_actions.py` (15 cases — STATUS_SPEC + PROBE_SPEC registry registration with token field marked secret / `card_bridge.status` unconfigured / configured with raw token / configured with token file / `card_bridge.probe` no URL → helpful reason / explicit URL no token → ok with auth posture + ATR / token accepted with fingerprint match / token rejected → 401 + `token-rejected` posture / unreachable URL → ok=False with transport class / auth-disabled non-loopback → flagged / falls back to configured URL when blank / `/apdu` suffix stripped / token never appears in serialised response / `/ping` failure short-circuits without `/status` call). Plus regression: existing `tests/test_card_bridge_auth.py` (31), `tests/test_card_backend_relay_token.py` (8), `tests/test_hil_bridge_card_relay.py` (8), `tests/test_hil_bridge_apdu_relay_auth.py` (12), `tests/test_card_bridge_server.py` (8) all re-run clean → 67 prior + 55 new = 122 Card Bridge cases all green. **Documentation** — `guides/CARD_BRIDGE_GUIDE.md` extended with a new "Inline overrides (CB-3 CLI flags)" subsection (flag examples, banner sample, empty-string clear behaviour), a "Doctor preflight" section showing the `Remote card bridge` row sample, and a "GUI surfaces (CB-4 backend)" subsection listing the two Command Center actions plus the remote-reader entry in `/api/live/readers`. **Pending** — CB-4 *frontend* (a dedicated Card Bridge panel in the GUI with start/stop a local bridge, copy URL+token to clipboard, live latency chart) is intentionally deferred to a follow-up slice so the backend contract can stabilise before the JS lands. The two new actions are operator-callable today via the action registry / Command Center / curl for headless / CI use. |

| 2026-04-28 | **Card Bridge CB-4 frontend — dedicated GUI Card Bridge panel.** Operator brief: ship the polished panel that wraps the read-only `card_bridge.status` / `card_bridge.probe` actions in a focused diagnostics surface so operators don't have to drive the Command Center generic form for everyday remote-bridge work. New view `data-view="card_bridge"` lives under the **Meta** sidebar (next to Overview / About) and is reachable via crumb `Meta · Card bridge`. **Layout** — three stacked `.cb-panel` cards: (1) "Configured target" — six-row label/value grid (Status badge, URL with Copy button, URL source, Token presence + 6-char fingerprint, Token source classifier — `YGGDRASIM_CARD_RELAY_TOKEN env` / `YGGDRASIM_CARD_RELAY_TOKEN_FILE env` / `runtime marker (auto-discovered)` / `(none)` — and Last probe timestamp), human-readable summary block ("Resolved `<url>` (via env). Bearer token wired up — fingerprint `a1b2c3`."), 5 s auto-refresh toggle (default on, pauses when the view loses focus); (2) "Live probe" — primary "Probe now" action button, collapsible URL/token override panel (token field marked `type="password"` so shoulder-surfing a screenshot still doesn't leak it), result grid with nine cards covering Posture badge / Ping latency / Status latency / Reader / ATR / Audit state / Local token fingerprint / Bridge token fingerprint (coloured green when local==bridge, amber when they differ — surfaces the "wrong token wired up" failure mode immediately) / Bind host, plus a dedicated reason banner that only renders on failure; (3) "Latency history" — inline SVG sparkline with two stacked polylines (`--cb-history-line-ping` in accent blue, `--cb-history-line-status` in `--ok` green) over a 60-sample rolling buffer (5 minutes at 5 s cadence), red dots at the bottom mark failed probes, friendly `<text>` labels show the auto-scaled y-axis ceiling (50 / 100 / 250 / 500 / 1000 / 2500 / 5000 / 10000 ms), Clear button reset the buffer. **CSS** — ~280 new lines in `app.css` covering `.cb-panel` (elevated card with shadow), `.cb-status-grid` (subgrid label/value/control), `.cb-badge` family (six variants: `cb-badge-ok` / `cb-badge-warn` / `cb-badge-fail` / `cb-badge-info` / `cb-badge-unknown` plus a leading dot via `::before`), `.cb-mono` (JetBrains Mono fallback chain), `.cb-override` (collapsible details), `.cb-probe-grid` (auto-fill grid, 180 px min column), `.cb-probe-reason` (red-soft fail surface), `.cb-history-chart` (140 px tall SVG with theme-token strokes), `.btn-small` (compact 4×10 button variant). All colours sourced from existing theme tokens (`--accent` / `--ok` / `--warn` / `--fail` / `--accent-soft` / etc.) so the panel inherits the active theme (Nord dark/light, 1oT dark/light, Matrix) without per-theme overrides. **JavaScript** — ~440 new lines in `app.js`, all in a self-contained module (closure-scoped `cbState`, `loadCardBridgeStatus`, `runCardBridgeProbe`, `renderCardBridgeStatus`, `renderCardBridgeProbe`, `cbPushHistorySample`, `cbRenderHistoryChart`, `cbStartAutoRefresh`/`cbStopAutoRefresh`, `cbCopyText` with `navigator.clipboard` primary path + `document.execCommand` textarea fallback for older browsers, `wireCardBridgePanel` event wiring). All API traffic uses the existing `apiFetch` helper so the bearer-auth + 401/429 handling is inherited. Posture badge mapping: `token-accepted` → "auth ok" (green), `no-token-required` → "no token (loopback)" (green), `token-rejected` → "token rejected" (red), `token-required-but-missing` → "token missing" (red), `auth-disabled-non-loopback` → "non-loopback w/o auth" (amber), `configured` → "configured" (blue), `not-configured` → "not configured" (grey), `unreachable` / `error` → red. Auto-refresh stops on view-leave so the GUI never polls a card bridge that the operator has navigated away from. Raw bearer tokens are never displayed in the panel — only the 6-char fingerprint surfaced by the dispatcher. **Tests** — `tests/test_gui_card_bridge_actions_http.py` (7 cases via FastAPI `TestClient` over the actual `/api/actions/card_bridge.{status,probe}/run` route — pins the wire shape the JS relies on): unconfigured status; configured status returns fingerprint without leaking the raw token; probe with no URL returns helpful reason; probe explicit URL happy path returns `auth_posture` + `atr_hex` + non-zero latency; probe wrong token returns 401 + `token-rejected` posture; unknown action returns 404; missing bearer header returns 401 from the auth middleware. All seven new HTTP tests use a fresh `tempfile.mkdtemp` for `YGGDRASIM_RUNTIME_ROOT` per case so the marker-file branch in `_resolve_card_relay_url` cannot bleed state between tests; the same isolation was retro-fitted to the existing CB-4 dispatcher tests + CB-3 doctor tests + CB-3 GUI live-reader tests after a full-suite run surfaced cross-test marker leakage. **JS validated** with `node --check app.js` (clean syntax). Full Card Bridge regression sweep (`test_remote_card_args` + `test_doctor_card_relay_probe` + `test_gui_live_remote_reader` + `test_gui_card_bridge_actions` + `test_gui_card_bridge_actions_http` + `test_card_bridge_auth` + `test_card_backend_relay_token` + `test_hil_bridge_card_relay` + `test_hil_bridge_apdu_relay_auth` + `test_card_bridge_server`) → 129 / 129 green. **Documentation** — `guides/CARD_BRIDGE_GUIDE.md` "GUI surfaces (CB-4)" section expanded with the panel layout (configured-target / live-probe / latency-history cards), auto-refresh behaviour, fingerprint-match indicator, and the override-panel password field. **Out of scope (deliberate)** — start/stop a local Card Bridge subprocess from the GUI is not part of this slice. Subprocess management requires port allocation, token-file lifecycle, reader picker, zombie cleanup on GUI shutdown, and persistent state across browser refreshes; landing it now would risk regressions in the auth path that's just stabilised. Operators run the bridge over SSH on the remote host (the documented topology), and the panel observes/diagnoses from the consumer side. A future CB-5 slice can introduce `card_bridge.start_local` / `stop_local` actions + a reader picker once the operator UX research is in. |

## See also

- `V2_ROADMAP.md` — once accepted, graduate this plan into an
  `R2-004` entry and link back here.
- `V1_FEATURE_PLAN.md` — the landed v1 feature plan pattern this doc
  mirrors in structure.
- `yggdrasim_common/registry.py` — the discoverable subsystem map the
  GUI will iterate over for its left-rail navigation.
- `yggdrasim_common/env_flags.py` — where the new `YGGDRASIM_GUI_*`
  rows land.
- `main/main.py` — entry point that gains the `--gui` and
  `--web-server` dispatch branches.
- `Tools/HilBridge/router.py`, `SCP11/eim_local/config.py`,
  `SCP11/*/config.py` — existing loopback port claims the GUI avoids.
