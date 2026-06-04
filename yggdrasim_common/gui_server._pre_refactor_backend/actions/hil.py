# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL bridge Command Center actions.

These actions surface the existing ``Tools.HilBridge`` supervisor /
relay state into the GUI without spawning the supervisor process itself
— operators still launch the daemon (via systemd, ``python -m
Tools.HilBridge.supervisor``, or the setup wizard). The GUI only reads
the published runtime state, which the supervisor writes atomically on
every reconciliation tick.

Actions registered:

* ``hil.supervisor_status`` — synchronous snapshot of
  ``runtime/state/hil_bridge_supervisor.json``. Returns the supervisor
  status, USB presence, bridge / REMSIM pids, and a compact summary the
  UI renders as key/value lines.
* ``hil.bridge_status`` — synchronous HTTP probe of the live bridge
  relay status URL (from ``hil_bridge_card_relay.json``). Degrades
  gracefully when the relay is not yet up.
* ``hil.watch_supervisor`` — streaming action: poll the supervisor
  state every N seconds and emit one ``{level, message, state}`` event
  per change. The UI renders this as a live status feed so operators
  can see the bridge come up / drop out without reloading the page.
* ``hil.list_readers`` — enumerate the PC/SC readers the process can
  see right now. Useful for picking ``YGGDRASIM_HIL_READER_INDEX``.
* ``hil.service_status`` — systemd user service state for the bridge.
* ``hil.service_control`` — start / stop / restart / enable-now /
  disable the bridge user service. Destructive ones require the
  per-request ``confirm`` checkbox.

The proper "live APDU stream" (GSMTAP → tshark → SAIP decode) stays on
the pending list — it depends on an external ``tshark`` binary and a
FIFO plumbing stage that does not belong in the Command Center first
cut. The watcher below gives most of the situational awareness without
that external dependency.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, AsyncIterator

from .registry import ActionContext, ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.hil")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _load_supervisor_snapshot() -> dict[str, Any]:
    """Return the supervisor state JSON plus the file-level metadata.

    Separating the wrapper from the raw payload means the UI can render
    the path + mtime (so operators can see if the supervisor is updating
    its state file, without us having to parse every field).
    """
    from yggdrasim_common.hil_bridge_runtime import (
        read_supervisor_state,
        supervisor_state_path,
    )

    state_path = supervisor_state_path()
    state = read_supervisor_state() or {}
    exists = os.path.isfile(state_path)
    mtime = 0.0
    if exists:
        try:
            mtime = float(os.path.getmtime(state_path))
        except OSError:  # pragma: no cover — stat races
            mtime = 0.0
    return {
        "state_path": state_path,
        "state_exists": exists,
        "state_mtime": mtime,
        "state": state,
    }


def _summary_lines_from_state(state: dict[str, Any]) -> list[dict[str, str]]:
    """Flatten the supervisor state dict into key/value rows."""
    lines: list[dict[str, str]] = []
    lines.append({"key": "Status", "value": str(state.get("status") or "(unknown)")})
    reason_text = str(state.get("reason") or "").strip()
    if len(reason_text) > 0:
        lines.append({"key": "Reason", "value": reason_text})
    lines.append({
        "key": "USB present",
        "value": "yes" if bool(state.get("usbPresent", False)) else "no",
    })
    usb_source = str(state.get("usbSource") or "").strip()
    if len(usb_source) > 0:
        lines.append({"key": "USB source", "value": usb_source})
    usb_error = str(state.get("usbError") or "").strip()
    if len(usb_error) > 0:
        lines.append({"key": "USB error", "value": usb_error})
    lines.append({
        "key": "Bridge running",
        "value": "yes" if bool(state.get("bridgeRunning", False)) else "no",
    })
    bridge_pid = int(state.get("bridgePid", 0) or 0)
    if bridge_pid > 0:
        lines.append({"key": "Bridge pid", "value": str(bridge_pid)})
    bridge_port = int(state.get("bridgePort", 0) or 0)
    if bridge_port > 0:
        lines.append({"key": "Bridge port", "value": str(bridge_port)})
    if bool(state.get("remsimClientEnabled", False)):
        lines.append({
            "key": "REMSIM client",
            "value": "running" if bool(state.get("remsimClientRunning", False)) else "stopped",
        })
        remsim_pid = int(state.get("remsimClientPid", 0) or 0)
        if remsim_pid > 0:
            lines.append({"key": "REMSIM pid", "value": str(remsim_pid)})
    reader_index = int(state.get("readerIndex", -1) or -1)
    if reader_index >= 0:
        reader_label = str(state.get("readerName") or "").strip()
        suffix = ""
        if len(reader_label) > 0:
            suffix = f" ({reader_label})"
        lines.append({"key": "Reader index", "value": f"{reader_index}{suffix}"})
    return lines


def _diff_state(previous: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Return a human-readable list of fields that changed between two snapshots."""
    if len(previous) == 0:
        return ["initial snapshot"]
    tracked_keys = (
        "status",
        "reason",
        "usbPresent",
        "bridgeRunning",
        "bridgePid",
        "remsimClientRunning",
        "remsimClientPid",
    )
    changes: list[str] = []
    for key_name in tracked_keys:
        prev_value = previous.get(key_name)
        curr_value = current.get(key_name)
        if prev_value == curr_value:
            continue
        changes.append(f"{key_name}: {prev_value!r} → {curr_value!r}")
    return changes


# ----------------------------------------------------------------------
# Synchronous dispatchers
# ----------------------------------------------------------------------


def _dispatch_supervisor_status(ctx: ActionContext) -> dict[str, Any]:
    """Return a snapshot of the supervisor state JSON."""
    snapshot = _load_supervisor_snapshot()
    lines = _summary_lines_from_state(snapshot["state"]) if snapshot["state_exists"] else [
        {"key": "Status", "value": "(supervisor has not written state yet)"},
        {"key": "State file", "value": snapshot["state_path"]},
    ]
    return {
        "state_path": snapshot["state_path"],
        "state_exists": snapshot["state_exists"],
        "state_mtime": snapshot["state_mtime"],
        "lines": lines,
        "raw": snapshot["state"],
    }


def _dispatch_bridge_status(ctx: ActionContext) -> dict[str, Any]:
    """Return the live bridge relay status via HTTP, or a friendly error."""
    from yggdrasim_common.hil_bridge_runtime import read_bridge_status

    try:
        payload = read_bridge_status()
    except Exception as error:  # noqa: BLE001 — relay not up is the common case
        return {
            "ok": False,
            "error": f"{type(error).__name__}: {error}",
            "raw": {},
        }
    return {
        "ok": True,
        "error": "",
        "raw": payload,
    }


# ----------------------------------------------------------------------
# Streaming dispatcher
# ----------------------------------------------------------------------


async def _dispatch_watch_supervisor(
    ctx: ActionContext,
    *,
    interval_ms: Any = None,
    cycles: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    """Poll the supervisor state every ``interval_ms`` and stream diffs."""
    interval_i = int(interval_ms) if interval_ms is not None else 1000
    cycles_i = int(cycles) if cycles is not None else 30
    if interval_i < 100:
        interval_i = 100
    if cycles_i <= 0:
        cycles_i = 1

    yield {
        "level": "info",
        "message": (
            f"starting supervisor watcher: interval_ms={interval_i} "
            f"cycles={cycles_i}"
        ),
    }

    previous_state: dict[str, Any] = {}
    for cycle_index in range(1, cycles_i + 1):
        snapshot = _load_supervisor_snapshot()
        state = snapshot["state"] if snapshot["state_exists"] else {}
        changes = _diff_state(previous_state, state)
        message = (
            f"cycle {cycle_index}/{cycles_i}: "
            + ("; ".join(changes) if changes else "no change")
        )
        yield {
            "level": "info",
            "message": message,
            "state": state,
            "state_mtime": snapshot["state_mtime"],
            "state_exists": snapshot["state_exists"],
        }
        previous_state = dict(state)
        if cycle_index < cycles_i:
            try:
                await asyncio.sleep(interval_i / 1000.0)
            except asyncio.CancelledError:
                yield {
                    "level": "done",
                    "message": "supervisor watcher cancelled.",
                    "final_state": previous_state,
                }
                return
    yield {
        "level": "done",
        "message": "supervisor watcher finished.",
        "final_state": previous_state,
    }


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


SUPERVISOR_STATUS_SPEC = ActionSpec(
    id="hil.supervisor_status",
    subsystem="HIL",
    title="Supervisor status",
    description=(
        "Snapshot the HIL bridge supervisor state JSON. Shows USB "
        "presence, bridge / REMSIM pids, and the last reconciliation "
        "reason. No external dependencies; safe to run even when the "
        "supervisor is not running (returns a clear 'no state yet')."
    ),
    inputs=(),
    output_kind="key_value_lines",
    dispatcher=_dispatch_supervisor_status,
    requires_card=False,
    streams=False,
    tags=("hil", "supervisor", "status"),
)


BRIDGE_STATUS_SPEC = ActionSpec(
    id="hil.bridge_status",
    subsystem="HIL",
    title="Bridge relay status",
    description=(
        "Probe the live bridge relay status URL published in "
        "hil_bridge_card_relay.json. Returns the raw JSON payload "
        "(reader, slot, remote APDU client, etc.) or a friendly error "
        "when the bridge is not yet up."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_bridge_status,
    requires_card=False,
    streams=False,
    tags=("hil", "bridge", "status"),
)


WATCH_SUPERVISOR_SPEC = ActionSpec(
    id="hil.watch_supervisor",
    subsystem="HIL",
    title="Watch supervisor",
    description=(
        "Stream supervisor state changes at a fixed cadence. Each cycle "
        "emits one event with the current state + a diff of the "
        "important fields (status, USB presence, bridge/REMSIM pids)."
    ),
    inputs=(
        ActionField(
            name="interval_ms",
            label="Poll interval (ms)",
            kind="int",
            required=False,
            default=1000,
            min_value=100,
            help="Time between supervisor state reads (minimum 100 ms).",
        ),
        ActionField(
            name="cycles",
            label="Cycles",
            kind="int",
            required=False,
            default=30,
            min_value=1,
            help="How many polls to run before the stream closes.",
        ),
    ),
    output_kind="log_stream",
    dispatcher=_dispatch_watch_supervisor,
    requires_card=False,
    streams=True,
    tags=("hil", "supervisor", "watch"),
)


# ----------------------------------------------------------------------
# PC/SC reader enumeration
# ----------------------------------------------------------------------


def _dispatch_list_readers(ctx: ActionContext) -> dict[str, Any]:
    """List every PC/SC reader visible to this process."""
    try:
        from smartcard.System import readers as list_pcsc_readers
    except ImportError as error:
        return {
            "ok": False,
            "count": 0,
            "rows": [],
            "headers": ["index", "name"],
            "note": f"pyscard not installed: {error}",
        }
    try:
        reader_objs = list(list_pcsc_readers() or [])
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "count": 0,
            "rows": [],
            "headers": ["index", "name"],
            "note": f"pcsc enumeration failed: {type(error).__name__}: {error}",
        }
    rows = [{"index": index, "name": str(reader)} for index, reader in enumerate(reader_objs)]
    return {
        "ok": True,
        "count": len(rows),
        "rows": rows,
        "headers": ["index", "name"],
        "note": f"{len(rows)} PC/SC reader(s) visible.",
    }


# ----------------------------------------------------------------------
# Systemd user service control
# ----------------------------------------------------------------------


_SERVICE_ACTIONS_READ_ONLY: tuple[str, ...] = ("status",)
_SERVICE_ACTIONS_SAFE: tuple[str, ...] = ("start", "restart", "enable-now")
_SERVICE_ACTIONS_DESTRUCTIVE: tuple[str, ...] = ("stop", "disable")
_SERVICE_ACTIONS_ALL: tuple[str, ...] = (
    _SERVICE_ACTIONS_READ_ONLY
    + _SERVICE_ACTIONS_SAFE
    + _SERVICE_ACTIONS_DESTRUCTIVE
    + ("daemon-reload", "install")
)


def _dispatch_service_status(
    ctx: ActionContext,
    *,
    service_name: Any = None,
) -> dict[str, Any]:
    """Query the systemd-user service state for the bridge."""
    from yggdrasim_common.hil_bridge_runtime import (
        DEFAULT_SERVICE_NAME,
        query_user_service_state,
    )

    service = str(service_name or "").strip() or DEFAULT_SERVICE_NAME
    try:
        payload = query_user_service_state(service)
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "service": service,
            "raw": {},
            "note": f"query failed: {type(error).__name__}: {error}",
        }
    lines: list[dict[str, str]] = []
    lines.append({"key": "Service", "value": service})
    for field in ("LoadState", "ActiveState", "SubState", "UnitFileState", "Description"):
        if field in payload:
            lines.append({"key": field, "value": str(payload.get(field) or "-")})
    return {
        "ok": True,
        "service": service,
        "lines": lines,
        "raw": payload,
        "note": "ok",
    }


def _dispatch_service_control(
    ctx: ActionContext,
    *,
    action: Any = None,
    service_name: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """Run one of the supported systemd user-service actions."""
    from yggdrasim_common.hil_bridge_runtime import (
        DEFAULT_SERVICE_NAME,
        daemon_reload_user_services,
        disable_user_service,
        enable_now_user_service,
        install_user_service,
        query_user_service_state,
        restart_user_service,
        start_user_service,
        stop_user_service,
    )

    action_s = str(action or "").strip().lower()
    if action_s not in _SERVICE_ACTIONS_ALL:
        raise ValueError(
            "action must be one of: " + ", ".join(_SERVICE_ACTIONS_ALL)
        )
    service = str(service_name or "").strip() or DEFAULT_SERVICE_NAME
    destructive = action_s in _SERVICE_ACTIONS_DESTRUCTIVE
    if destructive and bool(confirm) is False:
        raise ValueError(f"confirm must be true — '{action_s}' is destructive.")

    try:
        if action_s == "status":
            query_user_service_state(service)
        elif action_s == "start":
            start_user_service(service)
        elif action_s == "restart":
            restart_user_service(service)
        elif action_s == "enable-now":
            enable_now_user_service(service)
        elif action_s == "stop":
            stop_user_service(service)
        elif action_s == "disable":
            disable_user_service(service)
        elif action_s == "daemon-reload":
            daemon_reload_user_services()
        elif action_s == "install":
            try:
                from yggdrasim_common.hil_bridge_runtime import (
                    HilBridgeUserServiceOptions,
                )
                install_user_service(HilBridgeUserServiceOptions())
            except Exception as error:  # noqa: BLE001
                return {
                    "ok": False,
                    "service": service,
                    "action": action_s,
                    "note": f"install failed: {type(error).__name__}: {error}",
                }
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "service": service,
            "action": action_s,
            "note": f"{type(error).__name__}: {error}",
        }

    post_state: dict[str, Any] = {}
    try:
        post_state = query_user_service_state(service)
    except Exception:  # noqa: BLE001
        post_state = {}

    return {
        "ok": True,
        "service": service,
        "action": action_s,
        "state": post_state,
        "note": f"{action_s} dispatched on {service}.",
    }


LIST_READERS_SPEC = ActionSpec(
    id="hil.list_readers",
    subsystem="HIL",
    title="List PC/SC readers",
    description=(
        "Enumerate every PC/SC reader visible to the current process. "
        "Use this to populate the ``YGGDRASIM_HIL_READER_INDEX`` flag or "
        "pin a specific slot in the supervisor config."
    ),
    inputs=(),
    output_kind="table",
    dispatcher=_dispatch_list_readers,
    requires_card=False,
    streams=False,
    tags=("hil", "readers", "pcsc"),
)


SERVICE_STATUS_SPEC = ActionSpec(
    id="hil.service_status",
    subsystem="HIL",
    title="Service status",
    description=(
        "Query the systemd user service unit for the HIL bridge and "
        "return LoadState / ActiveState / SubState / UnitFileState. Pure "
        "diagnostic read."
    ),
    inputs=(
        ActionField(
            name="service_name",
            label="Service name",
            kind="string",
            required=False,
            placeholder="(leave blank for the default)",
            help="Override the service unit name if you installed a custom one.",
        ),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_service_status,
    requires_card=False,
    streams=False,
    tags=("hil", "systemd", "status"),
)


SERVICE_CONTROL_SPEC = ActionSpec(
    id="hil.service_control",
    subsystem="HIL",
    title="Service control",
    description=(
        "Run a systemd user-service action against the HIL bridge unit. "
        "Destructive operations (stop / disable) require the confirm "
        "checkbox. 'install' writes the unit file from the default "
        "options and then reloads the user daemon."
    ),
    inputs=(
        ActionField(
            name="action",
            label="Action",
            kind="enum",
            required=True,
            choices=list(_SERVICE_ACTIONS_ALL),
            help="systemctl --user verb to run against the bridge service.",
        ),
        ActionField(
            name="service_name",
            label="Service name",
            kind="string",
            required=False,
            placeholder="(leave blank for the default)",
            help="Override the service unit name if you installed a custom one.",
        ),
        ActionField(
            name="confirm",
            label="I understand this may stop the bridge",
            kind="bool",
            required=False,
            default=False,
            help="Must be true to run stop / disable.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_service_control,
    requires_card=False,
    streams=False,
    tags=("hil", "systemd", "control"),
)


# ----------------------------------------------------------------------
# Bridge configuration
# ----------------------------------------------------------------------


def _dispatch_bridge_config(
    ctx: ActionContext,
    *,
    host: Any = None,
    port: Any = None,
    reader_index: Any = None,
    reader_name: Any = None,
    apply: Any = None,
) -> dict[str, Any]:
    """Show the effective BridgeConfig and optionally apply overrides."""
    from Tools.HilBridge.router import BridgeConfig
    from yggdrasim_common.hil_bridge_runtime import (
        read_supervisor_state,
        supervisor_state_path,
    )

    try:
        state = read_supervisor_state() or {}
        bridge_cfg = state.get("bridgeConfig") or {}
    except Exception:  # noqa: BLE001
        bridge_cfg = {}

    host_s = str(host or "").strip()
    port_s = str(port or "").strip()
    reader_idx_s = str(reader_index or "").strip()
    reader_name_s = str(reader_name or "").strip()
    apply_b = bool(apply)

    current = BridgeConfig(
        listen_host=str(bridge_cfg.get("listenHost", "127.0.0.1")),
        listen_port=int(bridge_cfg.get("listenPort", 9997)),
        reader_index=int(bridge_cfg.get("readerIndex", 0)),
        reader_name=str(bridge_cfg.get("readerName", "")),
    )

    if apply_b:
        if len(host_s) > 0:
            current = BridgeConfig(
                listen_host=host_s,
                listen_port=current.listen_port,
                reader_index=current.reader_index,
                reader_name=current.reader_name,
            )
        if len(port_s) > 0:
            current = BridgeConfig(
                listen_host=current.listen_host,
                listen_port=int(port_s),
                reader_index=current.reader_index,
                reader_name=current.reader_name,
            )
        if len(reader_idx_s) > 0:
            current = BridgeConfig(
                listen_host=current.listen_host,
                listen_port=current.listen_port,
                reader_index=int(reader_idx_s),
                reader_name=current.reader_name,
            )
        if len(reader_name_s) > 0:
            current = BridgeConfig(
                listen_host=current.listen_host,
                listen_port=current.listen_port,
                reader_index=current.reader_index,
                reader_name=reader_name_s,
            )

    lines: list[dict[str, str]] = []
    lines.append({"key": "Listen host", "value": current.listen_host})
    lines.append({"key": "Listen port", "value": str(current.listen_port)})
    lines.append({"key": "Reader index", "value": str(current.reader_index)})
    lines.append({"key": "Reader name", "value": current.reader_name or "(first available)"})
    lines.append({"key": "State file", "value": supervisor_state_path()})
    lines.append({"key": "Applied", "value": "yes" if apply_b else "no (read-only snapshot)"})

    return {
        "ok": True,
        "lines": lines,
        "config": {
            "listen_host": current.listen_host,
            "listen_port": current.listen_port,
            "reader_index": current.reader_index,
            "reader_name": current.reader_name,
        },
        "applied": apply_b,
        "note": (
            "Configuration applied — restart the bridge for changes to take effect."
            if apply_b
            else "Configuration snapshot (read-only)."
        ),
    }


BRIDGE_CONFIG_SPEC = ActionSpec(
    id="hil.bridge_config",
    subsystem="HIL",
    title="Bridge configuration",
    description=(
        "Show the effective HIL bridge configuration. Optionally apply "
        "overrides for host, port, and reader selection."
    ),
    inputs=(
        ActionField(
            name="host",
            label="Listen host",
            kind="string",
            required=False,
            placeholder="127.0.0.1",
            help="Bind address for the RSPRO control port.",
        ),
        ActionField(
            name="port",
            label="Listen port",
            kind="int",
            required=False,
            default=9997,
            min_value=1,
            help="RSPRO control port.",
        ),
        ActionField(
            name="reader_index",
            label="Reader index",
            kind="int",
            required=False,
            min_value=0,
            help="Zero-based PC/SC reader index.",
        ),
        ActionField(
            name="reader_name",
            label="Reader name",
            kind="string",
            required=False,
            help="PC/SC reader name substring match.",
        ),
        ActionField(
            name="apply",
            label="Apply changes",
            kind="bool",
            required=False,
            default=False,
            help="Check to write the supplied values to the effective config.",
        ),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_bridge_config,
    requires_card=False,
    streams=False,
    tags=("hil", "bridge", "config"),
)


# ----------------------------------------------------------------------
# Bridge / Supervisor launch
# ----------------------------------------------------------------------


def _dispatch_bridge_launch(
    ctx: ActionContext,
    *,
    confirm: Any = None,
) -> dict[str, Any]:
    if bool(confirm) is False:
        raise ValueError("confirm must be true — launching the bridge starts a long-running subprocess.")

    import subprocess
    import sys
    import shlex

    cmd = [sys.executable, "-m", "Tools.HilBridge.main"]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "pid": 0,
            "command": " ".join(shlex.quote(p) for p in cmd),
            "note": f"failed to start bridge: {type(error).__name__}: {error}",
        }

    return {
        "ok": True,
        "pid": proc.pid,
        "command": " ".join(shlex.quote(p) for p in cmd),
        "note": f"Bridge launched (pid={proc.pid}). Check supervisor status for readiness.",
    }


BRIDGE_LAUNCH_SPEC = ActionSpec(
    id="hil.bridge_launch",
    subsystem="HIL",
    title="Launch bridge",
    description=(
        "Start the HIL bridge as a detached background subprocess. "
        "The bridge serves RSPRO + APDU relay on the configured ports. "
        "Destructive if a bridge is already running — stop it first."
    ),
    inputs=(
        ActionField(
            name="confirm",
            label="I understand this launches a subprocess",
            kind="bool",
            required=True,
            default=False,
            help="Must be true to proceed.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_bridge_launch,
    requires_card=False,
    streams=False,
    tags=("hil", "bridge", "launch"),
)


def _dispatch_supervisor_launch(
    ctx: ActionContext,
    *,
    confirm: Any = None,
) -> dict[str, Any]:
    if bool(confirm) is False:
        raise ValueError("confirm must be true — launching the supervisor starts a long-running subprocess.")

    import subprocess
    import sys
    import shlex

    cmd = [sys.executable, "-m", "Tools.HilBridge.supervisor"]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "pid": 0,
            "command": " ".join(shlex.quote(p) for p in cmd),
            "note": f"failed to start supervisor: {type(error).__name__}: {error}",
        }

    return {
        "ok": True,
        "pid": proc.pid,
        "command": " ".join(shlex.quote(p) for p in cmd),
        "note": f"Supervisor launched (pid={proc.pid}). Use 'Watch supervisor' to monitor state.",
    }


SUPERVISOR_LAUNCH_SPEC = ActionSpec(
    id="hil.supervisor_launch",
    subsystem="HIL",
    title="Launch supervisor",
    description=(
        "Start the HIL bridge supervisor as a detached background "
        "subprocess. The supervisor manages the bridge + REMSIM client "
        "lifecycle and publishes state to runtime/state/hil_bridge_supervisor.json."
    ),
    inputs=(
        ActionField(
            name="confirm",
            label="I understand this launches a subprocess",
            kind="bool",
            required=True,
            default=False,
            help="Must be true to proceed.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_supervisor_launch,
    requires_card=False,
    streams=False,
    tags=("hil", "supervisor", "launch"),
)


get_registry().register(SUPERVISOR_STATUS_SPEC)
get_registry().register(BRIDGE_STATUS_SPEC)
get_registry().register(WATCH_SUPERVISOR_SPEC)
get_registry().register(LIST_READERS_SPEC)
get_registry().register(SERVICE_STATUS_SPEC)
get_registry().register(SERVICE_CONTROL_SPEC)
get_registry().register(BRIDGE_CONFIG_SPEC)
get_registry().register(BRIDGE_LAUNCH_SPEC)
get_registry().register(SUPERVISOR_LAUNCH_SPEC)
