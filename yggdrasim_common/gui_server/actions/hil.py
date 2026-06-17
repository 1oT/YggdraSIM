# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL bridge Command Center actions.

These actions surface and control the existing ``Tools.HilBridge``
supervisor / relay state from the GUI. Read-only actions inspect the
published runtime state, while the session actions mirror the wrapper
start / stop flow through the systemd user service.

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
* ``hil.session_start`` / ``hil.session_stop`` — start or stop the
  supervised HIL session using the same service-unit update flow as the
  terminal wrapper.
* ``hil.decode_snapshot`` — read the active GSMTAP pcap with the same
  tshark-backed decoder used by the terminal decode view and return a
  bounded packet snapshot for the GUI HIL module.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any, AsyncIterator

from .registry import ActionContext, ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.hil")

_HIL_SESSION_MODE_RAW = "raw"
_HIL_SESSION_MODE_RAW_WIRESHARK = "raw_wireshark"
_HIL_SESSION_MODE_DECODED = "decoded"
_HIL_SESSION_MODES = (
    _HIL_SESSION_MODE_DECODED,
    _HIL_SESSION_MODE_RAW,
    _HIL_SESSION_MODE_RAW_WIRESHARK,
)


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
# Decoded capture snapshot
# ----------------------------------------------------------------------


def _default_decode_capture_path() -> str:
    from yggdrasim_common.runtime_paths import runtime_path

    capture_path = runtime_path("state", "hil_termshark", "live_capture.pcap")
    Path(capture_path).parent.mkdir(parents=True, exist_ok=True)
    return capture_path


def _extract_bridge_command_capture_path(command_value: Any) -> str:
    if isinstance(command_value, list) is False:
        return ""
    capture_flag = "--gsmtap-capture-path"
    for index, raw_value in enumerate(command_value):
        current_value = str(raw_value or "").strip()
        if current_value == capture_flag:
            if index + 1 >= len(command_value):
                return ""
            return str(command_value[index + 1] or "").strip()
        if current_value.startswith(f"{capture_flag}="):
            return current_value.split("=", 1)[1].strip()
    return ""


def _resolve_decode_capture_path(capture_path: Any = None) -> str:
    explicit_path = str(capture_path or "").strip()
    if len(explicit_path) > 0:
        return os.path.abspath(os.path.expanduser(explicit_path))
    try:
        snapshot = _load_supervisor_snapshot()
    except Exception:  # noqa: BLE001 - optional state file
        snapshot = {}
    state = snapshot.get("state", {}) if isinstance(snapshot, dict) else {}
    command_path = _extract_bridge_command_capture_path(state.get("bridgeCommand", []))
    if len(command_path) > 0:
        return os.path.abspath(os.path.expanduser(command_path))
    return _default_decode_capture_path()


def _normalize_session_mode(mode: Any) -> str:
    mode_text = str(mode or "").strip().lower().replace("-", "_")
    if mode_text in ("", "3", "decoded", "tshark", "termshark", "context", "dissector"):
        return _HIL_SESSION_MODE_DECODED
    if mode_text in ("1", "raw", "raw_only"):
        return _HIL_SESSION_MODE_RAW
    if mode_text in ("2", "wireshark", "raw_wireshark", "raw_plus_wireshark"):
        return _HIL_SESSION_MODE_RAW_WIRESHARK
    raise ValueError(
        "mode must be one of: " + ", ".join(_HIL_SESSION_MODES)
    )


def _bridge_command_uses_gsmtap(command_value: Any) -> bool | None:
    if isinstance(command_value, list) is False:
        return None
    for raw_value in command_value:
        if str(raw_value or "").strip() == "--no-gsmtap":
            return False
    return True


def _resolve_supervisor_quirks_env() -> tuple[str, str]:
    from yggdrasim_common.card_backend import get_sim_quirks_path

    allow_value = str(os.environ.get("YGGDRASIM_ALLOW_QUIRKS", "") or "").strip()
    quirks_path = get_sim_quirks_path()
    if len(allow_value) > 0:
        return quirks_path, allow_value
    if len(quirks_path) == 0:
        return "", ""
    return "none", ""


def _build_hil_bridge_service_options(
    *,
    gsmtap_enabled: bool = True,
    gsmtap_capture_path: str = "",
) -> Any:
    from yggdrasim_common.card_backend import (
        CARD_BACKEND_ENV,
        SIM_EIM_IDENTITY_ENV,
        SIM_EUICC_STORE_ENV,
        SIM_ISDR_CONFIG_ENV,
        SIM_PROFILE_STORE_ENV,
        SIM_QUIRKS_ENV,
        get_card_backend,
        get_sim_eim_identity_path,
        get_sim_euicc_store_root,
        get_sim_isdr_config_path,
        get_sim_profile_store_path,
    )
    from yggdrasim_common.hil_bridge_runtime import (
        DEFAULT_USB_VIDPID,
        HilBridgeUserServiceOptions,
        extract_remsim_extra_args_from_supervisor_state,
        guess_bridge_python_executable,
        read_supervisor_state,
    )
    from yggdrasim_common.runtime_paths import bundle_path

    supervisor_state = read_supervisor_state()
    python_executable = guess_bridge_python_executable(
        supervisor_state,
        fallback=sys.executable,
    )
    try:
        reader_index = int(supervisor_state.get("readerIndex", 0) or 0)
    except (TypeError, ValueError):
        reader_index = 0
    try:
        bridge_port = int(supervisor_state.get("bridgePort", 9997) or 9997)
    except (TypeError, ValueError):
        bridge_port = 9997
    quirks_env_value, allow_quirks_env_value = _resolve_supervisor_quirks_env()
    environment_overrides: list[tuple[str, str]] = [
        (CARD_BACKEND_ENV, get_card_backend()),
        (SIM_ISDR_CONFIG_ENV, get_sim_isdr_config_path()),
        (SIM_QUIRKS_ENV, quirks_env_value),
        (SIM_EIM_IDENTITY_ENV, get_sim_eim_identity_path()),
        (SIM_EUICC_STORE_ENV, get_sim_euicc_store_root()),
    ]
    if len(allow_quirks_env_value) > 0:
        environment_overrides.append(("YGGDRASIM_ALLOW_QUIRKS", allow_quirks_env_value))
    profile_store_path = get_sim_profile_store_path()
    if len(profile_store_path) > 0:
        environment_overrides.append((SIM_PROFILE_STORE_ENV, profile_store_path))

    return HilBridgeUserServiceOptions(
        python_executable=python_executable,
        working_directory=str(Path(__file__).resolve().parents[3]),
        reader_index=reader_index,
        host="127.0.0.1",
        port=bridge_port,
        advertise_host="127.0.0.1",
        usb_vidpid=DEFAULT_USB_VIDPID,
        gsmtap_enabled=bool(gsmtap_enabled),
        gsmtap_capture_path=str(gsmtap_capture_path or "").strip(),
        remsim_args=extract_remsim_extra_args_from_supervisor_state(supervisor_state),
        documentation_path=bundle_path("guides", "HIL_BRIDGE_GUIDE.md"),
        environment_overrides=tuple(environment_overrides),
    )


def _ensure_hil_bridge_user_service(
    *,
    gsmtap_enabled: bool = True,
    gsmtap_capture_path: str = "",
) -> tuple[str, bool, str]:
    from yggdrasim_common.hil_bridge_runtime import (
        daemon_reload_user_services,
        disable_user_service,
        render_user_service_unit,
        write_user_service_if_changed,
    )

    options = _build_hil_bridge_service_options(
        gsmtap_enabled=gsmtap_enabled,
        gsmtap_capture_path=gsmtap_capture_path,
    )
    unit_text = render_user_service_unit(options)
    written_path, unit_changed = write_user_service_if_changed(
        unit_text,
        service_name=options.service_name,
    )
    if unit_changed:
        daemon_reload_user_services()
    try:
        disable_user_service(options.service_name)
    except (OSError, RuntimeError):
        pass
    return written_path, unit_changed, options.service_name


def _activate_hil_bridge_service(
    *,
    active_before: bool,
    needs_restart: bool,
    service_name: str,
) -> dict[str, Any]:
    from yggdrasim_common.hil_bridge_runtime import (
        clear_card_relay_state,
        clear_supervisor_state,
        restart_user_service,
        start_user_service,
        stop_user_service,
        wait_for_bridge_ready,
    )

    try:
        if active_before is False:
            clear_supervisor_state()
            clear_card_relay_state()
            start_user_service(service_name)
        elif needs_restart:
            clear_supervisor_state()
            clear_card_relay_state()
            restart_user_service(service_name)
        return wait_for_bridge_ready()
    except Exception:
        if active_before is False:
            try:
                stop_user_service(service_name)
            except (OSError, RuntimeError):
                pass
        raise


def _packet_summary_to_dict(
    row: Any,
    *,
    annotated_info: str = "",
    apdu_command_hex: str = "",
    apdu_response_hex: str = "",
) -> dict[str, Any]:
    payload = {
        "number": int(getattr(row, "number", 0) or 0),
        "time_text": str(getattr(row, "time_text", "") or ""),
        "wall_time_text": str(getattr(row, "wall_time_text", "") or ""),
        "epoch_time_text": str(getattr(row, "epoch_time_text", "") or ""),
        "source": str(getattr(row, "source", "") or ""),
        "destination": str(getattr(row, "destination", "") or ""),
        "protocol": str(getattr(row, "protocol", "") or ""),
        "length_text": str(getattr(row, "length_text", "") or ""),
        "info": str(getattr(row, "info", "") or ""),
        "annotated_info": str(annotated_info or ""),
        "udp_payload_hex": str(getattr(row, "udp_payload_hex", "") or ""),
        "gsmtap_uplink": _gsmtap_uplink(getattr(row, "udp_payload_hex", "") or ""),
    }
    if len(str(apdu_command_hex or "").strip()) > 0:
        payload["apdu_command_hex"] = str(apdu_command_hex or "").strip().upper()
    if len(str(apdu_response_hex or "").strip()) > 0:
        payload["apdu_response_hex"] = str(apdu_response_hex or "").strip().upper()
    return payload


def _gsmtap_uplink(udp_payload_hex: Any) -> bool | None:
    normalized = str(udp_payload_hex or "").strip().replace(":", "")
    if len(normalized) < 12:
        return None
    try:
        gsmtap_packet = bytes.fromhex(normalized)
    except ValueError:
        return None
    if len(gsmtap_packet) < 6:
        return None
    arfcn = int.from_bytes(gsmtap_packet[4:6], byteorder="big", signed=False)
    return bool(arfcn & 0x4000)


def _annotation_to_dict(annotation: Any) -> dict[str, Any]:
    if annotation is None:
        return {}
    active_timers: list[dict[str, Any]] = []
    for timer in getattr(annotation, "active_timers", ()) or ():
        active_timers.append({
            "timer_id": int(getattr(timer, "timer_id", 0) or 0),
            "configured_seconds": int(getattr(timer, "configured_seconds", 0) or 0),
            "remaining_seconds": int(getattr(timer, "remaining_seconds", 0) or 0),
            "display_label": str(getattr(timer, "display_label", "") or ""),
        })
    return {
        "frame_number": int(getattr(annotation, "frame_number", 0) or 0),
        "summary_suffix": str(getattr(annotation, "summary_suffix", "") or ""),
        "context_lines": [
            str(line or "") for line in (getattr(annotation, "context_lines", ()) or ())
        ],
        "active_channel_count": int(getattr(annotation, "active_channel_count", 0) or 0),
        "active_timer_count": int(getattr(annotation, "active_timer_count", 0) or 0),
        "active_timers": active_timers,
        "capture_time_seconds": getattr(annotation, "capture_time_seconds", None),
        "channel_session_id": getattr(annotation, "channel_session_id", None),
        "channel_number": getattr(annotation, "channel_number", None),
        "channel_poll_index": getattr(annotation, "channel_poll_index", None),
        "state_event": bool(getattr(annotation, "state_event", False)),
        "card_session_index": int(getattr(annotation, "card_session_index", 1) or 1),
        "card_session_reset_reason": str(
            getattr(annotation, "card_session_reset_reason", "") or ""
        ),
        "card_session_iccid": str(getattr(annotation, "card_session_iccid", "") or ""),
    }


def _bounded_decode_limit(limit: Any = None) -> int:
    try:
        limit_i = int(limit) if limit is not None else 2000
    except (TypeError, ValueError):
        limit_i = 2000
    if limit_i <= 0:
        return 2000
    return min(limit_i, 5000)


def _build_replay_engine(keybag_path: str) -> tuple[Any, dict[str, Any]]:
    normalized_keybag = str(keybag_path or "").strip()
    if len(normalized_keybag) == 0:
        return None, {
            "source_path": "",
            "session_count": 0,
            "error_text": "",
        }
    from Tools.HilBridge.scp_replay import (
        ScpReplayEngine,
        load_keybag,
        load_keybag_safe,
    )

    summary = load_keybag_safe(normalized_keybag)
    summary_payload = {
        "source_path": str(getattr(summary, "source_path", normalized_keybag) or ""),
        "session_count": int(getattr(summary, "session_count", 0) or 0),
        "error_text": str(getattr(summary, "error_text", "") or ""),
    }
    if summary_payload["session_count"] <= 0:
        return None, summary_payload
    try:
        return ScpReplayEngine(load_keybag(normalized_keybag)), summary_payload
    except Exception as error:  # noqa: BLE001 - malformed optional keybag
        summary_payload["session_count"] = 0
        summary_payload["error_text"] = f"Replay engine init failed: {error}"
        return None, summary_payload


def _dispatch_decode_snapshot(
    ctx: ActionContext,
    *,
    capture_path: Any = None,
    selected_frame: Any = None,
    keybag_path: Any = None,
    limit: Any = None,
    include_detail: Any = None,
    include_annotations: Any = None,
    after_frame: Any = None,
    known_capture_size: Any = None,
    known_capture_mtime: Any = None,
) -> dict[str, Any]:
    del ctx
    try:
        from Tools.HilBridge.live_decode_state import (
            _parse_exchange_from_udp_payload_hex,
            annotate_packet_summary,
            build_stateful_packet_annotations,
        )
        from Tools.HilBridge.live_decode_view import (
            DEFAULT_DECODE_RULE,
            read_packet_detail,
            read_packet_hex,
            read_packet_summaries,
            resolve_tshark_binary,
        )
        from Tools.HilBridge.scp_replay import try_autodiscover_sidecar_keybag
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "rows": [],
            "annotations": {},
            "detail": "",
            "bytes": "",
            "include_detail": True,
            "include_annotations": True,
            "not_modified": False,
            "note": f"decoder unavailable: {type(error).__name__}: {error}",
        }

    resolved_capture_path = _resolve_decode_capture_path(capture_path)
    target_path = Path(resolved_capture_path)
    capture_exists = target_path.is_file()
    capture_size = 0
    capture_mtime = 0.0
    if capture_exists:
        try:
            stat_result = target_path.stat()
            capture_size = int(stat_result.st_size)
            capture_mtime = float(stat_result.st_mtime)
        except OSError:
            capture_exists = False
    tshark_binary = resolve_tshark_binary()
    if len(tshark_binary) == 0:
        return {
            "ok": False,
            "capture_path": resolved_capture_path,
            "capture_exists": capture_exists,
            "capture_size": capture_size,
            "capture_mtime": capture_mtime,
            "rows": [],
            "annotations": {},
            "detail": "",
            "bytes": "",
            "selected_frame": None,
            "include_detail": True,
            "include_annotations": True,
            "not_modified": False,
            "note": "tshark is not available.",
        }
    include_detail_bool = True
    if include_detail is not None:
        include_detail_bool = str(include_detail).strip().lower() not in {
            "",
            "0",
            "false",
            "no",
            "off",
        }
    include_annotations_bool = True
    if include_annotations is not None:
        include_annotations_bool = str(include_annotations).strip().lower() not in {
            "",
            "0",
            "false",
            "no",
            "off",
        }
    after_frame_i = 0
    try:
        after_frame_i = max(0, int(after_frame or 0))
    except (TypeError, ValueError):
        after_frame_i = 0
    known_capture_size_i: int | None = None
    known_capture_mtime_f: float | None = None
    try:
        if known_capture_size is not None:
            known_capture_size_i = int(known_capture_size)
    except (TypeError, ValueError):
        known_capture_size_i = None
    try:
        if known_capture_mtime is not None:
            known_capture_mtime_f = float(known_capture_mtime)
    except (TypeError, ValueError):
        known_capture_mtime_f = None
    if capture_exists is False or capture_size <= 24:
        return {
            "ok": True,
            "capture_path": resolved_capture_path,
            "capture_exists": capture_exists,
            "capture_size": capture_size,
            "capture_mtime": capture_mtime,
            "tshark_binary": tshark_binary,
            "rows": [],
            "annotations": {},
            "detail": "",
            "bytes": "",
            "selected_frame": None,
            "include_detail": include_detail_bool,
            "include_annotations": include_annotations_bool,
            "incremental": after_frame_i > 0,
            "after_frame": after_frame_i,
            "not_modified": False,
            "note": "capture is empty or not available yet.",
        }
    if (
        not include_detail_bool
        and known_capture_size_i == capture_size
        and known_capture_mtime_f is not None
        and abs(known_capture_mtime_f - capture_mtime) < 0.000001
    ):
        return {
            "ok": True,
            "capture_path": resolved_capture_path,
            "capture_exists": True,
            "capture_size": capture_size,
            "capture_mtime": capture_mtime,
            "tshark_binary": tshark_binary,
            "decode_rule": DEFAULT_DECODE_RULE,
            "row_count": 0,
            "returned_count": 0,
            "limit": _bounded_decode_limit(limit),
            "selected_frame": None,
            "rows": [],
            "annotations": {},
            "include_detail": include_detail_bool,
            "include_annotations": include_annotations_bool,
            "incremental": after_frame_i > 0,
            "after_frame": after_frame_i,
            "not_modified": True,
            "detail": "",
            "bytes": "",
            "keybag": {},
            "note": "",
        }

    rows, summary_error = read_packet_summaries(
        resolved_capture_path,
        tshark_binary=tshark_binary,
        decode_rule=DEFAULT_DECODE_RULE,
        after_frame=after_frame_i if after_frame_i > 0 else None,
    )
    row_limit = _bounded_decode_limit(limit)
    returned_rows = list(rows[-row_limit:])
    keybag_summary: dict[str, Any] = {}
    annotations: dict[int, Any] = {}
    if include_annotations_bool:
        resolved_keybag_path = str(keybag_path or "").strip()
        if len(resolved_keybag_path) == 0:
            resolved_keybag_path = str(
                try_autodiscover_sidecar_keybag(resolved_capture_path) or ""
            ).strip()
        replay_engine, keybag_summary = _build_replay_engine(resolved_keybag_path)
        annotations = build_stateful_packet_annotations(
            returned_rows,
            replay_engine=replay_engine,
        )

    rows_payload: list[dict[str, Any]] = []
    annotations_payload: dict[str, dict[str, Any]] = {}
    for row in returned_rows:
        frame_number = int(row.number)
        annotation = annotations.get(frame_number)
        annotated_row = annotate_packet_summary(row, annotation) if annotation is not None else row
        exchange = _parse_exchange_from_udp_payload_hex(
            str(getattr(row, "udp_payload_hex", "") or "")
        )
        rows_payload.append(
            _packet_summary_to_dict(
                row,
                annotated_info=str(getattr(annotated_row, "info", "") or ""),
                apdu_command_hex=(
                    exchange.command.hex().upper() if exchange is not None else ""
                ),
                apdu_response_hex=(
                    exchange.response.hex().upper() if exchange is not None else ""
                ),
            )
        )
        if include_annotations_bool:
            annotations_payload[str(frame_number)] = _annotation_to_dict(annotation)

    selected_frame_i: int | None = None
    try:
        if selected_frame is not None:
            selected_frame_i = int(selected_frame)
    except (TypeError, ValueError):
        selected_frame_i = None
    frame_numbers = {int(row.number) for row in returned_rows}
    if selected_frame_i not in frame_numbers:
        if include_detail_bool and len(returned_rows) > 0:
            selected_frame_i = int(returned_rows[-1].number)
        else:
            selected_frame_i = None

    detail_text = ""
    detail_error = ""
    bytes_text = ""
    bytes_error = ""
    if include_detail_bool and selected_frame_i is not None:
        detail_text, detail_error = read_packet_detail(
            resolved_capture_path,
            selected_frame_i,
            tshark_binary=tshark_binary,
            decode_rule=DEFAULT_DECODE_RULE,
        )
        bytes_text, bytes_error = read_packet_hex(
            resolved_capture_path,
            selected_frame_i,
            tshark_binary=tshark_binary,
            decode_rule=DEFAULT_DECODE_RULE,
        )

    note_parts: list[str] = []
    if len(summary_error.strip()) > 0:
        note_parts.append(summary_error.strip())
    if len(detail_error.strip()) > 0:
        note_parts.append(f"detail: {detail_error.strip()}")
    if len(bytes_error.strip()) > 0:
        note_parts.append(f"bytes: {bytes_error.strip()}")

    return {
        "ok": True,
        "capture_path": resolved_capture_path,
        "capture_exists": True,
        "capture_size": capture_size,
        "capture_mtime": capture_mtime,
        "tshark_binary": tshark_binary,
        "decode_rule": DEFAULT_DECODE_RULE,
        "row_count": len(rows),
        "returned_count": len(rows_payload),
        "limit": row_limit,
        "selected_frame": selected_frame_i,
        "rows": rows_payload,
        "annotations": annotations_payload,
        "include_detail": include_detail_bool,
        "include_annotations": include_annotations_bool,
        "incremental": after_frame_i > 0,
        "after_frame": after_frame_i,
        "not_modified": False,
        "detail": detail_text,
        "bytes": bytes_text,
        "keybag": keybag_summary,
        "note": " | ".join(note_parts),
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


DECODE_SNAPSHOT_SPEC = ActionSpec(
    id="hil.decode_snapshot",
    subsystem="HIL",
    title="Decode snapshot",
    description=(
        "Read the active GSMTAP capture with tshark and return packet "
        "summaries, stateful APDU context, decoded detail, and bytes for "
        "the selected frame."
    ),
    inputs=(
        ActionField(
            name="capture_path",
            label="Capture path",
            kind="path",
            required=False,
            placeholder="(auto-detect live capture)",
            help="Optional pcap/pcapng path. Blank uses the active supervisor capture path.",
        ),
        ActionField(
            name="selected_frame",
            label="Selected frame",
            kind="int",
            required=False,
            min_value=1,
            help="Frame number to load in the decoded detail and byte panes.",
        ),
        ActionField(
            name="keybag_path",
            label="Keybag path",
            kind="path",
            required=False,
            placeholder="(auto-detect sibling keybag)",
            help="Optional HIL keybag JSON used for secure-messaging replay annotations.",
        ),
        ActionField(
            name="limit",
            label="Packet limit",
            kind="int",
            required=False,
            default=2000,
            min_value=1,
            max_value=5000,
            help="Maximum packet rows to return to the GUI.",
        ),
        ActionField(
            name="include_detail",
            label="Include decoded detail",
            kind="bool",
            required=False,
            default=True,
            help="When disabled, return packet summaries without decoded field and byte panes.",
        ),
        ActionField(
            name="include_annotations",
            label="Include context annotations",
            kind="bool",
            required=False,
            default=True,
            help="When disabled, skip stateful APDU context annotations for lightweight polling.",
        ),
        ActionField(
            name="after_frame",
            label="After frame",
            kind="int",
            required=False,
            min_value=0,
            help="Return only packet summaries with frame.number greater than this value.",
        ),
        ActionField(
            name="known_capture_size",
            label="Known capture size",
            kind="int",
            required=False,
            min_value=0,
            help="Capture size already held by the caller for not-modified checks.",
        ),
        ActionField(
            name="known_capture_mtime",
            label="Known capture mtime",
            kind="float",
            required=False,
            help="Capture modification time already held by the caller for not-modified checks.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_decode_snapshot,
    requires_card=False,
    streams=False,
    tags=("hil", "decode", "tshark", "pcap"),
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
                    render_user_service_unit,
                )

                options = _build_hil_bridge_service_options()
                unit_text = render_user_service_unit(options)
                install_user_service(unit_text, service_name=service)
                daemon_reload_user_services()
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
    try:
        from yggdrasim_common.gui_server.lifecycle import (
            register_gui_service,
            unregister_gui_service,
        )

        if action_s in ("start", "restart", "enable-now"):
            register_gui_service(service)
        elif action_s in ("stop", "disable"):
            unregister_gui_service(service)
    except Exception:  # noqa: BLE001 - cleanup registration is best-effort
        pass

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


def _dispatch_session_start(
    ctx: ActionContext,
    *,
    mode: Any = None,
) -> dict[str, Any]:
    """Start the supervised HIL session for the selected GUI attach mode."""
    from yggdrasim_common.hil_bridge_runtime import (
        DEFAULT_SERVICE_NAME,
        query_user_service_state,
        read_supervisor_state,
    )

    mode_s = _normalize_session_mode(mode)
    gsmtap_enabled = mode_s != _HIL_SESSION_MODE_RAW
    capture_path = _default_decode_capture_path() if gsmtap_enabled else ""
    service_state = query_user_service_state(DEFAULT_SERVICE_NAME)
    active_before = str(service_state.get("activeState", "") or "").strip() == "active"
    supervisor_state = read_supervisor_state()
    bridge_command = supervisor_state.get("bridgeCommand", [])
    active_gsmtap_enabled = _bridge_command_uses_gsmtap(bridge_command)
    active_capture_path = _extract_bridge_command_capture_path(bridge_command)

    try:
        unit_path, unit_changed, service_name = _ensure_hil_bridge_user_service(
            gsmtap_enabled=gsmtap_enabled,
            gsmtap_capture_path=capture_path,
        )
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "mode": mode_s,
            "capture_path": capture_path,
            "service": DEFAULT_SERVICE_NAME,
            "note": f"could not prepare HIL service: {type(error).__name__}: {error}",
        }

    needs_restart = bool(
        active_before
        and (
            unit_changed
            or (
                active_gsmtap_enabled is not None
                and bool(active_gsmtap_enabled) != bool(gsmtap_enabled)
            )
            or str(active_capture_path or "").strip() != str(capture_path or "").strip()
        )
    )
    try:
        status_payload = _activate_hil_bridge_service(
            active_before=active_before,
            needs_restart=needs_restart,
            service_name=service_name,
        )
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "mode": mode_s,
            "service": service_name,
            "unit_path": unit_path,
            "unit_changed": unit_changed,
            "capture_path": capture_path,
            "gsmtap_enabled": gsmtap_enabled,
            "active_before": active_before,
            "needs_restart": needs_restart,
            "note": f"could not start HIL session: {type(error).__name__}: {error}",
        }
    try:
        from yggdrasim_common.gui_server.lifecycle import register_gui_service

        register_gui_service(service_name)
    except Exception:  # noqa: BLE001 - cleanup registration is best-effort
        pass

    if active_before and needs_restart:
        note = "HIL session restarted for the selected capture mode."
    elif active_before:
        note = "HIL session already active."
    else:
        note = "HIL session started."
    return {
        "ok": True,
        "mode": mode_s,
        "service": service_name,
        "unit_path": unit_path,
        "unit_changed": unit_changed,
        "capture_path": capture_path,
        "gsmtap_enabled": gsmtap_enabled,
        "active_before": active_before,
        "needs_restart": needs_restart,
        "status": status_payload,
        "note": note,
    }


def _dispatch_session_stop(
    ctx: ActionContext,
    *,
    confirm: Any = None,
) -> dict[str, Any]:
    """Stop the supervised HIL session."""
    if bool(confirm) is False:
        raise ValueError("confirm must be true — stopping HIL releases the bridge service.")

    from yggdrasim_common.hil_bridge_runtime import (
        DEFAULT_SERVICE_NAME,
        query_user_service_state,
        stop_user_service,
    )

    try:
        stop_user_service(DEFAULT_SERVICE_NAME)
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "service": DEFAULT_SERVICE_NAME,
            "note": f"could not stop HIL session: {type(error).__name__}: {error}",
        }
    try:
        from yggdrasim_common.gui_server.lifecycle import unregister_gui_service

        unregister_gui_service(DEFAULT_SERVICE_NAME)
    except Exception:  # noqa: BLE001 - cleanup registration is best-effort
        pass
    state = query_user_service_state(DEFAULT_SERVICE_NAME)
    return {
        "ok": True,
        "service": DEFAULT_SERVICE_NAME,
        "state": state,
        "note": "HIL session stopped.",
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


SESSION_START_SPEC = ActionSpec(
    id="hil.session_start",
    subsystem="HIL",
    title="Start HIL session",
    description=(
        "Prepare and start the supervised HIL bridge session. The decoded "
        "mode enables GSMTAP pcap capture for the GUI dissector; raw mode "
        "keeps only the APDU trace stream."
    ),
    inputs=(
        ActionField(
            name="mode",
            label="Attach mode",
            kind="enum",
            required=False,
            default=_HIL_SESSION_MODE_DECODED,
            choices=list(_HIL_SESSION_MODES),
            help="decoded = GUI dissector + raw APDU trace; raw = raw trace only; raw_wireshark = GSMTAP capture compatible with Wireshark.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_session_start,
    requires_card=False,
    streams=False,
    tags=("hil", "session", "start"),
)


SESSION_STOP_SPEC = ActionSpec(
    id="hil.session_stop",
    subsystem="HIL",
    title="Stop HIL session",
    description=(
        "Stop the supervised HIL bridge session and release the bridge "
        "service. Requires confirmation because it disrupts the live modem/card path."
    ),
    inputs=(
        ActionField(
            name="confirm",
            label="I understand this stops the HIL session",
            kind="bool",
            required=True,
            default=False,
            help="Must be true to stop the HIL bridge service.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_session_stop,
    requires_card=False,
    streams=False,
    tags=("hil", "session", "stop"),
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
    try:
        from yggdrasim_common.gui_server.lifecycle import register_gui_subprocess

        register_gui_subprocess("HIL bridge", proc)
    except Exception:  # noqa: BLE001 - cleanup registration is best-effort
        pass

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
    try:
        from yggdrasim_common.gui_server.lifecycle import register_gui_subprocess

        register_gui_subprocess("HIL supervisor", proc)
    except Exception:  # noqa: BLE001 - cleanup registration is best-effort
        pass

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
get_registry().register(DECODE_SNAPSHOT_SPEC)
get_registry().register(LIST_READERS_SPEC)
get_registry().register(SERVICE_STATUS_SPEC)
get_registry().register(SERVICE_CONTROL_SPEC)
get_registry().register(SESSION_START_SPEC)
get_registry().register(SESSION_STOP_SPEC)
get_registry().register(BRIDGE_CONFIG_SPEC)
get_registry().register(BRIDGE_LAUNCH_SPEC)
get_registry().register(SUPERVISOR_LAUNCH_SPEC)
