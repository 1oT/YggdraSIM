# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""GUI lifecycle cleanup for sessions and GUI-owned external services."""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any


_LOGGER = logging.getLogger("yggdrasim.gui.lifecycle")

_PROCESS_TERM_TIMEOUT_SECONDS = 1.0
_PROCESS_KILL_TIMEOUT_SECONDS = 1.0


@dataclass
class _GuiSubprocess:
    label: str
    process: Any


_LOCK = threading.Lock()
_GUI_SUBPROCESSES: dict[int, _GuiSubprocess] = {}
_GUI_SERVICES: set[str] = set()


def register_gui_subprocess(label: str, process: Any) -> None:
    """Track a subprocess launched from the GUI for shutdown cleanup."""
    try:
        pid = int(getattr(process, "pid", 0) or 0)
    except (TypeError, ValueError):
        pid = 0
    if pid <= 0:
        return
    with _LOCK:
        _GUI_SUBPROCESSES[pid] = _GuiSubprocess(
            label=str(label or "gui subprocess").strip() or "gui subprocess",
            process=process,
        )


def register_gui_service(service_name: str) -> None:
    """Track a user service that the GUI started or attached to."""
    normalized = str(service_name or "").strip()
    if len(normalized) == 0:
        return
    with _LOCK:
        _GUI_SERVICES.add(normalized)


def unregister_gui_service(service_name: str) -> None:
    """Forget a service after the GUI explicitly stops or disables it."""
    normalized = str(service_name or "").strip()
    if len(normalized) == 0:
        return
    with _LOCK:
        _GUI_SERVICES.discard(normalized)


def cleanup_gui_runtime(
    *,
    stop_external_services: bool = True,
    include_default_hil_service: bool = False,
    include_card_bridge_state: bool = False,
) -> dict[str, Any]:
    """Release GUI-owned runtime resources.

    Returns a compact JSON-compatible summary so tests and shutdown logs
    can verify what was attempted without exposing bearer tokens.
    """
    summary: dict[str, Any] = {
        "closed_sessions": _close_card_sessions(),
        "terminated_processes": [],
        "card_bridge": [],
        "services": [],
    }
    if stop_external_services:
        summary["terminated_processes"] = _terminate_registered_processes()
        if include_card_bridge_state:
            summary["card_bridge"] = _stop_card_bridge_runtime_state()
        summary["services"] = _stop_registered_services(
            include_default_hil_service=include_default_hil_service,
        )
    return summary


def _stop_card_bridge_runtime_state() -> list[dict[str, Any]]:
    try:
        from yggdrasim_common.gui_server.actions import card_bridge
        from yggdrasim_common.gui_server.actions.registry import ActionContext
    except Exception as error:  # noqa: BLE001
        return [{
            "action": "card_bridge",
            "status": "unavailable",
            "error": f"{type(error).__name__}: {error}",
        }]

    try:
        state = card_bridge._load_remote_rig_state()
    except Exception as error:  # noqa: BLE001
        return [{
            "action": "card_bridge",
            "status": "state-error",
            "error": f"{type(error).__name__}: {error}",
        }]
    if len(state) == 0:
        return []

    results: list[dict[str, Any]] = []
    tunnel_pid = _coerce_pid(state.get("ssh_tunnel_pid"))
    if tunnel_pid > 0:
        results.append(_run_card_bridge_stop_action(
            "ssh_tunnel_stop",
            lambda: card_bridge._dispatch_tunnel_stop(ActionContext(), confirm=True),
        ))

    local_pid = _coerce_pid(state.get("local_card_bridge_pid"))
    has_local_bridge_state = (
        local_pid > 0
        or "local_card_bridge_port" in state
        or "local_card_bridge_log" in state
        or "local_card_bridge_command" in state
    )
    if has_local_bridge_state:
        results.append(_run_card_bridge_stop_action(
            "pc_card_bridge_stop",
            lambda: card_bridge._dispatch_local_stop(ActionContext(), confirm=True),
        ))

    return results


def _run_card_bridge_stop_action(label: str, action: Any) -> dict[str, Any]:
    try:
        payload = action()
    except Exception as error:  # noqa: BLE001
        _LOGGER.warning("GUI Card Bridge cleanup failed action=%s: %s", label, error)
        return {
            "action": label,
            "ok": False,
            "status": "error",
            "error": f"{type(error).__name__}: {error}",
        }
    result = dict(payload or {})
    result["action"] = label
    return result


def _coerce_pid(value: Any) -> int:
    try:
        pid = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return pid if pid > 0 else 0


def _close_card_sessions() -> int:
    try:
        from yggdrasim_common.gui_server.sessions import get_manager
    except Exception as error:  # noqa: BLE001
        _LOGGER.warning("GUI session cleanup unavailable: %s", error)
        return 0
    try:
        return int(get_manager().close_all())
    except Exception as error:  # noqa: BLE001
        _LOGGER.warning("GUI session cleanup failed: %s", error)
        return 0


def _terminate_registered_processes() -> list[dict[str, Any]]:
    with _LOCK:
        entries = list(_GUI_SUBPROCESSES.values())
        _GUI_SUBPROCESSES.clear()

    results: list[dict[str, Any]] = []
    for entry in entries:
        process = entry.process
        try:
            pid = int(getattr(process, "pid", 0) or 0)
        except (TypeError, ValueError):
            pid = 0
        if pid <= 0:
            continue

        poll = getattr(process, "poll", None)
        if callable(poll):
            try:
                if poll() is not None:
                    results.append({"label": entry.label, "pid": pid, "status": "already-exited"})
                    continue
            except Exception:  # noqa: BLE001
                pass

        status_text = "terminated"
        error_text = ""
        try:
            _send_process_signal(process, signal.SIGTERM)
            _wait_process(process, _PROCESS_TERM_TIMEOUT_SECONDS)
            if _process_still_running(process):
                _send_process_signal(process, signal.SIGKILL)
                _wait_process(process, _PROCESS_KILL_TIMEOUT_SECONDS)
                status_text = "killed"
            if _process_still_running(process):
                status_text = "still-running"
        except ProcessLookupError:
            status_text = "already-exited"
        except Exception as error:  # noqa: BLE001
            status_text = "error"
            error_text = f"{type(error).__name__}: {error}"
            _LOGGER.warning(
                "GUI subprocess cleanup failed label=%s pid=%s: %s",
                entry.label,
                pid,
                error_text,
            )
        results.append({
            "label": entry.label,
            "pid": pid,
            "status": status_text,
            "error": error_text,
        })
    return results


def _send_process_signal(process: Any, signum: int) -> None:
    pid = int(getattr(process, "pid", 0) or 0)
    if pid <= 0:
        return
    if hasattr(os, "killpg"):
        try:
            os.killpg(pid, signum)
            return
        except ProcessLookupError:
            raise
        except OSError:
            pass
    if signum == signal.SIGTERM:
        terminate = getattr(process, "terminate", None)
        if callable(terminate):
            terminate()
            return
    if signum == signal.SIGKILL:
        kill = getattr(process, "kill", None)
        if callable(kill):
            kill()
            return
    os.kill(pid, signum)


def _wait_process(process: Any, timeout_seconds: float) -> None:
    wait = getattr(process, "wait", None)
    if not callable(wait):
        time.sleep(max(0.0, float(timeout_seconds)))
        return
    try:
        wait(timeout=max(0.0, float(timeout_seconds)))
    except TypeError:
        wait()
    except Exception:
        return


def _process_still_running(process: Any) -> bool:
    poll = getattr(process, "poll", None)
    if not callable(poll):
        return False
    try:
        return poll() is None
    except Exception:  # noqa: BLE001
        return False


def _stop_registered_services(*, include_default_hil_service: bool) -> list[dict[str, Any]]:
    try:
        from yggdrasim_common.hil_bridge_runtime import DEFAULT_SERVICE_NAME
    except Exception:  # noqa: BLE001
        DEFAULT_SERVICE_NAME = "yggdrasim-hil-supervisor.service"

    with _LOCK:
        service_names = set(_GUI_SERVICES)
        _GUI_SERVICES.clear()
    if include_default_hil_service:
        service_names.add(DEFAULT_SERVICE_NAME)

    results: list[dict[str, Any]] = []
    for service_name in sorted(service_names):
        results.append(_stop_hil_service(service_name))
    return results


def _stop_hil_service(service_name: str) -> dict[str, Any]:
    try:
        from yggdrasim_common.hil_bridge_runtime import (
            DEFAULT_SERVICE_NAME,
            clear_card_relay_state,
            clear_supervisor_state,
            query_user_service_state,
            stop_user_service,
        )
    except Exception as error:  # noqa: BLE001
        return {
            "service": service_name,
            "status": "unavailable",
            "error": f"{type(error).__name__}: {error}",
        }

    state = query_user_service_state(service_name)
    if str(state.get("activeState", "") or "").strip() != "active":
        if service_name == DEFAULT_SERVICE_NAME:
            clear_card_relay_state()
            clear_supervisor_state()
        return {
            "service": service_name,
            "status": "not-active",
            "state": state,
            "error": str(state.get("error", "") or ""),
        }

    error_text = ""
    status_text = "stopped"
    try:
        stop_user_service(service_name)
    except Exception as error:  # noqa: BLE001
        status_text = "error"
        error_text = f"{type(error).__name__}: {error}"
        _LOGGER.warning("GUI service cleanup failed service=%s: %s", service_name, error_text)

    if service_name == DEFAULT_SERVICE_NAME:
        clear_card_relay_state()
        clear_supervisor_state()
    return {
        "service": service_name,
        "status": status_text,
        "state": state,
        "error": error_text,
    }


def _reset_for_tests() -> None:
    with _LOCK:
        _GUI_SUBPROCESSES.clear()
        _GUI_SERVICES.clear()
