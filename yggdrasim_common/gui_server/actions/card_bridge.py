# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""``card_bridge.*`` actions — Command Center surface for the Card Bridge (CB-4).

Two read-only actions that let the GUI front-end inspect and probe a
remote card bridge without re-implementing the relay HTTP client:

* ``card_bridge.status`` — report the *currently configured* relay
  URL and token posture as resolved by ``card_backend``. Pure
  introspection: zero network traffic, safe to poll on a tight cadence.
* ``card_bridge.probe`` — open a short-lived ``GET /ping`` and
  ``GET /status`` against either the configured URL or an operator-
  supplied URL+token, return reachability, auth posture, ATR (when the
  bridge surfaces one), and round-trip latency.

The actions intentionally do *not* expose the raw bearer token in any
response payload. Token presence is conveyed via a 6-character SHA-256
fingerprint (``yggdrasim_common.card_bridge_auth.fingerprint``) so
operators can confirm the right token is wired up without leaking it
into GUI logs or screenshots.

The remote rig actions wrap the common HIL topology where the physical
card stays in a PC/SC reader on the operator workstation and the RPi
consumes it through an SSH reverse tunnel.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from yggdrasim_common.gui_server.actions.registry import (
    ActionContext,
    ActionField,
    ActionSpec,
    get_registry,
)

_LOGGER = logging.getLogger("yggdrasim.gui.actions.card_bridge")

# Hard cap on probe duration so a wedged remote can't stall the GUI's
# action queue. The probe issues at most two GETs; 4 s gives the
# bridge plenty of time to answer over an SSH tunnel even on a
# transatlantic link.
_PROBE_TIMEOUT_SECONDS = 2.0
_PROBE_MAX_RESPONSE_BYTES = 64 * 1024
_REMOTE_RIG_STATE_FILENAME = "card_bridge_remote_rig.json"
_DEFAULT_REMOTE_SERVICE_NAME = "yggdrasim-hil-supervisor.service"
_DEFAULT_REMOTE_CARD_URL = "http://127.0.0.1:8642/apdu"
_DEFAULT_REMOTE_TOKEN_FILE = "~/.config/yggdrasim/card_bridge/8642.token"
_DEFAULT_REMOTE_WORKDIR = "~/YggdraSIM"
_DEFAULT_REMOTE_PYTHON = "~/YggdraSIM/python/bin/python"
_DEFAULT_REMSIM_BINARY = "osmo-remsim-client-st2"
_REMOTE_GSMTAP_CAPTURE_RELATIVE = "state/hil_termshark/live_capture.pcap"
_DEFAULT_GUI_PORT = 27854
_DEFAULT_CARD_PORT = 8642
_DEFAULT_HIL_PORT = 9997
_DEFAULT_APDU_TIMEOUT_MS = 30000
_DEFAULT_USB_VIDPID = "1d50:60e3"
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]+\.service$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_apdu_suffix(url: str) -> str:
    candidate = url.strip()
    if candidate.endswith("/apdu"):
        candidate = candidate[: -len("/apdu")]
    return candidate.rstrip("/")


def _fingerprint(token: str) -> str:
    if len(token) == 0:
        return ""
    try:
        from yggdrasim_common.card_bridge_auth import fingerprint as _fp

        return _fp(token)
    except Exception:  # noqa: BLE001 — diagnostics-only path
        return ""


def _remote_rig_state_path() -> str:
    from yggdrasim_common.runtime_paths import ensure_runtime_dir, runtime_path

    ensure_runtime_dir("state")
    return runtime_path("state", _REMOTE_RIG_STATE_FILENAME)


def _load_remote_rig_state() -> dict[str, Any]:
    path = _remote_rig_state_path()
    if os.path.isfile(path) is False:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_remote_rig_state(updates: dict[str, Any]) -> dict[str, Any]:
    state = _load_remote_rig_state()
    state.update(updates)
    state["updated_at"] = time.time()
    path = _remote_rig_state_path()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return state


def _tail_text_file(path: str | Path, *, max_bytes: int = 4096) -> str:
    try:
        file_path = Path(path)
        with open(file_path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes), os.SEEK_SET)
            payload = handle.read(max_bytes)
    except OSError:
        return ""
    return payload.decode("utf-8", errors="replace").strip()


def _coerce_port(value: Any, default: int) -> int:
    try:
        port = int(value) if value is not None else int(default)
    except (TypeError, ValueError):
        port = int(default)
    if port < 1 or port > 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def _coerce_positive_int(value: Any, default: int) -> int:
    try:
        normalized = int(value) if value is not None else int(default)
    except (TypeError, ValueError):
        normalized = int(default)
    if normalized < 1:
        raise ValueError(f"value must be positive: {normalized}")
    return normalized


def _pid_is_running(pid: Any) -> bool:
    try:
        pid_i = int(pid or 0)
    except (TypeError, ValueError):
        return False
    if pid_i <= 0:
        return False
    try:
        os.kill(pid_i, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _terminate_process_group(pid: Any) -> dict[str, Any]:
    try:
        pid_i = int(pid or 0)
    except (TypeError, ValueError):
        pid_i = 0
    if pid_i <= 0:
        return {"ok": False, "pid": pid_i, "status": "missing-pid"}
    if _pid_is_running(pid_i) is False:
        return {"ok": True, "pid": pid_i, "status": "already-exited"}
    try:
        if hasattr(os, "killpg"):
            try:
                os.killpg(pid_i, signal.SIGTERM)
            except ProcessLookupError:
                os.kill(pid_i, signal.SIGTERM)
        else:
            os.kill(pid_i, signal.SIGTERM)
    except ProcessLookupError:
        return {"ok": True, "pid": pid_i, "status": "already-exited"}
    except OSError as error:
        return {
            "ok": False,
            "pid": pid_i,
            "status": "error",
            "error": f"{type(error).__name__}: {error}",
        }
    return {"ok": True, "pid": pid_i, "status": "terminated"}


def _detached_subprocess_kwargs() -> dict[str, Any]:
    """Return subprocess options for a separately terminable helper."""
    if os.name == "nt":
        creation_flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if creation_flag:
            return {"creationflags": creation_flag}
        return {}
    return {"start_new_session": True}


def _listen_socket_inodes_for_port(port: int) -> set[str]:
    inodes: set[str] = set()
    port_i = _coerce_port(port, _DEFAULT_CARD_PORT)
    port_hex = f"{port_i:04X}"
    for table_path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(table_path).read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines[1:]:
            parts = line.split()
            if len(parts) <= 9:
                continue
            local_address = parts[1]
            state = parts[3].upper()
            if state != "0A" or ":" not in local_address:
                continue
            _addr_hex, local_port_hex = local_address.rsplit(":", 1)
            if local_port_hex.upper() == port_hex:
                inodes.add(parts[9])
    return inodes


def _pid_socket_inodes(pid: int) -> set[str]:
    fd_dir = Path("/proc") / str(int(pid)) / "fd"
    inodes: set[str] = set()
    try:
        entries = list(fd_dir.iterdir())
    except OSError:
        return inodes
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[len("socket:[") : -1])
    return inodes


def _pid_cmdline(pid: int) -> list[str]:
    try:
        raw = (Path("/proc") / str(int(pid)) / "cmdline").read_bytes()
    except OSError:
        return []
    return [
        part.decode("utf-8", errors="replace")
        for part in raw.split(b"\0")
        if len(part) > 0
    ]


def _cmdline_is_card_bridge(command: list[str]) -> bool:
    if len(command) == 0:
        return False
    basenames = {Path(part).name for part in command}
    if "yggdrasim-card-bridge" in basenames:
        return True
    for index, part in enumerate(command):
        if part in {"Tools.CardBridge", "Tools.CardBridge.server"}:
            return True
        if part == "-m" and index + 1 < len(command):
            if command[index + 1] in {"Tools.CardBridge", "Tools.CardBridge.server"}:
                return True
    return False


def _find_local_card_bridge_listener_pid(port: Any) -> int:
    try:
        port_i = _coerce_port(port, _DEFAULT_CARD_PORT)
    except ValueError:
        return 0
    socket_inodes = _listen_socket_inodes_for_port(port_i)
    if len(socket_inodes) == 0:
        return 0
    try:
        proc_entries = list(Path("/proc").iterdir())
    except OSError:
        return 0
    for proc_entry in proc_entries:
        if proc_entry.name.isdigit() is False:
            continue
        pid = int(proc_entry.name)
        if _cmdline_is_card_bridge(_pid_cmdline(pid)) is False:
            continue
        if len(socket_inodes.intersection(_pid_socket_inodes(pid))) > 0:
            return pid
    return 0


def _terminate_local_card_bridge_for_state(state: dict[str, Any]) -> dict[str, Any]:
    result = _terminate_process_group(state.get("local_card_bridge_pid", 0))
    status = str(result.get("status") or "")
    if status not in {"missing-pid", "already-exited"}:
        return result
    port = _coerce_port(state.get("local_card_bridge_port", _DEFAULT_CARD_PORT), _DEFAULT_CARD_PORT)
    listener_pid = _find_local_card_bridge_listener_pid(port)
    if listener_pid <= 0:
        return {
            **result,
            "port": port,
            "note": "No GUI-owned or discoverable Card Bridge process was registered.",
        }
    discovered_result = _terminate_process_group(listener_pid)
    return {
        **discovered_result,
        "port": port,
        "discovered_pid": listener_pid,
        "note": "Discovered and stopped the Card Bridge process listening on the PC card port.",
    }


def _validate_ssh_target(target: Any) -> str:
    normalized = str(target or "").strip()
    if len(normalized) == 0:
        raise ValueError("ssh_target is required")
    if normalized.startswith("-"):
        raise ValueError("ssh_target must not start with '-'")
    if any(ord(ch) < 32 for ch in normalized):
        raise ValueError("ssh_target contains control characters")
    return normalized


def _validate_service_name(service_name: Any) -> str:
    normalized = str(service_name or _DEFAULT_REMOTE_SERVICE_NAME).strip()
    if _SERVICE_NAME_RE.fullmatch(normalized) is None:
        raise ValueError(
            "service_name must be a simple systemd unit name ending in .service"
        )
    return normalized


def _ssh_base_command(
    *,
    ssh_target: Any,
    identity_file: Any = None,
    ssh_path: Any = None,
    connect_timeout: Any = None,
) -> list[str]:
    target = _validate_ssh_target(ssh_target)
    binary = str(ssh_path or "ssh").strip() or "ssh"
    timeout_i = _coerce_positive_int(connect_timeout, 8)
    command = [
        binary,
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout_i}",
    ]
    identity = str(identity_file or "").strip()
    if len(identity) > 0:
        command.extend(["-i", os.path.expanduser(identity)])
    command.append(target)
    return command


def _run_ssh_command(
    *,
    ssh_target: Any,
    remote_command: str,
    identity_file: Any = None,
    ssh_path: Any = None,
    connect_timeout: Any = None,
    timeout_seconds: Any = None,
    stdin_text: str = "",
) -> dict[str, Any]:
    timeout_i = _coerce_positive_int(timeout_seconds, 20)
    command = _ssh_base_command(
        ssh_target=ssh_target,
        identity_file=identity_file,
        ssh_path=ssh_path,
        connect_timeout=connect_timeout,
    )
    command.append(str(remote_command or "").strip())
    completed = subprocess.run(
        command,
        input=stdin_text if len(stdin_text) > 0 else None,
        capture_output=True,
        text=True,
        timeout=timeout_i,
        check=False,
    )
    stdout_text = str(completed.stdout or "").strip()
    stderr_text = str(completed.stderr or "").strip()
    return {
        "ok": completed.returncode == 0,
        "returncode": int(completed.returncode),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "command": _redact_command(command),
    }


def _redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for index, part in enumerate(command):
        text = str(part)
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        if text in {"-i"}:
            redacted.append(text)
            skip_next = True
            continue
        if index == len(command) - 1 and "Authorization:" in text:
            redacted.append("<remote-command>")
            continue
        redacted.append(text)
    return redacted


def _build_ssh_tunnel_command(
    *,
    ssh_target: Any,
    local_card_port: Any = None,
    remote_card_port: Any = None,
    local_gui_port: Any = None,
    remote_gui_port: Any = None,
    identity_file: Any = None,
    ssh_path: Any = None,
    connect_timeout: Any = None,
    forward_gui: Any = True,
) -> list[str]:
    local_card = _coerce_port(local_card_port, _DEFAULT_CARD_PORT)
    remote_card = _coerce_port(remote_card_port, _DEFAULT_CARD_PORT)
    command = _ssh_base_command(
        ssh_target=ssh_target,
        identity_file=identity_file,
        ssh_path=ssh_path,
        connect_timeout=connect_timeout,
    )
    forward_parts = [
        "-N",
        "-T",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-R",
        f"{remote_card}:127.0.0.1:{local_card}",
    ]
    if bool(forward_gui):
        local_gui = _coerce_port(local_gui_port, _DEFAULT_GUI_PORT)
        remote_gui = _coerce_port(remote_gui_port, _DEFAULT_GUI_PORT)
        forward_parts.extend(["-L", f"{local_gui}:127.0.0.1:{remote_gui}"])
    command[1:1] = forward_parts
    return command


def _render_remote_hil_unit(
    *,
    remote_workdir: Any,
    remote_python: Any,
    service_name: Any = None,
    remote_card_url: Any = None,
    remote_token_file: Any = None,
    remsim_binary: Any = None,
    usb_vidpid: Any = None,
    hil_port: Any = None,
    apdu_timeout_ms: Any = None,
    gsmtap_capture_path: Any = None,
) -> str:
    del service_name
    workdir = str(remote_workdir or "").strip()
    if len(workdir) == 0:
        raise ValueError("remote_workdir is required")
    python_executable = _systemd_path(str(remote_python or "python3").strip() or "python3")
    card_url = str(remote_card_url or _DEFAULT_REMOTE_CARD_URL).strip()
    token_file = _systemd_path(str(remote_token_file or _DEFAULT_REMOTE_TOKEN_FILE).strip())
    remsim_binary_s = _systemd_path(str(remsim_binary or _DEFAULT_REMSIM_BINARY).strip())
    vidpid = str(usb_vidpid or _DEFAULT_USB_VIDPID).strip()
    port_i = _coerce_port(hil_port, _DEFAULT_HIL_PORT)
    timeout_i = _coerce_positive_int(apdu_timeout_ms, _DEFAULT_APDU_TIMEOUT_MS)
    capture_path = str(
        gsmtap_capture_path or _remote_gsmtap_capture_path(workdir)
    ).strip()
    exec_parts = [
        python_executable,
        "-m",
        "Tools.HilBridge.supervisor",
        "--remote-card-url",
        card_url,
        "--remote-card-token-file",
        token_file,
        "--remsim-binary",
        remsim_binary_s,
        "--host",
        "127.0.0.1",
        "--port",
        str(port_i),
        "--advertise-host",
        "127.0.0.1",
        "--usb-vidpid",
        vidpid,
        "--apdu-timeout-ms",
        str(timeout_i),
    ]
    if len(capture_path) > 0:
        exec_parts.extend(
            [
                "--gsmtap-capture-path",
                _systemd_path(capture_path),
            ]
        )
    exec_start = " ".join(_systemd_quote(part) for part in exec_parts)
    return (
        "[Unit]\n"
        "Description=YggdraSIM remote-card HIL bridge supervisor\n"
        "After=default.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={_systemd_quote(_systemd_path(workdir))}\n"
        "Environment=PYTHONUNBUFFERED=1\n"
        f"ExecStart={exec_start}\n"
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "KillMode=mixed\n"
        "TimeoutStopSec=10\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def _systemd_quote(value: str) -> str:
    text = str(value or "")
    if len(text) == 0:
        return '""'
    safe_characters = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._/:=@~%")
    if all(character in safe_characters for character in text):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _systemd_path(value: str) -> str:
    text = str(value or "").strip()
    if text == "~":
        return "%h"
    if text.startswith("~/"):
        return "%h/" + text[2:]
    return text


def _remote_gsmtap_capture_path(remote_workdir: Any = None) -> str:
    workdir = str(remote_workdir or _DEFAULT_REMOTE_WORKDIR).strip()
    if len(workdir) == 0:
        workdir = _DEFAULT_REMOTE_WORKDIR
    return workdir.rstrip("/") + "/" + _REMOTE_GSMTAP_CAPTURE_RELATIVE


def _remote_shell_path_expr(value: str) -> str:
    text = str(value or "").strip()
    if text == "~" or text == "%h":
        return "$HOME"
    if text.startswith("~/"):
        return "$HOME/" + shlex.quote(text[2:])
    if text.startswith("%h/"):
        return "$HOME/" + shlex.quote(text[3:])
    return shlex.quote(text)


def _parse_systemctl_show(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in str(text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _resolve_configured() -> dict[str, Any]:
    """Return the relay URL/token snapshot as ``card_backend`` would resolve them.

    Mirrors the resolution chain used by ``RelayCardConnection`` so the
    GUI sees exactly what a card-consuming CLI would see at the same
    instant. Returned dict contains plain JSON-serialisable values
    only — no raw tokens.
    """
    snapshot: dict[str, Any] = {
        "configured": False,
        "url": "",
        "url_source": "",
        "base_url": "",
        "has_token": False,
        "token_fingerprint": "",
        "token_source": "",
    }
    try:
        from yggdrasim_common.card_backend import (
            CARD_RELAY_TOKEN_ENV,
            CARD_RELAY_TOKEN_FILE_ENV,
            _resolve_card_relay_url,
            _resolve_card_relay_token,
        )
    except Exception as error:  # noqa: BLE001
        snapshot["error"] = f"card_backend unavailable: {error.__class__.__name__}"
        return snapshot

    try:
        url, source = _resolve_card_relay_url()
    except Exception as error:  # noqa: BLE001
        snapshot["error"] = f"resolve URL failed: {error.__class__.__name__}: {error}"
        return snapshot

    if len(url) == 0:
        return snapshot

    snapshot["configured"] = True
    snapshot["url"] = url
    snapshot["url_source"] = source
    snapshot["base_url"] = _strip_apdu_suffix(url)

    try:
        token = _resolve_card_relay_token(allow_marker=True)
    except Exception as error:  # noqa: BLE001
        snapshot["error"] = f"resolve token failed: {error.__class__.__name__}: {error}"
        return snapshot

    if len(token) > 0:
        snapshot["has_token"] = True
        snapshot["token_fingerprint"] = _fingerprint(token)
        # Identify which env knob produced the token so operators can
        # spot stale env state at a glance.
        if len(str(os.environ.get(CARD_RELAY_TOKEN_ENV, "")).strip()) > 0:
            snapshot["token_source"] = "env-raw"
        elif len(str(os.environ.get(CARD_RELAY_TOKEN_FILE_ENV, "")).strip()) > 0:
            snapshot["token_source"] = "env-file"
        else:
            snapshot["token_source"] = "marker"
    return snapshot


def _http_get_json(
    base_url: str,
    path: str,
    *,
    token: str,
    timeout_seconds: float = _PROBE_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any] | None, float, str]:
    """Issue ``GET base_url + path`` and return ``(status, json|None, latency_ms, error)``.

    On transport failure ``status`` is ``0`` and ``error`` carries a
    short class+message string. Body parsing failures yield
    ``json=None`` with ``status`` and ``latency_ms`` populated; the
    caller decides whether that's fatal.
    """
    full = f"{base_url}{path}"
    request = urllib.request.Request(full, method="GET")
    request.add_header("Accept", "application/json")
    if len(token) > 0:
        request.add_header("Authorization", f"Bearer {token}")

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status_code = int(response.status)
            payload_raw = response.read(_PROBE_MAX_RESPONSE_BYTES + 1)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
        if len(payload_raw) > _PROBE_MAX_RESPONSE_BYTES:
            return status_code, None, elapsed_ms, "response too large"
        try:
            decoded = json.loads(payload_raw.decode("utf-8", errors="replace"))
        except Exception:
            return status_code, None, elapsed_ms, ""
        if not isinstance(decoded, dict):
            return status_code, None, elapsed_ms, ""
        return status_code, decoded, elapsed_ms, ""
    except urllib.error.HTTPError as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return int(error.code), None, elapsed_ms, f"HTTP {error.code} ({error.reason})"
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return 0, None, elapsed_ms, f"{error.__class__.__name__}: {error}"


def _http_post_json(
    base_url: str,
    path: str,
    *,
    token: str,
    payload: dict[str, Any] | None = None,
    timeout_seconds: float = _PROBE_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any] | None, float, str]:
    full = f"{base_url}{path}"
    encoded = json.dumps(payload or {}).encode("utf-8")
    request = urllib.request.Request(full, data=encoded, method="POST")
    request.add_header("Accept", "application/json")
    request.add_header("Content-Type", "application/json")
    if len(token) > 0:
        request.add_header("Authorization", f"Bearer {token}")

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status_code = int(response.status)
            payload_raw = response.read(_PROBE_MAX_RESPONSE_BYTES + 1)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
        if len(payload_raw) > _PROBE_MAX_RESPONSE_BYTES:
            return status_code, None, elapsed_ms, "response too large"
        try:
            decoded = json.loads(payload_raw.decode("utf-8", errors="replace"))
        except Exception:
            return status_code, None, elapsed_ms, ""
        if not isinstance(decoded, dict):
            return status_code, None, elapsed_ms, ""
        return status_code, decoded, elapsed_ms, ""
    except urllib.error.HTTPError as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        payload_raw = error.read(_PROBE_MAX_RESPONSE_BYTES + 1)
        error_text = f"HTTP {error.code} ({error.reason})"
        if len(payload_raw) <= _PROBE_MAX_RESPONSE_BYTES:
            try:
                decoded = json.loads(payload_raw.decode("utf-8", errors="replace"))
            except Exception:
                decoded = None
            if isinstance(decoded, dict):
                return int(error.code), decoded, elapsed_ms, error_text
        return int(error.code), None, elapsed_ms, error_text
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return 0, None, elapsed_ms, f"{error.__class__.__name__}: {error}"


def _read_local_card_token(
    *,
    port: Any = None,
    token_file: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.card_bridge_auth import default_token_file_for_port

    port_i = _coerce_port(port, _DEFAULT_CARD_PORT)
    token_path_s = str(token_file or "").strip()
    token_path = (
        Path(os.path.expanduser(token_path_s))
        if len(token_path_s) > 0
        else default_token_file_for_port(port_i)
    )
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError as error:
        return {
            "ok": False,
            "token": "",
            "token_file": str(token_path),
            "error": f"{type(error).__name__}: {error}",
        }
    return {
        "ok": len(token) > 0,
        "token": token,
        "token_file": str(token_path),
        "token_fingerprint": _fingerprint(token),
        "error": "" if len(token) > 0 else "token file is empty",
    }


def _publish_local_card_relay_marker(
    *,
    port: Any,
    token_file: Any,
    reader: Any = "",
    atr: Any = "",
) -> dict[str, Any]:
    from yggdrasim_common.hil_bridge_runtime import card_relay_state_path

    port_i = _coerce_port(port, _DEFAULT_CARD_PORT)
    apdu_url = f"http://127.0.0.1:{port_i}/apdu"
    status_url = f"http://127.0.0.1:{port_i}/status"
    marker_path = Path(card_relay_state_path())
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": "ok",
        "url": apdu_url,
        "apduUrl": apdu_url,
        "statusUrl": status_url,
        "tokenFile": str(token_file or ""),
        "reader": str(reader or ""),
        "atr": str(atr or "").upper(),
        "source": "card_bridge.remote_rig",
        "updatedAt": time.time(),
    }
    with open(marker_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return {
        "ok": True,
        "marker_path": str(marker_path),
        "url": apdu_url,
        "token_file": str(token_file or ""),
    }


def _clear_local_card_relay_marker() -> None:
    from yggdrasim_common.hil_bridge_runtime import clear_card_relay_state

    clear_card_relay_state()


def _clear_remote_hil_attachment_state() -> None:
    _write_remote_rig_state({"remote_gsmtap_capture_path": ""})


def _wait_for_local_card_bridge(
    *,
    port: Any = None,
    token_file: Any = None,
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    port_i = _coerce_port(port, _DEFAULT_CARD_PORT)
    base_url = f"http://127.0.0.1:{port_i}"
    deadline = time.monotonic() + max(0.5, float(timeout_seconds))
    last_error = ""
    ping_status = 0
    while time.monotonic() < deadline:
        ping_status, _payload, _latency, last_error = _http_get_json(
            base_url,
            "/ping",
            token="",
            timeout_seconds=0.75,
        )
        if ping_status == 200:
            break
        time.sleep(0.15)
    if ping_status != 200:
        return {
            "ok": False,
            "port": port_i,
            "status": "unreachable",
            "error": last_error or f"ping returned HTTP {ping_status}",
            "note": "PC Card Bridge did not answer on localhost.",
        }

    token_payload = _read_local_card_token(port=port_i, token_file=token_file)
    token = str(token_payload.get("token") or "")
    status_code, status_payload, _latency, status_error = _http_get_json(
        base_url,
        "/status",
        token=token,
        timeout_seconds=2.0,
    )
    if status_code != 200:
        reason = status_error or f"status returned HTTP {status_code}"
        if status_code == 401 and len(token) == 0:
            reason = f"status requires a token but no token was readable from {token_payload.get('token_file')}"
        return {
            "ok": False,
            "port": port_i,
            "status": "status-failed",
            "status_code": status_code,
            "token_file": token_payload.get("token_file", ""),
            "error": reason,
            "note": "PC Card Bridge is reachable but status verification failed.",
        }

    status_dict = dict(status_payload or {})
    try:
        bridge_pid = int(status_dict.get("pid", 0) or 0)
    except (TypeError, ValueError):
        bridge_pid = 0
    atr = str(status_dict.get("atrHex") or status_dict.get("atr") or "").upper()
    card_status = str(status_dict.get("card") or "").lower()
    card_available = len(atr) > 0 or card_status in {"available", "present", "ok"}
    return {
        "ok": card_available,
        "pid": bridge_pid,
        "port": port_i,
        "status": "available" if card_available else (card_status or "unknown"),
        "reader": str(status_dict.get("reader") or ""),
        "atr": atr,
        "token_file": token_payload.get("token_file", ""),
        "token_fingerprint": token_payload.get("token_fingerprint", ""),
        "note": (
            "PC Card Bridge can reach the local card."
            if card_available
            else "PC Card Bridge is running but the card is not available."
        ),
    }


def _reset_local_card_bridge(
    *,
    port: Any = None,
    token_file: Any = None,
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    port_i = _coerce_port(port, _DEFAULT_CARD_PORT)
    base_url = f"http://127.0.0.1:{port_i}"
    token_payload = _read_local_card_token(port=port_i, token_file=token_file)
    token = str(token_payload.get("token") or "")
    status_code, status_payload, latency_ms, status_error = _http_post_json(
        base_url,
        "/card/reset",
        token=token,
        payload={"sessionId": "remote-rig-start"},
        timeout_seconds=timeout_seconds,
    )
    if status_code != 200:
        reason = status_error or f"reset returned HTTP {status_code}"
        if isinstance(status_payload, dict) and len(str(status_payload.get("error") or "")) > 0:
            reason = f"{reason}: {status_payload.get('error')}"
        if status_code == 401 and len(token) == 0:
            reason = f"reset requires a token but no token was readable from {token_payload.get('token_file')}"
        return {
            "ok": False,
            "port": port_i,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "token_file": token_payload.get("token_file", ""),
            "error": reason,
            "note": "PC Card Bridge reset failed.",
        }

    status_dict = dict(status_payload or {})
    atr = str(status_dict.get("atrHex") or status_dict.get("atr") or "").upper()
    reader = str(status_dict.get("reader") or "")
    return {
        "ok": len(atr) > 0,
        "port": port_i,
        "status": str(status_dict.get("status") or "reset"),
        "reader": reader,
        "atr": atr,
        "reset": dict(status_dict.get("reset") or {}),
        "latency_ms": latency_ms,
        "token_file": token_payload.get("token_file", ""),
        "token_fingerprint": token_payload.get("token_fingerprint", ""),
        "note": (
            "PC Card Bridge PC/SC handle refreshed."
            if len(atr) > 0
            else "PC Card Bridge reset completed but no ATR was reported."
        ),
    }


def _remember_reused_local_card_bridge(
    *,
    port: int,
    check: dict[str, Any],
) -> dict[str, Any]:
    try:
        bridge_pid = int(check.get("pid", 0) or 0)
    except (TypeError, ValueError):
        bridge_pid = 0
    if bridge_pid <= 0:
        bridge_pid = _find_local_card_bridge_listener_pid(port)
    _write_remote_rig_state({
        "local_card_bridge_pid": bridge_pid,
        "local_card_bridge_port": port,
        "local_card_bridge_external": True,
        "local_card_bridge_verified_at": time.time(),
        "local_card_bridge_reader": str(check.get("reader") or ""),
        "local_card_bridge_atr": str(check.get("atr") or ""),
        "local_card_bridge_token_file": str(check.get("token_file") or ""),
    })
    return {
        "ok": True,
        "pid": bridge_pid,
        "port": port,
        "already_running": True,
        "external": True,
        "reader": str(check.get("reader") or ""),
        "atr": str(check.get("atr") or ""),
        "token_file": str(check.get("token_file") or ""),
        "token_fingerprint": str(check.get("token_fingerprint") or ""),
        "note": "Card Bridge is already reachable on the PC side; reusing it.",
    }


def _remote_card_ping(
    *,
    ssh_target: Any,
    identity_file: Any = None,
    remote_card_port: Any = None,
) -> dict[str, Any]:
    port_i = _coerce_port(remote_card_port, _DEFAULT_CARD_PORT)
    url = f"http://127.0.0.1:{port_i}/ping"
    result = _run_ssh_command(
        ssh_target=ssh_target,
        identity_file=identity_file,
        remote_command=f"curl -fsS --max-time 4 {shlex.quote(url)}",
        timeout_seconds=8,
    )
    return {
        **result,
        "port": port_i,
        "note": (
            "RPi can reach the PC Card Bridge through the reverse tunnel."
            if result.get("ok")
            else "RPi cannot reach the PC Card Bridge through the reverse tunnel."
        ),
    }


def _remote_card_status(
    *,
    ssh_target: Any,
    identity_file: Any = None,
    remote_card_port: Any = None,
    remote_token_file: Any = None,
) -> dict[str, Any]:
    port_i = _coerce_port(remote_card_port, _DEFAULT_CARD_PORT)
    token_path = str(remote_token_file or _DEFAULT_REMOTE_TOKEN_FILE).strip()
    remote_file = _remote_shell_path_expr(token_path)
    url = f"http://127.0.0.1:{port_i}/status"
    remote_command = (
        f"TOKEN=$(cat {remote_file}) && "
        f"curl -fsS --max-time 5 -H \"Authorization: Bearer $TOKEN\" {shlex.quote(url)}"
    )
    result = _run_ssh_command(
        ssh_target=ssh_target,
        identity_file=identity_file,
        remote_command=remote_command,
        timeout_seconds=10,
    )
    payload: dict[str, Any] = {}
    parse_error = ""
    if result.get("ok"):
        try:
            decoded = json.loads(str(result.get("stdout") or "{}"))
            if isinstance(decoded, dict):
                payload = decoded
        except json.JSONDecodeError as error:
            parse_error = f"JSONDecodeError: {error}"
    atr = str(payload.get("atrHex") or payload.get("atr") or "").upper()
    return {
        "ok": bool(result.get("ok")) and len(parse_error) == 0,
        "returncode": result.get("returncode", 0),
        "stderr": result.get("stderr", ""),
        "token_file": token_path,
        "reader": str(payload.get("reader") or ""),
        "atr": atr,
        "card": str(payload.get("card") or ""),
        "token_fingerprint": str(payload.get("tokenFingerprint") or ""),
        "parse_error": parse_error,
        "note": (
            "RPi authenticated to the PC Card Bridge."
            if bool(result.get("ok")) and len(parse_error) == 0
            else "RPi Card Bridge status check failed."
        ),
    }


# ---------------------------------------------------------------------------
# card_bridge.status
# ---------------------------------------------------------------------------


def _dispatch_status(ctx: ActionContext, **_inputs: Any) -> dict[str, Any]:
    snapshot = _resolve_configured()
    if snapshot.get("configured") is True:
        snapshot["summary"] = (
            f"Configured: {snapshot.get('url')} "
            f"(via {snapshot.get('url_source')}); "
            + ("token present" if snapshot.get("has_token") else "no token")
        )
    else:
        snapshot["summary"] = "Not configured (using local PC/SC reader)."
    return snapshot


STATUS_SPEC = ActionSpec(
    id="card_bridge.status",
    subsystem="Card Bridge",
    title="Status",
    description=(
        "Report the currently configured remote card-bridge URL plus "
        "token posture as the running process would resolve them. "
        "Pure introspection — no network traffic. Use this to verify "
        "that --remote-card-url / YGGDRASIM_CARD_RELAY_URL took "
        "effect before opening a card session."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_status,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "diagnostics", "read-only"),
)


# ---------------------------------------------------------------------------
# card_bridge.probe
# ---------------------------------------------------------------------------


def _dispatch_probe(
    ctx: ActionContext,
    *,
    url: str = "",
    token: str = "",
    use_configured: bool = True,
) -> dict[str, Any]:
    """Probe a Card Bridge endpoint and return a structured health report.

    When *use_configured* is true (default) we fall back to the
    resolved configuration if the operator didn't supply an explicit
    URL/token in the form. That makes the action one click for the
    common case where the bridge is already wired up via env vars.
    """
    operator_url = str(url or "").strip()
    operator_token = str(token or "").strip()

    snapshot = _resolve_configured() if bool(use_configured) else {
        "configured": False,
        "url": "",
        "base_url": "",
        "has_token": False,
        "token_fingerprint": "",
    }

    target_url = operator_url
    target_token = operator_token
    used_configured_url = False
    used_configured_token = False
    if len(target_url) == 0 and bool(use_configured):
        target_url = str(snapshot.get("url") or "")
        used_configured_url = True
    if len(target_token) == 0 and bool(use_configured):
        # Fall back to whatever ``card_backend`` would resolve. We
        # don't echo the resolved token back to the client — the
        # fingerprint already conveys "we have one".
        try:
            from yggdrasim_common.card_backend import _resolve_card_relay_token

            target_token = _resolve_card_relay_token(allow_marker=True)
            used_configured_token = len(target_token) > 0
        except Exception as error:  # noqa: BLE001
            target_token = ""
            snapshot["resolve_error"] = (
                f"resolve token failed: {error.__class__.__name__}: {error}"
            )

    if len(target_url) == 0:
        return {
            "ok": False,
            "reason": "no URL — set --remote-card-url, YGGDRASIM_CARD_RELAY_URL, or pass `url` to this action.",
            "configured": snapshot,
        }

    base_url = _strip_apdu_suffix(target_url)
    fingerprint = _fingerprint(target_token)

    ping_status, ping_payload, ping_ms, ping_error = _http_get_json(
        base_url, "/ping", token=target_token
    )
    if ping_status == 0:
        return {
            "ok": False,
            "reason": ping_error or "ping failed",
            "url": base_url,
            "ping_latency_ms": round(ping_ms, 2),
            "token_fingerprint": fingerprint,
            "used_configured_url": used_configured_url,
            "used_configured_token": used_configured_token,
        }

    if ping_status != 200:
        return {
            "ok": False,
            "reason": ping_error or f"ping returned HTTP {ping_status}",
            "url": base_url,
            "ping_status": ping_status,
            "ping_latency_ms": round(ping_ms, 2),
            "token_fingerprint": fingerprint,
            "used_configured_url": used_configured_url,
            "used_configured_token": used_configured_token,
        }

    status_status, status_payload, status_ms, status_error = _http_get_json(
        base_url, "/status", token=target_token
    )

    auth_required = False
    bridge_fingerprint = ""
    bind_host = ""
    audit_enabled: object = None
    reader = ""
    atr_hex = ""
    if isinstance(status_payload, dict):
        auth_required = bool(status_payload.get("authRequired"))
        bridge_fingerprint = str(status_payload.get("tokenFingerprint") or "")
        bind_host = str(
            status_payload.get("host") or status_payload.get("bindHost") or ""
        )
        audit_enabled = status_payload.get("auditEnabled")
        reader = str(status_payload.get("reader") or "")
        atr_hex = str(status_payload.get("atrHex") or status_payload.get("atr") or "").upper()

    # 401 is canonical "auth required, request not satisfied" — treat
    # it as authoritative regardless of whether the body bothered to
    # echo ``authRequired``. Some older relays returned 401 without a
    # JSON body at all.
    if status_status == 401:
        auth_required = True

    auth_posture = "no-token-required"
    if auth_required:
        if status_status == 401:
            auth_posture = "token-rejected"
        elif len(target_token) == 0:
            auth_posture = "token-required-but-missing"
        else:
            auth_posture = "token-accepted"
    elif len(bind_host) > 0 and bind_host not in {"127.0.0.1", "::1", "localhost"}:
        auth_posture = "auth-disabled-non-loopback"

    overall_ok = (
        status_status == 200
        and auth_posture in {"no-token-required", "token-accepted"}
    )

    return {
        "ok": overall_ok,
        "reason": "" if overall_ok else (status_error or f"status HTTP {status_status}"),
        "url": base_url,
        "ping_status": ping_status,
        "ping_latency_ms": round(ping_ms, 2),
        "status_status": status_status,
        "status_latency_ms": round(status_ms, 2),
        "auth_required": auth_required,
        "auth_posture": auth_posture,
        "token_fingerprint": fingerprint,
        "bridge_token_fingerprint": bridge_fingerprint,
        "fingerprint_match": (
            len(fingerprint) > 0
            and len(bridge_fingerprint) > 0
            and fingerprint == bridge_fingerprint
        ),
        "bind_host": bind_host,
        "audit_enabled": audit_enabled,
        "reader": reader,
        "atr_hex": atr_hex,
        "used_configured_url": used_configured_url,
        "used_configured_token": used_configured_token,
    }


PROBE_SPEC = ActionSpec(
    id="card_bridge.probe",
    subsystem="Card Bridge",
    title="Probe bridge",
    description=(
        "GET /ping and GET /status against the configured (or supplied) "
        "Card Bridge URL. Reports reachability, auth posture, latency, "
        "and ATR. Bearer tokens are never echoed back — only their "
        "6-char SHA-256 fingerprint is returned so operators can "
        "confirm the right token is wired up."
    ),
    inputs=(
        ActionField(
            name="url",
            label="Bridge URL",
            kind="string",
            required=False,
            placeholder="http://127.0.0.1:8642/apdu (leave blank to use configured)",
            help=(
                "Override the configured YGGDRASIM_CARD_RELAY_URL. "
                "Trailing /apdu is stripped automatically."
            ),
        ),
        ActionField(
            name="token",
            label="Bearer token",
            kind="string",
            required=False,
            secret=True,
            help=(
                "Override the resolved bearer token. Leave blank to use "
                "YGGDRASIM_CARD_RELAY_TOKEN / TOKEN_FILE / runtime marker."
            ),
        ),
        ActionField(
            name="use_configured",
            label="Fall back to configured values",
            kind="bool",
            default=True,
            help=(
                "When checked, blank URL/token fields fall back to the "
                "card_backend resolution chain. Uncheck to probe a "
                "completely independent endpoint."
            ),
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_probe,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "diagnostics", "read-only", "network"),
)


# ---------------------------------------------------------------------------
# card_bridge.token_generate
# ---------------------------------------------------------------------------


def _dispatch_token_generate(
    ctx: ActionContext,
    *,
    output_path: Any = None,
    port: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.card_bridge_auth import (
        generate_token,
        fingerprint,
        write_token_file,
        default_token_file_for_port,
    )

    port_i = int(port) if port is not None else 8642
    token = generate_token()
    fp = fingerprint(token)
    path_s = str(output_path or "").strip()
    if len(path_s) > 0:
        import pathlib
        out = pathlib.Path(path_s)
    else:
        out = default_token_file_for_port(port_i)

    written = write_token_file(out, token)
    return {
        "ok": True,
        "token_fingerprint": fp,
        "token_file": str(written),
        "port": port_i,
        "note": f"Token ({fp}) written to {written}.",
    }


TOKEN_GENERATE_SPEC = ActionSpec(
    id="card_bridge.token_generate",
    subsystem="Card Bridge",
    title="Generate token",
    description=(
        "Generate a cryptographically random bearer token, fingerprint "
        "it, and write it to a 0600 token file. Use this to provision "
        "a new shared secret for card-bridge SSH tunnels."
    ),
    inputs=(
        ActionField(
            name="output_path",
            label="Output path",
            kind="save_path",
            required=False,
            help="Where to write the token file; defaults to ~/.config/yggdrasim/card_bridge/<port>.token.",
        ),
        ActionField(
            name="port",
            label="Port",
            kind="int",
            required=False,
            default=8642,
            min_value=1,
            help="Bridge port number (influences the default token file name).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_token_generate,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "token", "security"),
)


# ---------------------------------------------------------------------------
# card_bridge.config
# ---------------------------------------------------------------------------


def _dispatch_config(ctx: ActionContext, **_inputs: Any) -> dict[str, Any]:
    snapshot = _resolve_configured()
    from yggdrasim_common.card_bridge_auth import default_token_file_for_port

    lines: list[dict[str, str]] = []
    lines.append({"key": "Configured", "value": "yes" if snapshot.get("configured") else "no"})
    lines.append({"key": "URL", "value": str(snapshot.get("url") or "-")})
    lines.append({"key": "URL source", "value": str(snapshot.get("url_source") or "-")})
    lines.append({"key": "Base URL", "value": str(snapshot.get("base_url") or "-")})
    lines.append({"key": "Token present", "value": "yes" if snapshot.get("has_token") else "no"})
    fp = str(snapshot.get("token_fingerprint") or "-")
    lines.append({"key": "Token fingerprint", "value": fp})
    lines.append({"key": "Token source", "value": str(snapshot.get("token_source") or "-")})
    lines.append({"key": "Default token file", "value": str(default_token_file_for_port(8642))})
    return {
        "ok": True,
        "lines": lines,
        "snapshot": snapshot,
        "note": "Card bridge configuration snapshot.",
    }


CONFIG_SPEC = ActionSpec(
    id="card_bridge.config",
    subsystem="Card Bridge",
    title="Configuration",
    description=(
        "Show the effective Card Bridge configuration: relay URL, token "
        "posture, and default token file path. Pure introspection — no "
        "network traffic."
    ),
    inputs=(),
    output_kind="key_value_lines",
    dispatcher=_dispatch_config,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "config", "read-only"),
)


# ---------------------------------------------------------------------------
# Remote rig orchestration
# ---------------------------------------------------------------------------


def _dispatch_local_start(
    ctx: ActionContext,
    *,
    port: Any = None,
    reader_index: Any = None,
    reader_name: Any = None,
    token_file: Any = None,
    apdu_timeout_ms: Any = None,
    restart: Any = None,
    reuse_existing: Any = False,
    confirm: Any = None,
) -> dict[str, Any]:
    del ctx
    if bool(confirm) is False:
        raise ValueError("confirm must be true — starting Card Bridge opens a local PC/SC relay.")

    port_i = _coerce_port(port, _DEFAULT_CARD_PORT)
    timeout_i = _coerce_positive_int(apdu_timeout_ms, _DEFAULT_APDU_TIMEOUT_MS)
    try:
        reader_index_i = int(reader_index) if reader_index is not None else 0
    except (TypeError, ValueError):
        reader_index_i = 0
    reader_name_s = str(reader_name or "").strip()
    token_file_s = str(token_file or "").strip()

    state = _load_remote_rig_state()
    existing_pid = int(state.get("local_card_bridge_pid", 0) or 0)
    if bool(reuse_existing):
        existing_check = _wait_for_local_card_bridge(
            port=port_i,
            token_file=token_file_s,
            timeout_seconds=0.75,
        )
        if bool(existing_check.get("ok")):
            return _remember_reused_local_card_bridge(
                port=port_i,
                check=existing_check,
            )

    if _pid_is_running(existing_pid):
        if bool(restart) is False:
            return {
                "ok": True,
                "pid": existing_pid,
                "already_running": True,
                "note": "Card Bridge is already running from this GUI state.",
            }
        _terminate_process_group(existing_pid)

    command = [
        sys.executable,
        "-m",
        "Tools.CardBridge",
        "--port",
        str(port_i),
        "--apdu-timeout-ms",
        str(timeout_i),
        "--pcsc-share-mode",
        "shared",
    ]
    if len(reader_name_s) > 0:
        command.extend(["--reader-name", reader_name_s])
    else:
        command.extend(["--reader-index", str(max(0, reader_index_i))])
    if len(token_file_s) > 0:
        command.extend(["--token-file", os.path.expanduser(token_file_s)])

    log_path = Path(_remote_rig_state_path()).with_suffix(".card_bridge.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            command,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            **_detached_subprocess_kwargs(),
        )
    time.sleep(0.2)
    if process.poll() is not None:
        reuse_check: dict[str, Any] = {}
        if bool(reuse_existing):
            reuse_check = _wait_for_local_card_bridge(
                port=port_i,
                token_file=token_file_s,
                timeout_seconds=1.5,
            )
            if bool(reuse_check.get("ok")):
                return _remember_reused_local_card_bridge(
                    port=port_i,
                    check=reuse_check,
                )
        _write_remote_rig_state({
            "local_card_bridge_pid": 0,
            "local_card_bridge_port": port_i,
            "local_card_bridge_log": str(log_path),
            "local_card_bridge_command": command,
            "local_card_bridge_external": False,
        })
        return {
            "ok": False,
            "pid": int(process.pid),
            "port": port_i,
            "returncode": int(process.returncode or 0),
            "log_path": str(log_path),
            "log_tail": _tail_text_file(log_path),
            "port_check": reuse_check,
            "note": "Card Bridge exited during startup.",
        }
    try:
        from yggdrasim_common.gui_server.lifecycle import register_gui_subprocess

        register_gui_subprocess("Card Bridge", process)
    except Exception:  # noqa: BLE001 - cleanup registration is best-effort
        pass

    _write_remote_rig_state({
        "local_card_bridge_pid": int(process.pid),
        "local_card_bridge_port": port_i,
        "local_card_bridge_log": str(log_path),
        "local_card_bridge_command": command,
        "local_card_bridge_external": False,
    })
    return {
        "ok": True,
        "pid": int(process.pid),
        "port": port_i,
        "log_path": str(log_path),
        "note": "Card Bridge started on the PC side.",
    }


def _dispatch_local_stop(
    ctx: ActionContext,
    *,
    confirm: Any = None,
) -> dict[str, Any]:
    del ctx
    if bool(confirm) is False:
        raise ValueError("confirm must be true — stopping Card Bridge disrupts the remote card path.")
    state = _load_remote_rig_state()
    result = _terminate_local_card_bridge_for_state(state)
    _clear_local_card_relay_marker()
    _clear_remote_hil_attachment_state()
    _write_remote_rig_state({
        "local_card_bridge_pid": 0,
        "local_card_bridge_external": False,
    })
    return {
        **result,
        "note": str(result.get("note") or "Card Bridge stop requested."),
    }


def _dispatch_tunnel_start(
    ctx: ActionContext,
    *,
    ssh_target: Any = None,
    identity_file: Any = None,
    local_card_port: Any = None,
    remote_card_port: Any = None,
    local_gui_port: Any = None,
    remote_gui_port: Any = None,
    forward_gui: Any = True,
    restart: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    del ctx
    if bool(confirm) is False:
        raise ValueError("confirm must be true — starting the tunnel opens SSH port forwards.")
    state = _load_remote_rig_state()
    existing_pid = int(state.get("ssh_tunnel_pid", 0) or 0)
    if _pid_is_running(existing_pid):
        if bool(restart) is False:
            return {
                "ok": True,
                "pid": existing_pid,
                "already_running": True,
                "note": "SSH tunnel is already running from this GUI state.",
            }
        _terminate_process_group(existing_pid)

    command = _build_ssh_tunnel_command(
        ssh_target=ssh_target,
        identity_file=identity_file,
        local_card_port=local_card_port,
        remote_card_port=remote_card_port,
        local_gui_port=local_gui_port,
        remote_gui_port=remote_gui_port,
        forward_gui=forward_gui,
    )
    log_path = Path(_remote_rig_state_path()).with_suffix(".ssh_tunnel.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            command,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            **_detached_subprocess_kwargs(),
        )
    time.sleep(0.35)
    if process.poll() is not None:
        _write_remote_rig_state({
            "ssh_tunnel_pid": 0,
            "ssh_target": _validate_ssh_target(ssh_target),
            "ssh_tunnel_log": str(log_path),
            "ssh_tunnel_command": _redact_command(command),
        })
        return {
            "ok": False,
            "pid": int(process.pid),
            "returncode": int(process.returncode or 0),
            "log_path": str(log_path),
            "log_tail": _tail_text_file(log_path),
            "note": "SSH tunnel exited during startup.",
        }
    try:
        from yggdrasim_common.gui_server.lifecycle import register_gui_subprocess

        register_gui_subprocess("Remote rig SSH tunnel", process)
    except Exception:  # noqa: BLE001
        pass

    local_gui = _coerce_port(local_gui_port, _DEFAULT_GUI_PORT)
    remote_card = _coerce_port(remote_card_port, _DEFAULT_CARD_PORT)
    _write_remote_rig_state({
        "ssh_tunnel_pid": int(process.pid),
        "ssh_target": _validate_ssh_target(ssh_target),
        "remote_card_port": remote_card,
        "local_gui_port": local_gui,
        "remote_gui_port": _coerce_port(remote_gui_port, _DEFAULT_GUI_PORT),
        "ssh_tunnel_log": str(log_path),
        "ssh_tunnel_command": _redact_command(command),
    })
    return {
        "ok": True,
        "pid": int(process.pid),
        "remote_card_url": f"http://127.0.0.1:{remote_card}/apdu",
        "local_gui_url": f"http://127.0.0.1:{local_gui}" if bool(forward_gui) else "",
        "log_path": str(log_path),
        "note": "SSH tunnel started.",
    }


def _dispatch_tunnel_stop(
    ctx: ActionContext,
    *,
    confirm: Any = None,
) -> dict[str, Any]:
    del ctx
    if bool(confirm) is False:
        raise ValueError("confirm must be true — stopping the tunnel breaks remote HIL card access.")
    state = _load_remote_rig_state()
    result = _terminate_process_group(state.get("ssh_tunnel_pid", 0))
    _clear_local_card_relay_marker()
    _clear_remote_hil_attachment_state()
    _write_remote_rig_state({"ssh_tunnel_pid": 0})
    return {
        **result,
        "note": "SSH tunnel stop requested.",
    }


def _dispatch_sync_token(
    ctx: ActionContext,
    *,
    ssh_target: Any = None,
    identity_file: Any = None,
    local_token_file: Any = None,
    remote_token_file: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    del ctx
    if bool(confirm) is False:
        raise ValueError("confirm must be true — this writes the remote bearer token file.")
    from yggdrasim_common.card_bridge_auth import default_token_file_for_port

    local_path_s = str(local_token_file or "").strip()
    if len(local_path_s) == 0:
        local_path = default_token_file_for_port(_DEFAULT_CARD_PORT)
    else:
        local_path = Path(os.path.expanduser(local_path_s))
    if local_path.is_file() is False:
        raise ValueError(f"local token file not found: {local_path}")
    token = local_path.read_text(encoding="utf-8").strip()
    if len(token) == 0:
        raise ValueError(f"local token file is empty: {local_path}")
    remote_path = str(remote_token_file or _DEFAULT_REMOTE_TOKEN_FILE).strip()
    remote_dir = _remote_shell_path_expr(str(Path(remote_path).parent))
    remote_file = _remote_shell_path_expr(remote_path)
    remote_command = (
        f"mkdir -p {remote_dir} && "
        f"umask 077 && cat > {remote_file} && chmod 600 {remote_file}"
    )
    result = _run_ssh_command(
        ssh_target=ssh_target,
        identity_file=identity_file,
        remote_command=remote_command,
        stdin_text=token + "\n",
        timeout_seconds=20,
    )
    return {
        "ok": bool(result["ok"]),
        "returncode": result["returncode"],
        "stderr": result["stderr"],
        "remote_token_file": remote_path,
        "token_fingerprint": _fingerprint(token),
        "note": "Remote token file synced." if result["ok"] else "Remote token sync failed.",
    }


def _remote_remsim_binary_status(
    *,
    ssh_target: Any,
    identity_file: Any = None,
    remsim_binary: Any = None,
) -> dict[str, Any]:
    binary = str(remsim_binary or _DEFAULT_REMSIM_BINARY).strip()
    if len(binary) == 0:
        binary = _DEFAULT_REMSIM_BINARY
    quoted_binary = shlex.quote(binary)
    remote_command = (
        f"candidate={quoted_binary}; "
        "if [ -x \"$candidate\" ]; then printf '%s\\n' \"$candidate\"; exit 0; fi; "
        "if command -v \"$candidate\" >/dev/null 2>&1; then command -v \"$candidate\"; exit 0; fi; "
        "printf '%s\\n' \"$candidate\"; exit 127"
    )
    result = _run_ssh_command(
        ssh_target=ssh_target,
        identity_file=identity_file,
        remote_command=remote_command,
        timeout_seconds=10,
    )
    resolved = str(result.get("stdout") or "").splitlines()[0].strip() if len(str(result.get("stdout") or "").strip()) > 0 else binary
    ok = bool(result.get("ok"))
    return {
        "ok": ok,
        "returncode": result.get("returncode", 0),
        "stderr": result.get("stderr", ""),
        "remsim_binary": binary,
        "resolved_remsim_binary": resolved if ok else "",
        "note": (
            f"Remote REMSIM binary found: {resolved}."
            if ok
            else (
                "Remote REMSIM binary not found. Install osmo-remsim-client-st2 "
                "on the RPi or set RPi REMSIM binary to an executable path."
            )
        ),
    }


def _dispatch_install_remote_service(
    ctx: ActionContext,
    *,
    ssh_target: Any = None,
    identity_file: Any = None,
    service_name: Any = None,
    remote_workdir: Any = None,
    remote_python: Any = None,
    remote_card_url: Any = None,
    remote_token_file: Any = None,
    remsim_binary: Any = None,
    usb_vidpid: Any = None,
    hil_port: Any = None,
    apdu_timeout_ms: Any = None,
    gsmtap_capture_path: Any = None,
    start_now: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    del ctx
    if bool(confirm) is False:
        raise ValueError("confirm must be true — this writes a remote systemd user service.")
    service = _validate_service_name(service_name)
    capture_path = str(
        gsmtap_capture_path or _remote_gsmtap_capture_path(remote_workdir)
    ).strip()
    remsim_check = _remote_remsim_binary_status(
        ssh_target=ssh_target,
        identity_file=identity_file,
        remsim_binary=remsim_binary,
    )
    if bool(remsim_check.get("ok")) is False:
        return {
            **remsim_check,
            "service_name": service,
            "unit_path": f"~/.config/systemd/user/{service}",
            "remote_gsmtap_capture_path": capture_path,
            "started": False,
        }
    unit_text = _render_remote_hil_unit(
        remote_workdir=remote_workdir,
        remote_python=remote_python,
        service_name=service,
        remote_card_url=remote_card_url,
        remote_token_file=remote_token_file,
        remsim_binary=remsim_check.get("resolved_remsim_binary") or remsim_binary,
        usb_vidpid=usb_vidpid,
        hil_port=hil_port,
        apdu_timeout_ms=apdu_timeout_ms,
        gsmtap_capture_path=capture_path,
    )
    unit_path = f"~/.config/systemd/user/{service}"
    quoted_unit_path = _remote_shell_path_expr(unit_path)
    remote_command = (
        "mkdir -p ~/.config/systemd/user && "
        f"cat > {quoted_unit_path} && "
        "systemctl --user daemon-reload && "
        f"systemctl --user enable {shlex.quote(service)}"
    )
    if bool(start_now):
        remote_command += f" && systemctl --user restart {shlex.quote(service)}"
    result = _run_ssh_command(
        ssh_target=ssh_target,
        identity_file=identity_file,
        remote_command=remote_command,
        stdin_text=unit_text,
        timeout_seconds=25,
    )
    if bool(result["ok"]):
        _write_remote_rig_state({
            "ssh_target": _validate_ssh_target(ssh_target),
            "identity_file": str(identity_file or "").strip(),
            "remote_workdir": str(remote_workdir or _DEFAULT_REMOTE_WORKDIR).strip(),
            "remote_python": str(remote_python or _DEFAULT_REMOTE_PYTHON).strip(),
            "remote_gsmtap_capture_path": capture_path,
        })
    return {
        "ok": bool(result["ok"]),
        "returncode": result["returncode"],
        "stderr": result["stderr"],
        "service_name": service,
        "unit_path": unit_path,
        "remote_gsmtap_capture_path": capture_path,
        "started": bool(start_now) and bool(result["ok"]),
        "note": (
            "Remote HIL service installed."
            if result["ok"] and not bool(start_now)
            else "Remote HIL service installed and restarted."
            if result["ok"]
            else "Remote HIL service install failed."
        ),
    }


def _dispatch_remote_service_control(
    ctx: ActionContext,
    *,
    ssh_target: Any = None,
    identity_file: Any = None,
    service_name: Any = None,
    action: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    del ctx
    action_s = str(action or "status").strip().lower()
    allowed = {"start", "stop", "restart", "status"}
    if action_s not in allowed:
        raise ValueError("action must be one of: " + ", ".join(sorted(allowed)))
    if action_s in {"start", "stop", "restart"} and bool(confirm) is False:
        raise ValueError("confirm must be true for start / stop / restart.")
    service = _validate_service_name(service_name)
    if action_s == "status":
        remote_command = (
            "systemctl --user show "
            f"{shlex.quote(service)} "
            "--property=LoadState,ActiveState,SubState,UnitFileState,FragmentPath --no-pager"
        )
    else:
        remote_command = f"systemctl --user {action_s} {shlex.quote(service)}"
    result = _run_ssh_command(
        ssh_target=ssh_target,
        identity_file=identity_file,
        remote_command=remote_command,
        timeout_seconds=20,
    )
    if action_s == "stop" and bool(result["ok"]):
        _clear_local_card_relay_marker()
        _clear_remote_hil_attachment_state()
    parsed = _parse_systemctl_show(result["stdout"]) if action_s == "status" else {}
    return {
        "ok": bool(result["ok"]),
        "action": action_s,
        "service_name": service,
        "returncode": result["returncode"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "state": parsed,
        "note": (
            f"Remote service {action_s} completed."
            if result["ok"]
            else f"Remote service {action_s} failed."
        ),
    }


def _truthy_status_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y", "on", "active", "running", "ok"}


def _remote_hil_note(
    *,
    usb_present: bool,
    bridge_running: bool,
    remsim_enabled: bool,
    remsim_running: bool,
    control_connected: bool,
    bankd_connected: bool,
    reason: str,
    bridge_status_error: str,
) -> str:
    reason_text = str(reason or "").strip()
    if usb_present is False:
        return reason_text or "SIMtrace2 USB is not detected on the RPi."
    if bridge_running is False:
        return reason_text or "Remote HIL bridge child is not running."
    if remsim_enabled and remsim_running is False:
        return reason_text or "Remote REMSIM client is not running."
    if len(str(bridge_status_error or "").strip()) > 0:
        return "Remote HIL bridge status endpoint is not reachable."
    if control_connected is False:
        return "Remote REMSIM control connection is not attached."
    if bankd_connected is False:
        return "Remote REMSIM bankd connection is not attached; modem APDUs will not reach the card."
    return "Remote HIL modem path is connected."


def _remote_hil_runtime_status(
    *,
    ssh_target: Any,
    identity_file: Any = None,
    remote_workdir: Any = None,
    remote_python: Any = None,
) -> dict[str, Any]:
    target = _validate_ssh_target(ssh_target)
    workdir = str(remote_workdir or _DEFAULT_REMOTE_WORKDIR).strip()
    python_executable = str(remote_python or _DEFAULT_REMOTE_PYTHON).strip()
    remote_script = """
import json

payload = {"supervisor": {}, "relay": {}, "bridge_status": {}}
try:
    from yggdrasim_common.hil_bridge_runtime import (
        read_bridge_status,
        read_card_relay_state,
        read_supervisor_state,
    )
    payload["supervisor"] = read_supervisor_state()
    payload["relay"] = read_card_relay_state()
    try:
        payload["bridge_status"] = read_bridge_status()
    except Exception as exc:
        payload["bridge_status_error"] = f"{exc.__class__.__name__}: {exc}"
except Exception as exc:
    payload["error"] = f"{exc.__class__.__name__}: {exc}"
print(json.dumps(payload, sort_keys=True))
""".strip()
    remote_command = (
        f"cd {_remote_shell_path_expr(workdir)} && "
        f"{_remote_shell_path_expr(python_executable)} - <<'PY'\n"
        f"{remote_script}\n"
        "PY"
    )
    result = _run_ssh_command(
        ssh_target=target,
        identity_file=identity_file,
        remote_command=remote_command,
        timeout_seconds=12,
    )
    if bool(result.get("ok")) is False:
        return {
            "ok": False,
            "returncode": result.get("returncode", 0),
            "stderr": result.get("stderr", ""),
            "note": "Remote HIL runtime status check failed.",
        }

    payload: dict[str, Any] = {}
    parse_error = ""
    try:
        decoded = json.loads(str(result.get("stdout") or "{}"))
        if isinstance(decoded, dict):
            payload = decoded
    except json.JSONDecodeError as error:
        parse_error = f"JSONDecodeError: {error}"

    supervisor = dict(payload.get("supervisor") or {})
    relay = dict(payload.get("relay") or {})
    bridge_status = dict(payload.get("bridge_status") or {})
    if len(bridge_status) == 0:
        bridge_status = dict(relay)

    usb_present = _truthy_status_value(supervisor.get("usbPresent", False))
    bridge_running = _truthy_status_value(supervisor.get("bridgeRunning", False))
    remsim_enabled = _truthy_status_value(supervisor.get("remsimClientEnabled", True))
    remsim_running = _truthy_status_value(supervisor.get("remsimClientRunning", False))
    control_connected = _truthy_status_value(bridge_status.get("controlConnected", False))
    bankd_connected = _truthy_status_value(bridge_status.get("bankdConnected", False))
    bridge_status_error = str(payload.get("bridge_status_error") or "").strip()
    import_error = str(payload.get("error") or "").strip()
    reason = str(supervisor.get("reason") or "").strip()
    remsim_command = supervisor.get("remsimClientCommand", [])
    remsim_binary = ""
    if isinstance(remsim_command, list) and len(remsim_command) > 0:
        remsim_binary = str(remsim_command[0] or "").strip()
    remsim_binary_missing = (
        remsim_running is False
        and "no such file or directory" in reason.lower()
        and len(remsim_binary) > 0
    )
    modem_path_ready = (
        len(parse_error) == 0
        and len(import_error) == 0
        and usb_present
        and bridge_running
        and (remsim_enabled is False or remsim_running)
        and control_connected
        and bankd_connected
    )
    note = _remote_hil_note(
        usb_present=usb_present,
        bridge_running=bridge_running,
        remsim_enabled=remsim_enabled,
        remsim_running=remsim_running,
        control_connected=control_connected,
        bankd_connected=bankd_connected,
        reason=reason,
        bridge_status_error=bridge_status_error,
    )
    if len(import_error) > 0:
        note = f"Remote HIL runtime import failed: {import_error}"
    if len(parse_error) > 0:
        note = f"Remote HIL runtime status returned invalid JSON: {parse_error}"
    return {
        "ok": len(parse_error) == 0 and len(import_error) == 0,
        "returncode": result.get("returncode", 0),
        "stderr": result.get("stderr", ""),
        "parse_error": parse_error,
        "supervisor_status": str(supervisor.get("status") or ""),
        "reason": reason,
        "usb_present": usb_present,
        "bridge_running": bridge_running,
        "remsim_client_enabled": remsim_enabled,
        "remsim_client_running": remsim_running,
        "remsim_binary": remsim_binary,
        "remsim_binary_missing": remsim_binary_missing,
        "control_connected": control_connected,
        "bankd_connected": bankd_connected,
        "modem_path_ready": modem_path_ready,
        "bridge_status_error": bridge_status_error,
        "bridge_status": bridge_status,
        "supervisor": supervisor,
        "relay": relay,
        "note": note,
    }


def _wait_for_remote_hil_ready(
    *,
    ssh_target: Any,
    identity_file: Any = None,
    remote_workdir: Any = None,
    remote_python: Any = None,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(0.5, float(timeout_seconds))
    last_payload: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_payload = _remote_hil_runtime_status(
            ssh_target=ssh_target,
            identity_file=identity_file,
            remote_workdir=remote_workdir,
            remote_python=remote_python,
        )
        if bool(last_payload.get("modem_path_ready")):
            return {**last_payload, "ok": True}
        time.sleep(0.75)
    if len(last_payload) == 0:
        last_payload = {
            "note": "Remote HIL modem path did not report status before timeout."
        }
    return {**last_payload, "ok": False}


def _compact_remote_rig_step(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    step: dict[str, Any] = {
        "name": name,
        "ok": bool(payload.get("ok")),
        "note": str(
            payload.get("note")
            or payload.get("error")
            or payload.get("stderr")
            or ""
        ),
    }
    for key in (
        "pid",
        "port",
        "status",
        "returncode",
        "reader",
        "atr",
        "card",
        "token_file",
        "token_fingerprint",
        "remote_card_url",
        "local_gui_url",
        "log_path",
        "log_tail",
        "stderr",
        "parse_error",
        "supervisor_status",
        "reason",
        "usb_present",
        "bridge_running",
        "remsim_client_enabled",
        "remsim_client_running",
        "control_connected",
        "bankd_connected",
        "modem_path_ready",
        "bridge_status_error",
        "remsim_binary",
        "resolved_remsim_binary",
    ):
        value = payload.get(key)
        if value not in (None, ""):
            step[key] = value
    return step


def _remote_rig_finish(
    *,
    ok: bool,
    steps: list[dict[str, Any]],
    note: str,
    ssh_target: Any,
    identity_file: Any,
    service_name: Any,
    local_gui_port: Any,
    remote_workdir: Any = None,
    remote_python: Any = None,
) -> dict[str, Any]:
    status = _dispatch_remote_rig_status(
        ActionContext(),
        ssh_target=ssh_target,
        identity_file=identity_file,
        service_name=service_name,
        local_gui_port=local_gui_port,
        remote_workdir=remote_workdir,
        remote_python=remote_python,
    )
    return {
        "ok": bool(ok),
        "steps": steps,
        "lines": status.get("lines", []),
        "state": status.get("state", {}),
        "note": note,
    }


def _dispatch_remote_rig_start(
    ctx: ActionContext,
    *,
    ssh_target: Any = None,
    identity_file: Any = None,
    reader_index: Any = None,
    reader_name: Any = None,
    local_card_port: Any = None,
    remote_card_port: Any = None,
    local_gui_port: Any = None,
    remote_gui_port: Any = None,
    service_name: Any = None,
    remote_workdir: Any = None,
    remote_python: Any = None,
    remote_card_url: Any = None,
    remote_token_file: Any = None,
    remsim_binary: Any = None,
    usb_vidpid: Any = None,
    hil_port: Any = None,
    apdu_timeout_ms: Any = None,
    gsmtap_capture_path: Any = None,
    forward_gui: Any = False,
    restart_processes: Any = True,
    install_service: Any = True,
    confirm: Any = None,
) -> dict[str, Any]:
    if bool(confirm) is False:
        raise ValueError("confirm must be true — starting the remote rig opens local and SSH services.")

    local_card = _coerce_port(local_card_port, _DEFAULT_CARD_PORT)
    remote_card = _coerce_port(remote_card_port, local_card)
    local_gui = _coerce_port(local_gui_port, _DEFAULT_GUI_PORT)
    remote_gui = _coerce_port(remote_gui_port, _DEFAULT_GUI_PORT)
    target = _validate_ssh_target(ssh_target)
    service = _validate_service_name(service_name)
    workdir = str(remote_workdir or _DEFAULT_REMOTE_WORKDIR).strip()
    python_executable = str(remote_python or _DEFAULT_REMOTE_PYTHON).strip()
    token_file = str(remote_token_file or _DEFAULT_REMOTE_TOKEN_FILE).strip()
    remsim_binary_s = str(remsim_binary or _DEFAULT_REMSIM_BINARY).strip()
    card_url = str(remote_card_url or f"http://127.0.0.1:{remote_card}/apdu").strip()
    timeout_i = _coerce_positive_int(apdu_timeout_ms, _DEFAULT_APDU_TIMEOUT_MS)
    capture_path = str(
        gsmtap_capture_path or _remote_gsmtap_capture_path(workdir)
    ).strip()
    steps: list[dict[str, Any]] = []

    start_local = _dispatch_local_start(
        ctx,
        port=local_card,
        reader_index=reader_index,
        reader_name=reader_name,
        apdu_timeout_ms=timeout_i,
        restart=restart_processes,
        reuse_existing=True,
        confirm=True,
    )
    steps.append(_compact_remote_rig_step("pc_bridge_start", start_local))

    local_check = _wait_for_local_card_bridge(port=local_card, timeout_seconds=6.0)
    steps.append(_compact_remote_rig_step("pc_bridge_verify", local_check))
    if bool(local_check.get("ok")) is False:
        return _remote_rig_finish(
            ok=False,
            steps=steps,
            note="Remote rig start stopped: PC Card Bridge is not usable.",
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            local_gui_port=local_gui,
            remote_workdir=workdir,
            remote_python=python_executable,
        )
    local_reset = _reset_local_card_bridge(
        port=local_card,
        token_file=local_check.get("token_file"),
        timeout_seconds=6.0,
    )
    steps.append(_compact_remote_rig_step("pc_bridge_reset", local_reset))
    if bool(local_reset.get("ok")) is False:
        return _remote_rig_finish(
            ok=False,
            steps=steps,
            note="Remote rig start stopped: PC Card Bridge reset failed.",
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            local_gui_port=local_gui,
            remote_workdir=workdir,
            remote_python=python_executable,
        )
    local_check = {
        **local_check,
        "reader": local_reset.get("reader") or local_check.get("reader", ""),
        "atr": local_reset.get("atr") or local_check.get("atr", ""),
        "token_file": local_reset.get("token_file") or local_check.get("token_file", ""),
        "token_fingerprint": (
            local_reset.get("token_fingerprint")
            or local_check.get("token_fingerprint", "")
        ),
    }
    _publish_local_card_relay_marker(
        port=local_card,
        token_file=local_check.get("token_file", ""),
        reader=local_check.get("reader", ""),
        atr=local_check.get("atr", ""),
    )

    tunnel = _dispatch_tunnel_start(
        ctx,
        ssh_target=target,
        identity_file=identity_file,
        local_card_port=local_card,
        remote_card_port=remote_card,
        local_gui_port=local_gui,
        remote_gui_port=remote_gui,
        forward_gui=forward_gui,
        restart=restart_processes,
        confirm=True,
    )
    steps.append(_compact_remote_rig_step("ssh_tunnel_start", tunnel))

    remote_ping = _remote_card_ping(
        ssh_target=target,
        identity_file=identity_file,
        remote_card_port=remote_card,
    )
    steps.append(_compact_remote_rig_step("rpi_bridge_ping", remote_ping))
    if bool(remote_ping.get("ok")) is False:
        return _remote_rig_finish(
            ok=False,
            steps=steps,
            note="Remote rig start stopped: RPi cannot reach the PC Card Bridge.",
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            local_gui_port=local_gui,
            remote_workdir=workdir,
            remote_python=python_executable,
        )

    sync = _dispatch_sync_token(
        ctx,
        ssh_target=target,
        identity_file=identity_file,
        local_token_file=local_check.get("token_file"),
        remote_token_file=token_file,
        confirm=True,
    )
    steps.append(_compact_remote_rig_step("token_sync", sync))
    if bool(sync.get("ok")) is False:
        return _remote_rig_finish(
            ok=False,
            steps=steps,
            note="Remote rig start stopped: token sync failed.",
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            local_gui_port=local_gui,
            remote_workdir=workdir,
            remote_python=python_executable,
        )

    remote_status = _remote_card_status(
        ssh_target=target,
        identity_file=identity_file,
        remote_card_port=remote_card,
        remote_token_file=token_file,
    )
    steps.append(_compact_remote_rig_step("rpi_bridge_status", remote_status))
    if bool(remote_status.get("ok")) is False:
        return _remote_rig_finish(
            ok=False,
            steps=steps,
            note="Remote rig start stopped: RPi could not authenticate to the PC Card Bridge.",
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            local_gui_port=local_gui,
            remote_workdir=workdir,
            remote_python=python_executable,
        )

    remsim_check = _remote_remsim_binary_status(
        ssh_target=target,
        identity_file=identity_file,
        remsim_binary=remsim_binary_s,
    )
    steps.append(_compact_remote_rig_step("rpi_remsim_binary", remsim_check))
    if bool(remsim_check.get("ok")) is False:
        return _remote_rig_finish(
            ok=False,
            steps=steps,
            note="Remote rig start stopped: RPi REMSIM client is not installed or not executable.",
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            local_gui_port=local_gui,
            remote_workdir=workdir,
            remote_python=python_executable,
        )
    resolved_remsim_binary = str(remsim_check.get("resolved_remsim_binary") or remsim_binary_s)

    if bool(install_service):
        service_result = _dispatch_install_remote_service(
            ctx,
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            remote_workdir=workdir,
            remote_python=python_executable,
            remote_card_url=card_url,
            remote_token_file=token_file,
            remsim_binary=resolved_remsim_binary,
            usb_vidpid=usb_vidpid,
            hil_port=hil_port,
            apdu_timeout_ms=timeout_i,
            gsmtap_capture_path=capture_path,
            start_now=True,
            confirm=True,
        )
    else:
        service_result = _dispatch_remote_service_control(
            ctx,
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            action="restart",
            confirm=True,
        )
    steps.append(_compact_remote_rig_step("rpi_hil_service", service_result))
    if bool(service_result.get("ok")) is False:
        return _remote_rig_finish(
            ok=False,
            steps=steps,
            note="Remote rig start stopped: RPi HIL service failed.",
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            local_gui_port=local_gui,
            remote_workdir=workdir,
            remote_python=python_executable,
        )
    _write_remote_rig_state({
        "ssh_target": target,
        "identity_file": str(identity_file or "").strip(),
        "remote_workdir": workdir,
        "remote_python": python_executable,
        "remote_gsmtap_capture_path": str(
            service_result.get("remote_gsmtap_capture_path") or capture_path
        ),
    })

    hil_ready = _wait_for_remote_hil_ready(
        ssh_target=target,
        identity_file=identity_file,
        remote_workdir=workdir,
        remote_python=python_executable,
        timeout_seconds=14.0,
    )
    steps.append(_compact_remote_rig_step("rpi_hil_ready", hil_ready))
    if bool(hil_ready.get("ok")) is False:
        return _remote_rig_finish(
            ok=False,
            steps=steps,
            note="Remote rig start stopped: RPi HIL path is not ready for modem APDUs.",
            ssh_target=target,
            identity_file=identity_file,
            service_name=service,
            local_gui_port=local_gui,
            remote_workdir=workdir,
            remote_python=python_executable,
        )

    return _remote_rig_finish(
        ok=True,
        steps=steps,
        note="Remote HIL rig is ready: PC card bridge, tunnel, token, and RPi HIL service are active.",
        ssh_target=target,
        identity_file=identity_file,
        service_name=service,
        local_gui_port=local_gui,
        remote_workdir=workdir,
        remote_python=python_executable,
    )


def _normalize_full_stop_step(payload: dict[str, Any], *, missing_note: str) -> dict[str, Any]:
    status = str(payload.get("status") or "").strip()
    if status == "missing-pid":
        return {
            **payload,
            "ok": True,
            "note": missing_note,
        }
    return payload


def _dispatch_remote_rig_stop(
    ctx: ActionContext,
    *,
    ssh_target: Any = None,
    identity_file: Any = None,
    service_name: Any = None,
    local_gui_port: Any = None,
    remote_workdir: Any = None,
    remote_python: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    if bool(confirm) is False:
        raise ValueError("confirm must be true — stopping the remote rig tears down local and SSH services.")

    state = _load_remote_rig_state()
    target = str(ssh_target or state.get("ssh_target") or "").strip()
    identity = str(identity_file or state.get("identity_file") or "").strip()
    service = _validate_service_name(service_name)
    local_gui = _coerce_port(
        local_gui_port,
        int(state.get("local_gui_port", _DEFAULT_GUI_PORT) or _DEFAULT_GUI_PORT),
    )
    workdir = str(remote_workdir or state.get("remote_workdir") or _DEFAULT_REMOTE_WORKDIR).strip()
    python_executable = str(remote_python or state.get("remote_python") or _DEFAULT_REMOTE_PYTHON).strip()
    steps: list[dict[str, Any]] = []

    if len(target) > 0:
        remote_stop = _dispatch_remote_service_control(
            ctx,
            ssh_target=target,
            identity_file=identity,
            service_name=service,
            action="stop",
            confirm=True,
        )
    else:
        remote_stop = {
            "ok": True,
            "status": "skipped",
            "note": "Remote service stop skipped because no SSH target is configured.",
        }
    steps.append(_compact_remote_rig_step("rpi_hil_service_stop", remote_stop))

    tunnel_stop = _normalize_full_stop_step(
        _dispatch_tunnel_stop(ctx, confirm=True),
        missing_note="No GUI-owned SSH tunnel process was registered.",
    )
    steps.append(_compact_remote_rig_step("ssh_tunnel_stop", tunnel_stop))

    local_stop = _normalize_full_stop_step(
        _dispatch_local_stop(ctx, confirm=True),
        missing_note="No GUI-owned PC Card Bridge process was registered.",
    )
    steps.append(_compact_remote_rig_step("pc_bridge_stop", local_stop))

    _clear_local_card_relay_marker()
    _clear_remote_hil_attachment_state()

    ok = all(bool(step.get("ok")) for step in steps)
    status = _dispatch_remote_rig_status(
        ActionContext(),
        ssh_target="",
        identity_file=identity,
        service_name=service,
        local_gui_port=local_gui,
        remote_workdir=workdir,
        remote_python=python_executable,
    )
    return {
        "ok": ok,
        "steps": steps,
        "lines": status.get("lines", []),
        "state": status.get("state", {}),
        "note": (
            "Remote HIL rig stop requested."
            if ok
            else "Remote HIL rig stop completed with errors; check the step list."
        ),
    }


def _dispatch_remote_rig_status(
    ctx: ActionContext,
    *,
    ssh_target: Any = None,
    identity_file: Any = None,
    service_name: Any = None,
    local_gui_port: Any = None,
    remote_workdir: Any = None,
    remote_python: Any = None,
) -> dict[str, Any]:
    del ctx
    state = _load_remote_rig_state()
    local_pid = int(state.get("local_card_bridge_pid", 0) or 0)
    tunnel_pid = int(state.get("ssh_tunnel_pid", 0) or 0)
    local_card = _coerce_port(state.get("local_card_bridge_port", _DEFAULT_CARD_PORT), _DEFAULT_CARD_PORT)
    local_gui = _coerce_port(local_gui_port, int(state.get("local_gui_port", _DEFAULT_GUI_PORT) or _DEFAULT_GUI_PORT))
    service = _validate_service_name(service_name)
    local_pid_running = _pid_is_running(local_pid)
    local_bridge_external = bool(state.get("local_card_bridge_external"))
    local_bridge_reachable = False
    if local_pid_running is False:
        if local_pid > 0:
            local_pid = 0
            _write_remote_rig_state({"local_card_bridge_pid": 0})
        ping_status, _payload, _latency, _error = _http_get_json(
            f"http://127.0.0.1:{local_card}",
            "/ping",
            token="",
            timeout_seconds=0.25,
        )
        local_bridge_reachable = ping_status == 200
        if local_bridge_reachable:
            local_bridge_external = True
            discovered_pid = _find_local_card_bridge_listener_pid(local_card)
            if discovered_pid > 0:
                local_pid = discovered_pid
                local_pid_running = True
                _write_remote_rig_state({
                    "local_card_bridge_pid": discovered_pid,
                    "local_card_bridge_external": True,
                })
    local_bridge_running = local_pid_running or local_bridge_reachable
    remote_state: dict[str, Any] = {}
    remote_error = ""
    remote_hil: dict[str, Any] = {}
    if len(str(ssh_target or "").strip()) > 0:
        result = _dispatch_remote_service_control(
            ActionContext(),
            ssh_target=ssh_target,
            identity_file=identity_file,
            service_name=service,
            action="status",
        )
        remote_state = dict(result.get("state") or {})
        if result.get("ok") is not True:
            remote_error = str(result.get("stderr") or result.get("stdout") or "")
        runtime_status = _remote_hil_runtime_status(
            ssh_target=ssh_target,
            identity_file=identity_file,
            remote_workdir=remote_workdir,
            remote_python=remote_python,
        )
        remote_hil = dict(runtime_status)
        if runtime_status.get("ok") is not True and len(remote_error) == 0:
            remote_error = str(runtime_status.get("note") or "")
    lines = [
        {"key": "PC CardBridge", "value": "running" if local_bridge_running else "stopped"},
        {"key": "PC CardBridge pid", "value": str(local_pid or "-")},
        {"key": "SSH tunnel", "value": "running" if _pid_is_running(tunnel_pid) else "stopped"},
        {"key": "SSH tunnel pid", "value": str(tunnel_pid or "-")},
        {"key": "RPi GUI URL", "value": f"http://127.0.0.1:{local_gui}"},
    ]
    if remote_state:
        lines.append({"key": "Remote service", "value": remote_state.get("ActiveState", "-")})
        lines.append({"key": "Remote substate", "value": remote_state.get("SubState", "-")})
    if remote_hil:
        lines.append({"key": "RPi bridge", "value": "running" if remote_hil.get("bridge_running") else "stopped"})
        remsim_value = "running" if remote_hil.get("remsim_client_running") else "stopped"
        if remote_hil.get("remsim_binary_missing"):
            remsim_value = "missing"
        lines.append({"key": "RPi REMSIM", "value": remsim_value})
        lines.append({"key": "RPi modem link", "value": "connected" if remote_hil.get("modem_path_ready") else "waiting"})
    if len(remote_error) > 0:
        lines.append({"key": "Remote error", "value": remote_error})
    return {
        "ok": True,
        "lines": lines,
        "state": {
            **state,
            "local_card_bridge_pid": local_pid,
            "local_card_bridge_external": local_bridge_external,
            "local_card_bridge_running": local_bridge_running,
            "local_card_bridge_reachable": local_bridge_reachable,
            "ssh_tunnel_running": _pid_is_running(tunnel_pid),
            "local_gui_url": f"http://127.0.0.1:{local_gui}",
            "remote_service": remote_state,
            "remote_hil": remote_hil,
            "remote_error": remote_error,
        },
        "note": str(remote_hil.get("note") or "Remote rig status snapshot."),
    }


LOCAL_START_SPEC = ActionSpec(
    id="card_bridge.local_start",
    subsystem="Card Bridge",
    title="Start local bridge",
    description="Start a PC-side Card Bridge subprocess for the selected local PC/SC reader.",
    inputs=(
        ActionField(name="port", label="Port", kind="int", required=False, default=_DEFAULT_CARD_PORT, min_value=1),
        ActionField(name="reader_index", label="Reader index", kind="int", required=False, default=0, min_value=0),
        ActionField(name="reader_name", label="Reader name", kind="string", required=False),
        ActionField(name="token_file", label="Token file", kind="path", required=False),
        ActionField(name="apdu_timeout_ms", label="APDU timeout (ms)", kind="int", required=False, default=_DEFAULT_APDU_TIMEOUT_MS, min_value=1),
        ActionField(name="restart", label="Restart if running", kind="bool", required=False, default=False),
        ActionField(name="reuse_existing", label="Reuse reachable bridge", kind="bool", required=False, default=False),
        ActionField(name="confirm", label="Start Card Bridge", kind="bool", required=True, default=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_local_start,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "process"),
)


LOCAL_STOP_SPEC = ActionSpec(
    id="card_bridge.local_stop",
    subsystem="Card Bridge",
    title="Stop local bridge",
    description="Stop the PC-side Card Bridge subprocess started from the GUI.",
    inputs=(ActionField(name="confirm", label="Stop Card Bridge", kind="bool", required=True, default=False),),
    output_kind="json",
    dispatcher=_dispatch_local_stop,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "process"),
)


REMOTE_RIG_START_SPEC = ActionSpec(
    id="card_bridge.remote_rig_start",
    subsystem="Card Bridge",
    title="Start remote HIL rig",
    description=(
        "Start or verify the PC Card Bridge, open the SSH reverse tunnel, "
        "sync the bearer token, verify the RPi can authenticate to the PC "
        "card, and install/restart the RPi HIL supervisor service."
    ),
    inputs=(
        ActionField(name="ssh_target", label="SSH target", kind="string", required=True, placeholder="pi@rpi-host"),
        ActionField(name="identity_file", label="Identity file", kind="path", required=False),
        ActionField(name="reader_index", label="Reader index", kind="int", required=False, default=0, min_value=0),
        ActionField(name="reader_name", label="Reader name", kind="string", required=False),
        ActionField(name="local_card_port", label="Local card port", kind="int", required=False, default=_DEFAULT_CARD_PORT, min_value=1),
        ActionField(name="remote_card_port", label="Remote card port", kind="int", required=False, default=_DEFAULT_CARD_PORT, min_value=1),
        ActionField(name="local_gui_port", label="Local GUI port", kind="int", required=False, default=_DEFAULT_GUI_PORT, min_value=1),
        ActionField(name="remote_gui_port", label="Remote GUI port", kind="int", required=False, default=_DEFAULT_GUI_PORT, min_value=1),
        ActionField(name="service_name", label="Service", kind="string", required=False, default=_DEFAULT_REMOTE_SERVICE_NAME),
        ActionField(name="remote_workdir", label="Remote repo directory", kind="string", required=False, default=_DEFAULT_REMOTE_WORKDIR),
        ActionField(name="remote_python", label="Remote Python", kind="string", required=False, default=_DEFAULT_REMOTE_PYTHON),
        ActionField(name="remote_card_url", label="Remote card URL", kind="string", required=False, default=_DEFAULT_REMOTE_CARD_URL),
        ActionField(name="remote_token_file", label="Remote token file", kind="string", required=False, default=_DEFAULT_REMOTE_TOKEN_FILE),
        ActionField(name="remsim_binary", label="RPi REMSIM binary", kind="string", required=False, default=_DEFAULT_REMSIM_BINARY),
        ActionField(name="usb_vidpid", label="SIMtrace2 VID:PID", kind="string", required=False, default=_DEFAULT_USB_VIDPID),
        ActionField(name="hil_port", label="HIL port", kind="int", required=False, default=_DEFAULT_HIL_PORT, min_value=1),
        ActionField(name="apdu_timeout_ms", label="APDU timeout (ms)", kind="int", required=False, default=_DEFAULT_APDU_TIMEOUT_MS, min_value=1),
        ActionField(name="gsmtap_capture_path", label="RPi GSMTAP capture path", kind="string", required=False),
        ActionField(name="forward_gui", label="Also forward RPi GUI", kind="bool", required=False, default=False),
        ActionField(name="restart_processes", label="Restart owned processes", kind="bool", required=False, default=True),
        ActionField(name="install_service", label="Install service", kind="bool", required=False, default=True),
        ActionField(name="confirm", label="Start remote rig", kind="bool", required=True, default=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_remote_rig_start,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "orchestration"),
)


REMOTE_RIG_STOP_SPEC = ActionSpec(
    id="card_bridge.remote_rig_stop",
    subsystem="Card Bridge",
    title="Stop remote HIL rig",
    description=(
        "Stop the RPi HIL service when an SSH target is known, close the "
        "GUI-owned SSH tunnel and PC Card Bridge process, and clear stale "
        "remote-card runtime state."
    ),
    inputs=(
        ActionField(name="ssh_target", label="SSH target", kind="string", required=False, placeholder="pi@rpi-host"),
        ActionField(name="identity_file", label="Identity file", kind="path", required=False),
        ActionField(name="service_name", label="Service", kind="string", required=False, default=_DEFAULT_REMOTE_SERVICE_NAME),
        ActionField(name="local_gui_port", label="Local GUI port", kind="int", required=False, default=_DEFAULT_GUI_PORT, min_value=1),
        ActionField(name="remote_workdir", label="Remote repo directory", kind="string", required=False, default=_DEFAULT_REMOTE_WORKDIR),
        ActionField(name="remote_python", label="Remote Python", kind="string", required=False, default=_DEFAULT_REMOTE_PYTHON),
        ActionField(name="confirm", label="Stop full rig", kind="bool", required=True, default=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_remote_rig_stop,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "orchestration"),
)


TUNNEL_START_SPEC = ActionSpec(
    id="card_bridge.remote_rig_tunnel_start",
    subsystem="Card Bridge",
    title="Start RPi tunnel",
    description="Open SSH forwards for PC CardBridge to the RPi and RPi GUI back to the PC.",
    inputs=(
        ActionField(name="ssh_target", label="SSH target", kind="string", required=True, placeholder="pi@rpi-host"),
        ActionField(name="identity_file", label="Identity file", kind="path", required=False),
        ActionField(name="local_card_port", label="Local card port", kind="int", required=False, default=_DEFAULT_CARD_PORT, min_value=1),
        ActionField(name="remote_card_port", label="Remote card port", kind="int", required=False, default=_DEFAULT_CARD_PORT, min_value=1),
        ActionField(name="local_gui_port", label="Local GUI port", kind="int", required=False, default=_DEFAULT_GUI_PORT, min_value=1),
        ActionField(name="remote_gui_port", label="Remote GUI port", kind="int", required=False, default=_DEFAULT_GUI_PORT, min_value=1),
        ActionField(name="forward_gui", label="Forward RPi GUI", kind="bool", required=False, default=True),
        ActionField(name="restart", label="Restart if running", kind="bool", required=False, default=False),
        ActionField(name="confirm", label="Open SSH tunnel", kind="bool", required=True, default=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_tunnel_start,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "ssh"),
)


TUNNEL_STOP_SPEC = ActionSpec(
    id="card_bridge.remote_rig_tunnel_stop",
    subsystem="Card Bridge",
    title="Stop RPi tunnel",
    description="Stop the SSH tunnel subprocess started from the GUI.",
    inputs=(ActionField(name="confirm", label="Stop SSH tunnel", kind="bool", required=True, default=False),),
    output_kind="json",
    dispatcher=_dispatch_tunnel_stop,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "ssh"),
)


SYNC_TOKEN_SPEC = ActionSpec(
    id="card_bridge.remote_rig_sync_token",
    subsystem="Card Bridge",
    title="Sync token to RPi",
    description="Copy the local Card Bridge bearer token file to the RPi over SSH with mode 0600.",
    inputs=(
        ActionField(name="ssh_target", label="SSH target", kind="string", required=True, placeholder="pi@rpi-host"),
        ActionField(name="identity_file", label="Identity file", kind="path", required=False),
        ActionField(name="local_token_file", label="Local token file", kind="path", required=False),
        ActionField(name="remote_token_file", label="Remote token file", kind="string", required=False, default=_DEFAULT_REMOTE_TOKEN_FILE),
        ActionField(name="confirm", label="Write remote token file", kind="bool", required=True, default=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_sync_token,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "ssh", "token"),
)


INSTALL_REMOTE_SERVICE_SPEC = ActionSpec(
    id="card_bridge.remote_rig_install_service",
    subsystem="Card Bridge",
    title="Install RPi HIL service",
    description="Write or update the RPi systemd user service that runs the HIL supervisor against the tunneled PC card.",
    inputs=(
        ActionField(name="ssh_target", label="SSH target", kind="string", required=True, placeholder="pi@rpi-host"),
        ActionField(name="identity_file", label="Identity file", kind="path", required=False),
        ActionField(name="service_name", label="Service", kind="string", required=False, default=_DEFAULT_REMOTE_SERVICE_NAME),
        ActionField(name="remote_workdir", label="Remote repo directory", kind="string", required=True, default=_DEFAULT_REMOTE_WORKDIR, placeholder="~/YggdraSIM"),
        ActionField(name="remote_python", label="Remote Python", kind="string", required=False, default=_DEFAULT_REMOTE_PYTHON),
        ActionField(name="remote_card_url", label="Remote card URL", kind="string", required=False, default=_DEFAULT_REMOTE_CARD_URL),
        ActionField(name="remote_token_file", label="Remote token file", kind="string", required=False, default=_DEFAULT_REMOTE_TOKEN_FILE),
        ActionField(name="remsim_binary", label="RPi REMSIM binary", kind="string", required=False, default=_DEFAULT_REMSIM_BINARY),
        ActionField(name="usb_vidpid", label="SIMtrace2 VID:PID", kind="string", required=False, default=_DEFAULT_USB_VIDPID),
        ActionField(name="hil_port", label="HIL port", kind="int", required=False, default=_DEFAULT_HIL_PORT, min_value=1),
        ActionField(name="apdu_timeout_ms", label="APDU timeout (ms)", kind="int", required=False, default=_DEFAULT_APDU_TIMEOUT_MS, min_value=1),
        ActionField(name="gsmtap_capture_path", label="RPi GSMTAP capture path", kind="string", required=False),
        ActionField(name="start_now", label="Restart after install", kind="bool", required=False, default=True),
        ActionField(name="confirm", label="Install remote service", kind="bool", required=True, default=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_install_remote_service,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "ssh", "systemd"),
)


REMOTE_SERVICE_CONTROL_SPEC = ActionSpec(
    id="card_bridge.remote_rig_service",
    subsystem="Card Bridge",
    title="Control RPi HIL service",
    description="Start, stop, restart, or query the remote RPi HIL service through SSH.",
    inputs=(
        ActionField(name="ssh_target", label="SSH target", kind="string", required=True, placeholder="pi@rpi-host"),
        ActionField(name="identity_file", label="Identity file", kind="path", required=False),
        ActionField(name="service_name", label="Service", kind="string", required=False, default=_DEFAULT_REMOTE_SERVICE_NAME),
        ActionField(name="action", label="Action", kind="enum", required=True, choices=["status", "start", "restart", "stop"], default="status"),
        ActionField(name="confirm", label="Run service action", kind="bool", required=False, default=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_remote_service_control,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "ssh", "systemd"),
)


REMOTE_RIG_STATUS_SPEC = ActionSpec(
    id="card_bridge.remote_rig_status",
    subsystem="Card Bridge",
    title="Remote rig status",
    description="Show local CardBridge/tunnel state and, when an SSH target is supplied, the RPi service state.",
    inputs=(
        ActionField(name="ssh_target", label="SSH target", kind="string", required=False, placeholder="pi@rpi-host"),
        ActionField(name="identity_file", label="Identity file", kind="path", required=False),
        ActionField(name="service_name", label="Service", kind="string", required=False, default=_DEFAULT_REMOTE_SERVICE_NAME),
        ActionField(name="local_gui_port", label="Local GUI port", kind="int", required=False, default=_DEFAULT_GUI_PORT, min_value=1),
        ActionField(name="remote_workdir", label="Remote repo directory", kind="string", required=False, default=_DEFAULT_REMOTE_WORKDIR),
        ActionField(name="remote_python", label="Remote Python", kind="string", required=False, default=_DEFAULT_REMOTE_PYTHON),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_remote_rig_status,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "remote-rig", "status"),
)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


get_registry().register(STATUS_SPEC)
get_registry().register(PROBE_SPEC)
get_registry().register(TOKEN_GENERATE_SPEC)
get_registry().register(CONFIG_SPEC)
get_registry().register(LOCAL_START_SPEC)
get_registry().register(LOCAL_STOP_SPEC)
get_registry().register(REMOTE_RIG_START_SPEC)
get_registry().register(REMOTE_RIG_STOP_SPEC)
get_registry().register(TUNNEL_START_SPEC)
get_registry().register(TUNNEL_STOP_SPEC)
get_registry().register(SYNC_TOKEN_SPEC)
get_registry().register(INSTALL_REMOTE_SERVICE_SPEC)
get_registry().register(REMOTE_SERVICE_CONTROL_SPEC)
get_registry().register(REMOTE_RIG_STATUS_SPEC)
