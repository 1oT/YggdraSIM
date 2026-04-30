from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

from .progress import progress_session
from .runtime_paths import runtime_path

SUPERVISOR_STATE_FILENAME = "hil_bridge_supervisor.json"
CARD_RELAY_STATE_FILENAME = "hil_bridge_card_relay.json"
DEFAULT_SERVICE_NAME = "yggdrasim-hil-supervisor.service"
DEFAULT_USB_VIDPID = "1d50:60e3"
DEFAULT_HTTP_TIMEOUT_SECONDS = 5.0
DEFAULT_SYSTEMCTL_TIMEOUT_SECONDS = 20.0
DEFAULT_BRIDGE_READY_TIMEOUT_SECONDS = 12.0
DEFAULT_BRIDGE_READY_POLL_SECONDS = 0.25
_REMSIM_VALUE_FLAGS = {"-i", "-p", "-c", "-n", "-V", "-P", "-C", "-I", "-S", "-A", "-H"}


@dataclass(frozen=True, slots=True)
class HilBridgeUserServiceOptions:
    python_executable: str
    working_directory: str
    reader_index: int = 0
    host: str = "127.0.0.1"
    port: int = 9997
    advertise_host: str = "127.0.0.1"
    usb_vidpid: str = DEFAULT_USB_VIDPID
    gsmtap_enabled: bool = True
    gsmtap_capture_path: str = ""
    remsim_args: tuple[str, ...] = ()
    service_name: str = DEFAULT_SERVICE_NAME
    documentation_path: str = ""
    environment_overrides: tuple[tuple[str, str], ...] = ()


def supervisor_state_path() -> str:
    return runtime_path("state", SUPERVISOR_STATE_FILENAME)


def card_relay_state_path() -> str:
    return runtime_path("state", CARD_RELAY_STATE_FILENAME)


def load_json_file(path: str) -> dict[str, Any]:
    target_path = str(path or "").strip()
    if len(target_path) == 0:
        return {}
    if os.path.isfile(target_path) is False:
        return {}
    try:
        with open(target_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(payload, dict) is False:
        return {}
    return payload


def read_supervisor_state() -> dict[str, Any]:
    return load_json_file(supervisor_state_path())


def read_card_relay_state() -> dict[str, Any]:
    return load_json_file(card_relay_state_path())


def guess_bridge_python_executable(
    supervisor_state: dict[str, Any] | None = None,
    *,
    fallback: str = "",
) -> str:
    payload = dict(supervisor_state or {})
    bridge_command = payload.get("bridgeCommand", [])
    if isinstance(bridge_command, list):
        for candidate in bridge_command:
            candidate_text = str(candidate or "").strip()
            if len(candidate_text) == 0:
                continue
            return candidate_text
    fallback_text = str(fallback or "").strip()
    if len(fallback_text) > 0:
        return fallback_text
    return str(sys.executable or "").strip()


def extract_remsim_extra_args_from_supervisor_state(
    supervisor_state: dict[str, Any] | None,
) -> tuple[str, ...]:
    payload = dict(supervisor_state or {})
    remsim_command = payload.get("remsimClientCommand", [])
    if isinstance(remsim_command, list) is False:
        return ()
    normalized_args: list[str] = []
    for raw_arg in remsim_command[1:]:
        arg_text = str(raw_arg or "").strip()
        if len(arg_text) == 0:
            continue
        normalized_args.append(arg_text)

    extra_args: list[str] = []
    skip_next = False
    for index, arg_text in enumerate(normalized_args):
        if skip_next:
            skip_next = False
            continue
        if arg_text in _REMSIM_VALUE_FLAGS and index + 1 < len(normalized_args):
            skip_next = True
            continue
        if any(arg_text.startswith(f"{flag}=") for flag in _REMSIM_VALUE_FLAGS):
            continue
        extra_args.append(arg_text)
    return tuple(extra_args)


def split_shell_like_arguments(argument_text: str) -> tuple[str, ...]:
    normalized_text = str(argument_text or "").strip()
    if len(normalized_text) == 0:
        return ()
    return tuple(shlex.split(normalized_text))


def _systemd_quote(value: str) -> str:
    text = str(value or "")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    if len(text) == 0:
        return '""'
    safe_characters = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._/:=@")
    if all(character in safe_characters for character in text):
        return text
    return f'"{escaped}"'


def render_user_service_unit(options: HilBridgeUserServiceOptions) -> str:
    documentation_path = str(options.documentation_path or "").strip()
    documentation_line = ""
    if len(documentation_path) > 0:
        documentation_line = f"Documentation=file:{documentation_path}\n"

    environment_lines = ""
    for key_name, value_text in options.environment_overrides:
        normalized_key = str(key_name or "").strip()
        if len(normalized_key) == 0:
            continue
        assignment = f"{normalized_key}={str(value_text or '').strip()}"
        environment_lines += f"Environment={_systemd_quote(assignment)}\n"

    command = [
        str(options.python_executable or "").strip(),
        "-m",
        "Tools.HilBridge.supervisor",
        "--reader-index",
        str(int(options.reader_index)),
        "--host",
        str(options.host or "").strip(),
        "--port",
        str(int(options.port)),
        "--advertise-host",
        str(options.advertise_host or "").strip(),
        "--usb-vidpid",
        str(options.usb_vidpid or "").strip(),
    ]
    if bool(options.gsmtap_enabled) is False:
        command.append("--no-gsmtap")
    capture_path = str(options.gsmtap_capture_path or "").strip()
    if len(capture_path) > 0:
        command.extend(
            [
                "--gsmtap-capture-path",
                capture_path,
            ]
        )
    for remsim_arg in options.remsim_args:
        command.append(f"--remsim-arg={str(remsim_arg or '').strip()}")

    exec_start = " ".join(_systemd_quote(part) for part in command if len(str(part or "").strip()) > 0)
    working_directory = _systemd_quote(str(options.working_directory or "").strip())
    return (
        "[Unit]\n"
        "Description=YggdraSIM HIL bridge supervisor\n"
        f"{documentation_line}"
        "After=default.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={working_directory}\n"
        "Environment=PYTHONUNBUFFERED=1\n"
        f"{environment_lines}"
        f"ExecStart={exec_start}\n"
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "KillMode=mixed\n"
        "TimeoutStopSec=10\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def user_service_dir(*, home_dir: str = "") -> str:
    base_dir = Path(str(home_dir or "").strip()) if len(str(home_dir or "").strip()) > 0 else Path.home()
    return str(base_dir / ".config" / "systemd" / "user")


def user_service_path(service_name: str = DEFAULT_SERVICE_NAME, *, home_dir: str = "") -> str:
    return str(Path(user_service_dir(home_dir=home_dir)) / str(service_name or DEFAULT_SERVICE_NAME).strip())


def install_user_service(
    unit_text: str,
    service_name: str = DEFAULT_SERVICE_NAME,
    *,
    home_dir: str = "",
) -> str:
    written_path, _ = write_user_service_if_changed(
        unit_text,
        service_name=service_name,
        home_dir=home_dir,
    )
    return written_path


def write_user_service_if_changed(
    unit_text: str,
    *,
    service_name: str = DEFAULT_SERVICE_NAME,
    home_dir: str = "",
) -> tuple[str, bool]:
    """Write ``unit_text`` to the user systemd unit path; report whether it changed.

    The on-disk content is compared byte-for-byte against ``unit_text``.
    When they already match, the file is left untouched (preserving
    mtime so ``systemctl --user daemon-reload`` keeps the existing
    fragment) and the second tuple element is ``False``. When they
    differ — or when the file does not yet exist — the new content is
    written and the second tuple element is ``True``. The flag lets
    the wizard decide between "no-op" and "restart so the new
    Environment= block takes effect".
    """
    target_path = Path(user_service_path(service_name=service_name, home_dir=home_dir))
    target_path.parent.mkdir(parents=True, exist_ok=True)
    desired_text = str(unit_text or "")
    existing_text = ""
    if target_path.is_file():
        try:
            existing_text = target_path.read_text(encoding="utf-8")
        except OSError:
            existing_text = ""
    if existing_text == desired_text:
        return str(target_path), False
    target_path.write_text(desired_text, encoding="utf-8")
    return str(target_path), True


def clear_card_relay_state() -> None:
    """Remove the relay marker so :func:`wait_for_bridge_ready` cannot
    latch onto a stale URL from a previous bridge generation.

    Wizards that drive a stop+start (or daemon-reload + restart) over
    the supervisor should clear the marker first; the new bridge child
    publishes a fresh marker once it is fully up. Missing files are
    tolerated quietly.
    """
    relay_path = card_relay_state_path()
    try:
        os.remove(relay_path)
    except FileNotFoundError:
        return
    except OSError:
        return


def clear_supervisor_state() -> None:
    """Remove the supervisor state file so :func:`wait_for_bridge_ready`
    cannot latch onto a stale ``reason`` from a previous run.

    The supervisor publishes its current ``status`` and ``reason``
    fields here as the reconcile loop progresses. When a previous
    invocation crashed mid-warm-up the file is left on disk with a
    transient ``restart-pending`` reason like
    ``Waiting 1.0s before bridge restart…``. Without this clear, the
    next start of the wizard would surface that stale reason as if it
    were a fresh failure. Missing files are tolerated quietly.
    """
    state_path = supervisor_state_path()
    try:
        os.remove(state_path)
    except FileNotFoundError:
        return
    except OSError:
        return


def _systemctl_error_text(completed: subprocess.CompletedProcess[str]) -> str:
    stderr_text = str(completed.stderr or "").strip()
    if len(stderr_text) > 0:
        return stderr_text
    stdout_text = str(completed.stdout or "").strip()
    if len(stdout_text) > 0:
        return stdout_text
    return f"exit status {completed.returncode}"


def run_systemctl_user(
    args: list[str] | tuple[str, ...],
    *,
    timeout_seconds: float = DEFAULT_SYSTEMCTL_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    command = ["systemctl", "--user", *[str(arg or "").strip() for arg in args]]
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(1.0, float(timeout_seconds or DEFAULT_SYSTEMCTL_TIMEOUT_SECONDS)),
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"systemctl is not available: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"systemctl timed out: {exc}") from exc


def run_systemctl_user_checked(
    args: list[str] | tuple[str, ...],
    *,
    timeout_seconds: float = DEFAULT_SYSTEMCTL_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    completed = run_systemctl_user(args, timeout_seconds=timeout_seconds)
    if completed.returncode != 0:
        joined_args = " ".join(str(arg or "").strip() for arg in args)
        raise RuntimeError(f"systemctl --user {joined_args} failed: {_systemctl_error_text(completed)}")
    return completed


def query_user_service_state(service_name: str = DEFAULT_SERVICE_NAME) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "serviceName": str(service_name or DEFAULT_SERVICE_NAME).strip(),
        "systemctlAvailable": True,
        "loadState": "",
        "unitFileState": "",
        "activeState": "",
        "subState": "",
        "fragmentPath": "",
        "error": "",
    }
    try:
        completed = run_systemctl_user(
            [
                "show",
                payload["serviceName"],
                "--property=LoadState,UnitFileState,ActiveState,SubState,FragmentPath",
            ]
        )
    except RuntimeError as exc:
        payload["systemctlAvailable"] = False
        payload["error"] = str(exc)
        return payload

    if completed.returncode != 0:
        payload["error"] = _systemctl_error_text(completed)
        return payload

    for raw_line in str(completed.stdout or "").splitlines():
        line_text = str(raw_line or "").strip()
        if "=" not in line_text:
            continue
        key_text, value_text = line_text.split("=", 1)
        key_name = str(key_text or "").strip()
        if len(key_name) == 0:
            continue
        payload[key_name[:1].lower() + key_name[1:]] = str(value_text or "").strip()
    return payload


def daemon_reload_user_services() -> None:
    run_systemctl_user_checked(["daemon-reload"])


def enable_now_user_service(service_name: str = DEFAULT_SERVICE_NAME) -> None:
    run_systemctl_user_checked(["enable", "--now", str(service_name or DEFAULT_SERVICE_NAME).strip()])


def restart_user_service(service_name: str = DEFAULT_SERVICE_NAME) -> None:
    run_systemctl_user_checked(["restart", str(service_name or DEFAULT_SERVICE_NAME).strip()])


def start_user_service(service_name: str = DEFAULT_SERVICE_NAME) -> None:
    run_systemctl_user_checked(["start", str(service_name or DEFAULT_SERVICE_NAME).strip()])


def stop_user_service(service_name: str = DEFAULT_SERVICE_NAME) -> None:
    run_systemctl_user_checked(["stop", str(service_name or DEFAULT_SERVICE_NAME).strip()])


def disable_user_service(service_name: str = DEFAULT_SERVICE_NAME) -> None:
    run_systemctl_user_checked(["disable", str(service_name or DEFAULT_SERVICE_NAME).strip()])


def _request_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    headers: dict[str, str] = {}
    request_body: bytes | None = None
    if payload is not None:
        request_body = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request_object = request.Request(
        str(url or "").strip(),
        data=request_body,
        headers=headers,
        method=str(method or "GET").strip().upper(),
    )
    try:
        with request.urlopen(
            request_object,
            timeout=max(1.0, float(timeout_seconds or DEFAULT_HTTP_TIMEOUT_SECONDS)),
        ) as response:
            raw_payload = response.read()
    except error.HTTPError as exc:
        detail_text = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Bridge HTTP {exc.code}: {detail_text or exc.reason}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Bridge request failed: {exc.reason}") from exc

    if len(raw_payload) == 0:
        return {}
    try:
        response_payload = json.loads(raw_payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Bridge returned invalid JSON: {exc}") from exc
    if isinstance(response_payload, dict) is False:
        raise RuntimeError("Bridge returned a non-object JSON payload.")
    return response_payload


def _relay_control_url(key_name: str) -> str:
    relay_state = read_card_relay_state()
    url = str(relay_state.get(str(key_name or "").strip(), "") or "").strip()
    if len(url) == 0:
        raise RuntimeError("HIL bridge relay state is unavailable. Start the bridge first.")
    return url


def read_bridge_status() -> dict[str, Any]:
    return _request_json(_relay_control_url("statusUrl"), method="GET")


def is_hil_bridge_running() -> bool:
    supervisor_state = read_supervisor_state()
    if bool(supervisor_state.get("bridgeRunning", False)) is False:
        return False
    return True


def hil_bridge_warning_text() -> str:
    if is_hil_bridge_running() is False:
        return ""
    return (
        "Warning: YggdraSIM HIL is running. If the modem is active at the same time, "
        "concurrent traffic may change card state and cause unforeseen issues."
    )


def wait_for_bridge_ready(
    *,
    timeout_seconds: float = DEFAULT_BRIDGE_READY_TIMEOUT_SECONDS,
    poll_interval_seconds: float = DEFAULT_BRIDGE_READY_POLL_SECONDS,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(0.5, float(timeout_seconds or DEFAULT_BRIDGE_READY_TIMEOUT_SECONDS))
    last_relay_error_text = ""
    last_status_text = ""
    last_reason_text = ""
    crash_observed = False
    relay_url_observed = False
    # Readiness is an indeterminate poll loop — supervisor boot time
    # depends on USB detection, systemd warm-up, and the remsim
    # client init. The sticky footer gives operators a visible
    # heartbeat so a stalled bridge startup is obvious. Inactive on
    # non-TTY surfaces so scripted launches stay byte-identical.
    with progress_session("HIL bridge warm-up") as bar:
        bar.set_status("waiting for relay status URL")
        while time.monotonic() < deadline:
            relay_state = read_card_relay_state()
            status_url = str(relay_state.get("statusUrl", "") or "").strip()
            if len(status_url) > 0:
                relay_url_observed = True
                bar.set_status("probing relay status endpoint")
                try:
                    payload = _request_json(status_url, method="GET")
                except Exception as exc:
                    last_relay_error_text = str(exc)
                else:
                    return payload
            supervisor_state = read_supervisor_state()
            status_text = str(supervisor_state.get("status", "") or "").strip()
            reason_text = str(supervisor_state.get("reason", "") or "").strip()
            if len(status_text) > 0:
                last_status_text = status_text
            if len(reason_text) > 0:
                last_reason_text = reason_text
                bar.set_status(f"supervisor: {reason_text[:48]}")
            if status_text in ("restart-pending", "start-failed"):
                crash_observed = True
            time.sleep(max(0.05, float(poll_interval_seconds or DEFAULT_BRIDGE_READY_POLL_SECONDS)))
    raise RuntimeError(_compose_bridge_ready_failure(
        status_text=last_status_text,
        reason_text=last_reason_text,
        relay_error_text=last_relay_error_text,
        relay_url_observed=relay_url_observed,
        crash_observed=crash_observed,
    ))


def _compose_bridge_ready_failure(
    *,
    status_text: str,
    reason_text: str,
    relay_error_text: str,
    relay_url_observed: bool,
    crash_observed: bool,
) -> str:
    """Compose an actionable error message for ``wait_for_bridge_ready``.

    The supervisor publishes a ``status`` field (``running``,
    ``restart-pending``, ``start-failed``, ``usb-detect-error`` …) and
    a free-form ``reason``. Surfacing the raw ``reason`` on timeout —
    as the previous implementation did — was misleading because a
    transient ``restart-pending`` reason like
    ``Waiting 1.0s before bridge restart (simulated card backend).``
    looks like a non-fatal hint but is actually the symptom of a
    bridge child that keeps crashing within the warm-up window. This
    helper distinguishes those cases and points operators at the
    user-journal trace for the actual bridge-child failure.
    """
    journal_hint = (
        f"Run `journalctl --user -u {DEFAULT_SERVICE_NAME} "
        '--since "5 min ago" --no-pager | tail -n 80` for the bridge child traceback.'
    )
    if status_text == "start-failed":
        if len(reason_text) > 0:
            return f"HIL bridge could not start: {reason_text}. {journal_hint}"
        return f"HIL bridge could not start. {journal_hint}"
    if status_text == "usb-detect-error":
        if len(reason_text) > 0:
            return f"HIL bridge USB detection failed: {reason_text}. {journal_hint}"
        return f"HIL bridge USB detection failed. {journal_hint}"
    if crash_observed:
        return (
            "HIL bridge child crashed during warm-up and the supervisor "
            f"entered a restart-backoff loop. {journal_hint}"
        )
    if relay_url_observed and len(relay_error_text) > 0:
        return (
            "HIL bridge relay endpoint did not become reachable within "
            f"the warm-up window: {relay_error_text}. {journal_hint}"
        )
    if len(relay_error_text) > 0:
        return f"HIL bridge warm-up timeout: {relay_error_text}. {journal_hint}"
    if len(reason_text) > 0:
        return (
            f"Timed out waiting for HIL bridge relay readiness. "
            f"Last supervisor state: {reason_text}. {journal_hint}"
        )
    return f"Timed out waiting for HIL bridge relay readiness. {journal_hint}"
