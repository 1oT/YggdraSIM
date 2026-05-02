from __future__ import annotations

import os
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from uuid import uuid4

from .runtime_paths import runtime_root
from .structured_output import dump_structured_payload

ApduTraceListener = Callable[[dict[str, Any]], None]

_APDU_TRACE_LISTENER: Optional[ApduTraceListener] = None
_APDU_TRACE_LISTENER_LOCK = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def set_apdu_trace_listener(
    listener: Optional[ApduTraceListener],
) -> Optional[ApduTraceListener]:
    global _APDU_TRACE_LISTENER
    with _APDU_TRACE_LISTENER_LOCK:
        previous = _APDU_TRACE_LISTENER
        _APDU_TRACE_LISTENER = listener
    return previous


def emit_apdu_trace_event(
    *,
    log_name: str,
    apdu: bytes,
    response: bytes,
    sw1: int,
    sw2: int,
    transport: str = "",
) -> None:
    with _APDU_TRACE_LISTENER_LOCK:
        listener = _APDU_TRACE_LISTENER
    if callable(listener) is False:
        return
    payload = {
        "logged_at_utc": _utc_now_iso(),
        "transport": str(transport or "").strip(),
        "log_name": str(log_name or "").strip(),
        "apdu_hex": bytes(apdu).hex().upper(),
        "response_data_hex": bytes(response).hex().upper(),
        "sw1": int(sw1),
        "sw2": int(sw2),
        "status_hex": f"{int(sw1):02X}{int(sw2):02X}",
        "response_len": len(bytes(response)),
        "ok": f"{int(sw1):02X}{int(sw2):02X}" in ("9000", "9100"),
        "thread_id": threading.get_ident(),
    }
    try:
        listener(payload)
    except Exception:
        pass


_APDU_TRACE_SOFT_CAP_DEFAULT = 50_000
_APDU_TRACE_SOFT_CAP_ENV = "YGGDRASIM_SESSION_APDU_TRACE_CAP"


def _resolve_apdu_trace_soft_cap() -> int:
    raw = str(os.environ.get(_APDU_TRACE_SOFT_CAP_ENV, "") or "").strip()
    if len(raw) == 0:
        return _APDU_TRACE_SOFT_CAP_DEFAULT
    try:
        parsed = int(raw)
    except ValueError:
        return _APDU_TRACE_SOFT_CAP_DEFAULT
    if parsed <= 0:
        return _APDU_TRACE_SOFT_CAP_DEFAULT
    return parsed


class ShellSessionRecorder:
    def __init__(self, *, shell_name: str, module_entry_point: str):
        self.shell_name = str(shell_name or "").strip() or "shell"
        self.module_entry_point = str(module_entry_point or "").strip()
        self._previous_listener: Optional[ApduTraceListener] = None
        self._last_export_path = ""
        self._last_summary: dict[str, Any] = {}
        # Guards state mutated by ``record_apdu_event`` (invoked from the
        # listener on the dispatch thread) against the interactive-shell
        # thread that calls ``begin_command`` / ``finish_command`` / ``stop``.
        # list.append is GIL-atomic but the index counters and
        # ``_active_command`` cross-references are not, so a single lock is
        # the simplest correctness fix.
        self._state_lock = threading.Lock()
        self._apdu_trace_soft_cap = _resolve_apdu_trace_soft_cap()
        self._apdu_trace_cap_warned = False
        self._reset_capture()

    def _reset_capture(self) -> None:
        self._active = False
        self._session_id = ""
        self._started_at_utc = ""
        self._stopped_at_utc = ""
        self._pending_output_path = ""
        self._commands: list[dict[str, Any]] = []
        self._apdu_trace: list[dict[str, Any]] = []
        self._active_command: Optional[dict[str, Any]] = None
        self._next_command_index = 1
        self._next_apdu_index = 1

    def _safe_shell_label(self) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", self.shell_name).strip("_")
        if len(cleaned) == 0:
            return "session_recording"
        return cleaned

    def _default_output_path(self) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{self._safe_shell_label()}_{timestamp}.yaml"
        return str((Path(runtime_root()) / "reports" / "session_records" / filename).resolve())

    def _normalize_output_path(self, output_path: str = "") -> str:
        candidate = str(output_path or "").strip()
        if len(candidate) == 0:
            if len(self._pending_output_path) > 0:
                return self._pending_output_path
            return self._default_output_path()
        path = Path(os.path.expanduser(candidate))
        if path.is_absolute() is False:
            path = (Path.cwd() / path).resolve()
        else:
            path = path.resolve()
        if path.suffix.lower() not in (".yaml", ".yml", ".json"):
            path = path.with_suffix(".yaml")
        return str(path)

    def is_active(self) -> bool:
        with self._state_lock:
            return bool(self._active)

    def start(self, output_path: str = "") -> str:
        with self._state_lock:
            if self._active:
                raise ValueError(
                    "Recording is already active. Use RECORD STOP or RECORD CANCEL first."
                )
            self._reset_capture()
            self._active = True
            self._session_id = uuid4().hex
            self._started_at_utc = _utc_now_iso()
            self._pending_output_path = self._normalize_output_path(output_path)
            pending = self._pending_output_path
        # ``set_apdu_trace_listener`` takes the module-level listener lock; keep
        # it outside ``_state_lock`` to avoid cross-lock ordering risks if the
        # listener ever re-enters the recorder.
        self._previous_listener = set_apdu_trace_listener(self.record_apdu_event)
        return pending

    def cancel(self) -> None:
        if self._active is False:
            return
        set_apdu_trace_listener(self._previous_listener)
        self._previous_listener = None
        with self._state_lock:
            self._reset_capture()

    def begin_command(
        self,
        *,
        raw_command: str,
        canonical_command: str,
        replay_command: str,
        debug_enabled: bool,
        source: str,
    ) -> Optional[dict[str, Any]]:
        with self._state_lock:
            if self._active is False:
                return None
            command_record: dict[str, Any] = {
                "index": self._next_command_index,
                "raw_command": str(raw_command or "").strip(),
                "canonical_command": str(canonical_command or "").strip().upper(),
                "replay_command": str(replay_command or "").strip(),
                "source": str(source or "").strip() or "interactive",
                "debug_enabled": bool(debug_enabled),
                "started_at_utc": _utc_now_iso(),
                "finished_at_utc": "",
                "success": None,
                "error": "",
                "apdu_count": 0,
            }
            self._next_command_index += 1
            self._commands.append(command_record)
            self._active_command = command_record
            return command_record

    def finish_command(
        self,
        command_record: Optional[dict[str, Any]],
        *,
        success: bool,
        error: str = "",
    ) -> None:
        if command_record is None:
            return
        with self._state_lock:
            if len(str(command_record.get("finished_at_utc", "")).strip()) > 0:
                if self._active_command is command_record:
                    self._active_command = None
                return
            command_record["finished_at_utc"] = _utc_now_iso()
            command_record["success"] = bool(success)
            command_record["error"] = str(error or "").strip()
            if self._active_command is command_record:
                self._active_command = None

    def record_apdu_event(self, event: dict[str, Any]) -> None:
        emit_cap_warning = False
        cap_threshold = 0
        with self._state_lock:
            if self._active is False:
                return
            payload = dict(event)
            payload["index"] = self._next_apdu_index
            self._next_apdu_index += 1
            command_record = self._active_command
            if command_record is not None:
                payload["command_index"] = int(command_record.get("index", 0) or 0)
                payload["command_canonical"] = str(
                    command_record.get("canonical_command", "") or ""
                ).strip()
                payload["command_replay"] = str(
                    command_record.get("replay_command", "") or ""
                ).strip()
                command_record["apdu_count"] = int(command_record.get("apdu_count", 0) or 0) + 1
            else:
                payload["command_index"] = None
                payload["command_canonical"] = ""
                payload["command_replay"] = ""
            # Soft cap: drop the oldest entry so long-running recording
            # sessions cannot grow ``_apdu_trace`` without bound. We keep the
            # most recent ``_apdu_trace_soft_cap`` entries because the tail is
            # the interesting part when debugging a hang or a regression.
            if len(self._apdu_trace) >= self._apdu_trace_soft_cap:
                del self._apdu_trace[0]
                if self._apdu_trace_cap_warned is False:
                    self._apdu_trace_cap_warned = True
                    emit_cap_warning = True
                    cap_threshold = self._apdu_trace_soft_cap
            self._apdu_trace.append(payload)
        if emit_cap_warning:
            sys.stderr.write(
                "[session-recording] APDU trace buffer reached the "
                f"{cap_threshold}-event soft cap; oldest events will be dropped "
                f"(override via {_APDU_TRACE_SOFT_CAP_ENV}).\n"
            )

    def _successful_replay_commands(self) -> list[str]:
        # Callers hold ``_state_lock`` already (``status_payload`` /
        # ``_build_payload``) so we walk the list directly without taking it
        # again -- re-entering a ``threading.Lock`` would deadlock.
        commands: list[str] = []
        for command_record in self._commands:
            if command_record.get("success") is not True:
                continue
            replay_command = str(command_record.get("replay_command", "") or "").strip()
            if len(replay_command) == 0:
                continue
            commands.append(replay_command)
        return commands

    def _summary_payload(self, *, record_file: str) -> dict[str, Any]:
        successful_command_count = sum(
            1 for command_record in self._commands if command_record.get("success") is True
        )
        failed_command_count = sum(
            1 for command_record in self._commands if command_record.get("success") is False
        )
        replay_commands = self._successful_replay_commands()
        return {
            "command_count": len(self._commands),
            "successful_command_count": successful_command_count,
            "failed_command_count": failed_command_count,
            "apdu_count": len(self._apdu_trace),
            "replay_command_count": len(replay_commands),
            "record_file": record_file,
        }

    def status_payload(self) -> dict[str, Any]:
        with self._state_lock:
            if self._active:
                summary = self._summary_payload(record_file=self._pending_output_path)
            else:
                summary = dict(self._last_summary)
            return {
                "active": bool(self._active),
                "session_id": self._session_id,
                "module_entry_point": self.module_entry_point,
                "started_at_utc": self._started_at_utc,
                "pending_output_path": self._pending_output_path,
                "last_export_path": self._last_export_path,
                "command_count": int(summary.get("command_count", 0) or 0),
                "successful_command_count": int(
                    summary.get("successful_command_count", 0) or 0
                ),
                "failed_command_count": int(summary.get("failed_command_count", 0) or 0),
                "apdu_count": int(summary.get("apdu_count", 0) or 0),
            }

    def _build_payload(self, *, record_file: str) -> dict[str, Any]:
        replay_commands = self._successful_replay_commands()
        stopped_at_utc = self._stopped_at_utc or _utc_now_iso()
        return {
            "schema": "yggdrasim_session_recording/v1",
            "session_id": self._session_id,
            "shell": self.shell_name,
            "module_entry_point": self.module_entry_point,
            "recorded_at_utc": {
                "started": self._started_at_utc,
                "stopped": stopped_at_utc,
            },
            "context": {
                "cwd": os.getcwd(),
                "runtime_root": runtime_root(),
                "python_executable": sys.executable,
                "pid": os.getpid(),
            },
            "summary": self._summary_payload(record_file=record_file),
            "replay": {
                "entry_point": self.module_entry_point,
                "commands": replay_commands,
                "stdin_lines": replay_commands,
                "stdin_text": "\n".join(replay_commands),
                "semicolon_batch": "; ".join(replay_commands),
            },
            "commands": list(self._commands),
            "apdu_trace": list(self._apdu_trace),
        }

    def _write_payload(self, output_path: str, payload: dict[str, Any]) -> None:
        output_mode = "json" if Path(output_path).suffix.lower() == ".json" else "yaml"
        parent = os.path.dirname(output_path)
        if len(parent) > 0:
            os.makedirs(parent, exist_ok=True)
        rendered = dump_structured_payload(payload, output_mode=output_mode)
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            if rendered.endswith("\n") is False:
                handle.write("\n")

    def stop(self, output_path: str = "") -> tuple[str, dict[str, Any]]:
        # Detach the listener first so late APDU events from the dispatch
        # thread cannot land in ``_apdu_trace`` mid-serialisation. The
        # module-level listener lock (acquired inside
        # ``set_apdu_trace_listener``) is disjoint from ``_state_lock``, so
        # taking them in this order avoids a deadlock.
        with self._state_lock:
            if self._active is False:
                raise ValueError("Recording is not active.")
        set_apdu_trace_listener(self._previous_listener)
        self._previous_listener = None
        with self._state_lock:
            self._stopped_at_utc = _utc_now_iso()
            normalized_output_path = self._normalize_output_path(output_path)
            payload = self._build_payload(record_file=normalized_output_path)
        self._write_payload(normalized_output_path, payload)
        with self._state_lock:
            self._last_export_path = normalized_output_path
            self._last_summary = dict(payload.get("summary", {}))
            self._reset_capture()
        return normalized_output_path, payload
