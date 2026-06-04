# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 eIM-local Command Center actions.

Registers the full operator surface that ``python -m SCP11.eim_local``
exposes over its interactive shell, so the GUI can drive the same
flows without dropping into a raw REPL. Coverage:

* Read-only telemetry (status, discover, list_profiles, identity).
* Profile mutations (enable / disable / delete / load-profile).
* Metadata plumbing (store_metadata / update_metadata).
* eIM commands (get_eim_config, delete_eim, add_eim).
* eIM package tooling (lint, issue, hotfolder list).
* Error-code vocabulary + counter inspection.
* The existing streaming poll-campaign flow.

All synchronous dispatchers construct a fresh ``EimLocalSession`` per
call so there's no hidden cross-action state. The session's default
``apdu_channel`` is a ``PcscApduChannel`` pointed at the configured
reader index; operators can override the reader through the shell
env flags or config if needed.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import logging
import re
import threading
from typing import Any, AsyncIterator

from .registry import ActionContext, ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.eim_local")


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


def _scrub_bytes(value: Any) -> Any:
    """Convert nested bytes to uppercase hex so JSON serialisation works."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex().upper()
    if isinstance(value, dict):
        return {str(key): _scrub_bytes(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_bytes(entry) for entry in value]
    return value


def _build_eim_session() -> Any:
    """Instantiate an ``EimLocalSession`` using the default PC/SC channel."""
    from SCP11.eim_local.session import EimLocalSession

    return EimLocalSession()


def _hex_preview(payload: Any, max_chars: int = 160) -> str:
    text = bytes(payload or b"").hex().upper()
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "…"


# ----------------------------------------------------------------------
# Streaming dispatcher
# ----------------------------------------------------------------------


async def _dispatch_poll_campaign(
    ctx: ActionContext,
    *,
    cycles: Any = None,
    interval_ms: Any = None,
    hotfolder_dir: Any = None,
    until_empty: Any = None,
    max_cycles: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    """Stream progress events while the campaign runs on a background thread."""
    cycles_i = int(cycles) if cycles is not None else 10
    interval_i = int(interval_ms) if interval_ms is not None else 1000
    hotfolder_s = str(hotfolder_dir or "")
    until_empty_b = bool(until_empty)
    max_cycles_v = None if max_cycles is None else int(max_cycles)

    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def _emit(level: str, message: str, **extra: Any) -> None:
        asyncio.run_coroutine_threadsafe(
            queue.put({"level": level, "message": message, **extra}),
            loop,
        )

    def _worker() -> None:
        try:
            _emit("info", "loading EimLocalSession…")
            from SCP11.eim_local.session import EimLocalSession

            session = EimLocalSession()

            _emit(
                "info",
                (
                    f"starting poll-campaign "
                    f"cycles={cycles_i} interval_ms={interval_i} "
                    f"until_empty={until_empty_b} max_cycles={max_cycles_v} "
                    f"hotfolder={hotfolder_s or '(default)'}"
                ),
            )

            capture = _CapturingStream(post=_emit)
            with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
                report = session.poll_hotfolder_campaign(
                    cycles=cycles_i,
                    interval_ms=interval_i,
                    hotfolder_dir=hotfolder_s,
                    until_empty=until_empty_b,
                    max_cycles=max_cycles_v,
                )

            capture.flush()

            rows = report.get("rows", []) or []
            summary = report.get("summary", {}) or {}
            _emit(
                "info",
                (
                    f"summary: issued={summary.get('issued_cycles', 0)} "
                    f"no_package={summary.get('no_package_cycles', 0)} "
                    f"errors={summary.get('error_cycles', 0)} "
                    f"stop={summary.get('stop_reason', '-')}"
                ),
            )
            _emit(
                "done",
                f"poll-campaign finished with {len(rows)} cycle(s).",
                report=report,
            )
        except Exception as error:  # noqa: BLE001 — surface every failure mode
            import traceback

            _emit("error", f"{type(error).__name__}: {error}")
            _emit("error", traceback.format_exc())
            _emit("done", "poll-campaign aborted.")

    worker = threading.Thread(
        target=_worker,
        name="yggdrasim-gui-eim-poll-campaign",
        daemon=True,
    )
    worker.start()

    try:
        while True:
            event = await queue.get()
            yield event
            if event.get("level") == "done":
                break
    finally:
        # Give the worker a moment to flush the final sentinel.
        for _ in range(20):
            if not worker.is_alive():
                break
            await asyncio.sleep(0.05)


class _CapturingStream(io.TextIOBase):
    """Tee ``stdout``/``stderr`` into structured events, line by line."""

    def __init__(self, post) -> None:  # type: ignore[no-untyped-def]
        super().__init__()
        self._post = post
        self._buffer = ""

    def write(self, data: str) -> int:
        """Serialise and write the eIM-local action result to the response stream."""
        self._buffer += data
        while "\n" in self._buffer:
            line, _, rest = self._buffer.partition("\n")
            self._buffer = rest
            if len(line) == 0:
                continue
            self._post(_infer_level(line), line)
        return len(data)

    def flush(self) -> None:
        if len(self._buffer) > 0:
            self._post(_infer_level(self._buffer), self._buffer)
            self._buffer = ""


def _infer_level(line: str) -> str:
    lowered = line.lower()
    if "[-]" in line or "error" in lowered or "failed" in lowered:
        return "error"
    if "warn" in lowered or "[!]" in line:
        return "warn"
    if "[+]" in line or "ok" in lowered or "✓" in line:
        return "info"
    return "info"


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


# ----------------------------------------------------------------------
# Synchronous helper dispatchers (no hardware, no streaming)
# ----------------------------------------------------------------------


def _dispatch_list_fixtures(ctx: ActionContext) -> dict[str, Any]:
    """Return the fixed fixture package files that always seed the poll queue."""
    from SCP11.eim_local.session import EimLocalSession

    session = EimLocalSession()
    fixtures = session.list_fixed_poll_fixture_package_files() or []
    rows = [
        {"index": index, "path": str(path)} for index, path in enumerate(fixtures, start=1)
    ]
    return {
        "count": len(rows),
        "rows": rows,
    }


def _dispatch_hotfolder_metadata(
    ctx: ActionContext,
    *,
    hotfolder_dir: Any = None,
) -> dict[str, Any]:
    """Inspect the hotfolder: resolved path, queue depth, next package."""
    from SCP11.eim_local.session import EimLocalSession

    session = EimLocalSession()
    resolved_dir = str(hotfolder_dir or "").strip()
    metadata = session.hotfolder_poll_metadata(hotfolder_dir=resolved_dir)
    queue_preview = metadata.get("queue_preview", []) or []
    compact_preview = []
    for entry in queue_preview:
        if not isinstance(entry, dict):
            continue
        compact_preview.append({
            "order": entry.get("order", 0),
            "path": entry.get("path", ""),
            "name": entry.get("name", ""),
            "eim_id": entry.get("eim_id", ""),
            "package_id": entry.get("package_id", ""),
        })
    return {
        "hotfolder_dir": metadata.get("hotfolder_dir", ""),
        "polling_complete": bool(metadata.get("polling_complete", True)),
        "eim_result_code": metadata.get("eim_result_code"),
        "eim_result_name": metadata.get("eim_result_name", ""),
        "response_tlv_hex": metadata.get("response_tlv_hex", ""),
        "package_count": int(metadata.get("package_count", 0) or 0),
        "next_file": metadata.get("next_file", ""),
        "queue_preview": compact_preview,
    }


def _dispatch_issue_package(
    ctx: ActionContext,
    *,
    hotfolder_dir: Any = None,
) -> dict[str, Any]:
    """Issue the next package in the hotfolder queue (single-shot, sync)."""
    from SCP11.eim_local.session import EimLocalSession

    session = EimLocalSession()
    resolved_dir = str(hotfolder_dir or "").strip()
    issued = session.issue_next_hotfolder_package(hotfolder_dir=resolved_dir)
    if issued is None:
        return {
            "issued": False,
            "hotfolder_dir": session.resolve_hotfolder_path(override_path=resolved_dir),
            "reason": "queue empty",
        }
    package_path, _label, _cycle_index = issued
    return {
        "issued": True,
        "hotfolder_dir": session.resolve_hotfolder_path(override_path=resolved_dir),
        "package_path": str(package_path),
    }


LIST_FIXTURES_SPEC = ActionSpec(
    id="eim_local.list_fixtures",
    subsystem="Local eIM",
    title="List fixed fixtures",
    description="Enumerate the bundled fixture packages that seed every poll queue run.",
    inputs=(),
    output_kind="table",
    dispatcher=_dispatch_list_fixtures,
    requires_card=False,
    tags=("eim", "fixtures"),
)


HOTFOLDER_METADATA_SPEC = ActionSpec(
    id="eim_local.hotfolder_metadata",
    subsystem="Local eIM",
    title="Hotfolder metadata",
    description=(
        "Inspect the effective hotfolder: resolved path, queue depth, next "
        "package, and the last ES25 response-meta snapshot."
    ),
    inputs=(
        ActionField(
            name="hotfolder_dir",
            label="Hotfolder directory",
            kind="directory",
            required=False,
            placeholder="(leave blank for default)",
            help="Double-click to browse.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_hotfolder_metadata,
    requires_card=False,
    tags=("eim", "hotfolder"),
)


ISSUE_PACKAGE_SPEC = ActionSpec(
    id="eim_local.issue_package",
    subsystem="Local eIM",
    title="Issue next package",
    description=(
        "Pop and issue the next package in the hotfolder queue (single cycle, "
        "no loop). Useful for step-by-step debugging."
    ),
    inputs=(
        ActionField(
            name="hotfolder_dir",
            label="Hotfolder directory",
            kind="directory",
            required=False,
            placeholder="(leave blank for default)",
            help="Double-click to browse.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_issue_package,
    requires_card=False,
    tags=("eim", "issue"),
)


POLL_CAMPAIGN_SPEC = ActionSpec(
    id="eim_local.poll_campaign",
    subsystem="Local eIM",
    title="Poll campaign (hotfolder)",
    description=(
        "Run the effective poll queue campaign (fixed fixtures + hotfolder) "
        "and issue one eIM package per cycle. Streams per-cycle progress "
        "and returns a structured report when finished."
    ),
    inputs=(
        ActionField(
            name="cycles",
            label="Cycles",
            kind="int",
            required=False,
            default=10,
            min_value=1,
            help="Number of poll cycles to run. Ignored if 'until empty' is set.",
        ),
        ActionField(
            name="interval_ms",
            label="Interval (ms)",
            kind="int",
            required=False,
            default=1000,
            min_value=0,
            help="Sleep between cycles, in milliseconds.",
        ),
        ActionField(
            name="hotfolder_dir",
            label="Hotfolder directory",
            kind="directory",
            required=False,
            help="Override the hotfolder directory. Leave empty for the repo default. Double-click to browse.",
            placeholder="(leave blank for default)",
        ),
        ActionField(
            name="until_empty",
            label="Run until queue empty",
            kind="bool",
            required=False,
            default=False,
            help="Stop as soon as the poll queue is drained.",
        ),
        ActionField(
            name="max_cycles",
            label="Max cycles (safety cap)",
            kind="int",
            required=False,
            default=None,
            min_value=1,
            help="Hard upper bound on cycles when 'until empty' is enabled.",
        ),
    ),
    output_kind="log_stream",
    dispatcher=_dispatch_poll_campaign,
    requires_card=False,
    streams=True,
    tags=("eim", "poll", "campaign"),
)


# ----------------------------------------------------------------------
# Session-driven dispatchers (read-only telemetry)
# ----------------------------------------------------------------------


def _dispatch_status(ctx: ActionContext) -> dict[str, Any]:
    """Runtime snapshot — mirrors the shell STATUS command."""
    session = _build_eim_session()
    state = session.state
    eim_state = session.eim_state
    identity = session.identity_summary() or {}
    runtime = session.runtime_state_summary() or {}
    handover = session.handover_context() or {}

    lines: list[dict[str, str]] = []
    lines.append({"label": "Session open", "value": "yes" if state.session_open else "no"})
    lines.append({"label": "ISD-R selected", "value": "yes" if state.isdr_selected else "no"})
    txid_hex = state.transaction_id.hex().upper() if len(state.transaction_id) > 0 else "-"
    lines.append({"label": "Transaction id", "value": txid_hex})
    lines.append({"label": "BIP routing mode", "value": str(eim_state.bip_routing_mode or "-")})
    lines.append({"label": "BIP role", "value": str(eim_state.current_bip_role or "-")})
    lines.append({"label": "BIP endpoint", "value": str(eim_state.current_bip_endpoint or "-")})
    lines.append({"label": "eIM id", "value": str(identity.get("eim_id", "-") or "-")})
    lines.append({"label": "eIM FQDN", "value": str(identity.get("eim_fqdn", "-") or "-")})
    lines.append({"label": "eIM endpoint", "value": str(identity.get("eim_endpoint", "-") or "-")})
    lines.append({"label": "SM-DP+ endpoint", "value": str(identity.get("smdpp_endpoint", "-") or "-")})
    lines.append({"label": "Default matchingId", "value": str(identity.get("default_matching_id", "-") or "-")})
    lines.append({"label": "eIM package override", "value": str(eim_state.eim_package_override_path or "-")})
    lines.append({"label": "Hotfolder override", "value": str(eim_state.hotfolder_override_path or "-")})
    lines.append({"label": "Pending operations", "value": str(len(session.pending_operations()))})
    lines.append({"label": "Handover txid", "value": str(handover.get("transaction_id_hex", "-") or "-")})
    lines.append({"label": "Handover matchingId", "value": str(handover.get("matching_id", "-") or "-")})
    lines.append({"label": "Handover source", "value": str(handover.get("source", "-") or "-")})

    counter_map = runtime.get("counter_by_eim_id", {}) or {}
    counter_rows = []
    if isinstance(counter_map, dict):
        for eim_id in sorted(counter_map.keys()):
            counter_rows.append({"eim_id": eim_id, "next": str(counter_map.get(eim_id))})

    return {
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": 0,
        "identity": _scrub_bytes(identity),
        "runtime": _scrub_bytes(runtime),
        "handover": _scrub_bytes(handover),
        "counters": counter_rows,
    }


def _dispatch_discover(ctx: ActionContext) -> dict[str, Any]:
    """Run a card-touching discovery probe and scrub the snapshot for JSON."""
    session = _build_eim_session()
    trace_sink = io.StringIO()
    snapshot: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            snapshot = session.discover_card() or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    scrubbed = _scrub_bytes(snapshot) if isinstance(snapshot, dict) else {}
    eid_value = str(scrubbed.get("eid", "") or "").strip()
    profiles = scrubbed.get("profiles") or []
    profile_count = len(profiles) if isinstance(profiles, list) else 0
    return {
        "ok": len(note_parts) == 0,
        "eid": eid_value,
        "profile_count": profile_count,
        "snapshot": scrubbed,
        "note": "; ".join(note_parts) if note_parts else (
            f"discovery complete — EID={eid_value or '-'} · {profile_count} profile(s)"
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_list_profile_aliases(ctx: ActionContext) -> dict[str, Any]:
    """List the AID-registry profile aliases known to the session."""
    session = _build_eim_session()
    aliases = session.list_profile_aliases() or []
    rows = []
    for entry in aliases:
        if not isinstance(entry, dict):
            continue
        rows.append({
            "alias": str(entry.get("alias", "")).strip(),
            "aid": str(entry.get("aid", "")).strip(),
        })
    return {
        "count": len(rows),
        "rows": rows,
        "headers": ["alias", "aid"],
    }


def _dispatch_get_eim_config(ctx: ActionContext) -> dict[str, Any]:
    session = _build_eim_session()
    trace_sink = io.StringIO()
    raw_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            raw = session.get_eim_configuration_data()
        raw_hex = bytes(raw or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "raw_hex": raw_hex,
        "length": len(raw_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else "BF55 fetched.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_counters(ctx: ActionContext) -> dict[str, Any]:
    session = _build_eim_session()
    runtime = session.runtime_state_summary() or {}
    counter_map = runtime.get("counter_by_eim_id", {}) or {}
    rows: list[dict[str, Any]] = []
    if isinstance(counter_map, dict):
        for eim_id in sorted(counter_map.keys()):
            rows.append({"eim_id": str(eim_id), "next": counter_map.get(eim_id)})
    return {
        "count": len(rows),
        "rows": rows,
        "headers": ["eim_id", "next"],
    }


def _dispatch_handover_status(ctx: ActionContext) -> dict[str, Any]:
    session = _build_eim_session()
    payload = session.handover_context() or {}
    scrubbed = _scrub_bytes(payload) if isinstance(payload, dict) else {}
    lines = [
        {"label": "transactionId", "value": str(scrubbed.get("transaction_id_hex", "-") or "-")},
        {"label": "matchingId", "value": str(scrubbed.get("matching_id", "-") or "-")},
        {"label": "profile_path", "value": str(scrubbed.get("profile_path", "-") or "-")},
        {"label": "policy", "value": str(scrubbed.get("notification_policy", "-") or "-")},
        {"label": "source", "value": str(scrubbed.get("source", "-") or "-")},
    ]
    return {
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": 0,
        "handover": scrubbed,
    }


def _dispatch_eim_package_lint(
    ctx: ActionContext,
    *,
    package_path: Any = None,
    strict_executable: Any = None,
) -> dict[str, Any]:
    session = _build_eim_session()
    strict_b = bool(strict_executable)
    path_s = str(package_path or "").strip()
    trace_sink = io.StringIO()
    report: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            report = session.lint_eim_package(
                package_path=path_s,
                strict_executable=strict_b,
            ) or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    scrubbed = _scrub_bytes(report) if isinstance(report, dict) else {}
    errors_list = scrubbed.get("errors") or []
    return {
        "ok": len(note_parts) == 0 and (
            len(errors_list) == 0 if isinstance(errors_list, list) else True
        ),
        "report": scrubbed,
        "errors": errors_list if isinstance(errors_list, list) else [],
        "note": "; ".join(note_parts) if note_parts else (
            f"lint errors: {len(errors_list)}" if isinstance(errors_list, list) else "lint done"
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_eim_certs_inventory(
    ctx: ActionContext,
    *,
    package_path: Any = None,
    cert_path: Any = None,
) -> dict[str, Any]:
    session = _build_eim_session()
    path_s = str(package_path or "").strip()
    cert_s = str(cert_path or "").strip()
    trace_sink = io.StringIO()
    payload: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            payload = session.list_eim_certificate_inventory(
                package_path=path_s,
                cert_path=cert_s,
            ) or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    scrubbed = _scrub_bytes(payload) if isinstance(payload, dict) else {}
    rows = scrubbed.get("rows") or []
    return {
        "ok": len(note_parts) == 0,
        "count": int(scrubbed.get("count", len(rows)) or 0),
        "selected": scrubbed.get("selected") or {},
        "rows": rows if isinstance(rows, list) else [],
        "card_allowed_ci_pkids": scrubbed.get("card_allowed_ci_pkids", []),
        "inventory": scrubbed,
        "note": "; ".join(note_parts) if note_parts else "inventory enumerated.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_hotfolder_list(
    ctx: ActionContext,
    *,
    hotfolder_dir: Any = None,
) -> dict[str, Any]:
    session = _build_eim_session()
    dir_s = str(hotfolder_dir or "").strip()
    trace_sink = io.StringIO()
    files: list[str] = []
    resolved_dir = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            files = session.list_hotfolder_package_files(hotfolder_dir=dir_s) or []
            resolved_dir = session.resolve_hotfolder_path(override_path=dir_s)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    rows = [{"index": index, "path": path} for index, path in enumerate(files or [], start=1)]
    return {
        "ok": len(note_parts) == 0,
        "hotfolder_dir": resolved_dir,
        "count": len(rows),
        "rows": rows,
        "headers": ["index", "path"],
        "note": "; ".join(note_parts) if note_parts else f"{len(rows)} file(s) in hotfolder.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_error_codes(
    ctx: ActionContext,
    *,
    family: Any = None,
) -> dict[str, Any]:
    """Return the SGP.02 / SGP.22 / SGP.32 error-code vocabulary as rows."""
    target = str(family or "ALL").strip().upper().replace(".", "").replace("_", "")
    if len(target) == 0:
        target = "ALL"
    try:
        from SCP11.shared.gsma_error_codes import (
            SGP22_DOWNLOAD_ERROR_CODE,
            SGP22_ES10B_PROFILE_STATE_RESULT,
            SGP22_PROFILE_INSTALLATION_RESULT_REASON,
            SGP32_EIM_PACKAGE_ERROR,
            SGP32_EIM_PACKAGE_RESULT_ERROR,
            SGP32_PROFILE_DOWNLOAD_ERROR_REASON,
        )
    except ImportError as error:
        return {
            "ok": False,
            "note": f"error-code vocabulary unavailable: {error}",
            "tables": [],
        }

    tables: list[tuple[str, dict[int, str]]] = []
    if target in ("ALL", "SGP22"):
        tables.append(("SGP.22 DownloadErrorCode", SGP22_DOWNLOAD_ERROR_CODE))
        tables.append(("SGP.22 ES10b ProfileState Result", SGP22_ES10B_PROFILE_STATE_RESULT))
        tables.append(
            ("SGP.22 ProfileInstallationResultErrorReason", SGP22_PROFILE_INSTALLATION_RESULT_REASON),
        )
    if target in ("ALL", "SGP32"):
        tables.append(("SGP.32 GetEimPackage eimPackageError", SGP32_EIM_PACKAGE_ERROR))
        tables.append(
            ("SGP.32 ProvideEimPackageResult eimPackageResultErrorCode", SGP32_EIM_PACKAGE_RESULT_ERROR),
        )
        tables.append(
            ("SGP.32 ProfileDownloadTriggerResult profileDownloadErrorReason", SGP32_PROFILE_DOWNLOAD_ERROR_REASON),
        )
    if target in ("ALL", "SGP02"):
        tables.append(
            ("SGP.02 mapped to profile installation semantics", SGP22_PROFILE_INSTALLATION_RESULT_REASON),
        )

    if len(tables) == 0:
        raise ValueError("family must be one of: SGP.02, SGP.22, SGP.32, ALL.")

    rendered_tables: list[dict[str, Any]] = []
    for title, mapping in tables:
        rows: list[dict[str, Any]] = []
        for code in sorted(mapping.keys()):
            rows.append({"code": int(code), "name": str(mapping.get(code, "unknown"))})
        rendered_tables.append({"title": title, "rows": rows})
    return {
        "ok": True,
        "family": target,
        "tables": rendered_tables,
    }


# ----------------------------------------------------------------------
# Card-touching mutation dispatchers
# ----------------------------------------------------------------------


def _dispatch_enable_profile(
    ctx: ActionContext,
    *,
    identifier: Any = None,
) -> dict[str, Any]:
    return _run_profile_mutation(
        identifier=identifier,
        action="enable_profile",
        label="EnableProfile",
    )


def _dispatch_disable_profile(
    ctx: ActionContext,
    *,
    identifier: Any = None,
) -> dict[str, Any]:
    return _run_profile_mutation(
        identifier=identifier,
        action="disable_profile",
        label="DisableProfile",
    )


def _dispatch_delete_profile(
    ctx: ActionContext,
    *,
    identifier: Any = None,
) -> dict[str, Any]:
    return _run_profile_mutation(
        identifier=identifier,
        action="delete_profile",
        label="DeleteProfile",
    )


def _run_profile_mutation(
    identifier: Any,
    action: str,
    label: str,
) -> dict[str, Any]:
    ident_s = str(identifier or "").strip()
    if len(ident_s) == 0:
        raise ValueError("identifier is required (iccid, aid or alias).")
    session = _build_eim_session()
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        method = getattr(session, action)
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            response = method(ident_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "action": action,
        "identifier": ident_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else f"{label} completed ({len(response_hex) // 2} bytes).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_store_metadata(
    ctx: ActionContext,
    *,
    metadata_path: Any = None,
) -> dict[str, Any]:
    session = _build_eim_session()
    path_s = str(metadata_path or "").strip()
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            response = session.store_metadata(metadata_path=path_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "metadata_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else f"StoreMetadata completed ({len(response_hex) // 2} bytes).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_update_metadata(
    ctx: ActionContext,
    *,
    metadata_path: Any = None,
) -> dict[str, Any]:
    session = _build_eim_session()
    path_s = str(metadata_path or "").strip()
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            response = session.update_metadata(metadata_path=path_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "metadata_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else f"UpdateMetadata completed ({len(response_hex) // 2} bytes).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_delete_eim(
    ctx: ActionContext,
    *,
    eim_id: Any = None,
) -> dict[str, Any]:
    eim_s = str(eim_id or "").strip()
    if len(eim_s) == 0:
        raise ValueError("eim_id is required.")
    session = _build_eim_session()
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            response = session.delete_eim(eim_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "eim_id": eim_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else f"DeleteEim completed ({len(response_hex) // 2} bytes).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_euicc_memory_reset(
    ctx: ActionContext,
    *,
    package_path: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    if bool(confirm) is False:
        raise ValueError("confirm must be true — eUICC memory reset is destructive.")
    session = _build_eim_session()
    path_s = str(package_path or "").strip()
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            response = session.euicc_memory_reset(package_path=path_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "package_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else "eUICC memory reset dispatched.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_eim_package_issue(
    ctx: ActionContext,
    *,
    package_path: Any = None,
) -> dict[str, Any]:
    session = _build_eim_session()
    path_s = str(package_path or "").strip()
    trace_sink = io.StringIO()
    package_file = ""
    package_type = ""
    result_len = 0
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            package_file, package_type, result_len = session.issue_eim_package_file(package_path=path_s)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0 and int(result_len or 0) >= 0,
        "package_path": str(package_file),
        "package_type": str(package_type),
        "result_len": int(result_len or 0),
        "note": "; ".join(note_parts) if note_parts else f"Issued {package_type} package ({result_len} bytes).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


# ----------------------------------------------------------------------
# Additional dispatchers (scan, explain_last, resp_log, resp_log_filter,
# counter, load_profile, refresh_modem, isdr_*, add_eim, add_initial_eim,
# eim_package_explain, eim_package_issue_all, load_eim_package,
# eim_acknowledge, poll_export, poll_aggregate, handover_set,
# hotfolder_poll, hotfolder_fetch, notif_hygiene)
# ----------------------------------------------------------------------


def _dispatch_scan(ctx: ActionContext) -> dict[str, Any]:
    session = _build_eim_session()
    trace_sink = io.StringIO()
    note_parts: list[str] = []
    snapshot: dict[str, Any] = {}
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            snapshot = session.collect_quick_overview() or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    scrubbed = _scrub_bytes(snapshot) if isinstance(snapshot, dict) else {}
    eid_value = str(scrubbed.get("eid", "") or "").strip()
    profiles = scrubbed.get("profiles") or []
    return {
        "ok": len(note_parts) == 0,
        "eid": eid_value,
        "profile_count": len(profiles) if isinstance(profiles, list) else 0,
        "snapshot": scrubbed,
        "note": "; ".join(note_parts) if note_parts else (
            f"scan complete — EID={eid_value or '-'}"
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_explain_last(ctx: ActionContext) -> dict[str, Any]:
    session = _build_eim_session()
    st = session.state
    eim_st = session.eim_state

    lines: list[dict[str, str]] = []
    lines.append({"label": "Session open", "value": "yes" if st.session_open else "no"})
    lines.append({"label": "ISD-R selected", "value": "yes" if st.isdr_selected else "no"})
    txid = st.transaction_id.hex().upper() if len(st.transaction_id) > 0 else "-"
    lines.append({"label": "Transaction id", "value": txid})
    lines.append({"label": "BIP routing", "value": str(eim_st.bip_routing_mode or "-")})
    lines.append({"label": "BIP role", "value": str(eim_st.current_bip_role or "-")})
    lines.append({"label": "BIP endpoint", "value": str(eim_st.current_bip_endpoint or "-")})
    last_cmd = getattr(st, "last_command", "")
    lines.append({"label": "Last command", "value": str(last_cmd) if last_cmd else "-"})
    last_apdu = getattr(st, "last_apdu_hex", "")
    lines.append({"label": "Last APDU", "value": str(last_apdu) if last_apdu else "-"})
    last_resp = getattr(st, "last_response_hex", "")
    lines.append({"label": "Last response", "value": str(last_resp) if last_resp else "-"})
    last_error = getattr(st, "last_error", "")
    lines.append({"label": "Last error", "value": str(last_error) if last_error else "none"})
    lines.append({"label": "Package override", "value": str(eim_st.eim_package_override_path or "-")})
    lines.append({"label": "Hotfolder override", "value": str(eim_st.hotfolder_override_path or "-")})
    pending = session.pending_operations()
    lines.append({"label": "Pending ops", "value": str(len(pending))})

    return {
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": 0,
        "ok": True,
        "note": "last-command context captured.",
    }


def _dispatch_resp_log(
    ctx: ActionContext,
    *,
    max_entries: Any = None,
) -> dict[str, Any]:
    limit = int(max_entries) if max_entries is not None else 25
    session = _build_eim_session()
    entries = session.read_response_log(limit=limit) or []
    return {
        "count": len(entries),
        "limit": limit,
        "entries": _scrub_bytes(entries),
        "ok": True,
        "note": f"{len(entries)} response log entr{'y' if len(entries) == 1 else 'ies'}.",
    }


def _dispatch_resp_log_filter(
    ctx: ActionContext,
    *,
    pattern: Any = None,
    max_entries: Any = None,
) -> dict[str, Any]:
    query = str(pattern or "").strip()
    if len(query) == 0:
        raise ValueError("pattern is required.")
    limit = int(max_entries) if max_entries is not None else 50
    session = _build_eim_session()
    entries = session.filter_response_log(query=query, limit=limit) or []
    return {
        "count": len(entries),
        "query": query,
        "limit": limit,
        "entries": _scrub_bytes(entries),
        "ok": True,
        "note": f"{len(entries)} matching entr{'y' if len(entries) == 1 else 'ies'} for {query!r}.",
    }


def _dispatch_counter(
    ctx: ActionContext,
    *,
    eim_id: Any = None,
    new_value: Any = None,
) -> dict[str, Any]:
    eim_s = str(eim_id or "").strip()
    session = _build_eim_session()
    if new_value is not None:
        val = int(new_value)
        resolved_id, actual = session.set_counter_value(eim_id=eim_s, next_value=val)
        return {
            "eim_id": resolved_id,
            "next_value": actual,
            "set": True,
            "ok": True,
            "note": f"Counter for {resolved_id} set to {actual}.",
        }
    resolved_id, actual = session.get_counter_value(eim_id=eim_s)
    return {
        "eim_id": resolved_id,
        "next_value": actual,
        "set": False,
        "ok": True,
        "note": f"Counter for {resolved_id} = {actual}.",
    }


def _dispatch_eim_load_profile(
    ctx: ActionContext,
    *,
    identifier: Any = None,
    profile_path: Any = None,
) -> dict[str, Any]:
    ident_s = str(identifier or "").strip()
    path_s = str(profile_path or "").strip()
    session = _build_eim_session()
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            if len(path_s) > 0:
                session.state.last_profile_path = path_s
            if len(ident_s) > 0:
                response = session.load_profile(profile_path=path_s)
            else:
                response = session.run_load_profile_chain(profile_path=path_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "identifier": ident_s,
        "profile_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else f"LoadProfile completed ({len(response_hex) // 2} bytes).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_eim_refresh_modem(
    ctx: ActionContext,
    *,
    mode: Any = None,
) -> dict[str, Any]:
    mode_s = str(mode or "").strip()
    from yggdrasim_common.card_backend import trigger_card_relay_modem_refresh

    trigger_card_relay_modem_refresh(mode=mode_s if len(mode_s) > 0 else None)
    return {
        "mode": mode_s if len(mode_s) > 0 else "(default)",
        "ok": True,
        "note": "Modem refresh queued.",
    }


def _dispatch_isdr_get_eim_config(ctx: ActionContext) -> dict[str, Any]:
    session = _build_eim_session()
    trace_sink = io.StringIO()
    raw_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            session.select_isdr()
            raw = session.get_eim_configuration_data()
        raw_hex = bytes(raw or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "raw_hex": raw_hex,
        "length": len(raw_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else "BF55 fetched via ISD-R path.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_isdr_delete_eim(
    ctx: ActionContext,
    *,
    eim_id: Any = None,
) -> dict[str, Any]:
    eim_s = str(eim_id or "").strip()
    if len(eim_s) == 0:
        raise ValueError("eim_id is required.")
    session = _build_eim_session()
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            session.select_isdr()
            response = session.delete_eim(eim_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "eim_id": eim_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else f"ISD-R DeleteEim completed ({len(response_hex) // 2} bytes).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_isdr_add_eim(
    ctx: ActionContext,
    *,
    package_path: Any = None,
    initial: bool = False,
) -> dict[str, Any]:
    path_s = str(package_path or "").strip()
    session = _build_eim_session()
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            session.select_isdr()
            response = session.add_eim(
                package_path=path_s,
                source_mode="isdr",
            )
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    kind = "ISD-R AddInitialEim" if initial else "ISD-R AddEim"
    return {
        "ok": len(note_parts) == 0,
        "kind": kind,
        "package_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else f"{kind} completed ({len(response_hex) // 2} bytes).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_add_eim(
    ctx: ActionContext,
    *,
    package_path: Any = None,
    initial: bool = False,
) -> dict[str, Any]:
    path_s = str(package_path or "").strip()
    session = _build_eim_session()
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            if initial:
                response = session.add_initial_eim(package_path=path_s, source_mode="package")
            else:
                response = session.add_eim(package_path=path_s, source_mode="package")
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    kind = "AddInitialEim" if initial else "AddEim"
    return {
        "ok": len(note_parts) == 0,
        "kind": kind,
        "package_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else f"{kind} completed ({len(response_hex) // 2} bytes).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_eim_package_explain(
    ctx: ActionContext,
    *,
    package_path: Any = None,
) -> dict[str, Any]:
    path_s = str(package_path or "").strip()
    session = _build_eim_session()
    trace_sink = io.StringIO()
    payload: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            from SCP11.eim_local.eim_package_codec import EimPackageDocument

            doc = EimPackageDocument.load(path=path_s) if len(path_s) > 0 else EimPackageDocument.load()
            payload = {
                "package_path": str(doc.path),
                "package_type": str(doc.package_type or ""),
                "package_id": str(doc.package_id or ""),
                "eim_id": str(doc.eim_id or ""),
                "title": str(doc.title or ""),
                "version": str(doc.version or ""),
                "operations": len(doc.operations or []),
                "model_only": bool(doc.model_only),
                "metadata_present": doc.metadata is not None,
            }
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "explain": _scrub_bytes(payload),
        "note": "; ".join(note_parts) if note_parts else (
            f"package explained: {payload.get('package_type', '-')}"
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_eim_package_issue_all(
    ctx: ActionContext,
    *,
    package_dir: Any = None,
) -> dict[str, Any]:
    dir_s = str(package_dir or "").strip()
    session = _build_eim_session()
    trace_sink = io.StringIO()
    results: list[tuple[str, str, int]] = []
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            results = session.issue_all_eim_package_files(package_dir=dir_s)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    rows = [
        {"file": str(f), "type": str(t), "result_len": int(l)}
        for f, t, l in results
    ]
    return {
        "ok": len(note_parts) == 0,
        "package_dir": dir_s,
        "rows": rows,
        "count": len(rows),
        "note": "; ".join(note_parts) if note_parts else f"{len(rows)} package(s) issued.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_load_eim_package(
    ctx: ActionContext,
    *,
    package_path: Any = None,
) -> dict[str, Any]:
    path_s = str(package_path or "").strip()
    if len(path_s) == 0:
        raise ValueError("package_path is required.")
    session = _build_eim_session()
    trace_sink = io.StringIO()
    report: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            report = session.load_eim_package_to_isdr(package_path=path_s) or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "package_path": path_s,
        "report": _scrub_bytes(report),
        "note": "; ".join(note_parts) if note_parts else (
            f"eIM package loaded: {report.get('package_type', '-')}"
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_eim_acknowledge(
    ctx: ActionContext,
    *,
    transaction_id_hex: Any = None,
    matching_id: Any = None,
) -> dict[str, Any]:
    txid = str(transaction_id_hex or "").strip()
    mid = str(matching_id or "").strip()
    session = _build_eim_session()
    closed = session.acknowledge_eim_operations(
        transaction_id_hex=txid,
        matching_id=mid,
    )
    return {
        "ok": True,
        "closed_operations": closed,
        "transaction_id_hex": txid,
        "matching_id": mid,
        "note": f"{closed} pending operation(s) acknowledged.",
    }


def _dispatch_poll_export(
    ctx: ActionContext,
    *,
    output_path: Any = None,
) -> dict[str, Any]:
    path_s = str(output_path or "").strip()
    session = _build_eim_session()
    trace_sink = io.StringIO()
    note_parts: list[str] = []
    exported = ""
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            campaign = session.poll_hotfolder_campaign(cycles=1, interval_ms=0)
            exported = session.export_campaign_report(campaign, output_path=path_s)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "output_path": exported,
        "note": "; ".join(note_parts) if note_parts else f"Campaign report exported to {exported}.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_poll_aggregate(
    ctx: ActionContext,
    *,
    campaign_dirs: Any = None,
) -> dict[str, Any]:
    dir_s = str(campaign_dirs or "").strip()
    session = _build_eim_session()
    trace_sink = io.StringIO()
    note_parts: list[str] = []
    aggregated: dict[str, Any] = {}
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            aggregated = session.aggregate_campaign_reports(reports_dir=dir_s) or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "aggregated": _scrub_bytes(aggregated),
        "note": "; ".join(note_parts) if note_parts else (
            f"Aggregated {aggregated.get('report_count', 0)} report(s)."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_handover_set(
    ctx: ActionContext,
    *,
    matching_id: Any = None,
    transaction_id: Any = None,
) -> dict[str, Any]:
    mid = str(matching_id or "").strip()
    txid = str(transaction_id or "").strip()
    if len(mid) == 0:
        raise ValueError("matching_id is required.")
    session = _build_eim_session()
    ctx = session.set_handover_transaction(
        transaction_id_hex=txid if len(txid) > 0 else "00" * 16,
        matching_id=mid,
    )
    return {
        "ok": True,
        "matching_id": mid,
        "transaction_id_hex": txid if len(txid) > 0 else "00" * 16,
        "handover": _scrub_bytes({
            "transaction_id_hex": ctx.transaction_id_hex if hasattr(ctx, "transaction_id_hex") else txid,
            "matching_id": ctx.matching_id if hasattr(ctx, "matching_id") else mid,
        }),
        "note": f"Handover seeded with matchingId={mid}.",
    }


def _dispatch_hotfolder_poll(
    ctx: ActionContext,
    *,
    hotfolder_dir: Any = None,
) -> dict[str, Any]:
    dir_s = str(hotfolder_dir or "").strip()
    session = _build_eim_session()
    trace_sink = io.StringIO()
    note_parts: list[str] = []
    rows: list[dict[str, Any]] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            rows = session.poll_hotfolder(cycles=1, interval_ms=500, hotfolder_dir=dir_s) or []
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "hotfolder_dir": session.resolve_hotfolder_path(override_path=dir_s),
        "rows": _scrub_bytes(rows),
        "count": len(rows),
        "note": "; ".join(note_parts) if note_parts else f"{len(rows)} cycle(s) polled.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_hotfolder_fetch(
    ctx: ActionContext,
    *,
    hotfolder_dir: Any = None,
) -> dict[str, Any]:
    dir_s = str(hotfolder_dir or "").strip()
    session = _build_eim_session()
    trace_sink = io.StringIO()
    note_parts: list[str] = []
    meta: dict[str, Any] = {}
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            meta = session.hotfolder_poll_response_meta(hotfolder_dir=dir_s) or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "hotfolder_dir": session.resolve_hotfolder_path(override_path=dir_s),
        "meta": _scrub_bytes(meta),
        "note": "; ".join(note_parts) if note_parts else "Hotfolder fetch metadata captured.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_notif_hygiene(
    ctx: ActionContext,
    *,
    drain: Any = None,
) -> dict[str, Any]:
    drain_b = bool(drain)
    session = _build_eim_session()
    try:
        pending = session.enforce_notification_hygiene()
        extra = ""
        if drain_b:
            session.clear_notifications()
            extra = " Notifications drained."
        return {
            "ok": True,
            "pending_count": pending,
            "drained": drain_b,
            "note": f"{pending} pending notification(s).{extra}",
        }
    except RuntimeError as error:
        return {
            "ok": False,
            "pending_count": -1,
            "drained": drain_b,
            "note": str(error),
        }


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


STATUS_SPEC = ActionSpec(
    id="eim_local.status",
    subsystem="Local eIM",
    title="Status snapshot",
    description=(
        "Report the eIM-local runtime state: session / ISD-R flags, BIP "
        "role + endpoint, eIM identity (id, FQDN, endpoint, SM-DP+), "
        "pending operations, tracked counters, and the handover context."
    ),
    inputs=(),
    output_kind="key_value_lines",
    dispatcher=_dispatch_status,
    requires_card=False,
    tags=("eim", "status"),
)


DISCOVER_SPEC = ActionSpec(
    id="eim_local.discover",
    subsystem="Local eIM",
    title="Discover card",
    description=(
        "Run the local ISD-R discovery probe: EID, configured SM-DP+/SM-DS, "
        "profile inventory, and ECASD certificates. Touches the card via "
        "the configured PC/SC reader."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_discover,
    requires_card=True,
    tags=("eim", "discover", "read-only"),
)


LIST_PROFILE_ALIASES_SPEC = ActionSpec(
    id="eim_local.list_profile_aliases",
    subsystem="Local eIM",
    title="List profile aliases",
    description=(
        "Enumerate the AID-registry profile aliases so operators know "
        "which alias / ICCID / AID to feed into enable / disable / delete."
    ),
    inputs=(),
    output_kind="table",
    dispatcher=_dispatch_list_profile_aliases,
    requires_card=False,
    tags=("eim", "profiles", "aliases"),
)


GET_EIM_CONFIG_SPEC = ActionSpec(
    id="eim_local.get_eim_config",
    subsystem="Local eIM",
    title="Get eIM configuration data (BF55)",
    description=(
        "Run GetEimConfigurationData via the local ISD-R and return the "
        "raw hex response. Useful for verifying that ADD-EIM wrote the "
        "expected identity + signing certificate."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_get_eim_config,
    requires_card=True,
    tags=("eim", "config", "read"),
)


COUNTERS_SPEC = ActionSpec(
    id="eim_local.counters",
    subsystem="Local eIM",
    title="Counter inventory",
    description=(
        "List every tracked eIM counter (next-value per eim_id) from the "
        "runtime state store. Pure file-system read."
    ),
    inputs=(),
    output_kind="table",
    dispatcher=_dispatch_counters,
    requires_card=False,
    tags=("eim", "counters"),
)


HANDOVER_STATUS_SPEC = ActionSpec(
    id="eim_local.handover_status",
    subsystem="Local eIM",
    title="Handover status",
    description=(
        "Surface the current handover context (transactionId, matchingId, "
        "profile path, notification policy, source) as key/value rows."
    ),
    inputs=(),
    output_kind="key_value_lines",
    dispatcher=_dispatch_handover_status,
    requires_card=False,
    tags=("eim", "handover"),
)


EIM_PACKAGE_LINT_SPEC = ActionSpec(
    id="eim_local.eim_package_lint",
    subsystem="Local eIM",
    title="Lint eIM package",
    description=(
        "Validate an eIM package document: structural lint + optional "
        "strict-executable mode that flags model-only packages when the "
        "runtime is not in allow_model_only / mock_mode."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=False,
            placeholder="(leave blank for the configured default)",
            help="Path to the eIM package JSON. Relative paths resolve against the EIM_PACKAGES_DIR.",
        ),
        ActionField(
            name="strict_executable",
            label="Strict executable",
            kind="bool",
            required=False,
            default=False,
            help="Fail when the package is model-only and the runtime is not model-tolerant.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_eim_package_lint,
    requires_card=False,
    tags=("eim", "package", "lint"),
)


EIM_CERTS_INVENTORY_SPEC = ActionSpec(
    id="eim_local.eim_certs_inventory",
    subsystem="Local eIM",
    title="eIM certificate inventory",
    description=(
        "Enumerate candidate eIM signing certificates and the currently "
        "selected pair (package + certificate). Pure filesystem read."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=False,
            help="Optional package path to bias the preferred CI PKID selection.",
        ),
        ActionField(
            name="cert_path",
            label="Override cert path",
            kind="path",
            required=False,
            help="Optional explicit certificate path to evaluate.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_eim_certs_inventory,
    requires_card=False,
    tags=("eim", "certs", "inventory"),
)


HOTFOLDER_LIST_SPEC = ActionSpec(
    id="eim_local.hotfolder_list",
    subsystem="Local eIM",
    title="List hotfolder files",
    description=(
        "Enumerate every eIM package file present in the hotfolder "
        "directory, ordered by the session's queue-sort rules."
    ),
    inputs=(
        ActionField(
            name="hotfolder_dir",
            label="Hotfolder directory",
            kind="directory",
            required=False,
            placeholder="(leave blank for default)",
            help="Directory to enumerate; leave blank for the configured default.",
        ),
    ),
    output_kind="table",
    dispatcher=_dispatch_hotfolder_list,
    requires_card=False,
    tags=("eim", "hotfolder", "list"),
)


ERROR_CODES_SPEC = ActionSpec(
    id="eim_local.error_codes",
    subsystem="Local eIM",
    title="Error code reference",
    description=(
        "Render the SGP.02 / SGP.22 / SGP.32 error-code vocabulary as "
        "grouped tables. Pure reference data — no card or file access."
    ),
    inputs=(
        ActionField(
            name="family",
            label="Family",
            kind="enum",
            required=False,
            default="ALL",
            choices=["ALL", "SGP.02", "SGP.22", "SGP.32"],
            help="Restrict to a single family or keep ALL for the full set.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_error_codes,
    requires_card=False,
    tags=("eim", "error-codes", "reference"),
)


ENABLE_PROFILE_SPEC = ActionSpec(
    id="eim_local.enable_profile",
    subsystem="Local eIM",
    title="Enable profile",
    description=(
        "Run EnableProfile against the local ISD-R using the ICCID, AID, "
        "or alias you supply. Mirrors the shell's ENABLE-PROFILE command."
    ),
    inputs=(
        ActionField(
            name="identifier",
            label="ICCID / AID / alias",
            kind="string",
            required=True,
            placeholder="89014104… or A0000005591010FFFFFFFF8900001100 or mnoA",
            help="Target profile; accepts iccid digits, hex AID, or alias from LIST.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_enable_profile,
    requires_card=True,
    tags=("eim", "profile", "enable"),
)


DISABLE_PROFILE_SPEC = ActionSpec(
    id="eim_local.disable_profile",
    subsystem="Local eIM",
    title="Disable profile",
    description="Run DisableProfile against the local ISD-R.",
    inputs=(
        ActionField(
            name="identifier",
            label="ICCID / AID / alias",
            kind="string",
            required=True,
            help="Target profile; accepts iccid digits, hex AID, or alias.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_disable_profile,
    requires_card=True,
    tags=("eim", "profile", "disable"),
)


DELETE_PROFILE_SPEC = ActionSpec(
    id="eim_local.delete_profile",
    subsystem="Local eIM",
    title="Delete profile",
    description="Run DeleteProfile against the local ISD-R (destructive).",
    inputs=(
        ActionField(
            name="identifier",
            label="ICCID / AID / alias",
            kind="string",
            required=True,
            help="Target profile; accepts iccid digits, hex AID, or alias.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_delete_profile,
    requires_card=True,
    tags=("eim", "profile", "delete", "destructive"),
)


STORE_METADATA_SPEC = ActionSpec(
    id="eim_local.store_metadata",
    subsystem="Local eIM",
    title="Store metadata",
    description=(
        "Push StoreMetadata to the card from an eIM metadata JSON. Leave "
        "the path blank to use the session's configured default."
    ),
    inputs=(
        ActionField(
            name="metadata_path",
            label="Metadata path",
            kind="path",
            required=False,
            help="Path to the metadata JSON; leave blank for the configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_store_metadata,
    requires_card=True,
    tags=("eim", "metadata", "store"),
)


UPDATE_METADATA_SPEC = ActionSpec(
    id="eim_local.update_metadata",
    subsystem="Local eIM",
    title="Update metadata",
    description=(
        "Push UpdateMetadata to the card. Same input rules as StoreMetadata, "
        "but encodes via the update-metadata payload shape."
    ),
    inputs=(
        ActionField(
            name="metadata_path",
            label="Metadata path",
            kind="path",
            required=False,
            help="Path to the metadata JSON; leave blank for the configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_update_metadata,
    requires_card=True,
    tags=("eim", "metadata", "update"),
)


DELETE_EIM_SPEC = ActionSpec(
    id="eim_local.delete_eim",
    subsystem="Local eIM",
    title="Delete eIM",
    description="Issue DeleteEim for a given eim_id via the local ISD-R.",
    inputs=(
        ActionField(
            name="eim_id",
            label="eIM id",
            kind="string",
            required=True,
            help="eIM identifier to delete from the card.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_delete_eim,
    requires_card=True,
    tags=("eim", "delete", "destructive"),
)


EUICC_MEMORY_RESET_SPEC = ActionSpec(
    id="eim_local.euicc_memory_reset",
    subsystem="Local eIM",
    title="eUICC memory reset",
    description=(
        "Issue eUICCMemoryReset using the current eIM package's reset "
        "request / options. Destructive — requires confirm=true."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=False,
            help="Optional path to the eIM package document carrying the reset options.",
        ),
        ActionField(
            name="confirm",
            label="I understand this is destructive",
            kind="bool",
            required=True,
            default=False,
            help="Must be true to proceed.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_euicc_memory_reset,
    requires_card=True,
    tags=("eim", "memory-reset", "destructive"),
)


EIM_PACKAGE_ISSUE_SPEC = ActionSpec(
    id="eim_local.eim_package_issue",
    subsystem="Local eIM",
    title="Issue eIM package file",
    description=(
        "Dispatch a specific eIM package file through the session's issue "
        "pipeline and report (file, type, response length)."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=False,
            help="Path to the eIM package file; leave blank for the configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_eim_package_issue,
    requires_card=True,
    tags=("eim", "package", "issue"),
)

SCAN_SPEC = ActionSpec(
    id="eim_local.scan",
    subsystem="Local eIM",
    title="Scan card (quick overview)",
    description=(
        "Lightweight card overview: EID, profile count, and configured "
        "data summary. Touches the card to read the ISD-R snapshot."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_scan,
    requires_card=True,
    tags=("eim", "scan", "read-only"),
)

EXPLAIN_LAST_SPEC = ActionSpec(
    id="eim_local.explain_last",
    subsystem="Local eIM",
    title="Explain last command",
    description=(
        "Surface the context of the last command: session flags, BIP "
        "state, last APDU/response/error, package/hotfolder overrides, "
        "and pending operation count."
    ),
    inputs=(),
    output_kind="key_value_lines",
    dispatcher=_dispatch_explain_last,
    requires_card=False,
    tags=("eim", "debug"),
)

RESP_LOG_SPEC = ActionSpec(
    id="eim_local.resp_log",
    subsystem="Local eIM",
    title="Response log",
    description=(
        "Read the most recent entries from the eIM response log (ES25 "
        "response-meta history)."
    ),
    inputs=(
        ActionField(
            name="max_entries",
            label="Max entries",
            kind="int",
            required=False,
            default=25,
            min_value=1,
            help="Number of recent entries to return.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_resp_log,
    requires_card=False,
    tags=("eim", "response-log"),
)

RESP_LOG_FILTER_SPEC = ActionSpec(
    id="eim_local.resp_log_filter",
    subsystem="Local eIM",
    title="Filter response log",
    description=(
        "Search the response log for entries matching a pattern "
        "(checked against transaction_id, matching_id, package_path, action)."
    ),
    inputs=(
        ActionField(
            name="pattern",
            label="Search pattern",
            kind="string",
            required=True,
            help="Case-insensitive substring match.",
        ),
        ActionField(
            name="max_entries",
            label="Max entries",
            kind="int",
            required=False,
            default=50,
            min_value=1,
            help="Maximum number of matches to return.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_resp_log_filter,
    requires_card=False,
    tags=("eim", "response-log"),
)

COUNTER_SPEC = ActionSpec(
    id="eim_local.counter",
    subsystem="Local eIM",
    title="Counter inspect / set",
    description=(
        "Inspect or override a single eIM counter by eIM ID. Leave "
        "new_value empty to read; provide an integer to set."
    ),
    inputs=(
        ActionField(
            name="eim_id",
            label="eIM ID",
            kind="string",
            required=False,
            help="eIM identifier; leave blank for the effective eIM.",
        ),
        ActionField(
            name="new_value",
            label="New value (optional)",
            kind="int",
            required=False,
            help="Provide an integer to override the counter.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_counter,
    requires_card=False,
    tags=("eim", "counters"),
)

LOAD_PROFILE_SPEC = ActionSpec(
    id="eim_local.load_profile",
    subsystem="Local eIM",
    title="Load profile",
    description=(
        "One-shot profile delivery: run PrepareDownload + LoadProfile "
        "against the local ISD-R. Provide a profile identifier (ICCID "
        "or AID) if the profile needs targeting."
    ),
    inputs=(
        ActionField(
            name="identifier",
            label="ICCID / AID (optional)",
            kind="string",
            required=False,
            help="Target profile identifier; leave blank for default.",
        ),
        ActionField(
            name="profile_path",
            label="Profile path (.bpp / .der / .hex)",
            kind="path",
            required=False,
            help="Path to the bound profile package; leave blank for configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_eim_load_profile,
    requires_card=True,
    tags=("eim", "profile", "load"),
)

REFRESH_MODEM_SPEC = ActionSpec(
    id="eim_local.refresh_modem",
    subsystem="Local eIM",
    title="Refresh modem",
    description=(
        "Queue a proactive REFRESH toward the modem so it re-reads the "
        "profile list after enable/disable/delete."
    ),
    inputs=(
        ActionField(
            name="mode",
            label="Refresh mode",
            kind="enum",
            required=False,
            default="",
            choices=["", "UICC_RESET", "SIM_INIT", "SIM_RESET", "USIM_RESET"],
            help="Leave empty for the default refresh mode.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_eim_refresh_modem,
    requires_card=False,
    tags=("eim", "modem", "refresh"),
)

ISDR_GET_EIM_CONFIG_SPEC = ActionSpec(
    id="eim_local.isdr_get_eim_config",
    subsystem="Local eIM",
    title="Get eIM config (ISD-R path)",
    description=(
        "Fetch BF55 eIM configuration data via the ISD-R select path "
        "(alternate to the ES10b GetEimConfigurationData command)."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_isdr_get_eim_config,
    requires_card=True,
    tags=("eim", "isdr", "config", "read"),
)

ISDR_DELETE_EIM_SPEC = ActionSpec(
    id="eim_local.isdr_delete_eim",
    subsystem="Local eIM",
    title="Delete eIM (ISD-R path)",
    description=(
        "Issue DeleteEim for a given eIM ID via the ISD-R select path. "
        "Destructive — removes the eIM registration from the card."
    ),
    inputs=(
        ActionField(
            name="eim_id",
            label="eIM ID",
            kind="string",
            required=True,
            help="eIM identifier to delete from the card.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_isdr_delete_eim,
    requires_card=True,
    tags=("eim", "isdr", "delete", "destructive"),
)

ISDR_ADD_EIM_SPEC = ActionSpec(
    id="eim_local.isdr_add_eim",
    subsystem="Local eIM",
    title="Add eIM (ISD-R path)",
    description=(
        "Install an eIM on the card via the ISD-R select path using "
        "ISD-R handshake mode."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=False,
            help="Path to the eIM package; leave blank for the configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=lambda ctx, **kw: _dispatch_isdr_add_eim(ctx, initial=False, **kw),
    requires_card=True,
    tags=("eim", "isdr", "add"),
)

ISDR_ADD_INITIAL_EIM_SPEC = ActionSpec(
    id="eim_local.isdr_add_initial_eim",
    subsystem="Local eIM",
    title="Add initial eIM (ISD-R path)",
    description=(
        "Install the initial eIM on a fresh card via the ISD-R select "
        "path using ISD-R handshake mode."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=False,
            help="Path to the eIM package; leave blank for the configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=lambda ctx, **kw: _dispatch_isdr_add_eim(ctx, initial=True, **kw),
    requires_card=True,
    tags=("eim", "isdr", "add-initial"),
)

ADD_EIM_SPEC = ActionSpec(
    id="eim_local.add_eim",
    subsystem="Local eIM",
    title="Add eIM (ES10b path)",
    description=(
        "Install an eIM on the card using the ES10b package delivery "
        "path. Uses the local session + package contents."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=False,
            help="Path to the eIM package; leave blank for the configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=lambda ctx, **kw: _dispatch_add_eim(ctx, initial=False, **kw),
    requires_card=True,
    tags=("eim", "add"),
)

ADD_INITIAL_EIM_SPEC = ActionSpec(
    id="eim_local.add_initial_eim",
    subsystem="Local eIM",
    title="Add initial eIM (ES10b path)",
    description=(
        "Install the initial eIM on a fresh card using the ES10b "
        "package delivery path."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=False,
            help="Path to the eIM package; leave blank for the configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=lambda ctx, **kw: _dispatch_add_eim(ctx, initial=True, **kw),
    requires_card=True,
    tags=("eim", "add-initial"),
)

EIM_PACKAGE_EXPLAIN_SPEC = ActionSpec(
    id="eim_local.eim_package_explain",
    subsystem="Local eIM",
    title="Explain eIM package",
    description=(
        "Load an eIM package document and surface its structure: "
        "package type, ID, eIM ID, title, version, operation count, "
        "and metadata presence."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=False,
            help="Path to the eIM package JSON; leave blank for the configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_eim_package_explain,
    requires_card=False,
    tags=("eim", "package", "explain"),
)

EIM_PACKAGE_ISSUE_ALL_SPEC = ActionSpec(
    id="eim_local.eim_package_issue_all",
    subsystem="Local eIM",
    title="Issue all eIM packages",
    description=(
        "Iterate every eIM package file in the configured directory "
        "and issue each one to the card. Error-tolerant — individual "
        "failures are recorded in the results."
    ),
    inputs=(
        ActionField(
            name="package_dir",
            label="Package directory",
            kind="directory",
            required=False,
            help="Directory containing eIM package JSON files; leave blank for default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_eim_package_issue_all,
    requires_card=True,
    tags=("eim", "package", "issue-all"),
)

LOAD_EIM_PACKAGE_SPEC = ActionSpec(
    id="eim_local.load_eim_package",
    subsystem="Local eIM",
    title="Load eIM package to card",
    description=(
        "Dispatches an eIM package directly to the card, routing to "
        "the correct handler based on package_type (add_initial_eim, "
        "add_eim, euicc_memory_reset, or general issue)."
    ),
    inputs=(
        ActionField(
            name="package_path",
            label="Package path",
            kind="path",
            required=True,
            help="Path to the eIM package JSON file.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_load_eim_package,
    requires_card=True,
    tags=("eim", "package", "load"),
)

EIM_ACKNOWLEDGE_SPEC = ActionSpec(
    id="eim_local.eim_acknowledge",
    subsystem="Local eIM",
    title="Acknowledge eIM operations",
    description=(
        "Sync pending notifications, enforce notification hygiene, "
        "and close pending eIM operations. Optionally scoped by "
        "transaction_id and matching_id."
    ),
    inputs=(
        ActionField(
            name="transaction_id_hex",
            label="Transaction ID (hex)",
            kind="hex",
            required=False,
            help="Hex transaction ID to scope; leave blank for all pending.",
        ),
        ActionField(
            name="matching_id",
            label="Matching ID",
            kind="string",
            required=False,
            help="Matching ID to scope; leave blank for all pending.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_eim_acknowledge,
    requires_card=False,
    tags=("eim", "acknowledge"),
)

POLL_EXPORT_SPEC = ActionSpec(
    id="eim_local.poll_export",
    subsystem="Local eIM",
    title="Export poll report",
    description=(
        "Run a single-cycle poll and export the campaign report to a "
        "JSON file for offline analysis."
    ),
    inputs=(
        ActionField(
            name="output_path",
            label="Output path",
            kind="save_path",
            required=False,
            help="Where to write the report JSON; defaults to an auto-named file.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_poll_export,
    requires_card=False,
    tags=("eim", "poll", "export"),
)

POLL_AGGREGATE_SPEC = ActionSpec(
    id="eim_local.poll_aggregate",
    subsystem="Local eIM",
    title="Aggregate poll reports",
    description=(
        "Scan a directory for campaign report files and aggregate them "
        "into a combined multi-campaign summary."
    ),
    inputs=(
        ActionField(
            name="campaign_dirs",
            label="Reports directory",
            kind="directory",
            required=False,
            help="Directory containing eim_poll_campaign_*.json files; leave blank for default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_poll_aggregate,
    requires_card=False,
    tags=("eim", "poll", "aggregate"),
)

HANDOVER_SET_SPEC = ActionSpec(
    id="eim_local.handover_set",
    subsystem="Local eIM",
    title="Set handover context",
    description=(
        "Manually seed the handover context with a matchingId and "
        "optional transactionId so that subsequent IPAe operations "
        "pick up the transfer state."
    ),
    inputs=(
        ActionField(
            name="matching_id",
            label="Matching ID",
            kind="string",
            required=True,
            help="Matching ID for the handover target.",
        ),
        ActionField(
            name="transaction_id",
            label="Transaction ID (hex)",
            kind="hex",
            required=False,
            help="Hex transaction ID; auto-generated if left empty.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_handover_set,
    requires_card=False,
    tags=("eim", "handover"),
)

HOTFOLDER_POLL_SPEC = ActionSpec(
    id="eim_local.hotfolder_poll",
    subsystem="Local eIM",
    title="Hotfolder poll (single cycle)",
    description=(
        "Run a single hotfolder poll cycle: check the queue, issue "
        "one package if available, and return the cycle result."
    ),
    inputs=(
        ActionField(
            name="hotfolder_dir",
            label="Hotfolder directory",
            kind="directory",
            required=False,
            help="Hotfolder directory; leave blank for default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_hotfolder_poll,
    requires_card=True,
    tags=("eim", "hotfolder", "poll"),
)

HOTFOLDER_FETCH_SPEC = ActionSpec(
    id="eim_local.hotfolder_fetch",
    subsystem="Local eIM",
    title="Hotfolder fetch (response meta)",
    description=(
        "Fetch the response metadata for the current hotfolder poll "
        "state without issuing a package. Useful for checking the "
        "initial ES25 response before committing to a cycle."
    ),
    inputs=(
        ActionField(
            name="hotfolder_dir",
            label="Hotfolder directory",
            kind="directory",
            required=False,
            help="Hotfolder directory; leave blank for default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_hotfolder_fetch,
    requires_card=False,
    tags=("eim", "hotfolder", "fetch"),
)

NOTIF_HYGIENE_SPEC = ActionSpec(
    id="eim_local.notif_hygiene",
    subsystem="Local eIM",
    title="Notification hygiene",
    description=(
        "Sync pending notifications and check the count against the "
        "configured threshold. Optionally drain the notification queue."
    ),
    inputs=(
        ActionField(
            name="drain",
            label="Drain notifications",
            kind="bool",
            required=False,
            default=False,
            help="Clear the notification queue after checking.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_notif_hygiene,
    requires_card=False,
    tags=("eim", "notifications"),
)


get_registry().register(LIST_FIXTURES_SPEC)
get_registry().register(HOTFOLDER_METADATA_SPEC)
get_registry().register(ISSUE_PACKAGE_SPEC)
get_registry().register(POLL_CAMPAIGN_SPEC)
get_registry().register(STATUS_SPEC)
get_registry().register(DISCOVER_SPEC)
get_registry().register(LIST_PROFILE_ALIASES_SPEC)
get_registry().register(GET_EIM_CONFIG_SPEC)
get_registry().register(COUNTERS_SPEC)
get_registry().register(HANDOVER_STATUS_SPEC)
get_registry().register(EIM_PACKAGE_LINT_SPEC)
get_registry().register(EIM_CERTS_INVENTORY_SPEC)
get_registry().register(HOTFOLDER_LIST_SPEC)
get_registry().register(ERROR_CODES_SPEC)
get_registry().register(ENABLE_PROFILE_SPEC)
get_registry().register(DISABLE_PROFILE_SPEC)
get_registry().register(DELETE_PROFILE_SPEC)
get_registry().register(STORE_METADATA_SPEC)
get_registry().register(UPDATE_METADATA_SPEC)
get_registry().register(DELETE_EIM_SPEC)
get_registry().register(EUICC_MEMORY_RESET_SPEC)
get_registry().register(EIM_PACKAGE_ISSUE_SPEC)
get_registry().register(SCAN_SPEC)
get_registry().register(EXPLAIN_LAST_SPEC)
get_registry().register(RESP_LOG_SPEC)
get_registry().register(RESP_LOG_FILTER_SPEC)
get_registry().register(COUNTER_SPEC)
get_registry().register(LOAD_PROFILE_SPEC)
get_registry().register(REFRESH_MODEM_SPEC)
get_registry().register(ISDR_GET_EIM_CONFIG_SPEC)
get_registry().register(ISDR_DELETE_EIM_SPEC)
get_registry().register(ISDR_ADD_EIM_SPEC)
get_registry().register(ISDR_ADD_INITIAL_EIM_SPEC)
get_registry().register(ADD_EIM_SPEC)
get_registry().register(ADD_INITIAL_EIM_SPEC)
get_registry().register(EIM_PACKAGE_EXPLAIN_SPEC)
get_registry().register(EIM_PACKAGE_ISSUE_ALL_SPEC)
get_registry().register(LOAD_EIM_PACKAGE_SPEC)
get_registry().register(EIM_ACKNOWLEDGE_SPEC)
get_registry().register(POLL_EXPORT_SPEC)
get_registry().register(POLL_AGGREGATE_SPEC)
get_registry().register(HANDOVER_SET_SPEC)
get_registry().register(HOTFOLDER_POLL_SPEC)
get_registry().register(HOTFOLDER_FETCH_SPEC)
get_registry().register(NOTIF_HYGIENE_SPEC)
