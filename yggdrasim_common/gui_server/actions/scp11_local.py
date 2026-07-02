# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 local_access Command Center actions.

Wraps :class:`SCP11.local_access.session.LocalIsdrSession` for the GUI so
the same reads and mutations that ``python -m SCP11.local_access``
performs from the REPL can be fired as typed Command Center actions.
Mirrors the pattern used by ``scp11_live`` — each dispatcher opens a
fresh PC/SC channel, runs one ISD-R command, and disconnects in
``finally``. No long-lived LocalIsdrSession is cached in process; state
is rebuilt per call.

Read-only surface:

* ``scp11_local.get_eid``              — 5A tag via ISD-R SELECT + ECASD.
* ``scp11_local.list_profiles``        — ProfilesInfo (BF2D) decoded.
* ``scp11_local.get_euicc_info2``      — EUICCInfo2 (BF22) detail lines.
* ``scp11_local.get_configured_data``  — EuiccConfiguredData (BF3C)
  with default SM-DP+ / SM-DS / allowed CI PKIDs.
* ``scp11_local.list_notifications``   — pending notification queue
  (BF2B) raw hex, for parity with the ES10b variant.
* ``scp11_local.get_certs_inventory``  — local SM-DP+ DPauth / DPpb
  certificate bundle already scanned by ``LocalSgp26CertStore``.
* ``scp11_local.discover``             — composite snapshot call that
  runs the same probe the REPL ``DISCOVER`` command performs.

Write / mutation actions mirror the REPL exactly:

* ``scp11_local.enable_profile`` / ``scp11_local.disable_profile``
* ``scp11_local.delete_profile``            — requires ``confirm=true``.
* ``scp11_local.store_metadata`` / ``scp11_local.update_metadata``
* ``scp11_local.store_metadata_custom``     — targeted custom tag.

Each mutation opens a fresh PC/SC channel via ``_build_session``, runs
exactly one card command through the local ISD-R, and closes the
channel in ``finally``. No long-lived session state is cached by the
GUI layer.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import re
import shutil
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .registry import ActionContext, ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.scp11_local")


# ----------------------------------------------------------------------
# PC/SC plumbing
# ----------------------------------------------------------------------


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


def _reader_input_field() -> ActionField:
    """Shared reader picker field used by every card-touching action."""
    return ActionField(
        name="reader",
        label="Reader",
        kind="reader",
        required=False,
        default="",
        help="PC/SC reader name (leave empty for the first reader).",
    )


def _resolve_reader_index(reader_name: str) -> int:
    """Map a reader name back to a zero-based PC/SC index."""
    cleaned = str(reader_name or "").strip()
    if len(cleaned) == 0:
        return 0
    try:
        from smartcard.System import readers as list_pcsc_readers
    except ImportError as error:
        raise RuntimeError("pyscard is not installed — cannot pick reader by name.") from error
    for idx, reader in enumerate(list_pcsc_readers()):
        if str(reader) == cleaned:
            return idx
    raise RuntimeError(f"reader not found: {cleaned!r}")


def _reader_label(reader_name: str) -> str:
    cleaned = str(reader_name or "").strip()
    if len(cleaned) == 0:
        return "(default)"
    return cleaned


def _build_session(reader_index: int) -> tuple[Any, Any]:
    """Return ``(session, channel)`` — caller closes both in ``finally``."""
    from SCP11.live.transport import PcscApduChannel
    from SCP11.local_access.config import LocalAccessConfig
    from SCP11.local_access.session import LocalIsdrSession

    cfg = LocalAccessConfig(READER_INDEX=int(reader_index))
    channel = PcscApduChannel(reader_index=int(reader_index))
    session = LocalIsdrSession(cfg=cfg, apdu_channel=channel)
    return session, channel


def _close_channel(channel: Any) -> None:
    if channel is None:
        return
    connection = getattr(channel, "_conn", None)
    if connection is None:
        return
    try:
        connection.disconnect()
    except Exception:  # noqa: BLE001 — teardown path, never surface
        pass


# ----------------------------------------------------------------------
# Dataclass / dict scrubbers
# ----------------------------------------------------------------------


def _view_to_row(view: Any) -> dict[str, Any]:
    """Flatten a ``ProfileMetadataView`` into a plain dict row."""
    if is_dataclass(view):
        return asdict(view)
    if isinstance(view, dict):
        return dict(view)
    return {"value": str(view)}


def _scrub_bytes(value: Any) -> Any:
    """Recursively convert ``bytes``/``bytearray`` to uppercase hex strings.

    The SAIP / ISD-R helpers return nested ``dict`` / ``list`` trees that
    occasionally embed raw ``bytes``; JSON-encoding those would crash the
    API serializer. We uppercase hex so the UI renders card material in
    the same form as the existing scp11_live viewers.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex().upper()
    if isinstance(value, dict):
        return {str(key): _scrub_bytes(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_bytes(entry) for entry in value]
    return value


# ----------------------------------------------------------------------
# Read-only dispatchers
# ----------------------------------------------------------------------


def _dispatch_get_eid(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    eid_text = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            eid_text = str(session.get_eid() or "").strip()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    ok = len(eid_text) > 0 and len(note_parts) == 0
    raw_hex = ""
    try:
        raw_hex = str(getattr(session, "_last_eid_raw_hex", "") or "")
    except Exception:  # noqa: BLE001
        raw_hex = ""
    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "eid": eid_text,
        "eid_length": len(eid_text),
        "ok": ok,
        "raw_hex": raw_hex,
        "note": "; ".join(note_parts) if note_parts else (
            "EID decoded via ISD-R SELECT + ECASD GET DATA 5A."
            if ok
            else "No EID returned; verify the card is seated and ISD-R is addressable."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_list_profiles(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    rows: list[dict[str, Any]] = []
    note_parts: list[str] = []
    raw_hex = ""
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            # We unroll collect_profile_metadata() here so we can keep the
            # raw BF2D00 response for the GUI hex viewer — the helper
            # discards it and only returns the decoded views.
            session.reset_state()
            session.select_isdr()
            raw_profiles = session.get_profiles_info() or b""
            views = session.decode_profile_metadata_rows(raw_profiles) or []
        raw_hex = raw_profiles.hex().upper()
        for view in views:
            rows.append(_view_to_row(view))
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    headers = ["iccid", "aid", "state", "profile_class", "nickname", "service_provider", "profile_name"]
    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "headers": headers,
        "rows": rows,
        "raw_hex": raw_hex,
        "count": len(rows),
        "note": "; ".join(note_parts) if note_parts else (
            f"{len(rows)} profile(s) decoded from BF2D00."
            if len(rows) > 0
            else "BF2D00 returned no E3 entries."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_get_euicc_info2(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    raw_hex = ""
    lines: list[dict[str, str]] = []
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            session.select_isdr()
            raw = session.get_euicc_info2()
        raw_hex = (raw or b"").hex().upper()
        lines = _build_euicc_info2_lines(raw or b"")
        if len(lines) == 0:
            note_parts.append("response did not contain a BF22 wrapper")
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": 0,
        "raw_hex": raw_hex,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _build_euicc_info2_lines(raw: bytes) -> list[dict[str, str]]:
    """Reuse the shared EUICCInfo2 detail-line builder for rendering."""
    try:
        from SCP03.logic.euicc_info2 import build_euicc_info2_detail_lines
    except ImportError:
        return []
    try:
        detail = build_euicc_info2_detail_lines(raw) or []
    except Exception:  # noqa: BLE001
        return []
    rows: list[dict[str, str]] = []
    for entry in detail:
        if isinstance(entry, dict):
            key_name = str(entry.get("label") or entry.get("key") or "").strip()
            value_text = str(entry.get("value") or "").strip()
        elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
            key_name = str(entry[0] or "").strip()
            value_text = str(entry[1] or "").strip()
        else:
            key_name = ""
            value_text = str(entry or "").strip()
        if len(key_name) == 0 and len(value_text) == 0:
            continue
        rows.append({"label": key_name, "value": value_text})
    return rows


def _dispatch_get_configured_data(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    raw_hex = ""
    decoded: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            session.select_isdr()
            raw = session.get_euicc_configured_data()
            decoded = session.decode_euicc_configured_data(raw or b"")
        raw_hex = (raw or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    lines: list[dict[str, str]] = []
    lines.append({"label": "Default SM-DP+", "value": str(decoded.get("default_smdp", "") or "-")})
    lines.append({"label": "Root SM-DS (primary)", "value": str(decoded.get("root_smds_primary", "") or "-")})
    additional = decoded.get("root_smds_additional") or []
    if isinstance(additional, list) and len(additional) > 0:
        for idx, entry in enumerate(additional):
            lines.append({"label": f"SM-DS additional[{idx}]", "value": str(entry)})
    else:
        lines.append({"label": "SM-DS additional", "value": "-"})
    pkids = decoded.get("allowed_ci_pkid") or []
    lines.append({
        "label": "Allowed CI PKIDs",
        "value": ", ".join(str(entry) for entry in pkids) if pkids else "-",
    })

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": 0,
        "raw_hex": raw_hex,
        "decoded": decoded,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_list_notifications(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    raw_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            session.select_isdr()
            raw = session.get_notifications_list()
        raw_hex = (raw or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "raw_hex": raw_hex,
        "length": len(raw_hex) // 2,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_list_certs_inventory(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Report the local SM-DP+ certificate inventory (pure file-system scan)."""
    reader_name = str(reader or "")
    reader_index = 0
    from SCP11.local_access.config import LocalAccessConfig
    from SCP11.local_access.session import LocalIsdrSession

    session = LocalIsdrSession(
        cfg=LocalAccessConfig(READER_INDEX=reader_index),
        apdu_channel=None,
    )
    trace_sink = io.StringIO()
    report: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            report = session.list_local_smdp_certificate_inventory() or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    scrubbed = _scrub_bytes(report) if isinstance(report, dict) else {}
    auth_records = scrubbed.get("auth_records") or []
    pb_records = scrubbed.get("pb_records") or []
    allowed = scrubbed.get("allowed_ci_pkids") or []
    selected_auth = scrubbed.get("selected_auth") or {}
    selected_pb = scrubbed.get("selected_pb") or {}
    lines: list[dict[str, str]] = []
    lines.append({"label": "Allowed CI PKIDs", "value": ", ".join(str(e) for e in allowed) or "-"})
    lines.append({"label": "Selected DPauth cert", "value": str(selected_auth.get("certificate_path", "-"))})
    lines.append({"label": "Selected DPauth key", "value": str(selected_auth.get("private_key_path", "-"))})
    lines.append({"label": "Selected DPauth mode", "value": str(selected_auth.get("selection_reason", "-"))})
    lines.append({"label": "Selected DPpb cert", "value": str(selected_pb.get("certificate_path", "-"))})
    lines.append({"label": "Selected DPpb key", "value": str(selected_pb.get("private_key_path", "-"))})
    lines.append({"label": "Selected DPpb mode", "value": str(selected_pb.get("selection_reason", "-"))})
    lines.append({"label": "DPauth candidates", "value": str(len(auth_records))})
    lines.append({"label": "DPpb candidates", "value": str(len(pb_records))})
    server_address = str(selected_auth.get("server_address", "") or "").strip()
    if len(server_address) > 0:
        lines.append({"label": "Local SM-DP+ address", "value": server_address})

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": 0,
        "inventory": scrubbed,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _normalize_import_certificate_role(role: Any, certificate_path: str) -> str:
    role_s = str(role or "DPauth").strip().lower()
    if role_s in {"dpauth", "auth", "sm_dpauth", "sm-dpauth"}:
        return "auth"
    if role_s in {"dppb", "pb", "sm_dppb", "sm-dppb"}:
        return "pb"
    if role_s != "auto":
        raise ValueError("certificate_role must be DPauth, DPpb, or auto.")

    basename = os.path.basename(str(certificate_path)).upper()
    if "DPAUTH" in basename or "SM_DPAUTH" in basename:
        return "auth"
    if "DPPB" in basename or "SM_DPPB" in basename:
        return "pb"
    raise ValueError(
        "certificate_role=auto could not infer DPauth or DPpb from the file name."
    )


def _local_smdp_import_target_dir(certs_dir: str, role: str) -> Path:
    role_dir = "SM_DPauth" if role == "auth" else "SM_DPpb"
    return Path(certs_dir).expanduser().resolve() / "SM-DP+" / role_dir


def _copy_local_smdp_import_file(source_path: Path, target_dir: Path, *, overwrite: bool) -> Path:
    if source_path.is_file() is False:
        raise ValueError(f"source file does not exist: {source_path}")
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / source_path.name
    if target_path.exists() and overwrite is False:
        raise ValueError(f"target already exists: {target_path}")
    if source_path.resolve() != target_path.resolve():
        shutil.copy2(source_path, target_path)
    return target_path


def _dispatch_import_certificate(
    ctx: ActionContext,
    *,
    certificate_path: Any = None,
    private_key_path: Any = None,
    certificate_role: Any = "DPauth",
    root_ci_pkid: Any = None,
    server_address: Any = None,
    overwrite: Any = False,
) -> dict[str, Any]:
    cert_s = str(certificate_path or "").strip()
    if len(cert_s) == 0:
        raise ValueError("certificate_path is required.")

    from SCP11.local_access.config import LocalAccessConfig
    from SCP11.local_access.session import LocalIsdrSession

    cfg = LocalAccessConfig()
    role = _normalize_import_certificate_role(certificate_role, cert_s)
    role_label = "DPauth" if role == "auth" else "DPpb"
    overwrite_bool = bool(overwrite)
    target_dir = _local_smdp_import_target_dir(cfg.CERTS_DIR, role)
    imported_cert = _copy_local_smdp_import_file(
        Path(cert_s).expanduser(),
        target_dir,
        overwrite=overwrite_bool,
    )

    imported_key = ""
    key_s = str(private_key_path or "").strip()
    if len(key_s) > 0:
        imported_key_path = _copy_local_smdp_import_file(
            Path(key_s).expanduser(),
            target_dir,
            overwrite=overwrite_bool,
        )
        imported_key = str(imported_key_path)

    metadata: dict[str, Any] = {"role": role}
    if len(imported_key) > 0:
        metadata["private_key_path"] = os.path.basename(imported_key)
    root_ci_s = str(root_ci_pkid or "").strip().upper()
    if len(root_ci_s) > 0:
        metadata["root_ci_pkid"] = root_ci_s
    server_s = str(server_address or "").strip()
    if len(server_s) > 0:
        metadata["server_address"] = server_s
    meta_path = Path(str(imported_cert) + ".meta.json")
    meta_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    session = LocalIsdrSession(cfg=cfg, apdu_channel=None)
    inventory = session.list_local_smdp_certificate_inventory() or {}
    return {
        "ok": True,
        "certificate_role": role_label,
        "certificate_path": str(imported_cert),
        "private_key_path": imported_key,
        "metadata_path": str(meta_path),
        "certs_dir": cfg.CERTS_DIR,
        "inventory": _scrub_bytes(inventory) if isinstance(inventory, dict) else {},
        "note": f"Imported {role_label} certificate into the local SM-DP+ certificate store.",
    }


def _dispatch_discover(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    snapshot: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            snapshot = session.discover_card() or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    scrubbed = _scrub_bytes(snapshot) if isinstance(snapshot, dict) else {}
    eid_value = str(scrubbed.get("eid", "") or "").strip()
    default_smdp = ""
    configured = scrubbed.get("configured") or scrubbed.get("configured_data") or {}
    if isinstance(configured, dict):
        default_smdp = str(configured.get("default_smdp", "") or "").strip()
    profiles = scrubbed.get("profiles") or []
    profile_count = len(profiles) if isinstance(profiles, list) else 0

    decode_errors: list[str] = []
    for key in ("profiles_decode_error", "configured_decode_error"):
        value = str(scrubbed.get(key, "") or "").strip()
        if len(value) > 0:
            decode_errors.append(f"{key}={value}")

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "eid": eid_value,
        "default_smdp": default_smdp,
        "profile_count": profile_count,
        "decode_errors": decode_errors,
        "snapshot": scrubbed,
        "note": "; ".join(note_parts) if note_parts else (
            f"discovery complete — EID={eid_value or '-'} · {profile_count} profile(s)"
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


GET_EID_SPEC = ActionSpec(
    id="scp11_local.get_eid",
    subsystem="SCP11 Local",
    title="Get EID (ISD-R)",
    description=(
        "Open a PC/SC channel, run the local ISD-R select + ECASD GET "
        "DATA 5A path, and close the channel. Pure read; no SCP11 handshake."
    ),
    inputs=(_reader_input_field(),),
    output_kind="json",
    dispatcher=_dispatch_get_eid,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "read-only", "eid"),
)


LIST_PROFILES_SPEC = ActionSpec(
    id="scp11_local.list_profiles",
    subsystem="SCP11 Local",
    title="List profiles (ES10b local)",
    description=(
        "Fetch ProfilesInfo (BF2D00) through the local ISD-R and decode "
        "each E3 entry (ICCID, AID, state, class, nickname, service "
        "provider, profile name)."
    ),
    inputs=(_reader_input_field(),),
    output_kind="table",
    dispatcher=_dispatch_list_profiles,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "read-only", "profiles"),
)


GET_EUICC_INFO2_SPEC = ActionSpec(
    id="scp11_local.get_euicc_info2",
    subsystem="SCP11 Local",
    title="EUICCInfo2 (local)",
    description=(
        "Fetch EUICCInfo2 (BF2200) via the local ISD-R retrieve-path and "
        "render the shared detail-lines view (SVN, firmware, UICC CSN, "
        "CI pkids, capabilities)."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_euicc_info2,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "read-only", "euicc-info2"),
)


GET_CONFIGURED_DATA_SPEC = ActionSpec(
    id="scp11_local.get_configured_data",
    subsystem="SCP11 Local",
    title="EuiccConfiguredData (local)",
    description=(
        "Fetch BF3C00 through the local ISD-R and surface the default "
        "SM-DP+ address, primary / additional SM-DS, and allowed CI "
        "PKIDs as key/value rows."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_configured_data,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "read-only", "configured-data"),
)


LIST_NOTIFICATIONS_SPEC = ActionSpec(
    id="scp11_local.list_notifications",
    subsystem="SCP11 Local",
    title="Retrieve notifications list",
    description=(
        "Fetch the pending notifications queue (BF2B00) via the local "
        "ISD-R. Raw-hex view for parity with the ES10b live read; full "
        "row decoding is deferred to a follow-up slice."
    ),
    inputs=(_reader_input_field(),),
    output_kind="json",
    dispatcher=_dispatch_list_notifications,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "read-only", "notifications"),
)


GET_CERTS_INVENTORY_SPEC = ActionSpec(
    id="scp11_local.get_certs_inventory",
    subsystem="SCP11 Local",
    title="Local SM-DP+ cert inventory",
    description=(
        "Scan the local SM-DP+ DPauth / DPpb certificate bundles shipped "
        "with the SGP.26 reference tree. Pure filesystem read — does not "
        "touch the card. Shows the currently selected certificate per "
        "role and lists alternative candidates."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_list_certs_inventory,
    requires_card=False,
    streams=False,
    tags=("scp11", "local", "read-only", "certs"),
)


IMPORT_CERTIFICATE_SPEC = ActionSpec(
    id="scp11_local.import_certificate",
    subsystem="SCP11 Local",
    title="Import local SM-DP+ cert",
    description=(
        "Copy a DPauth or DPpb certificate into the persistent local "
        "SM-DP+ certificate store and write the metadata sidecar used by "
        "LocalSgp26CertStore."
    ),
    inputs=(
        ActionField(
            name="certificate_path",
            label="Certificate path",
            kind="path",
            required=True,
            help="Certificate file to copy into Workspace/LocalSMDPP/certs.",
        ),
        ActionField(
            name="private_key_path",
            label="Private key path",
            kind="path",
            required=False,
            help="Optional matching private key copied next to the certificate.",
        ),
        ActionField(
            name="certificate_role",
            label="Role",
            kind="enum",
            required=True,
            default="DPauth",
            choices=["DPauth", "DPpb", "auto"],
            help="SM-DP+ certificate role for local profile delivery.",
        ),
        ActionField(
            name="root_ci_pkid",
            label="Root CI PKID",
            kind="hex",
            required=False,
            help="Optional root CI PKID override written to the metadata sidecar.",
        ),
        ActionField(
            name="server_address",
            label="SM-DP+ address",
            kind="string",
            required=False,
            help="Optional server address written to the metadata sidecar.",
        ),
        ActionField(
            name="overwrite",
            label="Overwrite existing file",
            kind="bool",
            required=False,
            default=False,
            help="Replace an existing imported file with the same basename.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_import_certificate,
    requires_card=False,
    streams=False,
    tags=("scp11", "local", "certs", "import"),
)


DISCOVER_SPEC = ActionSpec(
    id="scp11_local.discover",
    subsystem="SCP11 Local",
    title="Discover (one-shot snapshot)",
    description=(
        "Run the same probe the local_access REPL 'DISCOVER' command "
        "fires: ISD-R select → ProfilesInfo → ConfiguredData → EID + "
        "ECASD issuer identity. Returns the full snapshot dict for "
        "further inspection in the JSON tree."
    ),
    inputs=(_reader_input_field(),),
    output_kind="json",
    dispatcher=_dispatch_discover,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "read-only", "discover"),
)


# ----------------------------------------------------------------------
# Mutation dispatchers
# ----------------------------------------------------------------------


def _run_profile_state_mutation(
    reader: Any,
    identifier: Any,
    action: str,
    label: str,
    *,
    confirm_required: bool = False,
    confirmed: bool = False,
) -> dict[str, Any]:
    """Shared helper for Enable / Disable / Delete profile mutations."""
    identifier_s = str(identifier or "").strip()
    if len(identifier_s) == 0:
        raise ValueError("identifier is required (iccid digits, AID hex, or alias).")
    if confirm_required and confirmed is False:
        raise ValueError(f"confirm must be true — {label} is destructive.")

    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        method = getattr(session, action)
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            response = method(identifier_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "action": action,
        "identifier": identifier_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else (
            f"{label} completed ({len(response_hex) // 2} bytes)."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_enable_profile(
    ctx: ActionContext,
    *,
    reader: Any = None,
    identifier: Any = None,
) -> dict[str, Any]:
    return _run_profile_state_mutation(
        reader=reader,
        identifier=identifier,
        action="enable_profile",
        label="EnableProfile",
    )


def _dispatch_disable_profile(
    ctx: ActionContext,
    *,
    reader: Any = None,
    identifier: Any = None,
) -> dict[str, Any]:
    return _run_profile_state_mutation(
        reader=reader,
        identifier=identifier,
        action="disable_profile",
        label="DisableProfile",
    )


def _dispatch_delete_profile(
    ctx: ActionContext,
    *,
    reader: Any = None,
    identifier: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    return _run_profile_state_mutation(
        reader=reader,
        identifier=identifier,
        action="delete_profile",
        label="DeleteProfile",
        confirm_required=True,
        confirmed=bool(confirm),
    )


def _dispatch_store_metadata(
    ctx: ActionContext,
    *,
    reader: Any = None,
    metadata_path: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    path_s = str(metadata_path or "").strip()
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            response = session.store_metadata(metadata_path=path_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "metadata_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else (
            f"StoreMetadata completed ({len(response_hex) // 2} bytes)."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_update_metadata(
    ctx: ActionContext,
    *,
    reader: Any = None,
    metadata_path: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    path_s = str(metadata_path or "").strip()
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            response = session.update_metadata(metadata_path=path_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "metadata_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else (
            f"UpdateMetadata completed ({len(response_hex) // 2} bytes)."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_store_metadata_custom(
    ctx: ActionContext,
    *,
    reader: Any = None,
    custom_tag: Any = None,
    metadata_path: Any = None,
) -> dict[str, Any]:
    custom_tag_s = str(custom_tag or "").strip()
    if len(custom_tag_s) == 0:
        raise ValueError("custom_tag is required (hex, e.g. 'BF70').")
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    path_s = str(metadata_path or "").strip()
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            response = session.store_metadata_custom(
                custom_tag_hex=custom_tag_s,
                metadata_path=path_s,
            )
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "custom_tag": custom_tag_s.upper(),
        "metadata_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else (
            f"StoreMetadata custom[{custom_tag_s.upper()}] completed "
            f"({len(response_hex) // 2} bytes)."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


# ----------------------------------------------------------------------
# Additional dispatchers (status, load_profile,
# store_metadata_custom_all, explain_last, export_keybag,
# record_start, record_stop, metadata_lint)
# ----------------------------------------------------------------------


def _dispatch_status(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    note_parts: list[str] = []
    state_snapshot: dict[str, Any] = {}
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            st = session.state
            state_snapshot = {
                "session_open": bool(st.session_open),
                "isdr_selected": bool(st.isdr_selected),
                "transaction_id": st.transaction_id.hex().upper() if len(st.transaction_id) > 0 else "",
                "scp11_active": bool(getattr(st, "scp11_active", False)),
                "last_profile_path": str(getattr(st, "last_profile_path", "") or ""),
                "last_metadata_path": str(getattr(st, "last_metadata_path", "") or ""),
            }
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    lines: list[dict[str, str]] = []
    for key, value in state_snapshot.items():
        lines.append({"label": key.replace("_", " ").title(), "value": str(value)})

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": 0,
        "state": state_snapshot,
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else "session state snapshot captured.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_load_profile(
    ctx: ActionContext,
    *,
    reader: Any = None,
    profile_path: Any = None,
    confirmation_code: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    path_s = str(profile_path or "").strip()
    if len(path_s) == 0:
        raise ValueError("profile_path is required for the one-shot load cycle.")
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    response_hex = ""
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            if confirmation_code is not None and len(str(confirmation_code).strip()) > 0:
                session.state.confirmation_code = str(confirmation_code).strip()
            response = session.run_load_profile_chain(profile_path=path_s)
        response_hex = bytes(response or b"").hex().upper()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "profile_path": path_s,
        "response_hex": response_hex,
        "response_length": len(response_hex) // 2,
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else (
            f"LoadProfile chain completed ({len(response_hex) // 2} bytes)."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_store_metadata_custom_all(
    ctx: ActionContext,
    *,
    reader: Any = None,
    metadata_path: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    path_s = str(metadata_path or "").strip()
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    results: list[tuple[str, bytes]] = []
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            results = session.store_metadata_custom_all(metadata_path=path_s)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    rows = [
        {"tag": tag, "response_hex": bytes(resp or b"").hex().upper()}
        for tag, resp in results
    ]
    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "metadata_path": path_s,
        "rows": rows,
        "count": len(rows),
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else (
            f"{len(rows)} custom metadata tag(s) sent."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_explain_last(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    note_parts: list[str] = []
    lines: list[dict[str, str]] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            st = session.state
            lines.append({"label": "Session open", "value": "yes" if st.session_open else "no"})
            lines.append({"label": "ISD-R selected", "value": "yes" if st.isdr_selected else "no"})
            txid = st.transaction_id.hex().upper() if len(st.transaction_id) > 0 else "-"
            lines.append({"label": "Transaction id", "value": txid})
            last_cmd = getattr(st, "last_command", "")
            lines.append({"label": "Last command", "value": str(last_cmd) if last_cmd else "-"})
            last_apdu = getattr(st, "last_apdu_hex", "")
            lines.append({"label": "Last APDU", "value": str(last_apdu) if last_apdu else "-"})
            last_resp = getattr(st, "last_response_hex", "")
            lines.append({"label": "Last response", "value": str(last_resp) if last_resp else "-"})
            last_error = getattr(st, "last_error", "")
            lines.append({"label": "Last error", "value": str(last_error) if last_error else "none"})
            last_profile = getattr(st, "last_profile_path", "")
            lines.append({"label": "Active profile", "value": str(last_profile) if last_profile else "-"})
            last_metadata = getattr(st, "last_metadata_path", "")
            lines.append({"label": "Active metadata", "value": str(last_metadata) if last_metadata else "-"})
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": 0,
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else "last-command context captured.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_export_keybag(
    ctx: ActionContext,
    *,
    reader: Any = None,
    output_path: Any = None,
    label: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    path_s = str(output_path or "").strip()
    label_s = str(label or "").strip()
    session, channel = _build_session(reader_index)
    trace_sink = io.StringIO()
    note_parts: list[str] = []
    keybag_path = ""
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            st = session.state
            if len(path_s) == 0:
                import os as _os
                path_s = _os.path.join(_os.path.expanduser("~"), "Documents", "scp11_keybag.json")
            bsp_enc = str(getattr(st, "last_bsp_s_enc_hex", "") or "").strip()
            bsp_mac = str(getattr(st, "last_bsp_s_mac_hex", "") or "").strip()
            bsp_dek = str(getattr(st, "last_bsp_s_dek_hex", "") or "").strip()
            bsp_rmac = str(getattr(st, "last_bsp_s_rmac_hex", "") or "").strip()
            if len(bsp_enc) == 0 and len(bsp_mac) == 0:
                raise ValueError(
                    "no BSP keys in session state — run LOAD-PROFILE first to derive SCP11c keys."
                )
            keybag: dict[str, Any] = {
                "label": label_s if len(label_s) > 0 else "scp11-local",
                "keys": {
                    "bsp_s_enc_hex": bsp_enc,
                    "bsp_s_mac_hex": bsp_mac,
                    "bsp_s_dek_hex": bsp_dek,
                    "bsp_s_rmac_hex": bsp_rmac,
                },
            }
            import json as _json
            with open(path_s, "w", encoding="utf-8") as fh:
                _json.dump(keybag, fh, indent=2)
            keybag_path = path_s
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "output_path": keybag_path,
        "label": label_s if len(label_s) > 0 else "scp11-local",
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else (
            f"Keybag exported to {keybag_path}."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_record_start(
    ctx: ActionContext,
    *,
    reader: Any = None,
    output_path: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    path_s = str(output_path or "").strip()
    from yggdrasim_common.session_recording import ShellSessionRecorder

    recorder = ShellSessionRecorder(
        shell_name="scp11_local_access",
        module_entry_point="python -m SCP11.local_access",
    )
    resolved = recorder.start(output_path=path_s)
    return {
        "reader_name": _reader_label(reader_name),
        "output_path": resolved,
        "recording": True,
        "ok": True,
        "note": f"Recording started → {resolved}",
    }


def _dispatch_record_stop(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    reader_name = str(reader or "")
    from yggdrasim_common.session_recording import ShellSessionRecorder

    recorder = ShellSessionRecorder(
        shell_name="scp11_local_access",
        module_entry_point="python -m SCP11.local_access",
    )
    try:
        out_path, summary = recorder.stop()
        recording = False
        note = f"Recording stopped — {summary.get('apdu_count', 0)} APDU(s) in {out_path}"
    except Exception as error:  # noqa: BLE001
        out_path = ""
        summary = {}
        recording = recorder.is_active()
        note = f"Stop failed ({error}) — recording may still be active."

    return {
        "reader_name": _reader_label(reader_name),
        "output_path": out_path,
        "summary": summary,
        "recording": recording,
        "ok": not recording,
        "note": note,
    }


def _dispatch_metadata_lint(
    ctx: ActionContext,
    *,
    metadata_path: Any = None,
) -> dict[str, Any]:
    path_s = str(metadata_path or "").strip()
    if len(path_s) == 0:
        raise ValueError("metadata_path is required.")
    session, channel = _build_session(0)
    trace_sink = io.StringIO()
    report: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            report = session.lint_metadata(metadata_path=path_s) or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_channel(channel)

    scrubbed = _scrub_bytes(report) if isinstance(report, dict) else {}
    return {
        "metadata_path": path_s,
        "report": scrubbed,
        "ok": len(note_parts) == 0 and len(scrubbed.get("errors", [])) == 0,
        "note": "; ".join(note_parts) if note_parts else (
            f"lint complete — {len(scrubbed.get('errors', []))} error(s)."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


# ----------------------------------------------------------------------
# Mutation specs
# ----------------------------------------------------------------------


ENABLE_PROFILE_SPEC = ActionSpec(
    id="scp11_local.enable_profile",
    subsystem="SCP11 Local",
    title="Enable profile",
    description=(
        "Run EnableProfile against the local ISD-R. Identifier accepts "
        "ICCID digits, hex AID, or an alias from the profile list."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="identifier",
            label="ICCID / AID / alias",
            kind="string",
            required=True,
            placeholder="89014104… or A0000005591010FFFFFFFF8900001100",
            help="Target profile identifier.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_enable_profile,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "profile", "enable"),
)


DISABLE_PROFILE_SPEC = ActionSpec(
    id="scp11_local.disable_profile",
    subsystem="SCP11 Local",
    title="Disable profile",
    description="Run DisableProfile against the local ISD-R.",
    inputs=(
        _reader_input_field(),
        ActionField(
            name="identifier",
            label="ICCID / AID / alias",
            kind="string",
            required=True,
            help="Target profile identifier.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_disable_profile,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "profile", "disable"),
)


DELETE_PROFILE_SPEC = ActionSpec(
    id="scp11_local.delete_profile",
    subsystem="SCP11 Local",
    title="Delete profile",
    description=(
        "Run DeleteProfile against the local ISD-R. Destructive — "
        "requires explicit confirm=true."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="identifier",
            label="ICCID / AID / alias",
            kind="string",
            required=True,
            help="Target profile identifier.",
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
    dispatcher=_dispatch_delete_profile,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "profile", "delete", "destructive"),
)


STORE_METADATA_SPEC = ActionSpec(
    id="scp11_local.store_metadata",
    subsystem="SCP11 Local",
    title="Store metadata",
    description=(
        "Encode the metadata JSON and push StoreMetadata to the local "
        "ISD-R. Leave ``metadata_path`` blank for the configured default."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="metadata_path",
            label="Metadata path",
            kind="path",
            required=False,
            help="Path to the metadata JSON; blank = configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_store_metadata,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "metadata", "store"),
)


UPDATE_METADATA_SPEC = ActionSpec(
    id="scp11_local.update_metadata",
    subsystem="SCP11 Local",
    title="Update metadata",
    description=(
        "Encode the metadata JSON and push UpdateMetadata to the local "
        "ISD-R. Same input contract as Store, but uses the update-shape "
        "payload on the card."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="metadata_path",
            label="Metadata path",
            kind="path",
            required=False,
            help="Path to the metadata JSON; blank = configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_update_metadata,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "metadata", "update"),
)


STORE_METADATA_CUSTOM_SPEC = ActionSpec(
    id="scp11_local.store_metadata_custom",
    subsystem="SCP11 Local",
    title="Store metadata (custom tag)",
    description=(
        "Push a StoreMetadata variant targeting an explicit custom "
        "tag (hex). Useful for vendor-specific metadata extensions."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="custom_tag",
            label="Custom tag (hex)",
            kind="hex",
            required=True,
            placeholder="BF70",
            help="Tag for the custom metadata container, hex-encoded.",
        ),
        ActionField(
            name="metadata_path",
            label="Metadata path",
            kind="path",
            required=False,
            help="Path to the metadata JSON; blank = configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_store_metadata_custom,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "metadata", "custom"),
)


STATUS_SPEC = ActionSpec(
    id="scp11_local.status",
    subsystem="SCP11 Local",
    title="Session status",
    description=(
        "Snapshot the local-access session state: ISD-R selection, "
        "transaction id, SCP11 activity, last profile/metadata paths, "
        "and outstanding error context."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_status,
    requires_card=False,
    streams=False,
    tags=("scp11", "local", "status"),
)

LOAD_PROFILE_SPEC = ActionSpec(
    id="scp11_local.load_profile",
    subsystem="SCP11 Local",
    title="Load profile (one-shot chain)",
    description=(
        "Run the full one-shot profile delivery chain: reset state, "
        "read the BPP, open SCP11 session, prepare download, load the "
        "profile bytes, and close the session. Equivalent to the REPL "
        "LOAD-PROFILE command."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="profile_path",
            label="Profile path (.bpp / .der / .hex)",
            kind="path",
            required=True,
            help="Path to the bound profile package file.",
        ),
        ActionField(
            name="confirmation_code",
            label="Confirmation code",
            kind="string",
            required=False,
            help="Optional confirmation code if required by the profile.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_load_profile,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "profile", "load"),
)

STORE_METADATA_CUSTOM_ALL_SPEC = ActionSpec(
    id="scp11_local.store_metadata_custom_all",
    subsystem="SCP11 Local",
    title="Store metadata (all custom tags)",
    description=(
        "Read every enabled custom metadata entry from the metadata "
        "JSON and push each one to the card as a StoreMetadata command. "
        "Useful for vendor-specific extension tags that must be sent "
        "in a batch."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="metadata_path",
            label="Metadata path",
            kind="path",
            required=False,
            help="Path to the metadata JSON; blank = configured default.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_store_metadata_custom_all,
    requires_card=True,
    streams=False,
    tags=("scp11", "local", "metadata", "custom-all"),
)

EXPLAIN_LAST_SPEC = ActionSpec(
    id="scp11_local.explain_last",
    subsystem="SCP11 Local",
    title="Explain last command",
    description=(
        "Surface the context of the last command: session flags, "
        "transaction id, last APDU/response, last error, and active "
        "profile/metadata overrides."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_explain_last,
    requires_card=False,
    streams=False,
    tags=("scp11", "local", "debug"),
)

EXPORT_KEYBAG_SPEC = ActionSpec(
    id="scp11_local.export_keybag",
    subsystem="SCP11 Local",
    title="Export keybag (SCP11c BSP keys)",
    description=(
        "Export the derived SCP11c BSP session keys (S-ENC, S-MAC, "
        "S-DEK, S-RMAC) to a JSON keybag file for offline Wireshark "
        "replay or EumDiag. Requires a prior LOAD-PROFILE to have "
        "established the key material."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="output_path",
            label="Output path",
            kind="save_path",
            required=False,
            help="Where to write the keybag JSON; defaults to ~/Documents/scp11_keybag.json.",
        ),
        ActionField(
            name="label",
            label="Label",
            kind="string",
            required=False,
            default="scp11-local",
            help="Human label for the keybag entry.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_export_keybag,
    requires_card=False,
    streams=False,
    tags=("scp11", "local", "keybag", "export"),
)

RECORD_START_SPEC = ActionSpec(
    id="scp11_local.record_start",
    subsystem="SCP11 Local",
    title="Start session recording",
    description=(
        "Begin capturing the APDU trace for this local-access session. "
        "The recording accumulates until 'Stop recording' is called."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="output_path",
            label="Output path",
            kind="save_path",
            required=False,
            help="Where to write the recording JSON; defaults to an auto-named file.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_record_start,
    requires_card=False,
    streams=False,
    tags=("scp11", "local", "record"),
)

RECORD_STOP_SPEC = ActionSpec(
    id="scp11_local.record_stop",
    subsystem="SCP11 Local",
    title="Stop session recording",
    description=(
        "End the active APDU trace recording and write the capture "
        "file to disk."
    ),
    inputs=(_reader_input_field(),),
    output_kind="json",
    dispatcher=_dispatch_record_stop,
    requires_card=False,
    streams=False,
    tags=("scp11", "local", "record"),
)

METADATA_LINT_SPEC = ActionSpec(
    id="scp11_local.metadata_lint",
    subsystem="SCP11 Local",
    title="Lint metadata JSON",
    description=(
        "Validate a metadata JSON file: check JSON syntax, test both "
        "StoreMetadata and UpdateMetadata ASN.1 projections, and flag "
        "duplicate custom tags."
    ),
    inputs=(
        ActionField(
            name="metadata_path",
            label="Metadata path",
            kind="path",
            required=True,
            help="Path to the metadata JSON file to lint.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_metadata_lint,
    requires_card=False,
    streams=False,
    tags=("scp11", "local", "metadata", "lint"),
)

get_registry().register(GET_EID_SPEC)
get_registry().register(LIST_PROFILES_SPEC)
get_registry().register(GET_EUICC_INFO2_SPEC)
get_registry().register(GET_CONFIGURED_DATA_SPEC)
get_registry().register(LIST_NOTIFICATIONS_SPEC)
get_registry().register(GET_CERTS_INVENTORY_SPEC)
get_registry().register(IMPORT_CERTIFICATE_SPEC)
get_registry().register(DISCOVER_SPEC)
get_registry().register(ENABLE_PROFILE_SPEC)
get_registry().register(DISABLE_PROFILE_SPEC)
get_registry().register(DELETE_PROFILE_SPEC)
get_registry().register(STORE_METADATA_SPEC)
get_registry().register(UPDATE_METADATA_SPEC)
get_registry().register(STORE_METADATA_CUSTOM_SPEC)
get_registry().register(STATUS_SPEC)
get_registry().register(LOAD_PROFILE_SPEC)
get_registry().register(STORE_METADATA_CUSTOM_ALL_SPEC)
get_registry().register(EXPLAIN_LAST_SPEC)
get_registry().register(EXPORT_KEYBAG_SPEC)
get_registry().register(RECORD_START_SPEC)
get_registry().register(RECORD_STOP_SPEC)
get_registry().register(METADATA_LINT_SPEC)
