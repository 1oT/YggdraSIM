# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 live Command Center actions.

Registers every SCP11/live/console command as a Command Center action so
the GUI can drive the same surface the CLI does. Dispatchers are
deliberately short-lived: each call opens a fresh PC/SC channel, runs a
single console handler (either directly on the orchestrator or via a
headless ``SCP11Console`` instance), and tears the channel down again.

Action tranches (register order kept in sync with the section headers
further down so the sidebar groups render predictably):

* **Read-only** (``get_eid``, ``list_profiles``, ``get_smdp``,
  ``list_notifications``, ``euicc_info1/2``, ``get_rat``, ``get_certs``,
  ``get_eim_config``, ``aids``, ``scan``, ``status``, ``read_metadata``,
  ``get_metadata``, ``get_pol``, ``get_all_data``, ``get_es9``,
  ``es9_cert_info``). Safe to run at any time; no confirmation gate.
* **Config writes** (``set_smdp``, ``set_es9``, ``set_es9_tls``,
  ``set_es9_ca``). Mutates inventory / config files; each spec carries a
  ``confirm`` checkbox.
* **Card mutations** (``enable_profile``, ``disable_profile``,
  ``delete_profile``, ``refresh_modem``, ``reset_card``,
  ``remove_notification``, ``clear_notifications``, ``set_pol``,
  ``store_metadata``). Every one gates on the same ``confirm`` checkbox
  the config writes use.
* **Streaming flows** (``discover``, ``eim_authenticate``,
  ``eim_download``, ``eim_poll``, ``download_profile``, ``flow``,
  ``verify_scp11``). Async-generator dispatchers tee the console /
  orchestrator stdout into the WS action stream.

All card-touching actions accept an optional ``reader`` name that the
action layer normalises back into a ``reader_index`` before the channel
is opened. The destructive ``confirm`` field is a per-call form input —
it is intentionally **not** wired to an environment flag, so it never
shows up in the GUI env config surface.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import importlib
import io
import logging
import re
import threading
import traceback
from dataclasses import replace
from typing import Any, AsyncIterator, Callable, Optional

from .registry import ActionContext, ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.scp11_live")


# ----------------------------------------------------------------------
# Provider package resolution
# ----------------------------------------------------------------------
# A context variable lets the test-flavour module (``scp11_test``) retune
# the provider import root ("SCP11.live" -> "SCP11.test") per request
# without having to duplicate 3k+ lines of dispatcher code. All helpers
# that used to ``from SCP11.live.X import Y`` now go through
# :func:`_provider_module` and pick the package pinned for this call.
_PROVIDER_PACKAGE: "contextvars.ContextVar[str]" = contextvars.ContextVar(
    "scp11_provider_package",
    default="live",
)


def _active_provider_package() -> str:
    """Return the currently pinned SCP11 provider flavour ("live"/"test")."""
    value = str(_PROVIDER_PACKAGE.get() or "live").strip().lower()
    if value not in ("live", "test"):
        return "live"
    return value


def _provider_module(submodule: str) -> Any:
    """Import ``SCP11.<package>.<submodule>`` for the active provider."""
    package = _active_provider_package()
    return importlib.import_module(f"SCP11.{package}.{submodule}")


@contextlib.contextmanager
def _use_provider(package: str):
    """Temporarily pin the SCP11 provider flavour for this call stack."""
    token = _PROVIDER_PACKAGE.set(str(package or "live"))
    try:
        yield
    finally:
        _PROVIDER_PACKAGE.reset(token)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _resolve_reader_index(reader_name: str) -> int:
    """Map a reader name back to a ``reader_index`` (0 if empty)."""
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


def _build_apdu_channel(reader_index: int) -> Any:
    """Open a PC/SC APDU channel bound to the chosen reader.

    Uses the active provider flavour ("live" by default; "test" when the
    scp11_test wrapper is in context).
    """
    PcscApduChannel = getattr(_provider_module("transport"), "PcscApduChannel")
    return PcscApduChannel(reader_index=reader_index)


def _close_apdu_channel(channel: Any) -> None:
    """Best-effort disconnect; swallow any PC/SC teardown errors."""
    if channel is None:
        return
    connection = getattr(channel, "_conn", None)
    if connection is None:
        return
    try:
        connection.disconnect()
    except Exception:  # noqa: BLE001 — cleanup path
        pass


def _make_orchestrator(reader_index: int) -> tuple[Any, Any, Any]:
    """Instantiate ``SGP22Orchestrator`` with a per-call APDU channel.

    Returns ``(orchestrator, channel, cfg)``; the caller must close the
    channel when it is done. ``SGP22Orchestrator.__init__`` is a cheap
    state-dict setup, so constructing one per call is acceptable for
    read-only probes.
    """
    SGPConfig = getattr(_provider_module("config"), "SGPConfig")
    SGP22Orchestrator = getattr(_provider_module("orchestrator"), "SGP22Orchestrator")

    base_cfg = SGPConfig()
    cfg = replace(base_cfg, READER_INDEX=int(reader_index))
    channel = _build_apdu_channel(int(reader_index))
    orchestrator = SGP22Orchestrator(cfg=cfg, apdu_channel=channel)
    return orchestrator, channel, cfg


def _tlv_parse(data: bytes) -> dict[int, Any]:
    """Parse a BER-TLV blob into a ``{tag_int: value_or_list}`` dict.

    Delegates to the SCP03 ``TlvParser`` (already shipped, multi-byte tag
    aware). Kept as a local helper so the import is lazy and does not
    block action-module registration when the parser is missing.
    """
    from SCP03.core.utils import TlvParser

    return TlvParser.parse(data)


def _tlv_first(parsed: dict[int, Any], tag: int, default: Any = None) -> Any:
    from SCP03.core.utils import TlvParser

    return TlvParser.get_first(parsed, tag, default)


def _tlv_as_list(value: Any) -> list[Any]:
    from SCP03.core.utils import TlvParser

    return TlvParser.as_list(value)


# ----------------------------------------------------------------------
# EID
# ----------------------------------------------------------------------


def _dispatch_get_eid(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Return the EID read via the ECASD applet."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    orchestrator, channel, _cfg = _make_orchestrator(reader_index)
    trace_sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            eid = orchestrator._read_card_eid(reselect_isdr=False)
    finally:
        _close_apdu_channel(channel)

    eid_text = str(eid or "").strip()
    ok = len(eid_text) > 0
    raw_hex = ""
    try:
        raw_hex = str(getattr(orchestrator, "_last_eid_raw_hex", "") or "")
    except Exception:  # noqa: BLE001
        raw_hex = ""
    return {
        "reader_index": reader_index,
        "reader_name": reader_name or "(default)",
        "eid": eid_text,
        "eid_length": len(eid_text),
        "ok": ok,
        "raw_hex": raw_hex,
        "note": (
            "EID decoded from ECASD tag 5A (BCD, 0x0F-padding stripped)."
            if ok
            else "No EID returned; verify the card is seated and the ECASD is addressable."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


# ----------------------------------------------------------------------
# Profiles list
# ----------------------------------------------------------------------


def _decode_profile_entry(entry: Any) -> dict[str, Any]:
    """Decode one ``E3`` ProfileInfo block into a dict row.

    ``entry`` is either the nested dict returned by :class:`TlvParser`
    (when the parser walked into ``E3``) or the raw bytes (if the parse
    stopped early). This function copes with both.
    """
    parsed: dict[int, Any]
    if isinstance(entry, dict):
        parsed = entry
    elif isinstance(entry, (bytes, bytearray)):
        try:
            parsed = _tlv_parse(bytes(entry))
        except Exception:  # noqa: BLE001 — report a raw row
            return {
                "iccid": "",
                "state": "",
                "profile_class": "",
                "nickname": "",
                "aid": "",
                "raw_hex": bytes(entry).hex().upper(),
            }
    else:
        return {
            "iccid": "",
            "state": "",
            "profile_class": "",
            "nickname": "",
            "aid": "",
            "raw_hex": "",
        }

    aid_bytes = _tlv_first(parsed, 0x4F) or _tlv_first(parsed, 0xA0)
    iccid_bytes = _tlv_first(parsed, 0x5A)
    state_bytes = _tlv_first(parsed, 0x9F70, b"\x00")
    class_bytes = _tlv_first(parsed, 0x95, b"\x02")
    name_bytes = (
        _tlv_first(parsed, 0x90)
        or _tlv_first(parsed, 0x92)
        or _tlv_first(parsed, 0x91)
    )

    aid_hex = aid_bytes.hex().upper() if isinstance(aid_bytes, (bytes, bytearray)) else ""
    iccid_hex = iccid_bytes.hex().upper() if isinstance(iccid_bytes, (bytes, bytearray)) else ""
    iccid_display = _swap_nibbles(iccid_hex)

    state_int = (
        int.from_bytes(bytes(state_bytes), "big") if isinstance(state_bytes, (bytes, bytearray)) else 0
    )
    state = "ENABLED" if state_int == 1 else "DISABLED"

    class_int = (
        int.from_bytes(bytes(class_bytes), "big") if isinstance(class_bytes, (bytes, bytearray)) else 2
    )
    class_map = {0: "TEST", 1: "PROV", 2: "OPER"}
    profile_class = class_map.get(class_int, "OPER")

    nickname = ""
    if isinstance(name_bytes, (bytes, bytearray)):
        try:
            nickname = bytes(name_bytes).decode("utf-8", "ignore").strip()
        except Exception:  # noqa: BLE001
            nickname = bytes(name_bytes).hex().upper()
    if len(nickname) == 0 and len(iccid_display) > 0:
        nickname = f"ICCID-{iccid_display[-4:]}"

    return {
        "iccid": iccid_display,
        "iccid_raw_hex": iccid_hex,
        "state": state,
        "state_code": state_int,
        "profile_class": profile_class,
        "profile_class_code": class_int,
        "nickname": nickname,
        "aid": aid_hex,
    }


def _swap_nibbles(value: str) -> str:
    """Swap every nibble pair, stripping any trailing ``F`` padding.

    Used to render ICCIDs from their on-card byte encoding
    (low-nibble-first BCD) back into the canonical display order.
    """
    cleaned = str(value or "").upper()
    if len(cleaned) % 2 != 0:
        return cleaned
    swapped_chars: list[str] = []
    for index in range(0, len(cleaned), 2):
        swapped_chars.append(cleaned[index + 1])
        swapped_chars.append(cleaned[index])
    result = "".join(swapped_chars)
    while result.endswith("F"):
        result = result[:-1]
    return result


def _dispatch_list_profiles(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Fetch ``ProfilesInfo`` (``BF2D``) and return a decoded table."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    orchestrator, channel, _cfg = _make_orchestrator(reader_index)

    rows: list[dict[str, Any]] = []
    raw_hex = ""
    sw_info = "9000"
    note_parts: list[str] = []
    trace_sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            orchestrator._phase_connect()
            raw = orchestrator._send_es10b_store_data(
                bytes.fromhex("BF2D00"),
                "GUI: GetProfilesInfo",
            )
        raw_hex = raw.hex().upper()
        parsed = _tlv_parse(raw)
        entries = _tlv_as_list(parsed.get(0xE3))
        for entry in entries:
            rows.append(_decode_profile_entry(entry))
        if len(rows) == 0:
            note_parts.append("no E3 profile records in response")
    except Exception as error:  # noqa: BLE001 — surface transport/TLV failures
        sw_info = "error"
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_apdu_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": reader_name or "(default)",
        "count": len(rows),
        "rows": rows,
        "raw_hex": raw_hex,
        "sw": sw_info,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


# ----------------------------------------------------------------------
# Configured SM-DP+ / SM-DS
# ----------------------------------------------------------------------


def _dispatch_get_smdp(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Fetch ``EuiccConfiguredData`` (``BF3C``) and return the addresses."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    orchestrator, channel, _cfg = _make_orchestrator(reader_index)
    trace_sink = io.StringIO()
    raw_hex = ""
    lines: list[dict[str, str]] = []
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            orchestrator._phase_connect()
            raw = orchestrator._send_es10b_store_data(
                bytes.fromhex("BF3C00"),
                "GUI: GetEuiccConfiguredData",
            )
        raw_hex = raw.hex().upper()
        parsed = _tlv_parse(raw)
        configured = _tlv_first(parsed, 0xBF3C)
        if isinstance(configured, dict):
            smdp_bytes = _tlv_first(configured, 0x80)
            smds_bytes = _tlv_first(configured, 0x81)
            if isinstance(smdp_bytes, (bytes, bytearray)):
                lines.append({
                    "label": "Default SM-DP+",
                    "value": bytes(smdp_bytes).decode("utf-8", "ignore").strip(),
                    "indent": 0,
                })
            else:
                lines.append({"label": "Default SM-DP+", "value": "(not set)", "indent": 0})
            if isinstance(smds_bytes, (bytes, bytearray)):
                lines.append({
                    "label": "Root SM-DS",
                    "value": bytes(smds_bytes).decode("utf-8", "ignore").strip(),
                    "indent": 0,
                })
            else:
                lines.append({"label": "Root SM-DS", "value": "(not set)", "indent": 0})
        else:
            note_parts.append("response did not contain a BF3C wrapper")
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_apdu_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": reader_name or "(default)",
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": len(bytes.fromhex(raw_hex)) if raw_hex else 0,
        "raw_hex": raw_hex,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


# ----------------------------------------------------------------------
# Notifications (BF28)
# ----------------------------------------------------------------------


def _dispatch_list_notifications(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Fetch pending notifications (``BF28``) and return a table."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    orchestrator, channel, _cfg = _make_orchestrator(reader_index)
    trace_sink = io.StringIO()
    rows: list[dict[str, Any]] = []
    raw_hex = ""
    note_parts: list[str] = []

    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            orchestrator._phase_connect()
            raw = orchestrator._send_es10b_store_data(
                bytes.fromhex("BF2800"),
                "GUI: ListNotifications",
            )
        raw_hex = raw.hex().upper()
        parsed = _tlv_parse(raw)
        # Response shape: BF28 { A0 { metadata-list-entries }* }
        outer = _tlv_first(parsed, 0xBF28)
        if isinstance(outer, dict):
            list_payload = _tlv_first(outer, 0xA0)
            if isinstance(list_payload, dict):
                entries_iter = _collect_nested_entries(list_payload)
            else:
                entries_iter = []
        else:
            entries_iter = []
        for entry in entries_iter:
            rows.append(_decode_notification_entry(entry))
        if len(rows) == 0:
            note_parts.append("no pending notifications")
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_apdu_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": reader_name or "(default)",
        "count": len(rows),
        "rows": rows,
        "raw_hex": raw_hex,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _collect_nested_entries(payload: dict[int, Any]) -> list[Any]:
    """Extract every BF2F notification metadata block from an A0 wrapper.

    Some eUICC vendors wrap each entry in BF2F (as per SGP.22), others
    emit the entry directly. Accept both shapes.
    """
    entries = _tlv_as_list(payload.get(0xBF2F))
    if len(entries) > 0:
        return entries
    # Fallback: A0 may itself contain the entry tags directly. Return the
    # dict verbatim so the row decoder can pick what it needs.
    return [payload]


def _decode_notification_entry(entry: Any) -> dict[str, Any]:
    """Decode a single notification metadata block into a row."""
    parsed: dict[int, Any]
    if isinstance(entry, dict):
        parsed = entry
    elif isinstance(entry, (bytes, bytearray)):
        try:
            parsed = _tlv_parse(bytes(entry))
        except Exception:  # noqa: BLE001
            return {"seq": "", "event": "", "address": "", "iccid": "", "raw_hex": bytes(entry).hex().upper()}
    else:
        return {"seq": "", "event": "", "address": "", "iccid": "", "raw_hex": ""}

    seq_bytes = _tlv_first(parsed, 0x80)
    event_bytes = _tlv_first(parsed, 0x81)
    address_bytes = _tlv_first(parsed, 0x0C)
    iccid_bytes = _tlv_first(parsed, 0x5A)

    seq = (
        str(int.from_bytes(bytes(seq_bytes), "big"))
        if isinstance(seq_bytes, (bytes, bytearray))
        else ""
    )
    event_bitmap = (
        int.from_bytes(bytes(event_bytes), "big")
        if isinstance(event_bytes, (bytes, bytearray))
        else 0
    )
    event_labels: list[str] = []
    # SGP.22 §2.6.5 NotificationEvent bit positions (bit 7 = MSB of first byte).
    if event_bitmap & 0x80:
        event_labels.append("notificationInstall")
    if event_bitmap & 0x40:
        event_labels.append("notificationEnable")
    if event_bitmap & 0x20:
        event_labels.append("notificationDisable")
    if event_bitmap & 0x10:
        event_labels.append("notificationDelete")
    event_text = ",".join(event_labels) if len(event_labels) > 0 else f"0x{event_bitmap:02X}"

    address_text = (
        bytes(address_bytes).decode("utf-8", "ignore").strip()
        if isinstance(address_bytes, (bytes, bytearray))
        else ""
    )
    iccid_hex = (
        bytes(iccid_bytes).hex().upper() if isinstance(iccid_bytes, (bytes, bytearray)) else ""
    )
    iccid_display = _swap_nibbles(iccid_hex)

    return {
        "seq": seq,
        "event": event_text,
        "address": address_text,
        "iccid": iccid_display,
    }


# ----------------------------------------------------------------------
# EuiccInfo2 (BF22)
# ----------------------------------------------------------------------


def _dispatch_get_euicc_info2(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Fetch ``EUICCInfo2`` (``BF22``) and return the raw hex + decoded summary."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    orchestrator, channel, _cfg = _make_orchestrator(reader_index)
    trace_sink = io.StringIO()
    raw_hex = ""
    lines: list[dict[str, str]] = []
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            orchestrator._phase_connect()
            raw = orchestrator._send_es10b_store_data(
                bytes.fromhex("BF2200"),
                "GUI: GetEUICCInfo2",
            )
        raw_hex = raw.hex().upper()
        lines = _build_euicc_info2_lines(raw)
        if len(lines) == 0:
            note_parts.append("response did not contain a BF22 wrapper")
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        _close_apdu_channel(channel)

    return {
        "reader_index": reader_index,
        "reader_name": reader_name or "(default)",
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": len(bytes.fromhex(raw_hex)) if raw_hex else 0,
        "raw_hex": raw_hex,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _build_euicc_info2_lines(raw: bytes) -> list[dict[str, Any]]:
    """Use the shared ``build_euicc_info2_detail_lines`` helper if present."""
    try:
        from SCP03.logic.euicc_info2 import build_euicc_info2_detail_lines
    except ImportError:
        return []
    try:
        detail = build_euicc_info2_detail_lines(raw) or []
    except Exception:  # noqa: BLE001
        return []
    rows: list[dict[str, Any]] = []
    for entry in detail:
        if isinstance(entry, dict):
            label_text = str(entry.get("label") or entry.get("key") or "").strip()
            value_text = str(entry.get("value") or "").strip()
            indent = int(entry.get("indent") or 0)
        elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
            label_text = str(entry[0] or "").strip()
            value_text = str(entry[1] or "").strip()
            indent = int(entry[2]) if len(entry) > 2 else 0
        else:
            label_text = ""
            value_text = str(entry or "").strip()
            indent = 0
        if len(label_text) == 0 and len(value_text) == 0:
            continue
        rows.append({"label": label_text, "value": value_text, "indent": indent})
    return rows


def _build_euicc_info1_lines(raw: bytes) -> list[dict[str, Any]]:
    """Decode EUICCInfo1 (BF20) into key-value lines for the GUI."""
    try:
        from SCP03.logic.sgp32_decode import decode_euicc_info1_summary
    except ImportError:
        return []
    try:
        summary = decode_euicc_info1_summary(raw)
    except Exception:  # noqa: BLE001
        return []
    if len(summary) == 0:
        return []
    lines: list[dict[str, Any]] = []
    svn = str(summary.get("svn", "")).strip()
    if len(svn) > 0:
        lines.append({"label": "SVN", "value": svn, "indent": 0})
    lines.append({
        "label": "CI PK Verification Entries",
        "value": str(summary.get("ci_pk_verify_entries", 0)),
        "indent": 0,
    })
    lines.append({
        "label": "CI PK Signing Entries",
        "value": str(summary.get("ci_pk_sign_entries", 0)),
        "indent": 0,
    })
    return lines


def _build_rat_lines(raw: bytes) -> list[dict[str, Any]]:
    """Decode GetRAT (BF43) into key-value lines for the GUI."""
    try:
        from SCP03.logic.sgp32_decode import decode_rat_rules
    except ImportError:
        return []
    try:
        rules = decode_rat_rules(raw)
    except Exception:  # noqa: BLE001
        return []
    if len(rules) == 0:
        return [{"label": "Rules", "value": "0 (empty)", "indent": 0}]
    lines: list[dict[str, Any]] = []
    lines.append({"label": "Rules", "value": str(len(rules)), "indent": 0})
    first_rule = rules[0]
    if "pprIdsRaw" in first_rule:
        lines.append({"label": "PPR IDs (raw)", "value": str(first_rule["pprIdsRaw"]), "indent": 1})
    if "pprIds" in first_rule:
        lines.append({"label": "PPR IDs", "value": str(first_rule["pprIds"]), "indent": 1})
    if "pprFlagsRaw" in first_rule:
        lines.append({"label": "PPR Flags (raw)", "value": str(first_rule["pprFlagsRaw"]), "indent": 1})
    if "pprFlags" in first_rule:
        lines.append({"label": "PPR Flags", "value": str(first_rule["pprFlags"]), "indent": 1})
    operators = first_rule.get("allowedOperators", [])
    if isinstance(operators, list) and len(operators) > 0:
        lines.append({"label": "Allowed Operators", "value": str(len(operators)), "indent": 1})
        first_op = operators[0]
        if "mccMnc" in first_op:
            lines.append({"label": "First Operator MCC/MNC", "value": str(first_op["mccMnc"]), "indent": 2})
        if "gid1" in first_op:
            lines.append({"label": "First Operator GID1", "value": str(first_op["gid1"]), "indent": 2})
        if "gid2" in first_op:
            lines.append({"label": "First Operator GID2", "value": str(first_op["gid2"]), "indent": 2})
    return lines


def _build_certs_lines(raw: bytes) -> list[dict[str, Any]]:
    """Decode GetCerts (BF56) into key-value lines for the GUI."""
    try:
        from SCP03.logic.sgp32_decode import decode_get_certs_response
    except ImportError:
        return []
    try:
        decoded = decode_get_certs_response(raw)
    except Exception:  # noqa: BLE001
        return []
    if len(decoded) == 0:
        return [{"label": "Certificates", "value": "(empty)", "indent": 0}]
    lines: list[dict[str, Any]] = []
    if "error" in decoded:
        lines.append({"label": "Error", "value": str(decoded["error"]), "indent": 0})
        return lines
    eum = decoded.get("eumCertificate", b"")
    euicc = decoded.get("euiccCertificate", b"")
    eum_present = isinstance(eum, bytes) and len(eum) > 0
    euicc_present = isinstance(euicc, bytes) and len(euicc) > 0
    lines.append({
        "label": "EUM Certificate",
        "value": f"Present ({len(eum)} B)" if eum_present else "Absent",
        "indent": 0,
    })
    lines.append({
        "label": "eUICC Certificate",
        "value": f"Present ({len(euicc)} B)" if euicc_present else "Absent",
        "indent": 0,
    })
    return lines


def _build_eim_config_lines(raw: bytes) -> list[dict[str, Any]]:
    """Decode GetEimConfigurationData (BF55) into key-value lines for the GUI."""
    try:
        from SCP03.logic.sgp32_decode import decode_eim_configuration_entries
    except ImportError:
        return []
    try:
        entries = decode_eim_configuration_entries(raw)
    except Exception:  # noqa: BLE001
        return []
    if len(entries) == 0:
        return [{"label": "eIM Entries", "value": "0 (empty)", "indent": 0}]
    lines: list[dict[str, Any]] = []
    lines.append({"label": "eIM Entries", "value": str(len(entries)), "indent": 0})
    first = entries[0]
    fqdn = str(first.get("eim_fqdn", "")).strip()
    eim_id = str(first.get("eim_id", "")).strip()
    eim_id_type = str(first.get("eim_id_type", "")).strip()
    counter = str(first.get("counter_value", "")).strip()
    protocol = str(first.get("supported_protocol", "")).strip()
    if len(fqdn) > 0:
        lines.append({"label": "First eIM FQDN", "value": fqdn, "indent": 1})
    if len(eim_id) > 0:
        lines.append({"label": "First eIM ID", "value": eim_id, "indent": 1})
    if len(eim_id_type) > 0:
        lines.append({"label": "First eIM ID Type", "value": eim_id_type, "indent": 1})
    if len(counter) > 0:
        lines.append({"label": "First eIM Counter", "value": counter, "indent": 1})
    if len(protocol) > 0:
        lines.append({"label": "First eIM Protocol", "value": protocol, "indent": 1})
    return lines


# ----------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Drop ANSI colour escape sequences captured from stdout."""
    return _ANSI_RE.sub("", text or "")


# ----------------------------------------------------------------------
# Headless SCP11Console builder + stdout capture
# ----------------------------------------------------------------------


class _FakeClient:
    """Lightweight stand-in for ``SCP11.<package>.main.SGP22Client``.

    ``SCP11Console`` only pokes three attributes on its ``client`` argument
    (``cfg``, ``apdu_channel``, ``orchestrator``), so we can wire a
    per-call console without running the full CLI bootstrap.
    """

    __slots__ = ("cfg", "apdu_channel", "orchestrator")

    def __init__(self, cfg: Any, apdu_channel: Any, orchestrator: Any) -> None:
        self.cfg = cfg
        self.apdu_channel = apdu_channel
        self.orchestrator = orchestrator


def _build_console(reader_index: int) -> tuple[Any, Any]:
    """Instantiate a headless ``SCP11Console`` bound to a fresh channel.

    Returns ``(console, channel)``; caller must close the channel. The
    console is never driven through ``run()`` / ``run_commands()`` — we
    invoke private handlers directly so we do not have to parse CLI
    argument strings or replay the snapshot pane.
    """
    SGPConfig = getattr(_provider_module("config"), "SGPConfig")
    SCP11Console = getattr(_provider_module("console"), "SCP11Console")
    SGP22Orchestrator = getattr(_provider_module("orchestrator"), "SGP22Orchestrator")

    base_cfg = SGPConfig()
    cfg = replace(base_cfg, READER_INDEX=int(reader_index))
    channel = _build_apdu_channel(int(reader_index))
    orchestrator = SGP22Orchestrator(cfg=cfg, apdu_channel=channel)
    fake = _FakeClient(cfg=cfg, apdu_channel=channel, orchestrator=orchestrator)
    console = SCP11Console(fake)
    return console, channel


def _capture_stdout(
    callable_: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> tuple[Any, str]:
    """Run ``callable_(*args, **kwargs)`` with stdout+stderr captured.

    Returns ``(result, trace_text)`` with ANSI stripped. Exceptions
    propagate — the caller decides how to surface them in the response.
    """
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        result = callable_(*args, **kwargs)
    return result, _strip_ansi(sink.getvalue())


def _run_console_handler(
    reader_index: int,
    handler_name: str,
    argument: str = "",
    *,
    connect_first: bool = True,
) -> tuple[Any, str, str]:
    """Construct a per-call console, invoke ``handler_name``, tear down.

    Returns ``(result, trace, reader_label)``. ``reader_label`` is a
    display-ready string ("(default)" when no reader was picked).
    """
    console, channel = _build_console(int(reader_index))
    try:
        if connect_first:
            try:
                console.orchestrator._phase_connect()
            except Exception:
                # Let the handler's own error path surface a descriptive
                # message; we deliberately do not double-report here.
                pass
        handler = getattr(console, handler_name)
        result, trace = _capture_stdout(handler, argument)
    finally:
        _close_apdu_channel(channel)
    return result, trace, "(default)"


def _run_console_callable(
    reader_index: int,
    work: Callable[[Any], Any],
    *,
    connect_first: bool = True,
) -> tuple[Any, str]:
    """Run ``work(console)`` inside a captured-stdout context.

    Hands the caller full access to the console (useful when they need
    to invoke several helpers or inspect state post-call) without
    forcing everyone through ``_run_console_handler``.
    """
    console, channel = _build_console(int(reader_index))
    try:
        if connect_first:
            try:
                console.orchestrator._phase_connect()
            except Exception:
                pass
        result, trace = _capture_stdout(work, console)
    finally:
        _close_apdu_channel(channel)
    return result, trace


# ----------------------------------------------------------------------
# Log-stream helpers (async tee for WS dispatchers)
# ----------------------------------------------------------------------


def _infer_level(line: str) -> str:
    """Best-effort log-level mapping for captured console output."""
    lowered = line.lower()
    if "[-]" in line or "error" in lowered or "failed" in lowered:
        return "error"
    if "warn" in lowered or "[!]" in line[:6]:
        return "warn"
    if "[+]" in line or "ok" in lowered or "\u2713" in line:
        return "info"
    return "info"


class _CapturingStream(io.TextIOBase):
    """Line-buffered text sink that forwards every ``\\n``-terminated
    chunk to ``post(level, message)`` on the caller's loop.

    ``\\r``-style progress redraws are absorbed so we never flood the
    stream socket with per-keystroke events.
    """

    def __init__(self, post: Callable[..., None]) -> None:
        super().__init__()
        self._post = post
        self._buffer = ""

    def write(self, data: str) -> int:  # type: ignore[override]
        """Serialise and write the SCP11-live action result to the response stream."""
        self._buffer += data
        while "\n" in self._buffer:
            line, _, rest = self._buffer.partition("\n")
            self._buffer = rest
            line = _ANSI_RE.sub("", line)
            if len(line) == 0:
                continue
            self._post(_infer_level(line), line)
        return len(data)

    def flush(self) -> None:  # type: ignore[override]
        if len(self._buffer) > 0:
            line = _ANSI_RE.sub("", self._buffer)
            self._buffer = ""
            if len(line) > 0:
                self._post(_infer_level(line), line)


async def _stream_console(
    reader_index: int,
    handler_name: str,
    argument: str = "",
    *,
    connect_first: bool = True,
    start_message: Optional[str] = None,
    done_message: str = "complete.",
) -> AsyncIterator[dict[str, Any]]:
    """Async-generator tee: run a console handler in a background thread
    and yield every captured stdout line as a stream event.

    The event contract matches the generic ``/api/actions/{id}/stream``
    route: each yielded dict has at least ``level`` + ``message``. A
    terminal ``level="done"`` event is always emitted (on error too).
    """
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    def _post(level: str, message: str, **extra: Any) -> None:
        event: dict[str, Any] = {"level": level, "message": message}
        if len(extra) > 0:
            event.update(extra)
        loop.call_soon_threadsafe(queue.put_nowait, event)

    def _worker() -> None:
        console: Any = None
        channel: Any = None
        try:
            console, channel = _build_console(int(reader_index))
        except Exception as error:
            _post("error", f"reader bind failed: {type(error).__name__}: {error}")
            _post("done", done_message, ok=False)
            return
        try:
            if connect_first:
                try:
                    with contextlib.redirect_stdout(_CapturingStream(_post)), \
                         contextlib.redirect_stderr(_CapturingStream(_post)):
                        console.orchestrator._phase_connect()
                except Exception as error:
                    _post("error", f"connect failed: {type(error).__name__}: {error}")
                    _post("done", done_message, ok=False)
                    return
            stream_stdout = _CapturingStream(_post)
            stream_stderr = _CapturingStream(_post)
            try:
                with contextlib.redirect_stdout(stream_stdout), \
                     contextlib.redirect_stderr(stream_stderr):
                    handler = getattr(console, handler_name)
                    handler(argument)
                stream_stdout.flush()
                stream_stderr.flush()
            except Exception as error:
                _post("error", f"{type(error).__name__}: {error}")
                for trace_line in traceback.format_exc().splitlines():
                    _post("error", trace_line)
                _post("done", done_message, ok=False)
                return
            _post("done", done_message, ok=True)
        finally:
            try:
                _close_apdu_channel(channel)
            except Exception:
                pass

    if start_message is not None and len(start_message) > 0:
        yield {"level": "info", "message": start_message}

    thread = threading.Thread(
        target=_worker,
        name=f"scp11_live-stream-{handler_name}",
        daemon=True,
    )
    thread.start()

    while True:
        event = await queue.get()
        yield event
        if event.get("level") == "done":
            break


# ----------------------------------------------------------------------
# Destructive-action confirm guard
# ----------------------------------------------------------------------


_CONFIRM_ERROR = (
    "destructive action: tick the 'I understand this modifies the card "
    "or persistent config' checkbox to confirm before running."
)


def _require_confirm(confirm: Any) -> None:
    """Raise ``ValueError`` if the per-call confirm checkbox is not set.

    Kept as a plain function (rather than a per-action env flag) so the
    gate is visible in the action form and never appears in the env
    config panel.
    """
    if not bool(confirm):
        raise ValueError(_CONFIRM_ERROR)


def _confirm_field(
    *,
    label: str = "I understand this modifies the card or persistent config",
    help_text: str = (
        "Required: must be ticked for the dispatcher to run. Not stored "
        "in any environment flag."
    ),
) -> ActionField:
    """Standard destructive-action confirm checkbox factory."""
    return ActionField(
        name="confirm",
        label=label,
        kind="bool",
        required=False,
        default=False,
        help=help_text,
    )


def _reader_input_field() -> ActionField:
    """Shared 'Reader' field factory for every card-touching action."""
    return ActionField(
        name="reader",
        label="Reader",
        kind="reader",
        required=False,
        default="",
        help="PC/SC reader name (leave empty for the first reader).",
    )


# ----------------------------------------------------------------------
# Tranche 1 — read-only expansion (direct orchestrator / console reads)
# ----------------------------------------------------------------------


def _orchestrator_store_data(
    reader_index: int,
    payload_hex: str,
    log_name: str,
) -> tuple[bytes, str]:
    """Run a single ES10b GET with a captured-stdout trace.

    Returns ``(response_bytes, trace_text)``. Raises on transport errors
    (same as the orchestrator primitive).
    """
    orchestrator, channel, _cfg = _make_orchestrator(int(reader_index))
    trace_sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            orchestrator._phase_connect()
            raw = orchestrator._send_es10b_store_data(
                bytes.fromhex(payload_hex),
                log_name,
            )
    finally:
        _close_apdu_channel(channel)
    return raw, _strip_ansi(trace_sink.getvalue())


def _reader_label(reader_name: str) -> str:
    if len(str(reader_name or "").strip()) == 0:
        return "(default)"
    return str(reader_name)


def _dispatch_get_euicc_info1(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Fetch ``EuiccInfo1`` (``BF2000``) and return decoded key-value lines."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    raw_hex = ""
    detail_lines: list[dict[str, Any]] = []
    trace_parts: list[str] = []
    note_parts: list[str] = []
    try:
        raw, trace = _orchestrator_store_data(
            reader_index, "BF2000", "GUI: GetEuiccInfo1"
        )
        raw_hex = raw.hex().upper()
        trace_parts.append(trace)
        if len(raw) > 0:
            detail_lines = _build_euicc_info1_lines(raw)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "detail_lines": detail_lines,
        "validation_lines": [],
        "input_length": len(bytes.fromhex(raw_hex)) if raw_hex else 0,
        "raw_hex": raw_hex,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": "".join(trace_parts),
    }


def _dispatch_get_rat(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Fetch ``RulesAuthorisationTable`` (``BF4300``) and return decoded key-value lines."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    raw_hex = ""
    detail_lines: list[dict[str, Any]] = []
    trace = ""
    note_parts: list[str] = []
    try:
        raw, trace = _orchestrator_store_data(
            reader_index, "BF4300", "GUI: GetRAT"
        )
        raw_hex = raw.hex().upper()
        if len(raw) > 0:
            detail_lines = _build_rat_lines(raw)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "detail_lines": detail_lines,
        "validation_lines": [],
        "input_length": len(bytes.fromhex(raw_hex)) if raw_hex else 0,
        "raw_hex": raw_hex,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": trace,
    }


def _dispatch_get_certs(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Fetch the eUICC ``GetCerts`` map (``BF5600``) and return decoded key-value lines."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    raw_hex = ""
    detail_lines: list[dict[str, Any]] = []
    trace = ""
    note_parts: list[str] = []
    try:
        raw, trace = _orchestrator_store_data(
            reader_index, "BF5600", "GUI: GetCerts"
        )
        raw_hex = raw.hex().upper()
        if len(raw) > 0:
            detail_lines = _build_certs_lines(raw)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "detail_lines": detail_lines,
        "validation_lines": [],
        "input_length": len(bytes.fromhex(raw_hex)) if raw_hex else 0,
        "raw_hex": raw_hex,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": trace,
    }


def _dispatch_get_eim_config(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Fetch ``GetEimConfigurationData`` (``BF5500``) and return decoded key-value lines."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    raw_hex = ""
    detail_lines: list[dict[str, Any]] = []
    trace = ""
    note_parts: list[str] = []
    try:
        raw, trace = _orchestrator_store_data(
            reader_index, "BF5500", "GUI: GetEimConfigurationData"
        )
        raw_hex = raw.hex().upper()
        if len(raw) > 0:
            detail_lines = _build_eim_config_lines(raw)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "detail_lines": detail_lines,
        "validation_lines": [],
        "input_length": len(bytes.fromhex(raw_hex)) if raw_hex else 0,
        "raw_hex": raw_hex,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": trace,
    }


def _dispatch_aids(ctx: ActionContext) -> dict[str, Any]:
    """Return the local AID alias registry (no card required)."""
    try:
        from SCP11.config import SCP03Config
    except ImportError:  # pragma: no cover — defensive
        SCP03Config = None  # type: ignore[assignment]

    path = ""
    try:
        path = getattr(SCP03Config, "AID_FILE", "") if SCP03Config is not None else ""
    except Exception:  # noqa: BLE001
        path = ""

    rows: list[dict[str, str]] = []
    note_parts: list[str] = []
    if len(path) > 0:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if len(line) == 0 or line.startswith("#"):
                        continue
                    parts = line.split(maxsplit=1)
                    aid = parts[0].strip().upper()
                    alias = parts[1].strip() if len(parts) > 1 else ""
                    if len(aid) == 0:
                        continue
                    rows.append({"aid": aid, "alias": alias})
        except FileNotFoundError:
            note_parts.append(f"aid.txt not found at {path}")
        except Exception as error:  # noqa: BLE001
            note_parts.append(f"{type(error).__name__}: {error}")
    else:
        note_parts.append("no AID alias registry configured")

    return {
        "path": path,
        "count": len(rows),
        "rows": rows,
        "note": "; ".join(note_parts) if note_parts else "ok",
    }


def _dispatch_status(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Compact 'configured-data' snapshot: EID + default SM-DP+ + root SM-DS."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    eid = ""
    lines: list[dict[str, str]] = []
    note_parts: list[str] = []

    orchestrator, channel, _cfg = _make_orchestrator(reader_index)
    trace_sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            try:
                eid = str(orchestrator._read_card_eid(reselect_isdr=False) or "").strip()
            except Exception as error:  # noqa: BLE001
                note_parts.append(f"EID read failed: {type(error).__name__}: {error}")
            try:
                orchestrator._phase_connect()
                raw = orchestrator._send_es10b_store_data(
                    bytes.fromhex("BF3C00"),
                    "GUI: GetEuiccConfiguredData",
                )
                parsed = _tlv_parse(raw)
                configured = _tlv_first(parsed, 0xBF3C)
                if isinstance(configured, dict):
                    smdp_bytes = _tlv_first(configured, 0x80)
                    smds_bytes = _tlv_first(configured, 0x81)
                    if isinstance(smdp_bytes, (bytes, bytearray)):
                        lines.append({
                            "label": "Default SM-DP+",
                            "value": bytes(smdp_bytes).decode("utf-8", "ignore").strip(),
                            "indent": 0,
                        })
                    else:
                        lines.append({"label": "Default SM-DP+", "value": "(not set)", "indent": 0})
                    if isinstance(smds_bytes, (bytes, bytearray)):
                        lines.append({
                            "label": "Root SM-DS",
                            "value": bytes(smds_bytes).decode("utf-8", "ignore").strip(),
                            "indent": 0,
                        })
                    else:
                        lines.append({"label": "Root SM-DS", "value": "(not set)", "indent": 0})
            except Exception as error:  # noqa: BLE001
                note_parts.append(f"configured-data read failed: {type(error).__name__}: {error}")
    finally:
        _close_apdu_channel(channel)

    lines.insert(0, {"label": "EID", "value": eid or "(unavailable)", "indent": 0})
    lines.insert(1, {"label": "Reader", "value": _reader_label(reader_name), "indent": 0})

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "eid": eid,
        "detail_lines": lines,
        "validation_lines": [],
        "input_length": 0,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_scan(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Mimic the shell ``SCAN`` pinned-snapshot summary (compact)."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)

    def _work(console: Any) -> dict[str, Any]:
        snapshot = console._collect_snapshot()
        profiles: list[dict[str, Any]] = []
        for row in getattr(snapshot, "profiles", []) or []:
            profiles.append({
                "iccid": getattr(row, "iccid", ""),
                "aid": getattr(row, "aid", ""),
                "state": getattr(row, "state", ""),
                "profile_class": getattr(row, "profile_class", ""),
                "nickname": getattr(row, "nickname", ""),
            })
        return {
            "eid": getattr(snapshot, "eid", ""),
            "issuer_number": getattr(snapshot, "issuer_number", ""),
            "issuer_name": getattr(snapshot, "issuer_name", ""),
            "profiles": profiles,
            "notification_count": int(getattr(snapshot, "notification_count", 0) or 0),
            "euicc_info2_summary": dict(getattr(snapshot, "euicc_info2_summary", {}) or {}),
            "eim_summary": dict(getattr(snapshot, "eim_summary", {}) or {}),
        }

    note_parts: list[str] = []
    result: dict[str, Any] = {}
    trace = ""
    try:
        result, trace = _run_console_callable(reader_index, _work, connect_first=False)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "snapshot": result or {},
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": trace,
    }


def _profile_metadata_view_to_dict(entry: Any) -> dict[str, Any]:
    """Normalise a ``ProfileMetadataView`` dataclass to a plain dict."""
    extra_pairs: list[dict[str, str]] = []
    for pair in getattr(entry, "additional_fields", []) or []:
        try:
            label, value = pair
        except Exception:  # noqa: BLE001
            continue
        extra_pairs.append({"label": str(label), "value": str(value)})
    return {
        "iccid": str(getattr(entry, "iccid", "") or ""),
        "aid": str(getattr(entry, "aid", "") or ""),
        "state": str(getattr(entry, "state", "") or ""),
        "profile_class": str(getattr(entry, "profile_class", "") or ""),
        "nickname": str(getattr(entry, "nickname", "") or ""),
        "service_provider": str(getattr(entry, "service_provider", "") or ""),
        "profile_name": str(getattr(entry, "profile_name", "") or ""),
        "profile_policy_rules_hex": str(getattr(entry, "profile_policy_rules_hex", "") or ""),
        "additional_fields": extra_pairs,
    }


def _dispatch_read_metadata(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Collect ``ProfileMetadataView`` rows for every on-card profile."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)

    def _work(console: Any) -> list[dict[str, Any]]:
        entries = console._collect_profile_metadata() or []
        return [_profile_metadata_view_to_dict(entry) for entry in entries]

    note_parts: list[str] = []
    rows: list[dict[str, Any]] = []
    trace = ""
    try:
        rows, trace = _run_console_callable(reader_index, _work)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "count": len(rows),
        "rows": rows,
        "note": "; ".join(note_parts) if note_parts else "ok",
        "trace": trace,
    }


def _dispatch_get_metadata(
    ctx: ActionContext,
    *,
    reader: Any = None,
    target: Any = None,
) -> dict[str, Any]:
    """Return the full metadata view for a single profile (id / aid / alias)."""
    identifier = str(target or "").strip()
    if len(identifier) == 0:
        raise ValueError("target is required (ICCID, AID, or alias).")

    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)

    def _work(console: Any) -> Optional[dict[str, Any]]:
        metadata = console._find_profile_metadata(identifier)
        if metadata is None:
            return None
        return _profile_metadata_view_to_dict(metadata)

    note_parts: list[str] = []
    view: Optional[dict[str, Any]] = None
    trace = ""
    try:
        view, trace = _run_console_callable(reader_index, _work)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    found = view is not None
    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "target": identifier,
        "found": found,
        "metadata": view or {},
        "note": (
            "; ".join(note_parts)
            if note_parts
            else ("ok" if found else "profile not found")
        ),
        "trace": trace,
    }


def _dispatch_get_pol(
    ctx: ActionContext,
    *,
    reader: Any = None,
    target: Any = None,
) -> dict[str, Any]:
    """Return Profile Policy Rules hex + decoded names for one profile."""
    identifier = str(target or "").strip()
    if len(identifier) == 0:
        raise ValueError("target is required (ICCID, AID, or alias).")

    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)

    def _work(console: Any) -> dict[str, Any]:
        metadata = console._find_profile_metadata(identifier)
        if metadata is None:
            return {"found": False}
        ppr_hex = str(getattr(metadata, "profile_policy_rules_hex", "") or "")
        decoded = ""
        if len(ppr_hex) > 0:
            try:
                decoded = console._decode_ppr_ids(ppr_hex)
            except Exception as error:  # noqa: BLE001
                decoded = f"decode failed: {error}"
        return {
            "found": True,
            "iccid": str(getattr(metadata, "iccid", "") or ""),
            "aid": str(getattr(metadata, "aid", "") or ""),
            "ppr_hex": ppr_hex,
            "ppr_decoded": decoded,
        }

    note_parts: list[str] = []
    data: dict[str, Any] = {"found": False}
    trace = ""
    try:
        data, trace = _run_console_callable(reader_index, _work)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    detail_lines: list[dict[str, Any]] = []
    if data.get("found"):
        detail_lines.append({"label": "ICCID", "value": str(data.get("iccid") or ""), "indent": 0})
        detail_lines.append({"label": "AID", "value": str(data.get("aid") or ""), "indent": 0})
        detail_lines.append({"label": "PPR Raw", "value": str(data.get("ppr_hex") or "(not present)"), "indent": 0})
        detail_lines.append({"label": "PPR Decoded", "value": str(data.get("ppr_decoded") or "none"), "indent": 0})
    else:
        detail_lines.append({"label": "Target", "value": identifier, "indent": 0})
        detail_lines.append({"label": "Result", "value": "profile not found", "indent": 0})

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "target": identifier,
        "detail_lines": detail_lines,
        "validation_lines": [],
        "input_length": 0,
        "note": "; ".join(note_parts) if note_parts else ("ok" if data.get("found") else "profile not found"),
        "trace": trace,
    }


def _dispatch_get_all_data(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Run the consolidated discovery suite (captured-stdout report)."""
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    note_parts: list[str] = []
    trace = ""
    try:
        _, trace, _ = _run_console_handler(
            reader_index,
            "_cmd_get_all_data",
            argument="",
        )
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "report": trace,
        "note": "; ".join(note_parts) if note_parts else "ok",
    }


def _dispatch_get_es9(ctx: ActionContext) -> dict[str, Any]:
    """Return the ES9 cfg view for the active provider flavour."""
    SGPConfig = None  # type: ignore[assignment]
    try:
        SGPConfig = getattr(_provider_module("config"), "SGPConfig")
    except Exception:  # pragma: no cover — config module missing / bad
        SGPConfig = None  # type: ignore[assignment]

    cfg = SGPConfig() if SGPConfig is not None else None
    detail_lines = [
        {
            "label": "ES9 Base URL",
            "value": str(getattr(cfg, "ES9_BASE_URL", "") or "(unset)"),
            "indent": 0,
        },
        {
            "label": "ES9 TLS Verification",
            "value": "ON" if bool(getattr(cfg, "ES9_VERIFY_TLS", False)) else "OFF",
            "indent": 0,
        },
        {
            "label": "ES9 CA Bundle",
            "value": str(getattr(cfg, "ES9_CA_BUNDLE_PATH", "") or "(system trust)"),
            "indent": 0,
        },
        {
            "label": "Default SM-DP+ (cfg)",
            "value": str(getattr(cfg, "RSP_SERVER_URL", "") or "(unset)"),
            "indent": 0,
        },
    ]
    return {
        "detail_lines": detail_lines,
        "validation_lines": [],
        "input_length": 0,
        "note": "ok" if cfg is not None else (
            f"SCP11.{_active_provider_package()}.config unavailable"
        ),
    }


def _dispatch_es9_cert_info(ctx: ActionContext) -> dict[str, Any]:
    """Probe the ES9 endpoint TLS chain (captured-stdout report)."""

    def _work(console: Any) -> None:
        console._print_es9_cert_info()

    note_parts: list[str] = []
    trace = ""
    try:
        _, trace = _run_console_callable(0, _work, connect_first=False)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "report": trace,
        "note": "; ".join(note_parts) if note_parts else "ok",
    }


# ----------------------------------------------------------------------
# Tranche 2 — config writes (require confirm checkbox)
# ----------------------------------------------------------------------


def _dispatch_set_smdp(
    ctx: ActionContext,
    *,
    reader: Any = None,
    address: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """Push a new default SM-DP+ address to the card / inventory."""
    _require_confirm(confirm)
    value = str(address or "").strip()
    if len(value) == 0:
        raise ValueError("address is required.")
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)

    def _work(console: Any) -> str:
        console._set_smdp_address(value)
        return str(console.current_smdp_address or "")

    try:
        applied, trace = _run_console_callable(reader_index, _work, connect_first=False)
    except Exception as error:  # noqa: BLE001
        return {
            "reader_index": reader_index,
            "reader_name": _reader_label(reader_name),
            "ok": False,
            "note": f"{type(error).__name__}: {error}",
            "trace": "",
        }

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "address_applied": applied,
        "ok": True,
        "note": "ok",
        "trace": trace,
    }


def _dispatch_set_es9(
    ctx: ActionContext,
    *,
    url: Any = None,
    persist: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """Switch the active ES9 base URL (optionally persist to config.py)."""
    _require_confirm(confirm)
    text = str(url or "").strip()
    if len(text) == 0:
        raise ValueError("url is required.")
    lowered = text.lower()
    if lowered.startswith("http://") is False and lowered.startswith("https://") is False:
        raise ValueError("url must start with http:// or https://")
    persist_flag = bool(persist)

    def _work(console: Any) -> dict[str, Any]:
        ok = console._set_es9_base_url(text, source="manual")
        if ok and persist_flag:
            console._persist_es9_base_url(console.current_es9_base_url)
        return {
            "ok": bool(ok),
            "applied": str(console.current_es9_base_url or ""),
            "persisted": bool(ok and persist_flag),
        }

    try:
        result, trace = _run_console_callable(0, _work, connect_first=False)
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "note": f"{type(error).__name__}: {error}",
            "trace": "",
        }

    return {
        "ok": bool(result.get("ok")),
        "applied": result.get("applied", ""),
        "persisted": bool(result.get("persisted")),
        "note": "ok" if result.get("ok") else "provider rejected ES9 base URL",
        "trace": trace,
    }


def _dispatch_set_es9_tls(
    ctx: ActionContext,
    *,
    mode: Any = None,
    persist: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """Toggle ES9 TLS verification (optionally persist)."""
    _require_confirm(confirm)
    raw_mode = str(mode or "").strip().lower()
    if raw_mode in ("on", "true", "1", "yes"):
        enabled = True
    elif raw_mode in ("off", "false", "0", "no"):
        enabled = False
    else:
        raise ValueError("mode must be one of: on, off.")
    persist_flag = bool(persist)

    def _work(console: Any) -> dict[str, Any]:
        ok = console._set_es9_tls_verify(enabled)
        if ok and persist_flag:
            console._persist_es9_verify_tls(console.current_es9_verify_tls)
        return {
            "ok": bool(ok),
            "enabled": bool(console.current_es9_verify_tls),
            "persisted": bool(ok and persist_flag),
        }

    try:
        result, trace = _run_console_callable(0, _work, connect_first=False)
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "note": f"{type(error).__name__}: {error}",
            "trace": "",
        }

    return {
        "ok": bool(result.get("ok")),
        "enabled": bool(result.get("enabled")),
        "persisted": bool(result.get("persisted")),
        "note": "ok" if result.get("ok") else "provider rejected ES9 TLS toggle",
        "trace": trace,
    }


def _dispatch_set_es9_ca(
    ctx: ActionContext,
    *,
    path: Any = None,
    persist: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """Point ES9 at a specific CA bundle (``NONE`` clears to system trust)."""
    _require_confirm(confirm)
    text = str(path or "").strip()
    if text.upper() == "NONE":
        text = ""
    persist_flag = bool(persist)

    def _work(console: Any) -> dict[str, Any]:
        ok = console._set_es9_ca_bundle_path(text)
        if ok and persist_flag:
            console._persist_es9_ca_bundle_path(console.current_es9_ca_bundle_path)
        return {
            "ok": bool(ok),
            "applied": str(console.current_es9_ca_bundle_path or ""),
            "persisted": bool(ok and persist_flag),
        }

    try:
        result, trace = _run_console_callable(0, _work, connect_first=False)
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "note": f"{type(error).__name__}: {error}",
            "trace": "",
        }

    return {
        "ok": bool(result.get("ok")),
        "applied": result.get("applied", ""),
        "persisted": bool(result.get("persisted")),
        "note": "ok" if result.get("ok") else "provider rejected ES9 CA bundle",
        "trace": trace,
    }


# ----------------------------------------------------------------------
# Tranche 3 — card mutations (require confirm checkbox)
# ----------------------------------------------------------------------


def _run_guarded_console_handler(
    reader_index: int,
    handler_name: str,
    argument: str,
) -> dict[str, Any]:
    """Shared skeleton for destructive console handlers.

    Always returns a dict-shape result ``{ok, note, trace}`` — the
    dispatchers add their own extra fields on top.
    """
    try:
        _, trace, _ = _run_console_handler(
            reader_index, handler_name, argument=argument
        )
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "note": f"{type(error).__name__}: {error}",
            "trace": "",
        }
    ok = True
    lowered = trace.lower()
    if "[-]" in trace or "failed" in lowered or "error" in lowered:
        ok = False
    return {
        "ok": ok,
        "note": "ok" if ok else "see trace for details",
        "trace": trace,
    }


def _dispatch_enable_profile(
    ctx: ActionContext,
    *,
    reader: Any = None,
    target: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    _require_confirm(confirm)
    identifier = str(target or "").strip()
    if len(identifier) == 0:
        raise ValueError("target is required (ICCID, AID, or alias).")
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    result = _run_guarded_console_handler(
        reader_index, "_cmd_enable_profile", identifier
    )
    result.update({
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "target": identifier,
    })
    return result


def _dispatch_disable_profile(
    ctx: ActionContext,
    *,
    reader: Any = None,
    target: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    _require_confirm(confirm)
    identifier = str(target or "").strip()
    if len(identifier) == 0:
        raise ValueError("target is required (ICCID, AID, or alias).")
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    result = _run_guarded_console_handler(
        reader_index, "_cmd_disable_profile", identifier
    )
    result.update({
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "target": identifier,
    })
    return result


def _dispatch_delete_profile(
    ctx: ActionContext,
    *,
    reader: Any = None,
    target: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    _require_confirm(confirm)
    identifier = str(target or "").strip()
    if len(identifier) == 0:
        raise ValueError("target is required (ICCID, AID, or alias).")
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    result = _run_guarded_console_handler(
        reader_index, "_cmd_delete_profile", identifier
    )
    result.update({
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "target": identifier,
    })
    return result


def _dispatch_refresh_modem(
    ctx: ActionContext,
    *,
    reader: Any = None,
    mode: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    _require_confirm(confirm)
    mode_text = str(mode or "").strip()
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    result = _run_guarded_console_handler(
        reader_index, "_cmd_refresh_modem", mode_text
    )
    result.update({
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "mode": mode_text or "(euicc-profile-state-change)",
    })
    return result


def _dispatch_reset_card(
    ctx: ActionContext,
    *,
    reader: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    _require_confirm(confirm)
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    result = _run_guarded_console_handler(
        reader_index, "_cmd_reset", ""
    )
    result.update({
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
    })
    return result


def _dispatch_remove_notification(
    ctx: ActionContext,
    *,
    reader: Any = None,
    seq: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    _require_confirm(confirm)
    try:
        seq_int = int(seq)
    except Exception as error:  # noqa: BLE001
        raise ValueError("seq must be a non-negative integer.") from error
    if seq_int < 0:
        raise ValueError("seq must be non-negative.")
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    result = _run_guarded_console_handler(
        reader_index, "_cmd_remove_notification", str(seq_int)
    )
    result.update({
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "seq": seq_int,
    })
    return result


def _dispatch_clear_notifications(
    ctx: ActionContext,
    *,
    reader: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    _require_confirm(confirm)
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)

    def _work(console: Any) -> int:
        return int(console._clear_notifications_internal(quiet=False) or 0)

    try:
        count, trace = _run_console_callable(reader_index, _work)
    except Exception as error:  # noqa: BLE001
        return {
            "reader_index": reader_index,
            "reader_name": _reader_label(reader_name),
            "ok": False,
            "note": f"{type(error).__name__}: {error}",
            "cleared": 0,
            "trace": "",
        }

    return {
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "ok": True,
        "cleared": int(count),
        "note": "ok",
        "trace": trace,
    }


def _dispatch_set_pol(
    ctx: ActionContext,
    *,
    reader: Any = None,
    target: Any = None,
    pol_hex: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    _require_confirm(confirm)
    identifier = str(target or "").strip()
    if len(identifier) == 0:
        raise ValueError("target is required (ICCID, AID, or alias).")
    payload_hex = str(pol_hex or "").strip().upper().replace(" ", "")
    if len(payload_hex) == 0:
        raise ValueError("pol_hex is required.")
    try:
        bytes.fromhex(payload_hex)
    except ValueError as error:
        raise ValueError("pol_hex must be valid hex.") from error

    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    argument = f"{identifier} {payload_hex}"
    result = _run_guarded_console_handler(
        reader_index, "_cmd_set_pol", argument
    )
    result.update({
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "target": identifier,
        "pol_hex": payload_hex,
    })
    return result


def _dispatch_store_metadata(
    ctx: ActionContext,
    *,
    reader: Any = None,
    target: Any = None,
    metadata_hex: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    _require_confirm(confirm)
    identifier = str(target or "").strip()
    if len(identifier) == 0:
        raise ValueError("target is required (ICCID, AID, or alias).")
    payload_hex = str(metadata_hex or "").strip().upper().replace(" ", "")
    if len(payload_hex) == 0:
        raise ValueError("metadata_hex is required.")
    try:
        bytes.fromhex(payload_hex)
    except ValueError as error:
        raise ValueError("metadata_hex must be valid hex.") from error

    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    argument = f"{identifier} {payload_hex}"
    result = _run_guarded_console_handler(
        reader_index, "_cmd_store_metadata", argument
    )
    result.update({
        "reader_index": reader_index,
        "reader_name": _reader_label(reader_name),
        "target": identifier,
        "metadata_hex": payload_hex,
    })
    return result


# ----------------------------------------------------------------------
# Tranche 4 — streaming flows (async-generator dispatchers)
# ----------------------------------------------------------------------


async def _dispatch_stream_discover(
    ctx: ActionContext,
    *,
    reader: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    async for event in _stream_console(
        reader_index,
        "_cmd_eim_discover",
        argument="",
        connect_first=True,
        start_message=f"DISCOVER: reader={_reader_label(reader_name)}",
        done_message="DISCOVER complete.",
    ):
        yield event


async def _dispatch_stream_eim_authenticate(
    ctx: ActionContext,
    *,
    reader: Any = None,
    matching_id: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    identifier = str(matching_id or "").strip()
    async for event in _stream_console(
        reader_index,
        "_cmd_eim_authenticate",
        argument=identifier,
        connect_first=False,
        start_message=(
            f"EIM-AUTHENTICATE: reader={_reader_label(reader_name)}"
            + (f" matchingId={identifier}" if identifier else "")
        ),
        done_message="EIM-AUTHENTICATE complete.",
    ):
        yield event


async def _dispatch_stream_eim_download(
    ctx: ActionContext,
    *,
    reader: Any = None,
    matching_id: Any = None,
    confirm: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    if not bool(confirm):
        yield {"level": "error", "message": _CONFIRM_ERROR}
        yield {"level": "done", "message": "EIM-DOWNLOAD refused (unconfirmed).", "ok": False}
        return
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    identifier = str(matching_id or "").strip()
    async for event in _stream_console(
        reader_index,
        "_cmd_eim_download",
        argument=identifier,
        connect_first=False,
        start_message=(
            f"EIM-DOWNLOAD: reader={_reader_label(reader_name)}"
            + (f" matchingId={identifier}" if identifier else "")
        ),
        done_message="EIM-DOWNLOAD complete.",
    ):
        yield event


async def _dispatch_stream_eim_poll(
    ctx: ActionContext,
    *,
    reader: Any = None,
    arguments: Any = None,
    confirm: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    if not bool(confirm):
        yield {"level": "error", "message": _CONFIRM_ERROR}
        yield {"level": "done", "message": "EIM-POLL refused (unconfirmed).", "ok": False}
        return
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    argv = str(arguments or "").strip()
    async for event in _stream_console(
        reader_index,
        "_cmd_eim_poll",
        argument=argv,
        connect_first=False,
        start_message=(
            f"EIM-POLL: reader={_reader_label(reader_name)}"
            + (f" args={argv}" if argv else "")
        ),
        done_message="EIM-POLL complete.",
    ):
        yield event


async def _dispatch_stream_download_profile_live(
    ctx: ActionContext,
    *,
    reader: Any = None,
    activation_code: Any = None,
    confirm: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    if not bool(confirm):
        yield {"level": "error", "message": _CONFIRM_ERROR}
        yield {"level": "done", "message": "DOWNLOAD-AC refused (unconfirmed).", "ok": False}
        return
    code = str(activation_code or "").strip()
    if len(code) == 0:
        yield {"level": "error", "message": "activation_code is required."}
        yield {"level": "done", "message": "DOWNLOAD-AC aborted.", "ok": False}
        return
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    async for event in _stream_console(
        reader_index,
        "_download_activation_code",
        argument=code,
        connect_first=False,
        start_message=f"DOWNLOAD-AC: reader={_reader_label(reader_name)}",
        done_message="DOWNLOAD-AC complete.",
    ):
        yield event


async def _dispatch_stream_flow(
    ctx: ActionContext,
    *,
    reader: Any = None,
    matching_id: Any = None,
    confirm: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    if not bool(confirm):
        yield {"level": "error", "message": _CONFIRM_ERROR}
        yield {"level": "done", "message": "FLOW refused (unconfirmed).", "ok": False}
        return
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    identifier = str(matching_id or "").strip()
    async for event in _stream_console(
        reader_index,
        "_cmd_flow",
        argument=identifier,
        connect_first=False,
        start_message=(
            f"FLOW: reader={_reader_label(reader_name)}"
            + (f" matchingId={identifier}" if identifier else "")
        ),
        done_message="FLOW complete.",
    ):
        yield event


async def _dispatch_stream_verify_scp11(
    ctx: ActionContext,
    *,
    reader: Any = None,
    matching_id: Any = None,
) -> AsyncIterator[dict[str, Any]]:
    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)
    identifier = str(matching_id or "").strip()
    async for event in _stream_console(
        reader_index,
        "_cmd_verify_scp11",
        argument=identifier,
        connect_first=False,
        start_message=(
            f"VERIFY-SCP11: reader={_reader_label(reader_name)}"
            + (f" matchingId={identifier}" if identifier else "")
        ),
        done_message="VERIFY-SCP11 complete.",
    ):
        yield event


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


GET_EID_SPEC = ActionSpec(
    id="scp11_live.get_eid",
    subsystem="eSIM Live",
    title="Get EID",
    description=(
        "Open a short-lived PC/SC channel, read the EID via the ECASD "
        "applet (GET DATA 80CA005A00), and close the channel again."
    ),
    inputs=(
        ActionField(
            name="reader",
            label="Reader",
            kind="reader",
            required=False,
            default="",
            help="PC/SC reader name (leave empty for the first reader).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_get_eid,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "eid"),
)


LIST_PROFILES_SPEC = ActionSpec(
    id="scp11_live.list_profiles",
    subsystem="eSIM Live",
    title="List profiles (ES10b)",
    description=(
        "Fetch ProfilesInfo via ES10b (BF2D00) and return a decoded row "
        "per E3 entry: ICCID, state, class, nickname, AID."
    ),
    inputs=(
        ActionField(
            name="reader",
            label="Reader",
            kind="reader",
            required=False,
            default="",
            help="PC/SC reader name (leave empty for the first reader).",
        ),
    ),
    output_kind="table",
    dispatcher=_dispatch_list_profiles,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "profiles"),
)


GET_SMDP_SPEC = ActionSpec(
    id="scp11_live.get_smdp",
    subsystem="eSIM Live",
    title="Get SM-DP+ / SM-DS",
    description=(
        "Fetch EuiccConfiguredData (BF3C00) and surface the default "
        "SM-DP+ address plus the root SM-DS as key/value rows."
    ),
    inputs=(
        ActionField(
            name="reader",
            label="Reader",
            kind="reader",
            required=False,
            default="",
            help="PC/SC reader name (leave empty for the first reader).",
        ),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_smdp,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "configured-data"),
)


LIST_NOTIFICATIONS_SPEC = ActionSpec(
    id="scp11_live.list_notifications",
    subsystem="eSIM Live",
    title="List pending notifications",
    description=(
        "Fetch the ES10b notification queue (BF2800) and decode each "
        "entry into (seq, event, address, ICCID). Shows which "
        "install/enable/disable/delete events the card has queued for "
        "delivery to the SM-DS."
    ),
    inputs=(
        ActionField(
            name="reader",
            label="Reader",
            kind="reader",
            required=False,
            default="",
            help="PC/SC reader name (leave empty for the first reader).",
        ),
    ),
    output_kind="table",
    dispatcher=_dispatch_list_notifications,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "notifications"),
)


EUICC_INFO2_SPEC = ActionSpec(
    id="scp11_live.euicc_info2",
    subsystem="eSIM Live",
    title="EUICCInfo2 (live)",
    description=(
        "Fetch EUICCInfo2 (BF2200) from the card and render the shared "
        "detail-lines view (SVN, firmware, capabilities, UICC CSN, CI "
        "pkids). Complements the offline 'EUICCInfo2 decode' tool "
        "action which accepts a pasted hex payload."
    ),
    inputs=(
        ActionField(
            name="reader",
            label="Reader",
            kind="reader",
            required=False,
            default="",
            help="PC/SC reader name (leave empty for the first reader).",
        ),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_euicc_info2,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "euicc-info2"),
)


get_registry().register(GET_EID_SPEC)
get_registry().register(LIST_PROFILES_SPEC)
get_registry().register(GET_SMDP_SPEC)
get_registry().register(LIST_NOTIFICATIONS_SPEC)
get_registry().register(EUICC_INFO2_SPEC)


# --- Tranche 1: read-only expansion ----------------------------------


EUICC_INFO1_SPEC = ActionSpec(
    id="scp11_live.euicc_info1",
    subsystem="eSIM Live",
    title="EUICCInfo1 (live)",
    description=(
        "Fetch EUICCInfo1 (BF2000) from the card — decoded SVN, "
        "CI PK verification entries, and CI PK signing entries."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_euicc_info1,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "euicc-info1"),
)


GET_RAT_SPEC = ActionSpec(
    id="scp11_live.get_rat",
    subsystem="eSIM Live",
    title="Rules Authorisation Table",
    description=(
        "Fetch the RulesAuthorisationTable (BF4300) — decoded PPR IDs, "
        "PPR flags, and allowed operator entries."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_rat,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "rat"),
)


GET_CERTS_SPEC = ActionSpec(
    id="scp11_live.get_certs",
    subsystem="eSIM Live",
    title="GetCerts",
    description=(
        "Fetch the GetCerts (BF5600) map — decoded EUM and eUICC "
        "certificate presence and byte counts."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_certs,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "certs"),
)


GET_EIM_CONFIG_SPEC = ActionSpec(
    id="scp11_live.get_eim_config",
    subsystem="eSIM Live",
    title="GetEimConfigurationData",
    description=(
        "Fetch GetEimConfigurationData (BF5500) — decoded eIM entries "
        "with FQDN, OID, type, counter, and protocol fields."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_eim_config,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "eim-config"),
)


AIDS_SPEC = ActionSpec(
    id="scp11_live.aids",
    subsystem="eSIM Live",
    title="AID alias registry",
    description=(
        "Return the local AID alias table used by ENABLE/DISABLE/DELETE "
        "target resolution. Reads the on-disk aid.txt — no card needed."
    ),
    inputs=(),
    output_kind="table",
    dispatcher=_dispatch_aids,
    requires_card=False,
    streams=False,
    tags=("scp11", "read-only", "aid"),
)


STATUS_SPEC = ActionSpec(
    id="scp11_live.status",
    subsystem="eSIM Live",
    title="Live status",
    description=(
        "Compact 'reader + EID + configured SM-DP+/SM-DS' snapshot, "
        "equivalent to the shell STATUS output."
    ),
    inputs=(_reader_input_field(),),
    output_kind="key_value_lines",
    dispatcher=_dispatch_status,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "status"),
)


SCAN_SPEC = ActionSpec(
    id="scp11_live.scan",
    subsystem="eSIM Live",
    title="Scan (start snapshot)",
    description=(
        "Run the shell SCAN command: collect EID, issuer identity, "
        "profile list, configured data, notification count, and the "
        "EUICCInfo2 / eIM summaries used by the top-half pane."
    ),
    inputs=(_reader_input_field(),),
    output_kind="json",
    dispatcher=_dispatch_scan,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "scan"),
)


READ_METADATA_SPEC = ActionSpec(
    id="scp11_live.read_metadata",
    subsystem="eSIM Live",
    title="Read all profile metadata",
    description=(
        "Collect the ProfileMetadataView table for every profile: "
        "ICCID, AID, state, class, nickname, service provider, "
        "profile name, and PPR hex."
    ),
    inputs=(_reader_input_field(),),
    output_kind="table",
    dispatcher=_dispatch_read_metadata,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "metadata"),
)


GET_METADATA_SPEC = ActionSpec(
    id="scp11_live.get_metadata",
    subsystem="eSIM Live",
    title="Get profile metadata",
    description=(
        "Return the full metadata view for a single profile picked by "
        "ICCID, AID, or alias."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="target",
            label="Target (ICCID / AID / alias)",
            kind="string",
            required=True,
            help="Any identifier accepted by the shell (ICCID, AID hex, or alias).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_get_metadata,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "metadata"),
)


GET_POL_SPEC = ActionSpec(
    id="scp11_live.get_pol",
    subsystem="eSIM Live",
    title="Get Profile Policy Rules",
    description=(
        "Return the PPR hex and decoded rule names for a single "
        "profile — mirrors the shell GET-POL output."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="target",
            label="Target (ICCID / AID / alias)",
            kind="string",
            required=True,
            help="Any identifier accepted by the shell (ICCID, AID hex, or alias).",
        ),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_pol,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "policy"),
)


GET_ALL_DATA_SPEC = ActionSpec(
    id="scp11_live.get_all_data",
    subsystem="eSIM Live",
    title="Get all data (consolidated)",
    description=(
        "Run the consolidated discovery suite (EID + profiles + "
        "status + EuiccInfo1/2 + RAT + notifications + eIM config + "
        "certs) and surface the combined report."
    ),
    inputs=(_reader_input_field(),),
    output_kind="markdown",
    dispatcher=_dispatch_get_all_data,
    requires_card=True,
    streams=False,
    tags=("scp11", "read-only", "discovery"),
)


GET_ES9_SPEC = ActionSpec(
    id="scp11_live.get_es9",
    subsystem="eSIM Live",
    title="Show ES9 configuration",
    description=(
        "Return the live ES9 configuration view (base URL, TLS mode, "
        "CA bundle, default SM-DP+). No card access."
    ),
    inputs=(),
    output_kind="key_value_lines",
    dispatcher=_dispatch_get_es9,
    requires_card=False,
    streams=False,
    tags=("scp11", "read-only", "es9"),
)


ES9_CERT_INFO_SPEC = ActionSpec(
    id="scp11_live.es9_cert_info",
    subsystem="eSIM Live",
    title="Probe ES9 certificate",
    description=(
        "Probe the TLS chain exposed by the active ES9 endpoint. "
        "Useful when diagnosing CA-bundle / SNI issues before running "
        "FLOW / DOWNLOAD-AC."
    ),
    inputs=(),
    output_kind="markdown",
    dispatcher=_dispatch_es9_cert_info,
    requires_card=False,
    streams=False,
    tags=("scp11", "read-only", "es9", "tls"),
)


get_registry().register(EUICC_INFO1_SPEC)
get_registry().register(GET_RAT_SPEC)
get_registry().register(GET_CERTS_SPEC)
get_registry().register(GET_EIM_CONFIG_SPEC)
get_registry().register(AIDS_SPEC)
get_registry().register(STATUS_SPEC)
get_registry().register(SCAN_SPEC)
get_registry().register(READ_METADATA_SPEC)
get_registry().register(GET_METADATA_SPEC)
get_registry().register(GET_POL_SPEC)
get_registry().register(GET_ALL_DATA_SPEC)
get_registry().register(GET_ES9_SPEC)
get_registry().register(ES9_CERT_INFO_SPEC)


# --- Tranche 2: config writes (confirm-gated) ------------------------


SET_SMDP_SPEC = ActionSpec(
    id="scp11_live.set_smdp",
    subsystem="eSIM Live",
    title="Set default SM-DP+",
    description=(
        "Push a new default SM-DP+ address via the shell helper. "
        "Updates the inventory entry for the current EID. Gated by "
        "the confirm checkbox."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="address",
            label="SM-DP+ address",
            kind="string",
            required=True,
            placeholder="smdp.example.com",
            help="FQDN only — no scheme; the shell normalises the value.",
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_smdp,
    requires_card=True,
    streams=False,
    tags=("scp11", "config-write", "smdp"),
)


SET_ES9_SPEC = ActionSpec(
    id="scp11_live.set_es9",
    subsystem="eSIM Live",
    title="Set ES9 base URL",
    description=(
        "Switch the active ES9 base URL. Toggle 'persist' to also rewrite "
        "``SCP11/live/config.py::ES9_BASE_URL`` so the value survives "
        "restarts. Gated by the confirm checkbox."
    ),
    inputs=(
        ActionField(
            name="url",
            label="ES9 base URL",
            kind="string",
            required=True,
            placeholder="https://rsp.example.com/gsma/rsp2",
            help="Must start with http:// or https://. No trailing slash required.",
        ),
        ActionField(
            name="persist",
            label="Persist to config.py",
            kind="bool",
            required=False,
            default=False,
            help="Rewrite SCP11/live/config.py so the URL survives restarts.",
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_es9,
    requires_card=False,
    streams=False,
    tags=("scp11", "config-write", "es9"),
)


SET_ES9_TLS_SPEC = ActionSpec(
    id="scp11_live.set_es9_tls",
    subsystem="eSIM Live",
    title="Set ES9 TLS verification",
    description=(
        "Toggle ES9 TLS verification (ON/OFF) on the active provider. "
        "Persist writes the change back to the runtime config file."
    ),
    inputs=(
        ActionField(
            name="mode",
            label="Mode",
            kind="enum",
            required=True,
            choices=["on", "off"],
            default="on",
            help="'on' requires a trusted chain; 'off' skips verification (test only).",
        ),
        ActionField(
            name="persist",
            label="Persist to config.py",
            kind="bool",
            required=False,
            default=False,
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_es9_tls,
    requires_card=False,
    streams=False,
    tags=("scp11", "config-write", "es9", "tls"),
)


SET_ES9_CA_SPEC = ActionSpec(
    id="scp11_live.set_es9_ca",
    subsystem="eSIM Live",
    title="Set ES9 CA bundle",
    description=(
        "Point ES9 at a specific CA bundle (or clear back to system trust "
        "by passing ``NONE``). Persist rewrites the runtime config file."
    ),
    inputs=(
        ActionField(
            name="path",
            label="CA bundle path (or NONE)",
            kind="path",
            required=True,
            placeholder="/etc/ssl/certs/ca-bundle.pem",
            help="Double-click to browse. Enter NONE to clear the override.",
        ),
        ActionField(
            name="persist",
            label="Persist to config.py",
            kind="bool",
            required=False,
            default=False,
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_es9_ca,
    requires_card=False,
    streams=False,
    tags=("scp11", "config-write", "es9", "ca"),
)


get_registry().register(SET_SMDP_SPEC)
get_registry().register(SET_ES9_SPEC)
get_registry().register(SET_ES9_TLS_SPEC)
get_registry().register(SET_ES9_CA_SPEC)


# --- Tranche 3: card mutations (confirm-gated) -----------------------


ENABLE_PROFILE_SPEC = ActionSpec(
    id="scp11_live.enable_profile",
    subsystem="eSIM Live",
    title="Enable profile",
    description=(
        "Enable the selected profile (by ICCID / AID / alias). Triggers "
        "the auto-disable+enable+REFRESH sequence the shell uses. Gated "
        "by the confirm checkbox."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="target",
            label="Target (ICCID / AID / alias)",
            kind="string",
            required=True,
            help="Any identifier accepted by the shell.",
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_enable_profile,
    requires_card=True,
    streams=False,
    tags=("scp11", "mutation", "profile"),
)


DISABLE_PROFILE_SPEC = ActionSpec(
    id="scp11_live.disable_profile",
    subsystem="eSIM Live",
    title="Disable profile",
    description=(
        "Disable the selected profile (by ICCID / AID / alias). Gated "
        "by the confirm checkbox."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="target",
            label="Target (ICCID / AID / alias)",
            kind="string",
            required=True,
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_disable_profile,
    requires_card=True,
    streams=False,
    tags=("scp11", "mutation", "profile"),
)


DELETE_PROFILE_SPEC = ActionSpec(
    id="scp11_live.delete_profile",
    subsystem="eSIM Live",
    title="Delete profile",
    description=(
        "Delete the selected profile from the eUICC. Irreversible — "
        "double-check the target before confirming."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="target",
            label="Target (ICCID / AID / alias)",
            kind="string",
            required=True,
        ),
        _confirm_field(
            label="I understand deleting a profile is irreversible",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_delete_profile,
    requires_card=True,
    streams=False,
    tags=("scp11", "mutation", "profile", "destructive"),
)


REFRESH_MODEM_SPEC = ActionSpec(
    id="scp11_live.refresh_modem",
    subsystem="eSIM Live",
    title="Refresh modem",
    description=(
        "Queue a REFRESH toward the attached modem. Default mode "
        "(empty) triggers 'euicc-profile-state-change'. Gated by the "
        "confirm checkbox."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="mode",
            label="Refresh mode",
            kind="string",
            required=False,
            default="",
            placeholder="(blank = euicc-profile-state-change)",
            help="e.g. 'uicc-reset', 'naa-reset', 'eap-reauth'.",
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_refresh_modem,
    requires_card=True,
    streams=False,
    tags=("scp11", "mutation", "modem"),
)


RESET_CARD_SPEC = ActionSpec(
    id="scp11_live.reset_card",
    subsystem="eSIM Live",
    title="Reset card session",
    description=(
        "Run the shell RESET command: hard-reset the card session "
        "(tear down logical channel, clear ephemeral state, "
        "re-run connect + load-credentials)."
    ),
    inputs=(
        _reader_input_field(),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_reset_card,
    requires_card=True,
    streams=False,
    tags=("scp11", "mutation", "session"),
)


REMOVE_NOTIFICATION_SPEC = ActionSpec(
    id="scp11_live.remove_notification",
    subsystem="eSIM Live",
    title="Remove notification",
    description=(
        "Remove a single notification from the queue by sequence "
        "number. Gated by the confirm checkbox."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="seq",
            label="Sequence number",
            kind="int",
            required=True,
            min_value=0,
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_remove_notification,
    requires_card=True,
    streams=False,
    tags=("scp11", "mutation", "notification"),
)


CLEAR_NOTIFICATIONS_SPEC = ActionSpec(
    id="scp11_live.clear_notifications",
    subsystem="eSIM Live",
    title="Clear all notifications",
    description=(
        "Iterate the notification list and remove every entry. Use "
        "after a flow that queued notifications you do not want to "
        "deliver to the SM-DS."
    ),
    inputs=(
        _reader_input_field(),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_clear_notifications,
    requires_card=True,
    streams=False,
    tags=("scp11", "mutation", "notification"),
)


SET_POL_SPEC = ActionSpec(
    id="scp11_live.set_pol",
    subsystem="eSIM Live",
    title="Set Profile Policy Rules",
    description=(
        "Request a PPR update for a profile. Currently routed through "
        "the guarded-provisioning placeholder in the shell — surfaces "
        "the request without issuing an APDU. Gated by the confirm "
        "checkbox."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="target",
            label="Target (ICCID / AID / alias)",
            kind="string",
            required=True,
        ),
        ActionField(
            name="pol_hex",
            label="PPR payload (hex)",
            kind="hex",
            required=True,
            placeholder="e.g. 810101",
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_pol,
    requires_card=True,
    streams=False,
    tags=("scp11", "mutation", "policy"),
)


STORE_METADATA_SPEC = ActionSpec(
    id="scp11_live.store_metadata",
    subsystem="eSIM Live",
    title="Store profile metadata",
    description=(
        "Request a metadata update for a profile. Routed through the "
        "guarded-provisioning placeholder in the shell — surfaces the "
        "request without issuing an APDU."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="target",
            label="Target (ICCID / AID / alias)",
            kind="string",
            required=True,
        ),
        ActionField(
            name="metadata_hex",
            label="Metadata payload (hex)",
            kind="hex",
            required=True,
        ),
        _confirm_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_store_metadata,
    requires_card=True,
    streams=False,
    tags=("scp11", "mutation", "metadata"),
)


get_registry().register(ENABLE_PROFILE_SPEC)
get_registry().register(DISABLE_PROFILE_SPEC)
get_registry().register(DELETE_PROFILE_SPEC)
get_registry().register(REFRESH_MODEM_SPEC)
get_registry().register(RESET_CARD_SPEC)
get_registry().register(REMOVE_NOTIFICATION_SPEC)
get_registry().register(CLEAR_NOTIFICATIONS_SPEC)
get_registry().register(SET_POL_SPEC)
get_registry().register(STORE_METADATA_SPEC)


# --- Tranche 4: streaming flows --------------------------------------


DISCOVER_SPEC = ActionSpec(
    id="scp11_live.discover",
    subsystem="eSIM Live",
    title="Discover (SGP.32)",
    description=(
        "Run the SGP.32 / consolidated discovery suite. Streams the "
        "console output live so you can watch each retrieval complete."
    ),
    inputs=(_reader_input_field(),),
    output_kind="log_stream",
    dispatcher=_dispatch_stream_discover,
    requires_card=True,
    streams=True,
    tags=("scp11", "stream", "discover"),
)


EIM_AUTHENTICATE_SPEC = ActionSpec(
    id="scp11_live.eim_authenticate",
    subsystem="eSIM Live",
    title="eIM authenticate",
    description=(
        "Run the SCP11 authentication phase only (connect, load "
        "credentials, Get eUICC Challenge, AuthenticateServer). Does "
        "not download a profile."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="matching_id",
            label="Matching ID (optional)",
            kind="string",
            required=False,
            default="",
        ),
    ),
    output_kind="log_stream",
    dispatcher=_dispatch_stream_eim_authenticate,
    requires_card=True,
    streams=True,
    tags=("scp11", "stream", "authenticate"),
)


EIM_DOWNLOAD_SPEC = ActionSpec(
    id="scp11_live.eim_download",
    subsystem="eSIM Live",
    title="eIM download (SGP.32)",
    description=(
        "Run the eIM poll+relay flow. May queue REFRESH and rewrite "
        "notifications — gated by the confirm checkbox."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="matching_id",
            label="Matching ID (optional)",
            kind="string",
            required=False,
            default="",
        ),
        _confirm_field(),
    ),
    output_kind="log_stream",
    dispatcher=_dispatch_stream_eim_download,
    requires_card=True,
    streams=True,
    tags=("scp11", "stream", "eim-download", "destructive"),
)


EIM_POLL_SPEC = ActionSpec(
    id="scp11_live.eim_poll",
    subsystem="eSIM Live",
    title="eIM poll",
    description=(
        "Invoke the plugin-provided eIM poll loop. Argument string is "
        "forwarded verbatim to the shell command — consult HELP EXPERT "
        "in the live console for the exact options."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="arguments",
            label="Arguments (optional)",
            kind="string",
            required=False,
            default="",
            placeholder="e.g. --attempts 3",
        ),
        _confirm_field(
            label="I understand this may trigger card / network activity",
        ),
    ),
    output_kind="log_stream",
    dispatcher=_dispatch_stream_eim_poll,
    requires_card=True,
    streams=True,
    tags=("scp11", "stream", "eim-poll"),
)


DOWNLOAD_PROFILE_LIVE_SPEC = ActionSpec(
    id="scp11_live.download_profile",
    subsystem="eSIM Live",
    title="Download profile (activation code)",
    description=(
        "Parse an LPA:1$... activation code, retarget the ES9 client, "
        "and run the full SGP.22 download flow via the shell helper. "
        "Modifies the card; gated by the confirm checkbox."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="activation_code",
            label="Activation code",
            kind="string",
            required=True,
            placeholder="LPA:1$smdp.example.com$MATCHING-ID",
        ),
        _confirm_field(
            label="I understand this installs a new profile on the card",
        ),
    ),
    output_kind="log_stream",
    dispatcher=_dispatch_stream_download_profile_live,
    requires_card=True,
    streams=True,
    tags=("scp11", "stream", "download", "destructive"),
)


FLOW_SPEC = ActionSpec(
    id="scp11_live.flow",
    subsystem="eSIM Live",
    title="Full SCP11 flow",
    description=(
        "Run the full SGP.22 FLOW using the currently configured "
        "SM-DP+ / ES9 target. Gated by the confirm checkbox."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="matching_id",
            label="Matching ID (optional)",
            kind="string",
            required=False,
            default="",
        ),
        _confirm_field(
            label="I understand this installs a new profile on the card",
        ),
    ),
    output_kind="log_stream",
    dispatcher=_dispatch_stream_flow,
    requires_card=True,
    streams=True,
    tags=("scp11", "stream", "flow", "destructive"),
)


VERIFY_SCP11_SPEC = ActionSpec(
    id="scp11_live.verify_scp11",
    subsystem="eSIM Live",
    title="Verify SCP11 handshake",
    description=(
        "Run the SCP11 authentication diagnostic: connect, load "
        "credentials, get challenge, AuthenticateServer, and capture "
        "transactionId / euiccSignature1. Non-destructive."
    ),
    inputs=(
        _reader_input_field(),
        ActionField(
            name="matching_id",
            label="Matching ID (optional)",
            kind="string",
            required=False,
            default="",
        ),
    ),
    output_kind="log_stream",
    dispatcher=_dispatch_stream_verify_scp11,
    requires_card=True,
    streams=True,
    tags=("scp11", "stream", "verify"),
)


get_registry().register(DISCOVER_SPEC)
get_registry().register(EIM_AUTHENTICATE_SPEC)
get_registry().register(EIM_DOWNLOAD_SPEC)
get_registry().register(EIM_POLL_SPEC)
get_registry().register(DOWNLOAD_PROFILE_LIVE_SPEC)
get_registry().register(FLOW_SPEC)
get_registry().register(VERIFY_SCP11_SPEC)
