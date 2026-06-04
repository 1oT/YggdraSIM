# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP80 OTA Command Center actions.

Wraps the ``SCP80.cli.OtaShell`` surface into structured actions so the
GUI can drive the same flow operators use via ``python -m SCP80``:

* ``scp80.show_config`` — report the active OTA profile (counter, header,
  SPI, KIc/KID, TAR, transport, concat_sms, tp_ud_max, reader protocol).
* ``scp80.set_config`` — set one key-value pair on the OTA profile and
  persist it to ``ota_config.ini`` + the inventory store.
* ``scp80.iccid_bind`` — bind / read the active ICCID inventory profile.
* ``scp80.build_plan`` — build the OTA packet plan without sending it.
  Returns the APDU list, reader-path APDU (single reassembled ENVELOPE),
  segment count, cipher/mac mode, and counter.
* ``scp80.send`` — build + transmit the plan against the active reader
  or ``print`` transport. Returns the structured ``send_ota_sequence``
  report (segment SWs, POR, delivered flag).
* ``scp80.send_raw`` — bypass the OTA pipeline and push a plain APDU
  across the transport (reader mode only).
* ``scp80.reset_connection`` — drop and reopen the reader connection,
  re-running the STK bootstrap.
* ``scp80.ota_smart`` — single-shot ``ota <hex>`` helper: build plan with
  payload override, send, run the SCP03 ``ContentDecoder`` against the
  POR body, and hand back both.

All dispatchers instantiate a fresh ``ConfigManager`` / ``Transport`` per
call; the CLI's long-lived ``OtaShell`` is not cached in-process. This
mirrors how the other read/write action modules behave — stateless from
the GUI's perspective, idempotent against the persisted config.
"""

from __future__ import annotations

import contextlib
import io
import logging
import re
from typing import Any

from .registry import ActionContext, ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.scp80")


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _load_config() -> Any:
    from SCP80.config import ConfigManager

    return ConfigManager()


def _build_transport(config: Any) -> Any:
    from SCP80.transport import Transport

    return Transport(config)


def _build_packet_builder(config: Any) -> Any:
    from SCP80.builder import OtaPacketBuilder

    return OtaPacketBuilder(config)


def _with_reader_override(reader_index: Any, config: Any) -> None:
    """Optional reader index override, applied before connect()."""
    if reader_index is None:
        return
    try:
        index_int = int(reader_index)
    except (TypeError, ValueError):
        return
    if index_int < 0:
        return
    config.data["reader_idx"] = str(index_int)


def _resolve_reader_index_from_name(reader_name: str) -> int:
    cleaned = str(reader_name or "").strip()
    if len(cleaned) == 0:
        return -1
    try:
        from smartcard.System import readers as list_pcsc_readers
    except ImportError:
        return -1
    for idx, reader in enumerate(list_pcsc_readers()):
        if str(reader) == cleaned:
            return idx
    return -1


def _apply_reader_choice(reader_name: str, reader_index: Any, config: Any) -> int:
    """Honour either an explicit index or a PC/SC reader name, returning the chosen index."""
    named_index = _resolve_reader_index_from_name(reader_name)
    if named_index >= 0:
        config.data["reader_idx"] = str(named_index)
        return named_index
    _with_reader_override(reader_index, config)
    try:
        return int(config.data.get("reader_idx", "0"))
    except (TypeError, ValueError):
        return 0


def _describe_keyset(slot_value: str) -> str:
    try:
        from SCP80.crypto import CryptoEngine
    except Exception:  # noqa: BLE001 — optional import path
        return str(slot_value or "")
    try:
        return CryptoEngine.describe_keyset(str(slot_value or ""))
    except Exception:  # noqa: BLE001 — descriptor never blocks the read
        return str(slot_value or "")


def _reader_input_field() -> ActionField:
    return ActionField(
        name="reader",
        label="Reader",
        kind="reader",
        required=False,
        default="",
        help="PC/SC reader name; leave empty to use the configured reader_idx.",
    )


def _reader_index_field() -> ActionField:
    return ActionField(
        name="reader_index",
        label="Reader index",
        kind="int",
        required=False,
        default=None,
        min_value=0,
        help="Override reader_idx for this call only. Leave empty to use the persisted value.",
    )


def _verbose_field() -> ActionField:
    return ActionField(
        name="verbose",
        label="Verbose APDU trace",
        kind="bool",
        required=False,
        default=False,
        help="Tee the underlying transport trace into the result.",
    )


# ----------------------------------------------------------------------
# Dispatchers
# ----------------------------------------------------------------------


def _dispatch_show_config(ctx: ActionContext) -> dict[str, Any]:
    config = _load_config()
    hidden = {"header", "cla", "sender"}
    lines: list[dict[str, str]] = []
    if len(config.active_iccid) > 0:
        lines.append({"key": "iccid", "value": str(config.active_iccid)})
    for key, value in config.data.items():
        if key in hidden:
            continue
        if key in ("kic", "kid"):
            display = _describe_keyset(str(value))
        else:
            display = str(value)
        lines.append({"key": key, "value": display})

    protocol_summary: dict[str, Any] = {}
    if config.data.get("transport") == "reader":
        transport = _build_transport(config)
        try:
            protocol_summary = transport.get_protocol_summary() or {}
        except Exception as error:  # noqa: BLE001 — reader absence is common
            protocol_summary = {"available": False, "error": str(error)}
        finally:
            transport.disconnect()

    return {
        "lines": lines,
        "active_iccid": str(config.active_iccid or ""),
        "protocol": protocol_summary,
        "config_path": str(config.file_path),
    }


def _dispatch_set_config(
    ctx: ActionContext,
    *,
    key: Any = None,
    value: Any = None,
) -> dict[str, Any]:
    key_s = str(key or "").strip().lower()
    if len(key_s) == 0:
        raise ValueError("key is required.")
    value_s = "" if value is None else str(value)

    config = _load_config()
    if key_s not in config.data:
        raise ValueError(f"unknown config key: {key_s!r}")
    try:
        config.set(key_s, value_s)
    except ValueError as error:
        raise ValueError(f"{key_s}: {error}") from error
    config.save()
    updated = str(config.data.get(key_s, ""))
    return {
        "ok": True,
        "key": key_s,
        "value": updated if key_s not in ("key_enc", "key_mac") else "********",
        "note": f"{key_s} updated.",
    }


def _dispatch_iccid_bind(
    ctx: ActionContext,
    *,
    iccid: Any = None,
) -> dict[str, Any]:
    iccid_s = "".join(ch for ch in str(iccid or "") if ch.isdigit())
    config = _load_config()
    if len(iccid_s) == 0:
        return {
            "ok": False,
            "active_iccid": str(config.active_iccid or ""),
            "note": "no ICCID digits provided; inventory profile unchanged.",
        }
    payload = config.bind_iccid_profile(iccid_s)
    loaded = isinstance(payload, dict) and len(payload) > 0
    return {
        "ok": True,
        "active_iccid": iccid_s,
        "loaded_profile": bool(loaded),
        "note": (
            f"loaded inventory profile for ICCID {iccid_s}."
            if loaded
            else f"seeded inventory profile for ICCID {iccid_s} from current defaults."
        ),
    }


def _plan_to_dict(plan: Any) -> dict[str, Any]:
    apdus: list[dict[str, Any]] = []
    for apdu in plan.apdus or []:
        apdus.append({
            "index": int(apdu.index) + 1,
            "total": int(apdu.total),
            "apdu_hex": str(apdu.apdu_hex),
            "tp_ud_length": int(apdu.tp_ud_length),
            "is_concatenated": bool(apdu.is_concatenated),
            "concat_ref": (None if apdu.concat_ref is None else int(apdu.concat_ref)),
        })
    return {
        "segment_count": len(apdus),
        "is_concatenated": bool(getattr(plan, "is_concatenated", False)),
        "cipher_mode": str(getattr(plan, "cipher_mode", "")),
        "mac_mode": str(getattr(plan, "mac_mode", "")),
        "cntr_hex": str(getattr(plan, "cntr_hex", "")),
        "block_0348_hex": bytes(getattr(plan, "block_0348", b"") or b"").hex().upper(),
        "payload_hex": str(getattr(plan, "payload_hex", "")),
        "apdus": apdus,
        "reader_apdus": list(getattr(plan, "reader_apdus", []) or []),
    }


def _dispatch_build_plan(
    ctx: ActionContext,
    *,
    payload: Any = None,
    verbose: Any = None,
) -> dict[str, Any]:
    payload_hex = str(payload or "").replace(" ", "").upper()
    verbose_b = bool(verbose)
    config = _load_config()
    builder = _build_packet_builder(config)
    trace_sink = io.StringIO()
    plan_dict: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            plan = builder.build_plan(
                verbose=verbose_b,
                override_payload=payload_hex if len(payload_hex) > 0 else None,
            )
        plan_dict = _plan_to_dict(plan)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")

    return {
        "ok": len(note_parts) == 0,
        "note": "; ".join(note_parts) if note_parts else "plan built",
        "plan": plan_dict,
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _plan_apdu_list_for_transport(plan: Any, config: Any) -> list[str]:
    is_reader = config.get("transport") == "reader"
    if is_reader and getattr(plan, "is_concatenated", False) and len(plan.reader_apdus) > 0:
        return list(plan.reader_apdus)
    return [apdu.apdu_hex for apdu in plan.apdus or []]


def _dispatch_send(
    ctx: ActionContext,
    *,
    reader: Any = None,
    reader_index: Any = None,
    payload: Any = None,
    verbose: Any = None,
) -> dict[str, Any]:
    payload_hex = str(payload or "").replace(" ", "").upper()
    verbose_b = bool(verbose)
    reader_name = str(reader or "")
    config = _load_config()
    chosen_index = _apply_reader_choice(reader_name, reader_index, config)
    builder = _build_packet_builder(config)
    transport = _build_transport(config)
    trace_sink = io.StringIO()
    plan_dict: dict[str, Any] = {}
    result: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            plan = builder.build_plan(
                verbose=verbose_b,
                override_payload=payload_hex if len(payload_hex) > 0 else None,
            )
            plan_dict = _plan_to_dict(plan)
            result = transport.send_ota_sequence(
                _plan_apdu_list_for_transport(plan, config),
                verbose=verbose_b,
            )
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        try:
            transport.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return {
        "ok": bool(result.get("delivered", False)) and len(note_parts) == 0,
        "reader_index": chosen_index,
        "transport": str(config.get("transport")),
        "plan": plan_dict,
        "result": result,
        "note": "; ".join(note_parts) if note_parts else (
            "OTA packet delivered."
            if result.get("delivered", False)
            else str(result.get("error") or "delivery failed")
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_send_raw(
    ctx: ActionContext,
    *,
    reader: Any = None,
    reader_index: Any = None,
    apdu_hex: Any = None,
) -> dict[str, Any]:
    apdu_s = str(apdu_hex or "").replace(" ", "").upper()
    if len(apdu_s) == 0:
        raise ValueError("apdu_hex is required.")
    config = _load_config()
    if config.get("transport") != "reader":
        raise ValueError("send_raw requires the reader transport; change it via scp80.set_config.")
    chosen_index = _apply_reader_choice(str(reader or ""), reader_index, config)
    transport = _build_transport(config)
    trace_sink = io.StringIO()
    data_hex = ""
    sw = 0
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            if transport.connect() is False:
                raise RuntimeError("reader connection unavailable")
            data, sw_value = transport.transmit(apdu_s)
        data_hex = bytes(data or b"").hex().upper()
        sw = int(sw_value)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        try:
            transport.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return {
        "ok": len(note_parts) == 0,
        "reader_index": chosen_index,
        "apdu_hex": apdu_s,
        "response_hex": data_hex,
        "sw": f"{sw:04X}" if sw else "",
        "note": "; ".join(note_parts) if note_parts else "raw APDU delivered.",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_reset_connection(
    ctx: ActionContext,
    *,
    reader: Any = None,
    reader_index: Any = None,
) -> dict[str, Any]:
    config = _load_config()
    if config.get("transport") != "reader":
        return {
            "ok": True,
            "transport": str(config.get("transport")),
            "note": "reset is a no-op outside reader transport.",
        }
    chosen_index = _apply_reader_choice(str(reader or ""), reader_index, config)
    transport = _build_transport(config)
    trace_sink = io.StringIO()
    note_parts: list[str] = []
    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            transport.reset_connection()
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        try:
            transport.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return {
        "ok": len(note_parts) == 0,
        "reader_index": chosen_index,
        "transport": str(config.get("transport")),
        "note": "; ".join(note_parts) if note_parts else "transport reset (STK bootstrap replayed).",
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _dispatch_protocol_summary(
    ctx: ActionContext,
    *,
    reader: Any = None,
    reader_index: Any = None,
) -> dict[str, Any]:
    config = _load_config()
    chosen_index = _apply_reader_choice(str(reader or ""), reader_index, config)
    if config.get("transport") != "reader":
        return {
            "ok": False,
            "transport": str(config.get("transport")),
            "available": False,
            "note": "reader transport not active; protocol summary only meaningful for PC/SC.",
        }
    transport = _build_transport(config)
    summary: dict[str, Any] = {}
    note_parts: list[str] = []
    try:
        summary = transport.get_protocol_summary() or {}
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        try:
            transport.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return {
        "ok": bool(summary.get("available", False)) and len(note_parts) == 0,
        "reader_index": chosen_index,
        "summary": summary,
        "note": "; ".join(note_parts) if note_parts else (
            f"ATR {summary.get('atr_hex') or 'unknown'} · {summary.get('active_protocol') or 'UNKNOWN'}"
        ),
    }


def _dispatch_ota_smart(
    ctx: ActionContext,
    *,
    reader: Any = None,
    reader_index: Any = None,
    apdu_hex: Any = None,
    verbose: Any = None,
) -> dict[str, Any]:
    """Single-shot ``ota <hex>`` helper: build, send, decode POR."""
    apdu_s = str(apdu_hex or "").replace(" ", "").upper()
    if len(apdu_s) == 0:
        raise ValueError("apdu_hex is required (raw APDU to wrap in SCP80).")
    verbose_b = bool(verbose)
    config = _load_config()
    chosen_index = _apply_reader_choice(str(reader or ""), reader_index, config)
    builder = _build_packet_builder(config)
    transport = _build_transport(config)
    trace_sink = io.StringIO()
    plan_dict: dict[str, Any] = {}
    result: dict[str, Any] = {}
    decoded_por: str = ""
    note_parts: list[str] = []

    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            plan = builder.build_plan(
                verbose=verbose_b,
                override_payload=apdu_s,
            )
            plan_dict = _plan_to_dict(plan)
            result = transport.send_ota_sequence(
                _plan_apdu_list_for_transport(plan, config),
                verbose=verbose_b,
            )
        por_hex = str(result.get("por") or "")
        if len(por_hex) > 0:
            decoded_por = _try_decode_por(apdu_s, por_hex)
    except Exception as error:  # noqa: BLE001
        note_parts.append(f"{type(error).__name__}: {error}")
    finally:
        try:
            transport.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return {
        "ok": bool(result.get("delivered", False)) and len(note_parts) == 0,
        "reader_index": chosen_index,
        "apdu_hex": apdu_s,
        "plan": plan_dict,
        "result": result,
        "por_decoded": decoded_por,
        "note": "; ".join(note_parts) if note_parts else (
            "OTA packet delivered."
            if result.get("delivered", False)
            else str(result.get("error") or "delivery failed")
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


def _try_decode_por(apdu_hex: str, por_hex: str) -> str:
    """Best-effort POR decode using the SCP03 ``ContentDecoder``."""
    try:
        from SCP80.cli import SmartDecoder
    except Exception:  # noqa: BLE001 — optional dep
        return ""
    try:
        decoder = SmartDecoder()
        fid, le = decoder.sniff_context(apdu_hex)
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink):
            decoder.try_decode(fid, le, por_hex)
        return _strip_ansi(sink.getvalue())
    except Exception:  # noqa: BLE001 — purely decorative
        return ""


def _dispatch_run_script(
    ctx: ActionContext,
    *,
    script_path: Any = None,
    stop_on_error: Any = None,
    reader: Any = None,
    reader_index: Any = None,
) -> dict[str, Any]:
    path_s = str(script_path or "").strip()
    if len(path_s) == 0:
        raise ValueError("script_path is required.")
    if not __import__("os").path.isfile(path_s):
        raise ValueError(f"script file not found: {path_s!r}")

    stop_b = True if stop_on_error is None else bool(stop_on_error)
    config = _load_config()
    chosen_index = _apply_reader_choice(str(reader or ""), reader_index, config)
    builder = _build_packet_builder(config)
    transport = _build_transport(config)
    trace_sink = io.StringIO()
    results: list[dict[str, Any]] = []
    note_parts: list[str] = []

    try:
        with open(path_s, "r", encoding="utf-8") as fh:
            raw_lines = fh.readlines()
    except Exception as error:  # noqa: BLE001
        raise ValueError(f"cannot read script file: {error}") from error

    try:
        with contextlib.redirect_stdout(trace_sink), contextlib.redirect_stderr(trace_sink):
            for line_no, raw_line in enumerate(raw_lines, start=1):
                line = raw_line.strip()
                if len(line) == 0 or line.startswith("#"):
                    continue
                hex_match = re.findall(r"[0-9A-Fa-f]{2,}", line.replace(" ", ""))
                payload_hex = "".join(hex_match) if hex_match else ""
                if len(payload_hex) == 0:
                    continue
                try:
                    plan = builder.build_plan(
                        verbose=False,
                        override_payload=payload_hex,
                    )
                    plan_dict = _plan_to_dict(plan)
                    result = transport.send_ota_sequence(
                        _plan_apdu_list_for_transport(plan, config),
                        verbose=False,
                    )
                    delivered = bool(result.get("delivered", False))
                    por = str(result.get("por") or "")
                    results.append({
                        "line": line_no,
                        "payload": payload_hex,
                        "delivered": delivered,
                        "por": por,
                        "error": "" if delivered else str(result.get("error") or "delivery failed"),
                    })
                    if not delivered and stop_b:
                        note_parts.append(f"stopped at line {line_no} (delivery failed).")
                        break
                except Exception as error:  # noqa: BLE001
                    results.append({
                        "line": line_no,
                        "payload": payload_hex,
                        "delivered": False,
                        "por": "",
                        "error": f"{type(error).__name__}: {error}",
                    })
                    if stop_b:
                        note_parts.append(f"stopped at line {line_no} ({error}).")
                        break
    finally:
        try:
            transport.disconnect()
        except Exception:  # noqa: BLE001
            pass

    delivered_count = sum(1 for r in results if r.get("delivered"))
    return {
        "ok": len(note_parts) == 0,
        "script_path": path_s,
        "reader_index": chosen_index,
        "total_lines": len([l for l in raw_lines if l.strip() and not l.strip().startswith("#")]),
        "executed": len(results),
        "delivered": delivered_count,
        "results": results,
        "note": "; ".join(note_parts) if note_parts else (
            f"script complete: {delivered_count}/{len(results)} delivered."
        ),
        "trace": _strip_ansi(trace_sink.getvalue()),
    }


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


SHOW_CONFIG_SPEC = ActionSpec(
    id="scp80.show_config",
    subsystem="SCP80",
    title="Show configuration",
    description=(
        "Dump the active SCP80 / RFM profile: counter, SPI, KIc/KID "
        "keyset descriptors, TAR, transport, reader protocol, "
        "concat_sms, and tp_ud_max."
    ),
    inputs=(),
    output_kind="key_value_lines",
    dispatcher=_dispatch_show_config,
    requires_card=False,
    tags=("scp80", "rfm", "config"),
)


SET_CONFIG_SPEC = ActionSpec(
    id="scp80.set_config",
    subsystem="SCP80",
    title="Set configuration key",
    description=(
        "Update one config key (cntr, spi, kic, kid, tar, key_enc, "
        "key_mac, transport, reader_idx, concat_sms, tp_ud_max, …) and "
        "persist it to ota_config.ini + the inventory store."
    ),
    inputs=(
        ActionField(
            name="key",
            label="Key",
            kind="enum",
            required=True,
            choices=[
                "cntr",
                "header",
                "payload",
                "spi",
                "kic",
                "kid",
                "tar",
                "key_enc",
                "key_mac",
                "cla",
                "transport",
                "reader_idx",
                "sender",
                "concat_sms",
                "tp_ud_max",
            ],
            help="Config key to write (see SCP80/config.py::DEFAULTS for the full matrix).",
        ),
        ActionField(
            name="value",
            label="Value",
            kind="string",
            required=True,
            help="Exact value (hex / decimal / ON/OFF per key rules).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_config,
    requires_card=False,
    tags=("scp80", "config", "write"),
)


ICCID_BIND_SPEC = ActionSpec(
    id="scp80.iccid_bind",
    subsystem="SCP80",
    title="Bind ICCID profile",
    description=(
        "Bind the active ICCID to the SCP80 inventory profile. Loads the "
        "persisted per-ICCID overrides when available; otherwise seeds a "
        "new inventory profile from the current defaults."
    ),
    inputs=(
        ActionField(
            name="iccid",
            label="ICCID (decimal digits)",
            kind="string",
            required=True,
            placeholder="89014104211118510720",
            help="Decimal digits only; non-digits are stripped automatically.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_iccid_bind,
    requires_card=False,
    tags=("scp80", "inventory", "iccid"),
)


BUILD_PLAN_SPEC = ActionSpec(
    id="scp80.build_plan",
    subsystem="SCP80",
    title="Build OTA plan (dry-run)",
    description=(
        "Build the full OTA packet plan — does not transmit. Returns the "
        "per-segment APDU list, the reader-path reassembled APDU, counter, "
        "cipher / MAC modes, and the raw 03.48 block in hex."
    ),
    inputs=(
        ActionField(
            name="payload",
            label="Payload override (hex)",
            kind="hex",
            required=False,
            placeholder="00A40004023F00",
            help="Optional raw APDU payload; leave empty to use the configured payload.",
        ),
        _verbose_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_build_plan,
    requires_card=False,
    tags=("scp80", "build", "dry-run"),
)


SEND_SPEC = ActionSpec(
    id="scp80.send",
    subsystem="SCP80",
    title="Send OTA packet",
    description=(
        "Build the OTA plan and push it across the active transport. In "
        "print mode this echoes the APDUs; in reader mode it executes the "
        "ENVELOPE sequence and returns the POR body + SW per segment."
    ),
    inputs=(
        _reader_input_field(),
        _reader_index_field(),
        ActionField(
            name="payload",
            label="Payload override (hex)",
            kind="hex",
            required=False,
            help="Optional raw APDU payload; leave empty to use the configured payload.",
        ),
        _verbose_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_send,
    requires_card=True,
    tags=("scp80", "send", "ota"),
)


SEND_RAW_SPEC = ActionSpec(
    id="scp80.send_raw",
    subsystem="SCP80",
    title="Send raw APDU",
    description=(
        "Bypass the OTA pipeline and push a plain APDU across the "
        "PC/SC transport (for diagnostics or re-issuing POR fetch "
        "commands). Reader transport only."
    ),
    inputs=(
        _reader_input_field(),
        _reader_index_field(),
        ActionField(
            name="apdu_hex",
            label="APDU (hex)",
            kind="hex",
            required=True,
            placeholder="00A40004023F00",
            help="Raw APDU to transmit.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_send_raw,
    requires_card=True,
    tags=("scp80", "send", "raw", "apdu"),
)


RESET_CONNECTION_SPEC = ActionSpec(
    id="scp80.reset_connection",
    subsystem="SCP80",
    title="Reset transport",
    description=(
        "Disconnect and re-open the PC/SC reader channel, replaying the "
        "STK bootstrap. Safe no-op when transport=print."
    ),
    inputs=(
        _reader_input_field(),
        _reader_index_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_reset_connection,
    requires_card=True,
    tags=("scp80", "reset", "transport"),
)


PROTOCOL_SUMMARY_SPEC = ActionSpec(
    id="scp80.protocol_summary",
    subsystem="SCP80",
    title="Reader protocol summary",
    description=(
        "Open the reader briefly and report the ATR, supported protocols, "
        "T=1 availability, and the active protocol. Useful for diagnosing "
        "concatenated-SMS extended ENVELOPE behaviour."
    ),
    inputs=(
        _reader_input_field(),
        _reader_index_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_protocol_summary,
    requires_card=True,
    tags=("scp80", "reader", "protocol"),
)


OTA_SMART_SPEC = ActionSpec(
    id="scp80.ota_smart",
    subsystem="SCP80",
    title="OTA smart (build + send + decode)",
    description=(
        "Build an OTA plan with the supplied APDU payload, transmit it, "
        "then run the SCP03 ContentDecoder against the POR body. Mirrors "
        "the CLI's ``ota <hex>`` command."
    ),
    inputs=(
        _reader_input_field(),
        _reader_index_field(),
        ActionField(
            name="apdu_hex",
            label="Inner APDU (hex)",
            kind="hex",
            required=True,
            placeholder="00A40004023F00",
            help="Raw APDU wrapped as the SCP80 OTA payload.",
        ),
        _verbose_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_ota_smart,
    requires_card=True,
    tags=("scp80", "ota", "decode"),
)


RUN_SCRIPT_SPEC = ActionSpec(
    id="scp80.run_script",
    subsystem="SCP80",
    title="Run script file",
    description=(
        "Execute a batch of OTA commands from a script file. Each "
        "non-comment, non-empty line is treated as a hex APDU payload, "
        "wrapped in SCP80, transmitted, and the POR is captured. "
        "Stops on first error when 'stop_on_error' is enabled."
    ),
    inputs=(
        ActionField(
            name="script_path",
            label="Script file",
            kind="path",
            required=True,
            help="Path to a plain-text file with one hex APDU per line.",
        ),
        ActionField(
            name="stop_on_error",
            label="Stop on first error",
            kind="bool",
            required=False,
            default=True,
            help="Abort the script if any line fails delivery.",
        ),
        _reader_input_field(),
        _reader_index_field(),
    ),
    output_kind="json",
    dispatcher=_dispatch_run_script,
    requires_card=True,
    tags=("scp80", "script", "batch"),
)


get_registry().register(SHOW_CONFIG_SPEC)
get_registry().register(SET_CONFIG_SPEC)
get_registry().register(ICCID_BIND_SPEC)
get_registry().register(BUILD_PLAN_SPEC)
get_registry().register(SEND_SPEC)
get_registry().register(SEND_RAW_SPEC)
get_registry().register(RESET_CONNECTION_SPEC)
get_registry().register(PROTOCOL_SUMMARY_SPEC)
get_registry().register(OTA_SMART_SPEC)
get_registry().register(RUN_SCRIPT_SPEC)
