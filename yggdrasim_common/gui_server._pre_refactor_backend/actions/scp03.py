# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP03 Command Center actions.

Registers two actions:

* ``scp03.scan`` — connects to the first (or nominated) PC/SC reader,
  runs the live file-system scan, and returns a structured tree plus a
  ``session_id`` the GUI can reuse for follow-up calls. The underlying
  ``CardTransporter`` is parked in the session manager; it stays open
  until the GUI closes it or the idle reaper fires.
* ``scp03.read_selected`` — given a ``session_id`` from the scan and a
  file path (``MF/ADF_USIM/EF_IMSI`` or a scan-cache index like ``"12"``),
  selects that file, returns the parsed FCP, and reads the full body:
  READ BINARY for transparent files (with ContentDecoder) or every
  record of a linear-fixed / cyclic file (each with hex + decoded).

Both dispatchers are synchronous; they run inside the FastAPI threadpool
and take ~1-2 s on real hardware. Longer flows (OTA, download-profile)
use the streaming path instead.
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
from typing import Any

from .registry import ActionContext, ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.scp03")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


# Well-known prefix for error strings that the GUI treats specially —
# mainly "there is no card in the reader, don't launch the expensive
# recover-session loop, just tell the operator". We piggy-back on the
# existing ``ok=false`` error channel because the ActionRegistry route
# already routes any dispatcher exception into ``{ok:false, error:str}``.
# Keeping the sentinel in one place avoids scattering magic strings.
NO_CARD_ERROR_PREFIX = "no_card:"
SESSION_GONE_ERROR_PREFIX = "session_gone:"


def _is_no_card_error(error: BaseException) -> bool:
    """Return True for PC/SC errors that mean "card removed / absent".

    The user-visible symptoms are the same for several exception types
    (``NoCardException``, ``CardConnectionException`` with ``0x8010000C``
    as the hresult, ``SmartcardException`` with "Unable to connect" from
    certain pcscd versions). We match on ``type(error).__name__`` rather
    than ``isinstance`` so this function stays import-safe even on boxes
    where pyscard isn't installed (e.g. CI sandbox).
    """
    name = type(error).__name__
    if name in ("NoCardException",):
        return True
    # Some pyscard layers wrap the 0x8010000C hresult in a generic
    # CardConnectionException. The surest test is the error string,
    # since the hresult attribute isn't always populated.
    text = str(error) or ""
    if "No smart card" in text:
        return True
    if "0x8010000C" in text.upper() or "0X8010000C" in text.upper():
        return True
    return False


def _resolve_reader_index(reader_name: str) -> int:
    """Map an optional reader name back to a ``reader_index``.

    If ``reader_name`` is empty, returns 0 (first reader). Raises if the
    named reader cannot be found.
    """
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


def _open_card_transporter(reader_index: int) -> Any:
    """Construct a ``CardTransporter`` using the chosen reader index.

    ``CardTransporter.connect()`` hardcodes index 0 today; we side-step
    that by opening the raw PC/SC connection ourselves (respecting
    ``YGGDRASIM_CARD_*`` backend flags), then handing it to the transporter.
    """
    from yggdrasim_common import card_backend
    from SCP03.transport.card import CardTransporter

    # CardTransporter.__init__ eagerly calls connect(); we monkey-patch
    # our already-chosen connection in so its hardcoded index-0 doesn't
    # steal the wrong reader. This is the minimal surgical approach.
    connection = card_backend.create_card_connection(reader_index=reader_index)
    transporter = CardTransporter.__new__(CardTransporter)
    from SCP03.crypto.session import Scp03Session

    transporter.connection = connection
    transporter.session = Scp03Session({"kenc": b"", "kmac": b"", "dek": b""})
    transporter.verbose = False
    transporter.debug = False
    return transporter


def _close_transporter(transporter: Any) -> None:
    try:
        transporter.disconnect()
    except Exception:  # noqa: BLE001 — best-effort cleanup
        try:
            if getattr(transporter, "connection", None) is not None:
                transporter.connection.disconnect()
        except Exception:
            pass


def _get_atr_hex(transporter: Any) -> str:
    try:
        atr = transporter.get_atr_bytes()
    except Exception:  # noqa: BLE001
        return ""
    return atr.hex().upper() if atr else ""


def _restore_fs_root_best_effort(session_or_transporter: Any) -> dict[str, Any]:
    """Leave the card on MF (3F00) + re-sync ``fs_controller.current_fid``.

    Dispatchers that route through sgp22 land the card on ISD-R
    (``A000000559...``) or another application. If the next thing the
    operator does is a file-tree click, the FS controller's internal
    ``current_fid`` disagrees with the card's real DF — the path-walk
    still works thanks to ``_normalise_fs_path``, but the in-memory FS
    state is stale and UI breadcrumbs drift.

    This helper selects MF via raw APDU (``00A40004023F00`` — SELECT by
    FID 3F00, P2 = first-or-only occurrence) and resets the FS
    controller's bookkeeping. Errors are swallowed because this is a
    post-op cleanup — the caller's response has already been assembled
    and the MF-restore is a best-effort nicety, not a correctness gate.

    Accepts either a ``session`` object (we pull ``handle["transporter"]``
    / ``handle["fs"]`` from it) or a bare transporter.
    """
    result: dict[str, Any] = {"ok": False, "sw": "", "fid": ""}
    transporter = None
    fs_controller = None

    handle = getattr(session_or_transporter, "handle", None)
    if isinstance(handle, dict):
        transporter = handle.get("transporter")
        fs_controller = handle.get("fs")
    else:
        transporter = session_or_transporter

    if transporter is None:
        return result

    try:
        _data, sw1, sw2 = transporter.transmit("00A40004023F00", silent=True)
        result["sw"] = f"{sw1:02X}{sw2:02X}"
        result["ok"] = sw1 == 0x90 or sw1 == 0x61
        result["fid"] = "3F00"
    except Exception as error:  # noqa: BLE001
        result["error"] = f"{type(error).__name__}: {error}"
        return result

    if fs_controller is not None:
        try:
            fs_controller.current_fid = "3F00"
        except Exception:  # noqa: BLE001
            pass
        try:
            fs_controller.current_path_hint = "MF"
        except Exception:  # noqa: BLE001
            pass

    return result


# ----------------------------------------------------------------------
# Dispatchers
# ----------------------------------------------------------------------


def _dispatch_scan(ctx: ActionContext, *, reader: Any = None) -> dict[str, Any]:
    from SCP03.logic.fs import FileSystemController
    from yggdrasim_common.gui_server.sessions import get_manager

    reader_name = str(reader or "")
    reader_index = _resolve_reader_index(reader_name)

    # Catch the "reader exists but slot is empty" class of errors here
    # instead of letting them bubble into the FastAPI 500 path. The GUI
    # used to see a raw traceback ("NoCardException: Unable to connect"),
    # fall into recover-session + rescan, fail that too, and chew a whole
    # extra second per file click. Now we raise a well-known RuntimeError
    # whose message the route converts into ``{ok:false, error:...}`` —
    # the frontend pattern-matches ``no_card:`` and skips recovery.
    try:
        transporter = _open_card_transporter(reader_index)
    except Exception as error:  # noqa: BLE001
        if _is_no_card_error(error):
            display = reader_name or "(default)"
            raise RuntimeError(
                f"{NO_CARD_ERROR_PREFIX} no smart card inserted in reader "
                f"{display!r} (hresult 0x8010000C)"
            ) from error
        raise

    # Build the FS controller and run the scan. ``scan_tree(return_tree=True)``
    # prints its usual tree to stdout; we throw that away for the API path
    # and keep the structured return value.
    fs_controller = FileSystemController(transporter)
    stdout_sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_sink):
            structured = fs_controller.scan_tree(return_tree=True)
    except Exception as error:  # noqa: BLE001
        _close_transporter(transporter)
        if _is_no_card_error(error):
            display = reader_name or "(default)"
            raise RuntimeError(
                f"{NO_CARD_ERROR_PREFIX} card removed during scan on reader "
                f"{display!r}"
            ) from error
        raise

    atr_hex = _get_atr_hex(transporter)

    manager = get_manager()
    session = manager.open(
        kind="scp03",
        handle={"transporter": transporter, "fs": fs_controller},
        close=lambda t=transporter: _close_transporter(t),
        metadata={
            "reader_index": reader_index,
            "reader_name": reader_name or "(default)",
            "atr_hex": atr_hex,
        },
    )

    tree_payload = structured or {"tree": [], "scan_cache": {}}
    return {
        "session_id": session.id,
        "reader_index": reader_index,
        "reader_name": reader_name or "(default)",
        "atr_hex": atr_hex,
        "tree": tree_payload.get("tree", []),
        "scan_cache": tree_payload.get("scan_cache", {}),
        "raw_trace": stdout_sink.getvalue(),
    }


def _strip_ansi(text: str) -> str:
    """Drop ANSI colour escapes we captured from stdout."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _normalise_fs_path(path: str) -> str:
    """Ensure a file-system path is rooted at MF before it hits ``select()``.

    ETSI TS 102 221 allows P1=00 (SELECT by FID) with a scope that is
    implementation-defined; many cards only resolve it against children
    of the current DF. That means a bare path like ``"EF.ICCID"`` only
    succeeds if the card happens to be sitting on MF at that instant.

    After any prior SELECT (e.g. the scan walker landed on ADF.USIM,
    or the user navigated into a DF and then clicked a top-level EF),
    a bare select call against ``EF.ICCID`` / ``EF.DIR`` / etc. fails
    with 6A82. The workaround users hit organically was "click MF,
    then click the file".

    Normalising bare, non-hex, non-indexed paths to ``MF/<name>`` routes
    the request through ``FileSystemController.select()``'s path-walk
    branch, which explicitly pre-selects MF before walking segments —
    so GUI clicks always land on the right file in one shot.

    We deliberately do **not** touch:
      * Paths that already contain ``/`` (caller is explicit about
        the absolute path; select() pre-selects MF on its own).
      * Paths starting with ``MF`` (already anchored).
      * Bare hex FIDs (``3F00``, ``2F00``, ``2FE2``) — these are
        fine for card-internal relative selection.
      * Pure numeric indices — those resolve via ``scan_cache``.
      * AIDs (long hex strings) — SELECT-by-AID already walks
        from MF on the card side.
    """
    cleaned = str(path or "").strip()
    if len(cleaned) == 0:
        return cleaned
    if "/" in cleaned:
        return cleaned
    upper = cleaned.upper()
    if upper == "MF" or upper.startswith("MF"):
        return cleaned
    # Hex-only identifiers (FIDs + AIDs) — leave alone. The card
    # resolves hex FIDs relative to the current DF, and AIDs are
    # looked up globally via SELECT-by-AID.
    is_hex = all(c in "0123456789ABCDEFabcdef" for c in cleaned)
    if is_hex:
        return cleaned
    # Pure digit strings are scan-cache indices; ``select()`` will
    # resolve them internally.
    if cleaned.isdigit():
        return cleaned
    return "MF/" + cleaned


def _dispatch_read_selected(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    path: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    session_id_s = str(session_id or "").strip()
    path_s = str(path or "").strip()
    if len(session_id_s) == 0:
        raise ValueError("session_id is required (run scp03.scan first).")
    if len(path_s) == 0:
        raise ValueError("path is required.")

    manager = get_manager()
    try:
        session = manager.get(session_id_s)
    except Exception as error:  # noqa: BLE001
        # The session may have been reaped (idle timeout) or the GUI is
        # running with a stale sessionId from localStorage. Surface a
        # well-known ``session_gone:`` marker so the frontend can
        # short-circuit recovery — there's nothing to recover to.
        raise RuntimeError(
            f"{SESSION_GONE_ERROR_PREFIX} session {session_id_s!r} not found "
            f"(may have been reaped; re-scan to open a new one)"
        ) from error
    if session.kind != "scp03":
        raise ValueError(f"session is not an scp03 session (kind={session.kind!r})")

    fs_controller = session.handle["fs"]
    transporter = session.handle["transporter"]

    # Belt-and-suspenders: the scan walker now emits fully qualified
    # "MF/..." paths, but older cached trees or a hand-typed path may
    # still arrive as a bare name like "EF.ICCID". The helper prefixes
    # "MF/" for non-slash, non-hex, non-index names so select()'s
    # path-walk branch always pre-selects MF before the leaf.
    walked_path = _normalise_fs_path(path_s)

    # Hard-anchor to MF before any MF-rooted FS read. Prior dispatchers
    # (card-info probe, cert-info, raw SELECT-by-AID, sgp22 / sgp32
    # helpers, anything that punches into ISD-R or ECASD) leave the
    # card's current DF pointing away from MF. The fs_controller's
    # path-walk branch does a best-effort ``_select_single("MF")`` for
    # slash-rooted paths, but on a handful of cards we saw that
    # relative SELECT fail once the card had already been pushed into a
    # non-MF ADF several layers deep. Emitting a raw ``00A40004023F00``
    # here is unconditionally cheap (single APDU, no side-effects) and
    # guarantees the subsequent walk starts from a clean slate. This
    # closes the "FS → any AID → FS click no longer reads" regression.
    #
    # We only run the pre-restore when the walked path is MF-rooted
    # (slash present, or normalised to ``MF/...``). Bare hex FIDs or
    # scan-cache indices are deliberately card-state-aware — respecting
    # that preserves the CLI-parity path for advanced operators typing
    # bare FIDs against a non-MF current DF.
    if "/" in walked_path:
        _restore_fs_root_best_effort(session)

    # SELECT — capture the (noisy) CLI print so we can bubble the trace
    # back to the UI without polluting the server log. Any PC/SC layer
    # failure (card removed mid-session, reader unplugged) gets tagged
    # with the ``no_card:`` prefix so the frontend skips the expensive
    # recover-session retry.
    select_sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(select_sink):
            success = fs_controller.select(walked_path, silent=False)
    except Exception as error:  # noqa: BLE001
        if _is_no_card_error(error):
            raise RuntimeError(
                f"{NO_CARD_ERROR_PREFIX} card removed during SELECT "
                f"{walked_path!r}"
            ) from error
        raise
    if success is False:
        return {
            "session_id": session_id_s,
            "path": path_s,
            "resolved_path": walked_path,
            "selected": False,
            "select_trace": _strip_ansi(select_sink.getvalue()),
            "fcp": {},
            "data": {},
        }

    fcp_raw = dict(fs_controller.current_fcp or {})

    # Serialise the FCP so JSON encoding is bulletproof (the
    # content-decoder occasionally stuffs bytes/tuples in there).
    fcp_clean = _sanitise_for_json(fcp_raw)

    structure = str(fcp_raw.get("structure") or "").strip().lower()
    data_payload = _read_payload_for_file(
        transporter,
        fs_controller,
        structure,
        path=path_s,
    )

    return {
        "session_id": session_id_s,
        "path": path_s,
        "resolved_path": walked_path,
        "selected": True,
        "select_trace": _strip_ansi(select_sink.getvalue()),
        "fid": str(fs_controller.current_fid or ""),
        "fcp": fcp_clean,
        "data": data_payload,
    }


def _read_payload_for_file(
    transporter: Any,
    fs_controller: Any,
    structure: str,
    *,
    path: str = "",
) -> dict[str, Any]:
    """Read the file's body with the right APDU shape, decoded + hex.

    * ``Transparent`` → READ BINARY (00B0 00 00 00), plus ContentDecoder.
    * ``Linear Fixed`` / ``Cyclic`` → iterate records 1..N (capped at 254),
      each with both hex and decoded, stop on SW 0x6A (record not found)
      or any non-0x90 response. Uses ``rec_len`` from the live FCP so
      short-file cards honour the actual record size.
    * Anything else (DF, MF, application ADF) → no data read, return an
      empty payload with an explanatory note.
    """
    fid = str(getattr(fs_controller, "current_fid", "") or "").strip().upper()
    context_path = str(path or "").strip()

    if structure == "transparent":
        data, sw1, sw2 = transporter.transmit("00B0000000", silent=True)
        hex_data = (data.hex().upper() if data else "")
        decoded = _decode_content_safely(fid, hex_data, context_path)
        return {
            "kind": "transparent",
            "sw": f"{sw1:02X}{sw2:02X}",
            "ok": sw1 == 0x90,
            "hex": hex_data,
            "length": len(data or b""),
            "decoded": decoded,
        }

    if structure in ("linear fixed", "linear-fixed", "linearfixed", "cyclic"):
        fcp = fs_controller.current_fcp or {}
        rec_len_int = 0
        try:
            rec_len_int = int(fcp.get("rec_len", 0) or 0)
        except (TypeError, ValueError):
            rec_len_int = 0
        le_byte = f"{rec_len_int:02X}" if 0 < rec_len_int < 0x100 else "00"

        records: list[dict[str, Any]] = []
        stop_reason = "end"
        non_empty = 0
        for record_number in range(1, 255):
            apdu = f"00B2{record_number:02X}04{le_byte}"
            data, sw1, sw2 = transporter.transmit(apdu, silent=True)
            sw_str = f"{sw1:02X}{sw2:02X}"
            # 0x6A xx / 0x6C xx retries: 0x6C means "wrong Le, correct is sw2".
            if sw1 == 0x6C and sw2 > 0:
                apdu = f"00B2{record_number:02X}04{sw2:02X}"
                data, sw1, sw2 = transporter.transmit(apdu, silent=True)
                sw_str = f"{sw1:02X}{sw2:02X}"
            if sw1 != 0x90:
                if sw1 == 0x6A:
                    stop_reason = "record_not_found"
                else:
                    stop_reason = f"sw_{sw_str}"
                # Record the terminating SW once for diagnostic transparency.
                records.append({
                    "record_number": record_number,
                    "sw": sw_str,
                    "ok": False,
                    "hex": "",
                    "length": 0,
                    "decoded": None,
                    "empty": True,
                })
                break
            hex_data = data.hex().upper() if data else ""
            is_empty_pattern = len(hex_data) > 0 and (
                all(ch == "F" for ch in hex_data) or all(ch == "0" for ch in hex_data)
            )
            decoded = None if is_empty_pattern else _decode_content_safely(
                fid, hex_data, context_path
            )
            records.append({
                "record_number": record_number,
                "sw": sw_str,
                "ok": True,
                "hex": hex_data,
                "length": len(data or b""),
                "decoded": decoded,
                "empty": is_empty_pattern,
            })
            if is_empty_pattern is False:
                non_empty += 1

        return {
            "kind": "records",
            "rec_len": rec_len_int,
            "record_count": len(records),
            "non_empty_count": non_empty,
            "stop_reason": stop_reason,
            "records": records,
            "note": (
                "Empty sentinel records (all-F / all-0) are kept for "
                "transparency but flagged as 'empty=true'."
            ),
        }

    return {
        "kind": "none",
        "note": f"No binary payload for structure={structure!r}; this looks like a directory/application.",
    }


def _decode_content_safely(fid: str, hex_data: str, context_path: str) -> Any:
    """Run ``ContentDecoder.decode_obj`` without letting a decoder bug
    break the whole response. Returns ``None`` on failure / empty input.
    """
    if len(hex_data) == 0:
        return None
    try:
        from SCP03.core.decoders import ContentDecoder
    except Exception:  # noqa: BLE001
        return None
    try:
        decoded = ContentDecoder.decode_obj(fid, hex_data, context_path=context_path)
    except Exception as error:  # noqa: BLE001
        return {"decoder_error": str(error)}
    if decoded is None:
        return None
    return _sanitise_for_json(decoded)


def _sanitise_for_json(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (bytes, bytearray, memoryview)):
        try:
            return bytes(obj).hex().upper()
        except Exception:  # noqa: BLE001
            return str(obj)
    if isinstance(obj, dict):
        return {str(key): _sanitise_for_json(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_sanitise_for_json(entry) for entry in obj]
    if isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


SCAN_SPEC = ActionSpec(
    id="scp03.scan",
    subsystem="SCP03",
    title="Scan file system",
    description=(
        "Connect to the chosen PC/SC reader, walk the live UICC file "
        "system, and return a clickable tree. Leaves a session open so "
        "subsequent reads are fast."
    ),
    inputs=(
        ActionField(
            name="reader",
            label="Reader",
            kind="reader",
            required=False,
            default="",
            help="Pick a PC/SC reader by name, or leave empty to use the first one.",
        ),
    ),
    output_kind="tree",
    dispatcher=_dispatch_scan,
    requires_card=True,
    streams=False,
    tags=("scan", "fs", "uicc"),
)


READ_SELECTED_SPEC = ActionSpec(
    id="scp03.read_selected",
    subsystem="SCP03",
    title="Select + read file",
    description=(
        "Select a file by path or scan-cache index, parse the FCP, and "
        "read the full body: READ BINARY for transparent files, every "
        "record (with per-record hex + decoded view) for linear-fixed / "
        "cyclic files."
    ),
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True, help="Session id returned by scp03.scan."),
        ActionField(name="path", label="Path or index", kind="string", required=True, placeholder="MF/ADF_USIM/EF_IMSI or 12"),
    ),
    output_kind="fcp",
    dispatcher=_dispatch_read_selected,
    requires_card=True,
    streams=False,
    tags=("fcp", "read"),
)


# ----------------------------------------------------------------------
# Additional session-based actions
# ----------------------------------------------------------------------


def _dispatch_select_only(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    path: Any = None,
) -> dict[str, Any]:
    """SELECT a file but do not read the body. Returns path + FCP only."""
    from yggdrasim_common.gui_server.sessions import get_manager

    session_id_s = str(session_id or "").strip()
    path_s = str(path or "").strip()
    if len(session_id_s) == 0:
        raise ValueError("session_id is required (run scp03.scan first).")
    if len(path_s) == 0:
        raise ValueError("path is required.")

    manager = get_manager()
    session = manager.get(session_id_s)
    if session.kind != "scp03":
        raise ValueError(f"session is not an scp03 session (kind={session.kind!r})")
    fs_controller = session.handle["fs"]
    # See _dispatch_read_selected for the rationale behind normalising
    # bare names to "MF/<name>" before calling select(). Keeps SELECT-
    # by-path robust regardless of where the card's current DF sat.
    walked_path = _normalise_fs_path(path_s)

    # Mirror the pre-restore guard from _dispatch_read_selected:
    # re-anchor the card to MF before any MF-rooted SELECT so drift
    # from a prior ISD-R / ECASD / SELECT-by-AID action can't poison
    # the path walk. Only triggers when the path is already
    # slash-rooted — bare FIDs stay card-state-aware on purpose.
    if "/" in walked_path:
        _restore_fs_root_best_effort(session)

    trace = io.StringIO()
    with contextlib.redirect_stdout(trace):
        success = fs_controller.select(walked_path, silent=False)
    if success is False:
        return {
            "session_id": session_id_s,
            "path": path_s,
            "resolved_path": walked_path,
            "selected": False,
            "select_trace": _strip_ansi(trace.getvalue()),
            "fcp": {},
        }
    return {
        "session_id": session_id_s,
        "path": path_s,
        "resolved_path": walked_path,
        "selected": True,
        "select_trace": _strip_ansi(trace.getvalue()),
        "fid": str(fs_controller.current_fid or ""),
        "fcp": _sanitise_for_json(dict(fs_controller.current_fcp or {})),
    }


def _dispatch_list_apps(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Probe EF.DIR and return the discovered application templates."""
    from yggdrasim_common.gui_server.sessions import get_manager

    session_id_s = str(session_id or "").strip()
    if len(session_id_s) == 0:
        raise ValueError("session_id is required (run scp03.scan first).")
    manager = get_manager()
    session = manager.get(session_id_s)
    if session.kind != "scp03":
        raise ValueError(f"session is not an scp03 session (kind={session.kind!r})")
    fs_controller = session.handle["fs"]
    apps = fs_controller._discover_ef_dir_applications()
    rows: list[dict[str, Any]] = []
    for entry in apps or []:
        if not isinstance(entry, dict):
            continue
        rows.append({
            "aid": str(entry.get("aid", "")),
            "label": str(entry.get("label", "")),
            "aliases": ", ".join(str(alias) for alias in entry.get("aliases", []) or []),
        })
    return {
        "session_id": session_id_s,
        "count": len(rows),
        "rows": rows,
    }


def _dispatch_close_session(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Explicitly close the active session (reader + FS controller)."""
    from yggdrasim_common.gui_server.sessions import get_manager

    session_id_s = str(session_id or "").strip()
    if len(session_id_s) == 0:
        raise ValueError("session_id is required.")
    manager = get_manager()
    closed = manager.close(session_id_s)
    return {
        "session_id": session_id_s,
        "closed": bool(closed),
    }


SELECT_SPEC = ActionSpec(
    id="scp03.select",
    subsystem="SCP03",
    title="Select file (no read)",
    description="SELECT a path on the active session and return just the parsed FCP.",
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
        ActionField(name="path", label="Path or index", kind="string", required=True, placeholder="MF/ADF_USIM/EF_DIR or 7"),
    ),
    output_kind="fcp",
    dispatcher=_dispatch_select_only,
    requires_card=True,
    tags=("select", "fcp"),
)


LIST_APPS_SPEC = ActionSpec(
    id="scp03.list_apps",
    subsystem="SCP03",
    title="List EF.DIR applications",
    description="Walk EF.DIR records on the active session and list every application template.",
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
    ),
    output_kind="table",
    dispatcher=_dispatch_list_apps,
    requires_card=True,
    tags=("ef-dir", "apps"),
)


CLOSE_SESSION_SPEC = ActionSpec(
    id="scp03.close_session",
    subsystem="SCP03",
    title="Close session",
    description="Disconnect the active SCP03 session (releases the reader).",
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_close_session,
    requires_card=False,
    tags=("session",),
)


# ----------------------------------------------------------------------
# C-1: Read-only card telemetry
# ----------------------------------------------------------------------


def _get_scp03_session(session_id: Any) -> tuple[Any, Any, str]:
    """Resolve a session id into (session, transporter, session_id_s).

    Raises ``ValueError`` on empty / wrong-kind sessions so every C-1
    dispatcher gets consistent error messaging.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run scp03.scan first).")
    session = get_manager().get(sid)
    if session.kind != "scp03":
        raise ValueError(f"session is not an scp03 session (kind={session.kind!r})")
    return session, session.handle["transporter"], sid


def _dispatch_atr(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    reset: Any = True,
) -> dict[str, Any]:
    """Return the raw ATR + ETSI/ISO decoded lines for the active session.

    Matches the CLI ``ATR`` command: a physical reset is issued before
    the ATR is read so the returned bytes reflect the card's actual
    answer-to-reset (not a cached value from initial connect that may
    be stale after prior APDU traffic). Pass ``reset=False`` to skip
    the reset and return the cached ATR — useful when the caller only
    wants the parsed view without perturbing card state.

    The returned ``lines`` list strips the redundant ``ATR: <hex>``
    header that ``transporter.describe_atr()`` emits (to match the CLI
    screen dump). Since the GUI already surfaces the hex in a dedicated
    KV row (``atr_hex``), the duplicate line would only add visual
    noise — and led to the "GUI shows ATR twice" parity complaint.
    """
    session, transporter, sid = _get_scp03_session(session_id)

    do_reset = bool(reset) if not isinstance(reset, str) else reset.strip().lower() not in ("false", "0", "no", "off", "")
    reset_ok = False
    if do_reset:
        try:
            reset_ok = bool(transporter.reset())
        except Exception:  # noqa: BLE001
            reset_ok = False
        if reset_ok:
            # A cold reset drops any secure-channel state; mirror the
            # CLI `_clear_prompt_context_tracking()` so the in-memory
            # FS view doesn't drift into "I'm still on ADF_USIM".
            try:
                transporter.reset_session_state()
            except Exception:  # noqa: BLE001
                pass
            _restore_fs_root_best_effort(session)

    raw = transporter.get_atr_bytes() or b""
    raw_hex = raw.hex().upper()
    try:
        described = list(transporter.describe_atr() or [])
    except Exception as error:  # noqa: BLE001
        described = [f"ATR parse error: {error}"]

    # The first describe_atr() line is always ``ATR: <hex>`` (matching
    # the CLI's top line). Drop it here so the GUI KV row + the lines
    # block don't duplicate the value.
    lines: list[str] = []
    for idx, entry in enumerate(described):
        text = str(entry)
        if idx == 0 and text.strip().startswith("ATR:"):
            continue
        lines.append(text)

    return {
        "session_id": sid,
        "atr_hex": raw_hex,
        "atr_length": len(raw),
        "lines": lines,
        "reset_requested": do_reset,
        "reset_ok": reset_ok,
    }


def _dispatch_ensure_fs_root(
    ctx: ActionContext, *, session_id: Any = None
) -> dict[str, Any]:
    """Re-select MF (3F00) on the card and re-sync the FS controller.

    The GUI calls this when the user navigates back to the **Files**
    ribbon tab after running an eUICC / ISD-R operation (which leaves
    the card sitting on the ISD-R AID). Without this, the next bare
    file-tree click would hit the wrong DF until ``_normalise_fs_path``
    promoted it to ``MF/...`` — functionally correct but the internal
    ``fs_controller.current_fid`` bookkeeping stayed wrong.

    Safe to call at any time; idempotent; swallows errors.
    """
    session, _transporter, sid = _get_scp03_session(session_id)
    restore = _restore_fs_root_best_effort(session)
    return {
        "session_id": sid,
        "ok": bool(restore.get("ok")),
        "sw": restore.get("sw", ""),
        "fid": restore.get("fid", ""),
        "error": restore.get("error", ""),
    }


def _dispatch_reset(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    """Cold-reset the card via the PC/SC transporter and re-read the ATR."""
    _session, transporter, sid = _get_scp03_session(session_id)
    before = transporter.get_atr_bytes() or b""
    ok = bool(transporter.reset())
    try:
        transporter.reset_session_state()
    except Exception:  # noqa: BLE001 — best-effort cleanup
        pass
    after = transporter.get_atr_bytes() or b""
    return {
        "session_id": sid,
        "ok": ok,
        "atr_before_hex": before.hex().upper(),
        "atr_after_hex": after.hex().upper(),
        "atr_changed": before != after,
    }


def _dispatch_recover_session(
    ctx: ActionContext, *, session_id: Any = None
) -> dict[str, Any]:
    """Cold-reset + re-walk MF so a stuck FS view can recover in place.

    Background. The "file-system → any AID → file-system" regression
    keeps surfacing on a handful of cards: even with the belt-and-
    suspenders MF-restore in ``_dispatch_read_selected`` (raw
    ``00A40004023F00`` before every slash-rooted read), some loaders
    park the card in a state where the next SELECT-by-FID still
    returns 6A82 until the card is power-cycled. The scan tree is
    also stale — the in-memory copy the GUI rendered no longer
    matches the card's actual DF, and the ``FileSystemController``'s
    ``current_fcp`` / ``current_fid`` are pointing at something the
    card hasn't been told about for minutes.

    Rather than paper over it with more pre-restore retries, this
    dispatcher gives the GUI a clean "reset + rescan" primitive it
    can fire the instant a read fails (or pre-emptively, when the
    user hops back to the Files view after an eUICC side trip). The
    session handle stays the same so the existing ``session_id``
    remains valid across the recovery — only the underlying state
    is refreshed.

    Sequence (all best-effort — we want recovery to keep progressing
    even if individual steps hiccup):

      1. ``transporter.reset()`` — cold ATR via PC/SC.
      2. ``transporter.reset_session_state()`` — drop any SCP03
         secure-channel bookkeeping (keys, MAC chain, counters).
      3. Re-instantiate ``FileSystemController`` on the existing
         transporter and call ``scan_tree(return_tree=True)`` to walk
         MF + the standard ADF list fresh. stdout capture keeps the
         scan's tree-printing noise off the server log.
      4. Swap the new ``FileSystemController`` into ``session.handle["fs"]``
         so subsequent ``_dispatch_read_selected`` calls bind the
         correct controller.

    Returns a ``scp03.scan``-compatible shape (``tree`` / ``scan_cache``
    / ``atr_hex``) so the GUI can swap the refreshed tree into
    ``tab.scanData`` without a special-case renderer.
    """
    from SCP03.logic.fs import FileSystemController
    from yggdrasim_common.gui_server.sessions import get_manager

    manager = get_manager()
    sid_s = str(session_id or "").strip()
    if len(sid_s) == 0:
        raise ValueError("session_id is required.")

    session = manager.get(sid_s)
    if session.kind != "scp03":
        raise ValueError(f"session is not an scp03 session (kind={session.kind!r})")

    transporter = session.handle["transporter"]

    # PC/SC reset may itself fail if the operator pulled the card
    # between the failing read and the recovery attempt. Capture the
    # failure in ``reset_error`` so the frontend can distinguish
    # "recovery tried but card is gone" from "recovery succeeded but
    # rescan is still empty". Bubble a well-known ``no_card:`` marker
    # if that's what we hit — the UI uses that to silence retry loops.
    before_atr = ""
    try:
        before_atr = (transporter.get_atr_bytes() or b"").hex().upper()
    except Exception:  # noqa: BLE001
        before_atr = ""
    reset_ok = False
    reset_error = ""
    no_card = False
    try:
        reset_ok = bool(transporter.reset())
    except Exception as error:  # noqa: BLE001
        reset_ok = False
        reset_error = f"{type(error).__name__}: {error}"
        if _is_no_card_error(error):
            no_card = True
    try:
        transporter.reset_session_state()
    except Exception:  # noqa: BLE001
        pass

    # Walk the tree again on a brand-new FS controller so we don't
    # carry any stale ``current_fcp`` / ``current_fid`` from the
    # previous walk. This also re-populates ``scan_cache`` so the
    # frontend tree index is consistent with the new walk.
    fs_controller = FileSystemController(transporter)
    scan_error: str | None = None
    stdout_sink = io.StringIO()
    structured: dict[str, Any] | None = None
    # Skip the rescan when we already know the card is gone — saves ~1
    # s of wasted SELECTs that will all fail with the same PC/SC error,
    # and keeps the log dock readable.
    if no_card:
        scan_error = reset_error or "NoCardException: card absent"
    else:
        try:
            with contextlib.redirect_stdout(stdout_sink):
                structured = fs_controller.scan_tree(return_tree=True)
        except Exception as error:  # noqa: BLE001
            scan_error = f"{type(error).__name__}: {error}"
            if _is_no_card_error(error):
                no_card = True

    # Swap in the fresh controller so ``_dispatch_read_selected`` on
    # the same session_id uses the refreshed bookkeeping.
    try:
        session.handle["fs"] = fs_controller
    except Exception:  # noqa: BLE001
        pass

    after_atr = ""
    try:
        after_atr = (transporter.get_atr_bytes() or b"").hex().upper()
    except Exception:  # noqa: BLE001
        after_atr = ""
    tree_payload = structured or {"tree": [], "scan_cache": {}}

    return {
        "session_id": sid_s,
        "reset_ok": reset_ok,
        "reset_error": reset_error,
        "no_card": no_card,
        "scan_ok": scan_error is None,
        "scan_error": scan_error or "",
        "atr_before_hex": before_atr,
        "atr_after_hex": after_atr,
        "atr_changed": before_atr != after_atr,
        "tree": tree_payload.get("tree", []),
        "scan_cache": tree_payload.get("scan_cache", {}),
        "raw_trace": _strip_ansi(stdout_sink.getvalue()),
    }


def _dispatch_card_info(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    """Summarise ATR + ICCID + EID probe against the active reader.

    ``_probe_iccid`` selects EF.ICCID (under MF) and ``_probe_eid_and_standard``
    punches through to ECASD and ISD-R via raw SELECT-by-AID. Without the
    finally-block restore, the next FS click would arrive with the card
    sitting on ISD-R, fs_controller.current_fid stuck on 2FE2, and the
    breadcrumb lying about the current scope. Restoring MF here keeps
    the FS view consistent with the card's actual state.
    """
    session, transporter, sid = _get_scp03_session(session_id)

    reset_ok = False
    try:
        reset_ok = bool(transporter.reset())
    except Exception:  # noqa: BLE001
        reset_ok = False

    atr_raw = transporter.get_atr_bytes() or b""
    atr_hex = atr_raw.hex().upper()

    try:
        iccid = _probe_iccid(transporter)
        eid, standard = _probe_eid_and_standard(transporter)

        return {
            "session_id": sid,
            "reset_ok": reset_ok,
            "atr_hex": atr_hex,
            "iccid": iccid,
            "eid": eid,
            "standard": standard,
        }
    finally:
        _restore_fs_root_best_effort(session)


def _probe_iccid(transporter: Any) -> str:
    """Select EF.ICCID and return the BCD-decoded value, or ''."""
    try:
        transporter.transmit("00A40004023F00", silent=True)
        _data, sw1, _sw2 = transporter.transmit("00A40004022FE2", silent=True)
        if sw1 not in (0x90, 0x61, 0x9F):
            return ""
        data, sw1, _sw2 = transporter.transmit("00B000000A", silent=True)
        if sw1 != 0x90 or not data:
            return ""
        hex_value = bytes(data).hex().upper()
        digits: list[str] = []
        for index in range(0, len(hex_value), 2):
            pair = hex_value[index : index + 2]
            if len(pair) < 2:
                continue
            digits.append(pair[1])
            digits.append(pair[0])
        return "".join(digits).replace("F", "")
    except Exception:  # noqa: BLE001
        return ""


def _probe_eid_and_standard(transporter: Any) -> tuple[str, str]:
    """Select ECASD + GET DATA 5A to capture the EID; infer profile standard."""
    ecasd_aid = "A0000005591010FFFFFFFF8900000200"
    isdr_aid = "A0000005591010FFFFFFFF8900000100"
    try:
        _data, sw1, _sw2 = transporter.transmit(
            f"00A4040010{ecasd_aid}", silent=True
        )
        if sw1 not in (0x90, 0x61):
            return "", "Legacy UICC"
        data, sw1, _sw2 = transporter.transmit("80CA5A00", silent=True)
        if sw1 != 0x90 or not data:
            return "", "Legacy UICC"
        eid_bytes = bytes(data)
        # The EID tag 5A may come wrapped in its TLV envelope; peel it.
        if len(eid_bytes) >= 2 and eid_bytes[0] == 0x5A:
            length = eid_bytes[1]
            eid_bytes = eid_bytes[2 : 2 + length]
        eid_hex = eid_bytes.hex().upper()
        _data, sw1, _sw2 = transporter.transmit(
            f"00A4040010{isdr_aid}", silent=True
        )
        standard = "eUICC" if sw1 in (0x90, 0x61) else "UICC + ECASD"
        return eid_hex, standard
    except Exception:  # noqa: BLE001
        return "", "Legacy UICC"


ATR_SPEC = ActionSpec(
    id="scp03.atr",
    subsystem="SCP03",
    title="ATR details",
    description=(
        "Cold-reset the card and return the raw ATR plus a decoded "
        "interface-character summary (TS / T0 / TA(i) / TB(i) / TC(i) "
        "/ TD(i) / historical bytes). Matches the CLI ``ATR`` command "
        "byte-for-byte; pass ``reset=false`` to read the cached ATR "
        "without perturbing card state."
    ),
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
        ActionField(
            name="reset",
            label="Cold-reset before reading",
            kind="bool",
            required=False,
            default=True,
            help=(
                "When true (default, matches the CLI), issues a PC/SC reset "
                "so the returned ATR reflects the card's live answer-to-"
                "reset instead of a value cached at session-open time."
            ),
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_atr,
    requires_card=True,
    tags=("atr", "read-only"),
)


ENSURE_FS_ROOT_SPEC = ActionSpec(
    id="scp03.ensure_fs_root",
    subsystem="SCP03",
    title="Re-select MF (file-system root)",
    description=(
        "Select MF (3F00) on the card and re-sync the FS controller's "
        "``current_fid`` + ``current_path_hint``. Used by the GUI to "
        "bring the card back to a known DF after an ISD-R / eUICC "
        "operation drifted the current selection; safe to invoke at "
        "any time (idempotent)."
    ),
    inputs=(ActionField(name="session_id", label="Session", kind="string", required=True),),
    output_kind="json",
    dispatcher=_dispatch_ensure_fs_root,
    requires_card=True,
    tags=("fs", "context", "read-only"),
)


RESET_SPEC = ActionSpec(
    id="scp03.reset",
    subsystem="SCP03",
    title="Reset card",
    description=(
        "Cold-reset the card via the PC/SC transporter and re-read the "
        "ATR. Drops any in-memory secure-channel state on the session."
    ),
    inputs=(ActionField(name="session_id", label="Session", kind="string", required=True),),
    output_kind="json",
    dispatcher=_dispatch_reset,
    requires_card=True,
    tags=("reset", "lifecycle"),
)


RECOVER_SESSION_SPEC = ActionSpec(
    id="scp03.recover_session",
    subsystem="SCP03",
    title="Recover FS state (reset + rescan)",
    description=(
        "Cold-reset the card, drop any secure-channel state, then walk "
        "the file-system tree afresh and swap the new FileSystemController "
        "into the session. Used by the GUI to auto-heal the file view "
        "after an eUICC / ISD-R side trip leaves the card parked on a "
        "non-MF DF. Returns the same ``tree`` / ``scan_cache`` shape as "
        "``scp03.scan`` so the frontend can drop the payload straight "
        "into the cached scan data."
    ),
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_recover_session,
    requires_card=True,
    tags=("reset", "lifecycle", "fs", "recovery"),
)


CARD_INFO_SPEC = ActionSpec(
    id="scp03.card_info",
    subsystem="SCP03",
    title="Card info",
    description=(
        "Summarise the card: ATR, ICCID, EID (if ECASD responds), and "
        "an inferred standard label (Legacy UICC / UICC + ECASD / eUICC)."
    ),
    inputs=(ActionField(name="session_id", label="Session", kind="string", required=True),),
    output_kind="json",
    dispatcher=_dispatch_card_info,
    requires_card=True,
    tags=("info", "read-only"),
)


# -- scp03.decode ------------------------------------------------------


def _dispatch_decode(
    ctx: ActionContext,
    *,
    hex_data: Any = None,
    fid: Any = None,
    context_path: Any = None,
) -> dict[str, Any]:
    """Decode an arbitrary hex blob as BER-TLV, falling back to registry LV."""
    raw_text = str(hex_data or "").strip()
    if len(raw_text) == 0:
        raise ValueError("hex_data is required (raw hex, spaces tolerated).")
    compact = raw_text.replace(" ", "").replace("_", "").replace("-", "")
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    try:
        data = bytes.fromhex(compact)
    except ValueError as error:
        raise ValueError(f"invalid hex string: {error}") from error

    from SCP03.core.utils import TlvParser

    parse_info = TlvParser.parse_detailed(data) or {}
    parsed = parse_info.get("parsed") or []
    complete = bool(parse_info.get("complete"))
    consumed = int(parse_info.get("consumed") or 0)
    error_note = parse_info.get("error") or ""

    fid_text = str(fid or "").strip().upper()
    path_text = str(context_path or "").strip()
    content_decoded: Any = None
    content_error = ""
    if len(fid_text) > 0 and len(path_text) > 0:
        try:
            content_decoded = _decode_content_safely(fid_text, compact.upper(), path_text)
        except Exception as error:  # noqa: BLE001
            content_error = str(error)

    result: dict[str, Any] = {
        "input_hex": compact.upper(),
        "byte_count": len(data),
        "complete": complete,
        "consumed": consumed,
        "error": str(error_note) if error_note else "",
        "parsed": _sanitise_for_json(parsed),
        "registry_stream": None,
        "content_decoded": content_decoded,
        "content_error": content_error,
    }

    if complete is False or len(parsed) == 0:
        registry_entries = _decode_registry_stream(data)
        if registry_entries is not None:
            result["registry_stream"] = registry_entries
            result["kind"] = "registry"
            return result
        result["kind"] = "incomplete"
        return result

    result["kind"] = "tlv"
    return result


def _decode_registry_stream(data: bytes) -> list[dict[str, Any]] | None:
    """Parse GP-style LV registry streams (AID-LEN | AID | STATE | EXTRA)."""
    entries: list[dict[str, Any]] = []
    index = 0
    while index < len(data):
        if index + 3 > len(data):
            return None
        aid_len = data[index]
        if aid_len < 5 or aid_len > 16:
            return None
        index += 1
        if index + aid_len + 2 > len(data):
            return None
        aid = data[index : index + aid_len]
        if len(aid) == 0 or aid[0] != 0xA0:
            return None
        index += aid_len
        state_byte = data[index]
        extra_byte = data[index + 1]
        index += 2
        entries.append(
            {
                "aid": aid.hex().upper(),
                "state": int(state_byte),
                "state_hex": f"{state_byte:02X}",
                "extra": int(extra_byte),
                "extra_hex": f"{extra_byte:02X}",
            }
        )
    if len(entries) == 0:
        return None
    return entries


DECODE_SPEC = ActionSpec(
    id="scp03.decode",
    subsystem="SCP03",
    title="Decode hex",
    description=(
        "Decode a raw hex blob. Tries BER-TLV first; falls back to the "
        "GP LV registry-stream shape if the bytes are not valid TLV."
    ),
    inputs=(
        ActionField(
            name="hex_data",
            label="Hex",
            kind="string",
            required=True,
            placeholder="A0 00 00 05 59 10 10 ...",
            help="Hex bytes to decode. Whitespace / 0x / dashes are stripped.",
        ),
        ActionField(
            name="fid",
            label="FID hint (optional)",
            kind="hex",
            required=False,
            placeholder="6F07",
            help="When set with context_path, also run ContentDecoder.decode_obj.",
        ),
        ActionField(
            name="context_path",
            label="Path hint (optional)",
            kind="string",
            required=False,
            placeholder="MF/ADF_USIM/EF_IMSI",
            help="Path used by the content decoder for table-specific decoding.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_decode,
    requires_card=False,
    tags=("decode", "tlv"),
)


# -- scp03.send_apdu ---------------------------------------------------


def _normalise_apdu_hex(raw: str) -> str:
    """Strip whitespace / 0x / dashes, upper-case, validate as hex."""
    text = str(raw or "").strip()
    if len(text) == 0:
        raise ValueError("apdu is required (hex string).")
    compact = text.replace(" ", "").replace("-", "").replace("_", "").replace("\t", "")
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if len(compact) % 2 != 0:
        raise ValueError("apdu must be an even-length hex string.")
    for ch in compact:
        if ch not in "0123456789abcdefABCDEF":
            raise ValueError(f"apdu contains non-hex character: {ch!r}")
    if len(compact) < 8:
        raise ValueError("apdu must be at least 4 bytes (CLA INS P1 P2).")
    return compact.upper()


def _parse_apdu_breakdown(apdu_hex: str) -> dict[str, Any]:
    """Classify the APDU as ISO 7816-4 case 1/2/3/4 and return the TLV slices.

    Case 1 : CLA INS P1 P2                         (4 bytes)
    Case 2 : CLA INS P1 P2 Le                      (5 bytes)
    Case 3 : CLA INS P1 P2 Lc Data                 (5 + Lc bytes)
    Case 4 : CLA INS P1 P2 Lc Data Le              (6 + Lc bytes)

    The ambiguous 5-byte form is reported as Case 2 (Le = last byte).
    A zero-Lc case-3 header with trailing data is treated as a
    case-4 APDU with Le omitted, matching how ``transporter.transmit``
    forwards the raw bytes to the card.
    """
    raw = bytes.fromhex(apdu_hex)
    total = len(raw)
    result: dict[str, Any] = {
        "cla": apdu_hex[0:2],
        "ins": apdu_hex[2:4],
        "p1": apdu_hex[4:6],
        "p2": apdu_hex[6:8],
        "lc": "",
        "data_hex": "",
        "data_length": 0,
        "le": "",
        "case": "",
        "byte_count": total,
    }
    if total == 4:
        result["case"] = "1"
        return result
    if total == 5:
        result["case"] = "2"
        result["le"] = apdu_hex[8:10]
        return result
    lc = raw[4]
    if lc == 0 and total > 5:
        # Extended-length APDUs start with 00 as Lc placeholder; we
        # don't decode extended form here (most cards in this repo
        # reject it) — just pass the bytes through unannotated.
        result["case"] = "ext"
        result["lc"] = apdu_hex[8:10]
        result["data_hex"] = apdu_hex[10:]
        result["data_length"] = (total - 5)
        return result
    expected_case3 = 5 + lc
    expected_case4 = 6 + lc
    if total == expected_case3:
        result["case"] = "3"
        result["lc"] = apdu_hex[8:10]
        result["data_hex"] = apdu_hex[10:]
        result["data_length"] = lc
        return result
    if total == expected_case4:
        result["case"] = "4"
        result["lc"] = apdu_hex[8:10]
        result["data_hex"] = apdu_hex[10 : 10 + lc * 2]
        result["data_length"] = lc
        result["le"] = apdu_hex[-2:]
        return result
    # Malformed — return what we parsed so the GUI can surface it as
    # a warning next to the field; the card will likely reject it.
    result["case"] = "malformed"
    result["lc"] = apdu_hex[8:10]
    result["data_hex"] = apdu_hex[10:]
    result["data_length"] = max(total - 5, 0)
    return result


def _apdu_with_corrected_le(apdu_hex: str, correct_le: int) -> str:
    """Return the APDU with its final Le byte replaced by ``correct_le``.

    Cards reply 0x6Cxx when the transmitted Le is wrong; the standard
    retry is to re-send the exact same header/body but with Le = xx.
    For case-1/3 APDUs (no Le to begin with) we append the new Le.
    """
    breakdown = _parse_apdu_breakdown(apdu_hex)
    new_le = f"{correct_le:02X}"
    case = str(breakdown.get("case") or "")
    if case == "1":
        return apdu_hex + new_le
    if case == "2":
        return apdu_hex[:-2] + new_le
    if case == "3":
        return apdu_hex + new_le
    if case == "4":
        return apdu_hex[:-2] + new_le
    # "ext" / "malformed" — best effort: replace or append.
    if len(apdu_hex) >= 10:
        return apdu_hex[:-2] + new_le
    return apdu_hex + new_le


def _ascii_preview(data: bytes) -> str:
    """Render printable ASCII for a response blob (non-printable → '.')."""
    if not data:
        return ""
    chars: list[str] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            chars.append(chr(byte))
        else:
            chars.append(".")
    return "".join(chars)


def _dispatch_send_apdu(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    apdu: Any = None,
    follow_61: Any = True,
    retry_6c: Any = True,
) -> dict[str, Any]:
    """Transmit an arbitrary hex APDU on the active session.

    Operator power tool. Does **not** go through ``fs_controller.select``
    so the card's current DF / AID is left exactly where the APDU put
    it — the whole point of this action is to let engineers drive the
    card directly. The next FS-tree click will pre-restore MF via
    ``_dispatch_read_selected``, so the operator can mix raw APDU
    surgery with file-tree navigation without hunting for a separate
    "reset my view" button.

    Automatic chaining mirrors the CLI shell:

      * ``61xx`` (more data available) → issues ``00C00000xx`` GET
        RESPONSE until SW != 0x61, concatenating the returned bytes.
        Bounded to 16 follow-ups to avoid loops on misbehaving cards.
      * ``6Cxx`` (wrong Le) → re-sends the original APDU once with the
        corrected Le byte. A second 6Cxx aborts the chain (that would
        indicate a card-side bug, not a usable retry).

    Returns the decoded breakdown, the fully-merged response data +
    ASCII preview, the final SW, a human-readable SW translation
    (via ``StatusWordTranslator.translate``), and a ``chain`` list so
    the UI can show the implicit follow-up APDUs alongside the one
    the operator typed.
    """
    session, transporter, sid = _get_scp03_session(session_id)

    apdu_hex = _normalise_apdu_hex(apdu)
    breakdown = _parse_apdu_breakdown(apdu_hex)

    follow_61_flag = bool(follow_61) if not isinstance(follow_61, str) else (
        follow_61.strip().lower() not in ("false", "0", "no", "off", "")
    )
    retry_6c_flag = bool(retry_6c) if not isinstance(retry_6c, str) else (
        retry_6c.strip().lower() not in ("false", "0", "no", "off", "")
    )

    # Initial transmit — capture any stdout the transporter emits so
    # the secure-channel wrapper's own debug prints don't leak into
    # the server log. We don't surface that trace; the GUI's APDU
    # panel has its own pre/post view of the wire.
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        data, sw1, sw2 = transporter.transmit(apdu_hex, silent=True)

    chain: list[dict[str, Any]] = []
    merged = bytes(data or b"")
    steps_budget = 16

    while steps_budget > 0:
        steps_budget -= 1
        if sw1 == 0x61 and follow_61_flag:
            length = sw2 if sw2 != 0 else 0x00
            get_resp = f"00C00000{length:02X}"
            chunk, sw1, sw2 = transporter.transmit(get_resp, silent=True)
            chunk_bytes = bytes(chunk or b"")
            merged = merged + chunk_bytes
            chain.append({
                "apdu": get_resp,
                "reason": "GET RESPONSE",
                "response_hex": chunk_bytes.hex().upper(),
                "response_length": len(chunk_bytes),
                "sw": f"{sw1:02X}{sw2:02X}",
            })
            continue
        if sw1 == 0x6C and retry_6c_flag:
            retry_apdu = _apdu_with_corrected_le(apdu_hex, sw2)
            chunk, sw1, sw2 = transporter.transmit(retry_apdu, silent=True)
            chunk_bytes = bytes(chunk or b"")
            # 6C retry replaces the response (same logical read, new Le)
            merged = chunk_bytes
            chain.append({
                "apdu": retry_apdu,
                "reason": "retry with corrected Le",
                "response_hex": chunk_bytes.hex().upper(),
                "response_length": len(chunk_bytes),
                "sw": f"{sw1:02X}{sw2:02X}",
            })
            # Only retry 6Cxx once — a second short-read is a card bug.
            retry_6c_flag = False
            continue
        break

    sw_hex = f"{sw1:02X}{sw2:02X}"
    try:
        from SCP03.core.utils import StatusWordTranslator
        sw_meaning = StatusWordTranslator.translate(sw1, sw2)
    except Exception:  # noqa: BLE001
        sw_meaning = ""

    response_hex = merged.hex().upper()

    return {
        "session_id": sid,
        "apdu": apdu_hex,
        "breakdown": breakdown,
        "response_hex": response_hex,
        "response_length": len(merged),
        "response_ascii": _ascii_preview(merged),
        "sw": sw_hex,
        "sw1": f"{sw1:02X}",
        "sw2": f"{sw2:02X}",
        "sw_meaning": sw_meaning,
        "ok": sw1 == 0x90,
        "chain": chain,
        "follow_61_enabled": follow_61_flag,
        "retry_6c_enabled": bool(retry_6c),
    }


SEND_APDU_SPEC = ActionSpec(
    id="scp03.send_apdu",
    subsystem="SCP03",
    title="Send APDU (raw)",
    description=(
        "Transmit an arbitrary hex APDU on the active session. Auto-"
        "follows ``61xx`` with GET RESPONSE and retries ``6Cxx`` with "
        "the card-suggested Le. Does NOT restore MF afterwards — the "
        "card's DF / AID is left exactly where your APDU put it."
    ),
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
        ActionField(
            name="apdu",
            label="APDU (hex)",
            kind="string",
            required=True,
            placeholder="00A40004023F00",
            help="Raw ISO 7816-4 APDU. Whitespace / 0x / dashes are stripped.",
        ),
        ActionField(
            name="follow_61",
            label="Auto-follow 61xx (GET RESPONSE)",
            kind="bool",
            required=False,
            default=True,
            help="When the card returns 61xx, issue 00C00000xx and append the returned bytes.",
        ),
        ActionField(
            name="retry_6c",
            label="Auto-retry 6Cxx (wrong Le)",
            kind="bool",
            required=False,
            default=True,
            help="When the card returns 6Cxx, re-send the same APDU with Le = xx.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_send_apdu,
    requires_card=True,
    tags=("apdu", "raw", "operator"),
)


# -- scp03.read_binary + scp03.read_record -----------------------------


def _dispatch_read_binary(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    path: Any = None,
) -> dict[str, Any]:
    """Standalone READ BINARY. Optionally SELECTs a path first."""
    session, transporter, sid = _get_scp03_session(session_id)
    fs_controller = session.handle["fs"]

    path_text = str(path or "").strip()
    select_trace = ""
    if path_text:
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink):
            ok = fs_controller.select(path_text, silent=False)
        select_trace = _strip_ansi(sink.getvalue())
        if ok is False:
            return {
                "session_id": sid,
                "path": path_text,
                "selected": False,
                "select_trace": select_trace,
                "ok": False,
                "hex": "",
                "length": 0,
                "decoded": None,
                "sw": "0000",
            }

    structure = str((fs_controller.current_fcp or {}).get("structure") or "").strip()
    fid = str(fs_controller.current_fid or "").upper()

    data, sw1, sw2 = transporter.transmit("00B0000000", silent=True)
    hex_data = data.hex().upper() if data else ""
    ok = sw1 == 0x90
    decoded = _decode_content_safely(fid, hex_data, path_text) if ok else None

    return {
        "session_id": sid,
        "path": path_text,
        "selected": True if path_text else None,
        "select_trace": select_trace,
        "structure": structure,
        "fid": fid,
        "sw": f"{sw1:02X}{sw2:02X}",
        "ok": ok,
        "hex": hex_data,
        "length": len(data or b""),
        "decoded": decoded,
    }


def _dispatch_read_record(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    selector: Any = None,
    path: Any = None,
) -> dict[str, Any]:
    """Read records by number (``N``), range (``Start-End``), or ``ALL``."""
    session, transporter, sid = _get_scp03_session(session_id)
    fs_controller = session.handle["fs"]

    sel_text = str(selector or "").strip()
    if len(sel_text) == 0:
        raise ValueError("selector is required (N, ALL, or Start-End).")

    # Parse selector now so we reject bad syntax before touching the card.
    start, end = _parse_record_range(sel_text)

    path_text = str(path or "").strip()
    select_trace = ""
    if path_text:
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink):
            ok = fs_controller.select(path_text, silent=False)
        select_trace = _strip_ansi(sink.getvalue())
        if ok is False:
            return {
                "session_id": sid,
                "path": path_text,
                "selector": sel_text,
                "selected": False,
                "select_trace": select_trace,
                "records": [],
            }

    structure = str((fs_controller.current_fcp or {}).get("structure") or "").strip()
    if structure not in ("Linear Fixed", "Cyclic"):
        return {
            "session_id": sid,
            "path": path_text,
            "selector": sel_text,
            "structure": structure,
            "ok": False,
            "note": f"RECORD not allowed on {structure!r}; select a Linear Fixed or Cyclic EF.",
            "records": [],
        }

    fcp = fs_controller.current_fcp or {}
    rec_len = 0
    try:
        rec_len = int(fcp.get("rec_len", 0) or 0)
    except (TypeError, ValueError):
        rec_len = 0
    le_byte = f"{rec_len:02X}" if 0 < rec_len < 0x100 else "00"

    records: list[dict[str, Any]] = []
    fid = str(fs_controller.current_fid or "").upper()
    stop_reason = "end"
    record_number = start
    while True:
        if end is not None and record_number > end:
            break
        if record_number > 254:
            stop_reason = "max_records_reached"
            break
        apdu = f"00B2{record_number:02X}04{le_byte}"
        data, sw1, sw2 = transporter.transmit(apdu, silent=True)
        if sw1 == 0x6C and sw2 > 0:
            apdu = f"00B2{record_number:02X}04{sw2:02X}"
            data, sw1, sw2 = transporter.transmit(apdu, silent=True)
        sw_str = f"{sw1:02X}{sw2:02X}"
        if sw1 != 0x90:
            if sw1 == 0x6A:
                stop_reason = "record_not_found"
            else:
                stop_reason = f"sw_{sw_str}"
            if end is None:
                break
            records.append({
                "record_number": record_number,
                "sw": sw_str,
                "ok": False,
                "hex": "",
                "length": 0,
                "decoded": None,
                "empty": True,
            })
            record_number += 1
            continue
        hex_data = data.hex().upper() if data else ""
        is_empty = len(hex_data) > 0 and (
            all(ch == "F" for ch in hex_data) or all(ch == "0" for ch in hex_data)
        )
        decoded = None if is_empty else _decode_content_safely(fid, hex_data, path_text)
        records.append({
            "record_number": record_number,
            "sw": sw_str,
            "ok": True,
            "hex": hex_data,
            "length": len(data or b""),
            "decoded": decoded,
            "empty": is_empty,
        })
        record_number += 1

    return {
        "session_id": sid,
        "path": path_text,
        "selector": sel_text,
        "structure": structure,
        "rec_len": rec_len,
        "start": start,
        "end": end,
        "stop_reason": stop_reason,
        "record_count": len(records),
        "records": records,
    }


def _parse_record_range(text: str) -> tuple[int, int | None]:
    """Return (start, end-or-None) for ``N`` / ``ALL`` / ``Start-End``."""
    token = text.strip().upper()
    if token in ("ALL", "*"):
        return 1, None
    if "-" in token:
        parts = token.split("-", 1)
        try:
            start = int(parts[0].strip())
            end = int(parts[1].strip())
        except ValueError as error:
            raise ValueError(
                f"invalid record range {text!r} (expected N or Start-End or ALL)"
            ) from error
        if start < 1 or end < start:
            raise ValueError(f"invalid record range bounds: {start}-{end}")
        return start, end
    try:
        single = int(token)
    except ValueError as error:
        raise ValueError(
            f"invalid record selector {text!r} (expected N or Start-End or ALL)"
        ) from error
    if single < 1:
        raise ValueError(f"record number must be >= 1 (got {single})")
    return single, single


READ_BINARY_SPEC = ActionSpec(
    id="scp03.read_binary",
    subsystem="SCP03",
    title="Read binary",
    description=(
        "READ BINARY against the active session. Optionally SELECTs a "
        "path first. Returns the raw hex and the content-decoded view."
    ),
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
        ActionField(
            name="path",
            label="Path (optional)",
            kind="string",
            required=False,
            placeholder="MF/ADF_USIM/EF_IMSI or blank",
            help="Leave blank to read whatever is currently selected.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_read_binary,
    requires_card=True,
    tags=("read", "transparent"),
)


READ_RECORD_SPEC = ActionSpec(
    id="scp03.read_record",
    subsystem="SCP03",
    title="Read record(s)",
    description=(
        "READ RECORD against a Linear Fixed / Cyclic EF. Selector may "
        "be a single record number, a range ``Start-End``, or ``ALL``."
    ),
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
        ActionField(
            name="selector",
            label="Selector",
            kind="string",
            required=True,
            placeholder="1 / ALL / 1-5",
            help="Record number, range, or ALL.",
        ),
        ActionField(
            name="path",
            label="Path (optional)",
            kind="string",
            required=False,
            placeholder="MF/ADF_USIM/EF_SMS or blank",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_read_record,
    requires_card=True,
    tags=("read", "records"),
)


# -- scp03.arr + scp03.dump_fs -----------------------------------------


def _dispatch_arr(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    path: Any = None,
) -> dict[str, Any]:
    """Read EF.ARR and return the decoded security rules as captured lines."""
    session, _transporter, sid = _get_scp03_session(session_id)
    fs_controller = session.handle["fs"]
    path_text = str(path or "").strip() or None

    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        try:
            fs_controller.get_arr(path=path_text)
        except Exception as error:  # noqa: BLE001
            print(f"[!] ARR error: {error}")
    trace = _strip_ansi(sink.getvalue())

    # Split into lines and flag success if we see the header we emit.
    lines = [line for line in trace.split("\n") if line.strip()]
    ok = any("--- ARR (" in line for line in lines)
    return {
        "session_id": sid,
        "path": path_text or "(current)",
        "ok": ok,
        "lines": lines,
        "raw_trace": trace,
    }


def _dispatch_dump_fs(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    output_dir: Any = None,
) -> dict[str, Any]:
    """Dump the full live FS to an ``<output_dir>/<ICCID>/`` tree."""
    import os as _os
    from pathlib import Path as _Path

    session, _transporter, sid = _get_scp03_session(session_id)
    fs_controller = session.handle["fs"]

    out_text = str(output_dir or "").strip()
    if len(out_text) == 0:
        out_text = str(_Path(_os.path.expanduser("~/Documents")) / "FS_DUMP")
    else:
        out_text = str(_Path(_os.path.expanduser(out_text)))

    if _os.path.basename(out_text) != "FS_DUMP":
        out_text = str(_Path(out_text) / "FS_DUMP")

    sink = io.StringIO()
    err: str = ""
    with contextlib.redirect_stdout(sink):
        try:
            fs_controller.dump_live_fs(out_text)
        except Exception as error:  # noqa: BLE001
            err = str(error)
    trace = _strip_ansi(sink.getvalue())

    # Try to surface the per-ICCID root directory that dump_live_fs created.
    created_root = ""
    try:
        root = _Path(out_text).resolve()
        if root.is_dir():
            subdirs = [p for p in root.iterdir() if p.is_dir()]
            subdirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            if len(subdirs) > 0:
                created_root = str(subdirs[0])
    except Exception:  # noqa: BLE001
        created_root = ""

    return {
        "session_id": sid,
        "output_dir": out_text,
        "created_root": created_root,
        "ok": err == "" and len(trace) > 0,
        "error": err,
        "raw_trace": trace,
        "lines": [line for line in trace.split("\n") if line.strip()],
    }


ARR_SPEC = ActionSpec(
    id="scp03.arr",
    subsystem="SCP03",
    title="Read EF.ARR",
    description=(
        "Decode EF.ARR (access rules). If no path is supplied, uses "
        "whatever is currently selected and chooses between 2F06 "
        "(MF-scope) and 6F06 (ADF-scope) heuristically."
    ),
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
        ActionField(
            name="path",
            label="Path (optional)",
            kind="string",
            required=False,
            placeholder="MF / USIM / FID (leave blank = current)",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_arr,
    requires_card=True,
    tags=("arr", "security"),
)


DUMP_FS_SPEC = ActionSpec(
    id="scp03.dump_fs",
    subsystem="SCP03",
    title="Dump file system",
    description=(
        "Walk the live file system and dump every reachable DF/EF to "
        "disk under ``<output_dir>/FS_DUMP/<ICCID>/``. Per-file text "
        "files carry FCP + raw + decoded payload."
    ),
    inputs=(
        ActionField(name="session_id", label="Session", kind="string", required=True),
        ActionField(
            name="output_dir",
            label="Output dir",
            kind="directory",
            required=False,
            placeholder="~/Documents (default)",
            help="Parent directory; the dumper creates an FS_DUMP/<ICCID>/ tree inside. Double-click to browse.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_dump_fs,
    requires_card=True,
    tags=("dump", "fs"),
)


get_registry().register(SCAN_SPEC)
get_registry().register(READ_SELECTED_SPEC)
get_registry().register(SELECT_SPEC)
get_registry().register(LIST_APPS_SPEC)
get_registry().register(CLOSE_SESSION_SPEC)

get_registry().register(ATR_SPEC)
get_registry().register(ENSURE_FS_ROOT_SPEC)
get_registry().register(RESET_SPEC)
get_registry().register(RECOVER_SESSION_SPEC)
get_registry().register(CARD_INFO_SPEC)
get_registry().register(DECODE_SPEC)
get_registry().register(SEND_APDU_SPEC)
get_registry().register(READ_BINARY_SPEC)
get_registry().register(READ_RECORD_SPEC)
get_registry().register(ARR_SPEC)
get_registry().register(DUMP_FS_SPEC)


# ======================================================================
# C-2 — auth + GP registry + profile telemetry
# ======================================================================
#
# Every C-2 dispatcher reuses the existing scp03 session (same transporter
# that ``scp03.scan`` parked in the session manager). GP-layer helpers
# (``GlobalPlatformManager``) are lazily instantiated per session and
# cached on ``session.handle["gp"]``; they survive as long as the tab.


def _get_or_make_gp_ctrl(session: Any) -> Any:
    """Return the cached ``GlobalPlatformManager`` or build one on demand.

    Keys default to ``Config.DEFAULT_KEYS`` (the demo values). Callers that
    need custom keys should rebuild the manager explicitly via
    ``session.handle['gp'] = None`` before dispatching.
    """
    gp = session.handle.get("gp")
    if gp is not None:
        return gp
    from SCP03.config import Config as Scp03Config
    from SCP03.logic.gp import GlobalPlatformManager

    keys = dict(Scp03Config.DEFAULT_KEYS)
    transporter = session.handle["transporter"]
    # Silence any stderr banners the GP manager wants to push on boot —
    # ``pending_demo_keys_warning`` is surfaced via the response instead.
    gp = GlobalPlatformManager(transporter, keys)
    session.handle["gp"] = gp
    return gp


def _run_gp_quietly(gp: Any, fn_name: str, *args: Any, **kwargs: Any) -> tuple[Any, str]:
    """Run a GP manager method, capturing its stdout into a text blob."""
    fn = getattr(gp, fn_name)
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        result = fn(*args, **kwargs)
    return result, _strip_ansi(sink.getvalue())


def _session_auth_status(transporter: Any) -> dict[str, Any]:
    """Snapshot the current secure session on a transporter, if any."""
    session = getattr(transporter, "session", None)
    if session is None:
        return {"authenticated": False, "protocol": None, "kvn": None}
    is_auth = bool(getattr(session, "is_authenticated", False))
    protocol = getattr(session, "protocol_name", None)
    sec_level = getattr(session, "sec_level", None)
    sec_level_hex = f"{sec_level:02X}" if isinstance(sec_level, int) else None
    return {
        "authenticated": is_auth,
        "protocol": protocol,
        "sec_level": sec_level_hex,
    }


def _apply_auth_key_overrides(
    gp: Any,
    protocol: str,
    *,
    kvn_override: str,
    enc_override: str,
    mac_override: str,
    dek_override: str,
) -> dict[str, str]:
    """Swap the GP manager's keyset for this authenticate call.

    Returns the set of fields that were actually overridden so the
    response can tell the caller which key material took effect (the
    GUI's auth prompt surfaces this so operators know whether they hit
    the workspace default or a session-scoped override).

    All values are hex strings; empty / whitespace-only inputs mean
    "leave the underlying key untouched". Malformed hex raises
    ``ValueError`` — the GP manager would otherwise crash downstream
    with a cryptography stack trace that's painful to decode at the
    action layer.
    """
    applied: dict[str, str] = {}
    proto = str(protocol or "SCP03").strip().upper()

    def _clean(raw: Any, label: str) -> str:
        text = str(raw or "").strip().upper().replace(" ", "")
        if len(text) == 0:
            return ""
        try:
            bytes.fromhex(text)
        except ValueError as error:
            raise ValueError(f"invalid {label}: {error}") from error
        return text

    enc_hex = _clean(enc_override, "enc_key")
    mac_hex = _clean(mac_override, "mac_key")
    dek_hex = _clean(dek_override, "dek_key")
    kvn_hex = _clean(kvn_override, "kvn")
    if len(kvn_hex) > 0 and len(kvn_hex) != 2:
        raise ValueError(f"kvn must be a single byte (2 hex chars), got {kvn_override!r}")

    if proto == "SCP02":
        keyset = getattr(gp, "scp02_keys", None) or {}
        if enc_hex:
            keyset["enc"] = bytes.fromhex(enc_hex); applied["enc_key"] = enc_hex
        if mac_hex:
            keyset["mac"] = bytes.fromhex(mac_hex); applied["mac_key"] = mac_hex
        if dek_hex:
            keyset["dek"] = bytes.fromhex(dek_hex); applied["dek_key"] = dek_hex
        if kvn_hex:
            gp.scp02_kvn = int(kvn_hex, 16); applied["kvn"] = kvn_hex
    else:
        keyset = getattr(gp, "scp03_keys", None) or {}
        if enc_hex:
            keyset["kenc"] = bytes.fromhex(enc_hex); applied["enc_key"] = enc_hex
        if mac_hex:
            keyset["kmac"] = bytes.fromhex(mac_hex); applied["mac_key"] = mac_hex
        if dek_hex:
            keyset["dek"] = bytes.fromhex(dek_hex); applied["dek_key"] = dek_hex
        if kvn_hex:
            gp.scp03_kvn = int(kvn_hex, 16); applied["kvn"] = kvn_hex

    return applied


def _dispatch_auth(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_aid: Any = None,
    protocol: str = "SCP03",
    kvn: Any = None,
    enc_key: Any = None,
    mac_key: Any = None,
    dek_key: Any = None,
) -> dict[str, Any]:
    """Authenticate the active session to a Security Domain (SCP03/02).

    The optional ``kvn`` / ``enc_key`` / ``mac_key`` / ``dek_key`` hex
    overrides bypass the workspace config so the operator can authenticate
    against a card whose production keys aren't checked into the Workspace
    keybag. Empty / omitted values fall through to ``Config.DEFAULT_KEYS``
    as before — the override is purely additive so existing callers keep
    working.
    """
    session, transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)

    aid_text = str(target_aid or "").strip().upper().replace(" ", "")
    if len(aid_text) > 0:
        # Override the GP manager's target AID before authentication so the
        # session binds to the requested SD.
        try:
            gp.target_aid = bytes.fromhex(aid_text)
        except ValueError as error:
            raise ValueError(f"invalid target_aid hex: {error}") from error

    protocol_norm = str(protocol or "SCP03").strip().upper()
    if protocol_norm not in ("SCP03", "SCP02"):
        raise ValueError(f"unsupported protocol: {protocol_norm!r}")

    applied_overrides = _apply_auth_key_overrides(
        gp,
        protocol_norm,
        kvn_override=kvn,
        enc_override=enc_key,
        mac_override=mac_key,
        dek_override=dek_key,
    )

    ok, trace = _run_gp_quietly(gp, "authenticate", protocol_norm)

    status = _session_auth_status(transporter)
    kvn_hex = None
    if protocol_norm == "SCP03":
        kvn_hex = f"{gp.scp03_kvn:02X}"
    else:
        kvn_hex = f"{gp.scp02_kvn:02X}"
    return {
        "session_id": sid,
        "ok": bool(ok),
        "protocol": protocol_norm,
        "target_aid": gp.target_aid.hex().upper(),
        "kvn": kvn_hex,
        "authenticated": status.get("authenticated", False),
        "active_protocol": gp.get_active_protocol_name(),
        "sec_level": status.get("sec_level"),
        # Which override fields actually took effect (never includes the
        # key bytes themselves — just the names, so the GUI can show a
        # "used custom keys" chip without leaking material into the log).
        "overrides_applied": sorted(applied_overrides.keys()),
        "trace": trace,
    }


def _dispatch_auth_scp03(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_aid: Any = None,
    kvn: Any = None,
    enc_key: Any = None,
    mac_key: Any = None,
    dek_key: Any = None,
) -> dict[str, Any]:
    return _dispatch_auth(
        ctx,
        session_id=session_id,
        target_aid=target_aid,
        protocol="SCP03",
        kvn=kvn,
        enc_key=enc_key,
        mac_key=mac_key,
        dek_key=dek_key,
    )


def _dispatch_auth_scp02(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_aid: Any = None,
    kvn: Any = None,
    enc_key: Any = None,
    mac_key: Any = None,
    dek_key: Any = None,
) -> dict[str, Any]:
    return _dispatch_auth(
        ctx,
        session_id=session_id,
        target_aid=target_aid,
        protocol="SCP02",
        kvn=kvn,
        enc_key=enc_key,
        mac_key=mac_key,
        dek_key=dek_key,
    )


def _dispatch_auth_status(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Report the current secure-session state without touching the card.

    The GUI polls this when a tab is restored from ``localStorage`` — the
    saved ``sessionId`` may still resolve to a live SCP session on the
    backend, in which case the operator shouldn't have to re-authenticate
    just because they reloaded the page. Purely observational; no APDUs
    are sent, no key material is dereferenced.
    """
    session, transporter, sid = _get_scp03_session(session_id)
    gp = session.handle.get("gp") if hasattr(session, "handle") else None
    status = _session_auth_status(transporter)
    target_aid_hex = ""
    active_protocol = status.get("protocol") or ""
    if gp is not None:
        try:
            target_aid_hex = bytes(getattr(gp, "target_aid", b"") or b"").hex().upper()
        except Exception:  # noqa: BLE001 — best-effort, not a hard error
            target_aid_hex = ""
        try:
            active_protocol = active_protocol or gp.get_active_protocol_name()
        except Exception:  # noqa: BLE001
            pass
    return {
        "session_id": sid,
        "authenticated": bool(status.get("authenticated", False)),
        "protocol": active_protocol or "",
        "sec_level": status.get("sec_level") or "",
        "target_aid": target_aid_hex,
    }


def _dispatch_logout(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    """Close any live SCP03/02 session on the transporter (no reader release)."""
    _session, transporter, sid = _get_scp03_session(session_id)
    was_active = False
    try:
        was_active = bool(transporter.logout())
    except Exception:  # noqa: BLE001 — surface failure but never raise
        was_active = False
    return {
        "session_id": sid,
        "was_active": was_active,
        "status": _session_auth_status(transporter),
    }


def _dispatch_keys(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_aid: Any = None,
) -> dict[str, Any]:
    """Return the GP key-info template (EXTENDED INFO, tag E0)."""
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)
    aid_text = str(target_aid or "").strip().upper().replace(" ", "") or None
    info = gp.get_keys_info_data(target_aid_hex=aid_text)
    return {
        "session_id": sid,
        "target_aid": aid_text or gp.target_aid.hex().upper(),
        "status": info.get("status", ""),
        "entries": info.get("entries", []),
        "raw_hex": info.get("raw_hex", ""),
    }


def _dispatch_registry(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    kind: str = "APPS",
) -> dict[str, Any]:
    """Dump the GP card registry for one of APPS / PACKAGES / SD."""
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)
    kind_norm = str(kind or "APPS").strip().upper()
    if kind_norm not in ("APPS", "PACKAGES", "SD"):
        raise ValueError(f"registry kind must be APPS | PACKAGES | SD (got {kind!r})")
    report = gp.get_registry_data(kind=kind_norm)
    return {
        "session_id": sid,
        "kind": kind_norm,
        "status": report.get("status", ""),
        "pages": report.get("pages", 0),
        "count": report.get("count", 0),
        "entries": report.get("entries", []),
        "raw_hex": report.get("raw_hex", ""),
    }


def _dispatch_registry_apps(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    return _dispatch_registry(ctx, session_id=session_id, kind="APPS")


def _dispatch_registry_pkgs(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    return _dispatch_registry(ctx, session_id=session_id, kind="PACKAGES")


def _dispatch_registry_sd(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    return _dispatch_registry(ctx, session_id=session_id, kind="SD")


def _parse_hex_byte(text: str, *, label: str) -> int:
    """Parse a single hex byte like ``'2F'`` / ``'0x80'`` / ``128``."""
    cleaned = str(text or "").strip().lower().removeprefix("0x")
    if len(cleaned) == 0:
        raise ValueError(f"{label} is required (hex byte, e.g. 2F)")
    try:
        value = int(cleaned, 16)
    except ValueError as error:
        raise ValueError(f"invalid {label}: {text!r}") from error
    if value < 0 or value > 0xFF:
        raise ValueError(f"{label} out of range 00..FF: {text!r}")
    return value


def _dispatch_get_data(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    p1: Any = None,
    p2: Any = None,
) -> dict[str, Any]:
    """GET DATA (80CA P1 P2 00) — returns raw hex plus a TLV decode when parseable."""
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)

    p1_val = _parse_hex_byte(p1, label="P1")
    p2_val = _parse_hex_byte(p2, label="P2")

    data, sw1, sw2 = gp.get_data_raw(p1_val, p2_val)
    data_bytes = bytes(data or b"")
    decoded: Any = None
    decode_error: str | None = None
    if sw1 == 0x90 and len(data_bytes) > 0:
        try:
            from SCP03.core.utils import TlvParser

            parsed = TlvParser.parse(data_bytes)
            decoded = _tlv_parsed_to_json(parsed)
        except Exception as error:  # noqa: BLE001
            decode_error = str(error)

    return {
        "session_id": sid,
        "p1": f"{p1_val:02X}",
        "p2": f"{p2_val:02X}",
        "sw": f"{sw1:02X}{sw2:02X}",
        "length": len(data_bytes),
        "hex": data_bytes.hex().upper(),
        "decoded": decoded,
        "decode_error": decode_error,
    }


def _tlv_parsed_to_json(obj: Any) -> Any:
    """Convert the TlvParser tree (dict[int, bytes | dict | list]) into JSON-safe form."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for tag, value in obj.items():
            key = f"{tag:02X}" if isinstance(tag, int) else str(tag)
            out[key] = _tlv_parsed_to_json(value)
        return out
    if isinstance(obj, list):
        return [_tlv_parsed_to_json(item) for item in obj]
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex().upper()
    return obj


def _dispatch_list_profiles(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    """Pull the SGP.22 profile list (BF2D00) and return structured rows."""
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)
    sgp22 = gp.sgp22

    try:
        sgp22._select_isd_r()
        data, sw1, sw2 = sgp22._send_store_data_with_retry_ladder("BF2D00")
        data_bytes = bytes(data or b"")
        profiles: list[dict[str, Any]] = []
        parse_error: str | None = None
        if sw1 == 0x90 and len(data_bytes) > 0:
            try:
                profiles = list(sgp22._profile_list_to_dicts(data_bytes))
            except Exception as error:  # noqa: BLE001
                parse_error = str(error)

        return {
            "session_id": sid,
            "sw": f"{sw1:02X}{sw2:02X}",
            "count": len(profiles),
            "profiles": profiles,
            "raw_hex": data_bytes.hex().upper(),
            "parse_error": parse_error,
        }
    finally:
        _restore_fs_root_best_effort(session)


def _dispatch_profile_scan(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    """Run the bundled SGP.22/SGP.32 retrieval set and return a structured report."""
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)
    sgp22 = gp.sgp22

    try:
        report = sgp22.get_euicc_report()
        return {
            "session_id": sid,
            "eid": report.get("eid", ""),
            "profiles": report.get("profiles", []),
            "euicc_info1": report.get("euicc_info1", {}),
            "euicc_info2": report.get("euicc_info2", {}),
            "euicc_configured_data": report.get("euicc_configured_data", {}),
            "euicc_info1_raw": report.get("euicc_info1_raw", ""),
            "euicc_info2_raw": report.get("euicc_info2_raw", ""),
            "euicc_configured_data_raw": report.get("euicc_configured_data_raw", ""),
        }
    finally:
        _restore_fs_root_best_effort(session)


def _dispatch_list_aids(ctx: ActionContext) -> dict[str, Any]:
    """Read the AID registry file and return a sorted list of aliases.

    This action does NOT require a session — it reflects workspace state
    only (``Workspace/SCP03/aid.txt``). Available even when no reader is
    attached.
    """
    from SCP03.config import Config as Scp03Config

    path = str(Scp03Config.AID_FILE)
    entries: list[dict[str, str]] = []
    read_error: str | None = None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if len(line) == 0:
                    continue
                if line.startswith("#"):
                    continue
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                name = parts[0].strip().upper()
                aid = parts[1].strip().upper().replace(" ", "")
                role = parts[2].strip() if len(parts) >= 3 else ""
                if len(name) == 0 or len(aid) == 0:
                    continue
                entries.append({"name": name, "aid": aid, "role": role})
    except FileNotFoundError:
        read_error = f"aid.txt not found at {path}"
    except Exception as error:  # noqa: BLE001
        read_error = str(error)
    entries.sort(key=lambda row: row.get("name", ""))
    return {
        "path": path,
        "count": len(entries),
        "entries": entries,
        "error": read_error,
    }


# --- C-2 action specs --------------------------------------------------


_SESSION_FIELD = ActionField(
    name="session_id", label="Session", kind="string", required=True
)
_OPTIONAL_TARGET_AID_FIELD = ActionField(
    name="target_aid",
    label="Target AID",
    kind="hex",
    required=False,
    placeholder="A0000005591010FFFFFFFF8900000100",
    help="Security Domain AID to bind to. Leave blank to use ISD.",
)


# Optional key-override fields reused by both auth specs. Empty inputs
# fall through to the workspace keybag (``Config.DEFAULT_KEYS``); populated
# inputs override for this authenticate call only and are forgotten once
# the GP controller is rebuilt (rescan / reset). Never persisted.
_AUTH_KVN_FIELD = ActionField(
    name="kvn",
    label="KVN override",
    kind="hex",
    required=False,
    placeholder="e.g. 30",
    help="Optional key version number (1 byte). Blank = use the workspace default.",
)
_AUTH_ENC_FIELD = ActionField(
    name="enc_key",
    label="ENC key override",
    kind="hex",
    required=False,
    placeholder="16 / 24 / 32 bytes hex",
    help="Optional ENC/KENC key. Blank = use workspace key. Not persisted.",
    secret=True,
)
_AUTH_MAC_FIELD = ActionField(
    name="mac_key",
    label="MAC key override",
    kind="hex",
    required=False,
    placeholder="16 / 24 / 32 bytes hex",
    help="Optional MAC/KMAC key. Blank = use workspace key. Not persisted.",
    secret=True,
)
_AUTH_DEK_FIELD = ActionField(
    name="dek_key",
    label="DEK key override",
    kind="hex",
    required=False,
    placeholder="16 / 24 / 32 bytes hex",
    help="Optional DEK key. Blank = use workspace key. Not persisted.",
    secret=True,
)


AUTH_SCP03_SPEC = ActionSpec(
    id="scp03.auth_scp03",
    subsystem="SCP03",
    title="Authenticate SCP03",
    description=(
        "INITIALIZE UPDATE + EXTERNAL AUTHENTICATE against the target "
        "Security Domain. Defaults to the workspace SCP03 keys; supply "
        "KVN / ENC / MAC / DEK overrides for a session-scoped keyset."
    ),
    inputs=(
        _SESSION_FIELD,
        _OPTIONAL_TARGET_AID_FIELD,
        _AUTH_KVN_FIELD,
        _AUTH_ENC_FIELD,
        _AUTH_MAC_FIELD,
        _AUTH_DEK_FIELD,
    ),
    output_kind="json",
    dispatcher=_dispatch_auth_scp03,
    requires_card=True,
    tags=("auth", "scp03"),
)


AUTH_SCP02_SPEC = ActionSpec(
    id="scp03.auth_scp02",
    subsystem="SCP03",
    title="Authenticate SCP02",
    description=(
        "INITIALIZE UPDATE + EXTERNAL AUTHENTICATE against the target "
        "Security Domain. Defaults to the workspace SCP02 keys; supply "
        "KVN / ENC / MAC / DEK overrides for a session-scoped keyset."
    ),
    inputs=(
        _SESSION_FIELD,
        _OPTIONAL_TARGET_AID_FIELD,
        _AUTH_KVN_FIELD,
        _AUTH_ENC_FIELD,
        _AUTH_MAC_FIELD,
        _AUTH_DEK_FIELD,
    ),
    output_kind="json",
    dispatcher=_dispatch_auth_scp02,
    requires_card=True,
    tags=("auth", "scp02"),
)


AUTH_STATUS_SPEC = ActionSpec(
    id="scp03.auth_status",
    subsystem="SCP03",
    title="Secure-session status",
    description=(
        "Report whether the active session is authenticated, which "
        "protocol + Security Domain it's bound to, and the active "
        "security level. Read-only; never sends an APDU."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_auth_status,
    # Passive observational probe — inspects the cached transporter /
    # GP state for the given session but never opens a new PC/SC
    # handle and never sends an APDU. We deliberately report
    # ``requires_card=False`` so the GUI can poll auth state after a
    # page reload without competing with the active scan for the
    # reader handle (pcsc-lite serialises connections per-reader).
    requires_card=False,
    tags=("auth", "status"),
)


LOGOUT_SPEC = ActionSpec(
    id="scp03.logout",
    subsystem="SCP03",
    title="Logout (close secure session)",
    description="Drop the current SCP03/02 secure session (reader stays attached).",
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_logout,
    requires_card=True,
    tags=("auth", "logout"),
)


KEYS_SPEC = ActionSpec(
    id="scp03.keys",
    subsystem="SCP03",
    title="Keys (key-info template)",
    description=(
        "GET DATA tag E0 on the target Security Domain and decode the "
        "key template (KVN, ID, type, length)."
    ),
    inputs=(_SESSION_FIELD, _OPTIONAL_TARGET_AID_FIELD),
    output_kind="json",
    dispatcher=_dispatch_keys,
    requires_card=True,
    tags=("keys", "registry"),
)


REGISTRY_APPS_SPEC = ActionSpec(
    id="scp03.registry_apps",
    subsystem="SCP03",
    title="GP registry — applications",
    description="GET STATUS P1=40 — list installed applications and their LCS.",
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_registry_apps,
    requires_card=True,
    tags=("registry", "apps"),
)


REGISTRY_PKGS_SPEC = ActionSpec(
    id="scp03.registry_pkgs",
    subsystem="SCP03",
    title="GP registry — packages",
    description="GET STATUS P1=20 — list loaded executable load files.",
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_registry_pkgs,
    requires_card=True,
    tags=("registry", "packages"),
)


REGISTRY_SD_SPEC = ActionSpec(
    id="scp03.registry_sd",
    subsystem="SCP03",
    title="GP registry — security domains",
    description="GET STATUS P1=80 — list security domains.",
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_registry_sd,
    requires_card=True,
    tags=("registry", "sd"),
)


GET_DATA_SPEC = ActionSpec(
    id="scp03.get_data",
    subsystem="SCP03",
    title="GET DATA (tag P1/P2)",
    description=(
        "Issue 80CA P1 P2 00 on the selected application and return the "
        "raw response plus a TLV decode when parseable."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="p1",
            label="P1",
            kind="hex",
            required=True,
            placeholder="2F",
            help="High tag byte (e.g. 9F for CPLC tag 9F7F).",
        ),
        ActionField(
            name="p2",
            label="P2",
            kind="hex",
            required=True,
            placeholder="00",
            help="Low tag byte (e.g. 7F for CPLC tag 9F7F).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_get_data,
    requires_card=True,
    tags=("get-data", "tlv"),
)


LIST_PROFILES_SPEC = ActionSpec(
    id="scp03.list_profiles",
    subsystem="SCP03",
    title="List profiles (SGP.22 ES10c)",
    description=(
        "Select ISD-R and retrieve the profile list via ES10c "
        "(STORE DATA BF2D00), returning a structured rows view."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_list_profiles,
    requires_card=True,
    tags=("profiles", "sgp22"),
)


PROFILE_SCAN_SPEC = ActionSpec(
    id="scp03.profile_scan",
    subsystem="SCP03",
    title="Profile scan (SGP.22 + SGP.32)",
    description=(
        "Run the bundled ES10c/ES10b retrieval set (GetEID, GetProfilesInfo, "
        "GetConfiguredData, EuiccInfo1, EuiccInfo2) and return a structured "
        "euicc report."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_profile_scan,
    requires_card=True,
    tags=("profiles", "scan", "sgp22"),
)


LIST_AIDS_SPEC = ActionSpec(
    id="scp03.list_aids",
    subsystem="SCP03",
    title="List AID aliases (aid.txt)",
    description="Read the workspace AID registry and return every alias.",
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_list_aids,
    requires_card=False,
    tags=("aid", "registry"),
)


get_registry().register(AUTH_SCP03_SPEC)
get_registry().register(AUTH_SCP02_SPEC)
get_registry().register(AUTH_STATUS_SPEC)
get_registry().register(LOGOUT_SPEC)
get_registry().register(KEYS_SPEC)
get_registry().register(REGISTRY_APPS_SPEC)
get_registry().register(REGISTRY_PKGS_SPEC)
get_registry().register(REGISTRY_SD_SPEC)
get_registry().register(GET_DATA_SPEC)
get_registry().register(LIST_PROFILES_SPEC)
get_registry().register(PROFILE_SCAN_SPEC)
get_registry().register(LIST_AIDS_SPEC)


# ======================================================================
# C-3 — mutation + validation + exports
# ======================================================================
#
# These dispatchers all live behind explicit ``confirm`` gates in the
# frontend — the backend still executes whatever the caller asks.
# Authentication is the card's responsibility: any mutation that
# requires secure messaging returns 69 82 / 69 85 unless the session is
# already authenticated via ``scp03.auth_scp03`` / ``scp03.auth_scp02``.


def _require_auth_session(transporter: Any) -> None:
    """Raise if there is no live, authenticated SCP session on the card."""
    session = getattr(transporter, "session", None)
    if session is None or bool(getattr(session, "is_authenticated", False)) is False:
        raise ValueError(
            "no authenticated secure session — run scp03.auth_scp03 / auth_scp02 first"
        )


def _dispatch_set_status(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_aid: Any = None,
    state_byte: Any = None,
) -> dict[str, Any]:
    """GP SET STATUS — change an application's lifecycle state."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    aid_text = str(target_aid or "").strip().upper().replace(" ", "")
    if len(aid_text) == 0:
        raise ValueError("target_aid is required.")
    try:
        bytes.fromhex(aid_text)
    except ValueError as error:
        raise ValueError(f"invalid target_aid hex: {error}") from error

    state_val = _parse_hex_byte(state_byte, label="state_byte")

    gp = _get_or_make_gp_ctrl(session)
    _result, trace = _run_gp_quietly(gp, "set_status", aid_text, state_val)

    return {
        "session_id": sid,
        "target_aid": aid_text,
        "state_byte": f"{state_val:02X}",
        "state_name": _SET_STATUS_STATE_NAMES.get(state_val, f"0x{state_val:02X}"),
        "trace": trace,
    }


_SET_STATUS_STATE_NAMES = {
    0x03: "INSTALLED",
    0x07: "SELECTABLE",
    0x0F: "PERSONALIZED",
    0x80: "LOCKED",
    0x83: "TERMINATED",
}


def _dispatch_lock(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_aid: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    if bool(confirm) is False:
        raise ValueError("confirm must be true — locking an application is irreversible on some cards.")
    return _dispatch_set_status(
        ctx,
        session_id=session_id,
        target_aid=target_aid,
        state_byte="80",
    )


def _dispatch_unlock(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_aid: Any = None,
) -> dict[str, Any]:
    return _dispatch_set_status(
        ctx,
        session_id=session_id,
        target_aid=target_aid,
        state_byte="07",
    )


def _dispatch_delete(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_aid: Any = None,
    recursive: bool = True,
) -> dict[str, Any]:
    """GP DELETE — remove an application / package (optionally recursive)."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    aid_text = str(target_aid or "").strip().upper().replace(" ", "")
    if len(aid_text) == 0:
        raise ValueError("target_aid is required.")
    try:
        bytes.fromhex(aid_text)
    except ValueError as error:
        raise ValueError(f"invalid target_aid hex: {error}") from error

    gp = _get_or_make_gp_ctrl(session)
    _result, trace = _run_gp_quietly(gp, "delete_object", aid_text, bool(recursive))

    return {
        "session_id": sid,
        "target_aid": aid_text,
        "recursive": bool(recursive),
        "trace": trace,
    }


def _dispatch_store_data(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    data: Any = None,
    p1: Any = None,
    p2: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """GP STORE DATA — hand-crafted or auto-chunked payload."""
    if bool(confirm) is False:
        raise ValueError("confirm must be true — STORE DATA writes arbitrary data to the card.")
    hex_text = str(data or "").strip().upper().replace(" ", "")
    if len(hex_text) == 0:
        raise ValueError("data is required (hex string).")
    if len(hex_text) % 2 != 0:
        raise ValueError("data has odd length (expecting hex pairs).")
    try:
        bytes.fromhex(hex_text)
    except ValueError as error:
        raise ValueError(f"invalid data hex: {error}") from error

    p1_str = str(p1 or "").strip()
    p2_str = str(p2 or "").strip()
    p1_val = _parse_hex_byte(p1_str, label="P1") if p1_str else None
    p2_val = _parse_hex_byte(p2_str, label="P2") if p2_str else None
    if (p1_val is None) != (p2_val is None):
        raise ValueError("provide both P1 and P2 or neither (for auto-chunking).")

    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    gp = _get_or_make_gp_ctrl(session)
    _result, trace = _run_gp_quietly(gp, "store_data", hex_text, p1_val, p2_val)

    return {
        "session_id": sid,
        "bytes": len(hex_text) // 2,
        "p1": f"{p1_val:02X}" if p1_val is not None else None,
        "p2": f"{p2_val:02X}" if p2_val is not None else None,
        "trace": trace,
    }


def _dispatch_update_binary(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    hex_data: Any = None,
    path: Any = None,
    offset: int = 0,
    confirm: Any = None,
) -> dict[str, Any]:
    """UPDATE BINARY (00D6 P1 P2) on the current or named EF.

    When ``path`` is supplied we SELECT it first (capturing the select
    trace). The underlying helper still targets offset 0x0000 unless the
    caller overrides ``offset`` (P1||P2).
    """
    if bool(confirm) is False:
        raise ValueError("confirm must be true — UPDATE BINARY overwrites file content on the card.")
    session, _transporter, sid = _get_scp03_session(session_id)
    fs_controller = session.handle["fs"]

    hex_text = str(hex_data or "").strip().upper().replace(" ", "")
    if len(hex_text) == 0:
        raise ValueError("hex_data is required.")
    if len(hex_text) % 2 != 0:
        raise ValueError("hex_data has odd length.")
    try:
        bytes.fromhex(hex_text)
    except ValueError as error:
        raise ValueError(f"invalid hex_data: {error}") from error

    select_trace = ""
    path_text = str(path or "").strip()
    if path_text:
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink):
            ok = fs_controller.select(path_text, silent=False)
        select_trace = _strip_ansi(sink.getvalue())
        if ok is False:
            return {
                "session_id": sid,
                "path": path_text,
                "selected": False,
                "select_trace": select_trace,
                "ok": False,
                "sw": "0000",
                "bytes": 0,
                "trace": "",
            }

    # Fall back to the current helper — fs_ctrl.update_binary talks to
    # whatever is currently selected. We capture its own trace for parity
    # with the other FS actions.
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        fs_controller.update_binary(hex_text)
    trace = _strip_ansi(sink.getvalue())
    sw = _extract_sw_from_trace(trace)
    ok = bool(sw and sw.startswith("9000"))

    return {
        "session_id": sid,
        "path": path_text,
        "selected": True if path_text else None,
        "select_trace": select_trace,
        "bytes": len(hex_text) // 2,
        "offset": int(offset or 0),
        "sw": sw,
        "ok": ok,
        "trace": trace,
    }


def _extract_sw_from_trace(trace: str) -> str:
    """Pull the final 4-char SW out of a captured FS trace (best-effort)."""
    import re

    matches = re.findall(r"\b([0-9A-F]{2})([0-9A-F]{2})\b", str(trace or "").upper())
    if len(matches) == 0:
        return ""
    last = matches[-1]
    return last[0] + last[1]


def _dispatch_update_record(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    record: Any = None,
    hex_data: Any = None,
    path: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """UPDATE RECORD (00DC REC 04 LC) on the current or named EF."""
    if bool(confirm) is False:
        raise ValueError("confirm must be true — UPDATE RECORD overwrites record content on the card.")
    session, _transporter, sid = _get_scp03_session(session_id)
    fs_controller = session.handle["fs"]

    rec_text = str(record or "").strip()
    if len(rec_text) == 0:
        raise ValueError("record is required (number, e.g. '1').")
    try:
        rec_int = int(rec_text, 10 if rec_text.isdigit() else 16)
    except ValueError as error:
        raise ValueError(f"invalid record: {rec_text!r}") from error
    if rec_int < 0 or rec_int > 0xFF:
        raise ValueError(f"record out of range 0..255: {rec_int}")

    hex_text = str(hex_data or "").strip().upper().replace(" ", "")
    if len(hex_text) == 0:
        raise ValueError("hex_data is required.")
    if len(hex_text) % 2 != 0:
        raise ValueError("hex_data has odd length.")
    try:
        bytes.fromhex(hex_text)
    except ValueError as error:
        raise ValueError(f"invalid hex_data: {error}") from error

    select_trace = ""
    path_text = str(path or "").strip()
    if path_text:
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink):
            ok = fs_controller.select(path_text, silent=False)
        select_trace = _strip_ansi(sink.getvalue())
        if ok is False:
            return {
                "session_id": sid,
                "path": path_text,
                "record": rec_int,
                "selected": False,
                "select_trace": select_trace,
                "ok": False,
                "sw": "0000",
                "bytes": 0,
                "trace": "",
            }

    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        fs_controller.update_record(rec_int, hex_text)
    trace = _strip_ansi(sink.getvalue())
    sw = _extract_sw_from_trace(trace)
    ok = bool(sw and sw.startswith("9000"))

    return {
        "session_id": sid,
        "path": path_text,
        "selected": True if path_text else None,
        "select_trace": select_trace,
        "record": rec_int,
        "bytes": len(hex_text) // 2,
        "sw": sw,
        "ok": ok,
        "trace": trace,
    }


def _dispatch_validate(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    scope: str = "ALL",
) -> dict[str, Any]:
    """Run ProfileValidator over the active session for a given scope."""
    session, _transporter, sid = _get_scp03_session(session_id)
    fs_controller = session.handle["fs"]

    scope_val = str(scope or "ALL").strip().upper()
    if scope_val not in ("ALL", "MF", "USIM", "ISIM"):
        raise ValueError(
            f"scope must be ALL | MF | USIM | ISIM (got {scope!r})"
        )

    from SCP03.logic.profile_validator import ProfileValidator

    validator = ProfileValidator(fs_controller, profile_metadata=None)
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        try:
            validator.run(scope=scope_val)
        except Exception as error:  # noqa: BLE001 — validator is best-effort
            return {
                "session_id": sid,
                "scope": scope_val,
                "ok": False,
                "error": str(error),
                "trace": _strip_ansi(sink.getvalue()),
            }
    trace = _strip_ansi(sink.getvalue())

    # Summarise counts by scanning the captured output for common markers.
    lines = trace.splitlines()
    passed = sum(1 for line in lines if "[+] PASS" in line or "[PASS]" in line)
    failed = sum(1 for line in lines if "[FAIL]" in line or "[-] FAIL" in line)
    warnings = sum(1 for line in lines if "[!]" in line or "[WARN" in line)

    return {
        "session_id": sid,
        "scope": scope_val,
        "ok": failed == 0,
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
        "trace": trace,
    }


def _dispatch_cert_info(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Walk ECASD certificate tags (5A / 45 / 42 / E0 / 7F21) and return summaries.

    Selects ECASD (``A0000005591010FFFFFFFF8900000200``) via raw
    SELECT-by-AID and then GET DATAs each tag. That leaves the card
    sitting on ECASD, which confuses the next FS-tree click because
    ``fs_controller.current_fid`` still claims MF. The finally-block
    restore re-anchors MF so the operator can flip back to the **Files**
    ribbon tab and read any EF without a stale-state surprise.
    """
    session, transporter, sid = _get_scp03_session(session_id)
    from SCP03.core.decoders import AdvancedDecoders
    from SCP03.core.utils import TlvParser

    ECASD_AID = "A0000005591010FFFFFFFF8900000200"
    transporter.transmit(f"00A40400{len(ECASD_AID) // 2:02X}{ECASD_AID}", silent=True)

    cert_tags: list[tuple[str, str]] = [
        ("5A", "EID"),
        ("45", "CIN"),
        ("42", "IIN"),
        ("E0", "Key Info"),
        ("7F21", "Certificate"),
    ]

    try:
        rows: list[dict[str, Any]] = []
        for tag_hex, label in cert_tags:
            cmd = f"80CA{tag_hex}00"
            data, sw1, sw2 = transporter.transmit(cmd, silent=True)
            if sw1 not in (0x90, 0x61):
                rows.append({
                    "label": label,
                    "tag": tag_hex,
                    "sw": f"{sw1:02X}{sw2:02X}",
                    "present": False,
                    "hex": "",
                    "decoded": None,
                })
                continue
            raw_bytes = bytes(data or b"")
            inner = raw_bytes
            try:
                parsed = TlvParser.parse(raw_bytes)
                tag_int = int(tag_hex, 16)
                extracted = TlvParser.get_first(parsed, tag_int)
                if isinstance(extracted, (bytes, bytearray)):
                    inner = bytes(extracted)
            except Exception:  # noqa: BLE001
                pass

            decoded: Any = None
            if len(inner) >= 4 and inner[0] == 0x30:
                try:
                    info = AdvancedDecoders.decode_cert_der(inner)
                    if info:
                        decoded = dict(info)
                except Exception:  # noqa: BLE001
                    decoded = None

            rows.append({
                "label": label,
                "tag": tag_hex,
                "sw": f"{sw1:02X}{sw2:02X}",
                "present": True,
                "hex": inner.hex().upper(),
                "decoded": decoded,
            })

        return {
            "session_id": sid,
            "target_aid": ECASD_AID,
            "entries": rows,
        }
    finally:
        _restore_fs_root_best_effort(session)


def _dispatch_export_euicc(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    output_path: Any = None,
    standard: str = "SGP.32",
) -> dict[str, Any]:
    """Export the euicc report as YAML (mirrors shell EXPORT-EUICC)."""
    import datetime as _datetime

    session, _transporter, sid = _get_scp03_session(session_id)

    out = str(output_path or "").strip()
    if len(out) == 0:
        out = "euicc_report.yaml"
    if not (out.endswith(".yaml") or out.endswith(".yml")):
        out = out + ".yaml"

    std = str(standard or "SGP.32").strip().upper()
    if len(std) == 0:
        std = "SGP.32"
    if std not in ("SGP.22", "SGP.32"):
        raise ValueError(f"standard must be SGP.22 or SGP.32 (got {standard!r})")

    gp = _get_or_make_gp_ctrl(session)
    sgp22 = gp.sgp22

    try:
        report = sgp22.get_euicc_report_extended(standard=std) if hasattr(
            sgp22, "get_euicc_report_extended"
        ) else sgp22.get_euicc_report()

        cplc_hex = ""
        try:
            cplc_data, cplc_sw1, _cplc_sw2 = gp.get_cplc_data()
            if cplc_data and cplc_sw1 == 0x90:
                cplc_hex = bytes(cplc_data).hex().upper()
                report["cplc_hex"] = cplc_hex
        except Exception:  # noqa: BLE001
            pass

        report["generated"] = _datetime.datetime.now().isoformat()

        try:
            import yaml as _yaml

            with open(out, "w", encoding="utf-8") as handle:
                _yaml.dump(
                    report,
                    handle,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False,
                )
        except Exception as error:  # noqa: BLE001
            return {
                "session_id": sid,
                "output_path": out,
                "ok": False,
                "error": f"write failed: {error}",
            }

        return {
            "session_id": sid,
            "output_path": out,
            "standard": std,
            "ok": True,
            "cplc_hex": cplc_hex,
            "profiles": report.get("profiles", []),
            "eid": report.get("eid", ""),
        }
    finally:
        _restore_fs_root_best_effort(session)


def _dispatch_export_keybag(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    output_path: Any = None,
    label: str = "scp03-live",
) -> dict[str, Any]:
    """Export the active SCP03 session keys as a HIL keybag JSON."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    out = str(output_path or "").strip()
    if len(out) == 0:
        out = "scp03_session.keys.json"

    label_text = str(label or "").strip()
    if len(label_text) == 0:
        label_text = "scp03-live"

    gp = _get_or_make_gp_ctrl(session)
    aid_hex = ""
    try:
        target_aid = bytes(getattr(gp, "target_aid", b"") or b"")
        if len(target_aid) > 0:
            aid_hex = target_aid.hex().upper()
    except Exception:  # noqa: BLE001
        aid_hex = ""

    try:
        from Tools.HilBridge.scp_keybag_export import (
            entry_from_scp03_session,
            write_keybag_file,
        )
    except ImportError as error:
        return {
            "session_id": sid,
            "ok": False,
            "error": f"keybag exporter unavailable: {error}",
        }

    try:
        entry = entry_from_scp03_session(
            transporter.session,
            label=label_text,
            match_aid_hex=aid_hex,
        )
    except RuntimeError as error:
        return {
            "session_id": sid,
            "ok": False,
            "error": str(error),
        }
    except Exception as error:  # noqa: BLE001
        return {
            "session_id": sid,
            "ok": False,
            "error": f"keybag snapshot failed: {error}",
        }

    try:
        written = write_keybag_file(out, [entry], merge_existing=True)
    except Exception as error:  # noqa: BLE001
        return {
            "session_id": sid,
            "ok": False,
            "error": f"keybag write failed: {error}",
        }

    return {
        "session_id": sid,
        "output_path": str(written),
        "label": label_text,
        "target_aid": aid_hex,
        "ok": True,
    }


# --- C-3 action specs --------------------------------------------------


_REQUIRED_TARGET_AID_FIELD = ActionField(
    name="target_aid",
    label="Target AID",
    kind="hex",
    required=True,
    placeholder="A00000015141434C00",
    help="Hex AID of the application / package to act on.",
)


SET_STATUS_SPEC = ActionSpec(
    id="scp03.set_status",
    subsystem="SCP03",
    title="Set status",
    description=(
        "GP SET STATUS — change the lifecycle byte of an application. "
        "State bytes: 03=INSTALLED, 07=SELECTABLE, 0F=PERSONALIZED, "
        "80=LOCKED, 83=TERMINATED. Requires an authenticated session."
    ),
    inputs=(
        _SESSION_FIELD,
        _REQUIRED_TARGET_AID_FIELD,
        ActionField(
            name="state_byte",
            label="State",
            kind="hex",
            required=True,
            placeholder="07",
            help="Lifecycle byte, e.g. 80 for LOCKED.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_status,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "lcs"),
)


LOCK_SPEC = ActionSpec(
    id="scp03.lock",
    subsystem="SCP03",
    title="Lock (LCS=80)",
    description="Shortcut for SET STATUS → LOCKED on the given AID. Irreversible on some cards — requires confirm.",
    inputs=(
        _SESSION_FIELD,
        _REQUIRED_TARGET_AID_FIELD,
        ActionField(
            name="confirm",
            label="I understand this locks the application",
            kind="bool",
            required=True,
            default=False,
            help="Must be true to proceed.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_lock,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "lcs", "destructive"),
)


UNLOCK_SPEC = ActionSpec(
    id="scp03.unlock",
    subsystem="SCP03",
    title="Unlock (LCS=07)",
    description="Shortcut for SET STATUS → SELECTABLE on the given AID.",
    inputs=(_SESSION_FIELD, _REQUIRED_TARGET_AID_FIELD),
    output_kind="json",
    dispatcher=_dispatch_unlock,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "lcs"),
)


DELETE_SPEC = ActionSpec(
    id="scp03.delete",
    subsystem="SCP03",
    title="Delete application / package",
    description=(
        "GP DELETE — destroys the referenced instance (and child "
        "objects when recursive). Irreversible on real cards."
    ),
    inputs=(
        _SESSION_FIELD,
        _REQUIRED_TARGET_AID_FIELD,
        ActionField(
            name="recursive",
            label="Recursive",
            kind="bool",
            default=True,
            help="If true, also delete objects associated with the AID (P2=80).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_delete,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "delete", "destructive"),
)


STORE_DATA_SPEC = ActionSpec(
    id="scp03.store_data",
    subsystem="SCP03",
    title="STORE DATA",
    description=(
        "GP STORE DATA (80E2). Leave P1/P2 blank to auto-chunk a large "
        "payload with GP block-index sequencing. Requires confirm — writes "
        "arbitrary data to the card."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="data",
            label="Data",
            kind="hex",
            required=True,
            help="Hex payload to store.",
        ),
        ActionField(
            name="p1",
            label="P1",
            kind="hex",
            required=False,
            placeholder="(auto)",
        ),
        ActionField(
            name="p2",
            label="P2",
            kind="hex",
            required=False,
            placeholder="(auto)",
            help="Provide BOTH P1 and P2 to send a single raw block.",
        ),
        ActionField(
            name="confirm",
            label="I understand this writes data to the card",
            kind="bool",
            required=True,
            default=False,
            help="Must be true to proceed.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_store_data,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "store-data"),
)


UPDATE_BINARY_SPEC = ActionSpec(
    id="scp03.update_binary",
    subsystem="SCP03",
    title="UPDATE BINARY",
    description=(
        "UPDATE BINARY (00D6) on the current or named transparent EF. "
        "Optionally SELECTs the target path first. Requires confirm — "
        "overwrites file content on the card."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="hex_data",
            label="Data",
            kind="hex",
            required=True,
            help="Hex payload to write.",
        ),
        ActionField(
            name="path",
            label="Path",
            kind="string",
            required=False,
            placeholder="MF/EF_ICCID",
            help="Optional path to SELECT first. Blank = use current selection.",
        ),
        ActionField(
            name="confirm",
            label="I understand this overwrites file content",
            kind="bool",
            required=True,
            default=False,
            help="Must be true to proceed.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_update_binary,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "update"),
)


UPDATE_RECORD_SPEC = ActionSpec(
    id="scp03.update_record",
    subsystem="SCP03",
    title="UPDATE RECORD",
    description=(
        "UPDATE RECORD (00DC REC 04 Lc Data) on the current or named "
        "linear-fixed / cyclic EF. Requires confirm — overwrites record content on the card."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="record",
            label="Record",
            kind="int",
            required=True,
            min_value=1,
            max_value=254,
            placeholder="1",
        ),
        ActionField(
            name="hex_data",
            label="Data",
            kind="hex",
            required=True,
            help="Hex payload for the record.",
        ),
        ActionField(
            name="path",
            label="Path",
            kind="string",
            required=False,
            placeholder="MF/ADF_USIM/EF_MSISDN",
            help="Optional path to SELECT first. Blank = use current selection.",
        ),
        ActionField(
            name="confirm",
            label="I understand this overwrites record content",
            kind="bool",
            required=True,
            default=False,
            help="Must be true to proceed.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_update_record,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "update"),
)


# ---------------------------------------------------------------------------
# Service-table staging — preview-only "what-if" encoder for bitmap EFs.
#
# Operators wanted a staging area where they can mock-toggle service flags on
# UST / IST / generic service-table EFs and *see* the resulting hex string
# before committing it to the card. This is pure local math — no card I/O,
# no auth gate — so the action is registered without ``requires_card`` /
# ``requires_auth`` and routes straight to the encoder helper.
# ---------------------------------------------------------------------------


def _dispatch_stage_service_table(
    ctx: ActionContext,
    *,
    active: Any = None,
    current_hex: Any = None,
    total_bytes: Any = None,
    table: Any = None,
) -> dict[str, Any]:
    """Compose a service-table EF body from a list of active service numbers.

    Pure offline encoder — used by the GUI staging panel to preview the
    bytes that would be written by an UPDATE BINARY before the operator
    actually pushes them to the card. Returns the new hex *and* the
    decoded checklist preview so the panel can render the round-trip
    in one shot.
    """
    from SCP03.core.decoders import AdvancedDecoders, ContentDecoder

    if active is None:
        raise ValueError("active is required (list of service numbers).")
    if isinstance(active, str):
        text = active.strip()
        if len(text) == 0:
            bits: list[int] = []
        else:
            try:
                import json as _json
                bits = [int(x) for x in _json.loads(text)]
            except Exception as error:
                raise ValueError(f"invalid active payload: {error}") from error
    elif isinstance(active, (list, tuple, set)):
        bits = []
        for entry in active:
            try:
                bits.append(int(entry))
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"invalid service number {entry!r}: {error}"
                ) from error
    else:
        raise ValueError(
            f"active must be a list of integers (got {type(active).__name__})."
        )

    cur_text = ""
    if current_hex is not None:
        cur_text = str(current_hex).replace(" ", "").replace(":", "").strip().upper()
        if len(cur_text) > 0:
            if len(cur_text) % 2 != 0:
                raise ValueError("current_hex has odd length")
            try:
                bytes.fromhex(cur_text)
            except ValueError as error:
                raise ValueError(f"current_hex is not valid hex: {error}") from error

    total: int | None = None
    if total_bytes is not None and str(total_bytes).strip() != "":
        try:
            total = int(str(total_bytes), 0)
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"total_bytes must be an integer: {error}"
            ) from error
        if total < 0 or total > 4096:
            raise ValueError(f"total_bytes out of sane range 0..4096: {total}")

    new_hex = AdvancedDecoders.encode_service_table(
        bits,
        total_bytes=total,
        current_hex=cur_text or None,
    )

    # Decode the newly-encoded bytes so the GUI can repaint the
    # checklist immediately. Reusing the existing per-table decoders
    # keeps the column labels (UST / IST / generic) identical to what
    # the operator already sees in the live FCP view.
    table_kind = str(table or "generic").strip().lower()
    decoded: dict[str, Any] | None
    if table_kind == "ust":
        decoded = AdvancedDecoders.decode_ust(new_hex)
    elif table_kind == "ist":
        decoded = ContentDecoder.decode_isim_ist(new_hex)
    else:
        decoded = ContentDecoder.decode_service_table_bits(new_hex)

    # Byte-level diff helper — the GUI surfaces it as a chip strip so
    # the operator can quickly spot which byte indices changed.
    diff_bytes: list[dict[str, Any]] = []
    if cur_text:
        for i in range(0, max(len(cur_text), len(new_hex)), 2):
            old_byte = cur_text[i:i + 2] or "00"
            new_byte = new_hex[i:i + 2] or "00"
            if old_byte != new_byte:
                diff_bytes.append({
                    "index": i // 2,
                    "before": old_byte,
                    "after": new_byte,
                })

    return {
        "table": table_kind,
        "current_hex": cur_text,
        "new_hex": new_hex,
        "byte_count": len(new_hex) // 2,
        "active": sorted(set(bits)),
        "diff_bytes": diff_bytes,
        "decoded": decoded,
    }


STAGE_SERVICE_TABLE_SPEC = ActionSpec(
    id="scp03.stage_service_table",
    subsystem="SCP03",
    title="Stage service-table edit",
    description=(
        "Preview-only encoder for bitmap service-table EFs (EF.UST, "
        "EF.IST, generic). Computes the EF body that would result "
        "from a list of active service numbers — does not touch the "
        "card. Use it to compose UPDATE BINARY payloads without "
        "doing the bit-math by hand."
    ),
    inputs=(
        # ``active`` is shipped as a JSON list from the staging popout;
        # the dispatcher coerces both list-objects and JSON-text inputs
        # so the action also works from a generic form / CLI.
        ActionField(
            name="active",
            label="Active service numbers (JSON list)",
            kind="json",
            required=True,
            help="JSON array of 1-indexed service numbers, e.g. [2, 10, 33].",
        ),
        ActionField(
            name="current_hex",
            label="Current EF hex (optional)",
            kind="hex",
            required=False,
            help=(
                "Existing body to use for sizing / diffing. Blank = "
                "auto-size from the highest active bit."
            ),
        ),
        ActionField(
            name="total_bytes",
            label="Total bytes (optional)",
            kind="int",
            required=False,
            min_value=0,
            max_value=4096,
            help="Override the EF body length. Wins over current_hex.",
        ),
        ActionField(
            name="table",
            label="Table kind",
            kind="enum",
            required=False,
            default="generic",
            choices=("ust", "ist", "generic"),
            help="Which name map to apply when re-decoding the result.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_stage_service_table,
    # Pure local math — no card session needed and no auth gate to
    # cross. Tagged ``staging`` so the GUI can group it under the
    # mock-edit affordances rather than the live mutation list.
    requires_card=False,
    requires_auth=False,
    tags=("staging", "encode", "service-table"),
)


VALIDATE_SPEC = ActionSpec(
    id="scp03.validate",
    subsystem="SCP03",
    title="Validate profile",
    description=(
        "Run ProfileValidator over the live card — asserts mandatory "
        "EFs, TLV structure, and ADF consistency for the chosen scope."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="scope",
            label="Scope",
            kind="enum",
            required=True,
            default="ALL",
            choices=("ALL", "MF", "USIM", "ISIM"),
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_validate,
    requires_card=True,
    tags=("validate", "profile"),
)


CERT_INFO_SPEC = ActionSpec(
    id="scp03.cert_info",
    subsystem="SCP03",
    title="ECASD cert info",
    description=(
        "Select ECASD and GET DATA for EID / CIN / IIN / key-info / "
        "certificate, decoding X.509 DER structures where present."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_cert_info,
    requires_card=True,
    tags=("validate", "certificate", "ecasd"),
)


EXPORT_EUICC_SPEC = ActionSpec(
    id="scp03.export_euicc",
    subsystem="SCP03",
    title="Export eUICC report (YAML)",
    description=(
        "Generate a YAML report covering profiles, euicc-info, "
        "configured-data, and CPLC."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="output_path",
            label="Output file",
            kind="save_path",
            required=False,
            placeholder="euicc_report.yaml",
            help="Blank = euicc_report.yaml in CWD. Double-click to browse.",
        ),
        ActionField(
            name="standard",
            label="Standard",
            kind="enum",
            required=True,
            default="SGP.32",
            choices=("SGP.22", "SGP.32"),
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_export_euicc,
    requires_card=True,
    tags=("export", "euicc", "yaml"),
)


EXPORT_KEYBAG_SPEC = ActionSpec(
    id="scp03.export_keybag",
    subsystem="SCP03",
    title="Export SCP03 keybag (HIL)",
    description=(
        "Dump the active SCP03 session keys into a HIL keybag JSON. "
        "Pair with a sibling .pcap for offline SM decryption in the HIL "
        "decode TUI."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="output_path",
            label="Output file",
            kind="save_path",
            required=False,
            placeholder="scp03_session.keys.json",
            help="Blank = scp03_session.keys.json in CWD. Double-click to browse.",
        ),
        ActionField(
            name="label",
            label="Label",
            kind="string",
            required=False,
            default="scp03-live",
            placeholder="scp03-live",
            help="Label stored alongside the keys (for multi-session bags).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_export_keybag,
    requires_card=True,
    # Keybag export reads the derived SCP03 session keys off the live
    # ``Scp03Session`` — pointless to call unless the session exists.
    requires_auth=True,
    tags=("export", "keybag", "hil"),
)


get_registry().register(SET_STATUS_SPEC)
get_registry().register(LOCK_SPEC)
get_registry().register(UNLOCK_SPEC)
get_registry().register(DELETE_SPEC)
get_registry().register(STORE_DATA_SPEC)
get_registry().register(UPDATE_BINARY_SPEC)
get_registry().register(UPDATE_RECORD_SPEC)
get_registry().register(STAGE_SERVICE_TABLE_SPEC)
get_registry().register(VALIDATE_SPEC)
get_registry().register(CERT_INFO_SPEC)
get_registry().register(EXPORT_EUICC_SPEC)
get_registry().register(EXPORT_KEYBAG_SPEC)


# ======================================================================
# C-4 — eUICC telemetry + lifecycle, crypto helpers, gold-profile diff
# ======================================================================
#
# These dispatchers cover the read-only ES10 retrievals that the shell
# exposes via GET-EID / GET-CERTS / GET-CONFIG / GET-SGP32-ALL, plus the
# profile lifecycle trio (enable/disable/delete) that currently lives
# behind the MANAGE-PROFILE shell wizard. The crypto pair
# (``derive_opc`` / ``run_auth_test_vector``) is pure offline Milenage —
# no card session required.
#
# The gold-profile set mirrors SET-GOLD-PROFILE / GOLD-PROFILE /
# CLEAR-GOLD-PROFILE / PROFILE-DIFF. The shell persists these into the
# same SQLite-backed inventory state; we reuse that so shell + GUI read
# the same baseline.


def _run_sgp22_quietly(sgp22: Any, fn_name: str, *args: Any, **kwargs: Any) -> tuple[Any, str]:
    """Run an ``sgp22`` helper with stdout captured; returns (result, text)."""
    fn = getattr(sgp22, fn_name)
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        result = fn(*args, **kwargs)
    return result, _strip_ansi(sink.getvalue())


def _resolve_profile_identifier(raw: Any) -> str:
    """Accept AID-hex or ICCID digits — mirrors shell `_resolve_mixed_aid` intent."""
    text = str(raw or "").strip().upper().replace(" ", "").replace(":", "")
    if len(text) == 0:
        raise ValueError("identifier is required (AID hex or ICCID).")
    # ICCID: digits only (with optional F padding). AID: hex.
    iccid_ok = all(ch in "0123456789F" for ch in text)
    aid_ok = all(ch in "0123456789ABCDEF" for ch in text)
    if not (iccid_ok or aid_ok):
        raise ValueError(f"identifier {raw!r} is neither ICCID digits nor AID hex.")
    return text


# ---------------------------------------------------------------- eUICC
def _dispatch_get_eid(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    """ES10c.GetEID — compact EID read.

    Returns the raw SW + extracted EID + a structured ``lines`` array
    (the same compact-print output the CLI emits, ANSI-stripped and
    blank-collapsed) so the GUI can render KV rows instead of dumping
    the terminal trace behind a disclosure triangle.
    """
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)
    sgp22 = gp.sgp22

    try:
        _result, trace = _run_sgp22_quietly(sgp22, "get_eid")
        # Re-derive the EID from the same response so the caller gets a
        # structured field instead of only the captured stdout.
        data, sw1, sw2 = sgp22._retrieve_eid_response()
        eid_hex = ""
        if sw1 == 0x90 and data:
            try:
                eid_hex = sgp22._extract_eid_hex(bytes(data))
            except Exception:  # noqa: BLE001
                eid_hex = bytes(data).hex().upper()
        return {
            "session_id": sid,
            "sw": f"{sw1:02X}{sw2:02X}",
            "eid": eid_hex,
            "lines": _sgp32_bulk_trace_lines(trace),
            "trace": trace,
        }
    finally:
        _restore_fs_root_best_effort(session)


def _build_get_certs_gui_decoded(data_bytes: bytes, sgp22: Any) -> dict[str, Any]:
    """Turn BF5600 bytes into a JSON-safe dict for ``renderDecodedBlock``.

    Mirrors the structured fields surfaced by ``_print_get_certs_compact_response``
    (``decode_get_certs_response`` + ``_summarize_cert_block``) instead of exposing
    only the monospace compact-printer transcript.
    """
    from SCP03.logic.sgp32_decode import decode_get_certs_response

    if len(data_bytes) == 0:
        return {}

    certs = decode_get_certs_response(data_bytes)
    err = certs.get("error")
    if err is not None:
        return {"error": str(err)}

    eum_cert = certs.get("eumCertificate")
    euicc_cert = certs.get("euiccCertificate")
    if not isinstance(eum_cert, bytes) and not isinstance(euicc_cert, bytes):
        fallback = sgp22._summarize_cert_block(data_bytes)
        if len(fallback) > 0:
            return {"certificateData": fallback}
        return {}

    out: dict[str, Any] = {}
    if isinstance(eum_cert, bytes):
        out["eumCertificate"] = sgp22._summarize_cert_block(eum_cert)
    if isinstance(euicc_cert, bytes):
        out["euiccCertificate"] = sgp22._summarize_cert_block(euicc_cert)
    return out


def _dispatch_get_euicc_certs(ctx: ActionContext, *, session_id: Any = None) -> dict[str, Any]:
    """ES10b.GetCerts — ECASD cert chain."""
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)
    sgp22 = gp.sgp22

    try:
        _result, trace = _run_sgp22_quietly(sgp22, "get_euicc_certs")

        # Capture the raw bytes too, for the hex viewer on the frontend.
        sgp22._select_isd_r()
        data, sw1, sw2 = sgp22._send_store_data_with_retry_ladder("BF5600")
        data_bytes = bytes(data or b"")
        parse_error: str | None = None
        decoded: dict[str, Any] = {}
        try:
            decoded = _build_get_certs_gui_decoded(data_bytes, sgp22)
        except Exception as error:  # noqa: BLE001
            parse_error = str(error)
        return {
            "session_id": sid,
            "sw": f"{sw1:02X}{sw2:02X}",
            "raw_hex": data_bytes.hex().upper(),
            "lines": _sgp32_bulk_trace_lines(trace),
            "trace": trace,
            "decoded": decoded,
            "parse_error": parse_error,
        }
    finally:
        _restore_fs_root_best_effort(session)


def _dispatch_get_euicc_configured_data(
    ctx: ActionContext, *, session_id: Any = None
) -> dict[str, Any]:
    """ES10a.GetEuiccConfiguredData (BF3C00)."""
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)
    sgp22 = gp.sgp22

    try:
        _result, trace = _run_sgp22_quietly(sgp22, "get_euicc_configured_data")

        sgp22._select_isd_r()
        data, sw1, sw2 = sgp22._send_store_data_with_retry_ladder("BF3C00")
        data_bytes = bytes(data or b"")
        decoded: dict[str, Any] = {}
        try:
            from SCP03.core.utils import TlvParser

            parsed = TlvParser.parse(data_bytes) if len(data_bytes) > 0 else {}
            configured = TlvParser.get_first(parsed, 0xBF3C)
            if isinstance(configured, dict):
                smdp = TlvParser.get_first(configured, 0x80)
                smds = TlvParser.get_first(configured, 0x81)
                if isinstance(smdp, (bytes, bytearray)):
                    decoded["default_smdp"] = bytes(smdp).decode("utf-8", "ignore").strip()
                if isinstance(smds, (bytes, bytearray)):
                    decoded["root_smds_primary"] = bytes(smds).decode("utf-8", "ignore").strip()
                pkids = TlvParser.get_first(configured, 0x84)
                if isinstance(pkids, bytes):
                    decoded["allowed_ci_pkid"] = [pkids.hex().upper()]
                elif isinstance(pkids, list):
                    decoded["allowed_ci_pkid"] = [
                        (bytes(p).hex().upper() if isinstance(p, (bytes, bytearray)) else str(p))
                        for p in pkids
                    ]
                additional = []
                for tag in (0x82, 0x83, 0x85, 0x86, 0x87, 0x88, 0x89):
                    val = TlvParser.get_first(configured, tag)
                    if isinstance(val, (bytes, bytearray)):
                        additional.append(bytes(val).decode("utf-8", "ignore").strip())
                if additional:
                    decoded["root_smds_additional"] = additional
        except Exception:
            pass
        return {
            "session_id": sid,
            "sw": f"{sw1:02X}{sw2:02X}",
            "raw_hex": data_bytes.hex().upper(),
            "decoded": decoded,
            "lines": _sgp32_bulk_trace_lines(trace),
            "trace": trace,
        }
    finally:
        _restore_fs_root_best_effort(session)


def _sgp32_bulk_trace_lines(trace_text: str) -> list[str]:
    """Normalise a captured stdout blob into a clean, ASCII-only line list.

    The sgp22 helpers print with ANSI colour codes and the occasional
    leading whitespace. The GUI renders these via ``scp03RenderTextLines``
    which expects a list of stripped strings. Returning an empty list
    (not ``None``) keeps the frontend branch logic simple.
    """
    text = _strip_ansi(trace_text or "")
    if len(text) == 0:
        return []
    out: list[str] = []
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if len(stripped) == 0:
            # Preserve a single blank line between paragraphs; suppress
            # runs so the structured renderer doesn't insert stray
            # heading breaks.
            if len(out) > 0 and out[-1] != "":
                out.append("")
            continue
        out.append(stripped)
    # Trim a trailing blank so the final output doesn't dangle.
    while len(out) > 0 and out[-1] == "":
        out.pop()
    return out


def _sgp32_run_section(
    sgp22: Any,
    *,
    key: str,
    title: str,
    es10_tag: str | None,
    printer_name: str | None,
    parser_mode: str,
) -> dict[str, Any]:
    """Run one SGP.32 retrieval + compact-print pair with isolated capture.

    ``parser_mode`` controls how the raw bytes are handed to the
    printer, since the three printer variants in ``sgp22`` take
    slightly different inputs:

    * ``"response"`` — printer wants the raw response ``bytes`` and
      parses internally (``_print_rat_compact_response``,
      ``_print_eim_configuration_compact``,
      ``_print_get_certs_compact_response``).
    * ``"parsed"`` — printer wants a pre-parsed TLV dict
      (``_print_notifications_list_compact``).

    Returns a section dict shaped for the GUI: status + hex + parsed
    text lines + raw per-section trace. Failures are swallowed and
    bubbled up via ``status="error"`` / ``note`` — the bulk sweep must
    keep running even if one section fails so the operator still sees
    the rest.
    """
    section: dict[str, Any] = {
        "key": key,
        "title": title,
        "es10_tag": es10_tag or "",
        "status": "empty",
        "hex": "",
        "lines": [],
        "trace": "",
        "note": "",
    }

    printer_sink = io.StringIO()
    try:
        if es10_tag is None:
            raise ValueError("_sgp32_run_section requires es10_tag")

        # 1. Pull raw TLV bytes. _es10_retrieve_data already selects
        #    ISD-R under the hood; we don't need to do it again.
        raw = bytes(sgp22._es10_retrieve_data(es10_tag) or b"")
        section["hex"] = raw.hex().upper()

        if len(raw) == 0:
            section["status"] = "empty"
            section["note"] = "No data returned (SW != 0x9000 or empty body)."
            return section

        # 2. Run the compact-printer for this section with stdout
        #    redirected — captures a human-readable view we can show
        #    as parsed KV / section rows in the GUI.
        if printer_name is not None:
            printer = getattr(sgp22, printer_name, None)
            if printer is not None:
                try:
                    with contextlib.redirect_stdout(printer_sink):
                        if parser_mode == "response":
                            printer(raw)
                        elif parser_mode == "parsed":
                            from SCP03.core.utils import TlvParser

                            try:
                                parsed = TlvParser.parse(raw)
                            except Exception:
                                parsed = {}
                            printer(parsed if isinstance(parsed, dict) else {})
                        else:
                            raise ValueError(
                                f"unknown parser_mode: {parser_mode!r}"
                            )
                except Exception as printer_error:  # noqa: BLE001
                    section["note"] = (
                        f"printer {printer_name!r} raised "
                        f"{type(printer_error).__name__}: {printer_error}"
                    )
        section["status"] = "ok"
    except Exception as retrieve_error:  # noqa: BLE001
        section["status"] = "error"
        section["note"] = (
            f"retrieve failed: {type(retrieve_error).__name__}: {retrieve_error}"
        )
    finally:
        section["trace"] = _strip_ansi(printer_sink.getvalue())
        section["lines"] = _sgp32_bulk_trace_lines(section["trace"])
    return section


def _dispatch_get_sgp32_all_data(
    ctx: ActionContext, *, session_id: Any = None
) -> dict[str, Any]:
    """SGP.32 bulk telemetry one-shot — scan + RAT + notifications + eIM cfg + certs.

    Returns a **structured** payload (``sections`` array) so the GUI can
    render each retrieval as its own labelled block instead of dumping
    the entire captured stdout into a terminal-style ``<pre>``. The
    legacy ``trace`` field is still populated for audit / debugging /
    scripts that grep the blob, but the frontend should prefer
    ``sections[*]`` whenever it's present.
    """
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)
    sgp22 = gp.sgp22

    overall_sink = io.StringIO()

    try:
        return _build_sgp32_bulk_report(sgp22, sid, overall_sink)
    finally:
        _restore_fs_root_best_effort(session)


def _build_sgp32_bulk_report(
    sgp22: Any, sid: str, overall_sink: Any
) -> dict[str, Any]:
    """Factored body of ``_dispatch_get_sgp32_all_data``.

    Split out so the outer dispatcher stays a thin try/finally shell
    that guarantees the card is re-pointed at MF on exit. Keeps the
    original section-building logic byte-compatible with the GUI.
    """
    # Step 1: the scan portion (run_sgp22_scan) is emitted inline by
    # sgp22 and has no single "compact printer" equivalent — capture its
    # stdout as a dedicated section so the GUI can show it as structured
    # lines instead of a raw dump. We still keep the raw text in
    # ``overall_sink`` so the fallback ``trace`` field remains complete.
    scan_sink = io.StringIO()
    scan_status = "ok"
    scan_note = ""
    try:
        with contextlib.redirect_stdout(scan_sink):
            sgp22.run_sgp22_scan()
            sgp22._select_isd_r()
    except Exception as scan_error:  # noqa: BLE001
        scan_status = "error"
        scan_note = (
            f"scan failed: {type(scan_error).__name__}: {scan_error}"
        )
    scan_text = _strip_ansi(scan_sink.getvalue())
    overall_sink.write(scan_text)

    sections: list[dict[str, Any]] = [
        {
            "key": "scan",
            "title": "eUICC Scan (SGP.22 / SGP.32 bundle)",
            "es10_tag": "",
            "status": scan_status,
            "hex": "",
            "lines": _sgp32_bulk_trace_lines(scan_text),
            "trace": scan_text,
            "note": scan_note,
        },
    ]

    # Step 2: the four ES10 retrieval helpers, each with its own compact
    # printer. Order mirrors the original get_sgp32_all_data() method so
    # the visible trace remains a superset of the old output.
    plan = (
        {
            "key": "rat",
            "title": "GetRAT — Rules Authorisation Table",
            "es10_tag": "BF4300",
            "printer_name": "_print_rat_compact_response",
            "parser_mode": "response",
        },
        {
            "key": "notifications",
            "title": "RetrieveNotificationsList",
            "es10_tag": "BF2B00",
            "printer_name": "_print_notifications_list_compact",
            "parser_mode": "parsed",
        },
        {
            "key": "eim_config",
            "title": "eIM Configuration Data",
            "es10_tag": "BF5500",
            "printer_name": "_print_eim_configuration_compact",
            "parser_mode": "response",
        },
        {
            "key": "certs",
            "title": "GetCerts — eUICC certificate inventory",
            "es10_tag": "BF5600",
            "printer_name": "_print_get_certs_compact_response",
            "parser_mode": "response",
        },
    )
    for step in plan:
        section = _sgp32_run_section(
            sgp22,
            key=step["key"],
            title=step["title"],
            es10_tag=step["es10_tag"],
            printer_name=step["printer_name"],
            parser_mode=step["parser_mode"],
        )
        sections.append(section)
        overall_sink.write("\n")
        if section["trace"]:
            overall_sink.write(section["trace"])

    # Small rollup so the GUI can show an at-a-glance summary chip row.
    ok_count = sum(1 for s in sections if s["status"] == "ok")
    empty_count = sum(1 for s in sections if s["status"] == "empty")
    error_count = sum(1 for s in sections if s["status"] == "error")

    return {
        "session_id": sid,
        "standard": "SGP.32",
        "sections": sections,
        "summary": {
            "total": len(sections),
            "ok": ok_count,
            "empty": empty_count,
            "error": error_count,
        },
        # Full captured stdout kept for backwards-compat / audit callers.
        # New GUI code prefers ``sections[*]``; only fall back to this
        # blob if a caller doesn't know how to parse the structured form.
        "trace": overall_sink.getvalue(),
    }


# ------------------------------------------------------------- lifecycle
def _dispatch_profile_lifecycle(
    ctx: ActionContext,
    *,
    session_id: Any,
    target: Any,
    fn_name: str,
    label: str,
) -> dict[str, Any]:
    """Shared implementation for enable_profile / disable_profile / delete_profile."""
    identifier = _resolve_profile_identifier(target)
    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)
    sgp22 = gp.sgp22

    try:
        result, trace = _run_sgp22_quietly(sgp22, fn_name, identifier)
        return {
            "session_id": sid,
            "action": label,
            "target": identifier,
            "ok": bool(result),
            "lines": _sgp32_bulk_trace_lines(trace),
            "trace": trace,
        }
    finally:
        _restore_fs_root_best_effort(session)


def _dispatch_enable_profile(
    ctx: ActionContext, *, session_id: Any = None, target: Any = None
) -> dict[str, Any]:
    return _dispatch_profile_lifecycle(
        ctx,
        session_id=session_id,
        target=target,
        fn_name="enable_profile",
        label="enable",
    )


def _dispatch_disable_profile(
    ctx: ActionContext, *, session_id: Any = None, target: Any = None
) -> dict[str, Any]:
    return _dispatch_profile_lifecycle(
        ctx,
        session_id=session_id,
        target=target,
        fn_name="disable_profile",
        label="disable",
    )


def _dispatch_delete_profile(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """ES10c.DeleteProfile — irrevocable, so ``confirm`` must match target."""
    identifier = _resolve_profile_identifier(target)
    confirm_text = str(confirm or "").strip().upper().replace(" ", "").replace(":", "")
    if confirm_text != identifier:
        raise ValueError(
            "confirm must equal the target (AID/ICCID) to prevent accidental deletion."
        )
    return _dispatch_profile_lifecycle(
        ctx,
        session_id=session_id,
        target=target,
        fn_name="delete_profile",
        label="delete",
    )


# ------------------------------------------------------------------ crypto
def _dispatch_derive_opc(
    ctx: ActionContext,
    *,
    ki: Any = None,
    op: Any = None,
) -> dict[str, Any]:
    """Derive OPc from Ki + OP (3GPP TS 35.206). No card required."""
    from SCP03.logic.security import SecurityController

    ki_text = str(ki or "").strip().upper().replace(" ", "")
    op_text = str(op or "").strip().upper().replace(" ", "")
    if len(ki_text) == 0 or len(op_text) == 0:
        raise ValueError("Ki and OP are required (32 hex chars each).")
    try:
        opc = SecurityController.derive_opc(ki_text, op_text)
    except ValueError as error:
        raise ValueError(f"OPc derivation rejected input: {error}") from error
    except RuntimeError as error:
        raise ValueError(str(error)) from error
    return {
        "ki": ki_text,
        "op": op_text,
        "opc": opc,
    }


def _dispatch_run_auth_test_vector(ctx: ActionContext) -> dict[str, Any]:
    """Run the 3GPP TS 35.207 Milenage offline vector — no card required."""
    from SCP03.logic.security import (
        AUTH_TEST_VECTOR,
        SecurityController,
    )

    report = SecurityController.build_auth_test_vector_report()
    exchange = SecurityController.build_auth_test_usim_exchange()

    def _row(label: str, derived: str, expected: str) -> dict[str, Any]:
        return {
            "label": label,
            "derived": derived,
            "expected": expected,
            "match": derived == expected,
        }

    rows = [
        _row("OPc", report.opc, AUTH_TEST_VECTOR["OPc"]),
        _row("RES", report.res, AUTH_TEST_VECTOR["RES"]),
        _row("CK", report.ck, AUTH_TEST_VECTOR["CK"]),
        _row("IK", report.ik, AUTH_TEST_VECTOR["IK"]),
        _row("Kc", report.kc, AUTH_TEST_VECTOR["Kc"]),
        _row("AUTN", exchange.autn, AUTH_TEST_VECTOR["AUTN"]),
        _row("USIM AUTH APDU", exchange.command_apdu, AUTH_TEST_VECTOR["USIM_AUTH_APDU"]),
        _row(
            "USIM AUTH RESPONSE",
            exchange.response_payload,
            AUTH_TEST_VECTOR["USIM_AUTH_RESPONSE"],
        ),
    ]
    mismatches = [row for row in rows if not row["match"]]
    return {
        "inputs": {
            "RAND": AUTH_TEST_VECTOR["RAND"],
            "Ki": AUTH_TEST_VECTOR["Ki"],
            "OP": AUTH_TEST_VECTOR["OP"],
            "SQN": AUTH_TEST_VECTOR["SQN"],
            "AMF": AUTH_TEST_VECTOR["AMF"],
        },
        "rows": rows,
        "all_match": len(mismatches) == 0,
        "mismatches": [row["label"] for row in mismatches],
    }


# --------------------------------------------------------- gold profile
_GOLD_STANDARDS = ("SGP.32", "SGP.22", "SGP.02")


def _read_gold_profile_state() -> dict[str, Any]:
    """Read the persisted gold-profile settings from the SCP03 inventory state."""
    from SCP03.config import Config as Scp03Config
    from yggdrasim_common.device_inventory import DeviceInventoryStore

    try:
        inv = DeviceInventoryStore()
        state = inv.get_module_state(Scp03Config.MODULE_STATE_NAME) or {}
    except Exception as error:  # noqa: BLE001 — surface but don't crash
        return {
            "path": "",
            "standard": "SGP.32",
            "authenticate_sd": False,
            "error": f"inventory unavailable: {error}",
        }

    gp = state.get("GOLD_PROFILE", {}) or {}
    path_raw = str(gp.get("path", "") or "").strip()
    std_raw = str(gp.get("standard", "SGP.32") or "SGP.32").strip().upper()
    if std_raw not in _GOLD_STANDARDS:
        std_raw = "SGP.32"
    auth_raw = str(gp.get("authenticate_sd", "false") or "false").strip().lower()
    return {
        "path": os.path.expanduser(path_raw) if path_raw else "",
        "standard": std_raw,
        "authenticate_sd": auth_raw in ("1", "true", "yes", "on"),
    }


def _write_gold_profile_state(payload: dict[str, Any]) -> None:
    """Persist the gold-profile settings into the SCP03 inventory state."""
    from SCP03.config import Config as Scp03Config
    from yggdrasim_common.device_inventory import DeviceInventoryStore

    inv = DeviceInventoryStore()
    current = inv.get_module_state(Scp03Config.MODULE_STATE_NAME) or {}
    if not isinstance(current, dict):
        current = {}
    current.setdefault("KEYS", {})
    gp = dict(current.get("GOLD_PROFILE", {}) or {})
    gp.update({str(k): ("" if v is None else str(v)) for k, v in payload.items()})
    current["GOLD_PROFILE"] = gp
    inv.replace_module_state(Scp03Config.MODULE_STATE_NAME, current)


def _dispatch_set_gold_profile(
    ctx: ActionContext,
    *,
    path: Any = None,
    standard: Any = None,
    authenticate_sd: Any = None,
) -> dict[str, Any]:
    """Persist a gold-profile baseline (path + standard + auth flag) to inventory."""
    path_raw = str(path or "").strip()
    if len(path_raw) == 0:
        raise ValueError("path is required (YAML file saved from the shell REPORT wizard).")
    std_raw = str(standard or "SGP.32").strip().upper()
    if std_raw not in _GOLD_STANDARDS:
        raise ValueError(f"standard must be one of {list(_GOLD_STANDARDS)}.")
    auth_flag = authenticate_sd in (True, "true", "True", "TRUE", "1", 1, "yes", "YES", "Y", "y", "on")

    expanded = os.path.expanduser(path_raw)
    payload = {
        "path": expanded,
        "standard": std_raw,
        "authenticate_sd": "true" if auth_flag else "false",
    }
    _write_gold_profile_state(payload)
    result = dict(payload)
    result["authenticate_sd"] = auth_flag
    result["exists"] = os.path.isfile(expanded)
    return result


def _dispatch_show_gold_profile(ctx: ActionContext) -> dict[str, Any]:
    """Inspect the persisted gold-profile settings (no card required)."""
    settings = _read_gold_profile_state()
    path = settings.get("path") or ""
    settings["exists"] = bool(path) and os.path.isfile(path)
    return settings


def _dispatch_clear_gold_profile(ctx: ActionContext) -> dict[str, Any]:
    """Clear the persisted gold-profile path (keep standard + auth prefs)."""
    settings = _read_gold_profile_state()
    settings_to_write = {
        "path": "",
        "standard": settings.get("standard", "SGP.32"),
        "authenticate_sd": "true" if settings.get("authenticate_sd") else "false",
    }
    _write_gold_profile_state(settings_to_write)
    return {
        "cleared": True,
        "standard": settings_to_write["standard"],
        "authenticate_sd": settings.get("authenticate_sd", False),
    }


def _build_euicc_baseline(gp: Any, *, standard: str) -> dict[str, Any]:
    """Mirror of ``Scp03Shell._build_euicc_export_report`` without shell state."""
    import datetime

    sgp22 = gp.sgp22
    report = sgp22.get_euicc_report_extended(standard=standard)
    cplc_data, sw1, _sw2 = gp.get_cplc_data()
    if cplc_data and sw1 == 0x90:
        report["cplc_hex"] = bytes(cplc_data).hex().upper()
    report["generated"] = datetime.datetime.now().isoformat()
    return report


def _dispatch_profile_diff(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    gold_path: Any = None,
    standard: Any = None,
) -> dict[str, Any]:
    """Live-card eUICC report vs gold YAML (``euicc_report`` section).

    Scope is eUICC-only in this first pass. The shell's combined-profile
    diff also covers file-system + MNO-SD; those phases currently require
    a full ``Scp03Shell`` instance (repeated resets + ADM verify) and
    will land in a follow-up once the helpers are refactored to stand
    alone.
    """
    import yaml

    session, _transporter, sid = _get_scp03_session(session_id)
    gp = _get_or_make_gp_ctrl(session)

    settings = _read_gold_profile_state()
    gold = str(gold_path or "").strip() or settings.get("path", "")
    if len(gold) == 0:
        raise ValueError(
            "no gold YAML: provide gold_path or run scp03.set_gold_profile first."
        )
    gold_expanded = os.path.expanduser(gold)
    if not os.path.isfile(gold_expanded):
        raise ValueError(f"gold YAML not found: {gold_expanded}")

    std = str(standard or "").strip().upper() or settings.get("standard", "SGP.32")
    if std not in _GOLD_STANDARDS:
        raise ValueError(f"standard must be one of {list(_GOLD_STANDARDS)}.")

    with open(gold_expanded, "r", encoding="utf-8") as handle:
        gold_doc = yaml.safe_load(handle)
    if not isinstance(gold_doc, dict):
        raise ValueError("gold YAML must decode to a mapping.")

    gold_euicc = gold_doc.get("euicc_report")
    if not isinstance(gold_euicc, dict):
        raise ValueError(
            "gold YAML does not contain an 'euicc_report' section; "
            "was it produced by the shell REPORT wizard?"
        )

    live_euicc = _build_euicc_baseline(gp, standard=std)

    from SCP03.logic.profile_snapshot_diff import combined_profile_unified_diff

    ok, diff_text = combined_profile_unified_diff(
        {"euicc_report": gold_euicc},
        {"euicc_report": live_euicc},
        gold_label=f"gold:{gold_expanded}",
        live_label="live:pcsc",
    )
    return {
        "session_id": sid,
        "gold_path": gold_expanded,
        "standard": std,
        "scope": "euicc",
        "match": bool(ok),
        "diff": diff_text if not ok else "",
        "live_generated": live_euicc.get("generated", ""),
    }


# -------------------- action specs ------------------------------------

GET_EID_SPEC = ActionSpec(
    id="scp03.get_eid",
    subsystem="SCP03",
    title="Get EID",
    description="ES10c.GetEID — compact EID read from ISD-R.",
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_get_eid,
    requires_card=True,
    tags=("euicc", "eid", "read-only"),
)


GET_EUICC_CERTS_SPEC = ActionSpec(
    id="scp03.get_euicc_certs",
    subsystem="SCP03",
    title="GetCerts (eUICC)",
    description="ES10b.GetCerts — ECASD / eUICC certificate chain retrieval.",
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_get_euicc_certs,
    requires_card=True,
    tags=("euicc", "certs", "read-only"),
)


GET_EUICC_CONFIGURED_DATA_SPEC = ActionSpec(
    id="scp03.get_euicc_configured_data",
    subsystem="SCP03",
    title="GetEuiccConfiguredData",
    description="ES10a.GetEuiccConfiguredData / GetEuiccConfiguredAddresses (BF3C00).",
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_get_euicc_configured_data,
    requires_card=True,
    tags=("euicc", "configured-data", "read-only"),
)


GET_SGP32_ALL_DATA_SPEC = ActionSpec(
    id="scp03.get_sgp32_all_data",
    subsystem="SCP03",
    title="SGP.32 bulk telemetry",
    description=(
        "Consolidated SGP.32 retrieval: scan + RAT + NotificationsList + "
        "eIM configuration + GetCerts. Runs the same sweep as the shell's "
        "GET-SGP32-ALL-DATA helper."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_get_sgp32_all_data,
    requires_card=True,
    tags=("euicc", "sgp32", "bulk", "read-only"),
)


ENABLE_PROFILE_SPEC = ActionSpec(
    id="scp03.enable_profile",
    subsystem="SCP03",
    title="Enable profile",
    description="ES10c.EnableProfile — make the selected profile active.",
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="target",
            label="Target (AID / ICCID)",
            kind="string",
            required=True,
            placeholder="A0000005591010FFFFFFFF8900050200  or  89XXXXXXXXXXXXXXXXXF",
            help="AID hex or ICCID digits — the shell accepts either.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_enable_profile,
    requires_card=True,
    tags=("euicc", "profile", "lifecycle"),
)


DISABLE_PROFILE_SPEC = ActionSpec(
    id="scp03.disable_profile",
    subsystem="SCP03",
    title="Disable profile",
    description="ES10c.DisableProfile — deactivate the selected profile.",
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="target",
            label="Target (AID / ICCID)",
            kind="string",
            required=True,
            placeholder="AID hex or ICCID digits",
            help="AID hex or ICCID digits.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_disable_profile,
    requires_card=True,
    tags=("euicc", "profile", "lifecycle"),
)


DELETE_PROFILE_SPEC = ActionSpec(
    id="scp03.delete_profile",
    subsystem="SCP03",
    title="Delete profile",
    description=(
        "ES10c.DeleteProfile — irreversible. The ``confirm`` field must "
        "match the target exactly before the dispatcher will proceed."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="target",
            label="Target (AID / ICCID)",
            kind="string",
            required=True,
            placeholder="AID hex or ICCID digits",
        ),
        ActionField(
            name="confirm",
            label="Type the target again to confirm",
            kind="string",
            required=True,
            placeholder="must match the target exactly",
            help="Typed back to guard against fat-finger deletions.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_delete_profile,
    requires_card=True,
    tags=("euicc", "profile", "lifecycle", "destructive"),
)


DERIVE_OPC_SPEC = ActionSpec(
    id="scp03.derive_opc",
    subsystem="SCP03",
    title="Derive OPc (Milenage)",
    description=(
        "Derive OPc from Ki and OP per 3GPP TS 35.206 — OPc = AES128(Ki, OP) "
        "XOR OP. No card required."
    ),
    inputs=(
        ActionField(
            name="ki",
            label="Ki (hex)",
            kind="string",
            required=True,
            placeholder="32 hex chars",
            help="Subscriber authentication key Ki (16 bytes).",
        ),
        ActionField(
            name="op",
            label="OP (hex)",
            kind="string",
            required=True,
            placeholder="32 hex chars",
            help="Operator Variant OP (16 bytes).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_derive_opc,
    requires_card=False,
    tags=("crypto", "milenage", "offline"),
)


RUN_AUTH_TEST_VECTOR_SPEC = ActionSpec(
    id="scp03.run_auth_test_vector",
    subsystem="SCP03",
    title="Run auth test vector",
    description=(
        "Run the 3GPP TS 35.207 Milenage offline vector and compare derived "
        "OPc / RES / CK / IK / Kc / AUTN / APDU against the published expected "
        "values. No card required."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_run_auth_test_vector,
    requires_card=False,
    tags=("crypto", "milenage", "test-vector", "offline"),
)


SET_GOLD_PROFILE_SPEC = ActionSpec(
    id="scp03.set_gold_profile",
    subsystem="SCP03",
    title="Set gold profile",
    description=(
        "Persist a gold-profile baseline (YAML from the shell REPORT "
        "wizard) into the SCP03 inventory state. PROFILE-DIFF will diff "
        "live card reads against this baseline."
    ),
    inputs=(
        ActionField(
            name="path",
            label="Gold YAML path",
            kind="path",
            required=True,
            placeholder="/path/to/gold_profile.yaml",
            help="YAML produced by REPORT (shell) — contains euicc_report section. Double-click to browse.",
        ),
        ActionField(
            name="standard",
            label="Standard",
            kind="enum",
            required=False,
            default="SGP.32",
            choices=list(_GOLD_STANDARDS),
            help="Declared standard the gold snapshot was taken under.",
        ),
        ActionField(
            name="authenticate_sd",
            label="Authenticate SD",
            kind="bool",
            required=False,
            default=False,
            help="If True, PROFILE-DIFF will run SCP03 auth before collecting the MNO-SD report.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_gold_profile,
    requires_card=False,
    tags=("gold", "snapshot", "config"),
)


SHOW_GOLD_PROFILE_SPEC = ActionSpec(
    id="scp03.show_gold_profile",
    subsystem="SCP03",
    title="Show gold profile",
    description="Inspect the persisted gold-profile settings.",
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_show_gold_profile,
    requires_card=False,
    tags=("gold", "snapshot", "config"),
)


CLEAR_GOLD_PROFILE_SPEC = ActionSpec(
    id="scp03.clear_gold_profile",
    subsystem="SCP03",
    title="Clear gold profile",
    description="Clear the persisted gold-profile path (keeps standard + auth flag).",
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_clear_gold_profile,
    requires_card=False,
    tags=("gold", "snapshot", "config"),
)


PROFILE_DIFF_SPEC = ActionSpec(
    id="scp03.profile_diff",
    subsystem="SCP03",
    title="Profile diff (eUICC)",
    description=(
        "Diff the live card's eUICC report against a gold YAML. "
        "Scope is eUICC-only — file-system + MNO-SD phases will land in "
        "a follow-up."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="gold_path",
            label="Gold YAML (override)",
            kind="path",
            required=False,
            placeholder="blank = use persisted gold_profile.path",
            help="Blank = fall back to the persisted gold-profile path. Double-click to browse.",
        ),
        ActionField(
            name="standard",
            label="Standard override",
            kind="enum",
            required=False,
            default="",
            choices=["", *_GOLD_STANDARDS],
            help="Blank = use persisted standard.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_profile_diff,
    requires_card=True,
    tags=("gold", "snapshot", "diff", "euicc"),
)


get_registry().register(GET_EID_SPEC)
get_registry().register(GET_EUICC_CERTS_SPEC)
get_registry().register(GET_EUICC_CONFIGURED_DATA_SPEC)
get_registry().register(GET_SGP32_ALL_DATA_SPEC)
get_registry().register(ENABLE_PROFILE_SPEC)
get_registry().register(DISABLE_PROFILE_SPEC)
get_registry().register(DELETE_PROFILE_SPEC)
get_registry().register(DERIVE_OPC_SPEC)
get_registry().register(RUN_AUTH_TEST_VECTOR_SPEC)
get_registry().register(SET_GOLD_PROFILE_SPEC)
get_registry().register(SHOW_GOLD_PROFILE_SPEC)
get_registry().register(CLEAR_GOLD_PROFILE_SPEC)
get_registry().register(PROFILE_DIFF_SPEC)


# ======================================================================
# C-4 Tier-3 — Admin / configuration (show_config / set_aid_alias /
# set_defaults). These mirror the shell's SHOW-CONFIG, SET-AID-ALIAS, and
# SET-DEFAULTS commands, but work without a full ``Scp03Shell`` instance
# by talking directly to the SQLite inventory and the aid.txt registry.
# ======================================================================


_SECRET_KEY_SLOTS = (
    "scp03_kenc",
    "scp03_kmac",
    "scp03_dek",
    "scp02_enc",
    "scp02_mac",
    "scp02_dek",
    "adm",
)


def _mask_secret_value(key_name: str, value: str, *, mask: bool) -> str:
    """Return value unchanged for non-secrets or when ``mask`` is False.

    For secret slots we keep the length readable but redact the body,
    so operators can still tell "something is set" vs "empty".
    """
    if not mask:
        return value
    if key_name.lower() not in _SECRET_KEY_SLOTS:
        return value
    cleaned = str(value or "").strip()
    if len(cleaned) == 0:
        return ""
    return f"****{len(cleaned)}ch****"


def _dispatch_show_config(
    ctx: ActionContext,
    *,
    mask_secrets: Any = True,
) -> dict[str, Any]:
    """Read the persisted SCP03 state (inventory + AID registry) and return it."""
    from SCP03.config import Config as Scp03Config
    from yggdrasim_common.device_inventory import DeviceInventoryStore

    mask = bool(mask_secrets) if not isinstance(mask_secrets, str) else (
        str(mask_secrets).lower() in ("1", "true", "yes", "on")
    )

    # Inventory-backed module state (KEYS + GOLD_PROFILE).
    inventory_error: str | None = None
    keys: dict[str, str] = {}
    gold: dict[str, str] = {}
    try:
        inv = DeviceInventoryStore()
        state = inv.get_module_state(Scp03Config.MODULE_STATE_NAME) or {}
    except Exception as error:  # noqa: BLE001
        inventory_error = str(error)
        state = {}
    if isinstance(state, dict):
        raw_keys = state.get("KEYS", {})
        if isinstance(raw_keys, dict):
            for slot_name, slot_value in raw_keys.items():
                keys[str(slot_name)] = str(slot_value or "")
        raw_gold = state.get("GOLD_PROFILE", {})
        if isinstance(raw_gold, dict):
            for gold_key, gold_value in raw_gold.items():
                gold[str(gold_key)] = str(gold_value or "")

    # Fall back to DEFAULT_KEYS entries so operators see a complete row list.
    for default_key, default_value in Scp03Config.DEFAULT_KEYS.items():
        if default_key not in keys:
            keys[default_key] = str(default_value or "")

    masked_keys = {
        slot_name: _mask_secret_value(slot_name, slot_value, mask=mask)
        for slot_name, slot_value in sorted(keys.items())
    }

    # aid.txt registry (fresh read — same path the shell uses).
    aid_path = str(Scp03Config.AID_FILE)
    aid_entries: list[dict[str, str]] = []
    aid_error: str | None = None
    try:
        with open(aid_path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if len(line) == 0 or line.startswith("#"):
                    continue
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                aid_entries.append(
                    {
                        "name": parts[0].strip().upper(),
                        "aid": parts[1].strip().upper().replace(" ", ""),
                        "role": parts[2].strip() if len(parts) >= 3 else "",
                    }
                )
    except FileNotFoundError:
        aid_error = f"aid.txt not found at {aid_path}"
    except Exception as error:  # noqa: BLE001
        aid_error = str(error)
    aid_entries.sort(key=lambda row: row.get("name", ""))

    return {
        "ini_file": str(Scp03Config.INI_FILE),
        "module_state_name": Scp03Config.MODULE_STATE_NAME,
        "inventory_error": inventory_error,
        "keys_masked": mask,
        "keys": masked_keys,
        "gold_profile": gold,
        "aid_file": aid_path,
        "aid_count": len(aid_entries),
        "aid_entries": aid_entries,
        "aid_error": aid_error,
    }


def _valid_aid_alias_name(name: str) -> bool:
    """Alias names must be alphanumeric / underscore / hyphen, 1-16 chars."""
    cleaned = str(name or "").strip()
    if len(cleaned) == 0 or len(cleaned) > 16:
        return False
    for ch in cleaned:
        if not (ch.isalnum() or ch in ("_", "-")):
            return False
    return True


def _rewrite_aid_file(entries: dict[str, str]) -> None:
    """Rewrite the aid.txt registry atomically with the provided alias map."""
    from SCP03.config import Config as Scp03Config

    path = str(Scp03Config.AID_FILE)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        for name in sorted(entries.keys()):
            handle.write(f"{name}:{entries[name]}\n")
    os.replace(tmp_path, path)


def _dispatch_set_aid_alias(
    ctx: ActionContext,
    *,
    name: Any = None,
    aid: Any = None,
    delete: Any = None,
) -> dict[str, Any]:
    """Add / update / delete an entry in the AID registry (aid.txt)."""
    from SCP03.config import Config as Scp03Config

    name_text = str(name or "").strip().upper()
    if not _valid_aid_alias_name(name_text):
        raise ValueError(
            "name must be 1-16 chars of [A-Z0-9_-]; case is normalized to upper."
        )
    delete_flag = delete in (True, "true", "True", "TRUE", "1", 1, "yes", "YES", "on")

    aid_text = str(aid or "").strip().upper().replace(" ", "").replace(":", "")
    if not delete_flag:
        if len(aid_text) == 0:
            raise ValueError("aid is required unless delete=true.")
        if len(aid_text) % 2 != 0:
            raise ValueError("aid must contain an even number of hex chars.")
        try:
            bytes.fromhex(aid_text)
        except ValueError as error:
            raise ValueError(f"aid is not valid hex: {error}") from error

    # Read existing registry first so we don't drop unrelated aliases.
    path = str(Scp03Config.AID_FILE)
    current: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if len(line) == 0 or line.startswith("#"):
                    continue
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                current[parts[0].strip().upper()] = parts[1].strip().upper().replace(" ", "")
    except FileNotFoundError:
        current = {}

    had_entry = name_text in current
    if delete_flag:
        if not had_entry:
            raise ValueError(f"no alias named {name_text!r} to delete.")
        del current[name_text]
    else:
        current[name_text] = aid_text

    _rewrite_aid_file(current)

    return {
        "path": path,
        "action": "delete" if delete_flag else ("update" if had_entry else "add"),
        "name": name_text,
        "aid": "" if delete_flag else aid_text,
        "count": len(current),
    }


def _dispatch_set_defaults(
    ctx: ActionContext,
    *,
    confirm: Any = None,
) -> dict[str, Any]:
    """Reset the persisted SCP03 KEYS back to the shipped demo defaults.

    Requires the operator to pass ``confirm="RESET"`` — this is a
    destructive settings change that invalidates live secure sessions.
    """
    from SCP03.config import Config as Scp03Config
    from yggdrasim_common.device_inventory import DeviceInventoryStore
    from yggdrasim_common.gui_server.sessions import get_manager

    confirm_text = str(confirm or "").strip().upper()
    if confirm_text != "RESET":
        raise ValueError('confirm must equal "RESET" (case-insensitive) to reset defaults.')

    # Read existing state so we preserve GOLD_PROFILE.
    inv = DeviceInventoryStore()
    state = inv.get_module_state(Scp03Config.MODULE_STATE_NAME) or {}
    if not isinstance(state, dict):
        state = {}

    default_keys = {str(k): str(v) for k, v in Scp03Config.DEFAULT_KEYS.items()}
    if "adm" not in default_keys:
        default_keys["adm"] = "0000000000000000"

    state["KEYS"] = default_keys
    state.setdefault("GOLD_PROFILE", {})
    inv.replace_module_state(Scp03Config.MODULE_STATE_NAME, state)

    # Invalidate cached GlobalPlatformManager instances on any live SCP03
    # sessions so the next auth call rebuilds with the fresh keys. We go
    # through each session_id reported by the manager and claim() it so
    # the session's handle dict is reachable without touching private
    # internals.
    invalidated = 0
    try:
        manager = get_manager()
        snapshot = manager.list()
        for row in snapshot:
            if row.get("kind") != "scp03":
                continue
            session_id = row.get("id")
            if not session_id:
                continue
            try:
                handle = manager.claim(str(session_id))
            except KeyError:
                continue
            if isinstance(handle, dict) and handle.get("gp") is not None:
                handle["gp"] = None
                invalidated += 1
    except Exception:  # noqa: BLE001 — best-effort
        pass

    return {
        "reset": True,
        "key_count": len(default_keys),
        "sessions_invalidated": invalidated,
        "module_state_name": Scp03Config.MODULE_STATE_NAME,
    }


SHOW_CONFIG_SPEC = ActionSpec(
    id="scp03.show_config",
    subsystem="SCP03",
    title="Show config",
    description=(
        "Inspect the persisted SCP03 state: KEYS (masked by default), "
        "GOLD_PROFILE, and the AID registry file. No card required."
    ),
    inputs=(
        ActionField(
            name="mask_secrets",
            label="Mask key material",
            kind="bool",
            required=False,
            default=True,
            help="Redact secret key slots (scp03_k* / scp02_* / adm) before returning.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_show_config,
    requires_card=False,
    tags=("config", "inventory", "read-only"),
)


SET_AID_ALIAS_SPEC = ActionSpec(
    id="scp03.set_aid_alias",
    subsystem="SCP03",
    title="Set AID alias",
    description=(
        "Add / update / remove a named AID entry in the aid.txt registry. "
        "Names are normalized to upper-case, 1-16 chars of [A-Z0-9_-]."
    ),
    inputs=(
        ActionField(
            name="name",
            label="Alias name",
            kind="string",
            required=True,
            placeholder="ISD",
            help="1-16 chars of letters / digits / underscore / hyphen.",
        ),
        ActionField(
            name="aid",
            label="AID (hex)",
            kind="string",
            required=False,
            placeholder="A0000005591010FFFFFFFF8900000100",
            help="Required unless delete=true.",
        ),
        ActionField(
            name="delete",
            label="Delete existing",
            kind="bool",
            required=False,
            default=False,
            help="If true, remove the alias instead of adding / updating.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_aid_alias,
    requires_card=False,
    tags=("config", "aid", "registry"),
)


SET_DEFAULTS_SPEC = ActionSpec(
    id="scp03.set_defaults",
    subsystem="SCP03",
    title="Reset key defaults",
    description=(
        "Reset the persisted KEYS to the shipped demo placeholders. "
        "Requires confirm=\"RESET\" and invalidates any cached "
        "GlobalPlatformManager instances on live SCP03 sessions."
    ),
    inputs=(
        ActionField(
            name="confirm",
            label="Confirm",
            kind="string",
            required=True,
            placeholder="type RESET to proceed",
            help="Destructive — wipes current KEYS from inventory.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_defaults,
    requires_card=False,
    tags=("config", "keys", "destructive"),
)


get_registry().register(SHOW_CONFIG_SPEC)
get_registry().register(SET_AID_ALIAS_SPEC)
get_registry().register(SET_DEFAULTS_SPEC)


# ======================================================================
# C-5 — Mutation depth: PUT KEY / INSTALL / FS-ADMIN / MANAGE-PIN /
# MANAGE-CHANNEL / RUN-AUTH (live). All of these talk to the active SCP03
# session, mutate card state, and are gated behind ``_require_auth_session``
# unless the operation explicitly does not need a secure channel
# (e.g. VERIFY PIN on a freshly selected ADF).
# ======================================================================


def _capture_method(target: Any, method_name: str, *args: Any, **kwargs: Any) -> tuple[Any, str]:
    """Run ``target.method_name(*args, **kwargs)`` while capturing stdout.

    Returns ``(return_value, trace_text)``. ANSI codes are stripped so the
    GUI can render the trace verbatim into a ``<pre>``.
    """
    fn = getattr(target, method_name)
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        result = fn(*args, **kwargs)
    return result, _strip_ansi(sink.getvalue())


def _normalize_hex(value: Any, *, label: str, allow_empty: bool = False) -> str:
    cleaned = str(value or "").strip().upper().replace(" ", "")
    if len(cleaned) == 0:
        if allow_empty:
            return ""
        raise ValueError(f"{label} is required.")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"{label} must be even-length hex.")
    try:
        bytes.fromhex(cleaned)
    except ValueError as error:
        raise ValueError(f"{label} is not valid hex: {error}") from error
    return cleaned


def _classify_sw(sw1: int, sw2: int) -> tuple[bool, str]:
    """Return ``(ok, label)`` for an APDU status word pair."""
    if sw1 == 0x90 and sw2 == 0x00:
        return True, "OK"
    if sw1 == 0x61:
        return True, f"OK (61{sw2:02X} more bytes available)"
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        return False, f"PIN failed — {sw2 & 0x0F} attempt(s) remaining"
    if sw1 == 0x69 and sw2 == 0x82:
        return False, "Security status not satisfied"
    if sw1 == 0x69 and sw2 == 0x83:
        return False, "Authentication blocked"
    if sw1 == 0x69 and sw2 == 0x84:
        return False, "Reference data invalidated"
    if sw1 == 0x69 and sw2 == 0x85:
        return False, "Conditions of use not satisfied"
    if sw1 == 0x6A and sw2 == 0x80:
        return False, "Incorrect data parameters"
    if sw1 == 0x6A and sw2 == 0x82:
        return False, "File not found"
    if sw1 == 0x6A and sw2 == 0x84:
        return False, "Not enough memory"
    if sw1 == 0x6A and sw2 == 0x86:
        return False, "Incorrect P1/P2"
    if sw1 == 0x6D and sw2 == 0x00:
        return False, "INS not supported"
    if sw1 == 0x6E and sw2 == 0x00:
        return False, "CLA not supported"
    return False, f"Card error {sw1:02X}{sw2:02X}"


# --- C-5: PUT KEY -----------------------------------------------------


def _dispatch_put_key(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    new_kvn: Any = None,
    new_key_id: Any = None,
    old_kvn: Any = "00",
    enc_key: Any = None,
    mac_key: Any = None,
    dek_key: Any = None,
    algorithm: Any = "AES",
    confirm: Any = None,
) -> dict[str, Any]:
    """GP PUT KEY (GPCS 11.8) — install or replace a keyset on the active SD."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    confirm_text = str(confirm or "").strip().upper()
    if confirm_text != "PUT-KEY":
        raise ValueError(
            "confirm=\"PUT-KEY\" is required — overwriting keys can brick the card."
        )

    new_kvn_int = _parse_hex_byte(new_kvn, label="new_kvn")
    new_kid_int = _parse_hex_byte(new_key_id, label="new_key_id")
    old_kvn_int = _parse_hex_byte(old_kvn or "00", label="old_kvn")

    enc_hex = _normalize_hex(enc_key, label="enc_key")
    mac_hex = _normalize_hex(mac_key, label="mac_key")
    dek_hex = _normalize_hex(dek_key, label="dek_key")

    # GP key lengths: AES-128/192/256 = 16/24/32 bytes; 3DES = 16 / 24.
    for label, hex_val in (("enc_key", enc_hex), ("mac_key", mac_hex), ("dek_key", dek_hex)):
        n_bytes = len(hex_val) // 2
        if n_bytes not in (16, 24, 32):
            raise ValueError(
                f"{label} length {n_bytes} bytes invalid — expected 16 / 24 / 32."
            )

    algo_norm = str(algorithm or "AES").strip().upper()
    if algo_norm in ("AES", "AES-128", "AES-192", "AES-256"):
        key_type = 0x88
    elif algo_norm in ("3DES", "DES", "TDES"):
        key_type = 0x82
    elif algo_norm.startswith("0X"):
        try:
            key_type = int(algo_norm, 16)
        except ValueError as error:
            raise ValueError(f"invalid algorithm hex override: {error}") from error
    else:
        raise ValueError(f"unsupported algorithm: {algo_norm!r}")

    gp = _get_or_make_gp_ctrl(session)
    success, trace = _capture_method(
        gp,
        "put_key",
        old_kvn_int,
        new_kid_int,
        new_kvn_int,
        [enc_hex, mac_hex, dek_hex],
        key_type,
    )

    return {
        "session_id": sid,
        "ok": bool(success),
        "old_kvn": f"{old_kvn_int:02X}",
        "new_kvn": f"{new_kvn_int:02X}",
        "new_key_id": f"{new_kid_int:02X}",
        "key_type": f"{key_type:02X}",
        "algorithm": algo_norm,
        "trace": trace,
    }


# --- C-5: INSTALL [for load + install + make-selectable] ---------------


def _dispatch_install_cap(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    cap_path: Any = None,
    privileges: Any = "00",
    install_params: Any = "C900",
    instantiate: Any = True,
    target_app_aid: Any = None,
    target_module_aid: Any = None,
    load_chunk_size: Any = None,
) -> dict[str, Any]:
    """GP INSTALL [for load] + LOAD + INSTALL [for install] in one go."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    path_text = str(cap_path or "").strip()
    if len(path_text) == 0:
        raise ValueError("cap_path is required.")
    if not os.path.exists(path_text):
        raise ValueError(f"CAP file not found: {path_text}")

    priv_hex = _normalize_hex(privileges or "00", label="privileges")
    params_hex = _normalize_hex(install_params or "C900", label="install_params", allow_empty=False)

    target_app = None
    if target_app_aid is not None:
        text = str(target_app_aid).strip()
        if len(text) > 0:
            target_app = _normalize_hex(text, label="target_app_aid")

    target_module = None
    if target_module_aid is not None:
        text = str(target_module_aid).strip()
        if len(text) > 0:
            target_module = _normalize_hex(text, label="target_module_aid")

    chunk_int = None
    if load_chunk_size is not None:
        try:
            cleaned = str(load_chunk_size).strip()
            if len(cleaned) > 0:
                chunk_int = int(cleaned)
                if chunk_int <= 0 or chunk_int > 255:
                    raise ValueError("load_chunk_size must be 1..255.")
        except (TypeError, ValueError) as error:
            raise ValueError(f"invalid load_chunk_size: {error}") from error

    instantiate_bool = bool(instantiate)
    if isinstance(instantiate, str):
        instantiate_bool = instantiate.strip().lower() in ("1", "true", "yes", "y")

    gp = _get_or_make_gp_ctrl(session)
    _result, trace = _capture_method(
        gp,
        "install_cap_file",
        path_text,
        privileges=priv_hex,
        install_params=params_hex,
        instantiate=instantiate_bool,
        target_app_aid=target_app,
        target_module_aid=target_module,
        load_chunk_size=chunk_int,
    )

    # install_cap_file returns None; success heuristics live in the trace.
    trace_lower = trace.lower()
    has_failure = ("[-]" in trace) or ("fail" in trace_lower)
    return {
        "session_id": sid,
        "ok": not has_failure,
        "cap_path": path_text,
        "privileges": priv_hex,
        "install_params": params_hex,
        "instantiate": instantiate_bool,
        "target_app_aid": target_app,
        "target_module_aid": target_module,
        "load_chunk_size": chunk_int,
        "trace": trace,
    }


def _dispatch_install_app(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    package_aid: Any = None,
    applet_aid: Any = None,
    module_aid: Any = None,
    privileges: Any = "00",
    install_params: Any = "C900",
    make_selectable: Any = True,
) -> dict[str, Any]:
    """GP INSTALL [for install] (P1=04) / [for install + make selectable] (P1=0C)."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    pkg_hex = _normalize_hex(package_aid, label="package_aid")
    app_hex = _normalize_hex(applet_aid, label="applet_aid")
    mod_hex = None
    if module_aid is not None and len(str(module_aid).strip()) > 0:
        mod_hex = _normalize_hex(module_aid, label="module_aid")
    priv_hex = _normalize_hex(privileges or "00", label="privileges")
    params_hex = _normalize_hex(install_params or "C900", label="install_params")

    make_sel_bool = bool(make_selectable)
    if isinstance(make_selectable, str):
        make_sel_bool = make_selectable.strip().lower() in ("1", "true", "yes", "y")

    gp = _get_or_make_gp_ctrl(session)
    _result, trace = _capture_method(
        gp,
        "install_app",
        pkg_hex,
        app_hex,
        mod_aid_hex=mod_hex,
        privileges=priv_hex,
        params=params_hex,
        make_selectable=make_sel_bool,
    )
    has_failure = ("[-]" in trace) or ("fail" in trace.lower())
    return {
        "session_id": sid,
        "ok": not has_failure,
        "package_aid": pkg_hex,
        "applet_aid": app_hex,
        "module_aid": mod_hex,
        "privileges": priv_hex,
        "install_params": params_hex,
        "make_selectable": make_sel_bool,
        "p1": "0C" if make_sel_bool else "04",
        "trace": trace,
    }


def _dispatch_install_make_selectable(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    aid: Any = None,
    privileges: Any = "00",
    params: Any = "",
    token: Any = "",
) -> dict[str, Any]:
    """GP INSTALL [for make selectable] (P1=08)."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    aid_hex = _normalize_hex(aid, label="aid")
    priv_hex = _normalize_hex(privileges or "00", label="privileges")
    params_hex = _normalize_hex(params or "", label="params", allow_empty=True)
    token_hex = _normalize_hex(token or "", label="token", allow_empty=True)

    gp = _get_or_make_gp_ctrl(session)
    _result, trace = _capture_method(
        gp,
        "install_make_selectable",
        aid_hex,
        privileges=priv_hex,
        params=params_hex,
        token=token_hex,
    )
    has_failure = ("[-]" in trace) or ("fail" in trace.lower())
    return {
        "session_id": sid,
        "ok": not has_failure,
        "aid": aid_hex,
        "privileges": priv_hex,
        "params": params_hex,
        "token": token_hex,
        "trace": trace,
    }


def _dispatch_install_extradition(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    aid: Any = None,
    sd_aid: Any = None,
    token: Any = "",
) -> dict[str, Any]:
    """GP INSTALL [for extradition] (P1=10) — re-bind an instance to a target SD."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    aid_hex = _normalize_hex(aid, label="aid")
    sd_hex = _normalize_hex(sd_aid, label="sd_aid")
    token_hex = _normalize_hex(token or "", label="token", allow_empty=True)

    gp = _get_or_make_gp_ctrl(session)
    _result, trace = _capture_method(
        gp,
        "install_extradition",
        aid_hex,
        sd_hex,
        token=token_hex,
    )
    has_failure = ("[-]" in trace) or ("fail" in trace.lower())
    return {
        "session_id": sid,
        "ok": not has_failure,
        "aid": aid_hex,
        "sd_aid": sd_hex,
        "token": token_hex,
        "trace": trace,
    }


def _dispatch_install_personalization(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    aid: Any = None,
) -> dict[str, Any]:
    """GP INSTALL [for personalization] (P1=20) — open perso channel for STORE DATA."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    aid_hex = _normalize_hex(aid, label="aid")

    gp = _get_or_make_gp_ctrl(session)
    _result, trace = _capture_method(gp, "install_personalization", aid_hex)
    has_failure = ("[-]" in trace) or ("fail" in trace.lower())
    return {
        "session_id": sid,
        "ok": not has_failure,
        "aid": aid_hex,
        "trace": trace,
    }


def _dispatch_install_registry_update(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    aid: Any = None,
    privileges: Any = "00",
    params: Any = "",
) -> dict[str, Any]:
    """GP INSTALL [for registry update] (P1=40) — change privileges / params."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    aid_hex = _normalize_hex(aid, label="aid")
    priv_hex = _normalize_hex(privileges or "00", label="privileges")
    params_hex = _normalize_hex(params or "", label="params", allow_empty=True)

    gp = _get_or_make_gp_ctrl(session)
    _result, trace = _capture_method(
        gp,
        "install_registry_update",
        aid_hex,
        privileges=priv_hex,
        params=params_hex,
    )
    has_failure = ("[-]" in trace) or ("fail" in trace.lower())
    return {
        "session_id": sid,
        "ok": not has_failure,
        "aid": aid_hex,
        "privileges": priv_hex,
        "params": params_hex,
        "trace": trace,
    }


# --- C-5: FS-ADMIN -----------------------------------------------------


def _select_path_chain(transporter: Any, parent_path_hex: str) -> list[dict[str, Any]]:
    """Walk a hex path two bytes at a time and return the SELECT trace."""
    trace_rows: list[dict[str, Any]] = []
    if len(parent_path_hex) == 0:
        return trace_rows
    if len(parent_path_hex) % 4 != 0:
        raise ValueError("parent_path must be 2-byte aligned (each FID = 4 hex chars).")
    offset = 0
    while offset < len(parent_path_hex):
        chunk = parent_path_hex[offset:offset + 4]
        apdu = f"00A4000402{chunk}"
        _data, sw1, sw2 = transporter.transmit(apdu, silent=True)
        ok, label = _classify_sw(sw1, sw2)
        trace_rows.append({"fid": chunk, "sw": f"{sw1:02X}{sw2:02X}", "ok": ok, "status": label})
        if not ok:
            raise ValueError(f"SELECT {chunk} failed: {label}")
        offset += 4
    return trace_rows


# ETSI TS 102 222 §6 — file type selector enum shared by the FCP builder
# below and the ``scp03.fs_build_fcp`` GUI wizard. Values are the labels
# the GUI drop-down exposes and the strings the wizard step emits.
_FS_TYPE_DF = "DF_ADF"
_FS_TYPE_TRANSPARENT_EF = "TRANSPARENT_EF"
_FS_TYPE_LINEAR_FIXED_EF = "LINEAR_FIXED_EF"
_FS_FILE_TYPES = (_FS_TYPE_DF, _FS_TYPE_TRANSPARENT_EF, _FS_TYPE_LINEAR_FIXED_EF)


def _build_fcp_template_fields(
    *,
    file_type: str,
    full_path: str,
    sec_attr_hex: str = "",
    file_size_hex: str = "",
    aid_hex: str = "",
    c6_hex: str = "",
    sfi_hex: str = "",
    rec_len_hex: str = "",
    num_rec_hex: str = "",
    prop_a5_hex: str = "",
) -> dict[str, Any]:
    """Build an ETSI TS 102 222 FCP template from structured fields.

    Port of ``SCP03.interface.shell_wizards._build_fcp_template`` — the
    CLI wizard operators have been using since v1. The GUI needs the same
    byte-for-byte FCP wire so the CLI and GUI drive identical CREATE FILE
    APDUs, and to keep a single source of truth for TS 102 222 layout.

    ``breakdown`` is a per-tag annotation list used by the wizard preview
    panel to render an operator-readable summary of what will hit the
    card — every CREATE FILE request is destructive, so a review step
    before firing ``00E0`` is non-negotiable.

    Parameters are strings because the GUI dispatcher forwards raw form
    values; empty strings are valid for optional slots (the CLI wizard
    uses ``"SKIP"`` for the same purpose). All hex is upper-cased and
    space-stripped via :func:`_normalize_hex`.

    Returns::

        {
            "fcp_hex":      "62...",          # full template incl. 62<len>
            "fid":          "<4 hex>",        # inner FID (tag 83 payload)
            "parent_path":  "<hex>",          # everything before the FID
            "file_size":    <int bytes>,
            "rec_len":      <int bytes, 0 when not linear>,
            "num_rec":      <int, 0 when not linear>,
            "file_type":    "DF_ADF" | ...,
            "breakdown":    [ {tag, hex, description}, ... ],
        }

    Raises ``ValueError`` on any invalid input — the dispatcher layer
    propagates that to the API error channel unchanged.
    """
    ft = str(file_type or "").strip().upper()
    if ft not in _FS_FILE_TYPES:
        raise ValueError(
            f"file_type must be one of {_FS_FILE_TYPES}, got {file_type!r}.")

    path = _normalize_hex(full_path, label="full_path")
    if len(path) < 4:
        raise ValueError("full_path must include at least a 2-byte FID.")
    if len(path) % 4 != 0:
        raise ValueError("full_path must be 2-byte aligned (4 hex chars per FID).")

    fid = path[-4:]
    parent = path[:-4]

    # Tag 83 — File identifier (always 2 bytes).
    tag_83 = f"8302{fid}"
    # Tag 8A — Life Cycle Status Integer = 0x05 (operational activated).
    # CLI wizard hard-codes this; we match the wire exactly. Operators
    # who need another LCS can use raw-FCP mode via fs_create_file.
    tag_8a = "8A0105"

    sec = _normalize_hex(sec_attr_hex, label="sec_attr_hex", allow_empty=True)

    tag_82 = ""
    tag_80_81 = ""
    tag_c6 = ""
    tag_88 = ""
    tag_84 = ""
    tag_a5 = ""

    file_size_int = 0
    rec_len_int = 0
    num_rec_int = 0

    if ft == _FS_TYPE_DF:
        # File descriptor for DF: 78 21 (DF, not shareable, structure=none).
        tag_82 = "82027821"

        size_hex = _normalize_hex(file_size_hex, label="file_size_hex")
        try:
            file_size_int = int(size_hex, 16)
        except ValueError as error:
            raise ValueError(
                f"file_size_hex: invalid integer: {error}") from error
        size_text = f"{file_size_int:04X}"
        # DF uses tag 81 (total file size / memory quota).
        tag_80_81 = f"81{len(size_text) // 2:02X}{size_text}"

        aid = _normalize_hex(aid_hex, label="aid_hex", allow_empty=True)
        if len(aid) > 0:
            tag_84 = f"84{len(aid) // 2:02X}{aid}"

        c6 = _normalize_hex(c6_hex, label="c6_hex", allow_empty=True)
        if len(c6) == 0:
            raise ValueError(
                "c6_hex (PIN Status Template DO) is required for DF/ADF.")
        # Caller hands us the complete C6 TLV — the CLI wizard does the
        # same so we don't have to second-guess the inner layout.
        tag_c6 = c6

    elif ft == _FS_TYPE_TRANSPARENT_EF:
        # Transparent EF descriptor: 41 21.
        tag_82 = "82024121"

        size_hex = _normalize_hex(file_size_hex, label="file_size_hex")
        try:
            file_size_int = int(size_hex, 16)
        except ValueError as error:
            raise ValueError(
                f"file_size_hex: invalid integer: {error}") from error
        size_text = f"{file_size_int:04X}"
        tag_80_81 = f"80{len(size_text) // 2:02X}{size_text}"

    elif ft == _FS_TYPE_LINEAR_FIXED_EF:
        rec_len_clean = _normalize_hex(rec_len_hex, label="rec_len_hex")
        num_rec_clean = _normalize_hex(num_rec_hex, label="num_rec_hex")
        try:
            rec_len_int = int(rec_len_clean, 16)
            num_rec_int = int(num_rec_clean, 16)
        except ValueError as error:
            raise ValueError(
                f"rec_len_hex/num_rec_hex: invalid integer: {error}") from error
        if rec_len_int <= 0 or num_rec_int <= 0:
            raise ValueError("rec_len / num_rec must be positive.")
        # Linear fixed EF descriptor: 42 21 <RECLEN_16>.
        tag_82 = f"82044221{rec_len_int:04X}"

        file_size_int = rec_len_int * num_rec_int
        size_text = f"{file_size_int:04X}"
        tag_80_81 = f"80{len(size_text) // 2:02X}{size_text}"

    # Short File Identifier (tag 88) — EF only. Matches the CLI which
    # emits 88 00 when the user skips the SFI step (SFI = none).
    if ft in (_FS_TYPE_TRANSPARENT_EF, _FS_TYPE_LINEAR_FIXED_EF):
        sfi = _normalize_hex(sfi_hex, label="sfi_hex", allow_empty=True)
        if len(sfi) == 0:
            tag_88 = "8800"
        elif len(sfi) != 2:
            raise ValueError("sfi_hex must be exactly 1 byte (2 hex chars).")
        else:
            tag_88 = f"8801{sfi}"

    # Tag A5 — Proprietary Info (optional inner bytes; we wrap them).
    prop = _normalize_hex(prop_a5_hex, label="prop_a5_hex", allow_empty=True)
    if len(prop) > 0:
        tag_a5 = f"A5{len(prop) // 2:02X}{prop}"

    # Preserve the CLI wizard's concatenation order precisely — even
    # though card parsers MUST be tag-order-agnostic, matching the CLI
    # wire keeps test vectors comparable and avoids surprises.
    fcp_content = (
        tag_82
        + tag_83
        + tag_84
        + tag_8a
        + sec
        + tag_80_81
        + tag_88
        + tag_c6
        + tag_a5
    )
    fcp_len = len(fcp_content) // 2
    if fcp_len > 0x7F:
        # CLI wizard uses short-form length; flag anything that would
        # require BER long-form so the operator notices rather than
        # silently emitting a broken template.
        raise ValueError(
            f"FCP body is {fcp_len} bytes — exceeds short-form length (127). "
            "Trim the security attribute / C6 / proprietary TLVs or use "
            "the raw-FCP mode.")
    fcp_hex = f"62{fcp_len:02X}{fcp_content}"

    breakdown: list[dict[str, str]] = []
    if tag_82:
        breakdown.append({
            "tag": "82",
            "hex": tag_82,
            "description": "File descriptor byte(s)",
        })
    breakdown.append({
        "tag": "83",
        "hex": tag_83,
        "description": f"File identifier = {fid}",
    })
    if tag_84:
        breakdown.append({
            "tag": "84",
            "hex": tag_84,
            "description": "ADF AID",
        })
    breakdown.append({
        "tag": "8A",
        "hex": tag_8a,
        "description": "Life Cycle Status = 05 (operational / activated)",
    })
    if sec:
        breakdown.append({
            "tag": sec[:2] if len(sec) >= 2 else "??",
            "hex": sec,
            "description": "Security attribute TLV (pass-through)",
        })
    if tag_80_81:
        hdr = tag_80_81[:2]
        descr = (
            "Total file / DF memory size" if hdr == "81"
            else "Transparent EF body size"
        )
        breakdown.append({"tag": hdr, "hex": tag_80_81, "description": descr})
    if tag_88:
        breakdown.append({
            "tag": "88",
            "hex": tag_88,
            "description": "Short File Identifier",
        })
    if tag_c6:
        breakdown.append({
            "tag": "C6",
            "hex": tag_c6,
            "description": "PIN Status Template DO",
        })
    if tag_a5:
        breakdown.append({
            "tag": "A5",
            "hex": tag_a5,
            "description": "Proprietary Information",
        })

    return {
        "fcp_hex": fcp_hex,
        "fid": fid,
        "parent_path": parent,
        "file_size": file_size_int,
        "rec_len": rec_len_int,
        "num_rec": num_rec_int,
        "file_type": ft,
        "breakdown": breakdown,
    }


def _dispatch_fs_build_fcp(
    ctx: ActionContext,
    *,
    file_type: Any = None,
    full_path: Any = None,
    sec_attr_hex: Any = None,
    file_size_hex: Any = None,
    aid_hex: Any = None,
    c6_hex: Any = None,
    sfi_hex: Any = None,
    rec_len_hex: Any = None,
    num_rec_hex: Any = None,
    prop_a5_hex: Any = None,
) -> dict[str, Any]:
    """Build an ETSI TS 102 222 FCP template offline (no card transmit).

    The GUI CREATE FILE wizard calls this to render a preview of the TLV
    wire-format + a per-tag breakdown before the operator confirms the
    destructive ``00E0`` CREATE FILE APDU. No session or card is needed.
    """
    return _build_fcp_template_fields(
        file_type=str(file_type or ""),
        full_path=str(full_path or ""),
        sec_attr_hex=str(sec_attr_hex or ""),
        file_size_hex=str(file_size_hex or ""),
        aid_hex=str(aid_hex or ""),
        c6_hex=str(c6_hex or ""),
        sfi_hex=str(sfi_hex or ""),
        rec_len_hex=str(rec_len_hex or ""),
        num_rec_hex=str(num_rec_hex or ""),
        prop_a5_hex=str(prop_a5_hex or ""),
    )


def _dispatch_fs_create_file(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    fcp_hex: Any = None,
    parent_path: Any = None,
) -> dict[str, Any]:
    """ETSI TS 102 222 CREATE FILE (00E0) with raw FCP template."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    fcp = _normalize_hex(fcp_hex, label="fcp_hex")
    select_trace: list[dict[str, Any]] = []
    if parent_path is not None and len(str(parent_path).strip()) > 0:
        parent_hex = _normalize_hex(parent_path, label="parent_path")
        select_trace = _select_path_chain(transporter, parent_hex)

    apdu = f"00E00000{len(fcp) // 2:02X}{fcp}"
    data, sw1, sw2 = transporter.transmit(apdu, silent=True)
    ok, label = _classify_sw(sw1, sw2)
    return {
        "session_id": sid,
        "ok": ok,
        "status": label,
        "sw": f"{sw1:02X}{sw2:02X}",
        "apdu": apdu,
        "fcp": fcp,
        "parent_select_trace": select_trace,
        "response_hex": (data or b"").hex().upper(),
    }


def _dispatch_fs_delete_file(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    fid: Any = None,
    parent_path: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """ETSI TS 102 222 DELETE FILE (00E4) — destroys EF/DF identified by FID."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    confirm_text = str(confirm or "").strip().upper()
    if confirm_text != "DELETE":
        raise ValueError("confirm=\"DELETE\" is required — DELETE FILE is irreversible.")

    fid_hex = _normalize_hex(fid, label="fid")
    if len(fid_hex) != 4:
        raise ValueError("fid must be exactly 2 bytes (4 hex chars).")

    select_trace: list[dict[str, Any]] = []
    if parent_path is not None and len(str(parent_path).strip()) > 0:
        parent_hex = _normalize_hex(parent_path, label="parent_path")
        select_trace = _select_path_chain(transporter, parent_hex)

    apdu = f"00E4000002{fid_hex}"
    _data, sw1, sw2 = transporter.transmit(apdu, silent=True)
    ok, label = _classify_sw(sw1, sw2)
    return {
        "session_id": sid,
        "ok": ok,
        "status": label,
        "sw": f"{sw1:02X}{sw2:02X}",
        "apdu": apdu,
        "fid": fid_hex,
        "parent_select_trace": select_trace,
    }


def _dispatch_fs_resize(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_fid: Any = None,
    new_file_size: Any = None,
    new_total_size: Any = None,
    parent_path: Any = None,
) -> dict[str, Any]:
    """ETSI TS 102 222 RESIZE FILE (80D4) with FCP tag-83 + tag-80 / tag-81."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    fid_hex = _normalize_hex(target_fid, label="target_fid")
    if len(fid_hex) != 4:
        raise ValueError("target_fid must be exactly 2 bytes (4 hex chars).")

    tag_83 = f"8302{fid_hex}"
    tag_80 = ""
    tag_81 = ""

    if new_file_size is not None and len(str(new_file_size).strip()) > 0:
        size_hex = _normalize_hex(new_file_size, label="new_file_size")
        try:
            size_int = int(size_hex, 16)
        except ValueError as error:
            raise ValueError(f"invalid new_file_size hex: {error}") from error
        size_text = f"{size_int:04X}"
        tag_80 = f"80{len(size_text) // 2:02X}{size_text}"

    if new_total_size is not None and len(str(new_total_size).strip()) > 0:
        size_hex = _normalize_hex(new_total_size, label="new_total_size")
        try:
            size_int = int(size_hex, 16)
        except ValueError as error:
            raise ValueError(f"invalid new_total_size hex: {error}") from error
        size_text = f"{size_int:04X}"
        tag_81 = f"81{len(size_text) // 2:02X}{size_text}"

    if len(tag_80) == 0 and len(tag_81) == 0:
        raise ValueError("at least one of new_file_size (tag 80) or new_total_size (tag 81) is required.")

    select_trace: list[dict[str, Any]] = []
    if parent_path is not None and len(str(parent_path).strip()) > 0:
        parent_hex = _normalize_hex(parent_path, label="parent_path")
        select_trace = _select_path_chain(transporter, parent_hex)

    fcp_content = tag_83 + tag_80 + tag_81
    fcp_hex = f"62{len(fcp_content) // 2:02X}{fcp_content}"
    apdu = f"80D40000{len(fcp_hex) // 2:02X}{fcp_hex}"
    data, sw1, sw2 = transporter.transmit(apdu, silent=True)
    ok, label = _classify_sw(sw1, sw2)
    return {
        "session_id": sid,
        "ok": ok,
        "status": label,
        "sw": f"{sw1:02X}{sw2:02X}",
        "apdu": apdu,
        "fcp": fcp_hex,
        "target_fid": fid_hex,
        "tag_80": tag_80,
        "tag_81": tag_81,
        "parent_select_trace": select_trace,
        "response_hex": (data or b"").hex().upper(),
    }


def _dispatch_fs_lifecycle(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    op: Any = None,
    fid: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """Single dispatcher for ACTIVATE / DEACTIVATE / TERMINATE-DF / TERMINATE-EF."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    op_norm = str(op or "").strip().upper()
    op_map = {
        "ACTIVATE": ("00440000", False),
        "DEACTIVATE": ("00040000", False),
        "TERMINATE_DF": ("00E60000", True),
        "TERMINATE_EF": ("00E80000", True),
    }
    if op_norm not in op_map:
        raise ValueError(f"unsupported op={op_norm!r}; expected one of {sorted(op_map)}.")

    head, irreversible = op_map[op_norm]
    if irreversible:
        confirm_text = str(confirm or "").strip().upper()
        if confirm_text != "TERMINATE":
            raise ValueError(
                "confirm=\"TERMINATE\" is required — TERMINATE-DF / TERMINATE-EF is irreversible."
            )

    fid_hex = ""
    if fid is not None and len(str(fid).strip()) > 0:
        fid_hex = _normalize_hex(fid, label="fid")
        if len(fid_hex) != 4:
            raise ValueError("fid must be exactly 2 bytes (4 hex chars).")

    if len(fid_hex) > 0:
        apdu = f"{head[:6]}02{fid_hex}"
    else:
        apdu = head + "00"

    _data, sw1, sw2 = transporter.transmit(apdu, silent=True)
    ok, label = _classify_sw(sw1, sw2)
    return {
        "session_id": sid,
        "ok": ok,
        "status": label,
        "sw": f"{sw1:02X}{sw2:02X}",
        "apdu": apdu,
        "op": op_norm,
        "fid": fid_hex,
    }


def _dispatch_fs_search_record(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target: Any = None,
    search_hex: Any = None,
) -> dict[str, Any]:
    """ETSI TS 102 221 SEARCH RECORD (00A2) — find record matching needle."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    needle = _normalize_hex(search_hex, label="search_hex")
    select_trace: list[dict[str, Any]] = []
    target_hex = ""
    if target is not None and len(str(target).strip()) > 0:
        target_hex = _normalize_hex(target, label="target")
        select_trace = _select_path_chain(transporter, target_hex)

    apdu = f"00A20104{len(needle) // 2:02X}{needle}"
    data, sw1, sw2 = transporter.transmit(apdu, silent=True)
    ok, label = _classify_sw(sw1, sw2)
    return {
        "session_id": sid,
        "ok": ok,
        "status": label,
        "sw": f"{sw1:02X}{sw2:02X}",
        "apdu": apdu,
        "search_hex": needle,
        "target": target_hex,
        "select_trace": select_trace,
        "response_hex": (data or b"").hex().upper(),
    }


def _dispatch_fs_suspend_uicc(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """ETSI TS 102 221 SUSPEND UICC (8076)."""
    session, transporter, sid = _get_scp03_session(session_id)
    _require_auth_session(transporter)

    confirm_text = str(confirm or "").strip().upper()
    if confirm_text != "SUSPEND":
        raise ValueError("confirm=\"SUSPEND\" is required — UICC will go to low-power state.")

    _data, sw1, sw2 = transporter.transmit("8076000000", silent=True)
    ok, label = _classify_sw(sw1, sw2)
    return {
        "session_id": sid,
        "ok": ok,
        "status": label,
        "sw": f"{sw1:02X}{sw2:02X}",
        "apdu": "8076000000",
    }


# --- C-5: MANAGE-PIN --------------------------------------------------


def _pad_pin_ascii(pin: str) -> str:
    """ISO 7816-4 ASCII-PIN padded with 0xFF to 8 bytes — uppercase hex."""
    raw = str(pin or "").encode("ascii")
    if len(raw) > 8:
        return raw[:8].hex().upper()
    return (raw + b"\xFF" * (8 - len(raw))).hex().upper()


def _dispatch_manage_pin(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    op: Any = None,
    pin_ref: Any = "01",
    pin: Any = None,
    new_pin: Any = None,
    puk: Any = None,
    confirm: Any = None,
) -> dict[str, Any]:
    """VERIFY / CHANGE / DISABLE / ENABLE / UNBLOCK PIN — single dispatcher."""
    session, transporter, sid = _get_scp03_session(session_id)

    op_norm = str(op or "").strip().upper()
    if op_norm not in ("VERIFY", "CHANGE", "DISABLE", "ENABLE", "UNBLOCK"):
        raise ValueError(f"unsupported op={op_norm!r}; expected VERIFY/CHANGE/DISABLE/ENABLE/UNBLOCK.")
    if op_norm in ("DISABLE", "UNBLOCK") and bool(confirm) is False:
        raise ValueError(f"confirm must be true — {op_norm} can block the PIN.")

    ref_byte = _parse_hex_byte(pin_ref or "01", label="pin_ref")

    if op_norm == "VERIFY":
        if pin is None or len(str(pin)) == 0:
            raise ValueError("pin is required for VERIFY.")
        payload = _pad_pin_ascii(pin)
        apdu = f"002000{ref_byte:02X}08{payload}"
    elif op_norm == "CHANGE":
        if pin is None or new_pin is None:
            raise ValueError("pin and new_pin are required for CHANGE.")
        payload = _pad_pin_ascii(pin) + _pad_pin_ascii(new_pin)
        apdu = f"002400{ref_byte:02X}10{payload}"
    elif op_norm == "DISABLE":
        if pin is None:
            raise ValueError("pin is required for DISABLE.")
        payload = _pad_pin_ascii(pin)
        apdu = f"002600{ref_byte:02X}08{payload}"
    elif op_norm == "ENABLE":
        if pin is None:
            raise ValueError("pin is required for ENABLE.")
        payload = _pad_pin_ascii(pin)
        apdu = f"002800{ref_byte:02X}08{payload}"
    else:  # UNBLOCK
        if puk is None or new_pin is None:
            raise ValueError("puk and new_pin are required for UNBLOCK.")
        payload = _pad_pin_ascii(puk) + _pad_pin_ascii(new_pin)
        apdu = f"002C00{ref_byte:02X}10{payload}"

    _data, sw1, sw2 = transporter.transmit(apdu, silent=True)
    ok, label = _classify_sw(sw1, sw2)

    attempts_remaining: int | None = None
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        attempts_remaining = sw2 & 0x0F
    elif ok and op_norm == "VERIFY":
        attempts_remaining = None  # card resets the counter on success

    return {
        "session_id": sid,
        "ok": ok,
        "status": label,
        "sw": f"{sw1:02X}{sw2:02X}",
        "apdu": apdu,
        "op": op_norm,
        "pin_ref": f"{ref_byte:02X}",
        "attempts_remaining": attempts_remaining,
    }


# --- C-5: MANAGE-CHANNEL ----------------------------------------------


def _dispatch_manage_channel(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    op: Any = None,
    channel: Any = None,
) -> dict[str, Any]:
    """GP MANAGE CHANNEL (0070) — open or close a logical channel."""
    session, transporter, sid = _get_scp03_session(session_id)

    op_norm = str(op or "").strip().upper()
    if op_norm == "OPEN":
        apdu = "0070000001"
    elif op_norm == "CLOSE":
        if channel is None or len(str(channel).strip()) == 0:
            raise ValueError("channel is required for CLOSE.")
        ch_byte = _parse_hex_byte(channel, label="channel")
        apdu = f"007080{ch_byte:02X}00"
    else:
        raise ValueError(f"unsupported op={op_norm!r}; expected OPEN or CLOSE.")

    data, sw1, sw2 = transporter.transmit(apdu, silent=True)
    ok, label = _classify_sw(sw1, sw2)

    assigned_channel = None
    if op_norm == "OPEN" and ok and data:
        assigned_channel = data.hex().upper()

    return {
        "session_id": sid,
        "ok": ok,
        "status": label,
        "sw": f"{sw1:02X}{sw2:02X}",
        "apdu": apdu,
        "op": op_norm,
        "assigned_channel": assigned_channel,
    }


# --- C-5: RUN-AUTH (live AUTHENTICATE) --------------------------------


def _decode_umts_auth_response(data: bytes) -> dict[str, Any]:
    """Parse a UMTS AUTHENTICATE response (DB / DC tag) into a dict."""
    out: dict[str, Any] = {"raw_hex": data.hex().upper()}
    if len(data) == 0:
        out["status"] = "(empty)"
        return out

    if data[0] == 0xDC:
        out["status"] = "Synchronization failure (AUTS)"
        if len(data) >= 2:
            out["auts"] = data[2:].hex().upper()
        return out

    if data[0] == 0xDB:
        out["status"] = "Authentication successful"
        idx = 1
        try:
            res_len = data[idx]; idx += 1
            out["res"] = data[idx:idx + res_len].hex().upper(); idx += res_len
            if idx < len(data):
                ck_len = data[idx]; idx += 1
                out["ck"] = data[idx:idx + ck_len].hex().upper(); idx += ck_len
            if idx < len(data):
                ik_len = data[idx]; idx += 1
                out["ik"] = data[idx:idx + ik_len].hex().upper(); idx += ik_len
            if idx < len(data):
                kc_len = data[idx]; idx += 1
                out["kc"] = data[idx:idx + kc_len].hex().upper()
        except IndexError:
            out["parse_warning"] = "Truncated UMTS authenticate response."
        return out

    if len(data) >= 12:
        out["status"] = "GSM SRES + Kc"
        out["sres"] = data[:4].hex().upper()
        out["kc"] = data[4:12].hex().upper()
        return out

    out["status"] = f"Unknown response ({len(data)} bytes)"
    return out


def _dispatch_run_auth_live(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    context: Any = "USIM",
    rand: Any = None,
    autn: Any = None,
) -> dict[str, Any]:
    """Live AUTHENTICATE (0088) on USIM/ISIM/GSM with RAND (+ AUTN for UMTS)."""
    session, transporter, sid = _get_scp03_session(session_id)

    ctx_norm = str(context or "USIM").strip().upper()
    if ctx_norm not in ("GSM", "USIM", "ISIM"):
        raise ValueError(f"context must be GSM / USIM / ISIM (got {ctx_norm!r}).")

    rand_hex = _normalize_hex(rand, label="rand")
    if len(rand_hex) != 32:
        raise ValueError("rand must be 16 bytes (32 hex chars).")

    autn_hex = ""
    if ctx_norm in ("USIM", "ISIM"):
        if autn is None or len(str(autn).strip()) == 0:
            raise ValueError(f"autn is required for {ctx_norm} AUTHENTICATE.")
        autn_hex = _normalize_hex(autn, label="autn")
        if len(autn_hex) != 32:
            raise ValueError("autn must be 16 bytes (32 hex chars).")
        payload = f"10{rand_hex}10{autn_hex}"
        apdu = f"00880081{len(payload) // 2:02X}{payload}00"
    else:
        apdu = f"0088008010{rand_hex}00"

    data, sw1, sw2 = transporter.transmit(apdu, silent=True)
    ok, label = _classify_sw(sw1, sw2)
    parsed: dict[str, Any] = {}
    if data is not None:
        parsed = _decode_umts_auth_response(data)
    return {
        "session_id": sid,
        "ok": ok,
        "status": label,
        "sw": f"{sw1:02X}{sw2:02X}",
        "apdu": apdu,
        "context": ctx_norm,
        "rand": rand_hex,
        "autn": autn_hex or None,
        "response": parsed,
    }


# --- C-5 ActionSpecs ---------------------------------------------------


PUT_KEY_SPEC = ActionSpec(
    id="scp03.put_key",
    subsystem="SCP03",
    title="PUT KEY",
    description=(
        "GP PUT KEY (GPCS 11.8) — install or replace a keyset on the active "
        "Security Domain. Wrong KVN/KID overwrites the wrong keyset and can "
        "permanently brick the card. Requires confirm=\"PUT-KEY\"."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="new_kvn", label="New KVN (hex)", kind="hex", required=True,
                    placeholder="01", help="KVN of the new keyset (1 byte)."),
        ActionField(name="new_key_id", label="New Key ID (hex)", kind="hex", required=True,
                    placeholder="01", help="First Key ID in the new triplet (1 byte)."),
        ActionField(name="old_kvn", label="Old KVN (hex)", kind="hex", required=False,
                    default="00", help="KVN to replace; 00 = add new."),
        ActionField(name="enc_key", label="ENC key (hex)", kind="hex", required=True,
                    help="32 / 48 / 64 hex chars (16 / 24 / 32 bytes)."),
        ActionField(name="mac_key", label="MAC key (hex)", kind="hex", required=True,
                    help="32 / 48 / 64 hex chars (16 / 24 / 32 bytes)."),
        ActionField(name="dek_key", label="DEK key (hex)", kind="hex", required=True,
                    help="32 / 48 / 64 hex chars (16 / 24 / 32 bytes)."),
        ActionField(name="algorithm", label="Algorithm", kind="enum",
                    choices=("AES", "3DES"), default="AES",
                    help="AES = 0x88 key-type byte; 3DES = 0x82."),
        ActionField(name="confirm", label="Confirm", kind="string", required=True,
                    placeholder="type PUT-KEY", help="Type PUT-KEY to proceed."),
    ),
    output_kind="json",
    dispatcher=_dispatch_put_key,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "keys", "destructive"),
)


INSTALL_CAP_SPEC = ActionSpec(
    id="scp03.install_cap",
    subsystem="SCP03",
    title="Install CAP file",
    description=(
        "GP INSTALL [for load] + LOAD + INSTALL [for install]. Parses the "
        "CAP file, walks every required block, and instantiates the first "
        "applet (or a custom AID via target_app_aid)."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="cap_path", label="CAP file path", kind="path", required=True,
                    help="Absolute path to the .cap / .ijc file."),
        ActionField(name="privileges", label="Privileges (hex)", kind="hex",
                    default="00", help="GP privileges byte(s) for the new applet."),
        ActionField(name="install_params", label="Install params (hex)", kind="hex",
                    default="C900",
                    help="GP install parameters TLV (default C900 = empty)."),
        ActionField(name="instantiate", label="Instantiate after load", kind="bool",
                    default=True, help="Untick to LOAD only (library packages)."),
        ActionField(name="target_app_aid", label="Override applet AID (hex)", kind="hex",
                    required=False,
                    help="Use a different applet AID than the first one in the CAP."),
        ActionField(name="target_module_aid", label="Override module AID (hex)", kind="hex",
                    required=False),
        ActionField(name="load_chunk_size", label="LOAD chunk size", kind="int",
                    required=False, placeholder="240",
                    help="Bytes per LOAD block (1..255). Auto-clamped to 239 under SCP secure-load."),
    ),
    output_kind="json",
    dispatcher=_dispatch_install_cap,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "install", "destructive"),
)


INSTALL_APP_SPEC = ActionSpec(
    id="scp03.install_app",
    subsystem="SCP03",
    title="Install applet (already loaded)",
    description=(
        "GP INSTALL [for install] (P1=04) / [for install + make selectable] (P1=0C)."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="package_aid", label="Package AID", kind="hex", required=True),
        ActionField(name="applet_aid", label="Applet AID", kind="hex", required=True),
        ActionField(name="module_aid", label="Module AID", kind="hex", required=False,
                    help="Defaults to applet_aid when blank."),
        ActionField(name="privileges", label="Privileges (hex)", kind="hex", default="00"),
        ActionField(name="install_params", label="Install params (hex)", kind="hex",
                    default="C900"),
        ActionField(name="make_selectable", label="Make selectable", kind="bool", default=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_install_app,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "install"),
)


INSTALL_MAKE_SELECTABLE_SPEC = ActionSpec(
    id="scp03.install_make_selectable",
    subsystem="SCP03",
    title="Install [for make selectable]",
    description="GP INSTALL [for make selectable] (P1=08) — unlock instance for SELECT.",
    inputs=(
        _SESSION_FIELD,
        ActionField(name="aid", label="AID", kind="hex", required=True),
        ActionField(name="privileges", label="Privileges (hex)", kind="hex", default="00"),
        ActionField(name="params", label="Params (hex)", kind="hex", required=False),
        ActionField(name="token", label="Token (hex)", kind="hex", required=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_install_make_selectable,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "install"),
)


INSTALL_EXTRADITION_SPEC = ActionSpec(
    id="scp03.install_extradition",
    subsystem="SCP03",
    title="Install [for extradition]",
    description="GP INSTALL [for extradition] (P1=10) — re-bind instance to a target SD.",
    inputs=(
        _SESSION_FIELD,
        ActionField(name="aid", label="Instance AID", kind="hex", required=True),
        ActionField(name="sd_aid", label="Target SD AID", kind="hex", required=True),
        ActionField(name="token", label="Token (hex)", kind="hex", required=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_install_extradition,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "install"),
)


INSTALL_PERSONALIZATION_SPEC = ActionSpec(
    id="scp03.install_personalization",
    subsystem="SCP03",
    title="Install [for personalization]",
    description=(
        "GP INSTALL [for personalization] (P1=20) — open personalization "
        "channel for follow-up STORE DATA traffic."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="aid", label="AID", kind="hex", required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_install_personalization,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "install", "perso"),
)


INSTALL_REGISTRY_UPDATE_SPEC = ActionSpec(
    id="scp03.install_registry_update",
    subsystem="SCP03",
    title="Install [for registry update]",
    description="GP INSTALL [for registry update] (P1=40) — change privileges / params.",
    inputs=(
        _SESSION_FIELD,
        ActionField(name="aid", label="AID", kind="hex", required=True),
        ActionField(name="privileges", label="Privileges (hex)", kind="hex", default="00"),
        ActionField(name="params", label="Params (hex)", kind="hex", required=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_install_registry_update,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "registry"),
)


FS_BUILD_FCP_SPEC = ActionSpec(
    id="scp03.fs_build_fcp",
    subsystem="SCP03",
    title="FS — build FCP template (preview)",
    description=(
        "Offline builder for ETSI TS 102 222 FCP templates. Accepts the "
        "same structured fields the CLI wizard asks for "
        "(``_build_fcp_template``) and returns the composed hex + a "
        "per-tag breakdown. No card transmit — used by the GUI CREATE "
        "FILE wizard to render a preview before the destructive 00E0 "
        "APDU is fired."
    ),
    inputs=(
        ActionField(name="file_type", label="File type", kind="enum",
                    required=True,
                    choices=("DF_ADF", "TRANSPARENT_EF", "LINEAR_FIXED_EF")),
        ActionField(name="full_path", label="Full hex path", kind="hex",
                    required=True, placeholder="3F007F105F01",
                    help="Last 2 bytes = new FID; preceding bytes = parent "
                         "path (walked by SELECT before CREATE)."),
        ActionField(name="sec_attr_hex", label="Security attribute TLV",
                    kind="hex", required=False,
                    help="Fully-encoded tag 8C / 8B / AB TLV. "
                         "Typically required by the SD — see ETSI TS 102 221 §9.2."),
        ActionField(name="file_size_hex", label="File size (hex bytes)",
                    kind="hex", required=False,
                    help="DF: memory quota (tag 81). "
                         "Transparent EF: body size (tag 80). "
                         "Linear EF: computed as rec_len × num_rec."),
        ActionField(name="aid_hex", label="ADF AID (tag 84)", kind="hex",
                    required=False,
                    help="DF/ADF only. Leave empty for a plain DF."),
        ActionField(name="c6_hex", label="PIN Status Template DO (tag C6)",
                    kind="hex", required=False,
                    help="DF/ADF only. REQUIRED for DF/ADF — hand the "
                         "entire TLV (C6 <len> <value>)."),
        ActionField(name="sfi_hex", label="Short File Identifier (hex)",
                    kind="hex", required=False,
                    help="EF only, exactly 1 byte. "
                         "Empty → emit 88 00 (no SFI)."),
        ActionField(name="rec_len_hex", label="Record length (hex)",
                    kind="hex", required=False,
                    help="Linear Fixed EF only. Bytes per record."),
        ActionField(name="num_rec_hex", label="Number of records (hex)",
                    kind="hex", required=False,
                    help="Linear Fixed EF only."),
        ActionField(name="prop_a5_hex", label="Proprietary info (tag A5)",
                    kind="hex", required=False,
                    help="Optional A5 inner bytes (without outer tag/length)."),
    ),
    output_kind="json",
    dispatcher=_dispatch_fs_build_fcp,
    requires_card=False,
    tags=("fs", "builder", "offline", "wizard"),
)


FS_CREATE_FILE_SPEC = ActionSpec(
    id="scp03.fs_create_file",
    subsystem="SCP03",
    title="FS — CREATE FILE",
    description=(
        "ETSI TS 102 222 CREATE FILE (00E0). Pass a complete FCP template "
        "(starting with tag 62) and an optional parent path to walk first. "
        "The GUI wizard composes the FCP via ``scp03.fs_build_fcp`` — raw "
        "mode here stays available for scripting / pasted templates."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="fcp_hex", label="FCP template (hex)", kind="hex", required=True,
                    placeholder="62198202412183020001A50FC10101...",
                    help="Full TLV-encoded FCP including outer tag 62."),
        ActionField(name="parent_path", label="Parent path (hex, 2-byte FIDs)",
                    kind="hex", required=False,
                    placeholder="3F007F10",
                    help="Optional path to SELECT before sending CREATE."),
    ),
    output_kind="json",
    dispatcher=_dispatch_fs_create_file,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "fs", "destructive"),
)


FS_DELETE_FILE_SPEC = ActionSpec(
    id="scp03.fs_delete_file",
    subsystem="SCP03",
    title="FS — DELETE FILE",
    description="ETSI TS 102 222 DELETE FILE (00E4). Requires confirm=\"DELETE\".",
    inputs=(
        _SESSION_FIELD,
        ActionField(name="fid", label="Target FID (4 hex)", kind="hex", required=True,
                    placeholder="6F07"),
        ActionField(name="parent_path", label="Parent path (hex, optional)", kind="hex",
                    required=False, placeholder="3F007F10"),
        ActionField(name="confirm", label="Confirm", kind="string", required=True,
                    placeholder="type DELETE"),
    ),
    output_kind="json",
    dispatcher=_dispatch_fs_delete_file,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "fs", "destructive"),
)


FS_RESIZE_SPEC = ActionSpec(
    id="scp03.fs_resize",
    subsystem="SCP03",
    title="FS — RESIZE FILE",
    description="ETSI TS 102 222 RESIZE FILE (80D4) — change EF size in place.",
    inputs=(
        _SESSION_FIELD,
        ActionField(name="target_fid", label="Target FID (4 hex)", kind="hex", required=True,
                    placeholder="6F07"),
        ActionField(name="new_file_size", label="New file size (hex)", kind="hex",
                    required=False, placeholder="0040",
                    help="Tag 80 — new transparent body size in bytes."),
        ActionField(name="new_total_size", label="New total size (hex)", kind="hex",
                    required=False, placeholder="0080",
                    help="Tag 81 — new total file size."),
        ActionField(name="parent_path", label="Parent path (hex, optional)", kind="hex",
                    required=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_fs_resize,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "fs", "destructive"),
)


FS_LIFECYCLE_SPEC = ActionSpec(
    id="scp03.fs_lifecycle",
    subsystem="SCP03",
    title="FS — lifecycle (activate / deactivate / terminate)",
    description=(
        "ETSI TS 102 221 / 222 lifecycle commands: ACTIVATE (0044), "
        "DEACTIVATE (0004), TERMINATE-DF (00E6), TERMINATE-EF (00E8). "
        "TERMINATE operations require confirm=\"TERMINATE\"."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="op", label="Operation", kind="enum", required=True,
                    choices=("ACTIVATE", "DEACTIVATE", "TERMINATE_DF", "TERMINATE_EF")),
        ActionField(name="fid", label="Target FID (4 hex, optional for current EF)",
                    kind="hex", required=False),
        ActionField(name="confirm", label="Confirm (for TERMINATE)", kind="string",
                    required=False, placeholder="type TERMINATE for terminate ops"),
    ),
    output_kind="json",
    dispatcher=_dispatch_fs_lifecycle,
    requires_card=True,
    requires_auth=True,
    tags=("mutation", "fs", "lcs"),
)


FS_SEARCH_RECORD_SPEC = ActionSpec(
    id="scp03.fs_search_record",
    subsystem="SCP03",
    title="FS — SEARCH RECORD",
    description="ETSI TS 102 221 SEARCH RECORD (00A2) — find record matching a hex needle.",
    inputs=(
        _SESSION_FIELD,
        ActionField(name="target", label="Target EF path (hex, optional)", kind="hex",
                    required=False, help="Walk this path before searching."),
        ActionField(name="search_hex", label="Search needle (hex)", kind="hex",
                    required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_fs_search_record,
    requires_card=True,
    requires_auth=True,
    tags=("fs", "search"),
)


FS_SUSPEND_UICC_SPEC = ActionSpec(
    id="scp03.fs_suspend_uicc",
    subsystem="SCP03",
    title="FS — SUSPEND UICC",
    description="ETSI TS 102 221 SUSPEND UICC (8076). Requires confirm=\"SUSPEND\".",
    inputs=(
        _SESSION_FIELD,
        ActionField(name="confirm", label="Confirm", kind="string", required=True,
                    placeholder="type SUSPEND"),
    ),
    output_kind="json",
    dispatcher=_dispatch_fs_suspend_uicc,
    requires_card=True,
    requires_auth=True,
    tags=("fs", "lcs", "destructive"),
)


MANAGE_PIN_SPEC = ActionSpec(
    id="scp03.manage_pin",
    subsystem="SCP03",
    title="Manage PIN",
    description=(
        "PIN lifecycle: VERIFY (0020) / CHANGE (0024) / DISABLE (0026) / "
        "ENABLE (0028) / UNBLOCK (002C). PINs are ASCII-padded with 0xFF. "
        "DISABLE and UNBLOCK require confirm — they can block the PIN."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="op", label="Operation", kind="enum", required=True,
                    choices=("VERIFY", "CHANGE", "DISABLE", "ENABLE", "UNBLOCK")),
        ActionField(name="pin_ref", label="PIN reference (hex)", kind="hex",
                    default="01", help="01 = PIN1, 02 = PIN2, 81 = ADM1, …"),
        ActionField(name="pin", label="PIN (ASCII)", kind="string", required=False,
                    placeholder="1234"),
        ActionField(name="new_pin", label="New PIN (ASCII)", kind="string", required=False,
                    placeholder="(for CHANGE / UNBLOCK)"),
        ActionField(name="puk", label="PUK (ASCII)", kind="string", required=False,
                    placeholder="(for UNBLOCK)"),
        ActionField(
            name="confirm",
            label="I understand DISABLE/UNBLOCK can block the PIN",
            kind="bool",
            required=False,
            default=False,
            help="Required when the operation is DISABLE or UNBLOCK.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_manage_pin,
    requires_card=True,
    tags=("pin", "auth"),
)


MANAGE_CHANNEL_SPEC = ActionSpec(
    id="scp03.manage_channel",
    subsystem="SCP03",
    title="MANAGE CHANNEL",
    description=(
        "GP MANAGE CHANNEL (0070) — open a new logical channel (P1=00, "
        "Lc=01) or close an existing one (P1=80, P2=channel)."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="op", label="Operation", kind="enum", required=True,
                    choices=("OPEN", "CLOSE")),
        ActionField(name="channel", label="Channel (hex, for CLOSE)", kind="hex",
                    required=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_manage_channel,
    requires_card=True,
    tags=("channel",),
)


RUN_AUTH_LIVE_SPEC = ActionSpec(
    id="scp03.run_auth_live",
    subsystem="SCP03",
    title="Run AUTHENTICATE (live)",
    description=(
        "Live AUTHENTICATE (0088) on USIM (P2=81) / ISIM (P2=81) / GSM "
        "(P2=80). Pass RAND (16 bytes) and AUTN (16 bytes for USIM/ISIM). "
        "Response is parsed into RES / CK / IK / Kc or AUTS on resync."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="context", label="Context", kind="enum", required=True,
                    choices=("USIM", "ISIM", "GSM"), default="USIM"),
        ActionField(name="rand", label="RAND (32 hex)", kind="hex", required=True),
        ActionField(name="autn", label="AUTN (32 hex, for USIM/ISIM)", kind="hex",
                    required=False),
    ),
    output_kind="json",
    dispatcher=_dispatch_run_auth_live,
    requires_card=True,
    tags=("auth", "milenage", "3gpp"),
)


get_registry().register(PUT_KEY_SPEC)
get_registry().register(INSTALL_CAP_SPEC)
get_registry().register(INSTALL_APP_SPEC)
get_registry().register(INSTALL_MAKE_SELECTABLE_SPEC)
get_registry().register(INSTALL_EXTRADITION_SPEC)
get_registry().register(INSTALL_PERSONALIZATION_SPEC)
get_registry().register(INSTALL_REGISTRY_UPDATE_SPEC)
get_registry().register(FS_BUILD_FCP_SPEC)
get_registry().register(FS_CREATE_FILE_SPEC)
get_registry().register(FS_DELETE_FILE_SPEC)
get_registry().register(FS_RESIZE_SPEC)
get_registry().register(FS_LIFECYCLE_SPEC)
get_registry().register(FS_SEARCH_RECORD_SPEC)
get_registry().register(FS_SUSPEND_UICC_SPEC)
get_registry().register(MANAGE_PIN_SPEC)
get_registry().register(MANAGE_CHANNEL_SPEC)
get_registry().register(RUN_AUTH_LIVE_SPEC)


# =====================================================================
# C-7 — Quality of life + adjacent functionality
# =====================================================================
#
# * scp03.run_script   — feed a semicolon- or newline-separated command
#                        list to the SCP03 engine in-process and return
#                        captured stdout. Mirrors ``SCP03 --cmd`` and the
#                        ``[S] Run SCP03 with a prepared script`` launcher
#                        entry, but without spawning a subprocess.
# * scp03.fs_report    — call ``FileSystemController.generate_report`` on
#                        the active session and save a YAML report to a
#                        caller-chosen filename. Returns captured stdout
#                        plus the absolute path of the written report.
# * scp03.guide_list   — enumerate the ShellGuides topics.
# * scp03.guide_show   — capture the printed text for a single topic
#                        (no interactive ``[Press Enter]`` loop).
# ---------------------------------------------------------------------


_GUIDE_TOPICS: tuple[tuple[str, str, str], ...] = (
    ("GP", "GlobalPlatform", "_print_gp_guide"),
    ("ETSI", "ETSI / 3GPP FS", "_print_etsi_guide"),
    ("GSMA", "GSMA eSIM / eUICC", "_print_gsma_guide"),
    ("INSTALL", "Install & APDU", "_print_install_guide"),
    ("SECURITY", "Crypto & Security", "_print_security_guide"),
    ("OTA", "SCP80 / OTA", "_print_ota_guide"),
    ("CONFIG", "Config & persistence", "_print_config_guide"),
    ("SAIP", "SAIP Tool", "_print_saip_guide"),
    ("SUCI", "SUCI Key Tool", "_print_suci_guide"),
    ("CLI", "CLI & piping", "_print_cli_guide"),
)


def _dispatch_run_script(
    ctx: ActionContext,
    *,
    script_path: Any = None,
    script_text: Any = None,
    yaml_out: Any = None,
) -> dict[str, Any]:
    """Run a script (inline text or a file path) through ``SCP03.main.entry_cmd``.

    Either ``script_path`` or ``script_text`` must be provided; if both
    are supplied ``script_text`` wins. Commands may be separated by
    newlines, ``;`` or both; the backend normalises to a single
    ``;``-joined line before calling the engine.
    """
    text_raw = str(script_text or "").strip()
    path_raw = str(script_path or "").strip()
    if len(text_raw) == 0 and len(path_raw) == 0:
        raise ValueError("provide a script file (script_path) or inline text (script_text).")

    if len(text_raw) == 0:
        expanded = os.path.expanduser(path_raw)
        if not os.path.isfile(expanded):
            raise ValueError(f"script file not found: {expanded}")
        try:
            with open(expanded, "r", encoding="utf-8") as handle:
                text_raw = handle.read()
        except OSError as error:
            raise ValueError(f"cannot read script file: {error}") from error
        source = expanded
    else:
        source = "<inline>"

    commands: list[str] = []
    for raw_line in text_raw.replace(";", "\n").splitlines():
        stripped = raw_line.strip()
        if len(stripped) == 0:
            continue
        if stripped.startswith("#"):
            continue
        commands.append(stripped)
    if len(commands) == 0:
        raise ValueError("script contained no executable lines.")

    yaml_path: str | None = None
    if yaml_out is not None:
        yaml_text = str(yaml_out).strip()
        if len(yaml_text) > 0:
            yaml_path = os.path.expanduser(yaml_text)

    from SCP03.main import entry_cmd

    sink = io.StringIO()
    err: str = ""
    try:
        with contextlib.redirect_stdout(sink):
            with contextlib.redirect_stderr(sink):
                entry_cmd("; ".join(commands), yaml_out=yaml_path)
    except SystemExit:
        pass
    except Exception as error:  # noqa: BLE001 — surface engine failure
        err = f"{type(error).__name__}: {error}"

    raw = _strip_ansi(sink.getvalue())
    lines = [line for line in raw.split("\n") if line.strip()]

    return {
        "source": source,
        "command_count": len(commands),
        "commands": commands,
        "yaml_out": yaml_path or "",
        "ok": len(err) == 0,
        "error": err,
        "raw_trace": raw,
        "lines": lines,
    }


def _dispatch_fs_report(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    filename: Any = None,
) -> dict[str, Any]:
    """Run ``FileSystemController.generate_report`` on the active session."""
    session, _transporter, sid = _get_scp03_session(session_id)
    fs_controller = session.handle.get("fs")
    if fs_controller is None:
        raise ValueError("session has no active FileSystemController (rescan first).")

    raw_name = str(filename or "").strip()
    if len(raw_name) == 0:
        raw_name = "scan_report.yaml"
    expanded = os.path.expanduser(raw_name)
    # When a bare filename is supplied, park the report next to the
    # working directory so the operator can locate it without hunting.
    if not os.path.isabs(expanded):
        expanded = os.path.abspath(expanded)

    sink = io.StringIO()
    err: str = ""
    try:
        with contextlib.redirect_stdout(sink):
            fs_controller.generate_report(expanded)
    except Exception as error:  # noqa: BLE001
        err = f"{type(error).__name__}: {error}"

    raw = _strip_ansi(sink.getvalue())
    lines = [line for line in raw.split("\n") if line.strip()]
    size = 0
    if os.path.isfile(expanded):
        try:
            size = os.path.getsize(expanded)
        except OSError:
            size = 0

    return {
        "session_id": sid,
        "filename": expanded,
        "file_size": size,
        "ok": len(err) == 0 and size > 0,
        "error": err,
        "raw_trace": raw,
        "lines": lines,
    }


def _dispatch_guide_list(ctx: ActionContext) -> dict[str, Any]:
    """Enumerate available ShellGuides topics without invoking any."""
    return {
        "topics": [
            {"code": code, "title": title}
            for (code, title, _method) in _GUIDE_TOPICS
        ],
        "count": len(_GUIDE_TOPICS),
    }


def _dispatch_guide_show(ctx: ActionContext, *, topic: Any = None) -> dict[str, Any]:
    """Render a single guide topic by invoking the printer classmethod."""
    raw = str(topic or "").strip().upper()
    if len(raw) == 0:
        raise ValueError("topic is required (see scp03.guide_list).")
    match: tuple[str, str, str] | None = None
    for entry in _GUIDE_TOPICS:
        if entry[0] == raw:
            match = entry
            break
    if match is None:
        allowed = ", ".join(code for (code, _t, _m) in _GUIDE_TOPICS)
        raise ValueError(f"unknown topic {raw!r}; pick one of [{allowed}]")

    from SCP03.interface.guides import ShellGuides

    method = getattr(ShellGuides, match[2], None)
    if method is None:
        raise ValueError(f"guide backend is missing method {match[2]!r}")

    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink):
            method()
    except Exception as error:  # noqa: BLE001
        raise ValueError(f"guide rendering failed: {error}") from error

    raw_text = _strip_ansi(sink.getvalue())
    lines = raw_text.split("\n")
    return {
        "topic": match[0],
        "title": match[1],
        "raw_trace": raw_text,
        "lines": lines,
        "line_count": len(lines),
    }


RUN_SCRIPT_SPEC = ActionSpec(
    id="scp03.run_script",
    subsystem="SCP03",
    title="Run script",
    description=(
        "Feed a shell script (file or inline text) to the SCP03 engine "
        "in-process and return captured stdout. Accepts newline- or "
        "semicolon-separated commands; lines starting with '#' are "
        "treated as comments."
    ),
    inputs=(
        ActionField(name="script_path", label="Script file", kind="path",
                    required=False,
                    help="Optional. Path to a .txt/.scp03/.sh-style command list."),
        ActionField(name="script_text", label="Inline commands", kind="text",
                    required=False, multiline=True,
                    placeholder="SCP03-SD\nLIST\nQ",
                    help="Optional. Overrides script_path when supplied."),
        ActionField(name="yaml_out", label="YAML report path", kind="save_path",
                    required=False,
                    help="Optional. Passed as --out to entry_cmd."),
    ),
    output_kind="json",
    dispatcher=_dispatch_run_script,
    requires_card=False,
    tags=("automation", "scripting"),
)


FS_REPORT_SPEC = ActionSpec(
    id="scp03.fs_report",
    subsystem="SCP03",
    title="FS report (YAML)",
    description=(
        "Run a deep filesystem scan on the active session and write a "
        "structured YAML report to the chosen path. Records, EF content, "
        "and ETSI decoders are all included. Large cards can take 60+ "
        "seconds; the GUI streams nothing, so expect the response to "
        "block until the write completes."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="filename", label="Report path", kind="save_path",
                    required=True, default="scan_report.yaml",
                    help="Absolute or workspace-relative YAML path."),
    ),
    output_kind="json",
    dispatcher=_dispatch_fs_report,
    requires_card=True,
    tags=("report", "fs", "yaml"),
)


GUIDE_LIST_SPEC = ActionSpec(
    id="scp03.guide_list",
    subsystem="SCP03",
    title="Guide topics",
    description="List the SCP03 ShellGuides topics available to scp03.guide_show.",
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_guide_list,
    requires_card=False,
    tags=("help", "guides"),
)


GUIDE_SHOW_SPEC = ActionSpec(
    id="scp03.guide_show",
    subsystem="SCP03",
    title="Guide show",
    description=(
        "Render a single ShellGuides topic (GP / ETSI / GSMA / INSTALL / "
        "SECURITY / OTA / CONFIG / SAIP / SUCI / CLI) as captured "
        "plain-text output."
    ),
    inputs=(
        ActionField(
            name="topic",
            label="Topic",
            kind="enum",
            required=True,
            choices=[code for (code, _t, _m) in _GUIDE_TOPICS],
            default="GP",
        ),
    ),
    output_kind="markdown",
    dispatcher=_dispatch_guide_show,
    requires_card=False,
    tags=("help", "guides"),
)


get_registry().register(RUN_SCRIPT_SPEC)
get_registry().register(FS_REPORT_SPEC)
get_registry().register(GUIDE_LIST_SPEC)
get_registry().register(GUIDE_SHOW_SPEC)
