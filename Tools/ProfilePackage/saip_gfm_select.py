# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""PE-GenericFileManagement single-DF-context helpers.

Design contract (YggdraSIM): one PE-GFM owns exactly one DF context.
The operator selects the DF path at the top of the editor, every file
appended under that PE lands directly under that DF, and nested or
sibling DF trees are modelled by *additional* PE-GFM PEs (one per DF
context).

Wire-level layout: ``decoded["fileManagementCMD"]`` is a list of
"transactions" where each transaction is a list of
``(opcode, value)`` pairs. ETSI TS 102 226 §6.6.5 / pySim
``ProfileElementGFM.pe2files`` permit any interleaving of ``filePath``
selects and ``createFCP`` / ``updateFCP`` / ``deleteFile`` operations.
The canonical YggdraSIM shape is::

    fileManagementCMD = [
        [
            ("filePath",  <DF path bytes, '' = MF root>),
            ("createFCP", <FCP dict for child #1>),
            ("createFCP", <FCP dict for child #2>),
            …
        ]
    ]

Imported / legacy GFMs that mix multiple ``filePath`` selects are
normalised on first access — the *first* select wins as the DF
context, anything after it that doesn't share the same path is moved
out into a sibling transaction (mirroring TCA SAIP §A.2 transaction
boundaries) and surfaced as a warning so the operator can decide
whether to split the PE.
"""

from __future__ import annotations

import re
from typing import Any


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _strip(value: Any) -> str:
    return re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))


def normalise_df_path(value: Any) -> str:
    """Validate / canonicalise a DF path expressed as concatenated FIDs.

    TS 102 221 §8.3.5: the path is an even-length string of 16-bit
    file identifiers. The MF (3F00) prefix is stripped because pySim
    re-prepends it on encode (``ProfileElementGFM.pe2files``); the
    empty string is the canonical "MF root" marker.
    """
    text = _strip(value)
    if len(text) == 0:
        return ""
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"DF path is not hexadecimal: {value!r}")
    if len(text) % 4 != 0:
        raise ValueError(
            f"DF path must be concatenated 16-bit FIDs (multiple of 4 "
            f"hex digits); got {len(text)} digits.",
        )
    upper = text.upper()
    if upper.startswith("3F00"):
        upper = upper[4:]
    return upper


def _filepath_value_to_hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex().upper()
    if isinstance(value, dict):
        for key in ("__ygg_saip_bytes__", "hex"):
            raw = value.get(key)
            if isinstance(raw, str):
                return raw.upper()
    if isinstance(value, str):
        return _strip(value).upper()
    return ""


def _ensure_command_list(pe_value: Any) -> list[list[tuple[str, Any]]]:
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-GFM value must be a dict.")
    fmc = pe_value.get("fileManagementCMD")
    if isinstance(fmc, list) is False:
        fmc = []
        pe_value["fileManagementCMD"] = fmc
    return fmc


def _flatten_transactions(
    transactions: list[Any],
) -> list[tuple[str, Any]]:
    flat: list[tuple[str, Any]] = []
    for txn in transactions:
        if isinstance(txn, list) is False:
            continue
        for entry in txn:
            if isinstance(entry, tuple) and len(entry) == 2:
                flat.append((str(entry[0]), entry[1]))
                continue
            if isinstance(entry, list) and len(entry) == 2:
                flat.append((str(entry[0]), entry[1]))
                continue
    return flat


def get_df_context(pe_value: dict[str, Any]) -> dict[str, Any]:
    """Inspect a GFM PE and report its current DF context.

    Returns ``{"df_path_hex": <str>, "file_count": <int>,
    "extra_filepath_count": <int>, "warnings": [<str>, ...]}``.
    ``extra_filepath_count`` is non-zero when the PE was loaded with
    interleaved ``filePath`` selects that disagree with the leading
    DF path; the GUI surfaces this as a banner with a "Split into
    sibling GFMs" suggestion.
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-GFM value must be a dict.")
    fmc = pe_value.get("fileManagementCMD")
    if isinstance(fmc, list) is False:
        return {
            "df_path_hex": "",
            "file_count": 0,
            "extra_filepath_count": 0,
            "warnings": [],
        }
    flat = _flatten_transactions(fmc)
    leading_path = ""
    seen_leading = False
    extra_paths: list[str] = []
    file_count = 0
    for opcode, value in flat:
        if opcode == "filePath":
            path_hex = _filepath_value_to_hex(value).upper()
            if path_hex.startswith("3F00"):
                path_hex = path_hex[4:]
            if seen_leading is False:
                leading_path = path_hex
                seen_leading = True
                continue
            if path_hex != leading_path:
                extra_paths.append(path_hex)
            continue
        if opcode in ("createFCP", "updateFCP", "deleteFile"):
            file_count += 1
    warnings: list[str] = []
    if len(extra_paths) > 0:
        warnings.append(
            f"GFM carries {len(extra_paths)} divergent filePath select(s); "
            "YggdraSIM models one DF context per GFM. Split into sibling "
            "PE-GFMs (one per DF) to retain the original semantics.",
        )
    return {
        "df_path_hex": leading_path,
        "file_count": file_count,
        "extra_filepath_count": len(extra_paths),
        "warnings": warnings,
    }


def set_df_context(
    pe_value: dict[str, Any],
    *,
    df_path: Any,
) -> dict[str, Any]:
    """Set / replace the DF context on a GFM PE in place.

    Operates on the canonical layout: a single transaction with one
    leading ``filePath`` select followed by every existing
    ``createFCP`` / ``updateFCP`` / ``deleteFile`` operation in their
    original order. Any divergent ``filePath`` entries from the input
    are dropped (callers receive the count via the response so the
    GUI can warn).
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-GFM value must be a dict.")
    canonical_path = normalise_df_path(df_path)
    fmc = _ensure_command_list(pe_value)
    flat = _flatten_transactions(fmc)
    dropped_paths = 0
    rebuilt: list[tuple[str, Any]] = [
        (
            "filePath",
            bytes.fromhex(canonical_path) if canonical_path else b"",
        ),
    ]
    for opcode, value in flat:
        if opcode == "filePath":
            dropped_paths += 1
            continue
        rebuilt.append((opcode, value))
    pe_value["fileManagementCMD"] = [rebuilt]
    return {
        "df_path_hex": canonical_path,
        "file_count": sum(1 for op, _v in rebuilt[1:] if op in ("createFCP", "updateFCP", "deleteFile")),
        "dropped_filepath_count": dropped_paths,
    }


def list_files(pe_value: dict[str, Any]) -> list[dict[str, Any]]:
    """Project the GFM file list for the file-system tab.

    Each output row carries ``{position, opcode, file_id_hex,
    df_path_hex}`` where ``df_path_hex`` is the leading DF context.
    Position is the 0-based index inside the canonical transaction so
    it doubles as the reorder cursor.
    """
    ctx = get_df_context(pe_value)
    df_path_hex = ctx.get("df_path_hex", "")
    fmc = pe_value.get("fileManagementCMD") if isinstance(pe_value, dict) else None
    rows: list[dict[str, Any]] = []
    if isinstance(fmc, list) is False:
        return rows
    flat = _flatten_transactions(fmc)
    cursor = 0
    for opcode, value in flat:
        if opcode == "filePath":
            continue
        if opcode not in ("createFCP", "updateFCP", "deleteFile"):
            continue
        fid_hex = ""
        if isinstance(value, dict):
            raw = value.get("fileID")
            if isinstance(raw, (bytes, bytearray)):
                fid_hex = bytes(raw).hex().upper()
            elif isinstance(raw, dict):
                inner = raw.get("__ygg_saip_bytes__") or raw.get("hex")
                if isinstance(inner, str):
                    fid_hex = inner.upper()
        rows.append(
            {
                "position": cursor,
                "opcode": opcode,
                "file_id_hex": fid_hex,
                "df_path_hex": df_path_hex,
            },
        )
        cursor += 1
    return rows


def reorder_files(
    pe_value: dict[str, Any],
    *,
    from_index: int,
    to_index: int,
) -> dict[str, Any]:
    """Reorder one file inside the canonical GFM transaction.

    Both indices are 0-based against the file list returned by
    ``list_files`` (i.e. the leading ``filePath`` select is not
    counted). Out-of-range indices raise ``IndexError`` so the GUI
    can surface the failure verbatim.
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-GFM value must be a dict.")
    fmc = pe_value.get("fileManagementCMD")
    if isinstance(fmc, list) is False or len(fmc) == 0:
        raise IndexError("GFM has no transactions; nothing to reorder.")
    transaction = fmc[0]
    if isinstance(transaction, list) is False:
        raise IndexError("GFM transaction is malformed; cannot reorder.")
    file_positions = [
        idx for idx, entry in enumerate(transaction)
        if isinstance(entry, (tuple, list)) and len(entry) == 2
        and str(entry[0]) in ("createFCP", "updateFCP", "deleteFile")
    ]
    n_files = len(file_positions)
    if from_index < 0 or from_index >= n_files:
        raise IndexError(
            f"from_index {from_index} out of range 0..{n_files - 1 if n_files else 0}.",
        )
    if to_index < 0 or to_index >= n_files:
        raise IndexError(
            f"to_index {to_index} out of range 0..{n_files - 1 if n_files else 0}.",
        )
    src_pos = file_positions[from_index]
    item = transaction.pop(src_pos)
    # Recompute target position because the pop may have shifted
    # indices — rebuild the file_positions list around the modified
    # transaction and insert at the recomputed slot.
    file_positions_after = [
        idx for idx, entry in enumerate(transaction)
        if isinstance(entry, (tuple, list)) and len(entry) == 2
        and str(entry[0]) in ("createFCP", "updateFCP", "deleteFile")
    ]
    if to_index >= len(file_positions_after):
        transaction.append(item)
    else:
        transaction.insert(file_positions_after[to_index], item)
    return {
        "from_index": int(from_index),
        "to_index": int(to_index),
        "file_count": n_files,
    }


def remove_file(pe_value: dict[str, Any], *, position: int) -> dict[str, Any]:
    """Remove the file at the given 0-based position inside the GFM."""
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-GFM value must be a dict.")
    fmc = pe_value.get("fileManagementCMD")
    if isinstance(fmc, list) is False or len(fmc) == 0:
        raise IndexError("GFM has no transactions.")
    transaction = fmc[0]
    if isinstance(transaction, list) is False:
        raise IndexError("GFM transaction malformed.")
    file_positions = [
        idx for idx, entry in enumerate(transaction)
        if isinstance(entry, (tuple, list)) and len(entry) == 2
        and str(entry[0]) in ("createFCP", "updateFCP", "deleteFile")
    ]
    if position < 0 or position >= len(file_positions):
        raise IndexError(
            f"position {position} out of range 0..{len(file_positions) - 1 if file_positions else 0}.",
        )
    src_pos = file_positions[position]
    removed = transaction.pop(src_pos)
    return {
        "removed_position": int(position),
        "remaining_files": len(file_positions) - 1,
        "removed_opcode": str(removed[0]) if isinstance(removed, (tuple, list)) else "",
    }


__all__ = [
    "get_df_context",
    "list_files",
    "normalise_df_path",
    "remove_file",
    "reorder_files",
    "set_df_context",
]
