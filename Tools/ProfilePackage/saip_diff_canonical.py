# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Context-aware re-keying of SAIP profile sections for diff.

Two profiles built by different tools, or the same tool at different
revisions, will routinely place the same EFs at different absolute
positions inside ``sections.genericFileManagement[N].file.fileManagementCMD[K]``.
The raw byte-offset / list-index diff treats those shifts as
``added`` / ``removed`` / ``changed`` entries, which floods the
report with mechanical encoding deltas and buries the real semantic
changes (FCP fields, EF content, security attributes).

This module re-keys ``genericFileManagement`` from a list-of-blocks
into a dict keyed by the resolved file-system path of each EF /
DF / MF (``3F00/7F20/6F07`` for EF.IMSI under DF.GSM, etc.). The
per-key value is the ordered command sub-list (``createFCP``,
``fillFileContent``, ``fillFileOffset``, …) that targets that file.
``filePath`` SELECTs are absorbed into the keys and never appear as
commands, so two profiles that contain the same EFs in different
list-index positions produce byte-identical canonical maps and the
diff engine no longer flags pure index shifts.

The transformation preserves the original tagged-tuple wrappers
verbatim, so the decoded-view cascade in
:mod:`saip_diff_tui` resolves field names and EF keys exactly as it
would on a non-canonical document.

Reference: ETSI TS 102 222 §6 (file management), GSMA SGP.22 §2.5.3
(Profile Element structure), local ``saip_json_codec`` for the
``@`` / ``hex`` tag conventions used here.
"""

from __future__ import annotations

from typing import Any


_TAG_BYTES: str = "hex"
_LEGACY_TAG_BYTES: str = "__ygg_saip_bytes__"
_TAG_TUPLE: str = "@"
_LEGACY_TAG_TUPLE: str = "__ygg_saip_tuple__"


_FID_NIBBLES: int = 4


def _tagged_bytes_hex(value: Any) -> str | None:
    """Return uppercased compact hex from a ``{'hex': ...}`` wrapper."""
    if isinstance(value, dict) is False:
        return None
    raw = value.get(_TAG_BYTES, value.get(_LEGACY_TAG_BYTES))
    if raw is None:
        return None
    text = (
        str(raw)
        .replace(" ", "")
        .replace("\n", "")
        .replace("\t", "")
    )
    if len(text) == 0:
        return None
    return text.upper()


def _tagged_tuple_parts(item: Any) -> tuple[str, Any] | None:
    if isinstance(item, dict) is False:
        return None
    inner = item.get(_TAG_TUPLE, item.get(_LEGACY_TAG_TUPLE))
    if isinstance(inner, list) is False:
        return None
    if len(inner) < 2:
        return None
    if isinstance(inner[0], str) is False:
        return None
    return inner[0], inner[1]


def _wrap_tagged_tuple(tag: str, payload: Any) -> dict[str, list[Any]]:
    return {_TAG_TUPLE: [tag, payload]}


def _split_path_hex(path_hex: str) -> list[str]:
    """Split a chained-FID path hex into per-FID 4-nibble segments.

    ETSI TS 102 221 §8.4.2 defines the SELECT path as a concatenation
    of 2-byte FIDs. Anything that is not a clean multiple of 4 nibbles
    is returned as a single opaque segment so the canonical key still
    differentiates from neighbours rather than being silently dropped.
    """
    text = str(path_hex or "").upper()
    if len(text) == 0:
        return []
    if (len(text) % _FID_NIBBLES) != 0:
        return [text]
    segments: list[str] = []
    for offset in range(0, len(text), _FID_NIBBLES):
        chunk = text[offset:offset + _FID_NIBBLES]
        if len(chunk) == _FID_NIBBLES:
            segments.append(chunk)
    return segments


def _iter_gfm_commands(
    generic_file_management: list[Any],
) -> list[tuple[str, Any]]:
    """Iterate ``(tag, payload)`` tuples across every block, in document order.

    SAIP allows multiple ``pe-genericFileManagement`` PEs at the top
    level, each carrying its own ``fileManagementCMD`` list. Diff
    cosmetics do not care which PE block holds the command, only which
    file it targets — so we flatten across blocks before re-keying.
    """
    cmds: list[tuple[str, Any]] = []
    for block in generic_file_management:
        if isinstance(block, dict) is False:
            continue
        cmd_list: Any = None
        if "fileManagementCMD" in block:
            cmd_list = block.get("fileManagementCMD")
        elif "file" in block and isinstance(block.get("file"), dict):
            cmd_list = block["file"].get("fileManagementCMD")
        if isinstance(cmd_list, list) is False:
            continue
        for cmd in cmd_list:
            parts = _tagged_tuple_parts(cmd)
            if parts is None:
                continue
            cmds.append(parts)
    return cmds


def _build_file_key(select_chain: list[str], fid: str | None) -> str:
    """Build the canonical dict key for a file at ``select_chain[+fid]``."""
    pieces: list[str] = list(select_chain)
    if fid is not None:
        cleaned = str(fid).strip().upper()
        if len(cleaned) > 0:
            pieces.append(cleaned)
    if len(pieces) == 0:
        return "<unscoped>"
    return "/".join(pieces)


def canonicalize_generic_file_management(
    value: list[Any],
) -> dict[str, list[Any]]:
    """Re-key a SAIP ``genericFileManagement`` section by resolved EF path.

    The output is a dict whose keys are slash-joined hex FID chains
    (e.g. ``3F00/7F20/6F07``) and whose values are ordered command
    sub-lists carrying every command that targets that file
    (``createFCP``, ``fillFileContent``, ``fillFileOffset``, plus
    any non-standard tag encountered after the SELECT-and-create that
    defined the file).

    ``filePath`` SELECTs are absorbed into the keys; they do not
    appear inside the per-file lists. Commands that arrive before any
    ``filePath`` or ``createFCP`` are bucketed under ``"<unscoped>"``
    so they remain visible to the diff engine but cannot collide with
    a real path key.

    The transformation is intentionally lossless for the purposes of
    semantic diffing: every original ``createFCP`` / ``fillFile*``
    payload is preserved verbatim under its target file. The only
    information dropped is the source list-position of each command,
    which is the source of the byte-offset noise this module exists
    to eliminate.
    """
    canonical: dict[str, list[Any]] = {}
    select_chain: list[str] = []
    active_key: str | None = None
    for tag, payload in _iter_gfm_commands(value):
        if tag == "filePath":
            path_hex = _tagged_bytes_hex(payload)
            if path_hex is None:
                continue
            new_chain = _split_path_hex(path_hex)
            if len(new_chain) == 0:
                continue
            select_chain = new_chain
            active_key = _build_file_key(select_chain, None)
            continue
        if tag == "createFCP":
            fid_hex: str | None = None
            if isinstance(payload, dict) is True:
                fid_hex = _tagged_bytes_hex(payload.get("fileID"))
            active_key = _build_file_key(select_chain, fid_hex)
            entry = canonical.setdefault(active_key, [])
            entry.append(_wrap_tagged_tuple(tag, payload))
            continue
        # fillFileContent, fillFileOffset, deleteFile, etc. attach to
        # whichever file the cursor most recently created or selected.
        # If neither has happened we bucket under <unscoped> so the
        # command is still diffable but cannot leak into a real key.
        target_key = active_key if active_key is not None else "<unscoped>"
        entry = canonical.setdefault(target_key, [])
        entry.append(_wrap_tagged_tuple(tag, payload))
    return canonical


_PE_HEADER_KEY_SUFFIXES: tuple[str, ...] = ("-header", "-Header")
_PE_HEADER_IDENTIFICATION_FIELD: str = "identification"


def _is_pe_header_key(key: Any) -> bool:
    """Return ``True`` when ``key`` matches the SAIP ``<x>-header`` shape.

    SAIP encoders are inconsistent about the casing of the suffix:
    ``aka-header``, ``mf-header``, ``usim-header`` use lowercase, but
    ``pin-Header``, ``puk-Header``, ``sd-Header`` use uppercase ``H``
    (see ``saip_pe_editors/_base.py``). Both spellings carry the same
    sequential ``identification`` field, so the strip needs to match
    both.
    """
    if isinstance(key, str) is False:
        return False
    for suffix in _PE_HEADER_KEY_SUFFIXES:
        if key.endswith(suffix):
            return True
    return False


def _strip_pe_header_identification(value: Any) -> Any:
    """Drop ``identification`` from every ``<pe-name>-header`` block.

    SGP.22 §2.5.3 places a sequential integer in
    ``sections.<peName>.<peName>-header.identification`` that simply
    tracks the PE's position in the original encoding. Two profiles
    that differ only in PE count or ordering surface every PE as a
    ``changed`` entry on this single field even though every other
    byte of the PE is identical. The field carries no semantic
    information for a SAIP-vs-SAIP comparison so we strip it before
    handing the document to the diff engine.

    The walk is structural: any dict-typed key whose name ends in
    ``-header`` or ``-Header`` has its ``identification`` sub-field
    removed; every other field of the header is preserved verbatim.
    Recurses through nested dicts and lists so PE blocks inside
    list-of-records sections (e.g. ``sections.usimContent[*]``) are
    also covered.
    """
    if isinstance(value, dict) is True:
        out: dict[str, Any] = {}
        for sub_key, sub_value in value.items():
            if (
                _is_pe_header_key(sub_key) is True
                and isinstance(sub_value, dict) is True
                and _PE_HEADER_IDENTIFICATION_FIELD in sub_value
            ):
                stripped: dict[str, Any] = {
                    inner_key: inner_value
                    for inner_key, inner_value in sub_value.items()
                    if inner_key != _PE_HEADER_IDENTIFICATION_FIELD
                }
                out[sub_key] = stripped
                continue
            out[sub_key] = _strip_pe_header_identification(sub_value)
        return out
    if isinstance(value, list) is True:
        return [_strip_pe_header_identification(item) for item in value]
    return value


def canonicalize_document_for_diff(document: Any) -> Any:
    """Return a copy of ``document`` with diff-noisy sections re-keyed.

    Two transformations are applied to the ``sections`` sub-tree:

    * ``genericFileManagement`` is re-keyed from a list of PE blocks
      into a path-keyed dict (``3F00/7F20/6F07``-style keys), so
      mechanical SELECT shifts no longer surface as added / removed
      entries.
    * Every PE-header ``identification`` field is stripped so the
      sequential PE index does not surface as a ``changed`` entry on
      every PE when the two profiles differ in PE count or order.

    All other top-level keys, including ``intro`` and unrelated
    ``sections.*`` entries, flow through with the second
    transformation applied. Non-dict inputs are returned as-is.

    Idempotent: a document that has already been canonicalised (so its
    ``genericFileManagement`` is already a dict, not a list, and its
    PE headers no longer carry ``identification``) is returned
    unchanged.
    """
    if isinstance(document, dict) is False:
        return document
    out: dict[str, Any] = {}
    for top_key, top_value in document.items():
        if top_key != "sections" or isinstance(top_value, dict) is False:
            out[top_key] = top_value
            continue
        new_sections: dict[str, Any] = {}
        for section_key, section_value in top_value.items():
            if (
                section_key == "genericFileManagement"
                and isinstance(section_value, list) is True
            ):
                new_sections[section_key] = canonicalize_generic_file_management(
                    section_value,
                )
                continue
            new_sections[section_key] = _strip_pe_header_identification(
                section_value,
            )
        out[top_key] = new_sections
    return out


__all__ = [
    "canonicalize_document_for_diff",
    "canonicalize_generic_file_management",
]
