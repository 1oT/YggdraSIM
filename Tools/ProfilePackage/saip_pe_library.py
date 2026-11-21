# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Operator library of saved profile elements.

One ``<name>.pe.json`` per entry under ``~/.yggdrasim/saip_pe_library/``
(``YGGDRASIM_SAIP_PE_LIBRARY`` names another directory). An entry is the
``ygg.pe_document.v1`` file ``saip.export_pe`` writes, so the library and
the file export share one format and one reader; saving adds the entry
name and the save time to the document's metadata. The directory lives
outside every checkout and is never tracked.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Mapping

PE_LIBRARY_DIR_ENV = "YGGDRASIM_SAIP_PE_LIBRARY"
PE_LIBRARY_DIR_NAME = "saip_pe_library"
PE_LIBRARY_SUFFIX = ".pe.json"
# The PE document the GUI's export and import share (actions/saip.py pins
# the same two values; tests/test_saip_pe_library.py keeps them equal).
PE_DOCUMENT_META_KEY = "__ygg_pe_document__"
PE_DOCUMENT_SCHEMA = "ygg.pe_document.v1"
# An Application PE carries its load block, so an entry can be megabytes;
# the cap matches the GUI upload limit.
MAX_ENTRY_BYTES = 64 * 1024 * 1024

_USER_DIR_NAME = ".yggdrasim"
_ENTRY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PeLibraryError(ValueError):
    """A library request the operator can correct (name, missing entry, bad file)."""


def pe_library_dir(environ: Mapping[str, str] | None = None) -> Path:
    """Return the library directory: the env override, else ``~/.yggdrasim/saip_pe_library``."""

    env = os.environ if environ is None else environ
    override = str(env.get(PE_LIBRARY_DIR_ENV, "") or "").strip()
    if override:
        return Path(os.path.expanduser(override))
    return Path(os.path.expanduser("~")) / _USER_DIR_NAME / PE_LIBRARY_DIR_NAME


def normalise_entry_name(name: Any) -> str:
    """Return a valid entry name or raise; the suffix is dropped when typed."""

    text = str(name or "").strip()
    if text.casefold().endswith(PE_LIBRARY_SUFFIX):
        text = text[: -len(PE_LIBRARY_SUFFIX)]
    if not text:
        raise PeLibraryError("A name for the saved profile element is required.")
    if _ENTRY_NAME_RE.match(text) is None:
        raise PeLibraryError(
            f"Saved profile element name {text!r} must be letters, digits, '.', '_' or '-' "
            "(64 characters at most) and start with a letter or digit."
        )
    return text


def entry_path(name: Any, directory: Path | None = None) -> Path:
    """The file one entry lives in."""

    base = pe_library_dir() if directory is None else Path(directory)
    return base / (normalise_entry_name(name) + PE_LIBRARY_SUFFIX)


def saved_at_stamp() -> str:
    """UTC time of a save, second precision, as the entry metadata records it."""

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_entry(
    name: Any,
    document: Mapping[str, Any],
    *,
    directory: Path | None = None,
    overwrite: bool = False,
) -> Path:
    """Store ``document`` as the entry ``name``; refuses an existing entry unless ``overwrite``."""

    from yggdrasim_common.secure_files import atomic_write_bytes, ensure_private_directory

    entry_name = normalise_entry_name(name)
    if isinstance(document, Mapping) is False:
        raise PeLibraryError("A PE document (JSON object) is required.")
    meta = document.get(PE_DOCUMENT_META_KEY)
    if isinstance(meta, Mapping) is False or str(meta.get("schema") or "") != PE_DOCUMENT_SCHEMA:
        raise PeLibraryError(
            f"Only a {PE_DOCUMENT_SCHEMA} PE document can be saved to the library."
        )
    base = pe_library_dir() if directory is None else Path(directory)
    ensure_private_directory(base)
    target = base / (entry_name + PE_LIBRARY_SUFFIX)
    payload = (json.dumps(dict(document), indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(payload) > MAX_ENTRY_BYTES:
        raise PeLibraryError(
            f"The PE document is {len(payload)} bytes; the library stores at most {MAX_ENTRY_BYTES}."
        )
    try:
        atomic_write_bytes(target, payload, overwrite=overwrite)
    except FileExistsError as error:
        raise FileExistsError(
            f"A saved profile element named {entry_name!r} exists; pass overwrite=true to replace it."
        ) from error
    return target


def read_entry(name: Any, directory: Path | None = None) -> dict[str, Any]:
    """Return the PE document stored as ``name``."""

    from yggdrasim_common.secure_files import read_bounded_regular_file

    entry_name = normalise_entry_name(name)
    path = entry_path(entry_name, directory)
    if path.is_file() is False:
        raise PeLibraryError(f"No saved profile element named {entry_name!r}.")
    try:
        raw = read_bounded_regular_file(path, MAX_ENTRY_BYTES)
    except (OSError, ValueError) as error:
        raise PeLibraryError(f"{path.name} could not be read: {error}") from error
    return _document_from_bytes(raw, path)


def _document_from_bytes(raw: bytes, path: Path) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PeLibraryError(f"{path.name} is not a readable PE document: {error}") from error
    if isinstance(document, dict) is False or isinstance(document.get(PE_DOCUMENT_META_KEY), dict) is False:
        raise PeLibraryError(
            f"{path.name} is not a PE document (no {PE_DOCUMENT_META_KEY} metadata)."
        )
    return document


def delete_entry(name: Any, directory: Path | None = None) -> Path:
    """Remove the entry ``name`` and return the path it occupied."""

    entry_name = normalise_entry_name(name)
    path = entry_path(entry_name, directory)
    if path.is_symlink() or path.is_file() is False:
        raise PeLibraryError(f"No saved profile element named {entry_name!r}.")
    path.unlink()
    return path


def entry_summary(path: Path, document: Mapping[str, Any]) -> dict[str, Any]:
    """The listing row for one entry: its metadata without the PE tree.

    The PE name comes from the stored PEHeader's ``pe-name``. An entry an
    earlier release saved also carries it, with a label, a source package
    name and a summary, in its metadata; the row keeps the name and the
    label and leaves the other two out.
    """

    meta = document.get(PE_DOCUMENT_META_KEY)
    if isinstance(meta, Mapping) is False:
        meta = {}
    stem = path.name[: -len(PE_LIBRARY_SUFFIX)] if path.name.endswith(PE_LIBRARY_SUFFIX) else path.stem
    return {
        "name": str(meta.get("library_name") or stem),
        "path": str(path),
        "pe_type": str(meta.get("pe_type") or ""),
        "label": str(meta.get("label") or ""),
        "pe_name": str(meta.get("pe_name") or "") or _stored_pe_name(document),
        "template": bool(meta.get("template")),
        "placeholders": [str(item) for item in (meta.get("placeholders") or [])],
        "saved_at": str(meta.get("saved_at") or ""),
        "size_bytes": int(path.stat().st_size),
    }


def _stored_pe_name(document: Mapping[str, Any]) -> str:
    """The workbench's ``pe-name`` in the PEHeader of the one stored section."""

    sections = document.get("sections")
    if isinstance(sections, Mapping) is False or len(sections) != 1:
        return ""
    section = next(iter(sections.values()))
    if isinstance(section, Mapping) is False:
        return ""
    for key, value in section.items():
        if str(key).lower().endswith("header") and isinstance(value, Mapping):
            name = value.get("pe-name")
            return name if isinstance(name, str) else ""
    return ""


def list_entries(directory: Path | None = None) -> list[dict[str, Any]]:
    """Every entry of the library, by name; an unreadable file reports its error."""

    from yggdrasim_common.secure_files import read_bounded_regular_file

    base = pe_library_dir() if directory is None else Path(directory)
    if base.is_dir() is False:
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(base.glob("*" + PE_LIBRARY_SUFFIX), key=lambda item: item.name.casefold()):
        if path.is_symlink() or path.is_file() is False:
            continue
        try:
            raw = read_bounded_regular_file(path, MAX_ENTRY_BYTES)
            document = _document_from_bytes(raw, path)
            rows.append(entry_summary(path, document))
        except (OSError, ValueError) as error:
            rows.append(
                {
                    "name": path.name[: -len(PE_LIBRARY_SUFFIX)],
                    "path": str(path),
                    "error": str(error),
                }
            )
    return rows


__all__ = [
    "MAX_ENTRY_BYTES",
    "PE_DOCUMENT_META_KEY",
    "PE_DOCUMENT_SCHEMA",
    "PE_LIBRARY_DIR_ENV",
    "PE_LIBRARY_DIR_NAME",
    "PE_LIBRARY_SUFFIX",
    "PeLibraryError",
    "delete_entry",
    "entry_path",
    "entry_summary",
    "list_entries",
    "normalise_entry_name",
    "pe_library_dir",
    "read_entry",
    "saved_at_stamp",
    "write_entry",
]
