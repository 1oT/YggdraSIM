# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Java Card CAP / IJC inspector — package, applet and import AIDs.

The PE-Application editor offers an "Import from CAP" button that
needs to extract the package AID, every applet AID and every import
(referenced package) AID from a CAP file *or* its converted IJC
form, without executing the byte-code or relying on any external
tooling. This module is the parser behind that button.

References:

* JCVM Spec §6 (CAP file format) — Header, Applet and Import
  components.
* GP Amd B §11 (CAP file packaging on the card).

A CAP file is a JAR/ZIP archive carrying ``*.cap`` component blobs
named ``Header.cap``, ``Applet.cap``, ``Import.cap``, .... Each
component is itself a length-prefixed structure beginning with a
1-byte tag identifying the component class (1 = header, 2 = directory,
3 = applet, 4 = import, ...).

An IJC (Installable Java Card) file is the same components
concatenated in directory order — i.e. a flat byte stream that starts
with the Header component (tag 0x01).
"""

from __future__ import annotations

import io
import zipfile
from typing import Any


_TAG_HEADER = 0x01
_TAG_DIRECTORY = 0x02
_TAG_APPLET = 0x03
_TAG_IMPORT = 0x04


def _read_aid(buf: bytes, offset: int) -> tuple[str, int] | None:
    """Read ``length(1) || aid(length)`` and return ``(hex, next)``."""
    if offset >= len(buf):
        return None
    length = buf[offset]
    cursor = offset + 1
    if length < 5 or length > 16 or cursor + length > len(buf):
        return None
    return (buf[cursor : cursor + length].hex().upper(), cursor + length)


def _parse_header_component(buf: bytes) -> dict[str, Any]:
    """JCVM §6.3 Header component — magic, version, flags, package AID."""
    out: dict[str, Any] = {}
    if len(buf) < 8:
        return out
    if buf[0:4] != b"\xDE\xCA\xFF\xED":
        out["magic_invalid"] = buf[0:4].hex().upper()
        return out
    out["minor_version"] = buf[4]
    out["major_version"] = buf[5]
    out["flags_hex"] = f"{buf[6]:02X}"
    cursor = 7
    if cursor + 2 > len(buf):
        return out
    out["package_minor"] = buf[cursor]
    out["package_major"] = buf[cursor + 1]
    cursor += 2
    aid_pair = _read_aid(buf, cursor)
    if aid_pair is None:
        return out
    out["package_aid_hex"] = aid_pair[0]
    return out


def _parse_applet_component(buf: bytes) -> list[str]:
    """JCVM §6.5 Applet component — count(1) || (length(1) || AID || install_method_offset(2))*."""
    if len(buf) == 0:
        return []
    count = buf[0]
    cursor = 1
    aids: list[str] = []
    for _ in range(count):
        aid_pair = _read_aid(buf, cursor)
        if aid_pair is None:
            break
        aid_hex, cursor = aid_pair
        aids.append(aid_hex)
        # Skip the install_method_offset (u2).
        cursor += 2
        if cursor > len(buf):
            break
    return aids


def _parse_import_component(buf: bytes) -> list[str]:
    """JCVM §6.4 Import component — count(1) || (package_minor || package_major || length(1) || AID)*."""
    if len(buf) == 0:
        return []
    count = buf[0]
    cursor = 1
    aids: list[str] = []
    for _ in range(count):
        if cursor + 2 > len(buf):
            break
        cursor += 2
        aid_pair = _read_aid(buf, cursor)
        if aid_pair is None:
            break
        aid_hex, cursor = aid_pair
        aids.append(aid_hex)
    return aids


def _walk_components(buf: bytes) -> dict[str, bytes]:
    """Walk a flat IJC byte stream and split it into components by tag."""
    components: dict[str, bytes] = {}
    cursor = 0
    while cursor + 3 <= len(buf):
        tag = buf[cursor]
        size = int.from_bytes(buf[cursor + 1 : cursor + 3], "big")
        component_bytes = buf[cursor + 3 : cursor + 3 + size]
        if cursor + 3 + size > len(buf):
            break
        if tag == _TAG_HEADER:
            components["Header"] = component_bytes
        elif tag == _TAG_DIRECTORY:
            components["Directory"] = component_bytes
        elif tag == _TAG_APPLET:
            components["Applet"] = component_bytes
        elif tag == _TAG_IMPORT:
            components["Import"] = component_bytes
        cursor += 3 + size
    return components


def _read_zip_components(raw: bytes) -> dict[str, bytes] | None:
    """Try to read a CAP-as-JAR. Returns ``None`` when the archive is not a CAP."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = {name.split("/")[-1].lower(): name for name in zf.namelist()}
            wanted = {
                "Header": names.get("header.cap"),
                "Applet": names.get("applet.cap"),
                "Import": names.get("import.cap"),
                "Directory": names.get("directory.cap"),
            }
            out: dict[str, bytes] = {}
            for component_name, archive_path in wanted.items():
                if archive_path is None:
                    continue
                blob = zf.read(archive_path)
                # Strip the 3-byte component header (tag + u2 size).
                if len(blob) >= 3:
                    out[component_name] = blob[3:]
            if "Header" in out:
                return out
            return None
    except (zipfile.BadZipFile, OSError):
        return None


def parse_cap_or_ijc(raw: bytes) -> dict[str, Any]:
    """Public entry point — accepts CAP-as-JAR or flat IJC bytes.

    Returns ``{"format": "cap" | "ijc",
              "package_aid_hex": <str | "">,
              "applet_aids": [<hex>, ...],
              "import_aids": [<hex>, ...],
              "header": {...},
              "warnings": [<str>, ...]}``.
    """
    if isinstance(raw, (bytes, bytearray)) is False:
        raise ValueError("CAP/IJC payload must be bytes.")
    raw = bytes(raw)
    if len(raw) == 0:
        raise ValueError("CAP/IJC payload is empty.")
    components: dict[str, bytes]
    fmt: str
    cap_components = _read_zip_components(raw)
    if cap_components is not None:
        components = cap_components
        fmt = "cap"
    else:
        components = _walk_components(raw)
        fmt = "ijc"
    warnings: list[str] = []
    header_payload: dict[str, Any] = {}
    if "Header" in components:
        header_payload = _parse_header_component(components["Header"])
    else:
        warnings.append("Header component missing — package AID unavailable.")
    applet_aids: list[str] = []
    if "Applet" in components:
        applet_aids = _parse_applet_component(components["Applet"])
    import_aids: list[str] = []
    if "Import" in components:
        import_aids = _parse_import_component(components["Import"])
    package_aid = header_payload.get("package_aid_hex", "")
    return {
        "format": fmt,
        "package_aid_hex": package_aid,
        "applet_aids": applet_aids,
        "import_aids": import_aids,
        "header": header_payload,
        "warnings": warnings,
    }


def parse_cap_path(path: str) -> dict[str, Any]:
    with open(path, "rb") as fh:
        raw = fh.read()
    return parse_cap_or_ijc(raw)


__all__ = ["parse_cap_or_ijc", "parse_cap_path"]
