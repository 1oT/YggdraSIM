# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Inline typed hex placeholder handling for vendor SAIP templates.

Vendor templates (Telna and similar) ship SAIP payloads as ASCII hex
with typed placeholders baked in at byte-aligned positions inside TLV
values:

    62128202412183026F078B036F06068001098800810908{imsi:IMSI:8:encode_imsi}80027F20

The ``{name:TYPE:length[:modifier]}`` form declares the byte length of
the region each placeholder occupies. Some vendor templates use a compact
form where the type and length are folded into the token name, for example
``{imsiIMSI8EncodeIMSI}`` or ``[iccidICCID10]``. YggdraSIM keeps every
placeholder literal intact through ``OPEN`` / ``INSPECT`` but still needs
valid DER bytes for pySim to decode. This module replaces each placeholder
with a deterministic, per-index sentinel of the declared byte length,
records the original literals in a sidecar, and re-inserts them into the
tagged JSON document after decode so the operator sees the placeholder
text exactly where it sat in the source file.

The placeholder itself is treated as opaque: nothing here parses the
``TYPE`` or ``modifier`` component, only the declared byte length.
Resolving placeholders to real bytes remains the job of the native
JSON template surface (``__ygg_token_defs__`` / ``APPLY-TEMPLATE``).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


_INLINE_PLACEHOLDER_RE = re.compile(
    r"\{"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r":"
    r"(?P<type>[A-Za-z_][A-Za-z0-9_]*)"
    r":"
    r"(?P<length>\d+)"
    r"(?::(?P<modifier>[A-Za-z_][A-Za-z0-9_]*))?"
    r"\}"
)
_COMPACT_PLACEHOLDER_RE = re.compile(
    r"\{(?P<brace>[A-Za-z_][A-Za-z0-9_]*)\}"
    r"|\[(?P<bracket>[A-Za-z_][A-Za-z0-9_]*)\]"
)
_COMPACT_PLACEHOLDER_BODY_RE = re.compile(
    r"^(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<type>ICCID|IMSI|MSISDN|BINARY|TEXT)"
    r"(?P<length>\d+)"
    r"(?P<modifier>[A-Za-z_][A-Za-z0-9_]*)?$"
)


_MIN_PLACEHOLDER_BYTES = 2
_MAX_PLACEHOLDER_BYTES = 4096
_MAX_PLACEHOLDERS_PER_FILE = 2048

_SIDECAR_VERSION = 1
_SIDECAR_SUFFIX = ".placeholders.json"

# blake2s ``person`` argument is capped at 8 bytes.
_SENTINEL_PERSON = b"ygghexph"

# Hex-tag keys used by ``saip_json_codec.jsonify_saip_value`` for tagged
# byte blobs. Both the current spelling (``hex``) and the legacy spelling
# (``__ygg_saip_bytes__``) are walked so decoded documents loaded via
# either path are covered.
_HEX_TAG_KEYS = ("hex", "__ygg_saip_bytes__")


@dataclass(frozen=True)
class InlinePlaceholderRecord:
    """One placeholder extracted from an inline typed-hex template."""

    index: int
    literal: str
    variable_name: str
    type_name: str
    byte_length: int
    modifier: str | None
    sentinel_hex: str


@dataclass(frozen=True)
class _InlinePlaceholderToken:
    literal: str
    variable_name: str
    type_name: str
    byte_length: int
    modifier: str | None
    start: int
    end: int


def _token_from_typed_match(match: re.Match[str]) -> _InlinePlaceholderToken:
    modifier = match.group("modifier")
    return _InlinePlaceholderToken(
        literal=match.group(0),
        variable_name=match.group("var"),
        type_name=match.group("type"),
        byte_length=int(match.group("length")),
        modifier=modifier if modifier is not None else None,
        start=match.start(),
        end=match.end(),
    )


def _token_from_compact_match(match: re.Match[str]) -> _InlinePlaceholderToken | None:
    body = match.group("brace") or match.group("bracket") or ""
    parsed = _COMPACT_PLACEHOLDER_BODY_RE.fullmatch(body)
    if parsed is None:
        return None
    modifier = parsed.group("modifier")
    return _InlinePlaceholderToken(
        literal=match.group(0),
        variable_name=parsed.group("var"),
        type_name=parsed.group("type"),
        byte_length=int(parsed.group("length")),
        modifier=modifier if modifier is not None else None,
        start=match.start(),
        end=match.end(),
    )


def _iter_inline_placeholder_tokens(raw_text: str) -> Iterator[_InlinePlaceholderToken]:
    tokens: list[_InlinePlaceholderToken] = [
        _token_from_typed_match(match)
        for match in _INLINE_PLACEHOLDER_RE.finditer(raw_text)
    ]
    for match in _COMPACT_PLACEHOLDER_RE.finditer(raw_text):
        token = _token_from_compact_match(match)
        if token is not None:
            tokens.append(token)
    yield from sorted(tokens, key=lambda token: token.start)


def detect_inline_placeholders(raw_text: str) -> bool:
    """Return True if ``raw_text`` contains at least one inline placeholder."""
    if isinstance(raw_text, str) is False:
        return False
    return next(_iter_inline_placeholder_tokens(raw_text), None) is not None


def iter_inline_placeholders(raw_text: str) -> Iterator[re.Match[str]]:
    """Yield regex matches for every inline placeholder in ``raw_text``."""
    if isinstance(raw_text, str) is False:
        return iter(())
    return _INLINE_PLACEHOLDER_RE.finditer(raw_text)


def extract_inline_placeholders_from_hex_text(hex_text: str) -> list[dict[str, Any]]:
    """Return a structured breakdown of every inline placeholder in ``hex_text``.

    Each entry carries the fields the decoded view needs to render the
    placeholder cleanly: literal text, variable name, declared type,
    declared byte length, optional modifier, and the character offsets
    the literal occupies in ``hex_text``. Empty list on non-string input
    or when no placeholders are present.
    """
    if isinstance(hex_text, str) is False:
        return []
    entries: list[dict[str, Any]] = []
    for token in _iter_inline_placeholder_tokens(hex_text):
        entries.append(
            {
                "literal": token.literal,
                "variable": token.variable_name,
                "type": token.type_name,
                "byte_length": token.byte_length,
                "modifier": token.modifier,
                "start": token.start,
                "end": token.end,
            }
        )
    return entries


def describe_inline_placeholder_hex(
    hex_text: str,
    *,
    field_name: str | None = None,
    ef_key: str | None = None,
) -> dict[str, Any] | None:
    """Build a decoded-view payload for a hex string carrying inline placeholders.

    Returns ``None`` when ``hex_text`` carries no inline typed
    placeholders so callers can fall through to the regular decoded
    cascade. When placeholders are present, the payload lists each
    literal with its declared metadata, plus the surrounding hex
    fragments so the operator can see where the placeholder sits inside
    the field. The output is JSON-serialisable and safe to hand to the
    read-only decoded pane.
    """
    entries = extract_inline_placeholders_from_hex_text(hex_text)
    if len(entries) == 0:
        return None

    segments: list[dict[str, Any]] = []
    cursor = 0
    for entry in entries:
        lead = hex_text[cursor : entry["start"]]
        if len(lead) > 0:
            segments.append({"kind": "hex", "text": lead.upper()})
        segments.append(
            {
                "kind": "placeholder",
                "literal": entry["literal"],
                "variable": entry["variable"],
                "type": entry["type"],
                "byte_length": entry["byte_length"],
                "modifier": entry["modifier"],
            }
        )
        cursor = entry["end"]
    tail = hex_text[cursor:]
    if len(tail) > 0:
        segments.append({"kind": "hex", "text": tail.upper()})

    placeholders_view: list[dict[str, Any]] = []
    for entry in entries:
        placeholder_record: dict[str, Any] = {
            "literal": entry["literal"],
            "variable": entry["variable"],
            "type": entry["type"],
            "byte_length": entry["byte_length"],
        }
        if entry["modifier"] is not None:
            placeholder_record["modifier"] = entry["modifier"]
        placeholders_view.append(placeholder_record)

    payload: dict[str, Any] = {
        "placeholders": placeholders_view,
        "segments": segments,
        "hex_with_literals": hex_text,
    }
    if field_name is not None and len(str(field_name).strip()) > 0:
        payload["field"] = str(field_name).strip()
    if ef_key is not None and len(str(ef_key).strip()) > 0:
        payload["ef"] = str(ef_key).strip()
    return payload


def _sentinel_bytes(index: int, byte_length: int) -> bytes:
    if byte_length < _MIN_PLACEHOLDER_BYTES:
        raise ValueError(
            f"Inline-placeholder byte length must be >= {_MIN_PLACEHOLDER_BYTES} "
            f"(got {byte_length})."
        )
    if byte_length > _MAX_PLACEHOLDER_BYTES:
        raise ValueError(
            f"Inline-placeholder byte length {byte_length} exceeds the "
            f"{_MAX_PLACEHOLDER_BYTES}-byte safety cap."
        )
    material = bytearray()
    counter = 0
    seed = str(index).encode("ascii")
    while len(material) < byte_length:
        digest = hashlib.blake2s(
            seed + b":" + counter.to_bytes(4, "big"),
            digest_size=32,
            person=_SENTINEL_PERSON,
        ).digest()
        material.extend(digest)
        counter += 1
    return bytes(material[:byte_length])


def substitute_inline_placeholders(
    raw_text: str,
) -> tuple[str, list[InlinePlaceholderRecord]]:
    """Replace each inline typed placeholder with a per-index sentinel.

    The caller is still responsible for whitespace/case normalisation of
    the returned text. ``records`` carries one entry per placeholder,
    ordered by appearance, with the sentinel hex run used in the
    rewritten text so a later splice pass can restore the literal.
    """
    if isinstance(raw_text, str) is False:
        raise TypeError("substitute_inline_placeholders requires a string input.")

    records: list[InlinePlaceholderRecord] = []
    sentinels_seen: set[str] = set()
    parts: list[str] = []
    cursor = 0

    for token in _iter_inline_placeholder_tokens(raw_text):
        placeholder_index = len(records)
        if placeholder_index >= _MAX_PLACEHOLDERS_PER_FILE:
            raise ValueError(
                f"Template declares more than {_MAX_PLACEHOLDERS_PER_FILE} "
                f"inline placeholders; refusing to continue."
            )

        byte_length = token.byte_length
        sentinel = _sentinel_bytes(placeholder_index, byte_length).hex().upper()

        # Re-salt and retry if blake2s hands us a sentinel that happens
        # to collide with one already used by this template. Extremely
        # unlikely with blake2s, but the retry keeps the sidecar
        # deterministic and cheap when it does.
        salt = 0
        while sentinel in sentinels_seen and salt < 256:
            salt += 1
            retry = hashlib.blake2s(
                f"{placeholder_index}:{salt}".encode("ascii"),
                digest_size=max(4, min(byte_length, 32)),
                person=_SENTINEL_PERSON,
            ).digest()
            padded = retry + b"\x00" * max(0, byte_length - len(retry))
            sentinel = padded[:byte_length].hex().upper()
        if sentinel in sentinels_seen:
            raise ValueError(
                f"Failed to allocate unique sentinel for placeholder "
                f"{token.literal!r}; report this as a bug."
            )
        sentinels_seen.add(sentinel)

        record = InlinePlaceholderRecord(
            index=placeholder_index,
            literal=token.literal,
            variable_name=token.variable_name,
            type_name=token.type_name,
            byte_length=byte_length,
            modifier=token.modifier,
            sentinel_hex=sentinel,
        )
        records.append(record)

        parts.append(raw_text[cursor:token.start])
        parts.append(sentinel)
        cursor = token.end

    parts.append(raw_text[cursor:])
    return "".join(parts), records


def substitute_inline_placeholders_in_editor_json(
    json_text: str,
) -> tuple[str, frozenset[str], int]:
    """Pre-substitute inline typed placeholders inside an editor JSON buffer.

    Walks the tagged ``hex`` leaves under ``sections.*`` and replaces any
    inline typed placeholder literal with a deterministic per-leaf
    sentinel run. The rewritten text is a valid JSON string whose tagged
    hex leaves satisfy ``bytes.fromhex`` so the lint harness can dejsonify
    the buffer without tripping on the placeholder syntax.

    Returns ``(rewritten_text, paths, count)`` where:

    * ``paths`` — dotted paths (``saipHeader.fileDescriptor`` style; the
      ``sections.`` wrapper is elided to match the path convention used by
      :func:`saip_json_codec.parse_editor_json_template_aware` and the
      lint engine's internal walker). Callers can feed these into the
      linter's ``placeholder_paths`` knob to downgrade findings rooted at
      placeholder-bearing fields.
    * ``count`` — total placeholders substituted across the whole buffer.

    When no inline placeholders are present, ``json_text`` is returned
    unchanged, ``paths`` is an empty set, and ``count`` is zero. The
    function also returns the buffer unchanged if it isn't parseable as
    JSON — callers that care about the syntax error should surface it via
    the strict parse path afterwards.
    """

    if isinstance(json_text, str) is False:
        return json_text, frozenset(), 0
    if detect_inline_placeholders(json_text) is False:
        return json_text, frozenset(), 0

    try:
        loaded = json.loads(json_text)
    except Exception:
        return json_text, frozenset(), 0

    paths: set[str] = set()
    placeholder_count = 0

    def _extend(path: str, key: str) -> str:
        if len(path) == 0:
            return key
        return f"{path}.{key}"

    def _extend_idx(path: str, idx: int) -> str:
        if len(path) == 0:
            return f"[{idx}]"
        return f"{path}[{idx}]"

    def _walk(node: Any, path: str) -> None:
        nonlocal placeholder_count
        if isinstance(node, dict):
            for key, value in list(node.items()):
                key_text = str(key)
                if key_text in _HEX_TAG_KEYS and isinstance(value, str):
                    if detect_inline_placeholders(value):
                        rewritten, records = substitute_inline_placeholders(value)
                        if len(records) > 0:
                            node[key] = rewritten
                            paths.add(path)
                            placeholder_count += len(records)
                    continue
                _walk(value, _extend(path, key_text))
            return
        if isinstance(node, list):
            for idx, item in enumerate(node):
                _walk(item, _extend_idx(path, idx))

    sections = loaded.get("sections") if isinstance(loaded, dict) else None
    if isinstance(sections, dict):
        for section_key, section_payload in sections.items():
            _walk(section_payload, str(section_key))

    if placeholder_count == 0:
        return json_text, frozenset(), 0

    return json.dumps(loaded), frozenset(paths), placeholder_count


def splice_literals_into_tagged_document(
    document: Any,
    records: list[InlinePlaceholderRecord],
) -> int:
    """Walk ``document`` replacing sentinel runs with placeholder literals.

    Target nodes are the ``hex`` tag emitted by
    ``saip_json_codec.jsonify_saip_value`` (and the legacy
    ``__ygg_saip_bytes__`` spelling). The comparison is case-insensitive
    because pySim emits lower-case hex while the sentinel is stored
    upper-case. Returns the total number of sentinel occurrences
    rewritten.
    """
    if len(records) == 0:
        return 0

    sentinels: list[tuple[str, InlinePlaceholderRecord]] = [
        (record.sentinel_hex.upper(), record) for record in records
    ]

    replacement_count = 0

    def _rewrite_hex(hex_text: str) -> str:
        nonlocal replacement_count
        rewritten = hex_text
        changed = True
        while changed:
            changed = False
            upper_view = rewritten.upper()
            for sentinel_hex, record in sentinels:
                idx = upper_view.find(sentinel_hex)
                if idx == -1:
                    continue
                rewritten = (
                    rewritten[:idx]
                    + record.literal
                    + rewritten[idx + len(sentinel_hex):]
                )
                replacement_count += 1
                changed = True
                break
        return rewritten

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in list(node.items()):
                if key in _HEX_TAG_KEYS and isinstance(value, str):
                    node[key] = _rewrite_hex(value)
                    continue
                _walk(value)
            return
        if isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(document)
    return replacement_count


def records_to_sidecar_payload(
    records: list[InlinePlaceholderRecord],
) -> dict[str, Any]:
    """Serialize placeholder records to the on-disk sidecar shape."""
    return {
        "version": _SIDECAR_VERSION,
        "placeholders": [
            {
                "index": record.index,
                "literal": record.literal,
                "variable": record.variable_name,
                "type": record.type_name,
                "byte_length": record.byte_length,
                "modifier": record.modifier,
                "sentinel_hex": record.sentinel_hex,
            }
            for record in records
        ],
    }


def sidecar_payload_to_records(payload: Any) -> list[InlinePlaceholderRecord]:
    """Deserialize a sidecar payload back to ``InlinePlaceholderRecord``s."""
    if isinstance(payload, dict) is False:
        raise ValueError("Inline-placeholder sidecar must be a JSON object.")
    raw_entries = payload.get("placeholders")
    if isinstance(raw_entries, list) is False:
        raise ValueError("Sidecar payload is missing a 'placeholders' list.")

    records: list[InlinePlaceholderRecord] = []
    for entry in raw_entries:
        if isinstance(entry, dict) is False:
            raise ValueError("Each sidecar placeholder entry must be a JSON object.")
        try:
            index = int(entry["index"])
            literal = str(entry["literal"])
            variable = str(entry["variable"])
            type_name = str(entry["type"])
            byte_length = int(entry["byte_length"])
            sentinel_hex = str(entry["sentinel_hex"])
        except KeyError as error:
            raise ValueError(
                f"Sidecar placeholder entry is missing required field: {error}"
            ) from error
        modifier_raw = entry.get("modifier")
        modifier = None if modifier_raw is None else str(modifier_raw)
        records.append(
            InlinePlaceholderRecord(
                index=index,
                literal=literal,
                variable_name=variable,
                type_name=type_name,
                byte_length=byte_length,
                modifier=modifier,
                sentinel_hex=sentinel_hex,
            )
        )
    return records


def write_sidecar(path: Path, records: list[InlinePlaceholderRecord]) -> None:
    """Write a JSON sidecar capturing every placeholder in ``records``."""
    target = Path(path)
    target.write_text(
        json.dumps(records_to_sidecar_payload(records), indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )


def read_sidecar(path: Path) -> list[InlinePlaceholderRecord]:
    """Load placeholder records from a sidecar produced by :func:`write_sidecar`."""
    source = Path(path)
    payload = json.loads(source.read_text(encoding="utf-8"))
    return sidecar_payload_to_records(payload)


def sidecar_path_for_cache(cache_path: Path) -> Path:
    """Return the conventional sidecar path for a cached DER payload."""
    return Path(cache_path).with_suffix(_SIDECAR_SUFFIX)
