# SPDX-License-Identifier: GPL-3.0-or-later
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

The placeholder itself is treated as opaque while it is substituted:
only the declared byte length matters. Resolving placeholders to real
bytes remains the job of the native JSON template surface
(``__ygg_token_defs__`` / ``APPLY-TEMPLATE``) and of the test-value
lists. What this module also owns is the spelling: the four styles a
literal can be written in (:data:`PLACEHOLDER_STYLES`), the
spelling-independent key that names one placeholder across them
(:func:`placeholder_key_fold`) and the renderer that rewrites a literal
in a given style (:func:`format_placeholder_literal`). The typed form is
the default style (:data:`DEFAULT_PLACEHOLDER_STYLE`): a writer uses it
wherever neither a list's ``# style:`` line nor its entries decide.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from yggdrasim_common.secure_files import (
    atomic_write_bytes,
    read_bounded_regular_file,
)


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
    r"(?P<type>ICCID|IMSI|MSISDN|BINARY|TEXT|RI|OPLMN)"
    r"(?P<length>\d+)"
    r"(?P<modifier>[A-Za-z_][A-Za-z0-9_]*)?$"
)


PLACEHOLDER_STYLE_COMPACT = "compact"
PLACEHOLDER_STYLE_TYPED = "typed"
PLACEHOLDER_STYLE_BRACE = "brace"
PLACEHOLDER_STYLE_BRACKET = "bracket"
PLACEHOLDER_STYLES: tuple[str, ...] = (
    PLACEHOLDER_STYLE_COMPACT,
    PLACEHOLDER_STYLE_TYPED,
    PLACEHOLDER_STYLE_BRACE,
    PLACEHOLDER_STYLE_BRACKET,
)
# The typed form is the spelling the operator's templates and lists use. The
# compact styles are still read (vendor templates) and a list written in one
# keeps it, but nothing chooses them unless the list or the entry already did.
DEFAULT_PLACEHOLDER_STYLE = PLACEHOLDER_STYLE_TYPED
PLACEHOLDER_STYLE_EXAMPLES: dict[str, str] = {
    PLACEHOLDER_STYLE_COMPACT: "iccidICCID10NibbleSwap",
    PLACEHOLDER_STYLE_TYPED: "{iccid:ICCID:10:nibble_swap}",
    PLACEHOLDER_STYLE_BRACE: "{iccidICCID10NibbleSwap}",
    PLACEHOLDER_STYLE_BRACKET: "[iccidICCID10NibbleSwap]",
}

# One modifier, several spellings: the typed grammar writes snake_case
# (``nibble_swap``, ``utf_8``), the compact grammar CamelCase (``NibbleSwap``,
# ``utf8``) and vendor templates also carry ``swapnibbles``. Keyed by the normalised
# form (case-folded, ``_`` and ``-`` dropped); the values are the typed
# and the compact spelling a renderer writes.
_MODIFIER_SPELLINGS: dict[str, tuple[str, str]] = {
    "nibbleswap": ("nibble_swap", "NibbleSwap"),
    "swapnibbles": ("swap_nibbles", "SwapNibbles"),
    "encodeimsi": ("encode_imsi", "EncodeIMSI"),
    "utf8": ("utf_8", "utf8"),
}
# ``swapnibbles`` selects the same ICCID wire form as ``nibbleswap``.
_MODIFIER_FOLD_ALIASES: dict[str, str] = {"swapnibbles": "nibbleswap"}

_MIN_PLACEHOLDER_BYTES = 2
_MAX_PLACEHOLDER_BYTES = 4096
_MAX_PLACEHOLDERS_PER_FILE = 2048

_SIDECAR_VERSION = 1
_SIDECAR_SUFFIX = ".placeholders.json"
_MAX_SIDECAR_BYTES = 16 * 1024 * 1024

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


def parse_placeholder_literal(literal: str) -> dict[str, Any] | None:
    """Split one placeholder literal into its parts, or ``None`` for non-literals.

    Both grammars are accepted, with or without their braces / brackets:
    ``{iccid:ICCID:10:NibbleSwap}`` and ``iccidICCID10NibbleSwap`` both give
    ``{"variable": "iccid", "type": "ICCID", "byte_length": 10,
    "modifier": "NibbleSwap", "key": "iccidICCID10NibbleSwap"}``. ``key``
    is the compact body, the form a universal token list is keyed by.
    """
    text = str(literal or "").strip()
    if len(text) >= 2 and text[0] in "{[" and text[-1] in "}]":
        text = text[1:-1].strip()
    if not text:
        return None
    typed = _INLINE_PLACEHOLDER_RE.fullmatch("{" + text + "}")
    if typed is not None:
        modifier = typed.group("modifier")
        parts = {
            "variable": typed.group("var"),
            "type": typed.group("type"),
            "byte_length": int(typed.group("length")),
            "modifier": modifier,
        }
    else:
        compact = _COMPACT_PLACEHOLDER_BODY_RE.fullmatch(text)
        if compact is None:
            return None
        modifier = compact.group("modifier")
        parts = {
            "variable": compact.group("var"),
            "type": compact.group("type"),
            "byte_length": int(compact.group("length")),
            "modifier": modifier,
        }
    parts["key"] = (
        f"{parts['variable']}{parts['type']}{parts['byte_length']}{modifier or ''}"
    )
    return parts


def strip_placeholder_delimiters(literal: Any) -> str:
    """Return ``literal`` without one surrounding pair of braces or brackets."""
    text = str(literal or "").strip()
    if len(text) >= 2 and text[0] in "{[" and text[-1] in "}]":
        return text[1:-1].strip()
    return text


def normalise_placeholder_modifier(modifier: Any, type_name: Any = "") -> str:
    """Return the comparison form of a modifier.

    Case-folded with ``_`` and ``-`` dropped, so ``NibbleSwap``,
    ``nibble_swap`` and ``nibbleswap`` are one modifier; ``SwapNibbles``
    folds onto it too, since it selects the same ICCID wire form. A
    ``utf8`` / ``utf-8`` modifier on a TEXT placeholder folds to nothing:
    UTF-8 is what TEXT encodes to without one.
    """
    folded = str(modifier or "").strip().casefold().replace("_", "").replace("-", "")
    folded = _MODIFIER_FOLD_ALIASES.get(folded, folded)
    if folded == "utf8" and str(type_name or "").strip().upper() == "TEXT":
        return ""
    return folded


def placeholder_key_fold(literal: Any) -> str:
    """Return the spelling-independent key of a placeholder literal or list name.

    ``{iccid:ICCID:10:nibble_swap}``, ``[iccidICCID10NibbleSwap]`` and
    ``iccidICCID10SwapNibbles`` all fold to ``iccid|ICCID|10|nibbleswap``;
    the variable keeps its case-folded spelling. A name that is not a
    placeholder (a ``{NAME}`` token) folds to its case-folded name without
    delimiters.
    """
    parts = parse_placeholder_literal(literal)
    if parts is None:
        return strip_placeholder_delimiters(literal).casefold()
    return (
        f"{str(parts['variable']).casefold()}|{str(parts['type']).upper()}|"
        f"{int(parts['byte_length'])}|"
        f"{normalise_placeholder_modifier(parts['modifier'], parts['type'])}"
    )


def placeholder_key_fold_relaxed(literal: Any) -> str:
    """Return :func:`placeholder_key_fold` with underscores dropped from the variable.

    ``{scp80_kic1:BINARY:16}`` and ``[scp80kic1BINARY16]`` name one
    variable in the typed and the compact grammar. Empty for a name that is
    not a placeholder, so a plain token name never matches loosely.
    """
    if parse_placeholder_literal(literal) is None:
        return ""
    return placeholder_key_fold(literal).replace("_", "")


def placeholder_literal_style(literal: Any) -> str | None:
    """Return the style a literal is written in, or ``None`` for a non-placeholder.

    ``typed`` is ``{var:TYPE:len[:modifier]}``; the compact body
    ``varTYPElen[Modifier]`` is ``compact`` bare, ``brace`` in ``{}`` and
    ``bracket`` in ``[]``.
    """
    text = str(literal or "").strip()
    body = strip_placeholder_delimiters(text)
    if not body:
        return None
    if _INLINE_PLACEHOLDER_RE.fullmatch("{" + body + "}") is not None:
        return PLACEHOLDER_STYLE_TYPED
    if _COMPACT_PLACEHOLDER_BODY_RE.fullmatch(body) is None:
        return None
    if body == text:
        return PLACEHOLDER_STYLE_COMPACT
    if text[0] == "[":
        return PLACEHOLDER_STYLE_BRACKET
    return PLACEHOLDER_STYLE_BRACE


def format_placeholder_literal(
    literal: Any,
    style: str = DEFAULT_PLACEHOLDER_STYLE,
) -> str:
    """Rewrite a placeholder literal, or a list name, in ``style``.

    The typed style spells a known modifier in snake_case
    (``nibble_swap``), the compact styles in CamelCase (``NibbleSwap``); a
    modifier outside that vocabulary is kept as written. A ``{NAME}``
    token has no typed form: it keeps its name and takes the style's
    delimiters (none for ``compact``).
    """
    if style not in PLACEHOLDER_STYLES:
        raise ValueError(
            f"Unknown placeholder style {style!r}; use one of "
            f"{', '.join(PLACEHOLDER_STYLES)}."
        )
    parts = parse_placeholder_literal(literal)
    if parts is None:
        name = strip_placeholder_delimiters(literal)
        if style == PLACEHOLDER_STYLE_COMPACT:
            return name
        if style == PLACEHOLDER_STYLE_BRACKET:
            return f"[{name}]"
        return "{" + name + "}"
    modifier = str(parts["modifier"] or "")
    folded = modifier.strip().casefold().replace("_", "").replace("-", "")
    spellings = _MODIFIER_SPELLINGS.get(folded)
    if style == PLACEHOLDER_STYLE_TYPED:
        spelt = spellings[0] if spellings is not None else modifier
        body = f"{parts['variable']}:{parts['type']}:{parts['byte_length']}"
        return "{" + body + (f":{spelt}" if spelt else "") + "}"
    spelt = spellings[1] if spellings is not None else modifier
    body = f"{parts['variable']}{parts['type']}{parts['byte_length']}{spelt}"
    if style == PLACEHOLDER_STYLE_BRACE:
        return "{" + body + "}"
    if style == PLACEHOLDER_STYLE_BRACKET:
        return f"[{body}]"
    return body


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


INLINE_PLACEHOLDER_TYPES: tuple[str, ...] = (
    "ICCID",
    "IMSI",
    "MSISDN",
    "BINARY",
    "TEXT",
    "RI",
    "OPLMN",
)
# The modifiers a placeholder declared in the workbench may carry, per
# type, in the comparison form of ``normalise_placeholder_modifier``. A
# vendor template is read as it comes; a literal typed into an editor is
# checked here so a misspelt modifier is refused before it is stored.
_INLINE_MODIFIERS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "ICCID": ("", "nibbleswap"),
    "IMSI": ("", "encodeimsi"),
    "MSISDN": ("", "nibbleswap"),
    "TEXT": ("",),
    "BINARY": ("",),
    "RI": ("",),
    "OPLMN": ("",),
}


def validate_inline_placeholder_parts(
    type_name: Any,
    byte_length: Any,
    modifier: Any = None,
    *,
    literal: str = "",
) -> None:
    """Refuse the parts of a placeholder the workbench cannot encode.

    The type must be one of :data:`INLINE_PLACEHOLDER_TYPES`, the width
    within the sentinel bounds, an ICCID exactly ten bytes, and the
    modifier one the type knows (``nibble_swap`` for ICCID and MSISDN,
    ``encode_imsi`` for IMSI, none for the rest).
    """
    label = literal or "placeholder"
    type_text = str(type_name or "").strip().upper()
    if type_text not in INLINE_PLACEHOLDER_TYPES:
        raise ValueError(
            f"{label}: unknown placeholder type {type_name!r}; use one of "
            f"{', '.join(INLINE_PLACEHOLDER_TYPES)}."
        )
    try:
        width = int(byte_length)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label}: the byte length must be a whole number.") from error
    if width < _MIN_PLACEHOLDER_BYTES or width > _MAX_PLACEHOLDER_BYTES:
        raise ValueError(
            f"{label}: the byte length must be between {_MIN_PLACEHOLDER_BYTES} and "
            f"{_MAX_PLACEHOLDER_BYTES}."
        )
    if type_text == "ICCID" and width != 10:
        raise ValueError(f"{label}: an ICCID placeholder is 10 bytes (ITU-T E.118).")
    if type_text == "IMSI" and width != 8:
        raise ValueError(
            f"{label}: an IMSI placeholder covers the 8 bytes after the length byte "
            "of EF.IMSI (3GPP TS 31.102 section 4.2.2)."
        )
    allowed = _INLINE_MODIFIERS_BY_TYPE[type_text]
    folded = normalise_placeholder_modifier(modifier, type_text)
    if folded not in allowed:
        spelt = [spelling[0] for key, spelling in _MODIFIER_SPELLINGS.items() if key in allowed]
        raise ValueError(
            f"{label}: modifier {modifier!r} is not one a {type_text} placeholder "
            f"takes ({', '.join(spelt) if spelt else 'none'})."
        )


def _unique_sentinel_hex(index: int, byte_length: int, taken: set[str]) -> str:
    """A sentinel run for ``index`` that collides with none in ``taken``."""
    sentinel = _sentinel_bytes(index, byte_length).hex().upper()
    salt = 0
    while sentinel in taken and salt < 256:
        salt += 1
        retry = hashlib.blake2s(
            f"{index}:{salt}".encode("ascii"),
            digest_size=max(4, min(byte_length, 32)),
            person=_SENTINEL_PERSON,
        ).digest()
        padded = retry + b"\x00" * max(0, byte_length - len(retry))
        sentinel = padded[:byte_length].hex().upper()
    if sentinel in taken:
        raise ValueError(
            f"Failed to allocate a unique sentinel for placeholder #{index}; "
            "report this as a bug."
        )
    return sentinel


def _placeholder_parts_fold(
    variable_name: Any, type_name: Any, byte_length: Any, modifier: Any
) -> tuple[str, str, int, str]:
    type_text = str(type_name or "").strip().upper()
    return (
        str(variable_name or "").casefold(),
        type_text,
        int(byte_length or 0),
        normalise_placeholder_modifier(modifier, type_text),
    )


def allocate_inline_placeholder_records(
    texts: Iterable[str],
    *,
    existing: Iterable[InlinePlaceholderRecord] = (),
    reusable: Iterable[InlinePlaceholderRecord] = (),
) -> tuple[list[str], list[InlinePlaceholderRecord], list[InlinePlaceholderRecord]]:
    """Replace the placeholder literals of edited texts with sentinel runs.

    A literal whose parts (variable, type, width, modifier) match a record
    in ``reusable`` takes that record's sentinel, first come first served,
    so a projection that showed a placeholder as its literal round-trips to
    the same occurrence. Every other literal gets a new record: its index
    follows the highest one in ``existing`` and ``reusable``, its sentinel
    collides with none of theirs, and its parts pass
    :func:`validate_inline_placeholder_parts`. Returns the rewritten texts
    (a text without a literal comes back unchanged), the new records and
    the reused ones.
    """
    existing_list = list(existing)
    pool = list(reusable)
    taken = {
        str(record.sentinel_hex or "").upper()
        for record in existing_list + pool
        if str(record.sentinel_hex or "").strip()
    }
    next_index = max((int(record.index) for record in existing_list + pool), default=-1) + 1
    rewritten: list[str] = []
    new_records: list[InlinePlaceholderRecord] = []
    reused: list[InlinePlaceholderRecord] = []
    for text in texts:
        if isinstance(text, str) is False or detect_inline_placeholders(text) is False:
            rewritten.append(text)
            continue
        parts: list[str] = []
        cursor = 0
        for token in _iter_inline_placeholder_tokens(text):
            fold = _placeholder_parts_fold(
                token.variable_name, token.type_name, token.byte_length, token.modifier
            )
            match = next(
                (
                    record
                    for record in pool
                    if _placeholder_parts_fold(
                        record.variable_name, record.type_name, record.byte_length, record.modifier
                    )
                    == fold
                ),
                None,
            )
            if match is not None:
                pool.remove(match)
                reused.append(match)
                sentinel = str(match.sentinel_hex).upper()
            else:
                validate_inline_placeholder_parts(
                    token.type_name, token.byte_length, token.modifier, literal=token.literal
                )
                if len(existing_list) + len(new_records) >= _MAX_PLACEHOLDERS_PER_FILE:
                    raise ValueError(
                        f"The template would carry more than {_MAX_PLACEHOLDERS_PER_FILE} "
                        "inline placeholders; refusing to continue."
                    )
                sentinel = _unique_sentinel_hex(next_index, token.byte_length, taken)
                new_records.append(
                    InlinePlaceholderRecord(
                        index=next_index,
                        literal=token.literal,
                        variable_name=token.variable_name,
                        type_name=token.type_name,
                        byte_length=token.byte_length,
                        modifier=token.modifier,
                        sentinel_hex=sentinel,
                    )
                )
                taken.add(sentinel)
                next_index += 1
            parts.append(text[cursor:token.start])
            parts.append(sentinel)
            cursor = token.end
        parts.append(text[cursor:])
        rewritten.append("".join(parts))
    return rewritten, new_records, reused


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

    * ``paths`` -- dotted paths (``saipHeader.fileDescriptor`` style; the
      ``sections.`` wrapper is elided to match the path convention used by
      :func:`saip_json_codec.parse_editor_json_template_aware` and the
      lint engine's internal walker). Callers can feed these into the
      linter's ``placeholder_paths`` knob to downgrade findings rooted at
      placeholder-bearing fields.
    * ``count`` -- total placeholders substituted across the whole buffer.

    When no inline placeholders are present, ``json_text`` is returned
    unchanged, ``paths`` is an empty set, and ``count`` is zero. The
    function also returns the buffer unchanged if it isn't parseable as
    JSON -- callers that care about the syntax error should surface it via
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

    replacement_count = 0

    def _walk(node: Any) -> None:
        nonlocal replacement_count
        if isinstance(node, dict):
            for key, value in list(node.items()):
                if key in _HEX_TAG_KEYS and isinstance(value, str):
                    node[key], hits = splice_literals_into_hex_text(value, records)
                    replacement_count += hits
                    continue
                _walk(value)
            return
        if isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(document)
    return replacement_count


def splice_literals_into_hex_text(
    hex_text: str,
    records: Iterable[InlinePlaceholderRecord],
) -> tuple[str, int]:
    """Replace every sentinel run in ``hex_text`` with its placeholder literal.

    The comparison is case-insensitive on the hex side, matching
    :func:`splice_literals_into_tagged_document`. Returns the rewritten
    text and the number of runs replaced; text without a sentinel comes
    back unchanged.
    """
    sentinels: list[tuple[str, InlinePlaceholderRecord]] = [
        (record.sentinel_hex.upper(), record) for record in records
    ]
    if len(sentinels) == 0 or isinstance(hex_text, str) is False:
        return hex_text, 0
    rewritten = hex_text
    replacement_count = 0
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
    return rewritten, replacement_count


_HEX_RUN_RE = re.compile(r"^[0-9A-Fa-f]+$")


def splice_literals_into_projection(
    node: Any,
    records: Iterable[InlinePlaceholderRecord],
) -> int:
    """Rewrite sentinel runs inside every hex-looking string of a JSON tree.

    The GUI's PE and file projections flatten bytes to plain uppercase hex
    strings rather than the ``{"hex": ...}`` nodes the tagged document
    carries, so :func:`splice_literals_into_tagged_document` never sees
    them. This walker rewrites any string made only of hex digits --
    dict values and list items alike -- in place and returns the number
    of runs replaced. Strings carrying other characters are left alone.
    """
    record_list = list(records)
    if len(record_list) == 0:
        return 0
    replacement_count = 0

    def _maybe_rewrite(value: str) -> str:
        nonlocal replacement_count
        if len(value) < 4 or _HEX_RUN_RE.fullmatch(value) is None:
            return value
        rewritten, hits = splice_literals_into_hex_text(value, record_list)
        replacement_count += hits
        return rewritten

    def _walk(current: Any) -> None:
        if isinstance(current, dict):
            for key, value in list(current.items()):
                if isinstance(value, str):
                    current[key] = _maybe_rewrite(value)
                    continue
                _walk(value)
            return
        if isinstance(current, list):
            for index, value in enumerate(current):
                if isinstance(value, str):
                    current[index] = _maybe_rewrite(value)
                    continue
                _walk(value)

    _walk(node)
    return replacement_count


def locate_sentinels_in_bytes(
    data: bytes,
    records: Iterable[InlinePlaceholderRecord],
) -> list[dict[str, Any]]:
    """Return the byte range of every sentinel occurrence inside ``data``.

    Each entry carries ``start`` / ``end`` (end exclusive) plus the
    record's literal and declared metadata, sorted by offset. The bytes
    themselves are left untouched, so a hex dump can stay a valid image
    while the ranges label where a placeholder sits.
    """
    payload = bytes(data)
    ranges: list[dict[str, Any]] = []
    for record in records:
        try:
            sentinel = bytes.fromhex(record.sentinel_hex)
        except ValueError:
            continue
        if len(sentinel) == 0:
            continue
        cursor = 0
        while True:
            start = payload.find(sentinel, cursor)
            if start == -1:
                break
            ranges.append(
                {
                    "start": start,
                    "end": start + len(sentinel),
                    "index": record.index,
                    "literal": record.literal,
                    "variable": record.variable_name,
                    "type": record.type_name,
                    "byte_length": record.byte_length,
                    "modifier": record.modifier,
                }
            )
            cursor = start + len(sentinel)
    ranges.sort(key=lambda entry: (entry["start"], entry["index"]))
    return ranges


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
    payload = (
        json.dumps(records_to_sidecar_payload(records), indent=2, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    if len(payload) > _MAX_SIDECAR_BYTES:
        raise ValueError("placeholder sidecar exceeds the safety limit")
    atomic_write_bytes(
        target,
        payload,
    )


def read_sidecar(path: Path) -> list[InlinePlaceholderRecord]:
    """Load placeholder records from a sidecar produced by :func:`write_sidecar`."""
    source = Path(path)
    encoded = read_bounded_regular_file(source, _MAX_SIDECAR_BYTES)
    payload = json.loads(encoded.decode("utf-8"))
    return sidecar_payload_to_records(payload)


def sidecar_path_for_cache(cache_path: Path) -> Path:
    """Return the conventional sidecar path for a cached DER payload."""
    return Path(cache_path).with_suffix(_SIDECAR_SUFFIX)
