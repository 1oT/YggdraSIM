# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP ASN.1 value-notation import.

Vendor profile templates sometimes ship a text file containing one
``ProfileElement ::= choice : { ... }`` assignment per PE. This parser
supports the value-notation subset emitted by those templates and builds
the same pySim ``ProfileElementSequence`` used by DER imports.
"""

from __future__ import annotations

import inspect
import re
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from Tools.ProfilePackage.saip_hex_template import (
    InlinePlaceholderRecord,
    substitute_inline_placeholders,
)


class SaipAsn1ValueError(ValueError):
    """Raised when SAIP ASN.1 value notation cannot be parsed."""


@dataclass(frozen=True)
class ParsedAsn1ValuePackage:
    """Decoded package plus placeholder records extracted from text."""

    pes: Any
    inline_placeholder_records: list[InlinePlaceholderRecord]


@dataclass(frozen=True)
class _Token:
    kind: str
    value: Any
    offset: int


_IDENT_START_RE = re.compile(r"[A-Za-z_]")
_IDENT_BODY_RE = re.compile(r"[A-Za-z0-9_-]")
_INTEGER_NAMED_BLOCK_RE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9_-]*)\s+(?:::=[\s]+)?INTEGER\s*\{(?P<body>.*?)\}",
    re.DOTALL,
)
_NAMED_NUMBER_RE = re.compile(r"([A-Za-z][A-Za-z0-9_-]*)\s*\(\s*(-?\d+)\s*\)")
_FIELD_NAME_ALIASES = {
    "keyCompontents": "keyComponents",
}


class _Lexer:
    def __init__(self, text: str) -> None:
        self._text = text
        self._pos = 0
        self._length = len(text)

    def tokens(self) -> list[_Token]:
        tokens: list[_Token] = []
        while True:
            self._skip_ignored()
            if self._pos >= self._length:
                tokens.append(_Token("EOF", "", self._pos))
                return tokens
            start = self._pos
            ch = self._text[self._pos]
            if self._text.startswith("::=", self._pos):
                self._pos += 3
                tokens.append(_Token("ASSIGN", "::=", start))
                continue
            if ch in "{}:,":
                self._pos += 1
                tokens.append(_Token(ch, ch, start))
                continue
            if ch == '"':
                tokens.append(_Token("STRING", self._read_string(), start))
                continue
            if ch == "'":
                tokens.append(_Token("HEX", self._read_hex_string(), start))
                continue
            if ch.isdigit():
                tokens.append(_Token("NUMBER", self._read_number(), start))
                continue
            if _IDENT_START_RE.fullmatch(ch) is not None:
                tokens.append(_Token("IDENT", self._read_identifier(), start))
                continue
            raise SaipAsn1ValueError(
                f"Unexpected character {ch!r} at byte offset {start}."
            )

    def _skip_ignored(self) -> None:
        while self._pos < self._length:
            ch = self._text[self._pos]
            if ch.isspace():
                self._pos += 1
                continue
            if self._text.startswith("--", self._pos):
                newline = self._text.find("\n", self._pos)
                if newline == -1:
                    self._pos = self._length
                else:
                    self._pos = newline + 1
                continue
            break

    def _read_identifier(self) -> str:
        start = self._pos
        self._pos += 1
        while self._pos < self._length:
            if _IDENT_BODY_RE.fullmatch(self._text[self._pos]) is None:
                break
            self._pos += 1
        return self._text[start:self._pos]

    def _read_number(self) -> int:
        start = self._pos
        while self._pos < self._length and self._text[self._pos].isdigit():
            self._pos += 1
        return int(self._text[start:self._pos], 10)

    def _read_string(self) -> str:
        self._pos += 1
        chars: list[str] = []
        while self._pos < self._length:
            ch = self._text[self._pos]
            self._pos += 1
            if ch == '"':
                return "".join(chars)
            if ch == "\\" and self._pos < self._length:
                chars.append(self._text[self._pos])
                self._pos += 1
                continue
            chars.append(ch)
        raise SaipAsn1ValueError("Unterminated double-quoted string.")

    def _read_hex_string(self) -> bytes:
        self._pos += 1
        start = self._pos
        end = self._text.find("'", start)
        if end == -1:
            raise SaipAsn1ValueError("Unterminated ASN.1 hex string.")
        payload = self._text[start:end]
        self._pos = end + 1
        if self._pos >= self._length or self._text[self._pos] not in "Hh":
            raise SaipAsn1ValueError("ASN.1 hex string must be followed by H.")
        self._pos += 1
        normalized = "".join(payload.split()).upper()
        if len(normalized) % 2 != 0:
            raise SaipAsn1ValueError("ASN.1 hex string has odd-length payload.")
        try:
            return bytes.fromhex(normalized)
        except ValueError as error:
            raise SaipAsn1ValueError(
                "ASN.1 hex string contains non-hex characters. "
                "Use typed placeholders with an embedded byte length."
            ) from error


class _Parser:
    def __init__(self, tokens: list[_Token], named_numbers: dict[str, int]) -> None:
        self._tokens = tokens
        self._idx = 0
        self._named_numbers = named_numbers

    def parse_profile_elements(self) -> list[tuple[str, OrderedDict[str, Any]]]:
        elements: list[tuple[str, OrderedDict[str, Any]]] = []
        while self._peek().kind != "EOF":
            _label = self._expect("IDENT").value
            type_name = self._expect("IDENT").value
            if type_name != "ProfileElement":
                raise self._error(f"Expected ProfileElement, got {type_name!r}.")
            self._expect("ASSIGN")
            pe_type = self._expect("IDENT").value
            self._expect(":")
            decoded = self._parse_value()
            if isinstance(decoded, OrderedDict) is False:
                raise self._error(
                    f"ProfileElement {pe_type!r} value must be a SEQUENCE."
                )
            elements.append((str(pe_type), decoded))
        return elements

    def _parse_value(self) -> Any:
        token = self._peek()
        if token.kind == "{":
            return self._parse_braced()
        if token.kind == "HEX":
            return self._advance().value
        if token.kind == "STRING":
            return self._advance().value
        if token.kind == "NUMBER":
            return self._advance().value
        if token.kind == "IDENT":
            ident = str(self._advance().value)
            if ident == "NULL":
                return None
            if self._match(":"):
                return (ident, self._parse_value())
            if ident in self._named_numbers:
                return self._named_numbers[ident]
            return ident
        raise self._error(f"Expected value, got {token.kind}.")

    def _parse_braced(self) -> Any:
        self._expect("{")
        if self._match("}"):
            return []
        if self._braced_value_is_oid():
            values: list[str] = []
            while self._peek().kind != "}":
                values.append(str(self._expect("NUMBER").value))
            self._expect("}")
            return ".".join(values)

        entries: list[tuple[str, Any, Any]] = []
        while self._peek().kind != "}":
            token = self._peek()
            if token.kind == "IDENT":
                name = str(self._advance().value)
                if self._match(":"):
                    entries.append(("choice", name, self._parse_value()))
                else:
                    entries.append(("field", name, self._parse_value()))
            else:
                entries.append(("value", None, self._parse_value()))
            self._match(",")
        self._expect("}")

        kinds = {entry[0] for entry in entries}
        if kinds == {"field"}:
            out: OrderedDict[str, Any] = OrderedDict()
            for _kind, name, value in entries:
                field_name = _FIELD_NAME_ALIASES.get(str(name), str(name))
                out[field_name] = value
            return out
        if kinds == {"choice"}:
            return [(str(name), value) for _kind, name, value in entries]
        if kinds == {"value"}:
            return [value for _kind, _name, value in entries]
        raise self._error("Cannot mix ASN.1 field, CHOICE, and bare-list entries.")

    def _braced_value_is_oid(self) -> bool:
        depth = 1
        idx = self._idx
        saw_number = False
        while idx < len(self._tokens):
            token = self._tokens[idx]
            if token.kind == "{":
                if depth == 1:
                    return False
                depth += 1
                idx += 1
                continue
            if token.kind == "}":
                depth -= 1
                if depth == 0:
                    return saw_number
                idx += 1
                continue
            if depth == 1:
                if token.kind != "NUMBER":
                    return False
                saw_number = True
            idx += 1
        return False

    def _peek(self) -> _Token:
        return self._tokens[self._idx]

    def _advance(self) -> _Token:
        token = self._tokens[self._idx]
        self._idx += 1
        return token

    def _match(self, kind: str) -> bool:
        if self._peek().kind != kind:
            return False
        self._idx += 1
        return True

    def _expect(self, kind: str) -> _Token:
        token = self._peek()
        if token.kind != kind:
            raise self._error(f"Expected {kind}, got {token.kind}.")
        return self._advance()

    def _error(self, message: str) -> SaipAsn1ValueError:
        token = self._peek()
        return SaipAsn1ValueError(f"{message} At byte offset {token.offset}.")


def parse_asn1_value_profile(
    text: str,
    *,
    workspace_root: Path,
) -> ParsedAsn1ValuePackage:
    """Parse SAIP ASN.1 value notation and return a decoded PE sequence."""
    from Tools.ProfilePackage.saip_json_codec import ensure_workspace_pysim_on_path

    ensure_workspace_pysim_on_path(Path(workspace_root))

    from pySim.esim.saip import ProfileElement, ProfileElementSequence

    substituted_text, placeholder_records = substitute_inline_placeholders(text)
    named_numbers = _load_named_numbers()
    tokens = _Lexer(substituted_text).tokens()
    parsed_elements = _Parser(tokens, named_numbers).parse_profile_elements()

    pes = ProfileElementSequence()
    pes.pe_list = []
    for pe_type, decoded in parsed_elements:
        _apply_value_notation_defaults(decoded)
        try:
            pe_cls = ProfileElement.class_for_petype(pe_type)
            if pe_cls is not None:
                pe = pe_cls(decoded, pe_sequence=pes)
            else:
                pe = ProfileElement(decoded, pe_sequence=pes)
                pe.type = pe_type
            if hasattr(pe, "_post_decode"):
                pe._post_decode()
        except Exception as error:
            detail = str(error).strip() or error.__class__.__name__
            raise SaipAsn1ValueError(
                f"Failed to build PE {pe_type!r} from ASN.1 value notation: {detail}"
            ) from error
        pes.pe_list.append(pe)

    try:
        der = pes.to_der()
        pes = ProfileElementSequence.from_der(der)
    except Exception as error:
        detail = str(error).strip() or error.__class__.__name__
        raise SaipAsn1ValueError(
            f"Failed to encode ASN.1 value notation as SAIP DER: {detail}"
        ) from error
    return ParsedAsn1ValuePackage(
        pes=pes,
        inline_placeholder_records=placeholder_records,
    )


def _apply_value_notation_defaults(node: Any) -> None:
    """Apply defaults pySim expects before post-decode hooks run."""
    if isinstance(node, dict):
        if "keyType" in node and "keyData" in node and "macLength" not in node:
            node["macLength"] = 8
        for value in node.values():
            _apply_value_notation_defaults(value)
        return
    if isinstance(node, list):
        for item in node:
            _apply_value_notation_defaults(item)
        return
    if isinstance(node, tuple) and len(node) == 2:
        _apply_value_notation_defaults(node[1])


def _load_named_numbers() -> dict[str, int]:
    """Load named INTEGER values from pySim's bundled SAIP ASN.1 files."""
    from pySim.esim import saip as pysaip

    package_root = Path(inspect.getfile(pysaip)).resolve().parents[1]
    asn1_root = package_root / "asn1" / "saip"
    values: dict[str, int] = {}
    for path in sorted(asn1_root.glob("*.asn")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        text = _strip_asn1_comments(text)
        for block in _INTEGER_NAMED_BLOCK_RE.finditer(text):
            for name, raw_value in _NAMED_NUMBER_RE.findall(block.group("body")):
                parsed = int(raw_value, 10)
                existing = values.get(name)
                if existing is not None and existing != parsed:
                    continue
                values[name] = parsed
    return values


def _strip_asn1_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"--.*?(?:\n|$)", "\n", text)
    return text
