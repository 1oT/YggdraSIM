# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SAIP ASN.1 value-notation import and export.

Vendor profile templates sometimes ship a text file containing one
``ProfileElement ::= choice : { ... }`` assignment per PE. This parser
supports the value-notation subset emitted by those templates and builds
the same pySim ``ProfileElementSequence`` used by DER imports. The
schema-guided renderer emits that same subset from a decoded pySim
sequence, including inline placeholder literals used by ``.varder``
templates.
"""

from __future__ import annotations

import inspect
import re
from collections import OrderedDict
from collections.abc import Iterable, Mapping
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


_SCHEMA_NODE_TYPES = {
    "Sequence",
    "Choice",
    "SequenceOf",
    "ExplicitTag",
    "Integer",
    "OctetString",
    "UTF8String",
    "ObjectIdentifier",
    "Null",
    "BitString",
}


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
                kind, value = self._read_bit_or_hex_string()
                tokens.append(_Token(kind, value, start))
                continue
            if ch.isdigit() or (
                ch == "-" and self._pos + 1 < self._length and self._text[self._pos + 1].isdigit()
            ):
                tokens.append(_Token("NUMBER", self._read_number(), start))
                continue
            if _IDENT_START_RE.fullmatch(ch) is not None:
                tokens.append(_Token("IDENT", self._read_identifier(), start))
                continue
            raise SaipAsn1ValueError(f"Unexpected character {ch!r} at byte offset {start}.")

    def _skip_ignored(self) -> None:
        while self._pos < self._length:
            ch = self._text[self._pos]
            if ch.isspace() or ch == "\ufeff":
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
        return self._text[start : self._pos]

    def _read_number(self) -> int:
        start = self._pos
        if self._text[self._pos] == "-":
            self._pos += 1
        while self._pos < self._length and self._text[self._pos].isdigit():
            self._pos += 1
        return int(self._text[start : self._pos], 10)

    def _read_string(self) -> str:
        self._pos += 1
        chars: list[str] = []
        while self._pos < self._length:
            ch = self._text[self._pos]
            self._pos += 1
            if ch == '"':
                return "".join(chars)
            if ch == "\\" and self._pos < self._length:
                escaped = self._text[self._pos]
                self._pos += 1
                chars.append(
                    {
                        "n": "\n",
                        "r": "\r",
                        "t": "\t",
                        "\\": "\\",
                        '"': '"',
                    }.get(escaped, escaped)
                )
                continue
            chars.append(ch)
        raise SaipAsn1ValueError("Unterminated double-quoted string.")

    def _read_bit_or_hex_string(self) -> tuple[str, Any]:
        self._pos += 1
        start = self._pos
        end = self._text.find("'", start)
        if end == -1:
            raise SaipAsn1ValueError("Unterminated ASN.1 bit/hex string.")
        payload = self._text[start:end]
        self._pos = end + 1
        if self._pos >= self._length or self._text[self._pos] not in "BbHh":
            raise SaipAsn1ValueError("ASN.1 bit/hex string must be followed by B or H.")
        suffix = self._text[self._pos].upper()
        self._pos += 1
        normalized = "".join(payload.split())
        if suffix == "B":
            if any(bit not in "01" for bit in normalized):
                raise SaipAsn1ValueError("ASN.1 bit string contains characters other than 0 and 1.")
            bit_length = len(normalized)
            if bit_length == 0:
                return "BIT", (b"", 0)
            padded = normalized.ljust(((bit_length + 7) // 8) * 8, "0")
            value = int(padded, 2).to_bytes(len(padded) // 8, byteorder="big")
            return "BIT", (value, bit_length)

        normalized = normalized.upper()
        if len(normalized) % 2 != 0:
            raise SaipAsn1ValueError("ASN.1 hex string has odd-length payload.")
        try:
            return "HEX", bytes.fromhex(normalized)
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

    def parse_profile_elements(self) -> list[tuple[str, Any]]:
        elements: list[tuple[str, Any]] = []
        while self._peek().kind != "EOF":
            _label = self._expect("IDENT").value
            type_name = self._expect("IDENT").value
            if type_name != "ProfileElement":
                raise self._error(f"Expected ProfileElement, got {type_name!r}.")
            self._expect("ASSIGN")
            pe_type = self._expect("IDENT").value
            self._expect(":")
            decoded = self._parse_value()
            elements.append((str(pe_type), decoded))
        return elements

    def _parse_value(self) -> Any:
        token = self._peek()
        if token.kind == "{":
            return self._parse_braced()
        if token.kind == "HEX":
            return self._advance().value
        if token.kind == "BIT":
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

    from pySim.esim.saip import ProfileElement, ProfileElementSequence, asn1

    substituted_text, placeholder_records = substitute_inline_placeholders(text)
    named_numbers = _load_named_numbers()
    tokens = _Lexer(substituted_text).tokens()
    parsed_elements = _Parser(tokens, named_numbers).parse_profile_elements()

    pes = ProfileElementSequence()
    pes.pe_list = []
    for pe_type, decoded in parsed_elements:
        schema_node = _profile_element_schema_node(asn1, pe_type)
        decoded = _coerce_parsed_value(
            schema_node,
            decoded,
            path=f"ProfileElement.{pe_type}",
        )
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


def render_asn1_value_profile(
    pes: Any,
    *,
    workspace_root: Path | None = None,
    inline_placeholder_records: Iterable[InlinePlaceholderRecord] | None = None,
) -> str:
    """Render a decoded SAIP PE sequence as ASN.1 value notation.

    ``pes`` may be a pySim ``ProfileElementSequence`` or an iterable of
    profile elements. Rendering is guided by pySim's compiled SAIP schema,
    which preserves the distinction between otherwise ambiguous Python
    values such as CHOICE and BIT STRING tuples or empty SEQUENCE and
    SEQUENCE OF values.

    When ``inline_placeholder_records`` is supplied, every recorded
    sentinel must occur exactly once in an OCTET STRING. Its original
    placeholder literal is spliced back into the emitted ``'...'H`` value.
    """
    root = (
        Path(workspace_root) if workspace_root is not None else Path(__file__).resolve().parents[2]
    )
    from Tools.ProfilePackage.saip_json_codec import ensure_workspace_pysim_on_path

    ensure_workspace_pysim_on_path(root)
    from pySim.esim.saip import asn1

    pe_list = _profile_element_list(pes)
    splicer = _PlaceholderSplicer(inline_placeholder_records)
    renderer = _SchemaValueRenderer(splicer)
    assignments: list[str] = []
    for index, pe in enumerate(pe_list):
        pe_type = getattr(pe, "type", None)
        decoded = getattr(pe, "decoded", None)
        if isinstance(pe_type, str) is False or len(pe_type) == 0:
            raise SaipAsn1ValueError(f"Profile element at index {index} has no valid type name.")
        schema_node = _profile_element_schema_node(asn1, pe_type)
        rendered = renderer.render(
            schema_node,
            decoded,
            level=0,
            path=f"ProfileElement.{pe_type}",
        )
        assignments.append(f"{pe_type} ProfileElement ::= {pe_type} :\n{rendered}")
    splicer.finish()
    return "\n\n".join(assignments) + ("\n" if assignments else "")


def export_asn1_value_profile(
    pes: Any,
    *,
    workspace_root: Path | None = None,
    inline_placeholder_records: Iterable[InlinePlaceholderRecord] | None = None,
) -> str:
    """Compatibility-named wrapper for :func:`render_asn1_value_profile`."""
    return render_asn1_value_profile(
        pes,
        workspace_root=workspace_root,
        inline_placeholder_records=inline_placeholder_records,
    )


def render_asn1_value(
    value: Any,
    schema_node: Any,
    *,
    inline_placeholder_records: Iterable[InlinePlaceholderRecord] | None = None,
) -> str:
    """Render one value using an asn1tools SAIP codec node.

    This lower-level entry point is useful for exported SAIP schema values
    that do not occur inside ``ProfileElement``, notably
    ``UICCCapability`` (BIT STRING).
    """
    splicer = _PlaceholderSplicer(inline_placeholder_records)
    rendered = _SchemaValueRenderer(splicer).render(
        schema_node,
        value,
        level=0,
        path=getattr(schema_node, "name", None) or "<value>",
    )
    splicer.finish()
    return rendered


def _profile_element_list(pes: Any) -> list[Any]:
    pe_list = getattr(pes, "pe_list", None)
    if pe_list is not None:
        return list(pe_list)
    if isinstance(pes, Iterable) and isinstance(pes, (str, bytes)) is False:
        return list(pes)
    raise SaipAsn1ValueError(
        "Expected a ProfileElementSequence or an iterable of profile elements."
    )


def _profile_element_schema_node(asn1: Any, pe_type: str) -> Any:
    try:
        profile_element = asn1.types["ProfileElement"]._type
        return profile_element.name_to_member[pe_type]
    except (AttributeError, KeyError, TypeError) as error:
        raise SaipAsn1ValueError(
            f"SAIP schema has no ProfileElement choice named {pe_type!r}."
        ) from error


def _sequence_members(schema_node: Any) -> list[Any]:
    members = list(getattr(schema_node, "root_members", None) or [])
    for addition in getattr(schema_node, "additions", None) or []:
        if isinstance(addition, (list, tuple)):
            members.extend(addition)
        else:
            members.append(addition)
    return members


def _schema_node_kind(schema_node: Any, *, path: str) -> str:
    kind = type(schema_node).__name__
    if kind not in _SCHEMA_NODE_TYPES:
        raise SaipAsn1ValueError(f"{path}: unsupported SAIP schema codec node {kind!r}.")
    return kind


def _coerce_parsed_value(schema_node: Any, value: Any, *, path: str) -> Any:
    """Resolve syntax-level ambiguities using the compiled SAIP schema."""
    kind = _schema_node_kind(schema_node, path=path)
    if kind == "ExplicitTag":
        return _coerce_parsed_value(schema_node.inner, value, path=path)
    if kind == "Sequence":
        if value == []:
            value = OrderedDict()
        if isinstance(value, Mapping) is False:
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 SEQUENCE.")
        member_by_name = {str(member.name): member for member in _sequence_members(schema_node)}
        unknown = [str(name) for name in value if str(name) not in member_by_name]
        if unknown:
            raise SaipAsn1ValueError(f"{path}: unknown SEQUENCE field(s): {', '.join(unknown)}.")
        out: OrderedDict[str, Any] = OrderedDict()
        for name, item in value.items():
            field_name = str(name)
            out[field_name] = _coerce_parsed_value(
                member_by_name[field_name],
                item,
                path=f"{path}.{field_name}",
            )
        return out
    if kind == "SequenceOf":
        if isinstance(value, list) is False:
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 SEQUENCE OF.")
        return [
            _coerce_parsed_value(
                schema_node.element_type,
                item,
                path=f"{path}[{index}]",
            )
            for index, item in enumerate(value)
        ]
    if kind == "Choice":
        if (
            isinstance(value, tuple) is False
            or len(value) != 2
            or isinstance(value[0], str) is False
        ):
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 CHOICE.")
        choice_name, payload = value
        try:
            member = schema_node.name_to_member[choice_name]
        except KeyError as error:
            raise SaipAsn1ValueError(
                f"{path}: unknown CHOICE alternative {choice_name!r}."
            ) from error
        return (
            choice_name,
            _coerce_parsed_value(
                member,
                payload,
                path=f"{path}.{choice_name}",
            ),
        )
    if kind == "Integer":
        if isinstance(value, int) is False or isinstance(value, bool):
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 INTEGER.")
        return value
    if kind == "OctetString":
        if isinstance(value, (bytes, bytearray)) is False:
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 OCTET STRING.")
        return bytes(value)
    if kind == "UTF8String":
        if isinstance(value, str) is False:
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 UTF8String.")
        return value
    if kind == "ObjectIdentifier":
        if isinstance(value, str) is False:
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 OBJECT IDENTIFIER.")
        return value
    if kind == "Null":
        if value is not None:
            raise SaipAsn1ValueError(f"{path}: expected ASN.1 NULL.")
        return None
    if kind == "BitString":
        _validate_bit_string(value, path=path)
        return (bytes(value[0]), value[1])
    raise AssertionError(f"Unhandled schema node kind: {kind}")


class _SchemaValueRenderer:
    def __init__(self, splicer: "_PlaceholderSplicer") -> None:
        self._splicer = splicer

    def render(
        self,
        schema_node: Any,
        value: Any,
        *,
        level: int,
        path: str,
    ) -> str:
        kind = _schema_node_kind(schema_node, path=path)
        if kind == "ExplicitTag":
            return self.render(schema_node.inner, value, level=level, path=path)
        if kind == "Sequence":
            return self._render_sequence(schema_node, value, level=level, path=path)
        if kind == "SequenceOf":
            return self._render_sequence_of(
                schema_node,
                value,
                level=level,
                path=path,
            )
        if kind == "Choice":
            return self._render_choice(schema_node, value, level=level, path=path)
        if kind == "Integer":
            if isinstance(value, int) is False or isinstance(value, bool):
                raise SaipAsn1ValueError(f"{path}: expected an ASN.1 INTEGER.")
            return str(value)
        if kind == "OctetString":
            if isinstance(value, (bytes, bytearray)) is False:
                raise SaipAsn1ValueError(f"{path}: expected an ASN.1 OCTET STRING.")
            payload = self._splicer.render_octets(bytes(value), path=path)
            return f"'{payload}'H"
        if kind == "UTF8String":
            if isinstance(value, str) is False:
                raise SaipAsn1ValueError(f"{path}: expected an ASN.1 UTF8String.")
            return f'"{_escape_asn1_string(value)}"'
        if kind == "ObjectIdentifier":
            return _render_object_identifier(value, path=path)
        if kind == "Null":
            if value is not None:
                raise SaipAsn1ValueError(f"{path}: expected ASN.1 NULL.")
            return "NULL"
        if kind == "BitString":
            raw, bit_length = _validate_bit_string(value, path=path)
            bits = "".join(f"{octet:08b}" for octet in raw)[:bit_length]
            return f"'{bits}'B"
        raise AssertionError(f"Unhandled schema node kind: {kind}")

    def _render_sequence(
        self,
        schema_node: Any,
        value: Any,
        *,
        level: int,
        path: str,
    ) -> str:
        if isinstance(value, Mapping) is False:
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 SEQUENCE.")
        members = _sequence_members(schema_node)
        member_by_name = {str(member.name): member for member in members}
        unknown = [str(name) for name in value if str(name) not in member_by_name]
        if unknown:
            raise SaipAsn1ValueError(f"{path}: unknown SEQUENCE field(s): {', '.join(unknown)}.")
        entries: list[str] = []
        for member in members:
            name = str(member.name)
            if name not in value:
                continue
            rendered = self.render(
                member,
                value[name],
                level=level + 1,
                path=f"{path}.{name}",
            )
            entries.append(f"{'  ' * (level + 1)}{name} {rendered}")
        return _render_braced_entries(entries, level=level)

    def _render_sequence_of(
        self,
        schema_node: Any,
        value: Any,
        *,
        level: int,
        path: str,
    ) -> str:
        if isinstance(value, list) is False:
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 SEQUENCE OF.")
        entries = [
            f"{'  ' * (level + 1)}"
            + self.render(
                schema_node.element_type,
                item,
                level=level + 1,
                path=f"{path}[{index}]",
            )
            for index, item in enumerate(value)
        ]
        return _render_braced_entries(entries, level=level)

    def _render_choice(
        self,
        schema_node: Any,
        value: Any,
        *,
        level: int,
        path: str,
    ) -> str:
        if (
            isinstance(value, tuple) is False
            or len(value) != 2
            or isinstance(value[0], str) is False
        ):
            raise SaipAsn1ValueError(f"{path}: expected an ASN.1 CHOICE.")
        choice_name, payload = value
        try:
            member = schema_node.name_to_member[choice_name]
        except KeyError as error:
            raise SaipAsn1ValueError(
                f"{path}: unknown CHOICE alternative {choice_name!r}."
            ) from error
        rendered = self.render(
            member,
            payload,
            level=level,
            path=f"{path}.{choice_name}",
        )
        return f"{choice_name} : {rendered}"


def _render_braced_entries(entries: list[str], *, level: int) -> str:
    if len(entries) == 0:
        return "{ }"
    with_commas = [
        entry + ("," if index + 1 < len(entries) else "") for index, entry in enumerate(entries)
    ]
    return "{\n" + "\n".join(with_commas) + f"\n{'  ' * level}}}"


def _escape_asn1_string(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _render_object_identifier(value: Any, *, path: str) -> str:
    if isinstance(value, str) is False:
        raise SaipAsn1ValueError(f"{path}: expected an ASN.1 OBJECT IDENTIFIER.")
    arcs = value.split(".")
    if len(arcs) < 2 or any(re.fullmatch(r"\d+", arc) is None for arc in arcs):
        raise SaipAsn1ValueError(f"{path}: invalid dotted OBJECT IDENTIFIER {value!r}.")
    return "{ " + " ".join(arcs) + " }"


def _validate_bit_string(value: Any, *, path: str) -> tuple[bytes, int]:
    if (
        isinstance(value, tuple) is False
        or len(value) != 2
        or isinstance(value[0], (bytes, bytearray)) is False
        or isinstance(value[1], int) is False
        or isinstance(value[1], bool)
    ):
        raise SaipAsn1ValueError(f"{path}: expected an ASN.1 BIT STRING tuple(bytes, bit_length).")
    raw = bytes(value[0])
    bit_length = value[1]
    if bit_length < 0 or bit_length > len(raw) * 8:
        raise SaipAsn1ValueError(
            f"{path}: BIT STRING length {bit_length} exceeds " f"{len(raw) * 8} available bits."
        )
    return raw, bit_length


class _PlaceholderSplicer:
    def __init__(
        self,
        records: Iterable[InlinePlaceholderRecord] | None,
    ) -> None:
        supplied = list(records or [])
        for record in supplied:
            if isinstance(record, InlinePlaceholderRecord) is False:
                raise SaipAsn1ValueError(
                    "inline_placeholder_records must contain " "InlinePlaceholderRecord values."
                )
        self._records = sorted(supplied, key=lambda record: record.index)
        indexes = [record.index for record in self._records]
        if indexes != list(range(len(self._records))):
            raise SaipAsn1ValueError(
                "Inline placeholder record indexes must be contiguous from zero."
            )

        regenerated_text = "".join(record.literal for record in self._records)
        _substituted, regenerated = substitute_inline_placeholders(regenerated_text)
        if len(regenerated) != len(self._records):
            raise SaipAsn1ValueError("An inline placeholder record contains an invalid literal.")

        self._sentinels: dict[int, bytes] = {}
        seen_sentinels: set[bytes] = set()
        for supplied_record, expected_record in zip(self._records, regenerated):
            if supplied_record != expected_record:
                raise SaipAsn1ValueError(
                    f"Inline placeholder record {supplied_record.index} does not "
                    "match its literal or deterministic sentinel."
                )
            try:
                sentinel = bytes.fromhex(supplied_record.sentinel_hex)
            except ValueError as error:
                raise SaipAsn1ValueError(
                    f"Inline placeholder record {supplied_record.index} has "
                    "invalid sentinel hex."
                ) from error
            if len(sentinel) != supplied_record.byte_length:
                raise SaipAsn1ValueError(
                    f"Inline placeholder record {supplied_record.index} declares "
                    f"{supplied_record.byte_length} bytes but its sentinel has "
                    f"{len(sentinel)}."
                )
            if sentinel in seen_sentinels:
                raise SaipAsn1ValueError("Inline placeholder records must use unique sentinels.")
            seen_sentinels.add(sentinel)
            self._sentinels[supplied_record.index] = sentinel
        self._encountered: list[int] = []

    def render_octets(self, value: bytes, *, path: str) -> str:
        matches: list[tuple[int, int, InlinePlaceholderRecord, bytes]] = []
        for record in self._records:
            sentinel = self._sentinels[record.index]
            start = value.find(sentinel)
            if start == -1:
                continue
            if value.find(sentinel, start + 1) != -1:
                raise SaipAsn1ValueError(
                    f"{path}: placeholder sentinel {record.index} occurs more " "than once."
                )
            if record.index in self._encountered:
                raise SaipAsn1ValueError(
                    f"{path}: placeholder sentinel {record.index} occurs in "
                    "more than one OCTET STRING."
                )
            matches.append((start, start + len(sentinel), record, sentinel))
        if len(matches) == 0:
            return value.hex().upper()

        matches.sort(key=lambda match: match[0])
        pieces: list[str] = []
        cursor = 0
        for start, end, record, _sentinel in matches:
            if start < cursor:
                raise SaipAsn1ValueError(f"{path}: inline placeholder sentinels overlap.")
            pieces.append(value[cursor:start].hex().upper())
            pieces.append(record.literal)
            self._encountered.append(record.index)
            cursor = end
        pieces.append(value[cursor:].hex().upper())
        return "".join(pieces)

    def finish(self) -> None:
        expected = [record.index for record in self._records]
        if self._encountered == expected:
            return
        missing = [index for index in expected if index not in self._encountered]
        if missing:
            raise SaipAsn1ValueError(
                "Inline placeholder sentinel(s) not found in rendered OCTET "
                f"STRING values: {', '.join(str(index) for index in missing)}."
            )
        raise SaipAsn1ValueError(
            "Inline placeholder sentinels occur in a different order than " "their record indexes."
        )


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
