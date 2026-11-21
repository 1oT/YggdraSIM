# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Schema-driven editing of one SAIP profile element.

Every member TCA SAIP v3.4.1 section 8 gives a profile element is read from
the ASN.1 module pySim compiled, so a member no typed editor covers is still
reachable: a leaf takes a value, an absent OPTIONAL or DEFAULT member is added
or removed, a SEQUENCE OF takes or drops an entry within its SIZE, and a
CHOICE switches alternative.

The functions work on the element's section of the session document, in
pySim's native decoded form (``bytes``, ``int``, ``None`` for NULL, a dotted
``str`` for an OBJECT IDENTIFIER, ``dict``, ``list``, ``(alternative,
payload)`` for a CHOICE); the codec's JSON transport form
(``__ygg_saip_bytes__`` / ``__ygg_saip_tuple__``) is read too, and writes are
native. Keys the schema does not name are left alone. A path is a list of
steps from the element: a member name into a SEQUENCE, an index into a
SEQUENCE OF, the alternative name into a CHOICE.
"""

from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

_TAG_BYTES = "__ygg_saip_bytes__"
_TAG_TUPLE = "__ygg_saip_tuple__"

_BUILTIN_KINDS: dict[str, str] = {
    "SEQUENCE": "sequence",
    "SET": "sequence",
    "SEQUENCE OF": "sequence_of",
    "SET OF": "sequence_of",
    "CHOICE": "choice",
    "OCTET STRING": "octets",
    "INTEGER": "integer",
    "ENUMERATED": "enumerated",
    "NULL": "null",
    "BOOLEAN": "boolean",
    "OBJECT IDENTIFIER": "oid",
    "UTF8String": "text",
    "IA5String": "text",
    "VisibleString": "text",
    "PrintableString": "text",
    "NumericString": "text",
    "BIT STRING": "bits",
}

# The identifier the TUI quick-add blank gives a PE-NonStandard issuerID, so
# both surfaces fill an absent OBJECT IDENTIFIER the same way.
_OID_FILLER = "1.3.6.1.4.1.0"
_TEXT_FILLER = "?"
_OID_TEXT_RE = re.compile(r"^[0-2](\.(?:0|[1-9][0-9]*))+$")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]*$")


class SaipStructureError(ValueError):
    """An edit the element's schema does not allow."""


class SaipSchema:
    """The SAIP ASN.1 module pySim compiled, with type references resolved."""

    def __init__(self, module_text: str) -> None:
        import asn1tools

        parsed = asn1tools.parse_string(module_text)
        self.module = parsed[next(iter(parsed))]
        self.types: dict[str, Any] = self.module["types"]
        self.values: dict[str, Any] = self.module.get("values") or {}
        # Keyed by id() and holding the node itself, so an id the collector
        # hands to another object never answers for it.
        self._cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}

    def element_node(self, pe_type: str) -> dict[str, Any]:
        """The resolved SEQUENCE of the ``ProfileElement`` alternative ``pe_type``."""
        choice = self.types["ProfileElement"]
        for member in choice.get("members") or []:
            if member and member.get("name") == pe_type:
                return self.resolve(member)
        raise SaipStructureError(f"{pe_type!r} is no ProfileElement alternative in the SAIP module.")

    def resolve(self, node: dict[str, Any]) -> dict[str, Any]:
        """``node`` with its type reference followed down to a built-in type.

        Constraints and DEFAULT written where the member is declared win over
        those of the referenced type; the referenced type supplies structure.
        """
        key = id(node)
        cached = self._cache.get(key)
        if cached is not None and cached[0] is node:
            return cached[1]
        merged = dict(node)
        display = str(node.get("type") or "")
        type_name = display
        seen: set[str] = set()
        while type_name not in _BUILTIN_KINDS:
            if type_name in seen or type_name not in self.types:
                raise SaipStructureError(f"type {type_name!r} does not resolve in the SAIP module.")
            seen.add(type_name)
            base = self.types[type_name]
            for field, value in base.items():
                if field != "type":
                    merged.setdefault(field, value)
            type_name = str(base.get("type") or "")
        merged["type"] = type_name
        merged["kind"] = _BUILTIN_KINDS[type_name]
        merged["display"] = display
        self._cache[key] = (node, merged)
        return merged

    def members(self, node: dict[str, Any]) -> list[dict[str, Any]]:
        return [self.resolve(member) for member in node.get("members") or [] if member]

    def element(self, node: dict[str, Any]) -> dict[str, Any]:
        return self.resolve(node["element"])

    def bound(self, value: Any) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            named = self.values.get(value)
            if isinstance(named, dict) and isinstance(named.get("value"), int):
                return int(named["value"])
            if value.lstrip("-").isdigit():
                return int(value)
        return None

    def size(self, node: dict[str, Any]) -> tuple[int, int | None] | None:
        """``(minimum, maximum)`` of a SIZE constraint; ``None`` for MAX or none."""
        size = node.get("size")
        if not size:
            return None
        first = size[0]
        if isinstance(first, (list, tuple)) and len(first) == 2:
            low = self.bound(first[0]) or 0
            high = None if first[1] == "MAX" else self.bound(first[1])
            return (low, high)
        fixed = self.bound(first)
        return (fixed, fixed) if fixed is not None else None

    def value_range(self, node: dict[str, Any]) -> tuple[int | None, int | None] | None:
        restricted = node.get("restricted-to")
        if not restricted:
            return None
        first = restricted[0]
        if isinstance(first, (list, tuple)) and len(first) == 2:
            return (self.bound(first[0]), None if first[1] == "MAX" else self.bound(first[1]))
        fixed = self.bound(first)
        return (fixed, fixed)

    def named_numbers(self, node: dict[str, Any]) -> dict[str, int]:
        named = node.get("named-numbers")
        if isinstance(named, dict):
            return {str(name): int(value) for name, value in named.items()}
        return {}

    def default(self, node: dict[str, Any]) -> Any:
        """The DEFAULT a member declares, in native form, or ``None``."""
        if "default" not in node:
            return None
        raw = node["default"]
        kind = node["kind"]
        if kind == "sequence_of":
            entry = self.element(node)
            single = self._scalar_default(entry, raw)
            count = (self.size(node) or (1, 1))[0] or 1
            return [copy.deepcopy(single) for _ in range(count)]
        return self._scalar_default(node, raw)

    def _scalar_default(self, node: dict[str, Any], raw: Any) -> Any:
        kind = node["kind"]
        if kind == "octets" and isinstance(raw, str) and raw.lower().startswith("0x"):
            return bytes.fromhex(raw[2:])
        if kind in ("integer", "enumerated"):
            if isinstance(raw, int):
                return raw
            named = self.named_numbers(node)
            if str(raw) in named:
                return named[str(raw)]
            bound = self.bound(raw)
            return bound if bound is not None else raw
        if kind == "boolean":
            return str(raw).upper() == "TRUE" if not isinstance(raw, bool) else raw
        return raw


_SCHEMA_CACHE: dict[str, SaipSchema] = {}


def load_schema() -> SaipSchema:
    """The SAIP module of the pySim on the path, concatenated as pySim compiles it."""
    from importlib import resources

    folder = resources.files("pySim.esim").joinpath("asn1").joinpath("saip")
    text = "".join(entry.read_text(encoding="utf-8") + "\n"
                   for entry in sorted(folder.iterdir(), key=lambda e: e.name)
                   if entry.name.endswith(".asn"))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    schema = _SCHEMA_CACHE.get(digest)
    if schema is None:
        schema = SaipSchema(text)
        _SCHEMA_CACHE[digest] = schema
    return schema


# -- native value forms ------------------------------------------------------


def _native(value: Any) -> Any:
    if isinstance(value, dict) and _TAG_BYTES in value and len(value) == 1:
        return bytes.fromhex(str(value[_TAG_BYTES] or ""))
    if isinstance(value, dict) and _TAG_TUPLE in value and len(value) == 1:
        pair = value[_TAG_TUPLE]
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            return (str(pair[0]), pair[1])
    return value


def _choice_parts(value: Any) -> tuple[str, Any] | None:
    value = _native(value)
    if isinstance(value, (tuple, list)) and len(value) == 2 and isinstance(value[0], str):
        return (value[0], value[1])
    return None


def _filler(schema: SaipSchema, node: dict[str, Any]) -> Any:
    """The value an added member starts with: its DEFAULT, or the smallest valid one."""
    declared = schema.default(node)
    if declared is not None:
        return copy.deepcopy(declared)
    kind = node["kind"]
    if kind == "octets":
        size = schema.size(node)
        return bytes((size or (0, None))[0])
    if kind in ("integer", "enumerated"):
        named = schema.named_numbers(node)
        if named:
            return min(named.values())
        span = schema.value_range(node)
        return span[0] if span and span[0] is not None else 0
    if kind == "null":
        return None
    if kind == "boolean":
        return False
    if kind == "oid":
        return _OID_FILLER
    if kind == "text":
        size = schema.size(node)
        return _TEXT_FILLER * ((size or (0, None))[0])
    if kind == "bits":
        return (b"", 0)
    if kind == "sequence":
        # The mandatory members and the DEFAULT ones at their default: the
        # shape asn1tools decodes to, which pySim reads (a KeyObject's
        # macLength) without a fallback of its own.
        return {
            member["name"]: _filler(schema, member)
            for member in schema.members(node)
            if not member.get("optional")
        }
    if kind == "sequence_of":
        size = schema.size(node)
        count = max(1, (size or (1, None))[0])
        entry = schema.element(node)
        return [_filler(schema, entry) for _ in range(count)]
    if kind == "choice":
        first = schema.members(node)[0]
        return (first["name"], _filler(schema, first))
    raise SaipStructureError(f"no filler for {node.get('display')!r}.")


def _is_filler(schema: SaipSchema, node: dict[str, Any], value: Any) -> bool:
    """A leaf still holding a filler no profile carries for real.

    Only the all-zero AID, the filler object identifier and the filler text
    count: a zero byte or an empty string is a value a profile may well hold.
    """
    if "default" in node:
        return False
    value = _native(value)
    kind = node["kind"]
    if kind == "oid":
        return value == _OID_FILLER
    if kind == "text":
        return bool(value) and value == _filler(schema, node)
    if kind == "octets" and node.get("display") == "ApplicationIdentifier":
        return isinstance(value, (bytes, bytearray)) and len(value) > 0 and not any(value)
    return False


# -- leaf parsing ------------------------------------------------------------


def _parse_leaf(schema: SaipSchema, node: dict[str, Any], text: Any, label: str) -> Any:
    kind = node["kind"]
    raw = str(text if text is not None else "").strip()
    if kind == "octets":
        compact = re.sub(r"\s+|0x|0X|[-:_]", "", raw)
        if _HEX_RE.fullmatch(compact) is None or len(compact) % 2:
            raise SaipStructureError(f"{label} takes hex bytes; got {raw!r}.")
        data = bytes.fromhex(compact)
        size = schema.size(node)
        if size is not None and (len(data) < size[0] or (size[1] is not None and len(data) > size[1])):
            raise SaipStructureError(f"{label} is SIZE ({_size_text(size)}) bytes; got {len(data)}.")
        return data
    if kind in ("integer", "enumerated"):
        named = schema.named_numbers(node)
        if raw in named:
            number = named[raw]
        else:
            try:
                number = int(raw, 0)
            except ValueError as error:
                names = ", ".join(sorted(named)) if named else "a number"
                raise SaipStructureError(f"{label} takes {names}; got {raw!r}.") from error
        span = schema.value_range(node)
        if span is not None:
            low, high = span
            if (low is not None and number < low) or (high is not None and number > high):
                raise SaipStructureError(f"{label} is {low}..{high}; got {number}.")
        return number
    if kind == "oid":
        if _OID_TEXT_RE.fullmatch(raw) is None:
            raise SaipStructureError(f"{label} takes a dotted object identifier; got {raw!r}.")
        arcs = [int(arc) for arc in raw.split(".")]
        if arcs[0] < 2 and arcs[1] > 39:
            raise SaipStructureError(f"{label}: under arc {arcs[0]} the second arc is 0..39 (Rec. ITU-T X.660 (07/2011) §7.6 b)).")
        return raw
    if kind == "text":
        size = schema.size(node)
        if size is not None and (len(raw) < size[0] or (size[1] is not None and len(raw) > size[1])):
            raise SaipStructureError(f"{label} is SIZE ({_size_text(size)}) characters; got {len(raw)}.")
        return raw
    if kind == "boolean":
        if raw.lower() not in ("true", "false"):
            raise SaipStructureError(f"{label} takes true or false; got {raw!r}.")
        return raw.lower() == "true"
    raise SaipStructureError(f"{label} ({node.get('display')}) takes no typed value; add or remove it instead.")


def _size_text(size: tuple[int, int | None]) -> str:
    low, high = size
    if high is None:
        return f"{low}..MAX"
    return str(low) if low == high else f"{low}..{high}"


def _leaf_text(node: dict[str, Any], value: Any) -> str | None:
    value = _native(value)
    kind = node["kind"]
    if kind == "octets" and isinstance(value, (bytes, bytearray)):
        return bytes(value).hex().upper()
    if kind in ("integer", "enumerated", "oid", "text") and value is not None:
        return str(value)
    if kind == "boolean" and isinstance(value, bool):
        return "true" if value else "false"
    if kind == "bits" and isinstance(value, (tuple, list)) and len(value) == 2:
        return bytes(value[0]).hex().upper()
    return None


# -- navigation ----------------------------------------------------------------


def _step_into(schema: SaipSchema, node: dict[str, Any], value: Any, step: Any, label: str):
    """``(child node, child value)`` one step below ``node``."""
    kind = node["kind"]
    if kind == "sequence":
        for member in schema.members(node):
            if member["name"] == step:
                return member, (value.get(step) if isinstance(value, dict) else None)
        raise SaipStructureError(f"{label} has no member {step!r}.")
    if kind == "sequence_of":
        if not isinstance(step, int):
            raise SaipStructureError(f"{label} is a list; step {step!r} is no index.")
        entries = value if isinstance(value, list) else []
        if step < 0 or step >= len(entries):
            raise SaipStructureError(f"{label} has no entry {step}.")
        return schema.element(node), entries[step]
    if kind == "choice":
        parts = _choice_parts(value)
        for member in schema.members(node):
            if member["name"] == step:
                if parts is None or parts[0] != step:
                    raise SaipStructureError(f"{label} holds {parts[0] if parts else 'nothing'}, not {step!r}.")
                return member, parts[1]
        raise SaipStructureError(f"{label} has no alternative {step!r}.")
    raise SaipStructureError(f"{label} is a leaf; there is nothing below it.")


def _locate(schema: SaipSchema, pe_type: str, section: dict[str, Any], path: list[Any]):
    """``(node, value, parent value, last step)`` at ``path``."""
    node = schema.element_node(pe_type)
    value: Any = section
    parent: Any = None
    label = pe_type
    for step in path:
        parent = value
        node, value = _step_into(schema, node, value, step, label)
        label = f"{label}/{step}"
    return node, value, parent, (path[-1] if path else None)


def _container(schema: SaipSchema, pe_type: str, section: dict[str, Any], path: list[Any]):
    """The live value at ``path`` that a child is written into."""
    node, value, parent, last = _locate(schema, pe_type, section, path)
    if node["kind"] == "choice":
        parts = _choice_parts(value)
        return node, parts
    return node, value


def _write(schema: SaipSchema, pe_type: str, section: dict[str, Any], path: list[Any], new_value: Any) -> None:
    """Store ``new_value`` at ``path``, rewriting a CHOICE parent in native form."""
    if not path:
        raise SaipStructureError("the element itself cannot be replaced.")
    parent_path, last = path[:-1], path[-1]
    parent_node, parent_value, grand, grand_step = _locate(schema, pe_type, section, parent_path)
    kind = parent_node["kind"]
    if kind == "sequence":
        if not isinstance(parent_value, dict):
            raise SaipStructureError(f"{'/'.join(map(str, parent_path)) or pe_type} is not present.")
        parent_value[last] = new_value
        return
    if kind == "sequence_of":
        parent_value[last] = new_value
        return
    if kind == "choice":
        _write(schema, pe_type, section, parent_path, (last, new_value))
        return
    raise SaipStructureError("a leaf has no members.")


def _header_member(schema: SaipSchema, pe_type: str) -> str | None:
    for member in schema.members(schema.element_node(pe_type)):
        if member["display"] == "PEHeader":
            return member["name"]
    return None


class _ChoiceSlot:
    """Reads and writes the payload of the CHOICE value held at ``holder[key]``."""

    def __init__(self, holder: Any, key: Any) -> None:
        self.holder = holder
        self.key = key

    def __getitem__(self, _unused: Any) -> Any:
        return _choice_parts(self.holder[self.key])[1]

    def __setitem__(self, _unused: Any, payload: Any) -> None:
        alternative = _choice_parts(self.holder[self.key])[0]
        self.holder[self.key] = (alternative, payload)


def _member_named(schema: SaipSchema, node: dict[str, Any], name: Any, label: str) -> dict[str, Any]:
    for member in schema.members(node):
        if member["name"] == name:
            return member
    raise SaipStructureError(f"{label} has no member {name!r}.")


def _materialize(schema: SaipSchema, pe_type: str, section: dict[str, Any], path: list[Any]) -> None:
    """Create whatever ``path`` runs through and is not there yet.

    An absent member is added with its filler, the index one past the end of
    a list appends an entry, and a CHOICE created on the way takes the
    alternative the path names. A CHOICE that already held another
    alternative is not switched: that would discard what it holds.
    """
    holder: Any = {"_": section}
    key: Any = "_"
    node = schema.element_node(pe_type)
    created = False
    label = pe_type
    for step in path:
        value = holder[key]
        kind = node["kind"]
        if kind == "sequence":
            member = _member_named(schema, node, step, label)
            if not isinstance(value, dict):
                raise SaipStructureError(f"{label} holds no SEQUENCE value.")
            if step not in value:
                value[step] = _filler(schema, member)
                created = True
            holder, key, node = value, step, member
        elif kind == "sequence_of":
            if isinstance(step, bool) or not isinstance(step, int):
                raise SaipStructureError(f"{label} is a list; step {step!r} is no index.")
            if not isinstance(value, list):
                raise SaipStructureError(f"{label} holds no list.")
            if step == len(value):
                size = schema.size(node)
                if size is not None and size[1] is not None and len(value) >= size[1]:
                    raise SaipStructureError(f"{label} holds at most {size[1]} entries.")
                value.append(_filler(schema, schema.element(node)))
                created = True
            elif step < 0 or step > len(value):
                raise SaipStructureError(f"{label} has no entry {step}.")
            holder, key, node = value, step, schema.element(node)
        elif kind == "choice":
            member = _member_named(schema, node, step, label)
            parts = _choice_parts(value)
            if parts is None or parts[0] != step:
                if parts is not None and not created:
                    raise SaipStructureError(f"{label} holds {parts[0]}; switch it to {step} first.")
                holder[key] = (step, _filler(schema, member))
                created = True
            holder, key, node = _ChoiceSlot(holder, key), None, member
        else:
            raise SaipStructureError(f"{label} is a leaf; there is nothing below it.")
        label = f"{label}/{step}"


def _is_present(schema: SaipSchema, pe_type: str, section: dict[str, Any], path: list[Any]) -> bool:
    """Whether every step of ``path`` holds a value."""
    node = schema.element_node(pe_type)
    value: Any = section
    label = pe_type
    for step in path:
        value = _native(value)
        kind = node["kind"]
        if kind == "sequence":
            node = _member_named(schema, node, step, label)
            if not isinstance(value, dict) or step not in value:
                return False
            value = value[step]
        elif kind == "sequence_of":
            if not isinstance(value, list) or not isinstance(step, int) or not 0 <= step < len(value):
                return False
            node, value = schema.element(node), value[step]
        elif kind == "choice":
            node = _member_named(schema, node, step, label)
            parts = _choice_parts(value)
            if parts is None or parts[0] != step:
                return False
            value = parts[1]
        else:
            return False
        label = f"{label}/{step}"
    return True


def _holds_anything(schema: SaipSchema, node: dict[str, Any], value: Any) -> bool:
    """Whether a SEQUENCE value carries a member that is not at its DEFAULT."""
    if not isinstance(value, dict):
        return True
    for member in schema.members(node):
        if member["name"] not in value:
            continue
        if "default" in member and _native(value[member["name"]]) == schema.default(member):
            continue
        return True
    return False


def _prune(schema: SaipSchema, pe_type: str, section: dict[str, Any], path: list[Any]) -> list[str]:
    """Drop the OPTIONAL containers ``path`` ends in that hold nothing any more."""
    dropped: list[str] = []
    while path:
        node, value, parent, last = _locate(schema, pe_type, section, path)
        empty = (
            (node["kind"] == "sequence" and not _holds_anything(schema, node, value))
            or (node["kind"] == "sequence_of" and isinstance(value, list) and not value)
        )
        optional = bool(node.get("optional")) or "default" in node
        if not (empty and optional and isinstance(parent, dict) and isinstance(last, str)):
            break
        del parent[last]
        dropped.append(str(last))
        path = path[:-1]
    return dropped


# -- operations ------------------------------------------------------------------


def set_leaf(section: dict[str, Any], pe_type: str, path: list[Any], text: Any) -> str:
    """Give the leaf at ``path`` a value, creating what leads to it.

    A NULL member takes ``true`` (present) or ``false`` (absent).
    """
    schema = load_schema()
    if not path:
        raise SaipStructureError("the element itself takes no value.")
    header = _header_member(schema, pe_type)
    if header is not None and path == [header, "identification"]:
        raise SaipStructureError("the PE identification is numbered by the tool (TCA SAIP v3.4.1 §8.1.3).")
    label = "/".join(map(str, path))
    node = _node_at(schema, pe_type, path)
    if node["kind"] == "null":
        flag = str(text if text is not None else "").strip().lower()
        if flag in ("false", "0", "off", "no", ""):
            return clear(section, pe_type, path)
        if flag not in ("true", "1", "on", "yes"):
            raise SaipStructureError(f"{label} is a flag; it takes true or false.")
        _materialize(schema, pe_type, section, path)
        return f"{label} set."
    if str(text if text is not None else "").strip() == "" and not _empty_is_a_value(schema, node):
        if node.get("optional") or "default" in node:
            return clear(section, pe_type, path)
        raise SaipStructureError(f"{label} is mandatory; give it a value.")
    parsed = _parse_leaf(schema, node, text, label)
    _materialize(schema, pe_type, section, path)
    _write(schema, pe_type, section, path, parsed)
    return f"{label} set."


def _empty_is_a_value(schema: SaipSchema, node: dict[str, Any]) -> bool:
    """Whether an emptied field means an empty value rather than no member.

    An explicit SIZE (0..n) makes the empty value one of its own: a Fcp
    shortEFID present and empty says the file has no SFI, absent it says
    the SFI comes from the file ID (ETSI TS 102 221 v18.4 §11.1.1.4.8). An
    OPTIONAL member without that bound is taken out instead; a mandatory
    one keeps the empty value where its type allows it.
    """
    if node["kind"] not in ("octets", "text"):
        return False
    size = schema.size(node)
    if node.get("optional") or "default" in node:
        return size is not None and size[0] == 0
    return size is None or size[0] == 0


def _node_at(schema: SaipSchema, pe_type: str, path: list[Any]) -> dict[str, Any]:
    """The schema node ``path`` names, whatever the value holds."""
    node = schema.element_node(pe_type)
    label = pe_type
    for step in path:
        kind = node["kind"]
        if kind in ("sequence", "choice"):
            node = _member_named(schema, node, step, label)
        elif kind == "sequence_of":
            if isinstance(step, bool) or not isinstance(step, int):
                raise SaipStructureError(f"{label} is a list; step {step!r} is no index.")
            node = schema.element(node)
        else:
            raise SaipStructureError(f"{label} is a leaf; there is nothing below it.")
        label = f"{label}/{step}"
    return node


def clear(section: dict[str, Any], pe_type: str, path: list[Any]) -> str:
    """Take the value at ``path`` out of the element.

    An OPTIONAL or DEFAULT member goes, a list entry goes (within its SIZE),
    an alternative takes its CHOICE with it, and an OPTIONAL container left
    with nothing in it goes as well. A mandatory member is refused.
    """
    schema = load_schema()
    if not path:
        raise SaipStructureError("the element itself cannot be cleared.")
    label = "/".join(map(str, path))
    if not _is_present(schema, pe_type, section, path):
        return f"{label} is not set."
    parent_path, last = path[:-1], path[-1]
    parent_node, parent_value, _grand, _step = _locate(schema, pe_type, section, parent_path)
    kind = parent_node["kind"]
    if kind == "sequence_of":
        summary = remove_entry(section, pe_type, parent_path, int(last))
    elif kind == "choice":
        return clear(section, pe_type, parent_path)
    else:
        member = _member_named(schema, parent_node, last, label)
        if not member.get("optional") and "default" not in member:
            raise SaipStructureError(f"{label} is mandatory; give it a value instead.")
        del parent_value[last]
        summary = f"{label} cleared."
    if _is_present(schema, pe_type, section, parent_path):
        dropped = _prune(schema, pe_type, section, parent_path)
        if dropped:
            summary += " Emptied, so removed: " + ", ".join(dropped) + "."
    return summary


def add_member(section: dict[str, Any], pe_type: str, path: list[Any], name: str) -> str:
    schema = load_schema()
    node, value = _container(schema, pe_type, section, path)
    if node["kind"] != "sequence" or not isinstance(value, dict):
        raise SaipStructureError(f"{'/'.join(map(str, path)) or pe_type} is no SEQUENCE that is present.")
    for member in schema.members(node):
        if member["name"] != name:
            continue
        if name in value:
            raise SaipStructureError(f"{name} is present already.")
        value[name] = _filler(schema, member)
        return f"{name} added."
    raise SaipStructureError(f"{name!r} is no member here.")


def remove_member(section: dict[str, Any], pe_type: str, path: list[Any], name: str) -> str:
    schema = load_schema()
    node, value = _container(schema, pe_type, section, path)
    if node["kind"] != "sequence" or not isinstance(value, dict):
        raise SaipStructureError(f"{'/'.join(map(str, path)) or pe_type} is no SEQUENCE that is present.")
    for member in schema.members(node):
        if member["name"] != name:
            continue
        if not member.get("optional") and "default" not in member:
            raise SaipStructureError(f"{name} is mandatory.")
        value.pop(name, None)
        return f"{name} removed."
    raise SaipStructureError(f"{name!r} is no member here.")


def add_entry(section: dict[str, Any], pe_type: str, path: list[Any]) -> str:
    schema = load_schema()
    node, value, _parent, _last = _locate(schema, pe_type, section, path)
    if node["kind"] != "sequence_of" or not isinstance(value, list):
        raise SaipStructureError(f"{'/'.join(map(str, path))} is no list that is present.")
    size = schema.size(node)
    if size is not None and size[1] is not None and len(value) >= size[1]:
        raise SaipStructureError(f"{'/'.join(map(str, path))} holds at most {size[1]} entries.")
    value.append(_filler(schema, schema.element(node)))
    return f"entry {len(value) - 1} added."


def remove_entry(section: dict[str, Any], pe_type: str, path: list[Any], index: int) -> str:
    """Drop entry ``index``; an OPTIONAL list that would fall below its SIZE goes."""
    schema = load_schema()
    node, value, parent, last = _locate(schema, pe_type, section, path)
    if node["kind"] != "sequence_of" or not isinstance(value, list):
        raise SaipStructureError(f"{'/'.join(map(str, path))} is no list that is present.")
    if index < 0 or index >= len(value):
        raise SaipStructureError(f"there is no entry {index}.")
    size = schema.size(node)
    minimum = size[0] if size is not None else 0
    if len(value) - 1 < minimum:
        if node.get("optional") and isinstance(parent, dict) and isinstance(last, str):
            del parent[last]
            return f"{last} removed with its last entry (SIZE ({_size_text(size)}))."
        raise SaipStructureError(
            f"{'/'.join(map(str, path))} needs at least {minimum} entries (SIZE ({_size_text(size)}))."
        )
    del value[index]
    return f"entry {index} removed."


def set_choice(section: dict[str, Any], pe_type: str, path: list[Any], alternative: str) -> str:
    schema = load_schema()
    node = _node_at(schema, pe_type, path)
    if node["kind"] != "choice":
        raise SaipStructureError(f"{'/'.join(map(str, path))} is no CHOICE.")
    member = _member_named(schema, node, alternative, "/".join(map(str, path)))
    _materialize(schema, pe_type, section, path)
    _write(schema, pe_type, section, path, (alternative, _filler(schema, member)))
    return f"{'/'.join(map(str, path))} switched to {alternative}."


def apply(section: dict[str, Any], pe_type: str, op: str, path: list[Any], **arguments: Any) -> str:
    """One edit by name: set, clear, add, remove, add_entry, remove_entry or choice."""
    if op == "set":
        return set_leaf(section, pe_type, path, arguments.get("value"))
    if op == "clear":
        return clear(section, pe_type, path)
    if op == "add":
        return add_member(section, pe_type, path, str(arguments.get("name") or ""))
    if op == "remove":
        return remove_member(section, pe_type, path, str(arguments.get("name") or ""))
    if op == "add_entry":
        return add_entry(section, pe_type, path)
    if op == "remove_entry":
        return remove_entry(section, pe_type, path, int(arguments.get("index")))
    if op == "choice":
        return set_choice(section, pe_type, path, str(arguments.get("alternative") or ""))
    raise SaipStructureError(f"unknown structure edit {op!r}.")


def tagged_path(pe_type: str, path: list[Any]) -> list[Any]:
    """``path`` as the tagged JSON document addresses it: a CHOICE is ``"@", 1``.

    The decoded-field entries of ``saip_decoded_edit`` carry their place in
    that form (``["algoConfiguration", "@", 1, "key"]``).
    """
    schema = load_schema()
    node = schema.element_node(pe_type)
    out: list[Any] = []
    label = pe_type
    for step in path:
        kind = node["kind"]
        if kind == "choice":
            out.extend(["@", 1])
            node = _member_named(schema, node, step, label)
        elif kind == "sequence":
            out.append(step)
            node = _member_named(schema, node, step, label)
        elif kind == "sequence_of":
            out.append(step)
            node = schema.element(node)
        else:
            raise SaipStructureError(f"{label} is a leaf; there is nothing below it.")
        label = f"{label}/{step}"
    return out


def present_leaves(section: dict[str, Any], pe_type: str) -> list[tuple[list[Any], dict[str, Any], Any]]:
    """``(path, schema node, native value)`` of every leaf the element holds."""
    schema = load_schema()
    found: list[tuple[list[Any], dict[str, Any], Any]] = []

    def walk(node: dict[str, Any], value: Any, path: list[Any]) -> None:
        value = _native(value)
        kind = node["kind"]
        if kind == "sequence":
            if isinstance(value, dict):
                for member in schema.members(node):
                    if member["name"] in value:
                        walk(member, value[member["name"]], path + [member["name"]])
        elif kind == "sequence_of":
            if isinstance(value, list):
                element = schema.element(node)
                for index, item in enumerate(value):
                    walk(element, item, path + [index])
        elif kind == "choice":
            parts = _choice_parts(value)
            if parts is not None:
                for member in schema.members(node):
                    if member["name"] == parts[0]:
                        walk(member, parts[1], path + [parts[0]])
        else:
            found.append((path, node, value))

    walk(schema.element_node(pe_type), section, [])
    return found


# -- projection ------------------------------------------------------------------


def structure(section: dict[str, Any], pe_type: str) -> dict[str, Any]:
    """Every member of the element, present or not, as a JSON-safe tree."""
    schema = load_schema()
    root = schema.element_node(pe_type)
    header = _header_member(schema, pe_type)
    return _project(schema, root, section, [], pe_type, True, header)


def _constraint_texts(schema: SaipSchema, node: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    size = schema.size(node)
    if size is not None:
        out["size"] = _size_text(size)
    span = schema.value_range(node)
    if span is not None:
        out["range"] = f"{span[0]}..{'MAX' if span[1] is None else span[1]}"
    named = schema.named_numbers(node)
    if named:
        out["named"] = sorted(named, key=lambda name: named[name])
        out["named_values"] = [[name, named[name]] for name in out["named"]]
    if "default" in node:
        default = schema.default(node)
        if node["kind"] == "sequence_of":
            # sqnInit defaults to 32 zero SQNs (TCA SAIP v3.4.1 page 48).
            entry = schema.element(node)
            texts = [_leaf_text(entry, item) for item in default]
            same = bool(texts) and texts[0] is not None and all(text == texts[0] for text in texts)
            out["default"] = f"{len(texts)} x {texts[0]}" if same else f"{len(texts)} entries"
        else:
            out["default"] = _leaf_text(node, default)
    return out


# How many absent levels below a present member the projection describes;
# the editor asks again once a value lands there.
_ABSENT_DEPTH = 4


def _project(
    schema: SaipSchema,
    node: dict[str, Any],
    value: Any,
    path: list[Any],
    name: str,
    present: bool,
    header: str | None,
    absent_depth: int = 0,
) -> dict[str, Any]:
    """One node of the projection, absent members included.

    An absent SEQUENCE lists its members (absent too) so an editor can show
    their fields; a list ends in a phantom entry, the index one past its end,
    until it holds the most its SIZE allows; an absent CHOICE names its
    alternatives.
    """
    value = _native(value) if present else None
    out: dict[str, Any] = {
        "path": list(path),
        "name": name,
        "type": node["display"],
        "kind": node["kind"],
        "optional": bool(node.get("optional")) or "default" in node,
        "present": present,
    }
    out.update(_constraint_texts(schema, node))
    kind = node["kind"]
    depth = 0 if present else absent_depth + 1
    if kind in ("sequence", "sequence_of") and depth > _ABSENT_DEPTH:
        out["children_omitted"] = True
        return out
    if kind == "sequence":
        own = value if isinstance(value, dict) else {}
        children = [
            _project(
                schema, member, own.get(member["name"]), path + [member["name"]],
                member["name"], present and member["name"] in own, header, depth,
            )
            for member in schema.members(node)
        ]
        out["children"] = children
        if header is not None and path == [header]:
            for child in children:
                if child["name"] == "identification":
                    # Unique within the profile (TCA SAIP v3.4.1 §8.1.3); the
                    # session numbers the elements.
                    child["read_only"] = True
                    child["read_only_reason"] = "Numbered by the tool: unique within the profile (TCA SAIP v3.4.1 §8.1.3)."
        return out
    if kind == "sequence_of":
        entries = value if isinstance(value, list) else []
        entry = schema.element(node)
        out["entries"] = len(entries)
        out["entry_type"] = entry["display"]
        children = [
            _project(schema, entry, item, path + [index], f"[{index}]", True, header)
            for index, item in enumerate(entries)
        ]
        size = schema.size(node)
        if size is None or size[1] is None or len(entries) < size[1]:
            phantom = _project(
                schema, entry, None, path + [len(entries)], f"[{len(entries)}]", False, header, depth,
            )
            phantom["phantom"] = True
            children.append(phantom)
        out["children"] = children
        return out
    if kind == "choice":
        out["alternatives"] = [member["name"] for member in schema.members(node)]
        parts = _choice_parts(value)
        if parts is not None:
            out["active"] = parts[0]
            for member in schema.members(node):
                if member["name"] == parts[0]:
                    out["children"] = [_project(
                        schema, member, parts[1], path + [parts[0]], parts[0], True, header,
                    )]
        return out
    if present:
        out["value"] = _leaf_text(node, value)
        out["placeholder"] = _is_filler(schema, node, value)
    return out


__all__ = [
    "SaipSchema",
    "SaipStructureError",
    "add_entry",
    "add_member",
    "apply",
    "clear",
    "load_schema",
    "present_leaves",
    "remove_entry",
    "remove_member",
    "set_choice",
    "set_leaf",
    "structure",
    "tagged_path",
]
