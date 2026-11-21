#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Emit the Wireshark APDU dissector's Lua lookup tables from Python.

The dissector needs the same instruction names, status words, BER-TLV
tags and risk classes the rest of YggdraSIM already carries. Copying
them into Lua by hand would mean a status word could be described one
way in the MCP server and another in a packet trace, which is exactly
what ``yggdrasim_common/apdu_risk.py`` warns against: one table, two
consumers cannot disagree.

Tables are lifted out of their source modules with :mod:`ast` rather
than imported. Importing ``Tools.YggdraMCP.server`` would drag in the
``mcp`` package, and ``SIMCARD.etsi_fs`` would drag in pySim, so an
import-based generator could not run in a bare CI job -- and the drift
test that guards the checked-in Lua has to run everywhere.

Usage::

    python scripts/generate_apdu_dissector_tables.py --write
    python scripts/generate_apdu_dissector_tables.py --check
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = (
    REPO_ROOT / "Tools" / "ApduDissector" / "lua" / "yggdrasim_apdu" / "tables.lua"
)

GENERATOR_NAME = "scripts/generate_apdu_dissector_tables.py"

#: Source modules the tables are lifted from, relative to the repo root.
SOURCES: dict[str, str] = {
    "apdu_risk": "yggdrasim_common/apdu_risk.py",
    "apdu_tables": "yggdrasim_common/apdu_tables.py",
    "stk_tables": "yggdrasim_common/stk_tables.py",
    "tls_tables": "yggdrasim_common/tls_tables.py",
    "asn1": "Tools/Asn1TlvDecode/main.py",
    "mcp": "Tools/YggdraMCP/server.py",
    "decode_state": "Tools/HilBridge/live_decode_state.py",
    "etsi_fs": "SIMCARD/etsi_fs.py",
    "gp": "SIMCARD/gp.py",
}


#: Converted GSMA specifications the RSP member names are read from.
#: SGP.22 is listed first and wins on a name collision: SGP.32 restates
#: several of its types with IoT-specific wording, and the base
#: specification is what an ES10 trace is read against.
SPEC_SOURCES: tuple[str, ...] = (
    "docs/tel-docs/converted/SGP.22-v3.1/SGP.22-v3.1.md",
    "docs/tel-docs/converted/SGP.32-v1.2/SGP.32-v1.2.md",
)

#: The RSP member names as last read from SPEC_SOURCES. The library is
#: gitignored, so a checkout without it -- CI, a fresh clone -- renders from
#: this extract, and a checkout with it checks that the extract is current.
RSP_EXTRACT = "scripts/apdu_dissector_rsp_members.json"

#: Fewer stated tags than this means the reader no longer sees them.
_MIN_STATED_TAGS = 100


class TableExtractionError(RuntimeError):
    """Raised when a source module no longer carries an expected table."""


# --------------------------------------------------------------- extraction
def _parse_module(path: Path) -> ast.Module:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as error:
        raise TableExtractionError(f"cannot parse {path}: {error}") from error


def _assignments(module: ast.Module) -> dict[str, ast.expr]:
    """Map every module-level assignment name to its value node."""
    found: dict[str, ast.expr] = {}
    for node in module.body:
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value is not None:
                found[node.target.id] = node.value
            continue
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = node.value
    return found


def _literal(assignments: dict[str, ast.expr], name: str, source: str) -> Any:
    node = assignments.get(name)
    if node is None:
        raise TableExtractionError(f"{source} no longer defines {name}")
    try:
        return ast.literal_eval(node)
    except ValueError as error:
        raise TableExtractionError(
            f"{source}:{name} is not a literal the generator can read: {error}"
        ) from error


def _apdu_commands(assignments: dict[str, ast.expr], source: str) -> dict[Any, tuple[str, str]]:
    """Read ``_APDU_COMMANDS``, whose values are ``ApduCommandInfo`` calls.

    ``ast.literal_eval`` refuses a call node, so the keys are evaluated
    literally and the first two positional arguments -- name and spec
    citation -- are pulled out of each call by hand.
    """
    node = assignments.get("_APDU_COMMANDS")
    if not isinstance(node, ast.Dict):
        raise TableExtractionError(f"{source} no longer defines _APDU_COMMANDS as a dict")
    commands: dict[Any, tuple[str, str]] = {}
    for key_node, value_node in zip(node.keys, node.values):
        if key_node is None:
            continue
        key = ast.literal_eval(key_node)
        if not isinstance(value_node, ast.Call) or len(value_node.args) < 2:
            raise TableExtractionError(
                f"{source}:_APDU_COMMANDS[{key!r}] is not an ApduCommandInfo(...) call"
            )
        commands[key] = (
            ast.literal_eval(value_node.args[0]),
            ast.literal_eval(value_node.args[1]),
        )
    return commands


def _set_literal(assignments: dict[str, ast.expr], name: str, source: str) -> list[Any]:
    """Read a ``frozenset({...})`` constant.

    ``ast.literal_eval`` refuses the call node even though its single
    argument is a literal set, so the wrapper is stepped over first.
    """
    node = assignments.get(name)
    if node is None:
        raise TableExtractionError(f"{source} no longer defines {name}")
    if isinstance(node, ast.Call):
        function = node.func
        callee = getattr(function, "id", "")
        if callee not in ("frozenset", "set") or len(node.args) != 1:
            raise TableExtractionError(
                f"{source}:{name} is not a frozenset(...) of literals"
            )
        node = node.args[0]
    try:
        value = ast.literal_eval(node)
    except ValueError as error:
        raise TableExtractionError(
            f"{source}:{name} is not a literal the generator can read: {error}"
        ) from error
    return sorted(value, key=lambda entry: (isinstance(entry, tuple), entry))


#: The SIMCARD.etsi_fs constants the AID table is built from. Kept as an
#: explicit list so the generated output and the source digest both
#: depend on these and nothing else.
AID_CONSTANTS = (
    "USIM_AID",
    "ISIM_AID",
    "ISDR_AID",
    "ECASD_AID",
    "MNO_SD_AID",
    "PROFILE_AID_PREFIX",
)


def _named_constants(
    assignments: dict[str, ast.expr],
    names: tuple[str, ...],
) -> dict[str, Any]:
    """Collect exactly the named literal module constants."""
    collected: dict[str, Any] = {}
    for name in names:
        node = assignments.get(name)
        if node is None:
            continue
        try:
            collected[name] = ast.literal_eval(node)
        except ValueError:
            continue
    return collected


def _prefixed_constants(
    assignments: dict[str, ast.expr],
    prefix: str,
) -> dict[str, Any]:
    """Collect every literal module constant whose name starts with *prefix*."""
    collected: dict[str, Any] = {}
    for name, node in assignments.items():
        if not name.startswith(prefix):
            continue
        try:
            collected[name] = ast.literal_eval(node)
        except ValueError:
            continue
    return collected


# ------------------------------------------------------------- normalisation
_TYPOGRAPHY = {
    "\u2014": "--",
    "\u2013": "-",
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2026": "...",
    "\u00a0": " ",
    "\u00a7": "section ",
    "\u00b7": "-",
}


def ascii_normalise(text: str) -> str:
    """Fold typography to ASCII.

    ``scripts/check_repo_hygiene.py`` scans text files for em dashes and
    curly quotes. The Python docstrings these names come from contain
    both, so a verbatim copy would import violations into the generated
    Lua the moment ``.lua`` joins the scanned suffixes.
    """
    folded = str(text or "")
    for source_character, replacement in _TYPOGRAPHY.items():
        folded = folded.replace(source_character, replacement)
    folded = unicodedata.normalize("NFKD", folded)
    return folded.encode("ascii", "ignore").decode("ascii")


def lua_string(value: str) -> str:
    """Quote *value* as a Lua string literal."""
    escaped = ascii_normalise(value)
    escaped = escaped.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{escaped}"'


# ----------------------------------------------------------------- rendering
def _render_int_keyed(
    name: str,
    mapping: dict[int, str],
    *,
    width: int = 2,
) -> str:
    lines = [f"M.{name} = {{"]
    for key in sorted(mapping):
        lines.append(f"    [0x{key:0{width}X}] = {lua_string(mapping[key])},")
    lines.append("}")
    return "\n".join(lines)


def _render_string_keyed(name: str, mapping: dict[str, str]) -> str:
    lines = [f"M.{name} = {{"]
    for key in sorted(mapping):
        lines.append(f"    [{lua_string(key)}] = {lua_string(mapping[key])},")
    lines.append("}")
    return "\n".join(lines)


def _render_paths(name: str, mapping: dict[str, Iterable[str]]) -> str:
    lines = [f"M.{name} = {{"]
    for key in sorted(mapping):
        joined = " / ".join(str(part) for part in mapping[key])
        lines.append(f"    [{lua_string(key)}] = {lua_string(joined)},")
    lines.append("}")
    return "\n".join(lines)


def _render_commands(commands: dict[Any, tuple[str, str]]) -> str:
    """Render the instruction tables.

    ``_APDU_COMMANDS`` is keyed on ``(CLA | None, INS)``. Lua has no
    tuple keys, so the table is split: a class-qualified table keyed on
    ``CLA * 256 + INS`` and a wildcard table keyed on ``INS`` alone.
    """
    qualified: dict[int, tuple[str, str]] = {}
    wildcard: dict[int, tuple[str, str]] = {}
    for key, (command_name, source) in commands.items():
        class_byte, instruction = key
        if class_byte is None:
            wildcard[int(instruction)] = (command_name, source)
        else:
            qualified[(int(class_byte) << 8) | int(instruction)] = (command_name, source)

    blocks: list[str] = []
    for table_name, table, width in (
        ("INS_NAMES", wildcard, 2),
        ("CLA_INS_NAMES", qualified, 4),
    ):
        lines = [f"M.{table_name} = {{"]
        for key in sorted(table):
            lines.append(f"    [0x{key:0{width}X}] = {lua_string(table[key][0])},")
        lines.append("}")
        blocks.append("\n".join(lines))
    for table_name, table, width in (
        ("INS_SOURCE", wildcard, 2),
        ("CLA_INS_SOURCE", qualified, 4),
    ):
        lines = [f"M.{table_name} = {{"]
        for key in sorted(table):
            lines.append(f"    [0x{key:0{width}X}] = {lua_string(table[key][1])},")
        lines.append("}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _render_risk(risk: dict[int, tuple[str, str]]) -> str:
    """Render risk classes as a numeric enum plus the human name.

    The numeric form is what makes ``yapdu.risk == 3`` a usable display
    filter for "show me every destructive command in this capture".
    """
    order = {"unknown": 0, "read": 1, "write": 2, "destructive": 3}
    class_lines = ["M.RISK_CLASS = {"]
    for label, value in sorted(order.items(), key=lambda item: item[1]):
        class_lines.append(f"    [{lua_string(label)}] = {value},")
    class_lines.append("}")

    name_lines = ["M.RISK_CLASS_NAMES = {"]
    for label, value in sorted(order.items(), key=lambda item: item[1]):
        name_lines.append(f"    [{value}] = {lua_string(label)},")
    name_lines.append("}")

    risk_lines = ["M.APDU_RISK = {"]
    detail_lines = ["M.APDU_RISK_NAME = {"]
    for key in sorted(risk):
        risk_class, description = risk[key]
        risk_lines.append(f"    [0x{key:02X}] = {order.get(risk_class, 0)},")
        detail_lines.append(f"    [0x{key:02X}] = {lua_string(description)},")
    risk_lines.append("}")
    detail_lines.append("}")

    # apdu_risk.classify_apdu reports an unlisted instruction as "write":
    # absence from the table is not evidence of safety.
    default_line = f"M.APDU_RISK_DEFAULT = {order['write']}"

    return "\n\n".join(
        [
            "\n".join(class_lines),
            "\n".join(name_lines),
            "\n".join(risk_lines),
            "\n".join(detail_lines),
            default_line,
        ]
    )


def _render_case_hints(hints: dict[Any, str]) -> str:
    qualified: dict[int, str] = {}
    wildcard: dict[int, str] = {}
    for key, case_name in hints.items():
        if isinstance(key, tuple):
            qualified[(int(key[0]) << 8) | int(key[1])] = case_name
        else:
            wildcard[int(key)] = case_name
    blocks = []
    for table_name, table, width in (
        ("INS_CASE_HINT", wildcard, 2),
        ("CLA_INS_CASE_HINT", qualified, 4),
    ):
        lines = [f"M.{table_name} = {{"]
        for key in sorted(table):
            lines.append(f"    [0x{key:0{width}X}] = {lua_string(table[key])},")
        lines.append("}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _render_requires_data(entries) -> str:
    """Render the instructions that always carry a command data field."""
    qualified: list[int] = []
    wildcard: list[int] = []
    for entry in entries:
        if isinstance(entry, tuple):
            qualified.append((int(entry[0]) << 8) | int(entry[1]))
        else:
            wildcard.append(int(entry))
    blocks = []
    for table_name, values, width in (
        ("INS_REQUIRES_DATA", wildcard, 2),
        ("CLA_INS_REQUIRES_DATA", qualified, 4),
    ):
        lines = [f"M.{table_name} = {{"]
        for key in sorted(values):
            lines.append(f"    [0x{key:0{width}X}] = true,")
        lines.append("}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _render_aids(constants: dict[str, str]) -> str:
    """Render the well-known AIDs as an AID-hex to friendly-name table."""
    labels = {
        "USIM_AID": "ADF.USIM",
        "ISIM_AID": "ADF.ISIM",
        "ISDR_AID": "ISD-R",
        "ECASD_AID": "ECASD",
        "MNO_SD_AID": "MNO-SD",
    }
    lines = ["M.AIDS = {"]
    for constant_name in sorted(labels):
        aid_hex = constants.get(constant_name)
        if not isinstance(aid_hex, str) or len(aid_hex) == 0:
            continue
        lines.append(f"    [{lua_string(aid_hex.upper())}] = {lua_string(labels[constant_name])},")
    lines.append("}")
    prefix = constants.get("PROFILE_AID_PREFIX", "")
    lines.append("")
    lines.append(f"M.PROFILE_AID_PREFIX = {lua_string(str(prefix).upper())}")
    return "\n".join(lines)


def _render_gp_lifecycle(constants: dict[str, int]) -> str:
    """Render GlobalPlatform life-cycle states.

    Several names share a value (``GP_LCS_PERSONALIZED`` and
    ``GP_LCS_SD_PERSONALIZED`` are both ``0x0F``), so the rendered table
    joins the colliding labels rather than silently keeping one.
    """
    by_value: dict[int, list[str]] = {}
    for name, value in constants.items():
        if not isinstance(value, int):
            continue
        label = name.removeprefix("GP_LCS_").replace("_", " ")
        by_value.setdefault(value, []).append(label)
    lines = ["M.GP_LIFECYCLE = {"]
    for value in sorted(by_value):
        joined = " / ".join(sorted(by_value[value]))
        lines.append(f"    [0x{value:02X}] = {lua_string(joined)},")
    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------- RSP ASN.1
# The GSMA RSP modules are declared AUTOMATIC TAGS, so a SEQUENCE whose
# members carry no tag of their own has [0], [1], [2] ... assigned in
# declaration order, and one whose members are tagged keeps the universal
# tag on any member that is not (X.680 clause 12.3). Both rules are
# needed: EUICCInfo2 is the tagged kind and ProfileInfoListResponse the
# automatic kind, and getting the second wrong shifts every name in it.

#: ITU-T X.680 universal tag numbers for the built-ins these modules use.
_UNIVERSAL_TAGS: dict[str, int] = {
    "BOOLEAN": 0x01,
    "INTEGER": 0x02,
    "BIT": 0x03,
    "OCTET": 0x04,
    "NULL": 0x05,
    "OBJECT": 0x06,
    "UTF8String": 0x0C,
    "NumericString": 0x12,
    "PrintableString": 0x13,
    "IA5String": 0x16,
    "VisibleString": 0x1A,
    "UTCTime": 0x17,
    "GeneralizedTime": 0x18,
    "SEQUENCE": 0x30,
    "SET": 0x31,
}

_CONSTRUCTED_KINDS = ("SEQUENCE", "SET", "CHOICE")

#: Types the RSP modules import rather than define (SGP.22 clause 2.4a).
#: Their encoding is fixed by the module they come from, so it is stated
#: here rather than guessed: without it every `SEQUENCE OF
#: SubjectKeyIdentifier` has no element type and a member typed
#: `Certificate` is read as primitive.
_IMPORTED_TYPES: dict[str, str] = {
    "Certificate": "SEQUENCE",           # RFC 5280 clause 4.1
    "CertificateList": "SEQUENCE",       # RFC 5280 clause 5.1
    "SubjectKeyIdentifier": "OCTET",     # RFC 5280 clause 4.2.1.2, an OCTET STRING
    "UICCCapability": "BIT",             # TCA eUICC Profile Package, a BIT STRING
}

#: `[3]`, `[PRIVATE 3]`, `[APPLICATION 15]`. The class decides the top two
#: bits of the identifier octet (X.690 clause 8.1.2.2), which is how
#: `ProfileInfo ::= [PRIVATE 3] SEQUENCE` becomes 'E3' rather than 'A3'.
_TAG = r"\[(?:(UNIVERSAL|APPLICATION|CONTEXT|PRIVATE)[ \t]+)?(\d+)\]"
_TAG_CLASS_BASE = {
    "UNIVERSAL": 0x00,
    "APPLICATION": 0x40,
    "CONTEXT": 0x80,
    "PRIVATE": 0xC0,
    None: 0x80,
}

_ASN1_HEAD = re.compile(
    r"^([A-Za-z][\w-]*)[ \t]*::=[ \t]*(?:" + _TAG + r"[ \t]*)?"
    r"(SEQUENCE|SET|CHOICE)[ \t]*\{",
    re.M,
)
#: A declaration that is not a constructed type: `Iccid ::= [APPLICATION
#: 26] OCTET STRING (SIZE(10))`. It still carries a tag its members
#: inherit when they are declared untagged.
_ASN1_DECL = re.compile(
    r"^([A-Za-z][\w-]*)[ \t]*::=[ \t]*(?:" + _TAG + r"[ \t]*)?([A-Za-z][\w ]*?)"
    r"(?:[ \t]*[({]|[ \t]*$)",
    re.M,
)
#: What the specification says a tag encodes to, used to check the
#: computed value rather than to produce it.
_ASN1_STATED_TAG = re.compile(r"--[^\n]*?[Tt]ag[ \t]*'([0-9A-Fa-f]{2,4})'")
_ASN1_MEMBER = re.compile(
    r"^([a-z][A-Za-z0-9_-]*)[ \t]*(?:" + _TAG + r")?[ \t]+(.+)$", re.S
)


def _asn1_uncomment(text: str) -> str:
    """Strip ASN.1 comments, including the ones the PDF conversion wrapped.

    A comment runs to end of line, but the conversion re-flowed long ones
    onto the next line without repeating the ``--``. Every such
    continuation starts at column zero while every real member is
    indented, which is what separates them: without this a body cannot be
    split on its commas, and a pattern allowed to span the break reads
    ``specification [57]`` out of a citation.
    """
    kept = []
    for line in text.split("\n"):
        stripped = re.sub(r"--.*$", "", line)
        kept.append(stripped)
    return "\n".join(kept)


def _asn1_body_lines(body: str) -> str:
    """Keep the indented lines of a body and drop the rest.

    Every member of these types is indented; every line the conversion
    left at column zero is the tail of a comment that wrapped, including
    the ones that begin with a quote -- the `'BF23'` under
    BoundProfilePackage's first member is comment text, and leaving it in
    place swallows the member that follows it.
    """
    return "\n".join(
        line for line in body.split("\n") if not line or line[:1].isspace()
    )


def _asn1_block(text: str, open_brace: int) -> str:
    """Return the text between *open_brace* and its matching close."""
    depth = 0
    for index in range(open_brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1:index]
    return ""


def _asn1_split_members(body: str) -> list[str]:
    """Split a SEQUENCE/CHOICE body on its top-level commas."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in body:
        if char in "{(":
            depth += 1
        elif char in "})":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [" ".join(part.split()) for part in parts if part.strip()]


def _asn1_tag(tag_class: str | None, number: int, constructed: bool) -> int | None:
    """Encode a tag the way X.690 clause 8.1.2 does.

    Numbers below 31 fit the identifier octet. Above that the low five
    bits are the escape to the multi-byte form, which is why
    ``EUICCInfo2 ::= [34]`` is 'BF22' and not 'A2': the value here is the
    tag bytes read as one integer, matching what tlv.read_tag produces.
    """
    base = _TAG_CLASS_BASE.get(tag_class)
    if base is None or number < 0:
        return None
    lead = base | (0x20 if constructed else 0x00)
    if number < 31:
        return lead | number
    if number < 128:
        return ((lead | 0x1F) << 8) | number
    return None


def _asn1_tag_key(tag: int) -> str:
    return f"{tag:04X}" if tag > 0xFF else f"{tag:02X}"


class _Asn1Module:
    """The constructed types of the RSP specifications, ready to resolve."""

    def __init__(self) -> None:
        self.types: dict[str, dict[str, Any]] = {}
        self.aliases: dict[str, str] = {}
        self.root_tags: dict[str, int] = {}
        #: What the specification's own comments say a type encodes to.
        self.stated_tags: dict[str, int] = {}
        #: Synthetic one-entry types for the elements of a SEQUENCE OF.
        self.list_types: dict[str, dict[int, tuple[str, str]]] = {}

    def add_spec(self, raw: str) -> None:
        # The tag a declaration carries is computed from its class and
        # number; the "-- Tag 'XX'" the specification writes beside it is
        # kept to check that computation, not to make it. A disagreement
        # means the line was misread, and the type is dropped.
        for match in _ASN1_HEAD.finditer(raw):
            name = match.group(1)
            if match.group(3) is None or name in self.stated_tags:
                continue
            # Only the declaration's own line: a "-- Tag 'XX'" further
            # down belongs to a different member. find returns -1 at the
            # end of the file, which search would read as "no room" and
            # skip the check silently.
            line_end = raw.find("\n", match.end())
            if line_end < 0:
                line_end = len(raw)
            stated = _ASN1_STATED_TAG.search(raw, match.end(), line_end)
            if stated is not None:
                self.stated_tags[name] = int(stated.group(1), 16)
        text = _asn1_uncomment(raw)
        for match in _ASN1_HEAD.finditer(text):
            name = match.group(1)
            body = _asn1_body_lines(_asn1_block(text, match.end() - 1))
            if self.types.get(name, {}).get("body", "").strip():
                continue
            self.types[name] = {"kind": match.group(4), "body": body}
            if match.group(3) is not None:
                tag = _asn1_tag(match.group(2), int(match.group(3)), True)
                if tag is not None:
                    self.root_tags.setdefault(name, tag)
        for match in _ASN1_DECL.finditer(text):
            name = match.group(1)
            if name in self.types:
                continue
            self.aliases.setdefault(name, match.group(4).strip())
            if match.group(3) is not None and name not in self.root_tags:
                constructed = match.group(4).strip().split()[0] in _CONSTRUCTED_KINDS
                tag = _asn1_tag(match.group(2), int(match.group(3)), constructed)
                if tag is not None:
                    self.root_tags[name] = tag

    def base_word(self, expression: str) -> str:
        """Follow a type alias down to the word that decides the tag."""
        words = expression.strip().split()
        if not words:
            return ""
        word = _IMPORTED_TYPES.get(words[0], words[0])
        seen: set[str] = set()
        while word in self.aliases and word not in seen:
            seen.add(word)
            following = self.aliases[word].split()
            if not following:
                break
            word = following[0]
        return word

    def is_constructed(self, expression: str) -> bool:
        word = self.base_word(expression)
        if word in _CONSTRUCTED_KINDS:
            return True
        entry = self.types.get(word)
        return entry is not None and entry["kind"] in _CONSTRUCTED_KINDS

    def declared_tag(self, name: str) -> int | None:
        """The tag a named type carries on the wire."""
        if name in self.root_tags:
            return self.root_tags[name]
        return _UNIVERSAL_TAGS.get(self.base_word(name))

    def opened_type(self, expression: str) -> str:
        """The type whose members apply inside a member, or "".

        A `SEQUENCE OF T` opens a synthetic type holding one entry: T
        under its own tag. Without it the children of
        ProfileInfoListResponse's 'A0' -- the 'E3' ProfileInfo records an
        eUICC lists its profiles with -- have nothing to be named by,
        because ASN.1 gives the elements of a SEQUENCE OF no field name.
        """
        words = expression.strip().split()
        if not words:
            return ""
        if words[0] in ("SEQUENCE", "SET") and len(words) > 2 and words[1] == "OF":
            element = words[2]
            if (
                element not in self.types
                and element not in self.aliases
                and element not in _IMPORTED_TYPES
            ):
                return ""
            tag = self.declared_tag(element)
            if tag is None:
                return ""
            synthetic = f"SEQUENCE OF {element}"
            self.list_types[synthetic] = {
                tag: (element, element if element in self.types else "")
            }
            return synthetic
        word = words[0]
        if word in self.types:
            return word
        seen: set[str] = set()
        while word in self.aliases and word not in seen:
            seen.add(word)
            following = self.aliases[word].split()
            if not following:
                break
            word = following[0]
            if word in self.types:
                return word
        return ""

    def _member_tag(
        self, tag_class: str | None, number: str | None, expression: str
    ) -> int | None:
        if number is not None:
            return _asn1_tag(tag_class, int(number), self.is_constructed(expression))
        # An untagged member keeps whatever tag its own type carries: the
        # declared tag of a named RSP type, otherwise the universal tag of
        # the built-in it resolves to.
        head = expression.strip().split()
        if head and head[0] in self.root_tags:
            return self.root_tags[head[0]]
        return _UNIVERSAL_TAGS.get(self.base_word(expression))

    def members(self, name: str) -> dict[int, tuple[str, str]] | None:
        """Tag to (member name, opened type) for *name*, or None if unsafe.

        Returns None rather than a guess when two members land on one tag:
        a misread body is better reported as no names at all than as names
        attached to the wrong tags.
        """
        entry = self.types.get(name)
        if entry is None:
            return None
        parsed: list[tuple[str, str | None, str | None, str]] = []
        for chunk in _asn1_split_members(entry["body"]):
            match = _ASN1_MEMBER.match(chunk)
            if match is None:
                continue
            parsed.append(
                (match.group(1), match.group(2), match.group(3), match.group(4))
            )
        if not parsed:
            return None
        # AUTOMATIC TAGS assigns [0], [1], ... in declaration order, but
        # only to a type where no member is tagged by hand.
        automatic = all(number is None for _, _, number, _ in parsed)
        members: dict[int, tuple[str, str]] = {}
        for index, (field, tag_class, number, expression) in enumerate(parsed):
            if automatic:
                tag = _asn1_tag(None, index, self.is_constructed(expression))
            else:
                tag = self._member_tag(tag_class, number, expression)
            if tag is None:
                continue
            if tag in members:
                return None
            members[tag] = (field, self.opened_type(expression))
        return members or None


def specs_present(repo_root: Path = REPO_ROOT) -> bool:
    return all((repo_root / relative).is_file() for relative in SPEC_SOURCES)


def read_rsp_extract(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """The checked-in RSP extract, refused unless it has the three tables."""
    path = repo_root / RSP_EXTRACT
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise TableExtractionError(f"cannot read {RSP_EXTRACT}: {error}") from error
    keys = ("rsp_roots", "rsp_members", "rsp_member_types")
    if not isinstance(data, dict) or any(not isinstance(data.get(key), dict) for key in keys):
        raise TableExtractionError(f"{RSP_EXTRACT} does not hold {', '.join(keys)}")
    return {key: data[key] for key in keys}


def render_rsp_extract(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def collect_rsp_members(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """The RSP member names: from the specifications when present, else the extract."""
    if specs_present(repo_root):
        return rsp_members_from_specs(repo_root)
    return read_rsp_extract(repo_root)


def rsp_members_from_specs(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Read the RSP member names out of the converted specifications.

    Raises :class:`TableExtractionError` when a computed tag disagrees
    with the one the specification states beside it: that means a
    declaration was misread, and a misread tag names the wrong field.
    """
    module = _Asn1Module()
    for relative in SPEC_SOURCES:
        path = repo_root / relative
        if not path.is_file():
            raise TableExtractionError(f"{relative} is missing")
        module.add_spec(path.read_text(encoding="utf-8", errors="replace"))

    disagreed = sorted(
        name
        for name, stated in module.stated_tags.items()
        if module.root_tags.get(name) != stated
    )
    if disagreed:
        raise TableExtractionError(
            "computed tag disagrees with the specification for: "
            + ", ".join(disagreed)
        )
    # The comparison passes vacuously once the "-- Tag 'XX'" pattern stops
    # matching, and the converted SGP.22 and SGP.32 texts state well over a
    # hundred tags.
    if len(module.stated_tags) < _MIN_STATED_TAGS:
        raise TableExtractionError(
            f"read {len(module.stated_tags)} stated tags from the specifications, "
            f"fewer than {_MIN_STATED_TAGS}: their tag comments are no longer recognised"
        )

    names: dict[str, dict[str, str]] = {}
    opens: dict[str, dict[str, str]] = {}
    for type_name in sorted(module.types):
        members = module.members(type_name)
        if members is None:
            continue
        for tag, (field, opened) in members.items():
            names.setdefault(type_name, {})[_asn1_tag_key(tag)] = field
            if opened:
                opens.setdefault(type_name, {})[_asn1_tag_key(tag)] = opened
    # opened_type fills list_types while members() runs, so this has to
    # come after the loop above.
    for synthetic, entries in module.list_types.items():
        for tag, (field, opened) in entries.items():
            names.setdefault(synthetic, {})[_asn1_tag_key(tag)] = field
            if opened:
                opens.setdefault(synthetic, {})[_asn1_tag_key(tag)] = opened

    # Only the 'BFxx' function tags: those are the ones an ES10 payload
    # can start with, and the resolver reaches this table through
    # is_rsp_function. A single-byte root would be a key nothing can look
    # up, and 'A2' is an ordinary constructed context tag far more often
    # than it is a RemoteProfileProvisioningResponse.
    roots = {
        _asn1_tag_key(tag): name
        for name, tag in module.root_tags.items()
        if name in names and 0xBF00 <= tag <= 0xBFFF
    }
    return {"rsp_roots": roots, "rsp_members": names, "rsp_member_types": opens}


def _render_nested_string(name: str, mapping: dict[str, dict[str, str]]) -> str:
    lines = [f"M.{name} = {{"]
    for outer in sorted(mapping):
        lines.append(f"    [{lua_string(outer)}] = {{")
        for inner in sorted(mapping[outer]):
            lines.append(
                f"        [{lua_string(inner)}] = {lua_string(mapping[outer][inner])},"
            )
        lines.append("    },")
    lines.append("}")
    return "\n".join(lines)


# ------------------------------------------------------------------- collect
def collect_tables(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Read every source table. Raises :class:`TableExtractionError`."""
    parsed = {
        key: _assignments(_parse_module(repo_root / relative))
        for key, relative in SOURCES.items()
    }

    collected: dict[str, Any] = {
        "risk": _literal(parsed["apdu_risk"], "APDU_RISK", SOURCES["apdu_risk"]),
        "case_hints": _literal(
            parsed["apdu_tables"], "APDU_CASE_HINTS", SOURCES["apdu_tables"]
        ),
        "requires_data": _set_literal(
            parsed["apdu_tables"], "APDU_REQUIRES_DATA", SOURCES["apdu_tables"]
        ),
        "proactive": _literal(
            parsed["stk_tables"], "PROACTIVE_COMMANDS", SOURCES["stk_tables"]
        ),
        "events": _literal(parsed["stk_tables"], "EVENT_LIST", SOURCES["stk_tables"]),
        "tls_content_types": _literal(
            parsed["tls_tables"], "TLS_CONTENT_TYPES", SOURCES["tls_tables"]
        ),
        "tls_alert_levels": _literal(
            parsed["tls_tables"], "TLS_ALERT_LEVELS", SOURCES["tls_tables"]
        ),
        "tls_alert_descriptions": _literal(
            parsed["tls_tables"], "TLS_ALERT_DESCRIPTIONS", SOURCES["tls_tables"]
        ),
        "tls_handshake_types": _literal(
            parsed["tls_tables"], "TLS_HANDSHAKE_TYPES", SOURCES["tls_tables"]
        ),
        "commands": _apdu_commands(parsed["asn1"], SOURCES["asn1"]),
        "fallback_tags": _literal(parsed["asn1"], "_FALLBACK_TAGS", SOURCES["asn1"]),
        "universal_tags": _literal(
            parsed["asn1"], "_UNIVERSAL_TAG_NAMES", SOURCES["asn1"]
        ),
        "tag_classes": _literal(parsed["asn1"], "_TAG_CLASS_NAMES", SOURCES["asn1"]),
        "status_words": _literal(parsed["mcp"], "STATUS_WORDS", SOURCES["mcp"]),
        "ber_tags": _literal(parsed["mcp"], "BER_TLV_TAGS", SOURCES["mcp"]),
        "refresh": _literal(
            parsed["decode_state"], "_REFRESH_QUALIFIER_NAMES", SOURCES["decode_state"]
        ),
        "file_paths": _literal(
            parsed["decode_state"], "_KNOWN_FILE_PATHS", SOURCES["decode_state"]
        ),
        "aid_paths": _literal(
            parsed["decode_state"], "_KNOWN_AID_PATHS", SOURCES["decode_state"]
        ),
        # Named explicitly, not swept up by prefix. An empty prefix
        # collects every literal constant in the module -- thirteen of
        # them, of which six are rendered -- and the other seven still
        # feed the source digest, so adding an unrelated constant to
        # SIMCARD/etsi_fs.py failed the drift test for a change that
        # altered no table.
        "aids": _named_constants(parsed["etsi_fs"], AID_CONSTANTS),
        "gp_lifecycle": _prefixed_constants(parsed["gp"], "GP_LCS_"),
    }
    collected.update(collect_rsp_members(repo_root))
    return collected


def _canonical(value: Any) -> Any:
    """Reduce a collected value to something order-independent."""
    if isinstance(value, dict):
        return sorted((repr(key), _canonical(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return repr(value)


def _source_digest(tables: dict[str, Any]) -> str:
    """Digest the collected tables so drift is attributable.

    The digest has to describe table *content*, not the order the source
    file happens to declare it in. Hashing ``repr()`` of a dict hashes
    its insertion order, so reordering STATUS_WORDS in
    ``Tools/YggdraMCP/server.py`` without changing a single entry failed
    the drift test -- while every rendered table stayed byte-identical,
    because the renderers all sort. A drift guard that fires on
    non-drift teaches people to regenerate without reading the diff,
    which is the one habit it exists to prevent.
    """
    canonical = repr(sorted((key, _canonical(value)) for key, value in tables.items()))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _tag_meaning_key(name: str) -> str:
    """Normalise a tag name for comparison across the two sources.

    The two tables spell the same concept differently -- ``ICCID`` and
    ``iccid``, ``EUICC_INFO2`` and ``EUICCInfo2`` -- so a plain string
    comparison would report almost every shared tag as a conflict.
    """
    return "".join(character for character in name.lower() if character.isalnum())


def _same_tag_meaning(left: str, right: str) -> bool:
    """True when two tag names plainly describe the same thing."""
    first = _tag_meaning_key(left)
    second = _tag_meaning_key(right)
    if first == second:
        return True
    # One naming the other plus a qualifier is agreement, not conflict.
    return first in second or second in first


# -------------------------------------------------------------------- render
def render_tables_lua(repo_root: Path = REPO_ROOT) -> str:
    """Return the complete generated Lua module as text."""
    tables = collect_tables(repo_root)

    # Merge the two BER-TLV tag tables.
    #
    # Twenty-one tags appear in both, and letting one silently overwrite
    # the other makes the dissector contradict the tool the losing name
    # came from. '5A' is the one that bites: Tools/Asn1TlvDecode calls it
    # EID_OR_ICCID because the reading depends on context, while
    # Tools/YggdraMCP calls it ICCID -- so taking the MCP name outright
    # labels the EID inside a BF3E GetEuiccData response "ICCID", which
    # is exactly the confusion the SGP-context qualifier exists to
    # prevent. Where the two disagree, both names are kept.
    ber_tags: dict[str, str] = {}
    fallback_names: dict[str, str] = {}
    for tag_hex, (tag_name, tag_source) in sorted(tables["fallback_tags"].items()):
        key = str(tag_hex).upper()
        fallback_names[key] = str(tag_name)
        ber_tags[key] = f"{tag_name} ({tag_source})"
    for tag_value, tag_name in sorted(tables["ber_tags"].items()):
        width = 2 if tag_value <= 0xFF else 4
        key = f"{tag_value:0{width}X}"
        other = fallback_names.get(key)
        if other is not None and _same_tag_meaning(other, str(tag_name)) is False:
            ber_tags[key] = f"{tag_name} / {other}"
        else:
            ber_tags[key] = str(tag_name)

    # 'A9'/'AA' are euiccCiPKId lists only inside an EUICCInfo1/2 (BF20/BF22).
    # Elsewhere -- the Type-2/3 file tags of an EF.PBR record, say -- they are
    # ordinary constructed context tags, so the flat dissector table names
    # them generically and rsp.lua applies the EUICCInfo meaning by parent.
    # The MCP source keeps its own names; only the generated table is toned
    # down, so a filesystem read is not labelled euiccCiPKIdListForVerification.
    for _context_tag, _generic_name in (
        ("A9", "context-9 constructed; meaning depends on the enclosing structure"),
        ("AA", "context-10 constructed; meaning depends on the enclosing structure"),
    ):
        if _context_tag in ber_tags:
            ber_tags[_context_tag] = _generic_name

    # A tag name is a label on a tree node, not a sentence. "context-0
    # constructed" already says the reading depends on where the tag sits;
    # the clause spelling that out is forty-five characters of every such
    # node in a capture. The MCP tables keep the long form -- they answer
    # in prose -- so only the generated Lua is shortened.
    for _key, _name in list(ber_tags.items()):
        ber_tags[_key] = _name.replace(
            "; meaning depends on the enclosing structure", ""
        )

    sections: list[str] = [
        _render_commands(tables["commands"]),
        _render_case_hints(tables["case_hints"]),
        _render_requires_data(tables["requires_data"]),
        _render_risk(tables["risk"]),
        _render_int_keyed("STATUS_WORDS", tables["status_words"], width=4),
        _render_string_keyed("BER_TAGS", ber_tags),
        _render_int_keyed("UNIVERSAL_TAGS", tables["universal_tags"]),
        _render_int_keyed("TAG_CLASSES", tables["tag_classes"]),
        _render_int_keyed("PROACTIVE_COMMANDS", tables["proactive"]),
        _render_int_keyed("EVENT_NAMES", tables["events"]),
        _render_int_keyed("REFRESH_QUALIFIERS", tables["refresh"]),
        _render_int_keyed("TLS_CONTENT_TYPES", tables["tls_content_types"]),
        _render_int_keyed("TLS_ALERT_LEVELS", tables["tls_alert_levels"]),
        _render_int_keyed("TLS_ALERT_DESCRIPTIONS", tables["tls_alert_descriptions"]),
        _render_int_keyed("TLS_HANDSHAKE_TYPES", tables["tls_handshake_types"]),
        _render_paths("FILE_PATHS", tables["file_paths"]),
        _render_paths("AID_PATHS", tables["aid_paths"]),
        _render_aids(tables["aids"]),
        _render_gp_lifecycle(tables["gp_lifecycle"]),
        _render_string_keyed("RSP_ROOTS", tables["rsp_roots"]),
        _render_nested_string("RSP_MEMBERS", tables["rsp_members"]),
        _render_nested_string("RSP_MEMBER_TYPES", tables["rsp_member_types"]),
    ]

    header = "\n".join(
        [
            "-- SPDX-License-Identifier: GPL-3.0-or-later",
            "-- Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.",
            "",
            f"-- Generated by {GENERATOR_NAME}. Do not edit by hand.",
            "--",
            "-- Every table here is lifted from a Python module that another",
            "-- part of YggdraSIM already treats as authoritative, so a status",
            "-- word or instruction name cannot mean one thing in a trace and",
            "-- another in the toolkit. Regenerate after changing any source:",
            "--",
            f"--   python {GENERATOR_NAME} --write",
            "--",
            "-- Sources:",
        ]
        + [f"--   {relative}" for _, relative in sorted(SOURCES.items())]
        + [f"--   {relative}" for relative in SPEC_SOURCES]
        + [
            "",
            "local M = {}",
            "",
            f'M.SOURCE_DIGEST = "{_source_digest(tables)}"',
            "",
        ]
    )

    body = "\n\n".join(sections)
    return header + "\n" + body + "\n\nreturn M\n"


# ----------------------------------------------------------------------- CLI
def _extract_is_current(extract_path: Path) -> bool:
    try:
        existing = extract_path.read_text(encoding="utf-8")
    except OSError:
        return False
    return existing == render_rsp_extract(rsp_members_from_specs())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="generate_apdu_dissector_tables",
        description="Emit the Wireshark APDU dissector's Lua lookup tables.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--write",
        action="store_true",
        help="Write the generated module to its checked-in location.",
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when the checked-in module is out of date.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help="Override the output path (defaults to the checked-in location).",
    )
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    try:
        rendered = render_tables_lua()
    except TableExtractionError as error:
        print(f"generate_apdu_dissector_tables: {error}", file=sys.stderr)
        return 2

    extract_path = REPO_ROOT / RSP_EXTRACT
    if args.check:
        try:
            existing = Path(args.output).read_text(encoding="utf-8")
        except OSError as error:
            print(f"generate_apdu_dissector_tables: {error}", file=sys.stderr)
            return 1
        if existing != rendered:
            print(
                "generate_apdu_dissector_tables: "
                f"{args.output} is out of date. Run `python {GENERATOR_NAME} --write`.",
                file=sys.stderr,
            )
            return 1
        if specs_present() and not _extract_is_current(extract_path):
            print(
                "generate_apdu_dissector_tables: "
                f"{RSP_EXTRACT} is out of date. Run `python {GENERATOR_NAME} --write`.",
                file=sys.stderr,
            )
            return 1
        return 0

    if args.write:
        if not specs_present():
            print(
                "generate_apdu_dissector_tables: --write reads the RSP names from "
                f"{SPEC_SOURCES[0]}; add the specification library first.",
                file=sys.stderr,
            )
            return 2
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        extract_path.write_text(render_rsp_extract(rsp_members_from_specs()), encoding="utf-8")
        print(f"wrote {target} and {RSP_EXTRACT}")
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
