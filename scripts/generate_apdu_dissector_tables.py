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
    "asn1": "Tools/Asn1TlvDecode/main.py",
    "mcp": "Tools/YggdraMCP/server.py",
    "decode_state": "Tools/HilBridge/live_decode_state.py",
    "etsi_fs": "SIMCARD/etsi_fs.py",
    "gp": "SIMCARD/gp.py",
}


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
        "aids": _prefixed_constants(parsed["etsi_fs"], ""),
        "gp_lifecycle": _prefixed_constants(parsed["gp"], "GP_LCS_"),
    }
    return collected


def _source_digest(tables: dict[str, Any]) -> str:
    """Digest the collected tables so drift is attributable."""
    canonical = repr(sorted((key, repr(value)) for key, value in tables.items()))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# -------------------------------------------------------------------- render
def render_tables_lua(repo_root: Path = REPO_ROOT) -> str:
    """Return the complete generated Lua module as text."""
    tables = collect_tables(repo_root)

    # Merge the two BER-TLV tag tables. The MCP copy carries spec clause
    # citations, so it wins where both name the same tag.
    ber_tags: dict[str, str] = {}
    for tag_hex, (tag_name, tag_source) in sorted(tables["fallback_tags"].items()):
        ber_tags[str(tag_hex).upper()] = f"{tag_name} ({tag_source})"
    for tag_value, tag_name in sorted(tables["ber_tags"].items()):
        width = 2 if tag_value <= 0xFF else 4
        ber_tags[f"{tag_value:0{width}X}"] = tag_name

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
        _render_paths("FILE_PATHS", tables["file_paths"]),
        _render_paths("AID_PATHS", tables["aid_paths"]),
        _render_aids(tables["aids"]),
        _render_gp_lifecycle(tables["gp_lifecycle"]),
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
        return 0

    if args.write:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        print(f"wrote {target}")
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
