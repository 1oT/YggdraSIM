# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP profile template engine: placeholder resolution and batch application.

Supports two placeholder styles — brace (``{NAME}``) and bracket
(``[NAME]``) — with typed encoders for ICCID (header + EF wire form)
and IMSI (3GPP TS 31.102 §4.2.2).  Batch records can be loaded from
CSV, JSON, JSONL, or YAML sources.
"""
from __future__ import annotations

import copy
import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import yaml

from .saip_json_codec import (
    _META_PLACEHOLDER_STYLE,
    _META_TOKEN_DEFS,
    _TAG_BYTES,
    _TAG_TUPLE,
    jsonify_document,
)

_ASSIGNMENT_RE = re.compile(
    r"^(?P<name>\{[A-Za-z][A-Za-z0-9_]*\}|\[[A-Za-z][A-Za-z0-9_]*\]|[A-Za-z][A-Za-z0-9_]*)=(?P<value>.+)$"
)
_PLACEHOLDER_ANY_RE = re.compile(
    r"\{#?([A-Za-z][A-Za-z0-9_]*)\}|\[#?([A-Za-z][A-Za-z0-9_]*)\]"
)


@dataclass(frozen=True)
class BatchPlaceholderRecord:
    label: str
    values: dict[str, str]


def normalize_placeholder_style(style: str) -> str:
    """Normalise a placeholder style name to ``"brace"`` or ``"bracket"``.

    Accepts ``"brace"``, ``"curly"`` (alias), or ``"bracket"``.  Raises
    ``ValueError`` for any other input.
    """
    normalized = str(style or "brace").strip().lower()
    if normalized == "curly":
        normalized = "brace"
    if normalized not in ("brace", "bracket"):
        raise ValueError(
            f'Placeholder style must be "brace" or "bracket" (got {style!r}).'
        )
    return normalized


def render_placeholder(name: str, style: str = "brace") -> str:
    """Return the canonical placeholder token string for ``name``.

    ``style="brace"`` → ``{NAME}``, ``style="bracket"`` → ``[NAME]``.
    """
    normalized_style = normalize_placeholder_style(style)
    normalized_name = normalize_placeholder_name(name)
    if normalized_style == "bracket":
        return f"[{normalized_name}]"
    return f"{{{normalized_name}}}"


def normalize_placeholder_name(raw_name: str) -> str:
    """Strip surrounding braces / brackets and validate the identifier.

    Accepts bare names (``ICCID``), brace-wrapped (``{ICCID}``), or
    bracket-wrapped (``[ICCID]``).  The name must match
    ``[A-Za-z][A-Za-z0-9_]*``; raises ``ValueError`` otherwise.
    """
    cleaned = str(raw_name or "").strip()
    if len(cleaned) >= 2:
        if cleaned.startswith("{") and cleaned.endswith("}"):
            cleaned = cleaned[1:-1].strip()
        elif cleaned.startswith("[") and cleaned.endswith("]"):
            cleaned = cleaned[1:-1].strip()
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", cleaned) is None:
        raise ValueError(
            f"Invalid placeholder name {raw_name!r}; use letters, digits, and underscore."
        )
    return cleaned


def parse_placeholder_assignment_tokens(tokens: Sequence[str]) -> dict[str, str]:
    """Parse a sequence of ``NAME=value`` CLI tokens into a name→value dict.

    Names may be bare, brace-wrapped, or bracket-wrapped.  Raises
    ``ValueError`` on malformed tokens or empty values.
    """
    assignments: dict[str, str] = {}
    for token in tokens:
        raw_token = str(token or "").strip()
        match = _ASSIGNMENT_RE.match(raw_token)
        if match is None:
            raise ValueError(
                "Placeholder assignments must use NAME=value, for example "
                "ICCID=89461111111111111112 or {IMSI}=123456781234567."
            )
        name = normalize_placeholder_name(match.group("name"))
        value = str(match.group("value") or "").strip()
        if len(value) == 0:
            raise ValueError(f"Placeholder {name} requires a value.")
        assignments[name] = value
    return assignments


def _compact_user_value(text: str) -> str:
    return (
        str(text or "")
        .strip()
        .replace(" ", "")
        .replace("\t", "")
        .replace("\n", "")
        .replace("-", "")
        .replace(":", "")
        .upper()
    )


def _swap_bcd_nibbles(hex_text: str) -> str:
    cleaned = str(hex_text or "").strip().upper()
    if len(cleaned) % 2 != 0:
        raise ValueError("BCD input must contain an even number of nibbles.")
    swapped_parts: list[str] = []
    offset = 0
    while offset < len(cleaned):
        pair = cleaned[offset : offset + 2]
        swapped_parts.append(pair[1] + pair[0])
        offset += 2
    return "".join(swapped_parts)


def encode_iccid_header_hex(value: str) -> str:
    """Encode a decimal ICCID string to the 20-nibble header form.

    Accepts 19 or 20 decimal digit strings.  A 19-digit input has an
    ``F`` filler appended; a 19-digit input that already ends in ``F``
    is accepted verbatim.  Returns a 20-nibble uppercase hex string in
    natural digit order (not BCD-swapped) — suitable for the ``header``
    section.  Use ``encode_iccid_ef_hex`` for the EF.ICCID wire form.
    """
    cleaned = _compact_user_value(value)
    padded = cleaned
    if cleaned.endswith("F"):
        digits = cleaned[:-1]
        if digits.isdigit() is False or len(digits) != 19:
            raise ValueError(
                "ICCID with trailing F must contain exactly 19 decimal digits before the filler nibble."
            )
        padded = digits + "F"
        return padded
    if cleaned.isdigit() is False:
        raise ValueError("ICCID must contain decimal digits, with optional trailing F filler.")
    if len(cleaned) == 19:
        return cleaned + "F"
    if len(cleaned) == 20:
        return cleaned
    raise ValueError("ICCID must contain 19 or 20 digits.")


def encode_iccid_ef_hex(value: str) -> str:
    """BCD-swap the ICCID header form to produce the EF.ICCID wire bytes.

    ITU-T E.118 §3.3 stores each digit pair nibble-swapped on the wire.
    """
    return _swap_bcd_nibbles(encode_iccid_header_hex(value))


def encode_imsi_ef_hex(value: str) -> str:
    """Encode a decimal IMSI string to the EF.IMSI wire bytes (hex string).

    3GPP TS 31.102 §4.2.2 layout: length byte (0x08) + parity nibble
    (0x9 for odd digit count, 0x1 for even) + BCD digits nibble-swapped
    + optional trailing 0xF filler.  Returns a 18-nibble hex string.
    """
    digits = _compact_user_value(value)
    if digits.isdigit() is False:
        raise ValueError("IMSI must contain decimal digits only.")
    if len(digits) == 0:
        raise ValueError("IMSI must not be empty.")
    if len(digits) > 16:
        raise ValueError("IMSI longer than 16 digits is not supported by template generation.")
    odd_digit_count = len(digits) % 2 == 1
    leading_nibble = "9"
    if odd_digit_count is False:
        leading_nibble = "1"
    swapped_digits = leading_nibble + digits
    if len(swapped_digits) % 2 != 0:
        swapped_digits += "F"
    byte_length = len(swapped_digits) // 2
    return f"{byte_length:02X}" + _swap_bcd_nibbles(swapped_digits)


def normalize_raw_hex_token_value(value: str, *, token_name: str) -> str:
    """Strip whitespace/separators and validate a raw hex token value.

    Used for placeholder tokens that have no typed encoder (i.e. not
    ICCID or IMSI).  Raises ``ValueError`` if the input is empty,
    contains non-hex characters, or has an odd nibble count.
    """
    cleaned = _compact_user_value(value)
    if len(cleaned) == 0:
        raise ValueError(f"Placeholder {token_name} requires a non-empty hex value.")
    if re.fullmatch(r"[0-9A-F]+", cleaned) is None:
        raise ValueError(
            f"Placeholder {token_name} must be raw hex when no typed encoder is known."
        )
    if len(cleaned) % 2 != 0:
        raise ValueError(
            f"Placeholder {token_name} raw hex must contain an even number of nibbles."
        )
    return cleaned


def build_override_token_definitions(assignments: dict[str, str]) -> dict[str, dict[str, str]]:
    """Convert a name→raw-value assignment map to a token-definition dict.

    ICCID and IMSI assignments are encoded via their typed encoders;
    all other tokens are validated as raw hex and stored verbatim.
    The returned dict maps token names to ``{"hex": "<uppercase hex>"}``
    dicts compatible with the profile JSON schema.
    """
    token_defs: dict[str, dict[str, str]] = {}
    for raw_name, raw_value in assignments.items():
        name = normalize_placeholder_name(raw_name)
        upper_name = name.upper()
        if upper_name == "ICCID":
            token_defs["ICCID"] = {"hex": encode_iccid_header_hex(raw_value)}
            token_defs["ICCID_EF"] = {"hex": encode_iccid_ef_hex(raw_value)}
            continue
        if upper_name == "IMSI":
            token_defs["IMSI"] = {"hex": encode_imsi_ef_hex(raw_value)}
            continue
        token_defs[name] = {
            "hex": normalize_raw_hex_token_value(raw_value, token_name=name)
        }
    return token_defs


def _replace_tagged_bytes_value(node: Any, replacement_hex: str) -> bool:
    if isinstance(node, dict) is False:
        return False
    current_hex = node.get(_TAG_BYTES)
    if isinstance(current_hex, str) is False:
        return False
    node[_TAG_BYTES] = replacement_hex
    return True


def _replace_fill_file_content_entries(entries: Any, replacement_hex: str) -> int:
    if isinstance(entries, list) is False:
        return 0
    replaced = 0
    for entry in entries:
        if isinstance(entry, dict) is False:
            continue
        tuple_value = entry.get(_TAG_TUPLE)
        if isinstance(tuple_value, list) is False:
            continue
        if len(tuple_value) != 2:
            continue
        if str(tuple_value[0]) != "fillFileContent":
            continue
        if _replace_tagged_bytes_value(tuple_value[1], replacement_hex):
            replaced += 1
    return replaced


def _replace_section_fill_file_content(
    sections: dict[str, Any],
    section_name: str,
    file_key: str,
    replacement_hex: str,
) -> int:
    section = sections.get(section_name)
    if isinstance(section, dict) is False:
        return 0
    return _replace_fill_file_content_entries(section.get(file_key), replacement_hex)


def build_placeholder_template_document(
    document: dict[str, Any],
    assignments: dict[str, str],
    *,
    placeholder_style: str = "brace",
) -> tuple[dict[str, Any], list[str]]:
    """Replace ICCID / IMSI values in ``document`` with placeholder tokens.

    ``assignments`` maps placeholder names (currently ``ICCID`` and
    ``IMSI``) to example values used only to locate the injection sites.
    Returns ``(tagged_document, summary_lines)`` where ``tagged_document``
    carries placeholder strings in place of the real values.
    """
    tagged = jsonify_document(document)
    normalized_style = normalize_placeholder_style(placeholder_style)
    summaries: list[str] = []
    if len(assignments) == 0:
        return tagged, summaries

    sections = tagged.get("sections")
    if isinstance(sections, dict) is False:
        raise ValueError("Tagged profile document does not contain a sections object.")

    for raw_name in assignments:
        name = normalize_placeholder_name(raw_name)
        upper_name = name.upper()
        if upper_name not in ("ICCID", "IMSI"):
            raise ValueError(
                f"Automatic template injection is currently supported for ICCID and IMSI only (got {name})."
            )

    token_defs = build_override_token_definitions(assignments)
    for raw_name in assignments:
        name = normalize_placeholder_name(raw_name)
        upper_name = name.upper()
        if upper_name == "ICCID":
            header_placeholder = render_placeholder("ICCID", normalized_style)
            ef_placeholder = render_placeholder("ICCID_EF", normalized_style)
            header_count = 0
            header = sections.get("header")
            if isinstance(header, dict):
                if _replace_tagged_bytes_value(header.get("iccid"), header_placeholder):
                    header_count = 1
            ef_count = _replace_section_fill_file_content(
                sections,
                "mf",
                "ef-iccid",
                ef_placeholder,
            )
            if header_count == 0 and ef_count == 0:
                raise ValueError(
                    "Could not inject ICCID placeholder: header.iccid and mf.ef-iccid were not found."
                )
            summaries.append(
                f"ICCID -> header:{header_count} ef-iccid:{ef_count} "
                f"(defs: ICCID, ICCID_EF)"
            )
            continue
        if upper_name == "IMSI":
            imsi_placeholder = render_placeholder("IMSI", normalized_style)
            imsi_count = 0
            for section_name in ("usim", "opt-usim", "isim", "opt-isim"):
                imsi_count += _replace_section_fill_file_content(
                    sections,
                    section_name,
                    "ef-imsi",
                    imsi_placeholder,
                )
            if imsi_count == 0:
                raise ValueError(
                    "Could not inject IMSI placeholder: no EF.IMSI fillFileContent entries were found."
                )
            summaries.append(f"IMSI -> ef-imsi:{imsi_count} (def: IMSI)")
            continue

    existing_defs = tagged.get(_META_TOKEN_DEFS)
    merged_defs: dict[str, Any] = {}
    if isinstance(existing_defs, dict):
        merged_defs = copy.deepcopy(existing_defs)
    for key, value in token_defs.items():
        merged_defs[key] = value
    tagged[_META_TOKEN_DEFS] = merged_defs
    tagged[_META_PLACEHOLDER_STYLE] = normalized_style
    return tagged, summaries


def apply_placeholder_overrides_to_loaded_document(
    loaded: dict[str, Any],
    assignments: dict[str, str],
) -> list[str]:
    """Merge ``assignments`` into an already-loaded template document's token-def table.

    Mutates ``loaded`` in place by updating its ``_META_TOKEN_DEFS`` dict.
    Returns a list of one-line summary strings describing what was overridden.
    """
    if isinstance(loaded, dict) is False:
        raise ValueError("Template root JSON value must be an object.")
    if len(assignments) == 0:
        return []

    existing_defs = loaded.get(_META_TOKEN_DEFS)
    merged_defs: dict[str, Any] = {}
    if isinstance(existing_defs, dict):
        merged_defs = copy.deepcopy(existing_defs)
    override_defs = build_override_token_definitions(assignments)
    for key, value in override_defs.items():
        merged_defs[key] = value
    loaded[_META_TOKEN_DEFS] = merged_defs
    if _META_PLACEHOLDER_STYLE not in loaded:
        loaded[_META_PLACEHOLDER_STYLE] = "brace"

    summaries: list[str] = []
    for raw_name in assignments:
        name = normalize_placeholder_name(raw_name)
        upper_name = name.upper()
        if upper_name == "ICCID":
            summaries.append("ICCID override -> ICCID + ICCID_EF")
            continue
        if upper_name == "IMSI":
            summaries.append("IMSI override -> IMSI")
            continue
        summaries.append(f"{name} override -> {name}")
    return summaries


def extract_template_placeholder_names(node: Any) -> set[str]:
    """Walk ``node`` recursively and collect all placeholder token names.

    Finds both brace-style ``{NAME}`` and bracket-style ``[NAME]`` tokens
    embedded in string values anywhere in the document tree.  Returns a
    set of bare names (without surrounding delimiters).
    """
    names: set[str] = set()

    def visit(value: Any) -> None:
        """Visit a template AST node and apply token substitutions recursively."""
        if isinstance(value, dict):
            for nested_value in value.values():
                visit(nested_value)
            return
        if isinstance(value, list):
            for nested_value in value:
                visit(nested_value)
            return
        if isinstance(value, str) is False:
            return
        for match in _PLACEHOLDER_ANY_RE.finditer(value):
            brace_name = match.group(1)
            bracket_name = match.group(2)
            if brace_name is not None:
                names.add(brace_name)
                continue
            if bracket_name is not None:
                names.add(bracket_name)

    visit(node)
    return names


def load_batch_placeholder_records(data_path: Path) -> list[BatchPlaceholderRecord]:
    """Load a batch personalisation file and return a list of records.

    Supported formats: ``.csv``, ``.json``, ``.jsonl``, ``.ndjson``,
    ``.yaml``, ``.yml``.  Each record exposes a ``label`` (row identifier)
    and a ``values`` dict mapping placeholder names to raw string values.
    Raises ``ValueError`` for unsupported extensions.
    """
    suffix = str(data_path.suffix or "").strip().lower()
    if suffix == ".csv":
        return _load_batch_placeholder_records_csv(data_path)
    if suffix in (".json",):
        return _load_batch_placeholder_records_json(data_path)
    if suffix in (".yaml", ".yml"):
        return _load_batch_placeholder_records_yaml(data_path)
    if suffix in (".jsonl", ".ndjson"):
        return _load_batch_placeholder_records_jsonl(data_path)
    raise ValueError(
        "Unsupported batch data format. Use .csv, .json, .jsonl, .ndjson, .yaml, or .yml."
    )


def _normalize_record_mapping(raw_mapping: Any, *, label: str) -> dict[str, str]:
    if isinstance(raw_mapping, dict) is False:
        raise ValueError(f"{label} must be an object mapping placeholder names to values.")
    normalized: dict[str, str] = {}
    for raw_key, raw_value in raw_mapping.items():
        key = normalize_placeholder_name(str(raw_key))
        if raw_value is None:
            continue
        value = str(raw_value).strip()
        if len(value) == 0:
            continue
        normalized[key] = value
    return normalized


def _load_batch_placeholder_records_csv(data_path: Path) -> list[BatchPlaceholderRecord]:
    records: list[BatchPlaceholderRecord] = []
    with data_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or len(reader.fieldnames) == 0:
            raise ValueError("CSV batch data requires a header row with placeholder names.")
        for index, row in enumerate(reader, start=2):
            label = f"csv row {index}"
            values = _normalize_record_mapping(row, label=label)
            records.append(BatchPlaceholderRecord(label=label, values=values))
    return records


def _load_batch_placeholder_records_json(data_path: Path) -> list[BatchPlaceholderRecord]:
    loaded = json.loads(data_path.read_text(encoding="utf-8"))
    return _normalize_batch_sequence(loaded, source_label="json records")


def _load_batch_placeholder_records_yaml(data_path: Path) -> list[BatchPlaceholderRecord]:
    loaded = yaml.safe_load(data_path.read_text(encoding="utf-8"))
    return _normalize_batch_sequence(loaded, source_label="yaml records")


def _load_batch_placeholder_records_jsonl(data_path: Path) -> list[BatchPlaceholderRecord]:
    records: list[BatchPlaceholderRecord] = []
    for index, raw_line in enumerate(data_path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = str(raw_line or "").strip()
        if len(stripped) == 0:
            continue
        loaded = json.loads(stripped)
        label = f"jsonl row {index}"
        values = _normalize_record_mapping(loaded, label=label)
        records.append(BatchPlaceholderRecord(label=label, values=values))
    return records


def _normalize_batch_sequence(loaded: Any, *, source_label: str) -> list[BatchPlaceholderRecord]:
    if isinstance(loaded, list) is False:
        raise ValueError(f"{source_label} must be a list of placeholder objects.")
    records: list[BatchPlaceholderRecord] = []
    for index, item in enumerate(loaded, start=1):
        label = f"{source_label} [{index}]"
        values = _normalize_record_mapping(item, label=label)
        records.append(BatchPlaceholderRecord(label=label, values=values))
    return records


def validate_batch_record_assignments(
    assignments: dict[str, str],
    *,
    template_placeholders: set[str],
    template_token_defs: dict[str, Any],
) -> dict[str, str]:
    """Validate a single batch record's assignments against the template.

    ``template_placeholders`` is the set of token names found in the
    template document; ``template_token_defs`` are the pre-defined
    fall-back values.  Raises ``ValueError`` when the record contains
    unknown names or leaves required placeholders unresolved.  Returns
    the normalised name→value dict for the record.
    """
    normalized: dict[str, str] = {}
    for raw_name, raw_value in assignments.items():
        name = normalize_placeholder_name(raw_name)
        value = str(raw_value or "").strip()
        if len(value) == 0:
            continue
        normalized[name] = value

    accepted = set(template_placeholders)
    if "ICCID" in template_placeholders or "ICCID_EF" in template_placeholders:
        accepted.add("ICCID")
        accepted.add("ICCID_EF")
    if "IMSI" in template_placeholders:
        accepted.add("IMSI")

    unknown = sorted(name for name in normalized if name not in accepted)
    if len(unknown) > 0:
        raise ValueError(
            "Unknown placeholder names in batch record: " + ", ".join(unknown)
        )

    available = set(template_token_defs)
    available.update(normalized)
    if "ICCID" in normalized:
        available.add("ICCID_EF")

    missing = sorted(name for name in template_placeholders if name not in available)
    if len(missing) > 0:
        raise ValueError(
            "Missing placeholder values for: " + ", ".join(missing)
        )
    return normalized


def batch_output_stem(assignments: dict[str, str], *, index: int) -> str:
    """Derive a filesystem-safe output filename stem for a batch record.

    Prefers ``profile_iccid_<value>`` or ``profile_imsi_<value>`` when the
    ICCID or IMSI assignment is present; falls back to ``profile_<NNN>``.
    """
    for preferred_name in ("ICCID", "IMSI"):
        raw_value = assignments.get(preferred_name)
        if raw_value is None:
            continue
        compact = re.sub(r"[^A-Za-z0-9]+", "", str(raw_value))
        if len(compact) == 0:
            continue
        return f"profile_{preferred_name.lower()}_{compact}"
    return f"profile_{index:03d}"
