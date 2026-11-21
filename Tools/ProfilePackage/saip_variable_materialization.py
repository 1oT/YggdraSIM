# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Typed SAIP variable catalog and inline-template materialization.

The workbench accepts two variable surfaces:

* generated tagged JSON carries a semantic ``__ygg_variable_catalog__``;
* compact ``.varder`` hex carries fixed-width inline placeholder records.

Both are fail-closed here.  Inputs are encoded according to their declared
type, every semantic locator must resolve exactly once, and no secret value is
returned by the helpers.  Production-completion/export policy remains owned by
the workbench and is deliberately not changed by materialization.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yggdrasim_common.secure_files import (
    atomic_write_bytes,
    read_bounded_regular_file,
)

from .saip_hex_template import (
    InlinePlaceholderRecord,
    normalise_placeholder_modifier,
    placeholder_key_fold,
    placeholder_key_fold_relaxed,
)
from .saip_profile_template import (
    encode_iccid_ef_hex,
    encode_iccid_header_hex,
    normalize_placeholder_name,
)

VARIABLE_CATALOG_SCHEMA = "yggdrasim.saip-variable-catalog/v1"
LEGACY_VARIABLE_CATALOG_SCHEMAS = frozenset(
    {"oneot.saip-variable-catalog/v1"}
)

_HEX_RE = re.compile(r"^[0-9A-F]+$")

# Stored inline-variable values travel beside a varder / ASN.1 template in
# a ``<stem>.variables.json`` sidecar (tagged JSON embeds the same map in
# its ``__ygg_inline_placeholders__`` block). The value is the operator's
# typed input, encoded per occurrence at export time.
INLINE_VARIABLE_SIDECAR_SCHEMA = "yggdrasim.saip-inline-variables/v1"
_INLINE_VARIABLE_SIDECAR_SUFFIX = ".variables.json"
_MAX_INLINE_VARIABLE_SIDECAR_BYTES = 4 * 1024 * 1024
_SECRET_NAME_RE = re.compile(
    r"(?:^|_)(?:K|KI|OPC|PIN\d*|PUK\d*|ADM\d*|KIC|KIK|KID|DEK|KEK|PSK)(?:$|_)",
    re.IGNORECASE,
)
_SECRET_CLASSIFICATION_TERMS = ("SECRET", "CREDENTIAL", "PRIVATE_KEY")
_FILE_DATA_CHOICES = frozenset({"fillFileContent", "fillFileOffset", "doNotCreate"})


class SaipVariableMaterializationError(ValueError):
    """Raised when a variable cannot be encoded or located unambiguously."""


@dataclass(frozen=True)
class VariableMaterializationResult:
    """Non-secret evidence for one successfully materialized variable."""

    variable_name: str
    binding_count: int
    secret: bool
    source: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "name": self.variable_name,
            "binding_count": self.binding_count,
            "secret": self.secret,
            "source": self.source,
        }


def variable_is_secret(variable_name: str, classification: str = "") -> bool:
    """Return whether a variable value must be redacted from UI/log payloads."""

    normalized_classification = str(classification or "").strip().upper()
    if any(term in normalized_classification for term in _SECRET_CLASSIFICATION_TERMS):
        return True
    return _SECRET_NAME_RE.search(str(variable_name or "").strip().upper()) is not None


def _catalog_symbol_key(symbol: Any, *, require_variable_id: bool = False) -> str:
    """Return a case-insensitive key for a catalog ID or source alias.

    Catalog IDs are placeholder names and therefore use the strict identifier
    grammar.  Aliases may intentionally preserve source notation such as
    ``FILESYSTEM_MARKER::<name>``; those still need collision-safe lookup but
    must not make an otherwise valid generated catalog unusable.
    """

    raw_symbol = str(symbol or "").strip()
    if len(raw_symbol) == 0:
        raise SaipVariableMaterializationError("SAIP variable catalog symbols cannot be empty.")
    try:
        return normalize_placeholder_name(raw_symbol).casefold()
    except ValueError as error:
        if require_variable_id:
            raise SaipVariableMaterializationError(str(error)) from error
        return raw_symbol.casefold()


def catalog_variables(document: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Return validated catalog variable rows, or an empty tuple when absent."""

    raw_catalog = document.get("__ygg_variable_catalog__")
    if raw_catalog is None:
        return ()
    if not isinstance(raw_catalog, dict):
        raise SaipVariableMaterializationError("SAIP variable catalog must be an object.")
    schema = str(raw_catalog.get("schema_version") or "")
    if schema not in {VARIABLE_CATALOG_SCHEMA, *LEGACY_VARIABLE_CATALOG_SCHEMAS}:
        raise SaipVariableMaterializationError(
            f"Unsupported SAIP variable catalog schema {schema!r}."
        )
    raw_variables = raw_catalog.get("variables")
    if not isinstance(raw_variables, list):
        raise SaipVariableMaterializationError("SAIP variable catalog has no variables list.")
    rows: list[dict[str, Any]] = []
    symbols: dict[str, str] = {}
    for raw_variable in raw_variables:
        if not isinstance(raw_variable, dict):
            raise SaipVariableMaterializationError(
                "Every SAIP variable catalog entry must be an object."
            )
        row = dict(raw_variable)
        variable_id = str(row.get("id") or "").strip()
        normalized = _catalog_symbol_key(variable_id, require_variable_id=True)
        owner = symbols.get(normalized)
        if owner is not None:
            raise SaipVariableMaterializationError(
                f"SAIP variable catalog symbol {variable_id!r} collides with {owner!r}."
            )
        symbols[normalized] = variable_id
        rows.append(row)
    for row in rows:
        variable_id = str(row["id"])
        aliases = row.get("aliases") or []
        if not isinstance(aliases, list):
            raise SaipVariableMaterializationError(
                f"Catalog variable {variable_id!r} has invalid aliases."
            )
        for raw_alias in aliases:
            normalized = _catalog_symbol_key(raw_alias)
            owner = symbols.get(normalized)
            if owner is not None and owner != variable_id:
                raise SaipVariableMaterializationError(
                    f"SAIP variable alias {raw_alias!r} collides with {owner!r}."
                )
            symbols[normalized] = variable_id
    return tuple(rows)


def find_catalog_variable(
    document: Mapping[str, Any],
    variable_name: str,
) -> dict[str, Any] | None:
    """Resolve a catalog ID or alias case-insensitively."""

    wanted = _catalog_symbol_key(variable_name)
    matches: list[dict[str, Any]] = []
    for row in catalog_variables(document):
        symbols = [str(row.get("id") or ""), *(str(item) for item in row.get("aliases") or [])]
        if any(_catalog_symbol_key(symbol) == wanted for symbol in symbols):
            matches.append(row)
    if len(matches) > 1:
        raise SaipVariableMaterializationError(
            f"Variable name {variable_name!r} resolves to multiple catalog entries."
        )
    return matches[0] if matches else None


def materialize_inline_variable(
    document: dict[str, Any],
    records: Iterable[InlinePlaceholderRecord],
    variable_name: str,
    value: str,
) -> tuple[dict[str, Any], list[InlinePlaceholderRecord], VariableMaterializationResult]:
    """Replace every unresolved inline occurrence for one variable atomically."""

    try:
        wanted = normalize_placeholder_name(variable_name).casefold()
    except ValueError as error:
        raise SaipVariableMaterializationError(str(error)) from error
    all_records = list(records)
    matching = [record for record in all_records if record.variable_name.casefold() == wanted]
    if not matching:
        raise SaipVariableMaterializationError(
            f"Inline variable {variable_name!r} has no unresolved occurrences."
        )
    encoded = [(record, encode_inline_placeholder_value(record, value)) for record in matching]
    candidate = copy.deepcopy(document)
    for record, replacement in encoded:
        sentinel = _hex_bytes(record.sentinel_hex, label=f"{record.variable_name} sentinel")
        candidate, count = _replace_byte_run(candidate, sentinel, replacement)
        if count != 1:
            raise SaipVariableMaterializationError(
                f"Inline variable {record.variable_name!r} occurrence #{record.index} "
                f"resolved to {count} byte regions instead of one."
            )
    remaining = [record for record in all_records if record.variable_name.casefold() != wanted]
    canonical_name = matching[0].variable_name
    return (
        candidate,
        remaining,
        VariableMaterializationResult(
            variable_name=canonical_name,
            binding_count=len(matching),
            secret=variable_is_secret(canonical_name),
            source="inline_varder",
        ),
    )


def encode_inline_placeholder_value(record: InlinePlaceholderRecord, value: str) -> bytes:
    """Encode a compact typed placeholder value to its exact declared width."""

    type_name = str(record.type_name or "").strip().upper()
    # ``NibbleSwap``, ``nibble_swap`` and ``SwapNibbles`` are one modifier and
    # ``utf8`` on TEXT folds away (saip_hex_template.normalise_placeholder_modifier).
    modifier = normalise_placeholder_modifier(record.modifier, type_name)
    if type_name in {"BINARY", "RI", "OPLMN"}:
        payload = _hex_bytes(value, label=record.variable_name)
    elif type_name == "TEXT":
        if modifier:
            raise SaipVariableMaterializationError(
                f"Inline TEXT variable {record.variable_name!r} has unsupported modifier "
                f"{record.modifier!r}."
            )
        payload = str(value).encode("utf-8")
    elif type_name == "ICCID":
        try:
            encoded_hex = (
                encode_iccid_ef_hex(value)
                if modifier == "nibbleswap"
                else encode_iccid_header_hex(value)
            )
        except ValueError as error:
            raise SaipVariableMaterializationError(str(error)) from error
        payload = bytes.fromhex(encoded_hex)
    elif type_name == "IMSI":
        payload = _encode_imsi_ef(value)[1:]
    elif type_name == "MSISDN":
        payload = _encode_msisdn_bcd(value, record.byte_length)
    else:
        raise SaipVariableMaterializationError(
            f"Inline variable {record.variable_name!r} uses unsupported type {type_name!r}."
        )
    if len(payload) != record.byte_length:
        raise SaipVariableMaterializationError(
            f"Inline variable {record.variable_name!r} requires exactly "
            f"{record.byte_length} bytes, got {len(payload)}."
        )
    return payload


def decode_inline_placeholder_value(record: Any, payload: bytes) -> str | None:
    """The typed value that encodes to ``payload`` for ``record``, or ``None``.

    The inverse of :func:`encode_inline_placeholder_value`: BINARY, RI and
    OPLMN read back as hex, TEXT as UTF-8, ICCID (header or EF form by the
    modifier), IMSI (TS 24.008 section 10.5.1.4 digit coding, without the
    length byte) and MSISDN (nibble-swapped BCD, F filler) as digits. The
    answer is proven by re-encoding; bytes that no value of the type
    produces give ``None``, so a caller stores them per occurrence instead.
    """

    data = bytes(payload or b"")
    type_name = str(getattr(record, "type_name", "") or "").strip().upper()
    modifier = normalise_placeholder_modifier(getattr(record, "modifier", None), type_name)
    width = int(getattr(record, "byte_length", 0) or 0)
    if not data or (width and len(data) != width):
        return None
    if type_name in {"BINARY", "RI", "OPLMN"}:
        return data.hex().upper()
    if type_name == "TEXT":
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return text if text.encode("utf-8") == data else None
    hex_text = data.hex().upper()
    if type_name == "ICCID":
        natural = (
            "".join(hex_text[index + 1] + hex_text[index] for index in range(0, len(hex_text), 2))
            if modifier == "nibbleswap"
            else hex_text
        )
        for digits in (natural, natural.rstrip("F")):
            if not digits or digits.isdigit() is False:
                continue
            try:
                encoded = (
                    encode_iccid_ef_hex(digits)
                    if modifier == "nibbleswap"
                    else encode_iccid_header_hex(digits)
                )
            except ValueError:
                continue
            if encoded.upper() == hex_text:
                return digits
        return None
    if type_name == "IMSI":
        digits = hex_text[0]
        for index in range(2, len(hex_text), 2):
            digits += hex_text[index + 1] + hex_text[index]
        digits = digits.rstrip("F")
        if digits.isdigit() is False:
            return None
        try:
            encoded = _encode_imsi_ef(digits)[1:]
        except SaipVariableMaterializationError:
            return None
        return digits if encoded == data else None
    if type_name == "MSISDN":
        digits = "".join(
            hex_text[index + 1] + hex_text[index] for index in range(0, len(hex_text), 2)
        ).rstrip("F")
        if not digits or digits.isdigit() is False:
            return None
        try:
            encoded = _encode_msisdn_bcd(digits, len(data))
        except SaipVariableMaterializationError:
            return None
        return digits if encoded == data else None
    return None


def placeholder_value_to_wire_hex(record: Any, value_text: str) -> str:
    """The bytes a list entry stores for ``value_text``, as upper-case hex.

    BINARY, RI and OPLMN take the exact bytes as hex. The other types take
    their typed input (digits, text) through :func:`encode_inline_placeholder_value`
    and fall back to exact-width hex, so ``0100000000F1`` answers an MSISDN
    placeholder as readily as the digits do. Raises
    :class:`SaipVariableMaterializationError` naming the literal otherwise.
    """

    type_name = str(getattr(record, "type_name", "") or "").strip().upper()
    literal = str(getattr(record, "literal", "") or "placeholder")
    if type_name in {"BINARY", "RI", "OPLMN"}:
        try:
            return validate_inline_raw_value(record, value_text).hex().upper()
        except SaipVariableMaterializationError as error:
            raise SaipVariableMaterializationError(f"{literal}: {error}") from error
    try:
        return encode_inline_placeholder_value(record, value_text).hex().upper()
    except SaipVariableMaterializationError as typed_error:
        try:
            return validate_inline_raw_value(record, value_text).hex().upper()
        except SaipVariableMaterializationError:
            raise SaipVariableMaterializationError(f"{literal}: {typed_error}") from typed_error


def materialize_catalog_variable(
    sequence: Any,
    document: Mapping[str, Any],
    variable_name: str,
    value: str,
) -> VariableMaterializationResult:
    """Apply one typed semantic catalog variable to a live PE sequence."""

    variable = find_catalog_variable(document, variable_name)
    if variable is None:
        raise SaipVariableMaterializationError(
            f"Variable {variable_name!r} is not present in the semantic catalog."
        )
    canonical_name = str(variable.get("id") or "")
    _enforce_catalog_exact_digits(variable, value)
    bindings = variable.get("bindings")
    if not isinstance(bindings, list) or not bindings:
        status = str(variable.get("status") or "UNBOUND")
        raise SaipVariableMaterializationError(
            f"Catalog variable {canonical_name!r} has no materializable binding "
            f"(status={status})."
        )
    rfm_contexts = _rfm_context_map(document, sequence)
    pending: list[tuple[Callable[[Any], None], Any]] = []
    for raw_binding in bindings:
        if not isinstance(raw_binding, dict):
            raise SaipVariableMaterializationError(
                f"Catalog variable {canonical_name!r} has a malformed binding."
            )
        locator = raw_binding.get("locator")
        if not isinstance(locator, dict):
            raise SaipVariableMaterializationError(
                f"Catalog variable {canonical_name!r} binding has no semantic locator."
            )
        encoded_value = _encode_catalog_binding(variable, raw_binding, value)
        setter = _resolve_catalog_setter(
            sequence,
            locator,
            rfm_contexts=rfm_contexts,
            materialization_value=value,
            catalog_encoder=str(raw_binding.get("encoder") or ""),
        )
        pending.append((setter, encoded_value))
    for setter, encoded_value in pending:
        setter(encoded_value)
    return VariableMaterializationResult(
        variable_name=canonical_name,
        binding_count=len(pending),
        secret=variable_is_secret(canonical_name, str(variable.get("classification") or "")),
        source="semantic_catalog",
    )


def _encode_catalog_binding(
    variable: Mapping[str, Any],
    binding: Mapping[str, Any],
    value: str,
) -> Any:
    variable_id = str(variable.get("id") or "")
    encoder = str(binding.get("encoder") or "").strip().upper()
    expected_length = binding.get("output_length_bytes")
    constraints = _variable_constraints(variable)
    if encoder == "RAW_HEX_V1":
        encoded: Any = _hex_bytes(value, label=variable_id)
    elif encoder == "ICCID_HEADER_BCD_V1":
        try:
            encoded = bytes.fromhex(encode_iccid_header_hex(value))
        except ValueError as error:
            raise SaipVariableMaterializationError(str(error)) from error
    elif encoder == "ICCID_EF_BCD_SWAP_V1":
        try:
            encoded = bytes.fromhex(encode_iccid_ef_hex(value))
        except ValueError as error:
            raise SaipVariableMaterializationError(str(error)) from error
    elif encoder == "EF_IMSI_V1":
        encoded = _encode_imsi_ef(value)
    elif encoder == "EF_MSISDN_RECORD_V1":
        output_length = _required_positive_int(expected_length, "MSISDN output length")
        encoded = _encode_msisdn_bcd(value, output_length)
    elif encoder in {"PIN_ASCII_FF_PAD_V1", "PUK_ASCII_V1"}:
        output_length = _required_positive_int(expected_length, "credential output length")
        encoded = _encode_ascii_credential(value, constraints, output_length, variable_id)
    elif encoder == "TAR_LIST_V1":
        encoded = _encode_tar_list(value)
    else:
        raise SaipVariableMaterializationError(
            f"Catalog variable {variable_id!r} uses unsupported encoder {encoder!r}."
        )
    if expected_length is not None and isinstance(encoded, bytes):
        required = _required_positive_int(expected_length, "binding output length")
        if len(encoded) != required:
            raise SaipVariableMaterializationError(
                f"Catalog variable {variable_id!r} requires exactly {required} encoded "
                f"bytes, got {len(encoded)}."
            )
    return encoded


def _variable_constraints(variable: Mapping[str, Any]) -> dict[str, Any]:
    raw_input = variable.get("input")
    raw_constraints = raw_input.get("constraints") if isinstance(raw_input, dict) else None
    return dict(raw_constraints) if isinstance(raw_constraints, dict) else {}


def _enforce_catalog_exact_digits(variable: Mapping[str, Any], value: str) -> None:
    """Enforce an optional generated token-definition digit constraint.

    The compact varder grammar cannot carry this metadata, but generated
    authoring sessions retain it in the semantic variable catalog.  Keeping
    the check here makes a selected operator token variant authoritative for
    live-session materialisation without changing any encoder or EF geometry.
    """

    constraints = _variable_constraints(variable)
    if "exact_digits" not in constraints:
        return
    exact = constraints.get("exact_digits")
    if not isinstance(exact, int) or isinstance(exact, bool) or not 1 <= exact <= 256:
        raise SaipVariableMaterializationError(
            f"Catalog variable {str(variable.get('id') or '')!r} has an invalid "
            "exact_digits constraint."
        )
    raw_input = variable.get("input")
    input_metadata = raw_input if isinstance(raw_input, Mapping) else {}
    input_kind = str(input_metadata.get("kind") or "").strip().upper()
    input_format = str(input_metadata.get("format") or "").strip().upper()
    if input_kind not in {"DECIMAL_DIGITS", "PHONE_NUMBER"} and input_format not in {
        "ICCID",
        "IMSI",
        "E164",
    }:
        raise SaipVariableMaterializationError(
            f"Catalog variable {str(variable.get('id') or '')!r} uses exact_digits "
            "with a non-digit input contract."
        )
    text = str(value or "").strip()
    if input_kind == "PHONE_NUMBER" or input_format == "E164":
        if text.startswith("+"):
            text = text[1:]
        digits = "".join(character for character in text if character not in " -().")
    else:
        digits = "".join(character for character in text if character not in " -")
    if not digits.isdigit() or not digits:
        raise SaipVariableMaterializationError(
            f"Catalog variable {str(variable.get('id') or '')!r} requires decimal digits."
        )
    if len(digits) != exact:
        raise SaipVariableMaterializationError(
            f"Catalog variable {str(variable.get('id') or '')!r} requires exactly "
            f"{exact} digits, got {len(digits)}."
        )


def _encode_ascii_credential(
    value: str,
    constraints: Mapping[str, Any],
    output_length: int,
    variable_id: str,
) -> bytes:
    text = str(value or "").strip()
    if not text.isdigit():
        raise SaipVariableMaterializationError(
            f"Catalog variable {variable_id!r} requires decimal digits."
        )
    minimum = int(constraints.get("min_characters") or output_length)
    maximum = int(constraints.get("max_characters") or output_length)
    if not minimum <= len(text) <= maximum or len(text) > output_length:
        raise SaipVariableMaterializationError(
            f"Catalog variable {variable_id!r} requires {minimum}..{maximum} digits."
        )
    return text.encode("ascii") + (b"\xff" * (output_length - len(text)))


def _encode_imsi_ef(value: str) -> bytes:
    digits = _decimal_digits(value, label="IMSI", maximum=15)
    odd = len(digits) % 2 == 1
    first_byte = (int(digits[0]) << 4) | (0x09 if odd else 0x01)
    body = bytearray([first_byte])
    remaining = digits[1:]
    if len(remaining) % 2:
        remaining += "F"
    for offset in range(0, len(remaining), 2):
        first, second = remaining[offset], remaining[offset + 1]
        low = int(first)
        high = 0x0F if second == "F" else int(second)
        body.append((high << 4) | low)
    if len(body) > 8:
        raise SaipVariableMaterializationError("IMSI does not fit the eight-byte EF payload.")
    # TS 31.102 §4.2.2: the length byte counts the significant bytes that
    # follow it, so a shorter IMSI reads less than 0x08.
    significant = len(body)
    body.extend(b"\xff" * (8 - len(body)))
    return bytes([significant]) + bytes(body)


def _encode_msisdn_bcd(value: str, byte_length: int) -> bytes:
    digits = _msisdn_digits(value)
    if len(digits) > byte_length * 2:
        raise SaipVariableMaterializationError(
            f"MSISDN exceeds the {byte_length * 2}-digit fixed slot."
        )
    nibbles = digits + ("F" * (byte_length * 2 - len(digits)))
    swapped = "".join(nibbles[index + 1] + nibbles[index] for index in range(0, len(nibbles), 2))
    return bytes.fromhex(swapped)


def _encode_tar_list(value: str) -> list[bytes]:
    if isinstance(value, str):
        parts = [item for item in re.split(r"[,;\s]+", value.strip()) if item]
    else:
        raise SaipVariableMaterializationError("TAR list must be comma- or space-separated hex.")
    if not parts:
        return []
    items = [_hex_bytes(part, label="TAR") for part in parts]
    if any(len(item) != 3 for item in items):
        raise SaipVariableMaterializationError("Every TAR must contain exactly three bytes.")
    if len(set(items)) != len(items):
        raise SaipVariableMaterializationError("TAR list contains duplicate values.")
    return items


def _decimal_digits(value: str, *, label: str, maximum: int) -> str:
    digits = "".join(character for character in str(value or "").strip() if character not in " -")
    if not digits.isdigit() or not digits:
        raise SaipVariableMaterializationError(f"{label} requires decimal digits.")
    if len(digits) > maximum:
        raise SaipVariableMaterializationError(f"{label} exceeds {maximum} digits.")
    return digits


def _hex_bytes(value: Any, *, label: str) -> bytes:
    text = str(value or "").strip().replace(" ", "").replace(":", "").replace("-", "")
    text = text.removeprefix("0x").removeprefix("0X").upper()
    if not text or len(text) % 2 or _HEX_RE.fullmatch(text) is None:
        raise SaipVariableMaterializationError(
            f"{label} requires non-empty, even-length hexadecimal bytes."
        )
    return bytes.fromhex(text)


def _required_positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise SaipVariableMaterializationError(f"{label} must be a positive integer.")
    return value


def _rfm_context_map(document: Mapping[str, Any], sequence: Any) -> dict[int, str]:
    generation = document.get("__ygg_generation__")
    raw_contexts = generation.get("rfm_contexts") if isinstance(generation, dict) else None
    rfm_pes = [pe for pe in sequence.pe_list if str(getattr(pe, "type", "")) == "rfm"]
    if not rfm_pes:
        return {}
    contexts = [str(item).strip().upper() for item in raw_contexts or []]
    if len(contexts) != len(rfm_pes):
        raise SaipVariableMaterializationError(
            "Semantic catalog cannot determine the RFM profile-element context order."
        )
    return {id(pe): context for pe, context in zip(rfm_pes, contexts, strict=True)}


def _resolve_catalog_setter(
    sequence: Any,
    locator: Mapping[str, Any],
    *,
    rfm_contexts: Mapping[int, str],
    materialization_value: str = "",
    catalog_encoder: str = "",
) -> Callable[[Any], None]:
    pe_type = str(locator.get("pe_type") or "").strip()
    context = str(locator.get("context") or "").strip().upper()
    field = str(locator.get("field") or "").strip()
    raw_match = locator.get("match")
    match = dict(raw_match) if isinstance(raw_match, dict) else {}
    candidates = [pe for pe in sequence.pe_list if str(getattr(pe, "type", "")) == pe_type]
    if pe_type == "rfm":
        candidates = [pe for pe in candidates if rfm_contexts.get(id(pe)) == context]
    pe_name = str(match.get("pe_name") or "").strip()
    if pe_name:
        candidates = [
            pe
            for pe in candidates
            if isinstance(getattr(pe, "decoded", None), dict) and pe_name in pe.decoded
        ]

    if pe_type in {"pinCodes", "pukCodes"} and field in {"pinValue", "pukValue"}:
        return _credential_setter(candidates, pe_type, field, match)
    if len(candidates) != 1:
        raise SaipVariableMaterializationError(
            f"Semantic locator {pe_type}/{context}/{field} resolved to "
            f"{len(candidates)} profile elements."
        )
    pe = candidates[0]
    decoded = getattr(pe, "decoded", None)
    if not isinstance(decoded, dict):
        raise SaipVariableMaterializationError(f"Profile element {pe_type!r} has no decoded body.")

    if pe_name:
        entries = decoded.get(pe_name)
        if not isinstance(entries, list):
            raise SaipVariableMaterializationError(
                f"Filesystem field {pe_type}.{pe_name} is not a CHOICE list."
            )
        _validate_filesystem_leaf(pe, entries, pe_name, str(match.get("fid_path") or ""))
        if field == "record.number":
            offset = _required_non_negative_int(match.get("byte_offset"), "record byte offset")
            length = _required_positive_int(match.get("byte_length"), "record byte length")
            if catalog_encoder.strip().upper() == "EF_MSISDN_RECORD_V1":
                if offset < 2:
                    raise SaipVariableMaterializationError(
                        "MSISDN record number offset leaves no ADN length/TON-NPI prefix."
                    )
                digit_count = len(_msisdn_digits(materialization_value))
                number_byte_count = (digit_count + 1) // 2
                if number_byte_count > length:
                    raise SaipVariableMaterializationError(
                        f"MSISDN requires {number_byte_count} BCD bytes but the record "
                        f"number slot contains {length}."
                    )
                adn_prefix = bytes((1 + number_byte_count, 0x91))

                def set_msisdn_number(value: Any) -> None:
                    payload = bytes(value)
                    if len(payload) != length:
                        raise SaipVariableMaterializationError(
                            f"Filesystem region requires exactly {length} bytes."
                        )
                    _set_file_regions(entries, ((offset - 2, adn_prefix),), 2)
                    _set_file_regions(entries, ((offset, payload),), length)

                return set_msisdn_number
            return lambda value: _set_file_regions(entries, ((offset, bytes(value)),), length)
        if field != "fillFileContent":
            raise SaipVariableMaterializationError(
                f"Unsupported filesystem semantic field {field!r}."
            )
        offset = _required_non_negative_int(match.get("byte_offset"), "file byte offset")
        length = _required_positive_int(match.get("byte_length"), "file byte length")
        record_start = match.get("record_start")
        record_end = match.get("record_end")
        if record_start is not None or record_end is not None:
            start = _required_positive_int(record_start, "record start")
            end = _required_positive_int(record_end, "record end")
            if end < start:
                raise SaipVariableMaterializationError("Filesystem record range is reversed.")
            record_length = _record_length(entries, pe_type, pe_name)
            if length != record_length or offset != (start - 1) * record_length:
                raise SaipVariableMaterializationError(
                    f"Filesystem locator {pe_type}.{pe_name} disagrees with record geometry."
                )

            def set_records(value: Any) -> None:
                payload = bytes(value)
                if len(payload) != record_length:
                    raise SaipVariableMaterializationError(
                        f"Filesystem record requires exactly {record_length} bytes."
                    )
                regions = tuple(
                    ((record_number - 1) * record_length, payload)
                    for record_number in range(start, end + 1)
                )
                _set_file_regions(entries, regions, record_length)

            return set_records
        declared_size = _file_size(entries)
        if offset == 0 and (declared_size is None or length == declared_size):
            return lambda value: _replace_whole_file_content(entries, bytes(value), length)
        return lambda value: _set_file_regions(entries, ((offset, bytes(value)),), length)

    if pe_type == "header" and field == "iccid":
        return lambda value: decoded.__setitem__("iccid", bytearray(value))
    if pe_type == "akaParameter" and field.startswith("algoParameter."):
        choice = decoded.get("algoConfiguration")
        parameters = choice[1] if isinstance(choice, tuple) and len(choice) == 2 else None
        if not isinstance(parameters, dict):
            raise SaipVariableMaterializationError("AKA profile element has no algoParameter choice.")
        expected_algorithm = match.get("algorithmID")
        if expected_algorithm is not None and parameters.get("algorithmID") != expected_algorithm:
            raise SaipVariableMaterializationError("AKA algorithm ID does not match the catalog locator.")
        leaf = field.rsplit(".", 1)[1]
        return lambda value: parameters.__setitem__(leaf, bytes(value))
    if pe_type == "securityDomain" and field.startswith("instance."):
        instance = decoded.get("instance")
        if not isinstance(instance, dict):
            raise SaipVariableMaterializationError("Security Domain has no instance object.")
        leaf = field.rsplit(".", 1)[1]
        return lambda value: instance.__setitem__(leaf, bytes(value))
    if pe_type == "securityDomain" and field == "keyComponents.keyData":
        return _security_domain_key_setter(pe, match)
    if pe_type == "rfm" and field in {"instanceAID", "minimumSecurityLevel"}:
        return lambda value: decoded.__setitem__(field, bytes(value))
    if pe_type == "rfm" and field == "tarList":
        return lambda value: decoded.__setitem__("tarList", [bytes(item) for item in value])
    if pe_type == "rfm" and field == "adfRFMAccess.adfAID":
        access = decoded.get("adfRFMAccess")
        if not isinstance(access, dict):
            raise SaipVariableMaterializationError(f"RFM {context} has no ADF access object.")
        return lambda value: access.__setitem__("adfAID", bytes(value))
    adf_prefix = f"adf-{context.lower()}.fileDescriptor."
    if pe_type == context.lower() and field.startswith(adf_prefix):
        root_name = f"adf-{context.lower()}"
        entries = decoded.get(root_name)
        if not isinstance(entries, list):
            raise SaipVariableMaterializationError(f"{context} PE has no {root_name} root.")
        descriptor = _named_tuple_dict(entries, "fileDescriptor")
        leaf = field.removeprefix(adf_prefix)
        return lambda value: descriptor.__setitem__(leaf, bytes(value))
    raise SaipVariableMaterializationError(
        f"Unsupported semantic locator {pe_type}/{context}/{field}."
    )


def _credential_setter(
    candidates: Iterable[Any],
    pe_type: str,
    field: str,
    match: Mapping[str, Any],
) -> Callable[[Any], None]:
    key_reference = _hex_int(match.get("keyReference"), "keyReference")
    rows: list[dict[str, Any]] = []
    for pe in candidates:
        decoded = getattr(pe, "decoded", None)
        container = decoded.get(pe_type) if isinstance(decoded, dict) else None
        raw_rows = container[1] if isinstance(container, tuple) and len(container) == 2 else container
        if isinstance(raw_rows, list):
            rows.extend(
                row
                for row in raw_rows
                if isinstance(row, dict) and row.get("keyReference") == key_reference
            )
    if len(rows) != 1:
        raise SaipVariableMaterializationError(
            f"{pe_type} key reference {key_reference:02X} resolved to {len(rows)} rows."
        )
    return lambda value: rows[0].__setitem__(field, bytes(value))


def _security_domain_key_setter(pe: Any, match: Mapping[str, Any]) -> Callable[[Any], None]:
    keys = getattr(pe, "keys", None)
    if not isinstance(keys, list):
        raise SaipVariableMaterializationError("Security Domain has no parsed key list.")
    wanted_kvn = _one_byte_hex(match.get("keyVersionNumber"))
    wanted_kid = _one_byte_hex(match.get("keyIdentifier"))
    wanted_type = _one_byte_hex(match.get("keyType"))
    ordinal = _required_non_negative_int(match.get("component_ordinal", 0), "key component ordinal")
    components: list[Any] = []
    for key in keys:
        if _one_byte_hex(getattr(key, "key_version_number", None)) != wanted_kvn:
            continue
        if _one_byte_hex(getattr(key, "key_identifier", None)) != wanted_kid:
            continue
        raw_components = getattr(key, "key_components", None)
        if not isinstance(raw_components, list) or ordinal >= len(raw_components):
            continue
        component = raw_components[ordinal]
        if _one_byte_hex(getattr(component, "key_type", None)) == wanted_type:
            components.append(component)
    if len(components) != 1:
        raise SaipVariableMaterializationError(
            f"Security Domain key {wanted_kvn}/{wanted_kid}/{wanted_type} resolved to "
            f"{len(components)} components."
        )
    return lambda value: setattr(components[0], "key_data", bytes(value))


def _validate_filesystem_leaf(pe: Any, entries: list[Any], pe_name: str, fid_path: str) -> None:
    if not fid_path:
        return
    parts = tuple(part.strip().upper() for part in fid_path.split("/") if part.strip())
    if not parts or parts[0] != "3F00" or any(len(part) != 4 or _HEX_RE.fullmatch(part) is None for part in parts):
        raise SaipVariableMaterializationError(
            f"Filesystem locator {pe_name!r} has invalid FID path {fid_path!r}."
        )
    expected = bytes.fromhex(parts[-1])
    descriptor = _named_tuple_dict(entries, "fileDescriptor")
    actual = descriptor.get("fileID")
    if actual is None:
        files = getattr(pe, "files", None)
        file_object = files.get(pe_name) if isinstance(files, dict) else None
        fid = getattr(file_object, "fid", None)
        if isinstance(fid, int):
            actual = fid.to_bytes(2, "big")
    if not isinstance(actual, (bytes, bytearray)) or bytes(actual) != expected:
        actual_hex = bytes(actual).hex().upper() if isinstance(actual, (bytes, bytearray)) else "<missing>"
        raise SaipVariableMaterializationError(
            f"Filesystem locator {pe_name!r} expects FID {parts[-1]}, got {actual_hex}."
        )


def _replace_whole_file_content(entries: list[Any], value: bytes, expected_length: int) -> None:
    if len(value) != expected_length:
        raise SaipVariableMaterializationError(
            f"Filesystem value requires exactly {expected_length} bytes."
        )
    kept = [
        item
        for item in entries
        if not (isinstance(item, tuple) and len(item) == 2 and str(item[0]) in _FILE_DATA_CHOICES)
    ]
    entries[:] = [*kept, ("fillFileContent", bytes(value))]


def _set_file_regions(
    entries: list[Any],
    regions: Iterable[tuple[int, bytes]],
    expected_length: int,
) -> None:
    for offset, value in regions:
        if len(value) != expected_length:
            raise SaipVariableMaterializationError(
                f"Filesystem region requires exactly {expected_length} bytes."
            )
        _scrub_fill_region(entries, offset, len(value))
        entries.extend([("fillFileOffset", offset), ("fillFileContent", bytes(value))])


def _scrub_fill_region(entries: list[Any], offset: int, length: int) -> None:
    target_end = offset + length
    cursor = 0
    for index, item in enumerate(entries):
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        name, raw_value = str(item[0]), item[1]
        if name == "fillFileOffset":
            cursor = _required_non_negative_int(raw_value, "fillFileOffset")
            continue
        if name != "fillFileContent":
            continue
        if not isinstance(raw_value, (bytes, bytearray)):
            raise SaipVariableMaterializationError("fillFileContent is not a byte string.")
        content = bytes(raw_value)
        content_end = cursor + len(content)
        overlap_start = max(cursor, offset)
        overlap_end = min(content_end, target_end)
        if overlap_start < overlap_end:
            start = overlap_start - cursor
            end = overlap_end - cursor
            entries[index] = (item[0], content[:start] + b"\xff" * (end - start) + content[end:])
        cursor = content_end


def _record_length(entries: list[Any], pe_type: str, pe_name: str) -> int:
    descriptor = _named_tuple_dict(entries, "fileDescriptor")
    raw = descriptor.get("fileDescriptor")
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 4:
        raise SaipVariableMaterializationError(
            f"{pe_type}.{pe_name} has no decodable record descriptor."
        )
    length = int.from_bytes(bytes(raw)[-2:], "big")
    if length <= 0:
        raise SaipVariableMaterializationError(f"{pe_type}.{pe_name} record length is invalid.")
    return length


def _file_size(entries: list[Any]) -> int | None:
    descriptor = _named_tuple_dict(entries, "fileDescriptor")
    raw = descriptor.get("efFileSize")
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        return None
    return int.from_bytes(bytes(raw), "big")


def _named_tuple_dict(entries: list[Any], name: str) -> dict[str, Any]:
    rows = [
        item[1]
        for item in entries
        if isinstance(item, tuple)
        and len(item) == 2
        and str(item[0]) == name
        and isinstance(item[1], dict)
    ]
    if len(rows) != 1:
        raise SaipVariableMaterializationError(
            f"Filesystem CHOICE {name!r} resolved to {len(rows)} dictionaries."
        )
    return rows[0]


def _hex_int(value: Any, label: str) -> int:
    try:
        return int(str(value or "").strip(), 16)
    except ValueError as error:
        raise SaipVariableMaterializationError(f"Invalid {label} value {value!r}.") from error


def _one_byte_hex(value: Any) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value & 0xFF:02X}"
    if isinstance(value, (bytes, bytearray)) and len(value) == 1:
        return bytes(value).hex().upper()
    text = str(value or "").strip().upper().removeprefix("0X")
    return text.zfill(2)


def _required_non_negative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SaipVariableMaterializationError(f"{label} must be a non-negative integer.")
    return value


def _msisdn_digits(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith("+"):
        text = text[1:]
    digits = "".join(character for character in text if character not in " -().")
    if not digits.isdigit() or not digits:
        raise SaipVariableMaterializationError("MSISDN requires decimal digits.")
    return digits


def _replace_byte_run(node: Any, needle: bytes, replacement: bytes) -> tuple[Any, int]:
    if isinstance(node, (bytes, bytearray)):
        payload = bytes(node)
        count = payload.count(needle)
        if count == 0:
            return node, 0
        rewritten = payload.replace(needle, replacement)
        return (bytearray(rewritten) if isinstance(node, bytearray) else rewritten), count
    if isinstance(node, dict):
        total = 0
        for key, value in list(node.items()):
            rewritten, count = _replace_byte_run(value, needle, replacement)
            if count:
                node[key] = rewritten
                total += count
        return node, total
    if isinstance(node, list):
        total = 0
        for index, value in enumerate(node):
            rewritten, count = _replace_byte_run(value, needle, replacement)
            if count:
                node[index] = rewritten
                total += count
        return node, total
    if isinstance(node, tuple):
        rewritten_items: list[Any] = []
        total = 0
        for value in node:
            rewritten, count = _replace_byte_run(value, needle, replacement)
            rewritten_items.append(rewritten)
            total += count
        return (tuple(rewritten_items) if total else node), total
    return node, 0


def inline_variable_names(records: Iterable[InlinePlaceholderRecord]) -> list[str]:
    """Return the canonical inline variable names in order of first appearance."""

    names: list[str] = []
    seen: set[str] = set()
    for record in records:
        name = str(getattr(record, "variable_name", "") or "").strip()
        if not name or name.casefold() in seen:
            continue
        seen.add(name.casefold())
        names.append(name)
    return names


def inline_record_key(record: Any) -> str:
    """Return the compact literal body that names one occurrence.

    ``<var><TYPE><byte_length>[<modifier>]`` is the form the sidecars and
    the session store raw values by, so ``{iccid:ICCID:10:NibbleSwap}`` and
    ``{iccidICCID10NibbleSwap}`` share the key ``iccidICCID10NibbleSwap``.
    The modifier is kept as written; comparisons across spellings go
    through ``saip_hex_template.placeholder_key_fold``.
    """

    modifier = str(getattr(record, "modifier", "") or "")
    return (
        f"{str(getattr(record, 'variable_name', '') or '')}"
        f"{str(getattr(record, 'type_name', '') or '')}"
        f"{int(getattr(record, 'byte_length', 0) or 0)}{modifier}"
    )


def validate_inline_raw_value(record: Any, value: Any) -> bytes:
    """Return the bytes a pre-encoded value supplies for one occurrence.

    The value must be hex of exactly the declared width. Type and modifier
    are not consulted: the bytes are already in wire form.
    """

    literal = str(getattr(record, "literal", "") or inline_record_key(record))
    payload = _hex_bytes(value, label=literal)
    width = int(getattr(record, "byte_length", 0) or 0)
    if len(payload) != width:
        raise SaipVariableMaterializationError(
            f"Inline placeholder {literal!r} requires exactly {width} bytes, "
            f"got {len(payload)}."
        )
    return payload


def match_inline_raw_values(
    records: Iterable[Any],
    raw_values: Mapping[str, Any] | None,
) -> dict[str, str]:
    """Pair pre-encoded values with occurrences by compact key.

    Keys match exactly first, then case-insensitively, then by the
    spelling-independent fold, so a value stored as
    ``{iccid:ICCID:10:nibble_swap}`` serves a ``[iccidICCID10NibbleSwap]``
    occurrence, and last with underscores dropped from the variable, so a
    sidecar written as ``scp80kic1BINARY16`` still serves
    ``{scp80_kic1:BINARY:16}``. Every returned value has been checked
    against its occurrence's width, so a caller splices it without a
    second look. Keys are the canonical record keys.
    """

    supplied = {
        str(key).strip(): str(value)
        for key, value in dict(raw_values or {}).items()
        if str(key).strip()
    }
    folded = {key.casefold(): value for key, value in supplied.items()}
    by_fold: dict[str, str] = {}
    by_relaxed: dict[str, str] = {}
    for key, value in supplied.items():
        by_fold.setdefault(placeholder_key_fold(key), value)
        loose = placeholder_key_fold_relaxed(key)
        if loose:
            by_relaxed.setdefault(loose, value)
    matched: dict[str, str] = {}
    for record in records:
        key = inline_record_key(record)
        value = supplied.get(key)
        if value is None:
            value = folded.get(key.casefold())
        if value is None:
            value = by_fold.get(placeholder_key_fold(key))
        if value is None:
            loose = placeholder_key_fold_relaxed(key)
            value = by_relaxed.get(loose) if loose else None
        if value is None or str(value).strip() == "":
            continue
        matched[key] = validate_inline_raw_value(record, value).hex().upper()
    return matched


def records_for_raw_key(records: Iterable[Any], key: Any) -> list[Any]:
    """Return the occurrences a stored raw value named ``key`` belongs to.

    The ladder of :func:`match_inline_raw_values` seen from the key's side:
    the occurrences whose record key folds like ``key``, else those that
    match once underscores are dropped from the variable. Empty when the
    template has no such occurrence.
    """

    text = str(key or "").strip()
    if not text:
        return []
    ordered = list(records)
    wanted = placeholder_key_fold(text)
    hits = [
        record for record in ordered if placeholder_key_fold(inline_record_key(record)) == wanted
    ]
    if hits:
        return hits
    loose = placeholder_key_fold_relaxed(text)
    if not loose:
        return []
    return [
        record
        for record in ordered
        if placeholder_key_fold_relaxed(inline_record_key(record)) == loose
    ]


def lookup_raw_value(raw_values: Mapping[str, Any] | None, key: Any) -> str | None:
    """Return the pre-encoded value stored under ``key`` in any spelling.

    The same ladder as :func:`match_inline_raw_values` for one key: exact,
    case-insensitive, the spelling-independent fold, then the fold with
    underscores dropped from the variable. ``None`` when nothing usable is
    stored.
    """

    wanted = str(key or "").strip()
    if not wanted:
        return None
    supplied = {
        str(name).strip(): str(value)
        for name, value in dict(raw_values or {}).items()
        if str(name).strip()
    }
    value = supplied.get(wanted)
    if value is None:
        folded = wanted.casefold()
        value = next((v for k, v in supplied.items() if k.casefold() == folded), None)
    if value is None:
        fold = placeholder_key_fold(wanted)
        value = next((v for k, v in supplied.items() if placeholder_key_fold(k) == fold), None)
    if value is None:
        loose = placeholder_key_fold_relaxed(wanted)
        if loose:
            value = next(
                (v for k, v in supplied.items() if placeholder_key_fold_relaxed(k) == loose),
                None,
            )
    if value is None or value.strip() == "":
        return None
    return value


def resolve_inline_records(
    records: Iterable[Any],
    values: Mapping[str, Any],
    raw_values: Mapping[str, Any] | None = None,
) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """Return ``(typed, raw, unresolved)`` for a record set.

    A variable is resolved by a typed value, or by a pre-encoded value for
    every one of its occurrences. ``unresolved`` lists the variables with
    neither, in order of first appearance.
    """

    all_records = list(records)
    typed, _missing = match_inline_variable_values(all_records, values)
    raw = match_inline_raw_values(all_records, raw_values)
    typed_folded = {name.casefold() for name in typed}
    unresolved: list[str] = []
    for name in inline_variable_names(all_records):
        if name.casefold() in typed_folded:
            continue
        group = [
            record
            for record in all_records
            if str(getattr(record, "variable_name", "") or "").casefold() == name.casefold()
        ]
        if group and all(inline_record_key(record) in raw for record in group):
            continue
        unresolved.append(name)
    return typed, raw, unresolved


def match_inline_variable_values(
    records: Iterable[InlinePlaceholderRecord],
    values: Mapping[str, Any],
) -> tuple[dict[str, str], list[str]]:
    """Pair stored values with the template's inline variables.

    Lookup is case-insensitive so ``ICCID`` satisfies a ``[iccidICCID10]``
    placeholder. Returns ``(matched, unresolved)``: ``matched`` maps each
    canonical record name to its stored value, ``unresolved`` lists the
    names that still have none.
    """

    folded_values: dict[str, str] = {}
    for raw_name, raw_value in dict(values or {}).items():
        folded_values[str(raw_name).strip().casefold()] = str(raw_value)
    matched: dict[str, str] = {}
    unresolved: list[str] = []
    for name in inline_variable_names(records):
        value = folded_values.get(name.casefold())
        if value is None or value == "":
            unresolved.append(name)
            continue
        matched[name] = value
    return matched, unresolved


def validate_inline_variable_value(
    records: Iterable[InlinePlaceholderRecord],
    variable_name: str,
    value: str,
) -> list[InlinePlaceholderRecord]:
    """Encode ``value`` for every occurrence of ``variable_name`` without applying it.

    Returns the matching records so the caller can report the occurrence
    count. Raises when the name has no occurrence or when any occurrence's
    typed encoder rejects the value, so a stored value is always one the
    later export can materialise.
    """

    wanted = str(variable_name or "").strip().casefold()
    matching = [
        record
        for record in records
        if str(getattr(record, "variable_name", "") or "").casefold() == wanted
    ]
    if not matching:
        raise SaipVariableMaterializationError(
            f"Inline variable {variable_name!r} has no occurrence in the template."
        )
    for record in matching:
        encode_inline_placeholder_value(record, value)
    return matching


def materialize_inline_records(
    document: Mapping[str, Any],
    records: Iterable[Any],
    values: Mapping[str, Any],
    *,
    raw_values: Mapping[str, Any] | None = None,
    require_complete: bool = True,
) -> tuple[dict[str, Any], list[Any], list[VariableMaterializationResult]]:
    """Apply every stored value to a copy of ``document`` in one pass.

    ``values`` are typed per variable; ``raw_values`` are pre-encoded per
    occurrence, keyed as :func:`inline_record_key` (a universal token
    list). A typed value wins for its variable; raw values fill the
    occurrences that have none. Returns ``(document, remaining_records,
    results)``. The input document and record list are never mutated, so
    a session keeps its template while an export takes the materialised
    copy. With ``require_complete`` the call refuses when any variable has
    no value, naming the unresolved ones, so a concrete export can never
    ship sentinel bytes.
    """

    all_records = list(records)
    typed, raw, unresolved = resolve_inline_records(all_records, values, raw_values)
    if require_complete and unresolved:
        raise SaipVariableMaterializationError(
            "Unresolved inline template variable(s): "
            + ", ".join(unresolved)
            + ". Set a value for each one before a concrete export."
        )
    candidate: dict[str, Any] = copy.deepcopy(dict(document))
    remaining = all_records
    results: list[VariableMaterializationResult] = []
    for name, value in typed.items():
        candidate, remaining, result = materialize_inline_variable(
            candidate,
            remaining,
            name,
            value,
        )
        results.append(result)
    raw_groups: dict[str, list[Any]] = {}
    still_open: list[Any] = []
    for record in remaining:
        key = inline_record_key(record)
        hex_value = raw.get(key)
        if hex_value is None:
            still_open.append(record)
            continue
        payload = validate_inline_raw_value(record, hex_value)
        sentinel = _hex_bytes(record.sentinel_hex, label=f"{record.variable_name} sentinel")
        candidate, count = _replace_byte_run(candidate, sentinel, payload)
        if count != 1:
            raise SaipVariableMaterializationError(
                f"Inline placeholder {record.literal!r} occurrence #{record.index} "
                f"resolved to {count} byte regions instead of one."
            )
        raw_groups.setdefault(str(record.variable_name), []).append(record)
    for name, group in raw_groups.items():
        results.append(
            VariableMaterializationResult(
                variable_name=name,
                binding_count=len(group),
                secret=variable_is_secret(name),
                source="universal_tokens",
            )
        )
    return candidate, still_open, results


def inline_variable_sidecar_path_for(template_path: Path) -> Path:
    """Return ``<stem>.variables.json`` next to ``template_path``."""

    return Path(template_path).with_suffix(_INLINE_VARIABLE_SIDECAR_SUFFIX)


def write_inline_variable_sidecar(
    path: Path,
    values: Mapping[str, Any],
    *,
    created_from: str = "",
    raw_values: Mapping[str, Any] | None = None,
    test_value_list: str = "",
) -> None:
    """Write stored inline-variable values as a JSON sidecar.

    Secret values are written too: the sidecar is what lets a reopened
    template export a complete profile again, and it sits beside the
    template under the same file permissions. ``raw_values`` are the
    pre-encoded per-occurrence bytes (test values from a list), keyed as
    :func:`inline_record_key`. ``test_value_list`` is the selector of the
    list bound to the template (a library name or a path); empty means
    the universal list alone.
    """

    payload: dict[str, Any] = {
        "schema": INLINE_VARIABLE_SIDECAR_SCHEMA,
        "values": {str(name): str(value) for name, value in dict(values).items()},
    }
    raw_payload = {
        str(key): str(value)
        for key, value in dict(raw_values or {}).items()
        if str(key).strip() and str(value).strip()
    }
    if raw_payload:
        payload["raw_values"] = raw_payload
    if str(test_value_list or "").strip():
        payload["test_value_list"] = str(test_value_list).strip()
    if created_from:
        payload["created_from"] = str(created_from)
    encoded = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(encoded) > _MAX_INLINE_VARIABLE_SIDECAR_BYTES:
        raise SaipVariableMaterializationError(
            "Inline-variable sidecar exceeds the safety limit."
        )
    atomic_write_bytes(Path(path), encoded, overwrite=True)


def read_inline_variable_sidecar_document(path: Path) -> dict[str, Any]:
    """Load ``{"values", "raw_values", "test_value_list"}`` from a variables sidecar.

    ``test_value_list`` is the bound list's selector, ``""`` when the
    sidecar names none.
    """

    encoded = read_bounded_regular_file(Path(path), _MAX_INLINE_VARIABLE_SIDECAR_BYTES)
    try:
        loaded = json.loads(encoded.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SaipVariableMaterializationError(
            f"Inline-variable sidecar is not valid JSON: {error}"
        ) from error
    if not isinstance(loaded, dict):
        raise SaipVariableMaterializationError("Inline-variable sidecar must be a JSON object.")
    schema = str(loaded.get("schema") or "")
    if schema != INLINE_VARIABLE_SIDECAR_SCHEMA:
        raise SaipVariableMaterializationError(
            f"Unsupported inline-variable sidecar schema {schema!r}."
        )
    raw_values = loaded.get("values")
    if not isinstance(raw_values, dict):
        raise SaipVariableMaterializationError(
            "Inline-variable sidecar has no 'values' object."
        )
    document: dict[str, Any] = {"values": {}, "raw_values": {}, "test_value_list": ""}
    bound = loaded.get("test_value_list")
    if bound is not None:
        if not isinstance(bound, str):
            raise SaipVariableMaterializationError(
                "Inline-variable sidecar 'test_value_list' must be a string."
            )
        document["test_value_list"] = bound.strip()
    for section, label in (("values", "value"), ("raw_values", "raw value")):
        block = loaded.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            raise SaipVariableMaterializationError(
                f"Inline-variable sidecar '{section}' must be a JSON object."
            )
        for raw_name, raw_value in block.items():
            name = str(raw_name).strip()
            if not name:
                raise SaipVariableMaterializationError(
                    "Inline-variable sidecar contains an empty variable name."
                )
            if not isinstance(raw_value, str):
                raise SaipVariableMaterializationError(
                    f"Inline-variable sidecar {label} for {name!r} must be a string."
                )
            document[section][name] = raw_value
    return document


def read_inline_variable_sidecar(path: Path) -> dict[str, str]:
    """Load ``name -> value`` from a sidecar written by :func:`write_inline_variable_sidecar`."""

    return read_inline_variable_sidecar_document(path)["values"]


__all__ = [
    "INLINE_VARIABLE_SIDECAR_SCHEMA",
    "SaipVariableMaterializationError",
    "VariableMaterializationResult",
    "catalog_variables",
    "decode_inline_placeholder_value",
    "encode_inline_placeholder_value",
    "find_catalog_variable",
    "inline_record_key",
    "inline_variable_names",
    "lookup_raw_value",
    "match_inline_raw_values",
    "records_for_raw_key",
    "read_inline_variable_sidecar_document",
    "resolve_inline_records",
    "validate_inline_raw_value",
    "inline_variable_sidecar_path_for",
    "match_inline_variable_values",
    "materialize_catalog_variable",
    "materialize_inline_records",
    "materialize_inline_variable",
    "placeholder_value_to_wire_hex",
    "read_inline_variable_sidecar",
    "validate_inline_variable_value",
    "variable_is_secret",
    "write_inline_variable_sidecar",
]
