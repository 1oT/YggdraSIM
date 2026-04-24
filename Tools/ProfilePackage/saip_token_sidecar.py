"""Token sidecar I/O.

A *token sidecar* is a small JSON file that carries the
``__ygg_placeholder_style__`` and ``__ygg_token_defs__`` portion of a
placeholder-bearing profile template, independently of the profile tree
itself. This lets operators:

- Export the token definitions from an authored template for re-use
  elsewhere (``EXPORT-TOKENS``).
- Apply a previously-saved set of token definitions onto a template that
  currently has no defs (``APPLY-TOKENS``).
- Auto-discover matching defs when opening a profile that carries
  variable placeholders (see ``candidate_sidecar_paths``).

Sidecar schema (validated by ``validate_sidecar_document``)::

    {
      "__ygg_placeholder_style__": "brace" | "bracket",
      "__ygg_token_defs__": { "ICCID": {"hex": "89..."}, ... },
      "__ygg_sidecar_meta__": {
          "schema": "ygg.token_sidecar.v1",
          "created_from": "my_template.json"  # optional
      }
    }

The meta object is optional. The placeholder-style default is ``brace``.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from .saip_json_codec import (
    TokenExpansionContext,
    _META_PLACEHOLDER_STYLE,
    _META_TOKEN_DEFS,
    _encode_ber_tlv_length,
)
from .saip_profile_template import extract_template_placeholder_names

_SIDECAR_SCHEMA_ID = "ygg.token_sidecar.v1"
_SIDECAR_META_KEY = "__ygg_sidecar_meta__"
_DEFAULT_SIDECAR_SUFFIX = ".tokens.json"


class TokenSidecarError(ValueError):
    """Raised when a sidecar cannot be loaded or validated."""


def default_sidecar_path_for(profile_path: Path) -> Path:
    """Return ``<stem>.tokens.json`` next to ``profile_path``."""
    resolved = Path(profile_path)
    return resolved.with_suffix(_DEFAULT_SIDECAR_SUFFIX)


def candidate_sidecar_paths(profile_path: Path) -> list[Path]:
    """Candidate sidecars for ``profile_path`` in descending preference.

    Order (first match wins):

    1. ``<profile_stem>.tokens.json`` (canonical).
    2. ``<profile_name>.tokens.json`` (for files without a stem like
       ``profile.json`` → ``profile.json.tokens.json``).
    3. ``tokens.json`` in the same directory.
    """

    resolved = Path(profile_path)
    parent = resolved.parent
    candidates: list[Path] = []
    seen: set[Path] = set()

    primary = default_sidecar_path_for(resolved)
    if primary not in seen:
        candidates.append(primary)
        seen.add(primary)

    stacked = parent / (resolved.name + _DEFAULT_SIDECAR_SUFFIX)
    if stacked not in seen:
        candidates.append(stacked)
        seen.add(stacked)

    generic = parent / "tokens.json"
    if generic not in seen:
        candidates.append(generic)
        seen.add(generic)

    return candidates


def normalize_style(value: Any) -> str:
    raw = str(value or "brace").strip().lower()
    if raw == "curly":
        raw = "brace"
    if raw not in ("brace", "bracket"):
        raise TokenSidecarError(
            f"Placeholder style must be 'brace' or 'bracket' (got {value!r})."
        )
    return raw


def _validate_token_def_entry(name: str, entry: Any) -> None:
    cleaned_name = str(name or "").strip()
    if len(cleaned_name) == 0:
        raise TokenSidecarError("Token name must be non-empty.")
    if isinstance(entry, str):
        return
    if isinstance(entry, dict):
        allowed_keys = {"hex", "zero_len", "pattern_hex", "byte_len"}
        unknown = [key for key in entry.keys() if key not in allowed_keys]
        if len(unknown) > 0:
            raise TokenSidecarError(
                f"Token {cleaned_name!r} has unsupported keys: {sorted(unknown)}."
            )
        if "hex" in entry and isinstance(entry["hex"], str) is False:
            raise TokenSidecarError(
                f"Token {cleaned_name!r}: 'hex' must be a string."
            )
        if "pattern_hex" in entry:
            if isinstance(entry["pattern_hex"], str) is False:
                raise TokenSidecarError(
                    f"Token {cleaned_name!r}: 'pattern_hex' must be a string."
                )
            if isinstance(entry.get("byte_len"), int) is False:
                raise TokenSidecarError(
                    f"Token {cleaned_name!r}: 'pattern_hex' requires integer 'byte_len'."
                )
        return
    raise TokenSidecarError(
        f"Token {cleaned_name!r} definition must be a string or object."
    )


def validate_sidecar_document(sidecar: Any) -> dict[str, Any]:
    if isinstance(sidecar, dict) is False:
        raise TokenSidecarError("Sidecar root must be a JSON object.")
    style_raw = sidecar.get(_META_PLACEHOLDER_STYLE, "brace")
    style = normalize_style(style_raw)

    defs_raw = sidecar.get(_META_TOKEN_DEFS, {})
    if isinstance(defs_raw, dict) is False:
        raise TokenSidecarError(
            f"Sidecar '{_META_TOKEN_DEFS}' must be a JSON object."
        )

    normalized_defs: dict[str, Any] = {}
    for name, entry in defs_raw.items():
        _validate_token_def_entry(str(name), entry)
        normalized_defs[str(name)] = copy.deepcopy(entry)

    meta = sidecar.get(_SIDECAR_META_KEY, {})
    if isinstance(meta, dict) is False:
        raise TokenSidecarError(
            f"Sidecar '{_SIDECAR_META_KEY}' must be a JSON object."
        )
    return {
        _META_PLACEHOLDER_STYLE: style,
        _META_TOKEN_DEFS: normalized_defs,
        _SIDECAR_META_KEY: dict(meta),
    }


def build_sidecar_from_template(
    template: dict[str, Any],
    *,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Extract a sidecar payload from a loaded (pre-dejsonify) template dict."""
    if isinstance(template, dict) is False:
        raise TokenSidecarError("Template root must be a JSON object.")

    style_raw = template.get(_META_PLACEHOLDER_STYLE, "brace")
    style = normalize_style(style_raw)

    defs_raw = template.get(_META_TOKEN_DEFS, {})
    if isinstance(defs_raw, dict) is False:
        raise TokenSidecarError(
            f"Template '{_META_TOKEN_DEFS}' must be a JSON object."
        )

    normalized_defs: dict[str, Any] = {}
    for name, entry in defs_raw.items():
        _validate_token_def_entry(str(name), entry)
        normalized_defs[str(name)] = copy.deepcopy(entry)

    placeholder_names = extract_template_placeholder_names(template)

    meta: dict[str, Any] = {"schema": _SIDECAR_SCHEMA_ID}
    if source_label is not None:
        label_text = str(source_label).strip()
        if len(label_text) > 0:
            meta["created_from"] = label_text
    if len(placeholder_names) > 0:
        meta["placeholder_names"] = sorted(placeholder_names)

    return {
        _META_PLACEHOLDER_STYLE: style,
        _META_TOKEN_DEFS: normalized_defs,
        _SIDECAR_META_KEY: meta,
    }


def load_sidecar(path: Path) -> dict[str, Any]:
    if path.is_file() is False:
        raise TokenSidecarError(f"Sidecar not found: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise TokenSidecarError(f"Cannot read sidecar {path}: {error}") from error
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as error:
        raise TokenSidecarError(f"Sidecar {path} is not valid JSON: {error}") from error
    return validate_sidecar_document(loaded)


def write_sidecar(
    path: Path,
    *,
    style: str,
    token_defs: dict[str, Any],
    source_label: str | None = None,
) -> None:
    normalized_style = normalize_style(style)
    for name, entry in token_defs.items():
        _validate_token_def_entry(str(name), entry)

    meta: dict[str, Any] = {"schema": _SIDECAR_SCHEMA_ID}
    if source_label is not None:
        label_text = str(source_label).strip()
        if len(label_text) > 0:
            meta["created_from"] = label_text

    payload: dict[str, Any] = {
        _META_PLACEHOLDER_STYLE: normalized_style,
        _META_TOKEN_DEFS: {name: copy.deepcopy(entry) for name, entry in token_defs.items()},
        _SIDECAR_META_KEY: meta,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def merge_sidecar_into_template(
    template: dict[str, Any],
    sidecar: dict[str, Any],
    *,
    overwrite: bool = False,
) -> list[str]:
    """Merge sidecar defs + placeholder-style into ``template`` in place.

    Returns a list of human-readable summaries describing what changed.
    ``overwrite=False`` preserves any existing definition already present
    in the template; ``overwrite=True`` replaces them.
    """

    if isinstance(template, dict) is False:
        raise TokenSidecarError("Template root must be a JSON object.")

    sidecar_payload = validate_sidecar_document(sidecar)
    style = sidecar_payload[_META_PLACEHOLDER_STYLE]
    side_defs = sidecar_payload[_META_TOKEN_DEFS]

    summaries: list[str] = []

    existing_style = template.get(_META_PLACEHOLDER_STYLE)
    if existing_style is None:
        template[_META_PLACEHOLDER_STYLE] = style
        summaries.append(f"placeholder style set to '{style}'")
    elif str(existing_style).strip().lower() != style:
        if overwrite:
            template[_META_PLACEHOLDER_STYLE] = style
            summaries.append(
                f"placeholder style replaced '{existing_style}' -> '{style}'"
            )
        else:
            summaries.append(
                f"placeholder style kept existing '{existing_style}' (sidecar='{style}')"
            )

    existing_defs_raw = template.get(_META_TOKEN_DEFS, {})
    if isinstance(existing_defs_raw, dict) is False:
        raise TokenSidecarError(
            f"Template '{_META_TOKEN_DEFS}' must be a JSON object."
        )
    merged: dict[str, Any] = {
        name: copy.deepcopy(value) for name, value in existing_defs_raw.items()
    }

    added: list[str] = []
    replaced: list[str] = []
    kept: list[str] = []
    for name, entry in side_defs.items():
        if name not in merged:
            merged[name] = copy.deepcopy(entry)
            added.append(name)
            continue
        if overwrite:
            merged[name] = copy.deepcopy(entry)
            replaced.append(name)
            continue
        kept.append(name)

    template[_META_TOKEN_DEFS] = merged

    if len(added) > 0:
        summaries.append("added defs: " + ", ".join(sorted(added)))
    if len(replaced) > 0:
        summaries.append("replaced defs: " + ", ".join(sorted(replaced)))
    if len(kept) > 0:
        summaries.append(
            "kept existing defs (sidecar ignored): " + ", ".join(sorted(kept))
        )
    return summaries


def template_has_unresolved_placeholders(template: dict[str, Any]) -> list[str]:
    """Return sorted placeholder names that appear in ``template`` without a def."""
    names = extract_template_placeholder_names(template)
    defs_raw = template.get(_META_TOKEN_DEFS, {})
    if isinstance(defs_raw, dict) is False:
        defs_raw = {}
    unresolved = sorted(
        name for name in names if name not in defs_raw and name != "ICCID_EF"
    )
    if (
        "ICCID_EF" in names
        and "ICCID_EF" not in defs_raw
        and "ICCID" not in defs_raw
    ):
        unresolved.append("ICCID_EF")
    return sorted(set(unresolved))


def first_available_sidecar(profile_path: Path) -> Path | None:
    for candidate in candidate_sidecar_paths(profile_path):
        if candidate.is_file():
            return candidate
    return None


# ---------------------------------------------------------------------------
# Token list editing (works on both template docs and sidecar docs)
# ---------------------------------------------------------------------------


def _resolve_token_defs_container(
    document: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Return the mutable token-def dict inside ``document`` (creating if absent)."""

    if isinstance(document, dict) is False:
        raise TokenSidecarError("Document root must be a JSON object.")
    defs = document.get(_META_TOKEN_DEFS)
    if defs is None:
        document[_META_TOKEN_DEFS] = {}
        defs = document[_META_TOKEN_DEFS]
    if isinstance(defs, dict) is False:
        raise TokenSidecarError(
            f"Document '{_META_TOKEN_DEFS}' must be a JSON object."
        )
    style_raw = document.get(_META_PLACEHOLDER_STYLE, "brace")
    style = normalize_style(style_raw)
    return defs, style


def list_token_definitions(document: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of the token defs inside ``document``."""

    defs, _style = _resolve_token_defs_container(document)
    return {name: copy.deepcopy(entry) for name, entry in defs.items()}


def read_token_defs_from_file(
    path: Path,
) -> tuple[dict[str, Any], str] | None:
    """Read only the token-defs portion from a JSON file on disk.

    Returns ``(token_defs_dict, placeholder_style)`` on success or
    ``None`` if the file is missing, not JSON, or does not contain the
    ``__ygg_token_defs__`` key. Sidecar files and full template files
    are both acceptable inputs; only the two metadata keys are read.
    Never raises on malformed input — missing/invalid data yields
    ``None`` so callers can treat "no usable defs found" as a first-class
    case.
    """

    try:
        raw_text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        loaded = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(loaded, dict) is False:
        return None
    defs = loaded.get(_META_TOKEN_DEFS)
    if isinstance(defs, dict) is False:
        return None
    style = normalize_style(loaded.get(_META_PLACEHOLDER_STYLE))
    return ({name: copy.deepcopy(entry) for name, entry in defs.items()}, style)


_TOKEN_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _validate_token_name(name: str) -> str:
    cleaned = str(name or "").strip()
    if _TOKEN_NAME_RE.fullmatch(cleaned) is None:
        raise TokenSidecarError(
            f"Invalid token name {name!r}: use [A-Za-z][A-Za-z0-9_]*."
        )
    return cleaned


def parse_token_value_argument(raw: str) -> Any:
    """Parse a CLI-supplied token value into the sidecar-accepted shape.

    Accepts either:

    - A JSON object starting with ``{`` (e.g. ``{"zero_len": 10}``).
    - A hex string (whitespace tolerated) for the convenience of CLI users.
      Example: ``89461111111111111112``.

    Empty / pure whitespace input is rejected to avoid silent misconfiguration.
    """

    text = str(raw or "").strip()
    if len(text) == 0:
        raise TokenSidecarError("Token value is empty.")
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as error:
            raise TokenSidecarError(
                f"Token value is not valid JSON: {error}"
            ) from error
        return parsed
    compact = text.replace(" ", "").replace("\t", "")
    if len(compact) == 0:
        raise TokenSidecarError("Token value is empty after stripping whitespace.")
    if len(compact) % 2 != 0:
        raise TokenSidecarError(
            "Token hex value must have even length (got "
            f"{len(compact)} nibbles)."
        )
    try:
        bytes.fromhex(compact)
    except ValueError as error:
        raise TokenSidecarError(
            f"Token hex value is not a valid hex string: {error}"
        ) from error
    return compact.lower()


def set_token_definition(
    document: dict[str, Any],
    name: str,
    value: Any,
    *,
    overwrite: bool = True,
) -> tuple[bool, Any]:
    """Insert or update a token definition in-place.

    Returns ``(created, previous_value)``. ``created`` is ``True`` when the
    token was newly added. When ``overwrite`` is ``False`` and the token
    already exists the call is a no-op and returns ``(False, existing)``.
    """

    clean_name = _validate_token_name(name)
    _validate_token_def_entry(clean_name, value)
    defs, _style = _resolve_token_defs_container(document)
    if clean_name in defs:
        if overwrite is False:
            return False, copy.deepcopy(defs[clean_name])
        previous = copy.deepcopy(defs[clean_name])
        defs[clean_name] = copy.deepcopy(value)
        return False, previous
    defs[clean_name] = copy.deepcopy(value)
    return True, None


def remove_token_definition(
    document: dict[str, Any],
    name: str,
) -> Any | None:
    """Drop a token definition. Returns the removed entry or ``None``."""

    clean_name = _validate_token_name(name)
    defs, _style = _resolve_token_defs_container(document)
    if clean_name not in defs:
        return None
    removed = copy.deepcopy(defs[clean_name])
    del defs[clean_name]
    return removed


# ---------------------------------------------------------------------------
# Placeholder reference scanning (hex fields in tagged-bytes nodes)
# ---------------------------------------------------------------------------


def _tagged_bytes_hex_fields(root: Any) -> list[tuple[list[Any], dict[str, Any], str]]:
    """Walk ``root`` and return every tagged-bytes hex string position.

    Each returned tuple is ``(path, parent_dict, hex_text)``. ``parent_dict``
    is the tagged-bytes object (``{"hex": "..."}``) and ``hex_text`` is the
    raw hex string including any placeholder tokens. Mutation happens by
    writing back into ``parent_dict["hex"]``.
    """

    out: list[tuple[list[Any], dict[str, Any], str]] = []

    def visit(node: Any, path: list[Any]) -> None:
        if isinstance(node, dict):
            hex_value = node.get("hex")
            if (
                isinstance(hex_value, str)
                and len(node) == 1
                and all(isinstance(key, str) for key in node.keys())
            ):
                out.append((list(path), node, hex_value))
                return
            for key, value in node.items():
                visit(value, path + [key])
            return
        if isinstance(node, list):
            for index, value in enumerate(node):
                visit(value, path + [index])
            return

    visit(root, [])
    return out


def _placeholder_pair_regex(style: str) -> re.Pattern[str]:
    """Regex that captures ``<length-bytes>{NAME}`` pairs for a given style."""

    normalized = normalize_style(style)
    if normalized == "brace":
        opener, closer = r"\{", r"\}"
    else:
        opener, closer = r"\[", r"\]"
    # group 1 = hex nibbles preceding the placeholder (even count, no spaces)
    # group 2 = already-derived marker (``#``) if present
    # group 3 = token name
    pattern = (
        r"(?<![0-9A-Fa-f])"
        r"((?:[0-9A-Fa-f]{2})+)"
        rf"{opener}(#?)([A-Za-z][A-Za-z0-9_]*){closer}"
    )
    return re.compile(pattern)


def _name_reference_regex(name: str, style: str) -> re.Pattern[str]:
    normalized = normalize_style(style)
    if normalized == "brace":
        opener, closer = r"\{", r"\}"
    else:
        opener, closer = r"\[", r"\]"
    return re.compile(
        rf"{opener}(#?){re.escape(name)}{closer}",
    )


def count_token_references(
    document: dict[str, Any],
    name: str,
) -> dict[str, int]:
    """Count ``{NAME}`` and ``{#NAME}`` references in tagged-bytes hex fields."""

    _defs, style = _resolve_token_defs_container(document)
    clean_name = _validate_token_name(name)
    pattern = _name_reference_regex(clean_name, style)
    content_hits = 0
    length_hits = 0
    for _path, _parent, hex_text in _tagged_bytes_hex_fields(document):
        for match in pattern.finditer(hex_text):
            if match.group(1) == "#":
                length_hits += 1
            else:
                content_hits += 1
    return {
        "content": content_hits,
        "length": length_hits,
        "total": content_hits + length_hits,
    }


def rename_token_in_template(
    document: dict[str, Any],
    old_name: str,
    new_name: str,
    *,
    rewrite_references: bool = True,
) -> dict[str, Any]:
    """Rename a token definition and (optionally) rewrite every reference.

    Returns a summary dict with the counts of what changed::

        {
            "renamed_def": bool,
            "content_refs": int,  # {OLD} -> {NEW}
            "length_refs": int,   # {#OLD} -> {#NEW}
            "paths": [list of dotted paths where rewrites happened],
        }

    Raises :class:`TokenSidecarError` when ``new_name`` already exists in
    the token defs (caller must resolve that collision first).
    """

    clean_old = _validate_token_name(old_name)
    clean_new = _validate_token_name(new_name)
    if clean_old == clean_new:
        return {
            "renamed_def": False,
            "content_refs": 0,
            "length_refs": 0,
            "paths": [],
        }
    defs, style = _resolve_token_defs_container(document)
    renamed_def = False
    if clean_old in defs:
        if clean_new in defs:
            raise TokenSidecarError(
                f"Cannot rename {clean_old!r} → {clean_new!r}: "
                f"{clean_new!r} already exists in __ygg_token_defs__."
            )
        # Preserve insertion order by rebuilding the dict.
        rebuilt: dict[str, Any] = {}
        for name, entry in defs.items():
            if name == clean_old:
                rebuilt[clean_new] = entry
            else:
                rebuilt[name] = entry
        defs.clear()
        defs.update(rebuilt)
        renamed_def = True

    summary: dict[str, Any] = {
        "renamed_def": renamed_def,
        "content_refs": 0,
        "length_refs": 0,
        "paths": [],
    }

    if rewrite_references is False:
        return summary

    pattern = _name_reference_regex(clean_old, style)
    touched_paths: list[str] = []

    def _replacement(match: re.Match[str]) -> str:
        marker = match.group(1)
        if normalize_style(style) == "brace":
            return "{" + marker + clean_new + "}"
        return "[" + marker + clean_new + "]"

    for path, parent, hex_text in _tagged_bytes_hex_fields(document):
        new_hex, n_replacements = pattern.subn(_replacement, hex_text)
        if n_replacements == 0:
            continue
        parent["hex"] = new_hex
        for match in pattern.finditer(hex_text):
            if match.group(1) == "#":
                summary["length_refs"] += 1
            else:
                summary["content_refs"] += 1
        touched_paths.append(_format_dotted_path(path))

    summary["paths"] = touched_paths
    return summary


def _format_dotted_path(path: list[Any]) -> str:
    parts: list[str] = []
    for segment in path:
        if isinstance(segment, int):
            if len(parts) == 0:
                parts.append(f"[{segment}]")
            else:
                parts[-1] = parts[-1] + f"[{segment}]"
            continue
        parts.append(str(segment))
    return ".".join(parts)


# ---------------------------------------------------------------------------
# RETOKENISE-LENGTHS: rewrite ``<length-bytes>{NAME}`` -> ``{#NAME}{NAME}``
# ---------------------------------------------------------------------------


def _expected_length_prefix_hex(content_bytes: int) -> str:
    return _encode_ber_tlv_length(content_bytes).hex().upper()


def retokenise_template_lengths(
    document: dict[str, Any],
    *,
    only_tokens: set[str] | list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Scan ``document`` and replace ``LL{NAME}`` pairs with ``{#NAME}{NAME}``.

    Only rewrites when the hex nibbles immediately preceding ``{NAME}``
    encode the exact BER-TLV length of the currently-defined
    ``__ygg_token_defs__`` entry for ``NAME``. Short-form (``LL``) and
    long-form (``81 LL``, ``82 LL LL`` ...) prefixes are both recognised.

    Passing ``only_tokens`` restricts the rewrite to the named tokens —
    useful for the TUI's "auto-migrate length companion for the token I
    just edited" prompt. ``None`` (default) means every defined token.

    Does nothing for tokens without a def, for placeholders that are
    already companions (``{#NAME}``), or when the preceding hex does not
    match the expected length bytes. Returns a report dict describing the
    rewrites performed.
    """

    defs, style = _resolve_token_defs_container(document)
    if len(defs) == 0:
        return {"rewrites": 0, "paths": [], "skipped": []}

    ctx = TokenExpansionContext(defs, style)
    expected_prefix: dict[str, str] = {}
    scope: set[str] | None = None
    if only_tokens is not None:
        scope = {str(name) for name in only_tokens}
    for name in defs.keys():
        if scope is not None and name not in scope:
            continue
        try:
            resolved_len = len(ctx.resolve_named(name))
        except ValueError:
            continue
        expected_prefix[name] = _expected_length_prefix_hex(resolved_len)

    pair_re = _placeholder_pair_regex(style)
    rewrites = 0
    touched_paths: list[str] = []
    skipped: list[dict[str, Any]] = []

    for path, parent, hex_text in _tagged_bytes_hex_fields(document):
        def _replace(match: re.Match[str]) -> str:
            nonlocal rewrites
            prefix_hex = match.group(1).upper()
            already_derived = match.group(2) == "#"
            token_name = match.group(3)

            if already_derived:
                return match.group(0)
            if token_name not in expected_prefix:
                if scope is None or token_name in scope:
                    skipped.append(
                        {
                            "path": _format_dotted_path(path),
                            "token": token_name,
                            "reason": "token not in __ygg_token_defs__",
                        }
                    )
                return match.group(0)

            needed = expected_prefix[token_name]
            if prefix_hex.endswith(needed) is False:
                skipped.append(
                    {
                        "path": _format_dotted_path(path),
                        "token": token_name,
                        "reason": (
                            f"prefix {prefix_hex!s} does not end with "
                            f"expected {needed!s}"
                        ),
                    }
                )
                return match.group(0)

            keep_hex = prefix_hex[: len(prefix_hex) - len(needed)]
            opener = "{" if normalize_style(style) == "brace" else "["
            closer = "}" if normalize_style(style) == "brace" else "]"
            rewrites += 1
            return (
                keep_hex
                + opener + "#" + token_name + closer
                + opener + token_name + closer
            )

        new_hex = pair_re.sub(_replace, hex_text)
        if new_hex != hex_text:
            parent["hex"] = new_hex
            touched_paths.append(_format_dotted_path(path))

    return {
        "rewrites": rewrites,
        "paths": touched_paths,
        "skipped": skipped,
    }


def find_unmigrated_length_candidates(
    document: dict[str, Any],
    token_name: str,
) -> list[dict[str, Any]]:
    """Return a list of ``<length>{NAME}`` candidates for ``token_name``.

    Each entry is ``{"path": dotted_path, "prefix": prefix_hex, ...}`` and
    represents a spot where the hex nibbles immediately before ``{token_name}``
    already encode the BER-TLV length of ``token_name``. Candidates are
    exactly the sites that :func:`retokenise_template_lengths(only_tokens=
    {token_name})` would rewrite — the function does not mutate ``document``.
    """

    defs, style = _resolve_token_defs_container(document)
    if token_name not in defs:
        return []
    ctx = TokenExpansionContext(defs, style)
    try:
        resolved_len = len(ctx.resolve_named(token_name))
    except ValueError:
        return []
    needed = _expected_length_prefix_hex(resolved_len)
    pair_re = _placeholder_pair_regex(style)
    hits: list[dict[str, Any]] = []
    for path, _parent, hex_text in _tagged_bytes_hex_fields(document):
        for match in pair_re.finditer(hex_text):
            prefix_hex = match.group(1).upper()
            already_derived = match.group(2) == "#"
            hit_name = match.group(3)
            if already_derived or hit_name != token_name:
                continue
            if prefix_hex.endswith(needed):
                hits.append(
                    {
                        "path": _format_dotted_path(path),
                        "prefix": prefix_hex,
                        "needed": needed,
                    }
                )
    return hits
