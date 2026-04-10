"""
JSON serialization helpers for SAIP decoded profile documents (pySim / asn1tools).

Bytes and tuples are tagged so JSON round-trips match encoder expectations.
Hex fields (``__ygg_saip_bytes__`` and ``__ygg_saip_ph__``) may embed named
placeholders: default ``{name}``, or ``[name]`` when
``__ygg_placeholder_style__`` is ``bracket``. Definitions live under
``__ygg_token_defs__`` at the document root (same value shapes as
``__ygg_saip_ph__``). Occurrences are expanded independently; nothing enforces
that the same token matches across the profile.

PySim is imported only from paths that build or encode profile elements.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any

_TYPE_SUFFIX_RE = re.compile(r"_(\d+)$")

_TAG_BYTES = "hex"
_TAG_TUPLE = "@"
_TAG_PLACEHOLDER = "placeholder"
_TAG_LABEL = "label"

_LEGACY_TAG_BYTES = "__ygg_saip_bytes__"
_LEGACY_TAG_TUPLE = "__ygg_saip_tuple__"
_LEGACY_TAG_PLACEHOLDER = "__ygg_saip_ph__"
_LEGACY_TAG_LABEL = "__ygg_label__"
_PREV_TAG_TUPLE = "tuple"

_META_TOKEN_DEFS = "__ygg_token_defs__"
_META_PLACEHOLDER_STYLE = "__ygg_placeholder_style__"
_DOCUMENT_META_KEYS = (_META_TOKEN_DEFS, _META_PLACEHOLDER_STYLE)


def _format_codec_path(path: tuple[str, ...]) -> str:
    parts: list[str] = []
    for token in path:
        token_text = str(token or "")
        if len(token_text) == 0:
            continue
        if token_text.startswith("[") and token_text.endswith("]") and len(parts) > 0:
            parts[-1] += token_text
            continue
        parts.append(token_text)
    return ".".join(parts)


class SaipCodecValueError(ValueError):
    """ValueError carrying JSON path context for tagged SAIP editor buffers."""

    def __init__(self, message: str, path: tuple[str, ...] = ()) -> None:
        self.detail = str(message or "").strip() or "Invalid SAIP value."
        self.path = tuple(path)
        path_text = _format_codec_path(self.path)
        if len(path_text) == 0:
            super().__init__(self.detail)
            return
        super().__init__(f"Invalid value at {path_text}: {self.detail}")


def _wrap_codec_error(error: Exception, path: tuple[str, ...]) -> SaipCodecValueError:
    if isinstance(error, SaipCodecValueError):
        return error
    detail = str(error).strip() or error.__class__.__name__
    return SaipCodecValueError(detail, path)


def _raise_codec_error(error: Exception, path: tuple[str, ...]) -> None:
    wrapped = _wrap_codec_error(error, path)
    if wrapped is error:
        raise wrapped
    raise wrapped from error


# Human-oriented hints next to ``__ygg_saip_bytes__`` (ignored on dejsonify / encode).
_JSON_VALUE_LABELS: dict[str, str] = {
    "fillFileContent": "Fill file content (SAIP)",
    "header": "Profile header PE",
    "application": "Application PE",
    "nonStandard": "Non-standard PE",
    "mf": "Master file (MF) tree",
    "usim": "USIM application tree",
    "opt-usim": "Optional USIM tree",
    "isim": "ISIM application tree",
    "opt-isim": "Optional ISIM tree",
    "telecom": "DF.TELECOM tree",
    "phonebook": "DF.PHONEBOOK tree",
    "df-5gs": "DF.5GS tree",
    "df-saip": "DF.SAIP tree",
    "df-snpn": "DF.SNPN tree",
    "df-5gprose": "DF.5GProSe tree",
    "securitydomain": "Security domain",
    "gsm-access": "DF.GSM-ACCESS tree",
    "eap": "DF.EAP tree",
    "ef-iccid": "EF.ICCID (2FE2)",
    "ef-dir": "EF.DIR (2F00)",
    "ef-pl": "EF.PL (2F05)",
    "ef-imsi": "EF.IMSI (6F07)",
    "ef-ad": "EF.AD (6FAD)",
    "ef-msisdn": "EF.MSISDN (6F40)",
    "ef-spn": "EF.SPN (6F46)",
    "ef-ust": "EF.UST (6F38)",
    "ef-acc": "EF.ACC (6F78)",
    "ef-loci": "EF.LOCI (6F7E)",
    "ef-psloci": "EF.PSLOCI (6F73)",
    "ef-epsloci": "EF.EPSLOCI (6FE3)",
    "ef-keysPS": "EF.KeysPS / EF.P-CSCF (6F09)",
    "ef-pcscf": "EF.P-CSCF (6F09)",
    "ef-suci-calc-info-usim": "EF.SUCI_Calc_Info (USIM 4F01)",
    "ef-supinai": "EF.SUPI_NAI (4F09)",
    "ef-arr": "EF.ARR",
}


def _canonical_tag_key(key: str) -> str:
    mapping = {
        _LEGACY_TAG_BYTES: _TAG_BYTES,
        _LEGACY_TAG_TUPLE: _TAG_TUPLE,
        _LEGACY_TAG_PLACEHOLDER: _TAG_PLACEHOLDER,
        _LEGACY_TAG_LABEL: _TAG_LABEL,
        _PREV_TAG_TUPLE: _TAG_TUPLE,
    }
    return mapping.get(str(key), str(key))


def _value_first(value: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in value:
            return value[key]
    raise KeyError(keys[0] if len(keys) > 0 else "missing key")


def _label_for_path_segment(segment: str) -> str:
    k = str(segment).strip()
    if k in _JSON_VALUE_LABELS:
        return _JSON_VALUE_LABELS[k]
    if k.startswith("ef-"):
        return f"EF field ({k})"
    if k.startswith("[") and k.endswith("]"):
        return k
    return k.replace("-", " ")


def _display_label_for_json_path(path: tuple[str, ...]) -> str | None:
    parts: list[str] = []
    for raw in path:
        key = _canonical_tag_key(str(raw).strip())
        if key in ("", "sections", "intro", _TAG_BYTES, _TAG_TUPLE, _TAG_PLACEHOLDER):
            continue
        if key == _TAG_LABEL:
            continue
        if key.startswith("__ygg_"):
            continue
        if key.startswith("[") and len(parts) > 0:
            parts[-1] = parts[-1] + f" {key}"
            continue
        parts.append(_label_for_path_segment(key))
    if len(parts) == 0:
        return None
    if len(parts) > 4:
        parts = parts[-4:]
    return " / ".join(parts)


class TokenExpansionContext:
    """
    Resolves ``{token}`` (default) or ``[token]`` (alternate) inside hex templates.

    Definitions live at document root under ``__ygg_token_defs__``. Each value uses
    the same shapes as ``__ygg_saip_ph__`` (hex string, ``{"hex":..}``, ``zero_len``,
    ``pattern_hex``+``byte_len``, or ``{}``).

    The same token name always expands from the same definition; occurrences are not
    cross-checked for consistency (e.g. multiple ``{ICCID}`` need not match).
    """

    def __init__(self, defs: dict[str, Any], style: str) -> None:
        if isinstance(defs, dict) is False:
            raise ValueError(f"{_META_TOKEN_DEFS} must be a JSON object.")
        self.defs = dict(defs)
        norm = str(style or "brace").strip().lower()
        if norm == "curly":
            norm = "brace"
        if norm not in ("brace", "bracket"):
            raise ValueError(
                f'{_META_PLACEHOLDER_STYLE} must be "brace" or "bracket" (got {style!r}).'
            )
        self.style = norm
        if norm == "brace":
            self._pat = re.compile(r"\{([A-Za-z][A-Za-z0-9_]*)\}")
        else:
            self._pat = re.compile(r"\[([A-Za-z][A-Za-z0-9_]*)\]")

    def resolve_named(self, name: str) -> bytes:
        if name not in self.defs:
            raise ValueError(
                f"Undefined placeholder token {name!r}; add it under {_META_TOKEN_DEFS}."
            )
        return _placeholder_inner_to_bytes(self.defs[name], self)

    def expand_mixed_hex(self, text: str) -> bytes:
        if self._pat.search(text) is None:
            compact = str(text).replace(" ", "").replace("\n", "").replace("\t", "")
            if len(compact) == 0:
                return b""
            if len(compact) % 2 != 0:
                raise ValueError("Hex string has odd length (no placeholders to account for it).")
            return bytes.fromhex(compact)

        parts: list[bytes] = []
        pos = 0
        for match in self._pat.finditer(text):
            frag = text[pos : match.start()]
            compact = frag.replace(" ", "").replace("\n", "").replace("\t", "")
            if len(compact) % 2 != 0:
                raise ValueError("Hex fragment before placeholder has odd length.")
            if len(compact) > 0:
                parts.append(bytes.fromhex(compact))
            parts.append(self.resolve_named(match.group(1)))
            pos = match.end()

        tail = text[pos:].replace(" ", "").replace("\n", "").replace("\t", "")
        if len(tail) % 2 != 0:
            raise ValueError("Hex fragment after last placeholder has odd length.")
        if len(tail) > 0:
            parts.append(bytes.fromhex(tail))
        return b"".join(parts)


def _placeholder_inner_to_bytes(inner: Any, ctx: TokenExpansionContext | None = None) -> bytes:
    """
    Expand editor placeholder payloads to concrete ``bytes`` for pySim encoders.

    Accepted shapes under ``__ygg_saip_ph__``:

    - A hex string (even length, optional spaces).
    - ``{"hex": "..."}``
    - ``{"zero_len": N}`` → ``N`` zero octets
    - ``{"pattern_hex": "..", "byte_len": N}`` → repeat pattern to ``N`` octets
    - ``{}`` → empty octet string
    """
    if isinstance(inner, str):
        text = str(inner)
        if ctx is not None:
            return ctx.expand_mixed_hex(text)
        compact = text.strip().replace(" ", "")
        if len(compact) == 0:
            return b""
        if len(compact) % 2 != 0:
            raise ValueError("__ygg_saip_ph__ hex string must have even length.")
        return bytes.fromhex(compact)

    if isinstance(inner, dict) is False:
        raise ValueError("__ygg_saip_ph__ must be a JSON object or hex string.")

    if len(inner) == 0:
        return b""

    if "hex" in inner:
        hx = str(inner["hex"])
        if ctx is not None:
            return ctx.expand_mixed_hex(hx)
        text = hx.strip().replace(" ", "")
        if len(text) % 2 != 0:
            raise ValueError("__ygg_saip_ph__.hex must have even length.")
        return bytes.fromhex(text)

    if "zero_len" in inner:
        n = int(inner["zero_len"])
        if n < 0:
            raise ValueError("__ygg_saip_ph__.zero_len must be non-negative.")
        return bytes(n)

    if "pattern_hex" in inner and "byte_len" in inner:
        pat_text = str(inner["pattern_hex"]).strip().replace(" ", "")
        if len(pat_text) % 2 != 0:
            raise ValueError("__ygg_saip_ph__.pattern_hex must have even length.")
        raw_pat = bytes.fromhex(pat_text)
        if len(raw_pat) == 0:
            raise ValueError("__ygg_saip_ph__.pattern_hex must be non-empty.")
        total = int(inner["byte_len"])
        if total < 0:
            raise ValueError("__ygg_saip_ph__.byte_len must be non-negative.")
        out = bytearray()
        while len(out) < total:
            out.extend(raw_pat)
        return bytes(out[:total])

    raise ValueError(
        "__ygg_saip_ph__: use a hex string, {}, "
        '{"hex":".."}, {"zero_len":N}, or {"pattern_hex":"..","byte_len":N}.'
    )


def ensure_workspace_pysim_on_path(workspace_root: Path) -> Path:
    """Insert bundled pysim tree on sys.path. Required before pySim.esim.saip imports."""
    pysim_root = Path(workspace_root).resolve() / "pysim"
    if pysim_root.is_dir() is False:
        raise RuntimeError(f"Local pySim source tree not found: {pysim_root}")
    root_text = str(pysim_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return pysim_root


def base_pe_type(section_key: str) -> str:
    """Strip numeric duplicate suffix (e.g. usim_2 -> usim)."""
    cleaned = str(section_key).strip()
    if cleaned == "":
        return ""
    matched = _TYPE_SUFFIX_RE.search(cleaned)
    if matched is None:
        return cleaned
    return cleaned[: matched.start()]


def jsonify_saip_value(
    value: Any,
    parent_key: str | None = None,
    path: tuple[str, ...] = (),
) -> Any:
    """Convert pySim decoded structures to JSON-serializable objects."""
    effective_path = path
    if parent_key is not None:
        key_text = str(parent_key)
        if len(path) == 0 or path[-1] != key_text:
            effective_path = path + (key_text,)

    if isinstance(value, bytes):
        out: dict[str, Any] = {_TAG_BYTES: value.hex()}
        lab = _display_label_for_json_path(effective_path)
        if lab is not None:
            out[_TAG_LABEL] = lab
        return out

    if isinstance(value, bytearray):
        out_b: dict[str, Any] = {_TAG_BYTES: bytes(value).hex()}
        lab_b = _display_label_for_json_path(effective_path)
        if lab_b is not None:
            out_b[_TAG_LABEL] = lab_b
        return out_b

    if isinstance(value, tuple):
        parts: list[Any] = []
        tuple_tag: str | None = None
        if len(value) > 0 and isinstance(value[0], str):
            tuple_tag = str(value[0])
        for idx, item in enumerate(value):
            child_path = effective_path
            if idx >= 1 and tuple_tag is not None:
                child_path = effective_path + (tuple_tag,)
            parts.append(jsonify_saip_value(item, path=child_path))
        return {_TAG_TUPLE: parts}

    if isinstance(value, OrderedDict):
        return {
            key: jsonify_saip_value(item, path=effective_path + (str(key),))
            for key, item in value.items()
        }

    if isinstance(value, dict):
        return {
            key: jsonify_saip_value(item, path=effective_path + (str(key),))
            for key, item in value.items()
        }

    if isinstance(value, list):
        out_list: list[Any] = []
        idx = 0
        while idx < len(value):
            out_list.append(
                jsonify_saip_value(value[idx], path=effective_path + (f"[{idx}]",))
            )
            idx += 1
        return out_list

    return value


def _structural_data_keys(value: dict) -> list[str]:
    """Keys that carry payload (not display-only labels and UI-only meta)."""
    allowed_tags = frozenset(
        {
            _TAG_BYTES,
            _TAG_TUPLE,
            _TAG_PLACEHOLDER,
            _LEGACY_TAG_BYTES,
            _LEGACY_TAG_TUPLE,
            _LEGACY_TAG_PLACEHOLDER,
        }
    )
    out: list[str] = []
    for k in value.keys():
        key_text = str(k)
        if key_text in (_TAG_LABEL, _LEGACY_TAG_LABEL):
            continue
        if key_text.startswith("__ygg_") and key_text not in allowed_tags:
            continue
        out.append(_canonical_tag_key(key_text))
    return out


def dejsonify_saip_value(
    value: Any,
    ctx: TokenExpansionContext | None = None,
    path: tuple[str, ...] = (),
) -> Any:
    """Restore pySim-friendly values from JSON-loaded structures."""
    if isinstance(value, dict):
        structural = _structural_data_keys(value)
        if set(structural) == {_TAG_BYTES}:
            hex_text = str(_value_first(value, _TAG_BYTES, _LEGACY_TAG_BYTES))
            try:
                if ctx is not None:
                    return ctx.expand_mixed_hex(hex_text)
                compact = hex_text.replace(" ", "").replace("\n", "").replace("\t", "")
                if len(compact) % 2 != 0:
                    raise SaipCodecValueError("hex string has odd length.", path)
                return bytes.fromhex(compact)
            except Exception as error:
                _raise_codec_error(error, path)

        if set(structural) == {_TAG_TUPLE}:
            inner = _value_first(value, _TAG_TUPLE, _LEGACY_TAG_TUPLE)
            if isinstance(inner, list) is False:
                raise SaipCodecValueError("Tagged tuple payload must be a JSON array.", path)
            out_items: list[Any] = []
            for index, item in enumerate(inner):
                item_path = path + (f"[{index}]",)
                try:
                    out_items.append(dejsonify_saip_value(item, ctx, item_path))
                except Exception as error:
                    _raise_codec_error(error, item_path)
            return tuple(out_items)

        if set(structural) == {_TAG_PLACEHOLDER}:
            try:
                return _placeholder_inner_to_bytes(
                    _value_first(value, _TAG_PLACEHOLDER, _LEGACY_TAG_PLACEHOLDER),
                    ctx,
                )
            except Exception as error:
                _raise_codec_error(error, path)

        ordered = OrderedDict()
        for key, item in value.items():
            key_text = str(key)
            if key_text in (_TAG_LABEL, _LEGACY_TAG_LABEL) or key_text.startswith(
                "__ygg_label__"
            ):
                continue
            child_path = path + (key_text,)
            try:
                ordered[key_text] = dejsonify_saip_value(item, ctx, child_path)
            except Exception as error:
                _raise_codec_error(error, child_path)
        return ordered

    if isinstance(value, list):
        out: list[Any] = []
        for index, item in enumerate(value):
            item_path = path + (f"[{index}]",)
            try:
                out.append(dejsonify_saip_value(item, ctx, item_path))
            except Exception as error:
                _raise_codec_error(error, item_path)
        return out

    return value


def jsonify_document(document: dict[str, Any]) -> dict[str, Any]:
    """Prepare a decoded dump document for json.dumps."""
    intro = document.get("intro", [])
    if isinstance(intro, list) is False:
        intro = [str(intro)]

    sections = document.get("sections", {})
    if isinstance(sections, dict) is False:
        raise ValueError("Document 'sections' must be an object.")

    out_sections: dict[str, Any] = {}
    for key, section_value in sections.items():
        sk = str(key)
        out_sections[sk] = jsonify_saip_value(section_value, sk)

    out: dict[str, Any] = {"intro": list(intro), "sections": out_sections}
    for meta_key in _DOCUMENT_META_KEYS:
        if meta_key in document:
            out[meta_key] = document[meta_key]
    return out


def dejsonify_document(document: dict[str, Any]) -> dict[str, Any]:
    """Restore a document from json.loads output."""
    intro = document.get("intro", [])
    if isinstance(intro, list) is False:
        intro = [str(intro)]

    sections = document.get("sections", {})
    if isinstance(sections, dict) is False:
        raise SaipCodecValueError("Document 'sections' must be an object.", ("sections",))

    defs_raw = document.get(_META_TOKEN_DEFS, {})
    if isinstance(defs_raw, dict) is False:
        raise SaipCodecValueError(f"{_META_TOKEN_DEFS} must be an object.", (_META_TOKEN_DEFS,))

    style_raw = document.get(_META_PLACEHOLDER_STYLE, "brace")
    try:
        ctx = TokenExpansionContext(defs_raw, str(style_raw))
    except Exception as error:
        _raise_codec_error(error, (_META_PLACEHOLDER_STYLE,))

    restored: dict[str, Any] = {
        "intro": list(intro),
        "sections": {},
    }
    for key, section_value in sections.items():
        section_key = str(key)
        section_path = ("sections", section_key)
        try:
            restored["sections"][section_key] = dejsonify_saip_value(
                section_value,
                ctx,
                section_path,
            )
        except Exception as error:
            _raise_codec_error(error, section_path)

    if _META_TOKEN_DEFS in document:
        restored[_META_TOKEN_DEFS] = dict(defs_raw)
    if _META_PLACEHOLDER_STYLE in document:
        restored[_META_PLACEHOLDER_STYLE] = document[_META_PLACEHOLDER_STYLE]

    return restored


def document_to_pretty_json(document: dict[str, Any]) -> str:
    """Tagged JSON text suitable for the transcode editor."""
    tagged = jsonify_document(document)
    return json.dumps(tagged, indent=2, ensure_ascii=False) + "\n"


_PLACEHOLDER_FRAG_RE = re.compile(
    r"\{[A-Za-z][A-Za-z0-9_]*\}|\[[A-Za-z][A-Za-z0-9_]*\]",
)


def _tagged_hex_literal_to_bytes(hex_str: str) -> bytes:
    compact = re.sub(r"\s+", "", str(hex_str))
    if len(compact) % 2 != 0:
        raise ValueError("Tagged hex literal has odd length after stripping whitespace.")
    return bytes.fromhex(compact)


def _token_ctx_from_loaded_document(loaded: dict[str, Any]) -> TokenExpansionContext | None:
    defs = loaded.get(_META_TOKEN_DEFS, {})
    if isinstance(defs, dict) is False:
        return None
    style = loaded.get(_META_PLACEHOLDER_STYLE, "brace")
    try:
        return TokenExpansionContext(defs, str(style))
    except ValueError:
        return None


def _merge_tagged_trees_preserve_hex_templates(
    pre: Any,
    post: Any,
    ctx: TokenExpansionContext | None,
) -> None:
    """
    Where ``pre`` (editor JSON) and ``post`` (fresh ``jsonify_document`` output) share
    the same shape, restore ``hex`` strings that contain placeholders
    when their expansion matches ``post``'s literal hex.
    """
    if ctx is None:
        return

    if isinstance(pre, dict) and isinstance(post, dict):
        pk = set(_structural_data_keys(pre))
        qk = set(_structural_data_keys(post))
        if pk == {_TAG_BYTES} and qk == {_TAG_BYTES}:
            pre_s = _value_first(pre, _TAG_BYTES, _LEGACY_TAG_BYTES)
            post_s = _value_first(post, _TAG_BYTES, _LEGACY_TAG_BYTES)
            if isinstance(pre_s, str) and isinstance(post_s, str):
                if _PLACEHOLDER_FRAG_RE.search(pre_s) is not None:
                    try:
                        expanded = ctx.expand_mixed_hex(pre_s)
                        post_bytes = _tagged_hex_literal_to_bytes(post_s)
                        if expanded == post_bytes:
                            post[_TAG_BYTES] = pre_s
                    except (ValueError, TypeError):
                        pass
            return

        if pk == {_TAG_TUPLE} and qk == {_TAG_TUPLE}:
            pl = _value_first(pre, _TAG_TUPLE, _LEGACY_TAG_TUPLE)
            pol = _value_first(post, _TAG_TUPLE, _LEGACY_TAG_TUPLE)
            if isinstance(pl, list) and isinstance(pol, list) and len(pl) == len(pol):
                idx = 0
                while idx < len(pl):
                    _merge_tagged_trees_preserve_hex_templates(pl[idx], pol[idx], ctx)
                    idx += 1
            return

        for key, pv in pre.items():
            if key in post:
                _merge_tagged_trees_preserve_hex_templates(pv, post[key], ctx)
        return

    if isinstance(pre, list) and isinstance(post, list):
        if len(pre) == len(post):
            idx = 0
            while idx < len(pre):
                _merge_tagged_trees_preserve_hex_templates(pre[idx], post[idx], ctx)
                idx += 1


def reapply_transcode_editor_placeholders(
    pre_loaded: dict[str, Any],
    post_tagged: dict[str, Any],
) -> None:
    """
    After DER encode → pySim decode → ``jsonify_document``, restore editor-only artefacts:

    - Root ``__ygg_token_defs__`` and ``__ygg_placeholder_style__`` from the pre-save JSON.
    - ``hex`` strings that used ``{token}`` / ``[token]`` when the
      expanded bytes match the round-tripped literal hex.

    ``pre_loaded`` is normally produced by ``json.loads`` on UTF-8 text read from disk
    after flushing the editor buffer (TRANSCODE-TUI save path). Pass **jsonify_document**
    output as ``post_tagged``. This function updates ``post_tagged`` in place.
    """
    if isinstance(pre_loaded, dict) is False:
        return
    if isinstance(post_tagged, dict) is False:
        return

    if _META_TOKEN_DEFS in pre_loaded:
        raw_defs = pre_loaded[_META_TOKEN_DEFS]
        if isinstance(raw_defs, dict):
            post_tagged[_META_TOKEN_DEFS] = copy.deepcopy(raw_defs)

    if _META_PLACEHOLDER_STYLE in pre_loaded:
        post_tagged[_META_PLACEHOLDER_STYLE] = copy.deepcopy(
            pre_loaded[_META_PLACEHOLDER_STYLE]
        )

    ctx = _token_ctx_from_loaded_document(pre_loaded)
    pre_secs = pre_loaded.get("sections")
    post_secs = post_tagged.get("sections")
    if isinstance(pre_secs, dict) and isinstance(post_secs, dict):
        _merge_tagged_trees_preserve_hex_templates(pre_secs, post_secs, ctx)


def transcode_sidecar_paths(
    source_profile_path: Path,
    transcode_root: Path | None = None,
    source_root: Path | None = None,
) -> tuple[Path, Path, Path]:
    """
    Resolve TRANSCODE-TUI persist paths for the opened profile input.

    When ``transcode_root`` is omitted, files are written next to the source input for
    backward-compatible callers. When ``transcode_root`` is provided, sidecars are placed
    under that dedicated folder instead. If ``source_root`` is also provided and the source
    file lives under it, the relative subdirectory layout is preserved below the dedicated
    transcode folder.

    Returns ``(json_path, der_path, txt_path)`` for the JSON editor snapshot, the
    last re-encoded DER, and a plain uppercase hex text export of the DER payload.
    """
    src = Path(source_profile_path).resolve()
    output_parent = src.parent
    output_stem = src.stem
    if transcode_root is not None:
        output_parent = Path(transcode_root).resolve()
        if source_root is not None:
            try:
                relative_parent = src.parent.relative_to(Path(source_root).resolve())
            except ValueError:
                digest = hashlib.sha256(src.as_posix().encode("utf-8")).hexdigest()[:12]
                output_parent = output_parent / "_external"
                output_stem = f"{src.stem}-{digest}"
            else:
                output_parent = output_parent / relative_parent
    json_path = output_parent / f"{output_stem}.transcode.json"
    der_path = output_parent / f"{output_stem}.transcode.der"
    txt_path = output_parent / f"{output_stem}.transcode.txt"
    return (json_path, der_path, txt_path)


def parse_editor_json(text: str) -> dict[str, Any]:
    """Parse editor buffer into a restored document dict."""
    stripped = str(text or "").strip()
    if len(stripped) == 0:
        raise ValueError("JSON buffer is empty.")

    loaded = json.loads(stripped)
    if isinstance(loaded, dict) is False:
        raise ValueError("Root JSON value must be an object.")

    return dejsonify_document(loaded)


def build_decoded_document_from_sequence(pes: Any, intro_lines: list[str] | None = None) -> dict[str, Any]:
    """Mirror SaipToolBridge.build_decoded_dump_document section keys (all_pe mode)."""
    counts: dict[str, int] = {}

    def unique_key(base_key: str) -> str:
        key_text = str(base_key or "section").strip() or "section"
        current_count = counts.get(key_text, 0) + 1
        counts[key_text] = current_count
        if current_count == 1:
            return key_text
        return f"{key_text}_{current_count}"

    sections: dict[str, Any] = {}
    for pe in pes.pe_list:
        sections[unique_key(pe.type)] = pe.decoded

    intro: list[str]
    if intro_lines is not None:
        intro = list(intro_lines)
    else:
        intro = [f"Profile with {len(pes.pe_list)} profile elements"]

    return {"intro": intro, "sections": sections}


def build_profile_sequence_from_document(
    document: dict[str, Any],
    workspace_root: Path,
) -> Any:
    """Reconstruct ProfileElementSequence from a restored document."""
    ensure_workspace_pysim_on_path(workspace_root)

    from pySim.esim.saip import ProfileElement, ProfileElementSequence

    sections = document.get("sections")
    if isinstance(sections, dict) is False:
        raise ValueError("Document must contain a 'sections' object.")

    pes = ProfileElementSequence()
    pes.pe_list = []

    for section_key, decoded_raw in sections.items():
        pe_type = base_pe_type(str(section_key))
        if pe_type == "":
            raise ValueError(f"Invalid section key: {section_key!r}")

        try:
            decoded = dejsonify_saip_value(decoded_raw, path=("sections", str(section_key)))
        except Exception as error:
            _raise_codec_error(error, ("sections", str(section_key)))
        if isinstance(decoded, dict) and isinstance(decoded, OrderedDict) is False:
            decoded = OrderedDict(decoded)

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
            raise ValueError(
                f"Failed to build PE {section_key!r} ({pe_type}): {detail}"
            ) from error

        pes.pe_list.append(pe)

    try:
        pes._process_pelist()
        pes.renumber_identification()
    except Exception as error:
        detail = str(error).strip() or error.__class__.__name__
        raise ValueError(f"PE sequence processing failed: {detail}") from error
    return pes


def encode_der_from_document(document: dict[str, Any], workspace_root: Path) -> bytes:
    """JSON document (restored Python types) to concatenated PE DER."""
    pes = build_profile_sequence_from_document(document, workspace_root)
    return pes.to_der()


def format_der_hex(der: bytes, width: int = 32) -> str:
    """Uppercase spaced hex lines for read-only display."""
    hex_text = der.hex().upper()
    lines: list[str] = []
    for offset in range(0, len(hex_text), width * 2):
        chunk = hex_text[offset : offset + width * 2]
        line_parts: list[str] = []
        step = 2
        index = 0
        while index < len(chunk):
            line_parts.append(chunk[index : index + step])
            index += step
        lines.append(" ".join(line_parts))
    return "\n".join(lines) + "\n"
