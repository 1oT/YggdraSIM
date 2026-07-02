# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
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

from yggdrasim_common.runtime_paths import bundle_root as runtime_bundle_root

_TYPE_SUFFIX_RE = re.compile(r"_(\d+)$")
_DISPLAY_WORD_RE = re.compile(r"[A-Z]+[0-9]+|[0-9]+[A-Za-z]+|[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+")

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
    "fillFileContent": "File content",
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


_DISPLAY_NAME_OVERRIDES: dict[str, str] = {
    "applicationspecificparametersc9": "Application specific parameters C9",
    "createfcp": "Create FCP",
    "effilesize": "EF file size",
    "filedescriptor": "File descriptor",
    "fileid": "File ID",
    "filemanagementcmd": "File management CMD",
    "filepath": "File path",
    "fillfilecontent": "File content",
    "fillfileoffset": "Fill file offset",
    "securityattributesreferenced": "Referenced security attributes",
    "shortefid": "Short EF Identifier",
    "uicctoolkitapplicationspecificparametersfield": (
        "UICC toolkit application specific parameters field"
    ),
}


_DISPLAY_WORD_OVERRIDES: dict[str, str] = {
    "3gpp": "3GPP",
    "5g": "5G",
    "5gs": "5GS",
    "5gprose": "5GProSe",
    "adf": "ADF",
    "aid": "AID",
    "aka": "AKA",
    "apn": "APN",
    "arr": "ARR",
    "ber": "BER",
    "cmd": "CMD",
    "df": "DF",
    "der": "DER",
    "dns": "DNS",
    "eap": "EAP",
    "ef": "EF",
    "eim": "EIM",
    "est": "EST",
    "fcp": "FCP",
    "fid": "FID",
    "gsm": "GSM",
    "iccid": "ICCID",
    "id": "ID",
    "imsi": "IMSI",
    "isim": "ISIM",
    "ist": "IST",
    "json": "JSON",
    "lcsi": "LCSI",
    "msisdn": "MSISDN",
    "naf": "NAF",
    "nai": "NAI",
    "oid": "OID",
    "ota": "OTA",
    "pe": "PE",
    "pin": "PIN",
    "pkcs15": "PKCS15",
    "puk": "PUK",
    "rfm": "RFM",
    "saip": "SAIP",
    "scp": "SCP",
    "sfi": "SFI",
    "sim": "SIM",
    "snpn": "SNPN",
    "sqn": "SQN",
    "suci": "SUCI",
    "supi": "SUPI",
    "tar": "TAR",
    "uicc": "UICC",
    "usim": "USIM",
    "ust": "UST",
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
    return humanize_saip_display_name(segment)


def humanize_saip_display_name(segment: str) -> str:
    """Return a human-readable label for a single JSON path segment.

    Applies word-split, case normalisation, and a curated override table
    so ``ef-acc`` becomes ``EF.ACC`` and ``usim`` becomes ``USIM``.
    Returns the raw segment unchanged if no mapping applies.
    """
    normalized = _canonical_tag_key(str(segment).strip())
    if len(normalized) == 0:
        return ""
    mapped_label = _JSON_VALUE_LABELS.get(normalized)
    if mapped_label is None:
        mapped_label = _JSON_VALUE_LABELS.get(normalized.lower())
    if mapped_label is not None:
        return mapped_label
    override_label = _DISPLAY_NAME_OVERRIDES.get(normalized.lower())
    if override_label is not None:
        return override_label
    if normalized.startswith("[") and normalized.endswith("]"):
        return normalized
    words: list[str] = []
    raw_chunks = normalized.replace("-", " ").replace("_", " ").split()
    for raw_chunk in raw_chunks:
        chunk_override = _DISPLAY_WORD_OVERRIDES.get(raw_chunk.lower())
        if chunk_override is not None:
            words.append(chunk_override)
            continue
        chunk_words = _DISPLAY_WORD_RE.findall(raw_chunk)
        if len(chunk_words) == 0:
            chunk_words = [raw_chunk]
        for chunk_word in chunk_words:
            word_override = _DISPLAY_WORD_OVERRIDES.get(chunk_word.lower())
            if word_override is not None:
                words.append(word_override)
                continue
            if chunk_word.isdigit():
                words.append(chunk_word)
                continue
            if chunk_word.isupper():
                words.append(chunk_word)
                continue
            words.append(chunk_word.lower())
    if len(words) == 0:
        return normalized
    first_word = words[0]
    if len(first_word) > 0:
        if first_word.isupper() is False:
            if first_word[0].isdigit() is False:
                words[0] = first_word[:1].upper() + first_word[1:]
    return " ".join(words)


def humanize_saip_display_path(
    path: tuple[str, ...] | list[str],
    *,
    limit: int = 4,
) -> str | None:
    """Convert a JSON path tuple to a readable ``"A / B / C"`` breadcrumb.

    Structural noise keys (``sections``, ``intro``, ``@``, ``hex``,
    ``__ygg_*``) are stripped.  Array index tokens ``[N]`` after EF keys
    are dropped; after other keys they are merged with the preceding label.
    Returns ``None`` when the filtered path is empty.
    """
    parts: list[str] = []
    last_non_index_key: str | None = None
    for raw in path:
        key = _canonical_tag_key(str(raw).strip())
        if key in ("", "sections", "intro", _TAG_BYTES, _TAG_TUPLE, _TAG_PLACEHOLDER):
            continue
        if key == _TAG_LABEL:
            continue
        if key.startswith("__ygg_"):
            continue
        if key.startswith("[") and key.endswith("]") and len(parts) > 0:
            if isinstance(last_non_index_key, str) and last_non_index_key.startswith("ef-"):
                continue
            parts[-1] = parts[-1] + f" {key}"
            continue
        parts.append(_label_for_path_segment(key))
        last_non_index_key = key
    if len(parts) == 0:
        return None
    if limit > 0:
        if len(parts) > limit:
            parts = parts[-limit:]
    return " / ".join(parts)


def _display_label_for_json_path(path: tuple[str, ...]) -> str | None:
    return humanize_saip_display_path(path)


def _encode_ber_tlv_length(byte_length: int) -> bytes:
    """Encode ``byte_length`` as BER-TLV length octets (ISO 7816-4 / X.690).

    Values in 0..127 are emitted as a single short-form byte. Larger lengths
    use the long form ``0x80 | N`` followed by ``N`` big-endian length
    octets. Callers pass the number of content octets that the companion
    placeholder will expand to.
    """

    if byte_length < 0:
        raise ValueError("Derived-length token cannot encode a negative length.")
    if byte_length < 0x80:
        return bytes([byte_length])
    buffer: list[int] = []
    remaining = byte_length
    while remaining > 0:
        buffer.append(remaining & 0xFF)
        remaining >>= 8
    if len(buffer) > 0x7E:
        raise ValueError(
            "Derived-length token exceeds BER-TLV long-form capacity (max 126 octets)."
        )
    buffer.reverse()
    return bytes([0x80 | len(buffer)]) + bytes(buffer)


def _transform_swap_nibbles(raw: bytes) -> bytes:
    """``SwapNibbles``: swap the high/low nibbles of every byte.

    Mirrors the nibble-swap step that ETSI TS 102 221 §13.2 (EF.ICCID)
    and 3GPP TS 31.102 BCD encodings require when carrying an upright
    digit string through to on-card storage. Example:
    ``8949001304080000016F`` → ``989400314080000010F6``.
    """
    return bytes(((b & 0x0F) << 4) | ((b & 0xF0) >> 4) for b in raw)


def _transform_encode_ef_imsi(raw: bytes) -> bytes:
    """``EncodeEfImsi``: 3GPP TS 31.102 §4.2.2 EF.IMSI encoding.

    Accepts either ASCII digits or a tightly packed BCD representation
    of the IMSI. Returns the 9-byte EF.IMSI body: 1 length byte +
    8 bytes of parity-tagged nibble-swapped digits (padded to 15 digits
    with the ``F`` filler nibble).
    """

    digits = "".join(ch for ch in raw.decode("ascii", errors="ignore") if ch.isdigit())
    if len(digits) == 0:
        # Treat the source as packed BCD (e.g. raw token already hex
        # digits). Strip any 0xF filler nibbles before re-encoding.
        text = raw.hex().upper().rstrip("F")
        digits = "".join(ch for ch in text if ch.isdigit())
    if len(digits) == 0 or len(digits) > 15:
        raise ValueError(
            "EncodeEfImsi expects an IMSI of 1..15 digits "
            f"(got {len(digits)})."
        )
    odd = (len(digits) % 2) == 1
    # First nibble of byte 1 = parity (0x9 odd, 0x1 even); second nibble = first digit.
    parity = 0x9 if odd else 0x1
    first_byte = (int(digits[0]) << 4) | parity
    body = [first_byte]
    pairs = digits[1:]
    if (len(pairs) % 2) == 1:
        pairs += "F"
    for index in range(0, len(pairs), 2):
        high = pairs[index]
        low = pairs[index + 1]
        high_nibble = 0xF if high.upper() == "F" else int(high)
        low_nibble = 0xF if low.upper() == "F" else int(low)
        body.append((low_nibble << 4) | high_nibble)
    while len(body) < 8:
        body.append(0xFF)
    return bytes([len(body)]) + bytes(body)


_PLACEHOLDER_TRANSFORMS: dict[str, Any] = {
    "SwapNibbles": _transform_swap_nibbles,
    "EncodeEfImsi": _transform_encode_ef_imsi,
}


class TokenExpansionContext:
    """
    Resolves ``{token}`` (default) or ``[token]`` (alternate) inside hex templates.

    Definitions live at document root under ``__ygg_token_defs__``. Each value uses
    the same shapes as ``__ygg_saip_ph__`` (hex string, ``{"hex":..}``, ``zero_len``,
    ``pattern_hex``+``byte_len``, or ``{}``).

    The same token name always expands from the same definition; occurrences are not
    cross-checked for consistency (e.g. multiple ``{ICCID}`` need not match).

    A ``{#NAME}`` / ``[#NAME]`` companion form emits the BER-TLV length octets
    of the resolved ``NAME`` token, letting templates stay in sync when the
    resolved byte-length of a placeholder changes. The content byte-length is
    encoded in short form (``0x00..0x7F``) or long form
    (``0x81 LL``, ``0x82 LL LL``, ``0x83 LL LL LL`` ...).

    A ``[Func(NAME)]`` / ``{Func(NAME)}`` form runs a registered transformation
    function on the resolved token bytes before emitting them. Two functions
    ship by default:

    - ``SwapNibbles``: byte-wise nibble swap, mirroring the ETSI TS 102 221
      §13.2 EF.ICCID and 3GPP TS 31.102 BCD encodings
      (``8949...01..0F`` → ``9894...10..F0``).
    - ``EncodeEfImsi``: takes an IMSI of up to 15 digits and produces the
      EF.IMSI content per 3GPP TS 31.102 §4.2.2 (length byte + parity-tagged
      first digit + nibble-swapped digit pairs, ``F``-padded for odd digit
      counts).
    """

    def __init__(
        self,
        defs: dict[str, Any],
        style: str,
        *,
        tolerate_undefined: bool = False,
    ) -> None:
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
        # Pattern captures (length_marker, name). The ``#`` marker is optional
        # and tags the match as a derived-length companion rather than a
        # content substitution.
        if norm == "brace":
            self._pat = re.compile(
                r"\{(#)?([A-Za-z][A-Za-z0-9_]*)"
                r"(?:\(([A-Za-z][A-Za-z0-9_]*)\))?\}"
            )
        else:
            self._pat = re.compile(
                r"\[(#)?([A-Za-z][A-Za-z0-9_]*)"
                r"(?:\(([A-Za-z][A-Za-z0-9_]*)\))?\]"
            )
        self.tolerate_undefined = bool(tolerate_undefined)
        # Names of undefined tokens encountered while tolerate_undefined=True.
        # Callers (e.g. the TUI lint harness) can inspect this to report
        # which placeholders still need definitions.
        self.undefined_tokens: set[str] = set()

    def resolve_named(self, name: str) -> bytes:
        """Resolve a ``{NAME}`` / ``[NAME]`` token to its byte value.

        Raises ``ValueError`` for undefined tokens unless
        ``tolerate_undefined`` is set, in which case an empty byte string
        is returned and the name is recorded in ``undefined_tokens``.
        """
        if name not in self.defs:
            if self.tolerate_undefined:
                self.undefined_tokens.add(str(name))
                return b""
            raise ValueError(
                f"Undefined placeholder token {name!r}; add it under {_META_TOKEN_DEFS}."
            )
        return _placeholder_inner_to_bytes(self.defs[name], self)

    def resolve_transformed(self, func_name: str, arg_name: str) -> bytes:
        """Apply a transformation function to a token's resolved bytes.

        Implements the ``[Func(NAME)]`` placeholder form. The function
        is resolved against ``_PLACEHOLDER_TRANSFORMS``; the inner token
        is resolved exactly like ``[NAME]`` and then handed to the
        function.
        """
        func = _PLACEHOLDER_TRANSFORMS.get(func_name)
        if func is None:
            raise ValueError(
                f"Unknown placeholder transformation function {func_name!r}; "
                "supported: " + ", ".join(sorted(_PLACEHOLDER_TRANSFORMS)) + "."
            )
        if arg_name not in self.defs:
            if self.tolerate_undefined:
                self.undefined_tokens.add(str(arg_name))
                return b""
            raise ValueError(
                f"Undefined placeholder token {arg_name!r} referenced via "
                f"{func_name}(); add it under {_META_TOKEN_DEFS}."
            )
        raw = _placeholder_inner_to_bytes(self.defs[arg_name], self)
        return func(raw)

    def resolve_length(
        self,
        name: str,
        *,
        transform: str | None = None,
    ) -> bytes:
        """Resolve ``{#NAME}`` / ``[#NAME]`` to BER-TLV length octets.

        When the companion ``NAME`` token is undefined and
        ``tolerate_undefined`` is set, emits a single ``0x00`` octet (short-form
        length for an empty content token) and records the undefined name so
        the lint harness can surface it.

        When ``transform`` is set (``[#Func(NAME)]``), the length is
        computed over the transformed bytes — this lets length-companion
        tokens stay in sync with EncodeEfImsi outputs whose byte length
        differs from the raw IMSI digit string.
        """

        if name not in self.defs:
            if self.tolerate_undefined:
                self.undefined_tokens.add(str(name))
                return bytes([0x00])
            raise ValueError(
                f"Undefined placeholder token {name!r} referenced via "
                f"derived-length companion; add it under {_META_TOKEN_DEFS}."
            )
        resolved = _placeholder_inner_to_bytes(self.defs[name], self)
        if transform is not None:
            func = _PLACEHOLDER_TRANSFORMS.get(transform)
            if func is None:
                raise ValueError(
                    f"Unknown placeholder transformation function {transform!r}; "
                    "supported: " + ", ".join(sorted(_PLACEHOLDER_TRANSFORMS)) + "."
                )
            resolved = func(resolved)
        return _encode_ber_tlv_length(len(resolved))

    def expand_mixed_hex(self, text: str) -> bytes:
        """Expand a hex string that may contain embedded ``{NAME}`` tokens.

        Literal hex fragments between tokens must each have an even nibble
        count.  Returns the concatenated byte string.
        """
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
            length_marker = match.group(1)
            head_name = match.group(2)
            arg_name = match.group(3) if match.lastindex and match.lastindex >= 3 else None
            if length_marker is not None:
                if arg_name is not None:
                    parts.append(self.resolve_length(arg_name, transform=head_name))
                else:
                    parts.append(self.resolve_length(head_name))
            else:
                if arg_name is not None:
                    parts.append(self.resolve_transformed(head_name, arg_name))
                else:
                    parts.append(self.resolve_named(head_name))
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


def ensure_workspace_pysim_on_path(
    workspace_root: Path,
    bundle_root_path: Path | None = None,
) -> Path:
    """Make ``pySim.esim.saip`` importable and return the resolved root.

    Resolution order, in descending priority:

    1. A developer checkout at ``<workspace>/pysim`` or the PyInstaller
       bundle root. This lets a maintainer work against an unreleased
       upstream branch without reinstalling after every change.
    2. A pip-installed ``pySim`` package (e.g. from the ``[saip]`` extra
       or ``pip install 'pySim @ git+https://github.com/osmocom/pysim.git'``).
       When the package is already importable we accept it as-is and
       return the directory that ``pySim.__file__`` resolves to, so
       callers that log the "pysim root" still get a meaningful path.

    We only raise ``RuntimeError`` when **both** paths fail; the
    message points the operator at the recommended install command.
    This avoids the previous behaviour where a perfectly valid
    ``pip install yggdrasim[saip]`` still broke the SAIP TUI because
    the on-disk clone was absent.

    .. warning::
       Callers MUST NOT re-insert the returned path into ``sys.path``.
       For the on-disk case this helper has already done so; for the
       pip-installed case the returned path points *inside*
       ``site-packages/pySim/`` (the package directory itself).
       Adding that directory to ``sys.path`` would shadow stdlib
       ``pprint`` with ``pySim/pprint.py`` and trigger a circular
       import in ``asn1tools`` (``from pprint import pformat``
       resolves to the pySim submodule, whose ``from pprint import
       PrettyPrinter`` then self-references). Consume the return
       value for logging and diagnostics only.
    """
    candidates = [
        Path(workspace_root).resolve() / "pysim",
    ]
    if bundle_root_path is not None:
        candidates.append(Path(bundle_root_path).resolve() / "pysim")
    candidates.append(Path(runtime_bundle_root()).resolve() / "pysim")

    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.is_dir():
            root_text = str(candidate)
            if root_text not in sys.path:
                sys.path.insert(0, root_text)
            return candidate

    try:
        import pySim  # noqa: F401  (import-probe; resolves to site-packages)
    except ImportError as import_error:
        tried = ", ".join(str(path) for path in seen)
        raise RuntimeError(
            "pySim is not available. Install the upstream package via "
            "`pip install 'yggdrasim[saip]'` (recommended) or "
            "`pip install 'pySim @ git+https://github.com/osmocom/pysim.git'`, "
            "or clone the upstream tree into one of: "
            f"{tried}. Underlying import error: "
            f"{type(import_error).__name__}: {import_error}."
        ) from import_error

    package_path = getattr(pySim, "__file__", None)
    if isinstance(package_path, str) and len(package_path) > 0:
        installed_root = Path(package_path).resolve().parent
        return installed_root

    tried = ", ".join(str(path) for path in seen)
    raise RuntimeError(
        "pySim imported but has no resolvable file location. "
        f"On-disk candidates checked: {tried}."
    )


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


_PLACEHOLDER_SCAN_RE = re.compile(
    r"\{#?([A-Za-z][A-Za-z0-9_]*)\}|\[#?([A-Za-z][A-Za-z0-9_]*)\]"
)


def _hex_text_has_placeholder(hex_text: str) -> bool:
    if isinstance(hex_text, str) is False:
        return False
    if _PLACEHOLDER_SCAN_RE.search(hex_text) is None:
        return False
    return True


def dejsonify_saip_value(
    value: Any,
    ctx: TokenExpansionContext | None = None,
    path: tuple[str, ...] = (),
    *,
    placeholder_paths: set[str] | None = None,
) -> Any:
    """Restore pySim-friendly values from JSON-loaded structures."""
    if isinstance(value, dict):
        structural = _structural_data_keys(value)
        if set(structural) == {_TAG_BYTES}:
            hex_text = str(_value_first(value, _TAG_BYTES, _LEGACY_TAG_BYTES))
            if placeholder_paths is not None and _hex_text_has_placeholder(hex_text):
                placeholder_paths.add(_format_codec_path(path))
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
                    out_items.append(
                        dejsonify_saip_value(
                            item,
                            ctx,
                            item_path,
                            placeholder_paths=placeholder_paths,
                        )
                    )
                except Exception as error:
                    _raise_codec_error(error, item_path)
            return tuple(out_items)

        if set(structural) == {_TAG_PLACEHOLDER}:
            if placeholder_paths is not None:
                placeholder_paths.add(_format_codec_path(path))
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
                ordered[key_text] = dejsonify_saip_value(
                    item,
                    ctx,
                    child_path,
                    placeholder_paths=placeholder_paths,
                )
            except Exception as error:
                _raise_codec_error(error, child_path)
        return ordered

    if isinstance(value, list):
        out: list[Any] = []
        for index, item in enumerate(value):
            item_path = path + (f"[{index}]",)
            try:
                out.append(
                    dejsonify_saip_value(
                        item,
                        ctx,
                        item_path,
                        placeholder_paths=placeholder_paths,
                    )
                )
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


def dejsonify_document(
    document: dict[str, Any],
    *,
    tolerate_undefined_placeholders: bool = False,
    placeholder_paths: set[str] | None = None,
) -> dict[str, Any]:
    """Restore a document from json.loads output.

    When ``tolerate_undefined_placeholders=True`` the context accepts
    undefined ``{NAME}`` / ``[NAME]`` tokens (resolved to zero bytes)
    instead of raising. This is intended for non-encoding passes such
    as the lint harness and template authoring flows.

    When ``placeholder_paths`` is a mutable set, it is populated with
    the dotted paths (e.g. ``sections.header.iccid``) of every hex field
    that embedded at least one placeholder token. Callers can use these
    paths to scope follow-up validation.
    """

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
        ctx = TokenExpansionContext(
            defs_raw,
            str(style_raw),
            tolerate_undefined=tolerate_undefined_placeholders,
        )
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
                placeholder_paths=placeholder_paths,
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
    r"\{#?[A-Za-z][A-Za-z0-9_]*\}|\[#?[A-Za-z][A-Za-z0-9_]*\]",
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


def parse_editor_json_template_aware(
    text: str,
) -> tuple[dict[str, Any], frozenset[str], frozenset[str]]:
    """Parse an editor buffer while tolerating undefined placeholders.

    Returns a three-tuple ``(document, placeholder_paths, undefined_tokens)``:

    * ``document`` — the restored decoded document with undefined placeholders
      expanded to zero bytes. The document is still usable for structural
      validation (lint) but should not be re-encoded to DER.
    * ``placeholder_paths`` — dotted paths (e.g. ``sections.header.iccid``) of
      every hex field that embedded at least one ``{NAME}`` / ``[NAME]`` token.
    * ``undefined_tokens`` — names that had no entry in
      ``__ygg_token_defs__``.
    """

    stripped = str(text or "").strip()
    if len(stripped) == 0:
        raise ValueError("JSON buffer is empty.")

    loaded = json.loads(stripped)
    if isinstance(loaded, dict) is False:
        raise ValueError("Root JSON value must be an object.")

    sections = loaded.get("sections", {})
    if isinstance(sections, dict) is False:
        raise SaipCodecValueError("Document 'sections' must be an object.", ("sections",))

    defs_raw = loaded.get(_META_TOKEN_DEFS, {})
    if isinstance(defs_raw, dict) is False:
        raise SaipCodecValueError(
            f"{_META_TOKEN_DEFS} must be an object.",
            (_META_TOKEN_DEFS,),
        )
    style_raw = loaded.get(_META_PLACEHOLDER_STYLE, "brace")
    try:
        ctx = TokenExpansionContext(defs_raw, str(style_raw), tolerate_undefined=True)
    except Exception as error:
        _raise_codec_error(error, (_META_PLACEHOLDER_STYLE,))

    placeholder_paths: set[str] = set()
    intro = loaded.get("intro", [])
    if isinstance(intro, list) is False:
        intro = [str(intro)]

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
                placeholder_paths=placeholder_paths,
            )
        except Exception as error:
            _raise_codec_error(error, section_path)

    if _META_TOKEN_DEFS in loaded:
        restored[_META_TOKEN_DEFS] = dict(defs_raw)
    if _META_PLACEHOLDER_STYLE in loaded:
        restored[_META_PLACEHOLDER_STYLE] = loaded[_META_PLACEHOLDER_STYLE]

    normalized_paths: set[str] = set()
    for raw_path in placeholder_paths:
        text = str(raw_path or "")
        if text.startswith("sections."):
            text = text[len("sections."):]
        normalized_paths.add(text)

    return (
        restored,
        frozenset(normalized_paths),
        frozenset(ctx.undefined_tokens),
    )


def build_decoded_document_from_sequence(pes: Any, intro_lines: list[str] | None = None) -> dict[str, Any]:
    """Mirror SaipToolBridge.build_decoded_dump_document section keys (all_pe mode)."""
    counts: dict[str, int] = {}

    def unique_key(base_key: str) -> str:
        """Return a de-duplicated key string for the JSON serialisation of a tagged tuple."""
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
