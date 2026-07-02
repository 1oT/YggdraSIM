# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP Workbench actions.

Each action dispatcher lazy-imports the heavyweight SAIP stack
(``pySim.esim.saip``, ``Tools.ProfilePackage.*``) so a GUI operator can
see the other subsystems' catalogues even when the SAIP extras are not
installed.

The module exposes two complementary surfaces:

Session-scoped browsing — mirrors ``SCP03`` session conventions:

* ``saip.open_package`` takes a filesystem path, decodes the package,
  and stashes the resulting ``ProfileElementSequence`` in the shared
  :class:`~yggdrasim_common.gui_server.sessions.SessionManager` with
  ``kind="saip"``. The GUI receives an opaque ``session_id`` it can hand
  back to the follow-up actions.
* ``saip.list_pes`` / ``saip.show_pe`` / ``saip.list_files`` /
  ``saip.show_file`` / ``saip.validate`` each take that ``session_id``
  and operate purely in memory. No APDUs, no network round-trips.
* ``saip.close_package`` drops the session (ActionContext-free).

Stateless one-shots — for operators who just want to run a quick lint
or transcode against a path without cycling a session:

* ``saip.lint_path`` — lint a DER / JSON package in one call.
* ``saip.decode_to_json`` — DER → decoded JSON in one call.

The session-scoped surface does not mutate the package. Package
transcoding / editing remains the domain of the standalone
``Tools.ProfilePackage`` TUIs.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import tempfile
from collections import OrderedDict
from pathlib import Path
from typing import Any

from yggdrasim_common.gui_server.actions.registry import (
    ActionContext,
    ActionField,
    ActionSpec,
    get_registry,
)

_LOGGER = logging.getLogger("yggdrasim.gui.actions.saip")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _workspace_root() -> Path:
    """Locate the repo root (first ancestor containing ``pyproject.toml``)."""
    here = Path(__file__).resolve()
    for candidate in [here] + list(here.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return here.parents[-1]


def _ensure_pysim_importable() -> None:
    """Delegate to the SAIP tool helper so we honour the same lookup order.

    Also applies a one-shot compatibility patch against upstream pySim
    so unknown PE types do not crash ``ProfileElementSequence.from_der``
    — see :func:`_patch_pysim_profile_element` for the details.
    """
    from Tools.ProfilePackage.saip_json_codec import (
        ensure_workspace_pysim_on_path,
    )

    ensure_workspace_pysim_on_path(_workspace_root())
    _patch_pysim_profile_element()


_PYSIM_PROFILE_ELEMENT_PATCHED = False


def _patch_pysim_profile_element() -> None:
    """Work around a pySim ``ProfileElement.from_der`` ordering bug.

    For PE types not registered in ``ProfileElement.class_for_petype``,
    upstream pySim executes::

        inst = ProfileElement(decoded, pe_sequence=pe_sequence)
        inst.type = pe_type

    However ``ProfileElement.__init__`` dereferences ``self.header_name``
    (which in turn reads ``self.type``) whenever ``decoded`` is falsy —
    which happens for PEs whose ASN.1 body decodes to an empty dict.
    ``self.type`` is only assigned on the NEXT line, so ``__init__``
    raises ``AttributeError: 'ProfileElement' object has no attribute
    'type'`` and the whole package load aborts.

    This patch swaps in an ``__init__`` that treats the missing ``type``
    attribute as "caller will set it" — identical to how registered
    subclasses behave (they carry ``type`` as a class attribute). All
    other behaviour is preserved byte-for-byte.
    """
    global _PYSIM_PROFILE_ELEMENT_PATCHED
    if _PYSIM_PROFILE_ELEMENT_PATCHED:
        return

    try:
        from collections import OrderedDict
        from pySim.esim.saip import ProfileElement
    except Exception:  # noqa: BLE001 — pySim not importable; nothing to patch
        return

    if getattr(ProfileElement.__init__, "_yggdrasim_patched", False):
        _PYSIM_PROFILE_ELEMENT_PATCHED = True
        return

    def _patched_init(
        self,
        decoded=None,
        mandated: bool = True,
        pe_sequence=None,
    ) -> None:
        self.pe_sequence = pe_sequence
        if decoded:
            self.decoded = decoded
            return
        self.decoded = OrderedDict()
        try:
            header_key = self.header_name
        except AttributeError:
            # ``self.type`` is not set yet. ``ProfileElement.from_der``
            # assigns it immediately after the ctor returns, so the
            # header-bootstrap we skip here is redundant for the
            # from-DER code path — it only matters for from-scratch PE
            # construction, which never reaches this branch.
            return
        if header_key:
            self.decoded[header_key] = {"identification": None}
            if mandated:
                self.decoded[header_key] = {"mandated": None}

    _patched_init._yggdrasim_patched = True  # type: ignore[attr-defined]
    ProfileElement.__init__ = _patched_init  # type: ignore[assignment]
    _PYSIM_PROFILE_ELEMENT_PATCHED = True


# Suffixes that the SAIP GUI treats as ASCII hex-text rather than
# binary DER. ``.varder`` is a vendor template convention: it is still
# hex text, but may carry placeholder literals instead of concrete
# bytes.
_TEMPLATE_HEX_INPUT_SUFFIXES = {".varder"}
_HEX_INPUT_SUFFIXES = {".hex", ".txt"} | _TEMPLATE_HEX_INPUT_SUFFIXES
_ASN_VALUE_INPUT_SUFFIXES = {".asn", ".asn1"}
_SIMPLE_PLACEHOLDER_RE = re.compile(
    r"\{#?[A-Za-z][A-Za-z0-9_]*\}|\[#?[A-Za-z][A-Za-z0-9_]*\]"
)


class _HexTemplateInputError(ValueError):
    """Raised when hex text is a template that needs materialisation first."""


def _looks_like_ascii_hex(raw: bytes) -> bool:
    """Heuristic: does *raw* look like ASCII hex digits + whitespace?

    Used as a content-based fallback for files whose suffix isn't
    informative (e.g. an operator dragging in a ``profile`` file with
    no extension). A minimum-length guard prevents tiny binary
    payloads that happen to start with a hex digit from being
    misclassified.
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if len(raw) < 8:
        return False
    # Only allow the canonical hex alphabet plus whitespace separators.
    allowed_letters = b"0123456789ABCDEFabcdef"
    allowed_whitespace = b" \t\r\n"
    for byte in raw[: min(len(raw), 4096)]:
        ch = bytes([byte])
        if ch in allowed_letters:
            continue
        if ch in allowed_whitespace:
            continue
        return False
    # Make sure there is at least one hex digit in the head — an
    # all-whitespace blob is not a hex-text profile.
    return any(bytes([b]) in allowed_letters for b in raw[:64])


def _looks_like_ascii_hex_template(raw: bytes) -> bool:
    """Return True for hex text containing simple template placeholders."""
    if len(raw) < 8:
        return False
    try:
        text_payload = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    if _SIMPLE_PLACEHOLDER_RE.search(text_payload) is None:
        return False
    without_placeholders = _SIMPLE_PLACEHOLDER_RE.sub("", text_payload)
    normalized_hex = "".join(without_placeholders.split()).upper()
    if len(normalized_hex) == 0:
        return False
    for character in normalized_hex:
        if character not in "0123456789ABCDEF":
            return False
    return True


def _looks_like_asn1_value_notation(raw: bytes) -> bool:
    """Return True for ASN.1 value notation rather than encoded DER."""
    try:
        text_payload = raw[:8192].decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    head = text_payload.lstrip()
    if len(head) == 0:
        return False
    if "::=" not in head[:4096]:
        return False
    if "ProfileElement" in head[:4096]:
        return True
    return False


def _raise_hex_text_payload_error(resolved_path: Path, raw_text: str) -> None:
    """Emit a context-aware error when hex text is not concrete hex."""
    from Tools.ProfilePackage.saip_hex_template import iter_inline_placeholders

    typed_matches = [match.group(0) for match in iter_inline_placeholders(raw_text)]
    if len(typed_matches) > 0:
        preview = ", ".join(sorted(set(typed_matches))[:4])
        raise _HexTemplateInputError(
            "Hex input file contains inline typed placeholders that did not "
            f"substitute cleanly ({preview}): {resolved_path}. Remove the "
            "placeholders or report the template shape as a bug."
        )

    simple_placeholder = _SIMPLE_PLACEHOLDER_RE.search(raw_text)
    if simple_placeholder is not None:
        raise _HexTemplateInputError(
            "Hex input file carries YggdraSIM-style placeholders "
            f"({simple_placeholder.group(0)}): {resolved_path}. Materialise "
            "the template with token definitions before opening it as raw hex."
        )

    raise ValueError(f"Hex input file contains non-hex characters: {resolved_path}")


def _decode_hex_text_payload_with_placeholders(
    resolved_path: Path,
    raw: bytes,
) -> tuple[bytes, list[Any]]:
    """Convert an ASCII hex-text profile to its binary DER payload.

    Mirrors the validation done by
    :meth:`Tools.ProfilePackage.saip_tool.SaipToolBridge._prepare_input_for_tool`
    so the GUI surfaces exactly the same error wording for malformed
    hex (empty / odd-length / stray non-hex characters).
    """
    try:
        text_payload = raw.decode("utf-8-sig")
    except UnicodeDecodeError as decode_err:
        raise ValueError(
            f"Hex input file is not UTF-8 decodable: {resolved_path}: {decode_err}"
        ) from decode_err

    from Tools.ProfilePackage.saip_hex_template import (
        detect_inline_placeholders,
        substitute_inline_placeholders,
    )

    placeholder_records: list[Any] = []
    working_text = text_payload
    if detect_inline_placeholders(text_payload):
        working_text, placeholder_records = substitute_inline_placeholders(text_payload)

    normalized_hex = "".join(working_text.split()).upper()
    if len(normalized_hex) == 0:
        raise ValueError(f"Hex input file is empty: {resolved_path}")
    for character in normalized_hex:
        if character not in "0123456789ABCDEF":
            _raise_hex_text_payload_error(resolved_path, text_payload)
    if len(normalized_hex) % 2 != 0:
        raise ValueError(f"Hex input file has odd-length payload: {resolved_path}")
    return bytes.fromhex(normalized_hex), placeholder_records


def _decode_hex_text_payload(resolved_path: Path, raw: bytes) -> bytes:
    """Convert an ASCII hex-text profile to concrete DER bytes."""
    payload, _placeholder_records = _decode_hex_text_payload_with_placeholders(
        resolved_path,
        raw,
    )
    return payload


def _sniff_encoding(raw: bytes) -> str:
    """Return ``"der"``, ``"json"``, ``"hex"`` or ``"asn"``.

    JSON wins on a leading ``{`` / ``[``; otherwise we look for ASCII
    hex content (including template text) and ASN.1 value notation. The
    final fall-through is ``"der"`` so already-binary payloads keep their
    fast path.
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    head = raw.lstrip()
    if len(head) == 0:
        return "der"
    first = head[0:1]
    if first in (b"{", b"["):
        return "json"
    if _looks_like_asn1_value_notation(raw):
        return "asn"
    if _looks_like_ascii_hex(raw):
        return "hex"
    if _looks_like_ascii_hex_template(raw):
        return "hex"
    return "der"


def _load_asn1_value_package(resolved_path: Path) -> dict[str, Any]:
    """Load SAIP ASN.1 value notation as a decoded PE sequence."""
    from Tools.ProfilePackage.saip_asn1_value import parse_asn1_value_profile

    try:
        text_payload = resolved_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as decode_err:
        raise ValueError(
            f"ASN.1 value-notation file is not UTF-8 decodable: "
            f"{resolved_path}: {decode_err}"
        ) from decode_err
    parsed = parse_asn1_value_profile(
        text_payload,
        workspace_root=_workspace_root(),
    )
    return {
        "pes": parsed.pes,
        "decoded_document": _build_decoded_document(parsed.pes, resolved_path),
        "encoding": "asn",
        "warnings": [],
        "inline_placeholder_records": parsed.inline_placeholder_records,
    }


def _load_package_from_path(resolved_path: Path) -> dict[str, Any]:
    """Return ``{"pes", "decoded_document", "encoding", "warnings"}`` for a package.

    Supports four input flavours, matching what the SAIP TUI accepts
    (``Tools/ProfilePackage/saip_open_picker_tui.py``):

    1. **Binary DER** — passed straight to ``ProfileElementSequence.from_der``.
    2. **ASCII hex text** (``.hex`` / ``.txt`` or content-sniffed) — the
       bytes are interpreted as UTF-8, whitespace is stripped, and the
       resulting hex is decoded with ``bytes.fromhex`` before being fed
       to the DER parser. Matches
       :meth:`SaipToolBridge._prepare_input_for_tool`.
    3. **ASN.1 value notation** (``.asn`` / ``.asn1``) — parsed into
       decoded PE values, then encoded and decoded through pySim so
       defaults and post-decode hooks match DER imports.
    4. **Decoded JSON** (transcode output) — round-tripped through
       :func:`build_profile_sequence_from_document`.

    DER parsing itself uses a two-stage strategy:

    1. Fast path — call ``ProfileElementSequence.from_der`` which parses
       every PE strictly. This is what's used for well-formed packages
       and is byte-for-byte compatible with pySim's native behaviour.
    2. Tolerant fallback — if the strict parse raises (e.g. asn1tools
       ``MissingDataError`` deep inside one PE), walk the BER-TLV
       segments ourselves and decode each one independently, skipping
       broken PEs while collecting per-segment diagnostics. This lets
       the operator open a partially-damaged package and see exactly
       which PE(s) caused the error instead of hitting an opaque
       ASN.1 exception with no file context.

    If the tolerant walker also recovers zero PEs we raise a
    :class:`ValueError` that embeds the file name, size, the head byte
    dump, the offset + hex of the first failing segment, and a hint
    describing what the operator may have handed us (wrapped response,
    JSON-misnamed-as-DER, etc.).
    """
    _ensure_pysim_importable()

    from pySim.esim.saip import ProfileElementSequence
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
        parse_editor_json_template_aware,
    )

    raw_disk = resolved_path.read_bytes()
    suffix = resolved_path.suffix.lower()
    warnings: list[dict[str, Any]] = []
    inline_placeholder_records: list[Any] = []

    # Suffix wins over content sniffing — operators occasionally save
    # genuine DER under a ``.txt`` extension; we still want to honour
    # that legacy hint by trying hex first and falling back to DER if
    # the generic hex decode fails. Template-specific failures stay
    # explicit so we do not bury token/materialisation guidance under
    # the tolerant DER parser's BER-TLV diagnostics. Extension-less
    # inputs use the heuristic.
    if suffix in _ASN_VALUE_INPUT_SUFFIXES:
        return _load_asn1_value_package(resolved_path)
    if suffix in _HEX_INPUT_SUFFIXES:
        try:
            raw, inline_placeholder_records = (
                _decode_hex_text_payload_with_placeholders(resolved_path, raw_disk)
            )
            encoding = "hex"
        except _HexTemplateInputError:
            raise
        except ValueError:
            if suffix in _TEMPLATE_HEX_INPUT_SUFFIXES:
                raise
            # Hex decode failed — treat the original bytes as DER and
            # let the strict / tolerant pipeline below report what's
            # actually wrong instead of swallowing a clue.
            raw = raw_disk
            encoding = _sniff_encoding(raw_disk)
            if encoding == "hex":
                encoding = "der"
    else:
        encoding = _sniff_encoding(raw_disk)
        if encoding == "asn":
            return _load_asn1_value_package(resolved_path)
        if encoding == "hex":
            raw, inline_placeholder_records = (
                _decode_hex_text_payload_with_placeholders(resolved_path, raw_disk)
            )
        else:
            raw = raw_disk

    if encoding == "json":
        decoded_document, _placeholders, _undefined = parse_editor_json_template_aware(
            raw.decode("utf-8", errors="replace"),
        )
        pes = build_profile_sequence_from_document(
            decoded_document, workspace_root=_workspace_root()
        )
    else:
        try:
            pes = ProfileElementSequence.from_der(raw)
        except Exception as strict_err:  # noqa: BLE001 — any asn1tools/pySim error
            pes, warnings, first_fail = _parse_pes_tolerant(raw)
            if len(pes.pe_list) == 0:
                raise _make_saip_load_error(
                    resolved_path, raw, strict_err, first_fail
                ) from strict_err
        decoded_document = _build_decoded_document(pes, resolved_path)

    return {
        "pes": pes,
        "decoded_document": decoded_document,
        "encoding": encoding,
        "warnings": warnings,
        "inline_placeholder_records": inline_placeholder_records,
    }


def _parse_pes_tolerant(
    raw: bytes,
) -> tuple[Any, list[dict[str, Any]], dict[str, Any] | None]:
    """Walk the BER-TLV segments of *raw* one at a time, tolerating errors.

    Returns ``(pes, warnings, first_fail)`` where:

    * ``pes`` is a fresh :class:`ProfileElementSequence` populated only
      with the PEs we could decode. Post-processing (``_process_pelist``)
      is attempted so downstream accessors work, but any exception from
      that is suppressed — the tolerant path must always return a
      sequence object.
    * ``warnings`` is one dict per failed segment with ``index``,
      ``offset``, ``segment_len``, ``head_hex`` and ``error`` keys.
    * ``first_fail`` mirrors the first entry in ``warnings`` (or a
      TLV-chop failure if the outer walker itself ran out of bytes),
      so :func:`_make_saip_load_error` can quote a single failure.
    """
    from pySim.esim.saip import (
        ProfileElement,
        ProfileElementSequence,
        bertlv_first_segment,
    )

    pes = ProfileElementSequence()
    warnings: list[dict[str, Any]] = []
    first_fail: dict[str, Any] | None = None
    remainder = raw
    offset = 0
    index = 0

    while len(remainder) > 0:
        try:
            first_tlv, next_remainder = bertlv_first_segment(remainder)
        except Exception as err:  # noqa: BLE001 — any asn1tools error
            first_fail = {
                "stage": "tlv_chop",
                "index": index,
                "offset": offset,
                "remaining": len(remainder),
                "head_hex": remainder[:16].hex(" ").upper(),
                "error": f"{type(err).__name__}: {err}",
            }
            break

        segment_len = len(first_tlv)
        if segment_len == 0:
            # Degenerate empty segment — avoid an infinite loop and note
            # the anomaly for the operator.
            entry = {
                "stage": "tlv_chop",
                "index": index,
                "offset": offset,
                "segment_len": 0,
                "head_hex": remainder[:16].hex(" ").upper(),
                "error": "empty TLV segment — aborting tolerant walk",
            }
            warnings.append(entry)
            if first_fail is None:
                first_fail = dict(entry)
            break

        try:
            pe = ProfileElement.from_der(first_tlv, pe_sequence=pes)
            pes.pe_list.append(pe)
        except Exception as err:  # noqa: BLE001 — any asn1tools/pySim error
            entry = {
                "stage": "pe_decode",
                "index": index,
                "offset": offset,
                "segment_len": segment_len,
                "head_hex": first_tlv[:16].hex(" ").upper(),
                "error": f"{type(err).__name__}: {err}",
            }
            warnings.append(entry)
            if first_fail is None:
                first_fail = dict(entry)

        remainder = next_remainder
        offset += segment_len
        index += 1

    try:
        pes._process_pelist()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — best effort
        pass

    return pes, warnings, first_fail


def _make_saip_load_error(
    path: Path,
    raw: bytes,
    original_err: Exception,
    first_fail: dict[str, Any] | None,
) -> ValueError:
    """Build a descriptive :class:`ValueError` when both parse paths fail.

    The message embeds enough forensic detail that the operator can
    tell at a glance whether the file is malformed, wrapped in some
    other container, or simply not a SAIP profile at all. The original
    exception is preserved via ``raise … from`` at the call site.
    """
    head_hex = raw[:16].hex(" ").upper() if raw else "(empty)"
    size = len(raw)
    lines = [
        f"Failed to parse SAIP package '{path.name}' ({size} bytes).",
        f"Head bytes: {head_hex}",
    ]
    if first_fail is not None:
        lines.append(
            "First failure at PE index "
            f"{first_fail.get('index')} (byte offset "
            f"{first_fail.get('offset')}, stage={first_fail.get('stage')}): "
            f"{first_fail.get('error')}"
        )
        if first_fail.get("head_hex"):
            lines.append(f"Failing segment head: {first_fail['head_hex']}")
    else:
        lines.append(
            f"Root error: {type(original_err).__name__}: {original_err}"
        )

    # Guidance tailored to the first byte — SAIP PEs are BER-TLV
    # class-context constructed (0xA0..0xBF) at the top level.
    first_byte = raw[0] if size > 0 else None
    if first_byte in (0x7B, 0x5B):  # '{' or '['
        lines.append(
            "Hint: the file starts with '{' or '[' but was treated as DER. "
            "If this is a decoded SAIP JSON document, rename it with a "
            "'.json' extension or pass it through saip.open_package with "
            "JSON content."
        )
    elif first_byte is not None and (first_byte & 0xE0) != 0xA0:
        # Not class-context constructed — probably not a raw SAIP PE.
        lines.append(
            f"Hint: first byte 0x{first_byte:02X} is not a class-context "
            "constructed BER-TLV tag (expected 0xA0..0xBF). The file may "
            "be a wrapped ES8+ LoadBoundProfilePackage response, an "
            "encrypted profile blob, or not a SAIP package at all. "
            "Re-export the file with 'saip encode --format der' or "
            "unwrap the outer envelope before opening."
        )
    return ValueError("\n".join(lines))


def _build_decoded_document(pes: Any, source_path: Path) -> dict[str, Any]:
    """Mirror ``SaipToolContext.build_decoded_dump_document('all_pe')``.

    Kept here inline so we don't have to instantiate the CLI tool just
    to compute a dump document for lint / diff.
    """
    counts: dict[str, int] = {}

    def _unique_key(pe_type: str) -> str:
        key_text = str(pe_type or "section").strip() or "section"
        next_seen = counts.get(key_text, 0) + 1
        counts[key_text] = next_seen
        if next_seen == 1:
            return key_text
        return f"{key_text}_{next_seen}"

    sections: dict[str, Any] = {}
    for pe in pes:
        sections[_unique_key(getattr(pe, "type", "unknown"))] = pe.decoded

    return {
        "intro": [
            f"Read {len(pes.pe_list)} PEs from '{source_path.name}'",
        ],
        "sections": sections,
    }


def _jsonify_decoded(value: Any) -> Any:
    """JSON-safe projection for PE decoded dicts.

    The underlying pySim decoder returns ``OrderedDict``, ``bytes``,
    ``tuple``, etc. We flatten bytes to hex and tuples to lists so the
    payload survives ``json.dumps`` without ``default=repr`` surprises.
    """
    from Tools.ProfilePackage.saip_json_codec import jsonify_saip_value

    try:
        return json.loads(json.dumps(jsonify_saip_value(value, path=("root",))))
    except Exception:
        # Fallback: best-effort scalar flatten (for when the SAIP path
        # isn't available or the payload isn't a decoded subtree).
        return _coerce_scalar(value)


def _coerce_scalar(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return value.hex().upper()
    if isinstance(value, dict):
        return {str(k): _coerce_scalar(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_coerce_scalar(v) for v in value]
    return value


def _pe_summary_row(pe: Any, index: int) -> dict[str, Any]:
    """One numbered row for ``saip.list_pes``."""
    pe_type = str(getattr(pe, "type", "") or "")
    label = _pe_display_label(pe)
    has_fs = _decoded_contains_fs(pe.decoded if hasattr(pe, "decoded") else None)
    has_apps = _decoded_contains_apps(pe.decoded if hasattr(pe, "decoded") else None)
    return {
        "index": index,
        "type": pe_type,
        "label": label,
        "has_fs": bool(has_fs),
        "has_apps": bool(has_apps),
    }


def _pe_display_label(pe: Any) -> str:
    """Extract a short human label for a PE (best effort)."""
    decoded = getattr(pe, "decoded", None)
    if not isinstance(decoded, dict):
        return ""
    # Many PEs keep a plain "label" string. Others carry a header with
    # a name / AID. We fall back to "" rather than guessing wrong.
    for key in ("label", "description", "profileName", "displayName"):
        val = decoded.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    header = decoded.get("header") or decoded.get("profileHeader")
    if isinstance(header, dict):
        for key in ("profileName", "iccid", "version"):
            val = header.get(key)
            if isinstance(val, (str, bytes, bytearray)):
                text = val.decode() if isinstance(val, (bytes, bytearray)) else val
                if text.strip():
                    return text.strip()
    return ""


_FS_MARKER_KEYS = frozenset(
    {
        "fileID",
        "fileDescriptor",
        "linkPath",
        "efFileSize",
        "shortEFID",
        "fillFileContent",
    }
)


def _decoded_contains_fs(value: Any) -> bool:
    """Detect FS file definitions in either decoded-tuple or wrapped JSON form."""
    if isinstance(value, dict):
        if any(k in value for k in _FS_MARKER_KEYS):
            return True
        for child in value.values():
            if _decoded_contains_fs(child):
                return True
    elif isinstance(value, (list, tuple)):
        # The transcoded JSON form encodes ASN.1 SEQUENCE OF as
        # ``("typeName", payload)`` tuples once dejsonified; treat the
        # type name as a marker too.
        if (
            len(value) == 2
            and isinstance(value[0], str)
            and value[0] in _FS_MARKER_KEYS
        ):
            return True
        for child in value:
            if _decoded_contains_fs(child):
                return True
    return False


def _decoded_contains_apps(value: Any) -> bool:
    if isinstance(value, dict):
        for key in value.keys():
            key_text = str(key)
            if "pplication" in key_text or "aid" in key_text.lower():
                return True
        for child in value.values():
            if _decoded_contains_apps(child):
                return True
    elif isinstance(value, (list, tuple)):
        for child in value:
            if _decoded_contains_apps(child):
                return True
    return False


# ---------------------------------------------------------------------
# SA-G4: GlobalPlatform privilege / lifecycle decoders for the
# Applications tab.
#
# Privilege bits per GP Card Specification 2.3 Table 6-1 (3 bytes,
# big-endian, MSB first within each byte). Bit names track the
# specification verbatim so cross-referencing GP audits is friction-free.
# ---------------------------------------------------------------------

_GP_PRIVILEGE_BITS: tuple[tuple[int, int, str], ...] = (
    (0, 0x80, "Security Domain"),
    (0, 0x40, "DAP Verification"),
    (0, 0x20, "Delegated Management"),
    (0, 0x10, "Card Lock"),
    (0, 0x08, "Card Terminate"),
    (0, 0x04, "Card Reset"),
    (0, 0x02, "CVM Management"),
    (0, 0x01, "Mandated DAP Verification"),
    (1, 0x80, "Trusted Path"),
    (1, 0x40, "Authorized Management"),
    (1, 0x20, "Token Verification"),
    (1, 0x10, "Global Delete"),
    (1, 0x08, "Global Lock"),
    (1, 0x04, "Global Registry"),
    (1, 0x02, "Final Application"),
    (1, 0x01, "Global Service"),
    (2, 0x80, "Receipt Generation"),
    (2, 0x40, "Ciphered Load File Data Block"),
    (2, 0x20, "Contactless Activation"),
    (2, 0x10, "Contactless Self-Activation"),
)


def _decode_gp_privileges(hex_value: str) -> dict[str, Any]:
    """Decode the 1-3 byte ``applicationPrivileges`` field into named flags.

    Returns ``{"hex": ..., "names": [...], "byte_count": N}``. Empty / non-hex
    inputs yield an empty ``names`` list so callers can render a clean
    "(no privileges set)" hint without special-casing the missing value.
    """
    clean = "".join(ch for ch in str(hex_value or "").lower() if ch in "0123456789abcdef")
    if len(clean) == 0 or (len(clean) % 2) != 0:
        return {"hex": clean.upper(), "names": [], "byte_count": 0}
    raw = bytes.fromhex(clean)
    names: list[str] = []
    for byte_idx, mask, label in _GP_PRIVILEGE_BITS:
        if byte_idx < len(raw) and (raw[byte_idx] & mask) != 0:
            names.append(label)
    return {"hex": clean.upper(), "names": names, "byte_count": len(raw)}


# Lifecycle state codings differ between SDs and applications per
# GP 2.3 §11.1.1; we surface both tables and let the caller pick the
# right one based on the parent PE type.

_GP_LIFECYCLE_SD: dict[int, str] = {
    0x01: "INSTALLED",
    0x07: "SELECTABLE",
    0x0F: "PERSONALIZED",
    0x83: "LOCKED",
    0xFF: "TERMINATED",
}

_GP_LIFECYCLE_APP: dict[int, str] = {
    0x03: "INSTALLED",
    0x07: "SELECTABLE",
    0x0F: "PERSONALIZED",
    0x83: "LOCKED",
    0xFF: "TERMINATED",
}

# PE-type comparisons are case-folded so callers can pass whatever
# casing pySim happens to emit (``securityDomain`` / ``securitydomain``
# / ``MNO-SD``). The frozensets store the lowercase canonical form so
# the membership check stays a single hash lookup.

_SD_PE_TYPES: frozenset[str] = frozenset(
    {
        "securitydomain",
        "mnosd",
        "mno-sd",
        "ssd",
        "isdr",
        "isdp",
    }
)


def _decode_gp_lifecycle(hex_value: str, pe_type: str) -> dict[str, str]:
    """Map a 1-byte lifecycle state to its GP label."""
    clean = "".join(ch for ch in str(hex_value or "").lower() if ch in "0123456789abcdef")
    if len(clean) == 0:
        return {"hex": "", "label": "—", "category": ""}
    try:
        value = int(clean[:2], 16)
    except ValueError:
        return {"hex": clean.upper(), "label": "(unparsed)", "category": ""}
    is_sd = str(pe_type or "").lower() in _SD_PE_TYPES
    table = _GP_LIFECYCLE_SD if is_sd else _GP_LIFECYCLE_APP
    return {
        "hex": clean.upper(),
        "label": table.get(value, "(unknown)"),
        "category": "sd" if is_sd else "app",
    }


_APP_PE_TYPES: frozenset[str] = frozenset(
    {
        "securitydomain",
        "mnosd",
        "mno-sd",
        "ssd",
        "isdr",
        "isdp",
        "application",
        "rfm",
        "ram",
    }
)


_APP_FRIENDLY_TYPES: dict[str, str] = {
    "securitydomain": "Security Domain",
    "mnosd": "MNO Security Domain",
    "mno-sd": "MNO Security Domain",
    "ssd": "Supplementary SD",
    "isdr": "ISD-R",
    "isdp": "ISD-P",
    "application": "Application",
    "rfm": "Remote File Mgmt",
    "ram": "Remote App Mgmt",
}


def _hex_value(value: Any) -> str:
    """Pull a hex string out of pySim's ``{"hex": ..., "label": ...}`` envelope.

    Plain strings pass through; bytes are hex-encoded; ``None`` returns
    an empty string. Anything else we don't recognise is stringified
    via :func:`str` so the caller still has *something* to display.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        hex_text = value.get("hex")
        if isinstance(hex_text, str):
            return hex_text
        legacy_hex_text = value.get("__ygg_saip_bytes__")
        if isinstance(legacy_hex_text, str):
            return legacy_hex_text
        raw_text = value.get("raw")
        if isinstance(raw_text, str):
            return raw_text
        raw_hex_text = value.get("rawHex")
        if isinstance(raw_hex_text, str):
            return raw_hex_text
        protocol_parameter_data = value.get("protocolParameterData")
        if protocol_parameter_data is not None:
            return _hex_value(protocol_parameter_data)
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return ""


_APP_PARAMETER_LABELS: dict[str, str] = {
    "volatileMemoryQuotaC7": "Volatile memory quota (C7)",
    "nonVolatileMemoryQuotaC8": "Non-volatile memory quota (C8)",
    "globalServiceParameters": "Global Service Parameters",
    "implicitSelectionParameter": "Implicit Selection Parameter",
    "volatileReservedMemory": "Volatile reserved memory",
    "nonVolatileReservedMemory": "Non-volatile reserved memory",
    "uiccToolkitApplicationSpecificParametersField": (
        "UICC Toolkit App. Specific Parameters (80)"
    ),
    "uiccAccessApplicationSpecificParametersField": (
        "UICC Access App. Specific Parameters (81)"
    ),
    "uiccAdministrativeAccessApplicationSpecificParametersField": (
        "UICC Administrative Access App. Specific Parameters (82)"
    ),
    "simFileAccessAndToolkitAppSpecificParametersField": (
        "SIM File Access and Toolkit App. Specific Parameters"
    ),
    "ts102226SIMFileAccessToolkitParameter": (
        "SIM File Access and Toolkit App. Specific Parameters (CA)"
    ),
    "additionalContactlessParameters": "Additional Contactless Parameters (B0)",
    "ts102226AdditionalContactlessParameters": (
        "Additional Contactless Parameters (B0)"
    ),
    "contactlessProtocolParameters": "Contactless protocol parameters",
    "userInteractionContactlessParameters": "User interaction parameters",
    "cumulativeGrantedVolatileMemory": "Cumulative granted volatile memory",
    "cumulativeGrantedNonVolatileMemory": (
        "Cumulative granted non-volatile memory"
    ),
}

_SD_MEMORY_PARAMETER_FIELDS: tuple[str, ...] = (
    "volatileMemoryQuotaC7",
    "nonVolatileMemoryQuotaC8",
    "volatileReservedMemory",
    "nonVolatileReservedMemory",
    "cumulativeGrantedVolatileMemory",
    "cumulativeGrantedNonVolatileMemory",
)


def _clean_hex_text(value: Any) -> str:
    text = _hex_value(value)
    return "".join(ch for ch in str(text or "").upper() if ch in "0123456789ABCDEF")


def _bytes_from_hex_value(value: Any) -> bytes | None:
    clean = _clean_hex_text(value)
    if len(clean) == 0 or (len(clean) % 2) != 0:
        return None
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return None


def _normalise_tar_value(value: Any) -> str:
    clean = _clean_hex_text(value)
    if len(clean) == 0:
        return ""
    return clean


def _tar_values_from_any(value: Any) -> list[str]:
    values: list[str] = []

    def append(candidate: Any) -> None:
        tar = _normalise_tar_value(candidate)
        if tar and tar not in values:
            values.append(tar)

    if isinstance(value, list):
        for item in value:
            for tar in _tar_values_from_any(item):
                append(tar)
        return values
    if isinstance(value, dict):
        for key in ("tar", "hex", "raw", "rawHex", "__ygg_saip_bytes__"):
            if key in value:
                append(value.get(key))
        decoded = value.get("decoded")
        if isinstance(decoded, list):
            for item in decoded:
                for tar in _tar_values_from_any(item):
                    append(tar)
        elif isinstance(decoded, dict):
            for tar in _tar_values_from_decoded_toolkit(decoded):
                append(tar)
        return values
    append(value)
    return values


def _tar_values_from_decoded_toolkit(decoded: Any) -> list[str]:
    if not isinstance(decoded, dict):
        return []
    values: list[str] = []
    raw_values = decoded.get("tarValues")
    if isinstance(raw_values, list):
        for item in raw_values:
            tar = _normalise_tar_value(item)
            if tar != "":
                values.append(tar)
    inferred = _normalise_tar_value(decoded.get("tarInferred"))
    if inferred != "" and inferred not in values:
        values.append(inferred)
    field_map = decoded.get("fieldMap")
    if isinstance(field_map, list):
        for field in field_map:
            if not isinstance(field, dict):
                continue
            if str(field.get("name") or "") != "tarValues":
                continue
            raw = _normalise_tar_value(field.get("raw"))
            if raw == "" or (len(raw) % 6) != 0:
                continue
            for index in range(0, len(raw), 6):
                tar = raw[index : index + 6]
                if tar not in values:
                    values.append(tar)
    return values


def _decode_sd_c9_summary(value: Any) -> dict[str, Any] | None:
    raw = _clean_hex_text(value)
    raw_bytes = _bytes_from_hex_value(value)
    if raw == "" or raw_bytes is None:
        return None
    summary: dict[str, Any] = {
        "raw": raw,
    }
    try:
        from Tools.ProfilePackage.saip_asn1_decode import _decode_sd_install_parameters

        decoded = _decode_sd_install_parameters(raw_bytes)
        summary["decoded"] = _jsonify_decoded(decoded)
        items = decoded.get("items") if isinstance(decoded, dict) else None
        if isinstance(items, list):
            summary["items"] = _jsonify_decoded(items)
    except Exception:
        pass
    return summary


def _decode_toolkit_parameter_summary(
    key: str,
    value: Any,
) -> dict[str, Any] | None:
    raw = _clean_hex_text(value)
    raw_bytes = _bytes_from_hex_value(value)
    if raw == "" or raw_bytes is None:
        return None
    summary: dict[str, Any] = {
        "key": key,
        "label": _APP_PARAMETER_LABELS.get(key, key),
        "raw": raw,
    }
    decoded: Any = None
    if key == "uiccToolkitApplicationSpecificParametersField":
        try:
            from Tools.ProfilePackage.saip_asn1_decode import (
                _decode_uicc_toolkit_parameters,
            )

            decoded = _decode_uicc_toolkit_parameters(raw_bytes)
        except Exception:
            decoded = None
    elif key == "uiccAccessApplicationSpecificParametersField":
        try:
            from Tools.ProfilePackage.saip_asn1_decode import (
                _decode_uicc_access_application_specific_parameters,
            )

            decoded = _decode_uicc_access_application_specific_parameters(
                raw_bytes,
                administrative=False,
            )
        except Exception:
            decoded = None
    elif key == "uiccAdministrativeAccessApplicationSpecificParametersField":
        try:
            from Tools.ProfilePackage.saip_asn1_decode import (
                _decode_uicc_access_application_specific_parameters,
            )

            decoded = _decode_uicc_access_application_specific_parameters(
                raw_bytes,
                administrative=True,
            )
        except Exception:
            decoded = None
    elif key == "ts102226SIMFileAccessToolkitParameter":
        try:
            from Tools.ProfilePackage.saip_asn1_decode import (
                _decode_ts102226_sim_file_access_toolkit_parameter,
            )

            decoded = _decode_ts102226_sim_file_access_toolkit_parameter(raw_bytes)
        except Exception:
            decoded = None
    elif key == "ts102226AdditionalContactlessParameters":
        try:
            from Tools.ProfilePackage.saip_asn1_decode import (
                _decode_contactless_protocol_parameters,
            )

            decoded = _decode_contactless_protocol_parameters(raw_bytes)
        except Exception:
            decoded = None
    elif key in (
        "globalServiceParameters",
        "implicitSelectionParameter",
        "contactlessProtocolParameters",
        "userInteractionContactlessParameters",
        *_SD_MEMORY_PARAMETER_FIELDS,
    ):
        try:
            from Tools.ProfilePackage.saip_asn1_decode import _decode_special_field

            decoded = _decode_special_field(key, raw_bytes)
        except Exception:
            decoded = None
    elif isinstance(value, dict) and isinstance(value.get("decoded"), dict):
        decoded = value.get("decoded")

    if decoded is not None:
        summary["decoded"] = _jsonify_decoded(decoded)
        tar_values = _tar_values_from_decoded_toolkit(decoded)
        if tar_values:
            summary["tar_values"] = tar_values
    return summary


def _application_parameter_summary(decoded: Any) -> dict[str, Any] | None:
    if not isinstance(decoded, dict):
        return None

    instances: list[tuple[int | None, dict[str, Any]]] = []
    instance = decoded.get("instance")
    if isinstance(instance, dict):
        instances.append((None, instance))
    instance_list = decoded.get("instanceList")
    if isinstance(instance_list, list):
        for index, item in enumerate(instance_list):
            if isinstance(item, dict):
                instances.append((index, item))
    if len(instances) == 0:
        instances.append((None, {}))

    c9: dict[str, Any] | None = None
    parameters: list[dict[str, Any]] = []
    system_parameters: list[dict[str, Any]] = []
    for instance_index, instance_payload in instances:
        if c9 is None:
            c9 = _decode_sd_c9_summary(
                instance_payload.get("applicationSpecificParametersC9")
            )
        raw_system_parameters = instance_payload.get("systemSpecificParameters")
        if isinstance(raw_system_parameters, dict):
            for key, value in raw_system_parameters.items():
                item = _decode_toolkit_parameter_summary(str(key), value)
                if item is not None:
                    if instance_index is not None:
                        item["instance_index"] = instance_index
                        item["label"] = (
                            f"Instance {instance_index} · "
                            f"{item.get('label') or item.get('key') or key}"
                        )
                    system_parameters.append(item)
        raw_parameters = instance_payload.get("applicationParameters")
        if not isinstance(raw_parameters, dict) and instance_index is None:
            raw_parameters = decoded.get("applicationParameters")
        if isinstance(raw_parameters, dict):
            for key, value in raw_parameters.items():
                item = _decode_toolkit_parameter_summary(str(key), value)
                if item is not None:
                    if instance_index is not None:
                        item["instance_index"] = instance_index
                        item["label"] = (
                            f"Instance {instance_index} · "
                            f"{item.get('label') or item.get('key') or key}"
                        )
                    parameters.append(item)

    tar_summary: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def append_tar(tar_value: Any, source: str, label: str) -> None:
        tar = _normalise_tar_value(tar_value)
        if tar == "":
            return
        dedupe_key = (tar, source)
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        tar_summary.append(
            {
                "tar": tar,
                "source": source,
                "label": label,
            }
        )

    raw_tars = decoded.get("tarList")
    for entry in _tar_values_from_any(raw_tars):
        append_tar(entry, "tarList", "RFM/RAM TAR list")

    for parameter in parameters:
        for tar_value in parameter.get("tar_values", []):
            source = f"applicationParameters.{parameter.get('key', '')}"
            label = str(parameter.get("label") or parameter.get("key") or source)
            append_tar(tar_value, source, label)

    if c9 is None and not parameters and not system_parameters and not tar_summary:
        return None
    out: dict[str, Any] = {}
    if c9 is not None:
        out["c9"] = c9
    if parameters:
        out["parameters"] = parameters
    if system_parameters:
        out["system_parameters"] = system_parameters
    if tar_summary:
        out["tar_values"] = tar_summary
    return out


def _strict_hex_text(value: Any, *, label: str) -> str:
    text = str(value or "").strip()
    text = re.sub(r"^(0[xX])", "", text)
    text = re.sub(r"[\s:_-]+", "", text).upper()
    if len(text) == 0:
        return ""
    if re.fullmatch(r"[0-9A-F]+", text) is None:
        raise ValueError(f"{label} must be hexadecimal.")
    if len(text) % 2 != 0:
        raise ValueError(f"{label} must contain an even number of hex digits.")
    return text


def _bytes_from_strict_hex(value: Any, *, label: str) -> bytes:
    return bytes.fromhex(_strict_hex_text(value, label=label))


def _state_enabled(state: dict[str, Any], key: str) -> bool:
    value = state.get(key)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return bool(value)


def _apply_optional_bytes_field(
    target: dict[str, Any],
    *,
    state: dict[str, Any],
    enabled_key: str,
    value_key: str,
    field_name: str,
    label: str,
    default_hex: str = "",
) -> bool:
    if enabled_key not in state and value_key not in state:
        return False
    if _state_enabled(state, enabled_key):
        target[field_name] = _bytes_from_strict_hex(
            state.get(value_key, default_hex),
            label=label,
        )
    else:
        target.pop(field_name, None)
    return True


def _normalise_toolkit_parameter_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        value = {}
    payload = dict(value)
    if _state_enabled(payload, "useRawHex"):
        raw_hex = _strict_hex_text(
            payload.get("rawHex", ""),
            label="uiccToolkitApplicationSpecificParametersField.rawHex",
        )
        if len(raw_hex) == 0:
            raise ValueError(
                "uiccToolkitApplicationSpecificParametersField.rawHex is required."
            )
        return {"rawHex": raw_hex}
    payload["rawHex"] = ""
    for key in (
        "accessDomain",
        "minimumSecurityLevelRaw",
        "trailingPadding",
    ):
        payload[key] = _strict_hex_text(payload.get(key, ""), label=key)
    for key, default in (
        ("priorityLevelOfToolkitAppInstance", 0),
        ("maxNumberOfTimers", 1),
        ("maxTextLengthForMenuEntry", 0),
        ("maxNumberOfChannels", 2),
    ):
        try:
            number = int(payload.get(key, default))
        except Exception as error:
            raise ValueError(f"{key} must be an integer.") from error
        if not 0 <= number <= 0xFF:
            raise ValueError(f"{key} must fit in one byte.")
        payload[key] = number

    menu_entries: list[dict[str, int]] = []
    raw_menu_entries = payload.get("menuEntries") or []
    if not isinstance(raw_menu_entries, list):
        raise ValueError("menuEntries must be a list.")
    for index, entry in enumerate(raw_menu_entries):
        if not isinstance(entry, dict):
            raise ValueError(f"menuEntries[{index}] must be an object.")
        try:
            entry_id = int(entry.get("id", 0))
            position = int(entry.get("position", 0))
        except Exception as error:
            raise ValueError(
                f"menuEntries[{index}] id and position must be integers."
            ) from error
        if not (0 <= entry_id <= 0xFF and 0 <= position <= 0xFF):
            raise ValueError(
                f"menuEntries[{index}] id and position must fit in one byte."
            )
        menu_entries.append({"id": entry_id, "position": position})
    payload["menuEntries"] = menu_entries

    tar_values: list[str] = []
    raw_tars = payload.get("tarValues") or []
    if not isinstance(raw_tars, list):
        raise ValueError("tarValues must be a list.")
    for index, tar_value in enumerate(raw_tars):
        tar = _strict_hex_text(tar_value, label=f"tarValues[{index}]")
        if len(tar) == 0:
            continue
        if len(tar) != 6:
            raise ValueError(f"tarValues[{index}] must be exactly 3 bytes.")
        tar_values.append(tar)
    payload["tarValues"] = tar_values
    return payload


def _normalise_ca_parameter_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "hex": _strict_hex_text(
                value,
                label="ts102226SIMFileAccessToolkitParameter",
            )
        }
    payload = dict(value)
    if _state_enabled(payload, "useRawHex"):
        return {
            "hex": _strict_hex_text(
                payload.get("rawHex", ""),
                label="ts102226SIMFileAccessToolkitParameter.rawHex",
            )
        }
    return {
        "simToolkitApplicationParameters": {
            "hex": _strict_hex_text(
                payload.get("simToolkitApplicationParametersHex", ""),
                label=(
                    "ts102226SIMFileAccessToolkitParameter."
                    "simToolkitApplicationParameters"
                ),
            )
        },
        "simFileAccessParameters": {
            "hex": _strict_hex_text(
                payload.get("simFileAccessParametersHex", ""),
                label=(
                    "ts102226SIMFileAccessToolkitParameter."
                    "simFileAccessParameters"
                ),
            )
        },
        "trailingBytes": _strict_hex_text(
            payload.get("trailingBytes", ""),
            label="ts102226SIMFileAccessToolkitParameter.trailingBytes",
        ),
    }


def _normalise_ber_tlv_items(value: Any, *, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} items must be a list.")
    items: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{label} items[{index}] must be an object.")
        tag = _strict_hex_text(item.get("tag", ""), label=f"{label}.items[{index}].tag")
        raw = _strict_hex_text(item.get("raw", ""), label=f"{label}.items[{index}].raw")
        if len(tag) == 0:
            raise ValueError(f"{label}.items[{index}].tag is required.")
        items.append({"tag": tag, "raw": raw})
    return items


def _normalise_contactless_parameter_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "hex": _strict_hex_text(
                value,
                label="ts102226AdditionalContactlessParameters.protocolParameterData",
            )
        }
    payload = dict(value)
    if _state_enabled(payload, "useRawHex"):
        return {
            "hex": _strict_hex_text(
                payload.get("rawHex", ""),
                label="ts102226AdditionalContactlessParameters.protocolParameterData",
            )
        }
    return {
        "items": _normalise_ber_tlv_items(
            payload.get("items") or [],
            label="ts102226AdditionalContactlessParameters.protocolParameterData",
        )
    }


def _normalise_memory_parameter_payload(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"hex": _strict_hex_text(value, label=label)}
    payload = dict(value)
    raw_hex = _strict_hex_text(
        payload.get("rawHex", payload.get("hex", "")),
        label=f"{label}.rawHex",
    )
    if raw_hex != "":
        return {"hex": raw_hex}
    decimal_raw = payload.get("decimal", 0)
    try:
        decimal = int(decimal_raw)
    except Exception as error:
        raise ValueError(f"{label}.decimal must be an integer.") from error
    return {"decimal": decimal}


def _normalise_global_service_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"hex": _strict_hex_text(value, label="globalServiceParameters")}
    payload = dict(value)
    if _state_enabled(payload, "useRawHex"):
        return {
            "hex": _strict_hex_text(
                payload.get("rawHex", ""),
                label="globalServiceParameters.rawHex",
            )
        }
    active = payload.get("activeServices") or []
    if not isinstance(active, list):
        raise ValueError("globalServiceParameters.activeServices must be a list.")
    return {"activeServices": [str(item) for item in active]}


def _normalise_implicit_selection_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"hex": _strict_hex_text(value, label="implicitSelectionParameter")}
    payload = dict(value)
    if _state_enabled(payload, "useRawHex"):
        return {
            "hex": _strict_hex_text(
                payload.get("rawHex", ""),
                label="implicitSelectionParameter.rawHex",
            )
        }
    channel_mask = payload.get("channelMask", "00")
    if isinstance(channel_mask, str):
        channel_mask_value: int | str = _strict_hex_text(
            channel_mask,
            label="implicitSelectionParameter.channelMask",
        )
        if channel_mask_value == "":
            channel_mask_value = "00"
    else:
        channel_mask_value = channel_mask
    return {
        "defaultSelected": _state_enabled(payload, "defaultSelected"),
        "channelMask": channel_mask_value,
    }


def _normalise_access_parameter_payload(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"hex": _strict_hex_text(value, label=label)}
    payload = dict(value)
    if _state_enabled(payload, "useRawHex"):
        return {
            "hex": _strict_hex_text(
                payload.get("rawHex", ""),
                label=f"{label}.rawHex",
            )
        }
    raw_records = payload.get("accessDomainRecords") or []
    if not isinstance(raw_records, list):
        raise ValueError(f"{label}.accessDomainRecords must be a list.")
    records: list[dict[str, str]] = []
    for index, record in enumerate(raw_records):
        if not isinstance(record, dict):
            raise ValueError(f"{label}.accessDomainRecords[{index}] must be an object.")
        if _state_enabled(record, "useRawHex"):
            record_hex = _strict_hex_text(
                record.get("hex", ""),
                label=f"{label}.accessDomainRecords[{index}].hex",
            )
        else:
            domain_byte = _strict_hex_text(
                record.get("domainByte", "00"),
                label=f"{label}.accessDomainRecords[{index}].domainByte",
            )
            if len(domain_byte) != 2:
                raise ValueError(
                    f"{label}.accessDomainRecords[{index}].domainByte must be one byte."
                )
            parameters = _strict_hex_text(
                record.get("parameters", ""),
                label=f"{label}.accessDomainRecords[{index}].parameters",
            )
            record_hex = domain_byte + parameters
        if len(record_hex) == 0:
            continue
        records.append({"hex": record_hex})
    return {"accessDomainRecords": records}


def _apply_sd_parameter_state_to_section(
    section: dict[str, Any],
    parameter_state: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(section, dict):
        raise ValueError("section must be an object.")
    if not isinstance(parameter_state, dict):
        raise ValueError("parameter_state must be an object.")

    instance = section.get("instance")
    if not isinstance(instance, dict):
        instance = {}
        section["instance"] = instance

    changed: list[str] = []

    if "c9_enabled" in parameter_state or "c9_hex" in parameter_state:
        if _state_enabled(parameter_state, "c9_enabled"):
            instance["applicationSpecificParametersC9"] = _bytes_from_strict_hex(
                parameter_state.get("c9_hex", ""),
                label="applicationSpecificParametersC9",
            )
            changed.append("applicationSpecificParametersC9")
        else:
            instance.pop("applicationSpecificParametersC9", None)
            changed.append("applicationSpecificParametersC9")

    system_params = instance.get("systemSpecificParameters")
    if not isinstance(system_params, dict):
        system_params = {}

    if (
        "system_global_service_enabled" in parameter_state
        or "system_global_service_hex" in parameter_state
        or "system_global_service" in parameter_state
    ):
        if _state_enabled(parameter_state, "system_global_service_enabled"):
            from Tools.ProfilePackage.saip_asn1_encode import (
                encode_global_service_parameters_field,
            )

            value = parameter_state.get("system_global_service")
            if value is None:
                value = parameter_state.get("system_global_service_hex", "")
            system_params["globalServiceParameters"] = (
                encode_global_service_parameters_field(
                    _normalise_global_service_payload(value)
                )
            )
        else:
            system_params.pop("globalServiceParameters", None)
        changed.append("systemSpecificParameters.globalServiceParameters")
    if (
        "system_implicit_selection_enabled" in parameter_state
        or "system_implicit_selection_hex" in parameter_state
        or "system_implicit_selection" in parameter_state
    ):
        if _state_enabled(parameter_state, "system_implicit_selection_enabled"):
            from Tools.ProfilePackage.saip_asn1_encode import (
                encode_implicit_selection_parameter_field,
            )

            value = parameter_state.get("system_implicit_selection")
            if value is None:
                value = parameter_state.get("system_implicit_selection_hex", "")
            system_params["implicitSelectionParameter"] = (
                encode_implicit_selection_parameter_field(
                    _normalise_implicit_selection_payload(value)
                )
            )
        else:
            system_params.pop("implicitSelectionParameter", None)
        changed.append("systemSpecificParameters.implicitSelectionParameter")

    raw_memory_params = parameter_state.get("memory_parameters")
    if isinstance(raw_memory_params, dict):
        from Tools.ProfilePackage.saip_asn1_encode import encode_decoded_roundtrip_bytes

        for field_name in _SD_MEMORY_PARAMETER_FIELDS:
            payload = raw_memory_params.get(field_name)
            if not isinstance(payload, dict):
                continue
            if _state_enabled(payload, "enabled"):
                system_params[field_name] = encode_decoded_roundtrip_bytes(
                    field_name,
                    _normalise_memory_parameter_payload(
                        payload,
                        label=field_name,
                    ),
                )
            else:
                system_params.pop(field_name, None)
            changed.append(f"systemSpecificParameters.{field_name}")

    if (
        "sim_file_access_toolkit_enabled" in parameter_state
        or "sim_file_access_toolkit_hex" in parameter_state
        or "sim_file_access_toolkit" in parameter_state
    ):
        if _state_enabled(parameter_state, "sim_file_access_toolkit_enabled"):
            from Tools.ProfilePackage.saip_asn1_encode import (
                encode_ts102226_sim_file_access_toolkit_parameter_field,
            )

            value = parameter_state.get("sim_file_access_toolkit")
            if value is None:
                value = parameter_state.get("sim_file_access_toolkit_hex", "")
            system_params["ts102226SIMFileAccessToolkitParameter"] = (
                encode_ts102226_sim_file_access_toolkit_parameter_field(
                    _normalise_ca_parameter_payload(value)
                )
            )
        else:
            system_params.pop("ts102226SIMFileAccessToolkitParameter", None)
        changed.append(
            "systemSpecificParameters.ts102226SIMFileAccessToolkitParameter"
        )
    if (
        "additional_contactless_enabled" in parameter_state
        or "additional_contactless_hex" in parameter_state
        or "additional_contactless" in parameter_state
    ):
        if _state_enabled(parameter_state, "additional_contactless_enabled"):
            from Tools.ProfilePackage.saip_asn1_encode import (
                encode_contactless_protocol_parameters_field,
            )

            value = parameter_state.get("additional_contactless")
            if value is None:
                value = parameter_state.get("additional_contactless_hex", "")
            system_params["ts102226AdditionalContactlessParameters"] = {
                "protocolParameterData": encode_contactless_protocol_parameters_field(
                    _normalise_contactless_parameter_payload(value)
                ),
            }
        else:
            system_params.pop("ts102226AdditionalContactlessParameters", None)
        changed.append(
            "systemSpecificParameters.ts102226AdditionalContactlessParameters"
        )

    if (
        "contactless_protocol_enabled" in parameter_state
        or "contactless_protocol_hex" in parameter_state
        or "contactless_protocol" in parameter_state
    ):
        if _state_enabled(parameter_state, "contactless_protocol_enabled"):
            from Tools.ProfilePackage.saip_asn1_encode import (
                encode_contactless_protocol_parameters_field,
            )

            value = parameter_state.get("contactless_protocol")
            if value is None:
                value = parameter_state.get("contactless_protocol_hex", "")
            system_params["contactlessProtocolParameters"] = (
                encode_contactless_protocol_parameters_field(
                    _normalise_contactless_parameter_payload(value)
                )
            )
        else:
            system_params.pop("contactlessProtocolParameters", None)
        changed.append("systemSpecificParameters.contactlessProtocolParameters")

    if (
        "user_interaction_contactless_enabled" in parameter_state
        or "user_interaction_contactless_hex" in parameter_state
        or "user_interaction_contactless" in parameter_state
    ):
        if _state_enabled(parameter_state, "user_interaction_contactless_enabled"):
            from Tools.ProfilePackage.saip_asn1_encode import (
                encode_user_interaction_contactless_parameters_field,
            )

            value = parameter_state.get("user_interaction_contactless")
            if value is None:
                value = parameter_state.get("user_interaction_contactless_hex", "")
            system_params["userInteractionContactlessParameters"] = (
                encode_user_interaction_contactless_parameters_field(
                    _normalise_contactless_parameter_payload(value)
                )
            )
        else:
            system_params.pop("userInteractionContactlessParameters", None)
        changed.append("systemSpecificParameters.userInteractionContactlessParameters")

    if len(system_params) > 0:
        instance["systemSpecificParameters"] = system_params
    else:
        instance.pop("systemSpecificParameters", None)

    app_params = instance.get("applicationParameters")
    if not isinstance(app_params, dict):
        app_params = {}

    if (
        "uicc_toolkit_enabled" in parameter_state
        or "uicc_toolkit" in parameter_state
    ):
        if _state_enabled(parameter_state, "uicc_toolkit_enabled"):
            from Tools.ProfilePackage.saip_asn1_encode import (
                encode_uicc_toolkit_parameters,
            )

            payload = _normalise_toolkit_parameter_payload(
                parameter_state.get("uicc_toolkit") or {}
            )
            app_params["uiccToolkitApplicationSpecificParametersField"] = (
                encode_uicc_toolkit_parameters(payload)
            )
        else:
            app_params.pop("uiccToolkitApplicationSpecificParametersField", None)
        changed.append("applicationParameters.uiccToolkitApplicationSpecificParametersField")

    if (
        "uicc_access_enabled" in parameter_state
        or "uicc_access_hex" in parameter_state
        or "uicc_access" in parameter_state
    ):
        if _state_enabled(parameter_state, "uicc_access_enabled"):
            from Tools.ProfilePackage.saip_asn1_encode import (
                encode_uicc_access_application_specific_parameters_field,
            )

            value = parameter_state.get("uicc_access")
            if value is None:
                value = parameter_state.get("uicc_access_hex", "0100")
            app_params["uiccAccessApplicationSpecificParametersField"] = (
                encode_uicc_access_application_specific_parameters_field(
                    _normalise_access_parameter_payload(
                        value,
                        label="uiccAccessApplicationSpecificParametersField",
                    )
                )
            )
        else:
            app_params.pop("uiccAccessApplicationSpecificParametersField", None)
        changed.append("applicationParameters.uiccAccessApplicationSpecificParametersField")
    if (
        "uicc_admin_enabled" in parameter_state
        or "uicc_admin_hex" in parameter_state
        or "uicc_admin" in parameter_state
    ):
        if _state_enabled(parameter_state, "uicc_admin_enabled"):
            from Tools.ProfilePackage.saip_asn1_encode import (
                encode_uicc_administrative_access_application_specific_parameters_field,
            )

            value = parameter_state.get("uicc_admin")
            if value is None:
                value = parameter_state.get("uicc_admin_hex", "0100")
            app_params["uiccAdministrativeAccessApplicationSpecificParametersField"] = (
                encode_uicc_administrative_access_application_specific_parameters_field(
                    _normalise_access_parameter_payload(
                        value,
                        label="uiccAdministrativeAccessApplicationSpecificParametersField",
                    )
                )
            )
        else:
            app_params.pop(
                "uiccAdministrativeAccessApplicationSpecificParametersField",
                None,
            )
        changed.append(
            "applicationParameters.uiccAdministrativeAccessApplicationSpecificParametersField"
        )

    if len(app_params) > 0:
        instance["applicationParameters"] = app_params
    else:
        instance.pop("applicationParameters", None)

    if "process_data" in parameter_state:
        raw_entries = parameter_state.get("process_data") or []
        if not isinstance(raw_entries, list):
            raise ValueError("process_data must be a list.")
        process_data = [
            _bytes_from_strict_hex(entry, label=f"processData[{index}]")
            for index, entry in enumerate(raw_entries)
            if _strict_hex_text(entry, label=f"processData[{index}]") != ""
        ]
        if len(process_data) > 0:
            instance["processData"] = process_data
        else:
            instance.pop("processData", None)
        changed.append("processData")

    return {
        "changed": changed,
        "summary": _application_parameter_summary(section),
    }


def _file_definitions(decoded_document: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a list of FS entries extracted from the decoded document.

    Tries the linter's flat-dict extractor first (works on certain
    canonicalised templates) and falls back to a tuple-aware walk that
    matches the runtime decoded shape produced by pySim — the form most
    SAIP packages carry once round-tripped through ``ProfileElementSequence``.
    """
    from Tools.ProfilePackage.lint_engine import SaipProfileLinter

    linter = SaipProfileLinter(strict=False)
    section_items = list(
        (key, value)
        for key, value in (decoded_document.get("sections") or {}).items()
    )
    defs = linter._extract_file_definitions(section_items)  # noqa: SLF001
    rows: list[dict[str, Any]] = []
    for item in defs:
        rows.append(
            {
                "section_key": item.section_key,
                "field_path": item.field_path,
                "file_id": item.file_id or "",
                "short_efid": item.short_efid or "",
                "descriptor": item.file_descriptor or "",
                "ef_size": item.ef_file_size or "",
                "link_path": item.link_path or "",
                "security_attrs": item.security_attributes_referenced or "",
                "max_size": item.maximum_file_size or "",
                "details": item.file_details or "",
            }
        )
    if len(rows) > 0:
        return rows

    # Fallback: tuple-form decoded SAIP. Each section is a dict whose
    # entries with keys starting "ef-", "df-", "adf-", "mf" carry a list
    # of CHOICE tuples. We surface one row per file entry.
    for section_key, payload in section_items:
        if isinstance(payload, dict) is False:
            continue
        for key, value in payload.items():
            key_text = str(key)
            if not (
                key_text.startswith("ef-")
                or key_text.startswith("df-")
                or key_text.startswith("adf")
                or key_text in ("mf", "telecom", "usim")
            ):
                continue
            row = _summarise_file_choices(value)
            if row is None:
                continue
            row["section_key"] = section_key
            row["field_path"] = key_text
            rows.append(row)
    return rows


def _summarise_file_choices(value: Any) -> dict[str, Any] | None:
    """Reduce a list-of-CHOICE-tuples payload to a flat row dict.

    Returns ``None`` if no recognised file marker is present.
    """
    if isinstance(value, (list, tuple)) is False:
        return None

    summary: dict[str, str] = {
        "file_id": "",
        "short_efid": "",
        "descriptor": "",
        "ef_size": "",
        "link_path": "",
        "security_attrs": "",
        "max_size": "",
        "details": "",
        # SAIP createFCP / fileDescriptor → proprietaryEFInfo block
        # (TCA SAIP §createFCP, TCA Profile Package PEDocumentation
        # ProprietaryEFInfo). Five known sub-fields:
        #   specialFileInformation – 1 B; high-update + readable-when-
        #       deactivated flags (TS 102 222 Table 5).
        #   fileDetails            – 1 B; BER-TLV DER-only flag
        #       (TCA SAIP TCA 3.1+).
        #   fillPattern            – pattern bytes used once across the
        #       file body (ETSI TS 102 222 §6.3.2.2.x).
        #   repeatPattern          – pattern bytes repeated until the
        #       file is filled.
        #   maximumFileSize        – BER-TLV upper bound (TCA 3.1+);
        #       distinct from the top-level ``maximumFileSize`` slot.
        "proprietary_special_info": "",
        "proprietary_details": "",
        "proprietary_fill_pattern": "",
        "proprietary_repeat_pattern": "",
        "proprietary_max_size": "",
    }
    saw_marker = False
    for item in value:
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        choice_name, choice_payload = item
        choice_text = str(choice_name)
        if choice_text in {
            "fileDescriptor",
            "fillFileContent",
            "fillFilePattern",
            "fillFileOffset",
            "doNotCreate",
        }:
            saw_marker = True
        if isinstance(choice_payload, dict) is False:
            continue
        for sub_key, sub_value in choice_payload.items():
            sub_key_text = str(sub_key)
            hex_val = _coerce_hex_field(sub_value)
            if sub_key_text == "fileDescriptor":
                if hex_val:
                    summary["descriptor"] = hex_val
                saw_marker = True
                continue
            if sub_key_text == "shortEFID":
                if hex_val:
                    summary["short_efid"] = hex_val
                saw_marker = True
                continue
            if sub_key_text == "efFileSize":
                if hex_val:
                    summary["ef_size"] = hex_val
                saw_marker = True
                continue
            if sub_key_text == "linkPath":
                if hex_val:
                    summary["link_path"] = hex_val
                saw_marker = True
                continue
            if sub_key_text == "securityAttributesReferenced":
                if hex_val:
                    summary["security_attrs"] = hex_val
                continue
            if sub_key_text == "maximumFileSize":
                if hex_val:
                    summary["max_size"] = hex_val
                continue
            if sub_key_text == "fileDetails":
                if hex_val:
                    summary["details"] = hex_val
                continue
            if sub_key_text == "fileID":
                if hex_val:
                    summary["file_id"] = hex_val
                saw_marker = True
                continue
            if sub_key_text == "proprietaryEFInfo":
                # Walk one level into the nested dict and pull the
                # known proprietary sub-fields. PEDocumentation
                # ProprietaryEFInfo enumerates five leaves; we expose
                # all five so the FCP editor can address each
                # individually.
                if isinstance(sub_value, dict):
                    for inner_key, inner_value in sub_value.items():
                        inner_hex = _coerce_hex_field(inner_value)
                        if not inner_hex:
                            continue
                        inner_text = str(inner_key)
                        if inner_text == "specialFileInformation":
                            summary["proprietary_special_info"] = inner_hex
                        elif inner_text == "fileDetails":
                            summary["proprietary_details"] = inner_hex
                        elif inner_text == "fillPattern":
                            summary["proprietary_fill_pattern"] = inner_hex
                        elif inner_text == "repeatPattern":
                            summary["proprietary_repeat_pattern"] = inner_hex
                        elif inner_text == "maximumFileSize":
                            summary["proprietary_max_size"] = inner_hex
                continue
    if saw_marker is False:
        return None
    return summary


def _coerce_hex_field(value: Any) -> str:
    """Best-effort hex extractor for transcoded {"hex": "...", ...} envelopes."""
    if isinstance(value, dict):
        hex_val = value.get("hex")
        if isinstance(hex_val, str):
            return hex_val.upper()
    if isinstance(value, (bytes, bytearray)):
        return value.hex().upper()
    if isinstance(value, str):
        return value
    return ""


# ----------------------------------------------------------------------
# Unified filesystem-tree extraction
#
# The classic ``_file_definitions`` returns a flat list keyed by
# ``(section_key, field_path)`` where field_path is the linter walk's
# dotted address. That walker does NOT descend into ASN.1 CHOICE tuples
# of the form ``("createFCP", {...})``, so every file created by a
# ``pe-genericFileManagement`` PE is invisible. The helpers below
# replace that for ``saip.list_files`` / ``saip.show_file``: they
# replay GFM ``filePath`` SELECTs, walk the per-section pe_name → DF
# cursor stack, and emit rows enriched with the resolved hex FID chain
# (``3F00/7F10/6F3A``), the file kind (``mf``/``df``/``adf``/
# ``ef-trans``/``ef-lf``/``ef-cyclic``/``ef-bertlv``), the canonical
# ``FOO.BAR`` friendly name from pySim's template registry, and the
# row's source (``template`` vs ``gfm``).
# ----------------------------------------------------------------------


_FS_TREE_TEMPLATE_INDEX_CACHE: dict[str, Any] = {}


def _saip_pe_name_template_index() -> dict[str, list[tuple[Any, Any]]]:
    """Return ``pe_name -> [(template_cls, FileTemplate), ...]`` index.

    pe_names repeat across templates (every base profile defines
    ``ef-arr``), so the value is a list. Callers that know the
    section's templateID resolve directly against that template.
    """
    cached = _FS_TREE_TEMPLATE_INDEX_CACHE.get("pe_name_index")
    if cached is not None:
        return cached
    index: dict[str, list[tuple[Any, Any]]] = {}
    try:
        _ensure_pysim_importable()
        from pySim.esim.saip.templates import ProfileTemplateRegistry
    except Exception:
        _FS_TREE_TEMPLATE_INDEX_CACHE["pe_name_index"] = index
        return index
    for _oid, tpl_cls in ProfileTemplateRegistry.by_oid.items():
        files_by_pename = getattr(tpl_cls, "files_by_pename", None)
        if not isinstance(files_by_pename, dict):
            continue
        for pe_name, ft in files_by_pename.items():
            index.setdefault(str(pe_name), []).append((tpl_cls, ft))
    _FS_TREE_TEMPLATE_INDEX_CACHE["pe_name_index"] = index
    return index


def _saip_template_for_section_payload(
    section_payload: Any,
) -> Any:
    """Return the ProfileTemplate backing a section, or ``None``."""
    if isinstance(section_payload, dict) is False:
        return None
    template_oid = section_payload.get("templateID")
    if template_oid is None:
        return None
    try:
        _ensure_pysim_importable()
        from pySim.esim.saip.templates import ProfileTemplateRegistry
        return ProfileTemplateRegistry.get_by_oid(str(template_oid))
    except Exception:
        return None


_FS_TREE_FILE_TYPE_TO_KIND: dict[str, str] = {
    "MF": "mf",
    "DF": "df",
    "ADF": "adf",
    "TR": "ef-trans",
    "LF": "ef-lf",
    "CY": "ef-cyclic",
    "BT": "ef-bertlv",
}


def _kind_from_descriptor(
    desc_hex: str,
    *,
    fid_hex: str = "",
    pename: str = "",
    has_df_name: bool = False,
) -> str:
    """Best-effort file-kind from FileDescriptor byte 1.

    ETSI TS 102 221 §11.1.1.4.3 defines the FDB. Bit positions:
    - b6 b5 b4 = 111 (mask 0x38): DF / ADF (FDB does not distinguish
      between the two — caller hints disambiguate)
    - b1 b2 b3 = 001 / 010 / 110: transparent / linear-fixed / cyclic
    - b4 set together with structure: BER-TLV

    ADF disambiguation rules (any one suffices):
    - ``pename`` starts with ``adf-`` (pySim template aliases use
      ``adf-usim`` / ``adf-isim`` / ``adf-csim`` / ``adf-v2x`` etc.)
    - ``fid_hex`` lies in the reserved 7FF0-7FFF range (TS 102 221
      §13.1 reserves this band for application root files).
    - ``has_df_name`` indicates the FCP carried a DF Name (tag 84)
      AID — only ADFs carry one.
    """
    if not desc_hex or len(desc_hex) < 2:
        return ""
    try:
        byte0 = int(desc_hex[:2], 16)
    except ValueError:
        return ""
    if (byte0 & 0x38) == 0x38:
        if _is_adf_hint(fid_hex=fid_hex, pename=pename, has_df_name=has_df_name):
            return "adf"
        return "df"
    if (byte0 & 0x39) == 0x39:
        return "ef-bertlv"
    structure = byte0 & 0x07
    if structure == 0x01:
        return "ef-trans"
    if structure == 0x02:
        return "ef-lf"
    if structure == 0x06:
        return "ef-cyclic"
    return "ef"


def _is_adf_hint(
    *,
    fid_hex: str = "",
    pename: str = "",
    has_df_name: bool = False,
) -> bool:
    """Return ``True`` when the caller can prove the container is an ADF."""
    if has_df_name is True:
        return True
    pename_lower = str(pename or "").strip().lower()
    if pename_lower.startswith("adf-"):
        return True
    fid_clean = str(fid_hex or "").strip().upper()
    if len(fid_clean) >= 4:
        try:
            fid_int = int(fid_clean[:4], 16)
        except ValueError:
            return False
        # TS 102 221 §13.1: 7FF0..7FFF reserved for application FIDs.
        if 0x7FF0 <= fid_int <= 0x7FFF:
            return True
    return False


def _fid_int_to_hex(fid: Any) -> str:
    if fid is None:
        return ""
    try:
        return f"{int(fid) & 0xFFFF:04X}"
    except (TypeError, ValueError):
        return ""


def _choice_list_field_hex(choice_list: Any, *names: str) -> str:
    """Extract a hex-encoded scalar from a list of ``(tag, payload)`` tuples."""
    if isinstance(choice_list, list) is False:
        return ""
    for item in choice_list:
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        tag, payload = item
        if tag != "fileDescriptor" or isinstance(payload, dict) is False:
            continue
        for name in names:
            if name in payload:
                hexed = _coerce_hex_field(payload.get(name))
                if hexed:
                    return hexed
    return ""


def _choice_list_has_file_content(choice_list: Any) -> bool:
    """Return ``True`` when a file tuple list carries explicit content."""
    if isinstance(choice_list, list) is False:
        return False
    for item in choice_list:
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        tag, payload = item
        if tag not in {"fillFileContent", "fillFileContents"}:
            continue
        if isinstance(payload, (bytes, bytearray)) and len(payload) > 0:
            return True
        if isinstance(payload, str) and len(payload.strip()) > 0:
            return True
        if payload is not None:
            return True
    return False


def _template_default_value_wire(value: Any) -> tuple[Any, str]:
    """Project a pySim template default value into a compact JSON shape."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex().upper(), "hex"
    if isinstance(value, int) and isinstance(value, bool) is False:
        return int(value), "number"
    if isinstance(value, str):
        return value, "text"
    return str(value), "text"


def _minimal_unsigned_hex(value: int) -> str:
    """Return minimal whole-octet uppercase hex for SAIP integer fields."""
    if value <= 0:
        return ""
    width = max(2, ((int(value).bit_length() + 7) // 8) * 2)
    return f"{int(value):0{width}X}"


def _template_default_info(ft: Any, value: Any) -> dict[str, Any]:
    """Return operator-facing template default metadata for a file row."""
    if ft is None:
        return {}
    default_val = getattr(ft, "default_val", None)
    if default_val is None:
        return {}
    default_wire, default_kind = _template_default_value_wire(default_val)
    info: dict[str, Any] = {
        "template_default_active": True,
        "template_default_value": default_wire,
        "template_default_value_kind": default_kind,
        "template_default_repeat": bool(getattr(ft, "default_val_repeat", False)),
        "template_default_has_overrides": _choice_list_has_file_content(value),
    }
    file_size = getattr(ft, "file_size", None)
    rec_len = getattr(ft, "rec_len", None)
    nb_rec = getattr(ft, "nb_rec", None)
    if isinstance(file_size, int) and isinstance(file_size, bool) is False:
        info["template_file_size"] = int(file_size)
    if isinstance(rec_len, int) and isinstance(rec_len, bool) is False:
        info["template_record_size"] = int(rec_len)
    if isinstance(nb_rec, int) and isinstance(nb_rec, bool) is False:
        info["template_record_count"] = int(nb_rec)
    return info


def _template_fcp_info(ft: Any) -> dict[str, Any]:
    """Return FCP fields inherited from a pySim file template.

    pySim omits FCP leaves from the PE when they match the selected
    template. The GUI still needs to show those values in the File
    Control Parameters tab, so we project template attributes into the
    same flat row keys used by explicit createFCP fields and mark their
    source as ``template``.
    """
    if ft is None:
        return {}
    info: dict[str, Any] = {}
    fid_hex = _fid_int_to_hex(getattr(ft, "fid", None))
    if fid_hex:
        info["file_id"] = fid_hex
        info["file_id_source"] = "template"
    sfi_value = getattr(ft, "sfi", None)
    if isinstance(sfi_value, int) and isinstance(sfi_value, bool) is False:
        info["short_efid"] = f"{int(sfi_value) & 0xFF:02X}"
        info["short_efid_source"] = "template"
    arr_value = getattr(ft, "arr", None)
    if isinstance(arr_value, int) and isinstance(arr_value, bool) is False:
        info["security_attrs"] = f"{int(arr_value) & 0xFF:02X}"
        info["security_attrs_source"] = "template"
    file_type = str(getattr(ft, "file_type", "") or "").upper()
    size_value = None
    if file_type in {"TR", "BT"}:
        file_size = getattr(ft, "file_size", None)
        if isinstance(file_size, int) and isinstance(file_size, bool) is False:
            size_value = int(file_size)
    elif file_type in {"LF", "CY"}:
        rec_len = getattr(ft, "rec_len", None)
        nb_rec = getattr(ft, "nb_rec", None)
        if (
            isinstance(rec_len, int)
            and isinstance(rec_len, bool) is False
            and isinstance(nb_rec, int)
            and isinstance(nb_rec, bool) is False
        ):
            size_value = int(rec_len) * int(nb_rec)
    if isinstance(size_value, int) and size_value > 0:
        info["ef_size"] = _minimal_unsigned_hex(size_value)
        info["ef_size_source"] = "template"
    return info


# Legacy SIM (3GPP TS 51.011 §10.2 / TS 31.102 §4.2) and TS 11.11 EFs
# that fall outside pySim's TCA SAIP §9 template tables. GFM-defined
# files routinely target these — particularly DF.TELECOM EFs that the
# pre-USIM legacy stack still relies on (EF.ADN under 7F10 vs the
# DF.PHONEBOOK EF.ADN at 5F3A/4F00..4F3F that TCA models). Without
# this table the GUI would render them as anonymous ``EF.<FID>`` rows.
_LEGACY_FID_TABLE: dict[tuple[str, str], str] = {
    # DF.TELECOM (3F00/7F10) — TS 51.011 §10.4
    ("7F10", "6F3A"): "EF.ADN",
    ("7F10", "6F3B"): "EF.FDN",
    ("7F10", "6F3C"): "EF.SMS",
    ("7F10", "6F3D"): "EF.CCP",
    ("7F10", "6F40"): "EF.MSISDN",
    ("7F10", "6F42"): "EF.SMSP",
    ("7F10", "6F43"): "EF.SMSS",
    ("7F10", "6F44"): "EF.LND",
    ("7F10", "6F47"): "EF.SMSR",
    ("7F10", "6F49"): "EF.SDN",
    ("7F10", "6F4A"): "EF.EXT1",
    ("7F10", "6F4B"): "EF.EXT2",
    ("7F10", "6F4C"): "EF.EXT3",
    ("7F10", "6F4D"): "EF.BDN",
    ("7F10", "6F4E"): "EF.EXT4",
    ("7F10", "6F4F"): "EF.ECCP",
    ("7F10", "6F53"): "EF.RMA",
    ("7F10", "6F54"): "EF.SUME",
    ("7F10", "6F58"): "EF.CMI",
    # DF.GSM-ACCESS (3F00/7F20) — TS 51.011 §10.3
    ("7F20", "6F05"): "EF.LP",
    ("7F20", "6F07"): "EF.IMSI",
    ("7F20", "6F20"): "EF.KC",
    ("7F20", "6F2C"): "EF.DCK",
    ("7F20", "6F30"): "EF.PLMNsel",
    ("7F20", "6F31"): "EF.HPLMN",
    ("7F20", "6F37"): "EF.ACMmax",
    ("7F20", "6F38"): "EF.UST",
    ("7F20", "6F39"): "EF.ACM",
    ("7F20", "6F41"): "EF.PUCT",
    ("7F20", "6F45"): "EF.CBMI",
    ("7F20", "6F46"): "EF.SPN",
    ("7F20", "6F74"): "EF.BCCH",
    ("7F20", "6F78"): "EF.ACC",
    ("7F20", "6F7B"): "EF.FPLMN",
    ("7F20", "6F7E"): "EF.LOCI",
    ("7F20", "6FAD"): "EF.AD",
    ("7F20", "6FAE"): "EF.PHASE",
}


def _saip_reverse_fid_friendly(
    fid_hex: str,
    *,
    parent_fid_hex: str = "",
) -> str:
    """Reverse-lookup a friendly ``FOO.BAR`` name from a 4-nibble hex FID.

    Resolution order:

    1. ``(parent_fid, fid)`` lookup in the legacy SIM table — needed for
       GFM-created DF.TELECOM EFs (EF.ADN at 6F3A under 7F10 etc.) that
       pySim's TCA SAIP §9 templates do not model.
    2. Parent-context-aware resolver from
       ``Tools.ProfilePackage.saip_asn1_decode.fid_name`` — disambiguates
       the cross-ADF collisions (6F40 → MSISDN vs CSIM-MDN, 6F07 → IMSI
       vs IST, 4F01 → SUCI-CALC-INFO-USIM vs 5GS3GPPLOCI vs V2X-CFG).
       The parent token is derived from the slash-joined ``parent_fid_hex``
       chain (``3F00/7FF0`` → ``adf-usim``, ``3F00/7F10`` → ``df-telecom``).
    3. pySim's template registry (preferred for USIM / ISIM / CSIM /
       opt-USIM EFs and the TCA DF.PHONEBOOK numbered EFs). With no
       parent context, the first matching template wins — the lookup
       above is what prevents the ADF.USIM / ADF.CSIM mislabel.
    """
    if not fid_hex or len(fid_hex) < 4:
        return ""
    canon_fid = fid_hex[:4].upper()
    parent_chain = str(parent_fid_hex or "").strip().upper()
    if parent_chain:
        last_segment = parent_chain.rsplit("/", 1)[-1]
        legacy = _LEGACY_FID_TABLE.get((last_segment, canon_fid))
        if legacy:
            return legacy
    try:
        from Tools.ProfilePackage.saip_asn1_decode import (
            fid_name,
            parent_token_for_container_fid,
            parent_token_from_file_path_hex,
        )
    except Exception:  # noqa: BLE001
        fid_name = None  # type: ignore[assignment]
        parent_token_for_container_fid = None  # type: ignore[assignment]
        parent_token_from_file_path_hex = None  # type: ignore[assignment]
    parent_token: str | None = None
    # If the chain root is a friendly ADF name (``ADF.USIM`` / ``ADF.ISIM``),
    # turn it into the canonical pySim parent token (``adf-usim``) so the
    # collision resolver can disambiguate 6F40 / 6F07 / 4F01 — the legacy
    # hex-only path won't recognise ``ADF.USIM`` since it has no FID.
    if parent_chain:
        head = parent_chain.split("/", 1)[0]
        if head.startswith("ADF."):
            parent_token = "adf-" + head[len("ADF."):].lower()
    if parent_token is None and parent_chain and parent_token_from_file_path_hex is not None:
        flat = parent_chain.replace("/", "")
        parent_token = parent_token_from_file_path_hex(flat)
        if parent_token is None and parent_token_for_container_fid is not None:
            tail = parent_chain.rsplit("/", 1)[-1]
            parent_token = parent_token_for_container_fid(tail)
    if parent_token == "df-graphics" and fid_name is not None:
        resolved = fid_name(canon_fid, parent_hint=parent_token)
        if resolved:
            return resolved
    # Always go through the candidate list directly so we can pick a
    # single contextual name instead of the resolver's compound
    # fallback ("EF.UST / EF.UST-SERVICE-TABLE", "DF.GSM / DF.EAP").
    # The compound output is informative for a debugger but bad for an
    # operator-facing tree label — it implies the same row is two
    # files at once when in reality it's either one EF with two
    # registry aliases, or one EF that the bench can't disambiguate
    # given the chain context.
    try:
        from Tools.ProfilePackage.saip_asn1_decode import fid_candidates
    except Exception:  # noqa: BLE001
        fid_candidates = None  # type: ignore[assignment]
    if fid_candidates is not None:
        candidates = list(fid_candidates(canon_fid))
        if candidates:
            picked = _pick_single_friendly_name(
                candidates,
                parent_token=parent_token,
                parent_chain=parent_chain,
            )
            if picked:
                return picked
    if fid_name is not None:
        resolved = fid_name(canon_fid, parent_hint=parent_token)
        if resolved:
            return resolved
    try:
        fid_int = int(canon_fid, 16)
    except ValueError:
        return ""
    index = _saip_pe_name_template_index()
    for _name, candidates in index.items():
        for _tpl_cls, ft in candidates:
            if getattr(ft, "fid", None) == fid_int:
                return getattr(ft, "name", "") or ""
    return ""


def _pick_single_friendly_name(
    candidates: list[tuple[str | None, str]],
    *,
    parent_token: str | None,
    parent_chain: str,
) -> str:
    """Reduce a candidate ``[(parent_token, label), ...]`` list to one label.

    Selection ladder, in order of confidence:

    1. **Parent-token match** — pick candidates whose registered parent
       equals the row's resolved parent token (``adf-usim`` /
       ``df-telecom`` / ``mf`` …). When multiple candidates match
       (e.g. EF.UST + EF.UST-SERVICE-TABLE both at adf-usim/6F38),
       the first registered alias wins. Aliases are added in
       canonical 3GPP-spec order in the FID name registry, so the
       first-wins policy hits the spec spelling reliably without
       a hand-curated preference table.
    2. **MF-anchored container fallback** — when the row is at MF
       level (parent_chain == ``3F00``) and no candidate carries a
       parent token (top-level container aliases like ``DF.GSM`` /
       ``DF.EAP`` at ``7F20``), again the first registered name
       wins. The legacy GSM ``DF.GSM`` is registered before the
       newer ``DF.EAP`` repurposing, matching the canonical
       TS 51.011 §10.4 assignment.
    3. **First-candidate fallback** — for orphaned rows whose
       location does not match any registered parent (typically a
       malformed GFM that creates a USIM EF directly under MF),
       pick the first registered candidate so the row stays
       readable.
    """
    if len(candidates) == 0:
        return ""

    if parent_token is not None:
        parent_matches = [
            label for parent, label in candidates if parent == parent_token
        ]
        if parent_matches:
            return parent_matches[0]

    if parent_chain == "3F00":
        no_parent = [label for parent, label in candidates if parent is None]
        if no_parent:
            return no_parent[0]

    return candidates[0][1]


def _walk_choice_paths(payload: Any, base_path: str = "") -> list[tuple[str, Any]]:
    """Walk dict / list / 2-tuple payloads, unwrapping ASN.1 CHOICE tuples.

    Tuples of the form ``(name: str, value)`` are treated as CHOICE
    entries; the tag is appended with ``.<name>`` rather than indexed.
    Mirrors :py:meth:`SaipProfileLinter._walk_with_choice_paths` so the
    GUI side can address GFM ``createFCP`` payloads buried inside
    ``sections.genericFileManagement.fileManagementCMD[i][j]``.
    """
    rows: list[tuple[str, Any]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_part = str(key)
            full_path = key_part if base_path == "" else f"{base_path}.{key_part}"
            rows.append((full_path, value))
            nested = _walk_choice_paths(value, full_path)
            if nested:
                rows.extend(nested)
        return rows
    if (
        isinstance(payload, tuple)
        and len(payload) == 2
        and isinstance(payload[0], str)
    ):
        name = str(payload[0])
        value = payload[1]
        full_path = name if base_path == "" else f"{base_path}.{name}"
        rows.append((full_path, value))
        nested = _walk_choice_paths(value, full_path)
        if nested:
            rows.extend(nested)
        return rows
    if isinstance(payload, (list, tuple)):
        for idx, value in enumerate(payload):
            full_path = f"{base_path}[{idx}]"
            rows.append((full_path, value))
            nested = _walk_choice_paths(value, full_path)
            if nested:
                rows.extend(nested)
        return rows
    return rows


def _build_adf_temp_fid_map(
    decoded_document: dict[str, Any],
) -> dict[str, str]:
    """Build the ``{temp_fid_hex: 'ADF.<NAME>'}`` lookup the walkers need.

    SAIP encodes each ADF (USIM, ISIM, CSIM, …) inside its own PE
    section keyed ``adf-<name>``. The ADF carries a temporary FID
    in the ``7FF0`` … ``7FFF`` range (TS 102 221 §13.1) that GFM
    SELECT bytecode uses to navigate into the application. Both the
    template walker (which sees the ``adf-usim`` payload directly)
    and the GFM walker (which only sees raw SELECT path bytes) need
    to translate that ``7FFx`` token back to the ADF's friendly name
    so the GUI can present ADFs as their own roots — never under MF.
    """
    mapping: dict[str, str] = {}
    sections = decoded_document.get("sections") or {}
    if isinstance(sections, dict) is False:
        return mapping
    for section_key, payload in sections.items():
        if isinstance(payload, dict) is False:
            continue
        adf_pename = ""
        for key in payload.keys():
            if str(key).lower().startswith("adf-"):
                adf_pename = str(key)
                break
        if not adf_pename:
            continue
        adf_value = payload.get(adf_pename)
        if isinstance(adf_value, list) is False:
            continue
        local_fid = _choice_list_field_hex(adf_value, "fileID")
        if not local_fid:
            continue
        # Friendly name comes from the pe_name (``adf-usim`` →
        # ``ADF.USIM``). Falls back to the raw pe_name if the ADF
        # uses a non-standard label.
        suffix = adf_pename[len("adf-"):].upper()
        friendly = f"ADF.{suffix}" if suffix else adf_pename.upper()
        mapping[local_fid.upper()] = friendly
    return mapping


def _reanchor_chain_under_adf(
    chain: list[str],
    adf_map: dict[str, str],
) -> list[str]:
    """Replace any ``[3F00, 7FFx, ...]`` prefix with ``[ADF.<NAME>, ...]``.

    Used by the GFM walker so SELECT paths that traverse an ADF's
    temporary FID end up rooted under the ADF's friendly name in the
    operator-facing tree, instead of dangling beneath MF.
    """
    if len(adf_map) == 0 or len(chain) < 2:
        return chain
    if str(chain[0]).upper() != "3F00":
        return chain
    candidate = str(chain[1]).upper()
    target = adf_map.get(candidate)
    if target is None:
        return chain
    return [target] + list(chain[2:])


def _filesystem_tree_rows(
    decoded_document: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return one row per file in the package, enriched with FS context.

    Every row carries the legacy ``_file_definitions`` fields plus:
    - ``parent_path`` — slash-joined hex FID chain of the containing DF
    - ``fid_chain``  — same incl. the file's own FID
    - ``kind``       — ``mf`` / ``df`` / ``adf`` / ``ef-trans`` /
                       ``ef-lf`` / ``ef-cyclic`` / ``ef-bertlv``
    - ``friendly_name`` — canonical ``EF.IMSI`` / ``DF.PHONEBOOK`` etc.
    - ``source``     — ``template`` or ``gfm``

    MF and every ADF are emitted as **separate roots** (parent_path
    empty). This matches the operator's mental model of the smart
    card: an ADF is its own application tree, not a folder under MF.
    """
    rows: list[dict[str, Any]] = []
    sections = decoded_document.get("sections") or {}
    if isinstance(sections, dict) is False:
        return rows
    adf_map = _build_adf_temp_fid_map(decoded_document)
    for section_key, payload in sections.items():
        sk_lower = str(section_key).lower()
        if sk_lower.startswith("genericfilemanagement"):
            rows.extend(_emit_gfm_filesystem_rows(str(section_key), payload, adf_map))
            continue
        if isinstance(payload, dict) is False:
            continue
        rows.extend(_emit_template_filesystem_rows(str(section_key), payload))
    return rows


def _template_parent_chain_fids(
    ft: Any,
    *,
    extended_root_chain: list[str] | None = None,
) -> list[str]:
    """Return the chain segments from the root down to ``ft`` (inclusive).

    Uses the pySim ``FileTemplate.parent`` link populated by
    ``ProfileTemplate.__init_subclass__`` (see
    ``pySim/esim/saip/templates.py`` lines 167–187). This is the
    authoritative nesting for files that belong to a known template —
    it correctly distinguishes "DF.PHONEBOOK is a child of DF.TELECOM"
    from "DF.PHONEBOOK is a sibling of DF.TELECOM under MF" without
    relying on payload insertion order.

    Root resolution rules:
    - If the topmost ancestor is an MF or DF template, the chain is
      anchored at ``3F00`` (prepended when the topmost FID is not
      already MF — handles DF.TELECOM templates whose root is the
      DF itself).
    - If the topmost ancestor is an ADF (file_type=='ADF'), the
      chain is anchored at the ADF's friendly name (``ADF.USIM``
      etc.) — never under MF. This matches the on-card model where
      ADFs are independent application roots, not folders inside
      MF; the GUI tree builder shows them as siblings of MF.
    - If the topmost ancestor has no MF/DF/ADF root (orphan file
      from an ``optional`` ProfileTemplate that ``extends`` another
      template, e.g. ``FilesUsimOptional`` extending
      ``FilesUsimMandatory``), the caller may pass
      ``extended_root_chain`` so the chain anchors under the parent
      template's base DF (``ADF.USIM`` for opt-usim, ``ADF.ISIM``
      for opt-isim, …) instead of the implicit MF.

    A chain of length zero is returned for files whose template
    carries no FID and no resolvable root (rare).
    """
    nodes: list[Any] = []
    current = ft
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        nodes.append(current)
        current = getattr(current, "parent", None)
    if len(nodes) == 0:
        return []
    nodes.reverse()
    root = nodes[0]
    root_type = str(getattr(root, "file_type", "") or "").upper()

    if root_type == "ADF":
        adf_label = str(getattr(root, "name", "") or "").strip() or "ADF"
        chain: list[str] = [adf_label]
        for node in nodes[1:]:
            fid_hex = _fid_int_to_hex(getattr(node, "fid", None))
            if fid_hex:
                chain.append(fid_hex)
        return chain

    if extended_root_chain and root_type != "MF":
        chain = list(extended_root_chain)
        for node in nodes:
            fid_hex = _fid_int_to_hex(getattr(node, "fid", None))
            if fid_hex:
                chain.append(fid_hex)
        return chain

    chain = []
    for node in nodes:
        fid_hex = _fid_int_to_hex(getattr(node, "fid", None))
        if fid_hex:
            chain.append(fid_hex)
    if len(chain) > 0 and chain[0].upper() != "3F00":
        chain = ["3F00"] + chain
    return chain


def _emit_template_filesystem_rows(
    section_key: str,
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    """Walk a template-shaped section, resolving nesting via pySim.

    For each file in the section payload we look up its ``FileTemplate``
    in ``template.files_by_pename`` and follow ``ft.parent`` to the
    root, building the hex FID chain. This matches pySim's own tree
    construction (``ProfileTemplate.__init_subclass__``) and stays
    correct regardless of the order pySim emits sibling DFs in the
    decoded dict — important because deeply-nested templates (TELECOM
    with DF.PHONEBOOK / DF.GRAPHICS / DF.MMSS, USIM with DF.PHONEBOOK +
    DF.5GS) used to mis-anchor child DFs as siblings under MF.

    A position-based cursor is kept as a fallback for files whose
    ``pe_name`` does not appear in the template (e.g. profile vendor
    extensions, or the section is missing a ``templateID``). The
    fallback prepends ``3F00`` so the row is still addressable.
    """
    template = _saip_template_for_section_payload(payload)
    files_by_pename: dict[str, Any] = {}
    if template is not None:
        files_by_pename = getattr(template, "files_by_pename", None) or {}

    # Optional templates (FilesUsimOptional, FilesIsimOptional, …) carry
    # ``extends = <mandatory template>`` and their first file is a plain
    # EF (not MF/DF/ADF). The pySim parent walk on those EFs terminates
    # at the EF itself with parent=None, which would otherwise leave us
    # anchoring under the implicit MF. Resolve the extended template's
    # base DF here once and feed it into every chain walk.
    extended_root_chain: list[str] = []
    if template is not None:
        anchor = getattr(template, "extends", None)
        if anchor is None:
            anchor = getattr(template, "parent", None)
        if anchor is not None:
            try:
                base_df_ft = anchor.base_df()
                extended_root_chain = _template_parent_chain_fids(base_df_ft)
            except Exception:
                extended_root_chain = []

    rows: list[dict[str, Any]] = []
    cursor_stack: list[tuple[str, str]] = [("mf", "3F00")]
    if extended_root_chain:
        cursor_stack = [("__extends__", seg) for seg in extended_root_chain]
    cursor_initialised_from_template = bool(extended_root_chain)
    last_container_pename = ""
    for key, value in payload.items():
        key_text = str(key)
        if key_text.endswith("-header") or key_text == "templateID":
            continue
        if isinstance(value, list) is False:
            continue
        ft = files_by_pename.get(key_text)
        local_fid = _choice_list_field_hex(value, "fileID")
        local_desc = _choice_list_field_hex(value, "fileDescriptor")
        local_dfname = _choice_list_field_hex(value, "dfName")
        is_container = (
            key_text == "mf"
            or key_text.startswith("df-")
            or key_text.startswith("adf-")
        )
        is_adf_container = key_text.startswith("adf-")
        template_chain = (
            _template_parent_chain_fids(
                ft, extended_root_chain=extended_root_chain or None
            )
            if ft is not None
            else []
        )
        if is_container is True and is_adf_container is True:
            # ADF roots are siblings of MF, never folders inside it.
            # Anchor the chain at the ADF's friendly name regardless
            # of any ``7FFx`` temp_fid carried in the section payload
            # (the temp_fid only matters to GFM SELECT bytecode).
            if template_chain:
                adf_label = template_chain[0]
            else:
                suffix = key_text[len("adf-"):].upper()
                adf_label = f"ADF.{suffix}" if suffix else key_text.upper()
            fid_chain = adf_label
            parent_path = ""
            cursor_stack = [(key_text, adf_label)]
            cursor_initialised_from_template = True
            last_container_pename = key_text
            kind_str = "adf"
            friendly = (
                getattr(ft, "name", "") if ft is not None else ""
            ) or adf_label
            rows.append(
                _make_filesystem_row(
                    section_key=section_key,
                    field_path=key_text,
                    value=value,
                    parent_path=parent_path,
                    fid_chain=fid_chain,
                    kind=kind_str,
                    friendly_name=friendly,
                    source="template",
                    template_default=_template_default_info(ft, value),
                    template_fcp=_template_fcp_info(ft),
                )
            )
            continue
        if is_container is True:
            fid_hex = local_fid or (_fid_int_to_hex(getattr(ft, "fid", None)))
            if key_text == "mf" and not fid_hex:
                fid_hex = "3F00"
            if template_chain:
                fid_chain = "/".join(template_chain)
                parent_path = "/".join(template_chain[:-1])
                cursor_stack = [
                    (key_text, seg) for seg in template_chain
                ]
                cursor_initialised_from_template = True
            else:
                if cursor_initialised_from_template is False and (
                    len(cursor_stack) <= 1 or last_container_pename == ""
                ):
                    if key_text == "mf":
                        cursor_stack = [(key_text, fid_hex)]
                    else:
                        cursor_stack = [("mf", "3F00"), (key_text, fid_hex)]
                else:
                    if len(cursor_stack) > 1:
                        cursor_stack.pop()
                    cursor_stack.append((key_text, fid_hex))
                parent_path = "/".join(item[1] for item in cursor_stack[:-1] if item[1])
                fid_chain = "/".join(item[1] for item in cursor_stack if item[1])
            last_container_pename = key_text
            kind_str = ""
            if ft is not None:
                tpl_kind = _FS_TREE_FILE_TYPE_TO_KIND.get(
                    getattr(ft, "file_type", ""), ""
                )
                if tpl_kind == "df" and _is_adf_hint(
                    fid_hex=fid_hex,
                    pename=key_text,
                    has_df_name=bool(local_dfname),
                ):
                    kind_str = "adf"
                else:
                    kind_str = tpl_kind
            if kind_str == "":
                kind_str = _kind_from_descriptor(
                    local_desc,
                    fid_hex=fid_hex,
                    pename=key_text,
                    has_df_name=bool(local_dfname),
                )
                if kind_str == "":
                    kind_str = "adf" if _is_adf_hint(
                        fid_hex=fid_hex,
                        pename=key_text,
                        has_df_name=bool(local_dfname),
                    ) else "df"
            friendly = getattr(ft, "name", "") or key_text
            rows.append(
                _make_filesystem_row(
                    section_key=section_key,
                    field_path=key_text,
                    value=value,
                    parent_path=parent_path,
                    fid_chain=fid_chain,
                    kind=kind_str,
                    friendly_name=friendly,
                    source="template",
                    template_default=_template_default_info(ft, value),
                    template_fcp=_template_fcp_info(ft),
                )
            )
            continue
        if key_text.startswith("ef-") is False:
            continue
        ef_fid = local_fid or (_fid_int_to_hex(getattr(ft, "fid", None)))
        if template_chain:
            # template_chain ends with the EF's own FID — the parent
            # is everything before it.
            parent_path = "/".join(template_chain[:-1])
            fid_chain = "/".join(template_chain)
        else:
            parent_path = "/".join(item[1] for item in cursor_stack if item[1])
            fid_chain = parent_path + "/" + ef_fid if ef_fid else parent_path
        kind_str = ""
        if ft is not None:
            kind_str = _FS_TREE_FILE_TYPE_TO_KIND.get(
                getattr(ft, "file_type", ""), ""
            )
        if kind_str == "":
            kind_str = _kind_from_descriptor(
                local_desc,
                fid_hex=ef_fid,
                pename=key_text,
            ) or "ef"
        # Parent-context-aware resolver disambiguates 6F40 (MSISDN vs
        # CSIM-MDN), 6F07 (IMSI vs IST), 4F01 (three-way collision).
        # Falls back to the template's ``name`` and then the raw pename.
        friendly = ""
        if ef_fid:
            friendly = _saip_reverse_fid_friendly(
                ef_fid,
                parent_fid_hex=parent_path,
            )
        if not friendly:
            friendly = getattr(ft, "name", "") or key_text
        rows.append(
            _make_filesystem_row(
                section_key=section_key,
                field_path=key_text,
                value=value,
                parent_path=parent_path,
                fid_chain=fid_chain,
                kind=kind_str,
                friendly_name=friendly,
                source="template",
                template_default=_template_default_info(ft, value),
                template_fcp=_template_fcp_info(ft),
            )
        )
    return rows


def _emit_gfm_filesystem_rows(
    section_key: str,
    payload: Any,
    adf_map: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Walk a genericFileManagement section, replaying ``filePath`` SELECTs.

    Each ``createFCP`` becomes a row addressable by ``field_path =
    fileManagementCMD[<i>][<j>]`` where (i, j) is the position of the
    defining CHOICE tuple. ``fillFileContent`` / ``fillFileOffset``
    tuples that follow each ``createFCP`` are stitched onto the file's
    synthetic CHOICE-tuple list so the FS detail view sees the same
    shape as a template EF.

    ``adf_map`` (``{temp_fid_hex: 'ADF.<NAME>'}``) lets the walker
    re-anchor SELECT chains that traverse an ADF's temporary FID
    (``7FF0`` … ``7FFF`` per TS 102 221 §13.1) under the ADF's
    friendly name. Without it, files placed under an ADF via GFM
    would render as siblings of MF children — visually wrong.

    SELECT cursor semantics:
    - Cursor starts at ``[0x3F00]`` (MF) at the top of every section.
    - ``filePath = b''`` resets the cursor to ``[0x3F00]``.
    - ``filePath = b'<even-length FID concat>'`` becomes
      ``[0x3F00] + path_from_gfm(bytes)`` — the path is always rooted
      at MF; ADF context (if any) is selected via the ADF's temporary
      FID inside the chain (TCA SAIP §9 / TS 102 221 §13.1: 7FF0..7FFF).
    - Odd-length ``filePath`` is malformed (pySim raises); the row is
      still emitted but kept addressable under MF so the operator can
      see the corrupt entry rather than have it disappear silently.
    - Within one transaction, a created DF / ADF becomes the implicit
      parent for following EF creates until a new ``filePath`` or
      container create appears. Some packages encode DF-local EF runs
      this way, and the GUI tree needs the resolved parent chain.
    """
    if isinstance(payload, dict) is False:
        return []
    fmc = payload.get("fileManagementCMD")
    if isinstance(fmc, list) is False:
        return []
    if adf_map is None:
        adf_map = {}
    rows: list[dict[str, Any]] = []
    select_chain: list[str] = ["3F00"]
    for i, transaction in enumerate(fmc):
        if isinstance(transaction, list) is False:
            continue
        active_index: int | None = None
        active_value: Any = None
        active_entries: list[tuple[str, Any]] = []
        transaction_container_chain: list[str] | None = None

        def flush_active() -> None:
            nonlocal active_index
            nonlocal active_value
            nonlocal active_entries
            nonlocal transaction_container_chain

            if active_index is None:
                return
            parent_chain = select_chain
            if (
                transaction_container_chain is not None
                and _gfm_create_fcp_kind(active_value) not in {"df", "adf", "mf"}
            ):
                parent_chain = transaction_container_chain
            row = _finalise_gfm_row(
                section_key=section_key,
                transaction_index=i,
                cmd_index=active_index,
                cmd_value=active_value,
                extra_entries=active_entries,
                select_chain=parent_chain,
                adf_map=adf_map,
            )
            rows.append(row)
            next_chain = _gfm_container_chain_from_row(row)
            if next_chain is not None:
                transaction_container_chain = next_chain
            active_index = None
            active_value = None
            active_entries = []

        for j, item in enumerate(transaction):
            if not (
                isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], str)
            ):
                continue
            tag, value = item
            if tag == "filePath":
                flush_active()
                transaction_container_chain = None
                raw = _coerce_hex_field(value)
                if not raw:
                    select_chain = ["3F00"]
                else:
                    if len(raw) % 4 != 0:
                        # Malformed per TS 102 222 §6 (path must be a
                        # concatenation of 16-bit FIDs). Keep the row
                        # addressable under MF and tag the synthetic
                        # segment so renderers can flag the corruption.
                        select_chain = ["3F00", "MALFORMED:" + raw.upper()]
                    else:
                        chain = ["3F00"]
                        for k in range(0, len(raw), 4):
                            chain.append(raw[k:k + 4])
                        select_chain = chain
                continue
            if tag == "createFCP":
                flush_active()
                active_index = j
                active_value = value
                active_entries = []
                continue
            if tag in ("fillFileContent", "fillFileOffset"):
                if active_index is not None:
                    active_entries.append((tag, value))
                continue
        flush_active()
    return rows


def _gfm_create_fcp_kind(cmd_value: Any) -> str:
    """Return the file kind implied by a GFM ``createFCP`` payload."""
    fcp_payload: dict[str, Any] = cmd_value if isinstance(cmd_value, dict) else {}
    return _kind_from_descriptor(
        _coerce_hex_field(fcp_payload.get("fileDescriptor")),
        fid_hex=_coerce_hex_field(fcp_payload.get("fileID")),
        has_df_name=bool(_coerce_hex_field(fcp_payload.get("dfName"))),
    )


def _gfm_container_chain_from_row(row: dict[str, Any]) -> list[str] | None:
    """Return a transaction-local parent chain for a created GFM container."""
    if str(row.get("kind") or "") not in {"mf", "df", "adf"}:
        return None
    chain_text = str(row.get("fid_chain") or "").strip()
    if not chain_text or "MALFORMED:" in chain_text:
        return None
    return [seg for seg in chain_text.split("/") if seg]


def _finalise_gfm_row(
    *,
    section_key: str,
    transaction_index: int,
    cmd_index: int,
    cmd_value: Any,
    extra_entries: list[tuple[str, Any]],
    select_chain: list[str],
    adf_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compose a single GFM-sourced filesystem row."""
    fcp_payload: dict[str, Any] = cmd_value if isinstance(cmd_value, dict) else {}
    file_id_hex = _coerce_hex_field(fcp_payload.get("fileID"))
    desc_hex = _coerce_hex_field(fcp_payload.get("fileDescriptor"))
    df_name_hex = _coerce_hex_field(fcp_payload.get("dfName"))
    synthetic_value: list[tuple[str, Any]] = [("fileDescriptor", fcp_payload)]
    for entry in extra_entries:
        synthetic_value.append(entry)
    # Re-anchor SELECT chains that traverse an ADF's temp_fid so the
    # row lands under the ADF's friendly root, not under MF/7FFx.
    effective_chain = _reanchor_chain_under_adf(select_chain, adf_map or {})
    parent_path = "/".join(seg for seg in effective_chain if seg)
    fid_chain = parent_path + "/" + file_id_hex if file_id_hex else parent_path
    friendly = _saip_reverse_fid_friendly(file_id_hex, parent_fid_hex=parent_path)
    desc_kind = _kind_from_descriptor(
        desc_hex,
        fid_hex=file_id_hex,
        has_df_name=bool(df_name_hex),
    )
    if not friendly:
        if desc_kind == "adf":
            friendly = "ADF." + (file_id_hex or "?")
        elif desc_kind == "df":
            friendly = "DF." + (file_id_hex or "?")
        else:
            friendly = "EF." + (file_id_hex or "?")
    kind_str = desc_kind or "ef"
    return _make_filesystem_row(
        section_key=section_key,
        field_path=f"fileManagementCMD[{transaction_index}][{cmd_index}]",
        value=synthetic_value,
        parent_path=parent_path,
        fid_chain=fid_chain,
        kind=kind_str,
        friendly_name=friendly,
        source="gfm",
    )


def _make_filesystem_row(
    *,
    section_key: str,
    field_path: str,
    value: Any,
    parent_path: str,
    fid_chain: str,
    kind: str,
    friendly_name: str,
    source: str,
    template_default: dict[str, Any] | None = None,
    template_fcp: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose the legacy FCP summary + filesystem-tree metadata into one dict."""
    summary = _summarise_file_choices(value)
    if summary is None:
        summary = {
            "file_id": "",
            "short_efid": "",
            "descriptor": "",
            "ef_size": "",
            "link_path": "",
            "security_attrs": "",
            "max_size": "",
            "details": "",
            "proprietary_special_info": "",
            "proprietary_details": "",
            "proprietary_fill_pattern": "",
            "proprietary_repeat_pattern": "",
            "proprietary_max_size": "",
        }
    row = dict(summary)
    row["section_key"] = section_key
    row["field_path"] = field_path
    row["parent_path"] = parent_path
    row["fid_chain"] = fid_chain
    row["kind"] = kind
    row["friendly_name"] = friendly_name
    row["source"] = source
    if isinstance(template_default, dict):
        row.update(template_default)
    inherited_fields: list[str] = []
    if isinstance(template_fcp, dict):
        for key, value in template_fcp.items():
            if key.endswith("_source"):
                continue
            if value is None or str(value).strip() == "":
                continue
            if str(row.get(key, "") or "").strip() != "":
                continue
            row[key] = value
            source_key = f"{key}_source"
            if template_fcp.get(source_key) == "template":
                row[source_key] = "template"
                inherited_fields.append(key)
    if inherited_fields:
        row["template_fcp_inherited_fields"] = inherited_fields
    return row


# ----------------------------------------------------------------------
# Dirty state + mutation helpers (SA-3)
# ----------------------------------------------------------------------


# Whitelist of sub-field names we allow GUI-level mutation on. Keeping
# this tight means we don't have to relitigate every possible ASN.1
# re-encoding path in SA-3. Anything outside this set returns a clear
# rejection from ``saip.update_file_field``.
_EDITABLE_SUB_FIELDS: frozenset[str] = frozenset(
    {
        "shortEFID",
        "fileDescriptor",
        "efFileSize",
        "linkPath",
        "securityAttributesReferenced",
        "lcsi",
        "fileID",
        "maximumFileSize",
        "pinStatusTemplateDO",
        # ``proprietaryEFInfo`` is a nested dict in the SAIP CHOICE
        # payload. The synthetic sub_keys below address its leaf
        # fields directly so the GUI can update them without
        # re-encoding the surrounding structure. PEDocumentation
        # ProprietaryEFInfo enumerates: specialFileInformation,
        # fileDetails, fillPattern, repeatPattern, maximumFileSize.
        "proprietaryEFInfo.specialFileInformation",
        "proprietaryEFInfo.fileDetails",
        "proprietaryEFInfo.fillPattern",
        "proprietaryEFInfo.repeatPattern",
        "proprietaryEFInfo.maximumFileSize",
    }
)


def _ensure_session_state(handle: dict[str, Any]) -> None:
    """Initialise SA-3 scratch state on a session handle (idempotent)."""
    handle.setdefault("dirty_pes", set())
    handle.setdefault("applied_overrides", {})


def _sections_by_pe_index(decoded_document: dict[str, Any]) -> list[str]:
    """Section keys in PE order (mirrors ``_build_decoded_document``)."""
    sections = decoded_document.get("sections") or {}
    return list(sections.keys())


def _resolve_pe_index(
    handle: dict[str, Any],
    section_key: str,
) -> int:
    """Return the PE list index that corresponds to ``section_key``."""
    keys = _sections_by_pe_index(handle["decoded_document"])
    if section_key not in keys:
        raise LookupError(f"unknown section_key: {section_key}")
    return keys.index(section_key)


def _refresh_decoded_document(handle: dict[str, Any]) -> None:
    """Rebuild the cached document from the live ProfileElementSequence."""
    _ensure_pysim_importable()
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
    )

    pes = handle["pes"]
    intro = handle.get("decoded_document", {}).get("intro") or [
        f"Profile with {len(pes.pe_list)} profile elements",
    ]
    handle["decoded_document"] = build_decoded_document_from_sequence(pes, intro)


def _apply_hex_mutation(
    choice_list: Any,
    sub_key: str,
    new_bytes: bytes,
) -> bool:
    """Mutate the first CHOICE tuple whose payload carries ``sub_key``.

    Returns ``True`` if a substitution was made. Operates on the live
    pySim-decoded list of ``(choice_name, OrderedDict)`` tuples.

    Dotted ``sub_key`` names address one level of nesting —
    ``proprietaryEFInfo.specialFileInformation``,
    ``proprietaryEFInfo.fileDetails``,
    ``proprietaryEFInfo.fillPattern``,
    ``proprietaryEFInfo.repeatPattern`` and
    ``proprietaryEFInfo.maximumFileSize``. The outer container is
    created on demand when missing so a freshly cloned EF can grow
    its proprietary block without a full re-encode.
    """
    from collections import OrderedDict as _OrderedDict

    if isinstance(choice_list, list) is False:
        return False
    head, _, tail = sub_key.partition(".")
    # First pass: try to update an existing entry (existing nested
    # dict, or top-level field).
    for index in range(len(choice_list)):
        item = choice_list[index]
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        _choice_name, choice_payload = item
        if isinstance(choice_payload, dict) is False:
            continue
        if tail == "":
            if sub_key not in choice_payload:
                continue
            choice_payload[sub_key] = new_bytes
            return True
        if head not in choice_payload:
            continue
        nested = choice_payload[head]
        if isinstance(nested, dict) is False:
            continue
        nested[tail] = new_bytes
        return True
    # Second pass (dotted only): grow the outer container if the file
    # has FCP siblings (fileDescriptor / fileID / efFileSize) but no
    # proprietaryEFInfo yet. PEDocumentation ProprietaryEFInfo defines
    # this dict as optional; SAIP packages omit it when default.
    if tail == "":
        return False
    fcp_siblings = {
        "fileDescriptor",
        "fileID",
        "efFileSize",
        "shortEFID",
        "linkPath",
        "securityAttributesReferenced",
    }
    for index in range(len(choice_list)):
        item = choice_list[index]
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        _choice_name, choice_payload = item
        if isinstance(choice_payload, dict) is False:
            continue
        if not any(key in choice_payload for key in fcp_siblings):
            continue
        choice_payload[head] = _OrderedDict([(tail, new_bytes)])
        return True
    return False


def _mutable_file_choice_list_for_path(
    pe: Any,
    path_text: str,
) -> Any:
    """Return the live list carrying FCP fields for a file path.

    Template-backed filesystem PEs store files directly under
    ``pe.decoded[field_path]``. Generic File Management files are
    addressed in the GUI as ``fileManagementCMD[i][j]`` where ``j`` is
    the ``createFCP`` operation inside a transaction; for mutation the
    live transaction itself is the correct choice-list because it owns
    the ``("createFCP", {...})`` tuple that carries the editable FCP
    fields. ``fillFile*`` entries in the same transaction remain
    untouched by :func:`_apply_hex_mutation`.
    """
    decoded = getattr(pe, "decoded", None)
    if isinstance(decoded, dict) is False:
        return None
    direct = decoded.get(path_text)
    if isinstance(direct, list):
        return direct
    if str(getattr(pe, "type", "") or "").lower() != "genericfilemanagement":
        return direct
    match = _GFM_FIELD_PATH_RE.match(str(path_text or ""))
    if match is None:
        return direct
    fmc = decoded.get("fileManagementCMD")
    if isinstance(fmc, list) is False:
        return None
    transaction_index = int(match.group(1))
    if transaction_index < 0 or transaction_index >= len(fmc):
        return None
    transaction = fmc[transaction_index]
    return transaction if isinstance(transaction, list) else None


def _normalise_hex_input(value: Any) -> bytes:
    """Parse a user-supplied hex string into raw bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    text = str(value or "").strip()
    if text == "":
        raise ValueError("hex value cannot be empty.")
    compact = text.replace(" ", "").replace("_", "").replace("-", "")
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if len(compact) % 2 != 0:
        raise ValueError(f"hex value has odd length (got {len(compact)} nibbles).")
    try:
        return bytes.fromhex(compact)
    except ValueError as error:
        raise ValueError(f"invalid hex value: {error}") from error


def _validate_sub_field_value(sub_key: str, raw: bytes) -> None:
    """Enforce simple length bounds on the whitelisted editable fields."""
    n = len(raw)
    expectations = {
        "shortEFID": (1, 1),
        "fileDescriptor": (2, 8),
        "efFileSize": (1, 4),
        "fileID": (2, 2),
        "lcsi": (1, 1),
        "linkPath": (1, 32),
        "securityAttributesReferenced": (1, 32),
        "maximumFileSize": (1, 4),
        "pinStatusTemplateDO": (1, 64),
        "proprietaryEFInfo.specialFileInformation": (1, 1),
        "proprietaryEFInfo.fileDetails": (1, 1),
        # ETSI TS 102 222 §6.3.2.2 — fillPattern / repeatPattern carry
        # a sequence of bytes that is written once (fillPattern) or
        # tiled until the body is full (repeatPattern). 1..32 B keeps
        # the editor honest without inventing a hard upper bound.
        "proprietaryEFInfo.fillPattern": (1, 32),
        "proprietaryEFInfo.repeatPattern": (1, 32),
        # TCA 3.1+ BER-TLV-only upper bound on the EF body size.
        "proprietaryEFInfo.maximumFileSize": (1, 4),
    }
    bounds = expectations.get(sub_key)
    if bounds is None:
        return
    low, high = bounds
    if n < low or n > high:
        raise ValueError(
            f"{sub_key} expected {low}..{high} bytes, got {n}."
        )


def _mark_dirty(handle: dict[str, Any], pe_index: int) -> None:
    handle["dirty_pes"].add(int(pe_index))


# --------------------------------------------------------------------
# SA-G6 — per-session undo / redo snapshot stack.
#
# Mutating dispatchers call ``_history_snapshot`` immediately after
# claiming the session handle and before mutating the document. The
# snapshot is a deep copy of ``decoded_document`` so subsequent edits
# do not leak into the saved state. The redo stack is cleared on any
# new edit (standard linear-history semantics).
#
# A capped stack avoids unbounded memory growth on long-lived sessions
# — the SAIP authoring UI is interactive so 64 steps is plenty for the
# usual workflow without holding tens of megabytes of decoded JSON.
# --------------------------------------------------------------------

SAIP_HISTORY_LIMIT = 64


def _history_init(handle: dict[str, Any]) -> dict[str, list[Any]]:
    history = handle.get("history")
    if isinstance(history, dict) is False:
        history = {"undo": [], "redo": []}
        handle["history"] = history
    history.setdefault("undo", [])
    history.setdefault("redo", [])
    return history


def _history_snapshot(handle: dict[str, Any]) -> None:
    """Push a deep-copy of the current document onto the undo stack.

    Discards the redo stack (linear history). Capped at
    :data:`SAIP_HISTORY_LIMIT` entries.
    """
    import copy as _copy

    document = handle.get("decoded_document")
    if document is None:
        return
    history = _history_init(handle)
    history["undo"].append(_copy.deepcopy(document))
    while len(history["undo"]) > SAIP_HISTORY_LIMIT:
        history["undo"].pop(0)
    history["redo"].clear()


def _with_history(dispatcher: Any) -> Any:
    """Wrap a mutating dispatcher so it records an undo snapshot first.

    The wrapper is intentionally lenient — failures to claim the
    session or take the snapshot are swallowed so the underlying
    dispatcher's own error path remains the source of truth for the
    caller. When ``session_id`` is missing (one-shot dispatchers like
    ``saip.lint_path``) the wrapper is a no-op.
    """
    import functools as _functools

    @_functools.wraps(dispatcher)
    def _wrapper(ctx: Any, **kwargs: Any) -> Any:
        sid = str(kwargs.get("session_id") or "").strip()
        if len(sid) > 0:
            try:
                from yggdrasim_common.gui_server.sessions import get_manager

                handle = get_manager().claim(sid)
                _ensure_session_state(handle)
                _history_snapshot(handle)
            except Exception:
                # The dispatcher will surface a clean error if the
                # session truly is gone; we don't want to mask its
                # message with one from the history layer.
                pass
        return dispatcher(ctx, **kwargs)

    return _wrapper


def _reload_source_into_handle(handle: dict[str, Any]) -> None:
    """Re-open the on-disk source and swap fresh state in-place."""
    source = handle.get("source_path")
    if not source:
        raise RuntimeError("session has no source_path; cannot revert.")
    package = _load_package_from_path(Path(source))
    handle["pes"] = package["pes"]
    handle["decoded_document"] = package["decoded_document"]
    handle["encoding"] = package["encoding"]
    handle["dirty_pes"] = set()
    handle["applied_overrides"] = {}


# ----------------------------------------------------------------------
# Compare + variables helpers (SA-4)
# ----------------------------------------------------------------------


def _pe_digest(pe: Any) -> str:
    """Stable SHA256 hex digest of a PE's DER-encoded form."""
    import hashlib

    try:
        der = pe.to_der()
    except Exception:
        # Fallback: hash the decoded OrderedDict JSON projection.
        decoded = _jsonify_decoded(getattr(pe, "decoded", {}))
        der = json.dumps(decoded, sort_keys=True).encode("utf-8")
    return hashlib.sha256(der).hexdigest()


def _gfm_canonical_digest(pe: Any) -> str:
    """SHA256 over the canonical (index-stable) form of a GFM PE.

    Two GFM PEs that install the same EFs but at different list-index
    positions must compare as equal so the compare view does not flag
    them as changed. ``canonicalize_generic_file_management`` re-keys
    the command blocks by resolved FS path, eliminating index shifts.
    """
    import hashlib

    try:
        from Tools.ProfilePackage.saip_diff_canonical import (
            canonicalize_generic_file_management,
        )
        decoded = _jsonify_decoded(getattr(pe, "decoded", {}))
        gfm_section = decoded.get("file", {})
        canonical = canonicalize_generic_file_management(
            gfm_section.get("fileManagementCMD", [])
        )
        canonical_bytes = json.dumps(canonical, sort_keys=True).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()
    except Exception:
        return _pe_digest(pe)


def _file_row_signature(row: dict[str, Any]) -> str:
    """Signature used to detect file-level changes between two packages."""
    keys = (
        "file_id",
        "short_efid",
        "descriptor",
        "ef_size",
        "link_path",
        "security_attrs",
        "max_size",
    )
    return "|".join(str(row.get(k, "")) for k in keys)


def _collect_variables(decoded_document: dict[str, Any]) -> dict[str, Any]:
    """Return variable definitions + usage counts from a decoded document."""
    _ensure_pysim_importable()
    from Tools.ProfilePackage.saip_profile_template import (
        extract_template_placeholder_names,
    )

    token_defs = decoded_document.get("__ygg_token_defs__")
    style = decoded_document.get("__ygg_placeholder_style__", "brace")

    names_from_doc = extract_template_placeholder_names(
        decoded_document.get("sections") or {}
    )
    defs_map: dict[str, dict[str, Any]] = {}
    if isinstance(token_defs, dict):
        for name, definition in token_defs.items():
            if isinstance(definition, dict):
                defs_map[str(name)] = dict(definition)
            else:
                defs_map[str(name)] = {"value": str(definition)}

    all_names = set(defs_map.keys()) | {str(n) for n in names_from_doc}
    variables: list[dict[str, Any]] = []
    for name in sorted(all_names):
        definition = defs_map.get(name, {})
        # Token defs written by build_override_token_definitions store
        # the encoded bytes under "hex". Fall back to "value" / "text"
        # for any authoring flow that prefers a human-readable form.
        resolved_value = (
            definition.get("value")
            or definition.get("hex")
            or definition.get("text")
            or ""
        )
        variables.append(
            {
                "name": name,
                "value": str(resolved_value),
                "kind": str(definition.get("kind") or definition.get("encoding") or ""),
                "defined": name in defs_map,
                "used_in_document": name in names_from_doc,
            }
        )
    return {
        "count": len(variables),
        "style": style,
        "variables": variables,
    }


# ----------------------------------------------------------------------
# Dispatchers
# ----------------------------------------------------------------------


def _dispatch_open_package(
    ctx: ActionContext,
    *,
    path: Any = None,
) -> dict[str, Any]:
    """Load a DER or JSON SAIP package and return a session id."""
    from yggdrasim_common.gui_server.sessions import get_manager

    path_text = str(path or "").strip()
    if len(path_text) == 0:
        raise ValueError("path is required (file to open).")
    resolved = Path(os.path.expanduser(path_text)).resolve()
    if resolved.is_file() is False:
        raise FileNotFoundError(f"not a file: {resolved}")

    package = _load_package_from_path(resolved)
    pes = package["pes"]
    decoded_document = package["decoded_document"]
    encoding = package["encoding"]
    warnings = package.get("warnings") or []
    inline_placeholder_records = package.get("inline_placeholder_records") or []

    manager = get_manager()
    handle = {
        "pes": pes,
        "decoded_document": decoded_document,
        "encoding": encoding,
        "source_path": str(resolved),
        "size_bytes": resolved.stat().st_size,
        "load_warnings": warnings,
        "inline_placeholder_records": inline_placeholder_records,
    }
    _ensure_session_state(handle)
    session = manager.open(
        kind="saip",
        handle=handle,
        close=lambda: None,
        metadata={
            "source_path": str(resolved),
            "encoding": encoding,
            "pe_count": len(pes.pe_list),
            "load_warning_count": len(warnings),
            "inline_placeholder_count": len(inline_placeholder_records),
        },
    )

    return {
        "session_id": session.id,
        "source_path": str(resolved),
        "file_name": resolved.name,
        "size_bytes": resolved.stat().st_size,
        "encoding": encoding,
        "pe_count": len(pes.pe_list),
        "pe_types": sorted(
            {str(getattr(pe, "type", "unknown")) for pe in pes.pe_list}
        ),
        "load_warnings": warnings,
        "inline_placeholder_count": len(inline_placeholder_records),
    }


def _dispatch_open_package_upload(
    ctx: ActionContext,
    *,
    filename: Any = None,
    content_base64: Any = None,
) -> dict[str, Any]:
    """Load a browser-dropped SAIP package from uploaded bytes."""
    safe_name = Path(str(filename or "dropped-profile.der")).name
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", safe_name).strip("._")
    if len(safe_name) == 0:
        safe_name = "dropped-profile.der"
    payload_text = str(content_base64 or "").strip()
    if len(payload_text) == 0:
        raise ValueError("content_base64 is required.")
    try:
        raw = base64.b64decode(payload_text, validate=True)
    except Exception as error:
        raise ValueError("content_base64 is not valid base64.") from error
    if len(raw) == 0:
        raise ValueError("uploaded file is empty.")

    upload_dir = Path(tempfile.gettempdir()) / "yggdrasim-saip-uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    target = upload_dir / safe_name
    if target.exists():
        stem = target.stem or "dropped-profile"
        suffix = target.suffix
        counter = 1
        while target.exists():
            target = upload_dir / f"{stem}-{counter}{suffix}"
            counter += 1
    target.write_bytes(raw)

    opened = _dispatch_open_package(ctx, path=str(target))
    opened["uploaded"] = True
    opened["uploaded_file_name"] = safe_name
    return opened


def _dispatch_list_pes(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")

    handle = get_manager().claim(sid)
    pes = handle["pes"]

    rows: list[dict[str, Any]] = []
    for index, pe in enumerate(pes):
        rows.append(_pe_summary_row(pe, index))

    return {
        "session_id": sid,
        "source_path": handle.get("source_path", ""),
        "count": len(rows),
        "rows": rows,
    }


def _dispatch_show_pe(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pes = handle["pes"]
    if idx < 0 or idx >= len(pes.pe_list):
        raise IndexError(f"pe_index {idx} out of range 0..{len(pes.pe_list) - 1}")

    pe = pes.pe_list[idx]
    decoded = _jsonify_decoded(getattr(pe, "decoded", {}))
    inline_placeholder_records = handle.get("inline_placeholder_records") or []
    if len(inline_placeholder_records) > 0:
        try:
            from Tools.ProfilePackage.saip_hex_template import (
                splice_literals_into_tagged_document,
            )

            splice_literals_into_tagged_document(decoded, inline_placeholder_records)
        except Exception:
            pass

    # Encoded PE bytes — pySim ``ProfileElement.to_der()`` re-encodes
    # the in-memory dict back through asn1tools so the Editor tab can
    # surface a "Reconstructed PE bytes" card the same way the file-
    # detail Data tab surfaces the reconstructed file image. Best-
    # effort: a partially-built PE (e.g. after a fresh saip.add_pe
    # before any field has been stamped) can fail to encode; in that
    # case ``pe_hex`` lands as an empty string and the GUI hides the
    # card instead of crashing.
    pe_hex = ""
    pe_byte_len = 0
    try:
        encoded_bytes = pe.to_der()
        if isinstance(encoded_bytes, (bytes, bytearray)):
            pe_hex = bytes(encoded_bytes).hex().upper()
            pe_byte_len = len(encoded_bytes)
    except Exception:
        pe_hex = ""
        pe_byte_len = 0

    # Enrich securityDomain-like PEs with decoded DGI records so the
    # GUI can render the sdPersoData as connectivity / key-object tables
    # without an extra round-trip (the raw hex is still in decoded.sdPersoData).
    if isinstance(decoded, dict) and decoded.get("sdPersoData"):
        try:
            from Tools.ProfilePackage.saip_dgi_decode import decode_dgi_records
            dgi_result = decode_dgi_records(decoded["sdPersoData"])
            if dgi_result is not None:
                decoded = dict(decoded)
                decoded["_dgi_decoded"] = dgi_result
        except Exception:
            pass

    # Enrich genericFileManagement PEs with pre-split file blocks so
    # the GUI can render one row per file without duplicating the
    # ``pysim_gfm_walk`` / ``pe2files`` iteration pattern in JS.
    pe_type = str(getattr(pe, "type", "") or "").lower()
    if pe_type in ("genericfilemanagement", "gfm") and isinstance(decoded, dict):
        try:
            from SIMCARD.saip_pysim_specs import pysim_gfm_split_blocks
            blocks = pysim_gfm_split_blocks(decoded)
            if blocks:
                decoded = dict(decoded)
                decoded["_gfm_file_blocks"] = [
                    [list(op) for op in block]
                    for block in blocks
                ]
        except Exception:
            pass

    if isinstance(decoded, dict):
        app_param_summary = _application_parameter_summary(decoded)
        if app_param_summary is not None:
            decoded = dict(decoded)
            decoded["_application_parameter_summary"] = app_param_summary
            tar_summary = app_param_summary.get("tar_values")
            if isinstance(tar_summary, list) and tar_summary:
                decoded["_tar_summary"] = tar_summary

    # Look up the section_key so the GUI can drive
    # ``saip.list_decoded_fields`` / ``saip.apply_decoded_edit`` for
    # PE-level edits (PIN/PUK, AKA, SecurityDomain) without having to
    # reconstruct the document section ordering on the client side.
    section_keys = _sections_by_pe_index(handle["decoded_document"])
    section_key = section_keys[idx] if 0 <= idx < len(section_keys) else ""

    return {
        "session_id": sid,
        "pe_index": idx,
        "section_key": section_key,
        "type": str(getattr(pe, "type", "unknown")),
        "label": _pe_display_label(pe),
        "decoded": decoded,
        # Encoded form for the Editor tab's "PE bytes" card. Empty
        # when ``pe.to_der()`` raised — the GUI hides the card in
        # that case rather than rendering a misleading 0-byte image.
        "pe_hex": pe_hex,
        "pe_size": pe_byte_len,
        # Phase 3: lets the GUI gate the "Add file…" button on PEs that
        # actually expose ``create_file()``. PE types without a
        # filesystem template (PIN, PUK, AKA, SecurityDomain, GFM, etc.)
        # report False; the GUI hides the button on those.
        "pe_supports_add_file": bool(hasattr(pe, "create_file")),
    }


# ----------------------------------------------------------------------
# Template-driven file catalog.
#
# pySim's ``ProfileTemplateRegistry`` (TCA SAIP §9 / Annex A) carries
# the full catalog of DFs/EFs each filesystem-bearing PE can hold. The
# eUICC Profile Creator surfaces this catalog as a checkable tree so
# operators see *all* files defined by the template — not just the
# ones currently materialised in the PE.
#
# These three actions expose:
#   * list_pe_template — read the catalog, with ``in_pe`` flags so the
#                        GUI can render checkboxes that reflect which
#                        files this PE currently carries;
#   * add_template_file — materialise a file by its ``pe_name`` using
#                         the pySim default-content rules (FCP defaults
#                         from the FileTemplate, fillFileContent of
#                         the right length, etc.);
#   * remove_template_file — drop a ``pe_name`` from the PE.
# ----------------------------------------------------------------------


_TEMPLATE_FILE_TYPE_LABELS = {
    "MF": "Master File",
    "ADF": "Application DF",
    "DF": "Dedicated File",
    "TR": "Transparent EF",
    "LF": "Linear-fixed EF",
    "CY": "Cyclic EF",
    "BT": "BER-TLV EF",
}


def _file_template_to_row(
    ft: Any,
    *,
    materialized_keys: set[str],
    parent_pename: str | None = None,
) -> dict[str, Any]:
    """Project a pySim ``FileTemplate`` into a JSON-safe wire row."""
    file_type = str(getattr(ft, "file_type", "") or "")
    nb_rec = None
    rec_len = None
    file_size = None
    if file_type in ("LF", "CY"):
        nb_rec = getattr(ft, "nb_rec", None)
        rec_len = getattr(ft, "rec_len", None)
    elif file_type in ("TR", "BT"):
        file_size = getattr(ft, "file_size", None)
    fid_value = getattr(ft, "fid", None)
    fid_hex = ("%04X" % int(fid_value)) if isinstance(fid_value, int) else None
    sfi_value = getattr(ft, "sfi", None)
    sfi_hex = ("%02X" % int(sfi_value)) if isinstance(sfi_value, int) else None
    arr_value = getattr(ft, "arr", None)
    if isinstance(arr_value, int):
        arr_text = str(arr_value)
    else:
        arr_text = None
    params = list(getattr(ft, "params", None) or [])
    ass_serv_raw = getattr(ft, "ass_serv", None)
    if isinstance(ass_serv_raw, dict):
        ass_serv: Any = {str(k): v for k, v in ass_serv_raw.items()}
    elif isinstance(ass_serv_raw, (list, tuple)):
        ass_serv = list(ass_serv_raw)
    else:
        ass_serv = None
    pe_name = str(getattr(ft, "pe_name", "") or "")
    return {
        "pe_name": pe_name,
        "name": str(getattr(ft, "name", "") or pe_name),
        "fid": fid_hex,
        "file_type": file_type,
        "type_label": _TEMPLATE_FILE_TYPE_LABELS.get(file_type, file_type),
        "sfi": sfi_hex,
        "arr_record": arr_text,
        "size": file_size,
        "record_length": rec_len,
        "record_count": nb_rec,
        "default_val": getattr(ft, "default_val", None),
        "default_val_repeat": bool(getattr(ft, "default_val_repeat", False)),
        "content_required": bool(getattr(ft, "content_rqd", False)),
        "high_update": bool(getattr(ft, "high_update", False)),
        "params": params,
        "ass_serv": ass_serv,
        "ppath": ["%04X" % int(p) for p in (getattr(ft, "ppath", None) or []) if isinstance(p, int)],
        "parent_pe_name": parent_pename,
        "in_pe": pe_name in materialized_keys,
    }


def _build_template_tree(
    template: Any,
    materialized_keys: set[str],
) -> list[dict[str, Any]]:
    """Walk the template ``tree`` recursively. ``children`` lives on every
    ``FileTemplate`` instance — pySim assembles the parent/child links in
    ``ProfileTemplate.__init_subclass__``."""
    def _walk(ft: Any, parent_pename: str | None) -> dict[str, Any]:
        row = _file_template_to_row(
            ft,
            materialized_keys=materialized_keys,
            parent_pename=parent_pename,
        )
        children = []
        for child in getattr(ft, "children", []) or ():
            children.append(_walk(child, row["pe_name"]))
        if len(children) > 0:
            row["children"] = children
        return row

    out: list[dict[str, Any]] = []
    for root in getattr(template, "tree", []) or ():
        out.append(_walk(root, None))
    return out


def _resolve_pe_for_section(
    handle: dict[str, Any],
    section_key: str,
) -> tuple[int, Any]:
    """Return ``(pe_index, pe)`` for the section_key or raise LookupError."""
    section_keys = _sections_by_pe_index(handle["decoded_document"])
    if section_key not in section_keys:
        raise LookupError(f"unknown section_key: {section_key!r}")
    idx = section_keys.index(section_key)
    pes = handle["pes"]
    if idx < 0 or idx >= len(pes.pe_list):
        raise IndexError(f"pe_index {idx} out of range")
    return (idx, pes.pe_list[idx])


def _materialized_pe_keys(pe: Any) -> set[str]:
    decoded = getattr(pe, "decoded", None)
    if isinstance(decoded, dict) is False:
        return set()
    out: set[str] = set()
    for key in decoded.keys():
        if isinstance(key, str):
            out.add(key)
    return out


def _dispatch_list_pe_template(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
) -> dict[str, Any]:
    """Return the TCA file template catalog for one PE.

    The catalog is exhaustive: every DF/EF defined by the template is
    surfaced, with an ``in_pe`` flag indicating whether the PE currently
    carries a materialised entry for that ``pe_name``. Operators can
    use this to drive an "Add file"-style checkable tree, mirroring
    the eUICC Profile Creator's *File System Template* group.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    sk = str(section_key or "").strip()
    if len(sk) == 0:
        raise ValueError("section_key is required.")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    _ensure_pysim_importable()
    pe_index, pe = _resolve_pe_for_section(handle, sk)
    pe_type = str(getattr(pe, "type", "unknown"))
    decoded = getattr(pe, "decoded", None)
    template_oid: str | None = None
    if isinstance(decoded, dict):
        raw = decoded.get("templateID")
        if isinstance(raw, str) and len(raw.strip()) > 0:
            template_oid = raw.strip()

    materialized = _materialized_pe_keys(pe)

    response: dict[str, Any] = {
        "session_id": sid,
        "section_key": sk,
        "pe_index": pe_index,
        "pe_type": pe_type,
        "template_oid": template_oid,
        "template_label": None,
        "template_class": None,
        "created_by_default": None,
        "optional": None,
        "files": [],
        "tree": [],
        "supported": False,
    }

    if template_oid is None:
        # Non-filesystem-bearing PE (PIN, PUK, AKA, GFM, SD, etc.) —
        # no catalog to project. The caller can still distinguish this
        # case by ``supported == False``.
        return response

    try:
        from pySim.esim.saip.templates import ProfileTemplateRegistry
    except ImportError as error:
        raise RuntimeError(
            "pySim's saip templates module is unavailable; cannot resolve template catalog"
        ) from error

    template = ProfileTemplateRegistry.get_by_oid(template_oid)
    if template is None:
        # OID present but no matching template registered. Surface the
        # OID + materialised keys only so the GUI can fall back to
        # "show what is in the PE" rendering.
        response["files"] = [
            {
                "pe_name": key,
                "name": key,
                "fid": None,
                "file_type": "?",
                "type_label": "Unknown",
                "in_pe": True,
            }
            for key in sorted(materialized)
            if key.startswith(("ef-", "df-", "adf-", "mf"))
        ]
        return response

    response["supported"] = True
    response["template_class"] = str(getattr(template, "__name__", "") or "")
    template_doc = getattr(template, "__doc__", None) or ""
    response["template_label"] = str(template_doc).strip().split("\n")[0]
    response["created_by_default"] = bool(getattr(template, "created_by_default", False))
    response["optional"] = bool(getattr(template, "optional", False))
    response["files"] = [
        _file_template_to_row(ft, materialized_keys=materialized)
        for ft in getattr(template, "files", []) or ()
    ]
    response["tree"] = _build_template_tree(template, materialized)
    # Surface any materialised keys that are NOT in the template (vendor
    # / out-of-spec entries) so the GUI can warn about them rather than
    # silently hiding them.
    template_pe_names = {row["pe_name"] for row in response["files"]}
    extras: list[str] = []
    for key in sorted(materialized):
        if key in template_pe_names:
            continue
        if key.startswith(("ef-", "df-", "adf-")):
            extras.append(key)
    response["extras_in_pe"] = extras
    return response


def _dispatch_add_template_file(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    pe_name: Any = None,
) -> dict[str, Any]:
    """Materialise a file (DF or EF) into a PE using pySim defaults.

    Uses ``ProfileElement.create_file(pe_name)`` so the file gets the
    template's FCP defaults and any default content. The decoded
    document is rebuilt from the PE sequence so the next read sees the
    new entry.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    sk = str(section_key or "").strip()
    if len(sk) == 0:
        raise ValueError("section_key is required.")
    name = str(pe_name or "").strip()
    if len(name) == 0:
        raise ValueError("pe_name is required.")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    _ensure_pysim_importable()
    pe_index, pe = _resolve_pe_for_section(handle, sk)
    decoded = getattr(pe, "decoded", None)
    if isinstance(decoded, dict) is False:
        raise ValueError(f"PE {sk} has no decoded payload to extend.")

    if name in decoded:
        raise ValueError(f"file {name!r} already present in PE {sk}.")

    # Sync pySim's File objects from decoded so create_file picks up
    # the right context. ``pe2files`` is idempotent on already-decoded
    # PEs (pySim does it as part of _post_decode).
    if hasattr(pe, "pe2files"):
        try:
            pe.pe2files()
        except Exception:
            # Best-effort: some PEs already have files synced.
            pass

    if hasattr(pe, "create_file") is False:
        raise ValueError(f"PE type {getattr(pe, 'type', '?')} does not support add_file.")

    new_file = pe.create_file(name)
    if hasattr(pe, "files2pe"):
        pe.files2pe()

    # Rebuild the decoded document so subsequent reads see the change.
    pes = handle["pes"]
    pes._process_pelist()
    intro_lines = handle["decoded_document"].get("intro", []) or []
    if isinstance(intro_lines, list) is False:
        intro_lines = [str(intro_lines)]
    new_doc = build_decoded_document_from_sequence(pes, intro_lines=intro_lines)
    # Preserve document-level meta (encoding, source path, etc).
    for meta_key in handle["decoded_document"]:
        if meta_key == "sections":
            continue
        if meta_key == "intro":
            continue
        if meta_key in new_doc:
            continue
        new_doc[meta_key] = handle["decoded_document"][meta_key]
    handle["decoded_document"] = new_doc
    _mark_dirty(handle, pe_index)

    return {
        "session_id": sid,
        "section_key": sk,
        "pe_name": name,
        "pe_index": pe_index,
        "added": True,
        "file_repr": repr(new_file),
    }


def _project_template_node_to_json(
    file_template: Any,
    materialized: set[str],
) -> dict[str, Any]:
    """Project a pySim file-template node into the GUI tree shape.

    ``disabled`` is set when the entry is already present on the PE so
    the modal renders the row read-only (a tooltip in the GUI explains
    "already present"). ``children`` recurses into the template
    sub-tree.
    """

    pe_name = str(getattr(file_template, "pe_name", "") or "").strip()
    name = str(getattr(file_template, "name", "") or pe_name or "?").strip()
    file_type_raw = str(getattr(file_template, "file_type", "") or "").upper()
    fid_raw = getattr(file_template, "fid", None)
    if isinstance(fid_raw, int) and fid_raw >= 0:
        fid_text = f"{fid_raw:04X}"
    else:
        fid_text = str(fid_raw or "").strip().upper()
    kind = "df" if file_type_raw in {"MF", "ADF", "DF"} else "ef"
    node: dict[str, Any] = {
        "pe_name": pe_name,
        "name": name,
        "fid": fid_text or None,
        "file_type": file_type_raw or None,
        "kind": kind,
        "disabled": pe_name in materialized,
        "rec_len": getattr(file_template, "rec_len", None),
        "nb_rec": getattr(file_template, "nb_rec", None),
        "file_size": getattr(file_template, "file_size", None),
        "children": [],
    }
    for child in getattr(file_template, "children", []) or ():
        node["children"].append(
            _project_template_node_to_json(child, materialized)
        )
    return node


def _dispatch_list_addable_files_for_pe(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
) -> dict[str, Any]:
    """Return the addable-files JSON tree for a PE.

    Driven by ``saip_pe_quick_add._filesystem_template_for_pe`` so the
    output matches what the TUI's quick-add menu would offer. Each
    node carries ``pe_name``, ``fid``, ``kind`` (``"df"`` / ``"ef"``),
    ``file_type`` (TS 102 221 §11.1.1.4.3), ``disabled`` (true if the
    entry is already present on the PE), and a recursive ``children``
    list. The GUI mounts this via the modal tree picker; ``disabled``
    rows render greyed-out with an "already present" tooltip.
    """

    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_pe_quick_add import (
        _filesystem_template_for_pe,
        _template_root_children,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    sk = str(section_key or "").strip()
    if len(sk) == 0:
        raise ValueError("section_key is required.")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    _ensure_pysim_importable()
    pe_index, pe = _resolve_pe_for_section(handle, sk)
    pe_type = str(getattr(pe, "type", "unknown"))
    supports_add_file = hasattr(pe, "create_file")

    if not supports_add_file:
        return {
            "session_id": sid,
            "section_key": sk,
            "pe_index": pe_index,
            "pe_type": pe_type,
            "supports_add_file": False,
            "tree": [],
            "context_label": None,
            "reason": "PE type does not expose create_file().",
        }

    try:
        template = _filesystem_template_for_pe(pe)
    except ValueError as error:
        return {
            "session_id": sid,
            "section_key": sk,
            "pe_index": pe_index,
            "pe_type": pe_type,
            "supports_add_file": False,
            "tree": [],
            "context_label": None,
            "reason": str(error),
        }

    materialized = _materialized_pe_keys(pe)
    roots = _template_root_children(template)
    tree = [
        _project_template_node_to_json(node, materialized) for node in roots
    ]

    base_df = None
    try:
        base_df = template.base_df()
    except Exception:
        base_df = None
    context_label = (
        str(getattr(base_df, "name", "") or getattr(base_df, "pe_name", "") or "root")
        if base_df is not None
        else "root"
    )

    return {
        "session_id": sid,
        "section_key": sk,
        "pe_index": pe_index,
        "pe_type": pe_type,
        "supports_add_file": True,
        "context_label": context_label,
        "tree": tree,
    }


def _dispatch_add_template_subtree(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    pe_names: Any = None,
) -> dict[str, Any]:
    """Atomically add a list of template DFs / EFs to a PE.

    Calls ``_dispatch_add_template_file`` once per ``pe_names`` entry
    in declared order (parent DFs before children). On any failure the
    PE state is rolled back to the snapshot taken before the loop and
    the original exception is re-raised wrapped with the count of
    successful adds. Useful for "Add this DF with default child EFs"
    flows where partial state would leave the PE inconsistent.
    """

    from yggdrasim_common.gui_server.sessions import get_manager
    import copy as _copy

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    sk = str(section_key or "").strip()
    if len(sk) == 0:
        raise ValueError("section_key is required.")
    if isinstance(pe_names, (list, tuple)) is False:
        raise ValueError("pe_names must be a list of template pe_name strings.")
    names: list[str] = []
    for raw in pe_names:
        text = str(raw or "").strip()
        if len(text) == 0:
            raise ValueError("pe_names entries must be non-empty strings.")
        names.append(text)
    if len(names) == 0:
        raise ValueError("pe_names must be non-empty.")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    _ensure_pysim_importable()
    pe_index, pe = _resolve_pe_for_section(handle, sk)

    decoded_snapshot = _copy.deepcopy(getattr(pe, "decoded", {}) or {})
    document_snapshot = _copy.deepcopy(handle["decoded_document"])
    dirty_snapshot = set(handle.get("dirty_pes", set()) or set())

    added: list[str] = []
    try:
        for name in names:
            _dispatch_add_template_file(
                ctx,
                session_id=sid,
                section_key=sk,
                pe_name=name,
            )
            added.append(name)
    except Exception as exc:
        # Rollback: restore the PE's decoded payload, regenerate the
        # pySim File objects, and re-publish the cached document. The
        # in-memory ``pes`` object is kept (we do not rebuild it from
        # scratch) so other PEs in the sequence are not disturbed.
        try:
            pe.decoded = decoded_snapshot
            if hasattr(pe, "pe2files"):
                try:
                    pe.pe2files()
                except Exception:
                    pass
        except Exception:
            pass
        handle["decoded_document"] = document_snapshot
        handle["dirty_pes"] = dirty_snapshot
        raise ValueError(
            "add_template_subtree rolled back after "
            f"{len(added)} of {len(names)} additions: {exc!s}"
        ) from exc

    return {
        "session_id": sid,
        "section_key": sk,
        "pe_index": pe_index,
        "added": added,
        "added_count": len(added),
    }


# ----------------------------------------------------------------------
# Generic File Management — Add file element
#
# The eUICC Profile Creator manual ("Profile Elements for File System
# Creation" → "File System Creation by Generic File Management")
# documents two affordances inside a PE-GFM editor:
#
#   * Add select element — appends a ``filePath`` SELECT that moves
#     the cursor to an existing DF/ADF.
#   * Add file element — appends a ``createFCP`` that defines a new
#     file at the current cursor.
#
# Template PEs (USIM / ISIM / OPT-USIM / MF / Telecom / Phonebook /
# GSM-Access / 5GS / SAIP / SNPN / 5GProSe / EAP / CD) use the
# ``saip.add_template_file`` / ``saip.add_template_subtree`` pair —
# they are template-bounded. GFM is the free-form fallback for
# everything else, so we expose an equivalent dispatcher here.
#
# The single ``saip.gfm_add_file_element`` action below merges the
# "select + create" pair into one atomic operation: the operator
# supplies a parent path (the DF that owns the new file) plus the
# new file's FID and File-Descriptor Byte, and a fresh transaction
# is appended to ``fileManagementCMD``. Treating each addition as a
# self-contained transaction keeps the GFM section's diff readable
# and avoids stitching ambiguity against existing transactions.
# ----------------------------------------------------------------------


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _normalise_hex(raw: Any, *, even: bool = True, label: str = "value") -> str:
    """Strip whitespace / ``0x`` / colons and validate hex parity."""
    text = str(raw or "").strip()
    if text == "":
        return ""
    text = text.replace(" ", "").replace(":", "")
    if text.lower().startswith("0x"):
        text = text[2:]
    if _HEX_RE.match(text) is None:
        raise ValueError(f"{label!r} must be hex characters only.")
    if even is True and (len(text) % 2) != 0:
        raise ValueError(f"{label!r} must have an even number of hex digits.")
    return text.upper()


def _dispatch_gfm_add_file_element(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    parent_path: Any = None,
    file_id: Any = None,
    file_descriptor: Any = None,
    short_efid: Any = None,
    ef_size: Any = None,
    record_size: Any = None,
    record_count: Any = None,
    lcsi: Any = None,
    transaction_index: Any = None,
) -> dict[str, Any]:
    """Append a ``filePath + createFCP`` pair to a GFM section.

    Args:
      section_key: GFM section key (``genericFileManagement`` or a
        ``genericFileManagement_N`` suffix variant).
      parent_path: Hex FID chain identifying the containing DF — e.g.
        ``"7F10"`` for DF.TELECOM or ``""`` for the MF root. The chain
        is encoded raw into the ``filePath`` SELECT per
        pe2files semantics (pySim prepends 3F00 on replay).
      file_id: 4-nibble hex FID of the new file (e.g. ``"6F3A"``).
      file_descriptor: Optional 2-byte hex File-Descriptor Byte +
        coding (e.g. ``"4221"`` for a linear-fixed EF with record-
        oriented coding). Defaults to ``"01"`` (transparent EF, no
        further structure) when omitted, which the operator can
        edit afterwards via the FCP editor.
      short_efid: Optional 1-byte hex Short EF Identifier.
      ef_size / record_size / record_count: Optional sizing fields
        the operator can refine later. Stored as hex bytes per the
        SAIP encoder contract.
      lcsi: Optional Life-Cycle Status Integer (default ``"05"`` —
        "Operational state - activated", ETSI TS 102 221 §11.1.1.4.9).
      transaction_index: When provided, append into that existing
        transaction instead of starting a new one. Defaults to a new
        transaction so each addition is a self-contained diff hunk.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if sid == "":
        raise ValueError("session_id is required (run saip.open_package first).")
    sk = str(section_key or "").strip()
    if sk == "":
        raise ValueError("section_key is required.")
    if sk.lower().startswith("genericfilemanagement") is False:
        raise ValueError(
            f"section {sk!r} is not a Generic File Management PE — use "
            f"saip.add_template_file for template-based PEs."
        )

    fid_hex = _normalise_hex(file_id, label="file_id")
    if len(fid_hex) != 4:
        raise ValueError(
            f"file_id must be exactly 4 hex digits (a 2-byte FID); got "
            f"{len(fid_hex)} digit(s)."
        )
    parent_hex = _normalise_hex(parent_path, label="parent_path")
    # MF (3F00) is the implicit base; pySim drops the leading 3F00 in
    # the encoded ``filePath`` SELECT (see ProfileElementGFM.pe2files
    # in pySim/esim/saip/__init__.py).
    if parent_hex.upper().startswith("3F00"):
        parent_hex = parent_hex[4:]
    desc_hex = ""
    if file_descriptor is not None and str(file_descriptor).strip() != "":
        desc_hex = _normalise_hex(file_descriptor, label="file_descriptor")
        if len(desc_hex) < 2:
            raise ValueError("file_descriptor must be at least 1 byte (2 hex digits).")
    else:
        # ETSI TS 102 221 §11.1.1.4.3: 0x41 = transparent working EF,
        # not shareable. Operator can refine via the FCP editor.
        desc_hex = "4121"
    short_efid_hex = ""
    if short_efid is not None and str(short_efid).strip() != "":
        short_efid_hex = _normalise_hex(short_efid, label="short_efid")
    ef_size_hex = ""
    if ef_size is not None and str(ef_size).strip() != "":
        ef_size_hex = _normalise_hex(ef_size, label="ef_size")
    record_size_hex = ""
    if record_size is not None and str(record_size).strip() != "":
        record_size_hex = _normalise_hex(record_size, label="record_size")
    record_count_hex = ""
    if record_count is not None and str(record_count).strip() != "":
        record_count_hex = _normalise_hex(record_count, label="record_count")
    lcsi_hex = "05"
    if lcsi is not None and str(lcsi).strip() != "":
        lcsi_hex = _normalise_hex(lcsi, label="lcsi")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    _ensure_pysim_importable()
    pe_index, pe = _resolve_pe_for_section(handle, sk)
    if str(getattr(pe, "type", "")).lower() != "genericfilemanagement":
        raise ValueError(
            f"section {sk!r} resolves to a {getattr(pe, 'type', '?')!r} PE — expected genericFileManagement."
        )

    decoded = getattr(pe, "decoded", None)
    if isinstance(decoded, dict) is False:
        raise ValueError(f"PE {sk!r} has no decoded payload to extend.")
    fmc = decoded.get("fileManagementCMD")
    if isinstance(fmc, list) is False:
        fmc = []
        decoded["fileManagementCMD"] = fmc

    fcp_payload: dict[str, Any] = {
        "fileDescriptor": bytes.fromhex(desc_hex),
        "fileID": bytes.fromhex(fid_hex),
        "lcsi": bytes.fromhex(lcsi_hex),
    }
    if short_efid_hex:
        fcp_payload["shortEFID"] = bytes.fromhex(short_efid_hex)
    if ef_size_hex:
        fcp_payload["efFileSize"] = bytes.fromhex(ef_size_hex)
    if record_size_hex:
        fcp_payload["proprietaryEFInfo"] = {
            "specialFileInformation": bytes.fromhex(record_size_hex),
        }
    if record_count_hex:
        # ``proprietaryEFInfo`` is a free-form dict per SAIP §5; we
        # surface the operator's input under a stable key so the FCP
        # editor can refine it without losing context.
        existing = fcp_payload.setdefault("proprietaryEFInfo", {})
        if isinstance(existing, dict):
            existing["maximumFileSize"] = bytes.fromhex(record_count_hex)

    new_transaction: list[tuple[str, Any]] = []
    # Always emit an explicit filePath SELECT — even when the operator
    # is targeting MF (empty path). Without it the file would inherit
    # the cursor left behind by the previous transaction, which is
    # almost never what the operator meant. ETSI TS 102 222 §6
    # treats an empty filePath as "select MF" (pySim does the same in
    # ``ProfileElementGFM.pe2files``).
    new_transaction.append(
        ("filePath", bytes.fromhex(parent_hex) if parent_hex else b"")
    )
    new_transaction.append(("createFCP", fcp_payload))

    target_index: int | None = None
    if transaction_index is not None:
        try:
            target_index = int(transaction_index)
        except (TypeError, ValueError) as exc:
            raise ValueError("transaction_index must be an integer.") from exc
        if target_index < 0 or target_index >= len(fmc):
            raise ValueError(
                f"transaction_index {target_index} out of range "
                f"(0..{len(fmc) - 1 if len(fmc) > 0 else 0})."
            )
        existing_transaction = fmc[target_index]
        if isinstance(existing_transaction, list) is False:
            raise ValueError(
                f"transaction {target_index} is not a list — refusing to extend a malformed GFM PE."
            )
        existing_transaction.extend(new_transaction)
        appended_at = target_index
    else:
        fmc.append(new_transaction)
        appended_at = len(fmc) - 1

    # Refresh the decoded-document mirror so subsequent list_files /
    # show_file calls see the new file.
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
    )
    pes = handle["pes"]
    pes._process_pelist()
    intro_lines = handle["decoded_document"].get("intro", []) or []
    if isinstance(intro_lines, list) is False:
        intro_lines = [str(intro_lines)]
    new_doc = build_decoded_document_from_sequence(pes, intro_lines=intro_lines)
    for meta_key in handle["decoded_document"]:
        if meta_key in ("sections", "intro"):
            continue
        if meta_key in new_doc:
            continue
        new_doc[meta_key] = handle["decoded_document"][meta_key]
    handle["decoded_document"] = new_doc
    _mark_dirty(handle, pe_index)

    return {
        "session_id": sid,
        "section_key": sk,
        "pe_index": pe_index,
        "transaction_index": appended_at,
        "file_id": fid_hex,
        "parent_path": parent_hex,
        "file_descriptor": desc_hex,
        "added": True,
    }


def _dispatch_remove_template_file(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    pe_name: Any = None,
) -> dict[str, Any]:
    """Drop a ``pe_name`` from the decoded payload of a PE.

    Mirrors what the TUI's NAA editor does on checkbox-uncheck.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    sk = str(section_key or "").strip()
    if len(sk) == 0:
        raise ValueError("section_key is required.")
    name = str(pe_name or "").strip()
    if len(name) == 0:
        raise ValueError("pe_name is required.")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pe_index, pe = _resolve_pe_for_section(handle, sk)
    decoded = getattr(pe, "decoded", None)
    if isinstance(decoded, dict) is False or name not in decoded:
        return {
            "session_id": sid,
            "section_key": sk,
            "pe_name": name,
            "pe_index": pe_index,
            "removed": False,
            "reason": "not present",
        }

    decoded.pop(name)
    if hasattr(pe, "files") and isinstance(pe.files, dict) and name in pe.files:
        pe.files.pop(name)
    # Mirror the change into the cached document section so subsequent
    # show_pe / list_files calls see it without a full reload.
    sections = handle["decoded_document"].get("sections")
    if isinstance(sections, dict) and sk in sections and isinstance(sections[sk], dict):
        sections[sk].pop(name, None)
    _mark_dirty(handle, pe_index)

    return {
        "session_id": sid,
        "section_key": sk,
        "pe_name": name,
        "pe_index": pe_index,
        "removed": True,
    }


_LIST_FILES_SORT_KEYS: dict[str, callable] = {
    "natural": lambda row: 0,
    "file_id": lambda row: (str(row.get("file_id") or "").upper(),),
    "name": lambda row: (str(row.get("friendly_name") or "").lower(),),
    "kind": lambda row: (
        str(row.get("kind") or "").lower(),
        str(row.get("file_id") or ""),
    ),
    "parent_path": lambda row: (
        str(row.get("parent_path") or ""),
        str(row.get("file_id") or ""),
    ),
    "size": lambda row: (
        # Coerce to int so "8" sorts before "1024"; missing → -1.
        int(row.get("ef_size")) if str(row.get("ef_size") or "").isdigit() else -1,
    ),
}


def _dispatch_list_files(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    sort_by: Any = None,
    descending: Any = None,
) -> dict[str, Any]:
    """List every file across all FS-bearing PEs, optionally re-sorted.

    ``sort_by`` keys mirror the manual's "Sorting the File Tree"
    dropdown: ``natural`` (decode order), ``file_id``, ``name``,
    ``kind``, ``parent_path``, ``size``.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    sort_key = str(sort_by or "natural").strip().lower() or "natural"
    if sort_key not in _LIST_FILES_SORT_KEYS:
        raise ValueError(
            f"unknown sort_by {sort_by!r}; allowed: "
            + ", ".join(sorted(_LIST_FILES_SORT_KEYS.keys())),
        )
    desc_flag = bool(descending) if descending is not None else False

    handle = get_manager().claim(sid)
    rows = _filesystem_tree_rows(handle["decoded_document"])
    if sort_key != "natural":
        sort_func = _LIST_FILES_SORT_KEYS[sort_key]
        rows = sorted(rows, key=sort_func, reverse=desc_flag)
    elif desc_flag:
        rows = list(reversed(rows))
    return {
        "session_id": sid,
        "count": len(rows),
        "sort_by": sort_key,
        "descending": desc_flag,
        "rows": rows,
    }


_SEARCH_FILES_VALID_MODES: frozenset[str] = frozenset(
    {"all", "name", "fid", "description", "translation"},
)


def _filesystem_row_search_haystacks(row: dict[str, Any]) -> dict[str, str]:
    """Return per-mode haystacks for one filesystem row (lower-cased)."""
    name_parts = [
        str(row.get("friendly_name") or ""),
        str(row.get("field_path") or ""),
    ]
    fid_parts = [
        str(row.get("file_id") or ""),
        str(row.get("short_efid") or ""),
        str(row.get("fid_chain") or ""),
        str(row.get("parent_path") or ""),
    ]
    description_parts = [
        str(row.get("descriptor") or ""),
        str(row.get("kind") or ""),
        str(row.get("ef_size") or ""),
        str(row.get("max_size") or ""),
        str(row.get("section_key") or ""),
        str(row.get("source") or ""),
    ]
    translation_parts = [
        str(row.get("details") or ""),
        str(row.get("security_attrs") or ""),
        str(row.get("link_path") or ""),
        str(row.get("proprietary_special_info") or ""),
        str(row.get("proprietary_details") or ""),
        str(row.get("proprietary_fill_pattern") or ""),
        str(row.get("proprietary_repeat_pattern") or ""),
        str(row.get("proprietary_max_size") or ""),
    ]
    return {
        "name": " | ".join(name_parts).lower(),
        "fid": " | ".join(fid_parts).lower(),
        "description": " | ".join(description_parts).lower(),
        "translation": " | ".join(translation_parts).lower(),
    }


def _filesystem_row_matches_query(
    row: dict[str, Any],
    *,
    needle_lower: str,
    needle_pattern: Any,
    mode: str,
) -> bool:
    """Test one row against a search query.

    ``needle_pattern`` is a pre-compiled regex when regex mode is on,
    else ``None`` (substring match against ``needle_lower``).
    """
    haystacks = _filesystem_row_search_haystacks(row)
    if mode == "all":
        candidate_keys = ("name", "fid", "description", "translation")
    else:
        candidate_keys = (mode,)
    for key in candidate_keys:
        hay = haystacks.get(key, "")
        if needle_pattern is not None:
            if needle_pattern.search(hay) is not None:
                return True
        else:
            if needle_lower in hay:
                return True
    return False


def _dispatch_search_files(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    query: Any = None,
    mode: Any = None,
    regex: Any = None,
) -> dict[str, Any]:
    """Filter the filesystem-tree rows by name / FID / description.

    Mirrors the eUICC Profile Creator manual's ``Find File`` dialog
    (``ePC_02/Finding_Files_in_the_File_System.htm``). The default
    ``mode`` is ``all`` which scans every haystack the matrix supports;
    ``name`` / ``fid`` / ``description`` / ``translation`` narrow the
    scan. Regex mode honours the same flag the manual exposes ("Regular
    expression mode") and uses Python ``re.IGNORECASE`` by default so
    operators don't have to spell ``(?i)`` themselves.
    """
    import re as _re

    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    needle = str(query or "").strip()
    if len(needle) == 0:
        raise ValueError("query is required (the search string).")
    mode_text = str(mode or "all").strip().lower() or "all"
    if mode_text not in _SEARCH_FILES_VALID_MODES:
        raise ValueError(
            f"mode must be one of {sorted(_SEARCH_FILES_VALID_MODES)} (got {mode!r})."
        )
    use_regex = bool(regex) if regex is not None else False
    pattern: Any = None
    if use_regex is True:
        try:
            pattern = _re.compile(needle, _re.IGNORECASE)
        except _re.error as exc:
            raise ValueError(f"invalid regex {needle!r}: {exc}") from exc

    handle = get_manager().claim(sid)
    rows = _filesystem_tree_rows(handle["decoded_document"])
    needle_lower = needle.lower()
    matched: list[dict[str, Any]] = []
    for row in rows:
        if _filesystem_row_matches_query(
            row,
            needle_lower=needle_lower,
            needle_pattern=pattern,
            mode=mode_text,
        ):
            matched.append(row)
    return {
        "session_id": sid,
        "query": needle,
        "mode": mode_text,
        "regex": use_regex,
        "scanned": len(rows),
        "match_count": len(matched),
        "rows": matched,
    }


# ---------------------------------------------------------------------
# SA-G4: list_applications
#
# Walks the PE list and emits one row per application-instance-bearing
# PE: Security Domains (ISD-R / ISD-P / MNO-SD / SSD via ``securityDomain``
# / ``mnoSD`` / ``ssd``), JavaCard ``application`` instances, and the
# Remote File / App Management surfaces (``rfm`` / ``ram``). For each
# row we surface the canonical GP bookkeeping fields — Instance AID,
# Class AID, Load Package AID, decoded privileges, decoded lifecycle
# state, key-list size — so the GUI can render a Comprion-style
# Applications view without re-decoding the JSON tree client-side.
# ---------------------------------------------------------------------

def _dispatch_list_applications(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")

    handle = get_manager().claim(sid)
    pes = handle["pes"]

    rows: list[dict[str, Any]] = []
    for idx, pe in enumerate(pes):
        pe_type = str(getattr(pe, "type", "") or "")
        pe_type_lo = pe_type.lower()
        if pe_type_lo not in _APP_PE_TYPES:
            continue
        decoded = _jsonify_decoded(getattr(pe, "decoded", {}))

        # SD / Application PEs nest the GP install bookkeeping under
        # ``instance``. RFM / RAM PEs flatten ``instanceAID`` (and
        # adjacent fields) at the top level — we look in both places
        # and fall back to a top-level read whenever the nested entry
        # is absent. This keeps the row shape consistent across all
        # six application-bearing PE flavours.
        instance = decoded.get("instance") if isinstance(decoded, dict) else None
        if isinstance(instance, dict) is False:
            instance = {}

        def _read(field_name: str) -> str:
            value = instance.get(field_name)
            if value is None and isinstance(decoded, dict):
                value = decoded.get(field_name)
            return _hex_value(value)

        load_pkg_aid = _read("applicationLoadPackageAID")
        class_aid = _read("classAID")
        instance_aid = _read("instanceAID")
        privileges_hex = _read("applicationPrivileges")
        lifecycle_hex = _read("lifeCycleState")
        c9_params = _read("applicationSpecificParametersC9")

        # Toolkit / system-specific parameters live one nesting level
        # deeper under ``applicationParameters``. We surface the raw
        # subfields untouched so the GUI can render whichever flavour
        # happens to be present (UICC toolkit / CRS / EAC / etc.).
        application_parameters: dict[str, str] = {}
        ap = instance.get("applicationParameters") if isinstance(instance, dict) else None
        if isinstance(ap, dict):
            for key, value in ap.items():
                hx = _hex_value(value)
                if hx != "":
                    application_parameters[str(key)] = hx.upper()

        # RFM / RAM expose a TAR list (Toolkit Application Reference,
        # ETSI TS 102 226 §5.1.1 — three bytes per entry). Surface the
        # decoded TAR strings so the Applications card can render them
        # as chips next to the AID.
        tar_list: list[str] = []
        raw_tars = decoded.get("tarList") if isinstance(decoded, dict) else None
        if isinstance(raw_tars, list):
            for entry in raw_tars:
                hx = _hex_value(entry)
                if hx != "":
                    tar_list.append(hx.upper())

        key_list = decoded.get("keyList") if isinstance(decoded, dict) else None
        key_count = len(key_list) if isinstance(key_list, list) else 0

        rows.append(
            {
                "pe_index": idx,
                "pe_type": pe_type,
                "friendly_type": _APP_FRIENDLY_TYPES.get(pe_type_lo, pe_type),
                "label": _pe_display_label(pe),
                "instance_aid": (instance_aid or "").upper(),
                "class_aid": (class_aid or "").upper(),
                "load_pkg_aid": (load_pkg_aid or "").upper(),
                "privileges": _decode_gp_privileges(privileges_hex),
                "lifecycle": _decode_gp_lifecycle(lifecycle_hex, pe_type),
                "c9_params_hex": (c9_params or "").upper(),
                "application_parameters": application_parameters,
                "tar_list": tar_list,
                "key_count": key_count,
                "is_security_domain": pe_type_lo in _SD_PE_TYPES,
            }
        )

    return {
        "session_id": sid,
        "count": len(rows),
        "rows": rows,
    }


def _is_arr_field_path(field_path: Any) -> bool:
    fp_norm = str(field_path or "").strip().lower().replace("_", "-")
    return (
        fp_norm == "ef-arr"
        or fp_norm.startswith("ef-arr-")
        or fp_norm.endswith("-ef-arr")
        or fp_norm.endswith("/ef-arr")
        or "/ef-arr-" in fp_norm
    )


def _dispatch_show_file(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    field_path: Any = None,
) -> dict[str, Any]:
    """Return the full payload dict for one file entry (no APDUs)."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    section = str(section_key or "").strip()
    path_text = str(field_path or "").strip()
    if len(section) == 0:
        raise ValueError("section_key is required.")
    if len(path_text) == 0:
        raise ValueError("field_path is required.")

    handle = get_manager().claim(sid)
    rows = _filesystem_tree_rows(handle["decoded_document"])
    for row in rows:
        if row["section_key"] == section and row["field_path"] == path_text:
            # Pull the original payload (not just the normalized row)
            # so the GUI has the full FCP-ish detail to render.
            match_payload = _locate_file_payload(
                handle["decoded_document"],
                section_key=section,
                field_path=path_text,
            )
            response: dict[str, Any] = {
                "session_id": sid,
                "section_key": section,
                "field_path": path_text,
                "fcp": {
                    "file_id": row["file_id"],
                    "short_efid": row["short_efid"],
                    "descriptor": row["descriptor"],
                    "ef_size": row["ef_size"],
                    "max_size": row["max_size"],
                    "security_attrs": row["security_attrs"],
                    "link_path": row["link_path"],
                    "details": row["details"],
                    "proprietary_special_info": row.get("proprietary_special_info", ""),
                    "proprietary_details": row.get("proprietary_details", ""),
                    "proprietary_fill_pattern": row.get("proprietary_fill_pattern", ""),
                    "proprietary_repeat_pattern": row.get("proprietary_repeat_pattern", ""),
                    "proprietary_max_size": row.get("proprietary_max_size", ""),
                    "parent_path": row.get("parent_path", ""),
                    "fid_chain": row.get("fid_chain", ""),
                    "kind": row.get("kind", ""),
                    "friendly_name": row.get("friendly_name", ""),
                    "source": row.get("source", "template"),
                    "file_id_source": row.get("file_id_source", ""),
                    "short_efid_source": row.get("short_efid_source", ""),
                    "ef_size_source": row.get("ef_size_source", ""),
                    "security_attrs_source": row.get("security_attrs_source", ""),
                    "template_fcp_inherited_fields": list(
                        row.get("template_fcp_inherited_fields", [])
                    ),
                    "template_default_active": bool(
                        row.get("template_default_active", False)
                    ),
                    "template_default_value": row.get("template_default_value"),
                    "template_default_value_kind": row.get(
                        "template_default_value_kind", ""
                    ),
                    "template_default_repeat": bool(
                        row.get("template_default_repeat", False)
                    ),
                    "template_default_has_overrides": bool(
                        row.get("template_default_has_overrides", False)
                    ),
                    "template_file_size": row.get("template_file_size"),
                    "template_record_size": row.get("template_record_size"),
                    "template_record_count": row.get("template_record_count"),
                },
                "payload": _jsonify_decoded(match_payload),
            }
            # Surface canonical Python decoder output so the GUI does
            # not re-implement BER-TLV / spec-specific decoders. Two
            # shapes are emitted:
            #
            #   ``decoded``  — single dict for transparent / BER-TLV EFs
            #                  (whole-image decode through
            #                  ``_decode_known_ef_payload``).
            #   ``records``  — per-record list for linear-fixed / cyclic
            #                  EFs (each record decoded individually,
            #                  FF-padded slots flagged as ``empty``).
            #
            # The two are mutually exclusive: a transparent EF returns
            # only ``decoded``; a record-fixed EF returns only
            # ``records``. Old EF.ARR-only ``arr_records`` is preserved
            # for backwards-compat with frontend versions that have
            # not yet picked up the generalised path.
            decoded_payload, records_payload = _decode_for_show_file(
                section_key=section,
                field_path=path_text,
                file_value=match_payload,
                file_id=row.get("file_id"),
                pes=handle.get("pes"),
                decoded_document=handle.get("decoded_document"),
            )
            if decoded_payload is not None:
                response["decoded"] = decoded_payload
            if records_payload is not None:
                response["records"] = records_payload
            if _is_arr_field_path(path_text) and records_payload:
                response["arr_records"] = _flatten_arr_records_legacy(
                    records_payload
                )
            # Canonical on-card image — pySim ``File.body`` after
            # ``file_content_from_tuples`` has applied the template's
            # ``default_val`` pattern across ``file_size`` and overlaid
            # the package's diffs. The frontend's
            # ``saipBuildVirtualFileImage`` only walks explicit
            # fillFileContent / fillFileOffset tuples, so files whose
            # bytes live in the template default (e.g. EF.ICCID,
            # EF.IMSI on a freshly-cloned profile) reconstructed as
            # all-FF. Surfacing the composed body lets the frontend
            # render the actual hex.
            try:
                body_resolution = _file_body_from_pe(
                    pes=handle.get("pes"),
                    decoded_document=handle.get("decoded_document"),
                    section_key=section,
                    field_path=path_text,
                )
            except Exception:  # noqa: BLE001
                body_resolution = None
            if body_resolution is not None:
                body_bytes, body_rec_len, body_nb_rec, body_size = body_resolution
                response["body_hex"] = body_bytes.hex().upper()
                response["body_size"] = len(body_bytes)
                if isinstance(body_rec_len, int) and body_rec_len > 0:
                    response["body_record_size"] = body_rec_len
                if isinstance(body_nb_rec, int) and body_nb_rec > 0:
                    response["body_record_count"] = body_nb_rec
                if isinstance(body_size, int) and body_size > 0:
                    response["body_declared_size"] = body_size
            return response
    # Soft-fail when the row doesn't exist instead of raising. Operators
    # can hit this by clicking a synthetic tree node (a parent DF that
    # has no createFCP row of its own) or a stale frontend reference
    # left over after a delete_pe / re-open. A LookupError here turns
    # into an HTTP 500 + a noisy stack trace; returning a structured
    # ``not_found`` payload lets the GUI render an empty-detail card and
    # carry on without cascading appendChild failures downstream.
    return {
        "session_id": sid,
        "section_key": section,
        "field_path": path_text,
        "not_found": True,
        "fcp": {},
        "payload": None,
        "warning": (
            f"no file definition at {section}::{path_text} — likely a "
            "synthetic tree parent or a stale selection (try re-clicking "
            "or refreshing the file list)."
        ),
    }


def _decode_for_show_file(
    *,
    section_key: str,
    field_path: str,
    file_value: Any,
    file_id: Any,
    pes: Any = None,
    decoded_document: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]] | None]:
    """Run the canonical Python decoders against a file's payload.

    Returns ``(decoded, records)`` — exactly one of which is non-None
    for files we can decode. ``decoded`` is the
    ``_decode_known_ef_payload`` output for the reconstructed image.
    ``records`` is a per-record list for linear-fixed / cyclic EFs,
    each item carrying the same dispatcher's output for that record's
    slice plus a 1-based ``record`` number and an ``empty`` flag.

    The reconstruction prefers pySim's ``File.body`` when available —
    that path applies the TCA template's ``default_val`` to all record
    slots before overlaying the package's ``fillFileContent`` /
    ``fillFileOffset`` diffs (pySim ``saip/__init__.py``
    ``file_content_from_tuples`` line 414+). The local fallback uses
    the SEEK_CUR semantic for ``fillFileOffset`` (pySim line 432:
    ``stream.seek(v, os.SEEK_CUR)``) — a delta from the current write
    head, NOT an absolute offset.
    """
    fp_lower = str(field_path or "").strip().lower()
    sk_lower = str(section_key or "").strip().lower()
    fid_upper = str(file_id or "").strip().upper()
    if fp_lower == "" or file_value is None:
        return (None, None)
    try:
        from Tools.ProfilePackage.saip_asn1_decode import (
            _bytes_from_tagged_or_raw,
            _int_from_scalar_or_text,
            _tuple_payload_items,
            _record_layout_from_descriptor_payload,
            _decode_known_ef_payload,
        )
    except ImportError:
        return (None, None)

    descriptor_payload: dict[str, Any] | None = None
    fill_chunks: list[tuple[int, bytes]] = []
    current_offset = 0
    # SEEK_CUR semantic: ``fillFileOffset(v)`` advances the write head
    # by ``v`` bytes. pySim ``saip/__init__.py`` line 432:
    # ``stream.seek(v, os.SEEK_CUR)``. Both this dispatcher and the
    # TUI's ``_decode_arr_records_from_descriptor_and_chunks`` used to
    # treat the value as absolute, which collapsed every record after
    # the first into the same slot.
    for tag_name, payload in _tuple_payload_items(file_value):
        if tag_name == "fileDescriptor" and isinstance(payload, dict):
            descriptor_payload = payload
            continue
        if tag_name == "fillFileOffset":
            offset_value = _int_from_scalar_or_text(payload)
            if offset_value is not None:
                current_offset += int(offset_value)
            continue
        if tag_name != "fillFileContent":
            continue
        content_bytes = _bytes_from_tagged_or_raw(payload)
        if content_bytes is None:
            continue
        fill_chunks.append((current_offset, content_bytes))
        current_offset += len(content_bytes)

    record_length: int | None = None
    record_count: int | None = None
    file_size: int | None = None
    if descriptor_payload is not None:
        record_length, record_count, file_size = (
            _record_layout_from_descriptor_payload(descriptor_payload)
        )

    # Best path: use pySim's File.body directly. That applies the
    # TCA template's default_val pattern to the full file_size before
    # overlaying the package's fillFileContent / fillFileOffset diffs.
    # Records that the package never explicitly writes (the test
    # profile's records 3..22 of EF.ARR, populated only by the
    # template default) end up with the template-default bytes, not
    # all-FF — which is what the on-card image actually carries.
    body_from_pe = _file_body_from_pe(
        pes=pes,
        decoded_document=decoded_document,
        section_key=section_key,
        field_path=field_path,
    )
    if body_from_pe is not None:
        body_bytes, body_rec_len, body_nb_rec, body_size = body_from_pe
        if body_rec_len is not None and body_rec_len > 0:
            record_length = int(body_rec_len)
        if body_nb_rec is not None and body_nb_rec > 0:
            record_count = int(body_nb_rec)
        if body_size is not None and body_size > 0:
            file_size = int(body_size)
        raw = bytearray(body_bytes)
        return _slice_and_decode(
            raw=raw,
            record_length=record_length,
            record_count=record_count,
            file_size=file_size,
            ef_key=fp_lower,
            fid=fid_upper,
            parent_hint=sk_lower,
            decode_known_ef_payload=_decode_known_ef_payload,
        )

    # Fallback: rebuild from the tuple list. This path is hit when
    # the session never built a pySim File for this entry (rare —
    # JSON-loaded packages also feed through ``ProfileElementSequence``
    # so File objects are populated). It does NOT apply template
    # defaults; trailing records will read as FF-only and be flagged
    # ``empty``.
    if len(fill_chunks) == 0 and (file_size is None or file_size <= 0):
        return (None, None)
    max_end = 0
    for off, blob in fill_chunks:
        end = int(off) + len(blob)
        if end > max_end:
            max_end = end

    is_record_fixed = (
        isinstance(record_length, int)
        and record_length > 0
    )
    total_records: int = 0
    if is_record_fixed:
        if isinstance(record_count, int) and record_count > 0:
            total_records = int(record_count)
        else:
            provisional = max(int(file_size or 0), max_end)
            if provisional <= 0:
                provisional = max_end
            if provisional > 0 and int(record_length) > 0:
                total_records = (provisional + int(record_length) - 1) // int(record_length)
            if total_records <= 0:
                total_records = 1

    record_layout_floor = (
        int(record_length) * int(total_records)
        if is_record_fixed and total_records > 0
        else 0
    )
    buffer_size = max(int(file_size or 0), max_end, record_layout_floor)
    if buffer_size <= 0:
        return (None, None)
    raw = bytearray(b"\xFF" * buffer_size)
    for off, blob in fill_chunks:
        start = max(0, int(off))
        end = start + len(blob)
        if end > len(raw):
            raw.extend(b"\xFF" * (end - len(raw)))
        raw[start:end] = blob

    return _slice_and_decode(
        raw=raw,
        record_length=record_length,
        record_count=total_records if is_record_fixed else record_count,
        file_size=file_size,
        ef_key=fp_lower,
        fid=fid_upper,
        parent_hint=sk_lower,
        decode_known_ef_payload=_decode_known_ef_payload,
    )


def _slice_and_decode(
    *,
    raw: bytearray,
    record_length: int | None,
    record_count: int | None,
    file_size: int | None,
    ef_key: str,
    fid: str,
    parent_hint: str,
    decode_known_ef_payload,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]] | None]:
    """Slice ``raw`` into records (when record-fixed) or decode whole."""
    is_record_fixed = (
        isinstance(record_length, int)
        and record_length > 0
        and isinstance(record_count, int)
        and record_count > 0
    )
    if is_record_fixed:
        records: list[dict[str, Any]] = []
        for record_number in range(1, int(record_count) + 1):
            start = (record_number - 1) * int(record_length)
            end = start + int(record_length)
            if start >= len(raw):
                records.append({"record": record_number, "empty": True})
                continue
            slice_bytes = bytes(raw[start:end])
            is_empty = all(byte_value == 0xFF for byte_value in slice_bytes)
            entry: dict[str, Any] = {"record": record_number, "empty": is_empty}
            if not is_empty:
                decoded = decode_known_ef_payload(
                    ef_key=ef_key,
                    fid=fid,
                    hex_clean=slice_bytes.hex(),
                    parent_hint=parent_hint,
                )
                if isinstance(decoded, dict):
                    entry["decoded"] = _jsonify_decoded(decoded)
            records.append(entry)
        return (None, records)

    decoded = decode_known_ef_payload(
        ef_key=ef_key,
        fid=fid,
        hex_clean=bytes(raw).hex(),
        parent_hint=parent_hint,
    )
    if isinstance(decoded, dict):
        return (_jsonify_decoded(decoded), None)
    return (None, None)


def _file_body_from_pe(
    *,
    pes: Any,
    decoded_document: dict[str, Any] | None,
    section_key: str,
    field_path: str,
) -> tuple[bytes, int | None, int | None, int | None] | None:
    """Resolve the pySim ``File`` for ``section_key/field_path`` and return
    ``(body, rec_len, nb_rec, file_size)`` or ``None`` if not available.

    pySim's ``File.body`` is the linearized on-card image after
    ``file_content_from_tuples`` applies the template's ``default_val``
    pattern to ``file_size`` bytes and then overlays the package's
    diffs (pySim ``saip/__init__.py`` line 414+). Using it sidesteps
    the SEEK_CUR / template-default interpretation that the local
    reconstruction has historically gotten wrong.
    """
    if pes is None:
        return None
    sections = (decoded_document or {}).get("sections") or {}
    section_keys = list(sections.keys())
    try:
        idx = section_keys.index(str(section_key))
    except ValueError:
        return None
    pe_list = getattr(pes, "pe_list", None)
    if pe_list is None or idx < 0 or idx >= len(pe_list):
        return None
    pe = pe_list[idx]
    files_attr = getattr(pe, "files", None)
    if not isinstance(files_attr, dict):
        return None
    pe_file = files_attr.get(str(field_path))
    if pe_file is None:
        return None
    try:
        body = pe_file.body
    except Exception:  # noqa: BLE001
        return None
    if body is None:
        return None
    rec_len = getattr(pe_file, "rec_len", None)
    nb_rec = getattr(pe_file, "nb_rec", None)
    try:
        size_val = pe_file.file_size
    except Exception:  # noqa: BLE001
        size_val = None
    return (
        bytes(body),
        int(rec_len) if isinstance(rec_len, int) and rec_len > 0 else None,
        int(nb_rec) if isinstance(nb_rec, int) and nb_rec > 0 else None,
        int(size_val) if isinstance(size_val, int) and size_val > 0 else None,
    )


def _jsonify_decoded(value: Any) -> Any:
    """Coerce a decoder payload into a JSON-safe shape.

    Decoder dicts occasionally carry ``bytes``, ``bytearray``, or ``set``
    values. ``json.dumps`` rejects all three, so we walk the structure
    once and substitute hex / list equivalents. Other primitive types
    (str / int / float / bool / None) and nested dicts / lists pass
    through unchanged.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, sub in value.items():
            out[str(key)] = _jsonify_decoded(sub)
        return out
    if isinstance(value, list):
        return [_jsonify_decoded(sub) for sub in value]
    if isinstance(value, tuple):
        return [_jsonify_decoded(sub) for sub in value]
    if isinstance(value, set):
        return [_jsonify_decoded(sub) for sub in sorted(value, key=lambda x: str(x))]
    if isinstance(value, (bytes, bytearray)):
        return value.hex().upper()
    return value


_HEX_LITERAL_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _unjsonify_decoded(value: Any) -> Any:
    """Inverse of ``_jsonify_decoded``.

    Walks a JSON-loaded tree and substitutes bytes-shaped hex strings
    back into ``bytes``. Dicts become ``OrderedDict`` so the inverse
    preserves the same key order operators saw on the JSON tab — pySim
    is permissive about FCP key ordering, but reviewers diffing
    re-emitted JSON expect a byte-for-byte round-trip. Strings that
    aren't even-length hex pass through unchanged: that mirrors the
    forward direction, which only hex-encodes ``bytes`` /
    ``bytearray`` values.
    """
    if isinstance(value, dict):
        out: "OrderedDict[str, Any]" = OrderedDict()
        for key, sub in value.items():
            out[str(key)] = _unjsonify_decoded(sub)
        return out
    if isinstance(value, list):
        return [_unjsonify_decoded(sub) for sub in value]
    if isinstance(value, str):
        s = value
        if len(s) > 0 and (len(s) % 2) == 0 and _HEX_LITERAL_RE.match(s) is not None:
            try:
                return bytes.fromhex(s)
            except ValueError:
                return s
        return s
    return value


def _flatten_arr_records_legacy(
    records_payload: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flatten the new ``records`` shape into the legacy ``arr_records``.

    The frontend's existing ``saipRenderArrRecordsCard`` reads
    ``record.format``, ``record.rules`` etc. directly off each entry.
    The new generalised ``records`` shape nests those under a
    ``decoded`` sub-dict so non-ARR record-fixed EFs can carry their
    own decoder payload without colliding with ARR-specific keys.
    Lift the ARR keys back to the entry root for the alias.
    """
    out: list[dict[str, Any]] = []
    for entry in records_payload or ():
        if not isinstance(entry, dict):
            continue
        flat: dict[str, Any] = {
            "record": entry.get("record"),
            "empty": bool(entry.get("empty", False)),
        }
        decoded = entry.get("decoded")
        if isinstance(decoded, dict):
            for key in (
                "format",
                "reference",
                "ruleCount",
                "rules",
                "summary",
                "parseErrorOffset",
                "remaining",
            ):
                if key in decoded:
                    flat[key] = decoded[key]
        out.append(flat)
    return out


_GFM_FIELD_PATH_RE = re.compile(
    r"^fileManagementCMD\[(\d+)\]\[(\d+)\]$"
)


def _locate_gfm_file_payload(
    section_payload: Any,
    transaction_index: int,
    cmd_index: int,
) -> Any:
    """Return a synthetic CHOICE-tuple list for a GFM-defined file.

    The synthetic list mimics the shape of a template EF —
    ``[("fileDescriptor", {...}), ("fillFileOffset", n),
    ("fillFileContent", b"..."), ...]`` — by stitching the
    ``createFCP`` payload at ``transaction[cmd_index]`` to the
    ``fillFileContent`` / ``fillFileOffset`` entries that follow it
    inside the same transaction (until the next ``createFCP`` or
    end-of-transaction). This way ``show_file`` can hand the same
    structure back to the GUI regardless of whether the file was
    created by a template PE or by Generic File Management.
    """
    if isinstance(section_payload, dict) is False:
        return None
    fmc = section_payload.get("fileManagementCMD")
    if isinstance(fmc, list) is False:
        return None
    if transaction_index < 0 or transaction_index >= len(fmc):
        return None
    transaction = fmc[transaction_index]
    if isinstance(transaction, list) is False:
        return None
    if cmd_index < 0 or cmd_index >= len(transaction):
        return None
    head = transaction[cmd_index]
    if not (
        isinstance(head, tuple)
        and len(head) == 2
        and head[0] == "createFCP"
    ):
        return None
    fcp_payload = head[1] if isinstance(head[1], dict) else {}
    synthetic: list[tuple[str, Any]] = [("fileDescriptor", fcp_payload)]
    cursor = cmd_index + 1
    while cursor < len(transaction):
        entry = transaction[cursor]
        if not (
            isinstance(entry, tuple)
            and len(entry) == 2
            and isinstance(entry[0], str)
        ):
            cursor += 1
            continue
        if entry[0] in ("filePath", "createFCP"):
            break
        if entry[0] in ("fillFileContent", "fillFileOffset"):
            synthetic.append(entry)
        cursor += 1
    return synthetic


def _locate_file_payload(
    decoded_document: dict[str, Any],
    *,
    section_key: str,
    field_path: str,
) -> Any:
    """Walk back through the document to return the raw payload dict.

    Three resolution layers, tried in order:

    1. GFM synthetic field paths (``fileManagementCMD[i][j]``) are
       dispatched to :func:`_locate_gfm_file_payload`, which stitches
       the matching ``createFCP`` to its trailing ``fillFile*`` entries.
    2. The linter's canonicalised dotted walk (works on most templates).
    3. Direct dict lookup against the section payload (fallback for
       packages where the walker did not surface the row).
    """
    sections = decoded_document.get("sections") or {}
    if section_key not in sections:
        return None
    if str(section_key).lower().startswith("genericfilemanagement"):
        match = _GFM_FIELD_PATH_RE.match(str(field_path or ""))
        if match is not None:
            return _locate_gfm_file_payload(
                sections[section_key],
                int(match.group(1)),
                int(match.group(2)),
            )
    from Tools.ProfilePackage.lint_engine import SaipProfileLinter

    linter = SaipProfileLinter(strict=False)
    for path, value in linter._walk_with_path(sections[section_key]):  # noqa: SLF001
        if str(path) == field_path:
            return value

    section_payload = sections[section_key]
    if isinstance(section_payload, dict) and field_path in section_payload:
        return section_payload[field_path]
    return None


def _dispatch_validate(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    strict: Any = None,
) -> dict[str, Any]:
    """Run the SAIP linter on the loaded package and return a findings list."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.lint_engine import SaipProfileLinter

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    strict_flag = bool(strict) if strict is not None else False

    handle = get_manager().claim(sid)
    source_path = handle.get("source_path") or "(in-memory package)"

    linter = SaipProfileLinter(strict=strict_flag)
    report = linter.lint_decoded_document(
        handle["decoded_document"],
        profile_label=str(source_path),
    )
    report_dict = report.to_dict()

    # SA-G5: build click-to-jump indexes so the GUI can route from a
    # finding row straight to either the PE in the Profile Elements
    # tab or the file in the File System tab. The maps are computed
    # once per validate call rather than per-finding.
    pe_index_by_section, file_keys = _build_validation_jump_indexes(handle)

    # Project into the shape the frontend "findings" renderer expects.
    findings: list[dict[str, Any]] = []
    for item in report_dict.get("findings", []):
        path_text = str(item.get("path", ""))
        target = _resolve_finding_target(
            path_text=path_text,
            pe_index_by_section=pe_index_by_section,
            file_keys=file_keys,
        )
        finding = {
            "code": item.get("code", ""),
            "severity": item.get("severity", "INFO"),
            "spec": item.get("spec", ""),
            "path": path_text,
            "message": item.get("message", ""),
            "recommendation": item.get("recommendation", ""),
            # SA-G5 — only emit the resolved keys when we found a
            # match so the frontend's "is this clickable?" check is
            # a simple ``finding.pe_index !== undefined``.
        }
        if target.get("pe_index") is not None:
            finding["pe_index"] = target["pe_index"]
        if target.get("section_key"):
            finding["section_key"] = target["section_key"]
        if target.get("field_path"):
            finding["field_path"] = target["field_path"]
        findings.append(finding)
    return {
        "session_id": sid,
        "profile": report_dict.get("profile", source_path),
        "strict": report_dict.get("strict", strict_flag),
        "score": report_dict.get("score", 0),
        "summary": report_dict.get("summary", {}),
        "count": len(findings),
        "findings": findings,
    }


def _build_validation_jump_indexes(
    handle: dict[str, Any],
) -> tuple[dict[str, int], frozenset[tuple[str, str]]]:
    """Index PEs by section_key and enumerate (section_key, field_path) files.

    ``pe_index_by_section`` is keyed by lowercase section so case-style
    drift between the linter and the PE list (``Header`` vs ``header``)
    doesn't break the lookup. ``file_keys`` carries the canonical case
    so the frontend can drive ``saip.show_file`` without re-resolving.
    """
    pe_index_by_section: dict[str, int] = {}
    pes = handle.get("pes")
    if pes is not None and hasattr(pes, "pe_list"):
        # ProfileElementSequence emits one section per PE; the section
        # key matches the PE type for top-level PEs (header / mf /
        # usim / opt-usim / telecom / gsm-access / securityDomain /
        # rfm / akaParameter / ...). We register both the bare type
        # and any explicit ``section_key`` attribute so heuristic
        # callers don't have to know which form the linter emitted.
        for idx, pe in enumerate(pes.pe_list):
            pe_type = str(getattr(pe, "type", "") or "").strip().lower()
            if pe_type and pe_type not in pe_index_by_section:
                pe_index_by_section[pe_type] = idx
            for attr_name in ("section_key", "section", "key"):
                attr_value = getattr(pe, attr_name, None)
                if isinstance(attr_value, str) and attr_value.strip():
                    key = attr_value.strip().lower()
                    if key not in pe_index_by_section:
                        pe_index_by_section[key] = idx
    decoded_document = handle.get("decoded_document") or {}
    file_keys = frozenset(
        (str(row["section_key"]), str(row["field_path"]))
        for row in _file_definitions(decoded_document)
    )
    return pe_index_by_section, file_keys


# Linter ``path`` strings that don't map to a PE / file by design.
# These are document-level or sequence-level findings (PE order,
# service-coverage rollups, document totals) — we leave them
# unrouted so the GUI shows them in the dock without a Jump button.
_VALIDATION_NON_ROUTABLE_PATHS: frozenset[str] = frozenset(
    {
        "",
        "sections",
        "pe-order",
        "document",
        "summary",
    }
)


def _resolve_finding_target(
    *,
    path_text: str,
    pe_index_by_section: dict[str, int],
    file_keys: frozenset[tuple[str, str]],
) -> dict[str, Any]:
    """Map a linter ``path`` string onto pe_index / section_key / field_path.

    Recognised patterns (per the in-tree ``SaipProfileLinter`` output):

    * ``"<section>"``  — bare PE section (``header`` / ``mf`` / ``usim`` …)
    * ``"<section>.<field>"`` — section-rooted field path
    * ``"<section>::<field>"`` — explicit file key (linter forward-compat)
    * ``"service:<name>"`` — service rollup; not routable
    * Anything in :data:`_VALIDATION_NON_ROUTABLE_PATHS` — left unrouted

    Falls through to ``{}`` when no pattern matches.
    """
    raw = (path_text or "").strip()
    if raw == "" or raw.lower() in _VALIDATION_NON_ROUTABLE_PATHS:
        return {}

    # Explicit "section::field" form. Treat as definitive.
    if "::" in raw:
        sec, _, field = raw.partition("::")
        sec = sec.strip()
        field = field.strip()
        if (sec, field) in file_keys:
            target: dict[str, Any] = {"section_key": sec, "field_path": field}
            pe_idx = pe_index_by_section.get(sec.lower())
            if pe_idx is not None:
                target["pe_index"] = pe_idx
            return target

    # ``service:foo`` rollups carry no PE / file scope by design.
    if raw.lower().startswith("service:"):
        return {}

    # Try ``<section>.<field>`` first — split on the first dot only,
    # so paths like ``header.connectivityParameters.spnDisplayCondition``
    # still anchor on the top-level section.
    section_candidate: str | None = None
    field_candidate: str | None = None
    if "." in raw:
        section_candidate, _, field_candidate = raw.partition(".")
        section_candidate = section_candidate.strip()
        field_candidate = field_candidate.strip()
    else:
        section_candidate = raw

    target: dict[str, Any] = {}
    if section_candidate:
        sec_lo = section_candidate.lower()
        pe_idx = pe_index_by_section.get(sec_lo)
        if pe_idx is not None:
            target["pe_index"] = pe_idx
            target["section_key"] = section_candidate
    if (
        section_candidate
        and field_candidate
        and (section_candidate, field_candidate) in file_keys
    ):
        # Strong match: the (section, field) tuple resolves to a known
        # file row, so we surface both the file route + the PE route.
        target["section_key"] = section_candidate
        target["field_path"] = field_candidate
    return target


def _dispatch_close_package(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    closed = get_manager().close(sid)
    return {
        "session_id": sid,
        "closed": bool(closed),
    }


# -- SA-3 editor dispatchers -------------------------------------------


def _dispatch_get_dirty(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Report which PEs are currently dirty (unsaved)."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    raw_dirty = sorted(int(idx) for idx in handle["dirty_pes"])
    keys = _sections_by_pe_index(handle["decoded_document"])
    pe_indices = [i for i in raw_dirty if i >= 0]
    sequence_wide = any(i < 0 for i in raw_dirty)
    return {
        "session_id": sid,
        "dirty": len(raw_dirty) > 0,
        "count": len(raw_dirty),
        "pe_indices": pe_indices,
        "sequence_wide": sequence_wide,
        "section_keys": [keys[i] for i in pe_indices if 0 <= i < len(keys)],
    }


def _dispatch_update_file_field(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    field_path: Any = None,
    sub_key: Any = None,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Mutate a single file-definition sub-field (hex-encoded)."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    section = str(section_key or "").strip()
    path_text = str(field_path or "").strip()
    sub = str(sub_key or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(section) == 0:
        raise ValueError("section_key is required.")
    if len(path_text) == 0:
        raise ValueError("field_path is required.")
    if sub not in _EDITABLE_SUB_FIELDS:
        raise ValueError(
            f"sub_key {sub!r} is not editable in SA-3. "
            f"Allowed: {sorted(_EDITABLE_SUB_FIELDS)}"
        )

    new_bytes = _normalise_hex_input(hex_value)
    _validate_sub_field_value(sub, new_bytes)

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pe_index = _resolve_pe_index(handle, section)
    pe = handle["pes"].pe_list[pe_index]

    choice_list = _mutable_file_choice_list_for_path(pe, path_text)
    applied = _apply_hex_mutation(choice_list, sub, new_bytes)
    if applied is False:
        raise LookupError(
            f"no CHOICE payload carrying {sub!r} under "
            f"{section}::{path_text}."
        )

    _mark_dirty(handle, pe_index)
    _refresh_decoded_document(handle)

    # Return the refreshed row summary so the GUI can update the table
    # without a full list_files round-trip.
    refreshed_payload = _locate_file_payload(
        handle["decoded_document"],
        section_key=section,
        field_path=path_text,
    )
    refreshed_row = _summarise_file_choices(refreshed_payload)
    return {
        "session_id": sid,
        "section_key": section,
        "field_path": path_text,
        "sub_key": sub,
        "new_hex": new_bytes.hex().upper(),
        "pe_index": pe_index,
        "dirty_pe_count": len(handle["dirty_pes"]),
        "row": refreshed_row,
    }


def _dispatch_update_record_bytes(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    field_path: Any = None,
    record_index: Any = None,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Splice a record's bytes into a linear-fixed / cyclic file.

    Mutates ``pe_file.body`` directly and re-emits the data tuples
    (``fillFileContent`` / ``fillFileOffset``) via pySim's
    ``file_content_to_tuples(optimize=True)``. Non-data tuples in the
    CHOICE list (``fileDescriptor`` and friends) survive untouched
    so shortEFID, lcsi, proprietaryEFInfo etc remain in place.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    section = str(section_key or "").strip()
    path_text = str(field_path or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(section) == 0:
        raise ValueError("section_key is required.")
    if len(path_text) == 0:
        raise ValueError("field_path is required.")
    try:
        rec_idx = int(record_index)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "record_index must be a 1-based integer."
        ) from error
    if rec_idx < 1:
        raise ValueError("record_index must be >= 1.")

    new_bytes = _normalise_hex_input(hex_value)

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pe_index = _resolve_pe_index(handle, section)
    pe = handle["pes"].pe_list[pe_index]

    files_attr = getattr(pe, "files", None)
    if not isinstance(files_attr, dict):
        raise LookupError(
            f"PE at {section!r} does not expose a files dict."
        )
    pe_file = files_attr.get(path_text)
    if pe_file is None:
        raise LookupError(
            f"no File object for {section}::{path_text}."
        )

    file_type = getattr(pe_file, "file_type", None)
    if file_type not in ("LF", "CY"):
        raise ValueError(
            f"file is not record-fixed (file_type={file_type!r}); "
            f"use saip.update_file_field for transparent / DF rewrites."
        )

    rec_len = getattr(pe_file, "rec_len", None)
    if not isinstance(rec_len, int) or rec_len <= 0:
        raise ValueError("file has no record length declared.")
    if len(new_bytes) != rec_len:
        raise ValueError(
            f"hex_value must be exactly {rec_len} B "
            f"(got {len(new_bytes)} B)."
        )
    nb_rec = getattr(pe_file, "nb_rec", None)
    if isinstance(nb_rec, int) and nb_rec > 0 and rec_idx > nb_rec:
        raise ValueError(
            f"record_index {rec_idx} exceeds nb_rec={nb_rec}."
        )

    body = bytearray(pe_file.body or b"")
    start = (rec_idx - 1) * rec_len
    end = start + rec_len
    if end > len(body):
        # Pad with FF up to the record's end (post-personalisation
        # default for unwritten record slots, TS 102 222 §6.x).
        body.extend(b"\xFF" * (end - len(body)))
    body[start:end] = new_bytes
    pe_file.body = bytes(body)

    new_data_tuples = list(pe_file.file_content_to_tuples(optimize=True))

    data_keys = {"fillFileContent", "fillFileOffset", "doNotCreate"}
    existing = pe.decoded.get(path_text)
    if not isinstance(existing, list):
        existing = []
    kept: list[Any] = []
    for item in existing:
        if (isinstance(item, tuple) and len(item) == 2
                and str(item[0]) in data_keys):
            continue
        kept.append(item)
    pe.decoded[path_text] = kept + new_data_tuples

    _mark_dirty(handle, pe_index)
    _refresh_decoded_document(handle)

    return {
        "session_id": sid,
        "section_key": section,
        "field_path": path_text,
        "record_index": rec_idx,
        "record_size": rec_len,
        "new_hex": new_bytes.hex().upper(),
        "pe_index": pe_index,
        "dirty_pe_count": len(handle["dirty_pes"]),
    }


def _dispatch_update_file_decoded(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    field_path: Any = None,
    payload: Any = None,
) -> dict[str, Any]:
    """Replace ``pe.decoded[field_path]`` with the supplied JSON tree.

    The frontend's JSON tab projects every file's CHOICE list through
    ``_jsonify_decoded``. This dispatcher applies the inverse — it
    walks the JSON, substitutes hex strings back into ``bytes``, and
    drops the result onto ``pe.decoded``. The corresponding
    ``pe.files[field_path]`` is then re-hydrated from the new tuple
    list (``pySim File.from_tuples`` runs ``file_content_from_tuples``
    end-to-end), so subsequent ``saip.show_file`` calls see the new
    body bytes immediately.

    Companion to ``saip.update_file_content`` (whole-body hex splice)
    and ``saip.update_record_bytes`` (per-record splice). Use this
    one when the operator needs to edit FCP fields, swap descriptor
    tags, or otherwise restructure the CHOICE list — e.g. flipping
    a doNotCreate marker on a clone, or surgically rewriting the
    ``proprietaryEFInfo`` block from JSON.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    section = str(section_key or "").strip()
    path_text = str(field_path or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(section) == 0:
        raise ValueError("section_key is required.")
    if len(path_text) == 0:
        raise ValueError("field_path is required.")
    if not isinstance(payload, list):
        raise ValueError(
            "payload must be a list of [name, value] pairs "
            "(matching the JSON projection from saip.show_file)."
        )

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pe_index = _resolve_pe_index(handle, section)
    pe = handle["pes"].pe_list[pe_index]

    if path_text not in pe.decoded:
        raise LookupError(
            f"no decoded entry for {section}::{path_text}; "
            f"only existing files can be JSON-edited."
        )

    new_choices: list[tuple[str, Any]] = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise ValueError(
                f"entry #{index} is not a [name, value] pair "
                f"(got {type(entry).__name__})."
            )
        name = entry[0]
        value = entry[1]
        if not isinstance(name, str) or len(name) == 0:
            raise ValueError(
                f"entry #{index} carries a non-string CHOICE name "
                f"({name!r})."
            )
        new_choices.append((str(name), _unjsonify_decoded(value)))

    pe.decoded[path_text] = new_choices

    files_attr = getattr(pe, "files", None)
    if isinstance(files_attr, dict):
        pe_file = files_attr.get(path_text)
        if pe_file is not None:
            try:
                pe_file.from_tuples(new_choices)
            except Exception as error:  # noqa: BLE001 — pySim raises ValueError + AttributeError
                raise ValueError(
                    f"pySim rejected the new tuple list: {error}"
                ) from error

    _mark_dirty(handle, pe_index)
    _refresh_decoded_document(handle)

    return {
        "session_id": sid,
        "section_key": section,
        "field_path": path_text,
        "tuple_count": len(new_choices),
        "tuple_names": [name for name, _ in new_choices],
        "pe_index": pe_index,
        "dirty_pe_count": len(handle["dirty_pes"]),
    }


def _dispatch_update_file_content(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    field_path: Any = None,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Replace a transparent / BER-TLV EF's body bytes wholesale.

    Companion to ``saip.update_record_bytes``. The two cover the
    record-fixed and non-record EF cases respectively. Both rely on
    pySim ``File.body`` + ``file_content_to_tuples(optimize=True)``
    to round-trip the in-memory package.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    section = str(section_key or "").strip()
    path_text = str(field_path or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(section) == 0:
        raise ValueError("section_key is required.")
    if len(path_text) == 0:
        raise ValueError("field_path is required.")

    new_bytes = _normalise_hex_input(hex_value)

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pe_index = _resolve_pe_index(handle, section)
    pe = handle["pes"].pe_list[pe_index]

    files_attr = getattr(pe, "files", None)
    if not isinstance(files_attr, dict):
        raise LookupError(
            f"PE at {section!r} does not expose a files dict."
        )
    pe_file = files_attr.get(path_text)
    if pe_file is None:
        raise LookupError(
            f"no File object for {section}::{path_text}."
        )

    file_type = getattr(pe_file, "file_type", None)
    if file_type not in ("TR", "BT"):
        raise ValueError(
            f"file is not transparent / BER-TLV (file_type={file_type!r}); "
            f"use saip.update_record_bytes for record-fixed EFs."
        )

    declared_size = None
    try:
        declared_size = pe_file.file_size
    except Exception:  # noqa: BLE001 — pySim accessor may raise on missing FCP
        declared_size = None
    if isinstance(declared_size, int) and declared_size > 0:
        if len(new_bytes) > declared_size:
            raise ValueError(
                f"hex_value too long ({len(new_bytes)} B) — "
                f"file_size declares {declared_size} B."
            )
        if len(new_bytes) < declared_size:
            # Pad short writes with FF up to the declared size so the
            # on-card image stays consistent with the FCP.
            new_bytes = new_bytes + b"\xFF" * (declared_size - len(new_bytes))

    pe_file.body = bytes(new_bytes)
    new_data_tuples = list(pe_file.file_content_to_tuples(optimize=True))

    data_keys = {"fillFileContent", "fillFileOffset", "doNotCreate"}
    existing = pe.decoded.get(path_text)
    if not isinstance(existing, list):
        existing = []
    kept: list[Any] = []
    for item in existing:
        if (isinstance(item, tuple) and len(item) == 2
                and str(item[0]) in data_keys):
            continue
        kept.append(item)
    pe.decoded[path_text] = kept + new_data_tuples

    _mark_dirty(handle, pe_index)
    _refresh_decoded_document(handle)

    return {
        "session_id": sid,
        "section_key": section,
        "field_path": path_text,
        "new_hex": new_bytes.hex().upper(),
        "byte_count": len(new_bytes),
        "pe_index": pe_index,
        "dirty_pe_count": len(handle["dirty_pes"]),
    }


_SAVE_PACKAGE_FORMATS: tuple[str, ...] = ("der", "hex", "json")
_SAVE_PACKAGE_DEFAULT_EXTS: dict[str, str] = {
    "der": ".der",
    "hex": ".hex",
    "json": ".json",
}


def _dispatch_save_package(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    output_path: Any = None,
    format: Any = None,  # noqa: A002 — GUI facing param name
    clear_dirty: Any = None,
    overwrite: Any = None,
) -> dict[str, Any]:
    """Write the current in-memory package out to disk.

    ``format`` choices (manual's "Save As" dialog):
      * ``der`` — binary DER, default extension ``.der``.
      * ``hex`` — ASCII hex of the DER, default ``.hex``. Round-
        trippable through ``saip.open_package``.
      * ``json`` — transcoded JSON document, default ``.json``.
        Preserves PE names / variable references the DER format
        cannot carry.

    By default refuses to overwrite an existing target — pass
    ``overwrite=true`` to replace. The format-default extension is
    appended when the supplied path has no suffix.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    out_text = str(output_path or "").strip()
    fmt = str(format or "der").strip().lower()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(out_text) == 0:
        raise ValueError("output_path is required.")
    if fmt not in _SAVE_PACKAGE_FORMATS:
        raise ValueError(
            f"format must be one of {', '.join(_SAVE_PACKAGE_FORMATS)} (got {fmt!r}).",
        )
    overwrite_flag = bool(overwrite) if overwrite is not None else False

    out_path = Path(os.path.expanduser(out_text)).resolve()
    if out_path.suffix == "":
        out_path = out_path.with_suffix(_SAVE_PACKAGE_DEFAULT_EXTS[fmt])
    if out_path.exists() and overwrite_flag is False:
        raise FileExistsError(
            f"target already exists (pass overwrite=true to replace): {out_path}",
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pes = handle["pes"]
    warnings: list[str] = []

    if fmt == "der":
        data = pes.to_der()
        out_path.write_bytes(data)
        size = len(data)
        warnings.append(
            "DER format does not carry PE names, formatting, or "
            "variable references; round-trip via JSON to preserve those.",
        )
    elif fmt == "hex":
        data = pes.to_der()
        text = data.hex().upper() + "\n"
        out_path.write_text(text, encoding="utf-8")
        size = len(text.encode("utf-8"))
        warnings.append(
            "Hex DER preserves the wire bytes but drops PE names / "
            "formatting / variable references (same as binary DER).",
        )
    else:
        _refresh_decoded_document(handle)
        doc = handle["decoded_document"]
        _ensure_pysim_importable()
        from Tools.ProfilePackage.saip_json_codec import jsonify_document

        tagged = jsonify_document(doc)
        text = json.dumps(tagged, indent=2, ensure_ascii=False)
        out_path.write_text(text, encoding="utf-8")
        size = len(text.encode("utf-8"))

    if bool(clear_dirty) if clear_dirty is not None else True:
        handle["dirty_pes"] = set()

    return {
        "session_id": sid,
        "output_path": str(out_path),
        "format": fmt,
        "size_bytes": size,
        "pe_count": len(pes.pe_list),
        "dirty_cleared": bool(clear_dirty) if clear_dirty is not None else True,
        "warnings": warnings,
    }


def _dispatch_revert_changes(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Reload the on-disk source; drop any in-memory edits."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    handle = get_manager().claim(sid)
    _reload_source_into_handle(handle)
    return {
        "session_id": sid,
        "source_path": handle["source_path"],
        "pe_count": len(handle["pes"].pe_list),
        "dirty": False,
    }


# ----------------------------------------------------------------------
# Decoded-editor surface (Tools/ProfilePackage/saip_decoded_edit.py)
#
# The hex-only ``saip.update_file_field`` action exposes the raw
# tagged-bytes substitution the SA-3 slice shipped with. That surface
# remains useful for power users (descriptor / link-path / pin-status
# mutations stay byte-accurate), but it forces the operator to know the
# encoding of every field in advance — typing IMSI digits, ICCID
# digits, LCSI states, USIM service flags, or even a 16-bit FID via
# raw hex is unforgiving.
#
# The dispatchers below thread the much richer decoded-editor model
# from :mod:`Tools.ProfilePackage.saip_decoded_edit` into the GUI:
#
# * :func:`_dispatch_list_decoded_fields` returns every decodable field
#   in a section together with a per-field editor model (hand-written
#   editor, registered round-trip encoder, read-only decoder, or
#   raw-hex fallback). Each entry carries the JSON-codec relative path
#   so the apply step can splice without re-walking the document.
#
# * :func:`_dispatch_apply_decoded_edit` encodes the operator-supplied
#   payload through ``encode_decoded_value_editor_payload``, splices
#   the result into the tagged JSON document at the supplied
#   ``rel_path``, re-builds the in-memory ``ProfileElementSequence``
#   via ``build_profile_sequence_from_document``, refreshes the cached
#   document, and marks the owning PE dirty.
#
# Both dispatchers operate on the **tagged** JSON projection
# (``jsonify_document(decoded_document)``) so the rel_path emitted by
# ``enumerate_pe_decodable_fields`` lines up byte-for-byte with the
# splice target. The native pySim form is rebuilt from the modified
# tagged document only at the very end of the apply step.
# ----------------------------------------------------------------------


def _splice_tagged_value_at_rel_path(
    section_value: Any,
    rel_path: list[Any],
    encoded_value: Any,
) -> None:
    """Replace the value at ``rel_path`` inside ``section_value``.

    Mutates ``section_value`` in place. Integer segments index into a
    list, string segments key into a dict. The function refuses to
    create new keys or extend lists — every intermediate segment must
    already exist on the tagged document (a missing slot would mean
    the operator's editor model was built against a different
    document version, which is recoverable only by re-running
    ``saip.list_decoded_fields``).
    """
    if isinstance(rel_path, list) is False:
        raise ValueError("rel_path must be a list of segments.")
    if len(rel_path) == 0:
        raise ValueError("rel_path cannot be empty.")
    cursor = section_value
    for idx, segment in enumerate(rel_path):
        is_last = idx == len(rel_path) - 1
        if isinstance(segment, int) and isinstance(segment, bool) is False:
            if isinstance(cursor, list) is False:
                raise ValueError(
                    f"rel_path[{idx}] expected list, got {type(cursor).__name__}."
                )
            if segment < 0 or segment >= len(cursor):
                raise ValueError(
                    f"rel_path[{idx}]={segment} is out of range "
                    f"(len={len(cursor)})."
                )
            if is_last:
                cursor[segment] = encoded_value
                return
            cursor = cursor[segment]
            continue
        seg_text = str(segment)
        if isinstance(cursor, dict) is False:
            raise ValueError(
                f"rel_path[{idx}] expected dict, got {type(cursor).__name__}."
            )
        if seg_text not in cursor:
            raise ValueError(
                f"rel_path[{idx}] segment {seg_text!r} not present in document."
            )
        if is_last:
            cursor[seg_text] = encoded_value
            return
        cursor = cursor[seg_text]


def _project_decoded_field_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Filter a raw enumeration entry into a JSON-safe wire shape.

    Drops the ``raw_value`` field (which can hold pySim native shapes
    that ``json.dumps`` does not understand) and pins the model
    attributes the GUI needs without leaking internal mutable state.
    """
    model = entry.get("model")
    if isinstance(model, dict) is False:
        model = {}
    editor_kind = str(
        entry.get("editor_kind") or model.get("editor_kind") or "json"
    ).strip().lower() or "json"
    target_length = entry.get("target_length")
    if isinstance(target_length, bool) or isinstance(target_length, int) is False:
        target_length = model.get("target_length")
    if isinstance(target_length, bool) or isinstance(target_length, int) is False:
        target_length = None
    projected = {
        "field_name": str(entry.get("field_name", "") or ""),
        "rel_path": list(entry.get("rel_path") or []),
        "last_ef_key": entry.get("last_ef_key"),
        "pe_section_key": entry.get("pe_section_key"),
        "display_path": str(entry.get("display_path", "") or ""),
        "summary": str(entry.get("summary", "") or ""),
        "editor_kind": editor_kind,
        "target_length": target_length,
        "read_only": bool(entry.get("read_only", model.get("read_only", False))),
        "model": {
            "title": str(model.get("title", "") or ""),
            "note": str(model.get("note", "") or ""),
            "editor_kind": editor_kind,
            "payload": _jsonify_decoded(model.get("payload")),
            "target_length": target_length,
            "read_only": bool(model.get("read_only", False)),
        },
    }
    gfm_file_path = str(entry.get("gfm_file_path") or "").strip()
    if gfm_file_path:
        projected["gfm_file_path"] = gfm_file_path
    return projected


def _dispatch_list_decoded_fields(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    rel_path_prefix: Any = None,
) -> dict[str, Any]:
    """Enumerate every decodable field for a PE section.

    ``rel_path_prefix`` is an optional list of segments. When given,
    the response only includes fields whose ``rel_path`` begins with
    the supplied prefix. The frontend uses this to scope the panel to
    one selected EF (e.g. ``["ef-iccid", 0]``) without forcing the
    backend to re-walk an entire ADF for every selection.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    section = str(section_key or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(section) == 0:
        raise ValueError("section_key is required.")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    _resolve_pe_index(handle, section)  # validates the section_key.

    _ensure_pysim_importable()
    from Tools.ProfilePackage.saip_decoded_edit import (
        enumerate_pe_decodable_fields,
    )
    from Tools.ProfilePackage.saip_json_codec import jsonify_document

    tagged_doc = jsonify_document(handle["decoded_document"])
    section_value = (tagged_doc.get("sections") or {}).get(section)
    if section_value is None:
        return {
            "session_id": sid,
            "section_key": section,
            "field_count": 0,
            "fields": [],
        }

    raw_entries = enumerate_pe_decodable_fields(
        section_value,
        pe_section_key=section,
    )

    prefix: list[Any] | None = None
    if isinstance(rel_path_prefix, list) and len(rel_path_prefix) > 0:
        prefix = list(rel_path_prefix)

    projected: list[dict[str, Any]] = []
    for entry in raw_entries:
        rel_path = list(entry.get("rel_path") or [])
        if prefix is not None:
            rel_matches = len(rel_path) >= len(prefix) and rel_path[: len(prefix)] == prefix
            gfm_path = str(entry.get("gfm_file_path") or "").strip()
            gfm_matches = False
            if len(prefix) >= 3 and str(prefix[0]) == "fileManagementCMD":
                gfm_matches = gfm_path == (
                    f"fileManagementCMD[{prefix[1]}][{prefix[2]}]"
                )
            if rel_matches is False and gfm_matches is False:
                continue
        projected.append(_project_decoded_field_entry(entry))

    return {
        "session_id": sid,
        "section_key": section,
        "rel_path_prefix": list(prefix) if prefix is not None else None,
        "field_count": len(projected),
        "fields": projected,
    }


def _dispatch_apply_decoded_edit(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    rel_path: Any = None,
    field_name: Any = None,
    last_ef_key: Any = None,
    editor_kind: Any = None,
    editor_payload: Any = None,
    target_length: Any = None,
) -> dict[str, Any]:
    """Apply a decoded-editor payload to the in-memory profile element.

    Encodes the supplied payload via the SAIP encoder registry,
    splices the resulting tagged value into the section's tagged JSON
    document, rebuilds the ``ProfileElementSequence`` from the
    modified document, refreshes the cached decoded document, and
    marks the owning PE dirty.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    section = str(section_key or "").strip()
    field_text = str(field_name or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(section) == 0:
        raise ValueError("section_key is required.")
    if len(field_text) == 0:
        raise ValueError("field_name is required.")
    if isinstance(rel_path, list) is False or len(rel_path) == 0:
        raise ValueError("rel_path must be a non-empty list of segments.")
    if isinstance(editor_payload, dict) is False:
        raise ValueError("editor_payload must be an object.")

    last_ef_text = str(last_ef_key or "").strip() or None
    kind_text = str(editor_kind or "").strip().lower() or None
    target_length_value: int | None
    if isinstance(target_length, bool):
        target_length_value = None
    elif isinstance(target_length, int):
        target_length_value = int(target_length)
    elif target_length is None:
        target_length_value = None
    else:
        try:
            target_length_value = int(str(target_length), 0)
        except Exception as err:
            raise ValueError(f"target_length is not an integer: {target_length!r}") from err

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pe_index = _resolve_pe_index(handle, section)

    _ensure_pysim_importable()
    from Tools.ProfilePackage.saip_decoded_edit import (
        encode_decoded_value_editor_payload,
    )
    from Tools.ProfilePackage.saip_profile_header_edit import (
        locate_header_section,
        sync_header_iccid_from_ef,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
        dejsonify_document,
        jsonify_document,
    )

    encoded_value = encode_decoded_value_editor_payload(
        field_name=field_text,
        editor_payload=editor_payload,
        last_ef_key=last_ef_text,
        target_length=target_length_value,
        editor_kind=kind_text,
    )

    tagged_doc = jsonify_document(handle["decoded_document"])
    sections = tagged_doc.get("sections") or {}
    section_value = sections.get(section)
    if section_value is None:
        raise LookupError(f"section {section!r} missing in document.")

    _splice_tagged_value_at_rel_path(section_value, list(rel_path), encoded_value)

    restored = dejsonify_document(tagged_doc)
    header_sync_summary: str | None = None
    ef_sync_key = re.sub(r"[^a-z0-9]+", "-", str(last_ef_text or "").strip().lower()).strip("-")
    field_sync_key = re.sub(r"[^a-z0-9]+", "", field_text.strip().lower())
    if (
        ef_sync_key in ("ef-iccid", "iccid")
        and field_sync_key in ("fillfilecontent", "fillfilecontents")
    ):
        header_sync_summary = sync_header_iccid_from_ef(restored)
    pes_new = build_profile_sequence_from_document(
        restored, _workspace_root()
    )
    handle["pes"] = pes_new
    _refresh_decoded_document(handle)
    _mark_dirty(handle, pe_index)
    if header_sync_summary:
        header_section_key, _header = locate_header_section(handle["decoded_document"])
        _mark_dirty(handle, _resolve_pe_index(handle, header_section_key))

    refreshed_section = (
        handle["decoded_document"].get("sections") or {}
    ).get(section)
    refreshed_summary: dict[str, Any] | None = None
    section_payload = refreshed_section
    if (
        isinstance(rel_path, list)
        and len(rel_path) >= 1
        and isinstance(section_payload, dict)
    ):
        first_key = rel_path[0]
        if isinstance(first_key, str) and first_key in section_payload:
            refreshed_summary = _summarise_file_choices(section_payload[first_key])

    response = {
        "session_id": sid,
        "section_key": section,
        "field_name": field_text,
        "rel_path": list(rel_path),
        "last_ef_key": last_ef_text,
        "editor_kind": kind_text,
        "pe_index": pe_index,
        "dirty_pe_count": len(handle["dirty_pes"]),
        "row": refreshed_summary,
    }
    if header_sync_summary:
        response["header_sync_summary"] = header_sync_summary
    return response


def _dispatch_update_sd_parameters(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    parameter_state: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    section = str(section_key or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(section) == 0:
        raise ValueError("section_key is required.")
    if not isinstance(parameter_state, dict):
        raise ValueError("parameter_state must be an object.")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pe_index = _resolve_pe_index(handle, section)
    sections = handle["decoded_document"].get("sections") or {}
    section_value = sections.get(section)
    if not isinstance(section_value, dict):
        raise LookupError(f"section {section!r} missing in document.")

    _ensure_pysim_importable()
    mutation = _apply_sd_parameter_state_to_section(
        section_value,
        parameter_state,
    )

    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    handle["pes"] = build_profile_sequence_from_document(
        handle["decoded_document"],
        workspace_root=_workspace_root(),
    )
    _refresh_decoded_document(handle)
    _mark_dirty(handle, pe_index)

    refreshed_section = (
        handle["decoded_document"].get("sections") or {}
    ).get(section)
    refreshed_summary = (
        _application_parameter_summary(refreshed_section)
        if isinstance(refreshed_section, dict)
        else None
    )

    return {
        "session_id": sid,
        "section_key": section,
        "pe_index": pe_index,
        "changed": mutation["changed"],
        "parameter_summary": refreshed_summary,
        "dirty": True,
    }


def _resolve_section_key_from_index_or_key(
    handle: dict[str, Any],
    *,
    section_key: Any = None,
    pe_index: Any = None,
) -> tuple[str, int]:
    section = str(section_key or "").strip()
    if section:
        return section, _resolve_pe_index(handle, section)
    if pe_index is None or isinstance(pe_index, bool):
        raise ValueError("section_key or pe_index is required.")
    try:
        index = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index is not an integer: {pe_index!r}") from error
    keys = _sections_by_pe_index(handle["decoded_document"])
    if not 0 <= index < len(keys):
        raise LookupError(f"pe_index {index} is out of range.")
    return keys[index], index


def _dispatch_update_rfm_tars(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    pe_index: Any = None,
    tar_hex_list: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if not isinstance(tar_hex_list, list):
        raise ValueError("tar_hex_list must be a list.")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section, index = _resolve_section_key_from_index_or_key(
        handle,
        section_key=section_key,
        pe_index=pe_index,
    )
    sections = handle["decoded_document"].get("sections") or {}
    section_value = sections.get(section)
    if not isinstance(section_value, dict):
        raise LookupError(f"section {section!r} missing in document.")

    _ensure_pysim_importable()
    from Tools.ProfilePackage import saip_rfm_edit
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    message = saip_rfm_edit.set_tar_list(
        section_value,
        [str(item or "") for item in tar_hex_list],
    )
    handle["pes"] = build_profile_sequence_from_document(
        handle["decoded_document"],
        workspace_root=_workspace_root(),
    )
    _refresh_decoded_document(handle)
    _mark_dirty(handle, index)
    refreshed_section = (
        handle["decoded_document"].get("sections") or {}
    ).get(section)
    summary = (
        _application_parameter_summary(refreshed_section)
        if isinstance(refreshed_section, dict)
        else None
    )
    refreshed_tars = []
    if isinstance(refreshed_section, dict):
        refreshed_tars = _tar_values_from_any(refreshed_section.get("tarList"))
    return {
        "session_id": sid,
        "section_key": section,
        "pe_index": index,
        "message": message,
        "tar_list": refreshed_tars,
        "parameter_summary": summary,
        "dirty": True,
    }


# -- SA-4 compare dispatchers ------------------------------------------


def _dispatch_compare_packages(
    ctx: ActionContext,
    *,
    session_a: Any = None,
    session_b: Any = None,
) -> dict[str, Any]:
    """Compare two open SAIP sessions and return a structured diff."""
    from yggdrasim_common.gui_server.sessions import get_manager

    a_id = str(session_a or "").strip()
    b_id = str(session_b or "").strip()
    if len(a_id) == 0 or len(b_id) == 0:
        raise ValueError("session_a and session_b are required.")
    if a_id == b_id:
        raise ValueError("session_a and session_b must be different sessions.")

    manager = get_manager()
    handle_a = manager.claim(a_id)
    handle_b = manager.claim(b_id)

    pes_a = handle_a["pes"]
    pes_b = handle_b["pes"]
    keys_a = _sections_by_pe_index(handle_a["decoded_document"])
    keys_b = _sections_by_pe_index(handle_b["decoded_document"])
    digest_a = [_pe_digest(pe) for pe in pes_a.pe_list]
    digest_b = [_pe_digest(pe) for pe in pes_b.pe_list]

    set_a = set(keys_a)
    set_b = set(keys_b)
    added = sorted(set_b - set_a)
    removed = sorted(set_a - set_b)
    common = sorted(set_a & set_b)

    pe_rows: list[dict[str, Any]] = []
    for key in common:
        ia = keys_a.index(key)
        ib = keys_b.index(key)
        pe_a = pes_a.pe_list[ia]
        pe_b = pes_b.pe_list[ib]
        # For genericFileManagement PEs use the canonical diff digest so
        # index-shifted GFM command blocks don't register as changes when
        # the semantic content is identical (ETSI TS 102 222 §6 ordering
        # is irrelevant for profiles that install the same EFs).
        pe_type = str(getattr(pe_a, "type", ""))
        if pe_type == "genericFileManagement":
            changed = _gfm_canonical_digest(pe_a) != _gfm_canonical_digest(pe_b)
        else:
            changed = digest_a[ia] != digest_b[ib]
        pe_rows.append(
            {
                "section_key": key,
                "pe_index_a": ia,
                "pe_index_b": ib,
                "changed": changed,
                "type": pe_type,
            }
        )

    # File-level diff across shared sections.
    files_a = _file_definitions(handle_a["decoded_document"])
    files_b = _file_definitions(handle_b["decoded_document"])
    index_a = {(r["section_key"], r["field_path"]): r for r in files_a}
    index_b = {(r["section_key"], r["field_path"]): r for r in files_b}
    file_added = sorted(set(index_b.keys()) - set(index_a.keys()))
    file_removed = sorted(set(index_a.keys()) - set(index_b.keys()))
    file_changed: list[dict[str, Any]] = []
    for key in sorted(set(index_a.keys()) & set(index_b.keys())):
        ra = index_a[key]
        rb = index_b[key]
        if _file_row_signature(ra) == _file_row_signature(rb):
            continue
        deltas: list[dict[str, Any]] = []
        for field in (
            "file_id",
            "short_efid",
            "descriptor",
            "ef_size",
            "link_path",
            "security_attrs",
            "max_size",
        ):
            if str(ra.get(field, "")) != str(rb.get(field, "")):
                deltas.append(
                    {
                        "field": field,
                        "a": ra.get(field, ""),
                        "b": rb.get(field, ""),
                    }
                )
        file_changed.append(
            {
                "section_key": key[0],
                "field_path": key[1],
                "deltas": deltas,
            }
        )

    return {
        "session_a": a_id,
        "session_b": b_id,
        "pe_summary": {
            "added": added,
            "removed": removed,
            "common": common,
            "changed": [r["section_key"] for r in pe_rows if r["changed"]],
        },
        "pe_rows": pe_rows,
        "file_summary": {
            "added": [list(k) for k in file_added],
            "removed": [list(k) for k in file_removed],
            "changed_count": len(file_changed),
        },
        "file_changed": file_changed,
    }


# -- SA-D semantic-diff dispatchers (context-aware profile comparison) -
#
# These dispatchers sit on top of ``Tools.ProfilePackage.saip_profile_diff``
# and emit the categorised, severity-tagged diff used by the SAIP
# workbench's "Compare" view. The legacy ``saip.compare`` action above
# stays in place for callers that depend on its (raw PE / file row)
# shape — the new family only adds a richer surface alongside it.


def _jsonified_session_document(handle: dict[str, Any]) -> dict[str, Any]:
    """Return the session's decoded document in jsonified form.

    The semantic-diff engine consumes the same shape produced by
    :func:`saip_json_codec.jsonify_document` (dict/list/str only). We
    centralise the conversion here so each dispatcher avoids importing
    the codec on its own.
    """
    from Tools.ProfilePackage.saip_json_codec import jsonify_document

    document = handle.get("decoded_document")
    if isinstance(document, dict) is False:
        raise RuntimeError("Session has no decoded document; was open_package run?")
    return jsonify_document(document)


def _label_for_session(handle: dict[str, Any], fallback: str) -> str:
    """Best-effort short label for a session in diff output banners.

    Uses the source path's basename when available so the operator
    sees ``"profile_a.der"`` instead of an opaque session_id.
    """
    source = handle.get("source_path")
    if source is None or len(str(source)) == 0:
        return fallback
    return Path(str(source)).name


def _dispatch_diff_packages(
    ctx: ActionContext,
    *,
    session_a: Any = None,
    session_b: Any = None,
) -> dict[str, Any]:
    """Semantic context-aware diff between two open SAIP sessions.

    Same input shape as the legacy ``saip.compare`` action, but the
    payload is the rich ``ProfileDiffReport`` from
    :mod:`Tools.ProfilePackage.saip_profile_diff` — categorised
    entries, severity tags, human-readable summaries, and the
    underlying structural counts.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_profile_diff import compute_profile_diff

    a_id = str(session_a or "").strip()
    b_id = str(session_b or "").strip()
    if len(a_id) == 0 or len(b_id) == 0:
        raise ValueError("session_a and session_b are required.")
    if a_id == b_id:
        raise ValueError("session_a and session_b must be different sessions.")

    manager = get_manager()
    handle_a = manager.claim(a_id)
    handle_b = manager.claim(b_id)

    document_a = _jsonified_session_document(handle_a)
    document_b = _jsonified_session_document(handle_b)
    label_a = _label_for_session(handle_a, fallback=a_id)
    label_b = _label_for_session(handle_b, fallback=b_id)

    report = compute_profile_diff(
        document_a,
        document_b,
        label_a=label_a,
        label_b=label_b,
    )
    payload = report.to_dict()
    payload["session_a"] = a_id
    payload["session_b"] = b_id
    return payload


def _dispatch_diff_against_source(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Diff a session's current state against its on-disk source.

    Mirrors a ``git diff`` against the file the session was opened
    from. Pulls a fresh copy of the source via
    :func:`_load_package_from_path` (so unsaved edits in the session
    show up as the "right side" of the diff) and runs the semantic
    engine. Used by the GUI's "What did I change?" affordance.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_json_codec import jsonify_document
    from Tools.ProfilePackage.saip_profile_diff import compute_profile_diff

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")

    handle = get_manager().claim(sid)
    source = handle.get("source_path")
    if source is None or len(str(source)) == 0:
        raise RuntimeError(
            "Session has no source_path on file; cannot diff against source. "
            "Re-open the package via saip.open_package."
        )

    fresh_package = _load_package_from_path(Path(str(source)))
    fresh_document = jsonify_document(fresh_package["decoded_document"])
    session_document = _jsonified_session_document(handle)

    label_left = f"{Path(str(source)).name} (on disk)"
    label_right = f"{Path(str(source)).name} (session edits)"
    report = compute_profile_diff(
        fresh_document,
        session_document,
        label_a=label_left,
        label_b=label_right,
    )
    payload = report.to_dict()
    payload["session_id"] = sid
    payload["source_path"] = str(source)
    return payload


def _dispatch_diff_against_path(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    path: Any = None,
) -> dict[str, Any]:
    """Diff a session against an arbitrary on-disk SAIP package.

    Useful for "compare current edits to a known-good vendor DER" or
    "compare two profiles where only one is open in a session". The
    target path is loaded via :func:`_load_package_from_path` so the
    same DER / hex-text / JSON ingestion rules apply as
    ``saip.open_package``.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_json_codec import jsonify_document
    from Tools.ProfilePackage.saip_profile_diff import compute_profile_diff

    sid = str(session_id or "").strip()
    target_path_text = str(path or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    if len(target_path_text) == 0:
        raise ValueError("path is required.")

    target_path = Path(target_path_text).expanduser().resolve()
    if target_path.is_file() is False:
        raise FileNotFoundError(f"path does not point to a regular file: {target_path}")

    handle = get_manager().claim(sid)
    session_document = _jsonified_session_document(handle)

    target_package = _load_package_from_path(target_path)
    target_document = jsonify_document(target_package["decoded_document"])

    label_left = _label_for_session(handle, fallback=sid)
    label_right = target_path.name
    report = compute_profile_diff(
        session_document,
        target_document,
        label_a=label_left,
        label_b=label_right,
    )
    payload = report.to_dict()
    payload["session_id"] = sid
    payload["target_path"] = str(target_path)
    return payload


# -- SA-4 variables dispatchers ----------------------------------------


def _dispatch_list_variables(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """List template placeholder variables present in the package."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    payload = _collect_variables(handle["decoded_document"])
    payload["session_id"] = sid
    payload["overrides_applied"] = dict(handle.get("applied_overrides") or {})
    return payload


def _dispatch_set_variable(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    name: Any = None,
    value: Any = None,
) -> dict[str, Any]:
    """Apply a placeholder override (ICCID / IMSI / arbitrary name)."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    name_text = str(name or "").strip()
    value_text = str(value or "")
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(name_text) == 0:
        raise ValueError("name is required.")

    _ensure_pysim_importable()
    from Tools.ProfilePackage.saip_profile_template import (
        apply_placeholder_overrides_to_loaded_document,
        normalize_placeholder_name,
    )

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    assignments = {name_text: value_text}
    summaries = apply_placeholder_overrides_to_loaded_document(
        handle["decoded_document"],
        assignments,
    )
    normalised = normalize_placeholder_name(name_text)
    handle["applied_overrides"][normalised] = value_text
    # Re-encode via build_profile_sequence_from_document so pes stays
    # in sync with the override'd document.
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
        _mark_dirty(handle, -1)  # sequence-wide dirty marker
    except Exception as error:
        # Override may have introduced undefined placeholders; keep the
        # document changes but report the warning so the GUI can surface it.
        return {
            "session_id": sid,
            "name": normalised,
            "value": value_text,
            "summaries": summaries,
            "warnings": [
                f"Document mutated; re-encode failed: {error}",
            ],
        }

    return {
        "session_id": sid,
        "name": normalised,
        "value": value_text,
        "summaries": summaries,
        "overrides_applied": dict(handle["applied_overrides"]),
    }


def _dispatch_reset_variable(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    name: Any = None,
) -> dict[str, Any]:
    """Reset a single placeholder override back to the on-disk source value.

    Reload the source document, drop the named override from the
    session bookkeeping, and re-apply every other override that was
    still in effect. This is the per-variable analogue of
    ``saip.revert_changes`` (which drops *all* edits + overrides) and
    keeps the active session usable without forcing the operator to
    re-type the rest of their override set.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    name_text = str(name or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(name_text) == 0:
        raise ValueError("name is required.")

    _ensure_pysim_importable()
    from Tools.ProfilePackage.saip_profile_template import (
        apply_placeholder_overrides_to_loaded_document,
        normalize_placeholder_name,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)

    normalised = normalize_placeholder_name(name_text)
    overrides = dict(handle.get("applied_overrides") or {})
    if normalised not in overrides:
        # Nothing to do — surface the no-op so the GUI can downgrade
        # the toast severity. This is *not* an error: the operator
        # may have already reset the value in a sibling tab.
        return {
            "session_id": sid,
            "name": normalised,
            "removed": False,
            "overrides_applied": overrides,
            "summaries": [f"{normalised} was not overridden; nothing to reset."],
        }

    overrides.pop(normalised, None)

    # Reload the document from disk so __ygg_token_defs__ goes back
    # to whatever the source carried, then layer the remaining
    # overrides on top in the same order they were applied.
    _reload_source_into_handle(handle)
    handle["applied_overrides"] = {}

    summaries: list[str] = [f"{normalised} reset to source."]
    if len(overrides) > 0:
        replay_summaries = apply_placeholder_overrides_to_loaded_document(
            handle["decoded_document"],
            overrides,
        )
        for replay in replay_summaries:
            summaries.append(replay)
        handle["applied_overrides"] = dict(overrides)

    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
        # The whole sequence was just rebuilt — flag everything dirty
        # so cache-clearing GUI flows still trigger.
        _mark_dirty(handle, -1)
    except Exception as error:
        return {
            "session_id": sid,
            "name": normalised,
            "removed": True,
            "overrides_applied": dict(handle["applied_overrides"]),
            "summaries": summaries,
            "warnings": [
                f"Document reset; re-encode failed after replaying "
                f"remaining overrides: {error}",
            ],
        }

    return {
        "session_id": sid,
        "name": normalised,
        "removed": True,
        "overrides_applied": dict(handle["applied_overrides"]),
        "summaries": summaries,
    }


# -- PE-sequence authoring: insert / remove / load / write ------------
#
# Operator-facing CRUD over the PE sequence. The four dispatchers
# below let a session mutate which PEs are present and shuttle
# individual PEs between the in-memory sequence and disk:
#
#   * insert — splice a fresh / scaffolded PE between header and end
#   * remove — drop a PE while protecting the mandatory anchors
#   * load   — decode a single-PE blob from disk into the sequence
#   * write  — serialise a single PE out to disk in der/hex/json
#
# Header (index 0) and PE-End (last index) are anchors; the
# dispatchers refuse to displace either one (TCA SAIP §A.2).


# Minimal default decoded payloads for the PE types the manual lists
# under "Add Profile Element". Each new PE gets an empty header (the
# operator fills name + identification afterwards). Keys not listed
# here can still be added via ``saip.import_pe`` from disk.
_PE_ADD_DEFAULTS: dict[str, dict[str, Any]] = {
    "akaParameter": {
        "aka-header": {"identification": 0},
        "algoConfiguration": ("algoParameter", {
            "algorithmID": 1,
            "algorithmOptions": b"\x00",
            "key": b"\x00" * 16,
            "opc": b"\x00" * 16,
        }),
        "sqnOptions": b"\x02",
        "sqnDelta": bytes.fromhex("000010000000"),
        "sqnAgeLimit": bytes.fromhex("000010000000"),
        "sqnInit": [bytes(6) for _ in range(32)],
    },
    # NOTE: ``cdmaParameter`` is not a registered pySim ProfileElement
    # class in the 3.3.1 schema bundled with this release; saip.add_pe
    # cannot scaffold one. Use saip.import_pe with a raw .der blob.
    "pinCodes": {
        "pin-Header": {"identification": 0},
        "pinCodes": ("pinconfig", []),
    },
    "pukCodes": {
        "puk-Header": {"identification": 0},
        "pukCodes": [],
    },
    "genericFileManagement": {
        "gfm-header": {"identification": 0},
        "fileManagementCMD": [],
    },
    "securityDomain": {
        "sd-Header": {"identification": 0},
    },
}

_PE_ADD_PRESET_ROWS: tuple[dict[str, str], ...] = (
    {
        "pe_type": "*",
        "preset_id": "",
        "title": "Blank / built-in default",
        "summary": "Use the minimal scaffold currently generated for this PE type.",
    },
    {
        "pe_type": "securityDomain",
        "preset_id": "mno_sd_scp_all",
        "title": "MNO-SD: SCP03 + SCP80 + SCP81",
        "summary": (
            "Default GP AIDs, common SD privileges, PERSONALIZED lifecycle, "
            "C9 SCP03/SCP80/SCP81 entries, and three placeholder AES keys."
        ),
    },
    {
        "pe_type": "securityDomain",
        "preset_id": "sd_scp03_minimal",
        "title": "Security Domain: SCP03 minimal",
        "summary": "Default GP AIDs, Security Domain privilege, PERSONALIZED lifecycle, and C9 SCP03.",
    },
    {
        "pe_type": "pinCodes",
        "preset_id": "pin_user_adm",
        "title": "PIN1 + ADM1",
        "summary": "PIN1 with PUK1 unblock reference plus ADM1 placeholder.",
    },
    {
        "pe_type": "pukCodes",
        "preset_id": "puk_primary_secondary",
        "title": "PUK1 + secondary PUK1",
        "summary": "Primary and secondary PUK placeholders matching common PIN slots.",
    },
    {
        "pe_type": "akaParameter",
        "preset_id": "aka_milenage_placeholder",
        "title": "MILENAGE placeholder",
        "summary": "MILENAGE algorithm block with placeholder K/OPc and default SQN settings.",
    },
    {
        "pe_type": "rfm",
        "preset_id": "rfm_default_access",
        "title": "RFM default access",
        "summary": "Example RFM AIDs, TAR B00001, MSL 0x16, and UICC/ADF access domains.",
    },
)


def _pe_add_preset_rows_for(pe_type: str | None = None) -> list[dict[str, str]]:
    requested = str(pe_type or "").strip()
    rows: list[dict[str, str]] = []
    for row in _PE_ADD_PRESET_ROWS:
        row_type = row["pe_type"]
        if row_type == "*" or requested == "" or row_type == requested:
            rows.append(dict(row))
    return rows


def _sd_common_key_list() -> list[dict[str, Any]]:
    key_data = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    return [
        {
            "keyUsageQualifier": bytes.fromhex(usage),
            "keyIdentifier": bytes([identifier]),
            "keyVersionNumber": b"\x01",
            "keyComponents": [
                {
                    "keyType": b"\x88",
                    "keyData": key_data,
                    "macLength": len(key_data),
                }
            ],
            "keyAccess": b"\x00",
        }
        for identifier, usage in (
            (1, "38"),
            (2, "34"),
            (3, "C8"),
        )
    ]


def _security_domain_instance_preset(*, scp_tlvs: bytes, privileges: bytes) -> dict[str, Any]:
    return {
        "applicationLoadPackageAID": bytes.fromhex("A0000001515350"),
        "classAID": bytes.fromhex("A000000151535041"),
        "instanceAID": bytes.fromhex("A000000151000000"),
        "applicationPrivileges": privileges,
        "lifeCycleState": b"\x0F",
        "applicationSpecificParametersC9": scp_tlvs,
    }


def _apply_pe_add_preset(pe: Any, pe_type: str, preset: str) -> str:
    preset_id = str(preset or "").strip()
    if preset_id == "":
        return ""
    pe_type_text = str(pe_type or "").strip()
    decoded = getattr(pe, "decoded", None)
    if isinstance(decoded, dict) is False:
        raise ValueError(f"Cannot apply preset {preset_id!r}; PE has no decoded payload.")

    if pe_type_text == "securityDomain":
        if preset_id == "mno_sd_scp_all":
            decoded["instance"] = _security_domain_instance_preset(
                scp_tlvs=bytes.fromhex("810203008102800081028100"),
                privileges=bytes.fromhex("82DC20"),
            )
            decoded["keyList"] = _sd_common_key_list()
            return "MNO-SD: SCP03 + SCP80 + SCP81"
        if preset_id == "sd_scp03_minimal":
            decoded["instance"] = _security_domain_instance_preset(
                scp_tlvs=bytes.fromhex("81020300"),
                privileges=bytes.fromhex("800000"),
            )
            decoded["keyList"] = _sd_common_key_list()
            return "Security Domain: SCP03 minimal"

    if pe_type_text == "pinCodes" and preset_id == "pin_user_adm":
        decoded["pinCodes"] = (
            "pinconfig",
            [
                {
                    "keyReference": 1,
                    "pinValue": bytes.fromhex("31323334FFFFFFFF"),
                    "unblockingPINReference": 1,
                    "pinAttributes": 6,
                    "maxNumOfAttemps-retryNumLeft": 0x33,
                },
                {
                    "keyReference": 10,
                    "pinValue": bytes.fromhex("3132333435363738"),
                    "pinAttributes": 1,
                    "maxNumOfAttemps-retryNumLeft": 0xAA,
                },
            ],
        )
        return "PIN1 + ADM1"

    if pe_type_text == "pukCodes" and preset_id == "puk_primary_secondary":
        decoded["pukCodes"] = [
            {
                "keyReference": 1,
                "pukValue": bytes.fromhex("3132333435363738"),
                "maxNumOfAttemps-retryNumLeft": 0xAA,
            },
            {
                "keyReference": 129,
                "pukValue": bytes.fromhex("3132333435363738"),
                "maxNumOfAttemps-retryNumLeft": 0xAA,
            },
        ]
        return "PUK1 + secondary PUK1"

    if pe_type_text == "akaParameter" and preset_id == "aka_milenage_placeholder":
        decoded["algoConfiguration"] = (
            "algoParameter",
            {
                "algorithmID": 1,
                "algorithmOptions": b"\x00",
                "key": bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
                "opc": bytes.fromhex("FFEEDDCCBBAA99887766554433221100"),
                "authCounterMax": bytes.fromhex("FFFFFF"),
                "rotationConstants": bytes.fromhex("4000204060"),
                "xoringConstants": (
                    bytes.fromhex("00000000000000000000000000000000")
                    + bytes.fromhex("00000000000000000000000000000001")
                    + bytes.fromhex("00000000000000000000000000000002")
                    + bytes.fromhex("00000000000000000000000000000004")
                    + bytes.fromhex("00000000000000000000000000000008")
                ),
                "numberOfKeccak": 1,
            },
        )
        decoded["sqnOptions"] = b"\x0E"
        decoded["sqnDelta"] = bytes.fromhex("000010000000")
        decoded["sqnAgeLimit"] = bytes.fromhex("000010000000")
        decoded["sqnInit"] = [bytes(6) for _ in range(32)]
        return "MILENAGE placeholder"

    if pe_type_text == "rfm" and preset_id == "rfm_default_access":
        decoded["instanceAID"] = bytes.fromhex("A00000055910100002")
        decoded["securityDomainAID"] = bytes.fromhex("A000000151000000")
        decoded["tarList"] = [bytes.fromhex("B00001")]
        decoded["minimumSecurityLevel"] = b"\x16"
        decoded["uiccAccessDomain"] = bytes.fromhex("02030104")
        decoded["uiccAdminAccessDomain"] = bytes.fromhex("02030104")
        decoded["adfRFMAccess"] = {
            "adfAID": bytes.fromhex("A0000000871002FF34FF0789312E30FF"),
            "adfAccessDomain": bytes.fromhex("02030104"),
            "adfAdminAccessDomain": bytes.fromhex("02030104"),
        }
        return "RFM default access"

    valid = [
        row["preset_id"]
        for row in _pe_add_preset_rows_for(pe_type_text)
        if row["preset_id"] != ""
    ]
    raise ValueError(
        f"preset {preset_id!r} is not available for PE type {pe_type_text!r}. "
        f"Available presets: {', '.join(valid) if valid else '(none)'}."
    )


# File extensions ``saip.import_pe`` accepts. The matching pySim
# ProfileElement parser handles plain DER for everything else; XML
# (the legacy "File Tree Express" container) needs a separate
# converter we do not bundle, so the dispatcher fails fast with a
# clear message rather than silently dropping the input.
_IMPORT_PE_HEX_SUFFIXES: frozenset[str] = frozenset({".asn", ".asn1", ".txt", ".hex"})
_IMPORT_PE_JSON_SUFFIXES: frozenset[str] = frozenset({".json"})


def _build_default_pe(pe_type: str, preset: str = "") -> Any:
    """Construct an empty pySim ``ProfileElement`` of the given type.

    PEs that are valid ``ProfileElement`` CHOICE alternatives but lack a
    dedicated pySim subclass (``csim``, ``opt-csim``, ``cdmaParameter``,
    ``iot``, ``opt-iot``) are scaffolded via the generic ``ProfileElement``
    fallback with a minimal header.  Only types that are absent from the
    compiled ASN.1 schema entirely (e.g. ``ssim`` pending a schema upgrade
    to v3.4+) raise ``ValueError``.
    """
    _ensure_pysim_importable()
    from collections import OrderedDict
    from pySim.esim.saip import ProfileElement, asn1

    cls = ProfileElement.class_for_petype(pe_type)
    if cls is None:
        # The pySim class registry does not have a dedicated subclass
        # for this type.  It may still be a valid CHOICE alternative
        # in the compiled ASN.1 schema — several PEs (csim, opt-csim,
        # cdmaParameter, iot, opt-iot) encode correctly via the generic
        # fallback path.
        choice = asn1.types["ProfileElement"]._type
        if pe_type not in choice.name_to_member:
            raise ValueError(
                f"unknown PE type {pe_type!r}; not a valid ProfileElement "
                "CHOICE alternative in the compiled ASN.1 schema. "
                "Use saip.import_pe to inject an arbitrary blob.",
            )
        # Derive the header key matching ProfileElement.header_name logic.
        if pe_type.startswith("opt-"):
            header_key = pe_type.replace("-", "") + "-header"
        elif pe_type in ProfileElement.header_name_translation_dict:
            header_key = ProfileElement.header_name_translation_dict[pe_type]
        else:
            header_key = pe_type + "-header"
        instance = ProfileElement(
            OrderedDict({header_key: {"identification": 0, "mandated": None}})
        )
        instance.type = pe_type
    else:
        instance = cls()
    if pe_type in _PE_ADD_DEFAULTS:
        defaults = dict(_PE_ADD_DEFAULTS[pe_type])
        for key, value in defaults.items():
            instance.decoded[key] = value
    _apply_pe_add_preset(instance, pe_type, preset)
    return instance


def _dispatch_list_pe_presets(
    ctx: ActionContext,
    *,
    pe_type: Any = None,
) -> dict[str, Any]:
    pe_type_text = str(pe_type or "").strip()
    rows = _pe_add_preset_rows_for(pe_type_text)
    return {
        "pe_type": pe_type_text,
        "rows": rows,
        "count": len(rows),
    }


def _dispatch_add_pe(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_type: Any = None,
    insert_at: Any = None,
    preset: Any = None,
) -> dict[str, Any]:
    """Insert a new PE of ``pe_type`` at the supplied index.

    ``insert_at`` is the 0-based slot the new PE will occupy after
    the splice — pass ``1`` to land just after ProfileHeader.
    Scaffolded payload defaults are wired up for the PE flavours the
    bench edits routinely (AKA / PIN / PUK / GFM / SecurityDomain);
    other pySim-registered types still resolve but come up empty.

    The ProfileHeader (index 0) and PE-End (last index) anchors are
    immovable per TCA SAIP §A.2; both ends of the range are refused.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    pe_type_text = str(pe_type or "").strip()
    if len(sid) == 0 or len(pe_type_text) == 0:
        raise ValueError("session_id and pe_type are required.")
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pes = handle["pes"]
    n = len(pes.pe_list)
    try:
        idx = int(insert_at) if insert_at is not None else n - 1
    except Exception as error:
        raise ValueError(f"insert_at must be an integer: {insert_at!r}") from error
    if idx < 1:
        raise ValueError(
            "insert_at must be >= 1 (index 0 is reserved for ProfileHeader, TCA SAIP §A.2).",
        )
    if idx > n - 1:
        raise ValueError(
            f"insert_at {idx} would displace PE-End; max allowed is {n - 1}.",
        )

    preset_text = str(preset or "").strip()
    new_pe = _build_default_pe(pe_type_text, preset_text)

    # Auto-name the new PE so it shows up as e.g. ``akaParameter#5``
    # in the PE list without forcing the operator to immediately
    # type one in. The header dict has at most one ``*-header`` /
    # ``*-Header`` slot — find it and stamp ``pe-name`` with the
    # type-suffixed default. Operators can rename via the existing
    # decoded-edit surface afterwards.
    if isinstance(getattr(new_pe, "decoded", None), dict):
        suggested_index = len(pes.pe_list)
        for header_key in list(new_pe.decoded.keys()):
            lower = header_key.lower()
            if lower.endswith("header") and isinstance(new_pe.decoded[header_key], dict):
                if "pe-name" not in new_pe.decoded[header_key]:
                    new_pe.decoded[header_key]["pe-name"] = f"{pe_type_text}#{suggested_index}"
                break

    new_list = list(pes.pe_list)
    new_list.insert(idx, new_pe)
    pes.pe_list = new_list

    # Renumber identification across the whole sequence so the new
    # PE picks up the lowest free integer (TCA SAIP §A.3 — header
    # identification fields are 1-based and contiguous).
    try:
        pes.renumber_identification()
    except Exception:
        # Some test profiles ship without proper headers on every PE
        # (only the mandatory header / end carry one); pySim's
        # renumber walks defensively but raises on truly malformed
        # sequences. Swallow so the insert still lands.
        pass

    handle["decoded_document"] = build_decoded_document_from_sequence(
        pes,
        handle.get("decoded_document", {}).get("intro")
        or [f"Profile with {len(pes.pe_list)} profile elements"],
    )
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)

    new_identification: int | None = None
    try:
        header_dict = next(
            (v for k, v in (new_pe.decoded or {}).items()
             if k.lower().endswith("header") and isinstance(v, dict)),
            None,
        )
        if header_dict is not None:
            new_identification = int(header_dict.get("identification") or 0)
    except Exception:
        new_identification = None

    return {
        "session_id": sid,
        "pe_index": idx,
        "pe_type": pe_type_text,
        "preset": preset_text,
        "identification": new_identification,
        "label": _pe_display_label(new_pe),
        "summary": (
            f"Inserted {pe_type_text} at index {idx}"
            + (f" using preset {preset_text!r}" if preset_text else "")
            + (f" with identification={new_identification}." if new_identification else ".")
        ),
        "warnings": warnings,
    }


def _dispatch_delete_pe(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Drop the PE at ``pe_index``; the header / end anchors are protected."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pes = handle["pes"]
    n = len(pes.pe_list)
    if idx < 0 or idx >= n:
        raise IndexError(f"pe_index {idx} out of range 0..{n - 1}")
    pe_type = str(getattr(pes.pe_list[idx], "type", ""))
    if pe_type == "header" or idx == 0:
        raise ValueError(
            "Cannot delete the ProfileHeader (TCA SAIP §A.2 mandates index 0).",
        )
    if pe_type == "end" or idx == n - 1:
        raise ValueError(
            "Cannot delete PE-End (TCA SAIP §A.2 mandates the last PE).",
        )

    removed = pes.pe_list[idx]
    label = _pe_display_label(removed)
    new_list = list(pes.pe_list)
    new_list.pop(idx)
    pes.pe_list = new_list

    handle["decoded_document"] = build_decoded_document_from_sequence(
        pes,
        handle.get("decoded_document", {}).get("intro")
        or [f"Profile with {len(pes.pe_list)} profile elements"],
    )
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, -1)

    return {
        "session_id": sid,
        "deleted_index": idx,
        "deleted_type": pe_type,
        "label": label,
        "remaining_count": len(pes.pe_list),
        "summary": f"Deleted {pe_type} ({label}) from index {idx}.",
        "warnings": warnings,
    }


def _decode_imported_pe_bytes(input_path: Path) -> Any:
    """Decode the file at ``input_path`` into a single ProfileElement."""
    _ensure_pysim_importable()
    from pySim.esim.saip import ProfileElement, ProfileElementSequence

    suffix = input_path.suffix.lower()
    if suffix == ".xml":
        raise ValueError(
            "XML imports (File Tree Express) are not implemented in this "
            "release; convert to .der or .asn1 hex before reloading.",
        )
    raw = input_path.read_bytes()
    if suffix in _IMPORT_PE_JSON_SUFFIXES:
        # Treat as a single-PE JSON snippet — wrap it in a tiny
        # document and re-encode to extract the PE.
        from Tools.ProfilePackage.saip_json_codec import (
            build_profile_sequence_from_document,
        )
        document = json.loads(raw.decode("utf-8"))
        if isinstance(document, dict) and "sections" in document:
            seq = build_profile_sequence_from_document(
                document, workspace_root=_workspace_root()
            )
        else:
            # Bare {section_key: payload} → wrap.
            seq = build_profile_sequence_from_document(
                {"sections": document}, workspace_root=_workspace_root()
            )
        if len(seq.pe_list) == 0:
            raise ValueError("imported JSON contained no profile element.")
        if len(seq.pe_list) > 1:
            raise ValueError(
                f"imported JSON contains {len(seq.pe_list)} profile elements; "
                "only one is allowed per import.",
            )
        return seq.pe_list[0]

    der_bytes: bytes
    if suffix in _IMPORT_PE_HEX_SUFFIXES:
        text = raw.decode("utf-8", errors="ignore")
        cleaned = "".join(text.split())
        try:
            der_bytes = bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError(
                f"file looks like hex text but bytes.fromhex failed: {error}",
            ) from error
    else:
        der_bytes = raw

    seq = ProfileElementSequence.from_der(der_bytes)
    if len(seq.pe_list) == 0:
        raise ValueError("imported file contained no profile element.")
    if len(seq.pe_list) > 1:
        raise ValueError(
            f"imported file contains {len(seq.pe_list)} profile elements; "
            "the loader only accepts one PE per file.",
        )
    return seq.pe_list[0]


def _dispatch_import_pe(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    input_path: Any = None,
    insert_at: Any = None,
) -> dict[str, Any]:
    """Insert a PE decoded from a file at ``insert_at``.

    Accepted suffixes:
      * ``.der`` — binary DER (default).
      * ``.asn`` / ``.asn1`` / ``.txt`` / ``.hex`` — ASCII hex of DER.
      * ``.json`` — single-PE JSON snippet (transcoded form).
      * ``.xml`` — legacy File Tree Express container; not handled
        in this release (no bundled converter).
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    in_text = str(input_path or "").strip()
    if len(sid) == 0 or len(in_text) == 0:
        raise ValueError("session_id and input_path are required.")
    source = Path(os.path.expanduser(in_text)).resolve()
    if source.is_file() is False:
        raise FileNotFoundError(f"input_path not found: {source}")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pes = handle["pes"]
    n = len(pes.pe_list)
    try:
        idx = int(insert_at) if insert_at is not None else n - 1
    except Exception as error:
        raise ValueError(f"insert_at must be an integer: {insert_at!r}") from error
    if idx < 1:
        raise ValueError(
            "insert_at must be >= 1 (index 0 is reserved for ProfileHeader).",
        )
    if idx > n - 1:
        raise ValueError(
            f"insert_at {idx} would displace PE-End; max allowed is {n - 1}.",
        )

    new_pe = _decode_imported_pe_bytes(source)
    new_list = list(pes.pe_list)
    new_list.insert(idx, new_pe)
    pes.pe_list = new_list

    handle["decoded_document"] = build_decoded_document_from_sequence(
        pes,
        handle.get("decoded_document", {}).get("intro")
        or [f"Profile with {len(pes.pe_list)} profile elements"],
    )
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)

    return {
        "session_id": sid,
        "input_path": str(source),
        "pe_index": idx,
        "pe_type": str(getattr(new_pe, "type", "unknown")),
        "label": _pe_display_label(new_pe),
        "summary": f"Imported {source.name} as PE[{idx}].",
        "warnings": warnings,
    }


def _dispatch_export_pe(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    output_path: Any = None,
    format: Any = None,
    overwrite: Any = None,
) -> dict[str, Any]:
    """Serialise a single PE out to disk.

    The caller is responsible for the destination filename — the GUI
    typically composes one as ``<pe_type>-<name>.<ext>``. ``format``
    matches ``saip.save_package``: ``der`` / ``hex`` / ``json``.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    out_text = str(output_path or "").strip()
    if len(sid) == 0 or len(out_text) == 0:
        raise ValueError("session_id and output_path are required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    fmt = str(format or "der").strip().lower() or "der"
    if fmt not in _SAVE_PACKAGE_FORMATS:
        raise ValueError(
            f"unknown format {format!r}; allowed: {', '.join(_SAVE_PACKAGE_FORMATS)}",
        )
    overwrite_flag = bool(overwrite) if overwrite is not None else False

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pes = handle["pes"]
    n = len(pes.pe_list)
    if idx < 0 or idx >= n:
        raise IndexError(f"pe_index {idx} out of range 0..{n - 1}")
    pe = pes.pe_list[idx]

    target = Path(os.path.expanduser(out_text)).resolve()
    if target.suffix == "":
        target = target.with_suffix(_SAVE_PACKAGE_DEFAULT_EXTS[fmt])
    if target.exists() and overwrite_flag is False:
        raise FileExistsError(
            f"target already exists (pass overwrite=true to replace): {target}",
        )
    target.parent.mkdir(parents=True, exist_ok=True)

    bytes_written = 0
    if fmt == "der":
        der = pe.to_der()
        target.write_bytes(der)
        bytes_written = len(der)
    elif fmt == "hex":
        der = pe.to_der()
        target.write_text(der.hex().upper() + "\n", encoding="utf-8")
        bytes_written = target.stat().st_size
    else:
        decoded = _jsonify_decoded(getattr(pe, "decoded", {}))
        text = json.dumps(decoded, indent=2, ensure_ascii=False) + "\n"
        target.write_text(text, encoding="utf-8")
        bytes_written = target.stat().st_size

    return {
        "session_id": sid,
        "pe_index": idx,
        "pe_type": str(getattr(pe, "type", "unknown")),
        "output_path": str(target),
        "format": fmt,
        "bytes_written": bytes_written,
    }


# -- Empty-package scaffold + variable-definition surface -------------
#
# Three smaller dispatchers that close out the operator-authoring
# surface beyond the PE CRUD already covered:
#
#   * ``saip.create_package`` — bring up a new in-memory session
#     containing only ProfileHeader + PE-End so the operator can
#     start building from a blank canvas (no file on disk required).
#   * ``saip.open_package_with_variables`` — open a DER / JSON
#     package together with a CSV variable-definitions sidecar in
#     a single call, mirroring the convention of placing a
#     ``profile.csv`` next to ``profile.der`` for personalisation.
#   * ``saip.add_variable_definition`` /
#     ``saip.remove_variable_definition`` — let the bench
#     pre-define / drop placeholder definitions on the variables
#     surface independently of binding them to a PE field.


def _new_empty_pes(
    *,
    ver_major: int = 2,
    ver_minor: int = 3,
    iccid_hex: str = "0" * 20,
    profile_type: str = "",
) -> Any:
    """Build a minimal valid ProfileElementSequence (header + end)."""
    _ensure_pysim_importable()
    from pySim.esim.saip import (
        ProfileElementHeader,
        ProfileElementEnd,
        ProfileElementSequence,
    )

    seq = ProfileElementSequence()
    header_kwargs: dict[str, Any] = {
        "ver_major": int(ver_major),
        "ver_minor": int(ver_minor),
        "iccid": str(iccid_hex),
    }
    if profile_type:
        header_kwargs["profile_type"] = profile_type
    seq.pe_list = [
        ProfileElementHeader(**header_kwargs),
        ProfileElementEnd(),
    ]
    seq.renumber_identification()
    return seq


def _dispatch_create_package(
    ctx: ActionContext,
    *,
    profile_version: Any = None,
    iccid: Any = None,
    profile_type: Any = None,
) -> dict[str, Any]:
    """Create a new in-memory session containing only header + end.

    ``profile_version`` is a ``"M.m"`` string ("2.3", "3.3", ...);
    omit it for the conservative 2.3 default. ``iccid`` accepts
    20-digit hex (or empty for the all-zero placeholder pySim
    plants by default — operators can fill it in afterwards via
    ``saip.update_profile_header_field``). The returned shape is
    identical to ``saip.open_package`` so every workbench dispatcher
    works against the new session unchanged.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
    )

    ver_text = str(profile_version or "2.3").strip()
    try:
        major_text, minor_text = ver_text.split(".", 1)
        major = int(major_text)
        minor = int(minor_text)
    except (ValueError, AttributeError) as error:
        raise ValueError(
            f"profile_version must be 'M.m' (e.g. '2.3' or '3.3'); got {profile_version!r}",
        ) from error

    iccid_text = str(iccid or "").strip()
    if iccid_text == "":
        iccid_hex = "0" * 20
    else:
        normalised = iccid_text.replace(" ", "").replace("-", "")
        if len(normalised) % 2 != 0 or all(c in "0123456789abcdefABCDEF" for c in normalised) is False:
            raise ValueError(
                f"iccid must be even-length hex (got {iccid_text!r}); "
                "use saip.update_profile_header_field to set decimal digits.",
            )
        if len(normalised) > 20:
            raise ValueError(
                f"iccid must be \u2264 20 hex chars (TS 102 221 §13.2); got {len(normalised)}",
            )
        # Pad with the F nibble so the on-wire form respects ITU-T E.118.
        iccid_hex = (normalised + "F" * (20 - len(normalised))).upper()

    pes = _new_empty_pes(
        ver_major=major,
        ver_minor=minor,
        iccid_hex=iccid_hex,
        profile_type=str(profile_type or "").strip(),
    )
    decoded_document = build_decoded_document_from_sequence(
        pes,
        [f"YggdraSIM-scaffold profile (v{major}.{minor}, {len(pes.pe_list)} PE)"],
    )

    handle = {
        "pes": pes,
        "decoded_document": decoded_document,
        "encoding": "scaffold",
        "source_path": "",
        "size_bytes": 0,
        "load_warnings": [],
    }
    _ensure_session_state(handle)
    session = get_manager().open(
        kind="saip",
        handle=handle,
        close=lambda: None,
        metadata={
            "source_path": "",
            "encoding": "scaffold",
            "pe_count": len(pes.pe_list),
            "load_warning_count": 0,
        },
    )
    # New sessions are dirty from the start — there's nothing on disk
    # yet to compare against, so the GUI's "unsaved changes" banner
    # should fire until the operator runs saip.save_package.
    handle["dirty_pes"] = {-1}

    return {
        "session_id": session.id,
        "source_path": "",
        "file_name": "",
        "size_bytes": 0,
        "encoding": "scaffold",
        "pe_count": len(pes.pe_list),
        "pe_types": sorted(
            {str(getattr(pe, "type", "unknown")) for pe in pes.pe_list}
        ),
        "load_warnings": [],
        "profile_version": f"{major}.{minor}",
        "iccid_hex": iccid_hex,
        "summary": (
            f"Scaffolded a new {ver_text} package with header + end. "
            "Run saip.save_package to persist; saip.add_pe to extend."
        ),
    }


def _walk_for_dict_placeholder_bindings(node: Any) -> set[str]:
    """Collect every ``__ygg_placeholder__`` name reachable under ``node``.

    Companion to ``extract_template_placeholder_names`` (which only
    finds string-embedded ``[NAME]`` / ``{NAME}`` markers). Walks
    dicts and lists recursively and treats any mapping carrying
    ``__ygg_placeholder__`` as a bound reference.
    """
    found: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            marker = value.get("__ygg_placeholder__")
            if isinstance(marker, str) and len(marker) > 0:
                found.add(marker)
            for nested in value.values():
                visit(nested)
            return
        if isinstance(value, list):
            for nested in value:
                visit(nested)
            return

    visit(node)
    return found


def _parse_sidecar_variables_csv(csv_path: Path) -> list[tuple[str, str]]:
    """Parse a SAIP-personalisation sidecar CSV (2-column NAME,VALUE).

    The bench convention places ``profile.csv`` next to ``profile.der``
    using the bare 2-column form (no header row). Blank lines and ``#``
    comment lines split logical record sets — the first set is what
    the open dispatcher applies (mirrors the documented appendix
    "Profile Personalization of Variables"). This is intentionally a
    different parser to ``saip.import_variables_csv`` which uses a
    header-row DictReader CSV.
    """
    import csv as _csv

    pairs: list[tuple[str, str]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as stream:
        reader = _csv.reader(stream)
        for raw_row in reader:
            row = [str(cell).strip() for cell in (raw_row or [])]
            # Skip blank lines and comment lines — these are the
            # separators between record sets in the manual's format.
            if len(row) == 0 or all(cell == "" for cell in row):
                if len(pairs) > 0:
                    break
                continue
            if row[0].startswith("#"):
                continue
            if len(row) < 2:
                continue
            name = row[0]
            value = row[1]
            if name == "" or value == "":
                continue
            pairs.append((name, value))
    return pairs


# ----------------------------------------------------------------------
# Token-list ↔ filename mapping store
#
# The eUICC Profile Creator manual auto-loads ``<package>.csv`` next to
# the profile package (see "Importing a Variable Definitions File").
# That sibling convention is too rigid for a real bench where one CSV
# is shared across many packages, or kept in a different directory
# from the .der it personalises. This store lets the operator pin
# any token-list path to any package basename; the open dispatcher
# consults the map first and only falls back to the sibling
# convention when no explicit mapping exists.
#
# Persisted as JSON under ``<runtime>/state/saip_token_mappings.json``
# so the binding survives process restarts and is shared across
# YggdraSIM tools that talk to the same runtime root.
# ----------------------------------------------------------------------


def _token_mapping_store_path() -> Path:
    from yggdrasim_common.runtime_paths import runtime_path

    return Path(runtime_path("state", "saip_token_mappings.json"))


def _load_token_mappings() -> dict[str, dict[str, Any]]:
    """Load the file→token-list map (returns ``{}`` when absent)."""
    store = _token_mapping_store_path()
    if store.is_file() is False:
        return {}
    try:
        raw = json.loads(store.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    mappings = raw.get("mappings") if isinstance(raw, dict) else None
    if isinstance(mappings, dict) is False:
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    for key, entry in mappings.items():
        if isinstance(entry, dict) is False:
            continue
        tokens_path = str(entry.get("tokens_path") or "").strip()
        if tokens_path == "":
            continue
        cleaned[str(key)] = {
            "tokens_path": tokens_path,
            "last_used": entry.get("last_used"),
        }
    return cleaned


def _save_token_mappings(mappings: dict[str, dict[str, Any]]) -> None:
    store = _token_mapping_store_path()
    store.parent.mkdir(parents=True, exist_ok=True)
    payload = {"mappings": mappings}
    store.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _resolve_token_mapping(pkg_path: Path) -> Path | None:
    """Look up a stored token-list path for a package.

    Match order:
      1. exact absolute path of the package
      2. basename (``profile.der``)
      3. stem  (``profile``)

    The first match wins. Resolved paths must exist on disk; missing
    targets are reported by the open dispatcher rather than silently
    skipped so the operator can repair the mapping.
    """
    mappings = _load_token_mappings()
    if len(mappings) == 0:
        return None
    candidates = [
        str(pkg_path),
        pkg_path.name,
        pkg_path.stem,
    ]
    for key in candidates:
        entry = mappings.get(key)
        if entry is None:
            continue
        target = Path(os.path.expanduser(str(entry.get("tokens_path") or "")))
        if target.is_file():
            return target
        # File moved / deleted — surface the broken mapping by
        # returning the bad path; caller turns it into a warning.
        return target
    return None


def _touch_token_mapping(pkg_path: Path) -> None:
    """Update the ``last_used`` timestamp for the matching mapping (no-op when absent)."""
    import time

    mappings = _load_token_mappings()
    if len(mappings) == 0:
        return
    candidates = [str(pkg_path), pkg_path.name, pkg_path.stem]
    changed = False
    for key in candidates:
        if key in mappings:
            mappings[key]["last_used"] = int(time.time())
            changed = True
            break
    if changed:
        _save_token_mappings(mappings)


def _dispatch_list_token_mappings(
    ctx: ActionContext,
) -> dict[str, Any]:
    """Return every persisted package→token-list mapping."""
    mappings = _load_token_mappings()
    rows = [
        {
            "filename": key,
            "tokens_path": entry.get("tokens_path"),
            "last_used": entry.get("last_used"),
        }
        for key, entry in sorted(mappings.items())
    ]
    return {
        "store_path": str(_token_mapping_store_path()),
        "count": len(rows),
        "mappings": rows,
    }


def _dispatch_set_token_mapping(
    ctx: ActionContext,
    *,
    filename: Any = None,
    tokens_path: Any = None,
) -> dict[str, Any]:
    """Pin ``filename`` (basename / stem / absolute path) to ``tokens_path``.

    Subsequent ``saip.open_package_with_variables`` calls will look
    up ``filename`` here before falling back to the sibling-CSV
    convention. ``tokens_path`` does not have to exist at the time
    of the call — the operator might be defining the mapping ahead
    of personalisation runs — but the open dispatcher will warn
    when the target turns out to be missing on disk.
    """
    fname = str(filename or "").strip()
    tpath = str(tokens_path or "").strip()
    if fname == "" or tpath == "":
        raise ValueError("filename and tokens_path are required.")
    mappings = _load_token_mappings()
    mappings[fname] = {
        "tokens_path": tpath,
        "last_used": mappings.get(fname, {}).get("last_used"),
    }
    _save_token_mappings(mappings)
    return {
        "filename": fname,
        "tokens_path": tpath,
        "count": len(mappings),
        "summary": f"Pinned {fname!r} → {tpath!r}.",
    }


def _dispatch_remove_token_mapping(
    ctx: ActionContext,
    *,
    filename: Any = None,
) -> dict[str, Any]:
    """Drop a persisted mapping. No-op when no entry matches."""
    fname = str(filename or "").strip()
    if fname == "":
        raise ValueError("filename is required.")
    mappings = _load_token_mappings()
    removed = mappings.pop(fname, None)
    _save_token_mappings(mappings)
    return {
        "filename": fname,
        "removed": removed is not None,
        "count": len(mappings),
        "summary": (
            f"Removed mapping for {fname!r}."
            if removed is not None
            else f"No mapping for {fname!r} (no-op)."
        ),
    }


def _dispatch_open_package_with_variables(
    ctx: ActionContext,
    *,
    path: Any = None,
    variables_path: Any = None,
) -> dict[str, Any]:
    """Open a package and apply its token-list (CSV).

    Resolution order for ``variables_path`` when omitted:
      1. **Pinned mapping** — first match in
         ``saip.list_token_mappings`` keyed by absolute path /
         basename / stem of the package being opened. This is the
         operator-driven binding for token lists that don't sit
         next to the .der file.
      2. **Sibling convention** — ``<package_basename>.csv`` next
         to the package, as documented in the manual's "Importing a
         Variable Definitions File".

    The returned shape extends ``saip.open_package``'s output with
    a ``variables_loaded`` summary so the GUI can report exactly
    which CSV (if any) was applied and via which resolution path.

    CSV format is the bare 2-column ``NAME,VALUE`` per line per the
    appendix "Profile Personalization of Variables". Blank lines
    and ``#`` comments split record sets; only the first set is
    applied here (use ``saip.batch_personalize`` to fan out the
    remaining sets across multiple output packages).
    """
    from Tools.ProfilePackage.saip_profile_template import (
        normalize_placeholder_name,
    )
    from yggdrasim_common.gui_server.sessions import get_manager

    path_text = str(path or "").strip()
    if len(path_text) == 0:
        raise ValueError("path is required (file to open).")

    base_response = _dispatch_open_package(ctx=ctx, path=path_text)

    pkg_path = Path(os.path.expanduser(path_text)).resolve()
    csv_text = str(variables_path or "").strip()
    csv_resolution = "explicit"
    csv_warning: str | None = None
    if csv_text == "":
        # 1) Pinned mapping (operator-curated). Touch the
        #    last-used timestamp so the GUI can sort recently
        #    bound packages first.
        pinned = _resolve_token_mapping(pkg_path)
        if pinned is not None and pinned.is_file():
            csv_path = pinned
            csv_resolution = "pinned"
            _touch_token_mapping(pkg_path)
        elif pinned is not None:
            csv_path = None
            csv_warning = (
                f"pinned token-list path {pinned} does not exist on disk; "
                "falling back to the sibling-CSV convention."
            )
        else:
            csv_path = None

        # 2) Sibling convention as the documented fallback.
        if csv_path is None:
            candidate = pkg_path.with_suffix(".csv")
            if candidate.is_file():
                csv_path = candidate
                csv_resolution = "sibling"
    else:
        csv_path = Path(os.path.expanduser(csv_text)).resolve()
        if csv_path.is_file() is False:
            raise FileNotFoundError(f"variables_path not found: {csv_path}")

    sid = base_response["session_id"]
    if csv_path is None:
        base_response["variables_loaded"] = {
            "path": "",
            "resolution": csv_resolution if csv_resolution != "explicit" else "none",
            "applied_count": 0,
            "summary": (
                csv_warning
                or "no token-list pinned for this package and no sibling CSV found."
            ),
        }
        return base_response

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pairs = _parse_sidecar_variables_csv(csv_path)
    if len(pairs) == 0:
        base_response["variables_loaded"] = {
            "path": str(csv_path),
            "resolution": csv_resolution,
            "applied_count": 0,
            "summary": "CSV opened but contained no placeholder records.",
        }
        return base_response

    assignments = {name: value for name, value in pairs}
    from Tools.ProfilePackage.saip_profile_template import (
        apply_placeholder_overrides_to_loaded_document,
    )
    summaries = apply_placeholder_overrides_to_loaded_document(
        handle["decoded_document"], assignments
    )
    for raw_name, raw_value in assignments.items():
        handle["applied_overrides"][normalize_placeholder_name(raw_name)] = str(raw_value)

    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
        _mark_dirty(handle, -1)
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")

    base_response["variables_loaded"] = {
        "path": str(csv_path),
        "resolution": csv_resolution,
        "applied_count": len(assignments),
        "summaries": summaries,
        "warnings": warnings,
        "summary": (
            f"Applied {len(assignments)} variable(s) from {csv_path.name} "
            f"({csv_resolution})."
        ),
    }
    return base_response


def _dispatch_add_variable_definition(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    name: Any = None,
    value: Any = None,
    encoding: Any = None,
    overwrite: Any = None,
) -> dict[str, Any]:
    """Register a placeholder definition without binding it to any PE.

    The name lands in ``__ygg_token_defs__`` ready for a later
    ``saip.add_variable_to_pe`` call (or for picking up by an
    external personalisation CSV). By default refuses to clobber an
    existing entry; pass ``overwrite=true`` to replace one in place.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_profile_template import (
        normalize_placeholder_name,
    )

    sid = str(session_id or "").strip()
    name_text = str(name or "").strip()
    value_text = str(value or "")
    enc_text = str(encoding or "hex").strip().lower() or "hex"
    if len(sid) == 0 or len(name_text) == 0:
        raise ValueError("session_id and name are required.")
    if enc_text not in ("hex", "utf8", "ascii"):
        raise ValueError(f"encoding must be hex / utf8 / ascii (got {enc_text!r}).")
    overwrite_flag = bool(overwrite) if overwrite is not None else False

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    token_defs = handle["decoded_document"].get("__ygg_token_defs__")
    if isinstance(token_defs, dict) is False:
        token_defs = {}
        handle["decoded_document"]["__ygg_token_defs__"] = token_defs

    normalised = normalize_placeholder_name(name_text)
    if normalised in token_defs and overwrite_flag is False:
        raise ValueError(
            f"placeholder {normalised!r} is already defined; pass overwrite=true to replace.",
        )
    token_defs[normalised] = {
        "value": value_text,
        "encoding": enc_text,
        "kind": "manual",
    }
    return {
        "session_id": sid,
        "name": normalised,
        "value": value_text,
        "encoding": enc_text,
        "definitions_count": len(token_defs),
        "summary": f"Registered placeholder [{normalised}] = {value_text!r}.",
    }


def _dispatch_remove_variable_definition(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    name: Any = None,
    force: Any = None,
) -> dict[str, Any]:
    """Drop a placeholder definition. Refuses if still bound to a PE.

    A bound definition (i.e. one whose name appears as ``[NAME]``
    inside a PE field) can still be removed by passing
    ``force=true`` — the bound reference will then resolve to an
    undefined-variable error on next encode, which is sometimes
    what the operator wants when migrating to a different name.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_profile_template import (
        extract_template_placeholder_names,
        normalize_placeholder_name,
    )

    sid = str(session_id or "").strip()
    name_text = str(name or "").strip()
    if len(sid) == 0 or len(name_text) == 0:
        raise ValueError("session_id and name are required.")
    force_flag = bool(force) if force is not None else False

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    token_defs = handle["decoded_document"].get("__ygg_token_defs__")
    if isinstance(token_defs, dict) is False or len(token_defs) == 0:
        raise LookupError(f"no placeholder definitions registered on this session.")

    normalised = normalize_placeholder_name(name_text)
    if normalised not in token_defs:
        raise LookupError(f"placeholder {normalised!r} is not defined.")

    bound_names = {
        normalize_placeholder_name(n)
        for n in extract_template_placeholder_names(
            handle["decoded_document"].get("sections") or {}
        )
    }
    # Also walk for the YggdraSIM dict-shaped marker that
    # ``saip.add_variable_to_pe`` stamps into typed PE slots
    # (``{"__ygg_placeholder__": NAME, ...}``); the manual's
    # bracket scanner above only matches string placeholders.
    bound_names |= _walk_for_dict_placeholder_bindings(
        handle["decoded_document"].get("sections") or {}
    )
    if normalised in bound_names and force_flag is False:
        raise ValueError(
            f"placeholder {normalised!r} is still bound to one or more PE fields; "
            "unbind first or pass force=true to drop the definition anyway.",
        )

    removed = token_defs.pop(normalised, None)
    return {
        "session_id": sid,
        "name": normalised,
        "removed_value": (removed or {}).get("value", ""),
        "definitions_count": len(token_defs),
        "summary": (
            f"Removed placeholder [{normalised}]"
            + (" (was still bound to a PE; encode will fail without re-binding)."
               if normalised in bound_names else ".")
        ),
    }


# -- AID-surface diff -------------------------------------------------
#
# Reuses the per-side ``saip.list_applications`` projection on both
# sessions and joins the two row sets on (pe_type, primary AID) so
# the bench gets a clean added / removed / unchanged report keyed
# by the application instance AID. Useful for cross-checking that an
# updated package still ships the same SD / Application / ELF
# inventory before pushing it to a card.


def _dispatch_compare_applications(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_path: Any = None,
) -> dict[str, Any]:
    """Diff the SD / Application / ELF inventory of two packages.

    Loads ``target_path`` into a throwaway session, projects both
    sides through ``saip.list_applications``, and joins the two row
    sets on (pe_type, primary AID). Returns the per-row delta plus
    a counts-by-status summary for the report banner.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    target_text = str(target_path or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    if len(target_text) == 0:
        raise ValueError("target_path is required.")

    target_resolved = Path(os.path.expanduser(target_text)).resolve()
    if target_resolved.is_file() is False:
        raise FileNotFoundError(f"target_path not found: {target_resolved}")

    # Reuse list_applications by opening a throwaway session for the
    # target — same dispatcher path as the in-memory side. Done via
    # a temporary session_id that we release afterwards.
    target_session = _dispatch_open_package(ctx=ctx, path=str(target_resolved))
    target_sid = target_session["session_id"]
    try:
        left_apps = _dispatch_list_applications(ctx=ctx, session_id=sid)
        right_apps = _dispatch_list_applications(ctx=ctx, session_id=target_sid)
    finally:
        try:
            from yggdrasim_common.gui_server.sessions import get_manager as _gm
            _gm().release(target_sid)
        except Exception:
            pass

    # Join by (pe_type, primary AID) — the existing list_applications
    # dispatcher emits ``instance_aid`` for SD / Application rows and
    # ``load_pkg_aid`` for executable load files. Fall back through
    # both before tagging the entry by its display label.
    def _key(row: dict[str, Any]) -> tuple[str, str]:
        primary = (
            row.get("instance_aid")
            or row.get("aid_hex")
            or row.get("load_pkg_aid")
            or row.get("class_aid")
            or row.get("label")
            or ""
        )
        return (str(row.get("pe_type") or row.get("role") or ""), str(primary))

    left_index = {_key(r): r for r in left_apps["rows"]}
    right_index = {_key(r): r for r in right_apps["rows"]}

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    for key, row in left_index.items():
        if key in right_index:
            unchanged.append(row)
        else:
            removed.append(row)
    for key, row in right_index.items():
        if key not in left_index:
            added.append(row)

    return {
        "session_id": sid,
        "target_path": str(target_resolved),
        "left_count": len(left_apps["rows"]),
        "right_count": len(right_apps["rows"]),
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "unchanged": len(unchanged),
        },
        "added": added,
        "removed": removed,
        "unchanged": unchanged,
    }


# -- Bench environment fingerprint ------------------------------------
#
# Dumps the YggdraSIM build version, the resolved pySim / asn1tools
# versions, the host Python + platform string, and the full list of
# registered actions. Operators paste the resulting HTML / XML / JSON
# blob into bug reports so a triage reader can tell which surface
# was actually loaded when an issue was hit.


def _yggdrasim_version_info() -> dict[str, Any]:
    """Best-effort version / install report (works without git)."""
    info: dict[str, Any] = {}
    repo_root = _workspace_root()
    pyproject = repo_root / "pyproject.toml"
    version = ""
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8")
            match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
            if match is not None:
                version = match.group(1)
        except Exception:
            pass
    info["version"] = version
    info["workspace_root"] = str(repo_root)

    # Loaded SAIP bits — useful for triage tickets.
    try:
        import pySim  # noqa: F401
        import pySim.esim.saip as _saip  # noqa: F401
        info["pysim_module"] = getattr(_saip, "__file__", "")
    except ImportError:
        info["pysim_module"] = ""
    try:
        import asn1tools as _asn1tools  # noqa: F401
        info["asn1tools_version"] = getattr(_asn1tools, "__version__", "")
    except ImportError:
        info["asn1tools_version"] = ""

    import platform as _platform
    import sys as _sys
    info["python"] = _sys.version.split()[0]
    info["platform"] = _platform.platform()
    return info


def _registered_action_summary() -> list[dict[str, str]]:
    """List every registered action id + subsystem (no descriptions)."""
    registry = get_registry()
    out: list[dict[str, str]] = []
    for spec in registry.all():
        out.append({
            "id": str(getattr(spec, "id", "")),
            "subsystem": str(getattr(spec, "subsystem", "")),
            "title": str(getattr(spec, "title", "")),
        })
    return out


def _format_product_summary_html(summary: dict[str, Any]) -> str:
    import html as _html

    def _esc(value: Any) -> str:
        return _html.escape(str(value or ""), quote=True)

    actions_rows = "".join(
        f"<tr><td>{_esc(a['id'])}</td><td>{_esc(a['subsystem'])}</td>"
        f"<td>{_esc(a['title'])}</td></tr>"
        for a in summary["actions"]
    )
    env = summary["environment"]
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>YggdraSIM product summary</title>"
        "<style>"
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
        "margin:24px;color:#222;background:#f8f8f8}"
        "h1{font-size:20px;margin-bottom:4px}"
        "h2{font-size:14px;margin-top:24px}"
        "table{border-collapse:collapse;width:100%;background:#fff;"
        "font-size:12px;box-shadow:0 1px 2px rgba(0,0,0,.05)}"
        "th,td{padding:6px 10px;border:1px solid #d8d8d8;text-align:left;"
        "font-family:'SFMono-Regular',Menlo,monospace}"
        "th{background:#eef2f5}"
        ".kv td:first-child{width:200px;color:#555}"
        "</style></head><body>"
        f"<h1>YggdraSIM product summary</h1>"
        f"<div>YggdraSIM version: <strong>{_esc(env['version'])}</strong></div>"
        "<h2>Environment</h2>"
        "<table class='kv'>"
        f"<tr><td>Workspace root</td><td>{_esc(env['workspace_root'])}</td></tr>"
        f"<tr><td>Python</td><td>{_esc(env['python'])}</td></tr>"
        f"<tr><td>Platform</td><td>{_esc(env['platform'])}</td></tr>"
        f"<tr><td>pySim module</td><td>{_esc(env['pysim_module'])}</td></tr>"
        f"<tr><td>asn1tools version</td><td>{_esc(env['asn1tools_version'])}</td></tr>"
        "</table>"
        f"<h2>Registered actions ({len(summary['actions'])})</h2>"
        "<table><tr><th>id</th><th>subsystem</th><th>title</th></tr>"
        f"{actions_rows}</table>"
        "</body></html>"
    )


def _format_product_summary_xml(summary: dict[str, Any]) -> str:
    import xml.sax.saxutils as _sax

    def _esc(value: Any) -> str:
        return _sax.escape(str(value or ""))

    env = summary["environment"]
    actions_xml = "".join(
        f"<action><id>{_esc(a['id'])}</id>"
        f"<subsystem>{_esc(a['subsystem'])}</subsystem>"
        f"<title>{_esc(a['title'])}</title></action>"
        for a in summary["actions"]
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<yggdrasim_product_summary>"
        f"<version>{_esc(env['version'])}</version>"
        "<environment>"
        f"<workspace_root>{_esc(env['workspace_root'])}</workspace_root>"
        f"<python>{_esc(env['python'])}</python>"
        f"<platform>{_esc(env['platform'])}</platform>"
        f"<pysim_module>{_esc(env['pysim_module'])}</pysim_module>"
        f"<asn1tools_version>{_esc(env['asn1tools_version'])}</asn1tools_version>"
        "</environment>"
        f"<actions count='{len(summary['actions'])}'>"
        f"{actions_xml}"
        "</actions>"
        "</yggdrasim_product_summary>"
    )


def _dispatch_product_summary(
    ctx: ActionContext,
    *,
    output_path: Any = None,
    format: Any = None,
    overwrite: Any = None,
) -> dict[str, Any]:
    """Render a bench / environment fingerprint report.

    Pass ``output_path=""`` to receive the JSON projection inline in
    the response without writing a file. ``format`` is ``html`` or
    ``xml`` when writing to disk; the default is ``html``.
    """
    fmt = str(format or "html").strip().lower() or "html"
    if fmt not in ("html", "xml", "json"):
        raise ValueError(f"format must be html / xml / json (got {fmt!r}).")
    overwrite_flag = bool(overwrite) if overwrite is not None else False

    summary = {
        "environment": _yggdrasim_version_info(),
        "actions": _registered_action_summary(),
    }

    out_text = str(output_path or "").strip()
    if len(out_text) == 0:
        return {"format": "json", "summary": summary}

    target = Path(os.path.expanduser(out_text)).resolve()
    if target.suffix == "":
        target = target.with_suffix(f".{fmt}")
    if target.exists() and overwrite_flag is False:
        raise FileExistsError(
            f"target already exists (pass overwrite=true to replace): {target}",
        )
    target.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "html":
        target.write_text(_format_product_summary_html(summary), encoding="utf-8")
    elif fmt == "xml":
        target.write_text(_format_product_summary_xml(summary), encoding="utf-8")
    else:
        target.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "format": fmt,
        "output_path": str(target),
        "bytes_written": target.stat().st_size,
        "action_count": len(summary["actions"]),
    }


# -- Linter rulebook --------------------------------------------------
#
# Surfaces every rule the SAIP linter ships with so the bench can
# render an "available checks" pane keyed by rule id, severity, and
# spec citation. Mirrors the id space the lint-finding rows already
# carry (``rule_id`` on each finding).


def _dispatch_list_validation_rules(
    ctx: ActionContext,
) -> dict[str, Any]:
    """Return every linter rule with id, severity, spec citation, message."""
    from Tools.ProfilePackage.lint_engine import SaipProfileLinter

    linter = SaipProfileLinter()
    out: list[dict[str, Any]] = []
    descriptors = getattr(linter, "rule_descriptors", None)
    if descriptors is None:
        # Older revisions exposed a different attribute name; fall
        # back to scanning instance attributes whose value is a list
        # of dataclass-like rule objects.
        for name in dir(linter):
            obj = getattr(linter, name, None)
            if isinstance(obj, (list, tuple)) and len(obj) > 0:
                first = obj[0]
                if hasattr(first, "rule_id") or hasattr(first, "code"):
                    descriptors = obj
                    break
    if descriptors is None:
        return {"count": 0, "rules": [], "warning": "linter rule registry not exposed"}

    for rule in descriptors:
        if isinstance(rule, dict):
            data = rule
        else:
            data = {
                "id": getattr(rule, "rule_id", getattr(rule, "code", "")),
                "severity": getattr(rule, "severity", ""),
                "spec": getattr(rule, "spec", ""),
                "message": getattr(rule, "message", getattr(rule, "description", "")),
                "recommendation": getattr(rule, "recommendation", ""),
            }
        out.append({
            "id": str(data.get("id") or ""),
            "severity": str(data.get("severity") or "").upper(),
            "spec": str(data.get("spec") or ""),
            "message": str(data.get("message") or ""),
            "recommendation": str(data.get("recommendation") or ""),
        })
    out.sort(key=lambda row: row["id"])
    return {"count": len(out), "rules": out}


# -- Bind PE field to placeholder -------------------------------------
#
# Replaces a concrete value inside a PE (e.g. ``iccid`` or
# ``instance.applicationInstanceAID``) with a YggdraSIM placeholder
# marker keyed by ``[NAME]``. The original value is captured into
# ``__ygg_token_defs__`` so saip.export_variables_csv and
# saip.set_variable can round-trip it through the variables surface.


def _walk_decoded_value(
    container: Any,
    path_parts: list[str],
) -> tuple[Any, str | int]:
    """Walk a JSON path like 'instance.applicationInstanceAID' into a value.

    Returns the (parent, key) pair so the caller can mutate in place.
    Numeric path components index into lists.
    """
    if len(path_parts) == 0:
        raise ValueError("path is empty.")
    cursor = container
    for step in path_parts[:-1]:
        if isinstance(cursor, list):
            try:
                cursor = cursor[int(step)]
            except (ValueError, IndexError) as error:
                raise LookupError(f"path step {step!r} not found in list") from error
        elif isinstance(cursor, dict):
            if step not in cursor:
                raise LookupError(f"path step {step!r} not found in dict (keys: {list(cursor.keys())[:8]})")
            cursor = cursor[step]
        else:
            raise LookupError(f"cannot descend into {type(cursor).__name__} at step {step!r}")
    last = path_parts[-1]
    if isinstance(cursor, list):
        try:
            return cursor, int(last)
        except ValueError as error:
            raise LookupError(f"path tail {last!r} is not a list index") from error
    if isinstance(cursor, dict):
        if last not in cursor:
            raise LookupError(f"path tail {last!r} not found in dict")
        return cursor, last
    raise LookupError(f"cannot resolve path tail at {type(cursor).__name__}")


def _dispatch_add_variable_to_pe(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    section_key: Any = None,
    field_path: Any = None,
    variable_name: Any = None,
    encoding: Any = None,
) -> dict[str, Any]:
    """Swap a concrete PE field value for a placeholder reference.

    The captured value is parked in ``__ygg_token_defs__[NAME]``
    with the supplied ``encoding`` hint (default ``hex``) so the
    variables surface (``saip.export_variables_csv`` /
    ``saip.set_variable``) can round-trip it later. ``field_path``
    is a dotted JSON path within the PE's decoded section — e.g.
    ``iccid``, ``instance.applicationInstanceAID``, or
    ``algoConfiguration.1.key`` for an indexed slot.

    Accepts either ``pe_index`` (numeric position in the PE
    sequence) or ``section_key`` (the dict key under
    ``decoded_document['sections']``); ``section_key`` wins when
    both are provided.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_profile_template import (
        normalize_placeholder_name,
    )

    sid = str(session_id or "").strip()
    name_text = str(variable_name or "").strip()
    path_text = str(field_path or "").strip()
    enc_text = str(encoding or "hex").strip().lower() or "hex"
    section_text = str(section_key or "").strip()
    if len(sid) == 0 or len(name_text) == 0 or len(path_text) == 0:
        raise ValueError(
            "session_id, variable_name, and field_path are all required.",
        )
    if enc_text not in ("hex", "utf8", "ascii"):
        raise ValueError(f"encoding must be hex / utf8 / ascii (got {enc_text!r}).")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    keys = _sections_by_pe_index(handle["decoded_document"])
    if section_text:
        if section_text not in keys:
            raise LookupError(f"section_key {section_text!r} is not in the open document.")
        section_key_resolved = section_text
        idx = keys.index(section_text)
    else:
        try:
            idx = int(pe_index)
        except Exception as error:
            raise ValueError(
                f"pe_index must be an integer when section_key is omitted: {pe_index!r}",
            ) from error
        if idx < 0 or idx >= len(keys):
            raise IndexError(f"pe_index {idx} out of range 0..{len(keys) - 1}")
        section_key_resolved = keys[idx]
    section_key = section_key_resolved  # rebind so downstream stays unchanged
    section = handle["decoded_document"]["sections"].get(section_key)
    if isinstance(section, dict) is False:
        raise LookupError(f"section {section_key!r} is not a dict.")

    parent, last = _walk_decoded_value(section, path_text.split("."))
    current_value = parent[last]

    # Capture the current value as the token definition. Bytes-shaped
    # values are stored as hex; strings are stored verbatim.
    if isinstance(current_value, (bytes, bytearray)):
        captured = bytes(current_value).hex().upper()
        if enc_text != "hex":
            captured = bytes(current_value).decode("utf-8", errors="replace")
    else:
        captured = str(current_value)

    normalised = normalize_placeholder_name(name_text)
    token_defs = handle["decoded_document"].get("__ygg_token_defs__")
    if isinstance(token_defs, dict) is False:
        token_defs = {}
        handle["decoded_document"]["__ygg_token_defs__"] = token_defs
    token_defs[normalised] = {
        "value": captured,
        "encoding": enc_text,
        "kind": "captured",
    }

    # Replace the field with a placeholder reference. We use the
    # bracket-style notation (``[NAME]``) the manual specifies, and
    # mark the parent slot with the YggdraSIM placeholder marker
    # ``__ygg_placeholder__`` so the encoder substitutes at re-encode
    # time. Falls back to a bare string when the parent slot can't
    # carry the marker.
    parent[last] = {"__ygg_placeholder__": normalised, "encoding": enc_text}
    _mark_dirty(handle, idx)

    return {
        "session_id": sid,
        "pe_index": idx,
        "field_path": path_text,
        "variable_name": normalised,
        "encoding": enc_text,
        "captured_value": captured,
        "summary": (
            f"Replaced {section_key}.{path_text} with [{normalised}]; "
            f"original value captured into __ygg_token_defs__."
        ),
    }


# -- Catalog: interpreted EFs + template OIDs -------------------------
#
# Two stateless catalogs the GUI uses to render its capability matrix:
#   * Which EFs YggdraSIM interprets via a structured editor (vs.
#     hex-only fallback);
#   * Which SAIP profile-template OIDs the in-tree pySim registry
#     knows about (drives the "Template" dropdown on FS-bearing PEs).


def _dispatch_list_interpreted_efs(
    ctx: ActionContext,
) -> dict[str, Any]:
    """Return every EF key with structured-editor support.

    Entries split into two tiers:
      * ``round_trip`` — non-lossy editors that preserve original
        bytes when the decoded form was not modified.
      * ``lossy_splice`` — editors that re-encode from the decoded
        form (record-based EFs where the upstream encoder cannot
        round-trip the original SFI / record-padding choices).
    """
    from Tools.ProfilePackage.saip_decoded_edit import (
        _HEX_HINTED_EF_KEYS,
        _LOSSY_SPLICE_EF_KEYS,
    )

    round_trip = sorted(_HEX_HINTED_EF_KEYS)
    lossy = sorted(_LOSSY_SPLICE_EF_KEYS)
    return {
        "round_trip_count": len(round_trip),
        "lossy_splice_count": len(lossy),
        "total": len(set(round_trip) | set(lossy)),
        "round_trip": round_trip,
        "lossy_splice": lossy,
    }


def _dispatch_list_template_oids(
    ctx: ActionContext,
) -> dict[str, Any]:
    """Return every SAIP profile template OID known to pySim's registry.

    Used by the GUI Template-OID picker on FS-bearing PEs (PE-USIM,
    PE-ISIM, PE-CSIM, PE-Telecom). The "spec" field cites TCA SAIP
    Annex A where the OIDs are catalogued.
    """
    _ensure_pysim_importable()
    from pySim.esim.saip.templates import ProfileTemplateRegistry

    registry = ProfileTemplateRegistry()
    rows: list[dict[str, Any]] = []
    for oid, template in sorted(
        registry.by_oid.items(),
        key=lambda item: tuple(int(part) for part in item[0].split(".")),
    ):
        # Templates expose a class-level ``association`` attribute that
        # tells us which PE type they bind to (USIM / ISIM / CSIM / ...).
        association = getattr(template, "association", None)
        rows.append(
            {
                "oid": oid,
                "class": template.__name__,
                "pe_type": str(association) if association else "",
            }
        )
    return {
        "spec": "TCA SAIP Annex A",
        "count": len(rows),
        "templates": rows,
    }


# -- PE info + reorder ------------------------------------------------
#
# Two small UX dispatchers the manual references:
#   * "PE Info" pane — describes the PE type, ASN.1 module, and the
#     spec section that defines it.
#   * "Reorder PEs" — moves a PE in the sequence. Header MUST stay at
#     index 0 and end MUST stay at the last index (TCA SAIP §A.2),
#     so the dispatcher refuses moves that would violate either
#     anchor.


_PE_TYPE_DOCS: dict[str, dict[str, str]] = {
    "header": {
        "title": "Profile Header",
        "asn1": "ProfileHeader",
        "spec": "TCA SAIP §A.2",
        "summary": (
            "Carries the profile-wide ICCID, profileType, mandatory "
            "services, GFSTE list, mandatory AIDs, connectivity "
            "parameters, and IoT PIX. MUST be the first PE in the "
            "sequence."
        ),
    },
    "end": {
        "title": "Profile End",
        "asn1": "PE-End",
        "spec": "TCA SAIP §A.2",
        "summary": "Sentinel PE that terminates the sequence.",
    },
    "pinCodes": {
        "title": "PIN Codes",
        "asn1": "PE-PINCodes",
        "spec": "TCA SAIP §A.2",
        "summary": (
            "Carries either an explicit pinconfig list (1..26 PIN "
            "definitions) or a filePath pointing at the directory "
            "whose PIN context this PE inherits."
        ),
    },
    "pukCodes": {
        "title": "PUK Codes",
        "asn1": "PE-PUKCodes",
        "spec": "TCA SAIP §A.2",
        "summary": "List of PUK definitions. Referenced from PINConfiguration.unblockingPINReference.",
    },
    "akaParameter": {
        "title": "AKA Parameter",
        "asn1": "PE-AKAParameter",
        "spec": "TCA SAIP §A.2 / 3GPP TS 35.205-208 (MILENAGE) / TS 35.231 (TUAK)",
        "summary": (
            "Algorithm + sequence-number configuration for AKA. "
            "Choice between mappingParameter (test algorithm) and "
            "algoParameter (MILENAGE / TUAK / CAVE)."
        ),
    },
    "cdmaParameter": {
        "title": "CDMA Parameter",
        "asn1": "PE-CDMAParameter",
        "spec": "TCA SAIP §A.2 / 3GPP2 [S0016]",
        "summary": (
            "A-Key (CAVE), optional SSD halves, and HRPD / SimpleIP "
            "/ MobileIP authentication data."
        ),
    },
    "securityDomain": {
        "title": "Security Domain",
        "asn1": "PE-SecurityDomain",
        "spec": "GP CS v2.3 §11 / TCA SAIP §A.2",
        "summary": (
            "GP Security Domain instance (AID, privileges, key "
            "list, perso-data DGI block). Privileges follow GP CS "
            "Table 11-49."
        ),
    },
    "genericFileManagement": {
        "title": "Generic File Management",
        "asn1": "PE-GFM",
        "spec": "TCA SAIP §A.2",
        "summary": (
            "Free-form file system PE. Each entry carries a filePath "
            "(MF-rooted concatenated FIDs) and a File body."
        ),
    },
    "usim": {
        "title": "USIM Application",
        "asn1": "PE-USIM",
        "spec": "TCA SAIP §A.2 / 3GPP TS 31.102",
        "summary": "USIM ADF + EFs. Bound to a SAIP profile template via templateID.",
    },
    "isim": {
        "title": "ISIM Application",
        "asn1": "PE-ISIM",
        "spec": "TCA SAIP §A.2 / 3GPP TS 31.103",
        "summary": "ISIM ADF + EFs. Bound to a SAIP profile template via templateID.",
    },
    "csim": {
        "title": "CSIM Application",
        "asn1": "PE-CSIM",
        "spec": "TCA SAIP §A.2 / 3GPP2 C.S0065",
        "summary": "CSIM ADF + EFs. Bound to a SAIP profile template via templateID.",
    },
    "iot": {
        "title": "IoT Application",
        "asn1": "PE-IoT",
        "spec": "TCA SAIP §A.2 / 3GPP TS 31.102 IoT annex",
        "summary": (
            "IoT ADF (5FE0 family). Slim USIM-derived application carrying "
            "the EFs the IoT-UE service-table flags as mandatory "
            "(EF.UMPC, EF.IMSI, EF.ARR, EF.threshold). Not constructable "
            "via saip.add_pe in this build — use saip.import_pe with a "
            "DER blob produced from a TCA-IoT template package."
        ),
    },
    "ssim": {
        "title": "SSIM Application",
        "asn1": "PE-SSIM",
        "spec": "TCA SAIP §A.2 / 3GPP TS 31.102 §4.4.13 / GSMA SSIM",
        "summary": (
            "Standalone SIM application (SSIM) used with EAP-TLS 1.3 "
            "based authentication (RFC 9190). Pairs with "
            "PE-SSIM-EAPTLSParameters for the certificate / key set. "
            "Not constructable via saip.add_pe in this build — use "
            "saip.import_pe with a TCA-SSIM template DER blob."
        ),
    },
    "ssim-eaptls": {
        "title": "SSIM EAP-TLS Parameters",
        "asn1": "PE-SSIM-EAPTLSParameters",
        "spec": "TCA SAIP §A.2 / RFC 9190 (EAP-TLS 1.3)",
        "summary": (
            "TLS certificate + chain + CA + private key for the SSIM "
            "EAP-TLS authentication algorithm. Provided within an "
            "ADF.SSIM context. Use saip.import_pe to inject a "
            "pre-generated DER blob; this PE's structure is opaque "
            "to the form editor and must be edited via Show JSON."
        ),
    },
    "opt-csim": {
        "title": "CSIM Optional Files",
        "asn1": "PE-OptionalCSIM",
        "spec": "TCA SAIP §9.5 / 3GPP2 C.S0065",
        "summary": (
            "CSIM ADF EFs that are not part of the mandatory set "
            "(EF.SSCI, EF.SSFC, EF.MDN, EF.SIPCAP, EF.MIPCAP, "
            "EF.HRPDCAP, EF.MMSN, …). Layered on top of PE-CSIM via "
            "the same template. Not constructable via saip.add_pe; "
            "use saip.import_pe."
        ),
    },
    "opt-iot": {
        "title": "IoT Optional Files",
        "asn1": "PE-OptionalIoT",
        "spec": "TCA SAIP §9.5 / 3GPP TS 31.102 IoT annex",
        "summary": (
            "IoT ADF EFs beyond the mandatory IoT slim set "
            "(EF.SUPI_NAI and the 3GPP TS 31.102 Rel-17 IoT extras). "
            "Layered on top of PE-IoT via the same template. Use "
            "saip.import_pe to inject a DER blob."
        ),
    },
    "telecom": {
        "title": "Telecom DF",
        "asn1": "PE-Telecom",
        "spec": "TCA SAIP §A.2 / TS 11.11",
        "summary": "DF.TELECOM (7F10) and its EFs.",
    },
    "mf": {
        "title": "Master File",
        "asn1": "PE-MF",
        "spec": "TCA SAIP §A.2 / TS 102 221 §13.1",
        "summary": (
            "Master File (3F00) plus the EFs that live directly under it "
            "(EF.ICCID, EF.PL, EF.DIR, EF.ARR, EF.UMPC). Carries the "
            "MF-level pinStatusTemplateDO."
        ),
    },
    "cd": {
        "title": "Card Directory DF",
        "asn1": "PE-CD",
        "spec": "TCA SAIP §9.3",
        "summary": (
            "DF.CD (7F11). Contains EF.LAUNCHPAD and the optional EF.ICON "
            "range (6F40..6F7E). Created on demand."
        ),
    },
    "phonebook": {
        "title": "Phonebook DF",
        "asn1": "PE-PhoneBook",
        "spec": "TCA SAIP §9.4 / TS 31.102 §4.4.2",
        "summary": (
            "DF.PHONEBOOK (5F3A) with EF.PBR, EF.AAS, EF.GAS, EF.ADN, "
            "EF.IAP, EF.PSC, EF.CC, EF.PUID, EF.EXT1. Lives under either "
            "DF.TELECOM (legacy) or ADF.USIM (USIM-aware)."
        ),
    },
    "gsm-access": {
        "title": "GSM-ACCESS DF",
        "asn1": "PE-GSM-ACCESS",
        "spec": "TCA SAIP §9.5.4 / TS 31.102 §5.3",
        "summary": (
            "DF.GSM-ACCESS (5F3B) with EF.Kc, EF.KcGPRS, EF.CPBCCH, "
            "EF.InvScan. GSM-bearing EFs accessed when the USIM falls "
            "back to a GSM-only network."
        ),
    },
    "df-5gs": {
        "title": "5G-System DF",
        "asn1": "PE-DF-5GS",
        "spec": "TCA SAIP §9.5.6 / TS 31.102 §4.4.11",
        "summary": (
            "DF.5GS (5FC0) carrying the 5G SUCI / 5G-GUTI / NSSAI / "
            "EF.UAC_AIC / EF.OPL5G family. Required when "
            "USIM-Service-Table services 122..130 are advertised."
        ),
    },
    "eap": {
        "title": "EAP DF",
        "asn1": "PE-DF-EAP",
        "spec": "TCA SAIP §9.5.5 / TS 31.102 §4.4.4",
        "summary": (
            "DF.EAP (5F40) holding EAP credentials and parameters. "
            "Optional; created when EAP-AKA / EAP-SIM authentication "
            "is provisioned on the profile."
        ),
    },
    "df-saip": {
        "title": "SAIP DF",
        "asn1": "PE-DF-SAIP",
        "spec": "TCA SAIP §9.5.10",
        "summary": (
            "DF.SAIP (6FD0). Holds SUCI calculation info "
            "(EF.SUCI_Calc_Info, AID 4F01) used by USIM-Service-Table "
            "service 124/125."
        ),
    },
    "df-snpn": {
        "title": "SNPN DF",
        "asn1": "PE-DF-SNPN",
        "spec": "TCA SAIP §9.5.12 / TS 31.102 §4.4.12",
        "summary": (
            "DF.SNPN (5FE0). Stand-alone Non-Public Network "
            "credentials. Optional; created for service 143."
        ),
    },
    "df-5gprose": {
        "title": "5G-ProSe DF",
        "asn1": "PE-DF-5G-ProSe",
        "spec": "TCA SAIP §9.5.13 / TS 31.102 §4.4.14",
        "summary": (
            "DF.5G_ProSe holding 5G Proximity Services configuration "
            "and credentials (EF.UEPC5G_PROSE, EF.UEPC5G_AKMA, …)."
        ),
    },
    "application": {
        "title": "Application Instance",
        "asn1": "PE-Application",
        "spec": "GP CS v2.3 §11.5 / TCA SAIP §A.2",
        "summary": (
            "JavaCard application instance (INSTALL [for install] payload "
            "in PE form). Carries Class AID, Instance AID, Load Package "
            "AID, application-specific install parameters, privileges, "
            "and the SD into which it should be installed."
        ),
    },
    "rfm": {
        "title": "Remote File Management",
        "asn1": "PE-RFM",
        "spec": "TCA SAIP §A.2 / TS 102 226 §8",
        "summary": (
            "Remote File Management application configuration: TAR, "
            "minimum security level, target ADF / DF, key reference "
            "set. One PE per RFM instance."
        ),
    },
    "opt-usim": {
        "title": "USIM Optional Files",
        "asn1": "PE-OptionalUSIM",
        "spec": "TCA SAIP §9.5.2 / TS 31.102",
        "summary": (
            "USIM ADF EFs that are not part of the mandatory file set "
            "(EF.MSISDN, EF.SPN, EF.ECC, EF.HPLMN, EF.OPLMNwACT, …). "
            "Layered on top of PE-USIM via the same template."
        ),
    },
    "opt-isim": {
        "title": "ISIM Optional Files",
        "asn1": "PE-OptionalISIM",
        "spec": "TCA SAIP §9.5.3 / TS 31.103",
        "summary": (
            "ISIM ADF EFs beyond the mandatory IMS Public/Private "
            "User Identity / Home Network Domain Name set."
        ),
    },
    "ssd": {
        "title": "Supplementary Security Domain",
        "asn1": "PE-SSD",
        "spec": "GP CS v2.3 §7.4 / TCA SAIP §A.2",
        "summary": (
            "Supplementary Security Domain — child SD installed under "
            "an ISD (typically MNO-SD or ISD-R). Carries its own AID, "
            "key set, privileges, and perso-data DGI block."
        ),
    },
    "mnoSD": {
        "title": "MNO Security Domain",
        "asn1": "PE-MNO-SD",
        "spec": "SGP.02 §3.4 / GP CS v2.3 §7.4",
        "summary": (
            "Mobile Network Operator Security Domain. The application "
            "provider SD that owns the operator's keys and provisions "
            "the OTA channel."
        ),
    },
}


def _dispatch_pe_info(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Return PE-type metadata for the contextual "PE Info" pane."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pes = handle["pes"]
    if idx < 0 or idx >= len(pes.pe_list):
        raise IndexError(f"pe_index {idx} out of range 0..{len(pes.pe_list) - 1}")
    pe = pes.pe_list[idx]
    pe_type = str(getattr(pe, "type", "unknown"))
    info = dict(
        _PE_TYPE_DOCS.get(
            pe_type,
            {
                "title": pe_type or "Unknown PE",
                "asn1": pe_type,
                "spec": "TCA SAIP §A.2 (catalog entry not registered locally)",
                "summary": (
                    "No local documentation entry registered for this PE "
                    "type. Refer to TCA SAIP §A.2 for the canonical "
                    "ASN.1 definition."
                ),
            },
        )
    )
    info.update(
        {
            "session_id": sid,
            "pe_index": idx,
            "type": pe_type,
            "label": _pe_display_label(pe),
            "section_key": (
                _sections_by_pe_index(handle["decoded_document"])[idx]
                if 0 <= idx < len(_sections_by_pe_index(handle["decoded_document"]))
                else ""
            ),
            "supports_add_file": bool(hasattr(pe, "create_file")),
        }
    )
    return info


def _dispatch_reorder_pes(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    from_index: Any = None,
    to_index: Any = None,
) -> dict[str, Any]:
    """Move a PE from one index to another within the sequence.

    Refuses moves that would displace the mandatory header / end
    sentinels (TCA SAIP §A.2: header MUST be PE 0, end MUST be the
    last PE). Re-encodes the sequence on success so subsequent
    ``saip.list_pes`` calls reflect the new order.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    try:
        src = int(from_index)
        dst = int(to_index)
    except Exception as error:
        raise ValueError(
            f"from_index / to_index must be integers: {from_index!r}, {to_index!r}",
        ) from error

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pes = handle["pes"]
    n = len(pes.pe_list)
    if src < 0 or src >= n:
        raise IndexError(f"from_index {src} out of range 0..{n - 1}")
    if dst < 0 or dst >= n:
        raise IndexError(f"to_index {dst} out of range 0..{n - 1}")

    src_type = str(getattr(pes.pe_list[src], "type", ""))
    dst_type = str(getattr(pes.pe_list[dst], "type", ""))
    if src_type == "header" or dst == 0:
        raise ValueError(
            "ProfileHeader MUST stay at index 0 (TCA SAIP §A.2).",
        )
    if src_type == "end" or dst == n - 1:
        raise ValueError(
            "PE-End MUST stay at the last index (TCA SAIP §A.2).",
        )
    # Refuse moving a body PE *into* the header/end anchors.
    if dst_type == "header":
        raise ValueError("Cannot displace ProfileHeader (TCA SAIP §A.2).")
    if dst_type == "end":
        raise ValueError("Cannot displace PE-End (TCA SAIP §A.2).")

    if src == dst:
        return {
            "session_id": sid,
            "from_index": src,
            "to_index": dst,
            "moved": False,
            "summary": "Source and destination indices are identical; no-op.",
        }

    pe_list = list(pes.pe_list)
    moved = pe_list.pop(src)
    pe_list.insert(dst, moved)
    pes.pe_list = pe_list

    # Rebuild the decoded document so section ordering matches the new
    # PE sequence; downstream ``_resolve_pe_index`` lookups depend on
    # this. Then re-encode (ensures the bytes view stays consistent).
    handle["decoded_document"] = build_decoded_document_from_sequence(
        pes,
        handle.get("decoded_document", {}).get("intro")
        or [f"Profile with {len(pes.pe_list)} profile elements"],
    )
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, -1)

    return {
        "session_id": sid,
        "from_index": src,
        "to_index": dst,
        "moved": True,
        "moved_type": src_type,
        "summary": f"Moved PE[{src}] ({src_type}) -> [{dst}].",
        "warnings": warnings,
    }


# -- Variable export / import (CSV) -----------------------------------
#
# The eUICC Profile Creator manual surfaces variables as a CSV view
# (see "Editing the Variable Definitions" / "Profile Personalization
# of Variables"). The GUI's "Variables" panel already lets the
# operator edit one variable at a time via ``saip.set_variable``;
# these two dispatchers cover the bulk import / export workflow so
# operators can edit large variable sets in a spreadsheet.


def _dispatch_export_variables_csv(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    output_path: Any = None,
) -> dict[str, Any]:
    """Export every variable + current value to a CSV file.

    CSV layout::

        name,value,kind,defined,used_in_document

    Mirrors the row shape of ``saip.list_variables`` so a CSV exported
    by one operator can be re-imported by another (or by the same
    operator on a sister profile).
    """
    import csv as _csv
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    out_text = str(output_path or "").strip()
    if len(sid) == 0 or len(out_text) == 0:
        raise ValueError("session_id and output_path are required.")
    target = Path(os.path.expanduser(out_text)).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    payload = _collect_variables(handle["decoded_document"])
    rows = payload.get("variables") or []
    fieldnames = ["name", "value", "kind", "defined", "used_in_document"]
    with target.open("w", encoding="utf-8", newline="") as stream:
        writer = _csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
    return {
        "session_id": sid,
        "output_path": str(target),
        "exported_count": len(rows),
    }


def _dispatch_import_variables_csv(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    input_path: Any = None,
    name_column: Any = None,
    value_column: Any = None,
) -> dict[str, Any]:
    """Bulk-apply variable overrides from a CSV file.

    Each row in the CSV becomes a single ``saip.set_variable`` call.
    Column names default to ``name`` and ``value`` but can be overridden
    so the operator does not have to rewrite a CSV exported elsewhere.
    Rows missing either column (or carrying an empty name) are
    skipped and reported in ``skipped_rows``.
    """
    import csv as _csv
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_profile_template import (
        apply_placeholder_overrides_to_loaded_document,
        normalize_placeholder_name,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    in_text = str(input_path or "").strip()
    if len(sid) == 0 or len(in_text) == 0:
        raise ValueError("session_id and input_path are required.")
    name_col = str(name_column or "name").strip() or "name"
    value_col = str(value_column or "value").strip() or "value"
    source = Path(os.path.expanduser(in_text)).resolve()
    if source.is_file() is False:
        raise FileNotFoundError(f"input_path not found: {source}")

    _ensure_pysim_importable()
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)

    assignments: dict[str, str] = {}
    skipped: list[dict[str, Any]] = []
    with source.open("r", encoding="utf-8", newline="") as stream:
        reader = _csv.DictReader(stream)
        if reader.fieldnames is None or name_col not in reader.fieldnames:
            raise ValueError(
                f"CSV header missing required column {name_col!r}; "
                f"available: {reader.fieldnames}",
            )
        for row_index, row in enumerate(reader, start=2):
            name = str(row.get(name_col) or "").strip()
            if len(name) == 0:
                skipped.append({"row": row_index, "reason": "empty name"})
                continue
            if value_col not in row:
                skipped.append({"row": row_index, "reason": f"missing {value_col!r}"})
                continue
            value = str(row.get(value_col) or "")
            assignments[name] = value

    if len(assignments) == 0:
        return {
            "session_id": sid,
            "input_path": str(source),
            "applied_count": 0,
            "skipped_rows": skipped,
            "summaries": ["CSV contained no usable rows."],
        }

    summaries = apply_placeholder_overrides_to_loaded_document(
        handle["decoded_document"],
        assignments,
    )
    for name, value in assignments.items():
        normalised = normalize_placeholder_name(name)
        handle["applied_overrides"][normalised] = value

    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
        _mark_dirty(handle, -1)
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")

    return {
        "session_id": sid,
        "input_path": str(source),
        "applied_count": len(assignments),
        "skipped_rows": skipped,
        "summaries": summaries,
        "overrides_applied": dict(handle["applied_overrides"]),
        "warnings": warnings,
    }


# -- Compare report HTML export ---------------------------------------


def _format_html_diff_report(report: dict[str, Any]) -> str:
    """Render a compare report dict as a self-contained HTML page.

    The CSS is intentionally inline so the artefact survives being
    e-mailed / opened on a spec-review laptop without an internet
    connection. No JavaScript — the manual's PDF-style report works
    the same way.
    """
    import html as _html

    def _esc(value: Any) -> str:
        return _html.escape(str(value or ""), quote=True)

    label_a = _esc(report.get("label_a", "A"))
    label_b = _esc(report.get("label_b", "B"))
    summary = report.get("summary", {}) or {}
    rows = report.get("rows") or report.get("entries") or []

    head = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>SAIP compare: {label_a} vs {label_b}</title>"
        "<style>"
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
        "margin:24px;color:#222;background:#f8f8f8}"
        "h1{font-size:18px;margin-bottom:4px}"
        "h2{font-size:14px;margin-top:24px}"
        "table{border-collapse:collapse;width:100%;background:#fff;"
        "box-shadow:0 1px 2px rgba(0,0,0,.05);font-size:12px}"
        "th,td{padding:6px 10px;border:1px solid #d8d8d8;text-align:left;"
        "vertical-align:top;font-family:'SFMono-Regular',Menlo,monospace}"
        "th{background:#eef2f5;font-weight:600}"
        "tr.added td{background:#e6f7e6}"
        "tr.removed td{background:#fbe6e6}"
        "tr.changed td{background:#fff4d6}"
        ".meta{margin-bottom:16px;color:#555;font-size:12px}"
        "</style></head><body>"
    )
    body_parts: list[str] = [
        f"<h1>SAIP profile compare</h1>",
        f"<div class='meta'><strong>A:</strong> {label_a} &middot; "
        f"<strong>B:</strong> {label_b}</div>",
    ]
    if isinstance(summary, dict) and len(summary) > 0:
        body_parts.append("<h2>Summary</h2><table><tr>")
        keys = list(summary.keys())
        body_parts.append("".join(f"<th>{_esc(k)}</th>" for k in keys))
        body_parts.append("</tr><tr>")
        body_parts.append("".join(f"<td>{_esc(summary[k])}</td>" for k in keys))
        body_parts.append("</tr></table>")

    body_parts.append("<h2>Differences</h2>")
    if isinstance(rows, list) is False or len(rows) == 0:
        body_parts.append("<p><em>No differences recorded in this report.</em></p>")
    else:
        body_parts.append(
            "<table><tr><th>Section</th><th>Path</th><th>Status</th>"
            f"<th>{label_a}</th><th>{label_b}</th></tr>"
        )
        for row in rows:
            if isinstance(row, dict) is False:
                continue
            status = str(row.get("status") or row.get("change") or "").lower()
            row_class = ""
            if status in ("added", "added_a", "added_b"):
                row_class = " class='added'"
            elif status in ("removed", "removed_a", "removed_b", "deleted"):
                row_class = " class='removed'"
            elif status in ("changed", "modified"):
                row_class = " class='changed'"
            body_parts.append(
                f"<tr{row_class}>"
                f"<td>{_esc(row.get('section', ''))}</td>"
                f"<td>{_esc(row.get('path', row.get('field', '')))}</td>"
                f"<td>{_esc(row.get('status', row.get('change', '')))}</td>"
                f"<td>{_esc(row.get('value_a', row.get('a', '')))}</td>"
                f"<td>{_esc(row.get('value_b', row.get('b', '')))}</td>"
                "</tr>"
            )
        body_parts.append("</table>")

    body_parts.append("</body></html>")
    return head + "".join(body_parts)


def _dispatch_compare_report_html(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    target_path: Any = None,
    output_path: Any = None,
) -> dict[str, Any]:
    """Run ``saip.compare_to_path`` and write the report as HTML.

    Convenience wrapper around the JSON compare dispatcher — the GUI
    calls this when the operator hits "Export HTML report" from the
    compare-results pane.
    """
    sid = str(session_id or "").strip()
    target_text = str(target_path or "").strip()
    out_text = str(output_path or "").strip()
    if len(sid) == 0 or len(target_text) == 0 or len(out_text) == 0:
        raise ValueError(
            "session_id, target_path, and output_path are all required.",
        )
    report = _dispatch_compare_to_path(
        ctx=ctx,
        session_id=sid,
        target_path=target_text,
    )
    target = Path(os.path.expanduser(out_text)).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_format_html_diff_report(report), encoding="utf-8")
    return {
        "session_id": sid,
        "target_path": report.get("target_path", target_text),
        "output_path": str(target),
        "format": "html",
        "summary": report.get("summary", {}),
    }


# -- PE text search ---------------------------------------------------
#
# Counterpart of ``saip.search_files``: searches PE-level decoded
# JSON content (PIN configuration, AKA params, security-domain
# install parameters, ...). Useful when an operator knows a value
# (an AID, an OID fragment, a hex pattern) but doesn't know which
# PE carries it.


def _dispatch_search_pe_text(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    query: Any = None,
    mode: Any = None,
    case_sensitive: Any = None,
) -> dict[str, Any]:
    """Substring / regex search over every PE's value-notation text."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    query_text = str(query or "")
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    if len(query_text) == 0:
        raise ValueError("query is required.")
    mode_text = str(mode or "substring").strip().lower() or "substring"
    if mode_text not in ("substring", "regex"):
        raise ValueError(f"mode must be 'substring' or 'regex': {mode!r}")
    case_flag = bool(case_sensitive) if case_sensitive is not None else False

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pes = handle["pes"]
    section_keys = _sections_by_pe_index(handle["decoded_document"])

    if mode_text == "regex":
        flags = 0 if case_flag else re.IGNORECASE
        try:
            pattern = re.compile(query_text, flags)
        except re.error as error:
            raise ValueError(f"invalid regex {query_text!r}: {error}") from error
        matcher = lambda haystack: pattern.search(haystack) is not None
    else:
        needle = query_text if case_flag else query_text.lower()
        matcher = (
            (lambda haystack: needle in haystack)
            if case_flag
            else (lambda haystack: needle in haystack.lower())
        )

    matches: list[dict[str, Any]] = []
    for index, pe in enumerate(pes.pe_list):
        decoded = _jsonify_decoded(getattr(pe, "decoded", {}))
        text = json.dumps(decoded, ensure_ascii=False, sort_keys=True)
        if matcher(text) is False:
            continue
        section_key = section_keys[index] if 0 <= index < len(section_keys) else ""
        matches.append(
            {
                "pe_index": index,
                "section_key": section_key,
                "type": str(getattr(pe, "type", "unknown")),
                "label": _pe_display_label(pe),
            }
        )

    return {
        "session_id": sid,
        "query": query_text,
        "mode": mode_text,
        "case_sensitive": case_flag,
        "match_count": len(matches),
        "matches": matches,
    }


# -- ProfileHeader edit dispatchers ------------------------------------
#
# The ProfileHeader PE carries every profile-wide knob the operator
# regularly tweaks: ICCID, profileType, mandatory services, GFSTE list,
# mandatory AIDs, connectivity parameters, IoT PIX. These dispatchers
# each cover one logical group so the GUI can chain them without
# round-tripping the entire header on every keystroke.
#
# Pattern (shared with ``_dispatch_set_variable``):
#   1. Mutate the in-memory header dict via the spec-aware helper.
#   2. Re-encode the sequence so ``handle["pes"]`` stays in sync.
#   3. Mark the header PE dirty so the GUI's "unsaved changes" banner
#      lights up.


def _profile_header_dispatch_prelude(
    sid_raw: Any,
) -> tuple[str, dict[str, Any], str, dict[str, Any], int]:
    """Resolve the session and locate the header section.

    Returns ``(session_id, handle, section_key, header_dict, pe_index)``.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_profile_header_edit import locate_header_section

    sid = str(sid_raw or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section_key, header_dict = locate_header_section(handle["decoded_document"])
    pe_index = _resolve_pe_index(handle, section_key)
    return sid, handle, section_key, header_dict, pe_index


def _profile_header_finish(
    sid: str,
    handle: dict[str, Any],
    pe_index: int,
    summaries: list[str],
) -> dict[str, Any]:
    """Re-encode the sequence and assemble the dispatcher response."""
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )
    from Tools.ProfilePackage.saip_profile_header_edit import (
        header_summary,
        locate_header_section,
    )

    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, pe_index)
    _, header_dict = locate_header_section(handle["decoded_document"])
    response: dict[str, Any] = {
        "session_id": sid,
        "pe_index": pe_index,
        "summaries": summaries,
        "header": header_summary(header_dict),
    }
    if len(warnings) > 0:
        response["warnings"] = warnings
    return response


def _dispatch_get_profile_header(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Return the ProfileHeader projection (no mutation)."""
    from Tools.ProfilePackage.saip_profile_header_edit import header_summary

    sid, _handle, section_key, header_dict, pe_index = (
        _profile_header_dispatch_prelude(session_id)
    )
    return {
        "session_id": sid,
        "pe_index": pe_index,
        "section_key": section_key,
        "header": header_summary(header_dict),
    }


def _dispatch_update_profile_header_field(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    field: Any = None,
    value: Any = None,
) -> dict[str, Any]:
    """Update a single scalar field on the ProfileHeader.

    Recognised ``field`` values:

    * ``version`` — ``major.minor`` SAIP version pair.
    * ``major_version`` — SAIP major-version UInt8.
    * ``minor_version`` — SAIP minor-version UInt8.
    * ``profile_type`` — UTF-8 label, 1..100 chars (clears on empty input).
    * ``iccid_digits`` — 19 or 20 decimal digits in ProfileHeader order.
    * ``iccid_hex`` — 20-nybble header-order hex (advanced override).
    * ``iccid_from_ef`` — derive header ICCID from EF.ICCID fill content.
    * ``pol_hex`` — policy-rules bitmask hex (clears on empty input).
    * ``connectivity_parameters_hex`` — opaque BER-TLV blob hex
      (clears on empty input).
    * ``iot_pix_hex`` — IoT Minimal Profile PIX hex (7..11 bytes,
      clears on empty input).
    """
    from Tools.ProfilePackage.saip_profile_header_edit import (
        set_connectivity_parameters_hex,
        set_iccid_digits,
        set_iccid_hex,
        set_iot_pix_hex,
        set_major_minor_version,
        set_pol_hex,
        set_profile_type,
        sync_header_iccid_from_ef,
    )

    field_text = str(field or "").strip().lower()
    if len(field_text) == 0:
        raise ValueError("field is required.")

    sid, handle, _section_key, header_dict, pe_index = (
        _profile_header_dispatch_prelude(session_id)
    )

    if field_text in ("version", "major_minor_version"):
        parts = re.split(r"[.\s/,;:]+", str(value or "").strip())
        parts = [part for part in parts if len(part) > 0]
        if len(parts) != 2:
            raise ValueError("version must be a major.minor pair, e.g. 3.3.")
        summary = set_major_minor_version(
            header_dict,
            major=parts[0],
            minor=parts[1],
        )
        return _profile_header_finish(sid, handle, pe_index, [summary])
    if field_text == "major_version":
        summary = set_major_minor_version(header_dict, major=value)
        return _profile_header_finish(sid, handle, pe_index, [summary])
    if field_text == "minor_version":
        summary = set_major_minor_version(header_dict, minor=value)
        return _profile_header_finish(sid, handle, pe_index, [summary])
    if field_text in ("iccid_from_ef", "sync_iccid_from_ef"):
        summary = sync_header_iccid_from_ef(handle["decoded_document"])
        return _profile_header_finish(sid, handle, pe_index, [summary])

    dispatch = {
        "profile_type": set_profile_type,
        "iccid_digits": set_iccid_digits,
        "iccid_hex": set_iccid_hex,
        "pol_hex": set_pol_hex,
        "connectivity_parameters_hex": set_connectivity_parameters_hex,
        "iot_pix_hex": set_iot_pix_hex,
    }
    handler = dispatch.get(field_text)
    if handler is None:
        raise ValueError(
            f"unknown ProfileHeader field {field!r}; supported: "
            + ", ".join(sorted(dispatch.keys())),
        )
    summary = handler(header_dict, value)
    return _profile_header_finish(sid, handle, pe_index, [summary])


def _dispatch_set_profile_header_versions(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    major: Any = None,
    minor: Any = None,
) -> dict[str, Any]:
    """Compatibility dispatcher for the typed ProfileHeader version editor."""
    from Tools.ProfilePackage.saip_profile_header_edit import set_major_minor_version

    sid, handle, _section_key, header_dict, pe_index = (
        _profile_header_dispatch_prelude(session_id)
    )
    summary = set_major_minor_version(header_dict, major=major, minor=minor)
    return _profile_header_finish(sid, handle, pe_index, [summary])


def _dispatch_set_mandatory_services(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    services: Any = None,
) -> dict[str, Any]:
    """Replace ``eUICC-Mandatory-services`` with the supplied dict."""
    from Tools.ProfilePackage.saip_profile_header_edit import set_mandatory_services

    if isinstance(services, dict) is False:
        raise ValueError("services must be a JSON object {service: bool}.")
    sid, handle, _section_key, header_dict, pe_index = (
        _profile_header_dispatch_prelude(session_id)
    )
    summary = set_mandatory_services(header_dict, services)
    return _profile_header_finish(sid, handle, pe_index, [summary])


def _dispatch_set_mandatory_gfste(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    oids: Any = None,
) -> dict[str, Any]:
    """Replace ``eUICC-Mandatory-GFSTEList`` with the supplied OID list."""
    from Tools.ProfilePackage.saip_profile_header_edit import set_mandatory_gfste

    if oids is None:
        oids = []
    if isinstance(oids, (list, tuple)) is False:
        raise ValueError("oids must be a JSON array of OID strings.")
    sid, handle, _section_key, header_dict, pe_index = (
        _profile_header_dispatch_prelude(session_id)
    )
    summary = set_mandatory_gfste(header_dict, list(oids))
    return _profile_header_finish(sid, handle, pe_index, [summary])


def _dispatch_set_mandatory_aids(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    aids: Any = None,
) -> dict[str, Any]:
    """Replace ``eUICC-Mandatory-AIDs`` with the supplied list."""
    from Tools.ProfilePackage.saip_profile_header_edit import set_mandatory_aids

    if aids is None:
        aids = []
    if isinstance(aids, (list, tuple)) is False:
        raise ValueError("aids must be a JSON array of {aid, version} entries.")
    sid, handle, _section_key, header_dict, pe_index = (
        _profile_header_dispatch_prelude(session_id)
    )
    summary = set_mandatory_aids(header_dict, list(aids))
    return _profile_header_finish(sid, handle, pe_index, [summary])


# -- SecurityDomain symbolic decoders ---------------------------------
#
# Stateless helpers — operate on the raw byte values directly, no
# session lookup required. Useful for the GUI dropdown editors that
# need to show "Security Domain | DAP Verification | Card Reset"
# instead of "0x86 00 00", and round-trip the operator's selection
# back into the SAIP decoded document.


def _dispatch_decode_sd_privileges(
    ctx: ActionContext,
    *,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Decode a 3-byte ``applicationPrivileges`` blob into named flags."""
    from Tools.ProfilePackage.saip_security_domain_decode import decode_privileges

    return decode_privileges(hex_value)


def _dispatch_encode_sd_privileges(
    ctx: ActionContext,
    *,
    flags: Any = None,
) -> dict[str, Any]:
    """Encode a list of privilege names into a 3-byte hex string."""
    from Tools.ProfilePackage.saip_security_domain_decode import encode_privileges

    if flags is None:
        flags = []
    if isinstance(flags, (list, tuple)) is False:
        raise ValueError("flags must be a JSON array of privilege names.")
    return {"hex": encode_privileges(list(flags))}


def _dispatch_decode_sd_life_cycle(
    ctx: ActionContext,
    *,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Decode a 1-byte ``lifeCycleState`` into its symbolic name."""
    from Tools.ProfilePackage.saip_security_domain_decode import decode_life_cycle

    return decode_life_cycle(hex_value)


def _dispatch_encode_sd_life_cycle(
    ctx: ActionContext,
    *,
    name_or_hex: Any = None,
) -> dict[str, Any]:
    """Encode a symbolic LCS name (or hex byte) into a 1-byte hex string."""
    from Tools.ProfilePackage.saip_security_domain_decode import encode_life_cycle

    return {"hex": encode_life_cycle(name_or_hex)}


def _dispatch_list_sd_privilege_catalog(
    ctx: ActionContext,
) -> dict[str, Any]:
    """Static catalog of GP CS Table 11-49 privilege flags."""
    from Tools.ProfilePackage.saip_security_domain_decode import (
        life_cycle_catalog,
        privilege_catalog,
    )

    return {
        "privileges": privilege_catalog(),
        "life_cycle_states": life_cycle_catalog(),
    }


# -- PE-PINCodes shared-context dispatchers ---------------------------


def _resolve_pin_pe(
    handle: dict[str, Any],
    pe_index: int,
) -> dict[str, Any]:
    """Locate the PE-PINCodes section in the decoded document."""
    keys = _sections_by_pe_index(handle["decoded_document"])
    if pe_index < 0 or pe_index >= len(keys):
        raise IndexError(f"pe_index {pe_index} out of range 0..{len(keys) - 1}")
    section_key = keys[pe_index]
    section = handle["decoded_document"]["sections"].get(section_key)
    if isinstance(section, dict) is False:
        raise LookupError(f"section {section_key!r} is not a dict.")
    base = re.sub(r"_\d+$", "", section_key)
    if base != "pinCodes":
        raise ValueError(
            f"PE at index {pe_index} is {base!r}, not pinCodes; "
            "shared-context only applies to PE-PINCodes.",
        )
    return section


def _dispatch_get_pin_shared_context(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Project the PE-PINCodes shared-context state."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_pin_shared_context import get_shared_context

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_pin_pe(handle, idx)
    state = get_shared_context(section)
    state["session_id"] = sid
    state["pe_index"] = idx
    return state


def _dispatch_set_pin_shared_context(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    file_path_hex: Any = None,
) -> dict[str, Any]:
    """Switch a PE-PINCodes into shared-context mode (or update its filePath)."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_pin_shared_context import (
        get_shared_context,
        set_shared_context,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_pin_pe(handle, idx)
    summary = set_shared_context(section, file_path_hex=file_path_hex)
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)
    state = get_shared_context(section)
    state["session_id"] = sid
    state["pe_index"] = idx
    state["summary"] = summary
    if len(warnings) > 0:
        state["warnings"] = warnings
    return state


def _dispatch_clear_pin_shared_context(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Switch a PE-PINCodes back to local ``pinconfig`` mode."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_pin_shared_context import (
        get_shared_context,
        set_local_context,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_pin_pe(handle, idx)
    summary = set_local_context(section)
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)
    state = get_shared_context(section)
    state["session_id"] = sid
    state["pe_index"] = idx
    state["summary"] = summary
    if len(warnings) > 0:
        state["warnings"] = warnings
    return state


_PIN_REFERENCE_OPTIONS: tuple[tuple[int, str, str], ...] = tuple(
    [(i, f"pinAppl{i}", f"PIN App {i}") for i in range(1, 9)]
    + [(128 + i, f"secondPINAppl{i}", f"Second PIN App {i}") for i in range(1, 9)]
    + [(9 + i, f"adm{i}", f"ADM {i}") for i in range(1, 6)]
    + [(132 + i, f"adm{i}", f"ADM {i}") for i in range(6, 11)]
)

_PUK_REFERENCE_OPTIONS: tuple[tuple[int, str, str], ...] = tuple(
    [(i, f"pukAppl{i}", f"PUK Reference {i}") for i in range(1, 9)]
    + [(128 + i, f"secondPUKAppl{i}", f"PUK Reference {8 + i}") for i in range(1, 9)]
)


def _pin_puk_section_base(section_key: str) -> str:
    if str(section_key).startswith("pinCodes"):
        return "pinCodes"
    if str(section_key).startswith("pukCodes"):
        return "pukCodes"
    raise ValueError(f"section {section_key!r} is not PE-PINCodes or PE-PUKCodes.")


def _pin_records_from_section(section: Any) -> list[dict[str, Any]]:
    if isinstance(section, dict) is False:
        return []
    raw = section.get("pinCodes")
    if isinstance(raw, tuple) and len(raw) == 2 and isinstance(raw[1], list):
        return [item for item in raw[1] if isinstance(item, dict)]
    if isinstance(raw, dict):
        inner = raw.get("@", raw.get("__ygg_saip_tuple__"))
        if isinstance(inner, list) and len(inner) >= 2 and isinstance(inner[1], list):
            return [item for item in inner[1] if isinstance(item, dict)]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def _set_pin_records_on_section(section: dict[str, Any], records: list[dict[str, Any]]) -> None:
    section.setdefault("pin-Header", {"mandated": None, "identification": 0})
    section["pinCodes"] = ("pinconfig", list(records))


def _puk_records_from_section(section: Any) -> list[dict[str, Any]]:
    if isinstance(section, dict) is False:
        return []
    raw = section.get("pukCodes")
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def _set_puk_records_on_section(section: dict[str, Any], records: list[dict[str, Any]]) -> None:
    section.setdefault("puk-Header", {"mandated": None, "identification": 0})
    section["pukCodes"] = list(records)


def _pin_puk_option_rows(
    options: tuple[tuple[int, str, str], ...],
    used: set[int],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for decimal, name, label in options:
        rows.append(
            {
                "decimal": decimal,
                "hex": f"{decimal:02X}",
                "name": name,
                "label": label,
                "used": decimal in used,
            }
        )
    return rows


def _collect_pin_puk_reference_state(
    decoded_document: dict[str, Any],
) -> dict[str, Any]:
    sections = decoded_document.get("sections") or {}
    pin_by_section: dict[str, list[dict[str, Any]]] = {}
    puk_by_section: dict[str, list[dict[str, Any]]] = {}
    all_pin_refs: set[int] = set()
    all_puk_refs: set[int] = set()
    for section_key, section in sections.items():
        if str(section_key).startswith("pinCodes"):
            rows: list[dict[str, Any]] = []
            for idx, rec in enumerate(_pin_records_from_section(section)):
                key_ref = rec.get("keyReference")
                if isinstance(key_ref, int):
                    all_pin_refs.add(key_ref)
                    rows.append(
                        {
                            "section_key": section_key,
                            "index": idx,
                            "decimal": key_ref,
                            "hex": f"{key_ref:02X}",
                        }
                    )
            pin_by_section[section_key] = rows
        elif str(section_key).startswith("pukCodes"):
            rows = []
            for idx, rec in enumerate(_puk_records_from_section(section)):
                key_ref = rec.get("keyReference")
                if isinstance(key_ref, int):
                    all_puk_refs.add(key_ref)
                    rows.append(
                        {
                            "section_key": section_key,
                            "index": idx,
                            "decimal": key_ref,
                            "hex": f"{key_ref:02X}",
                        }
                    )
            puk_by_section[section_key] = rows
    return {
        "pin_options": _pin_puk_option_rows(_PIN_REFERENCE_OPTIONS, all_pin_refs),
        "puk_options": _pin_puk_option_rows(_PUK_REFERENCE_OPTIONS, all_puk_refs),
        "pin_refs_by_section": pin_by_section,
        "puk_refs_by_section": puk_by_section,
        "defined_puk_references": [
            item for rows in puk_by_section.values() for item in rows
        ],
    }


def _dispatch_pin_puk_reference_catalog(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Return spec-defined and package-defined PIN/PUK reference choices."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    state = _collect_pin_puk_reference_state(handle["decoded_document"])
    state["session_id"] = sid
    state["spec"] = "PEDocumentation PE-PINcodes / PE-PUKcodes; ETSI TS 102 221 §9.5"
    return state


def _next_unused_reference(
    options: tuple[tuple[int, str, str], ...],
    used: set[int],
) -> int:
    for decimal, _name, _label in options:
        if decimal not in used:
            return decimal
    return options[-1][0]


def _dispatch_pin_puk_mutate_entry(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    operation: Any = None,
    index: Any = None,
) -> dict[str, Any]:
    """Add or remove one PE-PINCodes / PE-PUKCodes entry."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    section_name = str(section_key or "").strip()
    op = str(operation or "").strip().lower()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    if len(section_name) == 0:
        raise ValueError("section_key is required.")
    if op not in {"add", "remove"}:
        raise ValueError("operation must be 'add' or 'remove'.")

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    pe_index = _resolve_pe_index(handle, section_name)
    sections = handle["decoded_document"].get("sections") or {}
    section = sections.get(section_name)
    if isinstance(section, dict) is False:
        raise LookupError(f"section {section_name!r} missing or not an object.")
    base = _pin_puk_section_base(section_name)

    if base == "pinCodes":
        records = list(_pin_records_from_section(section))
        if op == "add":
            used = {
                rec.get("keyReference")
                for rec in records
                if isinstance(rec.get("keyReference"), int)
            }
            key_ref = _next_unused_reference(_PIN_REFERENCE_OPTIONS, set(used))
            records.append(
                {
                    "keyReference": key_ref,
                    "maxNumOfAttemps-retryNumLeft": (3 << 4) | 3,
                    "pinAttributes": 0x07,
                    "pinValue": b"11111111",
                }
            )
            summary = f"PIN entry added with keyReference 0x{key_ref:02X}."
        else:
            try:
                idx = int(index)
            except Exception as error:
                raise ValueError(f"index must be an integer: {index!r}") from error
            if idx < 0 or idx >= len(records):
                raise IndexError(f"PIN index {idx} out of range.")
            removed = records.pop(idx)
            key_ref = removed.get("keyReference")
            summary = (
                f"PIN entry {idx + 1} removed"
                + (f" (keyReference 0x{key_ref:02X})." if isinstance(key_ref, int) else ".")
            )
        _set_pin_records_on_section(section, records)
        count = len(records)
    else:
        records = list(_puk_records_from_section(section))
        if op == "add":
            used = {
                rec.get("keyReference")
                for rec in records
                if isinstance(rec.get("keyReference"), int)
            }
            key_ref = _next_unused_reference(_PUK_REFERENCE_OPTIONS, set(used))
            records.append(
                {
                    "keyReference": key_ref,
                    "maxNumOfAttemps-retryNumLeft": (10 << 4) | 10,
                    "pukValue": b"11111111",
                }
            )
            summary = f"PUK entry added with keyReference 0x{key_ref:02X}."
        else:
            try:
                idx = int(index)
            except Exception as error:
                raise ValueError(f"index must be an integer: {index!r}") from error
            if idx < 0 or idx >= len(records):
                raise IndexError(f"PUK index {idx} out of range.")
            removed = records.pop(idx)
            key_ref = removed.get("keyReference")
            summary = (
                f"PUK entry {idx + 1} removed"
                + (f" (keyReference 0x{key_ref:02X})." if isinstance(key_ref, int) else ".")
            )
        _set_puk_records_on_section(section, records)
        count = len(records)

    warnings: list[str] = []
    rebuilt = False
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
        rebuilt = True
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    if rebuilt:
        _refresh_decoded_document(handle)
    _mark_dirty(handle, pe_index)
    payload = {
        "session_id": sid,
        "section_key": section_name,
        "pe_index": pe_index,
        "operation": op,
        "entry_count": count,
        "summary": summary,
    }
    if warnings:
        payload["warnings"] = warnings
    return payload


def _resolve_cdma_pe(handle: dict[str, Any], pe_index: int) -> dict[str, Any]:
    """Locate the PE-CDMAParameter section for the supplied PE index."""
    keys = _sections_by_pe_index(handle["decoded_document"])
    if pe_index < 0 or pe_index >= len(keys):
        raise IndexError(f"pe_index {pe_index} out of range 0..{len(keys) - 1}")
    section_key = keys[pe_index]
    section = handle["decoded_document"]["sections"].get(section_key)
    if isinstance(section, dict) is False:
        raise LookupError(f"section {section_key!r} is not a dict.")
    base = re.sub(r"_\d+$", "", section_key)
    if base != "cdmaParameter":
        raise ValueError(
            f"PE at index {pe_index} is {base!r}, not cdmaParameter.",
        )
    return section


def _dispatch_get_cdma(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Project PE-CDMAParameter fields into the editor JSON shape."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_cdma_edit import cdma_summary

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_cdma_pe(handle, idx)
    summary = cdma_summary(section)
    summary["session_id"] = sid
    summary["pe_index"] = idx
    return summary


def _dispatch_set_cdma_field(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    field: Any = None,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Mutate a single PE-CDMAParameter field by name."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_cdma_edit import cdma_summary, set_cdma_field
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_cdma_pe(handle, idx)
    summary_msg = set_cdma_field(section, field=str(field or ""), hex_value=hex_value)
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)
    payload = cdma_summary(section)
    payload["session_id"] = sid
    payload["pe_index"] = idx
    payload["summary"] = summary_msg
    if len(warnings) > 0:
        payload["warnings"] = warnings
    return payload


def _dispatch_set_cdma_ssd_split(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    ssd_a_hex: Any = None,
    ssd_b_hex: Any = None,
) -> dict[str, Any]:
    """Set ``ssd`` from the SSD-A / SSD-B halves separately."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_cdma_edit import cdma_summary, set_ssd_split
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_cdma_pe(handle, idx)
    summary_msg = set_ssd_split(section, ssd_a_hex=ssd_a_hex, ssd_b_hex=ssd_b_hex)
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)
    payload = cdma_summary(section)
    payload["session_id"] = sid
    payload["pe_index"] = idx
    payload["summary"] = summary_msg
    if len(warnings) > 0:
        payload["warnings"] = warnings
    return payload


def _dispatch_list_cdma_field_catalog(
    ctx: ActionContext,
) -> dict[str, Any]:
    """Static catalog of CDMA fields (length constraints + mandatory flag)."""
    from Tools.ProfilePackage.saip_cdma_edit import supported_fields

    return {"fields": supported_fields()}


def _section_key_base(section_key: str) -> str:
    """Return a section base key without a numeric duplicate suffix."""
    return re.sub(r"_\d+$", "", str(section_key or ""))


def _typed_pe_dispatch_prelude(
    sid_raw: Any,
    pe_index_raw: Any,
    *,
    allowed_bases: set[str],
    label: str,
) -> tuple[str, dict[str, Any], str, dict[str, Any], int]:
    """Resolve a typed PE section by session and PE index."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(sid_raw or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        pe_index = int(pe_index_raw)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index_raw!r}") from error

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    keys = _sections_by_pe_index(handle["decoded_document"])
    if pe_index < 0 or pe_index >= len(keys):
        raise IndexError(f"pe_index {pe_index} out of range 0..{len(keys) - 1}")
    section_key = keys[pe_index]
    base = _section_key_base(section_key)
    if base not in allowed_bases:
        raise ValueError(f"PE at index {pe_index} is {base!r}, not {label}.")
    section = handle["decoded_document"].get("sections", {}).get(section_key)
    if isinstance(section, dict) is False:
        raise LookupError(f"section {section_key!r} is not a dict.")
    return sid, handle, section_key, section, pe_index


def _typed_pe_finish(
    sid: str,
    handle: dict[str, Any],
    section_key: str,
    section: dict[str, Any],
    pe_index: int,
    *,
    summary: str | None = None,
    projector: Any = None,
) -> dict[str, Any]:
    """Rebuild best-effort and return a JSON-safe typed-PE projection."""
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, pe_index)
    payload: dict[str, Any] = {
        "session_id": sid,
        "section_key": section_key,
        "pe_index": pe_index,
    }
    if summary is not None:
        payload["summary"] = summary
    if callable(projector):
        payload.update(projector(section))
    if warnings:
        payload["warnings"] = warnings
    return payload


_SD_SECTION_BASES = {"securityDomain", "mno-sd", "mnosd", "ssd", "isdr", "isdp"}


def _security_domain_prelude(
    session_id: Any,
    pe_index: Any,
) -> tuple[str, dict[str, Any], str, dict[str, Any], int]:
    return _typed_pe_dispatch_prelude(
        session_id,
        pe_index,
        allowed_bases=_SD_SECTION_BASES,
        label="securityDomain",
    )


def _dispatch_get_security_domain(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Project PE-SecurityDomain into the typed editor summary."""
    from Tools.ProfilePackage.saip_security_domain_edit import security_domain_summary

    sid, _handle, section_key, section, idx = _security_domain_prelude(session_id, pe_index)
    payload = {
        "session_id": sid,
        "section_key": section_key,
        "pe_index": idx,
    }
    payload.update(security_domain_summary(section))
    return payload


def _dispatch_add_security_domain_key(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    key_version: Any = None,
    key_identifier: Any = None,
    usage_qualifier_hex: Any = None,
    key_components: Any = None,
    key_access: Any = 0,
    counter_hex: Any = "",
) -> dict[str, Any]:
    """Append a key entry to PE-SecurityDomain keyList."""
    from Tools.ProfilePackage.saip_security_domain_edit import (
        add_key,
        security_domain_summary,
    )

    if isinstance(key_components, list) is False:
        raise ValueError("key_components must be a JSON array.")
    sid, handle, section_key, section, idx = _security_domain_prelude(session_id, pe_index)
    summary = add_key(
        section,
        key_version=key_version,
        key_identifier=key_identifier,
        usage_qualifier_hex=str(usage_qualifier_hex or ""),
        key_components=key_components,
        key_access=key_access,
        counter_hex=str(counter_hex or ""),
    )
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=security_domain_summary,
    )


def _dispatch_remove_security_domain_key(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    key_version: Any = None,
    key_identifier: Any = None,
) -> dict[str, Any]:
    """Remove a key entry from PE-SecurityDomain keyList."""
    from Tools.ProfilePackage.saip_security_domain_edit import (
        remove_key,
        security_domain_summary,
    )

    sid, handle, section_key, section, idx = _security_domain_prelude(session_id, pe_index)
    summary = remove_key(section, key_version=key_version, key_identifier=key_identifier)
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=security_domain_summary,
    )


def _dispatch_replace_security_domain_key(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    key_version: Any = None,
    key_identifier: Any = None,
    usage_qualifier_hex: Any = None,
    key_components: Any = None,
    key_access: Any = 0,
    counter_hex: Any = "",
) -> dict[str, Any]:
    """Replace a PE-SecurityDomain key entry in place."""
    from Tools.ProfilePackage.saip_security_domain_edit import (
        replace_key,
        security_domain_summary,
    )

    if isinstance(key_components, list) is False:
        raise ValueError("key_components must be a JSON array.")
    sid, handle, section_key, section, idx = _security_domain_prelude(session_id, pe_index)
    summary = replace_key(
        section,
        key_version=key_version,
        key_identifier=key_identifier,
        usage_qualifier_hex=str(usage_qualifier_hex or ""),
        key_components=key_components,
        key_access=key_access,
        counter_hex=str(counter_hex or ""),
    )
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=security_domain_summary,
    )


def _dispatch_add_security_domain_perso_block(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    block_hex: Any = None,
) -> dict[str, Any]:
    """Append an opaque SD personalisation block."""
    from Tools.ProfilePackage.saip_security_domain_edit import (
        add_perso_data_block,
        security_domain_summary,
    )

    sid, handle, section_key, section, idx = _security_domain_prelude(session_id, pe_index)
    summary = add_perso_data_block(section, str(block_hex or ""))
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=security_domain_summary,
    )


def _dispatch_remove_security_domain_perso_block(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    index: Any = None,
) -> dict[str, Any]:
    """Remove an SD personalisation block by index."""
    from Tools.ProfilePackage.saip_security_domain_edit import (
        remove_perso_data_block,
        security_domain_summary,
    )

    sid, handle, section_key, section, idx = _security_domain_prelude(session_id, pe_index)
    try:
        block_index = int(index)
    except Exception as error:
        raise ValueError(f"index must be an integer: {index!r}") from error
    summary = remove_perso_data_block(section, block_index)
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=security_domain_summary,
    )


def _dispatch_set_security_domain_instance_field(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    field: Any = None,
    value: Any = None,
) -> dict[str, Any]:
    """Mutate one PE-SecurityDomain instance scalar."""
    from Tools.ProfilePackage.saip_security_domain_edit import (
        security_domain_summary,
        set_instance_aid_hex,
        set_lifecycle_state,
        set_privileges_hex,
    )

    field_text = str(field or "").strip().lower()
    sid, handle, section_key, section, idx = _security_domain_prelude(session_id, pe_index)
    if field_text in ("instance_aid", "instanceaid"):
        summary = set_instance_aid_hex(section, str(value or ""))
    elif field_text in ("privileges", "application_privileges", "applicationprivileges"):
        summary = set_privileges_hex(section, str(value or ""))
    elif field_text in ("lifecycle_state", "life_cycle_state", "lifecyclestate"):
        summary = set_lifecycle_state(section, value)
    else:
        raise ValueError(f"unknown SecurityDomain instance field {field!r}.")
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=security_domain_summary,
    )


def _application_prelude(
    session_id: Any,
    pe_index: Any,
) -> tuple[str, dict[str, Any], str, dict[str, Any], int]:
    return _typed_pe_dispatch_prelude(
        session_id,
        pe_index,
        allowed_bases={"application"},
        label="application",
    )


def _dispatch_get_application(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Project PE-Application into the typed editor summary."""
    from Tools.ProfilePackage.saip_application_edit import application_summary

    sid, _handle, section_key, section, idx = _application_prelude(session_id, pe_index)
    payload = {
        "session_id": sid,
        "section_key": section_key,
        "pe_index": idx,
    }
    payload.update(application_summary(section))
    return payload


def _dispatch_add_application_instance(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    load_package_aid_hex: Any = None,
    class_aid_hex: Any = None,
    instance_aid_hex: Any = None,
    privileges_hex: Any = None,
    application_specific_parameters_hex: Any = "",
    lifecycle_state: Any = 0x07,
    extradite_sd_aid_hex: Any = "",
    uicc_toolkit_parameters_hex: Any = "",
    uicc_access_parameters_hex: Any = "",
    uicc_admin_access_parameters_hex: Any = "",
    process_data_hex_list: Any = None,
) -> dict[str, Any]:
    """Append an ApplicationInstance to PE-Application."""
    from Tools.ProfilePackage.saip_application_edit import (
        add_instance,
        application_summary,
    )

    process_list = process_data_hex_list if isinstance(process_data_hex_list, list) else []
    sid, handle, section_key, section, idx = _application_prelude(session_id, pe_index)
    summary = add_instance(
        section,
        load_package_aid_hex=str(load_package_aid_hex or ""),
        class_aid_hex=str(class_aid_hex or ""),
        instance_aid_hex=str(instance_aid_hex or ""),
        privileges_hex=str(privileges_hex or ""),
        application_specific_parameters_hex=str(application_specific_parameters_hex or ""),
        lifecycle_state=lifecycle_state,
        extradite_sd_aid_hex=str(extradite_sd_aid_hex or ""),
        uicc_toolkit_parameters_hex=str(uicc_toolkit_parameters_hex or ""),
        uicc_access_parameters_hex=str(uicc_access_parameters_hex or ""),
        uicc_admin_access_parameters_hex=str(uicc_admin_access_parameters_hex or ""),
        process_data_hex_list=process_list,
    )
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=application_summary,
    )


def _dispatch_remove_application_instance(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    instance_aid_hex: Any = None,
) -> dict[str, Any]:
    """Remove an ApplicationInstance from PE-Application."""
    from Tools.ProfilePackage.saip_application_edit import (
        application_summary,
        remove_instance,
    )

    sid, handle, section_key, section, idx = _application_prelude(session_id, pe_index)
    summary = remove_instance(section, str(instance_aid_hex or ""))
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=application_summary,
    )


def _dispatch_set_application_load_block(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    load_package_aid_hex: Any = None,
    load_block_object_hex: Any = None,
    security_domain_aid_hex: Any = "",
    non_volatile_code_limit_hex: Any = "",
    volatile_data_limit_hex: Any = "",
    non_volatile_data_limit_hex: Any = "",
    hash_value_hex: Any = "",
) -> dict[str, Any]:
    """Install or replace the PE-Application loadBlock."""
    from Tools.ProfilePackage.saip_application_edit import (
        application_summary,
        set_load_block,
    )

    sid, handle, section_key, section, idx = _application_prelude(session_id, pe_index)
    summary = set_load_block(
        section,
        load_package_aid_hex=str(load_package_aid_hex or ""),
        load_block_object_hex=str(load_block_object_hex or ""),
        security_domain_aid_hex=str(security_domain_aid_hex or ""),
        non_volatile_code_limit_hex=str(non_volatile_code_limit_hex or ""),
        volatile_data_limit_hex=str(volatile_data_limit_hex or ""),
        non_volatile_data_limit_hex=str(non_volatile_data_limit_hex or ""),
        hash_value_hex=str(hash_value_hex or ""),
    )
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=application_summary,
    )


def _dispatch_remove_application_load_block(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Remove the PE-Application loadBlock."""
    from Tools.ProfilePackage.saip_application_edit import (
        application_summary,
        remove_load_block,
    )

    sid, handle, section_key, section, idx = _application_prelude(session_id, pe_index)
    summary = remove_load_block(section)
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=application_summary,
    )


def _rfm_prelude(
    session_id: Any,
    pe_index: Any,
) -> tuple[str, dict[str, Any], str, dict[str, Any], int]:
    return _typed_pe_dispatch_prelude(
        session_id,
        pe_index,
        allowed_bases={"rfm"},
        label="rfm",
    )


def _dispatch_get_rfm(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Project PE-RFM into the typed editor summary."""
    from Tools.ProfilePackage.saip_rfm_edit import rfm_summary

    sid, _handle, section_key, section, idx = _rfm_prelude(session_id, pe_index)
    payload = {
        "session_id": sid,
        "section_key": section_key,
        "pe_index": idx,
    }
    payload.update(rfm_summary(section))
    return payload


def _dispatch_add_rfm_tar(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    tar_hex: Any = None,
) -> dict[str, Any]:
    """Append a TAR to PE-RFM tarList."""
    from Tools.ProfilePackage.saip_rfm_edit import add_tar, rfm_summary

    sid, handle, section_key, section, idx = _rfm_prelude(session_id, pe_index)
    summary = add_tar(section, str(tar_hex or ""))
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=rfm_summary,
    )


def _dispatch_remove_rfm_tar(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    tar_hex: Any = None,
) -> dict[str, Any]:
    """Remove a TAR from PE-RFM tarList."""
    from Tools.ProfilePackage.saip_rfm_edit import remove_tar, rfm_summary

    sid, handle, section_key, section, idx = _rfm_prelude(session_id, pe_index)
    summary = remove_tar(section, str(tar_hex or ""))
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=rfm_summary,
    )


def _dispatch_set_rfm_tar_list(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    tar_hex_list: Any = None,
) -> dict[str, Any]:
    """Replace PE-RFM tarList."""
    from Tools.ProfilePackage.saip_rfm_edit import rfm_summary, set_tar_list

    if isinstance(tar_hex_list, list) is False:
        raise ValueError("tar_hex_list must be a JSON array.")
    sid, handle, section_key, section, idx = _rfm_prelude(session_id, pe_index)
    summary = set_tar_list(section, tar_hex_list)
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=rfm_summary,
    )


def _dispatch_set_rfm_field(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    field: Any = None,
    value: Any = None,
) -> dict[str, Any]:
    """Mutate one PE-RFM scalar field."""
    from Tools.ProfilePackage.saip_rfm_edit import (
        rfm_summary,
        set_instance_aid_hex,
        set_minimum_security_level,
        set_security_domain_aid_hex,
        set_uicc_access_domain,
        set_uicc_admin_access_domain,
    )

    field_text = str(field or "").strip().lower()
    sid, handle, section_key, section, idx = _rfm_prelude(session_id, pe_index)
    if field_text in ("instance_aid", "instanceaid"):
        summary = set_instance_aid_hex(section, str(value or ""))
    elif field_text in ("security_domain_aid", "securitydomainaid"):
        summary = set_security_domain_aid_hex(section, str(value or ""))
    elif field_text in ("minimum_security_level", "minimumsecuritylevel"):
        summary = set_minimum_security_level(section, value)
    elif field_text in ("uicc_access_domain", "uiccaccessdomain"):
        summary = set_uicc_access_domain(section, str(value or ""))
    elif field_text in ("uicc_admin_access_domain", "uiccadminaccessdomain"):
        summary = set_uicc_admin_access_domain(section, str(value or ""))
    else:
        raise ValueError(f"unknown RFM field {field!r}.")
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=rfm_summary,
    )


def _dispatch_set_rfm_adf_access(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    adf_aid_hex: Any = None,
    adf_access_domain_hex: Any = "",
    adf_admin_access_domain_hex: Any = "",
) -> dict[str, Any]:
    """Install or replace PE-RFM ADF access binding."""
    from Tools.ProfilePackage.saip_rfm_edit import rfm_summary, set_adf_access

    sid, handle, section_key, section, idx = _rfm_prelude(session_id, pe_index)
    summary = set_adf_access(
        section,
        adf_aid_hex=str(adf_aid_hex or ""),
        adf_access_domain_hex=str(adf_access_domain_hex or ""),
        adf_admin_access_domain_hex=str(adf_admin_access_domain_hex or ""),
    )
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=rfm_summary,
    )


def _dispatch_remove_rfm_adf_access(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Remove PE-RFM ADF access binding."""
    from Tools.ProfilePackage.saip_rfm_edit import remove_adf_access, rfm_summary

    sid, handle, section_key, section, idx = _rfm_prelude(session_id, pe_index)
    summary = remove_adf_access(section)
    return _typed_pe_finish(
        sid, handle, section_key, section, idx,
        summary=summary, projector=rfm_summary,
    )


def _dispatch_list_mandatory_service_keys(
    ctx: ActionContext,
) -> dict[str, Any]:
    """Static catalog of allowed mandatory-service keys + labels.

    The GUI uses this to populate the multi-select control without
    hard-coding the enum on the client side.
    """
    from Tools.ProfilePackage.saip_profile_header_edit import (
        SERVICES_LIST_KEYS,
        SERVICES_LIST_LABELS,
    )

    return {
        "keys": list(SERVICES_LIST_KEYS),
        "labels": dict(SERVICES_LIST_LABELS),
    }


# ----------------------------------------------------------------------
# Stateless typed-edit dispatchers (round 9 — PE-parity helpers)
# ----------------------------------------------------------------------


def _dispatch_pin_encode_value(
    ctx: ActionContext,
    *,
    value: Any = None,
    coding: Any = None,
    target_byte_length: Any = 8,
    pad_byte: Any = 0xFF,
) -> dict[str, Any]:
    """Coerce a PIN/PUK digits-or-hex value into the on-card hex image."""
    from Tools.ProfilePackage.saip_pin_digits import coerce_to_hex

    target = int(target_byte_length) if target_byte_length is not None else 8
    pad = int(pad_byte) if pad_byte is not None else 0xFF
    hex_value = coerce_to_hex(
        value,
        coding=str(coding or "digits"),
        target_byte_length=target,
        pad_byte=pad,
    )
    return {"hex": hex_value, "byte_length": len(hex_value) // 2}


def _dispatch_pin_decode_value(
    ctx: ActionContext,
    *,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Decode a stored PIN/PUK byte image into its digit prefix + pad audit."""
    from Tools.ProfilePackage.saip_pin_digits import decode_hex_to_digits

    return decode_hex_to_digits(hex_value)


def _dispatch_aka_mapping_option_catalog(ctx: ActionContext) -> dict[str, Any]:
    """Catalog of mapping-option flags for the AKA mappingParameter editor."""
    from Tools.ProfilePackage.saip_aka_mapping import mapping_option_catalog

    return {"options": mapping_option_catalog()}


def _resolve_aka_pe(handle: dict[str, Any], pe_index: int) -> dict[str, Any]:
    """Locate a PE-AKAParameter section by index."""
    keys = _sections_by_pe_index(handle["decoded_document"])
    if pe_index < 0 or pe_index >= len(keys):
        raise IndexError(f"pe_index {pe_index} out of range 0..{len(keys) - 1}")
    section_key = keys[pe_index]
    section = handle["decoded_document"]["sections"].get(section_key)
    if isinstance(section, dict) is False:
        raise LookupError(f"section {section_key!r} is not a dict.")
    base = re.sub(r"_\d+$", "", section_key)
    if base != "akaParameter":
        raise ValueError(
            f"PE at index {pe_index} is {base!r}, not akaParameter.",
        )
    return section


def _dispatch_aka_get_choice(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Project the algoConfiguration CHOICE state of a PE-AKAParameter."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_aka_mapping import get_choice

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_aka_pe(handle, idx)
    state = get_choice(section)
    state["session_id"] = sid
    state["pe_index"] = idx
    return state


def _dispatch_aka_set_mapping_parameter(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    mapping_source_aid: Any = None,
    mapping_options_hex: Any = None,
    mapping_options_flags: Any = None,
) -> dict[str, Any]:
    """Switch a PE-AKAParameter to the mappingParameter CHOICE branch."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_aka_mapping import (
        get_choice,
        set_mapping_parameter,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    flags_list: list[str] | None = None
    if mapping_options_flags is not None:
        if isinstance(mapping_options_flags, (list, tuple)) is False:
            raise ValueError(
                "mapping_options_flags must be a JSON array of flag names.",
            )
        flags_list = [str(item) for item in mapping_options_flags]
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_aka_pe(handle, idx)
    summary = set_mapping_parameter(
        section,
        mapping_source_aid=mapping_source_aid,
        mapping_options_hex=mapping_options_hex,
        mapping_options_flags=flags_list,
    )
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)
    state = get_choice(section)
    state["session_id"] = sid
    state["pe_index"] = idx
    state["summary"] = summary
    if warnings:
        state["warnings"] = warnings
    return state


def _dispatch_aka_set_algo_parameter(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    algorithm_id: Any = None,
    restore_stash: Any = True,
) -> dict[str, Any]:
    """Switch a PE-AKAParameter back to the algoParameter CHOICE branch."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_aka_mapping import (
        get_choice,
        set_algo_parameter,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    algo_id: int | None = None
    if algorithm_id is not None and str(algorithm_id).strip() != "":
        try:
            algo_id = int(algorithm_id)
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"algorithm_id must be an integer: {algorithm_id!r}",
            ) from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_aka_pe(handle, idx)
    summary = set_algo_parameter(
        section,
        algorithm_id=algo_id,
        restore_stash_if_present=bool(restore_stash),
    )
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)
    state = get_choice(section)
    state["session_id"] = sid
    state["pe_index"] = idx
    state["summary"] = summary
    if warnings:
        state["warnings"] = warnings
    return state


def _dispatch_list_sd_catalog_extended(ctx: ActionContext) -> dict[str, Any]:
    """Catalog of SD install-parameter selectors for the GUI dropdowns."""
    from Tools.ProfilePackage.saip_security_domain_catalog import (
        access_domain_catalog,
        afi_catalog,
        key_access_catalog,
        key_component_catalog,
        key_usage_catalog,
        msl_catalog,
        restrict_catalog,
    )

    return {
        "access_domain": access_domain_catalog(),
        "afi": afi_catalog(),
        "key_access": key_access_catalog(),
        "key_component_type": key_component_catalog(),
        "key_usage": key_usage_catalog(),
        "msl": msl_catalog(),
        "restrict": restrict_catalog(),
    }


def _dispatch_sd_decode_field(
    ctx: ActionContext,
    *,
    field: Any = None,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Decode one of the named SD install-parameter byte selectors."""
    from Tools.ProfilePackage import saip_security_domain_catalog as cat

    decoders = {
        "access_domain": cat.decode_access_domain,
        "afi": cat.decode_afi,
        "key_access": cat.decode_key_access,
        "key_component_type": cat.decode_key_component_type,
        "key_usage": cat.decode_key_usage,
        "key_version": cat.decode_key_version,
        "msl": cat.decode_msl,
        "restrict": cat.decode_restrict,
    }
    name = str(field or "").strip().lower()
    if name not in decoders:
        raise ValueError(
            f"unknown SD field {field!r}; allowed: {sorted(decoders.keys())}",
        )
    return decoders[name](hex_value)


def _dispatch_sd_encode_field(
    ctx: ActionContext,
    *,
    field: Any = None,
    name_or_hex: Any = None,
    flags: Any = None,
    msl_kwargs: Any = None,
) -> dict[str, Any]:
    """Encode one of the named SD install-parameter byte selectors."""
    from Tools.ProfilePackage import saip_security_domain_catalog as cat

    name = str(field or "").strip().lower()
    if name == "access_domain":
        return {"hex": cat.encode_access_domain(name_or_hex)}
    if name == "afi":
        return {"hex": cat.encode_afi(name_or_hex)}
    if name == "key_access":
        return {"hex": cat.encode_key_access(name_or_hex)}
    if name == "key_component_type":
        return {"hex": cat.encode_key_component_type(name_or_hex)}
    if name == "key_usage":
        if flags is not None and isinstance(flags, (list, tuple)) is False:
            raise ValueError("flags must be a JSON array of usage names.")
        return {"hex": cat.encode_key_usage(list(flags) if flags else [])}
    if name == "restrict":
        if flags is not None and isinstance(flags, (list, tuple)) is False:
            raise ValueError("flags must be a JSON array of restrict-flag names.")
        return {"hex": cat.encode_restrict(list(flags) if flags else [])}
    if name == "msl":
        if isinstance(msl_kwargs, dict) is False:
            raise ValueError("msl_kwargs must be a JSON object for the MSL encoder.")
        return {"hex": cat.encode_msl(**msl_kwargs)}
    raise ValueError(
        f"unknown SD field {field!r}; allowed: access_domain / afi / "
        "key_access / key_component_type / key_usage / restrict / msl.",
    )


def _dispatch_arr_encode_reference(
    ctx: ActionContext,
    *,
    file_id: Any = None,
    record_index: Any = None,
) -> dict[str, Any]:
    """Build a 3-byte ``securityAttributesReferenced`` value from FID + record index."""
    from Tools.ProfilePackage.saip_arr_record_picker import encode_arr_reference

    return {"hex": encode_arr_reference(file_id, record_index)}


def _dispatch_arr_decode_reference(
    ctx: ActionContext,
    *,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Decode a 1- or 3-byte ``securityAttributesReferenced`` reference."""
    from Tools.ProfilePackage.saip_arr_record_picker import decode_arr_reference

    return decode_arr_reference(hex_value)


def _dispatch_arr_list_records(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    section_key: Any = None,
    file_path: Any = None,
) -> dict[str, Any]:
    """Project the records of an EF.ARR for the rule-picker dropdown.

    The dispatcher reuses the existing ``saip.show_file`` plumbing —
    callers supply either a section_key reference plus the on-disk
    file path inside that PE, or rely on the PE-walking machinery to
    resolve the file by path. Output is the projection from
    ``saip_arr_record_picker.project_records``.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_arr_record_picker import project_records

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    sk = str(section_key or "").strip()
    if len(sk) == 0:
        raise ValueError("section_key is required.")
    fp = str(file_path or "").strip()
    if len(fp) == 0:
        raise ValueError("file_path is required (e.g. '/3F00/2F06').")
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = handle["decoded_document"]["sections"].get(sk)
    if isinstance(section, dict) is False:
        raise LookupError(f"section {sk!r} not found in decoded document.")
    files = section.get("files")
    if isinstance(files, dict) is False:
        raise LookupError(f"section {sk!r} carries no ``files`` map.")
    candidate = files.get(fp) or files.get(fp.lstrip("/"))
    if isinstance(candidate, dict) is False:
        raise LookupError(f"file {fp!r} not found in section {sk!r}.")
    records = candidate.get("records")
    return {
        "session_id": sid,
        "section_key": sk,
        "file_path": fp,
        "records": project_records(records if isinstance(records, list) else []),
    }


def _resolve_gfm_pe(handle: dict[str, Any], pe_index: int) -> dict[str, Any]:
    """Locate a PE-GenericFileManagement section by index."""
    keys = _sections_by_pe_index(handle["decoded_document"])
    if pe_index < 0 or pe_index >= len(keys):
        raise IndexError(f"pe_index {pe_index} out of range 0..{len(keys) - 1}")
    section_key = keys[pe_index]
    section = handle["decoded_document"]["sections"].get(section_key)
    if isinstance(section, dict) is False:
        raise LookupError(f"section {section_key!r} is not a dict.")
    base = re.sub(r"_\d+$", "", section_key)
    if base != "genericFileManagement":
        raise ValueError(
            f"PE at index {pe_index} is {base!r}, not genericFileManagement.",
        )
    return section


def _dispatch_gfm_get_df_context(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
) -> dict[str, Any]:
    """Read the single-DF context configured on a PE-GFM."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_gfm_select import get_df_context, list_files

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_gfm_pe(handle, idx)
    ctx_payload = get_df_context(section)
    ctx_payload["session_id"] = sid
    ctx_payload["pe_index"] = idx
    ctx_payload["files"] = list_files(section)
    return ctx_payload


def _dispatch_gfm_set_df_context(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    df_path: Any = None,
) -> dict[str, Any]:
    """Set / replace the single-DF context on a PE-GFM (canonicalising the layout)."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_gfm_select import (
        get_df_context,
        list_files,
        set_df_context,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
    except Exception as error:
        raise ValueError(f"pe_index must be an integer: {pe_index!r}") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_gfm_pe(handle, idx)
    summary = set_df_context(section, df_path=df_path)
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)
    payload = get_df_context(section)
    payload["session_id"] = sid
    payload["pe_index"] = idx
    payload["files"] = list_files(section)
    payload["summary"] = summary
    if warnings:
        payload["warnings"] = warnings
    return payload


def _dispatch_gfm_reorder_files(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    from_index: Any = None,
    to_index: Any = None,
) -> dict[str, Any]:
    """Reorder one file inside the canonical GFM transaction."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_gfm_select import (
        get_df_context,
        list_files,
        reorder_files,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
        src = int(from_index)
        dst = int(to_index)
    except Exception as error:
        raise ValueError(
            "pe_index, from_index and to_index must all be integers.",
        ) from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_gfm_pe(handle, idx)
    summary = reorder_files(section, from_index=src, to_index=dst)
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)
    payload = get_df_context(section)
    payload["session_id"] = sid
    payload["pe_index"] = idx
    payload["files"] = list_files(section)
    payload["summary"] = summary
    if warnings:
        payload["warnings"] = warnings
    return payload


def _dispatch_gfm_remove_file(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    pe_index: Any = None,
    position: Any = None,
) -> dict[str, Any]:
    """Remove a single file from the canonical GFM transaction."""
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.saip_gfm_select import (
        get_df_context,
        list_files,
        remove_file,
    )
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required.")
    try:
        idx = int(pe_index)
        pos = int(position)
    except Exception as error:
        raise ValueError("pe_index and position must be integers.") from error
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    section = _resolve_gfm_pe(handle, idx)
    summary = remove_file(section, position=pos)
    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    _mark_dirty(handle, idx)
    payload = get_df_context(section)
    payload["session_id"] = sid
    payload["pe_index"] = idx
    payload["files"] = list_files(section)
    payload["summary"] = summary
    if warnings:
        payload["warnings"] = warnings
    return payload


def _dispatch_connectivity_decode(
    ctx: ActionContext,
    *,
    hex_value: Any = None,
) -> dict[str, Any]:
    """Break ``connectivityParameters`` octet string into per-bearer fields."""
    from Tools.ProfilePackage.saip_connectivity_parameters import (
        decode_connectivity_parameters,
    )

    return decode_connectivity_parameters(hex_value)


def _dispatch_connectivity_encode(
    ctx: ActionContext,
    *,
    bearers: Any = None,
) -> dict[str, Any]:
    """Re-build ``connectivityParameters`` from a list of bearer dicts."""
    from Tools.ProfilePackage.saip_connectivity_parameters import (
        encode_connectivity_parameters,
    )

    if isinstance(bearers, (list, tuple)) is False:
        raise ValueError("bearers must be a JSON array of bearer dicts.")
    return {"hex": encode_connectivity_parameters(list(bearers))}


def _dispatch_connectivity_bearer_catalog(ctx: ActionContext) -> dict[str, Any]:
    from Tools.ProfilePackage.saip_connectivity_parameters import bearer_catalog

    return {"bearers": bearer_catalog()}


def _dispatch_cap_inspect(
    ctx: ActionContext,
    *,
    payload_hex: Any = None,
    payload_path: Any = None,
) -> dict[str, Any]:
    """Inspect a CAP / IJC payload supplied either as hex or as an on-disk path."""
    from Tools.ProfilePackage.saip_cap_import import (
        parse_cap_or_ijc,
        parse_cap_path,
    )

    if payload_path is not None and str(payload_path).strip() != "":
        return parse_cap_path(str(payload_path))
    if payload_hex is None:
        raise ValueError("supply payload_hex or payload_path.")
    text = re.sub(r"\s+|0x|0X|-|:", "", str(payload_hex))
    if len(text) == 0:
        raise ValueError("payload_hex is empty.")
    if len(text) % 2 != 0:
        raise ValueError("payload_hex has odd nibble count.")
    return parse_cap_or_ijc(bytes.fromhex(text))


def _dispatch_ssim_eaptls_inspect(
    ctx: ActionContext,
    *,
    pem_or_der: Any = None,
    role: Any = "auto",
) -> dict[str, Any]:
    """Parse a single PEM / DER blob and report its kind + metadata."""
    from Tools.ProfilePackage.saip_ssim_eaptls import parse_pem_or_der

    if pem_or_der is None:
        raise ValueError("pem_or_der is required.")
    if isinstance(pem_or_der, (bytes, bytearray)):
        raw = bytes(pem_or_der)
    elif isinstance(pem_or_der, str):
        text = pem_or_der.strip()
        if "-----BEGIN" in text:
            raw = text.encode("utf-8")
        else:
            stripped = re.sub(r"\s+|0x|0X|-|:", "", text)
            if re.fullmatch(r"[0-9A-Fa-f]+", stripped) is None or len(stripped) % 2 != 0:
                raise ValueError(
                    "pem_or_der must be PEM text or hex-encoded DER bytes.",
                )
            raw = bytes.fromhex(stripped)
    else:
        raise ValueError("pem_or_der must be bytes or string.")
    info = parse_pem_or_der(raw)
    info["requested_role"] = str(role or "auto").strip().lower()
    return info


def _dispatch_ssim_eaptls_match_pair(
    ctx: ActionContext,
    *,
    certificate: Any = None,
    private_key: Any = None,
) -> dict[str, Any]:
    """Verify that a certificate's public key matches a supplied private key."""
    from Tools.ProfilePackage.saip_ssim_eaptls import keys_match

    def _coerce(value: Any, *, label: str) -> bytes:
        if value is None:
            raise ValueError(f"{label} is required.")
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str):
            text = value.strip()
            if "-----BEGIN" in text:
                return text.encode("utf-8")
            stripped = re.sub(r"\s+|0x|0X|-|:", "", text)
            if re.fullmatch(r"[0-9A-Fa-f]+", stripped) is None or len(stripped) % 2 != 0:
                raise ValueError(f"{label} must be PEM or hex DER.")
            return bytes.fromhex(stripped)
        raise ValueError(f"{label} must be bytes or string.")

    return keys_match(
        _coerce(certificate, label="certificate"),
        _coerce(private_key, label="private_key"),
    )


# ----------------------------------------------------------------------
# Action specs
# ----------------------------------------------------------------------


_SESSION_FIELD = ActionField(
    name="session_id",
    label="Package session",
    kind="string",
    required=True,
    help="Session id returned by saip.open_package.",
)

_PE_INDEX_FIELD = ActionField(
    name="pe_index",
    label="PE index",
    kind="int",
    required=True,
    min_value=0,
    help="Zero-based PE index as returned by saip.list_pes.",
)


OPEN_SPEC = ActionSpec(
    id="saip.open_package",
    subsystem="SAIP",
    title="Open package",
    description=(
        "Load a SAIP profile package (binary DER, ASCII hex-text, or "
        "decoded JSON) into a GUI session. Returns an opaque session_id "
        "you can feed into the other SAIP actions. Hex-text inputs "
        "(.hex / .txt) are normalised — whitespace stripped, case "
        "folded — before being handed to the DER parser."
    ),
    inputs=(
        ActionField(
            name="path",
            label="File path",
            kind="path",
            required=True,
            help=(
                "Absolute path to a .der / .bin / .upp (binary), "
                ".hex / .txt (ASCII hex), or .json (decoded transcode "
                "output) SAIP package. Double-click to browse."
            ),
            placeholder="/path/to/profile.der or .txt or .json",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_open_package,
    requires_card=False,
    streams=False,
    tags=("saip", "session", "open"),
)


OPEN_UPLOAD_SPEC = ActionSpec(
    id="saip.open_package_upload",
    subsystem="SAIP",
    title="Open uploaded package",
    description=(
        "Load a browser-dropped SAIP profile package from uploaded bytes. "
        "Accepts the same DER, ASCII hex-text, and decoded JSON formats "
        "as saip.open_package."
    ),
    inputs=(
        ActionField(
            name="filename",
            label="Filename",
            kind="string",
            required=True,
            help="Original dropped-file name, used for suffix-based decoding hints.",
        ),
        ActionField(
            name="content_base64",
            label="File content",
            kind="string",
            required=True,
            help="Base64-encoded file payload supplied by the browser.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_open_package_upload,
    requires_card=False,
    streams=False,
    tags=("saip", "session", "open", "upload"),
)


LIST_PES_SPEC = ActionSpec(
    id="saip.list_pes",
    subsystem="SAIP",
    title="List PEs",
    description=(
        "Enumerate every ProfileElement in the loaded package. Rows "
        "include index, type, label, and flags for whether the PE "
        "carries a file system or applications."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="table",
    dispatcher=_dispatch_list_pes,
    requires_card=False,
    streams=False,
    tags=("saip", "read-only"),
)


SHOW_PE_SPEC = ActionSpec(
    id="saip.show_pe",
    subsystem="SAIP",
    title="Show PE",
    description=(
        "Return a single PE as a JSON tree + an ASN.1 value-notation "
        "style text block. Picks a PE by index (use saip.list_pes to "
        "enumerate)."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            default=0,
            min_value=0,
            help="Zero-based index as returned by saip.list_pes.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_show_pe,
    requires_card=False,
    streams=False,
    tags=("saip", "read-only", "pe"),
)


LIST_FILES_SPEC = ActionSpec(
    id="saip.list_files",
    subsystem="SAIP",
    title="List files",
    description=(
        "Union of every file definition across all FS-bearing PEs. "
        "Each row carries the section + dotted field path for the "
        "downstream show_file action."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="sort_by",
            label="Sort by",
            kind="string",
            required=False,
            default="natural",
            help="natural | file_id | name | kind | parent_path | size",
        ),
        ActionField(
            name="descending",
            label="Descending",
            kind="bool",
            required=False,
            default=False,
            help="Reverse the sort order.",
        ),
    ),
    output_kind="table",
    dispatcher=_dispatch_list_files,
    requires_card=False,
    streams=False,
    tags=("saip", "read-only", "files"),
)


SEARCH_FILES_SPEC = ActionSpec(
    id="saip.search_files",
    subsystem="SAIP",
    title="Find files",
    description=(
        "Filter the unified filesystem tree by name, FID, description, "
        "or translation — mirrors the eUICC Profile Creator's File "
        "System tab Find dialog. Set ``regex`` to interpret ``query`` "
        "as a Python regex (case-insensitive)."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="query",
            label="Search string",
            kind="string",
            required=True,
            help="Substring (default) or regex pattern to look for.",
        ),
        ActionField(
            name="mode",
            label="Search area",
            kind="string",
            required=False,
            default="all",
            help=(
                "One of: all (default), name, fid, description, "
                "translation. ``name`` matches friendly_name + pename; "
                "``fid`` matches file_id, short_efid and the resolved "
                "fid_chain; ``description`` matches the file kind, "
                "descriptor bytes and section key; ``translation`` "
                "matches the FCP detail / proprietary fields."
            ),
        ),
        ActionField(
            name="regex",
            label="Regex mode",
            kind="boolean",
            required=False,
            default=False,
            help="Interpret ``query`` as a regex (re.IGNORECASE).",
        ),
    ),
    output_kind="table",
    dispatcher=_dispatch_search_files,
    requires_card=False,
    streams=False,
    tags=("saip", "read-only", "files", "search"),
)


LIST_PE_TEMPLATE_SPEC = ActionSpec(
    id="saip.list_pe_template",
    subsystem="SAIP",
    title="List PE template files",
    description=(
        "Return the TCA SAIP file template catalog for one PE — every "
        "DF/EF defined by the PE's template, marked with whether it is "
        "currently materialised in the PE. Drives the eUICC Profile "
        "Creator-style 'File System Template' tree."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key returned by saip.list_pes.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_list_pe_template,
    requires_card=False,
    streams=False,
    tags=("saip", "read-only", "pe", "template"),
)


ADD_TEMPLATE_FILE_SPEC = ActionSpec(
    id="saip.add_template_file",
    subsystem="SAIP",
    title="Add template file",
    description=(
        "Materialise a DF/EF defined by the PE's TCA SAIP template into "
        "the PE using pySim's default content rules. Marks the owning "
        "PE dirty so saip.save_package picks the change up."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key returned by saip.list_pes.",
        ),
        ActionField(
            name="pe_name",
            label="PE-name",
            kind="string",
            required=True,
            help="Template file pe_name to materialise (e.g. ef-imsi).",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_add_template_file),
    requires_card=False,
    streams=False,
    tags=("saip", "mutate", "pe", "template"),
)


LIST_ADDABLE_FILES_FOR_PE_SPEC = ActionSpec(
    id="saip.list_addable_files_for_pe",
    subsystem="SAIP",
    title="List addable files for PE",
    description=(
        "Project the PE's pySim filesystem template into a JSON DF/EF "
        "tree with already-present entries flagged ``disabled``. The "
        "GUI's Add-file modal mounts this tree and routes the operator's "
        "selection through ``saip.add_template_file`` / "
        "``saip.add_template_subtree``."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key returned by saip.list_pes.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_list_addable_files_for_pe,
    requires_card=False,
    streams=False,
    tags=("saip", "read-only", "pe", "template"),
)


ADD_TEMPLATE_SUBTREE_SPEC = ActionSpec(
    id="saip.add_template_subtree",
    subsystem="SAIP",
    title="Add template subtree",
    description=(
        "Atomically materialise a list of DF/EF template entries into a "
        "PE in declared order (parent DF first, child EFs after). On "
        "any failure the PE state is rolled back to the snapshot taken "
        "before the loop. Marks the owning PE dirty so saip.save_package "
        "picks the change up."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key returned by saip.list_pes.",
        ),
        ActionField(
            name="pe_names",
            label="PE-name list",
            kind="json",
            required=True,
            help="Ordered list of template pe_name strings to add.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_add_template_subtree),
    requires_card=False,
    streams=False,
    tags=("saip", "mutate", "pe", "template"),
)


GFM_ADD_FILE_ELEMENT_SPEC = ActionSpec(
    id="saip.gfm_add_file_element",
    subsystem="SAIP",
    title="GFM — add file element",
    description=(
        "Append a ``filePath`` + ``createFCP`` pair to a PE-GenericFile"
        "Management section. Mirrors the eUICC Profile Creator's "
        "*Add file element* affordance: the operator supplies the "
        "parent DF path plus the new file's FID and FCP byte; the "
        "addition lands as a fresh transaction at the tail of "
        "``fileManagementCMD`` unless ``transaction_index`` selects "
        "an existing block. Marks the owning PE dirty so "
        "saip.save_package picks the change up."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="GFM section key returned by saip.list_pes "
                 "(e.g. ``genericFileManagement`` or ``genericFileManagement_2``).",
        ),
        ActionField(
            name="parent_path",
            label="Parent path (hex FIDs)",
            kind="string",
            required=False,
            help="Hex FID chain of the containing DF, e.g. ``7F10`` for "
                 "DF.TELECOM, ``5F3A`` for DF.PHONEBOOK, or empty for MF. "
                 "Leading ``3F00`` is stripped (pySim adds it on replay).",
        ),
        ActionField(
            name="file_id",
            label="File ID (4 hex digits)",
            kind="string",
            required=True,
            help="2-byte hex FID of the new file, e.g. ``6F3A`` for EF.ADN.",
        ),
        ActionField(
            name="file_descriptor",
            label="File Descriptor Byte (hex)",
            kind="string",
            required=False,
            help="FCP tag 82 — File Descriptor + coding bytes per "
                 "ETSI TS 102 221 §11.1.1.4.3. Defaults to ``4121`` "
                 "(transparent EF) when omitted.",
        ),
        ActionField(
            name="short_efid",
            label="Short EFID (hex)",
            kind="string",
            required=False,
            help="Optional FCP tag 88 — 1-byte Short EF Identifier.",
        ),
        ActionField(
            name="ef_size",
            label="EF size (hex)",
            kind="string",
            required=False,
            help="Optional FCP tag 80 — total transparent EF size in hex.",
        ),
        ActionField(
            name="record_size",
            label="Record size (hex)",
            kind="string",
            required=False,
            help="Optional proprietary record size (record-fixed EFs only).",
        ),
        ActionField(
            name="record_count",
            label="Record count (hex)",
            kind="string",
            required=False,
            help="Optional proprietary record count (record-fixed EFs only).",
        ),
        ActionField(
            name="lcsi",
            label="LCSI (1 hex byte)",
            kind="string",
            required=False,
            help="Life-cycle status (default ``05`` — operational/activated).",
        ),
        ActionField(
            name="transaction_index",
            label="Transaction index",
            kind="integer",
            required=False,
            help="Existing fileManagementCMD index to extend. Omit to "
                 "append the new pair as its own transaction.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_gfm_add_file_element),
    requires_card=False,
    streams=False,
    tags=("saip", "mutate", "pe", "gfm"),
)


REMOVE_TEMPLATE_FILE_SPEC = ActionSpec(
    id="saip.remove_template_file",
    subsystem="SAIP",
    title="Remove template file",
    description=(
        "Drop a file (DF or EF) from a PE's decoded payload by its "
        "pe_name. Marks the owning PE dirty so saip.save_package picks "
        "the change up."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key returned by saip.list_pes.",
        ),
        ActionField(
            name="pe_name",
            label="PE-name",
            kind="string",
            required=True,
            help="Template file pe_name to remove (e.g. ef-imsi).",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_remove_template_file),
    requires_card=False,
    streams=False,
    tags=("saip", "mutate", "pe", "template"),
)


LIST_APPLICATIONS_SPEC = ActionSpec(
    id="saip.list_applications",
    subsystem="SAIP",
    title="List applications",
    description=(
        "Enumerate every application-instance-bearing PE — Security "
        "Domains, MNO-SD, SSDs, JavaCard applications, and remote "
        "management surfaces (RFM / RAM). Each row carries the "
        "Instance / Class / Load Package AIDs, decoded GP privileges, "
        "decoded lifecycle state, application-specific parameters, "
        "and the key-list count so the GUI can render the Applications "
        "tab without re-decoding the JSON payload."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="table",
    dispatcher=_dispatch_list_applications,
    requires_card=False,
    streams=False,
    tags=("saip", "read-only", "applications"),
)


SHOW_FILE_SPEC = ActionSpec(
    id="saip.show_file",
    subsystem="SAIP",
    title="Show file",
    description=(
        "Return FCP + payload for one file definition. Read-only. "
        "Takes the section key and dotted field path surfaced by "
        "saip.list_files."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key returned by saip.list_files.",
        ),
        ActionField(
            name="field_path",
            label="Field path",
            kind="string",
            required=True,
            help="Dotted field path returned by saip.list_files.",
        ),
    ),
    output_kind="fcp",
    dispatcher=_dispatch_show_file,
    requires_card=False,
    streams=False,
    tags=("saip", "read-only", "files"),
)


VALIDATE_SPEC = ActionSpec(
    id="saip.validate",
    subsystem="SAIP",
    title="Validate",
    description=(
        "Run the SAIP profile linter over the loaded package. Returns a "
        "list of findings (code / severity / spec / message) plus a "
        "score and the bucketed summary."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="strict",
            label="Strict mode",
            kind="bool",
            required=False,
            default=False,
            help="Escalate selected WARN findings to FAIL.",
        ),
    ),
    output_kind="findings",
    dispatcher=_dispatch_validate,
    requires_card=False,
    streams=False,
    tags=("saip", "read-only", "lint"),
)


CLOSE_SPEC = ActionSpec(
    id="saip.close_package",
    subsystem="SAIP",
    title="Close package",
    description="Drop the SAIP session and free its in-memory state.",
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_close_package,
    requires_card=False,
    streams=False,
    tags=("saip", "session", "close"),
)


# -- SA-3 editor specs -------------------------------------------------


GET_DIRTY_SPEC = ActionSpec(
    id="saip.get_dirty",
    subsystem="SAIP",
    title="Get dirty state",
    description=(
        "Return the set of PE indices with unsaved edits. Used by the "
        "workbench to gate close / save affordances."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_get_dirty,
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "dirty"),
)


UPDATE_FILE_FIELD_SPEC = ActionSpec(
    id="saip.update_file_field",
    subsystem="SAIP",
    title="Update file field",
    description=(
        "Mutate a single file-definition sub-field in the in-memory "
        "package (SA-3 editor). Editable fields: shortEFID, "
        "fileDescriptor, efFileSize, fileID, linkPath, "
        "securityAttributesReferenced, lcsi, maximumFileSize, "
        "pinStatusTemplateDO. Marks the owning PE dirty."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key (as returned by saip.list_files).",
        ),
        ActionField(
            name="field_path",
            label="Field path",
            kind="string",
            required=True,
            help="File path (e.g. 'ef-iccid').",
        ),
        ActionField(
            name="sub_key",
            label="Sub-field",
            kind="string",
            required=True,
            help="Which file field to mutate (e.g. shortEFID).",
        ),
        ActionField(
            name="hex_value",
            label="Hex value",
            kind="string",
            required=True,
            help="New value as hex (e.g. '10' or '42 21 00 26').",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_update_file_field),
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "write"),
)


UPDATE_FILE_DECODED_SPEC = ActionSpec(
    id="saip.update_file_decoded",
    subsystem="SAIP",
    title="Update file decoded JSON",
    description=(
        "Replace ``pe.decoded[field_path]`` with a JSON-shaped CHOICE "
        "list. The inverse of the JSON projection emitted by "
        "``saip.show_file`` — hex strings round-trip back to bytes "
        "and dicts keep their key order. ``pe.files[field_path]`` is "
        "re-hydrated from the new tuple list so subsequent "
        "``show_file`` calls reflect the edit immediately. Companion "
        "to ``saip.update_file_content`` (whole-body hex) and "
        "``saip.update_record_bytes`` (per-record splice)."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key (as returned by saip.list_files).",
        ),
        ActionField(
            name="field_path",
            label="Field path",
            kind="string",
            required=True,
            help="File path (e.g. 'ef-imsi').",
        ),
        ActionField(
            name="payload",
            label="JSON payload",
            kind="json",
            required=True,
            help=(
                "List of [choice_name, value] pairs matching the "
                "JSON projection from saip.show_file. Hex strings "
                "round-trip back to bytes."
            ),
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_update_file_decoded),
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "write", "json"),
)


UPDATE_FILE_CONTENT_SPEC = ActionSpec(
    id="saip.update_file_content",
    subsystem="SAIP",
    title="Update file content",
    description=(
        "Replace a transparent / BER-TLV EF body wholesale. The new "
        "bytes are FF-padded to ``efFileSize`` when shorter. Companion "
        "to ``saip.update_record_bytes`` for record-fixed EFs."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key (as returned by saip.list_files).",
        ),
        ActionField(
            name="field_path",
            label="Field path",
            kind="string",
            required=True,
            help="File path (e.g. 'ef-imsi').",
        ),
        ActionField(
            name="hex_value",
            label="Hex value",
            kind="string",
            required=True,
            help="New file body as hex (FF-padded to file_size if short).",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_update_file_content),
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "write", "content"),
)


UPDATE_RECORD_BYTES_SPEC = ActionSpec(
    id="saip.update_record_bytes",
    subsystem="SAIP",
    title="Update record bytes",
    description=(
        "Splice a record's bytes into a linear-fixed / cyclic EF in "
        "the in-memory package. The record is identified by its "
        "1-based index; ``hex_value`` must be exactly ``record_size`` "
        "bytes. The owning PE is marked dirty."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key (as returned by saip.list_files).",
        ),
        ActionField(
            name="field_path",
            label="Field path",
            kind="string",
            required=True,
            help="File path (e.g. 'ef-arr').",
        ),
        ActionField(
            name="record_index",
            label="Record index",
            kind="int",
            required=True,
            help="1-based record index (1..nb_rec).",
        ),
        ActionField(
            name="hex_value",
            label="Hex value",
            kind="string",
            required=True,
            help="New record bytes as hex (must equal record_size).",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_update_record_bytes),
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "write", "records"),
)


SAVE_PACKAGE_SPEC = ActionSpec(
    id="saip.save_package",
    subsystem="SAIP",
    title="Save package",
    description=(
        "Persist the current in-memory package to disk. Supports DER "
        "(raw bytes), HEX (ASCII hex of the DER, round-trippable via "
        "saip.open_package), and decoded JSON (preserves PE names and "
        "variable bindings the wire DER cannot carry). Format-default "
        "extension is appended when the supplied path has none. By "
        "default refuses to overwrite an existing target — pass "
        "overwrite=true to replace. Clears the dirty flag on success "
        "unless 'clear_dirty' is explicitly false."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="output_path",
            label="Output path",
            kind="save_path",
            required=True,
            help="Destination file path (.der / .hex / .json). Double-click to browse.",
            placeholder="/path/to/profile.der",
        ),
        ActionField(
            name="format",
            label="Output format",
            kind="string",
            required=False,
            default="der",
            help="'der' (raw DER), 'hex' (ASCII hex), or 'json' (decoded).",
        ),
        ActionField(
            name="overwrite",
            label="Overwrite existing",
            kind="bool",
            required=False,
            default=False,
            help="When false, an existing target raises FileExistsError.",
        ),
        ActionField(
            name="clear_dirty",
            label="Clear dirty flag",
            kind="bool",
            required=False,
            default=True,
            help="Clear the per-PE dirty set after writing.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_save_package,
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "save"),
)


REVERT_CHANGES_SPEC = ActionSpec(
    id="saip.revert_changes",
    subsystem="SAIP",
    title="Revert changes",
    description=(
        "Reload the on-disk source file; discards any in-memory edits "
        "and overrides. Idempotent."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_revert_changes,
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "revert"),
)


LIST_DECODED_FIELDS_SPEC = ActionSpec(
    id="saip.list_decoded_fields",
    subsystem="SAIP",
    title="List decoded fields",
    description=(
        "Enumerate every decodable field in a PE section using the "
        "SAIP decoded-editor model registry. Combines hand-written "
        "editors (ICCID, IMSI, LCSI, USIM/EST/ISIM service tables, "
        "Short EFID, ARR ref, file ID, EF size, fill-file offset), "
        "registered round-trip encoders, read-only decoders, and a "
        "raw-hex fallback so every byte field stays editable."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key (as returned by saip.list_files).",
        ),
        ActionField(
            name="rel_path_prefix",
            label="Rel-path prefix",
            kind="json",
            required=False,
            help=(
                "Optional list of segments to scope the enumeration. "
                "Pass e.g. [\"ef-iccid\", 0] to filter to one EF."
            ),
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_list_decoded_fields,
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "decoded", "list"),
)


APPLY_DECODED_EDIT_SPEC = ActionSpec(
    id="saip.apply_decoded_edit",
    subsystem="SAIP",
    title="Apply decoded edit",
    description=(
        "Encode a decoded-editor payload via the SAIP encoder registry "
        "and splice the result into the in-memory profile element at "
        "the supplied relative path. Marks the owning PE dirty so the "
        "next 'Save package' picks the change up."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key (as returned by saip.list_decoded_fields).",
        ),
        ActionField(
            name="rel_path",
            label="Relative path",
            kind="json",
            required=True,
            help="JSON list of segments (mirrors enumerate_pe_decodable_fields).",
        ),
        ActionField(
            name="field_name",
            label="Field name",
            kind="string",
            required=True,
            help="The field tag (e.g. fillFileContent, lcsi, fileID).",
        ),
        ActionField(
            name="last_ef_key",
            label="Last EF key",
            kind="string",
            required=False,
            help="Owning EF key (e.g. ef-iccid, ef-imsi, ef-ust).",
        ),
        ActionField(
            name="editor_kind",
            label="Editor kind",
            kind="string",
            required=False,
            help=(
                "Editor model identifier (iccid, imsi, lcsi_state, "
                "byte_count, short_efid, arr_reference, file_id, "
                "fill_file_offset, service_table, roundtrip_decoded, "
                "raw_hex_decoded, readonly_json)."
            ),
        ),
        ActionField(
            name="editor_payload",
            label="Editor payload",
            kind="json",
            required=True,
            help="Kind-specific JSON object (mirrors the model's payload).",
        ),
        ActionField(
            name="target_length",
            label="Target length",
            kind="int",
            required=False,
            help="Required byte width for raw-hex / round-trip encoders.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_apply_decoded_edit),
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "decoded", "write"),
)


UPDATE_SD_PARAMETERS_SPEC = ActionSpec(
    id="saip.update_sd_parameters",
    subsystem="SAIP",
    title="Update Security Domain parameters",
    description=(
        "Create, remove, and update PE-SecurityDomain install parameter "
        "slots from the structured parameter editor. Covers C9, "
        "system-specific parameters, UICC toolkit/access parameters, "
        "TAR values, and process data."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE section key for the Security Domain-like PE.",
        ),
        ActionField(
            name="parameter_state",
            label="Parameter state",
            kind="json",
            required=True,
            help="Structured PE-SD parameter state from the GUI editor.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_update_sd_parameters),
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "securityDomain", "decoded", "write"),
)


UPDATE_RFM_TARS_SPEC = ActionSpec(
    id="saip.update_rfm_tars",
    subsystem="SAIP",
    title="Update RFM TAR list",
    description=(
        "Replace a PE-RFM or PE-RAM TAR list with explicit 3-byte Toolkit "
        "Application References."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=False,
            help="PE section key for the RFM/RAM section.",
        ),
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=False,
            help="PE index fallback when section_key is not supplied.",
        ),
        ActionField(
            name="tar_hex_list",
            label="TAR list",
            kind="json",
            required=True,
            help="List of TAR values, each exactly 3 bytes / 6 hex nibbles.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_update_rfm_tars),
    requires_card=False,
    streams=False,
    tags=("saip", "editor", "rfm", "ram", "tar", "write"),
)


# -- SA-4 compare + variables specs ------------------------------------


COMPARE_PACKAGES_SPEC = ActionSpec(
    id="saip.compare",
    subsystem="SAIP",
    title="Compare packages",
    description=(
        "Diff two open SAIP sessions. Returns added / removed / changed "
        "PEs plus file-level deltas for shared sections."
    ),
    inputs=(
        ActionField(
            name="session_a",
            label="Session A",
            kind="string",
            required=True,
            help="Session id for the baseline package.",
        ),
        ActionField(
            name="session_b",
            label="Session B",
            kind="string",
            required=True,
            help="Session id for the comparison package.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_compare_packages,
    requires_card=False,
    streams=False,
    tags=("saip", "compare"),
)


# -- SA-D semantic-diff specs ------------------------------------------


DIFF_PACKAGES_SPEC = ActionSpec(
    id="saip.diff_packages",
    subsystem="SAIP",
    title="Diff packages (semantic)",
    description=(
        "Context-aware semantic diff between two open SAIP sessions. "
        "Each entry is categorised (identity / pe_sequence / files / "
        "applications / security / lifecycle / variables / structure / "
        "intro / other), tagged with a severity (critical / warning / "
        "info / note), and accompanied by a human-readable summary "
        "(e.g. \"USIM Application: imsi changed: 234561111111111 -> "
        "234562222222222\"). Returns the structured ProfileDiffReport "
        "from Tools.ProfilePackage.saip_profile_diff alongside the "
        "underlying structural counts."
    ),
    inputs=(
        ActionField(
            name="session_a",
            label="Session A",
            kind="string",
            required=True,
            help="Session id for the baseline package.",
        ),
        ActionField(
            name="session_b",
            label="Session B",
            kind="string",
            required=True,
            help="Session id for the comparison package.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_diff_packages,
    requires_card=False,
    streams=False,
    tags=("saip", "diff", "semantic"),
)


DIFF_AGAINST_SOURCE_SPEC = ActionSpec(
    id="saip.diff_against_source",
    subsystem="SAIP",
    title="Diff against on-disk source",
    description=(
        "Compare the in-memory session state against a fresh load of "
        "the package's source file. The left side is the on-disk copy; "
        "the right side is the live session (with any unsaved edits + "
        "applied placeholder overrides). The same semantic ProfileDiffReport "
        "shape as saip.diff_packages — useful for the GUI's \"What did "
        "I change?\" affordance."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_diff_against_source,
    requires_card=False,
    streams=False,
    tags=("saip", "diff", "semantic"),
)


DIFF_AGAINST_PATH_SPEC = ActionSpec(
    id="saip.diff_against_path",
    subsystem="SAIP",
    title="Diff against file path",
    description=(
        "Compare a session against an arbitrary SAIP package on disk. "
        "Accepts the same input formats as saip.open_package — DER "
        "(.der/.bin/.upp), ASCII hex text (.hex/.txt), or decoded "
        "transcode JSON. Returns the semantic ProfileDiffReport "
        "(left = session, right = file)."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="path",
            label="File path",
            kind="path",
            required=True,
            help=(
                "Absolute path to the SAIP package to compare against. "
                "Same accepted forms as saip.open_package."
            ),
            placeholder="/path/to/profile.der or .txt or .json",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_diff_against_path,
    requires_card=False,
    streams=False,
    tags=("saip", "diff", "semantic"),
)


LIST_VARIABLES_SPEC = ActionSpec(
    id="saip.list_variables",
    subsystem="SAIP",
    title="List variables",
    description=(
        "Enumerate template placeholder variables referenced anywhere "
        "in the decoded document. Returns a merge of "
        "__ygg_token_defs__ definitions with variables observed in the "
        "sections themselves."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_list_variables,
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "read-only"),
)


SET_VARIABLE_SPEC = ActionSpec(
    id="saip.set_variable",
    subsystem="SAIP",
    title="Set variable",
    description=(
        "Apply a placeholder override (currently ICCID / IMSI are "
        "recognised as structural injectors; arbitrary names are "
        "recorded in __ygg_token_defs__). Re-encodes the package to "
        "keep the sequence in sync."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="name",
            label="Variable name",
            kind="string",
            required=True,
            help="Token name, e.g. ICCID, IMSI, MCC_MNC.",
        ),
        ActionField(
            name="value",
            label="Variable value",
            kind="string",
            required=True,
            help="New value (BCD / hex / textual — depends on the variable).",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_variable),
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "write"),
)


GET_PROFILE_HEADER_SPEC = ActionSpec(
    id="saip.get_profile_header",
    subsystem="SAIP",
    title="Get ProfileHeader",
    description=(
        "Project the ProfileHeader PE into the editor-friendly JSON "
        "shape used by the workbench: ICCID digits, mandatory services, "
        "GFSTE list, mandatory AIDs, connectivity-parameters hex, IoT "
        "PIX. Read-only."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_get_profile_header,
    requires_card=False,
    streams=False,
    tags=("saip", "header", "read-only"),
)


UPDATE_PROFILE_HEADER_FIELD_SPEC = ActionSpec(
    id="saip.update_profile_header_field",
    subsystem="SAIP",
    title="Update ProfileHeader scalar field",
    description=(
        "Mutate one scalar field on the ProfileHeader PE. Field names: "
        "version, major_version, minor_version, profile_type, iccid_digits, iccid_hex, "
        "iccid_from_ef, pol_hex, connectivity_parameters_hex, iot_pix_hex. Empty value clears "
        "optional fields. Re-encodes the sequence on success."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="field",
            label="Header field",
            kind="string",
            required=True,
            help="One of version / major_version / minor_version / profile_type / iccid_digits / iccid_hex / iccid_from_ef / pol_hex / connectivity_parameters_hex / iot_pix_hex.",
        ),
        ActionField(
            name="value",
            label="New value",
            kind="string",
            required=False,
            default="",
            help="Field-specific value. Empty clears optional fields.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_update_profile_header_field),
    requires_card=False,
    streams=False,
    tags=("saip", "header", "write"),
)


SET_PROFILE_HEADER_VERSIONS_SPEC = ActionSpec(
    id="saip.set_profile_header_versions",
    subsystem="SAIP",
    title="Set ProfileHeader version pair",
    description="Set the ProfileHeader major/minor SAIP version fields.",
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="major",
            label="Major",
            kind="int",
            required=False,
            min_value=0,
            help="SAIP major version. Omit to keep the current value.",
        ),
        ActionField(
            name="minor",
            label="Minor",
            kind="int",
            required=False,
            min_value=0,
            help="SAIP minor version. Omit to keep the current value.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_profile_header_versions),
    requires_card=False,
    streams=False,
    tags=("saip", "header", "write"),
)


SET_MANDATORY_SERVICES_SPEC = ActionSpec(
    id="saip.set_mandatory_services",
    subsystem="SAIP",
    title="Set mandatory services",
    description=(
        "Replace the entire eUICC-Mandatory-services map. Pass a JSON "
        "object {service_key: bool} — falsy entries are dropped. The "
        "allowed key catalog comes from saip.list_mandatory_service_keys."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="services",
            label="Services map",
            kind="json",
            required=True,
            help='JSON object, e.g. {"usim": true, "milenage": true}.',
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_mandatory_services),
    requires_card=False,
    streams=False,
    tags=("saip", "header", "write"),
)


SET_MANDATORY_GFSTE_SPEC = ActionSpec(
    id="saip.set_mandatory_gfste",
    subsystem="SAIP",
    title="Set mandatory GFSTE list",
    description=(
        "Replace the eUICC-Mandatory-GFSTEList. Pass a JSON array of "
        "OID strings (e.g. [\"2.23.143.1.2.1\", \"2.23.143.1.2.4\"]). "
        "Empty array clears the list."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="oids",
            label="GFSTE OIDs",
            kind="json",
            required=True,
            help='JSON array of dotted-OID strings.',
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_mandatory_gfste),
    requires_card=False,
    streams=False,
    tags=("saip", "header", "write"),
)


SET_MANDATORY_AIDS_SPEC = ActionSpec(
    id="saip.set_mandatory_aids",
    subsystem="SAIP",
    title="Set mandatory AIDs",
    description=(
        "Replace the eUICC-Mandatory-AIDs. Pass a JSON array of "
        '{"aid": "<hex>", "version": "<2-byte hex>"} entries. Empty '
        "array drops the optional list."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="aids",
            label="Mandatory AIDs",
            kind="json",
            required=True,
            help='JSON array of {aid, version} entries.',
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_mandatory_aids),
    requires_card=False,
    streams=False,
    tags=("saip", "header", "write"),
)


DECODE_SD_PRIVILEGES_SPEC = ActionSpec(
    id="saip.decode_sd_privileges",
    subsystem="SAIP",
    title="Decode SD privileges (GP CS Table 11-49)",
    description=(
        "Decode a 3-byte SecurityDomain ``applicationPrivileges`` blob "
        "into named flags. Stateless — operates on the raw hex value."
    ),
    inputs=(
        ActionField(
            name="hex_value",
            label="Privileges hex",
            kind="string",
            required=True,
            help="3-byte hex (e.g. '860200').",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_decode_sd_privileges,
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "decode", "stateless"),
)


ENCODE_SD_PRIVILEGES_SPEC = ActionSpec(
    id="saip.encode_sd_privileges",
    subsystem="SAIP",
    title="Encode SD privileges",
    description=(
        "Encode an ordered list of GP CS Table 11-49 privilege names "
        "into a 3-byte hex string. Unknown names are rejected."
    ),
    inputs=(
        ActionField(
            name="flags",
            label="Privilege names",
            kind="json",
            required=True,
            help='JSON array, e.g. ["Security Domain", "Card Reset"].',
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_encode_sd_privileges),
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "encode", "stateless"),
)


DECODE_SD_LIFE_CYCLE_SPEC = ActionSpec(
    id="saip.decode_sd_life_cycle",
    subsystem="SAIP",
    title="Decode SD life cycle byte",
    description=(
        "Decode a 1-byte SecurityDomain / Application life-cycle "
        "state into its symbolic name (GP CS §11.1.1). Returns "
        "``CUSTOM`` for non-spec values."
    ),
    inputs=(
        ActionField(
            name="hex_value",
            label="LCS hex byte",
            kind="string",
            required=True,
            help="1-byte hex (e.g. '0F').",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_decode_sd_life_cycle,
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "decode", "stateless"),
)


ENCODE_SD_LIFE_CYCLE_SPEC = ActionSpec(
    id="saip.encode_sd_life_cycle",
    subsystem="SAIP",
    title="Encode SD life cycle",
    description=(
        "Encode a symbolic LCS name (e.g. PERSONALIZED) or hex byte "
        "into a 1-byte hex string."
    ),
    inputs=(
        ActionField(
            name="name_or_hex",
            label="Name or hex byte",
            kind="string",
            required=True,
            help="Symbolic name (PERSONALIZED, LOCKED, ...) or hex (e.g. '0F').",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_encode_sd_life_cycle),
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "encode", "stateless"),
)


LIST_SD_PRIVILEGE_CATALOG_SPEC = ActionSpec(
    id="saip.list_sd_privilege_catalog",
    subsystem="SAIP",
    title="List SD privilege catalog",
    description=(
        "Static catalog of GP CS Table 11-49 privilege flags + the "
        "GP CS §11.1.1 life-cycle states. Used by the GUI dropdowns."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_list_sd_privilege_catalog,
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "catalog"),
)


GET_PIN_SHARED_CONTEXT_SPEC = ActionSpec(
    id="saip.get_pin_shared_context",
    subsystem="SAIP",
    title="Get PIN shared-context state",
    description=(
        "Return the PE-PINCodes CHOICE state: shared (with filePath) "
        "or local (with pinconfig list size). Read-only."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
            help="Zero-based PE index of the PE-PINCodes section.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_get_pin_shared_context,
    requires_card=False,
    streams=False,
    tags=("saip", "pin", "read-only"),
)


SET_PIN_SHARED_CONTEXT_SPEC = ActionSpec(
    id="saip.set_pin_shared_context",
    subsystem="SAIP",
    title="Set PIN shared-context filePath",
    description=(
        "Switch a PE-PINCodes into shared-context mode by setting "
        "``filePath`` to the temporary FID of the directory whose "
        "PIN context this PE inherits (TS 102 221 §8.3.5). Concatenated "
        "16-bit FIDs (e.g. '7F10' or '7F105F3A'); slashes are "
        "stripped. Empty path means MF."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
            help="Zero-based PE index of the PE-PINCodes section.",
        ),
        ActionField(
            name="file_path_hex",
            label="filePath hex",
            kind="string",
            required=False,
            default="",
            help="Concatenated FIDs (e.g. '7F10' or '7F10/5F3A'). Empty = MF.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_pin_shared_context),
    requires_card=False,
    streams=False,
    tags=("saip", "pin", "write"),
)


CLEAR_PIN_SHARED_CONTEXT_SPEC = ActionSpec(
    id="saip.clear_pin_shared_context",
    subsystem="SAIP",
    title="Clear PIN shared-context",
    description=(
        "Switch a PE-PINCodes back to local ``pinconfig`` mode. The "
        "GUI is expected to repopulate the pinconfig list before "
        "re-encoding (SIZE(1..26)) is enforced."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
            help="Zero-based PE index of the PE-PINCodes section.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_clear_pin_shared_context),
    requires_card=False,
    streams=False,
    tags=("saip", "pin", "write"),
)


PIN_PUK_REFERENCE_CATALOG_SPEC = ActionSpec(
    id="saip.pin_puk_reference_catalog",
    subsystem="SAIP",
    title="List PIN/PUK reference choices",
    description=(
        "Return PE-PINCodes / PE-PUKCodes key-reference dropdown options "
        "from PEDocumentation and the PUK references currently defined "
        "in the open profile."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_pin_puk_reference_catalog,
    requires_card=False,
    streams=False,
    tags=("saip", "pin", "puk", "catalog"),
)


PIN_PUK_MUTATE_ENTRY_SPEC = ActionSpec(
    id="saip.pin_puk_mutate_entry",
    subsystem="SAIP",
    title="Add/remove PIN or PUK entry",
    description=(
        "Add or remove one record from a PE-PINCodes pinconfig list or "
        "PE-PUKCodes list, then rebuild the in-memory profile sequence."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=True,
            help="PE-PINCodes or PE-PUKCodes section key.",
        ),
        ActionField(
            name="operation",
            label="Operation",
            kind="string",
            required=True,
            help="'add' or 'remove'.",
        ),
        ActionField(
            name="index",
            label="Entry index",
            kind="int",
            required=False,
            min_value=0,
            help="Zero-based entry index for remove.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_pin_puk_mutate_entry),
    requires_card=False,
    streams=False,
    tags=("saip", "pin", "puk", "write"),
)


GET_CDMA_SPEC = ActionSpec(
    id="saip.get_cdma",
    subsystem="SAIP",
    title="Get PE-CDMAParameter",
    description=(
        "Project a PE-CDMAParameter into the editor JSON shape: "
        "authenticationKey, ssd (with SSD-A / SSD-B split when set), "
        "hrpdAccessAuthenticationData, simpleIPAuthenticationData, "
        "mobileIPAuthenticationData."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
            help="Zero-based index of the PE-CDMAParameter section.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_get_cdma,
    requires_card=False,
    streams=False,
    tags=("saip", "cdma", "read-only"),
)


SET_CDMA_FIELD_SPEC = ActionSpec(
    id="saip.set_cdma_field",
    subsystem="SAIP",
    title="Set PE-CDMAParameter field",
    description=(
        "Mutate one PE-CDMAParameter field by name. Recognised: "
        "authenticationKey (mandatory), ssd, hrpdAccessAuthenticationData, "
        "simpleIPAuthenticationData, mobileIPAuthenticationData. "
        "Empty hex on optional fields drops the entry. Length "
        "constraints come from TCA SAIP §A.2 / 3GPP2 S0016."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
            help="Zero-based PE index of the PE-CDMAParameter section.",
        ),
        ActionField(
            name="field",
            label="Field name",
            kind="string",
            required=True,
            help="Field key (see saip.list_cdma_field_catalog).",
        ),
        ActionField(
            name="hex_value",
            label="New value (hex)",
            kind="string",
            required=False,
            default="",
            help="Hex bytes; empty clears optional fields.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_cdma_field),
    requires_card=False,
    streams=False,
    tags=("saip", "cdma", "write"),
)


SET_CDMA_SSD_SPLIT_SPEC = ActionSpec(
    id="saip.set_cdma_ssd_split",
    subsystem="SAIP",
    title="Set PE-CDMAParameter SSD halves",
    description=(
        "Set ``ssd`` from the SSD-A and SSD-B 8-byte halves "
        "individually. Either half may be omitted to preserve the "
        "current value; clearing both halves drops the optional ssd "
        "field entirely."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
            help="Zero-based PE index of the PE-CDMAParameter section.",
        ),
        ActionField(
            name="ssd_a_hex",
            label="SSD-A (8 bytes hex)",
            kind="string",
            required=False,
            default=None,
            help="Bytes 1..8 of ssd. Omit to keep current.",
        ),
        ActionField(
            name="ssd_b_hex",
            label="SSD-B (8 bytes hex)",
            kind="string",
            required=False,
            default=None,
            help="Bytes 9..16 of ssd. Omit to keep current.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_cdma_ssd_split),
    requires_card=False,
    streams=False,
    tags=("saip", "cdma", "write"),
)


LIST_CDMA_FIELD_CATALOG_SPEC = ActionSpec(
    id="saip.list_cdma_field_catalog",
    subsystem="SAIP",
    title="List PE-CDMAParameter field catalog",
    description=(
        "Static catalog of PE-CDMAParameter fields with their "
        "length constraints and mandatory flag (TCA SAIP §A.2)."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_list_cdma_field_catalog,
    requires_card=False,
    streams=False,
    tags=("saip", "cdma", "catalog"),
)


GET_SECURITY_DOMAIN_SPEC = ActionSpec(
    id="saip.get_security_domain",
    subsystem="SAIP",
    title="Get PE-SecurityDomain",
    description="Project a SecurityDomain PE into the typed editor summary.",
    inputs=(_SESSION_FIELD, _PE_INDEX_FIELD),
    output_kind="json",
    dispatcher=_dispatch_get_security_domain,
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "read-only"),
)


ADD_SECURITY_DOMAIN_KEY_SPEC = ActionSpec(
    id="saip.add_security_domain_key",
    subsystem="SAIP",
    title="Add SecurityDomain key",
    description="Append a key entry to a SecurityDomain keyList.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="key_version", label="KVN", kind="int", required=True, min_value=0),
        ActionField(name="key_identifier", label="KID", kind="int", required=True, min_value=0),
        ActionField(name="usage_qualifier_hex", label="Usage qualifier", kind="string", required=True),
        ActionField(name="key_components", label="Key components", kind="json", required=True),
        ActionField(name="key_access", label="Key access", kind="int", required=False, default=0, min_value=0),
        ActionField(name="counter_hex", label="Counter", kind="string", required=False, default=""),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_add_security_domain_key),
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "write"),
)


REMOVE_SECURITY_DOMAIN_KEY_SPEC = ActionSpec(
    id="saip.remove_security_domain_key",
    subsystem="SAIP",
    title="Remove SecurityDomain key",
    description="Remove a key entry from a SecurityDomain keyList.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="key_version", label="KVN", kind="int", required=True, min_value=0),
        ActionField(name="key_identifier", label="KID", kind="int", required=True, min_value=0),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_remove_security_domain_key),
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "write"),
)


REPLACE_SECURITY_DOMAIN_KEY_SPEC = ActionSpec(
    id="saip.replace_security_domain_key",
    subsystem="SAIP",
    title="Replace SecurityDomain key",
    description="Replace a key entry in a SecurityDomain keyList.",
    inputs=ADD_SECURITY_DOMAIN_KEY_SPEC.inputs,
    output_kind="json",
    dispatcher=_with_history(_dispatch_replace_security_domain_key),
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "write"),
)


ADD_SECURITY_DOMAIN_PERSO_BLOCK_SPEC = ActionSpec(
    id="saip.add_security_domain_perso_block",
    subsystem="SAIP",
    title="Add SecurityDomain perso block",
    description="Append an opaque personalisation block to sdPersoData.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="block_hex", label="Block hex", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_add_security_domain_perso_block),
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "write"),
)


REMOVE_SECURITY_DOMAIN_PERSO_BLOCK_SPEC = ActionSpec(
    id="saip.remove_security_domain_perso_block",
    subsystem="SAIP",
    title="Remove SecurityDomain perso block",
    description="Remove a personalisation block from sdPersoData by index.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="index", label="Block index", kind="int", required=True, min_value=0),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_remove_security_domain_perso_block),
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "write"),
)


SET_SECURITY_DOMAIN_INSTANCE_FIELD_SPEC = ActionSpec(
    id="saip.set_security_domain_instance_field",
    subsystem="SAIP",
    title="Set SecurityDomain instance field",
    description="Mutate one SecurityDomain instance scalar.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="field", label="Field", kind="string", required=True),
        ActionField(name="value", label="Value", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_security_domain_instance_field),
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "write"),
)


GET_APPLICATION_SPEC = ActionSpec(
    id="saip.get_application",
    subsystem="SAIP",
    title="Get PE-Application",
    description="Project an Application PE into the typed editor summary.",
    inputs=(_SESSION_FIELD, _PE_INDEX_FIELD),
    output_kind="json",
    dispatcher=_dispatch_get_application,
    requires_card=False,
    streams=False,
    tags=("saip", "application", "read-only"),
)


ADD_APPLICATION_INSTANCE_SPEC = ActionSpec(
    id="saip.add_application_instance",
    subsystem="SAIP",
    title="Add application instance",
    description="Append an ApplicationInstance to a PE-Application.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="load_package_aid_hex", label="Load package AID", kind="string", required=True),
        ActionField(name="class_aid_hex", label="Class AID", kind="string", required=True),
        ActionField(name="instance_aid_hex", label="Instance AID", kind="string", required=True),
        ActionField(name="privileges_hex", label="Privileges", kind="string", required=True),
        ActionField(name="application_specific_parameters_hex", label="Parameters C9", kind="string", required=False, default=""),
        ActionField(name="lifecycle_state", label="Life cycle", kind="int", required=False, default=7, min_value=0),
        ActionField(name="extradite_sd_aid_hex", label="Extradite SD AID", kind="string", required=False, default=""),
        ActionField(name="uicc_toolkit_parameters_hex", label="Toolkit params", kind="string", required=False, default=""),
        ActionField(name="uicc_access_parameters_hex", label="Access params", kind="string", required=False, default=""),
        ActionField(name="uicc_admin_access_parameters_hex", label="Admin params", kind="string", required=False, default=""),
        ActionField(name="process_data_hex_list", label="Process data", kind="json", required=False, default=[]),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_add_application_instance),
    requires_card=False,
    streams=False,
    tags=("saip", "application", "write"),
)


REMOVE_APPLICATION_INSTANCE_SPEC = ActionSpec(
    id="saip.remove_application_instance",
    subsystem="SAIP",
    title="Remove application instance",
    description="Remove an ApplicationInstance by instance AID.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="instance_aid_hex", label="Instance AID", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_remove_application_instance),
    requires_card=False,
    streams=False,
    tags=("saip", "application", "write"),
)


SET_APPLICATION_LOAD_BLOCK_SPEC = ActionSpec(
    id="saip.set_application_load_block",
    subsystem="SAIP",
    title="Set application load block",
    description="Install or replace the PE-Application loadBlock.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="load_package_aid_hex", label="Load package AID", kind="string", required=True),
        ActionField(name="load_block_object_hex", label="Load block object", kind="string", required=True),
        ActionField(name="security_domain_aid_hex", label="Security Domain AID", kind="string", required=False, default=""),
        ActionField(name="non_volatile_code_limit_hex", label="NV code limit", kind="string", required=False, default=""),
        ActionField(name="volatile_data_limit_hex", label="Volatile data limit", kind="string", required=False, default=""),
        ActionField(name="non_volatile_data_limit_hex", label="NV data limit", kind="string", required=False, default=""),
        ActionField(name="hash_value_hex", label="Hash", kind="string", required=False, default=""),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_application_load_block),
    requires_card=False,
    streams=False,
    tags=("saip", "application", "write"),
)


REMOVE_APPLICATION_LOAD_BLOCK_SPEC = ActionSpec(
    id="saip.remove_application_load_block",
    subsystem="SAIP",
    title="Remove application load block",
    description="Remove the PE-Application loadBlock.",
    inputs=(_SESSION_FIELD, _PE_INDEX_FIELD),
    output_kind="json",
    dispatcher=_with_history(_dispatch_remove_application_load_block),
    requires_card=False,
    streams=False,
    tags=("saip", "application", "write"),
)


GET_RFM_SPEC = ActionSpec(
    id="saip.get_rfm",
    subsystem="SAIP",
    title="Get PE-RFM",
    description="Project an RFM PE into the typed editor summary.",
    inputs=(_SESSION_FIELD, _PE_INDEX_FIELD),
    output_kind="json",
    dispatcher=_dispatch_get_rfm,
    requires_card=False,
    streams=False,
    tags=("saip", "rfm", "read-only"),
)


ADD_RFM_TAR_SPEC = ActionSpec(
    id="saip.add_rfm_tar",
    subsystem="SAIP",
    title="Add RFM TAR",
    description="Append a TAR to PE-RFM tarList.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="tar_hex", label="TAR", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_add_rfm_tar),
    requires_card=False,
    streams=False,
    tags=("saip", "rfm", "write"),
)


REMOVE_RFM_TAR_SPEC = ActionSpec(
    id="saip.remove_rfm_tar",
    subsystem="SAIP",
    title="Remove RFM TAR",
    description="Remove a TAR from PE-RFM tarList.",
    inputs=ADD_RFM_TAR_SPEC.inputs,
    output_kind="json",
    dispatcher=_with_history(_dispatch_remove_rfm_tar),
    requires_card=False,
    streams=False,
    tags=("saip", "rfm", "write"),
)


SET_RFM_TAR_LIST_SPEC = ActionSpec(
    id="saip.set_rfm_tar_list",
    subsystem="SAIP",
    title="Set RFM TAR list",
    description="Replace PE-RFM tarList.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="tar_hex_list", label="TAR list", kind="json", required=True),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_rfm_tar_list),
    requires_card=False,
    streams=False,
    tags=("saip", "rfm", "write"),
)


SET_RFM_FIELD_SPEC = ActionSpec(
    id="saip.set_rfm_field",
    subsystem="SAIP",
    title="Set RFM field",
    description="Mutate one PE-RFM scalar field.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="field", label="Field", kind="string", required=True),
        ActionField(name="value", label="Value", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_rfm_field),
    requires_card=False,
    streams=False,
    tags=("saip", "rfm", "write"),
)


SET_RFM_ADF_ACCESS_SPEC = ActionSpec(
    id="saip.set_rfm_adf_access",
    subsystem="SAIP",
    title="Set RFM ADF access",
    description="Install or replace PE-RFM ADF access binding.",
    inputs=(
        _SESSION_FIELD,
        _PE_INDEX_FIELD,
        ActionField(name="adf_aid_hex", label="ADF AID", kind="string", required=True),
        ActionField(name="adf_access_domain_hex", label="ADF access", kind="string", required=False, default=""),
        ActionField(name="adf_admin_access_domain_hex", label="ADF admin access", kind="string", required=False, default=""),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_set_rfm_adf_access),
    requires_card=False,
    streams=False,
    tags=("saip", "rfm", "write"),
)


REMOVE_RFM_ADF_ACCESS_SPEC = ActionSpec(
    id="saip.remove_rfm_adf_access",
    subsystem="SAIP",
    title="Remove RFM ADF access",
    description="Remove PE-RFM ADF access binding.",
    inputs=(_SESSION_FIELD, _PE_INDEX_FIELD),
    output_kind="json",
    dispatcher=_with_history(_dispatch_remove_rfm_adf_access),
    requires_card=False,
    streams=False,
    tags=("saip", "rfm", "write"),
)


LIST_MANDATORY_SERVICE_KEYS_SPEC = ActionSpec(
    id="saip.list_mandatory_service_keys",
    subsystem="SAIP",
    title="List mandatory-service keys",
    description=(
        "Static catalog of every key allowed in the ServicesList "
        "(TCA SAIP §A.2). Returns {keys: [...], labels: {key: label}}."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_list_mandatory_service_keys,
    requires_card=False,
    streams=False,
    tags=("saip", "header", "catalog"),
)


RESET_VARIABLE_SPEC = ActionSpec(
    id="saip.reset_variable",
    subsystem="SAIP",
    title="Reset variable",
    description=(
        "Roll a single placeholder override back to its source "
        "value. Reloads the on-disk package, drops the named "
        "override from the session, and replays every other "
        "override that was still in effect. Per-variable analogue "
        "of saip.revert_changes."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="name",
            label="Variable name",
            kind="string",
            required=True,
            help="Token name, e.g. ICCID, IMSI, MCC_MNC.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_reset_variable),
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "write"),
)


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


get_registry().register(OPEN_SPEC)
get_registry().register(OPEN_UPLOAD_SPEC)
get_registry().register(LIST_PES_SPEC)
get_registry().register(SHOW_PE_SPEC)
get_registry().register(LIST_FILES_SPEC)
get_registry().register(SEARCH_FILES_SPEC)
get_registry().register(LIST_PE_TEMPLATE_SPEC)
get_registry().register(ADD_TEMPLATE_FILE_SPEC)
get_registry().register(LIST_ADDABLE_FILES_FOR_PE_SPEC)
get_registry().register(ADD_TEMPLATE_SUBTREE_SPEC)
get_registry().register(GFM_ADD_FILE_ELEMENT_SPEC)
get_registry().register(REMOVE_TEMPLATE_FILE_SPEC)
get_registry().register(SHOW_FILE_SPEC)
get_registry().register(LIST_APPLICATIONS_SPEC)
get_registry().register(VALIDATE_SPEC)
get_registry().register(CLOSE_SPEC)

get_registry().register(GET_DIRTY_SPEC)
get_registry().register(UPDATE_FILE_FIELD_SPEC)
get_registry().register(UPDATE_FILE_CONTENT_SPEC)
get_registry().register(UPDATE_FILE_DECODED_SPEC)
get_registry().register(UPDATE_RECORD_BYTES_SPEC)
get_registry().register(SAVE_PACKAGE_SPEC)
get_registry().register(REVERT_CHANGES_SPEC)
get_registry().register(LIST_DECODED_FIELDS_SPEC)
get_registry().register(APPLY_DECODED_EDIT_SPEC)
get_registry().register(UPDATE_SD_PARAMETERS_SPEC)
get_registry().register(UPDATE_RFM_TARS_SPEC)

get_registry().register(COMPARE_PACKAGES_SPEC)
get_registry().register(DIFF_PACKAGES_SPEC)
get_registry().register(DIFF_AGAINST_SOURCE_SPEC)
get_registry().register(DIFF_AGAINST_PATH_SPEC)
get_registry().register(LIST_VARIABLES_SPEC)
get_registry().register(SET_VARIABLE_SPEC)
get_registry().register(RESET_VARIABLE_SPEC)

get_registry().register(GET_PROFILE_HEADER_SPEC)
get_registry().register(UPDATE_PROFILE_HEADER_FIELD_SPEC)
get_registry().register(SET_PROFILE_HEADER_VERSIONS_SPEC)
get_registry().register(SET_MANDATORY_SERVICES_SPEC)
get_registry().register(SET_MANDATORY_GFSTE_SPEC)
get_registry().register(SET_MANDATORY_AIDS_SPEC)
get_registry().register(LIST_MANDATORY_SERVICE_KEYS_SPEC)

get_registry().register(DECODE_SD_PRIVILEGES_SPEC)
get_registry().register(ENCODE_SD_PRIVILEGES_SPEC)
get_registry().register(DECODE_SD_LIFE_CYCLE_SPEC)
get_registry().register(ENCODE_SD_LIFE_CYCLE_SPEC)
get_registry().register(LIST_SD_PRIVILEGE_CATALOG_SPEC)

get_registry().register(GET_PIN_SHARED_CONTEXT_SPEC)
get_registry().register(SET_PIN_SHARED_CONTEXT_SPEC)
get_registry().register(CLEAR_PIN_SHARED_CONTEXT_SPEC)
get_registry().register(PIN_PUK_REFERENCE_CATALOG_SPEC)
get_registry().register(PIN_PUK_MUTATE_ENTRY_SPEC)

get_registry().register(GET_CDMA_SPEC)
get_registry().register(SET_CDMA_FIELD_SPEC)
get_registry().register(SET_CDMA_SSD_SPLIT_SPEC)
get_registry().register(LIST_CDMA_FIELD_CATALOG_SPEC)
get_registry().register(GET_SECURITY_DOMAIN_SPEC)
get_registry().register(ADD_SECURITY_DOMAIN_KEY_SPEC)
get_registry().register(REMOVE_SECURITY_DOMAIN_KEY_SPEC)
get_registry().register(REPLACE_SECURITY_DOMAIN_KEY_SPEC)
get_registry().register(ADD_SECURITY_DOMAIN_PERSO_BLOCK_SPEC)
get_registry().register(REMOVE_SECURITY_DOMAIN_PERSO_BLOCK_SPEC)
get_registry().register(SET_SECURITY_DOMAIN_INSTANCE_FIELD_SPEC)
get_registry().register(GET_APPLICATION_SPEC)
get_registry().register(ADD_APPLICATION_INSTANCE_SPEC)
get_registry().register(REMOVE_APPLICATION_INSTANCE_SPEC)
get_registry().register(SET_APPLICATION_LOAD_BLOCK_SPEC)
get_registry().register(REMOVE_APPLICATION_LOAD_BLOCK_SPEC)
get_registry().register(GET_RFM_SPEC)
get_registry().register(ADD_RFM_TAR_SPEC)
get_registry().register(REMOVE_RFM_TAR_SPEC)
get_registry().register(SET_RFM_TAR_LIST_SPEC)
get_registry().register(SET_RFM_FIELD_SPEC)
get_registry().register(SET_RFM_ADF_ACCESS_SPEC)
get_registry().register(REMOVE_RFM_ADF_ACCESS_SPEC)


# ----------------------------------------------------------------------
# One-shot (stateless) helpers
# ----------------------------------------------------------------------


def _expand_path_list(values: Any) -> list[Path]:
    """Expand a comma-separated string / JSON-array of paths + globs.

    The dispatcher accepts both: a JSON array (preferred for programmatic
    callers) and a single string with comma-separated entries (for ad-hoc
    URL invocations from the browser GUI). Glob patterns (``*``, ``?``,
    ``[`` per :mod:`glob`) are expanded against the file system.
    """
    import glob as _glob

    if values is None:
        return []
    if isinstance(values, str):
        items = [chunk.strip() for chunk in values.split(",") if len(chunk.strip()) > 0]
    elif isinstance(values, (list, tuple)):
        items = [str(item).strip() for item in values if str(item).strip()]
    else:
        raise ValueError("paths must be a string or a list of strings.")

    expanded: list[Path] = []
    seen: set[str] = set()
    for entry in items:
        candidate = os.path.expanduser(entry)
        # ``glob`` returns the literal string when no wildcards match;
        # we still resolve to absolute paths so duplicates collapse.
        matches = _glob.glob(candidate)
        if len(matches) == 0:
            matches = [candidate]
        for match in matches:
            resolved = Path(match).resolve()
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            expanded.append(resolved)
    return expanded


def _dispatch_batch_lint_paths(
    ctx: ActionContext,
    *,
    paths: Any = None,
    strict: Any = None,
) -> dict[str, Any]:
    """Lint multiple SAIP packages in one call (mirrors ``epcval -p``).

    Accepts a comma-separated string or JSON array of paths. Each entry
    may be a literal file path or a glob pattern (e.g. ``Workspace/*.der``).
    Returns one entry per matched path containing the same finding shape
    as ``saip.lint_path``, plus an aggregate summary.
    """
    from Tools.ProfilePackage.lint_engine import SaipProfileLinter

    expanded = _expand_path_list(paths)
    if len(expanded) == 0:
        raise ValueError("paths is required and must resolve to at least one file.")
    strict_flag = bool(strict) if strict is not None else False

    results: list[dict[str, Any]] = []
    aggregate = {
        "total": 0,
        "fail": 0,
        "warn": 0,
        "info": 0,
        "errored": 0,
    }
    for resolved in expanded:
        entry: dict[str, Any] = {"path": str(resolved)}
        if resolved.is_file() is False:
            entry["error"] = f"not a file: {resolved}"
            aggregate["errored"] += 1
            results.append(entry)
            continue
        try:
            package = _load_package_from_path(resolved)
        except Exception as error:
            entry["error"] = f"load failed: {error}"
            aggregate["errored"] += 1
            results.append(entry)
            continue
        try:
            linter = SaipProfileLinter(strict=strict_flag)
            report = linter.lint_decoded_document(
                package["decoded_document"],
                profile_label=str(resolved),
            )
            report_dict = report.to_dict()
        except Exception as error:
            entry["error"] = f"lint failed: {error}"
            aggregate["errored"] += 1
            results.append(entry)
            continue

        findings = []
        for item in report_dict.get("findings", []):
            findings.append(
                {
                    "code": item.get("code", ""),
                    "severity": item.get("severity", "INFO"),
                    "spec": item.get("spec", ""),
                    "path": item.get("path", ""),
                    "message": item.get("message", ""),
                    "recommendation": item.get("recommendation", ""),
                }
            )
        entry.update(
            {
                "encoding": package["encoding"],
                "score": report_dict.get("score", 0),
                "summary": report_dict.get("summary", {}),
                "count": len(findings),
                "findings": findings,
            }
        )
        # Tally severities at the aggregate level so the GUI can render
        # a single PASS/FAIL header without walking the rows.
        sev_counts: dict[str, Any] = report_dict.get("summary", {}) or {}
        aggregate["total"] += 1
        for key in ("fail", "warn", "info"):
            try:
                aggregate[key] += int(sev_counts.get(key.upper(), 0))
            except Exception:
                pass
        results.append(entry)

    return {
        "strict": strict_flag,
        "aggregate": aggregate,
        "results": results,
    }


def _dispatch_batch_personalize(
    ctx: ActionContext,
    *,
    template_path: Any = None,
    data_path: Any = None,
    output_dir: Any = None,
    overwrite: Any = None,
) -> dict[str, Any]:
    """Materialise N personalised DER profiles from one template + a data file.

    Mirrors the eUICC Profile Creator "Batch Personalization" dialog
    (and the ``GENERATE-BATCH`` shell verb). Data file may be CSV /
    JSON / JSONL / YAML; column / key names must match template
    placeholder names 1:1.
    """
    import copy as _copy

    template_text = str(template_path or "").strip()
    data_text = str(data_path or "").strip()
    out_text = str(output_dir or "").strip()
    if len(template_text) == 0 or len(data_text) == 0 or len(out_text) == 0:
        raise ValueError(
            "template_path, data_path, and output_dir are all required.",
        )

    template_resolved = Path(os.path.expanduser(template_text)).resolve()
    data_resolved = Path(os.path.expanduser(data_text)).resolve()
    out_resolved = Path(os.path.expanduser(out_text)).resolve()
    if template_resolved.is_file() is False:
        raise FileNotFoundError(f"template_path not found: {template_resolved}")
    if data_resolved.is_file() is False:
        raise FileNotFoundError(f"data_path not found: {data_resolved}")

    overwrite_flag = bool(overwrite) if overwrite is not None else False

    _ensure_pysim_importable()
    from Tools.ProfilePackage.saip_json_codec import (
        dejsonify_document,
        encode_der_from_document,
    )
    from Tools.ProfilePackage.saip_profile_template import (
        apply_placeholder_overrides_to_loaded_document,
        batch_output_stem,
        extract_template_placeholder_names,
        load_batch_placeholder_records,
        validate_batch_record_assignments,
    )

    raw_text = template_resolved.read_text(encoding="utf-8")
    loaded_template = json.loads(raw_text)
    if isinstance(loaded_template, dict) is False:
        raise ValueError("Template root JSON value must be an object.")

    placeholders = extract_template_placeholder_names(loaded_template)
    if len(placeholders) == 0:
        raise ValueError("Template does not contain any placeholders.")
    token_defs_raw = loaded_template.get("__ygg_token_defs__", {})
    token_defs = dict(token_defs_raw) if isinstance(token_defs_raw, dict) else {}

    records = load_batch_placeholder_records(data_resolved)
    if len(records) == 0:
        raise ValueError("Batch data file did not contain any records.")

    validated: list[tuple[str, dict[str, str]]] = []
    for record in records:
        try:
            assignments = validate_batch_record_assignments(
                record.values,
                template_placeholders=placeholders,
                template_token_defs=token_defs,
            )
        except Exception as error:
            raise ValueError(f"{record.label}: {error}") from error
        validated.append((record.label, assignments))

    out_resolved.mkdir(parents=True, exist_ok=True)
    used_names: set[str] = set()
    generated: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for index, (label, assignments) in enumerate(validated, start=1):
        loaded = _copy.deepcopy(loaded_template)
        try:
            apply_placeholder_overrides_to_loaded_document(loaded, assignments)
            document = dejsonify_document(loaded)
            der = encode_der_from_document(document, _workspace_root())
        except Exception as error:
            failed.append({"label": label, "error": str(error)})
            continue

        base_stem = batch_output_stem(assignments, index=index)
        candidate_name = f"{base_stem}.der"
        suffix_index = 2
        while candidate_name in used_names:
            candidate_name = f"{base_stem}_{suffix_index}.der"
            suffix_index += 1
        used_names.add(candidate_name)
        target = out_resolved / candidate_name
        if target.exists() and overwrite_flag is False:
            skipped.append({"label": label, "path": str(target)})
            continue
        target.write_bytes(der)
        generated.append(
            {
                "label": label,
                "path": str(target),
                "size_bytes": len(der),
                "assignments": assignments,
            }
        )

    return {
        "template_path": str(template_resolved),
        "data_path": str(data_resolved),
        "output_dir": str(out_resolved),
        "overwrite": overwrite_flag,
        "generated_count": len(generated),
        "skipped_count": len(skipped),
        "failed_count": len(failed),
        "generated": generated,
        "skipped": skipped,
        "failed": failed,
    }


def _dispatch_lint_path(
    ctx: ActionContext,
    *,
    path: Any = None,
    strict: Any = None,
) -> dict[str, Any]:
    """Lint a SAIP package file on disk without opening a session.

    Accepts a DER or decoded-JSON input. Useful for CI style checks
    where the operator does not want to juggle ``open_package`` /
    ``close_package`` round-trips.
    """
    from Tools.ProfilePackage.lint_engine import SaipProfileLinter

    path_text = str(path or "").strip()
    if len(path_text) == 0:
        raise ValueError("path is required.")
    resolved = Path(os.path.expanduser(path_text)).resolve()
    if resolved.is_file() is False:
        raise FileNotFoundError(f"not a file: {resolved}")

    package = _load_package_from_path(resolved)
    strict_flag = bool(strict) if strict is not None else False
    linter = SaipProfileLinter(strict=strict_flag)
    report = linter.lint_decoded_document(
        package["decoded_document"],
        profile_label=str(resolved),
    )
    report_dict = report.to_dict()

    findings: list[dict[str, Any]] = []
    for item in report_dict.get("findings", []):
        findings.append(
            {
                "code": item.get("code", ""),
                "severity": item.get("severity", "INFO"),
                "spec": item.get("spec", ""),
                "path": item.get("path", ""),
                "message": item.get("message", ""),
                "recommendation": item.get("recommendation", ""),
            }
        )
    return {
        "path": str(resolved),
        "encoding": package["encoding"],
        "profile": report_dict.get("profile", str(resolved)),
        "strict": report_dict.get("strict", strict_flag),
        "score": report_dict.get("score", 0),
        "summary": report_dict.get("summary", {}),
        "count": len(findings),
        "findings": findings,
    }


def _dispatch_decode_to_json(
    ctx: ActionContext,
    *,
    path: Any = None,
    output_path: Any = None,
) -> dict[str, Any]:
    """One-shot DER / JSON → decoded JSON file writer.

    Runs the same transcode pipeline the SAIP CLI exposes, without
    needing a persisted session handle.
    """
    path_text = str(path or "").strip()
    out_text = str(output_path or "").strip()
    if len(path_text) == 0:
        raise ValueError("path is required.")
    if len(out_text) == 0:
        raise ValueError("output_path is required.")

    resolved = Path(os.path.expanduser(path_text)).resolve()
    if resolved.is_file() is False:
        raise FileNotFoundError(f"not a file: {resolved}")
    out_resolved = Path(os.path.expanduser(out_text)).resolve()
    out_resolved.parent.mkdir(parents=True, exist_ok=True)

    package = _load_package_from_path(resolved)
    _ensure_pysim_importable()
    from Tools.ProfilePackage.saip_json_codec import jsonify_document

    tagged = jsonify_document(package["decoded_document"])
    text = json.dumps(tagged, indent=2, ensure_ascii=False)
    out_resolved.write_text(text, encoding="utf-8")
    return {
        "input_path": str(resolved),
        "output_path": str(out_resolved),
        "encoding": package["encoding"],
        "pe_count": len(package["pes"].pe_list),
        "size_bytes": len(text.encode("utf-8")),
        "note": f"decoded document written to {out_resolved}.",
    }


def _dispatch_save_text_file(
    ctx: ActionContext,
    *,
    output_path: Any = None,
    text: Any = None,
    overwrite: Any = None,
) -> dict[str, Any]:
    """Generic text-to-disk writer used by ribbon helpers.

    Centralises the path validation + parent-directory creation the
    save-as dialog needs so the JS side does not have to round-trip
    through a filesystem-mutation endpoint that is not subsystem-aware.
    """
    out_text = str(output_path or "").strip()
    body = str(text if text is not None else "")
    if len(out_text) == 0:
        raise ValueError("output_path is required.")
    overwrite_flag = bool(overwrite) if overwrite is not None else False

    target = Path(os.path.expanduser(out_text)).resolve()
    if target.exists() and overwrite_flag is False:
        raise FileExistsError(
            f"target already exists (pass overwrite=true to replace): {target}",
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return {
        "output_path": str(target),
        "bytes_written": len(body.encode("utf-8")),
    }


def _dispatch_sync_arr(
    ctx: ActionContext,
    *,
    session_id: Any = None,
    dry_run: Any = None,
) -> dict[str, Any]:
    """SA-G3 — surface ARR-related cross-PE inconsistencies.

    Runs the linter and filters its output to access-rule findings
    (``YRL-ARR-*`` plus the structural prefixes that touch
    ``securityAttributesReferenced`` / ``arrFileFid``). The dispatcher
    intentionally does not mutate the document — automatic ARR repair
    is out of scope for this release; the caller can act on the
    findings via the regular decoded-form editor.
    """
    from yggdrasim_common.gui_server.sessions import get_manager
    from Tools.ProfilePackage.lint_engine import SaipProfileLinter

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    dry_flag = True if dry_run is None else bool(dry_run)

    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    source_path = handle.get("source_path") or "(in-memory package)"

    linter = SaipProfileLinter(strict=False)
    report = linter.lint_decoded_document(
        handle["decoded_document"],
        profile_label=str(source_path),
    )
    report_dict = report.to_dict()

    filtered: list[dict[str, Any]] = []
    arr_file_count = 0
    for item in report_dict.get("findings", []):
        code = str(item.get("code", "")).upper()
        path_text = str(item.get("path", ""))
        if not (
            code.startswith("YRL-ARR-")
            or "securityattributesreferenced" in path_text.lower()
            or "arrfilefid" in path_text.lower()
        ):
            continue
        filtered.append(
            {
                "code": item.get("code", ""),
                "severity": item.get("severity", "INFO"),
                "spec": item.get("spec", ""),
                "path": path_text,
                "message": item.get("message", ""),
                "recommendation": item.get("recommendation", ""),
            }
        )

    # Tally EFs that look like an ARR (record-oriented EFs whose file
    # identifier matches the well-known 2F06 / 6F06 family). Surfaces
    # one number for the GUI banner.
    sections = handle["decoded_document"].get("sections") or {}
    for _key, payload in sections.items():
        files = payload.get("files") or []
        for entry in files:
            fid = str(entry.get("file_id", "") or "").upper()
            if fid in ("2F06", "6F06") or fid.endswith("06") and entry.get("short_efid"):
                arr_file_count += 1

    return {
        "session_id": sid,
        "dry_run": dry_flag,
        "findings": filtered,
        "changes_proposed": 0,
        "changes_applied": 0,
        "arr_file_count": arr_file_count,
        "summary": (
            f"{len(filtered)} ARR-related finding(s); "
            "automatic repair is not implemented in this release. "
            "Use the decoded-form editor to fix each item."
        ),
    }


def _history_apply_swap(
    handle: dict[str, Any],
    *,
    pop_from: str,
    push_to: str,
) -> dict[str, Any]:
    """Pop a snapshot off ``pop_from``, swap it in, push old onto ``push_to``."""
    import copy as _copy
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    history = _history_init(handle)
    if len(history[pop_from]) == 0:
        verb = "undo" if pop_from == "undo" else "redo"
        return {
            "applied": False,
            "summary": f"nothing to {verb}.",
            "undo_depth": len(history["undo"]),
            "redo_depth": len(history["redo"]),
        }
    snapshot = history[pop_from].pop()
    history[push_to].append(_copy.deepcopy(handle.get("decoded_document")))
    while len(history[push_to]) > SAIP_HISTORY_LIMIT:
        history[push_to].pop(0)
    handle["decoded_document"] = snapshot

    warnings: list[str] = []
    try:
        handle["pes"] = build_profile_sequence_from_document(
            handle["decoded_document"], workspace_root=_workspace_root()
        )
    except Exception as error:
        warnings.append(f"Document mutated; re-encode failed: {error}")
    # We don't know exactly which PE changed (snapshots are document-
    # wide), so mark every PE dirty so the GUI reflects all changes.
    for index in range(len(handle["pes"].pe_list)):
        handle["dirty_pes"].add(index)

    return {
        "applied": True,
        "summary": (
            "undid last edit." if pop_from == "undo" else "redid last edit."
        ),
        "warnings": warnings,
        "undo_depth": len(history["undo"]),
        "redo_depth": len(history["redo"]),
    }


def _dispatch_undo(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Pop the most recent snapshot off the undo stack and swap it in."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    result = _history_apply_swap(handle, pop_from="undo", push_to="redo")
    result["session_id"] = sid
    return result


def _dispatch_redo(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    """Reapply the most recently undone snapshot."""
    from yggdrasim_common.gui_server.sessions import get_manager

    sid = str(session_id or "").strip()
    if len(sid) == 0:
        raise ValueError("session_id is required (run saip.open_package first).")
    handle = get_manager().claim(sid)
    _ensure_session_state(handle)
    result = _history_apply_swap(handle, pop_from="redo", push_to="undo")
    result["session_id"] = sid
    return result


LINT_PATH_SPEC = ActionSpec(
    id="saip.lint_path",
    subsystem="SAIP",
    title="Lint package (by path)",
    description=(
        "Lint a SAIP package file directly, without opening a session. "
        "Takes either a DER or decoded-JSON input; returns the same "
        "findings / score surface ``saip.validate`` exposes."
    ),
    inputs=(
        ActionField(
            name="path",
            label="Package path",
            kind="path",
            required=True,
            help="Absolute path to the .der/.bin/.json SAIP package.",
        ),
        ActionField(
            name="strict",
            label="Strict mode",
            kind="bool",
            required=False,
            default=False,
            help="Escalate selected WARN findings to FAIL.",
        ),
    ),
    output_kind="findings",
    dispatcher=_dispatch_lint_path,
    requires_card=False,
    streams=False,
    tags=("saip", "lint", "one-shot"),
)


COMPARE_APPLICATIONS_SPEC = ActionSpec(
    id="saip.compare_applications",
    subsystem="SAIP",
    title="Diff app surface against target package",
    description=(
        "Compare the SD / Application / ELF inventory of the open "
        "session against a target package loaded from disk. Returns "
        "added / removed / unchanged rows keyed by (pe_type, primary "
        "AID), plus a counts-by-status summary the GUI can render at "
        "the top of the report."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="target_path",
            label="Target package path",
            kind="path",
            required=True,
            help="Path to the SAIP package (DER / JSON / hex) to diff against.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_compare_applications,
    requires_card=False,
    streams=False,
    tags=("saip", "applications", "compare"),
)


PRODUCT_SUMMARY_SPEC = ActionSpec(
    id="saip.product_summary",
    subsystem="SAIP",
    title="Bench environment fingerprint",
    description=(
        "Render a fingerprint of the current YggdraSIM build (version, "
        "pySim and asn1tools versions, host Python and platform, full "
        "list of registered actions) for triage attachments. Pass "
        "output_path='' to receive the JSON projection inline in the "
        "response; supply a path to write HTML or XML to disk."
    ),
    inputs=(
        ActionField(
            name="output_path",
            label="Output path (empty for inline JSON)",
            kind="save_path",
            required=False,
            default="",
            help="Destination file. Empty string returns JSON in the response.",
        ),
        ActionField(
            name="format",
            label="Format",
            kind="string",
            required=False,
            default="html",
            help="html | xml | json (json default when output_path is empty).",
        ),
        ActionField(
            name="overwrite",
            label="Overwrite existing",
            kind="bool",
            required=False,
            default=False,
            help="When false, an existing target raises FileExistsError.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_product_summary,
    requires_card=False,
    streams=False,
    tags=("saip", "help", "export"),
)


LIST_VALIDATION_RULES_SPEC = ActionSpec(
    id="saip.list_validation_rules",
    subsystem="SAIP",
    title="Linter rulebook catalogue",
    description=(
        "Enumerate every SAIP-linter rule with id, severity, spec "
        "citation, message, and remediation hint. Lets the bench "
        "render an 'available checks' pane keyed against the same "
        "rule_id space the lint findings already carry."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_list_validation_rules,
    requires_card=False,
    streams=False,
    tags=("saip", "lint", "catalog"),
)


ADD_VARIABLE_TO_PE_SPEC = ActionSpec(
    id="saip.add_variable_to_pe",
    subsystem="SAIP",
    title="Bind PE field to variable",
    description=(
        "Swap a concrete PE field value for a [NAME] placeholder "
        "reference. The captured value is parked in "
        "__ygg_token_defs__[NAME] (with the supplied encoding hint, "
        "default hex) so the variables CSV surface can round-trip it. "
        "field_path is a dotted JSON path within the PE's decoded "
        "section, e.g. 'iccid' or 'instance.applicationInstanceAID'."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=False,
            min_value=0,
            help="Zero-based PE index. Omit when section_key is supplied.",
        ),
        ActionField(
            name="section_key",
            label="Section key",
            kind="string",
            required=False,
            default="",
            help="Decoded-document section name (e.g. 'header'). Wins over pe_index.",
        ),
        ActionField(
            name="field_path",
            label="Field path",
            kind="string",
            required=True,
            help="Dotted JSON path, e.g. 'iccid' or 'instance.applicationInstanceAID'.",
        ),
        ActionField(
            name="variable_name",
            label="Variable name",
            kind="string",
            required=True,
            help="Placeholder name (will appear in PE as [NAME]).",
        ),
        ActionField(
            name="encoding",
            label="Encoding hint",
            kind="string",
            required=False,
            default="hex",
            help="hex | utf8 | ascii — controls how the captured value is stored.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_add_variable_to_pe),
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "write"),
)


LIST_DECODED_EFS_SPEC = ActionSpec(
    id="saip.list_decoded_efs",
    subsystem="SAIP",
    title="List decoded EFs",
    description=(
        "Catalog of every EF YggdraSIM ships a structured editor for. "
        "Split into round_trip (non-lossy) and lossy_splice (record-"
        "based EFs that re-encode from the decoded form). Used by the "
        "GUI to render a capability matrix vs raw-hex fallback."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_list_interpreted_efs,
    requires_card=False,
    streams=False,
    tags=("saip", "catalog", "ef"),
)

# Back-compat alias — older clients may still call the legacy id; keep
# it routing to the same dispatcher for one release window.
LIST_INTERPRETED_EFS_SPEC = ActionSpec(
    id="saip.list_interpreted_efs",
    subsystem="SAIP",
    title="List decoded EFs (legacy id)",
    description=LIST_DECODED_EFS_SPEC.description,
    inputs=LIST_DECODED_EFS_SPEC.inputs,
    output_kind=LIST_DECODED_EFS_SPEC.output_kind,
    dispatcher=_dispatch_list_interpreted_efs,
    requires_card=False,
    streams=False,
    tags=("saip", "catalog", "ef", "deprecated"),
)


LIST_TEMPLATE_OIDS_SPEC = ActionSpec(
    id="saip.list_template_oids",
    subsystem="SAIP",
    title="List SAIP template OIDs",
    description=(
        "Catalog of every SAIP profile template OID registered in the "
        "in-tree pySim ProfileTemplateRegistry. Used by the GUI's "
        "Template OID picker on FS-bearing PEs (USIM / ISIM / CSIM / "
        "Telecom). Spec: TCA SAIP Annex A."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_list_template_oids,
    requires_card=False,
    streams=False,
    tags=("saip", "catalog", "template"),
)


PE_INFO_SPEC = ActionSpec(
    id="saip.pe_info",
    subsystem="SAIP",
    title="PE info pane",
    description=(
        "Return PE-type metadata for the contextual info pane: title, "
        "ASN.1 module name, spec citation, and a one-paragraph summary. "
        "Useful as the F1-style help dialog the manual references."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
            help="Zero-based PE index.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_pe_info,
    requires_card=False,
    streams=False,
    tags=("saip", "info", "read-only"),
)


REORDER_PES_SPEC = ActionSpec(
    id="saip.reorder_pes",
    subsystem="SAIP",
    title="Reorder PEs",
    description=(
        "Move a PE from one index to another within the sequence. "
        "Refuses moves that would displace the mandatory ProfileHeader "
        "(index 0) or PE-End (last index) anchors per TCA SAIP §A.2."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="from_index",
            label="From index",
            kind="int",
            required=True,
            min_value=0,
            help="Source PE position.",
        ),
        ActionField(
            name="to_index",
            label="To index",
            kind="int",
            required=True,
            min_value=0,
            help="Destination PE position.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_reorder_pes),
    requires_card=False,
    streams=False,
    tags=("saip", "reorder", "write"),
)


EXPORT_VARIABLES_CSV_SPEC = ActionSpec(
    id="saip.export_variables_csv",
    subsystem="SAIP",
    title="Export variables (CSV)",
    description=(
        "Export every template variable + current value to a CSV file "
        "with columns name, value, kind, defined, used_in_document. "
        "The file can be edited in a spreadsheet and re-imported via "
        "saip.import_variables_csv."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="output_path",
            label="Output CSV path",
            kind="save_path",
            required=True,
            help="Destination .csv file; parent directories are created.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_export_variables_csv,
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "export"),
)


IMPORT_VARIABLES_CSV_SPEC = ActionSpec(
    id="saip.import_variables_csv",
    subsystem="SAIP",
    title="Import variables (CSV)",
    description=(
        "Bulk-apply variable overrides from a CSV file. Each row "
        "becomes a single saip.set_variable call. Column names default "
        "to 'name' / 'value' but can be overridden so a foreign CSV "
        "(e.g. an OEM personalization sheet) can be imported without "
        "rewriting it."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="input_path",
            label="CSV path",
            kind="path",
            required=True,
            help="Source CSV file containing the variable assignments.",
        ),
        ActionField(
            name="name_column",
            label="Name column",
            kind="string",
            required=False,
            default="name",
            help="Column header carrying the variable name.",
        ),
        ActionField(
            name="value_column",
            label="Value column",
            kind="string",
            required=False,
            default="value",
            help="Column header carrying the variable value.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_import_variables_csv),
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "import", "write"),
)


COMPARE_REPORT_HTML_SPEC = ActionSpec(
    id="saip.compare_report_html",
    subsystem="SAIP",
    title="Compare to file (HTML report)",
    description=(
        "Diff the in-session profile against another package on disk "
        "and write the report as a self-contained HTML file (one "
        "table per section, colour-coded rows). Mirrors the manual's "
        "'Comparing File Systems' dialog -> Export."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="target_path",
            label="Target package path",
            kind="path",
            required=True,
            help="Path to the SAIP package (DER / JSON / hex) to diff against.",
        ),
        ActionField(
            name="output_path",
            label="Output HTML path",
            kind="save_path",
            required=True,
            help="Destination .html file; parent directories are created.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_compare_report_html,
    requires_card=False,
    streams=False,
    tags=("saip", "compare", "export"),
)


SEARCH_PE_TEXT_SPEC = ActionSpec(
    id="saip.search_pe_text",
    subsystem="SAIP",
    title="Search PEs by text",
    description=(
        "Substring or regex search over every PE's decoded JSON. "
        "Counterpart of saip.search_files for non-FS-bearing PEs "
        "(PIN, AKA, SecurityDomain, ...). Returns matching PE rows "
        "sorted by index."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="query",
            label="Search query",
            kind="string",
            required=True,
            help="Substring (default) or regex pattern.",
        ),
        ActionField(
            name="mode",
            label="Mode",
            kind="string",
            required=False,
            default="substring",
            help='"substring" (default) or "regex".',
        ),
        ActionField(
            name="case_sensitive",
            label="Case sensitive",
            kind="bool",
            required=False,
            default=False,
            help="When false, matching folds case.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_search_pe_text,
    requires_card=False,
    streams=False,
    tags=("saip", "search", "pe", "read-only"),
)


BATCH_LINT_PATHS_SPEC = ActionSpec(
    id="saip.batch_lint_paths",
    subsystem="SAIP",
    title="Batch lint packages",
    description=(
        "Lint multiple SAIP packages in one call (mirrors ``epcval -p`` "
        "and the ``LINT-BATCH`` shell verb). Accepts a comma-separated "
        "string or JSON array of paths; each entry may be a literal "
        "file path or a glob pattern. Returns one row per matched "
        "file plus an aggregate severity tally."
    ),
    inputs=(
        ActionField(
            name="paths",
            label="Package paths or globs",
            kind="string",
            required=True,
            help='e.g. "Workspace/SAIP/*.der,/srv/profiles/*.der" or a JSON array.',
        ),
        ActionField(
            name="strict",
            label="Strict mode",
            kind="bool",
            required=False,
            default=False,
            help="Escalate selected WARN findings to FAIL across all files.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_batch_lint_paths,
    requires_card=False,
    streams=False,
    tags=("saip", "lint", "batch"),
)


ADD_PE_SPEC = ActionSpec(
    id="saip.add_pe",
    subsystem="SAIP",
    title="Insert PE",
    description=(
        "Splice a new PE of the requested type into the sequence. "
        "Scaffolded payload defaults are wired up for akaParameter, "
        "pinCodes, pukCodes, genericFileManagement, securityDomain; "
        "other pySim-registered types still resolve but come up "
        "empty. The ProfileHeader (index 0) and PE-End (last index) "
        "anchors are immovable per TCA SAIP §A.2."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_type",
            label="PE type",
            kind="string",
            required=True,
            help="pySim PE type (e.g. akaParameter, pinCodes, securityDomain).",
        ),
        ActionField(
            name="insert_at",
            label="Insert at index",
            kind="int",
            required=False,
            min_value=1,
            help="Zero-based insertion point. Defaults to just before PE-End.",
        ),
        ActionField(
            name="preset",
            label="Preset",
            kind="string",
            required=False,
            default="",
            help="Optional preset id from saip.list_pe_presets.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_add_pe),
    requires_card=False,
    streams=False,
    tags=("saip", "pe", "write"),
)


LIST_PE_PRESETS_SPEC = ActionSpec(
    id="saip.list_pe_presets",
    subsystem="SAIP",
    title="List PE presets",
    description=(
        "Return standard add-PE presets. The blank row is always available; "
        "configured rows provide common setup for SD, PIN, PUK, AKA, and RFM."
    ),
    inputs=(
        ActionField(
            name="pe_type",
            label="PE type",
            kind="string",
            required=False,
            default="",
            help="Optional pySim PE type to filter presets.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_list_pe_presets,
    requires_card=False,
    streams=False,
    tags=("saip", "pe", "read-only"),
)


DELETE_PE_SPEC = ActionSpec(
    id="saip.delete_pe",
    subsystem="SAIP",
    title="Remove PE",
    description=(
        "Drop the PE at the supplied index from the sequence. The "
        "ProfileHeader (index 0) and PE-End (last index) anchors are "
        "protected per TCA SAIP §A.2 and cannot be removed."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=1,
            help="Zero-based PE index to remove.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_delete_pe),
    requires_card=False,
    streams=False,
    tags=("saip", "pe", "write"),
)


IMPORT_PE_SPEC = ActionSpec(
    id="saip.import_pe",
    subsystem="SAIP",
    title="Load PE from file",
    description=(
        "Decode a single-PE blob from disk and splice it into the "
        "sequence. Accepts .der (binary), .asn / .asn1 / .txt / .hex "
        "(ASCII hex of the same DER), and .json (transcoded single-PE "
        "snippet). The legacy XML File-Tree-Express container has no "
        "bundled converter and is rejected with a clear error."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="input_path",
            label="Source file",
            kind="path",
            required=True,
            help="Single-PE file (.der/.asn/.asn1/.txt/.hex/.json).",
        ),
        ActionField(
            name="insert_at",
            label="Insert at index",
            kind="int",
            required=False,
            min_value=1,
            help="Zero-based insertion point. Defaults to just before PE-End.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_import_pe),
    requires_card=False,
    streams=False,
    tags=("saip", "pe", "import", "write"),
)


CREATE_PACKAGE_SPEC = ActionSpec(
    id="saip.create_package",
    subsystem="SAIP",
    title="Scaffold new package",
    description=(
        "Bring up a new in-memory session containing only "
        "ProfileHeader + PE-End. Operators can extend it via "
        "saip.add_pe and persist it via saip.save_package. "
        "profile_version accepts 'M.m' (default '2.3'); iccid is "
        "even-length hex padded with the F nibble per ITU-T E.118."
    ),
    inputs=(
        ActionField(
            name="profile_version",
            label="Profile version",
            kind="string",
            required=False,
            default="2.3",
            help="TCA SAIP version, 'M.m' form (e.g. '2.3', '3.3').",
        ),
        ActionField(
            name="iccid",
            label="ICCID (hex, optional)",
            kind="string",
            required=False,
            default="",
            help="Even-length hex; defaults to the all-zero placeholder.",
        ),
        ActionField(
            name="profile_type",
            label="Profile type label (optional)",
            kind="string",
            required=False,
            default="",
            help="Free-form label written into ProfileHeader.profileType.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_create_package,
    requires_card=False,
    streams=False,
    tags=("saip", "package", "create"),
)


OPEN_PACKAGE_WITH_VARIABLES_SPEC = ActionSpec(
    id="saip.open_package_with_variables",
    subsystem="SAIP",
    title="Open package + variables sidecar",
    description=(
        "Open a SAIP package and apply a CSV variable-definitions "
        "sidecar in a single call. When variables_path is omitted, "
        "the dispatcher looks for <package_basename>.csv next to "
        "the package. Returns the same shape as saip.open_package "
        "with an extra 'variables_loaded' summary so the GUI can "
        "report which CSV (if any) was applied."
    ),
    inputs=(
        ActionField(
            name="path",
            label="Package path",
            kind="path",
            required=True,
            help="SAIP package on disk (.der / .json / .hex).",
        ),
        ActionField(
            name="variables_path",
            label="Variables CSV (optional)",
            kind="path",
            required=False,
            default="",
            help="Path to the .csv definitions file; defaults to a sibling lookup.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_open_package_with_variables,
    requires_card=False,
    streams=False,
    tags=("saip", "package", "variables", "open"),
)


LIST_TOKEN_MAPPINGS_SPEC = ActionSpec(
    id="saip.list_token_mappings",
    subsystem="SAIP",
    title="List token-list file mappings",
    description=(
        "Return every persisted package→token-list mapping. Each "
        "row carries the package key (absolute path / basename / "
        "stem), the bound token-list path, and the last-used "
        "timestamp. The store lives at "
        "<runtime>/state/saip_token_mappings.json."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_list_token_mappings,
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "tokens", "read"),
)


SET_TOKEN_MAPPING_SPEC = ActionSpec(
    id="saip.set_token_mapping",
    subsystem="SAIP",
    title="Pin token-list to package filename",
    description=(
        "Pin a token-list (CSV variable definitions) path to a "
        "package filename / basename / absolute path. "
        "saip.open_package_with_variables consults this map before "
        "the documented sibling-CSV convention."
    ),
    inputs=(
        ActionField(
            name="filename",
            label="Package key",
            kind="string",
            required=True,
            help="Absolute path, basename (profile.der), or stem (profile).",
        ),
        ActionField(
            name="tokens_path",
            label="Token-list CSV path",
            kind="path",
            required=True,
            help="Absolute path to the .csv variable-definitions file.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_token_mapping,
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "tokens", "write"),
)


REMOVE_TOKEN_MAPPING_SPEC = ActionSpec(
    id="saip.remove_token_mapping",
    subsystem="SAIP",
    title="Remove token-list mapping",
    description=(
        "Drop a persisted package→token-list mapping. No-op when "
        "the key is not in the store."
    ),
    inputs=(
        ActionField(
            name="filename",
            label="Package key",
            kind="string",
            required=True,
            help="Same key that was passed to saip.set_token_mapping.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_remove_token_mapping,
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "tokens", "write"),
)


ADD_VARIABLE_DEFINITION_SPEC = ActionSpec(
    id="saip.add_variable_definition",
    subsystem="SAIP",
    title="Register placeholder definition",
    description=(
        "Register a placeholder definition without binding it to "
        "any PE. The name lands in __ygg_token_defs__ ready for a "
        "later saip.add_variable_to_pe call (or for pickup by an "
        "external personalisation CSV). Refuses to clobber an "
        "existing entry unless overwrite=true."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="name",
            label="Variable name",
            kind="string",
            required=True,
            help="Placeholder identifier (will appear as [NAME] when bound).",
        ),
        ActionField(
            name="value",
            label="Default value",
            kind="string",
            required=False,
            default="",
            help="Default value the variables CSV / set_variable can override.",
        ),
        ActionField(
            name="encoding",
            label="Encoding hint",
            kind="string",
            required=False,
            default="hex",
            help="hex | utf8 | ascii — controls how the value is interpreted.",
        ),
        ActionField(
            name="overwrite",
            label="Overwrite existing",
            kind="bool",
            required=False,
            default=False,
            help="When false, a duplicate name raises ValueError.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_add_variable_definition),
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "write"),
)


REMOVE_VARIABLE_DEFINITION_SPEC = ActionSpec(
    id="saip.remove_variable_definition",
    subsystem="SAIP",
    title="Drop placeholder definition",
    description=(
        "Drop a placeholder definition. Refuses if the placeholder "
        "is still bound to one or more PE fields (the encode would "
        "fail on the next save) — pass force=true to drop the "
        "definition anyway."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="name",
            label="Variable name",
            kind="string",
            required=True,
            help="Placeholder identifier to remove.",
        ),
        ActionField(
            name="force",
            label="Force",
            kind="bool",
            required=False,
            default=False,
            help="Drop even if still bound to a PE field.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_remove_variable_definition),
    requires_card=False,
    streams=False,
    tags=("saip", "variables", "write"),
)


EXPORT_PE_SPEC = ActionSpec(
    id="saip.export_pe",
    subsystem="SAIP",
    title="Write PE to file",
    description=(
        "Serialise a single PE out to disk in der / hex / json. The "
        "caller picks the destination filename — the bench typically "
        "composes one as <pe_type>-<name>.<ext>. Refuses to overwrite "
        "an existing target unless overwrite=true."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
            help="Zero-based PE index to export.",
        ),
        ActionField(
            name="output_path",
            label="Output path",
            kind="save_path",
            required=True,
            help="Destination file. Format-default extension added if missing.",
        ),
        ActionField(
            name="format",
            label="Format",
            kind="string",
            required=False,
            default="der",
            help="der | hex | json",
        ),
        ActionField(
            name="overwrite",
            label="Overwrite existing",
            kind="bool",
            required=False,
            default=False,
            help="When false, an existing target raises FileExistsError.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_export_pe,
    requires_card=False,
    streams=False,
    tags=("saip", "pe", "export"),
)


BATCH_PERSONALIZE_SPEC = ActionSpec(
    id="saip.batch_personalize",
    subsystem="SAIP",
    title="Batch personalize profiles",
    description=(
        "Materialise N personalised DER profiles from one transcoded "
        "JSON template + a CSV / JSON / JSONL / YAML data file. "
        "Mirrors the eUICC Profile Creator Batch Personalization "
        "dialog and the ``GENERATE-BATCH`` shell verb. Filenames are "
        "derived from the per-record placeholder values."
    ),
    inputs=(
        ActionField(
            name="template_path",
            label="Template (.json)",
            kind="path",
            required=True,
            help="Path to a transcoded SAIP JSON template carrying placeholders.",
        ),
        ActionField(
            name="data_path",
            label="Batch data (csv / json / jsonl / yaml)",
            kind="path",
            required=True,
            help="Per-record placeholder values; column names match template placeholders.",
        ),
        ActionField(
            name="output_dir",
            label="Output directory",
            kind="path",
            required=True,
            help="Destination directory; created on demand.",
        ),
        ActionField(
            name="overwrite",
            label="Overwrite existing files",
            kind="bool",
            required=False,
            default=False,
            help="When false, existing target files are skipped (reported in 'skipped').",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_batch_personalize,
    requires_card=False,
    streams=False,
    tags=("saip", "batch", "personalize", "one-shot"),
)


DECODE_TO_JSON_SPEC = ActionSpec(
    id="saip.decode_to_json",
    subsystem="SAIP",
    title="Decode to JSON",
    description=(
        "One-shot DER → decoded JSON transcoder. Writes the tagged JSON "
        "document that the SAIP workbench / editor can round-trip."
    ),
    inputs=(
        ActionField(
            name="path",
            label="Input path",
            kind="path",
            required=True,
            help="Absolute path to the .der/.bin source file.",
        ),
        ActionField(
            name="output_path",
            label="Output path",
            kind="save_path",
            required=True,
            help="Destination .json path; parent directories are created.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_decode_to_json,
    requires_card=False,
    streams=False,
    tags=("saip", "transcode", "one-shot"),
)


get_registry().register(LINT_PATH_SPEC)
get_registry().register(BATCH_LINT_PATHS_SPEC)
get_registry().register(LIST_PE_PRESETS_SPEC)
get_registry().register(ADD_PE_SPEC)
get_registry().register(DELETE_PE_SPEC)
get_registry().register(IMPORT_PE_SPEC)
get_registry().register(EXPORT_PE_SPEC)
get_registry().register(CREATE_PACKAGE_SPEC)
get_registry().register(OPEN_PACKAGE_WITH_VARIABLES_SPEC)
get_registry().register(LIST_TOKEN_MAPPINGS_SPEC)
get_registry().register(SET_TOKEN_MAPPING_SPEC)
get_registry().register(REMOVE_TOKEN_MAPPING_SPEC)
get_registry().register(ADD_VARIABLE_DEFINITION_SPEC)
get_registry().register(REMOVE_VARIABLE_DEFINITION_SPEC)
get_registry().register(BATCH_PERSONALIZE_SPEC)
get_registry().register(COMPARE_APPLICATIONS_SPEC)
get_registry().register(PRODUCT_SUMMARY_SPEC)
get_registry().register(LIST_VALIDATION_RULES_SPEC)
get_registry().register(ADD_VARIABLE_TO_PE_SPEC)
get_registry().register(LIST_DECODED_EFS_SPEC)
get_registry().register(LIST_INTERPRETED_EFS_SPEC)  # legacy id, deprecated
get_registry().register(LIST_TEMPLATE_OIDS_SPEC)
get_registry().register(PE_INFO_SPEC)
get_registry().register(REORDER_PES_SPEC)
get_registry().register(EXPORT_VARIABLES_CSV_SPEC)
get_registry().register(IMPORT_VARIABLES_CSV_SPEC)
get_registry().register(COMPARE_REPORT_HTML_SPEC)
get_registry().register(SEARCH_PE_TEXT_SPEC)
get_registry().register(DECODE_TO_JSON_SPEC)


SAVE_TEXT_FILE_SPEC = ActionSpec(
    id="saip.save_text_file",
    subsystem="SAIP",
    title="Save text to file",
    description=(
        "Generic text-to-disk writer used by GUI helpers (Save report, "
        "export-as-text). Validates the path, creates the parent "
        "directory, and refuses to overwrite without explicit consent."
    ),
    inputs=(
        ActionField(
            name="output_path",
            label="Output path",
            kind="save_path",
            required=True,
            help="Absolute destination path; parent directories are created.",
        ),
        ActionField(
            name="text",
            label="Text body",
            kind="text",
            required=True,
            help="Body to write (UTF-8).",
        ),
        ActionField(
            name="overwrite",
            label="Overwrite existing file",
            kind="bool",
            required=False,
            default=False,
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_save_text_file,
    requires_card=False,
    streams=False,
    tags=("saip", "io", "save"),
)


SYNC_ARR_SPEC = ActionSpec(
    id="saip.sync_arr",
    subsystem="SAIP",
    title="Sync ARR / file references",
    description=(
        "Walk every PE that owns access-control file IDs and surface "
        "ARR-related inconsistencies (rule-index out of range, missing "
        "EF.ARR target, …). Read-only — automatic repair is out of "
        "scope for this release; the caller acts on the findings via "
        "the regular decoded-form editor."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="dry_run",
            label="Dry-run (report only)",
            kind="bool",
            required=False,
            default=True,
            help="Always true for now; the field is reserved for the future repair mode.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_sync_arr,
    requires_card=False,
    streams=False,
    tags=("saip", "arr", "sync"),
)


UNDO_SPEC = ActionSpec(
    id="saip.undo",
    subsystem="SAIP",
    title="Undo last edit",
    description=(
        "Pop the most recent snapshot off the per-session undo stack "
        "and restore it. Snapshots are recorded by mutating dispatchers "
        "before they touch the document, so the granularity matches a "
        "single ribbon / form action."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_undo,
    requires_card=False,
    streams=False,
    tags=("saip", "history", "undo"),
)


REDO_SPEC = ActionSpec(
    id="saip.redo",
    subsystem="SAIP",
    title="Redo last undone edit",
    description=(
        "Reapply the most recently undone snapshot. The redo stack is "
        "cleared whenever a fresh edit lands (linear history)."
    ),
    inputs=(_SESSION_FIELD,),
    output_kind="json",
    dispatcher=_dispatch_redo,
    requires_card=False,
    streams=False,
    tags=("saip", "history", "redo"),
)


get_registry().register(SAVE_TEXT_FILE_SPEC)
get_registry().register(SYNC_ARR_SPEC)
get_registry().register(UNDO_SPEC)
get_registry().register(REDO_SPEC)


# ----------------------------------------------------------------------
# Round 9 — PE-parity action specs (PIN coding, AKA mappingParameter,
# SD catalog extras, ARR record picker, GFM single-DF context,
# connectivityParameters BER-TLV breakdown, CAP/IJC import,
# SSIM-EAPTLS bundle import).
# ----------------------------------------------------------------------


PIN_ENCODE_VALUE_SPEC = ActionSpec(
    id="saip.pin_encode_value",
    subsystem="SAIP",
    title="Encode PIN/PUK value (digits ↔ hex)",
    description=(
        "Coerce a typed PIN/PUK value into its on-card byte image. "
        "TS 102 221 §9.5.1: each digit becomes its ASCII byte (0x30..0x39) "
        "right-padded with 0xFF up to ``target_byte_length`` (8 bytes for "
        "stock CHV slots, 16 for application-specific extended slots)."
    ),
    inputs=(
        ActionField(
            name="value",
            label="Typed value",
            kind="string",
            required=True,
            help="Digits (e.g. '1234') or hex bytes (e.g. '31323334FFFFFFFF').",
        ),
        ActionField(
            name="coding",
            label="Input coding",
            kind="string",
            required=True,
            help="'digits' to encode; 'hex' to validate and pass through.",
        ),
        ActionField(
            name="target_byte_length",
            label="Target byte length",
            kind="int",
            required=False,
            help="8 (default) or 16. Larger slots are rejected.",
        ),
        ActionField(
            name="pad_byte",
            label="Pad byte",
            kind="int",
            required=False,
            help="Right-pad value (default 0xFF per TS 102 221).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_pin_encode_value,
    requires_card=False,
    streams=False,
    tags=("saip", "pin", "encode", "stateless"),
)


PIN_DECODE_VALUE_SPEC = ActionSpec(
    id="saip.pin_decode_value",
    subsystem="SAIP",
    title="Decode PIN/PUK value (hex → digits)",
    description=(
        "Decode a stored PIN/PUK byte image into its typed digit prefix "
        "and report any non-conforming pad byte. The decoder accepts "
        "8-byte (CHV) and 16-byte (extended) images."
    ),
    inputs=(
        ActionField(
            name="hex_value",
            label="Stored hex image",
            kind="string",
            required=True,
            help="Hex representation of the on-card PIN/PUK octet string.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_pin_decode_value,
    requires_card=False,
    streams=False,
    tags=("saip", "pin", "decode", "stateless"),
)


AKA_MAPPING_OPTION_CATALOG_SPEC = ActionSpec(
    id="saip.aka_mapping_option_catalog",
    subsystem="SAIP",
    title="List AKA mapping-option flags",
    description=(
        "Catalog of TCA SAIP §A.2 ``MappingOptions`` bits (share-K, "
        "share-OPc, share-rotationConstants, …) that the GUI uses to "
        "render the mappingParameter checkbox group."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_aka_mapping_option_catalog,
    requires_card=False,
    streams=False,
    tags=("saip", "aka", "catalog"),
)


AKA_GET_CHOICE_SPEC = ActionSpec(
    id="saip.aka_get_choice",
    subsystem="SAIP",
    title="Get AKA algoConfiguration CHOICE state",
    description=(
        "Project a PE-AKAParameter's ``algoConfiguration`` CHOICE into "
        "``{algoParameter | mappingParameter | absent}`` plus the "
        "branch-specific fields. Read-only."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
            help="Zero-based PE index of the PE-AKAParameter section.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_aka_get_choice,
    requires_card=False,
    streams=False,
    tags=("saip", "aka", "read-only"),
)


AKA_SET_MAPPING_PARAMETER_SPEC = ActionSpec(
    id="saip.aka_set_mapping_parameter",
    subsystem="SAIP",
    title="Switch AKA to mappingParameter CHOICE",
    description=(
        "Replace ``algoConfiguration`` with the ``mappingParameter`` "
        "branch — reuse another NAA's authentication configuration via "
        "its instance AID and a one-byte mapping-options bitmask. The "
        "previous algoParameter payload is stashed so flipping back "
        "via ``saip.aka_set_algo_parameter`` restores it."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
        ),
        ActionField(
            name="mapping_source_aid",
            label="Source NAA AID (hex)",
            kind="string",
            required=True,
            help="5..16-byte ISO 7816-4 AID of the NAA whose AKA is reused.",
        ),
        ActionField(
            name="mapping_options_hex",
            label="Mapping options (hex)",
            kind="string",
            required=False,
            help="One byte. Mutually exclusive with mapping_options_flags.",
        ),
        ActionField(
            name="mapping_options_flags",
            label="Mapping option flags",
            kind="json",
            required=False,
            help='JSON array of flag names, e.g. ["share-K", "share-OPc"].',
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_aka_set_mapping_parameter),
    requires_card=False,
    streams=False,
    tags=("saip", "aka", "mapping-parameter", "edit"),
)


AKA_SET_ALGO_PARAMETER_SPEC = ActionSpec(
    id="saip.aka_set_algo_parameter",
    subsystem="SAIP",
    title="Switch AKA to algoParameter CHOICE",
    description=(
        "Replace ``algoConfiguration`` with the ``algoParameter`` "
        "branch. When a stash is present (set by a prior "
        "mappingParameter toggle) it is restored verbatim; otherwise "
        "an empty payload with the supplied algorithm_id is emitted."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(
            name="pe_index",
            label="PE index",
            kind="int",
            required=True,
            min_value=0,
        ),
        ActionField(
            name="algorithm_id",
            label="Algorithm id",
            kind="int",
            required=False,
            help="Optional MILENAGE / TUAK / Test algorithm-id integer.",
        ),
        ActionField(
            name="restore_stash",
            label="Restore stashed algoParameter payload",
            kind="bool",
            required=False,
            help="Default true — restores the previous algoParameter payload.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_aka_set_algo_parameter),
    requires_card=False,
    streams=False,
    tags=("saip", "aka", "algo-parameter", "edit"),
)


LIST_SD_CATALOG_EXTENDED_SPEC = ActionSpec(
    id="saip.list_sd_catalog_extended",
    subsystem="SAIP",
    title="List extended SecurityDomain catalogs",
    description=(
        "Static catalog of Access Domain (TS 102 226 §8.2.1.3), MSL "
        "(TS 102 225 §5.1.2), Application Family Identifier (GP Amd C "
        "§6.1.5.1), Key Usage / Access / Component Type (GP CS Tables "
        "11-17 / 11-19 / §11.1.8), and OPEN RestrictParameter (GP CS "
        "§11.5.4). Used by the GUI dropdowns."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_list_sd_catalog_extended,
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "catalog"),
)


SD_DECODE_FIELD_SPEC = ActionSpec(
    id="saip.sd_decode_field",
    subsystem="SAIP",
    title="Decode SD install-parameter field",
    description=(
        "Decode one of the named selectors: access_domain / afi / "
        "key_access / key_component_type / key_usage / key_version / "
        "msl / restrict. Stateless."
    ),
    inputs=(
        ActionField(name="field", label="Field", kind="string", required=True),
        ActionField(name="hex_value", label="Hex value", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_sd_decode_field,
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "decode", "stateless"),
)


SD_ENCODE_FIELD_SPEC = ActionSpec(
    id="saip.sd_encode_field",
    subsystem="SAIP",
    title="Encode SD install-parameter field",
    description=(
        "Encode one of the named selectors. Use ``name_or_hex`` for "
        "byte selectors (access_domain, afi, key_access, "
        "key_component_type), ``flags`` for bitmask selectors "
        "(key_usage, restrict), or ``msl_kwargs`` for the MSL builder."
    ),
    inputs=(
        ActionField(name="field", label="Field", kind="string", required=True),
        ActionField(name="name_or_hex", label="Name or hex", kind="string", required=False),
        ActionField(name="flags", label="Flags", kind="json", required=False),
        ActionField(name="msl_kwargs", label="MSL kwargs", kind="json", required=False),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_sd_encode_field),
    requires_card=False,
    streams=False,
    tags=("saip", "security-domain", "encode", "stateless"),
)


ARR_ENCODE_REFERENCE_SPEC = ActionSpec(
    id="saip.arr_encode_reference",
    subsystem="SAIP",
    title="Encode ARR reference (FID + record)",
    description=(
        "Build a 3-byte ``securityAttributesReferenced`` value (TS 102 "
        "221 §9.4 long form) from an EF.ARR FID and a 1..254 record index."
    ),
    inputs=(
        ActionField(name="file_id", label="EF.ARR FID", kind="string", required=True),
        ActionField(name="record_index", label="Record index", kind="int", required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_arr_encode_reference,
    requires_card=False,
    streams=False,
    tags=("saip", "arr", "encode", "stateless"),
)


ARR_DECODE_REFERENCE_SPEC = ActionSpec(
    id="saip.arr_decode_reference",
    subsystem="SAIP",
    title="Decode ARR reference",
    description=(
        "Decode a 1- or 3-byte ``securityAttributesReferenced`` value. "
        "Short form (1 byte) carries SFI in upper 5 bits + record number "
        "in lower 3; long form (3 bytes) carries the full FID."
    ),
    inputs=(
        ActionField(name="hex_value", label="Reference hex", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_arr_decode_reference,
    requires_card=False,
    streams=False,
    tags=("saip", "arr", "decode", "stateless"),
)


ARR_LIST_RECORDS_SPEC = ActionSpec(
    id="saip.arr_list_records",
    subsystem="SAIP",
    title="List EF.ARR records (rule picker)",
    description=(
        "Project the records of an EF.ARR file as it sits in the "
        "decoded document. Output rows carry the rule summary, the "
        "rule list, and the raw bytes so the FCP editor can render "
        "the rule-picker dropdown."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="section_key", label="Section key", kind="string", required=True),
        ActionField(name="file_path", label="EF.ARR path", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_arr_list_records,
    requires_card=False,
    streams=False,
    tags=("saip", "arr", "read-only"),
)


GFM_GET_DF_CONTEXT_SPEC = ActionSpec(
    id="saip.gfm_get_df_context",
    subsystem="SAIP",
    title="Get GFM single-DF context",
    description=(
        "Read the DF context configured on a PE-GenericFileManagement. "
        "YggdraSIM models one GFM PE = one DF context; the response "
        "carries the leading ``filePath`` value plus the ordered list "
        "of files appended under it."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="pe_index", label="PE index", kind="int", required=True, min_value=0),
    ),
    output_kind="json",
    dispatcher=_dispatch_gfm_get_df_context,
    requires_card=False,
    streams=False,
    tags=("saip", "gfm", "read-only"),
)


GFM_SET_DF_CONTEXT_SPEC = ActionSpec(
    id="saip.gfm_set_df_context",
    subsystem="SAIP",
    title="Set GFM single-DF context",
    description=(
        "Set / replace the DF context on a GFM PE. Existing file "
        "operations are reattached under the new path; divergent "
        "``filePath`` entries from the original layout are dropped "
        "(count surfaced in the response so the GUI can warn). For "
        "nested DFs, create one PE-GFM per DF context."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="pe_index", label="PE index", kind="int", required=True, min_value=0),
        ActionField(
            name="df_path",
            label="DF path (hex)",
            kind="string",
            required=False,
            help="Concatenated 16-bit FIDs (e.g. '7F10' or ''). Leading 3F00 stripped.",
        ),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_gfm_set_df_context),
    requires_card=False,
    streams=False,
    tags=("saip", "gfm", "edit"),
)


GFM_REORDER_FILES_SPEC = ActionSpec(
    id="saip.gfm_reorder_files",
    subsystem="SAIP",
    title="Reorder files inside a GFM PE",
    description=(
        "Move one file inside the canonical single-transaction GFM "
        "layout. Indices are 0-based against the file list returned by "
        "``saip.gfm_get_df_context``."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="pe_index", label="PE index", kind="int", required=True, min_value=0),
        ActionField(name="from_index", label="From index", kind="int", required=True, min_value=0),
        ActionField(name="to_index", label="To index", kind="int", required=True, min_value=0),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_gfm_reorder_files),
    requires_card=False,
    streams=False,
    tags=("saip", "gfm", "reorder", "edit"),
)


GFM_REMOVE_FILE_SPEC = ActionSpec(
    id="saip.gfm_remove_file",
    subsystem="SAIP",
    title="Remove a file from a GFM PE",
    description=(
        "Delete the create/update/delete operation at the supplied "
        "0-based position inside the canonical GFM transaction. Used "
        "by the file-system tab to retract entries without flushing "
        "the entire PE."
    ),
    inputs=(
        _SESSION_FIELD,
        ActionField(name="pe_index", label="PE index", kind="int", required=True, min_value=0),
        ActionField(name="position", label="Position", kind="int", required=True, min_value=0),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_gfm_remove_file),
    requires_card=False,
    streams=False,
    tags=("saip", "gfm", "remove", "edit"),
)


CONNECTIVITY_DECODE_SPEC = ActionSpec(
    id="saip.connectivity_decode",
    subsystem="SAIP",
    title="Decode connectivityParameters bearers",
    description=(
        "Walk the ProfileHeader ``connectivityParameters`` octet "
        "string and split it into typed SMS-PP / CAT_TP / HTTPS "
        "bearer dicts (ETSI TS 102 225 §5.1, TS 102 124, TS 102 226 "
        "§5.7). Unknown bearer tags round-trip as opaque blobs."
    ),
    inputs=(
        ActionField(name="hex_value", label="Bearer hex", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_connectivity_decode,
    requires_card=False,
    streams=False,
    tags=("saip", "connectivity", "decode", "stateless"),
)


CONNECTIVITY_ENCODE_SPEC = ActionSpec(
    id="saip.connectivity_encode",
    subsystem="SAIP",
    title="Encode connectivityParameters bearers",
    description=(
        "Inverse of ``saip.connectivity_decode`` — build the "
        "ProfileHeader bearer blob from a list of typed bearer dicts."
    ),
    inputs=(
        ActionField(name="bearers", label="Bearer list", kind="json", required=True),
    ),
    output_kind="json",
    dispatcher=_with_history(_dispatch_connectivity_encode),
    requires_card=False,
    streams=False,
    tags=("saip", "connectivity", "encode", "stateless"),
)


CONNECTIVITY_BEARER_CATALOG_SPEC = ActionSpec(
    id="saip.connectivity_bearer_catalog",
    subsystem="SAIP",
    title="List supported bearer types",
    description=(
        "Static catalog of the SMS-PP / CAT_TP / HTTPS bearer tags "
        "decoded by ``saip.connectivity_decode``."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_connectivity_bearer_catalog,
    requires_card=False,
    streams=False,
    tags=("saip", "connectivity", "catalog"),
)


CAP_INSPECT_SPEC = ActionSpec(
    id="saip.cap_inspect",
    subsystem="SAIP",
    title="Inspect CAP / IJC payload",
    description=(
        "Walk a Java Card CAP-as-JAR archive or flat IJC byte stream "
        "(JCVM §6) and extract the package AID, every applet AID, and "
        "every imported package AID. Either ``payload_hex`` or "
        "``payload_path`` must be supplied."
    ),
    inputs=(
        ActionField(
            name="payload_hex",
            label="CAP/IJC bytes (hex)",
            kind="string",
            required=False,
            help="Hex-encoded CAP archive or flat IJC stream.",
        ),
        ActionField(
            name="payload_path",
            label="CAP/IJC file path",
            kind="string",
            required=False,
            help="Optional on-disk path to a .cap or .ijc file.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_cap_inspect,
    requires_card=False,
    streams=False,
    tags=("saip", "cap-import", "stateless"),
)


SSIM_EAPTLS_INSPECT_SPEC = ActionSpec(
    id="saip.ssim_eaptls_inspect",
    subsystem="SAIP",
    title="Inspect SSIM-EAPTLS PEM / DER",
    description=(
        "Identify a single PEM-armoured or DER-encoded blob and "
        "report its kind (certificate / private_key / …) plus "
        "metadata extracted via ``cryptography`` when available "
        "(subject, issuer, public-key DER, fingerprints)."
    ),
    inputs=(
        ActionField(
            name="pem_or_der",
            label="PEM text or DER hex",
            kind="string",
            required=True,
            help="PEM block (with -----BEGIN-----) or hex-encoded DER bytes.",
        ),
        ActionField(
            name="role",
            label="Intended role",
            kind="string",
            required=False,
            help="auto (default) / device_certificate / private_key / ca.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_ssim_eaptls_inspect,
    requires_card=False,
    streams=False,
    tags=("saip", "ssim-eaptls", "stateless"),
)


SSIM_EAPTLS_MATCH_PAIR_SPEC = ActionSpec(
    id="saip.ssim_eaptls_match_pair",
    subsystem="SAIP",
    title="Verify SSIM-EAPTLS cert / key pair",
    description=(
        "Compare the public key inside a certificate against a "
        "supplied private key (SHA-256 of the SubjectPublicKeyInfo). "
        "Returns ``match: null`` when the ``cryptography`` library is "
        "unavailable so the operator can still import the bundle "
        "with the integrity assertion deferred."
    ),
    inputs=(
        ActionField(name="certificate", label="Certificate", kind="string", required=True),
        ActionField(name="private_key", label="Private key", kind="string", required=True),
    ),
    output_kind="json",
    dispatcher=_dispatch_ssim_eaptls_match_pair,
    requires_card=False,
    streams=False,
    tags=("saip", "ssim-eaptls", "stateless"),
)


for _spec in (
    PIN_ENCODE_VALUE_SPEC,
    PIN_DECODE_VALUE_SPEC,
    AKA_MAPPING_OPTION_CATALOG_SPEC,
    AKA_GET_CHOICE_SPEC,
    AKA_SET_MAPPING_PARAMETER_SPEC,
    AKA_SET_ALGO_PARAMETER_SPEC,
    LIST_SD_CATALOG_EXTENDED_SPEC,
    SD_DECODE_FIELD_SPEC,
    SD_ENCODE_FIELD_SPEC,
    ARR_ENCODE_REFERENCE_SPEC,
    ARR_DECODE_REFERENCE_SPEC,
    ARR_LIST_RECORDS_SPEC,
    GFM_GET_DF_CONTEXT_SPEC,
    GFM_SET_DF_CONTEXT_SPEC,
    GFM_REORDER_FILES_SPEC,
    GFM_REMOVE_FILE_SPEC,
    CONNECTIVITY_DECODE_SPEC,
    CONNECTIVITY_ENCODE_SPEC,
    CONNECTIVITY_BEARER_CATALOG_SPEC,
    CAP_INSPECT_SPEC,
    SSIM_EAPTLS_INSPECT_SPEC,
    SSIM_EAPTLS_MATCH_PAIR_SPEC,
):
    get_registry().register(_spec)
