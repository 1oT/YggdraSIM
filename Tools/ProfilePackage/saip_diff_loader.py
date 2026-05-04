"""
Unified profile-document loader for the SAIP diff engine.

``saip_diff_engine.diff_saip_documents`` consumes jsonified document
dicts. In practice the operator will point it at either:

* a ``*.json`` transcode sidecar (native input to the transcode TUI),
  which needs no external dependencies,
* a ``*.der`` / ``*.pp`` / ``*.upp`` raw SAIP profile package, which
  can only be decoded via ``pySim.esim.saip.ProfileElementSequence``,
* a ``*.txt`` / ``*.hex`` ASCII hex-dump of a DER package -- the same
  shape ``OPEN`` / ``USE`` accept via
  :meth:`Tools.ProfilePackage.saip_tool.SaipToolBridge._prepare_input_for_tool`.
  Whitespace and case are normalised before the bytes are handed to
  the DER decoder.
* a simulated-card profile manifest
  (``Workspace/.../<profile-dir>/profile_image.json``) emitted by
  ``SIMCARD.profile_store``. The manifest has a different top-level
  shape, so we normalise it into the transcode-tui document form
  before returning it to the diff engine.

The loader is designed to fail soft: if pySim is absent the DER path
raises :class:`SaipDiffLoadError` with a clear recovery hint, and the
JSON path always works. Downstream callers should catch the exception
and render it to the user.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from Tools.ProfilePackage.saip_json_codec import (
    build_decoded_document_from_sequence,
    jsonify_document,
    dejsonify_document,
    ensure_workspace_pysim_on_path,
)


class SaipDiffLoadError(RuntimeError):
    """Raised when the loader cannot turn a file into a diffable doc."""


@dataclass(frozen=True)
class LoadedDocument:
    """A normalised document ready for the diff engine.

    ``source_path`` is kept for renderer use (e.g. "diff A=<file> vs
    B=<file>" banners). ``shape`` reports which on-disk form the loader
    recognised so the caller can short-circuit further conversions.
    """

    source_path: Path
    shape: str
    document: dict[str, Any]


_TRANSCODE_JSON_MARKERS = ("intro", "sections")
_SIMULATOR_MANIFEST_MARKERS = ("profile_name", "iccid", "nodes")

# Suffixes the SAIP shell already treats as ASCII hex-text via
# ``SaipToolBridge._prepare_input_for_tool``. Mirroring the same set
# here keeps the diff command in lock-step with OPEN / USE so an
# operator can compare the exact files the inspector accepts.
_HEX_INPUT_SUFFIXES = {".hex", ".txt"}

_HEX_ALPHABET = frozenset("0123456789ABCDEFabcdef")
_HEX_WHITESPACE = frozenset(" \t\r\n\v\f")
_HEX_SNIFF_HEAD_LIMIT = 4096
_HEX_SNIFF_MIN_LENGTH = 8


def _looks_like_transcode_json(payload: dict[str, Any]) -> bool:
    if isinstance(payload, dict) is False:
        return False
    for marker in _TRANSCODE_JSON_MARKERS:
        if marker in payload:
            return True
    return False


def _looks_like_simulator_manifest(payload: dict[str, Any]) -> bool:
    if isinstance(payload, dict) is False:
        return False
    for marker in _SIMULATOR_MANIFEST_MARKERS:
        if marker in payload:
            return True
    return False


def _looks_like_ascii_hex(text: str) -> bool:
    """Heuristic: does *text* look like a hex-dump of a DER profile?

    The check is intentionally cheap -- we only inspect the first
    ``_HEX_SNIFF_HEAD_LIMIT`` characters, accept whitespace as a free
    separator (so multi-line ``xxd`` / ``hexdump -C``-style input is
    fine once column markers are stripped) and demand at least one
    actual hex digit. Files shorter than ``_HEX_SNIFF_MIN_LENGTH``
    characters fall through to the existing JSON / DER branches so we
    don't grab tiny one-line scratch files.
    """
    if len(text) < _HEX_SNIFF_MIN_LENGTH:
        return False
    seen_hex_digit = False
    for character in text[:_HEX_SNIFF_HEAD_LIMIT]:
        if character in _HEX_ALPHABET:
            seen_hex_digit = True
            continue
        if character in _HEX_WHITESPACE:
            continue
        return False
    return seen_hex_digit


def _decode_hex_text_payload(text: str, *, source: Path) -> bytes:
    """Convert a hex-dump string to its underlying DER bytes.

    Validation mirrors
    :meth:`Tools.ProfilePackage.saip_tool.SaipToolBridge._prepare_input_for_tool`
    so the diagnostic the diff command emits matches what the operator
    will see if they later try to OPEN the same file.
    """
    normalized_hex = "".join(text.split()).upper()
    if len(normalized_hex) == 0:
        raise SaipDiffLoadError(f"{source}: hex-text profile is empty")
    for character in normalized_hex:
        if character not in "0123456789ABCDEF":
            raise SaipDiffLoadError(
                f"{source}: hex-text profile contains non-hex characters"
            )
    if len(normalized_hex) % 2 != 0:
        raise SaipDiffLoadError(
            f"{source}: hex-text profile has odd-length payload "
            f"({len(normalized_hex)} characters after whitespace strip)"
        )
    return bytes.fromhex(normalized_hex)


def _normalise_simulator_manifest(payload: dict[str, Any], *, source: Path) -> dict[str, Any]:
    """Recast a SIMCARD ``SimProfileImage`` manifest as a transcode document.

    The simulator emits manifests via ``SIMCARD.profile_store``. We wrap
    the content in the ``{"intro": [...], "sections": {...}}`` skeleton
    the diff engine expects. This keeps the diff paths self-descriptive
    even when comparing a live sim-card profile against a vendor DER.
    """
    intro_lines: list[str] = []
    name = str(payload.get("profile_name") or "").strip()
    iccid = str(payload.get("iccid") or "").strip()
    imsi = str(payload.get("imsi") or "").strip()
    if len(name) > 0:
        intro_lines.append(f"SIMCARD profile {name}")
    else:
        intro_lines.append("SIMCARD profile")
    if len(iccid) > 0:
        intro_lines.append(f"ICCID={iccid}")
    if len(imsi) > 0:
        intro_lines.append(f"IMSI={imsi}")
    intro_lines.append(f"source={source.name}")

    sections: dict[str, Any] = {
        "profileHeader": {
            "profile_name": name,
            "iccid": iccid,
            "imsi": imsi,
            "impi": str(payload.get("impi") or ""),
        },
        "nodes": payload.get("nodes", []),
    }
    if "auth_config" in payload:
        sections["auth_config"] = payload["auth_config"]
    return {"intro": intro_lines, "sections": sections}


def _load_transcode_json(path: Path, payload: dict[str, Any]) -> LoadedDocument:
    # The transcode JSON is already jsonified. Round-trip it through
    # dejsonify/jsonify so token placeholders resolve deterministically
    # and we get the same shape as a freshly decoded DER would.
    try:
        raw_document = dejsonify_document(payload)
        document = jsonify_document(raw_document)
    except Exception as exc:
        raise SaipDiffLoadError(
            f"{path}: transcode JSON could not be re-canonicalised: {exc}"
        ) from exc
    return LoadedDocument(source_path=path, shape="transcode-json", document=document)


def _load_simulator_manifest(path: Path, payload: dict[str, Any]) -> LoadedDocument:
    document = _normalise_simulator_manifest(payload, source=path)
    return LoadedDocument(source_path=path, shape="simcard-manifest", document=document)


def _decode_der_bytes(
    path: Path,
    der_bytes: bytes,
    workspace_root: Path,
    *,
    shape: str = "saip-der",
) -> LoadedDocument:
    """Decode *der_bytes* via pySim and return a normalised document.

    The path is only used for error wording / ``LoadedDocument.source_path``.
    Splitting this out from :func:`_load_der_profile` lets the hex-text
    branch reuse the same pipeline without re-reading the file or
    duplicating the pySim import dance.
    """
    try:
        ensure_workspace_pysim_on_path(workspace_root)
        from pySim.esim.saip import ProfileElementSequence  # type: ignore[import]
    except (ImportError, RuntimeError) as exc:
        # ``ensure_workspace_pysim_on_path`` raises RuntimeError when
        # the workspace tree exists but pySim still isn't importable;
        # catching both keeps the loader's failure mode predictable
        # whether the environment ships pySim via pip or via a source
        # checkout.
        raise SaipDiffLoadError(
            f"{path}: DER diff needs pySim. Install the PyPI wheel "
            "(pip install pySim) or clone the upstream tree "
            "(git clone https://gitlab.com/osmocom/pysim.git pysim) "
            f"into {workspace_root}. Underlying error: {exc}"
        ) from exc
    try:
        pes = ProfileElementSequence.from_der(der_bytes)
        raw_document = build_decoded_document_from_sequence(pes)
        document = jsonify_document(raw_document)
    except Exception as exc:
        raise SaipDiffLoadError(
            f"{path}: DER decode failed: {exc.__class__.__name__}: {exc}"
        ) from exc
    return LoadedDocument(source_path=path, shape=shape, document=document)


def _load_der_profile(path: Path, workspace_root: Path) -> LoadedDocument:
    try:
        der_bytes = path.read_bytes()
    except OSError as exc:
        raise SaipDiffLoadError(f"{path}: cannot read DER bytes: {exc}") from exc
    return _decode_der_bytes(path, der_bytes, workspace_root, shape="saip-der")


def _load_hex_text_profile(
    path: Path,
    raw_text: str,
    workspace_root: Path,
) -> LoadedDocument:
    """Translate a hex-text profile into a DER-decoded document."""
    decoded_bytes = _decode_hex_text_payload(raw_text, source=path)
    return _decode_der_bytes(path, decoded_bytes, workspace_root, shape="saip-hex")


def load_profile_document(path: Path, *, workspace_root: Path) -> LoadedDocument:
    """Resolve a filesystem path to a diff-ready document.

    The caller should supply an absolute, user-expanded path. The
    loader sniffs the on-disk content rather than trusting the
    extension, so a mis-named file still lands in the right branch if
    its bytes make sense.
    """
    if path.is_file() is False:
        raise SaipDiffLoadError(f"{path}: file not found")

    raw_text: str | None = None
    parse_error: Exception | None = None
    try:
        raw_text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raw_text = None
    except OSError as exc:
        raise SaipDiffLoadError(f"{path}: cannot read file: {exc}") from exc

    if raw_text is not None:
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            parse_error = exc
            payload = None
        else:
            if _looks_like_simulator_manifest(payload):
                return _load_simulator_manifest(path, payload)
            if _looks_like_transcode_json(payload):
                return _load_transcode_json(path, payload)
            parse_error = ValueError(
                "JSON does not match transcode or simulator-manifest shape"
            )

        # Hex-text fallback. ``.txt`` / ``.hex`` profiles are ASCII
        # hex dumps of a DER package -- the same shape OPEN / USE
        # accept. We honour the explicit suffix unconditionally and
        # fall back to a content sniff for extension-less inputs so a
        # mis-named file still lands in the right branch. Any failure
        # here is a hex-specific error, not a "not transcode JSON"
        # message, so the operator gets a usable diagnostic.
        suffix = path.suffix.lower()
        suffix_indicates_hex = suffix in _HEX_INPUT_SUFFIXES
        content_indicates_hex = (
            suffix_indicates_hex is False
            and len(suffix) == 0
            and _looks_like_ascii_hex(raw_text)
        )
        if suffix_indicates_hex is True or content_indicates_hex is True:
            return _load_hex_text_profile(path, raw_text, workspace_root)

    # Fall through to DER decode for binary inputs or JSON-that-is-not-a-profile
    try:
        return _load_der_profile(path, workspace_root)
    except SaipDiffLoadError as der_error:
        if parse_error is None:
            raise
        raise SaipDiffLoadError(
            f"{path}: not recognised as transcode JSON "
            f"({parse_error}) and DER decode failed ({der_error})"
        ) from der_error


def load_two_profile_documents(
    path_a: Path,
    path_b: Path,
    *,
    workspace_root: Path,
) -> tuple[LoadedDocument, LoadedDocument]:
    """Convenience wrapper used by both the DIFF shell command and the TUI."""
    document_a = load_profile_document(path_a, workspace_root=workspace_root)
    document_b = load_profile_document(path_b, workspace_root=workspace_root)
    return document_a, document_b
