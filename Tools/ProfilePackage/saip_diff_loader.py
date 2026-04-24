"""
Unified profile-document loader for the SAIP diff engine.

``saip_diff_engine.diff_saip_documents`` consumes jsonified document
dicts. In practice the operator will point it at either:

* a ``*.json`` transcode sidecar (native input to the transcode TUI),
  which needs no external dependencies,
* a ``*.der`` / ``*.pp`` / ``*.upp`` raw SAIP profile package, which
  can only be decoded via ``pySim.esim.saip.ProfileElementSequence``,
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


def _load_der_profile(path: Path, workspace_root: Path) -> LoadedDocument:
    try:
        ensure_workspace_pysim_on_path(workspace_root)
        from pySim.esim.saip import ProfileElementSequence  # type: ignore[import]
    except ImportError as exc:
        raise SaipDiffLoadError(
            f"{path}: DER diff needs pySim. Install the PyPI wheel "
            "(pip install pySim) or clone the upstream tree "
            "(git clone https://gitlab.com/osmocom/pysim.git pysim) "
            f"into {workspace_root}. Underlying error: {exc}"
        ) from exc
    try:
        der_bytes = path.read_bytes()
    except OSError as exc:
        raise SaipDiffLoadError(f"{path}: cannot read DER bytes: {exc}") from exc
    try:
        pes = ProfileElementSequence.from_der(der_bytes)
        raw_document = build_decoded_document_from_sequence(pes)
        document = jsonify_document(raw_document)
    except Exception as exc:
        raise SaipDiffLoadError(
            f"{path}: DER decode failed: {exc.__class__.__name__}: {exc}"
        ) from exc
    return LoadedDocument(source_path=path, shape="saip-der", document=document)


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
