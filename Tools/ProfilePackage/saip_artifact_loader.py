# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Stable, evidence-oriented loader for SAIP profile artifacts.

The SAIP workbench already has mature handling for binary DER, ASCII-hex
profiles, ``.varder`` templates, ASN.1 value notation, and tagged JSON.  This
module is the public boundary for consumers that need the same behavior
without depending on the GUI's historical dictionary contract.

``load_saip_artifact`` returns a typed result that keeps the exact input bytes
and their SHA-256 digest alongside the decoded ProfileElement sequence.  It
also makes tolerant recovery explicit: if strict DER decoding failed and one
or more PEs were recovered or skipped, ``strict_complete`` is false.  A
validation caller must therefore never treat a partially recovered artifact
as a complete strict decode merely because some PEs are available.

The legacy GUI parser remains the single implementation while it is migrated
out of the action module.  The import is intentionally lazy, avoiding GUI
registration and pySim setup until an artifact is actually loaded.  The GUI
itself delegates back through this public boundary, so there is one parser
behavior rather than a second validation-specific implementation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class SaipArtifactWarning:
    """One diagnostic emitted while recovering an artifact.

    ``details`` retains every field from the parser's diagnostic mapping so
    evidence/reporting code can preserve offsets and segment bytes without
    coupling itself to fields added in a future parser version.
    """

    stage: str
    message: str
    pe_index: int | None = None
    byte_offset: int | None = None
    segment_length: int | None = None
    segment_head_hex: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SaipArtifactWarning":
        """Build a typed diagnostic from the legacy parser mapping."""

        details = dict(value)
        return cls(
            stage=str(details.get("stage") or "load"),
            message=str(details.get("error") or details.get("message") or ""),
            pe_index=_optional_int(details.get("index")),
            byte_offset=_optional_int(details.get("offset")),
            segment_length=_optional_int(details.get("segment_len", details.get("remaining"))),
            segment_head_hex=_optional_text(details.get("head_hex")),
            details=details,
        )

    def to_mapping(self) -> dict[str, Any]:
        """Return the lossless legacy diagnostic representation."""

        return dict(self.details)


@dataclass(frozen=True)
class SaipPlaceholderEvidence:
    """Evidence that an unresolved or typed placeholder exists in the input."""

    kind: str
    index: int | None = None
    literal: str | None = None
    variable_name: str | None = None
    type_name: str | None = None
    byte_length: int | None = None
    modifier: str | None = None
    document_path: str | None = None
    undefined: bool = False

    def to_mapping(self) -> dict[str, Any]:
        """Return a JSON-safe representation for validation evidence."""

        return {
            "kind": self.kind,
            "index": self.index,
            "literal": self.literal,
            "variable_name": self.variable_name,
            "type_name": self.type_name,
            "byte_length": self.byte_length,
            "modifier": self.modifier,
            "document_path": self.document_path,
            "undefined": self.undefined,
        }


@dataclass(frozen=True)
class SaipArtifactLoadResult:
    """A decoded SAIP artifact plus provenance and completeness evidence."""

    source_path: Path
    raw_input_bytes: bytes = field(repr=False)
    raw_input_sha256: str
    encoding: str
    source_format: str
    decoded_document: dict[str, Any] = field(repr=False)
    pes: Any = field(repr=False)
    placeholder_evidence: tuple[SaipPlaceholderEvidence, ...] = ()
    warnings: tuple[SaipArtifactWarning, ...] = ()
    strict_complete: bool = False
    strict_failure: str | None = None
    inline_placeholder_records: tuple[Any, ...] = field(
        default=(),
        repr=False,
        compare=False,
    )

    @property
    def pe_count(self) -> int:
        """Return the number of decoded ProfileElements."""

        pe_list = getattr(self.pes, "pe_list", None)
        if pe_list is not None:
            return len(pe_list)
        try:
            return len(self.pes)
        except (TypeError, AttributeError):
            return 0

    @property
    def is_template(self) -> bool:
        """Return whether unresolved placeholder evidence was observed."""

        return len(self.placeholder_evidence) > 0

    @property
    def is_strictly_complete(self) -> bool:
        """Readable alias for callers building validation gates."""

        return self.strict_complete

    def to_legacy_mapping(self) -> dict[str, Any]:
        """Project the result to the historical GUI loader dictionary."""

        return {
            "pes": self.pes,
            "decoded_document": self.decoded_document,
            "encoding": self.encoding,
            "warnings": [warning.to_mapping() for warning in self.warnings],
            "inline_placeholder_records": list(self.inline_placeholder_records),
            "placeholder_paths": [
                item.document_path
                for item in self.placeholder_evidence
                if item.kind == "json-placeholder-path" and item.document_path is not None
            ],
            "undefined_tokens": [
                item.variable_name
                for item in self.placeholder_evidence
                if item.kind == "undefined-token" and item.variable_name is not None
            ],
            "strict_complete": self.strict_complete,
            "strict_failure": self.strict_failure,
            "raw_input_sha256": self.raw_input_sha256,
        }


def load_saip_artifact(path: str | Path) -> SaipArtifactLoadResult:
    """Load a DER, ASN.1, tagged-JSON, hex, or ``.varder`` SAIP artifact.

    File recognition, pySim compatibility behavior, strict decoding, and
    tolerant recovery are shared with ``saip.open_package``.  Exceptions from
    that parser are deliberately preserved so existing operator guidance
    remains identical in the GUI and validation plug-ins.
    """

    source_path = Path(path).expanduser().resolve()

    # Lazy import avoids importing the GUI action catalogue for callers that
    # only inspect the result types.  `_load_package_payload_impl` is the
    # current single parser implementation; the action's compatibility helper
    # delegates back through this function.
    from yggdrasim_common.gui_server.actions.saip import (
        _load_package_payload_impl,
    )

    payload = _load_package_payload_impl(source_path)
    raw_input = payload.get("raw_input_bytes")
    if not isinstance(raw_input, (bytes, bytearray)):
        # Compatibility fallback for an older in-process action module.  The
        # current implementation always supplies the bytes it actually parsed.
        raw_input = source_path.read_bytes()
    raw_input_bytes = bytes(raw_input)

    warning_values = payload.get("warnings") or []
    warnings = tuple(
        SaipArtifactWarning.from_mapping(value)
        for value in warning_values
        if isinstance(value, Mapping)
    )

    inline_records = tuple(payload.get("inline_placeholder_records") or ())
    evidence: list[SaipPlaceholderEvidence] = [
        _inline_placeholder_evidence(record) for record in inline_records
    ]
    evidence.extend(
        SaipPlaceholderEvidence(
            kind="json-placeholder-path",
            document_path=str(document_path),
        )
        for document_path in payload.get("placeholder_paths") or ()
    )
    evidence.extend(
        SaipPlaceholderEvidence(
            kind="undefined-token",
            variable_name=str(variable_name),
            undefined=True,
        )
        for variable_name in payload.get("undefined_tokens") or ()
    )

    decoded_document = payload.get("decoded_document")
    if not isinstance(decoded_document, dict):
        raise TypeError("SAIP artifact loader returned no decoded document mapping.")

    # Missing completeness metadata is conservative, never optimistic.  Any
    # tolerant warning also forces incompleteness even if a stale producer
    # accidentally set the marker to true.
    strict_complete = payload.get("strict_complete") is True and not warnings
    strict_failure = _optional_text(payload.get("strict_failure"))
    encoding = str(payload.get("encoding") or "der")
    return SaipArtifactLoadResult(
        source_path=source_path,
        raw_input_bytes=raw_input_bytes,
        raw_input_sha256=hashlib.sha256(raw_input_bytes).hexdigest(),
        encoding=encoding,
        source_format=_source_format(source_path, encoding),
        decoded_document=decoded_document,
        pes=payload.get("pes"),
        placeholder_evidence=tuple(evidence),
        warnings=warnings,
        strict_complete=strict_complete,
        strict_failure=strict_failure,
        inline_placeholder_records=inline_records,
    )


def _inline_placeholder_evidence(record: Any) -> SaipPlaceholderEvidence:
    return SaipPlaceholderEvidence(
        kind="inline-typed",
        index=_optional_int(getattr(record, "index", None)),
        literal=_optional_text(getattr(record, "literal", None)),
        variable_name=_optional_text(getattr(record, "variable_name", None)),
        type_name=_optional_text(getattr(record, "type_name", None)),
        byte_length=_optional_int(getattr(record, "byte_length", None)),
        modifier=_optional_text(getattr(record, "modifier", None)),
    )


def _source_format(source_path: Path, encoding: str) -> str:
    if source_path.suffix.lower() == ".varder" and encoding == "hex":
        return "varder"
    return {
        "asn": "asn1-value",
        "json": "tagged-json",
        "hex": "hex",
        "der": "der",
    }.get(encoding, encoding)


def _optional_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


__all__ = [
    "SaipArtifactLoadResult",
    "SaipArtifactWarning",
    "SaipPlaceholderEvidence",
    "load_saip_artifact",
]
