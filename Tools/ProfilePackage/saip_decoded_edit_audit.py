# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Decoded-edit coverage audit for the SAIP decoded-field editor surfaces.

The TUI decoded editor in ``Tools/ProfilePackage/saip_decoded_edit.py``
dispatches through four layers:

1. Hand-written editor models (``build_decoded_value_editor_model``).
2. Round-trip pair encoders (``_BYTES_DISPATCHER`` / ``_SCALAR_DISPATCHER``
   / ``_SCALAR_AS_BYTES_DISPATCHER`` / ``_EF_CONTENT_DISPATCHER`` in
   ``saip_asn1_encode.py``).
3. Read-only decoded views (``_decode_special_field`` /
   ``_decode_scalar_special_field`` / ``_decode_known_ef_payload`` in
   ``saip_asn1_decode.py``).
4. Raw hex fallback.

This module walks the compiled pySim SAIP ASN.1 schema
(``pySim.esim.compile_asn1_subdir('saip')``) to enumerate every
``PE-*`` sequence, nested structural type (``Fcp``, ``ProprietaryInfo``,
``ApplicationInstance`` etc.) and ``File``-typed EF member. Each leaf
field or EF key is classified against the four registries above. The
result is a structured coverage report suitable for regression-locking
via a golden baseline (see ``tests/data/saip_decoded_edit_audit_*.json``).

Spec version is read from the shipped ``PE_Definitions-<version>.asn``
filename inside ``pySim/esim/asn1/saip/`` so the baseline can be keyed
on the pySim release rather than a hard-coded tag.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from Tools.ProfilePackage.saip_asn1_decode import (
    _AID_FIELD_NAMES,
    _MEMORY_LIMIT_FIELD_LABELS,
    _decode_scalar_special_field,
    _decode_special_field,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    roundtrip_capable_ef_keys,
    roundtrip_capable_fields,
)
from Tools.ProfilePackage.saip_decoded_edit import (
    _LCSI_STATE_TO_HEX as _HAND_WRITTEN_LCSI_MARKER,
    _SERVICE_TABLE_FILE_DEFS as _HAND_WRITTEN_SERVICE_TABLE_DEFS,
)

# ---------------------------------------------------------------------------
# Classification taxonomy
#
# Every leaf field collected from the ASN.1 schema is mapped to exactly one
# of the classes below. The names are stable and get written into the
# baseline JSON; renaming any of them is a breaking change.

CLASS_HAND_WRITTEN = "hand_written"
CLASS_ROUNDTRIP_BYTES = "roundtrip_bytes"
CLASS_ROUNDTRIP_SCALAR = "roundtrip_scalar"
CLASS_ROUNDTRIP_EF = "roundtrip_ef"
CLASS_READONLY_BYTES = "readonly_bytes"
CLASS_READONLY_SCALAR = "readonly_scalar"
CLASS_READONLY_EF = "readonly_ef"
CLASS_STRUCTURAL_ONLY = "structural_only"
CLASS_MISSING = "missing"

# ASN.1 PE-type → parent DF/ADF token hint. Threaded into
# ``_decode_known_ef_payload`` so the audit coverage check honours the
# same parent-aware FID dispatcher as the interactive TUI. When the PE
# type is not enumerated here, parent hint defaults to ``None`` which
# is equivalent to the pre-Round-6 behaviour.
_PE_TYPE_TO_PARENT_HINT: dict[str, str] = {
    "PE-MF": "mf",
    "PE-USIM": "adf-usim",
    "PE-OPT-USIM": "adf-usim",
    "PE-ISIM": "adf-isim",
    "PE-OPT-ISIM": "adf-isim",
    "PE-CSIM": "adf-csim",
    "PE-OPT-CSIM": "adf-csim",
    "PE-Telecom": "df-telecom",
    "PE-OPT-Telecom": "df-telecom",
    "PE-Phonebook": "df-phonebook",
    "PE-GSM-Access": "df-gsm-access",
    "PE-DF-5GS": "df-5gs",
    "PE-DF-5GProSe": "df-5gprose",
    "PE-DF-SNPN": "df-snpn",
    "PE-DF-5mbsUeConfig": "df-5mbsueconfig",
    "PE-DF-HNB": "df-hnb",
    "PE-DF-SAIP": "df-saip",
    "PE-DF-EAP": "df-eap",
}


def _parent_hint_for_path(path: tuple[str, ...]) -> str | None:
    if len(path) == 0:
        return None
    return _PE_TYPE_TO_PARENT_HINT.get(str(path[0]))


# Hand-written editors in ``saip_decoded_edit.py``. Keep in sync with
# ``build_decoded_value_editor_model`` and
# ``encode_decoded_value_editor_payload`` — both must know about a field
# for it to count as hand-written.
_HAND_WRITTEN_FIELDS: frozenset[str] = frozenset(
    {
        "shortEFID",
        "efFileSize",
        "securityAttributesReferenced",
        "lcsi",
        "fillFileOffset",
        "fileID",
        "iccid",
    }
)

# Hand-written editors that activate only when a specific ``last_ef_key``
# is in scope (fillFileContent of EF.UST / EF.EST / EF.IST / EF.IMSI /
# EF.ICCID). The mapping is consulted only for the ``fillFileContent``
# field name.
_HAND_WRITTEN_FILL_FILE_CONTENT_EFS: frozenset[str] = frozenset(
    {"ef-imsi", "ef-iccid"} | set(_HAND_WRITTEN_SERVICE_TABLE_DEFS.keys())
)

# Named structural types that we always expand (child fields matter
# semantically, parent wrapper does not). Anonymous ``SEQUENCE`` /
# ``CHOICE`` / ``SEQUENCE OF`` nodes are also expanded by the walker,
# but named types outside this set (e.g. ``ApplicationIdentifier``)
# stay as leaves because they are treated as tagged-bytes in the SAIP
# JSON. ``File`` is handled on its own dedicated EF path.
_EXPANDABLE_TYPES: frozenset[str] = frozenset(
    {
        "PEHeader",
        "ProfileHeader",
        "Fcp",
        "ProprietaryInfo",
        "ApplicationInstance",
        "ApplicationLoadPackage",
        "ApplicationSystemParameters",
        "UICCApplicationParameters",
        "KeyObject",
        "ControlReferenceTemplate",
        "ADFRFMAccess",
        "PINConfiguration",
        "PUKConfiguration",
        "MappingParameter",
        "AlgoParameter",
        "FileManagement",
        # Wave A: expand these so their children become individually
        # classifiable leaves rather than an opaque "missing" wrapper.
        "TS102226AdditionalContactlessParameters",
        "ServicesList",
        "IotOptions",
    }
)

# EF member names that anchor a DF / ADF / MF slot rather than carrying
# decodable EF content. The SAIP spec models them with the ``File``
# wrapper, but the only content is the FCP descriptor of the parent DF
# — there is no body to round-trip. We classify them as
# ``structural_only`` so they don't show up in the ``missing`` bucket.
# ``mf`` is the single-MF anchor used by PE-MF / PE-IoT.
_EF_ANCHOR_NAMES: frozenset[str] = frozenset(
    {
        "mf",
    }
)


def _is_ef_anchor(ef_key: str) -> bool:
    normalized = str(ef_key or "").strip()
    if normalized in _EF_ANCHOR_NAMES:
        return True
    if normalized.startswith("adf-"):
        return True
    if normalized.startswith("df-"):
        return True
    return False

# Leaf type names that we classify as "structural only" when they have no
# semantic decoder/editor. They still show up in the report but are kept
# out of the ``missing`` bucket because editing them via the decoded
# surface has no meaningful semantic to attach (the raw-hex fallback
# suffices and is already wired). Keeping them visible makes it easy to
# upgrade any one of them to a roundtrip encoder later.
_STRUCTURAL_LEAF_TYPE_NAMES: frozenset[str] = frozenset(
    {
        "NULL",
        "OBJECT IDENTIFIER",
        "UTF8String",
        "UInt8",
        "UInt15",
        "UInt16",
        "INTEGER",
    }
)


@dataclass(frozen=True)
class FieldRecord:
    """One leaf field or EF member of a PE sequence / nested sequence.

    ``path`` is the ASN.1 member path from the top-level PE down to the
    leaf (``("PE-USIM", "adf-usim")``, ``("PE-SecurityDomain",
    "instance", "applicationPrivileges")``).

    ``kind`` is either ``"field"`` for a named scalar/bytes member or
    ``"ef"`` for a ``File``-typed member (expanded via
    ``_decode_known_ef_payload`` / ``_EF_CONTENT_DISPATCHER``).
    """

    path: tuple[str, ...]
    type_name: str
    optional: bool
    kind: str
    classification: str

    @property
    def name(self) -> str:
        if len(self.path) == 0:
            return ""
        return str(self.path[-1])

    @property
    def parent(self) -> str:
        if len(self.path) <= 1:
            return ""
        return str(self.path[-2])


@dataclass
class GroupReport:
    group: str
    fields: list[FieldRecord] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for record in self.fields:
            current = int(totals.get(record.classification, 0))
            totals[record.classification] = current + 1
        return totals


@dataclass
class AuditReport:
    spec_version: str
    spec_asn1_file: str
    groups: list[GroupReport] = field(default_factory=list)

    def totals(self) -> dict[str, int]:
        """Return aggregate counts of all audit entry categories."""
        aggregate: dict[str, int] = {}
        for group in self.groups:
            for classification, count in group.summary().items():
                current = int(aggregate.get(classification, 0))
                aggregate[classification] = current + int(count)
        return aggregate

    def missing_entries(self) -> list[FieldRecord]:
        """Return the list of audit entries that are missing required decoded fields."""
        missing: list[FieldRecord] = []
        for group in self.groups:
            for record in group.fields:
                if record.classification == CLASS_MISSING:
                    missing.append(record)
        return missing


# ---------------------------------------------------------------------------
# pySim integration.


class AuditUnavailableError(RuntimeError):
    """Raised when the pySim SAIP ASN.1 schema cannot be compiled."""


def _load_saip_spec() -> tuple[Any, str, str]:
    """Return ``(asn1 specification, version, asn1_filename)``.

    Relies on ``pySim.esim.compile_asn1_subdir('saip')``. The version is
    parsed from the shipped ``PE_Definitions-<version>.asn`` filename
    (pySim 3.3.1 ships ``PE_Definitions-3.3.1.asn``). When the spec
    filename does not match the expected pattern, ``"unknown"`` is
    returned so the baseline key can still be stable.
    """

    try:
        from pySim.esim import compile_asn1_subdir
        import pySim.esim as pysim_esim
    except Exception as error:
        raise AuditUnavailableError(
            f"pySim.esim is not importable: {type(error).__name__}: {error}"
        ) from error

    try:
        spec = compile_asn1_subdir("saip")
    except Exception as error:
        raise AuditUnavailableError(
            f"compile_asn1_subdir('saip') failed: {type(error).__name__}: {error}"
        ) from error

    asn1_root = os.path.join(os.path.dirname(pysim_esim.__file__), "asn1", "saip")
    version = "unknown"
    asn1_file = ""
    if os.path.isdir(asn1_root):
        candidates = sorted(os.listdir(asn1_root))
        for candidate in candidates:
            if candidate.endswith(".asn") is False:
                continue
            matched = re.match(
                r"PE[_-]?Definitions[-_]?([0-9]+(?:\.[0-9]+)+)\.asn$",
                candidate,
                re.IGNORECASE,
            )
            if matched is None:
                continue
            version = matched.group(1)
            asn1_file = candidate
            break

    return spec, version, asn1_file


# ---------------------------------------------------------------------------
# Classifier.


def _is_ef_key_covered(
    ef_key: str,
    *,
    parent_hint: str | None = None,
) -> str | None:
    # The pySim EF-content dispatcher is case-sensitive (``ef-keysPS``
    # is the only mixed-case key). Match the ASN.1 member name verbatim
    # first, then fall back to lowercase for the read-only route which
    # normalises everything to lower-case internally.
    verbatim = str(ef_key or "").strip()
    if verbatim == "":
        return None
    capable_exact = set(roundtrip_capable_ef_keys())
    if verbatim in capable_exact:
        return CLASS_ROUNDTRIP_EF
    normalized_lower = verbatim.lower()
    if normalized_lower in capable_exact:
        return CLASS_ROUNDTRIP_EF
    # Read-only path: ``_decode_known_ef_payload`` recognises many more
    # EF tokens than the roundtrip dispatcher. We call it with an empty
    # hex string because the decoder tolerates that and the caller does
    # not care about the returned payload — only whether a non-None
    # result is reachable (i.e. a routing entry exists for the token).
    # The parent hint (``adf-usim`` / ``df-telecom`` / …) is threaded
    # through so parent-aware FID dispatchers see the same enclosing
    # context that the interactive edit surface would provide.
    try:
        from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload
        decoded = _decode_known_ef_payload(
            ef_key=normalized_lower,
            fid=None,
            hex_clean="",
            parent_hint=parent_hint,
        )
    except Exception:
        decoded = None
    if decoded is not None:
        return CLASS_READONLY_EF
    return None


def _is_field_hand_written(field_name: str, parent_name: str) -> bool:
    name = str(field_name or "").strip()
    if name in _HAND_WRITTEN_FIELDS:
        return True
    if name == "state" and parent_name == "lcsi":
        return True
    # fillFileContent has a hand-written editor only for a curated set
    # of EF keys. Callers that care route through the EF classifier.
    return False


def _is_field_roundtrip(field_name: str) -> str | None:
    name = str(field_name or "").strip()
    capability = roundtrip_capable_fields().get(name)
    if capability == "bytes":
        return CLASS_ROUNDTRIP_BYTES
    if capability == "scalar":
        return CLASS_ROUNDTRIP_SCALAR
    if name in _AID_FIELD_NAMES:
        # AIDs are registered through a shared bytes encoder.
        return CLASS_ROUNDTRIP_BYTES
    if name in _MEMORY_LIMIT_FIELD_LABELS:
        return CLASS_ROUNDTRIP_BYTES
    return None


def _is_field_readonly(field_name: str) -> str | None:
    name = str(field_name or "").strip()
    # Scalar first — the scalar decoder accepts None/empty cleanly and
    # returning a shape dict indicates the editor can render a view.
    try:
        scalar_result = _decode_scalar_special_field(name, 0)
    except Exception:
        scalar_result = None
    if scalar_result is not None:
        return CLASS_READONLY_SCALAR
    try:
        bytes_result = _decode_special_field(name, b"")
    except Exception:
        bytes_result = None
    if bytes_result is not None:
        return CLASS_READONLY_BYTES
    return None


def _classify_leaf_field(
    *,
    field_name: str,
    parent_name: str,
    type_name: str,
) -> str:
    if _is_field_hand_written(field_name, parent_name):
        return CLASS_HAND_WRITTEN
    roundtrip = _is_field_roundtrip(field_name)
    if roundtrip is not None:
        return roundtrip
    readonly = _is_field_readonly(field_name)
    if readonly is not None:
        return readonly
    if type_name in _STRUCTURAL_LEAF_TYPE_NAMES:
        return CLASS_STRUCTURAL_ONLY
    if str(field_name).endswith("-header"):
        # PE-level headers are SEQUENCEs that only carry ``mandated``
        # (NULL) and ``identification`` (UInt15). We flag them as
        # structural; the identification field is picked up separately
        # when the header is expanded.
        return CLASS_STRUCTURAL_ONLY
    return CLASS_MISSING


def _classify_ef_member(
    ef_key: str,
    *,
    parent_hint: str | None = None,
) -> str:
    covered = _is_ef_key_covered(ef_key, parent_hint=parent_hint)
    if covered is not None:
        return covered
    if _is_ef_anchor(ef_key) is True:
        return CLASS_STRUCTURAL_ONLY
    return CLASS_MISSING


# ---------------------------------------------------------------------------
# Walkers.


def _member_type_name(member: Any) -> str:
    """Return the ASN.1 type name for a Sequence/Choice member.

    asn1tools exposes ``member.type_name`` for named types but falls
    back to ``OCTET STRING``/``INTEGER`` for primitive leaves. We also
    peek into SequenceOf.element_type so EF members carrying the
    ``File`` wrapper surface ``File`` rather than the opaque CHOICE.
    """

    name = str(getattr(member, "type_name", "") or "").strip()
    if len(name) > 0:
        return name
    return type(member).__name__


def _iter_sequence_members(sequence: Any) -> Iterable[Any]:
    root = getattr(sequence, "root_members", None)
    if root is None:
        return []
    return list(root)


_MAX_RECURSION_DEPTH = 8


def _expand_type_by_name(
    *,
    spec: Any,
    type_name: str,
    path: tuple[str, ...],
    depth: int,
    optional: bool,
) -> list[FieldRecord]:
    compiled = spec.types.get(type_name)
    if compiled is None:
        return [
            FieldRecord(
                path=path,
                type_name=type_name,
                optional=optional,
                kind="field",
                classification=CLASS_STRUCTURAL_ONLY,
            )
        ]
    inner = getattr(compiled, "type", None)
    if inner is None:
        return [
            FieldRecord(
                path=path,
                type_name=type_name,
                optional=optional,
                kind="field",
                classification=CLASS_STRUCTURAL_ONLY,
            )
        ]
    records: list[FieldRecord] = []
    for member in _iter_sequence_members(inner):
        records.extend(
            _walk_member(
                spec=spec,
                member=member,
                path=path,
                depth=depth + 1,
            )
        )
    if len(records) == 0:
        records.append(
            FieldRecord(
                path=path,
                type_name=type_name,
                optional=optional,
                kind="field",
                classification=CLASS_STRUCTURAL_ONLY,
            )
        )
    return records


def _expand_member_inline(
    *,
    spec: Any,
    inner: Any,
    path: tuple[str, ...],
    depth: int,
    optional: bool,
    fallback_type_name: str,
) -> list[FieldRecord]:
    """Expand an anonymous SEQUENCE/CHOICE whose members we care about."""

    members = _iter_sequence_members(inner)
    if len(members) == 0:
        members = list(getattr(inner, "members", []) or [])
    if len(members) == 0:
        return [
            FieldRecord(
                path=path,
                type_name=fallback_type_name,
                optional=optional,
                kind="field",
                classification=CLASS_STRUCTURAL_ONLY,
            )
        ]
    records: list[FieldRecord] = []
    for member in members:
        records.extend(
            _walk_member(
                spec=spec,
                member=member,
                path=path,
                depth=depth + 1,
            )
        )
    return records


def _walk_member(
    *,
    spec: Any,
    member: Any,
    path: tuple[str, ...],
    depth: int = 0,
) -> list[FieldRecord]:
    if depth > _MAX_RECURSION_DEPTH:
        return []
    member_name = str(getattr(member, "name", "") or "").strip()
    if len(member_name) == 0:
        return []
    type_name = _member_type_name(member)
    optional = bool(getattr(member, "optional", False))
    member_path = path + (member_name,)
    member_cls = type(member).__name__

    # File wrapper: a SEQUENCE OF CHOICE carrying EF data. Routed
    # through the EF classifier by the member's own name (ef-*,
    # adf-*, df-*, mf). The parent hint is derived from the root PE
    # type so parent-aware FID dispatchers resolve deterministically.
    if type_name == "File":
        ef_class = _classify_ef_member(
            member_name,
            parent_hint=_parent_hint_for_path(path),
        )
        return [
            FieldRecord(
                path=member_path,
                type_name=type_name,
                optional=optional,
                kind="ef",
                classification=ef_class,
            )
        ]

    # Explicit CHOICE/SEQUENCE wrapper (ASN.1 ``[...] EXPLICIT``):
    # unwrap once, keep the same name, re-enter the walker against
    # the wrapped type.
    if member_cls == "ExplicitTag":
        wrapped = getattr(member, "inner", None)
        if wrapped is None:
            return [
                FieldRecord(
                    path=member_path,
                    type_name=type_name,
                    optional=optional,
                    kind="field",
                    classification=CLASS_STRUCTURAL_ONLY,
                )
            ]
        wrapped_cls = type(wrapped).__name__
        wrapped_type_name = _member_type_name(wrapped)
        if wrapped_cls in ("Choice", "Sequence"):
            expanded = _expand_member_inline(
                spec=spec,
                inner=wrapped,
                path=member_path,
                depth=depth,
                optional=optional,
                fallback_type_name=wrapped_type_name,
            )
            return expanded
        if wrapped_cls == "SequenceOf":
            element = getattr(wrapped, "element_type", None)
            if element is not None:
                return _walk_sequence_of_element(
                    spec=spec,
                    element=element,
                    path=member_path,
                    depth=depth,
                    optional=optional,
                )
        # Primitive behind the ExplicitTag.
        classification = _classify_leaf_field(
            field_name=member_name,
            parent_name=str(path[-1]) if len(path) > 0 else "",
            type_name=wrapped_type_name,
        )
        return [
            FieldRecord(
                path=member_path,
                type_name=wrapped_type_name,
                optional=optional,
                kind="field",
                classification=classification,
            )
        ]

    # Named structural type (ApplicationInstance, KeyObject, ...):
    # expand via the top-level type table, keeping the member name in
    # the path so the nested leaves can be addressed.
    if type_name in _EXPANDABLE_TYPES:
        return _expand_type_by_name(
            spec=spec,
            type_name=type_name,
            path=member_path,
            depth=depth,
            optional=optional,
        )

    # Choice members: expand each variant. Anonymous CHOICE nodes carry
    # type_name == "CHOICE"; known named CHOICE types are handled above.
    if member_cls == "Choice":
        return _expand_member_inline(
            spec=spec,
            inner=member,
            path=member_path,
            depth=depth,
            optional=optional,
            fallback_type_name=type_name,
        )

    # Anonymous SEQUENCE nodes (type_name == "SEQUENCE"): expand in place.
    if member_cls == "Sequence" and type_name in ("SEQUENCE", ""):
        return _expand_member_inline(
            spec=spec,
            inner=member,
            path=member_path,
            depth=depth,
            optional=optional,
            fallback_type_name=type_name,
        )

    # SEQUENCE OF <element>: treat as the element. If the element is a
    # plain OctetString / UTF8 / UInt etc., the member name itself is
    # the classification target (e.g. ``tarList``, ``sdPersoData``).
    if member_cls == "SequenceOf":
        element = getattr(member, "element_type", None)
        if element is None:
            classification = _classify_leaf_field(
                field_name=member_name,
                parent_name=str(path[-1]) if len(path) > 0 else "",
                type_name=type_name,
            )
            return [
                FieldRecord(
                    path=member_path,
                    type_name=type_name,
                    optional=optional,
                    kind="field",
                    classification=classification,
                )
            ]
        expanded = _walk_sequence_of_element(
            spec=spec,
            element=element,
            path=member_path,
            depth=depth,
            optional=optional,
        )
        if len(expanded) == 0:
            classification = _classify_leaf_field(
                field_name=member_name,
                parent_name=str(path[-1]) if len(path) > 0 else "",
                type_name=type_name,
            )
            return [
                FieldRecord(
                    path=member_path,
                    type_name=type_name,
                    optional=optional,
                    kind="field",
                    classification=classification,
                )
            ]
        return expanded

    # Leaf scalar / bytes field.
    classification = _classify_leaf_field(
        field_name=member_name,
        parent_name=str(path[-1]) if len(path) > 0 else "",
        type_name=type_name,
    )
    return [
        FieldRecord(
            path=member_path,
            type_name=type_name,
            optional=optional,
            kind="field",
            classification=classification,
        )
    ]


def _walk_sequence_of_element(
    *,
    spec: Any,
    element: Any,
    path: tuple[str, ...],
    depth: int,
    optional: bool,
) -> list[FieldRecord]:
    element_cls = type(element).__name__
    element_type_name = _member_type_name(element)

    if element_type_name == "File":
        ef_class = _classify_ef_member(
            str(path[-1]) if len(path) > 0 else "",
            parent_hint=_parent_hint_for_path(path),
        )
        return [
            FieldRecord(
                path=path,
                type_name=element_type_name,
                optional=optional,
                kind="ef",
                classification=ef_class,
            )
        ]

    if element_type_name in _EXPANDABLE_TYPES:
        return _expand_type_by_name(
            spec=spec,
            type_name=element_type_name,
            path=path,
            depth=depth,
            optional=optional,
        )

    if element_cls in ("Choice", "Sequence"):
        return _expand_member_inline(
            spec=spec,
            inner=element,
            path=path,
            depth=depth,
            optional=optional,
            fallback_type_name=element_type_name,
        )

    if element_cls == "SequenceOf":
        nested = getattr(element, "element_type", None)
        if nested is None:
            return []
        return _walk_sequence_of_element(
            spec=spec,
            element=nested,
            path=path,
            depth=depth + 1,
            optional=optional,
        )

    # Primitive element — leaf classified by the wrapper member name.
    leaf_name = str(path[-1]) if len(path) > 0 else ""
    classification = _classify_leaf_field(
        field_name=leaf_name,
        parent_name=str(path[-2]) if len(path) > 1 else "",
        type_name=element_type_name,
    )
    return [
        FieldRecord(
            path=path,
            type_name=element_type_name,
            optional=optional,
            kind="field",
            classification=classification,
        )
    ]


# ---------------------------------------------------------------------------
# Top-level PE enumeration.


def _profile_element_groups(spec: Any) -> list[tuple[str, str]]:
    """Return ``[(choice_name, sequence_type_name), ...]`` for every PE.

    Skips ``PE-Dummy`` placeholders that the ASN.1 reserves for future
    rfu slots.
    """

    choice_ct = spec.types.get("ProfileElement")
    if choice_ct is None:
        return []
    choice_inner = getattr(choice_ct, "type", None)
    if choice_inner is None:
        return []
    groups: list[tuple[str, str]] = []
    for member in getattr(choice_inner, "members", []) or []:
        name = str(getattr(member, "name", "") or "").strip()
        tn = _member_type_name(member)
        if len(name) == 0 or tn == "PE-Dummy":
            continue
        groups.append((name, tn))
    return groups


def audit_decoded_editors() -> AuditReport:
    """Produce the full decoded-editor coverage audit.

    Raises ``AuditUnavailableError`` if ``pySim.esim.compile_asn1_subdir``
    cannot be imported or the ``saip`` subdir fails to compile.
    """

    spec, version, asn1_file = _load_saip_spec()
    report = AuditReport(spec_version=version, spec_asn1_file=asn1_file)
    for choice_name, pe_type in _profile_element_groups(spec):
        compiled = spec.types.get(pe_type)
        if compiled is None:
            continue
        pe_inner = getattr(compiled, "type", None)
        if pe_inner is None:
            continue
        group_path = (pe_type,)
        group = GroupReport(group=pe_type)
        for member in _iter_sequence_members(pe_inner):
            for record in _walk_member(
                spec=spec,
                member=member,
                path=group_path,
            ):
                group.fields.append(record)
        report.groups.append(group)

    # Stable ordering for reproducibility: groups alphabetical, fields
    # in discovery order (matches the ASN.1 declaration order).
    report.groups.sort(key=lambda g: g.group)
    return report


# ---------------------------------------------------------------------------
# Baseline / diff helpers.


def report_to_baseline_dict(report: AuditReport) -> dict[str, Any]:
    """Render the audit as a JSON-serialisable baseline document."""

    groups_payload: dict[str, Any] = {}
    for group in report.groups:
        entries: list[dict[str, Any]] = []
        for record in group.fields:
            entries.append(
                {
                    "path": list(record.path),
                    "type_name": record.type_name,
                    "optional": record.optional,
                    "kind": record.kind,
                    "classification": record.classification,
                }
            )
        groups_payload[group.group] = {
            "summary": group.summary(),
            "fields": entries,
        }
    return {
        "saip_spec_version": report.spec_version,
        "saip_spec_asn1_file": report.spec_asn1_file,
        "totals": report.totals(),
        "groups": groups_payload,
    }


def format_audit_report(
    report: AuditReport,
    *,
    show_only_missing: bool = False,
) -> str:
    """Format the decoded-field edit audit results as a structured text report."""
    lines: list[str] = []
    header = (
        f"SAIP decoded-editor audit "
        f"(spec {report.spec_version}, "
        f"source {report.spec_asn1_file or '<unknown>'})"
    )
    lines.append(header)
    lines.append("=" * len(header))
    totals = report.totals()
    lines.append("Totals:")
    for key in sorted(totals.keys()):
        lines.append(f"  {key:>20s} : {totals[key]}")
    lines.append("")
    for group in report.groups:
        if show_only_missing is True:
            missing_only = [
                record for record in group.fields
                if record.classification == CLASS_MISSING
            ]
            if len(missing_only) == 0:
                continue
            lines.append(f"[{group.group}] missing ({len(missing_only)}):")
            for record in missing_only:
                lines.append(
                    f"  - {'.'.join(record.path)} "
                    f"({record.type_name}, kind={record.kind})"
                )
            lines.append("")
            continue
        summary = group.summary()
        summary_text = ", ".join(
            f"{key}={summary[key]}" for key in sorted(summary.keys())
        )
        lines.append(f"[{group.group}] {summary_text}")
        for record in group.fields:
            lines.append(
                f"  - {record.classification:>20s}  "
                f"{'.'.join(record.path)} "
                f"({record.type_name}, kind={record.kind}, "
                f"optional={record.optional})"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# Hand-written marker imports are kept here purely so static analysers
# don't strip them. They document that the hand-written ``lcsi`` editor
# uses the state→hex table from ``saip_decoded_edit.py``.
_ = _HAND_WRITTEN_LCSI_MARKER
