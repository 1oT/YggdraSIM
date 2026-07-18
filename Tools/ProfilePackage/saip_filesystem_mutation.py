# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Deterministic document-level SAIP filesystem materialization.

This module is the plugin-neutral seam between an imported filesystem tree
and YggdraSIM's decoded SAIP document model.  Entries already matched to a
registered ETSI template are materialized in their native filesystem PEs.
Only unmatched entries supplied through the fallback API are represented by
PE-GFM instances, using one PE per parent directory context.

Callers remain responsible for attaching generation/provenance metadata and
for resolving access policy.  GFM fallback accepts only
``FilesystemAccessPolicy.UNRESOLVED`` and never invents access rules.  It does,
however, preserve an explicit validated source EF.ARR FID plus record
reference.  Native entries encode ``securityAttributesReferenced`` only when
the caller supplies an explicit validated ``arr_record``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from .saip_json_codec import (
    base_pe_type,
    build_profile_sequence_from_document,
    ensure_workspace_pysim_on_path,
)
from .saip_pe_quick_add import (
    _FallbackFileTemplate,
    _explicit_file_descriptor,
)
from .saip_profile_scaffold import build_scaffold_profile_document_from_menu_ids

MF_FID = 0x3F00


class FilesystemMutationError(ValueError):
    """Raised when filesystem specifications cannot form a safe SAIP tree."""


class FilesystemNodeKind(str, Enum):
    """Filesystem node category represented by one creation specification."""

    MF = "mf"
    ADF = "adf"
    DF = "df"
    EF = "ef"


class ElementaryFileStructure(str, Enum):
    """ETSI elementary-file structure used to build the FCP descriptor."""

    TRANSPARENT = "transparent"
    LINEAR_FIXED = "linear-fixed"
    CYCLIC = "cyclic"
    BER_TLV = "ber-tlv"


class FilesystemAccessPolicy(str, Enum):
    """Access-policy state accepted by this filesystem-only composer."""

    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class NativeFilesystemEntrySpec:
    """One imported file matched to a native SAIP filesystem field.

    ``menu_id`` identifies the owning filesystem PE and ``pe_name`` identifies
    the field in that PE's registered template.  ``fid=None`` is accepted for
    a native ADF root whose imported FID was only a source selector; the
    composer assigns and records the standard temporary ADF FID instead.  A
    concrete source ADF FID is preserved when it is accompanied by its
    standards-level DF name/AID.
    ``arr_record`` is an explicit reference to an ARR record in the same
    context.  Its presence is authoritative; absence remains unresolved.
    ``sfi`` is the logical short file identifier in range 1..30; the
    materializer performs the ISO 7816/SAIP one-octet wire encoding.
    The MF kind is restricted to the one native root field ``mf.mf`` at FID
    ``3F00``; fallback/GFM specifications can never create an MF.
    """

    menu_id: str
    pe_name: str
    fid: int | None
    kind: FilesystemNodeKind
    structure: ElementaryFileStructure | None = None
    file_size: int | None = None
    record_length: int | None = None
    record_count: int | None = None
    sfi: int | None = None
    df_name: bytes | None = None
    literal_content: bytes | None = None
    lifecycle: int | None = 0x05
    arr_record: int | None = None


@dataclass(frozen=True, slots=True)
class FilesystemEntrySpec:
    """One DF, ADF, or EF to create below ``parent_fid_path``.

    ``parent_fid_path`` is absolute and must start with MF (``0x3F00``).
    ``df_name`` optionally carries an ISO 7816 DF-name/AID for an ADF or DF.
    Literal content is emitted byte-for-byte after ``createFCP``; no padding,
    access rules, or personalization values are synthesized.  When both
    ``arr_file_fid`` and ``arr_record`` are supplied, their validated source
    values are preserved as the three-byte ``securityAttributesReferenced``
    value.  Neither value is inferred when they are absent.  An explicit
    ``mf_field_name`` binds any imported FID to one mandatory PE-MF field.
    ``sfi`` is the logical short file identifier in range 1..30; callers must
    not pre-shift it into the one-octet ``shortEFID`` wire representation.
    """

    parent_fid_path: tuple[int, ...]
    fid: int
    kind: FilesystemNodeKind
    structure: ElementaryFileStructure | None = None
    file_size: int | None = None
    record_length: int | None = None
    record_count: int | None = None
    sfi: int | None = None
    df_name: bytes | None = None
    literal_content: bytes | None = None
    lifecycle: int | None = 0x05
    access_policy: FilesystemAccessPolicy = FilesystemAccessPolicy.UNRESOLVED
    mf_field_name: str | None = None
    arr_file_fid: int | None = None
    arr_record: int | None = None

    @property
    def fid_path(self) -> tuple[int, ...]:
        """Return the absolute path including this entry's own FID."""

        return self.parent_fid_path + (self.fid,)


@dataclass(frozen=True, slots=True)
class NativeTemporaryFidAssignment:
    """Auditable temporary FID inherited for one native ADF root."""

    menu_id: str
    pe_name: str
    fid: int


@dataclass(frozen=True, slots=True)
class FilesystemMaterializationSummary:
    """Immutable evidence describing the deterministic document layout."""

    entry_count: int
    reconciled_mf_fids: tuple[int, ...]
    gfm_parent_paths: tuple[tuple[int, ...], ...]
    der_byte_count: int
    native_menu_ids: tuple[str, ...] = ()
    # Actual native PE sequence after repeated file slots have been
    # partitioned.  ``native_menu_ids`` remains the compatibility view of
    # unique PE types; this field preserves repeated instances such as
    # ``("phonebook", "phonebook")``.
    native_menu_instances: tuple[str, ...] = ()
    native_entry_count: int = 0
    fallback_entry_count: int = 0
    inherited_temporary_fids: tuple[NativeTemporaryFidAssignment, ...] = ()


@dataclass(frozen=True, slots=True)
class FilesystemMaterializationResult:
    """Materialized document plus immutable structural evidence.

    The document itself intentionally remains the repository's normal mutable
    decoded-document object so a caller can add generation metadata before it
    is opened in an authoring session.
    """

    document: dict[str, Any]
    summary: FilesystemMaterializationSummary


_MANDATORY_MF_BINDINGS: dict[
    int,
    tuple[str, ElementaryFileStructure],
] = {
    0x2FE2: ("ef-iccid", ElementaryFileStructure.TRANSPARENT),
    # Compatibility with the vendored pySim FilesAtMF template.
    0x2F02: ("ef-iccid", ElementaryFileStructure.TRANSPARENT),
    0x2F00: ("ef-dir", ElementaryFileStructure.LINEAR_FIXED),
    0x2F06: ("ef-arr", ElementaryFileStructure.LINEAR_FIXED),
}

_MANDATORY_MF_FIELDS = frozenset(
    field_name for field_name, _structure in _MANDATORY_MF_BINDINGS.values()
)

_STRUCTURE_TO_TEMPLATE_TYPE: dict[ElementaryFileStructure, str] = {
    ElementaryFileStructure.TRANSPARENT: "TR",
    ElementaryFileStructure.LINEAR_FIXED: "LF",
    ElementaryFileStructure.CYCLIC: "CY",
    ElementaryFileStructure.BER_TLV: "BT",
}

NATIVE_TEMPLATE_MENU_IDS = (
    "mf",
    "cd",
    "telecom",
    "usim",
    "opt-usim",
    "isim",
    "opt-isim",
    "phonebook",
    "gsm-access",
    "eap",
    "df-5gs",
    "df-saip",
    "df-snpn",
    "df-5gprose",
)

_NATIVE_MENU_ORDER = NATIVE_TEMPLATE_MENU_IDS

# A PE-PHONEBOOK contains one ASN.1 member for each phonebook file kind, while
# the registered GFSTE deliberately exposes several allocatable slots with the
# same ``pe_name`` (for example multiple EF.ADN instances).  Those slots are
# represented by multiple PE-PHONEBOOK instances.  Other filesystem PEs are
# singleton contexts and duplicate fields there remain an error.
_REPEATABLE_NATIVE_MENU_IDS = frozenset({"phonebook"})

# These menu IDs have ASN.1/factory placeholders, but the vendored pySim has
# no matching filesystem ProfileTemplate.  Their placeholder OIDs currently
# collide with unrelated registered templates, so treating them as native
# would silently place files in the wrong tree.  The planner must use GFM.
_SKELETON_ONLY_FILESYSTEM_MENU_IDS = frozenset({"csim", "opt-csim", "iot", "opt-iot"})

_NATIVE_MENU_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "opt-usim": ("usim",),
    "phonebook": ("usim",),
    "gsm-access": ("usim",),
    "eap": ("usim",),
    "df-5gs": ("usim",),
    "df-saip": ("usim",),
    "df-snpn": ("usim",),
    "df-5gprose": ("usim",),
    "opt-isim": ("isim",),
}

_NATIVE_ADF_TEMPORARY_FIDS: dict[tuple[str, str], int] = {
    ("usim", "adf-usim"): 0x7FF0,
    ("isim", "adf-isim"): 0x7FF2,
}

_NATIVE_ADF_ROOTS: dict[str, str] = {
    "usim": "adf-usim",
    "isim": "adf-isim",
}

# The vendored Optional USIM V2 registry spells the EF.ACMmax template field
# ``ef-acmmax``, while the corresponding ASN.1 ProfileElement member is
# ``ef-acmax``.  Keep this standards-template compatibility alias local to the
# registry seam and verify both the schema field and target metadata at use.
_NATIVE_TEMPLATE_FIELD_ALIASES: dict[tuple[str, str], str] = {
    ("opt-usim", "ef-acmax"): "ef-acmmax",
}


def native_temporary_fid(menu_id: str, pe_name: str) -> int | None:
    """Return the core-owned temporary FID for a native ADF root, if any."""

    return _NATIVE_ADF_TEMPORARY_FIDS.get((str(menu_id), str(pe_name)))


def _hex_path(path: tuple[int, ...]) -> str:
    return "/".join(f"{part:04X}" for part in path)


def _require_int(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FilesystemMutationError(f"{label} must be an integer.")
    normalized = int(value)
    if normalized < minimum or normalized > maximum:
        raise FilesystemMutationError(
            f"{label} must be in range {minimum}..{maximum} (got {normalized})."
        )
    return normalized


def _validate_spec(spec: FilesystemEntrySpec, *, index: int) -> None:
    label = f"entry #{index}"
    if not isinstance(spec, FilesystemEntrySpec):
        raise TypeError(f"{label} must be a FilesystemEntrySpec.")
    if not isinstance(spec.parent_fid_path, tuple) or not spec.parent_fid_path:
        raise FilesystemMutationError(
            f"{label} parent_fid_path must be a non-empty tuple beginning with 3F00."
        )
    for part_index, part in enumerate(spec.parent_fid_path):
        _require_int(
            part,
            label=f"{label} parent_fid_path[{part_index}]",
            minimum=0,
            maximum=0xFFFF,
        )
    if spec.parent_fid_path[0] != MF_FID:
        raise FilesystemMutationError(f"{label} parent_fid_path must begin with MF 3F00.")
    if MF_FID in spec.parent_fid_path[1:]:
        raise FilesystemMutationError(f"{label} parent_fid_path contains a nested MF 3F00.")
    _require_int(spec.fid, label=f"{label} fid", minimum=0, maximum=0xFFFF)
    if spec.fid == MF_FID:
        raise FilesystemMutationError(f"{label} cannot create another MF (FID 3F00).")
    if not isinstance(spec.kind, FilesystemNodeKind):
        raise FilesystemMutationError(f"{label} kind must be a FilesystemNodeKind.")
    if spec.kind is FilesystemNodeKind.MF:
        raise FilesystemMutationError(
            f"{label} cannot create an MF through fallback/GFM materialization."
        )
    if not isinstance(spec.access_policy, FilesystemAccessPolicy):
        raise FilesystemMutationError(
            f"{label} access_policy must be FilesystemAccessPolicy.UNRESOLVED."
        )
    if spec.access_policy is not FilesystemAccessPolicy.UNRESOLVED:
        raise FilesystemMutationError(
            f"{label} access policy is outside this filesystem-only composer."
        )
    if (spec.arr_file_fid is None) != (spec.arr_record is None):
        raise FilesystemMutationError(
            f"{label} arr_file_fid and arr_record must be supplied together."
        )
    if spec.arr_file_fid is not None:
        _require_int(
            spec.arr_file_fid,
            label=f"{label} arr_file_fid",
            minimum=0,
            maximum=0xFFFF,
        )
        _require_int(
            spec.arr_record,
            label=f"{label} arr_record",
            minimum=1,
            maximum=0xFE,
        )
    if spec.lifecycle is not None:
        _require_int(
            spec.lifecycle,
            label=f"{label} lifecycle",
            minimum=0,
            maximum=0xFF,
        )
    if spec.sfi is not None:
        _require_int(spec.sfi, label=f"{label} sfi", minimum=1, maximum=30)
    if spec.df_name is not None:
        if not isinstance(spec.df_name, bytes):
            raise FilesystemMutationError(f"{label} df_name must be immutable bytes.")
        if len(spec.df_name) < 5 or len(spec.df_name) > 16:
            raise FilesystemMutationError(f"{label} df_name/AID must contain 5..16 bytes.")
    if spec.literal_content is not None and not isinstance(spec.literal_content, bytes):
        raise FilesystemMutationError(f"{label} literal_content must be immutable bytes.")
    if spec.mf_field_name is not None:
        if spec.mf_field_name not in _MANDATORY_MF_FIELDS:
            allowed = ", ".join(sorted(_MANDATORY_MF_FIELDS))
            raise FilesystemMutationError(f"{label} mf_field_name must be one of: {allowed}.")
        if spec.parent_fid_path != (MF_FID,) or spec.kind is not FilesystemNodeKind.EF:
            raise FilesystemMutationError(
                f"{label} mf_field_name is only valid for an EF directly below MF."
            )

    if spec.kind in {FilesystemNodeKind.ADF, FilesystemNodeKind.DF}:
        if spec.structure is not None:
            raise FilesystemMutationError(
                f"{label} directory nodes must not declare an EF structure."
            )
        if any(
            value is not None
            for value in (
                spec.file_size,
                spec.record_length,
                spec.record_count,
                spec.sfi,
                spec.literal_content,
            )
        ):
            raise FilesystemMutationError(
                f"{label} directory nodes must not declare EF geometry, SFI, or content."
            )
        return

    if spec.df_name is not None:
        raise FilesystemMutationError(f"{label} EF must not carry df_name/AID.")
    if not isinstance(spec.structure, ElementaryFileStructure):
        raise FilesystemMutationError(f"{label} EF requires an ElementaryFileStructure.")

    if spec.structure in {
        ElementaryFileStructure.TRANSPARENT,
        ElementaryFileStructure.BER_TLV,
    }:
        if spec.record_length is not None or spec.record_count is not None:
            raise FilesystemMutationError(
                f"{label} {spec.structure.value} EF must not declare record geometry."
            )
        if spec.file_size is None:
            raise FilesystemMutationError(f"{label} {spec.structure.value} EF requires file_size.")
        size = _require_int(
            spec.file_size,
            label=f"{label} file_size",
            minimum=1,
            maximum=0xFFFFFFFF,
        )
    else:
        if spec.record_length is None or spec.record_count is None:
            raise FilesystemMutationError(
                f"{label} {spec.structure.value} EF requires record_length and record_count."
            )
        record_length = _require_int(
            spec.record_length,
            label=f"{label} record_length",
            minimum=1,
            maximum=0xFFFF,
        )
        record_count = _require_int(
            spec.record_count,
            label=f"{label} record_count",
            minimum=1,
            maximum=0xFF,
        )
        size = record_length * record_count
        if spec.file_size is not None and spec.file_size != size:
            raise FilesystemMutationError(
                f"{label} file_size must equal record_length * record_count "
                f"({size}, got {spec.file_size})."
            )
    if spec.literal_content is not None and len(spec.literal_content) > size:
        raise FilesystemMutationError(
            f"{label} literal content is {len(spec.literal_content)} bytes, "
            f"larger than the declared {size}-byte file."
        )


def _validate_native_spec(spec: NativeFilesystemEntrySpec, *, index: int) -> None:
    label = f"native entry #{index}"
    if not isinstance(spec, NativeFilesystemEntrySpec):
        raise TypeError(f"{label} must be a NativeFilesystemEntrySpec.")
    if not isinstance(spec.menu_id, str) or not spec.menu_id.strip():
        raise FilesystemMutationError(f"{label} menu_id must be a non-empty string.")
    if spec.menu_id in _SKELETON_ONLY_FILESYSTEM_MENU_IDS:
        raise FilesystemMutationError(
            f"{label} menu_id {spec.menu_id!r} has no registry-backed filesystem "
            "template in vendored pySim; classify its files as GFM fallback."
        )
    if spec.menu_id not in _NATIVE_MENU_ORDER:
        allowed = ", ".join(_NATIVE_MENU_ORDER)
        raise FilesystemMutationError(
            f"{label} menu_id {spec.menu_id!r} is not a supported native filesystem PE; "
            f"expected one of: {allowed}."
        )
    if not isinstance(spec.pe_name, str) or not spec.pe_name.strip():
        raise FilesystemMutationError(f"{label} pe_name must be a non-empty string.")
    if not isinstance(spec.kind, FilesystemNodeKind):
        raise FilesystemMutationError(f"{label} kind must be a FilesystemNodeKind.")
    if spec.kind is FilesystemNodeKind.MF:
        if (spec.menu_id, spec.pe_name, spec.fid) != ("mf", "mf", MF_FID):
            raise FilesystemMutationError(
                f"{label} MF is valid only as menu_id='mf', pe_name='mf', fid=3F00."
            )
        if any(
            value is not None
            for value in (
                spec.structure,
                spec.file_size,
                spec.record_length,
                spec.record_count,
                spec.sfi,
                spec.df_name,
                spec.literal_content,
            )
        ):
            raise FilesystemMutationError(
                f"{label} MF must not declare EF geometry, SFI, DF name, or content."
            )
        if spec.lifecycle is not None:
            _require_int(
                spec.lifecycle,
                label=f"{label} lifecycle",
                minimum=0,
                maximum=0xFF,
            )
        if spec.arr_record is not None:
            _require_int(
                spec.arr_record,
                label=f"{label} arr_record",
                minimum=1,
                maximum=0xFF,
            )
        return
    if spec.fid is None:
        if spec.kind is not FilesystemNodeKind.ADF:
            raise FilesystemMutationError(f"{label} may omit fid only for a native ADF root.")
        if (spec.menu_id, spec.pe_name) not in _NATIVE_ADF_TEMPORARY_FIDS:
            raise FilesystemMutationError(
                f"{label} has no registered temporary ADF FID assignment."
            )
        validation_fid = _NATIVE_ADF_TEMPORARY_FIDS[(spec.menu_id, spec.pe_name)]
    else:
        if (
            spec.fid == 0x7FFF
            and (spec.menu_id, spec.pe_name) in _NATIVE_ADF_TEMPORARY_FIDS
            and spec.df_name is None
        ):
            raise FilesystemMutationError(
                f"{label} FID 7FFF has no concrete DF name/AID; use fid=None so the "
                "native temporary FID is inherited and recorded."
            )
        validation_fid = spec.fid
    if spec.arr_record is not None:
        _require_int(
            spec.arr_record,
            label=f"{label} arr_record",
            minimum=1,
            maximum=0xFF,
        )
    generic_spec = FilesystemEntrySpec(
        parent_fid_path=(MF_FID,),
        fid=validation_fid,
        kind=spec.kind,
        structure=spec.structure,
        file_size=spec.file_size,
        record_length=spec.record_length,
        record_count=spec.record_count,
        sfi=spec.sfi,
        df_name=spec.df_name,
        literal_content=spec.literal_content,
        lifecycle=spec.lifecycle,
    )
    _validate_spec(generic_spec, index=index)


def _validate_topology(
    specs: tuple[FilesystemEntrySpec, ...],
    *,
    allow_external_parents: bool = False,
) -> None:
    by_path: dict[tuple[int, ...], FilesystemEntrySpec] = {}
    for spec in specs:
        full_path = spec.fid_path
        if full_path in by_path:
            raise FilesystemMutationError(f"Duplicate filesystem path {_hex_path(full_path)}.")
        by_path[full_path] = spec

    for spec in specs:
        parent = spec.parent_fid_path
        if parent == (MF_FID,):
            continue
        parent_spec = by_path.get(parent)
        if parent_spec is None:
            if allow_external_parents:
                continue
            raise FilesystemMutationError(
                f"Filesystem parent {_hex_path(parent)} for "
                f"{_hex_path(spec.fid_path)} is not declared."
            )
        if parent_spec.kind not in {FilesystemNodeKind.ADF, FilesystemNodeKind.DF}:
            raise FilesystemMutationError(
                f"Filesystem parent {_hex_path(parent)} is not an ADF or DF."
            )


def _template_file_type(spec: FilesystemEntrySpec) -> str:
    if spec.kind is FilesystemNodeKind.MF:
        return "MF"
    if spec.kind is FilesystemNodeKind.ADF:
        return "ADF"
    if spec.kind is FilesystemNodeKind.DF:
        return "DF"
    assert spec.structure is not None
    return _STRUCTURE_TO_TEMPLATE_TYPE[spec.structure]


def _effective_file_size(spec: FilesystemEntrySpec) -> int | None:
    if spec.kind is not FilesystemNodeKind.EF:
        return None
    if spec.structure in {
        ElementaryFileStructure.LINEAR_FIXED,
        ElementaryFileStructure.CYCLIC,
    }:
        assert spec.record_length is not None
        assert spec.record_count is not None
        return spec.record_length * spec.record_count
    return spec.file_size


def _explicit_arr_reference(spec: FilesystemEntrySpec) -> bytes | None:
    """Return the caller-supplied long-form EF.ARR reference, if present."""

    if spec.arr_file_fid is None:
        return None
    assert spec.arr_record is not None
    return spec.arr_file_fid.to_bytes(2, "big") + bytes([spec.arr_record])


def _encoded_short_efid(sfi: int | None) -> bytes | None:
    """Encode one logical SFI as the SAIP ``shortEFID`` wire octet."""

    if sfi is None:
        return None
    logical_sfi = _require_int(sfi, label="sfi", minimum=1, maximum=30)
    return bytes([logical_sfi << 3])


def _descriptor_for_spec(
    spec: FilesystemEntrySpec,
    *,
    gfm_mode: bool,
) -> dict[str, Any]:
    full_path = spec.fid_path
    file_template = _FallbackFileTemplate(
        fid=spec.fid,
        name=(
            "MF"
            if spec.kind is FilesystemNodeKind.MF
            else (
                f"ADF.{spec.fid:04X}"
                if spec.kind is FilesystemNodeKind.ADF
                else (
                    f"DF.{spec.fid:04X}"
                    if spec.kind is FilesystemNodeKind.DF
                    else f"EF.{spec.fid:04X}"
                )
            )
        ),
        pe_name="file-" + "-".join(f"{part:04x}" for part in full_path),
        file_type=_template_file_type(spec),
        # 0xFF matches the quick-add helper's explicit-template sentinel and
        # therefore emits no securityAttributesReferenced field.
        arr=0xFF,
        sfi=spec.sfi,
        file_size=_effective_file_size(spec),
        rec_len=spec.record_length,
        nb_rec=spec.record_count,
        df_name=spec.df_name,
    )
    descriptor = _explicit_file_descriptor(file_template, gfm_mode=gfm_mode)
    # ``File.to_fileDescriptor()`` copies ``FileTemplate.sfi`` verbatim.  The
    # filesystem mutation specs deliberately carry the logical 1..30 value,
    # so perform the single logical-to-wire conversion at this boundary.  Do
    # not change the shared helper: its other callers can already use wire-form
    # values and shifting there would corrupt them.
    encoded_short_efid = _encoded_short_efid(spec.sfi)
    if encoded_short_efid is None:
        descriptor.pop("shortEFID", None)
    else:
        descriptor["shortEFID"] = encoded_short_efid
    # Defence in depth against future quick-add changes: omission is an
    # explicit unresolved-access contract and must never become a guessed ARR.
    descriptor.pop("securityAttributesReferenced", None)
    arr_reference = _explicit_arr_reference(spec)
    if arr_reference is not None:
        descriptor["securityAttributesReferenced"] = arr_reference
    if spec.lifecycle is None:
        descriptor.pop("lcsi", None)
    else:
        descriptor["lcsi"] = bytes([spec.lifecycle])
    # pySim's File.to_fileDescriptor() can expose absent ASN.1 OPTIONAL
    # members as explicit ``None`` values (notably pinStatusTemplateDO for
    # MF/DF/ADF descriptors).  ``None`` is not an ASN.1 value and strict
    # encoders reject it, so keep absence represented by an omitted mapping
    # member.  Do not synthesize a PIN status template here: access policy is
    # deliberately outside this filesystem-only materializer.
    return {key: value for key, value in descriptor.items() if value is not None}


def _file_choices(
    spec: FilesystemEntrySpec,
    *,
    gfm_mode: bool,
) -> list[tuple[str, Any]]:
    choices: list[tuple[str, Any]] = [
        (
            "createFCP" if gfm_mode else "fileDescriptor",
            _descriptor_for_spec(spec, gfm_mode=gfm_mode),
        )
    ]
    if spec.literal_content is not None:
        choices.append(("fillFileContent", spec.literal_content))
    return choices


def _native_choices_roundtrip_equal(
    actual_choices: Any,
    expected_choices: list[tuple[str, Any]],
) -> bool:
    """Compare native choices while accepting ASN.1's canonical LCSI default.

    An omitted optional ``lcsi`` is decoded by the vendored schema as its
    canonical default ``05``.  All other choice names and values remain exact.
    """

    if not isinstance(actual_choices, list) or len(actual_choices) != len(expected_choices):
        return False
    for actual, expected in zip(actual_choices, expected_choices):
        if not isinstance(actual, tuple) or len(actual) != 2:
            return False
        actual_choice, actual_value = actual
        expected_choice, expected_value = expected
        if actual_choice != expected_choice:
            return False
        if (
            expected_choice == "fileDescriptor"
            and isinstance(actual_value, dict)
            and isinstance(expected_value, dict)
        ):
            normalized_actual = dict(actual_value)
            if "lcsi" not in expected_value and normalized_actual.get("lcsi") == b"\x05":
                normalized_actual.pop("lcsi")
            if normalized_actual != expected_value:
                return False
        elif actual_value != expected_value:
            return False
    return True


def _native_menu_ids(specs: tuple[NativeFilesystemEntrySpec, ...]) -> tuple[str, ...]:
    requested = {"mf"}
    requested.update(spec.menu_id for spec in specs)
    pending = list(requested)
    while pending:
        menu_id = pending.pop()
        for dependency in _NATIVE_MENU_DEPENDENCIES.get(menu_id, ()):
            if dependency not in requested:
                requested.add(dependency)
                pending.append(dependency)
    return tuple(menu_id for menu_id in _NATIVE_MENU_ORDER if menu_id in requested)


def _native_spec_instances(
    specs: tuple[NativeFilesystemEntrySpec, ...],
) -> dict[str, tuple[tuple[NativeFilesystemEntrySpec, ...], ...]]:
    """Partition native fields into deterministic PE instances.

    The occurrence ordinal of a repeated ``pe_name`` selects its PE instance:
    every first occurrence shares instance 1, every second occurrence shares
    instance 2, and so on.  This keeps related phonebook slot ranges aligned
    without relying on workbook row or sheet names.  Exact duplicate
    field/FID specifications are rejected because they cannot represent two
    distinct filesystem nodes.
    """

    menu_rank = {menu_id: index for index, menu_id in enumerate(_NATIVE_MENU_ORDER)}
    ordered = sorted(
        specs,
        key=lambda spec: (
            menu_rank[spec.menu_id],
            spec.pe_name,
            -1 if spec.fid is None else spec.fid,
        ),
    )
    exact_fields: set[tuple[str, str, int | None]] = set()
    occurrences: dict[tuple[str, str], int] = {}
    instances: dict[str, list[list[NativeFilesystemEntrySpec]]] = {}
    for spec in ordered:
        exact_key = (spec.menu_id, spec.pe_name, spec.fid)
        if exact_key in exact_fields:
            fid_text = "inherited" if spec.fid is None else f"{spec.fid:04X}"
            raise FilesystemMutationError(
                "Duplicate native filesystem slot "
                f"{spec.menu_id}.{spec.pe_name}@{fid_text}."
            )
        exact_fields.add(exact_key)

        occurrence_key = (spec.menu_id, spec.pe_name)
        instance_index = occurrences.get(occurrence_key, 0)
        occurrences[occurrence_key] = instance_index + 1
        if instance_index and spec.menu_id not in _REPEATABLE_NATIVE_MENU_IDS:
            raise FilesystemMutationError(
                f"Duplicate native filesystem field {spec.menu_id}.{spec.pe_name}; "
                f"only {', '.join(sorted(_REPEATABLE_NATIVE_MENU_IDS))} "
                "supports repeated native PE instances."
            )
        menu_instances = instances.setdefault(spec.menu_id, [])
        while len(menu_instances) <= instance_index:
            menu_instances.append([])
        menu_instances[instance_index].append(spec)

    return {
        menu_id: tuple(tuple(instance) for instance in menu_instances)
        for menu_id, menu_instances in instances.items()
    }


def _native_scaffold_menu_ids(
    specs: tuple[NativeFilesystemEntrySpec, ...],
    instances: dict[str, tuple[tuple[NativeFilesystemEntrySpec, ...], ...]],
) -> tuple[str, ...]:
    """Return dependency-safe menu IDs including repeated native instances."""

    unique_menu_ids = _native_menu_ids(specs)
    return tuple(
        menu_id
        for menu_id in unique_menu_ids
        for _instance in range(max(1, len(instances.get(menu_id, ()))))
    )


def _native_section_keys(document: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """Index scaffold section keys by their base PE type, preserving order."""

    grouped: dict[str, list[str]] = {}
    sections = document.get("sections", {})
    if not isinstance(sections, dict):
        raise FilesystemMutationError("Native scaffold sections are malformed.")
    for section_key in sections:
        grouped.setdefault(base_pe_type(str(section_key)), []).append(str(section_key))
    return {menu_id: tuple(keys) for menu_id, keys in grouped.items()}


def _native_effective_fid(spec: NativeFilesystemEntrySpec) -> tuple[int, bool]:
    if spec.fid is not None:
        return (spec.fid, False)
    key = (spec.menu_id, spec.pe_name)
    try:
        return (_NATIVE_ADF_TEMPORARY_FIDS[key], True)
    except KeyError as error:
        raise FilesystemMutationError(
            f"Native field {spec.menu_id}.{spec.pe_name} has no temporary FID assignment."
        ) from error


def _native_as_generic_spec(
    spec: NativeFilesystemEntrySpec,
    *,
    effective_fid: int,
) -> FilesystemEntrySpec:
    return FilesystemEntrySpec(
        parent_fid_path=(MF_FID,),
        fid=effective_fid,
        kind=spec.kind,
        structure=spec.structure,
        file_size=spec.file_size,
        record_length=spec.record_length,
        record_count=spec.record_count,
        sfi=spec.sfi,
        df_name=spec.df_name,
        literal_content=spec.literal_content,
        lifecycle=spec.lifecycle,
    )


def _native_file_choices(
    spec: NativeFilesystemEntrySpec,
    *,
    effective_fid: int,
) -> list[tuple[str, Any]]:
    choices = _file_choices(
        _native_as_generic_spec(spec, effective_fid=effective_fid),
        gfm_mode=False,
    )
    descriptor = choices[0][1]
    if not isinstance(descriptor, dict):
        raise FilesystemMutationError(
            f"Native field {spec.menu_id}.{spec.pe_name} produced a malformed descriptor."
        )
    if spec.arr_record is None:
        descriptor.pop("securityAttributesReferenced", None)
    else:
        descriptor["securityAttributesReferenced"] = bytes([spec.arr_record])
    return choices


def _native_asn_file_field_names(menu_id: str) -> frozenset[str]:
    """Return actual file-bearing ASN.1 member names for one native PE."""

    from pySim.esim.saip import ProfileElement

    pe_class = ProfileElement.class_for_petype(menu_id)
    if pe_class is None:
        return frozenset()
    pe = pe_class()
    type_definition = getattr(pe, "tdef", None)
    members = list(getattr(type_definition, "root_members", ()) or ()) + list(
        getattr(type_definition, "additions", ()) or ()
    )
    return frozenset(
        str(getattr(member, "name", "") or "")
        for member in members
        if member.__class__.__name__ == "SequenceOf"
    )


def _native_template_target(
    document: dict[str, Any],
    workspace_root: Path,
    spec: NativeFilesystemEntrySpec,
    *,
    section_key: str | None = None,
) -> tuple[dict[str, Any], Any, Any]:
    ensure_workspace_pysim_on_path(workspace_root)
    from pySim.esim.saip.templates import ProfileTemplateRegistry

    resolved_section_key = str(section_key or spec.menu_id)
    section = document.get("sections", {}).get(resolved_section_key)
    if not isinstance(section, dict):
        raise FilesystemMutationError(
            f"Native scaffold did not produce PE section {resolved_section_key!r}."
        )
    template_id = section.get("templateID")
    if not isinstance(template_id, str) or not template_id:
        raise FilesystemMutationError(
            f"Native PE {spec.menu_id!r} does not expose a filesystem template."
        )
    template = ProfileTemplateRegistry.get_by_oid(template_id)
    if template is None:
        raise FilesystemMutationError(
            f"Native PE {spec.menu_id!r} template {template_id!r} is not registered."
        )
    files_by_pename = getattr(template, "files_by_pename", {})
    target = files_by_pename.get(spec.pe_name)
    alias_used = False
    if target is None:
        alias_name = _NATIVE_TEMPLATE_FIELD_ALIASES.get((spec.menu_id, spec.pe_name))
        if alias_name is not None:
            if spec.pe_name not in _native_asn_file_field_names(spec.menu_id):
                raise FilesystemMutationError(
                    f"Native compatibility field {spec.menu_id}.{spec.pe_name} "
                    "is not a file-bearing member in the current ASN.1 schema."
                )
            target = files_by_pename.get(alias_name)
            if target is None:
                raise FilesystemMutationError(
                    f"Native compatibility target {spec.menu_id}.{alias_name} is "
                    f"not present in template {template_id}."
                )
            target_fid = getattr(target, "fid", None)
            if spec.fid is None or target_fid != spec.fid:
                target_fid_text = (
                    f"{target_fid:04X}"
                    if isinstance(target_fid, int) and not isinstance(target_fid, bool)
                    else repr(target_fid)
                )
                raise FilesystemMutationError(
                    f"Native compatibility field {spec.menu_id}.{spec.pe_name} "
                    f"must use template FID {target_fid_text}."
                )
            alias_used = True
    if target is None and spec.pe_name in _native_asn_file_field_names(spec.menu_id):
        # Some GFSTE revisions expose an allocatable file slot under a
        # generic/template name while the ASN.1 PE has the standards-level
        # semantic member (for example EF.PBC).  Resolve only an unambiguous
        # same-FID/same-structure template slot and keep writing through the
        # requested ASN.1 member.  This is schema/FID driven and does not
        # depend on workbook labels.
        expected_type = (
            _STRUCTURE_TO_TEMPLATE_TYPE.get(spec.structure)
            if spec.kind is FilesystemNodeKind.EF
            else {
                FilesystemNodeKind.MF: "MF",
                FilesystemNodeKind.ADF: "ADF",
                FilesystemNodeKind.DF: "DF",
            }.get(spec.kind)
        )
        compatible_targets = [
            candidate
            for candidate in getattr(template, "files", ()) or ()
            if getattr(candidate, "fid", None) == spec.fid
            and str(getattr(candidate, "file_type", "") or "").upper()
            == expected_type
        ]
        if len(compatible_targets) == 1:
            target = compatible_targets[0]
            alias_used = True
    if target is None:
        raise FilesystemMutationError(
            f"Native field {spec.menu_id}.{spec.pe_name} is not present in template {template_id}."
        )

    template_type = str(getattr(target, "file_type", "") or "").upper()
    if spec.kind is FilesystemNodeKind.MF and template_type != "MF":
        raise FilesystemMutationError(
            f"Native field {spec.menu_id}.{spec.pe_name} is not an MF template field."
        )
    if spec.kind is FilesystemNodeKind.ADF and template_type != "ADF":
        raise FilesystemMutationError(
            f"Native field {spec.menu_id}.{spec.pe_name} is not an ADF template field."
        )
    if spec.kind is FilesystemNodeKind.DF and template_type != "DF":
        raise FilesystemMutationError(
            f"Native field {spec.menu_id}.{spec.pe_name} is not a DF template field."
        )
    if spec.kind is FilesystemNodeKind.EF and template_type not in {"TR", "LF", "CY", "BT"}:
        raise FilesystemMutationError(
            f"Native field {spec.menu_id}.{spec.pe_name} is not an EF template field."
        )
    if alias_used:
        assert spec.structure is not None
        expected_type = _STRUCTURE_TO_TEMPLATE_TYPE[spec.structure]
        if template_type != expected_type:
            raise FilesystemMutationError(
                f"Native compatibility field {spec.menu_id}.{spec.pe_name} has "
                f"structure {spec.structure.value}, but template FID {spec.fid:04X} "
                f"requires {template_type}."
            )
    return (section, template, target)


def _native_ancestor_templates(template: Any, target: Any) -> tuple[Any, ...]:
    boundary = None if getattr(template, "extends", None) is not None else template.base_df()
    ancestors: list[Any] = []
    current = getattr(target, "parent", None)
    while current is not None and current is not boundary:
        ancestors.append(current)
        current = getattr(current, "parent", None)
    ancestors.reverse()
    return tuple(ancestors)


def _reconciled_mf_specs(
    specs: tuple[FilesystemEntrySpec, ...],
) -> dict[str, FilesystemEntrySpec]:
    reconciled: dict[str, FilesystemEntrySpec] = {}
    for spec in specs:
        if spec.parent_fid_path != (MF_FID,):
            continue
        automatic_binding = _MANDATORY_MF_BINDINGS.get(spec.fid)
        field_name = spec.mf_field_name
        if field_name is None and automatic_binding is not None:
            field_name = automatic_binding[0]
        if field_name is None:
            continue

        expected_structure = next(
            structure
            for candidate_field, structure in _MANDATORY_MF_BINDINGS.values()
            if candidate_field == field_name
        )
        if spec.kind is not FilesystemNodeKind.EF or spec.structure is not expected_structure:
            raise FilesystemMutationError(
                f"Mandatory MF field {field_name} at FID {spec.fid:04X} must be an "
                f"{expected_structure.value} EF."
            )
        if field_name == "ef-iccid":
            if spec.file_size != 10:
                raise FilesystemMutationError(f"EF.ICCID ({spec.fid:04X}) must have file_size 10.")
            if spec.literal_content is not None and len(spec.literal_content) != 10:
                raise FilesystemMutationError(
                    f"EF.ICCID ({spec.fid:04X}) literal content must contain " "exactly 10 bytes."
                )
        prior = reconciled.get(field_name)
        if prior is not None:
            raise FilesystemMutationError(
                f"Mandatory MF field {field_name} is bound more than once "
                f"({prior.fid:04X} and {spec.fid:04X})."
            )
        reconciled[field_name] = spec
    return reconciled


def _group_gfm_specs(
    specs: tuple[FilesystemEntrySpec, ...],
    *,
    reconciled_paths: frozenset[tuple[int, ...]],
) -> tuple[tuple[tuple[int, ...], tuple[FilesystemEntrySpec, ...]], ...]:
    grouped: dict[tuple[int, ...], list[FilesystemEntrySpec]] = {}
    for spec in specs:
        if spec.fid_path in reconciled_paths:
            continue
        grouped.setdefault(spec.parent_fid_path, []).append(spec)

    out: list[tuple[tuple[int, ...], tuple[FilesystemEntrySpec, ...]]] = []
    for parent_path in sorted(grouped, key=lambda path: (len(path), path)):
        children = tuple(sorted(grouped[parent_path], key=lambda item: item.fid))
        out.append((parent_path, children))
    return tuple(out)


def _gfm_transaction(
    parent_path: tuple[int, ...],
    children: tuple[FilesystemEntrySpec, ...],
) -> list[tuple[str, Any]]:
    relative_parent = parent_path[1:]
    transaction: list[tuple[str, Any]] = [
        (
            "filePath",
            b"".join(part.to_bytes(2, "big") for part in relative_parent),
        )
    ]
    for child in children:
        transaction.extend(_file_choices(child, gfm_mode=True))
    return transaction


def _roundtrip_validate(
    document: dict[str, Any],
    *,
    workspace_root: Path,
    expected_gfm_specs: tuple[FilesystemEntrySpec, ...],
    reconciled_specs: tuple[tuple[str, FilesystemEntrySpec], ...],
    expected_native_fields: tuple[
        tuple[str, str, str, list[tuple[str, Any]]], ...
    ] = (),
) -> int:
    try:
        sequence = build_profile_sequence_from_document(document, workspace_root)
        encoded = sequence.to_der()
    except Exception as error:
        detail = str(error).strip() or error.__class__.__name__
        raise FilesystemMutationError(
            f"Filesystem document could not be encoded after materialization: {detail}"
        ) from error
    if not encoded:
        raise FilesystemMutationError("Filesystem document encoded to an empty DER package.")

    ensure_workspace_pysim_on_path(workspace_root)
    from pySim.esim.saip import ProfileElementSequence

    try:
        decoded = ProfileElementSequence.from_der(encoded)
    except Exception as error:
        detail = str(error).strip() or error.__class__.__name__
        raise FilesystemMutationError(
            f"Filesystem DER could not be decoded after materialization: {detail}"
        ) from error

    expected_types = [base_pe_type(key) for key in document["sections"]]
    decoded_types = [str(getattr(pe, "type", "")) for pe in decoded.pe_list]
    if decoded_types != expected_types:
        raise FilesystemMutationError(
            "Filesystem DER changed PE ordering during round-trip validation."
        )

    expected_arr_by_path = {
        _hex_path(spec.fid_path): _explicit_arr_reference(spec) for spec in expected_gfm_specs
    }
    expected_paths = set(expected_arr_by_path)
    decoded_paths: set[str] = set()
    for pe in decoded.get_pes_for_type("genericFileManagement"):
        files = getattr(pe, "files", None)
        if isinstance(files, dict):
            decoded_paths.update(str(path) for path in files)
            for path, file_obj in files.items():
                normalized_path = str(path)
                if normalized_path not in expected_arr_by_path:
                    continue
                expected_arr = expected_arr_by_path[normalized_path]
                actual_arr = getattr(file_obj, "arr", None)
                if actual_arr != expected_arr:
                    raise FilesystemMutationError(
                        "GFM securityAttributesReferenced changed for "
                        f"{normalized_path}; expected={expected_arr!r}, "
                        f"actual={actual_arr!r}."
                    )
    if decoded_paths != expected_paths:
        missing = sorted(expected_paths - decoded_paths)
        extra = sorted(decoded_paths - expected_paths)
        raise FilesystemMutationError(
            f"Filesystem GFM round-trip path mismatch; missing={missing}, extra={extra}."
        )

    mf_pes = decoded.get_pes_for_type("mf")
    if len(mf_pes) != 1:
        raise FilesystemMutationError("Filesystem document must contain exactly one PE-MF.")
    mf_decoded = getattr(mf_pes[0], "decoded", {})
    for field_name, spec in reconciled_specs:
        choices = mf_decoded.get(field_name)
        if not isinstance(choices, list):
            raise FilesystemMutationError(
                f"Reconciled MF field {field_name!r} disappeared during DER validation."
            )
        descriptor = next(
            (
                value
                for choice, value in choices
                if choice == "fileDescriptor" and isinstance(value, dict)
            ),
            None,
        )
        if descriptor is None or descriptor.get("fileID") != spec.fid.to_bytes(2, "big"):
            raise FilesystemMutationError(
                f"Reconciled MF field {field_name!r} did not preserve FID {spec.fid:04X}."
            )
        expected_arr = _explicit_arr_reference(spec)
        actual_arr = descriptor.get("securityAttributesReferenced")
        if actual_arr != expected_arr:
            raise FilesystemMutationError(
                f"Reconciled MF field {field_name!r} changed its explicit "
                "securityAttributesReferenced value."
            )

    decoded_by_section = dict(zip(document["sections"], decoded.pe_list))
    for section_key, menu_id, pe_name, expected_choices in expected_native_fields:
        native_pe = decoded_by_section.get(section_key)
        if native_pe is None or str(getattr(native_pe, "type", "")) != menu_id:
            raise FilesystemMutationError(
                f"Native round-trip lost PE section {section_key!r} ({menu_id})."
            )
        actual_choices = getattr(native_pe, "decoded", {}).get(pe_name)
        if not _native_choices_roundtrip_equal(actual_choices, expected_choices):
            raise FilesystemMutationError(
                f"Native field {section_key}.{pe_name} changed during DER validation."
            )
    return len(encoded)


def materialize_filesystem_document(
    entries: Iterable[FilesystemEntrySpec],
    workspace_root: Path,
    *,
    intro_lines: Iterable[str] | None = None,
) -> FilesystemMaterializationResult:
    """Build a deterministic decoded SAIP document from arbitrary entries.

    The returned document has the PE order ``header, mf, gfm*, end``.  GFM
    contexts are sorted by path depth and then numeric path, ensuring every
    directory is created before a later PE selects it.  Children inside a
    context are sorted by FID.
    """

    specs = tuple(entries)
    for index, spec in enumerate(specs):
        _validate_spec(spec, index=index)
    _validate_topology(specs)

    reconciled = _reconciled_mf_specs(specs)
    reconciled_paths = frozenset(spec.fid_path for spec in reconciled.values())
    grouped = _group_gfm_specs(specs, reconciled_paths=reconciled_paths)
    menu_ids = (
        "header",
        "mf",
        *("genericFileManagement" for _item in grouped),
        "end",
    )
    root = Path(workspace_root)
    document = build_scaffold_profile_document_from_menu_ids(
        "DYNAMIC-FILESYSTEM",
        menu_ids,
        root,
    )
    if intro_lines is None:
        document["intro"] = [
            "Dynamically materialized filesystem authoring document.",
            "Filesystem access policy remains unresolved.",
        ]
    else:
        document["intro"] = [str(line) for line in intro_lines]

    mf_section = document["sections"].get("mf")
    if not isinstance(mf_section, dict):
        raise FilesystemMutationError("Scaffold did not produce a PE-MF section.")
    for field_name in sorted(reconciled):
        mf_section[field_name] = _file_choices(
            reconciled[field_name],
            gfm_mode=False,
        )

    gfm_keys = [
        key for key in document["sections"] if base_pe_type(str(key)) == "genericFileManagement"
    ]
    if len(gfm_keys) != len(grouped):
        raise FilesystemMutationError("Scaffold produced an unexpected number of PE-GFM sections.")
    gfm_specs: list[FilesystemEntrySpec] = []
    for section_key, (parent_path, children) in zip(gfm_keys, grouped):
        section = document["sections"].get(section_key)
        if not isinstance(section, dict):
            raise FilesystemMutationError(f"Scaffold section {section_key!r} is malformed.")
        section["fileManagementCMD"] = [_gfm_transaction(parent_path, children)]
        gfm_specs.extend(children)

    der_size = _roundtrip_validate(
        document,
        workspace_root=root,
        expected_gfm_specs=tuple(gfm_specs),
        reconciled_specs=tuple(sorted(reconciled.items())),
    )
    summary = FilesystemMaterializationSummary(
        entry_count=len(specs),
        reconciled_mf_fids=tuple(sorted(spec.fid for spec in reconciled.values())),
        gfm_parent_paths=tuple(parent for parent, _children in grouped),
        der_byte_count=der_size,
        fallback_entry_count=len(specs),
    )
    return FilesystemMaterializationResult(document=document, summary=summary)


def materialize_native_filesystem_document(
    native_entries: Iterable[NativeFilesystemEntrySpec],
    workspace_root: Path,
    *,
    fallback_entries: Iterable[FilesystemEntrySpec] = (),
    intro_lines: Iterable[str] | None = None,
) -> FilesystemMaterializationResult:
    """Build a native-template-first SAIP filesystem authoring document.

    Native filesystem PEs are scaffolded once per required field instance.
    Supplied native files are placed in their registered template fields, with
    missing template ancestors added before their descendants.  Repeated
    allocatable PE-PHONEBOOK slots are partitioned into multiple native
    PE-PHONEBOOK instances.  Only entries supplied through
    ``fallback_entries`` are eligible for PE-GFM representation.
    ``NATIVE_TEMPLATE_MENU_IDS`` is the authoritative registry-backed planner
    allowlist; factory skeletons without real templates must remain fallback.
    """

    native_specs = tuple(native_entries)
    for index, spec in enumerate(native_specs):
        _validate_native_spec(spec, index=index)
    native_instances = _native_spec_instances(native_specs)

    fallback_specs = tuple(fallback_entries)
    for index, spec in enumerate(fallback_specs):
        _validate_spec(spec, index=index)
    _validate_topology(fallback_specs, allow_external_parents=True)

    reconciled_fallback = _reconciled_mf_specs(fallback_specs)
    native_mf_fields = {
        spec.pe_name
        for spec in native_specs
        if spec.menu_id == "mf" and spec.pe_name in _MANDATORY_MF_FIELDS
    }
    conflicting_mf_fields = native_mf_fields.intersection(reconciled_fallback)
    if conflicting_mf_fields:
        names = ", ".join(sorted(conflicting_mf_fields))
        raise FilesystemMutationError(
            f"Mandatory MF fields cannot be both native and fallback entries: {names}."
        )

    reconciled_paths = frozenset(spec.fid_path for spec in reconciled_fallback.values())
    grouped_fallback = _group_gfm_specs(
        fallback_specs,
        reconciled_paths=reconciled_paths,
    )
    native_menu_ids = _native_menu_ids(native_specs)
    native_menu_instances = _native_scaffold_menu_ids(
        native_specs,
        native_instances,
    )
    menu_ids = (
        "header",
        *native_menu_instances,
        *("genericFileManagement" for _item in grouped_fallback),
        "end",
    )
    root = Path(workspace_root)
    try:
        document = build_scaffold_profile_document_from_menu_ids(
            "NATIVE-DYNAMIC-FILESYSTEM",
            menu_ids,
            root,
        )
    except Exception as error:
        detail = str(error).strip() or error.__class__.__name__
        raise FilesystemMutationError(
            f"Could not scaffold native filesystem profile elements: {detail}"
        ) from error

    if intro_lines is None:
        document["intro"] = [
            "Dynamically materialized native-template filesystem document.",
            "Unmatched filesystem entries use explicit GFM fallback only.",
        ]
    else:
        document["intro"] = [str(line) for line in intro_lines]

    menu_rank = {menu_id: index for index, menu_id in enumerate(_NATIVE_MENU_ORDER)}
    section_keys = _native_section_keys(document)
    assigned_native_specs: list[tuple[str, NativeFilesystemEntrySpec]] = []
    for menu_id in native_menu_ids:
        instances = native_instances.get(menu_id, ())
        keys = section_keys.get(menu_id, ())
        if len(keys) != max(1, len(instances)):
            raise FilesystemMutationError(
                f"Native scaffold produced {len(keys)} {menu_id!r} section(s), "
                f"expected {max(1, len(instances))}."
            )
        for instance_index, instance_specs in enumerate(instances):
            assigned_native_specs.extend(
                (keys[instance_index], spec) for spec in instance_specs
            )
    expected_native_fields: dict[
        tuple[str, str, str],
        list[tuple[str, Any]],
    ] = {}
    inherited_assignments: dict[
        tuple[str, str],
        NativeTemporaryFidAssignment,
    ] = {}
    native_reconciled_mf_fids: set[int] = set()

    for section_key, spec in assigned_native_specs:
        section, template, target = _native_template_target(
            document,
            root,
            spec,
            section_key=section_key,
        )
        for ancestor in _native_ancestor_templates(template, target):
            ancestor_name = str(getattr(ancestor, "pe_name", "") or "").strip()
            if not ancestor_name or section.get(ancestor_name):
                continue
            # Scaffold documents represent unselected native template fields
            # as empty lists.  A selected child must carry every missing DF
            # ancestor as a real descriptor; relying on pySim's in-memory
            # filesystem cache makes the same document succeed or fail based
            # on which PE happened to be decoded earlier in the process.
            ancestor_descriptor = {
                key: value
                for key, value in _explicit_file_descriptor(
                    ancestor,
                    gfm_mode=False,
                ).items()
                if value is not None
            }
            ancestor_choices = [("fileDescriptor", ancestor_descriptor)]
            section[ancestor_name] = ancestor_choices
            expected_native_fields.setdefault(
                (section_key, spec.menu_id, ancestor_name),
                ancestor_choices,
            )
        effective_fid, inherited = _native_effective_fid(spec)
        choices = _native_file_choices(spec, effective_fid=effective_fid)
        section[spec.pe_name] = choices
        expected_native_fields[(section_key, spec.menu_id, spec.pe_name)] = choices
        if inherited:
            inherited_assignments[(spec.menu_id, spec.pe_name)] = NativeTemporaryFidAssignment(
                menu_id=spec.menu_id,
                pe_name=spec.pe_name,
                fid=effective_fid,
            )
        if spec.menu_id == "mf" and spec.pe_name in _MANDATORY_MF_FIELDS:
            native_reconciled_mf_fids.add(effective_fid)

    # Child PEs such as PE-PHONEBOOK require a concrete native ADF node even
    # when the source did not supply an ADF row.  Bootstrap only the root
    # descriptor and record the inherited temporary FID as explicit evidence.
    for menu_id, pe_name in _NATIVE_ADF_ROOTS.items():
        if menu_id not in native_menu_ids:
            continue
        root_section_key = section_keys[menu_id][0]
        field_key = (root_section_key, menu_id, pe_name)
        if field_key in expected_native_fields:
            continue
        bootstrap_spec = NativeFilesystemEntrySpec(
            menu_id=menu_id,
            pe_name=pe_name,
            fid=None,
            kind=FilesystemNodeKind.ADF,
        )
        section, _template, _target = _native_template_target(
            document,
            root,
            bootstrap_spec,
            section_key=root_section_key,
        )
        effective_fid, _inherited = _native_effective_fid(bootstrap_spec)
        choices = _native_file_choices(
            bootstrap_spec,
            effective_fid=effective_fid,
        )
        section[pe_name] = choices
        expected_native_fields[field_key] = choices
        inherited_assignments[(menu_id, pe_name)] = NativeTemporaryFidAssignment(
            menu_id=menu_id,
            pe_name=pe_name,
            fid=effective_fid,
        )

    mf_section = document.get("sections", {}).get("mf")
    if not isinstance(mf_section, dict):
        raise FilesystemMutationError("Native scaffold did not produce a PE-MF section.")
    for field_name in sorted(reconciled_fallback):
        mf_section[field_name] = _file_choices(
            reconciled_fallback[field_name],
            gfm_mode=False,
        )

    gfm_keys = [
        key for key in document["sections"] if base_pe_type(str(key)) == "genericFileManagement"
    ]
    if len(gfm_keys) != len(grouped_fallback):
        raise FilesystemMutationError(
            "Native scaffold produced an unexpected number of PE-GFM sections."
        )
    gfm_specs: list[FilesystemEntrySpec] = []
    for section_key, (parent_path, children) in zip(gfm_keys, grouped_fallback):
        section = document["sections"].get(section_key)
        if not isinstance(section, dict):
            raise FilesystemMutationError(f"Native scaffold section {section_key!r} is malformed.")
        section["fileManagementCMD"] = [_gfm_transaction(parent_path, children)]
        gfm_specs.extend(children)

    expected_native_rows = tuple(
        (section_key, menu_id, pe_name, choices)
        for (section_key, menu_id, pe_name), choices in sorted(
            expected_native_fields.items(),
            key=lambda item: (
                menu_rank[item[0][1]],
                section_keys[item[0][1]].index(item[0][0]),
                item[0][2],
            ),
        )
    )
    der_size = _roundtrip_validate(
        document,
        workspace_root=root,
        expected_gfm_specs=tuple(gfm_specs),
        reconciled_specs=tuple(sorted(reconciled_fallback.items())),
        expected_native_fields=expected_native_rows,
    )
    all_reconciled_fids = native_reconciled_mf_fids.union(
        spec.fid for spec in reconciled_fallback.values()
    )
    summary = FilesystemMaterializationSummary(
        entry_count=len(native_specs) + len(fallback_specs),
        reconciled_mf_fids=tuple(sorted(all_reconciled_fids)),
        gfm_parent_paths=tuple(parent for parent, _children in grouped_fallback),
        der_byte_count=der_size,
        native_menu_ids=native_menu_ids,
        native_menu_instances=native_menu_instances,
        native_entry_count=len(native_specs),
        fallback_entry_count=len(fallback_specs),
        inherited_temporary_fids=tuple(
            assignment
            for _key, assignment in sorted(
                inherited_assignments.items(),
                key=lambda item: (menu_rank[item[0][0]], item[0][1]),
            )
        ),
    )
    return FilesystemMaterializationResult(document=document, summary=summary)


__all__ = [
    "ElementaryFileStructure",
    "FilesystemAccessPolicy",
    "FilesystemEntrySpec",
    "FilesystemMaterializationResult",
    "FilesystemMaterializationSummary",
    "FilesystemMutationError",
    "FilesystemNodeKind",
    "MF_FID",
    "NATIVE_TEMPLATE_MENU_IDS",
    "NativeFilesystemEntrySpec",
    "NativeTemporaryFidAssignment",
    "materialize_filesystem_document",
    "materialize_native_filesystem_document",
    "native_temporary_fid",
]
