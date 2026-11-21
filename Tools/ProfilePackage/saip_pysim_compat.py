# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Narrow runtime compatibility fixes for the upstream pySim SAIP model.

The fixes in this module are installed on the imported runtime classes only;
YggdraSIM never modifies a vendored checkout or files in ``site-packages``.
Each installer is idempotent and deliberately preserves upstream behaviour
outside the field(s) named in its docstring. The defects documented in
``upstream_patches/osmocom-pysim-saip-*`` are fixed in the pinned pySim
(hampushellsberg-dev/pysim) instead. :func:`file_creation_content` gives the
content the eUICC creates a file with, the baseline a body edit encodes
against.
"""

from __future__ import annotations

import copy
from functools import wraps
from typing import Any

_BASE_DF_PATH_PATCH_MARKER = "_yggdrasim_base_df_path_compatibility"


# TCA SAIP §9.10 -- an EF slot the profile never writes reads back as
# "FF...FF", and §9.10.3.3 shows a fillFileOffset gap carrying the
# file's fill pattern rather than a value of its own.
_ERASED_STATE_BYTE = 0xFF


def install_base_df_path_compatibility() -> bool:
    """Avoid re-selecting a native PE's base DF below that same base DF.

    Some upstream pySim versions start a non-extending filesystem PE at its
    template base DF and then iterate the selected file template's full
    ``ppath``.  Templates such as PE-PHONEBOOK include DF.PHONEBOOK as the
    first path component, so those versions try to select 5F3A *under* 5F3A
    and fail with ``KeyError``.  Newer pySim versions tolerate this implicit
    path, but profiles must not depend on which version was imported first.

    The wrapper shallow-copies only the affected File instance's template and
    removes exactly one redundant leading base-DF component.  Registered
    templates and every unrelated path remain unchanged.
    """

    from pySim.esim.saip import FsProfileElement

    from yggdrasim_common.pysim_saip_import import import_saip_templates

    ProfileTemplateRegistry = import_saip_templates().ProfileTemplateRegistry
    current = FsProfileElement.add_file
    if getattr(current, _BASE_DF_PATH_PATCH_MARKER, False):
        return False

    @wraps(current)
    def _base_df_path_compatible_add_file(self: Any, file: Any) -> Any:
        profile_template = ProfileTemplateRegistry.get_by_oid(getattr(self, "templateID", None))
        file_template = getattr(file, "template", None)
        if profile_template is not None and file_template is not None:
            base_df = profile_template.base_df()
            parent_path = list(getattr(file_template, "ppath", ()) or ())
            if (
                not getattr(profile_template, "extends", None)
                and base_df is not None
                and getattr(file, "pe_name", None) != getattr(base_df, "pe_name", None)
                and parent_path
                and parent_path[0] == getattr(base_df, "fid", None)
            ):
                normalized_template = copy.copy(file_template)
                normalized_template.ppath = parent_path[1:]
                file.template = normalized_template
        return current(self, file)

    setattr(
        _base_df_path_compatible_add_file,
        _BASE_DF_PATH_PATCH_MARKER,
        True,
    )
    FsProfileElement.add_file = _base_df_path_compatible_add_file
    return True


def file_creation_content(file_obj: Any, length: int) -> bytes:
    """What the eUICC holds in a file before any ``fillFileContent`` lands.

    The Fcp pattern when one is declared, otherwise the template default, each
    expanded per record for a record oriented file the way pySim's
    ``File.file_content_from_tuples`` lays them out, and the erased state
    beyond.
    """
    image = bytearray()
    if file_obj.fill_pattern:
        image += file_obj.expand_fill_pattern()
    elif file_obj.template and file_obj.template.default_val:
        image += file_obj.template.expand_default_value_pattern(file_obj.file_size) or b""
    if len(image) < length:
        image += bytes([_ERASED_STATE_BYTE]) * (length - len(image))
    return bytes(image[:length])


class PinnedPySimFixesMissing(RuntimeError):
    """The imported pySim lacks SAIP fixes YggdraSIM no longer compensates for."""


# First FID of the EF.ADN range and the EF.ICCID FID, as the fixed pySim
# templates list them (``FilesUsimDfPhonebook``, ``FilesAtMF``; pySim's own
# ``EF_ICCID`` uses 2FE2 too).
_PHONEBOOK_ADN_RANGE_START = 0x4F58
_EF_ICCID_FID = 0x2FE2
# TCA SAIP V3.4.1 §8.3.2 ``File``: ``fillFileOffset UInt16``.
_FILL_FILE_OFFSET_MAX = 0xFFFF
# rfu2, a PE-Dummy (an empty SEQUENCE) in pySim's SAIP v3.3.1 module and in
# TCA SAIP V3.4.1 (page 16), which turned rfu1 into ssimEapTLSParameters.
_RFU_PE_DER = bytes.fromhex("ac00")
# A probe raising one of these met a pySim whose API differs from the pinned one.
_PROBE_ERRORS = (AttributeError, KeyError, TypeError, ValueError)


def _security_domain_keys_keep_access_and_counter() -> bool:
    """TCA SAIP V3.4.1 §8.6.3: ``keyAccess`` DEFAULT '00', ``keyCounterValue`` OPTIONAL."""
    from pySim.esim.saip import SecurityDomainKey

    key = {
        "keyUsageQualifier": b"\x38",
        "keyAccess": b"\x01",
        "keyIdentifier": b"\x01",
        "keyVersionNumber": b"\x03",
        "keyCounterValue": b"\x00" * 5,
        "keyComponents": [{"keyType": b"\x88", "keyData": bytes(16), "macLength": 8}],
    }
    try:
        rebuilt = SecurityDomainKey.from_saip_dict(key).to_saip_dict()
    except _PROBE_ERRORS:
        return False
    return rebuilt.get("keyAccess") == b"\x01" and rebuilt.get("keyCounterValue") == b"\x00" * 5


def _fill_file_offsets_fit_uint16() -> bool:
    """One byte changed at offset 66000 of a 70000-byte transparent file."""
    from pySim.esim.saip import File

    fcp = {"fileDescriptor": b"\x41\x21", "efFileSize": (70000).to_bytes(3, "big")}
    body = bytearray(b"\xff" * 70000)
    body[66000] = 0x01
    try:
        probe = File("probe", [("fileDescriptor", fcp)], None)
        probe.body = bytes(body)
        tuples = probe.file_content_to_tuples(optimize=True)
    except _PROBE_ERRORS:
        return False
    offsets = [value for key, value in tuples if key == "fillFileOffset"]
    return bool(offsets) and max(offsets) <= _FILL_FILE_OFFSET_MAX


def _rfu_pe_loads() -> bool:
    from pySim.esim.saip import ProfileElement

    try:
        return ProfileElement.from_der(_RFU_PE_DER).type == "rfu2"
    except _PROBE_ERRORS:
        return False


def require_pinned_pysim_fixes() -> None:
    """Refuse a pySim without the fixes of the pinned hampushellsberg-dev/pysim.

    The defects in ``upstream_patches/osmocom-pysim-*`` are fixed in the
    pinned pySim, and YggdraSIM no longer works around them. A pySim from
    elsewhere -- an older checkout under ``pysim/``, a stock upstream
    install -- decodes and encodes such profiles wrongly, so eight of the
    fixes are checked by their effect and the missing ones named in
    :class:`PinnedPySimFixesMissing`.
    """
    import pySim
    from pySim.esim.saip import ProfileElement, templates
    from pySim.ts_102_221 import LifeCycleStatusInteger

    missing: list[str] = []
    if ProfileElement.class_for_petype("iot") is None:
        missing.append("osmocom-pysim-saip-extra-profile-elements")
    phonebook = templates.FilesUsimDfPhonebook.files_by_pename
    if "ef-pbc" not in phonebook:
        missing.append("osmocom-pysim-saip-implicit-template-ppath (EF.PBC rows)")
    adn = phonebook.get("ef-adn")
    if adn is None or adn.fid != _PHONEBOOK_ADN_RANGE_START:
        missing.append("osmocom-pysim-saip-template-range-fid")
    iccid = templates.FilesAtMF.files_by_pename.get("ef-iccid")
    if iccid is None or iccid.fid != _EF_ICCID_FID:
        missing.append("osmocom-pysim-saip-implicit-template-ppath (EF.ICCID FID)")
    lcsi = LifeCycleStatusInteger()
    lcsi.from_tlv(bytes.fromhex("8a010c"))
    if lcsi.decoded != "termination":
        missing.append("osmocom-pysim-lcsi-termination")
    if not _security_domain_keys_keep_access_and_counter():
        missing.append("osmocom-pysim-saip-sd-key-access-counter")
    if not _fill_file_offsets_fit_uint16():
        missing.append("osmocom-pysim-saip-optimised-body-encoding (fillFileOffset beyond UInt16)")
    if not _rfu_pe_loads():
        missing.append("osmocom-pysim-saip-empty-pe-body")
    if missing:
        raise PinnedPySimFixesMissing(
            f"the pySim imported from {getattr(pySim, '__file__', '?')} lacks the fixes of "
            f"{', '.join(missing)}; install the pySim pyproject.toml pins "
            "(hampushellsberg-dev/pysim) and remove an older pysim/ checkout."
        )
