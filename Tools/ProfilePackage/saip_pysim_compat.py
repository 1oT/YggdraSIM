# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Narrow runtime compatibility fixes for the upstream pySim SAIP model.

The fixes in this module are installed on the imported runtime classes only;
YggdraSIM never modifies a vendored checkout or files in ``site-packages``.
Each installer is idempotent and deliberately preserves upstream behaviour
outside the field(s) named in its docstring.
"""

from __future__ import annotations

import copy
from collections import defaultdict, deque
from functools import wraps
from typing import Any

_SD_PASSTHROUGH_FIELDS = ("keyAccess", "keyCounterValue")
_SD_PATCH_MARKER = "_yggdrasim_lossless_sd_key_fields"
_BASE_DF_PATH_PATCH_MARKER = "_yggdrasim_base_df_path_compatibility"


def _key_identity(entry: Any) -> tuple[bytes, bytes] | None:
    """Return the stable SAIP key identity (KVN, KID), if available."""
    if not isinstance(entry, dict):
        return None
    version = entry.get("keyVersionNumber")
    identifier = entry.get("keyIdentifier")
    if not isinstance(version, (bytes, bytearray, memoryview)):
        return None
    if not isinstance(identifier, (bytes, bytearray, memoryview)):
        return None
    return bytes(version), bytes(identifier)


def _preserved_key_fields(key_list: Any) -> list[dict[str, Any]]:
    """Snapshot only fields that pySim's SecurityDomainKey cannot represent."""
    if not isinstance(key_list, list):
        return []
    snapshots: list[dict[str, Any]] = []
    for entry in key_list:
        snapshot: dict[str, Any] = {}
        if isinstance(entry, dict):
            for field_name in _SD_PASSTHROUGH_FIELDS:
                if field_name in entry:
                    snapshot[field_name] = copy.deepcopy(entry[field_name])
        snapshots.append(snapshot)
    return snapshots


def _restore_omitted_key_fields(
    original_key_list: Any,
    rebuilt_key_list: Any,
) -> None:
    """Merge fields omitted by the current upstream key serializer in-place.

    Identity matching keeps fields attached to their KVN/KID when keys are
    reordered. A positional fallback covers callers that edit the key identity
    through pySim's object model between decode and encode. If a future pySim
    release starts emitting either field itself, its emitted value wins.
    """
    if not isinstance(original_key_list, list):
        return
    if not isinstance(rebuilt_key_list, list):
        return

    snapshots = _preserved_key_fields(original_key_list)
    by_identity: dict[tuple[bytes, bytes], deque[int]] = defaultdict(deque)
    for index, entry in enumerate(original_key_list):
        identity = _key_identity(entry)
        if identity is not None:
            by_identity[identity].append(index)

    used_indexes: set[int] = set()
    for rebuilt_index, rebuilt_entry in enumerate(rebuilt_key_list):
        if not isinstance(rebuilt_entry, dict):
            continue

        source_index: int | None = None
        identity = _key_identity(rebuilt_entry)
        if identity is not None:
            candidates = by_identity.get(identity)
            while candidates:
                candidate = candidates.popleft()
                if candidate not in used_indexes:
                    source_index = candidate
                    break
        if source_index is None and rebuilt_index < len(snapshots):
            if rebuilt_index not in used_indexes:
                source_index = rebuilt_index
        if source_index is None:
            continue

        used_indexes.add(source_index)
        for field_name, field_value in snapshots[source_index].items():
            rebuilt_entry.setdefault(field_name, field_value)


def install_lossless_security_domain_encoding() -> bool:
    """Preserve explicit SD key access and counter fields across ``to_der``.

    pySim's ``ProfileElementSD._pre_encode`` reconstructs every ``keyList``
    entry through ``SecurityDomainKey.to_saip_dict``. The latter currently has
    no representation for the optional ASN.1 fields ``keyAccess`` and
    ``keyCounterValue``, so a decode/re-encode silently removes them. Wrap the
    pre-encoder and restore only fields it omitted.

    Returns ``True`` when this call installed the wrapper and ``False`` when an
    equivalent wrapper was already active.
    """
    from pySim.esim.saip import ProfileElementSD

    current = ProfileElementSD._pre_encode
    if getattr(current, _SD_PATCH_MARKER, False):
        return False

    @wraps(current)
    def _lossless_pre_encode(self: Any) -> None:
        decoded = getattr(self, "decoded", None)
        original_key_list = (
            copy.deepcopy(decoded.get("keyList")) if isinstance(decoded, dict) else None
        )
        current(self)
        rebuilt = getattr(self, "decoded", None)
        if isinstance(rebuilt, dict):
            _restore_omitted_key_fields(original_key_list, rebuilt.get("keyList"))

    setattr(_lossless_pre_encode, _SD_PATCH_MARKER, True)
    ProfileElementSD._pre_encode = _lossless_pre_encode
    return True


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
    from pySim.esim.saip.templates import ProfileTemplateRegistry

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
