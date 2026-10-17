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
_ERASED_FILL_PATCH_MARKER = "_yggdrasim_erased_state_file_fill"
_RECORD_FILL_PATCH_MARKER = "_yggdrasim_record_aware_fill_pattern"
_GFM_MF_PATCH_MARKER = "_yggdrasim_gfm_mf_creation"
_GFM_MF_CD_PATCH_MARKER = "_yggdrasim_gfm_mf_creation_cd"
# ETSI TS 102 221 file identifier of the MF; a GFM createFCP carrying it is
# the file-system root when no PE-MF precedes the PE.
_MF_FID = 0x3F00

# TCA SAIP §9.10 -- an EF slot the profile never writes reads back as
# "FF...FF", and §9.10.3.3 shows a fillFileOffset gap carrying the
# file's fill pattern rather than a value of its own.
_ERASED_STATE_BYTE = 0xFF
_BYTESIO_GROWTH_BYTE = 0x00


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


_SD_KEY_LIST_PATCH_MARKER = "_yggdrasim_optional_sd_key_list"


class SaipSecurityDomainKeyListMismatch(RuntimeError):
    """The optional SD ``keyList`` compensation no longer models this pySim."""


def install_optional_security_domain_key_list() -> bool:
    """Let a PE-SecurityDomain omit ``keyList``, and encode none without a key.

    TCA SAIP V3.4.1 §8.6.1 (page 55) declares ``keyList SEQUENCE (SIZE
    (1..MAX)) OF KeyObject OPTIONAL``: an SD without keys omits the member,
    and an empty list is no valid encoding of it. ``ProfileElementSD._post_decode``
    reads ``decoded['keyList']`` unconditionally, so an SD that omits it -- a
    supplementary SD read from a package, or the workbench's SD once its last
    key is removed -- raises ``KeyError``; ``_pre_encode`` writes ``keyList``
    from ``self.keys`` every time, so an SD without keys encodes an empty
    SEQUENCE OF.

    Evidence and the upstream patch are in
    ``upstream_patches/osmocom-pysim-saip-sd-optional-key-list/``.

    The decode wrapper hands upstream an empty list for a missing member and
    takes it out again, so the element keeps omitting it, and raises
    :class:`SaipSecurityDomainKeyListMismatch` when that decodes to keys. The
    encode wrapper drops the list upstream wrote when it is empty. Once
    upstream treats the member as optional both wrappers change nothing, and
    the pinned test says so.

    Returns ``True`` when this call installed the wrappers and ``False`` when
    equivalent wrappers were already active.
    """
    from pySim.esim.saip import ProfileElementSD

    current_post = ProfileElementSD._post_decode
    current_pre = ProfileElementSD._pre_encode
    if getattr(current_post, _SD_KEY_LIST_PATCH_MARKER, False):
        return False

    @wraps(current_post)
    def _post_decode_without_key_list(self: Any) -> None:
        decoded = getattr(self, "decoded", None)
        if not isinstance(decoded, dict) or "keyList" in decoded:
            current_post(self)
            return
        decoded["keyList"] = []
        try:
            current_post(self)
        finally:
            decoded.pop("keyList", None)
        if list(getattr(self, "keys", None) or []):
            raise SaipSecurityDomainKeyListMismatch(
                "an SD without keyList decoded to keys; the compensation in "
                "upstream_patches/osmocom-pysim-saip-sd-optional-key-list/ no "
                "longer models this pySim."
            )

    @wraps(current_pre)
    def _pre_encode_without_empty_key_list(self: Any) -> None:
        current_pre(self)
        decoded = getattr(self, "decoded", None)
        if isinstance(decoded, dict) and decoded.get("keyList") == []:
            del decoded["keyList"]

    setattr(_post_decode_without_key_list, _SD_KEY_LIST_PATCH_MARKER, True)
    setattr(_pre_encode_without_empty_key_list, _SD_KEY_LIST_PATCH_MARKER, True)
    ProfileElementSD._post_decode = _post_decode_without_key_list
    ProfileElementSD._pre_encode = _pre_encode_without_empty_key_list
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


class SaipErasedStateFillMismatch(RuntimeError):
    """The erased-state replay no longer reproduces upstream's own output.

    Raised when neither the compensated nor the uncompensated replay of a
    file's ``fillFileContent`` / ``fillFileOffset`` list matches the bytes
    upstream pySim returned. That means upstream changed its linearisation
    in a way this compensation does not model, so the file image cannot be
    trusted; callers must surface the failure rather than serve bytes that
    may not be the on-card image.
    """


def _replay_file_content(file_obj: Any, tuple_list: Any, growth_byte: int) -> bytes:
    """Linearise a file's data tuples, growing unwritten gaps with one byte.

    Mirrors ``pySim.esim.saip.File.file_content_from_tuples`` step for step:
    the fill/repeat pattern from the Fcp wins over the template default, the
    write head starts at 0, ``fillFileOffset`` advances it (SEEK_CUR) without
    writing, and ``fillFileContent`` deposits bytes at the head. The only
    variable is the byte used where the head has moved past everything laid
    down so far -- the region an ``io.BytesIO`` grows implicitly.
    """
    buffer = bytearray()
    if file_obj.fill_pattern:
        buffer += file_obj.expand_fill_pattern()
    elif file_obj.template and file_obj.template.default_val:
        expanded = file_obj.template.expand_default_value_pattern(file_obj.file_size)
        if expanded:
            buffer += expanded

    cursor = 0
    for key, value in tuple_list:
        if key == "fillFileOffset":
            cursor += value
        elif key == "fillFileContent":
            if cursor > len(buffer):
                buffer += bytes([growth_byte]) * (cursor - len(buffer))
            buffer[cursor:cursor + len(value)] = value
            cursor += len(value)
    return bytes(buffer)


def install_erased_state_file_fill() -> bool:
    """Fill ``fillFileOffset`` gaps with the erased state, not with NUL.

    ``File.file_content_from_tuples`` linearises a file through an
    ``io.BytesIO``. Seeking past the end of that stream and writing makes
    Python zero-fill the skipped region, so every gap a Profile Package
    leaves between two ``fillFileContent`` runs is reported as '00' bytes.
    TCA SAIP §9.10.3.3 encodes EF-ARR exactly that way -- ``fillPattern
    'FF'H`` followed by interleaved offsets and content -- and §9.10 states
    the default EF-ARR image is "padded with 'FF...FF'"; the gaps carry the
    file's pattern, and a file created without one reads back erased. A
    package with no Fcp pattern and no resolvable template therefore
    surfaces access rules, and every other sparsely-encoded EF, with '00'
    where the card holds 'FF'. The GUI writes those bytes back on the next
    record or hex edit, so the wrong value does not stay cosmetic.

    Evidence and the upstream patch are in
    ``upstream_patches/osmocom-pysim-saip-fill-file-offset-erased-state/``.

    The wrapper calls upstream first, so ``doNotCreate`` and the unknown-key
    path keep their exact behaviour, then replays the same tuple list twice:
    once growing gaps with the erased state and once with NUL. Upstream's
    result must equal one of the two, otherwise
    :class:`SaipErasedStateFillMismatch` is raised rather than a guess being
    returned. Matching the erased-state replay means upstream has fixed the
    gap fill and this compensation is already a no-op -- the point at which
    it can be deleted.

    Returns ``True`` when this call installed the wrapper and ``False`` when
    an equivalent wrapper was already active.
    """
    from pySim.esim.saip import File

    current = File.file_content_from_tuples
    if getattr(current, _ERASED_FILL_PATCH_MARKER, False):
        return False

    @wraps(current)
    def _erased_state_file_content_from_tuples(self: Any, tuple_list: Any) -> Any:
        upstream = current(self, tuple_list)
        if not isinstance(upstream, (bytes, bytearray)):
            return upstream
        upstream_bytes = bytes(upstream)
        erased = _replay_file_content(self, tuple_list, _ERASED_STATE_BYTE)
        if upstream_bytes == erased:
            return upstream
        predicted = _replay_file_content(self, tuple_list, _BYTESIO_GROWTH_BYTE)
        if upstream_bytes != predicted:
            raise SaipErasedStateFillMismatch(
                f"pySim linearised {getattr(self, 'pe_name', None)!r} into "
                f"{len(upstream_bytes)} B that no replay of its "
                "fillFileContent / fillFileOffset list reproduces; the "
                "erased-state compensation in "
                "upstream_patches/osmocom-pysim-saip-fill-file-offset-"
                "erased-state/ no longer models this pySim."
            )
        return erased

    setattr(
        _erased_state_file_content_from_tuples,
        _ERASED_FILL_PATCH_MARKER,
        True,
    )
    File.file_content_from_tuples = _erased_state_file_content_from_tuples
    return True


class SaipRecordFillMismatch(RuntimeError):
    """A per-record fill expansion did not cover the file it describes.

    Raised when the record-aware expansion cannot be reconciled with the
    file's declared geometry or with upstream's own single-record result, so
    the image cannot be trusted rather than silently mis-sized.
    """


def install_record_aware_fill_pattern() -> bool:
    """Apply a file's fill/repeat pattern per record, not once per file.

    ETSI TS 102 222 §6.3.2.2 defines both patterns record-wise for a record
    oriented EF: tag 'C1' initialises "the first W-1 bytes of each record",
    tag 'C2' repeats "for all remaining blocks of X bytes of data in the file
    or in a record", truncating at each record boundary.

    ``File.expand_fill_pattern`` passes ``self.file_size`` straight to
    ``ts_102_222.expand_pattern``, which knows nothing about records, so a
    linear-fixed EF.EXT2 declaring ``fillPattern '00FF'H`` expands to one '00'
    followed by erased bytes instead of a '00' opening every record. On the
    card each record starts with its record-type byte; the difference is the
    whole meaning of the file.

    Evidence and the upstream patch are in
    ``upstream_patches/osmocom-pysim-saip-fill-file-offset-erased-state/``.

    The wrapper calls upstream first, so a transparent or BER-TLV file and any
    file without record geometry keep upstream's result byte for byte. Where
    the geometry is known it expands one record and repeats it, checking the
    result against the declared size and -- for a single-record file, where the
    two readings must coincide -- against upstream's own bytes.

    Returns ``True`` when this call installed the wrapper and ``False`` when an
    equivalent wrapper was already active.
    """
    from pySim import ts_102_222
    from pySim.esim.saip import File

    current = File.expand_fill_pattern
    if getattr(current, _RECORD_FILL_PATCH_MARKER, False):
        return False

    @wraps(current)
    def _record_aware_expand_fill_pattern(self: Any) -> Any:
        upstream = current(self)
        if getattr(self, "file_type", None) not in ("LF", "CY"):
            return upstream
        record_length = getattr(self, "rec_len", None)
        record_count = getattr(self, "nb_rec", None)
        if not isinstance(record_length, int) or record_length <= 0:
            return upstream
        if not isinstance(record_count, int) or record_count <= 0:
            return upstream

        pattern = bytes(self.fill_pattern)
        record = ts_102_222.expand_pattern(
            pattern,
            self.fill_pattern_repeat,
            record_length,
        )[:record_length]
        expanded = record * record_count

        if len(expanded) != record_length * record_count:
            raise SaipRecordFillMismatch(
                f"record-aware fill of {getattr(self, 'pe_name', None)!r} "
                f"produced {len(expanded)} B for a "
                f"{record_count}x{record_length} B file."
            )
        if (
            record_count == 1
            and len(pattern) <= record_length
            and expanded != bytes(upstream)
        ):
            # One record makes the per-record and whole-file readings the same
            # expansion; a difference means upstream no longer does what this
            # compensation models.
            raise SaipRecordFillMismatch(
                f"single-record fill of {getattr(self, 'pe_name', None)!r} "
                "does not match pySim's own expansion; the record-aware "
                "compensation no longer models this pySim."
            )
        return expanded

    setattr(
        _record_aware_expand_fill_pattern,
        _RECORD_FILL_PATCH_MARKER,
        True,
    )
    File.expand_fill_pattern = _record_aware_expand_fill_pattern
    return True


_RECORD_TEMPLATE_DEFAULT_PATCH_MARKER = "_yggdrasim_record_aware_template_default"


class SaipTemplateDefaultMismatch(RuntimeError):
    """A per-record template default did not cover the file it describes."""


def install_record_aware_template_default() -> bool:
    """Lay a template's default value into each record of a record-oriented EF.

    TCA SAIP V3.4.1 section 9 gives a template file its default value per
    record: EF ICI (page 86) is 20 records of 38 bytes with the default
    'FF...FF 0000000001FFFF', one 38-byte record, and pySim's own
    ``FileTemplate._default_value_len`` returns the record length for a
    linear-fixed or cyclic file. ``File.file_content_from_tuples`` and
    ``File.file_content_to_tuples(optimize=True)`` nevertheless expand the
    default once across the whole file (``expand_default_value_pattern(
    self.file_size)``), so every record but the last reads back erased where
    the card holds the tail of the default, and an encoder round trip writes
    those tails out as content.

    Evidence and the upstream patch are in
    ``upstream_patches/osmocom-pysim-saip-fill-file-offset-erased-state/``
    (bug 3).

    The wrapper replaces ``FileTemplate.expand_default_value_pattern``. For a
    record-oriented template asked for more than one record it expands one
    record and repeats it, checking the length; a transparent template, a
    request of one record at most, a template without record geometry or a
    literal default that does not fill its record keep upstream's bytes. When
    upstream returns the per-record image itself the wrapper changes nothing,
    and the pinned test says so.

    Returns ``True`` when this call installed the wrapper and ``False`` when
    an equivalent wrapper was already active.
    """
    from pySim.esim.saip import templates

    current = templates.FileTemplate.expand_default_value_pattern
    if getattr(current, _RECORD_TEMPLATE_DEFAULT_PATCH_MARKER, False):
        return False

    @wraps(current)
    def _record_aware_expand_default_value_pattern(self: Any, length: Any = None) -> Any:
        upstream = current(self, length)
        if getattr(self, "file_type", None) not in ("LF", "CY"):
            return upstream
        record_length = getattr(self, "rec_len", None)
        if not isinstance(record_length, int) or record_length <= 0:
            return upstream
        if not isinstance(length, int) or length <= record_length:
            return upstream
        if not upstream:
            return upstream
        record = current(self, record_length)
        if not record or len(record) != record_length:
            return upstream
        record = bytes(record)
        count, rest = divmod(length, record_length)
        expanded = record * count + record[:rest]
        if len(expanded) != length:
            raise SaipTemplateDefaultMismatch(
                f"record-aware default of {getattr(self, 'name', None)!r} "
                f"produced {len(expanded)} B for {length} B."
            )
        return expanded

    setattr(
        _record_aware_expand_default_value_pattern,
        _RECORD_TEMPLATE_DEFAULT_PATCH_MARKER,
        True,
    )
    templates.FileTemplate.expand_default_value_pattern = (
        _record_aware_expand_default_value_pattern
    )
    return True


_PROPRIETARY_INFO_PATCH_MARKER = "_yggdrasim_proprietary_efinfo_without_descriptor"


class SaipProprietaryInfoMismatch(RuntimeError):
    """A template file did not take the pattern its Fcp declares."""


def install_proprietary_efinfo_without_descriptor() -> bool:
    """Read a template file's ``proprietaryEFInfo`` when its Fcp names no ``fileDescriptor``.

    TCA SAIP V3.4.1 §8.3.3 (pages 29 and 30) lets a PE change a template
    file's settings by naming the parameters it changes: ``proprietaryEFInfo``
    is optional for an EF, and "a repeat or fill pattern provided within the
    respective Fcp shall overwrite the default content completely".
    ``File.from_fileDescriptor`` applies ``proprietaryEFInfo`` -- the special
    file information, the fill or repeat pattern, a BER-TLV maximum size --
    only inside its ``'fileDescriptor' in fileDescriptor`` branch, so an Fcp
    that sets a pattern without repeating the descriptor the template defines
    reads as if it set none: the image shows the template default or the
    erased state where the card holds the pattern. The workbench's FCP rows
    write exactly that shape.

    Evidence and the upstream patch are in
    ``upstream_patches/osmocom-pysim-saip-proprietary-efinfo-without-descriptor/``.

    The wrapper calls upstream first. For an Fcp without ``fileDescriptor`` on
    a working EF whose type the template set, it applies the members in
    upstream's own order -- the repeat pattern, then the fill pattern, which
    wins as it does upstream -- and checks the file reports the declared
    pattern, raising :class:`SaipProprietaryInfoMismatch` otherwise. Once
    upstream applies them itself the assignments change nothing, and the
    pinned test says so.

    Returns ``True`` when this call installed the wrapper and ``False`` when
    an equivalent wrapper was already active.
    """
    from pySim.esim.saip import File

    current = File.from_fileDescriptor
    if getattr(current, _PROPRIETARY_INFO_PATCH_MARKER, False):
        return False

    @wraps(current)
    def _from_file_descriptor(self: Any, fcp: Any) -> Any:
        result = current(self, fcp)
        if not isinstance(fcp, dict) or "fileDescriptor" in fcp:
            return result
        pefi = fcp.get("proprietaryEFInfo")
        if not isinstance(pefi, dict) or not pefi:
            return result
        if getattr(self, "file_type", None) not in ("TR", "LF", "CY", "BT"):
            return result
        special = pefi.get("specialFileInformation")
        if special:
            # ETSI TS 102 222 Table 5 bits, read as upstream reads them.
            if special[0] & 0x80:
                self.high_update = True
            if special[0] & 0x40:
                self.read_and_update_when_deact = True
        if "repeatPattern" in pefi:
            self.fill_pattern = pefi["repeatPattern"]
            self.fill_pattern_repeat = True
        if "fillPattern" in pefi:
            self.fill_pattern = pefi["fillPattern"]
            self.fill_pattern_repeat = False
        if self.file_type == "BT" and "maximumFileSize" in pefi:
            self._file_size = self._decode_file_size(pefi["maximumFileSize"])
        declared = pefi.get("fillPattern", pefi.get("repeatPattern"))
        if declared is not None and bytes(getattr(self, "fill_pattern", None) or b"") != bytes(declared):
            raise SaipProprietaryInfoMismatch(
                f"{getattr(self, 'pe_name', None)!r} declares the pattern "
                f"{bytes(declared).hex()} but reads {getattr(self, 'fill_pattern', None)!r}; "
                "the compensation in upstream_patches/osmocom-pysim-saip-"
                "proprietary-efinfo-without-descriptor/ no longer models this pySim."
            )
        return result

    setattr(_from_file_descriptor, _PROPRIETARY_INFO_PATCH_MARKER, True)
    File.from_fileDescriptor = _from_file_descriptor
    return True


_BODY_ENCODING_PATCH_MARKER = "_yggdrasim_body_encoding_against_creation_content"
# TCA SAIP V3.4.1 §8.3.2 ``File``: ``fillFileOffset UInt16``.
_FILL_FILE_OFFSET_MAX = 0xFFFF


class SaipBodyEncodingMismatch(RuntimeError):
    """An optimised body encoding does not rebuild the body it encodes."""


def file_creation_content(file_obj: Any, length: int) -> bytes:
    """What the eUICC holds in a file before any ``fillFileContent`` lands.

    The Fcp pattern when one is declared, otherwise the template default, laid
    out as ``file_content_from_tuples`` lays it (per record with the record-aware
    compensations), and the erased state beyond -- the same model
    :func:`_replay_file_content` uses.
    """
    image = bytearray(_replay_file_content(file_obj, [], _ERASED_STATE_BYTE))
    if len(image) < length:
        image += bytes([_ERASED_STATE_BYTE]) * (length - len(image))
    return bytes(image[:length])


def _replay_body_tuples(base: bytes, tuple_list: Any) -> bytes:
    """Apply ``fillFileOffset`` / ``fillFileContent`` to ``base`` (TCA SAIP V3.4.1 §8.3.5).

    ``fillFileOffset`` moves the pointer from where it stands and
    ``fillFileContent`` writes there and moves it past what it wrote.
    """
    image = bytearray(base)
    cursor = 0
    for key, value in tuple_list:
        if key == "fillFileOffset":
            cursor += int(value)
        elif key == "fillFileContent":
            if cursor > len(image):
                image += bytes([_ERASED_STATE_BYTE]) * (cursor - len(image))
            image[cursor:cursor + len(value)] = value
            cursor += len(value)
    return bytes(image)


def _positional_body_tuples(base: bytes, body: bytes) -> list[tuple[str, Any]]:
    """The runs where ``body`` differs from ``base``, as relative-offset tuples."""
    out: list[tuple[str, Any]] = []
    head = 0
    index = 0
    while index < len(body):
        if index < len(base) and body[index] == base[index]:
            index += 1
            continue
        start = index
        while index < len(body) and not (index < len(base) and body[index] == base[index]):
            index += 1
        gap = start - head
        while gap > _FILL_FILE_OFFSET_MAX:
            out.append(("fillFileOffset", _FILL_FILE_OFFSET_MAX))
            gap -= _FILL_FILE_OFFSET_MAX
        out.append(("fillFileOffset", gap))
        out.append(("fillFileContent", bytes(body[start:index])))
        head = index
    return out


def install_body_encoding_against_creation_content() -> bool:
    """Encode an optimised file body against what the card creates the file with.

    ``File.file_content_to_tuples(optimize=True)`` writes only where the body
    differs from a baseline, and two things in it disagree with TCA SAIP
    V3.4.1:

    - the baseline is the template default (or 'FF' bytes), never the Fcp fill
      or repeat pattern, although §8.3.3 (page 30) has that pattern "overwrite
      the default content completely": bytes equal to the template default but
      not to the pattern are left out, and the card keeps the pattern there;
    - each ``fillFileOffset`` is computed as if it were an absolute position
      (``block.a - cur`` with ``cur`` growing by the sizes written), while §8.3.5
      (page 45) moves the pointer from where it stands and lets
      ``fillFileContent`` advance it, so every block after the first lands
      too far into the file.

    Evidence and the upstream patch are in
    ``upstream_patches/osmocom-pysim-saip-optimised-body-encoding/``.

    The wrapper calls upstream first and replays its tuples onto the content
    the card creates the file with (:func:`file_creation_content`): when that
    rebuilds the body, upstream's encoding stands, which is the case for every
    unoptimised call and the day upstream lands the fix. Otherwise it encodes
    the positional differences with relative offsets and replays those too,
    raising :class:`SaipBodyEncodingMismatch` if even they do not rebuild the
    body.

    Returns ``True`` when this call installed the wrapper and ``False`` when an
    equivalent wrapper was already active.
    """
    from pySim.esim.saip import File

    current = File.file_content_to_tuples
    if getattr(current, _BODY_ENCODING_PATCH_MARKER, False):
        return False

    @wraps(current)
    def _file_content_to_tuples(self: Any, optimize: bool = False) -> Any:
        upstream = current(self, optimize)
        body = getattr(self, "body", None)
        if not optimize or not isinstance(body, (bytes, bytearray)):
            return upstream
        body = bytes(body)
        base = file_creation_content(self, len(body))
        # A write past the body would grow the replay; the card refuses one
        # beyond the file size (§8.3.5), so only an exact rebuild stands.
        if _replay_body_tuples(base, upstream) == body:
            return upstream
        encoded = _positional_body_tuples(base, body)
        if _replay_body_tuples(base, encoded) != body:
            raise SaipBodyEncodingMismatch(
                f"the optimised encoding of {getattr(self, 'pe_name', None)!r} "
                "does not rebuild its body; the compensation in upstream_patches/"
                "osmocom-pysim-saip-optimised-body-encoding/ no longer models "
                "this pySim."
            )
        return encoded

    setattr(_file_content_to_tuples, _BODY_ENCODING_PATCH_MARKER, True)
    File.file_content_to_tuples = _file_content_to_tuples
    return True


class SaipGfmMfCreationMismatch(RuntimeError):
    """Raised when a GFM-created MF did not become the sequence root."""


def install_gfm_mf_creation() -> bool:
    """Let PE-GenericFileManagement create the MF when no PE-MF precedes it.

    TCA "Profile interoperability technical specification" V3.4.1 §8.1 orders
    the PEs: PE-MF "may be provided once as the first element of the file
    system creation" and "if this PE is not used, the MF shall be created as
    the first element of the file system using the PE-GenericFileManagement";
    §7.5 forbids PE-MF in an IoT Minimal Profile altogether and §8.3.5 repeats
    the usage rule for the GFM PE. Upstream ``ProfileElementGFM.add_file``
    resolves every file's parent through ``pe_sequence.mf``, so the createFCP
    that is the MF raises ``AttributeError: 'NoneType' object has no attribute
    'lookup_by_fidpath'`` and the whole package fails to decode.

    The wrapper acts only while the sequence has no root. The createFCP for
    file identifier 3F00 becomes the ``FsNodeMF`` root the way
    ``FsProfileElement.add_file`` roots a PE-MF ``mf`` entry, and the result
    is verified. Any other file reaching a rootless sequence is registered by
    path without a tree node, which is what upstream does for a PE decoded
    outside a sequence. ``ProfileElementSequence.cd`` gets the matching guard
    because the GFM walker selects the current DF before each file. Evidence
    and the upstream patch: ``upstream_patches/osmocom-pysim-saip-gfm-mf-creation/``.
    """
    from pySim.esim.saip import (
        FsNodeMF,
        Path as SaipPath,
        ProfileElementGFM,
        ProfileElementSequence,
    )

    current_add_file = ProfileElementGFM.add_file
    if getattr(current_add_file, _GFM_MF_PATCH_MARKER, False):
        return False
    current_cd = ProfileElementSequence.cd

    @wraps(current_add_file)
    def _gfm_add_file_rooting_the_mf(self: Any, file: Any, path: Any) -> Any:
        sequence = getattr(self, "pe_sequence", None)
        if sequence is None or getattr(sequence, "mf", None) is not None:
            return current_add_file(self, file, path)
        if isinstance(path, SaipPath):
            return current_add_file(self, file, path)
        fid_path = [int(fid) for fid in path]
        creates_mf = (
            getattr(file, "fid", None) == _MF_FID
            and getattr(file, "file_type", None) == "DF"
            and all(fid == _MF_FID for fid in fid_path)
        )
        if creates_mf:
            node = FsNodeMF(file)
            file.node = node
            sequence.mf = node
            sequence.cur_df = node
            key = getattr(file, "pe_name", None) or ProfileElementGFM.path_str([_MF_FID])
            self.files[key] = file
            if (
                sequence.mf is not node
                or node.file is not file
                or getattr(sequence, "cur_df", None) is not node
                or self.files.get(key) is not file
            ):
                raise SaipGfmMfCreationMismatch(
                    "the MF created by a PE-GenericFileManagement did not "
                    "become the root of the PE sequence; the GFM MF "
                    "compensation no longer models this pySim."
                )
            return None
        # No MF exists yet and this file is not its creation: keep the file
        # reachable by path, as upstream does for a PE decoded without a
        # sequence, instead of dereferencing the missing root.
        path_str = ProfileElementGFM.path_str(fid_path)
        if path_str in self.files:
            raise KeyError("Cannot add file: %s already exists" % path_str)
        self.files[path_str] = file
        return None

    @wraps(current_cd)
    def _cd_tolerating_a_rootless_sequence(self: Any, path: Any) -> Any:
        if getattr(self, "mf", None) is None:
            self.cur_df = None
            return None
        return current_cd(self, path)

    setattr(_gfm_add_file_rooting_the_mf, _GFM_MF_PATCH_MARKER, True)
    setattr(_cd_tolerating_a_rootless_sequence, _GFM_MF_CD_PATCH_MARKER, True)
    ProfileElementGFM.add_file = _gfm_add_file_rooting_the_mf
    ProfileElementSequence.cd = _cd_tolerating_a_rootless_sequence
    return True


_EXTRA_PE_PATCH_MARKER = "_yggdrasim_extra_profile_elements"
_NAA_GROUP_PATCH_MARKER = "_yggdrasim_iot_naa_grouping"
# TCA SAIP v3.4.1 §9.10.1 fixes the file identifier of the USIM ADF an IoT
# Minimal Profile creates; §9.10.2 places DF 5GS and DF SAIP under it.
_IOT_ADF_USIM_FID = 0x7FF1
_IOT_DF_5GS_FID = 0x5FC0
_IOT_DF_SAIP_FID = 0x5FD0
_EXTRA_PE_TYPES = ("cdmaParameter", "nonStandard", "iot", "opt-iot")


class SaipExtraProfileElementMismatch(RuntimeError):
    """The extra profile-element classes did not take effect in pySim."""


def _iot_profile_templates(oid_module: Any) -> tuple[Any, Any]:
    """The IoT Minimal Profile templates, defined once and registered with pySim.

    Transcribed from TCA SAIP v3.4.1 §9.10.1 ("created by default", OID
    2.23.143.1.2.17) and §9.10.2 ("not created by default", OID
    2.23.143.1.2.18). The mandatory template spans two levels: the MF and
    its files, then the USIM ADF (file identifier 7FF1) and its files, so
    the USIM rows carry the ADF as their parent path. The optional files
    all live under that ADF; DF 5GS and DF SAIP are its children.
    """
    from pySim.esim.saip import Path
    from pySim.esim.saip.templates import (
        FileTemplate,
        ProfileTemplate,
        ProfileTemplateRegistry,
    )

    mandatory = ProfileTemplateRegistry.get_by_oid(str(oid_module.IoT_by_default))
    optional = ProfileTemplateRegistry.get_by_oid(str(oid_module.IoTopt_not_by_default))
    if mandatory is not None and optional is not None:
        return mandatory, optional
    adf = [_IOT_ADF_USIM_FID]
    df_5gs = [_IOT_DF_5GS_FID]
    df_saip = [_IOT_DF_SAIP_FID]

    if mandatory is None:

        class FilesIotMandatory(ProfileTemplate):
            """Mandatory IoT Minimal Profile files as per Section 9.10.1 v3.4.1"""

            created_by_default = True
            oid = oid_module.IoT_by_default
            files = [
                FileTemplate(0x3F00, "MF", "MF", None, None, 7, None, None, False, ["pinStatusTemplateDO"]),
                FileTemplate(0x2F05, "EF.PL", "TR", None, 2, 1, 0x05, "FF...FF", False),
                FileTemplate(0x2FE2, "EF.ICCID", "TR", None, 10, 6, None, None, False),
                FileTemplate(0x2F00, "EF.DIR", "LF", 1, None, 5, 0x1E, None, False, ["size"]),
                FileTemplate(0x2F06, "EF.ARR", "LF", 8, 33, 5, None, None, False),
                FileTemplate(0x2F08, "EF.UMPC", "TR", None, 5, 5, 0x08, None, False),
                FileTemplate(_IOT_ADF_USIM_FID, "ADF.USIM", "ADF", None, None, 7, None, None, False, ["aid", "pinStatusTemplateDO"]),
                FileTemplate(0x6F07, "EF.IMSI", "TR", None, 9, 2, 0x07, None, True, ppath=adf),
                FileTemplate(0x6F06, "EF.ARR", "LF", None, None, 5, 0x17, None, False, pe_name="ef-arr-usim", ppath=adf),
                FileTemplate(0x6F08, "EF.Keys", "TR", None, 33, 4, 0x08, "07FF...FF", False, high_update=True, ppath=adf),
                FileTemplate(0x6F09, "EF.KeysPS", "TR", None, 33, 4, 0x09, "07FF...FF", False, high_update=True, pe_name="ef-keysPS", ppath=adf),
                FileTemplate(0x6F31, "EF.HPPLMN", "TR", None, 1, 2, 0x12, "0A", False, ppath=adf),
                FileTemplate(0x6F38, "EF.UST", "TR", None, 17, 2, 0x04, "000000000100...00", False, ppath=adf),
                FileTemplate(0x6F5B, "EF.START-HFN", "TR", None, 6, 4, 0x0F, "F00000F00000", False, high_update=True, ppath=adf),
                FileTemplate(0x6F5C, "EF.THRESHOLD", "TR", None, 3, 2, 0x10, "FFFFFF", False, ppath=adf),
                FileTemplate(0x6F73, "EF.PSLOCI", "TR", None, 14, 4, 0x0C, "FFFFFFFFFFFFFFFFFFFF0000FF01", False, high_update=True, ppath=adf),
                FileTemplate(0x6F78, "EF.ACC", "TR", None, 2, 2, 0x06, None, True, ppath=adf),
                FileTemplate(0x6F7B, "EF.FPLMN", "TR", None, 12, 4, 0x0D, "FF...FF", False, ppath=adf),
                FileTemplate(0x6F7E, "EF.LOCI", "TR", None, 11, 4, 0x0B, "FFFFFFFFFFFFFF0000FF01", False, high_update=True, ppath=adf),
                FileTemplate(0x6FAD, "EF.AD", "TR", None, 4, 5, 0x03, "00000002", False, ppath=adf),
                FileTemplate(0x6FB7, "EF.ECC", "LF", 1, 4, 5, 0x01, "FF...FF", False, ppath=adf),
                FileTemplate(0x6FC4, "EF.NETPAR", "TR", None, 128, 4, None, "FF...FF", False, high_update=True, ppath=adf),
            ]

        mandatory = FilesIotMandatory

    if optional is None:

        class FilesIotOptional(ProfileTemplate):
            """Optional IoT Minimal Profile files as per Section 9.10.2 v3.4.1"""

            created_by_default = False
            optional = True
            oid = oid_module.IoTopt_not_by_default
            base_path = Path("ADF.USIM")
            extends = mandatory
            files = [
                FileTemplate(0x6F3B, "EF.FDN", "LF", 20, 26, 8, None, "FF...FF", False, ass_serv=[2, 89]),
                FileTemplate(0x6F3C, "EF.SMS", "LF", 10, 176, 4, None, "00FF...FF", False, ass_serv=[10]),
                FileTemplate(0x6F42, "EF.SMSP", "LF", 1, 38, 4, None, "FF...FF", False, ass_serv=[12]),
                FileTemplate(0x6F43, "EF.SMSS", "TR", None, 2, 4, None, "FFFF", False, ass_serv=[10]),
                FileTemplate(0x6F46, "EF.SPN", "TR", None, 17, 5, None, None, True, ass_serv=[19]),
                FileTemplate(0x6F56, "EF.EST", "TR", None, 1, 8, 0x05, None, True, ass_serv=[2, 6, 34, 35]),
                FileTemplate(0x6F61, "EF.OPLMNwAcT", "TR", None, 40, 2, 0x11, "FFFFFF0000", False, ass_serv=[42], repeat=True),
                FileTemplate(0x6F62, "EF.HPLMNwAcT", "TR", None, 5, 2, 0x13, "FFFFFF0000", False, ass_serv=[43], repeat=True),
                FileTemplate(0x6FD9, "EF.EHPLMN", "TR", None, 15, 2, 0x1D, "FF...FF", False, ass_serv=[71]),
                FileTemplate(0x6FE3, "EF.EPSLOCI", "TR", None, 18, 4, 0x1E, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000001", False, ass_serv=[85], high_update=True),
                FileTemplate(0x6FE4, "EF.EPSNSC", "LF", 1, 80, 4, 0x18, "FF...FF", False, ass_serv=[85], high_update=True),
                FileTemplate(_IOT_DF_5GS_FID, "DF.5GS", "DF", None, None, 7, None, None, False, ["pinStatusTemplateDO"], pe_name="df-df-5gs"),
                FileTemplate(0x4F01, "EF.5GS3GPPLOCI", "TR", None, 20, 4, 0x01, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001", False, ass_serv=[122], high_update=True, ppath=df_5gs),
                FileTemplate(0x4F02, "EF.5GSN3GPPLOCI", "TR", None, 20, 4, 0x02, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001", False, ass_serv=[122], high_update=True, ppath=df_5gs),
                FileTemplate(0x4F03, "EF.5GS3GPPNSC", "LF", 2, 62, 4, 0x03, "FF...FF", False, ass_serv=[122, 136], high_update=True, ppath=df_5gs),
                FileTemplate(0x4F04, "EF.5GSN3GPPNSC", "LF", 2, 62, 4, 0x04, "FF...FF", False, ass_serv=[122, 136], high_update=True, ppath=df_5gs),
                FileTemplate(0x4F05, "EF.5GAUTHKEYS", "TR", None, 110, 4, 0x05, "FF...FF", False, ass_serv=[123], high_update=True, ppath=df_5gs),
                FileTemplate(0x4F06, "EF.UAC_AIC", "TR", None, 4, 2, 0x06, None, True, ass_serv=[126], ppath=df_5gs),
                FileTemplate(0x4F07, "EF.SUCI_Calc_Info", "TR", None, 44, 2, 0x07, "FF...FF", False, ass_serv=[124], ppath=df_5gs),
                FileTemplate(0x4F08, "EF.OPL5G", "LF", 1, 10, 5, 0x08, "FF...FF", False, ass_serv=[129], ppath=df_5gs),
                FileTemplate(0x4F09, "EF.SUPI_NAI", "TR", None, 20, 2, 0x09, None, True, ass_serv=[130], pe_name="ef-supi-nai", ppath=df_5gs),
                FileTemplate(0x4F0A, "EF.Routing_Indicator", "TR", None, 4, 2, 0x0A, "F0FF0000", False, ass_serv=[124], ppath=df_5gs),
                FileTemplate(0x4F0B, "EF.URSP", "BT", None, 200, 2, None, None, False, ass_serv=[132], ppath=df_5gs),
                FileTemplate(0x4F0C, "EF.TN3GPPSNN", "TR", None, 1, 2, 0x0C, "00", False, ass_serv=[135], ppath=df_5gs),
                FileTemplate(_IOT_DF_SAIP_FID, "DF.SAIP", "DF", None, None, 7, None, None, False, ["pinStatusTemplateDO"], pe_name="df-df-saip"),
                FileTemplate(0x4F01, "EF.SUCI_Calc_Info_USIM", "TR", None, 44, 3, None, "FF...FF", False, ass_serv=[125], pe_name="ef-suci-calc-info-usim", ppath=df_saip),
            ]

        optional = FilesIotOptional

    return mandatory, optional


def _template_relative_path(template: Any, file_template: Any) -> list[str]:
    """``[DF names..., file name]`` of a template row below the template's base.

    Follows the row's ``ppath`` (file identifiers of the containers between
    the base and the row) rather than the template's parse tree, which
    cannot express two sibling DFs inside one template.
    """
    names: list[str] = []
    for fid in list(getattr(file_template, "ppath", ()) or ()):
        container = next(
            (
                candidate
                for candidate in template.files
                if candidate.fid == fid and candidate.file_type in ("MF", "DF", "ADF")
            ),
            None,
        )
        names.append(container.name if container is not None else "%04X" % fid)
    names.append(file_template.name)
    return names


def install_extra_profile_elements() -> bool:
    """Map the element types pySim leaves unmapped and add the IoT templates.

    pySim's ``ProfileElement.class_for_petype`` (osmocom pysim c50f4b4 and
    master) returns ``None`` for ``cdmaParameter``, ``nonStandard``,
    ``iot`` and ``opt-iot``, so a profile carrying them decodes into the
    bare ``ProfileElement``: no templates, no file bodies, no place in the
    file-system tree. This installs thin classes for the two parameter
    elements and file-system elements for the IoT Minimal Profile (TCA
    SAIP v3.4.1 §8.3.4.8; templates §9.10.1 and §9.10.2), whose single
    element creates the MF-level files and the USIM ADF. pySim's template
    model knows one base DF per template, so ``ProfileElementIoT`` roots
    the MF the element may leave implicit and ``ProfileElementOptIoT``
    places its files under the ADF of the preceding PE-IoT, DF 5GS and
    DF SAIP as its children. ``NaaUsim`` gains the two types and the
    NAA grouping treats PE-IoT as the start of the USIM NAA.

    Every piece steps aside when upstream provides its own: a type
    upstream maps keeps upstream's class, a template OID upstream
    registers keeps upstream's template. The installer states its
    result and raises ``SaipExtraProfileElementMismatch`` when the lookup
    does not return the classes afterwards. Evidence and the upstream
    patch are in ``upstream_patches/osmocom-pysim-saip-extra-profile-elements/``.
    """
    import inspect

    from pySim.esim.saip import (
        File,
        FsProfileElement,
        NaaUsim,
        Path,
        ProfileElement,
        ProfileElementSequence,
        oid,
    )
    from pySim.esim.saip.templates import ProfileTemplateRegistry
    from pySim.utils import b2h, dec_imsi

    current_lookup = ProfileElement.class_for_petype
    if getattr(current_lookup, _EXTRA_PE_PATCH_MARKER, False):
        return False
    upstream_lookup = current_lookup.__func__

    mandatory_template, optional_template = _iot_profile_templates(oid)

    class ProfileElementCDMA(ProfileElement):
        """PE-CDMAParameter: the CDMA NAA parameters (TCA SAIP v3.4.1 §8.4.2)."""

        type = "cdmaParameter"

    class ProfileElementNonStandard(ProfileElement):
        """PE-NonStandard: an issuer-specific element (TCA SAIP v3.4.1 §8.9)."""

        type = "nonStandard"

    class ProfileElementIoT(FsProfileElement):
        """PE-IoT: the MF-level files and the USIM ADF of an IoT Minimal Profile."""

        type = "iot"

        def __init__(self, decoded: Any = None, **kwargs: Any) -> None:
            super().__init__(decoded, **kwargs)
            if decoded:
                return
            self.decoded["templateID"] = str(oid.IoT_by_default)
            for fname in ("mf", "ef-iccid", "ef-dir", "adf-usim", "ef-imsi", "ef-ust", "ef-acc", "ef-ecc"):
                self.decoded[fname] = []

        @property
        def adf_name(self) -> str:
            return b2h(self.decoded["adf-usim"][0][1]["dfName"])

        @property
        def imsi(self) -> Any:
            template = ProfileTemplateRegistry.get_by_oid(self.templateID)
            entry = File("ef-imsi", self.decoded["ef-imsi"], template.files_by_pename.get("ef-imsi"))
            return dec_imsi(b2h(entry.body))

        def file_template_for_path(self, path: Any, adf: Any = None) -> Any:
            template = ProfileTemplateRegistry.get_by_oid(self.templateID)
            for entry in template.files:
                if entry.path == path or entry.path.relative_to_mf() == path:
                    return entry
            return None

        def _root_template_mf(self) -> None:
            template = ProfileTemplateRegistry.get_by_oid(self.templateID)
            mf_file = File("mf", None, template.files_by_pename["mf"])
            mf_file._implicit_template_path = True
            sequence = self.pe_sequence
            if sequence is not None and getattr(sequence, "mf", None) is not None:
                self.files["mf"] = mf_file
                mf_file.node = sequence.mf
                return
            super().add_file(mf_file)

        def add_file(self, file: Any) -> Any:
            # ``mf`` is OPTIONAL in PE-IoT: the template's MF is rooted before
            # anything else is placed, and an MF a PE-GenericFileManagement
            # created earlier (TCA SAIP v3.4.1 §8.1) is reused, not doubled.
            sequence = self.pe_sequence
            if file.pe_name == "mf" and sequence is not None and getattr(sequence, "mf", None) is not None:
                if "mf" in self.files:
                    raise KeyError("Cannot add file: mf already exists")
                self.files["mf"] = file
                file.node = sequence.mf
                return None
            if file.pe_name != "mf" and "mf" not in self.files:
                self._root_template_mf()
            return super().add_file(file)

    class ProfileElementOptIoT(FsProfileElement):
        """PE-OPT-IoT: the optional USIM files of an IoT Minimal Profile."""

        type = "opt-iot"

        def __init__(self, decoded: Any = None, **kwargs: Any) -> None:
            super().__init__(decoded, **kwargs)
            if decoded:
                return
            self.decoded["templateID"] = str(oid.IoTopt_not_by_default)

        def file_template_for_path(self, path: Any, adf: Any = None) -> Any:
            template = ProfileTemplateRegistry.get_by_oid(self.templateID)
            adf_name = str(adf or "ADF.USIM")
            for entry in template.files:
                relative = _template_relative_path(template, entry)
                if Path([adf_name] + relative) == path or Path(["MF", adf_name] + relative) == path:
                    return entry
            return None

        def _usim_adf_node(self) -> Any:
            sequence = self.pe_sequence
            iot_pe = sequence.get_closest_prev_pe_for_templateID(self, oid.IoT_by_default)
            if iot_pe is not None:
                adf = iot_pe.files.get("adf-usim")
                if adf is not None and getattr(adf, "node", None) is not None:
                    return adf.node
            if getattr(sequence, "mf", None) is not None:
                try:
                    return sequence.mf[_IOT_ADF_USIM_FID]
                except KeyError:
                    pass
            if getattr(sequence, "cur_df", None) is not None:
                return sequence.cur_df
            raise ValueError(
                "PE-OPT-IoT needs the USIM ADF of a preceding PE-IoT "
                "(TCA SAIP v3.4.1 §8.3.4.8.2)."
            )

        def add_file(self, file: Any) -> Any:
            if file.pe_name in self.files:
                raise KeyError("Cannot add file: %s already exists" % file.pe_name)
            self.files[file.pe_name] = file
            sequence = self.pe_sequence
            if sequence is None:
                return None
            template = ProfileTemplateRegistry.get_by_oid(self.templateID)
            pe_df = self._usim_adf_node()
            for fid in list(getattr(file.template, "ppath", ()) or ()):
                try:
                    pe_df = pe_df[fid]
                    continue
                except KeyError:
                    pass
                container = next(
                    (
                        candidate
                        for candidate in template.files
                        if candidate.fid == fid and candidate.file_type in ("MF", "DF", "ADF")
                    ),
                    None,
                )
                if container is None:
                    raise KeyError("no template DF %04X on the path of %s" % (fid, file))
                path_file = self.files.get(container.pe_name)
                if path_file is None:
                    path_file = File(container.pe_name, None, container)
                    path_file._implicit_template_path = True
                    self.files[container.pe_name] = path_file
                pe_df = path_file.node if path_file.node else pe_df.add_file(path_file)
            sequence.cur_df = pe_df
            sequence.cur_df = pe_df.add_file(file)
            return None

    extra = {
        "cdmaParameter": ProfileElementCDMA,
        "nonStandard": ProfileElementNonStandard,
        "iot": ProfileElementIoT,
        "opt-iot": ProfileElementOptIoT,
    }

    def _class_for_petype_with_extras(cls: Any, pe_type: str) -> Any:
        found = upstream_lookup(cls, pe_type)
        if found is not None:
            return found
        return extra.get(pe_type)

    setattr(_class_for_petype_with_extras, _EXTRA_PE_PATCH_MARKER, True)
    _class_for_petype_with_extras.__wrapped__ = upstream_lookup
    ProfileElement.class_for_petype = classmethod(_class_for_petype_with_extras)

    for pe_type in _EXTRA_PE_TYPES:
        if pe_type not in NaaUsim.pe_types and pe_type in ("iot", "opt-iot"):
            NaaUsim.pe_types.append(pe_type)

    upstream_grouping = ProfileElementSequence._rebuild_pes_by_naa
    if not getattr(upstream_grouping, _NAA_GROUP_PATCH_MARKER, False) and "iot" not in inspect.getsource(upstream_grouping):

        def _rebuild_pes_by_naa_with_iot(self: Any) -> None:
            # pySim groups the elements between two NAA-creating elements
            # under that NAA; PE-IoT creates the USIM ADF, so it starts the
            # USIM group (TCA SAIP v3.4.1 §8.3.4.8.1).
            self.pes_by_naa = {}
            not_naa_related = ("securityDomain", "rfm", "application", "end")
            naa_start = {"mf": "mf", "usim": "usim", "isim": "isim", "csim": "csim", "iot": "usim"}
            cur_naa = None
            cur_naa_list: list[Any] = []
            for pe in self.pe_list:
                if pe.type in not_naa_related:
                    continue
                if pe.type in naa_start:
                    if cur_naa:
                        self.pes_by_naa.setdefault(cur_naa, []).append(cur_naa_list)
                    cur_naa = naa_start[pe.type]
                    cur_naa_list = []
                cur_naa_list.append(pe)
            if cur_naa and len(cur_naa_list) > 0:
                self.pes_by_naa.setdefault(cur_naa, []).append(cur_naa_list)

        setattr(_rebuild_pes_by_naa_with_iot, _NAA_GROUP_PATCH_MARKER, True)
        _rebuild_pes_by_naa_with_iot.__wrapped__ = upstream_grouping
        ProfileElementSequence._rebuild_pes_by_naa = _rebuild_pes_by_naa_with_iot

    for pe_type, pe_class in extra.items():
        resolved = ProfileElement.class_for_petype(pe_type)
        if resolved is None or (resolved is not pe_class and upstream_lookup(ProfileElement, pe_type) is None):
            raise SaipExtraProfileElementMismatch(
                "pySim does not resolve %r to a profile-element class after the "
                "extra elements were installed." % pe_type
            )
    if ProfileTemplateRegistry.get_by_oid(str(oid.IoT_by_default)) is not mandatory_template:
        raise SaipExtraProfileElementMismatch("the IoT template did not register with pySim.")
    if ProfileTemplateRegistry.get_by_oid(str(oid.IoTopt_not_by_default)) is not optional_template:
        raise SaipExtraProfileElementMismatch("the optional IoT template did not register with pySim.")
    return True


_PHONEBOOK_PBC_PATCH_MARKER = "_yggdrasim_phonebook_pbc_template"
# TCA SAIP v3.4.1 Annex A (page 74): DF.PHONEBOOK carries EF PBC at 4F60 to
# 4F67, linear fixed with 2-byte records, ARR record 5, default '00...00';
# the file size and the SFI come from the instance.
_PHONEBOOK_DF_FID = 0x5F3A
_PHONEBOOK_PBC_FIDS = range(0x4F60, 0x4F68)
_PHONEBOOK_PBC_RECORD_LEN = 2


class SaipPhonebookTemplateMismatch(RuntimeError):
    """pySim's phonebook templates do not carry EF.PBC after the fix."""


class SaipTemplateRangeFidMismatch(RuntimeError):
    """A pySim template still resolves a ranged file to a later FID."""


def _registered_templates() -> list[Any]:
    """Every ProfileTemplate class pySim registered, each once."""
    from pySim.esim.saip.templates import ProfileTemplateRegistry

    seen: list[Any] = []
    for template in ProfileTemplateRegistry.by_oid.values():
        if any(template is known for known in seen):
            continue
        seen.append(template)
    return seen


def _rebuild_files_by_pename(template: Any) -> bool:
    """Rebuild ``files_by_pename`` first-listed-wins; report whether it changed."""
    rebuilt: dict[str, Any] = {}
    for file_template in list(getattr(template, "files", None) or []):
        rebuilt.setdefault(str(file_template.pe_name), file_template)
    current = getattr(template, "files_by_pename", None)
    if isinstance(current, dict) is False:
        template.files_by_pename = rebuilt
        return True
    unchanged = len(current) == len(rebuilt) and all(
        current.get(name) is file_template
        for name, file_template in rebuilt.items()
    )
    if unchanged:
        return False
    current.clear()
    current.update(rebuilt)
    return True


def _is_upstream_pbc_row(file_template: Any) -> bool:
    return (
        getattr(file_template, "fid", None) in _PHONEBOOK_PBC_FIDS
        and str(getattr(file_template, "name", "")) == "EF.ADN"
        and getattr(file_template, "rec_len", None) == _PHONEBOOK_PBC_RECORD_LEN
        and list(getattr(file_template, "ppath", None) or []) == [_PHONEBOOK_DF_FID]
    )


def install_phonebook_pbc_template() -> bool:
    """Name the DF.PHONEBOOK 4F60..4F67 template rows EF.PBC (``ef-pbc``).

    Upstream ``df_pb_files`` labels that range ``EF.ADN`` although
    ``PE_Definitions-3.3.1.asn`` carries ``ef-pbc`` and TCA SAIP v3.4.1
    Annex A (page 74) puts EF PBC there: linear fixed, 2-byte records, ARR
    record 5, default '00...00'. Two things follow. No template is
    registered under ``ef-pbc``, so a PE-PHONEBOOK or PE-TELECOM whose
    ``ef-pbc`` carries no explicit fileDescriptor raises ``ValueError:
    Cannot add File(ef-pbc) of unknown file_type None to tree`` and the
    package does not decode. And ``ef-adn`` resolves to the last row
    spelled EF.ADN, 4F67 in the PBC range, instead of its own 4F58. The
    rows are renamed on the live template objects (the DF.TELECOM and
    ADF.USIM templates hold copies of the same rows, so every registered
    template is walked), ``files_by_pename`` is rebuilt for the templates
    touched, and the result is verified. A pySim that already names the
    rows EF.PBC leaves this a no-op. Evidence and the upstream patch:
    ``upstream_patches/osmocom-pysim-saip-implicit-template-ppath/`` (bug 2).
    """
    renamed = 0
    touched: list[Any] = []
    for template in _registered_templates():
        for file_template in list(getattr(template, "files", None) or []):
            if _is_upstream_pbc_row(file_template) is False:
                continue
            file_template.name = "EF.PBC"
            file_template.pe_name = "ef-pbc"
            file_template.params = ["size", "sfi"]
            renamed += 1
            if not any(template is known for known in touched):
                touched.append(template)
    for template in touched:
        _rebuild_files_by_pename(template)
    for template in _registered_templates():
        pbc_rows = [
            file_template
            for file_template in list(getattr(template, "files", None) or [])
            if getattr(file_template, "fid", None) in _PHONEBOOK_PBC_FIDS
            and list(getattr(file_template, "ppath", None) or []) == [_PHONEBOOK_DF_FID]
        ]
        if len(pbc_rows) == 0:
            continue
        wrong = [row for row in pbc_rows if str(getattr(row, "pe_name", "")) != "ef-pbc"]
        index = getattr(template, "files_by_pename", None) or {}
        if wrong or "ef-pbc" not in index:
            raise SaipPhonebookTemplateMismatch(
                "%s still carries %d DF.PHONEBOOK rows in 4F60..4F67 that are "
                "not ef-pbc after the EF.PBC compensation; the compensation "
                "no longer models this pySim." % (template.__name__, len(wrong))
            )
    return renamed > 0


def install_template_range_start_fids() -> bool:
    """Resolve a ranged template file to the first FID of its range.

    TCA SAIP v3.4.1 §9.1 (page 69): "In case of File ID ranges the File ID
    of the first instance is set to the start value of the range." pySim
    lists a ranged file once per FID under one ``pe_name`` (EF.ADN is eight
    rows, 4F58 to 4F5F) and ``ProfileTemplate.__init_subclass__`` fills
    ``files_by_pename`` by plain assignment, so the last row wins: a
    ``File`` without an explicit fileID reports 4F5F for EF.ADN, 4F67 for
    EF.PBC and 4F8F for EF.UID, while the eUICC creates 4F58, 4F60 and
    4F88 and a profile's own EF.PBR record points there. ``files_by_pename``
    is rebuilt first-listed-wins on every registered template and the
    result is verified against the lowest FID of each name, so a pySim
    that lists a range in another order is reported rather than trusted.
    Evidence and the upstream patch:
    ``upstream_patches/osmocom-pysim-saip-template-range-fid/``.
    """
    changed = 0
    for template in _registered_templates():
        if _rebuild_files_by_pename(template):
            changed += 1
    for template in _registered_templates():
        rows_by_name: dict[str, list[Any]] = {}
        for file_template in list(getattr(template, "files", None) or []):
            rows_by_name.setdefault(str(file_template.pe_name), []).append(file_template)
        index = getattr(template, "files_by_pename", None) or {}
        for pe_name, rows in rows_by_name.items():
            chosen = index.get(pe_name)
            fids = [
                row.fid
                for row in rows
                if isinstance(getattr(row, "fid", None), int)
                and isinstance(row.fid, bool) is False
            ]
            if chosen is rows[0] and (not fids or chosen.fid == min(fids)):
                continue
            raise SaipTemplateRangeFidMismatch(
                "%s resolves %r to FID %s; the first row of the range carries "
                "%s. The range-start compensation no longer models this pySim."
                % (
                    template.__name__,
                    pe_name,
                    "%04X" % chosen.fid if chosen is not None and chosen.fid is not None else None,
                    "%04X" % min(fids) if fids else None,
                )
            )
    return changed > 0
