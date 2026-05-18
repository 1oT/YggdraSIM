# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""pySim profile-template registry adapter.

Bridges pySim's ``ProfileTemplateRegistry`` (TCA SAIP §9 / Annex A
"File Structure Templates Definition") into the simulator's flat
``_FILE_SPECS`` registry. Two services are exposed:

``pysim_file_template_registry()``
    Returns an immutable dict ``{pe_name: tuple[FileTemplateSnapshot]}``
    capturing every ``FileTemplate`` registered against any
    ``ProfileTemplate``. The same ``pe_name`` can appear in several
    templates (e.g. ``ef-imsi`` lives in ``FilesUsimMandatory`` and
    ``FilesUsimMandatoryV2``); the snapshots preserve all of them so
    callers can disambiguate by parent context.

``apply_pysim_augmentations(specs)``
    Mutates a ``_FILE_SPECS``-shaped dict in place by overlaying
    pySim metadata onto entries that match by ``pe_name`` and FID. Only
    fills gaps -- never overrides an existing SFI, structure or FID --
    so the simulator's hand-curated parent-context anchors remain
    authoritative.

The adapter intentionally tolerates pySim being absent (e.g. minimal
deploys without the ``pySim-shell`` dependency installed): both helpers
become no-ops in that case so the simulator continues to boot from the
literal ``_FILE_SPECS`` table alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


_PYSIM_FTYPE_TO_STRUCTURE: dict[str, str] = {
    "TR": "transparent",
    "LF": "linear-fixed",
    "CY": "cyclic",
    "BT": "ber-tlv",
}


_STRUCTURE_TO_PYSIM_FTYPE: dict[str, str] = {
    structure: ftype for ftype, structure in _PYSIM_FTYPE_TO_STRUCTURE.items()
}


@dataclass(frozen=True)
class FileTemplateSnapshot:
    """Frozen, dependency-free view of a pySim ``FileTemplate``.

    The fields mirror the SAIP §9 file-spec columns. Tuples are used
    instead of lists so the snapshot is hashable and safe to share
    between concurrent decoders.
    """

    pe_name: str
    name: str
    fid_hex: str
    structure: str
    file_type: str
    sfi: int | None
    arr: int | None
    default_val: str | None
    default_val_repeat: bool
    content_rqd: bool
    params: tuple[str, ...]
    ass_serv: tuple[Any, ...]
    high_update: bool
    ppath: tuple[int, ...]
    nb_rec: int | None
    rec_len: int | None
    file_size: int | None
    template_oid: str
    template_class: str


_REGISTRY_CACHE: dict[str, tuple[FileTemplateSnapshot, ...]] | None = None


def _import_pysim_templates() -> Any:
    """Return the pySim ``templates`` module, or ``None`` if absent."""
    try:
        import pySim.esim.saip.templates as templates_module  # noqa: WPS433
    except ImportError:
        return None
    except Exception:
        # pySim's import side-effects can raise on malformed installs;
        # treat any failure the same as "not available".
        return None
    return templates_module


def _snapshot_from_filetemplate(ft: Any, tpl: Any) -> FileTemplateSnapshot | None:
    """Project a pySim ``FileTemplate`` onto a ``FileTemplateSnapshot``.

    Returns ``None`` for non-EF entries (MF/DF/ADF anchors) so the
    caller can drop them without further filtering.
    """
    file_type = str(getattr(ft, "file_type", "") or "")
    if file_type not in _PYSIM_FTYPE_TO_STRUCTURE:
        return None
    structure = _PYSIM_FTYPE_TO_STRUCTURE[file_type]
    raw_fid = getattr(ft, "fid", None)
    fid_hex = "%04X" % int(raw_fid) if isinstance(raw_fid, int) else ""
    params = tuple(str(p) for p in (getattr(ft, "params", None) or ()))
    ass_serv_raw = getattr(ft, "ass_serv", None) or ()
    ass_serv: tuple[Any, ...] = tuple(ass_serv_raw)
    ppath_raw = getattr(ft, "ppath", None) or ()
    ppath = tuple(int(x) for x in ppath_raw if isinstance(x, int))
    pe_name = str(getattr(ft, "pe_name", "") or "")
    name = str(getattr(ft, "name", "") or "")
    sfi_raw = getattr(ft, "sfi", None)
    sfi = int(sfi_raw) if isinstance(sfi_raw, int) else None
    arr_raw = getattr(ft, "arr", None)
    arr = int(arr_raw) if isinstance(arr_raw, int) else None
    default_val_raw = getattr(ft, "default_val", None)
    default_val = str(default_val_raw) if isinstance(default_val_raw, str) else None
    nb_rec = getattr(ft, "nb_rec", None) if file_type in ("LF", "CY") else None
    rec_len = getattr(ft, "rec_len", None) if file_type in ("LF", "CY") else None
    file_size = getattr(ft, "file_size", None) if file_type in ("TR", "BT") else None
    if not isinstance(nb_rec, int):
        nb_rec = None
    if not isinstance(rec_len, int):
        rec_len = None
    if not isinstance(file_size, int):
        file_size = None
    template_oid = str(getattr(tpl, "oid", "") or "")
    template_class = str(getattr(tpl, "__name__", "") or "")
    return FileTemplateSnapshot(
        pe_name=pe_name,
        name=name,
        fid_hex=fid_hex,
        structure=structure,
        file_type=file_type,
        sfi=sfi,
        arr=arr,
        default_val=default_val,
        default_val_repeat=bool(getattr(ft, "default_val_repeat", False)),
        content_rqd=bool(getattr(ft, "content_rqd", False)),
        params=params,
        ass_serv=ass_serv,
        high_update=bool(getattr(ft, "high_update", False)),
        ppath=ppath,
        nb_rec=nb_rec,
        rec_len=rec_len,
        file_size=file_size,
        template_oid=template_oid,
        template_class=template_class,
    )


def _build_registry() -> dict[str, tuple[FileTemplateSnapshot, ...]]:
    templates_module = _import_pysim_templates()
    if templates_module is None:
        return {}
    registry_cls = getattr(templates_module, "ProfileTemplateRegistry", None)
    if registry_cls is None:
        return {}
    by_oid = getattr(registry_cls, "by_oid", None)
    if isinstance(by_oid, dict) is False:
        return {}
    accumulator: dict[str, list[FileTemplateSnapshot]] = {}
    # Iteration order is insertion order (V1 -> V2 -> V3 -> V4),
    # which we preserve so callers can prefer "latest" deterministically.
    for tpl in by_oid.values():
        files = getattr(tpl, "files", None) or ()
        for ft in files:
            snap = _snapshot_from_filetemplate(ft, tpl)
            if snap is None:
                continue
            if not snap.pe_name:
                continue
            accumulator.setdefault(snap.pe_name, []).append(snap)
    return {pe_name: tuple(items) for pe_name, items in accumulator.items()}


def pysim_file_template_registry() -> dict[str, tuple[FileTemplateSnapshot, ...]]:
    """Cached snapshot of every pySim ``FileTemplate`` keyed by ``pe_name``."""
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is None:
        _REGISTRY_CACHE = _build_registry()
    return _REGISTRY_CACHE


def reset_registry_cache() -> None:
    """Drop the cached registry; intended for tests."""
    global _REGISTRY_CACHE
    _REGISTRY_CACHE = None


def _select_snapshot(
    pe_name: str,
    fid_hex: str,
    candidates: tuple[FileTemplateSnapshot, ...],
) -> FileTemplateSnapshot | None:
    """Pick the most relevant pySim snapshot for an existing ``_FILE_SPECS`` entry.

    Preference order:
      1. FID match (parent-context aware -- only same FID can collapse safely).
      2. If the local FID is empty, take the latest snapshot (last registered).
      3. Otherwise return ``None`` so the caller leaves the local entry alone.
    """
    if not candidates:
        return None
    norm_fid = fid_hex.upper()
    if norm_fid:
        for snap in candidates:
            if snap.fid_hex.upper() == norm_fid:
                return snap
        return None
    return candidates[-1]


def apply_pysim_augmentations(specs: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Fill in missing pySim-derived metadata on a ``_FILE_SPECS`` dict.

    The function mutates ``specs`` in place and also returns it so the
    caller can chain. The contract:

      * Existing ``fid``, ``structure`` and ``name`` values are kept --
        the simulator's anchors are authoritative.
      * ``sfi`` is filled in only when the local entry has ``None``.
      * Rich-metadata fields (``arr``, ``default_val``,
        ``default_val_repeat``, ``content_rqd``, ``params``,
        ``ass_serv``, ``high_update``, ``nb_rec``, ``rec_len``,
        ``file_size``, ``ppath``, ``template_oid``, ``template_class``)
        are added only if not already present, using
        ``dict.setdefault``.

    Aliases (pe_names that pySim knows about but our table does not)
    are NOT injected here; that disambiguation requires parent-context
    awareness which is handled by the FCP-decoder and GFM-walker layers.
    """
    registry = pysim_file_template_registry()
    if not registry:
        return specs
    for pe_name, spec in specs.items():
        candidates = registry.get(pe_name)
        if not candidates:
            continue
        local_fid = str(spec.get("fid", "") or "")
        snap = _select_snapshot(pe_name, local_fid, candidates)
        if snap is None:
            continue
        if spec.get("sfi") is None and snap.sfi is not None:
            spec["sfi"] = snap.sfi
        spec.setdefault("arr", snap.arr)
        spec.setdefault("default_val", snap.default_val)
        spec.setdefault("default_val_repeat", snap.default_val_repeat)
        spec.setdefault("content_rqd", snap.content_rqd)
        spec.setdefault("params", snap.params)
        spec.setdefault("ass_serv", snap.ass_serv)
        spec.setdefault("high_update", snap.high_update)
        spec.setdefault("nb_rec", snap.nb_rec)
        spec.setdefault("rec_len", snap.rec_len)
        spec.setdefault("file_size", snap.file_size)
        spec.setdefault("ppath", snap.ppath)
        spec.setdefault("template_oid", snap.template_oid)
        spec.setdefault("template_class", snap.template_class)
    return specs


def _canonical_ef_name(name: str) -> str:
    """Normalise EF names so ``EF.SUPI_NAI`` and ``EF.SUPI-NAI`` collide.

    pySim uses ``_`` (e.g. ``EF.SUPI_NAI``) while our table uses ``-``
    (``EF.SUPI-NAI``). Both encode the same logical EF. The same
    relaxation handles ``EF.UAC_AIC`` vs ``EF.UAC-AIC`` and the
    ``EF.5G_PROSE_*`` vs ``EF.5G-PROSE-*`` family.
    """
    return name.upper().replace("_", "-")


@dataclass(frozen=True)
class FcpAttributes:
    """Decoded view of a SAIP ``Fcp`` element (TS 102 221 §11.1.1.4).

    The class mirrors the attributes pySim's ``File.from_fileDescriptor``
    sets, plus our private ``linkPath`` extension (PRIVATE 7) which
    pySim does not handle. All numeric fields default to ``None`` so
    downstream consumers can distinguish "not present in FCP" from
    "explicitly zero".
    """

    fid: int | None = None
    sfi: int | None = None
    arr: bytes | None = None
    lcsi: int | None = None
    nb_rec: int | None = None
    rec_len: int | None = None
    file_size: int | None = None
    file_type: str = ""
    structure: str = ""
    shareable: bool = True
    high_update: bool = False
    read_and_update_when_deact: bool = False
    fill_pattern: bytes | None = None
    fill_pattern_repeat: bool = False
    pstdo: bytes | None = None
    df_name: bytes | None = None
    link_path: tuple[str, ...] = field(default_factory=tuple)

    @property
    def fid_hex(self) -> str:
        if self.fid is None:
            return ""
        return "%04X" % int(self.fid)

    @property
    def record_length(self) -> int:
        return int(self.rec_len or 0)

    @property
    def transparent_size(self) -> int:
        """Return the declared transparent file size from the FCP template in bytes."""
        if self.file_type in ("LF", "CY"):
            if self.nb_rec and self.rec_len:
                return int(self.nb_rec) * int(self.rec_len)
        if self.file_type in ("TR", "BT"):
            return int(self.file_size or 0)
        return int(self.file_size or 0)


def _decode_link_path_from_descriptor(descriptor: Any) -> tuple[str, ...]:
    """Extract the SAIP ``Fcp.linkPath`` PRIVATE 7 octet string.

    See SAIP / TCA Profile Interoperability v2.3.1 §8.3.5: the OCTET
    STRING is a concatenation of 2-byte FIDs from the MF down to the
    target. Empty payload denotes "turn the templated link file into
    an independent file"; malformed (odd length) payloads are dropped
    rather than half-decoded.
    """
    if isinstance(descriptor, dict) is False:
        return ()
    raw = descriptor.get("linkPath")
    if raw is None:
        return ()
    if isinstance(raw, (bytes, bytearray, memoryview)) is False:
        return ()
    payload = bytes(raw)
    if len(payload) == 0 or len(payload) % 2 != 0:
        return ()
    return tuple(
        payload[offset : offset + 2].hex().upper()
        for offset in range(0, len(payload), 2)
    )


def _import_pysim_file_class() -> Any:
    try:
        import pySim.esim.saip as saip_module  # noqa: WPS433
    except ImportError:
        return None
    except Exception:
        return None
    return getattr(saip_module, "File", None)


def _coerce_descriptor_dict(value: Any) -> dict[str, Any]:
    """Normalise an asn1tools-decoded ``Fcp`` value to a plain dict.

    asn1tools represents SEQUENCEs of OPTIONAL elements as either
    dicts (when fully fielded) or as lists of (name, value) tuples
    when only a subset is populated. We accept both shapes so the
    decoder works with either ``decoded["mf-header"]`` (already a
    dict) or ``decoded["templateID"]`` (tuple list).
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, list) is False:
        return {}
    out: dict[str, Any] = {}
    for item in value:
        if isinstance(item, tuple) is False or len(item) != 2:
            continue
        out[str(item[0])] = item[1]
    return out


def decode_fcp_attributes(fcp: Any) -> FcpAttributes:
    """Decode a ``Fcp``-shaped value into a typed ``FcpAttributes``.

    Routes through pySim's ``File.from_fileDescriptor`` so the parse
    of the inner ``fileDescriptor`` BER blob, ``proprietaryEFInfo``
    Special-File-Information byte, fill/repeat pattern and
    ``efFileSize`` GreedyInteger encoding all stay aligned with the
    upstream SAIP toolchain. The PRIVATE 7 ``linkPath`` extension is
    decoded separately because pySim does not yet recognise it.

    ``fcp`` may be:
      * a dict produced by asn1tools when decoding ``Fcp``
      * a list of (key, value) tuples for the same SEQUENCE
      * any value not matching the above -- returns a default-empty
        ``FcpAttributes`` so callers can branch on ``file_type==""``.
    """
    descriptor = _coerce_descriptor_dict(fcp)
    link_path = _decode_link_path_from_descriptor(descriptor)
    file_cls = _import_pysim_file_class()
    if file_cls is None or not descriptor:
        return FcpAttributes(link_path=link_path)
    try:
        instance = file_cls("ef-fcp-decoder")
        instance.from_fileDescriptor(descriptor)
    except Exception:
        return FcpAttributes(link_path=link_path)
    file_type = str(getattr(instance, "file_type", "") or "")
    structure = _PYSIM_FTYPE_TO_STRUCTURE.get(file_type, "")
    file_size_raw = getattr(instance, "_file_size", 0)
    try:
        file_size_int = int(file_size_raw) if file_size_raw else None
    except (TypeError, ValueError):
        file_size_int = None
    raw_lcsi = getattr(instance, "lcsi", None)
    # asn1tools decodes ``lcsi`` as an OCTET STRING (single byte); pySim
    # stores the raw bytes verbatim. Normalise to the integer life-cycle
    # status indicator so consumers do not have to repeat the conversion.
    if isinstance(raw_lcsi, (bytes, bytearray, memoryview)) and len(raw_lcsi) >= 1:
        lcsi_int: int | None = int(bytes(raw_lcsi)[0])
    elif isinstance(raw_lcsi, int):
        lcsi_int = int(raw_lcsi)
    else:
        lcsi_int = None
    return FcpAttributes(
        fid=getattr(instance, "fid", None),
        sfi=getattr(instance, "sfi", None),
        arr=getattr(instance, "arr", None),
        lcsi=lcsi_int,
        nb_rec=getattr(instance, "nb_rec", None),
        rec_len=getattr(instance, "rec_len", None),
        file_size=file_size_int,
        file_type=file_type,
        structure=structure,
        shareable=bool(getattr(instance, "shareable", True)),
        high_update=bool(getattr(instance, "high_update", False)),
        read_and_update_when_deact=bool(
            getattr(instance, "read_and_update_when_deact", False)
        ),
        fill_pattern=getattr(instance, "fill_pattern", None),
        fill_pattern_repeat=bool(getattr(instance, "fill_pattern_repeat", False)),
        pstdo=getattr(instance, "pstdo", None),
        df_name=getattr(instance, "df_name", None),
        link_path=link_path,
    )


def _import_pysim_saip_module() -> Any:
    """Return the pySim ``saip`` package, or ``None`` if absent."""
    try:
        import pySim.esim.saip as saip_module  # noqa: WPS433
    except ImportError:
        return None
    except Exception:
        return None
    return saip_module


def pysim_pe_wrapper(pe_type: str, decoded: dict[str, Any]) -> Any | None:
    """Construct a pySim ``ProfileElement*`` wrapper for ``pe_type``.

    Returns the wrapper instance with ``decoded`` already attached and
    any ``_post_decode`` hook applied. The wrapper is purely an
    interpretation layer: every consumer continues to read from the
    raw asn1tools dict and falls back gracefully when pySim is not
    available or constructor validation fails.

    The mapping between PE-type strings and wrapper classes follows
    ``ProfileElement.class_for_petype`` upstream.
    """
    saip_module = _import_pysim_saip_module()
    if saip_module is None:
        return None
    profile_element_cls = getattr(saip_module, "ProfileElement", None)
    if profile_element_cls is None:
        return None
    class_for_petype = getattr(profile_element_cls, "class_for_petype", None)
    if class_for_petype is None:
        return None
    pe_cls = class_for_petype(pe_type)
    if pe_cls is None:
        return None
    if isinstance(decoded, dict) is False:
        return None
    try:
        instance = pe_cls(decoded)
    except Exception:
        return None
    # ``_post_decode`` is an optional hook (only ``ProfileElementSD`` /
    # ``ProfileElementAKA`` / ``FsProfileElement`` define it). Calling
    # it explicitly is harmless when absent; pySim already runs it from
    # ``__init__`` for these classes, so we only need to retry when it
    # silently failed inside the constructor.
    if hasattr(instance, "_post_decode") and not getattr(instance, "_post_decoded", False):
        try:
            instance._post_decode()
            setattr(instance, "_post_decoded", True)
        except Exception:
            pass
    return instance


@dataclass(frozen=True)
class PySimSdKeySnapshot:
    """Frozen view of a pySim ``SecurityDomainKey``.

    Mirrors GP Card Spec v2.3.1 §11.5 PUT KEY tuple shape so the
    caller can map it onto ``SimProfileSecurityDomainKey`` without
    re-importing pySim symbols at the use site.
    """

    key_version_number: int
    key_identifier: int
    key_usage_qualifier: int
    components: tuple[tuple[str, bytes, int], ...]


def pysim_sd_keys(decoded: dict[str, Any]) -> tuple[PySimSdKeySnapshot, ...]:
    """Return SD ``keyList`` parsed via pySim's ``SecurityDomainKey``.

    Uses ``ProfileElementSD._post_decode`` which already calls
    ``SecurityDomainKey.from_saip_dict`` for every entry. ``components``
    is exposed as a tuple of ``(key_type_str, key_data, mac_length)``
    triples so the caller does not need to import pySim's KeyType
    enum.

    The function is fail-soft: a missing pySim install, a wrapper-
    construction error or a parse failure all yield an empty tuple.
    """
    wrapper = pysim_pe_wrapper("securityDomain", decoded)
    if wrapper is None:
        return ()
    keys = getattr(wrapper, "keys", None)
    if isinstance(keys, list) is False:
        return ()
    snapshots: list[PySimSdKeySnapshot] = []
    for key in keys:
        try:
            kvn = int(getattr(key, "key_version_number", 0) or 0) & 0xFF
            kid = int(getattr(key, "key_identifier", 0) or 0) & 0xFF
        except (TypeError, ValueError):
            continue
        usage = getattr(key, "key_usage_qualifier", None)
        usage_int = 0
        if isinstance(usage, dict):
            # KeyUsageQualifier is a Construct BitStruct; pySim parses it
            # into an OrderedDict of named bits. We collapse it back to
            # the GP §11.5 single-byte encoding so downstream code can
            # treat it uniformly.
            try:
                from pySim.esim.saip import KeyUsageQualifier  # noqa: WPS433

                usage_bytes = KeyUsageQualifier.build(usage)
                if isinstance(usage_bytes, (bytes, bytearray, memoryview)) and len(usage_bytes) >= 1:
                    usage_int = int(bytes(usage_bytes)[0])
            except Exception:
                usage_int = 0
        elif isinstance(usage, int):
            usage_int = int(usage) & 0xFF
        components_raw = getattr(key, "key_components", None) or ()
        components: list[tuple[str, bytes, int]] = []
        for comp in components_raw:
            comp_type = str(getattr(comp, "key_type", "") or "")
            comp_data_raw = getattr(comp, "key_data", b"")
            comp_data = (
                bytes(comp_data_raw)
                if isinstance(comp_data_raw, (bytes, bytearray, memoryview))
                else b""
            )
            try:
                mac_length = int(getattr(comp, "mac_length", 8) or 8)
            except (TypeError, ValueError):
                mac_length = 8
            components.append((comp_type, comp_data, mac_length))
        snapshots.append(
            PySimSdKeySnapshot(
                key_version_number=kvn,
                key_identifier=kid,
                key_usage_qualifier=usage_int,
                components=tuple(components),
            )
        )
    return tuple(snapshots)


def pysim_sd_scp_list(decoded: dict[str, Any]) -> tuple[tuple[int, int], ...]:
    """Return ``[(scp, i), ...]`` parsed from the C9 install parameters.

    Resolves SAIP §11.2.10 ``UICC SD Install Parameters`` tag C9 via
    pySim's ``ProfileElementSD.usip``. Each entry is the ``(SCP, i)``
    pair from GP Card Spec v2.3.1 Amendment D §7.5 (e.g. ``(3, 0x70)``
    for SCP03 with i=70). Returns ``()`` on failure.
    """
    wrapper = pysim_pe_wrapper("securityDomain", decoded)
    if wrapper is None:
        return ()
    usip = getattr(wrapper, "usip", None)
    if usip is None:
        return ()
    nested = getattr(usip, "nested_collection", None)
    if nested is None:
        return ()
    children = getattr(nested, "children", None) or []
    out: list[tuple[int, int]] = []
    for child in children:
        # Each SCP descriptor child carries an ``scp`` and ``i`` byte.
        scp = getattr(child, "scp", None)
        i_param = getattr(child, "i", None)
        if isinstance(scp, int) and isinstance(i_param, int):
            out.append((int(scp) & 0xFF, int(i_param) & 0xFF))
            continue
        # Fallback: the descriptor may expose a ``decoded`` dict
        decoded_dict = getattr(child, "decoded", None)
        if isinstance(decoded_dict, dict):
            scp_v = decoded_dict.get("scp")
            i_v = decoded_dict.get("i")
            if isinstance(scp_v, int) and isinstance(i_v, int):
                out.append((int(scp_v) & 0xFF, int(i_v) & 0xFF))
    return tuple(out)


@dataclass(frozen=True)
class GfmEntry:
    """Typed projection of one ``File`` produced by ``ProfileElementGFM``.

    Captures everything the simulator needs to materialise a
    ``SimProfileFsNode`` without having to reach back into pySim
    internals at the call site. ``path_fids`` is the full FID chain
    starting at MF (0x3F00) and ending with the file's own FID.
    """

    path_fids: tuple[int, ...]
    fid: int
    file_type: str
    df_name: bytes
    body: bytes
    sfi_raw: int | None
    arr: bytes | None
    lcsi: int | None
    rec_len: int | None
    nb_rec: int | None
    file_size: int | None
    high_update: bool
    read_and_update_when_deact: bool
    fill_pattern: bytes | None
    fill_pattern_repeat: bool
    pstdo: bytes | None
    link_path: tuple[str, ...]


def _gfm_collect_link_path(file_elements: Any) -> tuple[str, ...]:
    """Pull the PRIVATE 7 ``linkPath`` extension from a GFM tuple list.

    pySim's ``File.from_fileDescriptor`` does not yet recognise the
    SAIP §8.3.5 ``linkPath`` extension; we mirror the FCP-decoder's logic
    against the same descriptor blob so GFM-routed EFs still surface
    their explicit link target.
    """
    if isinstance(file_elements, list) is False:
        return ()
    for item in file_elements:
        if isinstance(item, tuple) is False or len(item) != 2:
            continue
        if str(item[0]) != "fileDescriptor":
            continue
        descriptor = _coerce_descriptor_dict(item[1])
        return _decode_link_path_from_descriptor(descriptor)
    return ()


def _decode_gfm_file(file_cls: Any, file_elements: list[tuple]) -> Any | None:
    """Run pySim's ``File.from_tuples`` on a single GFM tuple list.

    Returns the populated ``File`` instance, or ``None`` if pySim
    raises (e.g. unrecognised file-descriptor encoding). Decoupled from
    the walk so the path-anchoring loop stays compact.
    """
    try:
        instance = file_cls(None)
        instance.from_tuples(file_elements)
    except Exception:
        return None
    return instance


def _gfm_entry_from_file(
    instance: Any,
    path: list[int],
    file_elements: list[tuple],
) -> GfmEntry | None:
    """Project a decoded ``File`` instance onto a frozen ``GfmEntry``."""
    fid_attr = getattr(instance, "fid", None)
    if isinstance(fid_attr, int) is False:
        return None
    body_attr = getattr(instance, "_body", None)
    body_bytes = bytes(body_attr) if isinstance(body_attr, (bytes, bytearray, memoryview)) else b""
    df_name_attr = getattr(instance, "df_name", None)
    df_name_bytes = (
        bytes(df_name_attr)
        if isinstance(df_name_attr, (bytes, bytearray, memoryview))
        else b""
    )
    raw_lcsi = getattr(instance, "lcsi", None)
    if isinstance(raw_lcsi, (bytes, bytearray, memoryview)) and len(raw_lcsi) >= 1:
        lcsi_int: int | None = int(bytes(raw_lcsi)[0])
    elif isinstance(raw_lcsi, int):
        lcsi_int = int(raw_lcsi)
    else:
        lcsi_int = None
    sfi_attr = getattr(instance, "sfi", None)
    sfi_raw = int(sfi_attr) if isinstance(sfi_attr, int) else None
    file_size_raw = getattr(instance, "_file_size", 0)
    try:
        file_size_int = int(file_size_raw) if file_size_raw else None
    except (TypeError, ValueError):
        file_size_int = None
    rec_len_attr = getattr(instance, "rec_len", None)
    nb_rec_attr = getattr(instance, "nb_rec", None)
    link_path = _gfm_collect_link_path(file_elements)
    return GfmEntry(
        path_fids=tuple(path + [int(fid_attr)]),
        fid=int(fid_attr),
        file_type=str(getattr(instance, "file_type", "") or ""),
        df_name=df_name_bytes,
        body=body_bytes,
        sfi_raw=sfi_raw,
        arr=getattr(instance, "arr", None),
        lcsi=lcsi_int,
        rec_len=int(rec_len_attr) if isinstance(rec_len_attr, int) else None,
        nb_rec=int(nb_rec_attr) if isinstance(nb_rec_attr, int) else None,
        file_size=file_size_int,
        high_update=bool(getattr(instance, "high_update", False)),
        read_and_update_when_deact=bool(getattr(instance, "read_and_update_when_deact", False)),
        fill_pattern=getattr(instance, "fill_pattern", None),
        fill_pattern_repeat=bool(getattr(instance, "fill_pattern_repeat", False)),
        pstdo=getattr(instance, "pstdo", None),
        link_path=link_path,
    )


def pysim_gfm_walk(decoded: dict[str, Any]) -> tuple[GfmEntry, ...]:
    """Decode a ``genericFileManagement`` PE into typed ``GfmEntry`` items.

    Replicates pySim's ``ProfileElementGFM.pe2files`` walk while
    keeping iteration in caller-controlled scope:

      * ``filePath b''`` rewinds to MF (TS 102 222 §6.5.4).
      * ``filePath 7F20...`` resets the parent chain to MF + decoded
        FIDs.
      * Each ``createFCP`` flushes the previous file (if any) and
        starts a fresh file_elements buffer.
      * After flushing, if the just-created file was a DF/ADF, the
        current parent chain is extended with its FID so subsequent
        EFs anchor under it -- mirroring the simulator's pre-Phase-D
        ``df_anchor`` semantics.

    Returns ``()`` when pySim is unavailable or the input is empty.
    """
    file_cls = _import_pysim_file_class()
    if file_cls is None:
        return ()
    if isinstance(decoded, dict) is False:
        return ()
    cmd_list = decoded.get("fileManagementCMD")
    if isinstance(cmd_list, list) is False:
        return ()

    entries: list[GfmEntry] = []
    path: list[int] = [0x3F00]
    file_elements: list[tuple] = []

    def _flush(current_path: list[int]) -> list[int]:
        nonlocal file_elements
        if not file_elements:
            return current_path
        instance = _decode_gfm_file(file_cls, file_elements)
        if instance is None:
            file_elements = []
            return current_path
        entry = _gfm_entry_from_file(instance, current_path, file_elements)
        file_elements = []
        if entry is None:
            return current_path
        entries.append(entry)
        # Promote the DF/ADF anchor so subsequent EFs without an
        # explicit filePath inherit the new parent. ``MF`` re-anchors
        # to root so a top-level MF createFCP doesn't extend the path.
        if entry.file_type in ("DF", "ADF"):
            return current_path + [entry.fid]
        if entry.file_type == "MF":
            return [entry.fid]
        return current_path

    for sequence in cmd_list:
        if isinstance(sequence, list) is False:
            continue
        for command in sequence:
            if isinstance(command, tuple) is False or len(command) != 2:
                continue
            tag = str(command[0] or "")
            value = command[1]
            if tag == "filePath":
                path = _flush(path)
                if isinstance(value, (bytes, bytearray, memoryview)):
                    if len(value) == 0:
                        path = [0x3F00]
                    else:
                        raw = bytes(value)
                        if len(raw) % 2 == 0:
                            path = [0x3F00] + [
                                int.from_bytes(raw[i:i + 2], "big")
                                for i in range(0, len(raw), 2)
                            ]
                continue
            if tag == "createFCP":
                path = _flush(path)
                file_elements = [("fileDescriptor", value)]
                continue
            if tag in ("fillFileOffset", "fillFileContent"):
                file_elements.append((tag, value))
                continue
    _flush(path)
    return tuple(entries)


def pysim_normalize_aka_decoded(decoded: dict[str, Any]) -> dict[str, Any]:
    """Apply pySim's ``ProfileElementAKA._fixup_sqnInit_dec`` normalisation.

    Constructs the wrapper which calls the fixup as part of
    ``_post_decode`` (asn1tools mishandles SEQUENCE OF with DEFAULT;
    pySim materialises the default ``'0x000000000000'`` placeholder
    into a 32-element list of 6-byte zeros). Returns the wrapper's
    ``decoded`` dict; falls back to the input dict unchanged when
    pySim is not available.
    """
    wrapper = pysim_pe_wrapper("akaParameter", decoded)
    if wrapper is None:
        return decoded
    return getattr(wrapper, "decoded", decoded) or decoded


def pysim_alias_specs_for(
    specs: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Return pySim pe_name aliases pointing at the same FID + EF name.

    Used by callers that want to accept BPP fixtures emitted with
    pySim's V2/V3 spelling (``ef-supi-nai``) while keeping the legacy
    spelling (``ef-supinai``) as the canonical key in ``_FILE_SPECS``.
    Aliases are only injected when *both* FID and the canonical EF
    name match -- this prevents conflating EFs that happen to share a
    FID across different parent DFs (e.g. ``ef-pbc`` 4F09 in
    DF.PHONEBOOK vs ``ef-supinai`` 4F09 in DF.5GS).

    Each alias holds an independent shallow copy of the anchor dict so
    later mutations of one entry do not bleed into the other.
    """
    registry = pysim_file_template_registry()
    if not registry:
        return {}
    fid_name_index: dict[tuple[str, str], str] = {}
    for pe_name, spec in specs.items():
        local_fid = str(spec.get("fid", "") or "").upper()
        local_name = _canonical_ef_name(str(spec.get("name", "") or ""))
        if local_fid and local_name:
            fid_name_index.setdefault((local_fid, local_name), pe_name)
    aliases: dict[str, dict[str, Any]] = {}
    for pe_name, candidates in registry.items():
        if pe_name in specs:
            continue
        for snap in candidates:
            key = (snap.fid_hex.upper(), _canonical_ef_name(snap.name))
            target_pe = fid_name_index.get(key)
            if target_pe is None:
                continue
            anchor = specs.get(target_pe)
            if anchor is None:
                continue
            alias = dict(anchor)
            alias["name"] = snap.name
            alias["alias_of"] = target_pe
            aliases[pe_name] = alias
            break
    return aliases


# ---------------------------------------------------------------------------
# Service-bit-table maps lifted from pySim
# ---------------------------------------------------------------------------
#
# pySim ships authoritative bit -> service-name dictionaries inside its
# spec-aligned EF classes:
#
#   * ``pySim.ts_31_102.EF_UST_map``         -- USIM Service Table
#   * ``pySim.ts_31_102.EF_EST_map``         -- USIM Enabled Services Table
#   * ``pySim.ts_31_102.EF_5G_PROSE_ST_map`` -- 5G ProSe Service Table
#   * ``pySim.ts_31_103.EF_IST_map``         -- ISIM Service Table
#   * ``pySim.ts_51_011.EF_SST_map``         -- (legacy) SIM Service Table
#
# The simulator historically duplicated these as hand-curated dicts inside
# ``Tools/ProfilePackage/saip_asn1_decode``. The duplication was a known
# drift hazard (TS releases bump the table every 6-12 months). The helpers
# below expose the upstream maps so the local copies can be replaced by an
# overlay at module load time, while still degrading gracefully when pySim
# is not installed (the hand-curated maps remain functional in that case).


_SERVICE_TABLE_CACHE: dict[str, dict[int, str]] | None = None


def _import_pysim_service_tables() -> dict[str, dict[int, str]]:
    """Import the pySim service-name maps; cached + tolerant of absence."""

    global _SERVICE_TABLE_CACHE
    if _SERVICE_TABLE_CACHE is not None:
        return _SERVICE_TABLE_CACHE

    tables: dict[str, dict[int, str]] = {}
    try:
        from pySim import ts_31_102 as _ts_31_102  # type: ignore[import-not-found]

        ust = getattr(_ts_31_102, "EF_UST_map", None)
        if isinstance(ust, dict):
            tables["UST"] = {int(k): str(v) for k, v in ust.items()}
        est = getattr(_ts_31_102, "EF_EST_map", None)
        if isinstance(est, dict):
            tables["EST"] = {int(k): str(v) for k, v in est.items()}
        prose = getattr(_ts_31_102, "EF_5G_PROSE_ST_map", None)
        if isinstance(prose, dict):
            tables["5G_PROSE_ST"] = {int(k): str(v) for k, v in prose.items()}
    except Exception:
        pass

    try:
        from pySim import ts_31_103 as _ts_31_103  # type: ignore[import-not-found]

        ist = getattr(_ts_31_103, "EF_IST_map", None)
        if isinstance(ist, dict):
            tables["IST"] = {int(k): str(v) for k, v in ist.items()}
    except Exception:
        pass

    try:
        from pySim import ts_51_011 as _ts_51_011  # type: ignore[import-not-found]

        sst = getattr(_ts_51_011, "EF_SST_map", None)
        if isinstance(sst, dict):
            tables["SST"] = {int(k): str(v) for k, v in sst.items()}
    except Exception:
        pass

    _SERVICE_TABLE_CACHE = tables
    return tables


def pysim_service_table(name: str) -> dict[int, str]:
    """Return a copy of the pySim service-name map for ``name``.

    ``name`` is one of ``"UST"``, ``"EST"``, ``"IST"``, ``"SST"``,
    ``"5G_PROSE_ST"``. Returns an empty dict when pySim is unavailable
    or the requested table is missing -- callers must therefore treat
    ``{}`` as "no overlay; keep the local copy".
    """

    table = _import_pysim_service_tables().get(str(name).upper())
    if table is None:
        return {}
    return dict(table)


def overlay_pysim_service_names(
    target: dict[int, str],
    table_name: str,
) -> dict[int, str]:
    """Overlay pySim's bit -> service-name mapping onto ``target``.

    Mutates ``target`` in place: every bit pySim defines becomes the
    authoritative value, while bits that exist only in the local map
    (unlikely, but possible while a TS draft lags pySim) are left
    untouched. Returns the same ``target`` dict for chaining.

    When pySim is not installed the call is a no-op so existing
    deployments retain their hand-curated copy.
    """

    overlay = pysim_service_table(table_name)
    if not overlay:
        return target
    target.update(overlay)
    return target


def reset_pysim_service_table_cache() -> None:
    """Clear the cached service-table import. Test-only entry point."""

    global _SERVICE_TABLE_CACHE
    _SERVICE_TABLE_CACHE = None


_INSPECTOR_OVERLAY_TARGETS: tuple[tuple[str, str], ...] = (
    ("_UST_SERVICE_NAMES", "UST"),
    ("_EST_SERVICE_NAMES", "EST"),
    ("_ISIM_SERVICE_NAMES", "IST"),
)


def apply_pysim_service_table_overlay_to_inspector() -> dict[str, int]:
    """Overlay pySim's TS service maps onto the SAIP inspector dicts.

    ``Tools/ProfilePackage/saip_asn1_decode`` ships hand-curated copies
    of the USIM / Enabled-Service / ISIM service-name tables so the
    inspector stays self-contained when pySim is absent. When pySim
    *is* present we prefer its upstream-tracked values; this helper
    walks the inspector module and replaces the relevant dicts in
    place.

    Returns a ``{table_name: entry_count}`` summary describing how many
    bits each overlay touched. Returns an empty dict and logs nothing
    when the inspector or pySim cannot be imported -- the simulator
    must continue to boot in stripped deployments.
    """

    try:
        from Tools.ProfilePackage import saip_asn1_decode as _inspector  # type: ignore[import-not-found]
    except Exception:
        return {}

    summary: dict[str, int] = {}
    for attr_name, table_name in _INSPECTOR_OVERLAY_TARGETS:
        target = getattr(_inspector, attr_name, None)
        if isinstance(target, dict) is False:
            continue
        overlay = pysim_service_table(table_name)
        if not overlay:
            continue
        target.update(overlay)
        summary[table_name] = len(overlay)
    return summary
