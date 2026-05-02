"""
Insert blank ProfileElement instances using pySim default constructors (same templates
as bundled ``saip-tool`` / ``pySim.esim.saip``). Intended for TRANSCODE-TUI rapid edits.
"""

from __future__ import annotations

import copy
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

from .saip_json_codec import (
    _DOCUMENT_META_KEYS,
    base_pe_type,
    build_decoded_document_from_sequence,
    build_profile_sequence_from_document,
    ensure_workspace_pysim_on_path,
)


def iter_option_list_specs(
    blocked: set[str],
) -> List[Tuple[str, str, str | None, bool]]:
    """
    Rows for a Textual ``OptionList``: (option_id, title, hint_or_none, disabled).

    First row is cancel; remaining rows follow ``list_pe_quick_add_rows``.
    """
    out: List[Tuple[str, str, str | None, bool]] = [
        ("_cancel", "-- Cancel --", None, False),
    ]
    for menu_id, title, hint in list_pe_quick_add_rows():
        disabled = menu_id in blocked
        out.append((menu_id, title, hint, disabled))
    return out


def list_pe_quick_add_rows() -> List[Tuple[str, str, str]]:
    """
    Ordered menu rows: (menu_id, title, short hint).

    ``menu_id`` is stable for bindings and tests; ``securityDomain`` is MNO-style SD,
    ``securityDomain_ssd`` is ``ProfileElementSSD``.
    """
    rows: List[Tuple[str, str, str]] = [
        ("header", "header", "profile header (version, ICCID, mandatory services)"),
        ("end", "end", "PE-sequence end marker"),
        ("mf", "mf", "master file + EF.ICCID / EF.DIR / EF.ARR shells"),
        ("telecom", "telecom", "DF.TELECOM"),
        ("cd", "cd", "DF.CD"),
        ("phonebook", "phonebook", "DF.PHONEBOOK (USIM)"),
        ("gsm-access", "gsm-access", "DF.GSM-ACCESS under ADF.USIM"),
        ("df-5gs", "df-5gs", "DF.5GS"),
        ("eap", "eap", "DF.EAP"),
        ("df-saip", "df-saip", "DF.SAIP"),
        ("df-snpn", "df-snpn", "DF.SNPN"),
        ("df-5gprose", "df-5gprose", "DF.5GProSe"),
        ("pinCodes", "pinCodes", "default PIN placeholders"),
        ("pukCodes", "pukCodes", "default PUK placeholders"),
        ("securityDomain", "securityDomain", "MNO ISD-P style SD skeleton"),
        ("securityDomain_ssd", "securityDomain (SSD)", "supplementary SD template (SAIP 11.2.12)"),
        ("application", "application", "blank application PE; fill loadBlock and instanceList manually"),
        ("nonStandard", "nonStandard", "issuer-defined PE with OID + OCTET STRING content"),
        ("usim", "usim", "ADF.USIM mandatory file shells"),
        ("opt-usim", "opt-usim", "ADF.USIM optional template"),
        ("isim", "isim", "ADF.ISIM mandatory file shells"),
        ("opt-isim", "opt-isim", "ADF.ISIM optional template"),
        ("akaParameter", "akaParameter", "MILENAGE placeholder keys"),
        ("genericFileManagement", "genericFileManagement", "empty GFM command list"),
    ]
    return rows


def menu_ids_blocked_if_present(pes: Any) -> set[str]:
    """
    PE types that must appear at most once in a normal profile. ``pes`` is a
    ``ProfileElementSequence`` from pySim.
    """
    blocked: set[str] = set()
    if len(pes.get_pes_for_type("header")) >= 1:
        blocked.add("header")
    if len(pes.get_pes_for_type("end")) >= 1:
        blocked.add("end")
    if len(pes.get_pes_for_type("mf")) >= 1:
        blocked.add("mf")
    return blocked


def _factory_map() -> Dict[str, Callable[[], Any]]:
    from pySim.esim.saip import (
        ProfileElementAKA,
        ProfileElementApplication,
        ProfileElementEnd,
        ProfileElementGFM,
        ProfileElementHeader,
        ProfileElementMF,
        ProfileElementPin,
        ProfileElement,
        ProfileElementPuk,
        ProfileElementSD,
        ProfileElementSSD,
        ProfileElementUSIM,
        ProfileElementOptUSIM,
        ProfileElementISIM,
        ProfileElementOptISIM,
        ProfileElementTelecom,
        ProfileElementCD,
        ProfileElementPhonebook,
        ProfileElementGsmAccess,
        ProfileElementDf5GS,
        ProfileElementEAP,
        ProfileElementDfSAIP,
        ProfileElementDfSNPN,
        ProfileElementDf5GProSe,
    )

    def _blank_nonstandard() -> Any:
        pe = ProfileElement(
            OrderedDict(
                {
                    "nonStandard-header": {"mandated": None},
                    "issuerID": "1.3.6.1.4.1.0",
                    "content": b"",
                }
            )
        )
        pe.type = "nonStandard"
        return pe

    mapping: Dict[str, Callable[[], Any]] = {
        "header": ProfileElementHeader,
        "end": ProfileElementEnd,
        "mf": ProfileElementMF,
        "telecom": ProfileElementTelecom,
        "cd": ProfileElementCD,
        "phonebook": ProfileElementPhonebook,
        "gsm-access": ProfileElementGsmAccess,
        "df-5gs": ProfileElementDf5GS,
        "eap": ProfileElementEAP,
        "df-saip": ProfileElementDfSAIP,
        "df-snpn": ProfileElementDfSNPN,
        "df-5gprose": ProfileElementDf5GProSe,
        "pinCodes": ProfileElementPin,
        "pukCodes": ProfileElementPuk,
        "securityDomain": ProfileElementSD,
        "securityDomain_ssd": ProfileElementSSD,
        "application": ProfileElementApplication,
        "nonStandard": _blank_nonstandard,
        "usim": ProfileElementUSIM,
        "opt-usim": ProfileElementOptUSIM,
        "isim": ProfileElementISIM,
        "opt-isim": ProfileElementOptISIM,
        "akaParameter": ProfileElementAKA,
        "genericFileManagement": ProfileElementGFM,
    }
    return mapping


_FILE_TYPE_HINTS: dict[str, str] = {
    "MF": "master file",
    "ADF": "application DF",
    "DF": "directory file",
    "TR": "transparent EF",
    "LF": "linear-fixed EF",
    "CY": "cyclic EF",
    "BT": "BER-TLV EF",
}


def _normalized_intro_lines(document: dict[str, Any]) -> list[str]:
    intro = document.get("intro", [])
    if isinstance(intro, list):
        return list(intro)
    return [str(intro)]


def _copy_document_meta(source_document: dict[str, Any], target_document: dict[str, Any]) -> None:
    for meta_key in _DOCUMENT_META_KEYS:
        if meta_key in source_document:
            target_document[meta_key] = copy.deepcopy(source_document[meta_key])


def _build_document_from_pes(pes: Any, source_document: dict[str, Any]) -> dict[str, Any]:
    pes._process_pelist()
    pes.renumber_identification()
    out_document = build_decoded_document_from_sequence(
        pes,
        intro_lines=_normalized_intro_lines(source_document),
    )
    _copy_document_meta(source_document, out_document)
    return out_document


def _section_keys(document: dict[str, Any]) -> list[str]:
    sections = document.get("sections", {})
    if isinstance(sections, dict) is False:
        raise ValueError("Document 'sections' must be an object.")
    return list(sections.keys())


def _section_index(document: dict[str, Any], section_key: str) -> int:
    keys = _section_keys(document)
    if section_key not in keys:
        raise ValueError(f"Unknown profile element key: {section_key!r}")
    return keys.index(section_key)


def _blocked_types_present(document: dict[str, Any]) -> set[str]:
    blocked: set[str] = set()
    for section_key in _section_keys(document):
        blocked.add(base_pe_type(section_key))
    return blocked


def _build_pe_from_snapshot(snapshot: dict[str, Any], pes: Any) -> Any:
    from pySim.esim.saip import ProfileElement

    pe_type = str(snapshot.get("type", "")).strip()
    if len(pe_type) == 0:
        raise ValueError("PE snapshot missing type.")
    decoded = copy.deepcopy(snapshot.get("decoded"))
    pe_cls = ProfileElement.class_for_petype(pe_type)
    if pe_cls is not None:
        pe = pe_cls(decoded, pe_sequence=pes)
    else:
        pe = ProfileElement(decoded, pe_sequence=pes)
        pe.type = pe_type
    if hasattr(pe, "_post_decode"):
        pe._post_decode()
    return pe


def _build_blank_pe_snapshot(menu_id: str) -> dict[str, Any]:
    factories = _factory_map()
    if menu_id not in factories:
        raise ValueError(f"Unknown quick-add menu id: {menu_id!r}")
    ctor = factories[menu_id]
    new_pe = ctor()
    if hasattr(new_pe, "_post_decode"):
        new_pe._post_decode()
    return {
        "type": str(new_pe.type),
        "decoded": copy.deepcopy(new_pe.decoded),
    }


def copy_pe_snapshot(
    document: dict[str, Any],
    *,
    section_key: str,
) -> dict[str, Any]:
    sections = document.get("sections", {})
    if isinstance(sections, dict) is False:
        raise ValueError("Document 'sections' must be an object.")
    if section_key not in sections:
        raise ValueError(f"Unknown profile element key: {section_key!r}")
    return {
        "type": base_pe_type(section_key),
        "decoded": copy.deepcopy(sections[section_key]),
    }


def _insert_index_for_anchor(
    document: dict[str, Any],
    *,
    anchor_key: str | None,
    insert_after: bool,
) -> int:
    if anchor_key is None:
        keys = _section_keys(document)
        for index, key in enumerate(keys):
            if base_pe_type(key) == "end":
                return index
        return len(keys)
    anchor_index = _section_index(document, anchor_key)
    anchor_type = base_pe_type(anchor_key)
    if insert_after:
        if anchor_type == "end":
            return anchor_index
        return anchor_index + 1
    if anchor_type == "header":
        return 1
    return anchor_index


def paste_pe_snapshot(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    snapshot: dict[str, Any],
    anchor_key: str | None = None,
    insert_after: bool = True,
) -> dict[str, Any]:
    ensure_workspace_pysim_on_path(workspace_root)
    pe_type = str(snapshot.get("type", "")).strip()
    if len(pe_type) == 0:
        raise ValueError("PE snapshot missing type.")
    if pe_type in {"header", "end", "mf"} and pe_type in _blocked_types_present(document):
        raise ValueError(f"Profile already contains PE type {pe_type!r}; duplicate not allowed.")

    pes = build_profile_sequence_from_document(document, workspace_root)
    insert_index = _insert_index_for_anchor(
        document,
        anchor_key=anchor_key,
        insert_after=insert_after,
    )
    new_pe = _build_pe_from_snapshot(snapshot, pes)
    new_pe.pe_sequence = pes
    pes.pe_list.insert(insert_index, new_pe)
    return _build_document_from_pes(pes, document)


def move_pe_in_document(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    section_key: str,
    direction: str,
) -> dict[str, Any]:
    ensure_workspace_pysim_on_path(workspace_root)
    if direction not in {"up", "down"}:
        raise ValueError(f"Unsupported move direction: {direction!r}")

    index = _section_index(document, section_key)
    keys = _section_keys(document)
    pe_type = base_pe_type(section_key)
    if pe_type in {"header", "end"}:
        raise ValueError(f"Cannot move anchored PE type {pe_type!r}.")

    target_index = index - 1 if direction == "up" else index + 1
    if target_index < 0 or target_index >= len(keys):
        raise ValueError(f"Cannot move {direction}; already at boundary.")
    target_type = base_pe_type(keys[target_index])
    if target_type in {"header", "end"}:
        raise ValueError(f"Cannot move {pe_type!r} {direction} across anchored PE {target_type!r}.")

    pes = build_profile_sequence_from_document(document, workspace_root)
    pe = pes.pe_list.pop(index)
    pes.pe_list.insert(target_index, pe)
    return _build_document_from_pes(pes, document)


def remove_pe_from_document(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    section_key: str,
) -> dict[str, Any]:
    ensure_workspace_pysim_on_path(workspace_root)
    index = _section_index(document, section_key)
    pe_type = base_pe_type(section_key)
    if pe_type in {"header", "end"}:
        raise ValueError(f"Cannot remove anchored PE type {pe_type!r}.")

    pes = build_profile_sequence_from_document(document, workspace_root)
    pes.pe_list.pop(index)
    return _build_document_from_pes(pes, document)


def _section_pe_from_document(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    section_key: str,
) -> tuple[Any, Any]:
    ensure_workspace_pysim_on_path(workspace_root)
    pes = build_profile_sequence_from_document(document, workspace_root)
    index = _section_index(document, section_key)
    try:
        pe = pes.pe_list[index]
    except IndexError as exc:
        raise ValueError(f"Unknown profile element key: {section_key!r}") from exc
    return (pes, pe)


def _filesystem_template_for_pe(pe: Any) -> Any:
    from pySim.esim.saip import templates

    if hasattr(pe, "create_file") is False:
        raise ValueError(
            f"PE type {getattr(pe, 'type', '<unknown>')!r} does not support template-based file additions."
        )
    template_id = getattr(pe, "templateID", None)
    if isinstance(template_id, str) is False or len(template_id.strip()) == 0:
        raise ValueError(
            f"PE type {getattr(pe, 'type', '<unknown>')!r} does not expose a filesystem template."
        )
    template = templates.ProfileTemplateRegistry.get_by_oid(template_id)
    if template is None:
        raise ValueError(
            f"Could not resolve filesystem template {template_id!r} for PE type {getattr(pe, 'type', '<unknown>')!r}."
        )
    return template


def _template_file_for_pename(template: Any, pename: str | None) -> Any | None:
    normalized = str(pename or "").strip()
    if len(normalized) == 0:
        return None
    candidate = getattr(template, "files_by_pename", {}).get(normalized)
    if candidate is not None:
        return candidate
    for file_template in getattr(template, "files", []):
        if str(getattr(file_template, "pe_name", "")).strip() == normalized:
            return file_template
    return None


def _template_root_children(template: Any) -> list[Any]:
    if getattr(template, "extends", None) is not None:
        return [
            file_template
            for file_template in getattr(template, "files", [])
            if getattr(file_template, "parent", None) is None
        ]
    base_df = template.base_df()
    return list(getattr(base_df, "children", []))


def _template_context_from_key(template: Any, context_key: str | None) -> Any | None:
    focus_template = _template_file_for_pename(template, context_key)
    if focus_template is None:
        return None
    focus_type = str(getattr(focus_template, "file_type", "") or "").upper()
    if focus_type in {"MF", "ADF", "DF"}:
        context_template = focus_template
    else:
        context_template = getattr(focus_template, "parent", None)
    base_df = template.base_df()
    if (
        context_template is not None
        and getattr(template, "extends", None) is None
        and str(getattr(context_template, "pe_name", "") or "")
        == str(getattr(base_df, "pe_name", "") or "")
    ):
        return None
    return context_template


def _template_boundary(template: Any, context_template: Any | None) -> Any | None:
    if context_template is not None:
        return context_template
    if getattr(template, "extends", None) is not None:
        return None
    return template.base_df()


def _relative_template_ancestors(file_template: Any, boundary: Any | None) -> list[Any]:
    ancestors: list[Any] = []
    current = getattr(file_template, "parent", None)
    while current is not None and current is not boundary:
        ancestors.append(current)
        current = getattr(current, "parent", None)
    ancestors.reverse()
    return ancestors


def _iter_template_descendants(nodes: list[Any]) -> list[Any]:
    out: list[Any] = []
    for node in nodes:
        out.append(node)
        children = list(getattr(node, "children", []))
        if len(children) > 0:
            out.extend(_iter_template_descendants(children))
    return out


def _context_label_for_template(template: Any, context_template: Any | None) -> str:
    if context_template is None:
        base_df = template.base_df()
        return str(getattr(base_df, "name", "") or getattr(base_df, "pe_name", "") or "root")
    return str(
        getattr(context_template, "name", "")
        or getattr(context_template, "pe_name", "")
        or "root"
    )


def _file_option_title(
    file_template: Any,
    *,
    relative_ancestors: list[Any] | None = None,
) -> str:
    names: list[str] = []
    for ancestor in relative_ancestors or []:
        ancestor_name = str(getattr(ancestor, "name", "") or "").strip()
        if len(ancestor_name) > 0:
            names.append(ancestor_name)
    title = str(
        getattr(file_template, "name", "")
        or getattr(file_template, "pe_name", "")
        or "file"
    ).strip()
    if len(title) > 0:
        names.append(title)
    display = " / ".join(names) if len(names) > 0 else "file"
    fid = getattr(file_template, "fid", None)
    if isinstance(fid, int):
        return f"{display} ({fid:04X})"
    return display


def _file_option_hint(
    file_template: Any,
    *,
    missing_ancestors: list[Any] | None = None,
    arr_summary: str | None = None,
) -> str | None:
    parts: list[str] = []
    file_type = str(getattr(file_template, "file_type", "") or "").upper()
    hint = _FILE_TYPE_HINTS.get(file_type)
    if hint is not None:
        parts.append(hint)
    elif len(file_type) > 0:
        parts.append(file_type)
    missing_names = [
        str(getattr(ancestor, "name", "") or "").strip()
        for ancestor in missing_ancestors or []
        if len(str(getattr(ancestor, "name", "") or "").strip()) > 0
    ]
    if len(missing_names) > 0:
        parts.append("creates " + " / ".join(missing_names))
    arr_hint = _file_arr_hint(file_template, arr_summary=arr_summary)
    if arr_hint is not None:
        parts.append(arr_hint)
    if len(parts) == 0:
        return None
    return "; ".join(parts)


def _file_arr_hint(
    file_template: Any,
    *,
    arr_summary: str | None = None,
) -> str | None:
    arr = getattr(file_template, "arr", None)
    if isinstance(arr, int) is False:
        return None
    normalized_summary = str(arr_summary or "").strip()
    if len(normalized_summary) > 0:
        return f"ARR {arr}: {normalized_summary}"
    return f"ARR record {arr}"


def _merge_option_hints(*hint_values: str | None) -> str | None:
    parts: list[str] = []
    for hint_value in hint_values:
        text = str(hint_value or "").strip()
        if len(text) == 0:
            continue
        if text in parts:
            continue
        parts.append(text)
    if len(parts) == 0:
        return None
    return "; ".join(parts)


def _document_section_value(document: dict[str, Any], section_key: str) -> dict[str, Any] | None:
    sections = document.get("sections")
    if isinstance(sections, dict) is False:
        return None
    section_value = sections.get(section_key)
    if isinstance(section_value, dict) is False:
        return None
    return section_value


def _arr_summary_for_pe_section(
    document: dict[str, Any],
    *,
    section_key: str,
    file_template: Any,
) -> str | None:
    arr = getattr(file_template, "arr", None)
    if isinstance(arr, int) is False:
        return None
    section_value = _document_section_value(document, section_key)
    if section_value is None:
        return None
    from .saip_asn1_decode import describe_arr_record_from_section

    return describe_arr_record_from_section(
        section_value,
        record_number=arr,
    )


def _arr_summary_for_gfm_section(
    document: dict[str, Any],
    *,
    section_key: str,
    context_path: list[int] | tuple[int, ...],
    file_template: Any,
) -> str | None:
    arr = getattr(file_template, "arr", None)
    if isinstance(arr, int) is False:
        return None
    section_value = _document_section_value(document, section_key)
    if section_value is None:
        return None
    from .saip_asn1_decode import describe_arr_record_from_gfm_section

    return describe_arr_record_from_gfm_section(
        section_value,
        context_path=context_path,
        record_number=arr,
    )


def _minimal_big_endian_bytes(value: int) -> bytes:
    normalized = int(value)
    if normalized < 0:
        raise ValueError("Integer field must not be negative.")
    width = max(1, (normalized.bit_length() + 7) // 8)
    return normalized.to_bytes(width, "big", signed=False)


def _normalize_optional_int_override(value: Any, *, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer.")
    if isinstance(value, int):
        normalized = int(value)
    else:
        text = str(value or "").strip()
        if len(text) == 0:
            return None
        if text.isdigit() is False:
            raise ValueError(f"{label} must be a decimal integer.")
        normalized = int(text)
    if normalized < 0:
        raise ValueError(f"{label} must not be negative.")
    return normalized


def _file_override_defaults_from_template(
    file_template: Any,
    *,
    arr_summary: str | None = None,
) -> dict[str, str] | None:
    defaults: dict[str, str] = {
        "file_name": str(
            getattr(file_template, "name", "")
            or getattr(file_template, "pe_name", "")
            or "file"
        ).strip(),
        "file_type": str(getattr(file_template, "file_type", "") or "").strip().upper(),
    }
    supported = False
    sfi = getattr(file_template, "sfi", None)
    if isinstance(sfi, int):
        defaults["short_efid"] = str(int(sfi))
        supported = True
    arr = getattr(file_template, "arr", None)
    if isinstance(arr, int):
        defaults["arr_record"] = str(int(arr))
        if isinstance(arr_summary, str) and len(arr_summary.strip()) > 0:
            defaults["arr_summary"] = arr_summary.strip()
        supported = True
    file_type = defaults["file_type"]
    if file_type in {"TR", "BT"}:
        file_size = getattr(file_template, "file_size", None)
        if isinstance(file_size, int):
            defaults["file_size"] = str(int(file_size))
            supported = True
    if file_type in {"LF", "CY"}:
        rec_len = getattr(file_template, "rec_len", None)
        nb_rec = getattr(file_template, "nb_rec", None)
        if isinstance(rec_len, int):
            defaults["record_length"] = str(int(rec_len))
            supported = True
        if isinstance(nb_rec, int):
            defaults["record_count"] = str(int(nb_rec))
            supported = True
        if isinstance(rec_len, int) and isinstance(nb_rec, int):
            defaults["derived_file_size"] = str(int(rec_len) * int(nb_rec))
    if supported is False:
        return None
    return defaults


def _apply_file_overrides_to_template(
    file_template: Any,
    overrides: dict[str, Any] | None,
    *,
    gfm_mode: bool,
) -> Any:
    if isinstance(overrides, dict) is False or len(overrides) == 0:
        return file_template
    cloned = file_template
    short_efid = _normalize_optional_int_override(
        overrides.get("short_efid"),
        label="Short EFID",
    )
    if short_efid is not None:
        if short_efid <= 0 or short_efid > 30:
            raise ValueError("Short EFID must be in range 1..30.")
        cloned.sfi = short_efid
    arr_record = _normalize_optional_int_override(
        overrides.get("arr_record"),
        label="ARR record",
    )
    if arr_record is not None:
        if arr_record <= 0 or arr_record > 255:
            raise ValueError("ARR record must be in range 1..255.")
        cloned.arr = arr_record
        if gfm_mode:
            cloned.gfm_security_attributes = None
    file_type = str(getattr(cloned, "file_type", "") or "").upper()
    if file_type in {"TR", "BT"}:
        file_size = _normalize_optional_int_override(
            overrides.get("file_size"),
            label="File size",
        )
        if file_size is not None:
            if file_size <= 0 or file_size > 65535:
                raise ValueError("File size must be in range 1..65535.")
            cloned.file_size = file_size
    if file_type in {"LF", "CY"}:
        record_length = _normalize_optional_int_override(
            overrides.get("record_length"),
            label="Record length",
        )
        record_count = _normalize_optional_int_override(
            overrides.get("record_count"),
            label="Record count",
        )
        if record_length is not None:
            if record_length <= 0 or record_length > 65535:
                raise ValueError("Record length must be in range 1..65535.")
            cloned.rec_len = record_length
        if record_count is not None:
            if record_count <= 0 or record_count > 255:
                raise ValueError("Record count must be in range 1..255.")
            cloned.nb_rec = record_count
        if isinstance(cloned.rec_len, int) and isinstance(cloned.nb_rec, int):
            cloned.file_size = int(cloned.rec_len) * int(cloned.nb_rec)
    return cloned


def _template_with_file_overrides(
    file_template: Any,
    overrides: dict[str, Any] | None,
    *,
    gfm_mode: bool,
) -> Any:
    if isinstance(overrides, dict) is False or len(overrides) == 0:
        return file_template
    cloned = _clone_template_subtree(file_template)
    return _apply_file_overrides_to_template(
        cloned,
        overrides,
        gfm_mode=gfm_mode,
    )


def _filesystem_context_for_pe(
    pe: Any,
    template: Any,
    *,
    context_key: str | None,
    section_key: str,
) -> Any | None:
    context_template = _template_context_from_key(template, context_key)
    if context_template is None:
        return None
    context_key_text = str(getattr(context_template, "pe_name", "") or "").strip()
    if len(context_key_text) == 0 or context_key_text not in getattr(pe, "decoded", {}):
        raise ValueError(
            f"Target directory {context_key_text!r} is not present in PE {section_key!r}."
        )
    return context_template


def _fs_candidate_templates_for_context(
    pe: Any,
    template: Any,
    context_template: Any | None,
) -> list[tuple[Any, list[Any], list[Any]]]:
    existing_keys = {str(key) for key in getattr(pe, "decoded", {}).keys()}
    boundary = _template_boundary(template, context_template)
    if context_template is None:
        roots = _template_root_children(template)
    else:
        roots = list(getattr(context_template, "children", []))
    rows: list[tuple[Any, list[Any], list[Any]]] = []
    seen_penames: set[str] = set()
    for file_template in _iter_template_descendants(roots):
        file_key = str(getattr(file_template, "pe_name", "") or "").strip()
        if len(file_key) == 0:
            continue
        if file_key in seen_penames:
            continue
        seen_penames.add(file_key)
        if file_key in existing_keys:
            continue
        relative_ancestors = _relative_template_ancestors(file_template, boundary)
        missing_ancestors = [
            ancestor
            for ancestor in relative_ancestors
            if str(getattr(ancestor, "pe_name", "") or "").strip() not in existing_keys
        ]
        rows.append((file_template, relative_ancestors, missing_ancestors))
    return rows


def _fs_missing_ancestors_for_file(
    pe: Any,
    template: Any,
    context_template: Any | None,
    file_template: Any,
) -> list[Any]:
    existing_keys = {str(key) for key in getattr(pe, "decoded", {}).keys()}
    boundary = _template_boundary(template, context_template)
    relative_ancestors = _relative_template_ancestors(file_template, boundary)
    return [
        ancestor
        for ancestor in relative_ancestors
        if str(getattr(ancestor, "pe_name", "") or "").strip() not in existing_keys
    ]


class _FallbackFileTemplate:
    def __init__(
        self,
        *,
        fid: int | None,
        name: str,
        file_type: str,
        pe_name: str | None = None,
        arr: int = 1,
        sfi: int | None = None,
        file_size: int | None = None,
        rec_len: int | None = None,
        nb_rec: int | None = None,
        high_update: bool = False,
        gfm_security_attributes: bytes | None = None,
        df_name: bytes | None = None,
        pstdo: bytes | None = None,
        lcsi: bytes | None = None,
        fill_pattern: bytes | None = None,
        fill_pattern_repeat: bool = False,
        link_path: bytes | None = None,
    ) -> None:
        self.fid = fid
        self.name = name
        self.pe_name = (
            str(pe_name).strip()
            if isinstance(pe_name, str) and len(pe_name.strip()) > 0
            else name.replace(".", "-").replace("_", "-").lower()
        )
        self.file_type = file_type
        self.arr = arr
        self.sfi = sfi
        self.file_size = file_size
        self.rec_len = rec_len
        self.nb_rec = nb_rec
        self.high_update = high_update
        self.parent: Any | None = None
        self.children: list[Any] = []
        self.gfm_security_attributes = gfm_security_attributes
        self.df_name = df_name
        self.pstdo = pstdo
        self.lcsi = lcsi
        self.fill_pattern = fill_pattern
        self.fill_pattern_repeat = fill_pattern_repeat
        self.link_path = link_path


class _FallbackProfileTemplate:
    extends = None

    def __init__(self, root: _FallbackFileTemplate) -> None:
        self._root = root
        self.files = self._flatten(root)
        self.files_by_pename = {
            str(getattr(file_template, "pe_name", "") or "").strip(): file_template
            for file_template in self.files
            if len(str(getattr(file_template, "pe_name", "") or "").strip()) > 0
        }

    @staticmethod
    def _flatten(node: _FallbackFileTemplate) -> list[_FallbackFileTemplate]:
        out = [node]
        for child in node.children:
            out.extend(_FallbackProfileTemplate._flatten(child))
        return out

    def base_df(self) -> _FallbackFileTemplate:
        return self._root


_GFM_GSM_TEMPLATE: _FallbackProfileTemplate | None = None
_GFM_PKCS15_TEMPLATE: _FallbackProfileTemplate | None = None
_GFM_ADF_USIM_TEMPLATE: _FallbackProfileTemplate | None = None
_GFM_ADF_ISIM_TEMPLATE: _FallbackProfileTemplate | None = None
_GFM_MF_ROOT_ALIAS_SEPARATOR = "::"
_GFM_ADF_USIM_AID_PREFIX = bytes.fromhex("A0000000871002")
_GFM_ADF_ISIM_AID_PREFIX = bytes.fromhex("A0000000871004")


def _attach_fallback_child(
    parent: _FallbackFileTemplate,
    child: _FallbackFileTemplate,
) -> _FallbackFileTemplate:
    child.parent = parent
    parent.children.append(child)
    return child


def _fallback_numeric(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return int(value)
    text = str(value).strip()
    if len(text) == 0:
        return None
    return int(text, 16)


def _fallback_recommended_size(spec: Any) -> int | None:
    if spec is None:
        return None
    if isinstance(spec, tuple):
        preferred = spec[1]
        minimum = spec[0]
        if isinstance(preferred, int):
            return preferred
        if isinstance(minimum, int):
            return minimum
        return None
    if isinstance(spec, int):
        return spec
    return None


def _fallback_recommended_record_length(spec: Any) -> int | None:
    if spec is None:
        return None
    if isinstance(spec, tuple):
        preferred = spec[1]
        minimum = spec[0]
        if isinstance(preferred, int):
            return preferred
        if isinstance(minimum, int):
            return minimum
        return None
    if isinstance(spec, int):
        return spec
    return None


def _clone_template_subtree(file_template: Any) -> _FallbackFileTemplate:
    cloned = _FallbackFileTemplate(
        fid=getattr(file_template, "fid", None),
        name=str(getattr(file_template, "name", "") or "file"),
        pe_name=str(getattr(file_template, "pe_name", "") or "").strip() or None,
        file_type=str(getattr(file_template, "file_type", "") or "").upper(),
        arr=int(getattr(file_template, "arr", 1) or 1),
        sfi=getattr(file_template, "sfi", None),
        file_size=getattr(file_template, "file_size", None),
        rec_len=getattr(file_template, "rec_len", None),
        nb_rec=getattr(file_template, "nb_rec", None),
        high_update=bool(getattr(file_template, "high_update", False)),
        gfm_security_attributes=getattr(file_template, "gfm_security_attributes", None),
        df_name=getattr(file_template, "df_name", None),
        pstdo=getattr(file_template, "pstdo", None),
        lcsi=getattr(file_template, "lcsi", None),
        fill_pattern=getattr(file_template, "fill_pattern", None),
        fill_pattern_repeat=bool(getattr(file_template, "fill_pattern_repeat", False)),
        link_path=getattr(file_template, "link_path", None),
    )
    for child in list(getattr(file_template, "children", [])):
        _attach_fallback_child(cloned, _clone_template_subtree(child))
    return cloned


def _attach_unique_template_child(
    parent: _FallbackFileTemplate,
    child_template: Any,
    seen_penames: set[str],
) -> None:
    child_key = str(getattr(child_template, "pe_name", "") or "").strip()
    if len(child_key) == 0 or child_key in seen_penames:
        return
    seen_penames.add(child_key)
    _attach_fallback_child(parent, _clone_template_subtree(child_template))


def _gfm_mf_root_alias_id(root_key: str, target_key: str) -> str:
    return f"{root_key}{_GFM_MF_ROOT_ALIAS_SEPARATOR}{target_key}"


def _gfm_template_root_kind(root_template: Any) -> str | None:
    root_key = str(getattr(root_template, "pe_name", "") or "").strip()
    if root_key in {"adf-usim", "adf-isim"}:
        return root_key
    return None


def _gfm_template_root_aid_prefix(root_template: Any) -> bytes | None:
    root_kind = _gfm_template_root_kind(root_template)
    if root_kind == "adf-usim":
        return _GFM_ADF_USIM_AID_PREFIX
    if root_kind == "adf-isim":
        return _GFM_ADF_ISIM_AID_PREFIX
    return None


def _gfm_template_child_by_fid(parent_template: Any, fid: int) -> Any | None:
    for child in list(getattr(parent_template, "children", [])):
        child_fid = getattr(child, "fid", None)
        if isinstance(child_fid, int) and int(child_fid) == int(fid):
            return child
    return None


def _gfm_dynamic_adf_template_for_path(
    path: list[int] | tuple[int, ...],
    group_states: list[dict[str, Any]] | None = None,
) -> Any | None:
    normalized = tuple(int(part) for part in path)
    if len(normalized) < 2 or normalized[0] != 0x3F00:
        return None
    root_fid = int(normalized[1])
    if root_fid == 0x7FF0:
        return _build_gfm_adf_usim_template()
    if root_fid == 0x7FF2:
        return _build_gfm_adf_isim_template()
    for state in group_states or []:
        for entry in state.get("entries", []):
            created_path = entry.get("created_path")
            if created_path != (0x3F00, root_fid):
                continue
            df_name = entry.get("df_name")
            if isinstance(df_name, (bytes, bytearray, memoryview)) is False:
                continue
            df_name_bytes = bytes(df_name)
            if df_name_bytes.startswith(_GFM_ADF_USIM_AID_PREFIX):
                return _build_gfm_adf_usim_template()
            if df_name_bytes.startswith(_GFM_ADF_ISIM_AID_PREFIX):
                return _build_gfm_adf_isim_template()
    return None


def _gfm_adf_template_context_for_path(
    path: list[int] | tuple[int, ...],
    group_states: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any | None] | None:
    template = _gfm_dynamic_adf_template_for_path(path, group_states)
    if template is None:
        return None
    normalized = tuple(int(part) for part in path)
    relative_fids = list(normalized[2:])
    if len(relative_fids) == 0:
        return (template, None)
    current = template.base_df()
    for fid in relative_fids:
        current = _gfm_template_child_by_fid(current, int(fid))
        if current is None:
            return None
    current_type = str(getattr(current, "file_type", "") or "").upper()
    if current_type in {"MF", "ADF", "DF"}:
        return (template, current)
    return (template, getattr(current, "parent", None))


def _fallback_file_type_for_classic_card_file(card_file: Any) -> str:
    from pySim.filesystem import CardADF, CardDF, CyclicEF, LinFixedEF, TransRecEF, TransparentEF

    if isinstance(card_file, CyclicEF):
        return "CY"
    if isinstance(card_file, LinFixedEF):
        return "LF"
    if isinstance(card_file, TransRecEF):
        return "TR"
    if isinstance(card_file, TransparentEF):
        return "TR"
    if isinstance(card_file, CardADF):
        return "ADF"
    if isinstance(card_file, CardDF):
        return "DF"
    raise ValueError(f"Unsupported classic filesystem node type: {type(card_file)!r}")


def _gfm_gsm_saip_template_lookup() -> dict[str, Any]:
    from pySim.esim.saip import templates

    lookup: dict[str, Any] = {}
    for profile_template in (
        templates.FilesUsimMandatoryV2,
        templates.FilesUsimOptionalV3,
        templates.FilesUsimDfGsmAccess,
    ):
        for file_template in getattr(profile_template, "files", []):
            human_name = str(getattr(file_template, "name", "") or "").strip().upper()
            if len(human_name) == 0:
                continue
            lookup.setdefault(human_name, file_template)
    return lookup


def _build_gfm_gsm_template() -> _FallbackProfileTemplate:
    global _GFM_GSM_TEMPLATE
    if _GFM_GSM_TEMPLATE is not None:
        return _GFM_GSM_TEMPLATE

    from pySim.ts_51_011 import DF_GSM

    root = _FallbackFileTemplate(
        fid=0x7F20,
        name="DF.GSM",
        pe_name="df-gsm",
        file_type="DF",
        arr=0x05,
        gfm_security_attributes=bytes.fromhex("05"),
        pstdo=bytes.fromhex("010A"),
        lcsi=bytes.fromhex("05"),
    )
    _attach_fallback_child(
        root,
        _FallbackFileTemplate(
            fid=0x6F06,
            name="EF.ARR",
            pe_name="ef-arr",
            file_type="LF",
            arr=0x0A,
            rec_len=66,
            nb_rec=15,
            gfm_security_attributes=bytes.fromhex("6F060A"),
            lcsi=bytes.fromhex("05"),
        ),
    )

    saip_lookup = _gfm_gsm_saip_template_lookup()
    classic_root = DF_GSM()
    for classic_child in classic_root.children.values():
        human_name = str(getattr(classic_child, "name", "") or "").strip()
        if len(human_name) == 0:
            continue
        matched_template = saip_lookup.get(human_name.upper())
        file_type = _fallback_file_type_for_classic_card_file(classic_child)
        pe_name = None
        arr = 1
        sfi = _fallback_numeric(getattr(classic_child, "sfid", None))
        high_update = False
        gfm_security_attributes: bytes | None = None
        if matched_template is not None:
            pe_name = str(getattr(matched_template, "pe_name", "") or "").strip() or None
            arr = int(getattr(matched_template, "arr", 1))
            sfi = (
                _fallback_numeric(getattr(matched_template, "sfi", None))
                if getattr(matched_template, "sfi", None) is not None
                else sfi
            )
            high_update = bool(getattr(matched_template, "high_update", False))
            gfm_security_attributes = bytes.fromhex("6F06") + bytes([arr])
        file_size = None
        rec_len = None
        nb_rec = None
        total_size = _fallback_recommended_size(getattr(classic_child, "size", None))
        if file_type in {"TR", "BT"}:
            file_size = total_size
        elif file_type in {"LF", "CY"}:
            rec_len = _fallback_recommended_record_length(
                getattr(classic_child, "rec_len", None)
            )
            if (
                isinstance(total_size, int)
                and isinstance(rec_len, int)
                and rec_len > 0
                and total_size >= rec_len
                and total_size % rec_len == 0
            ):
                nb_rec = total_size // rec_len
        _attach_fallback_child(
            root,
            _FallbackFileTemplate(
                fid=int(str(getattr(classic_child, "fid", "") or "0"), 16),
                name=human_name,
                pe_name=pe_name,
                file_type=file_type,
                arr=arr,
                sfi=sfi,
                file_size=file_size,
                rec_len=rec_len,
                nb_rec=nb_rec,
                high_update=high_update,
                gfm_security_attributes=gfm_security_attributes,
                lcsi=bytes.fromhex("05"),
            ),
        )
    _GFM_GSM_TEMPLATE = _FallbackProfileTemplate(root)
    return _GFM_GSM_TEMPLATE


def _build_gfm_pkcs15_template() -> _FallbackProfileTemplate:
    global _GFM_PKCS15_TEMPLATE
    if _GFM_PKCS15_TEMPLATE is not None:
        return _GFM_PKCS15_TEMPLATE

    root = _FallbackFileTemplate(
        fid=0x7F50,
        name="DF.PKCS15",
        pe_name="df-pkcs15",
        file_type="DF",
        arr=0x16,
        gfm_security_attributes=bytes.fromhex("2F0616"),
        df_name=bytes.fromhex("A000000063504B43532D3135"),
        pstdo=bytes.fromhex("0A01"),
        lcsi=bytes.fromhex("05"),
    )
    common_arr = bytes.fromhex("6F0601")
    common_lcsi = bytes.fromhex("05")
    common_fill = bytes.fromhex("FF")
    _attach_fallback_child(
        root,
        _FallbackFileTemplate(
            fid=0x6F06,
            name="EF.ARR",
            pe_name="ef-arr",
            file_type="LF",
            arr=0x01,
            rec_len=32,
            nb_rec=1,
            gfm_security_attributes=common_arr,
            lcsi=common_lcsi,
        ),
    )
    for fid, name, pe_name, file_size in (
        (0x5031, "EF.PKCS15-ODF", "ef-pkcs15-odf", 0x20),
        (0x5207, "EF.PKCS15-DODF", "ef-pkcs15-dodf", 0x30),
        (0x4200, "EF.PKCS15-ACM", "ef-pkcs15-acm", 0x20),
        (0x4300, "EF.PKCS15-ACRF", "ef-pkcs15-acrf", 0x40),
        (0x4310, "EF.PKCS15-ACCF", "ef-pkcs15-accf", 0x100),
    ):
        _attach_fallback_child(
            root,
            _FallbackFileTemplate(
                fid=fid,
                name=name,
                pe_name=pe_name,
                file_type="TR",
                arr=0x01,
                file_size=file_size,
                gfm_security_attributes=common_arr,
                lcsi=common_lcsi,
                fill_pattern=common_fill,
                fill_pattern_repeat=False,
            ),
        )
    _GFM_PKCS15_TEMPLATE = _FallbackProfileTemplate(root)
    return _GFM_PKCS15_TEMPLATE


def _build_gfm_adf_usim_template() -> _FallbackProfileTemplate:
    global _GFM_ADF_USIM_TEMPLATE
    if _GFM_ADF_USIM_TEMPLATE is not None:
        return _GFM_ADF_USIM_TEMPLATE

    from pySim.esim.saip import templates

    root = _FallbackFileTemplate(
        fid=0x7FF0,
        name="ADF.USIM",
        pe_name="adf-usim",
        file_type="ADF",
        arr=0x0A,
        gfm_security_attributes=bytes.fromhex("0A"),
        df_name=bytes.fromhex("A0000000871002FF34FF0789312E30FF"),
        pstdo=bytes.fromhex("01810A"),
        lcsi=bytes.fromhex("05"),
    )
    _attach_fallback_child(
        root,
        _FallbackFileTemplate(
            fid=0x6F06,
            name="EF.ARR",
            pe_name="ef-arr",
            file_type="LF",
            arr=0x0A,
            sfi=0x17,
            gfm_security_attributes=bytes.fromhex("0A"),
            lcsi=bytes.fromhex("05"),
            link_path=bytes.fromhex("2F06"),
        ),
    )
    seen_penames = {"ef-arr"}
    for file_template in list(getattr(templates.FilesUsimOptionalV3, "files", [])):
        if getattr(file_template, "parent", None) is not None:
            continue
        _attach_unique_template_child(root, file_template, seen_penames)
    for branch_template in (
        templates.FilesUsimDfPhonebook,
        templates.FilesUsimDfGsmAccess,
        templates.FilesUsimDf5GSv3,
        templates.FilesUsimDfSaip,
        templates.FilesDfSnpn,
        templates.FilesDf5GProSe,
    ):
        _attach_unique_template_child(root, branch_template.base_df(), seen_penames)
    graphics_template = _template_file_for_pename(templates.FilesTelecomV2, "df-graphics")
    if graphics_template is not None:
        _attach_unique_template_child(root, graphics_template, seen_penames)
    _GFM_ADF_USIM_TEMPLATE = _FallbackProfileTemplate(root)
    return _GFM_ADF_USIM_TEMPLATE


def _build_gfm_adf_isim_template() -> _FallbackProfileTemplate:
    global _GFM_ADF_ISIM_TEMPLATE
    if _GFM_ADF_ISIM_TEMPLATE is not None:
        return _GFM_ADF_ISIM_TEMPLATE

    from pySim.esim.saip import templates

    root = _FallbackFileTemplate(
        fid=0x7FF2,
        name="ADF.ISIM",
        pe_name="adf-isim",
        file_type="ADF",
        arr=0x0E,
        gfm_security_attributes=bytes.fromhex("0E"),
        df_name=bytes.fromhex("A0000000871004FF34FF0789312E30FF"),
        pstdo=bytes.fromhex("010A"),
        lcsi=bytes.fromhex("05"),
    )
    _attach_fallback_child(
        root,
        _FallbackFileTemplate(
            fid=0x6F06,
            name="EF.ARR",
            pe_name="ef-arr",
            file_type="LF",
            arr=0x06,
            sfi=0x06,
            gfm_security_attributes=bytes.fromhex("06"),
            lcsi=bytes.fromhex("05"),
            link_path=bytes.fromhex("2F06"),
        ),
    )
    seen_penames = {"ef-arr"}
    for file_template in list(getattr(templates.FilesIsimOptionalv2, "files", [])):
        if getattr(file_template, "parent", None) is not None:
            continue
        _attach_unique_template_child(root, file_template, seen_penames)
    _GFM_ADF_ISIM_TEMPLATE = _FallbackProfileTemplate(root)
    return _GFM_ADF_ISIM_TEMPLATE


def _gfm_profile_has_path(pes: Any, path: list[int] | tuple[int, ...]) -> bool:
    mf = getattr(pes, "mf", None)
    if mf is None or hasattr(mf, "lookup_by_fidpath") is False:
        return False
    try:
        mf.lookup_by_fidpath(list(path))
    except Exception:
        return False
    return True


def _gfm_root_creation_specs(
    pes: Any,
) -> list[tuple[Any, list[Any]]]:
    from pySim.esim.saip import templates

    specs: list[tuple[Any, list[Any]]] = []
    for template in (
        templates.FilesTelecomV2,
        templates.FilesCD,
        _build_gfm_gsm_template(),
        _build_gfm_pkcs15_template(),
        _build_gfm_adf_usim_template(),
        _build_gfm_adf_isim_template(),
    ):
        root_template = template.base_df()
        root_fid = getattr(root_template, "fid", None)
        if isinstance(root_fid, int) is False:
            continue
        root_path = (0x3F00, int(root_fid))
        if _gfm_profile_has_path(pes, root_path):
            continue
        bootstrap_children: list[Any] = []
        local_arr = _template_file_for_pename(template, "ef-arr")
        if local_arr is not None:
            bootstrap_children.append(local_arr)
        specs.append((root_template, bootstrap_children))
    return specs


def _gfm_creation_hint(
    file_template: Any,
    *,
    create_templates: list[Any],
) -> str | None:
    hint = _file_option_hint(file_template)
    create_names: list[str] = []
    for template in create_templates:
        name = str(getattr(template, "name", "") or "").strip()
        if len(name) == 0 or name in create_names:
            continue
        create_names.append(name)
    if len(create_names) == 0:
        return hint
    create_hint = "creates " + " / ".join(create_names)
    if hint is None:
        return create_hint
    return f"{hint}; {create_hint}"


def _gfm_mf_root_option_with_bootstrap_overrides(
    option: dict[str, Any],
    bootstrap_overrides: dict[str, Any] | None,
) -> dict[str, Any]:
    if isinstance(bootstrap_overrides, dict) is False or len(bootstrap_overrides) == 0:
        return option
    root_template = option["root_template"]
    root_kind = _gfm_template_root_kind(root_template)
    if root_kind is None:
        return option
    root_name = str(getattr(root_template, "name", "") or root_kind)
    fid_text = str(
        bootstrap_overrides.get("temporary_fid", bootstrap_overrides.get("fid", ""))
        or ""
    ).strip().upper()
    if len(fid_text) != 4:
        raise ValueError(f"{root_name} temporary FID must be 4 hex characters.")
    try:
        root_fid = int(fid_text, 16)
    except ValueError as exc:
        raise ValueError(f"{root_name} temporary FID must be hexadecimal.") from exc
    aid_text = str(
        bootstrap_overrides.get("df_name", bootstrap_overrides.get("aid", ""))
        or ""
    ).strip().replace(" ", "").upper()
    if len(aid_text) == 0 or len(aid_text) % 2 != 0:
        raise ValueError(f"{root_name} AID must be non-empty even-length hex.")
    try:
        aid_bytes = bytes.fromhex(aid_text)
    except ValueError as exc:
        raise ValueError(f"{root_name} AID must be hexadecimal.") from exc
    aid_prefix = _gfm_template_root_aid_prefix(root_template)
    if aid_prefix is not None and aid_bytes.startswith(aid_prefix) is False:
        raise ValueError(
            f"{root_name} AID must start with {aid_prefix.hex().upper()}."
        )
    cloned_root = _clone_template_subtree(root_template)
    cloned_root.fid = int(root_fid)
    cloned_root.df_name = aid_bytes
    cloned_profile = _FallbackProfileTemplate(cloned_root)
    target_key = str(getattr(option["target_template"], "pe_name", "") or "").strip()
    bootstrap_keys = [
        str(getattr(child, "pe_name", "") or "").strip()
        for child in option["bootstrap_children"]
    ]
    ancestor_keys = [
        str(getattr(ancestor, "pe_name", "") or "").strip()
        for ancestor in option["relative_ancestors"]
    ]
    cloned_target = cloned_root
    if len(target_key) > 0:
        cloned_target = cloned_profile.files_by_pename.get(target_key, cloned_root)
    return {
        **option,
        "root_template": cloned_root,
        "target_template": cloned_target,
        "bootstrap_children": [
            cloned_profile.files_by_pename[key]
            for key in bootstrap_keys
            if len(key) > 0 and key in cloned_profile.files_by_pename
        ],
        "relative_ancestors": [
            cloned_profile.files_by_pename[key]
            for key in ancestor_keys
            if len(key) > 0 and key in cloned_profile.files_by_pename
        ],
    }


def _gfm_mf_root_creation_options(
    pes: Any,
) -> "OrderedDict[str, dict[str, Any]]":
    options: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
    for root_template, bootstrap_children in _gfm_root_creation_specs(pes):
        root_key = str(getattr(root_template, "pe_name", "") or "").strip()
        if len(root_key) == 0:
            continue
        options[root_key] = {
            "target_template": root_template,
            "root_template": root_template,
            "bootstrap_children": list(bootstrap_children),
            "relative_ancestors": [],
            "title": _file_option_title(root_template),
            "hint": _gfm_creation_hint(
                root_template,
                create_templates=list(bootstrap_children),
            ),
        }
        bootstrap_keys = {
            str(getattr(child, "pe_name", "") or "").strip()
            for child in bootstrap_children
        }
        for descendant in _iter_template_descendants(
            list(getattr(root_template, "children", []))
        ):
            descendant_key = str(getattr(descendant, "pe_name", "") or "").strip()
            if len(descendant_key) == 0:
                continue
            if descendant_key in bootstrap_keys:
                continue
            option_id = descendant_key
            if descendant_key in options:
                option_id = _gfm_mf_root_alias_id(root_key, descendant_key)
                if option_id in options:
                    continue
            relative_ancestors = _relative_template_ancestors(
                descendant,
                root_template,
            )
            options[option_id] = {
                "target_template": descendant,
                "root_template": root_template,
                "bootstrap_children": list(bootstrap_children),
                "relative_ancestors": relative_ancestors,
                "title": _file_option_title(
                    descendant,
                    relative_ancestors=[root_template] + relative_ancestors,
                ),
                "hint": _gfm_creation_hint(
                    descendant,
                    create_templates=[root_template]
                    + list(bootstrap_children)
                    + relative_ancestors,
                ),
            }
    return options


def _gfm_context_label_from_path(
    path: list[int] | tuple[int, ...],
    group_states: list[dict[str, Any]] | None = None,
) -> str:
    from .saip_asn1_decode import _fid_name_from_hex

    normalized = tuple(int(part) for part in path)
    dynamic_context = _gfm_adf_template_context_for_path(normalized, group_states)
    if dynamic_context is not None:
        template, context_template = dynamic_context
        names = ["MF", str(getattr(template.base_df(), "name", "") or "ADF")]
        if context_template is not None:
            ancestors = _relative_template_ancestors(
                context_template,
                template.base_df(),
            )
            names.extend(
                [
                    str(getattr(node, "name", "") or "").strip()
                    for node in ancestors
                    if len(str(getattr(node, "name", "") or "").strip()) > 0
                ]
            )
            context_name = str(getattr(context_template, "name", "") or "").strip()
            if len(context_name) > 0:
                names.append(context_name)
        return "/".join(names)
    explicit_labels = {
        (0x3F00, 0x7F11): "MF/DF.CD",
        (0x3F00, 0x7F20): "MF/DF.GSM",
        (0x3F00, 0x7F50): "MF/DF.PKCS15",
    }
    explicit = explicit_labels.get(normalized)
    if explicit is not None:
        return explicit

    parts: list[str] = []
    for index, fid in enumerate(normalized):
        fid_hex = f"{int(fid):04X}"
        if index == 0 and fid_hex == "3F00":
            parts.append("MF")
            continue
        parts.append(_fid_name_from_hex(fid_hex) or fid_hex)
    return "/".join(parts) if len(parts) > 0 else "MF"


def _gfm_group_states(file_management_cmd: Any) -> list[dict[str, Any]]:
    from pySim.esim.saip import File

    groups = file_management_cmd if isinstance(file_management_cmd, list) else []
    current_path = [0x3F00]
    out: list[dict[str, Any]] = []
    for group_index, group in enumerate(groups):
        group_path = list(current_path)
        entries: list[dict[str, Any]] = []
        current_file_path: list[int] | None = None
        if isinstance(group, list) is False:
            continue
        for item in group:
            if isinstance(item, tuple) is False or len(item) != 2:
                continue
            tag_name = str(item[0] or "").strip()
            payload = item[1]
            if tag_name == "filePath":
                raw_path = (
                    bytes(payload or b"")
                    if isinstance(payload, (bytes, bytearray, memoryview))
                    else b""
                )
                if len(raw_path) == 0:
                    group_path = [0x3F00]
                else:
                    group_path = [0x3F00] + File.path_from_gfm(raw_path)
                current_file_path = None
                entries.append(
                    {
                        "tag": tag_name,
                        "parent_path": tuple(group_path),
                    }
                )
                continue
            if tag_name == "createFCP" and isinstance(payload, dict):
                file_obj = File(None, [("fileDescriptor", payload)])
                created_path = tuple(list(group_path) + [int(file_obj.fid or 0)])
                file_type = str(file_obj.file_type or "").upper()
                df_name = getattr(file_obj, "df_name", None)
                entries.append(
                    {
                        "tag": tag_name,
                        "file_type": file_type,
                        "parent_path": tuple(group_path),
                        "created_path": created_path,
                        "df_name": bytes(df_name)
                        if isinstance(df_name, (bytes, bytearray, memoryview))
                        else None,
                    }
                )
                current_file_path = list(created_path)
                if file_type in {"MF", "ADF", "DF"}:
                    group_path = list(created_path)
                continue
            if tag_name in {"fillFileOffset", "fillFileContent"}:
                entries.append(
                    {
                        "tag": tag_name,
                        "file_path": tuple(current_file_path) if current_file_path is not None else None,
                        "parent_path": tuple(current_file_path[:-1]) if current_file_path is not None else tuple(group_path),
                    }
                )
        out.append(
            {
                "group_index": group_index,
                "start_path": tuple(current_path),
                "final_path": tuple(group_path),
                "entries": entries,
            }
        )
        current_path = list(group_path)
    return out


def _gfm_existing_paths(group_states: list[dict[str, Any]]) -> set[tuple[int, ...]]:
    paths: set[tuple[int, ...]] = set()
    for state in group_states:
        for entry in state.get("entries", []):
            created_path = entry.get("created_path")
            if isinstance(created_path, tuple) and len(created_path) > 0:
                paths.add(created_path)
    return paths


def _gfm_context_path_for_group(
    group_states: list[dict[str, Any]],
    group_index: int | None,
) -> tuple[int, ...]:
    if len(group_states) == 0:
        return (0x3F00,)
    if group_index is None:
        return tuple(group_states[-1]["final_path"])
    if group_index < 0 or group_index >= len(group_states):
        raise ValueError(f"Unknown file-management group index: {group_index!r}")
    return tuple(group_states[group_index]["final_path"])


def _gfm_template_context_for_path(
    path: list[int] | tuple[int, ...],
    group_states: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any | None]:
    from pySim.esim.saip import templates

    normalized = tuple(int(part) for part in path)
    dynamic_context = _gfm_adf_template_context_for_path(normalized, group_states)
    if dynamic_context is not None:
        return dynamic_context
    if normalized == (0x3F00,):
        return (templates.FilesAtMF, None)
    if normalized == (0x3F00, 0x7F10):
        return (templates.FilesTelecomV2, None)
    if normalized == (0x3F00, 0x7F11):
        return (templates.FilesCD, None)
    if normalized == (0x3F00, 0x7F20):
        return (_build_gfm_gsm_template(), None)
    if normalized == (0x3F00, 0x7F50):
        return (_build_gfm_pkcs15_template(), None)
    if normalized == (0x3F00, 0x7F10, 0x5F3A):
        return (templates.FilesUsimDfPhonebook, None)
    if normalized == (0x3F00, 0x7F10, 0x5F50):
        template = templates.FilesTelecomV2
        return (template, _template_file_for_pename(template, "df-graphics"))
    if normalized == (0x3F00, 0x7F10, 0x5F3B):
        template = templates.FilesTelecomV2
        return (template, _template_file_for_pename(template, "df-multimedia"))
    if normalized == (0x3F00, 0x7F10, 0x5F3C):
        template = templates.FilesTelecomV2
        return (template, _template_file_for_pename(template, "df-mmss"))
    if normalized == (0x3F00, 0x7F10, 0x5F3D):
        template = templates.FilesTelecomV2
        return (template, _template_file_for_pename(template, "df-mcs"))
    if normalized == (0x3F00, 0x7F10, 0x5F3E):
        template = templates.FilesTelecomV2
        return (template, _template_file_for_pename(template, "df-v2x"))
    raise ValueError(
        f"No guided file template mapping for {_gfm_context_label_from_path(normalized, group_states)!r}."
    )


def _template_node_full_path(
    context_path: list[int] | tuple[int, ...],
    template: Any,
    context_template: Any | None,
    file_template: Any,
) -> tuple[int, ...]:
    boundary = _template_boundary(template, context_template)
    relative_ancestors = _relative_template_ancestors(file_template, boundary)
    full_path = [int(part) for part in context_path]
    for ancestor in relative_ancestors:
        ancestor_fid = getattr(ancestor, "fid", None)
        if isinstance(ancestor_fid, int):
            full_path.append(int(ancestor_fid))
    file_fid = getattr(file_template, "fid", None)
    if isinstance(file_fid, int) is False:
        raise ValueError(
            f"Template node {getattr(file_template, 'pe_name', '<unknown>')!r} does not expose a fixed FID."
        )
    full_path.append(int(file_fid))
    return tuple(full_path)


def _gfm_candidate_templates_for_context(
    template: Any,
    context_template: Any | None,
    *,
    context_path: list[int] | tuple[int, ...],
    existing_paths: set[tuple[int, ...]],
) -> list[tuple[Any, list[Any], list[Any]]]:
    boundary = _template_boundary(template, context_template)
    if context_template is None:
        roots = _template_root_children(template)
    else:
        roots = list(getattr(context_template, "children", []))
    rows: list[tuple[Any, list[Any], list[Any]]] = []
    seen_penames: set[str] = set()
    for file_template in _iter_template_descendants(roots):
        file_key = str(getattr(file_template, "pe_name", "") or "").strip()
        if len(file_key) == 0:
            continue
        if file_key in seen_penames:
            continue
        seen_penames.add(file_key)
        candidate_path = _template_node_full_path(
            context_path,
            template,
            context_template,
            file_template,
        )
        if candidate_path in existing_paths:
            continue
        relative_ancestors = _relative_template_ancestors(file_template, boundary)
        missing_ancestors: list[Any] = []
        for ancestor in relative_ancestors:
            ancestor_path = _template_node_full_path(
                context_path,
                template,
                context_template,
                ancestor,
            )
            if ancestor_path not in existing_paths:
                missing_ancestors.append(ancestor)
        rows.append((file_template, relative_ancestors, missing_ancestors))
    return rows


class _GfmExplicitTemplateDefaults:
    fid = None
    sfi = None
    arr = 0xFF


_GFM_EXPLICIT_TEMPLATE_DEFAULTS = _GfmExplicitTemplateDefaults()


def _explicit_file_descriptor(file_template: Any, *, gfm_mode: bool) -> dict[str, Any]:
    from pySim.esim.saip import File

    file_obj = File(str(getattr(file_template, "pe_name", "") or "file"), None)
    file_obj.template = _GFM_EXPLICIT_TEMPLATE_DEFAULTS
    file_obj.from_template(file_template)
    if gfm_mode:
        gfm_security_attributes = getattr(file_template, "gfm_security_attributes", None)
        if isinstance(gfm_security_attributes, (bytes, bytearray, memoryview)):
            file_obj.arr = bytes(gfm_security_attributes)
    df_name = getattr(file_template, "df_name", None)
    if isinstance(df_name, (bytes, bytearray, memoryview)):
        file_obj.df_name = bytes(df_name)
    pstdo = getattr(file_template, "pstdo", None)
    if isinstance(pstdo, (bytes, bytearray, memoryview)):
        file_obj.pstdo = bytes(pstdo)
    lcsi = getattr(file_template, "lcsi", None)
    if isinstance(lcsi, (bytes, bytearray, memoryview)):
        file_obj.lcsi = bytes(lcsi)
    fill_pattern = getattr(file_template, "fill_pattern", None)
    if isinstance(fill_pattern, (bytes, bytearray, memoryview)):
        file_obj.fill_pattern = bytes(fill_pattern)
        file_obj.fill_pattern_repeat = bool(
            getattr(file_template, "fill_pattern_repeat", False)
        )
    file_descriptor = file_obj.to_fileDescriptor()
    link_path = getattr(file_template, "link_path", None)
    if isinstance(link_path, (bytes, bytearray, memoryview)):
        file_descriptor["linkPath"] = bytes(link_path)
    return file_descriptor


def _explicit_gfm_file_descriptor(file_template: Any) -> dict[str, Any]:
    return _explicit_file_descriptor(file_template, gfm_mode=True)


def _gfm_group_for_file_template(
    file_template: Any,
    parent_path: list[int] | tuple[int, ...],
) -> list[tuple[str, Any]]:
    from pySim.esim.saip import File

    normalized_parent = [int(part) for part in parent_path]
    if len(normalized_parent) == 0 or normalized_parent[0] != 0x3F00:
        raise ValueError(
            f"GFM parent path must start at MF (got {normalized_parent!r})."
        )
    return [
        ("filePath", File.path_to_gfm(normalized_parent[1:])),
        ("createFCP", _explicit_gfm_file_descriptor(file_template)),
    ]


def _reorder_gfm_decoded(pe: Any) -> None:
    commands = getattr(pe, "decoded", {}).get("fileManagementCMD")
    if isinstance(commands, list) is False:
        return
    pe.decoded["fileManagementCMD"] = list(commands)


def _reorder_fs_profile_element_decoded(pe: Any) -> None:
    tdef = getattr(pe, "tdef", None)
    decoded = getattr(pe, "decoded", None)
    if tdef is None or decoded is None or hasattr(tdef, "root_members") is False:
        return
    ordered: "OrderedDict[str, Any]" = OrderedDict()
    for member in tdef.root_members:
        member_name = str(getattr(member, "name", "") or "").strip()
        if len(member_name) == 0:
            continue
        if member_name in decoded:
            ordered[member_name] = decoded[member_name]
    for key, value in decoded.items():
        if key not in ordered:
            ordered[key] = value
    pe.decoded = ordered


def list_addable_file_rows(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    section_key: str,
    context_key: Any = None,
    group_index: int | None = None,
) -> tuple[Any, str, List[Tuple[str, str, str | None]]]:
    pes, pe = _section_pe_from_document(
        document,
        workspace_root,
        section_key=section_key,
    )
    if str(getattr(pe, "type", "") or "") == "genericFileManagement":
        group_states = _gfm_group_states(getattr(pe, "decoded", {}).get("fileManagementCMD"))
        context_path = _gfm_context_path_for_group(group_states, group_index)
        template, context_template = _gfm_template_context_for_path(
            context_path,
            group_states,
        )
        rows: List[Tuple[str, str, str | None]] = []
        seen_ids: set[str] = set()
        for file_template, relative_ancestors, missing_ancestors in _gfm_candidate_templates_for_context(
            template,
            context_template,
            context_path=context_path,
            existing_paths=_gfm_existing_paths(group_states),
        ):
            file_key = str(getattr(file_template, "pe_name", "") or "").strip()
            if len(file_key) == 0 or file_key in seen_ids:
                continue
            seen_ids.add(file_key)
            arr_summary = _arr_summary_for_gfm_section(
                document,
                section_key=section_key,
                context_path=context_path,
                file_template=file_template,
            )
            rows.append(
                (
                    file_key,
                    _file_option_title(
                        file_template,
                        relative_ancestors=relative_ancestors,
                    ),
                    _file_option_hint(
                        file_template,
                        missing_ancestors=missing_ancestors,
                        arr_summary=arr_summary,
                    ),
                )
            )
        if tuple(context_path) == (0x3F00,):
            for file_key, option in _gfm_mf_root_creation_options(pes).items():
                if len(file_key) == 0 or file_key in seen_ids:
                    continue
                seen_ids.add(file_key)
                arr_hint = _file_arr_hint(
                    option["target_template"],
                    arr_summary=_arr_summary_for_gfm_section(
                        document,
                        section_key=section_key,
                        context_path=context_path,
                        file_template=option["target_template"],
                    ),
                )
                rows.append(
                    (
                        file_key,
                        str(option["title"]),
                        _merge_option_hints(
                            str(option["hint"]) if option["hint"] is not None else None,
                            arr_hint,
                        ),
                    )
                )
        return (
            tuple(context_path),
            _gfm_context_label_from_path(context_path, group_states),
            rows,
        )
    del pes
    template = _filesystem_template_for_pe(pe)
    context_template = _filesystem_context_for_pe(
        pe,
        template,
        context_key=context_key,
        section_key=section_key,
    )
    normalized_context_key = (
        str(getattr(context_template, "pe_name", "") or "").strip() or None
        if context_template is not None
        else None
    )
    context_label = _context_label_for_template(template, context_template)
    rows: List[Tuple[str, str, str | None]] = []
    for file_template, relative_ancestors, missing_ancestors in _fs_candidate_templates_for_context(
        pe,
        template,
        context_template,
    ):
        arr_summary = _arr_summary_for_pe_section(
            document,
            section_key=section_key,
            file_template=file_template,
        )
        rows.append(
            (
                str(getattr(file_template, "pe_name", "") or "").strip(),
                _file_option_title(
                    file_template,
                    relative_ancestors=relative_ancestors,
                ),
                _file_option_hint(
                    file_template,
                    missing_ancestors=missing_ancestors,
                    arr_summary=arr_summary,
                ),
            )
        )
    return (normalized_context_key, context_label, rows)


def file_add_override_defaults(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    section_key: str,
    file_pe_name: str,
    context_key: Any = None,
    group_index: int | None = None,
) -> dict[str, str] | None:
    normalized_file_key = str(file_pe_name or "").strip()
    if len(normalized_file_key) == 0:
        return None
    pes, pe = _section_pe_from_document(
        document,
        workspace_root,
        section_key=section_key,
    )
    if str(getattr(pe, "type", "") or "") == "genericFileManagement":
        group_states = _gfm_group_states(getattr(pe, "decoded", {}).get("fileManagementCMD"))
        if isinstance(context_key, (list, tuple)):
            context_path = tuple(int(part) for part in context_key)
        else:
            context_path = _gfm_context_path_for_group(group_states, group_index)
        if tuple(context_path) == (0x3F00,):
            mf_option = _gfm_mf_root_creation_options(pes).get(normalized_file_key)
            if mf_option is None:
                return None
            return _file_override_defaults_from_template(
                mf_option["target_template"],
                arr_summary=_arr_summary_for_gfm_section(
                    document,
                    section_key=section_key,
                    context_path=context_path,
                    file_template=mf_option["target_template"],
                ),
            )
        template, context_template = _gfm_template_context_for_path(
            context_path,
            group_states,
        )
        candidate_rows = _gfm_candidate_templates_for_context(
            template,
            context_template,
            context_path=context_path,
            existing_paths=_gfm_existing_paths(group_states),
        )
        file_template = next(
            (
                candidate
                for candidate, _relative_ancestors, _missing_ancestors in candidate_rows
                if str(getattr(candidate, "pe_name", "") or "").strip() == normalized_file_key
            ),
            None,
        )
        if file_template is None:
            return None
        return _file_override_defaults_from_template(
            file_template,
            arr_summary=_arr_summary_for_gfm_section(
                document,
                section_key=section_key,
                context_path=context_path,
                file_template=file_template,
            ),
        )
    template = _filesystem_template_for_pe(pe)
    context_template = _filesystem_context_for_pe(
        pe,
        template,
        context_key=context_key,
        section_key=section_key,
    )
    allowed_rows = _fs_candidate_templates_for_context(
        pe,
        template,
        context_template,
    )
    file_template = next(
        (
            candidate
            for candidate, _relative_ancestors, _missing_ancestors in allowed_rows
            if str(getattr(candidate, "pe_name", "") or "").strip() == normalized_file_key
        ),
        None,
    )
    if file_template is None:
        return None
    return _file_override_defaults_from_template(
        file_template,
        arr_summary=_arr_summary_for_pe_section(
            document,
            section_key=section_key,
            file_template=file_template,
        ),
    )


def _replace_decoded_file_descriptor(
    file_entries: Any,
    file_descriptor: dict[str, Any],
) -> None:
    if isinstance(file_entries, list) is False:
        raise ValueError("Decoded file entries must be a list.")
    for index, item in enumerate(file_entries):
        if isinstance(item, tuple) and len(item) == 2 and str(item[0] or "") == "fileDescriptor":
            file_entries[index] = ("fileDescriptor", file_descriptor)
            return
        if isinstance(item, list) and len(item) == 2 and str(item[0] or "") == "fileDescriptor":
            file_entries[index] = ("fileDescriptor", file_descriptor)
            return
    file_entries.insert(0, ("fileDescriptor", file_descriptor))


def gfm_root_bootstrap_defaults(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    section_key: str,
    file_pe_name: str,
    context_key: Any = None,
    group_index: int | None = None,
) -> dict[str, str] | None:
    normalized_file_key = str(file_pe_name or "").strip()
    if len(normalized_file_key) == 0:
        return None
    pes, pe = _section_pe_from_document(
        document,
        workspace_root,
        section_key=section_key,
    )
    if str(getattr(pe, "type", "") or "") != "genericFileManagement":
        return None
    group_states = _gfm_group_states(getattr(pe, "decoded", {}).get("fileManagementCMD"))
    if isinstance(context_key, (list, tuple)):
        context_path = tuple(int(part) for part in context_key)
    else:
        context_path = _gfm_context_path_for_group(group_states, group_index)
    if tuple(context_path) != (0x3F00,):
        return None
    mf_option = _gfm_mf_root_creation_options(pes).get(normalized_file_key)
    if mf_option is None:
        return None
    root_template = mf_option["root_template"]
    root_kind = _gfm_template_root_kind(root_template)
    if root_kind is None:
        return None
    root_fid = getattr(root_template, "fid", None)
    df_name = getattr(root_template, "df_name", None)
    aid_prefix = _gfm_template_root_aid_prefix(root_template)
    if isinstance(root_fid, int) is False:
        return None
    if isinstance(df_name, (bytes, bytearray, memoryview)) is False:
        return None
    if isinstance(aid_prefix, (bytes, bytearray, memoryview)) is False:
        return None
    return {
        "root_kind": root_kind,
        "root_name": str(getattr(root_template, "name", "") or root_kind),
        "temporary_fid": f"{int(root_fid):04X}",
        "df_name": bytes(df_name).hex().upper(),
        "aid_prefix": bytes(aid_prefix).hex().upper(),
    }


def insert_blank_file_for_pename(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    section_key: str,
    file_pe_name: str,
    context_key: Any = None,
    group_index: int | None = None,
    bootstrap_overrides: dict[str, Any] | None = None,
    file_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_file_key = str(file_pe_name or "").strip()
    if len(normalized_file_key) == 0:
        raise ValueError("File PE-name must not be empty.")

    pes, pe = _section_pe_from_document(
        document,
        workspace_root,
        section_key=section_key,
    )
    if str(getattr(pe, "type", "") or "") == "genericFileManagement":
        group_states = _gfm_group_states(getattr(pe, "decoded", {}).get("fileManagementCMD"))
        if isinstance(context_key, (list, tuple)):
            context_path = tuple(int(part) for part in context_key)
        else:
            context_path = _gfm_context_path_for_group(group_states, group_index)
        template, context_template = _gfm_template_context_for_path(
            context_path,
            group_states,
        )
        commands = list(getattr(pe, "decoded", {}).get("fileManagementCMD", []))
        insert_index = len(commands)
        if group_index is not None:
            insert_index = max(0, min(int(group_index) + 1, len(commands)))
        if tuple(context_path) == (0x3F00,):
            mf_option = _gfm_mf_root_creation_options(pes).get(normalized_file_key)
            if mf_option is not None:
                mf_option = _gfm_mf_root_option_with_bootstrap_overrides(
                    mf_option,
                    bootstrap_overrides,
                )
                if isinstance(file_overrides, dict) and len(file_overrides) > 0:
                    root_template = mf_option["root_template"]
                    cloned_root = _clone_template_subtree(root_template)
                    cloned_profile = _FallbackProfileTemplate(cloned_root)
                    target_key = str(
                        getattr(mf_option["target_template"], "pe_name", "") or ""
                    ).strip()
                    bootstrap_keys = [
                        str(getattr(child, "pe_name", "") or "").strip()
                        for child in mf_option["bootstrap_children"]
                    ]
                    ancestor_keys = [
                        str(getattr(ancestor, "pe_name", "") or "").strip()
                        for ancestor in mf_option["relative_ancestors"]
                    ]
                    if len(target_key) > 0 and target_key in cloned_profile.files_by_pename:
                        _apply_file_overrides_to_template(
                            cloned_profile.files_by_pename[target_key],
                            file_overrides,
                            gfm_mode=True,
                        )
                    elif len(target_key) == 0:
                        cloned_root = _apply_file_overrides_to_template(
                            cloned_root,
                            file_overrides,
                            gfm_mode=True,
                        )
                        cloned_profile = _FallbackProfileTemplate(cloned_root)
                    mf_option = {
                        **mf_option,
                        "root_template": cloned_root,
                        "target_template": cloned_profile.files_by_pename.get(target_key, cloned_root),
                        "bootstrap_children": [
                            cloned_profile.files_by_pename[key]
                            for key in bootstrap_keys
                            if len(key) > 0 and key in cloned_profile.files_by_pename
                        ],
                        "relative_ancestors": [
                            cloned_profile.files_by_pename[key]
                            for key in ancestor_keys
                            if len(key) > 0 and key in cloned_profile.files_by_pename
                        ],
                    }
                root_template = mf_option["root_template"]
                target_template = mf_option["target_template"]
                bootstrap_children = list(mf_option["bootstrap_children"])
                relative_ancestors = list(mf_option["relative_ancestors"])
                root_fid = getattr(root_template, "fid", None)
                if isinstance(root_fid, int) is False:
                    raise ValueError(
                        f"Template root {normalized_file_key!r} does not expose a fixed FID."
                    )
                groups_to_insert: list[list[tuple[str, Any]]] = [
                    _gfm_group_for_file_template(
                        root_template,
                        [0x3F00],
                    )
                ]
                current_parent_path = [0x3F00, int(root_fid)]
                for child in bootstrap_children:
                    child_fid = getattr(child, "fid", None)
                    if isinstance(child_fid, int) is False:
                        continue
                    child_path = tuple(current_parent_path + [int(child_fid)])
                    if _gfm_profile_has_path(pes, child_path):
                        continue
                    groups_to_insert.append(
                        _gfm_group_for_file_template(
                            child,
                            current_parent_path,
                        )
                    )
                for ancestor in relative_ancestors:
                    ancestor_fid = getattr(ancestor, "fid", None)
                    if isinstance(ancestor_fid, int) is False:
                        continue
                    ancestor_path = tuple(current_parent_path + [int(ancestor_fid)])
                    if _gfm_profile_has_path(pes, ancestor_path) is False:
                        groups_to_insert.append(
                            _gfm_group_for_file_template(
                                ancestor,
                                current_parent_path,
                            )
                        )
                    current_parent_path = current_parent_path + [int(ancestor_fid)]
                if target_template is not root_template:
                    groups_to_insert.append(
                        _gfm_group_for_file_template(
                            target_template,
                            current_parent_path,
                        )
                    )
                commands[insert_index:insert_index] = groups_to_insert
                pe.decoded["fileManagementCMD"] = commands
                _reorder_gfm_decoded(pe)
                return _build_document_from_pes(pes, document)
        candidate_rows = _gfm_candidate_templates_for_context(
            template,
            context_template,
            context_path=context_path,
            existing_paths=_gfm_existing_paths(group_states),
        )
        file_template = next(
            (
                candidate
                for candidate, _relative_ancestors, _missing_ancestors in candidate_rows
                if str(getattr(candidate, "pe_name", "") or "").strip() == normalized_file_key
            ),
            None,
        )
        if file_template is None:
            raise ValueError(
                f"File {normalized_file_key!r} is not addable under {_gfm_context_label_from_path(context_path, group_states)!r} in PE {section_key!r}."
            )
        existing_paths = _gfm_existing_paths(group_states)
        missing_ancestors = [
            ancestor
            for ancestor in _relative_template_ancestors(
                file_template,
                _template_boundary(template, context_template),
            )
            if _template_node_full_path(context_path, template, context_template, ancestor) not in existing_paths
        ]
        file_template = _template_with_file_overrides(
            file_template,
            file_overrides,
            gfm_mode=True,
        )
        groups_to_insert: list[list[tuple[str, Any]]] = []
        current_parent_path = list(context_path)
        for ancestor in missing_ancestors:
            groups_to_insert.append(
                _gfm_group_for_file_template(
                    ancestor,
                    current_parent_path,
                )
            )
            ancestor_fid = getattr(ancestor, "fid", None)
            if isinstance(ancestor_fid, int):
                current_parent_path = current_parent_path + [int(ancestor_fid)]
        groups_to_insert.append(
            _gfm_group_for_file_template(
                file_template,
                current_parent_path,
            )
        )
        commands[insert_index:insert_index] = groups_to_insert
        pe.decoded["fileManagementCMD"] = commands
        _reorder_gfm_decoded(pe)
        return _build_document_from_pes(pes, document)
    template = _filesystem_template_for_pe(pe)
    context_template = _filesystem_context_for_pe(
        pe,
        template,
        context_key=context_key,
        section_key=section_key,
    )
    file_template = _template_file_for_pename(template, normalized_file_key)
    allowed_keys = {
        str(getattr(candidate, "pe_name", "") or "").strip()
        for candidate, _relative_ancestors, _missing_ancestors in _fs_candidate_templates_for_context(
            pe,
            template,
            context_template,
        )
    }
    if normalized_file_key not in allowed_keys or file_template is None:
        if normalized_file_key in getattr(pe, "decoded", {}):
            raise ValueError(f"File {normalized_file_key!r} already exists in PE {section_key!r}.")
        target_label = _context_label_for_template(
            template,
            context_template,
        )
        raise ValueError(
            f"File {normalized_file_key!r} is not addable under {target_label!r} in PE {section_key!r}."
        )
    for ancestor in _fs_missing_ancestors_for_file(
        pe,
        template,
        context_template,
        file_template,
    ):
        ancestor_key = str(getattr(ancestor, "pe_name", "") or "").strip()
        if len(ancestor_key) == 0 or ancestor_key in getattr(pe, "decoded", {}):
            continue
        pe.create_file(ancestor_key)
    pe.create_file(normalized_file_key)
    if isinstance(file_overrides, dict) and len(file_overrides) > 0:
        updated_template = _template_with_file_overrides(
            file_template,
            file_overrides,
            gfm_mode=False,
        )
        updated_entries = getattr(pe, "decoded", {}).get(normalized_file_key)
        if updated_entries is not None:
            _replace_decoded_file_descriptor(
                updated_entries,
                _explicit_file_descriptor(updated_template, gfm_mode=False),
            )
    _reorder_fs_profile_element_decoded(pe)
    return _build_document_from_pes(pes, document)


def insert_blank_pe_for_menu_id(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    menu_id: str,
    anchor_key: str | None = None,
    insert_after: bool = True,
) -> dict[str, Any]:
    """
    Parse ``document``, insert a new PE from pySim defaults at the requested anchor.

    With no anchor, default insertion remains immediately before ``end`` (or append if
    there is no ``end``).
    """
    if menu_id == "_cancel":
        raise ValueError("invalid menu_id")

    target_anchor = anchor_key
    target_after = insert_after
    if target_anchor is None:
        keys = _section_keys(document)
        for key in keys:
            if base_pe_type(key) == "end":
                target_anchor = key
                target_after = False
                break
    snapshot = _build_blank_pe_snapshot(menu_id)
    return paste_pe_snapshot(
        document,
        workspace_root,
        snapshot=snapshot,
        anchor_key=target_anchor,
        insert_after=target_after,
    )
