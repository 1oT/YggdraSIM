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
        ("_cancel", "— Cancel —", None, False),
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
