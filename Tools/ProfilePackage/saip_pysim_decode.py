"""
Map SAIP profile-element context + FID to pySim ``CardEF`` instances and decode hex.

Used when :mod:`SCP03.core.decoders.ContentDecoder` has no handler or returns
nothing, and for duplicate FIDs (e.g. ``4F01`` under DF.SAIP vs DF.5GS) via
PE-type preference order.
"""

from __future__ import annotations

import json
from typing import Any

from Tools.ProfilePackage.saip_json_codec import base_pe_type

_CANDIDATES: dict[str, list[tuple[str, Any]]] | None = None


def _walk_cardefs(node: Any, tag: str, bucket: dict[str, list[tuple[str, Any]]]) -> None:
    from pySim.filesystem import CardDF, CardEF

    if isinstance(node, CardDF):
        for child in node.children.values():
            _walk_cardefs(child, tag, bucket)
        return
    if isinstance(node, CardEF):
        if node.fid:
            key = str(node.fid).lower()
            bucket.setdefault(key, []).append((tag, node))
        return


def _ensure_index() -> dict[str, list[tuple[str, Any]]]:
    global _CANDIDATES
    if _CANDIDATES is not None:
        return _CANDIDATES

    from pySim.filesystem import CardMF
    from pySim.ts_102_221 import CardProfileUICC
    from pySim.ts_31_102 import ADF_USIM, DF_5G_ProSe, DF_SAIP, DF_SNPN, DF_USIM_5GS
    from pySim.ts_31_103 import ADF_ISIM
    from pySim.ts_51_011 import DF_TELECOM

    bucket: dict[str, list[tuple[str, Any]]] = {}

    mf = CardMF()
    uicc = CardProfileUICC()
    for entry in uicc.files_in_mf:
        mf.add_file(entry, ignore_existing=True)
    _walk_cardefs(mf, "uicc_mf", bucket)

    _walk_cardefs(ADF_USIM(has_imsi=True), "usim", bucket)
    _walk_cardefs(DF_TELECOM(), "telecom", bucket)
    _walk_cardefs(DF_USIM_5GS(), "5gs", bucket)
    _walk_cardefs(DF_SNPN(), "snpn", bucket)
    _walk_cardefs(DF_SAIP(), "saip", bucket)
    _walk_cardefs(DF_5G_ProSe(), "5gprose", bucket)
    _walk_cardefs(ADF_ISIM(), "isim", bucket)

    _CANDIDATES = bucket
    return bucket


def _preference_tags(pe_section_key: str) -> list[str]:
    b = base_pe_type(pe_section_key).lower()
    table: dict[str, list[str]] = {
        "mf": ["uicc_mf", "usim"],
        "header": ["uicc_mf"],
        "telecom": ["telecom", "uicc_mf"],
        "phonebook": ["telecom", "uicc_mf"],
        "usim": ["usim", "uicc_mf"],
        "opt-usim": ["usim", "uicc_mf"],
        "gsm-access": ["usim", "uicc_mf"],
        "df-5gs": ["5gs", "usim", "uicc_mf"],
        "df-snpn": ["snpn", "usim", "uicc_mf"],
        "df-saip": ["saip", "5gs", "usim", "uicc_mf"],
        "df-5gprose": ["5gprose", "usim", "uicc_mf"],
        "isim": ["isim", "uicc_mf"],
        "opt-isim": ["isim", "uicc_mf"],
        "eap": ["usim", "uicc_mf"],
        "cd": ["uicc_mf", "usim"],
    }
    if b in table:
        return table[b]
    return ["usim", "uicc_mf", "telecom", "5gs", "saip", "snpn", "isim", "5gprose"]


def _select_ef(fid: str, pe_section_key: str) -> Any | None:
    idx = _ensure_index()
    key = fid.lower()
    rows = idx.get(key)
    if rows is None:
        return None
    if len(rows) == 1:
        return rows[0][1]

    prefs = _preference_tags(pe_section_key)
    for tag in prefs:
        for t, ef in rows:
            if t == tag:
                return ef
    return rows[0][1]


def _decode_ef_payload(ef: Any, hex_clean: str) -> dict[str, Any] | None:
    from pySim.filesystem import CyclicEF, LinFixedEF, TransparentEF

    try:
        if isinstance(ef, (LinFixedEF, CyclicEF)):
            return ef.decode_record_hex(hex_clean, record_nr=1)
        if isinstance(ef, TransparentEF):
            return ef.decode_hex(hex_clean)
    except Exception:
        return None
    return None


def pysim_decoded_adds_detail(decoded: dict[str, Any]) -> bool:
    """True when pySim output is more than a bare ``raw`` echo (for SCP03 append)."""
    if len(decoded) == 0:
        return False
    if len(decoded) == 1 and "raw" in decoded:
        return False
    return True


def pysim_try_decode_ef(
    fid: str | None,
    pe_section_key: str,
    hex_clean: str,
) -> tuple[list[str] | None, dict[str, Any] | None]:
    """
    Decode file payload using pySim's EF class for ``fid`` when indexed.

    Returns ``(lines, dict)`` or ``(None, None)`` if pySim unavailable, unknown FID,
    or decode fails.
    """
    if fid is None:
        return (None, None)
    if hex_clean == "":
        return (None, None)

    try:
        ef = _select_ef(fid, pe_section_key)
        if ef is None:
            return (None, None)
        decoded = _decode_ef_payload(ef, hex_clean)
        if decoded is None:
            return (None, None)
        name = getattr(ef, "name", None) or fid
        header = f"pySim {name} ({ef.__class__.__name__}, fid={fid.upper()})"
        try:
            payload = json.dumps(decoded, indent=2, ensure_ascii=True)
        except TypeError:
            payload = str(decoded)
        lines = [header, *payload.splitlines()]
        return (lines, decoded)
    except ImportError:
        return (None, None)
    except Exception:
        return (None, None)
