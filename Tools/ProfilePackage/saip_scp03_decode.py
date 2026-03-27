"""
SCP03 Admin-style decoders for tagged SAIP JSON (TRANSCODE-TUI).

Walks ``sections.*`` trees (``__ygg_saip_bytes__``, ``__ygg_saip_tuple__``) and
invokes :class:`SCP03.core.decoders.ContentDecoder` with FID + filesystem context
hints. When ContentDecoder has no match, pySim ``CardEF`` templates are used
(:mod:`Tools.ProfilePackage.saip_pysim_decode`) before TLV-map fallback. Security-domain
blobs fall back to GP SEAC / PKCS#15-style decoders or a generic BER-TLV tree from
:class:`SCP03.core.utils.TlvParser`.
"""

from __future__ import annotations

import re
from typing import Any

from Tools.ProfilePackage.saip_json_codec import (
    _TAG_BYTES,
    _TAG_TUPLE,
    _LEGACY_TAG_BYTES,
    _LEGACY_TAG_TUPLE,
    _structural_data_keys,
    _value_first,
    base_pe_type,
)

_EF_KEY_TO_FID: dict[str, str] = {
    "ef-iccid": "2FE2",
    "ef-dir": "2F00",
    "ef-pl": "2F05",
    "ef-imsi": "6F07",
    "ef-ad": "6FAD",
    "ef-msisdn": "6F40",
    "ef-spn": "6F46",
    "ef-ust": "6F38",
    "ef-ust-service-table": "6F38",
    "ef-acc": "6F78",
    "ef-loci": "6F7E",
    "ef-psloci": "6F73",
    "ef-epsloci": "6FE3",
    "ef-plmnwact": "6F60",
    "ef-oplmnwact": "6F61",
    "ef-hplmnwact": "6F62",
    "ef-fplmn": "6F7B",
    "ef-gid1": "6F3E",
    "ef-gid2": "6F3F",
    "ef-smsp": "6F42",
    "ef-smss": "6F43",
    "ef-sms": "6F3C",
    "ef-cbmi": "6F45",
    "ef-cbmir": "6F50",
    "ef-cbmid": "6F48",
    "ef-sume": "6F5B",
    "ef-s7": "6F5C",
    "ef-li": "6F05",
    "ef-acmax": "6F37",
    "ef-acm": "6F39",
    "ef-ecc": "6FB7",
    "ef-puct": "6F41",
    "ef-adn": "6F3A",
    "ef-fdn": "6F3B",
    "ef-sdn": "6F49",
    "ef-lnd": "6F44",
    "ef-pnn": "6FC5",
    "ef-opl": "6FC6",
    "ef-spdi": "6FCD",
    "ef-epsnsc": "6FE4",
    "ef-gbanl": "6FDA",
    "ef-nafkca": "6FDD",
    "ef-keysPS": "6F09",
    "ef-pcscf": "6F09",
    "ef-suci-calc-info-usim": "4F01",
    "ef-supinai": "4F09",
}


def _filesystem_hint(pe_base: str) -> str | None:
    mapping: dict[str, str] = {
        "telecom": "MF/TELECOM",
        "phonebook": "MF/TELECOM/PHONEBOOK",
        "graphics": "MF/TELECOM/GRAPHICS",
        "multimedia": "MF/TELECOM/MULTIMEDIA",
        "mmss": "MF/TELECOM/MMSS",
        "cd": "MF/CD",
        "df-5gs": "MF/USIM/5GS",
        "df-snpn": "MF/USIM/SNPN",
        "df-saip": "MF/USIM/SAIP",
        "df-5gprose": "MF/USIM/5G_PROSE",
        "eap": "MF/USIM/EAP",
        "isim": "MF/ISIM",
        "opt-isim": "MF/ISIM",
        "mcs": "MF/USIM/MCS",
        "v2x": "MF/USIM/V2X",
        "a2x": "MF/USIM/A2X",
    }
    return mapping.get(pe_base)


def _fid_for_ef_key(pe_section_key: str, ef_key: str) -> str | None:
    pe_base = base_pe_type(pe_section_key)
    if ef_key == "ef-arr":
        if pe_base == "mf":
            return "2F06"
        return "6F06"
    return _EF_KEY_TO_FID.get(ef_key)


def _hex_from_tagged_bytes(value: Any) -> str | None:
    if isinstance(value, dict) is False:
        return None
    if set(_structural_data_keys(value)) != {_TAG_BYTES}:
        return None
    text = str(_value_first(value, _TAG_BYTES, _LEGACY_TAG_BYTES)).strip()
    text = re.sub(r"\s+", "", text)
    if re.fullmatch(r"[0-9A-Fa-f]*", text) is None:
        return None
    if len(text) % 2 != 0:
        return None
    return text.upper()


def _is_security_domain_pe(pe_section_key: str) -> bool:
    return base_pe_type(pe_section_key).lower() == "securitydomain"


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _looks_like_hex(value: str) -> bool:
    if len(value) < 8:
        return False
    if len(value) % 2 != 0:
        return False
    for character in value.upper():
        if character not in "0123456789ABCDEF":
            return False
    return True


def _format_scalar(value: Any) -> str:
    if value is None:
        return "Present"
    if isinstance(value, bool):
        if value:
            return "True"
        return "False"
    text = str(value).strip()
    if _looks_like_hex(text) and len(text) > 64:
        return f"{text[:32]}...{text[-24:]}"
    if len(text) > 120:
        return f"{text[:60]}...{text[-40:]}"
    return text


def _pad_key(name: str, key_width: int | None) -> str:
    if key_width is None:
        return name
    if len(name) >= key_width:
        return name
    return f"{name:<{key_width}}"


def _compute_key_width(value: dict[Any, Any]) -> int:
    width = 0
    for key in value.keys():
        width = max(width, len(str(key)))
    width = max(width, 18)
    width = min(width, 32)
    return width


def _format_block_header(name: str, indent: int, key_width: int | None = None) -> str:
    prefix = "  " * indent
    padded_name = _pad_key(name, key_width)
    return f"{prefix}| {padded_name}"


def _format_scalar_line(
    name: str | None,
    value: Any,
    indent: int,
    key_width: int | None = None,
) -> str:
    prefix = "  " * indent
    rendered_value = _format_scalar(value)
    if name is None:
        return f"{prefix}| {rendered_value}"
    padded_name = _pad_key(str(name), key_width)
    if key_width is None:
        return f"{prefix}| {padded_name:<28} : {rendered_value}"
    return f"{prefix}| {padded_name} : {rendered_value}"


def _format_inline_scalar_list(values: list[Any]) -> str | None:
    if len(values) == 0:
        return "[]"
    for value in values:
        if _is_scalar(value) is False:
            return None
    parts = [_format_scalar(value) for value in values[:8]]
    if len(values) > 8:
        parts.append(f"... (+{len(values) - 8})")
    text = ", ".join(parts)
    if len(text) > 120:
        text = text[:88] + "..."
    return f"[{text}]"


def _render_compact_value(
    value: Any,
    *,
    indent: int = 0,
    name: str | None = None,
    key_width: int | None = None,
) -> list[str]:
    if _is_scalar(value):
        return [_format_scalar_line(name, value, indent, key_width)]

    if isinstance(value, dict):
        if len(value) == 0:
            return [_format_scalar_line(name, "{}", indent, key_width)]
        lines: list[str] = []
        child_indent = indent
        if name is not None:
            lines.append(_format_block_header(name, indent, key_width))
            child_indent += 1
        child_width = _compute_key_width(value)
        for child_name, child_value in value.items():
            lines.extend(
                _render_compact_value(
                    child_value,
                    indent=child_indent,
                    name=str(child_name),
                    key_width=child_width,
                )
            )
        return lines

    if isinstance(value, list):
        inline = _format_inline_scalar_list(value)
        if inline is not None:
            return [_format_scalar_line(name, inline, indent, key_width)]
        if len(value) == 0:
            return [_format_scalar_line(name, "[]", indent, key_width)]
        lines: list[str] = []
        child_indent = indent
        if name is not None:
            lines.append(_format_block_header(name, indent, key_width))
            child_indent += 1
        for index, item in enumerate(value):
            lines.extend(
                _render_compact_value(
                    item,
                    indent=child_indent,
                    name=f"[{index}]",
                )
            )
        return lines

    return [_format_scalar_line(name, repr(value), indent, key_width)]


def _compact_decode_lines(lines: list[str]) -> list[str]:
    compacted: list[str] = []
    pending_blank = False
    for raw_line in lines:
        line = str(raw_line).rstrip()
        if len(line) == 0:
            if len(compacted) == 0:
                continue
            pending_blank = True
            continue
        if pending_blank:
            compacted.append("")
            pending_blank = False
        compacted.append(line)
    while compacted and compacted[-1] == "":
        compacted.pop()
    return compacted


def _compact_block(title: str, payload: Any) -> list[str]:
    return [title, *_render_compact_value(payload, indent=1)]


def _format_hits(hits: list[tuple[str, list[str]]]) -> str:
    lines_out: list[str] = []
    for index, (title, chunk) in enumerate(hits):
        if index > 0:
            lines_out.append("")
        lines_out.append(f"[{title}]")
        lines_out.extend(_compact_decode_lines(chunk))
    return "\n".join(lines_out).rstrip() + "\n"


def _decode_ambiguous_sd_blob(hex_clean: str) -> list[str]:
    try:
        from SCP03.core.decoders import AdvancedDecoders, ContentDecoder
        from SCP03.core.utils import TlvParser
    except ImportError as exc:
        return [f"SCP03 decoders unavailable: {exc}"]

    gp = AdvancedDecoders.decode_gp_seac_arf(hex_clean)
    if gp:
        first = gp[0]
        if first.startswith("GP_SEAC: Empty") is False:
            if first.startswith("GP_SEAC: Hex Decode Error") is False:
                if first.startswith("GP_SEAC: No TLV entries") is False:
                    return gp

    try:
        lines = ContentDecoder.decode_pkcs15_acrf_json(hex_clean)
        if lines:
            head = str(lines[0])
            if "Parse Error" not in head and "Hex Decode Error" not in head:
                return lines
    except Exception:
        pass

    try:
        raw = bytes.fromhex(hex_clean)
        parsed = TlvParser.parse(raw)
        tree = ContentDecoder._tlv_to_obj(parsed)
        return _compact_block("BER-TLV (generic)", tree)
    except Exception as exc:
        return [f"BER-TLV fallback failed: {exc}"]


def _decode_one_blob(
    fid: str | None,
    hex_clean: str,
    context_path: str | None,
    pe_section_key: str,
) -> list[str]:
    try:
        from SCP03.core.decoders import ContentDecoder
    except ImportError as exc:
        return [f"SCP03 decoders unavailable: {exc}"]

    if hex_clean == "":
        return []

    if _is_security_domain_pe(pe_section_key):
        if fid is not None:
            text = ContentDecoder.decode(fid, hex_clean, context_path=context_path or "")
            if text:
                return text.strip().split("\n")
        return _decode_ambiguous_sd_blob(hex_clean)

    if fid is None:
        if _is_security_domain_pe(pe_section_key):
            return _decode_ambiguous_sd_blob(hex_clean)
        try:
            mapped = ContentDecoder.decode_tlv_as_map(hex_clean)
            return _compact_block("TLV map (no EF FID)", mapped)
        except Exception:
            return [f"(no FID mapping; {len(hex_clean) // 2} bytes hex)"]

    text = ContentDecoder.decode(fid, hex_clean, context_path=context_path or "")
    scp_lines: list[str] = []
    if text:
        scp_lines = text.strip().split("\n")

    from Tools.ProfilePackage.saip_pysim_decode import (
        pysim_decoded_adds_detail,
        pysim_try_decode_ef,
    )

    pysim_lines, pysim_dec = pysim_try_decode_ef(fid, pe_section_key, hex_clean)
    compact_pysim_lines = pysim_lines
    if pysim_lines and pysim_dec is not None:
        compact_pysim_lines = [
            str(pysim_lines[0]).rstrip(),
            *_render_compact_value(pysim_dec, indent=1),
        ]

    if len(scp_lines) > 0:
        if pysim_lines and pysim_dec and pysim_decoded_adds_detail(pysim_dec):
            merged = list(scp_lines)
            merged.append("")
            if compact_pysim_lines:
                merged.extend(compact_pysim_lines)
            else:
                merged.extend(pysim_lines)
            return merged
        return scp_lines

    if compact_pysim_lines:
        return compact_pysim_lines
    if pysim_lines:
        return pysim_lines

    try:
        mapped = ContentDecoder.decode_tlv_as_map(hex_clean)
        return _compact_block(f"TLV map (FID {fid})", mapped)
    except Exception:
        return [f"No ContentDecoder match for FID {fid} ({len(hex_clean)//2} bytes)."]


def _walk(
    value: Any,
    pe_section_key: str,
    path_tail: list[str],
    last_ef_key: str | None,
    out: list[tuple[str, list[str]]],
    max_hits: int,
) -> None:
    if len(out) >= max_hits:
        return

    pe_base = base_pe_type(pe_section_key)
    ctx = _filesystem_hint(pe_base)

    if isinstance(value, dict):
        keys_structural = set(_structural_data_keys(value))
        if keys_structural == {_TAG_BYTES}:
            hx = _hex_from_tagged_bytes(value)
            if hx is None:
                return
            parent_key = path_tail[-1] if len(path_tail) > 0 else ""
            grand = path_tail[-2] if len(path_tail) > 1 else ""
            fid: str | None = None
            ef_guess = last_ef_key
            if ef_guess is None and parent_key.startswith("ef-"):
                ef_guess = parent_key
            if ef_guess is None and parent_key == "fillFileContent" and grand.startswith("ef-"):
                ef_guess = grand
            if ef_guess is not None:
                fid = _fid_for_ef_key(pe_section_key, ef_guess)
            lines = _decode_one_blob(fid, hx, ctx, pe_section_key)
            if len(lines) > 0:
                label = "/".join(path_tail[-4:]) if len(path_tail) > 0 else "(bytes)"
                out.append((f"{pe_section_key} :: {label}", lines))
            return

        if keys_structural == {_TAG_TUPLE}:
            inner = _value_first(value, _TAG_TUPLE, _LEGACY_TAG_TUPLE)
            if isinstance(inner, list) and len(inner) >= 2:
                tag = inner[0]
                payload = inner[1]
                if tag == "fillFileContent":
                    _walk(
                        payload,
                        pe_section_key,
                        path_tail + ["fillFileContent"],
                        last_ef_key,
                        out,
                        max_hits,
                    )
                    return
                _walk(
                    payload,
                    pe_section_key,
                    path_tail + [str(tag)],
                    last_ef_key,
                    out,
                    max_hits,
                )
            return

        for key, child in value.items():
            key_text = str(key)
            if key_text.startswith("__ygg_"):
                continue
            next_ef = last_ef_key
            if key_text.startswith("ef-"):
                next_ef = key_text
            _walk(child, pe_section_key, path_tail + [key_text], next_ef, out, max_hits)
        return

    if isinstance(value, list):
        for idx, child in enumerate(value):
            _walk(
                child,
                pe_section_key,
                path_tail + [f"[{idx}]"],
                last_ef_key,
                out,
                max_hits,
            )
        return


def build_scp03_decode_report(
    tagged_document: dict[str, Any],
    *,
    max_sections: int = 32,
    max_hits_per_doc: int = 120,
) -> str:
    """
    Produce plain-text lines for the TRANSCODE bottom panel.

    Expects a **JSON-loaded** root object (``intro`` / ``sections`` / meta), not
    dejsonified Python bytes.
    """
    sections = tagged_document.get("sections")
    if isinstance(sections, dict) is False:
        return "No sections object — cannot decode."

    hits: list[tuple[str, list[str]]] = []
    count_sections = 0

    for section_key, section_value in sections.items():
        if count_sections >= max_sections:
            break
        count_sections += 1
        sk = str(section_key)
        _walk(section_value, sk, [sk], None, hits, max_hits_per_doc)

    if len(hits) == 0:
        return (
            "No decodable byte blobs found (look for __ygg_saip_bytes__ under "
            "ef-* / fillFileContent, or securityDomain TLVs)."
        )

    if len(hits) > max_hits_per_doc:
        visible = hits[:max_hits_per_doc]
        return _format_hits(visible).rstrip() + (
            f"\n\n[truncated: {len(hits)} hits, showing {max_hits_per_doc}]\n"
        )

    return _format_hits(hits[:max_hits_per_doc])


def build_inspector_report_for_subtree(
    subtree: Any,
    pe_section_key: str,
    *,
    focus_path_hint: list[str] | None = None,
    last_ef_key: str | None = None,
    max_hits: int = 16,
) -> str:
    """
    SCP03 / pySim decode lines for tagged ``__ygg_saip_bytes__`` under a JSON subtree
    (TRANSCODE left inspector). Expects **json.loads** output shapes.
    """
    hits: list[tuple[str, list[str]]] = []
    path_tail = ["selection"]
    if focus_path_hint:
        path_tail = list(focus_path_hint)
    _walk(subtree, pe_section_key, path_tail, last_ef_key, hits, max_hits)
    if len(hits) == 0:
        if isinstance(subtree, dict):
            visible = [
                str(k)
                for k in subtree.keys()
                if str(k).startswith("__ygg_") is False and str(k) != "label"
            ]
            sample = ", ".join(visible[:10])
            suffix = " …" if len(visible) > 10 else ""
            return (
                f"No decodable tagged bytes under this object ({len(visible)} key(s)).\n"
                f"Keys: {sample}{suffix}"
            )
        if isinstance(subtree, list):
            return f"No decodable tagged bytes under this list ({len(subtree)} item(s))."
        text = repr(subtree)
        if len(text) > 240:
            text = text[:237] + "..."
        return f"No decodable tagged bytes under this value: {text}"

    return _format_hits(hits)
