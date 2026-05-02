"""
TRANSCODE-TUI left inspector: decode the JSON selection or whole profile.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from Tools.ProfilePackage.saip_json_codec import humanize_saip_display_name
from Tools.ProfilePackage.saip_transcode_sync import (
    enclosing_json_value_span,
    infer_section_key_from_json_cursor,
)


def _line_index_for_offset(text: str, offset: int) -> int:
    if offset <= 0:
        return 0
    capped = min(offset, len(text))
    return text.count("\n", 0, capped)


def _tuple_payloads(file_value: Any) -> list[tuple[str, Any]]:
    if isinstance(file_value, list) is False:
        return []
    out: list[tuple[str, Any]] = []
    for item in file_value:
        if isinstance(item, dict) is False:
            continue
        tagged = item.get("@")
        if isinstance(tagged, list) is False:
            continue
        if len(tagged) != 2:
            continue
        tag_name = tagged[0]
        if isinstance(tag_name, str) is False:
            continue
        out.append((tag_name, tagged[1]))
    return out


def _template_default_field_descriptions(
    file_template: Any,
    *,
    arr_summary: str | None = None,
) -> list[str]:
    out: list[str] = []
    fid = getattr(file_template, "fid", None)
    if isinstance(fid, int):
        out.append(f"fileID {fid:04X}")
    sfi = getattr(file_template, "sfi", None)
    if isinstance(sfi, int):
        out.append(f"shortEFID {sfi:02X}")
    arr = getattr(file_template, "arr", None)
    if isinstance(arr, int):
        if isinstance(arr_summary, str) and len(arr_summary.strip()) > 0:
            out.append(
                f"securityAttributesReferenced record {arr}: {arr_summary.strip()}"
            )
        else:
            out.append(f"securityAttributesReferenced record {arr}")
    file_type = str(getattr(file_template, "file_type", "") or "").upper()
    if file_type in {"TR", "BT"}:
        file_size = getattr(file_template, "file_size", None)
        if isinstance(file_size, int):
            out.append(f"file size {file_size}")
    if file_type in {"LF", "CY"}:
        rec_len = getattr(file_template, "rec_len", None)
        nb_rec = getattr(file_template, "nb_rec", None)
        if isinstance(rec_len, int) and isinstance(nb_rec, int):
            out.append(f"record layout {nb_rec} x {rec_len}")
    if bool(getattr(file_template, "high_update", False)):
        out.append("high update")
    default_val = getattr(file_template, "default_val", None)
    if isinstance(default_val, str) and len(default_val.strip()) > 0:
        out.append(f"default content pattern {default_val.strip()}")
    return out


def _implicit_template_defaults_report(
    loaded_document: Any,
    *,
    pe_key: str,
    focus_key_hint: str | None,
) -> str | None:
    if isinstance(loaded_document, dict) is False:
        return None
    sections = loaded_document.get("sections", {})
    if isinstance(sections, dict) is False:
        return None
    section = sections.get(pe_key)
    if isinstance(section, dict) is False:
        return None
    template_id = str(section.get("templateID", "") or "").strip()
    if len(template_id) == 0:
        return None

    try:
        from Tools.ProfilePackage.saip_json_codec import ensure_workspace_pysim_on_path

        ensure_workspace_pysim_on_path(Path(__file__).resolve().parents[2])
        from pySim.esim.saip import templates
    except Exception:
        return None

    template = templates.ProfileTemplateRegistry.get_by_oid(template_id)
    if template is None:
        return None

    mode = "created by default" if bool(getattr(template, "created_by_default", False)) else "not created by default"
    base_df = template.base_df()
    base_name = str(getattr(base_df, "name", "") or getattr(base_df, "pe_name", "") or "root")
    lines = [
        "Template defaults",
        f"Template OID: {template_id}",
        f"Template mode: {mode}",
        f"Base root: {base_name}",
    ]

    if focus_key_hint is None:
        return "\n".join(lines)

    file_template = _template_file_for_focus(template, focus_key_hint)
    if file_template is None:
        return "\n".join(lines)

    file_name = str(getattr(file_template, "name", "") or focus_key_hint)
    fid = getattr(file_template, "fid", None)
    file_type = str(getattr(file_template, "file_type", "") or "").upper()
    file_summary = file_name
    if isinstance(fid, int):
        file_summary = f"{file_name} ({fid:04X})"
    if len(file_type) > 0:
        file_summary = f"{file_summary} [{file_type}]"
    lines.append(f"Selected file: {file_summary}")

    arr_summary = None
    arr_record = getattr(file_template, "arr", None)
    if isinstance(arr_record, int):
        from Tools.ProfilePackage.saip_asn1_decode import describe_arr_record_from_section

        arr_summary = describe_arr_record_from_section(
            section,
            record_number=arr_record,
        )

    defaults = _template_default_field_descriptions(
        file_template,
        arr_summary=arr_summary,
    )
    if len(defaults) > 0:
        lines.append("Standard template values:")
        for item in defaults:
            lines.append(f"- {item}")

    file_value = section.get(focus_key_hint)
    descriptor_payload: dict[str, Any] = {}
    tuple_tags = {tag_name for tag_name, payload in _tuple_payloads(file_value)}
    for tag_name, payload_value in _tuple_payloads(file_value):
        if tag_name == "fileDescriptor" and isinstance(payload_value, dict):
            descriptor_payload = payload_value
            break

    implicit: list[str] = []
    for item in defaults:
        normalized = item.lower()
        if normalized.startswith("fileid ") and "fileID" not in descriptor_payload:
            implicit.append(item)
            continue
        if normalized.startswith("shortefid ") and "shortEFID" not in descriptor_payload:
            implicit.append(item)
            continue
        if normalized.startswith("securityattributesreferenced ") and "securityAttributesReferenced" not in descriptor_payload:
            implicit.append(item)
            continue
        if normalized.startswith("file size ") and "efFileSize" not in descriptor_payload:
            implicit.append(item)
            continue
        if normalized.startswith("record layout ") and "efFileSize" not in descriptor_payload:
            implicit.append(item)
            continue
        if normalized == "high update" and "proprietaryEFInfo" not in descriptor_payload:
            implicit.append(item)
            continue
        if normalized.startswith("default content pattern"):
            if "fillFileContent" not in tuple_tags and "fillFileOffset" not in tuple_tags:
                implicit.append(item)

    if len(implicit) > 0:
        lines.append("Implicit here because the JSON omits them:")
        for item in implicit:
            lines.append(f"- {item}")

    params = list(getattr(file_template, "params", []) or [])
    if len(params) > 0:
        lines.append("Template parameters without a universal default:")
        for param_name in params:
            lines.append(f"- {param_name}")

    return "\n".join(lines)


def _template_file_for_focus(template: Any, focus_key_hint: str) -> Any | None:
    file_template = getattr(template, "files_by_pename", {}).get(str(focus_key_hint))
    if file_template is not None:
        return file_template
    base_df = template.base_df()
    base_key = str(getattr(base_df, "pe_name", "") or "").strip()
    if focus_key_hint == base_key:
        return base_df
    return None


def build_template_defaults_report(
    loaded_document: Any,
    *,
    pe_key: str,
    focus_key_hint: str | None,
) -> str | None:
    return _implicit_template_defaults_report(
        loaded_document,
        pe_key=pe_key,
        focus_key_hint=focus_key_hint,
    )


def build_transcode_inspector_text(
    editor_text: str,
    sel_start: int,
    sel_end: int,
    *,
    left_mode: str,
    fixed_span: tuple[int, int] | None = None,
    pe_key_hint: str | None = None,
    focus_key_hint: str | None = None,
    subtree_override: Any | None = None,
) -> str:
    """
    ``left_mode``: ``selection`` (nearest JSON value + subtree decode) or
    ``profile_asn1`` (full-document walk across all profile elements).
    """
    stripped = str(editor_text or "").strip()
    if len(stripped) == 0:
        return "JSON empty."

    if left_mode == "profile_asn1":
        from Tools.ProfilePackage.saip_asn1_decode import build_profile_asn1_report

        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return f"JSON parse error -- cannot run profile decode:\n{exc}"
        if isinstance(loaded, dict) is False:
            return "Root must be a JSON object for profile-wide decode."
        return build_profile_asn1_report(loaded)

    from Tools.ProfilePackage.saip_asn1_decode import build_inspector_report_for_subtree

    if fixed_span is None:
        s, e = enclosing_json_value_span(editor_text, sel_start, sel_end)
    else:
        s, e = fixed_span
    line = _line_index_for_offset(editor_text, s)
    pe_key = pe_key_hint
    if pe_key is None:
        pe_key = infer_section_key_from_json_cursor(editor_text, line)
    if pe_key is None:
        pe_key = "mf"

    try:
        loaded_document = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return f"JSON parse error -- cannot inspect selection:\n{exc}"

    sub: Any
    if subtree_override is not None:
        sub = subtree_override
    else:
        frag = editor_text[s:e].strip()
        if len(frag) == 0:
            return "Empty selection span."
        try:
            sub = json.loads(frag)
        except json.JSONDecodeError as exc:
            return (
                f"Span [{s}:{e}) is not valid JSON ({exc}).\n"
                f"PE context (heuristic): {pe_key}\n"
                + frag[:800]
                + ("\n..." if len(frag) > 800 else "")
            )

    header = f"PE: {humanize_saip_display_name(pe_key)}\n"
    focus_path_hint = None
    last_ef_key = None
    if focus_key_hint is not None:
        focus_path_hint = [focus_key_hint]
        if focus_key_hint.startswith("ef-"):
            last_ef_key = focus_key_hint
    body = build_inspector_report_for_subtree(
        sub,
        pe_key,
        focus_path_hint=focus_path_hint,
        last_ef_key=last_ef_key,
    )
    output_text = header + body
    arr_summary_line = _resolve_arr_rule_summary_line(
        loaded_document,
        pe_key=pe_key,
        focus_key_hint=focus_key_hint,
    )
    if len(arr_summary_line) > 0:
        output_text = f"{output_text.rstrip()}\n{arr_summary_line}\n"
    return output_text


_ARR_FILE_TEMPLATE_CACHE: dict[tuple[str, str], tuple[Any, int] | None] = {}


def _resolve_file_template_with_arr(
    template_id: str,
    focus_key_hint: str,
) -> tuple[Any, int] | None:
    """Memoised lookup of (file_template, arr_record) for a template focus.

    The TRANSCODE-TUI rebuilds the inspector on every cursor move, so looking
    up the ProfileTemplateRegistry and pySim module on each call adds up. This
    cache keeps repeat selections on the same file essentially free.
    """
    cache_key = (template_id, focus_key_hint)
    if cache_key in _ARR_FILE_TEMPLATE_CACHE:
        return _ARR_FILE_TEMPLATE_CACHE[cache_key]
    try:
        from Tools.ProfilePackage.saip_json_codec import ensure_workspace_pysim_on_path

        ensure_workspace_pysim_on_path(Path(__file__).resolve().parents[2])
        from pySim.esim.saip import templates
    except Exception:
        _ARR_FILE_TEMPLATE_CACHE[cache_key] = None
        return None
    template = templates.ProfileTemplateRegistry.get_by_oid(template_id)
    if template is None:
        _ARR_FILE_TEMPLATE_CACHE[cache_key] = None
        return None
    file_template = _template_file_for_focus(template, focus_key_hint)
    if file_template is None:
        _ARR_FILE_TEMPLATE_CACHE[cache_key] = None
        return None
    arr_record = getattr(file_template, "arr", None)
    if isinstance(arr_record, int) is False:
        _ARR_FILE_TEMPLATE_CACHE[cache_key] = None
        return None
    resolved = (file_template, int(arr_record))
    _ARR_FILE_TEMPLATE_CACHE[cache_key] = resolved
    return resolved


def _resolve_arr_rule_summary_line(
    loaded_document: Any,
    *,
    pe_key: str | None,
    focus_key_hint: str | None,
) -> str:
    """Emit a single ARR rule summary line for the focused EF, if resolvable.

    The TRANSCODE-TUI inspector keeps its selection-mode output compact. When
    the focused EF is covered by a profile template with a fixed ARR record
    reference, and the same PE section carries a matching ARR payload, we
    surface the decoded rule summary on a single line so operators can see the
    referenced access rule without switching to the template-defaults pane.
    """
    if isinstance(loaded_document, dict) is False:
        return ""
    if pe_key is None or focus_key_hint is None:
        return ""
    sections = loaded_document.get("sections", {})
    if isinstance(sections, dict) is False:
        return ""
    section = sections.get(pe_key)
    if isinstance(section, dict) is False:
        return ""
    if isinstance(section.get("ef-arr"), list) is False:
        return ""
    template_id = str(section.get("templateID", "") or "").strip()
    if len(template_id) == 0:
        return ""
    resolved = _resolve_file_template_with_arr(template_id, focus_key_hint)
    if resolved is None:
        return ""
    _file_template, arr_record = resolved
    from Tools.ProfilePackage.saip_asn1_decode import describe_arr_record_from_section

    arr_summary = describe_arr_record_from_section(
        section,
        record_number=arr_record,
    )
    if isinstance(arr_summary, str) is False:
        return ""
    summary_text = arr_summary.strip()
    if len(summary_text) == 0:
        return ""
    return f"securityAttributesReferenced record {arr_record}: {summary_text}"
