"""
TRANSCODE-TUI left inspector: decode the JSON selection (or whole profile) via SCP03/pySim.
"""

from __future__ import annotations

import json
from typing import Any

from Tools.ProfilePackage.saip_transcode_sync import (
    enclosing_json_value_span,
    infer_section_key_from_json_cursor,
)


def _line_index_for_offset(text: str, offset: int) -> int:
    if offset <= 0:
        return 0
    capped = min(offset, len(text))
    return text.count("\n", 0, capped)


def build_transcode_inspector_text(
    editor_text: str,
    sel_start: int,
    sel_end: int,
    *,
    left_mode: str,
    fixed_span: tuple[int, int] | None = None,
    pe_key_hint: str | None = None,
    focus_key_hint: str | None = None,
) -> str:
    """
    ``left_mode``: ``selection`` (nearest JSON value + subtree decode) or ``profile_scp03``
    (full-document walk, same engine as former single-panel F4).
    """
    stripped = str(editor_text or "").strip()
    if len(stripped) == 0:
        return "JSON empty."

    if left_mode == "profile_scp03":
        from Tools.ProfilePackage.saip_scp03_decode import build_scp03_decode_report

        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return f"JSON parse error — cannot run profile decode:\n{exc}"
        if isinstance(loaded, dict) is False:
            return "Root must be a JSON object for profile-wide decode."
        return build_scp03_decode_report(loaded)

    from Tools.ProfilePackage.saip_scp03_decode import build_inspector_report_for_subtree

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

    frag = editor_text[s:e].strip()
    if len(frag) == 0:
        return "Empty selection span."

    try:
        sub: Any = json.loads(frag)
    except json.JSONDecodeError as exc:
        return (
            f"Span [{s}:{e}) is not valid JSON ({exc}).\n"
            f"PE context (heuristic): {pe_key}\n"
            + frag[:800]
            + ("\n…" if len(frag) > 800 else "")
        )

    header = f"PE: {pe_key}\n"
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
    return header + body
