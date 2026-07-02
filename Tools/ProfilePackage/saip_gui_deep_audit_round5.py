# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Fifth-pass SAIP workbench checks (icons, dispatch literals, GP tables).

Run::

    python3 -m Tools.ProfilePackage.saip_gui_deep_audit_round5
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_APP_CSS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.css"

_HAND_WRITTEN_NOT_IN_EDITABLE_SUBFIELDS: frozenset[str] = frozenset(
    {
        # Decoded-field leaf names, not ``update_file_field`` CHOICE sub-keys.
        "iccid",
        # ``fillFileOffset`` is routed through the fill-file / hex mutation
        # pipeline rather than the narrow FCP sub-field whitelist.
        "fillFileOffset",
    },
)

_FILE_SPEC_ALLOWED_STRUCTURES: frozenset[str] = frozenset(
    {
        "transparent",
        "linear-fixed",
        "cyclic",
        "ber_tlv",
    },
)


def _extract_saip_pe_registry_kind_values(app_js: str | None = None) -> frozenset[str]:
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    start = text.find("var SAIP_PE_REGISTRY = {")
    if start < 0:
        return frozenset()
    open_brace = text.find("{", start)
    depth = 0
    j = open_brace
    while j < len(text):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                block = text[open_brace + 1 : j]
                kinds = set(re.findall(r'kind:\s*"([^"]+)"', block))
                return frozenset(kinds)
        j += 1
    return frozenset()


def _saip_pe_icon_css_suffixes(app_css: str | None = None) -> frozenset[str]:
    text = (app_css if app_css is not None else _APP_CSS.read_text(encoding="utf-8"))
    return frozenset(re.findall(r"\.saip-pe-icon--([a-z0-9-]+)", text))


def registry_pe_icon_kinds_have_stylesheet_rules(
    app_js: str | None = None,
    app_css: str | None = None,
) -> list[str]:
    """Every ``SAIP_PE_REGISTRY`` ``kind`` must map to a ``.saip-pe-icon--*`` rule."""
    kinds = _extract_saip_pe_registry_kind_values(app_js)
    css = _saip_pe_icon_css_suffixes(app_css)
    return sorted(k for k in kinds if k not in css)


def hand_written_decoded_fields_vs_update_file_field_whitelist() -> list[str]:
    """Hand-written decoded leaves either match the FCP whitelist or are excused."""
    from Tools.ProfilePackage.saip_decoded_edit_audit import _HAND_WRITTEN_FIELDS
    from yggdrasim_common.gui_server.actions.saip import _EDITABLE_SUB_FIELDS

    bad: list[str] = []
    for field in sorted(_HAND_WRITTEN_FIELDS):
        if field in _EDITABLE_SUB_FIELDS or field in _HAND_WRITTEN_NOT_IN_EDITABLE_SUBFIELDS:
            continue
        bad.append(field)
    return bad


def file_spec_structure_vocabulary() -> list[str]:
    """``_FILE_SPECS`` ``structure`` values stay within the simulator vocabulary."""
    from SIMCARD.saip_profile import _FILE_SPECS

    bad: list[str] = []
    for raw_key, spec in _FILE_SPECS.items():
        struct = str(spec.get("structure") or "").strip().lower()
        if len(struct) == 0:
            bad.append(f"{raw_key}:empty_structure")
            continue
        if struct not in _FILE_SPEC_ALLOWED_STRUCTURES:
            bad.append(f"{raw_key}:{struct}")
    return bad


def _render_saip_pe_editor_body(app_js: str | None = None) -> str:
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    start = text.find("function renderSaipPeEditor(")
    if start < 0:
        return ""
    end = text.find("\n    return wrap;", start)
    if end < 0 or end <= start:
        return ""
    return text[start:end]


def _indirect_decoded_editor_pe_coverage(
    app_js: str,
    body: str,
) -> frozenset[str]:
    """PE bases covered by the direct decoded-editor dispatch path."""
    covered: set[str] = set()
    if "directEditor: true" not in body:
        return frozenset()
    if "saipIsPinPukSectionKey(sectionKey)" in app_js:
        covered.update({"pincodes", "pukcodes"})
    if "saipIsAkaSectionKey(sectionKey)" in app_js:
        covered.add("akaparameter")
    if "ssimEapTLSParameters" in app_js:
        covered.add("ssimeaptlsparameters")
    return frozenset(covered)


def dispatch_branch_literals_for_tiered_pe_types(app_js: str | None = None) -> list[str]:
    """Tiered PE bases have an explicit or direct-decoded editor path."""
    from Tools.ProfilePackage.saip_pe_gui_gap import (
        _NONSTANDARD_SPARSE_PE,
        _SECURITY_DOMAIN_PE,
        _SPARSE_CARD_PE,
        _TYPED_CARD_PE,
    )

    text = app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8")
    body = _render_saip_pe_editor_body(text)
    if len(body) == 0:
        return ["missing_renderSaipPeEditor_body"]
    required = _TYPED_CARD_PE | _SPARSE_CARD_PE | _NONSTANDARD_SPARSE_PE | _SECURITY_DOMAIN_PE
    covered = set(re.findall(r't\s*===\s*"([^"]+)"', body))
    covered.update(_indirect_decoded_editor_pe_coverage(text, body))
    missing: list[str] = []
    for pe in sorted(required):
        if pe not in covered:
            missing.append(pe)
    return missing


def gp_privilege_bit_masks_unique() -> list[str]:
    """GP Table 6-1 bit rows stay unique on (byte index, mask)."""
    from yggdrasim_common.gui_server.actions.saip import _GP_PRIVILEGE_BITS

    seen: set[tuple[int, int]] = set()
    dupes: list[str] = []
    for byte_idx, mask, label in _GP_PRIVILEGE_BITS:
        key = (byte_idx, mask)
        if key in seen:
            dupes.append(f"{label}:{key!r}")
        seen.add(key)
    return dupes


def main() -> int:
    v1 = registry_pe_icon_kinds_have_stylesheet_rules()
    v2 = hand_written_decoded_fields_vs_update_file_field_whitelist()
    v3 = file_spec_structure_vocabulary()
    v4 = dispatch_branch_literals_for_tiered_pe_types()
    v5 = gp_privilege_bit_masks_unique()
    lines = [
        "registry icon kinds vs app.css (expect []): " + repr(v1),
        "hand-written fields vs editable whitelist (expect []): " + repr(v2),
        "file spec structure vocabulary (expect []): " + repr(v3),
        "tiered PE dispatch literals in app.js (expect []): " + repr(v4),
        "duplicate GP privilege bits (expect []): " + repr(v5),
    ]
    sys.stdout.write("\n".join(lines) + "\n")
    if any(len(x) > 0 for x in (v1, v2, v3, v4, v5)):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
