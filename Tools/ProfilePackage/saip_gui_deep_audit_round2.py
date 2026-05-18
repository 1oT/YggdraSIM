# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Second-pass SAIP GUI / backend consistency checks.

Complements :mod:`Tools.ProfilePackage.saip_ef_wizard_gui_audit` with angles
that do not overlap the EF wizard registry work: server action frozensets,
lossy-splice anchors, PE dispatch hygiene, and filesystem-branch parity with
``saip_pe_gui_gap._FILE_TEMPLATE_PE``.

Run::

    python3 -m Tools.ProfilePackage.saip_gui_deep_audit_round2
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"

_LOSSY_SPLICE_WITHOUT_FILE_SPEC: frozenset[str] = frozenset(
    {
        # ANR alpha-id / number slots share one physical ``ef-anr`` row in
        # ``_FILE_SPECS``; decoders use virtual last_ef_key disambiguators.
        "ef-anra",
        "ef-anrb",
        "ef-anrc",
        # LND is optional in some templates; pySim paths may still splice it.
        "ef-lnd",
    },
)


def _app_action_pe_sets() -> tuple[frozenset[str], frozenset[str], dict[str, str]]:
    from yggdrasim_common.gui_server.actions.saip import (
        _APP_FRIENDLY_TYPES,
        _APP_PE_TYPES,
        _SD_PE_TYPES,
    )

    return _SD_PE_TYPES, _APP_PE_TYPES, dict(_APP_FRIENDLY_TYPES)


def saip_app_pe_types_cover_security_domains() -> list[str]:
    """Return violations: ``_APP_PE_TYPES`` must cover ``_SD_PE_TYPES``."""
    sd, app, _friendly = _app_action_pe_sets()
    return sorted(pe for pe in sd if pe not in app)


def saip_app_friendly_types_match_app_pe_types() -> list[str]:
    """Return symmetric mismatches between friendly labels and app PE types."""
    _sd, app, friendly = _app_action_pe_sets()
    violations: list[str] = []
    for k in sorted(app):
        if k not in friendly:
            violations.append(f"app_pe_missing_label:{k}")
    for k in sorted(friendly):
        if k not in app:
            violations.append(f"friendly_unknown_pe:{k}")
    return violations


def lossy_splice_ef_keys_backed_by_file_specs() -> list[str]:
    """Return ``_LOSSY_SPLICE_EF_KEYS`` entries missing from ``_FILE_SPECS``."""
    from SIMCARD.saip_profile import _FILE_SPECS
    from Tools.ProfilePackage.saip_decoded_edit import _LOSSY_SPLICE_EF_KEYS
    from Tools.ProfilePackage.saip_ef_wizard_gui_audit import normalize_ef_gui_key

    spec = {normalize_ef_gui_key(x) for x in _FILE_SPECS}
    bad: list[str] = []
    for raw in sorted(_LOSSY_SPLICE_EF_KEYS):
        k = normalize_ef_gui_key(raw)
        if k in spec or k in _LOSSY_SPLICE_WITHOUT_FILE_SPEC:
            continue
        bad.append(raw)
    return bad


def hand_written_fill_ef_keys_backed_by_file_specs() -> list[str]:
    """Hand-written fillFileContent anchors must exist in ``_FILE_SPECS``."""
    from Tools.ProfilePackage.saip_decoded_edit_audit import _HAND_WRITTEN_FILL_FILE_CONTENT_EFS
    from Tools.ProfilePackage.saip_ef_wizard_gui_audit import normalize_ef_gui_key
    from SIMCARD.saip_profile import _FILE_SPECS

    spec = {normalize_ef_gui_key(x) for x in _FILE_SPECS}
    bad: list[str] = []
    for raw in sorted(_HAND_WRITTEN_FILL_FILE_CONTENT_EFS):
        k = normalize_ef_gui_key(raw)
        if k not in spec:
            bad.append(raw)
    return bad


def _else_if_dispatch_pe_types(body: str) -> list[str]:
    """PE strings only from ``} else if (t === …) {`` dispatch lines."""
    types: list[str] = []
    for line in body.splitlines():
        if "} else if (t ===" not in line:
            continue
        match = re.search(r"\}\s*else\s+if\s*\(\s*t\s*===\s*(.+)\)\s*\{", line)
        if match is None:
            continue
        cond = match.group(1).strip()
        types.extend(re.findall(r't\s*===\s*"([^"]+)"', cond))
    return types


def render_saip_pe_editor_duplicate_dispatch_types(app_js: str | None = None) -> list[str]:
    """Dispatch-only ``t ===`` PE literals repeated in ``renderSaipPeEditor``."""
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    start = text.find("function renderSaipPeEditor(")
    if start < 0:
        return ["missing_renderSaipPeEditor"]
    end = text.find("\n    return wrap;", start)
    if end < 0 or end <= start:
        return ["missing_return_wrap"]
    body = text[start:end]
    hits = _else_if_dispatch_pe_types(body)
    counts = Counter(hits)
    return sorted(pe for pe, n in counts.items() if n > 1)


def filesystem_template_branch_types(app_js: str | None = None) -> frozenset[str]:
    """PE type literals in the file-template ``if`` chain (``app.js``)."""
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    start = text.find('t === "usim" || t === "opt-usim"')
    if start < 0:
        return frozenset()
    end = text.find('|| t === "iot" || t === "opt-iot"', start)
    if end < 0:
        return frozenset()
    chunk = text[start : end + len('|| t === "iot" || t === "opt-iot"')]
    return frozenset(re.findall(r't === "([^"]+)"', chunk))


def filesystem_branch_matches_gap_module(app_js: str | None = None) -> list[str]:
    """``_FILE_TEMPLATE_PE`` must match the browser filesystem branch exactly."""
    from Tools.ProfilePackage.saip_pe_gui_gap import _FILE_TEMPLATE_PE

    parsed = filesystem_template_branch_types(app_js)
    expected = _FILE_TEMPLATE_PE
    violations: list[str] = []
    for pe in sorted(parsed - expected):
        violations.append(f"js_only:{pe}")
    for pe in sorted(expected - parsed):
        violations.append(f"gap_only:{pe}")
    return violations


def main() -> int:
    v1 = saip_app_pe_types_cover_security_domains()
    v2 = saip_app_friendly_types_match_app_pe_types()
    v3 = lossy_splice_ef_keys_backed_by_file_specs()
    v4 = hand_written_fill_ef_keys_backed_by_file_specs()
    v5 = render_saip_pe_editor_duplicate_dispatch_types()
    v6 = filesystem_branch_matches_gap_module()
    lines = [
        "_APP_PE_TYPES ⊇ _SD_PE_TYPES (expect []): " + repr(v1),
        "_APP_FRIENDLY_TYPES ↔ _APP_PE_TYPES (expect []): " + repr(v2),
        "_LOSSY_SPLICE_EF_KEYS ⊆ specs∪allow (expect []): " + repr(v3),
        "_HAND_WRITTEN_FILL_FILE_CONTENT_EFS ⊆ specs (expect []): " + repr(v4),
        "duplicate t=== in renderSaipPeEditor (expect []): " + repr(v5),
        "filesystem branch vs _FILE_TEMPLATE_PE (expect []): " + repr(v6),
    ]
    sys.stdout.write("\n".join(lines) + "\n")
    if any(len(x) > 0 for x in (v1, v2, v3, v4, v5, v6)):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
