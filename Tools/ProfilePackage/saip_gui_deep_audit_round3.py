# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Third-pass SAIP GUI / tooling consistency (quick-add, tiers, actions, FS markers).

Run::

    python3 -m Tools.ProfilePackage.saip_gui_deep_audit_round3
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_SAIP_PY = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "actions" / "saip.py"
_QUICK_ADD_PY = _REPO_ROOT / "Tools" / "ProfilePackage" / "saip_pe_quick_add.py"


def quick_add_row_ids_match_gap_frozenset() -> list[str]:
    """TUI ``list_pe_quick_add_rows`` ids must match ``_QUICK_ADD_MENU_KEYS``."""
    from Tools.ProfilePackage.saip_pe_gui_gap import _QUICK_ADD_MENU_KEYS
    from Tools.ProfilePackage.saip_pe_quick_add import list_pe_quick_add_rows

    rows = {r[0] for r in list_pe_quick_add_rows()}
    expected = set(_QUICK_ADD_MENU_KEYS)
    if rows == expected:
        return []
    return ["symmetric_diff:" + repr(sorted(rows ^ expected))]


def quick_add_rows_avoid_gui_catchall_tier() -> list[str]:
    """Every quick-add target must land in a typed dispatch bucket (not untyped)."""
    from Tools.ProfilePackage.saip_pe_gui_gap import classify_pe_gui_tier
    from Tools.ProfilePackage.saip_pe_quick_add import list_pe_quick_add_rows

    bad: list[str] = []
    for menu_id, _title, _hint in list_pe_quick_add_rows():
        tier = classify_pe_gui_tier(menu_id)
        if tier == "untyped_card_catchall_wizard_plus_decoded_panel":
            bad.append(menu_id)
    return bad


def _factory_map_keys_from_ast() -> frozenset[str]:
    tree = ast.parse(_QUICK_ADD_PY.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_factory_map":
            for stmt in node.body:
                if not isinstance(stmt, ast.AnnAssign):
                    continue
                if not isinstance(stmt.target, ast.Name):
                    continue
                if stmt.target.id != "mapping":
                    continue
                if not isinstance(stmt.value, ast.Dict):
                    continue
                keys: set[str] = set()
                for key_node in stmt.value.keys:
                    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                        keys.add(key_node.value)
                return frozenset(keys)
    return frozenset()


def quick_add_factory_keys_match_row_ids() -> list[str]:
    """AST ``_factory_map`` keys must match quick-add row ids (pySim-free parse)."""
    from Tools.ProfilePackage.saip_pe_quick_add import list_pe_quick_add_rows

    rows = {r[0] for r in list_pe_quick_add_rows()}
    factory = set(_factory_map_keys_from_ast())
    if rows == factory:
        return []
    return ["factory_vs_rows:" + repr(sorted(rows ^ factory))]


def gui_saip_action_ids_referenced_in_app_js(app_js: str | None = None) -> frozenset[str]:
    """``saip.*`` action ids the workbench calls through ``/api/actions/.../run``."""
    text = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    refs: set[str] = set()
    refs.update(re.findall(r'"/api/actions/(saip\.[a-z0-9_]+)/run"', text))
    for a, b in re.findall(r'\?\s*"(saip\.[a-z0-9_]+)"\s*:\s*"(saip\.[a-z0-9_]+)"', text):
        refs.add(a)
        refs.add(b)
    return frozenset(refs)


def saip_action_ids_declared_in_saip_py(saip_py: str | None = None) -> frozenset[str]:
    text = (saip_py if saip_py is not None else _SAIP_PY.read_text(encoding="utf-8"))
    return frozenset(re.findall(r'id="(saip\.[a-z0-9_]+)"', text))


def gui_referenced_saip_actions_are_registered(app_js: str | None = None) -> list[str]:
    """Every ``app.js`` SAIP action endpoint must exist as an ``ActionSpec`` id."""
    js_refs = gui_saip_action_ids_referenced_in_app_js(app_js)
    py_ids = saip_action_ids_declared_in_saip_py()
    return sorted(a for a in js_refs if a not in py_ids)


def fs_marker_roots_vs_editable_subfields() -> list[str]:
    """``_FS_MARKER_KEYS`` roots are either editable via ``update_file_field`` or fill-only."""
    from yggdrasim_common.gui_server.actions.saip import _EDITABLE_SUB_FIELDS, _FS_MARKER_KEYS

    roots = {entry.split(".", 1)[0] for entry in _EDITABLE_SUB_FIELDS}
    fill_only = frozenset({"fillFileContent"})
    bad: list[str] = []
    for marker in sorted(_FS_MARKER_KEYS):
        if marker in roots or marker in fill_only:
            continue
        bad.append(marker)
    return bad


def main() -> int:
    v1 = quick_add_row_ids_match_gap_frozenset()
    v2 = quick_add_rows_avoid_gui_catchall_tier()
    v3 = quick_add_factory_keys_match_row_ids()
    v4 = gui_referenced_saip_actions_are_registered()
    v5 = fs_marker_roots_vs_editable_subfields()
    lines = [
        "quick_add rows vs _QUICK_ADD_MENU_KEYS (expect []): " + repr(v1),
        "quick_add tiers not catchall (expect []): " + repr(v2),
        "AST _factory_map vs quick-add rows (expect []): " + repr(v3),
        "app.js saip actions ⊆ saip.py ids (expect []): " + repr(v4),
        "_FS_MARKER_KEYS vs _EDITABLE_SUB_FIELDS roots (expect []): " + repr(v5),
    ]
    sys.stdout.write("\n".join(lines) + "\n")
    if any(len(x) > 0 for x in (v1, v2, v3, v4, v5)):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
