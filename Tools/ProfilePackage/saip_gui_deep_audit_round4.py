# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Fourth-pass SAIP server action wiring (registry, ids, enums, coverage).

Complements earlier GUI audits with ``yggdrasim_common/gui_server/actions/saip.py``
internals: every ``ActionSpec`` is registered, action ids stay unique, security-
domain rows get friendly labels for ``list_applications``, enum pickers stay
consistent, and declared ``saip.*`` actions are referenced from the workbench,
tests, or an explicit operator-tooling allow-list.

Run::

    python3 -m Tools.ProfilePackage.saip_gui_deep_audit_round4
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SAIP_PY = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "actions" / "saip.py"
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_TESTS_DIR = _REPO_ROOT / "tests"

# Declared for CLI / lint / decode helpers — the Command Center does not call them.
_SAIP_ACTIONS_NO_BROWSER_ENTRYPOINT: frozenset[str] = frozenset(
    {
        "saip.decode_to_json",
        "saip.lint_path",
    },
)


def _saip_py_text(saip_py: str | None = None) -> str:
    return saip_py if saip_py is not None else _SAIP_PY.read_text(encoding="utf-8")


def action_spec_symbols_match_registry_register(saip_py: str | None = None) -> list[str]:
    """Every ``ActionSpec`` assignment is passed to ``get_registry().register``."""
    text = _saip_py_text(saip_py)
    specs = set(re.findall(r"^([A-Z][A-Z0-9_]*_SPEC)\s*=\s*ActionSpec\(", text, re.MULTILINE))
    reg = set(re.findall(r"get_registry\(\)\.register\(([A-Z][A-Z0-9_]*_SPEC)\)", text))
    if specs == reg:
        return []
    return ["spec_vs_register:" + repr(sorted(specs ^ reg))]


def duplicate_saip_action_ids(saip_py: str | None = None) -> list[str]:
    """No two ``ActionSpec`` blocks may share the same ``id="saip.…"``."""
    text = _saip_py_text(saip_py)
    ids = re.findall(r'id="(saip\.[a-z0-9_]+)"', text)
    counts = Counter(ids)
    return sorted(i for i, n in counts.items() if n > 1)


def security_domain_types_have_application_friendly_labels() -> list[str]:
    """``_SD_PE_TYPES`` rows need human labels for ``list_applications``."""
    from yggdrasim_common.gui_server.actions.saip import _APP_FRIENDLY_TYPES, _SD_PE_TYPES

    missing = sorted(pe for pe in _SD_PE_TYPES if pe not in _APP_FRIENDLY_TYPES)
    return missing


def enum_payload_keys_have_choice_descriptors() -> list[str]:
    """``list_known_enum_payload_keys`` matches ``_COMMON_ENUM_CHOICES`` entries."""
    from Tools.ProfilePackage.saip_decoded_edit import (
        get_enum_choices_for_key,
        list_known_enum_payload_keys,
    )

    keys = list_known_enum_payload_keys()
    if len(keys) != len(set(keys)):
        return ["duplicate_enum_payload_key"]
    bad: list[str] = []
    for key in keys:
        if get_enum_choices_for_key(key) is None:
            bad.append(key)
    return bad


def _test_registry_saip_action_refs() -> frozenset[str]:
    refs: set[str] = set()
    for path in _TESTS_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        refs.update(re.findall(r'get_registry\(\)\.get\("(saip\.[a-z0-9_]+)"', text))
        refs.update(re.findall(r'registry\.get\("(saip\.[a-z0-9_]+)"', text))
    return frozenset(refs)


def declared_saip_actions_reachable_from_workbench_tests_or_tooling(
    app_js: str | None = None,
    saip_py: str | None = None,
) -> list[str]:
    """Declared ``saip.*`` ids must appear in ``app.js``, tests, or tooling allow-list."""
    from Tools.ProfilePackage.saip_gui_deep_audit_round3 import (
        gui_saip_action_ids_referenced_in_app_js,
        saip_action_ids_declared_in_saip_py,
    )

    text_py = _saip_py_text(saip_py)
    declared = set(saip_action_ids_declared_in_saip_py(text_py))
    text_js = (app_js if app_js is not None else _APP_JS.read_text(encoding="utf-8"))
    js_refs = set(gui_saip_action_ids_referenced_in_app_js(text_js))
    test_refs = set(_test_registry_saip_action_refs())
    allowed = declared - js_refs - test_refs - set(_SAIP_ACTIONS_NO_BROWSER_ENTRYPOINT)
    return sorted(allowed)


def main() -> int:
    v1 = action_spec_symbols_match_registry_register()
    v2 = duplicate_saip_action_ids()
    v3 = security_domain_types_have_application_friendly_labels()
    v4 = enum_payload_keys_have_choice_descriptors()
    v5 = declared_saip_actions_reachable_from_workbench_tests_or_tooling()
    lines = [
        "ActionSpec symbols vs register() (expect []): " + repr(v1),
        "duplicate saip action ids (expect []): " + repr(v2),
        "SD types missing friendly labels (expect []): " + repr(v3),
        "enum payload keys missing descriptors (expect []): " + repr(v4),
        "declared saip ids without UI/tests/tooling path (expect []): " + repr(v5),
    ]
    sys.stdout.write("\n".join(lines) + "\n")
    if any(len(x) > 0 for x in (v1, v2, v3, v4, v5)):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
