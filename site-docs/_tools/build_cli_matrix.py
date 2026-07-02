# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Generate the CLI matrix page from pyproject.toml and the registry.

Reads the ``[project.scripts]`` table from ``pyproject.toml`` and the
``CLI_MODULES`` and ``SUBSYSTEMS`` maps in
``yggdrasim_common/registry.py`` so the authored CLI reference page stays
aligned with the actual entry points that ship in a release.

The script writes a Markdown fragment intended to be pasted into
``site-docs/reference/cli-matrix.md`` between markers:

    <!-- cli-matrix:start -->
    ...
    <!-- cli-matrix:end -->

Existing content inside the markers is replaced. Content outside the markers
is preserved verbatim.

Usage:

    python site-docs/_tools/build_cli_matrix.py
    python site-docs/_tools/build_cli_matrix.py --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 fallback.
    import tomli as tomllib  # type: ignore[no-redef]


MATRIX_START = "<!-- cli-matrix:start -->"
MATRIX_END = "<!-- cli-matrix:end -->"

MODULE_TO_COMMAND_PREFIX = "yggdrasim_common.console_scripts:"

# Manual overrides for commands whose console-script symbol does not obviously
# map to a registry CLI_MODULES entry. Keep these minimal; add new rows here
# whenever a release introduces a new command.
MANUAL_COMMAND_MODULE_OVERRIDES: dict[str, str] = {
    "yggdrasim-card-bridge": "Tools.CardBridge",
    "yggdrasim-profile-package": "Tools.ProfilePackage",
    "yggdrasim-suci-tool": "Tools.SuciTool",
    "yggdrasim-hil-bridge": "Tools.HilBridge.main",
    "yggdrasim-hil-supervisor": "Tools.HilBridge.supervisor",
}

# Subsystems that are not in the registry get a local description table so
# the rendered matrix stays useful without forcing registry changes.
LOCAL_SUBSYSTEM_DESCRIPTIONS: dict[str, str] = {
    "Tools.CardBridge": "Loopback PC/SC-to-HTTP APDU bridge for SSH-forwarded remote-card workflows.",
    "Tools.HilBridge.main": "SIMtrace2-backed HIL bridge (direct).",
    "Tools.HilBridge.supervisor": "HIL supervisor that manages the bridge and remsim-client lifecycle.",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_pyproject() -> dict:
    path = repo_root() / "pyproject.toml"
    with path.open("rb") as handle:
        return tomllib.load(handle)


def load_registry():
    sys.path.insert(0, str(repo_root()))
    try:
        from yggdrasim_common import registry  # type: ignore[import-not-found]
    finally:
        sys.path.pop(0)
    return registry


def match_module_for_command(command_name: str, command_target: str, cli_modules: list[str]) -> str:
    if command_name in MANUAL_COMMAND_MODULE_OVERRIDES:
        return MANUAL_COMMAND_MODULE_OVERRIDES[command_name]
    if not command_target.startswith(MODULE_TO_COMMAND_PREFIX):
        return ""
    symbol = command_target[len(MODULE_TO_COMMAND_PREFIX):]
    symbol_squashed = symbol.replace("_", "").replace("-", "").lower()
    for module in cli_modules:
        full_squashed = module.replace(".", "").replace("_", "").lower()
        if full_squashed == symbol_squashed:
            return module
    best_match = ""
    best_score = 0
    for module in cli_modules:
        last_segment = module.split(".")[-1]
        candidate = last_segment.replace("_", "").lower()
        if candidate == symbol_squashed:
            return module
        if candidate in symbol_squashed:
            score = len(candidate)
            if score > best_score:
                best_score = score
                best_match = module
    return best_match


def build_rows(pyproject: dict, registry) -> list[tuple[str, str, str]]:
    scripts = pyproject.get("project", {}).get("scripts", {}) or {}
    rows: list[tuple[str, str, str]] = []
    for script_name in sorted(scripts.keys()):
        target = scripts[script_name]
        module = match_module_for_command(
            command_name=script_name,
            command_target=target,
            cli_modules=registry.CLI_MODULES,
        )
        description = ""
        if len(module) > 0:
            description = registry.SUBSYSTEMS.get(module, "")
            if len(description) == 0:
                description = LOCAL_SUBSYSTEM_DESCRIPTIONS.get(module, "")
        module_form = ""
        if len(module) > 0:
            module_form = f"`python -m {module}`"
        rows.append((f"`{script_name}`", module_form, description))
    return rows


def render_markdown(rows: list[tuple[str, str, str]]) -> str:
    lines = [MATRIX_START, "", "| Installed command | Module form | Description |", "| --- | --- | --- |"]
    for command, module_form, description in rows:
        module_cell = module_form if len(module_form) > 0 else "_(manual module)_"
        description_cell = description if len(description) > 0 else ""
        lines.append(f"| {command} | {module_cell} | {description_cell} |")
    lines.append("")
    lines.append(MATRIX_END)
    return "\n".join(lines) + "\n"


def inject(existing_text: str, rendered: str) -> str:
    pattern = re.compile(
        re.escape(MATRIX_START) + r".*?" + re.escape(MATRIX_END),
        re.DOTALL,
    )
    if pattern.search(existing_text) is not None:
        return pattern.sub(rendered.rstrip("\n"), existing_text)
    return existing_text.rstrip("\n") + "\n\n" + rendered


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the CLI matrix reference page section.")
    parser.add_argument(
        "--target",
        default="site-docs/reference/cli-matrix.md",
        help="Target Markdown page (default: site-docs/reference/cli-matrix.md)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the rendered section to stdout without modifying files.",
    )
    arguments = parser.parse_args()

    pyproject = load_pyproject()
    registry = load_registry()
    rows = build_rows(pyproject=pyproject, registry=registry)
    rendered = render_markdown(rows=rows)

    if arguments.dry_run is True:
        print(rendered)
        return 0

    target_path = (repo_root() / arguments.target).resolve()
    if target_path.is_file() is False:
        print(f"error: {target_path} does not exist", file=sys.stderr)
        return 2

    existing = target_path.read_text(encoding="utf-8")
    new_text = inject(existing_text=existing, rendered=rendered)
    if new_text != existing:
        target_path.write_text(new_text, encoding="utf-8")
        print(f"Updated {target_path.relative_to(repo_root())}")
    else:
        print(f"No changes needed in {target_path.relative_to(repo_root())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
