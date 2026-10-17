# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The generated reference pages match their generators.

``site-docs/reference/cli-matrix.md`` and ``site-docs/reference/env-flags.md``
carry a block between markers that is written by a script in
``site-docs/_tools/``. The matrix block had been hand-edited and had drifted
from the tree it describes, which is what these tests catch: a new console
script or env flag fails here until the matching generator has been re-run.
"""

from __future__ import annotations

import importlib.util
import re
import tomllib
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "site-docs" / "_tools"


def _load(module_name: str) -> ModuleType:
    """Import a generator by path; ``site-docs/_tools`` is not a package."""
    path = TOOLS / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _committed_block(page: Path, start: str, end: str) -> str:
    text = page.read_text(encoding="utf-8")
    match = re.search(re.escape(start) + r".*?" + re.escape(end), text, re.DOTALL)
    assert match is not None, f"{page.name} no longer carries its generator markers"
    return match.group(0).strip()


def test_cli_matrix_block_matches_the_generator() -> None:
    generator = _load("build_cli_matrix")
    rendered = generator.render_markdown(
        rows=generator.build_rows(
            pyproject=generator.load_pyproject(),
            registry=generator.load_registry(),
        )
    ).strip()
    committed = _committed_block(
        ROOT / "site-docs" / "reference" / "cli-matrix.md",
        generator.MATRIX_START,
        generator.MATRIX_END,
    )
    assert committed == rendered, (
        "site-docs/reference/cli-matrix.md is stale; run "
        "python site-docs/_tools/build_cli_matrix.py"
    )


def test_env_flags_block_matches_the_generator() -> None:
    generator = _load("build_env_flags")
    rendered = generator.render_markdown(env_flags=generator.load_env_flags()).strip()
    committed = _committed_block(
        ROOT / "site-docs" / "reference" / "env-flags.md",
        generator.TABLE_START,
        generator.TABLE_END,
    )
    assert committed == rendered, (
        "site-docs/reference/env-flags.md is stale; run "
        "python site-docs/_tools/build_env_flags.py"
    )


def _installed_commands() -> set[str]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle).get("project", {})
    return set(project.get("scripts", {})) | set(project.get("gui-scripts", {}))


def test_every_installed_command_reaches_the_matrix() -> None:
    """A command with no row is a command an operator cannot look up."""
    text = (ROOT / "site-docs" / "reference" / "cli-matrix.md").read_text(encoding="utf-8")
    missing = sorted(name for name in _installed_commands() if f"`{name}`" not in text)
    assert missing == [], f"commands missing from cli-matrix.md: {missing}"


def test_every_installed_command_reaches_the_command_suite() -> None:
    """Section 1.8 is hand-written, so it drifts the way the matrix did."""
    text = (ROOT / "site-docs" / "reference" / "command-suite.md").read_text(encoding="utf-8")
    start = text.index("### 1.8 Console-script entry points")
    section = text[start : text.index("## 2.", start)]
    missing = sorted(name for name in _installed_commands() if f"`{name}`" not in section)
    assert missing == [], f"commands missing from command-suite.md section 1.8: {missing}"
