# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Contracts for the generated standalone MCP distribution.

The tree is generated rather than committed, so the guard that matters is
that generation still succeeds and still rewrites every import it claims
to. A missed rewrite would ship a wheel that imports ``Tools`` at runtime
and fails on a host that has no YggdraSIM.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
import tempfile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER = REPO_ROOT / "scripts" / "release" / "build_mcp_standalone.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("yggdrasim_mcp_builder", BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["yggdrasim_mcp_builder"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    builder = _load_builder()
    target = tmp_path_factory.mktemp("standalone")
    builder.generate(target)
    return target / builder.PACKAGE


def test_generation_produces_every_declared_file(generated: Path) -> None:
    for relative in (
        "__init__.py",
        "server.py",
        "_vendor/__init__.py",
        "_vendor/asn1tlv.py",
        "_vendor/sgp32_decode.py",
        "_vendor/euicc_info2.py",
        "_vendor/session_diff.py",
        # The card transport chain, so the standalone can drive a card.
        "_vendor/secure_files.py",
        "_vendor/runtime_paths.py",
        "_vendor/apdu_recorder.py",
        "_vendor/card_backend.py",
        "_vendor/card_bridge_auth.py",
        "_vendor/remote_lab_security.py",
        "data/aid.txt",
    ):
        assert (generated / relative).is_file(), relative


def test_generated_sources_parse(generated: Path) -> None:
    for path in generated.rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_no_generated_module_imports_the_full_tree(generated: Path) -> None:
    """A missed rewrite ships a wheel that breaks on a host without YggdraSIM.

    Only the tools that deliberately degrade may still name these roots,
    and they do so inside a function guarded by ``except ImportError``.
    """
    full_tree_roots = ("Tools.", "SCP03.", "SCP80.", "SIMCARD.", "yggdrasim_common.")
    offenders: list[str] = []
    for path in generated.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            module = ""
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                module = node.module
            elif isinstance(node, ast.Import):
                module = node.names[0].name
            if not module.startswith(full_tree_roots):
                continue
            # Module level is fatal; inside a function it is a degrade path.
            if any(node is child for child in tree.body):
                offenders.append(f"{path.name}: {module}")
    assert offenders == [], offenders


def test_repo_root_no_longer_anchors_package_data(generated: Path) -> None:
    """A standalone install has package data but no repository."""

    server = (generated / "server.py").read_text(encoding="utf-8")
    assert "REPO_ROOT = Path.cwd()" in server
    assert '_PACKAGE_DATA = Path(__file__).resolve().parent / "data"' in server
    assert 'aid_path = _PACKAGE_DATA / "aid.txt"' in server
    assert 'REPO_ROOT / "SCP03"' not in server


def test_vendored_sources_match_the_repo_byte_for_byte(generated: Path) -> None:
    """Generated, never hand-edited, so it cannot drift from the original."""

    builder = _load_builder()
    for source, relative in builder.VENDORED.items():
        original = (REPO_ROOT / source).read_text(encoding="utf-8")
        vendored = (generated / relative).read_text(encoding="utf-8")
        if source.endswith("sgp32_decode.py"):
            for old, new in builder.VENDOR_REWRITES:
                original = original.replace(old, new)
        for old, new in builder.PER_MODULE_REWRITES.get(source, ()):
            assert old in original, f"{source}: rewrite no longer matches: {old[:50]!r}"
            original = original.replace(old, new)
        assert vendored == original, source


def test_declared_dependencies_carry_no_git_requirement() -> None:
    """The point of the split is a wheel a plain pip can resolve."""

    builder = _load_builder()
    with tempfile.TemporaryDirectory() as scratch:
        target = Path(scratch)
        builder.generate(target)
        pyproject = (target / "pyproject.toml").read_text(encoding="utf-8")
    assert "git+" not in pyproject
    for required in ("mcp>=1.2,<2", "pyyaml", "asn1crypto"):
        assert required in pyproject
    # pyscard needs a compiler and PCSC headers, so it stays optional.
    assert 'card = ["pyscard"]' in pyproject


def test_standalone_package_cannot_collide_with_yggdrasim() -> None:
    """Both wheels must be installable side by side."""

    builder = _load_builder()
    assert builder.PACKAGE == "yggdrasim_mcp"
    with tempfile.TemporaryDirectory() as scratch:
        target = Path(scratch)
        builder.generate(target)
        tops = {p.name for p in target.iterdir() if p.is_dir()}
    assert tops == {"yggdrasim_mcp"}, tops


def test_the_card_transport_chain_is_fully_vendored(generated: Path) -> None:
    """The standalone must reach a card without the rest of the tree.

    Every module the transport needs is standard-library only apart from
    its siblings, which is what makes this possible: a missed one would
    surface as a runtime ImportError on a host that has no YggdraSIM.
    """
    transport = generated / "_vendor" / "card_backend.py"
    tree = ast.parse(transport.read_text(encoding="utf-8"), filename=str(transport))

    top_level = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            top_level.add(node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            top_level.update(alias.name.split(".")[0] for alias in node.names)
    assert not top_level & {"yggdrasim_common", "SIMCARD", "SCP03", "Tools"}, top_level

    for sibling in ("secure_files", "runtime_paths", "apdu_recorder"):
        assert (generated / "_vendor" / f"{sibling}.py").is_file(), sibling


def test_the_simulator_backend_degrades_with_a_reason(generated: Path) -> None:
    """SIMCARD is a whole subsystem and is deliberately not vendored."""

    source = (generated / "_vendor" / "card_backend.py").read_text(encoding="utf-8")
    assert "from SIMCARD.connection import SimulatedCardConnection" in source
    assert "except ImportError as sim_error:" in source
    assert "needs the full YggdraSIM" in source


def test_the_server_resolves_card_backend_locally(generated: Path) -> None:
    server = (generated / "server.py").read_text(encoding="utf-8")
    assert "from yggdrasim_mcp._vendor import card_backend" in server
    assert "from yggdrasim_common import card_backend" not in server
    assert "from yggdrasim_common.card_backend import" not in server
