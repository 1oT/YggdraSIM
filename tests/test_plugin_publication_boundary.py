# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for keeping local plugin code out of public artifacts."""

from __future__ import annotations

import importlib.util
import re
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent


def _lines(relative_path: str) -> set[str]:
    """Return non-empty, non-comment configuration lines."""
    text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and line.lstrip().startswith("#") is False
    }


def _load_doc_mirror_module() -> ModuleType:
    script_path = REPO_ROOT / "site-docs/_tools/mirror_source_docs.py"
    spec = importlib.util.spec_from_file_location(
        "yggdrasim_mirror_source_docs_test",
        script_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load documentation mirror script for testing.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FrozenBundleBoundaryTests(unittest.TestCase):
    def test_pyinstaller_spec_does_not_collect_runtime_plugins(self) -> None:
        spec_text = (REPO_ROOT / "yggdrasim_main.spec").read_text(encoding="utf-8")

        self.assertIsNone(
            re.search(r"['\"]plugins['\"]", spec_text),
            msg="public frozen bundles must not collect the repository-local plugins tree",
        )


class SourcePackagingBoundaryTests(unittest.TestCase):
    def test_source_distribution_prunes_plugin_trees(self) -> None:
        manifest_lines = _lines("MANIFEST.in")

        self.assertIn("prune plugins", manifest_lines)
        self.assertIn("prune tests", manifest_lines)
        self.assertIn("prune tests/plugins", manifest_lines)
        self.assertIn("prune Tools/*MCP*", manifest_lines)
        self.assertFalse(
            any(line.startswith("recursive-include scripts/release") for line in manifest_lines)
        )

    def test_wheel_package_discovery_cannot_select_plugins(self) -> None:
        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            pyproject = tomllib.load(handle)

        include_patterns = pyproject["tool"]["setuptools"]["packages"]["find"]["include"]
        self.assertTrue(include_patterns)
        self.assertNotIn("Tools.OperatorLocalTool", include_patterns)
        self.assertFalse(any("*" in pattern for pattern in include_patterns))
        self.assertFalse(
            any(
                pattern.partition(".")[0].rstrip("*").lower() == "plugins"
                for pattern in include_patterns
            ),
            msg="setuptools package discovery must not include local plugin packages",
        )

    def test_docker_build_context_excludes_plugin_trees(self) -> None:
        dockerignore_lines = _lines(".dockerignore")

        self.assertIn(".?*", dockerignore_lines)
        self.assertNotIn(".*", dockerignore_lines)
        self.assertIn("plugins/", dockerignore_lines)
        self.assertIn("tests/plugins/", dockerignore_lines)
        self.assertIn("Tools/*MCP*/", dockerignore_lines)

    def test_final_docker_image_does_not_copy_the_source_checkout(self) -> None:
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        runtime = dockerfile.partition("FROM python:3.11-slim AS runtime")[2]

        self.assertTrue(runtime)
        self.assertIn("COPY --from=build /opt/venv /opt/venv", runtime)
        self.assertNotIn(
            "COPY --from=build /opt/YggdraSIM /opt/YggdraSIM",
            runtime,
        )


class WorkingTreeBoundaryTests(unittest.TestCase):
    def test_git_ignores_implementations_but_keeps_public_contract(self) -> None:
        gitignore_lines = _lines(".gitignore")
        plugin_gitignore_lines = _lines("plugins/.gitignore")

        self.assertIn("plugins/*", gitignore_lines)
        self.assertIn("!plugins/.gitignore", gitignore_lines)
        self.assertIn("!plugins/README.md", gitignore_lines)
        self.assertEqual({"*", "!.gitignore", "!README.md"}, plugin_gitignore_lines)


class DocumentationBoundaryTests(unittest.TestCase):
    def test_doc_mirror_allows_only_the_public_plugin_readme(self) -> None:
        mirror = _load_doc_mirror_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public_readme = root / "plugins/README.md"
            private_readme = root / "plugins/private_plugin/README.md"
            private_architecture = root / "plugins/private_plugin/docs/architecture.md"
            guide = root / "guides/example.md"
            for path in (
                public_readme,
                private_readme,
                private_architecture,
                guide,
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# Test\n", encoding="utf-8")
            mirror.repo_root = lambda: root

            mirrored = set(mirror.iter_markdown_sources())

        self.assertIn(Path("plugins/README.md"), mirrored)
        self.assertIn(Path("guides/example.md"), mirrored)
        self.assertNotIn(Path("plugins/private_plugin/README.md"), mirrored)
        self.assertNotIn(
            Path("plugins/private_plugin/docs/architecture.md"),
            mirrored,
        )


if __name__ == "__main__":
    unittest.main()
