# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_REPOSITORY = "https://github.com/1oT/YggdraSIM"
STALE_REPOSITORY_IDENTIFIERS = (
    "github.com/hampus/YggdraSIM",
    "github.com/hampushellsberg-dev/YggdraSIM",
    "hampushellsberg-dev.github.io/YggdraSIM",
)


def _text_files_under(root: Path) -> list[Path]:
    suffixes = {".md", ".toml", ".yaml", ".yml"}
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in suffixes
    )


def test_project_metadata_uses_canonical_repository_urls() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    urls = project["urls"]
    assert urls["Homepage"] == CANONICAL_REPOSITORY
    assert urls["Repository"] == CANONICAL_REPOSITORY
    assert urls["Issues"] == f"{CANONICAL_REPOSITORY}/issues"
    assert urls["Documentation"].startswith(CANONICAL_REPOSITORY)
    assert urls["Changelog"].startswith(CANONICAL_REPOSITORY)


def test_owned_documentation_has_no_stale_repository_identity() -> None:
    paths = [
        ROOT / "SECURITY.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "mkdocs.yml",
        ROOT / "mkdocs.oneot.yml",
    ]
    paths.extend(_text_files_under(ROOT / ".github"))
    paths.extend(_text_files_under(ROOT / "guides"))
    paths.extend(_text_files_under(ROOT / "site-docs"))
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for stale_identifier in STALE_REPOSITORY_IDENTIFIERS:
            assert stale_identifier not in text, (
                f"{path.relative_to(ROOT)} contains stale repository identity "
                f"{stale_identifier!r}"
            )


def test_security_and_contributor_mirrors_match_canonical_sources() -> None:
    for name in ("SECURITY.md", "CONTRIBUTING.md"):
        canonical = (ROOT / name).read_text(encoding="utf-8").rstrip()
        mirror = (ROOT / "site-docs" / "sources" / name).read_text(
            encoding="utf-8"
        ).rstrip()
        assert mirror == canonical

    github_policy = (ROOT / ".github" / "SECURITY.md").read_text(
        encoding="utf-8"
    )
    assert "[`../SECURITY.md`](../SECURITY.md)" in github_policy
    assert f"{CANONICAL_REPOSITORY}/security/advisories/new" in github_policy


def test_release_docs_describe_frozen_gui_companions() -> None:
    packaging = (ROOT / "site-docs" / "build-and-packaging.md").read_text(
        encoding="utf-8"
    )
    subsystem = (
        ROOT / "site-docs" / "subsystems" / "gui-command-center.md"
    ).read_text(encoding="utf-8")
    assert "CLI executable and a desktop-GUI companion" in packaging
    assert "paired CLI and desktop-GUI executables" in subsystem
    assert "frozen build cannot launch the Universal GUI" not in packaging
