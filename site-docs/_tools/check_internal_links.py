# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Static internal-link checker for site-docs.

Scans every Markdown file under ``site-docs/`` and verifies that all
relative inline links resolve to an existing file. Ignores external URLs,
fragment-only links, and anchors. Reports broken links grouped by source
file. Exits non-zero when any broken link is found.

Usage:

    python site-docs/_tools/check_internal_links.py
    python site-docs/_tools/check_internal_links.py --root site-docs
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


LINK_PATTERN = re.compile(r"(?<!\!)\[[^\]]+\]\(([^)]+)\)")
IMAGE_PATTERN = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")

EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "tel:", "ftp://", "ftps://")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def iter_markdown_files(root: Path):
    for path in sorted(root.rglob("*.md")):
        if any(part.startswith(".") for part in path.parts):
            continue
        yield path


def split_target(target: str) -> tuple[str, str]:
    fragment = ""
    if "#" in target:
        path_part, _, fragment = target.partition("#")
    else:
        path_part = target
    return path_part, fragment


def is_external(target: str) -> bool:
    lowered = target.strip().lower()
    for scheme in EXTERNAL_SCHEMES:
        if lowered.startswith(scheme):
            return True
    return False


def resolve_target(source: Path, path_part: str, docs_root: Path) -> Path | None:
    if len(path_part) == 0:
        return None
    if path_part.startswith("/"):
        candidate = docs_root / path_part.lstrip("/")
    else:
        candidate = (source.parent / path_part).resolve()
    return candidate


def candidate_paths(candidate: Path) -> list[Path]:
    paths = [candidate]
    if candidate.suffix == "":
        paths.append(candidate.with_suffix(".md"))
        paths.append(candidate / "index.md")
    return paths


def check_file(source: Path, docs_root: Path) -> list[str]:
    errors: list[str] = []
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"read error: {exc}"]

    patterns = (LINK_PATTERN, IMAGE_PATTERN)
    for pattern in patterns:
        for match in pattern.finditer(text):
            target = match.group(1).strip()
            if len(target) == 0:
                continue
            if is_external(target):
                continue
            if target.startswith("#"):
                continue
            if target.startswith("<!--"):
                continue
            path_part, _ = split_target(target)
            if len(path_part) == 0:
                continue
            candidate = resolve_target(source=source, path_part=path_part, docs_root=docs_root)
            if candidate is None:
                continue
            if any(path.exists() for path in candidate_paths(candidate)):
                continue
            errors.append(target)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Check internal links in MkDocs site-docs.")
    parser.add_argument("--root", default="site-docs", help="docs root to scan (default: site-docs)")
    arguments = parser.parse_args()

    docs_root = (repo_root() / arguments.root).resolve()
    if docs_root.is_dir() is False:
        print(f"error: {docs_root} is not a directory", file=sys.stderr)
        return 2

    total_errors = 0
    for path in iter_markdown_files(docs_root):
        relative = path.relative_to(repo_root())
        errors = check_file(source=path, docs_root=docs_root)
        if len(errors) == 0:
            continue
        print(f"{relative}:")
        for broken in errors:
            print(f"  -> {broken}")
        total_errors += len(errors)

    if total_errors == 0:
        print("No broken internal links found.")
        return 0
    print(f"{total_errors} broken internal link(s) found.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
