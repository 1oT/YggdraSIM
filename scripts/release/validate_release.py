#!/usr/bin/env python3
"""Validate tag/version identity and frozen release archives."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path


FORBIDDEN_ARCHIVE_COMPONENTS = (
    ".git",
    "plugins",
    "reports",
    "state",
    "workspace",
    "yggdrasim-data",
)
VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){2}(?:[a-zA-Z0-9.-]+)?$")


class ReleaseValidationError(RuntimeError):
    """Raised when release metadata or an artifact violates policy."""


def project_version(repo_root: Path) -> str:
    path = Path(repo_root) / "pyproject.toml"
    with path.open("rb") as handle:
        payload = tomllib.load(handle)
    version = str(payload.get("project", {}).get("version") or "").strip()
    if not VERSION_PATTERN.fullmatch(version):
        raise ReleaseValidationError(f"invalid project version in {path}: {version!r}")
    return version


def validate_tag(repo_root: Path, tag: str) -> str:
    version = project_version(repo_root)
    expected = f"v{version}"
    if str(tag).strip() != expected:
        raise ReleaseValidationError(
            f"release tag {tag!r} does not match project version; expected {expected!r}"
        )
    return version


def _archive_listing(artifact: Path) -> str:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller.utils.cliutils.archive_viewer",
            "-l",
            str(artifact),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise ReleaseValidationError(
            f"unable to inspect {artifact} with the active Python runtime: {detail}"
        )
    return completed.stdout


def _forbidden_listing_components(listing: str) -> list[str]:
    """Return prohibited directory components in a PyInstaller listing."""
    normalized = listing.replace("\\", "/").casefold()
    return [
        component
        for component in FORBIDDEN_ARCHIVE_COMPONENTS
        if re.search(
            rf"(?<![a-z0-9_-]){re.escape(component.casefold())}/",
            normalized,
        )
    ]


def validate_frozen_artifact(artifact: Path) -> None:
    path = Path(artifact)
    if not path.is_file() or path.is_symlink():
        raise ReleaseValidationError(f"artifact is not a regular non-symlink file: {path}")
    if path.stat().st_size <= 0:
        raise ReleaseValidationError(f"artifact is empty: {path}")
    listing = _archive_listing(path)
    violations = _forbidden_listing_components(listing)
    if violations:
        raise ReleaseValidationError(
            f"forbidden paths in {path.name}: {', '.join(violations)}"
        )
    canaries = [
        value.encode("utf-8")
        for value in os.environ.get("YGGDRASIM_RELEASE_CANARIES", "").split(",")
        if value
    ]
    if canaries:
        raw = path.read_bytes()
        if any(canary in raw for canary in canaries):
            raise ReleaseValidationError(f"release canary found in {path.name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    tag_parser = subparsers.add_parser("tag", help="validate v<project-version>")
    tag_parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    tag_parser.add_argument("--tag", required=True)

    artifact_parser = subparsers.add_parser(
        "artifact",
        help="inspect PyInstaller archives for forbidden data paths",
    )
    artifact_parser.add_argument("paths", type=Path, nargs="+")

    args = parser.parse_args()
    try:
        if args.command == "tag":
            version = validate_tag(args.repo_root, args.tag)
            print(f"release tag matches project version {version}")
        else:
            for artifact in args.paths:
                validate_frozen_artifact(artifact)
                print(f"validated frozen artifact: {artifact}")
    except ReleaseValidationError as error:
        print(f"release validation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
