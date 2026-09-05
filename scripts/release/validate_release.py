#!/usr/bin/env python3
"""Validate tag/version identity and frozen release archives."""

from __future__ import annotations

import argparse
import ast
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
ALLOWED_QT_PLUGIN_PREFIXES = frozenset(
    {
        ("pyqt5", "qt5", "plugins"),
        ("pyqt6", "qt6", "plugins"),
    }
)
ARCHIVE_LISTING_HEADER = (
    "position, length, uncompressed_length, is_compressed, typecode, name"
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
    """Return prohibited paths in a PyInstaller CArchive listing."""
    lines = listing.splitlines()
    try:
        header_index = next(
            index
            for index, line in enumerate(lines)
            if line.strip() == ARCHIVE_LISTING_HEADER
        )
    except StopIteration as error:
        raise ReleaseValidationError(
            "unsupported PyInstaller archive listing format"
        ) from error

    member_paths: list[str] = []
    for line_number, line in enumerate(lines[header_index + 1 :], header_index + 2):
        if not line.strip():
            continue
        try:
            row = ast.literal_eval(line.strip())
        except (SyntaxError, ValueError) as error:
            raise ReleaseValidationError(
                f"malformed PyInstaller archive listing row at line {line_number}"
            ) from error
        if (
            not isinstance(row, tuple)
            or len(row) != 6
            or not isinstance(row[4], str)
            or not isinstance(row[5], str)
        ):
            raise ReleaseValidationError(
                f"malformed PyInstaller archive listing row at line {line_number}"
            )
        member_paths.append(row[5])

    if not member_paths:
        raise ReleaseValidationError(
            "PyInstaller archive listing contains no member records"
        )

    prohibited: set[str] = set()
    for member_path in member_paths:
        normalized = member_path.replace("\\", "/")
        if (
            not normalized
            or "\x00" in normalized
            or normalized.startswith("/")
            or re.match(r"^[a-zA-Z]:", normalized)
        ):
            raise ReleaseValidationError(
                f"unsafe path in PyInstaller archive listing: {member_path!r}"
            )
        components = normalized.split("/")
        if any(component in {"", ".", ".."} for component in components):
            raise ReleaseValidationError(
                f"unsafe path in PyInstaller archive listing: {member_path!r}"
            )

        lowered = tuple(component.casefold() for component in components)
        for index, component in enumerate(lowered):
            if component not in FORBIDDEN_ARCHIVE_COMPONENTS:
                continue
            if (
                component == "plugins"
                and lowered[: index + 1] in ALLOWED_QT_PLUGIN_PREFIXES
            ):
                continue
            prohibited.add(component)

    return [
        component
        for component in FORBIDDEN_ARCHIVE_COMPONENTS
        if component.casefold() in prohibited
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


def run_sanitizer(repo_root: Path) -> int:
    """Gate a release commit on a clean identifier scan, when available.

    The scan rules name the allocations this tree is scrubbed of, so they
    live in an untracked plugin rather than here. A checkout without that
    plugin reports the gap and passes: a public clone cannot run the check
    and must not be blocked by its absence.
    """
    # Run as a script, sys.path[0] is this directory, so the plugin package
    # is only importable once the repo root is on the path.
    root = str(Path(__file__).resolve().parents[2])
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from plugins.release_sanitizer.scanner import scan_repository
    except ImportError:
        print("sanitizer: not installed in this checkout, skipping")
        return 0

    report = scan_repository(repo_root)
    leaks = report["identifier_leaks"]
    print(f"sanitizer: scanned {report['scanned']} tracked files")
    for finding in leaks:
        print(
            f"  LEAK {finding['source']}:{finding['line']}: "
            f"{finding['rule']} -> {finding['match']}",
            file=sys.stderr,
        )
    phrases = report["banned_phrases"]
    if phrases:
        print(f"sanitizer: {len(phrases)} prose findings (advisory)")
    if leaks:
        print(
            f"release validation failed: {len(leaks)} identifier leaks",
            file=sys.stderr,
        )
        return 2
    return 0


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

    sanitize_parser = subparsers.add_parser(
        "sanitize",
        help="scan tracked files for real-world identifier leaks",
    )
    sanitize_parser.add_argument("--repo-root", type=Path, default=Path.cwd())

    args = parser.parse_args()
    if args.command == "sanitize":
        return run_sanitizer(args.repo_root)
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
