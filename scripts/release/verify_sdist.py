#!/usr/bin/env python3
"""Verify source-distribution package resources against the release allowlist."""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath

if __package__:
    from .source_boundary import (
        SourceBoundaryError,
        assert_artifact_python_path_is_reviewed,
        assert_release_artifact_path_is_reviewed,
        load_reviewed_packages,
        load_reviewed_release_files,
        tracked_reviewed_python_sources,
    )
else:
    from source_boundary import (  # type: ignore[no-redef]
        SourceBoundaryError,
        assert_artifact_python_path_is_reviewed,
        assert_release_artifact_path_is_reviewed,
        load_reviewed_packages,
        load_reviewed_release_files,
        tracked_reviewed_python_sources,
    )


PACKAGE_ROOTS = {
    "main",
    "SCP03",
    "SCP80",
    "SCP11",
    "SIMCARD",
    "Tools",
    "yggdrasim_common",
}
PROHIBITED_PARTS = {
    ".git",
    "plugins",
    "pysim",
    "reports",
    "state",
    "workspace",
    "yggdrasim-data",
}


def _manifest_resources(path: Path) -> set[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        str(entry["path"])
        for entry in payload["entries"]
        if isinstance(entry, dict) and entry.get("path")
    }


def verify_sdist(archive_path: Path, manifest_path: Path) -> None:
    required = _manifest_resources(manifest_path)
    reviewed_packages = load_reviewed_packages()
    reviewed_release_files = load_reviewed_release_files()
    repo_root = Path(__file__).resolve().parents[2]
    expected_python = set(
        tracked_reviewed_python_sources(repo_root, reviewed_packages)
    )
    present_python: set[str] = set()
    present: set[str] = set()
    with tarfile.open(archive_path, mode="r:*") as archive:
        members = archive.getmembers()
        roots = {member.name.split("/", 1)[0] for member in members if member.name}
        if len(roots) != 1:
            raise RuntimeError("source distribution must contain one top-level directory")
        root = next(iter(roots))
        for member in members:
            prefix = root + "/"
            if member.name == root:
                continue
            if member.name.startswith(prefix) is False:
                raise RuntimeError(f"source-distribution path escapes root: {member.name}")
            relative_text = member.name[len(prefix) :]
            relative = PurePosixPath(relative_text)
            if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
                raise RuntimeError(
                    f"unsafe path in source distribution: {relative_text}"
                )
            lowered_parts = {part.casefold() for part in relative.parts}
            if lowered_parts & PROHIBITED_PARTS:
                raise RuntimeError(f"prohibited path in source distribution: {relative_text}")
            if member.issym() or member.islnk():
                raise RuntimeError(f"link in source distribution: {relative_text}")
            if relative_text in required:
                present.add(relative_text)
            if member.isfile() and relative.parts[:2] == ("scripts", "release"):
                assert_release_artifact_path_is_reviewed(
                    relative,
                    reviewed_release_files,
                )
            if (
                member.isfile()
                and relative.parts
                and relative.parts[0] in PACKAGE_ROOTS
                and relative.suffix == ".py"
            ):
                assert_artifact_python_path_is_reviewed(
                    relative,
                    reviewed_packages,
                )
                if relative.as_posix() not in expected_python:
                    raise SourceBoundaryError(
                        f"untracked Python source in source distribution: {relative}"
                    )
                present_python.add(relative.as_posix())
            if (
                member.isfile()
                and relative.parts
                and relative.parts[0] in PACKAGE_ROOTS
                and relative.suffix != ".py"
                and relative_text not in required
            ):
                raise RuntimeError(
                    "unexpected package resource outside release allowlist: "
                    f"{relative_text}"
                )
    missing = sorted(required - present)
    if missing:
        raise RuntimeError(
            "source distribution is missing approved resources:\n  "
            + "\n  ".join(missing)
        )
    missing_python = sorted(expected_python - present_python)
    if missing_python:
        raise RuntimeError(
            "source distribution is missing reviewed Python sources:\n  "
            + "\n  ".join(missing_python)
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("scripts/release/bundle-data.json"),
    )
    args = parser.parse_args()
    try:
        verify_sdist(args.archive, args.manifest)
    except (
        OSError,
        RuntimeError,
        SourceBoundaryError,
        tarfile.TarError,
        json.JSONDecodeError,
    ) as error:
        print(f"source-distribution verification failed: {error}", file=sys.stderr)
        return 2
    print(f"verified source-distribution resources: {args.archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
