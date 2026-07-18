#!/usr/bin/env python3
"""Verify that a wheel contains every approved immutable runtime resource."""

from __future__ import annotations

import argparse
import json
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

if __package__:
    from .source_boundary import (
        SourceBoundaryError,
        assert_artifact_python_path_is_reviewed,
        load_reviewed_packages,
        tracked_reviewed_python_sources,
    )
else:
    from source_boundary import (  # type: ignore[no-redef]
        SourceBoundaryError,
        assert_artifact_python_path_is_reviewed,
        load_reviewed_packages,
        tracked_reviewed_python_sources,
    )


PROHIBITED_PARTS = {
    ".git",
    "plugins",
    "pysim",
    "reports",
    "state",
    "workspace",
    "yggdrasim-data",
}
PROHIBITED_SUFFIXES = {
    ".crt",
    ".der",
    ".jks",
    ".key",
    ".p12",
    ".p8",
    ".pcap",
    ".pcapng",
    ".pem",
    ".pfx",
    ".sqlite3",
}


def _manifest_resources(path: Path) -> set[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        str(entry["path"])
        for entry in payload["entries"]
        if isinstance(entry, dict) and entry.get("path")
    }


def verify_wheel(wheel: Path, manifest: Path) -> None:
    required = _manifest_resources(manifest)
    reviewed_packages = load_reviewed_packages()
    repo_root = Path(__file__).resolve().parents[2]
    expected_python = set(
        tracked_reviewed_python_sources(repo_root, reviewed_packages)
    )
    present_python: set[str] = set()
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        for info in archive.infolist():
            if "\\" in info.filename:
                raise RuntimeError(f"non-portable wheel path: {info.filename}")
            path = PurePosixPath(info.filename)
            if path.is_absolute() or ".." in path.parts or "." in path.parts:
                raise RuntimeError(f"unsafe wheel path: {info.filename}")
            lowered_parts = {part.casefold() for part in path.parts}
            if lowered_parts & PROHIBITED_PARTS:
                raise RuntimeError(f"prohibited path in wheel: {info.filename}")
            if path.suffix.casefold() in PROHIBITED_SUFFIXES:
                raise RuntimeError(f"prohibited sensitive suffix in wheel: {info.filename}")
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise RuntimeError(f"symlink in wheel: {info.filename}")
            is_distribution_metadata = any(
                part.endswith(".dist-info") for part in path.parts
            )
            if path.suffix == ".py" and is_distribution_metadata is False:
                assert_artifact_python_path_is_reviewed(
                    path,
                    reviewed_packages,
                )
                if path.as_posix() not in expected_python:
                    raise SourceBoundaryError(
                        f"untracked Python source in wheel: {path}"
                    )
                present_python.add(path.as_posix())
            if (
                info.is_dir() is False
                and path.suffix != ".py"
                and info.filename not in required
                and is_distribution_metadata is False
            ):
                raise RuntimeError(
                    f"unexpected non-code resource outside release allowlist: "
                    f"{info.filename}"
                )
    missing = sorted(required - names)
    if missing:
        raise RuntimeError("wheel is missing approved resources:\n  " + "\n  ".join(missing))
    missing_python = sorted(expected_python - present_python)
    if missing_python:
        raise RuntimeError(
            "wheel is missing reviewed Python sources:\n  "
            + "\n  ".join(missing_python)
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("scripts/release/bundle-data.json"),
    )
    args = parser.parse_args()
    try:
        verify_wheel(args.wheel, args.manifest)
    except (
        OSError,
        RuntimeError,
        SourceBoundaryError,
        zipfile.BadZipFile,
        json.JSONDecodeError,
    ) as error:
        print(f"wheel verification failed: {error}", file=sys.stderr)
        return 2
    print(f"verified wheel resources: {args.wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
