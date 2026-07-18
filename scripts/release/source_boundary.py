#!/usr/bin/env python3
"""Validate the reviewed Python-package boundary before a public build."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PACKAGE_MANIFEST = Path(__file__).with_name("python-packages.json")


class SourceBoundaryError(RuntimeError):
    """Raised when Python package discovery crosses the reviewed boundary."""


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SourceBoundaryError(
            f"unable to read Python-package manifest {path}: {error}"
        ) from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise SourceBoundaryError("Python-package manifest must use schema_version 1")
    return payload


def load_reviewed_packages(path: Path = PACKAGE_MANIFEST) -> tuple[str, ...]:
    """Load and validate the exact public Python-package names."""
    raw_packages = _load_manifest(path).get("packages")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise SourceBoundaryError("Python-package manifest packages must be a list")

    packages: list[str] = []
    seen: set[str] = set()
    for raw_package in raw_packages:
        package = str(raw_package or "").strip()
        parts = package.split(".")
        if (
            not package
            or package in seen
            or any(not part.isidentifier() for part in parts)
        ):
            raise SourceBoundaryError(
                f"invalid or duplicate reviewed package name: {package!r}"
            )
        seen.add(package)
        packages.append(package)
    return tuple(packages)


def load_reviewed_release_files(path: Path = PACKAGE_MANIFEST) -> tuple[str, ...]:
    """Load the exact release-helper files allowed in source distributions."""
    raw_files = _load_manifest(path).get("release_files")
    if not isinstance(raw_files, list) or not raw_files:
        raise SourceBoundaryError("Python-package manifest release_files must be a list")
    reviewed: list[str] = []
    seen: set[str] = set()
    for raw_file in raw_files:
        text = str(raw_file or "").strip()
        relative = PurePosixPath(text)
        if (
            not text
            or text in seen
            or relative.is_absolute()
            or ".." in relative.parts
            or "." in relative.parts
            or relative.parts[:2] != ("scripts", "release")
            or relative.suffix not in {".json", ".py"}
        ):
            raise SourceBoundaryError(
                f"invalid or duplicate reviewed release file: {text!r}"
            )
        seen.add(text)
        reviewed.append(text)
    return tuple(reviewed)


def package_name_for_python_path(path: str | PurePosixPath) -> str:
    """Return the package owning one repository-relative ``.py`` path."""
    relative = PurePosixPath(path)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or "." in relative.parts
        or relative.suffix != ".py"
        or len(relative.parts) < 2
    ):
        raise SourceBoundaryError(f"unsafe Python source path: {relative}")
    return ".".join(relative.parent.parts)


def load_reviewed_source_additions(
    path: Path = PACKAGE_MANIFEST,
) -> tuple[str, ...]:
    """Load explicitly reviewed package sources not yet in the Git baseline.

    This keeps dirty-tree release checks exact while a remediation is under
    review. Once those files enter the baseline the entries are harmless and
    may be removed in the next manifest-maintenance pass.
    """
    raw_files = _load_manifest(path).get("reviewed_source_additions", [])
    if not isinstance(raw_files, list):
        raise SourceBoundaryError(
            "Python-package manifest reviewed_source_additions must be a list"
        )
    packages = frozenset(load_reviewed_packages(path))
    reviewed: list[str] = []
    seen: set[str] = set()
    for raw_file in raw_files:
        text = str(raw_file or "").strip()
        relative = PurePosixPath(text)
        if (
            not text
            or text in seen
            or relative.is_absolute()
            or ".." in relative.parts
            or "." in relative.parts
            or relative.suffix != ".py"
            or package_name_for_python_path(relative) not in packages
        ):
            raise SourceBoundaryError(
                f"invalid or duplicate reviewed source addition: {text!r}"
            )
        seen.add(text)
        reviewed.append(text)
    return tuple(reviewed)


def reviewed_python_sources(
    repo_root: Path,
    packages: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """Return Python files directly owned by exact reviewed packages."""
    root = Path(repo_root).resolve(strict=True)
    package_names = tuple(packages or load_reviewed_packages())
    sources: set[str] = set()
    for package in package_names:
        package_dir = root.joinpath(*package.split("."))
        if not package_dir.is_dir() or package_dir.is_symlink():
            raise SourceBoundaryError(
                f"reviewed package directory is missing or linked: {package}"
            )
        # Direct children only: recursively walking broad roots such as Tools
        # would silently reclassify local sibling namespaces as public.
        for source in package_dir.glob("*.py"):
            if source.is_symlink():
                raise SourceBoundaryError(
                    f"reviewed Python source is a symlink: {source.relative_to(root)}"
                )
            resolved = source.resolve(strict=True)
            try:
                relative = resolved.relative_to(root).as_posix()
            except ValueError as error:
                raise SourceBoundaryError(
                    f"reviewed Python source escapes the repository: {source}"
                ) from error
            sources.add(relative)
    return tuple(sorted(sources))


def reviewed_release_files(
    repo_root: Path,
    files: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """Validate and return the exact reviewed release-helper files."""
    root = Path(repo_root).resolve(strict=True)
    reviewed = tuple(files or load_reviewed_release_files())
    for relative_text in reviewed:
        candidate = root.joinpath(*PurePosixPath(relative_text).parts)
        if not candidate.is_file() or candidate.is_symlink():
            raise SourceBoundaryError(
                f"reviewed release file is missing or linked: {relative_text}"
            )
        try:
            candidate.resolve(strict=True).relative_to(root)
        except ValueError as error:
            raise SourceBoundaryError(
                f"reviewed release file escapes the repository: {relative_text}"
            ) from error
    return tuple(sorted(reviewed))


def _git_paths(
    root: Path,
    command: list[str],
    *,
    stdin: bytes | None = None,
) -> tuple[str, ...]:
    try:
        result = subprocess.run(
            command,
            cwd=root,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise SourceBoundaryError(
            "git is required to verify the public source boundary"
        ) from error
    if result.returncode not in {0, 1}:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise SourceBoundaryError(
            f"could not inspect public sources: {detail or result.returncode}"
        )
    return tuple(
        value.decode("utf-8", errors="replace")
        for value in result.stdout.split(b"\0")
        if value
    )


def tracked_reviewed_python_sources(
    repo_root: Path,
    packages: Iterable[str] | None = None,
    source_additions: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """Return the exact artifact Python paths owned by reviewed packages."""
    root = Path(repo_root).resolve(strict=True)
    reviewed = frozenset(packages or load_reviewed_packages())
    if not (root / ".git").exists():
        raise SourceBoundaryError(
            "a Git checkout is required to derive the reviewed artifact source set"
        )
    tracked = {
        path
        for path in _git_paths(root, ["git", "ls-files", "-z", "--", "*.py"])
        if PurePosixPath(path).suffix == ".py"
        and package_name_for_python_path(path) in reviewed
    }
    additions = set(
        load_reviewed_source_additions()
        if source_additions is None
        else source_additions
    )
    current = set(reviewed_python_sources(root, reviewed))
    invalid_additions = sorted(
        path
        for path in additions
        if path not in current
        or package_name_for_python_path(path) not in reviewed
    )
    if invalid_additions:
        raise SourceBoundaryError(
            "reviewed source addition is missing or outside the package boundary: "
            + ", ".join(invalid_additions)
        )
    return tuple(sorted(tracked | additions))


def assert_no_ignored_reviewed_python_sources(
    repo_root: Path,
    packages: Iterable[str] | None = None,
    release_files: Iterable[str] = (),
) -> tuple[str, ...]:
    """Reject ignored Python files that belong to the reviewed boundary."""
    root = Path(repo_root).resolve(strict=True)
    sources = reviewed_python_sources(root, packages)
    release_paths = reviewed_release_files(root, release_files) if release_files else ()
    candidates = tuple(
        sorted(
            set(sources)
            | {
                path
                for path in release_paths
                if PurePosixPath(path).suffix == ".py"
            }
        )
    )
    if not (root / ".git").exists() or not candidates:
        return sources
    ignored = sorted(
        _git_paths(
            root,
            ["git", "check-ignore", "-z", "--stdin"],
            stdin=("\0".join(candidates) + "\0").encode("utf-8"),
        )
    )
    if ignored:
        raise SourceBoundaryError(
            "ignored Python source belongs to the reviewed public boundary: "
            + ", ".join(ignored)
        )
    return sources


def assert_no_untracked_reviewed_sources(
    repo_root: Path,
    packages: Iterable[str] | None = None,
    release_files: Iterable[str] = (),
    source_additions: Iterable[str] = (),
) -> tuple[str, ...]:
    """Reject untracked files from reviewed packages and release helpers."""
    root = Path(repo_root).resolve(strict=True)
    sources = reviewed_python_sources(root, packages)
    release_paths = reviewed_release_files(root, release_files) if release_files else ()
    candidates = set(sources) | set(release_paths)
    if not (root / ".git").exists():
        return sources
    tracked = set(_git_paths(root, ["git", "ls-files", "-z", "--"]))
    explicitly_reviewed = set(release_paths) | set(source_additions)
    untracked = sorted(candidates - tracked - explicitly_reviewed)
    if untracked:
        raise SourceBoundaryError(
            "untracked file occurs inside the reviewed public source boundary: "
            + ", ".join(untracked)
        )
    return sources


def assert_artifact_python_path_is_reviewed(
    relative_path: str | PurePosixPath,
    packages: Iterable[str] | None = None,
) -> None:
    """Reject an artifact Python path outside the reviewed package set."""
    package = package_name_for_python_path(relative_path)
    reviewed = frozenset(packages or load_reviewed_packages())
    if package not in reviewed:
        raise SourceBoundaryError(
            f"Python source belongs to an unreviewed package {package!r}: "
            f"{PurePosixPath(relative_path)}"
        )


def assert_release_artifact_path_is_reviewed(
    relative_path: str | PurePosixPath,
    release_files: Iterable[str] | None = None,
) -> None:
    """Reject an unexpected file below ``scripts/release`` in an sdist."""
    relative = PurePosixPath(relative_path)
    if relative.parts[:2] != ("scripts", "release"):
        return
    reviewed = frozenset(release_files or load_reviewed_release_files())
    if relative.as_posix() not in reviewed:
        raise SourceBoundaryError(
            f"unreviewed release helper in artifact: {relative}"
        )


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=_repo_root())
    parser.add_argument("--manifest", type=Path, default=PACKAGE_MANIFEST)
    args = parser.parse_args()
    try:
        packages = load_reviewed_packages(args.manifest)
        release_files = load_reviewed_release_files(args.manifest)
        source_additions = load_reviewed_source_additions(args.manifest)
        sources = assert_no_ignored_reviewed_python_sources(
            args.repo_root,
            packages,
            release_files,
        )
        assert_no_untracked_reviewed_sources(
            args.repo_root,
            packages,
            release_files,
            source_additions,
        )
    except SourceBoundaryError as error:
        print(f"Python source-boundary validation failed: {error}", file=sys.stderr)
        return 2
    print(
        f"validated {len(sources)} Python sources in "
        f"{len(packages)} reviewed packages and "
        f"{len(release_files)} release files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
