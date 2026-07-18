#!/usr/bin/env python3
"""Stage the exact immutable data files allowed in frozen bundles.

PyInstaller accepts directory-valued ``datas`` entries and recursively copies
their contents.  That is convenient but unsafe in a developer checkout:
ignored workspaces, credentials, captures, and local plug-ins can silently
enter a public executable.  This helper consumes an explicit file manifest,
rejects symlinks and path escapes, copies only those files to a clean staging
directory, and emits a SHA-256 inventory that is itself bundled.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


KNOWN_FLAVORS = frozenset({"clean", "full"})
PROHIBITED_TOP_LEVEL = frozenset(
    {
        ".git",
        "plugins",
        "pysim",
        "reports",
        "state",
        "workspace",
        "yggdrasim-data",
    }
)
GENERATED_MANIFEST = "yggdrasim_release/bundle-data-manifest.json"
STAGE_MARKER = ".yggdrasim-bundle-stage"
STAGE_MARKER_CONTENT = "yggdrasim bundle-data staging directory v1\n"


class BundleDataError(RuntimeError):
    """Raised when a bundle-data manifest violates the release boundary."""


def assert_no_ignored_python_sources(
    repo_root: Path,
    package_names: list[str] | tuple[str, ...],
) -> None:
    """Reject ignored/canary Python files below published package roots.

    ``PyInstaller.collect_submodules`` discovers files from the working tree,
    independently of the data allowlist.  A local ignored ``*.py`` file below
    a published package would otherwise be compiled into a bundle.  Tracked
    files that happen to match a broad legacy ignore rule remain valid; Git's
    normal ``check-ignore`` semantics intentionally report only untracked
    ignored paths here.
    """
    root = Path(repo_root).resolve(strict=True)
    candidates: dict[str, Path] = {}
    for package_name in package_names:
        relative = PurePosixPath(*str(package_name).split("."))
        package_root = root.joinpath(*relative.parts)
        if not package_root.is_dir():
            raise BundleDataError(
                f"published Python package is missing: {package_name}"
            )
        for source in package_root.rglob("*.py"):
            if "__pycache__" in source.parts:
                continue
            if source.is_symlink():
                raise BundleDataError(
                    f"published Python source is a symlink: {source.relative_to(root)}"
                )
            resolved = source.resolve(strict=True)
            try:
                relative_source = resolved.relative_to(root).as_posix()
            except ValueError as error:
                raise BundleDataError(
                    f"published Python source escapes the repository: {source}"
                ) from error
            candidates[relative_source] = resolved

    canaries = [
        value.encode("utf-8")
        for value in os.environ.get("YGGDRASIM_RELEASE_CANARIES", "").split(",")
        if value
    ]
    for relative_source, source in candidates.items():
        if any(canary in source.read_bytes() for canary in canaries):
            raise BundleDataError(
                f"release canary found in Python source: {relative_source}"
            )

    if not (root / ".git").exists() or not candidates:
        return
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-z", "--stdin"],
            cwd=root,
            input=("\0".join(sorted(candidates)) + "\0").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise BundleDataError(
            "git is required to verify the frozen Python-source boundary"
        ) from error
    if result.returncode not in {0, 1}:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise BundleDataError(
            f"could not inspect ignored Python sources: {detail or result.returncode}"
        )
    ignored = [
        value.decode("utf-8", errors="replace")
        for value in result.stdout.split(b"\0")
        if value
    ]
    if ignored:
        raise BundleDataError(
            "ignored Python source occurs below a published package: "
            + ", ".join(sorted(ignored))
        )


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _manifest_path(repo_root: Path) -> Path:
    return repo_root / "scripts" / "release" / "bundle-data.json"


def _load_manifest(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleDataError(f"unable to read bundle-data manifest {path}: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise BundleDataError("bundle-data manifest must use schema_version 1")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise BundleDataError("bundle-data manifest entries must be a list")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(entries):
        if not isinstance(raw, dict):
            raise BundleDataError(f"bundle-data entry {index} must be an object")
        path_text = str(raw.get("path") or "").strip()
        if not path_text:
            raise BundleDataError(f"bundle-data entry {index} has no path")
        if path_text in seen:
            raise BundleDataError(f"duplicate bundle-data path: {path_text}")
        seen.add(path_text)
        flavors = raw.get("flavors", sorted(KNOWN_FLAVORS))
        if not isinstance(flavors, list) or not flavors:
            raise BundleDataError(f"bundle-data entry {path_text!r} has invalid flavors")
        flavor_set = {str(value) for value in flavors}
        if not flavor_set <= KNOWN_FLAVORS:
            raise BundleDataError(
                f"bundle-data entry {path_text!r} has unknown flavors: "
                f"{sorted(flavor_set - KNOWN_FLAVORS)}"
            )
        normalized.append({"path": path_text, "flavors": sorted(flavor_set)})
    return normalized


def _safe_source(repo_root: Path, path_text: str) -> tuple[Path, PurePosixPath]:
    relative = PurePosixPath(path_text)
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise BundleDataError(f"unsafe bundle-data path: {path_text!r}")
    if not relative.parts:
        raise BundleDataError("empty bundle-data path")
    if relative.parts[0].casefold() in PROHIBITED_TOP_LEVEL:
        raise BundleDataError(f"prohibited bundle-data root: {relative.parts[0]!r}")

    source = repo_root.joinpath(*relative.parts)
    cursor = repo_root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise BundleDataError(f"bundle-data path contains a symlink: {path_text!r}")
    try:
        resolved = source.resolve(strict=True)
    except OSError as error:
        raise BundleDataError(f"bundle-data source is missing: {path_text!r}") from error
    try:
        resolved.relative_to(repo_root)
    except ValueError as error:
        raise BundleDataError(f"bundle-data source escapes repository: {path_text!r}") from error
    if not resolved.is_file():
        raise BundleDataError(f"bundle-data source is not a regular file: {path_text!r}")
    return resolved, relative


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _assert_no_canaries(path: Path) -> None:
    """Reject caller-supplied release canaries if they appear in a staged file."""
    raw = os.environ.get("YGGDRASIM_RELEASE_CANARIES", "")
    canaries = [value.encode("utf-8") for value in raw.split(",") if value]
    if not canaries:
        return
    data = path.read_bytes()
    for canary in canaries:
        if canary in data:
            raise BundleDataError(f"release canary found in staged file: {path.name}")


def _reset_stage_directory(destination: Path, *, controlled_default: bool) -> None:
    """Create an empty stage without deleting an unrelated caller directory."""
    if destination.is_symlink():
        raise BundleDataError(f"bundle staging directory is a symlink: {destination}")
    if destination.exists():
        if not destination.is_dir():
            raise BundleDataError(
                f"bundle staging destination is not a directory: {destination}"
            )
        if not controlled_default and any(destination.iterdir()):
            marker = destination / STAGE_MARKER
            try:
                marker_content = marker.read_text(encoding="utf-8")
            except OSError as error:
                raise BundleDataError(
                    "refusing to replace an unowned non-empty bundle staging "
                    f"directory: {destination}"
                ) from error
            if marker.is_symlink() or marker_content != STAGE_MARKER_CONTENT:
                raise BundleDataError(
                    "refusing to replace an unowned non-empty bundle staging "
                    f"directory: {destination}"
                )
        shutil.rmtree(destination)
    destination.mkdir(parents=True, mode=0o700)
    marker = destination / STAGE_MARKER
    marker.write_text(STAGE_MARKER_CONTENT, encoding="utf-8")
    os.chmod(marker, 0o600)


def prepare_bundle_data(
    repo_root: Path,
    flavor: str,
    *,
    stage_dir: Path | None = None,
    manifest_path: Path | None = None,
) -> tuple[list[tuple[str, str]], Path]:
    """Return PyInstaller ``datas`` entries and the generated inventory path."""
    resolved_root = Path(repo_root).resolve(strict=True)
    normalized_flavor = str(flavor).strip().lower()
    if normalized_flavor not in KNOWN_FLAVORS:
        raise BundleDataError(f"unknown build flavor: {flavor!r}")
    entries = _load_manifest(
        Path(manifest_path).resolve(strict=True)
        if manifest_path is not None
        else _manifest_path(resolved_root)
    )

    destination_candidate = (
        Path(stage_dir)
        if stage_dir is not None
        else resolved_root / "build" / "bundle-data" / normalized_flavor
    )
    if destination_candidate.is_symlink():
        raise BundleDataError(
            f"bundle staging directory is a symlink: {destination_candidate}"
        )
    destination_root = destination_candidate.resolve()
    # Tests and downstream packagers may intentionally stage outside the
    # checkout, but never permit staging *over* the checkout itself.  The
    # default location must stay under ``build/`` in the checkout.
    if destination_root == resolved_root:
        raise BundleDataError(f"unsafe bundle staging directory: {destination_root}")
    if destination_root.parent == destination_root:
        raise BundleDataError(f"unsafe bundle staging directory: {destination_root}")
    if stage_dir is None and resolved_root not in destination_root.parents:
        raise BundleDataError(f"unsafe bundle staging directory: {destination_root}")
    _reset_stage_directory(
        destination_root,
        controlled_default=stage_dir is None,
    )

    datas: list[tuple[str, str]] = []
    inventory: list[dict[str, Any]] = []
    for entry in entries:
        if normalized_flavor not in entry["flavors"]:
            continue
        source, relative = _safe_source(resolved_root, entry["path"])
        destination = destination_root.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination, follow_symlinks=False)
        os.chmod(destination, 0o644)
        _assert_no_canaries(destination)
        inventory.append(
            {
                "mode": f"{destination.stat().st_mode & 0o7777:04o}",
                "path": relative.as_posix(),
                "sha256": _sha256(destination),
                "size": destination.stat().st_size,
            }
        )
        datas.append((str(destination), relative.parent.as_posix()))

    inventory.sort(key=lambda item: item["path"])
    generated_path = destination_root.joinpath(*PurePosixPath(GENERATED_MANIFEST).parts)
    generated_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "flavor": normalized_flavor,
        "files": inventory,
    }
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=generated_path.parent,
        prefix=".bundle-data-manifest.",
        delete=False,
    ) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    os.replace(temporary, generated_path)
    os.chmod(generated_path, 0o644)
    datas.append((str(generated_path), str(PurePosixPath(GENERATED_MANIFEST).parent)))
    return datas, generated_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=_repo_root())
    parser.add_argument("--flavor", choices=sorted(KNOWN_FLAVORS), required=True)
    parser.add_argument("--stage-dir", type=Path)
    args = parser.parse_args()
    datas, manifest = prepare_bundle_data(
        args.repo_root,
        args.flavor,
        stage_dir=args.stage_dir,
    )
    print(f"staged {len(datas) - 1} approved files")
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
