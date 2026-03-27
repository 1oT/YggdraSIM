from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


RUNTIME_ROOT_ENV = "YGGDRASIM_RUNTIME_ROOT"
PORTABLE_RUNTIME_DIRNAME = "YggdraSIM-data"
_WRITE_PROBE_FILENAME = ".yggdrasim_write_probe"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_root() -> str:
    if is_frozen():
        if hasattr(sys, "_MEIPASS"):
            return os.path.abspath(str(sys._MEIPASS))
    return str(Path(__file__).resolve().parent.parent)


def runtime_root() -> str:
    override = os.environ.get(RUNTIME_ROOT_ENV, "").strip()
    if len(override) > 0:
        normalized_override = os.path.abspath(os.path.expanduser(override))
        return _ensure_writable_root(normalized_override, strict=True)
    if is_frozen() is False:
        return bundle_root()
    portable_candidate = os.path.join(
        os.path.dirname(os.path.abspath(sys.executable)),
        PORTABLE_RUNTIME_DIRNAME,
    )
    portable_root = _try_writable_root(portable_candidate)
    if portable_root is not None:
        return portable_root
    fallback_root = os.path.join(
        os.path.expanduser("~"),
        PORTABLE_RUNTIME_DIRNAME,
    )
    return _ensure_writable_root(fallback_root, strict=True)


def runtime_path(*parts: str) -> str:
    return os.path.join(runtime_root(), *parts)


def bundle_path(*parts: str) -> str:
    return os.path.join(bundle_root(), *parts)


def ensure_directory(path: str) -> str:
    normalized = os.path.abspath(os.path.expanduser(str(path).strip()))
    os.makedirs(normalized, exist_ok=True)
    return normalized


def ensure_runtime_dir(*parts: str) -> str:
    return ensure_directory(runtime_path(*parts))


def ensure_seeded_runtime_file(*parts: str) -> str:
    target_path = runtime_path(*parts)
    source_path = bundle_path(*parts)
    _copy_file_if_missing(source_path, target_path)
    return target_path


def ensure_seeded_runtime_tree(*parts: str) -> str:
    target_dir = ensure_runtime_dir(*parts)
    source_dir = bundle_path(*parts)
    if _same_path(source_dir, target_dir):
        return target_dir
    if os.path.isdir(source_dir) is False:
        return target_dir
    for current_root, dir_names, file_names in os.walk(source_dir):
        relative_root = os.path.relpath(current_root, source_dir)
        if relative_root == ".":
            destination_root = target_dir
        else:
            destination_root = os.path.join(target_dir, relative_root)
        os.makedirs(destination_root, exist_ok=True)
        for directory_name in dir_names:
            os.makedirs(
                os.path.join(destination_root, directory_name),
                exist_ok=True,
            )
        for file_name in file_names:
            source_file = os.path.join(current_root, file_name)
            target_file = os.path.join(destination_root, file_name)
            _copy_file_if_missing(source_file, target_file)
    return target_dir


def _copy_file_if_missing(source_path: str, target_path: str) -> None:
    normalized_target = os.path.abspath(os.path.expanduser(str(target_path).strip()))
    target_parent = os.path.dirname(normalized_target)
    if len(target_parent) > 0:
        os.makedirs(target_parent, exist_ok=True)
    if os.path.exists(normalized_target):
        return
    normalized_source = os.path.abspath(os.path.expanduser(str(source_path).strip()))
    if os.path.isfile(normalized_source) is False:
        return
    if _same_path(normalized_source, normalized_target):
        return
    shutil.copy2(normalized_source, normalized_target)


def _try_writable_root(path: str) -> str | None:
    try:
        return _ensure_writable_root(path, strict=False)
    except OSError:
        return None


def _ensure_writable_root(path: str, strict: bool) -> str:
    normalized = os.path.abspath(os.path.expanduser(str(path).strip()))
    try:
        os.makedirs(normalized, exist_ok=True)
        probe_path = os.path.join(normalized, _WRITE_PROBE_FILENAME)
        with open(probe_path, "w", encoding="utf-8") as probe_file:
            probe_file.write("ok\n")
        os.remove(probe_path)
    except OSError:
        if strict:
            raise
        raise
    return normalized


def _same_path(left: str, right: str) -> bool:
    normalized_left = os.path.abspath(os.path.expanduser(str(left).strip()))
    normalized_right = os.path.abspath(os.path.expanduser(str(right).strip()))
    return normalized_left == normalized_right
