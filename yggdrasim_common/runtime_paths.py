# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Runtime path resolution: derives per-user config, cache, and state directories for the YggdraSIM installation."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

from yggdrasim_common.secure_files import (
    atomic_write_bytes,
    ensure_private_directory,
    ensure_private_file,
    harden_private_tree,
    read_bounded_regular_file,
)

RUNTIME_ROOT_ENV = "YGGDRASIM_RUNTIME_ROOT"
PORTABLE_RUNTIME_DIRNAME = "YggdraSIM-data"
INSTALLED_RUNTIME_DIRNAME = "YggdraSIM"
WORKSPACE_DIRNAME = "Workspace"
_WRITE_PROBE_FILENAME = ".yggdrasim_write_probe"
_MAX_SEED_FILE_BYTES = 64 * 1024 * 1024
_HARDENED_WORKSPACES: set[str] = set()
_LEGACY_WORKSPACE_ALIASES: tuple[tuple[str, str], ...] = (
    ("SCP03/keys.ini", f"{WORKSPACE_DIRNAME}/SCP03/keys.ini"),
    ("SCP03/fids.txt", f"{WORKSPACE_DIRNAME}/SCP03/fids.txt"),
    ("SCP03/aid.txt", f"{WORKSPACE_DIRNAME}/SCP03/aid.txt"),
    ("SCP03/binds.json", f"{WORKSPACE_DIRNAME}/SCP03/binds.json"),
    ("SCP11/local_access/certs", f"{WORKSPACE_DIRNAME}/LocalSMDPP/certs"),
    ("SCP11/local_access/profile", f"{WORKSPACE_DIRNAME}/LocalSMDPP/profile"),
    ("SCP11/local_access/debug", f"{WORKSPACE_DIRNAME}/LocalSMDPP/debug"),
    ("SCP11/eim_local/certs", f"{WORKSPACE_DIRNAME}/LocalEIM/certs"),
    ("SCP11/eim_local/profile", f"{WORKSPACE_DIRNAME}/LocalEIM/profile"),
    ("SCP11/eim_local/eim_packages", f"{WORKSPACE_DIRNAME}/LocalEIM/eim_packages"),
    ("SCP11/eim_local/eim_identity.json", f"{WORKSPACE_DIRNAME}/LocalEIM/eim_identity.json"),
    ("SCP11/eim_local/eim_response_log.jsonl", f"{WORKSPACE_DIRNAME}/LocalEIM/eim_response_log.jsonl"),
    ("SCP11/eim_local/eim_runtime_state.json", f"{WORKSPACE_DIRNAME}/LocalEIM/eim_runtime_state.json"),
    ("SCP11/eim_local/eim_poll_audit.sqlite3", f"{WORKSPACE_DIRNAME}/LocalEIM/eim_poll_audit.sqlite3"),
    ("Tools/ProfilePackage/profile", f"{WORKSPACE_DIRNAME}/SAIP/profile"),
    ("Tools/ProfilePackage/transcode", f"{WORKSPACE_DIRNAME}/SAIP/transcode"),
    ("Tools/ProfilePackage/examples", f"{WORKSPACE_DIRNAME}/SAIP/examples"),
    ("Tools/ProfilePackage/saip_tool_config.json", f"{WORKSPACE_DIRNAME}/SAIP/saip_tool_config.json"),
)


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_root() -> str:
    if is_frozen():
        if hasattr(sys, "_MEIPASS"):
            return os.path.abspath(str(sys._MEIPASS))
    return str(Path(__file__).resolve().parent.parent)


def runtime_root() -> str:
    """Return the active runtime root directory, applying any workspace override."""
    override = os.environ.get(RUNTIME_ROOT_ENV, "").strip()
    if len(override) > 0:
        normalized_override = os.path.abspath(os.path.expanduser(override))
        return _ensure_writable_root(normalized_override)
    if is_frozen() is False:
        source_root = _editable_source_root()
        if source_root is not None:
            return source_root
        return _ensure_writable_root(_installed_user_runtime_root())
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
    return _ensure_writable_root(fallback_root)


def _editable_source_root() -> str | None:
    """Return the repository root only for a real editable/source checkout."""
    candidate = Path(bundle_root()).resolve()
    required = (
        candidate / "pyproject.toml",
        candidate / "main" / "main.py",
        candidate / "yggdrasim_common" / "__init__.py",
    )
    if all(path.is_file() for path in required):
        return str(candidate)
    return None


def _installed_user_runtime_root() -> str:
    """Return a platform-native per-user data location for wheel installs."""
    home = Path.home()
    if os.name == "nt":
        base = (
            os.environ.get("LOCALAPPDATA", "").strip()
            or os.environ.get("APPDATA", "").strip()
        )
        if not base:
            base = str(home / "AppData" / "Local")
        return str(Path(base) / INSTALLED_RUNTIME_DIRNAME)
    if sys.platform == "darwin":
        return str(home / "Library" / "Application Support" / INSTALLED_RUNTIME_DIRNAME)
    xdg_data_home = os.environ.get("XDG_DATA_HOME", "").strip()
    base = Path(xdg_data_home).expanduser() if xdg_data_home else home / ".local" / "share"
    return str(base / INSTALLED_RUNTIME_DIRNAME)


def runtime_path(*parts: str) -> str:
    return os.path.join(runtime_root(), *parts)


def workspace_root() -> str:
    target = str(ensure_private_directory(runtime_path(WORKSPACE_DIRNAME)))
    if target not in _HARDENED_WORKSPACES:
        harden_private_tree(target)
        _HARDENED_WORKSPACES.add(target)
    return target


def workspace_path(*parts: str) -> str:
    return os.path.join(workspace_root(), *parts)


def remap_legacy_workspace_relative(path_text: str) -> str:
    """Remap a legacy workspace-relative path to the canonical runtime path."""
    normalized = str(path_text or "").strip().replace("\\", "/")
    for legacy_prefix, new_prefix in _LEGACY_WORKSPACE_ALIASES:
        if normalized == legacy_prefix:
            return new_prefix
        prefix_with_separator = legacy_prefix + "/"
        if normalized.startswith(prefix_with_separator):
            return new_prefix + normalized[len(legacy_prefix) :]
    return normalized


def bundle_path(*parts: str) -> str:
    return os.path.join(bundle_root(), *parts)


def ensure_directory(path: str) -> str:
    normalized = os.path.abspath(os.path.expanduser(str(path).strip()))
    os.makedirs(normalized, exist_ok=True)
    return normalized


def ensure_runtime_dir(*parts: str) -> str:
    return ensure_directory(runtime_path(*parts))


def ensure_workspace_dir(*parts: str) -> str:
    return str(ensure_private_directory(workspace_path(*parts)))


def ensure_seeded_runtime_file(*parts: str) -> str:
    target_path = runtime_path(*parts)
    source_path = bundle_path(*parts)
    _copy_file_if_missing(source_path, target_path)
    return target_path


def ensure_seeded_runtime_tree(*parts: str) -> str:
    target_dir = ensure_runtime_dir(*parts)
    source_dir = bundle_path(*parts)
    _copy_tree_if_missing(source_dir, target_dir)
    return target_dir


def ensure_seeded_workspace_file(source_parts: tuple[str, ...], *target_parts: str) -> str:
    target_path = workspace_path(*target_parts)
    source_path = bundle_path(*source_parts)
    _copy_file_if_missing(source_path, target_path)
    return target_path


def ensure_seeded_workspace_tree(source_parts: tuple[str, ...], *target_parts: str) -> str:
    target_dir = ensure_workspace_dir(*target_parts)
    source_dir = bundle_path(*source_parts)
    _copy_tree_if_missing(source_dir, target_dir)
    return target_dir


def _copy_file_if_missing(source_path: str, target_path: str) -> None:
    normalized_target = os.path.abspath(os.path.expanduser(str(target_path).strip()))
    target_parent = os.path.dirname(normalized_target)
    private_target = _is_workspace_path(normalized_target)
    if len(target_parent) > 0:
        if private_target:
            ensure_private_directory(target_parent)
        else:
            os.makedirs(target_parent, exist_ok=True)
    if os.path.exists(normalized_target):
        if private_target and os.path.isfile(normalized_target):
            ensure_private_file(normalized_target)
        return
    normalized_source = os.path.abspath(os.path.expanduser(str(source_path).strip()))
    if os.path.isfile(normalized_source) is False:
        return
    if _same_path(normalized_source, normalized_target):
        return
    if private_target:
        atomic_write_bytes(
            normalized_target,
            read_bounded_regular_file(normalized_source, _MAX_SEED_FILE_BYTES),
            overwrite=False,
        )
    else:
        shutil.copy2(normalized_source, normalized_target)


def _copy_tree_if_missing(source_dir: str, target_dir: str) -> None:
    normalized_source = os.path.abspath(os.path.expanduser(str(source_dir).strip()))
    normalized_target = os.path.abspath(os.path.expanduser(str(target_dir).strip()))
    if _same_path(normalized_source, normalized_target):
        return
    if os.path.isdir(normalized_source) is False:
        return
    for current_root, dir_names, file_names in os.walk(normalized_source):
        current_path = Path(current_root)
        safe_dir_names: list[str] = []
        for directory_name in dir_names:
            source_child = current_path / directory_name
            if source_child.is_symlink():
                continue
            safe_dir_names.append(directory_name)
        dir_names[:] = safe_dir_names
        relative_root = os.path.relpath(current_root, normalized_source)
        if relative_root == ".":
            destination_root = normalized_target
        else:
            destination_root = os.path.join(normalized_target, relative_root)
        destination_is_private = _is_workspace_path(destination_root)
        if destination_is_private:
            ensure_private_directory(destination_root)
        else:
            os.makedirs(destination_root, exist_ok=True)
        for directory_name in dir_names:
            destination_child = os.path.join(destination_root, directory_name)
            if destination_is_private:
                ensure_private_directory(destination_child)
            else:
                os.makedirs(destination_child, exist_ok=True)
        for file_name in file_names:
            source_file = os.path.join(current_root, file_name)
            if Path(source_file).is_symlink():
                continue
            target_file = os.path.join(destination_root, file_name)
            _copy_file_if_missing(source_file, target_file)


def _try_writable_root(path: str) -> str | None:
    try:
        return _ensure_writable_root(path)
    except OSError:
        return None


def _ensure_writable_root(path: str) -> str:
    normalized = os.path.abspath(os.path.expanduser(str(path).strip()))
    ensure_private_directory(normalized)
    descriptor, probe_path = tempfile.mkstemp(
        prefix=f"{_WRITE_PROBE_FILENAME}.{os.getpid()}.",
        dir=normalized,
    )
    try:
        payload = memoryview(b"ok\n")
        while payload:
            written = os.write(descriptor, payload)
            if written <= 0:
                raise OSError("Runtime-root write probe made no progress.")
            payload = payload[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
        try:
            os.remove(probe_path)
        except OSError:
            pass
    return normalized


def _same_path(left: str, right: str) -> bool:
    normalized_left = os.path.normcase(
        os.path.abspath(os.path.expanduser(str(left).strip()))
    )
    normalized_right = os.path.normcase(
        os.path.abspath(os.path.expanduser(str(right).strip()))
    )
    return normalized_left == normalized_right


def _is_workspace_path(path: str) -> bool:
    """Return whether *path* is inside the active private Workspace tree."""
    candidate = os.path.normcase(
        os.path.abspath(os.path.expanduser(str(path).strip()))
    )
    workspace = os.path.normcase(
        os.path.abspath(runtime_path(WORKSPACE_DIRNAME))
    )
    try:
        return os.path.commonpath((candidate, workspace)) == workspace
    except ValueError:
        return False
