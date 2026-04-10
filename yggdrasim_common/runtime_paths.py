from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


RUNTIME_ROOT_ENV = "YGGDRASIM_RUNTIME_ROOT"
PORTABLE_RUNTIME_DIRNAME = "YggdraSIM-data"
WORKSPACE_DIRNAME = "Workspace"
_WRITE_PROBE_FILENAME = ".yggdrasim_write_probe"
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


def workspace_root() -> str:
    return ensure_directory(runtime_path(WORKSPACE_DIRNAME))


def workspace_path(*parts: str) -> str:
    return os.path.join(workspace_root(), *parts)


def remap_legacy_workspace_relative(path_text: str) -> str:
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
    return ensure_directory(workspace_path(*parts))


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


def _copy_tree_if_missing(source_dir: str, target_dir: str) -> None:
    normalized_source = os.path.abspath(os.path.expanduser(str(source_dir).strip()))
    normalized_target = os.path.abspath(os.path.expanduser(str(target_dir).strip()))
    if _same_path(normalized_source, normalized_target):
        return
    if os.path.isdir(normalized_source) is False:
        return
    for current_root, dir_names, file_names in os.walk(normalized_source):
        relative_root = os.path.relpath(current_root, normalized_source)
        if relative_root == ".":
            destination_root = normalized_target
        else:
            destination_root = os.path.join(normalized_target, relative_root)
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
