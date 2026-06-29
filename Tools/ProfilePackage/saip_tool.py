# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP tool bridge: GUI-facing adapter over the pySim saip_tool subprocess.

``SaipToolBridge`` owns the workspace state (current input file, default
directories, tool-command configuration) and exposes the operator actions
the GUI surfaces: opening a profile file, running the tool with arbitrary
arguments, and building the decoded-dump document used by the transcode
editor.  It handles hex→DER conversion, per-call caching, placeholder
sidecar injection, and pySim path discovery.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from yggdrasim_common.runtime_paths import remap_legacy_workspace_relative
from .saip_hex_template import (
    InlinePlaceholderRecord,
    detect_inline_placeholders,
    iter_inline_placeholders,
    sidecar_path_for_cache,
    substitute_inline_placeholders,
    write_sidecar,
)
from .saip_json_codec import transcode_sidecar_paths

_DEFAULT_TOOL_TIMEOUT_SECONDS = 60
_TOOL_TIMEOUT_ENV = "YGGDRASIM_SAIP_TOOL_TIMEOUT_SECONDS"

# ``.profilepackage-cache/`` holds hex-to-DER conversions. One cache file per
# distinct input path + payload digest; over a long-running maintainer
# workflow these accumulate and the directory balloons. The soft cap keeps
# the most recently used ``_MAX_CACHE_FILES`` entries and drops older ones.
_MAX_CACHE_FILES = 64
_CACHE_MAX_BYTES_ENV = "YGGDRASIM_SAIP_TOOL_CACHE_MAX_BYTES"
_DEFAULT_CACHE_MAX_BYTES = 256 * 1024 * 1024


def _resolve_cache_max_bytes() -> int:
    raw = str(os.environ.get(_CACHE_MAX_BYTES_ENV, "") or "").strip()
    if len(raw) == 0:
        return _DEFAULT_CACHE_MAX_BYTES
    try:
        parsed = int(raw)
    except ValueError:
        return _DEFAULT_CACHE_MAX_BYTES
    if parsed <= 0:
        return _DEFAULT_CACHE_MAX_BYTES
    return parsed


def _prune_profile_package_cache(cache_dir: Path, *, keep: Path) -> None:
    """Best-effort LRU-style prune of the hex-to-DER cache.

    Keeps the file we just wrote (``keep``) plus the newest
    ``_MAX_CACHE_FILES - 1`` cache entries, subject to a total-size budget
    configured via ``YGGDRASIM_SAIP_TOOL_CACHE_MAX_BYTES``. Errors are
    swallowed because the cache is purely advisory: the caller has already
    materialised ``keep`` and needs to hand it to saip-tool regardless.
    """
    try:
        entries: list[tuple[float, int, Path]] = []
        for candidate in cache_dir.iterdir():
            if candidate.is_file() is False:
                continue
            if candidate.suffix.lower() != ".der":
                continue
            try:
                stat_result = candidate.stat()
            except OSError:
                continue
            entries.append((stat_result.st_mtime, stat_result.st_size, candidate))
    except OSError:
        return

    if len(entries) == 0:
        return

    try:
        kept_resolved = keep.resolve()
    except OSError:
        kept_resolved = keep

    entries.sort(key=lambda item: item[0], reverse=True)
    max_bytes = _resolve_cache_max_bytes()
    keepers: list[Path] = []
    doomed: list[Path] = []
    running_bytes = 0
    for _mtime, size, path in entries:
        try:
            path_resolved = path.resolve()
        except OSError:
            path_resolved = path
        is_kept = path_resolved == kept_resolved
        projected = running_bytes + size
        would_exceed_count = len(keepers) >= _MAX_CACHE_FILES
        would_exceed_bytes = projected > max_bytes
        if is_kept:
            keepers.append(path)
            running_bytes = projected
            continue
        if would_exceed_count or would_exceed_bytes:
            doomed.append(path)
            continue
        keepers.append(path)
        running_bytes = projected

    for path in doomed:
        try:
            path.unlink()
        except OSError:
            continue
        sidecar_companion = path.with_suffix(".placeholders.json")
        if sidecar_companion.exists():
            try:
                sidecar_companion.unlink()
            except OSError:
                continue


@dataclass
class SaipCommandResult:
    """Result of a single saip_tool subprocess invocation."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def _repo_root_from_saip_module() -> Path:
    """Resolve YggdraSIM tree root from this file (.../Tools/ProfilePackage/saip_tool.py)."""
    return Path(__file__).resolve().parents[2]


def _describe_exception_chain(error: BaseException) -> str:
    parts: list[str] = []
    current: BaseException | None = error
    while current is not None:
        text = str(current).strip() or current.__class__.__name__
        if len(parts) == 0 or parts[-1] != text:
            parts.append(text)
        next_error = getattr(current, "__cause__", None)
        if isinstance(next_error, BaseException):
            current = next_error
            continue
        break
    return " | ".join(parts)


def _parse_timeout_seconds(raw_value: object) -> int:
    try:
        parsed = int(str(raw_value or "").strip())
    except (TypeError, ValueError):
        return _DEFAULT_TOOL_TIMEOUT_SECONDS
    if parsed <= 0:
        return _DEFAULT_TOOL_TIMEOUT_SECONDS
    return parsed


def _desktop_file_picker_supported() -> bool:
    display_value = str(os.environ.get("DISPLAY", "") or "").strip()
    if len(display_value) > 0:
        return True
    wayland_value = str(os.environ.get("WAYLAND_DISPLAY", "") or "").strip()
    if len(wayland_value) > 0:
        return True
    return False


def _run_file_picker_command(command: Sequence[str]) -> str | None:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"Failed to launch desktop file picker: {error}") from error
    if completed.returncode != 0:
        stderr_text = str(completed.stderr or "").strip()
        if len(stderr_text) == 0:
            return None
        raise RuntimeError(stderr_text)
    selected_path = str(completed.stdout or "").strip()
    if len(selected_path) == 0:
        return None
    return selected_path


def _pick_existing_file_path(
    *,
    title: str,
    initial_directory: Path,
    file_filter_label: str,
    file_filter_glob: str,
) -> Path | None:
    if _desktop_file_picker_supported() is False:
        raise RuntimeError("No desktop display is available for the file picker.")
    normalized_initial_directory = Path(initial_directory).expanduser().resolve()
    if normalized_initial_directory.exists() is False:
        normalized_initial_directory = normalized_initial_directory.parent
    if normalized_initial_directory.is_dir() is False:
        normalized_initial_directory = Path.cwd().resolve()

    picker_command: list[str] | None = None
    if shutil.which("zenity") is not None:
        picker_command = [
            "zenity",
            "--file-selection",
            f"--title={title}",
            f"--filename={str(normalized_initial_directory)}/",
            f"--file-filter={file_filter_label} | {file_filter_glob}",
            "--file-filter=All files | *",
        ]
    elif shutil.which("qarma") is not None:
        picker_command = [
            "qarma",
            "--file-selection",
            f"--title={title}",
            f"--filename={str(normalized_initial_directory)}/",
            f"--file-filter={file_filter_label} | {file_filter_glob}",
            "--file-filter=All files | *",
        ]
    elif shutil.which("yad") is not None:
        picker_command = [
            "yad",
            "--file-selection",
            f"--title={title}",
            f"--filename={str(normalized_initial_directory)}/",
            f"--file-filter={file_filter_label} | {file_filter_glob}",
            "--file-filter=All files | *",
        ]
    elif shutil.which("kdialog") is not None:
        picker_command = [
            "kdialog",
            "--title",
            title,
            "--getopenfilename",
            str(normalized_initial_directory),
            f"{file_filter_label} ({file_filter_glob})",
        ]
    if picker_command is not None:
        selected_path = _run_file_picker_command(picker_command)
        if selected_path is None:
            return None
        return Path(selected_path).expanduser().resolve()

    python_executable = str(sys.executable or "").strip()
    if len(python_executable) > 0:
        tkinter_script = (
            "import sys\n"
            "import tkinter as tk\n"
            "from tkinter import filedialog\n"
            "root = tk.Tk()\n"
            "root.withdraw()\n"
            "path = filedialog.askopenfilename(\n"
            "    title=sys.argv[1],\n"
            "    initialdir=sys.argv[2],\n"
            "    filetypes=[(sys.argv[3], sys.argv[4]), ('All files', '*')],\n"
            ")\n"
            "root.update()\n"
            "root.destroy()\n"
            "print(path)\n"
        )
        selected_path = _run_file_picker_command(
            [
                python_executable,
                "-c",
                tkinter_script,
                title,
                str(normalized_initial_directory),
                file_filter_label,
                file_filter_glob,
            ]
        )
        if selected_path is None:
            return None
        return Path(selected_path).expanduser().resolve()

    raise RuntimeError(
        "No supported desktop file picker is available. Install zenity, qarma, yad, kdialog, or Tk support."
    )


class SaipToolBridge:
    """Stateful adapter between the GUI and the saip_tool / pySim pipeline.

    The bridge persists a ``current_input_file``, a ``default_profile_dir``,
    a ``default_transcode_dir``, and the active tool command across GUI
    sessions via a JSON config file at ``config_path``.  All path resolution
    is workspace-rooted: bare filenames resolve relative to
    ``default_profile_dir``; absolute paths outside the workspace boundary
    raise ``ValueError`` (workspace sandbox invariant).

    Hex-format input (``*.hex``, ``*.txt``, ``*.varder``) is converted to
    DER on first use and cached in ``.profilepackage-cache/`` keyed by
    content digest.
    """

    _HEX_INPUT_SUFFIXES = {".hex", ".txt", ".varder"}
    _INPUT_FILE_PICKER_LABEL = "SAIP profile files"
    _INPUT_FILE_PICKER_GLOB = "*.der *.txt *.hex *.varder *.upp *.bin"
    _RAW_INPUT_PATH_FLAGS = {
        "--applet-file": True,
        "--output-dir": False,
        "--output-file": False,
        "--output-prefix": False,
        "--pe-file": False,
    }

    def __init__(
        self,
        workspace_root: Path,
        runner: Optional[Callable[[Sequence[str]], subprocess.CompletedProcess[str]]] = None,
        tool_command: Optional[Sequence[str]] = None,
        config_path: Optional[Path] = None,
        bundle_root_path: Optional[Path] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.bundle_root = (
            Path(bundle_root_path).resolve()
            if bundle_root_path is not None
            else self.workspace_root
        )
        self.runner = runner if runner is not None else self._run_subprocess
        self.command_timeout_seconds = _parse_timeout_seconds(
            os.environ.get(_TOOL_TIMEOUT_ENV, _DEFAULT_TOOL_TIMEOUT_SECONDS)
        )
        self._tool_command = list(tool_command) if tool_command is not None else None
        self.config_path = (
            Path(config_path).resolve()
            if config_path is not None
            else (self.workspace_root / "Workspace" / "SAIP" / "saip_tool_config.json")
        )
        self.default_profile_dir = self.workspace_root / "Workspace" / "SAIP" / "profile"
        self.default_transcode_dir = self.workspace_root / "Workspace" / "SAIP" / "transcode"
        self.current_input_file: Optional[Path] = None
        self.last_input_open_directory: Optional[Path] = None
        self._load_config()
        self._seed_tree_if_missing(
            self.bundle_root / "Tools" / "ProfilePackage" / "profile",
            self.default_profile_dir,
        )
        self._seed_tree_if_missing(
            self.bundle_root / "Tools" / "ProfilePackage" / "examples",
            self.workspace_root / "Workspace" / "SAIP" / "examples",
        )
        self.default_profile_dir.mkdir(parents=True, exist_ok=True)
        self.default_transcode_dir.mkdir(parents=True, exist_ok=True)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

    def set_input_file(self, path_text: str) -> Path:
        """Resolve, validate, and persist a new current input file.

        The path is resolved via ``resolve_input_path`` (workspace-relative
        bare names anchor to ``default_profile_dir``).  Saves the config
        and updates ``last_input_open_directory``.  Raises
        ``FileNotFoundError`` when the resolved path does not exist, or
        ``IsADirectoryError`` when it resolves to a directory.
        """
        resolved_path = self.resolve_input_path(path_text, must_exist=True)
        if resolved_path.is_dir():
            raise IsADirectoryError(f"Expected a file, got directory: {resolved_path}")
        self.current_input_file = resolved_path
        self.last_input_open_directory = resolved_path.parent.resolve()
        self._save_config()
        return resolved_path

    def pick_input_file(self) -> Optional[Path]:
        """Open a native file-picker dialog and set the result as the current input.

        Returns the resolved ``Path`` on success, or ``None`` when the user
        cancels without selecting a file.  Falls through to
        ``set_input_file`` so the same validation rules apply.
        """
        initial_directory = self.default_profile_dir
        if self.last_input_open_directory is not None:
            initial_directory = self.last_input_open_directory
        elif self.current_input_file is not None:
            initial_directory = self.current_input_file.parent.resolve()
        selected_path = _pick_existing_file_path(
            title="Open SAIP profile package",
            initial_directory=initial_directory,
            file_filter_label=self._INPUT_FILE_PICKER_LABEL,
            file_filter_glob=self._INPUT_FILE_PICKER_GLOB,
        )
        if selected_path is None:
            return None
        return self.set_input_file(str(selected_path))

    def set_default_profile_dir(self, path_text: str) -> Path:
        """Set and persist the default profile directory used for bare-name resolution."""
        resolved_path = self.resolve_workspace_path(path_text, must_exist=False)
        resolved_path.mkdir(parents=True, exist_ok=True)
        self.default_profile_dir = resolved_path
        self._save_config()
        return resolved_path

    def set_default_transcode_dir(self, path_text: str) -> Path:
        """Set and persist the default transcode output directory."""
        resolved_path = self.resolve_workspace_path(path_text, must_exist=False)
        resolved_path.mkdir(parents=True, exist_ok=True)
        self.default_transcode_dir = resolved_path
        self._save_config()
        return resolved_path

    def list_default_profiles(self) -> list[Path]:
        """List non-hidden, non-sidecar files in the default profile directory."""
        if self.default_profile_dir.exists() is False or self.default_profile_dir.is_dir() is False:
            return []

        profiles: list[Path] = []
        for entry in sorted(self.default_profile_dir.iterdir(), key=lambda item: item.name.lower()):
            if entry.is_file() is False:
                continue
            if entry.name.startswith("."):
                continue
            if self.is_transcode_sidecar(entry):
                continue
            profiles.append(entry.resolve())
        return profiles

    @staticmethod
    def _seed_tree_if_missing(source_dir: Path, target_dir: Path) -> None:
        source = Path(source_dir).resolve()
        target = Path(target_dir).resolve()
        if source == target:
            return
        if source.exists() is False or source.is_dir() is False:
            return
        target.mkdir(parents=True, exist_ok=True)
        for current_root, dir_names, file_names in os.walk(source):
            relative_root = Path(current_root).resolve().relative_to(source)
            destination_root = target / relative_root
            destination_root.mkdir(parents=True, exist_ok=True)
            for directory_name in dir_names:
                (destination_root / directory_name).mkdir(parents=True, exist_ok=True)
            for file_name in file_names:
                source_file = Path(current_root) / file_name
                target_file = destination_root / file_name
                if target_file.exists():
                    continue
                shutil.copy2(source_file, target_file)

    @staticmethod
    def is_transcode_sidecar(path_value: Path) -> bool:
        """Return ``True`` when ``path_value`` is a generated transcode artefact.

        Matches ``.transcode.json``, ``.transcode.der``, and ``.transcode.txt``
        suffixes so these files are excluded from the profile list.
        """
        name = Path(path_value).name.lower()
        return (
            name.endswith(".transcode.json")
            or name.endswith(".transcode.der")
            or name.endswith(".transcode.txt")
        )

    def resolve_transcode_sidecar_paths(self, source_profile_path: Path) -> tuple[Path, Path, Path]:
        """Return the ``(json, der, txt)`` sidecar paths for a source profile.

        Delegates to ``saip_json_codec.transcode_sidecar_paths`` with the
        bridge's configured transcode and profile directories.
        """
        return transcode_sidecar_paths(
            source_profile_path,
            transcode_root=self.default_transcode_dir,
            source_root=self.default_profile_dir,
        )

    def get_input_file(self) -> Path:
        """Return the current input file path; raises ``ValueError`` when none is set."""
        if self.current_input_file is None:
            raise ValueError("No profile package selected. Use USE <path> first.")
        return self.current_input_file

    def set_tool_command(self, command_text: str) -> list[str]:
        """Parse and persist an explicit tool command string (shell-split tokens)."""
        tokens = shlex.split(command_text.strip())
        if len(tokens) == 0:
            raise ValueError("Tool command cannot be empty.")
        self._tool_command = tokens
        return list(self._tool_command)

    def get_tool_command(self) -> list[str]:
        """Resolve the effective tool command, consulting ``YGGDRASIM_SAIP_TOOL`` env and bundled script."""
        if self._tool_command is not None:
            return list(self._tool_command)

        configured_value = os.environ.get("YGGDRASIM_SAIP_TOOL", "").strip()
        if len(configured_value) > 0:
            self._tool_command = shlex.split(configured_value)
            return list(self._tool_command)

        for candidate in ("saip-tool.py", "saip-tool"):
            resolved_binary = shutil.which(candidate)
            if resolved_binary is not None:
                self._tool_command = [resolved_binary]
                return list(self._tool_command)

        seen_script: set[Path] = set()
        for base in (self.workspace_root, self.bundle_root, _repo_root_from_saip_module()):
            bundled_script = (base / "pysim" / "contrib" / "saip-tool.py").resolve()
            if bundled_script in seen_script:
                continue
            seen_script.add(bundled_script)
            if bundled_script.is_file():
                self._tool_command = [sys.executable, str(bundled_script)]
                return list(self._tool_command)

        raise RuntimeError(
            "saip-tool was not found. Install pySim saip-tool, set YGGDRASIM_SAIP_TOOL, "
            "or clone the upstream pySim tree so "
            "<YggdraSIM>/pysim/contrib/saip-tool.py is present "
            "(git clone https://gitlab.com/osmocom/pysim.git pysim). "
            f"Checked workspace {self.workspace_root}, bundle root {self.bundle_root}, "
            f"and module root {_repo_root_from_saip_module()}."
        )

    def describe_status(self) -> str:
        """Return a one-line status string for display in the GUI status bar."""
        current_file = "(not selected)"
        if self.current_input_file is not None:
            current_file = self._display_path(self.current_input_file)
        transcode_dir = self._display_path(self.default_transcode_dir)
        return f"Active profile: {current_file} | Transcode dir: {transcode_dir}"

    def describe_tool_command(self) -> str:
        """Return a display string for the resolved tool command, or a graceful error."""
        try:
            return " ".join(self.get_tool_command())
        except Exception as error:
            return f"unavailable ({error})"

    def _display_path(self, path_value: Path) -> str:
        path_obj = Path(path_value)
        try:
            return path_obj.relative_to(self.workspace_root).as_posix()
        except ValueError:
            return str(path_obj)

    def display_path(self, path_value: Path) -> str:
        """Return ``path_value`` relative to the workspace root when possible."""
        return self._display_path(path_value)

    def resolve_path(self, path_text: str, must_exist: bool = False) -> Path:
        """Alias for ``resolve_workspace_path``; kept for backwards compatibility."""
        return self.resolve_workspace_path(path_text, must_exist=must_exist)

    def _normalize_missing_leading_slash_input_path(
        self,
        raw_value: str,
        *,
        must_exist: bool,
    ) -> str:
        normalized = str(raw_value or "").strip()
        if must_exist is False:
            return normalized
        if normalized.startswith(os.sep) or normalized.startswith("~"):
            return normalized
        if normalized.startswith("home/") is False:
            return normalized

        workspace_candidate = (self.workspace_root / normalized).resolve()
        if workspace_candidate.exists():
            return normalized

        absolute_candidate = Path(os.sep + normalized).expanduser().resolve()
        if absolute_candidate.exists():
            return str(absolute_candidate)
        return normalized

    def resolve_input_path(self, path_text: str, must_exist: bool = False) -> Path:
        """Resolve a path string to an absolute ``Path``, anchored to the workspace.

        Resolution order: absolute / home-relative → workspace-relative with
        bare-name fallback to ``default_profile_dir`` → workspace root.
        Raises ``FileNotFoundError`` when ``must_exist=True`` and the path
        does not exist.  Does NOT enforce the workspace sandbox boundary —
        use ``resolve_workspace_path`` for that.
        """
        raw_value = str(path_text or "").strip()
        if len(raw_value) == 0:
            raise ValueError("Path cannot be empty.")
        raw_value = self._normalize_missing_leading_slash_input_path(
            raw_value,
            must_exist=must_exist,
        )
        if Path(raw_value).expanduser().is_absolute() is False:
            raw_value = remap_legacy_workspace_relative(raw_value)

        candidate_path = Path(raw_value).expanduser()
        if candidate_path.is_absolute() is False:
            has_relative_components = any(
                marker in raw_value for marker in ("/", os.sep)
            ) or raw_value.startswith(".")
            if has_relative_components is False:
                default_candidate = self.default_profile_dir / candidate_path
                resolved_default_candidate = default_candidate.resolve()
                if must_exist is False or resolved_default_candidate.exists():
                    return resolved_default_candidate
            candidate_path = self.workspace_root / candidate_path

        resolved_path = candidate_path.resolve()
        if must_exist and resolved_path.exists() is False:
            raise FileNotFoundError(f"Path not found: {resolved_path}")
        return resolved_path

    def resolve_workspace_path(self, path_text: str, must_exist: bool = False) -> Path:
        """Resolve a path string and enforce the workspace-root sandbox boundary.

        Raises ``ValueError`` when the resolved absolute path falls outside
        ``workspace_root``.  Relative paths are anchored to ``workspace_root``
        (not ``default_profile_dir``).
        """
        raw_value = str(path_text or "").strip()
        if len(raw_value) == 0:
            raise ValueError("Path cannot be empty.")
        if Path(raw_value).expanduser().is_absolute() is False:
            raw_value = remap_legacy_workspace_relative(raw_value)

        candidate_path = Path(raw_value).expanduser()
        if candidate_path.is_absolute() is False:
            candidate_path = self.workspace_root / candidate_path

        resolved_path = candidate_path.resolve()
        if self._is_within_workspace(resolved_path) is False:
            raise ValueError(f"Path is outside workspace root: {resolved_path}")

        if must_exist and resolved_path.exists() is False:
            raise FileNotFoundError(f"Path not found: {resolved_path}")

        return resolved_path

    def run_current(self, args: Sequence[str]) -> SaipCommandResult:
        """Run the tool against the currently selected input file."""
        return self.run(self.get_input_file(), args)

    def run(self, input_file: Path, args: Sequence[str]) -> SaipCommandResult:
        """Invoke the tool subprocess with ``input_file`` prepended to ``args``.

        Hex-format inputs are transparently converted to DER via
        ``_prepare_input_for_tool`` before the subprocess is launched.
        Returns a ``SaipCommandResult``; callers inspect ``returncode``
        and ``stdout`` / ``stderr`` directly.
        """
        resolved_input = self.resolve_input_path(str(input_file), must_exist=True)
        if resolved_input.is_dir():
            raise IsADirectoryError(f"Expected a file, got directory: {resolved_input}")

        prepared_input = self._prepare_input_for_tool(resolved_input)
        command = self.get_tool_command()
        command.append(str(prepared_input))
        for arg in args:
            command.append(str(arg))

        completed = self.runner(command)
        return SaipCommandResult(
            command=list(command),
            returncode=int(completed.returncode),
            stdout=str(completed.stdout or ""),
            stderr=str(completed.stderr or ""),
        )

    def build_decoded_dump_document(self, mode: str) -> dict:
        """Decode the current profile package in-process via pySim and return a document dict.

        ``mode`` selects the output shape:
        - ``"all_pe"`` — one section per PE in sequence order.
        - ``"all_pe_by_type"`` — one section per PE type (list of decoded dicts).
        - ``"all_pe_by_naa"`` — grouped by NAA (Network Access Application).

        Raises ``RuntimeError`` when the pySim source tree is not found, or
        ``ValueError`` on parse failure or unsupported mode.
        """
        resolved_input = self.resolve_input_path(str(self.get_input_file()), must_exist=True)
        prepared_input = self._prepare_input_for_tool(resolved_input)
        pysim_dirs = self._pysim_source_dirs()
        if len(pysim_dirs) == 0:
            raise RuntimeError(
                "Local pySim source tree not found under workspace, bundle root, or module root."
            )
        pysim_root = pysim_dirs[0]

        pysim_root_text = str(pysim_root)
        if pysim_root_text not in sys.path:
            sys.path.insert(0, pysim_root_text)

        from pySim.esim.saip import ProfileElementSequence

        try:
            pes = ProfileElementSequence.from_der(prepared_input.read_bytes())
        except Exception as error:
            detail = _describe_exception_chain(error)
            raise ValueError(
                f"Profile decode failed for {resolved_input}: {detail}"
            ) from error
        document: dict[str, object] = {
            "intro": [f"Read {len(pes.pe_list)} PEs from file '{prepared_input}'"],
            "sections": {},
        }
        sections: dict[str, object] = {}
        counts: dict[str, int] = {}

        def unique_key(base_key: str) -> str:
            """Return a de-duplicated key string for use in the SAIP tool's internal PE map."""
            key_text = str(base_key or "section").strip() or "section"
            current_count = counts.get(key_text, 0) + 1
            counts[key_text] = current_count
            if current_count == 1:
                return key_text
            return f"{key_text}_{current_count}"

        if mode == "all_pe":
            for pe in pes:
                sections[unique_key(pe.type)] = pe.decoded
        elif mode == "all_pe_by_type":
            for pe_type, pe_list in pes.pe_by_type.items():
                sections[unique_key(pe_type)] = [pe.decoded for pe in pe_list]
        elif mode == "all_pe_by_naa":
            for naa_name, naa_instances in pes.pes_by_naa.items():
                for index, naa_instance in enumerate(naa_instances):
                    sections[unique_key(f"{naa_name}{index}")] = [
                        {
                            "type": pe.type,
                            "decoded": pe.decoded,
                        }
                        for pe in naa_instance
                    ]
        else:
            raise ValueError(f"Unsupported decoded dump mode: {mode}")

        document["sections"] = sections
        return document

    def normalize_raw_arguments(self, tokens: Sequence[str]) -> list[str]:
        """Resolve workspace-relative paths embedded in ``--flag=<path>`` tokens.

        Flags listed in ``_RAW_INPUT_PATH_FLAGS`` have their value portion
        resolved via ``resolve_input_path`` (when ``must_exist=True``) or
        ``resolve_workspace_path`` (when ``must_exist=False``).  All other
        tokens are forwarded unchanged.
        """
        normalized: list[str] = []
        index = 0
        while index < len(tokens):
            token = str(tokens[index])
            if "=" in token:
                flag_name, raw_value = token.split("=", 1)
                if flag_name in self._RAW_INPUT_PATH_FLAGS:
                    must_exist = self._RAW_INPUT_PATH_FLAGS[flag_name]
                    resolver = self.resolve_input_path
                    if must_exist is False:
                        resolver = self.resolve_workspace_path
                    resolved_path = resolver(raw_value, must_exist=must_exist)
                    normalized.append(f"{flag_name}={resolved_path}")
                else:
                    normalized.append(token)
                index += 1
                continue

            normalized.append(token)
            if token in self._RAW_INPUT_PATH_FLAGS:
                must_exist = self._RAW_INPUT_PATH_FLAGS[token]
                next_index = index + 1
                if next_index >= len(tokens):
                    raise ValueError(f"Missing value for {token}.")
                resolver = self.resolve_input_path
                if must_exist is False:
                    resolver = self.resolve_workspace_path
                resolved_path = resolver(str(tokens[next_index]), must_exist=must_exist)
                normalized.append(str(resolved_path))
                index += 2
                continue

            index += 1

        return normalized

    def _pysim_source_dirs(self) -> list[Path]:
        """Directories that contain the `pySim` package (optional on-disk checkouts under .../pysim)."""
        roots: list[Path] = []
        seen: set[Path] = set()
        for base in (self.workspace_root, self.bundle_root, _repo_root_from_saip_module()):
            candidate = (base / "pysim").resolve()
            if candidate.is_dir() is False:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            roots.append(candidate)
        return roots

    def _subprocess_env_with_pysim(self) -> dict[str, str]:
        env = dict(os.environ)
        pysim_dirs = self._pysim_source_dirs()
        if len(pysim_dirs) == 0:
            return env
        prepend = os.pathsep.join(str(item) for item in pysim_dirs)
        existing = str(env.get("PYTHONPATH", "") or "").strip()
        if len(existing) == 0:
            env["PYTHONPATH"] = prepend
            return env
        parts = existing.split(os.pathsep)
        filtered = [item for item in pysim_dirs if str(item) not in parts]
        if len(filtered) == 0:
            return env
        extra = os.pathsep.join(str(item) for item in filtered)
        env["PYTHONPATH"] = extra + os.pathsep + existing
        return env

    def _run_subprocess(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        normalized_command = list(command)
        try:
            return subprocess.run(
                normalized_command,
                check=False,
                capture_output=True,
                text=True,
                env=self._subprocess_env_with_pysim(),
                timeout=self.command_timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            stdout_text = getattr(error, "stdout", None)
            if stdout_text is None:
                stdout_text = getattr(error, "output", "")
            stderr_text = getattr(error, "stderr", "")
            if isinstance(stdout_text, bytes):
                stdout_text = stdout_text.decode("utf-8", "replace")
            if isinstance(stderr_text, bytes):
                stderr_text = stderr_text.decode("utf-8", "replace")
            timeout_message = (
                f"saip-tool timed out after {self.command_timeout_seconds}s while "
                "decoding or processing the profile."
            )
            detail = _describe_exception_chain(error)
            if len(detail) > 0:
                timeout_message += f" {detail}"
            if len(str(stderr_text).strip()) > 0:
                timeout_message += f"\n{str(stderr_text).strip()}"
            return subprocess.CompletedProcess(
                normalized_command,
                124,
                stdout=str(stdout_text),
                stderr=timeout_message,
            )

    def _prepare_input_for_tool(self, resolved_input: Path) -> Path:
        if resolved_input.suffix.lower() not in self._HEX_INPUT_SUFFIXES:
            return resolved_input

        text_payload = resolved_input.read_text(encoding="utf-8-sig")
        placeholder_records: list[InlinePlaceholderRecord] = []
        if detect_inline_placeholders(text_payload):
            substituted_text, placeholder_records = substitute_inline_placeholders(
                text_payload
            )
            normalized_hex = "".join(substituted_text.split()).upper()
        else:
            normalized_hex = "".join(text_payload.split()).upper()

        if len(normalized_hex) == 0:
            raise ValueError(f"Hex input file is empty: {resolved_input}")

        for character in normalized_hex:
            if character not in "0123456789ABCDEF":
                self._raise_hex_input_error(resolved_input, text_payload)

        if len(normalized_hex) % 2 != 0:
            raise ValueError(f"Hex input file has odd-length payload: {resolved_input}")

        binary_payload = bytes.fromhex(normalized_hex)
        cache_dir = self.workspace_root / ".profilepackage-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(resolved_input.as_posix().encode("utf-8") + binary_payload).hexdigest()
        cache_path = cache_dir / f"{resolved_input.stem}-{digest[:16]}.der"
        cache_path.write_bytes(binary_payload)
        sidecar_path = sidecar_path_for_cache(cache_path)
        if len(placeholder_records) > 0:
            write_sidecar(sidecar_path, placeholder_records)
        else:
            try:
                sidecar_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
        _prune_profile_package_cache(cache_dir, keep=cache_path)
        return cache_path

    @staticmethod
    def _raise_hex_input_error(resolved_input: Path, raw_text: str) -> None:
        """Emit a context-aware error when a hex input won't parse.

        Distinguishes three cases so the operator gets actionable
        guidance instead of a bare "non-hex characters" line:

        * Inline typed placeholders still present after substitution
          (means :func:`substitute_inline_placeholders` missed a shape
          variant; surface the offending literals so the user can
          report them).
        * YggdraSIM-native ``{NAME}`` / ``[NAME]`` placeholders present
          (means the file is a JSON-style template mis-saved as hex
          text — point at ``APPLY-TEMPLATE``).
        * Anything else: the historical terse diagnostic.
        """
        typed_matches = [match.group(0) for match in iter_inline_placeholders(raw_text)]
        if len(typed_matches) > 0:
            preview = ", ".join(sorted(set(typed_matches))[:4])
            raise ValueError(
                f"Hex input file contains inline typed placeholders that did not "
                f"substitute cleanly ({preview}): {resolved_input}. "
                f"Remove the placeholders or report the template shape as a bug."
            )

        simple_placeholder = re.search(
            r"\{#?[A-Za-z][A-Za-z0-9_]*\}|\[#?[A-Za-z][A-Za-z0-9_]*\]",
            raw_text,
        )
        if simple_placeholder is not None:
            raise ValueError(
                f"Hex input file carries YggdraSIM-style placeholders "
                f"({simple_placeholder.group(0)}): {resolved_input}. "
                f"Use APPLY-TEMPLATE <template.json> <out.der> to materialise the "
                f"profile before opening it as raw hex."
            )

        raise ValueError(
            f"Hex input file contains non-hex characters: {resolved_input}"
        )

    def _is_within_workspace(self, resolved_path: Path) -> bool:
        try:
            resolved_path.relative_to(self.workspace_root)
        except ValueError:
            return False
        return True

    def _load_config(self) -> None:
        if self.config_path.exists() is False:
            return

        try:
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except OSError:
            return
        except (json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            self._quarantine_corrupt_config(decode_error)
            return

        profile_dir_value = str(payload.get("default_profile_dir", "")).strip()
        if len(profile_dir_value) > 0:
            try:
                self.default_profile_dir = self.resolve_workspace_path(profile_dir_value, must_exist=False)
            except (OSError, ValueError):
                pass

        transcode_dir_value = str(payload.get("default_transcode_dir", "")).strip()
        if len(transcode_dir_value) > 0:
            try:
                self.default_transcode_dir = self.resolve_workspace_path(
                    transcode_dir_value, must_exist=False
                )
            except (OSError, ValueError):
                pass

        last_input_open_directory_value = str(payload.get("last_input_open_directory", "")).strip()
        if len(last_input_open_directory_value) > 0:
            try:
                configured_directory = Path(last_input_open_directory_value).expanduser()
                if configured_directory.is_absolute() is False:
                    configured_directory = self.workspace_root / configured_directory
                configured_directory = configured_directory.resolve()
                self.last_input_open_directory = configured_directory
            except (OSError, ValueError, RuntimeError):
                pass

    def _quarantine_corrupt_config(
        self,
        decode_error: json.JSONDecodeError | UnicodeDecodeError,
    ) -> None:
        """Rename a corrupt saip_tool.json aside so operators keep their edit.

        Historical behaviour silently discarded the file and started with
        defaults, which hid hand-edit mistakes (unbalanced braces, stray
        comment, truncated copy/paste). The sidecar preserves the source
        material and we note the decision on stderr. Consistent with the
        ``inventory_crypto.json`` / ``card_backend.json`` quarantine paths.
        """
        import shutil as _shutil
        import time as _time

        sidecar_path = self.config_path.with_suffix(
            self.config_path.suffix + f".corrupt.{int(_time.time())}"
        )
        try:
            _shutil.move(str(self.config_path), str(sidecar_path))
        except OSError as move_error:
            sys.stderr.write(
                f"[saip-tool] {self.config_path} is corrupt ({decode_error}) "
                f"and could not be renamed aside ({move_error}); defaults "
                "will be used this session.\n"
            )
            return
        sys.stderr.write(
            f"[saip-tool] {self.config_path} was unparseable ({decode_error}); "
            f"moved to {sidecar_path}. Review or restore the file before "
            "relying on saved preferences.\n"
        )

    def _save_config(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            relative_profile_dir = self.default_profile_dir.relative_to(self.workspace_root)
            stored_profile_dir = relative_profile_dir.as_posix()
        except ValueError:
            stored_profile_dir = str(self.default_profile_dir)

        try:
            relative_transcode_dir = self.default_transcode_dir.relative_to(self.workspace_root)
            stored_transcode_dir = relative_transcode_dir.as_posix()
        except ValueError:
            stored_transcode_dir = str(self.default_transcode_dir)

        stored_last_input_open_directory = ""
        if self.last_input_open_directory is not None:
            try:
                relative_last_input_open_directory = self.last_input_open_directory.relative_to(
                    self.workspace_root
                )
                stored_last_input_open_directory = relative_last_input_open_directory.as_posix()
            except ValueError:
                stored_last_input_open_directory = str(self.last_input_open_directory)

        payload = {
            "default_profile_dir": stored_profile_dir,
            "default_transcode_dir": stored_transcode_dir,
            "last_input_open_directory": stored_last_input_open_directory,
        }
        self.config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
