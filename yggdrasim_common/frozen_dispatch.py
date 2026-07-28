# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Safe child-process commands for source and frozen YggdraSIM runtimes.

``sys.executable`` is a Python interpreter in a source installation, but it is
the application executable in a PyInstaller bundle.  Passing ``-m``, ``-c``,
or a Python script to the latter either relaunches the normal application or
fails in platform-specific ways.

Frozen children therefore re-enter the application through one private
sentinel and an explicit entry allow-list.  This module deliberately has no
generic "run this module", "run this code", or "run this script" operation.
Source mode retains the normal Python commands after resolving the intended
interpreter.
"""

from __future__ import annotations

import importlib
import os
import shutil
import sys
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Sequence, TextIO

from yggdrasim_common.quit_control import QuitAllRequested
from yggdrasim_common.runtime_paths import is_frozen

INTERNAL_ENTRY_FLAG = "--yggdrasim-internal-entry"
INTERNAL_ARGUMENT_SEPARATOR = "--"

_MAX_INTERNAL_ARGUMENTS = 4096
_MAX_INTERNAL_ARGUMENT_CHARS = 64 * 1024
_MAX_PICKER_FIELD_CHARS = 16 * 1024


class InternalDispatchError(RuntimeError):
    """Raised when a frozen-entry request violates the dispatch contract."""


@dataclass(frozen=True, slots=True)
class _CallableEntry:
    module: str
    attribute: str
    program_name: str


_CALLABLE_ENTRIES: Mapping[str, _CallableEntry] = MappingProxyType(
    {
        "cli-scp03": _CallableEntry("SCP03.main", "run_standalone", "SCP03"),
        "cli-scp80": _CallableEntry("SCP80.main", "run_standalone", "SCP80"),
        "cli-scp11": _CallableEntry("SCP11.main", "entry", "SCP11"),
        "cli-scp11-live": _CallableEntry(
            "SCP11.live.main",
            "entry",
            "SCP11.live",
        ),
        "cli-scp11-relay": _CallableEntry(
            "SCP11.relay.main",
            "entry",
            "SCP11.relay",
        ),
        "cli-scp11-local-access": _CallableEntry(
            "SCP11.local_access.main",
            "run_standalone",
            "SCP11.local_access",
        ),
        "cli-scp11-eim-local": _CallableEntry(
            "SCP11.eim_local.main",
            "run_standalone",
            "SCP11.eim_local",
        ),
        "card-bridge": _CallableEntry(
            "Tools.CardBridge.server",
            "main",
            "Tools.CardBridge",
        ),
        "profile-package": _CallableEntry(
            "Tools.ProfilePackage.main",
            "run_standalone",
            "Tools.ProfilePackage",
        ),
        "suci-tool": _CallableEntry(
            "Tools.SuciTool.main",
            "run_standalone",
            "Tools.SuciTool",
        ),
        "hil-bridge": _CallableEntry(
            "Tools.HilBridge.main",
            "run_standalone",
            "Tools.HilBridge.main",
        ),
        "hil-supervisor": _CallableEntry(
            "Tools.HilBridge.supervisor",
            "run_standalone",
            "Tools.HilBridge.supervisor",
        ),
        "hil-reset": _CallableEntry(
            "Tools.HilBridge.device_reset",
            "run_standalone",
            "Tools.HilBridge.device_reset",
        ),
    }
)

_MODULE_ENTRY_IDS: Mapping[str, str] = MappingProxyType(
    {
        "SCP03": "cli-scp03",
        "SCP80": "cli-scp80",
        "SCP11": "cli-scp11",
        "SCP11.live": "cli-scp11-live",
        "SCP11.relay": "cli-scp11-relay",
        "SCP11.local_access": "cli-scp11-local-access",
        "SCP11.eim_local": "cli-scp11-eim-local",
        "Tools.CardBridge": "card-bridge",
        "Tools.CardBridge.server": "card-bridge",
        "Tools.ProfilePackage": "profile-package",
        "Tools.SuciTool": "suci-tool",
        "Tools.HilBridge.main": "hil-bridge",
        "Tools.HilBridge.supervisor": "hil-supervisor",
        "Tools.HilBridge.device_reset": "hil-reset",
    }
)

_SPECIAL_ENTRY_IDS = frozenset({"tk-open-file", "profile-saip-tool"})
_ALLOWED_ENTRY_IDS = frozenset(_CALLABLE_ENTRIES) | _SPECIAL_ENTRY_IDS

_TK_OPEN_FILE_SOURCE = (
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


def _paired_application_launcher(
    launcher: str | os.PathLike[str],
) -> Path | None:
    """Return the expected GUI/console companion path for a frozen binary."""
    candidate = Path(str(launcher or "").strip()).expanduser().absolute()
    filename = candidate.name
    executable_suffix = ".exe" if filename.lower().endswith(".exe") else ""
    stem = filename[: -len(executable_suffix)] if executable_suffix else filename
    stem_lower = stem.lower()
    gui_prefix = "yggdrasim-gui"
    cli_prefix = "yggdrasim"
    if stem_lower.startswith(gui_prefix):
        companion_stem = cli_prefix + stem[len(gui_prefix) :]
    elif stem_lower.startswith(cli_prefix):
        companion_stem = gui_prefix + stem[len(cli_prefix) :]
    else:
        return None
    return candidate.with_name(companion_stem + executable_suffix)


def resolve_internal_launcher(
    launcher_executable: str | os.PathLike[str] | None = None,
) -> str:
    """Resolve the executable used for one allow-listed child re-entry.

    Frozen distributions install a console and GUI executable together. When
    called from the windowed executable, prefer its console companion so
    output capture and long-running service logs work on Windows as well as
    POSIX. A standalone/renamed GUI binary safely falls back to itself.
    """
    explicit = launcher_executable is not None
    launcher = str(
        launcher_executable if explicit else sys.executable
    ).strip()
    if len(launcher) == 0 or "\x00" in launcher:
        raise RuntimeError("the frozen application executable is unavailable")
    normalized = Path(
        os.path.abspath(os.path.expandvars(os.path.expanduser(launcher)))
    )
    companion_is_executable = False
    if explicit is False and is_frozen() and normalized.name.lower().startswith(
        "yggdrasim-gui"
    ):
        companion = _paired_application_launcher(normalized)
        if companion is not None and companion.is_file():
            companion_is_executable = (
                os.name == "nt" or os.access(companion, os.X_OK)
            )
        if companion_is_executable:
            normalized = companion
    return str(normalized)


def allowed_module_names() -> tuple[str, ...]:
    """Return the immutable module allow-list used by child launchers."""
    return tuple(_MODULE_ENTRY_IDS)


def internal_entry_id_for_module(module_name: str) -> str:
    """Return the allow-listed internal entry for *module_name*."""
    normalized = str(module_name or "").strip()
    try:
        return _MODULE_ENTRY_IDS[normalized]
    except KeyError as error:
        raise ValueError(
            f"module is not available to the internal child dispatcher: {normalized!r}"
        ) from error


def resolve_source_python(python_executable: str | os.PathLike[str] | None = None) -> str:
    """Resolve the Python interpreter used only by non-frozen source runs."""
    if is_frozen():
        raise RuntimeError("a frozen application is not a Python interpreter")

    explicit = python_executable is not None and len(str(python_executable).strip()) > 0
    candidate = (
        str(python_executable).strip()
        if explicit
        else str(sys.executable or "").strip()
    )
    if len(candidate) == 0:
        raise RuntimeError("the source Python interpreter could not be resolved")

    expanded = os.path.expandvars(os.path.expanduser(candidate))
    has_separator = os.sep in expanded or (
        os.altsep is not None and os.altsep in expanded
    )
    if os.path.isabs(expanded) or has_separator:
        resolved = os.path.abspath(expanded)
    else:
        discovered = shutil.which(expanded)
        if discovered is None:
            if explicit:
                raise RuntimeError(
                    f"configured source Python interpreter was not found: {candidate}"
                )
            raise RuntimeError("the source Python interpreter was not found on PATH")
        resolved = os.path.abspath(discovered)

    # Explicit absolute paths are sometimes rendered into a service file before
    # that target environment is installed.  Preserve that existing source-mode
    # workflow, while requiring the live default interpreter to be a real file.
    if explicit is False and os.path.isfile(resolved) is False:
        raise RuntimeError(f"source Python interpreter does not exist: {resolved}")
    return resolved


def launcher_targets_application_bundle(
    launcher: str | os.PathLike[str],
) -> bool:
    """Return whether *launcher* resolves to this frozen application pair.

    Text comparison catches the normal case. ``samefile`` also closes the
    hard-link/symlink alias case. The paired GUI/console executable is also
    included so neither binary can be disguised as a Python interpreter.
    """
    requested_text = str(launcher or "").strip()
    current_text = str(sys.executable or "").strip()
    if len(requested_text) == 0 or len(current_text) == 0:
        return False

    requested_text = os.path.expandvars(os.path.expanduser(requested_text))
    has_separator = os.sep in requested_text or (
        os.altsep is not None and os.altsep in requested_text
    )
    if os.path.isabs(requested_text) is False and has_separator is False:
        requested_text = shutil.which(requested_text) or requested_text

    requested_path = os.path.normcase(os.path.abspath(requested_text))
    current_path = os.path.normcase(os.path.abspath(current_text))
    application_paths = [current_path]
    companion = _paired_application_launcher(current_path)
    if companion is not None:
        application_paths.append(
            os.path.normcase(os.path.abspath(str(companion)))
        )
    for application_path in application_paths:
        if requested_path == application_path:
            return True
        try:
            if os.path.samefile(requested_path, application_path):
                return True
        except (OSError, ValueError):
            continue
    return False


def _normalize_arguments(arguments: Sequence[object]) -> list[str]:
    if len(arguments) > _MAX_INTERNAL_ARGUMENTS:
        raise ValueError(
            f"too many child arguments ({len(arguments)} > {_MAX_INTERNAL_ARGUMENTS})"
        )
    normalized: list[str] = []
    total_chars = 0
    for raw_argument in arguments:
        argument = str(raw_argument)
        if "\x00" in argument:
            raise ValueError("child arguments cannot contain NUL bytes")
        total_chars += len(argument)
        if total_chars > _MAX_INTERNAL_ARGUMENT_CHARS:
            raise ValueError("child argument payload is too large")
        normalized.append(argument)
    return normalized


def build_internal_command(
    entry_id: str,
    arguments: Sequence[object] = (),
    *,
    launcher_executable: str | os.PathLike[str] | None = None,
) -> list[str]:
    """Build a strict application re-entry command for one named capability."""
    normalized_entry = str(entry_id or "").strip()
    if normalized_entry not in _ALLOWED_ENTRY_IDS:
        raise ValueError(f"internal entry is not allow-listed: {normalized_entry!r}")
    launcher = resolve_internal_launcher(launcher_executable)
    return [
        launcher,
        INTERNAL_ENTRY_FLAG,
        normalized_entry,
        INTERNAL_ARGUMENT_SEPARATOR,
        *_normalize_arguments(arguments),
    ]


def build_module_command(
    module_name: str,
    arguments: Sequence[object] = (),
    *,
    source_python: str | os.PathLike[str] | None = None,
) -> list[str]:
    """Build a source ``python -m`` or frozen allow-listed re-entry command."""
    normalized_module = str(module_name or "").strip()
    entry_id = internal_entry_id_for_module(normalized_module)
    normalized_arguments = _normalize_arguments(arguments)
    if is_frozen():
        return build_internal_command(entry_id, normalized_arguments)
    return [
        resolve_source_python(source_python),
        "-m",
        normalized_module,
        *normalized_arguments,
    ]


def build_tk_file_picker_command(
    *,
    title: str,
    initial_directory: str | os.PathLike[str],
    file_filter_label: str,
    file_filter_glob: str,
) -> list[str]:
    """Build the fixed Tk open-file helper without exposing arbitrary ``-c``."""
    picker_arguments = [
        str(title),
        str(initial_directory),
        str(file_filter_label),
        str(file_filter_glob),
    ]
    if any(len(value) > _MAX_PICKER_FIELD_CHARS for value in picker_arguments):
        raise ValueError("file-picker argument is too large")
    normalized_arguments = _normalize_arguments(picker_arguments)
    if is_frozen():
        return build_internal_command("tk-open-file", normalized_arguments)
    return [
        resolve_source_python(),
        "-c",
        _TK_OPEN_FILE_SOURCE,
        *normalized_arguments,
    ]


def build_pysim_saip_tool_command(
    script_path: str | os.PathLike[str],
) -> list[str]:
    """Build a source pySim script command or the frozen tracked adapter.

    Frozen builds never execute the script path. They dispatch to the
    repo-owned adapter over installed pySim APIs.
    """
    candidate = Path(script_path).expanduser().resolve()
    if tuple(candidate.parts[-3:]) != ("pysim", "contrib", "saip-tool.py"):
        raise ValueError("only the bundled pySim contrib/saip-tool.py is supported")
    if candidate.is_file() is False:
        raise FileNotFoundError(candidate)
    if is_frozen():
        return build_internal_command("profile-saip-tool")
    return [resolve_source_python(), str(candidate)]


def build_profile_saip_tool_command() -> list[str]:
    """Build the tracked SAIP adapter command for source or frozen mode."""
    if is_frozen():
        return build_internal_command("profile-saip-tool")
    return [
        resolve_source_python(),
        "-m",
        "Tools.ProfilePackage.saip_cli_adapter",
    ]


def hidden_window_subprocess_kwargs() -> dict[str, int]:
    """Suppress helper console windows in a native Windows GUI process."""
    if os.name != "nt":
        return {}
    import subprocess

    creation_flag = int(getattr(subprocess, "CREATE_NO_WINDOW", 0) or 0)
    if creation_flag == 0:
        return {}
    return {"creationflags": creation_flag}


def command_targets_internal_entry(command: Sequence[object], entry_id: str) -> bool:
    """Return whether *command* is a well-formed invocation of *entry_id*."""
    normalized_entry = str(entry_id or "").strip()
    if normalized_entry not in _ALLOWED_ENTRY_IDS:
        return False
    parts = [str(part) for part in command]
    return (
        len(parts) >= 4
        and parts[1] == INTERNAL_ENTRY_FLAG
        and parts[2] == normalized_entry
        and parts[3] == INTERNAL_ARGUMENT_SEPARATOR
    )


def _normalize_exit_code(code: object) -> int:
    if code is None:
        return 0
    if isinstance(code, bool):
        return int(code)
    if isinstance(code, int):
        return int(code)
    return 1


def _invoke_callable_entry(entry: _CallableEntry) -> int:
    module = importlib.import_module(entry.module)
    target: Callable[[], object] = getattr(module, entry.attribute)
    result = target()
    return _normalize_exit_code(result)


def _invoke_tk_open_file(arguments: Sequence[str]) -> int:
    if len(arguments) != 4:
        raise InternalDispatchError("tk-open-file requires exactly four arguments")
    title, initial_directory, file_filter_label, file_filter_glob = arguments
    if any(
        len(value) > _MAX_PICKER_FIELD_CHARS
        for value in (title, initial_directory, file_filter_label, file_filter_glob)
    ):
        raise InternalDispatchError("file-picker argument is too large")
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError as error:
        raise InternalDispatchError("Tk file-picker support is unavailable") from error

    try:
        root = tk.Tk()
    except Exception as error:
        raise InternalDispatchError(
            f"Tk file-picker initialization failed: {error}"
        ) from error
    try:
        try:
            root.withdraw()
            selected = filedialog.askopenfilename(
                title=title,
                initialdir=initial_directory,
                filetypes=[
                    (file_filter_label, file_filter_glob),
                    ("All files", "*"),
                ],
            )
            root.update()
        except Exception as error:
            raise InternalDispatchError(
                f"Tk file-picker request failed: {error}"
            ) from error
    finally:
        root.destroy()
    print(str(selected or ""))
    return 0


def _invoke_profile_saip_tool(arguments: Sequence[str]) -> int:
    from Tools.ProfilePackage.saip_cli_adapter import run_cli

    return int(run_cli(arguments))


def _install_missing_standard_streams() -> list[tuple[str, TextIO]]:
    """Repair ``pythonw``/PyInstaller windowed streams for internal children."""
    replacements: list[tuple[str, TextIO]] = []
    for attribute, descriptor, mode in (
        ("stdin", 0, "r"),
        ("stdout", 1, "w"),
        ("stderr", 2, "w"),
    ):
        if getattr(sys, attribute, None) is not None:
            continue
        try:
            stream = open(
                descriptor,
                mode,
                encoding="utf-8",
                errors="replace",
                buffering=1,
                closefd=False,
            )
        except (OSError, ValueError):
            stream = open(
                os.devnull,
                mode,
                encoding="utf-8",
                errors="replace",
                buffering=1,
            )
        setattr(sys, attribute, stream)
        replacements.append((attribute, stream))
    return replacements


def _restore_standard_streams(
    replacements: Sequence[tuple[str, TextIO]],
) -> None:
    for attribute, stream in reversed(replacements):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass
        setattr(sys, attribute, None)
        try:
            stream.close()
        except OSError:
            pass


def _dispatch(entry_id: str, arguments: Sequence[str]) -> int:
    entry = _CALLABLE_ENTRIES.get(entry_id)
    if entry is not None:
        program_name = entry.program_name
        handler: Callable[[], int] = partial(_invoke_callable_entry, entry)
    elif entry_id == "tk-open-file":
        program_name = "yggdrasim-tk-open-file"
        handler = partial(_invoke_tk_open_file, arguments)
    elif entry_id == "profile-saip-tool":
        program_name = "yggdrasim-saip-tool"
        handler = partial(_invoke_profile_saip_tool, arguments)
    else:
        raise InternalDispatchError(f"unknown internal entry: {entry_id!r}")

    previous_argv = sys.argv
    sys.argv = [program_name, *arguments]
    try:
        try:
            return handler()
        except QuitAllRequested:
            return 0
        except SystemExit as exit_request:
            return _normalize_exit_code(exit_request.code)
        except KeyboardInterrupt:
            return 130
    finally:
        sys.argv = previous_argv


def dispatch_internal_entry(
    argv: Sequence[str] | None = None,
    *,
    stderr: TextIO | None = None,
) -> int | None:
    """Dispatch a private child invocation, or return ``None`` for normal CLI.

    The sentinel must be the first argument and the separator is mandatory.
    Unknown entry names are rejected without importing attacker-selected
    modules or evaluating attacker-selected Python.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) == 0 or arguments[0] != INTERNAL_ENTRY_FLAG:
        return None
    stream_replacements = _install_missing_standard_streams()
    error_stream = stderr if stderr is not None else sys.stderr
    try:
        try:
            if (
                len(arguments) < 3
                or arguments[2] != INTERNAL_ARGUMENT_SEPARATOR
            ):
                raise InternalDispatchError("malformed internal-entry command")
            entry_id = str(arguments[1] or "").strip()
            if entry_id not in _ALLOWED_ENTRY_IDS:
                raise InternalDispatchError(
                    f"internal entry is not allow-listed: {entry_id!r}"
                )
            child_arguments = _normalize_arguments(arguments[3:])
            return _dispatch(entry_id, child_arguments)
        except Exception as error:
            error_stream.write(
                f"yggdrasim internal child launch failed: "
                f"{type(error).__name__}: {error}\n"
            )
            return 3
    finally:
        _restore_standard_streams(stream_replacements)


__all__ = [
    "INTERNAL_ARGUMENT_SEPARATOR",
    "INTERNAL_ENTRY_FLAG",
    "InternalDispatchError",
    "allowed_module_names",
    "build_internal_command",
    "build_module_command",
    "build_profile_saip_tool_command",
    "build_pysim_saip_tool_command",
    "build_tk_file_picker_command",
    "command_targets_internal_entry",
    "dispatch_internal_entry",
    "hidden_window_subprocess_kwargs",
    "internal_entry_id_for_module",
    "launcher_targets_application_bundle",
    "resolve_source_python",
    "resolve_internal_launcher",
]
