# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Install the Lua dissector into Wireshark's personal plugin folder.

tshark users need none of this -- ``-X lua_script:`` takes a path. The
Wireshark GUI has no equivalent, so the files have to be copied where it
looks.

The destination is read from tshark itself rather than hardcoded per
platform. Wireshark reports its own folder layout, which already accounts
for the differences between Linux, macOS, Windows and Flatpak builds that
a hardcoded table would get wrong.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .tshark_runner import (
    DEFAULT_TSHARK_BINARY,
    DISSECTOR_FILENAME,
    TsharkMissingError,
    ensure_tshark_on_path,
    lua_directory,
)

PLUGIN_SUBDIRECTORY = "yggdrasim-apdu"
PERSONAL_LUA_LABEL = "Personal Lua Plugins"


class InstallError(RuntimeError):
    """Raised when the dissector cannot be installed."""


@dataclass(frozen=True)
class InstallPlan:
    """What an install would copy, and to where."""

    destination: Path
    files: tuple[Path, ...]

    def describe(self) -> str:
        lines = [f"destination: {self.destination}"]
        for path in self.files:
            lines.append(f"  {path.name}")
        return "\n".join(lines)


def parse_personal_lua_folder(folders_output: str) -> str:
    """Extract the personal Lua plugin path from ``tshark -G folders``.

    Rows are tab-separated ``label\\tpath``, but the label carries a
    trailing colon and is space-padded for alignment, so it is stripped
    of both before comparison. Returns ``""`` when the label is absent,
    which is what a build compiled without Lua looks like.
    """
    for line in str(folders_output or "").splitlines():
        if "\t" not in line:
            continue
        label, _, path = line.partition("\t")
        if label.strip().rstrip(":").strip() == PERSONAL_LUA_LABEL:
            return path.strip()
    return ""


def resolve_destination(
    *,
    tshark_binary: str = DEFAULT_TSHARK_BINARY,
    override: Path | None = None,
) -> Path:
    """Return the directory the Lua tree should be copied into."""
    if override is not None:
        return Path(override).expanduser().resolve() / PLUGIN_SUBDIRECTORY
    binary = ensure_tshark_on_path(tshark_binary)
    try:
        completed = subprocess.run(
            [binary, "-G", "folders"],
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InstallError(f"could not ask tshark for its folders: {error}") from error
    folder = parse_personal_lua_folder(completed.stdout)
    if not folder:
        raise InstallError(
            "tshark did not report a personal Lua plugin folder. The build "
            "may have been compiled without Lua support; check `tshark -v`."
        )
    return Path(folder).expanduser().resolve() / PLUGIN_SUBDIRECTORY


def build_plan(
    *,
    tshark_binary: str = DEFAULT_TSHARK_BINARY,
    override: Path | None = None,
    module_dir: Path | None = None,
) -> InstallPlan:
    """Work out what would be copied without copying anything."""
    source = lua_directory(module_dir)
    entry_point = source / DISSECTOR_FILENAME
    if not entry_point.is_file():
        raise InstallError(f"the bundled dissector is missing: {entry_point}")
    files = sorted(path for path in source.rglob("*.lua") if path.is_file())
    # The environment probe is a diagnostic, not part of the dissector.
    files = tuple(path for path in files if path.name != "probe_wireshark_env.lua")
    return InstallPlan(
        destination=resolve_destination(
            tshark_binary=tshark_binary, override=override
        ),
        files=files,
    )


def install(
    *,
    tshark_binary: str = DEFAULT_TSHARK_BINARY,
    override: Path | None = None,
    module_dir: Path | None = None,
) -> InstallPlan:
    """Copy the Lua tree into Wireshark's plugin folder."""
    plan = build_plan(
        tshark_binary=tshark_binary, override=override, module_dir=module_dir
    )
    source = lua_directory(module_dir)
    try:
        plan.destination.mkdir(parents=True, exist_ok=True)
        for path in plan.files:
            relative = path.relative_to(source)
            target = plan.destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o644)
    except OSError as error:
        raise InstallError(f"could not install the dissector: {error}") from error
    return plan


def uninstall(
    *,
    tshark_binary: str = DEFAULT_TSHARK_BINARY,
    override: Path | None = None,
) -> Path:
    """Remove a previously installed copy."""
    destination = resolve_destination(
        tshark_binary=tshark_binary, override=override
    )
    if destination.is_dir():
        try:
            shutil.rmtree(destination)
        except OSError as error:
            raise InstallError(f"could not remove {destination}: {error}") from error
    return destination


__all__ = [
    "InstallError",
    "InstallPlan",
    "TsharkMissingError",
    "build_plan",
    "install",
    "parse_personal_lua_folder",
    "resolve_destination",
    "uninstall",
]
