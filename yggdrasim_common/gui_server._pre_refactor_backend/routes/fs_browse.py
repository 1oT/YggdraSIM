# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""``/api/fs/browse`` — read-only filesystem listing for the in-browser picker.

Background
----------

When YggdraSIM runs in ``--gui`` (pywebview) mode the SPA delegates path
selection to the OS-native file dialogs through ``window.pywebview.api``.
In ``--web-server`` / plain-browser mode that bridge is absent — operators
saw the placeholder ``window.prompt`` text input ("Path to file (no native
picker available)") which is unusable for anything beyond a hand-typed
absolute path.

This module exposes a tiny read-only listing API the SPA's fallback file
picker can drive: enumerate one directory at a time, surface entries
classified by kind (``dir`` / ``file`` / ``symlink``) plus size /
modification time, and let the operator drill down or jump to a known
"shortcut" location (home, workspace, cwd, common ``Downloads`` /
``Documents`` etc.) without having to hand-paste paths.

Security posture
----------------

The endpoint is intentionally read-only. It does not:

  * read file contents,
  * follow symlinks across mount points (we report ``symlink_to`` but the
    operator picks the link itself, not its dereferenced target),
  * accept path components such as ``..`` after canonicalisation.

It does *not* enforce a sandbox boundary — the GUI server runs as the
operator, the SPA token is required for every request, and the operator
already has the same filesystem rights via shell. The point is to mirror
what they could do with ``ls`` from the same terminal, not to elevate
privilege. Errors (permission denied, missing path, broken symlinks)
are surfaced in the response payload rather than as 500s so the UI can
render an inline status line and still let the operator navigate
elsewhere.
"""

from __future__ import annotations

import logging
import os
import platform
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel


_LOGGER = logging.getLogger("yggdrasim.gui.fs_browse")


router = APIRouter(prefix="/api/fs", tags=["fs"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FsEntry(BaseModel):
    """One row of a directory listing."""

    name: str
    path: str
    kind: str  # "dir" | "file" | "symlink" | "other"
    size: int = 0
    mtime: float = 0.0
    hidden: bool = False
    symlink_target: str | None = None
    error: str | None = None


class FsShortcut(BaseModel):
    """A "jump to" location surfaced in the picker sidebar."""

    id: str
    label: str
    path: str
    available: bool


class FsBrowseResponse(BaseModel):
    """Single-directory listing payload consumed by the SPA picker."""

    path: str
    parent: str | None
    entries: list[FsEntry]
    shortcuts: list[FsShortcut]
    error: str | None = None
    drives: list[str] = []
    separator: str = "/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ShortcutSpec:
    """Static description of a jump-to location.

    Resolved to a real path only when the request comes in so PyInstaller-
    frozen builds and source checkouts both pick up the right roots
    without baking the path at import time.
    """

    sid: str
    label: str
    resolver: Any  # callable → Path | None


def _shortcut_home() -> Path | None:
    try:
        return Path.home().resolve()
    except (OSError, RuntimeError):
        return None


def _shortcut_cwd() -> Path | None:
    try:
        return Path.cwd().resolve()
    except OSError:
        return None


def _shortcut_workspace() -> Path | None:
    try:
        from yggdrasim_common.runtime_paths import bundle_path
    except Exception:
        return None
    try:
        return Path(bundle_path()).resolve()
    except (OSError, RuntimeError):
        return None


def _shortcut_under_home(*parts: str) -> Path | None:
    home = _shortcut_home()
    if home is None:
        return None
    candidate = home.joinpath(*parts)
    try:
        candidate = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    if not candidate.is_dir():
        return None
    return candidate


_SHORTCUT_SPECS: tuple[_ShortcutSpec, ...] = (
    _ShortcutSpec("home", "Home", _shortcut_home),
    _ShortcutSpec("cwd", "Working dir", _shortcut_cwd),
    _ShortcutSpec("workspace", "Workspace", _shortcut_workspace),
    _ShortcutSpec(
        "documents", "Documents",
        lambda: _shortcut_under_home("Documents"),
    ),
    _ShortcutSpec(
        "downloads", "Downloads",
        lambda: _shortcut_under_home("Downloads"),
    ),
    _ShortcutSpec(
        "desktop", "Desktop",
        lambda: _shortcut_under_home("Desktop"),
    ),
)


def _build_shortcuts() -> list[FsShortcut]:
    rows: list[FsShortcut] = []
    for spec in _SHORTCUT_SPECS:
        try:
            resolved = spec.resolver()
        except Exception:  # noqa: BLE001 — never fail the whole listing
            resolved = None
        if resolved is None:
            rows.append(FsShortcut(
                id=spec.sid, label=spec.label, path="", available=False,
            ))
            continue
        rows.append(FsShortcut(
            id=spec.sid,
            label=spec.label,
            path=str(resolved),
            available=True,
        ))
    # NOTE: we deliberately keep duplicate-path entries (e.g. "Working
    # dir" and "Workspace" landing on the same directory in a source
    # checkout) so the sidebar layout is stable across builds — having
    # both buttons point to the same path is mildly informative and
    # cheap; collapsing them would make the sidebar shift around in
    # confusing ways depending on where the operator launched the
    # suite from.
    return rows


def _windows_drives() -> list[str]:
    """Return drive roots ("C:\\", "D:\\", ...) on Windows."""

    if platform.system() != "Windows":
        return []
    drives: list[str] = []
    for letter in string.ascii_uppercase:
        candidate = f"{letter}:\\"
        if os.path.isdir(candidate):
            drives.append(candidate)
    return drives


def _resolve_request_path(raw: str) -> Path:
    """Canonicalise *raw* to an absolute resolved Path.

    Empty / blank input falls back to the operator's home directory so
    the UI has a sensible "first open" state. Relative paths resolve
    against the GUI server's CWD (matches operator expectations from
    the shell that launched the suite).
    """

    text = (raw or "").strip()
    if len(text) == 0:
        home = _shortcut_home()
        if home is not None:
            return home
        return Path("/").resolve()
    expanded = os.path.expanduser(os.path.expandvars(text))
    candidate = Path(expanded)
    if not candidate.is_absolute():
        candidate = (Path.cwd() / candidate)
    return candidate.resolve()


def _classify_kind(entry: os.DirEntry) -> str:
    try:
        if entry.is_symlink():
            return "symlink"
    except OSError:
        return "other"
    try:
        if entry.is_dir(follow_symlinks=False):
            return "dir"
    except OSError:
        pass
    try:
        if entry.is_file(follow_symlinks=False):
            return "file"
    except OSError:
        pass
    return "other"


def _entry_payload(entry: os.DirEntry) -> FsEntry:
    name = entry.name
    is_hidden = name.startswith(".")
    kind = _classify_kind(entry)
    size = 0
    mtime = 0.0
    err: str | None = None
    target: str | None = None
    try:
        stat = entry.stat(follow_symlinks=True)
        size = int(stat.st_size)
        mtime = float(stat.st_mtime)
    except OSError as error:
        err = str(error)
    if kind == "symlink":
        try:
            target = os.readlink(entry.path)
            # If the symlink points to a directory we still want the
            # navigator to treat the *link* as a directory entry so a
            # double-click drills into the link's target — surface that
            # via ``kind`` while keeping the symlink_target populated.
            if os.path.isdir(entry.path):
                kind = "dir"
            elif os.path.isfile(entry.path):
                kind = "file"
        except OSError as error:
            err = err or str(error)
    return FsEntry(
        name=name,
        path=str(Path(entry.path)),
        kind=kind,
        size=size,
        mtime=mtime,
        hidden=is_hidden,
        symlink_target=target,
        error=err,
    )


def _list_dir(path: Path) -> tuple[list[FsEntry], str | None]:
    rows: list[FsEntry] = []
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                rows.append(_entry_payload(entry))
    except PermissionError as error:
        return [], f"permission denied: {error}"
    except FileNotFoundError as error:
        return [], f"not found: {error}"
    except NotADirectoryError as error:
        return [], f"not a directory: {error}"
    except OSError as error:
        return [], f"os error: {error}"
    rows.sort(key=lambda row: (row.kind != "dir", row.name.lower()))
    return rows, None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/browse", response_model=FsBrowseResponse)
def browse(
    path: str = Query(default="", description="Absolute path to list."),
) -> FsBrowseResponse:
    """List directory contents at *path*.

    Empty input lands on the operator's home directory (a sensible
    default first-open state). The response always carries the resolved
    canonical ``path`` plus a ``parent`` pointer so the UI can chain
    breadcrumb navigation without re-resolving paths client-side.
    """

    try:
        target = _resolve_request_path(path)
    except (OSError, ValueError) as error:
        return FsBrowseResponse(
            path=path,
            parent=None,
            entries=[],
            shortcuts=_build_shortcuts(),
            error=f"could not resolve path: {error}",
            drives=_windows_drives(),
            separator=os.sep,
        )

    if not target.exists():
        return FsBrowseResponse(
            path=str(target),
            parent=str(target.parent) if str(target.parent) != str(target) else None,
            entries=[],
            shortcuts=_build_shortcuts(),
            error="path does not exist",
            drives=_windows_drives(),
            separator=os.sep,
        )

    if target.is_file():
        # Picker often kicks off with a stale file path — show the
        # parent directory and surface a hint so the user knows we
        # promoted them up one level.
        parent = target.parent
        rows, list_error = _list_dir(parent)
        return FsBrowseResponse(
            path=str(parent),
            parent=str(parent.parent) if str(parent.parent) != str(parent) else None,
            entries=rows,
            shortcuts=_build_shortcuts(),
            error=list_error or f"selected entry was a file: {target.name}",
            drives=_windows_drives(),
            separator=os.sep,
        )

    rows, list_error = _list_dir(target)
    parent_str: str | None = str(target.parent) if str(target.parent) != str(target) else None
    return FsBrowseResponse(
        path=str(target),
        parent=parent_str,
        entries=rows,
        shortcuts=_build_shortcuts(),
        error=list_error,
        drives=_windows_drives(),
        separator=os.sep,
    )


@router.get("/shortcuts", response_model=list[FsShortcut])
def shortcuts() -> list[FsShortcut]:
    """Return the static "jump to" location list used by the picker sidebar."""

    return _build_shortcuts()
