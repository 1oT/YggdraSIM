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

"""``/api/guides`` — markdown guide listing + read-only content endpoint.

Lists every ``*.md`` file shipped under the workspace ``guides/``
directory (and a small allow-list of repository-root entries — README,
LICENSE, NOTICE, AUTHORS) so the GUI's About panel can deep-link to
operator documentation without forcing the user to leave the desktop
shell.

Path safety is the only non-trivial concern here: requests carry an
opaque ``id`` derived from a known catalog mapping, never a raw
filesystem path, and the resolver rejects anything that escapes the
allow-listed directory after normalisation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from yggdrasim_common.runtime_paths import bundle_path


_LOGGER = logging.getLogger("yggdrasim.gui.guides")

router = APIRouter(prefix="/api", tags=["guides"])


# Catalog of guides exposed in the GUI About panel. Tuples are
# ``(id, title, repo-relative-path, group, blurb)`` where the id is
# the opaque token used in API URLs. Order in the list is the order
# rendered in the About panel.
_CATALOG: tuple[tuple[str, str, str, str, str], ...] = (
    # -- entry points & overviews --
    (
        "readme",
        "README",
        "README.md",
        "Overview",
        "Repository entry point — what YggdraSIM is and how to start.",
    ),
    (
        "guides-index",
        "Guide Index",
        "guides/README.md",
        "Overview",
        "Index of every operator and developer guide.",
    ),
    (
        "architecture",
        "Architecture",
        "guides/ARCHITECTURE.md",
        "Overview",
        "System structure, dependency map, runtime state, flow charts.",
    ),
    (
        "capabilities",
        "Capabilities",
        "guides/CAPABILITIES.md",
        "Overview",
        "Suite-level capability reference grouped by subsystem.",
    ),
    # -- install & build --
    (
        "install-clean",
        "Install · Clean",
        "guides/INSTALL_CLEAN.md",
        "Install & Build",
        "Minimal install path for offline / air-gapped use.",
    ),
    (
        "install-full",
        "Install · Full",
        "guides/INSTALL_FULL.md",
        "Install & Build",
        "Recommended install with every optional extra.",
    ),
    (
        "install-from-source",
        "Install · From Source",
        "guides/INSTALL_FROM_SOURCE.md",
        "Install & Build",
        "Editable / developer install with a source checkout.",
    ),
    (
        "install-raspberrypi",
        "Install · Raspberry Pi",
        "guides/INSTALL_RASPBERRYPI.md",
        "Install & Build",
        "Pi-specific install with PCSC quirks and systemd recipes.",
    ),
    (
        "build-and-packaging",
        "Build & Packaging",
        "guides/BUILD_AND_PACKAGING.md",
        "Install & Build",
        "Docker, PyInstaller, .deb, and packaging guidance.",
    ),
    # -- operator guides --
    (
        "cli-and-piping",
        "CLI & Piping",
        "guides/CLI_AND_PIPING_GUIDE.md",
        "Operator Guides",
        "Non-interactive command, piping, and automation patterns.",
    ),
    (
        "profile-lifecycle",
        "Profile Lifecycle Cheatsheet",
        "guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md",
        "Operator Guides",
        "Ready-to-run lifecycle, polling, and logging recipes.",
    ),
    (
        "hil-bridge",
        "HIL Bridge",
        "guides/HIL_BRIDGE_GUIDE.md",
        "Operator Guides",
        "SIMtrace2 / PCSC HIL bridge setup and operation.",
    ),
    (
        "simtrace2-cardem",
        "SIMtrace2 · Card Emulation",
        "guides/SIMTRACE2_CARDEM_GUIDE.md",
        "Operator Guides",
        "Card-emulation mode setup with SIMtrace2.",
    ),
    (
        "diagnostics-toolbox",
        "Diagnostics Toolbox",
        "guides/DIAGNOSTICS_TOOLBOX.md",
        "Operator Guides",
        "SAIP diff, SIMCARD-to-TUI auto-open, APDU fuzzer, EUM dissector.",
    ),
    (
        "template-and-tokens",
        "Templates & Tokens",
        "guides/TEMPLATE_AND_TOKENS.md",
        "Operator Guides",
        "SAIP template authoring, token sidecars, placeholder lifecycle.",
    ),
    # -- legal & credits --
    (
        "license",
        "LICENSE",
        "LICENSE",
        "Legal",
        "GPLv3 license text.",
    ),
    (
        "notice",
        "NOTICE",
        "NOTICE",
        "Legal",
        "Third-party attributions and notices.",
    ),
    (
        "authors",
        "AUTHORS",
        "AUTHORS",
        "Legal",
        "List of contributors.",
    ),
)


class GuideEntry(BaseModel):
    id: str
    title: str
    group: str
    blurb: str
    available: bool
    bytes: int


class GuideListResponse(BaseModel):
    guides: list[GuideEntry]
    root: str


class GuideContentResponse(BaseModel):
    id: str
    title: str
    path: str
    markdown: str
    bytes: int


def _resolve_catalog_path(rel_path: str) -> Path | None:
    """Return the resolved on-disk path for *rel_path*, or ``None``.

    The resolution is anchored at :func:`bundle_path` so the lookup
    works in both source-checkout mode and PyInstaller-frozen mode
    (where guides are bundled into ``_MEIPASS``). The resolved path
    is rejected if it escapes the bundle root after symlink resolution
    — defence-in-depth against ``..`` smuggling even though the id
    space is closed by the catalog.
    """
    if not rel_path:
        return None
    root = Path(bundle_path()).resolve()
    candidate = (root / rel_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


def _entry_for(item: tuple[str, str, str, str, str]) -> GuideEntry:
    guide_id, title, rel_path, group, blurb = item
    resolved = _resolve_catalog_path(rel_path)
    if resolved is None:
        return GuideEntry(
            id=guide_id,
            title=title,
            group=group,
            blurb=blurb,
            available=False,
            bytes=0,
        )
    try:
        size = resolved.stat().st_size
    except OSError:
        size = 0
    return GuideEntry(
        id=guide_id,
        title=title,
        group=group,
        blurb=blurb,
        available=True,
        bytes=size,
    )


@router.get("/guides", response_model=GuideListResponse)
def list_guides() -> GuideListResponse:
    """Return every catalog entry, flagged with availability + size."""
    entries = [_entry_for(item) for item in _CATALOG]
    return GuideListResponse(
        guides=entries,
        root=str(Path(bundle_path()).resolve()),
    )


@router.get("/guides/{guide_id}", response_model=GuideContentResponse)
def read_guide(guide_id: str) -> GuideContentResponse:
    """Return the markdown content for *guide_id* as plain text.

    The frontend renders the markdown to HTML in-browser so we don't
    have to bring a markdown library into the install footprint just
    for the About panel.
    """
    matches = [item for item in _CATALOG if item[0] == guide_id]
    if not matches:
        raise HTTPException(status_code=404, detail="unknown_guide_id")
    guide_id, title, rel_path, _group, _blurb = matches[0]
    resolved = _resolve_catalog_path(rel_path)
    if resolved is None:
        raise HTTPException(status_code=404, detail="guide_not_available")
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as err:
        _LOGGER.warning(
            "gui.guides.read_failed id=%s path=%s err=%s",
            guide_id, rel_path, err,
        )
        raise HTTPException(status_code=500, detail="guide_read_failed") from err
    return GuideContentResponse(
        id=guide_id,
        title=title,
        path=rel_path,
        markdown=text,
        bytes=len(text.encode("utf-8")),
    )
