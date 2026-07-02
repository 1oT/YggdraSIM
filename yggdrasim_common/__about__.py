# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Single-source version metadata for the YggdraSIM suite.

The value is read from the build stamp when present, then from the
``[project]`` block in ``pyproject.toml`` when the suite is run straight
from a source checkout, and finally from installed distribution metadata.
Callers should prefer this module over hard-coded version strings so the
`pyproject.toml` version stays the single point of truth for source
checkouts and release builds.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional


__all__ = ["__version__", "distribution_name", "get_version"]


distribution_name = "yggdrasim"


def _version_from_installed_dist() -> Optional[str]:
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:
        return None
    try:
        return version(distribution_name)
    except PackageNotFoundError:
        return None
    except Exception:
        return None


def _version_from_build_stamp() -> Optional[str]:
    # The PyInstaller spec writes ``yggdrasim_common/_build_flavor.py``
    # at bundle time. If it also populates ``BUILD_VERSION`` there, we
    # surface it here so frozen bundles can answer ``--version`` without
    # requiring ``pyproject.toml`` on disk.
    try:
        from yggdrasim_common import _build_flavor as stamp
    except Exception:
        return None
    value = getattr(stamp, "BUILD_VERSION", None)
    if value is None:
        return None
    text = str(value).strip()
    if len(text) == 0:
        return None
    return text


def _version_from_pyproject() -> Optional[str]:
    try:
        repo_root = Path(__file__).resolve().parents[1]
    except Exception:
        return None
    pyproject = repo_root / "pyproject.toml"
    try:
        text = pyproject.read_text(encoding="utf-8")
    except Exception:
        return None
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if match is None:
        return None
    return match.group(1).strip()


def get_version() -> str:
    """Return the best-effort suite version string.

    Resolution order:

    1. Build stamp written by ``yggdrasim_main.spec`` — used by frozen
       PyInstaller bundles that do not ship ``pyproject.toml``.
    2. ``pyproject.toml`` of the source checkout.
    3. Installed distribution metadata (wheel / editable install).
    4. Literal ``"0.0.0+unknown"`` so downstream code never has to
       None-check the version.
    """
    candidate = _version_from_build_stamp()
    if candidate is not None and len(candidate.strip()) > 0:
        return candidate.strip()
    candidate = _version_from_pyproject()
    if candidate is not None and len(candidate.strip()) > 0:
        return candidate.strip()
    candidate = _version_from_installed_dist()
    if candidate is not None and len(candidate.strip()) > 0:
        return candidate.strip()
    return "0.0.0+unknown"


__version__ = get_version()
