"""
Distribution-flavor detection for the YggdraSIM suite.

The suite is published in three shapes:

* ``clean``  — bundled executable without the HIL bridge. Targets Windows,
  macOS, desktop Linux, and Raspberry Pi. No ``pyudev``, no ``osmo-remsim``,
  no SIMtrace2 dependency.
* ``full``   — bundled executable with the HIL bridge included. Linux-only
  operationally, because the HIL bridge drives a SIMtrace2 through
  ``osmo-remsim-client-st2`` and ``pyudev``.
* ``source`` — users clone the repo and run ``pip install -e .``. Everything
  is present but HIL features remain opt-in; runtime warnings still apply
  when the supporting host tooling is missing.

The active flavor is resolved in this order:

1. Explicit ``YGGDRASIM_FLAVOR`` environment variable (``clean`` / ``full``
   / ``source``) — highest priority so operators can pin behaviour during
   tests.
2. Optional build stamp written by ``yggdrasim_main.spec`` at PyInstaller
   build time (``yggdrasim_common/_build_flavor.py`` exposing a single
   ``BUILD_FLAVOR`` string). This is how frozen executables know which
   SKU they are.
3. Fallback ``source`` when running from a git checkout without a stamp.

The module also exposes small predicates used by the launcher, the
``--doctor`` probe, and the console-script entry points so HIL-bridge
wiring is guarded from a single point and cannot drift across surfaces.
"""

from __future__ import annotations

import os
import sys
from typing import Final


__all__ = [
    "FLAVOR_CLEAN",
    "FLAVOR_FULL",
    "FLAVOR_SOURCE",
    "FLAVOR_ENV",
    "KNOWN_FLAVORS",
    "get_flavor",
    "get_flavor_source",
    "normalize_flavor",
    "is_hil_bridge_included",
    "is_hil_bridge_supported_platform",
    "hil_bridge_unavailable_reason",
    "describe_flavor",
]


FLAVOR_CLEAN: Final[str] = "clean"
FLAVOR_FULL: Final[str] = "full"
FLAVOR_SOURCE: Final[str] = "source"
FLAVOR_ENV: Final[str] = "YGGDRASIM_FLAVOR"
KNOWN_FLAVORS: Final[tuple[str, ...]] = (FLAVOR_CLEAN, FLAVOR_FULL, FLAVOR_SOURCE)


def normalize_flavor(raw_value: str) -> str:
    """Return a canonical flavor label, or ``""`` when the input is unknown."""
    text = str(raw_value or "").strip().lower()
    if text in KNOWN_FLAVORS:
        return text
    # Accept a few user-friendly aliases seen in release shorthand.
    if text in ("lite", "slim", "minimal", "no-hil"):
        return FLAVOR_CLEAN
    if text in ("hil", "all", "complete"):
        return FLAVOR_FULL
    if text in ("src", "dev", "editable"):
        return FLAVOR_SOURCE
    return ""


def _flavor_from_env() -> str:
    raw_env = os.environ.get(FLAVOR_ENV, "")
    return normalize_flavor(raw_env)


def _flavor_from_build_stamp() -> str:
    try:
        from yggdrasim_common import _build_flavor as stamp
    except Exception:
        return ""
    raw_stamp = getattr(stamp, "BUILD_FLAVOR", "")
    return normalize_flavor(raw_stamp)


def _flavor_from_runtime_hint() -> str:
    # Frozen bundles are always one of the published flavors. When the build
    # stamp is missing we still want to surface a sensible default rather
    # than claim ``source`` from a .exe that clearly was not cloned.
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return FLAVOR_CLEAN
    return FLAVOR_SOURCE


def get_flavor() -> str:
    """Return the active flavor label, falling back to ``source``."""
    for candidate in (_flavor_from_env(), _flavor_from_build_stamp()):
        if len(candidate) > 0:
            return candidate
    return _flavor_from_runtime_hint()


def get_flavor_source() -> str:
    """Return a short label describing where the flavor value came from.

    Useful for the ``--doctor`` report so users can tell whether the
    active flavor was forced via env or baked into a frozen build.
    """
    if len(_flavor_from_env()) > 0:
        return "env"
    if len(_flavor_from_build_stamp()) > 0:
        return "build-stamp"
    if getattr(sys, "frozen", False):
        return "frozen-default"
    return "source-checkout"


def is_hil_bridge_included() -> bool:
    """Return True when the current build ships the HIL bridge modules.

    ``source`` checkouts and ``full`` builds both include the code. A
    ``clean`` build explicitly strips the Tools/HilBridge tree and the
    ``yggdrasim_common.hil_bridge_runtime`` module, so HIL features cannot
    be reached at all.
    """
    flavor = get_flavor()
    if flavor == FLAVOR_CLEAN:
        return False
    return True


def is_hil_bridge_supported_platform() -> bool:
    """Return True when the host OS can run the HIL bridge.

    The bridge relies on SIMtrace2 + ``osmo-remsim-client-st2`` + udev-style
    USB monitoring, which is only realistic on Linux. macOS and Windows
    hosts are reported as unsupported so the menu can hide the entry
    cleanly instead of letting the subprocess fail with a cryptic error.
    """
    return sys.platform.startswith("linux")


def hil_bridge_unavailable_reason() -> str:
    """Return a human-friendly explanation, or ``""`` when HIL is usable."""
    if is_hil_bridge_included() is False:
        return (
            "The HIL bridge is not bundled in this clean build. "
            "Use the 'full' executable or install from source to access it."
        )
    if is_hil_bridge_supported_platform() is False:
        return (
            "The HIL bridge requires Linux (for udev monitoring and "
            "osmo-remsim-client-st2)."
        )
    return ""


def describe_flavor() -> str:
    """Render a one-line description used by ``--version`` and banners."""
    flavor = get_flavor()
    labels = {
        FLAVOR_CLEAN: "clean (no HIL bridge)",
        FLAVOR_FULL: "full (HIL bridge included)",
        FLAVOR_SOURCE: "source checkout",
    }
    return labels.get(flavor, flavor)
