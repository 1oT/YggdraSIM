# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The vendored browser libraries are byte-identical to their upstream release.

Each digest is the SHA-256 of the file in the npm tarball of the version the
library's ``NOTICE.md`` pins. A tree-wide text sweep once replaced four
NO-BREAK SPACEs in ``xterm.js`` with spaces, which xterm's DOM renderer relies
on for empty rows and decorated blank cells; a digest catches any such edit,
and an upgrade updates the digest together with the ``NOTICE.md`` version.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VENDOR_SOURCE = ROOT / "gui_frontend" / "src" / "vendor"
VENDOR_SERVED = ROOT / "yggdrasim_common" / "gui_server" / "static" / "vendor"

# path under vendor/ -> (npm package@version, file in the tarball, SHA-256)
UPSTREAM = {
    "mermaid/mermaid.min.js": (
        "mermaid@11.17.2",
        "package/dist/mermaid.min.js",
        "581ed7d74bd9048d0e3a91363927d72ef22942d7722546b27f7cc29e35390eb8",
    ),
    "xterm/xterm.js": (
        "xterm@5.3.0",
        "package/lib/xterm.js",
        "f0aea0f75f48559013ae6643c2479dd737d26da42d5524e6d2b70915ae6523c7",
    ),
    "xterm/xterm.css": (
        "xterm@5.3.0",
        "package/css/xterm.css",
        "832f3f2c603b43ad4351ff04970150cc7a873014276db126a6065c6dd81e4872",
    ),
    "xterm/addon-fit.js": (
        "xterm-addon-fit@0.8.0",
        "package/lib/xterm-addon-fit.js",
        "10f3194c5f17c1786fb7d5db865c1ec8539b6736a318063fd38bdaaf7c46848f",
    ),
}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("relative", sorted(UPSTREAM))
def test_vendored_library_matches_its_upstream_release(relative: str) -> None:
    release, member, expected = UPSTREAM[relative]
    assert _digest(VENDOR_SOURCE / relative) == expected, (
        f"{relative} differs from {member} in {release}"
    )


def test_every_vendored_library_has_a_pinned_digest() -> None:
    present = {
        path.relative_to(VENDOR_SOURCE).as_posix()
        for path in VENDOR_SOURCE.rglob("*")
        if path.is_file() and path.name != "NOTICE.md"
    }
    assert present == set(UPSTREAM)


def test_the_served_copies_are_the_vendored_ones() -> None:
    for relative in UPSTREAM:
        served = VENDOR_SERVED / relative
        if not served.exists():
            pytest.skip("bundle not built in this checkout")
        assert _digest(served) == _digest(VENDOR_SOURCE / relative)
