# -*- mode: python ; coding: utf-8 -*-
#
# Flavor-aware PyInstaller spec for YggdraSIM.
#
# The spec produces one of two bundles controlled by the ``YGGDRASIM_FLAVOR``
# environment variable at build time:
#
#   * ``clean`` (default) -- Windows / macOS / Linux / Raspberry Pi target.
#     The ``Tools/HilBridge`` tree and the ``yggdrasim_common.hil_bridge_runtime``
#     module are excluded so the bundle has no residual Linux-only ``pyudev`` or
#     ``osmo-remsim`` coupling.
#   * ``full`` -- Linux-only superset that ships the HIL bridge so the bundled
#     launcher can drive a SIMtrace2 through ``osmo-remsim-client-st2``.
#
# The spec also writes ``yggdrasim_common/_build_flavor.py`` before analysis
# so the frozen binary reports the correct flavor through
# ``yggdrasim_common.flavor.get_flavor()`` without requiring an environment
# variable at runtime.

import os
import shutil
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


# ``SPECPATH`` is the directory containing this spec file, which is the
# repository root. Do not add a ``.parent`` here -- that would walk one
# level above the checkout and break the stamp write-through plus every
# ``Tree(...)`` lookup below.
ROOT = Path(SPECPATH).resolve()
KNOWN_FLAVORS = ("clean", "full")


def _resolve_flavor() -> str:
    raw = str(os.environ.get("YGGDRASIM_FLAVOR", "clean") or "clean").strip().lower()
    if raw not in KNOWN_FLAVORS:
        print(
            f"[yggdrasim spec] Unknown YGGDRASIM_FLAVOR={raw!r}; falling back to 'clean'."
        )
        return "clean"
    return raw


FLAVOR = _resolve_flavor()
INCLUDE_HIL = FLAVOR == "full"
STAMP_PATH = ROOT / "yggdrasim_common" / "_build_flavor.py"


def _read_pyproject_version(repo_root: Path) -> str:
    # Simple ad-hoc reader to avoid a hard dependency on ``tomllib`` in
    # the Python environment running PyInstaller. The ``[project]
    # version = "..."`` line is always present in this repository's
    # pyproject.toml, so a regex is sufficient.
    import re

    pyproject_path = repo_root / "pyproject.toml"
    try:
        text = pyproject_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if match is None:
        return ""
    return match.group(1).strip()


def _write_build_stamp(path: Path, flavor_value: str, version_value: str) -> None:
    payload = (
        '"""Build stamp written by yggdrasim_main.spec at PyInstaller time."""\n'
        "from __future__ import annotations\n\n"
        f'BUILD_FLAVOR = "{flavor_value}"\n'
        f'BUILD_VERSION = "{version_value}"\n'
    )
    path.write_text(payload, encoding="utf-8")


BUILD_VERSION = _read_pyproject_version(ROOT)
_write_build_stamp(STAMP_PATH, FLAVOR, BUILD_VERSION)


print(f"[yggdrasim spec] Building bundle for flavor={FLAVOR!r} (HIL={'yes' if INCLUDE_HIL else 'no'}).")


# PyInstaller 6.x expects ``datas`` as a list of ``(src, dst_dir)``
# 2-tuples where ``src`` may be a file or a directory; the bootloader
# walks directories recursively. This replaces the previous ``Tree(...)``
# approach which produced 3-tuple TOC entries that PyInstaller 6.x
# rejects with ``too many values to unpack`` inside Analysis().
datas = []
data_tree_candidates = [
    "SCP03",
    "SCP80",
    "SCP11",
    "SIMCARD",
    "Workspace",
    "plugins",
    "pysim",
]
if INCLUDE_HIL:
    data_tree_candidates.append("Tools")
else:
    # For the clean bundle we still want to ship ProfilePackage and
    # SuciTool assets, just not the HIL bridge tree.
    tools_root = ROOT / "Tools"
    if tools_root.is_dir():
        for child in tools_root.iterdir():
            if child.is_dir() is False:
                continue
            if child.name == "HilBridge":
                continue
            datas.append((str(child), f"Tools/{child.name}"))

for relative in data_tree_candidates:
    source = ROOT / relative
    if source.exists():
        datas.append((str(source), relative))


# Top-level text files the launcher opens by path at runtime. ``main.py``
# resolves ``PROJECT_ROOT = sys._MEIPASS`` in frozen builds and then reads
# LICENSE / README.md / NOTICE from it, so they must land at the bundle
# root rather than inside a sub-directory.
for toplevel_filename in ("LICENSE", "NOTICE", "README.md"):
    toplevel_source = ROOT / toplevel_filename
    if toplevel_source.is_file():
        datas.append((str(toplevel_source), "."))

# The Guides menu in the launcher opens guides/ARCHITECTURE.md directly
# via ``_show_text_document``. Shipping the whole ``guides/`` tree keeps
# the surface consistent for any additional guide entries added later.
guides_source = ROOT / "guides"
if guides_source.is_dir():
    datas.append((str(guides_source), "guides"))


# Third-party dependencies that are imported lazily (inside functions
# or via pySim, which ships as a data tree rather than a walked Python
# package) must be declared here or PyInstaller's graph analysis will
# not detect them. A missing entry manifests as a ``--doctor`` WARN for
# the named module and as a hard ``ImportError`` the first time the
# feature that needs it is exercised.
THIRD_PARTY_HIDDEN = [
    "Cryptodome",
    "Crypto",
    "asn1tools",
    "asn1crypto",
    "construct",
    "bidict",
    "pytlv",
    "pyosmocom",
]

hiddenimports = list(THIRD_PARTY_HIDDEN)
package_candidates = [
    "SCP03",
    "SCP80",
    "SCP11",
    "SIMCARD",
    "yggdrasim_common",
]
if INCLUDE_HIL:
    package_candidates.append("Tools")
else:
    for package_name in ("Tools.ProfilePackage", "Tools.SuciTool"):
        hiddenimports.extend(collect_submodules(package_name))

for package_name in package_candidates:
    hiddenimports.extend(collect_submodules(package_name))


excludes = ["tests"]
if INCLUDE_HIL is False:
    # Keep the bundle lean by cutting every HIL-bridge module and the
    # optional ``pyudev`` import that would otherwise trigger a Linux-only
    # dependency during analysis.
    excludes.extend([
        "Tools.HilBridge",
        "Tools.HilBridge.main",
        "Tools.HilBridge.supervisor",
        "Tools.HilBridge.router",
        "Tools.HilBridge.pcsc",
        "Tools.HilBridge.protocol",
        "Tools.HilBridge.apdu_relay",
        "Tools.HilBridge.proactive",
        "Tools.HilBridge.sim_modem",
        "Tools.HilBridge.live_decode_state",
        "Tools.HilBridge.live_decode_tui",
        "Tools.HilBridge.live_decode_view",
        "Tools.HilBridge.live_tshark_stream",
        "Tools.HilBridge.termshark_capture_mirror",
        "Tools.HilBridge.termshark_capture_pcap",
        "yggdrasim_common.hil_bridge_runtime",
        "pyudev",
    ])


a = Analysis(
    [str(ROOT / "main" / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=sorted(set(hiddenimports)),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)


EXECUTABLE_NAME = f"yggdrasim-{FLAVOR}"

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=EXECUTABLE_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
