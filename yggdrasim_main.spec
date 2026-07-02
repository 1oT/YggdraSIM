# -*- mode: python ; coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

#
# Flavor-aware PyInstaller spec for YggdraSIM.
#
# The spec produces one of two bundles controlled by the ``YGGDRASIM_FLAVOR``
# environment variable at build time:
#
#   * ``clean`` (default) — Windows / macOS / Linux / Raspberry Pi target.
#     The Linux HIL supervisor/runtime modules are excluded so the bundle has
#     no residual ``pyudev`` or ``osmo-remsim`` coupling. The small APDU relay
#     helpers used by ``Tools/CardBridge`` remain available.
#   * ``full`` — Linux-only superset that ships the HIL bridge so the bundled
#     launcher can drive a SIMtrace2 through ``osmo-remsim-client-st2``.
#
# The spec also writes ``yggdrasim_common/_build_flavor.py`` before analysis
# so the frozen binary reports the correct flavor through
# ``yggdrasim_common.flavor.get_flavor()`` without requiring an environment
# variable at runtime.

import os
import shutil
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


# ``SPECPATH`` is the directory containing this spec file, which is the
# repository root. Do not add a ``.parent`` here — that would walk one
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
gui_static_dir = ROOT / "yggdrasim_common" / "gui_server" / "static"
if gui_static_dir.is_dir():
    datas.append((str(gui_static_dir), "yggdrasim_common/gui_server/static"))
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

try:
    datas.extend(collect_data_files("pySim", includes=["esim/asn1/**/*"]))
except Exception as error:
    print(f"[yggdrasim spec] pySim ASN.1 resources not collected: {error}")


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
GUI_THIRD_PARTY_HIDDEN = [
    "fastapi",
    "fastapi.middleware.cors",
    "fastapi.responses",
    "fastapi.staticfiles",
    "uvicorn",
    "webview",
    "websockets",
]

hiddenimports = list(THIRD_PARTY_HIDDEN) + list(GUI_THIRD_PARTY_HIDDEN)
gui_hiddenimports = list(THIRD_PARTY_HIDDEN) + list(GUI_THIRD_PARTY_HIDDEN)
package_candidates = [
    "main",
    "SCP03",
    "SCP80",
    "SCP11",
    "SIMCARD",
    "yggdrasim_common",
]
if INCLUDE_HIL:
    package_candidates.append("Tools")
else:
    for package_name in ("Tools.CardBridge", "Tools.ProfilePackage", "Tools.SuciTool"):
        collected = collect_submodules(package_name)
        hiddenimports.extend(collected)
        gui_hiddenimports.extend(collected)
    clean_tool_helpers = [
        "Tools.HilBridge",
        "Tools.HilBridge.apdu_relay",
        "Tools.HilBridge.pcsc",
    ]
    hiddenimports.extend(clean_tool_helpers)
    gui_hiddenimports.extend(clean_tool_helpers)

for package_name in package_candidates:
    hiddenimports.extend(collect_submodules(package_name))
    gui_hiddenimports.extend(collect_submodules(package_name))


excludes = ["tests"]
if INCLUDE_HIL is False:
    # Keep the bundle lean by cutting the HIL supervisor stack and the
    # optional ``pyudev`` import that would otherwise trigger a Linux-only
    # dependency during analysis. ``Tools.HilBridge.apdu_relay`` and
    # ``Tools.HilBridge.pcsc`` are intentionally kept because the clean
    # Card Bridge daemon reuses those platform-neutral helpers.
    excludes.extend([
        "Tools.HilBridge.main",
        "Tools.HilBridge.supervisor",
        "Tools.HilBridge.router",
        "Tools.HilBridge.protocol",
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


def _analysis_for(entry_script: Path, entry_hiddenimports: list[str]) -> Analysis:
    return Analysis(
        [str(entry_script)],
        pathex=[str(ROOT)],
        binaries=[],
        datas=datas,
        hiddenimports=sorted(set(entry_hiddenimports)),
        hookspath=[],
        hooksconfig={},
        runtime_hooks=[],
        excludes=excludes,
        noarchive=False,
    )


CLI_EXECUTABLE_NAME = f"yggdrasim-{FLAVOR}"
GUI_EXECUTABLE_NAME = f"yggdrasim-gui-{FLAVOR}"

cli_analysis = _analysis_for(ROOT / "main" / "main.py", hiddenimports)
cli_pyz = PYZ(cli_analysis.pure)

cli_exe = EXE(
    cli_pyz,
    cli_analysis.scripts,
    cli_analysis.binaries,
    cli_analysis.zipfiles,
    cli_analysis.datas,
    [],
    name=CLI_EXECUTABLE_NAME,
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

gui_analysis = _analysis_for(ROOT / "main" / "gui.py", gui_hiddenimports)
gui_pyz = PYZ(gui_analysis.pure)

gui_exe = EXE(
    gui_pyz,
    gui_analysis.scripts,
    gui_analysis.binaries,
    gui_analysis.zipfiles,
    gui_analysis.datas,
    [],
    name=GUI_EXECUTABLE_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
