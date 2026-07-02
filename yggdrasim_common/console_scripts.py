# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Console-script entry points: thin wrappers that delegate each named tool to its module's main function."""
from __future__ import annotations

import importlib
import sys
from typing import Any

from yggdrasim_common.quit_control import QuitAllRequested
from yggdrasim_common.flavor import hil_bridge_unavailable_reason


def _invoke(module_name: str, attribute_name: str) -> int:
    module = importlib.import_module(module_name)
    target = getattr(module, attribute_name)
    try:
        result: Any = target()
    except QuitAllRequested:
        return 0
    if isinstance(result, int):
        return int(result)
    return 0


def _invoke_launcher(default_mode: str | None = None) -> int:
    module = importlib.import_module("main.main")
    argv = list(sys.argv[1:])
    if default_mode is not None and not any(
        arg in ("--gui", "--web-server") for arg in argv
    ):
        argv.insert(0, default_mode)
    try:
        result: Any = module.run_cli(argv)
    except QuitAllRequested:
        return 0
    if isinstance(result, int):
        return int(result)
    return 0


def _guard_hil_bridge() -> int:
    """Short-circuit local SIMtrace2 HIL entries when they are unavailable.

    Returns a non-zero exit code and writes a friendly message to stderr
    when the current build flavor omits the local SIMtrace2/RemSIM bridge,
    or when the host platform does not support it. Card Bridge remains a
    separate cross-platform entry point.
    """
    reason = hil_bridge_unavailable_reason()
    if len(reason) == 0:
        return 0
    sys.stderr.write(f"yggdrasim-hil: {reason}\n")
    sys.stderr.write(
        "Use yggdrasim-card-bridge or main.py --card-bridge for cross-platform "
        "remote APDU streaming. See guides/INSTALL_FULL.md and "
        "guides/SIMTRACE2_CARDEM_GUIDE.md for direct SIMtrace2 HIL on Linux.\n"
    )
    return 2


def launcher() -> int:
    return _invoke_launcher()


def gui() -> int:
    return _invoke_launcher("--gui")


def web_server() -> int:
    return _invoke_launcher("--web-server")


def scp03() -> int:
    return _invoke("SCP03.main", "run_standalone")


def scp80() -> int:
    return _invoke("SCP80.main", "run_standalone")


def scp11() -> int:
    return _invoke("SCP11.main", "entry")


def scp11_live() -> int:
    return _invoke("SCP11.live.main", "entry")


def scp11_relay() -> int:
    return _invoke("SCP11.relay.main", "entry")


def scp11_local_access() -> int:
    return _invoke("SCP11.local_access.main", "run_standalone")


def scp11_eim_local() -> int:
    return _invoke("SCP11.eim_local.main", "run_standalone")


def hil_bridge() -> int:
    guard_code = _guard_hil_bridge()
    if guard_code != 0:
        return guard_code
    return _invoke("Tools.HilBridge.main", "entry")


def hil_bridge_supervisor() -> int:
    guard_code = _guard_hil_bridge()
    if guard_code != 0:
        return guard_code
    return _invoke("Tools.HilBridge.supervisor", "entry")


def card_bridge() -> int:
    """Reader-side APDU bridge CLI entry.

    The Card Bridge is useful from clean and source installs as a
    standalone PC/SC publisher. It intentionally does not use the HIL
    flavor guard; missing ``pyscard`` / PCSC support is reported by
    ``Tools.CardBridge.server`` when the reader is opened.
    """
    return _invoke("Tools.CardBridge.server", "main")


def profile_package() -> int:
    return _invoke("Tools.ProfilePackage.main", "run_standalone")


def suci_tool() -> int:
    return _invoke("Tools.SuciTool.main", "run_standalone")


def profile_autoload() -> int:
    return _invoke("Tools.ProfilePackage.simcard_watch", "run_cli")


def apdu_fuzzer() -> int:
    return _invoke("Tools.ApduFuzz.main", "run_cli")


def eum_diag() -> int:
    return _invoke("Tools.EumDiag.main", "run_cli")


def asn1_tlv_decode() -> int:
    return _invoke("Tools.Asn1TlvDecode.main", "run_cli")
