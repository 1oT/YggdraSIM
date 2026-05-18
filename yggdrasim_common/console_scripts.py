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


def _guard_hil_bridge() -> int:
    """Short-circuit HIL bridge entries when they are not available.

    Returns a non-zero exit code and writes a friendly message to stderr
    when the current build flavor omits the HIL bridge, or when the host
    platform does not support it. Returns ``0`` when the caller may
    continue into the real entry point.
    """
    reason = hil_bridge_unavailable_reason()
    if len(reason) == 0:
        return 0
    sys.stderr.write(f"yggdrasim-hil: {reason}\n")
    sys.stderr.write(
        "See guides/INSTALL_FULL.md and guides/SIMTRACE2_CARDEM_GUIDE.md "
        "for the HIL-capable install path.\n"
    )
    return 2


def scp03() -> int:
    return _invoke("SCP03.main", "run_standalone")


def scp80() -> int:
    return _invoke("SCP80.main", "run_standalone")


def scp11() -> int:
    return _invoke("SCP11.main", "entry")


def scp11_live() -> int:
    return _invoke("SCP11.live.main", "entry")


def scp11_test() -> int:
    return _invoke("SCP11.test.main", "entry")


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
    """Operator-laptop side of the APDU-over-SSH card-stream feature.

    Publishes a locally attached PC/SC reader over an HTTP relay
    endpoint that the rig-side HIL bridge consumes via its
    ``--remote-card-url`` flag. The rig keeps doing GSMTAP capture
    and APDU routing exactly as today; only the card itself moves.

    Pre-flight gating intentionally reuses the HIL-bridge guard so
    flavors that omit the bridge stack also omit the card-bridge
    counterpart — they share the same pyscard / smartcard runtime
    requirement.
    """
    guard_code = _guard_hil_bridge()
    if guard_code != 0:
        return guard_code
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
