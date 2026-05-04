"""
Environment preflight checks for the YggdraSIM suite.

``run_doctor`` prints a terminal-friendly report covering Python version,
common optional runtime dependencies, workspace paths, pySim
availability (either a developer checkout at ``<workspace>/pysim`` or
a pip-installed ``pySim`` package -- the latter is what the ``[saip]``
extra drops in), SQLite availability, PC/SC reader visibility, and
presence of the ``gpg`` binary used by the optional inventory
encryption provider. It is intentionally read-only: no SQLite rows are
written and no card transport is opened.

The helper is modular so individual probes can be reused by other
diagnostic paths or by wrapper tests without re-implementing the
detection logic.
"""

from __future__ import annotations

import importlib
import os
import shutil
import sys
from pathlib import Path
from typing import Callable

from yggdrasim_common.nord_palette import NORD


__all__ = [
    "DoctorCheck",
    "DoctorReport",
    "run_doctor",
]


class DoctorCheck:
    __slots__ = ("name", "status", "detail")

    def __init__(self, name: str, status: str, detail: str = "") -> None:
        self.name = str(name or "").strip()
        self.status = str(status or "").strip().lower()
        self.detail = str(detail or "").strip()


class DoctorReport:
    def __init__(self) -> None:
        self.checks: list[DoctorCheck] = []

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.checks.append(DoctorCheck(name, status, detail))

    def worst_status(self) -> str:
        rank_table = {"ok": 0, "info": 0, "warn": 1, "fail": 2}
        worst_rank = 0
        saw_info = False
        saw_ok = False
        for check in self.checks:
            status_rank = rank_table.get(check.status, 0)
            worst_rank = max(worst_rank, status_rank)
            if check.status == "info":
                saw_info = True
            if check.status == "ok":
                saw_ok = True
        if worst_rank == 2:
            return "fail"
        if worst_rank == 1:
            return "warn"
        if saw_ok:
            return "ok"
        if saw_info:
            return "info"
        return "ok"


def _color_for_status(status: str) -> str:
    # Map the four doctor-report verdicts onto the Nord aurora swatches.
    # Anything else (e.g. a future "skip" verdict) simply renders
    # without colour rather than picking a random escape sequence.
    colors = {
        "ok": NORD.GREEN,
        "warn": NORD.WARNING,
        "fail": NORD.FAIL,
        "info": NORD.CYAN,
    }
    return colors.get(status, "")


def _format_check(check: DoctorCheck) -> str:
    reset = NORD.RESET
    colour = _color_for_status(check.status)
    marker = {"ok": "[+]", "warn": "[*]", "fail": "[-]", "info": "[*]"}.get(
        check.status, "[*]"
    )
    detail = f" -- {check.detail}" if len(check.detail) > 0 else ""
    return f"{colour}{marker} {check.name}: {check.status.upper()}{detail}{reset}"


def _probe_python(report: DoctorReport) -> None:
    version_text = ".".join(str(part) for part in sys.version_info[:3])
    if sys.version_info >= (3, 10):
        report.add("Python runtime", "ok", f"{version_text} (>= 3.10)")
    else:
        report.add(
            "Python runtime",
            "fail",
            f"{version_text} detected; YggdraSIM requires >= 3.10",
        )


def _probe_module(
    report: DoctorReport,
    *,
    module_name: str,
    label: str,
    missing_status: str = "warn",
    missing_detail: str = "",
) -> None:
    try:
        module = importlib.import_module(module_name)
    except Exception as error:
        detail = missing_detail or f"import {module_name}: {error.__class__.__name__}"
        report.add(label, missing_status, detail)
        return
    version = getattr(module, "__version__", "")
    detail = f"{module_name} {version}".strip() if len(str(version or "")) > 0 else module_name
    report.add(label, "ok", detail)


def _probe_optional_pysim(report: DoctorReport, workspace_root: Path) -> None:
    """Probe for any of the three valid pySim provisioning paths.

    pySim is an **upstream** dependency. Resolution order:

    1. A developer checkout at ``<workspace>/pysim`` (advanced
       upstream-branch workflow).
    2. A pip-installed ``pySim`` package (e.g. from the ``[saip]``
       extra -- ``pip install 'yggdrasim[saip]'`` -- or a hand
       ``pip install 'pySim @ git+https://github.com/osmocom/pysim.git'``).

    Either path is valid. The probe reports ``ok`` when any one of
    them resolves and ``warn`` only when both fail; the warning spells
    out the recommended install so an operator running
    ``yggdrasim --doctor`` on a lean install knows exactly which
    command to run.
    """
    candidate = workspace_root / "pysim" / "pySim" / "esim" / "saip" / "__init__.py"
    if candidate.is_file():
        report.add(
            "pySim",
            "ok",
            f"developer checkout at {candidate.relative_to(workspace_root)}",
        )
        return

    try:
        pysim_module = importlib.import_module("pySim.esim.saip")
    except Exception as import_error:
        report.add(
            "pySim",
            "warn",
            "pySim.esim.saip not importable; SAIP and SCP11 local flows need it. "
            "Recommended: `pip install 'yggdrasim[saip]'` (installs pySim from "
            "https://github.com/osmocom/pysim.git). Developer-checkout "
            "alternative: clone the upstream tree into `pysim/` under the "
            f"workspace root. Underlying import error: {type(import_error).__name__}: {import_error}.",
        )
        return

    module_path = Path(getattr(pysim_module, "__file__", "") or "").resolve()
    detail = f"installed package at {module_path.parent}" if module_path.name != "" else "installed package"
    report.add("pySim", "ok", detail)


# Backwards-compatibility alias: older code and tests may still import
# ``_probe_vendored_pysim``. The underscore prefix marks it as internal
# but since it was never private to this module in practice the
# alias around to avoid breaking downstream callers.
_probe_vendored_pysim = _probe_optional_pysim


def _probe_sqlite(report: DoctorReport) -> None:
    try:
        import sqlite3  # noqa: F401
    except Exception as error:
        report.add("SQLite (sqlite3 module)", "fail", f"{error.__class__.__name__}: {error}")
        return
    report.add("SQLite (sqlite3 module)", "ok", sys.modules["sqlite3"].sqlite_version)


def _probe_reader(report: DoctorReport) -> None:
    try:
        from smartcard.System import readers  # type: ignore
    except Exception as error:
        report.add(
            "PC/SC (pyscard)",
            "warn",
            f"pyscard import failed: {error.__class__.__name__}",
        )
        return
    try:
        available = readers()
    except Exception as error:
        report.add(
            "PC/SC readers",
            "warn",
            f"reader listing failed: {error.__class__.__name__}",
        )
        return
    if len(available) == 0:
        report.add(
            "PC/SC readers",
            "info",
            "No readers attached (fine when using --card-backend sim).",
        )
        return
    names = ", ".join(str(reader) for reader in available)
    report.add("PC/SC readers", "ok", f"{len(available)} reader(s): {names}")


def _probe_gpg(report: DoctorReport) -> None:
    binary = shutil.which("gpg")
    if binary is None:
        report.add(
            "gpg binary",
            "info",
            "Not found (only required when inventory_crypto is enabled).",
        )
        return
    report.add("gpg binary", "ok", binary)


def _probe_flavor(report: DoctorReport) -> None:
    try:
        from yggdrasim_common import flavor as _flavor
    except Exception as error:
        report.add(
            "Build flavor",
            "warn",
            f"flavor module unavailable: {error.__class__.__name__}",
        )
        return
    label = _flavor.describe_flavor()
    source = _flavor.get_flavor_source()
    report.add("Build flavor", "ok", f"{label} (source: {source})")


def _probe_hil_bridge(report: DoctorReport) -> None:
    try:
        from yggdrasim_common import flavor as _flavor
    except Exception as error:
        report.add(
            "HIL bridge readiness",
            "info",
            f"flavor module unavailable: {error.__class__.__name__}",
        )
        return
    reason = _flavor.hil_bridge_unavailable_reason()
    if len(reason) > 0:
        report.add("HIL bridge readiness", "info", reason)
        return
    # Module presence check -- the clean build strips these, but a ``full``
    # or ``source`` install should have them available.
    try:
        importlib.import_module("Tools.HilBridge.main")
    except Exception as error:
        report.add(
            "HIL bridge readiness",
            "warn",
            f"Tools.HilBridge.main import failed: {error.__class__.__name__}",
        )
        return
    # pyudev is only required for event-driven supervisor hotplug.
    try:
        importlib.import_module("pyudev")
        pyudev_detail = "pyudev present"
    except Exception:
        pyudev_detail = "pyudev missing (supervisor falls back to lsusb polling)"
    # osmo-remsim-client-st2 is the runtime bridge between SIMtrace2 and us.
    remsim_binary = shutil.which("osmo-remsim-client-st2")
    if remsim_binary is None:
        report.add(
            "HIL bridge readiness",
            "warn",
            "osmo-remsim-client-st2 not on PATH -- see "
            "guides/SIMTRACE2_CARDEM_GUIDE.md",
        )
        return
    detail = f"{pyudev_detail}; osmo-remsim-client-st2 at {remsim_binary}"
    report.add("HIL bridge readiness", "ok", detail)


def _probe_hil_optional_helpers(report: DoctorReport) -> None:
    """Surface optional HIL helpers without changing the overall exit code."""
    try:
        from yggdrasim_common import flavor as _flavor
    except Exception:
        return
    if _flavor.is_hil_bridge_included() is False:
        return
    if _flavor.is_hil_bridge_supported_platform() is False:
        return
    helper_probes = (
        ("tshark (Wireshark CLI)", "tshark"),
        ("termshark (terminal decode)", "termshark"),
        ("dfu-util (SIMtrace2 flashing)", "dfu-util"),
        ("lsusb (USB identity)", "lsusb"),
    )
    for label, binary_name in helper_probes:
        resolved = shutil.which(binary_name)
        if resolved is None:
            report.add(label, "info", f"{binary_name} not on PATH")
            continue
        report.add(label, "ok", resolved)


def _probe_card_relay(report: DoctorReport) -> None:
    """Probe the configured remote card bridge (CB-3 reachability check).

    Decision tree:

    * If neither ``YGGDRASIM_CARD_RELAY_URL`` nor a runtime marker is
      set: emit a single ``info`` line so operators learn the feature
      exists without polluting the report.
    * If a URL is configured but the relay is unreachable: ``warn``.
    * If the relay answers but rejects the bearer token: ``warn``.
    * If the relay answers and authorises: ``ok`` plus a one-line
      summary of the auth posture so operators can spot e.g. a
      non-loopback bind without an audit log enabled.

    All probes use ``urllib.request`` with a tight timeout -- we never
    want the doctor to block on a wedged remote bridge.
    """
    try:
        from yggdrasim_common.card_backend import (
            _resolve_card_relay_url,
            _resolve_card_relay_token,
        )
    except Exception as error:  # noqa: BLE001
        report.add(
            "Remote card bridge",
            "info",
            f"card_backend module unavailable: {error.__class__.__name__}",
        )
        return

    try:
        relay_url, relay_url_source = _resolve_card_relay_url()
    except Exception as error:  # noqa: BLE001
        report.add(
            "Remote card bridge",
            "info",
            f"resolve URL failed: {error.__class__.__name__}: {error}",
        )
        return

    if len(relay_url) == 0:
        report.add(
            "Remote card bridge",
            "info",
            "Not configured -- set YGGDRASIM_CARD_RELAY_URL or pass --remote-card-url to talk to a Card Bridge over SSH.",
        )
        return
    _ = relay_url_source  # reserved for future per-source diagnostics

    # /apdu suffix is optional; the bridge's status endpoint lives at
    # the URL root. Strip the suffix if present so /ping can be reached
    # and /status.
    base_url = relay_url
    if relay_url.endswith("/apdu"):
        base_url = relay_url[: -len("/apdu")]
    base_url = base_url.rstrip("/")

    try:
        token = _resolve_card_relay_token(allow_marker=True)
    except Exception as error:  # noqa: BLE001
        report.add(
            "Remote card bridge",
            "warn",
            f"token resolution failed: {error.__class__.__name__}: {error}",
        )
        return

    import json as _json
    import urllib.error
    import urllib.request

    def _open(path: str) -> tuple[int, dict[str, object] | None]:
        full = f"{base_url}{path}"
        request = urllib.request.Request(full, method="GET")
        if len(token) > 0:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=2.0) as response:
            payload_raw = response.read().decode("utf-8", errors="replace")
            try:
                payload = _json.loads(payload_raw)
            except Exception:
                payload = None
            return int(response.status), payload if isinstance(payload, dict) else None

    try:
        ping_status, _ping_payload = _open("/ping")
    except urllib.error.HTTPError as error:
        report.add(
            "Remote card bridge",
            "warn",
            f"{base_url}/ping returned HTTP {error.code} ({error.reason}).",
        )
        return
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as error:
        report.add(
            "Remote card bridge",
            "warn",
            f"{base_url} unreachable: {error.__class__.__name__}: {error}",
        )
        return

    if ping_status != 200:
        report.add(
            "Remote card bridge",
            "warn",
            f"{base_url}/ping returned HTTP {ping_status}.",
        )
        return

    # Status carries the auth posture (authRequired / tokenFingerprint).
    # If we don't have a token but the relay requires one, surface
    # exactly that so the operator knows what to fix.
    try:
        status_status, status_payload = _open("/status")
    except urllib.error.HTTPError as error:
        if error.code == 401:
            report.add(
                "Remote card bridge",
                "warn",
                f"{base_url} reachable but token rejected (HTTP 401). Check YGGDRASIM_CARD_RELAY_TOKEN_FILE.",
            )
            return
        report.add(
            "Remote card bridge",
            "warn",
            f"{base_url}/status returned HTTP {error.code} ({error.reason}).",
        )
        return
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as error:
        report.add(
            "Remote card bridge",
            "warn",
            f"{base_url}/status unreachable: {error.__class__.__name__}: {error}",
        )
        return

    if status_status != 200:
        report.add(
            "Remote card bridge",
            "warn",
            f"{base_url}/status returned HTTP {status_status}.",
        )
        return

    auth_required = False
    fingerprint = ""
    bind_host = ""
    audit_enabled: object = None
    if isinstance(status_payload, dict):
        auth_required = bool(status_payload.get("authRequired"))
        fingerprint = str(status_payload.get("tokenFingerprint") or "")
        bind_host = str(status_payload.get("host") or status_payload.get("bindHost") or "")
        audit_enabled = status_payload.get("auditEnabled")

    parts: list[str] = []
    parts.append(f"{base_url} reachable")
    if auth_required:
        if len(token) == 0:
            report.add(
                "Remote card bridge",
                "warn",
                f"{base_url} requires a bearer token; none configured. Set YGGDRASIM_CARD_RELAY_TOKEN_FILE.",
            )
            return
        if len(fingerprint) > 0:
            parts.append(f"auth ok (token fp: {fingerprint})")
        else:
            parts.append("auth ok")
    else:
        if len(bind_host) > 0 and bind_host not in {"127.0.0.1", "::1", "localhost"}:
            report.add(
                "Remote card bridge",
                "warn",
                f"{base_url} reachable but auth disabled on non-loopback host '{bind_host}' -- refuse to use it.",
            )
            return
        parts.append("loopback bridge (no token required)")
    if audit_enabled is True:
        parts.append("audit on")
    elif audit_enabled is False:
        parts.append("audit off")
    report.add("Remote card bridge", "ok", "; ".join(parts))


def _detect_webview_backends() -> tuple[list[str], list[str]]:
    """Return ``(available_backends, install_hints)`` for pywebview.

    pywebview is a thin wrapper over a platform-native web widget. The
    widget itself has its own dependency tree and must be installed
    separately:

    * Linux -- **GTK** (``gi`` + WebKit2 GObject introspection) or
      **Qt** (``qtpy`` + QtWebEngine).
    * macOS -- **cocoa** (PyObjC / WKWebView).
    * Windows -- **EdgeChromium** (pythonnet + WebView2).

    The probe attempts the minimal import path for each candidate
    backend without instantiating a window, so ``--doctor`` can fail
    fast before ``webview.start()`` raises at runtime.
    """
    import sys as _sys

    available: list[str] = []
    hints: list[str] = []

    if _sys.platform.startswith("linux"):
        try:
            import gi  # type: ignore  # noqa: F401
            from gi.repository import WebKit2  # type: ignore  # noqa: F401

            available.append("gtk")
        except Exception:
            hints.append(
                "GTK backend: `sudo apt install python3-gi gir1.2-webkit2-4.1` "
                "(plus `pip install PyGObject` if the venv is not "
                "`--system-site-packages`)."
            )
        try:
            import qtpy  # type: ignore  # noqa: F401
            from qtpy import QtWebEngineWidgets  # type: ignore  # noqa: F401

            available.append("qt")
        except Exception:
            hints.append(
                "Qt backend (pip-only): "
                "`pip install 'qtpy>=2.4' 'PyQt6>=6.7' 'PyQt6-WebEngine>=6.7'`."
            )
    elif _sys.platform == "darwin":
        try:
            import webview.platforms.cocoa  # type: ignore  # noqa: F401

            available.append("cocoa")
        except Exception:
            hints.append(
                "Cocoa backend: `pip install pyobjc-framework-WebKit`."
            )
    elif _sys.platform == "win32":
        try:
            import webview.platforms.edgechromium  # type: ignore  # noqa: F401

            available.append("edgechromium")
        except Exception:
            hints.append(
                "EdgeChromium backend: install the WebView2 runtime and "
                "`pip install pythonnet`."
            )

    return available, hints


def _probe_gui_stack(report: DoctorReport) -> None:
    """Report the state of the optional universal-GUI dependency stack.

    Three-state contract:

    * ``ok``   -- full desktop stack importable AND at least one
      pywebview backend is importable (gtk / qt / cocoa / edgechromium).
    * ``info`` -- headless lab-server stack importable (fastapi +
      uvicorn) but pywebview is not installed; only ``--web-server``
      is usable from this host.
    * ``warn`` -- pywebview is installed but no platform backend
      resolves, or the configured desktop port is in use.
    * ``fail`` -- ``YGGDRASIM_GUI_TLS_CERT`` is set but unreadable.
    """
    # ``gui_server`` is an optional sub-tree (it lives behind the
    # ``[gui]`` / ``[gui-server]`` extras and is not vendored into the
    # ``clean`` flavor). When it is absent we still want ``--doctor``
    # to succeed: report the missing stack as ``info`` and bail out
    # before the rest of the probe touches GUI defaults that no longer
    # exist on this host.
    try:
        from yggdrasim_common.gui_server import config as gui_config
    except ModuleNotFoundError as gui_import_error:
        report.add(
            "GUI server stack",
            "info",
            f"yggdrasim_common.gui_server is not installed in this build "
            f"(clean flavor or trimmed checkout). "
            f"({type(gui_import_error).__name__}: {gui_import_error})",
        )
        return

    try:
        import fastapi  # type: ignore  # noqa: F401
        import uvicorn  # type: ignore  # noqa: F401
    except Exception as import_error:
        report.add(
            "GUI server deps (fastapi + uvicorn)",
            "info",
            f"not installed -- run `pip install 'yggdrasim[gui-server]'` "
            f"(remote) or `pip install 'yggdrasim[gui]'` (desktop). "
            f"({type(import_error).__name__}: {import_error})",
        )
        return

    try:
        import webview  # type: ignore  # noqa: F401
    except Exception:
        report.add(
            "GUI desktop stack (pywebview)",
            "info",
            "pywebview not installed -- desktop --gui disabled; --web-server "
            "still usable. Install with `pip install 'yggdrasim[gui]'`.",
        )
    else:
        backends, hints = _detect_webview_backends()
        if backends:
            report.add(
                "GUI desktop stack (pywebview)",
                "ok",
                f"pywebview importable; usable backends: {', '.join(backends)}",
            )
        else:
            detail = (
                "pywebview is installed but no platform backend could be "
                "loaded -- `--gui` will fail with `WebViewException`. "
                "Pick one of the options below and re-run `--doctor` "
                "to confirm."
            )
            if hints:
                detail = detail + " " + " | ".join(hints)
            report.add("GUI desktop stack (pywebview)", "warn", detail)

    # Port probe (desktop default). Warn only -- operators may intend
    # to use ephemeral fallback or to remap via YGGDRASIM_GUI_PORT.
    desktop_port = gui_config.DEFAULT_DESKTOP_PORT
    desktop_host = gui_config.DEFAULT_DESKTOP_HOST
    try:
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((desktop_host, desktop_port))
        report.add(
            "GUI desktop default port",
            "ok",
            f"{desktop_host}:{desktop_port} is free",
        )
    except OSError:
        report.add(
            "GUI desktop default port",
            "warn",
            f"{desktop_host}:{desktop_port} already in use -- desktop mode "
            f"will fall back to an ephemeral port.",
        )

    cert_path = os.environ.get(gui_config.ENV_GUI_TLS_CERT, "")
    if cert_path and not Path(cert_path).is_file():
        report.add(
            "GUI TLS certificate",
            "fail",
            f"{gui_config.ENV_GUI_TLS_CERT}={cert_path!r} does not resolve to a readable file.",
        )


def _probe_workspace(report: DoctorReport, workspace_root: Path) -> None:
    if workspace_root.is_dir():
        report.add("Workspace root", "ok", str(workspace_root))
    else:
        report.add("Workspace root", "fail", f"Missing: {workspace_root}")
    writable_candidate = workspace_root / "state"
    try:
        writable_candidate.mkdir(exist_ok=True)
    except Exception as error:
        report.add(
            "Writable state dir",
            "warn",
            f"{writable_candidate}: {error.__class__.__name__}",
        )
        return
    if os.access(writable_candidate, os.W_OK):
        report.add("Writable state dir", "ok", str(writable_candidate))
    else:
        report.add("Writable state dir", "warn", f"{writable_candidate} not writable")


def _default_workspace_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in (here.parents[1], here.parents[2] if len(here.parents) > 2 else here.parent):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return here.parents[1]


def run_doctor(
    workspace_root: Path | None = None,
    *,
    writer: Callable[[str], None] | None = None,
) -> int:
    """Execute all probes and print a human-readable report.

    Returns an exit code suitable for use from a CLI wrapper:

    * ``0`` when every probe is ``ok`` / ``info``
    * ``1`` when any probe reports ``warn`` or ``fail``
    """
    target_workspace = workspace_root or _default_workspace_root()
    emit: Callable[[str], None] = writer if writer is not None else print

    report = DoctorReport()
    _probe_python(report)
    _probe_module(
        report,
        module_name="cryptography",
        label="cryptography",
    )
    _probe_module(
        report,
        module_name="Cryptodome",
        label="pycryptodomex",
    )
    _probe_module(
        report,
        module_name="asn1tools",
        label="asn1tools",
    )
    _probe_module(
        report,
        module_name="pySim.esim.saip",
        label="pySim SAIP runtime",
    )
    _probe_module(
        report,
        module_name="textual",
        label="textual (TUI)",
        missing_status="info",
    )
    _probe_sqlite(report)
    _probe_optional_pysim(report, target_workspace)
    _probe_workspace(report, target_workspace)
    _probe_reader(report)
    _probe_gpg(report)
    _probe_flavor(report)
    _probe_hil_bridge(report)
    _probe_hil_optional_helpers(report)
    _probe_card_relay(report)
    _probe_gui_stack(report)

    try:
        from yggdrasim_common.__about__ import __version__
    except Exception:
        __version__ = "unknown"

    emit(f"YggdraSIM doctor -- suite version {__version__}")
    emit(f"Workspace: {target_workspace}")
    emit("")
    for check in report.checks:
        emit(_format_check(check))
    emit("")
    worst = report.worst_status()
    summary_text = {
        "ok": "All checks passed.",
        "info": "All checks passed (informational notes only).",
        "warn": "Some checks reported warnings.",
        "fail": "One or more checks failed.",
    }.get(worst, "Check completed.")
    emit(summary_text)
    if worst in {"warn", "fail"}:
        return 1
    return 0
