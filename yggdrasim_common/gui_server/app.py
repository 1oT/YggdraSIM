# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""FastAPI app factory + two entry points for the universal GUI.

This module is the single place where ``fastapi``, ``uvicorn``, and
``pywebview`` imports happen. None of them are resolved unless
:func:`run_desktop` or :func:`run_web_server` is called, which keeps
``pip install yggdrasim`` (no extras) lean per the §16.5 acceptance
criterion in ``V2_UNIVERSAL_GUI_PLAN.md``.

The two public entry points mirror the CLI flag shape:

* :func:`run_desktop` -- ``yggdrasim --gui``. Spawns uvicorn on a
  loopback port in a background thread, opens a ``pywebview`` window
  pointed at the resolved URL, and waits for the window to close.
* :func:`run_web_server` -- ``yggdrasim --web-server``. Spawns uvicorn
  on the configured interface, refuses an ephemeral port fallback,
  and prints the banner expected by the operator runbook.
"""

from __future__ import annotations

import errno
import importlib.util
import logging
import math
import os
import socket
import sys
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Optional

from yggdrasim_common import env_flags
from yggdrasim_common.cancellation import cancel_all_active_events

from .auth import AuthMiddleware, FailureRateLimiter
from .config import (
    ENV_GUI_ZOOM,
    GuiServerConfig,
    MODE_DESKTOP,
    WEBVIEW_ZOOM_AUTO,
    WEBVIEW_ZOOM_LADDER,
    build_desktop_config,
    build_web_server_config,
    normalize_webview_zoom,
    webview_gpu_enabled,
)


_LOGGER = logging.getLogger("yggdrasim.gui.app")


# --- readiness probe ----------------------------------------------------


_READY_TIMEOUT_SECONDS = 5.0
_STATIC_DIR = Path(__file__).resolve().parent / "static"
_PYWEBVIEW_GUI_ENV = "PYWEBVIEW_GUI"
# Native-dialog opt-in. The SPA's ``pathPicker`` asks the bridge which
# picker to use; anything outside the native set keeps the in-browser
# explorer, so the desktop default stays the same fallback as web mode.
_GUI_FILE_PICKER_ENV = "YGGDRASIM_GUI_FILE_PICKER"
_GUI_FILE_PICKER_NATIVE_VALUES = frozenset(("native", "os", "qt", "system"))
# Wayland window identity. A compositor reads the window's xdg-shell
# app_id from the toolkit, and both toolkits derive it from the process
# rather than the application: Qt from the interpreter's basename, GTK
# from ``g_get_prgname``. The window therefore announces itself as
# ``python3`` or ``main.py``, which no desktop can tell apart from any
# other Python process -- it gets the fallback icon, a wrong name in the
# task switcher, and no window rule can address it. The value is the
# basename of the desktop entry ``scripts/install_shortcuts.py`` writes,
# because that name is what associates a window with its entry.
_DESKTOP_APP_ID = "yggdrasim"
_QTWEBENGINE_CHROMIUM_FLAGS_ENV = "QTWEBENGINE_CHROMIUM_FLAGS"
_QTWEBENGINE_DEFAULT_FLAGS = (
    "--disable-background-networking",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-features=AutofillServerCommunication,MediaRouter,OptimizationGuideModelDownloading",
    "--disable-gpu",
    "--disable-gpu-compositing",
    "--disk-cache-size=67108864",
    "--js-flags=--max-old-space-size=256",
    "--media-cache-size=16777216",
    "--no-first-run",
    "--num-raster-threads=1",
    "--renderer-process-limit=1",
)
# Dropped from the set above when YGGDRASIM_GUI_GPU is on: they keep
# Chromium's raster and compositing on the CPU, in one raster thread, so
# every scroll frame of a large window is drawn in software. The other
# limits stay either way.
_QTWEBENGINE_GPU_OFF_FLAGS = frozenset(("--disable-gpu", "--disable-gpu-compositing", "--num-raster-threads=1"))


# Desktop teardown budget. The window is already gone by the time these
# run, so a slow shutdown reads to the operator as a hung application.
_SHUTDOWN_SERVER_TIMEOUT_SECONDS = 3.0
_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS = 5.0


class _UvicornRunner:
    """Thin wrapper around ``uvicorn.Server`` that can run in a thread.

    Exposes ``started`` and ``should_exit`` so the desktop entry point
    can wait for readiness and request a clean shutdown when the
    pywebview window closes.
    """

    def __init__(self, config: Any) -> None:
        import uvicorn  # local import -- only when running

        self._server = uvicorn.Server(config)
        self._thread: Optional[threading.Thread] = None

    @property
    def started(self) -> bool:
        return bool(getattr(self._server, "started", False))

    def start(self) -> None:
        """Start the GUI server in a background thread."""
        self._thread = threading.Thread(
            target=self._server.run,
            name="yggdrasim-gui-uvicorn",
            daemon=True,
        )
        self._thread.start()

    def wait_ready(self, timeout: float = _READY_TIMEOUT_SECONDS) -> bool:
        """Block until the GUI server reports that it is ready to accept connections."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        while time.monotonic() < deadline:
            if self.started:
                return True
            time.sleep(0.05)
        return self.started

    def stop(self, *, force: bool = False, timeout: float = 10.0) -> None:
        """Ask the server thread to exit, optionally without draining.

        A graceful stop waits for open connections to finish. The desktop
        window closing is not a request to finish them: a streaming
        action that never ends -- a poll cadence -- would hold the server
        open for as long as it keeps running. ``force`` sets uvicorn's
        ``force_exit`` so the listener and its live WebSockets are
        dropped instead of drained.
        """
        self._server.should_exit = True
        if force:
            self._server.force_exit = True
        if self._thread is not None:
            self._thread.join(timeout=max(0.0, float(timeout)))


# --- app factory --------------------------------------------------------


def create_app(config: GuiServerConfig) -> Any:
    """Build the FastAPI application for the given :class:`GuiServerConfig`.

    Kept importable for tests: once FastAPI is installed, a test can
    construct a client without starting uvicorn by calling
    ``create_app(config)`` + ``starlette.testclient.TestClient(app)``.
    """
    from fastapi import FastAPI
    from fastapi.responses import FileResponse, PlainTextResponse
    from fastapi.staticfiles import StaticFiles

    from yggdrasim_common.__about__ import __version__

    app = FastAPI(
        title="YggdraSIM Universal GUI",
        version=str(__version__),
        docs_url=None,      # keep OpenAPI docs off unless explicitly enabled
        redoc_url=None,     # ditto -- lab-server surface must stay narrow
        openapi_url="/api/openapi.json",
    )
    app.state.started_monotonic = time.monotonic()
    app.state.gui_mode = config.mode
    app.state.gui_config_redacted = config.redacted()
    # Raw token is needed by the WebSocket terminal bridge because
    # BaseHTTPMiddleware only runs on "http" scope -- WS handshakes bypass
    # it entirely, so the WS handler does its own token compare.
    app.state.gui_token = config.token
    # Handed to the SPA once by ``/api/gui/startup`` (routes/gui_startup.py).
    app.state.startup_open_paths = tuple(config.startup_open_paths)

    rate_limiter = FailureRateLimiter()
    app.state.rate_limiter = rate_limiter

    _register_shutdown_handler(
        app,
        lambda: _cleanup_gui_runtime_on_shutdown(
            include_default_hil_service=config.mode == MODE_DESKTOP,
        ),
    )

    # Pure-ASGI middleware: dodges the BaseHTTPMiddleware memory-growth
    # behaviour described in encode/starlette#1438. Long-running GUI
    # sessions (10s health-poll loop + frequent reader probes) used to
    # accumulate hundreds of MB of "phantom" RSS through that path.
    app.add_middleware(
        AuthMiddleware,
        expected_token=config.token,
        rate_limiter=rate_limiter,
    )

    # Explicit CORS only if the operator opted an origin in. Default
    # deny; same-origin SPA requests never need CORS.
    if len(config.allow_origins) > 0:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(config.allow_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    # Register routes. Imports deferred so the FastAPI import chain only
    # resolves when the app is actually being constructed.
    from .routes import health as health_routes
    from .routes import gui_startup as gui_startup_routes
    from .routes import native_drops as native_drop_routes
    from .routes import registry as registry_routes
    from .routes import backend as backend_routes
    from .routes import env_flags as env_flag_routes
    from .routes import tools as tools_routes
    from .routes import terminal as terminal_routes
    from .routes import live as live_routes
    from .routes import actions as actions_routes
    from .routes import apdu_events as apdu_event_routes
    from .routes import guides as guides_routes
    from .routes import fs_browse as fs_browse_routes
    from .routes import host_shell as host_shell_routes
    from .routes import remote_lab as remote_lab_routes
    from .routes import plugin_consoles as plugin_console_routes
    from .routes import plugin_console_runs as plugin_console_run_routes

    app.include_router(health_routes.router)
    app.include_router(gui_startup_routes.router)
    app.include_router(native_drop_routes.router)
    app.include_router(registry_routes.router)
    app.include_router(backend_routes.router)
    app.include_router(env_flag_routes.router)
    app.include_router(tools_routes.router)
    app.include_router(terminal_routes.router)
    app.include_router(live_routes.router)
    app.include_router(actions_routes.router)
    app.include_router(apdu_event_routes.router)
    app.include_router(guides_routes.router)
    # A desktop session is loopback-bound on the operator's own machine, so
    # the picker may see the whole filesystem. A web-server session is
    # reachable off-host and its token holder need not own that host, so
    # constrain listing to the directories the picker actually offers.
    # YGGDRASIM_GUI_FS_ROOTS overrides either default.
    fs_browse_routes.configure_browse_roots(
        None
        if config.mode == MODE_DESKTOP
        else fs_browse_routes.default_browse_roots()
    )
    app.include_router(fs_browse_routes.router)
    app.include_router(remote_lab_routes.router)
    app.include_router(plugin_console_routes.router)
    app.include_router(plugin_console_run_routes.router)
    # Host shell is a free-form RCE-equivalent surface, registered
    # unconditionally so /api/host-shell/capabilities can answer 200
    # with ``enabled=false`` and the SPA can hide the sidebar entry.
    # The WebSocket endpoint inside the router refuses connections
    # itself when YGGDRASIM_GUI_HOST_SHELL is not truthy, so leaving
    # it always-mounted is safe and keeps the discovery surface
    # uniform across desktop / web-server modes.
    app.include_router(host_shell_routes.router)

    # Static SPA bundle (+ favicon + root index). Keep this mount last so
    # it does not shadow /api/* prefixes.
    static_dir = _STATIC_DIR
    if static_dir.is_dir():
        app.mount(
            "/static",
            StaticFiles(directory=str(static_dir), html=False),
            name="static",
        )

        index_path = static_dir / "index.html"
        if index_path.is_file():
            @app.get("/", include_in_schema=False)
            def _serve_index() -> FileResponse:
                return FileResponse(str(index_path), media_type="text/html")

            @app.get("/index.html", include_in_schema=False)
            def _serve_index_alias() -> FileResponse:
                return FileResponse(str(index_path), media_type="text/html")
    else:
        _LOGGER.warning(
            "gui_server: static bundle missing at %s -- SPA will 404. "
            "Build step: scripts/build_gui_frontend.sh (or run from "
            "gui_frontend/ if present).",
            static_dir,
        )

        @app.get("/", include_in_schema=False)
        def _placeholder_index() -> PlainTextResponse:
            return PlainTextResponse(
                "YggdraSIM GUI server is running, but no static bundle was "
                "found. API is at /api/health. See "
                "V2_UNIVERSAL_GUI_PLAN.md §7 for the frontend build recipe.",
                status_code=200,
            )

    # Liveness outside /api/* so a supervisor can poll without a token.
    @app.get("/healthz", include_in_schema=False)
    def _liveness() -> PlainTextResponse:
        return PlainTextResponse("ok", status_code=200)

    return app


# --- port probing -------------------------------------------------------


def _probe_port_available(host: str, port: int) -> bool:
    """Return ``True`` if ``(host, port)`` is bindable right now.

    Uses a real bind attempt rather than just ``connect()`` so
    ``SO_REUSEADDR`` semantics don't give a false positive for ports
    that another process is still listening on.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with closing(socket.socket(family, socket.SOCK_STREAM)) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, int(port)))
            return True
    except OSError as error:
        if error.errno in (errno.EADDRINUSE, errno.EACCES):
            return False
        return False


def _resolve_bound_port(host: str, initial_port: int, allow_fallback: bool) -> int:
    """Pick the port uvicorn should bind.

    Desktop mode falls back to an OS-assigned ephemeral port if the
    configured port is busy. Server mode refuses to rebind silently so
    operators keep the stable URL they wrote into their runbook.
    """
    if _probe_port_available(host, initial_port):
        return int(initial_port)
    if not allow_fallback:
        raise SystemExit(
            f"GUI server cannot bind {host}:{initial_port} -- port in use. "
            "Choose another --port, or free the conflicting process. "
            "(web-server mode refuses silent ephemeral fallback; "
            "see V2_UNIVERSAL_GUI_PLAN.md §5.)"
        )
    # Ephemeral: ask the kernel for a free port on the same host.
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with closing(socket.socket(family, socket.SOCK_STREAM)) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


# --- desktop entry point ------------------------------------------------


def run_desktop(args: Any) -> int:
    """Entry point for ``yggdrasim --gui``.

    1. Resolve :class:`GuiServerConfig` (argparse + env + defaults).
    2. Pick a bindable port (fall back to ephemeral on EADDRINUSE).
    3. Start uvicorn in a background thread.
    4. Wait for readiness; bail out with a clear message on timeout.
    5. Open a pywebview window with the operator's page zoom
       (``YGGDRASIM_GUI_ZOOM``; Ctrl+plus / Ctrl+minus / Ctrl+0 in the
       window) and let its native event loop own the main thread. On
       close, cooperatively shut uvicorn down.
    """
    try:
        config = build_desktop_config(args)
    except SystemExit:
        raise
    except (OSError, ValueError, PermissionError) as error:
        print(f"[!] --gui config error: {error}", file=sys.stderr)
        return 2

    if importlib.util.find_spec("uvicorn") is None:
        print(
            "[!] --gui requires the optional dependencies. "
            "Install with: pip install 'yggdrasim[gui]'",
            file=sys.stderr,
        )
        return 3

    bound_port = _resolve_bound_port(
        config.host,
        config.port,
        allow_fallback=config.allow_ephemeral_port,
    )
    config.port = bound_port
    config.__post_init__()  # recompute base_url with the bound port

    app = create_app(config)
    runner = _build_uvicorn_runner(app, config)

    print("[+] YggdraSIM GUI (desktop) starting...")
    print(f"    URL:      {config.base_url}")
    print(f"    bind:     {config.host}:{config.port}")
    print(f"    token id: {config.redacted()['token_id']}")
    print(f"    PID:      {_current_pid()}")
    print(f"    zoom:     {config.webview_zoom}  (Ctrl+plus / Ctrl+minus / Ctrl+0 in the window)")
    if len(config.startup_open_paths) > 0:
        print(f"    open:     {', '.join(config.startup_open_paths)}")

    runner.start()
    if not runner.wait_ready(timeout=_READY_TIMEOUT_SECONDS):
        runner.stop()
        print("[!] GUI server did not report ready within 5 s; aborting.", file=sys.stderr)
        return 4

    try:
        _launch_pywebview(config)
    except SystemExit:
        raise
    finally:
        # Order matters. Cancelling first gives a running poll loop the
        # chance to unwind at its next checkpoint; forcing the server
        # down then drops whatever did not, so the window closing ends
        # the process instead of waiting on a cadence that never stops.
        cancelled = cancel_all_active_events()
        if cancelled > 0:
            _LOGGER.info("GUI shutdown cancelled %d in-flight run(s)", cancelled)
        runner.stop(force=True, timeout=_SHUTDOWN_SERVER_TIMEOUT_SECONDS)
        _cleanup_gui_runtime_on_shutdown(include_default_hil_service=True)
    return 0


# --- web-server entry point --------------------------------------------


def run_web_server(args: Any) -> int:
    """Entry point for ``yggdrasim --web-server``.

    Runs uvicorn on the main thread (no pywebview). Prints the banner
    with the full URL, token id (never the raw token), and a one-line
    SSH-tunnel recipe so the operator has a turnkey remote path.
    """
    try:
        config = build_web_server_config(args)
    except SystemExit:
        raise
    except (OSError, ValueError, PermissionError) as error:
        print(f"[!] --web-server config error: {error}", file=sys.stderr)
        return 2

    if importlib.util.find_spec("uvicorn") is None:
        print(
            "[!] --web-server requires the optional dependencies. "
            "Install with: pip install 'yggdrasim[gui-server]' (headless) "
            "or pip install 'yggdrasim[gui]' (with desktop mode).",
            file=sys.stderr,
        )
        return 3

    bound_port = _resolve_bound_port(
        config.host,
        config.port,
        allow_fallback=config.allow_ephemeral_port,
    )
    config.port = bound_port
    config.__post_init__()

    app = create_app(config)

    redacted = config.redacted()
    print("[+] YggdraSIM GUI (web-server) starting...")
    print(f"    URL:          {config.base_url}")
    print(f"    bind:         {config.host}:{config.port}")
    print(f"    TLS:          {'self-signed' if config.tls_self_signed else ('operator cert' if config.tls_cert_path else 'off (SSH tunnel recommended)')}")
    print(f"    token id:     {redacted['token_id']}")
    print(f"    idle cutoff:  {config.idle_seconds}s")
    if config.host == "0.0.0.0":
        print("[!] NOTE: binding 0.0.0.0 exposes the API beyond loopback.")
        print(f"    Consider --host 127.0.0.1 and `ssh -L {config.port}:localhost:{config.port} user@host`.")

    uvicorn_kwargs = _build_uvicorn_kwargs(app, config)
    import uvicorn
    try:
        uvicorn.run(**uvicorn_kwargs)
    except KeyboardInterrupt:
        pass
    return 0


# --- helpers ------------------------------------------------------------


def _current_pid() -> int:
    import os
    return os.getpid()


def _build_uvicorn_kwargs(app: Any, config: GuiServerConfig) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "app": app,
        "host": config.host,
        "port": int(config.port),
        "log_level": "warning",
        "access_log": False,
    }
    if config.tls_cert_path and config.tls_key_path:
        kwargs["ssl_certfile"] = config.tls_cert_path
        kwargs["ssl_keyfile"] = config.tls_key_path
    elif config.tls_self_signed:
        cert_path, key_path = _ensure_self_signed_tls()
        kwargs["ssl_certfile"] = cert_path
        kwargs["ssl_keyfile"] = key_path
    return kwargs


def _build_uvicorn_runner(app: Any, config: GuiServerConfig) -> _UvicornRunner:
    import uvicorn

    # Desktop force-stops uvicorn (force_exit) on window close so an idle
    # events WebSocket or a streaming action cannot hold shutdown open.
    # force_exit skips uvicorn's lifespan.shutdown(), orphaning the ASGI
    # lifespan task, which asyncio.run then cancels and logs as a
    # CancelledError traceback. Desktop cleanup runs in run_desktop's
    # finally (not the lifespan shutdown handler), so turn the lifespan
    # protocol off here -- nothing uses its startup. The web-server entry
    # point keeps it on: it has no finally and relies on that handler.
    uvicorn_config = uvicorn.Config(
        **_build_uvicorn_kwargs(app, config),
        lifespan="off",
    )
    return _UvicornRunner(uvicorn_config)


def _register_shutdown_handler(app: Any, handler: Any) -> None:
    """Register GUI cleanup across FastAPI/Starlette lifecycle variants."""
    add_event_handler = getattr(app, "add_event_handler", None)
    if callable(add_event_handler):
        add_event_handler("shutdown", handler)
        return

    router = getattr(app, "router", None)
    router_add_event_handler = getattr(router, "add_event_handler", None)
    if callable(router_add_event_handler):
        router_add_event_handler("shutdown", handler)
        return

    on_shutdown = getattr(router, "on_shutdown", None)
    if isinstance(on_shutdown, list):
        on_shutdown.append(handler)
        return

    _LOGGER.warning("GUI shutdown cleanup could not be registered on this FastAPI stack.")


def _cleanup_gui_runtime_on_shutdown(
    *,
    include_default_hil_service: bool,
    timeout: float = _SHUTDOWN_CLEANUP_TIMEOUT_SECONDS,
) -> None:
    """Release resources owned by the GUI server process.

    Cleanup stops external services and terminates registered child
    processes, any of which can block on a process that will not die. It
    therefore runs on a daemon thread with a deadline: closing the window
    has to end the application even when a service refuses to stop.
    """
    try:
        from yggdrasim_common.gui_server.lifecycle import cleanup_gui_runtime
    except Exception as error:  # noqa: BLE001
        _LOGGER.warning("GUI shutdown cleanup unavailable: %s", error)
        return

    def _run() -> None:
        summary = cleanup_gui_runtime(
            stop_external_services=True,
            include_default_hil_service=include_default_hil_service,
            include_card_bridge_state=include_default_hil_service,
        )
        _LOGGER.info("GUI shutdown cleanup: %s", summary)

    worker = threading.Thread(
        target=_run,
        name="yggdrasim-gui-shutdown-cleanup",
        daemon=True,
    )
    worker.start()
    worker.join(timeout=max(0.0, float(timeout)))
    if worker.is_alive():
        _LOGGER.warning(
            "GUI shutdown cleanup exceeded %.1f s; exiting anyway", timeout
        )


def _ensure_self_signed_tls() -> tuple[str, str]:
    """Generate a one-time self-signed TLS pair under ``state/gui_tls/``.

    Uses :mod:`cryptography` which is already a hard dependency of
    YggdraSIM, so self-signed mode adds no new install surface. Prints
    the SHA-256 fingerprint so the operator can pin it manually in the
    browser / client.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    from yggdrasim_common.runtime_paths import runtime_path

    tls_dir = Path(runtime_path("state", "gui_tls"))
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_path = tls_dir / "selfsigned.crt.pem"
    key_path = tls_dir / "selfsigned.key.pem"

    if cert_path.is_file() and key_path.is_file():
        _emit_tls_fingerprint(cert_path)
        return str(cert_path), str(key_path)

    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "yggdrasim-gui-selfsigned"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
    ])
    not_before = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
    not_after = not_before + timedelta(days=365)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

    cert_path.write_bytes(cert_bytes)
    key_path.write_bytes(key_bytes)
    try:
        key_path.chmod(0o600)
        cert_path.chmod(0o644)
    except OSError:
        pass

    print(f"[*] Wrote self-signed TLS pair to {tls_dir}")
    _emit_tls_fingerprint(cert_path)
    return str(cert_path), str(key_path)


def _emit_tls_fingerprint(cert_path: Path) -> None:
    import hashlib

    raw = cert_path.read_bytes()
    fingerprint = hashlib.sha256(raw).hexdigest().upper()
    formatted = ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))
    print(f"[*] Self-signed cert SHA-256: {formatted}")


def _first_dialog_path(result: Any) -> str:
    """Normalise ``create_file_dialog`` return values to a single string.

    Different pywebview backends return either ``None``, a ``str``, a
    ``tuple[str]`` or a ``list[str]`` depending on the platform. We
    collapse everything to the first path so the SPA sees a uniform
    string.
    """
    if result is None:
        return ""
    if isinstance(result, (list, tuple)):
        if len(result) == 0:
            return ""
        first = result[0]
        return "" if first is None else str(first)
    return str(result)


class _PywebviewJsBridge:
    """Native-file-dialog and window-close bridge exposed to the SPA as ``pywebview.api``.

    Each method returns a plain string (or ``""`` when the user cancels)
    so the JS side never has to worry about tuples, arrays, or platform
    quirks. ``save_file`` returns the chosen destination path as-is -- the
    SPA is responsible for appending a default filename if the user
    picked an empty location. ``close_app`` destroys the window; the
    ``run_desktop`` ``finally`` owns teardown once ``webview.start``
    returns, so the bridge does not cancel events or stop the server.
    """

    def __init__(self) -> None:
        self._webview = None  # set lazily via :meth:`attach`

    def attach(self, webview_module: Any) -> None:
        self._webview = webview_module

    def file_picker_mode(self) -> str:
        """Return the configured file-picker mode for the SPA."""
        raw = os.environ.get(_GUI_FILE_PICKER_ENV, "").strip().lower()
        if raw in _GUI_FILE_PICKER_NATIVE_VALUES:
            return "native"
        return "web"

    def _active_window(self) -> Any:
        if self._webview is None:
            raise RuntimeError("pywebview bridge not attached yet")
        windows = getattr(self._webview, "windows", None) or []
        if len(windows) == 0:
            raise RuntimeError("no active pywebview window")
        return windows[0]

    def pick_file(
        self,
        default_path: str = "",
        file_types: Optional[list[str]] = None,
        allow_multiple: bool = False,
    ) -> str:
        """Open a native *open-file* dialog. Returns ``""`` on cancel."""
        try:
            window = self._active_window()
            types = tuple(file_types or ())
            result = window.create_file_dialog(
                self._webview.OPEN_DIALOG,  # type: ignore[union-attr]
                directory=str(default_path or ""),
                allow_multiple=bool(allow_multiple),
                file_types=types,
            )
        except Exception:  # noqa: BLE001 -- surface to JS
            return ""
        return _first_dialog_path(result)

    def pick_folder(self, default_path: str = "") -> str:
        """Open a native *select-folder* dialog. Returns ``""`` on cancel."""
        try:
            window = self._active_window()
            result = window.create_file_dialog(
                self._webview.FOLDER_DIALOG,  # type: ignore[union-attr]
                directory=str(default_path or ""),
            )
        except Exception:  # noqa: BLE001
            return ""
        return _first_dialog_path(result)

    def save_file(
        self,
        default_path: str = "",
        save_filename: str = "",
        file_types: Optional[list[str]] = None,
    ) -> str:
        """Open a native *save-as* dialog. Returns ``""`` on cancel."""
        try:
            window = self._active_window()
            types = tuple(file_types or ())
            result = window.create_file_dialog(
                self._webview.SAVE_DIALOG,  # type: ignore[union-attr]
                directory=str(default_path or ""),
                save_filename=str(save_filename or ""),
                file_types=types,
            )
        except Exception:  # noqa: BLE001
            return ""
        return _first_dialog_path(result)

    def close_app(self) -> bool:
        """Destroy the desktop WebView window so ``webview.start`` returns.

        On the Qt backend ``destroy`` emits ``destroy_trigger`` -- a Qt
        signal delivered to the GUI thread via a queued connection -- so
        calling it from this js_api worker thread is safe. The window
        closing unblocks ``webview.start`` in ``run_desktop``, whose
        ``finally`` cancels in-flight runs, force-stops uvicorn, and runs
        cleanup.
        """
        try:
            window = self._active_window()
            destroy = getattr(window, "destroy", None)
            if callable(destroy):
                destroy()
                return True
            close = getattr(window, "close", None)
            if callable(close):
                close()
                return True
        except Exception:  # noqa: BLE001
            return False
        return False


def _qt_backend_available() -> bool:
    """Return ``True`` when pywebview's Qt path has a plausible binding."""
    return importlib.util.find_spec("qtpy") is not None


def _gtk_backend_available() -> bool:
    """Return ``True`` when Linux GTK + WebKit introspection can load."""
    if importlib.util.find_spec("gi") is None:
        return False
    try:
        import gi  # type: ignore

        gi.require_version("Gtk", "3.0")
        gi.require_version("Gdk", "3.0")
        try:
            gi.require_version("WebKit2", "4.1")
            gi.require_version("Soup", "3.0")
        except (ValueError, AttributeError):
            try:
                gi.require_version("WebKit2", "4.0")
                gi.require_version("Soup", "2.4")
            except (ValueError, AttributeError):
                return False
        from gi.repository import Gdk  # type: ignore  # noqa: F401
        from gi.repository import Gtk  # type: ignore  # noqa: F401
        from gi.repository import WebKit2  # type: ignore  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def _select_pywebview_backend() -> str | None:
    """Choose a pywebview backend without importing the backend itself."""
    forced = str(os.environ.get(_PYWEBVIEW_GUI_ENV, "") or "").strip().lower()
    if forced in {"qt", "gtk", "cef", "mshtml", "edgechromium"}:
        return forced

    if sys.platform.startswith("linux"):
        if "KDE_FULL_SESSION" in os.environ and _qt_backend_available():
            return "qt"
        if not _gtk_backend_available() and _qt_backend_available():
            return "qt"
    return None


def _append_env_words(name: str, values: tuple[str, ...]) -> None:
    existing = str(os.environ.get(name, "") or "").strip()
    words = existing.split() if existing else []
    seen = set(words)
    for value in values:
        if value not in seen:
            words.append(value)
            seen.add(value)
    if words:
        os.environ[name] = " ".join(words)


def _qtwebengine_flags(gpu: bool) -> tuple[str, ...]:
    """The Chromium switches the Qt window starts with; ``gpu`` drops the GPU-off ones."""
    if not gpu:
        return _QTWEBENGINE_DEFAULT_FLAGS
    return tuple(flag for flag in _QTWEBENGINE_DEFAULT_FLAGS if flag not in _QTWEBENGINE_GPU_OFF_FLAGS)


def _prepare_webview_environment(backend: str | None) -> None:
    """Apply backend-specific process limits before pywebview imports it."""
    if backend != "qt":
        return
    _append_env_words(
        _QTWEBENGINE_CHROMIUM_FLAGS_ENV,
        _qtwebengine_flags(webview_gpu_enabled()),
    )


def _apply_window_identity(backend: str | None) -> None:
    """Name the desktop window ``_DESKTOP_APP_ID`` instead of the interpreter.

    Both toolkits read the name before their application object exists,
    so this runs ahead of ``webview.start``. Only the Wayland app_id
    changes: under X11 Qt takes WM_CLASS from ``argv[0]`` and ignores the
    desktop file name, so an X11 window rule written against the old
    class keeps matching. A window that opens under the wrong name is a
    cosmetic fault, so a toolkit that cannot be imported here leaves the
    identity alone rather than failing the launch.
    """
    if not sys.platform.startswith("linux"):
        return
    if backend == "qt":
        try:
            from PyQt6.QtGui import QGuiApplication  # type: ignore
        except ImportError:
            return
        QGuiApplication.setDesktopFileName(_DESKTOP_APP_ID)
        return
    try:
        from gi.repository import GLib  # type: ignore
    except ImportError:
        return
    GLib.set_prgname(_DESKTOP_APP_ID)


def _webview_storage_path() -> str:
    """Return the persistent pywebview profile directory under runtime state."""
    from yggdrasim_common.runtime_paths import ensure_runtime_dir

    return ensure_runtime_dir("state", "gui_webview_profile")


# --- desktop window zoom ------------------------------------------------
# The SPA's layout is drawn for the 1280 x 800 window ``create_window``
# opens; on a larger display the operator may want it bigger. Desktop
# mode therefore manages the WebView's page zoom -- the same operation
# as Ctrl-plus in a browser, so viewport units, media queries, pointer
# coordinates and xterm's cell metrics stay consistent, which a CSS
# ``zoom`` on the document would not give. The setting is the
# ``YGGDRASIM_GUI_ZOOM`` env flag (editable in Configuration): ``1`` is
# the native size, a factor pins the zoom, ``auto`` fits the layout to
# the window. Ctrl+plus / Ctrl+minus / Ctrl+0 and Ctrl+wheel in the
# window step the zoom and write the factor back to the flag, so it is
# remembered; the window polls the flag so an edit made in
# Configuration applies without a relaunch.
_WEBVIEW_REFERENCE_SIZE = (1280, 800)
_WEBVIEW_AUTO_ZOOM_FLOOR = 1.0
_WEBVIEW_AUTO_ZOOM_CEILING = 2.0
_WEBVIEW_AUTO_ZOOM_STEP = 0.05
_WEBVIEW_ZOOM_POLL_MS = 1000


def auto_zoom_factor(
    width: Any,
    height: Any,
    *,
    reference: tuple[int, int] = _WEBVIEW_REFERENCE_SIZE,
    floor: float = _WEBVIEW_AUTO_ZOOM_FLOOR,
    ceiling: float = _WEBVIEW_AUTO_ZOOM_CEILING,
    step: float = _WEBVIEW_AUTO_ZOOM_STEP,
) -> float:
    """Return the page zoom that fits the reference layout into ``width`` x ``height``.

    The smaller of the two ratios keeps the whole reference layout
    visible. The result is rounded down to ``step`` so a drag resize does
    not relayout the page on every pixel, then clamped to
    ``floor``..``ceiling``. Below the reference size the factor stays at
    ``floor`` and the stylesheet's own breakpoints take over.
    """
    try:
        w = float(width)
        h = float(height)
    except (TypeError, ValueError):
        return floor
    if not (w > 0 and h > 0):
        return floor
    factor = min(w / reference[0], h / reference[1])
    factor = math.floor(factor / step + 1e-9) * step
    return round(min(max(factor, floor), ceiling), 2)


def zoom_step(current: Any, direction: int, *, ladder: tuple[float, ...] = WEBVIEW_ZOOM_LADDER) -> float:
    """Return the ladder value one step above (``direction > 0``) or below ``current``.

    ``current`` need not sit on the ladder; the ends clamp.
    """
    try:
        value = float(current)
    except (TypeError, ValueError):
        value = 1.0
    if direction > 0:
        for rung in ladder:
            if rung > value + 1e-9:
                return rung
        return ladder[-1]
    for rung in reversed(ladder):
        if rung < value - 1e-9:
            return rung
    return ladder[0]


def _zoom_policy(setting: Any) -> Callable[[Any, Any], float]:
    """Map a zoom setting (``auto`` or a factor) to a ``(width, height) -> factor`` callable."""
    text = normalize_webview_zoom(setting)
    if text == WEBVIEW_ZOOM_AUTO:
        return auto_zoom_factor
    fixed = float(text)

    def fixed_policy(_width: Any, _height: Any) -> float:
        return fixed

    return fixed_policy


def _zoom_setting_raw() -> str:
    """The zoom flag's current value, as set in the process environment."""
    flag = env_flags.get_flag(ENV_GUI_ZOOM)
    if flag is not None:
        return env_flags.get_flag_value(flag).strip()
    return str(os.environ.get(ENV_GUI_ZOOM, "") or "").strip()


def _remember_zoom(text: str) -> None:
    """Write ``text`` back to the zoom flag (blank clears it), persisted through the registry."""
    flag = env_flags.get_flag(ENV_GUI_ZOOM)
    try:
        if flag is not None:
            env_flags.set_flag_value(flag, text)
        elif text:
            os.environ[ENV_GUI_ZOOM] = text
        else:
            os.environ.pop(ENV_GUI_ZOOM, None)
    except (OSError, ValueError) as error:
        _LOGGER.warning("desktop zoom could not be remembered: %s", error)


def _key_code(value: Any) -> int:
    """Integer key code for a Qt key, whether the binding hands out ints or enums."""
    return int(getattr(value, "value", value))


def _zoom_target(native: Any) -> Optional[tuple[str, Any]]:
    """Classify a pywebview native handle: ``("qt", view)``, ``("gtk", window)`` or ``None``.

    pywebview's Qt backend hands out its ``BrowserView`` (the web view is
    its ``webview`` attribute); the GTK backend hands out the
    ``Gtk.Window`` and keeps the WebKit view among its children.
    """
    if native is None:
        return None
    view = getattr(native, "webview", None)
    if view is not None and hasattr(view, "setZoomFactor"):
        return "qt", view
    if hasattr(native, "get_children") and hasattr(native, "connect"):
        return "gtk", native
    return None


def _install_window_zoom(window: Any, policy: Callable[[Any, Any], float]) -> None:
    """Bind the zoom controls to the native window once it exists.

    pywebview runs each event's handlers on a fresh thread, so the
    handler registered here only decides when the native window exists
    and hands over to the toolkit; every toolkit call happens on the
    toolkit's own thread inside the attach functions. The first event
    that finds the native window attaches; the rest are no-ops.
    """
    lock = threading.Lock()
    state: dict[str, Any] = {"attached": False}

    def bootstrap(*_args: Any, **_kwargs: Any) -> None:
        with lock:
            if state["attached"]:
                return
            target = _zoom_target(getattr(window, "native", None))
            if target is None:
                return  # native window not up yet, or a backend without a zoom hook
            kind, handle = target
            state["attached"] = True
            try:
                if kind == "qt":
                    state["controller"] = _attach_qt_zoom(window, handle, policy)
                else:
                    state["controller"] = _attach_gtk_zoom(window, handle, policy)
            except Exception:  # noqa: BLE001 -- zoom is a convenience, never a reason to lose the window
                _LOGGER.exception("desktop zoom could not attach to the %s window", kind)

    for name in ("shown", "loaded", "resized"):
        event = getattr(window.events, name, None)
        if event is not None:
            event += bootstrap


def _attach_qt_zoom(window: Any, view: Any, policy: Callable[[Any, Any], float]) -> Any:
    """Create the Qt-side controller and apply the current setting.

    Called on a pywebview handler thread. The controller is a ``QObject``
    moved to the GUI thread and started by a posted event, which Qt
    delivers in the receiver's own thread (a signal connected to a
    Python method keeps its proxy in the connecting thread and would run
    the slot there). On the GUI thread it filters the ``BrowserView``'s
    resize events (for ``auto``), the application's key and wheel events
    (the shortcuts, wherever focus sits) and polls the flag once a
    second, so no Qt call ever crosses a thread.
    """
    from qtpy import QtCore, QtWidgets  # the binding pywebview's Qt backend runs on

    def enum(scope: Any, name: str, nested: str) -> Any:
        # qtpy promotes scoped enums to the scope; fall back to the scoped form.
        value = getattr(scope, name, None)
        return value if value is not None else getattr(getattr(scope, nested), name)

    qt = QtCore.Qt
    type_resize = enum(QtCore.QEvent, "Resize", "Type")
    type_key_press = enum(QtCore.QEvent, "KeyPress", "Type")
    type_wheel = enum(QtCore.QEvent, "Wheel", "Type")
    control = enum(qt, "ControlModifier", "KeyboardModifier")
    keys_in = {_key_code(enum(qt, name, "Key")) for name in ("Key_Plus", "Key_Equal")}
    keys_out = {_key_code(enum(qt, name, "Key")) for name in ("Key_Minus", "Key_Underscore")}
    keys_reset = {_key_code(enum(qt, "Key_0", "Key"))}
    type_start = enum(QtCore.QEvent, "User", "Type")

    class _ZoomController(QtCore.QObject):
        def __init__(self) -> None:
            super().__init__()
            self._native: Any = None
            self._factor: Optional[float] = None
            self._raw: Optional[str] = None
            self._policy = policy
            self._timer: Any = None

        # -- everything below runs on the GUI thread --

        def customEvent(self, event: Any) -> None:  # Qt override
            if event.type() == type_start:
                self._start()

        def _start(self) -> None:
            native = getattr(window, "native", None)
            app = QtWidgets.QApplication.instance()
            if native is None or app is None:
                return
            if QtCore.QThread.currentThread() != app.thread():
                _LOGGER.error("desktop zoom started off the GUI thread; leaving the zoom alone")
                return
            if self._native is None:
                self._native = native
                native.installEventFilter(self)  # resize
                app.installEventFilter(self)  # keys and wheel, wherever focus sits
                self._timer = QtCore.QTimer(self)
                self._timer.setInterval(_WEBVIEW_ZOOM_POLL_MS)
                self._timer.timeout.connect(self._sync)
                self._timer.start()
            self._sync()

        def _sync(self) -> None:
            raw = _zoom_setting_raw()
            if raw != self._raw:
                self._raw = raw
                self._policy = _zoom_policy(raw)
            self._fit()

        def _fit(self) -> None:
            try:
                width, height = self._native.width(), self._native.height()
            except RuntimeError:  # the window is gone; stop polling
                if self._timer is not None:
                    self._timer.stop()
                return
            self._set(self._policy(width, height))

        def _set(self, factor: Optional[float]) -> None:
            if factor is None or factor == self._factor:
                return
            self._factor = factor
            view.setZoomFactor(factor)
            _LOGGER.debug("desktop zoom %.2f", factor)

        def _choose(self, factor: float, *, remembered: Optional[str] = None) -> None:
            """Apply a factor the operator picked and remember it (``None`` = the factor itself)."""
            self._set(factor)
            _remember_zoom(format(factor, "g") if remembered is None else remembered)
            self._raw = _zoom_setting_raw()
            self._policy = _zoom_policy(self._raw)

        def _nudge(self, direction: int) -> None:
            current = self._factor if self._factor is not None else view.zoomFactor()
            self._choose(zoom_step(current, direction))

        def eventFilter(self, watched: Any, event: Any) -> bool:  # Qt override
            kind = event.type()
            if kind == type_resize:
                if watched is self._native:
                    self._fit()
                return False
            if kind == type_key_press:
                if not (event.modifiers() & control):
                    return False
                code = _key_code(event.key())
                if code in keys_in:
                    self._nudge(1)
                    return True
                if code in keys_out:
                    self._nudge(-1)
                    return True
                if code in keys_reset:
                    self._choose(1.0, remembered="")
                    return True
                return False
            if kind == type_wheel:
                if not (event.modifiers() & control):
                    return False
                delta = event.angleDelta().y()
                if delta:
                    self._nudge(1 if delta > 0 else -1)
                return True
            return False

    app = QtWidgets.QApplication.instance()
    if app is None:
        raise RuntimeError("no QApplication; pywebview's Qt backend is not running")
    controller = _ZoomController()
    controller.moveToThread(app.thread())
    QtCore.QCoreApplication.postEvent(controller, QtCore.QEvent(type_start))
    return controller


def _attach_gtk_zoom(window: Any, gtk_window: Any, policy: Callable[[Any, Any], float]) -> Any:
    """GTK counterpart of :func:`_attach_qt_zoom`, run on the GTK main loop.

    pywebview's GTK backend exposes the ``Gtk.Window``; the WebKit view is
    found among its children by its ``set_zoom_level`` method. A missing
    view only logs.
    """
    from gi.repository import Gdk, GLib  # pywebview's GTK backend is already up

    control = Gdk.ModifierType.CONTROL_MASK
    state: dict[str, Any] = {"view": None, "factor": None, "raw": None, "policy": policy}

    def find_view(widget: Any) -> Any:
        if hasattr(widget, "set_zoom_level"):
            return widget
        children = widget.get_children() if hasattr(widget, "get_children") else ()
        for child in children:
            found = find_view(child)
            if found is not None:
                return found
        return None

    def set_factor(factor: Optional[float]) -> None:
        if factor is None or factor == state["factor"]:
            return
        state["factor"] = factor
        state["view"].set_zoom_level(factor)

    def fit() -> None:
        allocation = gtk_window.get_allocation()
        set_factor(state["policy"](allocation.width, allocation.height))

    def sync() -> bool:
        raw = _zoom_setting_raw()
        if raw != state["raw"]:
            state["raw"] = raw
            state["policy"] = _zoom_policy(raw)
        fit()
        return True  # keep the timeout alive

    def choose(factor: float, *, remembered: Optional[str] = None) -> None:
        set_factor(factor)
        _remember_zoom(format(factor, "g") if remembered is None else remembered)
        state["raw"] = _zoom_setting_raw()
        state["policy"] = _zoom_policy(state["raw"])

    def nudge(direction: int) -> None:
        current = state["factor"] if state["factor"] is not None else state["view"].get_zoom_level()
        choose(zoom_step(current, direction))

    def on_key(_widget: Any, event: Any) -> bool:
        if not (event.state & control):
            return False
        name = Gdk.keyval_name(event.keyval) or ""
        if name in ("plus", "equal", "KP_Add"):
            nudge(1)
            return True
        if name in ("minus", "underscore", "KP_Subtract"):
            nudge(-1)
            return True
        if name in ("0", "KP_0"):
            choose(1.0, remembered="")
            return True
        return False

    def on_scroll(_widget: Any, event: Any) -> bool:
        if not (event.state & control):
            return False
        if event.direction == Gdk.ScrollDirection.UP:
            nudge(1)
        elif event.direction == Gdk.ScrollDirection.DOWN:
            nudge(-1)
        elif event.direction == Gdk.ScrollDirection.SMOOTH:
            has_deltas, _dx, dy = event.get_scroll_deltas()
            if has_deltas and dy:
                nudge(-1 if dy > 0 else 1)
        return True

    def attach() -> bool:  # GTK main loop, once
        view = find_view(gtk_window)
        if view is None:
            _LOGGER.warning("desktop zoom: no WebKit view under the GTK window")
            return False
        state["view"] = view
        gtk_window.connect("size-allocate", lambda *_args: fit())
        gtk_window.connect("key-press-event", on_key)
        view.connect("scroll-event", on_scroll)
        GLib.timeout_add(_WEBVIEW_ZOOM_POLL_MS, sync)
        sync()
        return False

    GLib.idle_add(attach)
    return state


def _launch_pywebview(config: GuiServerConfig) -> None:
    """Open the native WebView window and block until it closes."""
    backend = _select_pywebview_backend()
    _prepare_webview_environment(backend)
    _apply_window_identity(backend)

    try:
        import webview  # type: ignore
    except ImportError as error:
        raise SystemExit(
            "--gui needs pywebview. Install with: pip install 'yggdrasim[gui]'\n"
            f"(underlying import error: {error})"
        )

    # Token is passed via query string on first load; the SPA bootstrap
    # is expected to strip it and promote it to sessionStorage.
    url = f"{config.base_url}/?t={config.token}"

    bridge = _PywebviewJsBridge()
    bridge.attach(webview)
    # The page learns where a dropped file lives through
    # ``/api/gui/native_drop/resolve``; pywebview records the paths only
    # while this switch is on (native_drops.py).
    from yggdrasim_common.gui_server.native_drops import enable_native_drop_capture

    enable_native_drop_capture()

    window = webview.create_window(
        title="YggdraSIM",
        url=url,
        width=1280,
        height=800,
        resizable=True,
        confirm_close=False,
        js_api=bridge,
    )
    _install_window_zoom(window, _zoom_policy(config.webview_zoom))
    # ``private_mode=False`` so the embedded WebView keeps a persistent
    # storage profile on disk. Operator-facing preferences (theme
    # selection, recent SAIP packages, sidebar / topbar collapse state)
    # all live in ``window.localStorage`` and would otherwise be
    # discarded on every launcher restart.
    webview.start(
        debug=bool(config.webview_debug),
        gui=backend,
        private_mode=False,
        storage_path=_webview_storage_path(),
    )
