# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""FastAPI app factory + two entry points for the universal GUI.

This module is the single place where ``fastapi``, ``uvicorn``, and
``pywebview`` imports happen. None of them are resolved unless
:func:`run_desktop` or :func:`run_web_server` is called, which keeps
``pip install yggdrasim`` (no extras) lean per the §16.5 acceptance
criterion in ``V2_UNIVERSAL_GUI_PLAN.md``.

The two public entry points mirror the CLI flag shape:

* :func:`run_desktop` — ``yggdrasim --gui``. Spawns uvicorn on a
  loopback port in a background thread, opens a ``pywebview`` window
  pointed at the resolved URL, and waits for the window to close.
* :func:`run_web_server` — ``yggdrasim --web-server``. Spawns uvicorn
  on the configured interface, refuses an ephemeral port fallback,
  and prints the banner expected by the operator runbook.
"""

from __future__ import annotations

import errno
import importlib.util
import logging
import os
import socket
import sys
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Optional

from .auth import AuthMiddleware, FailureRateLimiter
from .config import (
    GuiServerConfig,
    MODE_DESKTOP,
    build_desktop_config,
    build_web_server_config,
)


_LOGGER = logging.getLogger("yggdrasim.gui.app")


# --- readiness probe ----------------------------------------------------


_READY_TIMEOUT_SECONDS = 5.0
_STATIC_DIR = Path(__file__).resolve().parent / "static"
_PYWEBVIEW_GUI_ENV = "PYWEBVIEW_GUI"
_GUI_FILE_PICKER_ENV = "YGGDRASIM_GUI_FILE_PICKER"
_GUI_FILE_PICKER_WEB_VALUES = frozenset(("web", "browser", "in-app", "in_app"))
_GUI_FILE_PICKER_NATIVE_VALUES = frozenset(("native", "os", "qt", "system"))
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
_DESKTOP_FORCE_EXIT_DELAY_SECONDS = 1.0


class _UvicornRunner:
    """Thin wrapper around ``uvicorn.Server`` that can run in a thread.

    Exposes ``started`` and ``should_exit`` so the desktop entry point
    can wait for readiness and request a clean shutdown when the
    pywebview window closes.
    """

    def __init__(self, config: Any) -> None:
        import uvicorn  # local import — only when running

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

    def stop(self) -> None:
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10.0)


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
        redoc_url=None,     # ditto — lab-server surface must stay narrow
        openapi_url="/api/openapi.json",
    )
    app.state.started_monotonic = time.monotonic()
    app.state.gui_mode = config.mode
    app.state.gui_config_redacted = config.redacted()
    # Raw token is needed by the WebSocket terminal bridge because
    # BaseHTTPMiddleware only runs on "http" scope — WS handshakes bypass
    # it entirely, so the WS handler does its own token compare.
    app.state.gui_token = config.token

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

    app.include_router(health_routes.router)
    app.include_router(registry_routes.router)
    app.include_router(backend_routes.router)
    app.include_router(env_flag_routes.router)
    app.include_router(tools_routes.router)
    app.include_router(terminal_routes.router)
    app.include_router(live_routes.router)
    app.include_router(actions_routes.router)
    app.include_router(apdu_event_routes.router)
    app.include_router(guides_routes.router)
    app.include_router(fs_browse_routes.router)
    app.include_router(remote_lab_routes.router)
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
            "gui_server: static bundle missing at %s — SPA will 404. "
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
            f"GUI server cannot bind {host}:{initial_port} — port in use. "
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
    5. Open a pywebview window and let its native event loop own the
       main thread. On close, cooperatively shut uvicorn down.
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
        runner.stop()
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

    uvicorn_config = uvicorn.Config(**_build_uvicorn_kwargs(app, config))
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


def _cleanup_gui_runtime_on_shutdown(*, include_default_hil_service: bool) -> None:
    """Release resources owned by the GUI server process."""
    try:
        from yggdrasim_common.gui_server.lifecycle import cleanup_gui_runtime
    except Exception as error:  # noqa: BLE001
        _LOGGER.warning("GUI shutdown cleanup unavailable: %s", error)
        return
    summary = cleanup_gui_runtime(
        stop_external_services=True,
        include_default_hil_service=include_default_hil_service,
        include_card_bridge_state=include_default_hil_service,
    )
    _LOGGER.info("GUI shutdown cleanup: %s", summary)


def _request_desktop_close_shutdown() -> None:
    """Run desktop cleanup and ensure pywebview cannot leave the process alive."""
    try:
        _cleanup_gui_runtime_on_shutdown(include_default_hil_service=True)
    finally:
        _schedule_desktop_process_exit()


def _schedule_desktop_process_exit(
    *,
    delay_seconds: float = _DESKTOP_FORCE_EXIT_DELAY_SECONDS,
) -> None:
    """Force-exit the desktop host if pywebview does not unwind cleanly."""

    def _exit_process() -> None:
        os._exit(0)

    timer = threading.Timer(max(0.0, float(delay_seconds)), _exit_process)
    timer.daemon = True
    timer.start()


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


class _PywebviewJsBridge:
    """Native-file-dialog bridge exposed to the SPA as ``pywebview.api``.

    Each method returns a plain string (or ``""`` when the user cancels)
    so the JS side never has to worry about tuples, arrays, or platform
    quirks. ``save_file`` returns the chosen destination path as-is — the
    SPA is responsible for appending a default filename if the user
    picked an empty location.
    """

    def __init__(self, on_close_requested: Callable[[], None] | None = None) -> None:
        self._webview = None  # set lazily via :meth:`attach`
        self._on_close_requested = on_close_requested

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
        except Exception:  # noqa: BLE001 — surface to JS
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
        """Clean up GUI-owned processes and close the desktop WebView window."""
        if self._on_close_requested is not None:
            try:
                self._on_close_requested()
            except Exception as error:  # noqa: BLE001
                _LOGGER.warning("desktop close cleanup failed: %s", error)
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


def _prepare_webview_environment(backend: str | None) -> None:
    """Apply backend-specific process limits before pywebview imports it."""
    if backend != "qt":
        return
    _append_env_words(
        _QTWEBENGINE_CHROMIUM_FLAGS_ENV,
        _QTWEBENGINE_DEFAULT_FLAGS,
    )


def _webview_storage_path() -> str:
    """Return the persistent pywebview profile directory under runtime state."""
    from yggdrasim_common.runtime_paths import ensure_runtime_dir

    return ensure_runtime_dir("state", "gui_webview_profile")


def _launch_pywebview(config: GuiServerConfig) -> None:
    """Open the native WebView window and block until it closes."""
    backend = _select_pywebview_backend()
    _prepare_webview_environment(backend)

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

    bridge = _PywebviewJsBridge(on_close_requested=_request_desktop_close_shutdown)
    bridge.attach(webview)

    window = webview.create_window(
        title="YggdraSIM",
        url=url,
        width=1280,
        height=800,
        resizable=True,
        confirm_close=False,
        js_api=bridge,
    )
    _ = window  # hold a reference; webview.start consumes it
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
