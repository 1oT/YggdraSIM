# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Configuration dataclass for the YggdraSIM universal GUI server.

The two entry points (:func:`run_desktop`, :func:`run_web_server` in
``app.py``) both need the same shape of settings: bind host, bind port,
bearer token, optional TLS material, path allow-list, and a handful of
session knobs. This module centralises the argparse + env-flag + default
merge so the server itself only has to consume a :class:`GuiServerConfig`
instance.

Design rules honoured here:

* No FastAPI / uvicorn / pywebview imports — this module is safe to
  import from anywhere, including ``main/main.py``'s argparse path,
  without dragging in the GUI optional dependencies.
* Tokens are only ever held inside a ``GuiServerConfig`` for the
  duration of a process. They are never written to disk by this module
  (the operator supplies a token file or an env var); see
  ``V2_UNIVERSAL_GUI_PLAN.md`` §9.2 for the security posture.
* Unknown env values fall back to documented defaults with a single
  ``_LOGGER.warning`` so a typo does not silently escalate privileges.
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


_LOGGER = logging.getLogger(__name__)


# --- env-flag names (mirrors V2_UNIVERSAL_GUI_PLAN §10) ------------------

ENV_GUI_HOST = "YGGDRASIM_GUI_HOST"
ENV_GUI_PORT = "YGGDRASIM_GUI_PORT"
ENV_GUI_SERVER_HOST = "YGGDRASIM_GUI_SERVER_HOST"
ENV_GUI_SERVER_PORT = "YGGDRASIM_GUI_SERVER_PORT"
ENV_GUI_TOKEN = "YGGDRASIM_GUI_TOKEN"
ENV_GUI_TOKEN_FILE = "YGGDRASIM_GUI_TOKEN_FILE"
ENV_GUI_TLS_CERT = "YGGDRASIM_GUI_TLS_CERT"
ENV_GUI_TLS_KEY = "YGGDRASIM_GUI_TLS_KEY"
ENV_GUI_ALLOW_ORIGIN = "YGGDRASIM_GUI_ALLOW_ORIGIN"
ENV_GUI_IDLE_SECONDS = "YGGDRASIM_GUI_IDLE_SECONDS"
ENV_GUI_PATH_ALLOWLIST = "YGGDRASIM_GUI_PATH_ALLOWLIST"
ENV_GUI_WEBVIEW_DEBUG = "YGGDRASIM_GUI_WEBVIEW_DEBUG"


# --- defaults -----------------------------------------------------------

DEFAULT_DESKTOP_HOST = "127.0.0.1"
DEFAULT_DESKTOP_PORT = 27853
DEFAULT_SERVER_HOST = "0.0.0.0"
DEFAULT_SERVER_PORT = 27854
DEFAULT_IDLE_SECONDS = 1800

# Entropy floor per §9.2 — any bearer that decodes smaller than this is
# refused before the server is allowed to start.
MIN_TOKEN_ENTROPY_CHARS = 32


# --- modes --------------------------------------------------------------

MODE_DESKTOP = "desktop"
MODE_WEB_SERVER = "web_server"


@dataclass
class GuiServerConfig:
    """Resolved GUI server configuration.

    Values here carry the final merged result of argparse flags,
    environment variables, and defaults — in that order of precedence.
    The dataclass is *not* frozen: :func:`app.run_desktop` needs to
    mutate ``port`` after a graceful fallback to an ephemeral port on
    ``EADDRINUSE``. All mutations happen inside the server module, never
    from user code.
    """

    mode: str
    host: str
    port: int
    token: str
    idle_seconds: int = DEFAULT_IDLE_SECONDS
    allow_origins: tuple[str, ...] = field(default_factory=tuple)
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None
    tls_self_signed: bool = False
    path_allowlist: tuple[str, ...] = field(default_factory=tuple)
    webview_debug: bool = False
    allow_ephemeral_port: bool = True
    # Computed in __post_init__; handy for log messages and the banner.
    base_url: str = ""

    def __post_init__(self) -> None:
        if self.mode not in (MODE_DESKTOP, MODE_WEB_SERVER):
            raise ValueError(f"Unknown GUI server mode: {self.mode!r}")
        if int(self.port) < 0 or int(self.port) > 65535:
            raise ValueError(f"GUI server port out of range: {self.port!r}")
        if len(str(self.host).strip()) == 0:
            raise ValueError("GUI server host must be non-empty")
        scheme = "https" if (self.tls_cert_path or self.tls_self_signed) else "http"
        display_host = self.host if self.host not in ("0.0.0.0", "::") else "127.0.0.1"
        self.base_url = f"{scheme}://{display_host}:{int(self.port)}"

    def redacted(self) -> dict[str, Any]:
        """Dict suitable for logging: token is truncated to an 8-char id."""
        import hashlib

        token_id = ""
        if len(self.token) > 0:
            token_id = hashlib.sha256(self.token.encode("utf-8")).hexdigest()[:8]
        return {
            "mode": self.mode,
            "host": self.host,
            "port": self.port,
            "token_id": token_id,
            "tls_cert": bool(self.tls_cert_path),
            "tls_self_signed": bool(self.tls_self_signed),
            "allow_origins": list(self.allow_origins),
            "idle_seconds": self.idle_seconds,
            "path_allowlist": list(self.path_allowlist),
            "webview_debug": self.webview_debug,
        }


# --- helpers ------------------------------------------------------------


def _env_text(name: str) -> str:
    return str(os.environ.get(name, "") or "").strip()


def _env_bool(name: str) -> bool:
    raw = _env_text(name).lower()
    return raw in ("1", "true", "yes", "on", "y")


def _env_int(name: str, default: int) -> int:
    raw = _env_text(name)
    if len(raw) == 0:
        return int(default)
    try:
        return int(raw)
    except ValueError:
        _LOGGER.warning(
            "gui_server.config: %s=%r is not an integer; using default %d.",
            name, raw, default,
        )
        return int(default)


def _env_paths(name: str) -> tuple[str, ...]:
    raw = _env_text(name)
    if len(raw) == 0:
        return tuple()
    parts = [part.strip() for part in raw.split(os.pathsep)]
    return tuple(part for part in parts if len(part) > 0)


def _env_origins(name: str) -> tuple[str, ...]:
    raw = _env_text(name)
    if len(raw) == 0:
        return tuple()
    parts = [origin.strip() for origin in raw.split(",")]
    return tuple(origin for origin in parts if len(origin) > 0)


def _read_token_file(path: str) -> str:
    """Read ``path`` and return its stripped contents.

    Refuses to read a file whose POSIX mode is group- or world-readable
    to stay consistent with the ``PKCS11_PIN_SOURCE`` / ``FilePemSigner``
    posture. Windows ignores the mode check (POSIX attributes are not
    reliable there), but the path itself is still validated to exist and
    be non-empty.
    """
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise FileNotFoundError(f"token file not found: {resolved}")
    if os.name == "posix":
        try:
            mode = resolved.stat().st_mode & 0o777
        except OSError as error:
            raise PermissionError(
                f"token file {resolved} is unreadable: {error}"
            ) from error
        if (mode & 0o077) != 0:
            raise PermissionError(
                f"token file {resolved} is group- or world-readable "
                f"(mode {oct(mode)}); refusing to load. "
                "Run `chmod 600 {resolved}` to fix."
            )
    text = resolved.read_text(encoding="utf-8").strip()
    if len(text) == 0:
        raise ValueError(f"token file {resolved} is empty")
    return text


def _validate_token_strength(token: str) -> None:
    """Refuse clearly weak tokens before the server opens a port."""
    if len(token) < MIN_TOKEN_ENTROPY_CHARS:
        raise ValueError(
            f"GUI bearer token must be at least {MIN_TOKEN_ENTROPY_CHARS} characters "
            f"(got {len(token)})."
        )


def _resolve_desktop_token(arg_token_file: Optional[str]) -> str:
    """Desktop mode: token is optional from operator input; auto-generate if absent.

    Precedence: ``--token-file`` > ``YGGDRASIM_GUI_TOKEN_FILE`` >
    ``YGGDRASIM_GUI_TOKEN`` > freshly generated 32-byte URL-safe random.
    """
    if arg_token_file is not None and len(str(arg_token_file).strip()) > 0:
        return _read_token_file(str(arg_token_file).strip())
    env_file = _env_text(ENV_GUI_TOKEN_FILE)
    if len(env_file) > 0:
        return _read_token_file(env_file)
    env_token = _env_text(ENV_GUI_TOKEN)
    if len(env_token) > 0:
        _validate_token_strength(env_token)
        return env_token
    return secrets.token_urlsafe(32)


def _resolve_server_token(arg_token_file: Optional[str]) -> str:
    """Web-server mode: token is mandatory and never auto-generated.

    Precedence: ``--token-file`` > ``YGGDRASIM_GUI_TOKEN_FILE`` >
    ``YGGDRASIM_GUI_TOKEN``. Empty resolution raises SystemExit so the
    process refuses to start without an explicit operator decision.
    """
    if arg_token_file is not None and len(str(arg_token_file).strip()) > 0:
        token = _read_token_file(str(arg_token_file).strip())
    else:
        env_file = _env_text(ENV_GUI_TOKEN_FILE)
        env_token = _env_text(ENV_GUI_TOKEN)
        if len(env_file) > 0:
            token = _read_token_file(env_file)
        elif len(env_token) > 0:
            token = env_token
        else:
            raise SystemExit(
                "yggdrasim --web-server requires an explicit bearer token. "
                "Supply one of --token-file <path>, YGGDRASIM_GUI_TOKEN_FILE=<path>, "
                "or YGGDRASIM_GUI_TOKEN=<value>."
            )
    _validate_token_strength(token)
    return token


def _coerce_origins(arg_origins: Optional[list[str]]) -> tuple[str, ...]:
    collected: list[str] = []
    for origin in (arg_origins or []):
        trimmed = str(origin or "").strip()
        if len(trimmed) == 0:
            continue
        if trimmed == "*":
            raise SystemExit(
                "yggdrasim --web-server: wildcard --allow-origin is refused; "
                "name the exact origin(s) that should be allowed."
            )
        collected.append(trimmed)
    for origin in _env_origins(ENV_GUI_ALLOW_ORIGIN):
        if origin == "*":
            raise SystemExit(
                f"yggdrasim --web-server: {ENV_GUI_ALLOW_ORIGIN}=* is refused."
            )
        if origin not in collected:
            collected.append(origin)
    return tuple(collected)


# --- public builders ----------------------------------------------------


def build_desktop_config(args: Any) -> GuiServerConfig:
    """Resolve a :class:`GuiServerConfig` for ``yggdrasim --gui``.

    ``args`` is the argparse ``Namespace`` returned by
    :func:`main.main._build_cli_parser`. The caller is expected to
    already have asserted that ``args.gui`` is truthy.
    """
    arg_host = getattr(args, "host", None)
    arg_port = getattr(args, "port", None)
    arg_token_file = getattr(args, "token_file", None)
    arg_allow_origin = list(getattr(args, "allow_origin", None) or [])

    host = str(arg_host or _env_text(ENV_GUI_HOST) or DEFAULT_DESKTOP_HOST).strip()
    if arg_port is not None:
        port = int(arg_port)
    else:
        port = _env_int(ENV_GUI_PORT, DEFAULT_DESKTOP_PORT)

    token = _resolve_desktop_token(arg_token_file)
    allow_origins = _coerce_origins(arg_allow_origin)
    idle_seconds = _env_int(ENV_GUI_IDLE_SECONDS, DEFAULT_IDLE_SECONDS)
    path_allowlist = _env_paths(ENV_GUI_PATH_ALLOWLIST)
    webview_debug = _env_bool(ENV_GUI_WEBVIEW_DEBUG)

    return GuiServerConfig(
        mode=MODE_DESKTOP,
        host=host,
        port=port,
        token=token,
        idle_seconds=idle_seconds,
        allow_origins=allow_origins,
        tls_cert_path=None,
        tls_key_path=None,
        tls_self_signed=False,
        path_allowlist=path_allowlist,
        webview_debug=webview_debug,
        allow_ephemeral_port=True,
    )


def build_web_server_config(args: Any) -> GuiServerConfig:
    """Resolve a :class:`GuiServerConfig` for ``yggdrasim --web-server``.

    Unlike desktop mode, this refuses to start without an operator-
    provided bearer token, refuses to fall back to an ephemeral port
    (operators rely on a stable URL), and accepts optional TLS cert/key
    pairs.
    """
    arg_host = getattr(args, "host", None)
    arg_port = getattr(args, "port", None)
    arg_token_file = getattr(args, "token_file", None)
    arg_tls_cert = getattr(args, "tls_cert", None)
    arg_tls_key = getattr(args, "tls_key", None)
    arg_tls_self_signed = bool(getattr(args, "tls_self_signed", False))
    arg_allow_origin = list(getattr(args, "allow_origin", None) or [])

    host = str(arg_host or _env_text(ENV_GUI_SERVER_HOST) or DEFAULT_SERVER_HOST).strip()
    if arg_port is not None:
        port = int(arg_port)
    else:
        port = _env_int(ENV_GUI_SERVER_PORT, DEFAULT_SERVER_PORT)

    token = _resolve_server_token(arg_token_file)

    tls_cert = str(arg_tls_cert or _env_text(ENV_GUI_TLS_CERT) or "").strip() or None
    tls_key = str(arg_tls_key or _env_text(ENV_GUI_TLS_KEY) or "").strip() or None
    if (tls_cert is None) != (tls_key is None):
        raise SystemExit(
            "yggdrasim --web-server: --tls-cert and --tls-key must be supplied together."
        )
    if tls_cert is not None and arg_tls_self_signed:
        raise SystemExit(
            "yggdrasim --web-server: choose --tls-cert/--tls-key OR --tls-self-signed, not both."
        )

    allow_origins = _coerce_origins(arg_allow_origin)
    idle_seconds = _env_int(ENV_GUI_IDLE_SECONDS, DEFAULT_IDLE_SECONDS)
    path_allowlist = _env_paths(ENV_GUI_PATH_ALLOWLIST)

    return GuiServerConfig(
        mode=MODE_WEB_SERVER,
        host=host,
        port=port,
        token=token,
        idle_seconds=idle_seconds,
        allow_origins=allow_origins,
        tls_cert_path=tls_cert,
        tls_key_path=tls_key,
        tls_self_signed=arg_tls_self_signed,
        path_allowlist=path_allowlist,
        webview_debug=False,
        allow_ephemeral_port=False,
    )
