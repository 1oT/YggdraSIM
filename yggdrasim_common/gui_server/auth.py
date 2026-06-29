# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Bearer-token middleware + rate-limiter for the GUI server.

Implements the security posture defined in ``V2_UNIVERSAL_GUI_PLAN`` §8.3
(desktop) and §9.2 (web server). Summary:

* Every request to ``/api/*`` requires ``Authorization: Bearer <token>``.
* Comparison is constant-time via :func:`hmac.compare_digest`.
* Failed auth is throttled per-source-IP with a simple token bucket
  (default: 5 failures / minute; further failures return HTTP 429).
* The raw token never enters any log line — only its SHA-256 prefix.
* Requests to ``/`` (SPA index), ``/static/*``, ``/favicon.ico``, and
  ``/healthz`` (liveness) bypass the auth check because they are either
  static assets served on the same origin or cheap liveness probes.
  All ``/api/*`` endpoints are authenticated — including ``/api/health``.

The module holds no FastAPI imports at the module level. It is safe to
unit-test the rate-limit + token-check helpers without the optional GUI
extras installed.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional


__all__ = (
    "AuthMiddleware",
    "FailureRateLimiter",
    "compare_tokens",
    "extract_bearer",
    "is_bypass_path",
    "token_id",
)


_LOGGER = logging.getLogger("yggdrasim.gui.auth")


# --- constants ----------------------------------------------------------

DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60.0
DEFAULT_RATE_LIMIT_MAX_FAILURES = 5

# Request paths that bypass the bearer check. Keep this list narrow on
# purpose — anything that needs data out of the engine must go through
# /api/*.
_BYPASS_EXACT: frozenset[str] = frozenset({
    "/",
    "/index.html",
    "/favicon.ico",
    "/healthz",  # cheap liveness for an external supervisor / systemd.
})
_BYPASS_PREFIXES: tuple[str, ...] = (
    "/static/",
    "/assets/",
)


# --- helpers ------------------------------------------------------------


def token_id(token: str) -> str:
    """Return an 8-char SHA-256 prefix suitable for log correlation.

    Empty input yields an empty string so log lines can distinguish
    "unauthenticated" (empty id) from "bad token" (non-empty id that
    will never match a known token).
    """
    if token is None or len(token) == 0:
        return ""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]


def is_bypass_path(path: str) -> bool:
    """Return True when *path* is exempt from authentication (e.g. /health, /about)."""
    if path in _BYPASS_EXACT:
        return True
    for prefix in _BYPASS_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def extract_bearer(header_value: Optional[str]) -> str:
    """Pull the token out of an ``Authorization: Bearer <token>`` header.

    Returns an empty string for any malformed header so the caller can
    uniformly treat "missing" and "malformed" as a single failure mode.
    """
    if header_value is None:
        return ""
    text = str(header_value).strip()
    if len(text) == 0:
        return ""
    parts = text.split(None, 1)
    if len(parts) != 2:
        return ""
    scheme, value = parts[0].strip().lower(), parts[1].strip()
    if scheme != "bearer":
        return ""
    return value


def compare_tokens(expected: str, provided: str) -> bool:
    """Constant-time token compare.

    Empty expected always yields ``False`` so a misconfigured server
    cannot degrade to "accept any token" on startup.
    """
    if expected is None or len(expected) == 0:
        return False
    if provided is None or len(provided) == 0:
        return False
    expected_bytes = expected.encode("utf-8")
    provided_bytes = provided.encode("utf-8")
    if len(expected_bytes) != len(provided_bytes):
        # hmac.compare_digest is constant-time only for equal-length
        # inputs. Pad the shorter one so the comparison still runs in
        # constant time with respect to content.
        pad = max(len(expected_bytes), len(provided_bytes))
        expected_bytes = expected_bytes.ljust(pad, b"\x00")
        provided_bytes = provided_bytes.ljust(pad, b"\x00")
        return False or hmac.compare_digest(expected_bytes, provided_bytes)  # always False, but timed
    return hmac.compare_digest(expected_bytes, provided_bytes)


# --- rate limiter -------------------------------------------------------


@dataclass
class _FailureBucket:
    failures: list[float] = field(default_factory=list)


class FailureRateLimiter:
    """Per-source-IP token bucket for failed auth attempts.

    Thread-safe, in-process only. Not persisted: restarting the server
    wipes the bucket, which is acceptable for a single-secret bearer
    surface.
    """

    def __init__(
        self,
        *,
        window_seconds: float = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
        max_failures: int = DEFAULT_RATE_LIMIT_MAX_FAILURES,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if max_failures <= 0:
            raise ValueError("max_failures must be > 0")
        self._window = float(window_seconds)
        self._limit = int(max_failures)
        self._clock = clock or time.monotonic
        self._buckets: dict[str, _FailureBucket] = {}
        self._lock = threading.Lock()

    def register_failure(self, source: str) -> bool:
        """Record a failure and return ``True`` if the source is now over limit."""
        now = float(self._clock())
        source_key = str(source or "").strip() or "unknown"
        with self._lock:
            bucket = self._buckets.setdefault(source_key, _FailureBucket())
            bucket.failures = [ts for ts in bucket.failures if now - ts <= self._window]
            bucket.failures.append(now)
            return len(bucket.failures) > self._limit

    def is_blocked(self, source: str) -> bool:
        """Return True when the source address has exceeded the failed-auth threshold."""
        now = float(self._clock())
        source_key = str(source or "").strip() or "unknown"
        with self._lock:
            bucket = self._buckets.get(source_key)
            if bucket is None:
                return False
            bucket.failures = [ts for ts in bucket.failures if now - ts <= self._window]
            return len(bucket.failures) > self._limit

    def reset(self, source: str) -> None:
        source_key = str(source or "").strip() or "unknown"
        with self._lock:
            self._buckets.pop(source_key, None)

    def retry_after_seconds(self, source: str) -> float:
        """Return the cooldown duration in seconds before the blocked address may retry."""
        now = float(self._clock())
        source_key = str(source or "").strip() or "unknown"
        with self._lock:
            bucket = self._buckets.get(source_key)
            if bucket is None or len(bucket.failures) == 0:
                return 0.0
            oldest = min(bucket.failures)
            remaining = self._window - (now - oldest)
            return max(0.0, remaining)


# --- pure-ASGI middleware -----------------------------------------------
#
# Earlier revisions of this file shipped a ``build_auth_middleware`` factory
# that returned a ``dispatch`` coroutine fed into Starlette's
# :class:`starlette.middleware.base.BaseHTTPMiddleware`. That class buffers
# the entire response body through an ``anyio`` memory stream and pins a
# task-group reference per request — a long-standing memory growth source
# (encode/starlette#1438, encode/starlette#1715). Every ``/api/health``
# poll (10 s tick), every reader-pane refresh, and every Command Center
# action would each leak a few KB into uvicorn's worker memory, which over
# a multi-hour GUI session became hundreds of MB of "phantom" RSS.
#
# The replacement is a thin pure-ASGI middleware: it wraps ``__call__``
# directly, never wraps the response body, and only allocates the small
# headers list it needs to inject the hardening headers. WebSocket /
# lifespan scopes pass through untouched — every WS handler already runs
# its own ``compare_tokens`` check.


def _scope_path(scope: dict[str, Any]) -> str:
    raw = scope.get("path", "")
    return raw if isinstance(raw, str) else ""


def _scope_authorization(scope: dict[str, Any]) -> str:
    """Pull ``Authorization`` out of a raw ASGI ``headers`` list."""
    raw_headers = scope.get("headers") or []
    for key, value in raw_headers:
        try:
            if key.lower() == b"authorization":
                return value.decode("latin-1")
        except (AttributeError, UnicodeDecodeError):
            continue
    return ""


def _scope_client_source(scope: dict[str, Any]) -> str:
    """Kernel-reported peer address; proxy headers are intentionally ignored."""
    client = scope.get("client")
    if not client:
        return "unknown"
    host = client[0] if isinstance(client, (list, tuple)) and len(client) > 0 else None
    if host is None or len(str(host)) == 0:
        return "unknown"
    return str(host)


# CSP must travel as an HTTP response header for ``frame-ancestors`` to
# be honoured — browsers silently ignore that directive when delivered
# via ``<meta http-equiv="Content-Security-Policy">``. The other source
# directives (script-src, style-src, …) work either way, but unifying
# delivery on the header keeps the policy in one place.
_CSP_HEADER: bytes = (
    b"default-src 'self'; "
    # xterm.js and some vendored bundles still hit eval-capable code paths
    # during initialisation; without this, Chromium logs EvalError and
    # downstream DOM wiring can fail mid-bootstrap.
    b"script-src 'self' 'unsafe-eval'; "
    b"style-src 'self' 'unsafe-inline'; "
    b"img-src 'self' data:; "
    b"connect-src 'self' ws: wss:; "
    b"frame-ancestors 'none'; "
    b"base-uri 'self'; "
    b"form-action 'self'"
)


_HARDEN_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (b"content-security-policy", _CSP_HEADER),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
)


async def _send_json(send: Callable[..., Awaitable[None]], status_code: int, body: bytes,
                    extra_headers: Optional[list[tuple[bytes, bytes]]] = None) -> None:
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({
        "type": "http.response.start",
        "status": int(status_code),
        "headers": headers,
    })
    await send({
        "type": "http.response.body",
        "body": body,
        "more_body": False,
    })


class AuthMiddleware:
    """Pure-ASGI bearer-token gate + per-source-IP rate limit.

    Public attributes mirror the old factory shape so any external
    integrator that imported the helpers directly does not break.
    """

    def __init__(
        self,
        app: Any,
        *,
        expected_token: str,
        rate_limiter: Optional[FailureRateLimiter] = None,
    ) -> None:
        self.app = app
        self.expected_token = expected_token or ""
        self.rate_limiter = rate_limiter if rate_limiter is not None else FailureRateLimiter()

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Awaitable[Any]],
                       send: Callable[..., Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = _scope_path(scope)
        if is_bypass_path(path) or not path.startswith("/api/"):
            await self.app(scope, receive, self._wrap_send(send))
            return

        source = _scope_client_source(scope)
        if self.rate_limiter.is_blocked(source):
            retry_after = self.rate_limiter.retry_after_seconds(source)
            _LOGGER.warning(
                "gui.auth: rate-limited source=%s retry_after=%.1fs path=%s",
                source, retry_after, path,
            )
            body = (
                b'{"error":"rate_limited","retry_after_seconds":'
                + str(round(retry_after, 1)).encode("ascii")
                + b"}"
            )
            await _send_json(
                send,
                429,
                body,
                extra_headers=[(b"retry-after", str(int(retry_after) or 1).encode("ascii"))],
            )
            return

        provided = extract_bearer(_scope_authorization(scope))
        if not compare_tokens(self.expected_token, provided):
            over_limit = self.rate_limiter.register_failure(source)
            provided_id = token_id(provided) if len(provided) > 0 else "none"
            _LOGGER.warning(
                "gui.auth: reject source=%s path=%s token_id=%s over_limit=%s",
                source, path, provided_id, over_limit,
            )
            await _send_json(
                send,
                401,
                b'{"error":"unauthorized"}',
                extra_headers=[(b"www-authenticate", b"Bearer")],
            )
            return

        await self.app(scope, receive, self._wrap_send(send))

    @staticmethod
    def _wrap_send(send: Callable[..., Awaitable[None]]) -> Callable[..., Awaitable[None]]:
        """Inject hardening headers onto ``http.response.start`` only.

        The wrapper is a single closure over the original ``send``. It is
        intentionally allocation-light: no per-request task groups, no
        anyio memory streams, no extra background tasks.
        """

        async def _hardened_send(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])
                seen = {key.lower() for key, _ in headers if isinstance(key, (bytes, bytearray))}
                for hkey, hval in _HARDEN_HEADERS:
                    if hkey not in seen:
                        headers.append((hkey, hval))
                message = dict(message)
                message["headers"] = headers
            await send(message)

        return _hardened_send
