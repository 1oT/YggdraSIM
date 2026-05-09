# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Shared bearer-token utilities for the YggdraSIM card relay.

Used by:

* ``Tools/HilBridge/apdu_relay.HilBridgeApduRelayService`` — the in-tree
  relay handler that sits inside the HIL bridge.
* ``yggdrasim_common.card_backend.RelayCardConnection`` — the
  pyscard-shaped consumer client.

Design contract:

* Tokens are at least 32 bytes of OS-provided entropy, encoded as
  URL-safe base64 with padding stripped.
* Tokens live in mode-0600 files under
  ``${XDG_CONFIG_HOME:-~/.config}/yggdrasim/card_bridge/<port>.token``.
  Operators retrieve them through the same SSH session that establishes
  the ``LocalForward`` — the file format is one line, no trailing
  whitespace.
* Token files are written with the create-truncate-write-chmod dance so
  the mode bits stand even if the inherited umask was looser.
* ``compare()`` uses :func:`hmac.compare_digest` against the UTF-8
  encoded form to keep the comparison constant-time.
* The full token is **never** logged. Callers display
  :func:`fingerprint` (the first 6 characters of a SHA-256 over the
  token) so an operator can correlate a running daemon with a token
  file without exposing the credential itself.
* Loopback bind without a token is permitted for back-compat with the
  existing HilBridge marker workflow. Any non-loopback bind must carry
  a token; the daemon refuses to start otherwise — see
  ``HilBridgeApduRelayService.start``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

# Token / env contract. The variable names are stable across both
# server and client so an operator can use a single ``.env`` to pin
# both the daemon's emitted token and the consumer's bearer header.
DEFAULT_TOKEN_BYTES = 32
TOKEN_ENV_VAR = "YGGDRASIM_CARD_RELAY_TOKEN"
TOKEN_FILE_ENV_VAR = "YGGDRASIM_CARD_RELAY_TOKEN_FILE"
TOKEN_FINGERPRINT_LENGTH = 6

LOOPBACK_HOSTS = frozenset(
    {
        "127.0.0.1",
        "::1",
        "localhost",
        "ip6-localhost",
        "ip6-loopback",
    }
)


def generate_token(*, byte_count: int = DEFAULT_TOKEN_BYTES) -> str:
    """Return a fresh URL-safe base64 token with ``byte_count`` bytes of entropy.

    ``byte_count`` is floor-clamped to :data:`DEFAULT_TOKEN_BYTES` so a
    caller can't accidentally hand us a 4-byte value and end up with a
    token that's brute-forceable in milliseconds.
    """
    if byte_count < DEFAULT_TOKEN_BYTES:
        raise ValueError(
            f"Token entropy must be at least {DEFAULT_TOKEN_BYTES} bytes "
            f"(got {byte_count})."
        )
    raw = secrets.token_bytes(byte_count)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def fingerprint(token: str) -> str:
    """Return a stable short identifier for log lines / startup banners.

    The fingerprint is deterministic (SHA-256 of the token, truncated)
    so operators can match a daemon banner against the on-disk token
    file without revealing the credential itself.
    """
    if len(token) == 0:
        return ""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return digest[:TOKEN_FINGERPRINT_LENGTH]


def compare(presented: str, expected: str) -> bool:
    """Constant-time equality check.

    Returns ``False`` if either side is empty so a daemon that has not
    been seeded with a token doesn't accidentally accept a stray
    ``Authorization: Bearer`` header with no value.
    """
    if len(presented) == 0 or len(expected) == 0:
        return False
    return hmac.compare_digest(
        presented.encode("utf-8"),
        expected.encode("utf-8"),
    )


def parse_bearer_header(header_value: str) -> str:
    """Extract the bearer token from an ``Authorization`` header value.

    Returns the empty string on any parse failure (missing scheme,
    wrong scheme, no value). Callers feed the result straight into
    :func:`compare`, which already rejects empty strings.
    """
    cleaned = str(header_value or "").strip()
    if len(cleaned) == 0:
        return ""
    parts = cleaned.split(None, 1)
    if len(parts) != 2:
        return ""
    scheme = parts[0].strip().lower()
    if scheme != "bearer":
        return ""
    return parts[1].strip()


def default_token_directory() -> Path:
    """Return the conventional token directory.

    Honours ``XDG_CONFIG_HOME``; falls back to ``~/.config`` on POSIX.
    The directory is created lazily by :func:`write_token_file`.
    """
    xdg_root = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if len(xdg_root) > 0:
        base = Path(xdg_root)
    else:
        base = Path.home() / ".config"
    return base / "yggdrasim" / "card_bridge"


def default_token_file_for_port(port: int) -> Path:
    """Conventional token file path for the given listen port."""
    if port < 0 or port > 65535:
        raise ValueError(f"Invalid TCP port for token file: {port}")
    return default_token_directory() / f"{port}.token"


def write_token_file(path: Path, token: str) -> Path:
    """Write *token* to *path* with mode 0600. Returns the resolved path."""
    if len(token) == 0:
        raise ValueError("Refusing to write an empty token file.")
    resolved = Path(path).expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        str(resolved),
        os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
        0o600,
    )
    try:
        os.write(descriptor, token.encode("utf-8") + b"\n")
    finally:
        os.close(descriptor)
    # Force the mode bits in case the inherited umask was looser than
    # 0077; the open() above only respects the *minimum* of mode and
    # umask, so we re-apply explicitly.
    try:
        os.chmod(resolved, 0o600)
    except OSError:
        pass
    return resolved


def read_token_file(path: Path) -> str:
    """Return the token text stored at *path*, stripped of whitespace.

    Raises :class:`OSError` on read failure; callers decide whether to
    fall through to other resolution sources.
    """
    resolved = Path(path).expanduser().resolve()
    text = resolved.read_text(encoding="utf-8")
    return text.strip()


def resolve_token_from_environment() -> str:
    """Return the bearer token configured via environment variables.

    Resolution order:

    1. ``YGGDRASIM_CARD_RELAY_TOKEN`` — raw token value. Convenient for
       inline ``ssh user@host -t 'YGGDRASIM_CARD_RELAY_TOKEN=…'``
       invocations but visible to ``ps`` for the lifetime of the
       process; prefer the file form whenever possible.
    2. ``YGGDRASIM_CARD_RELAY_TOKEN_FILE`` — path to a 0600-mode file
       holding the token on a single line.

    Returns an empty string when neither is set.
    """
    direct = os.environ.get(TOKEN_ENV_VAR, "").strip()
    if len(direct) > 0:
        return direct
    file_path = os.environ.get(TOKEN_FILE_ENV_VAR, "").strip()
    if len(file_path) > 0:
        try:
            return read_token_file(Path(file_path))
        except OSError:
            return ""
    return ""


def is_loopback_host(host: str) -> bool:
    """Return ``True`` when *host* binds only to a loopback interface.

    Anything in 127.0.0.0/8 counts as loopback (RFC 5735), as does the
    IPv6 loopback ``::1`` and the conventional ``localhost`` hostnames.
    """
    cleaned = str(host or "").strip().lower()
    if cleaned in LOOPBACK_HOSTS:
        return True
    if cleaned.startswith("127."):
        return True
    return False
