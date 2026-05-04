"""Argparse helper for the ``--remote-card-url`` / ``--remote-card-token-file`` flags.

Card-consuming CLIs (``main/main.py``, the SCP03 / SCP11 / SAIP shells,
the doctor, and any operator-facing wrapper that ends up calling
``yggdrasim_common.card_backend.create_card_connection``) historically
discover a remote card relay through environment variables --
``YGGDRASIM_CARD_RELAY_URL`` for the endpoint and either
``YGGDRASIM_CARD_RELAY_TOKEN`` or ``YGGDRASIM_CARD_RELAY_TOKEN_FILE``
for authorisation.

This module exposes the same surface as a pair of argparse options so
operators can pass ``--remote-card-url http://127.0.0.1:8642/apdu``
inline. The helper rewrites the corresponding env variables before the
CLI hands control off to the card-backend layer, so the existing
resolution chain (env > marker > nothing) works unchanged downstream.

Two pieces:

* :func:`add_remote_card_arguments` -- registers the flags on a parser.
* :func:`apply_remote_card_arguments` -- propagates the parsed values
  into the running process's environment.

Both are no-ops when the operator hasn't supplied the flags, so wiring
them into a CLI that already honours the env variables is purely
additive.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from yggdrasim_common.card_backend import (
    CARD_RELAY_TOKEN_ENV,
    CARD_RELAY_TOKEN_FILE_ENV,
    CARD_RELAY_URL_ENV,
)

# Argparse dest names -- kept stable so callers can read the values
# back from the parsed namespace if they need to log them or surface
# them in a doctor-style preflight banner.
DEST_REMOTE_CARD_URL = "remote_card_url"
DEST_REMOTE_CARD_TOKEN_FILE = "remote_card_token_file"


def add_remote_card_arguments(
    parser: argparse.ArgumentParser,
    *,
    title: str = "Remote card bridge (CB-3)",
) -> argparse._ArgumentGroup:
    """Register the remote-card flags on *parser* and return the group.

    The flags are grouped under their own argparse heading so ``--help``
    output stays readable. Returning the group lets callers append
    extra related options (e.g. a future ``--remote-card-allow-stale``
    diagnostics flag) without re-creating the heading.
    """
    group = parser.add_argument_group(title)
    group.add_argument(
        "--remote-card-url",
        dest=DEST_REMOTE_CARD_URL,
        default=None,
        help=(
            "Point this YggdraSIM invocation at a remote card-bridge URL "
            "(e.g. http://127.0.0.1:8642/apdu after opening an SSH "
            "LocalForward). Mirrors the YGGDRASIM_CARD_RELAY_URL "
            "environment variable; the flag wins when both are set."
        ),
    )
    group.add_argument(
        "--remote-card-token-file",
        dest=DEST_REMOTE_CARD_TOKEN_FILE,
        default=None,
        help=(
            "Path to a 0600 file holding the bearer token printed by "
            "the card bridge on startup. Mirrors "
            "YGGDRASIM_CARD_RELAY_TOKEN_FILE; preferred over the raw "
            "YGGDRASIM_CARD_RELAY_TOKEN env var so the token never "
            "appears in `ps` output."
        ),
    )
    return group


def apply_remote_card_arguments(
    namespace: argparse.Namespace,
    *,
    environment: dict[str, str] | None = None,
) -> dict[str, str]:
    """Mirror the parsed flag values into the process environment.

    Returns a dict describing the resulting state: ``url`` (active
    relay URL), ``token_file`` (active token-file path), ``url_source``
    and ``token_source`` (one of ``"flag"`` / ``"env"`` / ``""`` to
    record where the value came from). Callers can fold the dict into
    a debug log so it's clear at a glance whether the flag, the env
    var, or nothing took effect.

    The CLI flag wins over an existing env value because operators
    typically pass it to override a stale env. To unset an inherited
    env variable from the command line, simply pass an empty string:
    ``--remote-card-url ""``. The empty string clears the env entry.
    """
    env = environment if environment is not None else os.environ

    url_value = getattr(namespace, DEST_REMOTE_CARD_URL, None)
    url_source = ""
    if url_value is not None:
        cleaned = str(url_value).strip()
        if len(cleaned) == 0:
            env.pop(CARD_RELAY_URL_ENV, None)
        else:
            env[CARD_RELAY_URL_ENV] = cleaned
        url_source = "flag"
    elif len(str(env.get(CARD_RELAY_URL_ENV, "")).strip()) > 0:
        url_source = "env"

    token_file_value = getattr(namespace, DEST_REMOTE_CARD_TOKEN_FILE, None)
    token_source = ""
    if token_file_value is not None:
        cleaned_path = str(token_file_value).strip()
        if len(cleaned_path) == 0:
            env.pop(CARD_RELAY_TOKEN_FILE_ENV, None)
        else:
            # Eagerly resolve user expansion so the downstream resolver
            # doesn't see relative paths whose meaning depends on CWD
            # at lookup time.
            resolved = str(Path(cleaned_path).expanduser())
            env[CARD_RELAY_TOKEN_FILE_ENV] = resolved
            # If the operator passed --remote-card-token-file, they
            # almost certainly intend to *replace* any stale raw token
            # in the env. Drop it so the file form wins downstream.
            env.pop(CARD_RELAY_TOKEN_ENV, None)
        token_source = "flag"
    else:
        if len(str(env.get(CARD_RELAY_TOKEN_FILE_ENV, "")).strip()) > 0:
            token_source = "env-file"
        elif len(str(env.get(CARD_RELAY_TOKEN_ENV, "")).strip()) > 0:
            token_source = "env-raw"

    return {
        "url": str(env.get(CARD_RELAY_URL_ENV, "")).strip(),
        "url_source": url_source,
        "token_file": str(env.get(CARD_RELAY_TOKEN_FILE_ENV, "")).strip(),
        "token_source": token_source,
    }


def describe_remote_card_state(state: dict[str, Any]) -> str:
    """One-line human-readable summary of :func:`apply_remote_card_arguments`'s result."""
    url = state.get("url") or ""
    if len(url) == 0:
        return "remote card bridge: not configured (using local PC/SC reader)"
    token_file = state.get("token_file") or ""
    token_source = state.get("token_source") or ""
    if token_source == "flag":
        token_clause = f"token file (flag): {token_file}"
    elif token_source == "env-file":
        token_clause = f"token file (env): {token_file}"
    elif token_source == "env-raw":
        token_clause = "token via YGGDRASIM_CARD_RELAY_TOKEN env"
    else:
        token_clause = "no token (loopback bridges only)"
    return f"remote card bridge: {url}; {token_clause}"
