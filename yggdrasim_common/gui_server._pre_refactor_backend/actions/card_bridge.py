# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""``card_bridge.*`` actions — Command Center surface for the Card Bridge (CB-4).

Two read-only actions that let the GUI front-end inspect and probe a
remote card bridge without re-implementing the relay HTTP client:

* ``card_bridge.status`` — report the *currently configured* relay
  URL and token posture as resolved by ``card_backend``. Pure
  introspection: zero network traffic, safe to poll on a tight cadence.
* ``card_bridge.probe`` — open a short-lived ``GET /ping`` and
  ``GET /status`` against either the configured URL or an operator-
  supplied URL+token, return reachability, auth posture, ATR (when the
  bridge surfaces one), and round-trip latency.

The actions intentionally do *not* expose the raw bearer token in any
response payload. Token presence is conveyed via a 6-character SHA-256
fingerprint (``yggdrasim_common.card_bridge_auth.fingerprint``) so
operators can confirm the right token is wired up without leaking it
into GUI logs or screenshots.

Local subprocess management (start/stop a Card Bridge daemon from the
GUI) is deliberately out of scope for CB-4 backend — operators run the
bridge over SSH on the remote host with the reader. A future slice can
introduce ``card_bridge.start_local`` / ``stop_local`` without
disturbing this read-only contract.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any

from yggdrasim_common.gui_server.actions.registry import (
    ActionContext,
    ActionField,
    ActionSpec,
    get_registry,
)

_LOGGER = logging.getLogger("yggdrasim.gui.actions.card_bridge")

# Hard cap on probe duration so a wedged remote can't stall the GUI's
# action queue. The probe issues at most two GETs; 4 s gives the
# bridge plenty of time to answer over an SSH tunnel even on a
# transatlantic link.
_PROBE_TIMEOUT_SECONDS = 2.0
_PROBE_MAX_RESPONSE_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_apdu_suffix(url: str) -> str:
    candidate = url.strip()
    if candidate.endswith("/apdu"):
        candidate = candidate[: -len("/apdu")]
    return candidate.rstrip("/")


def _fingerprint(token: str) -> str:
    if len(token) == 0:
        return ""
    try:
        from yggdrasim_common.card_bridge_auth import fingerprint as _fp

        return _fp(token)
    except Exception:  # noqa: BLE001 — diagnostics-only path
        return ""


def _resolve_configured() -> dict[str, Any]:
    """Return the relay URL/token snapshot as ``card_backend`` would resolve them.

    Mirrors the resolution chain used by ``RelayCardConnection`` so the
    GUI sees exactly what a card-consuming CLI would see at the same
    instant. Returned dict contains plain JSON-serialisable values
    only — no raw tokens.
    """
    snapshot: dict[str, Any] = {
        "configured": False,
        "url": "",
        "url_source": "",
        "base_url": "",
        "has_token": False,
        "token_fingerprint": "",
        "token_source": "",
    }
    try:
        from yggdrasim_common.card_backend import (
            CARD_RELAY_TOKEN_ENV,
            CARD_RELAY_TOKEN_FILE_ENV,
            _resolve_card_relay_url,
            _resolve_card_relay_token,
        )
    except Exception as error:  # noqa: BLE001
        snapshot["error"] = f"card_backend unavailable: {error.__class__.__name__}"
        return snapshot

    try:
        url, source = _resolve_card_relay_url()
    except Exception as error:  # noqa: BLE001
        snapshot["error"] = f"resolve URL failed: {error.__class__.__name__}: {error}"
        return snapshot

    if len(url) == 0:
        return snapshot

    snapshot["configured"] = True
    snapshot["url"] = url
    snapshot["url_source"] = source
    snapshot["base_url"] = _strip_apdu_suffix(url)

    try:
        token = _resolve_card_relay_token(allow_marker=True)
    except Exception as error:  # noqa: BLE001
        snapshot["error"] = f"resolve token failed: {error.__class__.__name__}: {error}"
        return snapshot

    if len(token) > 0:
        snapshot["has_token"] = True
        snapshot["token_fingerprint"] = _fingerprint(token)
        # Identify which env knob produced the token so operators can
        # spot stale env state at a glance.
        if len(str(os.environ.get(CARD_RELAY_TOKEN_ENV, "")).strip()) > 0:
            snapshot["token_source"] = "env-raw"
        elif len(str(os.environ.get(CARD_RELAY_TOKEN_FILE_ENV, "")).strip()) > 0:
            snapshot["token_source"] = "env-file"
        else:
            snapshot["token_source"] = "marker"
    return snapshot


def _http_get_json(
    base_url: str,
    path: str,
    *,
    token: str,
    timeout_seconds: float = _PROBE_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any] | None, float, str]:
    """Issue ``GET base_url + path`` and return ``(status, json|None, latency_ms, error)``.

    On transport failure ``status`` is ``0`` and ``error`` carries a
    short class+message string. Body parsing failures yield
    ``json=None`` with ``status`` and ``latency_ms`` populated; the
    caller decides whether that's fatal.
    """
    full = f"{base_url}{path}"
    request = urllib.request.Request(full, method="GET")
    request.add_header("Accept", "application/json")
    if len(token) > 0:
        request.add_header("Authorization", f"Bearer {token}")

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status_code = int(response.status)
            payload_raw = response.read(_PROBE_MAX_RESPONSE_BYTES + 1)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
        if len(payload_raw) > _PROBE_MAX_RESPONSE_BYTES:
            return status_code, None, elapsed_ms, "response too large"
        try:
            decoded = json.loads(payload_raw.decode("utf-8", errors="replace"))
        except Exception:
            return status_code, None, elapsed_ms, ""
        if not isinstance(decoded, dict):
            return status_code, None, elapsed_ms, ""
        return status_code, decoded, elapsed_ms, ""
    except urllib.error.HTTPError as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return int(error.code), None, elapsed_ms, f"HTTP {error.code} ({error.reason})"
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return 0, None, elapsed_ms, f"{error.__class__.__name__}: {error}"


# ---------------------------------------------------------------------------
# card_bridge.status
# ---------------------------------------------------------------------------


def _dispatch_status(ctx: ActionContext, **_inputs: Any) -> dict[str, Any]:
    snapshot = _resolve_configured()
    if snapshot.get("configured") is True:
        snapshot["summary"] = (
            f"Configured: {snapshot.get('url')} "
            f"(via {snapshot.get('url_source')}); "
            + ("token present" if snapshot.get("has_token") else "no token")
        )
    else:
        snapshot["summary"] = "Not configured (using local PC/SC reader)."
    return snapshot


STATUS_SPEC = ActionSpec(
    id="card_bridge.status",
    subsystem="Card Bridge",
    title="Status",
    description=(
        "Report the currently configured remote card-bridge URL plus "
        "token posture as the running process would resolve them. "
        "Pure introspection — no network traffic. Use this to verify "
        "that --remote-card-url / YGGDRASIM_CARD_RELAY_URL took "
        "effect before opening a card session."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_status,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "diagnostics", "read-only"),
)


# ---------------------------------------------------------------------------
# card_bridge.probe
# ---------------------------------------------------------------------------


def _dispatch_probe(
    ctx: ActionContext,
    *,
    url: str = "",
    token: str = "",
    use_configured: bool = True,
) -> dict[str, Any]:
    """Probe a Card Bridge endpoint and return a structured health report.

    When *use_configured* is true (default) we fall back to the
    resolved configuration if the operator didn't supply an explicit
    URL/token in the form. That makes the action one click for the
    common case where the bridge is already wired up via env vars.
    """
    operator_url = str(url or "").strip()
    operator_token = str(token or "").strip()

    snapshot = _resolve_configured() if bool(use_configured) else {
        "configured": False,
        "url": "",
        "base_url": "",
        "has_token": False,
        "token_fingerprint": "",
    }

    target_url = operator_url
    target_token = operator_token
    used_configured_url = False
    used_configured_token = False
    if len(target_url) == 0 and bool(use_configured):
        target_url = str(snapshot.get("url") or "")
        used_configured_url = True
    if len(target_token) == 0 and bool(use_configured):
        # Fall back to whatever ``card_backend`` would resolve. We
        # don't echo the resolved token back to the client — the
        # fingerprint already conveys "we have one".
        try:
            from yggdrasim_common.card_backend import _resolve_card_relay_token

            target_token = _resolve_card_relay_token(allow_marker=True)
            used_configured_token = len(target_token) > 0
        except Exception as error:  # noqa: BLE001
            target_token = ""
            snapshot["resolve_error"] = (
                f"resolve token failed: {error.__class__.__name__}: {error}"
            )

    if len(target_url) == 0:
        return {
            "ok": False,
            "reason": "no URL — set --remote-card-url, YGGDRASIM_CARD_RELAY_URL, or pass `url` to this action.",
            "configured": snapshot,
        }

    base_url = _strip_apdu_suffix(target_url)
    fingerprint = _fingerprint(target_token)

    ping_status, ping_payload, ping_ms, ping_error = _http_get_json(
        base_url, "/ping", token=target_token
    )
    if ping_status == 0:
        return {
            "ok": False,
            "reason": ping_error or "ping failed",
            "url": base_url,
            "ping_latency_ms": round(ping_ms, 2),
            "token_fingerprint": fingerprint,
            "used_configured_url": used_configured_url,
            "used_configured_token": used_configured_token,
        }

    if ping_status != 200:
        return {
            "ok": False,
            "reason": ping_error or f"ping returned HTTP {ping_status}",
            "url": base_url,
            "ping_status": ping_status,
            "ping_latency_ms": round(ping_ms, 2),
            "token_fingerprint": fingerprint,
            "used_configured_url": used_configured_url,
            "used_configured_token": used_configured_token,
        }

    status_status, status_payload, status_ms, status_error = _http_get_json(
        base_url, "/status", token=target_token
    )

    auth_required = False
    bridge_fingerprint = ""
    bind_host = ""
    audit_enabled: object = None
    reader = ""
    atr_hex = ""
    if isinstance(status_payload, dict):
        auth_required = bool(status_payload.get("authRequired"))
        bridge_fingerprint = str(status_payload.get("tokenFingerprint") or "")
        bind_host = str(
            status_payload.get("host") or status_payload.get("bindHost") or ""
        )
        audit_enabled = status_payload.get("auditEnabled")
        reader = str(status_payload.get("reader") or "")
        atr_hex = str(status_payload.get("atrHex") or status_payload.get("atr") or "").upper()

    # 401 is canonical "auth required, request not satisfied" — treat
    # it as authoritative regardless of whether the body bothered to
    # echo ``authRequired``. Some older relays returned 401 without a
    # JSON body at all.
    if status_status == 401:
        auth_required = True

    auth_posture = "no-token-required"
    if auth_required:
        if status_status == 401:
            auth_posture = "token-rejected"
        elif len(target_token) == 0:
            auth_posture = "token-required-but-missing"
        else:
            auth_posture = "token-accepted"
    elif len(bind_host) > 0 and bind_host not in {"127.0.0.1", "::1", "localhost"}:
        auth_posture = "auth-disabled-non-loopback"

    overall_ok = (
        status_status == 200
        and auth_posture in {"no-token-required", "token-accepted"}
    )

    return {
        "ok": overall_ok,
        "reason": "" if overall_ok else (status_error or f"status HTTP {status_status}"),
        "url": base_url,
        "ping_status": ping_status,
        "ping_latency_ms": round(ping_ms, 2),
        "status_status": status_status,
        "status_latency_ms": round(status_ms, 2),
        "auth_required": auth_required,
        "auth_posture": auth_posture,
        "token_fingerprint": fingerprint,
        "bridge_token_fingerprint": bridge_fingerprint,
        "fingerprint_match": (
            len(fingerprint) > 0
            and len(bridge_fingerprint) > 0
            and fingerprint == bridge_fingerprint
        ),
        "bind_host": bind_host,
        "audit_enabled": audit_enabled,
        "reader": reader,
        "atr_hex": atr_hex,
        "used_configured_url": used_configured_url,
        "used_configured_token": used_configured_token,
    }


PROBE_SPEC = ActionSpec(
    id="card_bridge.probe",
    subsystem="Card Bridge",
    title="Probe bridge",
    description=(
        "GET /ping and GET /status against the configured (or supplied) "
        "Card Bridge URL. Reports reachability, auth posture, latency, "
        "and ATR. Bearer tokens are never echoed back — only their "
        "6-char SHA-256 fingerprint is returned so operators can "
        "confirm the right token is wired up."
    ),
    inputs=(
        ActionField(
            name="url",
            label="Bridge URL",
            kind="string",
            required=False,
            placeholder="http://127.0.0.1:8642/apdu (leave blank to use configured)",
            help=(
                "Override the configured YGGDRASIM_CARD_RELAY_URL. "
                "Trailing /apdu is stripped automatically."
            ),
        ),
        ActionField(
            name="token",
            label="Bearer token",
            kind="string",
            required=False,
            secret=True,
            help=(
                "Override the resolved bearer token. Leave blank to use "
                "YGGDRASIM_CARD_RELAY_TOKEN / TOKEN_FILE / runtime marker."
            ),
        ),
        ActionField(
            name="use_configured",
            label="Fall back to configured values",
            kind="bool",
            default=True,
            help=(
                "When checked, blank URL/token fields fall back to the "
                "card_backend resolution chain. Uncheck to probe a "
                "completely independent endpoint."
            ),
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_probe,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "diagnostics", "read-only", "network"),
)


# ---------------------------------------------------------------------------
# card_bridge.token_generate
# ---------------------------------------------------------------------------


def _dispatch_token_generate(
    ctx: ActionContext,
    *,
    output_path: Any = None,
    port: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common.card_bridge_auth import (
        generate_token,
        fingerprint,
        write_token_file,
        default_token_file_for_port,
    )

    port_i = int(port) if port is not None else 8642
    token = generate_token()
    fp = fingerprint(token)
    path_s = str(output_path or "").strip()
    if len(path_s) > 0:
        import pathlib
        out = pathlib.Path(path_s)
    else:
        out = default_token_file_for_port(port_i)

    written = write_token_file(out, token)
    return {
        "ok": True,
        "token_fingerprint": fp,
        "token_file": str(written),
        "port": port_i,
        "note": f"Token ({fp}) written to {written}.",
    }


TOKEN_GENERATE_SPEC = ActionSpec(
    id="card_bridge.token_generate",
    subsystem="Card Bridge",
    title="Generate token",
    description=(
        "Generate a cryptographically random bearer token, fingerprint "
        "it, and write it to a 0600 token file. Use this to provision "
        "a new shared secret for card-bridge SSH tunnels."
    ),
    inputs=(
        ActionField(
            name="output_path",
            label="Output path",
            kind="save_path",
            required=False,
            help="Where to write the token file; defaults to ~/.config/yggdrasim/card_bridge/<port>.token.",
        ),
        ActionField(
            name="port",
            label="Port",
            kind="int",
            required=False,
            default=8642,
            min_value=1,
            help="Bridge port number (influences the default token file name).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_token_generate,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "token", "security"),
)


# ---------------------------------------------------------------------------
# card_bridge.config
# ---------------------------------------------------------------------------


def _dispatch_config(ctx: ActionContext, **_inputs: Any) -> dict[str, Any]:
    snapshot = _resolve_configured()
    from yggdrasim_common.card_bridge_auth import default_token_file_for_port

    lines: list[dict[str, str]] = []
    lines.append({"key": "Configured", "value": "yes" if snapshot.get("configured") else "no"})
    lines.append({"key": "URL", "value": str(snapshot.get("url") or "-")})
    lines.append({"key": "URL source", "value": str(snapshot.get("url_source") or "-")})
    lines.append({"key": "Base URL", "value": str(snapshot.get("base_url") or "-")})
    lines.append({"key": "Token present", "value": "yes" if snapshot.get("has_token") else "no"})
    fp = str(snapshot.get("token_fingerprint") or "-")
    lines.append({"key": "Token fingerprint", "value": fp})
    lines.append({"key": "Token source", "value": str(snapshot.get("token_source") or "-")})
    lines.append({"key": "Default token file", "value": str(default_token_file_for_port(8642))})
    return {
        "ok": True,
        "lines": lines,
        "snapshot": snapshot,
        "note": "Card bridge configuration snapshot.",
    }


CONFIG_SPEC = ActionSpec(
    id="card_bridge.config",
    subsystem="Card Bridge",
    title="Configuration",
    description=(
        "Show the effective Card Bridge configuration: relay URL, token "
        "posture, and default token file path. Pure introspection — no "
        "network traffic."
    ),
    inputs=(),
    output_kind="key_value_lines",
    dispatcher=_dispatch_config,
    requires_card=False,
    streams=False,
    tags=("card-bridge", "config", "read-only"),
)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


get_registry().register(STATUS_SPEC)
get_registry().register(PROBE_SPEC)
get_registry().register(TOKEN_GENERATE_SPEC)
get_registry().register(CONFIG_SPEC)
