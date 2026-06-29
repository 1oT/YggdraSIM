# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Unit coverage for ``yggdrasim_common.gui_server.config`` and ``.auth``.

These helpers intentionally have *no* FastAPI / uvicorn / pywebview
imports at module load, so the tests here run on a baseline
``pip install yggdrasim`` install without requiring the optional GUI
extras. Any test that actually needs FastAPI belongs in a separate
``test_gui_routes_*`` module gated on the extras being installed.
"""

from __future__ import annotations

import os
import types

import pytest

from yggdrasim_common.gui_server import auth, config


# ---------------------------------------------------------------------------
# GuiServerConfig + builders
# ---------------------------------------------------------------------------


def _mk_args(**overrides):
    namespace = types.SimpleNamespace(
        host=None,
        port=None,
        token_file=None,
        tls_cert=None,
        tls_key=None,
        tls_self_signed=False,
        allow_origin=[],
    )
    for key, value in overrides.items():
        setattr(namespace, key, value)
    return namespace


def test_desktop_config_defaults(monkeypatch):
    for flag in (
        "YGGDRASIM_GUI_HOST", "YGGDRASIM_GUI_PORT",
        "YGGDRASIM_GUI_TOKEN", "YGGDRASIM_GUI_TOKEN_FILE",
        "YGGDRASIM_GUI_ALLOW_ORIGIN",
    ):
        monkeypatch.delenv(flag, raising=False)
    resolved = config.build_desktop_config(_mk_args())
    assert resolved.mode == config.MODE_DESKTOP
    assert resolved.host == config.DEFAULT_DESKTOP_HOST
    assert resolved.port == config.DEFAULT_DESKTOP_PORT
    assert len(resolved.token) >= config.MIN_TOKEN_ENTROPY_CHARS
    assert resolved.allow_ephemeral_port is True
    assert resolved.tls_cert_path is None
    assert resolved.base_url.startswith("http://127.0.0.1:")


def test_desktop_config_argparse_overrides_env(monkeypatch):
    monkeypatch.setenv("YGGDRASIM_GUI_HOST", "127.0.0.7")
    monkeypatch.setenv("YGGDRASIM_GUI_PORT", "30000")
    args = _mk_args(host="127.0.0.1", port=30123)
    resolved = config.build_desktop_config(args)
    assert resolved.host == "127.0.0.1"
    assert resolved.port == 30123


def test_desktop_config_token_file_permissions(monkeypatch, tmp_path):
    token_path = tmp_path / "tok"
    token_path.write_text("A" * 48)
    os.chmod(token_path, 0o600)
    args = _mk_args(token_file=str(token_path))
    resolved = config.build_desktop_config(args)
    assert resolved.token == "A" * 48

    os.chmod(token_path, 0o644)
    with pytest.raises(PermissionError):
        config.build_desktop_config(_mk_args(token_file=str(token_path)))


def test_web_server_config_requires_token(monkeypatch):
    for flag in (
        "YGGDRASIM_GUI_TOKEN", "YGGDRASIM_GUI_TOKEN_FILE",
        "YGGDRASIM_GUI_SERVER_HOST", "YGGDRASIM_GUI_SERVER_PORT",
    ):
        monkeypatch.delenv(flag, raising=False)
    with pytest.raises(SystemExit):
        config.build_web_server_config(_mk_args())


def test_web_server_config_rejects_weak_token(monkeypatch):
    monkeypatch.setenv("YGGDRASIM_GUI_TOKEN", "too-short")
    with pytest.raises(ValueError):
        config.build_web_server_config(_mk_args())


def test_web_server_config_tls_cert_without_key_is_rejected(monkeypatch):
    monkeypatch.setenv("YGGDRASIM_GUI_TOKEN", "A" * 48)
    with pytest.raises(SystemExit):
        config.build_web_server_config(_mk_args(tls_cert="/tmp/cert.pem"))


def test_web_server_config_rejects_wildcard_origin(monkeypatch):
    monkeypatch.setenv("YGGDRASIM_GUI_TOKEN", "A" * 48)
    with pytest.raises(SystemExit):
        config.build_web_server_config(_mk_args(allow_origin=["*"]))


def test_redacted_never_exposes_raw_token(monkeypatch):
    monkeypatch.delenv("YGGDRASIM_GUI_TOKEN", raising=False)
    monkeypatch.delenv("YGGDRASIM_GUI_TOKEN_FILE", raising=False)
    resolved = config.build_desktop_config(_mk_args())
    snapshot = resolved.redacted()
    assert resolved.token not in repr(snapshot)
    assert len(snapshot["token_id"]) == 8


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def test_compare_tokens_rejects_empty_expected():
    assert auth.compare_tokens("", "anything") is False


def test_compare_tokens_constant_time_match():
    token = "A" * 48
    assert auth.compare_tokens(token, token) is True
    assert auth.compare_tokens(token, token[:-1]) is False
    assert auth.compare_tokens(token, token + "x") is False


def test_extract_bearer_variants():
    assert auth.extract_bearer("Bearer abc") == "abc"
    assert auth.extract_bearer("bearer abc") == "abc"
    assert auth.extract_bearer("Basic abc") == ""
    assert auth.extract_bearer("") == ""
    assert auth.extract_bearer(None) == ""
    assert auth.extract_bearer("BearerNoSpace") == ""


def test_bypass_paths_are_recognised():
    for path in ("/", "/index.html", "/static/app.js", "/assets/logo.svg", "/favicon.ico", "/healthz"):
        assert auth.is_bypass_path(path) is True
    for path in ("/api/health", "/api/backend/state"):
        assert auth.is_bypass_path(path) is False


def test_failure_rate_limiter_triggers_after_limit():
    clock = {"t": 0.0}
    limiter = auth.FailureRateLimiter(
        window_seconds=60.0,
        max_failures=5,
        clock=lambda: clock["t"],
    )
    for i in range(5):
        assert limiter.register_failure("127.0.0.1") is False
        clock["t"] += 1.0
    # 6th failure pushes over the limit.
    over = limiter.register_failure("127.0.0.1")
    assert over is True
    assert limiter.is_blocked("127.0.0.1") is True
    # Isolation per source.
    assert limiter.is_blocked("192.0.2.1") is False


def test_failure_rate_limiter_recovers_after_window():
    clock = {"t": 0.0}
    limiter = auth.FailureRateLimiter(
        window_seconds=10.0,
        max_failures=2,
        clock=lambda: clock["t"],
    )
    limiter.register_failure("src")
    limiter.register_failure("src")
    assert limiter.register_failure("src") is True
    clock["t"] += 11.0
    assert limiter.is_blocked("src") is False


def test_token_id_deterministic_and_short():
    token = "A" * 48
    assert auth.token_id(token) == auth.token_id(token)
    assert len(auth.token_id(token)) == 8
    assert auth.token_id("") == ""
