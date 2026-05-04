"""Unit tests for ``yggdrasim_common.remote_card_args`` (CB-3).

Covers:

* Argparse registration: flags exist with the expected dest names.
* ``apply_remote_card_arguments`` mirrors the parsed flags into the
  process environment (URL + token-file overrides, env clearing on
  empty string, source attribution).
* ``describe_remote_card_state`` produces the expected one-liner for
  configured / unconfigured / loopback / env-only cases.

The tests use a private ``environment`` dict so the real ``os.environ``
is never mutated -- keeps the suite safe to run alongside other tests
that depend on a clean env.
"""

from __future__ import annotations

import argparse

import pytest

from yggdrasim_common.card_backend import (
    CARD_RELAY_TOKEN_ENV,
    CARD_RELAY_TOKEN_FILE_ENV,
    CARD_RELAY_URL_ENV,
)
from yggdrasim_common.remote_card_args import (
    DEST_REMOTE_CARD_TOKEN_FILE,
    DEST_REMOTE_CARD_URL,
    add_remote_card_arguments,
    apply_remote_card_arguments,
    describe_remote_card_state,
)


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    add_remote_card_arguments(parser)
    return parser


# --- argparse registration --------------------------------------------------


def test_flags_register_with_expected_dest_names():
    parser = _make_parser()
    namespace = parser.parse_args([])
    assert hasattr(namespace, DEST_REMOTE_CARD_URL)
    assert hasattr(namespace, DEST_REMOTE_CARD_TOKEN_FILE)
    assert getattr(namespace, DEST_REMOTE_CARD_URL) is None
    assert getattr(namespace, DEST_REMOTE_CARD_TOKEN_FILE) is None


def test_flags_accept_url_and_token_file():
    parser = _make_parser()
    namespace = parser.parse_args(
        [
            "--remote-card-url",
            "http://127.0.0.1:8642/apdu",
            "--remote-card-token-file",
            "/tmp/tok",
        ]
    )
    assert getattr(namespace, DEST_REMOTE_CARD_URL) == "http://127.0.0.1:8642/apdu"
    assert getattr(namespace, DEST_REMOTE_CARD_TOKEN_FILE) == "/tmp/tok"


def test_flags_group_appears_in_help_output():
    parser = _make_parser()
    formatted = parser.format_help()
    assert "Remote card bridge" in formatted
    assert "--remote-card-url" in formatted
    assert "--remote-card-token-file" in formatted


# --- apply_remote_card_arguments mirroring ---------------------------------


def test_apply_writes_url_and_token_file_into_environment():
    parser = _make_parser()
    namespace = parser.parse_args(
        [
            "--remote-card-url",
            "http://127.0.0.1:8642/apdu",
            "--remote-card-token-file",
            "/tmp/mock-token",
        ]
    )
    env: dict[str, str] = {}
    state = apply_remote_card_arguments(namespace, environment=env)
    assert env[CARD_RELAY_URL_ENV] == "http://127.0.0.1:8642/apdu"
    assert env[CARD_RELAY_TOKEN_FILE_ENV] == "/tmp/mock-token"
    assert state["url"] == "http://127.0.0.1:8642/apdu"
    assert state["url_source"] == "flag"
    assert state["token_source"] == "flag"


def test_apply_with_no_flags_preserves_existing_env():
    parser = _make_parser()
    namespace = parser.parse_args([])
    env: dict[str, str] = {
        CARD_RELAY_URL_ENV: "http://127.0.0.1:9999/apdu",
        CARD_RELAY_TOKEN_FILE_ENV: "/etc/cardtok",
    }
    state = apply_remote_card_arguments(namespace, environment=env)
    assert env[CARD_RELAY_URL_ENV] == "http://127.0.0.1:9999/apdu"
    assert env[CARD_RELAY_TOKEN_FILE_ENV] == "/etc/cardtok"
    assert state["url_source"] == "env"
    assert state["token_source"] == "env-file"


def test_apply_empty_url_string_clears_env():
    parser = _make_parser()
    namespace = parser.parse_args(["--remote-card-url", ""])
    env: dict[str, str] = {CARD_RELAY_URL_ENV: "http://stale/apdu"}
    state = apply_remote_card_arguments(namespace, environment=env)
    assert CARD_RELAY_URL_ENV not in env
    assert state["url"] == ""
    assert state["url_source"] == "flag"


def test_apply_empty_token_file_string_clears_env():
    parser = _make_parser()
    namespace = parser.parse_args(["--remote-card-token-file", ""])
    env: dict[str, str] = {CARD_RELAY_TOKEN_FILE_ENV: "/tmp/stale"}
    state = apply_remote_card_arguments(namespace, environment=env)
    assert CARD_RELAY_TOKEN_FILE_ENV not in env
    assert state["token_file"] == ""
    assert state["token_source"] == "flag"


def test_apply_token_file_clears_raw_token_env():
    parser = _make_parser()
    namespace = parser.parse_args(["--remote-card-token-file", "/tmp/tok"])
    env: dict[str, str] = {CARD_RELAY_TOKEN_ENV: "raw-leftover-token"}
    apply_remote_card_arguments(namespace, environment=env)
    assert CARD_RELAY_TOKEN_ENV not in env
    assert env[CARD_RELAY_TOKEN_FILE_ENV] == "/tmp/tok"


def test_apply_expands_user_in_token_file_path(tmp_path, monkeypatch):
    parser = _make_parser()
    namespace = parser.parse_args(["--remote-card-token-file", "~/relay.tok"])
    monkeypatch.setenv("HOME", str(tmp_path))
    env: dict[str, str] = {}
    apply_remote_card_arguments(namespace, environment=env)
    assert env[CARD_RELAY_TOKEN_FILE_ENV] == str(tmp_path / "relay.tok")


def test_apply_reports_env_raw_when_only_raw_token_present():
    parser = _make_parser()
    namespace = parser.parse_args([])
    env: dict[str, str] = {
        CARD_RELAY_URL_ENV: "http://127.0.0.1:8642/apdu",
        CARD_RELAY_TOKEN_ENV: "raw-token",
    }
    state = apply_remote_card_arguments(namespace, environment=env)
    assert state["token_source"] == "env-raw"


def test_apply_reports_no_token_when_url_set_without_token():
    parser = _make_parser()
    namespace = parser.parse_args([])
    env: dict[str, str] = {CARD_RELAY_URL_ENV: "http://127.0.0.1:8642/apdu"}
    state = apply_remote_card_arguments(namespace, environment=env)
    assert state["url_source"] == "env"
    assert state["token_source"] == ""


# --- describe_remote_card_state --------------------------------------------


def test_describe_unconfigured_state():
    line = describe_remote_card_state(
        {
            "url": "",
            "url_source": "",
            "token_file": "",
            "token_source": "",
        }
    )
    assert "not configured" in line
    assert "local PC/SC" in line


def test_describe_configured_with_token_flag():
    line = describe_remote_card_state(
        {
            "url": "http://127.0.0.1:8642/apdu",
            "url_source": "flag",
            "token_file": "/tmp/tok",
            "token_source": "flag",
        }
    )
    assert "http://127.0.0.1:8642/apdu" in line
    assert "/tmp/tok" in line
    assert "flag" in line


def test_describe_configured_with_env_file_token():
    line = describe_remote_card_state(
        {
            "url": "http://10.0.0.5:8642/apdu",
            "url_source": "env",
            "token_file": "/etc/cardtok",
            "token_source": "env-file",
        }
    )
    assert "/etc/cardtok" in line
    assert "env" in line


def test_describe_configured_with_raw_env_token():
    line = describe_remote_card_state(
        {
            "url": "http://10.0.0.5:8642/apdu",
            "url_source": "env",
            "token_file": "",
            "token_source": "env-raw",
        }
    )
    assert "YGGDRASIM_CARD_RELAY_TOKEN" in line


def test_describe_configured_loopback_no_token():
    line = describe_remote_card_state(
        {
            "url": "http://127.0.0.1:8642/apdu",
            "url_source": "env",
            "token_file": "",
            "token_source": "",
        }
    )
    assert "no token" in line
    assert "loopback" in line


# --- regression: parser keeps unrelated flags intact -----------------------


def test_parser_does_not_collide_with_existing_flags():
    parser = argparse.ArgumentParser()
    parser.add_argument("--something-else", default=None)
    add_remote_card_arguments(parser)
    namespace = parser.parse_args(
        ["--something-else", "value", "--remote-card-url", "http://x/apdu"]
    )
    assert namespace.something_else == "value"
    assert getattr(namespace, DEST_REMOTE_CARD_URL) == "http://x/apdu"


def test_apply_returns_token_file_path_in_state():
    parser = _make_parser()
    namespace = parser.parse_args(["--remote-card-token-file", "/var/run/cardtok"])
    env: dict[str, str] = {}
    state = apply_remote_card_arguments(namespace, environment=env)
    assert state["token_file"] == "/var/run/cardtok"


def test_apply_real_environ_round_trip():
    """When ``environment`` is omitted the helper must mutate ``os.environ``.

    Manual snapshot/restore so the test never leaks state into other
    suites that observe ``YGGDRASIM_CARD_RELAY_URL`` (e.g. the
    HilBridge marker-fallback test stack).
    """
    import os as _os

    snapshot = {
        key: _os.environ.get(key)
        for key in (CARD_RELAY_URL_ENV, CARD_RELAY_TOKEN_FILE_ENV, CARD_RELAY_TOKEN_ENV)
    }
    for key in snapshot:
        _os.environ.pop(key, None)
    try:
        parser = _make_parser()
        namespace = parser.parse_args(
            ["--remote-card-url", "http://127.0.0.1:8642/apdu"]
        )
        apply_remote_card_arguments(namespace)
        assert _os.environ.get(CARD_RELAY_URL_ENV) == "http://127.0.0.1:8642/apdu"
    finally:
        for key, value in snapshot.items():
            if value is None:
                _os.environ.pop(key, None)
            else:
                _os.environ[key] = value


def test_apply_state_keys_exhaustive():
    parser = _make_parser()
    namespace = parser.parse_args([])
    env: dict[str, str] = {}
    state = apply_remote_card_arguments(namespace, environment=env)
    for key in ("url", "url_source", "token_file", "token_source"):
        assert key in state, f"missing key: {key}"


def test_describe_handles_missing_keys_gracefully():
    line = describe_remote_card_state({})
    assert "not configured" in line


@pytest.mark.parametrize(
    "argv,expected_url",
    [
        ([], None),
        (["--remote-card-url", "http://h:1/apdu"], "http://h:1/apdu"),
        (["--remote-card-url", " trim-me  "], " trim-me  "),
    ],
)
def test_parse_url_variants(argv, expected_url):
    parser = _make_parser()
    namespace = parser.parse_args(argv)
    assert getattr(namespace, DEST_REMOTE_CARD_URL) == expected_url


def test_apply_strips_whitespace_in_url():
    parser = _make_parser()
    namespace = parser.parse_args(["--remote-card-url", "  http://x/apdu  "])
    env: dict[str, str] = {}
    apply_remote_card_arguments(namespace, environment=env)
    assert env[CARD_RELAY_URL_ENV] == "http://x/apdu"
