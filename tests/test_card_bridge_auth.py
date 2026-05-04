"""Unit tests for ``yggdrasim_common.card_bridge_auth``.

Pure-function module; no network, no card. Every test runs against a
``TemporaryDirectory`` so the host's real ``~/.config`` is untouched.
"""

from __future__ import annotations

import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from yggdrasim_common import card_bridge_auth as auth


class TokenGenerationTests(unittest.TestCase):
    def test_generate_returns_url_safe_high_entropy_string(self) -> None:
        token = auth.generate_token()
        self.assertGreaterEqual(len(token), 32)
        # URL-safe base64 charset only; padding has been stripped.
        for character in token:
            self.assertIn(character, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    def test_two_tokens_are_distinct(self) -> None:
        first = auth.generate_token()
        second = auth.generate_token()
        self.assertNotEqual(first, second)

    def test_under_minimum_entropy_raises(self) -> None:
        with self.assertRaises(ValueError):
            auth.generate_token(byte_count=8)


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_is_deterministic_and_short(self) -> None:
        token = "Test-Token-Value-12345"
        fp_one = auth.fingerprint(token)
        fp_two = auth.fingerprint(token)
        self.assertEqual(fp_one, fp_two)
        self.assertEqual(len(fp_one), auth.TOKEN_FINGERPRINT_LENGTH)

    def test_fingerprint_changes_with_token(self) -> None:
        self.assertNotEqual(auth.fingerprint("alpha"), auth.fingerprint("alpha "))

    def test_empty_token_yields_empty_fingerprint(self) -> None:
        self.assertEqual(auth.fingerprint(""), "")


class CompareTests(unittest.TestCase):
    def test_matching_tokens_compare_equal(self) -> None:
        self.assertTrue(auth.compare("alpha", "alpha"))

    def test_mismatching_tokens_compare_unequal(self) -> None:
        self.assertFalse(auth.compare("alpha", "beta"))

    def test_empty_presented_returns_false(self) -> None:
        self.assertFalse(auth.compare("", "alpha"))

    def test_empty_expected_returns_false(self) -> None:
        # Defence-in-depth -- even if the daemon hasn't been seeded with
        # a token, an empty Authorization header must never authorise.
        self.assertFalse(auth.compare("alpha", ""))


class ParseBearerHeaderTests(unittest.TestCase):
    def test_parses_canonical_bearer(self) -> None:
        self.assertEqual(auth.parse_bearer_header("Bearer abc123"), "abc123")

    def test_parses_lowercase_scheme(self) -> None:
        self.assertEqual(auth.parse_bearer_header("bearer abc123"), "abc123")

    def test_strips_surrounding_whitespace(self) -> None:
        self.assertEqual(auth.parse_bearer_header("  Bearer\tabc123\n"), "abc123")

    def test_rejects_non_bearer_scheme(self) -> None:
        self.assertEqual(auth.parse_bearer_header("Basic abc123"), "")

    def test_rejects_missing_scheme(self) -> None:
        self.assertEqual(auth.parse_bearer_header("abc123"), "")

    def test_rejects_empty_value(self) -> None:
        self.assertEqual(auth.parse_bearer_header(""), "")


class TokenFileIoTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.tempdir = Path(self._tempdir.name).resolve()

    def test_write_and_read_round_trip(self) -> None:
        path = self.tempdir / "subdir" / "token.txt"
        token = "one-line-token-with-trailing-newline-stripped"
        written = auth.write_token_file(path, token)
        self.assertEqual(written, path.resolve())
        self.assertEqual(auth.read_token_file(path), token)

    def test_write_rejects_empty_token(self) -> None:
        with self.assertRaises(ValueError):
            auth.write_token_file(self.tempdir / "empty.token", "")

    def test_write_creates_parent_directories(self) -> None:
        path = self.tempdir / "deeply" / "nested" / "dir" / "x.token"
        auth.write_token_file(path, "value")
        self.assertTrue(path.is_file())

    def test_write_sets_owner_only_permissions(self) -> None:
        path = self.tempdir / "permission.token"
        auth.write_token_file(path, "value")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600)


class DefaultTokenLocationTests(unittest.TestCase):
    def test_xdg_config_home_overrides_home(self) -> None:
        with TemporaryDirectory() as tempdir:
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tempdir}):
                directory = auth.default_token_directory()
        self.assertTrue(str(directory).endswith("/yggdrasim/card_bridge"))
        self.assertTrue(str(directory).startswith(tempdir))

    def test_default_falls_back_to_home_config(self) -> None:
        environment = dict(os.environ)
        environment.pop("XDG_CONFIG_HOME", None)
        with patch.dict(os.environ, environment, clear=True):
            directory = auth.default_token_directory()
        self.assertTrue(str(directory).endswith("/.config/yggdrasim/card_bridge"))

    def test_token_file_for_port_includes_port_number(self) -> None:
        with TemporaryDirectory() as tempdir:
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tempdir}):
                token_path = auth.default_token_file_for_port(8642)
        self.assertTrue(str(token_path).endswith("/yggdrasim/card_bridge/8642.token"))

    def test_token_file_for_port_rejects_out_of_range_values(self) -> None:
        with self.assertRaises(ValueError):
            auth.default_token_file_for_port(-1)
        with self.assertRaises(ValueError):
            auth.default_token_file_for_port(70000)


class EnvironmentResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.tempdir = Path(self._tempdir.name).resolve()

    def test_direct_env_var_wins(self) -> None:
        with patch.dict(os.environ, {auth.TOKEN_ENV_VAR: "from-env"}, clear=False):
            os.environ.pop(auth.TOKEN_FILE_ENV_VAR, None)
            self.assertEqual(auth.resolve_token_from_environment(), "from-env")

    def test_token_file_env_var_is_used_when_direct_is_empty(self) -> None:
        path = self.tempdir / "envfile.token"
        path.write_text("from-file\n", encoding="utf-8")
        environment = dict(os.environ)
        environment.pop(auth.TOKEN_ENV_VAR, None)
        environment[auth.TOKEN_FILE_ENV_VAR] = str(path)
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(auth.resolve_token_from_environment(), "from-file")

    def test_returns_empty_when_neither_env_var_set(self) -> None:
        environment = dict(os.environ)
        environment.pop(auth.TOKEN_ENV_VAR, None)
        environment.pop(auth.TOKEN_FILE_ENV_VAR, None)
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(auth.resolve_token_from_environment(), "")


class LoopbackHostTests(unittest.TestCase):
    def test_recognises_canonical_loopback_strings(self) -> None:
        for candidate in ("127.0.0.1", "::1", "localhost", "ip6-localhost"):
            self.assertTrue(auth.is_loopback_host(candidate))

    def test_recognises_extended_127_range(self) -> None:
        self.assertTrue(auth.is_loopback_host("127.5.5.5"))

    def test_rejects_public_addresses(self) -> None:
        for candidate in ("0.0.0.0", "192.168.1.1", "10.0.0.5", "8.8.8.8"):
            self.assertFalse(auth.is_loopback_host(candidate))

    def test_handles_empty_or_whitespace(self) -> None:
        self.assertFalse(auth.is_loopback_host(""))
        self.assertFalse(auth.is_loopback_host("   "))


if __name__ == "__main__":
    unittest.main()
