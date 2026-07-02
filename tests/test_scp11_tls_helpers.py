# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the SCP11 TLS gate helpers.

Two gates are covered:

1. ``create_insecure_context`` / ``configure_unpinned_context`` — used
   by request-carrying transports. Default: refused. Opt-in via
   ``YGGDRASIM_SCP11_ALLOW_INSECURE_TLS``. Hard-lock via
   ``YGGDRASIM_SCP11_REQUIRE_PINNED_TLS``.

2. ``create_introspection_context`` — used by read-only TOFU chain
   reads. Default: allowed so operators can pop a new card / new eIM
   FQDN in and have the auto-learn path bootstrap trust. Hard-lock
   via ``YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION``.
"""

from __future__ import annotations

import os
import ssl
import unittest

from SCP11.shared import tls_helpers


ENV_ALLOW = tls_helpers.INSECURE_TLS_ENV
ENV_REQUIRE = tls_helpers.REQUIRE_PINNED_TLS_ENV
ENV_REQUIRE_INTROSPECTION = tls_helpers.REQUIRE_PINNED_INTROSPECTION_TLS_ENV


class _EnvScope:
    """Context manager that isolates the three env flags under test."""

    def __init__(self, **overrides: str | None) -> None:
        self._overrides = overrides
        self._saved: dict[str, str | None] = {}

    def __enter__(self) -> "_EnvScope":
        for name, value in self._overrides.items():
            self._saved[name] = os.environ.get(name)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        return self

    def __exit__(self, *exc_info: object) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class InsecureContextGateTests(unittest.TestCase):
    def test_default_refuses_without_opt_in(self) -> None:
        with _EnvScope(**{ENV_ALLOW: None, ENV_REQUIRE: None}):
            with self.assertRaises(RuntimeError) as caught:
                tls_helpers.create_insecure_context("pytest/insecure_default")
            self.assertIn("YGGDRASIM_SCP11_ALLOW_INSECURE_TLS", str(caught.exception))

    def test_opt_in_returns_unverified_context(self) -> None:
        with _EnvScope(**{ENV_ALLOW: "1", ENV_REQUIRE: None}):
            context = tls_helpers.create_insecure_context("pytest/insecure_opt_in")
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_hard_lock_overrides_opt_in(self) -> None:
        with _EnvScope(**{ENV_ALLOW: "1", ENV_REQUIRE: "1"}):
            with self.assertRaises(RuntimeError) as caught:
                tls_helpers.create_insecure_context("pytest/insecure_hard_lock")
            self.assertIn("YGGDRASIM_SCP11_REQUIRE_PINNED_TLS", str(caught.exception))

    def test_configure_unpinned_context_honours_gate(self) -> None:
        with _EnvScope(**{ENV_ALLOW: None, ENV_REQUIRE: None}):
            base_context = ssl.create_default_context()
            with self.assertRaises(RuntimeError):
                tls_helpers.configure_unpinned_context(base_context, "pytest/configure_refused")

    def test_configure_unpinned_context_downgrades_when_opted_in(self) -> None:
        base_context = ssl.create_default_context()
        self.assertTrue(base_context.check_hostname)
        with _EnvScope(**{ENV_ALLOW: "1", ENV_REQUIRE: None}):
            downgraded = tls_helpers.configure_unpinned_context(base_context, "pytest/configure_ok")
        self.assertIs(downgraded, base_context)
        self.assertFalse(base_context.check_hostname)
        self.assertEqual(base_context.verify_mode, ssl.CERT_NONE)


class IntrospectionContextGateTests(unittest.TestCase):
    def test_default_allows_tofu_chain_reads(self) -> None:
        with _EnvScope(**{ENV_REQUIRE_INTROSPECTION: None}):
            context = tls_helpers.create_introspection_context("pytest/introspection_default")
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_hard_lock_refuses_tofu_chain_reads(self) -> None:
        with _EnvScope(**{ENV_REQUIRE_INTROSPECTION: "1"}):
            with self.assertRaises(RuntimeError) as caught:
                tls_helpers.create_introspection_context("pytest/introspection_hard_lock")
            self.assertIn("YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION", str(caught.exception))

    def test_introspection_independent_of_insecure_request_gate(self) -> None:
        with _EnvScope(**{
            ENV_ALLOW: None,
            ENV_REQUIRE: "1",
            ENV_REQUIRE_INTROSPECTION: None,
        }):
            context = tls_helpers.create_introspection_context("pytest/introspection_independent")
            self.assertIsInstance(context, ssl.SSLContext)
            with self.assertRaises(RuntimeError):
                tls_helpers.create_insecure_context("pytest/insecure_still_refused")

    def test_introspection_tls_allowed_helper_matches_env(self) -> None:
        with _EnvScope(**{ENV_REQUIRE_INTROSPECTION: None}):
            self.assertTrue(tls_helpers.introspection_tls_allowed())
        with _EnvScope(**{ENV_REQUIRE_INTROSPECTION: "1"}):
            self.assertFalse(tls_helpers.introspection_tls_allowed())
        with _EnvScope(**{ENV_REQUIRE_INTROSPECTION: "false"}):
            self.assertTrue(tls_helpers.introspection_tls_allowed())


if __name__ == "__main__":
    unittest.main()
