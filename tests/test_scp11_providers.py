# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SCP11/providers.py public utilities.

Covers: Sgp26LocalProvider.load_certificate_chain (empty-paths path),
        Sgp26LocalProvider.decode_b64_to_bytes,
        RemoteEs9Provider passthrough getters via a minimal mock client.
"""

from __future__ import annotations

import unittest

try:
    from SCP11.providers import RemoteEs9Provider, Sgp26LocalProvider
    _IMPORT_OK = True
except (ImportError, ModuleNotFoundError):
    _IMPORT_OK = False

_SKIP = unittest.skipUnless(_IMPORT_OK, "SCP11 deps not installed")


# ---------------------------------------------------------------------------
# Sgp26LocalProvider.decode_b64_to_bytes  (static — no deps)
# ---------------------------------------------------------------------------

@_SKIP
class DecodeB64ToBytesTests(unittest.TestCase):

    def test_empty_string_returns_empty_bytes(self) -> None:
        self.assertEqual(Sgp26LocalProvider.decode_b64_to_bytes(""), b"")

    def test_known_b64_decoded(self) -> None:
        # "AAEC" → bytes 0x00 0x01 0x02
        result = Sgp26LocalProvider.decode_b64_to_bytes("AAEC")
        self.assertEqual(result, bytes([0x00, 0x01, 0x02]))

    def test_padding_handled(self) -> None:
        result = Sgp26LocalProvider.decode_b64_to_bytes("AA==")
        self.assertEqual(result, bytes([0x00]))

    def test_returns_bytes_type(self) -> None:
        result = Sgp26LocalProvider.decode_b64_to_bytes("dGVzdA==")
        self.assertIsInstance(result, bytes)
        self.assertEqual(result, b"test")


# ---------------------------------------------------------------------------
# Sgp26LocalProvider.load_certificate_chain — empty-paths path
# ---------------------------------------------------------------------------

@_SKIP
class LoadCertificateChainEmptyTests(unittest.TestCase):

    def test_empty_paths_no_exception(self) -> None:
        provider = Sgp26LocalProvider()
        provider.load_certificate_chain()
        self.assertTrue(provider._chain_loaded)
        self.assertIsNone(provider._trust_anchor)
        self.assertEqual(provider._intermediates, [])
        self.assertIsNone(provider._issuer_cert)


# ---------------------------------------------------------------------------
# RemoteEs9Provider passthrough getters via a minimal stub client
# ---------------------------------------------------------------------------

class _StubClient:
    """Minimal Es9LikeClient stub for testing RemoteEs9Provider delegation."""

    def get_base_url(self) -> str:
        return "https://smdp.example.test"

    def get_verify_tls(self) -> bool:
        return True

    def get_ca_bundle_path(self) -> str:
        return "/tmp/ca.pem"

    def resolve_provider_certificate_validation_bundle(
        self, certificate_der: bytes, trust_hint_ci_pkid: str = ""
    ) -> str:
        return "/tmp/resolved_ca.pem"


@_SKIP
class RemoteEs9ProviderGetterTests(unittest.TestCase):

    def setUp(self) -> None:
        self._provider = RemoteEs9Provider(_StubClient())

    def test_get_base_url_delegates(self) -> None:
        self.assertEqual(self._provider.get_base_url(), "https://smdp.example.test")

    def test_get_verify_tls_delegates(self) -> None:
        self.assertTrue(self._provider.get_verify_tls())

    def test_get_ca_bundle_path_delegates(self) -> None:
        self.assertEqual(self._provider.get_ca_bundle_path(), "/tmp/ca.pem")

    def test_resolve_bundle_delegates(self) -> None:
        result = self._provider.resolve_provider_certificate_validation_bundle(
            b"\x00", trust_hint_ci_pkid=""
        )
        self.assertEqual(result, "/tmp/resolved_ca.pem")


if __name__ == "__main__":
    unittest.main()
