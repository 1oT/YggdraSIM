# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Client-side bearer token tests for ``yggdrasim_common.card_backend``.

Verifies that:

* :class:`RelayCardConnection` attaches an ``Authorization: Bearer …``
  header to outbound HTTP exchanges when a token is configured.
* :func:`_resolve_card_relay_token` honours ``YGGDRASIM_CARD_RELAY_TOKEN``
  and ``YGGDRASIM_CARD_RELAY_TOKEN_FILE`` in the documented order.
* The marker file's optional ``token`` / ``tokenFile`` fields are
  consulted only for marker-sourced relay URLs.

The HTTP exchange is captured by stubbing
``yggdrasim_common.card_backend._request_card_relay_json`` so no real
network IO happens.
"""

from __future__ import annotations

import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib import error as urllib_error
from unittest.mock import patch

from yggdrasim_common import card_backend


class RelayCardConnectionAuthHeaderTests(unittest.TestCase):
    def test_transmit_attaches_bearer_when_token_present(self) -> None:
        captured: dict[str, Any] = {}

        def fake_request(url, *, method, timeout_seconds, request_json=None, auth_token=""):
            captured["url"] = url
            captured["method"] = method
            captured["request_json"] = request_json
            captured["auth_token"] = auth_token
            if url.endswith("/status"):
                return {"atr": "3B00"}
            return {"data": "DEADBEEF", "sw1": "90", "sw2": "00"}

        with patch.object(card_backend, "_request_card_relay_json", side_effect=fake_request):
            connection = card_backend.RelayCardConnection(
                "http://127.0.0.1:8642/apdu",
                auth_token="my-token",
            )
            connection.connect()
            data, sw1, sw2 = connection.transmit(bytes.fromhex("00A40400"))

        self.assertEqual(data, [0xDE, 0xAD, 0xBE, 0xEF])
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(captured["auth_token"], "my-token")
        self.assertEqual(captured["request_json"], {"apdu": "00A40400"})

    def test_transmit_omits_bearer_when_no_token(self) -> None:
        captured: dict[str, Any] = {}

        def fake_request(url, *, method, timeout_seconds, request_json=None, auth_token=""):
            captured["auth_token"] = auth_token
            if url.endswith("/status"):
                return {"atr": "3B00"}
            return {"data": "", "sw1": "90", "sw2": "00"}

        with patch.object(card_backend, "_request_card_relay_json", side_effect=fake_request):
            connection = card_backend.RelayCardConnection("http://127.0.0.1:8642/apdu")
            connection.connect()
            connection.transmit(bytes.fromhex("00A40400"))

        self.assertEqual(captured["auth_token"], "")


class RequestHelperHeaderTests(unittest.TestCase):
    def test_helper_sets_authorization_header(self) -> None:
        captured_request: dict[str, Any] = {}

        class _FakeResponse:
            status = 200

            def __init__(self, body: bytes) -> None:
                self._body = body

            def __enter__(self) -> "_FakeResponse":
                return self

            def __exit__(self, *_args) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                return self._body if size < 0 else self._body[:size]

        def fake_urlopen(request, timeout=0):
            captured_request["headers"] = dict(request.header_items())
            captured_request["url"] = request.full_url
            captured_request["data"] = request.data
            return _FakeResponse(b"{\"ok\": true}")

        with patch.object(card_backend.urllib_request, "urlopen", side_effect=fake_urlopen):
            payload = card_backend._request_card_relay_json(
                "http://127.0.0.1:8642/apdu",
                method="POST",
                request_json={"apdu": "00"},
                auth_token="bearer-value",
            )

        self.assertEqual(payload, {"ok": True})
        # urllib lower-cases header names internally; iterate without assuming case.
        header_lookup = {key.lower(): value for key, value in captured_request["headers"].items()}
        self.assertEqual(header_lookup.get("authorization"), "Bearer bearer-value")

    def test_helper_rejects_oversized_response(self) -> None:
        class _OversizedResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                return b"x" * size

        with patch.object(
            card_backend.urllib_request,
            "urlopen",
            return_value=_OversizedResponse(),
        ):
            with self.assertRaisesRegex(RuntimeError, "1 MiB safety limit"):
                card_backend._request_card_relay_json(
                    "http://127.0.0.1:8642/status",
                    method="GET",
                )

    def test_timeout_error_does_not_echo_url_or_token(self) -> None:
        secret_url = "http://127.0.0.1:8642/status?access_token=url-secret"
        with patch.object(
            card_backend.urllib_request,
            "urlopen",
            side_effect=TimeoutError(secret_url),
        ):
            with self.assertRaises(RuntimeError) as raised:
                card_backend._request_card_relay_json(
                    secret_url,
                    method="GET",
                    auth_token="bearer-secret",
                )

        message = str(raised.exception)
        self.assertEqual(message, "Card relay connection timed out.")
        self.assertNotIn("url-secret", message)
        self.assertNotIn("bearer-secret", message)

    def test_http_error_redacts_presented_bearer(self) -> None:
        token = "opaque-bearer-secret"
        error = urllib_error.HTTPError(
            "http://127.0.0.1:8642/status",
            401,
            "Unauthorized",
            {},
            io.BytesIO(
                b'{"error":"Authorization: Bearer opaque-bearer-secret rejected"}'
            ),
        )
        with patch.object(
            card_backend.urllib_request,
            "urlopen",
            side_effect=error,
        ):
            with self.assertRaises(RuntimeError) as raised:
                card_backend._request_card_relay_json(
                    "http://127.0.0.1:8642/status",
                    method="GET",
                    auth_token=token,
                )

        message = str(raised.exception)
        self.assertIn("<redacted>", message)
        self.assertNotIn(token, message)


class TokenResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.tempdir = Path(self._tempdir.name).resolve()

    def _clean_env(self) -> dict[str, str]:
        environment = dict(os.environ)
        for key in (
            card_backend.CARD_RELAY_TOKEN_ENV,
            card_backend.CARD_RELAY_TOKEN_FILE_ENV,
        ):
            environment.pop(key, None)
        return environment

    def test_direct_env_token_wins(self) -> None:
        environment = self._clean_env()
        environment[card_backend.CARD_RELAY_TOKEN_ENV] = "direct-token"
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(
                card_backend._resolve_card_relay_token(allow_marker=False),
                "direct-token",
            )

    def test_token_file_env_used_when_direct_is_empty(self) -> None:
        path = self.tempdir / "tok.txt"
        path.write_text("file-token\n", encoding="utf-8")
        environment = self._clean_env()
        environment[card_backend.CARD_RELAY_TOKEN_FILE_ENV] = str(path)
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(
                card_backend._resolve_card_relay_token(allow_marker=False),
                "file-token",
            )

    def test_marker_token_consulted_only_when_allowed(self) -> None:
        environment = self._clean_env()

        def fake_marker_payload() -> dict[str, Any]:
            return {"token": "marker-token"}

        with patch.dict(os.environ, environment, clear=True):
            with patch.object(
                card_backend, "_read_card_relay_marker_payload", side_effect=fake_marker_payload
            ):
                self.assertEqual(
                    card_backend._resolve_card_relay_token(allow_marker=True),
                    "marker-token",
                )
                self.assertEqual(
                    card_backend._resolve_card_relay_token(allow_marker=False),
                    "",
                )

    def test_marker_token_file_field_is_followed(self) -> None:
        token_path = self.tempdir / "marker_tok.txt"
        token_path.write_text("via-marker-file\n", encoding="utf-8")
        environment = self._clean_env()

        def fake_marker_payload() -> dict[str, Any]:
            return {"tokenFile": str(token_path)}

        with patch.dict(os.environ, environment, clear=True):
            with patch.object(
                card_backend, "_read_card_relay_marker_payload", side_effect=fake_marker_payload
            ):
                self.assertEqual(
                    card_backend._resolve_card_relay_token(allow_marker=True),
                    "via-marker-file",
                )

    def test_returns_empty_when_no_source_set(self) -> None:
        environment = self._clean_env()
        with patch.dict(os.environ, environment, clear=True):
            with patch.object(
                card_backend, "_read_card_relay_marker_payload", return_value={}
            ):
                self.assertEqual(
                    card_backend._resolve_card_relay_token(allow_marker=True),
                    "",
                )


if __name__ == "__main__":
    unittest.main()
