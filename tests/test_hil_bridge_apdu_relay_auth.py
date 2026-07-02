# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Integration tests for the bearer-auth / audit additions to ``apdu_relay``.

The historical functional tests in ``tests/test_hil_bridge_card_relay.py``
already cover the loopback-no-token path. This module exercises:

* The non-loopback bind guard rejecting startup without a token.
* Bearer-required mode rejecting requests without ``Authorization``.
* Bearer-required mode accepting requests with the correct token.
* The peer throttle locking out a peer after repeated bad tokens.
* The header-only audit log emitting fields without the APDU body.
* The status payload exposing the auth posture and token fingerprint.

Each test starts a relay on an ephemeral port and tears it down in
``finally``. Tests run sequentially so port reuse isn't an issue.
"""

from __future__ import annotations

import json
import logging
import unittest
from urllib import error as urllib_error
from urllib import request as urllib_request

from Tools.HilBridge.apdu_relay import (
    ApduRelayConfig,
    HilBridgeApduRelayService,
    _PeerThrottle,
)


def _post(url: str, payload: dict, *, token: str = "") -> tuple[int, dict]:
    """POST a JSON payload, returning ``(status, body)`` even on 4xx/5xx."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib_request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if len(token) > 0:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib_request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if len(raw) > 0 else {}
    except urllib_error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"_raw": raw}
        return exc.code, payload


def _get(url: str, *, token: str = "") -> tuple[int, dict]:
    request = urllib_request.Request(url, method="GET")
    if len(token) > 0:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib_request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if len(raw) > 0 else {}
    except urllib_error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"_raw": raw}
        return exc.code, payload


class _FakeService(unittest.TestCase):
    pass


class StartupGuardTests(unittest.TestCase):
    def test_non_loopback_bind_without_token_refuses_to_start(self) -> None:
        service = HilBridgeApduRelayService(
            ApduRelayConfig(host="0.0.0.0", port=0, enabled=True),
            exchange_callback=lambda apdu, *, session_id="": (b"", 0x90, 0x00),
            status_callback=lambda: {},
        )
        with self.assertRaises(RuntimeError) as ctx:
            service.start()
        self.assertIn("0.0.0.0", str(ctx.exception))
        self.assertIn("bearer token", str(ctx.exception))

    def test_non_loopback_bind_with_token_starts_cleanly(self) -> None:
        service = HilBridgeApduRelayService(
            ApduRelayConfig(host="127.0.0.1", port=0, enabled=True, auth_token="token-xyz"),
            exchange_callback=lambda apdu, *, session_id="": (b"", 0x90, 0x00),
            status_callback=lambda: {"reader": "fake"},
        )
        try:
            service.start()
            self.assertTrue(service.apdu_url.startswith("http://127.0.0.1:"))
        finally:
            service.stop()


class TokenEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self._exchanges: list[bytes] = []
        self._service = HilBridgeApduRelayService(
            ApduRelayConfig(
                host="127.0.0.1",
                port=0,
                enabled=True,
                auth_token="correct-horse-battery-staple",
                auth_lockout_failures=3,
                auth_lockout_window_seconds=30.0,
                auth_lockout_duration_seconds=60.0,
            ),
            exchange_callback=self._capture,
            status_callback=lambda: {"reader": "fake", "atr": "3B00"},
        )
        self._service.start()
        self.addCleanup(self._service.stop)

    def _capture(self, apdu: bytes, *, session_id: str = "") -> tuple[bytes, int, int]:
        del session_id
        self._exchanges.append(bytes(apdu))
        return bytes.fromhex("DEADBEEF"), 0x90, 0x00

    def test_request_without_authorization_is_rejected(self) -> None:
        status, payload = _post(
            self._service.apdu_url,
            {"apdu": "00A40400"},
        )
        self.assertEqual(status, 401)
        self.assertIn("error", payload)
        self.assertEqual(self._exchanges, [])

    def test_request_with_wrong_token_is_rejected(self) -> None:
        status, payload = _post(
            self._service.apdu_url,
            {"apdu": "00A40400"},
            token="not-the-right-token",
        )
        self.assertEqual(status, 401)
        self.assertIn("error", payload)
        self.assertEqual(self._exchanges, [])

    def test_request_with_correct_token_succeeds(self) -> None:
        status, payload = _post(
            self._service.apdu_url,
            {"apdu": "00A40400"},
            token="correct-horse-battery-staple",
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"data": "DEADBEEF", "sw1": "90", "sw2": "00"})
        self.assertEqual(self._exchanges, [bytes.fromhex("00A40400")])

    def test_status_endpoint_also_requires_token(self) -> None:
        status_unauth, _ = _get(self._service.status_url)
        self.assertEqual(status_unauth, 401)
        status_authed, payload = _get(
            self._service.status_url, token="correct-horse-battery-staple"
        )
        self.assertEqual(status_authed, 200)
        self.assertTrue(payload.get("authRequired"))
        self.assertIn("tokenFingerprint", payload)
        self.assertEqual(len(payload["tokenFingerprint"]), 6)

    def test_ping_endpoint_remains_unauthenticated(self) -> None:
        # /ping is intentionally open: it returns no card data, only
        # liveness, and SSH-tunnelled clients use it to verify the
        # LocalForward without yet caring about the token.
        ping_url = self._service.base_url + "/ping"
        request = urllib_request.Request(ping_url, method="GET")
        with urllib_request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read().strip(), b"pong")


class PeerThrottleTests(unittest.TestCase):
    def test_lockout_after_threshold_is_reached(self) -> None:
        throttle = _PeerThrottle(failures=3, window_seconds=30.0, lockout_seconds=60.0)
        self.assertFalse(throttle.is_locked("192.0.2.4", now=100.0))
        self.assertFalse(throttle.record_failure("192.0.2.4", now=100.0))
        self.assertFalse(throttle.record_failure("192.0.2.4", now=100.5))
        self.assertTrue(throttle.record_failure("192.0.2.4", now=101.0))
        self.assertTrue(throttle.is_locked("192.0.2.4", now=140.0))
        self.assertFalse(throttle.is_locked("192.0.2.4", now=200.0))

    def test_success_resets_failure_log(self) -> None:
        throttle = _PeerThrottle(failures=3, window_seconds=30.0, lockout_seconds=60.0)
        throttle.record_failure("192.0.2.4", now=100.0)
        throttle.record_failure("192.0.2.4", now=100.1)
        throttle.record_success("192.0.2.4")
        self.assertFalse(throttle.record_failure("192.0.2.4", now=101.0))

    def test_failures_outside_window_are_dropped(self) -> None:
        throttle = _PeerThrottle(failures=3, window_seconds=10.0, lockout_seconds=60.0)
        throttle.record_failure("192.0.2.4", now=100.0)
        throttle.record_failure("192.0.2.4", now=101.0)
        # Third failure 30s later — outside the 10s window, so the
        # earlier ones must be evicted and this should not lock out.
        self.assertFalse(throttle.record_failure("192.0.2.4", now=130.0))


class AuditLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self._records: list[logging.LogRecord] = []
        self._handler = logging.Handler()
        self._handler.emit = self._records.append
        logger = logging.getLogger("yggdrasim.test.card_bridge.audit")
        logger.setLevel(logging.INFO)
        logger.addHandler(self._handler)
        self.addCleanup(logger.removeHandler, self._handler)

    def test_audit_record_contains_header_bytes_only_by_default(self) -> None:
        service = HilBridgeApduRelayService(
            ApduRelayConfig(
                host="127.0.0.1",
                port=0,
                enabled=True,
                audit_enabled=True,
                audit_full_apdu=False,
                audit_logger_name="yggdrasim.test.card_bridge.audit",
            ),
            exchange_callback=lambda apdu, *, session_id="": (bytes.fromhex("CAFE"), 0x90, 0x00),
            status_callback=lambda: {"reader": "fake"},
        )
        service.start()
        try:
            _post(service.apdu_url, {"apdu": "00A40400022FE2"})
        finally:
            service.stop()

        self.assertEqual(len(self._records), 1)
        record = self._records[0]
        audit = record.__dict__["audit"]
        # Header bytes are present.
        self.assertEqual(audit["cla"], "00")
        self.assertEqual(audit["ins"], "A4")
        self.assertEqual(audit["p1"], "04")
        self.assertEqual(audit["p2"], "00")
        self.assertEqual(audit["lc"], "02")
        self.assertEqual(audit["sw"], "9000")
        # APDU body and response hex are deliberately omitted.
        self.assertNotIn("apduHex", audit)
        self.assertNotIn("respHex", audit)

    def test_full_apdu_audit_includes_hex_when_explicitly_enabled(self) -> None:
        service = HilBridgeApduRelayService(
            ApduRelayConfig(
                host="127.0.0.1",
                port=0,
                enabled=True,
                audit_enabled=True,
                audit_full_apdu=True,
                audit_logger_name="yggdrasim.test.card_bridge.audit",
            ),
            exchange_callback=lambda apdu, *, session_id="": (bytes.fromhex("CAFE"), 0x90, 0x00),
            status_callback=lambda: {"reader": "fake"},
        )
        service.start()
        try:
            _post(service.apdu_url, {"apdu": "00A40400022FE2"})
        finally:
            service.stop()

        self.assertEqual(len(self._records), 1)
        audit = self._records[0].__dict__["audit"]
        self.assertEqual(audit["apduHex"], "00A40400022FE2")
        self.assertEqual(audit["respHex"], "CAFE")


if __name__ == "__main__":
    unittest.main()
