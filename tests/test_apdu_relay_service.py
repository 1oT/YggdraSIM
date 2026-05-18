# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``Tools.HilBridge.apdu_relay.HilBridgeApduRelayService`` helpers.

Covers: expected_token, peer_throttle, exchange_apdu, request_modem_refresh,
record_apdu_audit, and the private _build_audit_record static method.
No sockets are opened; the exchange and status callbacks are mocked.
"""

from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock

from Tools.HilBridge.apdu_relay import (
    ApduRelayConfig,
    HilBridgeApduRelayService,
)


def _make_service(
    *,
    auth_token: str = "",
    audit_enabled: bool = False,
    audit_full_apdu: bool = False,
    with_modem_refresh: bool = False,
) -> HilBridgeApduRelayService:
    config = ApduRelayConfig(
        auth_token=auth_token,
        audit_enabled=audit_enabled,
        audit_full_apdu=audit_full_apdu,
    )
    exchange_cb = MagicMock(return_value=(b"\x90\x00", 0x90, 0x00))
    status_cb = MagicMock(return_value={})
    modem_cb = MagicMock(return_value={"refreshed": True}) if with_modem_refresh else None
    return HilBridgeApduRelayService(
        config=config,
        exchange_callback=exchange_cb,
        status_callback=status_cb,
        modem_refresh_callback=modem_cb,
    )


class ExpectedTokenTests(unittest.TestCase):

    def test_empty_token(self) -> None:
        svc = _make_service(auth_token="")
        self.assertEqual(svc.expected_token, "")

    def test_non_empty_token(self) -> None:
        svc = _make_service(auth_token="secret-token-xyz")
        self.assertEqual(svc.expected_token, "secret-token-xyz")

    def test_returns_string(self) -> None:
        self.assertIsInstance(_make_service().expected_token, str)


class PeerThrottleTests(unittest.TestCase):

    def test_returns_peer_throttle_instance(self) -> None:
        svc = _make_service()
        from Tools.HilBridge.apdu_relay import _PeerThrottle
        self.assertIsInstance(svc.peer_throttle, _PeerThrottle)

    def test_same_object_each_call(self) -> None:
        svc = _make_service()
        self.assertIs(svc.peer_throttle, svc.peer_throttle)


class ExchangeApduTests(unittest.TestCase):

    def test_delegates_to_callback(self) -> None:
        svc = _make_service()
        svc._exchange_callback.return_value = (b"\xDE\xAD", 0x90, 0x00)
        data, sw1, sw2 = svc.exchange_apdu(b"\x00\xA4\x04\x00")
        self.assertEqual(data, b"\xDE\xAD")
        svc._exchange_callback.assert_called_once()

    def test_apdu_forwarded_to_callback(self) -> None:
        svc = _make_service()
        apdu = b"\x00\xA4\x04\x00\x04\xA0\x00\x00\x05"
        svc.exchange_apdu(apdu)
        call_args = svc._exchange_callback.call_args
        self.assertEqual(call_args[0][0], apdu)

    def test_returns_three_tuple(self) -> None:
        svc = _make_service()
        result = svc.exchange_apdu(b"\x00\xC0\x00\x00")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)


class RequestModemRefreshTests(unittest.TestCase):

    def test_raises_when_no_callback(self) -> None:
        svc = _make_service(with_modem_refresh=False)
        with self.assertRaises(RuntimeError):
            svc.request_modem_refresh()

    def test_delegates_when_callback_present(self) -> None:
        svc = _make_service(with_modem_refresh=True)
        result = svc.request_modem_refresh(mode="uicc-reset")
        self.assertIsInstance(result, dict)
        svc._modem_refresh_callback.assert_called_once()


class RecordApduAuditTests(unittest.TestCase):

    def test_no_op_when_audit_disabled(self) -> None:
        svc = _make_service(audit_enabled=False)
        # Should complete without exception and not call the logger.
        svc.record_apdu_audit(
            peer="127.0.0.1",
            apdu=b"\x00\xA4\x04\x00",
            response_data=b"",
            sw1=0x90,
            sw2=0x00,
            started_at=time.monotonic(),
            session_id="",
            error="",
        )

    def test_emits_when_audit_enabled(self) -> None:
        svc = _make_service(audit_enabled=True)
        with self.assertLogs(level="INFO") as cm:
            svc.record_apdu_audit(
                peer="192.0.2.1",
                apdu=bytes.fromhex("00A40400"),
                response_data=b"",
                sw1=0x90,
                sw2=0x00,
                started_at=time.monotonic(),
                session_id="sid1",
                error="",
            )
        self.assertTrue(any("9000" in line for line in cm.output))

    def test_full_apdu_included_when_opted_in(self) -> None:
        svc = _make_service(audit_enabled=True, audit_full_apdu=True)
        with self.assertLogs(level="INFO") as cm:
            svc.record_apdu_audit(
                peer="192.0.2.1",
                apdu=bytes.fromhex("00A40400"),
                response_data=b"\x01",
                sw1=0x90,
                sw2=0x00,
                started_at=time.monotonic(),
                session_id="sid2",
                error="",
            )
        combined = " ".join(cm.output)
        self.assertIn("00A40400", combined.upper())


class BuildAuditRecordTests(unittest.TestCase):

    def _record(self, apdu: bytes, **kw) -> dict:
        return HilBridgeApduRelayService._build_audit_record(
            peer=kw.get("peer", "127.0.0.1"),
            apdu=apdu,
            response_data=kw.get("response_data", b""),
            sw1=kw.get("sw1", 0x90),
            sw2=kw.get("sw2", 0x00),
            started_at=time.monotonic(),
            session_id=kw.get("session_id", ""),
            error=kw.get("error", ""),
        )

    def test_sw_field_formatted(self) -> None:
        record = self._record(b"\x00\xA4\x04\x00", sw1=0x6A, sw2=0x82)
        self.assertEqual(record["sw"], "6A82")

    def test_cla_ins_p1_p2_extracted(self) -> None:
        record = self._record(bytes.fromhex("00B00000"))
        self.assertEqual(record["cla"], "00")
        self.assertEqual(record["ins"], "B0")
        self.assertEqual(record["p1"], "00")
        self.assertEqual(record["p2"], "00")

    def test_lc_included_for_5plus_bytes(self) -> None:
        record = self._record(bytes.fromhex("00D60000" "0A" + "00" * 10))
        self.assertIn("lc", record)

    def test_short_apdu_no_cla(self) -> None:
        record = self._record(b"\x00\xA4")
        self.assertNotIn("cla", record)

    def test_error_field_included(self) -> None:
        record = self._record(b"\x00\xA4\x04\x00", error="timeout")
        self.assertEqual(record["error"], "timeout")

    def test_no_error_field_when_empty(self) -> None:
        record = self._record(b"\x00\xA4\x04\x00", error="")
        self.assertNotIn("error", record)

    def test_returns_dict(self) -> None:
        self.assertIsInstance(self._record(b"\x00\xA4\x04\x00"), dict)


if __name__ == "__main__":
    unittest.main()
