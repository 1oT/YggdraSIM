"""Unit tests for Tools/Sunrise6G/qod.py."""

from __future__ import annotations

import unittest

from Tools.Sunrise6G.qod import (
    DEFAULT_QOD_DURATION_SECONDS,
    QodSessionNotFoundError,
    QodStubClient,
    QodStubError,
)


class _FakeClock:
    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _id_factory():
    counter = {"n": 0}

    def _next():
        counter["n"] += 1
        return f"sid-{counter['n']:03d}"

    return _next


class _SessionInfoMixin:
    """Helpers shared by the tests below."""

    def _build_session_info(self, **overrides):
        info = {
            "qosProfile": "QOS_E",
            "duration": 600,
            "applicationServer": {"ipv4Address": "203.0.113.10"},
            "device": {"phoneNumber": "+15550100199"},
        }
        info.update(overrides)
        return info


class CreateQodSessionTests(unittest.TestCase, _SessionInfoMixin):
    def setUp(self):
        self.clock = _FakeClock()
        self.client = QodStubClient(clock=self.clock, id_factory=_id_factory())

    def test_minimum_payload_creates_session(self):
        info = self._build_session_info()
        out = self.client.create_qod_session(info)
        self.assertEqual(out["sessionId"], "sid-001")
        self.assertEqual(out["qosStatus"], "AVAILABLE")
        self.assertEqual(out["qosProfile"], "QOS_E")
        self.assertEqual(out["duration"], 600)
        self.assertEqual(out["device"], {"phoneNumber": "+15550100199"})
        self.assertEqual(out["applicationServer"], {"ipv4Address": "203.0.113.10"})

    def test_string_application_server_ip_is_accepted(self):
        info = self._build_session_info(applicationServer="203.0.113.10")
        out = self.client.create_qod_session(info)
        self.assertEqual(out["applicationServer"], {"ipv4Address": "203.0.113.10"})

    def test_default_duration_when_omitted(self):
        info = self._build_session_info()
        info.pop("duration")
        out = self.client.create_qod_session(info)
        self.assertEqual(out["duration"], DEFAULT_QOD_DURATION_SECONDS)

    def test_ports_propagate(self):
        info = self._build_session_info(
            devicePorts={"ports": [80, 443]},
            applicationServerPorts={"ports": [443]},
        )
        out = self.client.create_qod_session(info)
        self.assertEqual(out["devicePorts"], {"ports": [80, 443]})
        self.assertEqual(out["applicationServerPorts"], {"ports": [443]})

    def test_invalid_qos_profile_rejected(self):
        info = self._build_session_info(qosProfile="QOS_XL")
        with self.assertRaises(QodStubError):
            self.client.create_qod_session(info)

    def test_missing_application_server_rejected(self):
        info = self._build_session_info()
        info.pop("applicationServer")
        with self.assertRaises(QodStubError):
            self.client.create_qod_session(info)

    def test_empty_device_rejected(self):
        info = self._build_session_info(device={})
        with self.assertRaises(QodStubError):
            self.client.create_qod_session(info)


class GetDeleteListTests(unittest.TestCase, _SessionInfoMixin):
    def setUp(self):
        self.clock = _FakeClock()
        self.client = QodStubClient(clock=self.clock, id_factory=_id_factory())
        self.created = self.client.create_qod_session(self._build_session_info())

    def test_get_returns_same_record(self):
        sid = self.created["sessionId"]
        fetched = self.client.get_qod_session(sid)
        self.assertEqual(fetched["sessionId"], sid)
        self.assertEqual(fetched["qosProfile"], "QOS_E")

    def test_get_unknown_id_raises(self):
        with self.assertRaises(QodSessionNotFoundError):
            self.client.get_qod_session("does-not-exist")

    def test_delete_removes_record(self):
        sid = self.created["sessionId"]
        self.client.delete_qod_session(sid)
        self.assertEqual(self.client.session_count(), 0)

    def test_delete_unknown_raises(self):
        with self.assertRaises(QodSessionNotFoundError):
            self.client.delete_qod_session("ghost-session")

    def test_list_returns_camara_view_with_extras(self):
        rows = self.client.list_sessions()
        self.assertEqual(len(rows), 1)
        self.assertIn("remainingDurationSeconds", rows[0])
        self.assertFalse(rows[0]["expired"])
        self.assertGreater(rows[0]["remainingDurationSeconds"], 0)

    def test_list_excludes_expired_by_default(self):
        self.clock.advance(10_000)
        self.assertEqual(self.client.list_sessions(), [])
        rows = self.client.list_sessions(include_expired=True)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["expired"])

    def test_get_expired_raises(self):
        sid = self.created["sessionId"]
        self.clock.advance(10_000)
        with self.assertRaises(QodSessionNotFoundError):
            self.client.get_qod_session(sid)

    def test_expire_due_drops_records(self):
        # Add a second session with a longer duration
        long_lived = self.client.create_qod_session(
            self._build_session_info(duration=86_400)
        )
        self.clock.advance(10_000)
        pruned = self.client.expire_due()
        self.assertEqual(pruned, 1)
        # The long-lived session is still present
        rows = self.client.list_sessions()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sessionId"], long_lived["sessionId"])

    def test_clear_resets_state(self):
        self.client.create_qod_session(self._build_session_info())
        cleared = self.client.clear()
        self.assertGreaterEqual(cleared, 1)
        self.assertEqual(self.client.session_count(), 0)

    def test_find_by_device_filters(self):
        self.client.create_qod_session(
            self._build_session_info(device={"phoneNumber": "+12025550123"})
        )
        rows = self.client.find_by_device(  # type: ignore[arg-type]
            __import__(
                "Tools.Sunrise6G.models",
                fromlist=["DeviceIdentity"],
            ).DeviceIdentity(phone_number="+15550100199")
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["device"], {"phoneNumber": "+15550100199"})


if __name__ == "__main__":
    unittest.main()
