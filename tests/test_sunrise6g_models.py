"""Unit tests for Tools/Sunrise6G/models.py.

Locks down the CAMARA-shape marshaling helpers and the dataclass
validators. These run entirely off-network and never touch the
real SUNRISE-6G OpenSDK.
"""

from __future__ import annotations

import unittest

from Tools.Sunrise6G.models import (
    DeviceIdentity,
    LocationFix,
    LocationVerification,
    LocationVerificationResult,
    QodSession,
    QosStatus,
    SUPPORTED_QOS_PROFILES,
    _haversine_meters,
    _iso8601,
)


class DeviceIdentityTests(unittest.TestCase):
    def test_round_trip_phone_only(self):
        device = DeviceIdentity(phone_number="+15558675309")
        camara = device.to_camara()
        self.assertEqual(camara, {"phoneNumber": "+15558675309"})
        self.assertEqual(DeviceIdentity.from_camara(camara), device)

    def test_round_trip_full(self):
        device = DeviceIdentity(
            phone_number="+12025550123",
            network_access_identifier="ue@example.com",
            ipv4_public="203.0.113.4",
            ipv4_private="10.0.0.4",
            ipv6="2001:db8::4",
        )
        camara = device.to_camara()
        self.assertEqual(camara["phoneNumber"], "+12025550123")
        self.assertEqual(camara["networkAccessIdentifier"], "ue@example.com")
        self.assertEqual(
            camara["ipv4Address"],
            {"publicAddress": "203.0.113.4", "privateAddress": "10.0.0.4"},
        )
        self.assertEqual(camara["ipv6Address"], "2001:db8::4")
        self.assertEqual(DeviceIdentity.from_camara(camara), device)

    def test_from_camara_handles_string_ipv4(self):
        device = DeviceIdentity.from_camara({"ipv4Address": "203.0.113.4"})
        self.assertEqual(device.ipv4_public, "203.0.113.4")
        self.assertIsNone(device.ipv4_private)

    def test_empty_device_marker(self):
        device = DeviceIdentity()
        self.assertTrue(device.is_empty())
        self.assertEqual(device.stable_key(), "empty:device")

    def test_invalid_phone_number_rejected(self):
        with self.assertRaises(ValueError):
            DeviceIdentity(phone_number="not-a-number")

    def test_invalid_nai_rejected(self):
        with self.assertRaises(ValueError):
            DeviceIdentity(network_access_identifier="no-at-sign")

    def test_invalid_ipv4_rejected(self):
        with self.assertRaises(ValueError):
            DeviceIdentity(ipv4_public="999.999.999.999")

    def test_stable_key_priority(self):
        device = DeviceIdentity(
            phone_number="+15558675309",
            ipv4_public="203.0.113.4",
        )
        # phone wins over ipv4
        self.assertTrue(device.stable_key().startswith("phone:"))


class QodSessionTests(unittest.TestCase):
    def _build(self, **overrides):
        defaults = dict(
            session_id="9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
            device=DeviceIdentity(phone_number="+15558675309"),
            application_server_ip="203.0.113.10",
            qos_profile="QOS_E",
            duration_seconds=600,
            started_at_unix=1_700_000_000.0,
            sink_url=None,
            device_ports=(80, 443),
            application_server_ports=(80,),
            status=QosStatus.AVAILABLE,
        )
        defaults.update(overrides)
        return QodSession(**defaults)

    def test_to_camara_session_info_shape(self):
        session = self._build()
        info = session.to_camara_session_info()
        self.assertEqual(info["sessionId"], session.session_id)
        self.assertEqual(info["qosStatus"], QosStatus.AVAILABLE)
        self.assertEqual(info["qosProfile"], "QOS_E")
        self.assertEqual(info["duration"], 600)
        self.assertEqual(info["device"], {"phoneNumber": "+15558675309"})
        self.assertEqual(info["applicationServer"], {"ipv4Address": "203.0.113.10"})
        self.assertEqual(info["devicePorts"], {"ports": [80, 443]})
        self.assertEqual(info["applicationServerPorts"], {"ports": [80]})
        self.assertNotIn("sink", info)

    def test_to_camara_session_info_includes_sink(self):
        session = self._build(sink_url="https://example.com/notify")
        info = session.to_camara_session_info()
        self.assertEqual(info["sink"], "https://example.com/notify")

    def test_invalid_qos_profile_rejected(self):
        with self.assertRaises(ValueError):
            self._build(qos_profile="QOS_XL")

    def test_duration_bounds(self):
        with self.assertRaises(ValueError):
            self._build(duration_seconds=0)
        with self.assertRaises(ValueError):
            self._build(duration_seconds=86_401)

    def test_invalid_application_server_ip(self):
        with self.assertRaises(ValueError):
            self._build(application_server_ip="not.an.ip")

    def test_empty_device_rejected(self):
        with self.assertRaises(ValueError):
            self._build(device=DeviceIdentity())

    def test_port_bounds(self):
        with self.assertRaises(ValueError):
            self._build(device_ports=(70_000,))

    def test_status_must_be_known(self):
        with self.assertRaises(ValueError):
            self._build(status="UNKNOWN")

    def test_remaining_seconds_and_expiry(self):
        session = self._build(duration_seconds=10, started_at_unix=100.0)
        self.assertEqual(session.expires_at_unix(), 110.0)
        self.assertFalse(session.is_expired(now_unix=109.5))
        self.assertEqual(session.remaining_seconds(now_unix=105.0), 5)
        self.assertTrue(session.is_expired(now_unix=110.0))
        self.assertEqual(session.remaining_seconds(now_unix=200.0), 0)


class LocationFixTests(unittest.TestCase):
    def _device(self):
        return DeviceIdentity(phone_number="+15558675309")

    def test_to_camara_location_circle_shape(self):
        fix = LocationFix(
            device=self._device(),
            latitude=59.32938,
            longitude=18.06871,
            radius_meters=500,
            last_location_time_unix=1_700_000_000.0,
        )
        camara = fix.to_camara_location()
        self.assertEqual(camara["area"]["areaType"], "CIRCLE")
        self.assertEqual(
            camara["area"]["center"],
            {"latitude": 59.32938, "longitude": 18.06871},
        )
        self.assertEqual(camara["area"]["radius"], 500)
        self.assertEqual(camara["lastLocationTime"], _iso8601(1_700_000_000.0))

    def test_age_and_staleness(self):
        fix = LocationFix(
            device=self._device(),
            latitude=0.0,
            longitude=0.0,
            radius_meters=500,
            last_location_time_unix=1_000.0,
        )
        self.assertEqual(fix.age_seconds(now_unix=1_010.0), 10)
        self.assertFalse(fix.is_stale(now_unix=1_010.0, max_age_seconds=60))
        self.assertTrue(fix.is_stale(now_unix=1_200.0, max_age_seconds=60))

    def test_is_within_haversine(self):
        fix = LocationFix(
            device=self._device(),
            latitude=0.0,
            longitude=0.0,
            radius_meters=100,
            last_location_time_unix=0.0,
        )
        # ~111 m north
        self.assertTrue(fix.is_within(latitude=0.001, longitude=0.0, accuracy_meters=50))
        # ~1.1 km north -- outside both radii
        self.assertFalse(fix.is_within(latitude=0.01, longitude=0.0, accuracy_meters=50))

    def test_lat_long_bounds(self):
        with self.assertRaises(ValueError):
            LocationFix(
                device=self._device(),
                latitude=91.0,
                longitude=0.0,
                radius_meters=100,
                last_location_time_unix=0.0,
            )
        with self.assertRaises(ValueError):
            LocationFix(
                device=self._device(),
                latitude=0.0,
                longitude=181.0,
                radius_meters=100,
                last_location_time_unix=0.0,
            )

    def test_radius_bounds(self):
        with self.assertRaises(ValueError):
            LocationFix(
                device=self._device(),
                latitude=0.0,
                longitude=0.0,
                radius_meters=0,
                last_location_time_unix=0.0,
            )


class LocationVerificationTests(unittest.TestCase):
    def test_construct(self):
        verification = LocationVerification(
            device=DeviceIdentity(phone_number="+15558675309"),
            latitude=59.0,
            longitude=18.0,
            accuracy_meters=500,
            max_age_seconds=120,
        )
        self.assertEqual(verification.max_age_seconds, 120)

    def test_invalid_max_age_rejected(self):
        with self.assertRaises(ValueError):
            LocationVerification(
                device=DeviceIdentity(phone_number="+15558675309"),
                latitude=0.0,
                longitude=0.0,
                accuracy_meters=500,
                max_age_seconds=86_401,
            )


class HelperTests(unittest.TestCase):
    def test_iso8601_format(self):
        self.assertEqual(_iso8601(0.0), "1970-01-01T00:00:00Z")
        # Microseconds are dropped.
        self.assertEqual(_iso8601(0.999), "1970-01-01T00:00:00Z")

    def test_haversine_known_distance(self):
        # London <-> Paris, ~344 km on the standard reference sphere.
        distance = _haversine_meters(51.5074, -0.1278, 48.8566, 2.3522)
        self.assertAlmostEqual(distance / 1000.0, 344.0, delta=5.0)

    def test_haversine_zero(self):
        self.assertAlmostEqual(_haversine_meters(0.0, 0.0, 0.0, 0.0), 0.0)

    def test_supported_qos_profiles(self):
        self.assertIn("QOS_E", SUPPORTED_QOS_PROFILES)
        self.assertIn("QOS_L", SUPPORTED_QOS_PROFILES)
        self.assertIn(LocationVerificationResult.MATCH, ("MATCH",))


if __name__ == "__main__":
    unittest.main()
