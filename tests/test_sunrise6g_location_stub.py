"""Unit tests for Tools/Sunrise6G/location.py."""

from __future__ import annotations

import unittest

from Tools.Sunrise6G.location import (
    LocationFixNotFoundError,
    LocationStubClient,
    LocationStubError,
)
from Tools.Sunrise6G.models import (
    DeviceIdentity,
    LocationVerification,
    LocationVerificationResult,
)


class _FakeClock:
    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class AnchorManagementTests(unittest.TestCase):
    def setUp(self):
        self.clock = _FakeClock()
        self.client = LocationStubClient(clock=self.clock)
        self.device = DeviceIdentity(phone_number="+15558675309")

    def test_set_anchor_returns_camara_shape_with_device(self):
        anchor = self.client.set_anchor(
            self.device,
            latitude=59.32938,
            longitude=18.06871,
            radius_meters=500,
        )
        self.assertEqual(anchor["area"]["areaType"], "CIRCLE")
        self.assertEqual(anchor["area"]["radius"], 500)
        self.assertEqual(anchor["device"], {"phoneNumber": "+15558675309"})

    def test_set_anchor_overwrites_existing(self):
        self.client.set_anchor(
            self.device,
            latitude=0.0,
            longitude=0.0,
            radius_meters=100,
        )
        self.client.set_anchor(
            self.device,
            latitude=10.0,
            longitude=10.0,
            radius_meters=200,
        )
        self.assertEqual(self.client.fix_count(), 1)

    def test_remove_returns_true_only_when_present(self):
        self.assertFalse(self.client.remove(self.device))
        self.client.set_anchor(
            self.device,
            latitude=0.0,
            longitude=0.0,
            radius_meters=100,
        )
        self.assertTrue(self.client.remove(self.device))

    def test_clear_returns_count(self):
        self.client.set_anchor(
            self.device,
            latitude=0.0,
            longitude=0.0,
            radius_meters=100,
        )
        self.assertEqual(self.client.clear(), 1)
        self.assertEqual(self.client.fix_count(), 0)

    def test_set_anchor_with_explicit_timestamp(self):
        anchor = self.client.set_anchor(
            self.device,
            latitude=0.0,
            longitude=0.0,
            radius_meters=100,
            last_location_time_unix=1_000.0,
        )
        self.assertEqual(anchor["lastLocationTime"], "1970-01-01T00:16:40Z")

    def test_set_anchor_rejects_empty_device(self):
        with self.assertRaises(LocationStubError):
            self.client.set_anchor(
                DeviceIdentity(),
                latitude=0.0,
                longitude=0.0,
                radius_meters=100,
            )


class RetrieveLocationTests(unittest.TestCase):
    def setUp(self):
        self.clock = _FakeClock()
        self.client = LocationStubClient(clock=self.clock)
        self.device = DeviceIdentity(phone_number="+15558675309")
        self.client.set_anchor(
            self.device,
            latitude=59.32938,
            longitude=18.06871,
            radius_meters=500,
        )

    def test_retrieve_returns_camara_location(self):
        location = self.client.retrieve_location(self.device, max_age_seconds=60)
        self.assertEqual(location["area"]["areaType"], "CIRCLE")
        self.assertEqual(location["area"]["radius"], 500)
        self.assertIn("lastLocationTime", location)

    def test_retrieve_unknown_device_raises(self):
        unknown = DeviceIdentity(phone_number="+12025550123")
        with self.assertRaises(LocationFixNotFoundError):
            self.client.retrieve_location(unknown)

    def test_retrieve_stale_fix_raises(self):
        self.clock.advance(120)
        with self.assertRaises(LocationFixNotFoundError):
            self.client.retrieve_location(self.device, max_age_seconds=60)

    def test_retrieve_invalid_max_age_rejected(self):
        with self.assertRaises(LocationStubError):
            self.client.retrieve_location(self.device, max_age_seconds=0)
        with self.assertRaises(LocationStubError):
            self.client.retrieve_location(self.device, max_age_seconds=86_401)


class VerifyLocationTests(unittest.TestCase):
    def setUp(self):
        self.clock = _FakeClock()
        self.client = LocationStubClient(clock=self.clock)
        self.device = DeviceIdentity(phone_number="+15558675309")
        self.client.set_anchor(
            self.device,
            latitude=0.0,
            longitude=0.0,
            radius_meters=100,
        )

    def _verify(self, **overrides):
        defaults = dict(
            device=self.device,
            latitude=0.0,
            longitude=0.0,
            accuracy_meters=500,
            max_age_seconds=60,
        )
        defaults.update(overrides)
        return LocationVerification(**defaults)

    def test_match_when_anchor_inside_accuracy_circle(self):
        result = self.client.verify_location(self._verify(accuracy_meters=1_000))
        self.assertEqual(
            result["verificationResult"], LocationVerificationResult.MATCH
        )

    def test_partial_when_overlapping_but_not_contained(self):
        # Anchor is at (0,0,100m). Verifier at ~150m east with 100m
        # accuracy: distance 167m, sum-of-radii 200m => PARTIAL.
        result = self.client.verify_location(
            self._verify(longitude=0.0015, accuracy_meters=100)
        )
        self.assertEqual(
            result["verificationResult"], LocationVerificationResult.PARTIAL
        )

    def test_no_match_when_clearly_disjoint(self):
        result = self.client.verify_location(
            self._verify(latitude=10.0, longitude=10.0, accuracy_meters=100)
        )
        self.assertEqual(
            result["verificationResult"], LocationVerificationResult.NO_MATCH
        )

    def test_unknown_when_no_anchor(self):
        unknown = DeviceIdentity(phone_number="+12025550123")
        result = self.client.verify_location(
            LocationVerification(
                device=unknown,
                latitude=0.0,
                longitude=0.0,
                accuracy_meters=100,
                max_age_seconds=60,
            )
        )
        self.assertEqual(
            result["verificationResult"], LocationVerificationResult.UNKNOWN
        )

    def test_unknown_when_stale(self):
        self.clock.advance(120)
        result = self.client.verify_location(self._verify())
        self.assertEqual(
            result["verificationResult"], LocationVerificationResult.UNKNOWN
        )
        self.assertIn("lastLocationTime", result)


class ListAnchorsTests(unittest.TestCase):
    def test_list_returns_each_anchor_once(self):
        client = LocationStubClient(clock=_FakeClock())
        client.set_anchor(
            DeviceIdentity(phone_number="+15558675309"),
            latitude=0.0,
            longitude=0.0,
            radius_meters=100,
        )
        client.set_anchor(
            DeviceIdentity(phone_number="+12025550123"),
            latitude=10.0,
            longitude=10.0,
            radius_meters=200,
        )
        anchors = client.list_anchors()
        self.assertEqual(len(anchors), 2)
        phone_numbers = sorted(a["device"]["phoneNumber"] for a in anchors)
        self.assertEqual(phone_numbers, ["+12025550123", "+15558675309"])


if __name__ == "__main__":
    unittest.main()
