"""Unit tests for Tools/Sunrise6G/bridge.py."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from Tools.Sunrise6G.bridge import (
    DEFAULT_MODE,
    ENV_MODE,
    ENV_NETWORK_ADAPTER,
    ENV_NETWORK_BASE_URL,
    ENV_NETWORK_SCS_AS_ID,
    Sunrise6gBridge,
    Sunrise6gBridgeError,
    Sunrise6gBridgeOffError,
    Sunrise6gOffBridge,
    Sunrise6gSdkBridge,
    Sunrise6gStubBridge,
    get_default_bridge,
    reset_default_bridge,
)
from Tools.Sunrise6G.location import (
    LocationStubClient,
    reset_default_location_stub_client,
)
from Tools.Sunrise6G.models import (
    DeviceIdentity,
    LocationVerification,
    LocationVerificationResult,
)
from Tools.Sunrise6G.qod import QodStubClient, reset_default_qod_stub_client


def _device():
    return DeviceIdentity(phone_number="+15550100199")


class StubBridgeTests(unittest.TestCase):
    def setUp(self):
        self.qod = QodStubClient()
        self.location = LocationStubClient()
        self.bridge = Sunrise6gStubBridge(
            qod_client=self.qod,
            location_client=self.location,
        )

    def test_protocol_compliance(self):
        self.assertIsInstance(self.bridge, Sunrise6gBridge)

    def test_diagnostics_reports_counts_and_mode(self):
        snapshot = self.bridge.diagnostics()
        self.assertEqual(snapshot["mode"], "stub")
        self.assertEqual(snapshot["qod_session_count"], 0)
        self.assertEqual(snapshot["location_anchor_count"], 0)

    def test_qod_lifecycle(self):
        info = {
            "qosProfile": "QOS_E",
            "duration": 600,
            "applicationServer": {"ipv4Address": "203.0.113.10"},
            "device": {"phoneNumber": "+15550100199"},
        }
        created = self.bridge.create_qod_session(info)
        sid = created["sessionId"]
        fetched = self.bridge.get_qod_session(sid)
        self.assertEqual(fetched["sessionId"], sid)
        listed = self.bridge.list_qod_sessions()
        self.assertEqual(len(listed), 1)
        self.bridge.delete_qod_session(sid)
        with self.assertRaises(Sunrise6gBridgeError):
            self.bridge.get_qod_session(sid)

    def test_location_retrieve_and_verify(self):
        device = _device()
        self.location.set_anchor(device, latitude=0.0, longitude=0.0, radius_meters=100)
        location = self.bridge.retrieve_location(device, max_age_seconds=60)
        self.assertEqual(location["area"]["radius"], 100)
        verification = LocationVerification(
            device=device,
            latitude=0.0,
            longitude=0.0,
            accuracy_meters=1_000,
            max_age_seconds=60,
        )
        self.assertEqual(
            self.bridge.verify_location(verification)["verificationResult"],
            LocationVerificationResult.MATCH,
        )

    def test_retrieve_unknown_raises_bridge_error(self):
        with self.assertRaises(Sunrise6gBridgeError):
            self.bridge.retrieve_location(_device())


class OffBridgeTests(unittest.TestCase):
    def test_diagnostics_reports_off(self):
        bridge = Sunrise6gOffBridge()
        self.assertEqual(bridge.diagnostics()["mode"], "off")

    def test_every_call_raises(self):
        bridge = Sunrise6gOffBridge()
        with self.assertRaises(Sunrise6gBridgeOffError):
            bridge.create_qod_session({})
        with self.assertRaises(Sunrise6gBridgeOffError):
            bridge.get_qod_session("sid")
        with self.assertRaises(Sunrise6gBridgeOffError):
            bridge.delete_qod_session("sid")
        with self.assertRaises(Sunrise6gBridgeOffError):
            bridge.retrieve_location(_device())


class SdkBridgeTests(unittest.TestCase):
    """Tests the SDK bridge plumbing without requiring the real SDK."""

    def test_constructs_with_injected_sdk_module(self):
        captured: dict[str, object] = {}

        class _FakeNetworkClient:
            def create_qod_session(self, session_info):
                captured["create"] = session_info
                return {"sessionId": "sdk-session-1", "qosStatus": "REQUESTED"}

            def get_qod_session(self, *, session_id):
                captured["get"] = session_id
                return {"sessionId": session_id}

            def delete_qod_session(self, *, session_id):
                captured["delete"] = session_id

            def create_monitoring_event_subscription(self, request):
                captured["retrieve"] = request
                return {
                    "lastLocationTime": "2026-04-25T12:00:00Z",
                    "area": {
                        "areaType": "CIRCLE",
                        "center": {"latitude": 0.0, "longitude": 0.0},
                        "radius": 100,
                    },
                }

        class _FakeSdk:
            @staticmethod
            def create_adapters_from(specs):
                captured["specs"] = specs
                return {"network": _FakeNetworkClient()}

        bridge = Sunrise6gSdkBridge(
            network_adapter="open5gs",
            network_base_url="http://nef.example:8080",
            network_scs_as_id="scs-as-1",
            sdk_module=_FakeSdk,
        )
        self.assertEqual(bridge.diagnostics()["mode"], "sdk")
        self.assertEqual(bridge.diagnostics()["network_adapter"], "open5gs")

        info = {
            "qosProfile": "QOS_E",
            "duration": 600,
            "applicationServer": {"ipv4Address": "203.0.113.10"},
            "device": {"phoneNumber": "+15550100199"},
        }
        result = bridge.create_qod_session(info)
        self.assertEqual(result["sessionId"], "sdk-session-1")
        self.assertEqual(captured["create"], info)
        self.assertEqual(
            captured["specs"],
            {
                "network": {
                    "client_name": "open5gs",
                    "base_url": "http://nef.example:8080",
                    "scs_as_id": "scs-as-1",
                }
            },
        )

        bridge.get_qod_session("sid-1")
        self.assertEqual(captured["get"], "sid-1")

        bridge.delete_qod_session("sid-1")
        self.assertEqual(captured["delete"], "sid-1")

        location = bridge.retrieve_location(_device())
        self.assertEqual(location["area"]["radius"], 100)
        self.assertEqual(captured["retrieve"]["device"], {"phoneNumber": "+15550100199"})
        self.assertEqual(captured["retrieve"]["maxAge"], 60)

    def test_unsupported_network_adapter_rejected(self):
        with self.assertRaises(Sunrise6gBridgeError):
            Sunrise6gSdkBridge(
                network_adapter="unknown",
                network_base_url="http://x",
                network_scs_as_id="y",
                sdk_module=object(),
            )

    def test_lazy_sdk_import_failure_is_clear(self):
        bridge = Sunrise6gSdkBridge(
            network_adapter="open5gs",
            network_base_url="http://nef.example:8080",
            network_scs_as_id="scs",
        )
        with mock.patch.dict("sys.modules", {"sunrise6g_opensdk.common.sdk": None}):
            with self.assertRaises(Sunrise6gBridgeError) as ctx:
                bridge.create_qod_session({})
        self.assertIn("sunrise6g_opensdk", str(ctx.exception))

    def test_verify_location_uses_retrieved_circle(self):
        class _FakeNetworkClient:
            def create_monitoring_event_subscription(self, request):
                return {
                    "lastLocationTime": "2026-04-25T12:00:00Z",
                    "area": {
                        "areaType": "CIRCLE",
                        "center": {"latitude": 0.0, "longitude": 0.0},
                        "radius": 100,
                    },
                }

        class _FakeSdk:
            @staticmethod
            def create_adapters_from(_specs):
                return {"network": _FakeNetworkClient()}

        bridge = Sunrise6gSdkBridge(
            network_adapter="open5gs",
            network_base_url="http://nef.example:8080",
            network_scs_as_id="scs",
            sdk_module=_FakeSdk,
        )
        verification = LocationVerification(
            device=_device(),
            latitude=0.0,
            longitude=0.0,
            accuracy_meters=1_000,
            max_age_seconds=60,
        )
        result = bridge.verify_location(verification)
        self.assertEqual(
            result["verificationResult"],
            LocationVerificationResult.MATCH,
        )
        self.assertEqual(result["lastLocationTime"], "2026-04-25T12:00:00Z")


class FactoryTests(unittest.TestCase):
    def setUp(self):
        # Wipe the per-process bridge cache and any underlying state
        # so each test starts clean.
        reset_default_bridge()
        reset_default_qod_stub_client()
        reset_default_location_stub_client()

    def tearDown(self):
        reset_default_bridge()

    def test_default_mode_is_stub(self):
        os.environ.pop(ENV_MODE, None)
        bridge = get_default_bridge()
        self.assertEqual(bridge.mode, "stub")

    def test_off_mode(self):
        os.environ[ENV_MODE] = "off"
        try:
            bridge = get_default_bridge()
            self.assertEqual(bridge.mode, "off")
        finally:
            os.environ.pop(ENV_MODE, None)

    def test_invalid_mode_rejected(self):
        os.environ[ENV_MODE] = "garbage"
        try:
            with self.assertRaises(Sunrise6gBridgeError):
                get_default_bridge()
        finally:
            os.environ.pop(ENV_MODE, None)

    def test_sdk_mode_requires_url_and_scs(self):
        os.environ[ENV_MODE] = "sdk"
        os.environ.pop(ENV_NETWORK_BASE_URL, None)
        os.environ.pop(ENV_NETWORK_SCS_AS_ID, None)
        try:
            with self.assertRaises(Sunrise6gBridgeError):
                get_default_bridge()
        finally:
            os.environ.pop(ENV_MODE, None)

    def test_sdk_mode_caches_per_invocation(self):
        os.environ[ENV_MODE] = "sdk"
        os.environ[ENV_NETWORK_ADAPTER] = "open5gs"
        os.environ[ENV_NETWORK_BASE_URL] = "http://nef.example:8080"
        os.environ[ENV_NETWORK_SCS_AS_ID] = "scs"
        try:
            first = get_default_bridge()
            second = get_default_bridge()
            self.assertIs(first, second)
            self.assertEqual(first.mode, "sdk")
        finally:
            for env_var in (
                ENV_MODE,
                ENV_NETWORK_ADAPTER,
                ENV_NETWORK_BASE_URL,
                ENV_NETWORK_SCS_AS_ID,
            ):
                os.environ.pop(env_var, None)


if __name__ == "__main__":
    unittest.main()
