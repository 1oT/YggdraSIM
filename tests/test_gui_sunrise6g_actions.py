"""Unit tests for yggdrasim_common/gui_server/actions/sunrise6g.py.

Verifies action registration, dispatcher input coercion, and the
test-injection seam that swaps the bridge for a hand-rolled fake.
"""

from __future__ import annotations

import unittest
from typing import Any

from Tools.Sunrise6G.location import (
    get_default_location_stub_client,
    reset_default_location_stub_client,
)
from Tools.Sunrise6G.models import DeviceIdentity
from Tools.Sunrise6G.qod import (
    get_default_qod_stub_client,
    reset_default_qod_stub_client,
)
from yggdrasim_common.gui_server.actions import sunrise6g as actions_module
from yggdrasim_common.gui_server.actions.registry import ActionContext, get_registry


# ----------------------------------------------------------------------
# Bridge fake
# ----------------------------------------------------------------------


class _FakeBridge:
    mode = "stub"

    def __init__(self) -> None:
        self.diagnostics_calls = 0
        self.created_sessions: list[dict[str, Any]] = []
        self.deleted_session_ids: list[str] = []
        self.retrieve_calls: list[tuple[DeviceIdentity, int]] = []
        self.verify_calls: list[Any] = []
        self.next_session_id = "fake-session-1"
        self.location_response = {
            "area": {
                "areaType": "CIRCLE",
                "center": {"latitude": 0.0, "longitude": 0.0},
                "radius": 100,
            },
            "lastLocationTime": "2026-04-25T12:00:00Z",
        }
        self.verify_response = {
            "verificationResult": "MATCH",
            "lastLocationTime": "2026-04-25T12:00:00Z",
        }

    def diagnostics(self) -> dict[str, Any]:
        self.diagnostics_calls += 1
        return {"mode": self.mode, "fake": True}

    def create_qod_session(self, session_info: dict[str, Any]) -> dict[str, Any]:
        self.created_sessions.append(session_info)
        return {
            "sessionId": self.next_session_id,
            "qosStatus": "AVAILABLE",
            "qosProfile": session_info.get("qosProfile"),
            "duration": session_info.get("duration"),
            "device": session_info.get("device"),
            "applicationServer": session_info.get("applicationServer"),
        }

    def get_qod_session(self, session_id: str) -> dict[str, Any]:
        return {"sessionId": session_id, "qosStatus": "AVAILABLE"}

    def delete_qod_session(self, session_id: str) -> None:
        self.deleted_session_ids.append(session_id)

    def list_qod_sessions(self) -> list[dict[str, Any]]:
        return [{"sessionId": "fake-session-1"}]

    def retrieve_location(
        self,
        device: DeviceIdentity,
        *,
        max_age_seconds: int = 60,
    ) -> dict[str, Any]:
        self.retrieve_calls.append((device, max_age_seconds))
        return self.location_response

    def verify_location(self, verification: Any) -> dict[str, Any]:
        self.verify_calls.append(verification)
        return self.verify_response


class _ActionTests(unittest.TestCase):
    def setUp(self):
        self.bridge = _FakeBridge()
        actions_module.set_bridge_for_testing(self.bridge)
        reset_default_qod_stub_client()
        reset_default_location_stub_client()
        self.ctx = ActionContext()

    def tearDown(self):
        actions_module.set_bridge_for_testing(None)
        reset_default_qod_stub_client()
        reset_default_location_stub_client()


class RegistrationTests(_ActionTests):
    def test_all_specs_are_registered(self):
        ids = {
            "sunrise6g.status",
            "sunrise6g.qod_create",
            "sunrise6g.qod_get",
            "sunrise6g.qod_list",
            "sunrise6g.qod_delete",
            "sunrise6g.qod_expire_due",
            "sunrise6g.location_set_anchor",
            "sunrise6g.location_retrieve",
            "sunrise6g.location_verify",
            "sunrise6g.location_list_anchors",
            "sunrise6g.clear_state",
        }
        registry = get_registry()
        for spec_id in ids:
            spec = registry.get(spec_id)
            self.assertIsNotNone(spec, f"{spec_id} not registered")
            self.assertEqual(spec.subsystem, "Sunrise6G")
            self.assertIn("sunrise6g", spec.tags)


class StatusDispatcherTests(_ActionTests):
    def test_status_returns_bridge_diagnostics(self):
        result = actions_module._dispatch_status(self.ctx)
        self.assertEqual(result, {"mode": "stub", "fake": True})
        self.assertEqual(self.bridge.diagnostics_calls, 1)


class QodDispatcherTests(_ActionTests):
    def test_create_dispatches_camara_payload(self):
        result = actions_module._dispatch_qod_create(
            self.ctx,
            qos_profile="QOS_E",
            duration_seconds=600,
            application_server_ip="203.0.113.10",
            sink_url="https://example.com/notify",
            device_phone_number="+15558675309",
            device_ports="80, 443",
            application_server_ports="443",
        )
        self.assertEqual(result["session"]["sessionId"], "fake-session-1")
        sent = self.bridge.created_sessions[0]
        self.assertEqual(sent["qosProfile"], "QOS_E")
        self.assertEqual(sent["duration"], 600)
        self.assertEqual(sent["applicationServer"], {"ipv4Address": "203.0.113.10"})
        self.assertEqual(sent["device"], {"phoneNumber": "+15558675309"})
        self.assertEqual(sent["devicePorts"], {"ports": [80, 443]})
        self.assertEqual(sent["applicationServerPorts"], {"ports": [443]})
        self.assertEqual(sent["sink"], "https://example.com/notify")

    def test_create_requires_some_device_identifier(self):
        with self.assertRaises(ValueError):
            actions_module._dispatch_qod_create(
                self.ctx,
                qos_profile="QOS_E",
                duration_seconds=600,
                application_server_ip="203.0.113.10",
            )

    def test_create_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            actions_module._dispatch_qod_create(
                self.ctx,
                qos_profile="QOS_E",
                duration_seconds=600,
                application_server_ip="203.0.113.10",
                device_phone_number="+15558675309",
                device_ports="-1",
            )

    def test_get_dispatches_session_id(self):
        result = actions_module._dispatch_qod_get(self.ctx, session_id="abc")
        self.assertEqual(result["session"]["sessionId"], "abc")

    def test_list_dispatches(self):
        result = actions_module._dispatch_qod_list(self.ctx)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["sessions"][0]["sessionId"], "fake-session-1")

    def test_delete_dispatches(self):
        result = actions_module._dispatch_qod_delete(self.ctx, session_id="x-y-z")
        self.assertEqual(result["session_id"], "x-y-z")
        self.assertTrue(result["deleted"])
        self.assertEqual(self.bridge.deleted_session_ids, ["x-y-z"])

    def test_expire_due_calls_default_stub(self):
        import time

        client = get_default_qod_stub_client()
        client.create_qod_session(
            {
                "qosProfile": "QOS_E",
                "duration": 1,
                "applicationServer": {"ipv4Address": "203.0.113.10"},
                "device": {"phoneNumber": "+15558675309"},
            }
        )
        # Advance the clock far past the duration. We use an offset
        # from the real wall-clock so the patched ``now`` is always
        # later than the session's ``started_at`` regardless of
        # test order or build-time skew.
        future = time.time() + 100_000.0
        client._clock = lambda: future  # type: ignore[attr-defined]
        result = actions_module._dispatch_qod_expire_due(self.ctx)
        self.assertEqual(result["mode"], "stub")
        self.assertEqual(result["pruned"], 1)


class LocationDispatcherTests(_ActionTests):
    def test_set_anchor_dispatches_to_default_client(self):
        result = actions_module._dispatch_location_set_anchor(
            self.ctx,
            latitude="59.32938",
            longitude="18.06871",
            radius_meters=500,
            device_phone_number="+15558675309",
        )
        self.assertEqual(result["mode"], "stub")
        self.assertEqual(result["anchor"]["area"]["radius"], 500)
        # The anchor went into the default singleton.
        self.assertEqual(get_default_location_stub_client().fix_count(), 1)

    def test_retrieve_dispatches_with_max_age(self):
        result = actions_module._dispatch_location_retrieve(
            self.ctx,
            max_age_seconds=120,
            device_phone_number="+15558675309",
        )
        self.assertEqual(result["location"]["area"]["radius"], 100)
        device, max_age = self.bridge.retrieve_calls[0]
        self.assertEqual(device.phone_number, "+15558675309")
        self.assertEqual(max_age, 120)

    def test_verify_dispatches_to_bridge(self):
        result = actions_module._dispatch_location_verify(
            self.ctx,
            latitude="0.0",
            longitude="0.0",
            accuracy_meters=1_000,
            max_age_seconds=60,
            device_phone_number="+15558675309",
        )
        self.assertEqual(result["verification"]["verificationResult"], "MATCH")
        self.assertEqual(len(self.bridge.verify_calls), 1)

    def test_list_anchors_returns_default_client_state(self):
        client = get_default_location_stub_client()
        client.set_anchor(
            DeviceIdentity(phone_number="+15558675309"),
            latitude=0.0,
            longitude=0.0,
            radius_meters=100,
        )
        result = actions_module._dispatch_location_list_anchors(self.ctx)
        self.assertEqual(result["count"], 1)

    def test_clear_state_resets_default_clients(self):
        get_default_qod_stub_client().create_qod_session(
            {
                "qosProfile": "QOS_E",
                "duration": 600,
                "applicationServer": {"ipv4Address": "203.0.113.10"},
                "device": {"phoneNumber": "+15558675309"},
            }
        )
        get_default_location_stub_client().set_anchor(
            DeviceIdentity(phone_number="+15558675309"),
            latitude=0.0,
            longitude=0.0,
            radius_meters=100,
        )
        result = actions_module._dispatch_clear_state(self.ctx)
        self.assertTrue(result["cleared"])
        self.assertEqual(get_default_qod_stub_client().session_count(), 0)
        self.assertEqual(get_default_location_stub_client().fix_count(), 0)


if __name__ == "__main__":
    unittest.main()
