# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Per-notification ES9+ routing — SGP.22 §5.6.4 compliance tests.

NotificationMetadata.notificationAddress (BF2F tag 0C, UTF8String)
identifies the SM-DP+ that minted each PendingNotification. The LPA
MUST forward the notification there rather than to a global ES9
endpoint, otherwise notifications minted by a live SM-DP+ end up
routed against test infrastructure (or vice versa) and
``handleNotification`` either times out or fails TLS validation.

This suite covers three layers:

* the ``HandleNotificationRequest.smdp_address`` carrier field on
  every variant (live, base, test);
* the ES9 client URL-resolution helper that consumes the field; and
* the orchestrator hook that extracts the FQDN from decoded
  notification details before invoking the provider.
"""

from __future__ import annotations

import importlib
import unittest
from unittest import mock


class HandleNotificationRequestSmdpAddressFieldTests(unittest.TestCase):
    """Every variant must expose the SGP.22 §5.6.4 routing carrier."""

    def test_live_models_carry_smdp_address(self) -> None:
        from SCP11.live.models import HandleNotificationRequest

        request = HandleNotificationRequest(
            pending_notification="dGVzdA==",
            smdp_address="dpp1.example.com",
        )
        self.assertEqual(request.smdp_address, "dpp1.example.com")

    def test_base_models_carry_smdp_address(self) -> None:
        from SCP11.models import HandleNotificationRequest

        request = HandleNotificationRequest(
            pending_notification="dGVzdA==",
            smdp_address="dpp1.example.com",
        )
        self.assertEqual(request.smdp_address, "dpp1.example.com")

    def test_test_models_carry_smdp_address(self) -> None:
        from SCP11.test.models import HandleNotificationRequest

        request = HandleNotificationRequest(
            pending_notification="dGVzdA==",
            smdp_address="dpp1.example.com",
        )
        self.assertEqual(request.smdp_address, "dpp1.example.com")

    def test_smdp_address_defaults_to_empty_for_legacy_callers(self) -> None:
        # Existing callers that build the request positionally with a
        # single argument MUST keep working -- empty string preserves
        # the legacy "use configured base URL" behaviour.
        from SCP11.live.models import HandleNotificationRequest as Live
        from SCP11.models import HandleNotificationRequest as Base
        from SCP11.test.models import HandleNotificationRequest as Test

        for cls in (Live, Base, Test):
            with self.subTest(cls=cls.__module__):
                request = cls(pending_notification="dGVzdA==")
                self.assertEqual(request.smdp_address, "")


class Es9ClientHandleNotificationRoutingTests(unittest.TestCase):
    """The ES9 client must POST to the per-notification SM-DP+."""

    def _build_recording_client(self, client_module_name: str):
        # Each variant ships an isolated ``Es9LikeClient`` -- exercise
        # all three so a regression in one branch cannot slip through
        # under cover of a passing sibling.
        es9_module = importlib.import_module(client_module_name)
        client = es9_module.Es9LikeClient(base_url="https://rsp.example.com/")
        captured: dict = {}

        def fake_post(
            base_url,
            path,
            body,
            protocol_header="gsma/rsp/v2.2.0",
            pinned_tls_public_key_data=b"",
            trust_hint_ci_pkid="",
            use_configured_ca_bundle=True,
            tls_log_label="ES9",
        ):
            captured["base_url"] = base_url
            captured["path"] = path
            captured["body"] = body
            captured["tls_log_label"] = tls_log_label
            return {}

        client._post_json_to_base_url = fake_post
        return client, captured

    def test_live_client_routes_to_notification_address(self) -> None:
        client, captured = self._build_recording_client("SCP11.live.es9_client")
        from SCP11.live.models import HandleNotificationRequest

        request = HandleNotificationRequest(
            pending_notification="dGVzdA==",
            smdp_address="dpp1.example.com",
        )
        client.handle_notification(request)
        self.assertEqual(captured["base_url"], "https://dpp1.example.com")
        self.assertEqual(captured["path"], "/gsma/rsp2/es9plus/handleNotification")
        self.assertEqual(captured["body"], {"pendingNotification": "dGVzdA=="})

    def test_base_client_routes_to_notification_address(self) -> None:
        client, captured = self._build_recording_client("SCP11.es9_client")
        from SCP11.models import HandleNotificationRequest

        request = HandleNotificationRequest(
            pending_notification="dGVzdA==",
            smdp_address="dpp1.example.com",
        )
        client.handle_notification(request)
        self.assertEqual(captured["base_url"], "https://dpp1.example.com")

    def test_test_client_routes_to_notification_address(self) -> None:
        client, captured = self._build_recording_client("SCP11.test.es9_client")
        from SCP11.test.models import HandleNotificationRequest

        request = HandleNotificationRequest(
            pending_notification="dGVzdA==",
            smdp_address="smdp.example.test",
        )
        client.handle_notification(request)
        self.assertEqual(captured["base_url"], "https://smdp.example.test")

    def test_empty_smdp_address_falls_back_to_configured_base_url(self) -> None:
        client, captured = self._build_recording_client("SCP11.live.es9_client")
        from SCP11.live.models import HandleNotificationRequest

        request = HandleNotificationRequest(
            pending_notification="dGVzdA==",
            smdp_address="",
        )
        client.handle_notification(request)
        self.assertEqual(captured["base_url"], "https://rsp.example.com")

    def test_resolver_preserves_explicit_scheme_and_strips_trailing_slash(self) -> None:
        client, _ = self._build_recording_client("SCP11.live.es9_client")
        self.assertEqual(
            client._resolve_handle_notification_base_url("https://dpp1.example.com:8443/"),
            "https://dpp1.example.com:8443",
        )
        self.assertEqual(
            client._resolve_handle_notification_base_url("http://internal.example.test/"),
            "http://internal.example.test",
        )

    def test_resolver_treats_whitespace_only_address_as_empty(self) -> None:
        client, _ = self._build_recording_client("SCP11.live.es9_client")
        self.assertEqual(
            client._resolve_handle_notification_base_url("   "),
            "https://rsp.example.com",
        )

    def test_resolver_accepts_non_string_input_without_raising(self) -> None:
        client, _ = self._build_recording_client("SCP11.live.es9_client")
        self.assertEqual(
            client._resolve_handle_notification_base_url(None),  # type: ignore[arg-type]
            "https://rsp.example.com",
        )


class OrchestratorForwardPendingNotificationRoutingTests(unittest.TestCase):
    """The orchestrator must extract the FQDN and pass it through."""

    def _build_orchestrator(self, orch_module_name: str, models_module_name: str):
        # The three orchestrator variants share the routing surface but
        # are implemented as independent modules; verify each one wires
        # ``notificationAddress`` through to the provider unchanged.
        orch_module = importlib.import_module(orch_module_name)
        models_module = importlib.import_module(models_module_name)
        captured: list = []

        class RecordingProvider:
            def handle_notification(self, request_obj):
                captured.append(request_obj)
                return {}

        orchestrator = orch_module.SGP22Orchestrator.__new__(orch_module.SGP22Orchestrator)
        orchestrator.profile_provider = RecordingProvider()
        return orchestrator, captured, models_module

    def _exercise_forwarding_with_address(self, orch_module_name: str, models_module_name: str, address: str) -> dict:
        orchestrator, captured, _ = self._build_orchestrator(
            orch_module_name, models_module_name
        )
        details = {"notificationAddress": address, "seqNumber": 7, "choice": "otherSignedNotification"}
        with mock.patch.object(orchestrator, "_decode_pending_notification_details", return_value=details):
            with mock.patch.object(orchestrator, "_summarize_es9_response", return_value="{}"):
                with mock.patch.object(orchestrator, "_format_notification_details", return_value=""):
                    with mock.patch.object(orchestrator, "_b64encode", return_value="dGVzdA=="):
                        result = orchestrator._forward_pending_notification(
                            b"\x01\x02",
                            7,
                            "queued",
                        )
        return {"result": result, "captured": captured}

    def test_live_orchestrator_passes_notification_address_through(self) -> None:
        outcome = self._exercise_forwarding_with_address(
            "SCP11.live.orchestrator",
            "SCP11.live.models",
            "dpp1.example.com",
        )
        self.assertTrue(outcome["result"])
        self.assertEqual(len(outcome["captured"]), 1)
        self.assertEqual(outcome["captured"][0].smdp_address, "dpp1.example.com")
        self.assertEqual(outcome["captured"][0].pending_notification, "dGVzdA==")

    def test_base_orchestrator_passes_notification_address_through(self) -> None:
        outcome = self._exercise_forwarding_with_address(
            "SCP11.orchestrator",
            "SCP11.models",
            "dpp1.example.com",
        )
        self.assertEqual(outcome["captured"][0].smdp_address, "dpp1.example.com")

    def test_test_orchestrator_passes_notification_address_through(self) -> None:
        outcome = self._exercise_forwarding_with_address(
            "SCP11.test.orchestrator",
            "SCP11.test.models",
            "smdp.example.test",
        )
        self.assertEqual(outcome["captured"][0].smdp_address, "smdp.example.test")

    def test_missing_notification_address_results_in_empty_carrier(self) -> None:
        orchestrator, captured, _ = self._build_orchestrator(
            "SCP11.live.orchestrator", "SCP11.live.models"
        )
        details = {"seqNumber": 9, "choice": "otherSignedNotification"}
        with mock.patch.object(orchestrator, "_decode_pending_notification_details", return_value=details):
            with mock.patch.object(orchestrator, "_summarize_es9_response", return_value="{}"):
                with mock.patch.object(orchestrator, "_format_notification_details", return_value=""):
                    with mock.patch.object(orchestrator, "_b64encode", return_value="dGVzdA=="):
                        orchestrator._forward_pending_notification(b"\x01\x02", 9, "queued")
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].smdp_address, "")

    def test_byte_encoded_notification_address_is_decoded(self) -> None:
        # Some decoders surface the FQDN as raw UTF-8 bytes rather than
        # a str; the extractor MUST tolerate both shapes so the choice
        # of underlying ASN.1 backend cannot strand notifications.
        orchestrator, captured, _ = self._build_orchestrator(
            "SCP11.live.orchestrator", "SCP11.live.models"
        )
        details = {"notificationAddress": b"dpp1.example.com", "seqNumber": 4}
        extracted = orchestrator._extract_notification_address_for_forwarding(details)
        self.assertEqual(extracted, "dpp1.example.com")

    def test_whitespace_around_notification_address_is_stripped(self) -> None:
        orchestrator, _, _ = self._build_orchestrator(
            "SCP11.live.orchestrator", "SCP11.live.models"
        )
        extracted = orchestrator._extract_notification_address_for_forwarding(
            {"notificationAddress": "  dpp1.example.com  "}
        )
        self.assertEqual(extracted, "dpp1.example.com")

    def test_non_dict_details_does_not_raise(self) -> None:
        orchestrator, _, _ = self._build_orchestrator(
            "SCP11.live.orchestrator", "SCP11.live.models"
        )
        self.assertEqual(
            orchestrator._extract_notification_address_for_forwarding(None),  # type: ignore[arg-type]
            "",
        )
        self.assertEqual(
            orchestrator._extract_notification_address_for_forwarding([]),  # type: ignore[arg-type]
            "",
        )


if __name__ == "__main__":
    unittest.main()
