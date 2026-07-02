# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Targeted tests for the command-scoped session reset policy.

The SCP11 live / test consoles classify every registered command into
one of three buckets:

* ``SHARED`` - leave the card session untouched.
* ``SOFT_RESET`` - wipe ephemeral crypto / STK fields on
  ``orchestrator.state`` before the handler runs, but keep the transport
  open.
* ``HARD_RESET`` - close the logical channel, clear ephemeral state,
  then re-run ``_phase_connect`` + ``_phase_load_credentials`` so the
  handler starts on a freshly reconnected session.

The tests below exercise the policy dispatcher directly against stub
orchestrators so the behavior is validated without needing a real card.
"""

import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
LIVE_CONSOLE_PATH = ROOT / "SCP11" / "live" / "console.py"
TEST_CONSOLE_PATH = ROOT / "SCP11" / "test" / "console.py"


def _load_module(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class DummyCfg:
    RSP_SERVER_URL = "rsp.default.example"
    ES9_BASE_URL = "https://rsp.default.example"
    ES9_VERIFY_TLS = True
    ES9_CA_BUNDLE_PATH = ""


class DummyApduChannel:
    def __init__(self) -> None:
        self.send_calls = []

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        return b""


class DummyProfileProvider:
    def __init__(self) -> None:
        self.base_url = DummyCfg.ES9_BASE_URL

    def set_base_url(self, base_url: str) -> None:
        self.base_url = base_url


class RecordingOrchestrator:
    """Minimal orchestrator stub that records session lifecycle calls."""

    def __init__(self) -> None:
        self.phase_connect_calls = 0
        self.phase_load_calls = 0
        self.close_channel_calls: list[str] = []
        self.state = SimpleNamespace(
            transaction_id=b"\xAA" * 16,
            provider_transaction_id="prev-txn",
            server_challenge=b"\xBB" * 16,
            euicc_signed1=b"\xCC" * 8,
            euicc_signature1=b"\xDD" * 8,
            euicc_signed2=b"\xEE" * 8,
            authenticate_server_response_b64="prev-auth",
            prepare_download_response_b64="prev-prep",
            bpp_b64="prev-bpp-b64",
            bpp_bytes=b"\x01\x02\x03",
            load_bpp_response=b"\x04\x05",
            load_bpp_aid=b"\x06",
            load_bpp_sima_response=b"\x07",
            eim_package_response=b"\x08\x09",
            card_challenge=b"\x0A" * 16,
            provider_smdp_certificate=b"\x0B\x0C",
            relay_session_id="prev-session",
            stk_command_history=["old-cmd"],
            stk_status_history=["old-status"],
            stk_flow_events=["old-event"],
            stk_timer_history=["old-timer"],
            stk_generic_ack_history=["old-ack"],
            stk_trigger_history=["old-trigger"],
            stk_dns_history=["old-dns"],
            stk_tls_history=["old-tls"],
            stk_alert_history=["old-alert"],
            stk_open_channel_history=["old-oc"],
            stk_open_channel_failure_history=["old-ocf"],
            stk_pending_channel_queue=[b"\xFF"],
            stk_pending_channel_data=b"\xFF",
            stk_last_proactive_command=b"\xFF",
            stk_last_channel_data_sent=42,
            # persistent fields that must NOT be cleared
            current_euicc_ci_pkid="pkid-preserved",
            stk_event_list=[3, 9, 10],
            stk_poll_interval_seconds=286,
            stk_location_information=b"\x62\xF2\x10\x00\x01\x00\x01",
            stk_imei=b"abc123",
        )
        self._last_eim_poll_reached_server = True
        self.profile_provider = DummyProfileProvider()

    def _phase_connect(self) -> None:
        self.phase_connect_calls += 1

    def _phase_load_credentials(self) -> None:
        self.phase_load_calls += 1

    def _close_es10b_logical_channel(self, scope: str) -> None:
        self.close_channel_calls.append(scope)

    def _sync_pending_notifications(self, response: bytes = b"") -> None:
        # Unused by policy tests but kept so post-handler sync does not
        # raise on trigger_notification_sync=True entries.
        return None


class _SessionPolicyHarness:
    module = None

    def _build_console(self):
        client = SimpleNamespace(
            cfg=DummyCfg(),
            apdu_channel=DummyApduChannel(),
            orchestrator=RecordingOrchestrator(),
        )
        console = self.module.SCP11Console(client)
        console._style = self.module.ConsoleStyle("", "", "", "", "", "", "")
        # Neutralize notification post-hooks so each test only observes
        # the session policy work done by _execute_command itself.
        console._sync_notifications_after_success = lambda response=b"": None
        console._clear_notifications_internal = lambda quiet=False: 0
        return console


class SessionPolicyBehaviorMixin(_SessionPolicyHarness):
    """Shared assertions run against both live and test console modules."""

    def test_session_policy_constants_are_distinct(self):
        policy = self.module.SessionPolicy
        self.assertEqual(policy.SHARED, "shared")
        self.assertEqual(policy.SOFT_RESET, "soft")
        self.assertEqual(policy.HARD_RESET, "hard")

    def test_shared_command_performs_no_reset_work(self):
        console = self._build_console()
        console._commands["HELP"].handler = lambda argument: True

        orchestrator = console.orchestrator
        before_txn = bytes(orchestrator.state.transaction_id)

        keep_running = console._execute_command("HELP", "")

        self.assertTrue(keep_running)
        self.assertEqual(orchestrator.phase_connect_calls, 0)
        self.assertEqual(orchestrator.phase_load_calls, 0)
        self.assertEqual(orchestrator.close_channel_calls, [])
        # Ephemeral state untouched by SHARED dispatch.
        self.assertEqual(orchestrator.state.transaction_id, before_txn)
        self.assertEqual(orchestrator.state.card_challenge, b"\x0A" * 16)

    def test_shared_command_does_not_flip_session_dirty_bit(self):
        console = self._build_console()
        console._commands["HELP"].handler = lambda argument: True

        console._session_dirty = False
        console._execute_command("HELP", "")

        self.assertFalse(console._session_dirty)

    def test_soft_reset_clears_ephemeral_state_without_reconnect(self):
        console = self._build_console()
        console._commands["LIST"].handler = lambda argument: True

        orchestrator = console.orchestrator
        console._execute_command("LIST", "")

        # Ephemeral bytes / strings zeroed.
        self.assertEqual(orchestrator.state.transaction_id, b"")
        self.assertEqual(orchestrator.state.card_challenge, b"")
        self.assertEqual(orchestrator.state.euicc_signed1, b"")
        self.assertEqual(orchestrator.state.bpp_bytes, b"")
        self.assertEqual(orchestrator.state.authenticate_server_response_b64, "")
        self.assertEqual(orchestrator.state.bpp_b64, "")
        self.assertEqual(orchestrator.state.relay_session_id, "")
        # STK histories cleared.
        self.assertEqual(orchestrator.state.stk_command_history, [])
        self.assertEqual(orchestrator.state.stk_status_history, [])
        self.assertEqual(orchestrator.state.stk_pending_channel_queue, [])
        self.assertEqual(orchestrator.state.stk_pending_channel_data, b"")
        self.assertEqual(orchestrator.state.stk_last_channel_data_sent, 0)
        # eIM gate flag reset.
        self.assertFalse(orchestrator._last_eim_poll_reached_server)
        # No reconnect / channel-close work performed.
        self.assertEqual(orchestrator.phase_connect_calls, 0)
        self.assertEqual(orchestrator.phase_load_calls, 0)
        self.assertEqual(orchestrator.close_channel_calls, [])

    def test_soft_reset_preserves_persistent_discovery_fields(self):
        console = self._build_console()
        console._commands["LIST"].handler = lambda argument: True

        orchestrator = console.orchestrator
        console._execute_command("LIST", "")

        # These fields describe the card's advertised terminal identity
        # and discovery snapshot; they must survive SOFT_RESET.
        self.assertEqual(orchestrator.state.current_euicc_ci_pkid, "pkid-preserved")
        self.assertEqual(orchestrator.state.stk_event_list, [3, 9, 10])
        self.assertEqual(orchestrator.state.stk_poll_interval_seconds, 286)
        self.assertEqual(
            orchestrator.state.stk_location_information,
            b"\x62\xF2\x10\x00\x01\x00\x01",
        )
        self.assertEqual(orchestrator.state.stk_imei, b"abc123")

    def test_soft_reset_marks_session_dirty_after_handler(self):
        console = self._build_console()
        console._commands["LIST"].handler = lambda argument: True

        console._session_dirty = False
        console._execute_command("LIST", "")

        self.assertTrue(console._session_dirty)

    def test_hard_reset_reconnects_when_session_dirty(self):
        console = self._build_console()
        console._commands["DOWNLOAD"].handler = lambda argument: True

        orchestrator = console.orchestrator
        console._session_dirty = True

        console._execute_command("DOWNLOAD", "")

        # Ephemeral fields zeroed.
        self.assertEqual(orchestrator.state.transaction_id, b"")
        self.assertEqual(orchestrator.state.bpp_bytes, b"")
        # Logical channel closed then reconnect + load credentials.
        self.assertEqual(len(orchestrator.close_channel_calls), 1)
        self.assertIn("DOWNLOAD", orchestrator.close_channel_calls[0])
        self.assertEqual(orchestrator.phase_connect_calls, 1)
        self.assertEqual(orchestrator.phase_load_calls, 1)
        # Hard reset completed, then handler ran, which flips dirty bit back True.
        self.assertTrue(console._session_dirty)

    def test_hard_reset_skipped_when_session_clean(self):
        console = self._build_console()
        console._commands["DOWNLOAD"].handler = lambda argument: True

        orchestrator = console.orchestrator
        # Simulate a shell that has just completed _initialize_session
        # so no reset is warranted for the very first command.
        console._session_dirty = False

        console._execute_command("DOWNLOAD", "")

        self.assertEqual(orchestrator.phase_connect_calls, 0)
        self.assertEqual(orchestrator.phase_load_calls, 0)
        self.assertEqual(orchestrator.close_channel_calls, [])
        # Handler still runs and then marks the session dirty.
        self.assertTrue(console._session_dirty)

    def test_hard_reset_invalidates_cached_discovery_snapshot(self):
        console = self._build_console()
        console._commands["DOWNLOAD"].handler = lambda argument: True
        console._latest_snapshot = object()
        console._cached_poll_target_fqdns = ["eim1.example"]
        console._session_dirty = True

        console._execute_command("DOWNLOAD", "")

        self.assertIsNone(console._latest_snapshot)
        self.assertEqual(console._cached_poll_target_fqdns, [])

    def test_leave_marks_dirty_even_when_handler_raises(self):
        console = self._build_console()

        def failing_handler(argument):
            raise RuntimeError("boom")

        console._commands["LIST"].handler = failing_handler
        console._session_dirty = False

        with self.assertRaises(RuntimeError):
            console._execute_command("LIST", "")

        self.assertTrue(console._session_dirty)

    def test_reset_orchestrator_ephemeral_state_is_safe_against_stub_without_state(self):
        console = self._build_console()
        # Drop both ``state`` and session lifecycle hooks to mimic the
        # minimal orchestrator stubs used elsewhere in the test suite.
        console.orchestrator = SimpleNamespace()

        # Must not raise when the orchestrator lacks a ``state`` attribute.
        console._reset_orchestrator_ephemeral_state()
        console._reset_card_session_hard(reason="TEST")

    def test_every_registered_command_has_session_policy(self):
        console = self._build_console()
        policy = self.module.SessionPolicy
        valid = {policy.SHARED, policy.SOFT_RESET, policy.HARD_RESET}
        for name, spec in console._commands.items():
            assigned = getattr(spec, "session_policy", None)
            self.assertIn(
                assigned,
                valid,
                msg=f"command {name!r} has invalid session_policy: {assigned!r}",
            )

    def test_download_and_flow_use_hard_reset_policy(self):
        console = self._build_console()
        policy = self.module.SessionPolicy
        for name in ("DOWNLOAD", "EIM-DOWNLOAD", "FLOW", "DOWNLOAD-PROFILE",
                     "ENABLE-PROFILE", "DISABLE-PROFILE", "DELETE-PROFILE",
                     "EIM-AUTHENTICATE", "RESET"):
            self.assertEqual(
                console._commands[name].session_policy,
                policy.HARD_RESET,
                msg=f"{name} expected HARD_RESET policy",
            )

    def test_card_read_commands_use_soft_reset_policy(self):
        console = self._build_console()
        policy = self.module.SessionPolicy
        for name in ("LIST", "STATUS", "GET-EID", "SCAN", "GET-EUICC-INFO1",
                     "GET-NOTIFICATIONS", "METADATA", "GET-ALL-DATA",
                     "DISCOVER"):
            self.assertEqual(
                console._commands[name].session_policy,
                policy.SOFT_RESET,
                msg=f"{name} expected SOFT_RESET policy",
            )

    def test_local_config_commands_use_shared_policy(self):
        console = self._build_console()
        policy = self.module.SessionPolicy
        for name in ("HELP", "HELP-ALL", "GET-ES9", "SET-ES9",
                     "SET-ES9-TLS", "SET-ES9-CA", "ES9-CERT-INFO",
                     "AIDS", "EXIT", "QA"):
            self.assertEqual(
                console._commands[name].session_policy,
                policy.SHARED,
                msg=f"{name} expected SHARED policy",
            )


class SessionPolicyLiveShellTests(SessionPolicyBehaviorMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_module("live_console_session_policy_module", LIVE_CONSOLE_PATH)


class SessionPolicyTestShellTests(SessionPolicyBehaviorMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_module("test_console_session_policy_module", TEST_CONSOLE_PATH)


if __name__ == "__main__":
    unittest.main()
