# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the supervisor's lease over an operator-supplied card.

When a rig consumes a card that lives on someone else's desk, the
supervisor holds the lease rather than the bridge child: the child is
restarted on a backoff, and every restart would otherwise drop the lease
and re-take it, which the far end reads as a session switch and answers
with a physical card reset.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from Tools.HilBridge.router import BridgeConfig
from Tools.HilBridge.supervisor import (
    CARD_LEASE_TTL_SECONDS,
    HilBridgeSupervisor,
    HilBridgeSupervisorConfig,
    UsbPresenceSnapshot,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _relay_error(status: int) -> RuntimeError:
    error = RuntimeError(f"Card relay HTTP {status}: refused")
    error.status = status
    return error


class _SupervisorHarness:
    """A supervisor wired to a temp lease path and a stub USB monitor."""

    def __init__(self, *, remote_card_url: str = "http://127.0.0.1:8642/apdu") -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.lease_path = os.path.join(self.directory.name, "card_lease.token")
        self.state_path = os.path.join(self.directory.name, "supervisor.json")
        self.clock = _Clock()
        self.supervisor = HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(remote_card_url=remote_card_url),
                state_path=self.state_path,
                card_lease_path=self.lease_path,
            ),
            usb_monitor=mock.MagicMock(),
            monotonic=self.clock,
        )

    def close(self) -> None:
        self.directory.cleanup()


class SupervisorCardLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _SupervisorHarness()
        self.addCleanup(self.harness.close)
        self.supervisor = self.harness.supervisor

    def test_a_local_reader_rig_never_touches_the_lease(self) -> None:
        """No remote card means nothing to lease and no request to make."""
        local = _SupervisorHarness(remote_card_url="")
        self.addCleanup(local.close)
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json"
        ) as request:
            self.assertTrue(local.supervisor.claim_card_lease())
        request.assert_not_called()
        self.assertFalse(os.path.exists(local.lease_path))

    def test_claim_writes_an_owner_only_file_for_the_bridge_child(self) -> None:
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={"leaseToken": "lease-abc"},
        ):
            self.assertTrue(self.supervisor.claim_card_lease())
        self.assertTrue(os.path.exists(self.harness.lease_path))
        with open(self.harness.lease_path, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read().strip(), "lease-abc")
        self.assertEqual(os.stat(self.harness.lease_path).st_mode & 0o777, 0o600)

    def test_a_held_card_stops_the_bridge_from_starting(self) -> None:
        """The one case where continuing would put two masters on one card."""
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            side_effect=_relay_error(409),
        ):
            self.assertFalse(self.supervisor.claim_card_lease())
        self.assertFalse(os.path.exists(self.harness.lease_path))

    def test_a_relay_that_grants_no_lease_still_runs_the_bridge(self) -> None:
        """Back-compat: a relay with no bearer token answers 403."""
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            side_effect=_relay_error(403),
        ):
            self.assertTrue(self.supervisor.claim_card_lease())
        self.assertFalse(os.path.exists(self.harness.lease_path))

    def test_an_unreachable_relay_still_runs_the_bridge(self) -> None:
        """A tunnel that is not up yet must not be read as a held card."""
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            side_effect=RuntimeError("Card relay connection failed (OSError)."),
        ):
            self.assertTrue(self.supervisor.claim_card_lease())

    def test_opting_out_skips_the_lease_entirely(self) -> None:
        supervisor = HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(remote_card_url="http://127.0.0.1:8642/apdu"),
                state_path=self.harness.state_path,
                card_lease_path=self.harness.lease_path,
                remote_card_lease_enabled=False,
            ),
            usb_monitor=mock.MagicMock(),
        )
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json"
        ) as request:
            self.assertTrue(supervisor.claim_card_lease())
        request.assert_not_called()

    def test_release_drops_the_lease_and_removes_the_file(self) -> None:
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={"leaseToken": "lease-abc"},
        ):
            self.supervisor.claim_card_lease()
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={},
        ) as request:
            self.supervisor.release_card_lease()
        self.assertFalse(os.path.exists(self.harness.lease_path))
        self.assertEqual(request.call_args.kwargs["method"], "DELETE")

    def test_release_removes_the_file_even_when_the_far_end_is_gone(self) -> None:
        """The TTL is the backstop; a stale file would outlive the lease."""
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={"leaseToken": "lease-abc"},
        ):
            self.supervisor.claim_card_lease()
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            side_effect=RuntimeError("Card relay connection failed (OSError)."),
        ):
            self.supervisor.release_card_lease()
        self.assertFalse(os.path.exists(self.harness.lease_path))


class SupervisorCardLeaseRenewalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _SupervisorHarness()
        self.addCleanup(self.harness.close)
        self.supervisor = self.harness.supervisor
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={"leaseToken": "lease-abc"},
        ):
            self.supervisor.claim_card_lease()

    def test_renewal_is_paced_rather_than_issued_every_reconcile(self) -> None:
        """The reconcile loop runs every two seconds; the lease does not."""
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={},
        ) as request:
            for _ in range(10):
                self.harness.clock.advance(2.0)
                self.supervisor.renew_card_lease()
        request.assert_not_called()

    def test_renewal_fires_once_the_lease_is_a_third_spent(self) -> None:
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={},
        ) as request:
            self.harness.clock.advance(CARD_LEASE_TTL_SECONDS / 3.0 + 1.0)
            self.supervisor.renew_card_lease()
        self.assertEqual(request.call_count, 1)
        self.assertEqual(
            request.call_args.kwargs["request_json"]["leaseToken"], "lease-abc"
        )

    def test_a_failed_renewal_does_not_drop_the_lease(self) -> None:
        """A blip must not hand the card to someone else mid-session."""
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            side_effect=RuntimeError("Card relay connection timed out."),
        ):
            self.harness.clock.advance(CARD_LEASE_TTL_SECONDS)
            self.supervisor.renew_card_lease()
        self.assertTrue(os.path.exists(self.harness.lease_path))


class SupervisorCardLeaseCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _SupervisorHarness()
        self.addCleanup(self.harness.close)
        self.supervisor = self.harness.supervisor

    def test_the_lease_reaches_the_child_as_a_path_not_a_value(self) -> None:
        """A lease on the command line would show in every process listing."""
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={"leaseToken": "lease-abc"},
        ):
            self.supervisor.claim_card_lease()
        command = self.supervisor._build_bridge_command()
        self.assertIn("--remote-card-lease-file", command)
        self.assertIn(self.harness.lease_path, command)
        self.assertNotIn("lease-abc", command)

    def test_no_lease_means_no_flag(self) -> None:
        command = self.supervisor._build_bridge_command()
        self.assertNotIn("--remote-card-lease-file", command)

    def test_state_reports_the_lease_for_the_operator(self) -> None:
        with mock.patch(
            "Tools.HilBridge.supervisor._request_card_relay_json",
            return_value={"leaseToken": "lease-abc"},
        ):
            self.supervisor.claim_card_lease()
        self.supervisor._write_state(
            status="running",
            snapshot=UsbPresenceSnapshot(source="test", present=True),
            reason="",
        )
        with open(self.harness.state_path, "r", encoding="utf-8") as handle:
            raw_state = handle.read()
        state = json.loads(raw_state)
        self.assertEqual(state["cardLease"], "held")
        self.assertTrue(len(state["cardLeaseHolder"]) > 0)
        # The state file is world-readable; the lease itself must not be in it.
        self.assertNotIn("lease-abc", raw_state)


if __name__ == "__main__":
    unittest.main()
