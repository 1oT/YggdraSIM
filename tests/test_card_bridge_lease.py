# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the cooperative card lease in ``Tools.HilBridge.apdu_relay``.

The lease stops two consumers driving one card at once. Expiry is the
safety property and is exercised first: a lease that outlives its holder
strands a card on a rig that may have no reachable power control.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock
from urllib import error as urllib_error
from urllib import request as urllib_request

from Tools.HilBridge.apdu_relay import (
    CARD_LEASE_HEADER,
    DEFAULT_LEASE_TTL_SECONDS,
    MAX_LEASE_TTL_SECONDS,
    MIN_LEASE_TTL_SECONDS,
    ApduRelayConfig,
    CardLeaseConflict,
    HilBridgeApduRelayService,
    _CardLeaseRegistry,
)


class _FakeClock:
    """A monotonic clock the test advances by hand."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class CardLeaseExpiryTests(unittest.TestCase):
    """Expiry first: nothing else matters if a dead holder wedges the card."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.lease = _CardLeaseRegistry(clock=self.clock)

    def test_lease_expires_without_release_and_frees_the_card(self) -> None:
        self.lease.claim(holder="rig-a", ttl_seconds=60.0)
        self.assertFalse(self.lease.authorize("wrong-token"))

        self.clock.advance(59.0)
        self.assertFalse(self.lease.authorize("wrong-token"))

        # The holder dies here; nobody releases anything.
        self.clock.advance(2.0)
        self.assertTrue(self.lease.authorize(""))
        self.assertFalse(self.lease.state().held)

    def test_expired_lease_can_be_claimed_by_a_different_holder(self) -> None:
        self.lease.claim(holder="rig-a", ttl_seconds=30.0)
        self.clock.advance(31.0)
        token = self.lease.claim(holder="operator-b", ttl_seconds=30.0)
        self.assertEqual(self.lease.state().holder, "operator-b")
        self.assertTrue(self.lease.authorize(token))

    def test_ttl_is_clamped_at_both_ends(self) -> None:
        self.lease.claim(holder="rig-a", ttl_seconds=0.0)
        self.assertEqual(self.lease.state().ttl_seconds, MIN_LEASE_TTL_SECONDS)
        self.lease.release(force=True)

        self.lease.claim(holder="rig-a", ttl_seconds=10_000_000.0)
        self.assertEqual(self.lease.state().ttl_seconds, MAX_LEASE_TTL_SECONDS)

    def test_a_renewal_after_the_lease_lapsed_re_establishes_the_same_token(self) -> None:
        """Otherwise the holder is orphaned by its own heartbeat.

        Minting a new token here leaves the holder renewing one the relay
        no longer knows, so the first call that actually needs the lease
        is refused by a lease nobody can present.
        """
        token = self.lease.claim(holder="rig-a", ttl_seconds=30.0)
        self.clock.advance(31.0)
        self.assertFalse(self.lease.state().held)

        renewed = self.lease.claim(
            holder="rig-a", ttl_seconds=30.0, renew_token=token
        )
        self.assertEqual(renewed, token)
        self.assertTrue(self.lease.authorize(token))
        self.assertEqual(self.lease.state().holder, "rig-a")

    def test_a_lapsed_renewal_keeps_the_holder_when_none_is_resent(self) -> None:
        token = self.lease.claim(holder="rig-a", ttl_seconds=30.0)
        self.clock.advance(31.0)
        self.lease.claim(holder="", ttl_seconds=30.0, renew_token=token)
        self.assertEqual(self.lease.state().holder, "rig-a")

    def test_a_stranger_still_cannot_renew_a_held_lease(self) -> None:
        """Re-establishing must not become a way in while one is held."""
        self.lease.claim(holder="rig-a", ttl_seconds=60.0)
        with self.assertRaises(CardLeaseConflict):
            self.lease.claim(
                holder="someone-else", ttl_seconds=60.0, renew_token="invented"
            )

    def test_renewal_extends_from_now_rather_than_from_the_original_claim(self) -> None:
        token = self.lease.claim(holder="rig-a", ttl_seconds=60.0)
        self.clock.advance(50.0)
        self.lease.claim(holder="rig-a", ttl_seconds=60.0, renew_token=token)
        self.clock.advance(50.0)
        self.assertTrue(self.lease.state().held)
        self.assertFalse(self.lease.authorize("wrong-token"))


class CardLeaseExclusionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.lease = _CardLeaseRegistry(clock=self.clock)

    def test_no_lease_held_means_every_caller_reaches_the_card(self) -> None:
        """The compatibility property: an unleased relay behaves as before."""
        self.assertTrue(self.lease.authorize(""))
        self.assertTrue(self.lease.authorize("anything"))
        self.assertFalse(self.lease.state().held)

    def test_holder_reaches_the_card_and_everyone_else_is_refused(self) -> None:
        token = self.lease.claim(holder="remote-lab:session-1")
        self.assertTrue(self.lease.authorize(token))
        self.assertFalse(self.lease.authorize(""))
        self.assertFalse(self.lease.authorize("some-other-token"))

    def test_second_claim_by_another_holder_raises_with_the_holder_named(self) -> None:
        self.lease.claim(holder="remote-lab:session-1", ttl_seconds=60.0)
        with self.assertRaises(CardLeaseConflict) as caught:
            self.lease.claim(holder="hil:modem-a", ttl_seconds=60.0)
        self.assertEqual(caught.exception.holder, "remote-lab:session-1")
        self.assertGreater(caught.exception.expires_in_seconds, 0.0)

    def test_release_needs_the_lease_token(self) -> None:
        token = self.lease.claim(holder="rig-a")
        with self.assertRaises(CardLeaseConflict):
            self.lease.release(lease_token="not-the-token")
        self.assertTrue(self.lease.release(lease_token=token))
        self.assertTrue(self.lease.authorize(""))

    def test_forced_release_breaks_a_lease_for_operator_recovery(self) -> None:
        self.lease.claim(holder="rig-a")
        self.assertTrue(self.lease.release(force=True))
        self.assertFalse(self.lease.state().held)

    def test_releasing_nothing_reports_false_rather_than_raising(self) -> None:
        self.assertFalse(self.lease.release(force=True))

    def test_state_never_discloses_the_lease_token(self) -> None:
        token = self.lease.claim(holder="rig-a")
        rendered = repr(self.lease.state())
        self.assertNotIn(token, rendered)


def _service(auth_token: str) -> HilBridgeApduRelayService:
    return HilBridgeApduRelayService(
        config=ApduRelayConfig(auth_token=auth_token),
        exchange_callback=lambda apdu: (b"\x90\x00", 0x90, 0x00),
        status_callback=dict,
    )


class CardLeaseServiceTests(unittest.TestCase):
    def test_lease_payload_reports_support_only_with_a_bearer_token(self) -> None:
        """A lease on an unauthenticated relay would protect nothing."""
        self.assertFalse(_service("").lease_payload()["leaseSupported"])
        self.assertTrue(_service("bridge-token").lease_payload()["leaseSupported"])

    def test_fresh_service_reports_no_lease_and_admits_every_caller(self) -> None:
        service = _service("bridge-token")
        payload = service.lease_payload()
        self.assertFalse(payload["held"])
        self.assertEqual(payload["holder"], "")
        self.assertTrue(service.lease.authorize(""))

    def test_lease_payload_reports_the_holder_and_default_ttl(self) -> None:
        service = _service("bridge-token")
        service.lease.claim(holder="remote-lab:session-9")
        payload = service.lease_payload()
        self.assertTrue(payload["held"])
        self.assertEqual(payload["holder"], "remote-lab:session-9")
        self.assertEqual(payload["ttlSeconds"], DEFAULT_LEASE_TTL_SECONDS)
        self.assertNotIn("leaseToken", payload)

    def test_lease_url_hangs_off_the_relay_base_url(self) -> None:
        service = _service("bridge-token")
        self.assertTrue(service.lease_url.endswith("/lease"))
        self.assertTrue(service.lease_url.startswith(service.base_url))


class CardLeaseHttpTests(unittest.TestCase):
    """Drive the real handler over a loopback socket.

    The registry tests above cover the decision; these cover the wiring,
    which is where an enforcement point is actually missed.
    """

    def setUp(self) -> None:
        self.transmitted: list[bytes] = []

        def exchange(apdu: bytes, **_kwargs: object) -> tuple[bytes, int, int]:
            self.transmitted.append(apdu)
            return b"", 0x90, 0x00

        self.service = HilBridgeApduRelayService(
            config=ApduRelayConfig(host="127.0.0.1", port=0, auth_token="bridge-token"),
            exchange_callback=exchange,
            status_callback=dict,
            card_reset_callback=lambda **_kwargs: {"status": "reset"},
        )
        self.service.start()
        self.addCleanup(self.service.stop)
        self.base_url = self.service.base_url

    def _call(
        self,
        method: str,
        path: str,
        *,
        body: dict | None = None,
        lease_token: str = "",
        token: str = "bridge-token",
    ) -> tuple[int, dict]:
        payload = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib_request.Request(
            self.base_url + path, data=payload, method=method
        )
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Content-Type", "application/json")
        if len(lease_token) > 0:
            request.add_header(CARD_LEASE_HEADER, lease_token)
        try:
            with urllib_request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib_error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def _transmit(self, lease_token: str = "") -> tuple[int, dict]:
        return self._call(
            "POST", "/apdu", body={"apdu": "00A40004023F00"}, lease_token=lease_token
        )

    def test_apdu_flows_freely_while_no_lease_is_held(self) -> None:
        status, _ = self._transmit()
        self.assertEqual(status, 200)
        self.assertEqual(len(self.transmitted), 1)

    def test_lease_claim_then_only_the_holder_transmits(self) -> None:
        status, claimed = self._call(
            "POST", "/lease", body={"holder": "remote-lab:session-1"}
        )
        self.assertEqual(status, 200)
        lease_token = claimed["leaseToken"]
        self.assertTrue(len(lease_token) > 0)

        held_status, _ = self._transmit(lease_token=lease_token)
        self.assertEqual(held_status, 200)

        refused_status, refused = self._transmit()
        self.assertEqual(refused_status, 409)
        self.assertEqual(refused["holder"], "remote-lab:session-1")
        # Only the holder's APDU reached the card; the refused one did not.
        self.assertEqual(len(self.transmitted), 1)

    def test_card_reset_is_gated_by_the_lease_too(self) -> None:
        _, claimed = self._call("POST", "/lease", body={"holder": "rig-a"})
        refused_status, _ = self._call("POST", "/card/reset", body={})
        self.assertEqual(refused_status, 409)
        allowed_status, _ = self._call(
            "POST", "/card/reset", body={}, lease_token=claimed["leaseToken"]
        )
        self.assertEqual(allowed_status, 200)

    def test_second_holder_is_refused_with_the_current_holder_named(self) -> None:
        self._call("POST", "/lease", body={"holder": "remote-lab:session-1"})
        status, payload = self._call("POST", "/lease", body={"holder": "hil:modem-a"})
        self.assertEqual(status, 409)
        self.assertEqual(payload["holder"], "remote-lab:session-1")

    def test_release_frees_the_card_for_everyone(self) -> None:
        _, claimed = self._call("POST", "/lease", body={"holder": "rig-a"})
        status, _ = self._call(
            "DELETE", "/lease", body={"leaseToken": claimed["leaseToken"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(self._transmit()[0], 200)

    def test_lease_get_reports_state_without_the_token(self) -> None:
        _, claimed = self._call("POST", "/lease", body={"holder": "rig-a"})
        status, payload = self._call("GET", "/lease")
        self.assertEqual(status, 200)
        self.assertTrue(payload["held"])
        self.assertEqual(payload["holder"], "rig-a")
        self.assertNotIn("leaseToken", payload)
        self.assertNotIn(claimed["leaseToken"], json.dumps(payload))

    def test_claiming_without_a_holder_is_a_bad_request(self) -> None:
        status, _ = self._call("POST", "/lease", body={})
        self.assertEqual(status, 400)

    def test_lease_routes_still_require_the_bearer_token(self) -> None:
        status, _ = self._call("GET", "/lease", token="wrong-token")
        self.assertEqual(status, 401)


class CardLeaseUnauthenticatedRelayTests(unittest.TestCase):
    def test_relay_without_a_bearer_token_refuses_to_grant_a_lease(self) -> None:
        """Otherwise the lease is theatre on an open loopback port."""
        service = HilBridgeApduRelayService(
            config=ApduRelayConfig(host="127.0.0.1", port=0, auth_token=""),
            exchange_callback=lambda apdu, **_kwargs: (b"", 0x90, 0x00),
            status_callback=dict,
        )
        service.start()
        self.addCleanup(service.stop)
        request = urllib_request.Request(
            service.base_url + "/lease",
            data=json.dumps({"holder": "rig-a"}).encode("utf-8"),
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        with self.assertRaises(urllib_error.HTTPError) as caught:
            urllib_request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 403)


class LeasedReaderIsReportedAsBusyTests(unittest.TestCase):
    """A card streamed to another machine must not read as idle here.

    Nothing on this host holds a session for it, so every local signal
    says the reader is free while the card is in fact being driven.
    """

    def setUp(self) -> None:
        # A bridge writes this on startup and the probe looks for it by
        # port. The suite isolates the config directory, so each test
        # supplies it rather than inheriting one another test left.
        from yggdrasim_common.card_bridge_auth import (
            default_token_file_for_port,
            write_token_file,
        )

        self.port_token = default_token_file_for_port(8642)
        self.port_token.parent.mkdir(parents=True, exist_ok=True)
        write_token_file(self.port_token, "port-token")
        self.addCleanup(self.port_token.unlink, True)

    def test_status_names_the_holder(self) -> None:
        service = _service("bridge-token")
        service.lease.claim(holder="hil-supervisor@rig.example.test")
        payload = service.status_payload()
        self.assertTrue(payload["cardLease"]["held"])
        self.assertEqual(
            payload["cardLease"]["holder"], "hil-supervisor@rig.example.test"
        )

    def test_status_never_carries_the_lease_itself(self) -> None:
        service = _service("bridge-token")
        token = service.lease.claim(holder="rig-a")
        self.assertNotIn(token, json.dumps(service.status_payload()))

    def test_an_unleased_bridge_reports_it_plainly(self) -> None:
        payload = _service("bridge-token").status_payload()
        self.assertFalse(payload["cardLease"]["held"])
        self.assertEqual(payload["cardLease"]["holder"], "")

    def test_the_reader_probe_annotates_the_leased_reader(self) -> None:
        from yggdrasim_common.gui_server.routes import live

        bridge_status = {
            "reader": "Example Reader 00 00",
            "cardLease": {"held": True, "holder": "hil-supervisor@rig.example.test"},
        }
        with mock.patch(
            "yggdrasim_common.card_backend._request_card_relay_json",
            return_value=bridge_status,
        ):
            with mock.patch(
                "yggdrasim_common.gui_server.actions.card_bridge._load_remote_rig_state",
                return_value={"local_card_bridge_port": 8642},
            ):
                leases = live._local_bridge_card_leases()
        self.assertEqual(
            leases, {"Example Reader 00 00": "hil-supervisor@rig.example.test"}
        )

    def test_a_stale_token_path_does_not_hide_the_lease(self) -> None:
        """The recorded path can belong to a bridge on another port.

        Reading it succeeds while the request it authenticates does not,
        so the probe tries the port's own token first and falls through
        to whichever actually answers.
        """
        from yggdrasim_common.gui_server.routes import live

        good = {
            "reader": "Example Reader 00 00",
            "cardLease": {"held": True, "holder": "hil-supervisor@rig.example.test"},
        }
        with mock.patch(
            "yggdrasim_common.card_backend._request_card_relay_json",
            return_value=good,
        ):
            with mock.patch(
                "yggdrasim_common.gui_server.actions.card_bridge._load_remote_rig_state",
                return_value={
                    "local_card_bridge_port": 8642,
                    "local_card_bridge_token_file": "/nonexistent/stale.token",
                },
            ):
                leases = live._local_bridge_card_leases()
        # The recorded path cannot be read at all, so a probe that tried
        # it first would give up. Trying the port's own token first finds
        # the lease anyway.
        self.assertEqual(
            leases, {"Example Reader 00 00": "hil-supervisor@rig.example.test"}
        )

    def test_a_bridge_that_is_gone_costs_the_probe_nothing(self) -> None:
        """The reader poll runs every few seconds and must never fail here."""
        from yggdrasim_common.gui_server.routes import live

        with mock.patch(
            "yggdrasim_common.card_backend._request_card_relay_json",
            side_effect=RuntimeError("Card relay connection failed (OSError)."),
        ):
            with mock.patch(
                "yggdrasim_common.gui_server.actions.card_bridge._load_remote_rig_state",
                return_value={"local_card_bridge_port": 8642},
            ):
                self.assertEqual(live._local_bridge_card_leases(), {})

    def test_no_local_bridge_means_no_probe_at_all(self) -> None:
        from yggdrasim_common.gui_server.routes import live

        with mock.patch(
            "yggdrasim_common.gui_server.actions.card_bridge._load_remote_rig_state",
            return_value={},
        ):
            self.assertEqual(live._local_bridge_card_leases(), {})


if __name__ == "__main__":
    unittest.main()
