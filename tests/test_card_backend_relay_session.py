# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""``RelayCardConnection`` carries a relay-session identity.

Every operator shell that reaches the card through the HIL bridge does
so under a session id, and reports the session closed on teardown. That
is what lets the bridge power-cycle the card at the boundaries instead
of letting a shell's secure-channel or logical-channel state leak into
the next modem session.

No sockets: the relay transport is patched out entirely.
"""

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from yggdrasim_common import card_backend


def _fake_relay(captured: list[dict[str, Any]], *, reset_error: Exception | None = None):
    def fake_request(url, *, method, timeout_seconds, request_json=None, auth_token=""):
        del timeout_seconds, auth_token
        captured.append({"url": url, "method": method, "request_json": request_json})
        if url.endswith("/status"):
            return {"atr": "3B00"}
        if url.endswith("/card/reset"):
            if reset_error is not None:
                raise reset_error
            return {"status": "reset", "atr": "3B9F"}
        return {"data": "", "sw1": "90", "sw2": "00"}

    return fake_request


class RelaySessionIdentityTests(unittest.TestCase):

    def test_session_id_is_minted_when_not_supplied(self) -> None:
        connection = card_backend.RelayCardConnection("http://127.0.0.1:8642/apdu")
        self.assertTrue(len(connection.session_id) > 0)

    def test_supplied_session_id_is_kept(self) -> None:
        connection = card_backend.RelayCardConnection(
            "http://127.0.0.1:8642/apdu",
            session_id="scp11-live",
        )
        self.assertEqual(connection.session_id, "scp11-live")

    def test_two_connections_get_distinct_session_ids(self) -> None:
        first = card_backend.RelayCardConnection("http://127.0.0.1:8642/apdu")
        second = card_backend.RelayCardConnection("http://127.0.0.1:8642/apdu")
        self.assertNotEqual(first.session_id, second.session_id)

    def test_card_reset_url_sits_beside_the_apdu_endpoint(self) -> None:
        connection = card_backend.RelayCardConnection("http://127.0.0.1:8642/apdu")
        self.assertEqual(connection._card_reset_url, "http://127.0.0.1:8642/card/reset")

    def test_card_reset_url_handles_an_endpoint_without_the_apdu_leaf(self) -> None:
        connection = card_backend.RelayCardConnection("http://127.0.0.1:8642")
        self.assertEqual(connection._card_reset_url, "http://127.0.0.1:8642/card/reset")


class RelaySessionLifecycleTests(unittest.TestCase):

    def test_transmit_carries_the_session_id(self) -> None:
        captured: list[dict[str, Any]] = []
        with patch.object(card_backend, "_request_card_relay_json", side_effect=_fake_relay(captured)):
            connection = card_backend.RelayCardConnection(
                "http://127.0.0.1:8642/apdu",
                session_id="scp03-a",
            )
            connection.connect()
            connection.transmit(bytes.fromhex("00A40400"))

        apdu_calls = [call for call in captured if call["url"].endswith("/apdu")]
        self.assertEqual(apdu_calls[0]["request_json"]["sessionId"], "scp03-a")

    def test_disconnect_reports_the_session_end(self) -> None:
        captured: list[dict[str, Any]] = []
        with patch.object(card_backend, "_request_card_relay_json", side_effect=_fake_relay(captured)):
            connection = card_backend.RelayCardConnection(
                "http://127.0.0.1:8642/apdu",
                session_id="scp03-a",
            )
            connection.connect()
            connection.transmit(bytes.fromhex("00A40400"))
            connection.disconnect()

        reset_calls = [call for call in captured if call["url"].endswith("/card/reset")]
        self.assertEqual(len(reset_calls), 1)
        self.assertEqual(reset_calls[0]["method"], "POST")
        self.assertEqual(
            reset_calls[0]["request_json"],
            {"sessionId": "scp03-a", "boundary": "end"},
        )

    def test_disconnect_without_any_apdu_stays_silent(self) -> None:
        # Nothing reached the card, so there is no state to clear -- and
        # no reason to bounce a modem that may be mid-session.
        captured: list[dict[str, Any]] = []
        with patch.object(card_backend, "_request_card_relay_json", side_effect=_fake_relay(captured)):
            connection = card_backend.RelayCardConnection("http://127.0.0.1:8642/apdu")
            connection.connect()
            connection.disconnect()

        self.assertEqual([call for call in captured if call["url"].endswith("/card/reset")], [])

    def test_second_disconnect_does_not_report_again(self) -> None:
        captured: list[dict[str, Any]] = []
        with patch.object(card_backend, "_request_card_relay_json", side_effect=_fake_relay(captured)):
            connection = card_backend.RelayCardConnection("http://127.0.0.1:8642/apdu")
            connection.connect()
            connection.transmit(bytes.fromhex("00A40400"))
            connection.disconnect()
            connection.disconnect()

        reset_calls = [call for call in captured if call["url"].endswith("/card/reset")]
        self.assertEqual(len(reset_calls), 1)

    def test_disconnect_survives_an_unreachable_relay(self) -> None:
        # Teardown runs when a shell exits; a relay that has already
        # gone away must not turn that into a traceback.
        captured: list[dict[str, Any]] = []
        fake = _fake_relay(captured, reset_error=RuntimeError("Card relay HTTP 503"))
        with patch.object(card_backend, "_request_card_relay_json", side_effect=fake):
            connection = card_backend.RelayCardConnection("http://127.0.0.1:8642/apdu")
            connection.connect()
            connection.transmit(bytes.fromhex("00A40400"))
            connection.disconnect()  # must not raise

        self.assertEqual(len([c for c in captured if c["url"].endswith("/card/reset")]), 1)

    def test_reconnect_after_disconnect_reports_a_fresh_end(self) -> None:
        captured: list[dict[str, Any]] = []
        with patch.object(card_backend, "_request_card_relay_json", side_effect=_fake_relay(captured)):
            connection = card_backend.RelayCardConnection("http://127.0.0.1:8642/apdu")
            connection.connect()
            connection.transmit(bytes.fromhex("00A40400"))
            connection.disconnect()
            connection.connect()
            connection.transmit(bytes.fromhex("00A40400"))
            connection.disconnect()

        reset_calls = [call for call in captured if call["url"].endswith("/card/reset")]
        self.assertEqual(len(reset_calls), 2)


if __name__ == "__main__":
    unittest.main()
