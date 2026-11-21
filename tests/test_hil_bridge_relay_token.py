# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the bearer token guarding the HIL bridge's own APDU relay.

The relay refuses to serve a routable address unauthenticated. Until this
resolver existed the router built it with no token at all, so any
non-loopback bind killed the bridge at startup and the supervisor
crash-looped it. The rule that matters most here is the one that is not
about tokens: a loopback bind with nothing configured stays exactly as it
was, because that is every single-machine deployment.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from Tools.HilBridge.pcsc import PcscBridgeError
from Tools.HilBridge.router import _resolve_relay_auth_token


class RelayAuthTokenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_loopback_without_a_token_file_stays_unauthenticated(self) -> None:
        """The compatibility rule: nothing configured, nothing changes."""
        token, path = _resolve_relay_auth_token(
            host="127.0.0.1", port=0, token_file=""
        )
        self.assertEqual(token, "")
        self.assertEqual(path, "")

    def test_ipv6_loopback_is_also_left_alone(self) -> None:
        token, path = _resolve_relay_auth_token(host="::1", port=0, token_file="")
        self.assertEqual(token, "")
        self.assertEqual(path, "")

    def test_a_routable_bind_provisions_a_token_instead_of_failing(self) -> None:
        """Asking to be reachable means to be reachable, not to crash."""
        conventional = self.root / "relay-9997.token"
        with mock.patch(
            "Tools.HilBridge.router.default_token_file_for_port",
            return_value=conventional,
        ):
            token, path = _resolve_relay_auth_token(
                host="0.0.0.0", port=9997, token_file=""
            )
        self.assertTrue(len(token) > 0)
        self.assertEqual(path, str(conventional))
        self.assertTrue(conventional.is_file())

    def test_a_named_file_is_created_and_readable_only_by_its_owner(self) -> None:
        target = self.root / "named.token"
        token, path = _resolve_relay_auth_token(
            host="127.0.0.1", port=0, token_file=str(target)
        )
        self.assertTrue(len(token) > 0)
        self.assertEqual(Path(path), target)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)

    def test_an_existing_token_file_is_read_not_replaced(self) -> None:
        """Restarting the bridge must not invalidate a consumer's token."""
        target = self.root / "existing.token"
        target.write_text("already-issued\n", encoding="utf-8")
        token, path = _resolve_relay_auth_token(
            host="127.0.0.1", port=0, token_file=str(target)
        )
        self.assertEqual(token, "already-issued")
        self.assertEqual(Path(path), target)
        self.assertEqual(target.read_text(encoding="utf-8").strip(), "already-issued")

    def test_an_empty_token_file_is_an_error_rather_than_an_open_relay(self) -> None:
        target = self.root / "empty.token"
        target.write_text("", encoding="utf-8")
        with self.assertRaises(PcscBridgeError):
            _resolve_relay_auth_token(
                host="127.0.0.1", port=0, token_file=str(target)
            )

    def test_a_missing_parent_directory_is_created_rather_than_refused(self) -> None:
        nested = self.root / "state" / "relay.token"
        token, path = _resolve_relay_auth_token(
            host="0.0.0.0", port=9997, token_file=str(nested)
        )
        self.assertTrue(len(token) > 0)
        self.assertEqual(Path(path), nested)

    def test_an_unwritable_path_reports_the_path_rather_than_binding_open(self) -> None:
        """A file where a directory belongs: the write cannot succeed."""
        blocker = self.root / "not-a-directory"
        blocker.write_text("", encoding="utf-8")
        unwritable = blocker / "relay.token"
        with self.assertRaises(PcscBridgeError) as caught:
            _resolve_relay_auth_token(
                host="0.0.0.0", port=9997, token_file=str(unwritable)
            )
        self.assertIn(str(unwritable), str(caught.exception))


if __name__ == "__main__":
    unittest.main()
