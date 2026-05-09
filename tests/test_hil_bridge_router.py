# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``Tools.HilBridge.router.BridgeSession`` instance methods.

Covers: allocate_tag, reset_runtime_state, server_identity, bankd_identity.
No network sockets or card transport are touched; all external collaborators
are replaced with ``MagicMock``.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from Tools.HilBridge.router import BridgeConfig, BridgeSession


def _make_session(**kwargs: object) -> BridgeSession:
    config = BridgeConfig(**{k: v for k, v in kwargs.items() if hasattr(BridgeConfig, k)})
    card = MagicMock()
    gsmtap = MagicMock()
    return BridgeSession(config=config, card=card, gsmtap=gsmtap)


class AllocateTagTests(unittest.TestCase):

    def test_starts_at_one(self) -> None:
        session = _make_session()
        self.assertEqual(session.allocate_tag(), 1)

    def test_increments_monotonically(self) -> None:
        session = _make_session()
        tags = [session.allocate_tag() for _ in range(5)]
        self.assertEqual(tags, [1, 2, 3, 4, 5])

    def test_returns_int(self) -> None:
        session = _make_session()
        self.assertIsInstance(session.allocate_tag(), int)

    def test_independent_sessions_do_not_share_counter(self) -> None:
        a = _make_session()
        b = _make_session()
        a.allocate_tag()
        a.allocate_tag()
        self.assertEqual(b.allocate_tag(), 1)


class ResetRuntimeStateTests(unittest.TestCase):

    def setUp(self) -> None:
        self._session = _make_session()
        self._session.control = MagicMock()
        self._session.bankd = MagicMock()
        self._session.control_stage = "active"
        self._session.atr_sent = True

    def test_control_cleared(self) -> None:
        self._session.reset_runtime_state()
        self.assertIsNone(self._session.control)

    def test_bankd_cleared(self) -> None:
        self._session.reset_runtime_state()
        self.assertIsNone(self._session.bankd)

    def test_control_stage_reset_to_idle(self) -> None:
        self._session.reset_runtime_state()
        self.assertEqual(self._session.control_stage, "idle")

    def test_atr_sent_cleared(self) -> None:
        self._session.reset_runtime_state()
        self.assertFalse(self._session.atr_sent)

    def test_idempotent(self) -> None:
        self._session.reset_runtime_state()
        self._session.reset_runtime_state()
        self.assertIsNone(self._session.control)
        self.assertEqual(self._session.control_stage, "idle")


class ServerIdentityTests(unittest.TestCase):

    def test_returns_dict(self) -> None:
        session = _make_session()
        self.assertIsInstance(session.server_identity(), dict)

    def test_contains_name(self) -> None:
        session = _make_session(bridge_name="test-bridge")
        identity = session.server_identity()
        import json
        serialised = json.dumps(identity)
        self.assertIn("test-bridge", serialised)

    def test_result_is_not_empty(self) -> None:
        session = _make_session()
        self.assertGreater(len(session.server_identity()), 0)

    def test_separate_calls_return_equal_dicts(self) -> None:
        session = _make_session()
        self.assertEqual(session.server_identity(), session.server_identity())


class BankdIdentityTests(unittest.TestCase):

    def test_returns_dict(self) -> None:
        session = _make_session()
        self.assertIsInstance(session.bankd_identity(), dict)

    def test_contains_bankd_suffix(self) -> None:
        session = _make_session(bridge_name="my-bridge")
        import json
        serialised = json.dumps(session.bankd_identity())
        self.assertIn("bankd", serialised)

    def test_differs_from_server_identity(self) -> None:
        session = _make_session()
        self.assertNotEqual(session.server_identity(), session.bankd_identity())

    def test_result_is_not_empty(self) -> None:
        session = _make_session()
        self.assertGreater(len(session.bankd_identity()), 0)


if __name__ == "__main__":
    unittest.main()
