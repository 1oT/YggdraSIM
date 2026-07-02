# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SIMCARD/quirks.py QuirkRegistry public methods."""

from __future__ import annotations

import unittest

from SIMCARD.quirks import QuirkRegistry
from SIMCARD.state import SimCardState


def _bare_state() -> SimCardState:
    return SimCardState.__new__(SimCardState)


class AddBeforeApduTests(unittest.TestCase):

    def test_hook_appended(self) -> None:
        registry = QuirkRegistry()
        hook = lambda apdu, state: None
        registry.add_before_apdu(hook)
        self.assertIn(hook, registry.before_apdu_hooks)

    def test_multiple_hooks_ordered(self) -> None:
        registry = QuirkRegistry()
        h1 = lambda apdu, state: None
        h2 = lambda apdu, state: None
        registry.add_before_apdu(h1)
        registry.add_before_apdu(h2)
        self.assertEqual(registry.before_apdu_hooks, [h1, h2])


class AddAfterApduTests(unittest.TestCase):

    def test_hook_appended(self) -> None:
        registry = QuirkRegistry()
        hook = lambda apdu, result, state: None
        registry.add_after_apdu(hook)
        self.assertIn(hook, registry.after_apdu_hooks)


class AddOnResetTests(unittest.TestCase):

    def test_hook_appended(self) -> None:
        registry = QuirkRegistry()
        hook = lambda state: None
        registry.add_on_reset(hook)
        self.assertIn(hook, registry.on_reset_hooks)


class AddStateHookTests(unittest.TestCase):

    def test_hook_appended(self) -> None:
        registry = QuirkRegistry()
        hook = lambda state: None
        registry.add_state_hook(hook)
        self.assertIn(hook, registry.state_hooks)


class ApplyStateHooksTests(unittest.TestCase):

    def test_all_hooks_called_in_order(self) -> None:
        call_log: list[int] = []
        registry = QuirkRegistry()
        registry.add_state_hook(lambda state: call_log.append(1))
        registry.add_state_hook(lambda state: call_log.append(2))
        state = _bare_state()
        registry.apply_state_hooks(state)
        self.assertEqual(call_log, [1, 2])

    def test_no_hooks_runs_silently(self) -> None:
        registry = QuirkRegistry()
        state = _bare_state()
        registry.apply_state_hooks(state)  # must not raise

    def test_empty_registry_all_lists_empty(self) -> None:
        registry = QuirkRegistry()
        self.assertEqual(registry.before_apdu_hooks, [])
        self.assertEqual(registry.after_apdu_hooks, [])
        self.assertEqual(registry.on_reset_hooks, [])
        self.assertEqual(registry.state_hooks, [])


if __name__ == "__main__":
    unittest.main()
