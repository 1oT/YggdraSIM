# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""YggdraCore Command Center action conformance tests.

Locks the six Phase-1c actions registered by
``yggdrasim_common.gui_server.actions.yggdracore``:

* ``yggdracore.subscription_upsert`` validates inputs and pushes the
  record into the in-process :class:`SubscriptionStore`.
* ``yggdracore.subscription_list`` redacts secret material.
* ``yggdracore.subscription_delete`` and ``subscription_clear``
  prune state correctly.
* ``yggdracore.status`` returns a stable diagnostics shape.
* ``yggdracore.clear_auth_contexts`` empties the stub AUSF.

The dispatchers operate on the shared default singletons; each test
resets state through :func:`reset_default_subscription_store` /
:func:`reset_default_ausf_stub` so ordering cannot leak.
"""

from __future__ import annotations

import unittest

from Tools.YggdraCore.ausf_stub import (
    get_default_ausf_stub,
    reset_default_ausf_stub,
)
from Tools.YggdraCore.subscription_store import (
    get_default_subscription_store,
    reset_default_subscription_store,
)
from yggdrasim_common.gui_server.actions.registry import (
    ActionContext,
    get_registry,
)
import yggdrasim_common.gui_server.actions.yggdracore  # noqa: F401  -- registers specs


_K_HEX = "465B5CE8B199B49FAA5F0A2EE238A6BC"
_OPC_HEX = "CD63CB71954A9F4E48A5994E37A02BAF"
_SUPI = "imsi-001010000000001"


def _ctx() -> ActionContext:
    return ActionContext(session_id=None, extras={})


class ActionRegistrationTests(unittest.TestCase):
    def test_all_phase1c_specs_registered(self) -> None:
        registry = get_registry()
        expected = {
            "yggdracore.subscription_upsert",
            "yggdracore.subscription_list",
            "yggdracore.subscription_delete",
            "yggdracore.subscription_clear",
            "yggdracore.status",
            "yggdracore.clear_auth_contexts",
        }
        registered = {spec.id for spec in registry.all() if spec.id.startswith("yggdracore.")}
        self.assertTrue(expected.issubset(registered))

    def test_specs_share_subsystem_label(self) -> None:
        registry = get_registry()
        for spec_id in (
            "yggdracore.subscription_upsert",
            "yggdracore.subscription_list",
            "yggdracore.status",
        ):
            self.assertEqual(registry.get(spec_id).subsystem, "YggdraCore")


class SubscriptionDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_default_subscription_store()
        reset_default_ausf_stub()
        from yggdrasim_common.gui_server.actions.yggdracore import (
            _dispatch_clear_auth_contexts,
            _dispatch_status,
            _dispatch_subscription_clear,
            _dispatch_subscription_delete,
            _dispatch_subscription_list,
            _dispatch_subscription_upsert,
        )

        self.upsert = _dispatch_subscription_upsert
        self.list_subs = _dispatch_subscription_list
        self.delete = _dispatch_subscription_delete
        self.clear = _dispatch_subscription_clear
        self.status = _dispatch_status
        self.clear_contexts = _dispatch_clear_auth_contexts

    def tearDown(self) -> None:
        reset_default_subscription_store()
        reset_default_ausf_stub()

    def test_upsert_then_list_round_trip(self) -> None:
        result = self.upsert(_ctx(), supi=_SUPI, k=_K_HEX, opc=_OPC_HEX)
        self.assertEqual(result["subscription"]["supi"], _SUPI)
        listing = self.list_subs(_ctx())
        self.assertEqual(listing["count"], 1)
        view = listing["subscriptions"][0]
        self.assertEqual(view["supi"], _SUPI)
        # Secret material must not leak through the public view.
        self.assertNotIn("k", view)
        self.assertNotIn("opc", view)

    def test_upsert_rejects_short_k(self) -> None:
        with self.assertRaises(ValueError):
            self.upsert(_ctx(), supi=_SUPI, k="00" * 8, opc=_OPC_HEX)

    def test_delete_returns_removed_flag(self) -> None:
        self.upsert(_ctx(), supi=_SUPI, k=_K_HEX, opc=_OPC_HEX)
        result = self.delete(_ctx(), supi=_SUPI)
        self.assertTrue(result["removed"])
        result_again = self.delete(_ctx(), supi=_SUPI)
        self.assertFalse(result_again["removed"])

    def test_clear_returns_count(self) -> None:
        self.upsert(_ctx(), supi=_SUPI, k=_K_HEX, opc=_OPC_HEX)
        result = self.clear(_ctx())
        self.assertEqual(result["cleared_subscriptions"], 1)
        self.assertEqual(get_default_subscription_store().list(), [])

    def test_status_includes_endpoint_surface(self) -> None:
        result = self.status(_ctx())
        self.assertIn("subscriptions", result)
        self.assertIn("aanf_entries", result)
        self.assertIn("in_flight_auth_contexts", result)
        self.assertIn("http_endpoints", result)
        self.assertIn("launcher_hint", result)

    def test_clear_auth_contexts_returns_count(self) -> None:
        # Manually inject a context by running the AUSF.
        self.upsert(_ctx(), supi=_SUPI, k=_K_HEX, opc=_OPC_HEX)
        get_default_ausf_stub().start_ue_authentication(
            supi=_SUPI,
            sn_name="5G:mnc001.mcc001.3gppnetwork.org",
        )
        result = self.clear_contexts(_ctx())
        self.assertEqual(result["cleared_contexts"], 1)


if __name__ == "__main__":
    unittest.main()
