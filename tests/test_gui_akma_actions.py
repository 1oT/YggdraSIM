# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""AKMA Command Center action conformance tests.

Locks the five Phase-1b actions registered by
``yggdrasim_common.gui_server.actions.akma``:

* ``akma.derive_keys`` produces KAKMA / A-TID / A-KID matching
  :mod:`SIMCARD.akma` and adds KAF when AF_ID is supplied.
* ``akma.aanf_register`` populates the in-process AAnF stub with a
  byte-correct entry.
* ``akma.aanf_list`` mirrors the live snapshot.
* ``akma.af_session_establish`` derives a KAF that matches
  :func:`SIMCARD.akma.derive_k_af` byte-for-byte.
* ``akma.aanf_clear`` wipes state.

Each test isolates AAnF state via a fresh global stub reset so
test ordering cannot leak.
"""

from __future__ import annotations

import unittest

from SIMCARD.akma import derive_a_tid, derive_k_af, derive_k_akma, format_a_kid
from Tools.YggdraCore.aanf_stub import (
    get_default_aanf_stub,
    reset_default_aanf_stub,
)
from yggdrasim_common.gui_server.actions import (  # noqa: F401  -- import for ActionContext shim
    registry as actions_registry_module,
)
from yggdrasim_common.gui_server.actions.registry import (
    ActionContext,
    get_registry,
)
import yggdrasim_common.gui_server.actions.akma  # noqa: F401  -- triggers spec registration


_KAUSF_HEX = "A" * 64  # 32-byte KAUSF: simple, deterministic, non-secret.
_KAUSF = bytes.fromhex(_KAUSF_HEX)
_SUPI = "imsi-001010000000001"
_RID = "0"
_MCC = "001"
_MNC = "01"
_AF_ID = "af.example.com\x01\x00\x01\x00"


def _ctx() -> ActionContext:
    return ActionContext(session_id=None, extras={})


class ActionSpecRegistrationTests(unittest.TestCase):
    def test_all_phase1b_actions_registered(self) -> None:
        registry = get_registry()
        expected = {
            "akma.derive_keys",
            "akma.aanf_register",
            "akma.aanf_list",
            "akma.af_session_establish",
            "akma.aanf_clear",
        }
        registered = {spec.id for spec in registry.all() if spec.id.startswith("akma.")}
        self.assertTrue(expected.issubset(registered))

    def test_actions_share_subsystem_label(self) -> None:
        registry = get_registry()
        for action_id in ("akma.derive_keys", "akma.aanf_register", "akma.af_session_establish"):
            spec = registry.get(action_id)
            self.assertEqual(spec.subsystem, "AKMA")
            self.assertEqual(spec.output_kind, "json")
            self.assertFalse(spec.requires_card)


class DeriveKeysDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions.akma import _dispatch_derive_keys

        self.dispatcher = _dispatch_derive_keys

    def test_kakma_matches_simcard_module(self) -> None:
        result = self.dispatcher(
            _ctx(),
            k_ausf=_KAUSF_HEX,
            supi=_SUPI,
            routing_indicator=_RID,
            mcc=_MCC,
            mnc=_MNC,
        )
        expected_kakma = derive_k_akma(_KAUSF, _SUPI).hex().upper()
        self.assertEqual(result["mode"], "stub")
        self.assertEqual(result["kakma_hex"], expected_kakma)

    def test_a_kid_matches_format_helper(self) -> None:
        result = self.dispatcher(
            _ctx(),
            k_ausf=_KAUSF_HEX,
            supi=_SUPI,
            routing_indicator=_RID,
            mcc=_MCC,
            mnc=_MNC,
        )
        a_tid = derive_a_tid(_KAUSF, _SUPI)
        expected_a_kid = format_a_kid(
            a_tid,
            routing_indicator=_RID,
            mcc=_MCC,
            mnc=_MNC,
        )
        self.assertEqual(result["a_kid"], expected_a_kid)
        self.assertEqual(result["realm"], "akma.5gc.mnc001.mcc001.3gppnetwork.org")

    def test_optional_af_id_produces_k_af(self) -> None:
        result = self.dispatcher(
            _ctx(),
            k_ausf=_KAUSF_HEX,
            supi=_SUPI,
            routing_indicator=_RID,
            mcc=_MCC,
            mnc=_MNC,
            af_id=_AF_ID,
        )
        kakma = derive_k_akma(_KAUSF, _SUPI)
        expected_k_af = derive_k_af(kakma, _AF_ID).hex().upper()
        self.assertEqual(result["k_af_hex"], expected_k_af)

    def test_missing_af_id_omits_k_af(self) -> None:
        result = self.dispatcher(
            _ctx(),
            k_ausf=_KAUSF_HEX,
            supi=_SUPI,
            routing_indicator=_RID,
            mcc=_MCC,
            mnc=_MNC,
        )
        self.assertNotIn("k_af_hex", result)

    def test_invalid_kausf_length_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.dispatcher(
                _ctx(),
                k_ausf="AA" * 16,
                supi=_SUPI,
                routing_indicator=_RID,
                mcc=_MCC,
                mnc=_MNC,
            )

    def test_invalid_encoding_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.dispatcher(
                _ctx(),
                k_ausf=_KAUSF_HEX,
                supi=_SUPI,
                routing_indicator=_RID,
                mcc=_MCC,
                mnc=_MNC,
                encoding="ascii85",
            )


class AAnFRegisterAndLookupDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_default_aanf_stub()
        from yggdrasim_common.gui_server.actions.akma import (
            _dispatch_aanf_clear,
            _dispatch_aanf_list,
            _dispatch_aanf_register,
            _dispatch_af_session_establish,
            _dispatch_derive_keys,
        )

        self.derive = _dispatch_derive_keys
        self.register = _dispatch_aanf_register
        self.list_action = _dispatch_aanf_list
        self.session = _dispatch_af_session_establish
        self.clear = _dispatch_aanf_clear

        derived = self.derive(
            _ctx(),
            k_ausf=_KAUSF_HEX,
            supi=_SUPI,
            routing_indicator=_RID,
            mcc=_MCC,
            mnc=_MNC,
        )
        self.a_kid = derived["a_kid"]
        self.kakma_hex = derived["kakma_hex"]

    def tearDown(self) -> None:
        reset_default_aanf_stub()

    def test_register_then_list_shows_entry(self) -> None:
        self.register(
            _ctx(),
            supi=_SUPI,
            a_kid=self.a_kid,
            k_akma=self.kakma_hex,
        )
        listing = self.list_action(_ctx())
        self.assertEqual(listing["count"], 1)
        self.assertEqual(listing["entries"][0]["a_kid"], self.a_kid)
        self.assertEqual(listing["entries"][0]["supi"], _SUPI)

    def test_session_establish_returns_matching_k_af(self) -> None:
        self.register(
            _ctx(),
            supi=_SUPI,
            a_kid=self.a_kid,
            k_akma=self.kakma_hex,
        )
        result = self.session(
            _ctx(),
            a_kid=self.a_kid,
            af_id=_AF_ID,
        )
        kakma = bytes.fromhex(self.kakma_hex)
        expected_k_af = derive_k_af(kakma, _AF_ID).hex().upper()
        self.assertEqual(result["k_af_hex"], expected_k_af)
        self.assertEqual(result["a_kid"], self.a_kid)
        self.assertEqual(result["af_id"], _AF_ID)

    def test_session_establish_unknown_a_kid_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.session(
                _ctx(),
                a_kid="0.UNKNOWN@akma.5gc.mnc001.mcc001.3gppnetwork.org",
                af_id=_AF_ID,
            )

    def test_clear_drops_all_entries(self) -> None:
        self.register(
            _ctx(),
            supi=_SUPI,
            a_kid=self.a_kid,
            k_akma=self.kakma_hex,
        )
        result = self.clear(_ctx())
        self.assertEqual(result["cleared_entries"], 1)
        self.assertEqual(get_default_aanf_stub().snapshot(), [])


if __name__ == "__main__":
    unittest.main()
