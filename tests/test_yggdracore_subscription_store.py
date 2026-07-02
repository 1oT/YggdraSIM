# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the YggdraCore subscription store (Tools/YggdraCore/subscription_store.py).

Locks the CRUD surface and the SQN reservation arithmetic the stub
AUSF depends on:

* upsert / get / delete / list / clear round-trips.
* SQN increments monotonically and persists across reads.
* Overflow at 2^48 is rejected loudly.
* Field validation rejects malformed K / OPc / SUPI / MCC / MNC / RID.
* ``serving_network_name`` and ``akma_realm`` match the canonical
  TS 33.501 / TS 23.003 formatters.
"""

from __future__ import annotations

import unittest

from Tools.YggdraCore.subscription_store import (
    SubscriptionStore,
    SubscriptionStoreError,
)


_SUPI = "imsi-001010000000001"
_K = bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC")
_OPC = bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF")


class CrudTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SubscriptionStore()

    def test_upsert_then_get(self) -> None:
        record = self.store.upsert(supi=_SUPI, k=_K, opc=_OPC)
        self.assertEqual(self.store.get(_SUPI), record)

    def test_upsert_overwrites_in_place(self) -> None:
        self.store.upsert(supi=_SUPI, k=_K, opc=_OPC)
        new_opc = bytes(b ^ 0xFF for b in _OPC)
        self.store.upsert(supi=_SUPI, k=_K, opc=new_opc)
        self.assertEqual(self.store.get(_SUPI).opc, new_opc)

    def test_get_unknown_raises(self) -> None:
        with self.assertRaises(SubscriptionStoreError):
            self.store.get("imsi-999999999999999")

    def test_delete_returns_true_when_present(self) -> None:
        self.store.upsert(supi=_SUPI, k=_K, opc=_OPC)
        self.assertTrue(self.store.delete(_SUPI))
        self.assertFalse(self.store.delete(_SUPI))

    def test_list_is_sorted(self) -> None:
        for index in range(3):
            self.store.upsert(
                supi=f"imsi-00101000000000{index}",
                k=_K,
                opc=_OPC,
            )
        records = self.store.list()
        self.assertEqual([r.supi for r in records], sorted([r.supi for r in records]))

    def test_clear_returns_count(self) -> None:
        self.store.upsert(supi=_SUPI, k=_K, opc=_OPC)
        self.store.upsert(supi="imsi-001010000000002", k=_K, opc=_OPC)
        self.assertEqual(self.store.clear(), 2)
        self.assertEqual(self.store.list(), [])


class SqnReservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SubscriptionStore()
        self.store.upsert(supi=_SUPI, k=_K, opc=_OPC)

    def test_reserve_increments_by_one_by_default(self) -> None:
        first = self.store.reserve_next_sqn(_SUPI)
        second = self.store.reserve_next_sqn(_SUPI)
        self.assertEqual(int.from_bytes(second, "big") - int.from_bytes(first, "big"), 1)

    def test_reserve_persists_across_get(self) -> None:
        reserved = self.store.reserve_next_sqn(_SUPI)
        self.assertEqual(self.store.get(_SUPI).sqn, reserved)

    def test_reserve_supports_custom_increment(self) -> None:
        first = self.store.reserve_next_sqn(_SUPI, increment=32)
        second = self.store.reserve_next_sqn(_SUPI, increment=32)
        delta = int.from_bytes(second, "big") - int.from_bytes(first, "big")
        self.assertEqual(delta, 32)

    def test_reserve_rejects_non_positive_increment(self) -> None:
        with self.assertRaises(ValueError):
            self.store.reserve_next_sqn(_SUPI, increment=0)

    def test_reserve_overflow_is_loud(self) -> None:
        max_record_sqn = (1 << 48) - 1
        self.store.upsert(
            supi=_SUPI,
            k=_K,
            opc=_OPC,
            sqn=(max_record_sqn - 1).to_bytes(6, "big"),
        )
        # First call lands exactly at 2^48-1 -- still fine.
        self.store.reserve_next_sqn(_SUPI)
        with self.assertRaises(SubscriptionStoreError):
            self.store.reserve_next_sqn(_SUPI)

    def test_reserve_unknown_supi_raises(self) -> None:
        with self.assertRaises(SubscriptionStoreError):
            self.store.reserve_next_sqn("imsi-000000000000000")


class FieldValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SubscriptionStore()

    def test_rejects_short_k(self) -> None:
        with self.assertRaises(ValueError):
            self.store.upsert(supi=_SUPI, k=b"\x00" * 8, opc=_OPC)

    def test_rejects_short_opc(self) -> None:
        with self.assertRaises(ValueError):
            self.store.upsert(supi=_SUPI, k=_K, opc=b"\x00" * 8)

    def test_rejects_wrong_amf_length(self) -> None:
        with self.assertRaises(ValueError):
            self.store.upsert(supi=_SUPI, k=_K, opc=_OPC, amf=b"\x00")

    def test_rejects_wrong_sqn_length(self) -> None:
        with self.assertRaises(ValueError):
            self.store.upsert(supi=_SUPI, k=_K, opc=_OPC, sqn=b"\x00" * 4)

    def test_rejects_short_mcc(self) -> None:
        with self.assertRaises(ValueError):
            self.store.upsert(supi=_SUPI, k=_K, opc=_OPC, mcc="12")

    def test_rejects_invalid_rid(self) -> None:
        with self.assertRaises(ValueError):
            self.store.upsert(supi=_SUPI, k=_K, opc=_OPC, routing_indicator="abcd")

    def test_rejects_overlong_rid(self) -> None:
        with self.assertRaises(ValueError):
            self.store.upsert(supi=_SUPI, k=_K, opc=_OPC, routing_indicator="12345")


class FormattingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SubscriptionStore()
        self.record = self.store.upsert(
            supi=_SUPI,
            k=_K,
            opc=_OPC,
            mcc="001",
            mnc="01",
        )

    def test_serving_network_name_matches_ts_33_501(self) -> None:
        self.assertEqual(
            self.record.serving_network_name(),
            "5G:mnc001.mcc001.3gppnetwork.org",
        )

    def test_akma_realm_matches_ts_23_003(self) -> None:
        self.assertEqual(
            self.record.akma_realm(),
            "akma.5gc.mnc001.mcc001.3gppnetwork.org",
        )

    def test_public_view_omits_secret_material(self) -> None:
        view = self.record.public_view()
        self.assertNotIn("k", view)
        self.assertNotIn("opc", view)
        self.assertIn("supi", view)
        self.assertIn("akma_enabled", view)


if __name__ == "__main__":
    unittest.main()
