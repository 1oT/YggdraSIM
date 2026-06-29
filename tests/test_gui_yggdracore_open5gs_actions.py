# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""GUI Open5GS action conformance tests (Phase 2).

Locks the six BYO Open5GS actions registered by
``yggdrasim_common.gui_server.actions.yggdracore``:

* ``yggdracore.open5gs_status`` -- detector snapshot dispatch
* ``yggdracore.open5gs_provision`` -- single subscriber upsert
* ``yggdracore.open5gs_provision_all`` -- batch upsert
* ``yggdracore.open5gs_read`` -- sanitised single-doc read
* ``yggdracore.open5gs_remove`` -- single-doc delete
* ``yggdracore.open5gs_purge_yggdrasim`` -- bulk YggdraSIM-tagged delete

Tests inject a hand-rolled fake repository (matching the same
collection contract exercised by ``test_yggdracore_open5gs_bridge.py``)
through :func:`set_open5gs_repository_for_testing` so the dispatchers
exercise their real input-coercion paths without touching MongoDB or
``pymongo``.
"""

from __future__ import annotations

import unittest
from typing import Any, Optional

from Tools.YggdraCore.open5gs_bridge import (
    Open5gsSubscriberRepository,
    PROVENANCE_TAG_FIELD,
)
from Tools.YggdraCore.subscription_store import (
    get_default_subscription_store,
    reset_default_subscription_store,
)
from yggdrasim_common.gui_server.actions.registry import (
    ActionContext,
    get_registry,
)
import yggdrasim_common.gui_server.actions.yggdracore as yggdracore_actions  # noqa: F401


_K_HEX = "465B5CE8B199B49FAA5F0A2EE238A6BC"
_OPC_HEX = "CD63CB71954A9F4E48A5994E37A02BAF"
_SUPI = "imsi-001010000000001"
_IMSI = "001010000000001"


def _ctx() -> ActionContext:
    return ActionContext(session_id=None, extras={})


# ----------------------------------------------------------------------
# Same fakes as test_yggdracore_open5gs_bridge.py, kept local so the
# test files stay independently runnable.
# ----------------------------------------------------------------------


class _FakeUpdateResult:
    def __init__(self, matched_count: int, upserted_id: Optional[Any]) -> None:
        self.matched_count = matched_count
        self.upserted_id = upserted_id


class _FakeDeleteResult:
    def __init__(self, deleted_count: int) -> None:
        self.deleted_count = deleted_count


class _FakeCollection:
    def __init__(self) -> None:
        self._docs: dict[str, dict[str, Any]] = {}

    def find_one(self, query: dict[str, Any]) -> Optional[dict[str, Any]]:
        for doc in self._docs.values():
            if self._match(doc, query):
                return dict(doc)
        return None

    def replace_one(
        self,
        query: dict[str, Any],
        document: dict[str, Any],
        *,
        upsert: bool = False,
    ) -> _FakeUpdateResult:
        imsi = str(query.get("imsi") or "")
        if imsi in self._docs:
            self._docs[imsi] = dict(document)
            return _FakeUpdateResult(matched_count=1, upserted_id=None)
        if not upsert:
            return _FakeUpdateResult(matched_count=0, upserted_id=None)
        self._docs[imsi] = dict(document)
        return _FakeUpdateResult(matched_count=0, upserted_id=imsi)

    def find(self, query: Optional[dict[str, Any]] = None):
        query = dict(query or {})
        return [dict(doc) for doc in self._docs.values() if self._match(doc, query)]

    def delete_one(self, query: dict[str, Any]) -> _FakeDeleteResult:
        for imsi, doc in list(self._docs.items()):
            if self._match(doc, query):
                self._docs.pop(imsi)
                return _FakeDeleteResult(deleted_count=1)
        return _FakeDeleteResult(deleted_count=0)

    def delete_many(self, query: dict[str, Any]) -> _FakeDeleteResult:
        keep: dict[str, dict[str, Any]] = {}
        deleted = 0
        for imsi, doc in self._docs.items():
            if self._match(doc, query):
                deleted += 1
            else:
                keep[imsi] = doc
        self._docs = keep
        return _FakeDeleteResult(deleted_count=deleted)

    def _match(self, document: dict[str, Any], query: dict[str, Any]) -> bool:
        for key, expected in query.items():
            value = document.get(key)
            if isinstance(expected, dict) and "$exists" in expected:
                if expected["$exists"] != (key in document):
                    return False
            elif value != expected:
                return False
        return True


class _FakeDetector:
    def __init__(self, snapshot: Any) -> None:
        self._snapshot = snapshot

    def detect(self) -> Any:
        return self._snapshot


class _FakeDetection:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------


class ActionRegistrationTests(unittest.TestCase):
    def test_all_open5gs_specs_registered(self) -> None:
        registry = get_registry()
        expected = {
            "yggdracore.open5gs_status",
            "yggdracore.open5gs_provision",
            "yggdracore.open5gs_provision_all",
            "yggdracore.open5gs_read",
            "yggdracore.open5gs_remove",
            "yggdracore.open5gs_purge_yggdrasim",
        }
        registered = {spec.id for spec in registry.all() if spec.id.startswith("yggdracore.open5gs_")}
        self.assertEqual(expected, registered)

    def test_open5gs_specs_carry_byo_tag(self) -> None:
        registry = get_registry()
        for spec_id in (
            "yggdracore.open5gs_status",
            "yggdracore.open5gs_provision",
            "yggdracore.open5gs_purge_yggdrasim",
        ):
            self.assertIn("byo", registry.get(spec_id).tags)


class StatusDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        snapshot = _FakeDetection(
            {
                "binaries_present": ["open5gs-amfd"],
                "binaries_missing": ["open5gs-ausfd"],
                "binary_paths": {"open5gs-amfd": "/usr/bin/open5gs-amfd"},
                "mongo_uri": "mongodb://127.0.0.1:27017",
                "mongo_reachable": True,
                "mongo_error": None,
                "pymongo_available": True,
                "has_complete_5g_sa": False,
            }
        )
        yggdracore_actions.set_open5gs_detector_for_testing(_FakeDetector(snapshot))

    def tearDown(self) -> None:
        yggdracore_actions.set_open5gs_detector_for_testing(None)

    def test_status_returns_snapshot_with_mode(self) -> None:
        result = yggdracore_actions._dispatch_open5gs_status(_ctx())
        self.assertEqual(result["binaries_present"], ["open5gs-amfd"])
        self.assertIn("mode", result)
        self.assertIn("mongo_uri", result)


class ProvisioningDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_default_subscription_store()
        self.collection = _FakeCollection()
        self.repository = Open5gsSubscriberRepository(collection=self.collection)
        yggdracore_actions.set_open5gs_repository_for_testing(self.repository)
        store = get_default_subscription_store()
        store.upsert(supi=_SUPI, k=bytes.fromhex(_K_HEX), opc=bytes.fromhex(_OPC_HEX))

    def tearDown(self) -> None:
        yggdracore_actions.set_open5gs_repository_for_testing(None)
        reset_default_subscription_store()

    def test_provision_dispatches_to_repository(self) -> None:
        result = yggdracore_actions._dispatch_open5gs_provision(_ctx(), supi=_SUPI)
        self.assertEqual(result["imsi"], _IMSI)
        self.assertTrue(result["upserted"])
        self.assertIn("mode", result)
        self.assertIn(_IMSI, self.collection._docs)

    def test_provision_unknown_supi_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            yggdracore_actions._dispatch_open5gs_provision(_ctx(), supi="imsi-999999999999999")

    def test_provision_supports_custom_apn_and_sst(self) -> None:
        yggdracore_actions._dispatch_open5gs_provision(
            _ctx(),
            supi=_SUPI,
            apn="ims",
            sst=2,
            sd="abcdef",
        )
        slice_doc = self.collection._docs[_IMSI]["slice"][0]
        self.assertEqual(slice_doc["sst"], 2)
        self.assertEqual(slice_doc["sd"], "abcdef")
        self.assertEqual(slice_doc["session"][0]["name"], "ims")

    def test_provision_all_pushes_every_record(self) -> None:
        store = get_default_subscription_store()
        store.upsert(
            supi="imsi-001010000000002",
            k=bytes.fromhex(_K_HEX),
            opc=bytes.fromhex(_OPC_HEX),
            akma_enabled=False,
        )
        result = yggdracore_actions._dispatch_open5gs_provision_all(_ctx())
        self.assertEqual(result["count"], 2)
        self.assertEqual(len(self.collection._docs), 2)

    def test_provision_all_only_akma_filters(self) -> None:
        store = get_default_subscription_store()
        store.upsert(
            supi="imsi-001010000000002",
            k=bytes.fromhex(_K_HEX),
            opc=bytes.fromhex(_OPC_HEX),
            akma_enabled=False,
        )
        result = yggdracore_actions._dispatch_open5gs_provision_all(
            _ctx(),
            only_akma_enabled=True,
        )
        self.assertEqual(result["count"], 1)


class ReadRemovePurgeDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_default_subscription_store()
        self.collection = _FakeCollection()
        self.repository = Open5gsSubscriberRepository(collection=self.collection)
        yggdracore_actions.set_open5gs_repository_for_testing(self.repository)
        store = get_default_subscription_store()
        store.upsert(supi=_SUPI, k=bytes.fromhex(_K_HEX), opc=bytes.fromhex(_OPC_HEX))
        yggdracore_actions._dispatch_open5gs_provision(_ctx(), supi=_SUPI)

    def tearDown(self) -> None:
        yggdracore_actions.set_open5gs_repository_for_testing(None)
        reset_default_subscription_store()

    def test_read_returns_sanitised_doc(self) -> None:
        result = yggdracore_actions._dispatch_open5gs_read(_ctx(), imsi=_IMSI)
        self.assertTrue(result["found"])
        sec = result["subscriber"]["security"]
        # Fingerprint format documented in the bridge module.
        self.assertRegex(sec["k"], r"\(16 bytes\)$")
        self.assertRegex(sec["opc"], r"\(16 bytes\)$")

    def test_read_unknown_imsi_returns_found_false(self) -> None:
        result = yggdracore_actions._dispatch_open5gs_read(_ctx(), imsi="999999999999999")
        self.assertFalse(result["found"])
        self.assertIsNone(result["subscriber"])

    def test_remove_returns_removed_flag(self) -> None:
        first = yggdracore_actions._dispatch_open5gs_remove(_ctx(), imsi=_IMSI)
        self.assertTrue(first["removed"])
        again = yggdracore_actions._dispatch_open5gs_remove(_ctx(), imsi=_IMSI)
        self.assertFalse(again["removed"])

    def test_purge_yggdrasim_only_removes_tagged(self) -> None:
        # Inject an externally-managed (untagged) doc.
        self.collection._docs["001010000000099"] = {
            "imsi": "001010000000099",
            "security": {"k": "00" * 16, "opc": "00" * 16, "amf": "8000", "op": None},
        }
        result = yggdracore_actions._dispatch_open5gs_purge_yggdrasim(_ctx())
        self.assertEqual(result["purged"], 1)
        self.assertIn("001010000000099", self.collection._docs)
        # Sanity: provenance tag is what kept the externally-managed doc.
        self.assertNotIn(
            PROVENANCE_TAG_FIELD,
            self.collection._docs["001010000000099"],
        )


if __name__ == "__main__":
    unittest.main()
