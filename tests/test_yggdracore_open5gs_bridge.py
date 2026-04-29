"""BYO Open5GS bridge tests (Tools/YggdraCore/open5gs_bridge.py).

Locks the provisioning surface using a hand-rolled fake of the
``pymongo.collection.Collection`` interface. The fake matches only
the calls the bridge actually makes -- ``find_one``, ``replace_one``
(with ``upsert=True``), ``find``, ``delete_one``, ``delete_many`` --
so the tests document the contract precisely without pulling
``pymongo`` or ``mongomock`` into CI.

Coverage:

* :class:`Open5gsDetector` -- binary discovery (PATH lookup
  injected) and MongoDB probe gating (works without pymongo).
* :class:`Open5gsSubscriberRepository` -- provisioning produces an
  Open5GS-shaped document with the expected security / slice /
  AMBR layout and the ``_yggdrasim_provisioned`` provenance tag.
* :meth:`read` redacts K / OPc to a fingerprint.
* :meth:`remove` and :meth:`purge_yggdrasim` remove only what they
  should.
"""

from __future__ import annotations

import re
import unittest
from typing import Any, Optional

from Tools.YggdraCore.open5gs_bridge import (
    OPEN5GS_5G_SA_BINARIES,
    Open5gsBridgeConfig,
    Open5gsBridgeError,
    Open5gsDetector,
    Open5gsSubscriberRepository,
    PROVENANCE_SUPI_FIELD,
    PROVENANCE_TAG_FIELD,
    provision_default_store,
)
from Tools.YggdraCore.subscription_store import (
    SubscriptionStore,
    get_default_subscription_store,
    reset_default_subscription_store,
)


_K = bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC")
_OPC = bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF")
_SUPI = "imsi-001010000000001"


class _FakeUpdateResult:
    def __init__(self, matched_count: int, upserted_id: Optional[Any]) -> None:
        self.matched_count = matched_count
        self.upserted_id = upserted_id


class _FakeDeleteResult:
    def __init__(self, deleted_count: int) -> None:
        self.deleted_count = deleted_count


class _FakeCollection:
    """Minimal pymongo Collection mock keyed by IMSI."""

    def __init__(self) -> None:
        self._docs: dict[str, dict[str, Any]] = {}

    # -- pymongo-shaped surface used by the bridge --------------------

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


class DetectorTests(unittest.TestCase):
    def test_binary_paths_returned_when_all_present(self) -> None:
        which = lambda name: f"/usr/bin/{name}" if name in OPEN5GS_5G_SA_BINARIES else None
        detector = Open5gsDetector(which=which, mongo_probe=lambda uri: None)
        result = detector.detect()
        self.assertEqual(result.binaries_missing, ())
        self.assertEqual(len(result.binary_paths), len(OPEN5GS_5G_SA_BINARIES))
        self.assertTrue(result.has_complete_5g_sa)

    def test_partial_install_lists_missing_binaries(self) -> None:
        present = {"open5gs-amfd", "open5gs-ausfd"}
        which = lambda name: "/usr/bin/" + name if name in present else None
        detector = Open5gsDetector(which=which, mongo_probe=lambda uri: None)
        result = detector.detect()
        self.assertEqual(set(result.binaries_present), present)
        self.assertGreater(len(result.binaries_missing), 0)
        self.assertFalse(result.has_complete_5g_sa)

    def test_mongo_probe_failure_surfaces_error(self) -> None:
        def boom(uri: str) -> None:
            raise RuntimeError("connection refused")

        which = lambda name: None
        detector = Open5gsDetector(which=which, mongo_probe=boom)
        result = detector.detect()
        self.assertEqual(result.mongo_reachable, False)
        self.assertIn("connection refused", result.mongo_error or "")
        self.assertTrue(result.pymongo_available)

    def test_to_dict_is_json_friendly(self) -> None:
        which = lambda name: None
        detector = Open5gsDetector(which=which, mongo_probe=lambda uri: None)
        snapshot = detector.detect().to_dict()
        for key in (
            "binaries_present",
            "binaries_missing",
            "binary_paths",
            "mongo_uri",
            "mongo_reachable",
            "pymongo_available",
            "has_complete_5g_sa",
        ):
            self.assertIn(key, snapshot)


class ProvisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.collection = _FakeCollection()
        self.repository = Open5gsSubscriberRepository(collection=self.collection)
        self.store = SubscriptionStore()
        self.record = self.store.upsert(supi=_SUPI, k=_K, opc=_OPC)

    def test_provision_writes_open5gs_shape_document(self) -> None:
        result = self.repository.provision(self.record)
        self.assertEqual(result.imsi, "001010000000001")
        self.assertTrue(result.upserted)
        document = self.collection._docs["001010000000001"]
        self.assertEqual(document["imsi"], "001010000000001")
        self.assertEqual(document["security"]["k"], _K.hex().upper())
        self.assertEqual(document["security"]["opc"], _OPC.hex().upper())
        self.assertIsNone(document["security"]["op"])
        self.assertEqual(document["security"]["amf"], "8000")
        slice_doc = document["slice"][0]
        self.assertEqual(slice_doc["sst"], 1)
        self.assertEqual(slice_doc["default_indicator"], True)
        self.assertEqual(slice_doc["session"][0]["name"], "internet")
        self.assertEqual(slice_doc["session"][0]["type"], 3)
        self.assertEqual(document["ambr"]["downlink"]["value"], 1_000_000_000)
        self.assertEqual(document["schema_version"], 1)

    def test_provision_tags_provenance(self) -> None:
        self.repository.provision(self.record)
        document = self.collection._docs["001010000000001"]
        self.assertIn(PROVENANCE_TAG_FIELD, document)
        self.assertEqual(document[PROVENANCE_SUPI_FIELD], _SUPI)
        # Tag is an ISO-8601 UTC timestamp.
        self.assertRegex(
            document[PROVENANCE_TAG_FIELD],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
        )

    def test_provision_overwrites_existing_doc(self) -> None:
        self.repository.provision(self.record)
        # Re-upsert with a different OPc -- must update in place.
        new_opc = bytes(b ^ 0xFF for b in _OPC)
        self.store.upsert(supi=_SUPI, k=_K, opc=new_opc)
        record_v2 = self.store.get(_SUPI)
        result = self.repository.provision(record_v2)
        self.assertTrue(result.matched)
        self.assertFalse(result.upserted)
        self.assertEqual(
            self.collection._docs["001010000000001"]["security"]["opc"],
            new_opc.hex().upper(),
        )

    def test_provision_supports_custom_slice_sd(self) -> None:
        result = self.repository.provision(
            self.record,
            apn="ims",
            sst=2,
            sd="ABCDEF",
            session_type=1,
            qos_index=5,
        )
        slice_doc = self.collection._docs[result.imsi]["slice"][0]
        self.assertEqual(slice_doc["sst"], 2)
        self.assertEqual(slice_doc["sd"], "abcdef")
        self.assertEqual(slice_doc["session"][0]["name"], "ims")
        self.assertEqual(slice_doc["session"][0]["type"], 1)
        self.assertEqual(slice_doc["session"][0]["qos"]["index"], 5)

    def test_provision_rejects_nai_supi(self) -> None:
        record_nai = self.store.upsert(
            supi="nai-test@example.com",
            k=_K,
            opc=_OPC,
        )
        with self.assertRaises(Open5gsBridgeError):
            self.repository.provision(record_nai)

    def test_provision_rejects_invalid_session_type(self) -> None:
        with self.assertRaises(ValueError):
            self.repository.provision(self.record, session_type=99)


class ReadAndPurgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.collection = _FakeCollection()
        self.repository = Open5gsSubscriberRepository(collection=self.collection)
        self.store = SubscriptionStore()

    def _provision(self, supi: str) -> str:
        record = self.store.upsert(supi=supi, k=_K, opc=_OPC)
        return self.repository.provision(record).imsi

    def test_read_returns_sanitised_document(self) -> None:
        imsi = self._provision(_SUPI)
        sanitised = self.repository.read(imsi)
        self.assertIsNotNone(sanitised)
        # K / OPc are replaced by a fingerprint of the form "ABCD\u2026EFGH (16 bytes)".
        self.assertNotEqual(sanitised["security"]["k"], _K.hex().upper())
        self.assertRegex(sanitised["security"]["k"], r"\(16 bytes\)$")
        self.assertRegex(sanitised["security"]["opc"], r"\(16 bytes\)$")

    def test_read_unknown_imsi_returns_none(self) -> None:
        self.assertIsNone(self.repository.read("999999999999999"))

    def test_remove_returns_true_when_present(self) -> None:
        self._provision(_SUPI)
        self.assertTrue(self.repository.remove(_SUPI))
        self.assertFalse(self.repository.remove(_SUPI))

    def test_purge_yggdrasim_removes_only_tagged_docs(self) -> None:
        # Provision two via YggdraSIM
        imsi_a = self._provision("imsi-001010000000001")
        imsi_b = self._provision("imsi-001010000000002")
        # Inject an externally-managed doc (no provenance tag).
        self.collection._docs["001010000000099"] = {
            "imsi": "001010000000099",
            "security": {"k": "00" * 16, "opc": "00" * 16, "amf": "8000", "op": None},
        }
        purged = self.repository.purge_yggdrasim()
        self.assertEqual(purged, 2)
        # External doc untouched.
        self.assertIn("001010000000099", self.collection._docs)
        self.assertNotIn(imsi_a, self.collection._docs)
        self.assertNotIn(imsi_b, self.collection._docs)

    def test_list_subscribers_only_yggdrasim_filters(self) -> None:
        self._provision(_SUPI)
        # External doc.
        self.collection._docs["001010000000099"] = {
            "imsi": "001010000000099",
            "security": {"k": "00" * 16, "opc": "00" * 16, "amf": "8000", "op": None},
        }
        all_subs = self.repository.list_subscribers()
        only_ours = self.repository.list_subscribers(only_yggdrasim=True)
        self.assertEqual(len(all_subs), 2)
        self.assertEqual(len(only_ours), 1)


class ProvisionDefaultStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_default_subscription_store()
        self.collection = _FakeCollection()
        self.repository = Open5gsSubscriberRepository(collection=self.collection)
        store = get_default_subscription_store()
        store.upsert(supi="imsi-001010000000001", k=_K, opc=_OPC, akma_enabled=True)
        store.upsert(supi="imsi-001010000000002", k=_K, opc=_OPC, akma_enabled=False)

    def tearDown(self) -> None:
        reset_default_subscription_store()

    def test_pushes_every_record(self) -> None:
        results = provision_default_store(repository=self.repository)
        self.assertEqual(len(results), 2)
        self.assertIn("001010000000001", self.collection._docs)
        self.assertIn("001010000000002", self.collection._docs)

    def test_only_akma_enabled_filters(self) -> None:
        results = provision_default_store(
            repository=self.repository,
            only_akma_enabled=True,
        )
        self.assertEqual(len(results), 1)
        self.assertIn("001010000000001", self.collection._docs)
        self.assertNotIn("001010000000002", self.collection._docs)


class BridgeConfigEnvTests(unittest.TestCase):
    def test_from_env_uses_defaults_when_unset(self) -> None:
        config = Open5gsBridgeConfig.from_env()
        # Defaults documented in the bridge module.
        self.assertTrue(re.match(r"^mongodb://", config.mongo_uri))
        self.assertEqual(config.db_name, "open5gs")
        self.assertEqual(config.collection_name, "subscribers")


if __name__ == "__main__":
    unittest.main()
