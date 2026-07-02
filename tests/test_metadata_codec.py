# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SCP11/local_access/metadata_codec.py public functions.

Covers: collect_enabled_custom_metadata_tags, build_store_metadata_request_payload,
        build_update_metadata_request_payload, load_metadata_json_document.
The pySim-dependent encode_* functions are exercised through their payload-builder
branches; ASN.1 encoding itself is gated by pySim availability.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from SCP11.local_access.metadata_codec import (
    build_store_metadata_request_payload,
    build_update_metadata_request_payload,
    collect_enabled_custom_metadata_tags,
    load_metadata_json_document,
)


# ---------------------------------------------------------------------------
# Minimal valid metadata document fixture
# ---------------------------------------------------------------------------

def _minimal_doc(*, iccid: str = "89882012345678901234") -> dict:
    return {
        "profile": {
            "iccid": iccid,
            "name": "Test Profile",
            "profile_class": "operational",
        },
        "operator": {
            "name": "Test Operator",
        },
    }


# ---------------------------------------------------------------------------
# load_metadata_json_document
# ---------------------------------------------------------------------------

class LoadMetadataJsonDocumentTests(unittest.TestCase):

    def test_valid_json_file_loaded(self) -> None:
        doc = {"profile": {}, "operator": {}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump(doc, fh)
            path = fh.name
        try:
            result = load_metadata_json_document(path)
            self.assertIsInstance(result, dict)
        finally:
            os.unlink(path)

    def test_non_object_root_raises(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump([1, 2, 3], fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                load_metadata_json_document(path)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# collect_enabled_custom_metadata_tags
# ---------------------------------------------------------------------------

class CollectEnabledCustomMetadataTagsTests(unittest.TestCase):

    def test_no_custom_key_returns_empty(self) -> None:
        result = collect_enabled_custom_metadata_tags({"profile": {}})
        self.assertEqual(result, [])

    def test_enabled_tag_collected(self) -> None:
        doc = {
            "custom": {
                "AB": {
                    "include": True,
                    "value_hex": "AABB",
                }
            }
        }
        result = collect_enabled_custom_metadata_tags(doc)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["tag_hex"], "AB")
        self.assertEqual(result[0]["value_hex"], "AABB")

    def test_disabled_tag_excluded(self) -> None:
        doc = {
            "custom": {
                "AB": {
                    "include": False,
                    "value_hex": "AABB",
                }
            }
        }
        result = collect_enabled_custom_metadata_tags(doc)
        self.assertEqual(result, [])

    def test_enabled_tag_with_empty_value_hex_raises(self) -> None:
        doc = {
            "custom": {
                "AB": {
                    "include": True,
                    "value_hex": "",
                }
            }
        }
        with self.assertRaises(ValueError):
            collect_enabled_custom_metadata_tags(doc)

    def test_odd_length_hex_raises(self) -> None:
        doc = {
            "custom": {
                "AB": {
                    "include": True,
                    "value_hex": "ABC",
                }
            }
        }
        with self.assertRaises(ValueError):
            collect_enabled_custom_metadata_tags(doc)

    def test_non_hex_value_raises(self) -> None:
        doc = {
            "custom": {
                "AB": {
                    "include": True,
                    "value_hex": "GG",
                }
            }
        }
        with self.assertRaises(ValueError):
            collect_enabled_custom_metadata_tags(doc)

    def test_nested_tags_collected(self) -> None:
        doc = {
            "custom": {
                "group": {
                    "AB": {
                        "include": True,
                        "value_hex": "AABB",
                    }
                }
            }
        }
        result = collect_enabled_custom_metadata_tags(doc)
        self.assertEqual(len(result), 1)
        self.assertIn("AB", result[0]["tag_hex"])

    def test_custom_non_dict_raises(self) -> None:
        with self.assertRaises(ValueError):
            collect_enabled_custom_metadata_tags({"custom": "string"})


# ---------------------------------------------------------------------------
# build_store_metadata_request_payload
# ---------------------------------------------------------------------------

class BuildStoreMetadataRequestPayloadTests(unittest.TestCase):

    def test_minimal_doc_produces_payload(self) -> None:
        payload = build_store_metadata_request_payload(_minimal_doc())
        self.assertIn("iccid", payload)
        self.assertIn("serviceProviderName", payload)
        self.assertIn("profileName", payload)

    def test_service_provider_name_matches(self) -> None:
        payload = build_store_metadata_request_payload(_minimal_doc())
        self.assertEqual(payload["serviceProviderName"], "Test Operator")

    def test_profile_name_matches(self) -> None:
        payload = build_store_metadata_request_payload(_minimal_doc())
        self.assertEqual(payload["profileName"], "Test Profile")

    def test_missing_operator_name_raises(self) -> None:
        doc = _minimal_doc()
        del doc["operator"]["name"]
        with self.assertRaises((ValueError, KeyError)):
            build_store_metadata_request_payload(doc)

    def test_missing_profile_name_raises(self) -> None:
        doc = _minimal_doc()
        del doc["profile"]["name"]
        with self.assertRaises(ValueError):
            build_store_metadata_request_payload(doc)

    def test_operator_name_too_long_raises(self) -> None:
        doc = _minimal_doc()
        doc["operator"]["name"] = "X" * 33
        with self.assertRaises(ValueError):
            build_store_metadata_request_payload(doc)

    def test_profile_name_too_long_raises(self) -> None:
        doc = _minimal_doc()
        doc["profile"]["name"] = "Y" * 65
        with self.assertRaises(ValueError):
            build_store_metadata_request_payload(doc)

    def test_missing_profile_key_raises(self) -> None:
        doc = _minimal_doc()
        del doc["profile"]
        with self.assertRaises(ValueError):
            build_store_metadata_request_payload(doc)

    def test_missing_operator_key_raises(self) -> None:
        doc = _minimal_doc()
        del doc["operator"]
        with self.assertRaises(ValueError):
            build_store_metadata_request_payload(doc)

    def test_iccid_encoded_to_bytes(self) -> None:
        payload = build_store_metadata_request_payload(_minimal_doc())
        self.assertIsInstance(payload["iccid"], bytes)

    def test_with_mcc_mnc(self) -> None:
        doc = _minimal_doc()
        doc["operator"]["mcc"] = "001"
        doc["operator"]["mnc"] = "01"
        payload = build_store_metadata_request_payload(doc)
        self.assertIsInstance(payload["profileOwner"]["mccMnc"], bytes)

    def test_notification_events_build(self) -> None:
        doc = _minimal_doc()
        doc["notification_events"] = {
            "address": "smdp.example.test",
            "install": True,
        }
        payload = build_store_metadata_request_payload(doc)
        self.assertIsInstance(payload["notificationConfigurationInfo"], list)
        self.assertEqual(len(payload["notificationConfigurationInfo"]), 1)


# ---------------------------------------------------------------------------
# build_update_metadata_request_payload
# ---------------------------------------------------------------------------

class BuildUpdateMetadataRequestPayloadTests(unittest.TestCase):

    def test_operator_name_update(self) -> None:
        doc = {"operator": {"name": "New Operator"}}
        payload = build_update_metadata_request_payload(doc)
        self.assertEqual(payload["serviceProviderName"], "New Operator")

    def test_profile_name_update(self) -> None:
        doc = {"profile": {"name": "New Name"}}
        payload = build_update_metadata_request_payload(doc)
        self.assertEqual(payload["profileName"], "New Name")

    def test_empty_doc_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_update_metadata_request_payload({})

    def test_policy_rules_update(self) -> None:
        doc = {"policy_rules": {"disable_not_allowed": True}}
        payload = build_update_metadata_request_payload(doc)
        self.assertIn("profilePolicyRules", payload)

    def test_operator_name_too_long_raises(self) -> None:
        doc = {"operator": {"name": "Z" * 33}}
        with self.assertRaises(ValueError):
            build_update_metadata_request_payload(doc)

    def test_icon_type_update(self) -> None:
        doc = {"profile": {"icon": {"type": "PNG"}}}
        payload = build_update_metadata_request_payload(doc)
        self.assertIn("iconType", payload)


if __name__ == "__main__":
    unittest.main()
