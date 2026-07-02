# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Unit tests for ``saip_security_domain_edit``.

The helpers operate on a decoded ``PE-SecurityDomain`` dict, so each
test seeds a minimal section, runs a mutator, and checks the resulting
structure. Round-trip via ``build_profile_sequence_from_document`` is
exercised in the dispatcher-integration tests.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_security_domain_edit as sd_edit


def _empty_sd() -> dict:
    return {
        "sd-Header": {},
        "instance": {
            "instanceAID": bytes.fromhex("A0000001515350"),
            "classAID": bytes.fromhex("A0000001515350"),
            "applicationLoadPackageAID": bytes.fromhex("A000000151"),
            "applicationPrivileges": bytes.fromhex("80"),
            "lifeCycleState": bytes.fromhex("07"),
            "applicationSpecificParametersC9": bytes.fromhex("C900"),
        },
    }


def _sample_component() -> dict:
    return {
        "keyType": 0x88,
        "keyData": "00112233445566778899AABBCCDDEEFF",
        "macLength": 8,
    }


class LocateSecurityDomainSectionsTests(unittest.TestCase):

    def test_returns_every_sd_section(self) -> None:
        doc = {
            "sections": {
                "header": {},  # no "instance" -> skipped
                "securityDomain": _empty_sd(),
                "mno-sd": _empty_sd(),
            }
        }
        out = sd_edit.locate_security_domain_sections(doc)
        keys = sorted(k for k, _ in out)
        self.assertEqual(keys, ["mno-sd", "securityDomain"])

    def test_empty_document_returns_empty_list(self) -> None:
        self.assertEqual(sd_edit.locate_security_domain_sections({}), [])


class KeyListAddTests(unittest.TestCase):

    def test_add_key_creates_keyList(self) -> None:
        sd = _empty_sd()
        msg = sd_edit.add_key(
            sd,
            key_version=0x01,
            key_identifier=0x01,
            usage_qualifier_hex="C0",
            key_components=[_sample_component()],
        )
        self.assertIn("KVN=0x01", msg)
        self.assertIn("keyList", sd)
        self.assertEqual(len(sd["keyList"]), 1)
        entry = sd["keyList"][0]
        self.assertEqual(entry["keyVersionNumber"], bytes([0x01]))
        self.assertEqual(entry["keyIdentifier"], bytes([0x01]))
        self.assertEqual(entry["keyUsageQualifier"], bytes.fromhex("C0"))
        self.assertEqual(len(entry["keyComponents"]), 1)
        self.assertEqual(entry["keyComponents"][0]["keyType"], bytes([0x88]))
        self.assertEqual(entry["keyComponents"][0]["macLength"], 8)

    def test_add_three_keys_round_trip(self) -> None:
        sd = _empty_sd()
        for kid in (1, 2, 3):
            sd_edit.add_key(
                sd,
                key_version=0x30,
                key_identifier=kid,
                usage_qualifier_hex="C0",
                key_components=[_sample_component()],
            )
        self.assertEqual(len(sd["keyList"]), 3)

    def test_duplicate_kvn_kid_rejected(self) -> None:
        sd = _empty_sd()
        sd_edit.add_key(
            sd,
            key_version=0x30,
            key_identifier=0x01,
            usage_qualifier_hex="C0",
            key_components=[_sample_component()],
        )
        with self.assertRaises(ValueError):
            sd_edit.add_key(
                sd,
                key_version=0x30,
                key_identifier=0x01,
                usage_qualifier_hex="80",
                key_components=[_sample_component()],
            )

    def test_empty_components_rejected(self) -> None:
        with self.assertRaises(ValueError):
            sd_edit.add_key(
                _empty_sd(),
                key_version=0x30,
                key_identifier=0x01,
                usage_qualifier_hex="C0",
                key_components=[],
            )

    def test_mac_length_above_16_rejected(self) -> None:
        with self.assertRaises(ValueError):
            sd_edit.add_key(
                _empty_sd(),
                key_version=0x30,
                key_identifier=0x01,
                usage_qualifier_hex="C0",
                key_components=[{"keyType": 0x88, "keyData": "DEAD", "macLength": 17}],
            )

    def test_usage_qualifier_must_be_1_or_2_bytes(self) -> None:
        with self.assertRaises(ValueError):
            sd_edit.add_key(
                _empty_sd(),
                key_version=0x30,
                key_identifier=0x01,
                usage_qualifier_hex="C0C0C0",  # 3 bytes
                key_components=[_sample_component()],
            )

    def test_counter_round_trip(self) -> None:
        sd = _empty_sd()
        sd_edit.add_key(
            sd,
            key_version=0x30,
            key_identifier=0x01,
            usage_qualifier_hex="C0",
            key_components=[_sample_component()],
            counter_hex="00000005",
        )
        self.assertEqual(sd["keyList"][0]["keyCounterValue"], bytes.fromhex("00000005"))


class KeyListRemoveTests(unittest.TestCase):

    def _seed(self) -> dict:
        sd = _empty_sd()
        for kid in (1, 2, 3):
            sd_edit.add_key(
                sd,
                key_version=0x30,
                key_identifier=kid,
                usage_qualifier_hex="C0",
                key_components=[_sample_component()],
            )
        return sd

    def test_remove_middle_key(self) -> None:
        sd = self._seed()
        sd_edit.remove_key(sd, key_version=0x30, key_identifier=2)
        kids = [e["keyIdentifier"][0] for e in sd["keyList"]]
        self.assertEqual(kids, [1, 3])

    def test_remove_last_drops_list(self) -> None:
        sd = _empty_sd()
        sd_edit.add_key(
            sd,
            key_version=0x30,
            key_identifier=1,
            usage_qualifier_hex="C0",
            key_components=[_sample_component()],
        )
        sd_edit.remove_key(sd, key_version=0x30, key_identifier=1)
        self.assertNotIn("keyList", sd)

    def test_remove_missing_raises(self) -> None:
        sd = self._seed()
        with self.assertRaises(LookupError):
            sd_edit.remove_key(sd, key_version=0x30, key_identifier=99)

    def test_replace_key_preserves_position(self) -> None:
        sd = self._seed()
        sd_edit.replace_key(
            sd,
            key_version=0x30,
            key_identifier=2,
            usage_qualifier_hex="80",  # changed
            key_components=[_sample_component()],
        )
        # Two keys before replacement plus the new one -> still 3 keys.
        self.assertEqual(len(sd["keyList"]), 3)
        # The replaced key should now carry usage_qualifier 0x80.
        replaced = next(
            e for e in sd["keyList"] if e["keyIdentifier"] == bytes([2])
        )
        self.assertEqual(replaced["keyUsageQualifier"], bytes.fromhex("80"))


class PersoDataTests(unittest.TestCase):

    def test_add_perso_block(self) -> None:
        sd = _empty_sd()
        sd_edit.add_perso_data_block(sd, "AABBCCDD")
        self.assertEqual(sd["sdPersoData"], [bytes.fromhex("AABBCCDD")])

    def test_remove_perso_block_by_index(self) -> None:
        sd = _empty_sd()
        sd_edit.add_perso_data_block(sd, "AA")
        sd_edit.add_perso_data_block(sd, "BB")
        sd_edit.remove_perso_data_block(sd, 0)
        self.assertEqual(sd["sdPersoData"], [bytes.fromhex("BB")])

    def test_remove_perso_block_out_of_range(self) -> None:
        sd = _empty_sd()
        sd_edit.add_perso_data_block(sd, "AA")
        with self.assertRaises(IndexError):
            sd_edit.remove_perso_data_block(sd, 5)

    def test_empty_perso_block_rejected(self) -> None:
        with self.assertRaises(ValueError):
            sd_edit.add_perso_data_block(_empty_sd(), "")


class InstanceMetadataTests(unittest.TestCase):

    def test_set_instance_aid(self) -> None:
        sd = _empty_sd()
        sd_edit.set_instance_aid_hex(sd, "A000000151535444")
        self.assertEqual(sd["instance"]["instanceAID"], bytes.fromhex("A000000151535444"))

    def test_set_instance_aid_wrong_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            sd_edit.set_instance_aid_hex(_empty_sd(), "DEADBEEF")  # 4 bytes

    def test_set_lifecycle_state(self) -> None:
        sd = _empty_sd()
        sd_edit.set_lifecycle_state(sd, 0x0F)
        self.assertEqual(sd["instance"]["lifeCycleState"], bytes([0x0F]))


class SummaryTests(unittest.TestCase):

    def test_summary_includes_keys_and_perso(self) -> None:
        sd = _empty_sd()
        sd_edit.add_key(
            sd,
            key_version=0x30,
            key_identifier=0x01,
            usage_qualifier_hex="C0",
            key_components=[_sample_component()],
        )
        sd_edit.add_perso_data_block(sd, "AABB")
        summary = sd_edit.security_domain_summary(sd)
        self.assertEqual(summary["instance_aid_hex"], "A0000001515350")
        self.assertEqual(summary["lifecycle_state"], 0x07)
        self.assertEqual(len(summary["keys"]), 1)
        self.assertEqual(summary["keys"][0]["key_version"], 0x30)
        self.assertEqual(summary["keys"][0]["components"][0]["key_type_label"][:3], "AES")
        self.assertEqual(summary["perso_data_hex"], ["AABB"])


if __name__ == "__main__":
    unittest.main()
