# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Dispatcher-layer smoke tests for the typed PE-section editors.

Covers ``saip.{get,add,remove,replace}_security_domain_*``,
``saip.{get,add,remove,set}_application_*``, and
``saip.{get,add,remove,set}_rfm_*`` plus
``saip.set_profile_header_versions``. Sessions are constructed
in-memory (no pySim round-trip) so the test runs without a SAIP
package fixture; ``_typed_pe_section_finish`` swallows the
re-encode failure and surfaces it as a warning, which is the
expected behaviour for synthetic decoded documents.
"""

from __future__ import annotations

import unittest
from typing import Any


def _make_handle(sections: dict[str, Any]) -> dict[str, Any]:
    """Build a minimal SessionManager handle for the dispatcher tests."""
    return {
        "decoded_document": {
            "intro": ["synthetic profile for dispatcher tests"],
            "sections": dict(sections),
        },
        "pes": None,
        "dirty_pes": set(),
        "applied_overrides": {},
    }


def _open_synthetic_session(sections: dict[str, Any]) -> str:
    from yggdrasim_common.gui_server.sessions import get_manager

    record = get_manager().open(
        kind="saip-test",
        handle=_make_handle(sections),
        close=lambda: None,
        idle_timeout_s=60.0,
        metadata={"origin": "test_saip_typed_pe_dispatchers"},
    )
    return record.id


def _release(session_id: str) -> None:
    from yggdrasim_common.gui_server.sessions import get_manager

    try:
        get_manager()._sessions.pop(session_id, None)
    except Exception:
        pass


class HeaderVersionDispatcherTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        self.saip = saip_actions
        # ProfileHeader minimum the summary projector tolerates.
        # major/minor stored as ints (the in-tree set_major_minor_version
        # mutator normalises to int; header_summary reads via int()).
        self.sid = _open_synthetic_session({
            "header": {
                "major-version": 3,
                "minor-version": 3,
                "iccid": b"\x98\x88\x20\x32\x65\x43\x87\x09\x21\x43",
                "profileType": "synthetic-test",
            },
        })

    def tearDown(self) -> None:
        _release(self.sid)

    def test_set_versions_round_trip(self) -> None:
        result = self.saip._dispatch_set_profile_header_versions(
            ctx=None,
            session_id=self.sid,
            major=4,
            minor=0,
        )
        self.assertEqual(result["header"]["major_version"], 4)
        self.assertEqual(result["header"]["minor_version"], 0)
        self.assertEqual(len(result["summaries"]), 1)

    def test_set_versions_minor_only(self) -> None:
        result = self.saip._dispatch_set_profile_header_versions(
            ctx=None,
            session_id=self.sid,
            minor=2,
        )
        self.assertEqual(result["header"]["major_version"], 3)
        self.assertEqual(result["header"]["minor_version"], 2)


class SecurityDomainDispatcherTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        self.saip = saip_actions
        self.sid = _open_synthetic_session({
            "securityDomain": {
                "instance": {
                    "instanceAID": b"\xA0\x00\x00\x01\x51\x00\x00\x00",
                    "applicationPrivileges": b"\xC0\x00\x00",
                    "lifeCycleState": b"\x07",
                },
                "keyList": [],
                "sdPersoData": [],
            },
        })

    def tearDown(self) -> None:
        _release(self.sid)

    def test_get_security_domain_projects_summary(self) -> None:
        result = self.saip._dispatch_get_security_domain(
            ctx=None, session_id=self.sid, pe_index=0,
        )
        self.assertEqual(result["pe_index"], 0)
        self.assertEqual(result["section_key"], "securityDomain")
        self.assertEqual(result["keys"], [])
        self.assertEqual(result["perso_data_hex"], [])
        self.assertEqual(result["lifecycle_state"], 0x07)

    def test_add_then_remove_key_round_trip(self) -> None:
        # GP §11.1 AES-128 key set, KVN 0x20 / KID 0x01. Usage
        # qualifier 0x18 = ENC | DEC (GP CS §11.1.9).
        add_result = self.saip._dispatch_add_security_domain_key(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            key_version=0x20,
            key_identifier=0x01,
            usage_qualifier_hex="18",
            key_components=[
                {"keyType": "88", "keyData": "00" * 16, "macLength": "10"},
            ],
            key_access=0,
            counter_hex="",
        )
        self.assertEqual(len(add_result["keys"]), 1)
        self.assertEqual(add_result["keys"][0]["key_version"], 0x20)
        self.assertEqual(add_result["keys"][0]["key_identifier"], 0x01)
        self.assertIn("added key", add_result["summary"])

        remove_result = self.saip._dispatch_remove_security_domain_key(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            key_version=0x20,
            key_identifier=0x01,
        )
        self.assertEqual(len(remove_result["keys"]), 0)

    def test_add_duplicate_key_raises(self) -> None:
        kwargs = dict(
            session_id=self.sid,
            pe_index=0,
            key_version=0x21,
            key_identifier=0x01,
            usage_qualifier_hex="18",
            key_components=[
                {"keyType": "88", "keyData": "11" * 16, "macLength": "10"},
            ],
            key_access=0,
            counter_hex="",
        )
        self.saip._dispatch_add_security_domain_key(ctx=None, **kwargs)
        with self.assertRaises(ValueError):
            self.saip._dispatch_add_security_domain_key(ctx=None, **kwargs)

    def test_replace_key_round_trip(self) -> None:
        self.saip._dispatch_add_security_domain_key(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            key_version=0x22,
            key_identifier=0x01,
            usage_qualifier_hex="18",
            key_components=[
                {"keyType": "88", "keyData": "AA" * 16, "macLength": "10"},
            ],
        )
        replaced = self.saip._dispatch_replace_security_domain_key(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            key_version=0x22,
            key_identifier=0x01,
            usage_qualifier_hex="18",
            key_components=[
                {"keyType": "88", "keyData": "BB" * 16, "macLength": "10"},
            ],
        )
        self.assertEqual(len(replaced["keys"]), 1)
        self.assertEqual(
            replaced["keys"][0]["components"][0]["key_data_hex"],
            ("BB" * 16).upper(),
        )

    def test_perso_block_add_remove(self) -> None:
        added = self.saip._dispatch_add_security_domain_perso_block(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            block_hex="E2 0A 4F 08 A0 00 00 00 03 00 00 00",
        )
        self.assertEqual(len(added["perso_data_hex"]), 1)
        removed = self.saip._dispatch_remove_security_domain_perso_block(
            ctx=None, session_id=self.sid, pe_index=0, index=0,
        )
        self.assertEqual(len(removed["perso_data_hex"]), 0)

    def test_set_instance_field_lifecycle(self) -> None:
        # GP CS §11.1.1 PERSONALIZED = 0x0F.
        result = self.saip._dispatch_set_security_domain_instance_field(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            field="lifecycle_state",
            value="0x0F",
        )
        self.assertEqual(result["lifecycle_state"], 0x0F)

    def test_set_instance_field_unknown_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_set_security_domain_instance_field(
                ctx=None, session_id=self.sid, pe_index=0,
                field="bogus", value="x",
            )

    def test_wrong_pe_type_raises(self) -> None:
        # Re-key the section to a non-SD base name; the resolver
        # must reject the call rather than silently mutate.
        from yggdrasim_common.gui_server.sessions import get_manager
        handle = get_manager().claim(self.sid)
        handle["decoded_document"]["sections"] = {
            "rfm": handle["decoded_document"]["sections"]["securityDomain"],
        }
        with self.assertRaises(ValueError):
            self.saip._dispatch_get_security_domain(
                ctx=None, session_id=self.sid, pe_index=0,
            )


class ApplicationDispatcherTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        self.saip = saip_actions
        self.sid = _open_synthetic_session({
            "application": {
                "instanceList": [],
            },
        })

    def tearDown(self) -> None:
        _release(self.sid)

    def test_get_application_returns_empty_instance_list(self) -> None:
        result = self.saip._dispatch_get_application(
            ctx=None, session_id=self.sid, pe_index=0,
        )
        self.assertEqual(result["instances"], [])
        self.assertIsNone(result["load_block"])

    def test_add_then_remove_instance(self) -> None:
        added = self.saip._dispatch_add_application_instance(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            load_package_aid_hex="A0 00 00 01 51 00",
            class_aid_hex="A0 00 00 01 51 00 01",
            instance_aid_hex="A0 00 00 01 51 00 01 02",
            privileges_hex="000000",
            application_specific_parameters_hex="C9 00",
            lifecycle_state=0x07,
        )
        self.assertEqual(len(added["instances"]), 1)
        self.assertIn("added", added["summary"])
        removed = self.saip._dispatch_remove_application_instance(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            instance_aid_hex="A0 00 00 01 51 00 01 02",
        )
        self.assertEqual(len(removed["instances"]), 0)

    def test_set_load_block_round_trip(self) -> None:
        added = self.saip._dispatch_set_application_load_block(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            load_package_aid_hex="A0000001510010",
            load_block_object_hex="C4 04 DE AD BE EF",
        )
        self.assertIsNotNone(added["load_block"])
        self.assertGreater(added["load_block"]["load_block_object_size"], 0)
        removed = self.saip._dispatch_remove_application_load_block(
            ctx=None, session_id=self.sid, pe_index=0,
        )
        self.assertIsNone(removed["load_block"])


class RfmDispatcherTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        self.saip = saip_actions
        self.sid = _open_synthetic_session({
            "rfm": {
                "instanceAID": b"\xA0\x00\x00\x00\x09\x00\x02",
                "minimumSecurityLevel": b"\x06",
                "uiccAccessDomain": b"",
                "uiccAdminAccessDomain": b"",
                "tarList": [],
            },
        })

    def tearDown(self) -> None:
        _release(self.sid)

    def test_get_rfm_summary(self) -> None:
        result = self.saip._dispatch_get_rfm(
            ctx=None, session_id=self.sid, pe_index=0,
        )
        self.assertEqual(result["section_key"], "rfm")
        self.assertEqual(result["tar_list"], [])
        self.assertEqual(result["minimum_security_level"], 0x06)

    def test_add_and_remove_tar(self) -> None:
        added = self.saip._dispatch_add_rfm_tar(
            ctx=None, session_id=self.sid, pe_index=0,
            tar_hex="B0 00 10",
        )
        self.assertEqual(added["tar_list"], ["B00010"])
        with self.assertRaises(ValueError):
            self.saip._dispatch_add_rfm_tar(
                ctx=None, session_id=self.sid, pe_index=0, tar_hex="B00010",
            )
        removed = self.saip._dispatch_remove_rfm_tar(
            ctx=None, session_id=self.sid, pe_index=0, tar_hex="B00010",
        )
        self.assertEqual(removed["tar_list"], [])

    def test_set_tar_list_replaces(self) -> None:
        result = self.saip._dispatch_set_rfm_tar_list(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            tar_hex_list=["B00010", "B00011", "B00012"],
        )
        self.assertEqual(result["tar_list"], ["B00010", "B00011", "B00012"])

    def test_set_field_minimum_security_level(self) -> None:
        result = self.saip._dispatch_set_rfm_field(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            field="minimum_security_level",
            value=0x12,
        )
        self.assertEqual(result["minimum_security_level"], 0x12)

    def test_set_field_unknown_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_set_rfm_field(
                ctx=None, session_id=self.sid, pe_index=0,
                field="bogus", value="x",
            )

    def test_set_then_remove_adf_access(self) -> None:
        added = self.saip._dispatch_set_rfm_adf_access(
            ctx=None,
            session_id=self.sid,
            pe_index=0,
            adf_aid_hex="A0 00 00 00 87 10 02",
            adf_access_domain_hex="01 02 03",
            adf_admin_access_domain_hex="",
        )
        self.assertIsNotNone(added["adf_access"])
        self.assertEqual(
            added["adf_access"]["adf_aid_hex"], "A0000000871002",
        )
        removed = self.saip._dispatch_remove_rfm_adf_access(
            ctx=None, session_id=self.sid, pe_index=0,
        )
        self.assertIsNone(removed["adf_access"])


class RegistryWiringTests(unittest.TestCase):
    """All new specs must be registered + reachable by id."""

    def test_all_new_specs_registered(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as _saip_actions  # noqa: F401
        from yggdrasim_common.gui_server.actions.registry import get_registry

        registry = get_registry()
        ids: set[str] = set()
        if hasattr(registry, "all_specs"):
            ids = {spec.id for spec in registry.all_specs()}
        else:
            for attr in ("specs", "_specs", "list_specs"):
                if hasattr(registry, attr):
                    value = getattr(registry, attr)
                    value = value() if callable(value) else value
                    ids = {getattr(s, "id", s) for s in value}
                    break
        expected = {
            "saip.set_profile_header_versions",
            "saip.get_security_domain",
            "saip.add_security_domain_key",
            "saip.remove_security_domain_key",
            "saip.replace_security_domain_key",
            "saip.add_security_domain_perso_block",
            "saip.remove_security_domain_perso_block",
            "saip.set_security_domain_instance_field",
            "saip.get_application",
            "saip.add_application_instance",
            "saip.remove_application_instance",
            "saip.set_application_load_block",
            "saip.remove_application_load_block",
            "saip.get_rfm",
            "saip.add_rfm_tar",
            "saip.remove_rfm_tar",
            "saip.set_rfm_tar_list",
            "saip.set_rfm_field",
            "saip.set_rfm_adf_access",
            "saip.remove_rfm_adf_access",
        }
        self.assertTrue(
            expected.issubset(ids),
            f"missing from registry: {sorted(expected - ids)}",
        )


if __name__ == "__main__":
    unittest.main()
