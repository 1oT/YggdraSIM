# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Unit tests for ``saip_application_edit``."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_application_edit as app_edit


def _empty_application() -> dict:
    return {"app-Header": {}}


def _instance_kwargs(instance_aid_hex: str) -> dict:
    return {
        "load_package_aid_hex": "A0000000871002",
        "class_aid_hex": "A0000000871002FF33FF",
        "instance_aid_hex": instance_aid_hex,
        "privileges_hex": "00",
        "application_specific_parameters_hex": "C900",
    }


class LocateApplicationSectionsTests(unittest.TestCase):

    def test_returns_application_sections(self) -> None:
        doc = {
            "sections": {
                "header": {"major-version": 3},  # no application markers
                "application": {"instanceList": []},
                "applicationManagement": {"loadBlock": {}},
            }
        }
        out = app_edit.locate_application_sections(doc)
        keys = sorted(k for k, _ in out)
        self.assertEqual(keys, ["application", "applicationManagement"])


class InstanceListTests(unittest.TestCase):

    def test_add_instance_round_trip(self) -> None:
        app = _empty_application()
        msg = app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))
        self.assertIn("A0000000871002FF33FF01", msg)
        self.assertEqual(len(app["instanceList"]), 1)
        entry = app["instanceList"][0]
        self.assertEqual(entry["instanceAID"], bytes.fromhex("A0000000871002FF33FF01"))
        self.assertEqual(entry["lifeCycleState"], bytes([0x07]))

    def test_add_two_instances(self) -> None:
        app = _empty_application()
        for suffix in ("01", "02"):
            app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF" + suffix))
        self.assertEqual(len(app["instanceList"]), 2)

    def test_duplicate_instance_aid_rejected(self) -> None:
        app = _empty_application()
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))
        with self.assertRaises(ValueError):
            app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))

    def test_short_aid_rejected(self) -> None:
        with self.assertRaises(ValueError):
            kwargs = _instance_kwargs("DEADBEEF")  # 4 bytes
            app_edit.add_instance(_empty_application(), **kwargs)

    def test_remove_instance(self) -> None:
        app = _empty_application()
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF02"))
        app_edit.remove_instance(app, "A0000000871002FF33FF01")
        self.assertEqual(len(app["instanceList"]), 1)
        self.assertEqual(
            app["instanceList"][0]["instanceAID"],
            bytes.fromhex("A0000000871002FF33FF02"),
        )

    def test_remove_last_instance_drops_list(self) -> None:
        app = _empty_application()
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))
        app_edit.remove_instance(app, "A0000000871002FF33FF01")
        self.assertNotIn("instanceList", app)

    def test_remove_missing_aid_raises(self) -> None:
        app = _empty_application()
        with self.assertRaises(LookupError):
            app_edit.remove_instance(app, "A0000000871002FF33FF01")

    def test_uicc_parameters_attached_when_present(self) -> None:
        app = _empty_application()
        app_edit.add_instance(
            app,
            **_instance_kwargs("A0000000871002FF33FF01"),
            uicc_toolkit_parameters_hex="0102",
            uicc_access_parameters_hex="03",
        )
        params = app["instanceList"][0]["applicationParameters"]
        self.assertEqual(
            params["uiccToolkitApplicationSpecificParametersField"],
            bytes.fromhex("0102"),
        )
        self.assertEqual(
            params["uiccAccessApplicationSpecificParametersField"],
            bytes.fromhex("03"),
        )
        self.assertNotIn(
            "uiccAdministrativeAccessApplicationSpecificParametersField",
            params,
        )

    def test_process_data_list(self) -> None:
        app = _empty_application()
        app_edit.add_instance(
            app,
            **_instance_kwargs("A0000000871002FF33FF01"),
            process_data_hex_list=["0A0B", "0C"],
        )
        self.assertEqual(
            app["instanceList"][0]["processData"],
            [bytes.fromhex("0A0B"), bytes.fromhex("0C")],
        )


class LoadBlockTests(unittest.TestCase):

    def test_set_load_block_round_trip(self) -> None:
        app = _empty_application()
        app_edit.set_load_block(
            app,
            load_package_aid_hex="A0000000871002",
            load_block_object_hex="C402DEAD",
            security_domain_aid_hex="A0000001515350",
            non_volatile_code_limit_hex="1000",
        )
        lb = app["loadBlock"]
        self.assertEqual(lb["loadPackageAID"], bytes.fromhex("A0000000871002"))
        self.assertEqual(lb["loadBlockObject"], bytes.fromhex("C402DEAD"))
        self.assertEqual(lb["securityDomainAID"], bytes.fromhex("A0000001515350"))
        self.assertEqual(lb["nonVolatileCodeLimitC6"], bytes.fromhex("1000"))

    def test_empty_load_block_object_rejected(self) -> None:
        with self.assertRaises(ValueError):
            app_edit.set_load_block(
                _empty_application(),
                load_package_aid_hex="A0000000871002",
                load_block_object_hex="",
            )

    def test_remove_load_block(self) -> None:
        app = _empty_application()
        app_edit.set_load_block(
            app,
            load_package_aid_hex="A0000000871002",
            load_block_object_hex="C402DEAD",
        )
        app_edit.remove_load_block(app)
        self.assertNotIn("loadBlock", app)

    def test_remove_missing_load_block_raises(self) -> None:
        with self.assertRaises(LookupError):
            app_edit.remove_load_block(_empty_application())


class SummaryTests(unittest.TestCase):

    def test_summary_includes_load_block_and_instances(self) -> None:
        app = _empty_application()
        app_edit.set_load_block(
            app,
            load_package_aid_hex="A0000000871002",
            load_block_object_hex="C402DEAD",
        )
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))
        summary = app_edit.application_summary(app)
        self.assertEqual(summary["load_block"]["load_package_aid_hex"], "A0000000871002")
        self.assertEqual(summary["load_block"]["load_block_object_size"], 4)
        self.assertEqual(len(summary["instances"]), 1)
        self.assertEqual(summary["instances"][0]["instance_aid_hex"], "A0000000871002FF33FF01")


if __name__ == "__main__":
    unittest.main()
