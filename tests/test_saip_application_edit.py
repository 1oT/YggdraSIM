# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Unit tests for ``saip_application_edit``."""

from __future__ import annotations

import copy
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

    def test_summary_names_the_package_and_the_process_data(self) -> None:
        app = _empty_application()
        app_edit.add_instance(
            app,
            **_instance_kwargs("A0000000871002FF33FF01"),
            process_data_hex_list=["0A0B"],
        )
        summary = app_edit.application_summary(app)
        self.assertEqual(summary["own_package_hex"], "A0000000871002")
        row = summary["instances"][0]
        self.assertEqual(row["index"], 0)
        self.assertEqual(row["process_data_hex_list"], ["0A0B"])
        # The only instance, without a load package, may name any package.
        self.assertEqual(row["own_package_hex"], "")


def _loaded_application() -> dict:
    app = _empty_application()
    app_edit.set_load_block(
        app,
        load_package_aid_hex="A0000000871002",
        load_block_object_hex="C402DEAD",
    )
    return app


class OnePackageTests(unittest.TestCase):
    """TCA SAIP v3.4.1 §8.7.1 (page 59): instances of the PE's one package."""

    def test_an_instance_of_another_package_is_refused(self) -> None:
        app = _loaded_application()
        kwargs = _instance_kwargs("A0000000871002FF33FF01")
        kwargs["load_package_aid_hex"] = "A0000000871003"
        with self.assertRaises(ValueError) as caught:
            app_edit.add_instance(app, **kwargs)
        self.assertIn("§8.7.1", str(caught.exception))
        self.assertNotIn("instanceList", app)

    def test_without_a_load_package_the_instances_share_one(self) -> None:
        app = _empty_application()
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))
        kwargs = _instance_kwargs("A0000000871002FF33FF02")
        kwargs["load_package_aid_hex"] = "A0000000871003"
        with self.assertRaises(ValueError):
            app_edit.add_instance(app, **kwargs)
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF02"))
        self.assertEqual(len(app["instanceList"]), 2)

    def test_a_new_load_package_takes_the_instances_along(self) -> None:
        app = _loaded_application()
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))
        message = app_edit.set_load_block(
            app,
            load_package_aid_hex="A0000000871003",
            load_block_object_hex="C402BEEF",
        )
        self.assertIn("1 instance(s) now install it", message)
        self.assertEqual(
            app["instanceList"][0]["applicationLoadPackageAID"],
            bytes.fromhex("A0000000871003"),
        )

    def test_a_load_package_added_later_takes_the_instances_along(self) -> None:
        app = _empty_application()
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))
        app_edit.set_load_block(
            app,
            load_package_aid_hex="A0000000871003",
            load_block_object_hex="C402BEEF",
        )
        self.assertIsNone(app_edit.package_conflict(app))
        self.assertEqual(app_edit.own_package(app), bytes.fromhex("A0000000871003"))

    def test_conflict_names_the_foreign_package(self) -> None:
        app = _loaded_application()
        app["instanceList"] = [{"applicationLoadPackageAID": bytes.fromhex("A0000000871009")}]
        conflict = app_edit.package_conflict(app)
        self.assertIsNotNone(conflict)
        self.assertIn("A0000000871009", conflict)
        self.assertIn("A0000000871002", conflict)


def _update_kwargs(**overrides: str) -> dict:
    kwargs = {
        "load_package_aid_hex": "A0000000871002",
        "class_aid_hex": "A0000000871002FF33FF",
        "new_instance_aid_hex": "",
        "privileges_hex": "00",
        "lifecycle_state": 0x07,
        "application_specific_parameters_hex": "C900",
        "extradite_sd_aid_hex": "",
    }
    kwargs.update(overrides)
    return kwargs


class UpdateInstanceTests(unittest.TestCase):

    def _two_instances(self) -> dict:
        app = _loaded_application()
        app_edit.add_instance(
            app,
            **_instance_kwargs("A0000000871002FF33FF01"),
            uicc_toolkit_parameters_hex="0102",
            process_data_hex_list=["0A0B"],
        )
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF02"))
        return app

    def test_update_keeps_the_members_it_does_not_write(self) -> None:
        app = self._two_instances()
        entry = app["instanceList"][0]
        entry["systemSpecificParameters"] = {"globalServiceParameters": b"\x01"}
        entry["controlReferenceTemplate"] = {"applicationProviderIdentifier": b"\x42"}
        message = app_edit.update_instance(
            app,
            "A0000000871002FF33FF01",
            **_update_kwargs(
                new_instance_aid_hex="A0000000871002FF33FF03",
                privileges_hex="800000",
                application_specific_parameters_hex="",
                extradite_sd_aid_hex="A0000001515350",
            ),
        )
        self.assertIn("A0000000871002FF33FF03", message)
        self.assertIn("was A0000000871002FF33FF01", message)
        updated = app["instanceList"][0]
        self.assertIs(updated, entry)
        self.assertEqual(updated["instanceAID"], bytes.fromhex("A0000000871002FF33FF03"))
        self.assertEqual(updated["applicationPrivileges"], bytes.fromhex("800000"))
        self.assertEqual(updated["applicationSpecificParametersC9"], b"")
        self.assertEqual(updated["extraditeSecurityDomainAID"], bytes.fromhex("A0000001515350"))
        self.assertEqual(updated["systemSpecificParameters"], {"globalServiceParameters": b"\x01"})
        self.assertEqual(updated["controlReferenceTemplate"], {"applicationProviderIdentifier": b"\x42"})
        self.assertEqual(
            updated["applicationParameters"]["uiccToolkitApplicationSpecificParametersField"],
            bytes.fromhex("0102"),
        )
        self.assertEqual(updated["processData"], [bytes.fromhex("0A0B")])
        self.assertEqual(
            app["instanceList"][1]["instanceAID"],
            bytes.fromhex("A0000000871002FF33FF02"),
        )

    def test_life_cycle_and_extradite_round_trip(self) -> None:
        app = self._two_instances()
        app_edit.update_instance(
            app,
            "A0000000871002FF33FF02",
            **_update_kwargs(lifecycle_state=0x0F, extradite_sd_aid_hex="A0000001515350"),
        )
        app_edit.update_instance(app, "A0000000871002FF33FF02", **_update_kwargs())
        entry = app["instanceList"][1]
        self.assertEqual(entry["lifeCycleState"], b"\x07")
        self.assertNotIn("extraditeSecurityDomainAID", entry)
        self.assertEqual(entry["instanceAID"], bytes.fromhex("A0000000871002FF33FF02"))

    def test_an_aid_another_instance_holds_is_refused(self) -> None:
        app = self._two_instances()
        with self.assertRaises(ValueError):
            app_edit.update_instance(
                app,
                "A0000000871002FF33FF01",
                **_update_kwargs(new_instance_aid_hex="A0000000871002FF33FF02"),
            )

    def test_a_missing_instance_raises(self) -> None:
        with self.assertRaises(LookupError):
            app_edit.update_instance(
                _loaded_application(),
                "A0000000871002FF33FF01",
                **_update_kwargs(),
            )

    def test_a_changed_package_has_to_be_the_pe_package(self) -> None:
        app = self._two_instances()
        with self.assertRaises(ValueError) as caught:
            app_edit.update_instance(
                app,
                "A0000000871002FF33FF01",
                **_update_kwargs(load_package_aid_hex="A0000000871003"),
            )
        self.assertIn("§8.7.1", str(caught.exception))
        self.assertEqual(
            app["instanceList"][0]["applicationLoadPackageAID"],
            bytes.fromhex("A0000000871002"),
        )

    def test_an_instance_already_on_another_package_stays_editable(self) -> None:
        app = _loaded_application()
        app["instanceList"] = [{
            "applicationLoadPackageAID": bytes.fromhex("A0000000871009"),
            "classAID": bytes.fromhex("A0000000871009FF"),
            "instanceAID": bytes.fromhex("A0000000871009FF01"),
            "applicationPrivileges": b"\x00",
            "lifeCycleState": b"\x07",
            "applicationSpecificParametersC9": b"",
        }]
        app_edit.update_instance(
            app,
            "A0000000871009FF01",
            **_update_kwargs(
                load_package_aid_hex="A0000000871009",
                class_aid_hex="A0000000871009FF",
                privileges_hex="800000",
            ),
        )
        self.assertEqual(app["instanceList"][0]["applicationPrivileges"], bytes.fromhex("800000"))


class KeepOnePackageTests(unittest.TestCase):
    """The structure editor's member edits keep the instances on one package."""

    def _before(self) -> dict:
        app = _loaded_application()
        app_edit.add_instance(app, **_instance_kwargs("A0000000871002FF33FF01"))
        return app

    def test_an_added_entry_installs_the_pe_package(self) -> None:
        before = self._before()
        after = copy.deepcopy(before)
        after["instanceList"].append({"applicationLoadPackageAID": bytes(5)})
        note = app_edit.keep_one_package(before, after)
        self.assertEqual(
            after["instanceList"][1]["applicationLoadPackageAID"],
            bytes.fromhex("A0000000871002"),
        )
        self.assertIn("A0000000871002", note)

    def test_a_changed_load_package_takes_the_instances_along(self) -> None:
        before = self._before()
        after = copy.deepcopy(before)
        after["loadBlock"]["loadPackageAID"] = bytes.fromhex("A0000000871003")
        note = app_edit.keep_one_package(before, after)
        self.assertEqual(
            after["instanceList"][0]["applicationLoadPackageAID"],
            bytes.fromhex("A0000000871003"),
        )
        self.assertIn("1 instance(s)", note)

    def test_an_instance_moved_to_another_package_is_refused(self) -> None:
        before = self._before()
        after = copy.deepcopy(before)
        after["instanceList"][0]["applicationLoadPackageAID"] = bytes.fromhex("A0000000871003")
        with self.assertRaises(ValueError):
            app_edit.keep_one_package(before, after)

    def test_a_filler_load_package_moves_nothing(self) -> None:
        before = _empty_application()
        app_edit.add_instance(before, **_instance_kwargs("A0000000871002FF33FF01"))
        after = copy.deepcopy(before)
        after["loadBlock"] = {"loadPackageAID": bytes(5), "loadBlockObject": b""}
        self.assertEqual(app_edit.keep_one_package(before, after), "")
        self.assertEqual(
            after["instanceList"][0]["applicationLoadPackageAID"],
            bytes.fromhex("A0000000871002"),
        )

    def test_a_profile_that_already_mixes_packages_stays_editable(self) -> None:
        before = self._before()
        before["instanceList"].append({"applicationLoadPackageAID": bytes.fromhex("A0000000871009")})
        after = copy.deepcopy(before)
        after["instanceList"][0]["applicationPrivileges"] = bytes.fromhex("800000")
        self.assertEqual(app_edit.keep_one_package(before, after), "")


if __name__ == "__main__":
    unittest.main()
