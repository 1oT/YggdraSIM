# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The local SM-DS on its operator surfaces: the SMDS verb, the Command Center actions, their tab and the MCP tier.

The verb and the actions print the same lines, because an action runs the
verb. Nothing here opens a reader, and the store is a scratch one; the
certificates the status names come from the test PKI, since the SGP.26 bundle
is not on a clean checkout.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SCP11.eim_local.engine import smds
from SCP11.eim_local.engine.overview import build_overview
from SCP11.eim_local.engine.service import LocalEim
from SCP11.eim_local.engine.store import DATABASE_FILE, EimStore
from SCP11.eim_local.main import EimLocalShell
from tests.smds_support import EID, OTHER_EID, SMDP_ADDRESS, SMDS_ADDRESS, SMDS_OID, Pki

REPO = Path(__file__).resolve().parents[1]
ACTIONS = ("eim_local.smds_events", "eim_local.smds_register", "eim_local.smds_delete", "eim_local.smds_address")


def _spec(action_id: str):
    from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

    return next(entry for entry in SPECS if entry.id == action_id)


class _Bench(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.pki = Pki()

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": folder.name})
        environment.start()
        self.addCleanup(environment.stop)
        material = mock.patch.object(smds, "bundle_material", return_value=self.pki.material())
        material.start()
        self.addCleanup(material.stop)

    def events(self) -> list[tuple[str, str, str, int]]:
        store = EimStore(self.folder / DATABASE_FILE)
        return [(event.eid, event.event_id, event.rsp_server_address, event.event_type)
                for event in store.smds_events()]


class ShellTests(_Bench):
    def setUp(self) -> None:
        super().setUp()
        self.shell = EimLocalShell()

    def run_line(self, line: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._dispatch_command_line(line, source="test")
        return buffer.getvalue()

    def test_status_names_the_address_the_certificate_and_the_records(self) -> None:
        self.run_line(f"SMDS REGISTER {EID} MID-1")
        output = self.run_line("SMDS")
        self.assertIn(f"[*] Local SM-DS {SMDS_ADDRESS}: 1 Event Record(s) for 1 eUICC(s).", output)
        self.assertIn(f"SM-DS OID {SMDS_OID}; test CERT.DSauth under eSIM CA {self.pki.ci_pkid.hex().upper()[:8]}.",
                      output)
        self.assertIn("Only an eUICC that trusts the SGP.26 test eSIM CA accepts this SM-DS.", output)
        self.assertIn("The service is not running", output)
        self.assertIn(f"EventID MID-1 for {EID} at {SMDP_ADDRESS} (Profile Download), registered ", output)
        self.assertEqual(self.run_line("SMDS STATUS"), output)

    def test_status_without_a_certificate_says_what_es11_answers(self) -> None:
        with mock.patch.object(smds, "bundle_material", return_value=smds.SmdsMaterial()):
            output = self.run_line("SMDS")
        self.assertIn("No Variant O CERT.DSauth.SIG in the SGP.26 bundle", output)
        self.assertIn("SM-DS Certificate - Unavailable", output)

    def test_register_list_and_delete(self) -> None:
        output = self.run_line(f"SMDS REGISTER {EID} MID-1")
        self.assertIn(f"[+] Event Record registered for {EID}: EventID MID-1 at {SMDP_ADDRESS} (Profile Download).",
                      output)
        # the line that follows is the one that retrieves it
        self.assertIn(f"QUEUE DOWNLOAD {EID} contact_smds=on indirect=on smds_address={SMDS_ADDRESS}", output)
        self.run_line(f"SMDS REGISTER {OTHER_EID} EVENT-7 rsp=smdp2.example.test type=rpm")
        self.assertEqual(self.events(), [(EID, "MID-1", SMDP_ADDRESS, 1), (OTHER_EID, "EVENT-7", "smdp2.example.test", 2)])
        listed = self.run_line("SMDS LIST")
        self.assertIn("[*] 2 Event Record(s) at the local SM-DS", listed)
        self.assertIn(f"EventID EVENT-7 for {OTHER_EID} at smdp2.example.test (RPM), registered ", listed)
        one = self.run_line(f"SMDS LIST {EID}")
        self.assertIn(f"[*] 1 Event Record(s) for {EID}", one)
        self.assertNotIn("EVENT-7", one)
        self.assertIn("[+] 1 Event Record(s) deleted: EventID MID-1", self.run_line(f"SMDS DELETE {EID} MID-1"))
        self.assertEqual([event[1] for event in self.events()], ["EVENT-7"])

    def test_an_event_id_is_made_up_when_none_is_given(self) -> None:
        output = self.run_line(f"SMDS REGISTER {EID}")
        match = re.search(r"EventID ([0-9A-F]{16}) at ", output)
        self.assertIsNotNone(match, output)
        self.assertIn("the EventID made up here", output)
        self.assertEqual(self.events(), [(EID, match.group(1), SMDP_ADDRESS, 1)])
        # the key=value form carries an EventID the argument reader would split
        self.run_line(f"SMDS REGISTER {EID} event=A=B")
        self.assertEqual(self.events()[1][1], "A=B")

    def test_refusals_are_printed_and_change_nothing(self) -> None:
        self.run_line(f"SMDS REGISTER {EID} MID-1")
        for line, text in (
            (f"SMDS REGISTER {EID} MID-1", "[!] EventID 'MID-1' is already registered"),
            ("SMDS REGISTER 123 MID-2", "[!] eid: An EID is 32 decimal digits"),
            (f"SMDS REGISTER {EID} MID-2 rsp=https://smdpp.example.test/", "[!] rspServerAddress"),
            (f"SMDS REGISTER {EID} MID-2 type=push", "[!] type is download or rpm."),
            ("SMDS REGISTER", "[!] SMDS REGISTER <eid>"),
            (f"SMDS DELETE {EID} NO-SUCH", "[!] no Event Record 'NO-SUCH'"),
            (f"SMDS DELETE {EID}", "[!] SMDS DELETE <eid> <eventId>"),
            ("SMDS ADDRESS https://smds.example.test", "[!] smds_address"),
            (f"SMDS ADDRESS {SMDP_ADDRESS}", "[!] smdpp.example.test is the address of the local SM-DP+"),
            ("SMDS ADDRESS EIM7.yggdrasim.local", "[!] eim7.yggdrasim.local is a Local eIM name"),
            ("SMDS FROBNICATE", "[!] SMDS [status] | LIST"),
        ):
            with self.subTest(line=line):
                self.assertIn(text, self.run_line(line))
        self.assertEqual(self.events(), [(EID, "MID-1", SMDP_ADDRESS, 1)])

    def test_the_address_is_shown_and_set_without_a_restart_when_nothing_runs(self) -> None:
        self.assertIn(f"[*] Local SM-DS address: {SMDS_ADDRESS}", self.run_line("SMDS ADDRESS"))
        with mock.patch("SCP11.eim_local.engine_shell.restart_background") as restart:
            output = self.run_line("SMDS ADDRESS SMDS2.Example.Test")
        self.assertIn("[+] The local SM-DS answers under smds2.example.test.", output)
        restart.assert_not_called()
        self.assertIn("smds2.example.test", self.run_line("SMDS"))
        self.assertRegex(self.run_line("EIM-SETTINGS"), r"smds_address\s+smds2\.example\.test")

    def test_status_says_when_the_sm_dp_has_the_same_name(self) -> None:
        # the address can still come to collide, through the setting or a change of the SM-DP+ address
        self.run_line(f"EIM-SETTINGS smds_address={SMDP_ADDRESS}")
        output = self.run_line("SMDS")
        self.assertIn(f"[!] Warning: {SMDP_ADDRESS} is also the address of the local SM-DP+, which keeps the name", output)

    def test_a_running_service_is_restarted_under_the_new_name(self) -> None:
        running = {"running": True, "url": "http://127.0.0.1:8743", "smds_address": SMDS_ADDRESS, "log": "-"}
        with mock.patch("SCP11.eim_local.engine_shell.describe", return_value=running), \
                mock.patch("SCP11.eim_local.engine_shell.restart_background") as restart:
            self.assertIn("ES11 is answered at http://127.0.0.1:8743", self.run_line("SMDS"))
            output = self.run_line("SMDS ADDRESS smds2.example.test")
            self.assertIn("The running service was restarted", output)
            restart.assert_called_once_with()
            # the status file of the stubbed service still carries the old name
            self.assertIn("still answers under smds.example.test: SERVE restart", self.run_line("SMDS"))

    def test_the_verb_is_in_the_help_and_opens_no_reader(self) -> None:
        from SCP11.eim_local.engine_shell import DOCS, HELP_SECTIONS

        self.assertIn("SMDS", DOCS)
        self.assertIn("No verb opens a reader.", DOCS["SMDS"]["summary"])
        self.assertTrue(any(key == "SMDS" for _title, entries in HELP_SECTIONS for _usage, key in entries))
        with mock.patch("SCP11.eim_local.engine_shell.EngineVerbs._ensure_channel",
                        side_effect=AssertionError("the SM-DS verbs read no card")):
            self.run_line(f"SMDS REGISTER {EID} MID-1")
            self.run_line("SMDS")
            self.run_line(f"SMDS DELETE {EID} MID-1")


class ActionTests(_Bench):
    def run_action(self, action_id: str, **values: object) -> list[str]:
        return _spec(action_id).dispatcher(None, **values)["lines"]

    def test_the_actions_are_registered_without_a_reader(self) -> None:
        for action_id in ACTIONS:
            spec = _spec(action_id)
            self.assertEqual(spec.subsystem, "Local eIM", action_id)
            self.assertFalse(spec.requires_card, action_id)
            self.assertTrue(all(field.kind != "reader" for field in spec.inputs), action_id)

    def test_register_list_delete_and_address_run_the_verb(self) -> None:
        lines = self.run_action("eim_local.smds_register", eid=EID, event_id="MID-1", rsp="", event_type="download")
        self.assertIn(f"[+] Event Record registered for {EID}: EventID MID-1 at {SMDP_ADDRESS} (Profile Download).",
                      lines)
        # a refusal of the verb is the action's error, and nothing is written
        with self.assertRaises(smds.SmdsError):
            self.run_action("eim_local.smds_register", eid=OTHER_EID, event_id="EVENT 7", rsp="", event_type="rpm")
        self.assertEqual(self.events(), [(EID, "MID-1", SMDP_ADDRESS, 1)])
        self.run_action("eim_local.smds_register", eid=OTHER_EID, event_id="A=B", rsp="smdp2.example.test",
                        event_type="rpm")
        self.assertEqual(self.events()[1], (OTHER_EID, "A=B", "smdp2.example.test", 2))
        status = self.run_action("eim_local.smds_events", eid="")
        self.assertIn(f"[*] Local SM-DS {SMDS_ADDRESS}: 2 Event Record(s) for 2 eUICC(s).", status)
        one = self.run_action("eim_local.smds_events", eid=EID)
        self.assertEqual(one[0], f"[*] 1 Event Record(s) for {EID} at the local SM-DS {SMDS_ADDRESS}.")
        # a line of the result list reads without its columns: the page shows it as running text
        self.assertTrue(one[1].strip().startswith(
            f"EventID MID-1 for {EID} at {SMDP_ADDRESS} (Profile Download), registered "), one[1])
        deleted = self.run_action("eim_local.smds_delete", eid=EID, event_id="MID-1")
        self.assertIn("[+] 1 Event Record(s) deleted: EventID MID-1", deleted[0])
        self.assertEqual(self.run_action("eim_local.smds_address", address=""),
                         [f"[*] Local SM-DS address: {SMDS_ADDRESS}"])
        with mock.patch("SCP11.eim_local.engine_shell.restart_background") as restart:
            changed = self.run_action("eim_local.smds_address", address="smds2.example.test")
        self.assertEqual(changed, ["[+] The local SM-DS answers under smds2.example.test."])
        restart.assert_not_called()

    def test_a_form_without_its_required_values_is_refused_before_the_verb(self) -> None:
        for action_id, values in (("eim_local.smds_register", {"eid": "", "event_id": "X"}),
                                  ("eim_local.smds_delete", {"eid": EID, "event_id": ""}),
                                  ("eim_local.smds_delete", {"eid": "", "event_id": "X"})):
            with self.subTest(action_id=action_id, values=values):
                with self.assertRaises(ValueError):
                    self.run_action(action_id, **values)
        self.assertEqual(self.events(), [])

    def test_the_overview_carries_the_sm_ds_address_of_a_running_service(self) -> None:
        from SCP11.eim_local.engine import overview as overview_module

        running = {"running": True, "answers": True, "url": "http://127.0.0.1:8743", "smds_address": SMDS_ADDRESS,
                   "store": str(self.folder), "log": "-"}
        with mock.patch.object(overview_module.server, "describe", return_value=running):
            self.assertEqual(build_overview(LocalEim(self.folder))["service"]["smds_address"], SMDS_ADDRESS)


class PageAndTierTests(unittest.TestCase):
    def test_the_actions_sit_in_their_tabs_in_the_order_listed(self) -> None:
        center = (REPO / "gui_frontend" / "src" / "js" / "command-center.js").read_text(encoding="utf-8")
        # Operations holds the registry next to the profiles of the local SM-DP+; the name is configuration
        self.assertIn('"queue_settings", "smdp_profiles",\n          "smds_events", "smds_register", "smds_delete",',
                      center)
        self.assertIn('"service_stop", "traffic",\n          "smds_address",', center)
        page = (REPO / "gui_frontend" / "src" / "js" / "local-eim-page.js").read_text(encoding="utf-8")
        self.assertIn('["Local SM-DS address", service.smds_address],', page)
        self.assertIn('["Local SM-DS (TLS)", service.smds_tls_url],', page)

    def test_every_action_gets_a_button_on_the_page(self) -> None:
        # The dashboard leaves out an action whose id contains one of these words anywhere ("status" took the
        # first name of the Local SM-DS action), and the ones the Local eIM page shows itself.
        center = (REPO / "gui_frontend" / "src" / "js" / "command-center.js").read_text(encoding="utf-8")
        skipped = re.search(r"var DASHBOARD_SKIP_SUFFIXES = \[(.*?)\];", center, re.DOTALL)
        folded = re.search(r"var LOCAL_EIM_OVERVIEW_SUFFIXES = \{(.*?)\};", center, re.DOTALL)
        self.assertIsNotNone(skipped)
        self.assertIsNotNone(folded)
        words = re.findall(r'"([a-z0-9_]+)"', skipped.group(1))
        self.assertIn("status", words)
        for action_id in ACTIONS:
            with self.subTest(action_id=action_id):
                self.assertEqual([word for word in words if word in action_id], [])
                self.assertNotRegex(folded.group(1), rf"\b{action_id.rsplit('.', 1)[-1]}\b")

    def test_every_label_has_its_naming_row(self) -> None:
        naming = (REPO / "guides" / "NAMING_CONVENTIONS.md").read_text(encoding="utf-8")
        for action_id in ACTIONS:
            self.assertIn(_spec(action_id).title, naming, action_id)
        self.assertIn("Local SM-DS address", naming)
        self.assertIn("Local SM-DS (TLS)", naming)
        self.assertIn("SM-DS card TLS port", naming)
        self.assertIn("SMDS", naming)

    def test_the_verb_is_a_write_for_an_mcp_client(self) -> None:
        from Tools.YggdraMCP import server

        spec = server._SHELLS["scp11_eim"]
        self.assertIn("SMDS", spec.write)
        self.assertNotIn("SMDS", spec.card_verbs)
        self.assertNotIn("SMDS", spec.read | spec.destructive)


if __name__ == "__main__":
    unittest.main()
