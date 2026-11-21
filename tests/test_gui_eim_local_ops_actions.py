# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local eIM queue actions: registered, placed in a tab, and running the shell verbs.

Each action builds the same argument line the eIM-local shell takes and prints
the same lines; these run against an engine store of their own, no card.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.service import LocalEim
from SCP11.eim_local.engine.store import TrafficRecord
from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS
from yggdrasim_common.gui_server.actions.registry import ActionContext, ensure_builtin_actions_loaded

EID = "89049032123451234512345678901235"
COMMAND_CENTER = Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "command-center.js"


def _run(action_id: str, **values: object) -> list[str]:
    spec = next(entry for entry in SPECS if entry.id == action_id)
    return list(spec.dispatcher(ActionContext(), **values)["lines"])


class RegistrationTests(unittest.TestCase):
    def test_every_action_registers_and_sits_in_a_local_eim_tab(self) -> None:
        registry = ensure_builtin_actions_loaded()
        ids = {spec.id for spec in registry.all()}
        source = COMMAND_CENTER.read_text(encoding="utf-8")
        start = source.index('"Local eIM": [')
        block = source[start:source.index("\n    ],\n", start)]
        suffixes = set(re.findall(r'"([a-z_]+)"', block))
        for spec in SPECS:
            self.assertIn(spec.id, ids)
            self.assertIn(spec.id.rsplit(".", 1)[-1], suffixes, spec.id)


class DispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": folder.name})
        environment.start()
        self.addCleanup(environment.stop)

    def test_identity_queue_edit_cancel_and_lists(self) -> None:
        identity = "\n".join(_run("eim_local.identity_new", eim_id="1.3.6.1.4.1.32473.999.10.124",
                                  eim_fqdn="eim.example.test"))
        self.assertIn("eim.example.test", identity)
        plan = "\n".join(_run("eim_local.op_queue", operation="DELETE", eid=EID, value="8988211111111111129",
                              plan=True))
        self.assertIn("[plan]", plan)
        queued = "\n".join(_run("eim_local.op_queue", operation="ENABLE", eid=EID, value="8988211111111111129",
                                params="rollback=on"))
        operation_id = int(re.search(r"^\s+(\d+)\s+CREATED", queued, re.MULTILINE).group(1))
        edited = "\n".join(_run("eim_local.op_edit", operation_id=operation_id, changes="iccid=8988211111111111112"))
        self.assertIn("edited", edited)
        shown = "\n".join(_run("eim_local.op_show", operation_id=operation_id))
        self.assertIn("8988211111111111112", shown)
        pending = "\n".join(_run("eim_local.op_list", scope="pending"))
        self.assertIn(str(operation_id), pending)
        _run("eim_local.op_cancel", operation_id=operation_id)
        completed = "\n".join(_run("eim_local.op_list", scope="completed"))
        self.assertIn("CANCELED", completed)
        self.assertIn(EID, "\n".join(_run("eim_local.euicc_list")))
        self.assertIn("max_retries", "\n".join(_run("eim_local.queue_settings", changes="max_retries=1")))
        self.assertIn("Not running", "\n".join(_run("eim_local.service_status")))

    def test_confirm_is_required_where_the_card_or_the_record_loses_data(self) -> None:
        with self.assertRaises(ValueError):
            _run("eim_local.euicc_remove", eid=EID, confirm=False)
        with self.assertRaises(ValueError):
            _run("eim_local.associate", reader="", confirm=False)
        with self.assertRaises(ValueError):
            _run("eim_local.associate_handover", reader="", confirm=False, eim_id="2.999.1", sign="OTHER")

    def test_association_choices_list_the_identity_and_the_setups(self) -> None:
        _run("eim_local.identity_new", eim_id="1.3.6.1.4.1.32473.999.10.124", eim_fqdn="eim.example.test")
        _run("eim_local.tls_setup_new", name="other", fqdn="eim-other.example.test", chain="root", trust="root")
        choices = "\n".join(_run("eim_local.associate_choices"))
        self.assertIn("* identity", choices)
        self.assertIn("other                    FQDN eim-other.example.test  trusts root  chain root", choices)
        self.assertIn("Stored certificates for ASSOCIATE HANDOVER", choices)

    def test_traffic_lists_the_recorded_exchanges(self) -> None:
        self.assertIn("No exchanges recorded", "\n".join(_run("eim_local.traffic")))
        engine = LocalEim(Path(os.environ["YGGDRASIM_LOCAL_EIM_STORE"]))
        request = codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(EID)))
        engine.store.insert_traffic(TrafficRecord(
            id=0, at="2026-11-08T20:25:05.911+00:00", peer_host="127.0.0.1", peer_port=40000, listener_port=8744,
            binding="esipa-asn1", path="/gsma/rsp2/asn1", request=request, status=200,
            response=codec.build_get_eim_package_error(codec.NO_EIM_PACKAGE_AVAILABLE), eid=EID,
            note="noEimPackageAvailable"))
        listed = "\n".join(_run("eim_local.traffic", count=5, eid=EID, brief=True))
        self.assertIn("GetEimPackageRequest -> noEimPackageAvailable", listed)
        self.assertNotIn("eimPackageError", listed)
        detailed = "\n".join(_run("eim_local.traffic", hex_bodies=True))
        self.assertIn("02    eimPackageError                noEimPackageAvailable (1)", detailed)
        self.assertIn(request.hex().upper(), detailed)


if __name__ == "__main__":
    unittest.main()
