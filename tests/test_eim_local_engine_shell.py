# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The eIM-local shell's queue verbs, run through the shell's own dispatcher.

QUEUE, OPS, OP, EDIT, MOVE, CANCEL, COPY, PACKAGE-IMPORT, EUICC, IDENTITY,
EIM-SETTINGS and SERVE status work without a card, on an engine store of the
test's own; HELP lists them, and a refusal prints a line instead of ending the
shell. ADD-EIM and DELETE-EIM queue their eCO.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.esipa import handle_asn1
from SCP11.eim_local.engine.service import LocalEim
from SCP11.eim_local.engine.store import TrafficRecord
from SCP11.eim_local.engine.traffic import Verdict
from SCP11.eim_local.main import EimLocalShell

EID = "89049032123451234512345678901235"
TEMPLATES = Path(__file__).resolve().parents[1] / "SCP11" / "eim_local" / "eim_packages" / "templates"


class EngineShellTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": folder.name})
        environment.start()
        self.addCleanup(environment.stop)
        self.shell = EimLocalShell()

    def run_line(self, line: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._dispatch_command_line(line, source="test")
        return buffer.getvalue()

    def queued_id(self, output: str) -> int:
        match = re.search(r"^\s+(\d+)\s+CREATED", output, re.MULTILINE)
        self.assertIsNotNone(match, output)
        return int(match.group(1))

    def test_queue_edit_move_cancel_copy(self) -> None:
        self.assertIn("eim_id", self.run_line("IDENTITY NEW 1.3.6.1.4.1.32473.999.10.124 eim.example.test"))
        first = self.queued_id(self.run_line(f"QUEUE ENABLE {EID} 8988211111111111129 rollback=on"))
        second = self.queued_id(self.run_line(f"QUEUE LIST-PROFILES {EID}"))
        self.assertIn("edited", self.run_line(f"EDIT {first} iccid=8988211111111111112 at=2026-11-06T08:00Z"))
        self.assertIn(f"{second}, {first}", self.run_line(f"MOVE {second} first"))
        detail = self.run_line(f"OP {first}")
        self.assertIn("8988211111111111112", detail)
        self.assertIn("not before : 2026-11-06T08:00:00+00:00", detail)
        self.assertIn("canceled", self.run_line(f"CANCEL {second}"))
        self.assertIn("as a copy of", self.run_line(f"COPY {second}"))
        self.assertIn("ENABLE_PROFILE", self.run_line("OPS all type=ENABLE_PROFILE --json"))

    def test_plan_refresh_records_and_settings(self) -> None:
        self.assertIn("[plan]", self.run_line(f"QUEUE DELETE {EID} 8988211111111111129 --plan"))
        self.assertIn("Queued 3 operation(s)", self.run_line(f"QUEUE REFRESH {EID}"))
        self.assertIn("Registered", self.run_line("EUICC ADD 89049032123451234512345678901299 bench card"))
        self.assertIn("counter 40", self.run_line(f"EUICC SET {EID} counter_value=40"))
        self.assertIn(EID, self.run_line("EUICC"))
        self.assertIn("learn_unknown_eids       True", self.run_line("EIM-SETTINGS learn_unknown_eids=on"))
        self.assertIn("Not running", self.run_line("SERVE status"))

    def test_package_import_queues_what_a_document_stands_for(self) -> None:
        psmos = TEMPLATES / "template_euicc_package_request_psmos.json"
        self.assertIn("[plan] PSMO_RAW", self.run_line(f"PACKAGE-IMPORT {psmos} {EID} --plan"))
        self.assertIn("Queued 1 operation(s) from 1 document(s)", self.run_line(f"PACKAGE-IMPORT {psmos} {EID}"))
        # an IpaEuiccDataRequest document (SGP.32 v1.3 section 2.11.1.2) in the templates' shape, built
        # here: the template of that type is not part of the tracked tree
        wrapped = self.folder / "ipa_euicc_data_request.json"
        wrapped.write_text(json.dumps({
            "package_type": "ipa_euicc_data_request",
            "package_version": "1.0.0",
            "sgp32": {"ipa_euicc_data_request": {
                "include": True, "command_tag_hex": "BF52",
                "tag_list": {"include": True, "tag_hex": "5C", "items": {
                    "notifications": {"include": True, "tag_hex": "A0"},
                    "euicc_package_results": {"include": True, "tag_hex": "A2"}}}}}}))
        self.assertIn("Queued 1", self.run_line(f"PACKAGE-IMPORT {wrapped} {EID}"))
        listing = self.run_line("OPS all --json")
        self.assertIn("PSMO_RAW", listing)
        self.assertIn("IPA_EUICC_DATA", listing)
        configuration = TEMPLATES / "template_euicc_package_request_eim_configuration_data.json"
        self.assertIn("psmoList or an ecoList", self.run_line(f"PACKAGE-IMPORT {configuration} {EID}"))

    def test_add_and_delete_eim_queue_their_eco(self) -> None:
        self.run_line("IDENTITY NEW 1.3.6.1.4.1.32473.999.10.124 eim.example.test")
        self.assertIn("Delete eIM 2.999.1", self.run_line(f"DELETE-EIM {EID} 2.999.1"))
        self.assertIn("Unknown command: ISDR-DELETE-EIM", self.run_line("ISDR-DELETE-EIM 2.999.1"))
        refused = self.run_line(f"ADD-EIM {EID} 2.999.1 eim_id_type=not-a-type")
        self.assertIn("[!]", refused)
        self.assertNotIn("Queued", refused)

    def test_the_card_session_gets_the_ipad_declaration_once_and_again_after_a_reset(self) -> None:
        from SCP11.eim_local.config import EimLocalConfig
        from SCP11.eim_local.engine_shell import EngineVerbs
        from SCP11.eim_local.session import EimLocalSession
        from SCP11.shared.eim_configuration_data import TERMINAL_CAPABILITY_IPAD

        class Channel:
            def __init__(self) -> None:
                self.sent: list[bytes] = []
                self.resets = 0

            def send(self, apdu: bytes, _label: str) -> bytes:
                self.sent.append(bytes(apdu))
                if apdu[:4] == b"\x80\xCA\x00\x5A":
                    # GET DATA '5A' on the ECASD, the EID read the session starts with.
                    return bytes.fromhex("5A10" + EID)
                if apdu[:2] == b"\x80\xE2":
                    return bytes.fromhex("BF3E125A10" + EID)
                return b""

            def reset(self) -> bool:
                self.resets += 1
                return True

        channel = Channel()
        session = EimLocalSession(cfg=EimLocalConfig(), apdu_channel=channel)
        verbs = EngineVerbs(type("Shell", (), {"session": session})(), emit=lambda _line: None)
        self.assertEqual(verbs._card_eid(), EID)
        verbs._exchange(bytes.fromhex("BF3E035C015A"), "GetEID again")
        # TS 102 221 v18.4 §11.1.19 TERMINAL CAPABILITY first, once, before the ISD-R SELECT and the STORE DATA.
        self.assertEqual(channel.sent[0], TERMINAL_CAPABILITY_IPAD)
        self.assertEqual(channel.sent.count(TERMINAL_CAPABILITY_IPAD), 1)
        self.assertTrue(verbs._reset_card())
        verbs._exchange(bytes.fromhex("BF3E035C015A"), "GetEID after the reset")
        self.assertEqual(channel.sent.count(TERMINAL_CAPABILITY_IPAD), 2)
        self.assertEqual(channel.sent[-3], TERMINAL_CAPABILITY_IPAD)

    def test_traffic_lists_the_exchanges_and_op_describes_the_package(self) -> None:
        self.assertIn("No exchanges recorded", self.run_line("TRAFFIC"))
        self.run_line("IDENTITY NEW 1.3.6.1.4.1.32473.999.10.124 eim.example.test")
        self.queued_id(self.run_line(f"QUEUE ENABLE {EID} 8988211111111111129 rollback=on"))
        engine = LocalEim(self.folder)
        request = codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(EID)))
        # A card the eIM has not read yet is asked for its data first (a system operation); that is the
        # exchange the service would have recorded.
        verdict = Verdict()
        status, answer = handle_asn1(engine, request, verdict=verdict)
        served = verdict.operation_id
        self.assertIsNotNone(served)
        engine.store.insert_traffic(TrafficRecord(
            id=0, at="2026-11-08T20:25:05.911+00:00", peer_host="127.0.0.1", peer_port=40000, listener_port=8744,
            tls_setup="alpha", tls_version="TLSv1.2", binding="esipa-asn1", path="/gsma/rsp2/asn1", request=request,
            status=status, response=answer, duration_ms=3, eid=EID, operation_id=served, note=verdict.note))
        listed = self.run_line("TRAFFIC")
        self.assertIn("[*] 1 exchange(s), oldest first:", listed)
        self.assertIn("127.0.0.1:40000       alpha        GetEimPackageRequest -> IpaEuiccDataRequest tagList "
                      "eumCertificate, euiccCertificate, euiccInfo2", listed)
        self.assertIn("BF52  IpaEuiccDataRequest", listed)
        self.assertIn(f"operation {served}, served operation {served} (IPA_EUICC_DATA)", listed)
        self.assertNotIn("BF52  IpaEuiccDataRequest", self.run_line("TRAFFIC --brief"))
        self.assertIn(request.hex().upper(), self.run_line("TRAFFIC --hex"))
        self.assertEqual(json.loads(self.run_line("TRAFFIC --json"))[0]["operation_id"], served)
        self.assertIn("No exchanges recorded", self.run_line(f"TRAFFIC eid={EID[:-1]}5 op=99"))
        detail = self.run_line(f"OP {served}")
        self.assertIn("served     :", detail)
        self.assertIn("BF52  IpaEuiccDataRequest            tagList eumCertificate, euiccCertificate, euiccInfo2",
                      detail)

    def test_refusals_print_and_help_lists_the_verbs(self) -> None:
        self.assertIn("[!]", self.run_line("EDIT 999 iccid=8988211111111111129"))
        self.assertIn("[!]", self.run_line(f"QUEUE NOT-AN-OPERATION {EID}"))
        help_text = self.run_line("HELP")
        for verb in ("QUEUE", "OPS", "SERVE", "DELIVER", "ASSOCIATE"):
            self.assertIn(verb, help_text)


if __name__ == "__main__":
    unittest.main()
