# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The GUI's listener for injected eIM Packages, and what the reader it holds does to other actions.

``scp11_live.eim_listen`` runs the console verb EIM-LISTEN as a stream. The
stream's stop flag is what Cancel, a closed page and a server shutdown set,
so the tests end the listener by that flag alone and then look at the port
and at the card channel. While the stream holds a reader, an action that
would open it is refused by the route, and one that drives no card is not.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import http.client
import io
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from SCP11.eim_local.engine.service import LocalEim, LocalEimError
from SCP11.eim_local.engine_shell import EngineVerbs
from SCP11.live import console as live_console
from SCP11.live.orchestrator import SGP22Orchestrator
from SCP11.shared import esipa_transfer as transfer
from tests.test_local_eim_engine import EIM_ID, SimCard
from tests.test_scp11_orchestrator import TEST_EID, FakeApduChannel, FakeCfg, FakeProvider
from yggdrasim_common import reader_claims
from yggdrasim_common.cancellation import attach_cancel_event
from yggdrasim_common.gui_server.actions import eim_local_ops, scp11_live
from yggdrasim_common.gui_server.actions.registry import ActionContext, ensure_builtin_actions_loaded
from yggdrasim_common.gui_server.routes import actions as actions_routes

ACKNOWLEDGEMENT = bytes.fromhex("BF4E09BF5306800101800102")
RESULT = bytes.fromhex("BF511AA218801065696D2E6578616D706C652E746573748204A1A2A3A4")
SOURCE = Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "command-center.js"


def _node(script: str):
    """Run *script* under node and return what it printed as JSON; the test is skipped without node."""
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("node is not installed")
    done = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30, check=True)
    return json.loads(done.stdout)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _post(port: int, body: bytes = ACKNOWLEDGEMENT, content_type: str = transfer.CONTENT_TYPE_ASN1) -> int:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("POST", transfer.PATH_ASN1, body=body, headers={
            "Content-Type": content_type, "X-Admin-Protocol": transfer.ADMIN_PROTOCOL})
        response = connection.getresponse()
        response.read()
        return int(response.status)
    finally:
        connection.close()


class _Stream:
    """One run of the action's dispatcher on a loop of its own, its events collected as they come."""

    def __init__(self, inputs: dict, cancel: threading.Event) -> None:
        self.events: list[dict] = []
        self.finished_at = 0.0

        async def consume() -> None:
            ctx = ActionContext(extras={"cancel_event": cancel})
            async for event in scp11_live.EIM_LISTEN_SPEC.dispatcher(ctx, **inputs):
                self.events.append(event)

        def run() -> None:
            loop = asyncio.new_event_loop()
            executor = ThreadPoolExecutor(max_workers=4)
            loop.set_default_executor(executor)
            try:
                loop.run_until_complete(consume())
            finally:
                self.finished_at = time.monotonic()
                executor.shutdown(wait=True)
                loop.close()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def messages(self) -> list[str]:
        return [str(event.get("message", "")) for event in list(self.events)]

    def wait_for(self, text: str, seconds: float = 10.0) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if any(text in message for message in self.messages()):
                return True
            time.sleep(0.02)
        return False

    def end(self, seconds: float = 15.0) -> dict:
        self.thread.join(timeout=seconds)
        assert not self.thread.is_alive(), self.messages()
        return self.events[-1]


class ListenStreamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.closed_at: list[float] = []
        self.eid = TEST_EID
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(),
                                         profile_provider=FakeProvider(bpp_bytes=b""))
        orchestrator._phase_connect = lambda: None
        orchestrator._read_card_eid = lambda reselect_isdr=True: self.eid
        orchestrator._relay_eim_package_to_card = lambda package, **_arguments: RESULT
        orchestrator._remove_notification_from_list = lambda _seq_number: None
        orchestrator._close_es10b_logical_channel = lambda _scope: None
        client = SimpleNamespace(
            cfg=SimpleNamespace(READER_INDEX=0, READER_NAME="", RSP_SERVER_URL="rsp.example.test",
                                ES9_BASE_URL="https://rsp.example.test", ES9_VERIFY_TLS=True, ES9_CA_BUNDLE_PATH=""),
            apdu_channel=SimpleNamespace(),
            orchestrator=orchestrator,
        )
        self.console = live_console.SCP11Console(client)
        self.console._style = live_console.ConsoleStyle("", "", "", "", "", "", "")
        # The session policy of the registered verb is the shell's own; the handler is what runs here.
        self.console._execute_command = lambda _command, argument: self.console._cmd_eim_listen(argument)
        for patch in (
            mock.patch.object(scp11_live, "_build_console", lambda _index, _name="": (self.console, object())),
            mock.patch.object(scp11_live, "_close_apdu_channel", lambda _channel: self.closed_at.append(time.monotonic())),
            mock.patch.object(scp11_live, "_resolve_reader_index", lambda _name: 0),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.cancel = threading.Event()
        self.addCleanup(self.cancel.set)
        self.port = _free_port()

    def start(self, **inputs: object) -> _Stream:
        stream = _Stream({"reader": "", "port": self.port, **inputs}, self.cancel)
        self.addCleanup(lambda: (self.cancel.set(), stream.thread.join(timeout=15)))
        return stream

    def assert_port_closed(self) -> None:
        with self.assertRaises(OSError):
            _post(self.port)

    def test_the_stop_flag_ends_the_listener_and_the_stream_ends_after_the_card_is_released(self) -> None:
        stream = self.start()
        self.assertTrue(stream.wait_for(f"listening on http://127.0.0.1:{self.port} for EID {TEST_EID}."), stream.messages())
        self.assertEqual(_post(self.port), 200)
        self.assertTrue(stream.wait_for("the eIM acknowledged 1, 2"))
        # What Cancel, a closed page and a server shutdown all do: set the run's stop flag.
        self.cancel.set()
        last = stream.end()
        self.assertEqual((last["level"], last["message"], last["ok"], last.get("cancelled")),
                         ("done", "EIM-LISTEN ended.", True, True))
        self.assertTrue(any("eIM package injection: stopped after 1 call(s)." in text for text in stream.messages()))
        self.assert_port_closed()
        self.assertEqual(len(self.closed_at), 1)
        self.assertLessEqual(self.closed_at[0], stream.finished_at)
        self.assertEqual(stream.messages()[0], f"EIM-LISTEN: reader=(default) port={self.port} notifications=deliver")

    def test_it_ends_by_itself_after_the_calls_asked_for(self) -> None:
        stream = self.start(calls=1, notifications="keep")
        self.assertTrue(stream.wait_for("listening on"))
        self.assertTrue(stream.wait_for("Pending Notifications are left on the eUICC (notifications=keep)."))
        self.assertEqual(_post(self.port), 200)
        last = stream.end()
        self.assertEqual((last["level"], last["ok"], last.get("cancelled")), ("done", True, None))
        self.assert_port_closed()

    def test_a_caller_it_refuses_does_not_fail_the_run(self) -> None:
        stream = self.start()
        self.assertTrue(stream.wait_for("listening on"))
        self.assertEqual(_post(self.port, content_type="text/plain"), 415)
        self.assertTrue(stream.wait_for("[!] TransferEimPackage: request refused"))
        self.cancel.set()
        self.assertTrue(stream.end()["ok"])

    def test_a_listener_that_cannot_start_fails_the_stream(self) -> None:
        self.eid = ""
        stream = self.start()
        last = stream.end()
        self.assertEqual((last["level"], last["ok"]), ("done", False))
        self.assertTrue(any("[!] EIM-LISTEN failed: the eUICC gave no EID" in text for text in stream.messages()))
        self.assert_port_closed()

    def test_the_console_verb_hands_the_stop_flag_to_the_listener(self) -> None:
        seen: list[dict] = []
        self.console.orchestrator.run_eim_listen = lambda **options: seen.append(options) or 0
        flag = threading.Event()
        attach_cancel_event(self.console, flag)
        with contextlib.redirect_stdout(io.StringIO()):
            self.console._cmd_eim_listen("port=0")
        self.assertIs(seen[0]["stop"], flag)
        self.assertTrue(self.console._last_eim_listen_ok)


class FormTests(unittest.TestCase):
    def test_the_form_asks_for_a_loopback_listener_and_nothing_else(self) -> None:
        spec = scp11_live.EIM_LISTEN_SPEC
        self.assertEqual((spec.id, spec.subsystem, spec.title, spec.streams, spec.requires_card),
                         ("scp11_live.eim_listen", "eSIM Management", "Listen for injected eIM packages", True, True))
        self.assertEqual([field.name for field in spec.inputs], ["reader", "port", "notifications", "calls", "idle"])
        self.assertEqual(spec.inputs[0].kind, "reader")
        self.assertEqual((spec.inputs[2].choices, spec.inputs[2].default), (["deliver", "keep"], "deliver"))
        self.assertIn("the one an injected enable or disable creates included", spec.description)

    def test_the_options_are_built_here_and_take_numbers_only(self) -> None:
        build = scp11_live._eim_listen_argument
        self.assertEqual(build(None, None, None, None), "port=8746 notifications=deliver")
        self.assertEqual(build("", "", "", ""), "port=8746 notifications=deliver")
        self.assertEqual(build(0, "KEEP", 0, 0), "port=0 notifications=keep")
        self.assertEqual(build("8750", "keep", "2", "30"), "port=8750 notifications=keep calls=2 idle=30")
        # A field cannot carry another option of the verb (an address, a file).
        for arguments in (("8746 host=0.0.0.0", "deliver", None, None), (8746, "deliver", "2 cert=/tmp/x", None),
                          (8746, "deliver", None, "5 key=/tmp/x"), (8746, "drop", None, None)):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    build(*arguments)

    def test_the_action_sits_in_the_ipad_tab(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        table_start = source.index("  var CC_ACTION_GROUPS_BY_SUBSYSTEM = {")
        table = source[table_start:source.index("\n  };\n", table_start) + len("\n  };\n")]
        suffix_start = source.index("  function ccActionSuffix(actionId) {")
        suffix = source[suffix_start:source.index("\n  }\n", suffix_start) + len("\n  }\n")]
        start = source.index("  function ccGroupActionsForSubsystem(")
        functions = source[start:source.index("  var CC_ESIM_ACTION_FLAVORS", start)]
        actions = [{"id": spec.id, "title": spec.title, "tags": list(spec.tags)}
                   for spec in ensure_builtin_actions_loaded().by_subsystem().get("eSIM Management", [])
                   if spec.id.startswith("scp11_live.")]
        page = _node(table + suffix + functions + (
            "var grouped = ccGroupActionsForSubsystem('eSIM Management', %s) || [];"
            "console.log(JSON.stringify(grouped.map(function (bucket) {"
            " return [bucket.group.id, bucket.items.map(function (item) { return item.id; })]; })));"
        ) % json.dumps(actions))
        placed = {group_id: items for group_id, items in page}
        self.assertIn("scp11_live.eim_listen", placed["esim-sgp32-iot"])
        self.assertEqual(sum(items.count("scp11_live.eim_listen") for items in placed.values()), 1)


class KeptStreamTests(unittest.TestCase):
    """A running stream keeps its form: the page's own registry under node, and where the page uses it."""

    HARNESS = """
var commandState = {};
var buttons = %s.map(function (id) {
  var classes = {};
  var attributes = {"data-cc-action-id": id};
  return {
    id: id, classes: classes, attributes: attributes,
    classList: { toggle: function (name, on) { classes[name] = !!on; }, add: function (name) { classes[name] = true; } },
    getAttribute: function (name) { return attributes[name]; },
    setAttribute: function (name, value) { attributes[name] = value; },
    removeAttribute: function (name) { delete attributes[name]; },
  };
});
var document = { querySelectorAll: function () { return buttons; } };
%s
var listen = { id: "scp11_live.eim_listen", subsystem: "eSIM Management" };
var root = { kept: true };
var steps = [];
function snapshot(label) {
  var here = ccLiveStreamIn("eSIM Management");
  steps.push([label,
              buttons.map(function (b) { return [b.id, !!b.classes["is-running"], b.attributes["aria-description"] || ""]; }),
              !!ccLiveStreamFor(listen.id), !!here && here.root === root, !!ccLiveStreamIn("Local eIM")]);
}
snapshot("before");
var release = ccKeepLiveStream(listen, root);
snapshot("running");
release();
snapshot("ended");
release();
snapshot("released twice");
var nothing = ccKeepLiveStream(null, root);
console.log(JSON.stringify({ steps: steps, nothing: typeof nothing === "function" && ccLiveStreams().length === 0 }));
"""

    def test_the_registry_keeps_a_stream_until_it_ends_and_marks_its_button(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("  function ccLiveStreams() {")
        helpers = source[start:source.index("  function ccCardStreamOn(readerName) {", start)]
        ids = ["scp11_live.eim_listen", "scp11_live.eim_download"]
        page = _node(self.HARNESS % (json.dumps(ids), helpers))
        idle = [["scp11_live.eim_listen", False, ""], ["scp11_live.eim_download", False, ""]]
        running = [["scp11_live.eim_listen", True, "running"], ["scp11_live.eim_download", False, ""]]
        self.assertEqual(page["steps"], [
            ["before", idle, False, False, False],
            ["running", running, True, True, False],
            ["ended", idle, False, False, False],
            ["released twice", idle, False, False, False],
        ])
        self.assertTrue(page["nothing"])

    def test_the_page_puts_the_kept_form_back_and_lets_go_of_it_when_the_stream_closes(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        opener = source[source.index("    function _openEsimActionPane(action) {"):]
        opener = opener[:opener.index("    function _createInlineActionPane() {")]
        # Opening an action whose stream runs shows its own form again, before anything is built or run anew.
        self.assertLess(opener.index("var live = ccLiveStreamFor(action.id);"),
                        opener.index("if (ccActionShouldAutoRunInEsimFlowPane(action)) {"))
        self.assertIn("liveBody.appendChild(live.root);\n        return;", opener)
        # A module entered while one of its streams runs shows that stream.
        self.assertIn("var runningHere = useEsimSplitPane ? ccLiveStreamIn(subsystem) : null;\n"
                      "      if (runningHere) _openEsimActionPane(runningHere.action);", source)
        runner = source[source.index("  function runStreamingAction(action, inputs, statusEl, resultEl, card, form) {"):]
        runner = runner[:runner.index("  function renderReportSummary(report) {")]
        self.assertIn("releaseLiveStream = ccKeepLiveStream(action, form);", runner)
        closing = runner[runner.index("sock.onclose = function () {"):]
        self.assertIn("releaseLiveStream();", closing[:closing.index("sock.onerror = function () {")])
        # The pane a status goes to is looked up when it is written: the form may have moved.
        status = runner[runner.index("function setInlinePaneStatus(text) {"):]
        self.assertIn('resultEl.closest(".cc-esim-flow-pane")', status[:status.index("if (runBtn) runBtn.disabled = true;")])
        self.assertIn('btn.setAttribute("data-cc-action-id", action.id);', source)

    def test_the_mark_takes_the_colour_of_the_button_text(self) -> None:
        css = (SOURCE.parents[1] / "css" / "views" / "command-center-compact-pane.css").read_text(encoding="utf-8")
        rule = css[css.index(".cc-compact-rbtn.is-running .cc-compact-rbtn-label::after {"):]
        rule = rule[:rule.index("}")]
        self.assertIn("background: currentColor;", rule)
        self.assertNotIn("#", rule.replace("/*", "").split("background")[1])


class _DefaultReader:
    def __str__(self) -> str:
        return "R"


class ReaderClaimTests(unittest.TestCase):
    """With the listener's stream holding reader R: who is refused, and who needs no reader."""

    def setUp(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        real = {spec.id: spec for spec in eim_local_ops.SPECS}
        real["scp11_live.scan"] = scp11_live.get_registry().get("scp11_live.scan")
        self.specs = {}
        for action_id, spec in real.items():
            def record(ctx, _id=action_id, **inputs):
                self.calls.append((_id, inputs))
                return {"lines": ["ran"]}
            self.specs[action_id] = dataclasses.replace(spec, dispatcher=record)
        for patch in (
            mock.patch.dict("os.environ", {"YGGDRASIM_CARD_BACKEND": "reader"}),
            mock.patch.object(actions_routes, "ensure_builtin_actions_loaded",
                              lambda: SimpleNamespace(get=lambda action_id: self.specs.get(action_id))),
            mock.patch("smartcard.System.readers", return_value=[_DefaultReader()]),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        token = reader_claims.claim("R", scp11_live.EIM_LISTEN_SPEC.title, long_running=True)
        self.addCleanup(lambda: self.assertEqual(reader_claims.claimed_readers(), {}))
        self.addCleanup(reader_claims.release, "R", token)

    def run_action(self, action_id: str, **inputs: object):
        loop = asyncio.new_event_loop()
        executor = ThreadPoolExecutor(max_workers=4)
        loop.set_default_executor(executor)
        try:
            return loop.run_until_complete(
                actions_routes.run_action(action_id, actions_routes.RunRequest(inputs=dict(inputs))))
        finally:
            executor.shutdown(wait=True)
            loop.close()

    def test_an_action_that_would_open_the_reader_is_refused_before_it_runs(self) -> None:
        for action_id, inputs in (
            ("eim_local.op_queue", {"operation": "LIST-PROFILES", "reader": "R"}),
            # No reader named is the first reader, which is R here.
            ("eim_local.op_queue", {"operation": "LIST-PROFILES", "reader": ""}),
            ("eim_local.op_queue", {"operation": "LIST-PROFILES"}),
            ("eim_local.package_import", {"source": "/tmp/package.json", "reader": "R"}),
            ("eim_local.deliver", {"reader": "R"}),
            ("eim_local.deliver", {}),
            ("eim_local.euicc_read", {"reader": "R"}),
            ("scp11_live.scan", {"reader": "R"}),
            ("scp11_live.scan", {}),
        ):
            with self.subTest(action=action_id, inputs=inputs):
                started = time.monotonic()
                response = self.run_action(action_id, **inputs)
                self.assertLess(time.monotonic() - started, 2.0)
                self.assertFalse(response.ok)
                self.assertTrue(str(response.error).startswith(
                    "reader busy: Listen for injected eIM packages has held 'R' since "), response.error)
        self.assertEqual(self.calls, [])

    def test_queueing_for_a_named_euicc_and_injecting_need_no_reader(self) -> None:
        eid = "89049032123451234512345678901235"
        for action_id, inputs in (
            ("eim_local.op_queue", {"operation": "LIST-PROFILES", "eid": eid, "reader": "R"}),
            ("eim_local.op_queue", {"operation": "LIST-PROFILES", "eid": eid}),
            ("eim_local.op_queue", {"operation": "LIST-PROFILES", "eid_file": "/tmp/eids.txt"}),
            ("eim_local.package_import", {"source": "/tmp/package.json", "eid": eid}),
            ("eim_local.inject", {"eid": eid}),
            ("eim_local.inject_cert", {}),
            ("eim_local.op_list", {}),
        ):
            with self.subTest(action=action_id, inputs=inputs):
                self.calls.clear()
                response = self.run_action(action_id, **inputs)
                self.assertTrue(response.ok, response.error)
                self.assertEqual([entry[0] for entry in self.calls], [action_id])

    def test_the_rule_a_spec_gives_is_the_rule_its_dispatcher_follows(self) -> None:
        eid = "89049032123451234512345678901235"
        readers: list[object] = []
        with mock.patch.object(eim_local_ops, "_run", lambda _verb, _argument, reader=None: readers.append(reader) or {}):
            spec = {entry.id: entry for entry in eim_local_ops.SPECS}
            for action_id, inputs in (
                ("eim_local.op_queue", {"operation": "LIST-PROFILES", "reader": "R"}),
                ("eim_local.op_queue", {"operation": "LIST-PROFILES", "eid": eid, "reader": "R"}),
                ("eim_local.op_queue", {"operation": "LIST-PROFILES", "eid_file": "/tmp/eids.txt", "reader": "R"}),
                ("eim_local.package_import", {"source": "/tmp/package.json", "reader": "R"}),
                ("eim_local.package_import", {"source": "/tmp/package.json", "eid": eid, "reader": "R"}),
            ):
                with self.subTest(action=action_id, inputs=inputs):
                    readers.clear()
                    spec[action_id].dispatcher(ActionContext(), **inputs)
                    opened = readers[0] is not None
                    self.assertEqual(opened, spec[action_id].uses_reader(inputs))
        self.assertEqual([entry.id for entry in eim_local_ops.SPECS if entry.uses_reader is not None],
                         ["eim_local.op_queue", "eim_local.package_import"])


class NoReaderRunTests(unittest.TestCase):
    """A call the route claimed no reader for cannot come to open one, whatever its fields hold.

    Queue with an EID field is such a call. The verb reads the card whenever
    that field does not read as an EID, so the run itself has to be unable to:
    the real dispatchers run here, on a store of the test's own, with the
    listener's claim held and the channel classes standing for the reader.
    """

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.opened = mock.Mock(side_effect=AssertionError("the reader was opened"))
        for patch in (
            mock.patch.dict("os.environ", {"YGGDRASIM_CARD_BACKEND": "reader", "YGGDRASIM_LOCAL_EIM_STORE": folder.name}),
            mock.patch("smartcard.System.readers", return_value=[_DefaultReader()]),
            mock.patch("SCP11.transport.PcscApduChannel", self.opened),
            mock.patch("SCP11.live.transport.PcscApduChannel", self.opened),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.engine = LocalEim()
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)
        # The fallback a shell takes when its reader is held must not be open to this call either.
        self.engine.set_inject_target(self.card.eid, "http://127.0.0.1:8746")
        token = reader_claims.claim("R", scp11_live.EIM_LISTEN_SPEC.title, long_running=True)
        self.addCleanup(lambda: self.assertEqual(reader_claims.claimed_readers(), {}))
        self.addCleanup(reader_claims.release, "R", token)

    def run_action(self, action_id: str, **inputs: object):
        loop = asyncio.new_event_loop()
        executor = ThreadPoolExecutor(max_workers=4)
        loop.set_default_executor(executor)
        try:
            return loop.run_until_complete(
                actions_routes.run_action(action_id, actions_routes.RunRequest(inputs=dict(inputs))))
        finally:
            executor.shutdown(wait=True)
            loop.close()

    def queued(self) -> list[str]:
        return [operation.eid for operation in LocalEim().operations() if operation.state == "CREATED"]

    def test_an_eid_field_that_is_no_eid_reads_no_card_and_queues_nothing(self) -> None:
        for inputs in (
            {"operation": "LIST-PROFILES", "eid": "123"},
            {"operation": "LIST-PROFILES", "eid": "123", "reader": "R"},
            {"operation": "LIST-PROFILES", "eid": "8988211111111111112"},
            {"operation": "ENABLE", "eid": "not-an-eid", "value": "8988211111111111112"},
        ):
            with self.subTest(inputs=inputs):
                response = self.run_action("eim_local.op_queue", **inputs)
                self.assertFalse(response.ok)
                self.assertNotIn("reader busy", str(response.error))
                self.assertIn("No EID was given that reads as one (32 digits)", str(response.error))
        response = self.run_action("eim_local.package_import", source="/tmp/absent-package.json", eid="123")
        self.assertFalse(response.ok)
        self.opened.assert_not_called()
        self.assertEqual(self.queued(), [])

    def test_the_named_euicc_is_queued_for_while_the_listener_holds_the_reader(self) -> None:
        response = self.run_action("eim_local.op_queue", operation="LIST-PROFILES", eid=self.card.eid, reader="R")
        self.assertTrue(response.ok, response.error)
        self.assertEqual(self.queued(), [self.card.eid])
        self.opened.assert_not_called()

    def test_a_run_without_a_reader_refuses_to_open_a_channel_at_all(self) -> None:
        verbs = EngineVerbs(eim_local_ops._Shell(eim_local_ops._offline_session()), emit=lambda _line: None)
        for call in (verbs._ensure_channel, verbs._card_eid, verbs._unnamed_eid):
            with self.subTest(call=call.__name__):
                with self.assertRaises(LocalEimError):
                    call()
        self.opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
