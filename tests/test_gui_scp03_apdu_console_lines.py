# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The raw APDU console takes one APDU per line and reads each command.

The console input holds one command per line, '#' starting a comment (the
script format the SCP03 shell's RUN reads). Every line gets a row in the
breakdown table, with the Offline Tools context decoder's reading of the
command beside its fields, and Send transmits the lines one after the other.
A run goes on after normal processing and warnings and stops at the first
error status word (ETSI TS 102 221 v18.4 §10.2.1), at a failed send, a
transport failure or an ended secure channel. Every preset is a well-framed
APDU: GET STATUS carries the '4F 00' search criterion of GPC v2.3.1 §11.4.2.3
and SELECT MNO-SD the default ISD AID of GPC v2.3.1 Annex H.1.3. The OTA
"Concatenated SMS" choice offers the two values SCP80/config.py stores. The
helpers run under ``node`` from the built bundle; the decoder fixtures come
from the decoder itself.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from typing import Any

from Tools.Asn1TlvDecode.context import decode_context_text
from Tools.Asn1TlvDecode.main import DecodeError, _parse_apdu_body
from tests.test_gui_saip_fcp_record_count_view import _function

_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_COMMAND_CENTER = _REPO_ROOT / "gui_frontend" / "src" / "js" / "command-center.js"

_FUNCTIONS = (
    "scp03NormaliseApduInput",
    "scp03ParseApduLines",
    "scp03ApduSwStopsBatch",
    "scp03ApduCommandText",
    "scp03BreakdownApdu",
    "scp03SendApduBatch",
    "scp03PushApduHistory",
    "otaOnOff",
)

_DECODED_LINES = ("00A4080C022FE2", "00B000000A", "00A4040008A000000151000000", "00A40004023F")


def _presets() -> list[tuple[str, str]]:
    source = _COMMAND_CENTER.read_text(encoding="utf-8")
    block = source.split("var SCP03_APDU_PRESETS = [", 1)[1].split("];", 1)[0]
    return re.findall(r'label: "([^"]+)",\s*apdu: "([0-9A-F]+)"', block)


_HARNESS = r"""
(async function () {
  var calls = [];
  var script = [];
  async function apiFetch(path, options) {
    var body = JSON.parse(options.body);
    calls.push(body.inputs.apdu);
    var next = script.shift();
    if (next instanceof Error) throw next;
    return next;
  }
  var logBus = { emit: function () {} };
  var painted = 0;
  function scp03ApduLiveHost() { return null; }
  function scp03RenderApduResults() { painted += 1; }
  function scp03RenderApduHistory() {}
  var document = { getElementById: function () { return null; } };
  function _localEimText(value) { return String(value == null ? "" : value).trim(); }
  function ok(sw, extra) {
    return { ok: true, data: Object.assign({ apdu: "", sw: sw, ok: sw.substring(0, 2) === "90",
                                              response_length: 0, sw_meaning: "" }, extra || {}) };
  }
  async function run(responses, stopOnError) {
    calls = [];
    script = responses.slice();
    var tab = { sessionId: "s1", apduHistory: [] };
    var commands = ["00A4080C022FE2", "00B000000A", "00B0000004"].map(function (hex, i) {
      return { line: i + 2, hex: hex, issues: [] };
    });
    await scp03SendApduBatch(tab, commands, { follow61: true, retry6c: true, wireTrace: false,
                                              stopOnError: stopOnError });
    return { calls: calls, note: tab.apduBatchNote, running: tab.apduBatchRunning,
             history: tab.apduHistory.length,
             results: tab.apduLastResults.map(function (entry) {
               return [entry.index, entry.line, entry.pending, entry.error || (entry.data && entry.data.sw)];
             }) };
  }

__DEFS__

  var F = __FIXTURES__;
  var out = {};
  out.lines = scp03ParseApduLines(F.input);
  out.stops = {};
  F.sws.forEach(function (sw) { out.stops[sw] = scp03ApduSwStopsBatch(sw); });
  out.texts = F.exchanges.map(scp03ApduCommandText);
  out.presetsValid = F.presets.map(function (apdu) { return scp03BreakdownApdu(apdu).valid; });
  out.batchStops = await run([ok("9000"), ok("6A82"), ok("9000")], true);
  out.batchGoesOn = await run([ok("9000"), ok("6A82"), ok("9000")], false);
  out.batchWarning = await run([ok("9000"), ok("6282"), ok("9000")], true);
  out.batchTransport = await run([ok("9000", { transport_error: "reader removed" }), ok("9000")], false);
  out.batchRefused = await run([{ ok: false, error: "no session" }], true);
  out.batchThrown = await run([ok("9000"), new Error("HTTP 500")], true);
  out.onOff = ["on", "ON", "true", "Yes", "1", "off", "false", "No", "0", "", "maybe"].map(otaOnOff);
  process.stdout.write(JSON.stringify(out));
})().catch(function (err) {
  process.stderr.write(String((err && err.stack) || err));
  process.exit(1);
});
"""

_STOP_SWS = (
    "9000", "9110", "9201", "6282", "63C2", "6110", "9F10",
    "9300", "6400", "6581", "6700", "6982", "6A82", "6B00", "6C10", "6D00", "6E00", "6F00", "9862",
)


def _run_node() -> dict[str, Any]:
    bundle = _APP_JS.read_text(encoding="utf-8")
    defs = "\n".join(_function(bundle, name) for name in _FUNCTIONS)
    decoded = decode_context_text("\n".join("> " + line for line in _DECODED_LINES))
    fixtures = {
        "input": "# read EF ICCID\n00A4080C022FE2\n\n 00 b0 00 00 0a   # ten bytes\n00A4\nZZ",
        "sws": list(_STOP_SWS),
        "exchanges": decoded["exchanges"],
        "presets": [apdu for _label, apdu in _presets()],
    }
    script = _HARNESS.replace("__DEFS__", defs).replace("__FIXTURES__", json.dumps(fixtures))
    completed = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, timeout=30, check=False
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout)


@unittest.skipUnless(shutil.which("node"), "node is required to run the bundle's helpers")
class ApduConsoleLineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.out = _run_node()

    def test_each_line_is_a_command_and_comments_and_blanks_are_skipped(self) -> None:
        self.assertEqual(
            self.out["lines"],
            [
                {"line": 2, "hex": "00A4080C022FE2", "issues": []},
                {"line": 4, "hex": "00B000000A", "issues": []},
                {"line": 5, "hex": "00A4", "issues": ["need at least 4 bytes (CLA INS P1 P2)"]},
                {"line": 6, "hex": "ZZ", "issues": ["non-hex characters"]},
            ],
        )

    def test_normal_endings_and_warnings_go_on_and_errors_stop(self) -> None:
        go_on = {"9000", "9110", "9201", "6282", "63C2", "6110", "9F10"}
        self.assertEqual(self.out["stops"], {sw: sw not in go_on for sw in _STOP_SWS})

    def test_the_command_column_reads_the_decoder(self) -> None:
        self.assertEqual(
            self.out["texts"],
            [
                {"text": "SELECT FILE · select by path from the MF · Path 2FE2", "error": False},
                {"text": "READ BINARY · offset 0", "error": False},
                {
                    "text": "SELECT FILE · selection by DF name (AID) · AID A000000151000000 (MNOSD)",
                    "error": False,
                },
                {"text": "short APDU Lc exceeds supplied input", "error": True},
            ],
        )

    def test_a_run_stops_at_the_first_error_status_word(self) -> None:
        self.assertEqual(
            self.out["batchStops"],
            {
                "calls": ["00A4080C022FE2", "00B000000A"],
                "note": "Stopped after #2 (SW 6A82); 1 command not sent.",
                "running": False,
                "history": 2,
                "results": [[1, 2, False, "9000"], [2, 3, False, "6A82"]],
            },
        )

    def test_without_the_stop_every_line_is_sent(self) -> None:
        self.assertEqual(self.out["batchGoesOn"]["calls"], ["00A4080C022FE2", "00B000000A", "00B0000004"])
        self.assertEqual(self.out["batchGoesOn"]["note"], "")
        self.assertEqual(self.out["batchWarning"]["calls"], ["00A4080C022FE2", "00B000000A", "00B0000004"])

    def test_a_transport_failure_or_a_failed_send_always_stops(self) -> None:
        self.assertEqual(
            self.out["batchTransport"]["note"], "Stopped after #1 (transport failed); 2 commands not sent."
        )
        self.assertEqual(self.out["batchRefused"]["results"], [[1, 2, False, "no session"]])
        self.assertEqual(
            self.out["batchRefused"]["note"], "Stopped after #1 (send failed); 2 commands not sent."
        )
        self.assertEqual(self.out["batchThrown"]["results"][1], [2, 3, False, "HTTP 500"])
        self.assertEqual(self.out["batchThrown"]["running"], False)

    def test_every_preset_is_a_well_framed_apdu(self) -> None:
        presets = _presets()
        self.assertTrue(all(self.out["presetsValid"]), presets)
        for label, apdu in presets:
            try:
                _parse_apdu_body(bytes.fromhex(apdu))
            except DecodeError as error:
                self.fail(f"{label} ({apdu}): {error}")
        by_label = dict(presets)
        self.assertEqual(by_label["SELECT MNO-SD"], "00A4040008A000000151000000")
        self.assertEqual(by_label["GET STATUS -- ISD (80)"], "80F28002024F0000")
        self.assertEqual(by_label["GET STATUS -- Apps (40)"], "80F24002024F0000")

    def test_ota_concatenated_sms_reads_every_stored_spelling_as_on_or_off(self) -> None:
        self.assertEqual(
            self.out["onOff"], ["ON", "ON", "ON", "ON", "ON", "OFF", "OFF", "OFF", "OFF", "", "MAYBE"]
        )


class ApduConsoleWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = _COMMAND_CENTER.read_text(encoding="utf-8")

    def test_the_decoder_reads_every_line_as_a_command(self) -> None:
        self.assertIn('apiFetch("/api/actions/tool.decoder.context/run"', self.source)
        self.assertIn('hexList.map(function (hex) { return "> " + hex; }).join("\\n")', self.source)

    def test_a_preset_is_added_as_a_line_of_its_own(self) -> None:
        self.assertIn(
            'input.value = current ? current + "\\n" + presetSel.value : presetSel.value;', self.source
        )

    def test_send_names_the_number_of_commands(self) -> None:
        self.assertIn('"Send " + commands.length + " APDUs"', self.source)

    def test_ota_concatenated_sms_offers_on_and_off(self) -> None:
        field = self.source.split('key: "concat_sms",', 1)[1].split("},\n", 3)
        block = "},\n".join(field[:3])
        self.assertEqual(re.findall(r'value: "([^"]+)"', block), ["ON", "OFF"])
        self.assertIn("normalise: otaOnOff,", block)


if __name__ == "__main__":
    unittest.main()
