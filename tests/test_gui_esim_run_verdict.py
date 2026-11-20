# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""An eSIM Management profile command is judged by its marker lines, and the page believes it.

Before, the server failed a command whose trace held the word "failed" or
"error" anywhere, so a DISABLE that the card carried out read as failed when
only the Notification sync after it went wrong; and the page put "<operation>
ok" over any answer, an ``ok: false`` one included.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional
from unittest import mock

import pytest

from yggdrasim_common.gui_server.actions import scp11_live

ROOT = Path(__file__).resolve().parents[1]
COMMAND_CENTER = ROOT / "gui_frontend" / "src" / "js" / "command-center.js"


def _guarded(trace: str, sync: Optional[bool] = None) -> dict[str, Any]:
    def fake_callable(reader_index, work, *, connect_first=True, reader_name=""):
        return sync, trace

    with mock.patch.object(scp11_live, "_run_console_callable", fake_callable):
        return scp11_live._run_guarded_console_handler(0, "_cmd_disable_profile", "8988201234567890123")


def test_a_state_change_with_an_incomplete_sync_is_a_success_with_a_note() -> None:
    result = _guarded(
        "[*] DisableProfile: iccid=98882010325476981032\n"
        "[+] DisableProfile: success.\n"
        "[*] Notification sync: forwarding 1 notification(s).\n"
        "[*] Notification sync: handleNotification failed for queued notification seq=3 (timeout).\n"
        "[*] Notification sync: 1 notification(s) could not be forwarded to SM-DP+; leaving the "
        "unforwarded entries on-card for the next attempt.\n",
        sync=False,
    )
    assert result["ok"] is True
    assert result["notification_sync"] == "incomplete"
    assert "Notification sync did not complete" in result["note"]


def test_a_completed_sync_is_reported_and_the_note_stays_ok() -> None:
    result = _guarded("[+] DisableProfile: success.\n[*] Notification sync: no queued notifications found.\n", sync=True)
    assert result == {
        "ok": True,
        "note": "ok",
        "trace": result["trace"],
        "notification_sync": "completed",
    }


def test_no_sync_key_when_no_sync_ran() -> None:
    result = _guarded("[+] SET-POL done.\n", sync=None)
    assert result["ok"] is True
    assert "notification_sync" not in result


@pytest.mark.parametrize(
    "trace",
    [
        "[-] EnableProfile failed, code 0x01: iccidOrAidNotFound [SGP.22 ES10b]\n",
        "[!] Could not resolve profile: 8988\n[*] Run LIST and use ICCID or AID from output.\n",
        "[!] DisableProfile failed: card did not answer\n",
    ],
)
def test_a_failed_command_is_a_failure(trace: str) -> None:
    result = _guarded(trace)
    assert result["ok"] is False
    assert result["note"] == "see trace for details"


def test_a_warning_or_a_word_in_a_note_does_not_fail_the_command() -> None:
    result = _guarded(
        "[!] Warning: the reader reports a slow card.\n"
        "[*] EnableProfile: the error counter of the previous session was reset.\n"
        "[+] EnableProfile: success.\n"
    )
    assert result["ok"] is True


def test_an_exception_is_a_failure_with_its_text() -> None:
    def broken(*args, **kwargs):
        raise RuntimeError("no reader")

    with mock.patch.object(scp11_live, "_run_console_callable", broken):
        result = scp11_live._run_guarded_console_handler(0, "_cmd_enable_profile", "x")
    assert result == {"ok": False, "note": "RuntimeError: no reader", "trace": ""}


def _function_source(source: str, name: str) -> str:
    match = re.search(r"^[ \t]*(?:async[ \t]+)?function %s\(" % re.escape(name), source, re.M)
    assert match is not None, name
    start = source.index("{", match.end() - 1)
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
    raise AssertionError("unbalanced braces in %s" % name)


def test_the_page_status_helper_reads_ok_false() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    helper = _function_source(COMMAND_CENTER.read_text(encoding="utf-8"), "_esimRunStatusText")
    script = helper + """
var cases = [
  _esimRunStatusText(null, "disable ok", "disable failed"),
  _esimRunStatusText({ ok: false }, "disable ok", "disable failed"),
  _esimRunStatusText({ ok: false }, "ok"),
  _esimRunStatusText({ ok: true }, "disable ok", "disable failed"),
  _esimRunStatusText({ lines: [] }, "bound"),
];
process.stdout.write(JSON.stringify(cases));
"""
    done = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30, check=True)
    assert json.loads(done.stdout) == ["error", "disable failed", "failed", "disable ok", "bound"]


def test_every_esim_runner_ends_on_the_helper() -> None:
    source = COMMAND_CENTER.read_text(encoding="utf-8")
    # The flow pane runner, the OTA runner and bind, the two page runners and the toolbar reset.
    assert source.count("_esimRunStatusText(data,") >= 6
    for stale in (
        'setBusy(false, data ? (opts.doneText || "ok") : "error");',
        'setBusy(false, data ? "bound" : "error");',
        '_setEsimModuleToolbarBusy(false, data ? "reset ok" : "reset error");',
        '_setEsimFlowStatus(opts.doneText || "ok");',
    ):
        assert stale not in source, stale
    runner = _function_source(source, "_runActionInEsimFlowPane")
    assert "data.ok === false" in runner


def test_the_profile_lifecycle_status_reads_ok_false() -> None:
    source = COMMAND_CENTER.read_text(encoding="utf-8")
    start = source.index('runningText: operation + " profile",')
    block = source[start:start + 1200]
    assert 'failedText: operation + " failed"' in block
    assert "data.ok === false" in block
    assert '(lifecycleFailed ? " failed" : " ok")' in block
