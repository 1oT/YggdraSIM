# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Notifications on the Local eIM page: the three actions, the overview rows and the page's own status text.

The actions run the shell's NOTIFICATIONS verb; the page reads the rows from
``eim_local.overview`` and sends or holds through the actions (SGP.32 v1.3
§5.7.4 is the call a Send makes). The receiver is a recorder, and the page's
functions run under ``node``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from SCP11.eim_local.engine import notifications as outbox
from SCP11.eim_local.engine.overview import build_overview
from SCP11.eim_local.engine.service import LocalEim
from tests.local_eim_notification_support import ICCID, RECEIVER, Receiver, SigningEuicc

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "gui_frontend" / "src" / "js" / "local-eim-page.js"
EIM_ID = "1.3.6.1.4.1.32473.999.10.7"
ACTIONS = ("eim_local.notifications", "eim_local.notifications_send")


@pytest.fixture()
def bench(tmp_path: Path):
    """A scratch store with one eUICC whose Notifications the test signs, and a receiver that records."""
    receiver = Receiver()
    with mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(tmp_path)}), \
            mock.patch.object(outbox, "receiver_sender", lambda *_args, **_options: receiver):
        engine = LocalEim(tmp_path)
        engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        euicc = SigningEuicc()
        engine.register(euicc.eid)
        engine.apply_card_reads(euicc.eid, {"euicc_certificate": euicc.certificate,
                                            "eum_certificate": euicc.eum_certificate})
        yield engine, euicc, receiver


def _spec(action_id: str):
    from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

    return next(entry for entry in SPECS if entry.id == action_id)


def test_the_three_actions_are_registered_without_a_reader() -> None:
    for action_id in ACTIONS:
        spec = _spec(action_id)
        assert spec.subsystem == "Local eIM" and spec.requires_card is False, action_id
        assert all(field.kind != "reader" for field in spec.inputs), action_id
    # Sending cannot be taken back: the form asks for a deliberate gesture.
    assert "destructive" in _spec("eim_local.notifications_send").tags
    assert "destructive" not in _spec("eim_local.notifications").tags


def test_list_and_send_run_the_verb_and_nothing_holds(bench) -> None:
    engine, euicc, receiver = bench
    for number in (7, 9, 11):
        engine.accept_notification(euicc.eid, euicc.other(number, "disable" if number == 7 else "enable"))
    listed = _spec("eim_local.notifications").dispatcher(None, eid=euicc.eid)["lines"]
    assert f"[*] {euicc.eid}: 3 pending" in listed
    assert any(f"7  disable  for {RECEIVER}, ICCID {ICCID}: pending" in line for line in listed)
    from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

    assert "eim_local.notifications_hold" not in {entry.id for entry in SPECS}

    named = _spec("eim_local.notifications_send").dispatcher(None, eid=euicc.eid, seq_numbers="9")["lines"]
    assert named == [f"[+] Notification 9 (enable) of {euicc.eid}: delivered to {RECEIVER}"]
    sent = _spec("eim_local.notifications_send").dispatcher(None, eid="", seq_numbers="")["lines"]
    assert sent == [f"[+] Notification 7 (disable) of {euicc.eid}: delivered to {RECEIVER}",
                    f"[+] Notification 11 (enable) of {euicc.eid}: delivered to {RECEIVER}"]
    assert receiver.hosts == [RECEIVER, RECEIVER, RECEIVER]
    assert {row["seq_number"]: row["state"] for row in engine.notifications(euicc.eid)} == {
        7: "delivered", 9: "delivered", 11: "delivered"}


def test_a_field_takes_sequence_numbers_and_nothing_that_reads_as_an_option(bench) -> None:
    _engine, euicc, receiver = bench
    send = _spec("eim_local.notifications_send").dispatcher
    for text in ("7; EUICC REMOVE", "--force", "target=smdp.example.test", "7 all", "-3"):
        with pytest.raises(ValueError):
            send(None, eid=euicc.eid, seq_numbers=text)
    assert receiver.calls == []


def test_the_overview_carries_the_rows_newest_first_and_no_octets(bench) -> None:
    engine, euicc, receiver = bench
    receiver.fail(RECEIVER, "connection refused")
    engine.accept_notification(euicc.eid, euicc.other(7, "disable"))
    engine.accept_notification(euicc.eid, euicc.other(9, "enable"))
    engine.forward_notifications()
    document = build_overview(engine, eid=euicc.eid)
    rows = document["euicc"]["notifications"]
    assert [row["seq_number"] for row in rows] == [9, 7]
    assert rows[1]["state"] == "pending" and rows[1]["attempts"] == 1 and rows[1]["last_error"] == "connection refused"
    assert rows[1]["address"] == RECEIVER and rows[1]["iccid"] == ICCID and rows[1]["event"] == "disable"
    assert all("hex" not in row and "sender" not in row for row in rows)
    assert "notification_forwarding" not in document["settings"]
    json.dumps(document)


def test_deliver_from_the_gui_closes_the_card_channel_before_any_receiver_is_called(tmp_path: Path) -> None:
    from SCP11.eim_local.engine.service import OperationRequest
    from SCP11.eim_local.engine_shell import EngineVerbs
    from tests.test_local_eim_engine import ENABLED, SimCard
    from yggdrasim_common.gui_server.actions import eim_local_ops, scp11_local

    order: list[str] = []
    card = SimCard()
    channel = object()

    def sender(host: str, _notification: bytes) -> None:
        order.append(f"sent to {host}")

    with mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(tmp_path)}), \
            mock.patch.object(outbox, "receiver_sender", lambda *_args, **_options: sender), \
            mock.patch.object(eim_local_ops, "_card_session",
                              lambda reader: (eim_local_ops._offline_session(), channel)), \
            mock.patch.object(scp11_local, "_close_channel",
                              lambda closed: order.append("channel closed") if closed is channel else None), \
            mock.patch.object(EngineVerbs, "_with_reader", lambda _verbs, _verb, body: body()), \
            mock.patch.object(EngineVerbs, "_exchange", lambda _verbs, payload, label: card.exchange(payload, label)), \
            mock.patch.object(EngineVerbs, "_reset_card", lambda _verbs: True):
        engine = LocalEim(tmp_path)
        engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        engine.associate(card.exchange, card.eid)
        engine.submit([OperationRequest(eid=card.eid, type="DISABLE_PROFILE", params={"iccid": ENABLED})])
        lines = _spec("eim_local.deliver").dispatcher(None, reader="any", once=False)["lines"]
    assert order == ["channel closed", "sent to rsp.example.com"]
    assert lines[-1] == f"[+] Notification 1 (disable) of {card.eid}: delivered to rsp.example.com"
    assert "[*] 1 package(s) delivered." in lines


_HARNESS = """
function lepTime(iso) { return "T(" + iso + ")"; }
%s
var rows = %s;
console.log(JSON.stringify(rows.map(function (row) {
  return [lepNotificationLabel(row.state), lepNotificationTone(row.state), lepNotificationNote(row)];
})));
"""


def test_the_page_words_each_state_from_the_row_the_engine_gives(bench) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    engine, euicc, receiver = bench
    receiver.fail(RECEIVER, "connection refused")
    engine.accept_notification(euicc.eid, euicc.other(7))
    engine.forward_notifications()
    receiver.recover(RECEIVER)
    for number in (8, 9, 10):
        engine.accept_notification(euicc.eid, euicc.other(number, "enable", f"smdp{number}.example.test"))
    engine.forward_notifications(euicc.eid, seq_numbers=[8])
    receiver.fail("smdp9.example.test", "smdp9.example.test answered HTTP 403", retry=False)
    engine.forward_notifications(euicc.eid, seq_numbers=[9])
    record = engine.record(euicc.eid)
    record.data["notifications"].append({"at": "2026-10-30T08:00:00+00:00", "seq_number": 3,
                                         "hex": euicc.other(3).hex().upper()})
    with engine.store.transaction() as connection:
        engine.store.save_record(record, connection)
    rows = {row["seq_number"]: row for row in engine.notifications(euicc.eid)}
    text = PAGE.read_text(encoding="utf-8")
    start = text.index("  function lepNotificationTone(state) {")
    functions = text[start:text.index("  function lepButton(", start)]
    # A pending one on a record without the eUICC certificate, and one an earlier version held.
    waiting = {"seq_number": 12, "state": "pending", "attempts": 0, "waiting": outbox.MISSING_EUICC_CERTIFICATE}
    legacy = {"seq_number": 13, "state": "kept", "reason": "held by the operator"}
    script = _HARNESS % (functions, json.dumps([rows[7], rows[8], rows[9], rows[10], rows[3], waiting, legacy]))
    worded = json.loads(subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30,
                                       check=True).stdout)
    assert worded[0] == ["Pending", "info", f"1 attempt, last: connection refused; next T({rows[7]['next_attempt_at']})"]
    assert worded[1] == ["Delivered", "ok", f"T({rows[8]['delivered_at']})"]
    assert worded[2] == ["Failed", "fail", "smdp9.example.test answered HTTP 403"]
    assert worded[3] == ["Pending", "info", ""]
    assert worded[4] == ["Kept", "info", "taken before the eIM forwarded Notifications"]
    assert worded[5] == ["Pending", "info", f"waits for {outbox.MISSING_EUICC_CERTIFICATE}"]
    assert worded[6] == ["Kept", "info", "held by an earlier version: held by the operator"]


def test_the_page_and_the_tab_are_wired() -> None:
    page = PAGE.read_text(encoding="utf-8")
    center = (REPO / "gui_frontend" / "src" / "js" / "command-center.js").read_text(encoding="utf-8")
    assert '"eim_local.notifications_send"' in page
    # Nothing on the page or in the tab holds a Notification back.
    assert "notifications_hold" not in page and "notifications_hold" not in center
    assert "Hold" not in page[page.index("    function renderNotifications("):page.index("    function renderEvents(")]
    assert "notification_forwarding" not in page
    assert '"notifications", "notifications_send",' in center
    # The Notifications follow the Event log, the eUICC's operations.
    euicc_page = page[page.index("    function renderEuicc(root) {"):page.index("    function renderOperation(root) {")]
    assert euicc_page.index("renderEvents(root, euicc);") < euicc_page.index("renderNotifications(root, euicc);")
    # A row's Send names its own sequence number; only Send pending goes without one.
    assert "{ eid: euicc.eid, seq_numbers: String(number) }" in page
    # What the eIM would not send by itself takes a second press, like the page's other one-way buttons.
    assert 'if (row.state !== "pending" && send.getAttribute("data-armed") !== "1") {' in page
    assert 'send.textContent = "Confirm send";' in page
    assert page.count("innerHTML") == 1
    naming = (REPO / "guides" / "NAMING_CONVENTIONS.md").read_text(encoding="utf-8")
    for label in ("Send Notifications", "Send pending", "Notification Receiver", "Pending, Delivered, Failed, Kept"):
        assert label in naming, label
    for label in ("Hold Notifications", "Hold pending", "notification_forwarding"):
        assert label not in naming, label
