# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local eIM overview (``SCP11.eim_local.engine.overview``) and the page built on it.

The overview reads the store and changes nothing: an empty store, a store
without an identity, a record that was never refreshed and an operation
without a result all answer a complete document. The GUI action returns that
document, and the page reaches the store only through the module's actions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from SCP11.eim_local.engine.overview import build_overview
from SCP11.eim_local.engine.service import LocalEim, OperationRequest

REPO = Path(__file__).resolve().parents[1]
EID = "89049032000000000000000000000017"
EIM_ID = "1.3.6.1.4.1.32473.999.10.7"


@pytest.fixture()
def store(tmp_path: Path):
    with mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(tmp_path)}):
        yield tmp_path


def test_empty_store_answers_a_complete_document(store: Path) -> None:
    overview = build_overview()
    assert overview["identity"] is None
    assert overview["euiccs"] == []
    assert overview["euicc"] is None
    assert overview["tls"] == {"active": "", "setups": [], "served": []}
    assert overview["service"]["running"] is False
    assert overview["store"] == str(store)
    assert "max_retries" in overview["settings"]
    json.dumps(overview)


def test_identity_carries_its_certificates_and_no_private_key(store: Path) -> None:
    eim = LocalEim(store)
    eim.new_identity(eim_id=EIM_ID, eim_fqdn="eim.example.test")
    identity = build_overview(eim)["identity"]
    assert identity["eim_id"] == EIM_ID
    assert identity["effective_fqdn"] == "eim.example.test"
    labels = [row["label"] for row in identity["signing_certificate"]]
    assert "Subject" in labels and "Valid Until" in labels
    assert len(identity["signing_public_key_hex"]) > 0
    text = json.dumps(build_overview(eim))
    assert "PRIVATE KEY" not in text
    key_bytes = Path(identity["signing_key_path"]).read_bytes()
    assert key_bytes.hex().upper() not in text.upper()


def test_one_euicc_with_a_pending_operation_and_no_refresh(store: Path) -> None:
    eim = LocalEim(store)
    eim.new_identity(eim_id=EIM_ID, eim_fqdn="eim.example.test")
    eim.register(EID, label="bench card")
    operation = eim.submit([OperationRequest(eid=EID, type="PROFILE_INFO_LIST")])[0]

    listing = build_overview(eim)
    assert listing["euicc"] is None
    assert listing["euiccs"] == [{
        "eid": EID, "label": "bench card", "associated": False, "last_poll_at": None,
        "poll_count": 0, "profile_count": 0, "pending": 1,
        "created_at": listing["euiccs"][0]["created_at"],
    }]

    detail = build_overview(eim, eid=f" {EID.lower()} ")["euicc"]
    assert detail["eid"] == EID
    assert detail["profiles"] == [] and detail["eims"] == [] and detail["refreshed"] == {}
    assert detail["stored"] == [] and detail["euicc_certificate"] == []
    assert [item["id"] for item in detail["pending"]] == [operation.id]
    row = detail["operations"][0]
    assert (row["type"], row["title"], row["state"], row["final"]) == (
        "PROFILE_INFO_LIST", "List profiles", "CREATED", False)
    assert row["error"] == "" and row["finished_at"] is None
    json.dumps(detail)


def test_overview_changes_nothing_and_an_unknown_eid_falls_back(store: Path) -> None:
    eim = LocalEim(store)
    eim.register(EID)
    eim.submit([OperationRequest(eid=EID, type="LIST_EIM")])
    before = [(item.id, item.state, item.position) for item in eim.operations(eid=EID)]
    records_before = [(item.eid, item.counter_value, dict(item.data)) for item in eim.records()]
    for _ in range(3):
        assert build_overview(eim, eid="00")["euicc"] is None
        build_overview(eim, eid=EID)
    assert [(item.id, item.state, item.position) for item in eim.operations(eid=EID)] == before
    assert [(item.eid, item.counter_value, dict(item.data)) for item in eim.records()] == records_before


def test_catalogue_lists_every_operation_type_with_its_parameters(store: Path) -> None:
    from SCP11.eim_local.engine.catalogue import OPERATION_TYPES
    from yggdrasim_common.gui_server.actions.eim_local_ops import OPERATION_CHOICES

    listed = build_overview()["catalogue"]
    assert [entry["type"] for entry in listed] == list(OPERATION_TYPES)
    for entry in listed:
        kind = OPERATION_TYPES[entry["type"]]
        assert [param["name"] for param in entry["params"]] == [param.name for param in kind.params]
        # The page queues by verb through the form action's choice list.
        assert entry["verb"] in OPERATION_CHOICES, entry["verb"]


def test_operation_detail_before_and_after_an_edit(store: Path) -> None:
    from SCP11.eim_local.engine.overview import operation_detail
    from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

    actions = {spec.id: spec.dispatcher for spec in SPECS}
    eim = LocalEim(store)
    eim.register(EID)
    operation = eim.submit([OperationRequest(
        eid=EID, type="ENABLE_PROFILE", params={"iccid": "8988201234567890123"})])[0]

    detail = actions["eim_local.op_detail"](None, operation_id=operation.id)
    assert detail["editable"] is True and detail["package_state"] == "fixed so far"
    assert detail["package_hex"].startswith("A3") and detail["package_rows"] == []
    assert detail["result_hex"] == "" and detail["result_rows"] == []
    assert [spec["name"] for spec in detail["param_specs"]] == ["iccid", "rollback"]
    assert len(detail["history"]) == 1

    # The page's edit: key="value" lines through the edit action.
    actions["eim_local.op_edit"](None, operation_id=operation.id, changes='rollback="on"\nretries="5"')
    changed = operation_detail(eim, operation.id)
    assert changed["params"]["rollback"] is True and changed["max_retries"] == 5
    assert changed["package_hex"] != detail["package_hex"]
    assert len(changed["history"]) == 2

    eim.cancel(operation.id)
    assert operation_detail(eim, operation.id)["editable"] is False
    with pytest.raises(ValueError):
        actions["eim_local.op_detail"](None, operation_id=999999)


def test_quick_controls_queue_the_intended_operations(store: Path) -> None:
    from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

    queue = next(spec.dispatcher for spec in SPECS if spec.id == "eim_local.op_queue")
    eim = LocalEim(store)
    eim.register(EID)
    iccid = "8988201234567890123"
    for inputs in (
        {"operation": "IMMEDIATE-ENABLE", "params": "enabled=on"},
        {"operation": "IMMEDIATE-ENABLE", "params": "enabled=off"},
        {"operation": "DEFAULT-SMDP", "params": 'address="smdpp.example.test"'},
        {"operation": "FALLBACK", "value": iccid},
        {"operation": "UNSET-FALLBACK"},
        {"operation": "ENABLE", "value": iccid, "params": "rollback=on"},
        {"operation": "DOWNLOAD", "value": "1$smdpp.example.test$MATCHING-ID", "params": "indirect=on"},
    ):
        queue(None, eid=EID, **inputs)
    queued = [(item.type, item.params) for item in eim.operations(eid=EID, newest_first=False)]
    assert queued == [
        ("CONFIGURE_IMMEDIATE_ENABLE", {"enabled": True}),
        ("CONFIGURE_IMMEDIATE_ENABLE", {"enabled": False}),
        ("SET_DEFAULT_DP_ADDRESS", {"address": "smdpp.example.test"}),
        ("SET_FALLBACK_ATTRIBUTE", {"iccid": iccid}),
        ("UNSET_FALLBACK_ATTRIBUTE", {}),
        ("ENABLE_PROFILE", {"iccid": iccid, "rollback": True}),
        ("PROFILE_DOWNLOAD_TRIGGER", {"activation_code": "1$smdpp.example.test$MATCHING-ID", "indirect": True}),
    ]


def test_gui_action_returns_the_document(store: Path) -> None:
    from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

    spec = next(entry for entry in SPECS if entry.id == "eim_local.overview")
    assert spec.output_kind == "json" and spec.requires_card is False
    LocalEim(store).register(EID)
    answer = spec.dispatcher(None, eid=EID)
    assert answer["euicc"]["eid"] == EID
    assert "lines" not in answer


def test_page_is_wired_and_goes_through_the_module_actions() -> None:
    source = REPO / "gui_frontend" / "src"
    page = (source / "js" / "local-eim-page.js").read_text(encoding="utf-8")
    center = (source / "js" / "command-center.js").read_text(encoding="utf-8")
    order = (source / "js" / ".js_order").read_text(encoding="utf-8").split()
    assert order.index("local-eim-page.js") == order.index("command-center.js") + 1
    assert "views/local-eim-page.css" in (source / "css" / ".css_order").read_text(encoding="utf-8")

    # The page never calls the API itself and builds no markup from strings.
    assert "apiFetch(" not in page and "innerHTML = \"\"" in page
    assert page.count("innerHTML") == 1
    used = {
        "eim_local.overview", "eim_local.op_queue", "eim_local.op_cancel", "eim_local.op_detail",
        "eim_local.op_edit", "eim_local.op_copy",
        "eim_local.deliver", "eim_local.euicc_read", "eim_local.euicc_register", "eim_local.associate",
        "eim_local.identity_new", "eim_local.service_start", "eim_local.service_stop",
        "eim_local.service_restart", "eim_local.traffic", "eim_local.tls_setup_list",
        "eim_local.tls_setup_new", "eim_local.tls_leaf_new", "eim_local.tls_results", "eim_local.queue_settings",
    }
    from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

    registered = {spec.id for spec in SPECS}
    for action_id in used:
        assert f'"{action_id}"' in page, action_id
        assert action_id in registered, action_id
    for operation in ("LIST-PROFILES", "IPA-DATA", "LIST-EIM", "ENABLE", "DISABLE", "DELETE", "DOWNLOAD",
                      "IMMEDIATE-ENABLE", "DEFAULT-SMDP", "FALLBACK", "UNSET-FALLBACK", "REFRESH"):
        assert f'"{operation}"' in page, operation
    # The timer ends with the page; a card step needs the bound reader.
    assert "if (!attached()) {\n          stopTimer();" in page
    assert "details[open], [data-armed='1']" in page
    assert "Link this eIM resets the card's eIM configuration" in page
    assert "Select a reader in the top bar first" in page
    # No plugin is named: a second delivery route is whatever carries the tag.
    assert 'hooks.actionsWithTag("ipae-deliver")' in page
    # A queued download is routed to the IPAd download, not left to Deliver.
    assert 'operation.type === "PROFILE_DOWNLOAD_TRIGGER"' in page
    assert 'hooks.openForm("scp11_live.eim_download", {});' in page
    assert "plugin." not in page and "plugin.polling" not in center

    assert "function _showLocalEimPage()" in center
    assert "if (isLocalEimSurface && esimFlowBody) {\n        _showLocalEimPage();" in center
    assert "overview: true," in center
    assert "if (isLocalEimSurface) dashBody.hidden = true;" in center
    assert 'legacyFold.className = "cc-local-eim-legacy";' in center
