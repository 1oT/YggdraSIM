# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Offline Tools actions of the AddInitialEim builder and the GUI hooks they rely on."""

from __future__ import annotations

from pathlib import Path

import pytest

from SCP11.shared import eim_builder_store as store
from tests.eim_builder_support import TEST_EIM_FQDN, TEST_EIM_ID, der, make_certificate, pem, private_key_pem
from yggdrasim_common.gui_server.actions.registry import coerce_inputs, ensure_builtin_actions_loaded

ROOT = Path(__file__).resolve().parents[1]
BUILD_ID = "tool.eim_builder.add_initial_eim"
CERTIFICATES_ID = "tool.eim_builder.certificates"
VALUES_ID = "tool.eim_builder.saved_values"


@pytest.fixture()
def store_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(store.STORE_DIR_ENV, str(tmp_path))
    return tmp_path


def _run(action_id: str, **inputs):
    spec = ensure_builtin_actions_loaded().get(action_id)
    return spec.dispatcher(None, **coerce_inputs(spec, inputs))


def test_actions_register_under_offline_tools_without_a_card() -> None:
    registry = ensure_builtin_actions_loaded()
    for action_id in (BUILD_ID, CERTIFICATES_ID, VALUES_ID):
        spec = registry.get(action_id)
        assert spec.subsystem == "Offline Tools"
        assert spec.requires_card is False
        assert spec.output_kind == "key_value_lines"


def test_certificate_store_import_list_and_remove(store_dir: Path) -> None:
    certificate, key = make_certificate(TEST_EIM_ID)
    imported = _run(
        CERTIFICATES_ID,
        operation="import",
        name="eim-signing",
        certificate_text=(pem(certificate) + private_key_pem(key)).decode(),
    )
    assert imported["detail_lines"][0]["label"] == "eim-signing"
    assert "private key" in imported["validation_lines"][0]["value"]
    tls, _ = make_certificate("eIM TLS Test CA", ca=True)
    source = store_dir / "tls.der"
    source.write_bytes(der(tls))
    _run(CERTIFICATES_ID, operation="import", name="tls-ca", certificate_file=str(source))
    listed = _run(CERTIFICATES_ID, operation="list")
    assert [line["label"] for line in listed["detail_lines"] if line["indent"] == 0] == ["eim-signing", "tls-ca"]
    _run(CERTIFICATES_ID, operation="remove", name="tls-ca")
    assert [entry.name for entry in store.list_certificates()[0]] == ["eim-signing"]


@pytest.mark.parametrize(
    ("inputs", "message"),
    [
        ({"operation": "import"}, "needs a certificate"),
        ({"operation": "import", "certificate_text": "x", "certificate_file": "/nonexistent"}, "not both"),
        ({"operation": "remove", "name": "missing"}, "No stored certificate"),
    ],
)
def test_certificate_store_errors_are_value_errors(store_dir: Path, inputs: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _run(CERTIFICATES_ID, **inputs)


def test_build_returns_the_script_and_saves_the_typed_values(store_dir: Path) -> None:
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="eim-signing")
    result = _run(
        BUILD_ID,
        eim_id=TEST_EIM_ID,
        eim_fqdn=TEST_EIM_FQDN,
        eim_certificate="eim-signing",
        association_token=True,
        indirect_profile_download="true",
        euicc_ci_pk_id="F5:41:72",
    )
    steps = result["script"]["steps"]
    assert [step["apdu"] for step in steps[:4]] == [
        "80AA000005A903840101",
        "0070000001",
        "01A4040010A0000005591010FFFFFFFF8900000100",
        "81E2910007BF640482020106",
    ]
    assert result["request_hex"].startswith("BF57")
    # The request shows as one STORE DATA beside the script, not as a bare TLV.
    assert "raw_hex" not in result
    single = result["single_apdu"]["steps"]
    assert len(single) == 1 and single[0]["apdu"].startswith("81E29100")
    assert single[0]["apdu"].endswith(result["request_hex"])
    assert any("one APDU" in line["value"] for line in result["validation_lines"])
    assert "nothing was sent" in result["note"] and "AddInitialEim send" in result["note"]
    assert any("MANAGE CHANNEL answers channel 01" in line["value"] for line in result["validation_lines"])
    assert {line["label"] for line in result["detail_lines"]} >= {"eimId", "eimFqdn", "eUICCMemoryReset"}
    saved = _run(VALUES_ID, operation="list")
    assert saved["certificates"] == ["eim-signing"]
    assert saved["values"]["eim_id"] == [TEST_EIM_ID]
    assert saved["values"]["euicc_ci_pk_id"] == ["F54172"]
    assert saved["last"]["tls_certificate"] == ""
    # The whole form comes back, settings and ticks included, not only the typed values.
    last_form = saved["last_configuration"]
    assert last_form["association_token"] is True and last_form["indirect_profile_download"] is True
    assert last_form["eim_retrieve_https"] is True and last_form["eim_inject_coaps"] is False


def test_build_without_protocol_bits_omits_the_member(store_dir: Path) -> None:
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="eim-signing")
    result = _run(BUILD_ID, eim_id=TEST_EIM_ID, eim_certificate="eim-signing", eim_retrieve_https=False)
    protocol = [line["value"] for line in result["detail_lines"] if line["label"] == "eimSupportedProtocol"]
    assert protocol[0].startswith("(omitted")


def test_build_with_an_unknown_certificate_is_a_value_error(store_dir: Path) -> None:
    with pytest.raises(ValueError, match="No stored certificate"):
        _run(BUILD_ID, eim_id=TEST_EIM_ID, eim_certificate="missing")


def test_saved_values_forget(store_dir: Path) -> None:
    store.remember_values({"eim_fqdn": TEST_EIM_FQDN})
    result = _run(VALUES_ID, operation="forget", field="eim_fqdn", value=TEST_EIM_FQDN)
    assert result["values"]["eim_fqdn"] == []
    with pytest.raises(ValueError, match="holds no saved value"):
        _run(VALUES_ID, operation="forget", field="eim_fqdn", value=TEST_EIM_FQDN)


def test_frontend_offers_saved_values_and_renders_the_script() -> None:
    source = (ROOT / "gui_frontend/src/js/command-center.js").read_text(encoding="utf-8")
    bundle = (ROOT / "yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
    css = (ROOT / "gui_frontend/src/css/views/command-center-keyval.css").read_text(encoding="utf-8")
    for text in (source, bundle):
        assert 'var CC_EIM_BUILDER_VALUES_ACTION_ID = "tool.eim_builder.saved_values";' in text
        assert '"tool.eim_builder.add_initial_eim": CC_EIM_BUILDER_FORM_FIELDS,' in text
        assert '"scp11_live.add_initial_eim": CC_EIM_BUILDER_FORM_FIELDS,' in text
        assert '"scp11_live.add_initial_eim": true,' in text
        assert '"tool.eim_builder.send": CC_EIM_BUILDER_FORM_FIELDS,' in text
        assert '"tool.eim_builder.send": true,' in text
        assert "function ccAttachEimBuilderSuggestions(" in text
        assert "function ccRenderApduScript(" in text
        assert "sheet.appendChild(ccRenderApduScript(script));" in text
        assert "sheet.appendChild(ccRenderApduScript(singleApdu));" in text
        # A build or send form opens with the last build's whole form; a field
        # the operator already changed keeps its value.
        assert "ccApplyEimBuilderConfiguration(form, lastConfiguration, { skipEdited: true });" in text
        assert 'if (skipEdited && control.dataset && control.dataset.ccEimEdited === "true") return;' in text
        # The send lands in the SGP.32 IoT (IPA-d) tab of eSIM Management.
        assert '"get_eim_config", "add_initial_eim", "get_rat", "get_all_data",' in text
        assert '|| suffix === "add_initial_eim"' in text
    assert ".cc-apdu-script-apdu" in css


def test_send_action_shares_the_form_and_is_gated(store_dir: Path) -> None:
    registry = ensure_builtin_actions_loaded()
    send = registry.get("scp11_live.add_initial_eim")
    build = registry.get(BUILD_ID)
    names = [field.name for field in send.inputs]
    assert names[0] == "reader" and names[-1] == "confirm"
    assert names[1:-1] == [field.name for field in build.inputs]
    assert (send.subsystem, send.streams, send.requires_card) == ("eSIM Management", True, True)
    assert "destructive" in send.tags


def _collect(agen) -> list[dict]:
    import asyncio

    async def run() -> list[dict]:
        return [event async for event in agen]

    return asyncio.run(run())


def test_send_refuses_without_confirm_and_on_a_bad_build(store_dir: Path) -> None:
    from yggdrasim_common.gui_server.actions import scp11_live

    unconfirmed = _collect(scp11_live._dispatch_stream_add_initial_eim(None, eim_id=TEST_EIM_ID))
    assert unconfirmed[-1]["level"] == "done" and unconfirmed[-1]["ok"] is False
    bad = _collect(
        scp11_live._dispatch_stream_add_initial_eim(None, confirm=True, eim_id=TEST_EIM_ID, eim_certificate="missing")
    )
    assert any("not built" in event["message"] for event in bad)
    assert bad[-1]["ok"] is False and "nothing was sent" in bad[-1]["message"]


def test_send_streams_the_build_then_the_console_send(store_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from yggdrasim_common.gui_server.actions import scp11_live

    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="eim-signing")
    seen: dict = {}

    async def fake_stream(reader_index, handler_name, argument="", **kwargs):
        seen.update(handler=handler_name, argument=argument, connect_first=kwargs.get("connect_first"))
        console = type("Console", (), {"_add_initial_eim_succeeded": True})()
        yield {"level": "done", "message": kwargs["done_message"], "ok": kwargs["succeeded"](console)}

    monkeypatch.setattr(scp11_live, "_stream_console", fake_stream)
    events = _collect(
        scp11_live._dispatch_stream_add_initial_eim(
            None, confirm=True, eim_id=TEST_EIM_ID, eim_certificate="eim-signing", eim_retrieve_https=True
        )
    )
    assert seen["handler"] == "_send_add_initial_eim_hex"
    assert seen["connect_first"] is True
    assert seen["argument"].startswith("BF57")
    assert any(event["message"].startswith("eUICCMemoryReset: BF640482020106") for event in events)
    assert events[-1] == {"level": "done", "message": "ADD-INITIAL-EIM complete.", "ok": True}


def test_offline_tools_send_matches_the_esim_send(store_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from yggdrasim_common.gui_server.actions import scp11_live

    registry = ensure_builtin_actions_loaded()
    offline = registry.get("tool.eim_builder.send")
    esim = registry.get("scp11_live.add_initial_eim")
    assert offline.subsystem == "Offline Tools"
    assert (offline.streams, offline.requires_card) == (True, True)
    assert "destructive" in offline.tags
    assert [field.name for field in offline.inputs] == [field.name for field in esim.inputs]
    assert offline.description == esim.description

    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="eim-signing")
    seen: dict = {}

    async def fake_stream(reader_index, handler_name, argument="", **kwargs):
        seen.update(handler=handler_name, argument=argument)
        console = type("Console", (), {"_add_initial_eim_succeeded": True})()
        yield {"level": "done", "message": kwargs["done_message"], "ok": kwargs["succeeded"](console)}

    monkeypatch.setattr(scp11_live, "_stream_console", fake_stream)
    events = _collect(offline.dispatcher(None, confirm=True, eim_id=TEST_EIM_ID, eim_certificate="eim-signing"))
    assert seen["handler"] == "_send_add_initial_eim_hex" and seen["argument"].startswith("BF57")
    assert events[-1]["ok"] is True
    refused = _collect(offline.dispatcher(None, eim_id=TEST_EIM_ID, eim_certificate="eim-signing"))
    assert refused[-1]["ok"] is False


def test_certificate_rename_and_saved_value_edit_from_the_gui(store_dir: Path) -> None:
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="before")
    store.remember_values({"eim_id": "typo", "eim_certificate": "before"})
    store.save_configuration("cfg", {"eim_certificate": "before"})
    renamed = _run(CERTIFICATES_ID, operation="rename", name="before", new_name="after")
    assert renamed["detail_lines"][0]["value"] == "cfg"
    edited = _run(VALUES_ID, operation="edit", field="eim_id", value="typo", new_value=TEST_EIM_ID)
    assert edited["values"]["eim_id"] == [TEST_EIM_ID]
    store.remember_values({"tls_certificate": "ghost"})
    listed = _run(VALUES_ID, operation="list")
    assert any(line["value"] == "ghost (not in the certificate store)" for line in listed["detail_lines"])
    removed = _run(CERTIFICATES_ID, operation="remove", name="after")
    assert "Configurations still naming after: cfg" in removed["validation_lines"][0]["value"]


def test_configurations_from_the_build_form_and_the_configurations_action(store_dir: Path) -> None:
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="eim-signing")
    result = _run(
        BUILD_ID,
        configuration="lab",
        save_configuration=True,
        eim_id=TEST_EIM_ID,
        eim_certificate="eim-signing",
        eim_inject_https=True,
        eim_retrieve_https=False,
        indirect_profile_download=True,
    )
    assert any("Saved the form as configuration lab" in line["value"] for line in result["validation_lines"])
    snapshot = _run(VALUES_ID, operation="list")["configurations"]["lab"]
    assert (snapshot["eim_inject_https"], snapshot["eim_retrieve_https"]) == (True, False)
    assert snapshot["indirect_profile_download"] is True and snapshot["eim_id"] == TEST_EIM_ID
    unnamed = _run(BUILD_ID, save_configuration=True, eim_id=TEST_EIM_ID, eim_certificate="eim-signing")
    assert any("without a configuration name" in line["value"] for line in unnamed["validation_lines"])
    listing = _run("tool.eim_builder.configurations", operation="list")
    assert listing["configurations"] == ["lab"]
    assert _run("tool.eim_builder.configurations", operation="rename", name="lab", new_name="lab-2")["configurations"] == ["lab-2"]
    assert _run("tool.eim_builder.configurations", operation="delete", name="lab-2")["configurations"] == []


def test_frontend_fills_a_picked_configuration_and_lists_tools_in_the_nav() -> None:
    source = (ROOT / "gui_frontend/src/js/command-center.js").read_text(encoding="utf-8")
    bundle = (ROOT / "yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
    nav_css = (ROOT / "gui_frontend/src/css/views/command-center-nav-tree.css").read_text(encoding="utf-8")
    for text in (source, bundle):
        assert 'configuration: "configurations",' in text
        assert "function ccApplyEimBuilderConfiguration(" in text
        assert '"tool.eim_builder.configurations": { name: "configurations" },' in text
        # Offline Tools: one nav entry per entry of its table, no card grid;
        # the builder's five tools are one entry with a tab each.
        assert "function ccOfflineToolSubLeaves(" in text
        assert 'id: "add-initial-eim",' in text
        for tool in ("add_initial_eim", "send", "configurations", "certificates", "saved_values"):
            assert '{ action: "tool.eim_builder.' + tool + '", label: ' in text
        # A pane shown again reads the saved names another tab may have changed.
        assert "ccAttachEimBuilderSuggestions(action, rec.form);" in text
        assert 'subList.className = "cc-nav-subchildren";' in text
        # The caret opens the list without selecting the module.
        assert 'subToggle.className = "cc-nav-subtoggle";' in text
        assert '_ccNavGroupRememberState(leaf.id + "-tools", open ? "open" : "closed");' in text
        assert '|| item.getAttribute("data-cc-sub-open") === "1"' in text
        assert "_openInlineActionPane(offlineAction);" in text
        assert "// Every entry is its own nav entry; the surface shows one of them.\n      mutationActions = [];" in text
    assert ".cc-nav-subchildren {" in nav_css
    assert ".cc-nav-subtoggle {" in nav_css
