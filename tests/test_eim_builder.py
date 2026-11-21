# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""AddInitialEim builder and its terminal wizard."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from SCP11.shared import eim_builder_store as store
from SCP11.shared.eim_builder import (
    BuilderInputs,
    EimBuilderError,
    build_add_initial_eim,
    canonical_eim_id_type,
    parse_protocol_names,
    run_wizard,
)
from tests.eim_builder_support import TEST_EIM_FQDN, TEST_EIM_ID, der, make_certificate, pem


@pytest.fixture()
def stocked(tmp_path: Path) -> Path:
    eim, _ = make_certificate(TEST_EIM_ID)
    tls, _ = make_certificate("eIM TLS Test CA", ca=True)
    store.import_certificates(der(eim), name="eim-signing", directory=tmp_path)
    store.import_certificates(der(tls), name="tls-ca", directory=tmp_path)
    return tmp_path


def _inputs(**changes) -> BuilderInputs:
    values = dict(
        eim_id=TEST_EIM_ID,
        eim_certificate="eim-signing",
        eim_fqdn=TEST_EIM_FQDN,
        association_token=True,
        tls_certificate="tls-ca",
        indirect_profile_download=True,
    )
    values.update(changes)
    return BuilderInputs(**values)


def _severities(result) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for finding in result.findings:
        grouped.setdefault(finding.severity, []).append(finding.text)
    return grouped


def test_build_returns_a_verified_request_and_the_reset_first_script(stocked: Path) -> None:
    result = build_add_initial_eim(_inputs(), directory=stocked)
    assert result.request[:2] == b"\xBF\x57"
    assert result.reset_request.hex().upper() == "BF640482020106"
    assert result.script_text().splitlines()[:4] == [
        "80AA000005A903840101",
        "0070000001",
        "01A4040010A0000005591010FFFFFFFF8900000100",
        "81E2910007BF640482020106",
    ]
    labels = {label: value for _indent, label, value in result.summary_rows()}
    assert labels["eimId"] == TEST_EIM_ID
    assert labels["eimIdType"] == "eimIdTypeOid (1)"
    assert labels["associationToken"].startswith("-1")
    assert "tls-ca" in labels["trustedPublicKeyDataTls"]
    assert "warning" not in _severities(result)


def test_build_records_the_typed_values_and_the_last_build(stocked: Path) -> None:
    build_add_initial_eim(_inputs(euicc_ci_pk_id="f5 41 72"), directory=stocked)
    values = store.load_values(stocked)
    assert values["eim_id"] == [TEST_EIM_ID]
    assert values["euicc_ci_pk_id"] == ["F54172"]
    build_add_initial_eim(_inputs(tls_certificate="", euicc_ci_pk_id=""), directory=stocked, remember=True)
    last = store.load_last_build(stocked)
    assert (last["tls_certificate"], last["euicc_ci_pk_id"]) == ("", "")
    assert store.load_values(stocked)["tls_certificate"] == ["tls-ca"]


def test_build_without_remember_leaves_the_store_alone(stocked: Path) -> None:
    build_add_initial_eim(_inputs(), directory=stocked, remember=False)
    assert (stocked / store.VALUES_FILE_NAME).exists() is False


def test_public_key_forms_carry_the_subject_public_key_info(stocked: Path) -> None:
    result = build_add_initial_eim(
        _inputs(eim_key_form="eimPublicKey", tls_key_form="trustedEimPkTls"), directory=stocked, remember=False
    )
    spki = store.read_certificate("eim-signing", stocked).spki_der
    assert b"\xA0" + spki[1:] in result.request
    assert result.entry.eim_public_key_data.der == spki


def test_no_protocol_bit_leaves_the_member_out(stocked: Path) -> None:
    result = build_add_initial_eim(_inputs(eim_supported_protocol=()), directory=stocked, remember=False)
    assert result.entry.eim_supported_protocol is None
    labels = {label: value for _indent, label, value in result.summary_rows()}
    assert labels["eimSupportedProtocol"].startswith("(omitted")


def test_findings_name_what_the_specification_expects(tmp_path: Path) -> None:
    eim, _ = make_certificate("some-other-cn", days=10)
    tls, _ = make_certificate("tls-without-ski", ca=True, ski=False)
    store.import_certificates(der(eim), name="eim", directory=tmp_path)
    store.import_certificates(der(tls), name="tls", directory=tmp_path)
    result = build_add_initial_eim(
        _inputs(eim_certificate="eim", tls_certificate="tls", counter_value=0x800000),
        directory=tmp_path,
        remember=False,
        now=datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc),
    )
    warnings = " ".join(_severities(result)["warning"])
    assert "8388607" in warnings
    assert "expired" in warnings
    assert "SubjectKeyIdentifier" in warnings
    without_tls = build_add_initial_eim(_inputs(eim_certificate="eim", tls_certificate=""), directory=tmp_path, remember=False)
    assert any("trustedCertificateTls" in text for text in _severities(without_tls)["note"])
    # The eimId is free text: a certificate CN that differs from it draws nothing.
    assert not any("CN" in finding.text for finding in result.findings + without_tls.findings)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"eim_id": " "}, "eimId is required"),
        ({"eim_certificate": ""}, "eIM certificate"),
        ({"eim_certificate": "missing"}, "eimPublicKeyData: No stored certificate"),
        ({"tls_certificate": "missing"}, "trustedPublicKeyDataTls: No stored certificate"),
        ({"euicc_ci_pk_id": "F5G"}, "euiccCiPKId is not valid hex"),
        ({"eim_id_type": "eimIdTypeX"}, "eimIdType"),
        ({"eim_key_form": "rawKey"}, "eimPublicKeyData alternative"),
        ({"eim_id": "é" * 65}, "128"),
        ({"eim_id": "eim-one", "eim_id_type": "eimIdTypeOid"}, "dotted OID"),
        ({"eim_id_type": "uuid"}, "eimIdType 'uuid'"),
    ],
)
def test_bad_inputs_raise_a_builder_error(stocked: Path, changes: dict, message: str) -> None:
    with pytest.raises(EimBuilderError, match=message):
        build_add_initial_eim(_inputs(**changes), directory=stocked, remember=False)


def test_eim_id_type_shorthand_and_the_fqdn_mismatch_warning(stocked: Path) -> None:
    assert canonical_eim_id_type("OID") == "eimIdTypeOid"
    assert canonical_eim_id_type("Fqdn") == "eimIdTypeFqdn"
    # SGP.32 v1.3 §4.3 / §2.11.1.1.1: with eimIdTypeFqdn the host typed as eimFqdn is the entry's eimId.
    result = build_add_initial_eim(_inputs(eim_id_type="fqdn"), directory=stocked, remember=False)
    assert (result.entry.eim_id, result.entry.eim_id_type, result.entry.eim_fqdn) == (TEST_EIM_FQDN, 2, None)
    assert b"\x80\x10" + TEST_EIM_FQDN.encode() + b"\x82\x01\x02" in result.request
    assert any("is not sent" in text and TEST_EIM_ID in text for text in _severities(result)["warning"])
    with pytest.raises(EimBuilderError, match="eimIdTypeFqdn needs the eimId as a host name"):
        build_add_initial_eim(_inputs(eim_id_type="fqdn", eim_fqdn=""), directory=stocked, remember=False)
    with pytest.raises(EimBuilderError, match="name two"):
        build_add_initial_eim(_inputs(eim_id="eim-a.example.test", eim_id_type="fqdn"), directory=stocked, remember=False)
    same = build_add_initial_eim(_inputs(eim_id=TEST_EIM_FQDN, eim_id_type="fqdn"), directory=stocked, remember=False)
    assert (same.entry.eim_id, same.entry.eim_fqdn) == (TEST_EIM_FQDN, None)
    assert not same.findings or all(finding.severity != "warning" or "is not sent" not in finding.text
                                    for finding in same.findings)
    host = build_add_initial_eim(_inputs(eim_id=TEST_EIM_FQDN, eim_id_type="auto"), directory=stocked, remember=False)
    assert (host.entry.eim_id, host.entry.eim_id_type, host.entry.eim_fqdn) == (TEST_EIM_FQDN, 2, None)
    oid = build_add_initial_eim(_inputs(), directory=stocked, remember=False)
    assert (oid.entry.eim_id_type, oid.entry.eim_fqdn) == (1, TEST_EIM_FQDN)
    assert not any("eimIdTypeFqdn" in finding.text for finding in oid.findings)
    from SCP11.shared.eim_configuration_data import add_initial_eim_problems
    from dataclasses import replace
    assert any("eimFqdn SHALL NOT be provided" in text
               for text in add_initial_eim_problems([replace(host.entry, eim_fqdn=TEST_EIM_FQDN)]))
    assert add_initial_eim_problems([host.entry]) == []
    assert not any("MANAGE CHANNEL" in finding.text for finding in result.findings)


def test_protocol_names_by_name_or_number() -> None:
    assert parse_protocol_names("1, eiminjectcoaps 1") == ("eimRetrieveHttps", "eimInjectCoaps")
    with pytest.raises(EimBuilderError):
        parse_protocol_names("6")
    with pytest.raises(EimBuilderError):
        parse_protocol_names("eimCarrierPigeon")


def _scripted(answers: list[str]):
    pending = list(answers)
    prompts: list[str] = []

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        if not pending:
            raise EOFError()
        return pending.pop(0)

    return ask, prompts


def test_wizard_collects_one_member_per_step(stocked: Path) -> None:
    ask, prompts = _scripted(["1", "", TEST_EIM_ID, "", TEST_EIM_FQDN, "abc", "7", "y", "2", "", "1,3", "SKIP", "y"])
    lines: list[str] = []
    inputs = run_wizard(ask, lines.append, directory=stocked)
    assert inputs == BuilderInputs(
        eim_id=TEST_EIM_ID,
        eim_certificate="eim-signing",
        eim_key_form="eimCertificate",
        eim_id_type="auto",
        eim_fqdn=TEST_EIM_FQDN,
        counter_value=7,
        association_token=True,
        tls_certificate="tls-ca",
        tls_key_form="trustedCertificateTls",
        eim_supported_protocol=("eimRetrieveHttps", "eimInjectHttps"),
        euicc_ci_pk_id="",
        indirect_profile_download=True,
    )
    assert any("counterValue is a whole number" in line for line in lines)
    assert len(prompts) == 13


def test_wizard_defaults_come_from_the_last_build(stocked: Path) -> None:
    build_add_initial_eim(_inputs(euicc_ci_pk_id="F54172", tls_certificate=""), directory=stocked)
    ask, _prompts = _scripted([""] * 11)
    inputs = run_wizard(ask, lambda _line: None, directory=stocked)
    assert inputs is not None
    assert (inputs.eim_certificate, inputs.eim_id, inputs.eim_fqdn) == ("eim-signing", TEST_EIM_ID, TEST_EIM_FQDN)
    assert (inputs.tls_certificate, inputs.euicc_ci_pk_id) == ("", "F54172")


def test_the_eim_id_default_is_the_last_build_whatever_the_certificate(stocked: Path) -> None:
    other, _ = make_certificate("eIM Second Test CN")
    store.import_certificates(der(other), name="eim-second", directory=stocked)
    build_add_initial_eim(_inputs(), directory=stocked)
    ask, _prompts = _scripted(["eim-second"] + [""] * 11)
    lines: list[str] = []
    inputs = run_wizard(ask, lines.append, directory=stocked)
    assert inputs is not None
    assert inputs.eim_id == TEST_EIM_ID
    assert not any("eIM Second Test CN" in line for line in lines if "eimId" in line)


def test_the_eim_id_is_free_text(stocked: Path) -> None:
    ask, _prompts = _scripted(["1", "", "my eIM / any text", "", "", "", "", "", "", "", ""])
    inputs = run_wizard(ask, lambda _line: None, directory=stocked)
    assert inputs is not None and inputs.eim_id == "my eIM / any text"
    result = build_add_initial_eim(inputs, directory=stocked, remember=False)
    assert result.entry.eim_id == "my eIM / any text"
    assert result.entry.eim_id_type == 3


def test_wizard_reads_shorthand_and_refuses_an_oid_type_for_text(stocked: Path) -> None:
    answers = ["1", "key", "eim-one", "OID", "prop", "", "", "", "SKIP", "", "SKIP", ""]
    ask, _prompts = _scripted(answers)
    lines: list[str] = []
    inputs = run_wizard(ask, lines.append, directory=stocked)
    assert inputs is not None
    assert (inputs.eim_key_form, inputs.eim_id_type) == ("eimPublicKey", "eimIdTypeProprietary")
    assert any("dotted OID" in line for line in lines)


def test_wizard_reuses_an_identical_stored_certificate(stocked: Path, tmp_path: Path) -> None:
    source = tmp_path / "again.der"
    source.write_bytes(store.read_certificate("eim-signing", stocked).der)
    ask, _prompts = _scripted([str(source), "", TEST_EIM_ID] + [""] * 8)
    lines: list[str] = []
    inputs = run_wizard(ask, lines.append, directory=stocked)
    assert inputs is not None and inputs.eim_certificate == "eim-signing"
    assert any("Already stored as eim-signing" in line for line in lines)


def test_wizard_imports_a_certificate_given_as_a_path(tmp_path: Path) -> None:
    certificate, _ = make_certificate(TEST_EIM_ID)
    source = tmp_path / "incoming.pem"
    source.write_bytes(pem(certificate))
    directory = tmp_path / "store"
    other, _ = make_certificate("other")
    store.import_certificates(der(other), name="taken", directory=directory)
    ask, _prompts = _scripted([str(source), "taken", "", "", TEST_EIM_ID, "", "", "", "n", "SKIP", "", "SKIP", "n"])
    lines: list[str] = []
    inputs = run_wizard(ask, lines.append, directory=directory)
    assert inputs is not None
    assert inputs.eim_certificate == TEST_EIM_ID
    assert inputs.eim_supported_protocol == ("eimRetrieveHttps",)
    assert any(line.strip().startswith("[+] Stored") for line in lines)
    assert any("taken is already stored" in line for line in lines)
    assert store.read_certificate(TEST_EIM_ID, directory).der == der(certificate)


@pytest.mark.parametrize("answers", [["CANCEL"], ["1", "", "abort"], []])
def test_wizard_cancel_and_end_of_input_build_nothing(stocked: Path, answers: list[str]) -> None:
    ask, _prompts = _scripted(answers)
    lines: list[str] = []
    assert run_wizard(ask, lines.append, directory=stocked) is None
    assert any("cancelled" in line for line in lines)
    assert (stocked / store.VALUES_FILE_NAME).exists() is False


def test_configuration_round_trip_and_type_checks() -> None:
    from SCP11.shared.eim_builder import configuration_from_inputs, inputs_from_configuration

    inputs = _inputs(eim_id_type="eimIdTypeOid", counter_value=5, eim_supported_protocol=("eimInjectHttps",))
    stored = configuration_from_inputs(inputs)
    assert stored["eim_supported_protocol"] == ["eimInjectHttps"]
    assert inputs_from_configuration(stored) == inputs
    assert inputs_from_configuration({"eim_id": "x", "eim_id_type": "oid"}).eim_id_type == "eimIdTypeOid"
    assert inputs_from_configuration({"eim_supported_protocol": None}).eim_supported_protocol is None
    for bad in ({"counter_value": "5"}, {"association_token": 1}, {"eim_id": 5}, {"eim_supported_protocol": "x"}):
        with pytest.raises(EimBuilderError):
            inputs_from_configuration(bad)


def test_configured_wizard_starts_from_a_configuration_and_saves_one(stocked: Path) -> None:
    from SCP11.shared.eim_builder import configuration_from_inputs, offer_save_configuration, run_configured_wizard

    store.save_configuration(
        "lab",
        configuration_from_inputs(
            _inputs(counter_value=9, eim_key_form="eimPublicKey", eim_supported_protocol=None, euicc_ci_pk_id="F541")
        ),
        stocked,
    )
    ask, _prompts = _scripted(["1"] + [""] * 12)
    lines: list[str] = []
    outcome = run_configured_wizard(ask, lines.append, directory=stocked)
    assert outcome is not None and outcome.configuration == "lab"
    assert (outcome.inputs.counter_value, outcome.inputs.eim_key_form) == (9, "eimPublicKey")
    assert outcome.inputs.eim_supported_protocol is None
    assert outcome.inputs.euicc_ci_pk_id == "F541"
    ask, _prompts = _scripted(["lab-2"])
    assert offer_save_configuration(ask, lines.append, outcome.inputs, "lab", directory=stocked) == "lab-2"
    assert sorted(store.load_configurations(stocked)) == ["lab", "lab-2"]
    ask, _prompts = _scripted([""])
    assert offer_save_configuration(ask, lines.append, outcome.inputs, directory=stocked) == ""
    ask, _prompts = _scripted(["CANCEL"])
    assert run_configured_wizard(ask, lines.append, directory=stocked) is None


def test_build_records_the_whole_form_as_the_last_build(stocked: Path) -> None:
    inputs = _inputs(eim_id=TEST_EIM_FQDN, counter_value=42, eim_id_type="eimIdTypeFqdn", eim_key_form="eimPublicKey",
                     eim_supported_protocol=("eimRetrieveCoaps", "eimInjectCoaps"), indirect_profile_download=True)
    build_add_initial_eim(inputs, directory=stocked)
    remembered = store.load_last_configuration(stocked)
    assert remembered["counter_value"] == 42
    assert remembered["eim_id_type"] == "eimIdTypeFqdn"
    assert remembered["eim_key_form"] == "eimPublicKey"
    assert remembered["eim_supported_protocol"] == ["eimRetrieveCoaps", "eimInjectCoaps"]
    assert remembered["indirect_profile_download"] is True


def test_the_wizard_starts_from_the_whole_last_build(stocked: Path) -> None:
    build_add_initial_eim(_inputs(counter_value=42, eim_key_form="eimPublicKey"), directory=stocked)
    ask, _prompts = _scripted([""] * 12)
    inputs = run_wizard(ask, lambda _line: None, directory=stocked)
    assert inputs is not None
    assert (inputs.counter_value, inputs.eim_key_form, inputs.eim_id) == (42, "eimPublicKey", TEST_EIM_ID)


def test_the_request_as_one_apdu_splits_into_the_script_blocks(stocked: Path) -> None:
    from yggdrasim_common.apdu_chunking import plan_oversized_command

    result = build_add_initial_eim(_inputs(), directory=stocked, remember=False)
    assert len(result.request) > 255
    single = result.request_apdu.apdu
    # Extended Lc: '00' and two length bytes, then the whole request.
    assert single[:4] == bytes.fromhex("81E29100")
    assert single[4:7] == b"\x00" + len(result.request).to_bytes(2, "big")
    assert single[7:] == result.request
    assert "extended Lc" in result.request_apdu.label
    blocks = [step.apdu for step in result.script if step.label.startswith("STORE DATA: AddInitialEim")]
    assert [block.apdu for block in plan_oversized_command(single)] == blocks


def test_a_short_request_is_one_short_apdu(stocked: Path) -> None:
    result = build_add_initial_eim(
        _inputs(eim_key_form="eimPublicKey", tls_certificate=""), directory=stocked, remember=False
    )
    assert len(result.request) <= 255
    single = result.request_apdu.apdu
    assert single == bytes.fromhex("81E29100") + bytes([len(result.request)]) + result.request
    assert [step.apdu for step in result.script][-1] == single
