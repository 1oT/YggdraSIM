# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local eIM authoring of SGP.32 §2.11.1.2 IpaEuiccDataRequest (BF52).

The eIM composes the request; the IPA answers it. These cover the composing
half -- lint rules, spec rows, and the wire encoding -- and close the loop by
parsing the emitted bytes back with the IPA-side parser.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from SCP11.eim_local.eim_package_codec import (
    encode_notification_event_bits,
    ipa_euicc_data_request_tag_items,
    lint_eim_package_document,
)
from SCP11.eim_local.session import EimLocalSession
from SCP11.eim_packages import TYPE_EUICC_CONFIGURATION, parse_eim_package

TEMPLATE_PATH = (
    Path(__file__).resolve().parent.parent
    / "SCP11"
    / "eim_local"
    / "eim_packages"
    / "templates"
    / "template_ipa_euicc_data_request.json"
)

# The canonical document shape, held here so the behaviour tests do not depend
# on the template file being present in the checkout.
CANONICAL_DOCUMENT: dict[str, Any] = {
    "package_type": "ipa_euicc_data_request",
    "package_version": "1.0.0",
    "spec_target": "SGP.32 §2.11.1.2 IpaEuiccDataRequest (BF52)",
    "sgp32": {
        "ipa_euicc_data_request": {
            "include": True,
            "command_tag_hex": "BF52",
            "tag_list": {
                "include": True,
                "tag_hex": "5C",
                "items": {
                    "notifications": {"include": True, "tag_hex": "A0"},
                    "default_smdp_address": {"include": False, "tag_hex": "81"},
                    "euicc_package_results": {"include": True, "tag_hex": "A2"},
                    "euicc_info1": {"include": False, "tag_hex": "BF20"},
                    "euicc_info2": {"include": False, "tag_hex": "BF22"},
                    "root_smds_address": {"include": False, "tag_hex": "83"},
                    "association_token": {"include": False, "tag_hex": "84"},
                    "eum_certificate": {"include": False, "tag_hex": "A5"},
                    "euicc_certificate": {"include": False, "tag_hex": "A6"},
                    "ipa_capabilities": {"include": False, "tag_hex": "A8"},
                    "device_info": {"include": False, "tag_hex": "A9"},
                },
            },
            "euicc_ci_pk_identifier_to_be_used": {
                "include": False,
                "tag_hex": "04",
                "value_hex": "",
            },
            "search_criteria_notification": {
                "include": False,
                "tag_hex": "A1",
                "choice": "profile_management_operation",
                "seq_number": {"include": False, "tag_hex": "80", "value": 1},
                "profile_management_operation": {
                    "include": True,
                    "tag_hex": "81",
                    "events": {
                        "notification_install": False,
                        "notification_local_enable": True,
                        "notification_local_disable": False,
                        "notification_local_delete": False,
                    },
                },
            },
            "search_criteria_euicc_package_result": {
                "include": False,
                "tag_hex": "A2",
                "seq_number": {"include": True, "tag_hex": "80", "value": 1},
            },
            "eim_transaction_id": {"include": False, "tag_hex": "83", "value_hex": ""},
            "request_payload": {"include": False, "value_hex": ""},
        }
    },
    "runtime": {
        "matching_id": "EIM-IPA-EUICC-DATA",
        "transaction_id_hex": "",
        "allow_model_only": True,
    },
    "additional_tlvs": [],
    "optional_tags": {},
}


def _blank_session() -> EimLocalSession:
    # Bypass __init__: the request encoder is pure over the document and the
    # class helper methods, so no card or file state is needed.
    return object.__new__(EimLocalSession)


def _template() -> dict[str, Any]:
    return copy.deepcopy(CANONICAL_DOCUMENT)


def _encode(document: dict[str, Any]) -> bytes:
    return _blank_session().build_wire_payload_preview(document)


def _spec_status(document: dict[str, Any], check: str) -> str:
    for row in lint_eim_package_document(document)["spec_checks"]:
        if row["check"] == check:
            return row["status"]
    return "MISSING"


def test_template_lints_clean_and_selects_notifications_and_package_results() -> None:
    report = lint_eim_package_document(_template())
    assert report["ok"] is True, report["errors"]
    assert report["spec_failed"] == 0
    request = _template()["sgp32"]["ipa_euicc_data_request"]
    assert ipa_euicc_data_request_tag_items(request) == ("A0", "A2")


def test_full_request_encoding_matches_der_reference() -> None:
    document = _template()
    request = document["sgp32"]["ipa_euicc_data_request"]
    request["euicc_ci_pk_identifier_to_be_used"] = {
        "include": True,
        "tag_hex": "04",
        "value_hex": "0102030405",
    }
    request["search_criteria_notification"] = {
        "include": True,
        "tag_hex": "A1",
        "choice": "seq_number",
        "seq_number": {"include": True, "tag_hex": "80", "value": 2},
    }
    request["search_criteria_euicc_package_result"] = {
        "include": True,
        "tag_hex": "A2",
        "seq_number": {"include": True, "tag_hex": "80", "value": 9},
    }
    request["eim_transaction_id"] = {"include": True, "tag_hex": "83", "value_hex": "0102"}

    # DER for IpaEuiccDataRequest with every OPTIONAL field present.
    # euiccCiPKIdentifierToBeUsed keeps the universal '04' tag: tagList bears
    # [APPLICATION 28], so automatic tagging does not apply to this SEQUENCE.
    assert _encode(document).hex().upper() == (
        "BF52195C02A0A204050102030405A103800102A20380010983020102"
    )


def test_tag_list_emits_spec_order_regardless_of_document_order() -> None:
    document = _template()
    items = document["sgp32"]["ipa_euicc_data_request"]["tag_list"]["items"]
    items["device_info"]["include"] = True
    items["euicc_info2"]["include"] = True
    reordered = {
        "device_info": items["device_info"],
        "euicc_info2": items["euicc_info2"],
        "notifications": items["notifications"],
        "euicc_package_results": items["euicc_package_results"],
    }
    document["sgp32"]["ipa_euicc_data_request"]["tag_list"]["items"] = reordered

    assert _encode(document).hex().upper().startswith("BF52075C05A0A2BF22A9")


def test_emitted_request_parses_back_with_search_criteria() -> None:
    document = _template()
    request = document["sgp32"]["ipa_euicc_data_request"]
    request["search_criteria_notification"]["include"] = True
    request["search_criteria_euicc_package_result"]["include"] = True
    request["search_criteria_euicc_package_result"]["seq_number"]["value"] = 9

    parsed = parse_eim_package(_encode(document))

    assert parsed.package_type == TYPE_EUICC_CONFIGURATION
    assert parsed.requested_tags == (b"\xA0", b"\xA2")
    # notificationLocalEnable(1) only.
    assert parsed.notification_profile_management_operation == bytes.fromhex("0640")
    assert parsed.notification_seq_number is None
    assert parsed.euicc_package_result_seq_number == 9


def test_eim_package_request_choice_branch_encodes_and_lints_identically() -> None:
    template = _template()
    request = template["sgp32"]["ipa_euicc_data_request"]
    wrapped = {
        "package_type": "eim_package_request",
        "package_version": "1.0.0",
        "sgp32": {
            "eim_package_request": {
                "include": True,
                "choice": "ipa_euicc_data_request",
                "ipa_euicc_data_request": copy.deepcopy(request),
            }
        },
        "runtime": {"matching_id": "EIM-PKG-REQ", "allow_model_only": True},
    }

    report = lint_eim_package_document(wrapped)

    assert report["ok"] is True, report["errors"]
    assert _encode(wrapped) == _encode(template)


def test_lint_rejects_empty_tag_list() -> None:
    document = _template()
    for row in document["sgp32"]["ipa_euicc_data_request"]["tag_list"]["items"].values():
        row["include"] = False

    errors = lint_eim_package_document(document)["errors"]

    assert any("tag_list must select at least one data item" in error for error in errors)


def test_lint_rejects_tag_outside_the_spec_list() -> None:
    document = _template()
    items = document["sgp32"]["ipa_euicc_data_request"]["tag_list"]["items"]
    items["notifications"]["tag_hex"] = "A7"

    errors = lint_eim_package_document(document)["errors"]

    assert any("is not an SGP.32 §2.11.1.2 data item" in error for error in errors)


def test_lint_rejects_profile_management_operation_with_no_events() -> None:
    document = _template()
    criteria = document["sgp32"]["ipa_euicc_data_request"]["search_criteria_notification"]
    criteria["include"] = True
    for name in criteria["profile_management_operation"]["events"]:
        criteria["profile_management_operation"]["events"][name] = False

    errors = lint_eim_package_document(document)["errors"]

    assert any("must set at least one notification type" in error for error in errors)


def test_lint_rejects_negative_search_criteria_sequence_number() -> None:
    document = _template()
    criteria = document["sgp32"]["ipa_euicc_data_request"]["search_criteria_euicc_package_result"]
    criteria["include"] = True
    criteria["seq_number"]["value"] = -1

    errors = lint_eim_package_document(document)["errors"]

    assert any("seq_number.value must be a non-negative integer" in error for error in errors)


def test_lint_rejects_oversized_ci_public_key_identifier() -> None:
    document = _template()
    document["sgp32"]["ipa_euicc_data_request"]["euicc_ci_pk_identifier_to_be_used"] = {
        "include": True,
        "tag_hex": "04",
        "value_hex": "AA" * 21,
    }

    errors = lint_eim_package_document(document)["errors"]

    assert any("must be at most 20 bytes" in error for error in errors)


def test_spec_check_flags_search_criteria_without_its_tag_list_entry() -> None:
    document = _template()
    document["sgp32"]["ipa_euicc_data_request"]["tag_list"]["items"]["notifications"]["include"] = False
    document["sgp32"]["ipa_euicc_data_request"]["search_criteria_notification"]["include"] = True

    # SGP.32 §2.11.1.2: without tag 'A0' the IPA ignores searchCriteriaNotification.
    assert _spec_status(document, "searchCriteriaNotification paired with tagList 'A0'") == "FAIL"
    assert _spec_status(document, "searchCriteriaEuiccPackageResult paired with tagList 'A2'") == "MISSING"


def test_notification_event_bits_match_the_card_side_encoding() -> None:
    assert encode_notification_event_bits({"notification_install": True}) == bytes.fromhex("0780")
    assert encode_notification_event_bits({"notification_local_enable": True}) == bytes.fromhex("0640")
    assert encode_notification_event_bits(
        {"notification_install": True, "notification_local_delete": True}
    ) == bytes.fromhex("0490")
    assert encode_notification_event_bits({}) == b"\x00"


def _opaque_document(value_hex: str) -> dict[str, Any]:
    return {
        "package_type": "ipa_euicc_data_request",
        "package_version": "1.0.0",
        "sgp32": {
            "ipa_euicc_data_request": {
                "include": True,
                "request_payload": {"include": True, "value_hex": value_hex},
            }
        },
        "runtime": {"allow_model_only": True},
    }


def test_captured_body_is_replayed_verbatim_under_bf52() -> None:
    document = _opaque_document("5C02A0A2")

    report = lint_eim_package_document(document)

    assert report["ok"] is True, report["errors"]
    assert _encode(document).hex().upper() == "BF52045C02A0A2"
    assert _spec_status(document, "IpaEuiccDataRequest body supplied verbatim") == "PASS"


def test_captured_body_keeping_its_own_bf52_tag_is_not_double_wrapped() -> None:
    assert _encode(_opaque_document("BF52045C02A0A2")).hex().upper() == "BF52045C02A0A2"


def test_lint_rejects_captured_body_without_hex() -> None:
    errors = lint_eim_package_document(_opaque_document(""))["errors"]

    assert any("request_payload.value_hex must be non-empty" in error for error in errors)


def test_execution_coverage_registers_the_type_as_model_only() -> None:
    coverage = _blank_session().execution_coverage_matrix()["ipa_euicc_data_request"]

    assert coverage["mode"] == "model_only"
    assert coverage["execution_path"] == "pending_operation_register"


@pytest.mark.skipif(
    TEMPLATE_PATH.exists() is False,
    reason="template_ipa_euicc_data_request.json is not present in this checkout",
)
def test_shipped_template_matches_the_canonical_document() -> None:
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as handle:
        shipped = json.load(handle)

    assert shipped == CANONICAL_DOCUMENT
