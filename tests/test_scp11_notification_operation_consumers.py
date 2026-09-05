# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import pytest

from SCP11.local_access.session import LocalIsdrSession
from SCP11.orchestrator import SGP22Orchestrator
from SIMCARD.sgp import SgpLogic


def _tlv(tag: bytes, value: bytes) -> bytes:
    assert len(value) < 0x80
    return bytes(tag) + bytes([len(value)]) + bytes(value)


def _consumer_instances() -> tuple[object, object]:
    return (
        object.__new__(SGP22Orchestrator),
        object.__new__(LocalIsdrSession),
    )


@pytest.mark.parametrize(
    ("operation", "expected_name"),
    [
        (SgpLogic.NOTIF_INSTALL, "install"),
        (SgpLogic.NOTIF_ENABLE, "enable"),
        (SgpLogic.NOTIF_DISABLE, "disable"),
        (SgpLogic.NOTIF_DELETE, "delete"),
    ],
)
def test_scp11_consumers_decode_simulator_notification_event_bit_strings(
    operation: int,
    expected_name: str,
) -> None:
    operation_value = SgpLogic._encode_notification_event(operation)
    metadata_value = (
        _tlv(b"\x80", b"\x01")
        + _tlv(b"\x81", operation_value)
        + _tlv(b"\x0C", b"notify.example.test")
    )

    for consumer in _consumer_instances():
        details = consumer._decode_notification_metadata_fields(metadata_value)

        assert details["profileManagementOperation"] == operation
        assert details["profileManagementOperationName"] == expected_name
        assert details["notificationParseError"] == ""


@pytest.mark.parametrize(
    ("operation_value", "error_fragment"),
    [
        (b"", "unused-bit octet"),
        (b"\x07", "unused-bit octet"),
        (b"\x08\x80", "must be 0..7"),
        (b"\x07\x81", "non-zero padding"),
        (b"\x00\x00", "exactly one event bit"),
        (b"\x04\x50", "exactly one event bit"),
        (b"\x00\x80", "not canonical"),
    ],
)
def test_scp11_consumers_do_not_reinterpret_malformed_notification_bit_strings(
    operation_value: bytes,
    error_fragment: str,
) -> None:
    metadata_value = _tlv(b"\x81", operation_value)

    for consumer in _consumer_instances():
        details = consumer._decode_notification_metadata_fields(metadata_value)

        assert details["profileManagementOperation"] is None
        assert details["profileManagementOperationName"] == ""
        assert error_fragment in details["notificationParseError"]


def test_scp11_consumers_report_duplicate_notification_operation_fields() -> None:
    metadata_value = _tlv(b"\x81", b"\x07\x80") + _tlv(
        b"\x81", b"\x06\x40"
    )

    for consumer in _consumer_instances():
        details = consumer._decode_notification_metadata_fields(metadata_value)

        assert details["profileManagementOperation"] is None
        assert details["profileManagementOperationName"] == ""
        assert "duplicate" in details["notificationParseError"]


def test_scp11_consumers_preserve_invalid_notification_address_bytes() -> None:
    metadata_value = (
        _tlv(b"\x81", b"\x07\x80")
        + _tlv(b"\x0C", b"rsp.\xFF.example")
    )

    for consumer in _consumer_instances():
        details = consumer._decode_notification_metadata_fields(metadata_value)

        assert details["notificationAddress"] == ""
        assert details["notificationAddressRawHex"] == "7273702EFF2E6578616D706C65"
        assert "not valid UTF-8" in details["notificationParseError"]


def test_orchestrator_normalises_asn1tools_bit_string_tuple() -> None:
    orchestrator = object.__new__(SGP22Orchestrator)
    details: dict = {}

    orchestrator._collect_notification_details(
        {"profileManagementOperation": (b"\x10", 4)},
        details,
    )

    assert details["profileManagementOperation"] == SgpLogic.NOTIF_DELETE
    assert details["profileManagementOperationName"] == "delete"
    assert "notificationParseError" not in details


@pytest.mark.parametrize(
    "decoded_value",
    [
        (b"\x80", 0),
        (b"\x80", 9),
        (b"\x81", 1),
        1,
    ],
)
def test_orchestrator_reports_malformed_decoded_bit_string(
    decoded_value: object,
) -> None:
    orchestrator = object.__new__(SGP22Orchestrator)
    details: dict = {}

    orchestrator._collect_notification_details(
        {"profileManagementOperation": decoded_value},
        details,
    )

    assert "notificationParseError" in details
    assert "profileManagementOperation" not in details


def test_orchestrator_decoded_address_fallback_is_strict_and_fail_closed() -> None:
    orchestrator = object.__new__(SGP22Orchestrator)
    details: dict = {}

    orchestrator._collect_notification_details(
        {"notificationAddress": b"rsp.\xFF.example"},
        details,
    )

    assert "notificationAddress" not in details
    assert details["notificationAddressRawHex"] == "7273702EFF2E6578616D706C65"
    assert "not valid UTF-8" in details["notificationParseError"]
    assert orchestrator._extract_notification_address_for_forwarding(
        {"notificationAddress": b"rsp.\xFF.example"}
    ) == ""


def test_notification_diagnostics_are_visible_in_operator_summaries() -> None:
    orchestrator = object.__new__(SGP22Orchestrator)
    local_session = object.__new__(LocalIsdrSession)
    valid_details = {
        "profileManagementOperation": SgpLogic.NOTIF_ENABLE,
        "profileManagementOperationName": "enable",
    }
    invalid_details = {
        "notificationParseError": (
            "profileManagementOperation BIT STRING has non-zero padding bits"
        )
    }

    assert (
        "profileManagementOperation=enable(2)"
        in orchestrator._format_notification_details(valid_details)
    )
    assert (
        "notificationParseError="
        in orchestrator._format_notification_details(invalid_details)
    )

    valid_result = _tlv(
        bytes.fromhex("BF37"),
        _tlv(
            bytes.fromhex("BF27"),
            _tlv(b"\x80", b"\x01")
            + _tlv(
                bytes.fromhex("BF2F"),
                _tlv(b"\x80", b"\x02")
                + _tlv(b"\x81", b"\x06\x40")
                + _tlv(b"\x0C", b"notify.example.test"),
            ),
        ),
    )
    malformed_result = _tlv(
        bytes.fromhex("BF37"),
        _tlv(
            bytes.fromhex("BF27"),
            _tlv(b"\x80", b"\x01")
            + _tlv(
                bytes.fromhex("BF2F"),
                _tlv(b"\x80", b"\x02") + _tlv(b"\x81", b"\x07\x81"),
            ),
        ),
    )

    assert (
        "profileManagementOperation=enable(2)"
        in local_session._summarize_profile_installation_result(valid_result)
    )
    assert (
        "notificationParseError="
        in local_session._summarize_profile_installation_result(malformed_result)
    )
