# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

from types import SimpleNamespace

import pytest

from Tools.ProfilePackage.saip_hex_template import InlinePlaceholderRecord
from Tools.ProfilePackage.saip_variable_materialization import (
    SaipVariableMaterializationError,
    catalog_variables,
    encode_inline_placeholder_value,
    find_catalog_variable,
    materialize_catalog_variable,
    materialize_inline_variable,
    variable_is_secret,
)


def _record(
    index: int,
    variable: str,
    type_name: str,
    byte_length: int,
    sentinel_hex: str,
    modifier: str | None = None,
) -> InlinePlaceholderRecord:
    return InlinePlaceholderRecord(
        index=index,
        literal=f"{{{variable}{type_name}{byte_length}{modifier or ''}}}",
        variable_name=variable,
        type_name=type_name,
        byte_length=byte_length,
        modifier=modifier,
        sentinel_hex=sentinel_hex,
    )


def _catalog(variable: dict) -> dict:
    return {
        "__ygg_variable_catalog__": {
            "schema_version": "yggdrasim.saip-variable-catalog/v1",
            "variables": [variable],
        }
    }


def test_legacy_catalog_schema_remains_readable_during_identifier_migration() -> None:
    document = _catalog(
        {
            "id": "ICCID",
            "classification": "PROFILE_IDENTITY",
            "bindings": [],
        }
    )
    document["__ygg_variable_catalog__"]["schema_version"] = (
        "oneot.saip-variable-catalog/v1"
    )

    assert [item["id"] for item in catalog_variables(document)] == ["ICCID"]


def test_inline_typed_encoders_enforce_exact_slot_widths() -> None:
    iccid_header = _record(0, "ICCID", "ICCID", 10, "AA" * 10)
    iccid_ef = _record(1, "ICCID", "ICCID", 10, "BB" * 10, "NibbleSwap")
    imsi = _record(2, "IMSI", "IMSI", 8, "CC" * 8, "EncodeIMSI")
    pin = _record(3, "PIN1", "TEXT", 4, "DD" * 4, "utf8")

    assert encode_inline_placeholder_value(iccid_header, "8947000000000000001") == bytes.fromhex(
        "8947000000000000001F"
    )
    assert encode_inline_placeholder_value(iccid_ef, "8947000000000000001") == bytes.fromhex(
        "987400000000000000F1"
    )
    assert len(encode_inline_placeholder_value(imsi, "240011234567890")) == 8
    assert encode_inline_placeholder_value(pin, "1234") == b"1234"
    with pytest.raises(SaipVariableMaterializationError, match="exactly 4 bytes"):
        encode_inline_placeholder_value(pin, "12345")


def test_inline_materialization_is_atomic_and_retains_other_records() -> None:
    first = _record(0, "SHARED", "BINARY", 2, "A1A2")
    second = _record(1, "SHARED", "BINARY", 2, "B1B2")
    other = _record(2, "OTHER", "BINARY", 2, "C1C2")
    document = {
        "sections": {
            "one": b"\x00\xa1\xa2\x01",
            "two": ("choice", {"payload": b"\xb1\xb2\xc1\xc2"}),
        }
    }

    materialized, remaining, result = materialize_inline_variable(
        document,
        [first, second, other],
        "shared",
        "DEAD",
    )

    assert document["sections"]["one"] == b"\x00\xa1\xa2\x01"
    assert materialized["sections"]["one"] == b"\x00\xde\xad\x01"
    assert materialized["sections"]["two"][1]["payload"] == b"\xde\xad\xc1\xc2"
    assert remaining == [other]
    assert result.binding_count == 2
    assert result.source == "inline_varder"


def test_inline_materialization_rejects_non_unique_sentinel() -> None:
    record = _record(0, "DUP", "BINARY", 2, "A1A2")
    document = {"sections": {"one": b"\xa1\xa2", "two": b"\xa1\xa2"}}
    with pytest.raises(SaipVariableMaterializationError, match="2 byte regions"):
        materialize_inline_variable(document, [record], "DUP", "BEEF")
    assert document["sections"]["one"] == b"\xa1\xa2"


def test_catalog_materializes_header_iccid_by_alias() -> None:
    header = SimpleNamespace(type="header", decoded={"iccid": bytearray(10)})
    sequence = SimpleNamespace(pe_list=[header])
    document = _catalog(
        {
            "id": "ICCID",
            "aliases": ["PROFILE_ID"],
            "classification": "PROFILE_IDENTITY",
            "bindings": [
                {
                    "encoder": "ICCID_HEADER_BCD_V1",
                    "output_length_bytes": 10,
                    "locator": {
                        "pe_type": "header",
                        "context": "PROFILE",
                        "field": "iccid",
                    },
                }
            ],
        }
    )

    result = materialize_catalog_variable(
        sequence,
        document,
        "profile_id",
        "8947000000000000001",
    )

    assert bytes(header.decoded["iccid"]) == bytes.fromhex("8947000000000000001F")
    assert result.variable_name == "ICCID"
    assert result.binding_count == 1


def test_catalog_token_definition_exact_digits_is_enforced_before_encoding() -> None:
    header = SimpleNamespace(type="header", decoded={"iccid": bytearray(10)})
    sequence = SimpleNamespace(pe_list=[header])
    document = _catalog(
        {
            "id": "ICCID",
            "classification": "PROFILE_IDENTITY",
            "input": {
                "kind": "DECIMAL_DIGITS",
                "format": "ICCID",
                "constraints": {"exact_digits": 19},
            },
            "bindings": [
                {
                    "encoder": "ICCID_HEADER_BCD_V1",
                    "output_length_bytes": 10,
                    "locator": {
                        "pe_type": "header",
                        "context": "PROFILE",
                        "field": "iccid",
                    },
                }
            ],
        }
    )

    with pytest.raises(SaipVariableMaterializationError, match="exactly 19 digits, got 20"):
        materialize_catalog_variable(
            sequence,
            document,
            "ICCID",
            "89470000000000000012",
        )
    assert bytes(header.decoded["iccid"]) == bytes(10)

    materialize_catalog_variable(
        sequence,
        document,
        "ICCID",
        "8947000000000000001",
    )
    assert bytes(header.decoded["iccid"]) == bytes.fromhex("8947000000000000001F")


def test_catalog_accepts_and_resolves_source_notation_aliases() -> None:
    document = _catalog(
        {
            "id": "FILESYSTEM_CONTENT_1",
            "aliases": ["FILESYSTEM_MARKER::<raw-name>"],
            "bindings": [],
        }
    )

    assert catalog_variables(document)[0]["id"] == "FILESYSTEM_CONTENT_1"
    assert (
        find_catalog_variable(document, "filesystem_marker::<RAW-NAME>")["id"]
        == "FILESYSTEM_CONTENT_1"
    )


def test_catalog_materializes_one_record_without_discarding_neighbors() -> None:
    entries = [
        (
            "fileDescriptor",
            {
                "fileID": bytes.fromhex("6FC5"),
                "efFileSize": bytes.fromhex("10"),
                "fileDescriptor": bytes.fromhex("42210008"),
            },
        ),
        ("fillFileContent", b"\x01" * 16),
    ]
    pe = SimpleNamespace(type="usim", decoded={"ef-pnn": entries})
    sequence = SimpleNamespace(pe_list=[pe])
    document = _catalog(
        {
            "id": "PNN_2",
            "classification": "FILESYSTEM_CONTENT",
            "bindings": [
                {
                    "encoder": "RAW_HEX_V1",
                    "output_length_bytes": 8,
                    "locator": {
                        "pe_type": "usim",
                        "context": "USIM",
                        "field": "fillFileContent",
                        "match": {
                            "pe_name": "ef-pnn",
                            "byte_offset": 8,
                            "byte_length": 8,
                            "record_start": 2,
                            "record_end": 2,
                        },
                    },
                }
            ],
        }
    )

    materialize_catalog_variable(sequence, document, "PNN_2", "AA" * 8)

    assert entries[1][1] == b"\x01" * 8 + b"\xff" * 8
    assert entries[-2:] == [("fillFileOffset", 8), ("fillFileContent", b"\xaa" * 8)]


@pytest.mark.parametrize(
    ("number", "expected_prefix", "expected_number"),
    [
        ("46701234567890", bytes.fromhex("0891"), bytes.fromhex("64072143658709FF")),
        ("467012345678901", bytes.fromhex("0991"), bytes.fromhex("64072143658709F1")),
        ("4670123456789012", bytes.fromhex("0991"), bytes.fromhex("6407214365870921")),
    ],
)
def test_catalog_msisdn_materialization_updates_adn_length_and_ton_npi(
    number: str,
    expected_prefix: bytes,
    expected_number: bytes,
) -> None:
    entries = [
        (
            "fileDescriptor",
            {
                "fileID": bytes.fromhex("6F40"),
                "efFileSize": bytes.fromhex("44"),
                "fileDescriptor": bytes.fromhex("42210022"),
            },
        ),
        ("fillFileContent", b"\xff" * 68),
    ]
    pe = SimpleNamespace(type="opt-usim", decoded={"ef-msisdn": entries})
    sequence = SimpleNamespace(pe_list=[pe])
    document = _catalog(
        {
            "id": "MSISDN",
            "classification": "SUBSCRIBER_IDENTITY",
            "input": {
                "kind": "PHONE_NUMBER",
                "format": "E164",
                "constraints": {"exact_digits": len(number)},
            },
            "bindings": [
                {
                    "encoder": "EF_MSISDN_RECORD_V1",
                    "output_length_bytes": 8,
                    "locator": {
                        "pe_type": "opt-usim",
                        "context": "USIM",
                        "field": "record.number",
                        "match": {
                            "pe_name": "ef-msisdn",
                            "fid_path": "3F00/7FFF/6F40",
                            "byte_offset": 22,
                            "byte_length": 8,
                        },
                    },
                }
            ],
        }
    )

    materialize_catalog_variable(sequence, document, "MSISDN", number)

    assert entries[-4:] == [
        ("fillFileOffset", 20),
        ("fillFileContent", expected_prefix),
        ("fillFileOffset", 22),
        ("fillFileContent", expected_number),
    ]


def test_secret_classification_and_names_are_redacted_candidates() -> None:
    assert variable_is_secret("KI", "AUTHENTICATION_SECRET")
    assert variable_is_secret("SCP80_KIC")
    assert variable_is_secret("PIN2")
    assert not variable_is_secret("ICCID", "PROFILE_IDENTITY")
