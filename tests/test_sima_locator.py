# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""PEStatus offset locator: outline a SAIP package, name the elements at an offset."""

from __future__ import annotations

import pytest

from SCP11.shared.sima_locator import (
    MAX_OUTLINE_DEPTH,
    describe_pe_status_location,
    outline_profile_package,
)
from tests.sima_locator_support import (
    CREATE_DF_GSM,
    CREATE_EF_LP,
    FDN_LINK,
    GFM,
    HEADER,
    PACKAGE,
    SELECT_MF,
    SERVICES,
    SMS_LINK,
    TEMPLATE_MF,
    pe_header,
    span_in,
    tlv,
)


@pytest.fixture(scope="module")
def schema():
    return pytest.importorskip("pySim.esim.saip").asn1


@pytest.fixture(scope="module")
def outlines(schema):
    return outline_profile_package(PACKAGE, schema)


def test_outline_names_each_pe_with_its_identification(outlines) -> None:
    assert [item.pe_type for item in outlines] == ["header", "genericFileManagement", "end"]
    assert [item.identification for item in outlines] == [None, 11, 12]
    assert [item.package_start for item in outlines] == [0, len(HEADER), len(HEADER) + len(GFM)]


def test_offset_between_two_fcps_names_both(outlines) -> None:
    fdn_start, fdn_end = span_in(GFM, FDN_LINK)
    sms_start, sms_end = span_in(GFM, SMS_LINK)
    assert sms_start == fdn_end
    link_start = fdn_end - len(tlv("C7", bytes.fromhex("7FFF6F3B")))

    lines = describe_pe_status_location(outlines, 11, fdn_end)

    assert lines[0] == (
        "simaResponseLocation=PE identification 11 = TLV[2] genericFileManagement "
        f"plaintext[{len(HEADER)}:{len(HEADER) + len(GFM)}]"
    )
    assert (
        "  endsAt=fileManagementCMD[0][2].createFCP.linkPath "
        f"(fileID 6F3B, linkPath 7FFF/6F3B, in 7F10) bytes[{link_start}:{fdn_end}]"
    ) in lines
    assert (
        "  startsAt=fileManagementCMD[0][3].createFCP "
        f"(fileID 6F3C, linkPath 7FFF/6F3C, in 7F10) bytes[{sms_start}:{sms_end}]"
    ) in lines
    assert fdn_start < link_start


def test_header_offset_after_the_services_list(outlines) -> None:
    _start, services_end = span_in(HEADER, SERVICES)

    lines = describe_pe_status_location(outlines, None, services_end)

    assert lines[0] == f"simaResponseLocation=the Profile header = TLV[1] header plaintext[0:{len(HEADER)}]"
    assert f"  endsAt=eUICC-Mandatory-services.dfLink bytes[{services_end - 2}:{services_end}]" in lines
    assert any(line.startswith("  startsAt=eUICC-Mandatory-GFSTEList bytes[") for line in lines)


def test_object_identifiers_read_in_dotted_notation(outlines) -> None:
    start, end = span_in(HEADER, TEMPLATE_MF)

    lines = describe_pe_status_location(outlines, None, start)

    assert f"  startsAt=eUICC-Mandatory-GFSTEList[0] (2.23.143.1.2.1) bytes[{start}:{end}]" in lines


def test_offset_inside_a_value_takes_the_fcp_note(outlines) -> None:
    start, end = span_in(GFM, tlv("83", bytes.fromhex("6F3C")))

    lines = describe_pe_status_location(outlines, 11, start + 3)

    assert (
        "  inside=fileManagementCMD[0][3].createFCP.fileID "
        f"(fileID 6F3C, linkPath 7FFF/6F3C, in 7F10) bytes[{start}:{end}]"
    ) in lines


def test_file_path_and_a_created_df_move_the_current_df(outlines) -> None:
    df_start, df_end = span_in(GFM, CREATE_DF_GSM)
    lp_start, lp_end = span_in(GFM, CREATE_EF_LP)
    select_start = df_start - len(SELECT_MF)

    select_lines = describe_pe_status_location(outlines, 11, select_start)
    df_lines = describe_pe_status_location(outlines, 11, df_start)
    lp_lines = describe_pe_status_location(outlines, 11, lp_start)

    assert f"  startsAt=fileManagementCMD[1][0].filePath (select MF) bytes[{select_start}:{df_start}]" in select_lines
    assert f"  startsAt=fileManagementCMD[1][1].createFCP (fileID 7F20, in MF) bytes[{df_start}:{df_end}]" in df_lines
    assert f"  startsAt=fileManagementCMD[1][2].createFCP (fileID 6F05, in 7F20) bytes[{lp_start}:{lp_end}]" in lp_lines


def test_offset_equal_to_the_pe_length_names_its_last_element(outlines) -> None:
    lines = describe_pe_status_location(outlines, 11, len(GFM))

    assert any(line.startswith("  endsAt=fileManagementCMD[1][3].fillFileContent bytes[") for line in lines)
    assert not any(line.startswith(("  startsAt=", "  inside=")) for line in lines)


def test_offset_past_the_pe_is_reported(outlines) -> None:
    lines = describe_pe_status_location(outlines, 11, len(GFM) + 1)

    assert lines[-1] == "  pastEnd=the offset lies beyond the PE"


def test_offset_inside_the_pe_tag_and_length(outlines) -> None:
    lines = describe_pe_status_location(outlines, 11, 1)

    assert lines[-1] == "  inside=the tag and length of genericFileManagement"


def test_unknown_identification_is_reported(outlines) -> None:
    assert describe_pe_status_location(outlines, 99, 4) == [
        "simaResponseLocation=no PE in the loaded package matches PE identification 99"
    ]


@pytest.mark.parametrize("offset", [-1, True, "4", None])
def test_offset_that_is_not_a_count_gives_no_lines(outlines, offset) -> None:
    assert describe_pe_status_location(outlines, 11, offset) == []


def test_without_a_schema_spans_carry_tag_paths() -> None:
    plain = outline_profile_package(PACKAGE)
    _start, fdn_end = span_in(GFM, FDN_LINK)

    lines = describe_pe_status_location(plain, 11, fdn_end)

    assert [item.pe_type for item in plain] == ["tag A0", "tag A1", "tag AA"]
    assert [item.identification for item in plain] == [None, 11, 12]
    assert any(line.startswith("  startsAt=A1[1].30[0].62[3] bytes[") for line in lines)


@pytest.mark.parametrize(
    "data",
    [b"", b"\x01", b"\xA0", b"\xA0\x05\x80", b"\xA0\x82\x01", HEADER[:-1]],
    ids=["empty", "one-byte", "tag-only", "over-claiming", "truncated-length", "short-header"],
)
def test_decode_boundaries_give_no_outline(data) -> None:
    assert outline_profile_package(data) == []


def test_a_bound_profile_package_is_not_outlined() -> None:
    assert outline_profile_package(tlv("BF36", tlv("BF23", tlv("80", b"\x01")))) == []


def test_an_over_claiming_child_stops_its_walk(schema) -> None:
    broken = tlv("A1", pe_header(11) + bytes.fromhex("A103300980"))

    outlines = outline_profile_package(HEADER + broken, schema)

    assert outlines[1].identification == 11
    assert [span.path for span in outlines[1].spans if span.depth == 1] == ["gfm-header", "fileManagementCMD"]
    assert not any(span.depth > 2 and span.path.startswith("fileManagementCMD") for span in outlines[1].spans)


def test_nesting_beyond_the_depth_cap_is_not_walked() -> None:
    nested = b""
    for _ in range(MAX_OUTLINE_DEPTH + 8):
        nested = tlv("A0", nested)

    outlines = outline_profile_package(HEADER + tlv("A1", nested))

    assert max(span.depth for span in outlines[1].spans) == MAX_OUTLINE_DEPTH
