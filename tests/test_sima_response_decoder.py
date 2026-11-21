# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""EUICCResponse decoding per TCA eUICC Profile Package V3.4.1 section 8.11."""

from SCP11.shared.sima_response import decode_sima_response, describe_pe_status, format_sima_response

ALL_OK = "3007A0053003800100"
FAILURE = "3026A016300980010381010583010C30098001068101078201028100820A6261642076616C756573"


def test_decode_all_ok_response() -> None:
    decoded = decode_sima_response(bytes.fromhex(ALL_OK))

    assert decoded["complete"] is True
    assert decoded["summary"] == "peStatus[0].status=ok(0)"
    assert decoded["semantic"]["ok"] is True
    assert decoded["semantic"]["pe_status"] == [
        {"status": 0, "status_name": "ok", "identification": None, "additional_information": None, "offset": None}
    ]
    assert decoded["nodes"][0]["children"][0]["children"][0]["label"] == "PEStatus"
    assert "80(len=1, status)=00" in decoded["translation"]


def test_decode_failure_lists_every_pe_status_and_the_abort_flag() -> None:
    decoded = decode_sima_response(bytes.fromhex(FAILURE))

    assert decoded["complete"] is True
    semantic = decoded["semantic"]
    assert semantic["ok"] is False
    assert semantic["profile_installation_aborted"] is True
    assert semantic["status_message"] == "bad values"
    assert [entry["status_name"] for entry in semantic["pe_status"]] == ["bad-values", "invalid-parameter"]
    assert semantic["pe_status"][0]["identification"] == 5
    assert semantic["pe_status"][0]["offset"] == 12
    assert semantic["pe_status"][1]["additional_information"] == 2
    assert decoded["summary"] == (
        "peStatus[0].status=bad-values(3) identification=5 offset=12, "
        "peStatus[1].status=invalid-parameter(6) identification=7 additional-information=2, "
        "profileInstallationAborted, statusMessage='bad values'"
    )
    labels = [child.get("label") for child in decoded["nodes"][0]["children"]]
    assert labels == ["peStatus", "profileInstallationAborted", "statusMessage"]


def test_format_sima_response_keeps_one_line_shape() -> None:
    formatted = format_sima_response(bytes.fromhex(ALL_OK))

    assert formatted.startswith(ALL_OK + " [")
    assert "30(len=7, EUICCResponse)" in formatted
    assert "A0(len=5, peStatus)" in formatted
    assert "peStatus[0].status=ok(0)" in formatted


def test_status_names_cover_the_iso_and_proprietary_ranges() -> None:
    assert describe_pe_status(31) == "unsupported-profile-version"
    assert describe_pe_status(0x6A88) == "status-word-6A88"
    assert describe_pe_status(0x9000) == "status-word-9000"
    assert describe_pe_status(0xA001) == "proprietary"
    assert describe_pe_status(12) == "unknown"


def test_non_euicc_response_has_no_semantics() -> None:
    decoded = decode_sima_response(bytes.fromhex("3008A106800105810108"))

    assert decoded["semantic"] == {}
    assert decoded["summary"] == ""
