# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
from __future__ import annotations

from SCP11.shared.sima_response import decode_sima_response, format_sima_response


def test_decode_sima_success_response_with_nested_result_data() -> None:
    decoded = decode_sima_response(bytes.fromhex("3007A0053003800100"))

    assert decoded["complete"] is True
    assert decoded["summary"] == "successResult.resultCode=0"
    assert decoded["semantic"]["choice"] == "successResult"
    assert decoded["semantic"]["result_code"] == 0
    assert decoded["nodes"][0]["children"][0]["children"][0]["label"] == "resultData"
    assert "80(len=1, resultCode)=00" in decoded["translation"]


def test_decode_sima_failure_response_without_nested_sequence() -> None:
    decoded = decode_sima_response(bytes.fromhex("3008A106800105810108"))

    assert decoded["complete"] is True
    assert decoded["summary"] == "failureResult.resultCode=5, failureResult.resultDetail=8"
    assert decoded["semantic"]["choice"] == "failureResult"
    assert decoded["semantic"]["result_code"] == 5
    assert decoded["semantic"]["result_detail"] == 8
    assert decoded["nodes"][0]["children"][0]["children"][1]["label"] == "resultDetail"


def test_format_sima_response_keeps_legacy_one_line_shape() -> None:
    formatted = format_sima_response(bytes.fromhex("3007A0053003800100"))

    assert formatted.startswith("3007A0053003800100 [")
    assert "30(len=7, simaResponse)" in formatted
    assert "A0(len=5, finalResult.successResult)" in formatted
    assert "successResult.resultCode=0" in formatted
