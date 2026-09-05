# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Contracts for the session APDU-trace diff."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from yggdrasim_common.session_diff import (
    KIND_ONLY_LEFT,
    KIND_ONLY_RIGHT,
    KIND_RESPONSE,
    KIND_STATUS,
    SessionDiffError,
    diff_recordings,
    format_diff,
    load_recording,
    run_cli,
)


def _entry(apdu: str, data: str = "", status: str = "9000") -> dict:
    return {
        "apdu_hex": apdu,
        "response_data_hex": data,
        "status_hex": status,
        "sw1": int(status[:2], 16),
        "sw2": int(status[2:], 16),
        "response_len": len(data) // 2,
        "ok": status in ("9000", "9100"),
    }


def _recording(tmp_path: Path, name: str, entries: list[dict]) -> Path:
    payload = {
        "schema": "yggdrasim_session_recording/v1",
        "session_id": name,
        "shell": "scp03",
        "apdu_trace": [dict(item, index=index) for index, item in enumerate(entries)],
    }
    path = tmp_path / f"{name}.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


_BASELINE = [
    _entry("00A40004023F00", "621A8202"),
    _entry("00B0000010", "98620000000000000001"),
    _entry("00A4000402FFFF", "", "6A82"),
]


def test_identical_sessions_report_no_differences(tmp_path: Path) -> None:
    left = _recording(tmp_path, "left", _BASELINE)
    right = _recording(tmp_path, "right", _BASELINE)
    result = diff_recordings(left, right)
    assert result.identical is True
    assert result.entries == []
    assert "identical" in format_diff(result)


def test_a_flipped_status_word_is_located_precisely(tmp_path: Path) -> None:
    changed = list(_BASELINE)
    changed[1] = _entry("00B0000010", "98620000000000000001", "6982")
    result = diff_recordings(
        _recording(tmp_path, "left", _BASELINE),
        _recording(tmp_path, "right", changed),
    )
    assert len(result.entries) == 1
    only = result.entries[0]
    assert only.kind == KIND_STATUS
    assert only.left_index == 1 and only.right_index == 1
    assert only.left_value == "9000" and only.right_value == "6982"


def test_a_changed_response_body_is_reported_separately(tmp_path: Path) -> None:
    changed = list(_BASELINE)
    changed[1] = _entry("00B0000010", "98620000000000000099")
    result = diff_recordings(
        _recording(tmp_path, "left", _BASELINE),
        _recording(tmp_path, "right", changed),
    )
    assert [entry.kind for entry in result.entries] == [KIND_RESPONSE]


def test_an_inserted_exchange_does_not_cascade(tmp_path: Path) -> None:
    """The reason alignment is not positional.

    One extra exchange on the right must show up as a single insertion, not
    as every following exchange looking different.
    """
    with_retry = [_BASELINE[0], _entry("00C0000010", "AABB"), _BASELINE[1], _BASELINE[2]]
    result = diff_recordings(
        _recording(tmp_path, "left", _BASELINE),
        _recording(tmp_path, "right", with_retry),
    )
    assert len(result.entries) == 1
    assert result.entries[0].kind == KIND_ONLY_RIGHT
    assert result.entries[0].apdu_hex == "00C0000010"


def test_a_truncated_session_reports_the_missing_tail(tmp_path: Path) -> None:
    result = diff_recordings(
        _recording(tmp_path, "left", _BASELINE),
        _recording(tmp_path, "right", _BASELINE[:1]),
    )
    assert [entry.kind for entry in result.entries] == [KIND_ONLY_LEFT, KIND_ONLY_LEFT]
    assert result.left_count == 3 and result.right_count == 1


def test_an_empty_trace_is_not_a_crash(tmp_path: Path) -> None:
    result = diff_recordings(
        _recording(tmp_path, "left", []),
        _recording(tmp_path, "right", []),
    )
    assert result.identical is True


def test_status_is_derived_when_only_sw_bytes_are_present(tmp_path: Path) -> None:
    payload = {
        "schema": "yggdrasim_session_recording/v1",
        "apdu_trace": [{"apdu_hex": "00A40004023F00", "sw1": 0x69, "sw2": 0x82}],
    }
    path = tmp_path / "sw-only.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    assert load_recording(path)[0].status_hex == "6982"


def test_json_recordings_load_too(tmp_path: Path) -> None:
    payload = {
        "schema": "yggdrasim_session_recording/v1",
        "apdu_trace": [dict(_entry("00A40004023F00"), index=0)],
    }
    path = tmp_path / "session.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert len(load_recording(path)) == 1


@pytest.mark.parametrize(
    "payload, fragment",
    [
        ({"schema": "something/else", "apdu_trace": []}, "not a session recording"),
        ({"schema": "yggdrasim_session_recording/v1"}, "no apdu_trace"),
        ([], "not a session recording mapping"),
    ],
)
def test_non_recordings_are_refused_with_a_reason(tmp_path, payload, fragment) -> None:
    path = tmp_path / "bogus.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(SessionDiffError) as raised:
        load_recording(path)
    assert fragment in str(raised.value)


def test_a_missing_recording_names_the_path(tmp_path: Path) -> None:
    with pytest.raises(SessionDiffError) as raised:
        load_recording(tmp_path / "absent.yaml")
    assert "absent.yaml" in str(raised.value)


def test_text_output_truncates_payloads_by_default(tmp_path: Path, capsys) -> None:
    """Response payloads can carry PINs, so the default output clips them."""

    secret = "AA" * 64
    changed = [_entry("00B0000010", secret)]
    baseline = [_entry("00B0000010", "BB" * 64)]
    result = diff_recordings(
        _recording(tmp_path, "left", baseline),
        _recording(tmp_path, "right", changed),
    )
    clipped = format_diff(result)
    assert secret not in clipped
    assert "hex chars" in clipped
    assert secret in format_diff(result, preview=0)


def test_cli_exit_codes_signal_divergence(tmp_path: Path, capsys) -> None:
    left = _recording(tmp_path, "left", _BASELINE)
    same = _recording(tmp_path, "same", _BASELINE)
    changed = _recording(tmp_path, "changed", _BASELINE[:1])

    assert run_cli([str(left), str(same)]) == 0
    assert run_cli([str(left), str(changed)]) == 1
    assert run_cli([str(left), str(tmp_path / "absent.yaml")]) == 2
    assert "session-diff:" in capsys.readouterr().out


def test_cli_json_output_is_machine_readable(tmp_path: Path, capsys) -> None:
    left = _recording(tmp_path, "left", _BASELINE)
    changed = _recording(tmp_path, "changed", _BASELINE[:2])
    assert run_cli([str(left), str(changed), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["identical"] is False
    assert payload["counts"][KIND_ONLY_LEFT] == 1
    assert payload["left"]["exchanges"] == 3
