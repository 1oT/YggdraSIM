# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""EimLocalSession transport envelope and explicit euiccMemoryReset options.

These cover the two core hooks the standalone eUICC-config plugin binds to:
``exchange_isdr_command`` (generic ISD-R transport) and the ``options`` path on
``euicc_memory_reset`` that lets a caller state the 7 reset flags explicitly
instead of resolving them from a package document.
"""
from __future__ import annotations

from SCP11.eim_local.session import EimLocalSession


def _blank_session() -> EimLocalSession:
    # Bypass __init__: the transport envelope and option encoders are pure over
    # the class attributes and helper methods, so no card or file state is needed.
    return object.__new__(EimLocalSession)


def test_memory_reset_options_all_true_matches_es10c_alltrue() -> None:
    session = _blank_session()
    normalized = session._normalize_memory_reset_option_source(
        {name: True for name, _camel in EimLocalSession.EUICC_MEMORY_RESET_OPTION_FIELDS}
    )
    payload = session._wrap_tlv(
        bytes.fromhex("BF64"),
        session._wrap_tlv(b"\x82", session._encode_euicc_memory_reset_options(normalized)),
    )
    # es10c EuiccMemoryResetOptions.allTrue(): 7 bits set, 1 unused bit -> 01 FE.
    assert payload.hex().upper() == "BF6404820201FE"


def test_memory_reset_options_accepts_camelcase_single_flag() -> None:
    session = _blank_session()
    normalized = session._normalize_memory_reset_option_source({"resetEimConfigData": True})
    assert normalized["reset_eim_config_data"] is True
    # resetEimConfigData is bit 5; six bits wide, two unused -> 02 04.
    assert session._encode_euicc_memory_reset_options(normalized).hex().upper() == "0204"


def test_memory_reset_options_empty_is_single_zero_byte() -> None:
    session = _blank_session()
    normalized = session._normalize_memory_reset_option_source({})
    assert session._encode_euicc_memory_reset_options(normalized).hex().upper() == "00"


def test_exchange_isdr_command_runs_reset_select_send_sync_in_order() -> None:
    session = _blank_session()
    calls: list[str] = []
    session.reset_state = lambda: calls.append("reset")  # type: ignore[method-assign]
    session.select_isdr = lambda: calls.append("select")  # type: ignore[method-assign]

    def _send(payload: bytes, label: str) -> bytes:
        calls.append(f"send:{payload.hex().upper()}:{label}")
        return bytes.fromhex("BF5502A000")

    session._send_retrieve_store_data = _send  # type: ignore[method-assign]
    session._sync_pending_notifications = lambda response: calls.append("sync")  # type: ignore[method-assign]

    result = session.exchange_isdr_command(bytes.fromhex("BF5500"), "TEST: probe")
    assert result.hex().upper() == "BF5502A000"
    assert calls == ["reset", "select", "send:BF5500:TEST: probe", "sync"]


def test_exchange_isdr_command_can_skip_notification_sync() -> None:
    session = _blank_session()
    calls: list[str] = []
    session.reset_state = lambda: calls.append("reset")  # type: ignore[method-assign]
    session.select_isdr = lambda: calls.append("select")  # type: ignore[method-assign]
    session._send_retrieve_store_data = lambda payload, label: (calls.append("send") or b"")  # type: ignore[method-assign]
    session._sync_pending_notifications = lambda response: calls.append("sync")  # type: ignore[method-assign]

    session.exchange_isdr_command(b"\xbf\x56\x00", "TEST: getCerts", sync_notifications=False)
    assert "sync" not in calls
    assert calls == ["reset", "select", "send"]
