# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Continuity API coverage used by read-only validation transports."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from SIMCARD.connection import SimulatedCardConnection
from SIMCARD.engine import SimulatedSimCardEngine


class _Resettable:
    def reset(self) -> None:
        return None


def _minimal_engine() -> SimulatedSimCardEngine:
    engine = object.__new__(SimulatedSimCardEngine)
    engine.state = SimpleNamespace(
        eid="89001012012341234012345678901234",
        iccid="8946000000000000001",
        current_protocol=None,
        reset_counter=0,
        pending_fetch_queue=[],
        store_data_buffer=b"",
        store_data_expected_block=0,
    )
    engine.fs = _Resettable()
    engine.naa = _Resettable()
    engine.auth = _Resettable()
    engine.scp03 = _Resettable()
    engine.sgp = _Resettable()
    engine.toolkit = _Resettable()
    engine.quirks = SimpleNamespace(on_reset_hooks=[])
    return engine


def _connection(engine: SimulatedSimCardEngine) -> SimulatedCardConnection:
    connection = object.__new__(SimulatedCardConnection)
    connection._engine = engine
    connection._connected = False
    connection._protocol = None
    connection._owns_validation_lease = False
    return connection


def test_simulator_identity_is_stable_and_reset_generation_is_monotonic() -> None:
    engine = _minimal_engine()
    connection = _connection(engine)

    identity = connection.getValidationCardIdentity()
    assert identity == engine.state.eid
    assert connection.getResetCounter() == 0

    connection.connect(protocol=1)
    assert connection.getValidationCardIdentity() == identity
    assert connection.getResetCounter() == 1

    connection.connect(protocol=1)
    assert connection.getValidationCardIdentity() == identity
    assert connection.getResetCounter() == 2


def test_simulator_identity_falls_back_to_iccid() -> None:
    engine = _minimal_engine()
    engine.state.eid = ""
    connection = _connection(engine)

    assert connection.getValidationCardIdentity() == engine.state.iccid


def test_validation_lease_blocks_other_connections_until_owner_disconnects() -> None:
    engine = _minimal_engine()
    engine.transmit = lambda payload: (payload, 0x90, 0x00)  # type: ignore[method-assign]
    owner = _connection(engine)
    other = _connection(engine)

    owner.acquireValidationLease()
    try:
        owner.connect()
        assert owner.transmit([0x00, 0xA4, 0x00, 0x00]) == (
            [0x00, 0xA4, 0x00, 0x00],
            0x90,
            0x00,
        )
        with pytest.raises(RuntimeError, match="reserved"):
            other.connect()
        with pytest.raises(RuntimeError, match="reserved"):
            other.transmit([0x00, 0xA4, 0x00, 0x00])
    finally:
        owner.disconnect()

    other.connect()
    assert other.getResetCounter() == 2


def test_shared_engine_apdus_are_serialized_across_connections() -> None:
    engine = _minimal_engine()
    first = _connection(engine)
    second = _connection(engine)
    first._connected = True
    second._connected = True
    first_entered = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()
    state_guard = threading.Lock()
    active = 0
    maximum_active = 0
    call_count = 0

    def _transmit(payload: bytes) -> tuple[bytes, int, int]:
        nonlocal active, maximum_active, call_count
        with state_guard:
            active += 1
            call_count += 1
            maximum_active = max(maximum_active, active)
            ordinal = call_count
        if ordinal == 1:
            first_entered.set()
            assert release_first.wait(timeout=2)
        else:
            second_entered.set()
        with state_guard:
            active -= 1
        return payload, 0x90, 0x00

    engine.transmit = _transmit  # type: ignore[method-assign]
    results: list[tuple[list[int], int, int]] = []

    def _send(connection: SimulatedCardConnection, command: int) -> None:
        results.append(connection.transmit([0x00, command, 0x00, 0x00]))

    first_thread = threading.Thread(target=_send, args=(first, 0xA4))
    second_thread = threading.Thread(target=_send, args=(second, 0xB0))
    first_thread.start()
    assert first_entered.wait(timeout=2)
    second_thread.start()
    assert second_entered.wait(timeout=0.1) is False
    release_first.set()
    first_thread.join(timeout=2)
    second_thread.join(timeout=2)

    assert first_thread.is_alive() is False
    assert second_thread.is_alive() is False
    assert second_entered.is_set()
    assert maximum_active == 1
    assert len(results) == 2
