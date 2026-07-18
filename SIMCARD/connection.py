# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Simulated card connection facade: routes ISO 7816 C-APDUs to the shared SimulatedSimCardEngine and emits R-APDUs."""
from __future__ import annotations

import threading
import weakref
from typing import Any

from SIMCARD.engine import SimulatedSimCardEngine
from yggdrasim_common.card_backend import (
    get_sim_eim_identity_path,
    get_sim_euicc_store_root,
    get_sim_isdr_config_path,
    get_sim_profile_store_path,
    get_sim_quirks_path,
)


_SHARED_ENGINE: SimulatedSimCardEngine | None = None
_SHARED_ENGINE_QUIRKS_PATH = ""
_SHARED_ENGINE_ISDR_CONFIG_PATH = ""
_SHARED_ENGINE_EIM_IDENTITY_PATH = ""
_SHARED_ENGINE_EUICC_STORE_ROOT = ""
_SHARED_ENGINE_PROFILE_STORE_PATH = ""
# Guards the whole ``_SHARED_ENGINE`` / path-key tuple, every engine APDU, and
# the validation owner below. The simulator models one physical card, so two
# connection facades must never mutate its selected-file state concurrently.
# RLock lets ``transmit`` perform its implicit ``connect`` without dropping the
# serialization boundary.
_SHARED_ENGINE_LOCK = threading.RLock()
_VALIDATION_LEASE_OWNER: weakref.ReferenceType[Any] | None = None


def _validation_lease_owner_locked() -> Any | None:
    """Return the live validation owner while ``_SHARED_ENGINE_LOCK`` is held."""
    global _VALIDATION_LEASE_OWNER
    reference = _VALIDATION_LEASE_OWNER
    if reference is None:
        return None
    owner = reference()
    if owner is None:
        _VALIDATION_LEASE_OWNER = None
    return owner


def _assert_validation_access_locked(connection: Any) -> None:
    owner = _validation_lease_owner_locked()
    if owner is not None and owner is not connection:
        raise RuntimeError(
            "Simulated card is reserved by a read-only validation session."
        )


def get_shared_engine() -> SimulatedSimCardEngine:
    """Return the process-wide singleton ``SimEngine`` instance, constructing it on first call."""
    global _SHARED_ENGINE, _SHARED_ENGINE_QUIRKS_PATH, _SHARED_ENGINE_ISDR_CONFIG_PATH, _SHARED_ENGINE_EIM_IDENTITY_PATH, _SHARED_ENGINE_EUICC_STORE_ROOT, _SHARED_ENGINE_PROFILE_STORE_PATH
    quirks_path = get_sim_quirks_path()
    isdr_config_path = get_sim_isdr_config_path()
    eim_identity_path = get_sim_eim_identity_path()
    euicc_store_root = get_sim_euicc_store_root()
    profile_store_path = get_sim_profile_store_path()
    with _SHARED_ENGINE_LOCK:
        needs_rebuild = (
            _SHARED_ENGINE is None
            or quirks_path != _SHARED_ENGINE_QUIRKS_PATH
            or isdr_config_path != _SHARED_ENGINE_ISDR_CONFIG_PATH
            or eim_identity_path != _SHARED_ENGINE_EIM_IDENTITY_PATH
            or euicc_store_root != _SHARED_ENGINE_EUICC_STORE_ROOT
            or profile_store_path != _SHARED_ENGINE_PROFILE_STORE_PATH
        )
        if needs_rebuild:
            if _validation_lease_owner_locked() is not None:
                raise RuntimeError(
                    "Simulated card configuration cannot change during validation."
                )
            _SHARED_ENGINE = SimulatedSimCardEngine(
                quirks_path=quirks_path,
                isdr_config_path=isdr_config_path,
                sim_eim_identity_path=eim_identity_path,
                euicc_store_root=euicc_store_root,
                profile_store_path=profile_store_path,
            )
            _SHARED_ENGINE_QUIRKS_PATH = quirks_path
            _SHARED_ENGINE_ISDR_CONFIG_PATH = isdr_config_path
            _SHARED_ENGINE_EIM_IDENTITY_PATH = eim_identity_path
            _SHARED_ENGINE_EUICC_STORE_ROOT = euicc_store_root
            _SHARED_ENGINE_PROFILE_STORE_PATH = profile_store_path
        engine = _SHARED_ENGINE
    return engine


class SimulatedCardConnection:
    def __init__(self) -> None:
        self._engine = get_shared_engine()
        self._connected = False
        self._protocol = None
        self._owns_validation_lease = False

    def connect(self, protocol=None) -> None:
        with _SHARED_ENGINE_LOCK:
            _assert_validation_access_locked(self)
            self._connect_locked(protocol)

    def _connect_locked(self, protocol=None) -> None:
        self._protocol = protocol
        self._connected = True
        self._engine.state.current_protocol = protocol
        self._engine.reset()

    def disconnect(self) -> None:
        with _SHARED_ENGINE_LOCK:
            self._connected = False
            self._release_validation_lease_locked()

    def transmit(self, apdu):
        payload = bytes(int(part) & 0xFF for part in apdu)
        with _SHARED_ENGINE_LOCK:
            _assert_validation_access_locked(self)
            if self._connected is False:
                self._connect_locked(self._protocol)
            data, sw1, sw2 = self._engine.transmit(payload)
        return list(data), sw1, sw2

    def getATR(self):
        with _SHARED_ENGINE_LOCK:
            return list(self._engine.get_atr())

    def getProtocol(self):
        return self._protocol

    def getValidationCardIdentity(self) -> str:
        """Return the stable simulator identity for validation continuity checks."""
        with _SHARED_ENGINE_LOCK:
            return str(
                self._engine.state.eid or self._engine.state.iccid or ""
            ).strip()

    def getResetCounter(self) -> int:
        """Return the monotonic simulator reset generation."""
        with _SHARED_ENGINE_LOCK:
            return int(self._engine.state.reset_counter)

    def acquireValidationLease(self) -> None:
        """Reserve the shared simulator engine for this connection.

        The lease is process-wide because every ``SimulatedCardConnection``
        facade points at the same stateful engine. It is deliberately
        non-blocking: validation preview creation must fail closed instead of
        waiting behind an unrelated run.
        """
        global _VALIDATION_LEASE_OWNER
        with _SHARED_ENGINE_LOCK:
            owner = _validation_lease_owner_locked()
            if owner is self:
                self._owns_validation_lease = True
                return
            if owner is not None:
                raise RuntimeError(
                    "Simulated card is already reserved for validation."
                )
            _VALIDATION_LEASE_OWNER = weakref.ref(self)
            self._owns_validation_lease = True

    def releaseValidationLease(self) -> None:
        """Release this connection's validation reservation, if held."""
        with _SHARED_ENGINE_LOCK:
            self._release_validation_lease_locked()

    def _release_validation_lease_locked(self) -> None:
        global _VALIDATION_LEASE_OWNER
        owner = _validation_lease_owner_locked()
        if owner is self:
            _VALIDATION_LEASE_OWNER = None
        self._owns_validation_lease = False
