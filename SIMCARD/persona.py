# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Persona card: a private simulated eUICC built from one directory and reset to a baked copy.

A persona directory holds ``isdr_config.json`` (identity and EUICCInfo fields, in the iSD-R
configuration format), ``eim_identity.json`` and ``euicc_store/`` (the eUICC store root,
profiles included); each may be absent. Baking builds the card once and writes back what the
first build completes, such as the minted EUM and eUICC certificates, so every card rebuilt
from the baked copy answers EID, EUICCInfo1, EUICCInfo2, the profile list, the eIM
configuration and the certificates byte for byte the same. A persona engine is private
(``SimulatedSimCardEngine(private=True)``): it is never the process-wide shared engine, takes
none of its six paths from the environment, the persisted settings or the Workspace, and
carries no plugin extension and no process-wide behaviour profile. The SGP.26 signing keys
still load from their fixed Workspace-seeded paths.
"""

from __future__ import annotations

import hashlib
import shutil
import threading
from pathlib import Path
from typing import Any, Callable

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.euicc_store import sync_euicc_store
from SIMCARD.profile_store import sync_profiles_to_store
from SIMCARD.quirks import ApduResult

ISDR_CONFIG_FILENAME = "isdr_config.json"
EIM_IDENTITY_FILENAME = "eim_identity.json"
EUICC_STORE_DIRNAME = "euicc_store"
PRISTINE_DIRNAME = "pristine"
LIVE_DIRNAME = "live"

# Requests whose answers carry no signature, so they repeat exactly on an unchanged card:
# EUICCInfo1, EUICCInfo2, GetProfilesInfo, ListNotification, GetEuiccConfiguredData and
# GetEimConfigurationData.
_FINGERPRINT_REQUESTS = ("BF2000", "BF2200", "BF2D00", "BF2800", "BF3C00", "BF5500")

ApduObserver = Callable[[bytes, ApduResult], None]


class PersonaError(RuntimeError):
    """A persona card could not be built, or a reset did not restore the baked card."""


def build_persona_engine(directory: str | Path) -> SimulatedSimCardEngine:
    """Build a private card whose every configuration path points into *directory*."""
    root = Path(directory).resolve()
    return SimulatedSimCardEngine(
        quirks_path="none",
        isdr_config_path=str(root / ISDR_CONFIG_FILENAME),
        sim_eim_identity_path=str(root / EIM_IDENTITY_FILENAME),
        euicc_store_root=str(root / EUICC_STORE_DIRNAME),
        behaviour_profile_path="none",
        private=True,
    )


def card_fingerprint(engine: SimulatedSimCardEngine) -> str:
    """SHA-256 over what a server can see of the card at rest, read past any extension."""
    sgp = engine.sgp
    parts = [str(engine.state.eid or "").encode("ascii", "ignore")]
    for request in _FINGERPRINT_REQUESTS:
        response, sw1, sw2 = sgp._dispatch_store_data(bytes.fromhex(request))
        parts.append(bytes(response) + bytes([sw1 & 0xFF, sw2 & 0xFF]))
    parts.append(sgp._current_euicc_certificate_der())
    parts.append(sgp._current_eum_certificate_der())
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.hexdigest()


def _replace_directory(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


class PersonaCard:
    """A persona card owned by one caller and rebuilt from its baked copy on every reset.

    ``work_directory`` receives ``pristine/`` (the baked copy) and ``live/`` (the copy the
    current engine writes through to); both are replaced, nothing else there is touched.
    APDU observers and STORE DATA extensions registered here are re-attached to each rebuilt
    engine.
    """

    def __init__(self, source: str | Path, work_directory: str | Path) -> None:
        source_path = Path(source).resolve()
        if source_path.is_dir() is False:
            raise PersonaError(f"Persona directory {source_path} does not exist.")
        work_path = Path(work_directory).resolve()
        if work_path == source_path or source_path in work_path.parents or work_path in source_path.parents:
            raise PersonaError("The work directory and the persona directory must not contain each other.")
        work_path.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.generation = 0
        self._pristine = work_path / PRISTINE_DIRNAME
        self._live = work_path / LIVE_DIRNAME
        self._apdu_observers: list[ApduObserver] = []
        self._store_data_extensions: list[Any] = []
        _replace_directory(source_path, self._pristine)
        baked = build_persona_engine(self._pristine)
        sync_euicc_store(baked.state)
        sync_profiles_to_store(str(baked.state.profile_store_path or ""), baked.state.profiles)
        self.fingerprint = card_fingerprint(baked)
        self.engine = self._build_live()

    def _build_live(self) -> SimulatedSimCardEngine:
        _replace_directory(self._pristine, self._live)
        engine = build_persona_engine(self._live)
        rebuilt = card_fingerprint(engine)
        if rebuilt != self.fingerprint:
            raise PersonaError(
                f"Persona card rebuilt from {self._pristine} differs from the baked card "
                f"(fingerprint {rebuilt[:16]} against {self.fingerprint[:16]})."
            )
        for observer in self._apdu_observers:
            engine.add_apdu_observer(observer)
        for extension in self._store_data_extensions:
            engine.sgp.register_extension(extension)
        return engine

    def reset(self) -> None:
        """Replace the card with a fresh one built from the baked copy; fails closed."""
        with self.lock:
            self.engine = self._build_live()
            self.generation += 1

    def add_apdu_observer(self, observer: ApduObserver) -> None:
        with self.lock:
            if observer not in self._apdu_observers:
                self._apdu_observers.append(observer)
            self.engine.add_apdu_observer(observer)

    def remove_apdu_observer(self, observer: ApduObserver) -> None:
        with self.lock:
            if observer in self._apdu_observers:
                self._apdu_observers.remove(observer)
            self.engine.remove_apdu_observer(observer)

    def register_store_data_extension(self, extension: Any) -> None:
        with self.lock:
            if extension not in self._store_data_extensions:
                self._store_data_extensions.append(extension)
            self.engine.sgp.register_extension(extension)

    def unregister_store_data_extension(self, extension: Any) -> None:
        with self.lock:
            if extension in self._store_data_extensions:
                self._store_data_extensions.remove(extension)
            self.engine.sgp.unregister_extension(extension)

    def connection(self) -> PersonaCardConnection:
        return PersonaCardConnection(self)


class PersonaCardConnection:
    """pyscard-style connection to a persona card, serialised by the card's own lock.

    It shares nothing with the process-wide simulated card connection, so a validation
    reservation of the shared card does not reach it. A persona reset is picked up on the next
    APDU as a fresh connect.
    """

    def __init__(self, card: PersonaCard) -> None:
        self._card = card
        self._protocol: Any = None
        self._generation = -1

    def connect(self, protocol: Any = None, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        with self._card.lock:
            self._protocol = protocol
            self._card.engine.state.current_protocol = protocol
            self._card.engine.reset()
            self._generation = self._card.generation

    def disconnect(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        self._generation = -1

    def transmit(self, apdu: Any) -> tuple[list[int], int, int]:
        payload = bytes(int(part) & 0xFF for part in apdu)
        with self._card.lock:
            if self._generation != self._card.generation:
                self.connect(self._protocol)
            data, sw1, sw2 = self._card.engine.transmit(payload)
        return list(data), sw1, sw2

    def getATR(self) -> list[int]:
        with self._card.lock:
            return list(self._card.engine.get_atr())

    def getProtocol(self) -> Any:
        return self._protocol
