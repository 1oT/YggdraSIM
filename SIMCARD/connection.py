from __future__ import annotations

import threading

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
# Guards the whole ``_SHARED_ENGINE`` / path-key tuple. Two dispatchers
# instantiating ``SimulatedCardConnection`` from different threads must not
# race through the path-change check and each construct their own engine;
# that would deliver duplicate EF reads back to two shells sharing the same
# on-disk store.
_SHARED_ENGINE_LOCK = threading.Lock()


def get_shared_engine() -> SimulatedSimCardEngine:
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

    def connect(self, protocol=None) -> None:
        self._protocol = protocol
        self._connected = True
        self._engine.state.current_protocol = protocol
        self._engine.reset()

    def disconnect(self) -> None:
        self._connected = False

    def transmit(self, apdu):
        if self._connected is False:
            self.connect(self._protocol)
        payload = bytes(int(part) & 0xFF for part in apdu)
        data, sw1, sw2 = self._engine.transmit(payload)
        return list(data), sw1, sw2

    def getATR(self):
        return list(self._engine.get_atr())

    def getProtocol(self):
        return self._protocol
