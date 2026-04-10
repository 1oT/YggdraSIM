from __future__ import annotations

import json
import os
from typing import Any, Callable

from .runtime_paths import ensure_seeded_workspace_file, ensure_workspace_dir, workspace_path


CARD_BACKEND_ENV = "YGGDRASIM_CARD_BACKEND"
SIM_QUIRKS_ENV = "YGGDRASIM_SIM_QUIRKS"
SIM_ISDR_CONFIG_ENV = "YGGDRASIM_SIM_ISDR_CONFIG"
SIM_EIM_IDENTITY_ENV = "YGGDRASIM_SIM_EIM_IDENTITY"
SIM_EUICC_STORE_ENV = "YGGDRASIM_SIM_EUICC_STORE"
SIM_PROFILE_STORE_ENV = "YGGDRASIM_SIM_PROFILE_STORE"

CARD_BACKEND_READER = "reader"
CARD_BACKEND_SIM = "sim"
CARD_BACKEND_SETTINGS_FILENAME = "card_backend.json"
_SETTINGS_KEY_CARD_BACKEND = "card_backend"
_SETTINGS_KEY_SIM_QUIRKS_PATH = "sim_quirks_path"
_SETTINGS_KEY_SIM_ISDR_CONFIG_PATH = "sim_isdr_config_path"
_SETTINGS_KEY_SIM_EIM_IDENTITY_PATH = "sim_eim_identity_path"
_SETTINGS_KEY_SIM_EUICC_STORE_ROOT = "sim_euicc_store_root"
_SETTINGS_KEY_SIM_PROFILE_STORE_PATH = "sim_profile_store_path"
SETTING_SOURCE_DEFAULT = "default"
SETTING_SOURCE_WORKSPACE_DEFAULT = "workspace default"
SETTING_SOURCE_DERIVED_DEFAULT = "derived default"
SETTING_SOURCE_SAVED_OVERRIDE = "saved override"
SETTING_SOURCE_SESSION_OVERRIDE = "session override"
SETTING_SOURCE_SAVED_SELECTION = "saved selection"


def normalize_card_backend(value: Any, default: str = CARD_BACKEND_READER) -> str:
    text = str(value or "").strip().lower()
    if len(text) == 0:
        return str(default or CARD_BACKEND_READER).strip().lower() or CARD_BACKEND_READER
    if text in ("reader", "pcsc", "real", "physical", "card"):
        return CARD_BACKEND_READER
    if text in ("sim", "simulated", "simulator", "virtual", "mock"):
        return CARD_BACKEND_SIM
    return str(default or CARD_BACKEND_READER).strip().lower() or CARD_BACKEND_READER


def _normalize_card_backend_value(value: Any) -> str:
    text = str(value or "").strip().lower()
    if len(text) == 0:
        return ""
    if text in ("reader", "pcsc", "real", "physical", "card"):
        return CARD_BACKEND_READER
    if text in ("sim", "simulated", "simulator", "virtual", "mock"):
        return CARD_BACKEND_SIM
    return ""


def _card_backend_settings_path() -> str:
    return workspace_path("main", CARD_BACKEND_SETTINGS_FILENAME)


def _load_card_backend_settings() -> dict[str, Any]:
    settings_path = _card_backend_settings_path()
    if os.path.isfile(settings_path) is False:
        return {}
    try:
        with open(settings_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return {}
    if isinstance(payload, dict):
        return dict(payload)
    return {}


def _save_card_backend_settings(payload: dict[str, Any]) -> None:
    settings_path = _card_backend_settings_path()
    settings_dir = os.path.dirname(settings_path)
    if len(settings_dir) > 0:
        os.makedirs(settings_dir, exist_ok=True)
    with open(settings_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _get_persisted_setting(key: str) -> str:
    payload = _load_card_backend_settings()
    value = payload.get(str(key), "")
    return str(value or "").strip()


def _persist_setting(key: str, value: str) -> None:
    payload = _load_card_backend_settings()
    payload[str(key)] = str(value or "").strip()
    _save_card_backend_settings(payload)


def _normalize_optional_path(path_text: str) -> str:
    normalized = str(path_text or "").strip()
    if len(normalized) == 0:
        return ""
    return os.path.abspath(os.path.expanduser(normalized))


def _get_persisted_card_backend(default: str = CARD_BACKEND_READER) -> str:
    return normalize_card_backend(_get_persisted_setting(_SETTINGS_KEY_CARD_BACKEND), default=default)


def _persist_card_backend(backend: str) -> None:
    _persist_setting(_SETTINGS_KEY_CARD_BACKEND, normalize_card_backend(backend))


def get_card_backend(default: str = CARD_BACKEND_READER) -> str:
    configured = str(os.environ.get(CARD_BACKEND_ENV, "") or "").strip()
    if len(configured) > 0:
        return normalize_card_backend(configured, default=default)
    return _get_persisted_card_backend(default=default)


def set_card_backend(backend: str, *, persist: bool = True) -> str:
    normalized = normalize_card_backend(backend)
    os.environ[CARD_BACKEND_ENV] = normalized
    if persist:
        try:
            _persist_card_backend(normalized)
        except Exception:
            pass
    return normalized


def get_card_backend_source() -> str:
    configured = str(os.environ.get(CARD_BACKEND_ENV, "") or "").strip()
    persisted = _get_persisted_setting(_SETTINGS_KEY_CARD_BACKEND)
    normalized_persisted = _normalize_card_backend_value(persisted)
    normalized_configured = _normalize_card_backend_value(configured)
    if len(configured) > 0:
        if len(normalized_persisted) > 0 and normalized_configured == normalized_persisted:
            return SETTING_SOURCE_SAVED_SELECTION
        if len(normalized_persisted) == 0 and normalized_configured == CARD_BACKEND_READER:
            return SETTING_SOURCE_DEFAULT
        return SETTING_SOURCE_SESSION_OVERRIDE
    if len(normalized_persisted) > 0:
        return SETTING_SOURCE_SAVED_SELECTION
    return SETTING_SOURCE_DEFAULT


def is_simulated_card_backend() -> bool:
    return get_card_backend() == CARD_BACKEND_SIM


def get_default_sim_quirks_path() -> str:
    return ensure_seeded_workspace_file(
        ("SIMCARD", "sim_quirks_template.py"),
        "SIMCARD",
        "sim_quirks.py",
    )


def get_default_sim_isdr_config_path() -> str:
    return ensure_seeded_workspace_file(
        ("SIMCARD", "isdr_config_template.json"),
        "SIMCARD",
        "isdr_config.json",
    )


def get_default_sim_eim_identity_path() -> str:
    return ensure_seeded_workspace_file(
        ("SIMCARD", "eim_identity_template.json"),
        "SIMCARD",
        "eim_identity.json",
    )


def get_sim_isdr_config_path() -> str:
    configured = str(os.environ.get(SIM_ISDR_CONFIG_ENV, "") or "").strip()
    if len(configured) > 0:
        return os.path.abspath(os.path.expanduser(configured))
    persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_ISDR_CONFIG_PATH)
    if len(persisted) > 0:
        return os.path.abspath(os.path.expanduser(persisted))
    default_path = get_default_sim_isdr_config_path()
    if os.path.isfile(default_path):
        return default_path
    return ""


def set_sim_isdr_config_path(path: str, *, persist: bool = True) -> str:
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_ISDR_CONFIG_ENV, None)
        if persist:
            try:
                _persist_setting(_SETTINGS_KEY_SIM_ISDR_CONFIG_PATH, "")
            except Exception:
                pass
        return ""
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_ISDR_CONFIG_ENV] = absolute_path
    if persist:
        try:
            _persist_setting(_SETTINGS_KEY_SIM_ISDR_CONFIG_PATH, absolute_path)
        except Exception:
            pass
    return absolute_path


def get_sim_isdr_config_source() -> str:
    configured = _normalize_optional_path(os.environ.get(SIM_ISDR_CONFIG_ENV, ""))
    persisted = _normalize_optional_path(_get_persisted_setting(_SETTINGS_KEY_SIM_ISDR_CONFIG_PATH))
    if len(configured) > 0:
        if len(persisted) > 0 and configured == persisted:
            return SETTING_SOURCE_SAVED_OVERRIDE
        return SETTING_SOURCE_SESSION_OVERRIDE
    if len(persisted) > 0:
        return SETTING_SOURCE_SAVED_OVERRIDE
    return SETTING_SOURCE_WORKSPACE_DEFAULT


def get_sim_eim_identity_path() -> str:
    configured = str(os.environ.get(SIM_EIM_IDENTITY_ENV, "") or "").strip()
    if len(configured) > 0:
        return os.path.abspath(os.path.expanduser(configured))
    persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_EIM_IDENTITY_PATH)
    if len(persisted) > 0:
        return os.path.abspath(os.path.expanduser(persisted))
    default_path = get_default_sim_eim_identity_path()
    if os.path.isfile(default_path):
        return default_path
    return ""


def set_sim_eim_identity_path(path: str, *, persist: bool = True) -> str:
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_EIM_IDENTITY_ENV, None)
        if persist:
            try:
                _persist_setting(_SETTINGS_KEY_SIM_EIM_IDENTITY_PATH, "")
            except Exception:
                pass
        return ""
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_EIM_IDENTITY_ENV] = absolute_path
    if persist:
        try:
            _persist_setting(_SETTINGS_KEY_SIM_EIM_IDENTITY_PATH, absolute_path)
        except Exception:
            pass
    return absolute_path


def get_sim_eim_identity_source() -> str:
    configured = _normalize_optional_path(os.environ.get(SIM_EIM_IDENTITY_ENV, ""))
    persisted = _normalize_optional_path(_get_persisted_setting(_SETTINGS_KEY_SIM_EIM_IDENTITY_PATH))
    if len(configured) > 0:
        if len(persisted) > 0 and configured == persisted:
            return SETTING_SOURCE_SAVED_OVERRIDE
        return SETTING_SOURCE_SESSION_OVERRIDE
    if len(persisted) > 0:
        return SETTING_SOURCE_SAVED_OVERRIDE
    return SETTING_SOURCE_WORKSPACE_DEFAULT


def get_default_sim_euicc_store_root() -> str:
    return ensure_workspace_dir("SIMCARD", "euicc_store")


def get_sim_euicc_store_root() -> str:
    configured = str(os.environ.get(SIM_EUICC_STORE_ENV, "") or "").strip()
    if len(configured) > 0:
        return os.path.abspath(os.path.expanduser(configured))
    persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_EUICC_STORE_ROOT)
    if len(persisted) > 0:
        return os.path.abspath(os.path.expanduser(persisted))
    return get_default_sim_euicc_store_root()


def set_sim_euicc_store_root(path: str, *, persist: bool = True) -> str:
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_EUICC_STORE_ENV, None)
        if persist:
            try:
                _persist_setting(_SETTINGS_KEY_SIM_EUICC_STORE_ROOT, "")
            except Exception:
                pass
        return ""
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_EUICC_STORE_ENV] = absolute_path
    if persist:
        try:
            _persist_setting(_SETTINGS_KEY_SIM_EUICC_STORE_ROOT, absolute_path)
        except Exception:
            pass
    return absolute_path


def get_sim_euicc_store_root_source() -> str:
    configured = _normalize_optional_path(os.environ.get(SIM_EUICC_STORE_ENV, ""))
    persisted = _normalize_optional_path(_get_persisted_setting(_SETTINGS_KEY_SIM_EUICC_STORE_ROOT))
    if len(configured) > 0:
        if len(persisted) > 0 and configured == persisted:
            return SETTING_SOURCE_SAVED_OVERRIDE
        return SETTING_SOURCE_SESSION_OVERRIDE
    if len(persisted) > 0:
        return SETTING_SOURCE_SAVED_OVERRIDE
    return SETTING_SOURCE_WORKSPACE_DEFAULT


def get_sim_quirks_path() -> str:
    configured = str(os.environ.get(SIM_QUIRKS_ENV, "") or "").strip()
    if len(configured) > 0:
        return os.path.abspath(os.path.expanduser(configured))
    persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH)
    if len(persisted) > 0:
        return os.path.abspath(os.path.expanduser(persisted))
    default_path = get_default_sim_quirks_path()
    if os.path.isfile(default_path):
        return default_path
    return ""


def get_default_sim_profile_store_path() -> str:
    return ensure_workspace_dir("SIMCARD", "profile_store")


def get_sim_profile_store_path() -> str:
    configured = str(os.environ.get(SIM_PROFILE_STORE_ENV, "") or "").strip()
    if len(configured) > 0:
        return os.path.abspath(os.path.expanduser(configured))
    persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_PROFILE_STORE_PATH)
    if len(persisted) > 0:
        return os.path.abspath(os.path.expanduser(persisted))
    return ""


def set_sim_profile_store_path(path: str, *, persist: bool = True) -> str:
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_PROFILE_STORE_ENV, None)
        if persist:
            try:
                _persist_setting(_SETTINGS_KEY_SIM_PROFILE_STORE_PATH, "")
            except Exception:
                pass
        return ""
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_PROFILE_STORE_ENV] = absolute_path
    if persist:
        try:
            _persist_setting(_SETTINGS_KEY_SIM_PROFILE_STORE_PATH, absolute_path)
        except Exception:
            pass
    return absolute_path


def get_sim_profile_store_path_source() -> str:
    configured = _normalize_optional_path(os.environ.get(SIM_PROFILE_STORE_ENV, ""))
    persisted = _normalize_optional_path(_get_persisted_setting(_SETTINGS_KEY_SIM_PROFILE_STORE_PATH))
    if len(configured) > 0:
        if len(persisted) > 0 and configured == persisted:
            return SETTING_SOURCE_SAVED_OVERRIDE
        return SETTING_SOURCE_SESSION_OVERRIDE
    if len(persisted) > 0:
        return SETTING_SOURCE_SAVED_OVERRIDE
    return SETTING_SOURCE_DERIVED_DEFAULT


def set_sim_quirks_path(path: str, *, persist: bool = True) -> str:
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_QUIRKS_ENV, None)
        if persist:
            try:
                _persist_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH, "")
            except Exception:
                pass
        return ""
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_QUIRKS_ENV] = absolute_path
    if persist:
        try:
            _persist_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH, absolute_path)
        except Exception:
            pass
    return absolute_path


def get_sim_quirks_source() -> str:
    configured = _normalize_optional_path(os.environ.get(SIM_QUIRKS_ENV, ""))
    persisted = _normalize_optional_path(_get_persisted_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH))
    if len(configured) > 0:
        if len(persisted) > 0 and configured == persisted:
            return SETTING_SOURCE_SAVED_OVERRIDE
        return SETTING_SOURCE_SESSION_OVERRIDE
    if len(persisted) > 0:
        return SETTING_SOURCE_SAVED_OVERRIDE
    return SETTING_SOURCE_WORKSPACE_DEFAULT


def describe_card_backend() -> str:
    backend = get_card_backend()
    if backend != CARD_BACKEND_SIM:
        return CARD_BACKEND_READER
    quirks_path = get_sim_quirks_path()
    isdr_config_path = get_sim_isdr_config_path()
    extras: list[str] = []
    if len(isdr_config_path) > 0:
        extras.append(os.path.basename(isdr_config_path))
    if len(quirks_path) > 0:
        extras.append(os.path.basename(quirks_path))
    if len(extras) == 0:
        return CARD_BACKEND_SIM
    return f"{CARD_BACKEND_SIM} [{', '.join(extras)}]"


def create_card_connection(
    *,
    reader_index: int = 0,
    protocol: Any = None,
    readers_func: Callable[[], Any] | None = None,
):
    if is_simulated_card_backend():
        from SIMCARD.connection import SimulatedCardConnection

        connection = SimulatedCardConnection()
        connection.connect(protocol)
        return connection

    if readers_func is None:
        from smartcard.System import readers as default_readers

        readers_func = default_readers
    reader_list = readers_func()
    if len(reader_list) == 0:
        raise RuntimeError("No smart card readers found.")
    if reader_index < 0 or reader_index >= len(reader_list):
        raise RuntimeError(
            f"Reader index {reader_index} is out of range. Detected readers: {len(reader_list)}."
        )
    connection = reader_list[reader_index].createConnection()
    if protocol is None:
        connection.connect()
    else:
        connection.connect(protocol)
    return connection
