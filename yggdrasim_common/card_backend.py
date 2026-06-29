# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Card backend selector: persists and resolves the active transport (physical reader vs simulated card) and associated config paths."""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
from typing import Any, Callable
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlparse, urlunparse

from .runtime_paths import ensure_seeded_workspace_file, ensure_workspace_dir, runtime_path, workspace_path


_LOGGER = logging.getLogger(__name__)


CARD_BACKEND_ENV = "YGGDRASIM_CARD_BACKEND"
CARD_RELAY_URL_ENV = "YGGDRASIM_CARD_RELAY_URL"
CARD_RELAY_TOKEN_ENV = "YGGDRASIM_CARD_RELAY_TOKEN"
CARD_RELAY_TOKEN_FILE_ENV = "YGGDRASIM_CARD_RELAY_TOKEN_FILE"
SIM_QUIRKS_ENV = "YGGDRASIM_SIM_QUIRKS"
SIM_ISDR_CONFIG_ENV = "YGGDRASIM_SIM_ISDR_CONFIG"
SIM_EIM_IDENTITY_ENV = "YGGDRASIM_SIM_EIM_IDENTITY"
SIM_EUICC_STORE_ENV = "YGGDRASIM_SIM_EUICC_STORE"
SIM_PROFILE_STORE_ENV = "YGGDRASIM_SIM_PROFILE_STORE"

CARD_BACKEND_READER = "reader"
CARD_BACKEND_SIM = "sim"
# Sentinel value that means "do not load any simulator quirks file". It is
# accepted by YGGDRASIM_SIM_QUIRKS, by the persisted setting, and by the
# ``set_sim_quirks_path`` helper. When seen, the getter short-circuits to
# the empty-string path so no fall-through to the seeded workspace default
# occurs and the quirks registry stays empty without tripping the
# YGGDRASIM_ALLOW_QUIRKS gate.
SIM_QUIRKS_PATH_NONE = "none"
SIM_QUIRKS_PATH_DISABLED_ALIASES = ("none", "off", "disabled", "disable")
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
SETTING_SOURCE_DISABLED = "disabled"
CARD_RELAY_MARKER_FILENAME = "hil_bridge_card_relay.json"
DEFAULT_CARD_RELAY_TIMEOUT_SECONDS = 30


def normalize_card_backend(value: Any, default: str = CARD_BACKEND_READER) -> str:
    """Canonicalise a backend specifier string to one of the known backend types."""
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
    except json.JSONDecodeError as decode_error:
        _quarantine_corrupt_card_backend(settings_path, decode_error)
        return {}
    except OSError as io_error:
        _LOGGER.warning(
            "card_backend: unable to read %s (%s); using empty settings.",
            settings_path,
            io_error,
        )
        return {}
    if isinstance(payload, dict):
        return dict(payload)
    return {}


def _quarantine_corrupt_card_backend(
    settings_path: str,
    decode_error: json.JSONDecodeError,
) -> None:
    sidecar_path = f"{settings_path}.corrupt.{int(time.time())}"
    try:
        shutil.move(settings_path, sidecar_path)
    except OSError as move_error:
        _LOGGER.error(
            "card_backend: %s is corrupt (%s) and could not be renamed "
            "aside (%s); empty settings will be used until the file is "
            "repaired.",
            settings_path,
            decode_error,
            move_error,
        )
        return
    _LOGGER.warning(
        "card_backend: %s was unparseable (%s); moved to %s. Review or "
        "restore the file before relying on saved backend choices.",
        settings_path,
        decode_error,
        sidecar_path,
    )


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


def _try_persist_setting(key: str, value: str) -> None:
    try:
        _persist_setting(key, value)
    except OSError as io_error:
        _LOGGER.warning(
            "card_backend: could not persist %s=%r (%s: %s).",
            key,
            value,
            io_error.__class__.__name__,
            io_error,
        )


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
    """Write the active card-backend choice to the runtime config."""
    normalized = normalize_card_backend(backend)
    os.environ[CARD_BACKEND_ENV] = normalized
    if persist:
        try:
            _persist_card_backend(normalized)
        except OSError as io_error:
            _LOGGER.warning(
                "card_backend: could not persist backend=%r (%s: %s).",
                normalized, io_error.__class__.__name__, io_error,
            )
    return normalized


def get_card_backend_source() -> str:
    """Return the config source (env-var, config file, or default) that set the current backend."""
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
    """Return the filesystem path of the ISD-R configuration file for the current backend."""
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
    """Set the SIM ISD-R config path override in the backend configuration."""
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_ISDR_CONFIG_ENV, None)
        if persist:
            _try_persist_setting(_SETTINGS_KEY_SIM_ISDR_CONFIG_PATH, "")
        return ""
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_ISDR_CONFIG_ENV] = absolute_path
    if persist:
        _try_persist_setting(_SETTINGS_KEY_SIM_ISDR_CONFIG_PATH, absolute_path)
    return absolute_path


def get_sim_isdr_config_source() -> str:
    """Return the effective source label for the SIM ISD-R config path (env-var, config, or default)."""
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
    """Return the path to the SIM eIM identity file for the current backend."""
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
    """Set the SIM eIM identity path override in the backend configuration."""
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_EIM_IDENTITY_ENV, None)
        if persist:
            _try_persist_setting(_SETTINGS_KEY_SIM_EIM_IDENTITY_PATH, "")
        return ""
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_EIM_IDENTITY_ENV] = absolute_path
    if persist:
        _try_persist_setting(_SETTINGS_KEY_SIM_EIM_IDENTITY_PATH, absolute_path)
    return absolute_path


def get_sim_eim_identity_source() -> str:
    """Return the effective source label for the SIM eIM identity path."""
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
    """Return the root directory path for the SIM eUICC store."""
    configured = str(os.environ.get(SIM_EUICC_STORE_ENV, "") or "").strip()
    if len(configured) > 0:
        return os.path.abspath(os.path.expanduser(configured))
    persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_EUICC_STORE_ROOT)
    if len(persisted) > 0:
        return os.path.abspath(os.path.expanduser(persisted))
    return get_default_sim_euicc_store_root()


def set_sim_euicc_store_root(path: str, *, persist: bool = True) -> str:
    """Set the SIM eUICC store root path override in the backend configuration."""
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_EUICC_STORE_ENV, None)
        if persist:
            _try_persist_setting(_SETTINGS_KEY_SIM_EUICC_STORE_ROOT, "")
        return ""
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_EUICC_STORE_ENV] = absolute_path
    if persist:
        _try_persist_setting(_SETTINGS_KEY_SIM_EUICC_STORE_ROOT, absolute_path)
    return absolute_path


def get_sim_euicc_store_root_source() -> str:
    """Return the effective source label for the SIM eUICC store root path."""
    configured = _normalize_optional_path(os.environ.get(SIM_EUICC_STORE_ENV, ""))
    persisted = _normalize_optional_path(_get_persisted_setting(_SETTINGS_KEY_SIM_EUICC_STORE_ROOT))
    if len(configured) > 0:
        if len(persisted) > 0 and configured == persisted:
            return SETTING_SOURCE_SAVED_OVERRIDE
        return SETTING_SOURCE_SESSION_OVERRIDE
    if len(persisted) > 0:
        return SETTING_SOURCE_SAVED_OVERRIDE
    return SETTING_SOURCE_WORKSPACE_DEFAULT


def _is_sim_quirks_disabled_sentinel(value: Any) -> bool:
    """Return ``True`` when ``value`` is one of the "disabled" sentinels.

    The sentinel is case-insensitive and matches any of
    ``SIM_QUIRKS_PATH_DISABLED_ALIASES`` (``none`` / ``off`` /
    ``disabled`` / ``disable``). Any leading/trailing whitespace is
    tolerated so operators can paste from guides without surprise.
    """
    text = str(value or "").strip().lower()
    if len(text) == 0:
        return False
    return text in SIM_QUIRKS_PATH_DISABLED_ALIASES


def is_sim_quirks_disabled() -> bool:
    """Return ``True`` when the operator has explicitly opted out of
    loading any simulator quirks file.

    This inspects the same env-var/persisted cascade as
    :func:`get_sim_quirks_path`. The env var always wins over the
    persisted setting, mirroring the resolver: if the env carries a
    concrete path the operator has actively re-enabled quirks for the
    current process, even when an older persisted ``"none"`` sentinel
    is still on disk. Callers that need both the path and the disabled
    state should prefer :func:`get_sim_quirks_path` followed by
    :func:`is_sim_quirks_disabled` to keep the two in sync.
    """
    configured = str(os.environ.get(SIM_QUIRKS_ENV, "") or "").strip()
    if _is_sim_quirks_disabled_sentinel(configured):
        return True
    if len(configured) > 0:
        # A concrete env path overrides any persisted opt-out: the
        # operator has explicitly pointed the current process at a
        # quirks file, so the resolver will return that path and the
        # disabled probe must agree.
        return False
    persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH)
    if _is_sim_quirks_disabled_sentinel(persisted):
        return True
    return False


def get_sim_quirks_path() -> str:
    """Return the path to the SIM quirks override file."""
    configured = str(os.environ.get(SIM_QUIRKS_ENV, "") or "").strip()
    if _is_sim_quirks_disabled_sentinel(configured):
        return ""
    if len(configured) > 0:
        return os.path.abspath(os.path.expanduser(configured))
    persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH)
    if _is_sim_quirks_disabled_sentinel(persisted):
        return ""
    if len(persisted) > 0:
        return os.path.abspath(os.path.expanduser(persisted))
    default_path = get_default_sim_quirks_path()
    if os.path.isfile(default_path):
        return default_path
    return ""


def get_default_sim_profile_store_path() -> str:
    return ensure_workspace_dir("SIMCARD", "profile_store")


def get_sim_profile_store_path() -> str:
    """Return the path to the profile binary store directory."""
    configured = str(os.environ.get(SIM_PROFILE_STORE_ENV, "") or "").strip()
    if len(configured) > 0:
        return os.path.abspath(os.path.expanduser(configured))
    persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_PROFILE_STORE_PATH)
    if len(persisted) > 0:
        return os.path.abspath(os.path.expanduser(persisted))
    return ""


def set_sim_profile_store_path(path: str, *, persist: bool = True) -> str:
    """Set the profile store path override in the backend configuration."""
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_PROFILE_STORE_ENV, None)
        if persist:
            _try_persist_setting(_SETTINGS_KEY_SIM_PROFILE_STORE_PATH, "")
        return ""
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_PROFILE_STORE_ENV] = absolute_path
    if persist:
        _try_persist_setting(_SETTINGS_KEY_SIM_PROFILE_STORE_PATH, absolute_path)
    return absolute_path


def get_sim_profile_store_path_source() -> str:
    """Return the effective source label for the profile store path."""
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
    """Set the quirks override file path in the backend configuration."""
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        os.environ.pop(SIM_QUIRKS_ENV, None)
        if persist:
            _try_persist_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH, "")
        return ""
    if _is_sim_quirks_disabled_sentinel(normalized):
        # Explicit opt-out: record the canonical sentinel in both env
        # and persisted store so `get_sim_quirks_path` returns "" and
        # the getter does not fall through to the reseeded workspace
        # default.
        os.environ[SIM_QUIRKS_ENV] = SIM_QUIRKS_PATH_NONE
        if persist:
            _try_persist_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH, SIM_QUIRKS_PATH_NONE)
        return SIM_QUIRKS_PATH_NONE
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    os.environ[SIM_QUIRKS_ENV] = absolute_path
    if persist:
        _try_persist_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH, absolute_path)
    return absolute_path


def get_sim_quirks_source() -> str:
    """Return the effective source label for the SIM quirks path."""
    raw_configured = str(os.environ.get(SIM_QUIRKS_ENV, "") or "").strip()
    raw_persisted = _get_persisted_setting(_SETTINGS_KEY_SIM_QUIRKS_PATH)
    if _is_sim_quirks_disabled_sentinel(raw_configured):
        return SETTING_SOURCE_DISABLED
    if _is_sim_quirks_disabled_sentinel(raw_persisted):
        return SETTING_SOURCE_DISABLED
    configured = _normalize_optional_path(raw_configured)
    persisted = _normalize_optional_path(raw_persisted)
    if len(configured) > 0:
        if len(persisted) > 0 and configured == persisted:
            return SETTING_SOURCE_SAVED_OVERRIDE
        return SETTING_SOURCE_SESSION_OVERRIDE
    if len(persisted) > 0:
        return SETTING_SOURCE_SAVED_OVERRIDE
    return SETTING_SOURCE_WORKSPACE_DEFAULT


def _card_relay_marker_path() -> str:
    return runtime_path("state", CARD_RELAY_MARKER_FILENAME)


def _normalize_card_relay_url(value: Any) -> str:
    text = str(value or "").strip()
    if len(text) == 0:
        return ""
    if text.startswith(("http://", "https://")) is False:
        return ""
    if text.rstrip("/").endswith("/apdu"):
        return text.rstrip("/")
    return text.rstrip("/") + "/apdu"


def _build_card_relay_status_url(apdu_url: str) -> str:
    parsed = urlparse(apdu_url)
    normalized_path = parsed.path.rstrip("/")
    if normalized_path.endswith("/apdu"):
        status_path = normalized_path[: -len("/apdu")] + "/status"
    elif normalized_path == "":
        status_path = "/status"
    else:
        status_path = normalized_path + "/status"
    return urlunparse((parsed.scheme, parsed.netloc, status_path, "", "", ""))


def _read_card_relay_marker_payload() -> dict[str, Any]:
    """Return the parsed marker payload, or an empty dict on any failure."""
    marker_path = _card_relay_marker_path()
    if os.path.isfile(marker_path) is False:
        return {}
    try:
        with open(marker_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as marker_error:
        _LOGGER.warning(
            "card_backend: unreadable relay marker %s (%s: %s); falling back to defaults.",
            marker_path,
            marker_error.__class__.__name__,
            marker_error,
        )
        return {}
    if isinstance(payload, dict) is False:
        return {}
    return payload


def _resolve_card_relay_url() -> tuple[str, str]:
    configured = _normalize_card_relay_url(os.environ.get(CARD_RELAY_URL_ENV, ""))
    if len(configured) > 0:
        return configured, "env"

    payload = _read_card_relay_marker_payload()
    if len(payload) == 0:
        return "", ""

    marker_url = _normalize_card_relay_url(payload.get("url") or payload.get("apduUrl") or "")
    if len(marker_url) == 0:
        return "", ""
    return marker_url, "marker"


def _resolve_card_relay_token(*, allow_marker: bool) -> str:
    """Resolve the bearer token for the card relay client.

    Resolution order matches :func:`_resolve_card_relay_url` so the
    URL and the token are sourced consistently:

    1. ``YGGDRASIM_CARD_RELAY_TOKEN`` — raw token value.
    2. ``YGGDRASIM_CARD_RELAY_TOKEN_FILE`` — path to a 0600 token file.
    3. The runtime marker (only when *allow_marker* is True), which
       may carry either ``token`` (raw) or ``tokenFile`` (path).

    Returning an empty string is fine: the relay accepts unauthenticated
    requests when bound to loopback, which is the historical HilBridge
    deployment that we must not regress.
    """
    direct = str(os.environ.get(CARD_RELAY_TOKEN_ENV, "") or "").strip()
    if len(direct) > 0:
        return direct

    file_path = str(os.environ.get(CARD_RELAY_TOKEN_FILE_ENV, "") or "").strip()
    if len(file_path) > 0:
        try:
            with open(os.path.expanduser(file_path), "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError as token_error:
            _LOGGER.warning(
                "card_backend: cannot read token file %s (%s: %s); proceeding without bearer.",
                file_path,
                token_error.__class__.__name__,
                token_error,
            )
            return ""

    if allow_marker is False:
        return ""

    payload = _read_card_relay_marker_payload()
    if len(payload) == 0:
        return ""
    raw_marker_token = str(payload.get("token", "") or "").strip()
    if len(raw_marker_token) > 0:
        return raw_marker_token
    marker_token_file = str(payload.get("tokenFile", "") or "").strip()
    if len(marker_token_file) > 0:
        try:
            with open(os.path.expanduser(marker_token_file), "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            return ""
    return ""


def _request_card_relay_json(
    url: str,
    *,
    method: str,
    timeout_seconds: int = DEFAULT_CARD_RELAY_TIMEOUT_SECONDS,
    request_json: dict[str, Any] | None = None,
    auth_token: str = "",
) -> dict[str, Any]:
    encoded_body = None
    headers = {"Accept": "application/json"}
    if request_json is not None:
        encoded_body = json.dumps(request_json).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if len(auth_token) > 0:
        headers["Authorization"] = f"Bearer {auth_token}"
    request = urllib_request.Request(url, data=encoded_body, headers=headers, method=method)
    try:
        with urllib_request.urlopen(
            request,
            timeout=max(1, int(timeout_seconds or DEFAULT_CARD_RELAY_TIMEOUT_SECONDS)),
        ) as response:
            raw_payload = response.read().decode("utf-8")
    except urllib_error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace").strip()
        detail = error_body or str(exc.reason)
        raise RuntimeError(f"Card relay HTTP {exc.code}: {detail}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError(f"Card relay connection failed: {exc}") from exc

    try:
        payload = json.loads(raw_payload) if len(raw_payload) > 0 else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Card relay returned invalid JSON: {raw_payload}") from exc
    if isinstance(payload, dict) is False:
        raise RuntimeError("Card relay response is not a JSON object.")
    error_text = str(payload.get("error", "") or "").strip()
    if len(error_text) > 0:
        raise RuntimeError(error_text)
    return payload


class RelayCardConnection:
    def __init__(
        self,
        endpoint: str,
        timeout_seconds: int = DEFAULT_CARD_RELAY_TIMEOUT_SECONDS,
        *,
        auth_token: str = "",
    ):
        normalized_endpoint = _normalize_card_relay_url(endpoint)
        if len(normalized_endpoint) == 0:
            raise RuntimeError("Invalid card relay endpoint.")
        self._endpoint = normalized_endpoint
        self._status_url = _build_card_relay_status_url(normalized_endpoint)
        self._timeout_seconds = max(1, int(timeout_seconds or DEFAULT_CARD_RELAY_TIMEOUT_SECONDS))
        self._auth_token = str(auth_token or "").strip()
        self._connected = False
        self._atr: list[int] = []

    @property
    def auth_token(self) -> str:
        """Return the bearer token configured on this connection (or empty)."""
        return self._auth_token

    def connect(self, protocol: Any = None) -> None:
        """Connect to the physical card via the configured PCSC or serial backend."""
        del protocol
        payload = self._request_json(self._status_url, method="GET")
        atr_hex = str(payload.get("atr", "") or "").strip()
        try:
            self._atr = list(bytes.fromhex(atr_hex)) if len(atr_hex) > 0 else []
        except ValueError as exc:
            raise RuntimeError(f"Card relay returned invalid ATR hex: {atr_hex}") from exc
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def getATR(self):
        if self._connected is False:
            self.connect()
        return list(self._atr)

    def transmit(self, apdu):
        """Transmit a C-APDU and return the R-APDU bytes."""
        if self._connected is False:
            self.connect()
        apdu_bytes = bytes(apdu)
        payload = self._request_json(
            self._endpoint,
            method="POST",
            request_json={"apdu": apdu_bytes.hex().upper()},
        )
        data_hex = str(payload.get("data", "") or "").strip()
        sw1_hex = str(payload.get("sw1", "") or "").strip()
        sw2_hex = str(payload.get("sw2", "") or "").strip()
        if len(sw1_hex) == 0 or len(sw2_hex) == 0:
            raise RuntimeError("Card relay response is missing status words.")
        try:
            data = list(bytes.fromhex(data_hex)) if len(data_hex) > 0 else []
            sw1 = int(sw1_hex, 16)
            sw2 = int(sw2_hex, 16)
        except ValueError as exc:
            raise RuntimeError(f"Card relay response contained invalid hex fields: {payload}") from exc
        return data, sw1, sw2

    def _request_json(self, url: str, *, method: str, request_json: dict[str, Any] | None = None) -> dict[str, Any]:
        return _request_card_relay_json(
            url,
            method=method,
            timeout_seconds=self._timeout_seconds,
            request_json=request_json,
            auth_token=self._auth_token,
        )


def describe_card_backend() -> str:
    """Return a multi-line human-readable description of the current backend configuration."""
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
    # Defer the import so the recorder module isn't dragged in until a
    # connection is actually being created — keeps cold-start cheap for
    # CLI tools that never touch a card.
    """Create and return a live card connection using the configured backend."""
    from .apdu_recorder import wrap_connection

    if is_simulated_card_backend():
        from SIMCARD.connection import SimulatedCardConnection

        connection = SimulatedCardConnection()
        connection.connect(protocol)
        return wrap_connection(connection, source="simulator")

    relay_url, relay_source = _resolve_card_relay_url()
    if len(relay_url) > 0:
        relay_token = _resolve_card_relay_token(allow_marker=relay_source == "marker")
        relay_connection = RelayCardConnection(relay_url, auth_token=relay_token)
        try:
            relay_connection.connect(protocol)
        except Exception as relay_error:
            # If the operator explicitly set YGGDRASIM_CARD_RELAY_URL, a failure
            # to reach it is fatal; if the URL came from the runtime marker we
            # fall back to local readers so stale markers don't wedge startup.
            if relay_source == "env":
                raise
            _LOGGER.info(
                "card_backend: relay %s unreachable (%s: %s); falling back to local reader.",
                relay_url,
                relay_error.__class__.__name__,
                relay_error,
            )
        else:
            return wrap_connection(
                relay_connection,
                source=f"relay#{reader_index}",
            )

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
    # pyscard defaults disposition to ``SCARD_UNPOWER_CARD``, which means
    # the card gets power-cycled every time this connection closes. That
    # is a problem whenever multiple handles share the same reader —
    # e.g. the reader-bar poll grabbing ATRs while an scp03 scan session
    # is live: when the poll handle disconnects, pcscd honours UNPOWER
    # and the live session's card state (selected DF, secure channel,
    # transient-memory slots) is torn down silently. Passing
    # ``SCARD_LEAVE_CARD`` keeps the card powered up so long as *any*
    # handle is still open, which is exactly what we want for a shared
    # desktop UI that can open many concurrent sessions against the
    # same reader.
    try:
        from smartcard.scard import SCARD_LEAVE_CARD as _SCARD_LEAVE_CARD
    except Exception:  # noqa: BLE001 — pyscard shim may omit scard consts
        _SCARD_LEAVE_CARD = 0
    def _connect_with_leave_card() -> None:
        try:
            if protocol is None:
                connection.connect(disposition=_SCARD_LEAVE_CARD)
            else:
                connection.connect(protocol, disposition=_SCARD_LEAVE_CARD)
            return
        except TypeError:
            # Older pyscard releases lack the ``disposition`` kwarg on
            # ``connect``; fall back and patch the attribute directly.
            pass
        if protocol is None:
            connection.connect()
        else:
            connection.connect(protocol)
        try:
            connection.disposition = _SCARD_LEAVE_CARD
        except Exception:  # noqa: BLE001
            pass
    _connect_with_leave_card()
    # Pre-resolve a stable name for the recorder source so the GUI's
    # APDU dock can group rows per-reader at a glance. Falls back to
    # the raw index when the reader exposes no name.
    try:
        reader_name = str(reader_list[reader_index]) or f"pcsc#{reader_index}"
    except Exception:  # noqa: BLE001 — exotic reader objects
        reader_name = f"pcsc#{reader_index}"
    return wrap_connection(connection, source=reader_name)
