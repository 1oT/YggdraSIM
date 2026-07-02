# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Simulated card quirk flags: opt-out knobs for spec-compliant but interoperability-breaking behaviours."""
from __future__ import annotations

import copy
import importlib.util
import os
from dataclasses import dataclass, field, fields, is_dataclass
from types import ModuleType
from typing import Any, Callable

from SIMCARD.state import SimCardState, SimEimEntry


ApduResult = tuple[bytes, int, int]
BeforeHook = Callable[[bytes, SimCardState], ApduResult | None]
AfterHook = Callable[[bytes, ApduResult, SimCardState], ApduResult | None]
ResetHook = Callable[[SimCardState], None]
StateHook = Callable[[SimCardState], None]

_BYTE_FIELDS = {
    "root_ci_pkid",
    "info1_svn",
    "profile_version",
    "svn",
    "firmware_version",
    "ts102241_version",
    "globalplatform_version",
    "pp_version",
    "euicc_ci_pkid",
    "eim_public_key_data",
    "trusted_tls_public_key_data",
    "eum_certificate_der",
    "euicc_certificate_der",
}
_BYTE_LIST_FIELDS = {
    "iot_versions",
    "additional_pp_versions",
    "allowed_ci_pkids",
    "ci_list",
}
_INT_LIST_FIELDS = {
    "uicc_capability_bits",
    "rsp_capability_bits",
    "forbidden_profile_policy_bits",
    "supported_protocol_bits",
}
_STRING_LIST_FIELDS = {"additional_root_smds_addresses"}
_INT_FIELDS = {
    "system_apps_count",
    "free_nvm",
    "free_ram",
    "euicc_category",
    "ipa_mode",
    "eim_id_type",
    "counter_value",
    "association_token",
}
_BOOL_FIELDS = {
    "ecall_supported",
    "fallback_supported",
    "indirect_profile_download",
}


@dataclass
class QuirkRegistry:
    before_apdu_hooks: list[BeforeHook] = field(default_factory=list)
    after_apdu_hooks: list[AfterHook] = field(default_factory=list)
    on_reset_hooks: list[ResetHook] = field(default_factory=list)
    state_hooks: list[StateHook] = field(default_factory=list)

    def add_before_apdu(self, hook: BeforeHook) -> None:
        self.before_apdu_hooks.append(hook)

    def add_after_apdu(self, hook: AfterHook) -> None:
        self.after_apdu_hooks.append(hook)

    def add_on_reset(self, hook: ResetHook) -> None:
        self.on_reset_hooks.append(hook)

    def add_state_hook(self, hook: StateHook) -> None:
        self.state_hooks.append(hook)

    def apply_state_hooks(self, state: SimCardState) -> None:
        for hook in self.state_hooks:
            hook(state)


_ALLOW_QUIRKS_ENV = "YGGDRASIM_ALLOW_QUIRKS"
_DISABLE_QUIRKS_ENV = "YGGDRASIM_DISABLE_QUIRKS"
# Path-level sentinels that mean "no quirks file - do not even attempt to
# resolve one". Kept in sync with ``SIM_QUIRKS_PATH_DISABLED_ALIASES`` in
# :mod:`yggdrasim_common.card_backend`. Duplicated here to keep the module
# importable without the common-package dependency (SIMCARD is loaded very
# early during simulator bring-up).
_QUIRKS_PATH_DISABLED_ALIASES = ("none", "off", "disabled", "disable")


def _quirks_loading_enabled() -> bool:
    value = os.environ.get(_ALLOW_QUIRKS_ENV, "").strip().lower()
    return value in ("1", "true", "yes", "on")


def _quirks_disabled_by_env() -> bool:
    """Return ``True`` when the kill-switch env flag is set truthy.

    The kill switch is orthogonal to ``YGGDRASIM_ALLOW_QUIRKS``: it
    always wins, regardless of whether the path points at an existing
    trusted file and regardless of whether the allow gate is flipped
    on. Use it in CI / sandboxed environments where the simulator must
    never import arbitrary Python from disk.
    """
    value = os.environ.get(_DISABLE_QUIRKS_ENV, "").strip().lower()
    return value in ("1", "true", "yes", "on")


def _path_is_disabled_sentinel(path: str) -> bool:
    text = str(path or "").strip().lower()
    if len(text) == 0:
        return False
    return text in _QUIRKS_PATH_DISABLED_ALIASES


def load_quirk_registry(path: str) -> QuirkRegistry:
    """Load the per-card quirk overrides from the quirks YAML file into the engine registry."""
    registry = QuirkRegistry()
    if _quirks_disabled_by_env():
        return registry
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        return registry
    if _path_is_disabled_sentinel(normalized):
        return registry
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    if os.path.isfile(absolute_path) is False:
        return registry
    if _quirks_loading_enabled() is False:
        raise PermissionError(
            "Simulator quirk loading is disabled by default because it executes "
            "arbitrary Python from disk. Set "
            f"{_ALLOW_QUIRKS_ENV}=1 in the environment to enable loading "
            f"{absolute_path}, or set {_DISABLE_QUIRKS_ENV}=1 / "
            f"YGGDRASIM_SIM_QUIRKS=none to run the simulator with an "
            f"empty quirks registry."
        )
    module = _load_module_from_path(absolute_path)
    metadata_hook = _build_metadata_state_hook(module)
    if metadata_hook is not None:
        registry.add_state_hook(metadata_hook)
    state_hook = getattr(module, "configure_state", None)
    if callable(state_hook):
        registry.add_state_hook(state_hook)
    register = getattr(module, "register_quirks", None)
    if callable(register):
        register(registry)
    before_hook = getattr(module, "before_apdu", None)
    if callable(before_hook):
        registry.add_before_apdu(before_hook)
    after_hook = getattr(module, "after_apdu", None)
    if callable(after_hook):
        registry.add_after_apdu(after_hook)
    reset_hook = getattr(module, "on_reset", None)
    if callable(reset_hook):
        registry.add_on_reset(reset_hook)
    return registry


def _build_metadata_state_hook(module: ModuleType) -> StateHook | None:
    overrides: dict[str, Any] = {}
    raw_metadata = getattr(module, "metadata_overrides", None)
    if isinstance(raw_metadata, dict):
        overrides.update(raw_metadata)

    alias_map = {
        "atr": "atr",
        "atr_hex": "atr",
        "default_dp_address": "default_dp_address",
        "root_ci_pkid": "root_ci_pkid",
        "euicc_info_overrides": "euicc_info",
        "configured_data_overrides": "configured_data",
        "eim_entries": "eim_entries",
        "eum_certificate_der": "eum_certificate_der",
        "euicc_certificate_der": "euicc_certificate_der",
    }
    for attribute_name, target_key in alias_map.items():
        if hasattr(module, attribute_name):
            overrides[target_key] = getattr(module, attribute_name)

    if len(overrides) == 0:
        return None

    frozen_overrides = copy.deepcopy(overrides)

    def apply(state: SimCardState) -> None:
        _apply_metadata_overrides(state, frozen_overrides)

    return apply


def _apply_metadata_overrides(state: SimCardState, overrides: dict[str, Any]) -> None:
    atr_override = overrides["atr"] if "atr" in overrides else overrides.get("atr_hex")
    if atr_override is not None:
        state.atr = _coerce_bytes(atr_override)

    default_dp_address = overrides.get("default_dp_address")
    if default_dp_address is not None:
        state.default_dp_address = str(default_dp_address)

    configured_override = overrides.get("configured_data")
    eim_entries_override = overrides.get("eim_entries")

    if "root_ci_pkid" in overrides:
        previous_root = bytes(state.root_ci_pkid or b"")
        new_root = _coerce_bytes(overrides["root_ci_pkid"])
        state.root_ci_pkid = new_root
        if _override_key_missing(configured_override, "allowed_ci_pkids"):
            state.configured_data.allowed_ci_pkids = _replace_matching_bytes(
                state.configured_data.allowed_ci_pkids,
                previous_root,
                new_root,
            )
        if _override_key_missing(configured_override, "ci_list"):
            state.configured_data.ci_list = _replace_matching_bytes(
                state.configured_data.ci_list,
                previous_root,
                new_root,
            )
        if eim_entries_override is None:
            for entry in state.eim_entries:
                if len(bytes(entry.euicc_ci_pkid or b"")) == 0 or bytes(entry.euicc_ci_pkid) == previous_root:
                    entry.euicc_ci_pkid = new_root

    euicc_info_override = overrides.get("euicc_info")
    if euicc_info_override is not None:
        _apply_dataclass_overrides(state.euicc_info, euicc_info_override)

    if configured_override is not None:
        _apply_dataclass_overrides(state.configured_data, configured_override)

    if eim_entries_override is not None:
        state.eim_entries = [_coerce_eim_entry(entry) for entry in _normalize_sequence(eim_entries_override)]

    for field_name in ("eum_certificate_der", "euicc_certificate_der"):
        if field_name in overrides:
            setattr(state, field_name, _coerce_bytes(overrides[field_name]))


def _apply_dataclass_overrides(target: Any, overrides: Any) -> None:
    if is_dataclass(overrides):
        for field_info in fields(overrides):
            setattr(target, field_info.name, copy.deepcopy(getattr(overrides, field_info.name)))
        return
    if isinstance(overrides, dict) is False:
        return
    for field_name, override_value in overrides.items():
        if hasattr(target, field_name) is False:
            continue
        current_value = getattr(target, field_name)
        if is_dataclass(current_value) and (isinstance(override_value, dict) or is_dataclass(override_value)):
            _apply_dataclass_overrides(current_value, override_value)
            continue
        setattr(target, field_name, _coerce_override_value(field_name, override_value))


def _coerce_override_value(field_name: str, value: Any) -> Any:
    if field_name in _BYTE_FIELDS:
        return _coerce_bytes(value)
    if field_name in _BYTE_LIST_FIELDS:
        return [_coerce_bytes(item) for item in _normalize_sequence(value)]
    if field_name in _INT_LIST_FIELDS:
        return [int(item) for item in _normalize_sequence(value)]
    if field_name in _STRING_LIST_FIELDS:
        return [str(item) for item in _normalize_sequence(value)]
    if field_name in _INT_FIELDS:
        return int(value)
    if field_name in _BOOL_FIELDS:
        return _coerce_bool(value)
    return copy.deepcopy(value)


def _coerce_eim_entry(value: Any) -> SimEimEntry:
    if isinstance(value, SimEimEntry):
        return copy.deepcopy(value)
    entry = SimEimEntry(eim_id="")
    _apply_dataclass_overrides(entry, value)
    if len(str(entry.eim_id or "").strip()) == 0:
        raise ValueError("Simulator quirks eim_entries must provide eim_id.")
    return entry


def _coerce_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return bytes(value)
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return bytes(value.tobytes())
    if isinstance(value, str):
        cleaned = value.strip().replace(" ", "").replace(":", "").replace("-", "")
        if cleaned.startswith("0x") or cleaned.startswith("0X"):
            cleaned = cleaned[2:]
        if len(cleaned) == 0:
            return b""
        return bytes.fromhex(cleaned)
    if isinstance(value, (list, tuple)):
        return bytes(int(item) & 0xFF for item in value)
    raise TypeError(f"Unsupported simulator quirk byte value: {type(value).__name__}")


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
    return bool(value)


def _normalize_sequence(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    if value is None:
        return []
    return [value]


def _override_key_missing(container: Any, key: str) -> bool:
    if isinstance(container, dict):
        return key not in container
    if is_dataclass(container):
        return hasattr(container, key) is False
    return True


def _replace_matching_bytes(values: list[bytes], old_value: bytes, new_value: bytes) -> list[bytes]:
    replaced = False
    output: list[bytes] = []
    for value in values:
        raw = bytes(value or b"")
        if len(old_value) > 0 and raw == old_value:
            output.append(bytes(new_value))
            replaced = True
            continue
        output.append(raw)
    if replaced is False and len(bytes(new_value or b"")) > 0:
        output.append(bytes(new_value))
    return output


def _load_module_from_path(path: str) -> ModuleType:
    module_name = f"yggdrasim_simcard_quirks_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load simulator quirks from {path}.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
