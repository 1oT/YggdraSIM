# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SIMCARD-adjacent Command Center actions (C-7 slice).

Wraps four standalone helpers that currently live behind direct module
imports or launcher subcommands so operators can invoke them from the
GUI without dropping into a raw shell:

* ``simcard.quirks_status``      — introspect the resolved quirks file
  and the current runtime gating (``YGGDRASIM_ALLOW_QUIRKS`` /
  ``YGGDRASIM_DISABLE_QUIRKS``) without side-effects.
* ``simcard.profile_store_list`` — list profiles in a Workspace-style
  profile store directory, with manifest metadata.
* ``simcard.euicc_store_list``   — enumerate child eUICC stores under
  a chosen root path (EID-keyed directories).
* ``simcard.tuak_derive_topc``   — derive TOPc from a TOP + K pair
  using the simulator's TUAK helper. Registered under Offline Tools;
  pure math, does not read card.

No action here reaches the PC/SC transport layer — these are
module-local utilities that supplement the SCP03 workbench.
"""

from __future__ import annotations

import os
from typing import Any

from .registry import ActionContext, ActionField, ActionSpec, get_registry


OFFLINE_TOOLS_SUBSYSTEM = "Offline Tools"


# ----------------------------------------------------------------------
# simcard.quirks_status
# ----------------------------------------------------------------------


def _env_flag_state(name: str) -> dict[str, Any]:
    raw = os.environ.get(name, "")
    cleaned = str(raw or "").strip().lower()
    truthy = cleaned in ("1", "true", "yes", "on")
    return {
        "name": name,
        "set": name in os.environ,
        "value": raw,
        "interpreted": truthy,
    }


def _dispatch_quirks_status(
    ctx: ActionContext,
    *,
    path: Any = None,
) -> dict[str, Any]:
    """Return the resolved quirks file state without importing it."""
    from SIMCARD.quirks import (
        _ALLOW_QUIRKS_ENV,
        _DISABLE_QUIRKS_ENV,
        _path_is_disabled_sentinel,
        _quirks_disabled_by_env,
        _quirks_loading_enabled,
    )

    raw_path = str(path or "").strip()
    if len(raw_path) == 0:
        raw_path = os.environ.get("YGGDRASIM_SIM_QUIRKS", "")
    resolved = os.path.abspath(os.path.expanduser(str(raw_path or "").strip())) if raw_path else ""

    exists = False
    size = 0
    if len(resolved) > 0 and os.path.isfile(resolved):
        exists = True
        try:
            size = os.path.getsize(resolved)
        except OSError:
            size = 0

    sentinel = _path_is_disabled_sentinel(str(raw_path or ""))
    disabled = _quirks_disabled_by_env()
    allowed = _quirks_loading_enabled()

    effective = "empty-registry"
    if disabled:
        effective = "disabled-by-kill-switch"
    elif sentinel:
        effective = "disabled-by-sentinel"
    elif not exists:
        effective = "no-file"
    elif not allowed:
        effective = "gated-off"
    else:
        effective = "loadable"

    return {
        "input_path": raw_path,
        "resolved_path": resolved,
        "exists": exists,
        "file_size": size,
        "sentinel": sentinel,
        "env": {
            "allow": _env_flag_state(_ALLOW_QUIRKS_ENV),
            "disable": _env_flag_state(_DISABLE_QUIRKS_ENV),
        },
        "effective_state": effective,
    }


# ----------------------------------------------------------------------
# simcard.profile_store_list
# ----------------------------------------------------------------------


def _dispatch_profile_store_list(
    ctx: ActionContext,
    *,
    store_path: Any = None,
) -> dict[str, Any]:
    raw = str(store_path or "").strip()
    if len(raw) == 0:
        raise ValueError("store_path is required.")
    resolved = os.path.abspath(os.path.expanduser(raw))
    if os.path.isdir(resolved) is False:
        raise ValueError(f"profile store directory not found: {resolved}")

    from SIMCARD.profile_store import load_profiles_from_store

    try:
        entries = load_profiles_from_store(resolved)
    except Exception as error:  # noqa: BLE001
        raise ValueError(f"profile store load failed: {error}") from error

    rows: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        image = getattr(entry, "profile_image", None)
        image_fs_nodes = 0
        if image is not None:
            fs_nodes = getattr(image, "fs_nodes", None)
            if isinstance(fs_nodes, (list, tuple)):
                image_fs_nodes = len(fs_nodes)
        rows.append({
            "order": index,
            "aid": str(entry.aid or ""),
            "iccid": str(entry.iccid or ""),
            "state": str(entry.state or ""),
            "profile_class": str(getattr(entry, "profile_class", "") or ""),
            "nickname": str(getattr(entry, "nickname", "") or ""),
            "service_provider": str(getattr(entry, "service_provider", "") or ""),
            "profile_name": str(getattr(entry, "profile_name", "") or ""),
            "imsi": str(getattr(entry, "imsi", "") or ""),
            "has_upp": len(bytes(getattr(entry, "upp_bytes", b"") or b"")) > 0,
            "profile_source": str(getattr(entry, "profile_source", "") or ""),
            "image_fs_nodes": image_fs_nodes,
        })

    return {
        "store_path": resolved,
        "count": len(rows),
        "entries": rows,
    }


# ----------------------------------------------------------------------
# simcard.euicc_store_list
# ----------------------------------------------------------------------


def _dispatch_euicc_store_list(
    ctx: ActionContext,
    *,
    root_path: Any = None,
) -> dict[str, Any]:
    raw = str(root_path or "").strip()
    if len(raw) == 0:
        raise ValueError("root_path is required.")
    resolved = os.path.abspath(os.path.expanduser(raw))
    if os.path.isdir(resolved) is False:
        raise ValueError(f"eUICC store root directory not found: {resolved}")

    from SIMCARD.euicc_store import (
        default_profile_store_path,
        euicc_store_exists,
        resolve_euicc_store_path,
    )

    stores: list[dict[str, Any]] = []
    try:
        child_names = sorted(os.listdir(resolved))
    except OSError as error:
        raise ValueError(f"cannot list root_path: {error}") from error

    for name in child_names:
        child = os.path.join(resolved, name)
        if os.path.isdir(child) is False:
            continue
        # Treat the directory name as the candidate EID.
        candidate_eid = name.strip()
        resolved_store = resolve_euicc_store_path(resolved, candidate_eid)
        exists = False
        try:
            exists = euicc_store_exists(resolved_store)
        except Exception:  # noqa: BLE001 — tolerate malformed stores
            exists = False
        profile_store = ""
        try:
            profile_store = default_profile_store_path(resolved_store)
        except Exception:  # noqa: BLE001
            profile_store = ""
        stores.append({
            "eid_candidate": candidate_eid,
            "path": resolved_store,
            "exists": exists,
            "profile_store_path": profile_store,
            "profile_store_exists": os.path.isdir(profile_store) if profile_store else False,
        })

    return {
        "root_path": resolved,
        "count": len(stores),
        "stores": stores,
    }


# ----------------------------------------------------------------------
# simcard.tuak_derive_topc
# ----------------------------------------------------------------------


def _decode_hex_bytes(field_name: str, raw: Any, *, allowed_lengths: tuple[int, ...]) -> bytes:
    cleaned = str(raw or "").replace(" ", "").replace(":", "").strip().upper()
    if len(cleaned) == 0:
        raise ValueError(f"{field_name}: hex string is empty")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"{field_name}: hex string has odd length")
    try:
        value = bytes.fromhex(cleaned)
    except ValueError as error:
        raise ValueError(f"{field_name}: invalid hex — {error}") from error
    if len(value) not in allowed_lengths:
        allowed = ", ".join(str(n) for n in allowed_lengths)
        raise ValueError(
            f"{field_name}: length must be one of [{allowed}] bytes, got {len(value)}"
        )
    return value


def _dispatch_tuak_derive_topc(
    ctx: ActionContext,
    *,
    top: Any = None,
    key: Any = None,
    number_of_keccak: Any = None,
) -> dict[str, Any]:
    top_bytes = _decode_hex_bytes("top", top, allowed_lengths=(32,))
    key_bytes = _decode_hex_bytes("key", key, allowed_lengths=(16, 32))
    rounds = 1
    if number_of_keccak is not None:
        try:
            rounds = int(number_of_keccak)
        except (TypeError, ValueError) as error:
            raise ValueError(f"number_of_keccak: not an integer: {number_of_keccak!r}") from error
    if rounds < 1 or rounds > 16:
        raise ValueError("number_of_keccak must be in [1, 16].")

    from SIMCARD.tuak import derive_topc

    try:
        topc = derive_topc(top_bytes, key_bytes, number_of_keccak=rounds)
    except Exception as error:  # noqa: BLE001 — surface the validator
        raise ValueError(f"derive_topc failed: {error}") from error

    return {
        "top_hex": top_bytes.hex().upper(),
        "key_length_bits": len(key_bytes) * 8,
        "number_of_keccak": rounds,
        "topc_hex": topc.hex().upper(),
    }


# ----------------------------------------------------------------------
# ActionSpecs
# ----------------------------------------------------------------------


QUIRKS_STATUS_SPEC = ActionSpec(
    id="simcard.quirks_status",
    subsystem="SIMCARD",
    title="Quirks — status",
    description=(
        "Show the resolved simulator quirks file (from YGGDRASIM_SIM_QUIRKS "
        "or an explicit path), its size, and whether the allow / disable "
        "kill-switch environment flags let it actually load. Does not "
        "import or execute the quirks module; read-only telemetry."
    ),
    inputs=(
        ActionField(
            name="path",
            label="Quirks file (optional)",
            kind="path",
            required=False,
            help="Defaults to YGGDRASIM_SIM_QUIRKS when empty.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_quirks_status,
    requires_card=False,
    tags=("simulator", "quirks", "telemetry"),
)


PROFILE_STORE_LIST_SPEC = ActionSpec(
    id="simcard.profile_store_list",
    subsystem="SIMCARD",
    title="Profile store — list",
    description=(
        "Enumerate profile directories under a SIMCARD-style profile "
        "store root. Each manifest is parsed into AID / ICCID / state / "
        "image stats without decrypting UPP payloads."
    ),
    inputs=(
        ActionField(
            name="store_path",
            label="Store directory",
            kind="directory",
            required=True,
            help="Directory containing per-profile subdirectories.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_profile_store_list,
    requires_card=False,
    tags=("simulator", "profiles"),
)


EUICC_STORE_LIST_SPEC = ActionSpec(
    id="simcard.euicc_store_list",
    subsystem="SIMCARD",
    title="eUICC store — list",
    description=(
        "List child eUICC stores under a chosen root. The directory name "
        "is treated as the candidate EID; the resolver returns the "
        "canonical per-EID store path and whether it carries persisted "
        "state. Use to double-check Workspace layout before running the "
        "simulator."
    ),
    inputs=(
        ActionField(
            name="root_path",
            label="eUICC store root",
            kind="directory",
            required=True,
            help="Root that contains per-EID sub-directories.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_euicc_store_list,
    requires_card=False,
    tags=("simulator", "euicc"),
)


TUAK_DERIVE_TOPC_SPEC = ActionSpec(
    id="simcard.tuak_derive_topc",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="TUAK — derive TOPc",
    description=(
        "Derive TOPc from TOP (32 bytes) and subscriber key K "
        "(16 or 32 bytes) using 3GPP TS 35.231 TUAK. Pure arithmetic — "
        "does not touch the card or the live simulator."
    ),
    inputs=(
        ActionField(name="top", label="TOP (64 hex)", kind="hex", required=True,
                    help="32-byte operator constant."),
        ActionField(name="key", label="K (32 or 64 hex)", kind="hex", required=True,
                    help="Subscriber key — 128 or 256 bit."),
        ActionField(name="number_of_keccak", label="Keccak rounds", kind="int",
                    required=False, default=1, min_value=1, max_value=16,
                    help="TS 35.231 NR_KECCAK — typically 1."),
    ),
    output_kind="json",
    dispatcher=_dispatch_tuak_derive_topc,
    requires_card=False,
    tags=("crypto", "tuak", "3gpp"),
)


get_registry().register(QUIRKS_STATUS_SPEC)
get_registry().register(PROFILE_STORE_LIST_SPEC)
get_registry().register(EUICC_STORE_LIST_SPEC)
get_registry().register(TUAK_DERIVE_TOPC_SPEC)
