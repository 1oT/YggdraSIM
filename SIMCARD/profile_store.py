# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Profile store: tracks enabled/disabled profiles and maps EID profile slots to on-disk state files."""
from __future__ import annotations

import os
import shutil
from typing import Any

from SIMCARD.saip_profile import decode_profile_image
from SIMCARD.state import (
    SimProfileAuthConfig,
    SimProfileEntry,
    SimProfileFsNode,
    SimProfileImage,
    SimProfilePinEntry,
    SimProfilePukEntry,
    SimProfileRfmInstance,
    SimProfileSecurityDomain,
    SimProfileSecurityDomainKey,
)
from yggdrasim_common.inventory_crypto import (
    read_secret_file_bytes,
    read_secret_json_file,
    write_secret_file_bytes,
    write_secret_json_file,
)

STORE_VERSION = 1
MANIFEST_FILENAME = "manifest.json"
PROFILE_IMAGE_FILENAME = "profile_image.json"
PROFILE_UPP_FILENAME = "profile.upp.der"


def load_profiles_from_store(store_path: str) -> list[SimProfileEntry]:
    """Load all profile JSON files from the store directory into ``state.profiles``."""
    root_path = _ensure_store_root(store_path)
    if len(root_path) == 0:
        return []
    loaded: list[tuple[int, str, SimProfileEntry]] = []
    for child_name in sorted(os.listdir(root_path)):
        child_path = os.path.join(root_path, child_name)
        if os.path.isdir(child_path) is False:
            continue
        loaded_entry = _load_profile_directory(child_path)
        if loaded_entry is None:
            continue
        order_index, entry = loaded_entry
        loaded.append((order_index, child_name, entry))
    loaded.sort(key=lambda item: (item[0], item[1]))
    return [entry for _, _, entry in loaded]


def sync_profiles_to_store(store_path: str, profiles: list[SimProfileEntry]) -> None:
    """Persist the current ``state.profiles`` list back to the store directory as JSON files."""
    root_path = _ensure_store_root(store_path)
    if len(root_path) == 0:
        return
    desired_directories: set[str] = set()
    for order_index, profile in enumerate(profiles):
        directory_name = _profile_directory_name(profile)
        desired_directories.add(directory_name)
        directory_path = os.path.join(root_path, directory_name)
        os.makedirs(directory_path, exist_ok=True)
        _write_json_file(
            os.path.join(directory_path, MANIFEST_FILENAME),
            _serialize_profile_manifest(profile, order_index=order_index),
        )
        if profile.profile_image is not None:
            _write_json_file(
                os.path.join(directory_path, PROFILE_IMAGE_FILENAME),
                _serialize_profile_image(profile.profile_image),
            )
        else:
            _delete_if_exists(os.path.join(directory_path, PROFILE_IMAGE_FILENAME))
        if len(bytes(profile.upp_bytes or b"")) > 0:
            write_secret_file_bytes(
                os.path.join(directory_path, PROFILE_UPP_FILENAME),
                bytes(profile.upp_bytes),
            )
        else:
            _delete_if_exists(os.path.join(directory_path, PROFILE_UPP_FILENAME))

    for child_name in os.listdir(root_path):
        child_path = os.path.join(root_path, child_name)
        if os.path.isdir(child_path) is False:
            continue
        if child_name in desired_directories:
            continue
        shutil.rmtree(child_path, ignore_errors=True)


def load_profile_image_json_file(path: str) -> SimProfileImage | None:
    return _load_profile_image_from_json(
        os.path.abspath(os.path.expanduser(str(path or "").strip())),
        protect_plaintext_on_read=False,
    )


def profile_store_has_entries(store_path: str) -> bool:
    """Return True when the profile store directory contains at least one profile entry."""
    root_path = _ensure_store_root(store_path)
    if len(root_path) == 0:
        return False
    for child_name in os.listdir(root_path):
        child_path = os.path.join(root_path, child_name)
        if os.path.isdir(child_path) is False:
            continue
        if any(
            os.path.exists(os.path.join(child_path, filename))
            for filename in (MANIFEST_FILENAME, PROFILE_IMAGE_FILENAME, PROFILE_UPP_FILENAME)
        ):
            return True
    return False


def _load_profile_directory(directory_path: str) -> tuple[int, SimProfileEntry] | None:
    manifest_path = os.path.join(directory_path, MANIFEST_FILENAME)
    manifest = _read_json_file(manifest_path, protect_plaintext_on_read=True)
    if isinstance(manifest, dict) is False:
        return None

    aid = str(manifest.get("aid", "")).strip().upper()
    iccid = str(manifest.get("iccid", "")).strip()
    if len(aid) == 0 or len(iccid) == 0:
        return None

    profile_name = str(manifest.get("profile_name", "")).strip()
    profile_image = _load_profile_image(
        directory_path=directory_path,
        source_preference=str(manifest.get("profile_source", "")).strip().lower(),
        default_iccid=iccid,
        default_name=profile_name,
        default_imsi=str(manifest.get("imsi", "")).strip(),
        default_impi=str(manifest.get("impi", "")).strip(),
    )
    upp_path = os.path.join(directory_path, PROFILE_UPP_FILENAME)
    upp_bytes = b""
    if os.path.isfile(upp_path):
        try:
            upp_bytes = read_secret_file_bytes(upp_path, protect_plaintext_on_read=True)
        except OSError:
            upp_bytes = b""

    imsi = str(manifest.get("imsi", "")).strip()
    impi = str(manifest.get("impi", "")).strip()
    if profile_image is not None:
        if len(str(profile_image.iccid or "").strip()) > 0:
            iccid = str(profile_image.iccid).strip()
        if len(str(profile_image.imsi or "").strip()) > 0:
            imsi = str(profile_image.imsi).strip()
        if len(str(profile_image.impi or "").strip()) > 0:
            impi = str(profile_image.impi).strip()
        if len(str(profile_image.profile_name or "").strip()) > 0:
            profile_name = str(profile_image.profile_name).strip()

    manifest_auth_config = _deserialize_profile_auth(manifest.get("auth"))
    if manifest_auth_config is None and profile_image is not None:
        image_auth_config = getattr(profile_image, "auth_config", None)
        if image_auth_config is not None:
            manifest_auth_config = image_auth_config

    entry = SimProfileEntry(
        aid=aid,
        iccid=iccid,
        state=str(manifest.get("state", "disabled")).strip().lower() or "disabled",
        profile_class=str(manifest.get("profile_class", "operational")).strip().lower() or "operational",
        nickname=str(manifest.get("nickname", "")).strip(),
        service_provider=str(manifest.get("service_provider", "")).strip(),
        profile_name=profile_name,
        imsi=imsi,
        impi=impi,
        notification_address=str(manifest.get("notification_address", "")).strip(),
        upp_bytes=upp_bytes,
        profile_image=profile_image,
        profile_source=_normalize_profile_source(
            manifest.get("profile_source"),
            has_upp=len(upp_bytes) > 0,
        ),
        auth_config=manifest_auth_config,
        fallback_attribute=bool(manifest.get("fallback_attribute", False)),
        rollback_armed=bool(manifest.get("rollback_armed", False)),
        ecall_indication=bool(manifest.get("ecall_indication", False)),
        connectivity_params_http=_coerce_hex_bytes(manifest.get("connectivity_params_http_hex", "")),
    )
    order_index = int(manifest.get("order_index", 0) or 0)
    return order_index, entry


def _load_profile_image(
    *,
    directory_path: str,
    source_preference: str,
    default_iccid: str,
    default_name: str,
    default_imsi: str,
    default_impi: str,
) -> SimProfileImage | None:
    # The JSON image is the canonical cached view written by
    # ``sync_profiles_to_store`` at install time. Re-decoding the raw UPP on
    # every startup is both wasteful and dangerous: the pySim SAIP ASN.1
    # decoder can loop unboundedly on pathological ``ProfileElement``
    # payloads (observed with the ``B2`` telecom section on some live
    # profiles). Even with the bounded decode helper in ``saip_profile`` the
    # worker threads that hit the deadline keep holding references and leak
    # several GB of RAM across repeated tool launches. Trust the JSON cache
    # first and only fall back to the UPP if the JSON side-file is missing
    # or unreadable; the ``source_preference`` hint is kept purely for
    # forensics/debugging (it used to drive the priority).
    _ = source_preference  # retained for backwards-compat manifests; no longer drives ordering
    image_path = os.path.join(directory_path, PROFILE_IMAGE_FILENAME)
    upp_path = os.path.join(directory_path, PROFILE_UPP_FILENAME)

    cached_image = _load_profile_image_from_json(
        image_path,
        protect_plaintext_on_read=True,
    )
    if cached_image is not None:
        return cached_image
    return _load_profile_image_from_upp(
        upp_path,
        default_iccid=default_iccid,
        default_name=default_name,
        default_imsi=default_imsi,
        default_impi=default_impi,
    )


def _load_profile_image_from_upp(
    upp_path: str,
    *,
    default_iccid: str,
    default_name: str,
    default_imsi: str,
    default_impi: str,
) -> SimProfileImage | None:
    if os.path.isfile(upp_path) is False:
        return None
    try:
        upp_bytes = read_secret_file_bytes(upp_path, protect_plaintext_on_read=True)
    except OSError:
        return None
    return decode_profile_image(
        upp_bytes,
        default_iccid=default_iccid,
        default_name=default_name,
        default_imsi=default_imsi,
        default_impi=default_impi,
    )


def _load_profile_image_from_json(
    image_path: str,
    *,
    protect_plaintext_on_read: bool = False,
) -> SimProfileImage | None:
    image_data = _read_json_file(
        image_path,
        protect_plaintext_on_read=protect_plaintext_on_read,
    )
    if isinstance(image_data, dict) is False:
        return None
    nodes: list[SimProfileFsNode] = []
    for node_data in image_data.get("nodes", []):
        if isinstance(node_data, dict) is False:
            continue
        raw_path = node_data.get("path", [])
        path_items = []
        if isinstance(raw_path, str):
            path_items = [part for part in raw_path.split("/") if len(part) > 0]
        elif isinstance(raw_path, list):
            path_items = [str(item) for item in raw_path if len(str(item)) > 0]
        if len(path_items) == 0:
            continue
        nodes.append(
            SimProfileFsNode(
                path=tuple(path_items),
                name=str(node_data.get("name", path_items[-1])).strip() or path_items[-1],
                kind=str(node_data.get("kind", "ef")).strip() or "ef",
                fid=str(node_data.get("fid", "")).strip().upper(),
                aid=str(node_data.get("aid", "")).strip().upper(),
                label=str(node_data.get("label", "")).strip(),
                structure=str(node_data.get("structure", "transparent")).strip() or "transparent",
                data=_coerce_hex_bytes(node_data.get("data_hex", "")),
                records=[_coerce_hex_bytes(item) for item in node_data.get("records_hex", []) if item is not None],
                sfi=_coerce_optional_int(node_data.get("sfi")),
                write_acl=str(node_data.get("write_acl", "always") or "always").strip().lower() or "always",
                lifecycle_state=_coerce_lifecycle_state(node_data.get("lifecycle_state")),
                link_path=_coerce_link_path(node_data.get("link_path")),
            )
        )
    return SimProfileImage(
        profile_name=str(image_data.get("profile_name", "")).strip(),
        iccid=str(image_data.get("iccid", "")).strip(),
        imsi=str(image_data.get("imsi", "")).strip(),
        impi=str(image_data.get("impi", "")).strip(),
        nodes=nodes,
        auth_config=_deserialize_profile_auth(image_data.get("auth")),
        connectivity_params_http=_coerce_hex_bytes(image_data.get("connectivity_params_http_hex", "")),
        pin_codes=_deserialize_pin_codes(image_data.get("pin_codes")),
        puk_codes=_deserialize_puk_codes(image_data.get("puk_codes")),
        security_domains=_deserialize_security_domains(image_data.get("security_domains")),
        rfm_instances=_deserialize_rfm_instances(image_data.get("rfm_instances")),
    )


def _serialize_profile_manifest(profile: SimProfileEntry, *, order_index: int) -> dict[str, Any]:
    return {
        "store_version": STORE_VERSION,
        "order_index": int(order_index),
        "aid": str(profile.aid).strip().upper(),
        "iccid": str(profile.iccid).strip(),
        "state": str(profile.state).strip().lower(),
        "profile_class": str(profile.profile_class).strip().lower(),
        "nickname": str(profile.nickname).strip(),
        "service_provider": str(profile.service_provider).strip(),
        "profile_name": str(profile.profile_name).strip(),
        "imsi": str(profile.imsi).strip(),
        "impi": str(profile.impi).strip(),
        "notification_address": str(profile.notification_address).strip(),
        "profile_source": _normalize_profile_source(profile.profile_source, has_upp=len(bytes(profile.upp_bytes or b"")) > 0),
        "auth": _serialize_profile_auth(profile.auth_config),
        "fallback_attribute": bool(profile.fallback_attribute),
        "rollback_armed": bool(profile.rollback_armed),
        "ecall_indication": bool(profile.ecall_indication),
        "connectivity_params_http_hex": bytes(profile.connectivity_params_http or b"").hex().upper(),
    }


def _serialize_profile_image(image: SimProfileImage) -> dict[str, Any]:
    return {
        "profile_name": str(image.profile_name).strip(),
        "iccid": str(image.iccid).strip(),
        "imsi": str(image.imsi).strip(),
        "impi": str(image.impi).strip(),
        "auth": _serialize_profile_auth(image.auth_config),
        "connectivity_params_http_hex": bytes(image.connectivity_params_http or b"").hex().upper(),
        "pin_codes": _serialize_pin_codes(image.pin_codes),
        "puk_codes": _serialize_puk_codes(image.puk_codes),
        "security_domains": _serialize_security_domains(image.security_domains),
        "rfm_instances": _serialize_rfm_instances(image.rfm_instances),
        "nodes": [
            {
                "path": list(node.path),
                "name": str(node.name).strip(),
                "kind": str(node.kind).strip(),
                "fid": str(node.fid).strip().upper(),
                "aid": str(node.aid).strip().upper(),
                "label": str(node.label).strip(),
                "structure": str(node.structure).strip(),
                "data_hex": bytes(node.data or b"").hex().upper(),
                "records_hex": [bytes(record or b"").hex().upper() for record in node.records],
                "sfi": node.sfi,
                "write_acl": str(getattr(node, "write_acl", "always") or "always").strip().lower() or "always",
                "lifecycle_state": int(getattr(node, "lifecycle_state", 0x05) or 0x05) & 0xFF,
                "link_path": list(getattr(node, "link_path", ()) or ()),
            }
            for node in image.nodes
        ],
    }


def _profile_directory_name(profile: SimProfileEntry) -> str:
    if len(str(profile.aid or "").strip()) > 0:
        identifier = "AID_" + str(profile.aid).strip().upper()
    else:
        identifier = "ICCID_" + str(profile.iccid).strip()
    safe_parts = []
    for character in identifier:
        if character.isalnum() or character in ("_", "-", "."):
            safe_parts.append(character)
        else:
            safe_parts.append("_")
    return "".join(safe_parts)


def _normalize_profile_source(value: Any, *, has_upp: bool) -> str:
    text = str(value or "").strip().lower()
    if text in ("json", "upp"):
        return text
    if has_upp:
        return "upp"
    return "json"


def _ensure_store_root(store_path: str) -> str:
    raw_text = str(store_path or "").strip()
    if len(raw_text) == 0:
        return ""
    normalized = os.path.abspath(os.path.expanduser(raw_text))
    os.makedirs(normalized, exist_ok=True)
    return normalized


def _read_json_file(path: str, *, protect_plaintext_on_read: bool = False) -> Any:
    return read_secret_json_file(
        path,
        protect_plaintext_on_read=protect_plaintext_on_read,
    )


def _write_json_file(path: str, value: Any) -> None:
    write_secret_json_file(path, value)


def _delete_if_exists(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        return


def _coerce_hex_bytes(value: Any) -> bytes:
    text = str(value or "").strip().replace(" ", "").replace(":", "").replace("-", "")
    if len(text) == 0:
        return b""
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    if len(text) % 2 != 0:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def _coerce_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_link_path(value: Any) -> tuple[str, ...]:
    """Decode the persisted ``link_path`` field back to a tuple of
    upper-case hex FIDs.

    Manifests written before this field existed (everything pre-link-
    path) emit ``None`` / missing here; map that to the empty tuple
    so the deserialised node behaves like an independent EF (no link
    target). Lists of arbitrary scalars are coerced to canonical
    upper-case 2-byte hex; anything that cannot be normalised is
    dropped silently rather than aborting the whole image load.
    """
    if value is None:
        return tuple()
    if isinstance(value, (list, tuple)) is False:
        return tuple()
    fids: list[str] = []
    for item in value:
        token = str(item or "").strip().upper()
        if len(token) == 4 and all(c in "0123456789ABCDEF" for c in token):
            fids.append(token)
    return tuple(fids)


def _coerce_lifecycle_state(value: Any) -> int:
    """Best-effort decode of the persisted ``lifecycle_state`` byte.

    Manifests written before gap-5 didn't carry the field; default to
    0x05 (operational-activated) so a reload reproduces the old
    behaviour. Recognised values are 0x04 (deactivated), 0x05
    (activated), and 0x0C (terminated -- set by TERMINATE EF /
    TERMINATE DF). Anything else clamps back to 0x05 because the
    simulator never deliberately produces the other §11.1.1.4.9
    values.
    """
    if value is None:
        return 0x05
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        return 0x05
    if coerced & 0xFF in (0x04, 0x05, 0x0C):
        return coerced & 0xFF
    return 0x05


def _serialize_profile_auth(config: SimProfileAuthConfig | None) -> dict[str, Any] | None:
    if config is None:
        return None
    return {
        "algorithm": str(config.algorithm or "").strip().lower(),
        "ki_hex": bytes(config.ki or b"").hex().upper(),
        "opc_hex": bytes(config.opc or b"").hex().upper(),
        "op_hex": bytes(config.op or b"").hex().upper(),
        "amf_hex": bytes(config.amf or b"").hex().upper(),
        "sqn_hex": bytes(config.sqn or b"").hex().upper(),
        "number_of_keccak": int(getattr(config, "number_of_keccak", 1) or 1),
        "auth_counter_max_hex": bytes(getattr(config, "auth_counter_max", b"") or b"").hex().upper(),
    }


def _deserialize_profile_auth(value: Any) -> SimProfileAuthConfig | None:
    if isinstance(value, dict) is False:
        return None
    config = SimProfileAuthConfig()
    algorithm = str(value.get("algorithm", config.algorithm)).strip().lower()
    if len(algorithm) > 0:
        config.algorithm = algorithm
    for field_name, key_name in (
        ("ki", "ki_hex"),
        ("opc", "opc_hex"),
        ("op", "op_hex"),
        ("amf", "amf_hex"),
        ("sqn", "sqn_hex"),
        ("auth_counter_max", "auth_counter_max_hex"),
    ):
        if key_name not in value:
            continue
        setattr(config, field_name, _coerce_hex_bytes(value.get(key_name)))
    number_of_keccak_raw = value.get("number_of_keccak")
    if number_of_keccak_raw is not None:
        try:
            keccak_value = int(number_of_keccak_raw)
        except (TypeError, ValueError):
            keccak_value = 1
        # TS 35.231 Annex A bounds numberOfKeccak to [1, 255].
        keccak_value = max(1, min(0xFF, keccak_value))
        config.number_of_keccak = keccak_value
    return config


def _serialize_pin_codes(entries: list[SimProfilePinEntry]) -> list[dict[str, Any]]:
    serialised: list[dict[str, Any]] = []
    for entry in entries or []:
        serialised.append(
            {
                "key_reference": int(entry.key_reference) & 0xFF,
                "value_hex": bytes(entry.value or b"").hex().upper(),
                "unblock_reference": int(entry.unblock_reference) & 0xFF,
                "attributes": int(entry.attributes) & 0xFF,
                "max_attempts": int(entry.max_attempts) & 0x0F,
                "retries_remaining": int(entry.retries_remaining) & 0x0F,
            }
        )
    return serialised


def _deserialize_pin_codes(value: Any) -> list[SimProfilePinEntry]:
    decoded: list[SimProfilePinEntry] = []
    if isinstance(value, list) is False:
        return decoded
    for item in value:
        if isinstance(item, dict) is False:
            continue
        decoded.append(
            SimProfilePinEntry(
                key_reference=int(item.get("key_reference", 0) or 0) & 0xFF,
                value=_coerce_hex_bytes(item.get("value_hex", "")),
                unblock_reference=int(item.get("unblock_reference", 0) or 0) & 0xFF,
                attributes=int(item.get("attributes", 0) or 0) & 0xFF,
                max_attempts=int(item.get("max_attempts", 3) or 3) & 0x0F,
                retries_remaining=int(item.get("retries_remaining", 3) or 3) & 0x0F,
            )
        )
    return decoded


def _serialize_puk_codes(entries: list[SimProfilePukEntry]) -> list[dict[str, Any]]:
    serialised: list[dict[str, Any]] = []
    for entry in entries or []:
        serialised.append(
            {
                "key_reference": int(entry.key_reference) & 0xFF,
                "value_hex": bytes(entry.value or b"").hex().upper(),
                "max_attempts": int(entry.max_attempts) & 0xFF,
                "retries_remaining": int(entry.retries_remaining) & 0xFF,
            }
        )
    return serialised


def _deserialize_puk_codes(value: Any) -> list[SimProfilePukEntry]:
    decoded: list[SimProfilePukEntry] = []
    if isinstance(value, list) is False:
        return decoded
    for item in value:
        if isinstance(item, dict) is False:
            continue
        decoded.append(
            SimProfilePukEntry(
                key_reference=int(item.get("key_reference", 0) or 0) & 0xFF,
                value=_coerce_hex_bytes(item.get("value_hex", "")),
                max_attempts=int(item.get("max_attempts", 10) or 10) & 0xFF,
                retries_remaining=int(item.get("retries_remaining", 10) or 10) & 0xFF,
            )
        )
    return decoded


def _serialize_security_domains(entries: list[SimProfileSecurityDomain]) -> list[dict[str, Any]]:
    serialised: list[dict[str, Any]] = []
    for entry in entries or []:
        serialised.append(
            {
                "instance_aid": str(entry.instance_aid or "").strip().upper(),
                "class_aid": str(entry.class_aid or "").strip().upper(),
                "load_package_aid": str(entry.load_package_aid or "").strip().upper(),
                "privileges_hex": bytes(entry.privileges or b"").hex().upper(),
                "lifecycle_state": int(entry.lifecycle_state) & 0xFF,
                "install_parameters_hex": bytes(entry.install_parameters or b"").hex().upper(),
                "uicc_toolkit_parameters_hex": bytes(entry.uicc_toolkit_parameters or b"").hex().upper(),
                "keys": [
                    {
                        "usage_qualifier": int(k.usage_qualifier) & 0xFF,
                        "key_identifier": int(k.key_identifier) & 0xFF,
                        "key_version": int(k.key_version) & 0xFF,
                        "key_type": int(k.key_type) & 0xFF,
                        "key_data_hex": bytes(k.key_data or b"").hex().upper(),
                        "mac_length": int(k.mac_length) & 0xFF,
                        "counter_hex": bytes(k.counter or b"").hex().upper(),
                        "access": int(k.access) & 0xFF,
                    }
                    for k in entry.keys
                ],
                "perso_data_hex": [bytes(payload or b"").hex().upper() for payload in entry.perso_data],
            }
        )
    return serialised


def _deserialize_security_domains(value: Any) -> list[SimProfileSecurityDomain]:
    decoded: list[SimProfileSecurityDomain] = []
    if isinstance(value, list) is False:
        return decoded
    for item in value:
        if isinstance(item, dict) is False:
            continue
        keys: list[SimProfileSecurityDomainKey] = []
        for key_item in item.get("keys", []) or []:
            if isinstance(key_item, dict) is False:
                continue
            keys.append(
                SimProfileSecurityDomainKey(
                    usage_qualifier=int(key_item.get("usage_qualifier", 0) or 0) & 0xFF,
                    key_identifier=int(key_item.get("key_identifier", 0) or 0) & 0xFF,
                    key_version=int(key_item.get("key_version", 0) or 0) & 0xFF,
                    key_type=int(key_item.get("key_type", 0) or 0) & 0xFF,
                    key_data=_coerce_hex_bytes(key_item.get("key_data_hex", "")),
                    mac_length=int(key_item.get("mac_length", 8) or 8) & 0xFF,
                    counter=_coerce_hex_bytes(key_item.get("counter_hex", "")),
                    access=int(key_item.get("access", 0) or 0) & 0xFF,
                )
            )
        perso_data: list[bytes] = []
        for perso_item in item.get("perso_data_hex", []) or []:
            if perso_item is None:
                continue
            perso_data.append(_coerce_hex_bytes(perso_item))
        decoded.append(
            SimProfileSecurityDomain(
                instance_aid=str(item.get("instance_aid", "") or "").strip().upper(),
                class_aid=str(item.get("class_aid", "") or "").strip().upper(),
                load_package_aid=str(item.get("load_package_aid", "") or "").strip().upper(),
                privileges=_coerce_hex_bytes(item.get("privileges_hex", "")),
                lifecycle_state=int(item.get("lifecycle_state", 0x07) or 0x07) & 0xFF,
                install_parameters=_coerce_hex_bytes(item.get("install_parameters_hex", "")),
                uicc_toolkit_parameters=_coerce_hex_bytes(item.get("uicc_toolkit_parameters_hex", "")),
                keys=keys,
                perso_data=perso_data,
            )
        )
    return decoded


def _serialize_rfm_instances(entries: list[SimProfileRfmInstance]) -> list[dict[str, Any]]:
    serialised: list[dict[str, Any]] = []
    for entry in entries or []:
        serialised.append(
            {
                "instance_aid": str(entry.instance_aid or "").strip().upper(),
                "tar_list_hex": [bytes(tar or b"").hex().upper() for tar in entry.tar_list],
                "minimum_security_level": int(entry.minimum_security_level) & 0xFF,
                "uicc_access_domain_hex": bytes(entry.uicc_access_domain or b"").hex().upper(),
                "uicc_admin_access_domain_hex": bytes(entry.uicc_admin_access_domain or b"").hex().upper(),
                "adf_aid": str(entry.adf_aid or "").strip().upper(),
                "adf_access_domain_hex": bytes(entry.adf_access_domain or b"").hex().upper(),
                "adf_admin_access_domain_hex": bytes(entry.adf_admin_access_domain or b"").hex().upper(),
            }
        )
    return serialised


def _deserialize_rfm_instances(value: Any) -> list[SimProfileRfmInstance]:
    decoded: list[SimProfileRfmInstance] = []
    if isinstance(value, list) is False:
        return decoded
    for item in value:
        if isinstance(item, dict) is False:
            continue
        tar_list: list[bytes] = []
        for tar in item.get("tar_list_hex", []) or []:
            if tar is None:
                continue
            tar_list.append(_coerce_hex_bytes(tar))
        decoded.append(
            SimProfileRfmInstance(
                instance_aid=str(item.get("instance_aid", "") or "").strip().upper(),
                tar_list=tar_list,
                minimum_security_level=int(item.get("minimum_security_level", 0) or 0) & 0xFF,
                uicc_access_domain=_coerce_hex_bytes(item.get("uicc_access_domain_hex", "")),
                uicc_admin_access_domain=_coerce_hex_bytes(item.get("uicc_admin_access_domain_hex", "")),
                adf_aid=str(item.get("adf_aid", "") or "").strip().upper(),
                adf_access_domain=_coerce_hex_bytes(item.get("adf_access_domain_hex", "")),
                adf_admin_access_domain=_coerce_hex_bytes(item.get("adf_admin_access_domain_hex", "")),
            )
        )
    return decoded
