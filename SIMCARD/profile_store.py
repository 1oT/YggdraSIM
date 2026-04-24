from __future__ import annotations

import os
import shutil
from typing import Any

from SIMCARD.saip_profile import decode_profile_image
from SIMCARD.state import SimProfileAuthConfig, SimProfileEntry, SimProfileFsNode, SimProfileImage
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
            )
        )
    return SimProfileImage(
        profile_name=str(image_data.get("profile_name", "")).strip(),
        iccid=str(image_data.get("iccid", "")).strip(),
        imsi=str(image_data.get("imsi", "")).strip(),
        impi=str(image_data.get("impi", "")).strip(),
        nodes=nodes,
        auth_config=_deserialize_profile_auth(image_data.get("auth")),
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
    }


def _serialize_profile_image(image: SimProfileImage) -> dict[str, Any]:
    return {
        "profile_name": str(image.profile_name).strip(),
        "iccid": str(image.iccid).strip(),
        "imsi": str(image.imsi).strip(),
        "impi": str(image.impi).strip(),
        "auth": _serialize_profile_auth(image.auth_config),
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
