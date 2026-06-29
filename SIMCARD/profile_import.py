# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Profile import pipeline: DER→pySim decode, ES8+ command sequence execution, and rollback on failure."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from SIMCARD.etsi_fs import build_default_state, next_generated_profile_aid
from SIMCARD.profile_store import (
    load_profile_image_json_file,
    load_profiles_from_store,
    profile_store_has_entries,
    sync_profiles_to_store,
)
from SIMCARD.saip_profile import decode_profile_image, _get_saip_asn1
from SIMCARD.state import SimProfileEntry, SimProfileFsNode, SimProfileImage
from SIMCARD.utils import encode_iccid_ef


@dataclass
class ProfileImportResult:
    aid: str
    iccid: str
    profile_name: str
    profile_source: str
    enabled: bool
    store_path: str
    artifact_path: str


def import_profile_artifact(
    artifact_path: str,
    profile_store_path: str,
    *,
    enable: bool = False,
    service_provider: str = "",
    profile_class: str = "operational",
    nickname: str = "",
) -> ProfileImportResult:
    """Import a SAIP profile artifact (bound profile package or decoded JSON) into the card engine."""
    store_path = str(profile_store_path or "").strip()
    if len(store_path) == 0:
        raise ValueError("Simulator profile store path is not configured.")

    source_path = Path(artifact_path).expanduser().resolve()
    if source_path.is_file() is False:
        raise FileNotFoundError(f"Profile artifact not found: {source_path}")

    if profile_store_has_entries(store_path):
        profiles = load_profiles_from_store(store_path)
    else:
        profiles = build_default_state().profiles

    profile_name_fallback = source_path.stem.replace("_", " ").replace("-", " ").strip()
    source_kind, profile_image, upp_bytes = _load_profile_from_source(
        source_path,
        default_name=profile_name_fallback,
    )

    iccid = str(profile_image.iccid or "").strip()
    if len(iccid) == 0:
        iccid = _next_generated_iccid(profiles)
    while any(current.iccid == iccid for current in profiles):
        iccid = _next_generated_iccid(profiles, seed=iccid)
    profile_image.iccid = iccid
    _upsert_profile_image_iccid(profile_image, iccid)

    aid = _next_generated_profile_aid(profiles)
    profile_name = str(profile_image.profile_name or "").strip() or profile_name_fallback or f"Imported {iccid[-4:]}"
    profile_image.profile_name = profile_name
    imported_profile = SimProfileEntry(
        aid=aid,
        iccid=iccid,
        state="enabled" if enable else "disabled",
        profile_class=str(profile_class or "operational").strip().lower() or "operational",
        nickname=str(nickname or "").strip() or profile_name,
        service_provider=str(service_provider or "").strip() or "Imported SAIP",
        profile_name=profile_name,
        imsi=str(profile_image.imsi or "").strip(),
        impi=str(profile_image.impi or "").strip(),
        notification_address="rsp.example.com",
        upp_bytes=upp_bytes,
        profile_image=profile_image,
        profile_source="json" if source_kind == "json" else "upp",
        # SAIP profileHeader.connectivityParameters seeds SGP.32 §5.9.24
        # GetConnectivityParameters; the bytes flow straight through.
        connectivity_params_http=bytes(profile_image.connectivity_params_http or b""),
    )

    if enable:
        for current in profiles:
            current.state = "disabled"
    profiles.append(imported_profile)
    sync_profiles_to_store(store_path, profiles)
    return ProfileImportResult(
        aid=aid,
        iccid=iccid,
        profile_name=profile_name,
        profile_source=imported_profile.profile_source,
        enabled=enable,
        store_path=store_path,
        artifact_path=str(source_path),
    )


def _load_profile_from_source(
    source_path: Path,
    *,
    default_name: str,
) -> tuple[str, SimProfileImage, bytes]:
    source_kind = _detect_source_kind(source_path)
    if source_kind == "sim_json":
        profile_image = load_profile_image_json_file(str(source_path))
        if profile_image is None:
            raise ValueError(f"Could not decode simulator profile JSON: {source_path}")
        return "json", profile_image, b""

    if source_kind == "saip_json":
        upp_bytes = _encode_upp_from_tagged_json(source_path)
        profile_image = decode_profile_image(upp_bytes, default_name=default_name)
        if profile_image is None:
            raise ValueError(f"Could not decode SAIP JSON as profile artifact: {source_path}")
        return "upp", profile_image, upp_bytes

    if source_kind == "hex_upp":
        upp_bytes = _decode_hex_text_upp(source_path)
    else:
        try:
            upp_bytes = source_path.read_bytes()
        except OSError as error:
            raise FileNotFoundError(str(error)) from error
    profile_image = decode_profile_image(upp_bytes, default_name=default_name)
    if profile_image is None:
        raise ValueError(f"Could not decode SAIP/ASN.1 profile artifact: {source_path}")
    return "upp", profile_image, upp_bytes


def _detect_source_kind(source_path: Path) -> str:
    json_payload = _read_json_object(source_path)
    if isinstance(json_payload, dict):
        if _looks_like_sim_profile_image_json(json_payload):
            return "sim_json"
        if _looks_like_saip_tagged_json(json_payload):
            return "saip_json"
        raise ValueError(
            f"Unsupported JSON profile input: {source_path}. Expected simulator profile_image JSON "
            "or tagged SAIP JSON with a top-level 'sections' object."
        )
    if _looks_like_hex_text_file(source_path):
        return "hex_upp"
    return "upp"


def _read_json_object(source_path: Path) -> dict | None:
    try:
        text = source_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    except OSError as error:
        raise FileNotFoundError(str(error)) from error
    stripped = text.lstrip()
    if len(stripped) == 0 or stripped[0] not in "{[":
        return None
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(loaded, dict):
        return loaded
    raise ValueError(f"JSON profile input root must be an object: {source_path}")


def _looks_like_sim_profile_image_json(payload: dict) -> bool:
    return isinstance(payload.get("nodes"), list)


def _looks_like_saip_tagged_json(payload: dict) -> bool:
    return isinstance(payload.get("sections"), dict)


def _looks_like_hex_text_file(source_path: Path) -> bool:
    try:
        text = source_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    except OSError as error:
        raise FileNotFoundError(str(error)) from error
    stripped = "".join(str(text or "").split())
    if len(stripped) == 0:
        return False
    for character in stripped:
        if character not in "0123456789abcdefABCDEF":
            return False
    return len(stripped) % 2 == 0


def _decode_hex_text_upp(source_path: Path) -> bytes:
    try:
        text = source_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"Hex profile input is not valid UTF-8 text: {source_path}") from error
    except OSError as error:
        raise FileNotFoundError(str(error)) from error
    normalized_hex = "".join(str(text or "").split())
    if len(normalized_hex) == 0:
        raise ValueError(f"Hex profile input is empty: {source_path}")
    try:
        return bytes.fromhex(normalized_hex)
    except ValueError as error:
        raise ValueError(
            f"Text profile input is not valid hex DER: {source_path}. Supported textual formats are "
            "hex-encoded DER or tagged SAIP JSON."
        ) from error


def _encode_upp_from_tagged_json(source_path: Path) -> bytes:
    from Tools.ProfilePackage.saip_json_codec import parse_editor_json

    try:
        text = source_path.read_text(encoding="utf-8")
    except OSError as error:
        raise FileNotFoundError(str(error)) from error
    try:
        document = parse_editor_json(text)
    except Exception as error:
        detail = str(error).strip() or error.__class__.__name__
        raise ValueError(f"Could not parse tagged SAIP JSON: {source_path}: {detail}") from error
    asn1 = _get_saip_asn1()
    if asn1 is None:
        raise ValueError(
            "SAIP ASN.1 schema is unavailable. Tagged SAIP JSON import needs the bundled SAIP ASN.1 support."
        )
    sections = document.get("sections", {})
    if isinstance(sections, dict) is False:
        raise ValueError("Tagged SAIP JSON document did not contain a 'sections' object.")
    encoded_parts: list[bytes] = []
    try:
        for section_key, decoded in sections.items():
            pe_type = _base_profile_element_type(str(section_key))
            if len(pe_type) == 0:
                raise ValueError(f"Invalid profile element key: {section_key!r}")
            encoded_parts.append(asn1.encode("ProfileElement", (pe_type, decoded)))
    except Exception as error:
        detail = str(error).strip() or error.__class__.__name__
        raise ValueError(f"Could not encode tagged SAIP JSON to DER: {source_path}: {detail}") from error
    return b"".join(encoded_parts)


def _base_profile_element_type(section_key: str) -> str:
    cleaned = str(section_key or "").strip()
    if len(cleaned) == 0:
        return ""
    base_key, separator, suffix = cleaned.rpartition("_")
    if separator == "_" and suffix.isdigit():
        return base_key
    return cleaned


def _next_generated_profile_aid(profiles: list[SimProfileEntry]) -> str:
    return next_generated_profile_aid(profiles)


def _next_generated_iccid(profiles: list[SimProfileEntry], seed: str = "") -> str:
    used = {profile.iccid for profile in profiles}
    suffix = len(profiles) + 11
    if len(seed) > 0 and seed[-2:].isdigit():
        suffix = int(seed[-2:]) + 1
    while True:
        candidate = f"898811111111111111{suffix:02d}"
        if candidate not in used:
            return candidate
        suffix += 1


def _upsert_profile_image_iccid(profile_image: SimProfileImage, iccid: str) -> None:
    for node in profile_image.nodes:
        if tuple(node.path) == ("MF", "EF.ICCID"):
            node.data = encode_iccid_ef(iccid)
            node.records = []
            return
    profile_image.nodes.append(
        SimProfileFsNode(
            path=("MF", "EF.ICCID"),
            name="EF.ICCID",
            kind="ef",
            fid="2FE2",
            structure="transparent",
            data=encode_iccid_ef(iccid),
            sfi=0x02,
        )
    )
