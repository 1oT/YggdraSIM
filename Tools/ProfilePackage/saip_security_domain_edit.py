# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP ``PE-SecurityDomain`` structured edit helpers.

The PE-SecurityDomain element (TCA SAIP §A.2 / GP Card Spec v2.3.1
§11.4) is one of the most edit-heavy PEs in any profile: operators
routinely need to provision new SCP03 / SCP02 key sets, rotate
existing keys, drop compromised key sets, and append issuer-personalised
STORE DATA blocks. The decoded-edit panel renders these as nested
arrays which the generic JSON editor cannot grow safely (it can only
mutate existing rows). This module provides the spec-aware list-mutating
primitives that the GUI / TUI dispatchers wire up.

Decoded shape post ``build_decoded_document_from_sequence``::

    {
      "sd-Header": {...},
      "instance": {
        "instanceAID": <bytes>,
        "classAID": <bytes>,
        "applicationLoadPackageAID": <bytes>,
        "applicationPrivileges": <bytes>,
        "lifeCycleState": <bytes len=1>,
        "applicationSpecificParametersC9": <bytes>,
        "applicationParameters": {...},  # optional
      },
      "keyList": [KeyObject, ...]  # optional
      "sdPersoData": [<bytes>, ...] # optional
    }

Every mutator returns a short summary string the GUI surfaces as a
toast. Callers are responsible for re-encoding the sequence and
flagging the session dirty.
"""

from __future__ import annotations

import re
from typing import Any


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


# GP Card Spec v2.3.1 §11.1.9 KeyUsageQualifier bits b1..b8.
# Documented for the GUI to surface meaningful labels; the encoder
# itself accepts any 1..2 byte OCTET STRING so the GUI is free to mix
# bits per issuer policy.
KEY_USAGE_QUALIFIER_BITS: dict[int, str] = {
    0x01: "VERIFY (MAC verification)",
    0x02: "COMPUTE (MAC computation)",
    0x04: "ENC (encryption)",
    0x08: "DEC (decryption)",
    0x10: "SENSITIVE (key is sensitive)",
    0x20: "RFU",
    0x40: "RFU",
    0x80: "RFU",
}


# GP Card Spec v2.3.1 §11.1.8 KeyType byte values, see also Amendment D §7.5.
KEY_TYPE_LABELS: dict[int, str] = {
    0x80: "DES (legacy)",
    0x82: "TDES_CBC (SCP02)",
    0x84: "TDES_ECB (SCP02)",
    0x88: "AES (SCP03 / SCP11)",
    0x90: "HMAC_SHA1",
    0x91: "HMAC_SHA1_160",
    0x95: "HMAC_SHA256",
    0xA1: "RSA_PUBLIC_EXP_E",
    0xA0: "RSA_PUBLIC_MOD_N",
    0xA2: "RSA_PRIVATE_MOD_N",
    0xA3: "RSA_PRIVATE_EXP_D",
    0xA4: "RSA_PRIVATE_CRT_P",
    0xA5: "RSA_PRIVATE_CRT_Q",
    0xA6: "RSA_PRIVATE_CRT_PQ",
    0xA7: "RSA_PRIVATE_CRT_DP1",
    0xA8: "RSA_PRIVATE_CRT_DQ1",
    0xB0: "EC_PUBLIC",
    0xB1: "EC_PRIVATE",
    0xB2: "EC_KEY_PARAMETERS",
    0xF0: "EXTENDED_TYPE",
    0xFF: "NOT_AVAILABLE",
}


# ----------------------------------------------------------------------
# Hex normalisation (same shape as saip_profile_header_edit)
# ----------------------------------------------------------------------


def _hex_to_bytes(value: Any, *, label: str = "value", expect_length: int | None = None) -> bytes:
    text = re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))
    if len(text) == 0:
        return b""
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"{label} is not hexadecimal: {value!r}")
    if len(text) % 2 != 0:
        raise ValueError(
            f"{label} has odd nybble count ({len(text)}); expected an even number.",
        )
    data = bytes.fromhex(text)
    if expect_length is not None and len(data) != expect_length:
        raise ValueError(
            f"{label} must be exactly {expect_length} bytes; got {len(data)}.",
        )
    return data


def _coerce_byte_or_default(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        if isinstance(value, str):
            text = value.strip()
            if len(text) == 0:
                return default
            return int(text, 0) & 0xFF
        return int(value) & 0xFF
    except (TypeError, ValueError):
        raise ValueError(f"expected a byte value, got {value!r}")


# ----------------------------------------------------------------------
# Section location
# ----------------------------------------------------------------------


def locate_security_domain_sections(decoded_document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return every ``(section_key, sd_dict)`` pair from the document.

    A profile may carry multiple security domains (ISD-R, ECASD,
    MNO-SD, SSDs). Callers select the target by section_key or by
    instance AID after inspecting the returned dicts.
    """
    sections = decoded_document.get("sections")
    if isinstance(sections, dict) is False:
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    for key, value in sections.items():
        if not isinstance(key, str):
            continue
        if not isinstance(value, dict):
            continue
        # SD-style sections always carry an "instance" sub-dict per
        # SAIP §A.2; sniff that to recognise them whether they were
        # decoded under "securityDomain", "mno-sd", "ssd", "isdr", etc.
        if "instance" in value and isinstance(value["instance"], dict):
            out.append((key, value))
    return out


# ----------------------------------------------------------------------
# Key list mutators
# ----------------------------------------------------------------------


def _build_key_object(
    *,
    key_version: int,
    key_identifier: int,
    usage_qualifier: bytes,
    key_access: int,
    key_components: list[dict[str, Any]],
    counter: bytes | None,
) -> dict[str, Any]:
    if len(usage_qualifier) == 0 or len(usage_qualifier) > 2:
        raise ValueError(
            f"usage_qualifier must be 1..2 bytes (GP §11.1.9); got {len(usage_qualifier)}.",
        )
    if not (0x00 <= key_version <= 0xFF):
        raise ValueError(f"key_version must fit in a byte; got {key_version}.")
    if not (0x00 <= key_identifier <= 0xFF):
        raise ValueError(f"key_identifier must fit in a byte; got {key_identifier}.")
    if not (0x00 <= key_access <= 0xFF):
        raise ValueError(f"key_access must fit in a byte; got {key_access}.")
    if len(key_components) == 0:
        raise ValueError("a KeyObject must carry at least one keyComponent (GP §11.1.10).")
    components_out: list[dict[str, Any]] = []
    for comp in key_components:
        if isinstance(comp, dict) is False:
            raise ValueError(f"key component must be a dict: {comp!r}")
        comp_type = _coerce_byte_or_default(comp.get("keyType") or comp.get("key_type"), 0x88)
        data_value = comp.get("keyData") if "keyData" in comp else comp.get("key_data")
        data_bytes = _hex_to_bytes(data_value, label="keyData")
        if len(data_bytes) == 0:
            raise ValueError("keyData must be non-empty.")
        mac_length = _coerce_byte_or_default(
            comp.get("macLength") if "macLength" in comp else comp.get("mac_length"),
            8,
        )
        # GP Card Spec v2.3.1 §11.1.10 macLength is in [0..16]; values
        # above 16 indicate an encoder bug and would break SCP02/03 MAC
        # truncation.
        if mac_length > 16:
            raise ValueError(f"macLength must be 0..16; got {mac_length}.")
        components_out.append(
            {
                "keyType": bytes([comp_type]),
                "keyData": data_bytes,
                "macLength": mac_length,
            }
        )
    out: dict[str, Any] = {
        "keyUsageQualifier": usage_qualifier,
        "keyAccess": bytes([key_access]),
        "keyIdentifier": bytes([key_identifier]),
        "keyVersionNumber": bytes([key_version]),
        "keyComponents": components_out,
    }
    if counter is not None and len(counter) > 0:
        out["keyCounterValue"] = counter
    return out


def add_key(
    sd: dict[str, Any],
    *,
    key_version: int | str,
    key_identifier: int | str,
    usage_qualifier_hex: str,
    key_components: list[dict[str, Any]],
    key_access: int | str = 0,
    counter_hex: str = "",
) -> str:
    """Append a new ``KeyObject`` to ``keyList``.

    ``key_components`` is a list of ``{keyType, keyData, macLength}``
    dicts. ``keyType`` accepts either an integer (GP §11.1.8 value) or
    a hex string. ``keyData`` is hex. Replacing an existing
    ``keyVersion/keyIdentifier`` pair raises so callers must
    ``remove_key`` first or use ``replace_key``.
    """
    key_version_int = _coerce_byte_or_default(key_version, 0)
    key_identifier_int = _coerce_byte_or_default(key_identifier, 0)
    key_access_int = _coerce_byte_or_default(key_access, 0)
    usage_bytes = _hex_to_bytes(usage_qualifier_hex, label="usage_qualifier_hex")
    counter_bytes = _hex_to_bytes(counter_hex, label="counter_hex")

    key_list = sd.get("keyList")
    if key_list is None:
        key_list = []
        sd["keyList"] = key_list
    if isinstance(key_list, list) is False:
        raise ValueError("keyList is not a list; cannot append.")

    # GP §11.5 PUT KEY requires every (KVN, KID) pair to be unique
    # within a Security Domain. Reject duplicates here so the encoder
    # never produces an invalid keyList.
    for existing in key_list:
        if isinstance(existing, dict) is False:
            continue
        existing_kvn = existing.get("keyVersionNumber")
        existing_kid = existing.get("keyIdentifier")
        existing_kvn_int = (
            existing_kvn[0]
            if isinstance(existing_kvn, (bytes, bytearray)) and len(existing_kvn) >= 1
            else None
        )
        existing_kid_int = (
            existing_kid[0]
            if isinstance(existing_kid, (bytes, bytearray)) and len(existing_kid) >= 1
            else None
        )
        if existing_kvn_int == key_version_int and existing_kid_int == key_identifier_int:
            raise ValueError(
                f"key (KVN=0x{key_version_int:02X}, KID=0x{key_identifier_int:02X}) "
                "already present; remove or replace it first."
            )

    new_key = _build_key_object(
        key_version=key_version_int,
        key_identifier=key_identifier_int,
        usage_qualifier=usage_bytes,
        key_access=key_access_int,
        key_components=key_components,
        counter=counter_bytes if len(counter_bytes) > 0 else None,
    )
    key_list.append(new_key)
    return (
        f"added key (KVN=0x{key_version_int:02X}, KID=0x{key_identifier_int:02X}, "
        f"{len(key_components)} component(s)); keyList size={len(key_list)}."
    )


def remove_key(sd: dict[str, Any], *, key_version: int | str, key_identifier: int | str) -> str:
    """Drop the ``KeyObject`` with the given (KVN, KID) from ``keyList``."""
    key_version_int = _coerce_byte_or_default(key_version, 0)
    key_identifier_int = _coerce_byte_or_default(key_identifier, 0)
    key_list = sd.get("keyList")
    if isinstance(key_list, list) is False or len(key_list) == 0:
        raise LookupError(
            f"no key (KVN=0x{key_version_int:02X}, KID=0x{key_identifier_int:02X}) to remove.",
        )
    for index, entry in enumerate(key_list):
        if isinstance(entry, dict) is False:
            continue
        kvn = entry.get("keyVersionNumber")
        kid = entry.get("keyIdentifier")
        kvn_int = kvn[0] if isinstance(kvn, (bytes, bytearray)) and len(kvn) >= 1 else None
        kid_int = kid[0] if isinstance(kid, (bytes, bytearray)) and len(kid) >= 1 else None
        if kvn_int == key_version_int and kid_int == key_identifier_int:
            del key_list[index]
            if len(key_list) == 0:
                # SAIP §A.2 keyList is OPTIONAL — drop the empty list so
                # the encoder does not emit an empty SEQUENCE OF.
                sd.pop("keyList", None)
                return f"removed key (KVN=0x{key_version_int:02X}, KID=0x{key_identifier_int:02X}); keyList now empty."
            return (
                f"removed key (KVN=0x{key_version_int:02X}, KID=0x{key_identifier_int:02X}); "
                f"keyList size={len(key_list)}."
            )
    raise LookupError(
        f"no key (KVN=0x{key_version_int:02X}, KID=0x{key_identifier_int:02X}) found.",
    )


def replace_key(sd: dict[str, Any], **kwargs: Any) -> str:
    """Replace an existing key in place (``remove_key`` + ``add_key``).

    Accepts the same keyword arguments as ``add_key``.
    """
    key_version = kwargs["key_version"]
    key_identifier = kwargs["key_identifier"]
    try:
        remove_key(sd, key_version=key_version, key_identifier=key_identifier)
    except LookupError:
        pass
    return add_key(sd, **kwargs)


# ----------------------------------------------------------------------
# Personalisation data
# ----------------------------------------------------------------------


def add_perso_data_block(sd: dict[str, Any], block_hex: str) -> str:
    """Append a raw STORE DATA block to ``sdPersoData``.

    GP Card Spec v2.3.1 §11.11 personalisation blocks are opaque to
    SAIP; the byte string is replayed as-is by the issuer applet
    loader. An empty block is rejected.
    """
    block_bytes = _hex_to_bytes(block_hex, label="block_hex")
    if len(block_bytes) == 0:
        raise ValueError("perso data block must be non-empty.")
    perso = sd.get("sdPersoData")
    if perso is None:
        perso = []
        sd["sdPersoData"] = perso
    if isinstance(perso, list) is False:
        raise ValueError("sdPersoData is not a list; cannot append.")
    perso.append(block_bytes)
    return f"added perso data block ({len(block_bytes)} bytes); sdPersoData size={len(perso)}."


def remove_perso_data_block(sd: dict[str, Any], index: int) -> str:
    """Drop the personalisation block at ``index``."""
    perso = sd.get("sdPersoData")
    if isinstance(perso, list) is False or len(perso) == 0:
        raise LookupError("sdPersoData is empty.")
    if not (0 <= index < len(perso)):
        raise IndexError(f"index {index} out of range for sdPersoData (size={len(perso)}).")
    removed = perso.pop(index)
    size = len(removed) if isinstance(removed, (bytes, bytearray)) else 0
    if len(perso) == 0:
        sd.pop("sdPersoData", None)
        return f"removed perso block #{index} ({size} bytes); sdPersoData now empty."
    return f"removed perso block #{index} ({size} bytes); sdPersoData size={len(perso)}."


# ----------------------------------------------------------------------
# Instance metadata
# ----------------------------------------------------------------------


def set_instance_aid_hex(sd: dict[str, Any], hex_value: str) -> str:
    """Replace ``instance.instanceAID`` (GP §11.4 install registry AID)."""
    aid_bytes = _hex_to_bytes(hex_value, label="instanceAID")
    if not (5 <= len(aid_bytes) <= 16):
        raise ValueError(
            f"AID must be 5..16 bytes (ISO 7816-5); got {len(aid_bytes)}.",
        )
    instance = sd.get("instance")
    if isinstance(instance, dict) is False:
        raise LookupError("PE-SecurityDomain has no 'instance' sub-section.")
    instance["instanceAID"] = aid_bytes
    return f"instanceAID set to {aid_bytes.hex().upper()}."


def set_privileges_hex(sd: dict[str, Any], hex_value: str) -> str:
    """Replace ``instance.applicationPrivileges`` (GP §11.1.2 privileges)."""
    priv = _hex_to_bytes(hex_value, label="applicationPrivileges")
    instance = sd.get("instance")
    if isinstance(instance, dict) is False:
        raise LookupError("PE-SecurityDomain has no 'instance' sub-section.")
    instance["applicationPrivileges"] = priv
    return f"applicationPrivileges set to {priv.hex().upper() if len(priv) > 0 else '(empty)'}."


def set_lifecycle_state(sd: dict[str, Any], state: int | str) -> str:
    """Replace ``instance.lifeCycleState`` (GP §11.1.1 lifecycle byte)."""
    state_int = _coerce_byte_or_default(state, 0x07)
    instance = sd.get("instance")
    if isinstance(instance, dict) is False:
        raise LookupError("PE-SecurityDomain has no 'instance' sub-section.")
    instance["lifeCycleState"] = bytes([state_int])
    return f"lifeCycleState set to 0x{state_int:02X}."


# ----------------------------------------------------------------------
# Read-side summary
# ----------------------------------------------------------------------


def security_domain_summary(sd: dict[str, Any]) -> dict[str, Any]:
    """Project a PE-SecurityDomain section to a JSON-safe summary."""

    def _hex_or_empty(value: Any) -> str:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).hex().upper()
        return ""

    instance = sd.get("instance") if isinstance(sd.get("instance"), dict) else {}
    keys_in = sd.get("keyList") or []
    keys_out: list[dict[str, Any]] = []
    if isinstance(keys_in, list):
        for entry in keys_in:
            if isinstance(entry, dict) is False:
                continue
            kvn = entry.get("keyVersionNumber")
            kid = entry.get("keyIdentifier")
            kvn_int = kvn[0] if isinstance(kvn, (bytes, bytearray)) and len(kvn) >= 1 else 0
            kid_int = kid[0] if isinstance(kid, (bytes, bytearray)) and len(kid) >= 1 else 0
            components_in = entry.get("keyComponents") or []
            components_out: list[dict[str, Any]] = []
            if isinstance(components_in, list):
                for comp in components_in:
                    if isinstance(comp, dict) is False:
                        continue
                    type_raw = comp.get("keyType")
                    type_int = (
                        type_raw[0]
                        if isinstance(type_raw, (bytes, bytearray)) and len(type_raw) >= 1
                        else 0
                    )
                    components_out.append(
                        {
                            "key_type": type_int,
                            "key_type_label": KEY_TYPE_LABELS.get(type_int, f"0x{type_int:02X}"),
                            "key_data_hex": _hex_or_empty(comp.get("keyData")),
                            "mac_length": int(comp.get("macLength") or 8),
                        }
                    )
            keys_out.append(
                {
                    "key_version": kvn_int,
                    "key_identifier": kid_int,
                    "usage_qualifier_hex": _hex_or_empty(entry.get("keyUsageQualifier")),
                    "key_access_hex": _hex_or_empty(entry.get("keyAccess")),
                    "counter_hex": _hex_or_empty(entry.get("keyCounterValue")),
                    "components": components_out,
                }
            )

    perso_in = sd.get("sdPersoData") or []
    perso_out: list[str] = []
    if isinstance(perso_in, list):
        for chunk in perso_in:
            if isinstance(chunk, (bytes, bytearray)):
                perso_out.append(bytes(chunk).hex().upper())

    lcs_raw = instance.get("lifeCycleState")
    lcs_int = (
        lcs_raw[0]
        if isinstance(lcs_raw, (bytes, bytearray)) and len(lcs_raw) >= 1
        else 0x07
    )

    return {
        "instance_aid_hex": _hex_or_empty(instance.get("instanceAID")),
        "class_aid_hex": _hex_or_empty(instance.get("classAID")),
        "load_package_aid_hex": _hex_or_empty(instance.get("applicationLoadPackageAID")),
        "privileges_hex": _hex_or_empty(instance.get("applicationPrivileges")),
        "lifecycle_state": lcs_int,
        "keys": keys_out,
        "perso_data_hex": perso_out,
    }


__all__ = [
    "KEY_TYPE_LABELS",
    "KEY_USAGE_QUALIFIER_BITS",
    "add_key",
    "add_perso_data_block",
    "locate_security_domain_sections",
    "remove_key",
    "remove_perso_data_block",
    "replace_key",
    "security_domain_summary",
    "set_instance_aid_hex",
    "set_lifecycle_state",
    "set_privileges_hex",
]
