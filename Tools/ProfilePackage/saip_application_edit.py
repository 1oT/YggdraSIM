# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SAIP ``PE-Application`` structured edit helpers.

The PE-Application element (TCA SAIP v3.4.1 §8.7 / GP Card Spec v2.3.1
§11.5-11.6) carries an optional load-block descriptor and a list of
SD-hosted applet instances. Operators routinely need to register new
applet instances on an existing SSD, swap a load block for a newer
applet revision, or drop a decommissioned instance. The generic
decoded-edit panel cannot grow ``instanceList`` safely; this module
exposes the spec-aware list-mutating primitives.

Decoded shape post ``build_decoded_document_from_sequence``::

    {
      "app-Header": {...},
      "loadBlock": {                                   # optional
        "loadPackageAID": <bytes>,
        "securityDomainAID": <bytes>,                  # optional
        "nonVolatileCodeLimitC6": <bytes>,             # optional
        "volatileDataLimitC7": <bytes>,                # optional
        "nonVolatileDataLimitC8": <bytes>,             # optional
        "hashValue": <bytes>,                          # optional
        "loadBlockObject": <bytes>,
      },
      "instanceList": [ApplicationInstance, ...]       # optional
    }

An Application PE loads at most one package, and its instances install that
package: "Multiple instances of the same ApplicationLoadPackage can be
installed within one Application PE" (TCA SAIP v3.4.1 §8.7.1, page 59). The
mutators keep every instance on that one package; a profile that already
installs instances of several packages still opens, edits and round-trips.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _hex_to_bytes(value: Any, *, label: str = "value", min_len: int | None = None, max_len: int | None = None) -> bytes:
    text = re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))
    if len(text) == 0:
        return b""
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"{label} is not hexadecimal: {value!r}")
    if len(text) % 2 != 0:
        raise ValueError(f"{label} has odd nybble count ({len(text)}).")
    data = bytes.fromhex(text)
    if min_len is not None and len(data) < min_len:
        raise ValueError(f"{label} must be at least {min_len} bytes; got {len(data)}.")
    if max_len is not None and len(data) > max_len:
        raise ValueError(f"{label} must be at most {max_len} bytes; got {len(data)}.")
    return data


def _byte_or_default(value: Any, default: int) -> int:
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


def locate_application_sections(decoded_document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return every ``(section_key, application_dict)`` pair from the document."""
    sections = decoded_document.get("sections")
    if isinstance(sections, dict) is False:
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    for key, value in sections.items():
        if isinstance(key, str) is False or isinstance(value, dict) is False:
            continue
        # ``application`` sections always have one of ``loadBlock`` or
        # ``instanceList`` -- they may not both be present but at least
        # one of them must (otherwise the PE is meaningless).
        if "loadBlock" in value or "instanceList" in value or "app-Header" in value:
            out.append((key, value))
    return out


# ----------------------------------------------------------------------
# One load package per PE (TCA SAIP v3.4.1 §8.7.1)
# ----------------------------------------------------------------------


def _set_aid(value: Any) -> bytes | None:
    """``value`` as an AID that names something; the all-zero filler AID does not."""
    if isinstance(value, (bytes, bytearray)) and any(value):
        return bytes(value)
    return None


def _instance_packages(application: Mapping[str, Any], *, skip: int | None = None) -> list[bytes]:
    entries = application.get("instanceList")
    if isinstance(entries, list) is False:
        return []
    out: list[bytes] = []
    for index, entry in enumerate(entries):
        if index == skip or isinstance(entry, dict) is False:
            continue
        aid = _set_aid(entry.get("applicationLoadPackageAID"))
        if aid is not None:
            out.append(aid)
    return out


def _load_package(application: Mapping[str, Any]) -> bytes | None:
    load_block = application.get("loadBlock")
    if isinstance(load_block, dict) is False:
        return None
    return _set_aid(load_block.get("loadPackageAID"))


def own_package(application: Mapping[str, Any], *, skip: int | None = None) -> bytes | None:
    """The package the PE's instances install, or None while nothing names one.

    The load package when the PE loads one, else the package every instance
    but ``skip`` installs.
    """
    loaded = _load_package(application)
    if loaded is not None:
        return loaded
    packages = set(_instance_packages(application, skip=skip))
    if len(packages) == 1:
        return packages.pop()
    return None


def package_conflict(application: Mapping[str, Any]) -> str | None:
    """Why the PE installs instances of more than one package, or None."""
    packages = _instance_packages(application)
    own = _load_package(application)
    if own is None and len(packages) > 0:
        own = packages[0]
    foreign = sorted({aid for aid in packages if aid != own})
    if len(foreign) == 0 or own is None:
        return None
    names = ", ".join(aid.hex().upper() for aid in foreign)
    return (
        f"an instance installs package {names}, not this PE's package "
        f"{own.hex().upper()}: an Application PE installs instances of its one "
        "load package (TCA SAIP v3.4.1 §8.7.1)."
    )


def _check_own_package(application: Mapping[str, Any], package: bytes, *, skip: int | None = None) -> None:
    own = own_package(application, skip=skip)
    if own is not None and package != own:
        raise ValueError(
            f"load package AID {package.hex().upper()} is not this PE's package "
            f"{own.hex().upper()}: an Application PE installs instances of its one "
            "load package (TCA SAIP v3.4.1 §8.7.1).",
        )


def _follow_package(application: dict[str, Any], old: bytes | None, new: bytes | None) -> int:
    """Move the instances that installed ``old`` to ``new``; answers how many moved."""
    if old is None or new is None or old == new:
        return 0
    moved = 0
    for entry in application.get("instanceList") or []:
        if isinstance(entry, dict) and _set_aid(entry.get("applicationLoadPackageAID")) == old:
            entry["applicationLoadPackageAID"] = new
            moved += 1
    return moved


def keep_one_package(before: Mapping[str, Any], after: dict[str, Any]) -> str:
    """Hold ``after``, one member edit of ``before``, to the PE's one load package.

    A load package AID the edit changed takes along the instances that
    installed the old one, and an instance the edit added installs the PE's
    package. An edit that leaves an instance on another package is refused,
    unless ``before`` already installed several. Answers a note on what
    followed, or "".
    """
    old = own_package(before)
    new = _load_package(after)
    notes: list[str] = []
    moved = _follow_package(after, old, new)
    if moved > 0 and new is not None:
        notes.append(f"{moved} instance(s) now install package {new.hex().upper()}.")
    own = new if new is not None else old
    earlier = before.get("instanceList")
    entries = after.get("instanceList")
    if own is not None and isinstance(entries, list):
        first_new = len(earlier) if isinstance(earlier, list) else 0
        for entry in entries[first_new:]:
            if isinstance(entry, dict) and _set_aid(entry.get("applicationLoadPackageAID")) is None:
                entry["applicationLoadPackageAID"] = own
                notes.append(f"The new instance installs package {own.hex().upper()}.")
    conflict = package_conflict(after)
    if conflict is not None and package_conflict(before) is None:
        raise ValueError(conflict[0].upper() + conflict[1:])
    return " ".join(notes)


# ----------------------------------------------------------------------
# Instance list mutators
# ----------------------------------------------------------------------


def _check_instance_identity(
    *,
    load_package_aid: bytes,
    class_aid: bytes,
    instance_aid: bytes,
    privileges: bytes,
    extradite_sd_aid: bytes,
) -> None:
    if not (5 <= len(load_package_aid) <= 16):
        raise ValueError(f"load package AID must be 5..16 bytes; got {len(load_package_aid)}.")
    if not (5 <= len(class_aid) <= 16):
        raise ValueError(f"class AID must be 5..16 bytes; got {len(class_aid)}.")
    if not (5 <= len(instance_aid) <= 16):
        raise ValueError(f"instance AID must be 5..16 bytes; got {len(instance_aid)}.")
    if len(privileges) == 0 or len(privileges) > 3:
        raise ValueError(
            f"privileges must be 1..3 bytes (GP §11.1.2); got {len(privileges)}.",
        )
    if len(extradite_sd_aid) > 0 and not (5 <= len(extradite_sd_aid) <= 16):
        raise ValueError(
            f"extradite SD AID must be 5..16 bytes; got {len(extradite_sd_aid)}.",
        )


def _build_instance(
    *,
    load_package_aid: bytes,
    class_aid: bytes,
    instance_aid: bytes,
    privileges: bytes,
    lifecycle_state: int,
    application_specific_parameters: bytes,
    extradite_sd_aid: bytes,
    application_parameters: dict[str, bytes] | None,
    process_data: list[bytes],
) -> dict[str, Any]:
    _check_instance_identity(
        load_package_aid=load_package_aid,
        class_aid=class_aid,
        instance_aid=instance_aid,
        privileges=privileges,
        extradite_sd_aid=extradite_sd_aid,
    )
    entry: dict[str, Any] = {
        "applicationLoadPackageAID": load_package_aid,
        "classAID": class_aid,
        "instanceAID": instance_aid,
        "applicationPrivileges": privileges,
        "lifeCycleState": bytes([lifecycle_state]),
        "applicationSpecificParametersC9": application_specific_parameters,
    }
    if len(extradite_sd_aid) > 0:
        entry["extraditeSecurityDomainAID"] = extradite_sd_aid
    if application_parameters is not None and len(application_parameters) > 0:
        entry["applicationParameters"] = application_parameters
    if len(process_data) > 0:
        entry["processData"] = process_data
    return entry


def add_instance(
    application: dict[str, Any],
    *,
    load_package_aid_hex: str,
    class_aid_hex: str,
    instance_aid_hex: str,
    privileges_hex: str,
    application_specific_parameters_hex: str,
    lifecycle_state: int | str = 0x07,
    extradite_sd_aid_hex: str = "",
    uicc_toolkit_parameters_hex: str = "",
    uicc_access_parameters_hex: str = "",
    uicc_admin_access_parameters_hex: str = "",
    process_data_hex_list: list[str] | None = None,
) -> str:
    """Append a new ``ApplicationInstance`` to ``instanceList``.

    The (instanceAID) is checked for uniqueness within the PE; the GP
    registry rejects duplicate AIDs at INSTALL [for install] time so we
    refuse to author one here. The instance installs the PE's own package.
    """
    load_package_aid = _hex_to_bytes(load_package_aid_hex, label="loadPackageAID")
    _check_own_package(application, load_package_aid)
    class_aid = _hex_to_bytes(class_aid_hex, label="classAID")
    instance_aid = _hex_to_bytes(instance_aid_hex, label="instanceAID")
    privileges = _hex_to_bytes(privileges_hex, label="applicationPrivileges")
    asp = _hex_to_bytes(application_specific_parameters_hex, label="applicationSpecificParametersC9")
    extradite_sd_aid = _hex_to_bytes(extradite_sd_aid_hex, label="extraditeSecurityDomainAID")
    lifecycle_int = _byte_or_default(lifecycle_state, 0x07)

    app_params: dict[str, bytes] | None = None
    toolkit_bytes = _hex_to_bytes(uicc_toolkit_parameters_hex, label="uiccToolkitParameters")
    access_bytes = _hex_to_bytes(uicc_access_parameters_hex, label="uiccAccessParameters")
    admin_bytes = _hex_to_bytes(uicc_admin_access_parameters_hex, label="uiccAdminAccessParameters")
    if len(toolkit_bytes) + len(access_bytes) + len(admin_bytes) > 0:
        app_params = {}
        if len(toolkit_bytes) > 0:
            app_params["uiccToolkitApplicationSpecificParametersField"] = toolkit_bytes
        if len(access_bytes) > 0:
            app_params["uiccAccessApplicationSpecificParametersField"] = access_bytes
        if len(admin_bytes) > 0:
            app_params["uiccAdministrativeAccessApplicationSpecificParametersField"] = admin_bytes

    process_data: list[bytes] = []
    for hex_text in (process_data_hex_list or []):
        chunk = _hex_to_bytes(hex_text, label="processData entry")
        if len(chunk) > 0:
            process_data.append(chunk)

    instance_list = application.get("instanceList")
    if instance_list is None:
        instance_list = []
        application["instanceList"] = instance_list
    if isinstance(instance_list, list) is False:
        raise ValueError("instanceList is not a list; cannot append.")

    # GP §11.4: instance AIDs must be unique on the card. SAIP imposes
    # the same rule within a single PE-Application section.
    for existing in instance_list:
        if isinstance(existing, dict) is False:
            continue
        existing_aid = existing.get("instanceAID")
        if isinstance(existing_aid, (bytes, bytearray)) and bytes(existing_aid) == instance_aid:
            raise ValueError(
                f"instance AID {instance_aid.hex().upper()} already present in PE-Application.",
            )

    entry = _build_instance(
        load_package_aid=load_package_aid,
        class_aid=class_aid,
        instance_aid=instance_aid,
        privileges=privileges,
        lifecycle_state=lifecycle_int,
        application_specific_parameters=asp,
        extradite_sd_aid=extradite_sd_aid,
        application_parameters=app_params,
        process_data=process_data,
    )
    instance_list.append(entry)
    return f"added instance {instance_aid.hex().upper()}; instanceList size={len(instance_list)}."


def update_instance(
    application: dict[str, Any],
    instance_aid_hex: str,
    *,
    load_package_aid_hex: str,
    class_aid_hex: str,
    new_instance_aid_hex: str,
    privileges_hex: str,
    lifecycle_state: int | str,
    application_specific_parameters_hex: str,
    extradite_sd_aid_hex: str,
) -> str:
    """Rewrite the INSTALL members of the instance ``instance_aid_hex`` names.

    The instance keeps its place in ``instanceList`` and every member this
    does not write (``systemSpecificParameters``, ``applicationParameters``,
    ``processData``, ``controlReferenceTemplate``). An empty
    ``new_instance_aid_hex`` keeps the AID; an empty extradite AID drops the
    member, so the instance is associated to the MNO-SD (TCA SAIP v3.4.1
    §8.7.3). A changed load package AID has to be the PE's own package.
    """
    target = _hex_to_bytes(instance_aid_hex, label="instanceAID")
    instance_list = application.get("instanceList")
    entries = instance_list if isinstance(instance_list, list) else []
    position = next(
        (
            index for index, entry in enumerate(entries)
            if isinstance(entry, dict) and entry.get("instanceAID") == target
        ),
        None,
    )
    if position is None:
        raise LookupError(f"no instance with AID {target.hex().upper()} found.")
    entry = entries[position]

    load_package_aid = _hex_to_bytes(load_package_aid_hex, label="loadPackageAID")
    class_aid = _hex_to_bytes(class_aid_hex, label="classAID")
    instance_aid = _hex_to_bytes(new_instance_aid_hex, label="instanceAID") or target
    privileges = _hex_to_bytes(privileges_hex, label="applicationPrivileges")
    asp = _hex_to_bytes(application_specific_parameters_hex, label="applicationSpecificParametersC9")
    extradite_sd_aid = _hex_to_bytes(extradite_sd_aid_hex, label="extraditeSecurityDomainAID")
    lifecycle_int = _byte_or_default(lifecycle_state, 0x07)
    _check_instance_identity(
        load_package_aid=load_package_aid,
        class_aid=class_aid,
        instance_aid=instance_aid,
        privileges=privileges,
        extradite_sd_aid=extradite_sd_aid,
    )
    if load_package_aid != _set_aid(entry.get("applicationLoadPackageAID")):
        _check_own_package(application, load_package_aid, skip=position)
    for index, other in enumerate(entries):
        if index != position and isinstance(other, dict) and other.get("instanceAID") == instance_aid:
            raise ValueError(
                f"instance AID {instance_aid.hex().upper()} already present in PE-Application.",
            )

    entry["applicationLoadPackageAID"] = load_package_aid
    entry["classAID"] = class_aid
    entry["instanceAID"] = instance_aid
    entry["applicationPrivileges"] = privileges
    entry["lifeCycleState"] = bytes([lifecycle_int])
    entry["applicationSpecificParametersC9"] = asp
    if len(extradite_sd_aid) > 0:
        entry["extraditeSecurityDomainAID"] = extradite_sd_aid
    else:
        entry.pop("extraditeSecurityDomainAID", None)
    if instance_aid != target:
        return f"updated instance {instance_aid.hex().upper()} (was {target.hex().upper()})."
    return f"updated instance {instance_aid.hex().upper()}."


def remove_instance(application: dict[str, Any], instance_aid_hex: str) -> str:
    """Drop the ``ApplicationInstance`` with the given instance AID."""
    target = _hex_to_bytes(instance_aid_hex, label="instanceAID")
    instance_list = application.get("instanceList")
    if isinstance(instance_list, list) is False or len(instance_list) == 0:
        raise LookupError("instanceList is empty.")
    for index, entry in enumerate(instance_list):
        if isinstance(entry, dict) is False:
            continue
        aid = entry.get("instanceAID")
        if isinstance(aid, (bytes, bytearray)) and bytes(aid) == target:
            del instance_list[index]
            if len(instance_list) == 0:
                application.pop("instanceList", None)
                return f"removed instance {target.hex().upper()}; instanceList now empty."
            return f"removed instance {target.hex().upper()}; instanceList size={len(instance_list)}."
    raise LookupError(f"no instance with AID {target.hex().upper()} found.")


# ----------------------------------------------------------------------
# Load block mutators
# ----------------------------------------------------------------------


def set_load_block(
    application: dict[str, Any],
    *,
    load_package_aid_hex: str,
    load_block_object_hex: str,
    security_domain_aid_hex: str = "",
    non_volatile_code_limit_hex: str = "",
    volatile_data_limit_hex: str = "",
    non_volatile_data_limit_hex: str = "",
    hash_value_hex: str = "",
) -> str:
    """Install or replace the ``loadBlock`` sub-section.

    The load-package AID and the load-block object are mandatory per
    GP Card Spec v2.3.1 §11.6. The four memory-limit fields and the
    hash value are optional but routinely shipped. The instances that
    installed the PE's previous package install the new one.
    """
    previous_package = own_package(application)
    load_package_aid = _hex_to_bytes(load_package_aid_hex, label="loadPackageAID")
    load_block_obj = _hex_to_bytes(load_block_object_hex, label="loadBlockObject")
    if not (5 <= len(load_package_aid) <= 16):
        raise ValueError(
            f"load package AID must be 5..16 bytes; got {len(load_package_aid)}.",
        )
    if len(load_block_obj) == 0:
        raise ValueError("loadBlockObject must be non-empty.")

    load_block: dict[str, Any] = {
        "loadPackageAID": load_package_aid,
        "loadBlockObject": load_block_obj,
    }
    sd_aid = _hex_to_bytes(security_domain_aid_hex, label="securityDomainAID")
    if len(sd_aid) > 0:
        if not (5 <= len(sd_aid) <= 16):
            raise ValueError(
                f"security domain AID must be 5..16 bytes; got {len(sd_aid)}.",
            )
        load_block["securityDomainAID"] = sd_aid
    nvcl = _hex_to_bytes(non_volatile_code_limit_hex, label="nonVolatileCodeLimitC6")
    if len(nvcl) > 0:
        load_block["nonVolatileCodeLimitC6"] = nvcl
    vdl = _hex_to_bytes(volatile_data_limit_hex, label="volatileDataLimitC7")
    if len(vdl) > 0:
        load_block["volatileDataLimitC7"] = vdl
    nvdl = _hex_to_bytes(non_volatile_data_limit_hex, label="nonVolatileDataLimitC8")
    if len(nvdl) > 0:
        load_block["nonVolatileDataLimitC8"] = nvdl
    hv = _hex_to_bytes(hash_value_hex, label="hashValue")
    if len(hv) > 0:
        load_block["hashValue"] = hv

    application["loadBlock"] = load_block
    message = f"loadBlock set; load package AID={load_package_aid.hex().upper()}, " \
              f"loadBlockObject={len(load_block_obj)} bytes."
    moved = _follow_package(application, previous_package, load_package_aid)
    if moved > 0:
        message += f" {moved} instance(s) now install it."
    return message


def remove_load_block(application: dict[str, Any]) -> str:
    """Drop the ``loadBlock`` sub-section."""
    if "loadBlock" not in application:
        raise LookupError("PE-Application has no loadBlock to remove.")
    application.pop("loadBlock", None)
    return "loadBlock removed."


# ----------------------------------------------------------------------
# Read-side summary
# ----------------------------------------------------------------------


def application_summary(application: dict[str, Any]) -> dict[str, Any]:
    """Project the PE-Application section to a JSON-safe summary."""

    def _hex_or_empty(value: Any) -> str:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).hex().upper()
        return ""

    load_block = application.get("loadBlock") if isinstance(application.get("loadBlock"), dict) else None
    load_block_summary: dict[str, Any] | None = None
    if load_block is not None:
        load_block_summary = {
            "load_package_aid_hex": _hex_or_empty(load_block.get("loadPackageAID")),
            "security_domain_aid_hex": _hex_or_empty(load_block.get("securityDomainAID")),
            "non_volatile_code_limit_hex": _hex_or_empty(load_block.get("nonVolatileCodeLimitC6")),
            "volatile_data_limit_hex": _hex_or_empty(load_block.get("volatileDataLimitC7")),
            "non_volatile_data_limit_hex": _hex_or_empty(load_block.get("nonVolatileDataLimitC8")),
            "hash_value_hex": _hex_or_empty(load_block.get("hashValue")),
            "load_block_object_size": (
                len(load_block.get("loadBlockObject"))
                if isinstance(load_block.get("loadBlockObject"), (bytes, bytearray))
                else 0
            ),
        }

    instances_in = application.get("instanceList") or []
    instances_out: list[dict[str, Any]] = []
    if isinstance(instances_in, list):
        for index, entry in enumerate(instances_in):
            if isinstance(entry, dict) is False:
                continue
            lcs_raw = entry.get("lifeCycleState")
            lcs_int = (
                lcs_raw[0]
                if isinstance(lcs_raw, (bytes, bytearray)) and len(lcs_raw) >= 1
                else 0x07
            )
            app_params = entry.get("applicationParameters") or {}
            process_data = entry.get("processData")
            instances_out.append(
                {
                    "index": index,
                    "own_package_hex": _hex_or_empty(own_package(application, skip=index)),
                    "process_data_hex_list": [
                        _hex_or_empty(chunk) for chunk in process_data
                    ] if isinstance(process_data, list) else [],
                    "load_package_aid_hex": _hex_or_empty(entry.get("applicationLoadPackageAID")),
                    "class_aid_hex": _hex_or_empty(entry.get("classAID")),
                    "instance_aid_hex": _hex_or_empty(entry.get("instanceAID")),
                    "extradite_sd_aid_hex": _hex_or_empty(entry.get("extraditeSecurityDomainAID")),
                    "privileges_hex": _hex_or_empty(entry.get("applicationPrivileges")),
                    "lifecycle_state": lcs_int,
                    "application_specific_parameters_hex": _hex_or_empty(
                        entry.get("applicationSpecificParametersC9")
                    ),
                    "uicc_toolkit_parameters_hex": _hex_or_empty(
                        app_params.get("uiccToolkitApplicationSpecificParametersField")
                    ) if isinstance(app_params, dict) else "",
                    "uicc_access_parameters_hex": _hex_or_empty(
                        app_params.get("uiccAccessApplicationSpecificParametersField")
                    ) if isinstance(app_params, dict) else "",
                    "uicc_admin_access_parameters_hex": _hex_or_empty(
                        app_params.get("uiccAdministrativeAccessApplicationSpecificParametersField")
                    ) if isinstance(app_params, dict) else "",
                }
            )

    return {
        "load_block": load_block_summary,
        "instances": instances_out,
        "own_package_hex": _hex_or_empty(own_package(application)),
    }


__all__ = [
    "add_instance",
    "application_summary",
    "keep_one_package",
    "locate_application_sections",
    "own_package",
    "package_conflict",
    "remove_instance",
    "remove_load_block",
    "set_load_block",
    "update_instance",
]
