# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local eIM overview: the store as one JSON-ready document, read only.

``build_overview`` answers what the Local eIM page shows: the eIM itself
(identity, signing certificate, the chains it serves, the service, the queue
rules), every eUICC it knows, and for one eUICC its profiles, the eIMs the
card lists, what was last read from it and its operations. Nothing here
reaches a card or changes the store; stored card data is as old as the stamp
beside it (``refreshed``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from SCP11.eim_local.engine import notifications, server, tls_setup, traffic
from SCP11.eim_local.engine.catalogue import KIND_CONFIGURATION, OPERATION_TYPES
from SCP11.eim_local.engine.identity import EimIdentity, IdentityError
from SCP11.eim_local.engine.service import LocalEim, LocalEimError, OperationRequest
from SCP11.eim_local.engine.store import PENDING_STATES, STATE_CREATED, EuiccRecord, Operation, StoreError
from SCP11.shared.certificate_view import certificate_rows

EVENT_LIMIT = 100
# Card answers kept as hex by the engine, in the order the page lists them.
# The third member is the context the page asks the decoder for: ES10 for the
# two EUICCInfo answers, plain BER-TLV for the other data objects, none for a
# value that is not a TLV.
_STORED_HEX = (
    ("euicc_info1_hex", "EUICCInfo1", "es10"),
    ("euicc_info2_hex", "EUICCInfo2", "es10"),
    ("ipa_capabilities_hex", "IPA capabilities", "tlv"),
    ("device_info_hex", "Device information", "tlv"),
    ("rat_hex", "Rules Authorisation Table", "tlv"),
    ("rplmn_hex", "Registered PLMN", ""),
)
_SERVICE_KEYS = (
    "url", "host", "port", "tls_url", "tls_setup", "tls_versions", "tls_note",
    "smdp_address", "smdp_fqdn", "smdp_tls_url", "smdp_tls_note", "smds_address", "smds_tls_url",
    "smds_tls_note", "started_at", "pid",
)


def _certificate(der: bytes) -> list[dict[str, Any]]:
    if len(der) == 0:
        return []
    return [
        {"indent": row.indent, "label": row.label, "value": row.value, "tone": row.tone}
        for row in certificate_rows(der)
    ]


def _pem_chain(path: str) -> list[bytes]:
    """The DER certificates of a PEM chain file, leaf first; [] when it cannot be read."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    try:
        data = Path(path).read_bytes()
    except OSError:
        return []
    try:
        return [item.public_bytes(Encoding.DER) for item in x509.load_pem_x509_certificates(data)]
    except ValueError:
        return []


def _identity(directory: Path, identity: EimIdentity | None) -> dict[str, Any] | None:
    if identity is None:
        return None
    summary = identity.describe()
    # An unreadable certificate file is shown as missing.
    try:
        signing = identity.signing_certificate_der()
    except (IdentityError, OSError, ValueError):
        signing = b""
    try:
        tls_der = identity.tls_certificate_der()
    except (IdentityError, OSError, ValueError):
        tls_der = b""
    return {
        "eim_id": identity.eim_id,
        "eim_id_type": identity.eim_id_type,
        "eim_id_type_name": summary.get("eim_id_type_name", ""),
        "eim_fqdn": identity.eim_fqdn,
        "effective_fqdn": tls_setup.effective_fqdn(directory, identity),
        "fqdn_source": tls_setup.fqdn_source(directory),
        "supported_protocols": list(identity.supported_protocols or []),
        "indirect_profile_download": bool(identity.indirect_profile_download),
        "euicc_ci_pkid_hex": identity.euicc_ci_pkid_hex,
        "created_at": identity.created_at,
        "signing_certificate_path": identity.signing_certificate_path,
        "signing_key_path": identity.signing_key_path,
        "signing_public_key_hex": summary.get("signing_public_key_hex", ""),
        "signing_certificate": _certificate(signing),
        "tls_certificate_path": identity.tls_certificate_path,
        "tls_key_path": identity.tls_key_path,
        "tls_certificate": _certificate(tls_der),
    }


def _tls(directory: Path, identity: EimIdentity | None) -> dict[str, Any]:
    active = tls_setup.active_name(directory)
    setups = []
    for setup in tls_setup.list_setups(directory):
        setups.append({
            "name": setup.name,
            "active": setup.name == active,
            "fqdn": setup.effective_fqdn,
            "leaf_name": setup.leaf_name,
            "chain": setup.chain,
            "trust": setup.trust,
            "curve": setup.curve,
            "versions": setup.versions,
            "client_auth": setup.client_auth,
            "created_at": setup.created_at,
        })
    served = []
    # A broken setup must not hide the rest of the page.
    try:
        materials = tls_setup.served_materials(directory, identity)
    except (IdentityError, OSError, ValueError):
        materials = []
    for material in materials:
        served.append({
            "label": material.label,
            "names": list(material.names),
            "versions": material.versions,
            "client_auth": material.client_auth,
            "chain_path": material.chain_path,
            "key_path": material.key_path,
            "leaf": material.leaf,
            "leaf_sha256": material.leaf_sha256,
            "certificates": [_certificate(der) for der in _pem_chain(material.chain_path)],
        })
    return {"active": active, "setups": setups, "served": served}


def _service(directory: Path) -> dict[str, Any]:
    status = server.describe(directory)
    summary: dict[str, Any] = {
        "running": bool(status.get("running")),
        "answers": bool(status.get("answers")),
        "store": str(status.get("store", "")),
        "log": str(status.get("log", "")),
    }
    for key in _SERVICE_KEYS:
        if key in status:
            summary[key] = status[key]
    return summary


def _euicc_row(record: EuiccRecord, pending: int) -> dict[str, Any]:
    return {
        "eid": record.eid,
        "label": record.label,
        "associated": bool(record.data.get("associated")),
        "last_poll_at": record.last_poll_at,
        "poll_count": record.poll_count,
        "profile_count": len(record.profiles),
        "pending": pending,
        "created_at": record.created_at,
    }


def _operation(operation: Operation) -> dict[str, Any]:
    kind = OPERATION_TYPES.get(operation.type)
    result = operation.result if isinstance(operation.result, dict) else {}
    return {
        "id": operation.id,
        "type": operation.type,
        "title": kind.title if kind is not None else operation.type,
        "state": operation.state,
        "final": operation.final,
        "created_at": operation.created_at,
        "served_at": operation.served_at,
        "finished_at": operation.finished_at,
        "route": operation.route,
        "author": operation.author,
        "system": bool(operation.system),
        "params": dict(operation.params or {}),
        "error": operation.error or str(result.get("error") or ""),
        "warnings": list(operation.warnings or []),
        "retries": operation.retries,
        "max_retries": operation.max_retries,
    }


def _euicc_detail(eim: LocalEim, record: EuiccRecord) -> dict[str, Any]:
    data = record.data
    operations = eim.operations(eid=record.eid, limit=EVENT_LIMIT)
    stored = [
        {"key": key, "label": label, "hex": str(data.get(key) or ""), "decode": context}
        for key, label, context in _STORED_HEX
        if len(str(data.get(key) or "")) > 0
    ]
    refreshed = data.get("refreshed") if isinstance(data.get("refreshed"), dict) else {}
    first_seen = data.get("first_seen") if isinstance(data.get("first_seen"), dict) else {}
    return {
        "eid": record.eid,
        "label": record.label,
        "associated": bool(data.get("associated")),
        "association_token": record.association_token,
        "counter_value": record.counter_value,
        "tls_setup": str(data.get("tls_setup") or ""),
        "created_at": record.created_at,
        "first_seen": dict(first_seen),
        "first_poll_at": record.first_poll_at,
        "last_poll_at": record.last_poll_at,
        "poll_count": record.poll_count,
        "refreshed": dict(refreshed),
        "profiles": [dict(item) for item in record.profiles if isinstance(item, dict)],
        "eims": [dict(item) for item in record.eims if isinstance(item, dict)],
        "default_smdp_address": str(data.get("default_smdp_address") or ""),
        "root_smds_address": str(data.get("root_smds_address") or ""),
        "immediate_enable": data.get("immediate_enable"),
        "stored": stored,
        "euicc_certificate": _certificate(bytes(record.euicc_certificate or b"")),
        "eum_certificate": _certificate(bytes(record.eum_certificate or b"")),
        "pending": [_operation(item) for item in operations if item.state in PENDING_STATES],
        "operations": [_operation(item) for item in operations],
        # What IPAs handed over for this eUICC and where each stands; newest first for the page.
        "notifications": list(reversed(notifications.rows_of(record))),
    }


def saved_eim_configurations() -> list[dict[str, str]]:
    """The eIM configurations saved in the AddInitialEim builder store: name and one line each; [] when unreadable."""
    from SCP11.shared import eim_builder, eim_builder_store

    try:
        configurations = eim_builder_store.load_configurations()
    except (eim_builder_store.EimBuilderStoreError, OSError):
        return []
    return [{"name": name, "summary": eim_builder.configuration_summary(configurations[name])}
            for name in sorted(configurations)]


def catalogue() -> list[dict[str, Any]]:
    """Every operation type with its parameters, in the catalogue's order.

    A parameter that names a saved eIM configuration offers the names saved
    now as its choices.
    """
    saved = [entry["name"] for entry in saved_eim_configurations()]
    return [
        {
            "type": kind.name,
            "verb": kind.verb,
            "title": kind.title,
            "package": kind.package,
            "signed": kind.signed,
            "params": _param_specs(kind, saved),
        }
        for kind in OPERATION_TYPES.values()
    ]


def _param_specs(kind: Any, saved: list[str]) -> list[dict[str, Any]]:
    return [
        {"name": param.name, "kind": param.kind, "required": param.required, "help": param.help,
         "choices": list(saved) if param.kind == KIND_CONFIGURATION else list(param.choices)}
        for param in (kind.params if kind is not None else ())
    ]


def _described(rows: list[traffic.Detail]) -> list[dict[str, str]]:
    return [{"tag": row.tag, "name": row.name, "value": row.value} for row in rows]


def operation_detail(eim: LocalEim | None, operation_id: int) -> dict[str, Any]:
    """One operation in full: parameters, timeline, the package bytes and the result.

    ``package_hex`` is what was served once it was; before that it is the
    part of the package fixed already (``package_state`` says which). Only a
    CREATED operation takes changes (``editable``).
    """
    eim = eim if eim is not None else LocalEim()
    operation = eim.operation(int(operation_id))
    detail = _operation(operation)
    kind = OPERATION_TYPES.get(operation.type)
    package_hex = operation.served_hex or ""
    package_state = "served" if len(package_hex) > 0 else ""
    plan_warnings: list[str] = []
    if len(package_hex) == 0:
        try:
            entry = eim.plan([OperationRequest(
                eid=operation.eid, type=operation.type, params=dict(operation.params or {}),
                raw_items=operation.raw_items, fault=operation.fault,
            )])[0]
        except (LocalEimError, StoreError, ValueError):
            entry = None
        if entry is not None:
            package_hex = entry.preview_hex
            package_state = "fixed so far"
            plan_warnings = list(entry.warnings)
    result = operation.result if isinstance(operation.result, dict) else {}
    detail.update({
        "eid": operation.eid,
        "editable": operation.state == STATE_CREATED,
        "param_specs": _param_specs(kind, [entry["name"] for entry in saved_eim_configurations()]),
        "raw_items": operation.raw_items,
        "not_before": operation.not_before,
        "fault": operation.fault,
        "flags": list(operation.flags or []),
        "transaction_id": operation.transaction_id,
        "counter_value": operation.counter_value,
        "association_token": operation.association_token,
        "position": operation.position,
        "package_hex": package_hex,
        "package_state": package_state,
        # Named rows for a served package and a stored result; the part of
        # an unserved package is items only and goes to the TLV decoder.
        "package_rows": (_described(traffic.describe_package(bytes.fromhex(package_hex)))
                         if package_state == "served" else []),
        "result_rows": (_described(traffic.describe_result(bytes.fromhex(operation.result_hex)))
                        if operation.result_hex else []),
        "plan_warnings": plan_warnings,
        "result_hex": operation.result_hex or "",
        "result": dict(result),
        "history": [dict(item) for item in (operation.history or []) if isinstance(item, dict)],
    })
    return detail


def build_overview(eim: LocalEim | None = None, *, eid: str = "") -> dict[str, Any]:
    """The Local eIM as one document; ``eid`` picks the eUICC shown in detail.

    An unknown ``eid`` answers ``euicc: None`` with the list intact, so a page
    holding a removed eUICC falls back to the list.
    """
    eim = eim if eim is not None else LocalEim()
    directory = Path(eim.directory)
    identity = eim.identity_or_none()
    pending_by_eid: dict[str, int] = {}
    for operation in eim.operations(states=PENDING_STATES, limit=1000):
        pending_by_eid[operation.eid] = pending_by_eid.get(operation.eid, 0) + 1
    records = eim.records()
    detail = None
    wanted = "".join(str(eid or "").split()).upper()
    if len(wanted) > 0:
        for record in records:
            if record.eid.upper() == wanted:
                detail = _euicc_detail(eim, record)
                break
    return {
        "store": str(directory),
        "identity": _identity(directory, identity),
        "tls": _tls(directory, identity),
        "service": _service(directory),
        "settings": dict(eim.settings()),
        "catalogue": catalogue(),
        "eim_configurations": saved_eim_configurations(),
        "euiccs": [_euicc_row(record, pending_by_eid.get(record.eid, 0)) for record in records],
        "euicc": detail,
    }
