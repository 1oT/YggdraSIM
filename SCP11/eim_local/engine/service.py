# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The Local eIM service: queue operations per eUICC, sign them when served, read the results back.

Operation states: CREATED -> SENT -> SUCCESS / PARTIAL_SUCCESS /
ERROR, CANCELED. A queued operation is unsigned; the counter (incremented by
one per eUICC Package for that eUICC, SGP.32 v1.3 §2.11.1.1, p.31), the
associationToken and the signature are added when an IPA or a delivery route
takes it, so editing, moving or canceling a CREATED operation costs nothing.
One operation per eUICC is in flight. An unanswered one is first looked for
among the results the eUICC keeps (IpaEuiccDataRequest 'A2', §2.11.1.2), and
only served again when none matches. Results are checked against the eUICC
certificate and sequence number (§3.3.1 step 11, p.73), and the ok ones
update the eUICC record.
"""

from __future__ import annotations

import datetime
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine import compact as compact_forms
from SCP11.eim_local.engine import notifications as outbox
from SCP11.eim_local.engine import smds as smds_module
from SCP11.eim_local.engine.catalogue import (
    CERTIFICATE_TAGS,
    IPA_DATA_TAGS,
    PACKAGE_DEVICE,
    RECOVERY_TAGS,
    REFUSED_TAG_LIST,
    TAG_LIST_ALL,
    TAG_LIST_DEFAULT,
    OperationError,
    OperationType,
    build_items,
    build_unsigned_request,
    describe,
    expand_eim_configuration,
    fault_warning,
    normalize_params,
    operation_type,
    package_rule_warnings,
    precondition_warnings,
    refused_tag_list,
)
from SCP11.eim_local.engine.identity import (
    LOCAL_EIM_NAME_PATTERN,
    local_eim_name,
    DEFAULT_EIM_FQDN,
    EXAMPLE_EIM_ID,
    EimIdentity,
    IdentityError,
    generate_identity,
    import_identity,
    load_identity,
)
from SCP11.eim_local.engine.tls_setup import active_name, effective_fqdn, fqdn_source, trusted_tls_key_data
from SCP11.eim_local.engine.store import (
    FINAL_STATES,
    STATE_CANCELED,
    STATE_CREATED,
    STATE_ERROR,
    STATE_PARTIAL_SUCCESS,
    STATE_SENT,
    STATE_SUCCESS,
    DATABASE_FILE,
    EimStore,
    EuiccRecord,
    Operation,
    StoreError,
    store_directory,
    utc_now,
)
from SCP11.shared.eim_configuration_data import (
    EimConfigurationData,
    ScriptStep,
    decode_add_initial_eim_response,
    decode_euicc_memory_reset_response,
    encode_add_initial_eim_request,
    encode_euicc_memory_reset_request,
    ISD_R_AID,
    MANAGE_CHANNEL_OPEN,
    SCRIPT_LOGICAL_CHANNEL,
)
from yggdrasim_common.apdu_chunking import cla_for_logical_channel, plan_chunked_apdus

TRANSACTION_ID_OCTETS = 8
COUNTER_MAX = 0x7FFFFF
DEFAULT_MAX_RETRIES = 3

SETTING_LEARN = "learn_unknown_eids"
SETTING_RECOVERY = "recover_lost_results"
SETTING_MAX_RETRIES = "max_retries"
SETTING_VERIFY = "result_verification"
SETTING_TLS_KEYLOG = "tls_keylog"
SETTING_SMDS_ADDRESS = smds_module.ADDRESS_SETTING
VERIFY_FLAG = "flag"
VERIFY_DISCARD = "discard"
SETTING_DEFAULTS: dict[str, Any] = {
    # An EID that polls the eIM over ESipa or that a YggdraSIM surface reads from a card is
    # registered without an EUICC ADD (note_detected_eid); off, the eIM answers eidNotFound.
    SETTING_LEARN: True,
    SETTING_RECOVERY: True,
    SETTING_MAX_RETRIES: DEFAULT_MAX_RETRIES,
    SETTING_VERIFY: VERIFY_FLAG,
    # The card-facing listeners append their TLS session secrets to tls-keylog.txt in the store
    # directory (NSS key log format), so Wireshark can decrypt a capture of the sessions; read at
    # service start.
    SETTING_TLS_KEYLOG: False,
    # The FQDN the local SM-DS answers under: an ES11.InitiateAuthentication that names it is the
    # SM-DS's, any other address stays with the SM-DP+ (SGP.22 v3.1 §5.8.1).
    SETTING_SMDS_ADDRESS: smds_module.DEFAULT_ADDRESS,
}

ROUTE_ESIPA = "esipa"
ROUTE_DIRECT = "direct"
ROUTE_EXPORT = "export"
ROUTE_IMPORT = "import"
# The eIM calls ESipa.TransferEimPackage on the IPA (SGP.32 v1.3 §3.1.1.2). Not a poll: next_package
# counts one only for the routes on which the IPA came to fetch.
ROUTE_INJECT = "inject"
# The client certificate the eIM presents to an IPA it calls over HTTPS, under the store directory.
INJECT_CLIENT_DIR = "inject_client"
INJECT_CLIENT_STEM = "eim"
# Flag of a PROFILE_DOWNLOAD_TRIGGER the relay closed itself with what the SM-DS answered over ES11'
# (SGP.32 v1.3 §3.9.2.2): a download result an IPA sends for it afterwards is noted, not applied.
EVENT_RETRIEVAL_CLOSED_FLAG = "event-retrieval-closed"


class LocalEimError(RuntimeError):
    """An operator request the Local eIM cannot carry out."""


@dataclass
class OperationRequest:
    eid: str
    type: str
    params: dict[str, Any] = field(default_factory=dict)
    raw_items: str = ""
    not_before: str | None = None
    max_retries: int | None = None
    fault: str = ""


@dataclass
class PlanEntry:
    eid: str
    type: str
    description: str
    params: dict[str, Any]
    preview_hex: str
    warnings: list[str]
    registered: bool


@dataclass
class Served:
    """What GetEimPackage answers: one package, or an eimPackageError code."""

    package: bytes = b""
    error: int | None = None
    operation: Operation | None = None
    blocked: bool = False

    @property
    def response(self) -> bytes:
        if self.error is not None:
            return codec.build_get_eim_package_error(self.error)
        return codec.build_get_eim_package_response(self.package)


@dataclass
class Accepted:
    """What ProvideEimPackageResult answers, with what the result did."""

    acknowledgements: list[int] = field(default_factory=list)
    operation: Operation | None = None
    messages: list[str] = field(default_factory=list)
    error: int | None = None
    # Notifications this result put on the record: a service forwards after it answered.
    notifications: int = 0

    @property
    def response(self) -> bytes:
        return codec.build_provide_result_response(self.acknowledgements, error=self.error)


def parse_time(value: str | None) -> datetime.datetime | None:
    if value is None or len(str(value).strip()) == 0:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.datetime.fromisoformat(text)
    except ValueError as error:
        raise OperationError(f"Not an ISO 8601 time: {value!r}.") from error
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.astimezone(datetime.timezone.utc)


def _iso(moment: datetime.datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.replace(microsecond=0).isoformat()


def _event(operation: Operation, text: str) -> None:
    operation.history.append({"at": utc_now(), "event": text})


class LocalEim:
    """One Local eIM: an identity, a store, and the queue rules above."""

    def __init__(self, directory: Path | None = None, *, clock: Callable[[], datetime.datetime] | None = None) -> None:
        self.directory = Path(directory) if directory is not None else store_directory()
        self.store = EimStore(self.directory / DATABASE_FILE)
        self._clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))

    # ------------------------------------------------------------------
    # Settings and identity
    # ------------------------------------------------------------------

    def setting(self, key: str) -> Any:
        return self.store.setting(key, SETTING_DEFAULTS.get(key))

    def settings(self) -> dict[str, Any]:
        values = dict(SETTING_DEFAULTS)
        values.update(self.store.settings())
        return values

    def set_setting(self, key: str, value: Any) -> Any:
        if key not in SETTING_DEFAULTS:
            raise LocalEimError(f"Unknown setting {key!r}; known: {', '.join(SETTING_DEFAULTS)}.")
        if key in (SETTING_LEARN, SETTING_RECOVERY, SETTING_TLS_KEYLOG):
            from SCP11.eim_local.engine.catalogue import parse_bool

            value = parse_bool(value, key)
        elif key == SETTING_MAX_RETRIES:
            from SCP11.eim_local.engine.catalogue import parse_int

            value = max(0, parse_int(value, key))
        elif key == SETTING_VERIFY:
            value = str(value).strip().lower()
            if value not in (VERIFY_FLAG, VERIFY_DISCARD):
                raise LocalEimError(f"{key} is {VERIFY_FLAG!r} or {VERIFY_DISCARD!r}.")
        elif key == SETTING_SMDS_ADDRESS:
            try:
                value = smds_module.host_name(value, key)
            except smds_module.SmdsError as error:
                raise LocalEimError(str(error)) from error
        self.store.set_setting(key, value)
        return value

    def identity(self) -> EimIdentity:
        identity = load_identity(self.directory)
        if identity is None:
            raise IdentityError("The Local eIM has no identity yet: run IDENTITY NEW (or IDENTITY IMPORT).")
        return identity

    def identity_or_none(self) -> EimIdentity | None:
        try:
            return load_identity(self.directory)
        except IdentityError:
            return None

    def new_identity(self, *, eim_id: str = "", eim_fqdn: str = "", eim_id_type: int | None = None) -> EimIdentity:
        return generate_identity(
            self.directory,
            eim_id=eim_id or EXAMPLE_EIM_ID,
            eim_fqdn=eim_fqdn or DEFAULT_EIM_FQDN,
            eim_id_type=eim_id_type,
        )

    def import_identity(self, **values: Any) -> EimIdentity:
        return import_identity(self.directory, **values)

    # ------------------------------------------------------------------
    # eUICC records
    # ------------------------------------------------------------------

    def record(self, eid: str) -> EuiccRecord | None:
        return self.store.record(codec.normalize_eid(eid))

    def records(self) -> list[EuiccRecord]:
        return self.store.records()

    def register(self, eid: str, *, label: str = "") -> EuiccRecord:
        normalized = codec.normalize_eid(eid)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None:
                record = EuiccRecord(eid=normalized, label=label, created_at=utc_now())
                self.store.insert_record(record, connection)
            elif len(label) > 0:
                record.label = label
                self.store.save_record(record, connection)
        return record

    def note_detected_eid(self, eid: str, *, source: str) -> EuiccRecord | None:
        """Register an EID a YggdraSIM surface read from a card; None when it is known or learning is off.

        The record keeps where and when the EID was first seen. A malformed EID raises ValueError.
        """
        normalized = codec.normalize_eid(eid)
        if not bool(self.setting(SETTING_LEARN)):
            return None
        with self.store.transaction() as connection:
            if self.store.record(normalized, connection) is not None:
                return None
            record = EuiccRecord(eid=normalized, label=f"detected by {source}", created_at=utc_now())
            record.data["first_seen"] = {"by": source, "at": record.created_at}
            self.store.insert_record(record, connection)
        return record

    def remove(self, eid: str) -> int:
        return self.store.delete_record(codec.normalize_eid(eid))

    def update_record(self, eid: str, changes: dict[str, Any]) -> EuiccRecord:
        """Set record fields by hand: label, associationToken, counterValue, seqNumber, associated, and the
        eUICC certificate chain beyond nextCertInChain (otherCertsInChain, SGP.22 v3.1 5.7.13) as hex."""
        normalized = codec.normalize_eid(eid)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None:
                raise StoreError(f"No eUICC {normalized}.")
            for key, value in changes.items():
                name = str(key).strip().lower().replace("-", "_")
                if name == "label":
                    record.label = str(value)
                elif name in ("association_token", "token"):
                    record.association_token = None if str(value).strip().lower() in ("", "none") else int(value)
                elif name in ("counter_value", "counter"):
                    record.counter_value = int(value)
                elif name in ("seq_number", "seq"):
                    record.seq_number = None if str(value).strip().lower() in ("", "none") else int(value)
                elif name == "associated":
                    from SCP11.eim_local.engine.catalogue import parse_bool

                    record.data["associated"] = parse_bool(value, name)
                elif name in ("other_certs_in_chain", "other_certs_in_chain_hex"):
                    chain = "".join(str(value).split()).upper()
                    if chain == "":
                        record.data.pop("other_certs_in_chain_hex", None)
                    else:
                        try:
                            certificates = bytes.fromhex(chain)
                        except ValueError as error:
                            raise LocalEimError(f"{key} is not hex: {error}") from error
                        if len(certificates) == 0 or certificates[0] != 0x30:
                            raise LocalEimError(f"{key} must be one or more DER certificates ('30' ...).")
                        record.data["other_certs_in_chain_hex"] = chain
                else:
                    raise LocalEimError(
                        f"Unknown record field {key!r}; known: label, association_token, counter_value, "
                        "seq_number, associated, other_certs_in_chain."
                    )
            self.store.save_record(record, connection)
        return record

    def inject_target(self, eid: str) -> dict[str, str] | None:
        """Where the IPA of *eid* takes ESipa.TransferEimPackage: ``{"url", "binding"}``, or None."""
        record = self.store.record(codec.normalize_eid(eid))
        target = record.data.get("inject_target") if record is not None else None
        if not isinstance(target, dict) or not target.get("url"):
            return None
        return {"url": str(target["url"]), "binding": str(target.get("binding") or "asn1")}

    def set_inject_target(self, eid: str, url: str, binding: str = "asn1") -> EuiccRecord:
        """Keep the address the Local eIM injects to for *eid*; ``url`` empty clears it."""
        from SCP11.eim_local.engine.inject import InjectError, parse_target

        normalized = codec.normalize_eid(eid)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None:
                raise StoreError(f"No eUICC {normalized}.")
            if str(url or "").strip() == "":
                record.data.pop("inject_target", None)
            else:
                try:
                    record.data["inject_target"] = parse_target(url, binding).as_dict()
                except InjectError as error:
                    raise LocalEimError(str(error)) from error
            self.store.save_record(record, connection)
        return record

    def inject_client_pair(self) -> tuple[Path, Path] | None:
        """The client certificate and key this Local eIM presents to an IPA over HTTPS; None before they are made."""
        from SCP11.shared import tls_identity

        certificate, key = tls_identity.pair_paths(self.directory / INJECT_CLIENT_DIR, INJECT_CLIENT_STEM)
        if certificate.is_file() and key.is_file():
            return certificate, key
        return None

    def make_inject_client_pair(self) -> tuple[Path, Path]:
        """Make that pair once: self-signed, named after the eIM; a pair that exists is returned as it is.

        The IPA authenticates the eIM (SGP.32 v1.3 section 3.1.2.1). An IPA
        that listens over HTTPS does it by this certificate, which the
        operator names there.
        """
        from SCP11.shared import tls_identity

        existing = self.inject_client_pair()
        if existing is not None:
            return existing
        identity = self.identity_or_none()
        if identity is None:
            raise LocalEimError("No eIM identity yet; IDENTITY NEW makes one.")
        fqdn = str(getattr(identity, "eim_fqdn", "") or "").strip()
        common_name = (fqdn or str(identity.eim_id))[:64]
        try:
            names = [fqdn] if fqdn else []
            certificate, key = tls_identity.issue_self_signed(common_name, names, role=tls_identity.ROLE_CLIENT)
            return tls_identity.write_pair(self.directory / INJECT_CLIENT_DIR, INJECT_CLIENT_STEM, certificate, key)
        except tls_identity.TlsIdentityError as error:
            raise LocalEimError(str(error)) from error

    def ask_for_certificate_again(self, eid: str) -> None:
        """Let the next signed operation of *eid* ask for the eUICC certificate once more.

        The engine asks once per record. An answer that was not this eUICC's
        (an injection sent to another card's IPA) must not count as that one
        time, or every later result stays unverified.
        """
        normalized = codec.normalize_eid(eid)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None or len(record.euicc_certificate) > 0:
                return
            if record.data.pop("certificate_requested", None) is not None:
                self.store.save_record(record, connection)

    def apply_card_reads(self, eid: str, reads: dict[str, Any]) -> EuiccRecord:
        """Fold a direct card read (profiles, eIMs, certificates, configured data) into the record."""
        normalized = codec.normalize_eid(eid)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None:
                record = EuiccRecord(eid=normalized, created_at=utc_now())
                self.store.insert_record(record, connection)
            now = utc_now()
            refreshed = record.data.setdefault("refreshed", {})
            if "profiles" in reads:
                record.data["profiles"] = reads["profiles"]
                refreshed["profiles"] = now
            if "eims" in reads:
                record.data["eims"] = reads["eims"]
                refreshed["eims"] = now
                identity = self.identity_or_none()
                if identity is not None:
                    ours = [entry for entry in reads["eims"] if entry.get("eim_id") == identity.eim_id]
                    record.data["associated"] = len(ours) > 0
                    if ours and ours[0].get("association_token") is not None:
                        record.association_token = int(ours[0]["association_token"])
                    if ours and ours[0].get("counter_value") is not None:
                        record.counter_value = max(record.counter_value, int(ours[0]["counter_value"]))
            if reads.get("euicc_certificate"):
                record.euicc_certificate = bytes(reads["euicc_certificate"])
            if reads.get("eum_certificate"):
                record.eum_certificate = bytes(reads["eum_certificate"])
            for key in ("default_smdp_address", "root_smds_address", "euicc_info2_hex", "euicc_info1_hex"):
                if key in reads:
                    record.data[key] = reads[key]
            self.store.save_record(record, connection)
        return record

    # ------------------------------------------------------------------
    # Submitting and editing
    # ------------------------------------------------------------------

    def _check(self, request: OperationRequest) -> tuple[OperationType, dict[str, Any], bytes, list[str]]:
        kind = operation_type(request.type)
        values, configuration_notes = expand_eim_configuration(kind, request.params)
        params = normalize_params(kind, values)
        raw_items = codec_hex(request.raw_items)
        record = self.store.record(codec.normalize_eid(request.eid))
        if kind.signed:
            items = build_items(kind, params, raw_items, record=record)
            preview = items
        else:
            if len(raw_items) > 0:
                raise OperationError(f"{kind.name} is not a signed eUICC Package; raw items do not apply.")
            preview = build_unsigned_request(kind, params, b"")
            items = b""
        warnings = precondition_warnings(kind, params, record, self.identity_or_none())
        warnings.extend(package_rule_warnings(kind, items))
        warnings.extend(configuration_notes)
        if request.fault:
            if not kind.signed:
                raise OperationError("Faults are injected into signed eUICC Packages only.")
            warnings.append(fault_warning(request.fault))
        parse_time(request.not_before)
        return kind, params, preview, warnings

    def plan(self, requests: list[OperationRequest]) -> list[PlanEntry]:
        """Validate and describe without storing anything."""
        entries: list[PlanEntry] = []
        for request in requests:
            kind, params, preview, warnings = self._check(request)
            eid = codec.normalize_eid(request.eid)
            entries.append(
                PlanEntry(
                    eid=eid,
                    type=kind.name,
                    description=describe(kind, params),
                    params=params,
                    preview_hex=preview.hex().upper(),
                    warnings=warnings,
                    registered=self.store.record(eid) is not None,
                )
            )
        return entries

    def submit(
        self,
        requests: list[OperationRequest],
        *,
        author: str = "operator",
        summary: str = "",
        first: bool = False,
    ) -> list[Operation]:
        """Queue the operations as one task; failed preconditions only add warnings."""
        checked = [(request, *self._check(request)) for request in requests]
        if len(checked) == 0:
            raise LocalEimError("Nothing to queue.")
        created: list[Operation] = []
        default_retries = int(self.setting(SETTING_MAX_RETRIES))
        with self.store.transaction() as connection:
            task_id = self.store.insert_task(
                connection,
                author=author,
                summary=summary or "; ".join(describe(kind, params) for _r, kind, params, _p, _w in checked[:3]),
            )
            for request, kind, params, _preview, warnings in checked:
                eid = codec.normalize_eid(request.eid)
                if self.store.record(eid, connection) is None:
                    self.store.insert_record(EuiccRecord(eid=eid, created_at=utc_now()), connection)
                position = (
                    self.store.first_position(eid, connection) if first else self.store.next_position(eid, connection)
                )
                operation = Operation(
                    id=0,
                    task_id=task_id,
                    eid=eid,
                    type=kind.name,
                    state=STATE_CREATED,
                    position=position,
                    params=params,
                    raw_items=codec_hex(request.raw_items),
                    max_retries=default_retries if request.max_retries is None else max(0, int(request.max_retries)),
                    not_before=_iso(parse_time(request.not_before)),
                    transaction_id=os.urandom(TRANSACTION_ID_OCTETS).hex().upper(),
                    created_at=utc_now(),
                    warnings=list(warnings),
                    fault=request.fault,
                    author=author,
                )
                _event(operation, f"created by {author}: {describe(kind, params)}")
                operation.id = self.store.insert_operation(operation, connection)
                created.append(operation)
        self.store.prune()
        return created

    def edit(self, operation_id: int, changes: dict[str, Any]) -> Operation:
        """Change a CREATED operation: parameters, raw items, type, not-before, retries, fault.

        Parameter names are merged; an empty value removes one. ``raw_items``
        replaces the built PSMO / eCO items (empty restores the built ones).
        """
        changes = dict(changes)
        with self.store.transaction() as connection:
            operation = self.store.operation(operation_id, connection)
            retry_only = {str(key).strip().lower().replace("-", "_") for key in changes} <= {"max_retries", "retries"}
            if operation.state == STATE_SENT and retry_only and changes:
                from SCP11.eim_local.engine.catalogue import parse_int

                operation.max_retries = max(0, parse_int(next(iter(changes.values())), "max_retries"))
                _event(operation, f"edited while in flight: max retries {operation.max_retries}")
                self.store.save_operation(operation, connection)
                return operation
            if operation.state != STATE_CREATED:
                raise LocalEimError(
                    f"Operation {operation_id} is {operation.state}; only a CREATED operation is edited "
                    "(a SENT one only its max_retries; COPY makes an editable copy of any operation)."
                )
            type_change = changes.pop("type", None)
            kind = operation_type(type_change if type_change else operation.type)
            notes: list[str] = []
            param_changes: dict[str, Any] = {}
            for key, value in changes.items():
                name = str(key).strip().lower().replace("-", "_")
                if name in ("raw_items", "items_hex"):
                    operation.raw_items = codec_hex(value)
                    notes.append("raw items " + ("set" if operation.raw_items else "cleared"))
                elif name in ("not_before", "at"):
                    operation.not_before = _iso(parse_time(value))
                    notes.append(f"not before {operation.not_before or 'cleared'}")
                elif name in ("max_retries", "retries"):
                    from SCP11.eim_local.engine.catalogue import parse_int

                    operation.max_retries = max(0, parse_int(value, name))
                    notes.append(f"max retries {operation.max_retries}")
                elif name == "fault":
                    operation.fault = str(value or "").strip()
                    if operation.fault:
                        fault_warning(operation.fault)
                    notes.append(f"fault {operation.fault or 'cleared'}")
                else:
                    param_changes[name] = value
            if kind.name != operation.type:
                notes.append(f"type {operation.type} -> {kind.name}")
                operation.type = kind.name
                base: dict[str, Any] = {}
            else:
                base = dict(operation.params)
            param_changes, configuration_notes = expand_eim_configuration(kind, param_changes, replace=True)
            notes.extend(configuration_notes)
            updates = normalize_params(kind, param_changes, partial=True)
            for name, value in updates.items():
                old = base.get(name)
                if value is None:
                    base.pop(name, None)
                    notes.append(f"{name} removed")
                else:
                    base[name] = value
                    notes.append(f"{name} {old!r} -> {value!r}")
            params = normalize_params(kind, base)
            record = self.store.record(operation.eid, connection)
            if kind.signed:
                items = build_items(kind, params, operation.raw_items, record=record)
            else:
                if operation.raw_items:
                    raise OperationError(f"{kind.name} is not a signed eUICC Package; raw items do not apply.")
                build_unsigned_request(kind, params, b"")
                items = b""
            operation.params = params
            operation.warnings = precondition_warnings(kind, params, record, self.identity_or_none())
            operation.warnings.extend(package_rule_warnings(kind, items))
            if operation.fault:
                operation.warnings.append(fault_warning(operation.fault))
            _event(operation, "edited: " + ("; ".join(notes) if notes else "no change"))
            self.store.save_operation(operation, connection)
        return operation

    def move(self, operation_id: int, where: str, other_id: int | None = None) -> list[Operation]:
        """Reorder a CREATED operation within its eUICC's queue: first, last, up, down, before or after another."""
        with self.store.transaction() as connection:
            operation = self.store.operation(operation_id, connection)
            if operation.state != STATE_CREATED:
                raise LocalEimError(f"Operation {operation_id} is {operation.state}; only CREATED operations move.")
            waiting = [entry for entry in self.store.queue(operation.eid, connection) if entry.state == STATE_CREATED]
            ids = [entry.id for entry in waiting]
            index = ids.index(operation.id)
            ids.pop(index)
            target = where.strip().lower()
            if target == "first":
                ids.insert(0, operation.id)
            elif target == "last":
                ids.append(operation.id)
            elif target == "up":
                ids.insert(max(0, index - 1), operation.id)
            elif target == "down":
                ids.insert(min(len(ids), index + 1), operation.id)
            elif target in ("before", "after"):
                if other_id is None or other_id not in ids:
                    raise LocalEimError(f"{target} needs another CREATED operation of the same eUICC.")
                anchor = ids.index(other_id)
                ids.insert(anchor if target == "before" else anchor + 1, operation.id)
            else:
                raise LocalEimError("Move to first, last, up, down, before <id> or after <id>.")
            by_id = {entry.id: entry for entry in waiting}
            base = min(entry.position for entry in waiting)
            for offset, entry_id in enumerate(ids):
                entry = by_id[entry_id]
                if entry.position != base + offset:
                    entry.position = base + offset
                    if entry_id == operation.id:
                        _event(entry, f"moved {target}")
                    self.store.save_operation(entry, connection)
            return [by_id[entry_id] for entry_id in ids]

    def cancel(self, operation_id: int) -> Operation:
        """Cancel a CREATED operation, or give up on a SENT one (the eUICC may have run it)."""
        with self.store.transaction() as connection:
            operation = self.store.operation(operation_id, connection)
            if operation.final:
                raise LocalEimError(f"Operation {operation_id} is already {operation.state}.")
            if operation.state == STATE_SENT:
                operation.flags.append("canceled-after-serving")
                _event(operation, "canceled after it was served; the eUICC may have executed it")
            else:
                _event(operation, "canceled")
            operation.state = STATE_CANCELED
            operation.finished_at = utc_now()
            self.store.save_operation(operation, connection)
        return operation

    def cancel_eid(self, eid: str) -> list[Operation]:
        normalized = codec.normalize_eid(eid)
        with self.store.transaction() as connection:
            waiting = [entry for entry in self.store.queue(normalized, connection) if entry.state == STATE_CREATED]
        return [self.cancel(entry.id) for entry in waiting]

    def copy(self, operation_id: int, changes: dict[str, Any] | None = None, *, author: str = "operator") -> Operation:
        """Queue a copy of any operation, optionally changed: the RETRY of the portal."""
        source = self.store.operation(operation_id)
        params = dict(source.params)
        request = OperationRequest(
            eid=source.eid,
            type=source.type,
            params=params,
            raw_items=source.raw_items,
            max_retries=source.max_retries,
            fault=source.fault,
        )
        created = self.submit([request], author=author, summary=f"copy of operation {source.id}")[0]
        if changes:
            created = self.edit(created.id, dict(changes))
        return created

    def operation(self, operation_id: int) -> Operation:
        return self.store.operation(operation_id)

    def operations(self, **filters: Any) -> list[Operation]:
        eid = filters.pop("eid", "")
        if eid:
            filters["eid"] = codec.normalize_eid(eid)
        return self.store.operations(**filters)

    def queue(self, eid: str) -> list[Operation]:
        with self.store.transaction() as connection:
            return self.store.queue(codec.normalize_eid(eid), connection)

    def download_for(self, eim_transaction_id: bytes) -> Operation | None:
        """The PROFILE_DOWNLOAD_TRIGGER served with *eim_transaction_id*, whatever its eUICC."""
        if len(eim_transaction_id) == 0:
            return None
        with self.store.transaction() as connection:
            found = self.store.find_by_transaction_any(eim_transaction_id.hex().upper(), connection)
        if found is None or found.type != "PROFILE_DOWNLOAD_TRIGGER":
            return None
        return found

    def note(self, operation_id: int, text: str) -> None:
        """Add an event to an operation's timeline."""
        with self.store.transaction() as connection:
            operation = self.store.operation(operation_id, connection)
            _event(operation, text)
            self.store.save_operation(operation, connection)

    # ------------------------------------------------------------------
    # Serving
    # ------------------------------------------------------------------

    def _system_operation(
        self,
        connection: Any,
        eid: str,
        type_name: str,
        params: dict[str, Any],
        reason: str,
        *,
        recovery_for: int | None = None,
    ) -> Operation:
        kind = operation_type(type_name)
        operation = Operation(
            id=0,
            eid=eid,
            type=kind.name,
            state=STATE_CREATED,
            position=self.store.first_position(eid, connection),
            params=normalize_params(kind, params),
            system=True,
            recovery_for=recovery_for,
            max_retries=0,
            transaction_id=os.urandom(TRANSACTION_ID_OCTETS).hex().upper(),
            created_at=utc_now(),
            author="eIM",
        )
        _event(operation, f"created by the eIM: {reason}")
        operation.id = self.store.insert_operation(operation, connection)
        return operation

    def _now(self) -> datetime.datetime:
        return self._clock()

    def next_package(
        self,
        eid: str,
        *,
        route: str = ROUTE_ESIPA,
        notify_state_change: bool = False,
        state_change_cause: int | None = None,
        only: int | None = None,
        refuse_packages: tuple[str, ...] = (),
    ) -> Served:
        """Answer GetEimPackage for *eid* (SGP.32 v1.3 §5.14.5, p.168-170).

        *refuse_packages* names package kinds the caller cannot run; when the
        next operation is one of them it stays queued and the answer is
        noEimPackageAvailable with ``blocked`` set.
        """
        try:
            normalized = codec.normalize_eid(eid)
        except ValueError:
            return Served(error=codec.INVALID_EID)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None:
                if not bool(self.setting(SETTING_LEARN)):
                    return Served(error=codec.EID_NOT_FOUND)
                record = EuiccRecord(eid=normalized, label="registered on first poll", created_at=utc_now())
                self.store.insert_record(record, connection)
            if route in (ROUTE_ESIPA, ROUTE_DIRECT):
                now_text = utc_now()
                record.first_poll_at = record.first_poll_at or now_text
                record.last_poll_at = now_text
                record.poll_count += 1
                self.store.save_record(record, connection)
            if notify_state_change:
                cause = codec.STATE_CHANGE_CAUSES.get(state_change_cause, str(state_change_cause))
                self._system_operation(
                    connection, normalized, "PROFILE_INFO_LIST", {},
                    f"notifyStateChange (cause {cause}) in GetEimPackage",
                )
            candidate = self._select(connection, record, only=only)
            if candidate is None:
                return Served(error=codec.NO_EIM_PACKAGE_AVAILABLE)
            if operation_type(candidate.type).package in refuse_packages:
                return Served(error=codec.NO_EIM_PACKAGE_AVAILABLE, operation=candidate, blocked=True)
            if operation_type(candidate.type).package == PACKAGE_DEVICE and route != ROUTE_DIRECT:
                # A device-side function runs on the reader (DELIVER); an IPA polling over ESipa cannot take it.
                return Served(error=codec.NO_EIM_PACKAGE_AVAILABLE, operation=candidate, blocked=True)
            try:
                package = self._serve(connection, record, candidate, route)
            except IdentityError as error:
                # A configuration gap, not the operation's fault: it stays queued.
                _event(candidate, f"not served: {error}")
                self.store.save_operation(candidate, connection)
                return Served(error=codec.UNDEFINED_ERROR, operation=candidate)
            except (OperationError, ValueError) as error:
                candidate.state = STATE_ERROR
                candidate.finished_at = utc_now()
                candidate.error = f"not served: {error}"
                _event(candidate, candidate.error)
                self.store.save_operation(candidate, connection)
                return Served(error=codec.UNDEFINED_ERROR, operation=candidate)
            return Served(package=package, operation=candidate)

    def note_state_report(self, eid: str, request: codec.GetEimPackageRequest) -> str:
        """Record what an IPA reports about the eUICC outside a package: its registered PLMN, a state change.

        SGP.32 v1.3 §5.14.5 puts rPLMN and notifyStateChange on
        GetEimPackageRequest. An IPAe that sends them inside
        ProvideEimPackageResult (no EimPackageResult alternative is tagged so,
        §5.14.6) is acknowledged with the empty response, and a reported state
        change queues the same Profile list refresh as GetEimPackage does.
        """
        normalized = codec.normalize_eid(eid)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None:
                return "unknown EID"
            notes: list[str] = []
            if len(request.rplmn) > 0:
                record.data["rplmn_hex"] = request.rplmn.hex().upper()
                record.data["rplmn_reported_at"] = utc_now()
                notes.append(f"rPLMN {record.data['rplmn_hex']}")
            if request.notify_state_change:
                cause = codec.STATE_CHANGE_CAUSES.get(request.state_change_cause, str(request.state_change_cause))
                self._system_operation(
                    connection, normalized, "PROFILE_INFO_LIST", {},
                    f"notifyStateChange (cause {cause}) in a ProvideEimPackageResult",
                )
                notes.append(f"notifyStateChange (cause {cause})")
            self.store.save_record(record, connection)
            return ", ".join(notes) or "nothing new"

    def _select(self, connection: Any, record: EuiccRecord, *, only: int | None = None) -> Operation | None:
        queue = self.store.queue(record.eid, connection)
        sent = sorted((entry for entry in queue if entry.state == STATE_SENT), key=lambda entry: (entry.served_at or "", entry.id))
        if sent:
            in_flight = sent[-1]
            outcome = self._unanswered(connection, record, in_flight, sent)
            if outcome is not None or only is not None:
                return outcome if (only is None or (outcome is not None and outcome.id == only)) else None
            queue = self.store.queue(record.eid, connection)
            if any(entry.state == STATE_SENT and entry.max_retries == 0 for entry in queue):
                return None
        now = self._now()
        for entry in queue:
            if entry.state != STATE_CREATED:
                continue
            if only is not None and entry.id != only:
                continue
            not_before = parse_time(entry.not_before)
            if only is None and not_before is not None and not_before > now:
                continue
            kind = operation_type(entry.type)
            if (
                kind.signed
                and len(record.euicc_certificate) == 0
                and not entry.system
                and only is None
                and not record.data.get("certificate_requested")
            ):
                # Asked once: a card that does not return it gets its packages
                # anyway, and their results are flagged as unverified.
                record.data["certificate_requested"] = utc_now()
                self.store.save_record(record, connection)
                return self._system_operation(
                    connection, record.eid, "IPA_EUICC_DATA", {"tags": CERTIFICATE_TAGS},
                    "the record holds no eUICC certificate to verify results with",
                )
            if (
                entry.type == "PROFILE_DOWNLOAD_TRIGGER"
                and not entry.system
                and only is None
                and record.data.get("download_data_for") != entry.id
            ):
                # Asked before each download: the IPA polling now runs it, and its IPA Capabilities decide
                # the trigger (SGP.32 v1.3 §2.11.1.3) and the answers of an indirect download (§5.14). An
                # eUICC and Device supporting both move between the IPAe and an IPAd (§3.8.4 NOTE, p.100).
                record.data["download_data_for"] = entry.id
                self.store.save_record(record, connection)
                return self._system_operation(
                    connection, record.eid, "IPA_EUICC_DATA", {"tags": compact_forms.download_data_tags(record)},
                    "a download depends on the IPA Capabilities of the IPA that runs it",
                )
            if (
                entry.type == "PROFILE_DOWNLOAD_TRIGGER"
                and not entry.system
                and only is None
                and compact_forms.METADATA_VERIFICATION in compact_forms.record_features(record)
                and self.identity_or_none() is not None
                and record.data.get("associated") is not False
            ):
                # The eIM checks the Profile Metadata of such an IPA against the RAT and the installed
                # Profiles it holds, "obtained prior to the start of this procedure using the PSMOs getRAT
                # and listProfileInfo" (SGP.32 v1.3 §3.2.3.2 step 15); each is asked for once.
                for missing, type_name, marker in (
                    (len(compact_forms.record_bytes(record.data, "rat_hex")) == 0, "GET_RAT", "rat_requested"),
                    ("profiles" not in record.data, "PROFILE_INFO_LIST", "profiles_requested"),
                ):
                    if missing and not record.data.get(marker):
                        record.data[marker] = utc_now()
                        self.store.save_record(record, connection)
                        return self._system_operation(
                            connection, record.eid, type_name, {},
                            "the IPA leaves the Profile Metadata check to the eIM, which lacks this for it",
                        )
            return entry
        return None

    def _unanswered(self, connection: Any, record: EuiccRecord, in_flight: Operation, sent: list[Operation]) -> Operation | None:
        """Decide what to serve while *in_flight* has no result: hold, recover, retry or give up."""
        if in_flight.recovery_for is not None:
            originals = [entry for entry in sent if entry.id == in_flight.recovery_for]
            if originals and self._awaits_refresh(originals[0]):
                # The recovery request stays out as well: the IPA may answer it after the REFRESH.
                self._hold_for_refresh(connection, originals[0])
                return None
            in_flight.state = STATE_ERROR
            in_flight.finished_at = utc_now()
            in_flight.error = "no result"
            _event(in_flight, "no result before the next poll")
            self.store.save_operation(in_flight, connection)
            if not originals:
                return None
            return self._retry(connection, originals[0])
        if in_flight.max_retries == 0 and not in_flight.system:
            held = "held: no result, retries off; waiting for the operator"
            if not in_flight.history or in_flight.history[-1].get("event") != held:
                _event(in_flight, held)
                self.store.save_operation(in_flight, connection)
            return None
        kind = operation_type(in_flight.type)
        if (
            kind.signed
            and bool(self.setting(SETTING_RECOVERY))
            and "recovery-asked" not in in_flight.flags
            and len(record.euicc_certificate) > 0
        ):
            in_flight.flags.append("recovery-asked")
            _event(in_flight, "no result; asking the eUICC for its stored eUICC Package Results")
            self.store.save_operation(in_flight, connection)
            return self._system_operation(
                connection, record.eid, "IPA_EUICC_DATA", {"tags": RECOVERY_TAGS},
                f"recover the result of operation {in_flight.id}", recovery_for=in_flight.id,
            )
        if self._awaits_refresh(in_flight):
            self._hold_for_refresh(connection, in_flight)
            return None
        return self._retry(connection, in_flight)

    @staticmethod
    def _awaits_refresh(operation: Operation) -> bool:
        """Whether *operation*'s package enables or disables a Profile, so its result follows the eUICC's REFRESH.

        SGP.32 v1.3 §3.3.1 steps 8a-8b (p.72-73): the eUICC generates the
        result of such a package upon the Terminal Response to its REFRESH or
        after the reset, and the IPA reports it on a later session. A live
        eUICC's IPAe polled twice in between; a package served again then runs
        the state change twice, so it is never served again by itself.
        """
        if len(operation.served_hex) == 0:
            return False
        try:
            return codec.changes_profile_state(bytes.fromhex(operation.served_hex))
        except ValueError:
            return False

    def _hold_for_refresh(self, connection: Any, operation: Operation) -> None:
        held = ("held: a Profile state change; the IPA reports its result after the eUICC's REFRESH "
                "(SGP.32 v1.3 §3.3.1 step 8a); CANCEL ends the wait")
        if not operation.history or operation.history[-1].get("event") != held:
            _event(operation, held)
            self.store.save_operation(operation, connection)

    def _close_recovery(self, connection: Any, record: EuiccRecord, original: Operation) -> None:
        """A recovery request still out for *original* is finished once the result arrived on its own."""
        for entry in self.store.queue(record.eid, connection):
            if entry.state == STATE_SENT and entry.recovery_for == original.id:
                self._finish(entry, STATE_SUCCESS, f"the result of operation {original.id} arrived without it")
                self.store.save_operation(entry, connection)

    def _retry(self, connection: Any, operation: Operation) -> Operation | None:
        if operation.system and operation.max_retries == 0:
            operation.state = STATE_ERROR
            operation.finished_at = utc_now()
            operation.error = "no result"
            _event(operation, "no result before the next poll")
            self.store.save_operation(operation, connection)
            return None
        if operation.retries >= operation.max_retries:
            operation.state = STATE_ERROR
            operation.finished_at = utc_now()
            operation.error = f"no result after {operation.retries + 1} serves"
            _event(operation, operation.error)
            self.store.save_operation(operation, connection)
            return None
        operation.retries += 1
        operation.state = STATE_CREATED
        operation.flags = [flag for flag in operation.flags if flag != "recovery-asked"]
        operation.position = self.store.first_position(operation.eid, connection)
        _event(operation, f"served again (retry {operation.retries} of {operation.max_retries}): no result")
        self.store.save_operation(operation, connection)
        return operation

    def _serve(self, connection: Any, record: EuiccRecord, operation: Operation, route: str) -> bytes:
        kind = operation_type(operation.type)
        transaction_id = bytes.fromhex(operation.transaction_id)
        if not kind.signed:
            package = build_unsigned_request(kind, operation.params, transaction_id,
                                             ipa_features=compact_forms.record_features(record))
        else:
            identity = self.identity()
            counter = record.counter_value + 1
            if counter > COUNTER_MAX and operation.fault != "counter-overflow":
                raise OperationError(f"counterValue would pass {COUNTER_MAX:#x}; set the record's counter by hand.")
            eim_id = identity.eim_id
            eid = record.eid
            token = record.association_token
            if operation.fault == "stale-counter":
                counter = max(0, record.counter_value)
            elif operation.fault == "counter-overflow":
                counter = COUNTER_MAX + 1
            elif operation.fault == "wrong-eid":
                eid = ("00" * 15) + ("01" if eid[-2:] != "01" else "02")
            elif operation.fault == "unknown-eim":
                eim_id = eim_id + ".unknown"
            signing_token = (token or 0) + 1 if operation.fault == "wrong-token" else token
            items = build_items(kind, operation.params, operation.raw_items, record=record)
            signed = codec.build_euicc_package_signed(
                eim_id=eim_id, eid=eid, counter_value=counter, transaction_id=transaction_id,
                kind=kind.package, items=items,
            )
            signature = codec.sign_raw(identity.signing_key(), codec.signature_input(signed, signing_token))
            if operation.fault == "bad-signature":
                signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
            package = codec.build_euicc_package_request(signed, signature)
            if operation.fault not in ("stale-counter", "counter-overflow"):
                record.counter_value = counter
                self.store.save_record(record, connection)
            operation.counter_value = counter
            operation.association_token = token
        operation.state = STATE_SENT
        operation.served_at = utc_now()
        operation.route = route
        operation.served_hex = package.hex().upper()
        counter_note = f", counterValue {operation.counter_value}" if kind.signed else ""
        _event(operation, f"served over {route}{counter_note}")
        self.store.save_operation(operation, connection)
        return package

    def export(self, operation_id: int) -> tuple[bytes, tuple[ScriptStep, ...]]:
        """Serve one CREATED operation for another IPA: the package and a STORE DATA script."""
        operation = self.store.operation(operation_id)
        if operation.state != STATE_CREATED:
            raise LocalEimError(f"Operation {operation_id} is {operation.state}; only a CREATED one is exported.")
        served = self.next_package(operation.eid, route=ROUTE_EXPORT, only=operation_id)
        if served.operation is None or served.operation.id != operation_id or served.error is not None:
            raise LocalEimError(
                f"Operation {operation_id} could not be served now (another operation of {operation.eid} is in flight)."
            )
        return served.package, store_data_script(served.package)

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def accept_result(self, eid: str, result_tlv: bytes, *, route: str = ROUTE_ESIPA, operation_id: int | None = None) -> Accepted:
        """Process one EimPackageResult (SGP.32 v1.3 §5.14.6, p.170-172)."""
        normalized = codec.normalize_eid(eid) if eid else ""
        result = codec.decode_eim_package_result(result_tlv)
        with self.store.transaction() as connection:
            if not normalized:
                normalized = self._eid_from_result(connection, result)
            record = self.store.record(normalized, connection) if normalized else None
            if record is None:
                # §5.14.6 (p.171): an EID received (or found) but unknown is eidNotFound; no EID and
                # no eUICC identified from the data already available is missingEid.
                if normalized:
                    return Accepted(error=codec.EID_NOT_FOUND, messages=["unknown EID"])
                return Accepted(error=codec.MISSING_EID,
                                messages=["no EID, and no known eimTransactionId in the result"])
            accepted = Accepted()
            if result.kind in ("euicc_package_result", "epr_and_notifications"):
                self._accept_euicc_result(connection, record, result.euicc_package_result, route, accepted, operation_id)
                for notification in result.notifications:
                    self._take_notification(record, notification, accepted, route)
            elif result.kind == "ipa_euicc_data_response":
                self._accept_ipa_data(connection, record, result.raw, route, accepted, operation_id)
            elif result.kind == "profile_download_trigger_result":
                self._accept_download(connection, record, result.raw, route, accepted, operation_id)
            else:
                self._accept_error(connection, record, result, route, accepted, operation_id)
            self.store.save_record(record, connection)
            return accepted

    def complete_device_function(self, operation_id: int, result: codec.DeviceResult, response: bytes) -> Operation:
        """Close a device-side function (SGP.32 v1.3 §5.9.16, §5.9.20, §5.9.21) with the eUICC's answer."""
        with self.store.transaction() as connection:
            operation = self.store.operation(operation_id, connection)
            if operation is None:
                raise LocalEimError(f"No operation {operation_id}.")
            operation.result_hex = bytes(response).hex().upper()
            operation.result = {"kind": "device", "items": [result.describe()]}
            if not result.ok:
                operation.error = result.describe()
            self._finish(operation, STATE_SUCCESS if result.ok else STATE_ERROR, result.describe())
            self.store.save_operation(operation, connection)
            return operation

    def accept_relayed_installation(
        self, operation_id: int, installation_result: bytes, *, verified: bool | None = True,
    ) -> Accepted:
        """Close download *operation_id* with the ProfileInstallationResult 'BF37' of its indirect download.

        The IPA hands it over as a PendingNotification in ESipa.HandleNotification (SGP.32 v1.3
        §3.2.3.2 step 23, p.64); ProfileDownloadTriggerResult informs the eIM about a direct download
        only (§2.11.2.3, p.44). *verified* None is a result whose eUICC signature could not be checked
        (no certificate on record); the operation is flagged unverified.
        """
        with self.store.transaction() as connection:
            operation = self.store.operation(operation_id, connection)
            if operation is None or operation.type != "PROFILE_DOWNLOAD_TRIGGER":
                return Accepted(messages=[f"no download operation {operation_id}"])
            record = self.store.record(operation.eid, connection)
            if record is None:
                return Accepted(error=codec.EID_NOT_FOUND, messages=["unknown EID"])
            accepted = Accepted()
            raw = codec.tlv(codec.TAG_PROFILE_DOWNLOAD_TRIGGER,
                            codec.tlv(b"\x82", bytes.fromhex(operation.transaction_id)) + bytes(installation_result))
            self._accept_download(connection, record, raw, ROUTE_ESIPA, accepted, operation.id, relayed=True)
            closed = accepted.operation
            if verified is None and closed is not None and "unverified" not in closed.flags:
                closed.flags.append("unverified")
                _event(closed, "ProfileInstallationResult signature not checked: no eUICC certificate on record")
                self.store.save_operation(closed, connection)
            self.store.save_record(record, connection)
            return accepted

    def complete_event_retrieval(
        self, operation_id: int, events: list[dict[str, str]], *, smds_oid: str = "", error: str = "",
    ) -> list[Operation]:
        """Close SM-DS retrieval *operation_id* with the Event Records the relay got over ES11', and queue an
        indirect download per record at the front of the queue, in the order received (SGP.22 v3.1 3.6.2
        step 10, p.158): the EventID is its Matching ID and the SM-DS OID the Matching ID source (3.1.3,
        p.101). The first one is excused from the IPA data refresh so that it can ride in the
        ESipa.AuthenticateClient answer (SGP.32 v1.3 3.9.2.2 step 14). *error* fails the retrieval instead.
        """
        with self.store.transaction() as connection:
            operation = self.store.operation(operation_id, connection)
            if operation is None or operation.type != "PROFILE_DOWNLOAD_TRIGGER":
                return []
            # The mark _accept_download reads: this operation's outcome is the relay's, on either branch.
            if EVENT_RETRIEVAL_CLOSED_FLAG not in operation.flags:
                operation.flags.append(EVENT_RETRIEVAL_CLOSED_FLAG)
            if error:
                operation.error = error
                self._finish(operation, STATE_ERROR, f"SM-DS event retrieval failed: {error}")
            else:
                operation.result = {"events": [dict(event) for event in events]}
                self._finish(operation, STATE_SUCCESS, f"{len(events)} Event Record(s) from the SM-DS")
            self.store.save_operation(operation, connection)
            eid = operation.eid
        if error or len(events) == 0:
            return []
        requests = [OperationRequest(eid=eid, type="PROFILE_DOWNLOAD_TRIGGER", params={
            "activation_code": f"1${event['rspServerAddress']}${event['eventId']}", "indirect": True,
            "event_id": str(event["eventId"]), "smds_oid": smds_oid,
        }) for event in events]
        # first=True puts each request at the front, so the last one submitted leads: submit in reverse
        queued = list(reversed(self.submit(
            list(reversed(requests)), author="eim",
            summary=f"{len(requests)} download(s) from SM-DS Event Records", first=True,
        )))
        with self.store.transaction() as connection:
            record = self.store.record(eid, connection)
            if record is not None:
                record.data["download_data_for"] = queued[0].id
                self.store.save_record(record, connection)
        return queued

    def accept_notification(self, eid: str, notification: bytes, *, route: str = ROUTE_ESIPA) -> Accepted:
        """Take a PendingNotification that arrived through ESipa.HandleNotification (SGP.32 v1.3 §5.14.7)."""
        normalized = codec.normalize_eid(eid)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None:
                return Accepted(error=codec.EID_NOT_FOUND)
            accepted = Accepted()
            self._take_notification(record, notification, accepted, route)
            self.store.save_record(record, connection)
            return accepted

    def notification_owner(self, notification: bytes) -> str:
        """The EID of the eUICC that signed *notification*, or '' when no record's certificate verifies it.

        ESipa.HandleNotification carries no EID (SGP.32 v1.3 §5.14.7). The
        eidValue of a compactOtherSignedNotification only says where to look
        first: the signature decides.
        """
        try:
            view = outbox.read(notification)
        except outbox.NotificationError:
            return ""
        records = self.store.records()
        if view.eid:
            records.sort(key=lambda record: record.eid != view.eid)
        for record in records:
            if record.euicc_certificate and not outbox.unverified(view, record.euicc_certificate):
                return record.eid
        return ""

    def notifications(self, eid: str = "") -> list[dict[str, Any]]:
        """The Notifications on record (rows without their octets), for one eUICC or all."""
        return outbox.listing(self, codec.normalize_eid(eid) if eid else "")

    def forward_notifications(
        self,
        eid: str = "",
        *,
        seq_numbers: Any = (),
        sender: outbox.Sender | None = None,
        explicit: bool = False,
    ) -> list[outbox.Outcome]:
        """Send due Notifications to their receivers (``notifications.forward``), on this engine's clock."""
        return outbox.forward(self, codec.normalize_eid(eid) if eid else "", seq_numbers=seq_numbers,
                              sender=sender, explicit=explicit, now=self._clock())

    def import_result(self, operation_id: int, result_hex: str) -> Accepted:
        """Close an operation with a result obtained outside the Local eIM (an EimPackageResult in hex)."""
        operation = self.store.operation(operation_id)
        return self.accept_result(operation.eid, bytes.fromhex(codec_hex(result_hex)), route=ROUTE_IMPORT,
                                  operation_id=operation_id)

    def _eid_from_result(self, connection: Any, result: codec.EimPackageResult) -> str:
        transaction_id = b""
        if len(result.euicc_package_result) > 0:
            try:
                transaction_id = codec.decode_euicc_package_result(result.euicc_package_result).transaction_id
            except codec.CodecError:
                transaction_id = b""
        elif len(result.transaction_id) > 0:
            transaction_id = result.transaction_id
        if len(transaction_id) == 0:
            return ""
        row = connection.execute(
            "SELECT eid FROM operation WHERE transaction_id = ? ORDER BY id DESC LIMIT 1",
            (transaction_id.hex().upper(),),
        ).fetchone()
        return "" if row is None else str(row["eid"])

    def _target(
        self,
        connection: Any,
        record: EuiccRecord,
        transaction_id: bytes,
        *,
        counter_value: int | None = None,
        types: tuple[str, ...] = (),
        operation_id: int | None = None,
    ) -> Operation | None:
        if operation_id is not None:
            return self.store.operation(operation_id, connection)
        if len(transaction_id) > 0:
            found = self.store.find_by_transaction(record.eid, transaction_id.hex().upper(), connection)
            if found is not None:
                return found
        if counter_value is not None:
            found = self.store.find_by_counter(record.eid, counter_value, connection)
            if found is not None:
                return found
        for entry in self.store.queue(record.eid, connection):
            if entry.state == STATE_SENT and (not types or entry.type in types):
                return entry
        return None

    def _finish(self, operation: Operation, state: str, text: str) -> None:
        if operation.final:
            operation.flags.append("late-result")
            _event(operation, f"late result after {operation.state}: {text}")
            return
        operation.state = state
        operation.finished_at = utc_now()
        _event(operation, text)

    def _verify(self, record: EuiccRecord, operation: Operation | None, decoded: codec.EuiccPackageResult) -> list[str]:
        problems: list[str] = []
        token = operation.association_token if operation is not None else record.association_token
        if decoded.signed:
            if len(record.euicc_certificate) == 0:
                problems.append("no eUICC certificate on the record; signature not checked")
            else:
                try:
                    if not codec.verify_euicc_package_result(decoded, record.euicc_certificate, token):
                        problems.append("eUICC signature does not verify")
                except codec.CodecError as error:
                    problems.append(f"eUICC certificate unusable: {error}")
        if decoded.kind == "result" and decoded.seq_number is not None and record.seq_number is not None:
            if decoded.seq_number <= record.seq_number:
                problems.append(f"seqNumber {decoded.seq_number} is not greater than {record.seq_number}")
        return problems

    def _accept_euicc_result(
        self,
        connection: Any,
        record: EuiccRecord,
        raw: bytes,
        route: str,
        accepted: Accepted,
        operation_id: int | None,
        *,
        recovered_by: Operation | None = None,
    ) -> None:
        decoded = codec.decode_euicc_package_result(raw)
        operation = self._target(
            connection, record, decoded.transaction_id, counter_value=decoded.counter_value, operation_id=operation_id,
        )
        problems = self._verify(record, operation, decoded)
        discard = bool(problems) and self.setting(SETTING_VERIFY) == VERIFY_DISCARD and decoded.signed
        if operation is None:
            accepted.messages.append(f"result for no known operation (eimTransactionId {decoded.transaction_id.hex().upper()})")
        if discard:
            accepted.messages.append("result discarded: " + "; ".join(problems))
            if operation is not None:
                operation.flags.append("result-discarded")
                operation.result_hex = raw.hex().upper()
                _event(operation, "result discarded: " + "; ".join(problems))
                self.store.save_operation(operation, connection)
            return
        if decoded.kind == "result" and decoded.seq_number is not None:
            accepted.acknowledgements.append(decoded.seq_number)
            if record.seq_number is None or decoded.seq_number > record.seq_number:
                record.seq_number = decoded.seq_number
        if decoded.kind == "error_unsigned" and decoded.association_token is not None:
            if decoded.association_token != record.association_token:
                accepted.messages.append(
                    f"the eUICC reports associationToken {decoded.association_token}; the record now uses it"
                )
                record.association_token = decoded.association_token
        if operation is None:
            return
        operation.result_hex = raw.hex().upper()
        operation.result = _result_summary(decoded)
        if problems:
            operation.flags.extend(flag for flag in ("unverified",) if flag not in operation.flags)
            operation.warnings.extend(problems)
        if recovered_by is not None:
            operation.flags.append(f"recovered-by-{recovered_by.id}")
        state, text = _verdict(decoded)
        if route == ROUTE_IMPORT:
            text += " (imported)"
        was_open = not operation.final
        self._finish(operation, state, text)
        if state in (STATE_SUCCESS, STATE_PARTIAL_SUCCESS) and decoded.kind == "result":
            self._apply_items(record, operation, decoded)
        accepted.operation = operation
        accepted.messages.append(f"operation {operation.id}: {text}")
        if was_open and decoded.kind == "result":
            # An imported result closes an operation another IPA ran by hand, a recovered one was read back
            # from the eUICC's stored results: both tell what the eUICC made of the tagList, neither queues.
            self._note_profile_list_answer(
                connection, record, operation, decoded, accepted,
                ask_again=recovered_by is None and route != ROUTE_IMPORT,
            )
        self.store.save_operation(operation, connection)
        if was_open and recovered_by is None:
            self._close_recovery(connection, record, operation)

    def _note_profile_list_answer(
        self,
        connection: Any,
        record: EuiccRecord,
        operation: Operation,
        decoded: codec.EuiccPackageResult,
        accepted: Accepted,
        *,
        ask_again: bool,
    ) -> None:
        """Keep what the eUICC made of the tagList the eIM chose for a List profiles.

        SGP.22 v3.1 §5.7.15 names the tags an eUICC supports in a tagList and
        does not say what it answers to another one; a card of SGP.32 v1.2
        answered the list of the v1.3 ProfileInfo with incorrectInputValues.
        A list the eIM chose and the eUICC refused that way is kept on the
        record, so the next List profiles without ``tags`` goes without a
        tagList, and such a refused operation is asked again without one, once
        (*ask_again*). A tagList given by hand is the operator's and is neither
        kept nor repeated; the same list accepted later clears the entry. A
        request with a search criterion is repeated and not kept: its refusal
        does not say which of the two the eUICC objected to.
        """
        if operation.type != "PROFILE_INFO_LIST" or operation.raw_items or operation.fault:
            return
        answers = [item for item in decoded.items if item.name == "listProfileInfoResult"]
        sent = codec.list_profile_info_tag_list(bytes.fromhex(operation.served_hex or ""))
        if len(answers) != 1 or not sent:
            return
        answer = answers[0]
        asked = str(operation.params.get("tags") or "")
        if answer.ok:
            if refused_tag_list(record) == sent:
                record.data.pop(REFUSED_TAG_LIST, None)
                _event(operation, f"the eUICC accepted the tagList {sent} it had refused before")
            return
        if answer.code != codec.PROFILE_INFO_LIST_INCORRECT_INPUT or asked not in ("", TAG_LIST_ALL):
            return
        criterion = operation.params.get("iccid")
        note = f"the eUICC refused the tagList {sent} (incorrectInputValues)"
        kept = ""
        if not criterion:
            record.data[REFUSED_TAG_LIST] = {
                "tags": sent, "at": operation.finished_at or utc_now(), "operation": operation.id,
            }
            kept = "; a List profiles without tags goes without a tagList from now on"
        if asked == TAG_LIST_ALL or not ask_again:
            _event(operation, f"{note}{kept}")
            accepted.messages.append(f"operation {operation.id}: {note}{kept}")
            return
        params: dict[str, Any] = {"tags": TAG_LIST_DEFAULT}
        if criterion:
            params["iccid"] = criterion
        again = self._system_operation(
            connection, record.eid, "PROFILE_INFO_LIST", params,
            f"{note} of operation {operation.id}; asked again without one, for the eUICC's own default set",
        )
        _event(operation, f"{note}; operation {again.id} asks again without one")
        accepted.messages.append(f"operation {operation.id}: {note}; operation {again.id} asks again without one")

    def _apply_items(self, record: EuiccRecord, operation: Operation, decoded: codec.EuiccPackageResult) -> None:
        """Update the record from the ok results."""
        params = operation.params
        now = utc_now()
        refreshed = record.data.setdefault("refreshed", {})
        identity = self.identity_or_none()
        for item in decoded.items:
            if not item.ok:
                continue
            iccid = params.get("iccid")
            profiles = record.data.get("profiles")
            if item.name == "listProfileInfoResult":
                record.data["profiles"] = item.detail.get("profiles", [])
                refreshed["profiles"] = now
            elif item.name == "listEimResult":
                record.data["eims"] = item.detail.get("eims", [])
                refreshed["eims"] = now
            elif item.name == "enableResult" and isinstance(profiles, list) and iccid:
                for profile in profiles:
                    profile["state"] = "enabled" if _same_iccid(profile, iccid) else "disabled"
            elif item.name == "disableResult" and isinstance(profiles, list) and iccid:
                for profile in profiles:
                    if _same_iccid(profile, iccid):
                        profile["state"] = "disabled"
            elif item.name == "deleteResult" and isinstance(profiles, list) and iccid:
                record.data["profiles"] = [profile for profile in profiles if not _same_iccid(profile, iccid)]
            elif item.name == "setFallbackAttributeResult" and isinstance(profiles, list) and iccid:
                for profile in profiles:
                    profile["fallback"] = _same_iccid(profile, iccid)
            elif item.name == "unsetFallbackAttributeResult" and isinstance(profiles, list):
                for profile in profiles:
                    profile["fallback"] = False
            elif item.name == "configureImmediateEnableResult":
                record.data["immediate_enable"] = bool(params.get("enabled"))
                if params.get("default_smdp_address"):
                    record.data["default_smdp_address"] = params["default_smdp_address"]
            elif item.name == "setDefaultDpAddressResult":
                record.data["default_smdp_address"] = params.get("address", "")
            elif item.name == "getRATResult":
                record.data["rat_hex"] = item.detail.get("rat_hex", "")
            elif item.name == "listEimResult":
                record.data["eims"] = item.detail.get("eims", [])
                refreshed["eims"] = now
                if identity is not None:
                    record.data["associated"] = any(entry.get("eim_id") == identity.eim_id for entry in record.eims)
            elif item.name == "addEimResult":
                eims = record.data.setdefault("eims", [])
                entry: dict[str, Any] = {"eim_id": params.get("eim_id", "")}
                if item.detail.get("association_token") is not None:
                    entry["association_token"] = item.detail["association_token"]
                eims.append(entry)
            elif item.name == "deleteEimResult":
                record.data["eims"] = [entry for entry in record.eims if entry.get("eim_id") != params.get("eim_id")]
                if identity is not None and params.get("eim_id") == identity.eim_id:
                    record.data["associated"] = False
            elif item.name == "updateEimResult":
                if identity is not None and params.get("eim_id") == identity.eim_id and params.get("counter_value") is not None:
                    record.counter_value = int(params["counter_value"])

    def _ours(self, eim_id: str) -> bool:
        identity = self.identity_or_none()
        return identity is not None and identity.eim_id == eim_id

    def _take_notification(self, record: EuiccRecord, notification: bytes, accepted: Accepted, route: str) -> None:
        """Put a Notification on the record and acknowledge it; sending it on is ``forward_notifications``.

        SGP.32 v1.3 §3.7 (Figure 27, step 2b) has the eIM acknowledge the IPA
        and then call ES9+'.HandleNotification, so the eUICC may drop a
        Notification the receiver has not seen yet: it stays here until then.
        The list of an IPA data response is acknowledged the same way, so it
        goes on from here as well, whatever the IPA does with it.
        """
        entry, new = outbox.take(record, notification, route=route, now=utc_now())
        seq_number = entry.get("seq_number")
        if seq_number is not None and seq_number not in accepted.acknowledgements:
            accepted.acknowledgements.append(seq_number)
        state = outbox.state_of(entry)
        if not new:
            accepted.messages.append(f"notification {seq_number} was taken before ({state})")
            return
        accepted.notifications += 1
        target = f" for {entry['address']}" if entry.get("address") else ""
        if state == outbox.STATE_FAILED:
            accepted.messages.append(f"notification {seq_number}{target} taken, cannot be sent: "
                                     f"{entry.get('reason', '')}")
        else:
            accepted.messages.append(f"notification {seq_number}{target} taken")

    def _accept_ipa_data(
        self,
        connection: Any,
        record: EuiccRecord,
        raw: bytes,
        route: str,
        accepted: Accepted,
        operation_id: int | None,
    ) -> None:
        decoded = codec.decode_ipa_euicc_data_response(raw)
        operation = self._target(
            connection, record, decoded.transaction_id, types=("IPA_EUICC_DATA",), operation_id=operation_id,
        )
        if not decoded.ok:
            if operation is not None:
                operation.result_hex = raw.hex().upper()
                operation.error = f"ipaEuiccDataResponseError {decoded.error_name} ({decoded.error_code})"
                self._finish(operation, STATE_ERROR, operation.error)
                self.store.save_operation(operation, connection)
                accepted.operation = operation
            accepted.messages.append(f"IPA eUICC data error {decoded.error_name}")
            return
        members = decoded.members
        if operation is not None:
            if members.get("euicc_certificate"):
                record.euicc_certificate = members["euicc_certificate"]
            if members.get("eum_certificate"):
                record.eum_certificate = members["eum_certificate"]
        elif (members.get("euicc_certificate", record.euicc_certificate) != record.euicc_certificate
              or members.get("eum_certificate", record.eum_certificate) != record.eum_certificate):
            # The eUICC certificate on record is what a Notification's signature is checked under before
            # the eIM posts it to the address it names, so only an answer this eIM asked for sets it.
            accepted.messages.append("certificates of an IPA data response no operation asked for were not taken")
        if "default_smdp_address" in members:
            record.data["default_smdp_address"] = members["default_smdp_address"].decode("utf-8", errors="replace")
        if "root_smds_address" in members:
            record.data["root_smds_address"] = members["root_smds_address"].decode("utf-8", errors="replace")
        if "association_token" in members:
            token = int.from_bytes(members["association_token"], "big", signed=True)
            if token != record.association_token:
                accepted.messages.append(f"associationToken {token} from the IPA eUICC data; the record now uses it")
            record.association_token = token
        for key in ("euicc_info1", "euicc_info2", "ipa_capabilities", "device_info"):
            if key in members:
                record.data[f"{key}_hex"] = members[key].hex().upper()
        asked_tags = str((operation.params if operation is not None else {}).get("tags") or "")
        asked = compact_forms.tag_list_names(" ".join(IPA_DATA_TAGS) if asked_tags == TAG_LIST_ALL else asked_tags)
        if "A8" in asked and "ipa_capabilities" not in members:
            # Asked and not given: the capabilities on record belong to another IPA, or to none.
            record.data.pop("ipa_capabilities_hex", None)
        record.data.setdefault("refreshed", {})["ipa_data"] = utc_now()
        for notification in decoded.notifications:
            self._take_notification(record, notification, accepted, route)
        recovered_target: Operation | None = None
        original: Operation | None = None
        if operation is not None and operation.recovery_for is not None:
            original = self.store.operation(operation.recovery_for, connection)
        for stored in decoded.package_results:
            try:
                result = codec.decode_euicc_package_result(stored)
            except codec.CodecError as error:
                accepted.messages.append(f"stored eUICC Package Result does not decode: {error}")
                continue
            matches = original is not None and (
                result.transaction_id.hex().upper() == original.transaction_id
                or (result.counter_value is not None and result.counter_value == original.counter_value)
            )
            if matches and original is not None and not original.final:
                self._accept_euicc_result(
                    connection, record, stored, route, accepted, original.id, recovered_by=operation,
                )
                recovered_target = original
            elif result.kind == "result" and result.seq_number is not None and self._ours(result.eim_id):
                # A stored result of this eIM that matches nothing pending was
                # processed by being discarded (§5.14.6); another eIM's stays.
                accepted.acknowledgements.append(result.seq_number)
        if operation is not None:
            operation.result_hex = raw.hex().upper()
            operation.result = {
                "members": sorted(members),
                "package_results": len(decoded.package_results),
                "notifications": len(decoded.notifications),
            }
            if original is not None:
                text = (
                    f"recovered the result of operation {original.id}" if recovered_target is not None
                    else f"no stored result for operation {original.id}; it will be served again"
                )
            else:
                text = "eUICC data received"
            self._finish(operation, STATE_SUCCESS, text)
            self.store.save_operation(operation, connection)
            accepted.operation = operation
            accepted.messages.append(f"operation {operation.id}: {text}")

    def _accept_download(
        self,
        connection: Any,
        record: EuiccRecord,
        raw: bytes,
        route: str,
        accepted: Accepted,
        operation_id: int | None,
        *,
        relayed: bool = False,
    ) -> None:
        decoded = codec.decode_profile_download_trigger_result(raw)
        operation = self._target(
            connection, record, decoded.transaction_id, types=("PROFILE_DOWNLOAD_TRIGGER",), operation_id=operation_id,
        )
        seq_number = codec.notification_seq_number(decoded.installation_result) if decoded.installation_result else None
        if seq_number is not None:
            accepted.acknowledgements.append(seq_number)
        if decoded.ok:
            text = "profile installed"
            state = STATE_SUCCESS
            record.data.setdefault("refreshed", {})["profiles_stale"] = utc_now()
        elif decoded.installation_result:
            text = "profile installation failed (ProfileInstallationResult errorResult)"
            state = STATE_ERROR
        else:
            text = f"profileDownloadError reason {decoded.error_reason}"
            state = STATE_ERROR
        if operation is None:
            accepted.messages.append(f"download result for no known operation: {text}")
            return
        source = "ProfileInstallationResult of the indirect download" if relayed else "ProfileDownloadTriggerResult"
        if operation.final and EVENT_RETRIEVAL_CLOSED_FLAG in operation.flags:
            # The eIM ran this Event Retrieval itself and closed the operation with what the SM-DS
            # answered (SGP.32 v1.3 §3.9.2.2 step 13). A download result an IPA sends under the same
            # eimTransactionId is not this operation's outcome: it is noted, and the record kept.
            _event(operation, f"{source} as well: {text}")
            self.store.save_operation(operation, connection)
            accepted.operation = operation
            accepted.messages.append(f"operation {operation.id}: {text} ({source}; the event retrieval is closed)")
            return
        if operation.final and bool((operation.result or {}).get("relayed")) != relayed:
            # The other report of the same download: an IPA may still send ProfileDownloadTriggerResult,
            # which §2.11.2.3 (p.44) asks for a direct download only, besides the relayed result.
            _event(operation, f"{source} as well: {text}")
            self.store.save_operation(operation, connection)
            accepted.operation = operation
            accepted.messages.append(f"operation {operation.id}: {text} ({source}; already closed)")
            return
        operation.result_hex = raw.hex().upper()
        operation.result = {"ok": decoded.ok, "error_reason": decoded.error_reason, "relayed": relayed}
        if state == STATE_ERROR:
            operation.error = text
        self._finish(operation, state, f"{text} ({source})" if relayed else text)
        self.store.save_operation(operation, connection)
        accepted.operation = operation
        accepted.messages.append(f"operation {operation.id}: {text}")

    def _accept_error(
        self,
        connection: Any,
        record: EuiccRecord,
        result: codec.EimPackageResult,
        route: str,
        accepted: Accepted,
        operation_id: int | None,
    ) -> None:
        operation = self._target(connection, record, result.transaction_id, operation_id=operation_id)
        name = codec.EIM_PACKAGE_RESULT_ERRORS.get(result.error_code or 0, "unknown")
        text = f"eimPackageResultResponseError {name} ({result.error_code})"
        if operation is None:
            accepted.messages.append(f"{text} for no known operation")
            return
        operation.result_hex = result.raw.hex().upper()
        operation.error = text
        self._finish(operation, STATE_ERROR, text)
        self.store.save_operation(operation, connection)
        accepted.operation = operation
        accepted.messages.append(f"operation {operation.id}: {text}")

    # ------------------------------------------------------------------
    # Putting the Local eIM on a card
    # ------------------------------------------------------------------

    def association_setup(self, eid: str | None, requested: str | None = None) -> str:
        """The TLS setup an association of *eid* takes: the one asked for, else the card's remembered one, else the one in use.

        '' stands for the identity's own certificate and FQDN. Every association
        records its setup on the card's record, so a card swap changes nothing
        in the service: the listener serves every setup by name and the next
        ASSOCIATE of that card picks the setup it already holds.
        """
        from SCP11.eim_local.engine.tls_setup import TlsSetupError, load_setup

        if requested is not None:
            name = "" if requested in ("", "identity") else str(requested).strip()
            if len(name) > 0:
                try:
                    load_setup(self.directory, name)
                except TlsSetupError as error:
                    raise LocalEimError(str(error)) from error
            return name
        record = self.record(eid) if eid else None
        remembered = str(record.data.get("tls_setup", "") or "") if record is not None else ""
        if remembered == "identity":
            return ""
        if len(remembered) > 0:
            try:
                load_setup(self.directory, remembered)
                return remembered
            except TlsSetupError:
                pass
        return active_name(self.directory)

    def association_configuration(
        self, *, key_form: str = "certificate", setup: str | None = None, fqdn: str | None = None,
    ) -> EimConfigurationData:
        """The EimConfigurationData ASSOCIATE sends: the identity, with the eIM FQDN and the TLS trust of TLS setup *setup*.

        SGP.32 v1.3 §2.11.1.1.1 (p.32-33): trustedPublicKeyDataTls is what the
        card checks the eIM's TLS server against, so it follows what the
        card-facing listener serves under that name; eimFqdn is where the
        card's IPAe polls, so it follows the same setup (and is left out when
        eimIdType is eimIdTypeFqdn, the eimId then being the FQDN). *setup*
        None means the one in use.
        """
        identity = self.identity()
        configuration = identity.configuration_data(key_form=key_form, include_tls=False)
        own = effective_fqdn(self.directory, identity, setup)
        fqdn = self._association_fqdn(own, fqdn, setup)
        return replace(
            configuration,
            eim_fqdn=None if identity.eim_id_type == 2 else (fqdn or None),
            trusted_public_key_data_tls=trusted_tls_key_data(self.directory, identity, setup),
        )

    def _association_fqdn(self, own: str, asked: str | None, setup: str | None) -> str:
        """The name an association carries: the setup's own, or *asked* when the setup's leaf also names it."""
        from SCP11.eim_local.engine.tls_setup import active_name, load_setup

        wanted = str(asked or "").strip().lower().rstrip(".")
        if len(wanted) == 0 or wanted == own.lower():
            return own
        if not local_eim_name(wanted):
            raise LocalEimError(f"fqdn {wanted} is not a Local eIM name ({LOCAL_EIM_NAME_PATTERN}).")
        resolved = active_name(self.directory) if setup is None else ("" if setup in ("", "identity") else setup)
        leaf = load_setup(self.directory, resolved).leaf_name.lower() if len(resolved) > 0 else ""
        suffix = leaf[1:] if leaf.startswith("*.") else ""
        head = wanted[: -len(suffix)] if len(suffix) > 0 and wanted.endswith(suffix) else ""
        if len(head) == 0 or "." in head:
            raise LocalEimError(
                f"fqdn {wanted} is not named by the leaf of {'TLS setup ' + resolved if resolved else 'the identity'} "
                f"({leaf or own or '-'}): the card would refuse the certificate. Use a setup whose leaf is a wildcard "
                "(TLS-SETUP NEW <name> fqdn=eim1.yggdrasim.local san=*.yggdrasim.local chain=root trust=root)."
            )
        return wanted

    def association_requests(self, *, key_form: str = "certificate", setup: str | None = None) -> tuple[bytes, bytes]:
        """Return (eUICCMemoryReset 'BF64', AddInitialEim 'BF57') for this identity under TLS setup *setup*."""
        configuration = self.association_configuration(key_form=key_form, setup=setup)
        return encode_euicc_memory_reset_request(), encode_add_initial_eim_request([configuration])

    def associate(
        self,
        exchange: Callable[[bytes, str], bytes],
        eid: str,
        *,
        reset_first: bool = True,
        key_form: str = "certificate",
        setup: str | None = None,
        fqdn: str | None = None,
    ) -> list[str]:
        """Reset the card's eIM configuration, AddInitialEim this identity, seed the record.

        *exchange* sends one ES10b command to the ISD-R and returns the answer.
        The counter sent in the entry and the associationToken the eUICC
        assigns are what the first eUICC Package is signed with. *setup* is
        the TLS setup the card is told to poll and trust (None: the card's
        remembered one, else the one in use); the record remembers it.
        """
        name = self.association_setup(eid, setup)
        configuration = self.association_configuration(key_form=key_form, setup=name, fqdn=fqdn)
        check_association_name(configuration)
        lines, token = self._add_initial_eim(exchange, configuration, reset_first=reset_first)
        normalized = codec.normalize_eid(eid)
        self.register(normalized)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None:
                raise StoreError(f"No eUICC {normalized} after registering it.")
            record.association_token = token
            record.counter_value = 0
            record.seq_number = None
            record.data["associated"] = True
            record.data.pop("handover", None)
            record.data["tls_setup"] = name or "identity"
            record.data["eims"] = [{
                "eim_id": configuration.eim_id, "eim_fqdn": configuration.eim_fqdn or "",
                "association_token": token, "tls_setup": name or "identity",
            }]
            self.store.save_record(record, connection)
        trust = f"TLS setup {name}" if name else "the identity"
        lines.insert(0, f"eimFqdn {configuration.eim_fqdn or '-'} ({fqdn_source(self.directory, name)}); "
                        f"trustedPublicKeyDataTls from {trust}; remembered for this card")
        lines.append(f"record {normalized}: associationToken {token}, counterValue 0")
        return lines

    def hand_over(
        self,
        exchange: Callable[[bytes, str], bytes],
        eid: str,
        configuration: EimConfigurationData,
        *,
        reset_first: bool = True,
        how: dict[str, str] | None = None,
    ) -> list[str]:
        """Put another eIM's EimConfigurationData on the card with AddInitialEim, by the operator's explicit choice.

        The Local eIM holds no private key of that eIM: the eUICC verifies every
        eUICC Package against the key in eimPublicKeyData together with the
        stored associationToken (SGP.32 v1.3 §5.9.1, p.123-124), so a package
        from this rig comes back euiccPackageErrorUnsigned until ASSOCIATE puts
        the identity back. The record keeps the token the card assigned, marked
        foreign, so the queue warns instead of signing in vain.
        """
        lines, token = self._add_initial_eim(exchange, configuration, reset_first=reset_first)
        normalized = codec.normalize_eid(eid)
        self.register(normalized)
        with self.store.transaction() as connection:
            record = self.store.record(normalized, connection)
            if record is None:
                raise StoreError(f"No eUICC {normalized} after registering it.")
            record.association_token = token
            record.counter_value = int(configuration.counter_value or 0)
            record.seq_number = None
            record.data["associated"] = False
            record.data.pop("tls_setup", None)
            record.data["eims"] = [{
                "eim_id": configuration.eim_id, "eim_fqdn": configuration.eim_fqdn or "",
                "association_token": token, "foreign": True,
            }]
            record.data["handover"] = {**(how or {}), "eim_id": str(configuration.eim_id or ""), "at": utc_now()}
            self.store.save_record(record, connection)
        lines.append(f"record {normalized}: associationToken {token} belongs to {configuration.eim_id}; the Local eIM "
                     "holds no key for it, so its packages are refused (euiccPackageErrorUnsigned) until ASSOCIATE")
        return lines

    def _add_initial_eim(
        self,
        exchange: Callable[[bytes, str], bytes],
        configuration: EimConfigurationData,
        *,
        reset_first: bool,
    ) -> tuple[list[str], int | None]:
        """eUICCMemoryReset of the eIM configuration (SGP.32 v1.3 §5.9.5), then AddInitialEim (§5.9.4); the token assigned."""
        lines: list[str] = []
        if reset_first:
            reset = encode_euicc_memory_reset_request()
            reset_result = decode_euicc_memory_reset_response(exchange(reset, "EIM-LOCAL: eUICCMemoryReset"))
            lines.extend(reset_result.describe())
            if not reset_result.allows_add_initial_eim:
                raise LocalEimError("eUICCMemoryReset failed: " + "; ".join(reset_result.describe()))
        request = encode_add_initial_eim_request([configuration])
        response = decode_add_initial_eim_response(exchange(request, "EIM-LOCAL: AddInitialEim"))
        if not response.ok:
            raise LocalEimError(f"AddInitialEim refused: {response.error_name} ({response.error_code}).")
        token: int | None = None
        for entry in response.entries:
            if entry.startswith("associationToken "):
                token = int(entry.split(" ", 1)[1])
        lines.append("AddInitialEim: " + ", ".join(response.entries))
        return lines, token


def check_association_name(configuration: EimConfigurationData) -> None:
    """Refuse an association under a name the Local eIM does not answer for; the card would poll that host itself."""
    fqdn = str(configuration.eim_fqdn or "")
    if len(fqdn) == 0 and int(configuration.eim_id_type or 0) == 2:
        # eimIdTypeFqdn: the eimId is the name the card polls (SGP.32 v1.3 §2.11.1.1.1).
        fqdn = str(configuration.eim_id or "")
    if local_eim_name(fqdn):
        return
    raise LocalEimError(
        f"eimFqdn {fqdn or '-'} is not a Local eIM name ({LOCAL_EIM_NAME_PATTERN}): no other name is resolved or "
        "redirected to the Local eIM, so a card told it would poll that host itself. Give the TLS setup a matching "
        "name (TLS-SETUP NEW ... fqdn=eim1.yggdrasim.local); ASSOCIATE HANDOVER is the verb that hands a card to "
        "another eIM."
    )


def codec_hex(value: Any) -> str:
    text = "".join(str(value or "").split()).upper()
    if len(text) % 2 != 0 or any(character not in "0123456789ABCDEF" for character in text):
        raise OperationError(f"Not hex octets: {value!r}.")
    return text


def _same_iccid(profile: dict[str, Any], iccid: str) -> bool:
    return str(profile.get("iccid", "")).upper().rstrip("F") == str(iccid).upper().rstrip("F")


def _result_summary(decoded: codec.EuiccPackageResult) -> dict[str, Any]:
    return {
        "kind": decoded.kind,
        "counter_value": decoded.counter_value,
        "seq_number": decoded.seq_number,
        "error": decoded.error_name,
        "items": [item.describe() for item in decoded.items],
    }


def _verdict(decoded: codec.EuiccPackageResult) -> tuple[str, str]:
    """SUCCESS, PARTIAL_SUCCESS or ERROR for one result, and the result described."""
    if decoded.kind == "error_signed":
        return STATE_ERROR, f"euiccPackageErrorSigned {decoded.error_name} ({decoded.error_code})"
    if decoded.kind == "error_unsigned":
        code = f" {decoded.error_name} ({decoded.error_code})" if decoded.error_code is not None else ""
        return STATE_ERROR, f"euiccPackageErrorUnsigned{code}"
    items = decoded.items
    described = "; ".join(item.describe() for item in items) or "no results"
    if len(items) == 0:
        return STATE_SUCCESS, described
    if not any(item.ok for item in items):
        return STATE_ERROR, described
    if any(item.name == "rollbackResult" and item.ok for item in items):
        return STATE_ERROR, described + " (rolled back)"
    if all(item.ok for item in items):
        return STATE_SUCCESS, described
    return STATE_PARTIAL_SUCCESS, described


def store_data_script(package: bytes) -> tuple[ScriptStep, ...]:
    """MANAGE CHANNEL, SELECT ISD-R on the new channel, then the package as ES10b STORE DATA blocks."""
    channel = SCRIPT_LOGICAL_CHANNEL
    select_cla = cla_for_logical_channel(channel, base=0x00)
    store_cla = cla_for_logical_channel(channel, base=0x80)
    steps: list[ScriptStep] = [
        ScriptStep("MANAGE CHANNEL: open, the card assigns the channel", MANAGE_CHANNEL_OPEN),
        ScriptStep(f"SELECT ISD-R on channel {channel}", bytes([select_cla, 0xA4, 0x04, 0x00, len(ISD_R_AID)]) + ISD_R_AID),
    ]
    blocks = plan_chunked_apdus(bytes(package), cla=store_cla, ins=0xE2, p1_last=0x91)
    for block in blocks:
        label = "STORE DATA: eIM Package"
        if block.total > 1:
            label += f" block {block.index + 1}/{block.total}"
        steps.append(ScriptStep(label, block.apdu))
    return tuple(steps)


__all__ = [
    "Accepted",
    "FINAL_STATES",
    "LocalEim",
    "LocalEimError",
    "OperationRequest",
    "PlanEntry",
    "ROUTE_DIRECT",
    "ROUTE_ESIPA",
    "ROUTE_EXPORT",
    "ROUTE_INJECT",
    "Served",
    "STATE_CANCELED",
    "STATE_CREATED",
    "STATE_ERROR",
    "STATE_PARTIAL_SUCCESS",
    "STATE_SENT",
    "STATE_SUCCESS",
    "parse_time",
]
