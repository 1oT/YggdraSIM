# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The eIM half of the indirect profile download (SGP.32 v1.3 §3.2.3.2, p.57-64).

The IPA sends the SGP.22 download steps to the eIM over ESipa and the eIM runs
each one as the ES9+' function against the SM-DP+: InitiateAuthentication
'BF39' (steps 8-11), AuthenticateClient 'BF3B' (13-15), GetBoundProfilePackage
'BF3A' (17-19), CancelSession 'BF41' (§3.2.3.3) and the ProfileInstallationResult
of HandleNotification 'BF3D' (step 23). The SM-DP+ is this service's own when
its address is the one named, else the named host over ES9+.

A trigger queued with ``contact_smds`` makes the same first two steps an Event
Retrieval by the eIM (§3.9.2.2): ES11'.InitiateAuthentication and
ES11'.AuthenticateClient against the SM-DS, this service's own when its
address is the one named. The Event Records become downloads on the queue and
the IPA is answered with the SM-DS transactionId and the first one's trigger.

A PROFILE_DOWNLOAD_TRIGGER queued with ``indirect`` keeps its download data
here: the IPA's InitiateAuthentication names the operation's eimTransactionId,
and the Activation Code (SGP.22 v3.1 §4.1) gives the SM-DP+ address, the
Matching ID and the optional SM-DP+ OID. As step 10 requires, the eIM checks
serverAddress (smdpAddressMismatch) and that OID (smdpOidMismatch); an unknown
eimTransactionId is invalidEimTransactionId. Any other failure is answered
undefinedError(127) and its cause goes to the service log and the operation's
timeline.

For an IPA whose IPA Capabilities (read with an IPA data request, the record's
``ipa_capabilities_hex``) declare minimizeEsipaBytes, the eIM restores the
compact forms the IPA sends and answers in the compact forms it expects
(``compact.py``, SGP.32 v1.3 §5.14.1-5.14.8); with eimCtxParams1Generation it
builds ctxParams1, with eimProfileMetadataVerification it checks the Profile
Metadata itself and keeps it from the IPA.
"""

from __future__ import annotations

import base64
import binascii
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable

from SCP11.eim_local.engine import compact as compact_forms
from SCP11.eim_local.engine.catalogue import trigger_served_empty
from SCP11.live.models import (
    AuthenticateClientRequest,
    AuthenticateClientResponse,
    CancelSessionRequest,
    GetBoundProfilePackageRequest,
    GetBoundProfilePackageResponse,
    HandleNotificationRequest,
    InitiateAuthenticationRequest,
    InitiateAuthenticationResponse,
)
from SCP11.shared import esipa_download as esipa
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

MAX_SESSIONS = 64
_FAILURES = (RuntimeError, ValueError, OSError, LookupError)


def _b64(value: bytes) -> str:
    return base64.b64encode(bytes(value)).decode("ascii")


def _der(text: Any) -> bytes:
    """A DER field the SM-DP+ returned: base64 (ES9+ JSON), hex as a fallback."""
    value = str(text or "").strip()
    if not value:
        return b""
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return bytes.fromhex(value)


def _hex_or_b64(text: Any) -> bytes:
    """transactionId or a key identifier: hex (ES9+ JSON) or base64 (the local SM-DP+)."""
    value = str(text or "").strip()
    if value and len(value) % 2 == 0 and all(char in "0123456789abcdefABCDEF" for char in value):
        return bytes.fromhex(value)
    return _der(value)


def _key_identifier(text: Any) -> bytes:
    value = _hex_or_b64(text)
    if value[:1] == b"\x04":
        try:
            tag, inner, raw = read_single_ber_tlv(value)
        except (ValueError, IndexError):
            return value
        if tag == b"\x04" and len(raw) == len(value):
            return bytes(inner)
    return value


def server_address(server_signed1: bytes) -> str:
    """serverAddress '83' of ServerSigned1 (SGP.22 v3.1), or ''."""
    try:
        _tag, value, _raw = read_single_ber_tlv(server_signed1)
        offset = 0
        while offset < len(value):
            tag, item, _item_raw, offset = read_ber_tlv(value, offset)
            if tag == b"\x83":
                return item.decode("utf-8", errors="replace")
    except (ValueError, IndexError):
        return ""
    return ""


def certificate_oids(certificate: bytes) -> set[str]:
    """registeredID values of the certificate's subjectAltName: where CERT.DPauth carries the SM-DP+ OID."""
    from cryptography import x509

    try:
        names = x509.load_der_x509_certificate(certificate).extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except (ValueError, x509.ExtensionNotFound):
        return set()
    return {oid.dotted_string for oid in names.get_values_for_type(x509.RegisteredID)}


def activation_code_fields(code: str) -> tuple[str, str, str]:
    """(SM-DP+ address, Matching ID, SM-DP+ OID) of an Activation Code; ('', '', '') when it is not one."""
    from SCP11.eim_packages import _parse_activation_code_parts

    address, matching = _parse_activation_code_parts(str(code or ""))
    if address is None:
        return "", "", ""
    fields = str(code).split("$")
    return address, matching or "", fields[3].strip() if len(fields) > 3 else ""


class LocalSmdpEs9:
    """The local SM-DP+ (``LocalSmdp``) behind the ES9+ client's calls, in-process."""

    def __init__(self, smdp: Any) -> None:
        self.smdp = smdp

    def _call(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.smdp.handle(f"/gsma/rsp2/es9plus/{name}", payload)

    def initiate_authentication(self, request: InitiateAuthenticationRequest) -> InitiateAuthenticationResponse:
        answer = self._call("initiateAuthentication", {
            "euiccChallenge": request.euicc_challenge, "euiccInfo1": request.euicc_info1,
            "smdpAddress": request.smdp_address,
        })
        return InitiateAuthenticationResponse(
            transaction_id=answer["transactionId"], server_signed1=answer["serverSigned1"],
            server_signature1=answer["serverSignature1"], server_certificate=answer["serverCertificate"],
            euicc_ci_pkid_to_be_used=answer["euiccCiPKIdToBeUsed"],
        )

    def authenticate_client(self, request: AuthenticateClientRequest) -> AuthenticateClientResponse:
        answer = self._call("authenticateClient", {
            "transactionId": request.transaction_id, "authenticateServerResponse": request.authenticate_server_response,
        })
        return AuthenticateClientResponse(
            transaction_id=answer["transactionId"], smdp_signed2=answer["smdpSigned2"],
            smdp_signature2=answer["smdpSignature2"], smdp_certificate=answer["smdpCertificate"],
            profile_metadata=answer.get("profileMetadata"),
        )

    def get_bound_profile_package(self, request: GetBoundProfilePackageRequest) -> GetBoundProfilePackageResponse:
        answer = self._call("getBoundProfilePackage", {
            "transactionId": request.transaction_id, "prepareDownloadResponse": request.prepare_download_response,
        })
        return GetBoundProfilePackageResponse(bound_profile_package=answer["boundProfilePackage"])

    def cancel_session(self, request: CancelSessionRequest) -> dict[str, Any]:
        return self._call("cancelSession", {
            "transactionId": request.transaction_id, "cancelSessionResponse": request.cancel_session_response,
        })

    def handle_notification(self, request: HandleNotificationRequest) -> dict[str, Any]:
        return self._call("handleNotification", {"pendingNotification": request.pending_notification})


class LocalSmdsEs11:
    """The local SM-DS (``LocalSmds``) behind the ES9+ client's two calls, in process: ES11' (SGP.32 v1.3 §5.11)."""

    def __init__(self, smds: Any) -> None:
        self.smds = smds

    def initiate_authentication(self, request: InitiateAuthenticationRequest) -> InitiateAuthenticationResponse:
        answer = self.smds.handle("/gsma/rsp2/es9plus/initiateAuthentication", {
            "euiccChallenge": _der(request.euicc_challenge).hex(), "euiccInfo1": _der(request.euicc_info1).hex(),
            "smdpAddress": request.smdp_address,
        })
        return InitiateAuthenticationResponse(
            transaction_id=answer["transactionId"], server_signed1=answer["serverSigned1"],
            server_signature1=answer["serverSignature1"], server_certificate=answer["serverCertificate"],
            euicc_ci_pkid_to_be_used=answer["euiccCiPKIdToBeUsed"],
        )

    def authenticate_client(self, request: AuthenticateClientRequest) -> AuthenticateClientResponse:
        answer = self.smds.handle("/gsma/rsp2/es9plus/authenticateClient", {
            "transactionId": request.transaction_id,
            "authenticateServerResponse": _der(request.authenticate_server_response).hex(),
        })
        return AuthenticateClientResponse(
            transaction_id=answer["transactionId"], smdp_signed2="", smdp_signature2="", smdp_certificate="",
            event_entries=list(answer["eventEntries"]),
        )


@dataclass
class _Session:
    provider_transaction_id: str
    smdp_address: str
    provider: Any
    operation_id: int | None = None
    eid: str = ""
    compact: compact_forms.CompactSession = field(default_factory=compact_forms.CompactSession)
    # an SM-DS event retrieval (SGP.32 v1.3 3.9.2.2) rather than an SM-DP+ download
    smds: bool = False


_record_bytes = compact_forms.record_bytes
ipa_features_of = compact_forms.record_features


class IndirectRelay:
    """One service's indirect download sessions, keyed by the SM-DP+ transactionId."""

    def __init__(
        self,
        engine: Any,
        smdp: Any = None,
        *,
        smds: Any = None,
        log: Callable[[str], None] | None = None,
        provider_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self.engine = engine
        self.smdp = smdp
        self.smds = smds
        self.log = log or (lambda _line: None)
        self._factory = provider_factory or self._provider_for
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._lock = threading.Lock()

    # -- dispatch ----------------------------------------------------------

    def handle(self, data: bytes) -> bytes:
        tag = bytes(data[:2])
        if tag == esipa.TAG_INITIATE_AUTHENTICATION:
            return self._initiate_authentication(data)
        if tag == esipa.TAG_AUTHENTICATE_CLIENT:
            return self._authenticate_client(data)
        if tag == esipa.TAG_GET_BOUND_PROFILE_PACKAGE:
            return self._bound_profile_package(data)
        if tag == esipa.TAG_CANCEL_SESSION:
            return self._cancel_session(data)
        raise esipa.EsipaDownloadError(f"'{tag.hex().upper()}' is no indirect download step")

    def forward_notification(self, notification: bytes) -> bool:
        """Send a ProfileInstallationResult of a relayed session on to its SM-DP+ (step 23).

        A compactProfileInstallationResult (§5.14.7) is restored first; the
        eUICC signature over the (restored) data is checked before it goes on.
        The result closes the session's download operation (§3.2.3.2 step 23).
        """
        compact = bytes(notification[:1]) == b"\xA0"
        if compact:
            transaction_id = compact_forms.compact_notification_transaction_id(notification)
        else:
            transaction_id = esipa.installation_result_transaction_id(notification)
        # Kept, not dropped: an IPA may still cancel the session after a failed install.
        session = self._session(transaction_id) if transaction_id else None
        if session is None:
            return False
        if compact:
            try:
                notification = compact_forms.restore_pending_notification(notification, session.compact)
            except compact_forms.RestoreError as error:
                self._note(session.operation_id, f"indirect: compact ProfileInstallationResult not restored: {error}")
                return False
            self._note(session.operation_id, "indirect: compact ProfileInstallationResult restored, eUICC signature verified")
            verified: bool | None = True
        else:
            verified = compact_forms.installation_result_verifies(notification, session.compact.euicc_certificate)
        if verified is False:
            self._note(session.operation_id, "indirect: ProfileInstallationResult signature does not verify; "
                                             "the download stays open")
        elif session.operation_id is not None:
            # §3.2.3.2 step 23: this is the result of the indirect download; no ProfileDownloadTriggerResult
            # need follow it (§2.11.2.3 asks for one after a direct download only).
            self.engine.accept_relayed_installation(session.operation_id, notification, verified=verified)
        try:
            session.provider.handle_notification(HandleNotificationRequest(
                pending_notification=_b64(notification), smdp_address=session.smdp_address,
            ))
        except _FAILURES as error:
            kept = self._keep_for_another_attempt(session, notification)
            self._note(session.operation_id, f"indirect: ProfileInstallationResult not forwarded: {error}"
                       + ("; the eIM tries again (NOTIFICATIONS lists it)" if kept else ""))
            return kept
        self._note(session.operation_id, f"indirect: ProfileInstallationResult forwarded to {session.smdp_address}")
        return True

    def _keep_for_another_attempt(self, session: _Session, notification: bytes) -> bool:
        """Put the (restored) result on the eUICC's record, where the eIM's forwarding sends it again.

        The IPA was acknowledged and removes the result from the eUICC
        (SGP.32 v1.3 §3.2.3.2 step 23), so a result the SM-DP+ did not take
        would otherwise be lost. False when the session names no known eUICC.
        """
        if not session.eid:
            return False
        try:
            return self.engine.accept_notification(session.eid, notification).error is None
        except _FAILURES:
            return False

    def sessions(self) -> int:
        with self._lock:
            return len(self._sessions)

    # -- steps -------------------------------------------------------------

    def _initiate_authentication(self, data: bytes) -> bytes:
        try:
            request = esipa.decode_initiate_authentication_request(data)
        except esipa.EsipaDownloadError as error:
            self.log(f"indirect: InitiateAuthentication refused: {error}")
            return esipa.encode_initiate_authentication_error(esipa.UNDEFINED_ERROR)
        address = request.smdp_address.strip()
        matching = ""
        oid = ""
        euicc_info1 = request.euicc_info1
        operation = None
        record = None
        from_eim = False
        if request.eim_transaction_id:
            operation = self.engine.download_for(request.eim_transaction_id)
            if operation is None:
                self.log(f"indirect: no download for eimTransactionId {request.eim_transaction_id.hex().upper()}")
                return esipa.encode_initiate_authentication_error(52)
            record = self.engine.record(operation.eid)
            data_on_record = record.data if record is not None else {}
            code = str(operation.params.get("activation_code") or "")
            smds = bool(operation.params.get("contact_smds"))
            if smds:
                # §3.9.2.2 step 6: the SM-DS FQDN comes from the IPA or the eIM identifies it
                held_address = str(operation.params.get("smds_address") or data_on_record.get("root_smds_address")
                                   or "")
                held_matching = ""
            elif code:
                held_address, held_matching, oid = activation_code_fields(code)
            else:
                held_address = str(data_on_record.get("default_smdp_address", "") or "")
                held_matching = ""
            if not address:
                address, matching, from_eim = held_address, held_matching, True
            if not euicc_info1 and data_on_record.get("euicc_info1_hex"):
                euicc_info1 = bytes.fromhex(str(data_on_record["euicc_info1_hex"]))
        operation_id = operation.id if operation is not None else None
        smds = operation is not None and bool(operation.params.get("contact_smds"))
        if not address:
            self._note(operation_id, "indirect: no SM-DP+ address from the IPA or the operation")
            return esipa.encode_initiate_authentication_error(1)
        if not euicc_info1:
            self._note(operation_id, "indirect: no euiccInfo1 from the IPA or on record")
            return esipa.encode_initiate_authentication_error(esipa.UNDEFINED_ERROR)
        features = ipa_features_of(record)
        if not features and not request.smdp_address and not request.euicc_info1:
            # No IPA Capabilities on record; an IPA that leaves out both is one with minimizeEsipaBytes
            # (SGP.32 v1.3 §5.14.1: such an IPA SHOULD NOT send euiccInfo1 and smdpAddress).
            features = frozenset({compact_forms.MINIMIZE})
            self._note(operation_id, "indirect: no IPA Capabilities on record; treated as minimizeEsipaBytes")
        session = compact_forms.CompactSession(features=features)
        if record is not None:
            session.euicc_info2 = _record_bytes(record.data, "euicc_info2_hex")
            session.euicc_certificate = bytes(record.euicc_certificate or b"")
            session.eum_certificate = bytes(record.eum_certificate or b"")
            session.other_certs_in_chain = _record_bytes(record.data, "other_certs_in_chain_hex")
        # §5.14.1 Table 13 NOTE 3: the Matching ID goes to an IPA that builds ctxParams1 itself but got no
        # Activation Code (an empty trigger); an IPA with eimCtxParams1Generation gets ctxParams1 instead.
        served_empty = operation is not None and trigger_served_empty(operation, features)
        try:
            if compact_forms.CTX_PARAMS1_GENERATION in features:
                session.ctx_params1 = compact_forms.ctx_params1_for(
                    matching, _record_bytes(record.data if record is not None else {}, "device_info_hex"))
            provider = self._factory(address)
            answer = provider.initiate_authentication(InitiateAuthenticationRequest(
                euicc_challenge=_b64(request.euicc_challenge), euicc_info1=_b64(euicc_info1), smdp_address=address,
            ))
            transaction_id = _hex_or_b64(answer.transaction_id)
            pkid = _key_identifier(answer.euicc_ci_pkid_to_be_used)
            session.ci_pkid = pkid
            if session.minimize:
                pkid = compact_forms.truncated_ci_pkid(pkid, compact_forms.signing_ci_pkids(euicc_info1))
            ok = esipa.InitiateAuthenticationOk(
                transaction_id=b"" if session.minimize else transaction_id,
                server_signed1=_der(answer.server_signed1),
                server_signature1=esipa.signature_value(_der(answer.server_signature1)),
                euicc_ci_pkid=pkid,
                server_certificate=_der(answer.server_certificate),
                matching_id=matching if served_empty and not session.ctx_params1 else "",
                ctx_params1=esipa.tlv(b"\xA2", session.ctx_params1) if session.ctx_params1 else b"",
            )
        except _FAILURES as error:
            self._note(operation_id, f"indirect: InitiateAuthentication at {address} failed: {error}")
            return esipa.encode_initiate_authentication_error(esipa.UNDEFINED_ERROR)
        session.server_signed1 = ok.server_signed1
        session.server_certificate = ok.server_certificate
        if from_eim:
            named = server_address(ok.server_signed1)
            if named and named.lower() != address.lower():
                self._note(operation_id, f"indirect: SM-DP+ answered as {named}, not {address}")
                return esipa.encode_initiate_authentication_error(50)
        if oid and oid not in certificate_oids(ok.server_certificate):
            self._note(operation_id, f"indirect: CERT.DPauth does not carry the SM-DP+ OID {oid}")
            return esipa.encode_initiate_authentication_error(51)
        self._remember(transaction_id, _Session(str(answer.transaction_id), address, provider, operation_id,
                                                eid=operation.eid if operation is not None else "", compact=session,
                                                smds=smds))
        shape = " in the compact form" if session.minimize else ""
        function = "ES11'.InitiateAuthentication" if smds else "InitiateAuthentication"
        self._note(operation_id, f"indirect: {function} relayed to {address} "
                                 f"(transactionId {transaction_id.hex().upper()}){shape}")
        return esipa.encode_initiate_authentication_ok(ok)

    def _remember_chain(self, eid: str, chain: bytes, operation_id: int | None) -> None:
        if not eid:
            return
        # Read inside the transaction: a record read before it would write back a stale Notification list.
        with self.engine.store.transaction() as connection:
            record = self.engine.store.record(eid, connection)
            if record is None:
                return
            record.data["other_certs_in_chain_hex"] = chain.hex().upper()
            self.engine.store.save_record(record, connection)
        self._note(operation_id, f"indirect: eUICC certificate chain beyond nextCertInChain kept for {eid} "
                                 f"({len(chain)} bytes)")

    def _authenticate_client(self, data: bytes) -> bytes:
        try:
            transaction_id, response = esipa.decode_authenticate_client_request(data)
        except esipa.EsipaDownloadError as error:
            self.log(f"indirect: AuthenticateClient refused: {error}")
            return esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR)
        session = self._session(transaction_id)
        if session is None:
            return esipa.encode_authenticate_client_error(10)
        forms = session.compact
        try:
            # §5.14.3: an IPA with minimizeEsipaBytes may send compactAuthenticateResponseOk.
            restored = compact_forms.restore_authenticate_server_response(response, forms)
        except compact_forms.RestoreError as error:
            self._note(session.operation_id, f"indirect: AuthenticateServerResponse not restored: {error}")
            return esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR)
        if restored != response:
            self._note(session.operation_id, "indirect: compact AuthenticateServerResponse restored, eUICC signature verified")
        if len(forms.euicc_certificate) == 0 or len(forms.eum_certificate) == 0:
            # The later compact forms are checked with the certificates this answer carried.
            euicc_certificate, eum_certificate = compact_forms.response_certificates(restored)
            forms.euicc_certificate = forms.euicc_certificate or euicc_certificate
            forms.eum_certificate = forms.eum_certificate or eum_certificate
        chain = compact_forms.response_other_certs(restored)
        if len(chain) > 0 and chain != forms.other_certs_in_chain:
            # A full answer taught the eIM the rest of the eUICC certificate chain; a later compact answer
            # of this eUICC is restored with it (SGP.22 v3.1 5.7.13 otherCertsInChain).
            forms.other_certs_in_chain = chain
            self._remember_chain(session.eid, chain, session.operation_id)
        try:
            answer = session.provider.authenticate_client(AuthenticateClientRequest(
                transaction_id=session.provider_transaction_id, authenticate_server_response=_b64(restored),
                smdp_address=session.smdp_address,
            ))
            if session.smds:
                return self._event_records(session, transaction_id, answer)
            ok = esipa.AuthenticateClientOk(
                transaction_id=transaction_id,
                smdp_signed2=_der(answer.smdp_signed2),
                smdp_signature2=_der(answer.smdp_signature2),
                smdp_certificate=_der(answer.smdp_certificate),
                profile_metadata=_der(answer.profile_metadata) if answer.profile_metadata else b"",
            )
        except _FAILURES as error:
            self._note(session.operation_id, f"indirect: AuthenticateClient failed: {error}")
            if session.smds:
                if session.operation_id is not None:
                    self.engine.complete_event_retrieval(session.operation_id, [], error=str(error))
                self._session(transaction_id, pop=True)
            return esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR)
        forms.smdp_signed2 = ok.smdp_signed2
        forms.smdp_signature2 = esipa.tlv(b"\x5F\x37", esipa.signature_value(ok.smdp_signature2))
        forms.smdp_certificate = ok.smdp_certificate
        forms.profile_metadata = ok.profile_metadata
        if compact_forms.confirmation_code_required(ok.smdp_signed2):
            # §5.14.3: hashCc MAY be provided when the SM-DP+ requires a Confirmation Code and the eIM holds
            # it; the compact PrepareDownload answer is then restored with it (§5.14.2).
            operation = self.engine.operation(session.operation_id) if session.operation_id is not None else None
            code = str(operation.params.get("confirmation_code") or "") if operation is not None else ""
            if code:
                forms.hash_cc = compact_forms.hashed_confirmation_code(
                    code, compact_forms.transaction_id_of(ok.smdp_signed2))
                ok.hash_cc = forms.hash_cc
                self._note(session.operation_id, "indirect: Confirmation Code required; its hash handed to the IPA")
            else:
                self._note(session.operation_id, "indirect: Confirmation Code required by the SM-DP+ and none on "
                                                 "the operation; the IPA has to supply hashCc")
        if compact_forms.METADATA_VERIFICATION in forms.features:
            # §5.14.3: the eIM checks the Profile Metadata for an IPA that cannot (SGP.22 v3.1 §3.1.3 step 7).
            record = self.engine.record(session.eid) if session.eid else None
            refusal = compact_forms.metadata_refusal(
                ok.profile_metadata, compact_forms.record_bytes(record.data if record else {}, "rat_hex"),
                record.profiles if record is not None else [],
            )
            if refusal:
                self._note(session.operation_id, f"indirect: Profile Metadata refused: {refusal}")
                return esipa.encode_authenticate_client_error(50)
            ok.profile_metadata = b""
        if forms.minimize:
            ok.transaction_id = b""
        self._note(session.operation_id, "indirect: AuthenticateClient relayed")
        return esipa.encode_authenticate_client_ok(ok)

    def _event_records(self, session: _Session, transaction_id: bytes, answer: Any) -> bytes:
        """ESipa.AuthenticateClient of an SM-DS session (SGP.32 v1.3 3.9.2.2 steps 12-14): the Event Records
        become downloads, and the answer carries the SM-DS transactionId and, when the first download is
        next for this eUICC, its trigger. The RSP session with the SM-DS ends here."""
        entries = answer.event_entries if isinstance(getattr(answer, "event_entries", None), list) else []
        events = [{"eventId": str(entry["eventId"]), "rspServerAddress": str(entry["rspServerAddress"])}
                  for entry in entries
                  if isinstance(entry, dict) and entry.get("eventId") and entry.get("rspServerAddress")]
        oids = sorted(certificate_oids(session.compact.server_certificate))
        queued = []
        if session.operation_id is not None:
            queued = self.engine.complete_event_retrieval(session.operation_id, events, smds_oid=oids[0] if oids else "")
        trigger = b""
        if queued:
            served = self.engine.next_package(session.eid, only=queued[0].id)
            if served.error is None and served.operation is not None and served.operation.id == queued[0].id:
                trigger = served.package
        what = f"{len(events)} Event Record(s)"
        if trigger:
            what += f", download {queued[0].id} queued and its trigger sent"
        elif queued:
            what += f", {len(queued)} download(s) queued"
        self._note(session.operation_id, f"indirect: ES11'.AuthenticateClient relayed; {what}")
        self._session(transaction_id, pop=True)
        return esipa.encode_authenticate_client_ds_ok(esipa.AuthenticateClientDsOk(transaction_id, trigger))

    def _bound_profile_package(self, data: bytes) -> bytes:
        try:
            transaction_id, response = esipa.decode_get_bound_profile_package_request(data)
        except esipa.EsipaDownloadError as error:
            self.log(f"indirect: GetBoundProfilePackage refused: {error}")
            return esipa.encode_get_bound_profile_package_error(esipa.UNDEFINED_ERROR)
        session = self._session(transaction_id)
        if session is None:
            return esipa.encode_get_bound_profile_package_error(95)
        forms = session.compact
        try:
            # §5.14.2: an IPA with minimizeEsipaBytes may send compactDownloadResponseOk.
            restored = compact_forms.restore_prepare_download_response(response, forms)
        except compact_forms.RestoreError as error:
            self._note(session.operation_id, f"indirect: PrepareDownloadResponse not restored: {error}")
            return esipa.encode_get_bound_profile_package_error(esipa.UNDEFINED_ERROR)
        if restored != response:
            self._note(session.operation_id, "indirect: compact PrepareDownloadResponse restored, eUICC signature verified")
        try:
            answer = session.provider.get_bound_profile_package(GetBoundProfilePackageRequest(
                transaction_id=session.provider_transaction_id, prepare_download_response=_b64(restored),
                smdp_address=session.smdp_address,
            ))
            package = _der(answer.bound_profile_package)
            if compact_forms.METADATA_VERIFICATION in forms.features and forms.profile_metadata:
                # §5.14.2: the Profile Metadata the eIM checked is the one the package carries.
                carried = compact_forms.bound_package_metadata(package)
                if carried and carried != forms.profile_metadata:
                    self._note(session.operation_id, "indirect: the Bound Profile Package carries other Profile Metadata")
                    return esipa.encode_get_bound_profile_package_error(50)
            reply = esipa.encode_get_bound_profile_package_ok(b"" if forms.minimize else transaction_id, package)
        except _FAILURES as error:
            self._note(session.operation_id, f"indirect: GetBoundProfilePackage failed: {error}")
            return esipa.encode_get_bound_profile_package_error(esipa.UNDEFINED_ERROR)
        self._note(session.operation_id, f"indirect: Bound Profile Package relayed ({len(package)} bytes)")
        return reply

    def _cancel_session(self, data: bytes) -> bytes:
        try:
            transaction_id, response = esipa.decode_cancel_session_request(data)
        except esipa.EsipaDownloadError as error:
            self.log(f"indirect: CancelSession refused: {error}")
            return esipa.encode_cancel_session_error(esipa.UNDEFINED_ERROR)
        session = self._session(transaction_id, pop=True)
        if session is None:
            return esipa.encode_cancel_session_error(1)
        try:
            # §5.14.8: an IPA with minimizeEsipaBytes may send compactCancelSessionResponseOk.
            restored = compact_forms.restore_cancel_session_response(response, session.compact)
        except compact_forms.RestoreError as error:
            self._note(session.operation_id, f"indirect: CancelSessionResponse not restored: {error}")
            return esipa.encode_cancel_session_error(esipa.UNDEFINED_ERROR)
        try:
            session.provider.cancel_session(CancelSessionRequest(
                transaction_id=session.provider_transaction_id, cancel_session_response=_b64(restored),
            ))
        except _FAILURES as error:
            self._note(session.operation_id, f"indirect: CancelSession failed: {error}")
            return esipa.encode_cancel_session_error(esipa.UNDEFINED_ERROR)
        self._note(session.operation_id, "indirect: CancelSession relayed")
        return esipa.encode_cancel_session_ok()

    # -- helpers -----------------------------------------------------------

    def _provider_for(self, address: str) -> Any:
        if self.smds is not None and self.smds.owns_address(address):
            return LocalSmdsEs11(self.smds)
        local = self.smdp.address() if self.smdp is not None else ""
        if self.smdp is not None and address.lower() == local.lower():
            return LocalSmdpEs9(self.smdp)
        from SCP11.live.es9_client import Es9LikeClient

        return Es9LikeClient(base_url=f"https://{address}")

    def _remember(self, transaction_id: bytes, session: _Session) -> None:
        with self._lock:
            key = transaction_id.hex().upper()
            self._sessions[key] = session
            self._sessions.move_to_end(key)
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.popitem(last=False)

    def _session(self, transaction_id: bytes, *, pop: bool = False) -> _Session | None:
        key = bytes(transaction_id).hex().upper()
        with self._lock:
            return self._sessions.pop(key, None) if pop else self._sessions.get(key)

    def _note(self, operation_id: int | None, text: str) -> None:
        self.log(text)
        if operation_id is None:
            return
        try:
            self.engine.note(operation_id, text)
        except _FAILURES as error:
            self.log(f"indirect: could not note on operation {operation_id}: {error}")
