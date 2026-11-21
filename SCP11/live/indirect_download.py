# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""IPA side of the indirect profile download: the SGP.22 steps relayed through the eIM.

The orchestrator drives a download through a profile provider, the ES9+ client
for a direct download. ``EsipaProfileProvider`` offers the same calls and sends
them to the eIM as ESipa messages instead (SGP.32 v1.3 §3.2.3.2):
InitiateAuthentication 'BF39', AuthenticateClient 'BF3B', GetBoundProfilePackage
'BF3A', CancelSession 'BF41' and HandleNotification 'BF3D'. Everything else,
the SM-DP+ certificate bundle lookup among it, stays the wrapped client's.

When the eIM answers AuthenticateClient for an SM-DS (authenticateClientOkDSEsipa,
§3.9.2.2 step 14), the provider says so in its answer instead of the SM-DP+
members: the Event Retrieval is done and no download step follows on this
session.

Fields go back to the orchestrator in the forms the local SM-DP+ uses on the
direct path: DER objects base64, transactionId and the CI key identifier hex,
serverSignature1 bare, smdpSignature2 as its '5F37' object.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

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


def _b64(value: bytes) -> str:
    return base64.b64encode(bytes(value)).decode("ascii")


def _field(value: str) -> bytes:
    """A DER field of a provider model: base64, hex as a fallback."""
    text = str(value or "").strip()
    if not text:
        return b""
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error):
        pass
    try:
        return bytes.fromhex(text)
    except ValueError as error:
        raise esipa.EsipaDownloadError("a download field is neither base64 nor hex") from error


def _transaction_id(value: str) -> bytes:
    """transactionId as the orchestrator hands it back: the hex this provider gave, or base64."""
    text = str(value or "").strip()
    if len(text) == 32:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    return _field(text)


def _signed1_transaction_id(server_signed1: bytes) -> bytes:
    """transactionId '80' of serverSigned1, for an answer that leaves the optional copy out."""
    try:
        _tag, value, _raw = read_single_ber_tlv(server_signed1)
        offset = 0
        while offset < len(value):
            tag, item, _item_raw, offset = read_ber_tlv(value, offset)
            if tag == b"\x80":
                return bytes(item)
    except (ValueError, IndexError):
        return b""
    return b""


def _signed1_server_address(server_signed1: bytes) -> str:
    """serverAddress '83' of serverSigned1 (SGP.22 v3.1 ServerSigned1), or ''."""
    try:
        _tag, value, _raw = read_single_ber_tlv(server_signed1)
        offset = 0
        while offset < len(value):
            tag, item, _item_raw, offset = read_ber_tlv(value, offset)
            if tag == b"\x83":
                return item.decode("utf-8", errors="replace").strip()
    except (ValueError, IndexError):
        return ""
    return ""


def _signing_ci_pkids(euicc_info1: bytes) -> list[bytes]:
    """euiccCiPKIdListForSigning 'AA' of EUICCInfo1 'BF20', or [] when it does not parse."""
    try:
        _tag, value, _raw = read_single_ber_tlv(bytes(euicc_info1 or b""))
        offset = 0
        while offset < len(value):
            tag, item, _item_raw, offset = read_ber_tlv(value, offset)
            if tag != b"\xAA":
                continue
            pkids: list[bytes] = []
            inner = 0
            while inner < len(item):
                pkid_tag, pkid, _pkid_raw, inner = read_ber_tlv(item, inner)
                if pkid_tag == b"\x04":
                    pkids.append(bytes(pkid))
            return pkids
    except (ValueError, IndexError):
        return []
    return []


def _answered_by_smds(answer: bytes) -> bool:
    """Whether AuthenticateClientResponseEsipa 'BF3B' holds authenticateClientOkDSEsipa, its second
    alternative 'A1' (SGP.32 v1.3 §6.3.2.2, p.181); anything that does not parse is left to the decoder."""
    try:
        _tag, value, _raw = read_single_ber_tlv(bytes(answer or b""))
        tag, _item, _item_raw, _next = read_ber_tlv(value, 0)
    except (ValueError, IndexError):
        return False
    return tag == b"\xA1"


def _expanded_ci_pkid(identifier: bytes, euicc_info1: bytes) -> bytes:
    """euiccCiPKIdentifierToBeUsed in full. To an IPA with minimizeEsipaBytes the eIM sends the leading
    bytes that pick it out of euiccCiPKIdListForSigning, zero bytes when that list holds one identifier
    (SGP.32 v1.3 §5.14.1 Table 13 NOTE 2, p.159); a full identifier comes back unchanged."""
    signing = _signing_ci_pkids(euicc_info1)
    if identifier in signing:
        return identifier
    matches = [pkid for pkid in signing if pkid.startswith(identifier)]
    if len(matches) == 1:
        return matches[0]
    if len(identifier) == 0:
        raise esipa.EsipaDownloadError(
            "ESipa.InitiateAuthentication: a zero-length CI Public Key Identifier, and euiccInfo1 lists "
            f"{len(signing)} for signing"
        )
    return identifier


class EsipaProfileProvider:
    """The download calls of the ES9+ client, carried over ESipa to one eIM."""

    def __init__(
        self,
        client: Any,
        *,
        eim_fqdn: str,
        pinned_tls_public_key_data: bytes = b"",
        eim_transaction_id: bytes = b"",
    ) -> None:
        self._client = client
        self.eim_fqdn = str(eim_fqdn or "")
        self._pinned = bytes(pinned_tls_public_key_data or b"")
        self.eim_transaction_id = bytes(eim_transaction_id or b"")
        self.matching_id = ""

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def set_base_url(self, base_url: str) -> None:
        """The IPA never contacts the SM-DP+ in an indirect download; the eIM does."""

    def _post(self, body: bytes, step: str) -> bytes:
        answer = self._client.post_esipa(self.eim_fqdn, body, self._pinned)
        if len(answer) == 0:
            raise esipa.EsipaDownloadError(f"ESipa.{step}: the eIM sent no answer")
        return answer

    def initiate_authentication(self, request_obj: InitiateAuthenticationRequest) -> InitiateAuthenticationResponse:
        request = esipa.InitiateAuthenticationRequest(
            euicc_challenge=_field(request_obj.euicc_challenge),
            smdp_address=str(request_obj.smdp_address or "").strip(),
            euicc_info1=_field(request_obj.euicc_info1),
            eim_transaction_id=self.eim_transaction_id,
        )
        answer = esipa.decode_initiate_authentication_response(
            self._post(esipa.encode_initiate_authentication_request(request), "InitiateAuthentication")
        )
        self.matching_id = answer.matching_id
        transaction_id = answer.transaction_id or _signed1_transaction_id(answer.server_signed1)
        # The SM-DP+ certificate check looks its trust up by host, as on the direct path.
        address = _signed1_server_address(answer.server_signed1)
        if address and hasattr(self._client, "set_base_url"):
            self._client.set_base_url(f"https://{address}")
        return InitiateAuthenticationResponse(
            transaction_id=transaction_id.hex().upper(),
            server_signed1=_b64(answer.server_signed1),
            server_signature1=_b64(answer.server_signature1),
            server_certificate=_b64(answer.server_certificate),
            euicc_ci_pkid_to_be_used=_expanded_ci_pkid(answer.euicc_ci_pkid, request.euicc_info1).hex().upper(),
            matching_id=answer.matching_id or None,
        )

    def authenticate_client(self, request_obj: AuthenticateClientRequest) -> AuthenticateClientResponse:
        transaction_id = _transaction_id(request_obj.transaction_id)
        body = esipa.encode_authenticate_client_request(transaction_id, _field(request_obj.authenticate_server_response))
        raw = self._post(body, "AuthenticateClient")
        if _answered_by_smds(raw):
            # SGP.32 v1.3 §3.9.2.2 step 14: the eIM retrieved the Event Records and keeps them; the
            # answer is the SM-DS transactionId and, when the eIM wants a download started, its trigger.
            events = esipa.decode_authenticate_client_ds_response(raw)
            return AuthenticateClientResponse(
                transaction_id=(events.transaction_id or transaction_id).hex().upper(),
                smdp_signed2="",
                smdp_signature2="",
                smdp_certificate="",
                event_retrieval_by_eim=True,
                profile_download_trigger=_b64(events.profile_download_trigger) if events.profile_download_trigger else None,
            )
        answer = esipa.decode_authenticate_client_response(raw)
        return AuthenticateClientResponse(
            transaction_id=(answer.transaction_id or transaction_id).hex().upper(),
            smdp_signed2=_b64(answer.smdp_signed2),
            smdp_signature2=_b64(answer.smdp_signature2),
            smdp_certificate=_b64(answer.smdp_certificate),
            profile_metadata=_b64(answer.profile_metadata) if answer.profile_metadata else None,
        )

    def get_bound_profile_package(self, request_obj: GetBoundProfilePackageRequest) -> GetBoundProfilePackageResponse:
        body = esipa.encode_get_bound_profile_package_request(
            _transaction_id(request_obj.transaction_id), _field(request_obj.prepare_download_response)
        )
        package = esipa.decode_get_bound_profile_package_response(self._post(body, "GetBoundProfilePackage"))
        return GetBoundProfilePackageResponse(bound_profile_package=_b64(package))

    def cancel_session(self, request_obj: CancelSessionRequest) -> dict:
        body = esipa.encode_cancel_session_request(
            _transaction_id(request_obj.transaction_id), _field(request_obj.cancel_session_response)
        )
        esipa.decode_cancel_session_response(self._post(body, "CancelSession"))
        return {}

    def handle_notification(self, request_obj: HandleNotificationRequest) -> dict:
        """ESipa.HandleNotification (§3.2.3.2 step 23): a Notification function, answered with HTTP 204."""
        body = esipa.encode_handle_notification(_field(request_obj.pending_notification))
        self._client.post_esipa(self.eim_fqdn, body, self._pinned)
        return {}
