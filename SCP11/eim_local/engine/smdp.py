# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The local SM-DP+ behind the Local eIM service: ES9+ over the SGP.22 JSON binding.

InitiateAuthentication, AuthenticateClient and GetBoundProfilePackage are
answered with the Local eIM session's SM-DP+ material (the SGP.26 test
certificates it already loads) and a Bound Profile Package built for the
session the eUICC opened. The Matching ID in ctxParams1 picks the profile:
``smdp_profiles.json`` in the engine store maps Matching IDs to profile files,
and any other Matching ID gets the session's configured profile. A profile
download trigger the Local eIM serves with ``1$<this address>$<Matching ID>``
is completed here by whichever IPA runs it. AuthenticateClient answers with the
Profile Metadata of that profile; the ASN.1 binding a card's IPAe speaks
(``es9_binding``) cannot leave it out.

With the local SM-DS attached (``smds``) the SM-DP+ deletes the Event Record
a download came from once that download ends: on its ProfileInstallationResult
(SGP.22 v3.1 §3.1.3.3 step 10) and on a CancelSession for any reason but
postponed or timeout (§3.0.2 step 8).
"""

from __future__ import annotations

import base64
import binascii
import json
import sqlite3
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

PROFILES_FILE = "smdp_profiles.json"
# Open ES9+ sessions are kept per transactionId until the BPP is served; a
# client that never finishes is pushed out by newer ones.
MAX_OPEN_TRANSACTIONS = 64
# CancelSessionReason postponed and timeout leave the download order pending (SGP.22 v3.1 §3.0.2, §5.7.14).
CANCEL_REASONS_KEEPING_THE_ORDER = (1, 2)

ES9_PATHS = (
    "/gsma/rsp2/es9plus/initiateAuthentication",
    "/gsma/rsp2/es9plus/authenticateClient",
    "/gsma/rsp2/es9plus/getBoundProfilePackage",
    "/gsma/rsp2/es9plus/handleNotification",
    "/gsma/rsp2/es9plus/cancelSession",
)


class SmdpError(RuntimeError):
    """An ES9+ request the local SM-DP+ cannot answer."""


class SmdpAddressError(SmdpError):
    """InitiateAuthentication names another server's address (SGP.22 v3.1 §5.6.1: 8.8.1 / 3.8, Invalid SM-DP+ Address)."""

    subject_code = "8.8.1"
    reason_code = "3.8"


def _decode_field(value: Any, name: str) -> bytes:
    text = str(value or "").strip()
    if len(text) == 0:
        raise SmdpError(f"{name} is missing or empty.")
    try:
        if len(text) % 2 == 0 and all(character in "0123456789abcdefABCDEF" for character in text):
            return bytes.fromhex(text)
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as error:
        raise SmdpError(f"{name} is neither base64 nor hex.") from error


def _b64(value: bytes) -> str:
    return base64.b64encode(bytes(value)).decode("ascii")


def _children(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, item_value, raw, offset = read_ber_tlv(value, offset)
        items.append((tag, item_value, raw))
    return items


def euicc_signature1(authenticate_server_response: bytes) -> bytes:
    """Return euiccSignature1 '5F37' from AuthenticateServerResponse 'BF38' { 'A0' { '30' ..., '5F37' ... } }."""
    _tag, value, _raw = read_single_ber_tlv(authenticate_server_response)
    for tag, item_value, _item_raw in _children(value):
        if tag != b"\xA0":
            continue
        for inner_tag, inner_value, _inner_raw in _children(item_value):
            if inner_tag == b"\x5F\x37":
                return bytes(inner_value)
    raise SmdpError("AuthenticateServerResponse carries no euiccSignature1.")


def euicc_eid(authenticate_server_response: bytes) -> str:
    """Return the EID of the eUICC certificate in AuthenticateServerResponse 'BF38' { 'A0' { ... } }, or ''.

    AuthenticateResponseOk carries euiccSigned1, euiccSignature1, then
    euiccCertificate and eumCertificate; the eUICC certificate's subject
    'serialNumber' is the EID as a decimal string (SGP.22 v3.1 §4.5.2.1.0.2).
    The SM-DP+ binds the BPP to it, so it is taken from there, not read from a card.
    """
    from SCP11.eim_local.engine.codec import certificate_eid

    try:
        _tag, value, _raw = read_single_ber_tlv(authenticate_server_response)
        for tag, item_value, _item_raw in _children(value):
            if tag != b"\xA0":
                continue
            certificates = [raw for item_tag, _v, raw in _children(item_value) if item_tag == b"\x30"][1:]
            for certificate in certificates:
                digits = certificate_eid(certificate)
                if digits:
                    return digits
    except ValueError:
        return ""
    return ""


def matching_id(authenticate_server_response: bytes) -> str:
    """Return the Matching ID of ctxParamsForCommonAuthentication, or ''.

    euiccSigned1 '30' { '80', '83', '84', 'BF22', ctxParams1 }: ctxParams1 is an
    untagged CHOICE, so its ctxParamsForCommonAuthentication alternative is the
    'A0' itself, matchingId '80' directly inside (SGP.22 v3.1 EuiccSigned1).
    """
    try:
        _tag, value, _raw = read_single_ber_tlv(authenticate_server_response)
        for tag, item_value, _item_raw in _children(value):
            if tag != b"\xA0":
                continue
            for signed_tag, signed_value, _signed_raw in _children(item_value):
                if signed_tag != b"\x30":
                    continue
                for ctx_tag, ctx_value, _ctx_raw in _children(signed_value):
                    if ctx_tag != b"\xA0":
                        continue
                    for field_tag, field_value, _field_raw in _children(ctx_value):
                        if field_tag == b"\x80":
                            return field_value.decode("utf-8", errors="replace")
    except ValueError:
        return ""
    return ""


def bound_package_metadata(bound_profile_package: bytes) -> bytes:
    """The StoreMetadataRequest 'BF25' a Bound Profile Package 'BF36' carries, or b''.

    sequenceOf88 'A1' holds the StoreMetadata command as '88' blocks (SGP.22
    v3.1 §2.5.4); each is protected by a C-MAC only, its data followed by the
    8-octet C-MAC (§2.6.4.5), so the metadata reads back without a session key.
    """
    try:
        tag, value, _raw = read_single_ber_tlv(bytes(bound_profile_package or b""))
        if tag != b"\xBF\x36":
            return b""
        for item_tag, item_value, _item_raw in _children(value):
            if item_tag != b"\xA1":
                continue
            data = b"".join(block[:-8] for block_tag, block, _block_raw in _children(item_value)
                            if block_tag == b"\x88" and len(block) > 8)
            found, _metadata, raw = read_single_ber_tlv(data)
            return bytes(raw) if found == b"\xBF\x25" else b""
    except (ValueError, IndexError):
        return b""
    return b""


def cancel_reason(cancel_session_response: bytes) -> int | None:
    """reason of euiccCancelSessionSigned in a CancelSessionResponse 'BF41', or None when it carries none.

    'BF41' { 'A0' cancelSessionResponseOk { '30' { transactionId '80', smdpOid
    '81', reason '82' }, '5F37' } } (SGP.22 v3.1 §5.7.14): the three members
    are untagged in the module, so they carry automatic tags.
    """
    try:
        tag, value, _raw = read_single_ber_tlv(bytes(cancel_session_response or b""))
        if tag != b"\xBF\x41":
            return None
        for choice_tag, choice_value, _choice_raw in _children(value):
            if choice_tag != b"\xA0":
                continue
            for signed_tag, signed_value, _signed_raw in _children(choice_value):
                if signed_tag != b"\x30":
                    continue
                for member_tag, member_value, _member_raw in _children(signed_value):
                    if member_tag == b"\x82" and len(member_value) > 0:
                        return int.from_bytes(member_value, "big", signed=True)
    except (ValueError, IndexError):
        return None
    return None


def host_of(address: str) -> str:
    """The host name of an SM-DP+ address given as a name, a host:port or a URL; lower case."""
    text = str(address or "").strip().lower()
    if "://" in text:
        text = urlparse(text).hostname or ""
    return text.split("/", 1)[0].split(":", 1)[0].rstrip(".")


class LocalSmdp:
    """ES9+ answers from a headless Local eIM session; one instance per service process."""

    def __init__(self, directory: Path, session_factory: Callable[[], Any] | None = None) -> None:
        self.directory = Path(directory)
        self._factory = session_factory or _default_session
        self._session: Any = None
        self._lock = threading.RLock()
        self._transactions: OrderedDict[str, dict[str, Any]] = OrderedDict()
        # The EID and Matching ID of each session whose BPP was served, kept until its
        # ProfileInstallationResult arrives; bounded like the open sessions.
        self._delivered: OrderedDict[str, dict[str, Any]] = OrderedDict()
        # The local SM-DS, when the service runs one: told when a download ends.
        self.smds: Any = None
        self.log: Callable[[str], None] = lambda _line: None

    def session(self) -> Any:
        with self._lock:
            if self._session is None:
                self._session = self._factory()
            return self._session

    def address(self) -> str:
        try:
            return str(self.session()._effective_smdp_address() or "").strip()
        except (AttributeError, OSError, ValueError):
            return ""

    def host(self) -> str:
        """The FQDN an IPA resolves to reach this SM-DP+, '' without an address."""
        return host_of(self.address())

    def transaction(self, transaction_id: bytes) -> dict[str, Any] | None:
        """What is kept of an open ES9+ session, or None for a transactionId this SM-DP+ did not hand out."""
        with self._lock:
            entry = self._transactions.get(bytes(transaction_id).hex().upper())
            return dict(entry) if entry is not None else None

    def profiles(self) -> dict[str, str]:
        path = self.directory / PROFILES_FILE
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError as error:
            raise SmdpError(f"{path} is not valid JSON: {error}") from error
        if not isinstance(document, dict):
            raise SmdpError(f"{path} must map Matching IDs to profile paths.")
        return {str(key): str(value) for key, value in document.items()}

    def set_profile(self, matching: str, profile_path: str) -> dict[str, str]:
        """Map *matching* to *profile_path*; an empty path removes the mapping."""
        profiles = self.profiles()
        key = str(matching).strip()
        if len(key) == 0:
            raise SmdpError("A Matching ID is needed.")
        if len(str(profile_path).strip()) == 0:
            profiles.pop(key, None)
        else:
            resolved = Path(str(profile_path)).expanduser()
            if not resolved.is_file():
                raise SmdpError(f"No profile file at {resolved}.")
            profiles[key] = str(resolved)
        path = self.directory / PROFILES_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(profiles, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return profiles

    def handle(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        name = path.rstrip("/").rsplit("/", 1)[-1]
        if name == "initiateAuthentication":
            return self._initiate_authentication(payload)
        if name == "authenticateClient":
            return self._authenticate_client(payload)
        if name == "getBoundProfilePackage":
            return self._get_bound_profile_package(payload)
        if name in ("handleNotification", "cancelSession"):
            transaction = str(payload.get("transactionId", "") or "")
            if name == "handleNotification" and not transaction:
                transaction = self._installation_result_transaction(payload)
            ended: dict[str, Any] | None = None
            if transaction:
                with self._lock:
                    opened = self._transactions.pop(transaction.upper(), None)
                    delivered = self._delivered.pop(transaction.upper(), None) if name == "handleNotification" else None
                if name == "handleNotification":
                    ended = delivered
                elif opened is not None and self._cancel_ends_order(payload):
                    ended = opened
            self.log(f"ES9+ {name}")
            if ended is not None:
                self._download_ended(ended)
            return {}
        raise SmdpError(f"Unknown ES9+ function {name!r}.")

    @staticmethod
    def _installation_result_transaction(payload: dict[str, Any]) -> str:
        """The transactionId a ProfileInstallationResult names, in hex; '' for any other Notification."""
        from SCP11.shared.esipa_download import installation_result_transaction_id

        try:
            notification = _decode_field(payload.get("pendingNotification"), "pendingNotification")
        except SmdpError:
            return ""
        return installation_result_transaction_id(notification).hex().upper()

    @staticmethod
    def _cancel_ends_order(payload: dict[str, Any]) -> bool:
        """Whether a CancelSession ends the download order: any reason read from it but postponed and timeout."""
        try:
            reason = cancel_reason(_decode_field(payload.get("cancelSessionResponse"), "cancelSessionResponse"))
        except SmdpError:
            return False
        return reason is not None and reason not in CANCEL_REASONS_KEEPING_THE_ORDER

    def _note_delivered(self, transaction_hex: str, eid: str, matching: str) -> None:
        """Keep what the ProfileInstallationResult of a served BPP will be matched with."""
        with self._lock:
            self._delivered[transaction_hex] = {"eid": eid, "matching_id": matching}
            self._delivered.move_to_end(transaction_hex)
            while len(self._delivered) > MAX_OPEN_TRANSACTIONS:
                self._delivered.popitem(last=False)

    def _download_ended(self, context: dict[str, Any]) -> None:
        """Event Deletion at the local SM-DS for a download that ended; its failure never fails the ES9+ answer."""
        if self.smds is None:
            return
        try:
            self.smds.download_ended(str(context.get("eid", "") or ""), str(context.get("matching_id", "") or ""),
                                     self.host())
        except (sqlite3.Error, OSError, RuntimeError, ValueError) as error:
            self.log(f"ES9+: Event Deletion at the local SM-DS failed: {error}")

    def _remember(self, transaction_hex: str, values: dict[str, Any]) -> None:
        with self._lock:
            entry = self._transactions.setdefault(transaction_hex, {})
            entry.update(values)
            self._transactions.move_to_end(transaction_hex)
            while len(self._transactions) > MAX_OPEN_TRANSACTIONS:
                self._transactions.popitem(last=False)

    def _initiate_authentication(self, payload: dict[str, Any]) -> dict[str, Any]:
        from SCP11.live.crypto_engine import CryptoEngine

        requested = str(payload.get("smdpAddress", "") or "").strip()
        own = self.address()
        # serverSigned1 carries the address it is signed for: answering for another server's
        # address would sign as that server under this one's certificate. Refused before any
        # key is loaded, since none is needed to refuse.
        if requested and own and host_of(requested) != host_of(own):
            raise SmdpAddressError(f"InitiateAuthentication names {requested}; this SM-DP+ is {own}.")
        session = self.session()
        session._ensure_local_material_loaded()
        challenge = _decode_field(payload.get("euiccChallenge"), "euiccChallenge")
        address = requested or own
        signed1, transaction_id, server_challenge = CryptoEngine.generate_server_challenges(challenge, address)
        signature = CryptoEngine.sign_asn1(signed1, session._key_auth)
        transaction_hex = bytes(transaction_id).hex().upper()
        self._remember(transaction_hex, {"server_challenge": bytes(server_challenge), "smdp_address": address})
        self.log(f"ES9+ initiateAuthentication {transaction_hex} for {address}")
        ci_pkid = str(getattr(session.state, "selected_ci_pkid", "") or "") or session.cfg.ROOT_CI_ID.hex().upper()
        return {
            "transactionId": _b64(transaction_id),
            "serverSigned1": _b64(signed1),
            "serverSignature1": _b64(signature),
            "serverCertificate": _b64(session._cert_auth),
            "euiccCiPKIdToBeUsed": ci_pkid,
        }

    def _authenticate_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        from SCP11.live.payload_builder import PayloadBuilder

        session = self.session()
        session._ensure_local_material_loaded()
        transaction_id = _decode_field(payload.get("transactionId"), "transactionId")
        response = _decode_field(payload.get("authenticateServerResponse"), "authenticateServerResponse")
        signature = euicc_signature1(response)
        prepare = PayloadBuilder.build_prepare_download(transaction_id, signature, session._cert_pb, session._key_pb)
        _tag, value, _raw = read_single_ber_tlv(prepare)
        parts = _children(value)
        if len(parts) < 3:
            raise SmdpError("The local PrepareDownload request lacks smdpSigned2, smdpSignature2 or the certificate.")
        transaction_hex = transaction_id.hex().upper()
        chosen = matching_id(response)
        self._remember(transaction_hex, {"matching_id": chosen, "eid": euicc_eid(response)})
        self.log(f"ES9+ authenticateClient {transaction_hex} matchingId {chosen or '(none)'}")
        answer = {
            "transactionId": _b64(transaction_id),
            "smdpSigned2": _b64(parts[0][2]),
            "smdpSignature2": _b64(parts[1][2]),
            "smdpCertificate": _b64(parts[2][2]),
        }
        try:
            metadata = self.profile_metadata(chosen)
        except (SmdpError, ValueError, OSError, RuntimeError, LookupError, AttributeError, TypeError) as error:
            # The download fails on the same cause at GetBoundProfilePackage; a JSON client still gets this step.
            self.log(f"ES9+ authenticateClient {transaction_hex}: no Profile Metadata: {error}")
            metadata = b""
        if metadata:
            answer["profileMetadata"] = _b64(metadata)
        return answer

    def profile_for(self, matching: str) -> str:
        return self.profiles().get(str(matching or "").strip(), "")

    def profile_metadata(self, matching: str) -> bytes:
        """StoreMetadataRequest 'BF25' of the profile *matching* selects, as its BPP will carry it."""
        builder = self._builder()
        source = builder._read_profile_source_bytes(profile_path=self.profile_for(matching))
        if source.startswith(b"\xBF\x36"):
            metadata = bound_package_metadata(source)
            if not metadata:
                raise SmdpError("The Bound Profile Package on file carries no readable StoreMetadata.")
            return metadata
        return bytes(builder.build_store_metadata_request(source))

    def _get_bound_profile_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        prepare_response = _decode_field(payload.get("prepareDownloadResponse"), "prepareDownloadResponse")
        transaction_id = _decode_field(payload.get("transactionId"), "transactionId")
        transaction_hex = transaction_id.hex().upper()
        with self._lock:
            context = dict(self._transactions.get(transaction_hex, {}))
        profile_path = self.profile_for(str(context.get("matching_id", "")))
        eid = str(context.get("eid", "") or "")
        builder = self._builder()
        builder.state.prepare_download_response = bytes(prepare_response)
        builder.state.transaction_id = bytes(transaction_id)
        builder.state.server_challenge = bytes(context.get("server_challenge", b"") or b"")
        if eid:
            # The builder runs without a card: the EID comes from AuthenticateClient.
            builder._read_card_eid = lambda: eid
        source = builder._read_profile_source_bytes(profile_path=profile_path)
        if source.startswith(b"\xBF\x36"):
            package = bytes(source)
        else:
            package = builder._build_session_bound_profile_package(source)
        with self._lock:
            self._transactions.pop(transaction_hex, None)
        self._note_delivered(transaction_hex, eid, str(context.get("matching_id", "") or ""))
        self.log(
            f"ES9+ getBoundProfilePackage {transaction_hex}: {len(package)} bytes from "
            f"{profile_path or 'the configured profile'}"
        )
        return {"transactionId": _b64(transaction_id), "boundProfilePackage": _b64(package)}

    def _builder(self) -> Any:
        """A fresh session per BPP, carrying the loaded SM-DP+ material (one BPP, one session state)."""
        session = self.session()
        session._ensure_local_material_loaded()
        builder = session.__class__(cfg=session.cfg, apdu_channel=None)
        for name in ("_cert_auth", "_key_auth", "_cert_pb", "_key_pb"):
            setattr(builder, name, getattr(session, name))
        for name in (
            "allowed_ci_pkids",
            "selected_ci_pkid",
            "selected_auth_certificate_path",
            "selected_pb_certificate_path",
            "selected_auth_private_key_path",
            "selected_pb_private_key_path",
        ):
            if hasattr(session.state, name):
                value = getattr(session.state, name)
                setattr(builder.state, name, list(value) if isinstance(value, list) else value)
        return builder


def _default_session() -> Any:
    from SCP11.eim_local.config import EimLocalConfig
    from SCP11.eim_local.session import EimLocalSession

    return EimLocalSession(cfg=EimLocalConfig(), apdu_channel=None)
