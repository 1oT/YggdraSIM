# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 providers: concrete SM-DP+ and eIM provider implementations for local-file, HTTP, and relay-socket delivery."""
# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

import base64
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List

from cryptography import x509 as crypto_x509
from cryptography.hazmat.backends import default_backend

try:
    from .es9_client import Es9LikeClient
    from .models import (
        AuthenticateClientRequest,
        AuthenticateClientResponse,
        CancelSessionRequest,
        EimPollRequest,
        EimPollResponse,
        GetBoundProfilePackageRequest,
        GetBoundProfilePackageResponse,
        HandleNotificationRequest,
        InitiateAuthenticationRequest,
        InitiateAuthenticationResponse,
    )
except ImportError:
    from es9_client import Es9LikeClient
    from models import (
        AuthenticateClientRequest,
        AuthenticateClientResponse,
        CancelSessionRequest,
        EimPollRequest,
        EimPollResponse,
        GetBoundProfilePackageRequest,
        GetBoundProfilePackageResponse,
        HandleNotificationRequest,
        InitiateAuthenticationRequest,
        InitiateAuthenticationResponse,
    )


class ProfileProvider(ABC):
    @abstractmethod
    def initiate_authentication(
        self, request_obj: InitiateAuthenticationRequest
    ) -> InitiateAuthenticationResponse:
        pass

    @abstractmethod
    def authenticate_client(
        self, request_obj: AuthenticateClientRequest
    ) -> AuthenticateClientResponse:
        pass

    @abstractmethod
    def get_bound_profile_package(
        self, request_obj: GetBoundProfilePackageRequest
    ) -> GetBoundProfilePackageResponse:
        pass

    @abstractmethod
    def cancel_session(self, request_obj: CancelSessionRequest) -> dict:
        pass

    @abstractmethod
    def handle_notification(self, request_obj: HandleNotificationRequest) -> dict:
        pass

    @abstractmethod
    def get_eim_package(self, request_obj: EimPollRequest) -> EimPollResponse:
        pass

    @abstractmethod
    def provide_eim_package_result(self, request_obj: EimPollRequest) -> dict:
        pass

    @abstractmethod
    def poll_eim(self, request_obj: EimPollRequest) -> EimPollResponse:
        pass


class RemoteEs9Provider(ProfileProvider):
    def __init__(self, es9_client: Es9LikeClient):
        self._client = es9_client

    def initiate_authentication(
        self, request_obj: InitiateAuthenticationRequest
    ) -> InitiateAuthenticationResponse:
        return self._client.initiate_authentication(request_obj)

    def authenticate_client(
        self, request_obj: AuthenticateClientRequest
    ) -> AuthenticateClientResponse:
        return self._client.authenticate_client(request_obj)

    def get_bound_profile_package(
        self, request_obj: GetBoundProfilePackageRequest
    ) -> GetBoundProfilePackageResponse:
        return self._client.get_bound_profile_package(request_obj)

    def cancel_session(self, request_obj: CancelSessionRequest) -> dict:
        return self._client.cancel_session(request_obj)

    def handle_notification(self, request_obj: HandleNotificationRequest) -> dict:
        return self._client.handle_notification(request_obj)

    def get_eim_package(self, request_obj: EimPollRequest) -> EimPollResponse:
        return self._client.get_eim_package(request_obj)

    def provide_eim_package_result(self, request_obj: EimPollRequest) -> dict:
        return self._client.provide_eim_package_result(request_obj)

    def poll_eim(self, request_obj: EimPollRequest) -> EimPollResponse:
        return self._client.poll_eim(request_obj)

    def get_base_url(self) -> str:
        return self._client.get_base_url()

    def set_base_url(self, base_url: str) -> None:
        self._client.set_base_url(base_url)

    def get_verify_tls(self) -> bool:
        return self._client.get_verify_tls()

    def set_verify_tls(self, enabled: bool) -> None:
        self._client.set_verify_tls(enabled)

    def get_ca_bundle_path(self) -> str:
        return self._client.get_ca_bundle_path()

    def set_ca_bundle_path(self, path: str) -> None:
        self._client.set_ca_bundle_path(path)

    def resolve_provider_certificate_validation_bundle(
        self,
        certificate_der: bytes,
        trust_hint_ci_pkid: str = "",
    ) -> str:
        """Return the filesystem path of the CA PEM bundle appropriate for validating this provider's server cert."""
        return self._client.resolve_provider_certificate_validation_bundle(
            certificate_der,
            trust_hint_ci_pkid=trust_hint_ci_pkid,
        )


class Sgp26LocalProvider(ProfileProvider):
    """
    SGP.26 local-profile-loading provider scaffold.
    It validates certificate chains and keeps API parity with ES9 boundaries.
    """

    def __init__(self, trust_anchor_path: str = "", intermediate_paths: List[str] = None, issuer_cert_path: str = ""):
        self._trust_anchor_path = trust_anchor_path
        self._intermediate_paths = intermediate_paths or []
        self._issuer_cert_path = issuer_cert_path
        self._chain_loaded = False
        self._trust_anchor = None
        self._intermediates = []
        self._issuer_cert = None

    def load_certificate_chain(self) -> None:
        """Load and return a list of PEM certificate strings from a directory or file path."""
        if len(self._trust_anchor_path) > 0:
            self._trust_anchor = self._load_cert(self._trust_anchor_path)
        else:
            self._trust_anchor = None

        self._intermediates = []
        for cert_path in self._intermediate_paths:
            self._intermediates.append(self._load_cert(cert_path))

        if len(self._issuer_cert_path) > 0:
            self._issuer_cert = self._load_cert(self._issuer_cert_path)
        else:
            self._issuer_cert = None

        self._chain_loaded = True

    def validate_chain_time_window(self) -> None:
        """Raise ``CertificateExpiredError`` if any certificate in the chain is outside its validity period."""
        if self._chain_loaded is False:
            self.load_certificate_chain()

        now = datetime.now(timezone.utc)
        certs_to_check = []
        if self._trust_anchor is not None:
            certs_to_check.append(self._trust_anchor)
        certs_to_check.extend(self._intermediates)
        if self._issuer_cert is not None:
            certs_to_check.append(self._issuer_cert)

        for cert in certs_to_check:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            if now < not_before:
                raise ValueError("Certificate not yet valid in SGP.26 provider chain")
            if now > not_after:
                raise ValueError("Expired certificate detected in SGP.26 provider chain")

    def validate_chain_subject_issuers(self) -> None:
        """Raise ``CertificateChainError`` when the issuer/subject chain of the certificate list is broken."""
        if self._chain_loaded is False:
            self.load_certificate_chain()

        previous_subject = None
        if self._trust_anchor is not None:
            previous_subject = self._trust_anchor.subject.rfc4514_string()

        for cert in self._intermediates:
            if previous_subject is not None:
                issuer_name = cert.issuer.rfc4514_string()
                if issuer_name != previous_subject:
                    raise ValueError("Intermediate issuer does not match previous certificate subject")
            previous_subject = cert.subject.rfc4514_string()

        if self._issuer_cert is not None and previous_subject is not None:
            issuer_name = self._issuer_cert.issuer.rfc4514_string()
            if issuer_name != previous_subject:
                raise ValueError("Issuer certificate does not chain from intermediate subject")

    def initiate_authentication(
        self, request_obj: InitiateAuthenticationRequest
    ) -> InitiateAuthenticationResponse:
        self._ensure_chain()
        raise NotImplementedError("SGP.26 local initiateAuthentication is not implemented yet")

    def authenticate_client(
        self, request_obj: AuthenticateClientRequest
    ) -> AuthenticateClientResponse:
        self._ensure_chain()
        raise NotImplementedError("SGP.26 local authenticateClient is not implemented yet")

    def get_bound_profile_package(
        self, request_obj: GetBoundProfilePackageRequest
    ) -> GetBoundProfilePackageResponse:
        self._ensure_chain()
        raise NotImplementedError("SGP.26 local getBoundProfilePackage is not implemented yet")

    def cancel_session(self, request_obj: CancelSessionRequest) -> dict:
        self._ensure_chain()
        raise NotImplementedError("SGP.26 local cancelSession is not implemented yet")

    def handle_notification(self, request_obj: HandleNotificationRequest) -> dict:
        self._ensure_chain()
        raise NotImplementedError("SGP.26 local handleNotification is not implemented yet")

    def get_eim_package(self, request_obj: EimPollRequest) -> EimPollResponse:
        self._ensure_chain()
        raise NotImplementedError("SGP.26 local getEimPackage is not implemented yet")

    def provide_eim_package_result(self, request_obj: EimPollRequest) -> dict:
        self._ensure_chain()
        raise NotImplementedError("SGP.26 local provideEimPackageResult is not implemented yet")

    def poll_eim(self, request_obj: EimPollRequest) -> EimPollResponse:
        self._ensure_chain()
        raise NotImplementedError("SGP.26 local eIM polling is not implemented yet")

    def _ensure_chain(self) -> None:
        self.validate_chain_time_window()
        self.validate_chain_subject_issuers()

    def _load_cert(self, cert_path: str):
        with open(cert_path, "rb") as cert_file:
            cert_data = cert_file.read()
        try:
            return crypto_x509.load_pem_x509_certificate(cert_data, backend=default_backend())
        except ValueError:
            return crypto_x509.load_der_x509_certificate(cert_data, backend=default_backend())

    @staticmethod
    def decode_b64_to_bytes(value: str) -> bytes:
        if len(value) == 0:
            return b""
        return base64.b64decode(value.encode("utf-8"))
