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
        GetBoundProfilePackageRequest,
        GetBoundProfilePackageResponse,
        InitiateAuthenticationRequest,
        InitiateAuthenticationResponse,
    )
except ImportError:
    from es9_client import Es9LikeClient
    from models import (
        AuthenticateClientRequest,
        AuthenticateClientResponse,
        GetBoundProfilePackageRequest,
        GetBoundProfilePackageResponse,
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
