import json
import os
import ssl
import urllib.error
import urllib.request

try:
    from .models import (
        AuthenticateClientRequest,
        AuthenticateClientResponse,
        GetBoundProfilePackageRequest,
        GetBoundProfilePackageResponse,
        InitiateAuthenticationRequest,
        InitiateAuthenticationResponse,
    )
except ImportError:
    from models import (
        AuthenticateClientRequest,
        AuthenticateClientResponse,
        GetBoundProfilePackageRequest,
        GetBoundProfilePackageResponse,
        InitiateAuthenticationRequest,
        InitiateAuthenticationResponse,
    )


class Es9LikeClient:
    """Typed ES9-like HTTP client boundary used by SCP11 orchestration."""

    def __init__(
        self,
        base_url: str,
        timeout_seconds: int = 30,
        verify_tls: bool = True,
        ca_bundle_path: str = "",
    ):
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._verify_tls = verify_tls
        self._ca_bundle_path = ca_bundle_path.strip()

    def get_base_url(self) -> str:
        return self._base_url

    def set_base_url(self, base_url: str) -> None:
        normalized = base_url.strip().rstrip("/")
        if len(normalized) == 0:
            raise ValueError("ES9 base URL cannot be empty")
        self._base_url = normalized

    def get_verify_tls(self) -> bool:
        return self._verify_tls

    def set_verify_tls(self, enabled: bool) -> None:
        self._verify_tls = bool(enabled)

    def get_ca_bundle_path(self) -> str:
        return self._ca_bundle_path

    def set_ca_bundle_path(self, path: str) -> None:
        normalized = path.strip()
        if len(normalized) == 0:
            self._ca_bundle_path = ""
            return
        if os.path.exists(normalized) is False:
            raise ValueError(f"ES9 CA bundle does not exist: {normalized}")
        self._ca_bundle_path = normalized

    def initiate_authentication(self, request_obj: InitiateAuthenticationRequest) -> InitiateAuthenticationResponse:
        payload = {
            "euiccChallenge": request_obj.euicc_challenge,
            "euiccInfo1": request_obj.euicc_info1,
            "smdpAddress": request_obj.smdp_address,
        }
        response = self._post_json("/gsma/rsp2/es9plus/initiateAuthentication", payload)
        return InitiateAuthenticationResponse(
            transaction_id=str(response.get("transactionId", "")),
            server_signed1=str(response.get("serverSigned1", "")),
            server_signature1=str(response.get("serverSignature1", "")),
            server_certificate=str(response.get("serverCertificate", "")),
            euicc_ci_pkid_to_be_used=str(response.get("euiccCiPKIdToBeUsed", "")),
        )

    def authenticate_client(self, request_obj: AuthenticateClientRequest) -> AuthenticateClientResponse:
        payload = {
            "transactionId": request_obj.transaction_id,
            "authenticateServerResponse": request_obj.authenticate_server_response,
            "smdpAddress": request_obj.smdp_address,
        }
        response = self._post_json("/gsma/rsp2/es9plus/authenticateClient", payload)
        return AuthenticateClientResponse(
            transaction_id=str(response.get("transactionID", request_obj.transaction_id)),
            profile_metadata=response.get("profileMetadata"),
            smdp_signed2=str(response.get("smdpSigned2", "")),
            smdp_signature2=str(response.get("smdpSignature2", "")),
            smdp_certificate=str(response.get("smdpCertificate", "")),
        )

    def get_bound_profile_package(
        self, request_obj: GetBoundProfilePackageRequest
    ) -> GetBoundProfilePackageResponse:
        payload = {
            "transactionId": request_obj.transaction_id,
            "prepareDownloadResponse": request_obj.prepare_download_response,
            "smdpAddress": request_obj.smdp_address,
        }
        response = self._post_json("/gsma/rsp2/es9plus/getBoundProfilePackage", payload)
        bpp = str(response.get("boundProfilePackage", ""))
        return GetBoundProfilePackageResponse(bound_profile_package=bpp)

    def _post_json(self, path: str, body: dict) -> dict:
        endpoint = self._base_url + path
        payload = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Admin-Protocol": "gsma/rsp/v2.2.0",
            },
        )

        ssl_context = None
        if endpoint.lower().startswith("https://"):
            if self._verify_tls:
                if len(self._ca_bundle_path) > 0:
                    ssl_context = ssl.create_default_context(cafile=self._ca_bundle_path)
                else:
                    ssl_context = ssl.create_default_context()
            else:
                ssl_context = ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds, context=ssl_context) as response:
                raw_response = response.read().decode("utf-8")
        except urllib.error.URLError as error:
            raise IOError(f"ES9 request failed for {endpoint}: {error}") from error

        if len(raw_response.strip()) == 0:
            return {}

        try:
            return json.loads(raw_response)
        except json.JSONDecodeError:
            json_start = raw_response.find("{")
            if json_start == -1:
                raise IOError(f"ES9 response was not JSON: {raw_response}")
            trimmed = raw_response[json_start:]
            return json.loads(trimmed)
