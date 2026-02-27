from dataclasses import dataclass
from typing import Optional


TRANSPORT_MODE_PCSC = "pcsc"
TRANSPORT_MODE_RELAY = "relay"

BACKEND_MODE_REMOTE_DP = "remote_dp"
BACKEND_MODE_LOCAL_SGP26 = "local_sgp26"


@dataclass
class InitiateAuthenticationRequest:
    euicc_challenge: str
    euicc_info1: str
    smdp_address: str


@dataclass
class InitiateAuthenticationResponse:
    transaction_id: str
    server_signed1: str
    server_signature1: str
    server_certificate: str
    euicc_ci_pkid_to_be_used: str


@dataclass
class AuthenticateClientRequest:
    transaction_id: str
    authenticate_server_response: str
    smdp_address: str


@dataclass
class AuthenticateClientResponse:
    transaction_id: str
    smdp_signed2: str
    smdp_signature2: str
    smdp_certificate: str
    profile_metadata: Optional[str] = None


@dataclass
class GetBoundProfilePackageRequest:
    transaction_id: str
    prepare_download_response: str
    smdp_address: str


@dataclass
class GetBoundProfilePackageResponse:
    bound_profile_package: str


@dataclass
class SCP11SessionState:
    transaction_id: bytes = b""
    card_challenge: bytes = b""
    server_challenge: bytes = b""
    euicc_signature1: bytes = b""
    relay_session_id: str = ""
    authenticate_server_response_b64: str = ""
    prepare_download_response_b64: str = ""
    bpp_b64: str = ""
