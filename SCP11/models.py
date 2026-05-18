# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 data models: dataclasses for ES2+/ES9+ request/response payloads, profile metadata, and session state."""
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

from dataclasses import dataclass, field
from typing import List, Optional


TRANSPORT_MODE_PCSC = "pcsc"
TRANSPORT_MODE_RELAY = "relay"

BACKEND_MODE_REMOTE_DP = "remote_dp"
BACKEND_MODE_LOCAL_SGP26 = "local_sgp26"

EIM_TRANSPORT_MODE_ESIPA = "esipa_direct"
EIM_TRANSPORT_MODE_REST_RESOURCE = "rest_resource"


@dataclass
class InitiateAuthenticationRequest:
    euicc_challenge: str
    euicc_info1: str
    smdp_address: str
    euicc_ci_pkid_hint: str = ""


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
class CancelSessionRequest:
    transaction_id: str
    cancel_session_response: str


@dataclass
class HandleNotificationRequest:
    pending_notification: str
    # SGP.22 §5.6.4: each PendingNotification carries the FQDN of the
    # SM-DP+ that minted it (NotificationMetadata.notificationAddress,
    # tag 0C UTF8String). The LPA MUST forward the notification to that
    # address rather than to a global ES9 endpoint -- profiles from
    # different SM-DP+ instances coexist on the same eUICC and trust
    # roots / CI keys differ between live and test environments.
    # Empty string means "fall back to the configured base URL", which
    # preserves the legacy behaviour for tests and for cards whose
    # metadata does not carry a notificationAddress.
    smdp_address: str = ""


@dataclass
class EimPollRequest:
    eim_fqdn: str
    eim_id: str
    eim_id_type: str
    counter_value: str
    association_token: str
    supported_protocol: str
    euicc_ci_pkid: str
    indirect_profile_download: str
    euicc_configured_data: str
    eim_configuration_data: str
    euicc_info1: str = ""
    euicc_info2: str = ""
    eid: str = ""
    matching_id: str = ""
    transaction_id: str = ""
    euicc_package_result: str = ""
    euicc_challenge: str = ""
    trusted_tls_public_key_data: bytes = b""
    raw_body: Optional[bytes] = None


@dataclass
class EimPollResponse:
    transaction_id: str = ""
    euicc_package_list: List[str] = field(default_factory=list)
    package_format: str = ""
    ack_sequence_numbers: List[int] = field(default_factory=list)
    polling_complete: bool = True
    retry_after_seconds: int = 0
    eim_result_code: Optional[int] = None


@dataclass
class SCP11SessionState:
    transaction_id: bytes = b""
    provider_transaction_id: str = ""
    provider_smdp_certificate: bytes = b""
    current_euicc_ci_pkid: str = ""
    card_challenge: bytes = b""
    server_challenge: bytes = b""
    euicc_signed1: bytes = b""
    euicc_signature1: bytes = b""
    euicc_signed2: bytes = b""
    relay_session_id: str = ""
    authenticate_server_response_b64: str = ""
    prepare_download_response_b64: str = ""
    bpp_b64: str = ""
    bpp_bytes: bytes = b""
    load_bpp_response: bytes = b""
    load_bpp_aid: bytes = b""
    load_bpp_sima_response: bytes = b""
    eim_package_response: bytes = b""
