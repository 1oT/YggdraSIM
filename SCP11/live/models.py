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
from typing import Dict, List, Optional


TRANSPORT_MODE_PCSC = "pcsc"
TRANSPORT_MODE_RELAY = "relay"

BACKEND_MODE_REMOTE_DP = "remote_dp"
BACKEND_MODE_LOCAL_SGP26 = "local_sgp26"

EIM_TRANSPORT_MODE_ESIPA = "esipa_direct"


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
    polling_complete: bool = True
    retry_after_seconds: int = 0
    eim_result_code: Optional[int] = None


@dataclass
class StkTimerState:
    timer_id: int
    active: bool = False
    value_seconds: int = 0
    activation_count: int = 0
    start_monotonic: float = 0.0
    expires_at_monotonic: float = 0.0
    last_command_qualifier: int = 0
    last_value_tlv: bytes = b""
    last_identifier_tlv: bytes = b""
    last_expiration_envelope: bytes = b""


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
    stk_event_list: List[int] = field(default_factory=list)
    stk_command_history: List[str] = field(default_factory=list)
    stk_poll_interval_seconds: int = 0
    stk_polling_off: bool = False
    stk_location_information: bytes = bytes.fromhex("00F11000010001")
    stk_imei: bytes = bytes.fromhex("316F542E59676764726153494D")
    stk_last_proactive_command: bytes = b""
    stk_status_history: List[str] = field(default_factory=list)
    stk_flow_events: List[str] = field(default_factory=list)
    stk_timer_history: List[str] = field(default_factory=list)
    stk_generic_ack_history: List[str] = field(default_factory=list)
    stk_trigger_history: List[str] = field(default_factory=list)
    stk_open_channel_history: List[str] = field(default_factory=list)
    stk_open_channel_failure_history: List[str] = field(default_factory=list)
    stk_dns_history: List[str] = field(default_factory=list)
    stk_tls_history: List[str] = field(default_factory=list)
    stk_alert_history: List[str] = field(default_factory=list)
    stk_timers: Dict[int, StkTimerState] = field(default_factory=dict)
    stk_open_channel_active: bool = False
    stk_open_channel_protocol: str = ""
    stk_open_channel_endpoint: str = ""
    stk_pending_channel_queue: List[bytes] = field(default_factory=list)
    stk_pending_channel_data: bytes = b""
    stk_last_channel_data_sent: int = 0
