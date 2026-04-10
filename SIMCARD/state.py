from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


DEFAULT_SIM_ATR = bytes.fromhex("3B9F96801FC7A073BE21136743200718000001A5")


@dataclass
class SimProfileFsNode:
    path: tuple[str, ...]
    name: str
    kind: str
    fid: str = ""
    aid: str = ""
    label: str = ""
    structure: str = "transparent"
    data: bytes = b""
    records: list[bytes] = field(default_factory=list)
    sfi: int | None = None


@dataclass
class SimProfileImage:
    profile_name: str = ""
    iccid: str = ""
    imsi: str = ""
    impi: str = ""
    nodes: list[SimProfileFsNode] = field(default_factory=list)


@dataclass
class SimProfileEntry:
    aid: str
    iccid: str
    state: str = "enabled"
    profile_class: str = "test"
    nickname: str = ""
    service_provider: str = ""
    profile_name: str = ""
    imsi: str = ""
    impi: str = ""
    notification_address: str = ""
    upp_bytes: bytes = b""
    profile_image: SimProfileImage | None = None
    profile_source: str = "json"


@dataclass
class SimFileNode:
    node_id: str
    name: str
    kind: str
    fid: str = ""
    aid: str = ""
    label: str = ""
    parent_id: str = ""
    structure: str = "transparent"
    data: bytes = b""
    records: list[bytes] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    sfi: int | None = None

    @property
    def total_size(self) -> int:
        if self.structure == "linear-fixed":
            return sum(len(record) for record in self.records)
        return len(self.data)

    @property
    def record_length(self) -> int:
        if len(self.records) == 0:
            return 0
        return len(self.records[0])


@dataclass
class SimNotificationEntry:
    seq_number: int
    operation: int
    address: str
    iccid: str
    aid: str = ""
    payload: bytes = b""


@dataclass
class SimScp03Session:
    key_version: int = 0x30
    host_challenge: bytes = b""
    card_challenge: bytes = b""
    security_level: int = 0
    authenticated: bool = False
    chaining_value: bytes = b"\x00" * 16
    ssc: int = 0
    selected_aid: str = ""


@dataclass
class SimSgpSession:
    card_challenge: bytes = b""
    transaction_id: bytes = b""
    server_address: str = ""
    server_challenge: bytes = b""
    authenticate_server_request: bytes = b""
    authenticate_server_response: bytes = b""
    prepare_download_request: bytes = b""
    prepare_download_response: bytes = b""
    euicc_signed1: bytes = b""
    euicc_signature1: bytes = b""
    euicc_signed2: bytes = b""
    euicc_signature2: bytes = b""
    euicc_otpk: bytes = b""
    euicc_ot_private_key: Any = None
    smdp_certificate: bytes = b""
    session_open: bool = False
    prepare_download_done: bool = False
    pending_bpp_segments: list[bytes] = field(default_factory=list)
    install_command_id: int = 0
    bpp_bsp: Any = None
    bpp_section: str = ""
    bpp_section_remaining: int = -1
    bpp_configure_isdp_request: bytes = b""
    bpp_store_metadata_request: bytes = b""
    bpp_store_metadata: dict[str, Any] = field(default_factory=dict)
    bpp_replace_session_keys_request: bytes = b""
    bpp_unprotected_profile: bytes = b""


@dataclass
class SimEuiccExtCardResources:
    system_apps_count: int = 3
    free_nvm: int = 0x02EC08
    free_ram: int = 0x2400


@dataclass
class SimIotSpecificInfo:
    iot_versions: list[bytes] = field(default_factory=lambda: [bytes.fromhex("010200")])
    ecall_supported: bool = True
    fallback_supported: bool = True


@dataclass
class SimEuiccInfoConfig:
    info1_svn: bytes = bytes.fromhex("020600")
    profile_version: bytes = bytes.fromhex("020301")
    svn: bytes = bytes.fromhex("020600")
    firmware_version: bytes = bytes.fromhex("030100")
    ts102241_version: bytes = bytes.fromhex("030300")
    globalplatform_version: bytes = bytes.fromhex("020300")
    uicc_capability_bits: list[int] = field(default_factory=lambda: [1, 2, 4, 13, 16, 17])
    rsp_capability_bits: list[int] = field(default_factory=lambda: [0, 2, 3])
    euicc_category: int = 2
    forbidden_profile_policy_bits: list[int] = field(default_factory=lambda: [1, 2])
    pp_version: bytes = bytes.fromhex("030000")
    sas_accreditation_number: str = "KN-DN-UP-0327"
    ipa_mode: int = 1
    ext_card_resources: SimEuiccExtCardResources = field(default_factory=SimEuiccExtCardResources)
    iot_specific_info: SimIotSpecificInfo = field(default_factory=SimIotSpecificInfo)
    additional_pp_versions: list[bytes] = field(default_factory=lambda: [bytes.fromhex("030301")])


@dataclass
class SimEuiccConfiguredData:
    root_smds_address: str = "lpa.ds.gsma.com"
    additional_root_smds_addresses: list[str] = field(
        default_factory=lambda: ["smds2.yggdrasim.test", "smds3.yggdrasim.test"]
    )
    allowed_ci_pkids: list[bytes] = field(default_factory=list)
    ci_list: list[bytes] = field(default_factory=list)


@dataclass
class SimEimEntry:
    eim_id: str
    eim_fqdn: str = ""
    eim_id_type: int = 1
    counter_value: int = 1
    association_token: int = 1
    supported_protocol_bits: list[int] = field(default_factory=lambda: [0])
    euicc_ci_pkid: bytes = b""
    indirect_profile_download: bool = True
    eim_public_key_data: bytes = b""
    trusted_tls_public_key_data: bytes = b""


@dataclass
class SimScp03StaticKeys:
    kenc: bytes = bytes.fromhex("1122334455667788AABBCCDDEEFF0011")
    kmac: bytes = bytes.fromhex("1122334455667788AABBCCDDEEFF0011")
    dek: bytes = bytes.fromhex("1122334455667788AABBCCDDEEFF0011")
    kvn: int = 0x30


@dataclass
class SimScp80SecurityConfig:
    spi: str = "1621"
    kic: str = "15"
    kid: str = "15"
    tar: str = "B00000"
    key_enc: bytes = bytes.fromhex("1111111111111111")
    key_mac: bytes = bytes.fromhex("1111111111111111")


@dataclass
class SimCardState:
    atr: bytes
    eid: str
    iccid: str
    imsi: str
    default_dp_address: str
    root_ci_pkid: bytes
    isdr_aid: str = ""
    isdr_label: str = "ISDR"
    ecasd_aid: str = ""
    ecasd_label: str = "ECASD"
    mno_sd_aid: str = ""
    mno_sd_label: str = "MNO-SD"
    euicc_store_path: str = ""
    profile_store_path: str = ""
    euicc_info: SimEuiccInfoConfig = field(default_factory=SimEuiccInfoConfig)
    configured_data: SimEuiccConfiguredData = field(default_factory=SimEuiccConfiguredData)
    eim_entries: list[SimEimEntry] = field(default_factory=list)
    eum_certificate_der: bytes = b""
    euicc_certificate_der: bytes = b""
    scp03_keys: SimScp03StaticKeys = field(default_factory=SimScp03StaticKeys)
    scp80_security: SimScp80SecurityConfig = field(default_factory=SimScp80SecurityConfig)
    current_node_id: str = "3F00"
    ota_history: list[str] = field(default_factory=list)
    apdu_history: list[str] = field(default_factory=list)
    pending_fetch_queue: list[bytes] = field(default_factory=list)
    current_protocol: int | None = None
    profiles: list[SimProfileEntry] = field(default_factory=list)
    nodes: dict[str, SimFileNode] = field(default_factory=dict)
    base_nodes: dict[str, SimFileNode] = field(default_factory=dict)
    active_profile_aid: str = ""
    notifications: list[SimNotificationEntry] = field(default_factory=list)
    next_notification_seq: int = 1
    store_data_buffer: bytes = b""
    store_data_expected_block: int = 0
    scp03_session: SimScp03Session = field(default_factory=SimScp03Session)
    sgp_session: SimSgpSession = field(default_factory=SimSgpSession)
