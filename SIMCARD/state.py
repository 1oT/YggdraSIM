from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


DEFAULT_SIM_ATR = bytes.fromhex("3B9F96801FC78031A073BE21136743200718000001A5")


# Default cap for the simulator's bounded "history" lists (envelope
# history, IPA-poll phase trace, BIP RECEIVE channel ring, etc.). The
# simulator engine is a process-wide singleton so any list that grows
# per-APDU or per-poll-phase will leak memory across long-running
# shells unless a cap is enforced. 256 entries is more than enough for
# any consumer that only reads the tail (``[-1]`` / sliced suffix) or
# ``len()`` while keeping the working set well below 1 MB even when
# every entry is a full-sized hex APDU. Override via the
# ``YGGDRASIM_SIM_HISTORY_CAP`` env var when a longer trail is needed
# for forensics; values <= 0 fall back to the default.
_DEFAULT_HISTORY_CAP: int = 256


def _resolve_history_cap() -> int:
    raw = str(os.environ.get("YGGDRASIM_SIM_HISTORY_CAP", "") or "").strip()
    if len(raw) == 0:
        return _DEFAULT_HISTORY_CAP
    try:
        parsed = int(raw)
    except ValueError:
        return _DEFAULT_HISTORY_CAP
    if parsed <= 0:
        return _DEFAULT_HISTORY_CAP
    return parsed


MAX_HISTORY_ENTRIES: int = _resolve_history_cap()


def append_bounded(target: list, value: Any, maxlen: int = 0) -> None:
    """Append ``value`` to ``target`` and trim the front to ``maxlen`` entries.

    ``target`` stays a real ``list`` (so ``[-1]`` indexing, ``==``
    comparison against literal lists, and iteration in tests keep
    working). The trim is FIFO so the most recent entries survive,
    which is what every consumer of these histories actually wants.
    A ``maxlen`` of 0 (or negative) falls back to
    :data:`MAX_HISTORY_ENTRIES`.
    """
    cap = int(maxlen) if int(maxlen) > 0 else MAX_HISTORY_ENTRIES
    target.append(value)
    overflow = len(target) - cap
    if overflow > 0:
        del target[:overflow]


# SGP.32 §3.5 IPA-poll bearer defaults. The simulator ships an APN of
# ``internet.apn`` because every commercial test SIM has at least that
# context activated; ``8.8.8.8`` is the public Google resolver used to
# translate the eIM FQDN to an IPv4 address before OPEN CHANNEL is
# emitted (ETSI TS 102 223 §8.59 "Other address" requires a literal
# IPv4/IPv6 destination, not an FQDN). Both knobs are env-overridable
# at process start so a CI lab or operator harness can pin a different
# APN / DNS server without editing source.
_DEFAULT_IPA_POLL_APN: str = "internet.apn"
_DEFAULT_IPA_POLL_DNS_SERVER: str = "8.8.8.8"


def _env_str(name: str, fallback: str) -> str:
    value = os.environ.get(name, "")
    if value is None:
        return fallback
    cleaned = str(value).strip()
    if len(cleaned) == 0:
        return fallback
    return cleaned


def _resolve_default_ipa_poll_apn() -> str:
    return _env_str("YGGDRASIM_SIM_IPA_POLL_APN", _DEFAULT_IPA_POLL_APN)


def _resolve_default_ipa_poll_dns_server() -> str:
    return _env_str("YGGDRASIM_SIM_IPA_POLL_DNS_SERVER", _DEFAULT_IPA_POLL_DNS_SERVER)


def _default_stk_imei_bcd() -> bytes:
    """ETSI TS 102 223 §8.20 / 3GPP TS 24.008 §10.5.1.4 IMEI encoding.

    Default IMEI ``086543245654321`` mirrors the controller-side
    default in :mod:`SCP03.logic.stk`. The byte layout is:

    - Byte 1: high nibble = first IMEI digit, low nibble = ``0xA``
      (type-of-identity ``010`` for IMEI, parity bit ``1`` for the
      odd 15-digit count).
    - Bytes 2-8: BCD nibble-swapped digit pairs (digits 2-15).
    """
    digits = "086543245654321"
    out = bytearray(8)
    out[0] = ((int(digits[0]) & 0x0F) << 4) | 0x0A
    for index in range(1, 8):
        low_digit = int(digits[2 * index - 1]) & 0x0F
        high_digit = int(digits[2 * index]) & 0x0F
        out[index] = (high_digit << 4) | low_digit
    return bytes(out)


def _default_stk_location_information() -> bytes:
    """ETSI TS 102 223 §8.19 / 3GPP TS 24.008 §10.5.1.3 GSM Location.

    7 bytes: 3-byte packed-BCD PLMN (MCC=001 / MNC=01 / 3GPP test PLMN)
    + 2-byte LAC (0x0001) + 2-byte Cell ID (0x0001).
    """
    return bytes.fromhex("00F11000010001")


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
    # ETSI TS 102 221 §9 / TS 31.102 §4 access condition for UPDATE
    # operations. Recognized values:
    #   "always" - permissive, default. Honoured for backwards-compat
    #              with profile stores written before this field existed.
    #   "never"  - reject all writes (returns 6982).
    #   "pin1"   - require CHV1/PIN1 (P2=0x01) verified.
    #   "adm"    - require an authenticated SCP03 session OR any of the
    #              ADM CHVs (0x0A..0x0E) verified.
    write_acl: str = "always"
    # ETSI TS 102 221 §11.1.13/§11.1.14/§11.1.16/§11.1.17 file
    # lifecycle. The byte is echoed back in the FCP 8A tag and gates
    # READ/UPDATE/SEARCH:
    #   0x05 -- operational (activated). Default.
    #   0x04 -- operational (deactivated) after DEACTIVATE FILE.
    #   0x0C -- terminated. Set by TERMINATE EF / TERMINATE DF and
    #           irreversible -- subsequent ACTIVATE FILE is rejected.
    # Other values from §11.1.1.4.9 (creation, initialisation) are
    # accepted but never set by the simulator.
    lifecycle_state: int = 0x05
    # SAIP / TCA Profile Interoperability v2.3.1 §8.3.5 ``linkPath``
    # (``Fcp.linkPath``, ``[PRIVATE 7]`` OCTET STRING). Concatenation
    # of 2-byte FIDs walking from the MF (or, for ADF-rooted paths,
    # from the temporary ADF FID) down to the file this slot
    # mirrors. An empty tuple means "no link" -- the file is
    # independent or its content is supplied directly. A non-empty
    # tuple instructs the runtime FS rebuild to copy ``data`` /
    # ``records`` / ``structure`` from the resolved target before
    # the Annex H mirror or template-default fallbacks fire.
    link_path: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class SimProfileAuthConfig:
    algorithm: str = "milenage"
    ki: bytes = b""
    opc: bytes = b""
    op: bytes = b""
    amf: bytes = bytes.fromhex("8000")
    sqn: bytes = b"\x00" * 6
    # TUAK specific. Ignored for MILENAGE. Number of Keccak-f[1600] iterations.
    number_of_keccak: int = 1
    # Optional SAIP-sourced counter bound. Empty when unused.
    auth_counter_max: bytes = b""


@dataclass
class SimProfilePinEntry:
    """SAIP §5.6.1 PINKey decoded from a ``pinCodes`` ProfileElement.

    ``key_reference`` is the ETSI TS 102 221 §9.5.1 P2 byte (0x01 = global
    PIN1, 0x02..0x08 = global PIN2..PIN8, 0x0A..0x0E = ADM1..ADM5, 0x81 =
    universal PIN1 / local PIN1 of the current application). ``value`` is
    the 8-byte PIN block exactly as the card would compare it (left-aligned
    ASCII digits, right-padded with 0xFF).
    """

    key_reference: int = 0x01
    value: bytes = b""
    unblock_reference: int = 0
    attributes: int = 0x00
    max_attempts: int = 3
    retries_remaining: int = 3


@dataclass
class SimProfilePukEntry:
    """SAIP §5.6.2 PUKKey decoded from a ``pukCodes`` ProfileElement."""

    key_reference: int = 0x01
    value: bytes = b""
    max_attempts: int = 10
    retries_remaining: int = 10


@dataclass
class SimProfileSecurityDomainKey:
    """GP Card Spec v2.3.1 §11.5 PUT KEY entry materialised from
    ``securityDomain.keyList``. ``usage_qualifier`` and ``access`` carry
    the GP-defined bitmaps verbatim so downstream GP Registry / SCP03
    bring-up can reuse them without re-parsing the SAIP shape.
    """

    usage_qualifier: int = 0x00
    key_identifier: int = 0x00
    key_version: int = 0x00
    key_type: int = 0x00
    key_data: bytes = b""
    mac_length: int = 8
    counter: bytes = b""
    access: int = 0x00


@dataclass
class SimProfileSecurityDomain:
    """SAIP §5.5 SecurityDomain ProfileElement.

    Mirrors the on-card GP §11.4 application registry tuple plus the
    SCP03/SCP02 keyset that is normally provisioned by INSTALL [for
    personalization] / STORE DATA.
    """

    instance_aid: str = ""
    class_aid: str = ""
    load_package_aid: str = ""
    privileges: bytes = b""
    lifecycle_state: int = 0x07
    install_parameters: bytes = b""
    uicc_toolkit_parameters: bytes = b""
    keys: list[SimProfileSecurityDomainKey] = field(default_factory=list)
    perso_data: list[bytes] = field(default_factory=list)


@dataclass
class SimProfileRfmInstance:
    """SAIP §5.7 RFM ProfileElement.

    Captures the OTA SAT remote-file-management applet binding so
    SCP80 / SCP81 dispatch can match incoming TARs to the right
    instance and access policy. ``adf_aid`` is empty for MF/DF-scoped
    instances; ETSI TS 102 226 §8.4 limits each RFM instance to a
    single ADF binding.
    """

    instance_aid: str = ""
    tar_list: list[bytes] = field(default_factory=list)
    minimum_security_level: int = 0x00
    uicc_access_domain: bytes = b""
    uicc_admin_access_domain: bytes = b""
    adf_aid: str = ""
    adf_access_domain: bytes = b""
    adf_admin_access_domain: bytes = b""


@dataclass
class SimProfileImage:
    profile_name: str = ""
    iccid: str = ""
    imsi: str = ""
    impi: str = ""
    nodes: list[SimProfileFsNode] = field(default_factory=list)
    auth_config: SimProfileAuthConfig | None = None
    # SAIP profileHeader.connectivityParameters (TCA Profile
    # Interoperability §3.4.2). Captured verbatim from the SAIP image
    # so SGP.32 ES10b.GetConnectivityParameters can echo the same TLV
    # stream a real card would. Empty bytes mean "not provisioned".
    connectivity_params_http: bytes = b""
    # SAIP §5.6 PIN/PUK material extracted from the BPP. The runtime
    # ``rebuild_runtime_filesystem`` path applies these to
    # ``SimCardState.chv_references`` so VERIFY PIN / UNBLOCK PIN react
    # to the issuer's secrets rather than the simulator's lab defaults.
    pin_codes: list[SimProfilePinEntry] = field(default_factory=list)
    puk_codes: list[SimProfilePukEntry] = field(default_factory=list)
    # SAIP §5.5 SecurityDomain instances (MNO-SD, SSDs, RFM hosts).
    # Holds GP keys + lifecycle state so the runtime can bring up
    # SCP03/SCP80 secure channels with the issuer-provisioned material.
    security_domains: list[SimProfileSecurityDomain] = field(default_factory=list)
    # SAIP §5.7 RFM applet bindings. Non-functional placeholders today
    # but available to ``SIMCARD.scp80`` so OTA dispatch can be wired
    # up without re-parsing the BPP.
    rfm_instances: list[SimProfileRfmInstance] = field(default_factory=list)


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
    auth_config: SimProfileAuthConfig | None = None
    # SGP.32 §2.11.1.1 fallbackAttribute. At most one Profile on the
    # eUICC carries this flag at any time. ExecuteFallbackMechanism
    # consults this to pick the target Profile and ReturnFromFallback
    # uses it to clear the marker.
    fallback_attribute: bool = False
    # SGP.32 §5.9.16 enable.rollbackFlag. Set when the eIM-issued
    # ``enable`` PSMO requested rollback authorisation; cleared when
    # rollback is consumed or the IPA confirms attach.
    rollback_armed: bool = False
    # SGP.32 §2.5.x / §5.9.22 ecallIndication. Marks the Emergency
    # Profile (eCall) candidate so EnableEmergencyProfile /
    # DisableEmergencyProfile can locate it. At most one Profile per
    # eUICC carries this flag.
    ecall_indication: bool = False
    # SGP.32 §5.9.24 GetConnectivityParameters httpParams (also used
    # for CoAP). Sourced from the SAIP profile's ConnectivityParameters
    # element when present, or set explicitly via tooling/tests. Empty
    # bytes mean "parametersNotAvailable".
    connectivity_params_http: bytes = b""


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
    # See ``SimProfileFsNode.write_acl``. Carried at runtime so
    # ``EtsiFileSystem.update_binary`` / ``update_record`` can enforce
    # the policy without a second image lookup on the hot path.
    write_acl: str = "always"
    # ETSI TS 102 221 §11.1.1.4.9 file lifecycle (FCP tag 8A). Mirrors
    # ``SimProfileFsNode.lifecycle_state`` so DEACTIVATE / ACTIVATE FILE
    # can flip the runtime state without touching the persistent image
    # in the same code path.
    lifecycle_state: int = 0x05
    # SAIP §8.3.5 ``Fcp.linkPath`` -- chain of 2-byte FIDs walking
    # from the MF down to the file this node mirrors. Carried from
    # the parsed ``SimProfileFsNode.link_path`` so the runtime FS
    # builder and any later read-time alias resolver can follow the
    # link without re-walking the BPP image. See
    # ``etsi_fs._apply_explicit_file_links_from_profile``.
    link_path: tuple[str, ...] = field(default_factory=tuple)

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
class SimEuiccPackageResultEntry:
    """SGP.32 §2.11.2.1 EuiccPackageResult held by the eUICC.

    The eUICC keeps the signed result in store until the IPA confirms
    delivery to the eIM via ES10b.RemoveNotificationFromList referencing
    ``seq_number``. Only the *signed* result variants
    (``euiccPackageResultSigned``) are persisted, per §2.11.2 paragraph 4.
    Verification-time errors (``euiccPackageErrorUnsigned`` /
    ``euiccPackageErrorSigned``) are returned but never stored.
    """

    seq_number: int
    eim_id: str
    counter_value: int
    eim_transaction_id: bytes = b""
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
class SimToolkitMenuItem:
    identifier: int
    text: str


@dataclass
class SimToolkitState:
    bootstrap_enabled: bool = True
    provide_imei: bool = True
    menu_title: str = ""
    menu_items: list[SimToolkitMenuItem] = field(
        default_factory=lambda: [
            SimToolkitMenuItem(identifier=0x80, text="Add Profile"),
            SimToolkitMenuItem(identifier=0x81, text="List Profiles"),
            SimToolkitMenuItem(identifier=0x82, text="Get Eim Package"),
        ]
    )
    event_list: list[int] = field(default_factory=lambda: [0x03, 0x09, 0x0A, 0x12])
    poll_interval_seconds: int = 60
    language: bytes = b"en"
    location_information: bytes = field(default_factory=_default_stk_location_information)
    imei: bytes = field(default_factory=_default_stk_imei_bcd)
    # ETSI TS 102 223 §6.4.15 PROVIDE LOCAL INFORMATION carry-along
    # state. The terminal supplies these via TERMINAL RESPONSE; the
    # simulator caches the most recent value so an STK applet (or a
    # test) can query "what did the terminal last report".
    #   date_time_timezone: TS 102 223 §8.39 raw 7-byte bcd payload.
    #   imeisv: §8.66 raw 16-digit BCD identifier.
    #   battery_state: §8.108 single byte (0=very low ... 4=full).
    #   access_technology: §8.61 single byte (0=GSM, 3=UTRAN, 8=E-UTRAN, 11=NG-RAN).
    date_time_timezone: bytes = b""
    imeisv: bytes = b""
    battery_state: int = 0
    access_technology: int = 0
    terminal_profile: bytes = b""
    terminal_capabilities: list[bytes] = field(default_factory=list)
    # ETSI TS 102 221 §11.1.19 Terminal Capability decoded fields
    #. Each TERMINAL CAPABILITY APDU carries a sequence
    # of optional TLVs; the latest decoded values are latched here
    # so an applet / test can introspect terminal support without
    # walking the raw blob list.
    terminal_power_supply: int = 0
    terminal_extended_logical_channels: int = 0
    terminal_additional_interfaces: bytes = b""
    terminal_euicc_capabilities: bytes = b""
    terminal_eutran_secure_channel: bytes = b""
    envelope_history: list[bytes] = field(default_factory=list)
    last_terminal_response: bytes = b""
    bootstrap_initialized: bool = False
    active_proactive_command: bytes = b""
    next_command_number: int = 1
    open_channel_active: bool = False
    open_channel_protocol: str = ""
    open_channel_endpoint: str = ""
    open_channel_network_access_name: str = ""
    open_channel_transport_protocol_type: int = 0
    # ETSI TS 102 223 §8.7 / §8.56 -- channel identifier reported by
    # the terminal in the OPEN CHANNEL TR channel-status TLV
    # (``38 02 [byte1] [byte2]``, channel id = byte1 & 0x07). Stored
    # so the SEND DATA / RECEIVE DATA / CLOSE CHANNEL builders can
    # encode the destination device identity as ``0x20 + ch_id``
    # rather than the generic terminal id (0x82); some terminals
    # return general-result 0x3A / additional-info 0x03
    # ("Channel identifier not valid") if the dest byte is wrong.
    open_channel_id: int = 0
    last_channel_data_sent: int = 0
    last_received_channel_data: bytes = b""
    received_channel_history: list[bytes] = field(default_factory=list)
    # ETSI TS 102 223 §7.4 Event Download bookkeeping. The simulator
    # records the most recent event-code delivered by the terminal so
    # an STK applet can poll "did we just see an idle-screen / browser
    # termination / network-rejection notification". The history list
    # is unbounded by design; tests trim it explicitly when needed.
    event_history: list[int] = field(default_factory=list)
    last_event_code: int = 0
    idle_screen_available: bool = False
    last_browser_termination_cause: int = 0
    last_network_rejection_cause: bytes = b""
    # ETSI TS 102 223 §7.4.10 SS Event (0x0A) -- the SS-string the
    # terminal observed, raw payload of the matching D6 envelope.
    last_ss_event_data: bytes = b""
    # ETSI TS 102 223 §7.4.10 USSD Event (0x0B) -- the USSD-string
    # decoded from the envelope (DCS-aware, falls back to the raw
    # bytes when the DCS is unknown).
    last_ussd_event_data: bytes = b""
    last_ussd_event_dcs: int = 0
    # ETSI TS 102 223 §7.4.12 Local Connection event (0x0C). Tracks
    # whether the most recent local-bearer notification reported the
    # connection as established (True) or terminated (False).
    local_connection_active: bool = False
    # ETSI TS 102 223 §6.4.27 TIMER MANAGEMENT bookkeeping. The card
    # tracks up to 8 timers per spec (timer-id 0x01..0x08); this map
    # is keyed by id and stores the remaining seconds. ``None`` means
    # "not running".
    timer_table: dict[int, int] = field(default_factory=dict)
    last_expired_timer_id: int = 0
    # SGP.32 §3.5 IPA polling needs the modem to deliver an ENVELOPE
    # (Timer Expiration / D7) at a deterministic cadence. POLL INTERVAL
    # alone only schedules STATUS heartbeats and never produces the D7
    # envelope, so the eIM poll trigger never fires. The
    # bring-up therefore prefers TIMER MANAGEMENT START with a
    # spec-shaped Timer Identifier (A4) + Timer Value (A5) pair; the
    # legacy POLL INTERVAL path is retained as a fallback strategy for
    # paired tests / older harnesses that asserted the old wire shape.
    #
    # ``poll_strategy`` controls what ``_bootstrap_commands`` enqueues
    # right after TERMINAL PROFILE:
    #   - "timer"         (default) -- TIMER MANAGEMENT START only.
    #   - "poll_interval"            -- POLL INTERVAL only (legacy).
    #   - "both"                     -- TIMER MANAGEMENT START *and*
    #                                   POLL INTERVAL (defensive when
    #                                   the modem rejects one of the
    #                                   two qualifiers but still
    #                                   honours the other).
    #   - "off"                      -- neither command is queued.
    # ``timer_management_seconds`` / ``timer_management_id`` define the
    # initial timer setpoint; ``timer_management_auto_rearm`` controls
    # whether the simulator re-enqueues the same TIMER MANAGEMENT START
    # when the matching D7 envelope arrives, so the poll loop keeps
    # firing without external orchestration.
    poll_strategy: str = "timer"
    timer_management_seconds: int = 30
    timer_management_id: int = 1
    timer_management_auto_rearm: bool = True
    # SGP.32 §3.5 IPA-poll BIP trigger. When ``ipa_poll_enabled`` is
    # True, every D7 TIMER EXPIRATION envelope auto-rearms the timer
    # *and* enqueues a BIP poll sequence -- OPEN CHANNEL, SEND DATA,
    # RECEIVE DATA, CLOSE CHANNEL -- towards the configured eIM
    # endpoint. The modem services the bearer (DNS resolution, TLS
    # handshake, HTTP) so the simulator only needs to publish the
    # proactive commands. Empty FQDN falls back to the first
    # ``state.eim_entries`` entry, then to the workspace eIM identity
    # default. See ETSI TS 102 223 §6.4.27 / §6.4.29 / §6.4.30 / §6.4.28.
    ipa_poll_enabled: bool = True
    ipa_poll_eim_fqdn: str = ""
    ipa_poll_eim_port: int = 443
    # ETSI TS 102 223 §8.70 transport-level type. 0x02 is TCP CLIENT
    # REMOTE which the modem upgrades to TLS based on port 443; this
    # is the SGP.32 IPA-poll convention. Override to 0x06 (TLS over
    # TCP) only if the modem firmware demands explicit signalling.
    ipa_poll_transport_type: int = 0x02
    ipa_poll_buffer_size: int = 0x0400
    ipa_poll_receive_size: int = 0xFA
    ipa_poll_alpha_id: str = ""
    ipa_poll_request_payload: bytes = b""
    # SGP.32 §3.5 / ETSI TS 102 223 §8.59 / §8.70 BIP destination wiring.
    # OPEN CHANNEL TLVs:
    #   tag 47 = APN (Network Access Name, label-list encoded)
    #   tag 3C = transport type + port
    #   tag 3E = literal IPv4/IPv6 destination
    # ``ipa_poll_apn`` is seeded from (in order):
    #   1. the active SAIP profile's APN (BPP override) -- see
    #      ``state.toolkit.ipa_poll_apn_source == "bpp"``
    #   2. ``YGGDRASIM_SIM_IPA_POLL_APN`` env override
    #   3. ``"internet.apn"`` workspace fallback
    # ``ipa_poll_dns_server`` accepts an env override via
    # ``YGGDRASIM_SIM_IPA_POLL_DNS_SERVER``.
    ipa_poll_apn: str = field(default_factory=_resolve_default_ipa_poll_apn)
    ipa_poll_apn_source: str = "default"
    ipa_poll_dns_server: str = field(default_factory=_resolve_default_ipa_poll_dns_server)
    ipa_poll_dns_port: int = 53
    ipa_poll_dns_query_id: int = 0
    ipa_poll_resolved_ip: str = ""
    ipa_poll_resolved_ip_family: int = 0
    ipa_poll_last_resolution_error: str = ""
    ipa_poll_resolution_pending: bool = False
    # IPA-poll phase machine. The simulator advances through:
    #   "idle"          -> nothing in flight
    #   "dns_open"      -> OPEN CHANNEL UDP (resolver:53) queued
    #   "dns_query"     -> SEND DATA (DNS questions) queued
    #   "dns_recv"      -> RECEIVE DATA queued; awaiting answers
    #   "dns_close"     -> CLOSE CHANNEL queued; resolved IP cached
    #   "eim_open"      -> OPEN CHANNEL TCP (eim_ip:443) queued
    #   "eim_request"   -> SEND DATA carrying ESipa request body
    #   "eim_recv"      -> RECEIVE DATA awaiting ESipa response
    #   "eim_close"     -> CLOSE CHANNEL queued; cycle complete
    # ``ipa_poll_phase_history`` keeps a bounded log of recent transitions
    # so a polling tool can confirm the order without diffing FETCH bytes.
    ipa_poll_phase: str = "idle"
    ipa_poll_phase_history: list[str] = field(default_factory=list)
    # Channel-id bookkeeping. When OPEN CHANNEL succeeds the modem TR
    # echoes a ``B1 01 <id>`` channel-status TLV; the IPA caches it so
    # subsequent SEND/RECEIVE DATA channel data can be routed to the
    # right bearer (see TS 102 223 §8.56).
    ipa_poll_dns_channel_id: int = 0
    ipa_poll_eim_channel_id: int = 0
    # DNS payload buffers. ``ipa_poll_dns_pending_questions`` is the
    # ordered list of (qname, qtype) tuples still to be shipped under
    # the current bearer. ``ipa_poll_dns_response_buffer`` accumulates
    # RECEIVE DATA bytes until a complete DNS message is parsed (some
    # modems split a single response across two RECEIVE DATA TRs).
    # ``ipa_poll_dns_a_pending`` / ``ipa_poll_dns_aaaa_pending`` track
    # the dual-stack questions still in flight.
    ipa_poll_dns_pending_questions: list[tuple[str, int]] = field(default_factory=list)
    ipa_poll_dns_response_buffer: bytes = b""
    ipa_poll_dns_a_pending: bool = False
    ipa_poll_dns_aaaa_pending: bool = False
    # Counter that increments every time a complete IPA poll cycle
    # finishes (whether successfully delivering an EuiccPackage or
    # bailing on a bearer error). Used by tests / status renderers.
    ipa_poll_cycle_count: int = 0
    # SGP.32 §3.5 -- consecutive cycle-failure tally. Bumps when a
    # SEND DATA or RECEIVE DATA inside the IPA-poll cycle returns a
    # non-success TR (general result 0x3A "BIP error", 0x20 "no
    # service", etc.); resets when a cycle completes with at least
    # one EuiccPackage successfully dispatched into ISD-R. Operators
    # use this to suppress noisy retries on a modem whose UDP/TCP
    # bearer is broken end-to-end. ``ipa_poll_last_cycle_error``
    # records the last failure context (phase + result code +
    # additional-info byte) for diagnostics.
    ipa_poll_consecutive_failures: int = 0
    ipa_poll_last_cycle_error: str = ""
    # ETSI TS 102 223 §6.4.27 / §8.38 -- watchdog timer used between
    # SEND DATA and RECEIVE DATA inside an IPA-poll cycle. Default
    # values per TS 102 223. Skipping the wait can trigger general
    # result 0x3A and additional info 0x00 on RECEIVE DATA against
    # some terminals.
    ipa_poll_wait_timer_id: int = 2
    ipa_poll_wait_timer_seconds: int = 65
    # Tracks whether the watchdog timer is currently armed inside the
    # IPA-poll cycle. Used by the TLS reactive loop to avoid arming
    # the same timer twice across an interleaved SEND/RECV burst and
    # to guarantee a deactivate is queued before CLOSE CHANNEL.
    ipa_poll_wait_timer_armed: bool = False
    # SGP.32 §3.5 / TS 102 223 §6.4.27 IPA-poll TLS toggle.
    # ``ipa_poll_tls_enabled`` selects between the TLS-1.2 path
    # (default) and the plain-HTTP fallback used by dispatch tests
    # that exercise the SGP.32 envelope wiring without a TLS engine.
    # ``ipa_poll_tls_state`` holds the ``CardTlsClientState``
    # (memory BIOs + SSLObject) for the cycle in flight;
    # ``ipa_poll_tls_inbound_buffer`` accumulates RECEIVE DATA bytes
    # until a full TLS record is parsed (some modems split a
    # single record across two RECEIVE DATA TRs).
    # ``ipa_poll_tls_idle_receives`` is a small safety counter: once a
    # bounded number of RECEIVE DATAs come back with zero bytes the
    # IPA aborts the cycle so a stuck bearer cannot loop forever.
    ipa_poll_tls_enabled: bool = True
    ipa_poll_tls_state: Any = None
    ipa_poll_tls_inbound_buffer: bytes = b""
    ipa_poll_tls_idle_receives: int = 0
    ipa_poll_tls_max_idle_receives: int = 16
    ipa_poll_tls_last_error: str = ""
    # Buffered plaintext application data once the handshake completes
    # -- used by tests that want to confirm the bytes the card decrypted
    # from the eIM, separate from the dispatcher's per-package fan-out.
    ipa_poll_tls_decrypted_payload: bytes = b""
    # SGP.32 §3.5 IPA-poll session bookkeeping. ``ipa_poll_session_active``
    # tracks whether the simulator is currently mid-cycle (OPEN CHANNEL
    # accepted, SEND/RECEIVE pending). Cleared when CLOSE CHANNEL TR
    # comes back or when the bearer fails. ``ipa_poll_last_response_payload``
    # caches the bytes the modem returned via RECEIVE DATA so an
    # operator can introspect what the eIM said even after the
    # session is torn down. ``ipa_poll_dispatched_packages`` records
    # the outer tag of each EuiccPackage the IPA dispatched into ISD-R
    # this cycle -- useful for tests that need to assert "the eIM's
    # ProfileDownloadTrigger was forwarded".
    ipa_poll_session_active: bool = False
    ipa_poll_last_request_payload: bytes = b""
    ipa_poll_last_response_payload: bytes = b""
    ipa_poll_dispatched_packages: list[bytes] = field(default_factory=list)
    # SGP.32 §6.5.2.1 ProvideEimPackageResult (BF50) bookkeeping.
    # ``ipa_poll_pending_result_payload`` is the BF50 body the IPA
    # built after dispatching the eIM's EuiccPackages into ISD-R --
    # it is shipped back to the eIM in a follow-up SEND DATA so the
    # eIM sees the per-package execution result. ``ipa_poll_last_result_payload``
    # caches the most recent body for introspection. ``ipa_poll_dispatched_responses``
    # holds the raw R-APDU bytes the dispatcher returned for each
    # forwarded package so tests can confirm the ISD-R reply chain.
    ipa_poll_pending_result_payload: bytes = b""
    ipa_poll_last_result_payload: bytes = b""
    ipa_poll_dispatched_responses: list[bytes] = field(default_factory=list)
    # SGP.32 §6.5.2.1 per-cycle failure bookkeeping. Each entry is
    # ``(outer_tag, error_code)`` where ``outer_tag`` is the BFxx
    # tag the dispatcher could not handle and ``error_code`` is the
    # SGP.32 EimPackageResultErrorCode (1 invalidPackageFormat,
    # 2 unknownPackage, 127 undefinedError) the IPA attached to its
    # outgoing BF50. Cleared at the start of every IPA-poll cycle.
    ipa_poll_failed_packages: list[tuple[bytes, int]] = field(default_factory=list)
    # Latch: True between the moment the IPA injected a follow-up
    # ProvideEimPackageResult SEND DATA and the cycle teardown
    # (CLOSE CHANNEL TR). Prevents a cascading injection if the eIM
    # replies to the BF50 with another package -- real eIMs ack
    # with an empty body or a single BF50 acknowledgement, which
    # the IPA must consume but not re-mirror.
    ipa_poll_followup_emitted: bool = False
    # ETSI TS 102 223 §6.4.7 POLLING OFF state. Set when the terminal
    # acknowledges POLLING OFF; cleared by SET UP IDLE MODE / new
    # POLL INTERVAL.
    polling_off_active: bool = False
    # ETSI TS 102 223 §6.4.34 DECLARE SERVICE registrations. Each
    # entry is the raw service-record TLV blob; the order is
    # preserved so an STK applet can replay them after a session
    # reset.
    declared_services: list[bytes] = field(default_factory=list)
    # ETSI TS 102 223 §6.4.32 / §6.4.33 service-discovery scratch
    # space. ``last_service_search_result`` caches the matching
    # service-record blob (or empty if not found) returned in the
    # most recent SERVICE SEARCH terminal response.
    # ``last_service_information`` stores the service-info blob
    # returned by GET SERVICE INFORMATION.
    last_service_search_result: bytes = b""
    last_service_information: bytes = b""
    # ETSI TS 102 223 §6.4.11..14 multi-card terminal API. The
    # simulator caches the most recent values so an STK applet can
    # query the readers it has interacted with.
    powered_card_readers: set[int] = field(default_factory=set)
    last_reader_status: bytes = b""
    last_card_apdu_response: bytes = b""
    last_card_apdu_reader: int = 0
    # ETSI TS 102 223 §6.4.16 RUN AT COMMAND terminal-response
    # bookkeeping. The simulator stores both the raw bytes and a
    # utf-8 best-effort decode so test fixtures can match either
    # against the recorded modem reply.
    last_at_response: bytes = b""
    last_at_response_text: str = ""
    # ETSI TS 102 223 §7.4.13 HCI Connectivity Event. Tracks
    # whether the most recent embedded-SE HCI gate notification
    # signalled the gate as connected (True) or disconnected
    # (False).
    hci_connectivity_active: bool = False
    # ETSI TS 102 223 §6.4.36 SET FRAMES bookkeeping. The card
    # advertises one or more frames (sub-rectangles of the display)
    # via this proactive; on a successful TR the layout is cached
    # so a follow-on toolkit applet can render relative to the
    # negotiated geometry.
    last_set_frames_layout: bytes = b""
    last_set_frames_default_id: int = 0
    # ETSI TS 102 223 §6.4.37 GET FRAMES STATUS. The Frames
    # Information TLV (tag 0x49 / 0xC9) returned by the terminal
    # describes how many frames are available and which is active.
    last_frames_information: bytes = b""
    # ETSI TS 102 223 §7.4.20 Contactless State Request event
    # (event code 0x16) bookkeeping. The status byte (TLV 0x40)
    # tracks whether the contactless front-end is currently
    # active.
    contactless_active: bool = False
    # 3GPP TS 31.111 §7.5.x IMS Registration Event (0x18) and
    # IMS Incoming Data Event (0x19). The simulator caches the
    # most recent registration-status byte plus the IMS payload so
    # an STK applet can correlate the two without scraping the
    # event history.
    ims_registered: bool = False
    last_ims_event_data: bytes = b""
    # 3GPP TS 23.041 §9.4.1 Cell Broadcast Download (envelope D2)
    # bookkeeping. The CB page TLV (0x8C) carries 88 bytes split
    # into Serial Number (2), Message Identifier (2), DCS (1),
    # Page parameter (1) and 82 bytes of content; the simulator
    # caches each field plus the raw page so an STK applet can
    # match either encoding.
    last_cb_serial_number: int = 0
    last_cb_message_id: int = 0
    last_cb_dcs: int = 0
    last_cb_page_parameter: int = 0
    last_cb_content: bytes = b""
    last_cb_page_raw: bytes = b""
    cb_pages_received: int = 0
    # ETSI TS 102 223 §7.5.6 Menu Selection (envelope D3) latch.
    # The terminal forwards the user-selected item identifier (TLV
    # 0x90) plus an optional help-request flag (qualifier byte 0
    # bit 0). The simulator stores the most recent selection so an
    # STK applet does not have to scrape the envelope history.
    last_menu_item_id: int = 0
    last_menu_help_request: bool = False
    menu_selections: list[int] = field(default_factory=list)
    # ETSI TS 102 223 §6.4 proactive-response latches.
    # Each "send" / "play" / "notify" proactive that previously
    # had no dedicated TR handler persists its outcome here.
    last_send_ss_result: int = 0
    last_send_ss_additional: bytes = b""
    last_send_ss_response: bytes = b""
    last_send_ussd_result: int = 0
    last_send_ussd_response_text: str = ""
    last_send_ussd_response_dcs: int = 0
    last_send_short_message_result: int = 0
    last_send_dtmf_result: int = 0
    last_play_tone_result: int = 0
    last_language_notification_result: int = 0
    # ETSI TS 102 223 §6.4.21 LAUNCH BROWSER TR-side latch (round
    # 14). The terminal response only echoes a result code per
    # §6.6.21; the corresponding browser-termination event already
    # latches into ``last_browser_termination_cause``. Keeping the
    # outcome of the launch itself separate lets a polling tool
    # distinguish "browser refused to start" from "browser ran and
    # the user closed it later".
    last_launch_browser_result: int = 0
    # ETSI TS 102 223 §6.4.5 REFRESH TR-side latch. The
    # terminal response carries only a result code per §6.6.5; the
    # simulator caches the refresh-mode that the TR confirmed plus a
    # monotonic attempt counter so an STK applet can distinguish
    # "refresh accepted" from "REFRESH already in progress" without
    # walking the command queue.
    last_refresh_result: int = 0
    last_refresh_mode: int = 0
    refresh_attempts: int = 0
    # ETSI TS 102 223 §6.4.13 SET UP CALL TR-side latch.
    # The TR per §6.6.13 carries the result code and may include
    # Additional Information (TLV ``1A`` / ``9A``) describing the
    # network-side cause when the call could not be established.
    # The simulator caches the result, the additional-info blob,
    # and the dialled number echoed by the proactive command so
    # tests can correlate a SET UP CALL with its outcome.
    last_set_up_call_result: int = 0
    last_set_up_call_additional: bytes = b""
    last_set_up_call_address: str = ""
    # ETSI TS 102 223 §6.4.1 DISPLAY TEXT. The TR per
    # §6.6.1 only echoes a result code; the simulator caches it
    # so a polling tool can confirm the text actually rendered.
    last_display_text_result: int = 0
    # ETSI TS 102 223 §6.4.2 GET INKEY. The TR per
    # §6.6.2 carries the user-typed character in TLV ``0D`` /
    # ``8D`` (DCS + 1 unit). The simulator latches the result
    # plus the decoded character (best-effort; UCS-2 is decoded
    # to a single code point when possible).
    last_get_inkey_result: int = 0
    last_get_inkey_text: str = ""
    last_get_inkey_dcs: int = 0
    # ETSI TS 102 223 §6.4.3 GET INPUT. The TR per
    # §6.6.3 carries the user-typed string in TLV ``0D`` / ``8D``
    # plus a result. The simulator caches both so a paired test
    # can validate the text the modem returned.
    last_get_input_result: int = 0
    last_get_input_text: str = ""
    last_get_input_dcs: int = 0
    # ETSI TS 102 223 §6.4.4 SELECT ITEM. The TR per
    # §6.6.4 carries the chosen item identifier in TLV ``10`` /
    # ``90``. The simulator latches the result + chosen id.
    last_select_item_result: int = 0
    last_select_item_id: int = 0
    # ETSI TS 102 223 §6.4.5 SET UP MENU. TR carries
    # only a result code; the simulator latches it independently
    # of the menu selections envelope so a tool can know whether
    # the menu was actually committed by the terminal.
    last_set_up_menu_result: int = 0
    # ETSI TS 102 223 §6.4.20 SET UP IDLE MODE TEXT.
    # TR carries only a result code.
    last_set_up_idle_mode_text_result: int = 0
    # ETSI TS 102 223 §6.4.2 / §6.4.3 simple proactive TR latches
    #. MORE TIME and POLL INTERVAL only carry a result
    # code on the TR side; POLL INTERVAL additionally echoes the
    # negotiated polling duration the terminal accepted.
    last_more_time_result: int = 0
    last_poll_interval_result: int = 0
    last_poll_interval_negotiated_seconds: int = 0
    last_poll_interval_negotiated_raw: bytes = b""
    # ETSI TS 102 223 §7.4 call-lifecycle event downloads (round
    # 12). The simulator captures the per-event metadata so STK
    # applets can correlate MT-call -> Call-Connected -> Call-
    # Disconnected without scraping ``event_history``.
    last_mt_call_transaction_id: int = 0
    last_mt_call_address: str = ""
    last_mt_call_subaddress: bytes = b""
    last_call_connected_transaction_id: int = 0
    last_call_disconnected_transaction_id: int = 0
    last_call_disconnected_cause: bytes = b""
    call_active: bool = False
    # §7.4.4 User Activity Event. The terminal raises this when
    # the user touches a key / dial; the simulator just bumps a
    # monotonic counter so an STK applet polling for activity
    # gets a non-decreasing signal.
    user_activity_count: int = 0
    # §7.4.x Access Technology Change. Byte 0 is the access
    # technology code per TS 102 223 §8.85 (0x00 = GSM, 0x01 =
    # UTRAN/UMTS, 0x02 = E-UTRAN/LTE, 0x03 = NG-RAN/5G).
    last_access_technology: int = 0
    access_technology_changes: int = 0
    # §7.4.x Display Parameters Change Event. The TLV payload
    # carries terminal-side display geometry; the simulator caches
    # the raw blob plus a counter so a UI-aware applet can react
    # without parsing every event.
    last_display_parameters: bytes = b""
    display_parameters_changes: int = 0
    # ETSI TS 102 223 §7.4.4 Location Status Event Download
    #. The 1-byte status TLV (0x9B / 0x1B) takes one
    # of three values:
    #   0x00 normal service
    #   0x01 limited service
    #   0x02 no service
    # The simulator latches the latest reading plus an events-
    # received counter that bumps on every envelope. The counter
    # mirrors the behaviour of ``display_parameters_changes`` so
    # an applet that just wants "did I get any Location Status
    # event since boot?" can read the counter without comparing
    # values.
    last_location_status: int = 0
    location_status_changes: int = 0
    # ETSI TS 102 223 §7.4.x Data Available Event Download
    #. The terminal raises this with TLV 0x37 (Channel
    # Data Length) -- and optionally TLV 0x38 (Channel Status) --
    # when a BIP socket has accumulated received data ready for
    # the applet to drain via RECEIVE DATA. The simulator latches
    # the announced length plus a counter so polling tests can
    # detect the trigger without scraping event_history. The
    # browser_termination_cause branch on the same event code
    # remains untouched.
    last_data_available_channel_length: int = 0
    last_data_available_channel_status: bytes = b""
    data_available_events: int = 0
    # ETSI TS 102 223 §7.4.16 Frames Information Change Event
    #. When the user reshapes the terminal display
    # the modem forwards the new layout under TLV 0x49 (Frames
    # Information). The simulator already exposes
    # ``last_frames_information`` from SET FRAMES TR responses;
    # this counter increments on each event so applets can tell
    # how many times the user reshaped the display since boot.
    frames_information_changes: int = 0
    # ETSI TS 102 223 §7.4.7 Card Reader Status Event Download
    #. Multi-card terminals broadcast a 1-byte status
    # under TLV 0xA0 (Card Reader Status) describing the reader
    # whose state changed (bit 7 = card present, bit 6 = card
    # powered, bits 0..3 = reader id). The simulator latches the
    # raw byte and the affected reader id so an applet that
    # registered for the event can react without re-parsing.
    last_card_reader_status: int = 0
    last_card_reader_id: int = 0
    card_reader_status_events: int = 0
    # ETSI TS 102 223 §6.4.16 SET UP EVENT LIST TR latch (round
    # 18). The TR per §6.6.16 carries only a result byte. The
    # corresponding event-list registration flow is exercised by
    # the SCP03 helper that builds the proactive command; this
    # latch lets a polling tool confirm that the terminal accepted
    # the new list (vs. responding with terminal busy / unable).
    last_set_up_event_list_result: int = 0
    # ETSI TS 102 223 §6.4.4 POLLING OFF TR latch. The
    # TR per §6.6.4 echoes only a result byte; the simulator
    # already toggles ``polling_off_active`` on success. The
    # result-code latch records non-success outcomes too so a
    # polling applet can detect a "terminal refused to disable
    # polling" without scraping the command queue.
    last_polling_off_result: int = 0
    # ETSI TS 102 223 §6.4.27 TIMER MANAGEMENT TR latch (round
    # 18). The TR carries the result byte plus the timer-id /
    # timer-value TLVs already consumed by
    # _apply_timer_management_response. The result-code field
    # mirrors the other proactive latches so a polling applet can
    # tell "terminal accepted start" (0x00) from "terminal busy"
    # (0x20) without inspecting timer_table.
    last_timer_management_result: int = 0
    # ETSI TS 102 223 §6.4.15 PROVIDE LOCAL INFORMATION TR latch
    #. The qualifier byte selects which datum the
    # terminal must return (0x00 location info, 0x01 IMEI, 0x03
    # date/time, ..) and the simulator already harvests each
    # decoded field via _apply_provide_local_information_response.
    # The result-code latch + echoed qualifier lets a polling tool
    # confirm "I asked for X and the terminal answered with X"
    # without comparing every individual cache.
    last_provide_local_information_result: int = 0
    last_provide_local_information_qualifier: int = 0
    # 3GPP TS 31.111 §7.3.1.1 Call Control by USIM envelope decode
    #. The terminal forwards every MO call attempt to
    # the SIM via the D4 envelope so the operator can intercept /
    # blacklist / re-route. The simulator now extracts the dialled
    # number (TLV 06/86), TON/NPI byte, optional sub-address
    # (08/88), Capability Configuration Parameters (07/87) and
    # the calling-area Location Information (13/93). The envelope
    # response remains the canned "Allowed, no modification" reply
    # because vendor-specific call-control logic belongs in an
    # applet, not the simulator core.
    last_cc_address: str = ""
    last_cc_address_ton_npi: int = 0
    last_cc_subaddress: bytes = b""
    last_cc_capability_params: bytes = b""
    last_cc_location_information: bytes = b""
    cc_envelopes_received: int = 0
    # 3GPP TS 31.111 §7.3.2.1 MO Short Message Control envelope
    # decode. The terminal forwards every MO SMS to
    # the SIM via the D5 envelope so the operator can intercept
    # the destination address or override the SC. The simulator
    # extracts the destination (RP-DA, first Address TLV) and
    # the SC address (RP-OA, second Address TLV) plus the
    # calling-area Location Information.
    last_mo_sms_destination_address: str = ""
    last_mo_sms_destination_ton_npi: int = 0
    last_mo_sms_sc_address: str = ""
    last_mo_sms_sc_ton_npi: int = 0
    last_mo_sms_location_information: bytes = b""
    mo_sms_envelopes_received: int = 0
    # 3GPP TS 31.111 §7.3.3 USSD Download envelope decode (round
    # 19). The terminal forwards an MT USSD that the network
    # initiated, wrapped in the D8 envelope; the body carries the
    # USSD String TLV (8A) with byte 0 = DCS, bytes 1.. = encoded
    # text. The simulator latches the DCS, the raw bytes, and a
    # best-effort decoded string so an applet can react without
    # reparsing the envelope.
    last_ussd_download_dcs: int = 0
    last_ussd_download_text: str = ""
    last_ussd_download_raw: bytes = b""
    ussd_downloads_received: int = 0


@dataclass
class SimChvReference:
    reference: int
    value: str = ""
    unblock_value: str = ""
    enabled: bool = True
    verified: bool = False
    retry_limit: int = 3
    retries_remaining: int = 3
    unblock_retry_limit: int = 10
    unblock_retries_remaining: int = 10


@dataclass
class SimGpAppEntry:
    """GP Card Spec v2.3.1 §11.4 registry entry.

    ``kind`` is one of:

    - ``"sd"``       Security Domain (ISD, ECASD, ISD-P, MNO-SD, SSD).
    - ``"application"`` Java Card applet instance.
    - ``"elf"``      Executable Load File (CAP package).
    - ``"module"``   Executable Module (applet class within a CAP).

    ``lifecycle_state`` follows §11.1.1 / §11.1.2:

    - 0x01 LOADED          (ELF only)
    - 0x03 INSTALLED       (Application only)
    - 0x07 SELECTABLE      (Application; for SDs this is "PERSONALIZED")
    - 0x0F PERSONALIZED    (Application)
    - 0x83 LOCKED          (Application; SD has its own LOCKED 0x7F)
    """

    aid: str = ""
    privileges: bytes = b""
    lifecycle_state: int = 0x07
    kind: str = "application"
    associated_elf: str = ""
    modules: list[str] = field(default_factory=list)


@dataclass
class SimGpInstallContext:
    """Mirror of an in-flight INSTALL [for load] / LOAD chain.

    The simulator does not actually verify CAP file bytecode, so the
    accumulated ``load_buffer`` is retained only so the caller can
    inspect it during tests; once the LOAD sequence completes the
    ELF AID is registered into ``SimCardState.gp_apps`` and the
    context is reset.
    """

    pending_elf_aid: str = ""
    pending_sd_aid: str = ""
    load_buffer: bytes = b""
    expected_block: int = 0
    last_block_seen: bool = False


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
    # ``apdu_count`` replaces the legacy unbounded ``apdu_history`` list
    # for envelope-free APDU tracing (see ``engine.transmit``). OTA
    # envelopes still record a bounded hex snapshot list so SCP80 replay
    # diagnostics match the main simulator tree without retaining every
    # payload for the process lifetime.
    ota_packet_count: int = 0
    ota_history: list[str] = field(default_factory=list)
    apdu_count: int = 0
    pending_fetch_queue: list[bytes] = field(default_factory=list)
    current_protocol: int | None = None
    profiles: list[SimProfileEntry] = field(default_factory=list)
    nodes: dict[str, SimFileNode] = field(default_factory=dict)
    base_nodes: dict[str, SimFileNode] = field(default_factory=dict)
    active_profile_aid: str = ""
    notifications: list[SimNotificationEntry] = field(default_factory=list)
    next_notification_seq: int = 1
    # SGP.32 §2.11.2 stored eUICC Package Results (signed). Drained by the
    # IPA via ES10b.RemoveNotificationFromList referencing ``seq_number``.
    euicc_package_results: list[SimEuiccPackageResultEntry] = field(default_factory=list)
    # SGP.22 §5.7.13 LoadCRL persistence. Each entry is the raw CRL DER
    # bytes the eUICC accepted from the RSP server. The simulator does
    # not enforce revocation today, but it persists the payloads so
    # reports / GUIs can introspect "did the eIM push CRL N?".
    loaded_crls: list[bytes] = field(default_factory=list)
    # SGP.32 §2.11.1 monotonic association-token allocator. Starts at 0 and
    # increments to produce the next association token; it MUST NOT be
    # resettable by eUICC Memory Reset, hence its own counter.
    association_token_counter: int = 0
    # SGP.32 §5.9.17 ConfigureImmediateProfileEnabling persistence. The
    # eUICC retains ``immediate_enable_flag`` plus the default SM-DP+
    # OID and address used by the IPA for direct-trigger downloads.
    immediate_enable_flag: bool = False
    immediate_enable_smdp_oid: str = ""
    immediate_enable_smdp_address: str = ""
    # SGP.32 §5.9.16 ProfileRollback bookkeeping. When ``enable``
    # PSMO carries the rollbackFlag the eUICC remembers the previously
    # enabled Profile so it can revert on a successful ProfileRollback.
    previous_enabled_aid: str = ""
    # SGP.32 §5.9.22 / §5.9.23 Emergency Profile bookkeeping. Tracks
    # whether the eCall feature is currently active (an Emergency
    # Profile is enabled) and which Profile to restore when the
    # Emergency Profile is disabled. Distinct from the rollback
    # bookkeeping because Emergency activation is sticky across
    # IoT Device restarts (per spec) whereas rollback is single-shot.
    emergency_profile_active: bool = False
    emergency_pre_aid: str = ""
    store_data_buffer: bytes = b""
    store_data_expected_block: int = 0
    scp03_session: SimScp03Session = field(default_factory=SimScp03Session)
    # Persistent SCP03 secure-channel sequence counter. GP Card Spec v2.3.1
    # Amendment D §7.1.1.4.3 requires the 3-byte counter to be appended to the
    # INITIALIZE UPDATE response when the pseudo-random card challenge option
    # is in use (i-byte bit 4 = 0).
    scp03_sequence_counter: int = 0
    sgp_session: SimSgpSession = field(default_factory=SimSgpSession)
    toolkit: SimToolkitState = field(default_factory=SimToolkitState)
    chv_references: dict[int, SimChvReference] = field(default_factory=dict)
    # Logical channels that are currently open. Channel 0 is the basic
    # channel and is implicitly available. ISO 7816-4 §7.1.2 / GP Card
    # Spec v2.3.1 §11.1.2 allow channels 1..3 on a baseline card.
    open_logical_channels: set[int] = field(default_factory=lambda: {0})
    # GP Card Spec v2.3.1 §11.4 application registry plus an INSTALL/LOAD
    # context. INSTALL [for load] populates ``gp_install``; LOAD blocks
    # accumulate into ``gp_install.load_buffer``; on the final block the
    # ELF graduates to ``gp_apps`` and ``gp_install`` is reset.
    gp_apps: list[SimGpAppEntry] = field(default_factory=list)
    gp_install: SimGpInstallContext = field(default_factory=SimGpInstallContext)
    # SAIP §5.7 RFM applet bindings activated for the currently enabled
    # Profile. Populated by ``rebuild_runtime_filesystem`` from
    # ``SimProfileImage.rfm_instances`` so SCP80/SCP81 dispatch can
    # resolve incoming TARs against the correct ADF + access policy
    # without reaching back into the BPP.
    rfm_instances: list[SimProfileRfmInstance] = field(default_factory=list)
    # ETSI TS 102 221 §11.1.7 GET CHALLENGE freshness echo. The most
    # recently issued challenge is kept around so OTA / SCP cryptogram
    # paths and tests can correlate it with subsequent host commands.
    last_challenge_bytes: bytes = b""
    # ETSI TS 102 221 §11.1.22 SUSPEND UICC bookkeeping. The card
    # returns an 8-byte resume token plus a negotiated suspend duration
    # so a follow-up RESUME can correlate. Empty bytes mean "no
    # outstanding suspend session".
    last_suspend_token: bytes = b""
    last_suspend_duration_seconds: int = 0
    # ETSI TS 102 221 §11.1.18 TERMINATE CARD USAGE. Once set, the card
    # is logically bricked: every APDU except STATUS / SELECT is
    # answered with 6F00 ("no precise diagnosis") and the lifecycle
    # cannot be reversed. The flag lives on the volatile session
    # because the simulator is reset between processes -- a real card
    # would persist this in the OS image.
    terminated_card_usage: bool = False
    # ETSI TS 102 221 §11.1.12 GET RESPONSE buffer. Populated whenever
    # a previous command produced a deferred response (e.g. when the
    # quirk layer rewrites a 9000 reply into 61 LL). GET RESPONSE
    # consumes this buffer and clears it on read; an empty buffer
    # responds with 6985 ("conditions of use not satisfied") just
    # like a commercial UICC after the response window has elapsed.
    last_response_buffer: bytes = b""
    # ETSI TS 102 221 §11.1.14 / §11.1.15 RETRIEVE DATA / SET DATA
    # registry. Keyed by the 16-bit data-object tag (P1||P2) carried
    # in the C-APDU; the value is the verbatim TLV body the card
    # returns. Pre-populated by ``_seed_default_card_data_objects``
    # with the canonical Card Capabilities, Card Service Data,
    # Application Identifier list and Extended Card Resources blobs
    # so that capability discovery completes without additional
    # operator personalisation.
    card_data_objects: dict[int, bytes] = field(default_factory=dict)
    # 3GPP TS 31.102 §7.1.2.2 / §7.1.2.3 GBA bookkeeping.
    # ``gba_ks`` holds the bootstrap key (CK||IK = 32 bytes) cached
    # from the most recent successful AUTHENTICATE P2=0x84.
    # ``gba_b_tid`` is the bootstrap transaction identifier the
    # simulator returned to the modem; the network typically uses
    # this string to locate the corresponding Ks. ``gba_key_lifetime``
    # is the §7.1.2.2 key lifetime in seconds (0 = unset / not
    # bootstrapped). Each successful NAF derivation is appended to
    # ``gba_naf_records`` keyed by NAF_Id||IMPI for offline
    # introspection.
    gba_ks: bytes = b""
    gba_b_tid: str = ""
    gba_key_lifetime: int = 0
    gba_naf_records: dict[str, bytes] = field(default_factory=dict)
