from __future__ import annotations

import copy

from SIMCARD.state import (
    DEFAULT_SIM_ATR,
    SimCardState,
    SimChvReference,
    SimEimEntry,
    SimEuiccConfiguredData,
    SimFileNode,
    SimProfileAuthConfig,
    SimProfileEntry,
    SimProfileFsNode,
    SimProfileImage,
)
from SIMCARD.utils import encode_iccid_ef, encode_imsi_ef, tlv


USIM_AID = "A0000000871002FF86FF112233445566"
ISIM_AID = "A0000000871004FF86FF112233445566"
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
ECASD_AID = "A0000005591010FFFFFFFF8900000200"
ISDP1_AID = "A0000005591010FFFFFFFF8900001100"
ISDP2_AID = "A0000005591010FFFFFFFF8900001200"
MNO_SD_AID = "A000000151000000"
PROFILE_AID_PREFIX = "A0000005591010FFFFFFFF890000"
PROFILE_AID_SUFFIX_START = 0x1100
PROFILE_AID_SUFFIX_STEP = 0x0100
PROFILE_AID_SUFFIX_MAX = 0xFF00


def next_generated_profile_aid(profiles: list[SimProfileEntry]) -> str:
    """Allocate the next ISD-P AID following the GSMA SGP.02/22 convention.

    Profile AIDs use the prefix ``A0000005591010FFFFFFFF890000`` and a 16-bit
    suffix where the third nibble from the right identifies the profile slot
    (0x1100, 0x1200, 0x1300, ...). The last byte stays at 0x00 so every
    generated ISD-P lands on a clean slot boundary.
    """
    used = {str(profile.aid or "").strip().upper() for profile in profiles}
    suffix = PROFILE_AID_SUFFIX_START
    while suffix <= PROFILE_AID_SUFFIX_MAX:
        candidate = f"{PROFILE_AID_PREFIX}{suffix:04X}"
        if candidate not in used:
            return candidate
        suffix += PROFILE_AID_SUFFIX_STEP
    raise RuntimeError("Exhausted available ISD-P AID slots (0x1100..0xFF00 step 0x0100)")


def _app_record(aid_hex: str, label: str) -> bytes:
    value = tlv("4F", bytes.fromhex(aid_hex)) + tlv("50", label.encode("utf-8"))
    return tlv("61", value)


def _profile_path_node_id(path: tuple[str, ...]) -> str:
    if len(path) == 1 and path[0] == "MF":
        return "3F00"
    sanitized = [part.replace("/", "_").replace(" ", "_") for part in path[1:]]
    return "PROFILE::" + "::".join(sanitized)


def _encode_plmn_3gpp(mcc: str, mnc: str) -> bytes:
    mcc_digits = str(mcc or "").strip()
    mnc_digits = str(mnc or "").strip()
    if len(mcc_digits) != 3 or mcc_digits.isdigit() is False:
        return b"\xFF\xFF\xFF"
    if len(mnc_digits) not in (2, 3) or mnc_digits.isdigit() is False:
        return b"\xFF\xFF\xFF"
    mcc_values = [int(digit) for digit in mcc_digits]
    mnc_values = [int(digit) for digit in mnc_digits]
    if len(mnc_values) == 2:
        mnc3 = 0xF
    else:
        mnc3 = mnc_values[2]
    byte1 = ((mcc_values[1] & 0x0F) << 4) | (mcc_values[0] & 0x0F)
    byte2 = ((mnc3 & 0x0F) << 4) | (mcc_values[2] & 0x0F)
    byte3 = ((mnc_values[1] & 0x0F) << 4) | (mnc_values[0] & 0x0F)
    return bytes((byte1, byte2, byte3))


def _mcc_mnc_from_imsi(imsi: str, mnc_length: int) -> tuple[str, str]:
    digits = str(imsi or "").strip()
    if len(digits) < 5 or digits.isdigit() is False:
        return "", ""
    if mnc_length not in (2, 3):
        mnc_length = 2
    mcc_text = digits[:3]
    mnc_text = digits[3 : 3 + mnc_length]
    return mcc_text, mnc_text


def _encode_ef_ust_default() -> bytes:
    # Conservative USIM Service Table. Service numbering per TS 31.102 §4.2.8.
    # Services enabled: 19 (SPN), 27 (GSM access), 33 (RFU/must-be-1),
    # 38 (GSM security context), 50 (PNN), 51 (OPL).
    service_bytes = bytearray(16)
    enabled_services = (19, 27, 33, 38, 50, 51)
    for service_number in enabled_services:
        byte_index = (service_number - 1) // 8
        bit_index = (service_number - 1) % 8
        service_bytes[byte_index] |= 1 << bit_index
    return bytes(service_bytes)


def _encode_ef_spn(service_provider: str) -> bytes:
    name_bytes = str(service_provider or "YggdraSIM").encode("utf-8")[:16]
    padding = b"\xFF" * (16 - len(name_bytes))
    return bytes((0x01,)) + name_bytes + padding


def _encode_ef_loci(plmn_bytes: bytes) -> bytes:
    tmsi = b"\xFF\xFF\xFF\xFF"
    lac = b"\xFF\xFE"
    tmsi_time = b"\xFF"
    status = b"\x01"
    return tmsi + bytes(plmn_bytes) + lac + tmsi_time + status


def _encode_ef_psloci(plmn_bytes: bytes) -> bytes:
    ptmsi = b"\xFF\xFF\xFF\xFF"
    ptmsi_sig = b"\xFF\xFF\xFF"
    lac = b"\xFF\xFE"
    rac = b"\xFF"
    status = b"\x01"
    return ptmsi + ptmsi_sig + bytes(plmn_bytes) + lac + rac + status


def _encode_ef_epsloci(plmn_bytes: bytes) -> bytes:
    guti = bytes(plmn_bytes) + b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    tai = bytes(plmn_bytes) + b"\xFF\xFE"
    status = b"\x01"
    return guti + tai + status


def _encode_ef_hplmnwact(plmn_bytes: bytes) -> bytes:
    access_technology = b"\x80\x80"
    return bytes(plmn_bytes) + access_technology


def _attach_ready_usim_nodes(
    *,
    imsi: str,
    service_provider: str,
    mnc_length: int,
) -> list[SimProfileFsNode]:
    mcc_text, mnc_text = _mcc_mnc_from_imsi(imsi, mnc_length)
    plmn_bytes = _encode_plmn_3gpp(mcc_text, mnc_text) if len(mcc_text) == 3 else b"\xFF\xFF\xFF"

    invalidated_keys = b"\x07" + (b"\xFF" * 32)
    fplmn_entries = b"\xFF" * 12
    ehplmn_record = bytes(plmn_bytes)
    hplmnwact_record = _encode_ef_hplmnwact(plmn_bytes)
    start_hfn = b"\x00\x00\x00\x00\x00\x00"
    threshold = b"\x02\x00\x00\x02\x00\x00"
    access_classes = b"\x00\x04"
    ef_ecc_records = [b"\x11\xF2\xFF\x00", b"\x19\xF1\xFF\x00"]
    ef_ust_bytes = _encode_ef_ust_default()
    ef_spn_bytes = _encode_ef_spn(service_provider)
    ef_ad_bytes = bytes((0x00, 0x00, 0x00, mnc_length & 0x0F))
    ef_arr_record = bytes.fromhex("800101A40683010190A004840132")

    return [
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.ARR"),
            name="EF.ARR",
            kind="ef",
            fid="6F06",
            structure="linear-fixed",
            records=[ef_arr_record],
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.LI"),
            name="EF.LI",
            kind="ef",
            fid="6F05",
            structure="transparent",
            data=b"en",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.UST"),
            name="EF.UST",
            kind="ef",
            fid="6F38",
            structure="transparent",
            data=ef_ust_bytes,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SPN"),
            name="EF.SPN",
            kind="ef",
            fid="6F46",
            structure="transparent",
            data=ef_spn_bytes,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.ACC"),
            name="EF.ACC",
            kind="ef",
            fid="6F78",
            structure="transparent",
            data=access_classes,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.ECC"),
            name="EF.ECC",
            kind="ef",
            fid="6FB7",
            structure="linear-fixed",
            records=ef_ecc_records,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.AD"),
            name="EF.AD",
            kind="ef",
            fid="6FAD",
            structure="transparent",
            data=ef_ad_bytes,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.KEYS"),
            name="EF.KEYS",
            kind="ef",
            fid="6F08",
            structure="transparent",
            data=invalidated_keys,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.KeysPS"),
            name="EF.KeysPS",
            kind="ef",
            fid="6F09",
            structure="transparent",
            data=invalidated_keys,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.LOCI"),
            name="EF.LOCI",
            kind="ef",
            fid="6F7E",
            structure="transparent",
            data=_encode_ef_loci(plmn_bytes),
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.PSLOCI"),
            name="EF.PSLOCI",
            kind="ef",
            fid="6F73",
            structure="transparent",
            data=_encode_ef_psloci(plmn_bytes),
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.EPSLOCI"),
            name="EF.EPSLOCI",
            kind="ef",
            fid="6FE3",
            structure="transparent",
            data=_encode_ef_epsloci(plmn_bytes),
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.EPSNSC"),
            name="EF.EPSNSC",
            kind="ef",
            fid="6FE4",
            structure="transparent",
            data=b"",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.FPLMN"),
            name="EF.FPLMN",
            kind="ef",
            fid="6F7B",
            structure="transparent",
            data=fplmn_entries,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.EHPLMN"),
            name="EF.EHPLMN",
            kind="ef",
            fid="6FD9",
            structure="transparent",
            data=ehplmn_record,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.HPLMNwAcT"),
            name="EF.HPLMNwAcT",
            kind="ef",
            fid="6F62",
            structure="transparent",
            data=hplmnwact_record,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.PLMNwAcT"),
            name="EF.PLMNwAcT",
            kind="ef",
            fid="6F60",
            structure="transparent",
            data=b"\xFF" * 40,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.OPLMNwAcT"),
            name="EF.OPLMNwAcT",
            kind="ef",
            fid="6F61",
            structure="transparent",
            data=b"\xFF" * 40,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.PNN"),
            name="EF.PNN",
            kind="ef",
            fid="6FC5",
            structure="linear-fixed",
            records=[b"\xFF" * 20],
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.OPL"),
            name="EF.OPL",
            kind="ef",
            fid="6FC6",
            structure="linear-fixed",
            records=[b"\xFF" * 8],
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.START_HFN"),
            name="EF.START_HFN",
            kind="ef",
            fid="6F5B",
            structure="transparent",
            data=start_hfn,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.THRESHOLD"),
            name="EF.THRESHOLD",
            kind="ef",
            fid="6F5C",
            structure="transparent",
            data=threshold,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SUCI_Calc_Info"),
            name="EF.SUCI_Calc_Info",
            kind="ef",
            fid="4F01",
            structure="transparent",
            data=b"",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.SUPI_NAI"),
            name="EF.SUPI_NAI",
            kind="ef",
            fid="4F09",
            structure="transparent",
            data=b"",
        ),
    ]


def _default_profile_image(
    iccid: str,
    imsi: str,
    impi: str,
    *,
    service_provider: str = "YggdraSIM",
    mnc_length: int = 2,
    minimal: bool = False,
) -> SimProfileImage:
    base_nodes: list[SimProfileFsNode] = [
        SimProfileFsNode(
            path=("MF", "EF.ICCID"),
            name="EF.ICCID",
            kind="ef",
            fid="2FE2",
            structure="transparent",
            data=encode_iccid_ef(iccid),
            sfi=0x02,
        ),
        SimProfileFsNode(
            path=("MF", "EF.PL"),
            name="EF.PL",
            kind="ef",
            fid="2F05",
            structure="transparent",
            data=b"en",
            sfi=0x05,
        ),
        SimProfileFsNode(
            path=("MF", "EF.ARR"),
            name="EF.ARR",
            kind="ef",
            fid="2F06",
            structure="linear-fixed",
            records=[bytes.fromhex("800101A40683010190A004840132")],
            sfi=0x06,
        ),
        SimProfileFsNode(
            path=("MF", "DF.TELECOM"),
            name="DF.TELECOM",
            kind="df",
            fid="7F10",
        ),
        SimProfileFsNode(
            path=("MF", "DF.GSM"),
            name="DF.GSM",
            kind="df",
            fid="7F20",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM"),
            name="ADF.USIM",
            kind="adf",
            fid="7FF0",
            aid=USIM_AID,
            label="USIM",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.USIM", "EF.IMSI"),
            name="EF.IMSI",
            kind="ef",
            fid="6F07",
            structure="transparent",
            data=encode_imsi_ef(imsi),
            sfi=0x07,
        ),
        SimProfileFsNode(
            path=("MF", "ADF.ISIM"),
            name="ADF.ISIM",
            kind="adf",
            fid="7FF2",
            aid=ISIM_AID,
            label="ISIM",
        ),
        SimProfileFsNode(
            path=("MF", "ADF.ISIM", "EF.IMPI"),
            name="EF.IMPI",
            kind="ef",
            fid="6F02",
            structure="transparent",
            data=impi.encode("utf-8"),
        ),
    ]

    if minimal:
        base_nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.USIM", "EF.AD"),
                name="EF.AD",
                kind="ef",
                fid="6FAD",
                structure="transparent",
                data=bytes((0x00, 0x00, 0x00, mnc_length & 0x0F)),
            )
        )
        return SimProfileImage(
            iccid=iccid,
            imsi=imsi,
            impi=impi,
            nodes=base_nodes,
        )

    attach_nodes = _attach_ready_usim_nodes(
        imsi=imsi,
        service_provider=service_provider,
        mnc_length=mnc_length,
    )
    return SimProfileImage(
        iccid=iccid,
        imsi=imsi,
        impi=impi,
        nodes=base_nodes + attach_nodes,
    )


def _register_node(nodes: dict[str, SimFileNode], node: SimFileNode) -> None:
    nodes[node.node_id] = node
    if len(node.parent_id) > 0 and node.parent_id in nodes:
        nodes[node.parent_id].children.append(node.node_id)


def _build_name_path_index(nodes: dict[str, SimFileNode]) -> dict[tuple[str, ...], str]:
    index: dict[tuple[str, ...], str] = {}

    def walk(node_id: str, path: tuple[str, ...]) -> None:
        node = nodes[node_id]
        index[path] = node_id
        for child_id in node.children:
            child = nodes.get(child_id)
            if child is None:
                continue
            walk(child_id, path + (child.name,))

    if "3F00" in nodes:
        walk("3F00", ("MF",))
    return index


def _resolve_active_profile(state: SimCardState) -> SimProfileEntry | None:
    active = None
    active_aid = str(state.active_profile_aid or "").strip().upper()
    if len(active_aid) > 0:
        for profile in state.profiles:
            if profile.aid.upper() == active_aid:
                active = profile
                break
    if active is None:
        for profile in state.profiles:
            if str(profile.state).strip().lower() == "enabled":
                active = profile
                break
    state.active_profile_aid = active.aid if active is not None else ""
    return active


def apply_security_domain_config(state: SimCardState) -> None:
    _apply_security_domain_node(state.base_nodes, "ISDR", state.isdr_aid, state.isdr_label)
    _apply_security_domain_node(state.base_nodes, "ECASD", state.ecasd_aid, state.ecasd_label)
    _apply_security_domain_node(state.base_nodes, "MNO_SD", state.mno_sd_aid, state.mno_sd_label)
    if len(state.nodes) > 0:
        _apply_security_domain_node(state.nodes, "ISDR", state.isdr_aid, state.isdr_label)
        _apply_security_domain_node(state.nodes, "ECASD", state.ecasd_aid, state.ecasd_label)
        _apply_security_domain_node(state.nodes, "MNO_SD", state.mno_sd_aid, state.mno_sd_label)


def _apply_security_domain_node(
    nodes: dict[str, SimFileNode],
    node_id: str,
    aid_hex: str,
    label: str,
) -> None:
    node = nodes.get(node_id)
    if node is None:
        return
    if len(str(aid_hex or "").strip()) > 0:
        node.aid = str(aid_hex).strip().upper()
    if len(str(label or "").strip()) > 0:
        node.label = str(label).strip()


def rebuild_runtime_filesystem(state: SimCardState) -> None:
    previous_node_id = str(state.current_node_id or "3F00")
    base_nodes = state.base_nodes if len(state.base_nodes) > 0 else state.nodes
    state.nodes = copy.deepcopy(base_nodes)
    nodes = state.nodes
    path_index = _build_name_path_index(nodes)

    for index, profile in enumerate(state.profiles, start=1):
        label = f"ISD-P{index}"
        _register_node(
            nodes,
            SimFileNode(
                node_id=f"ISDP::{profile.aid.upper()}",
                name=label,
                kind="adf",
                aid=profile.aid,
                label=label,
                parent_id="ISDR",
            ),
        )

    active_profile = _resolve_active_profile(state)
    active_image = active_profile.profile_image if active_profile is not None else None
    if active_profile is not None:
        if len(active_profile.iccid) > 0:
            state.iccid = active_profile.iccid
        if len(active_profile.imsi) > 0:
            state.imsi = active_profile.imsi
        if active_image is not None:
            if len(active_image.iccid) > 0:
                state.iccid = active_image.iccid
            if len(active_image.imsi) > 0:
                state.imsi = active_image.imsi
            for image_node in sorted(active_image.nodes, key=lambda item: (len(item.path), item.path)):
                if len(image_node.path) <= 1 or image_node.path[0] != "MF":
                    continue
                parent_id = path_index.get(image_node.path[:-1])
                if parent_id is None:
                    continue
                node = SimFileNode(
                    node_id=_profile_path_node_id(image_node.path),
                    name=image_node.name,
                    kind=image_node.kind,
                    fid=image_node.fid,
                    aid=image_node.aid,
                    label=image_node.label,
                    parent_id=parent_id,
                    structure=image_node.structure,
                    data=bytes(image_node.data),
                    records=[bytes(record) for record in image_node.records],
                    sfi=image_node.sfi,
                )
                _register_node(nodes, node)
                path_index[image_node.path] = node.node_id

    dir_records: list[bytes] = []
    for path, aid_hex, label in (
        (("MF", "ADF.USIM"), USIM_AID, "USIM"),
        (("MF", "ADF.ISIM"), ISIM_AID, "ISIM"),
        (("MF", "ISD-R"), str(state.isdr_aid or ISDR_AID), str(state.isdr_label or "ISDR")),
        (("MF", "ECASD"), str(state.ecasd_aid or ECASD_AID), str(state.ecasd_label or "ECASD")),
        (("MF", "MNO-SD"), str(state.mno_sd_aid or MNO_SD_AID), str(state.mno_sd_label or "MNO-SD")),
    ):
        if path in path_index:
            dir_records.append(_app_record(aid_hex, label))
    if len(dir_records) > 0:
        # Linear-fixed EFs must have fixed-size records (TS 102 221 §8.2).
        # Pad every slot with 0xFF to the longest application record so
        # READ RECORD returns a deterministic record_length regardless of
        # which slot the terminal reads. This matches the zero-padded
        # record layout observed on commercial UICC references.
        max_record_length = max(len(record) for record in dir_records)
        padded_records = [
            record + b"\xFF" * (max_record_length - len(record))
            for record in dir_records
        ]
        _register_node(
            nodes,
            SimFileNode(
                node_id="2F00",
                name="EF.DIR",
                kind="ef",
                fid="2F00",
                parent_id="3F00",
                structure="linear-fixed",
                records=padded_records,
                sfi=0x1E,
            ),
        )

    if ("MF", "EF.ICCID") not in path_index and len(state.iccid) > 0:
        _register_node(
            nodes,
            SimFileNode(
                node_id="2FE2",
                name="EF.ICCID",
                kind="ef",
                fid="2FE2",
                parent_id="3F00",
                structure="transparent",
                data=encode_iccid_ef(state.iccid),
                sfi=0x02,
            ),
        )

    state.current_node_id = previous_node_id if previous_node_id in nodes else "3F00"


def build_default_state() -> SimCardState:
    iccid = "89461111111111111112"
    # MCC/MNC 001/01 - 3GPP test PLMN. Keeps the default profile identity
    # compatible with osmo-hlr / open5gs / free5gc lab HSS configurations.
    imsi = "001010000000001"
    secondary_imsi = "001010000000002"
    mnc_length_default = 2
    primary_service_provider = "YggdraSIM Lab"
    secondary_service_provider = "YggdraSIM Lab (Secondary)"
    root_ci_pkid = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
    default_auth = SimProfileAuthConfig(
        algorithm="milenage",
        ki=bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC"),
        op=bytes.fromhex("CDC202D5123E20F62B6D676AC72CB318"),
        opc=bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF"),
        amf=bytes.fromhex("8000"),
        sqn=bytes.fromhex("000000000001"),
    )
    configured_data = SimEuiccConfiguredData(
        root_smds_address="lpa.ds.gsma.com",
        additional_root_smds_addresses=["smds2.yggdrasim.test", "smds3.yggdrasim.test"],
        allowed_ci_pkids=[root_ci_pkid],
        ci_list=[root_ci_pkid],
    )
    profiles = [
        SimProfileEntry(
            aid=ISDP1_AID,
            iccid=iccid,
            state="enabled",
            profile_class="operational",
            nickname="Lab (EU 01)",
            service_provider=primary_service_provider,
            profile_name="Yggdrasil Primary",
            imsi=imsi,
            impi="user@yggdrasim.test",
            notification_address="rsp.example.com",
            profile_image=_default_profile_image(
                iccid,
                imsi,
                "user@yggdrasim.test",
                service_provider=primary_service_provider,
                mnc_length=mnc_length_default,
            ),
            profile_source="json",
            auth_config=copy.deepcopy(default_auth),
        ),
        SimProfileEntry(
            aid=ISDP2_AID,
            iccid="89461111111111111129",
            state="disabled",
            profile_class="test",
            nickname="Lab (EU 02)",
            service_provider=secondary_service_provider,
            profile_name="Yggdrasil Secondary",
            imsi=secondary_imsi,
            impi="user-secondary@yggdrasim.test",
            notification_address="rsp.example.com",
            profile_image=_default_profile_image(
                "89461111111111111129",
                secondary_imsi,
                "user-secondary@yggdrasim.test",
                service_provider=secondary_service_provider,
                mnc_length=mnc_length_default,
            ),
            profile_source="json",
            auth_config=copy.deepcopy(default_auth),
        ),
    ]
    state = SimCardState(
        atr=DEFAULT_SIM_ATR,
        eid="89044045930000000000001492294428",
        iccid=iccid,
        imsi=imsi,
        default_dp_address="rsp.example.com",
        root_ci_pkid=root_ci_pkid,
        isdr_aid=ISDR_AID,
        isdr_label="ISDR",
        ecasd_aid=ECASD_AID,
        ecasd_label="ECASD",
        mno_sd_aid=MNO_SD_AID,
        mno_sd_label="MNO-SD",
        configured_data=configured_data,
        eim_entries=[
            SimEimEntry(
                eim_id="2.25.311782205282738360923618091971140414400",
                eim_fqdn="yggdrasim.eim.test.1ot.com",
                eim_id_type=1,
                counter_value=1,
                association_token=16,
                supported_protocol_bits=[0, 2],
                euicc_ci_pkid=root_ci_pkid,
                indirect_profile_download=True,
            )
        ],
        profiles=profiles,
        active_profile_aid=profiles[0].aid,
        chv_references={
            0x01: SimChvReference(reference=0x01, value="1234", unblock_value="12345678"),
            0x81: SimChvReference(reference=0x81, value="1234", unblock_value="12345678"),
        },
    )
    state.toolkit.menu_title = "YggdraSIM"
    nodes: dict[str, SimFileNode] = {}
    _register_node(nodes, SimFileNode(node_id="3F00", name="MF", kind="mf", fid="3F00"))
    _register_node(
        nodes,
        SimFileNode(
            node_id="ISDR",
            name="ISD-R",
            kind="adf",
            aid=state.isdr_aid,
            label=state.isdr_label,
            parent_id="3F00",
        ),
    )
    _register_node(
        nodes,
        SimFileNode(
            node_id="ECASD",
            name="ECASD",
            kind="adf",
            aid=state.ecasd_aid,
            label=state.ecasd_label,
            parent_id="3F00",
        ),
    )
    _register_node(
        nodes,
        SimFileNode(
            node_id="MNO_SD",
            name="MNO-SD",
            kind="adf",
            aid=state.mno_sd_aid,
            label=state.mno_sd_label,
            parent_id="3F00",
        ),
    )
    state.base_nodes = copy.deepcopy(nodes)
    state.nodes = copy.deepcopy(nodes)
    rebuild_runtime_filesystem(state)
    return state


class EtsiFileSystem:
    def __init__(self, state: SimCardState) -> None:
        self.state = state

    def reset(self) -> None:
        self.state.current_node_id = "3F00"

    def current_node(self) -> SimFileNode:
        return self.state.nodes[self.state.current_node_id]

    def _find_child_by_fid(self, parent_id: str, fid: str) -> SimFileNode | None:
        parent = self.state.nodes.get(parent_id)
        if parent is None:
            return None
        target = fid.upper()
        for child_id in parent.children:
            child = self.state.nodes[child_id]
            if child.fid.upper() == target:
                return child
        return None

    def _find_node_by_fid(self, fid: str) -> SimFileNode | None:
        target = fid.upper()
        current = self._find_child_by_fid(self.state.current_node_id, target)
        if current is not None:
            return current
        for node in self.state.nodes.values():
            if node.fid.upper() == target:
                return node
        return None

    def _find_node_by_aid(self, aid_hex: str) -> SimFileNode | None:
        target = aid_hex.upper()
        for node in self.state.nodes.values():
            if node.aid.upper() == target:
                return node
        return None

    def select(self, selector: bytes, p1: int = 0x00, p2: int = 0x00) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.1 SELECT.

        P1 encodes the selection scope (FID, AID, parent DF, path from MF,
        path from current DF). P2 low-nibble (bits b4-b3, mask 0x0C) gates
        the response template:

        - 0x00 FCI (tag 6F) — current default template for SDs
        - 0x04 FCP (tag 62) — current default template for regular files
        - 0x08 FMD (tag 64) — not supported, collapses to FCP
        - 0x0C no response data

        Backward compatibility: when P1=0x00 and the selector length is 2
        it is treated as a FID; otherwise it is treated as an AID. This
        matches the pre-v1 behaviour exercised by the existing SIMCARD
        test gauntlet.
        """
        p1_value = int(p1) & 0xFF
        p2_value = int(p2) & 0xFF
        normalized = bytes(selector or b"")

        node = self._resolve_select_target(p1_value, normalized)
        if node is None:
            return b"", 0x6A, 0x82
        self.state.current_node_id = node.node_id

        response_template = p2_value & 0x0C
        if response_template == 0x0C:
            return b"", 0x90, 0x00
        return self.build_fcp(node), 0x90, 0x00

    def _resolve_select_target(self, p1: int, selector: bytes) -> SimFileNode | None:
        selector_hex = selector.hex().upper()

        if p1 == 0x00:
            if len(selector) == 2:
                return self._find_node_by_fid(selector_hex)
            return self._find_node_by_aid(selector_hex)

        if p1 == 0x01:
            if len(selector) != 2:
                return None
            return self._find_child_by_fid(self.state.current_node_id, selector_hex)

        if p1 == 0x02:
            if len(selector) != 2:
                return None
            candidate = self._find_child_by_fid(self.state.current_node_id, selector_hex)
            if candidate is None or candidate.kind != "ef":
                return None
            return candidate

        if p1 == 0x03:
            current = self.state.nodes.get(self.state.current_node_id)
            if current is None:
                return None
            parent_id = str(getattr(current, "parent_id", "") or "").strip()
            if len(parent_id) == 0:
                return None
            return self.state.nodes.get(parent_id)

        if p1 == 0x04:
            return self._find_node_by_aid_prefix(selector_hex)

        if p1 == 0x08:
            return self._resolve_select_by_path(selector, anchor_mf=True)

        if p1 == 0x09:
            return self._resolve_select_by_path(selector, anchor_mf=False)

        return None

    def _find_node_by_aid_prefix(self, aid_hex: str) -> SimFileNode | None:
        target = aid_hex.upper()
        if len(target) == 0:
            return None
        exact = self._find_node_by_aid(target)
        if exact is not None:
            return exact
        for node in self.state.nodes.values():
            aid_candidate = str(getattr(node, "aid", "") or "").strip().upper()
            if len(aid_candidate) == 0:
                continue
            if aid_candidate.startswith(target):
                return node
        return None

    def _resolve_select_by_path(self, selector: bytes, *, anchor_mf: bool) -> SimFileNode | None:
        raw = bytes(selector or b"")
        if len(raw) == 0 or len(raw) % 2 != 0:
            return None
        fids = [raw[index : index + 2].hex().upper() for index in range(0, len(raw), 2)]

        if anchor_mf:
            mf_node = self.state.nodes.get("3F00")
            if mf_node is None:
                return None
            current = mf_node
            if fids[0] == "3F00":
                fids = fids[1:]
        else:
            current = self.state.nodes.get(self.state.current_node_id)
            if current is None:
                return None

        for fid in fids:
            if fid == current.fid.upper():
                continue
            candidate = self._find_child_by_fid(current.node_id, fid)
            if candidate is None:
                return None
            current = candidate
        return current

    def read_binary(
        self,
        *,
        p1: int = 0x00,
        p2: int = 0x00,
        offset: int | None = None,
        le: int | None = None,
    ) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.3 READ BINARY.

        If P1 bit 8 is set the lower 5 bits of P1 select an EF by SFI
        under the currently selected DF and P2 is the byte offset
        (0..255). Otherwise P1||P2 is a 15-bit offset into the currently
        selected transparent EF.
        """
        p1_value = int(p1) & 0xFF
        p2_value = int(p2) & 0xFF
        if offset is not None:
            target_node = self.current_node()
            resolved_offset = int(offset)
        elif p1_value & 0x80:
            sfi = p1_value & 0x1F
            target_node = self._resolve_sfi_under_current(sfi)
            if target_node is None:
                return b"", 0x6A, 0x82
            self.state.current_node_id = target_node.node_id
            resolved_offset = p2_value
        else:
            target_node = self.current_node()
            resolved_offset = ((p1_value & 0x7F) << 8) | p2_value

        if target_node.kind != "ef" or target_node.structure != "transparent":
            # ETSI TS 102 221 §11.1.3: READ BINARY against a record-oriented
            # or non-EF target is reported as "command incompatible with
            # file structure" (69 81), not "no current EF" (69 86).
            return b"", 0x69, 0x81
        if resolved_offset < 0 or resolved_offset > len(target_node.data):
            return b"", 0x6B, 0x00
        payload = target_node.data[resolved_offset:]
        if le not in (None, 0, 256, 65536):
            payload = payload[:le]
        return payload, 0x90, 0x00

    def read_record(
        self,
        record_number: int,
        *,
        p2: int = 0x04,
        le: int | None = None,
    ) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.5 READ RECORD.

        P2 bits 7..3 hold the SFI (0 means current EF). P2 bits 2..0
        hold the mode: 0x04 absolute, 0x02 next, 0x03 previous. Cyclic
        modes (0x06 / 0x07) collapse to absolute on a linear-fixed EF.
        """
        p2_value = int(p2) & 0xFF
        sfi = (p2_value >> 3) & 0x1F
        mode = p2_value & 0x07

        if sfi != 0:
            target_node = self._resolve_sfi_under_current(sfi)
            if target_node is None:
                return b"", 0x6A, 0x82
            self.state.current_node_id = target_node.node_id
        else:
            target_node = self.current_node()

        if target_node.kind != "ef" or target_node.structure != "linear-fixed":
            # ETSI TS 102 221 §11.1.5: READ RECORD against a transparent
            # EF is reported as "command incompatible with file
            # structure" (69 81).
            return b"", 0x69, 0x81

        record_count = len(target_node.records)
        if record_count == 0:
            return b"", 0x6A, 0x83

        if mode in (0x02, 0x06):
            selected_record = max(1, int(record_number or 0))
        elif mode in (0x03, 0x07):
            selected_record = max(1, int(record_number or 0))
        else:
            selected_record = int(record_number or 0)

        if selected_record <= 0 or selected_record > record_count:
            return b"", 0x6A, 0x83
        payload = target_node.records[selected_record - 1]
        if le not in (None, 0, 256, 65536):
            payload = payload[:le]
        return payload, 0x90, 0x00

    def _resolve_sfi_under_current(self, sfi: int) -> SimFileNode | None:
        sfi_value = int(sfi) & 0x1F
        if sfi_value == 0:
            return None
        parent = self.state.nodes.get(self.state.current_node_id)
        if parent is None:
            return None
        for child_id in parent.children:
            child = self.state.nodes.get(child_id)
            if child is None:
                continue
            if child.kind != "ef":
                continue
            child_sfi = getattr(child, "sfi", None)
            if child_sfi is None:
                continue
            if (int(child_sfi) & 0x1F) == sfi_value:
                return child
        return None

    def update_binary(self, offset: int, payload: bytes) -> tuple[bytes, int, int]:
        node = self.current_node()
        if node.kind != "ef" or node.structure != "transparent":
            return b"", 0x69, 0x81
        existing = bytearray(node.data)
        if offset > len(existing):
            existing.extend(b"\xFF" * (offset - len(existing)))
        end_offset = offset + len(payload)
        if end_offset > len(existing):
            existing.extend(b"\xFF" * (end_offset - len(existing)))
        existing[offset:end_offset] = payload
        node.data = bytes(existing)
        return b"", 0x90, 0x00

    def update_record(self, record_number: int, payload: bytes) -> tuple[bytes, int, int]:
        node = self.current_node()
        if node.kind != "ef" or node.structure != "linear-fixed":
            return b"", 0x69, 0x81
        if record_number <= 0:
            return b"", 0x6A, 0x83
        while len(node.records) < record_number:
            fill_length = node.record_length or len(payload)
            node.records.append(b"\xFF" * fill_length)
        node.records[record_number - 1] = bytes(payload)
        return b"", 0x90, 0x00

    def build_fcp(self, node: SimFileNode) -> bytes:
        """Build FCP per ETSI TS 102 221 §11.1.1.4.

        Descriptor bytes use the shareable flag (bit 7) so the FCP
        structure matches the response of commercial UICC references
        where MF/DF/ADF advertise 0x78 and EFs advertise 0x41 (transparent)
        or 0x42 (linear fixed), both with data-coding byte 0x21. The
        previous 0x38/0x01/0x02 encoding was a valid subset but strict
        terminals sometimes rely on the shareable bit when deciding
        whether a file can be accessed concurrently from multiple
        logical channels.

        8A (life-cycle status) is always emitted with 05
        (operational-activated); its absence can be rejected as an
        incomplete FCP by strict stacks and real UICCs always include
        it. 88 (short EF identifier) is emitted for EFs that have one
        assigned, with the SFI left-aligned in the high five bits per
        §11.1.1.4.7.
        """
        if node.kind == "adf" and self._is_security_domain(node):
            return self._build_isd_fci(node)
        if node.kind in ("mf", "df", "adf"):
            descriptor = b"\x78\x21"
        elif node.structure == "linear-fixed":
            descriptor = (
                bytes([0x42, 0x21])
                + node.record_length.to_bytes(2, "big", signed=False)
                + bytes([len(node.records) & 0xFF])
            )
        else:
            descriptor = b"\x41\x21"
        body = tlv("82", descriptor)
        if len(node.fid) == 4:
            body += tlv("83", bytes.fromhex(node.fid))
        if len(node.aid) > 0:
            body += tlv("84", bytes.fromhex(node.aid))
        if node.kind == "ef":
            size = node.total_size
            if size > 0:
                width = 1
                if size > 0xFF:
                    width = 2
                body += tlv("80", size.to_bytes(width, "big", signed=False))
            if node.sfi is not None and (int(node.sfi) & 0x1F) != 0:
                body += tlv("88", bytes([(int(node.sfi) & 0x1F) << 3]))
        body += tlv("8A", b"\x05")
        return tlv("62", body)

    def _is_security_domain(self, node: SimFileNode) -> bool:
        aid_hex = str(node.aid or "").strip().upper()
        if len(aid_hex) == 0:
            return False
        isdr_aid = str(self.state.isdr_aid or "").strip().upper()
        ecasd_aid = str(self.state.ecasd_aid or "").strip().upper()
        mno_aid = str(self.state.mno_sd_aid or "").strip().upper()
        return aid_hex in (isdr_aid, ecasd_aid, mno_aid)

    def _build_isd_fci(self, node: SimFileNode) -> bytes:
        """FCI template per SGP.22 §5.7.1 / GP Card Spec v2.3.1 §11.1.5.

        ISD-R / ECASD / MNO-SD SHALL respond to SELECT with an FCI (tag 6F)
        carrying at minimum the AID (84) and a proprietary A5 block with
        9F65 (max buffer). ISD-R additionally advertises E0 (extended card
        resources) and E1 (profile-installation result envelope size).
        """
        aid_hex = str(node.aid or "").strip().upper()
        body = tlv("84", bytes.fromhex(aid_hex))

        max_buffer = 0x00FF
        proprietary = tlv("9F65", max_buffer.to_bytes(2, "big", signed=False))
        body += tlv("A5", proprietary)

        isdr_aid = str(self.state.isdr_aid or "").strip().upper()
        if aid_hex == isdr_aid:
            ext = self.state.euicc_info.ext_card_resources
            ext_payload = (
                tlv("81", bytes([ext.system_apps_count & 0xFF]))
                + tlv("82", ext.free_nvm.to_bytes(3, "big", signed=False))
                + tlv("83", ext.free_ram.to_bytes(2, "big", signed=False))
            )
            body += tlv("E0", ext_payload)
            body += tlv("E1", tlv("80", (0x06C0).to_bytes(2, "big", signed=False)))

        return tlv("6F", body)
