from __future__ import annotations

import copy

from SIMCARD.state import (
    DEFAULT_SIM_ATR,
    SimCardState,
    SimEimEntry,
    SimEuiccConfiguredData,
    SimFileNode,
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
RESERVED_PROFILE_AID_SUFFIXES = (0x1100, 0x1200)
DYNAMIC_PROFILE_AID_SUFFIX_START = 0x1303


def next_generated_profile_aid(profiles: list[SimProfileEntry]) -> str:
    used = {str(profile.aid or "").strip().upper() for profile in profiles}
    suffixes: list[int] = []
    for aid in used:
        if not aid.startswith(PROFILE_AID_PREFIX) or len(aid) != len(PROFILE_AID_PREFIX) + 4:
            continue
        try:
            suffixes.append(int(aid[-4:], 16))
        except ValueError:
            continue
    if len(suffixes) == 0:
        return f"{PROFILE_AID_PREFIX}{RESERVED_PROFILE_AID_SUFFIXES[0]:04X}"
    if RESERVED_PROFILE_AID_SUFFIXES[0] in suffixes and all(
        suffix < RESERVED_PROFILE_AID_SUFFIXES[1] for suffix in suffixes
    ):
        return f"{PROFILE_AID_PREFIX}{RESERVED_PROFILE_AID_SUFFIXES[1]:04X}"
    dynamic_suffixes = [suffix for suffix in suffixes if suffix >= DYNAMIC_PROFILE_AID_SUFFIX_START]
    suffix = DYNAMIC_PROFILE_AID_SUFFIX_START if len(dynamic_suffixes) == 0 else max(dynamic_suffixes) + 1
    while True:
        candidate = f"{PROFILE_AID_PREFIX}{suffix:04X}"
        if candidate not in used:
            return candidate
        suffix += 1


def _app_record(aid_hex: str, label: str) -> bytes:
    value = tlv("4F", bytes.fromhex(aid_hex)) + tlv("50", label.encode("utf-8"))
    return tlv("61", value)


def _profile_path_node_id(path: tuple[str, ...]) -> str:
    if len(path) == 1 and path[0] == "MF":
        return "3F00"
    sanitized = [part.replace("/", "_").replace(" ", "_") for part in path[1:]]
    return "PROFILE::" + "::".join(sanitized)


def _default_profile_image(iccid: str, imsi: str, impi: str) -> SimProfileImage:
    return SimProfileImage(
        iccid=iccid,
        imsi=imsi,
        impi=impi,
        nodes=[
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
                path=("MF", "ADF.USIM", "EF.AD"),
                name="EF.AD",
                kind="ef",
                fid="6FAD",
                structure="transparent",
                data=bytes.fromhex("00000002"),
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
        ],
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
        _register_node(
            nodes,
            SimFileNode(
                node_id="2F00",
                name="EF.DIR",
                kind="ef",
                fid="2F00",
                parent_id="3F00",
                structure="linear-fixed",
                records=dir_records,
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
    imsi = "1234567812345678"
    root_ci_pkid = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
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
            service_provider="YggdraSIM Lab",
            profile_name="Yggdrasil Primary",
            imsi=imsi,
            impi="user@yggdrasim.test",
            notification_address="rsp.example.com",
            profile_image=_default_profile_image(iccid, imsi, "user@yggdrasim.test"),
            profile_source="json",
        ),
        SimProfileEntry(
            aid=ISDP2_AID,
            iccid="89461111111111111129",
            state="disabled",
            profile_class="test",
            nickname="Lab (EU 02)",
            service_provider="YggdraSIM Lab",
            profile_name="Yggdrasil Secondary",
            imsi="1234567812345679",
            impi="user-secondary@yggdrasim.test",
            notification_address="rsp.example.com",
            profile_image=_default_profile_image(
                "89461111111111111129",
                "1234567812345679",
                "user-secondary@yggdrasim.test",
            ),
            profile_source="json",
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
    )
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

    def select(self, selector: bytes) -> tuple[bytes, int, int]:
        if len(selector) == 2:
            node = self._find_node_by_fid(selector.hex().upper())
        else:
            node = self._find_node_by_aid(selector.hex().upper())
        if node is None:
            return b"", 0x6A, 0x82
        self.state.current_node_id = node.node_id
        return self.build_fcp(node), 0x90, 0x00

    def read_binary(self, offset: int = 0, le: int | None = None) -> tuple[bytes, int, int]:
        node = self.current_node()
        if node.kind != "ef" or node.structure != "transparent":
            return b"", 0x69, 0x86
        if offset < 0 or offset > len(node.data):
            return b"", 0x6B, 0x00
        payload = node.data[offset:]
        if le not in (None, 0, 256, 65536):
            payload = payload[:le]
        return payload, 0x90, 0x00

    def read_record(self, record_number: int, le: int | None = None) -> tuple[bytes, int, int]:
        node = self.current_node()
        if node.kind != "ef" or node.structure != "linear-fixed":
            return b"", 0x69, 0x86
        if record_number <= 0 or record_number > len(node.records):
            return b"", 0x6A, 0x83
        record = node.records[record_number - 1]
        payload = record
        if le not in (None, 0, 256, 65536):
            payload = payload[:le]
        return payload, 0x90, 0x00

    def update_binary(self, offset: int, payload: bytes) -> tuple[bytes, int, int]:
        node = self.current_node()
        if node.kind != "ef" or node.structure != "transparent":
            return b"", 0x69, 0x86
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
            return b"", 0x69, 0x86
        if record_number <= 0:
            return b"", 0x6A, 0x83
        while len(node.records) < record_number:
            fill_length = node.record_length or len(payload)
            node.records.append(b"\xFF" * fill_length)
        node.records[record_number - 1] = bytes(payload)
        return b"", 0x90, 0x00

    def build_fcp(self, node: SimFileNode) -> bytes:
        if node.kind in ("mf", "df", "adf"):
            descriptor = b"\x38\x00"
        elif node.structure == "linear-fixed":
            descriptor = (
                bytes([0x02, 0x00])
                + node.record_length.to_bytes(2, "big", signed=False)
                + bytes([len(node.records) & 0xFF])
            )
        else:
            descriptor = b"\x01\x00"
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
        return tlv("62", body)
