from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Any

from SIMCARD.etsi_fs import ISIM_AID, USIM_AID
from SIMCARD.state import SimProfileFsNode, SimProfileImage
from SIMCARD.utils import decode_imsi_ef, encode_iccid_ef, encode_imsi_ef, read_tlv

_SAIP_ASN1 = None
_SAIP_ASN1_FAILED = False

_SECTION_SPECS: dict[str, dict[str, Any]] = {
    "mf": {
        "base_path": ("MF",),
        "root_path": None,
        "root_kind": "",
        "root_fid": "",
        "root_aid": "",
        "root_label": "",
    },
    "telecom": {
        "base_path": ("MF", "DF.TELECOM"),
        "root_path": ("MF", "DF.TELECOM"),
        "root_kind": "df",
        "root_fid": "7F10",
        "root_aid": "",
        "root_label": "",
    },
    "usim": {
        "base_path": ("MF", "ADF.USIM"),
        "root_path": ("MF", "ADF.USIM"),
        "root_kind": "adf",
        "root_fid": "7FF0",
        "root_aid": USIM_AID,
        "root_label": "USIM",
    },
    "opt-usim": {
        "base_path": ("MF", "ADF.USIM"),
        "root_path": ("MF", "ADF.USIM"),
        "root_kind": "adf",
        "root_fid": "7FF0",
        "root_aid": USIM_AID,
        "root_label": "USIM",
    },
    "isim": {
        "base_path": ("MF", "ADF.ISIM"),
        "root_path": ("MF", "ADF.ISIM"),
        "root_kind": "adf",
        "root_fid": "7FF2",
        "root_aid": ISIM_AID,
        "root_label": "ISIM",
    },
    "opt-isim": {
        "base_path": ("MF", "ADF.ISIM"),
        "root_path": ("MF", "ADF.ISIM"),
        "root_kind": "adf",
        "root_fid": "7FF2",
        "root_aid": ISIM_AID,
        "root_label": "ISIM",
    },
}

_FILE_SPECS: dict[str, dict[str, Any]] = {
    "ef-iccid": {"name": "EF.ICCID", "fid": "2FE2", "structure": "transparent", "sfi": 0x02},
    "ef-dir": {"name": "EF.DIR", "fid": "2F00", "structure": "linear-fixed", "sfi": 0x1E},
    "ef-imsi": {"name": "EF.IMSI", "fid": "6F07", "structure": "transparent", "sfi": 0x07},
    "ef-ad": {"name": "EF.AD", "fid": "6FAD", "structure": "transparent", "sfi": None},
    "ef-ust": {"name": "EF.UST", "fid": "6F38", "structure": "transparent", "sfi": None},
    "ef-spn": {"name": "EF.SPN", "fid": "6F46", "structure": "transparent", "sfi": None},
    "ef-acc": {"name": "EF.ACC", "fid": "6F78", "structure": "transparent", "sfi": None},
    "ef-ecc": {"name": "EF.ECC", "fid": "6FB7", "structure": "linear-fixed", "sfi": None},
    "ef-msisdn": {"name": "EF.MSISDN", "fid": "6F40", "structure": "linear-fixed", "sfi": None},
    "ef-loci": {"name": "EF.LOCI", "fid": "6F7E", "structure": "transparent", "sfi": None},
    "ef-psloci": {"name": "EF.PSLOCI", "fid": "6F73", "structure": "transparent", "sfi": None},
    "ef-epsloci": {"name": "EF.EPSLOCI", "fid": "6FE3", "structure": "transparent", "sfi": None},
    "ef-plmnwact": {"name": "EF.PLMNWACT", "fid": "6F60", "structure": "transparent", "sfi": None},
    "ef-oplmnwact": {"name": "EF.OPLMNWACT", "fid": "6F61", "structure": "transparent", "sfi": None},
    "ef-hplmnwact": {"name": "EF.HPLMNWACT", "fid": "6F62", "structure": "transparent", "sfi": None},
    "ef-fplmn": {"name": "EF.FPLMN", "fid": "6F7B", "structure": "transparent", "sfi": None},
    "ef-gid1": {"name": "EF.GID1", "fid": "6F3E", "structure": "transparent", "sfi": None},
    "ef-gid2": {"name": "EF.GID2", "fid": "6F3F", "structure": "transparent", "sfi": None},
    "ef-smsp": {"name": "EF.SMSP", "fid": "6F42", "structure": "linear-fixed", "sfi": None},
    "ef-smss": {"name": "EF.SMSS", "fid": "6F43", "structure": "transparent", "sfi": None},
    "ef-sms": {"name": "EF.SMS", "fid": "6F3C", "structure": "linear-fixed", "sfi": None},
    "ef-pnn": {"name": "EF.PNN", "fid": "6FC5", "structure": "linear-fixed", "sfi": None},
    "ef-opl": {"name": "EF.OPL", "fid": "6FC6", "structure": "linear-fixed", "sfi": None},
    "ef-spdi": {"name": "EF.SPDI", "fid": "6FCD", "structure": "transparent", "sfi": None},
    "ef-epsnsc": {"name": "EF.EPSNSC", "fid": "6FE4", "structure": "transparent", "sfi": None},
    "ef-keysPS": {"name": "EF.KeysPS", "fid": "6F09", "structure": "transparent", "sfi": None},
    "ef-pcscf": {"name": "EF.PCSCF", "fid": "6F09", "structure": "transparent", "sfi": None},
    "ef-suci-calc-info-usim": {
        "name": "EF.SUCI_CALC_INFO",
        "fid": "4F01",
        "structure": "transparent",
        "sfi": None,
    },
    "ef-supinai": {"name": "EF.SUPI_NAI", "fid": "4F09", "structure": "transparent", "sfi": None},
    "ef-impi": {"name": "EF.IMPI", "fid": "6F02", "structure": "transparent", "sfi": None},
    "ef-domain": {"name": "EF.DOMAIN", "fid": "6F03", "structure": "transparent", "sfi": None},
    "ef-impu": {"name": "EF.IMPU", "fid": "6F04", "structure": "linear-fixed", "sfi": None},
    "ef-ist": {"name": "EF.IST", "fid": "6F07", "structure": "transparent", "sfi": None},
}


def decode_profile_image(
    upp_bytes: bytes,
    *,
    default_iccid: str = "",
    default_name: str = "",
    default_imsi: str = "",
    default_impi: str = "",
) -> SimProfileImage | None:
    raw = bytes(upp_bytes or b"")
    if len(raw) == 0:
        return None
    image = SimProfileImage(
        profile_name=str(default_name or "").strip(),
        iccid=str(default_iccid or "").strip(),
        imsi=str(default_imsi or "").strip(),
        impi=str(default_impi or "").strip(),
    )

    header_name, header_iccid = _extract_profile_identity_from_header_tlv(raw)
    if len(header_name) > 0:
        image.profile_name = header_name
    if len(header_iccid) > 0:
        image.iccid = header_iccid

    asn1 = _get_saip_asn1()
    if asn1 is None:
        return _finalize_image(image)

    offset = 0
    while offset < len(raw):
        try:
            _, _, raw_tlv, next_offset = read_tlv(raw, offset)
            pe_type, decoded = asn1.decode("ProfileElement", raw_tlv)
        except Exception:
            break
        if isinstance(decoded, dict):
            _consume_profile_element(image, str(pe_type or "").strip(), decoded)
        offset = next_offset
    return _finalize_image(image)


def _get_saip_asn1():
    global _SAIP_ASN1, _SAIP_ASN1_FAILED
    if _SAIP_ASN1 is not None:
        return _SAIP_ASN1
    if _SAIP_ASN1_FAILED:
        return None
    try:
        project_root = Path(__file__).resolve().parent.parent
        pysim_root = project_root / "pysim"
        root_text = str(pysim_root)
        if pysim_root.is_dir() and root_text not in sys.path:
            sys.path.insert(0, root_text)
        from pySim.esim import compile_asn1_subdir

        _SAIP_ASN1 = compile_asn1_subdir("saip")
    except Exception:
        _SAIP_ASN1_FAILED = True
        return None
    return _SAIP_ASN1


def _extract_profile_identity_from_header_tlv(profile_bytes: bytes) -> tuple[str, str]:
    try:
        tag_bytes, value, _, _ = read_tlv(profile_bytes, 0)
    except Exception:
        return "", ""
    if tag_bytes != b"\xA0":
        return "", ""

    profile_name = ""
    profile_iccid = ""
    offset = 0
    while offset < len(value):
        try:
            child_tag, child_value, _, next_offset = read_tlv(value, offset)
        except Exception:
            break
        if child_tag == b"\x82" and len(profile_name) == 0:
            try:
                profile_name = bytes(child_value).decode("utf-8", "ignore").strip()
            except Exception:
                profile_name = ""
        elif child_tag == b"\x83" and len(profile_iccid) == 0:
            profile_iccid = bytes(child_value).hex().upper().rstrip("F")
        offset = next_offset
    return profile_name, profile_iccid


def _consume_profile_element(image: SimProfileImage, pe_type: str, decoded: dict[str, Any]) -> None:
    if pe_type == "header":
        profile_name = decoded.get("profileType")
        if isinstance(profile_name, str) and len(profile_name.strip()) > 0:
            image.profile_name = profile_name.strip()
        header_iccid = decoded.get("iccid")
        if isinstance(header_iccid, (bytes, bytearray, memoryview)) and len(header_iccid) > 0:
            image.iccid = bytes(header_iccid).hex().upper().rstrip("F")
        return

    spec = _SECTION_SPECS.get(pe_type)
    if spec is None:
        return

    root_path = spec.get("root_path")
    if isinstance(root_path, tuple):
        image.nodes.append(
            SimProfileFsNode(
                path=root_path,
                name=root_path[-1],
                kind=str(spec.get("root_kind", "df") or "df"),
                fid=str(spec.get("root_fid", "") or ""),
                aid=str(spec.get("root_aid", "") or ""),
                label=str(spec.get("root_label", "") or ""),
            )
        )

    base_path = tuple(spec.get("base_path", ("MF",)))
    for key, value in decoded.items():
        if key.endswith("-header") or key == "templateID":
            continue
        file_spec = _FILE_SPECS.get(str(key))
        if file_spec is None:
            continue
        payload = _materialize_file_payload(value)
        if payload is None:
            continue
        structure = str(file_spec.get("structure", "transparent") or "transparent")
        records = [payload] if structure == "linear-fixed" and len(payload) > 0 else []
        data = b"" if structure == "linear-fixed" else payload
        image.nodes.append(
            SimProfileFsNode(
                path=base_path + (str(file_spec["name"]),),
                name=str(file_spec["name"]),
                kind="ef",
                fid=str(file_spec.get("fid", "") or ""),
                structure=structure,
                data=data,
                records=records,
                sfi=file_spec.get("sfi"),
            )
        )


def _materialize_file_payload(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, list) is False:
        return b""
    stream = io.BytesIO()
    for item in value:
        if isinstance(item, tuple) is False or len(item) != 2:
            continue
        tag_name = str(item[0] or "").strip()
        if tag_name == "doNotCreate":
            return None
        if tag_name == "fillFileOffset":
            try:
                stream.seek(int(item[1] or 0), io.SEEK_CUR)
            except Exception:
                continue
            continue
        if tag_name == "fillFileContent":
            payload = item[1]
            if isinstance(payload, (bytes, bytearray, memoryview)):
                stream.write(bytes(payload))
    return stream.getvalue()


def _finalize_image(image: SimProfileImage) -> SimProfileImage | None:
    deduped: dict[tuple[str, ...], SimProfileFsNode] = {}
    for node in image.nodes:
        if len(node.path) == 0:
            continue
        existing = deduped.get(node.path)
        if existing is None:
            deduped[node.path] = node
            continue
        replacement_has_payload = len(node.data) > 0 or len(node.records) > 0 or len(node.aid) > 0
        existing_has_payload = (
            len(existing.data) > 0 or len(existing.records) > 0 or len(existing.aid) > 0
        )
        if replacement_has_payload or existing_has_payload is False:
            deduped[node.path] = node
    image.nodes = sorted(deduped.values(), key=lambda item: (len(item.path), item.path))

    if len(image.profile_name) == 0 and len(image.iccid) > 0:
        image.profile_name = f"ICCID-{image.iccid[-4:]}"

    usim_imsi = _node_by_path(image, ("MF", "ADF.USIM", "EF.IMSI"))
    if usim_imsi is not None and len(usim_imsi.data) > 0:
        decoded = decode_imsi_ef(usim_imsi.data)
        if len(decoded) > 0:
            image.imsi = decoded
    isim_impi = _node_by_path(image, ("MF", "ADF.ISIM", "EF.IMPI"))
    if isim_impi is not None and len(isim_impi.data) > 0:
        try:
            image.impi = isim_impi.data.decode("utf-8", "ignore").strip()
        except Exception:
            pass

    if len(image.iccid) > 0 and _node_by_path(image, ("MF", "EF.ICCID")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "EF.ICCID"),
                name="EF.ICCID",
                kind="ef",
                fid="2FE2",
                structure="transparent",
                data=encode_iccid_ef(image.iccid),
                sfi=0x02,
            )
        )

    if len(image.imsi) > 0 and _node_by_path(image, ("MF", "ADF.USIM")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.USIM"),
                name="ADF.USIM",
                kind="adf",
                fid="7FF0",
                aid=USIM_AID,
                label="USIM",
            )
        )
    if len(image.imsi) > 0 and _node_by_path(image, ("MF", "ADF.USIM", "EF.IMSI")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.USIM", "EF.IMSI"),
                name="EF.IMSI",
                kind="ef",
                fid="6F07",
                structure="transparent",
                data=encode_imsi_ef(image.imsi),
                sfi=0x07,
            )
        )
    if len(image.imsi) > 0 and _node_by_path(image, ("MF", "ADF.USIM", "EF.AD")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.USIM", "EF.AD"),
                name="EF.AD",
                kind="ef",
                fid="6FAD",
                structure="transparent",
                data=bytes.fromhex("00000002"),
            )
        )

    if len(image.impi) > 0 and _node_by_path(image, ("MF", "ADF.ISIM")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.ISIM"),
                name="ADF.ISIM",
                kind="adf",
                fid="7FF2",
                aid=ISIM_AID,
                label="ISIM",
            )
        )
    if len(image.impi) > 0 and _node_by_path(image, ("MF", "ADF.ISIM", "EF.IMPI")) is None:
        image.nodes.append(
            SimProfileFsNode(
                path=("MF", "ADF.ISIM", "EF.IMPI"),
                name="EF.IMPI",
                kind="ef",
                fid="6F02",
                structure="transparent",
                data=image.impi.encode("utf-8"),
            )
        )

    image.nodes = sorted({node.path: node for node in image.nodes}.values(), key=lambda item: (len(item.path), item.path))
    if len(image.nodes) == 0 and len(image.iccid) == 0 and len(image.imsi) == 0 and len(image.impi) == 0:
        return None
    return image


def _node_by_path(image: SimProfileImage, path: tuple[str, ...]) -> SimProfileFsNode | None:
    for node in image.nodes:
        if node.path == path:
            return node
    return None
