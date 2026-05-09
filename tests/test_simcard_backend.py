import contextlib
import importlib.util
import datetime
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.x509.oid import ExtensionOID, NameOID

from SIMCARD.bsp import BspInstance
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import next_generated_profile_aid
from SIMCARD.profile_import import import_profile_artifact
from SIMCARD.utils import encode_iccid_ef, encode_imsi_ef
from SCP03.config import Config
from SCP03.crypto.session import Scp03Session
from SCP03.logic.euicc_info2 import build_euicc_info2_detail_lines, build_euicc_info2_validation_lines
from SCP03.logic.sgp32_decode import decode_notifications_response
from SCP03.logic.sgp32_decode import (
    decode_eim_configuration_entries,
    decode_euicc_info1_summary,
    decode_get_certs_response,
)
from SCP11.live.factory import build_apdu_channel
from yggdrasim_common.card_backend import (
    CARD_BACKEND_ENV,
    SIM_EIM_IDENTITY_ENV,
    SIM_EUICC_STORE_ENV,
    SIM_ISDR_CONFIG_ENV,
    SIM_PROFILE_STORE_ENV,
    SIM_QUIRKS_ENV,
    create_card_connection,
)


MAIN_WRAPPER_PATH = Path(__file__).resolve().parent.parent / "main" / "main.py"
MAIN_WRAPPER_SPEC = importlib.util.spec_from_file_location(
    "main_wrapper_card_backend_module",
    MAIN_WRAPPER_PATH,
)
assert MAIN_WRAPPER_SPEC is not None
assert MAIN_WRAPPER_SPEC.loader is not None
main_wrapper = importlib.util.module_from_spec(MAIN_WRAPPER_SPEC)
sys.modules[MAIN_WRAPPER_SPEC.name] = main_wrapper
MAIN_WRAPPER_SPEC.loader.exec_module(main_wrapper)

ISDR_AID = "A0000005591010FFFFFFFF8900000100"
ECASD_AID = "A0000005591010FFFFFFFF8900000200"
USIM_AID = "A0000000871002FF86FF112233445566"
ISIM_AID = "A0000000871004FF86FF112233445566"

_SAIP_ASN1 = None


def encode_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def wrap_tlv(tag: bytes | str, value: bytes) -> bytes:
    tag_bytes = bytes.fromhex(tag) if isinstance(tag, str) else bytes(tag)
    return tag_bytes + encode_length(len(value)) + bytes(value)


def encode_named_bit_string(bits: list[int]) -> bytes:
    normalized = sorted({int(bit) for bit in bits if int(bit) >= 0})
    if len(normalized) == 0:
        return b"\x00"
    highest = normalized[-1]
    payload = bytearray((highest // 8) + 1)
    for bit in normalized:
        byte_index = bit // 8
        bit_offset = bit % 8
        payload[byte_index] |= 1 << (7 - bit_offset)
    total_bits = len(payload) * 8
    unused_bits = total_bits - (highest + 1)
    return bytes([unused_bits]) + bytes(payload)


def build_add_eim_command_payload(
    root_tag: str,
    *,
    eim_id: str,
    eim_fqdn: str = "",
    eim_id_type: int = 1,
    counter_value: int = 1,
    association_token: int | None = None,
    supported_protocol_bits: list[int] | None = None,
    euicc_ci_pkid_hex: str = "",
    indirect_profile_download: bool = False,
    eim_certificate_der: bytes = b"",
    trusted_tls_certificate_der: bytes = b"",
) -> bytes:
    row = wrap_tlv("80", eim_id.encode("utf-8"))
    if len(eim_fqdn) > 0:
        row += wrap_tlv("81", eim_fqdn.encode("utf-8"))
    row += wrap_tlv("82", int(eim_id_type).to_bytes(1, "big", signed=False))
    row += wrap_tlv("83", int(counter_value).to_bytes(max(1, (int(counter_value).bit_length() + 7) // 8), "big"))
    if association_token is not None:
        encoded_token = int(association_token).to_bytes(
            max(1, (int(association_token).bit_length() + 7) // 8),
            "big",
            signed=False,
        )
        row += wrap_tlv("84", encoded_token)
    if supported_protocol_bits is not None:
        row += wrap_tlv("87", encode_named_bit_string(supported_protocol_bits))
    if len(euicc_ci_pkid_hex) > 0:
        row += wrap_tlv("88", bytes.fromhex(euicc_ci_pkid_hex))
    if indirect_profile_download:
        row += wrap_tlv("89", b"")
    if len(eim_certificate_der) > 0:
        row += wrap_tlv("A5", wrap_tlv("A1", eim_certificate_der))
    if len(trusted_tls_certificate_der) > 0:
        row += wrap_tlv("A6", wrap_tlv("A1", trusted_tls_certificate_der))
    return wrap_tlv(root_tag, wrap_tlv("A0", wrap_tlv("30", row)))


def build_euicc_memory_reset_payload(*, reset_eim_config_data: bool = True) -> bytes:
    option_bits: list[int] = []
    if reset_eim_config_data:
        option_bits.append(5)
    return wrap_tlv("BF64", wrap_tlv("82", encode_named_bit_string(option_bits)))


def write_sim_eim_identity(
    runtime_root: Path,
    *,
    eim_id: str,
    eim_fqdn: str,
    eim_id_type: str = "oid",
    euicc_ci_pk_id: str = "",
    eim_public_key_cert_der: bytes = b"",
    trusted_tls_cert_der: bytes = b"",
) -> Path:
    simcard_dir = Path(runtime_root) / "Workspace" / "SIMCARD"
    cert_dir = simcard_dir / "certs" / "eim"
    cert_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "eim_id": str(eim_id),
        "eim_id_type": str(eim_id_type),
        "eim_fqdn": str(eim_fqdn),
        "eim_endpoint": f"https://{eim_fqdn}/gsma/rsp2/asn1",
        "euicc_ci_pk_id": str(euicc_ci_pk_id or ""),
    }
    if len(eim_public_key_cert_der) > 0:
        (cert_dir / "local-eim-signer.der").write_bytes(bytes(eim_public_key_cert_der))
        payload["eim_public_key_cert_path"] = "local-eim-signer.der"
    if len(trusted_tls_cert_der) > 0:
        (cert_dir / "local-eim-tls.der").write_bytes(bytes(trusted_tls_cert_der))
        payload["trusted_tls_cert_path"] = "local-eim-tls.der"
    identity_path = simcard_dir / "eim_identity.json"
    identity_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return identity_path


def compile_saip_asn1():
    global _SAIP_ASN1
    if _SAIP_ASN1 is not None:
        return _SAIP_ASN1
    pysim_root = Path(__file__).resolve().parents[1] / "pysim"
    root_text = str(pysim_root)
    if pysim_root.is_dir() and root_text not in sys.path:
        sys.path.insert(0, root_text)
    try:
        from pySim.esim import compile_asn1_subdir
    except ModuleNotFoundError as import_error:
        # ``pysim/`` is an optional on-disk upstream checkout (gitignored)
        # that source trees and installed wheels alike may not have.
        # Tests that need the SAIP ASN.1 schema should be skipped rather
        # than fail hard, matching the WARN behaviour of
        # ``yggdrasim --doctor``.
        raise unittest.SkipTest(
            f"pySim not available; SAIP fixture build requires the optional pysim/ checkout "
            f"(clone https://gitlab.com/osmocom/pysim.git into {pysim_root}). "
            f"Underlying error: {import_error.name}."
        )

    _SAIP_ASN1 = compile_asn1_subdir("saip")
    return _SAIP_ASN1


def build_minimal_saip_upp(*, iccid: str, imsi: str, impi: str, profile_name: str) -> bytes:
    saip_asn1 = compile_saip_asn1()
    profile_elements = [
        (
            "header",
            {
                "major-version": 2,
                "minor-version": 3,
                "profileType": profile_name,
                "iccid": bytes.fromhex(iccid),
                "eUICC-Mandatory-services": {"usim": None, "isim": None},
                "eUICC-Mandatory-GFSTEList": [
                    "2.23.143.1.2.1",
                    "2.23.143.1.2.4.2",
                    "2.23.143.1.2.8",
                ],
            },
        ),
        (
            "mf",
            {
                "mf-header": {"mandated": None, "identification": 2},
                "templateID": "2.23.143.1.2.1",
                "mf": [],
                "ef-iccid": [("fillFileContent", encode_iccid_ef(iccid))],
                "ef-dir": [],
                "ef-arr": [],
            },
        ),
        (
            "usim",
            {
                "usim-header": {"mandated": None, "identification": 3},
                "templateID": "2.23.143.1.2.4.2",
                "adf-usim": [],
                "ef-imsi": [("fillFileContent", encode_imsi_ef(imsi))],
                "ef-arr": [],
                "ef-ust": [],
                "ef-spn": [],
                "ef-est": [],
                "ef-acc": [],
                "ef-ecc": [],
            },
        ),
        (
            "isim",
            {
                "isim-header": {"mandated": None, "identification": 4},
                "templateID": "2.23.143.1.2.8",
                "adf-isim": [],
                "ef-impi": [("fillFileContent", impi.encode("utf-8"))],
                "ef-impu": [],
                "ef-domain": [],
                "ef-ist": [],
                "ef-arr": [],
            },
        ),
        ("end", {"end-header": {"mandated": None, "identification": 5}}),
    ]
    return b"".join(saip_asn1.encode("ProfileElement", element) for element in profile_elements)


def read_tlv(data: bytes, offset: int = 0) -> tuple[bytes, bytes, bytes, int]:
    if offset >= len(data):
        raise ValueError("TLV offset out of range.")
    tag_start = offset
    offset += 1
    if data[tag_start] & 0x1F == 0x1F:
        while offset < len(data):
            current = data[offset]
            offset += 1
            if current & 0x80 == 0:
                break
    tag_bytes = data[tag_start:offset]
    first = data[offset]
    if first < 0x80:
        length = first
        length_size = 1
    else:
        count = first & 0x7F
        length = int.from_bytes(data[offset + 1 : offset + 1 + count], "big")
        length_size = 1 + count
    value_start = offset + length_size
    value_end = value_start + length
    return tag_bytes, data[value_start:value_end], data[tag_start:value_end], value_end


def find_first_tlv(data: bytes, target_tag: bytes | str) -> bytes:
    target = bytes.fromhex(target_tag) if isinstance(target_tag, str) else bytes(target_tag)
    offset = 0
    while offset < len(data):
        tag_bytes, value, raw_tlv, next_offset = read_tlv(data, offset)
        if tag_bytes == target:
            return raw_tlv
        if tag_bytes[0] & 0x20:
            nested = find_first_tlv(value, target)
            if len(nested) > 0:
                return nested
        offset = next_offset
    return b""


def extract_nested_tlv_value(data: bytes, parent_tag: bytes | str, child_tag: bytes | str) -> bytes:
    parent_raw = find_first_tlv(data, parent_tag)
    if len(parent_raw) == 0:
        return b""
    _, parent_value, _, _ = read_tlv(parent_raw, 0)
    child_raw = find_first_tlv(parent_value, child_tag)
    if len(child_raw) == 0:
        return b""
    _, child_value, _, _ = read_tlv(child_raw, 0)
    return child_value


def extract_euicc_challenge(response: bytes | list[int]) -> bytes:
    """Unwrap the BF2E/80 envelope emitted by ES10b.GetEUICCChallenge."""
    blob = bytes(response)
    return extract_nested_tlv_value(blob, "BF2E", "80")


def send_store_data_payload(connection, payload: bytes, chunk_size: int = 120) -> tuple[bytes, int, int]:
    response = (b"", 0x6F, 0x00)
    offset = 0
    block = 0
    while offset < len(payload):
        chunk = payload[offset : offset + chunk_size]
        offset += len(chunk)
        p1 = 0x91 if offset >= len(payload) else 0x11
        apdu = bytes([0x80, 0xE2, p1, block & 0xFF, len(chunk)]) + chunk
        response = connection.transmit(list(apdu))
        block += 1
    return bytes(response[0]), int(response[1]), int(response[2])


def authenticate_scp03(connection) -> Scp03Session:
    select_apdu = bytes.fromhex(f"00A4040010{ISDR_AID}")
    data, sw1, sw2 = connection.transmit(list(select_apdu))
    if (sw1, sw2) != (0x90, 0x00):
        raise AssertionError(f"SELECT failed: {sw1:02X}{sw2:02X} data={bytes(data).hex().upper()}")

    host_challenge = bytes.fromhex("0102030405060708")
    init_apdu = bytes.fromhex(f"8050300008{host_challenge.hex()}")
    data, sw1, sw2 = connection.transmit(list(init_apdu))
    if (sw1, sw2) != (0x90, 0x00):
        raise AssertionError(f"INITIALIZE UPDATE failed: {sw1:02X}{sw2:02X}")

    session = Scp03Session(
        {
            "kenc": bytes.fromhex(Config.DEFAULT_KEYS["scp03_kenc"]),
            "kmac": bytes.fromhex(Config.DEFAULT_KEYS["scp03_kmac"]),
            "dek": bytes.fromhex(Config.DEFAULT_KEYS["scp03_dek"]),
        }
    )
    session.sec_level = 0x33
    session.derive_keys(host_challenge, bytes(data))
    host_crypto = session.calculate_host_cryptogram()
    header = bytes([0x84, 0x82, 0x33, 0x00, 0x10])
    c_mac = cmac.CMAC(algorithms.AES(session.s_mac))
    c_mac.update(session.chaining_value + header + host_crypto)
    full_mac = c_mac.finalize()
    session.chaining_value = full_mac

    ext_auth_apdu = header + host_crypto + full_mac[:8]
    data, sw1, sw2 = connection.transmit(list(ext_auth_apdu))
    if (sw1, sw2) != (0x90, 0x00):
        raise AssertionError(f"EXTERNAL AUTH failed: {sw1:02X}{sw2:02X}")

    session.ssc = 1
    session.is_authenticated = True
    return session


def transmit_wrapped(connection, session: Scp03Session, apdu_hex: str) -> tuple[bytes, int, int]:
    wrapped = session.wrap_apdu(list(bytes.fromhex(apdu_hex)))
    data, sw1, sw2 = connection.transmit(list(wrapped))
    return session.unwrap_response(bytes(data), sw1, sw2), sw1, sw2


def build_self_signed_cert_and_key(common_name: str) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER), private_key


def load_local_sgp26_auth_and_pb_material() -> tuple[
    bytes,
    ec.EllipticCurvePrivateKey,
    bytes,
    ec.EllipticCurvePrivateKey,
]:
    cert_root = (
        Path(__file__).resolve().parent.parent
        / "SCP11"
        / "SGP.26_test_Certs"
        / "Valid Test Cases"
        / "Variant O"
        / "SM-DP+"
    )
    # Operator workstations may have applied envelope encryption (gpg) to
    # the SGP.26 reference material. read_secret_file_bytes transparently
    # decrypts PGP-wrapped payloads for both the CERT_*.der and SK_*.pem
    # files, so the helper works the same on a stock checkout and on a
    # secret-encrypted checkout.
    from yggdrasim_common.inventory_crypto import read_secret_file_bytes

    auth_cert_der = read_secret_file_bytes(cert_root / "SM_DPauth" / "CERT_S_SM_DPauth_VARO_SIG_NIST.der")
    auth_key = serialization.load_pem_private_key(
        read_secret_file_bytes(cert_root / "SM_DPauth" / "SK_S_SM_DPauth_SIG_NIST.pem"),
        password=None,
    )
    pb_cert_der = read_secret_file_bytes(cert_root / "SM_DPpb" / "CERT_S_SM_DPpb_VARO_SIG_NIST.der")
    pb_key = serialization.load_pem_private_key(
        read_secret_file_bytes(cert_root / "SM_DPpb" / "SK_S_SM_DPpb_SIG_NIST.pem"),
        password=None,
    )
    if isinstance(auth_key, ec.EllipticCurvePrivateKey) is False:
        raise TypeError("Expected SGP.26 auth key to be an EC private key.")
    if isinstance(pb_key, ec.EllipticCurvePrivateKey) is False:
        raise TypeError("Expected SGP.26 PB key to be an EC private key.")
    return auth_cert_der, auth_key, pb_cert_der, pb_key


def ecdsa_raw_signature(private_key: ec.EllipticCurvePrivateKey, payload: bytes) -> bytes:
    signature_der = private_key.sign(bytes(payload), ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(signature_der)
    return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")


def verify_raw_ecdsa_signature(
    certificate: crypto_x509.Certificate,
    payload: bytes,
    raw_signature: bytes,
) -> None:
    signature_der = encode_dss_signature(
        int.from_bytes(raw_signature[:32], "big"),
        int.from_bytes(raw_signature[32:], "big"),
    )
    certificate.public_key().verify(signature_der, bytes(payload), ec.ECDSA(hashes.SHA256()))


def build_authenticate_server_payload(
    *,
    transaction_id: bytes,
    euicc_challenge: bytes,
    server_address: str,
    server_challenge: bytes,
    cert_der: bytes,
    cert_private_key: ec.EllipticCurvePrivateKey,
    root_ci_id: bytes = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3"),
    ctx_params: bytes | None = None,
    signature_override: bytes | None = None,
) -> bytes:
    server_signed1 = wrap_tlv(
        b"\x30",
        wrap_tlv(b"\x80", bytes(transaction_id))
        + wrap_tlv(b"\x81", bytes(euicc_challenge))
        + wrap_tlv(b"\x83", server_address.encode("utf-8"))
        + wrap_tlv(b"\x84", bytes(server_challenge)),
    )
    signature = (
        bytes(signature_override)
        if signature_override is not None
        else ecdsa_raw_signature(cert_private_key, server_signed1)
    )
    body = server_signed1 + wrap_tlv("5F37", signature)
    if len(bytes(root_ci_id)) > 0:
        body += wrap_tlv(b"\x04", bytes(root_ci_id))
    body += bytes(cert_der)
    if ctx_params is not None and len(bytes(ctx_params)) > 0:
        body += bytes(ctx_params)
    return wrap_tlv("BF38", body)


def build_prepare_download_payload(
    *,
    transaction_id: bytes,
    euicc_signature1: bytes,
    cert_der: bytes,
    cert_private_key: ec.EllipticCurvePrivateKey,
    smdp_signed2_raw: bytes | None = None,
    signature_override: bytes | None = None,
) -> bytes:
    signed2 = (
        bytes(smdp_signed2_raw)
        if smdp_signed2_raw is not None and len(bytes(smdp_signed2_raw)) > 0
        else wrap_tlv(b"\x30", wrap_tlv(b"\x80", bytes(transaction_id)) + b"\x01\x01\x00")
    )
    signed_material = signed2 + wrap_tlv("5F37", bytes(euicc_signature1))
    signature = (
        bytes(signature_override)
        if signature_override is not None
        else ecdsa_raw_signature(cert_private_key, signed_material)
    )
    return wrap_tlv("BF21", signed2 + wrap_tlv("5F37", signature) + bytes(cert_der))


def build_signed_bpp_segments(
    *,
    transaction_id: bytes,
    euicc_otpk_raw: bytes,
    eid_hex: str,
    cert_private_key: ec.EllipticCurvePrivateKey,
    iccid: str,
    provider_name: str,
    profile_name: str,
    imsi: str = "1234567812345678",
    impi: str = "user@install.test",
    upp_payload: bytes | None = None,
    a3_plaintext_chunk_size: int | None = None,
) -> dict[str, bytes | list[bytes]]:
    host_id = b"SIMHOST01"
    smdp_ot_private = ec.generate_private_key(ec.SECP256R1())
    smdp_otpk = smdp_ot_private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    remote_op_id_raw = wrap_tlv(b"\x82", b"\x01")
    transaction_id_raw = wrap_tlv(b"\x80", transaction_id)
    control_ref_inner = wrap_tlv(b"\x80", b"\x88") + wrap_tlv(b"\x81", b"\x10") + wrap_tlv(b"\x84", host_id)
    control_ref_raw = wrap_tlv(b"\xA6", control_ref_inner)
    smdp_otpk_raw = wrap_tlv("5F49", smdp_otpk)
    signed_data = remote_op_id_raw + transaction_id_raw + control_ref_raw + smdp_otpk_raw + euicc_otpk_raw
    bf23_signature = ecdsa_raw_signature(cert_private_key, signed_data)
    bootstrap = wrap_tlv(
        "BF36",
        wrap_tlv(
            "BF23",
            remote_op_id_raw
            + transaction_id_raw
            + control_ref_raw
            + smdp_otpk_raw
            + wrap_tlv("5F37", bf23_signature),
        ),
    )

    _, euicc_otpk, _, _ = read_tlv(euicc_otpk_raw, 0)
    euicc_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), euicc_otpk)
    shared_secret = smdp_ot_private.exchange(ec.ECDH(), euicc_public)
    bsp = BspInstance.from_kdf(shared_secret, 0x88, 16, host_id, bytes.fromhex(eid_hex))

    configure_isdp = wrap_tlv("BF24", b"")
    a0 = bsp.encrypt_and_mac_one(0x87, configure_isdp)

    store_metadata = wrap_tlv(
        "BF25",
        wrap_tlv("5A", encode_iccid_ef(iccid))
        + wrap_tlv("91", provider_name.encode("utf-8"))
        + wrap_tlv("92", profile_name.encode("utf-8"))
        + wrap_tlv("95", b"\x02"),
    )
    a1 = bsp.mac_only_one(0x88, store_metadata)

    if upp_payload is None:
        upp_payload = build_minimal_saip_upp(
            iccid=iccid,
            imsi=imsi,
            impi=impi,
            profile_name=profile_name,
        )
    a3_members: list[bytes] = []
    if a3_plaintext_chunk_size is None or int(a3_plaintext_chunk_size) <= 0:
        a3_members.append(bsp.encrypt_and_mac_one(0x86, upp_payload))
    else:
        remainder = bytes(upp_payload)
        while len(remainder) > 0:
            chunk = remainder[: int(a3_plaintext_chunk_size)]
            remainder = remainder[int(a3_plaintext_chunk_size) :]
            a3_members.append(bsp.encrypt_and_mac_one(0x86, chunk))
    a3 = b"".join(a3_members)

    return {
        "bootstrap": bootstrap,
        "a0": a0,
        "a1": a1,
        "a3": a3,
        "a3_members": a3_members,
    }


def parse_profile_install_result(raw_response: bytes) -> tuple[int | None, int | None]:
    a2_raw = find_first_tlv(raw_response, "A2")
    if len(a2_raw) == 0:
        return None, None
    _, a2_value, _, _ = read_tlv(a2_raw, 0)
    final_raw = find_first_tlv(a2_value, "A0")
    if len(final_raw) == 0:
        final_raw = find_first_tlv(a2_value, "A1")
    if len(final_raw) == 0:
        return None, None
    _, final_value, _, _ = read_tlv(final_raw, 0)
    result_code = None
    result_detail = None
    offset = 0
    while offset < len(final_value):
        tag, value, _, next_offset = read_tlv(final_value, offset)
        if tag == b"\x80":
            result_code = int.from_bytes(value, "big")
        elif tag == b"\x81":
            result_detail = int.from_bytes(value, "big")
        offset = next_offset
    return result_code, result_detail


class SimulatedConnectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                SIM_EIM_IDENTITY_ENV: "",
                SIM_EUICC_STORE_ENV: str(Path(self._temp_dir.name) / "euicc"),
                SIM_ISDR_CONFIG_ENV: str(Path(self._temp_dir.name) / "missing_isdr_config.json"),
                SIM_PROFILE_STORE_ENV: str(Path(self._temp_dir.name) / "profiles"),
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._temp_dir.cleanup()

    def test_sgp_replace_session_keys_parser_accepts_context_specific_fields(self) -> None:
        engine = SimulatedSimCardEngine()
        initial_mcv = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        ppk_enc = bytes.fromhex("101112131415161718191A1B1C1D1E1F")
        ppk_cmac = bytes.fromhex("202122232425262728292A2B2C2D2E2F")
        payload = wrap_tlv(
            "BF26",
            wrap_tlv(b"\x80", initial_mcv) + wrap_tlv(b"\x81", ppk_enc) + wrap_tlv(b"\x82", ppk_cmac),
        )

        parsed = engine.sgp._parse_replace_session_keys_request(payload)

        self.assertEqual(parsed["initialMacChainingValue"], initial_mcv)
        self.assertEqual(parsed["ppkEnc"], ppk_enc)
        self.assertEqual(parsed["ppkCmac"], ppk_cmac)

    def test_simulated_connection_supports_basic_fs_and_sgp_reads(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("00A40004022FE2")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(bytes(data).startswith(bytes.fromhex("62")))
            self.assertIn(bytes.fromhex("83022FE2"), bytes(data))

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("00B000000A")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bytes(data).hex().upper(), "98881111111111111121")

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("00A40004022F00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("00B2010400")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertIn(bytes.fromhex("4F10A0000000871002FF86FF112233445566"), bytes(data))

            data, sw1, sw2 = connection.transmit(
                list(bytes.fromhex("00A4040010A0000005591010FFFFFFFF8900000200"))
            )
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("80CA005A00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(
                bytes(data).hex().upper(),
                "5A1089045967676472615349763031303005",
            )

            data, sw1, sw2 = connection.transmit(
                list(bytes.fromhex("00A4040010A0000005591010FFFFFFFF8900000100"))
            )
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2D00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(bytes(data).startswith(bytes.fromhex("BF2D")))
            self.assertIn(bytes.fromhex("4F10A0000005591010FFFFFFFF8900001100"), bytes(data))

    def test_simulated_connection_rejects_authenticate_server_with_invalid_signature(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            cert_der, cert_private_key = build_self_signed_cert_and_key("Invalid Signature DPauth")
            auth_payload = build_authenticate_server_payload(
                transaction_id=bytes.fromhex("0102030405060708090A0B0C0D0E0F10"),
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x55" * 16,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
                ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
                signature_override=b"\xAA" * 64,
            )

            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(auth_response, bytes.fromhex("BF3805A103800103"))

    def test_simulated_connection_rejects_prepare_download_with_invalid_signature(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            transaction_id = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
            cert_der, cert_private_key = build_self_signed_cert_and_key("Prepare Signature DPauth")
            auth_payload = build_authenticate_server_payload(
                transaction_id=transaction_id,
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x66" * 16,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
                ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
            )
            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)

            prepare_payload = build_prepare_download_payload(
                transaction_id=transaction_id,
                euicc_signature1=euicc_signature1,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
                signature_override=b"\x99" * 64,
            )
            prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(prepare_response, bytes.fromhex("BF2105A103800102"))

    def test_simulated_connection_rejects_prepare_download_with_certificate_mismatch(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            transaction_id = bytes.fromhex("102132435465768798A9BACBDCEDFE0F")
            auth_cert_der, auth_private_key = build_self_signed_cert_and_key("Prepare Match DPauth")
            auth_payload = build_authenticate_server_payload(
                transaction_id=transaction_id,
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x77" * 16,
                cert_der=auth_cert_der,
                cert_private_key=auth_private_key,
                ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
            )
            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)

            other_cert_der, other_private_key = build_self_signed_cert_and_key("Prepare Mismatch DPpb")
            prepare_payload = build_prepare_download_payload(
                transaction_id=transaction_id,
                euicc_signature1=euicc_signature1,
                cert_der=other_cert_der,
                cert_private_key=other_private_key,
            )
            prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(prepare_response, bytes.fromhex("BF2105A103800101"))

    def test_simulated_connection_accepts_local_smdpp_auth_and_pb_certificate_pair(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            transaction_id = bytes.fromhex("2031425364758697A8B9CADBECFD0E1F")
            auth_cert_der, auth_private_key, pb_cert_der, pb_private_key = (
                load_local_sgp26_auth_and_pb_material()
            )
            auth_payload = build_authenticate_server_payload(
                transaction_id=transaction_id,
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x55" * 16,
                cert_der=auth_cert_der,
                cert_private_key=auth_private_key,
                ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
            )
            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)

            prepare_payload = build_prepare_download_payload(
                transaction_id=transaction_id,
                euicc_signature1=euicc_signature1,
                cert_der=pb_cert_der,
                cert_private_key=pb_private_key,
            )
            prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(prepare_response.startswith(bytes.fromhex("BF21")))
            self.assertGreater(len(find_first_tlv(prepare_response, "5F49")), 0)

    def test_simulated_connection_emits_verifiable_card_cert_chain_and_signatures(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            eid_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF3E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            eid_text = extract_nested_tlv_value(bytes(eid_response), "BF3E", "5A").hex().upper()

            transaction_id = bytes.fromhex("31425364758697A8B9CADBECFD0E1F20")
            auth_cert_der, auth_private_key, pb_cert_der, pb_private_key = (
                load_local_sgp26_auth_and_pb_material()
            )
            auth_payload = build_authenticate_server_payload(
                transaction_id=transaction_id,
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x33" * 16,
                cert_der=auth_cert_der,
                cert_private_key=auth_private_key,
                ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
            )
            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            _, auth_outer_value, _, _ = read_tlv(auth_response, 0)
            ok_tag, ok_value, _, _ = read_tlv(auth_outer_value, 0)
            self.assertEqual(ok_tag, b"\xA0")
            euicc_signed1_tag, _, euicc_signed1_raw, offset = read_tlv(ok_value, 0)
            self.assertEqual(euicc_signed1_tag, b"\x30")
            signature_tag, euicc_signature1, _, offset = read_tlv(ok_value, offset)
            self.assertEqual(signature_tag, bytes.fromhex("5F37"))
            euicc_certificate_tag, _, euicc_certificate_der, offset = read_tlv(ok_value, offset)
            self.assertEqual(euicc_certificate_tag, b"\x30")
            eum_certificate_tag, _, eum_certificate_der, offset = read_tlv(ok_value, offset)
            self.assertEqual(eum_certificate_tag, b"\x30")
            self.assertEqual(offset, len(ok_value))

            root_certificate = crypto_x509.load_pem_x509_certificate(
                (Path(__file__).resolve().parent.parent / "SCP11" / "ES9_TEST_CI_CA.pem").read_bytes()
            )
            eum_certificate = crypto_x509.load_der_x509_certificate(eum_certificate_der)
            euicc_certificate = crypto_x509.load_der_x509_certificate(euicc_certificate_der)

            root_certificate.public_key().verify(
                eum_certificate.signature,
                eum_certificate.tbs_certificate_bytes,
                ec.ECDSA(eum_certificate.signature_hash_algorithm),
            )
            eum_certificate.public_key().verify(
                euicc_certificate.signature,
                euicc_certificate.tbs_certificate_bytes,
                ec.ECDSA(euicc_certificate.signature_hash_algorithm),
            )
            verify_raw_ecdsa_signature(euicc_certificate, euicc_signed1_raw, euicc_signature1)
            self.assertEqual(
                euicc_certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value,
                eid_text,
            )

            name_constraints = eum_certificate.extensions.get_extension_for_oid(
                ExtensionOID.NAME_CONSTRAINTS
            ).value
            self.assertIsNotNone(name_constraints.permitted_subtrees)
            self.assertTrue(
                any(
                    isinstance(subtree, crypto_x509.DirectoryName)
                    and any(
                        attribute.oid == NameOID.SERIAL_NUMBER and attribute.value == eid_text[:8]
                        for attribute in subtree.value
                    )
                    for subtree in name_constraints.permitted_subtrees or []
                )
            )

            prepare_payload = build_prepare_download_payload(
                transaction_id=transaction_id,
                euicc_signature1=euicc_signature1,
                cert_der=pb_cert_der,
                cert_private_key=pb_private_key,
            )
            prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            _, prepare_outer_value, _, _ = read_tlv(prepare_response, 0)
            ok_tag, ok_value, _, _ = read_tlv(prepare_outer_value, 0)
            self.assertEqual(ok_tag, b"\xA0")
            euicc_signed2_tag, _, euicc_signed2_raw, offset = read_tlv(ok_value, 0)
            self.assertEqual(euicc_signed2_tag, b"\x30")
            signature_tag, euicc_signature2, _, offset = read_tlv(ok_value, offset)
            self.assertEqual(signature_tag, bytes.fromhex("5F37"))
            self.assertEqual(offset, len(ok_value))

            verify_raw_ecdsa_signature(
                euicc_certificate,
                euicc_signed2_raw + find_first_tlv(prepare_payload, "5F37"),
                euicc_signature2,
            )

    def test_simulated_engine_applies_isdr_config_file_to_runtime_identity(self) -> None:
        custom_isdr_aid = "A0000005591010FFFFFFFF89000001AA"
        config_path = Path(self._temp_dir.name) / "isdr_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "eid": "89044045930000000000001492294499",
                    "default_dp_address": "rsp.isdr-config.test",
                    "isdr": {"aid": custom_isdr_aid, "label": "ISDR-CFG"},
                    "scp03_keys": {
                        "kenc_hex": "0102030405060708090A0B0C0D0E0F10",
                        "kmac_hex": "1112131415161718191A1B1C1D1E1F20",
                        "dek_hex": "2122232425262728292A2B2C2D2E2F30",
                        "kvn": 0x31,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )

        engine = SimulatedSimCardEngine(
            isdr_config_path=str(config_path),
            euicc_store_root=str(Path(self._temp_dir.name) / "euicc"),
            profile_store_path=str(Path(self._temp_dir.name) / "profiles"),
        )

        self.assertEqual(engine.state.eid, "89044045930000000000001492294499")
        self.assertEqual(engine.state.default_dp_address, "rsp.isdr-config.test")
        self.assertEqual(engine.state.isdr_aid, custom_isdr_aid)
        self.assertEqual(engine.state.isdr_label, "ISDR-CFG")
        self.assertEqual(engine.state.scp03_keys.kvn, 0x31)

        data, sw1, sw2 = engine.fs.select(bytes.fromhex(custom_isdr_aid))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        data, sw1, sw2 = engine.fs.select(bytes.fromhex(ISDR_AID))
        self.assertEqual((sw1, sw2), (0x6A, 0x82))

        status_data, sw1, sw2 = engine.gp.handle_get_status(0x80, 0x00, b"")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertIn(bytes.fromhex(custom_isdr_aid), status_data)
        self.assertNotIn(bytes.fromhex(ISDR_AID), status_data)

        init_data, sw1, sw2 = engine.scp03.handle_initialize_update(
            0x31,
            bytes.fromhex("0102030405060708"),
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(init_data[10], 0x31)

    def test_simulated_connection_supports_real_scp03_secure_channel(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)
            session = authenticate_scp03(connection)

            data, sw1, sw2 = transmit_wrapped(connection, session, "80CA00E000")
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertIn(bytes.fromhex("C00401308810"), data)
            self.assertIn(bytes.fromhex("C00402308810"), data)
            self.assertIn(bytes.fromhex("C00403308810"), data)

            data, sw1, sw2 = transmit_wrapped(connection, session, "80F28000024F00")
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertIn(bytes.fromhex(ISDR_AID), data)
            self.assertIn(bytes.fromhex(ECASD_AID), data)

    def test_simulated_connection_surfaces_richer_metadata_payloads(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            info1_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2000")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            info1_summary = decode_euicc_info1_summary(bytes(info1_response))
            self.assertEqual(info1_summary["svn"], "v2.6.0 (020600)")
            self.assertGreaterEqual(info1_summary["ci_pk_verify_entries"], 1)
            self.assertGreaterEqual(info1_summary["ci_pk_sign_entries"], 1)

            info2_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2200")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            detail_lines = build_euicc_info2_detail_lines(bytes(info2_response))
            validation_lines = build_euicc_info2_validation_lines(bytes(info2_response))
            self.assertTrue(any(label == "IPA Mode" for _, label, _ in detail_lines))
            self.assertTrue(any(label == "IoT Specific Info" for _, label, _ in detail_lines))
            self.assertTrue(
                any(label == "SGP.32 Validation" and value == "PASS" for _, label, value in validation_lines)
            )

            configured_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF3C00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertIn(b"rsp.example.com", bytes(configured_response))
            self.assertIn(b"lpa.ds.gsma.com", bytes(configured_response))
            self.assertGreater(len(find_first_tlv(bytes(configured_response), "83")), 0)
            self.assertGreater(len(find_first_tlv(bytes(configured_response), "A4")), 0)

            eim_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5500")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            entries = decode_eim_configuration_entries(bytes(eim_response))
            self.assertGreaterEqual(len(entries), 1)
            first_entry = entries[0]
            self.assertEqual(first_entry["eim_id"], "2.25.311782205282738360923618091971140414400")
            self.assertEqual(first_entry["eim_fqdn"], "eim.example.test")
            self.assertIn("eimRetrieveHttps", first_entry["supported_protocol"])
            self.assertIn("eimInjectHttps", first_entry["supported_protocol"])
            self.assertEqual(
                first_entry["euicc_ci_pkid"],
                "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
            )
            self.assertIn("eim_public_key_data", first_entry)
            self.assertIn("trusted_tls_public_key_data", first_entry)

            certs_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5600")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            certs = decode_get_certs_response(bytes(certs_response))
            self.assertIn("eumCertificate", certs)
            self.assertIn("euiccCertificate", certs)
            self.assertTrue(bytes(certs["eumCertificate"]).startswith(b"\x30"))
            self.assertTrue(bytes(certs["euiccCertificate"]).startswith(b"\x30"))

    def test_simulated_engine_seeds_sim_eim_identity_file_into_workspace(self) -> None:
        runtime_root = Path(self._temp_dir.name) / "runtime"
        euicc_store_root = Path(self._temp_dir.name) / "euicc-seeded"
        identity_path = runtime_root / "Workspace" / "SIMCARD" / "eim_identity.json"
        self.assertFalse(identity_path.exists())

        with mock.patch.dict(
            os.environ,
            {
                CARD_BACKEND_ENV: "sim",
                "YGGDRASIM_RUNTIME_ROOT": str(runtime_root),
            },
            clear=False,
        ):
            engine = SimulatedSimCardEngine(euicc_store_root=str(euicc_store_root))
            self.assertEqual(len(engine.state.eim_entries), 1)

        self.assertTrue(identity_path.exists())
        payload = json.loads(identity_path.read_text(encoding="utf-8"))
        self.assertEqual(
            str(payload.get("eim_id", "")).strip(),
            "2.25.311782205282738360923618091971140414400",
        )
        self.assertEqual(
            str(payload.get("eim_fqdn", "")).strip(),
            "eim.example.test",
        )

    def test_simulated_connection_applies_metadata_overrides_from_quirks_file(self) -> None:
        root_ci_pkid = "00112233445566778899AABBCCDDEEFF00112233"
        atr_hex = "3B8F8001804F0CA000000306030001000000006A"
        eum_certificate_der, _ = build_self_signed_cert_and_key("Override EUM")
        euicc_certificate_der, _ = build_self_signed_cert_and_key("Override eUICC")

        quirks_source = f"""
metadata_overrides = {{
    "atr": "{atr_hex}",
    "default_dp_address": "rsp.override.test",
    "root_ci_pkid": "{root_ci_pkid}",
    "euicc_info": {{
        "info1_svn": "010203",
        "profile_version": "030201",
        "svn": "030201",
        "firmware_version": "040506",
        "globalplatform_version": "020500",
        "pp_version": "040100",
        "ipa_mode": 0,
        "iot_specific_info": {{
            "iot_versions": ["070809"],
            "ecall_supported": True,
            "fallback_supported": True,
        }},
        "rsp_capability_bits": [0, 1],
    }},
    "configured_data": {{
        "root_smds_address": "smds.override.test",
        "additional_root_smds_addresses": ["backup.override.test"],
        "allowed_ci_pkids": ["{root_ci_pkid}"],
        "ci_list": ["{root_ci_pkid}"],
    }},
    "eim_entries": [
        {{
            "eim_id": "manager-override",
            "eim_fqdn": "eim.override.test",
            "eim_id_type": 3,
            "counter_value": 9,
            "association_token": 42,
            "supported_protocol_bits": [0, 4],
            "euicc_ci_pkid": "{root_ci_pkid}",
            "indirect_profile_download": False,
        }}
    ],
    "eum_certificate_der": "{eum_certificate_der.hex()}",
    "euicc_certificate_der": "{euicc_certificate_der.hex()}",
}}
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            quirks_path = Path(temp_dir) / "sim_metadata_quirks.py"
            quirks_path.write_text(quirks_source, encoding="utf-8")

            with mock.patch.dict(
                os.environ,
                {CARD_BACKEND_ENV: "sim", SIM_QUIRKS_ENV: str(quirks_path)},
                clear=False,
            ):
                connection = create_card_connection(reader_index=0)
                self.assertEqual(bytes(connection.getATR()).hex().upper(), atr_hex)

                data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                info1_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2000")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                info1_summary = decode_euicc_info1_summary(bytes(info1_response))
                self.assertEqual(info1_summary["svn"], "v1.2.3 (010203)")
                self.assertIn(bytes.fromhex(root_ci_pkid), bytes(info1_response))

                info2_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2200")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                detail_lines = build_euicc_info2_detail_lines(bytes(info2_response))
                self.assertTrue(
                    any(label == "IPA Mode" and "ipad" in value for _, label, value in detail_lines)
                )
                self.assertIn(bytes.fromhex(root_ci_pkid), bytes(info2_response))

                configured_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF3C00")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertIn(b"rsp.override.test", bytes(configured_response))
                self.assertIn(b"smds.override.test", bytes(configured_response))
                self.assertIn(b"backup.override.test", bytes(configured_response))
                self.assertIn(bytes.fromhex(root_ci_pkid), bytes(configured_response))

                eim_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5500")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                entries = decode_eim_configuration_entries(bytes(eim_response))
                self.assertEqual(len(entries), 1)
                self.assertEqual(entries[0]["eim_id"], "manager-override")
                self.assertEqual(entries[0]["eim_fqdn"], "eim.override.test")
                self.assertEqual(entries[0]["eim_id_type"], "eimIdTypeProprietary (3)")
                self.assertEqual(entries[0]["counter_value"], "9")
                self.assertEqual(entries[0]["association_token"], "42")
                self.assertIn("eimRetrieveHttps", entries[0]["supported_protocol"])
                self.assertIn("eimProprietary", entries[0]["supported_protocol"])
                self.assertEqual(entries[0]["euicc_ci_pkid"], root_ci_pkid)
                self.assertNotIn("indirect_profile_download", entries[0])

                certs_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5600")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                certs = decode_get_certs_response(bytes(certs_response))
                self.assertEqual(bytes(certs["eumCertificate"]), eum_certificate_der)
                self.assertEqual(bytes(certs["euiccCertificate"]), euicc_certificate_der)

    def test_simulated_connection_add_eim_persists_new_bf55_row(self) -> None:
        root_ci_pkid = "F54172BDF98A95D65CBEB88A38A1C11D800A85C3"
        target_eim_id = "2.25.123456789012345678901234567890123456"
        eim_certificate_der, _ = build_self_signed_cert_and_key("Simulator Added eIM")
        tls_certificate_der, _ = build_self_signed_cert_and_key("Simulator Added eIM TLS")

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(
                os.environ,
                {CARD_BACKEND_ENV: "sim", SIM_EUICC_STORE_ENV: temp_dir},
                clear=False,
            ):
                connection = create_card_connection(reader_index=0)
                data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                add_payload = build_add_eim_command_payload(
                    "BF58",
                    eim_id=target_eim_id,
                    eim_fqdn="added.eim.local",
                    eim_id_type=1,
                    counter_value=7,
                    association_token=42,
                    supported_protocol_bits=[0],
                    euicc_ci_pkid_hex=root_ci_pkid,
                    indirect_profile_download=True,
                    eim_certificate_der=eim_certificate_der,
                    trusted_tls_certificate_der=tls_certificate_der,
                )
                add_response, sw1, sw2 = send_store_data_payload(connection, add_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(add_response, bytes.fromhex("BF5800"))

                eim_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5500")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                entries = decode_eim_configuration_entries(bytes(eim_response))
                matching_entries = [entry for entry in entries if entry.get("eim_id") == target_eim_id]
                self.assertEqual(len(matching_entries), 1)
                entry = matching_entries[0]
                self.assertEqual(entry["eim_fqdn"], "added.eim.local")
                self.assertEqual(entry["counter_value"], "7")
                self.assertEqual(entry["association_token"], "42")
                self.assertIn("eimRetrieveHttps", entry["supported_protocol"])
                self.assertEqual(entry["euicc_ci_pkid"], root_ci_pkid)
                self.assertEqual(entry["indirect_profile_download"], "Present")

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            persisted_entries = [
                entry for entry in recreated_engine.state.eim_entries if entry.eim_id == target_eim_id
            ]
            self.assertEqual(len(persisted_entries), 1)
            persisted = persisted_entries[0]
            self.assertEqual(persisted.eim_fqdn, "added.eim.local")
            self.assertEqual(persisted.counter_value, 7)
            self.assertEqual(persisted.association_token, 42)
            self.assertEqual(persisted.supported_protocol_bits, [0])
            self.assertEqual(persisted.euicc_ci_pkid.hex().upper(), root_ci_pkid)
            self.assertTrue(persisted.indirect_profile_download)
            self.assertTrue(bytes(persisted.eim_public_key_data).startswith(bytes.fromhex("A1")))
            self.assertTrue(bytes(persisted.trusted_tls_public_key_data).startswith(bytes.fromhex("A1")))

    def test_simulated_engine_default_eim_row_follows_sim_eim_identity_file(self) -> None:
        target_eim_id = "local-eim-manager"
        target_fqdn = "local.eim.identity.test"
        root_ci_pkid = "11223344556677889900AABBCCDDEEFF00112233"
        signer_certificate_der, _ = build_self_signed_cert_and_key("Local Identity Signer")
        tls_certificate_der, _ = build_self_signed_cert_and_key("Local Identity TLS")

        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            euicc_store_root = Path(temp_dir) / "euicc"
            write_sim_eim_identity(
                runtime_root,
                eim_id=target_eim_id,
                eim_fqdn=target_fqdn,
                eim_id_type="proprietary",
                euicc_ci_pk_id=root_ci_pkid,
                eim_public_key_cert_der=signer_certificate_der,
                trusted_tls_cert_der=tls_certificate_der,
            )

            with mock.patch.dict(
                os.environ,
                {
                    CARD_BACKEND_ENV: "sim",
                    SIM_EUICC_STORE_ENV: str(euicc_store_root),
                    "YGGDRASIM_RUNTIME_ROOT": str(runtime_root),
                },
                clear=False,
            ):
                engine = SimulatedSimCardEngine(euicc_store_root=str(euicc_store_root))
                self.assertEqual(len(engine.state.eim_entries), 1)
                entry = engine.state.eim_entries[0]
                self.assertEqual(entry.eim_id, target_eim_id)
                self.assertEqual(entry.eim_fqdn, target_fqdn)
                self.assertEqual(entry.eim_id_type, 3)
                self.assertEqual(entry.counter_value, 1)
                self.assertEqual(entry.association_token, 16)
                self.assertEqual(entry.supported_protocol_bits, [0, 2])
                self.assertEqual(entry.euicc_ci_pkid.hex().upper(), root_ci_pkid)
                self.assertTrue(entry.indirect_profile_download)
                self.assertEqual(bytes(entry.eim_public_key_data), signer_certificate_der)
                self.assertEqual(bytes(entry.trusted_tls_public_key_data), tls_certificate_der)

                data, sw1, sw2 = engine.transmit(bytes.fromhex(f"00A4040010{ISDR_AID}"))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                eim_response, sw1, sw2 = engine.transmit(bytes.fromhex("80E2910003BF5500"))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                entries = decode_eim_configuration_entries(bytes(eim_response))
                self.assertEqual(len(entries), 1)
                self.assertEqual(entries[0]["eim_id"], target_eim_id)
                self.assertEqual(entries[0]["eim_fqdn"], target_fqdn)
                self.assertEqual(entries[0]["eim_id_type"], "eimIdTypeProprietary (3)")
                self.assertEqual(entries[0]["euicc_ci_pkid"], root_ci_pkid)

    def test_simulated_engine_default_eim_row_prefers_override_path_over_workspace_default(self) -> None:
        workspace_eim_id = "workspace-eim-manager"
        override_eim_id = "real-eim-manager"
        override_fqdn = "real.eim.example"
        override_pkid = "223344556677889900AABBCCDDEEFF0011223344"

        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            euicc_store_root = Path(temp_dir) / "euicc"
            write_sim_eim_identity(
                runtime_root,
                eim_id=workspace_eim_id,
                eim_fqdn="workspace.eim.identity.test",
            )
            override_identity_path = Path(temp_dir) / "real_eim_identity.json"
            override_identity_path.write_text(
                json.dumps(
                    {
                        "eim_id": override_eim_id,
                        "eim_id_type": "fqdn",
                        "eim_fqdn": override_fqdn,
                        "eim_endpoint": f"https://{override_fqdn}/gsma/rsp2/asn1",
                        "euicc_ci_pk_id": override_pkid,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            with mock.patch.dict(
                os.environ,
                {
                    CARD_BACKEND_ENV: "sim",
                    SIM_EUICC_STORE_ENV: str(euicc_store_root),
                    SIM_EIM_IDENTITY_ENV: str(override_identity_path),
                    "YGGDRASIM_RUNTIME_ROOT": str(runtime_root),
                },
                clear=False,
            ):
                engine = SimulatedSimCardEngine(euicc_store_root=str(euicc_store_root))
                self.assertEqual(len(engine.state.eim_entries), 1)
                entry = engine.state.eim_entries[0]
                self.assertEqual(entry.eim_id, override_eim_id)
                self.assertEqual(entry.eim_fqdn, override_fqdn)
                self.assertEqual(entry.eim_id_type, 2)
                self.assertEqual(entry.euicc_ci_pkid.hex().upper(), override_pkid)

    def test_simulated_connection_add_initial_eim_upserts_existing_row(self) -> None:
        default_eim_id = "2.25.311782205282738360923618091971140414400"
        root_ci_pkid = "F54172BDF98A95D65CBEB88A38A1C11D800A85C3"
        replacement_certificate_der, _ = build_self_signed_cert_and_key("Simulator Replacement eIM")

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(
                os.environ,
                {CARD_BACKEND_ENV: "sim", SIM_EUICC_STORE_ENV: temp_dir},
                clear=False,
            ):
                connection = create_card_connection(reader_index=0)
                data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                add_initial_payload = build_add_eim_command_payload(
                    "BF57",
                    eim_id=default_eim_id,
                    eim_fqdn="updated.eim.local",
                    eim_id_type=1,
                    counter_value=9,
                    association_token=255,
                    supported_protocol_bits=[0, 4],
                    euicc_ci_pkid_hex=root_ci_pkid,
                    indirect_profile_download=False,
                    eim_certificate_der=replacement_certificate_der,
                )
                add_response, sw1, sw2 = send_store_data_payload(connection, add_initial_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(add_response, bytes.fromhex("BF5700"))

                eim_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5500")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                entries = decode_eim_configuration_entries(bytes(eim_response))
                self.assertEqual(len(entries), 1)
                entry = entries[0]
                self.assertEqual(entry["eim_id"], default_eim_id)
                self.assertEqual(entry["eim_fqdn"], "updated.eim.local")
                self.assertEqual(entry["counter_value"], "9")
                self.assertEqual(entry["association_token"], "255")
                self.assertIn("eimRetrieveHttps", entry["supported_protocol"])
                self.assertIn("eimProprietary", entry["supported_protocol"])
                self.assertNotIn("indirect_profile_download", entry)

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            self.assertEqual(len(recreated_engine.state.eim_entries), 1)
            self.assertEqual(recreated_engine.state.eim_entries[0].eim_fqdn, "updated.eim.local")
            self.assertEqual(recreated_engine.state.eim_entries[0].counter_value, 9)
            self.assertEqual(recreated_engine.state.eim_entries[0].association_token, 255)
            self.assertEqual(recreated_engine.state.eim_entries[0].supported_protocol_bits, [0, 4])
            self.assertFalse(recreated_engine.state.eim_entries[0].indirect_profile_download)

    def test_simulated_connection_euicc_memory_reset_restores_sim_eim_identity_default(self) -> None:
        target_eim_id = "reset-local-eim-manager"
        target_fqdn = "reset.local.eim.identity.test"
        root_ci_pkid = "5566778899AABBCCDDEEFF001122334455667788"
        custom_eim_id = "2.25.998877665544332211009988776655443322"
        signer_certificate_der, _ = build_self_signed_cert_and_key("Reset Local Identity Signer")
        tls_certificate_der, _ = build_self_signed_cert_and_key("Reset Local Identity TLS")

        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            euicc_store_root = Path(temp_dir) / "euicc"
            write_sim_eim_identity(
                runtime_root,
                eim_id=target_eim_id,
                eim_fqdn=target_fqdn,
                eim_id_type="proprietary",
                euicc_ci_pk_id=root_ci_pkid,
                eim_public_key_cert_der=signer_certificate_der,
                trusted_tls_cert_der=tls_certificate_der,
            )

            with mock.patch.dict(
                os.environ,
                {
                    CARD_BACKEND_ENV: "sim",
                    SIM_EUICC_STORE_ENV: str(euicc_store_root),
                    "YGGDRASIM_RUNTIME_ROOT": str(runtime_root),
                },
                clear=False,
            ):
                connection = create_card_connection(reader_index=0)
                data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                initial_eim_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5500")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                initial_entries = decode_eim_configuration_entries(bytes(initial_eim_response))
                self.assertEqual(len(initial_entries), 1)
                self.assertEqual(initial_entries[0]["eim_id"], target_eim_id)
                self.assertEqual(initial_entries[0]["eim_fqdn"], target_fqdn)

                delete_default_payload = wrap_tlv("BF59", wrap_tlv("80", target_eim_id.encode("utf-8")))
                delete_response, sw1, sw2 = send_store_data_payload(connection, delete_default_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(delete_response, bytes.fromhex("BF5900"))

                add_payload = build_add_eim_command_payload(
                    "BF58",
                    eim_id=custom_eim_id,
                    eim_fqdn="custom-reset.eim.local",
                    eim_id_type=1,
                    counter_value=3,
                    association_token=12,
                    supported_protocol_bits=[0, 2],
                    euicc_ci_pkid_hex=root_ci_pkid,
                    indirect_profile_download=True,
                )
                add_response, sw1, sw2 = send_store_data_payload(connection, add_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(add_response, bytes.fromhex("BF5800"))

                reset_response, sw1, sw2 = send_store_data_payload(
                    connection,
                    build_euicc_memory_reset_payload(reset_eim_config_data=True),
                )
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(reset_response, bytes.fromhex("BF6400"))

                eim_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5500")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                entries = decode_eim_configuration_entries(bytes(eim_response))
                self.assertEqual(len(entries), 1)
                self.assertEqual(entries[0]["eim_id"], target_eim_id)
                self.assertEqual(entries[0]["eim_fqdn"], target_fqdn)
                self.assertEqual(entries[0]["eim_id_type"], "eimIdTypeProprietary (3)")
                self.assertEqual(entries[0]["euicc_ci_pkid"], root_ci_pkid)

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=str(euicc_store_root))
            self.assertEqual(len(recreated_engine.state.eim_entries), 1)
            restored = recreated_engine.state.eim_entries[0]
            self.assertEqual(restored.eim_id, target_eim_id)
            self.assertEqual(restored.eim_fqdn, target_fqdn)
            self.assertEqual(restored.eim_id_type, 3)
            self.assertEqual(restored.euicc_ci_pkid.hex().upper(), root_ci_pkid)
            self.assertEqual(bytes(restored.eim_public_key_data), signer_certificate_der)
            self.assertEqual(bytes(restored.trusted_tls_public_key_data), tls_certificate_der)

    def test_simulated_connection_delete_eim_does_not_auto_reseed_bf55(self) -> None:
        default_eim_id = "2.25.311782205282738360923618091971140414400"

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(
                os.environ,
                {CARD_BACKEND_ENV: "sim", SIM_EUICC_STORE_ENV: temp_dir},
                clear=False,
            ):
                connection = create_card_connection(reader_index=0)
                data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                delete_payload = wrap_tlv("BF59", wrap_tlv("80", default_eim_id.encode("utf-8")))
                delete_response, sw1, sw2 = send_store_data_payload(connection, delete_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(delete_response, bytes.fromhex("BF5900"))

                eim_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5500")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(decode_eim_configuration_entries(bytes(eim_response)), [])

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            self.assertEqual(len(recreated_engine.state.eim_entries), 0)

    def test_simulated_connection_euicc_memory_reset_restores_default_eim_row(self) -> None:
        default_eim_id = "2.25.311782205282738360923618091971140414400"
        custom_eim_id = "2.25.998877665544332211009988776655443322"

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(
                os.environ,
                {CARD_BACKEND_ENV: "sim", SIM_EUICC_STORE_ENV: temp_dir},
                clear=False,
            ):
                connection = create_card_connection(reader_index=0)
                data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                delete_default_payload = wrap_tlv("BF59", wrap_tlv("80", default_eim_id.encode("utf-8")))
                delete_response, sw1, sw2 = send_store_data_payload(connection, delete_default_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(delete_response, bytes.fromhex("BF5900"))

                add_payload = build_add_eim_command_payload(
                    "BF58",
                    eim_id=custom_eim_id,
                    eim_fqdn="custom-reset.eim.local",
                    eim_id_type=1,
                    counter_value=3,
                    association_token=12,
                    supported_protocol_bits=[0, 2],
                    euicc_ci_pkid_hex="F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
                    indirect_profile_download=True,
                )
                add_response, sw1, sw2 = send_store_data_payload(connection, add_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(add_response, bytes.fromhex("BF5800"))

                reset_response, sw1, sw2 = send_store_data_payload(
                    connection,
                    build_euicc_memory_reset_payload(reset_eim_config_data=True),
                )
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(reset_response, bytes.fromhex("BF6400"))

                eim_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF5500")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                entries = decode_eim_configuration_entries(bytes(eim_response))
                self.assertEqual(len(entries), 1)
                self.assertEqual(entries[0]["eim_id"], default_eim_id)
                self.assertEqual(entries[0]["eim_fqdn"], "eim.example.test")

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            self.assertEqual(len(recreated_engine.state.eim_entries), 1)
            self.assertEqual(recreated_engine.state.eim_entries[0].eim_id, default_eim_id)
            self.assertEqual(recreated_engine.state.eim_entries[0].eim_fqdn, "eim.example.test")

    def test_simulated_connection_tracks_stateful_es10_session_and_install_flow(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            info2_before, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2200")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            installed_apps_before = int.from_bytes(
                extract_nested_tlv_value(bytes(info2_before), "84", "81"),
                "big",
            )
            free_nvm_before = int.from_bytes(
                extract_nested_tlv_value(bytes(info2_before), "84", "82"),
                "big",
            )

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            challenge_value = extract_euicc_challenge(challenge)
            self.assertEqual(len(challenge_value), 16)

            transaction_id = bytes.fromhex("11223344556677889900AABBCCDDEEFF")
            server_signed1 = wrap_tlv(
                b"\x30",
                wrap_tlv(b"\x80", transaction_id)
                + wrap_tlv(b"\x81", challenge_value)
                + wrap_tlv(b"\x83", b"rsp.example.com")
                + wrap_tlv(b"\x84", b"\x22" * 16),
            )
            cert_der, cert_private_key = build_self_signed_cert_and_key("Simulator DPpb")
            ctx_params = wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx")))
            auth_payload = build_authenticate_server_payload(
                transaction_id=transaction_id,
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x22" * 16,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
                ctx_params=ctx_params,
            )
            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(auth_response.startswith(bytes.fromhex("BF38")))
            self.assertGreater(len(find_first_tlv(auth_response, "5F37")), 0)

            _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)
            prepare_payload = build_prepare_download_payload(
                transaction_id=transaction_id,
                euicc_signature1=euicc_signature1,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
            )
            prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(prepare_response.startswith(bytes.fromhex("BF21")))
            euicc_otpk_raw = find_first_tlv(prepare_response, "5F49")
            self.assertGreater(len(euicc_otpk_raw), 0)
            _, euicc_otpk, _, _ = read_tlv(euicc_otpk_raw, 0)
            self.assertEqual(len(euicc_otpk), 65)

            bpp_segments = build_signed_bpp_segments(
                transaction_id=transaction_id,
                euicc_otpk_raw=euicc_otpk_raw,
                eid_hex="89045967676472615349763031303005",
                cert_private_key=cert_private_key,
                iccid="89881111111111111177",
                provider_name="Test Provider",
                profile_name="Cryptographic Install",
            )
            bootstrap_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["bootstrap"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bootstrap_response, b"")

            mid_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a0"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(mid_response, b"")

            mid_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a1"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(mid_response, b"")

            result_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a3"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(result_response.startswith(bytes.fromhex("BF37")))
            aid_raw = find_first_tlv(result_response, "4F")
            self.assertGreater(len(aid_raw), 0)
            _, installed_aid, _, _ = read_tlv(aid_raw, 0)
            self.assertEqual(installed_aid.hex().upper(), "A0000005591010FFFFFFFF8900001300")
            result_code, result_detail = parse_profile_install_result(result_response)
            self.assertEqual(result_code, 5)
            self.assertEqual(result_detail, 0)

            seq_metadata = find_first_tlv(result_response, "BF2F")
            self.assertGreater(len(seq_metadata), 0)
            _, seq_value, _, _ = read_tlv(find_first_tlv(seq_metadata, "80"), 0)
            seq_number = int.from_bytes(seq_value, "big")

            profiles_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2D00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertIn(installed_aid, bytes(profiles_response))

            info2_after_install, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2200")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            installed_apps_after = int.from_bytes(
                extract_nested_tlv_value(bytes(info2_after_install), "84", "81"),
                "big",
            )
            free_nvm_after = int.from_bytes(
                extract_nested_tlv_value(bytes(info2_after_install), "84", "82"),
                "big",
            )
            self.assertGreater(installed_apps_after, installed_apps_before)
            self.assertLess(free_nvm_after, free_nvm_before)

            enable_request = wrap_tlv("BF31", wrap_tlv("4F", installed_aid))
            enable_response, sw1, sw2 = send_store_data_payload(connection, enable_request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(enable_response.startswith(bytes.fromhex("BF31")))

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("00A40004022FE2")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("00B000000A")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bytes(data), encode_iccid_ef("89881111111111111177"))

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{USIM_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("00A40004026F07")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("00B000000A")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bytes(data), encode_imsi_ef("1234567812345678"))

            impi_payload = b"user@install.test"
            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISIM_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            data, sw1, sw2 = connection.transmit(list(bytes.fromhex("00A40004026F02")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            read_impi_apdu = bytes([0x00, 0xB0, 0x00, 0x00, len(impi_payload)])
            data, sw1, sw2 = connection.transmit(list(read_impi_apdu))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bytes(data), impi_payload)

            notification_request = wrap_tlv("BF2B", wrap_tlv(b"\xA0", wrap_tlv(b"\x80", seq_value)))
            notification_response, sw1, sw2 = send_store_data_payload(connection, notification_request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(notification_response.startswith(bytes.fromhex("BF2B")))

            remove_request = wrap_tlv("BF30", wrap_tlv(b"\x80", seq_number.to_bytes(1, "big")))
            remove_response, sw1, sw2 = send_store_data_payload(connection, remove_request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(remove_response, bytes.fromhex("BF3000"))

    def test_simulated_connection_delete_profile_lists_queued_notification(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            deleted_aid = "A0000005591010FFFFFFFF8900001200"
            deleted_iccid = "89881111111111111129"
            delete_request = wrap_tlv("BF33", wrap_tlv("4F", bytes.fromhex(deleted_aid)))
            delete_response, sw1, sw2 = send_store_data_payload(connection, delete_request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(delete_response, bytes.fromhex("BF3303800100"))

            list_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2800")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(bytes(list_response).startswith(bytes.fromhex("BF28")))

            metadata_raw = find_first_tlv(bytes(list_response), "BF2F")
            self.assertGreater(len(metadata_raw), 0)

            _, seq_value, _, _ = read_tlv(find_first_tlv(metadata_raw, "80"), 0)
            seq_number = int.from_bytes(seq_value, "big", signed=False)
            self.assertEqual(seq_number, 1)

            _, operation_value, _, _ = read_tlv(find_first_tlv(metadata_raw, "81"), 0)
            self.assertEqual(operation_value, b"\x04")

            _, address_value, _, _ = read_tlv(find_first_tlv(metadata_raw, "0C"), 0)
            self.assertEqual(address_value.decode("utf-8"), "rsp.example.com")

            _, iccid_value, _, _ = read_tlv(find_first_tlv(metadata_raw, "5A"), 0)
            self.assertEqual(iccid_value, encode_iccid_ef(deleted_iccid))

            retrieve_request = wrap_tlv("BF2B", wrap_tlv("A0", wrap_tlv("80", seq_value)))
            retrieve_response, sw1, sw2 = send_store_data_payload(connection, retrieve_request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(retrieve_response.startswith(bytes.fromhex("BF2B")))

            pending_notification = find_first_tlv(retrieve_response, "BF37")
            self.assertGreater(len(pending_notification), 0)
            pending_metadata = find_first_tlv(pending_notification, "BF2F")
            self.assertGreater(len(pending_metadata), 0)

            _, pending_operation_value, _, _ = read_tlv(find_first_tlv(pending_metadata, "81"), 0)
            self.assertEqual(pending_operation_value, b"\x04")

            remove_request = wrap_tlv("BF30", wrap_tlv(b"\x80", seq_value))
            remove_response, sw1, sw2 = send_store_data_payload(connection, remove_request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(remove_response, bytes.fromhex("BF3000"))

            empty_list_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2800")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            # SGP.22 §5.7.9 mandates an explicit empty SEQUENCE OF wrapper
            # (tag A0, length 0) when no notifications are queued.
            self.assertEqual(bytes(empty_list_response), bytes.fromhex("BF2802A000"))

    def test_simulated_connection_retrieve_notifications_list_returns_all_queued_notifications(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            disable_request = wrap_tlv(
                "BF32",
                wrap_tlv("4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100")),
            )
            disable_response, sw1, sw2 = send_store_data_payload(connection, disable_request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(disable_response, bytes.fromhex("BF3203800100"))

            delete_request = wrap_tlv(
                "BF33",
                wrap_tlv("4F", bytes.fromhex("A0000005591010FFFFFFFF8900001200")),
            )
            delete_response, sw1, sw2 = send_store_data_payload(connection, delete_request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(delete_response, bytes.fromhex("BF3303800100"))

            notifications_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2B00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(bytes(notifications_response).startswith(bytes.fromhex("BF2B")))

            decoded = decode_notifications_response(bytes(notifications_response))
            self.assertEqual(decoded["error"], "")
            self.assertEqual(len(decoded["package_results"]), 0)
            self.assertEqual(len(decoded["notifications"]), 2)

            first, second = decoded["notifications"]
            self.assertEqual(first.get("seqNumber"), "1")
            self.assertEqual(first.get("iccid"), "89881111111111111112")
            self.assertEqual(first.get("notificationAddress"), '"rsp.example.com"')
            self.assertEqual(second.get("seqNumber"), "2")
            self.assertEqual(second.get("iccid"), "89881111111111111129")
            self.assertEqual(second.get("notificationAddress"), '"rsp.example.com"')

    def test_simulated_connection_retrieve_euicc_package_results_is_explicit_empty_branch(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            delete_request = wrap_tlv(
                "BF33",
                wrap_tlv("4F", bytes.fromhex("A0000005591010FFFFFFFF8900001200")),
            )
            delete_response, sw1, sw2 = send_store_data_payload(connection, delete_request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(delete_response, bytes.fromhex("BF3303800100"))

            package_results_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910005BF2B028200")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bytes(package_results_response), bytes.fromhex("BF2B00"))

            notifications_response, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2B00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            decoded = decode_notifications_response(bytes(notifications_response))
            self.assertEqual(len(decoded["notifications"]), 1)
            self.assertEqual(decoded["notifications"][0].get("seqNumber"), "1")

    def test_simulated_connection_cancel_session_returns_valid_error_response(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            cancel_request = wrap_tlv("BF41", wrap_tlv("80", b"\x10" * 8) + wrap_tlv("81", b"\x02"))
            cancel_response, sw1, sw2 = send_store_data_payload(connection, cancel_request)

            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(cancel_response, bytes.fromhex("BF4103810102"))

    def test_simulated_connection_accepts_chunked_bpp_bootstrap_with_full_bf36_length(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            transaction_id = bytes.fromhex("5566778899AABBCCDDEEFF0011223344")
            cert_der, cert_private_key = build_self_signed_cert_and_key("Chunked Bootstrap DPpb")
            auth_payload = build_authenticate_server_payload(
                transaction_id=transaction_id,
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x24" * 16,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
                ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
            )
            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)
            prepare_payload = build_prepare_download_payload(
                transaction_id=transaction_id,
                euicc_signature1=euicc_signature1,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
            )
            prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            euicc_otpk_raw = find_first_tlv(prepare_response, "5F49")
            bpp_segments = build_signed_bpp_segments(
                transaction_id=transaction_id,
                euicc_otpk_raw=euicc_otpk_raw,
                eid_hex="89045967676472615349763031303005",
                cert_private_key=cert_private_key,
                iccid="89881111111111111191",
                provider_name="Chunked Provider",
                profile_name="Chunked Bootstrap",
                upp_payload=b"\x01",
            )
            bf23_raw = find_first_tlv(bpp_segments["bootstrap"], "BF23")
            full_bpp = wrap_tlv(
                "BF36",
                bf23_raw
                + wrap_tlv("A0", bpp_segments["a0"])
                + wrap_tlv("A1", bpp_segments["a1"])
                + wrap_tlv("A3", bpp_segments["a3"]),
            )

            root_tag, root_value, _, _ = read_tlv(full_bpp, 0)
            self.assertEqual(root_tag, bytes.fromhex("BF36"))
            child_tag, _, _, next_offset = read_tlv(root_value, 0)
            self.assertEqual(child_tag, bytes.fromhex("BF23"))
            bootstrap_end = next_offset + (len(full_bpp) - len(root_value))
            bootstrap_segment = full_bpp[:bootstrap_end]
            self.assertGreater(len(bootstrap_segment), 120)

            first_chunk = bootstrap_segment[:120]
            second_chunk = bootstrap_segment[120:]
            response, sw1, sw2 = connection.transmit(
                list(bytes([0x80, 0xE2, 0x11, 0x00, len(first_chunk)]) + first_chunk)
            )
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bytes(response), b"")

            response, sw1, sw2 = connection.transmit(
                list(bytes([0x80, 0xE2, 0x91, 0x01, len(second_chunk)]) + second_chunk)
            )
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bytes(response), b"")

            a0_response, sw1, sw2 = send_store_data_payload(connection, wrap_tlv("A0", bpp_segments["a0"]))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(a0_response, b"")

    def test_simulated_connection_waits_for_all_declared_a3_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(
                os.environ,
                {
                    CARD_BACKEND_ENV: "sim",
                    SIM_PROFILE_STORE_ENV: str(Path(temp_dir) / "profiles"),
                },
                clear=False,
            ):
                connection = create_card_connection(reader_index=0)

                data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                transaction_id = bytes.fromhex("66778899AABBCCDDEEFF001122334455")
                cert_der, cert_private_key = build_self_signed_cert_and_key("Segmented A3 DPpb")
                auth_payload = build_authenticate_server_payload(
                    transaction_id=transaction_id,
                    euicc_challenge=extract_euicc_challenge(challenge),
                    server_address="rsp.example.com",
                    server_challenge=b"\x34" * 16,
                    cert_der=cert_der,
                    cert_private_key=cert_private_key,
                    ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
                )
                auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)
                prepare_payload = build_prepare_download_payload(
                    transaction_id=transaction_id,
                    euicc_signature1=euicc_signature1,
                    cert_der=cert_der,
                    cert_private_key=cert_private_key,
                )
                prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                euicc_otpk_raw = find_first_tlv(prepare_response, "5F49")
                oversized_upp = wrap_tlv("A0", wrap_tlv("80", b"\x01")) + (b"\xAA" * 1500)
                bpp_segments = build_signed_bpp_segments(
                    transaction_id=transaction_id,
                    euicc_otpk_raw=euicc_otpk_raw,
                    eid_hex="89045967676472615349763031303005",
                    cert_private_key=cert_private_key,
                    iccid="89881111111111111222",
                    provider_name="Segmented Provider",
                    profile_name="Segmented A3 Profile",
                    upp_payload=oversized_upp,
                    a3_plaintext_chunk_size=1000,
                )
                a3_members = bpp_segments["a3_members"]
                self.assertGreaterEqual(len(a3_members), 2)
                self.assertEqual(len(a3_members[0]), 1020)

                bootstrap_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["bootstrap"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(bootstrap_response, b"")

                a0_response, sw1, sw2 = send_store_data_payload(connection, wrap_tlv("A0", bpp_segments["a0"]))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(a0_response, b"")

                a1_response, sw1, sw2 = send_store_data_payload(connection, wrap_tlv("A1", bpp_segments["a1"]))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(a1_response, b"")

                a3_header = bytes.fromhex("A3") + encode_length(len(bpp_segments["a3"]))
                a3_header_response, sw1, sw2 = send_store_data_payload(connection, a3_header)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(a3_header_response, b"")

                for member in a3_members[:-1]:
                    intermediate_response, sw1, sw2 = send_store_data_payload(connection, member)
                    self.assertEqual((sw1, sw2), (0x90, 0x00))
                    self.assertEqual(intermediate_response, b"")

                result_response, sw1, sw2 = send_store_data_payload(connection, a3_members[-1])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                result_code, result_detail = parse_profile_install_result(result_response)
                self.assertEqual((result_code, result_detail), (5, 0))

    def test_installed_profile_persists_across_engine_recreation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(
                os.environ,
                {CARD_BACKEND_ENV: "sim", SIM_PROFILE_STORE_ENV: temp_dir},
                clear=False,
            ):
                connection = create_card_connection(reader_index=0)

                data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                transaction_id = bytes.fromhex("102030405060708090A0B0C0D0E0F000")
                server_signed1 = wrap_tlv(
                    b"\x30",
                    wrap_tlv(b"\x80", transaction_id)
                    + wrap_tlv(b"\x81", bytes(challenge))
                    + wrap_tlv(b"\x83", b"persist.example.com")
                    + wrap_tlv(b"\x84", b"\x44" * 16),
                )
                cert_der, cert_private_key = build_self_signed_cert_and_key("Persist DPpb")
                auth_payload = build_authenticate_server_payload(
                    transaction_id=transaction_id,
                    euicc_challenge=extract_euicc_challenge(challenge),
                    server_address="persist.example.com",
                    server_challenge=b"\x44" * 16,
                    cert_der=cert_der,
                    cert_private_key=cert_private_key,
                    ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
                )
                auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)
                prepare_payload = build_prepare_download_payload(
                    transaction_id=transaction_id,
                    euicc_signature1=euicc_signature1,
                    cert_der=cert_der,
                    cert_private_key=cert_private_key,
                )
                prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                euicc_otpk_raw = find_first_tlv(prepare_response, "5F49")

                bpp_segments = build_signed_bpp_segments(
                    transaction_id=transaction_id,
                    euicc_otpk_raw=euicc_otpk_raw,
                    eid_hex="89045967676472615349763031303005",
                    cert_private_key=cert_private_key,
                    iccid="89881111111111111166",
                    provider_name="Persistent Provider",
                    profile_name="Persistent Profile",
                )
                _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["bootstrap"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a0"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a1"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                result_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a3"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                aid_raw = find_first_tlv(result_response, "4F")
                self.assertGreater(len(aid_raw), 0)
                _, installed_aid, _, _ = read_tlv(aid_raw, 0)
                installed_aid_hex = installed_aid.hex().upper()
                self.assertEqual(installed_aid_hex, "A0000005591010FFFFFFFF8900001300")

                enable_request = wrap_tlv("BF31", wrap_tlv("4F", installed_aid))
                enable_response, sw1, sw2 = send_store_data_payload(connection, enable_request)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertTrue(enable_response.startswith(bytes.fromhex("BF31")))

            persisted_profile_dir = Path(temp_dir) / f"AID_{installed_aid_hex}"
            self.assertTrue((persisted_profile_dir / "manifest.json").is_file())
            self.assertTrue((persisted_profile_dir / "profile_image.json").is_file())
            self.assertTrue((persisted_profile_dir / "profile.upp.der").is_file())

            recreated_engine = SimulatedSimCardEngine(profile_store_path=temp_dir)
            loaded_profiles = {profile.aid.upper(): profile for profile in recreated_engine.state.profiles}
            self.assertIn(installed_aid_hex, loaded_profiles)
            persisted_profile = loaded_profiles[installed_aid_hex]
            self.assertEqual(persisted_profile.iccid, "89881111111111111166")
            self.assertEqual(persisted_profile.profile_name, "Persistent Profile")
            self.assertEqual(persisted_profile.service_provider, "Persistent Provider")
            self.assertEqual(persisted_profile.state, "enabled")
            self.assertEqual(persisted_profile.profile_source, "upp")
            self.assertIsNotNone(persisted_profile.profile_image)
            self.assertEqual(recreated_engine.state.active_profile_aid.upper(), installed_aid_hex)

            data, sw1, sw2 = recreated_engine.fs.select(bytes.fromhex(USIM_AID))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            data, sw1, sw2 = recreated_engine.fs.select(bytes.fromhex("6F07"))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            data, sw1, sw2 = recreated_engine.fs.read_binary(offset=0, le=10)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bytes(data), encode_imsi_ef("1234567812345678"))

    def test_bpp_install_notification_address_prefers_active_server_address(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_store_dir = Path(temp_dir) / "profiles"
            quirks_path = Path(temp_dir) / "sim_quirks.py"
            quirks_path.write_text(
                'metadata_overrides = {"default_dp_address": "rsp.override.test"}\n',
                encoding="utf-8",
            )

            with mock.patch.dict(
                os.environ,
                {
                    CARD_BACKEND_ENV: "sim",
                    SIM_PROFILE_STORE_ENV: str(profile_store_dir),
                    SIM_QUIRKS_ENV: str(quirks_path),
                },
                clear=False,
            ):
                connection = create_card_connection(reader_index=0)

                data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                transaction_id = bytes.fromhex("2233445566778899AABBCCDDEEFF0011")
                server_address = "dpp1.esim.tst.1ot.mobi"
                cert_der, cert_private_key = build_self_signed_cert_and_key("Notification Target DPpb")
                auth_payload = build_authenticate_server_payload(
                    transaction_id=transaction_id,
                    euicc_challenge=extract_euicc_challenge(challenge),
                    server_address=server_address,
                    server_challenge=b"\x41" * 16,
                    cert_der=cert_der,
                    cert_private_key=cert_private_key,
                    ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
                )
                auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)
                prepare_payload = build_prepare_download_payload(
                    transaction_id=transaction_id,
                    euicc_signature1=euicc_signature1,
                    cert_der=cert_der,
                    cert_private_key=cert_private_key,
                )
                prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                euicc_otpk_raw = find_first_tlv(prepare_response, "5F49")

                bpp_segments = build_signed_bpp_segments(
                    transaction_id=transaction_id,
                    euicc_otpk_raw=euicc_otpk_raw,
                    eid_hex="89045967676472615349763031303005",
                    cert_private_key=cert_private_key,
                    iccid="89881111111111111167",
                    provider_name="Notification Provider",
                    profile_name="Notification Profile",
                    upp_payload=b"\x01",
                )
                _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["bootstrap"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a0"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a1"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                result_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a3"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                self.assertEqual(parse_profile_install_result(result_response), (5, 0))
                notification_address = extract_nested_tlv_value(result_response, "BF2F", "0C").decode(
                    "utf-8",
                    "ignore",
                )
                self.assertEqual(notification_address, server_address)

                aid_raw = find_first_tlv(result_response, "4F")
                self.assertGreater(len(aid_raw), 0)
                _, installed_aid, _, _ = read_tlv(aid_raw, 0)
                manifest_path = profile_store_dir / f"AID_{installed_aid.hex().upper()}" / "manifest.json"
                self.assertTrue(manifest_path.is_file())
                from yggdrasim_common.inventory_crypto import read_secret_json_file
                manifest = read_secret_json_file(manifest_path)
                self.assertIsInstance(manifest, dict)
                self.assertEqual(manifest["notification_address"], server_address)

    def test_euicc_store_persists_card_identity_and_scp03_keys_by_eid(self) -> None:
        from yggdrasim_common.inventory_crypto import (
            read_secret_json_file,
            write_secret_json_file,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            euicc_manifest_path = Path(engine.state.euicc_store_path) / "euicc.json"
            self.assertTrue(euicc_manifest_path.is_file())

            manifest = read_secret_json_file(euicc_manifest_path)
            self.assertIsInstance(manifest, dict)
            manifest["root_ci_pkid_hex"] = "00112233445566778899AABBCCDDEEFF00112233"
            manifest["scp03_keys"] = {
                "kenc_hex": "0102030405060708090A0B0C0D0E0F10",
                "kmac_hex": "1112131415161718191A1B1C1D1E1F20",
                "dek_hex": "2122232425262728292A2B2C2D2E2F30",
                "kvn": 0x31,
            }
            write_secret_json_file(euicc_manifest_path, manifest)

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            self.assertEqual(recreated_engine.state.root_ci_pkid.hex().upper(), "00112233445566778899AABBCCDDEEFF00112233")
            self.assertEqual(recreated_engine.state.scp03_keys.kvn, 0x31)
            self.assertEqual(
                recreated_engine.state.scp03_keys.kenc.hex().upper(),
                "0102030405060708090A0B0C0D0E0F10",
            )
            self.assertEqual(
                recreated_engine.state.scp03_keys.kmac.hex().upper(),
                "1112131415161718191A1B1C1D1E1F20",
            )
            self.assertEqual(
                recreated_engine.state.scp03_keys.dek.hex().upper(),
                "2122232425262728292A2B2C2D2E2F30",
            )

            data, sw1, sw2 = recreated_engine.scp03.handle_initialize_update(
                0x31,
                bytes.fromhex("0102030405060708"),
            )
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(data[10], 0x31)

    def test_import_profile_artifact_loads_as_installed_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            upp_path = Path(temp_dir) / "external_profile.der"
            upp_path.write_bytes(
                build_minimal_saip_upp(
                    iccid="89881111111111111144",
                    imsi="1234567812345678",
                    impi="imported@sim.test",
                    profile_name="Imported From ASN1",
                )
            )

            result = import_profile_artifact(
                str(upp_path),
                engine.state.profile_store_path,
                enable=True,
            )

            self.assertEqual(result.profile_name, "Imported From ASN1")
            self.assertEqual(result.iccid, "89881111111111111144")
            self.assertEqual(result.profile_source, "upp")
            self.assertEqual(result.aid, "A0000005591010FFFFFFFF8900001300")
            self.assertTrue(result.enabled)

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            loaded_profiles = {profile.aid.upper(): profile for profile in recreated_engine.state.profiles}
            self.assertIn(result.aid.upper(), loaded_profiles)
            imported_profile = loaded_profiles[result.aid.upper()]
            self.assertEqual(imported_profile.profile_name, "Imported From ASN1")
            self.assertEqual(imported_profile.iccid, "89881111111111111144")
            self.assertEqual(imported_profile.service_provider, "Imported SAIP")
            self.assertEqual(imported_profile.state, "enabled")
            self.assertEqual(imported_profile.profile_source, "upp")
            self.assertEqual(recreated_engine.state.active_profile_aid.upper(), result.aid.upper())

            data, sw1, sw2 = recreated_engine.fs.select(bytes.fromhex(USIM_AID))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            data, sw1, sw2 = recreated_engine.fs.select(bytes.fromhex("6F07"))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            data, sw1, sw2 = recreated_engine.fs.read_binary(offset=0, le=10)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bytes(data), encode_imsi_ef("1234567812345678"))

    def test_import_profile_artifact_accepts_hex_text_der(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            upp_hex_path = Path(temp_dir) / "external_profile.txt"
            upp_hex_path.write_text(
                build_minimal_saip_upp(
                    iccid="89881111111111111145",
                    imsi="1234567812345678",
                    impi="hex@sim.test",
                    profile_name="Imported From Hex Text",
                ).hex().upper()
                + "\n",
                encoding="utf-8",
            )

            result = import_profile_artifact(
                str(upp_hex_path),
                engine.state.profile_store_path,
                enable=True,
            )

            self.assertEqual(result.profile_name, "Imported From Hex Text")
            self.assertEqual(result.iccid, "89881111111111111145")
            self.assertEqual(result.profile_source, "upp")

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            imported = [profile for profile in recreated_engine.state.profiles if profile.aid.upper() == result.aid.upper()]
            self.assertEqual(len(imported), 1)
            self.assertEqual(imported[0].profile_name, "Imported From Hex Text")
            self.assertEqual(imported[0].state, "enabled")

    def test_import_profile_artifact_accepts_tagged_saip_json(self) -> None:
        from Tools.ProfilePackage.saip_json_codec import jsonify_document

        with tempfile.TemporaryDirectory() as temp_dir:
            engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            tagged_json_path = Path(temp_dir) / "external_profile.transcode.json"
            tagged_document = jsonify_document(
                {
                    "intro": ["Tagged JSON import test"],
                    "sections": {
                        "header": {
                            "major-version": 2,
                            "minor-version": 3,
                            "profileType": "Imported From Tagged JSON",
                            "iccid": bytes.fromhex("89881111111111111146"),
                            "eUICC-Mandatory-services": {"usim": None, "isim": None},
                            "eUICC-Mandatory-GFSTEList": [
                                "2.23.143.1.2.1",
                                "2.23.143.1.2.4.2",
                                "2.23.143.1.2.8",
                            ],
                        },
                        "mf": {
                            "mf-header": {"mandated": None, "identification": 2},
                            "templateID": "2.23.143.1.2.1",
                            "mf": [],
                            "ef-iccid": [("fillFileContent", encode_iccid_ef("89881111111111111146"))],
                            "ef-dir": [],
                            "ef-arr": [],
                        },
                        "usim": {
                            "usim-header": {"mandated": None, "identification": 3},
                            "templateID": "2.23.143.1.2.4.2",
                            "adf-usim": [],
                            "ef-imsi": [("fillFileContent", encode_imsi_ef("1234567812345678"))],
                            "ef-arr": [],
                            "ef-ust": [],
                            "ef-spn": [],
                            "ef-est": [],
                            "ef-acc": [],
                            "ef-ecc": [],
                        },
                        "isim": {
                            "isim-header": {"mandated": None, "identification": 4},
                            "templateID": "2.23.143.1.2.8",
                            "adf-isim": [],
                            "ef-impi": [("fillFileContent", b"tagged@sim.test")],
                            "ef-impu": [],
                            "ef-domain": [],
                            "ef-ist": [],
                            "ef-arr": [],
                        },
                        "end": {"end-header": {"mandated": None, "identification": 5}},
                    },
                }
            )
            tagged_json_path.write_text(json.dumps(tagged_document, indent=2) + "\n", encoding="utf-8")

            result = import_profile_artifact(
                str(tagged_json_path),
                engine.state.profile_store_path,
                enable=True,
            )

            self.assertEqual(result.profile_name, "Imported From Tagged JSON")
            self.assertEqual(result.iccid, "89881111111111111146")
            self.assertEqual(result.profile_source, "upp")

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=temp_dir)
            imported = [profile for profile in recreated_engine.state.profiles if profile.aid.upper() == result.aid.upper()]
            self.assertEqual(len(imported), 1)
            self.assertEqual(imported[0].profile_name, "Imported From Tagged JSON")
            self.assertEqual(imported[0].state, "enabled")

    def test_generated_profile_aids_follow_real_world_sequence(self) -> None:
        profiles: list[types.SimpleNamespace] = []
        self.assertEqual(next_generated_profile_aid(profiles), "A0000005591010FFFFFFFF8900001100")

        profiles.append(types.SimpleNamespace(aid="A0000005591010FFFFFFFF8900001100"))
        self.assertEqual(next_generated_profile_aid(profiles), "A0000005591010FFFFFFFF8900001200")

        profiles.append(types.SimpleNamespace(aid="A0000005591010FFFFFFFF8900001200"))
        self.assertEqual(next_generated_profile_aid(profiles), "A0000005591010FFFFFFFF8900001300")

        profiles.append(types.SimpleNamespace(aid="A0000005591010FFFFFFFF8900001300"))
        self.assertEqual(next_generated_profile_aid(profiles), "A0000005591010FFFFFFFF8900001400")

        profiles.append(types.SimpleNamespace(aid="A0000005591010FFFFFFFF8900001400"))
        self.assertEqual(next_generated_profile_aid(profiles), "A0000005591010FFFFFFFF8900001500")

        gapped = [types.SimpleNamespace(aid="A0000005591010FFFFFFFF8900001100"),
                  types.SimpleNamespace(aid="A0000005591010FFFFFFFF8900001300")]
        self.assertEqual(next_generated_profile_aid(gapped), "A0000005591010FFFFFFFF8900001200")

    def test_simulated_connection_rejects_tampered_bpp_segment(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            transaction_id = bytes.fromhex("FFEEDDCCBBAA00998877665544332211")
            server_signed1 = wrap_tlv(
                b"\x30",
                wrap_tlv(b"\x80", transaction_id)
                + wrap_tlv(b"\x81", bytes(challenge))
                + wrap_tlv(b"\x83", b"rsp.example.com")
                + wrap_tlv(b"\x84", b"\x33" * 16),
            )
            cert_der, cert_private_key = build_self_signed_cert_and_key("Tamper DPpb")
            auth_payload = build_authenticate_server_payload(
                transaction_id=transaction_id,
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x33" * 16,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
                ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
            )
            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)
            prepare_payload = build_prepare_download_payload(
                transaction_id=transaction_id,
                euicc_signature1=euicc_signature1,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
            )
            prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            euicc_otpk_raw = find_first_tlv(prepare_response, "5F49")

            bpp_segments = build_signed_bpp_segments(
                transaction_id=transaction_id,
                euicc_otpk_raw=euicc_otpk_raw,
                eid_hex="89045967676472615349763031303005",
                cert_private_key=cert_private_key,
                iccid="89881111111111111188",
                provider_name="Tampered Provider",
                profile_name="Tampered Install",
            )
            tampered_a3 = bytearray(bpp_segments["a3"])
            tampered_a3[-1] ^= 0x01

            bootstrap_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["bootstrap"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(bootstrap_response, b"")

            _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a0"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a1"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            result_response, sw1, sw2 = send_store_data_payload(connection, bytes(tampered_a3))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertTrue(result_response.startswith(bytes.fromhex("BF37")))
            result_code, result_detail = parse_profile_install_result(result_response)
            self.assertEqual(result_code, 5)
            self.assertEqual(result_detail, 8)

    def test_simulated_connection_rejects_duplicate_profile_iccid_during_bpp_install(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            transaction_id = bytes.fromhex("11223344556677889900AABBCCDDEEFF")
            cert_der, cert_private_key = build_self_signed_cert_and_key("Duplicate ICCID DPauth")
            auth_payload = build_authenticate_server_payload(
                transaction_id=transaction_id,
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x31" * 16,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
                ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
            )
            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)

            prepare_payload = build_prepare_download_payload(
                transaction_id=transaction_id,
                euicc_signature1=euicc_signature1,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
            )
            prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            euicc_otpk_raw = find_first_tlv(prepare_response, "5F49")

            bpp_segments = build_signed_bpp_segments(
                transaction_id=transaction_id,
                euicc_otpk_raw=euicc_otpk_raw,
                eid_hex="89045967676472615349763031303005",
                cert_private_key=cert_private_key,
                iccid="89881111111111111112",
                provider_name="Duplicate Provider",
                profile_name="Duplicate ICCID",
                upp_payload=b"\x01",
            )
            _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["bootstrap"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a0"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a1"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            result_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a3"])
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            result_code, result_detail = parse_profile_install_result(result_response)
            self.assertEqual(result_code, 5)
            self.assertEqual(result_detail, 9)

    def test_simulated_connection_rejects_bpp_iccid_mismatch(self) -> None:
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            connection = create_card_connection(reader_index=0)

            data, sw1, sw2 = connection.transmit(list(bytes.fromhex(f"00A4040010{ISDR_AID}")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            challenge, sw1, sw2 = connection.transmit(list(bytes.fromhex("80E2910003BF2E00")))
            self.assertEqual((sw1, sw2), (0x90, 0x00))

            transaction_id = bytes.fromhex("99AABBCCDDEEFF001122334455667788")
            cert_der, cert_private_key = build_self_signed_cert_and_key("Mismatch ICCID DPauth")
            auth_payload = build_authenticate_server_payload(
                transaction_id=transaction_id,
                euicc_challenge=extract_euicc_challenge(challenge),
                server_address="rsp.example.com",
                server_challenge=b"\x32" * 16,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
                ctx_params=wrap_tlv(b"\xA0", wrap_tlv(b"\x81", wrap_tlv(b"\x04", b"ctx"))),
            )
            auth_response, sw1, sw2 = send_store_data_payload(connection, auth_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            _, euicc_signature1, _, _ = read_tlv(find_first_tlv(auth_response, "5F37"), 0)

            prepare_payload = build_prepare_download_payload(
                transaction_id=transaction_id,
                euicc_signature1=euicc_signature1,
                cert_der=cert_der,
                cert_private_key=cert_private_key,
            )
            prepare_response, sw1, sw2 = send_store_data_payload(connection, prepare_payload)
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            euicc_otpk_raw = find_first_tlv(prepare_response, "5F49")

            bpp_segments = build_signed_bpp_segments(
                transaction_id=transaction_id,
                euicc_otpk_raw=euicc_otpk_raw,
                eid_hex="89045967676472615349763031303005",
                cert_private_key=cert_private_key,
                iccid="89881111111111111178",
                provider_name="Mismatch Provider",
                profile_name="Mismatch ICCID",
                upp_payload=b"\x01",
            )
            fake_profile = types.SimpleNamespace(
                iccid="89881111111111111179",
                profile_name="Patched Profile",
                imsi="",
                impi="",
                nodes=[],
            )
            with mock.patch("SIMCARD.sgp.decode_profile_image", return_value=fake_profile):
                _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["bootstrap"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a0"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                _, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a1"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))

                result_response, sw1, sw2 = send_store_data_payload(connection, bpp_segments["a3"])
                self.assertEqual((sw1, sw2), (0x90, 0x00))
            result_code, result_detail = parse_profile_install_result(result_response)
            self.assertEqual(result_code, 5)
            self.assertEqual(result_detail, 13)


class SaipProfileDecodeBoundedTests(unittest.TestCase):
    """
    Regression tests for the per-element timeout around
    ``asn1.decode('ProfileElement', raw_tlv)`` inside
    ``SIMCARD.saip_profile.decode_profile_image``.

    The simulator's LOAD-PROFILE path used to wedge the APDU response
    whenever pySim's asn1tools DER codec entered its unbounded
    ``decode_content`` loop on a pathological ProfileElement. These tests
    pin the contract that the decoder now punts on the offending element
    instead of blocking the whole install.
    """

    def test_bounded_decode_returns_none_when_asn1_never_finishes(self) -> None:
        import time

        from SIMCARD.saip_profile import _decode_profile_element_bounded

        class HangingAsn1:
            def decode(self, _type_name, _raw_tlv):
                while True:
                    time.sleep(0.05)

        started = time.time()
        result = _decode_profile_element_bounded(
            HangingAsn1(),
            b"\x86\x01\xAA",
            timeout_seconds=0.75,
        )
        elapsed = time.time() - started

        self.assertIsNone(result)
        self.assertLess(elapsed, 2.0, "timeout must fire well before the test harness bails")

    def test_bounded_decode_returns_none_on_exception(self) -> None:
        from SIMCARD.saip_profile import _decode_profile_element_bounded

        class RaisingAsn1:
            def decode(self, _type_name, _raw_tlv):
                raise ValueError("synthetic decoder error")

        result = _decode_profile_element_bounded(
            RaisingAsn1(),
            b"\x86\x01\xAA",
            timeout_seconds=1.0,
        )

        self.assertIsNone(result)

    def test_bounded_decode_returns_result_when_decode_succeeds(self) -> None:
        from SIMCARD.saip_profile import _decode_profile_element_bounded

        class StubAsn1:
            def decode(self, _type_name, _raw_tlv):
                return ("telecom", {"iccid": b"\x89\x46"})

        result = _decode_profile_element_bounded(
            StubAsn1(),
            b"\xB2\x01\xAA",
            timeout_seconds=1.0,
        )

        self.assertIsNotNone(result)
        pe_type, decoded = result
        self.assertEqual(pe_type, "telecom")
        self.assertEqual(decoded, {"iccid": b"\x89\x46"})

    def test_decode_profile_image_skips_hanging_element_and_keeps_going(self) -> None:
        import time

        from SIMCARD import saip_profile

        if saip_profile._get_saip_asn1() is None:
            self.skipTest("pySim SAIP asn1 compiler unavailable in this environment")

        header_name_tlv = bytes([0x82, 0x08]) + b"Header10"
        header_iccid_tlv = bytes([0x83, 0x08]) + bytes.fromhex("6000000000000000")
        header_value = header_name_tlv + header_iccid_tlv
        header_tlv = bytes([0xA0, len(header_value)]) + header_value

        hanging_tlv = bytes([0xB2, 0x03, 0xAA, 0x01, 0x02])
        trailing_tlv = bytes([0xB3, 0x02, 0x81, 0x00])

        upp_bytes = header_tlv + hanging_tlv + trailing_tlv

        hang_controller = {"hanging_seen": False, "trailing_seen": False}

        class HangingOnceAsn1:
            def __init__(self, real_asn1) -> None:
                self._real = real_asn1

            def decode(self, type_name, raw_tlv):
                first_tag = bytes(raw_tlv)[:1]
                if first_tag == b"\xB2":
                    hang_controller["hanging_seen"] = True
                    while True:
                        time.sleep(0.05)
                if first_tag == b"\xB3":
                    hang_controller["trailing_seen"] = True
                return self._real.decode(type_name, raw_tlv)

        real_asn1 = saip_profile._get_saip_asn1()
        with mock.patch(
            "SIMCARD.saip_profile._get_saip_asn1",
            return_value=HangingOnceAsn1(real_asn1),
        ), mock.patch.dict(
            os.environ,
            {"YGGDRASIM_SIM_SAIP_DECODE_TIMEOUT_SECONDS": "0.75"},
            clear=False,
        ):
            started = time.time()
            image = saip_profile.decode_profile_image(
                upp_bytes,
                default_iccid="",
                default_name="",
            )
            elapsed = time.time() - started

        self.assertTrue(hang_controller["hanging_seen"], "hanging B2 element must be attempted")
        self.assertTrue(
            hang_controller["trailing_seen"],
            "elements after the hang must still be attempted",
        )
        self.assertLess(elapsed, 4.0, "decode_profile_image must not hang on a single bad element")
        self.assertIsNotNone(image)

    def test_native_salvage_recovers_telecom_ef_adn_when_asn1_hangs(self) -> None:
        """
        When ``asn1tools`` cannot decode a ``PE-TELECOM`` element (either
        because it trips the DER ``decode_content`` infinite loop or
        raises on a malformed inner TLV), the profile image used to lose
        every file that lived under ``DF.TELECOM``. The native salvage
        walker now recovers file slots that follow the SAIP
        ``File ::= SEQUENCE OF CHOICE`` encoding without going through
        asn1tools. Pin that ``EF.ADN`` is reconstructed with the right
        FID, structure, and record payload even when the bounded decode
        returns ``None``.
        """
        import time

        from SIMCARD import saip_profile

        # Construct a minimal PE-TELECOM (B2) with an ef-adn [24] File
        # slot carrying a single ``fillFileContent`` OCTET STRING. The
        # field layout follows AUTOMATIC TAGS IMPLICIT per SAIP 3.3.1:
        #   telecom-header [0] -> 0xA0, templateID [1] -> 0x81,
        #   df-telecom [2] -> 0xA2, ef-adn [24] -> 0xB8,
        #   fillFileContent [3] -> 0x83.
        telecom_header = bytes.fromhex("A003810101")  # identification=1
        template_oid = bytes.fromhex("81020000")  # placeholder, walker ignores value
        df_telecom = bytes.fromhex("A200")  # empty File

        file_content = bytes([0x83, 0x05]) + b"ABCDE"
        ef_adn_tlv = bytes([0xB8, len(file_content)]) + file_content

        pe_content = telecom_header + template_oid + df_telecom + ef_adn_tlv
        pe_tlv = bytes([0xB2, len(pe_content)]) + pe_content

        header_name = b"TestName"
        header_iccid = bytes.fromhex("6000000000000000")
        header_value = (
            bytes([0x82, len(header_name)]) + header_name
            + bytes([0x83, len(header_iccid)]) + header_iccid
        )
        header_tlv = bytes([0xA0, len(header_value)]) + header_value

        upp_bytes = header_tlv + pe_tlv

        class HangingAsn1:
            def decode(self, _type_name, _raw_tlv):
                while True:
                    time.sleep(0.05)

        with mock.patch(
            "SIMCARD.saip_profile._get_saip_asn1",
            return_value=HangingAsn1(),
        ), mock.patch.dict(
            os.environ,
            {"YGGDRASIM_SIM_SAIP_DECODE_TIMEOUT_SECONDS": "0.5"},
            clear=False,
        ):
            image = saip_profile.decode_profile_image(
                upp_bytes,
                default_iccid="",
                default_name="",
            )

        self.assertIsNotNone(image)
        assert image is not None

        telecom_root = next(
            (node for node in image.nodes if node.path == ("MF", "DF.TELECOM")),
            None,
        )
        self.assertIsNotNone(
            telecom_root,
            "DF.TELECOM root node must be materialised by the telecom salvage path",
        )

        ef_adn_node = next(
            (node for node in image.nodes if node.path == ("MF", "DF.TELECOM", "EF.ADN")),
            None,
        )
        self.assertIsNotNone(
            ef_adn_node,
            "EF.ADN file content must be recovered by the native PE-TELECOM walker",
        )
        assert ef_adn_node is not None
        self.assertEqual(ef_adn_node.fid.upper(), "6F3A")
        self.assertEqual(ef_adn_node.structure, "linear-fixed")
        self.assertEqual(ef_adn_node.records, [b"ABCDE"])

    def test_native_salvage_respects_do_not_create_marker(self) -> None:
        """
        A PE-TELECOM slot whose File starts with ``doNotCreate`` must not
        produce a file-system node even though the section itself is
        salvageable. This mirrors the behaviour of the asn1tools-driven
        path via ``_materialize_file_payload``.
        """
        import time

        from SIMCARD import saip_profile

        # ef-adn [24] -> File containing only doNotCreate ([0] IMPLICIT NULL).
        do_not_create = bytes([0x80, 0x00])
        ef_adn_tlv = bytes([0xB8, len(do_not_create)]) + do_not_create

        telecom_header = bytes.fromhex("A003810101")
        pe_content = telecom_header + ef_adn_tlv
        pe_tlv = bytes([0xB2, len(pe_content)]) + pe_content

        header_value = (
            bytes([0x82, 0x08]) + b"TestName"
            + bytes([0x83, 0x08]) + bytes.fromhex("6000000000000000")
        )
        header_tlv = bytes([0xA0, len(header_value)]) + header_value
        upp_bytes = header_tlv + pe_tlv

        class HangingAsn1:
            def decode(self, _type_name, _raw_tlv):
                while True:
                    time.sleep(0.05)

        with mock.patch(
            "SIMCARD.saip_profile._get_saip_asn1",
            return_value=HangingAsn1(),
        ), mock.patch.dict(
            os.environ,
            {"YGGDRASIM_SIM_SAIP_DECODE_TIMEOUT_SECONDS": "0.5"},
            clear=False,
        ):
            image = saip_profile.decode_profile_image(
                upp_bytes,
                default_iccid="",
                default_name="",
            )

        self.assertIsNotNone(image)
        assert image is not None

        # DF.TELECOM itself should still be materialised...
        self.assertTrue(
            any(node.path == ("MF", "DF.TELECOM") for node in image.nodes),
            "DF.TELECOM root must still be created around a doNotCreate slot",
        )
        # ...but EF.ADN must be suppressed.
        self.assertFalse(
            any(node.path == ("MF", "DF.TELECOM", "EF.ADN") for node in image.nodes),
            "doNotCreate marker must suppress the EF.ADN node",
        )

    def test_bounded_decode_actively_terminates_runaway_worker_thread(self) -> None:
        """
        Regression: the original daemon-thread implementation merely let the
        asn1 decode keep running after ``_decode_profile_element_bounded``
        returned, which allowed the asn1tools inner list to grow unboundedly
        and leaked several GB of RAM across repeated installs / startups.
        The ctypes-based async-exception path must actually unwind the
        worker so it disappears shortly after the soft deadline.
        """
        import threading
        import time

        from SIMCARD.saip_profile import _decode_profile_element_bounded

        worker_name = "saip-profile-element-decode"

        class BytecodeHangingAsn1:
            def decode(self, _type_name, _raw_tlv):
                # Pure Python bytecode loop so PyThreadState_SetAsyncExc can
                # land between opcodes; mirrors the shape of the asn1tools
                # DER ``decode_content`` loop that caused the original hang.
                counter = 0
                while True:
                    counter = (counter + 1) & 0xFFFF

        before = sum(
            1 for thread in threading.enumerate() if thread.name == worker_name
        )

        result = _decode_profile_element_bounded(
            BytecodeHangingAsn1(),
            b"\x86\x01\xAA",
            timeout_seconds=0.5,
        )

        self.assertIsNone(result)

        # The worker must die within a bounded grace window; allow a couple
        # of scheduler ticks so the async exception can land even on a busy
        # test host.
        deadline = time.time() + 3.0
        while time.time() < deadline:
            alive = sum(
                1 for thread in threading.enumerate() if thread.name == worker_name
            )
            if alive <= before:
                break
            time.sleep(0.05)

        still_alive = sum(
            1 for thread in threading.enumerate() if thread.name == worker_name
        )
        self.assertLessEqual(
            still_alive,
            before,
            "runaway asn1 decode worker must be killed after the deadline fires",
        )


class SaipProfilePeSectionCoverageTests(unittest.TestCase):
    """
    Pin the shape of the SAIP PE section schema table against the section
    dispatcher and the canonical ASN.1 CHOICE layout so regressions (e.g.
    a dropped PE section, a stale field-index mapping, or a section spec
    that drifts out of sync with ``_PE_SECTION_SCHEMAS``) surface
    immediately. Covers both the structural wiring and the native
    salvage path for the large File-based sections.
    """

    # Expected AUTOMATIC TAGS choice-index for every file-based PE
    # section we salvage natively. Mirrors the CHOICE member order in
    # pySim's ``PE_Definitions-3.3.1.asn``.
    _EXPECTED_PE_CHOICE_INDEX: dict[str, int] = {
        "mf": 16,
        "cd": 17,
        "telecom": 18,
        "usim": 19,
        "opt-usim": 20,
        "isim": 21,
        "opt-isim": 22,
        "phonebook": 23,
        "gsm-access": 24,
        "csim": 25,
        "opt-csim": 26,
        "eap": 27,
        "df-5gs": 28,
        "df-saip": 29,
        "df-snpn": 30,
        "df-5gprose": 31,
    }

    def test_pe_section_schemas_align_with_section_specs(self) -> None:
        """Every salvaged ``pe_type`` must have a corresponding section spec."""

        from SIMCARD.saip_profile import _PE_SECTION_SCHEMAS, _SECTION_SPECS

        for outer_tag, schema in _PE_SECTION_SCHEMAS.items():
            pe_type = str(schema.get("pe_type") or "").strip()
            self.assertTrue(
                len(pe_type) > 0,
                f"PE section schema {outer_tag.hex().upper()} must declare a pe_type",
            )
            self.assertIn(
                pe_type,
                _SECTION_SPECS,
                f"Salvaged pe_type {pe_type!r} has no entry in _SECTION_SPECS",
            )
            fields = schema.get("fields") or {}
            self.assertIsInstance(fields, dict)
            self.assertGreater(
                len(fields),
                0,
                f"PE section {pe_type!r} declares no AUTOMATIC TAGS fields",
            )
            # Field indices must start at 0 and be contiguous; a gap
            # means the walker cannot line up with the asn1tools schema.
            indices = sorted(fields.keys())
            self.assertEqual(indices[0], 0)
            self.assertEqual(
                indices,
                list(range(indices[-1] + 1)),
                f"PE section {pe_type!r} has non-contiguous field indices",
            )

    def test_pe_section_schemas_use_automatic_tags_encoding(self) -> None:
        """Outer tag bytes must match the AUTOMATIC TAGS encoding for CHOICE [N]."""

        from SIMCARD.saip_profile import _PE_CHOICE_OUTER_TAGS, _PE_SECTION_SCHEMAS

        pe_type_to_outer_tag = {
            str(schema["pe_type"]): outer_tag
            for outer_tag, schema in _PE_SECTION_SCHEMAS.items()
        }

        for pe_type, choice_index in self._EXPECTED_PE_CHOICE_INDEX.items():
            self.assertIn(
                pe_type,
                pe_type_to_outer_tag,
                f"Missing PE section schema for {pe_type!r}",
            )
            expected_tag = _PE_CHOICE_OUTER_TAGS.get(choice_index)
            self.assertEqual(
                pe_type_to_outer_tag[pe_type],
                expected_tag,
                f"Outer tag for {pe_type!r} does not match CHOICE [{choice_index}]",
            )

    @staticmethod
    def _build_upp_with_bad_pe(outer_tag: bytes, pe_content: bytes) -> bytes:
        pe_tlv = bytes(outer_tag) + bytes([len(pe_content)]) + pe_content
        header_value = (
            bytes([0x82, 0x08]) + b"TestName"
            + bytes([0x83, 0x08]) + bytes.fromhex("6000000000000000")
        )
        header_tlv = bytes([0xA0, len(header_value)]) + header_value
        return header_tlv + pe_tlv

    @staticmethod
    def _file_with_single_content(field_tag_byte: int, payload: bytes) -> bytes:
        """Encode a File slot with a single ``fillFileContent`` alternative."""

        inner = bytes([0x83, len(payload)]) + payload
        return bytes([field_tag_byte, len(inner)]) + inner

    def test_native_salvage_recovers_usim_ef_spn_when_asn1_hangs(self) -> None:
        """
        PE-USIM is the most common asn1tools hang site on live profiles
        (alongside PE-TELECOM). Pin that the native walker recovers
        ``EF.SPN`` (field 13 of PE-USIM → AUTOMATIC TAG [13] = 0xAD) with
        the expected FID and transparent payload even when asn1 cannot
        decode the envelope.
        """
        import time

        from SIMCARD import saip_profile

        ef_spn_payload = bytes.fromhex("010A4C61625F45553031FFFFFFFFFFFFFF")
        ef_spn_tlv = self._file_with_single_content(0xAD, ef_spn_payload)
        usim_header = bytes.fromhex("A003810103")
        pe_content = usim_header + ef_spn_tlv
        upp_bytes = self._build_upp_with_bad_pe(b"\xB3", pe_content)

        class HangingAsn1:
            def decode(self, _type_name, _raw_tlv):
                while True:
                    time.sleep(0.05)

        with mock.patch(
            "SIMCARD.saip_profile._get_saip_asn1",
            return_value=HangingAsn1(),
        ), mock.patch.dict(
            os.environ,
            {"YGGDRASIM_SIM_SAIP_DECODE_TIMEOUT_SECONDS": "0.5"},
            clear=False,
        ):
            image = saip_profile.decode_profile_image(
                upp_bytes,
                default_iccid="",
                default_name="",
            )

        self.assertIsNotNone(image)
        assert image is not None

        adf_usim = next(
            (node for node in image.nodes if node.path == ("MF", "ADF.USIM")),
            None,
        )
        self.assertIsNotNone(
            adf_usim,
            "ADF.USIM root node must be materialised by the usim salvage path",
        )

        ef_spn = next(
            (node for node in image.nodes if node.path == ("MF", "ADF.USIM", "EF.SPN")),
            None,
        )
        self.assertIsNotNone(
            ef_spn,
            "EF.SPN must be recovered by the native PE-USIM walker",
        )
        assert ef_spn is not None
        self.assertEqual(ef_spn.fid.upper(), "6F46")
        self.assertEqual(ef_spn.structure, "transparent")
        self.assertEqual(ef_spn.data, ef_spn_payload)

    def test_native_salvage_recovers_isim_ef_impi_when_asn1_hangs(self) -> None:
        """
        PE-ISIM salvage must materialise ADF.ISIM and its canonical
        EF.IMPI (field 3 → AUTOMATIC TAG [3] = 0xA3).
        """
        import time

        from SIMCARD import saip_profile

        ef_impi_payload = b"sip:user@example.org"
        ef_impi_tlv = self._file_with_single_content(0xA3, ef_impi_payload)
        isim_header = bytes.fromhex("A003810105")
        pe_content = isim_header + ef_impi_tlv
        upp_bytes = self._build_upp_with_bad_pe(b"\xB5", pe_content)

        class HangingAsn1:
            def decode(self, _type_name, _raw_tlv):
                while True:
                    time.sleep(0.05)

        with mock.patch(
            "SIMCARD.saip_profile._get_saip_asn1",
            return_value=HangingAsn1(),
        ), mock.patch.dict(
            os.environ,
            {"YGGDRASIM_SIM_SAIP_DECODE_TIMEOUT_SECONDS": "0.5"},
            clear=False,
        ):
            image = saip_profile.decode_profile_image(
                upp_bytes,
                default_iccid="",
                default_name="",
            )

        self.assertIsNotNone(image)
        assert image is not None

        self.assertTrue(
            any(node.path == ("MF", "ADF.ISIM") for node in image.nodes),
            "ADF.ISIM root must be materialised by the isim salvage path",
        )
        ef_impi = next(
            (node for node in image.nodes if node.path == ("MF", "ADF.ISIM", "EF.IMPI")),
            None,
        )
        self.assertIsNotNone(ef_impi)
        assert ef_impi is not None
        self.assertEqual(ef_impi.fid.upper(), "6F02")
        self.assertEqual(ef_impi.structure, "transparent")
        self.assertEqual(ef_impi.data, ef_impi_payload)

    def test_native_salvage_nests_phonebook_ef_adn_under_df_phonebook(self) -> None:
        """
        A standalone PE-PHONEBOOK envelope (outer tag 0xB7) must place
        ``EF.ADN`` (field 11 → 0xAB) under ``DF.PHONEBOOK`` rather than
        repeating the PE-TELECOM flat layout. This differentiates the
        schema spec from the legacy telecom-nested codepath.
        """
        import time

        from SIMCARD import saip_profile

        ef_adn_payload = b"PBONLY"
        ef_adn_tlv = self._file_with_single_content(0xAB, ef_adn_payload)
        phonebook_header = bytes.fromhex("A003810107")
        pe_content = phonebook_header + ef_adn_tlv
        upp_bytes = self._build_upp_with_bad_pe(b"\xB7", pe_content)

        class HangingAsn1:
            def decode(self, _type_name, _raw_tlv):
                while True:
                    time.sleep(0.05)

        with mock.patch(
            "SIMCARD.saip_profile._get_saip_asn1",
            return_value=HangingAsn1(),
        ), mock.patch.dict(
            os.environ,
            {"YGGDRASIM_SIM_SAIP_DECODE_TIMEOUT_SECONDS": "0.5"},
            clear=False,
        ):
            image = saip_profile.decode_profile_image(
                upp_bytes,
                default_iccid="",
                default_name="",
            )

        self.assertIsNotNone(image)
        assert image is not None

        self.assertTrue(
            any(
                node.path == ("MF", "DF.TELECOM", "DF.PHONEBOOK") for node in image.nodes
            ),
            "DF.PHONEBOOK root must be materialised under DF.TELECOM by the phonebook salvage path",
        )
        ef_adn = next(
            (
                node
                for node in image.nodes
                if node.path == ("MF", "DF.TELECOM", "DF.PHONEBOOK", "EF.ADN")
            ),
            None,
        )
        self.assertIsNotNone(
            ef_adn,
            "EF.ADN from PE-PHONEBOOK must be nested under DF.PHONEBOOK",
        )
        assert ef_adn is not None
        self.assertEqual(ef_adn.fid.upper(), "6F3A")
        self.assertEqual(ef_adn.structure, "linear-fixed")
        self.assertEqual(ef_adn.records, [ef_adn_payload])

    def test_native_salvage_handles_longform_tag_for_df_5gprose(self) -> None:
        """
        PE-DF-5GPROSE lives at CHOICE [31] which AUTOMATIC TAGS encodes
        as the long-form tag ``BF 1F``. The salvage dispatcher must
        recognise the multi-byte outer tag and still walk the File
        contents correctly.
        """
        import time

        from SIMCARD import saip_profile

        ef_prose_st_payload = bytes.fromhex("0102030405")
        ef_prose_tlv = self._file_with_single_content(0xA3, ef_prose_st_payload)
        prose_header = bytes.fromhex("A00381010B")
        pe_content = prose_header + ef_prose_tlv
        # CHOICE [31] -> outer tag BF 1F (constructed context-specific).
        pe_tlv = bytes([0xBF, 0x1F, len(pe_content)]) + pe_content
        header_value = (
            bytes([0x82, 0x08]) + b"TestName"
            + bytes([0x83, 0x08]) + bytes.fromhex("6000000000000000")
        )
        header_tlv = bytes([0xA0, len(header_value)]) + header_value
        upp_bytes = header_tlv + pe_tlv

        class HangingAsn1:
            def decode(self, _type_name, _raw_tlv):
                while True:
                    time.sleep(0.05)

        with mock.patch(
            "SIMCARD.saip_profile._get_saip_asn1",
            return_value=HangingAsn1(),
        ), mock.patch.dict(
            os.environ,
            {"YGGDRASIM_SIM_SAIP_DECODE_TIMEOUT_SECONDS": "0.5"},
            clear=False,
        ):
            image = saip_profile.decode_profile_image(
                upp_bytes,
                default_iccid="",
                default_name="",
            )

        self.assertIsNotNone(image)
        assert image is not None

        prose_root = next(
            (
                node
                for node in image.nodes
                if node.path == ("MF", "ADF.USIM", "DF.5G_PROSE")
            ),
            None,
        )
        self.assertIsNotNone(
            prose_root,
            "DF.5G_PROSE root must be materialised from the BF 1F envelope",
        )
        ef_prose_st = next(
            (
                node
                for node in image.nodes
                if node.path
                == ("MF", "ADF.USIM", "DF.5G_PROSE", "EF.5G-PROSE-ST")
            ),
            None,
        )
        self.assertIsNotNone(ef_prose_st)
        assert ef_prose_st is not None
        self.assertEqual(ef_prose_st.data, ef_prose_st_payload)

    def test_native_salvage_skips_non_file_section_outer_tags(self) -> None:
        """
        Non-file ProfileElement alternatives (header, pinCodes,
        akaParameter, rfu1..rfu5, application, rfm, nonStandard, end,
        genericFileManagement) do not belong in ``_PE_SECTION_SCHEMAS``
        and must therefore be skipped by the salvage dispatcher. This
        ensures a PE-PINCodes or PE-AKAParameter that happens to trip
        asn1tools does not get routed through the File walker (which
        would produce garbage because those PEs are not SEQUENCE-OF-
        File).
        """
        from SIMCARD.saip_profile import (
            _PE_SECTION_SCHEMAS,
            _salvage_profile_element_natively,
        )

        non_file_tags = [
            b"\xA0",  # header
            b"\xA1",  # genericFileManagement
            b"\xA2",  # pinCodes
            b"\xA3",  # pukCodes
            b"\xA4",  # akaParameter
            b"\xA5",  # cdmaParameter
            b"\xA6",  # securityDomain
            b"\xA7",  # rfm
            b"\xA8",  # application
            b"\xA9",  # nonStandard
            b"\xAA",  # end
            b"\xAB",  # rfu1
            b"\xAF",  # rfu5
        ]

        for tag in non_file_tags:
            self.assertNotIn(
                tag,
                _PE_SECTION_SCHEMAS,
                f"Non-file ProfileElement tag {tag.hex().upper()} must not be in schemas",
            )
            dummy_tlv = bytes(tag) + b"\x00"
            self.assertIsNone(
                _salvage_profile_element_natively(dummy_tlv),
                f"Salvage must return None for non-file outer tag {tag.hex().upper()}",
            )


class ProfileStoreLoadPrefersJsonImageTests(unittest.TestCase):
    """
    Regression: ``load_profiles_from_store`` used to re-run
    ``decode_profile_image`` on the raw UPP for every profile whose
    manifest declared ``profile_source == 'upp'`` (which is the default
    for BPP-installed profiles). When the UPP contained a pathological
    ProfileElement the resulting decode thread leaked several GB of RAM
    on every tool launch. Pin that the JSON image cache is always
    preferred and the UPP decode path is only used as a fallback when
    the JSON side-file is absent.
    """

    def test_json_image_cache_is_preferred_even_when_manifest_says_upp(self) -> None:
        from SIMCARD import profile_store
        from SIMCARD.state import (
            SimProfileAuthConfig,
            SimProfileEntry,
            SimProfileFsNode,
            SimProfileImage,
        )

        with tempfile.TemporaryDirectory() as store_root:
            profile = SimProfileEntry(
                aid="A0000005591010FFFFFFFF8900001100",
                iccid="89880811111111111112",
                state="disabled",
                profile_class="operational",
                nickname="Lab (EU 01)",
                service_provider="",
                profile_name="Lab EU 01",
                imsi="001010123456789",
                impi="",
                notification_address="",
                # Non-empty UPP so sync_profiles_to_store writes
                # profile_source="upp" into the manifest.
                upp_bytes=b"\xA0\x04\x82\x02AB",
                profile_image=SimProfileImage(
                    profile_name="Lab EU 01",
                    iccid="89880811111111111112",
                    imsi="001010123456789",
                    impi="",
                    nodes=[
                        SimProfileFsNode(
                            path=("MF", "EF.IMSI"),
                            name="EF.IMSI",
                            kind="ef",
                            fid="6F07",
                            structure="transparent",
                            data=bytes.fromhex("08091010123456789F"),
                        ),
                    ],
                ),
                auth_config=SimProfileAuthConfig(
                    algorithm="milenage",
                    ki=bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
                    opc=bytes.fromhex("FFEEDDCCBBAA99887766554433221100"),
                ),
            )
            profile_store.sync_profiles_to_store(store_root, [profile])

            profile_dir = next(
                path for path in Path(store_root).iterdir() if path.is_dir()
            )
            manifest_path = profile_dir / "manifest.json"
            self.assertTrue(manifest_path.is_file())
            image_path = profile_dir / "profile_image.json"
            self.assertTrue(image_path.is_file())

            with mock.patch(
                "SIMCARD.profile_store.decode_profile_image",
                autospec=True,
            ) as decode_mock:
                loaded = profile_store.load_profiles_from_store(store_root)

            self.assertEqual(
                decode_mock.call_count,
                0,
                "load_profiles_from_store must not re-decode the UPP when the JSON image is cached",
            )
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].aid, profile.aid)
            self.assertEqual(loaded[0].iccid, profile.iccid)
            self.assertEqual(loaded[0].profile_name, profile.profile_name)
            self.assertIsNotNone(loaded[0].profile_image)

    def test_upp_is_redecoded_only_when_json_image_cache_is_missing(self) -> None:
        from SIMCARD import profile_store
        from SIMCARD.state import (
            SimProfileAuthConfig,
            SimProfileEntry,
            SimProfileFsNode,
            SimProfileImage,
        )

        with tempfile.TemporaryDirectory() as store_root:
            profile = SimProfileEntry(
                aid="A0000005591010FFFFFFFF8900001100",
                iccid="89880811111111111112",
                state="disabled",
                profile_class="operational",
                nickname="Lab (EU 01)",
                service_provider="",
                profile_name="Lab EU 01",
                imsi="001010123456789",
                impi="",
                notification_address="",
                upp_bytes=b"\xA0\x04\x82\x02AB",
                profile_image=SimProfileImage(
                    profile_name="Lab EU 01",
                    iccid="89880811111111111112",
                    imsi="001010123456789",
                    impi="",
                    nodes=[
                        SimProfileFsNode(
                            path=("MF", "EF.IMSI"),
                            name="EF.IMSI",
                            kind="ef",
                            fid="6F07",
                            structure="transparent",
                            data=bytes.fromhex("08091010123456789F"),
                        ),
                    ],
                ),
                auth_config=SimProfileAuthConfig(
                    algorithm="milenage",
                    ki=bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
                    opc=bytes.fromhex("FFEEDDCCBBAA99887766554433221100"),
                ),
            )
            profile_store.sync_profiles_to_store(store_root, [profile])

            profile_dir = next(
                path for path in Path(store_root).iterdir() if path.is_dir()
            )
            image_path = profile_dir / "profile_image.json"
            image_path.unlink()

            decoded_image = SimProfileImage(
                profile_name="Lab EU 01",
                iccid="89880811111111111112",
                imsi="001010123456789",
                impi="",
                nodes=[],
            )
            with mock.patch(
                "SIMCARD.profile_store.decode_profile_image",
                autospec=True,
                return_value=decoded_image,
            ) as decode_mock:
                loaded = profile_store.load_profiles_from_store(store_root)

            self.assertEqual(
                decode_mock.call_count,
                1,
                "UPP decode must be the fallback when the JSON image is absent",
            )
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].iccid, profile.iccid)


class SimulatedBackendIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                SIM_EIM_IDENTITY_ENV: "",
                SIM_EUICC_STORE_ENV: str(Path(self._temp_dir.name) / "euicc"),
                SIM_ISDR_CONFIG_ENV: str(Path(self._temp_dir.name) / "missing_isdr_config.json"),
                SIM_PROFILE_STORE_ENV: str(Path(self._temp_dir.name) / "profiles"),
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._temp_dir.cleanup()

    def test_scp11_factory_uses_simulated_connection_when_backend_is_sim(self) -> None:
        cfg = types.SimpleNamespace(
            TRANSPORT_MODE="pcsc",
            READER_INDEX=0,
            RELAY_URL="",
            RELAY_TIMEOUT_SECONDS=30,
            RELAY_VERIFY_TLS=True,
            RELAY_SESSION_ID="",
        )
        with mock.patch.dict(os.environ, {CARD_BACKEND_ENV: "sim"}, clear=False):
            channel = build_apdu_channel(cfg)

        self.assertEqual(channel.__class__.__name__, "PcscApduChannel")
        self.assertEqual(channel._conn.__class__.__name__, "SimulatedCardConnection")


class MainWrapperCardBackendTests(unittest.TestCase):
    def test_wrapper_card_backend_flag_sets_sim_backend_and_runtime_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = str(Path(temp_dir) / "runtime_root")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "reader",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: "",
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                    exit_code = main_wrapper.run_cli(
                        [
                            "--card-backend",
                            "sim",
                            "--sim-isdr-config",
                            "/tmp/yggdrasim_isdr_config.json",
                            "--sim-quirks",
                            "/tmp/yggdrasim_sim_quirks.py",
                            "--sim-eim-identity",
                            "/tmp/yggdrasim_sim_eim_identity.json",
                            "--sim-euicc-store",
                            "/tmp/yggdrasim_sim_euicc",
                            "--sim-profile-store",
                            "/tmp/yggdrasim_sim_profiles",
                        ]
                    )
                    backend_value = os.environ.get(CARD_BACKEND_ENV)
                    isdr_config_value = os.environ.get(SIM_ISDR_CONFIG_ENV)
                    quirks_value = os.environ.get(SIM_QUIRKS_ENV)
                    eim_identity_value = os.environ.get(SIM_EIM_IDENTITY_ENV)
                    euicc_store_value = os.environ.get(SIM_EUICC_STORE_ENV)
                    profile_store_value = os.environ.get(SIM_PROFILE_STORE_ENV)

        self.assertEqual(exit_code, 0)
        self.assertEqual(backend_value, "sim")
        self.assertEqual(isdr_config_value, "/tmp/yggdrasim_isdr_config.json")
        self.assertEqual(quirks_value, "/tmp/yggdrasim_sim_quirks.py")
        self.assertEqual(eim_identity_value, "/tmp/yggdrasim_sim_eim_identity.json")
        self.assertEqual(euicc_store_value, "/tmp/yggdrasim_sim_euicc")
        self.assertEqual(profile_store_value, "/tmp/yggdrasim_sim_profiles")
        mocked_menu.assert_called_once_with()

    def test_wrapper_can_import_saip_profile_into_simulator_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_path = Path(temp_dir) / "wrapper_import.der"
            artifact_path.write_bytes(
                build_minimal_saip_upp(
                    iccid="89881111111111111155",
                    imsi="1234567812345678",
                    impi="wrapper@sim.test",
                    profile_name="Wrapper Import",
                )
            )
            euicc_root = str(Path(temp_dir) / "euicc")
            runtime_root = str(Path(temp_dir) / "runtime_root")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "reader",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: str(Path(temp_dir) / "missing_isdr_config.json"),
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                    exit_code = main_wrapper.run_cli(
                        [
                            "--sim-import-profile",
                            str(artifact_path),
                            "--sim-import-enable",
                            "--sim-euicc-store",
                            euicc_root,
                        ]
                    )
                    backend_value = os.environ.get(CARD_BACKEND_ENV)
            self.assertEqual(exit_code, 0)
            self.assertEqual(backend_value, "sim")
            mocked_menu.assert_called_once_with()

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=euicc_root)
            imported = [
                profile for profile in recreated_engine.state.profiles if profile.profile_name == "Wrapper Import"
            ]
            self.assertEqual(len(imported), 1)
            self.assertEqual(imported[0].iccid, "89881111111111111155")
            self.assertEqual(imported[0].state, "enabled")

    def test_runtime_settings_menu_can_update_simulator_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            isdr_path = str(Path(temp_dir) / "runtime_isdr.json")
            quirks_path = str(Path(temp_dir) / "runtime_quirks.py")
            eim_identity_path = str(Path(temp_dir) / "runtime_eim_identity.json")
            euicc_root = str(Path(temp_dir) / "runtime_euicc")
            profile_root = str(Path(temp_dir) / "runtime_profiles")
            runtime_root = str(Path(temp_dir) / "runtime_root")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "reader",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: "",
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                with mock.patch.object(main_wrapper, "clear_screen"), mock.patch.object(
                    main_wrapper, "pause"
                ), mock.patch(
                    "builtins.input",
                    side_effect=[
                        "2",
                        "3",
                        isdr_path,
                        "4",
                        quirks_path,
                        "E",
                        eim_identity_path,
                        "5",
                        euicc_root,
                        "6",
                        profile_root,
                        "Q",
                    ],
                ):
                    main_wrapper.configure_card_backend()
                    backend_value = os.environ.get(CARD_BACKEND_ENV)
                    isdr_value = os.environ.get(SIM_ISDR_CONFIG_ENV)
                    quirks_value = os.environ.get(SIM_QUIRKS_ENV)
                    eim_identity_value = os.environ.get(SIM_EIM_IDENTITY_ENV)
                    euicc_value = os.environ.get(SIM_EUICC_STORE_ENV)
                    profile_value = os.environ.get(SIM_PROFILE_STORE_ENV)

        self.assertEqual(backend_value, "sim")
        self.assertEqual(isdr_value, isdr_path)
        self.assertEqual(quirks_value, quirks_path)
        self.assertEqual(eim_identity_value, eim_identity_path)
        self.assertEqual(euicc_value, euicc_root)
        self.assertEqual(profile_value, profile_root)

    def test_runtime_settings_menu_can_import_profile_into_simulator_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_path = Path(temp_dir) / "runtime_menu_import.profile_image.json"
            artifact_path.write_text(
                json.dumps(
                    {
                        "profile_name": "Runtime Menu Import",
                        "iccid": "89881111111111111166",
                        "imsi": "1234567812345678",
                        "impi": "runtime@sim.test",
                        "nodes": [
                            {
                                "path": ["MF", "EF.ICCID"],
                                "name": "EF.ICCID",
                                "kind": "ef",
                                "fid": "2FE2",
                                "structure": "transparent",
                                "data_hex": encode_iccid_ef("89881111111111111166").hex().upper(),
                                "records_hex": [],
                                "aid": "",
                                "label": "",
                                "sfi": None,
                            },
                            {
                                "path": ["MF", "ADF.USIM", "EF.IMSI"],
                                "name": "EF.IMSI",
                                "kind": "ef",
                                "fid": "6F07",
                                "structure": "transparent",
                                "data_hex": encode_imsi_ef("1234567812345678").hex().upper(),
                                "records_hex": [],
                                "aid": "",
                                "label": "",
                                "sfi": None,
                            },
                        ],
                    },
                    indent=2,
                )
            )
            euicc_root = str(Path(temp_dir) / "runtime_menu_euicc")
            runtime_root = str(Path(temp_dir) / "runtime_root")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "reader",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: str(Path(temp_dir) / "missing_runtime_isdr.json"),
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: euicc_root,
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                with mock.patch.object(main_wrapper, "clear_screen"), mock.patch.object(
                    main_wrapper, "pause"
                ), mock.patch(
                    "builtins.input",
                    side_effect=["7", str(artifact_path), "Y", "Q"],
                ):
                    main_wrapper.configure_card_backend()
                    backend_value = os.environ.get(CARD_BACKEND_ENV)

            recreated_engine = SimulatedSimCardEngine(euicc_store_root=euicc_root)
            imported = [
                profile
                for profile in recreated_engine.state.profiles
                if profile.profile_name == "Runtime Menu Import"
            ]

        self.assertEqual(backend_value, "sim")
        self.assertEqual(len(imported), 1)
        self.assertEqual(imported[0].iccid, "89881111111111111166")
        self.assertEqual(imported[0].state, "enabled")

    def test_runtime_settings_menu_can_reset_simulator_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime_root"
            runtime_root.mkdir(parents=True, exist_ok=True)
            override_isdr = Path(temp_dir) / "override_isdr.json"
            override_quirks = Path(temp_dir) / "override_quirks.py"
            override_eim_identity = Path(temp_dir) / "override_eim_identity.json"
            override_euicc_root = Path(temp_dir) / "override_euicc"
            override_profile_root = Path(temp_dir) / "override_profiles"
            override_isdr.write_text('{"override": true}\n', encoding="utf-8")
            override_quirks.write_text('metadata_overrides = {"default_dp_address": "override.test"}\n', encoding="utf-8")
            override_eim_identity.write_text('{"eim_id": "override-eim"}\n', encoding="utf-8")
            override_euicc_root.mkdir(parents=True, exist_ok=True)
            (override_euicc_root / "stale.txt").write_text("stale\n", encoding="utf-8")
            override_profile_root.mkdir(parents=True, exist_ok=True)
            (override_profile_root / "stale.txt").write_text("stale\n", encoding="utf-8")

            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": str(runtime_root),
                    "YGGDRASIM_ALLOW_QUIRKS": "1",
                    CARD_BACKEND_ENV: "reader",
                    SIM_EIM_IDENTITY_ENV: str(override_eim_identity),
                    SIM_ISDR_CONFIG_ENV: str(override_isdr),
                    SIM_QUIRKS_ENV: str(override_quirks),
                    SIM_EUICC_STORE_ENV: str(override_euicc_root),
                    SIM_PROFILE_STORE_ENV: str(override_profile_root),
                },
                clear=False,
            ):
                default_isdr_path = Path(main_wrapper.get_default_sim_isdr_config_path())
                default_quirks_path = Path(main_wrapper.get_default_sim_quirks_path())
                default_eim_identity_path = Path(main_wrapper.get_default_sim_eim_identity_path())
                default_isdr_path.write_text('{"stale_default": true}\n', encoding="utf-8")
                default_quirks_path.write_text('metadata_overrides = {"default_dp_address": "stale.test"}\n', encoding="utf-8")
                default_eim_identity_path.write_text('{"stale_identity": true}\n', encoding="utf-8")

                with mock.patch.object(main_wrapper, "clear_screen"), mock.patch.object(
                    main_wrapper, "pause"
                ), mock.patch(
                    "builtins.input",
                    side_effect=["9", "Y", "Q"],
                ):
                    main_wrapper.configure_card_backend()
                    backend_value = os.environ.get(CARD_BACKEND_ENV)
                    eim_identity_value = os.environ.get(SIM_EIM_IDENTITY_ENV)
                    isdr_value = os.environ.get(SIM_ISDR_CONFIG_ENV)
                    quirks_value = os.environ.get(SIM_QUIRKS_ENV)
                    euicc_value = os.environ.get(SIM_EUICC_STORE_ENV)
                    profile_value = os.environ.get(SIM_PROFILE_STORE_ENV)
                    reset_isdr_text = Path(main_wrapper.get_default_sim_isdr_config_path()).read_text(encoding="utf-8")
                    reset_quirks_text = Path(main_wrapper.get_default_sim_quirks_path()).read_text(encoding="utf-8")
                    reset_eim_identity_text = Path(main_wrapper.get_default_sim_eim_identity_path()).read_text(
                        encoding="utf-8"
                    )
                    default_euicc_root = Path(main_wrapper.get_default_sim_euicc_store_root())

            self.assertEqual(backend_value, "sim")
            self.assertIsNone(eim_identity_value)
            self.assertIsNone(isdr_value)
            self.assertIsNone(quirks_value)
            self.assertIsNone(euicc_value)
            self.assertIsNone(profile_value)
            self.assertTrue(override_eim_identity.exists())
            self.assertFalse(override_euicc_root.exists())
            self.assertFalse(override_profile_root.exists())
            self.assertTrue(default_euicc_root.is_dir())
            self.assertNotIn("stale_default", reset_isdr_text)
            self.assertIn("default_dp_address", reset_isdr_text)
            self.assertIn("metadata_overrides = {}", reset_quirks_text)
            self.assertNotIn("stale_identity", reset_eim_identity_text)
            self.assertIn("eim_id", reset_eim_identity_text)

    def test_wrapper_reuses_persisted_card_backend_when_flag_is_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = str(Path(temp_dir) / "runtime_root")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: "",
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                main_wrapper.set_card_backend("sim")
                os.environ.pop(CARD_BACKEND_ENV, None)
                with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                    exit_code = main_wrapper.run_cli([])
                    backend_value = os.environ.get(CARD_BACKEND_ENV)

        self.assertEqual(exit_code, 0)
        self.assertEqual(backend_value, "sim")
        mocked_menu.assert_called_once_with()

    def test_wrapper_card_backend_flag_does_not_overwrite_persisted_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = str(Path(temp_dir) / "runtime_root")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: "",
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                main_wrapper.set_card_backend("sim")
                os.environ.pop(CARD_BACKEND_ENV, None)
                with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                    exit_code = main_wrapper.run_cli(["--card-backend", "reader"])
                    backend_value = os.environ.get(CARD_BACKEND_ENV)
                os.environ.pop(CARD_BACKEND_ENV, None)
                persisted_backend = main_wrapper.get_card_backend()

        self.assertEqual(exit_code, 0)
        self.assertEqual(backend_value, "reader")
        self.assertEqual(persisted_backend, "sim")
        mocked_menu.assert_called_once_with()

    def test_wrapper_reuses_persisted_simulator_paths_when_flags_are_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = str(Path(temp_dir) / "runtime_root")
            persisted_isdr = str(Path(temp_dir) / "persisted_isdr.json")
            persisted_quirks = str(Path(temp_dir) / "persisted_quirks.py")
            persisted_eim_identity = str(Path(temp_dir) / "persisted_eim_identity.json")
            persisted_euicc = str(Path(temp_dir) / "persisted_euicc")
            persisted_profile = str(Path(temp_dir) / "persisted_profiles")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: "",
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                main_wrapper.set_sim_isdr_config_path(persisted_isdr)
                main_wrapper.set_sim_quirks_path(persisted_quirks)
                main_wrapper.set_sim_eim_identity_path(persisted_eim_identity)
                main_wrapper.set_sim_euicc_store_root(persisted_euicc)
                main_wrapper.set_sim_profile_store_path(persisted_profile)
                os.environ.pop(SIM_EIM_IDENTITY_ENV, None)
                os.environ.pop(SIM_ISDR_CONFIG_ENV, None)
                os.environ.pop(SIM_QUIRKS_ENV, None)
                os.environ.pop(SIM_EUICC_STORE_ENV, None)
                os.environ.pop(SIM_PROFILE_STORE_ENV, None)
                with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                    exit_code = main_wrapper.run_cli([])
                resolved_eim_identity = main_wrapper.get_sim_eim_identity_path()
                resolved_isdr = main_wrapper.get_sim_isdr_config_path()
                resolved_quirks = main_wrapper.get_sim_quirks_path()
                resolved_euicc = main_wrapper.get_sim_euicc_store_root()
                resolved_profile = main_wrapper.get_sim_profile_store_path()

        self.assertEqual(exit_code, 0)
        self.assertEqual(resolved_eim_identity, persisted_eim_identity)
        self.assertEqual(resolved_isdr, persisted_isdr)
        self.assertEqual(resolved_quirks, persisted_quirks)
        self.assertEqual(resolved_euicc, persisted_euicc)
        self.assertEqual(resolved_profile, persisted_profile)
        mocked_menu.assert_called_once_with()

    def test_wrapper_simulator_path_flags_do_not_overwrite_persisted_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = str(Path(temp_dir) / "runtime_root")
            persisted_isdr = str(Path(temp_dir) / "persisted_isdr.json")
            persisted_quirks = str(Path(temp_dir) / "persisted_quirks.py")
            persisted_eim_identity = str(Path(temp_dir) / "persisted_eim_identity.json")
            persisted_euicc = str(Path(temp_dir) / "persisted_euicc")
            persisted_profile = str(Path(temp_dir) / "persisted_profiles")
            cli_isdr = str(Path(temp_dir) / "cli_isdr.json")
            cli_quirks = str(Path(temp_dir) / "cli_quirks.py")
            cli_eim_identity = str(Path(temp_dir) / "cli_eim_identity.json")
            cli_euicc = str(Path(temp_dir) / "cli_euicc")
            cli_profile = str(Path(temp_dir) / "cli_profiles")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: "",
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                main_wrapper.set_sim_isdr_config_path(persisted_isdr)
                main_wrapper.set_sim_quirks_path(persisted_quirks)
                main_wrapper.set_sim_eim_identity_path(persisted_eim_identity)
                main_wrapper.set_sim_euicc_store_root(persisted_euicc)
                main_wrapper.set_sim_profile_store_path(persisted_profile)
                os.environ.pop(SIM_EIM_IDENTITY_ENV, None)
                os.environ.pop(SIM_ISDR_CONFIG_ENV, None)
                os.environ.pop(SIM_QUIRKS_ENV, None)
                os.environ.pop(SIM_EUICC_STORE_ENV, None)
                os.environ.pop(SIM_PROFILE_STORE_ENV, None)
                with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                    exit_code = main_wrapper.run_cli(
                        [
                            "--sim-isdr-config",
                            cli_isdr,
                            "--sim-quirks",
                            cli_quirks,
                            "--sim-eim-identity",
                            cli_eim_identity,
                            "--sim-euicc-store",
                            cli_euicc,
                            "--sim-profile-store",
                            cli_profile,
                        ]
                    )
                    runtime_eim_identity = os.environ.get(SIM_EIM_IDENTITY_ENV)
                    runtime_isdr = os.environ.get(SIM_ISDR_CONFIG_ENV)
                    runtime_quirks = os.environ.get(SIM_QUIRKS_ENV)
                    runtime_euicc = os.environ.get(SIM_EUICC_STORE_ENV)
                    runtime_profile = os.environ.get(SIM_PROFILE_STORE_ENV)
                os.environ.pop(SIM_EIM_IDENTITY_ENV, None)
                os.environ.pop(SIM_ISDR_CONFIG_ENV, None)
                os.environ.pop(SIM_QUIRKS_ENV, None)
                os.environ.pop(SIM_EUICC_STORE_ENV, None)
                os.environ.pop(SIM_PROFILE_STORE_ENV, None)
                resolved_eim_identity = main_wrapper.get_sim_eim_identity_path()
                resolved_isdr = main_wrapper.get_sim_isdr_config_path()
                resolved_quirks = main_wrapper.get_sim_quirks_path()
                resolved_euicc = main_wrapper.get_sim_euicc_store_root()
                resolved_profile = main_wrapper.get_sim_profile_store_path()

        self.assertEqual(exit_code, 0)
        self.assertEqual(runtime_eim_identity, cli_eim_identity)
        self.assertEqual(runtime_isdr, cli_isdr)
        self.assertEqual(runtime_quirks, cli_quirks)
        self.assertEqual(runtime_euicc, cli_euicc)
        self.assertEqual(runtime_profile, cli_profile)
        self.assertEqual(resolved_eim_identity, persisted_eim_identity)
        self.assertEqual(resolved_isdr, persisted_isdr)
        self.assertEqual(resolved_quirks, persisted_quirks)
        self.assertEqual(resolved_euicc, persisted_euicc)
        self.assertEqual(resolved_profile, persisted_profile)
        mocked_menu.assert_called_once_with()

    def test_runtime_settings_menu_shows_value_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = str(Path(temp_dir) / "runtime_root")
            persisted_isdr = str(Path(temp_dir) / "persisted_isdr.json")
            persisted_eim_identity = str(Path(temp_dir) / "persisted_eim_identity.json")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: "",
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                main_wrapper.set_card_backend("sim")
                main_wrapper.set_sim_isdr_config_path(persisted_isdr)
                main_wrapper.set_sim_eim_identity_path(persisted_eim_identity)
                os.environ.pop(CARD_BACKEND_ENV, None)
                os.environ.pop(SIM_EIM_IDENTITY_ENV, None)
                os.environ.pop(SIM_ISDR_CONFIG_ENV, None)
                os.environ.pop(SIM_QUIRKS_ENV, None)
                os.environ.pop(SIM_EUICC_STORE_ENV, None)
                os.environ.pop(SIM_PROFILE_STORE_ENV, None)
                with mock.patch.object(main_wrapper, "clear_screen"), mock.patch.object(
                    main_wrapper, "pause"
                ), mock.patch(
                    "builtins.input",
                    side_effect=["Q"],
                ):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        main_wrapper.configure_card_backend()
                rendered = output.getvalue()

        self.assertIn("saved selection", rendered)
        self.assertIn(f"{persisted_isdr} [saved override]", rendered)
        self.assertIn(f"{persisted_eim_identity} [saved override]", rendered)
        self.assertIn("Quirks file", rendered)
        self.assertIn("[workspace default]", rendered)
        self.assertIn(
            "Profile store        : (derived from eUICC store root + active EID) [derived default]",
            rendered,
        )

    def test_main_menu_banner_shows_simulator_override_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = str(Path(temp_dir) / "runtime_root")
            persisted_isdr = str(Path(temp_dir) / "persisted_isdr.json")
            persisted_eim_identity = str(Path(temp_dir) / "persisted_eim_identity.json")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "",
                    SIM_EIM_IDENTITY_ENV: "",
                    SIM_ISDR_CONFIG_ENV: "",
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    SIM_PROFILE_STORE_ENV: "",
                },
                clear=False,
            ):
                main_wrapper.set_card_backend("sim")
                main_wrapper.set_sim_isdr_config_path(persisted_isdr)
                main_wrapper.set_sim_eim_identity_path(persisted_eim_identity)
                os.environ.pop(CARD_BACKEND_ENV, None)
                os.environ.pop(SIM_EIM_IDENTITY_ENV, None)
                os.environ.pop(SIM_ISDR_CONFIG_ENV, None)
                os.environ.pop(SIM_QUIRKS_ENV, None)
                os.environ.pop(SIM_EUICC_STORE_ENV, None)
                os.environ.pop(SIM_PROFILE_STORE_ENV, None)
                with mock.patch.object(main_wrapper, "clear_screen"), mock.patch(
                    "builtins.input",
                    side_effect=["Q"],
                ):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        with self.assertRaises(SystemExit):
                            main_wrapper.main_menu()
                rendered = output.getvalue()

        self.assertIn("Active card backend:", rendered)
        self.assertIn("saved selection", rendered)
        self.assertIn(f"ISDR config          : {persisted_isdr} [saved override]", rendered)
        self.assertIn(f"eIM identity         : {persisted_eim_identity} [saved override]", rendered)


if __name__ == "__main__":
    unittest.main()
