# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-live pySim support: codec and OTA keyset wrappers for the live physical-reader variant."""
import os
from typing import Any, List, Optional

from cryptography import x509 as crypto_x509
from yggdrasim_common.process_debug import suppress_noisy_crypto_warnings

try:
    from ..pysim_path import ensure_repo_pysim_on_path
except ImportError:
    from SCP11.pysim_path import ensure_repo_pysim_on_path

ensure_repo_pysim_on_path()

try:
    from pySim.esim import compile_asn1_subdir
    from pySim.esim import rsp as pysim_rsp
    from pySim.esim import x509_cert as pysim_x509
except ImportError:
    compile_asn1_subdir = None
    pysim_rsp = None
    pysim_x509 = None


_PY_SIM_RSP_ASN1 = None
if compile_asn1_subdir is not None:
    try:
        _PY_SIM_RSP_ASN1 = compile_asn1_subdir("rsp")
    except Exception:
        _PY_SIM_RSP_ASN1 = None


def pysim_available() -> bool:
    """Return True when the pySim RSP ASN.1 codec is importable in the current environment."""
    if _PY_SIM_RSP_ASN1 is None:
        return False
    if pysim_rsp is None:
        return False
    if pysim_x509 is None:
        return False
    return True


def pysim_rsp_asn1() -> Optional[Any]:
    if pysim_available() is False:
        return None
    return _PY_SIM_RSP_ASN1


def encode_rsp_type(type_name: str, payload: Any) -> bytes:
    asn1 = pysim_rsp_asn1()
    if asn1 is None:
        return b""
    return asn1.encode(str(type_name), payload)


def decode_rsp_type(type_name: str, payload: bytes) -> Any:
    asn1 = pysim_rsp_asn1()
    if asn1 is None:
        return None
    return asn1.decode(str(type_name), bytes(payload))


def unwrap_tlv_octet_string(value: bytes, tag_bytes: bytes) -> bytes:
    """Strip a BER-TLV OCTET STRING wrapper and return the raw payload bytes."""
    raw_value = bytes(value)
    wanted_tag = bytes(tag_bytes)
    if raw_value.startswith(wanted_tag) is False:
        return raw_value

    offset = len(wanted_tag)
    if offset >= len(raw_value):
        return raw_value

    first = raw_value[offset]
    if first < 0x80:
        length = first
        length_size = 1
    else:
        count = first & 0x7F
        if count == 0:
            return raw_value
        end = offset + 1 + count
        if end > len(raw_value):
            return raw_value
        length = int.from_bytes(raw_value[offset + 1:end], "big")
        length_size = 1 + count

    value_start = offset + length_size
    value_end = value_start + length
    if value_end != len(raw_value):
        return raw_value
    return raw_value[value_start:value_end]


def extract_euicc_signed1(authenticate_server_response: bytes) -> bytes:
    if pysim_available() is False:
        return b""
    return pysim_rsp.extract_euiccSigned1(authenticate_server_response)


def extract_euicc_signed2(prepare_download_response: bytes) -> bytes:
    if pysim_available() is False:
        return b""
    return pysim_rsp.extract_euiccSigned2(prepare_download_response)


def encode_server_signed1(
    transaction_id: bytes,
    euicc_challenge: bytes,
    server_address: str,
    server_challenge: bytes,
) -> bytes:
    """Encode a ServerSigned1 structure for ES9+.AuthenticateClient (SGP.22 §5.7.14)."""
    payload = {
        "transactionId": bytes(transaction_id),
        "euiccChallenge": bytes(euicc_challenge),
        "serverAddress": str(server_address),
        "serverChallenge": bytes(server_challenge),
    }
    return encode_rsp_type("ServerSigned1", payload)


def decode_certificate(certificate_der: bytes) -> Any:
    return decode_rsp_type("Certificate", certificate_der)


def encode_smdp_signed2(
    transaction_id: bytes,
    cc_required_flag: bool,
    bpp_euicc_otpk: bytes = b"",
) -> bytes:
    """Encode an SmdpSigned2 structure for ES9+.GetBoundProfilePackage (SGP.22 §5.7.15)."""
    payload = {
        "transactionId": bytes(transaction_id),
        "ccRequiredFlag": bool(cc_required_flag),
    }
    if len(bpp_euicc_otpk) > 0:
        payload["bppEuiccOtpk"] = bytes(bpp_euicc_otpk)
    return encode_rsp_type("SmdpSigned2", payload)


def encode_ctx_params1(ctx_params: dict) -> bytes:
    return encode_rsp_type("CtxParams1", ("ctxParamsForCommonAuthentication", ctx_params))


def encode_authenticate_server_request(
    server_signed1_der: bytes,
    server_signature1: bytes,
    euicc_ci_pk_id_to_be_used: bytes,
    server_certificate_der: bytes,
    ctx_params: dict,
) -> bytes:
    """Encode a complete ES9+.AuthenticateClient request payload."""
    decoded_server_signed1 = decode_rsp_type("ServerSigned1", server_signed1_der)
    decoded_server_certificate = decode_certificate(server_certificate_der)
    if decoded_server_signed1 is None:
        return b""
    if decoded_server_certificate is None:
        return b""
    raw_signature = unwrap_tlv_octet_string(server_signature1, bytes.fromhex("5F37"))
    payload = {
        "serverSigned1": decoded_server_signed1,
        "serverSignature1": raw_signature,
        "serverCertificate": decoded_server_certificate,
        "ctxParams1": ("ctxParamsForCommonAuthentication", ctx_params),
    }
    if len(euicc_ci_pk_id_to_be_used) > 0:
        payload["euiccCiPKIdToBeUsed"] = bytes(euicc_ci_pk_id_to_be_used)
    return encode_rsp_type("AuthenticateServerRequest", payload)


def encode_prepare_download_request(
    smdp_signed2_der: bytes,
    smdp_signature2: bytes,
    smdp_certificate_der: bytes,
    hash_cc: bytes = b"",
) -> bytes:
    """Encode an ES9+.PrepareDownload request payload (SGP.22 §5.7.16)."""
    decoded_smdp_signed2 = decode_rsp_type("SmdpSigned2", smdp_signed2_der)
    decoded_smdp_certificate = decode_certificate(smdp_certificate_der)
    if decoded_smdp_signed2 is None:
        return b""
    if decoded_smdp_certificate is None:
        return b""
    payload = {
        "smdpSigned2": decoded_smdp_signed2,
        "smdpSignature2": bytes(smdp_signature2),
        "smdpCertificate": decoded_smdp_certificate,
    }
    if len(hash_cc) > 0:
        payload["hashCc"] = bytes(hash_cc)
    return encode_rsp_type("PrepareDownloadRequest", payload)


def encode_cancel_session_request(transaction_id: bytes, reason: int) -> bytes:
    payload = {
        "transactionId": bytes(transaction_id),
        "reason": int(reason),
    }
    return encode_rsp_type("CancelSessionRequest", payload)


def encode_notification_sent_request(seq_number: int) -> bytes:
    payload = {
        "seqNumber": int(seq_number),
    }
    return encode_rsp_type("NotificationSentRequest", payload)


def decode_authenticate_server_response(authenticate_server_response: bytes) -> Any:
    return decode_rsp_type("AuthenticateServerResponse", authenticate_server_response)


def decode_prepare_download_response(prepare_download_response: bytes) -> Any:
    return decode_rsp_type("PrepareDownloadResponse", prepare_download_response)


def decode_initialise_secure_channel_request(raw_tlv: bytes) -> Any:
    return decode_rsp_type("InitialiseSecureChannelRequest", raw_tlv)


def decode_notification_metadata(raw_tlv: bytes) -> Any:
    return decode_rsp_type("NotificationMetadata", raw_tlv)


def decode_pending_notification(raw_tlv: bytes) -> Any:
    return decode_rsp_type("PendingNotification", raw_tlv)


def decode_retrieve_notifications_list_response(raw_tlv: bytes) -> Any:
    return decode_rsp_type("RetrieveNotificationsListResponse", raw_tlv)


def decode_list_notification_response(raw_tlv: bytes) -> Any:
    return decode_rsp_type("ListNotificationResponse", raw_tlv)


def verify_certificate_against_ca_bundle(certificate_der: bytes, ca_bundle_path: str) -> str:
    """Verify an X.509 DER certificate against a PEM CA bundle using the cryptography library."""
    if pysim_available() is False:
        return ""
    if len(ca_bundle_path.strip()) == 0:
        return ""
    if os.path.exists(ca_bundle_path) is False:
        raise FileNotFoundError(f"CA bundle not found: {ca_bundle_path}")

    leaf_certificate = crypto_x509.load_der_x509_certificate(certificate_der)
    root_certificates = _load_pem_certificates(ca_bundle_path)
    if len(root_certificates) == 0:
        raise ValueError(f"CA bundle did not contain any PEM certificates: {ca_bundle_path}")

    last_error = None
    for root_certificate in root_certificates:
        try:
            certificate_set = pysim_x509.CertificateSet(root_certificate)
            certificate_set.verify_cert_chain(leaf_certificate)
            return root_certificate.subject.rfc4514_string()
        except Exception as error:
            last_error = error

    if last_error is None:
        raise ValueError("Certificate verification failed without a detailed pySim error.")
    raise ValueError(f"Certificate verification failed against supplied CA bundle: {last_error}")


def get_certificate_authority_key_identifier(certificate_der: bytes) -> bytes:
    """Extract the Authority Key Identifier extension bytes from a DER-encoded X.509 certificate."""
    if pysim_available() is False:
        return b""
    try:
        certificate = crypto_x509.load_der_x509_certificate(certificate_der)
        return pysim_x509.cert_get_auth_key_id(certificate)
    except Exception:
        return b""


def _load_pem_certificates(bundle_path: str) -> List[crypto_x509.Certificate]:
    with open(bundle_path, "rb") as bundle_file:
        bundle_data = bundle_file.read()

    certificates = []
    marker = b"-----END CERTIFICATE-----"
    segments = bundle_data.split(marker)
    with suppress_noisy_crypto_warnings():
        for segment in segments:
            cleaned = segment.strip()
            if len(cleaned) == 0:
                continue
            pem_bytes = cleaned + b"\n" + marker + b"\n"
            certificates.append(crypto_x509.load_pem_x509_certificate(pem_bytes))
    return certificates
