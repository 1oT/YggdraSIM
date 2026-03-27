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
# Copyright (c) 2026 Hampus Hellsberg and contributors
# -----------------------------------------------------------------------------

try:
    from pySim.esim import compile_asn1_subdir
except ImportError:
    compile_asn1_subdir = None

try:
    from .asn1_registry import ASN1Registry
    from .crypto_engine import CryptoEngine
    from .pysim_support import (
        encode_authenticate_server_request,
        encode_ctx_params1,
        encode_prepare_download_request,
        encode_smdp_signed2,
    )
except ImportError:
    from asn1_registry import ASN1Registry
    from crypto_engine import CryptoEngine
    from pysim_support import (
        encode_authenticate_server_request,
        encode_ctx_params1,
        encode_prepare_download_request,
        encode_smdp_signed2,
    )

_PY_SIM_RSP_ASN1 = None
if compile_asn1_subdir is not None:
    try:
        _PY_SIM_RSP_ASN1 = compile_asn1_subdir("rsp")
    except Exception:
        _PY_SIM_RSP_ASN1 = None


class PayloadBuilder:
    """Constructs SGP.22 AuthenticateServer and PrepareDownload payloads."""

    @staticmethod
    def build_auth_server(signed1, signature, cert, ctx_params, root_ci_id: bytes = None) -> bytes:
        safe_ctx_params = PayloadBuilder._normalize_ctx_params(ctx_params)
        signed1_der = PayloadBuilder._asn1crypto_or_bytes_to_der(signed1)
        certificate_der = PayloadBuilder._asn1crypto_or_bytes_to_der(cert)

        if _PY_SIM_RSP_ASN1 is not None:
            encoded = encode_authenticate_server_request(
                server_signed1_der=signed1_der,
                server_signature1=bytes(signature),
                euicc_ci_pk_id_to_be_used=bytes(root_ci_id or b""),
                server_certificate_der=certificate_der,
                ctx_params=PayloadBuilder._normalize_pysim_ctx_params(safe_ctx_params),
            )
            if len(encoded) > 0:
                return encoded
            ctx_params_der = PayloadBuilder._build_ctx_params1_with_pysim(safe_ctx_params)
        else:
            ctx_content = ASN1Registry.CtxParamsForCommonAuthentication(safe_ctx_params)
            ctx_choice = ASN1Registry.CtxParams1(
                name="ctxParamsForCommonAuthentication",
                value=ctx_content,
            )
            ctx_params_der = ctx_choice.dump()

        return PayloadBuilder._build_auth_server_request_tlv(
            signed1_der=signed1_der,
            signature=bytes(signature),
            root_ci_id=root_ci_id,
            certificate_der=certificate_der,
            ctx_params_der=ctx_params_der,
        )

    @staticmethod
    def _build_auth_server_request_tlv(
        signed1_der: bytes,
        signature: bytes,
        root_ci_id: bytes,
        certificate_der: bytes,
        ctx_params_der: bytes,
    ) -> bytes:
        raw_signature = PayloadBuilder._unwrap_application_octet_string(
            bytes(signature),
            bytes.fromhex("5F37"),
        )
        value_parts = [
            signed1_der,
            PayloadBuilder._wrap_tlv(bytes.fromhex("5F37"), raw_signature),
        ]
        if root_ci_id is not None and len(root_ci_id) > 0:
            value_parts.append(PayloadBuilder._wrap_tlv(bytes([0x04]), bytes(root_ci_id)))
        value_parts.append(certificate_der)
        value_parts.append(ctx_params_der)
        outer_value = b"".join(value_parts)
        return PayloadBuilder._wrap_tlv(bytes.fromhex("BF38"), outer_value)

    @staticmethod
    def _build_ctx_params1_with_pysim(ctx_params: dict) -> bytes:
        choice_value = PayloadBuilder._normalize_pysim_ctx_params(ctx_params)
        encoded = encode_ctx_params1(choice_value)
        if len(encoded) > 0:
            return encoded
        return _PY_SIM_RSP_ASN1.encode(
            "CtxParams1",
            ("ctxParamsForCommonAuthentication", choice_value),
        )

    @staticmethod
    def _normalize_pysim_ctx_params(ctx_params: dict) -> dict:
        device_info = dict(ctx_params.get("deviceInfo", {}))
        capabilities = dict(device_info.get("deviceCapabilities", {}))
        pysim_device_info = {
            "tac": bytes(device_info.get("tac", b"")),
            "deviceCapabilities": PayloadBuilder._normalize_pysim_capabilities(capabilities),
        }
        choice_value = {
            "deviceInfo": pysim_device_info,
        }
        matching_id = str(ctx_params.get("matchingId", "")).strip()
        if len(matching_id) > 0:
            choice_value["matchingId"] = matching_id
        return choice_value

    @staticmethod
    def _normalize_ctx_params(ctx_params: dict) -> dict:
        normalized = dict(ctx_params)
        device_info = dict(normalized.get("deviceInfo", {}))
        capabilities = dict(device_info.get("deviceCapabilities", {}))
        if len(capabilities) == 0:
            capabilities["gsmSupportedRelease"] = b"\x99\x00\x00"
        if (
            "eutranEpcSupportedRelease" not in capabilities
            and "eutranSupportedRelease" in capabilities
        ):
            capabilities["eutranEpcSupportedRelease"] = capabilities["eutranSupportedRelease"]
        capabilities.pop("eutranSupportedRelease", None)
        device_info["deviceCapabilities"] = capabilities
        normalized["deviceInfo"] = device_info
        return normalized

    @staticmethod
    def _asn1crypto_or_bytes_to_der(value) -> bytes:
        if isinstance(value, bytes):
            return value
        if hasattr(value, "dump"):
            return value.dump()
        raise TypeError(f"Unsupported ASN.1 value type: {type(value)!r}")

    @staticmethod
    def _normalize_pysim_capabilities(capabilities: dict) -> dict:
        normalized = {}
        ordered_fields = [
            "gsmSupportedRelease",
            "utranSupportedRelease",
            "cdma2000onexSupportedRelease",
            "cdma2000hrpdSupportedRelease",
            "cdma2000ehrpdSupportedRelease",
            "eutranSupportedRelease",
            "contactlessSupportedRelease",
            "rspCrlSupportedVersion",
            "rspRpmSupportedVersion",
        ]
        for field_name in ordered_fields:
            value = capabilities.get(field_name)
            if value is None and field_name == "eutranSupportedRelease":
                value = capabilities.get("eutranEpcSupportedRelease")
            if value is None:
                continue
            normalized[field_name] = bytes(value)
        return normalized

    @staticmethod
    def build_prepare_download(transaction_id, euicc_sig1, cert, key) -> bytes:
        smdp_signed2_der = encode_smdp_signed2(
            transaction_id=bytes(transaction_id),
            cc_required_flag=False,
        )
        if len(smdp_signed2_der) == 0:
            smdp_signed2 = ASN1Registry.SmdpSigned2(
                {
                    "transactionId": ASN1Registry.TransactionId(transaction_id),
                    "ccRequiredFlag": False,
                }
            )
            smdp_signed2_der = smdp_signed2.dump()

        euicc_signature1_der = PayloadBuilder._wrap_tlv(
            bytes.fromhex("5F37"),
            PayloadBuilder._unwrap_application_octet_string(
                bytes(euicc_sig1),
                bytes.fromhex("5F37"),
            ),
        )
        raw_to_sign = smdp_signed2_der + euicc_signature1_der
        raw_signature = CryptoEngine.sign_raw_sha256(raw_to_sign, key)
        certificate_der = PayloadBuilder._asn1crypto_or_bytes_to_der(cert)
        # Use fallback encoding only: the exact smdp_signed2_der we sign must be the exact
        # bytes sent in the request. pySIM decode/re-encode can change DER (e.g. INTEGER
        # padding) and causes invalidSignature(2) on the eUICC.
        value_parts = [
            smdp_signed2_der,
            PayloadBuilder._wrap_tlv(bytes.fromhex("5F37"), raw_signature),
            certificate_der,
        ]
        outer_value = b"".join(value_parts)
        return PayloadBuilder._wrap_tlv(bytes.fromhex("BF21"), outer_value)

    @staticmethod
    def build_prepare_download_remote(smdp_signed2_der: bytes, smdp_signature2: bytes, cert) -> bytes:
        raw_signature = PayloadBuilder._unwrap_application_octet_string(
            bytes(smdp_signature2),
            bytes.fromhex("5F37"),
        )
        certificate_der = PayloadBuilder._asn1crypto_or_bytes_to_der(cert)
        if _PY_SIM_RSP_ASN1 is not None:
            encoded = encode_prepare_download_request(
                smdp_signed2_der=bytes(smdp_signed2_der),
                smdp_signature2=raw_signature,
                smdp_certificate_der=certificate_der,
            )
            if len(encoded) > 0:
                return encoded
        value_parts = [
            bytes(smdp_signed2_der),
            PayloadBuilder._wrap_tlv(bytes.fromhex("5F37"), raw_signature),
            certificate_der,
        ]
        outer_value = b"".join(value_parts)
        return PayloadBuilder._wrap_tlv(bytes.fromhex("BF21"), outer_value)

    @staticmethod
    def _encode_der_length(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        if length <= 0xFF:
            return bytes([0x81, length])
        if length <= 0xFFFF:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        raise ValueError("DER length exceeds supported two-octet long-form encoding.")

    @staticmethod
    def _wrap_tlv(tag_bytes: bytes, value: bytes) -> bytes:
        return tag_bytes + PayloadBuilder._encode_der_length(len(value)) + value

    @staticmethod
    def _unwrap_application_octet_string(value: bytes, tag_bytes: bytes) -> bytes:
        if value.startswith(tag_bytes) is False:
            return value

        length, length_size = PayloadBuilder._decode_der_length(value, len(tag_bytes))
        if length_size == 0:
            return value

        value_start = len(tag_bytes) + length_size
        value_end = value_start + length
        if value_end != len(value):
            return value
        return value[value_start:value_end]

    @staticmethod
    def _decode_der_length(data: bytes, offset: int):
        if offset >= len(data):
            return 0, 0
        first = data[offset]
        if first < 0x80:
            return first, 1
        count = first & 0x7F
        if count == 0:
            return 0, 0
        end = offset + 1 + count
        if end > len(data):
            return 0, 0
        return int.from_bytes(data[offset + 1:end], "big"), 1 + count
