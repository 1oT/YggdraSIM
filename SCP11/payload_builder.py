# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 payload builder: assembles BPP STORE-DATA fragments and ES8+ command sequences from a decoded profile DER."""
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

try:
    from .pysim_path import ensure_repo_pysim_on_path
except ImportError:
    from pysim_path import ensure_repo_pysim_on_path

ensure_repo_pysim_on_path()

try:
    from pySim.esim import compile_asn1_subdir
except Exception:
    compile_asn1_subdir = None

try:
    from .asn1_registry import ASN1Registry
    from .crypto_engine import CryptoEngine
    from .pysim_support import (
        encode_authenticate_server_request,
        encode_ctx_params1,
        encode_prepare_download_request,
        encode_rsp_type,
        encode_smdp_signed2,
        rsp_type_members,
    )
except ImportError:
    from asn1_registry import ASN1Registry
    from crypto_engine import CryptoEngine
    from pysim_support import (
        encode_authenticate_server_request,
        encode_ctx_params1,
        encode_prepare_download_request,
        encode_rsp_type,
        encode_smdp_signed2,
        rsp_type_members,
    )

_PY_SIM_RSP_ASN1 = None
if compile_asn1_subdir is not None:
    try:
        _PY_SIM_RSP_ASN1 = compile_asn1_subdir("rsp")
    except Exception:
        _PY_SIM_RSP_ASN1 = None


# SGP.22 v3.1 DeviceInfo and DeviceCapabilities members in definition order (page 441, page 442).
DEVICE_INFO_MEMBERS = (
    "tac",
    "deviceCapabilities",
    "imei",
    "preferredLanguages",
    "deviceTestMode",
    "lpaRspCapability",
)
DEVICE_CAPABILITY_MEMBERS = (
    "gsmSupportedRelease",
    "utranSupportedRelease",
    "cdma2000onexSupportedRelease",
    "cdma2000hrpdSupportedRelease",
    "cdma2000ehrpdSupportedRelease",
    "eutranEpcSupportedRelease",
    "contactlessSupportedRelease",
    "rspCrlSupportedVersion",
    "nrEpcSupportedRelease",
    "nr5gcSupportedRelease",
    "eutran5gcSupportedRelease",
    "lpaSvn",
    "catSupportedClasses",
    "euiccFormFactorType",
    "deviceAdditionalFeatureSupport",
)


def _bit_string(value, name: str) -> tuple[bytes, int]:
    """A named BIT STRING as asn1tools takes it: (bytes, bit count) as given, or the bit numbers set.

    From bit numbers the count ends at the highest one set, as DER drops trailing zero bits.
    """
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], (bytes, bytearray)):
        return bytes(value[0]), int(value[1])
    numbers = sorted({int(number) for number in value})
    if numbers and numbers[0] < 0:
        raise ValueError(f"{name}: bit numbers start at 0")
    count = numbers[-1] + 1 if numbers else 0
    data = bytearray((count + 7) // 8)
    for number in numbers:
        data[number // 8] |= 0x80 >> (number % 8)
    return bytes(data), count


class PayloadBuilder:
    """Constructs SGP.22 AuthenticateServer and PrepareDownload payloads."""

    @staticmethod
    def build_auth_server(signed1, signature, cert, ctx_params, root_ci_id: bytes = None) -> bytes:
        """Build the ES9+.AuthenticateServer request TLV payload (SGP.22 §5.7.13).

        Encoded with pySim's SGP.22 v3.1 module; without it, the asn1crypto model in
        ``asn1_registry`` builds ctxParams1 and gives the same bytes.
        """
        safe_ctx_params = PayloadBuilder._normalize_ctx_params(ctx_params)
        pysim_ctx_params = PayloadBuilder._normalize_pysim_ctx_params(safe_ctx_params)
        signed1_der = PayloadBuilder._asn1crypto_or_bytes_to_der(signed1)
        certificate_der = PayloadBuilder._asn1crypto_or_bytes_to_der(cert)

        if _PY_SIM_RSP_ASN1 is not None:
            encoded = encode_authenticate_server_request(
                server_signed1_der=signed1_der,
                server_signature1=bytes(signature),
                euicc_ci_pk_id_to_be_used=bytes(root_ci_id or b""),
                server_certificate_der=certificate_der,
                ctx_params=pysim_ctx_params,
            )
            if len(encoded) > 0:
                return encoded
        ctx_params_der = PayloadBuilder._build_ctx_params1_with_pysim(safe_ctx_params)
        if len(ctx_params_der) == 0:
            ctx_content = ASN1Registry.CtxParamsForCommonAuthentication(
                PayloadBuilder._asn1crypto_ctx_params(pysim_ctx_params)
            )
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
    def encode_device_info(device_info: dict) -> bytes:
        """DER DeviceInfo as the AuthenticateServer ctxParams1 carries it, for every surface that sends one.

        SGP.22 v3.1 DeviceInfo (page 441) through pySim's v3.1 module, AUTOMATIC TAGS: tac '80',
        deviceCapabilities 'A1', imei '82', preferredLanguages 'A3', deviceTestMode '84',
        lpaRspCapability '85'. The values go through the ctxParams1 normalisation, so the eIM and the
        SM-DP+ are told the same device. Empty when the v3.1 module is unavailable.
        """
        if len(rsp_type_members("DeviceInfo", v3=True)) == 0:
            return b""
        normalized = PayloadBuilder._normalize_ctx_params({"deviceInfo": dict(device_info)})
        value = PayloadBuilder._normalize_pysim_ctx_params(normalized)["deviceInfo"]
        return encode_rsp_type("DeviceInfo", value, v3=True)

    @staticmethod
    def _build_ctx_params1_with_pysim(ctx_params: dict) -> bytes:
        """CtxParams1 through pySim's SGP.22 v3.1 module; empty when it is unavailable."""
        return encode_ctx_params1(PayloadBuilder._normalize_pysim_ctx_params(ctx_params))

    @staticmethod
    def _normalize_pysim_ctx_params(ctx_params: dict) -> dict:
        """The CtxParamsForCommonAuthentication members PayloadBuilder fills, as pySim's v3.1 module takes them.

        operationType, iccid, matchingIdSource and vendorSpecificExtension (SGP.22 v3.1 page 449)
        are not filled here; operationType is then its DEFAULT, profileDownload.
        """
        choice_value = {
            "deviceInfo": PayloadBuilder._normalize_device_info(dict(ctx_params.get("deviceInfo", {}))),
        }
        matching_id = str(ctx_params.get("matchingId", "")).strip()
        if len(matching_id) > 0:
            choice_value["matchingId"] = matching_id
        return choice_value

    @staticmethod
    def _normalize_device_info(device_info: dict) -> dict:
        """SGP.22 v3.1 DeviceInfo values for asn1tools; a member name v3.1 does not define is refused."""
        unknown = set(device_info) - set(DEVICE_INFO_MEMBERS)
        if unknown:
            raise ValueError(f"DeviceInfo members SGP.22 v3.1 does not define: {', '.join(sorted(unknown))}")
        tac = bytes(device_info.get("tac", b""))
        if len(tac) != 4:
            raise ValueError(f"DeviceInfo tac is Octet4 (SGP.22 v3.1); got {len(tac)} bytes")
        normalized: dict = {
            "tac": tac,
            "deviceCapabilities": PayloadBuilder._normalize_pysim_capabilities(
                dict(device_info.get("deviceCapabilities", {}))
            ),
        }
        imei = bytes(device_info.get("imei", b"") or b"")
        if len(imei) > 0:
            if len(imei) != 8:
                raise ValueError(f"DeviceInfo imei is Octet8 (SGP.22 v3.1); got {len(imei)} bytes")
            normalized["imei"] = imei
        languages = [str(language) for language in (device_info.get("preferredLanguages") or [])]
        if languages:
            normalized["preferredLanguages"] = languages
        if device_info.get("deviceTestMode"):
            normalized["deviceTestMode"] = None
        if device_info.get("lpaRspCapability") is not None:
            normalized["lpaRspCapability"] = _bit_string(device_info["lpaRspCapability"], "lpaRspCapability")
        return normalized

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
        """SGP.22 v3.1 DeviceCapabilities values for asn1tools, in definition order.

        eutranSupportedRelease, the SGP.22 v2 name, is read as eutranEpcSupportedRelease; any other
        name v3.1 does not define (rspRpmSupportedVersion included) is refused rather than dropped.
        """
        given = dict(capabilities)
        if "eutranSupportedRelease" in given and "eutranEpcSupportedRelease" not in given:
            given["eutranEpcSupportedRelease"] = given.pop("eutranSupportedRelease")
        given.pop("eutranSupportedRelease", None)
        unknown = set(given) - set(DEVICE_CAPABILITY_MEMBERS)
        if unknown:
            raise ValueError(f"DeviceCapabilities members SGP.22 v3.1 does not define: {', '.join(sorted(unknown))}")
        normalized: dict = {}
        for field_name in DEVICE_CAPABILITY_MEMBERS:
            value = given.get(field_name)
            if value is None:
                continue
            if field_name == "catSupportedClasses":
                normalized[field_name] = _bit_string(value, field_name)
            elif field_name == "euiccFormFactorType":
                normalized[field_name] = int(value)
            elif field_name == "deviceAdditionalFeatureSupport":
                features = dict(value)
                if set(features) - {"naiSupport"}:
                    raise ValueError("DeviceAdditionalFeatureSupport defines naiSupport only (SGP.22 v3.1)")
                normalized[field_name] = {key: bytes(item) for key, item in features.items()}
            else:
                normalized[field_name] = bytes(value)
        return normalized

    @staticmethod
    def _asn1crypto_ctx_params(pysim_ctx_params: dict) -> dict:
        """The asn1tools values of _normalize_pysim_ctx_params in the forms the asn1crypto model takes."""
        from asn1crypto import core

        def bits(value: tuple[bytes, int]) -> tuple[int, ...]:
            data, count = value
            return tuple((data[index // 8] >> (7 - index % 8)) & 1 for index in range(count))

        ctx = dict(pysim_ctx_params)
        device_info = dict(ctx["deviceInfo"])
        capabilities = dict(device_info["deviceCapabilities"])
        if "catSupportedClasses" in capabilities:
            capabilities["catSupportedClasses"] = bits(capabilities["catSupportedClasses"])
        device_info["deviceCapabilities"] = capabilities
        if "lpaRspCapability" in device_info:
            device_info["lpaRspCapability"] = bits(device_info["lpaRspCapability"])
        if "deviceTestMode" in device_info:
            device_info["deviceTestMode"] = core.Null()
        ctx["deviceInfo"] = device_info
        return ctx

    @staticmethod
    def build_prepare_download(transaction_id, euicc_sig1, cert, key) -> bytes:
        """Build the ES9+.PrepareDownload request TLV payload for a locally signed profile (SGP.22 §5.7.16)."""
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
        """Build the ES9+.PrepareDownload request TLV payload for a remotely signed profile (SGP.22 §5.7.16)."""
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
