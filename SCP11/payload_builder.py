from asn1crypto import core

try:
    from .asn1_registry import ASN1Registry
    from .crypto_engine import CryptoEngine
except ImportError:
    from asn1_registry import ASN1Registry
    from crypto_engine import CryptoEngine


class PayloadBuilder:
    """Constructs SGP.22 AuthenticateServer and PrepareDownload payloads."""

    @staticmethod
    def build_auth_server(signed1, signature, cert, ctx_params, root_ci_id: bytes = None) -> bytes:
        safe_ctx_params = PayloadBuilder._normalize_ctx_params(ctx_params)
        ctx_content = ASN1Registry.CtxParamsForCommonAuthentication(safe_ctx_params)
        request_data = {
            "serverSigned1": signed1,
            "serverSignature1": ASN1Registry.ServerSignature(signature),
            "serverCertificate": cert,
            "ctxParams1": ASN1Registry.CtxParams1(
                name="ctxParamsForCommonAuthentication",
                value=ctx_content,
            ),
        }

        if root_ci_id is not None and len(root_ci_id) > 0:
            request_data["euiccCiPKIdToBeUsed"] = core.OctetString(root_ci_id)

        request = ASN1Registry.AuthenticateServerRequest(request_data)
        return request.dump()

    @staticmethod
    def _normalize_ctx_params(ctx_params: dict) -> dict:
        normalized = dict(ctx_params)
        device_info = dict(normalized.get("deviceInfo", {}))
        capabilities = dict(device_info.get("deviceCapabilities", {}))
        if len(capabilities) == 0:
            capabilities["gsmSupportedRelease"] = b"\x99\x00\x00"
        device_info["deviceCapabilities"] = capabilities
        normalized["deviceInfo"] = device_info
        return normalized

    @staticmethod
    def build_prepare_download(transaction_id, euicc_sig1, cert, key) -> bytes:
        smdp_signed2 = ASN1Registry.SmdpSigned2(
            {
                "transactionId": ASN1Registry.TransactionId(transaction_id),
                "ccRequiredFlag": False,
            }
        )
        raw_to_sign = smdp_signed2.dump() + euicc_sig1
        raw_signature = CryptoEngine.sign_raw_sha256(raw_to_sign, key)
        request = ASN1Registry.PrepareDownloadRequest(
            {
                "smdpSigned2": smdp_signed2,
                "smdpSignature2": core.OctetString(raw_signature),
                "smdpCertificate": cert,
            }
        )
        return request.dump()
