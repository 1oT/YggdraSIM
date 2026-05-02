import datetime
import unittest
from unittest.mock import patch

from asn1crypto import x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.asn1_registry import ASN1Registry
from SCP11.crypto_engine import CryptoEngine
from SCP11.payload_builder import PayloadBuilder
from SCP11.pysim_support import encode_smdp_signed2

try:
    from pySim.esim import compile_asn1_subdir
except ImportError:
    compile_asn1_subdir = None


def build_self_signed_cert():
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert"),
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
    der = certificate.public_bytes(serialization.Encoding.DER)
    asn1_cert = x509.Certificate.load(der)
    return asn1_cert, private_key


class PayloadBuilderTests(unittest.TestCase):
    def test_prepare_download_signs_smdp_signed2_plus_wrapped_euicc_signature1(self):
        cert, private_key = build_self_signed_cert()
        transaction_id = b"\x10" * 16
        euicc_sig1 = b"\x20" * 64
        recorded = {}

        def fake_sign(data: bytes, _private_key):
            recorded["data"] = data
            return b"\x55" * 64

        with patch("SCP11.payload_builder.CryptoEngine.sign_raw_sha256", side_effect=fake_sign):
            PayloadBuilder.build_prepare_download(
                transaction_id=transaction_id,
                euicc_sig1=euicc_sig1,
                cert=cert,
                key=private_key,
            )

        expected_prefix = encode_smdp_signed2(
            transaction_id=transaction_id,
            cc_required_flag=False,
        ) + bytes.fromhex("5F3740") + euicc_sig1
        self.assertEqual(recorded["data"], expected_prefix)

    def test_authenticate_server_payload_encodes(self):
        cert, private_key = build_self_signed_cert()
        signed1, _, _ = CryptoEngine.generate_server_challenges(b"\x01" * 16, "rsp.example.com")
        signature = CryptoEngine.sign_asn1(signed1, private_key)
        payload = PayloadBuilder.build_auth_server(
            signed1=signed1,
            signature=signature,
            cert=cert,
            ctx_params={"deviceInfo": {"tac": b"\x01\x02\x03\x04", "deviceCapabilities": {}}},
            root_ci_id=bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3"),
        )

        self.assertTrue(payload.startswith(bytes.fromhex("BF38")))
        self.assertNotIn(bytes.fromhex("5F37435F3740"), payload)
        self.assertIn(bytes.fromhex("5F3740"), payload)
        if compile_asn1_subdir is not None:
            asn1 = compile_asn1_subdir("rsp")
            decoded = asn1.decode("AuthenticateServerRequest", payload)
            ctx_choice_name, ctx_choice_value = decoded["ctxParams1"]
            self.assertEqual(ctx_choice_name, "ctxParamsForCommonAuthentication")
            self.assertEqual(ctx_choice_value["deviceInfo"]["tac"], b"\x01\x02\x03\x04")
            self.assertEqual(
                ctx_choice_value["deviceInfo"]["deviceCapabilities"]["gsmSupportedRelease"],
                b"\x99\x00\x00",
            )

    def test_authenticate_server_maps_eutran_epc_capability_for_pysim(self):
        cert, private_key = build_self_signed_cert()
        signed1, _, _ = CryptoEngine.generate_server_challenges(b"\x01" * 16, "rsp.example.com")
        signature = CryptoEngine.sign_asn1(signed1, private_key)
        payload = PayloadBuilder.build_auth_server(
            signed1=signed1,
            signature=signature,
            cert=cert,
            ctx_params={
                "deviceInfo": {
                    "tac": b"\x01\x02\x03\x04",
                    "deviceCapabilities": {
                        "gsmSupportedRelease": b"\x99\x00\x00",
                        "eutranEpcSupportedRelease": b"\x98\x00\x00",
                    },
                }
            },
            root_ci_id=bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3"),
        )

        self.assertTrue(payload.startswith(bytes.fromhex("BF38")))
        if compile_asn1_subdir is not None:
            asn1 = compile_asn1_subdir("rsp")
            decoded = asn1.decode("AuthenticateServerRequest", payload)
            _, ctx_choice_value = decoded["ctxParams1"]
            self.assertEqual(
                ctx_choice_value["deviceInfo"]["deviceCapabilities"]["eutranSupportedRelease"],
                b"\x98\x00\x00",
            )

    def test_normalize_ctx_params_keeps_legacy_eutran_epc_field(self):
        normalized = PayloadBuilder._normalize_ctx_params(
            {
                "deviceInfo": {
                    "tac": b"\x01\x02\x03\x04",
                    "deviceCapabilities": {
                        "gsmSupportedRelease": b"\x99\x00\x00",
                        "eutranEpcSupportedRelease": b"\x98\x00\x00",
                    },
                }
            }
        )

        capabilities = normalized["deviceInfo"]["deviceCapabilities"]
        self.assertEqual(capabilities["eutranEpcSupportedRelease"], b"\x98\x00\x00")
        self.assertNotIn("eutranSupportedRelease", capabilities)

    def test_normalize_pysim_capabilities_accepts_legacy_eutran_epc_field(self):
        normalized = PayloadBuilder._normalize_pysim_capabilities(
            {
                "gsmSupportedRelease": b"\x99\x00\x00",
                "eutranEpcSupportedRelease": b"\x98\x00\x00",
            }
        )

        self.assertEqual(normalized["eutranSupportedRelease"], b"\x98\x00\x00")
        self.assertNotIn("eutranEpcSupportedRelease", normalized)

    def test_authenticate_server_legacy_path_accepts_eutran_epc_capability(self):
        cert, private_key = build_self_signed_cert()
        signed1, _, _ = CryptoEngine.generate_server_challenges(b"\x01" * 16, "rsp.example.com")
        signature = CryptoEngine.sign_asn1(signed1, private_key)

        with patch("SCP11.payload_builder._PY_SIM_RSP_ASN1", None):
            payload = PayloadBuilder.build_auth_server(
                signed1=signed1,
                signature=signature,
                cert=cert,
                ctx_params={
                    "deviceInfo": {
                        "tac": b"\x01\x02\x03\x04",
                        "deviceCapabilities": {
                            "gsmSupportedRelease": b"\x99\x00\x00",
                            "eutranEpcSupportedRelease": b"\x98\x00\x00",
                        },
                    }
                },
                root_ci_id=bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3"),
            )

        self.assertTrue(payload.startswith(bytes.fromhex("BF38")))

    def test_authenticate_server_unwraps_prewrapped_signature(self):
        cert, private_key = build_self_signed_cert()
        signed1, _, _ = CryptoEngine.generate_server_challenges(b"\x01" * 16, "rsp.example.com")
        raw_signature = CryptoEngine.sign_asn1(signed1, private_key)
        wrapped_signature = bytes.fromhex("5F3740") + raw_signature
        payload = PayloadBuilder.build_auth_server(
            signed1=signed1,
            signature=wrapped_signature,
            cert=cert,
            ctx_params={"deviceInfo": {"tac": b"\x01\x02\x03\x04", "deviceCapabilities": {}}},
            root_ci_id=bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3"),
        )

        self.assertTrue(payload.startswith(bytes.fromhex("BF38")))
        self.assertNotIn(bytes.fromhex("5F37435F3740"), payload)
        self.assertIn(bytes.fromhex("5F3740"), payload)
        if compile_asn1_subdir is not None:
            asn1 = compile_asn1_subdir("rsp")
            decoded = asn1.decode("AuthenticateServerRequest", payload)
            self.assertEqual(decoded["serverSignature1"], raw_signature)

    def test_prepare_download_payload_encodes(self):
        cert, private_key = build_self_signed_cert()
        payload = PayloadBuilder.build_prepare_download(
            transaction_id=b"\x10" * 16,
            euicc_sig1=b"\x20" * 64,
            cert=cert,
            key=private_key,
        )

        self.assertTrue(payload.startswith(bytes.fromhex("BF21")))
        if compile_asn1_subdir is not None:
            asn1 = compile_asn1_subdir("rsp")
            decoded = asn1.decode("PrepareDownloadRequest", payload)
            self.assertEqual(decoded["smdpSigned2"]["transactionId"], b"\x10" * 16)
            self.assertEqual(decoded["smdpSigned2"]["ccRequiredFlag"], False)
        else:
            parsed = ASN1Registry.PrepareDownloadRequest.load(payload)
            self.assertIsNotNone(parsed)

    def test_prepare_download_local_matches_remote_layout(self):
        cert, private_key = build_self_signed_cert()
        transaction_id = b"\x10" * 16
        euicc_sig1 = b"\x20" * 64

        local_payload = PayloadBuilder.build_prepare_download(
            transaction_id=transaction_id,
            euicc_sig1=euicc_sig1,
            cert=cert,
            key=private_key,
        )
        smdp_signed2_der = PayloadBuilder._asn1crypto_or_bytes_to_der(
            encode_smdp_signed2(
                transaction_id=transaction_id,
                cc_required_flag=False,
            )
        )
        raw_signature = CryptoEngine.sign_raw_sha256(smdp_signed2_der + euicc_sig1, private_key)
        remote_payload = PayloadBuilder.build_prepare_download_remote(
            smdp_signed2_der=smdp_signed2_der,
            smdp_signature2=raw_signature,
            cert=cert,
        )

        local_children = self._read_child_tags(local_payload)
        remote_children = self._read_child_tags(remote_payload)
        self.assertEqual(local_children, ["30", "5F37", "30"])
        self.assertEqual(local_children, remote_children)

    @staticmethod
    def _read_child_tags(payload: bytes) -> list[str]:
        from SCP11.local_access.session import LocalIsdrSession

        _, outer_value, _, _ = LocalIsdrSession._read_tlv(payload, 0)
        tags = []
        offset = 0
        while offset < len(outer_value):
            tag_bytes, _, _, next_offset = LocalIsdrSession._read_tlv(outer_value, offset)
            tags.append(tag_bytes.hex().upper())
            offset = next_offset
        return tags

    def test_prepare_download_remote_unwraps_prewrapped_signature(self):
        cert, _ = build_self_signed_cert()
        remote_signature = bytes.fromhex("5F3740") + (b"\x55" * 64)
        payload = PayloadBuilder.build_prepare_download_remote(
            smdp_signed2_der=bytes.fromhex("300D80081111111111111111010100"),
            smdp_signature2=remote_signature,
            cert=cert,
        )

        self.assertTrue(payload.startswith(bytes.fromhex("BF21")))
        self.assertNotIn(bytes.fromhex("04435F3740"), payload)
        self.assertNotIn(bytes.fromhex("5F37435F3740"), payload)
        self.assertIn(bytes.fromhex("5F3740"), payload)
        if compile_asn1_subdir is not None:
            asn1 = compile_asn1_subdir("rsp")
            decoded = asn1.decode("PrepareDownloadRequest", payload)
            self.assertEqual(decoded["smdpSigned2"]["transactionId"], b"\x11" * 8)
            self.assertEqual(decoded["smdpSignature2"], b"\x55" * 64)
        else:
            parsed = ASN1Registry.PrepareDownloadRequest.load(payload)
            self.assertIsNotNone(parsed)


if __name__ == "__main__":
    unittest.main()
