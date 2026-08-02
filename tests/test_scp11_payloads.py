# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import datetime
import unittest
from pathlib import Path
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


class ProviderPayloadFaultTolerance(unittest.TestCase):
    """A malformed provider payload must not unwind the download flow.

    smdpSigned2 is re-encoded through the ASN.1 spec, so a truncated field
    from the SM-DP+ surfaces as an asn1tools error rather than a decode
    result. The orchestrator already falls back to local signing when the
    provider's smdpCertificate is unusable; the signed2 field reaching the
    same builder must take the same route.
    """

    #: Shapes an SM-DP+ could return that asn1tools cannot decode.
    MALFORMED = (
        ("empty", b""),
        ("tag only", b"\x30"),
        ("length promises 256 bytes, none follow", b"\x30\x82\x01\x00"),
    )

    def test_the_builder_itself_still_rejects_malformed_signed2(self) -> None:
        """The guard belongs at the caller; the builder keeps failing loudly."""

        for label, bad in self.MALFORMED:
            with self.subTest(label):
                with self.assertRaises(Exception):
                    PayloadBuilder.build_prepare_download_remote(
                        smdp_signed2_der=bad,
                        smdp_signature2=b"\x5f\x37\x02\xaa\xbb",
                        cert=b"\x30\x03\x02\x01\x00",
                    )

    def _orchestrator_call_site(self, module_path: str) -> str:
        source = Path(module_path).read_text(encoding="utf-8")
        start = source.index("self.state.provider_smdp_certificate = smdp_certificate_raw")
        return source[start:start + 1400]

    def test_both_orchestrators_guard_the_remote_build(self) -> None:
        for module_path in ("SCP11/orchestrator.py", "SCP11/live/orchestrator.py"):
            with self.subTest(module_path):
                region = self._orchestrator_call_site(module_path)
                self.assertIn("try:", region)
                self.assertIn("build_prepare_download_remote(", region)
                self.assertIn("_local_fallback_enabled()", region)
                # Same two-branch shape as the smdpCertificate case: raise
                # when local fallback is off, otherwise degrade to it.
                self.assertIn("fallback to local signing", region)
                self.assertIn("raise RuntimeError(", region)
