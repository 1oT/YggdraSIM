import datetime
import unittest

from asn1crypto import x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.asn1_registry import ASN1Registry
from SCP11.crypto_engine import CryptoEngine
from SCP11.payload_builder import PayloadBuilder


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

    def test_prepare_download_payload_encodes(self):
        cert, private_key = build_self_signed_cert()
        payload = PayloadBuilder.build_prepare_download(
            transaction_id=b"\x10" * 16,
            euicc_sig1=b"\x20" * 64,
            cert=cert,
            key=private_key,
        )

        self.assertTrue(payload.startswith(bytes.fromhex("BF21")))
        parsed = ASN1Registry.PrepareDownloadRequest.load(payload)
        self.assertIsNotNone(parsed)


if __name__ == "__main__":
    unittest.main()
