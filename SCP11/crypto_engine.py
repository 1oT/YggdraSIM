import os
from typing import Any, Tuple

from asn1crypto import core, x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

try:
    from .asn1_registry import ASN1Registry
except ImportError:
    from asn1_registry import ASN1Registry


class CryptoEngine:
    """Encapsulates key loading, ECDSA signing, and helper transformations."""

    @staticmethod
    def load_credentials(cert_path: str, key_path: str) -> Tuple[Any, Any]:
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"Missing credential file: {cert_path}")
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Missing credential file: {key_path}")

        with open(cert_path, "rb") as cert_file:
            cert = x509.Certificate.load(cert_file.read())

        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        return cert, private_key

    @staticmethod
    def sign_asn1(asn1_obj: core.Asn1Value, private_key: Any) -> bytes:
        payload = asn1_obj.dump()
        return CryptoEngine.sign_raw_sha256(payload, private_key)

    @staticmethod
    def sign_raw_sha256(data: bytes, private_key: Any) -> bytes:
        signature_der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        r_value, s_value = decode_dss_signature(signature_der)
        r_bytes = r_value.to_bytes(32, "big")
        s_bytes = s_value.to_bytes(32, "big")
        return r_bytes + s_bytes

    @staticmethod
    def generate_server_challenges(card_challenge: bytes, server_url: str) -> Tuple[Any, bytes, bytes]:
        transaction_id = os.urandom(16)
        server_challenge = os.urandom(16)
        signed1 = ASN1Registry.ServerSigned1(
            {
                "transactionId": ASN1Registry.TransactionId(transaction_id),
                "euiccChallenge": ASN1Registry.EuiccChallenge(card_challenge),
                "serverAddress": ASN1Registry.ServerAddress(server_url),
                "serverChallenge": ASN1Registry.ServerChallenge(server_challenge),
            }
        )
        return signed1, transaction_id, server_challenge
