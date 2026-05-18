# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-live crypto engine: ECIES key agreement and AES-GCM envelope for the live physical-reader session."""
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

import os
from typing import Any, Optional, Tuple

from asn1crypto import core, x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

try:
    from .asn1_registry import ASN1Registry
    from .pysim_support import encode_server_signed1
except ImportError:
    from asn1_registry import ASN1Registry
    from pysim_support import encode_server_signed1


class CryptoEngine:
    """Encapsulates key loading, ECDSA signing, and helper transformations."""

    @staticmethod
    def load_credentials(cert_path: str, key_path: str) -> Tuple[Any, Any]:
        """Load the SGP.22 TLS certificates and private key into the crypto engine from the configured paths."""
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
        if isinstance(asn1_obj, bytes):
            payload = asn1_obj
        else:
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
    def generate_server_challenges(
        card_challenge: bytes,
        server_url: str,
        transaction_id: Optional[bytes] = None,
    ) -> Tuple[Any, bytes, bytes]:
        """Generate and return the eUICC challenge bytes for the INITIALIZE AUTHENTICATION step (SGP.22 §5.7.12)."""
        if transaction_id is None or len(transaction_id) == 0:
            transaction_id = os.urandom(16)
        else:
            transaction_id = bytes(transaction_id)[:16]
            if len(transaction_id) < 16:
                transaction_id = transaction_id + b"\x00" * (16 - len(transaction_id))
        server_challenge = os.urandom(16)
        signed1_der = encode_server_signed1(
            transaction_id=transaction_id,
            euicc_challenge=card_challenge,
            server_address=server_url,
            server_challenge=server_challenge,
        )
        if len(signed1_der) > 0:
            return signed1_der, transaction_id, server_challenge

        signed1 = ASN1Registry.ServerSigned1(
            {
                "transactionId": ASN1Registry.TransactionId(transaction_id),
                "euiccChallenge": ASN1Registry.EuiccChallenge(card_challenge),
                "serverAddress": ASN1Registry.ServerAddress(server_url),
                "serverChallenge": ASN1Registry.ServerChallenge(server_challenge),
            }
        )
        return signed1, transaction_id, server_challenge
