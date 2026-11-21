# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES10b.CancelSession of the simulated eUICC (SGP.22 v3.1 §5.7.14).

The signed answer, the Transaction ID checks and the end of the RSP Session.
"""

from __future__ import annotations

import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.utils import read_tlv, tlv

TRANSACTION_ID = bytes.fromhex("11" * 16)
# SGP.33-1 v1.2 #S_SM_DP+_OID1 (A.1 p.150); DER content 88 37 0A.
SMDP_TEST_OID = "2.999.10"


def _dpauth_certificate_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SM-DP+ DPauth")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.RegisteredID(x509.ObjectIdentifier(SMDP_TEST_OID))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _request(transaction_id: bytes, reason: int) -> bytes:
    return tlv("BF41", tlv("80", transaction_id) + tlv("81", bytes([reason])))


class CancelSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        self.logic = SgpLogic(self.state)
        session = self.state.sgp_session
        session.card_challenge = b"\x22" * 16
        session.transaction_id = TRANSACTION_ID
        session.smdp_certificate = _dpauth_certificate_der()

    def test_matching_transaction_id_is_answered_with_a_signed_cancellation(self) -> None:
        response, sw1, sw2 = self.logic.handle_store_data(_request(TRANSACTION_ID, 1))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _, response_value, _, _ = read_tlv(response, 0)
        ok_tag, ok_value, _, _ = read_tlv(response_value, 0)
        self.assertEqual(ok_tag, b"\xA0")
        signed_tag, _, signed_raw, offset = read_tlv(ok_value, 0)
        signature_tag, signature, _, _ = read_tlv(ok_value, offset)
        self.assertEqual((signed_tag, signature_tag), (b"\x30", bytes.fromhex("5F37")))
        self.assertEqual(
            signed_raw,
            tlv("30", tlv("80", TRANSACTION_ID) + tlv("81", bytes.fromhex("88370A")) + tlv("82", b"\x01")),
        )
        public_key = x509.load_der_x509_certificate(self.logic._current_euicc_certificate_der()).public_key()
        public_key.verify(
            encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
            signed_raw,
            ec.ECDSA(hashes.SHA256()),
        )
        self.assertEqual(self.state.sgp_session.transaction_id, b"")

    def test_other_transaction_id_is_invalid_and_keeps_the_session(self) -> None:
        response, _, _ = self.logic.handle_store_data(_request(b"\x99" * 16, 1))

        self.assertEqual(response, bytes.fromhex("BF4103810105"))
        self.assertEqual(self.state.sgp_session.transaction_id, TRANSACTION_ID)

    def test_session_without_transaction_id_is_discarded(self) -> None:
        self.state.sgp_session.transaction_id = b""

        response, _, _ = self.logic.handle_store_data(_request(TRANSACTION_ID, 2))

        self.assertEqual(response, bytes.fromhex("BF4103810105"))
        self.assertEqual(self.state.sgp_session.card_challenge, b"")


if __name__ == "__main__":
    unittest.main()
