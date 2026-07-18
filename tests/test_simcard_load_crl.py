# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SGP.22 §5.7.13 ES10b.LoadCRL — validated eUICC-side acceptance."""

from __future__ import annotations

import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SIMCARD.sgp import SgpLogic
from SIMCARD.state import SimCardState
from SIMCARD.utils import read_tlv, tlv


def _make_sgp_logic() -> SgpLogic:
    state = SimCardState(
        atr=b"",
        eid="89049032123451234512345678901235",
        iccid="8949000000000000001",
        imsi="999990000000001",
        default_dp_address="",
        root_ci_pkid=b"",
    )
    return SgpLogic(state)


def _issuer_material() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LoadCRL Test Issuer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate.public_bytes(serialization.Encoding.DER)


def _signed_crl_der(
    key: ec.EllipticCurvePrivateKey,
    *,
    sequence: int = 0,
) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LoadCRL Test Issuer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - datetime.timedelta(minutes=sequence + 1))
        .next_update(now + datetime.timedelta(days=1))
        .add_extension(x509.CRLNumber(sequence + 1), critical=False)
        .sign(key, hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.DER)


def _load_request(crl_der: bytes) -> bytes:
    tag, value, _raw, next_offset = read_tlv(crl_der, 0)
    if tag != b"\x30" or next_offset != len(crl_der):
        raise AssertionError("test CRL is not one complete DER SEQUENCE")
    return tlv("BF35", tlv(b"\xA0", value))


class LoadCrlTests(unittest.TestCase):
    def test_non_empty_crl_is_persisted_and_returns_ok(self) -> None:
        logic = _make_sgp_logic()
        issuer_key, issuer_certificate_der = _issuer_material()
        logic._ci_certificate_der = issuer_certificate_der
        crl_der = _signed_crl_der(issuer_key)
        request = _load_request(crl_der)

        response, sw1, sw2 = logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertTrue(response.startswith(bytes.fromhex("BF35")))
        # 80 01 00 = ok(0)
        self.assertIn(b"\x80\x01\x00", response)
        self.assertEqual(len(logic.state.loaded_crls), 1)
        self.assertEqual(logic.state.loaded_crls[0], crl_der)

    def test_empty_body_returns_invalid_signature(self) -> None:
        logic = _make_sgp_logic()
        request = bytes.fromhex("BF3500")

        response, sw1, sw2 = logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # 81 01 02 = invalidSignature(2)
        self.assertIn(b"\x81\x01\x02", response)
        self.assertEqual(len(logic.state.loaded_crls), 0)

    def test_multiple_crls_accumulate_in_order(self) -> None:
        logic = _make_sgp_logic()
        issuer_key, issuer_certificate_der = _issuer_material()
        logic._ci_certificate_der = issuer_certificate_der

        crls = [_signed_crl_der(issuer_key, sequence=index) for index in range(3)]
        requests = [_load_request(crl_der) for crl_der in crls]

        for request in requests:
            _resp, sw1, sw2 = logic.handle_store_data(request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))

        self.assertEqual(logic.state.loaded_crls, crls)


if __name__ == "__main__":
    unittest.main()
