# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The simulated eUICC's eimPublicKeyData and trustedPublicKeyDataTls, as stored and as answered.

SGP.32 v1.3 §2.11.1.1.2 (p.33) declares both as a CHOICE of a
SubjectPublicKeyInfo and a Certificate in an AUTOMATIC TAGS module, so the
alternative travels as ``A0`` / ``A1`` in place of the SEQUENCE tag.
GetEimConfigurationData answers in that form whatever the entry holds: the
implicit form AddInitialEim delivers, the bare certificate the simulator seeds
its own eIM with, or the alternative wrapped around a whole SEQUENCE that
earlier legacy entries carried.
"""

from __future__ import annotations

import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP03.logic.sgp32_decode import decode_eim_configuration_entries
from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.sgp32_packages import encode_eim_key_choice, unwrap_eim_key_material
from SIMCARD.state import SimEimEntry
from SIMCARD.utils import tlv


def _certificate_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"), x509.NameAttribute(NameOID.COMMON_NAME, "Key Data Test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


CERTIFICATE_DER = _certificate_der()
SPKI_DER = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
)


class EncodingTests(unittest.TestCase):
    def test_every_stored_form_comes_out_as_the_choice_alternative(self) -> None:
        implicit_certificate = b"\xA1" + CERTIFICATE_DER[1:]
        implicit_key = b"\xA0" + SPKI_DER[1:]
        for stored, expected in (
            (CERTIFICATE_DER, implicit_certificate),
            (SPKI_DER, implicit_key),
            (implicit_certificate, implicit_certificate),
            (implicit_key, implicit_key),
            (tlv(b"\xA1", CERTIFICATE_DER), implicit_certificate),
            (tlv(b"\xA5", implicit_certificate), implicit_certificate),
        ):
            with self.subTest(stored[:4].hex()):
                self.assertEqual(encode_eim_key_choice(stored), expected)
                self.assertEqual(unwrap_eim_key_material(stored), CERTIFICATE_DER if expected[0] == 0xA1 else SPKI_DER)

    def test_what_does_not_read_is_left_as_it_is(self) -> None:
        for raw in (b"", b"\x30", b"\x30\x05\x01", CERTIFICATE_DER[:40], b"\xA1\x7F\x00", b"\x04\x01\x00"):
            with self.subTest(raw.hex()):
                self.assertEqual(encode_eim_key_choice(raw), raw)


class AnswerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logic = SgpLogic(build_default_state())

    def entries(self) -> list[dict]:
        answer, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5500"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return decode_eim_configuration_entries(answer)

    def test_the_simulators_own_eim_answers_with_certificates(self) -> None:
        for entry in self.entries():
            self.assertEqual(entry["eim_public_key_kind"], "certificate", entry["eim_id"])
            self.assertEqual(entry["trusted_tls_public_key_kind"], "certificate", entry["eim_id"])

    def test_an_entry_holding_a_bare_or_wrapped_value_answers_in_the_spec_form(self) -> None:
        self.logic.state.eim_entries.append(SimEimEntry(
            eim_id="1.3.6.1.4.1.32473.999.10.124", eim_fqdn="eim.example.test", eim_id_type=1, counter_value=1,
            association_token=2, supported_protocol_bits=[0], euicc_ci_pkid=bytes(self.logic.state.root_ci_pkid),
            eim_public_key_data=tlv(b"\xA1", CERTIFICATE_DER), trusted_tls_public_key_data=SPKI_DER,
        ))
        entry = next(item for item in self.entries() if item["eim_id"] == "1.3.6.1.4.1.32473.999.10.124")
        self.assertEqual((entry["eim_public_key_kind"], entry["eim_public_key_der"]), ("certificate", CERTIFICATE_DER))
        self.assertEqual((entry["trusted_tls_public_key_kind"], entry["trusted_tls_public_key_der"]), ("publicKey", SPKI_DER))


if __name__ == "__main__":
    unittest.main()
