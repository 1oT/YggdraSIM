# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Notification and Profile Installation Result encoding of the simulated eUICC.

SGP.22 v3.1 §2.5.6 (Profile Installation Result), §5.5.3 (notificationConfigurationInfo),
§5.7.6 (end of the RSP Session), §5.7.10 (OtherSignedNotification) and §5.7.16-§5.7.18 (one
Notification per configured recipient, the implicitly disabled Profile included).
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
from SIMCARD.state import SimProfileEntry
from SIMCARD.utils import read_tlv, tlv

# SGP.33-1 v1.2 #S_SM_DP+_OID1 (A.1 p.150); DER content 88 37 0A.
SMDP_TEST_OID = "2.999.10"
TEST_ICCID = "8988201234567890123"
PPI_RESPONSE_OK = bytes.fromhex("3007A0053003800100")


def _smdp_certificate_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test SM-DP+ DPpb"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.RegisteredID(x509.ObjectIdentifier(SMDP_TEST_OID))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _verify_raw_signature(certificate_der: bytes, signature: bytes, payload: bytes) -> None:
    public_key = x509.load_der_x509_certificate(certificate_der).public_key()
    public_key.verify(
        encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
        payload,
        ec.ECDSA(hashes.SHA256()),
    )


def _other_signed_parts(payload: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """(tbsOtherNotification, euiccNotificationSignature, euiccCertificate, nextCertInChain)."""
    tag, value, _, end = read_tlv(payload, 0)
    if tag != b"\x30" or end != len(payload):
        raise AssertionError(f"not an OtherSignedNotification: {payload[:4].hex()}")
    metadata_tag, _, metadata_raw, offset = read_tlv(value, 0)
    signature_tag, signature, _, offset = read_tlv(value, offset)
    _, _, euicc_certificate, offset = read_tlv(value, offset)
    _, _, next_certificate, offset = read_tlv(value, offset)
    if metadata_tag != bytes.fromhex("BF2F") or signature_tag != bytes.fromhex("5F37") or offset != len(value):
        raise AssertionError("OtherSignedNotification members out of order")
    return metadata_raw, signature, euicc_certificate, next_certificate


def _metadata_fields(metadata_raw: bytes) -> dict[bytes, bytes]:
    _, value, _, _ = read_tlv(metadata_raw, 0)
    fields: dict[bytes, bytes] = {}
    offset = 0
    while offset < len(value):
        tag, field_value, _, offset = read_tlv(value, offset)
        fields[tag] = field_value
    return fields


def _profile(state, aid: str) -> SimProfileEntry:
    return next(profile for profile in state.profiles if profile.aid.upper() == aid.upper())


class NotificationConfigurationParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logic = SgpLogic(build_default_state())

    def test_entries_decode_from_the_automatic_tag_form(self) -> None:
        # NotificationConfigurationInformation has no tagged member: 30 { 80 bits, 81 address }.
        enable_only = tlv("30", tlv("80", b"\x06\x40") + tlv("81", b"a.example.test"))
        enable_and_disable = tlv("30", tlv("80", b"\x05\x60") + tlv("81", b"b.example.test"))

        configuration = self.logic._parse_notification_configuration_info(enable_only + enable_and_disable)

        self.assertEqual(
            configuration,
            [(1, "a.example.test"), (1, "b.example.test"), (2, "b.example.test")],
        )

    def test_universal_utf8_address_without_event_is_rejected(self) -> None:
        legacy_entry = tlv("30", tlv("0C", b"a.example.test"))

        with self.assertRaises(ValueError):
            self.logic._parse_notification_configuration_info(legacy_entry)


class OtherSignedNotificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        self.logic = SgpLogic(self.state)
        self.enabled = next(profile for profile in self.state.profiles if profile.state == "enabled")
        self.disabled = next(profile for profile in self.state.profiles if profile.state == "disabled")
        self.state.notifications = []

    def test_enable_notifies_every_configured_recipient_and_the_implicitly_disabled_profile(self) -> None:
        self.disabled.notification_configuration = [(1, "enable-a.example.test"), (1, "enable-b.example.test")]
        self.enabled.notification_configuration = [(2, "disable.example.test"), (1, "not-this-event.example.test")]
        request = tlv("BF31", tlv("A0", tlv("4F", bytes.fromhex(self.disabled.aid))) + tlv("81", b"\xFF"))

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((response, sw1, sw2), (bytes.fromhex("BF3103800100"), 0x90, 0x00))
        seen = []
        for entry in self.state.notifications:
            metadata_raw, signature, euicc_certificate, _ = _other_signed_parts(entry.payload)
            _verify_raw_signature(euicc_certificate, signature, metadata_raw)
            fields = _metadata_fields(metadata_raw)
            seen.append((fields[b"\x81"], fields[b"\x0C"].decode("utf-8")))
        self.assertCountEqual(
            seen,
            [
                (b"\x05\x20", "disable.example.test"),
                (b"\x06\x40", "enable-a.example.test"),
                (b"\x06\x40", "enable-b.example.test"),
            ],
        )

    def test_metadata_without_configuration_generates_no_notification(self) -> None:
        self.disabled.notification_configuration = []
        request = tlv("BF33", tlv("4F", bytes.fromhex(self.disabled.aid)))

        response, _, _ = self.logic.handle_store_data(request)

        self.assertEqual(response, bytes.fromhex("BF3303800100"))
        self.assertEqual(self.state.notifications, [])

    def test_sequence_number_is_a_der_integer(self) -> None:
        self.state.next_notification_seq = 128
        self.disabled.notification_configuration = None

        entries = self.logic._enqueue_notification(operation=SgpLogic.NOTIF_DELETE, profile=self.disabled)

        metadata_raw, _, _, _ = _other_signed_parts(entries[0].payload)
        self.assertEqual(_metadata_fields(metadata_raw)[b"\x80"], b"\x00\x80")


class ProfileInstallationResultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        self.logic = SgpLogic(self.state)
        self.state.notifications = []
        session = self.state.sgp_session
        session.transaction_id = bytes.fromhex("11" * 16)
        session.server_address = "smdp.example.test"
        session.smdp_certificate = _smdp_certificate_der()

    def _split_pir(self, pir: bytes) -> tuple[bytes, bytes]:
        tag, value, _, end = read_tlv(pir, 0)
        self.assertEqual((tag, end), (bytes.fromhex("BF37"), len(pir)))
        data_tag, _, result_data, offset = read_tlv(value, 0)
        signature_tag, signature, _, offset = read_tlv(value, offset)
        self.assertEqual((data_tag, signature_tag, offset), (bytes.fromhex("BF27"), bytes.fromhex("5F37"), len(value)))
        return result_data, signature

    def test_success_result_is_signed_stored_and_ends_the_session(self) -> None:
        profile = SimProfileEntry(
            aid="A0000005591010FFFFFFFF8900001500",
            iccid=TEST_ICCID,
            notification_configuration=[(0, "install.example.test")],
        )

        pir = self.logic._deliver_installation_result(success=True, profile=profile)

        result_data, signature = self._split_pir(pir)
        euicc_certificate = self.logic._current_euicc_certificate_der()
        _verify_raw_signature(euicc_certificate, signature, result_data)
        self.assertIn(tlv("06", bytes.fromhex("88370A")), result_data)
        self.assertIn(
            tlv("A2", tlv("A0", tlv("4F", bytes.fromhex(profile.aid)) + tlv("04", PPI_RESPONSE_OK))),
            result_data,
        )
        self.assertIn(tlv("0C", b"smdp.example.test"), result_data)
        payloads = [entry.payload for entry in self.state.notifications]
        self.assertEqual(payloads[0], pir)
        install_metadata, _, _, _ = _other_signed_parts(payloads[1])
        self.assertEqual(_metadata_fields(install_metadata)[b"\x0C"], b"install.example.test")
        self.assertEqual(self.state.sgp_session.transaction_id, b"")

    def test_error_result_omits_the_unknown_iccid(self) -> None:
        pir = self.logic._install_failure("bf23", 3)

        result_data, signature = self._split_pir(pir)
        _verify_raw_signature(self.logic._current_euicc_certificate_der(), signature, result_data)
        # SGP.22 v3.1 §2.5.6: initialiseSecureChannel(0), invalidTransactionId(3).
        self.assertIn(tlv("A2", tlv("A1", tlv("80", b"\x00") + tlv("81", b"\x03"))), result_data)
        _, result_value, _, _ = read_tlv(result_data, 0)
        _, _, metadata_raw, _ = read_tlv(result_value, read_tlv(result_value, 0)[3])
        self.assertNotIn(b"\x5A", _metadata_fields(metadata_raw))
        self.assertEqual(self.state.notifications[0].payload, pir)

    def test_bound_profile_package_without_session_answers_6a88(self) -> None:
        self.state.sgp_session.prepare_download_done = False

        response = self.logic.handle_store_data(bytes.fromhex("BF3603BF2300"))

        self.assertEqual(response, (b"", 0x6A, 0x88))
        self.assertEqual(self.state.notifications, [])


if __name__ == "__main__":
    unittest.main()
