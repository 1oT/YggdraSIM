import contextlib
import datetime
import io
import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from types import SimpleNamespace

from asn1crypto import core, x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
import yaml

from SCP11.asn1_registry import ASN1Registry
from SCP11.local_access.cert_store import LocalSgp26CertStore
import SCP11.local_access.session as local_access_session
from SCP11.local_access import LocalAccessConfig, LocalIsdrSession
from SCP11.local_access.main import LocalAccessShell
from SCP11.local_access.payload_diff import analyze_payload_pair, decode_payload_bytes
from SCP11.pysim_path import ensure_repo_pysim_on_path
from SCP11.shared.pysim_support import decode_rsp_type
from yggdrasim_common.session_recording import emit_apdu_trace_event


def encode_der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def wrap_tlv(tag_bytes: bytes, value: bytes) -> bytes:
    return bytes(tag_bytes) + encode_der_length(len(value)) + value


def encode_iccid_for_tlv(iccid_digits: str) -> bytes:
    padded = iccid_digits
    if len(padded) % 2 != 0:
        padded += "F"
    encoded = []
    index = 0
    while index < len(padded):
        encoded.append(padded[index + 1] + padded[index])
        index += 2
    return bytes.fromhex("".join(encoded))


def build_profiles_info_response() -> bytes:
    primary = wrap_tlv(
        b"\xE3",
        b"".join(
            [
                wrap_tlv(b"\x5A", encode_iccid_for_tlv("8901000000000000001")),
                wrap_tlv(b"\x4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100")),
                wrap_tlv(bytes.fromhex("9F70"), b"\x01"),
                wrap_tlv(b"\x95", b"\x02"),
                wrap_tlv(b"\x90", b"Primary"),
            ]
        ),
    )
    secondary = wrap_tlv(
        b"\xE3",
        b"".join(
            [
                wrap_tlv(b"\x5A", encode_iccid_for_tlv("8901000000000000002")),
                wrap_tlv(b"\x4F", bytes.fromhex("A0000005591010FFFFFFFF8900001200")),
                wrap_tlv(bytes.fromhex("9F70"), b"\x00"),
                wrap_tlv(b"\x95", b"\x02"),
                wrap_tlv(b"\x90", b"Secondary"),
            ]
        ),
    )
    return primary + secondary


def build_eim_configuration_response() -> bytes:
    entry = wrap_tlv(
        b"\xA0",
        wrap_tlv(
            b"\x30",
            b"".join(
                [
                    wrap_tlv(b"\x80", b"manager-1"),
                    wrap_tlv(b"\x81", b"eim1.example.test"),
                    wrap_tlv(b"\x82", b"\x01"),
                ]
            ),
        ),
    )
    return wrap_tlv(bytes.fromhex("BF55"), entry)


def build_self_signed_cert_and_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Local Access Test"),
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
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    asn1_certificate = x509.Certificate.load(certificate_der)
    return asn1_certificate, private_key, certificate_der


def write_auth_credentials(target_dir: Path):
    certificate, private_key, certificate_der = build_self_signed_cert_and_key()

    cert_path = target_dir / "CERT.DPauth.ECDSA.der"
    key_path = target_dir / "SK.DPauth.ECDSA.pem"

    cert_path.write_bytes(certificate_der)
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return certificate, cert_path, key_path


def write_pb_credentials(target_dir: Path):
    certificate, private_key, certificate_der = build_self_signed_cert_and_key()

    cert_path = target_dir / "CERT.DPpb.ECDSA.der"
    key_path = target_dir / "SK.DPpb.ECDSA.pem"

    cert_path.write_bytes(certificate_der)
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return certificate, private_key, certificate_der, cert_path, key_path


def write_custom_smdp_credentials(
    target_dir: Path,
    stem: str,
    role: str,
    root_ci_pkid: str = "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
    server_address: str = "",
):
    _, private_key, certificate_der = build_self_signed_cert_and_key()
    cert_path = target_dir / f"{stem}.der"
    key_path = target_dir / f"{stem}.key.pem"
    cert_path.write_bytes(certificate_der)
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    metadata = {
        "role": role,
        "private_key_path": key_path.name,
        "root_ci_pkid": root_ci_pkid,
    }
    if len(server_address) > 0:
        metadata["server_address"] = server_address
    cert_path.with_suffix(".meta.json").write_text(json.dumps(metadata), encoding="utf-8")
    return cert_path, key_path


def build_authenticate_server_response() -> bytes:
    certificate, _, _ = build_self_signed_cert_and_key()
    ctx = ASN1Registry.CtxParams1(
        name="ctxParamsForCommonAuthentication",
        value=ASN1Registry.CtxParamsForCommonAuthentication(
            {
                "deviceInfo": {
                    "tac": b"\x01\x02\x03\x04",
                    "deviceCapabilities": {
                        "gsmSupportedRelease": b"\x99\x00\x00",
                    },
                }
            }
        ),
    )
    euicc_signed1 = ASN1Registry.EuiccSigned1(
        {
            "transactionId": ASN1Registry.TransactionId(b"\x11" * 16),
            "serverAddress": ASN1Registry.ServerAddress("local.isdr"),
            "serverChallenge": ASN1Registry.ServerChallenge(b"\x22" * 16),
            "euiccInfo2": core.Any(core.OctetString(b"\x00")),
            "ctxParams1": ctx,
        }
    )
    response_ok = ASN1Registry.AuthenticateResponseOk(
        {
            "euiccSigned1": euicc_signed1,
            "euiccSignature1": ASN1Registry.EuiccSignature1(b"\x33" * 64),
            "euiccCertificate": certificate,
            "nextCertInChain": certificate,
        }
    )
    choice = ASN1Registry.AuthenticateServerResponse(
        name="authenticateResponseOk",
        value=response_ok,
    )
    choice_bytes = choice.dump()
    return wrap_tlv(bytes.fromhex("BF38"), choice_bytes)


def build_prepare_download_response(transaction_id: bytes, euicc_otpk: bytes) -> bytes:
    euicc_signed2 = wrap_tlv(b"\x80", transaction_id) + wrap_tlv(bytes.fromhex("5F49"), euicc_otpk)
    response_ok = wrap_tlv(b"\x30", euicc_signed2) + wrap_tlv(bytes.fromhex("5F37"), b"\x44" * 64)
    return wrap_tlv(bytes.fromhex("BF21"), wrap_tlv(b"\xA0", response_ok))


def build_profile_installation_failure(transaction_id: bytes) -> bytes:
    notification_metadata = (
        wrap_tlv(b"\x80", bytes.fromhex("021F"))
        + wrap_tlv(b"\x81", bytes.fromhex("07"))
        + wrap_tlv(b"\x0C", b"smdpplus2.smdpp.example.test")
        + wrap_tlv(b"\x5A", bytes.fromhex("89460811111111111112"))
    )
    failure_result = wrap_tlv(
        b"\xA1",
        wrap_tlv(b"\x80", bytes([0x05])) + wrap_tlv(b"\x81", bytes([0x0D])),
    )
    value = (
        wrap_tlv(b"\x80", transaction_id)
        + wrap_tlv(bytes.fromhex("BF2F"), notification_metadata)
        + wrap_tlv(b"\x06", bytes.fromhex("88370A"))
        + wrap_tlv(b"\xA2", failure_result)
        + wrap_tlv(bytes.fromhex("5F37"), b"\xAA" * 64)
    )
    return wrap_tlv(bytes.fromhex("BF37"), wrap_tlv(bytes.fromhex("BF27"), value))


class FakeApduChannel:
    def __init__(self):
        self.send_calls = []
        self.chunked_calls = []
        self.auth_response = build_authenticate_server_response()
        self.notification_list_response = wrap_tlv(bytes.fromhex("BF28"), b"")
        self.notification_retrieve_response = wrap_tlv(bytes.fromhex("BF2B"), b"")
        self.notification_remove_response = bytes.fromhex("BF3000")
        self.profiles_info_response = build_profiles_info_response()
        self.retrieve_notifications_response = wrap_tlv(bytes.fromhex("BF2B"), b"")
        self.eim_configuration_response = build_eim_configuration_response()
        self.certs_response = bytes.fromhex("BF5600")
        self.euicc_info2_response = bytes.fromhex("BF2200")
        self.rat_response = bytes.fromhex("BF4300")

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if log_name == "LOCAL: Select ISD-R":
            return bytes.fromhex("6F00")
        if log_name == "LOCAL: Select ECASD":
            return bytes.fromhex("6F00")
        if log_name == "LOCAL: GetEuiccInfo1":
            return bytes.fromhex("BF2000")
        if log_name == "LOCAL: GetEuiccConfiguredData":
            return wrap_tlv(
                bytes.fromhex("BF3C"),
                wrap_tlv(b"\x80", b"smdpplus2.smdpp.example.test")
                + wrap_tlv(b"\x83", bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")),
            )
        if log_name == "LOCAL: GetEuiccChallenge":
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        if log_name == "LOCAL: GetProfilesInfo":
            return self.profiles_info_response
        if log_name == "LOCAL: GetEuiccInfo2":
            return self.euicc_info2_response
        if log_name == "LOCAL: GetRAT":
            return self.rat_response
        if log_name == "LOCAL: RetrieveNotificationsList":
            return self.retrieve_notifications_response
        if log_name == "LOCAL: GetEimConfigurationData":
            return self.eim_configuration_response
        if log_name == "LOCAL: GetCerts":
            return self.certs_response
        if log_name == "LOCAL: GetEID":
            return wrap_tlv(b"\x5A", bytes.fromhex("89049032118427504800000000000607"))
        if log_name == "LOCAL: GetIssuerIdentificationNumber":
            return wrap_tlv(b"\x42", bytes.fromhex("89049032"))
        if log_name == "LOCAL: ListNotifications":
            return self.notification_list_response
        if log_name.startswith("LOCAL: RetrieveNotification ["):
            return self.notification_retrieve_response
        if log_name.startswith("LOCAL: RemoveNotificationFromList ["):
            return self.notification_remove_response
        if log_name == "LOCAL: CancelSession":
            return bytes.fromhex("BF4103810102")
        raise AssertionError(f"Unexpected APDU log name: {log_name}")

    def send_chunked(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2_start: int,
        payload: bytes,
        log_name: str,
        chunk_size: int = 250,
    ) -> bytes:
        self.chunked_calls.append((cla, ins, p1, p2_start, payload, log_name, chunk_size))
        if log_name != "LOCAL: AuthenticateServer":
            raise AssertionError(f"Unexpected chunked APDU log name: {log_name}")
        return self.auth_response


class CaptureApduChannel:
    def __init__(self):
        self.send_calls = []
        self.chunked_calls = []

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        return b""

    def send_chunked(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2_start: int,
        payload: bytes,
        log_name: str,
        chunk_size: int = 250,
    ) -> bytes:
        self.chunked_calls.append((cla, ins, p1, p2_start, payload, log_name, chunk_size))
        return b""


class LocalAccessSessionTests(unittest.TestCase):
    def test_local_access_dependency_stubs_are_scoped_to_context(self):
        for module_name in [
            "smartcard",
            "smartcard.util",
            "smartcard.CardConnection",
            "smartcard.System",
            "smpp",
            "smpp.pdu",
            "smpp.pdu.pdu_types",
            "smpp.pdu.operations",
        ]:
            sys.modules.pop(module_name, None)

        smartcard_stub_active = local_access_session._smartcard_support_available() is False
        smpp_stub_active = local_access_session._smpp_support_available() is False

        with local_access_session._temporary_session_bound_dependency_stubs():
            from smartcard.util import toBytes
            from smpp.pdu import operations, pdu_types

            self.assertEqual(toBytes("01 02 0A"), [0x01, 0x02, 0x0A])
            # The bytes-accepting contract is a stub-only convenience: the
            # real pyscard toBytes() requires str and raises TypeError on
            # bytes input. Only assert that shape when our stub is in force.
            if smartcard_stub_active:
                self.assertEqual(toBytes(bytes.fromhex("ABCD")), [0xAB, 0xCD])
            if smpp_stub_active:
                self.assertTrue(hasattr(pdu_types, "DataCoding"))
                self.assertTrue(hasattr(operations, "SubmitSM"))
            else:
                self.assertTrue(
                    hasattr(pdu_types, "DataCoding") or hasattr(pdu_types, "PDU")
                )
                self.assertTrue(hasattr(operations, "SubmitSM"))

        smartcard_module_group = [
            "smartcard",
            "smartcard.util",
            "smartcard.CardConnection",
            "smartcard.System",
        ]
        smpp_module_group = [
            "smpp",
            "smpp.pdu",
            "smpp.pdu.pdu_types",
            "smpp.pdu.operations",
        ]
        # The context manager only records (and therefore only restores)
        # snapshots for module groups that actually had stubs installed. If
        # the real package is importable on this host, the context leaves
        # the real package in sys.modules untouched, which is correct.
        if smartcard_stub_active:
            for module_name in smartcard_module_group:
                self.assertNotIn(module_name, sys.modules)
        if smpp_stub_active:
            for module_name in smpp_module_group:
                self.assertNotIn(module_name, sys.modules)

    def test_pysim_helper_exposes_imports(self):
        """``ensure_repo_pysim_on_path`` is a prepend-helper, not a gate.

        It returns a ``Path`` when a developer checkout is present at
        ``<repo>/pysim`` (the upstream-branch-development workflow)
        and ``None`` when the operator is running against a pip
        install from the ``[saip]`` extra. Both states are valid; the
        invariant we actually care about is that ``pySim.esim.rsp``
        imports and exposes ``RspSessionState`` after the helper
        returned, regardless of which provisioning path resolved it.
        """
        pysim_root = ensure_repo_pysim_on_path()
        if pysim_root is not None:
            self.assertTrue(pysim_root.is_dir())
        module = importlib.import_module("pySim.esim.rsp")
        self.assertTrue(hasattr(module, "RspSessionState"))

    def test_decode_payload_bytes_accepts_ascii_hex_with_whitespace(self):
        payload = decode_payload_bytes(b"AA BB\nCC\r\n")
        self.assertEqual(payload, bytes.fromhex("AABBCC"))

    def test_decode_payload_bytes_accepts_ascii_hex_with_trailing_newline(self):
        payload = decode_payload_bytes(b"A00100\n")
        self.assertEqual(payload, bytes.fromhex("A00100"))

    def test_bpp_layout_summary_collapses_member_spam(self):
        lines = [
            "BF36 total=9587 value=9582",
            "BF23 total=178 value=174 transactionId=36F07BBD7B95FD8ACEB509DE0444CC14",
            "A0 total=28 value=26 members=1 memberLengths=[26]",
            "A0[1] len=26",
            "A1 total=164 value=161 members=1 memberLengths=[161]",
            "A1[1] len=161",
            "A2 total=76 value=74 members=1 memberLengths=[74]",
            "A2[1] len=74",
            "A3 total=9136 value=9132 members=9 memberLengths=[1036, 1036, 1036, 1036, 1036, 1036, 1036, 1036, 844]",
            "A3[1] len=1036 plaintext[0:1008] overlaps TLV[1] A0 header, TLV[2] B0 mf (2.23.143.1.2.1)",
            "A3[9] len=844 plaintext[8064:8884] overlaps TLV[14] A1 genericFileManagement, TLV[15] A6 securityDomain, TLV[16] A7 rfm, TLV[17] AA end",
        ]

        summary = LocalAccessShell._summarize_bpp_layout_lines(lines)

        self.assertIn("A0 total=28 value=26 members=1 lengths=26", summary)
        self.assertIn("A1 total=164 value=161 members=1 lengths=161", summary)
        self.assertIn("A2 total=76 value=74 members=1 lengths=74", summary)
        self.assertIn(
            "A3 total=9136 value=9132 members=9 lengths=8x1036 + 844 plaintext=1828 [0:8884]",
            summary,
        )
        self.assertIn(
            "A3 overlap span=TLV[1] A0 header -> TLV[17] AA end",
            summary,
        )
        self.assertFalse(any(line.startswith("A3[1]") for line in summary))

    def test_bpp_crypto_summary_collapses_chunk_debug(self):
        lines = [
            "BPP structure replaceSessionKeys=present",
            "BSP keys s_enc=65B46224F7638A5DB0EC9A20A73B3884 s_mac=793A3AC8B6C18393D7EC0709C772384B initial_mcv=5631AFF82BE03EA4F0913037F4905A43",
            "Pre-BSP payload bin=/tmp/_debug_pre_bsp_payload.bin hex=/tmp/_debug_pre_bsp_payload.txt sha256=B63DA9675E33DA301F158734EF5784F3AE31C4337F52E4286FBB898642AFD7B9",
            "A2 replaceSessionKeys ppk_enc=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ppk_mac=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB initial_mcv=00000000000000000000000000000000",
            "A3 prelude ppk chunk_size=1008 block_nr=1 mac_chain=00000000000000000000000000000000",
            "A3[1] plain=1008 plain_sha256=42D35DDC9D4BFC99A65EE5AEB5B49BD24B8EAB9B37F27231726789F99D754087 protected=1036 protected_tag=86 protected_value=1032 block_nr=1->2 mac_chain=00000000000000000000000000000000->E61355EFD8F59EE27D64D6859020AEE0 plaintext[0:1008] overlaps TLV[1] A0 header",
            "A3[2] plain=1008 plain_sha256=3CCA4B41F7006B1F3922C450722496EBC862FE6467A9E5708343AACC97C89252 protected=1036 protected_tag=86 protected_value=1032 block_nr=2->3 mac_chain=E61355EFD8F59EE27D64D6859020AEE0->947A7F38812A3679C85BB4FEB869D103 plaintext[1008:2016] overlaps TLV[2] B0 mf",
            "A3[9] plain=820 plain_sha256=A293E66D780E9E4B677B2F17E5D5C894119A41DB22564A6A866C09A81FBC2D50 protected=844 protected_tag=86 protected_value=840 block_nr=9->10 mac_chain=8224DB08DEF178736CFA48F62BF9F44A->7EBF091793F28A7B446693F4F284922C plaintext[8064:8884] overlaps TLV[17] AA end",
        ]

        summary = LocalAccessShell._summarize_bpp_crypto_lines(lines)

        self.assertIn(
            "Pre-BSP payload bin=_debug_pre_bsp_payload.bin hex=_debug_pre_bsp_payload.txt sha256=B63DA9675E33DA301F158734EF5784F3AE31C4337F52E4286FBB898642AFD7B9",
            summary,
        )
        self.assertIn(
            "A3 chunks=3 plain=2x1008 + 820 (2836) protected=2x1036 + 844 (2916)",
            summary,
        )
        self.assertIn(
            "A3 protected_value=2x1032 + 840 block_nr=1->10 tag=86 mac_chain=00000000000000000000000000000000->7EBF091793F28A7B446693F4F284922C",
            summary,
        )
        self.assertFalse(any(line.startswith("A3[1]") for line in summary))

    def test_resolve_profile_target_encodes_decimal_iccid_before_hex_fallback(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())

        resolved = session._resolve_profile_target("8901000000000000001")

        self.assertEqual(
            resolved,
            (session.TAG_ICCID, "981000000000000000F1"),
        )

    def test_delete_profile_uses_encoded_iccid_payload_for_decimal_identifier(self):
        session = LocalIsdrSession(apdu_channel=CaptureApduChannel())
        session.collect_profile_metadata = lambda: []  # type: ignore[method-assign]
        session._sync_pending_notifications = lambda response=b"": None  # type: ignore[method-assign]

        response = session.delete_profile("89460811111111111112")

        expected_payload = session._build_profile_state_payload(
            session.TAG_DELETE_PROFILE,
            session.TAG_ICCID,
            "98648011111111111121",
        )
        expected_apdu = bytes([0x80, 0xE2, 0x91, 0x00, len(expected_payload)]) + expected_payload

        self.assertEqual(response, b"")
        self.assertEqual(session.apdu_channel.send_calls[0][0], "LOCAL: Select ISD-R")
        self.assertEqual(session.apdu_channel.send_calls[1][0], "LOCAL: DeleteProfile [Block 0]")
        self.assertEqual(session.apdu_channel.send_calls[1][1], expected_apdu)

    def test_analyze_payload_pair_reports_first_diff(self):
        analysis = analyze_payload_pair(bytes.fromhex("A00100"), bytes.fromhex("A00200"))
        self.assertFalse(analysis["equal"])
        self.assertEqual(analysis["first_diff"], 1)
        self.assertEqual(analysis["diff_spans"], [(1, 2)])

    def test_build_effective_metadata_document_derives_fields_from_profile(self):
        profile_path = Path(__file__).resolve().parent.parent / "SCP11" / "local_access" / "profile" / "test_profile.txt"
        profile_bytes = bytes.fromhex(profile_path.read_text(encoding="utf-8").strip())
        with tempfile.TemporaryDirectory() as metadata_dir:
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(METADATA_DIR=str(metadata_dir)),
                apdu_channel=FakeApduChannel(),
            )

            metadata = session._build_effective_metadata_document(profile_bytes)

        self.assertEqual(metadata["profile"]["iccid"], "89460811111111111112")
        self.assertEqual(metadata["profile"]["name"], "Sample Lab")
        self.assertEqual(metadata["profile"]["profile_type"], "Sample Lab")
        self.assertEqual(metadata["operator"]["name"], "Sample Lab")
        self.assertTrue(metadata["notification_events"]["enable"])
        self.assertTrue(metadata["notification_events"]["disable"])
        self.assertTrue(metadata["notification_events"]["delete"])

    def test_build_effective_metadata_document_falls_back_to_header_tlv_when_pysim_parse_fails(self):
        profile_path = Path(__file__).resolve().parent.parent / "SCP11" / "local_access" / "profile" / "test_profile.txt"
        profile_bytes = bytes.fromhex(profile_path.read_text(encoding="utf-8").strip())
        local_access_session = importlib.import_module("SCP11.local_access.session")
        if getattr(local_access_session, "pysim_saip", None) is None:
            self.skipTest("pySim SAIP support unavailable in this environment")

        with tempfile.TemporaryDirectory() as metadata_dir:
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(METADATA_DIR=str(metadata_dir)),
                apdu_channel=FakeApduChannel(),
            )
            with mock.patch.object(
                local_access_session.pysim_saip.ProfileElementSequence,
                "from_der",
                side_effect=RuntimeError("synthetic parse failure"),
            ):
                metadata = session._build_effective_metadata_document(profile_bytes)

        self.assertEqual(metadata["profile"]["iccid"], "89460811111111111112")
        self.assertEqual(metadata["profile"]["name"], "Sample Lab")
        self.assertEqual(metadata["profile"]["profile_type"], "Sample Lab")
        self.assertEqual(metadata["operator"]["name"], "Sample Lab")

    def test_default_metadata_file_does_not_override_profile_identity_fields(self):
        profile_path = Path(__file__).resolve().parent.parent / "SCP11" / "local_access" / "profile" / "test_profile.txt"
        profile_bytes = bytes.fromhex(profile_path.read_text(encoding="utf-8").strip())
        metadata_document = {
            "profile": {
                "name": "Sample Lab",
                "iccid": "89460811111111111112",
            },
            "operator": {
                "name": "Sample Lab",
                "mcc": "999",
                "mnc": "99",
            },
        }
        with tempfile.TemporaryDirectory() as metadata_dir:
            metadata_path = Path(metadata_dir) / "metadata.json"
            metadata_path.write_text(json.dumps(metadata_document), encoding="utf-8")
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(METADATA_DIR=str(metadata_dir)),
                apdu_channel=FakeApduChannel(),
            )

            metadata = session._build_effective_metadata_document(profile_bytes)

        self.assertEqual(metadata["profile"]["name"], "Sample Lab")
        self.assertEqual(metadata["profile"]["profile_type"], "Sample Lab")
        self.assertEqual(metadata["profile"]["iccid"], "89460811111111111112")
        self.assertEqual(metadata["operator"]["name"], "Sample Lab")
        self.assertEqual(metadata["operator"]["mcc"], "999")
        self.assertEqual(metadata["operator"]["mnc"], "99")

    def test_open_session_prefers_manual_override_folder(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            certs_dir = Path(temp_dir)
            _, cert_path, key_path = write_auth_credentials(certs_dir)
            cfg = LocalAccessConfig(
                CERTS_DIR=str(certs_dir),
                CERT_PATH_AUTH=str(cert_path),
                KEY_PATH_AUTH=str(key_path),
                SERVER_ADDRESS="local.isdr",
            )
            channel = FakeApduChannel()
            session = LocalIsdrSession(cfg=cfg, apdu_channel=channel)
            channel.send_calls.clear()
            channel.chunked_calls.clear()

            result = session.open_session()

        self.assertTrue(session.state.isdr_selected)
        self.assertTrue(session.state.session_open)
        self.assertEqual(len(session.state.transaction_id), 16)
        self.assertEqual(session.state.card_challenge, bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55"))
        self.assertEqual(result.euicc_signature1, b"\x33" * 64)
        self.assertTrue(result.authenticate_server_response.startswith(bytes.fromhex("BF38")))
        self.assertTrue(session.state.authenticate_server_request.startswith(bytes.fromhex("BF38")))
        self.assertIn("F54172BDF98A95D65CBEB88A38A1C11D800A85C3", session.state.allowed_ci_pkids)
        self.assertEqual(session.state.selected_auth_certificate_path, str(cert_path))
        self.assertEqual(channel.send_calls[0][0], "LOCAL: Select ISD-R")
        self.assertEqual(channel.send_calls[1][0], "LOCAL: GetEuiccInfo1")
        self.assertEqual(channel.send_calls[2][0], "LOCAL: GetEuiccConfiguredData")
        self.assertEqual(channel.send_calls[3][0], "LOCAL: GetEuiccChallenge")
        self.assertEqual(channel.chunked_calls[0][5], "LOCAL: AuthenticateServer")

    def test_open_session_accepts_drop_in_smdp_credentials_with_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            certs_dir = Path(temp_dir)
            auth_cert_path, auth_key_path = write_custom_smdp_credentials(
                certs_dir,
                "operator-alpha-auth",
                "auth",
                server_address="local.smdpp.operator.example",
            )
            pb_cert_path, pb_key_path = write_custom_smdp_credentials(
                certs_dir,
                "operator-alpha-pb",
                "pb",
            )
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(
                    CERTS_DIR=str(certs_dir),
                    SERVER_ADDRESS="local.isdr",
                ),
                apdu_channel=FakeApduChannel(),
            )

            session.open_session()

        self.assertEqual(session.state.selected_auth_certificate_path, str(auth_cert_path.resolve()))
        self.assertEqual(session.state.selected_auth_private_key_path, str(auth_key_path.resolve()))
        self.assertEqual(session.state.selected_auth_certificate_reason, "local_override_ci_match")
        self.assertEqual(session.state.selected_local_smdp_address, "local.smdpp.operator.example")
        self.assertEqual(session.state.selected_pb_certificate_path, str(pb_cert_path.resolve()))
        self.assertEqual(session.state.selected_pb_private_key_path, str(pb_key_path.resolve()))
        self.assertEqual(session.state.selected_pb_certificate_reason, "local_override_ci_match")

    def test_cancel_session_wraps_cancel_apdu(self):
        channel = FakeApduChannel()
        session = LocalIsdrSession(apdu_channel=channel)
        session.state.transaction_id = b"\x10" * 16
        session.state.session_open = True

        response = session.cancel_session(reason=LocalIsdrSession.CANCEL_SESSION_REASON_TIMEOUT)

        self.assertEqual(response, bytes.fromhex("BF4103810102"))
        self.assertFalse(session.state.session_open)
        self.assertEqual(channel.send_calls[-1][0], "LOCAL: CancelSession")
        cancel_apdu = channel.send_calls[-1][1]
        self.assertTrue(cancel_apdu.startswith(bytes.fromhex("80E29100")))
        self.assertIn(bytes.fromhex("BF41"), cancel_apdu)
        self.assertTrue(cancel_apdu.endswith(bytes.fromhex("810102")))

    def test_send_retrieve_store_data_uses_chunked_transport_for_large_payload(self):
        channel = CaptureApduChannel()
        session = LocalIsdrSession(apdu_channel=channel)
        payload = bytes.fromhex("BF57") + (b"\xAA" * 298)
        channel.send_calls.clear()

        response = session._send_retrieve_store_data(payload, "LOCAL: ExtendedStoreData")

        self.assertEqual(response, b"")
        self.assertEqual(len(channel.send_calls), 0)
        self.assertEqual(len(channel.chunked_calls), 1)
        cla, ins, p1, p2_start, sent_payload, log_name, chunk_size = channel.chunked_calls[0]
        self.assertEqual((cla, ins, p1, p2_start), (0x80, 0xE2, 0x91, 0x00))
        self.assertEqual(sent_payload, payload)
        self.assertEqual(log_name, "LOCAL: ExtendedStoreData")
        self.assertEqual(chunk_size, 250)

    def test_close_session_without_active_transaction_is_noop(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())

        response = session.close_session()

        self.assertEqual(response, b"")

    def test_discover_card_collects_live_style_snapshot(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())

        snapshot = session.discover_card()

        self.assertEqual(snapshot["eid"], "89049032118427504800000000000607")
        self.assertEqual(snapshot["issuer_number"], "89049032")
        self.assertEqual(snapshot["issuer_name"], "Giesecke+Devrient")
        self.assertEqual(snapshot["configured_decoded"]["default_smdp"], "smdpplus2.smdpp.example.test")
        self.assertEqual(len(snapshot["profiles"]), 2)
        self.assertEqual(snapshot["profiles"][0].state, "ENABLED")
        self.assertEqual(snapshot["profiles"][1].nickname, "Secondary")
        self.assertEqual(
            [name for name, _ in session.apdu_channel.send_calls[:15]],
            [
                "LOCAL: Select ISD-R",
                "LOCAL: GetProfilesInfo",
                "LOCAL: GetEuiccConfiguredData",
                "LOCAL: Select ECASD",
                "LOCAL: GetEID",
                "LOCAL: Select ISD-R",
                "LOCAL: Select ECASD",
                "LOCAL: GetIssuerIdentificationNumber",
                "LOCAL: Select ISD-R",
                "LOCAL: GetEuiccInfo1",
                "LOCAL: GetEuiccInfo2",
                "LOCAL: GetRAT",
                "LOCAL: RetrieveNotificationsList",
                "LOCAL: GetEimConfigurationData",
                "LOCAL: GetCerts",
            ],
        )

    def test_discover_card_returns_decode_errors_without_raising(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        session.decode_profile_metadata_rows = mock.Mock(
            side_effect=RuntimeError("synthetic profile decode failure")
        )
        session.decode_euicc_configured_data = mock.Mock(
            side_effect=RuntimeError("synthetic configured-data decode failure")
        )

        snapshot = session.discover_card()

        self.assertEqual(snapshot["profiles"], [])
        self.assertEqual(snapshot["configured_decoded"]["default_smdp"], "")
        self.assertIn("synthetic profile decode failure", snapshot["profiles_decode_error"])
        self.assertIn(
            "synthetic configured-data decode failure",
            snapshot["configured_decode_error"],
        )

    def test_pre_bsp_debug_files_use_dedicated_debug_dir(self):
        with tempfile.TemporaryDirectory() as profile_dir, tempfile.TemporaryDirectory() as debug_dir:
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(
                    PROFILE_DIR=str(profile_dir),
                    DEBUG_DIR=str(debug_dir),
                ),
                apdu_channel=FakeApduChannel(),
            )

            session._persist_pre_bsp_payload_debug(bytes.fromhex("A00100"))

            bin_path = Path(debug_dir) / "_debug_pre_bsp_payload.bin"
            hex_path = Path(debug_dir) / "_debug_pre_bsp_payload.txt"
            self.assertEqual(Path(session.state.last_pre_bsp_payload_bin_path), bin_path.resolve())
            self.assertEqual(Path(session.state.last_pre_bsp_payload_hex_path), hex_path.resolve())
            self.assertEqual(bin_path.read_bytes(), bytes.fromhex("A00100"))
            self.assertEqual(hex_path.read_text(encoding="ascii").strip(), "A00100")
            self.assertEqual(list(Path(profile_dir).iterdir()), [])

    def test_local_shell_enable_profile_auto_disables_active_profile(self):
        shell = LocalAccessShell()
        calls = []
        shell.session = SimpleNamespace(
            collect_profile_metadata=lambda: [
                SimpleNamespace(
                    iccid="8901000000000000001",
                    aid="A0000005591010FFFFFFFF8900001100",
                    state="ENABLED",
                    profile_class="OPER",
                    nickname="Primary",
                    profile_name="",
                ),
                SimpleNamespace(
                    iccid="8901000000000000002",
                    aid="A0000005591010FFFFFFFF8900001200",
                    state="DISABLED",
                    profile_class="OPER",
                    nickname="Secondary",
                    profile_name="",
                ),
            ],
            resolve_profile_target=lambda identifier: (
                b"\x5A",
                "981000000000000000F2",
            )
            if identifier == "8901000000000000002"
            else (
                b"\x4F",
                "A0000005591010FFFFFFFF8900001100",
            ),
            disable_profile=lambda identifier: calls.append(("disable", identifier)) or bytes.fromhex("BF3203800100"),
            enable_profile=lambda identifier: calls.append(("enable", identifier)) or bytes.fromhex("BF3103800100"),
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_enable_profile(["8901000000000000002"])

        # The shared profile-action helpers normalise both the
        # auto-disable and the enable call to the canonical metadata
        # identifier (AID first, ICCID fallback). Operators still type
        # the ICCID — resolution happens inside the helpers.
        self.assertEqual(
            calls,
            [
                ("disable", "A0000005591010FFFFFFFF8900001100"),
                ("enable", "A0000005591010FFFFFFFF8900001200"),
            ],
        )
        self.assertIn("auto-disabling active profile", output.getvalue())

    def test_local_shell_enable_profile_refuses_auto_disable_when_ppr1_forbids_disable(self):
        shell = LocalAccessShell()
        calls = []
        shell.session = SimpleNamespace(
            collect_profile_metadata=lambda: [
                SimpleNamespace(
                    iccid="8901000000000000001",
                    aid="A0000005591010FFFFFFFF8900001100",
                    state="ENABLED",
                    profile_class="OPER",
                    nickname="Primary",
                    profile_name="",
                    profile_policy_rules_hex="0640",
                ),
                SimpleNamespace(
                    iccid="8901000000000000002",
                    aid="A0000005591010FFFFFFFF8900001200",
                    state="DISABLED",
                    profile_class="OPER",
                    nickname="Secondary",
                    profile_name="",
                    profile_policy_rules_hex="",
                ),
            ],
            resolve_profile_target=lambda identifier: (
                b"\x5A",
                "981000000000000000F2",
            )
            if identifier == "8901000000000000002"
            else (
                b"\x4F",
                "A0000005591010FFFFFFFF8900001100",
            ),
            disable_profile=lambda identifier: calls.append(("disable", identifier)) or bytes.fromhex("BF3203800100"),
            enable_profile=lambda identifier: calls.append(("enable", identifier)) or bytes.fromhex("BF3103800100"),
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_enable_profile(["8901000000000000002"])

        self.assertEqual(calls, [])
        self.assertIn("guarded mode refused to auto-disable active profile", output.getvalue())
        self.assertIn("ppr1-disable-not-allowed", output.getvalue())

    def test_local_shell_disable_profile_noops_when_already_disabled(self):
        shell = LocalAccessShell()
        calls = []
        shell.session = SimpleNamespace(
            collect_profile_metadata=lambda: [
                SimpleNamespace(
                    iccid="8901000000000000002",
                    aid="A0000005591010FFFFFFFF8900001200",
                    state="DISABLED",
                    profile_class="OPER",
                    nickname="Secondary",
                    profile_name="",
                )
            ],
            resolve_profile_target=lambda identifier: (
                b"\x5A",
                "981000000000000000F2",
            ),
            disable_profile=lambda identifier: calls.append(("disable", identifier)) or bytes.fromhex("BF3203800100"),
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_disable_profile(["8901000000000000002"])

        self.assertEqual(calls, [])
        self.assertIn("already disabled", output.getvalue())

    def test_local_shell_delete_profile_auto_disables_enabled_target_first(self):
        """Harmonised contract: deleting an ENABLED profile auto-disables it
        first (mirrors eSIM Live / Test / Local eIM after SCP11 command
        harmonisation). The previous "delete-while-enabled (laptop
        override)" behaviour is gone — SGP.22 §5.7.18 forbids it and
        relying on the card to forgive the sequence was non-portable."""
        shell = LocalAccessShell()
        calls = []
        shell.session = SimpleNamespace(
            collect_profile_metadata=lambda: [
                SimpleNamespace(
                    iccid="8901000000000000001",
                    aid="A0000005591010FFFFFFFF8900001100",
                    state="ENABLED",
                    profile_class="OPER",
                    nickname="Primary",
                    profile_name="",
                ),
                SimpleNamespace(
                    iccid="8901000000000000002",
                    aid="A0000005591010FFFFFFFF8900001200",
                    state="DISABLED",
                    profile_class="OPER",
                    nickname="Secondary",
                    profile_name="",
                ),
            ],
            resolve_profile_target=lambda identifier: (
                b"\x5A",
                "981000000000000000F1",
            ),
            disable_profile=lambda identifier: calls.append(("disable", identifier)) or bytes.fromhex("BF3203800100"),
            delete_profile=lambda identifier: calls.append(("delete", identifier)) or bytes.fromhex("BF3303800100"),
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_delete_profile(["8901000000000000001"])

        # The shared helpers resolve to the canonical metadata
        # identifier (AID first, ICCID fallback) so the underlying
        # ``disable_profile`` / ``delete_profile`` callbacks see the
        # same target the eSIM Live shell would. Operators still type
        # the ICCID — the resolution happens inside the helpers.
        self.assertEqual(
            calls,
            [
                ("disable", "A0000005591010FFFFFFFF8900001100"),
                ("delete", "A0000005591010FFFFFFFF8900001100"),
            ],
        )
        rendered = output.getvalue()
        self.assertIn("auto-disabling enabled target", rendered)

    def test_local_shell_help_shows_canonical_commands_and_alias_notes(self):
        shell = LocalAccessShell()
        shell._terminal_width = lambda: 120  # type: ignore[method-assign]

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_help([])

        rendered = output.getvalue()
        self.assertIn("Use HELP <command> for usage and alias details.", rendered)
        self.assertIn("Canonical command names are listed here", rendered)
        self.assertIn("ENABLE-PROFILE <id>", rendered)
        self.assertIn("DELETE-PROFILE <id>", rendered)
        self.assertNotIn("  ENABLE <id>", rendered)
        self.assertNotIn("  DELETE <id>", rendered)
        self.assertIn("Aliases: ENABLE, DISABLE, DELETE", rendered)
        self.assertTrue(
            any(
                "CERTS [--json|--yaml]" in line and "STATUS" in line
                for line in rendered.splitlines()
            )
        )

    def test_local_shell_discover_reports_decode_warnings(self):
        shell = LocalAccessShell()
        shell.session = SimpleNamespace(
            discover_card=lambda: {
                "profiles": [],
                "configured_decoded": {
                    "default_smdp": "",
                    "root_smds_primary": "",
                    "root_smds_additional": [],
                    "allowed_ci_pkid": [],
                },
                "profiles_decode_error": "synthetic profile decode failure",
                "configured_decode_error": "synthetic configured-data decode failure",
            }
        )

        with mock.patch(
            "SCP11.local_access.main.render_consolidated_discovery_snapshot"
        ) as mocked_render:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                shell._cmd_discover()

        mocked_render.assert_called_once()
        rendered = output.getvalue()
        self.assertIn("Profile metadata decode failed: synthetic profile decode failure", rendered)
        self.assertIn(
            "eUICC configured-data decode failed: synthetic configured-data decode failure",
            rendered,
        )

    def test_local_shell_run_commands_returns_error_after_command_exception(self):
        shell = LocalAccessShell()
        shell._build_session = lambda: None  # type: ignore[method-assign]
        shell._finalize_recording_on_exit = lambda: None  # type: ignore[method-assign]
        shell._execute_command = mock.Mock(side_effect=RuntimeError("synthetic decode failure"))

        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as raised:
                shell.run_commands("DISCOVER")

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("synthetic decode failure", output.getvalue())

    def test_local_shell_help_alias_lookup_resolves_to_canonical_command(self):
        shell = LocalAccessShell()

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_help(["DELETE"])

        rendered = output.getvalue()
        self.assertIn("[DELETE-PROFILE]", rendered)
        self.assertIn("Usage   : DELETE-PROFILE <id>", rendered)
        self.assertIn("Aliases : DELETE", rendered)

    def test_local_shell_debug_flag_strips_argument_and_toggles_raw_apdu_logging(self):
        class _FakeApduChannel:
            def __init__(self) -> None:
                self.raw_apdu_logging = False
                self.raw_logging_updates: list[bool] = []

            def set_raw_apdu_logging(self, enabled: bool) -> None:
                self.raw_apdu_logging = bool(enabled)
                self.raw_logging_updates.append(bool(enabled))

            def get_raw_apdu_logging(self) -> bool:
                return bool(self.raw_apdu_logging)

        shell = LocalAccessShell()
        fake_channel = _FakeApduChannel()
        captured_arguments: list[list[str]] = []
        shell.session = SimpleNamespace(
            apdu_channel=fake_channel,
            state=SimpleNamespace(session_open=False),
        )
        shell._cmd_profile = lambda arguments: captured_arguments.append(list(arguments))

        keep_running = shell._execute_command("PROFILE", ["demo_profile.txt", "--debug"])

        self.assertTrue(keep_running)
        self.assertEqual(captured_arguments, [["demo_profile.txt"]])
        self.assertEqual(fake_channel.raw_logging_updates, [True, False])

    def test_local_shell_global_debug_enables_transport_logging_on_session_build(self):
        class _FakeApduChannel:
            def __init__(self) -> None:
                self.raw_apdu_logging = False
                self.raw_logging_updates: list[bool] = []

            def set_raw_apdu_logging(self, enabled: bool) -> None:
                self.raw_apdu_logging = bool(enabled)
                self.raw_logging_updates.append(bool(enabled))

            def get_raw_apdu_logging(self) -> bool:
                return bool(self.raw_apdu_logging)

        fake_channel = _FakeApduChannel()
        fake_session = SimpleNamespace(
            apdu_channel=fake_channel,
            state=SimpleNamespace(session_open=False),
        )

        with mock.patch.dict(os.environ, {"YGGDRASIM_GLOBAL_DEBUG": "1"}, clear=False):
            shell = LocalAccessShell()
        shell._session_cls = lambda cfg: fake_session

        shell._build_session()

        self.assertEqual(fake_channel.raw_logging_updates, [True])

    def test_local_shell_record_exports_replayable_commands_and_apdu_trace(self):
        shell = LocalAccessShell()
        shell.session = SimpleNamespace(
            apdu_channel=SimpleNamespace(),
            state=SimpleNamespace(session_open=False),
        )

        def _fake_profile(arguments: list[str]) -> None:
            self.assertEqual(arguments, ["demo_profile.txt"])
            emit_apdu_trace_event(
                log_name="LOCAL: Test APDU",
                apdu=bytes.fromhex("00A40400"),
                response=bytes.fromhex("6F00"),
                sw1=0x90,
                sw2=0x00,
                transport="FakeApduChannel",
            )

        shell._cmd_profile = _fake_profile

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "local_record.yaml"

            with contextlib.redirect_stdout(io.StringIO()):
                shell._execute_command(
                    "RECORD",
                    ["START", str(output_path)],
                    raw_command=f"RECORD START {output_path}",
                )
                shell._execute_command(
                    "PROFILE",
                    ["demo_profile.txt"],
                    raw_command="PROFILE demo_profile.txt",
                )
                shell._execute_command(
                    "RECORD",
                    ["STOP"],
                    raw_command="RECORD STOP",
                )

            payload = yaml.safe_load(output_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["replay"]["commands"], ["PROFILE demo_profile.txt"])
        self.assertEqual(payload["commands"][0]["canonical_command"], "PROFILE")
        self.assertEqual(payload["commands"][0]["apdu_count"], 1)
        self.assertEqual(payload["apdu_trace"][0]["log_name"], "LOCAL: Test APDU")
        self.assertEqual(
            payload["apdu_trace"][0]["command_replay"],
            "PROFILE demo_profile.txt",
        )

    def test_local_shell_discover_prints_live_style_sections(self):
        shell = LocalAccessShell()
        shell.session = SimpleNamespace(
            discover_card=lambda: {
                "eid": "89049032118427504800000000000607",
                "profiles": [
                    SimpleNamespace(
                        iccid="8901000000000000001",
                        aid="A0000005591010FFFFFFFF8900001100",
                        state="ENABLED",
                        profile_class="OPER",
                        nickname="Primary",
                        profile_name="",
                    )
                ],
                "configured_raw": wrap_tlv(
                    bytes.fromhex("BF3C"),
                    wrap_tlv(b"\x80", b"smdpplus2.smdpp.example.test"),
                ),
                "configured_decoded": {
                    "default_smdp": "smdpplus2.smdpp.example.test",
                    "root_smds_primary": "",
                    "root_smds_additional": [],
                    "allowed_ci_pkid": [],
                },
                "euicc_info1": bytes.fromhex("BF2000"),
                "euicc_info2": bytes.fromhex("BF2200"),
                "rat": bytes.fromhex("BF4300"),
                "notifications": wrap_tlv(bytes.fromhex("BF2B"), b""),
                "eim_configuration": build_eim_configuration_response(),
                "certs": bytes.fromhex("BF5600"),
            }
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_discover()

        rendered = output.getvalue()
        self.assertIn("=== SGP.32 Consolidated Data Retrieval ===", rendered)
        self.assertIn("=== Running SGP.22/SGP.32 Scan ===", rendered)
        self.assertIn("[+] EID", rendered)
        self.assertIn("[+] GetProfilesInfo", rendered)
        self.assertIn("[+] GetEuiccConfiguredData", rendered)
        self.assertIn("[+] GetEuiccInfo1", rendered)
        self.assertIn("[+] GetEuiccInfo2", rendered)
        self.assertIn("[+] GetRAT", rendered)
        self.assertIn("[+] RetrieveNotificationsList", rendered)
        self.assertIn("[+] GetEimConfigurationData", rendered)
        self.assertIn("[+] GetCerts", rendered)

    def test_local_shell_certs_prints_selected_drop_in_summary(self):
        shell = LocalAccessShell()
        shell.session = SimpleNamespace(
            list_local_smdp_certificate_inventory=lambda: {
                "allowed_ci_pkids": ["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"],
                "selected_auth": {
                    "certificate_path": "/tmp/operator-alpha-auth.der",
                    "private_key_path": "/tmp/operator-alpha-auth.key.pem",
                    "selection_reason": "local_override_ci_match",
                    "server_address": "local.smdpp.operator.example",
                },
                "selected_pb": {
                    "certificate_path": "/tmp/operator-alpha-pb.der",
                    "private_key_path": "/tmp/operator-alpha-pb.key.pem",
                    "selection_reason": "local_override_ci_match",
                },
                "auth_records": [{}],
                "pb_records": [{}],
            }
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_certs([])

        rendered = output.getvalue()
        self.assertIn("Local SM-DP+ Certificate Inventory", rendered)
        self.assertIn("/tmp/operator-alpha-auth.der", rendered)
        self.assertIn("local.smdpp.operator.example", rendered)
        self.assertIn("local_override_ci_match", rendered)

    def test_local_shell_certs_yaml_output_is_parseable(self):
        shell = LocalAccessShell()
        shell.session = SimpleNamespace(
            list_local_smdp_certificate_inventory=lambda: {
                "allowed_ci_pkids": ["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"],
                "selected_auth": {
                    "certificate_path": "/tmp/operator-alpha-auth.der",
                    "private_key_path": "/tmp/operator-alpha-auth.key.pem",
                    "selection_reason": "local_override_ci_match",
                },
                "selected_pb": {
                    "certificate_path": "/tmp/operator-alpha-pb.der",
                    "private_key_path": "/tmp/operator-alpha-pb.key.pem",
                    "selection_reason": "local_override_ci_match",
                },
                "auth_records": [{}],
                "pb_records": [{}],
            }
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_certs(["--yaml"])

        payload = yaml.safe_load(output.getvalue())
        self.assertEqual(
            payload["selected_auth"]["certificate_path"],
            "/tmp/operator-alpha-auth.der",
        )
        self.assertEqual(payload["selected_pb"]["selection_reason"], "local_override_ci_match")

    def test_local_shell_explain_last_yaml_output_is_parseable(self):
        shell = LocalAccessShell()
        shell.session = SimpleNamespace(
            current_eid="89049032118427504800000000000607",
            resolve_profile_path=lambda: "/tmp/profile.der",
            resolve_metadata_path=lambda: "/tmp/metadata.json",
            state=SimpleNamespace(
                session_open=False,
                isdr_selected=True,
                transaction_id=b"\x01\x02",
                card_challenge=b"\x03\x04",
                server_challenge=b"\x05\x06",
                load_notifications_synced=True,
                allowed_ci_pkids=["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"],
                selected_ci_pkid="F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
                selected_auth_certificate_path="/tmp/operator-alpha-auth.der",
                selected_auth_private_key_path="/tmp/operator-alpha-auth.key.pem",
                selected_auth_certificate_reason="local_override_ci_match",
                selected_pb_certificate_path="/tmp/operator-alpha-pb.der",
                selected_pb_private_key_path="/tmp/operator-alpha-pb.key.pem",
                selected_pb_certificate_reason="local_override_ci_match",
                selected_local_smdp_address="local.smdpp.operator.example",
                profile_override_path="",
                metadata_override_path="",
                select_response=b"\x90\x00",
                euicc_info1=bytes.fromhex("BF2000"),
                configured_data=bytes.fromhex("BF3C00"),
                authenticate_server_request=bytes.fromhex("BF3800"),
                authenticate_server_response=bytes.fromhex("BF2100"),
                euicc_signed1=b"\xAA",
                euicc_signature1=b"\xBB",
                prepare_download_response=bytes.fromhex("BF2100"),
                last_load_bpp_response=bytes.fromhex("BF3700"),
                cancel_session_response=bytes.fromhex("BF4103810102"),
                bpp_command_descriptions=["StoreData chunk 1"],
                upp_protected_command_descriptions=["Protected chunk 1"],
                last_bpp_layout_lines=["A0 total=1 memberLengths=[1]"],
                last_bpp_crypto_debug_lines=[
                    "Pre-BSP payload bin=/tmp/pre.bin hex=/tmp/pre.txt sha256=AA",
                    "A3[0] plain=1 plain_sha256=AA protected=2 protected_tag=86 "
                    "protected_value=1 block_nr=1->2 mac_chain=AA->BB",
                ],
                last_pre_bsp_payload_bin_path="/tmp/pre.bin",
                last_pre_bsp_payload_hex_path="/tmp/pre.txt",
            ),
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_explain_last(["--yaml"])

        payload = yaml.safe_load(output.getvalue())
        self.assertTrue(payload["session_initialized"])
        self.assertEqual(payload["session"]["active_eid"], "89049032118427504800000000000607")
        self.assertEqual(payload["targets"]["resolved_profile_path"], "/tmp/profile.der")
        self.assertEqual(payload["responses"]["last_load_bpp_response"]["len"], 3)
        self.assertEqual(
            payload["bpp"]["debug_artifacts"]["pre_bsp_payload_hex_path"],
            "/tmp/pre.txt",
        )

    def test_real_sgp26_bundle_resolves_variant_o_nist_auth_and_pb(self):
        project_root = Path(__file__).resolve().parent.parent
        valid_root = project_root / "SCP11" / "SGP.26_test_Certs" / "Valid Test Cases"
        store = LocalSgp26CertStore(str(valid_root), prefer_curve="NIST")

        auth_record = store.resolve_auth_record(["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"])
        pb_record = store.resolve_pb_record(["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"])

        self.assertIsNotNone(auth_record)
        self.assertIsNotNone(pb_record)
        self.assertEqual(auth_record.root_ci_ski, "F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
        self.assertEqual(pb_record.root_ci_ski, "F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
        self.assertEqual(auth_record.curve, "NIST")
        self.assertEqual(pb_record.curve, "NIST")
        self.assertIn("Variant O/SM-DP+/SM_DPauth/CERT_S_SM_DPauth_VARO_SIG_NIST.der", auth_record.certificate_path)
        self.assertIn("Variant O/SM-DP+/SM_DPpb/CERT_S_SM_DPpb_VARO_SIG_NIST.der", pb_record.certificate_path)

    def test_open_session_uses_preloaded_bundle_when_certs_folder_has_no_override(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            certs_dir = Path(temp_dir)
            cfg = LocalAccessConfig(
                CERTS_DIR=str(certs_dir),
                CERT_PATH_AUTH=str(certs_dir / "CERT.DPauth.ECDSA.der"),
                KEY_PATH_AUTH=str(certs_dir / "SK.DPauth.ECDSA.pem"),
                CERT_PATH_PB=str(certs_dir / "CERT.DPpb.ECDSA.der"),
                KEY_PATH_PB=str(certs_dir / "SK.DPpb.ECDSA.pem"),
                SERVER_ADDRESS="local.isdr",
            )
            channel = FakeApduChannel()
            session = LocalIsdrSession(cfg=cfg, apdu_channel=channel)

            session.open_session()

        self.assertIn("Variant O/SM-DP+/SM_DPauth/CERT_S_SM_DPauth_VARO_SIG_NIST.der", session.state.selected_auth_certificate_path)

    def test_partial_manual_override_pair_falls_back_to_bundle(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            certs_dir = Path(temp_dir)
            certs_dir.joinpath("CERT.DPauth.ECDSA.der").write_bytes(b"\x30\x00")
            cfg = LocalAccessConfig(
                CERTS_DIR=str(certs_dir),
                CERT_PATH_AUTH=str(certs_dir / "CERT.DPauth.ECDSA.der"),
                KEY_PATH_AUTH=str(certs_dir / "SK.DPauth.ECDSA.pem"),
                SERVER_ADDRESS="local.isdr",
            )
            session = LocalIsdrSession(cfg=cfg, apdu_channel=FakeApduChannel())

            session.open_session()

        self.assertIn(
            "Variant O/SM-DP+/SM_DPauth/CERT_S_SM_DPauth_VARO_SIG_NIST.der",
            session.state.selected_auth_certificate_path,
        )
        self.assertEqual(session.state.selected_auth_certificate_reason, "sgp26_bundle_ci_match")

    def test_resolve_profile_path_uses_single_default_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_dir = Path(temp_dir)
            default_profile = profile_dir / "default-profile.bin"
            default_profile.write_bytes(b"\x01\x02\x03")
            cfg = LocalAccessConfig(PROFILE_DIR=str(profile_dir))
            session = LocalIsdrSession(cfg=cfg, apdu_channel=FakeApduChannel())

            resolved_path = session.resolve_profile_path()

        self.assertEqual(resolved_path, str(default_profile.resolve()))

    def test_profile_override_path_wins_over_default_directory_file(self):
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as override_dir:
            profile_dir = Path(temp_dir)
            default_profile = profile_dir / "default-profile.bin"
            default_profile.write_bytes(b"\x01\x02\x03")
            override_profile = Path(override_dir) / "override-profile.bin"
            override_profile.write_bytes(b"\xAA\xBB")
            cfg = LocalAccessConfig(PROFILE_DIR=str(profile_dir))
            session = LocalIsdrSession(cfg=cfg, apdu_channel=FakeApduChannel())

            resolved_path = session.set_profile_override_path(str(override_profile))

        self.assertEqual(resolved_path, str(override_profile.resolve()))
        self.assertEqual(session.state.profile_override_path, str(override_profile.resolve()))

    def test_resolve_profile_path_expands_user_home(self):
        home_dir = Path.home()
        with tempfile.NamedTemporaryFile(dir=home_dir, suffix=".bin", delete=False) as temp_file:
            temp_file.write(b"\xAA")
            temp_path = Path(temp_file.name)
        try:
            tilde_path = str(temp_path).replace(str(home_dir), "~", 1)
            session = LocalIsdrSession(apdu_channel=FakeApduChannel())

            resolved_path = session.resolve_profile_path(override_path=tilde_path)

            self.assertEqual(resolved_path, str(temp_path.resolve()))
        finally:
            temp_path.unlink(missing_ok=True)

    def test_multiple_default_profile_files_require_override(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_dir = Path(temp_dir)
            profile_dir.joinpath("one.bin").write_bytes(b"\x01")
            profile_dir.joinpath("two.bin").write_bytes(b"\x02")
            cfg = LocalAccessConfig(PROFILE_DIR=str(profile_dir))
            session = LocalIsdrSession(cfg=cfg, apdu_channel=FakeApduChannel())

            with self.assertRaises(ValueError):
                session.resolve_profile_path()

    def test_resolve_metadata_path_uses_single_default_json_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            metadata_dir = Path(temp_dir)
            default_metadata = metadata_dir / "default-metadata.json"
            default_metadata.write_text("{}", encoding="utf-8")
            cfg = LocalAccessConfig(METADATA_DIR=str(metadata_dir))
            session = LocalIsdrSession(cfg=cfg, apdu_channel=FakeApduChannel())

            resolved_path = session.resolve_metadata_path()

        self.assertEqual(resolved_path, str(default_metadata.resolve()))

    def test_metadata_override_path_wins_over_default_directory_file(self):
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as override_dir:
            metadata_dir = Path(temp_dir)
            default_metadata = metadata_dir / "default-metadata.json"
            default_metadata.write_text("{}", encoding="utf-8")
            override_metadata = Path(override_dir) / "override-metadata.json"
            override_metadata.write_text("{}", encoding="utf-8")
            cfg = LocalAccessConfig(METADATA_DIR=str(metadata_dir))
            session = LocalIsdrSession(cfg=cfg, apdu_channel=FakeApduChannel())

            resolved_path = session.set_metadata_override_path(str(override_metadata))

        self.assertEqual(resolved_path, str(override_metadata.resolve()))
        self.assertEqual(session.state.metadata_override_path, str(override_metadata.resolve()))

    def test_apply_inventory_profile_ignores_missing_profile_override_file(self):
        with tempfile.TemporaryDirectory() as profile_dir:
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(PROFILE_DIR=str(profile_dir)),
                apdu_channel=FakeApduChannel(),
            )
            session.state.profile_override_path = ""
            session.state.resolved_profile_path = ""

            session._apply_inventory_profile(
                {
                    "profile_override_path": str(Path(profile_dir) / "missing-profile.bin"),
                }
            )

        self.assertEqual(session.state.profile_override_path, "")
        self.assertEqual(session.state.resolved_profile_path, "")

    def test_apply_inventory_profile_ignores_missing_metadata_override_file(self):
        with tempfile.TemporaryDirectory() as metadata_dir:
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(METADATA_DIR=str(metadata_dir)),
                apdu_channel=FakeApduChannel(),
            )
            session.state.metadata_override_path = ""
            session.state.resolved_metadata_path = ""

            session._apply_inventory_profile(
                {
                    "metadata_override_path": str(Path(metadata_dir) / "missing-metadata.json"),
                }
            )

        self.assertEqual(session.state.metadata_override_path, "")
        self.assertEqual(session.state.resolved_metadata_path, "")

    def test_resolve_metadata_path_expands_user_home(self):
        home_dir = Path.home()
        with tempfile.NamedTemporaryFile(dir=home_dir, suffix=".json", delete=False) as temp_file:
            temp_file.write(b"{}")
            temp_path = Path(temp_file.name)
        try:
            tilde_path = str(temp_path).replace(str(home_dir), "~", 1)
            session = LocalIsdrSession(apdu_channel=FakeApduChannel())

            resolved_path = session.resolve_metadata_path(override_path=tilde_path)

            self.assertEqual(resolved_path, str(temp_path.resolve()))
        finally:
            temp_path.unlink(missing_ok=True)

    def test_encode_metadata_asn1_projects_store_metadata_request(self):
        metadata_document = {
            "profile": {
                "name": "Hampus test profile",
                "profile_class": "OPERATIONAL",
                "profile_type": "Hampus Test",
                "iccid": "89460811111111111112",
                "icon": {
                    "type": "NONE",
                    "data_hex": "",
                },
            },
            "operator": {
                "name": "Hampus Test",
                "gid1": "FFFFFFFFFFFFFFFF",
                "gid2": "FFFFFFFFFFFFFFFF",
                "mcc": "999",
                "mnc": "99",
            },
            "notification_events": {
                "install": False,
                "enable": True,
                "disable": True,
                "delete": True,
                "address": "",
            },
            "policy_rules": {
                "update_control_forbidden": False,
                "disable_not_allowed": False,
                "delete_not_allowed": False,
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            metadata_dir = Path(temp_dir)
            metadata_path = metadata_dir / "metadata.json"
            metadata_path.write_text(json.dumps(metadata_document), encoding="utf-8")
            cfg = LocalAccessConfig(METADATA_DIR=str(metadata_dir))
            session = LocalIsdrSession(cfg=cfg, apdu_channel=FakeApduChannel())

            encoded = session.encode_metadata_asn1()

        from SCP11.local_access.metadata_codec import build_store_metadata_request_payload

        payload = build_store_metadata_request_payload(metadata_document)
        self.assertEqual(len(payload["notificationConfigurationInfo"]), 1)
        notif_bits = payload["notificationConfigurationInfo"][0]["profileManagementOperation"]
        self.assertEqual(notif_bits, (b"\x70", 0), "NotificationEvent bits 1,2,3 (enable,disable,delete) per ASN.1")

        decoded = decode_rsp_type("StoreMetadataRequest", encoded)
        self.assertEqual(decoded["iccid"], bytes.fromhex("89460811111111111112"))
        self.assertEqual(decoded["serviceProviderName"], "Hampus Test")
        self.assertEqual(decoded["profileName"], "Hampus test profile")
        self.assertEqual(decoded["iconType"], 0)
        self.assertEqual(decoded["icon"], b"")
        self.assertEqual(decoded["profileClass"], 2)
        self.assertEqual(decoded["profileOwner"]["mccMnc"], bytes.fromhex("99999F"))
        self.assertEqual(decoded["profileOwner"]["gid1"], bytes.fromhex("FFFFFFFFFFFFFFFF"))
        self.assertEqual(decoded["profileOwner"]["gid2"], bytes.fromhex("FFFFFFFFFFFFFFFF"))
        self.assertEqual(decoded["profilePolicyRules"], (b"\x00", 5))
        self.assertEqual(len(decoded["notificationConfigurationInfo"]), 1)
        notification_entry = decoded["notificationConfigurationInfo"][0]
        self.assertEqual(notification_entry["notificationAddress"], "")
        op_bits = notification_entry["profileManagementOperation"]
        self.assertIsInstance(op_bits, tuple)
        self.assertEqual(len(op_bits), 2)
        self.assertIsInstance(op_bits[0], bytes)
        self.assertIsInstance(op_bits[1], int)

    def test_build_session_bound_profile_package_uses_live_transaction_id(self):
        metadata_document = {
            "profile": {
                "name": "Local pySim profile",
                "profile_class": "OPERATIONAL",
                "iccid": "89460811111111111112",
                "icon": {
                    "type": "NONE",
                    "data_hex": "",
                },
            },
            "operator": {
                "name": "YggdraSIM",
                "gid1": "FFFFFFFFFFFFFFFF",
                "gid2": "FFFFFFFFFFFFFFFF",
                "mcc": "999",
                "mnc": "99",
            },
            "notification_events": {
                "install": False,
                "enable": True,
                "disable": True,
                "delete": True,
                "address": "",
            },
            "policy_rules": {
                "update_control_forbidden": False,
                "disable_not_allowed": False,
                "delete_not_allowed": False,
            },
        }

        with tempfile.TemporaryDirectory() as metadata_dir, tempfile.TemporaryDirectory() as profile_dir:
            metadata_path = Path(metadata_dir) / "metadata.json"
            metadata_path.write_text(json.dumps(metadata_document), encoding="utf-8")
            _, pb_key, pb_der, _, _ = write_pb_credentials(Path(metadata_dir))

            session = LocalIsdrSession(
                cfg=LocalAccessConfig(METADATA_DIR=str(metadata_dir), PROFILE_DIR=str(profile_dir)),
                apdu_channel=FakeApduChannel(),
            )
            session._cert_pb = pb_der
            session._key_pb = pb_key
            session.set_metadata_override_path(str(metadata_path))
            session.state.selected_ci_pkid = session.cfg.ROOT_CI_ID.hex().upper()
            session.state.server_challenge = b"\x22" * 16
            session.state.transaction_id = b"\x10" * 16
            session.state.configured_data = wrap_tlv(
                bytes.fromhex("BF3C"),
                wrap_tlv(b"\x80", b"smdpplus2.smdpp.example.test"),
            )

            euicc_otpk_key = ec.generate_private_key(ec.SECP256R1())
            euicc_otpk = euicc_otpk_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            session.state.prepare_download_response = build_prepare_download_response(
                session.state.transaction_id,
                euicc_otpk,
            )

            built_bpp = session._build_session_bound_profile_package(bytes.fromhex("A00100"))

        self.assertTrue(built_bpp.startswith(bytes.fromhex("BF36")))
        self.assertEqual(
            session._extract_transaction_id_from_bpp(built_bpp),
            b"\x10" * 16,
        )
        self.assertEqual(session.apdu_channel.send_calls[0][0], "LOCAL: Select ECASD")
        self.assertEqual(session.apdu_channel.send_calls[1][0], "LOCAL: GetEID")

    def test_build_session_bound_profile_package_honors_custom_a3_chunk_size(self):
        metadata_document = {
            "profile": {
                "name": "Local pySim profile",
                "profile_class": "OPERATIONAL",
                "iccid": "89460811111111111112",
                "icon": {
                    "type": "NONE",
                    "data_hex": "",
                },
            },
            "operator": {
                "name": "YggdraSIM",
                "gid1": "FFFFFFFFFFFFFFFF",
                "gid2": "FFFFFFFFFFFFFFFF",
                "mcc": "999",
                "mnc": "99",
            },
            "notification_events": {
                "install": False,
                "enable": True,
                "disable": True,
                "delete": True,
                "address": "",
            },
            "policy_rules": {
                "update_control_forbidden": False,
                "disable_not_allowed": False,
                "delete_not_allowed": False,
            },
        }

        with tempfile.TemporaryDirectory() as metadata_dir, tempfile.TemporaryDirectory() as profile_dir:
            metadata_path = Path(metadata_dir) / "metadata.json"
            metadata_path.write_text(json.dumps(metadata_document), encoding="utf-8")
            _, pb_key, pb_der, _, _ = write_pb_credentials(Path(metadata_dir))

            session = LocalIsdrSession(
                cfg=LocalAccessConfig(
                    METADATA_DIR=str(metadata_dir),
                    PROFILE_DIR=str(profile_dir),
                    BPP_A3_PLAINTEXT_CHUNK_SIZE=16,
                ),
                apdu_channel=FakeApduChannel(),
            )
            session._cert_pb = pb_der
            session._key_pb = pb_key
            session.set_metadata_override_path(str(metadata_path))
            session.state.selected_ci_pkid = session.cfg.ROOT_CI_ID.hex().upper()
            session.state.server_challenge = b"\x22" * 16
            session.state.transaction_id = b"\x10" * 16
            session.state.configured_data = wrap_tlv(
                bytes.fromhex("BF3C"),
                wrap_tlv(b"\x80", b"smdpplus2.smdpp.example.test"),
            )

            euicc_otpk_key = ec.generate_private_key(ec.SECP256R1())
            euicc_otpk = euicc_otpk_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            session.state.prepare_download_response = build_prepare_download_response(
                session.state.transaction_id,
                euicc_otpk,
            )

            built_bpp = session._build_session_bound_profile_package(bytes.fromhex("AA" * 40))
            layout_lines = session._describe_bpp_layout(built_bpp)

        self.assertTrue(any("A3 total=" in line and "members=3" in line for line in layout_lines))
        self.assertTrue(any("plaintext[0:16]" in line for line in layout_lines))
        self.assertTrue(
            any(
                "replaceSessionKeys=absent" in line
                for line in session.state.last_bpp_crypto_debug_lines
            )
        )
        self.assertTrue(any("chunk_size=16" in line for line in session.state.last_bpp_crypto_debug_lines))
        self.assertTrue(
            any(
                "A3 prelude chunk_size=16 block_nr=1002" in line
                for line in session.state.last_bpp_crypto_debug_lines
            )
        )

    def test_local_access_config_disables_manual_a3_chunking_by_default(self):
        cfg = LocalAccessConfig()

        self.assertEqual(cfg.BPP_A3_PLAINTEXT_CHUNK_SIZE, 0)
        self.assertEqual(cfg.BPP_INITIAL_BLOCK_NR, 1000)
        self.assertTrue(cfg.BPP_USE_PPK_REPLACE_SESSION_KEYS)

    def test_build_session_bound_profile_package_emits_replace_session_keys_in_default_mode(self):
        metadata_document = {
            "profile": {
                "name": "Local pySim profile",
                "profile_class": "OPERATIONAL",
                "iccid": "89460811111111111112",
                "icon": {
                    "type": "NONE",
                    "data_hex": "",
                },
            },
            "operator": {
                "name": "YggdraSIM",
                "gid1": "FFFFFFFFFFFFFFFF",
                "gid2": "FFFFFFFFFFFFFFFF",
                "mcc": "999",
                "mnc": "99",
            },
            "notification_events": {
                "install": False,
                "enable": True,
                "disable": True,
                "delete": True,
                "address": "",
            },
            "policy_rules": {
                "update_control_forbidden": False,
                "disable_not_allowed": False,
                "delete_not_allowed": False,
            },
        }

        with tempfile.TemporaryDirectory() as metadata_dir, tempfile.TemporaryDirectory() as profile_dir:
            metadata_path = Path(metadata_dir) / "metadata.json"
            metadata_path.write_text(json.dumps(metadata_document), encoding="utf-8")
            _, pb_key, pb_der, _, _ = write_pb_credentials(Path(metadata_dir))

            session = LocalIsdrSession(
                cfg=LocalAccessConfig(
                    METADATA_DIR=str(metadata_dir),
                    PROFILE_DIR=str(profile_dir),
                ),
                apdu_channel=FakeApduChannel(),
            )
            session._cert_pb = pb_der
            session._key_pb = pb_key
            session.set_metadata_override_path(str(metadata_path))
            session.state.selected_ci_pkid = session.cfg.ROOT_CI_ID.hex().upper()
            session.state.server_challenge = b"\x22" * 16
            session.state.transaction_id = b"\x10" * 16
            session.state.configured_data = wrap_tlv(
                bytes.fromhex("BF3C"),
                wrap_tlv(b"\x80", b"smdpplus2.smdpp.example.test"),
            )

            euicc_otpk_key = ec.generate_private_key(ec.SECP256R1())
            euicc_otpk = euicc_otpk_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            session.state.prepare_download_response = build_prepare_download_response(
                session.state.transaction_id,
                euicc_otpk,
            )

            built_bpp = session._build_session_bound_profile_package(bytes.fromhex("AA" * 40))
            layout_lines = session._describe_bpp_layout(built_bpp)

        self.assertTrue(any("A2 total=" in line and "members=1" in line for line in layout_lines))
        self.assertTrue(
            any(
                "replaceSessionKeys=present" in line
                for line in session.state.last_bpp_crypto_debug_lines
            )
        )
        self.assertTrue(
            any(
                line.startswith("A2 replaceSessionKeys ")
                for line in session.state.last_bpp_crypto_debug_lines
            )
        )
        prelude_lines = [
            line for line in session.state.last_bpp_crypto_debug_lines
            if "A3 prelude ppk" in line and "block_nr=" in line
        ]
        self.assertGreater(len(prelude_lines), 0)
        self.assertTrue(
            any("block_nr=1003" in line for line in prelude_lines),
            "PPK A3 prelude must use block_nr=1003 (continuation after A0/A1/A2 from seed 1000)",
        )

    def test_run_load_profile_chain_prefers_session_bound_local_bpp_generation(self):
        with tempfile.TemporaryDirectory() as profile_dir:
            profile_path = Path(profile_dir) / "local-profile.hex"
            profile_path.write_text("A00100", encoding="utf-8")
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(
                    PROFILE_DIR=str(profile_dir),
                    GENERATE_SESSION_BOUND_BPP=True,
                    WRAP_SEGMENT_IN_BOOTSTRAP=False,
                ),
                apdu_channel=FakeApduChannel(),
            )
            calls = []
            generated_bpp = wrap_tlv(
                bytes.fromhex("BF36"),
                wrap_tlv(bytes.fromhex("BF23"), wrap_tlv(b"\x80", b"\x55" * 16)) + bytes.fromhex("A00100"),
            )

            def fake_open(transaction_id_override=None):
                calls.append(("open", transaction_id_override))
                session.state.session_open = True
                session.state.transaction_id = b"\x55" * 16
                return None

            def fake_prepare():
                calls.append(("prepare", None))
                session.state.prepare_download_response = b"\x01"
                return b"\x01"

            def fake_build(payload: bytes) -> bytes:
                calls.append(("build", payload))
                return generated_bpp

            def fake_load(payload: bytes, *, progress_bar=None) -> bytes:
                _ = progress_bar
                calls.append(("load", payload))
                return bytes.fromhex("9000")

            def fake_close(reason=LocalIsdrSession.CANCEL_SESSION_REASON_END_USER_REJECTION):
                calls.append(("close", reason))
                session.state.session_open = False
                return b""

            session.open_session = fake_open
            session.prepare_download = fake_prepare
            session._build_session_bound_profile_package = fake_build
            session._load_profile_from_bytes = fake_load
            session.close_session = fake_close

            response = session.run_load_profile_chain()

        self.assertEqual(response, bytes.fromhex("9000"))
        self.assertEqual(calls[0], ("open", None))
        self.assertEqual(calls[1], ("prepare", None))
        self.assertEqual(calls[2], ("build", bytes.fromhex("A00100")))
        self.assertEqual(calls[3], ("load", generated_bpp))
        self.assertEqual(calls[4][0], "close")

    def test_run_load_profile_chain_resets_prepare_download_state_between_attempts(self):
        with tempfile.TemporaryDirectory() as profile_dir:
            profile_path = Path(profile_dir) / "local-profile.hex"
            profile_path.write_text("A00100", encoding="utf-8")
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(
                    PROFILE_DIR=str(profile_dir),
                    GENERATE_SESSION_BOUND_BPP=True,
                    WRAP_SEGMENT_IN_BOOTSTRAP=False,
                ),
                apdu_channel=FakeApduChannel(),
            )
            open_seen_state = []
            prepare_calls = []
            load_calls = []
            next_txid_octet = 1

            def fake_open(transaction_id_override=None):
                nonlocal next_txid_octet
                open_seen_state.append(
                    (
                        bytes(session.state.transaction_id),
                        bytes(session.state.prepare_download_response),
                        transaction_id_override,
                    )
                )
                session.state.session_open = True
                session.state.transaction_id = bytes([next_txid_octet]) * 16
                next_txid_octet += 1
                return None

            def fake_prepare():
                prepare_calls.append(bytes(session.state.transaction_id))
                session.state.prepare_download_response = b"\x01"
                return b"\x01"

            def fake_build(_payload: bytes) -> bytes:
                return wrap_tlv(
                    bytes.fromhex("BF36"),
                    wrap_tlv(bytes.fromhex("BF23"), wrap_tlv(b"\x80", session.state.transaction_id)),
                )

            def fake_load(payload: bytes, *, progress_bar=None) -> bytes:
                _ = progress_bar
                load_calls.append(payload)
                return bytes.fromhex("9000")

            def fake_close(reason=LocalIsdrSession.CANCEL_SESSION_REASON_END_USER_REJECTION):
                _ = reason
                session.state.session_open = False
                return b""

            session.open_session = fake_open
            session.prepare_download = fake_prepare
            session._build_session_bound_profile_package = fake_build
            session._load_profile_from_bytes = fake_load
            session.close_session = fake_close

            first_response = session.run_load_profile_chain()
            second_response = session.run_load_profile_chain()

        self.assertEqual(first_response, bytes.fromhex("9000"))
        self.assertEqual(second_response, bytes.fromhex("9000"))
        self.assertEqual(
            open_seen_state,
            [
                (b"", b"", None),
                (b"", b"", None),
            ],
        )
        self.assertEqual(
            prepare_calls,
            [
                b"\x01" * 16,
                b"\x02" * 16,
            ],
        )
        self.assertEqual(len(load_calls), 2)

    def test_load_profile_from_bytes_raises_on_terminal_failure_result(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        session.state.session_open = True
        session.state.prepare_download_response = b"\x01"
        valid_bpp = wrap_tlv(
            bytes.fromhex("BF36"),
            wrap_tlv(bytes.fromhex("BF23"), wrap_tlv(b"\x80", b"\x10" * 16)),
        )
        session._segment_bound_profile_package = lambda _: [b"\xAA"]
        session._send_personalization_store_data = lambda *_args, **_kwargs: build_profile_installation_failure(
            b"\x10" * 16
        )

        with self.assertRaises(RuntimeError) as error:
            session._load_profile_from_bytes(valid_bpp)

        error_text = str(error.exception)
        self.assertIn("bppCommandId=5", error_text)
        self.assertIn("errorReason=13", error_text)
        self.assertIn("iccid=89460811111111111112", error_text)
        self.assertIn("\n  [ERROR 13]", error_text)
        self.assertIn("\n  command=A3.ProtectedProfilePackageCommand", error_text)
        log_names = [name for name, _apdu in session.apdu_channel.send_calls]
        self.assertIn("LOCAL: ListNotifications", log_names)
        self.assertIn("LOCAL: RetrieveNotification [543]", log_names)
        self.assertIn("LOCAL: RemoveNotificationFromList [543]", log_names)

    def test_retrieve_notification_request_encodes_high_bit_sequence_as_positive_integer(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())

        payload = session._build_retrieve_notification_request_payload(188)

        self.assertEqual(payload, bytes.fromhex("BF2B06A004800200BC"))

    def test_load_profile_from_bytes_advances_progress_per_segment_and_sync(self):
        """
        Regression: the sticky-footer progress bar must keep moving
        through every LoadBoundProfilePackage segment and land on the
        trailing "sync notifications" step. Before the fix the outer
        ``load_profile_from_path`` reserved a single "load bound
        profile package" slot which jumped to 100 % the moment the
        install began and sat there for the entire segment loop.
        """

        class _FakeProgressBar:
            def __init__(self, total: int) -> None:
                self.total = int(total)
                self.completed = 0
                self.advance_calls: list[tuple[str, int]] = []
                self.set_total_calls: list[int] = []

            def set_total(self, new_total: int) -> None:
                self.total = int(new_total)
                self.set_total_calls.append(int(new_total))
                if self.completed > self.total:
                    self.completed = self.total

            def advance(self, label: str = "", count: int = 1) -> None:
                step_count = int(count)
                if step_count < 0:
                    step_count = 0
                self.completed = self.completed + step_count
                if self.completed > self.total:
                    self.completed = self.total
                self.advance_calls.append((str(label or ""), step_count))

        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        session.state.session_open = True
        session.state.prepare_download_response = b"\x01"
        valid_bpp = wrap_tlv(
            bytes.fromhex("BF36"),
            wrap_tlv(bytes.fromhex("BF23"), wrap_tlv(b"\x80", b"\x10" * 16)),
        )
        # Three segments, none of them terminal — the loop must walk
        # through all of them without short-circuiting so we can assert
        # on three per-segment advances.
        segments = [b"\xAA", b"\xBB", b"\xCC"]
        session._segment_bound_profile_package = lambda _: list(segments)
        session._send_personalization_store_data = lambda *_args, **_kwargs: b""
        session._sync_pending_notifications = lambda *_args, **_kwargs: None

        # Pre-install phase already consumed 4 slots (open, prepare,
        # bind, describe) just like load_profile_from_path does.
        bar = _FakeProgressBar(total=4)
        bar.completed = 4

        result = session._load_profile_from_bytes(valid_bpp, progress_bar=bar)

        self.assertEqual(result, b"")
        # Total must be expanded to cover every segment plus the final
        # "sync notifications" step. 4 pre-install + 3 segments + 1
        # sync = 8.
        self.assertEqual(bar.total, 8)
        self.assertIn(8, bar.set_total_calls)
        advance_labels = [label for label, _count in bar.advance_calls]
        self.assertEqual(
            advance_labels,
            [
                "load segment 1/3",
                "load segment 2/3",
                "load segment 3/3",
                "sync notifications",
            ],
        )
        # Counter must land at 100 % only after the final sync advance,
        # not before — otherwise the footer would sit at 100 % while
        # the notify sync is still running.
        self.assertEqual(bar.completed, 8)

    def test_load_profile_from_bytes_coasts_remaining_segments_on_terminal_result(self):
        """
        When the card returns a terminal ProfileInstallationResult
        mid-stream the remaining segments are skipped; the bar must
        still reach 100 % by the time "sync notifications" fires.
        """

        class _FakeProgressBar:
            def __init__(self, total: int) -> None:
                self.total = int(total)
                self.completed = 0
                self.advance_calls: list[tuple[str, int]] = []

            def set_total(self, new_total: int) -> None:
                self.total = int(new_total)
                if self.completed > self.total:
                    self.completed = self.total

            def advance(self, label: str = "", count: int = 1) -> None:
                step_count = int(count)
                if step_count < 0:
                    step_count = 0
                self.completed = self.completed + step_count
                if self.completed > self.total:
                    self.completed = self.total
                self.advance_calls.append((str(label or ""), step_count))

        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        session.state.session_open = True
        session.state.prepare_download_response = b"\x01"
        valid_bpp = wrap_tlv(
            bytes.fromhex("BF36"),
            wrap_tlv(bytes.fromhex("BF23"), wrap_tlv(b"\x80", b"\x10" * 16)),
        )
        segments = [b"\xAA", b"\xBB", b"\xCC", b"\xDD"]
        session._segment_bound_profile_package = lambda _: list(segments)

        call_index = {"value": 0}

        def fake_store_data(*_args, **_kwargs):
            call_index["value"] = call_index["value"] + 1
            # Second segment triggers a terminal failure so the loop
            # short-circuits after draining segment #2.
            if call_index["value"] == 2:
                return build_profile_installation_failure(b"\x10" * 16)
            return b""

        session._send_personalization_store_data = fake_store_data
        session._sync_pending_notifications = lambda *_args, **_kwargs: None

        bar = _FakeProgressBar(total=4)
        bar.completed = 4

        with self.assertRaises(RuntimeError):
            session._load_profile_from_bytes(valid_bpp, progress_bar=bar)

        advance_labels = [label for label, _count in bar.advance_calls]
        # Expect the two real segment advances, a short-circuit coast
        # advance worth 2 (remaining segments), and the final sync.
        self.assertIn("load segment 1/4", advance_labels)
        self.assertIn("load segment 2/4", advance_labels)
        self.assertIn("install short-circuit", advance_labels)
        self.assertIn("sync notifications", advance_labels)
        # The coast advance must carry a count equal to the number of
        # segments we did not send (4 total - 2 attempted = 2).
        coast_counts = [
            count for label, count in bar.advance_calls
            if label == "install short-circuit"
        ]
        self.assertEqual(coast_counts, [2])
        # Bar lands at 100 % by the time the final sync fires.
        self.assertEqual(bar.completed, bar.total)
        self.assertEqual(bar.total, 4 + 4 + 1)

    def test_run_load_profile_chain_syncs_notifications_before_close_when_load_aborts(self):
        with tempfile.TemporaryDirectory() as profile_dir:
            profile_path = Path(profile_dir) / "local-profile.hex"
            profile_path.write_text("A00100", encoding="utf-8")
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(
                    PROFILE_DIR=str(profile_dir),
                    GENERATE_SESSION_BOUND_BPP=True,
                    WRAP_SEGMENT_IN_BOOTSTRAP=False,
                ),
                apdu_channel=FakeApduChannel(),
            )
            calls = []

            def fake_open(transaction_id_override=None):
                calls.append(("open", transaction_id_override))
                session.state.session_open = True
                session.state.transaction_id = b"\x55" * 16
                return None

            def fake_prepare():
                calls.append(("prepare", None))
                session.state.prepare_download_response = b"\x01"
                return b"\x01"

            def fake_build(payload: bytes) -> bytes:
                calls.append(("build", payload))
                return wrap_tlv(
                    bytes.fromhex("BF36"),
                    wrap_tlv(bytes.fromhex("BF23"), wrap_tlv(b"\x80", b"\x55" * 16)),
                )

            def fake_load(_payload: bytes, *, progress_bar=None) -> bytes:
                _ = progress_bar
                session.state.last_load_bpp_response = build_profile_installation_failure(b"\x55" * 16)
                raise RuntimeError("synthetic failure before inner notification sync")

            def fake_sync(response: bytes = b"") -> None:
                calls.append(("sync", response))

            def fake_close(reason=LocalIsdrSession.CANCEL_SESSION_REASON_END_USER_REJECTION):
                calls.append(("close", reason))
                session.state.session_open = False
                return b""

            session.open_session = fake_open
            session.prepare_download = fake_prepare
            session._build_session_bound_profile_package = fake_build
            session._load_profile_from_bytes = fake_load
            session._sync_pending_notifications = fake_sync
            session.close_session = fake_close

            with self.assertRaises(RuntimeError):
                session.run_load_profile_chain()

        self.assertEqual(calls[0], ("open", None))
        self.assertEqual(calls[1], ("prepare", None))
        self.assertEqual(calls[2], ("build", bytes.fromhex("A00100")))
        self.assertEqual(calls[3][0], "sync")
        self.assertEqual(calls[3][1], build_profile_installation_failure(b"\x55" * 16))
        self.assertEqual(calls[4][0], "close")

    def test_run_load_profile_chain_does_not_double_sync_notifications(self):
        with tempfile.TemporaryDirectory() as profile_dir:
            profile_path = Path(profile_dir) / "local-profile.hex"
            profile_path.write_text("A00100", encoding="utf-8")
            session = LocalIsdrSession(
                cfg=LocalAccessConfig(
                    PROFILE_DIR=str(profile_dir),
                    GENERATE_SESSION_BOUND_BPP=True,
                    WRAP_SEGMENT_IN_BOOTSTRAP=False,
                ),
                apdu_channel=FakeApduChannel(),
            )
            calls = []

            def fake_open(transaction_id_override=None):
                session.state.session_open = True
                session.state.transaction_id = b"\x55" * 16
                return None

            def fake_prepare():
                session.state.prepare_download_response = b"\x01"
                return b"\x01"

            def fake_build(_payload: bytes) -> bytes:
                return wrap_tlv(
                    bytes.fromhex("BF36"),
                    wrap_tlv(bytes.fromhex("BF23"), wrap_tlv(b"\x80", b"\x55" * 16)),
                )

            def fake_load(_payload: bytes, *, progress_bar=None) -> bytes:
                _ = progress_bar
                session.state.load_notifications_synced = True
                calls.append("load")
                return bytes.fromhex("9000")

            def fake_sync(response: bytes = b"") -> None:
                calls.append(("sync", response))

            def fake_close(reason=LocalIsdrSession.CANCEL_SESSION_REASON_END_USER_REJECTION):
                calls.append(("close", reason))
                session.state.session_open = False
                return b""

            session.open_session = fake_open
            session.prepare_download = fake_prepare
            session._build_session_bound_profile_package = fake_build
            session._load_profile_from_bytes = fake_load
            session._sync_pending_notifications = fake_sync
            session.close_session = fake_close

            response = session.run_load_profile_chain()

        self.assertEqual(response, bytes.fromhex("9000"))
        self.assertEqual(calls, ["load", ("close", LocalIsdrSession.CANCEL_SESSION_REASON_END_USER_REJECTION)])

    def test_install_failure_summary_includes_bpp_command_stage(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        session.state.bpp_command_descriptions = [
            "BF23.InitialiseSecureChannelRequest",
            "A0.ConfigureISDPRequest",
            "A1.StoreMetadataRequest",
            "A2.ReplaceSessionKeys",
            "A3.ProtectedProfilePackageCommand",
        ]

        summary = session._summarize_profile_installation_result(
            build_profile_installation_failure(b"\x10" * 16)
        )

        self.assertIn("bppCommandId=5", summary)
        self.assertIn("command=A3.ProtectedProfilePackageCommand", summary)
        self.assertIn("errorReason=13", summary)

    def test_install_failure_summary_identifies_likely_a3_chunk_and_block_window(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        session.state.bpp_command_descriptions = [
            "BF23.InitialiseSecureChannelRequest",
            "A0.ConfigureISDPRequest",
            "A1.StoreMetadataRequest",
            "A2.ReplaceSessionKeys",
            "A3.ProtectedProfilePackageCommand",
        ]
        session.state.last_bpp_layout_lines = [
            "BF36 total=13557 value=13552",
            "A3 total=13104 value=13100 members=13 memberLengths=[1036, 1036, 1036, 1036, 1036, 1036, 1036, 1036, 1036, 1036, 1036, 1036, 668]",
            "A3[11] len=1036 plaintext[10080:11088] overlaps TLV[14] A1 genericFileManagement, TLV[15] A6 securityDomain",
            "A3[12] len=1036 plaintext[11088:12096] overlaps TLV[15] A6 securityDomain, TLV[16] A7 rfm, TLV[17] AA end",
            "A3[13] len=668 plaintext[12096:12744] overlaps TLV[17] AA end",
        ]

        summary = session._summarize_profile_installation_result(
            build_profile_installation_failure(b"\x10" * 16)
        )

        self.assertIn("\n", summary)
        self.assertIn("likelyProtectedChunk=A3[12]", summary)
        self.assertIn("blocks=12.0 -> 12.8", summary)
        self.assertIn("plaintext[11088:12096]", summary)
        self.assertIn("terminalChunkContinuation=A3[13]", summary)
        self.assertIn("blocks=13.0 -> 13.5", summary)

    def test_install_failure_summary_keeps_full_overlap_list(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        session.state.bpp_command_descriptions = [
            "BF23.InitialiseSecureChannelRequest",
            "A0.ConfigureISDPRequest",
            "A1.StoreMetadataRequest",
            "A2.ReplaceSessionKeys",
            "A3.ProtectedProfilePackageCommand",
        ]
        session.state.last_bpp_layout_lines = [
            "BF36 total=1600 value=1595",
            "A3 total=1200 value=1196 members=2 memberLengths=[1036, 188]",
            "A3[1] len=1036 plaintext[0:1008] overlaps TLV[1] A0 header, TLV[2] B0 mf, TLV[3] A1 usim, TLV[4] A1 isim, TLV[5] A7 rfm",
            "A3[2] len=188 plaintext[1008:1180] overlaps TLV[5] A7 rfm",
        ]

        summary = session._summarize_profile_installation_result(
            build_profile_installation_failure(b"\x10" * 16)
        )

        self.assertIn("TLV[5] A7 rfm", summary)
        self.assertIn("overlaps:\n    TLV[1] A0 header", summary)
        self.assertNotIn("...,", summary)
        self.assertNotIn(", ...", summary)

    def test_describe_upp_protected_command_sequence_keeps_all_overlap_labels(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        session._describe_upp_element_ranges = lambda _profile_bytes: [
            (0, 10, "TLV[1] A0 header"),
            (0, 10, "TLV[2] B0 mf"),
            (0, 10, "TLV[3] A1 usim"),
            (0, 10, "TLV[4] A1 isim"),
            (0, 10, "TLV[5] A7 rfm"),
        ]

        descriptions = session._describe_upp_protected_command_sequence(b"\xAA" * 10, chunk_size=10)

        self.assertEqual(len(descriptions), 1)
        self.assertIn("TLV[5] A7 rfm", descriptions[0])
        self.assertNotIn(", ...", descriptions[0])

    def test_describe_upp_element_ranges_falls_back_to_individual_pe_decode(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        local_access_session = importlib.import_module("SCP11.local_access.session")

        class _FakeProfileElementSequence:
            @staticmethod
            def from_der(_payload):
                raise RuntimeError("synthetic full-sequence decode failure")

        class _FakeProfileElement:
            @staticmethod
            def from_der(raw_tlv):
                tag = raw_tlv[0]
                if tag == 0xA7:
                    return SimpleNamespace(type="rfm", header_name="rfm-header", templateID="")
                if tag == 0xA9:
                    return SimpleNamespace(type="application", header_name="app-Header", templateID="")
                if tag == 0xAA:
                    return SimpleNamespace(type="end", header_name="end-header", templateID="")
                raise ValueError(f"unexpected tag {tag:02X}")

        fake_pysim_saip = SimpleNamespace(
            ProfileElementSequence=_FakeProfileElementSequence,
            ProfileElement=_FakeProfileElement,
        )
        profile_bytes = (
            wrap_tlv(b"\xA7", b"\x00")
            + wrap_tlv(b"\xA9", b"\x00")
            + wrap_tlv(b"\xAA", b"\x00")
        )

        with mock.patch.object(local_access_session, "pysim_saip", fake_pysim_saip):
            ranges = session._describe_upp_element_ranges(profile_bytes)

        labels = [label for _start, _end, label in ranges]
        self.assertEqual(labels[0], "TLV[1] A7 rfm")
        self.assertEqual(labels[1], "TLV[2] A9 application")
        self.assertEqual(labels[2], "TLV[3] AA end")

    @pytest.mark.slow
    def test_describe_upp_protected_command_sequence_includes_plaintext_range_and_elements(self):
        profile_path = Path(__file__).resolve().parent.parent / "SCP11" / "local_access" / "profile" / "test_profile.txt"
        profile_bytes = bytes.fromhex(profile_path.read_text(encoding="utf-8").strip())
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())

        descriptions = session._describe_upp_protected_command_sequence(profile_bytes)

        self.assertGreaterEqual(len(descriptions), 2)
        self.assertIn("plaintext[0:1008]", descriptions[0])
        self.assertIn("header", descriptions[0])
        self.assertIn("mf", descriptions[0])
        self.assertIn("plaintext[1008:2016]", descriptions[1])
        self.assertIn("telecom", descriptions[1])

    def test_describe_bpp_layout_lists_member_lengths_and_plaintext_ranges(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        session.state.upp_protected_command_descriptions = [
            "plaintext[0:3] overlaps TLV[1] A0 header",
            "plaintext[3:7] overlaps TLV[2] B0 mf",
        ]
        bpp_bytes = wrap_tlv(
            bytes.fromhex("BF36"),
            wrap_tlv(bytes.fromhex("BF23"), wrap_tlv(b"\x80", b"\x10" * 16))
            + wrap_tlv(
                b"\xA3",
                wrap_tlv(b"\x86", b"\xAA")
                + wrap_tlv(b"\x86", b"\xBB\xCC"),
            ),
        )

        lines = session._describe_bpp_layout(bpp_bytes)

        self.assertIn("BF36 total=", lines[0])
        self.assertIn("transactionId=10101010101010101010101010101010", lines[1])
        self.assertIn("A3 total=", lines[2])
        self.assertIn("memberLengths=[3, 4]", lines[2])
        self.assertIn("A3[1] len=3 plaintext[0:3]", lines[3])
        self.assertIn("A3[2] len=4 plaintext[3:7]", lines[4])

    def test_segment_bound_profile_package_frames_a1_a3_headers_per_sgp22_annex_m(self):
        # SGP.22 Annex M expects the A0 ConfigureISDPRequest to be
        # delivered as a single wrapped segment, while A1/A2/A3
        # containers ship their headers as their own StoreData chains
        # followed by each inner 86/88 TLV. Stripping the A1/A3 headers
        # has been observed to make real eUICCs emit a spurious terminal
        # ProfileInstallationResult on the first bare 86 and leave the
        # SM-DP+ session pending.
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        bpp_bytes = wrap_tlv(
            bytes.fromhex("BF36"),
            wrap_tlv(bytes.fromhex("BF23"), wrap_tlv(b"\x80", b"\x10" * 16))
            + wrap_tlv(b"\xA0", wrap_tlv(b"\x87", b"\xAA"))
            + wrap_tlv(b"\xA1", wrap_tlv(b"\x88", b"\xBB"))
            + wrap_tlv(b"\xA3", wrap_tlv(b"\x86", b"\xCC") + wrap_tlv(b"\x86", b"\xDD")),
        )

        segments = session._segment_bound_profile_package(bpp_bytes)
        descriptions = session._describe_bpp_command_sequence(bpp_bytes)

        self.assertEqual(len(segments), 7)
        self.assertTrue(segments[0].startswith(bytes.fromhex("BF36")))
        self.assertEqual(segments[1], wrap_tlv(b"\xA0", wrap_tlv(b"\x87", b"\xAA")))
        self.assertEqual(segments[2], bytes.fromhex("A103"))
        self.assertEqual(segments[3], wrap_tlv(b"\x88", b"\xBB"))
        self.assertEqual(segments[4], bytes.fromhex("A306"))
        self.assertEqual(segments[5], wrap_tlv(b"\x86", b"\xCC"))
        self.assertEqual(segments[6], wrap_tlv(b"\x86", b"\xDD"))
        self.assertEqual(
            descriptions,
            [
                "BF23.InitialiseSecureChannelRequest",
                "A0.ConfigureISDPRequest[1]",
                "A1.StoreMetadataRequest[1]",
                "A3.ProtectedProfilePackageCommand[1]",
                "A3.ProtectedProfilePackageCommand[2]",
            ],
        )


if __name__ == "__main__":
    unittest.main()
