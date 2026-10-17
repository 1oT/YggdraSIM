# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import datetime
import tempfile
import types
import unittest
from pathlib import Path

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.test.es9_client import Es9LikeClient
from SCP11.test.models import EimPollRequest
from SCP11.test.orchestrator import SGP22Orchestrator


def encode_der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def wrap_tlv(tag_hex: str, value: bytes) -> bytes:
    tag_bytes = bytes.fromhex(tag_hex)
    return tag_bytes + encode_der_length(len(value)) + value


def build_self_signed_cert_der() -> bytes:
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Test eIM"),
        ]
    )
    certificate = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class DummyCfg:
    pass


class RecordingEimClient(Es9LikeClient):
    def __init__(self, ca_bundle_path: str):
        super().__init__(
            base_url="https://rsp.example.com",
            eim_base_url="https://eim1.esim.example.test",
            ca_bundle_path=ca_bundle_path,
        )
        self.use_configured_ca_bundle_flags = []

    def _build_ssl_context_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str = "",
        use_configured_ca_bundle: bool = True,
        log_label: str = "ES9",
    ):
        self.use_configured_ca_bundle_flags.append(use_configured_ca_bundle)
        return None

    def _open_http_response(
        self,
        request,
        ssl_context,
        endpoint: str,
        label: str,
        timeout_seconds=None,
        pinned_tls_spki=None,
    ):
        class _Response:
            status = 200

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, exc_type, exc, tb):
                return False

        return _Response()

    def _read_http_response_bytes(self, response, endpoint: str, label: str) -> bytes:
        return b'{"euiccPackageList":[],"pollingComplete":true,"eimResultCode":1}'


class AcknowledgedPackageProvider:
    def __init__(self):
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        if len(self.poll_eim_calls) == 1:
            return types.SimpleNamespace(
                transaction_id="TX-ACK",
                euicc_package_list=["BF5103800101"],
                package_format="",
                polling_complete=False,
                retry_after_seconds=0,
                eim_result_code=None,
            )
        return types.SimpleNamespace(
            transaction_id="TX-ACK",
            euicc_package_list=[],
            package_format="",
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=1,
        )

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(request_obj)
        return {
            "packageFormat": "eimAcknowledgements",
            "pollingComplete": True,
        }


class EmptyResponsePackageProvider:
    def __init__(self):
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        if len(self.poll_eim_calls) == 1:
            return types.SimpleNamespace(
                transaction_id="TX-EMPTY",
                euicc_package_list=["BF5203800101"],
                package_format="",
                polling_complete=False,
                retry_after_seconds=0,
                eim_result_code=None,
            )
        return types.SimpleNamespace(
            transaction_id="TX-EMPTY",
            euicc_package_list=[],
            package_format="",
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=1,
        )

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(request_obj)
        return {
            "packageFormat": "emptyResponse",
            "pollingComplete": True,
        }


class DrainRoundSkipProvider:
    def __init__(self):
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []
        self._per_fqdn_call_counts = {}

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        fqdn = str(getattr(request_obj, "eim_fqdn", "") or "").strip()
        call_count = self._per_fqdn_call_counts.get(fqdn, 0) + 1
        self._per_fqdn_call_counts[fqdn] = call_count
        if fqdn == "eim1.example.com":
            return types.SimpleNamespace(
                transaction_id="TX-DRAIN-1",
                euicc_package_list=[],
                package_format="",
                polling_complete=True,
                retry_after_seconds=0,
                eim_result_code=1,
            )
        if fqdn == "eim2.example.com" and call_count == 1:
            return types.SimpleNamespace(
                transaction_id="TX-DRAIN-2A",
                euicc_package_list=["BF5103800101"],
                package_format="",
                polling_complete=False,
                retry_after_seconds=0,
                eim_result_code=None,
            )
        return types.SimpleNamespace(
            transaction_id="TX-DRAIN-2B",
            euicc_package_list=[],
            package_format="",
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=1,
        )

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(request_obj)
        return {
            "pollingComplete": True,
            "retryAfterSeconds": 0,
        }


class TestSplitPinningTests(unittest.TestCase):
    def test_test_eim_poll_request_uses_fqdn_eim_id_when_fqdn_field_absent(self):
        eim_configuration = wrap_tlv(
            "BF55",
            wrap_tlv(
                "A0",
                wrap_tlv(
                    "30",
                    b"".join(
                        [
                            wrap_tlv("80", b"eim1.example.test"),
                            wrap_tlv("82", b"\x02"),
                        ]
                    ),
                ),
            ),
        )
        configured_data = wrap_tlv("BF3C", wrap_tlv("80", b"rsp.example.test"))
        orchestrator = SGP22Orchestrator(cfg=DummyCfg(), apdu_channel=None, profile_provider=None)
        orchestrator.cache_eim_poll_metadata(
            eid="89049032000000000000000000000101",
            euicc_configured_data=configured_data,
            eim_configuration_data=eim_configuration,
            euicc_info1=wrap_tlv("BF20", b"\x82\x03\x02\x05\x00"),
            euicc_info2=wrap_tlv("BF22", b"\x81\x03\x02\x03\x01"),
        )

        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)

        self.assertEqual(request.eim_fqdn, "eim1.example.test")
        self.assertEqual(request.eim_id, "eim1.example.test")
        self.assertEqual(request.eim_id_type, "eimIdTypeFqdn (2)")

    def _run_test_orchestrator_single_entry(self, provider):
        orchestrator = SGP22Orchestrator(cfg=DummyCfg(), apdu_channel=None, profile_provider=provider)
        request = EimPollRequest(
            eim_fqdn="eim1.esim.example.test",
            eim_id="manager-1",
            eim_id_type="1",
            counter_value="0",
            association_token="",
            supported_protocol="3",
            euicc_ci_pkid="",
            indirect_profile_download="0",
            euicc_configured_data="",
            eim_configuration_data="",
            euicc_info1="",
            euicc_info2="",
            eid="89049032000000000000000000000101",
            euicc_challenge="",
            trusted_tls_public_key_data="",
            transaction_id="",
            euicc_package_result="",
            raw_body=bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
        )
        relayed_packages = []

        orchestrator._phase_connect = lambda: None
        orchestrator._resolve_eim_poll_entry_indices = lambda entry_index=None: [0]
        orchestrator._build_eim_poll_request = lambda matching_id="", entry_index=0, expected_eim_id="": request

        def fake_relay(package_bytes, poll_round, package_index):
            relayed_packages.append((package_bytes, poll_round, package_index))
            return bytes.fromhex("BF5280")

        orchestrator._relay_eim_package_to_card = fake_relay
        orchestrator.run_eim_poll(matching_id="MATCH-1")
        return relayed_packages, provider

    def _run_test_orchestrator_entry_sequence(self, provider, entry_requests):
        cfg = DummyCfg()
        cfg.EIM_MAX_DRAIN_ROUNDS = 3
        orchestrator = SGP22Orchestrator(cfg=cfg, apdu_channel=None, profile_provider=provider)
        relayed_packages = []

        orchestrator._phase_connect = lambda: None
        orchestrator._resolve_eim_poll_entry_indices = (
            lambda entry_index=None: list(range(len(entry_requests)))
        )
        orchestrator._build_eim_poll_request = (
            lambda matching_id="", entry_index=0, expected_eim_id="": entry_requests[entry_index]
        )

        def fake_relay(package_bytes, poll_round, package_index):
            relayed_packages.append((package_bytes, poll_round, package_index))
            return bytes.fromhex("BF5280")

        orchestrator._relay_eim_package_to_card = fake_relay
        orchestrator.run_eim_poll(matching_id="MATCH-1")
        return relayed_packages, provider

    def test_test_orchestrator_initializes_eim_poll_debug_flag(self):
        orchestrator = SGP22Orchestrator(cfg=DummyCfg(), apdu_channel=None, profile_provider=None)

        self.assertIs(orchestrator._eim_poll_debug_enabled, False)

    def test_certificate_form_a6_does_not_become_direct_tls_pin(self):
        orchestrator = SGP22Orchestrator(cfg=DummyCfg(), apdu_channel=None, profile_provider=None)
        certificate_der = build_self_signed_cert_der()

        extracted = orchestrator._extract_direct_tls_subject_public_key_info(
            wrap_tlv("A1", certificate_der)
        )

        self.assertEqual(extracted, b"")

    def test_direct_spki_form_a6_still_extracts_pin(self):
        orchestrator = SGP22Orchestrator(cfg=DummyCfg(), apdu_channel=None, profile_provider=None)
        tls_key_material = bytes.fromhex(
            "301306072A8648CE3D020106082A8648CE3D03010703420004" + "22" * 64
        )

        extracted = orchestrator._extract_direct_tls_subject_public_key_info(
            wrap_tlv("A0", tls_key_material)
        )

        self.assertEqual(extracted, wrap_tlv("30", tls_key_material))

    def test_test_eim_binary_uses_configured_ca_bundle_when_not_pinning(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_path = Path(temp_dir) / "test-ca.pem"
            bundle_path.write_text("dummy\n", encoding="utf-8")
            client = RecordingEimClient(str(bundle_path))

            client._post_eim_binary(
                "https://eim1.esim.example.test",
                bytes.fromhex("BF4F125A1089049032118427504800000000006079"),
                b"",
            )

        self.assertEqual(client.use_configured_ca_bundle_flags, [True])

    def test_test_run_eim_poll_repolls_after_acknowledged_package_result(self):
        relayed_packages, provider = self._run_test_orchestrator_single_entry(
            AcknowledgedPackageProvider()
        )

        self.assertEqual(len(provider.poll_eim_calls), 2)
        self.assertEqual(len(provider.provide_eim_package_result_calls), 1)
        self.assertEqual(provider.provide_eim_package_result_calls[0].transaction_id, "TX-ACK")
        self.assertEqual(provider.poll_eim_calls[1].transaction_id, "TX-ACK")
        self.assertEqual(
            relayed_packages,
            [
                (bytes.fromhex("BF5103800101"), 1, 1),
            ],
        )

    def test_test_run_eim_poll_repolls_after_empty_package_result_response(self):
        relayed_packages, provider = self._run_test_orchestrator_single_entry(
            EmptyResponsePackageProvider()
        )

        self.assertEqual(len(provider.poll_eim_calls), 2)
        self.assertEqual(len(provider.provide_eim_package_result_calls), 1)
        self.assertEqual(provider.provide_eim_package_result_calls[0].transaction_id, "TX-EMPTY")
        self.assertEqual(provider.poll_eim_calls[1].transaction_id, "TX-EMPTY")
        self.assertEqual(
            relayed_packages,
            [
                (bytes.fromhex("BF5203800101"), 1, 1),
            ],
        )

    def test_test_run_eim_poll_skips_no_package_entries_in_later_drain_rounds(self):
        relayed_packages, provider = self._run_test_orchestrator_entry_sequence(
            DrainRoundSkipProvider(),
            [
                EimPollRequest(
                    eim_fqdn="eim1.example.com",
                    eim_id="manager-1",
                    eim_id_type="1",
                    counter_value="0",
                    association_token="",
                    supported_protocol="3",
                    euicc_ci_pkid="",
                    indirect_profile_download="0",
                    euicc_configured_data="",
                    eim_configuration_data="",
                    euicc_info1="",
                    euicc_info2="",
                    eid="89049032000000000000000000000101",
                    euicc_challenge="",
                    trusted_tls_public_key_data="",
                    transaction_id="",
                    euicc_package_result="",
                    raw_body=bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
                ),
                EimPollRequest(
                    eim_fqdn="eim2.example.com",
                    eim_id="manager-2",
                    eim_id_type="1",
                    counter_value="0",
                    association_token="",
                    supported_protocol="3",
                    euicc_ci_pkid="",
                    indirect_profile_download="0",
                    euicc_configured_data="",
                    eim_configuration_data="",
                    euicc_info1="",
                    euicc_info2="",
                    eid="89049032000000000000000000000101",
                    euicc_challenge="",
                    trusted_tls_public_key_data="",
                    transaction_id="",
                    euicc_package_result="",
                    raw_body=bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
                ),
            ],
        )

        self.assertEqual(
            [call.eim_fqdn for call in provider.poll_eim_calls],
            [
                "eim1.example.com",
                "eim2.example.com",
                "eim2.example.com",
            ],
        )
        self.assertEqual(len(provider.provide_eim_package_result_calls), 1)
        self.assertEqual(
            relayed_packages,
            [
                (bytes.fromhex("BF5103800101"), 1, 1),
            ],
        )


if __name__ == "__main__":
    unittest.main()
