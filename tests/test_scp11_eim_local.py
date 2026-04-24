import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import yaml

from SCP03.logic.euicc_info2 import parse_tlv_nodes
from SCP03.logic.sgp32_decode import decode_eim_configuration_entry
from SCP11.eim_local.eim_package_codec import (
    lint_eim_package_document,
    resolve_package_runtime_hints,
)
from SCP11.eim_local.config import EimLocalConfig
from SCP11.eim_local.models import EimHandoverContext, ensure_handover_transaction
from plugins.polling.wifi_ethernet_bridge import LocalizedPollingBridge
from SCP11.eim_local.session import EimLocalSession
from SCP11.eim_local.main import EimLocalShell
from SCP11.eim_packages import TYPE_PROFILE_DOWNLOAD_TRIGGER, parse_eim_package
from yggdrasim_common.session_recording import emit_apdu_trace_event


DEFAULT_TEST_EIM_OID = "2.25.311782205282738360923618091971140414400"
DEFAULT_TEST_EIM_FQDN = "yggdrasim.eim.test.1ot.com"


def create_poll_fixture_dirs(base_dir: Path) -> tuple[Path, Path]:
    fixtures_dir = base_dir / "fixtures"
    eim_to_esim_dir = fixtures_dir / "eim_to_esim"
    esim_to_eim_dir = fixtures_dir / "esim_to_eim"
    eim_to_esim_dir.mkdir(parents=True, exist_ok=True)
    esim_to_eim_dir.mkdir(parents=True, exist_ok=True)
    return eim_to_esim_dir, esim_to_eim_dir


def build_add_eim_package_document(package_type: str, counter_value: int = 1) -> dict[str, object]:
    request_key = "add_initial_eim_request"
    if package_type.strip().lower() in ("add_eim", "addeim"):
        request_key = "add_eim_request"
    return {
        "package_type": package_type,
        "package_version": "2.0.0",
        "sgp32": {
            request_key: {
                "include": True,
                "eim_configuration_data_list": [
                    {
                        "include": True,
                        "eim_id": {"include": True, "value": DEFAULT_TEST_EIM_OID},
                        "eim_fqdn": {"include": True, "value": DEFAULT_TEST_EIM_FQDN},
                        "eim_id_type": {"include": True, "value": "eimIdTypeOid"},
                        "counter_value": {"include": True, "value": counter_value},
                        "association_token": {"include": True, "value": -1},
                        "eim_public_key_data": {
                            "include": True,
                            "choice": "eim_certificate",
                            "eim_certificate_der_hex": "DEADBEEF",
                        },
                        "trusted_public_key_data_tls": {
                            "include": True,
                            "choice": "trusted_eim_pk_tls",
                            "trusted_eim_pk_tls_spki_hex": "11223344",
                        },
                        "eim_supported_protocol": {
                            "include": True,
                            "eimRetrieveHttps": True,
                            "eimRetrieveCoaps": False,
                            "eimInjectHttps": False,
                            "eimInjectCoaps": False,
                            "eimProprietary": False,
                        },
                        "euicc_ci_pk_id": {
                            "include": True,
                            "value_hex": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
                        },
                        "indirect_profile_download": {"include": True},
                    }
                ],
            }
        },
    }


def build_euicc_memory_reset_package_document(
    *,
    reset_eim_config_data: bool = True,
) -> dict[str, object]:
    return {
        "package_type": "euicc_memory_reset",
        "package_version": "2.0.0",
        "sgp22": {
            "euicc_memory_reset_request": {
                "include": True,
                "options": {
                    "delete_operational_profiles": False,
                    "delete_field_loaded_test_profiles": False,
                    "reset_default_smdp_address": False,
                    "delete_preloaded_test_profiles": False,
                    "delete_provisioning_profiles": False,
                    "reset_eim_config_data": reset_eim_config_data,
                    "reset_immediate_enable_config": False,
                },
            }
        },
    }


def extract_first_eim_configuration_row(command_payload: bytes) -> tuple[int, bytes]:
    root_nodes = parse_tlv_nodes(command_payload)
    if len(root_nodes) != 1:
        raise AssertionError("Expected exactly one root node in add-eim payload.")
    root_tag, root_value, _ = root_nodes[0]
    list_nodes = parse_tlv_nodes(root_value)
    if len(list_nodes) != 1 or list_nodes[0][0] != 0xA0:
        raise AssertionError("Expected A0 list wrapper inside add-eim payload.")
    row_nodes = parse_tlv_nodes(list_nodes[0][1])
    if len(row_nodes) == 0 or row_nodes[0][0] != 0x30:
        raise AssertionError("Expected SEQUENCE row inside add-eim payload.")
    return root_tag, row_nodes[0][1]


def encode_der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def wrap_tlv(tag_bytes: bytes, value: bytes) -> bytes:
    return bytes(tag_bytes) + encode_der_length(len(value)) + value


def encode_iccid_for_tlv(iccid_digits: str) -> bytes:
    padded = str(iccid_digits).strip()
    if len(padded) % 2 != 0:
        padded += "F"
    return bytes.fromhex(padded)


def write_minimal_profile_payload(profile_path: Path, iccid_digits: str, profile_name: str = "Test") -> None:
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    payload = wrap_tlv(
        b"\xA0",
        wrap_tlv(b"\x82", profile_name.encode("utf-8"))
        + wrap_tlv(b"\x83", encode_iccid_for_tlv(iccid_digits)),
    )
    profile_path.write_text(payload.hex().upper(), encoding="ascii")


def build_eim_configuration_response_for_shell() -> bytes:
    row = wrap_tlv(
        b"\x30",
        wrap_tlv(b"\x80", DEFAULT_TEST_EIM_OID.encode("utf-8"))
        + wrap_tlv(b"\x81", DEFAULT_TEST_EIM_FQDN.encode("utf-8"))
        + wrap_tlv(b"\x82", b"\x01")
        + wrap_tlv(b"\x83", b"\x01"),
    )
    return wrap_tlv(bytes.fromhex("BF55"), wrap_tlv(b"\xA0", row))


def write_test_signing_certificate(
    cert_dir: Path,
    stem: str,
    root_ci_pkid_hex: str,
    subject_cn: str,
) -> tuple[Path, bytes]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=bytes.fromhex(root_ci_pkid_hex),
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    cert_path = cert_dir / f"CERT_S_EIMsign_{stem}.der"
    key_path = cert_dir / f"SK_S_EIMsign_{stem}.pem"
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    cert_path.write_bytes(cert_der)
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, cert_der


def write_local_smdp_drop_in(
    cert_dir: Path,
    stem: str,
    server_address: str,
    root_ci_pkid_hex: str = "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
) -> tuple[Path, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Local {stem}")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    cert_path = cert_dir / f"{stem}.der"
    key_path = cert_dir / f"{stem}.key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.with_suffix(".meta.json").write_text(
        json.dumps(
            {
                "role": "auth",
                "private_key_path": key_path.name,
                "root_ci_pkid": root_ci_pkid_hex,
                "server_address": server_address,
            }
        ),
        encoding="utf-8",
    )
    return cert_path, key_path


def write_test_pem_certificate(cert_dir: Path, stem: str = "local_eim_cert") -> Path:
    cert_dir.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, stem)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    cert_path = cert_dir / f"{stem}.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return cert_path


class FakeEimLocalApduChannel:
    def __init__(self) -> None:
        self.send_calls: list[tuple[str, bytes]] = []

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, bytes(apdu)))
        if log_name == "LOCAL: Select ISD-R":
            return bytes.fromhex("6F00")
        if log_name == "LOCAL: Select ECASD":
            return bytes.fromhex("6F00")
        if log_name == "LOCAL: GetEID":
            return bytes.fromhex("5A10890490320000000000000000000000000001")
        if log_name in ("EIM-LOCAL: AddInitialEim", "EIM-LOCAL: AddInitialEim [LOCAL-AUTH]"):
            return bytes.fromhex("BF5700")
        if log_name in ("EIM-LOCAL: AddEim", "EIM-LOCAL: AddEim [LOCAL-AUTH]"):
            return bytes.fromhex("BF5800")
        if log_name == "EIM-LOCAL: eUICCMemoryReset":
            return bytes.fromhex("BF6400")
        if log_name == "EIM-LOCAL: RetrieveNotificationsList":
            return bytes.fromhex("BF2B00")
        raise AssertionError(f"Unexpected APDU log name: {log_name}")


class EimPackageCodecTests(unittest.TestCase):
    def test_lint_accepts_minimal_valid_document(self) -> None:
        document = {
            "package_type": "ipae_handover",
            "package_version": "1.0.0",
            "matching_id": "A",
            "transaction_id_hex": "01020304",
            "profile_path": "SCP11/eim_local/profile/test_profile.txt",
            "additional_tlvs": [{"tag_hex": "83", "value_hex": "0102"}],
            "optional_tags": {
                "vendorTagBF76": {"include": True, "tag_hex": "BF76", "value_hex": "0102"}
            },
        }
        report = lint_eim_package_document(document)
        self.assertTrue(report["ok"])
        self.assertEqual(report["additional_tlv_count"], 1)
        self.assertEqual(report["optional_tlv_count"], 1)

    def test_lint_rejects_odd_length_transaction_id(self) -> None:
        document = {
            "package_type": "ipae_handover",
            "transaction_id_hex": "123",
            "additional_tlvs": [],
        }
        report = lint_eim_package_document(document)
        self.assertFalse(report["ok"])
        joined = "\n".join(report["errors"])
        self.assertIn("Invalid hex string", joined)

    def test_lint_accepts_sgp32_add_initial_eim_shape(self) -> None:
        document = {
            "package_type": "add_initial_eim",
            "package_version": "2.0.0",
            "sgp32": {
                "add_initial_eim_request": {
                    "include": True,
                    "eim_configuration_data_list": [
                        {
                            "include": True,
                            "eim_id": {"include": True, "value": "EIM-1"},
                            "counter_value": {"include": True, "value": 1},
                            "eim_public_key_data": {
                                "include": True,
                                "choice": "eim_certificate",
                                "eim_certificate_der_path": "SCP11/eim_local/certs/eim/CERT.EIM.pem",
                            },
                        }
                    ],
                }
            },
        }
        report = lint_eim_package_document(document)
        self.assertTrue(report["ok"])

    def test_runtime_hints_extract_txid_from_profile_download_trigger_result(self) -> None:
        document = {
            "package_type": "provide_eim_package_result",
            "sgp32": {
                "provide_eim_package_result": {
                    "profile_download_trigger_result": {
                        "transaction_id_hex": "0102030405060708",
                    }
                }
            },
        }
        hints = resolve_package_runtime_hints(document)
        self.assertEqual(hints.get("transaction_id_hex"), "0102030405060708".upper())

    def test_lint_accepts_selective_euicc_memory_reset_shape(self) -> None:
        report = lint_eim_package_document(build_euicc_memory_reset_package_document())
        self.assertTrue(report["ok"])
        self.assertEqual(report["package_type"], "euicc_memory_reset")


class EimLocalModelTests(unittest.TestCase):
    def test_ensure_handover_transaction_requires_txid(self) -> None:
        handover = EimHandoverContext()
        with self.assertRaisesRegex(RuntimeError, "No handover transaction is present"):
            ensure_handover_transaction(handover)

    def test_handover_context_json_roundtrip(self) -> None:
        handover = EimHandoverContext(
            transaction_id=bytes.fromhex("A1B2C3D4"),
            matching_id="M1",
            source="manual",
        )
        payload = handover.as_json_dict()
        self.assertEqual(payload["transaction_id_hex"], "A1B2C3D4")
        self.assertEqual(payload["matching_id"], "M1")

    def test_eim_package_lint_from_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = Path(temp_dir) / "pkg.json"
            package_path.write_text(
                json.dumps(
                    {
                        "package_type": "ipad_discover",
                        "package_version": "1.0.0",
                        "matching_id": "DISCOVER",
                        "additional_tlvs": [],
                    }
                ),
                encoding="utf-8",
            )
            document = json.loads(package_path.read_text(encoding="utf-8"))
            report = lint_eim_package_document(document)
            self.assertTrue(report["ok"])
            self.assertEqual(report["package_type"], "ipad_discover")

    def test_runtime_hint_resolution_prefers_sgp32_content(self) -> None:
        document = {
            "package_type": "add_initial_eim",
            "runtime": {
                "matching_id": "RUNTIME-MID",
                "cert_der_path": "runtime.der",
            },
            "sgp32": {
                "add_initial_eim_request": {
                    "eim_configuration_data_list": [
                        {
                            "eim_id": {"include": True, "value": "EIM-SGP32"},
                            "eim_public_key_data": {
                                "choice": "eim_certificate",
                                "eim_certificate_der_path": "sgp32.der",
                            },
                        }
                    ]
                }
            },
        }
        hints = resolve_package_runtime_hints(document)
        self.assertEqual(hints["matching_id"], "RUNTIME-MID")
        self.assertEqual(hints["cert_der_path"], "runtime.der")

    def test_repo_relative_path_is_not_double_joined(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            resolved = session._normalize_user_path(
                "SCP11/eim_local/certs/eim/CERT.EIM.pem",
                base_dir=config.EIM_CERTS_DIR,
            )
            self.assertIn("/SCP11/eim_local/certs/eim/CERT.EIM.pem", resolved)
            self.assertNotIn("/certs/eim/SCP11/eim_local", resolved)

    def test_hotfolder_empty_maps_to_no_eim_package_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            hotfolder_dir = Path(temp_dir) / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_INCLUDE_FIXED_FIXTURES=False,
            )
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            meta = session.hotfolder_poll_response_meta()
            self.assertEqual(meta["package_count"], 0)
            self.assertEqual(meta["eim_result_code"], 1)
            self.assertEqual(meta["eim_result_name"], "noEimPackageAvailable")
            self.assertEqual(meta["response_tlv_hex"], "BF4F03020101")

    def test_acknowledge_writes_response_log_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            response_log_file = str(Path(temp_dir) / "eim_response_log.jsonl")
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_RESPONSE_LOG_FILE=response_log_file,
            )
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            closed = session.acknowledge_eim_operations(transaction_id_hex="A1B2", matching_id="MID-1")
            self.assertEqual(closed, 0)
            log_lines = Path(response_log_file).read_text(encoding="utf-8").strip().splitlines()
            self.assertGreaterEqual(len(log_lines), 1)
            payload = json.loads(log_lines[-1])
            self.assertEqual(payload.get("action"), "eim_acknowledge")
            self.assertEqual(payload.get("transaction_id_hex"), "A1B2")
            self.assertEqual(payload.get("matching_id"), "MID-1")
            self.assertTrue(payload.get("success"))
            parsed_rows = session.read_response_log(limit=5)
            self.assertGreaterEqual(len(parsed_rows), 1)
            self.assertEqual(parsed_rows[-1].get("action"), "eim_acknowledge")

    def test_error_code_set_updates_profile_download_error_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            package_path = Path(temp_dir) / "pkg.json"
            package_path.write_text(
                json.dumps(
                    {
                        "package_type": "provide_eim_package_result",
                        "sgp32": {
                            "provide_eim_package_result": {
                                "result_choice": "profile_download_trigger_result",
                                "profile_download_trigger_result": {
                                    "profile_download_error": {
                                        "include": False,
                                        "value": "undefinedError(127)",
                                    }
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
            )
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            payload = session.set_error_code_in_package(
                family="sgp32_profile_download_error_reason",
                code_value="ecallActive",
                package_path=str(package_path),
            )
            self.assertEqual(payload["resolved_code"], 104)
            document = json.loads(package_path.read_text(encoding="utf-8"))
            pd_error = (
                document["sgp32"]["provide_eim_package_result"]["profile_download_trigger_result"]["profile_download_error"]
            )
            self.assertTrue(pd_error["include"])
            self.assertEqual(pd_error["value"], "ecallActive(104)")

    def test_error_code_set_updates_eim_package_result_error_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            package_path = Path(temp_dir) / "pkg.json"
            package_path.write_text(
                json.dumps(
                    {
                        "package_type": "provide_eim_package_result",
                        "sgp32": {
                            "provide_eim_package_result": {
                                "result_choice": "profile_download_trigger_result",
                                "eim_package_result_response_error": {
                                    "include": False,
                                    "error_code": "undefinedError(127)",
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            payload = session.set_error_code_in_package(
                family="sgp32_eim_package_result_error",
                code_value="invalidPackageFormat",
                package_path=str(package_path),
            )
            self.assertEqual(payload["resolved_code"], 1)
            document = json.loads(package_path.read_text(encoding="utf-8"))
            provide = document["sgp32"]["provide_eim_package_result"]
            self.assertEqual(provide["result_choice"], "eim_package_result_response_error")
            self.assertTrue(provide["eim_package_result_response_error"]["include"])
            self.assertEqual(
                provide["eim_package_result_response_error"]["error_code"],
                "invalidPackageFormat(1)",
            )

    def test_counter_shortcut_set_uses_active_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            identity_file = Path(temp_dir) / "identity.json"
            identity_file.write_text(
                json.dumps(
                    {
                        "eim_id": "EIM-ACTIVE-IDENTITY",
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_IDENTITY_FILE=str(identity_file),
            )
            shell = EimLocalShell()
            shell.cfg = config
            shell.session = EimLocalSession(cfg=config, apdu_channel=None)
            shell._cmd_counter("set 77")
            eim_id, next_value = shell.session.get_counter_value("EIM-ACTIVE-IDENTITY")
            self.assertEqual(eim_id, "EIM-ACTIVE-IDENTITY")
            self.assertEqual(next_value, 77)

    def test_response_log_filter_and_clear(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            response_log_file = str(Path(temp_dir) / "eim_response_log.jsonl")
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_RESPONSE_LOG_FILE=response_log_file,
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            session.acknowledge_eim_operations(transaction_id_hex="AA01", matching_id="MID-A")
            session.acknowledge_eim_operations(transaction_id_hex="BB02", matching_id="MID-B")
            rows = session.filter_response_log(query="MID-B", limit=10)
            self.assertEqual(len(rows), 1)
            self.assertEqual(str(rows[0].get("matching_id")), "MID-B")
            removed = session.clear_response_log()
            self.assertGreaterEqual(removed, 1)
            self.assertEqual(session.read_response_log(limit=5), [])

    def test_poll_hotfolder_empty_returns_no_package_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            hotfolder_dir = Path(temp_dir) / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_INCLUDE_FIXED_FIXTURES=False,
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            rows = session.poll_hotfolder(cycles=2, interval_ms=0)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0].get("eim_result_code"), 1)
            self.assertFalse(bool(rows[0].get("issued")))

    def test_poll_queue_includes_fixed_fixtures_and_dynamic_hotfolder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            runtime_state_file = str(base_dir / "state.json")
            hotfolder_dir = base_dir / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            eim_to_esim_dir, esim_to_eim_dir = create_poll_fixture_dirs(base_dir)

            (eim_to_esim_dir / "010_trigger.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "allow_model_only": True,
                            "queue_id": 10,
                            "transaction_id_hex": "10",
                            "matching_id": "FIXTURE-TRIGGER",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (hotfolder_dir / "015_dynamic.json").write_text(
                json.dumps(
                    {
                        "package_type": "eim_acknowledgements",
                        "runtime": {
                            "queue_id": 15,
                            "transaction_id_hex": "15",
                            "matching_id": "DYNAMIC-QUEUE",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (esim_to_eim_dir / "020_result.json").write_text(
                json.dumps(
                    {
                        "package_type": "provide_eim_package_result",
                        "runtime": {
                            "queue_id": 20,
                            "transaction_id_hex": "20",
                            "matching_id": "FIXTURE-RESULT",
                        },
                    }
                ),
                encoding="utf-8",
            )

            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_EIM_TO_ESIM_DIR=str(eim_to_esim_dir),
                EIM_POLL_ESIM_TO_EIM_DIR=str(esim_to_eim_dir),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)

            rows = session.list_hotfolder_preview()
            self.assertEqual(len(rows), 3)
            self.assertEqual(
                [str(row.get("session_source", "")) for row in rows],
                ["fixture.eim_to_esim", "hotfolder", "fixture.esim_to_eim"],
            )
            self.assertEqual(
                [int(row.get("queue_order", 0)) for row in rows],
                [10, 15, 20],
            )
            self.assertEqual(
                [str(row.get("matching_id", "")) for row in rows],
                ["FIXTURE-TRIGGER", "DYNAMIC-QUEUE", "FIXTURE-RESULT"],
            )

            meta = session.hotfolder_poll_response_meta()
            self.assertEqual(meta["package_count"], 3)
            self.assertIsNone(meta["eim_result_code"])

            issued = session.issue_next_hotfolder_package()
            self.assertIsNotNone(issued)
            assert issued is not None
            self.assertEqual(Path(issued[0]).name, "010_trigger.json")
            self.assertEqual(issued[1], "profile_download_trigger_request")
            self.assertEqual(issued[2], 0)

    def test_poll_hotfolder_campaign_issues_each_queue_file_once_per_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            runtime_state_file = str(base_dir / "state.json")
            hotfolder_dir = base_dir / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            eim_to_esim_dir, esim_to_eim_dir = create_poll_fixture_dirs(base_dir)

            (eim_to_esim_dir / "010_trigger.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "allow_model_only": True,
                            "queue_id": 10,
                            "transaction_id_hex": "10",
                            "matching_id": "FIXTURE-TRIGGER",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (hotfolder_dir / "015_dynamic.json").write_text(
                json.dumps(
                    {
                        "package_type": "eim_acknowledgements",
                        "runtime": {
                            "queue_id": 15,
                            "transaction_id_hex": "15",
                            "matching_id": "DYNAMIC-QUEUE",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (esim_to_eim_dir / "020_result.json").write_text(
                json.dumps(
                    {
                        "package_type": "provide_eim_package_result",
                        "runtime": {
                            "queue_id": 20,
                            "transaction_id_hex": "20",
                            "matching_id": "FIXTURE-RESULT",
                        },
                    }
                ),
                encoding="utf-8",
            )

            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_EIM_TO_ESIM_DIR=str(eim_to_esim_dir),
                EIM_POLL_ESIM_TO_EIM_DIR=str(esim_to_eim_dir),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)

            report = session.poll_hotfolder_campaign(cycles=5, interval_ms=0)
            rows = report.get("rows", [])

            self.assertEqual(len(rows), 5)
            self.assertEqual(
                [Path(str(row.get("issued_file", ""))).name for row in rows[:3]],
                ["010_trigger.json", "015_dynamic.json", "020_result.json"],
            )
            self.assertTrue(all(bool(row.get("issued", False)) for row in rows[:3]))
            self.assertTrue(all(int(row.get("package_count", -1)) == 0 for row in rows[3:]))
            self.assertTrue(all(bool(row.get("issued", False)) is False for row in rows[3:]))
            self.assertTrue(all(row.get("eim_result_code") == 1 for row in rows[3:]))
            self.assertEqual(
                report.get("summary", {}).get("issued_cycles"),
                3,
            )
            self.assertEqual(
                report.get("summary", {}).get("no_package_cycles"),
                2,
            )

    def test_issue_next_hotfolder_package_advances_session_queue_without_repeating(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            runtime_state_file = str(base_dir / "state.json")
            hotfolder_dir = base_dir / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            eim_to_esim_dir, esim_to_eim_dir = create_poll_fixture_dirs(base_dir)

            (eim_to_esim_dir / "010_trigger.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "allow_model_only": True,
                            "queue_id": 10,
                            "transaction_id_hex": "10",
                            "matching_id": "FIXTURE-TRIGGER",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (hotfolder_dir / "015_dynamic.json").write_text(
                json.dumps(
                    {
                        "package_type": "eim_acknowledgements",
                        "runtime": {
                            "queue_id": 15,
                            "transaction_id_hex": "15",
                            "matching_id": "DYNAMIC-QUEUE",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (esim_to_eim_dir / "020_result.json").write_text(
                json.dumps(
                    {
                        "package_type": "provide_eim_package_result",
                        "runtime": {
                            "queue_id": 20,
                            "transaction_id_hex": "20",
                            "matching_id": "FIXTURE-RESULT",
                        },
                    }
                ),
                encoding="utf-8",
            )

            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_EIM_TO_ESIM_DIR=str(eim_to_esim_dir),
                EIM_POLL_ESIM_TO_EIM_DIR=str(esim_to_eim_dir),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)

            first = session.issue_next_hotfolder_package()
            second_meta = session.hotfolder_poll_metadata()
            second = session.issue_next_hotfolder_package()
            third = session.issue_next_hotfolder_package()
            fourth = session.issue_next_hotfolder_package()

            self.assertIsNotNone(first)
            assert first is not None
            self.assertEqual(Path(str(first[0])).name, "010_trigger.json")
            self.assertEqual(Path(str(second_meta.get("next_file", ""))).name, "015_dynamic.json")
            self.assertEqual(int(second_meta.get("package_count", 0)), 2)
            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(Path(str(second[0])).name, "015_dynamic.json")
            self.assertIsNotNone(third)
            assert third is not None
            self.assertEqual(Path(str(third[0])).name, "020_result.json")
            self.assertIsNone(fourth)

    def test_execution_coverage_matrix_contains_expected_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            matrix = session.execution_coverage_matrix()
            self.assertIn("provide_eim_package_result", matrix)
            self.assertEqual(matrix["provide_eim_package_result"]["mode"], "executable")
            self.assertIn("bound_profile_package", matrix)
            self.assertEqual(matrix["bound_profile_package"]["mode"], "executable")
            self.assertEqual(
                matrix["profile_download_trigger_request"]["execution_path"],
                "indirect_profile_download",
            )
            self.assertIn("eim_package_request", matrix)
            self.assertEqual(matrix["eim_package_request"]["mode"], "model_only")

    def test_model_only_package_requires_allow_model_only_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            package_path = Path(temp_dir) / "pkg.json"
            package_path.write_text(
                json.dumps(
                    {
                        "package_type": "eim_package_request",
                        "runtime": {
                            "transaction_id_hex": "0102",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            with self.assertRaisesRegex(ValueError, "model_only"):
                session.issue_eim_package_file(str(package_path))

    def test_model_only_package_runs_when_allow_flag_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            package_path = Path(temp_dir) / "pkg.json"
            package_path.write_text(
                json.dumps(
                    {
                        "package_type": "eim_package_request",
                        "runtime": {
                            "allow_model_only": True,
                            "transaction_id_hex": "0102",
                            "matching_id": "MID-ALLOW",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            _, package_type, result_len = session.issue_eim_package_file(str(package_path))
            self.assertEqual(package_type, "eim_package_request")
            self.assertEqual(result_len, 0)

    def test_lint_strict_exec_fails_model_only_without_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            package_path = Path(temp_dir) / "pkg.json"
            package_path.write_text(
                json.dumps(
                    {
                        "package_type": "eim_package_request",
                        "runtime": {},
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            report = session.lint_eim_package(package_path=str(package_path), strict_executable=True)
            self.assertFalse(bool(report.get("ok")))
            errors = report.get("errors", [])
            self.assertTrue(any("strict_executable mode" in str(item) for item in errors))

    def test_issue_profile_download_trigger_request_executes_indirect_download(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            response_log_file = str(Path(temp_dir) / "responses.jsonl")
            package_path = Path(temp_dir) / "trigger.json"
            package_path.write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "transaction_id_hex": "0102030405060708090A0B0C0D0E0F10",
                            "matching_id": "MID-TRIGGER",
                            "profile_path": "SCP11/eim_local/profile/test_profile.txt",
                            "smdp_address": "https://local.smdpp.example/gsma/rsp2",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_RESPONSE_LOG_FILE=response_log_file,
            )
            session = EimLocalSession(cfg=config, apdu_channel=object())
            calls: list[tuple[str, str]] = []

            def fake_ipae_download(profile_path: str = "", matching_id: str = "") -> bytes:
                calls.append((profile_path, matching_id))
                return bytes.fromhex("BF3700")

            session.ipae_download = fake_ipae_download  # type: ignore[assignment]
            session._read_card_eid = lambda: "89049032000000000000000000000000"  # type: ignore[assignment]

            _, package_type, result_len = session.issue_eim_package_file(str(package_path))
            self.assertEqual(package_type, "profile_download_trigger_request")
            self.assertEqual(
                calls,
                [("SCP11/eim_local/profile/test_profile.txt", "MID-TRIGGER")],
            )
            self.assertEqual(result_len, len(session.state.eim_package_response))
            self.assertTrue(session.state.eim_package_response.startswith(bytes.fromhex("BF50")))
            self.assertIn("BF54", session.state.eim_package_response.hex().upper())
            rows = session.read_response_log(limit=5)
            self.assertGreaterEqual(len(rows), 1)
            last = rows[-1]
            self.assertEqual(last.get("package_type"), "profile_download_trigger_request")
            self.assertTrue(bool(last.get("success")))
            details = last.get("details", {})
            self.assertEqual(details.get("execution_path"), "indirect_profile_download")
            self.assertEqual(details.get("download_mode"), "indirect")
            self.assertEqual(details.get("smdp_address"), "https://local.smdpp.example/gsma/rsp2")

    def test_issue_bound_profile_package_executes_direct_download(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            response_log_file = str(Path(temp_dir) / "responses.jsonl")
            package_path = Path(temp_dir) / "direct.json"
            package_path.write_text(
                json.dumps(
                    {
                        "package_type": "bound_profile_package",
                        "runtime": {
                            "transaction_id_hex": "1112131415161718191A1B1C1D1E1F20",
                            "matching_id": "MID-DIRECT",
                            "profile_path": "SCP11/eim_local/profile/test_profile.txt",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_RESPONSE_LOG_FILE=response_log_file,
            )
            session = EimLocalSession(cfg=config, apdu_channel=object())
            calls: list[tuple[bytes, str]] = []

            def fake_direct(transaction_id: bytes, profile_path: str = "") -> tuple[bytes, bytes]:
                calls.append((bytes(transaction_id), profile_path))
                return bytes.fromhex("BF3700"), bytes.fromhex("BF3600")

            session._run_direct_profile_download_with_transaction = fake_direct  # type: ignore[assignment]
            session._read_card_eid = lambda: "89049032000000000000000000000000"  # type: ignore[assignment]

            _, package_type, result_len = session.issue_eim_package_file(str(package_path))
            self.assertEqual(package_type, "bound_profile_package")
            self.assertEqual(
                calls,
                [(bytes.fromhex("1112131415161718191A1B1C1D1E1F20"), "SCP11/eim_local/profile/test_profile.txt")],
            )
            self.assertEqual(result_len, len(session.state.eim_package_response))
            self.assertTrue(session.state.eim_package_response.startswith(bytes.fromhex("BF50")))
            self.assertIn("BF51", session.state.eim_package_response.hex().upper())
            rows = session.read_response_log(limit=5)
            self.assertGreaterEqual(len(rows), 1)
            last = rows[-1]
            self.assertEqual(last.get("package_type"), "bound_profile_package")
            self.assertTrue(bool(last.get("success")))
            details = last.get("details", {})
            self.assertEqual(details.get("execution_path"), "direct_profile_download")
            self.assertEqual(details.get("download_mode"), "direct")
            self.assertEqual(details.get("bound_profile_package_len"), 3)

    def test_run_load_profile_chain_with_transaction_builds_session_bound_bpp_for_raw_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=object())
            calls: list[tuple[str, bytes]] = []

            session._read_profile_source_bytes = lambda profile_path="": bytes.fromhex("A00100")  # type: ignore[assignment]
            session.select_isdr = lambda: calls.append(("select_isdr", b"")) or b""  # type: ignore[assignment]

            def fake_open_session(transaction_id_override=None):
                calls.append(("open_session", bytes(transaction_id_override or b"")))
                session.state.session_open = True
                return None

            session.open_session = fake_open_session  # type: ignore[assignment]
            session.prepare_download = lambda: calls.append(("prepare_download", b"")) or b""  # type: ignore[assignment]

            def fake_build_session_bound_profile_package(profile_bytes: bytes) -> bytes:
                calls.append(("build_bpp", bytes(profile_bytes)))
                return bytes.fromhex("BF3600")

            session._build_session_bound_profile_package = fake_build_session_bound_profile_package  # type: ignore[assignment]

            def fake_load_profile_from_bytes(bpp_bytes: bytes, *, progress_bar=None) -> bytes:
                _ = progress_bar
                calls.append(("load_profile_from_bytes", bytes(bpp_bytes)))
                return bytes.fromhex("BF3700")

            session._load_profile_from_bytes = fake_load_profile_from_bytes  # type: ignore[assignment]
            session._sync_pending_notifications = lambda response=b"": calls.append(("sync_notifications", bytes(response)))  # type: ignore[assignment]

            def fake_close_session(reason=0):
                _ = reason
                calls.append(("close_session", b""))
                session.state.session_open = False
                return b""

            session.close_session = fake_close_session  # type: ignore[assignment]

            response = session.run_load_profile_chain_with_transaction(
                bytes.fromhex("0102030405060708090A0B0C0D0E0F10"),
                "profile.txt",
            )

            self.assertEqual(response, bytes.fromhex("BF3700"))
            self.assertIn(("build_bpp", bytes.fromhex("A00100")), calls)
            self.assertIn(("load_profile_from_bytes", bytes.fromhex("BF3600")), calls)
            self.assertEqual(calls[0], ("select_isdr", b""))
            self.assertEqual(calls[-1], ("sync_notifications", bytes.fromhex("BF3700")))

    def test_run_load_profile_chain_with_transaction_preserves_existing_bpp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=object())
            calls: list[tuple[str, bytes]] = []

            session._read_profile_source_bytes = lambda profile_path="": bytes.fromhex("BF3600")  # type: ignore[assignment]
            session.select_isdr = lambda: b""  # type: ignore[assignment]

            def fake_open_session(transaction_id_override=None):
                _ = transaction_id_override
                session.state.session_open = True
                return None

            session.open_session = fake_open_session  # type: ignore[assignment]
            session.prepare_download = lambda: b""  # type: ignore[assignment]

            def fail_build_session_bound_profile_package(profile_bytes: bytes) -> bytes:
                _ = profile_bytes
                raise AssertionError("Existing BF36 input must not be rebound.")

            session._build_session_bound_profile_package = fail_build_session_bound_profile_package  # type: ignore[assignment]

            def fake_load_profile_from_bytes(bpp_bytes: bytes, *, progress_bar=None) -> bytes:
                _ = progress_bar
                calls.append(("load_profile_from_bytes", bytes(bpp_bytes)))
                return bytes.fromhex("BF3700")

            session._load_profile_from_bytes = fake_load_profile_from_bytes  # type: ignore[assignment]
            session._sync_pending_notifications = lambda response=b"": None  # type: ignore[assignment]
            session.close_session = lambda reason=0: b""  # type: ignore[assignment]

            response = session.run_load_profile_chain_with_transaction(
                bytes.fromhex("1112131415161718191A1B1C1D1E1F20"),
                "bound-profile.bin",
            )

            self.assertEqual(response, bytes.fromhex("BF3700"))
            self.assertEqual(calls, [("load_profile_from_bytes", bytes.fromhex("BF3600"))])

    def test_issue_provide_eim_package_result_is_wire_preview_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            response_log_file = str(Path(temp_dir) / "responses.jsonl")
            package_path = Path(temp_dir) / "provide.json"
            package_path.write_text(
                json.dumps(
                    {
                        "package_type": "provide_eim_package_result",
                        "runtime": {
                            "transaction_id_hex": "A1B2C3D4",
                            "matching_id": "MID-PROVIDE",
                        },
                        "sgp32": {
                            "provide_eim_package_result": {
                                "result_choice": "euicc_package_result",
                                "euicc_package_result": {
                                    "include": True,
                                    "value_hex": "BF3700",
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_RESPONSE_LOG_FILE=response_log_file,
            )
            session = EimLocalSession(cfg=config, apdu_channel=object())

            def fail_ipae_download(*args, **kwargs):
                raise AssertionError("provide_eim_package_result should not trigger ipae_download")

            session.ipae_download = fail_ipae_download  # type: ignore[assignment]

            _, package_type, result_len = session.issue_eim_package_file(str(package_path))
            self.assertEqual(package_type, "provide_eim_package_result")
            self.assertEqual(result_len, len(session.state.eim_package_response))
            self.assertTrue(session.state.eim_package_response.startswith(bytes.fromhex("BF50")))
            self.assertIn("BF51", session.state.eim_package_response.hex().upper())
            rows = session.read_response_log(limit=5)
            last = rows[-1]
            details = last.get("details", {})
            self.assertEqual(details.get("execution_path"), "provide_eim_package_result_preview")

    def test_poll_hotfolder_campaign_until_empty_stops_early(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            hotfolder_dir = Path(temp_dir) / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_INCLUDE_FIXED_FIXTURES=False,
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            report = session.poll_hotfolder_campaign(
                cycles=10,
                interval_ms=0,
                until_empty=True,
                max_cycles=5,
            )
            summary = report.get("summary", {})
            self.assertEqual(int(report.get("executed_cycles", 0)), 1)
            self.assertEqual(str(summary.get("stop_reason", "")), "queue_empty")

    def test_export_campaign_report_writes_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_POLL_INCLUDE_FIXED_FIXTURES=False,
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            report = session.poll_hotfolder_campaign(cycles=1, interval_ms=0, until_empty=True, max_cycles=1)
            output_path = str(Path(temp_dir) / "campaign_report.json")
            saved = session.export_campaign_report(report, output_path=output_path)
            self.assertEqual(saved, output_path)
            payload = json.loads(Path(output_path).read_text(encoding="utf-8"))
            self.assertIn("summary", payload)
            self.assertIn("rows", payload)

    def test_wire_preview_profile_download_trigger_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            payload = session.build_wire_payload_preview(
                {
                    "package_type": "profile_download_trigger_result",
                    "runtime": {"transaction_id_hex": "A1B2C3D4"},
                    "sgp32": {
                        "profile_download_trigger_result": {
                            "result_code": {"include": True, "value": "ok"},
                        }
                    },
                }
            )
            self.assertTrue(payload.hex().upper().startswith("BF54"))
            self.assertIn("80", payload.hex().upper())

    def test_wire_preview_euicc_memory_reset_encodes_selective_eim_reset_bit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            payload = session.build_wire_payload_preview(build_euicc_memory_reset_package_document())
            self.assertEqual(payload.hex().upper(), "BF640482020204")

    def test_wire_preview_profile_download_trigger_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            payload = session.build_wire_payload_preview(
                {
                    "package_type": "profile_download_trigger_request",
                    "runtime": {
                        "transaction_id_hex": "0102030405060708090A0B0C0D0E0F10",
                        "matching_id": "MID-TRIGGER",
                    },
                }
            )
            parsed = parse_eim_package(payload)
            self.assertEqual(parsed.package_type, TYPE_PROFILE_DOWNLOAD_TRIGGER)
            self.assertEqual(parsed.eim_transaction_id.hex().upper(), "0102030405060708090A0B0C0D0E0F10")
            self.assertEqual(parsed.matching_id, "MID-TRIGGER")
            self.assertEqual(parsed.smdp_address, session.eim_identity["smdp_address"])

    def test_wire_preview_profile_download_trigger_prefers_local_smdp_drop_in_address(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            certs_dir = Path(temp_dir) / "local_smdp_certs"
            write_local_smdp_drop_in(
                certs_dir,
                "operator-alpha-auth",
                "local.smdpp.operator.example",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                CERTS_DIR=str(certs_dir),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            session.eim_identity["smdp_address"] = "identity.smdpp.example"

            payload = session.build_wire_payload_preview(
                {
                    "package_type": "profile_download_trigger_request",
                    "runtime": {
                        "transaction_id_hex": "0102030405060708090A0B0C0D0E0F10",
                        "matching_id": "MID-LOCAL",
                    },
                }
            )

            parsed = parse_eim_package(payload)

        self.assertEqual(parsed.smdp_address, "local.smdpp.operator.example")

    def test_wire_preview_wrapped_profile_download_trigger_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            payload = session.build_wire_payload_preview(
                {
                    "package_type": "eim_package_request",
                    "runtime": {"matching_id": "MID-RUNTIME"},
                    "sgp32": {
                        "eim_package_request": {
                            "choice": "profile_download_trigger_request",
                            "profile_download_trigger_request": {
                                "matching_id": {"include": True, "value": "MID-WRAPPED"},
                                "transaction_id": {"include": True, "value_hex": "A1B2C3D4E5F60708A9B0C1D2E3F40506"},
                            },
                        }
                    },
                }
            )
            parsed = parse_eim_package(payload)
            self.assertEqual(parsed.package_type, TYPE_PROFILE_DOWNLOAD_TRIGGER)
            self.assertEqual(parsed.eim_transaction_id.hex().upper(), "A1B2C3D4E5F60708A9B0C1D2E3F40506")
            self.assertEqual(parsed.matching_id, "MID-WRAPPED")
            self.assertEqual(parsed.smdp_address, session.eim_identity["smdp_address"])

    def test_wire_preview_eim_package_result_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            payload = session.build_wire_payload_preview(
                {
                    "package_type": "eim_package_result",
                    "runtime": {"transaction_id_hex": "01020304"},
                    "sgp32": {"eim_package_result": {"choice": "euicc_package_result"}},
                }
            )
            self.assertTrue(payload.hex().upper().startswith("BF51"))
            self.assertIn("01020304", payload.hex().upper())

    def test_wire_preview_provide_eim_package_result_error_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            payload = session.build_wire_payload_preview(
                {
                    "package_type": "provide_eim_package_result",
                    "sgp32": {
                        "provide_eim_package_result": {
                            "result_choice": "eim_package_result_response_error",
                            "eim_package_result_response_error": {"error_code": "invalidPackageFormat"},
                        }
                    },
                }
            )
            self.assertTrue(payload.hex().upper().startswith("BF50"))
            self.assertIn("020101", payload.hex().upper())

    def test_wire_preview_add_initial_eim_encodes_full_eim_configuration_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            payload = session.build_wire_payload_preview(build_add_eim_package_document("add_initial_eim"))
            root_tag, row_value = extract_first_eim_configuration_row(payload)
            self.assertEqual(root_tag, 0xBF57)
            decoded = decode_eim_configuration_entry(row_value)
            self.assertEqual(decoded.get("eim_id"), DEFAULT_TEST_EIM_OID)
            self.assertEqual(decoded.get("eim_fqdn"), DEFAULT_TEST_EIM_FQDN)
            self.assertEqual(decoded.get("eim_id_type"), "eimIdTypeOid (1)")
            self.assertEqual(decoded.get("counter_value"), "1")
            self.assertEqual(decoded.get("association_token"), "255")
            self.assertEqual(decoded.get("eim_public_key_data"), bytes.fromhex("A104DEADBEEF"))
            self.assertEqual(decoded.get("trusted_tls_public_key_data"), bytes.fromhex("A00411223344"))
            self.assertEqual(
                decoded.get("euicc_ci_pkid"),
                "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
            )
            self.assertEqual(decoded.get("indirect_profile_download"), "Present")
            supported_protocol = str(decoded.get("supported_protocol", ""))
            self.assertTrue(supported_protocol.startswith("0780"))
            self.assertIn("eimRetrieveHttps", supported_protocol)

    def test_wire_preview_add_eim_uses_bf58_root_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            payload = session.build_wire_payload_preview(build_add_eim_package_document("add_eim", counter_value=2))
            root_tag, row_value = extract_first_eim_configuration_row(payload)
            self.assertEqual(root_tag, 0xBF58)
            decoded = decode_eim_configuration_entry(row_value)
            self.assertEqual(decoded.get("counter_value"), "2")

    def test_wire_preview_add_initial_eim_accepts_pem_certificate_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            pem_cert_path = write_test_pem_certificate(Path(temp_dir) / "certs", "explicit_eim_cert")
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            document = build_add_eim_package_document("add_initial_eim")
            row = document["sgp32"]["add_initial_eim_request"]["eim_configuration_data_list"][0]
            row["eim_public_key_data"] = {
                "include": True,
                "choice": "eim_certificate",
                "eim_certificate_der_path": str(pem_cert_path),
            }
            row["trusted_public_key_data_tls"] = {"include": False}
            payload = session.build_wire_payload_preview(document)
            _, row_value = extract_first_eim_configuration_row(payload)
            decoded = decode_eim_configuration_entry(row_value)
            cert_choice = decoded.get("eim_public_key_data")
            self.assertIsInstance(cert_choice, bytes)
            assert isinstance(cert_choice, bytes)
            self.assertTrue(cert_choice.startswith(b"\xA1"))
            self.assertGreater(len(cert_choice), 64)

    def test_wire_preview_add_initial_eim_uses_identity_endpoint_and_cert_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            identity_file = Path(temp_dir) / "identity.json"
            pem_cert_path = write_test_pem_certificate(Path(temp_dir) / "certs", "identity_eim_cert")
            identity_file.write_text(
                json.dumps(
                    {
                        "eim_id": DEFAULT_TEST_EIM_OID,
                        "eim_fqdn": DEFAULT_TEST_EIM_FQDN,
                        "eim_id_type": "oid",
                        "eim_endpoint": "https://identity.eim.example/gsma/rsp2/asn1",
                        "eim_public_key_cert_path": str(pem_cert_path),
                        "trusted_tls_cert_path": str(pem_cert_path),
                        "euicc_ci_pk_id": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_IDENTITY_FILE=str(identity_file),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            document = {
                "package_type": "add_initial_eim",
                "sgp32": {
                    "add_initial_eim_request": {
                        "include": True,
                        "eim_configuration_data_list": [
                            {
                                "include": True,
                                "eim_id": {"include": True, "value": ""},
                                "eim_fqdn": {"include": True, "value": ""},
                                "eim_id_type": {"include": True, "value": ""},
                                "counter_value": {"include": True, "value": 1},
                                "eim_public_key_data": {
                                    "include": True,
                                    "choice": "eim_certificate",
                                },
                                "trusted_public_key_data_tls": {
                                    "include": True,
                                    "choice": "trusted_certificate_tls",
                                },
                                "euicc_ci_pk_id": {
                                    "include": True,
                                    "value_hex": "",
                                },
                            }
                        ],
                    }
                },
            }
            payload = session.build_wire_payload_preview(document)
            _, row_value = extract_first_eim_configuration_row(payload)
            decoded = decode_eim_configuration_entry(row_value)
            self.assertEqual(decoded.get("eim_id"), DEFAULT_TEST_EIM_OID)
            self.assertEqual(decoded.get("eim_fqdn"), DEFAULT_TEST_EIM_FQDN)
            self.assertEqual(decoded.get("eim_id_type"), "eimIdTypeOid (1)")
            self.assertEqual(
                decoded.get("euicc_ci_pkid"),
                "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
            )
            cert_choice = decoded.get("eim_public_key_data")
            trusted_choice = decoded.get("trusted_tls_public_key_data")
            self.assertIsInstance(cert_choice, bytes)
            self.assertIsInstance(trusted_choice, bytes)
            assert isinstance(cert_choice, bytes)
            assert isinstance(trusted_choice, bytes)
            self.assertTrue(cert_choice.startswith(b"\xA1"))
            self.assertTrue(trusted_choice.startswith(b"\xA1"))

    def test_preview_eim_signing_certificate_prefers_card_matching_ci_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            cert_dir = base_dir / "certs"
            match_path, _ = write_test_signing_certificate(
                cert_dir,
                "MATCH",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "match.eim.test",
            )
            fallback_path, _ = write_test_signing_certificate(
                cert_dir,
                "FALLBACK",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "fallback.eim.test",
            )
            identity_file = base_dir / "identity.json"
            identity_file.write_text(
                json.dumps(
                    {
                        "eim_public_key_cert_path": str(fallback_path),
                        "euicc_ci_pk_id": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_IDENTITY_FILE=str(identity_file),
                EIM_CERTS_DIR=str(cert_dir),
                SGP26_VALID_CERT_DIR=str(base_dir / "sgp26-empty"),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            session.state.allowed_ci_pkids = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
            preview = session.preview_eim_signing_certificate()
            self.assertEqual(preview["path"], str(match_path))
            self.assertEqual(preview["reason"], "card_allowed_ci_match")
            self.assertEqual(
                preview["root_ci_pkids"],
                ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            )

    def test_preview_eim_signing_certificate_respects_explicit_cert_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            cert_dir = base_dir / "certs"
            match_path, _ = write_test_signing_certificate(
                cert_dir,
                "MATCH",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "match.eim.test",
            )
            fallback_path, _ = write_test_signing_certificate(
                cert_dir,
                "FALLBACK",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "fallback.eim.test",
            )
            identity_file = base_dir / "identity.json"
            identity_file.write_text(
                json.dumps(
                    {
                        "eim_public_key_cert_path": str(fallback_path),
                        "euicc_ci_pk_id": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_IDENTITY_FILE=str(identity_file),
                EIM_CERTS_DIR=str(cert_dir),
                SGP26_VALID_CERT_DIR=str(base_dir / "sgp26-empty"),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            session.state.allowed_ci_pkids = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
            preview = session.preview_eim_signing_certificate(cert_path=str(fallback_path))
            self.assertEqual(preview["path"], str(fallback_path))
            self.assertEqual(preview["reason"], "explicit_override")
            self.assertNotEqual(str(match_path), preview["path"])

    def test_wire_preview_add_initial_eim_auto_selects_card_matching_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            cert_dir = base_dir / "certs"
            match_path, match_der = write_test_signing_certificate(
                cert_dir,
                "MATCH",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "match.eim.test",
            )
            fallback_path, _ = write_test_signing_certificate(
                cert_dir,
                "FALLBACK",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "fallback.eim.test",
            )
            identity_file = base_dir / "identity.json"
            identity_file.write_text(
                json.dumps(
                    {
                        "eim_public_key_cert_path": str(fallback_path),
                        "euicc_ci_pk_id": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_IDENTITY_FILE=str(identity_file),
                EIM_CERTS_DIR=str(cert_dir),
                SGP26_VALID_CERT_DIR=str(base_dir / "sgp26-empty"),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            session.state.allowed_ci_pkids = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
            document = {
                "package_type": "add_initial_eim",
                "sgp32": {
                    "add_initial_eim_request": {
                        "include": True,
                        "eim_configuration_data_list": [
                            {
                                "include": True,
                                "eim_id": {"include": True, "value": DEFAULT_TEST_EIM_OID},
                                "eim_fqdn": {"include": True, "value": "match.eim.test"},
                                "eim_id_type": {"include": True, "value": "oid"},
                                "counter_value": {"include": True, "value": 1},
                                "eim_public_key_data": {
                                    "include": True,
                                    "choice": "eim_certificate",
                                },
                                "trusted_public_key_data_tls": {"include": False},
                                "euicc_ci_pk_id": {
                                    "include": True,
                                    "value_hex": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                                },
                            }
                        ],
                    }
                },
            }
            payload = session.build_wire_payload_preview(document)
            _, row_value = extract_first_eim_configuration_row(payload)
            decoded = decode_eim_configuration_entry(row_value)
            self.assertEqual(decoded.get("eim_public_key_data"), wrap_tlv(b"\xA1", match_der))
            summary = session.selected_eim_certificate_summary()
            self.assertEqual(summary["path"], str(match_path))
            self.assertEqual(summary["reason"], "card_ci_and_preferred_ci_match")
            self.assertEqual(
                summary["root_ci_pkids"],
                ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            )

    def test_preview_eim_signing_certificate_uses_sidecar_metadata_for_nonstandard_cert(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            cert_dir = base_dir / "certs"
            fallback_path, _ = write_test_signing_certificate(
                cert_dir,
                "FALLBACK",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "fallback.eim.test",
            )
            metadata_cert_path = cert_dir / "CERT_S_EIMsign_META.der"
            metadata_key_path = cert_dir / "SK_S_EIMsign_META.pem"
            metadata_cert_path.write_bytes(bytes.fromhex("3081"))
            metadata_key_path.write_text("placeholder", encoding="utf-8")
            (cert_dir / "CERT_S_EIMsign_META.meta.json").write_text(
                json.dumps(
                    {
                        "role": "signing",
                        "private_key_path": "SK_S_EIMsign_META.pem",
                        "root_ci_pkid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "subject_cn": "meta.eim.test",
                        "curve": "NIST",
                    }
                ),
                encoding="utf-8",
            )
            identity_file = base_dir / "identity.json"
            identity_file.write_text(
                json.dumps(
                    {
                        "eim_public_key_cert_path": str(metadata_cert_path),
                        "euicc_ci_pk_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_IDENTITY_FILE=str(identity_file),
                EIM_CERTS_DIR=str(cert_dir),
                SGP26_VALID_CERT_DIR=str(base_dir / "sgp26-empty"),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            session.state.allowed_ci_pkids = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
            preview = session.preview_eim_signing_certificate()
            self.assertEqual(preview["path"], str(metadata_cert_path))
            self.assertEqual(preview["reason"], "card_ci_and_preferred_ci_match")
            self.assertEqual(
                preview["private_key_path"],
                str(metadata_key_path),
            )
            self.assertNotEqual(preview["path"], str(fallback_path))

    def test_issue_package_add_eim_uses_sgp32_wire_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            response_log_file = str(Path(temp_dir) / "responses.jsonl")
            package_path = Path(temp_dir) / "add_eim_package.json"
            document = build_add_eim_package_document("add_eim", counter_value=7)
            package_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_RESPONSE_LOG_FILE=response_log_file,
            )
            apdu_channel = FakeEimLocalApduChannel()
            session = EimLocalSession(cfg=config, apdu_channel=apdu_channel)
            expected_payload = session.build_wire_payload_preview(document)
            _, package_type, result_len = session.issue_eim_package_file(str(package_path))
            self.assertEqual(package_type, "add_eim")
            self.assertEqual(result_len, 3)
            add_apdu = next(
                apdu
                for log_name, apdu in apdu_channel.send_calls
                if log_name == "EIM-LOCAL: AddEim"
            )
            self.assertIn(expected_payload.hex().upper(), add_apdu.hex().upper())
            response_rows = session.read_response_log(limit=5)
            self.assertTrue(any(str(row.get("action")) == "AddEim" for row in response_rows))
            add_rows = [row for row in response_rows if str(row.get("action")) == "AddEim"]
            self.assertGreaterEqual(len(add_rows), 1)
            details = add_rows[-1].get("details", {})
            self.assertEqual(str(details.get("mode", "")), "package_sgp32")

    def test_issue_package_add_eim_preserves_explicit_zero_counter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            response_log_file = str(Path(temp_dir) / "responses.jsonl")
            package_path = Path(temp_dir) / "add_eim_package_zero_counter.json"
            document = build_add_eim_package_document("add_eim", counter_value=0)
            package_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_RESPONSE_LOG_FILE=response_log_file,
            )
            apdu_channel = FakeEimLocalApduChannel()
            session = EimLocalSession(cfg=config, apdu_channel=apdu_channel)
            expected_payload = session.build_wire_payload_preview(document)

            _, package_type, result_len = session.issue_eim_package_file(str(package_path))

            self.assertEqual(package_type, "add_eim")
            self.assertEqual(result_len, 3)
            add_apdu = next(
                apdu
                for log_name, apdu in apdu_channel.send_calls
                if log_name == "EIM-LOCAL: AddEim"
            )
            self.assertIn(expected_payload.hex().upper(), add_apdu.hex().upper())
            _, row_value = extract_first_eim_configuration_row(expected_payload)
            decoded = decode_eim_configuration_entry(row_value)
            self.assertEqual(decoded.get("counter_value"), "0")

    def test_load_eim_package_to_isdr_uses_local_auth_package_transport_for_add_eim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            response_log_file = str(Path(temp_dir) / "responses.jsonl")
            package_path = Path(temp_dir) / "add_eim_package.json"
            document = build_add_eim_package_document("add_eim", counter_value=9)
            package_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_RESPONSE_LOG_FILE=response_log_file,
            )
            apdu_channel = FakeEimLocalApduChannel()
            session = EimLocalSession(cfg=config, apdu_channel=apdu_channel)
            open_calls: list[str] = []
            close_calls: list[str] = []

            def fake_open_session(transaction_id_override=None):
                _ = transaction_id_override
                session.state.session_open = True
                open_calls.append("open")
                return None

            def fake_close_session(reason=0):
                _ = reason
                session.state.session_open = False
                close_calls.append("close")
                return b""

            session.open_session = fake_open_session
            session.close_session = fake_close_session

            report = session.load_eim_package_to_isdr(str(package_path))

            self.assertEqual(report["package_type"], "add_eim")
            self.assertEqual(report["transport"], "local_auth")
            self.assertEqual(int(report["result_len"]), 3)
            self.assertEqual(open_calls, ["open"])
            self.assertEqual(close_calls, ["close"])
            add_apdu = next(
                apdu
                for log_name, apdu in apdu_channel.send_calls
                if log_name == "EIM-LOCAL: AddEim [LOCAL-AUTH]"
            )
            expected_payload = session.build_wire_payload_preview(document)
            self.assertIn(expected_payload.hex().upper(), add_apdu.hex().upper())
            response_rows = session.read_response_log(limit=10)
            add_rows = [row for row in response_rows if str(row.get("action")) == "AddEim"]
            self.assertGreaterEqual(len(add_rows), 1)
            details = add_rows[-1].get("details", {})
            self.assertEqual(str(details.get("mode", "")), "package_sgp32_isdr")
            self.assertEqual(str(details.get("transport", "")), "local_auth")

    def test_load_eim_package_to_isdr_supports_euicc_memory_reset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            response_log_file = str(Path(temp_dir) / "responses.jsonl")
            package_path = Path(temp_dir) / "euicc_memory_reset.json"
            document = build_euicc_memory_reset_package_document()
            package_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=runtime_state_file,
                EIM_RESPONSE_LOG_FILE=response_log_file,
            )
            apdu_channel = FakeEimLocalApduChannel()
            session = EimLocalSession(cfg=config, apdu_channel=apdu_channel)

            report = session.load_eim_package_to_isdr(str(package_path))

            self.assertEqual(report["package_type"], "euicc_memory_reset")
            self.assertEqual(report["transport"], "isdr_store_data")
            self.assertEqual(int(report["result_len"]), 3)
            reset_apdu = next(
                apdu
                for log_name, apdu in apdu_channel.send_calls
                if log_name == "EIM-LOCAL: eUICCMemoryReset"
            )
            expected_payload = session.build_wire_payload_preview(document)
            self.assertIn(expected_payload.hex().upper(), reset_apdu.hex().upper())
            response_rows = session.read_response_log(limit=10)
            self.assertTrue(any(str(row.get("action")) == "euicc_memory_reset" for row in response_rows))

    def test_isdr_get_eim_config_and_load_package_render_decoded_reporting(self) -> None:
        shell = EimLocalShell()
        decoded_response = build_eim_configuration_response_for_shell()
        shell.session = SimpleNamespace(
            get_eim_configuration_data=lambda: decoded_response,
            load_eim_package_to_isdr=lambda package_path="", cert_path="": {
                "package_path": package_path or "SCP11/eim_local/eim_packages/fake_eim_add_eim_package.json",
                "package_type": "add_eim",
                "result_len": 3,
                "response": bytes.fromhex("BF5800"),
                "execution_path": "add_eim_package_isdr",
                "transport": "local_auth",
                "response_preview_hex": "BF5800",
            },
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_isdr_get_eim_config()
            shell._cmd_load_eim_package("SCP11/eim_local/eim_packages/fake_eim_add_eim_package.json")

        rendered = output.getvalue()
        self.assertIn("ISDR GetEimConfigurationData", rendered)
        self.assertIn("eIM rows : 1", rendered)
        self.assertIn("yggdrasim.eim.test.1ot.com", rendered)
        self.assertIn("LOAD-EIM-PACKAGE completed", rendered)
        self.assertIn("transport : local_auth", rendered)
        self.assertEqual(
            shell._resolve_cached_poll_target_fqdns(),
            [DEFAULT_TEST_EIM_FQDN],
        )

    def test_discover_renders_shared_scp11_snapshot(self) -> None:
        shell = EimLocalShell()
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
                    wrap_tlv(b"\x80", b"smdpplus2.esim.tst.1ot.mobi"),
                ),
                "configured_decoded": {
                    "default_smdp": "smdpplus2.esim.tst.1ot.mobi",
                    "root_smds_primary": "",
                    "root_smds_additional": [],
                    "allowed_ci_pkid": [],
                },
                "euicc_info1": bytes.fromhex("BF2000"),
                "euicc_info2": bytes.fromhex("BF2200"),
                "rat": bytes.fromhex("BF4300"),
                "notifications": wrap_tlv(bytes.fromhex("BF2B"), b""),
                "eim_configuration": build_eim_configuration_response_for_shell(),
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
        self.assertIn(DEFAULT_TEST_EIM_FQDN, rendered)
        self.assertEqual(
            shell._resolve_cached_poll_target_fqdns(),
            [DEFAULT_TEST_EIM_FQDN],
        )

    def test_delete_eim_invalidates_cached_poll_target_fqdns(self) -> None:
        shell = EimLocalShell()
        shell._set_cached_poll_target_fqdns([DEFAULT_TEST_EIM_FQDN])
        shell.session = SimpleNamespace(
            delete_eim=lambda eim_id: bytes.fromhex("BF5900"),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            shell._cmd_delete_eim(DEFAULT_TEST_EIM_OID)

        self.assertEqual(shell._resolve_cached_poll_target_fqdns(), [])

    def test_aggregate_campaign_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_state_file = str(Path(temp_dir) / "state.json")
            reports_dir = Path(temp_dir) / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            (reports_dir / "eim_poll_campaign_20260319T000000Z.json").write_text(
                json.dumps(
                    {
                        "executed_cycles": 2,
                        "summary": {"issued_cycles": 1, "error_cycles": 0, "stop_reason": "queue_empty"},
                        "rows": [],
                    }
                ),
                encoding="utf-8",
            )
            (reports_dir / "eim_poll_campaign_20260319T000001Z.json").write_text(
                json.dumps(
                    {
                        "executed_cycles": 3,
                        "summary": {"issued_cycles": 2, "error_cycles": 1, "stop_reason": "max_cycles"},
                        "rows": [],
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(EIM_RUNTIME_STATE_FILE=runtime_state_file)
            session = EimLocalSession(cfg=config, apdu_channel=None)
            report = session.aggregate_campaign_reports(str(reports_dir))
            self.assertEqual(int(report.get("campaign_count", 0)), 2)
            self.assertEqual(int(report.get("total_cycles", 0)), 5)
            self.assertEqual(int(report.get("total_issued_cycles", 0)), 3)
            self.assertEqual(int(report.get("total_error_cycles", 0)), 1)
            stop_map = report.get("stop_reason_counts", {})
            self.assertEqual(int(stop_map.get("queue_empty", 0)), 1)
            self.assertEqual(int(stop_map.get("max_cycles", 0)), 1)

    def test_record_poll_audit_event_persists_sqlite_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            package_path = base_dir / "sample_package.json"
            package_path.write_text("{}", encoding="utf-8")
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_RESPONSE_LOG_FILE=str(base_dir / "responses.jsonl"),
                EIM_POLL_AUDIT_DB_FILE=str(base_dir / "poll_audit.sqlite3"),
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)

            session.record_poll_audit_event(
                action="localized_ipad_poll",
                package_path=str(package_path),
                package_type="profile_download_trigger_request",
                transaction_id_hex="AA01",
                matching_id="MID-1",
                success=True,
                result_len=2,
                response_preview_hex="BF4F",
                details={"execution_path": "indirect_profile_download"},
                flow="ipad_live",
                flow_run_id="RUN-1",
                eid="89049032000000000000000000000001",
            )

            rows = session.read_poll_audit_rows(limit=5)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["eid"], "89049032000000000000000000000001")
            self.assertEqual(row["flow"], "ipad_live")
            self.assertEqual(row["flow_run_id"], "RUN-1")
            self.assertEqual(row["package_type"], "profile_download_trigger_request")
            self.assertEqual(row["package_name"], "sample_package.json")
            self.assertTrue(bool(row["success"]))
            self.assertEqual(row["event"]["matching_id"], "MID-1")

    def test_localized_bridge_writes_served_and_result_audit_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            hotfolder_dir = base_dir / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            (hotfolder_dir / "010_trigger.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "transaction_id_hex": "0102030405060708090A0B0C0D0E0F10",
                            "matching_id": "MID-BRIDGE",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_RESPONSE_LOG_FILE=str(base_dir / "responses.jsonl"),
                EIM_POLL_AUDIT_DB_FILE=str(base_dir / "poll_audit.sqlite3"),
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_INCLUDE_FIXED_FIXTURES=False,
            )
            session = EimLocalSession(cfg=config, apdu_channel=None)
            bridge = LocalizedPollingBridge(session)
            bridge.set_flow_context(
                "ipad_live",
                flow_run_id="RUN-BRIDGE",
                eid="89049032000000000000000000000001",
            )

            bridge._installed_profile_iccids = set()
            bridge._installed_profile_iccids_loaded = True

            payload = bridge._serve_eim_package()
            self.assertGreater(len(payload), 0)
            bridge._acknowledge_eim_package_result(bytes.fromhex("BF5000"))

            rows = session.read_poll_audit_rows(limit=10, flow="ipad_live")
            actions = [str(row.get("action", "")) for row in rows]
            self.assertIn("localized_eim_package_served", actions)
            self.assertIn("localized_eim_package_result", actions)
            served_row = next(row for row in rows if str(row.get("action", "")) == "localized_eim_package_served")
            result_row = next(row for row in rows if str(row.get("action", "")) == "localized_eim_package_result")
            self.assertEqual(served_row["package_name"], "010_trigger.json")
            self.assertEqual(served_row["transaction_id_hex"], "0102030405060708090A0B0C0D0E0F10")
            self.assertEqual(served_row["matching_id"], "MID-BRIDGE")
            self.assertEqual(served_row["flow_run_id"], "RUN-BRIDGE")
            self.assertEqual(result_row["response_preview_hex"], "BF5000")

    def test_localized_bridge_initiate_authentication_decodes_base64_challenge(self) -> None:
        class _FakeServerSigned1:
            def dump(self) -> bytes:
                return b"signed1"

        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_RESPONSE_LOG_FILE=str(base_dir / "responses.jsonl"),
                EIM_POLL_AUDIT_DB_FILE=str(base_dir / "poll_audit.sqlite3"),
                EIM_POLL_INCLUDE_FIXED_FIXTURES=False,
            )
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            bridge = LocalizedPollingBridge(session)
            session._ensure_local_material_loaded = lambda: None
            session._cert_auth = b"cert"
            session._key_auth = object()
            expected_challenge = b"\xAA" * 16
            signed1 = _FakeServerSigned1()

            with mock.patch(
                "plugins.polling.wifi_ethernet_bridge.CryptoEngine.generate_server_challenges",
                return_value=(signed1, b"\x10" * 16, b"\x20" * 16),
            ) as mocked_generate, mock.patch(
                "plugins.polling.wifi_ethernet_bridge.CryptoEngine.sign_asn1",
                return_value=b"sig",
            ) as mocked_sign:
                response = bridge._handle_smdp_initiate_authentication(
                    {
                        "euiccChallenge": base64.b64encode(expected_challenge).decode("ascii"),
                        "smdpAddress": "yggdrasim.smdpp.test.1ot.com",
                    }
                )

            mocked_generate.assert_called_once_with(
                expected_challenge,
                "yggdrasim.smdpp.test.1ot.com",
            )
            mocked_sign.assert_called_once_with(signed1, session._key_auth)
            self.assertEqual(base64.b64decode(response["transactionId"]), b"\x10" * 16)
            self.assertEqual(base64.b64decode(response["serverSigned1"]), b"signed1")
            self.assertEqual(base64.b64decode(response["serverSignature1"]), b"sig")
            self.assertEqual(base64.b64decode(response["serverCertificate"]), b"cert")

    def test_localized_bridge_get_bound_profile_package_reports_profile_context_on_builder_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_RESPONSE_LOG_FILE=str(base_dir / "responses.jsonl"),
                EIM_POLL_AUDIT_DB_FILE=str(base_dir / "poll_audit.sqlite3"),
                EIM_POLL_INCLUDE_FIXED_FIXTURES=False,
            )
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            bridge = LocalizedPollingBridge(session)
            fake_builder = SimpleNamespace(
                state=SimpleNamespace(prepare_download_response=b"", transaction_id=b""),
                _read_profile_source_bytes=lambda profile_path="": bytes.fromhex("A00100"),
                resolve_profile_path=lambda override_path="": str(base_dir / "profile" / "test_profile.txt"),
            )

            def _raise_missing_pysim(profile_bytes: bytes) -> bytes:
                _ = profile_bytes
                raise RuntimeError("pySim session-bound BPP generation is unavailable in this environment.")

            fake_builder._build_session_bound_profile_package = _raise_missing_pysim
            bridge._build_offline_profile_builder_session = lambda: fake_builder  # type: ignore[assignment]

            with self.assertRaisesRegex(
                RuntimeError,
                "resolved profile source .* as profile_payload \\(3 bytes\\)",
            ) as raised:
                bridge._handle_smdp_get_bound_profile_package(
                    {
                        "transactionId": base64.b64encode(b"\x10" * 16).decode("ascii"),
                        "prepareDownloadResponse": base64.b64encode(b"\xBF\x21\x00").decode("ascii"),
                    }
                )

            self.assertIn(
                "pySim session-bound BPP generation is unavailable",
                str(raised.exception),
            )

    def test_localized_bridge_skips_duplicate_profile_trigger_after_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            hotfolder_dir = base_dir / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            eim_to_esim_dir, esim_to_eim_dir = create_poll_fixture_dirs(base_dir)
            profile_path = base_dir / "profile" / "duplicate_profile.txt"
            write_minimal_profile_payload(profile_path, "89460811111111111112")
            (eim_to_esim_dir / "010_first.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "queue_id": 10,
                            "transaction_id_hex": "10000000000000000000000000000001",
                            "matching_id": "FIRST",
                            "profile_path": str(profile_path),
                            "smdp_address": "yggdrasim.smdpp.test.1ot.com",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (hotfolder_dir / "110_second.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "queue_id": 110,
                            "transaction_id_hex": "11000000000000000000000000000001",
                            "matching_id": "SECOND",
                            "profile_path": str(profile_path),
                            "smdp_address": "yggdrasim.smdpp.test.1ot.com",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_RESPONSE_LOG_FILE=str(base_dir / "responses.jsonl"),
                EIM_POLL_AUDIT_DB_FILE=str(base_dir / "poll_audit.sqlite3"),
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_EIM_TO_ESIM_DIR=str(eim_to_esim_dir),
                EIM_POLL_ESIM_TO_EIM_DIR=str(esim_to_eim_dir),
            )
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            bridge = LocalizedPollingBridge(session)

            first_payload = bridge._serve_eim_package()
            first_parsed = parse_eim_package(first_payload)
            self.assertEqual(first_parsed.package_type, TYPE_PROFILE_DOWNLOAD_TRIGGER)
            self.assertEqual(first_parsed.matching_id, "FIRST")

            success_branch = session._build_profile_download_trigger_result_tlv(
                bytes.fromhex("BF3700"),
                eim_transaction_id=bytes(first_parsed.eim_transaction_id),
            )
            success_result = session._build_provide_eim_package_result_tlv(success_branch)
            next_payload = bridge._acknowledge_eim_package_result(success_result)

            self.assertEqual(next_payload, bytes.fromhex("BF4F03020101"))
            self.assertEqual(bridge.status_payload().get("queue_index"), 2)
            rows = session.read_poll_audit_rows(limit=10)
            actions = [str(row.get("action", "")) for row in rows]
            self.assertIn("localized_eim_package_skipped_duplicate_iccid", actions)

    def test_localized_bridge_keeps_duplicate_profile_trigger_after_failed_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            hotfolder_dir = base_dir / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            eim_to_esim_dir, esim_to_eim_dir = create_poll_fixture_dirs(base_dir)
            profile_path = base_dir / "profile" / "duplicate_profile.txt"
            write_minimal_profile_payload(profile_path, "89460811111111111112")
            (eim_to_esim_dir / "010_first.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "queue_id": 10,
                            "transaction_id_hex": "10000000000000000000000000000001",
                            "matching_id": "FIRST",
                            "profile_path": str(profile_path),
                            "smdp_address": "yggdrasim.smdpp.test.1ot.com",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (hotfolder_dir / "110_second.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "queue_id": 110,
                            "transaction_id_hex": "11000000000000000000000000000001",
                            "matching_id": "SECOND",
                            "profile_path": str(profile_path),
                            "smdp_address": "yggdrasim.smdpp.test.1ot.com",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_RESPONSE_LOG_FILE=str(base_dir / "responses.jsonl"),
                EIM_POLL_AUDIT_DB_FILE=str(base_dir / "poll_audit.sqlite3"),
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_EIM_TO_ESIM_DIR=str(eim_to_esim_dir),
                EIM_POLL_ESIM_TO_EIM_DIR=str(esim_to_eim_dir),
            )
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            bridge = LocalizedPollingBridge(session)

            first_payload = bridge._serve_eim_package()
            first_parsed = parse_eim_package(first_payload)
            self.assertEqual(first_parsed.matching_id, "FIRST")

            error_branch = session._build_profile_download_trigger_result_error(
                eim_transaction_id=bytes(first_parsed.eim_transaction_id),
                error_reason=127,
            )
            error_result = session._build_provide_eim_package_result_tlv(error_branch)
            next_payload = bridge._acknowledge_eim_package_result(error_result)
            next_parsed = parse_eim_package(next_payload)

            self.assertEqual(next_parsed.package_type, TYPE_PROFILE_DOWNLOAD_TRIGGER)
            self.assertEqual(next_parsed.matching_id, "SECOND")
            rows = session.read_poll_audit_rows(limit=10)
            actions = [str(row.get("action", "")) for row in rows]
            self.assertNotIn("localized_eim_package_skipped_duplicate_iccid", actions)

    def test_localized_bridge_skips_profile_trigger_when_iccid_is_already_installed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            hotfolder_dir = base_dir / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            eim_to_esim_dir, esim_to_eim_dir = create_poll_fixture_dirs(base_dir)
            profile_path = base_dir / "profile" / "duplicate_profile.txt"
            write_minimal_profile_payload(profile_path, "89460811111111111112")
            (eim_to_esim_dir / "010_first.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "queue_id": 10,
                            "transaction_id_hex": "10000000000000000000000000000001",
                            "matching_id": "FIRST",
                            "profile_path": str(profile_path),
                            "smdp_address": "yggdrasim.smdpp.test.1ot.com",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_RESPONSE_LOG_FILE=str(base_dir / "responses.jsonl"),
                EIM_POLL_AUDIT_DB_FILE=str(base_dir / "poll_audit.sqlite3"),
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_EIM_TO_ESIM_DIR=str(eim_to_esim_dir),
                EIM_POLL_ESIM_TO_EIM_DIR=str(esim_to_eim_dir),
            )
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            bridge = LocalizedPollingBridge(session)
            bridge.set_card_query_session(SimpleNamespace(collect_profile_metadata=lambda: [SimpleNamespace(iccid="89460811111111111112")]))

            payload = bridge._serve_eim_package()

            self.assertEqual(payload, bytes.fromhex("BF4F03020101"))
            rows = session.read_poll_audit_rows(limit=10)
            actions = [str(row.get("action", "")) for row in rows]
            self.assertIn("localized_eim_package_skipped_duplicate_iccid", actions)

    def test_localized_bridge_uses_builder_profile_source_for_duplicate_iccid_skip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            hotfolder_dir = base_dir / "hotfolder"
            hotfolder_dir.mkdir(parents=True, exist_ok=True)
            eim_to_esim_dir, esim_to_eim_dir = create_poll_fixture_dirs(base_dir)
            profile_path = base_dir / "profile" / "builder_profile.txt"
            write_minimal_profile_payload(profile_path, "89460811111111111112")
            (eim_to_esim_dir / "010_first.json").write_text(
                json.dumps(
                    {
                        "package_type": "profile_download_trigger_request",
                        "runtime": {
                            "queue_id": 10,
                            "transaction_id_hex": "10000000000000000000000000000001",
                            "matching_id": "FIRST",
                            "profile_path": "missing/profile/path.txt",
                            "smdp_address": "yggdrasim.smdpp.test.1ot.com",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = EimLocalConfig(
                EIM_RUNTIME_STATE_FILE=str(base_dir / "state.json"),
                EIM_RESPONSE_LOG_FILE=str(base_dir / "responses.jsonl"),
                EIM_POLL_AUDIT_DB_FILE=str(base_dir / "poll_audit.sqlite3"),
                EIM_HOTFOLDER_DIR=str(hotfolder_dir),
                EIM_POLL_EIM_TO_ESIM_DIR=str(eim_to_esim_dir),
                EIM_POLL_ESIM_TO_EIM_DIR=str(esim_to_eim_dir),
            )
            session = EimLocalSession(cfg=config, apdu_channel=SimpleNamespace())
            bridge = LocalizedPollingBridge(session)
            bridge.set_card_query_session(SimpleNamespace(collect_profile_metadata=lambda: [SimpleNamespace(iccid="89460811111111111112")]))
            profile_bytes = session._read_profile_source_bytes(profile_path=str(profile_path))
            bridge._build_offline_profile_builder_session = lambda: SimpleNamespace(  # type: ignore[assignment]
                _read_profile_source_bytes=lambda profile_path="": profile_bytes
            )

            payload = bridge._serve_eim_package()

            self.assertEqual(payload, bytes.fromhex("BF4F03020101"))
            rows = session.read_poll_audit_rows(limit=10)
            actions = [str(row.get("action", "")) for row in rows]
            self.assertIn("localized_eim_package_skipped_duplicate_iccid", actions)

    def test_parse_localized_ipae_args_supports_defaults_and_debug(self) -> None:
        defaults = EimLocalShell._parse_localized_ipae_args("")
        self.assertEqual(defaults, (1, 30, False))
        parsed = EimLocalShell._parse_localized_ipae_args("5 12 --debug")
        self.assertEqual(parsed, (5, 12, True))
        parsed_with_extended_flags = EimLocalShell._parse_localized_ipae_args(
            "7 18 -t 20s -s 5 --debug"
        )
        self.assertEqual(parsed_with_extended_flags, (7, 18, True))

    def test_parse_localized_ipad_args_supports_matching_id_and_debug(self) -> None:
        # Plugin-owned helper — import from the polling plugin package.
        from plugins.polling.shell_lifecycle import _parse_localized_ipad_args
        defaults = _parse_localized_ipad_args("")
        self.assertEqual(defaults, ("", False))
        parsed = _parse_localized_ipad_args("MATCH-1 --debug")
        self.assertEqual(parsed, ("MATCH-1", True))
        reversed_order = _parse_localized_ipad_args("--debug MATCH-2")
        self.assertEqual(reversed_order, ("MATCH-2", True))
        with self.assertRaisesRegex(ValueError, "at most one matchingId"):
            _parse_localized_ipad_args("MID-1 MID-2")

    def test_local_eim_debug_flag_strips_argument_and_toggles_raw_apdu_logging(self) -> None:
        class _FakeApduChannel:
            def __init__(self) -> None:
                self.raw_apdu_logging = False
                self.raw_logging_updates: list[bool] = []

            def set_raw_apdu_logging(self, enabled: bool) -> None:
                self.raw_apdu_logging = bool(enabled)
                self.raw_logging_updates.append(bool(enabled))

            def get_raw_apdu_logging(self) -> bool:
                return bool(self.raw_apdu_logging)

        shell = EimLocalShell()
        fake_channel = _FakeApduChannel()
        shell.session = SimpleNamespace(
            apdu_channel=fake_channel,
            state=SimpleNamespace(session_open=False),
        )
        captured_arguments: list[str] = []
        shell._commands["DISCOVER"] = lambda argument: captured_arguments.append(argument)

        keep_running = shell._execute_command_line("DISCOVER --debug")

        self.assertTrue(keep_running)
        self.assertEqual(captured_arguments, [""])
        self.assertEqual(fake_channel.raw_logging_updates, [True, False])

    def test_local_eim_global_debug_enables_transport_logging_on_startup(self) -> None:
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
        fake_session = SimpleNamespace(apdu_channel=fake_channel)

        with mock.patch.dict(os.environ, {"YGGDRASIM_GLOBAL_DEBUG": "1"}, clear=False):
            with mock.patch("SCP11.eim_local.main.EimLocalSession", return_value=fake_session):
                EimLocalShell()

        self.assertEqual(fake_channel.raw_logging_updates, [True])

    def test_local_eim_record_exports_replayable_commands_and_apdu_trace(self) -> None:
        shell = EimLocalShell()
        shell.session = SimpleNamespace(
            apdu_channel=SimpleNamespace(),
            state=SimpleNamespace(session_open=False),
        )
        shell._commands["DISCOVER"] = lambda argument: emit_apdu_trace_event(
            log_name="EIM-LOCAL: Test APDU",
            apdu=bytes.fromhex("80E2910003BF2000"),
            response=bytes.fromhex("BF2000"),
            sw1=0x90,
            sw2=0x00,
            transport="FakeApduChannel",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "eim_record.yaml"

            with contextlib.redirect_stdout(io.StringIO()):
                shell._execute_command_line(f"RECORD START {output_path}")
                shell._execute_command_line("DISCOVER")
                shell._execute_command_line("RECORD STOP")

            payload = yaml.safe_load(output_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["replay"]["commands"], ["DISCOVER"])
        self.assertEqual(payload["commands"][0]["canonical_command"], "DISCOVER")
        self.assertEqual(payload["commands"][0]["apdu_count"], 1)
        self.assertEqual(payload["apdu_trace"][0]["log_name"], "EIM-LOCAL: Test APDU")
        self.assertEqual(payload["apdu_trace"][0]["status_hex"], "9000")

    def test_local_eim_localized_ipad_keeps_debug_flag_for_internal_parser(self) -> None:
        class _FakeApduChannel:
            def set_raw_apdu_logging(self, enabled: bool) -> None:
                raise AssertionError("IPAD-LIVE should manage its own debug flag.")

            def get_raw_apdu_logging(self) -> bool:
                return False

        shell = EimLocalShell()
        shell.session = SimpleNamespace(
            apdu_channel=_FakeApduChannel(),
            state=SimpleNamespace(session_open=False),
        )
        captured_arguments: list[str] = []
        shell._commands["IPAD-LIVE"] = lambda argument: captured_arguments.append(argument)

        keep_running = shell._execute_command_line("IPAD-LIVE MATCH-1 --debug")

        self.assertTrue(keep_running)
        self.assertEqual(captured_arguments, ["MATCH-1 --debug"])

    def test_local_eim_localized_ipad_uses_global_debug_when_enabled(self) -> None:
        fake_session = SimpleNamespace(apdu_channel=SimpleNamespace())
        fake_runner = SimpleNamespace(run=mock.Mock())

        with mock.patch.dict(os.environ, {"YGGDRASIM_GLOBAL_DEBUG": "1"}, clear=False):
            with mock.patch("SCP11.eim_local.main.EimLocalSession", return_value=fake_session):
                shell = EimLocalShell()

        with mock.patch(
            "plugins.polling.ipad_standalone.LocalizedIPAdRunner",
            return_value=fake_runner,
        ):
            shell._run_localized_ipad("live", matching_id="MATCH-1")

        self.assertTrue(bool(fake_runner.run.call_args.kwargs["debug"]))

    def test_shell_registry_shows_canonical_commands_only(self) -> None:
        shell = EimLocalShell()
        self.assertNotIn("INFO", shell._commands)
        self.assertNotIn("POLL", shell._commands)
        self.assertNotIn("Q", shell._commands)
        self.assertEqual(shell._canonical_command("INFO"), "DISCOVER")
        self.assertEqual(shell._canonical_command("POLL-CAMPAIGN"), "POLL-CAMPAIGN")
        self.assertEqual(shell._canonical_command("Q"), "EXIT")

    def test_handover_status_yaml_output_is_parseable(self) -> None:
        shell = EimLocalShell()
        shell.session = SimpleNamespace(
            handover_context=lambda: {
                "transaction_id_hex": "01020304AABBCCDD",
                "matching_id": "MID-1",
                "profile_path": "/tmp/profile.der",
                "notification_policy": "strict",
                "source": "manual",
            },
            state=SimpleNamespace(session_open=False),
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_handover_status("--yaml")

        payload = yaml.safe_load(output.getvalue())
        self.assertEqual(payload["transaction_id_hex"], "01020304AABBCCDD")
        self.assertEqual(payload["matching_id"], "MID-1")

    def test_eim_package_explain_yaml_output_includes_runtime_hints_and_cert_selection(self) -> None:
        shell = EimLocalShell()
        shell.session = SimpleNamespace(
            resolve_eim_package_path=lambda override_path="": "/tmp/package.json",
            load_eim_package_document=lambda override_path="": {
                "package_type": "add_initial_eim",
                "package_version": "2.0.0",
                "command_tag_hex": "BF57",
                "runtime": {
                    "matching_id": "MID-1",
                    "transaction_id_hex": "0102",
                    "profile_path": "/tmp/profile.der",
                    "smdp_address": "rsp.example.com",
                    "bip_endpoint": "https://eim.local",
                    "cert_der_path": "/tmp/runtime-cert.der",
                },
                "sgp32": {
                    "add_initial_eim_request": {
                        "eim_configuration_data_list": [
                            {
                                "eim_id": {"include": True, "value": DEFAULT_TEST_EIM_OID},
                                "eim_public_key_data": {
                                    "include": True,
                                    "choice": "eim_certificate",
                                    "eim_certificate_der_path": "/tmp/eim-cert.der",
                                },
                            }
                        ]
                    }
                },
            },
            lint_eim_package=lambda package_path="", strict_executable=False: {
                "ok": True,
                "package_path": "/tmp/package.json",
                "package_type": "add_initial_eim",
                "package_version": "2.0.0",
                "additional_tlv_count": 1,
                "optional_tlv_count": 0,
                "spec_passed": 2,
                "spec_failed": 0,
                "spec_checks": [{"status": "PASS", "check": "BF57", "detail": "ok"}],
                "warnings": [],
                "errors": [],
            },
            preview_eim_signing_certificate=lambda package_path="": {
                "path": "/tmp/selected-cert.der",
                "private_key_path": "/tmp/selected-key.pem",
                "reason": "auto_select_ci_match",
                "root_ci_pkids": ["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"],
                "preferred_ci_pkids": ["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"],
            },
            identity_summary=lambda: {
                "eim_id": DEFAULT_TEST_EIM_OID,
                "eim_fqdn": DEFAULT_TEST_EIM_FQDN,
                "default_matching_id": "MID-DEFAULT",
                "eim_endpoint": "https://eim.local",
                "smdp_address": "rsp.example.com",
            },
            state=SimpleNamespace(session_open=False),
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_eim_package_explain("--yaml")

        payload = yaml.safe_load(output.getvalue())
        self.assertEqual(payload["package"]["type"], "add_initial_eim")
        self.assertEqual(payload["runtime_hints"]["matching_id"], "MID-1")
        self.assertEqual(
            payload["signing_certificate"]["path"],
            "/tmp/selected-cert.der",
        )
        self.assertEqual(payload["lint"]["spec_passed"], 2)

    def test_help_groups_localized_watchdog_and_queue_campaign_separately(self) -> None:
        fake_session = SimpleNamespace(apdu_channel=SimpleNamespace())
        with mock.patch("SCP11.eim_local.main.EimLocalSession", return_value=fake_session):
            shell = EimLocalShell()
        shell._terminal_width = lambda: 140  # type: ignore[method-assign]
        shell._plugin_localized_help_rows = [
            (
                "IPAE-LIVE [attempts] [timer-window] [-t 20s] [-s 5] [--debug]",
                "Localized IPAe STK/BIP watchdog via SCP11 live",
            )
        ]

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_help()

        rendered = output.getvalue()
        self.assertIn("Use HELP <command> for full usage", rendered)
        self.assertIn("Localized Routing & Handover", rendered)
        self.assertIn("Queue Campaigns", rendered)
        self.assertIn("IPAE-LIVE [attempts] [timer-window] [-t 20s] [-s 5] [--debug]", rendered)
        self.assertIn("POLL-CAMPAIGN [cycles] [intervalMs] [...]", rendered)
        self.assertIn("EIM-PACKAGE-EXPLAIN [path] [--yaml]", rendered)
        self.assertIn("REFRESH-MODEM [mode]", rendered)
        self.assertLess(rendered.index("Localized Routing & Handover"), rendered.index("IPAE-LIVE [attempts] [timer-window] [-t 20s] [-s 5] [--debug]"))
        self.assertLess(rendered.index("Queue Campaigns"), rendered.index("POLL-CAMPAIGN [cycles] [intervalMs] [...]"))
        self.assertTrue(
            any(
                "LOAD-PROFILE [path]" in line and "STORE-METADATA [path]" in line
                for line in rendered.splitlines()
            )
        )

    def test_canonical_template_inventory_is_clean(self) -> None:
        cfg = EimLocalConfig()
        templates_dir = Path(cfg.EIM_PACKAGE_TEMPLATES_DIR)
        self.assertTrue((templates_dir / "template_get_eim_package.json").exists())
        self.assertTrue((templates_dir / "template_provide_eim_package_result.json").exists())
        self.assertTrue((templates_dir / "template_euicc_memory_reset.json").exists())
        self.assertFalse((templates_dir / "template_ipad_discover.json").exists())
        self.assertFalse((templates_dir / "template_ipae_handover_download.json").exists())
        self.assertFalse((templates_dir / "template_euicc_memory_reset_eim_only.json").exists())
        self.assertFalse((templates_dir / "template_add_initial_eim_1ot_ref.json").exists())
        self.assertFalse((templates_dir / "template_add_initial_eim_yggdrasim_1ot_ref.json").exists())

    def test_seeded_fake_eim_peer_artifacts_are_aligned(self) -> None:
        cfg = EimLocalConfig()
        package_path = Path(cfg.EIM_PACKAGES_DIR) / "fake_eim_add_eim_package.json"
        peer_info_path = Path(cfg.EIM_PACKAGES_DIR) / "fake_eim_peer_addition_info.json"
        identity_path = Path(cfg.EIM_IDENTITY_FILE)

        self.assertTrue(package_path.exists())
        self.assertTrue(peer_info_path.exists())
        self.assertTrue(identity_path.exists())

        package_document = json.loads(package_path.read_text(encoding="utf-8"))
        peer_info = json.loads(peer_info_path.read_text(encoding="utf-8"))
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        row = (
            package_document["sgp32"]["add_eim_request"]["eim_configuration_data_list"][0]
        )

        self.assertEqual(row["eim_id"]["value"], identity["eim_id"])
        self.assertEqual(row["eim_fqdn"]["value"], identity["eim_fqdn"])
        self.assertEqual(
            package_document["runtime"]["matching_id"],
            identity["default_matching_id"],
        )
        self.assertEqual(
            row["euicc_ci_pk_id"]["value_hex"],
            identity["euicc_ci_pk_id"],
        )
        self.assertTrue(
            row["eim_public_key_data"]["eim_certificate_der_path"].endswith(".pem")
        )
        self.assertTrue(
            row["trusted_public_key_data_tls"]["trusted_certificate_der_path"].endswith(".pem")
        )
        self.assertEqual(
            peer_info["provisioning_artifacts"]["canonical_add_eim_package_path"],
            "SCP11/eim_local/eim_packages/fake_eim_add_eim_package.json",
        )

    def test_cmd_paths_renders_localized_bridge_summary(self) -> None:
        shell = EimLocalShell()
        shell.session = SimpleNamespace(
            identity_summary=lambda: {
                "eim_fqdn": "yggdrasim.eim.test.1ot.com",
                "smdp_address": "yggdrasim.smdpp.test.1ot.com",
            }
        )
        shell._bridge_status_payload = lambda: {
            "started": False,
            "bind_host": "127.0.0.1",
            "dns_port": 15353,
            "eim_base_url": "https://127.0.0.1:18443",
            "smdp_base_url": "https://127.0.0.1:19443",
            "smdp_fqdn": "yggdrasim.smdpp.test.1ot.com",
        }
        shell._plugin_path_sections = [
            {
                "title": "3. SIM IP Polling",
                "lines": [
                    "   live cmd  : IPAE-LIVE [matchingId] [--debug]",
                    "   test cmd  : IPAE-TEST [matchingId] [--debug]",
                    "   route     : SIM <-> bridge <-> eIM/SM-DP+",
                ],
            }
        ]

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._cmd_paths()

        rendered = output.getvalue()
        self.assertIn("Direct Auth", rendered)
        self.assertIn("IPAD-LIVE", rendered)
        self.assertIn("IPAE-LIVE", rendered)
        self.assertIn("SIM <-> IPAd <-> eIM/SM-DP+", rendered)
        self.assertIn("SIM <-> bridge <-> eIM/SM-DP+", rendered)
        self.assertIn("SIM IP Polling", rendered)
        self.assertIn("127.0.0.1:15353", rendered)
        self.assertIn("yggdrasim.eim.test.1ot.com", rendered)

    def test_localized_bridge_provider_disables_direct_eim_tls_public_key_pinning(self) -> None:
        shell = EimLocalShell()
        calls: list[bool] = []

        class FakeClient:
            def set_eim_tls_public_key_pinning_enabled(self, enabled: bool) -> None:
                calls.append(bool(enabled))

        provider = SimpleNamespace(_client=FakeClient())

        returned = shell._configure_localized_bridge_profile_provider(provider)

        self.assertIs(returned, provider)
        self.assertEqual(calls, [False])

    def test_run_localized_ipad_uses_bridge_and_orchestrator(self) -> None:
        shell = EimLocalShell()
        calls: dict[str, object] = {}

        class FakeBridge:
            eim_base_url = "https://127.0.0.1:18443"
            smdp_base_url = "https://127.0.0.1:19443"

            def set_flow_context(self, flow: str, flow_run_id: str = "", eid: str = "") -> None:
                calls["flow"] = flow
                calls["flow_run_id"] = flow_run_id
                calls["eid"] = eid

            def status_payload(self) -> dict[str, object]:
                return {
                    "queue_index": 1,
                    "pending_package_path": "fixtures/010_trigger.json",
                    "ack_count": 2,
                }

        class FakeOrchestrator:
            apdu_channel = SimpleNamespace()

            def run_eim_poll(self, matching_id: str = "") -> None:
                calls["matching_id"] = matching_id

        def ensure_bridge(reset_runtime: bool = True) -> FakeBridge:
            calls["reset_runtime"] = reset_runtime
            return FakeBridge()

        def load_orchestrator(profile_name: str) -> FakeOrchestrator:
            calls["profile_name"] = profile_name
            return FakeOrchestrator()

        shell._close_shell_session_if_open = lambda: calls.setdefault("closed_shell", True)
        shell.session._read_card_eid_safe = lambda: "89049032000000000000000000000001"
        shell.session.record_poll_audit_event = lambda **kwargs: calls.setdefault("poll_events", []).append(kwargs)
        shell._ensure_poll_bridge = ensure_bridge
        shell._load_network_orchestrator = load_orchestrator
        shell._close_network_runtime = lambda orchestrator: calls.setdefault("closed_runtime", True)

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._run_localized_ipad("live", matching_id="MATCH-1")

        rendered = output.getvalue()
        self.assertEqual(calls["profile_name"], "live")
        self.assertEqual(calls["matching_id"], "MATCH-1")
        self.assertEqual(calls["reset_runtime"], False)
        self.assertTrue(bool(calls["closed_runtime"]))
        self.assertEqual(calls["flow"], "ipad_live")
        self.assertEqual(calls["eid"], "89049032000000000000000000000001")
        self.assertEqual(len(calls["poll_events"]), 1)
        self.assertEqual(calls["poll_events"][0]["flow"], "ipad_live")
        self.assertIn("Active path: IPAd", rendered)
        self.assertIn("SIM <-> IPAd <-> eIM/SM-DP+", rendered)
        self.assertIn("Localized IPAd run completed", rendered)
        self.assertIn("ack_count", rendered)

    def test_run_localized_ipae_maps_attempts_to_watchdog(self) -> None:
        shell = EimLocalShell()
        calls: dict[str, object] = {}

        class FakeBridge:
            bind_host = "127.0.0.1"
            dns_port = 15353

            def set_flow_context(self, flow: str, flow_run_id: str = "", eid: str = "") -> None:
                calls["flow"] = flow
                calls["flow_run_id"] = flow_run_id
                calls["eid"] = eid

            def status_payload(self) -> dict[str, object]:
                return {
                    "ack_count": 0,
                    "active_transactions": 1,
                    "pending_package_path": "",
                }

        class FakeOrchestrator:
            apdu_channel = SimpleNamespace()

            def run_eim_status_watchdog(self, **kwargs) -> None:
                calls["watchdog_kwargs"] = kwargs

        def ensure_bridge(reset_runtime: bool = True) -> FakeBridge:
            calls["reset_runtime"] = reset_runtime
            return FakeBridge()

        def load_orchestrator(profile_name: str) -> FakeOrchestrator:
            calls["profile_name"] = profile_name
            orchestrator = FakeOrchestrator()
            calls["orchestrator"] = orchestrator
            return orchestrator

        shell._close_shell_session_if_open = lambda: calls.setdefault("closed_shell", True)
        shell.session._read_card_eid_safe = lambda: "89049032000000000000000000000002"
        shell.session.record_poll_audit_event = lambda **kwargs: calls.setdefault("poll_events", []).append(kwargs)
        shell._ensure_poll_bridge = ensure_bridge
        shell._load_network_orchestrator = load_orchestrator
        shell._close_network_runtime = lambda orchestrator: calls.setdefault("closed_runtime", True)
        shell._set_cached_poll_target_fqdns(["eim2.esim.tst.1ot.mobi"])

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._run_localized_ipae("test", argument="7 18 -t 20s -s 5 --debug")

        rendered = output.getvalue()
        watchdog_kwargs = calls["watchdog_kwargs"]
        self.assertEqual(calls["profile_name"], "test")
        self.assertEqual(calls["reset_runtime"], True)
        self.assertEqual(watchdog_kwargs["poll_attempts_per_fqdn"], 7)
        self.assertEqual(watchdog_kwargs["timer_expiration_window_seconds"], 18)
        self.assertTrue(bool(watchdog_kwargs["timer_window_explicit"]))
        self.assertEqual(watchdog_kwargs["poll_attempt_delay_seconds"], 20)
        self.assertEqual(watchdog_kwargs["poll_attempt_post_status_loops"], 5)
        self.assertTrue(bool(watchdog_kwargs["debug"]))
        self.assertEqual(watchdog_kwargs["duration_seconds"], 60)
        self.assertEqual(calls["flow"], "ipae_test")
        self.assertEqual(calls["eid"], "89049032000000000000000000000002")
        self.assertEqual(len(calls["poll_events"]), 1)
        self.assertEqual(calls["poll_events"][0]["flow"], "ipae_test")
        self.assertTrue(
            callable(
                getattr(
                    calls["orchestrator"],
                    "_resolve_cached_poll_target_fqdns",
                    None,
                )
            )
        )
        self.assertEqual(
            calls["orchestrator"]._resolve_cached_poll_target_fqdns(),
            ["eim2.esim.tst.1ot.mobi"],
        )
        self.assertIn("Active path: SIM IP", rendered)
        self.assertIn("SIM <-> bridge <-> eIM/SM-DP+", rendered)
        self.assertIn("Localized IPAe watchdog completed", rendered)

    def test_run_localized_ipae_auto_extends_timer_window_for_delayed_attempts(self) -> None:
        shell = EimLocalShell()
        calls: dict[str, object] = {}

        class FakeBridge:
            bind_host = "127.0.0.1"
            dns_port = 15353

            def set_flow_context(self, flow: str, flow_run_id: str = "", eid: str = "") -> None:
                calls["flow"] = flow
                calls["flow_run_id"] = flow_run_id
                calls["eid"] = eid

            def status_payload(self) -> dict[str, object]:
                return {
                    "ack_count": 0,
                    "active_transactions": 1,
                    "pending_package_path": "",
                }

        class FakeOrchestrator:
            apdu_channel = SimpleNamespace()

            def run_eim_status_watchdog(self, **kwargs) -> None:
                calls["watchdog_kwargs"] = kwargs

        def ensure_bridge(reset_runtime: bool = True) -> FakeBridge:
            calls["reset_runtime"] = reset_runtime
            return FakeBridge()

        def load_orchestrator(profile_name: str) -> FakeOrchestrator:
            calls["profile_name"] = profile_name
            return FakeOrchestrator()

        shell._close_shell_session_if_open = lambda: calls.setdefault("closed_shell", True)
        shell.session._read_card_eid_safe = lambda: "89049032000000000000000000000002"
        shell.session.record_poll_audit_event = lambda **kwargs: calls.setdefault("poll_events", []).append(kwargs)
        shell._ensure_poll_bridge = ensure_bridge
        shell._load_network_orchestrator = load_orchestrator
        shell._close_network_runtime = lambda orchestrator: calls.setdefault("closed_runtime", True)

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._run_localized_ipae("test", argument="3 -t 15 -s 60")

        rendered = output.getvalue()
        watchdog_kwargs = calls["watchdog_kwargs"]
        self.assertEqual(calls["profile_name"], "test")
        self.assertEqual(watchdog_kwargs["poll_attempts_per_fqdn"], 3)
        # Realistic per-attempt budget floor is 20s (covers DNS + TLS + eIM
        # POST + drain + CLOSE CHANNEL observed on production cards). Expected
        # floor: 3 attempts * 1 target * 20s + 60 post-status loops * 5s = 360.
        self.assertEqual(watchdog_kwargs["timer_expiration_window_seconds"], 360)
        self.assertEqual(watchdog_kwargs["poll_attempt_delay_seconds"], 15)
        self.assertEqual(watchdog_kwargs["poll_attempt_post_status_loops"], 60)
        self.assertFalse(bool(watchdog_kwargs["debug"]))
        self.assertIn("timer expiration stimuli window: 360s (auto)", rendered)
        self.assertIn("auto-extended to 360s", rendered)


class PollCampaignSummaryFormattingTests(unittest.TestCase):
    """Lock the compact text-mode rendering of the POLL-CAMPAIGN summary.

    The renderer is a pure function over the campaign ``rows`` list, so
    the tests construct an :class:`EimLocalShell` and drive
    ``_print_poll_campaign_rows`` directly without touching the
    session / card layer.
    """

    def _render(self, rows):
        shell = EimLocalShell()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            shell._print_poll_campaign_rows(rows)
        return buffer.getvalue()

    def test_factors_common_base_path_once_and_prints_relative_suffixes(self):
        rows = [
            {
                "cycle": 1,
                "issued": True,
                "issued_type": "profile_download_trigger_request",
                "issued_result_len": 47,
                "issued_file": "/ws/LocalEIM/eim_packages/fixtures/eim_to_esim/010_trigger.json",
            },
            {
                "cycle": 2,
                "issued": True,
                "issued_type": "provide_eim_package_result",
                "issued_result_len": 24,
                "issued_file": "/ws/LocalEIM/eim_packages/fixtures/esim_to_eim/020_result.json",
            },
            {
                "cycle": 3,
                "issued": True,
                "issued_type": "eim_acknowledgements",
                "issued_result_len": 0,
                "issued_file": "/ws/LocalEIM/eim_packages/hotfolder/030_ack.json",
            },
        ]

        rendered = self._render(rows)

        # Base line printed once, workspace prefix does not repeat.
        self.assertIn("[*] Base: /ws/LocalEIM/eim_packages", rendered)
        self.assertEqual(rendered.count("/ws/LocalEIM/eim_packages"), 1)
        # Suffixes shown as relative paths.
        self.assertIn("fixtures/eim_to_esim/010_trigger.json", rendered)
        self.assertIn("fixtures/esim_to_eim/020_result.json", rendered)
        self.assertIn("hotfolder/030_ack.json", rendered)

    def test_applies_short_type_codes_for_known_package_types(self):
        rows = [
            {
                "cycle": 1,
                "issued": True,
                "issued_type": "profile_download_trigger_request",
                "issued_result_len": 47,
                "issued_file": "/base/a.json",
            },
            {
                "cycle": 2,
                "issued": True,
                "issued_type": "provide_eim_package_result",
                "issued_result_len": 24,
                "issued_file": "/base/b.json",
            },
            {
                "cycle": 3,
                "issued": True,
                "issued_type": "eim_acknowledgements",
                "issued_result_len": 0,
                "issued_file": "/base/c.json",
            },
        ]

        rendered = self._render(rows)

        self.assertIn("trigger_req", rendered)
        self.assertIn("eim_result", rendered)
        self.assertIn("ack", rendered)
        # Long canonical names must not leak into the tabular cells.
        self.assertNotIn("profile_download_trigger_request", rendered)
        self.assertNotIn("provide_eim_package_result", rendered)
        self.assertNotIn("eim_acknowledgements", rendered)

    def test_unknown_type_is_passed_through_verbatim(self):
        rows = [
            {
                "cycle": 1,
                "issued": True,
                "issued_type": "some_future_type",
                "issued_result_len": 7,
                "issued_file": "/base/x.json",
            }
        ]

        rendered = self._render(rows)

        self.assertIn("some_future_type", rendered)

    def test_no_package_and_error_rows_use_compact_layout(self):
        rows = [
            {
                "cycle": 1,
                "issued": False,
                "eim_result_code": 1,
                "eim_result_name": "noEimPackageAvailable",
                "issued_file": "",
            },
            {
                "cycle": 2,
                "issued": True,
                "issued_type": "profile_download_trigger_request",
                "issued_result_len": 47,
                "issued_file": "/base/a.json",
                "error": "NetworkError: unreachable",
            },
        ]

        rendered = self._render(rows)

        self.assertIn("no-package", rendered)
        self.assertIn("result=1 (noEimPackageAvailable)", rendered)
        self.assertIn("[error] NetworkError: unreachable", rendered)

    def test_no_cycle_rows_emits_nothing(self):
        rendered = self._render([])
        self.assertEqual(rendered, "")

    def test_type_code_helper_maps_known_and_passes_unknown(self):
        shell = EimLocalShell()
        self.assertEqual(
            shell._compact_poll_campaign_type("profile_download_trigger_request"),
            "trigger_req",
        )
        self.assertEqual(
            shell._compact_poll_campaign_type("provide_eim_package_result"),
            "eim_result",
        )
        self.assertEqual(shell._compact_poll_campaign_type("eim_acknowledgements"), "ack")
        self.assertEqual(shell._compact_poll_campaign_type(""), "-")
        self.assertEqual(shell._compact_poll_campaign_type("custom_thing"), "custom_thing")

    def test_common_base_helper_handles_single_row_and_missing_paths(self):
        shell = EimLocalShell()
        self.assertEqual(
            shell._poll_campaign_common_base(
                [{"issued_file": "/tmp/run/one/a.json"}]
            ),
            "/tmp/run/one",
        )
        self.assertEqual(shell._poll_campaign_common_base([]), "")
        self.assertEqual(
            shell._poll_campaign_common_base([{"issued_file": ""}, {"issued_file": None}]),
            "",
        )


if __name__ == "__main__":
    unittest.main()
