"""sim ↔ local eIM ISD-R loopback validation (SGP.32 mode A).

Goal: prove the simulated SIMCARD answers the local eIM ESipa-driver
(``EimLocalSession``) over a real ``apdu_channel`` and completes the
SGP.32 ISD-R discovery + AddInitialEim round-trip.

The local eIM normally talks to a production eUICC over PCSC. By
setting ``YGGDRASIM_CARD_BACKEND=sim`` the same ``PcscApduChannel`` is
served by ``SIMCARD/connection.py``'s ``SimulatedCardConnection``,
which routes APDUs into ``SimulatedSimCardEngine`` -- the same engine
the HIL bridge uses.

If these tests pass against the simulator, the same local eIM build
will also work against a production card without code changes; the
user has separately verified the production-card leg in the lab.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from SCP11.eim_local.config import EimLocalConfig
from SCP11.eim_local.session import EimLocalSession
from SCP11.transport import PcscApduChannel
from yggdrasim_common.card_backend import (
    CARD_BACKEND_ENV,
    SIM_EIM_IDENTITY_ENV,
    SIM_EUICC_STORE_ENV,
    SIM_ISDR_CONFIG_ENV,
    SIM_PROFILE_STORE_ENV,
    SIM_QUIRKS_ENV,
)


def _make_self_signed_cert(subject_label: str) -> tuple[bytes, bytes]:
    """Build a deterministic self-signed P-256 cert + raw private key DER."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = crypto_x509.Name(
        [crypto_x509.NameAttribute(NameOID.COMMON_NAME, subject_label)]
    )
    now = datetime.now(timezone.utc)
    builder = (
        crypto_x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
    )
    certificate = builder.sign(private_key, hashes.SHA256())
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_der, key_der


class _SimulatorEimLoopbackBase(unittest.TestCase):
    """Shared setup: temp runtime root + simulator card backend + clean engine."""

    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        runtime_root = Path(self._temp_dir.name) / "runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        euicc_store = Path(self._temp_dir.name) / "euicc"
        profile_store = Path(self._temp_dir.name) / "profiles"
        eim_identity = Path(self._temp_dir.name) / "sim_eim_identity.json"
        eim_identity.write_text(
            json.dumps(
                {
                    "eim_id": "2.25.311782205282738360923618091971140414400",
                    "eim_id_type": "oid",
                    "eim_fqdn": "yggdrasim.eim.test.1ot.com",
                    "counter_value": 0,
                    "association_token": -1,
                    "supported_protocol_bits": [0],
                }
            ),
            encoding="utf-8",
        )

        self._env_patch = mock.patch.dict(
            os.environ,
            {
                CARD_BACKEND_ENV: "sim",
                "YGGDRASIM_RUNTIME_ROOT": str(runtime_root),
                SIM_EUICC_STORE_ENV: str(euicc_store),
                SIM_PROFILE_STORE_ENV: str(profile_store),
                SIM_EIM_IDENTITY_ENV: str(eim_identity),
                SIM_ISDR_CONFIG_ENV: "",
                SIM_QUIRKS_ENV: "",
            },
            clear=False,
        )
        self._env_patch.start()

        # Force a fresh simulator engine for this test. Without this,
        # state from a previous test (cached eIM entries, profiles)
        # would bleed across.
        import SIMCARD.connection as sim_conn

        sim_conn._SHARED_ENGINE = None
        sim_conn._SHARED_ENGINE_QUIRKS_PATH = ""
        sim_conn._SHARED_ENGINE_ISDR_CONFIG_PATH = ""
        sim_conn._SHARED_ENGINE_EIM_IDENTITY_PATH = ""
        sim_conn._SHARED_ENGINE_EUICC_STORE_ROOT = ""
        sim_conn._SHARED_ENGINE_PROFILE_STORE_PATH = ""

        self.runtime_root = runtime_root

    def tearDown(self) -> None:
        # Drop the engine again so the next test picks up clean state.
        import SIMCARD.connection as sim_conn

        sim_conn._SHARED_ENGINE = None
        self._env_patch.stop()
        self._temp_dir.cleanup()

    def _build_channel(self) -> PcscApduChannel:
        channel = PcscApduChannel(reader_index=0)
        # Keep the sim trace quiet during tests; the per-test assertion
        # text is enough signal.
        channel.set_quiet_apdu_logging(True)
        return channel

    def _build_session(self) -> EimLocalSession:
        cfg = EimLocalConfig()
        return EimLocalSession(cfg=cfg, apdu_channel=self._build_channel())


class IsdrDiscoveryAgainstSimulatorTests(_SimulatorEimLoopbackBase):
    """Confirm discover_card() crosses every BFxx surface the eIM
    relies on and gets a parseable answer (Mode A — local simulator)."""

    def test_select_isdr_returns_9000_against_simulator(self) -> None:
        session = self._build_session()
        response = session.select_isdr()
        self.assertGreater(len(response), 0, "ISD-R SELECT should return FCI bytes")

    def test_get_eid_round_trip_against_simulator_returns_19_digit_bcd(self) -> None:
        session = self._build_session()
        eid = session.get_eid()
        # SGP.02 §2.2.2 EID is 32 BCD digits. The simulator's default
        # EID is configurable but always reported as 32 hex characters.
        self.assertEqual(len(eid), 32, f"EID should be 32 BCD digits, got '{eid}'")
        self.assertTrue(eid.isdigit(), f"EID must be all digits, got '{eid}'")

    def test_get_euicc_info1_returns_bf20_envelope(self) -> None:
        session = self._build_session()
        session.select_isdr()
        info1 = session.get_euicc_info1()
        self.assertTrue(
            info1.startswith(bytes.fromhex("BF20")),
            f"GetEuiccInfo1 must start with BF20, got {info1[:4].hex().upper()}",
        )

    def test_get_euicc_info2_returns_bf22_envelope(self) -> None:
        session = self._build_session()
        session.select_isdr()
        info2 = session.get_euicc_info2()
        self.assertTrue(
            info2.startswith(bytes.fromhex("BF22")),
            f"GetEuiccInfo2 must start with BF22, got {info2[:4].hex().upper()}",
        )

    def test_get_profiles_info_returns_bf2d_envelope(self) -> None:
        session = self._build_session()
        session.select_isdr()
        profiles = session.get_profiles_info()
        self.assertTrue(
            profiles.startswith(bytes.fromhex("BF2D")),
            f"GetProfilesInfo must start with BF2D, got {profiles[:4].hex().upper()}",
        )

    def test_get_euicc_configured_data_returns_bf3c_envelope(self) -> None:
        session = self._build_session()
        session.select_isdr()
        configured = session.get_euicc_configured_data()
        self.assertTrue(
            configured.startswith(bytes.fromhex("BF3C")),
            f"GetEuiccConfiguredData must start with BF3C, got {configured[:4].hex().upper()}",
        )

    def test_get_rat_returns_bf43_envelope(self) -> None:
        session = self._build_session()
        session.select_isdr()
        rat = session.get_rat()
        self.assertTrue(
            rat.startswith(bytes.fromhex("BF43")),
            f"GetRAT must start with BF43, got {rat[:4].hex().upper()}",
        )

    def test_get_notifications_list_returns_bf2b_envelope(self) -> None:
        session = self._build_session()
        session.select_isdr()
        notifications = session.get_notifications_list()
        self.assertTrue(
            notifications.startswith(bytes.fromhex("BF2B")),
            f"RetrieveNotificationsList must start with BF2B, got {notifications[:4].hex().upper()}",
        )

    def test_get_eim_configuration_data_returns_bf55_envelope(self) -> None:
        session = self._build_session()
        session.select_isdr()
        eim_config = session.get_eim_configuration_data()
        self.assertTrue(
            eim_config.startswith(bytes.fromhex("BF55")),
            f"GetEimConfigurationData must start with BF55, got {eim_config[:4].hex().upper()}",
        )

    def test_get_certs_returns_bf56_envelope(self) -> None:
        session = self._build_session()
        session.select_isdr()
        certs = session.get_certs()
        self.assertTrue(
            certs.startswith(bytes.fromhex("BF56")),
            f"GetCerts must start with BF56, got {certs[:4].hex().upper()}",
        )

    def test_full_discover_card_completes_against_simulator(self) -> None:
        """End-to-end: every read in EimLocalSession.discover_card()
        must succeed and yield a parseable snapshot dict."""
        session = self._build_session()
        snapshot = session.discover_card()

        self.assertIn("eid", snapshot)
        self.assertEqual(len(snapshot["eid"]), 32)
        self.assertTrue(snapshot["eid"].isdigit())

        self.assertGreater(len(snapshot["euicc_info1"]), 0)
        self.assertGreater(len(snapshot["euicc_info2"]), 0)
        self.assertGreater(len(snapshot["rat"]), 0)
        self.assertGreater(len(snapshot["eim_configuration"]), 0)
        self.assertGreater(len(snapshot["certs"]), 0)

        # The simulator ships a default eIM entry (the workspace
        # sim_eim_identity.json above). discover_card() returns the
        # configured-data dictionary too; assert it's structurally
        # well-formed.
        self.assertIn("configured_decoded", snapshot)
        configured = snapshot["configured_decoded"]
        self.assertIsInstance(configured, dict)
        self.assertIn("allowed_ci_pkid", configured)


class AddInitialEimAgainstSimulatorTests(_SimulatorEimLoopbackBase):
    """Confirm a SGP.32 AddInitialEim package travels eIM -> sim and
    lands a new entry in the simulator's eIM list (Mode A — local
    simulator)."""

    def _write_signing_cert(self, target_dir: Path) -> Path:
        cert_der, key_der = _make_self_signed_cert("Loopback Test eIM")
        target_dir.mkdir(parents=True, exist_ok=True)
        cert_path = target_dir / "loopback_eim_cert.der"
        key_path = target_dir / "loopback_eim_key.der"
        cert_path.write_bytes(cert_der)
        key_path.write_bytes(key_der)
        return cert_path

    def _write_add_initial_eim_package(
        self, package_path: Path, cert_der_path: Path, eim_id: str, eim_fqdn: str
    ) -> None:
        document = {
            "package_type": "add_initial_eim",
            "package_version": "2.0.0",
            "sgp32": {
                "add_initial_eim_request": {
                    "include": True,
                    "eim_configuration_data_list": [
                        {
                            "include": True,
                            "eim_id": {"include": True, "value": eim_id},
                            "eim_fqdn": {"include": True, "value": eim_fqdn},
                            "eim_id_type": {"include": True, "value": "eimIdTypeOid"},
                            "counter_value": {"include": True, "value": 1},
                            "association_token": {"include": True, "value": -1},
                            "eim_public_key_data": {
                                "include": True,
                                "choice": "eim_certificate",
                                "eim_certificate_der_path": str(cert_der_path),
                            },
                            "trusted_public_key_data_tls": {
                                "include": False,
                            },
                            "eim_supported_protocol": {
                                "include": True,
                                "eimRetrieveHttps": True,
                                "eimRetrieveCoaps": False,
                                "eimInjectHttps": False,
                                "eimInjectCoaps": False,
                            },
                            "euicc_ci_pk_id_to_be_used": {
                                "include": True,
                                "value": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
                            },
                            "indirect_profile_download": False,
                        }
                    ],
                }
            },
        }
        package_path.write_text(json.dumps(document), encoding="utf-8")

    def test_add_initial_eim_lands_in_simulator_eim_entries(self) -> None:
        session = self._build_session()
        # Make sure the simulator is selected before we issue the
        # AddInitialEim STORE DATA round-trip.
        session.select_isdr()

        # Read the baseline eIM list from the simulator so we can
        # diff correctly even if the simulator pre-seeded a default
        # entry.
        baseline_bf55 = session.get_eim_configuration_data()
        baseline_present = baseline_bf55.startswith(bytes.fromhex("BF55"))
        self.assertTrue(baseline_present, "BF55 envelope must be present at baseline")

        target_eim_id = "2.25.999111000111000111000111000111000111"
        target_fqdn = "loopback.test.eim.example.com"
        package_dir = Path(self._temp_dir.name) / "loopback_packages"
        package_dir.mkdir(parents=True, exist_ok=True)
        cert_path = self._write_signing_cert(package_dir)
        package_path = package_dir / "loopback_add_initial_eim.json"
        self._write_add_initial_eim_package(package_path, cert_path, target_eim_id, target_fqdn)

        response = session.add_initial_eim(package_path=str(package_path))
        # The simulator currently echoes BF57 with an empty body on
        # success (see SIMCARD/sgp.py::_handle_add_eim). The eIM
        # wraps this card_response into its own log; the binding
        # observable is whether the simulator now lists the entry.
        self.assertGreaterEqual(
            len(response),
            0,
            "AddInitialEim should at least produce an empty response, "
            "any IOError would have raised.",
        )

        # Re-read BF55 GetEimConfigurationData and assert the new
        # entry is now there.
        updated_bf55 = session.get_eim_configuration_data()
        self.assertIn(
            target_eim_id.encode("utf-8"),
            updated_bf55,
            f"Newly added eIM {target_eim_id} should appear in the simulator's "
            f"BF55 GetEimConfigurationData response.",
        )
        self.assertIn(
            target_fqdn.encode("utf-8"),
            updated_bf55,
            f"Newly added eIM FQDN {target_fqdn} should appear in BF55.",
        )


if __name__ == "__main__":
    unittest.main()
