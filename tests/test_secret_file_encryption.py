from __future__ import annotations

import base64
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.eim_local.eim_cert_store import EimCertificateStore
from SCP11.local_access.cert_store import LocalSgp26CertStore
from SIMCARD.euicc_store import load_euicc_store_into_state, sync_euicc_store
from SIMCARD.profile_store import load_profiles_from_store, sync_profiles_to_store
from SIMCARD.state import DEFAULT_SIM_ATR, SimCardState, SimProfileAuthConfig, SimProfileEntry, SimProfileFsNode, SimProfileImage
from yggdrasim_common.inventory_crypto import (
    read_secret_file_bytes,
    read_secret_json_file,
    write_secret_file_bytes,
    write_secret_json_file,
)


class _FakeFileCryptoManager:
    HEADER = b"-----BEGIN PGP MESSAGE-----"

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    @staticmethod
    def write_encryption_enabled() -> bool:
        return True

    @classmethod
    def is_encrypted_file_bytes(cls, payload: object) -> bool:
        if isinstance(payload, str):
            raw_bytes = payload.encode("utf-8")
        else:
            raw_bytes = bytes(payload)
        return raw_bytes.lstrip().startswith(cls.HEADER)

    @classmethod
    def encrypt_bytes(cls, plaintext: bytes) -> bytes:
        return (
            cls.HEADER
            + b"\n"
            + base64.b64encode(bytes(plaintext))
            + b"\n-----END PGP MESSAGE-----\n"
        )

    @classmethod
    def decrypt_bytes(cls, ciphertext: bytes | str) -> bytes:
        if isinstance(ciphertext, str):
            raw_bytes = ciphertext.encode("utf-8")
        else:
            raw_bytes = bytes(ciphertext)
        encoded_lines = [
            line.strip()
            for line in raw_bytes.splitlines()
            if len(line.strip()) > 0 and line.startswith(b"-----") is False
        ]
        return base64.b64decode(b"".join(encoded_lines))


def _build_self_signed_cert_and_key(common_name: str = "secret-file-test") -> tuple[bytes, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        crypto_x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_der, key_pem


class SecretFileEncryptionTests(unittest.TestCase):
    def test_secret_file_helpers_round_trip_and_migrate_plaintext_on_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            binary_path = temp_path / "secret.der"
            json_path = temp_path / "secret.json"
            plaintext_path = temp_path / "plain.pem"

            write_secret_file_bytes(binary_path, b"\x30\x82\x01\x0A", crypto_manager=_FakeFileCryptoManager())
            write_secret_json_file(json_path, {"secret": True}, crypto_manager=_FakeFileCryptoManager())
            plaintext_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nTEST\n")

            migrated = read_secret_file_bytes(
                plaintext_path,
                crypto_manager=_FakeFileCryptoManager(),
                protect_plaintext_on_read=True,
            )

            self.assertEqual(migrated, b"-----BEGIN PRIVATE KEY-----\nTEST\n")
            self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(binary_path.read_bytes()))
            self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(json_path.read_bytes()))
            self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(plaintext_path.read_bytes()))
            self.assertEqual(
                read_secret_file_bytes(binary_path, crypto_manager=_FakeFileCryptoManager()),
                b"\x30\x82\x01\x0A",
            )
            self.assertEqual(
                read_secret_json_file(json_path, crypto_manager=_FakeFileCryptoManager()),
                {"secret": True},
            )

    def test_profile_store_encrypts_sensitive_files_and_loads_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "profiles"
            profile = SimProfileEntry(
                aid="A0000005591010FFFFFFFF8900001100",
                iccid="89460811111111111112",
                profile_name="Encrypted Test",
                imsi="001010123456789",
                impi="user@example.test",
                profile_image=SimProfileImage(
                    profile_name="Encrypted Test",
                    iccid="89460811111111111112",
                    imsi="001010123456789",
                    impi="user@example.test",
                    nodes=[
                        SimProfileFsNode(
                            path=("MF", "EF.IMSI"),
                            name="EF.IMSI",
                            kind="ef",
                            fid="6F07",
                            data=bytes.fromhex("08091010123456789F"),
                        )
                    ],
                ),
                auth_config=SimProfileAuthConfig(
                    algorithm="milenage",
                    ki=bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
                    opc=bytes.fromhex("FFEEDDCCBBAA99887766554433221100"),
                ),
            )

            with mock.patch(
                "yggdrasim_common.inventory_crypto.InventoryCryptoManager",
                _FakeFileCryptoManager,
            ):
                sync_profiles_to_store(str(store_path), [profile])
                profile_dir = next(path for path in store_path.iterdir() if path.is_dir())
                manifest_path = profile_dir / "manifest.json"
                image_path = profile_dir / "profile_image.json"

                self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(manifest_path.read_bytes()))
                self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(image_path.read_bytes()))

                loaded = load_profiles_from_store(str(store_path))

            self.assertEqual(len(loaded), 1)
            self.assertIsNotNone(loaded[0].auth_config)
            assert loaded[0].auth_config is not None
            self.assertEqual(bytes(loaded[0].auth_config.ki).hex().upper(), "00112233445566778899AABBCCDDEEFF")
            self.assertEqual(bytes(loaded[0].auth_config.opc).hex().upper(), "FFEEDDCCBBAA99887766554433221100")
            self.assertEqual(loaded[0].imsi, "001010123456789")
            self.assertEqual(loaded[0].impi, "user@example.test")

    def test_euicc_store_encrypts_manifest_and_loads_scp_key_material_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "euicc"
            state = SimCardState(
                atr=DEFAULT_SIM_ATR,
                eid="89049032000000000000000000000001",
                iccid="89460811111111111112",
                imsi="001010123456789",
                default_dp_address="smdpplus.example.test",
                root_ci_pkid=bytes.fromhex("00112233445566778899AABBCCDDEEFF00112233"),
                euicc_store_path=str(store_path),
            )
            state.scp03_keys.kenc = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
            state.scp03_keys.kmac = bytes.fromhex("1112131415161718191A1B1C1D1E1F20")
            state.scp03_keys.dek = bytes.fromhex("2122232425262728292A2B2C2D2E2F30")
            state.scp03_keys.kvn = 0x31
            state.scp80_security.key_enc = bytes.fromhex("3132333435363738")
            state.scp80_security.key_mac = bytes.fromhex("4142434445464748")
            state.scp80_security.spi = "1621"
            state.scp80_security.kic = "15"
            state.scp80_security.kid = "15"

            reloaded_state = SimCardState(
                atr=b"",
                eid="",
                iccid="",
                imsi="",
                default_dp_address="",
                root_ci_pkid=b"",
            )

            with mock.patch(
                "yggdrasim_common.inventory_crypto.InventoryCryptoManager",
                _FakeFileCryptoManager,
            ):
                sync_euicc_store(state)
                manifest_path = store_path / "euicc.json"
                self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(manifest_path.read_bytes()))

                loaded = load_euicc_store_into_state(str(store_path), reloaded_state)

            self.assertTrue(loaded)
            self.assertEqual(reloaded_state.root_ci_pkid.hex().upper(), "00112233445566778899AABBCCDDEEFF00112233")
            self.assertEqual(reloaded_state.scp03_keys.kvn, 0x31)
            self.assertEqual(reloaded_state.scp03_keys.kenc.hex().upper(), "0102030405060708090A0B0C0D0E0F10")
            self.assertEqual(reloaded_state.scp03_keys.kmac.hex().upper(), "1112131415161718191A1B1C1D1E1F20")
            self.assertEqual(reloaded_state.scp03_keys.dek.hex().upper(), "2122232425262728292A2B2C2D2E2F30")
            self.assertEqual(reloaded_state.scp80_security.key_enc.hex().upper(), "3132333435363738")
            self.assertEqual(reloaded_state.scp80_security.key_mac.hex().upper(), "4142434445464748")

    def test_local_cert_store_encrypts_override_material_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            certs_dir = Path(temp_dir)
            cert_der, key_pem = _build_self_signed_cert_and_key("local-smdp")
            cert_path = certs_dir / "operator-alpha-auth.der"
            key_path = certs_dir / "operator-alpha-auth.key.pem"
            metadata_path = certs_dir / "operator-alpha-auth.meta.json"
            cert_path.write_bytes(cert_der)
            key_path.write_bytes(key_pem)
            metadata_path.write_text(
                json.dumps(
                    {
                        "role": "auth",
                        "private_key_path": key_path.name,
                        "root_ci_pkid": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch(
                "yggdrasim_common.inventory_crypto.InventoryCryptoManager",
                _FakeFileCryptoManager,
            ):
                store = LocalSgp26CertStore(
                    valid_cert_root="",
                    override_cert_root=str(certs_dir),
                )
                records = store.auth_records()

            self.assertEqual(len(records), 1)
            self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(cert_path.read_bytes()))
            self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(key_path.read_bytes()))
            self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(metadata_path.read_bytes()))

    def test_eim_cert_store_encrypts_local_material_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            certs_dir = Path(temp_dir)
            cert_der, key_pem = _build_self_signed_cert_and_key("local-eim")
            cert_path = certs_dir / "CERT_S_EIMsign_MATCH.der"
            key_path = certs_dir / "SK_S_EIMsign_MATCH.pem"
            cert_path.write_bytes(cert_der)
            key_path.write_bytes(key_pem)

            with mock.patch(
                "yggdrasim_common.inventory_crypto.InventoryCryptoManager",
                _FakeFileCryptoManager,
            ):
                store = EimCertificateStore(
                    local_cert_root=str(certs_dir),
                    sgp26_valid_cert_root=str(certs_dir / "sgp26-empty"),
                )
                records = store.signing_records()

            self.assertEqual(len(records), 1)
            self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(cert_path.read_bytes()))
            self.assertTrue(_FakeFileCryptoManager.is_encrypted_file_bytes(key_path.read_bytes()))


if __name__ == "__main__":
    unittest.main()
