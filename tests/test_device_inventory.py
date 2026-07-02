# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from yggdrasim_common.device_inventory import DeviceInventoryStore
from yggdrasim_common.inventory_crypto import InventoryCryptoManager
from SCP11.eim_local.runtime_state import EimRuntimeStateStore
from SCP11.local_access.config import LocalAccessConfig
from SCP11.local_access.session import LocalIsdrSession
from SCP11.shared.device_inventory_support import EidInventoryNamespace


class _DummyApduChannel:
    def send(self, _apdu: bytes, _log_name: str) -> bytes:
        return b""


class _FakeCryptoManager:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def write_encryption_enabled(self) -> bool:
        return self.enabled

    def blocks_plaintext_secret_writes(self) -> bool:
        return self.enabled

    def provider_ready_for_encrypt(self) -> bool:
        return self.enabled

    @staticmethod
    def is_encrypted_payload(payload: object) -> bool:
        if isinstance(payload, dict) is False:
            return False
        return bool(payload.get("__fake_encrypted__", False))

    @staticmethod
    def encrypt_payload(payload: dict[str, object]) -> dict[str, object]:
        return {
            "__fake_encrypted__": True,
            "ciphertext": json.dumps(payload, sort_keys=True),
        }

    @staticmethod
    def decrypt_payload(payload: dict[str, object]) -> dict[str, object]:
        return json.loads(str(payload["ciphertext"]))


class DeviceInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_dir = Path(__file__).resolve().parents[1] / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=self.state_dir)
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "device_inventory.sqlite3"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_inventory_crypto_config_defaults_to_disabled(self) -> None:
        config_path = self.temp_path / "inventory_crypto.json"

        manager = InventoryCryptoManager(config_path=str(config_path))

        self.assertFalse(manager.write_encryption_enabled())
        self.assertTrue(config_path.exists())
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["enabled"], False)
        self.assertEqual(loaded["provider"], "gpg")
        self.assertEqual(loaded["gpg"]["gpg_key_file"], "")

    def test_inventory_crypto_reads_gpg_recipient_from_key_file(self) -> None:
        config_path = self.temp_path / "inventory_crypto.json"
        key_path = self.temp_path / "gpg_key.fingerprint"
        key_path.write_text(
            "# preferred recipient fingerprint\nFC9E 9424 840E 8909 AB94 D399 22C9 3CC8 82B9 8FC5\n",
            encoding="utf-8",
        )
        config_path.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "provider": "gpg",
                    "gpg": {
                        "binary": "gpg",
                        "gpg_key_file": "gpg_key.fingerprint",
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        manager = InventoryCryptoManager(config_path=str(config_path))

        self.assertEqual(
            manager._gpg_recipients(),
            ["FC9E9424840E8909AB94D39922C93CC882B98FC5"],
        )

    def test_inventory_crypto_encrypt_invokes_gpg_subprocess(self) -> None:
        config_path = self.temp_path / "inventory_crypto.json"
        config_path.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "provider": "gpg",
                    "gpg": {
                        "binary": "gpg",
                        "recipients": ["ABCDEF0123456789"],
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        manager = InventoryCryptoManager(config_path=str(config_path))
        completed = subprocess.CompletedProcess(
            ["gpg", "--batch", "--yes", "--quiet", "--armor", "--encrypt"],
            0,
            stdout=b"ciphertext\n",
            stderr=b"",
        )

        with mock.patch(
            "yggdrasim_common.inventory_crypto.shutil.which",
            return_value="/usr/bin/gpg",
        ):
            with mock.patch(
                "yggdrasim_common.inventory_crypto.subprocess.run",
                return_value=completed,
            ) as mocked_run:
                ciphertext = manager._gpg_encrypt(b'{"secret": true}')

        self.assertEqual(ciphertext, "ciphertext\n")
        mocked_run.assert_called_once_with(
            [
                "gpg",
                "--batch",
                "--yes",
                "--quiet",
                "--armor",
                "--encrypt",
                "--recipient",
                "ABCDEF0123456789",
            ],
            input=b'{"secret": true}',
            capture_output=True,
            check=False,
            timeout=120.0,
        )

    def test_inventory_crypto_dict_payload_round_trip_through_fake_gpg(self) -> None:
        """COMMON-P4-01 (a): ``encrypt_payload`` / ``decrypt_payload`` round-trip.

        The real GPG binary is replaced with a reversible base64 stand-in so
        the test works in CI without a keyring. What matters for the audit
        checklist is that the ``dict`` the operator hands in is the same
        ``dict`` that comes back after a round-trip through the public
        encrypt/decrypt surface.
        """
        import base64 as _b64

        config_path = self.temp_path / "inventory_crypto.json"
        config_path.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "provider": "gpg",
                    "plaintext_fallback_writes": False,
                    "gpg": {
                        "binary": "gpg",
                        "recipients": ["ABCDEF0123456789"],
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        manager = InventoryCryptoManager(config_path=str(config_path))

        def _fake_gpg_run(command, *, input=b"", capture_output=True, check=False, timeout=None):
            del capture_output
            del check
            del timeout
            if "--encrypt" in command:
                armored = (
                    "-----BEGIN PGP MESSAGE-----\n"
                    + _b64.b64encode(bytes(input)).decode("ascii")
                    + "\n-----END PGP MESSAGE-----\n"
                )
                return subprocess.CompletedProcess(command, 0, stdout=armored.encode("utf-8"), stderr=b"")
            trimmed_lines = [
                line
                for line in bytes(input).decode("utf-8").splitlines()
                if len(line.strip()) > 0 and line.startswith("-----") is False
            ]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=_b64.b64decode("".join(trimmed_lines)),
                stderr=b"",
            )

        payload = {
            "ki": "00112233445566778899AABBCCDDEEFF",
            "opc": "FFEEDDCCBBAA99887766554433221100",
            "notes": {"kvn": 0x31, "lab": True},
        }

        with mock.patch(
            "yggdrasim_common.inventory_crypto.shutil.which",
            return_value="/usr/bin/gpg",
        ):
            with mock.patch(
                "yggdrasim_common.inventory_crypto.subprocess.run",
                side_effect=_fake_gpg_run,
            ):
                envelope = manager.encrypt_payload(payload)
                decrypted = manager.decrypt_payload(envelope)

        self.assertTrue(envelope[InventoryCryptoManager.ENVELOPE_MARKER])
        self.assertEqual(envelope["provider"], "gpg")
        self.assertIn("-----BEGIN PGP MESSAGE-----", envelope["ciphertext_ascii"])
        self.assertEqual(decrypted, payload)

    def test_inventory_crypto_blocks_plaintext_secret_writes_when_enabled(self) -> None:
        """COMMON-P4-01 (b): refuse plaintext fallback when configured.

        With ``enabled=True`` and ``plaintext_fallback_writes=False`` the
        manager must advertise ``blocks_plaintext_secret_writes() is True``
        so callers wired through ``write_secret_file_bytes`` never silently
        land plaintext on disk.
        """
        config_path = self.temp_path / "inventory_crypto.json"
        config_path.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "provider": "gpg",
                    "plaintext_fallback_writes": False,
                    "gpg": {
                        "binary": "gpg",
                        "recipients": ["ABCDEF0123456789"],
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        manager = InventoryCryptoManager(config_path=str(config_path))

        with mock.patch(
            "yggdrasim_common.inventory_crypto.shutil.which",
            return_value="/usr/bin/gpg",
        ):
            self.assertTrue(manager.write_encryption_enabled())
            self.assertFalse(manager.plaintext_fallback_writes_allowed())
            self.assertTrue(manager.provider_ready_for_encrypt())
            self.assertTrue(manager.blocks_plaintext_secret_writes())

    def test_inventory_crypto_write_secret_file_leaves_no_plaintext_on_disk(self) -> None:
        """COMMON-P4-01 (c): ``write_secret_file_bytes`` never leaves plaintext behind."""
        from yggdrasim_common.inventory_crypto import write_secret_file_bytes

        config_path = self.temp_path / "inventory_crypto.json"
        config_path.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "provider": "gpg",
                    "gpg": {
                        "binary": "gpg",
                        "recipients": ["ABCDEF0123456789"],
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        manager = InventoryCryptoManager(config_path=str(config_path))
        secret_path = self.temp_path / "secret.bin"
        plaintext = b"\x00\x11\x22\x33KI-MATERIAL\x44\x55"
        armored = (
            b"-----BEGIN PGP MESSAGE-----\n"
            b"ciphertext-placeholder\n"
            b"-----END PGP MESSAGE-----\n"
        )

        with mock.patch(
            "yggdrasim_common.inventory_crypto.shutil.which",
            return_value="/usr/bin/gpg",
        ):
            with mock.patch(
                "yggdrasim_common.inventory_crypto.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout=armored, stderr=b""),
            ):
                write_secret_file_bytes(secret_path, plaintext, crypto_manager=manager)

        on_disk = secret_path.read_bytes()
        self.assertTrue(on_disk.lstrip().startswith(b"-----BEGIN PGP MESSAGE-----"))
        self.assertNotIn(b"KI-MATERIAL", on_disk)

    def test_inventory_crypto_refuses_to_encrypt_without_recipients(self) -> None:
        """COMMON-P4-01 (d): ``_gpg_encrypt`` raises when recipient list is empty."""
        config_path = self.temp_path / "inventory_crypto.json"
        config_path.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "provider": "gpg",
                    "gpg": {
                        "binary": "gpg",
                        "recipients": [],
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        manager = InventoryCryptoManager(config_path=str(config_path))

        with mock.patch(
            "yggdrasim_common.inventory_crypto.shutil.which",
            return_value="/usr/bin/gpg",
        ):
            self.assertFalse(manager.provider_ready_for_encrypt())
            with self.assertRaises(ValueError):
                manager._gpg_encrypt(b"unusable without recipients")

    def test_inventory_crypto_refuses_gpg_key_file_outside_config_directory(self) -> None:
        """COMMON-P4-01 (e): ``gpg_key_file`` path cannot escape the config dir."""
        config_path = self.temp_path / "inventory_crypto.json"

        sibling_root = Path(tempfile.mkdtemp(dir=self.state_dir))
        try:
            escape_target = sibling_root / "rogue_recipient.txt"
            escape_target.write_text("DEADBEEFCAFEBABE0011223344556677\n", encoding="utf-8")
            config_path.write_text(
                json.dumps(
                    {
                        "enabled": True,
                        "provider": "gpg",
                        "gpg": {
                            "binary": "gpg",
                            "gpg_key_file": str(escape_target),
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            manager = InventoryCryptoManager(config_path=str(config_path))
            self.assertIsNone(manager._gpg_key_file_path())
            self.assertEqual(manager._gpg_recipients(), [])
        finally:
            try:
                for child in sibling_root.iterdir():
                    child.unlink()
                sibling_root.rmdir()
            except OSError:
                pass

    def test_inventory_crypto_decrypt_invokes_gpg_subprocess(self) -> None:
        config_path = self.temp_path / "inventory_crypto.json"
        config_path.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "provider": "gpg",
                    "gpg": {
                        "binary": "gpg",
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        manager = InventoryCryptoManager(config_path=str(config_path))
        completed = subprocess.CompletedProcess(
            ["gpg", "--batch", "--yes", "--quiet", "--decrypt"],
            0,
            stdout=b'{"secret": true}',
            stderr=b"",
        )

        with mock.patch(
            "yggdrasim_common.inventory_crypto.shutil.which",
            return_value="/usr/bin/gpg",
        ):
            with mock.patch(
                "yggdrasim_common.inventory_crypto.subprocess.run",
                return_value=completed,
            ) as mocked_run:
                plaintext = manager._gpg_decrypt("ciphertext")

        self.assertEqual(plaintext, b'{"secret": true}')
        mocked_run.assert_called_once_with(
            ["gpg", "--batch", "--yes", "--quiet", "--decrypt"],
            input=b"ciphertext",
            capture_output=True,
            check=False,
            timeout=120.0,
        )

    def test_store_round_trip_per_namespace(self) -> None:
        store = DeviceInventoryStore(db_path=str(self.db_path))
        store.replace_namespace(
            "iccid",
            "8947000000000000000",
            "scp80",
            {
                "cntr": "0000000001",
                "spi": "E1",
            },
        )

        merged = store.merge_namespace(
            "iccid",
            "8947000000000000000",
            "scp80",
            {
                "kid": "00112233445566778899AABBCCDDEEFF",
            },
        )

        self.assertEqual(merged["cntr"], "0000000001")
        self.assertEqual(merged["spi"], "E1")
        self.assertEqual(merged["kid"], "00112233445566778899AABBCCDDEEFF")

    def test_store_uses_crypto_envelope_when_enabled(self) -> None:
        store = DeviceInventoryStore(
            db_path=str(self.db_path),
            crypto_manager=_FakeCryptoManager(),
        )
        store.replace_namespace(
            "iccid",
            "8947000000000000000",
            "scp80",
            {
                "cntr": "0000000001",
                "spi": "1621",
            },
        )

        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT payload_json
                FROM inventory_namespaces
                WHERE identity_kind = ?
                  AND identity_value = ?
                  AND namespace = ?
                """,
                ("iccid", "8947000000000000000", "scp80"),
            ).fetchone()

        self.assertIsNotNone(row)
        raw_payload = json.loads(str(row[0]))
        self.assertTrue(raw_payload["__fake_encrypted__"])
        self.assertEqual(
            store.get_namespace("iccid", "8947000000000000000", "scp80")["spi"],
            "1621",
        )

    def test_module_state_round_trip(self) -> None:
        store = DeviceInventoryStore(db_path=str(self.db_path))

        store.replace_module_state(
            "scp80_config",
            {
                "transport": "reader",
                "reader_idx": "0",
            },
        )

        payload = store.get_module_state("scp80_config")
        self.assertEqual(payload["transport"], "reader")
        self.assertEqual(payload["reader_idx"], "0")

    def test_module_state_uses_crypto_envelope_when_enabled(self) -> None:
        store = DeviceInventoryStore(
            db_path=str(self.db_path),
            crypto_manager=_FakeCryptoManager(),
        )
        store.replace_module_state(
            "scp03_config",
            {
                "KEYS": {
                    "scp03_kenc": "00112233445566778899AABBCCDDEEFF",
                }
            },
        )

        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT payload_json
                FROM module_state
                WHERE module_name = ?
                """,
                ("scp03_config",),
            ).fetchone()

        self.assertIsNotNone(row)
        raw_payload = json.loads(str(row[0]))
        self.assertTrue(raw_payload["__fake_encrypted__"])
        payload = store.get_module_state("scp03_config")
        self.assertEqual(
            payload["KEYS"]["scp03_kenc"],
            "00112233445566778899AABBCCDDEEFF",
        )

    def test_eim_runtime_state_syncs_existing_counter_to_inventory(self) -> None:
        runtime_path = self.temp_path / "runtime_state.json"
        runtime_path.write_text(
            json.dumps(
                {
                    "counter_by_eim_id": {
                        "1.2.3": 7,
                    },
                    "last_transaction_id_hex": "01020304",
                    "last_matching_id": "MATCH-1",
                    "last_operation": "seed",
                    "updated_at_utc": "",
                }
            ),
            encoding="utf-8",
        )
        store = DeviceInventoryStore(db_path=str(self.db_path))
        runtime = EimRuntimeStateStore(str(runtime_path), inventory=store)

        self.assertEqual(runtime.get_next_counter("1.2.3"), 7)
        payload = store.get_namespace("eim_id", "1.2.3", "scp11_eim_local")
        self.assertEqual(payload["next_counter"], 7)
        self.assertEqual(payload["last_operation"], "seed")
        self.assertEqual(payload["last_matching_id"], "MATCH-1")

    def test_local_access_restores_persistent_eid_profile(self) -> None:
        cfg = LocalAccessConfig()
        session = LocalIsdrSession(cfg=cfg, apdu_channel=_DummyApduChannel())
        session._inventory = EidInventoryNamespace("scp11_local_access", db_path=str(self.db_path))

        profile_override = "SCP11/local_access/profile/test_profile.txt"
        metadata_override = "SCP11/local_access/profile/metadata/default_profile_metadata.json"
        session._inventory.replace(
            "89049032000000000000000000000001",
            {
                "selected_ci_pkid": "AABBCCDD",
                "selected_auth_certificate_path": "SCP11/local_access/certs/auth.der",
                "selected_pb_certificate_path": "SCP11/local_access/certs/pb.der",
                "profile_override_path": profile_override,
                "metadata_override_path": metadata_override,
            },
        )

        expected_profile_override = session._normalize_user_path(
            profile_override,
            base_dir=cfg.PROFILE_DIR,
        )
        expected_metadata_override = session._normalize_user_path(
            metadata_override,
            base_dir=cfg.METADATA_DIR,
        )
        session._bind_inventory_for_eid("89049032000000000000000000000001")
        self.assertEqual(session.current_eid, "89049032000000000000000000000001")
        self.assertEqual(session.state.selected_ci_pkid, "AABBCCDD")
        self.assertEqual(session.state.selected_auth_certificate_path, "SCP11/local_access/certs/auth.der")
        self.assertEqual(session.state.selected_pb_certificate_path, "SCP11/local_access/certs/pb.der")
        self.assertEqual(session.state.profile_override_path, expected_profile_override)
        self.assertEqual(session.state.metadata_override_path, expected_metadata_override)

        session.reset_state()
        self.assertEqual(session.state.profile_override_path, expected_profile_override)
        self.assertEqual(session.state.metadata_override_path, expected_metadata_override)
        self.assertEqual(session.state.selected_ci_pkid, "AABBCCDD")


if __name__ == "__main__":
    unittest.main()
