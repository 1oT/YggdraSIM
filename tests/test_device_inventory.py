import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

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
