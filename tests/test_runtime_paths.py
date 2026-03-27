import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yggdrasim_common.runtime_paths as runtime_paths
from SCP11.es9_client import Es9LikeClient
from SCP11.eim_local.config import EimLocalConfig
from SCP11.local_access.config import LocalAccessConfig
from SCP11.local_access.session import LocalIsdrSession


class _DummyApduChannel:
    def send(self, _apdu: bytes, _log_name: str) -> bytes:
        return b""


class FrozenRuntimePathTests(unittest.TestCase):
    def _frozen_patches(self, runtime_root: Path):
        executable_path = runtime_root.parent / "bin" / "YggdraSIM"
        executable_path.parent.mkdir(parents=True, exist_ok=True)
        executable_path.write_text("", encoding="utf-8")
        return (
            mock.patch.object(sys, "frozen", True, create=True),
            mock.patch.object(sys, "executable", str(executable_path)),
            mock.patch.dict(
                os.environ,
                {runtime_paths.RUNTIME_ROOT_ENV: str(runtime_root)},
                clear=False,
            ),
        )

    def test_runtime_root_uses_override_for_frozen_build(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "portable-data"
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                resolved = runtime_paths.runtime_root()
            self.assertEqual(resolved, str(runtime_root))
            self.assertTrue(runtime_root.is_dir())

    def test_local_access_config_seeds_writable_runtime_tree_when_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                cfg = LocalAccessConfig()
            self.assertEqual(cfg.CERTS_DIR, str(runtime_root / "SCP11" / "local_access" / "certs"))
            self.assertTrue((runtime_root / "SCP11" / "local_access" / "certs").is_dir())
            self.assertTrue((runtime_root / "SCP11" / "local_access" / "profile").is_dir())
            self.assertTrue((runtime_root / "SCP11" / "local_access" / "profile" / "test_profile.txt").exists())
            self.assertTrue(
                (
                    runtime_root
                    / "SCP11"
                    / "local_access"
                    / "profile"
                    / "metadata"
                    / "default_profile_metadata.json"
                ).exists()
            )

    def test_eim_local_config_seeds_writable_runtime_tree_when_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                cfg = EimLocalConfig()
            self.assertEqual(cfg.EIM_PACKAGES_DIR, str(runtime_root / "SCP11" / "eim_local" / "eim_packages"))
            self.assertTrue((runtime_root / "SCP11" / "eim_local" / "certs" / "eim").is_dir())
            self.assertTrue((runtime_root / "SCP11" / "eim_local" / "eim_identity.json").exists())
            self.assertTrue(
                (
                    runtime_root
                    / "SCP11"
                    / "eim_local"
                    / "eim_packages"
                    / "templates"
                    / "template_add_eim.json"
                ).exists()
            )

    def test_local_access_session_resolves_repo_style_path_from_runtime_root_when_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            target_file = runtime_root / "SCP11" / "eim_local" / "certs" / "eim" / "CERT.EIM.pem"
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text("dummy\n", encoding="utf-8")
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                cfg = LocalAccessConfig()
                session = LocalIsdrSession(cfg=cfg, apdu_channel=_DummyApduChannel())
                resolved = session._normalize_user_path(
                    "SCP11/eim_local/certs/eim/CERT.EIM.pem",
                    base_dir=cfg.CERTS_DIR,
                )
            self.assertEqual(resolved, str(target_file))

    def test_es9_client_uses_runtime_root_for_lookup_cache_when_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                client = Es9LikeClient(base_url="https://rsp.example.com")
            self.assertEqual(client._module_dir, str(runtime_root / "SCP11"))
            self.assertEqual(client._workspace_root, str(runtime_root))
            self.assertEqual(
                client._es9_ca_lookup_path,
                str(runtime_root / "SCP11" / "es9_ca_lookup.json"),
            )

    def test_device_inventory_defaults_follow_runtime_root_when_frozen(self) -> None:
        import yggdrasim_common.device_inventory as device_inventory
        import yggdrasim_common.inventory_crypto as inventory_crypto

        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                importlib.reload(inventory_crypto)
                importlib.reload(device_inventory)
                store = device_inventory.DeviceInventoryStore()
                self.assertEqual(
                    Path(store.db_path),
                    runtime_root / "state" / "device_inventory.sqlite3",
                )
                self.assertEqual(
                    Path(store.crypto.config_path),
                    runtime_root / "state" / "inventory_crypto.json",
                )
            importlib.reload(inventory_crypto)
            importlib.reload(device_inventory)


if __name__ == "__main__":
    unittest.main()
