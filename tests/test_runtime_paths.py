import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yggdrasim_common.runtime_paths as runtime_paths
from SCP11.config import SGPConfig as RelayConfig
from SCP11.es9_client import Es9LikeClient
from SCP11.eim_local.config import EimLocalConfig
from SCP11.live.config import SGPConfig as LiveRelayConfig
from SCP11.local_access.config import LocalAccessConfig
from SCP11.local_access.session import LocalIsdrSession
from SCP11.test.config import SGPConfig as TestRelayConfig


# These tests round-trip ``frozen``-build fixture seeding from the source
# tree into a synthesised runtime root. The cert and key bundles they
# look for live behind the workspace ``.gitignore`` (``*.pem`` / ``*.der``
# are excluded so private signing material never lands in the public
# release tree). On a fresh CI checkout the fixtures are absent, so the
# seeding has nothing to copy and the assertions fail through no fault
# of the code under test. Skip the affected tests cleanly when the
# canonical fixture files are missing -- they're the same ones the
# install scripts ship via the release artefact, and they only exist
# in the maintainer's working tree.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SGP26_VARO_DPAUTH_CERT = (
    _REPO_ROOT
    / "SCP11"
    / "SGP.26_test_Certs"
    / "Valid Test Cases"
    / "Variant O"
    / "SM-DP+"
    / "SM_DPauth"
    / "CERT_S_SM_DPauth_VARO_SIG_NIST.der"
)
_SCP11_ES9_TEST_CI_CA = _REPO_ROOT / "SCP11" / "ES9_TEST_CI_CA.pem"

_SGP26_FIXTURE_PRESENT = _SGP26_VARO_DPAUTH_CERT.is_file()
_SCP11_PEM_FIXTURE_PRESENT = _SCP11_ES9_TEST_CI_CA.is_file()

_SGP26_SKIP_REASON = (
    f"SGP.26 cert fixture not present at {_SGP26_VARO_DPAUTH_CERT} "
    "(*.der is gitignored; populated only in the maintainer tree)."
)
_SCP11_PEM_SKIP_REASON = (
    f"SCP11 PEM fixture not present at {_SCP11_ES9_TEST_CI_CA} "
    "(*.pem is gitignored; populated only in the maintainer tree)."
)


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

    @unittest.skipUnless(_SGP26_FIXTURE_PRESENT, _SGP26_SKIP_REASON)
    def test_local_access_config_seeds_writable_runtime_tree_when_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                cfg = LocalAccessConfig()
            self.assertEqual(cfg.CERTS_DIR, str(runtime_root / "Workspace" / "LocalSMDPP" / "certs"))
            self.assertEqual(
                cfg.SGP26_VALID_CERT_DIR,
                str(runtime_root / "Workspace" / "SCP11" / "SGP.26_test_Certs" / "Valid Test Cases"),
            )
            self.assertTrue((runtime_root / "Workspace" / "LocalSMDPP" / "certs").is_dir())
            self.assertTrue((runtime_root / "Workspace" / "LocalSMDPP" / "profile").is_dir())
            self.assertTrue(
                (
                    runtime_root
                    / "Workspace"
                    / "SCP11"
                    / "SGP.26_test_Certs"
                    / "Valid Test Cases"
                    / "Variant O"
                    / "SM-DP+"
                    / "SM_DPauth"
                    / "CERT_S_SM_DPauth_VARO_SIG_NIST.der"
                ).exists()
            )
            self.assertTrue((runtime_root / "Workspace" / "LocalSMDPP" / "profile" / "test_profile.txt").exists())
            self.assertTrue(
                (
                    runtime_root
                    / "Workspace"
                    / "LocalSMDPP"
                    / "profile"
                    / "metadata"
                    / "default_profile_metadata.json"
                ).exists()
            )

    def test_scp03_config_seeds_shared_workspace_files_when_frozen(self) -> None:
        import SCP03.config as scp03_config

        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            try:
                with patch_frozen, patch_executable, patch_env:
                    importlib.reload(scp03_config)
                    self.assertEqual(
                        Path(scp03_config.Config.CONFIG_DIR),
                        runtime_root / "Workspace" / "SCP03",
                    )
                    self.assertEqual(
                        Path(scp03_config.Config.AID_FILE),
                        runtime_root / "Workspace" / "SCP03" / "aid.txt",
                    )
                    self.assertTrue((runtime_root / "Workspace" / "SCP03" / "keys.ini").exists())
                    self.assertTrue((runtime_root / "Workspace" / "SCP03" / "fids.txt").exists())
                    self.assertTrue((runtime_root / "Workspace" / "SCP03" / "aid.txt").exists())
                    self.assertTrue((runtime_root / "Workspace" / "SCP03" / "binds.json").exists())
            finally:
                importlib.reload(scp03_config)

    @unittest.skipUnless(_SCP11_PEM_FIXTURE_PRESENT, _SCP11_PEM_SKIP_REASON)
    def test_scp11_relay_configs_seed_workspace_cert_paths_when_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                relay_cfg = RelayConfig()
                live_cfg = LiveRelayConfig()
                test_cfg = TestRelayConfig()
            self.assertEqual(relay_cfg.CERT_PATH_AUTH, str(runtime_root / "Workspace" / "SCP11" / "CERT.DPauth.ECDSA.der"))
            self.assertEqual(live_cfg.CERT_PATH_AUTH, str(runtime_root / "Workspace" / "SCP11" / "live" / "CERT.DPauth.ECDSA.der"))
            self.assertEqual(test_cfg.CERT_PATH_AUTH, str(runtime_root / "Workspace" / "SCP11" / "test" / "CERT.DPauth.ECDSA.der"))
            self.assertTrue((runtime_root / "Workspace" / "SCP11" / "ES9_TEST_CI_CA.pem").exists())
            self.assertTrue((runtime_root / "Workspace" / "SCP11" / "SK.DPauth.ECDSA.pem").exists())
            self.assertTrue((runtime_root / "Workspace" / "SCP11" / "live" / "ES9_TEST_CI_CA.pem").exists())
            self.assertTrue((runtime_root / "Workspace" / "SCP11" / "live" / "SK.DPauth.ECDSA.pem").exists())
            self.assertTrue((runtime_root / "Workspace" / "SCP11" / "test" / "ES9_TEST_CI_CA.pem").exists())
            self.assertTrue((runtime_root / "Workspace" / "SCP11" / "test" / "SK.DPauth.ECDSA.pem").exists())

    def test_eim_local_config_seeds_writable_runtime_tree_when_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                cfg = EimLocalConfig()
            self.assertEqual(cfg.EIM_PACKAGES_DIR, str(runtime_root / "Workspace" / "LocalEIM" / "eim_packages"))
            self.assertTrue((runtime_root / "Workspace" / "LocalEIM" / "certs" / "eim").is_dir())
            self.assertTrue((runtime_root / "Workspace" / "LocalEIM" / "eim_identity.json").exists())
            self.assertTrue(
                (
                    runtime_root
                    / "Workspace"
                    / "LocalEIM"
                    / "eim_packages"
                    / "templates"
                    / "template_add_eim.json"
                ).exists()
            )
            addeim_readme = runtime_root / "Workspace" / "LocalEIM" / "certs" / "addeim" / "README.md"
            addeim_template = (
                runtime_root
                / "Workspace"
                / "LocalEIM"
                / "certs"
                / "addeim"
                / "eim_identity.template.json"
            )
            self.assertTrue(addeim_readme.exists())
            self.assertTrue(addeim_template.exists())
            addeim_template_text = addeim_template.read_text(encoding="utf-8")
            self.assertIn("/path/to/local_eim_signing_cert.pem", addeim_template_text)
            self.assertNotIn("Workspace/LocalEIM/certs/addeim/", addeim_template_text)
            self.assertIn('"eim_hostname_fqdn": "eim.yggdrasim.example.test"', addeim_template_text)
            self.assertIn('"tls_connection_certificate_choice": "server_certificate"', addeim_template_text)
            self.assertIn('"https_over_tcp_retrieval": true', addeim_template_text)

    def test_local_access_session_resolves_repo_style_path_from_runtime_root_when_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            target_file = runtime_root / "Workspace" / "LocalEIM" / "certs" / "eim" / "CERT.EIM.pem"
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

    def test_local_access_session_remaps_legacy_scp03_aid_path_to_workspace_when_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = Path(temp_dir) / "runtime"
            target_file = runtime_root / "Workspace" / "SCP03" / "aid.txt"
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text("ISD-R: A0000005591010FFFFFFFF8900000100\n", encoding="utf-8")
            patch_frozen, patch_executable, patch_env = self._frozen_patches(runtime_root)
            with patch_frozen, patch_executable, patch_env:
                cfg = LocalAccessConfig()
                session = LocalIsdrSession(cfg=cfg, apdu_channel=_DummyApduChannel())
                resolved = session._normalize_user_path("SCP03/aid.txt")
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
