# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.


import subprocess
import sys
import textwrap
import unittest
from pathlib import Path


class Scp11PackageLayoutTests(unittest.TestCase):
    def test_relay_namespace_imports(self):
        from SCP11.relay import SGP22Client, SGP22Orchestrator, SGPConfig

        self.assertIsNotNone(SGP22Client)
        self.assertIsNotNone(SGP22Orchestrator)
        self.assertIsNotNone(SGPConfig)

    def test_shared_namespace_imports(self):
        from SCP11.shared import ASN1Registry, CryptoEngine, PayloadBuilder, SGP22Transport

        self.assertIsNotNone(ASN1Registry)
        self.assertIsNotNone(CryptoEngine)
        self.assertIsNotNone(PayloadBuilder)
        self.assertIsNotNone(SGP22Transport)

    def test_eim_package_namespaces_share_canonical_parser_symbols(self):
        import SCP11.eim_packages as canonical
        import SCP11.live.eim_packages as live
        import SCP11.relay.eim_packages as relay
        import SCP11.test.eim_packages as compatibility

        self.assertIs(live.parse_eim_package, canonical.parse_eim_package)
        self.assertIs(relay.parse_eim_package, canonical.parse_eim_package)
        self.assertIs(compatibility.parse_eim_package, canonical.parse_eim_package)
        self.assertIs(compatibility, live)
        self.assertEqual(set(relay.__all__), set(live.__all__))

    def test_compatibility_exports_preserve_symbol_identity(self):
        from SCP11.crypto_engine import CryptoEngine as RootCryptoEngine
        from SCP11.live.crypto_engine import CryptoEngine as LiveCryptoEngine
        from SCP11.live.models import EimPollRequest as LivePollRequest
        from SCP11.relay.models import EimPollRequest as RelayPollRequest
        from SCP11.shared.crypto_engine import CryptoEngine as SharedCryptoEngine
        from SCP11.test.models import EimPollRequest as TestPollRequest

        self.assertIs(SharedCryptoEngine, RootCryptoEngine)
        self.assertIs(LiveCryptoEngine, RootCryptoEngine)
        self.assertIs(RelayPollRequest, LivePollRequest)
        self.assertIs(TestPollRequest, LivePollRequest)

    def test_shared_transport_has_one_implementation(self):
        import SCP11.live.transport as live_transport
        import SCP11.shared.transport as shared_transport
        import SCP11.transport as root_transport

        self.assertIs(live_transport, root_transport)
        self.assertIs(shared_transport.PcscApduChannel, root_transport.PcscApduChannel)

    def test_old_relay_copies_are_gone(self):
        import importlib.util

        for name in (
            "SCP11.orchestrator",
            "SCP11.console",
            "SCP11.es9_client",
            "SCP11.models",
            "SCP11.config",
            "SCP11.factory",
            "SCP11.providers",
        ):
            with self.subTest(name=name):
                self.assertIsNone(importlib.util.find_spec(name))

    def test_live_console_imports_when_hil_runtime_is_omitted(self):
        repo_root = Path(__file__).resolve().parent.parent
        script = textwrap.dedent(
            """
            import builtins
            import os

            os.environ["YGGDRASIM_FLAVOR"] = "clean"
            real_import = builtins.__import__

            def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
                if name == "yggdrasim_common.hil_bridge_runtime":
                    raise ImportError("simulated clean bundle exclusion")
                if name == "yggdrasim_common" and fromlist and "hil_bridge_runtime" in fromlist:
                    raise ImportError("simulated clean bundle exclusion")
                return real_import(name, globals, locals, fromlist, level)

            builtins.__import__ = fake_import
            import SCP11.live.console
            import SCP11.test.console
            raise SystemExit(0)
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_factory_import_preserves_nested_package_import_error(self):
        repo_root = Path(__file__).resolve().parent.parent
        script = textwrap.dedent(
            """
            import builtins

            real_import = builtins.__import__

            def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
                package = ""
                if isinstance(globals, dict):
                    package = str(globals.get("__package__", "") or "")
                if level == 1 and name == "transport" and package == "SCP11.live":
                    raise ModuleNotFoundError(
                        "No module named 'missing_transport_dependency'",
                        name="missing_transport_dependency",
                    )
                return real_import(name, globals, locals, fromlist, level)

            builtins.__import__ = fake_import
            try:
                import SCP11.live.factory
            except ModuleNotFoundError as error:
                raise SystemExit(0 if error.name == "missing_transport_dependency" else 2)
            raise SystemExit(1)
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
