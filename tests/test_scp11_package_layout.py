# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

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
                if level == 1 and name == "transport" and package == "SCP11":
                    raise ModuleNotFoundError(
                        "No module named 'missing_transport_dependency'",
                        name="missing_transport_dependency",
                    )
                return real_import(name, globals, locals, fromlist, level)

            builtins.__import__ = fake_import
            try:
                import SCP11.factory
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
