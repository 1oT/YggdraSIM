# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import importlib
import importlib.util
import sys
import types
import unittest
from pathlib import Path


def _install_smartcard_stubs() -> None:
    if "smartcard" in sys.modules:
        return

    smartcard_module = types.ModuleType("smartcard")
    system_module = types.ModuleType("smartcard.System")
    card_connection_module = types.ModuleType("smartcard.CardConnection")
    atr_module = types.ModuleType("smartcard.ATR")

    class _CardConnection:
        T0_protocol = 0
        T1_protocol = 1
        RAW_protocol = 2

    class _Atr:
        def __init__(self, _raw):
            pass

        @staticmethod
        def getSupportedProtocols():
            return {"T=1": True}

    system_module.readers = lambda: []
    card_connection_module.CardConnection = _CardConnection
    atr_module.ATR = _Atr

    smartcard_module.System = system_module
    smartcard_module.CardConnection = card_connection_module
    smartcard_module.ATR = atr_module

    sys.modules["smartcard"] = smartcard_module
    sys.modules["smartcard.System"] = system_module
    sys.modules["smartcard.CardConnection"] = card_connection_module
    sys.modules["smartcard.ATR"] = atr_module


_install_smartcard_stubs()


class RepoModuleImportSmokeTests(unittest.TestCase):
    @staticmethod
    def _import_from_file(module_name: str, file_path: Path):
        unique_name = f"_smoke_{module_name.replace('.', '_')}"
        spec = importlib.util.spec_from_file_location(unique_name, file_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to create import spec for {file_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[unique_name] = module
        parent_dir = str(file_path.parent)
        inserted_parent = False
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
            inserted_parent = True
        try:
            spec.loader.exec_module(module)
        finally:
            if inserted_parent:
                sys.path.pop(0)
        return module

    def test_import_all_repo_modules(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        include_roots = {"main", "SCP03", "SCP80", "SCP11", "Tools", "yggdrasim_common"}
        module_specs: list[tuple[str, Path]] = []

        for file_path in repo_root.rglob("*.py"):
            relative = file_path.relative_to(repo_root)
            if len(relative.parts) == 0:
                continue
            if relative.parts[0] not in include_roots:
                continue
            if "__pycache__" in relative.parts:
                continue
            module_specs.append((".".join(relative.with_suffix("").parts), file_path))

        for module_name, file_path in sorted(set(module_specs)):
            with self.subTest(module=module_name):
                try:
                    imported = importlib.import_module(module_name)
                except ModuleNotFoundError:
                    imported = self._import_from_file(module_name, file_path)
                self.assertIsNotNone(imported)


if __name__ == "__main__":
    unittest.main()
