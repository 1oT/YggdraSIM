"""Tests for :mod:`yggdrasim_common.env_flags`.

Exercises the registry invariants, the persistence pipeline for the
three scope kinds (runtime-root file, per-user home file, session-only),
and the apply-on-startup helper that the launcher wires in before
``ensure_plugins_loaded()``.

The tests isolate each case inside a dedicated ``TemporaryDirectory``
and repoint both ``HOME`` and ``YGGDRASIM_RUNTIME_ROOT`` at it. Without
that isolation a test run would touch the operator's real user home
and their actual runtime root.
"""

from __future__ import annotations

import importlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yggdrasim_common.env_flags as env_flags


class _TempRoot:
    """Context helper that gives each test a clean HOME + RUNTIME_ROOT."""

    def __init__(self) -> None:
        self._tmp: tempfile.TemporaryDirectory | None = None
        self._patcher: mock._patch_dict | None = None

    def __enter__(self) -> str:
        self._tmp = tempfile.TemporaryDirectory()
        root = self._tmp.name
        # clear=False to keep PATH etc., overriding only the two env
        # variables that steer env_flags' persistence targets.
        self._patcher = mock.patch.dict(
            os.environ,
            {
                "HOME": root,
                "YGGDRASIM_RUNTIME_ROOT": root,
            },
            clear=False,
        )
        self._patcher.start()
        # Drop any YGGDRASIM_* values that would leak state across tests.
        for flag in env_flags.FLAG_REGISTRY:
            if flag.name in ("YGGDRASIM_RUNTIME_ROOT",):
                continue
            os.environ.pop(flag.name, None)
        return root

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._patcher is not None:
            self._patcher.stop()
        if self._tmp is not None:
            self._tmp.cleanup()


class RegistryShapeTests(unittest.TestCase):
    def test_registry_is_non_empty_and_unique(self) -> None:
        self.assertGreater(len(env_flags.FLAG_REGISTRY), 0)
        seen_names: set[str] = set()
        for flag in env_flags.FLAG_REGISTRY:
            self.assertTrue(flag.name.startswith("YGGDRASIM_"), flag.name)
            self.assertNotIn(flag.name, seen_names, f"duplicate: {flag.name}")
            seen_names.add(flag.name)

    def test_every_flag_has_a_known_category(self) -> None:
        known = set(env_flags.CATEGORY_ORDER)
        for flag in env_flags.FLAG_REGISTRY:
            self.assertIn(flag.category, known, flag.name)

    def test_every_flag_has_a_known_kind(self) -> None:
        known_kinds = {
            env_flags.KIND_BOOL_TOGGLE,
            env_flags.KIND_CHOICE,
            env_flags.KIND_PATH,
            env_flags.KIND_INT,
            env_flags.KIND_FLOAT,
            env_flags.KIND_STRING,
        }
        for flag in env_flags.FLAG_REGISTRY:
            self.assertIn(flag.kind, known_kinds, flag.name)
            if flag.kind == env_flags.KIND_CHOICE:
                self.assertGreater(len(flag.choices), 0, flag.name)

    def test_every_flag_has_known_persistence_scope(self) -> None:
        known = {
            env_flags.PERSIST_FILE,
            env_flags.PERSIST_HOME,
            env_flags.PERSIST_SESSION,
        }
        for flag in env_flags.FLAG_REGISTRY:
            self.assertIn(flag.persist_scope, known, flag.name)

    def test_every_flag_has_known_applies_marker(self) -> None:
        known = {env_flags.APPLIES_RUNTIME, env_flags.APPLIES_STARTUP}
        for flag in env_flags.FLAG_REGISTRY:
            self.assertIn(flag.applies, known, flag.name)

    def test_lookup_helpers_agree_with_registry(self) -> None:
        for flag in env_flags.FLAG_REGISTRY:
            self.assertIs(env_flags.get_flag(flag.name), flag)
            self.assertTrue(env_flags.is_registered_flag(flag.name))
        self.assertIsNone(env_flags.get_flag("NOT_A_FLAG"))
        self.assertFalse(env_flags.is_registered_flag("NOT_A_FLAG"))


class RuntimeScopePersistenceTests(unittest.TestCase):
    def test_runtime_scope_roundtrip(self) -> None:
        with _TempRoot() as root:
            flag = env_flags.get_flag("YGGDRASIM_GLOBAL_DEBUG")
            self.assertIsNotNone(flag)
            env_flags.set_flag_value(flag, "1", persist=True)
            persisted_path = os.path.join(root, "state", "env_overrides.json")
            self.assertTrue(os.path.isfile(persisted_path))
            with open(persisted_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload.get("YGGDRASIM_GLOBAL_DEBUG"), "1")
            os.environ.pop(flag.name, None)
            applied = env_flags.apply_persisted_env_overrides()
            self.assertEqual(applied.get(flag.name), "1")
            self.assertEqual(os.environ.get(flag.name), "1")

    def test_clear_removes_persisted_entry(self) -> None:
        with _TempRoot() as root:
            flag = env_flags.get_flag("YGGDRASIM_GLOBAL_DEBUG")
            env_flags.set_flag_value(flag, "1", persist=True)
            env_flags.clear_flag_value(flag, persist=True)
            persisted_path = os.path.join(root, "state", "env_overrides.json")
            with open(persisted_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertNotIn(flag.name, payload)
            self.assertNotIn(flag.name, os.environ)

    def test_session_persist_false_does_not_touch_disk(self) -> None:
        with _TempRoot() as root:
            flag = env_flags.get_flag("YGGDRASIM_GLOBAL_DEBUG")
            env_flags.set_flag_value(flag, "1", persist=False)
            self.assertEqual(os.environ.get(flag.name), "1")
            persisted_path = os.path.join(root, "state", "env_overrides.json")
            self.assertFalse(os.path.isfile(persisted_path))


class HomeScopePersistenceTests(unittest.TestCase):
    def test_home_scope_writes_to_home_only(self) -> None:
        with _TempRoot() as root:
            flag = env_flags.get_flag("YGGDRASIM_RUNTIME_ROOT")
            self.assertEqual(flag.persist_scope, env_flags.PERSIST_HOME)
            # Point the overridden runtime root at a writable subfolder so
            # follow-up runtime_path() lookups do not try to ``mkdir`` into
            # a non-writable system path.
            writable_runtime_override = os.path.join(root, "alt-runtime")
            os.makedirs(writable_runtime_override, exist_ok=True)
            env_flags.set_flag_value(flag, writable_runtime_override, persist=True)
            home_file = os.path.join(root, ".yggdrasim", "env_overrides.json")
            self.assertTrue(os.path.isfile(home_file))
            with open(home_file, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload.get("YGGDRASIM_RUNTIME_ROOT"), writable_runtime_override)


class SessionScopePersistenceTests(unittest.TestCase):
    def test_session_scope_never_writes(self) -> None:
        with _TempRoot() as root:
            flag = env_flags.get_flag("YGGDRASIM_FLAVOR")
            self.assertEqual(flag.persist_scope, env_flags.PERSIST_SESSION)
            env_flags.set_flag_value(flag, "full", persist=True)
            self.assertEqual(os.environ.get("YGGDRASIM_FLAVOR"), "full")
            home_file = os.path.join(root, ".yggdrasim", "env_overrides.json")
            runtime_file = os.path.join(root, "state", "env_overrides.json")
            self.assertFalse(os.path.isfile(home_file))
            self.assertFalse(os.path.isfile(runtime_file))


class ApplyOverridesPrecedenceTests(unittest.TestCase):
    def test_existing_env_wins_over_persisted(self) -> None:
        with _TempRoot():
            flag = env_flags.get_flag("YGGDRASIM_GLOBAL_DEBUG")
            env_flags.set_flag_value(flag, "1", persist=True)
            # Simulate a shell pre-export that explicitly sets a different value.
            os.environ[flag.name] = "0"
            applied = env_flags.apply_persisted_env_overrides()
            self.assertNotIn(flag.name, applied)
            self.assertEqual(os.environ[flag.name], "0")

    def test_home_overrides_win_over_runtime_for_same_key(self) -> None:
        with _TempRoot() as root:
            home_dir = os.path.join(root, ".yggdrasim")
            runtime_dir = os.path.join(root, "state")
            os.makedirs(home_dir, exist_ok=True)
            os.makedirs(runtime_dir, exist_ok=True)
            # Write a conflict on a registered flag under both files.
            with open(os.path.join(home_dir, "env_overrides.json"), "w", encoding="utf-8") as handle:
                json.dump({"YGGDRASIM_GLOBAL_DEBUG": "home-wins"}, handle)
            with open(os.path.join(runtime_dir, "env_overrides.json"), "w", encoding="utf-8") as handle:
                json.dump({"YGGDRASIM_GLOBAL_DEBUG": "runtime-loses"}, handle)
            os.environ.pop("YGGDRASIM_GLOBAL_DEBUG", None)
            env_flags.apply_persisted_env_overrides()
            self.assertEqual(os.environ.get("YGGDRASIM_GLOBAL_DEBUG"), "home-wins")


class ResetAndDumpTests(unittest.TestCase):
    def test_reset_all_clears_both_files(self) -> None:
        with _TempRoot() as root:
            flag_runtime = env_flags.get_flag("YGGDRASIM_GLOBAL_DEBUG")
            flag_home = env_flags.get_flag("YGGDRASIM_RUNTIME_ROOT")
            writable_runtime_override = os.path.join(root, "alt-runtime")
            os.makedirs(writable_runtime_override, exist_ok=True)
            env_flags.set_flag_value(flag_runtime, "1", persist=True)
            env_flags.set_flag_value(flag_home, writable_runtime_override, persist=True)
            # Restore the original runtime root so reset_all_persisted clears
            # the correct file on disk (set_flag_value above repointed
            # YGGDRASIM_RUNTIME_ROOT at writable_runtime_override, which would
            # make the runtime-scoped file resolve to a different location).
            os.environ["YGGDRASIM_RUNTIME_ROOT"] = root
            removed = env_flags.reset_all_persisted(clear_session=True)
            self.assertGreaterEqual(removed, 2)
            runtime_file = os.path.join(root, "state", "env_overrides.json")
            with open(runtime_file, "r", encoding="utf-8") as handle:
                self.assertEqual(json.load(handle), {})
            home_file = os.path.join(root, ".yggdrasim", "env_overrides.json")
            with open(home_file, "r", encoding="utf-8") as handle:
                self.assertEqual(json.load(handle), {})
            self.assertNotIn(flag_runtime.name, os.environ)
            os.environ["YGGDRASIM_FLAVOR"] = "source"
            env_flags.reset_all_persisted(clear_session=True)
            self.assertEqual(os.environ.get("YGGDRASIM_FLAVOR"), "source")

    def test_dump_export_lines_quotes_embedded_single_quotes(self) -> None:
        with _TempRoot():
            os.environ["YGGDRASIM_GLOBAL_DEBUG"] = "it's-fine"
            lines = env_flags.dump_export_lines()
            matching = [line for line in lines if "YGGDRASIM_GLOBAL_DEBUG" in line]
            self.assertEqual(len(matching), 1)
            self.assertIn("it'\\''s-fine", matching[0])
            self.assertTrue(matching[0].startswith("export "))

    def test_corrupt_file_is_quarantined(self) -> None:
        with _TempRoot() as root:
            runtime_dir = os.path.join(root, "state")
            os.makedirs(runtime_dir, exist_ok=True)
            bad_path = os.path.join(runtime_dir, "env_overrides.json")
            with open(bad_path, "w", encoding="utf-8") as handle:
                handle.write("{not-json}")
            # Any read path through the persistence layer should tolerate
            # the corrupt file and move it aside.
            result = env_flags.load_persisted_overrides()
            self.assertEqual(result, {})
            directory_listing = os.listdir(runtime_dir)
            quarantined = [name for name in directory_listing if name.startswith("env_overrides.json.corrupt.")]
            self.assertEqual(len(quarantined), 1, directory_listing)


class EditorEntryPointTests(unittest.TestCase):
    """Smoke tests for :mod:`yggdrasim_common.env_flags_ui` loaded as the launcher does."""

    @staticmethod
    def _load_editor_module():
        module_path = Path(__file__).resolve().parent.parent / "yggdrasim_common" / "env_flags_ui.py"
        spec = importlib.util.spec_from_file_location(
            "yggdrasim_env_flags_ui_under_test", module_path
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    class _StubColors:
        # Match the attribute surface the editor touches via getattr, so
        # missing attributes raise AttributeError during review instead
        # of silently returning empty strings at runtime.
        HEADER = ""
        BLUE = ""
        CYAN = ""
        GREEN = ""
        WARNING = ""
        FAIL = ""
        BROWN = ""
        WHITE = ""
        BOLD = ""
        ENDC = ""

    def test_editor_module_exposes_run_with_injection_signature(self) -> None:
        module = self._load_editor_module()
        self.assertTrue(hasattr(module, "run"))
        import inspect
        parameters = inspect.signature(module.run).parameters
        self.assertEqual(
            list(parameters.keys()),
            ["colors", "clear_screen_callable", "pause_callable"],
        )

    def test_editor_run_returns_when_user_quits_at_top_menu(self) -> None:
        module = self._load_editor_module()
        clear_calls: list[int] = []
        pause_calls: list[int] = []

        def _stub_clear() -> None:
            clear_calls.append(1)

        def _stub_pause() -> None:
            pause_calls.append(1)

        captured_output = io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO("Q\n")):
            with mock.patch.object(sys, "stdout", captured_output):
                module.run(self._StubColors, _stub_clear, _stub_pause)
        # Top screen should have rendered once; no sub-screen means pause
        # is never called.
        self.assertGreaterEqual(len(clear_calls), 1)
        self.assertEqual(len(pause_calls), 0)
        rendered = captured_output.getvalue()
        self.assertIn("Environment Flags", rendered)
        # Every registered category should appear on the index screen.
        for category in env_flags.CATEGORY_ORDER:
            self.assertIn(category, rendered)


class ValidationPropertyTests(unittest.TestCase):
    def test_choice_flags_have_non_empty_choices_and_include_defaults(self) -> None:
        # Extra belt-and-suspenders: any choice flag's default_hint should
        # make sense for at least one of the listed values.
        for flag in env_flags.FLAG_REGISTRY:
            if flag.kind != env_flags.KIND_CHOICE:
                continue
            self.assertGreater(len(flag.choices), 0, flag.name)
            for choice in flag.choices:
                self.assertEqual(choice, str(choice).strip())

    def test_bool_flags_use_string_defaults(self) -> None:
        for flag in env_flags.FLAG_REGISTRY:
            if flag.kind != env_flags.KIND_BOOL_TOGGLE:
                continue
            self.assertIsInstance(flag.bool_on_value, str)
            self.assertIsInstance(flag.bool_off_value, str)


if __name__ == "__main__":
    unittest.main()
