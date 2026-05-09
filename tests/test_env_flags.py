# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for yggdrasim_common/env_flags.py registry and value helpers.

Covers: iter_flags, flags_by_category, get_flag_value, get_flag_source,
is_registered_flag, load_persisted_overrides, apply_persisted_env_overrides,
set_flag_value, clear_flag_value, reset_all_persisted, dump_export_lines.
All env-var accesses clean up via setUp/tearDown.
"""

from __future__ import annotations

import os
import unittest

from yggdrasim_common.env_flags import (
    FLAG_REGISTRY,
    PERSIST_SESSION,
    EnvFlag,
    apply_persisted_env_overrides,
    clear_flag_value,
    dump_export_lines,
    flags_by_category,
    get_flag,
    get_flag_source,
    get_flag_value,
    is_registered_flag,
    iter_flags,
    load_persisted_overrides,
    reset_all_persisted,
    set_flag_value,
)

_SOURCE_UNSET = "unset (default)"
_SOURCE_ENV = "env / CLI override"


# ---------------------------------------------------------------------------
# iter_flags
# ---------------------------------------------------------------------------

class IterFlagsTests(unittest.TestCase):

    def test_returns_non_empty_tuple(self) -> None:
        result = iter_flags()
        self.assertIsInstance(result, tuple)
        self.assertGreater(len(result), 0)

    def test_all_elements_are_env_flags(self) -> None:
        for flag in iter_flags():
            self.assertIsInstance(flag, EnvFlag)

    def test_same_object_as_flag_registry(self) -> None:
        self.assertIs(iter_flags(), FLAG_REGISTRY)

    def test_result_is_frozen_tuple(self) -> None:
        result = iter_flags()
        with self.assertRaises(AttributeError):
            result.append(None)  # tuples have no append


# ---------------------------------------------------------------------------
# flags_by_category
# ---------------------------------------------------------------------------

class FlagsByCategoryTests(unittest.TestCase):

    def test_known_category_returns_flags(self) -> None:
        # "Build / runtime" has at least 1 flag (YGGDRASIM_FLAVOR)
        result = flags_by_category("Build / runtime")
        self.assertIsInstance(result, tuple)
        self.assertGreater(len(result), 0)

    def test_all_results_share_category(self) -> None:
        cat = "Build / runtime"
        for flag in flags_by_category(cat):
            self.assertEqual(flag.category, cat)

    def test_unknown_category_returns_empty_tuple(self) -> None:
        result = flags_by_category("NoSuchCategory_XYZ")
        self.assertEqual(result, ())

    def test_empty_string_returns_empty_tuple(self) -> None:
        result = flags_by_category("")
        self.assertEqual(result, ())

    def test_returns_tuple(self) -> None:
        result = flags_by_category("Build / runtime")
        self.assertIsInstance(result, tuple)


# ---------------------------------------------------------------------------
# get_flag_value
# ---------------------------------------------------------------------------

class GetFlagValueTests(unittest.TestCase):

    def setUp(self) -> None:
        self._flag = iter_flags()[0]
        self._saved = os.environ.pop(self._flag.name, None)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(self._flag.name, None)
        else:
            os.environ[self._flag.name] = self._saved

    def test_unset_returns_empty_string(self) -> None:
        result = get_flag_value(self._flag)
        self.assertEqual(result, "")

    def test_set_env_var_returns_value(self) -> None:
        os.environ[self._flag.name] = "test_value_123"
        result = get_flag_value(self._flag)
        self.assertEqual(result, "test_value_123")

    def test_returns_string_type(self) -> None:
        result = get_flag_value(self._flag)
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# get_flag_source
# ---------------------------------------------------------------------------

class GetFlagSourceTests(unittest.TestCase):

    def setUp(self) -> None:
        self._flag = iter_flags()[0]
        self._saved = os.environ.pop(self._flag.name, None)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(self._flag.name, None)
        else:
            os.environ[self._flag.name] = self._saved

    def test_unset_flag_reports_unset(self) -> None:
        result = get_flag_source(self._flag)
        self.assertEqual(result, _SOURCE_UNSET)

    def test_env_set_reports_env_or_session(self) -> None:
        os.environ[self._flag.name] = "some_value"
        result = get_flag_source(self._flag)
        self.assertIsInstance(result, str)
        self.assertNotEqual(result, _SOURCE_UNSET)

    def test_returns_string(self) -> None:
        result = get_flag_source(self._flag)
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# get_flag (already tested indirectly above; explicit coverage)
# ---------------------------------------------------------------------------

class GetFlagTests(unittest.TestCase):

    def test_known_name_returns_flag(self) -> None:
        flag = iter_flags()[0]
        result = get_flag(flag.name)
        self.assertIs(result, flag)

    def test_unknown_name_returns_none(self) -> None:
        self.assertIsNone(get_flag("NOT_A_REAL_FLAG_XYZ"))

    def test_empty_name_returns_none(self) -> None:
        self.assertIsNone(get_flag(""))


# ---------------------------------------------------------------------------
# is_registered_flag
# ---------------------------------------------------------------------------

class IsRegisteredFlagTests(unittest.TestCase):

    def test_known_flag_name(self) -> None:
        flag = iter_flags()[0]
        self.assertTrue(is_registered_flag(flag.name))

    def test_unknown_name_returns_false(self) -> None:
        self.assertFalse(is_registered_flag("TOTALLY_UNKNOWN_FLAG_XYZ_9999"))

    def test_empty_string_returns_false(self) -> None:
        self.assertFalse(is_registered_flag(""))

    def test_all_registry_names_are_registered(self) -> None:
        for flag in FLAG_REGISTRY:
            self.assertTrue(is_registered_flag(flag.name))


# ---------------------------------------------------------------------------
# load_persisted_overrides
# ---------------------------------------------------------------------------

class LoadPersistedOverridesTests(unittest.TestCase):

    def test_returns_dict(self) -> None:
        result = load_persisted_overrides()
        self.assertIsInstance(result, dict)

    def test_keys_are_registered_flags(self) -> None:
        result = load_persisted_overrides()
        for key in result:
            self.assertTrue(is_registered_flag(key), f"Unexpected key: {key}")

    def test_values_are_strings(self) -> None:
        result = load_persisted_overrides()
        for value in result.values():
            self.assertIsInstance(value, str)


# ---------------------------------------------------------------------------
# apply_persisted_env_overrides
# ---------------------------------------------------------------------------

class ApplyPersistedEnvOverridesTests(unittest.TestCase):

    def setUp(self) -> None:
        # Use a session-only flag that is never persisted; set it in env
        # to verify that apply_persisted_env_overrides does not stomp it.
        self._session_flag = next(
            f for f in FLAG_REGISTRY if f.persist_scope == PERSIST_SESSION
        )
        self._saved = os.environ.pop(self._session_flag.name, None)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(self._session_flag.name, None)
        else:
            os.environ[self._session_flag.name] = self._saved

    def test_returns_dict(self) -> None:
        result = apply_persisted_env_overrides()
        self.assertIsInstance(result, dict)

    def test_pre_set_env_var_not_overwritten(self) -> None:
        os.environ[self._session_flag.name] = "sentinel_value_xyz"
        apply_persisted_env_overrides()
        self.assertEqual(os.environ.get(self._session_flag.name), "sentinel_value_xyz")


# ---------------------------------------------------------------------------
# set_flag_value / clear_flag_value
# ---------------------------------------------------------------------------

class SetFlagValueTests(unittest.TestCase):

    def setUp(self) -> None:
        self._flag = next(
            f for f in FLAG_REGISTRY if f.persist_scope == PERSIST_SESSION
        )
        self._saved = os.environ.pop(self._flag.name, None)

    def tearDown(self) -> None:
        os.environ.pop(self._flag.name, None)
        if self._saved is not None:
            os.environ[self._flag.name] = self._saved

    def test_set_value_visible_in_env(self) -> None:
        set_flag_value(self._flag, "abc123", persist=False)
        self.assertEqual(os.environ.get(self._flag.name), "abc123")

    def test_set_empty_removes_from_env(self) -> None:
        os.environ[self._flag.name] = "existing"
        set_flag_value(self._flag, "", persist=False)
        self.assertNotIn(self._flag.name, os.environ)

    def test_returns_stripped_value(self) -> None:
        result = set_flag_value(self._flag, "  trimmed  ", persist=False)
        self.assertEqual(result, "trimmed")

    def test_clear_flag_value_removes_from_env(self) -> None:
        os.environ[self._flag.name] = "present"
        clear_flag_value(self._flag, persist=False)
        self.assertNotIn(self._flag.name, os.environ)


# ---------------------------------------------------------------------------
# reset_all_persisted
# ---------------------------------------------------------------------------

class ResetAllPersistedTests(unittest.TestCase):

    def test_returns_int(self) -> None:
        result = reset_all_persisted()
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)

    def test_idempotent_second_call(self) -> None:
        reset_all_persisted()
        second = reset_all_persisted()
        self.assertEqual(second, 0)

    def test_clear_session_removes_persistable_flags_from_env(self) -> None:
        persistable = next(
            f for f in FLAG_REGISTRY if f.persist_scope != PERSIST_SESSION
        )
        saved = os.environ.pop(persistable.name, None)
        try:
            os.environ[persistable.name] = "test_value_reset"
            reset_all_persisted(clear_session=True)
            self.assertNotIn(persistable.name, os.environ)
        finally:
            if saved is not None:
                os.environ[persistable.name] = saved
            else:
                os.environ.pop(persistable.name, None)


# ---------------------------------------------------------------------------
# dump_export_lines
# ---------------------------------------------------------------------------

class DumpExportLinesTests(unittest.TestCase):

    def setUp(self) -> None:
        self._flag = next(
            f for f in FLAG_REGISTRY if f.persist_scope == PERSIST_SESSION
        )
        self._saved = os.environ.pop(self._flag.name, None)

    def tearDown(self) -> None:
        os.environ.pop(self._flag.name, None)
        if self._saved is not None:
            os.environ[self._flag.name] = self._saved

    def test_returns_list(self) -> None:
        self.assertIsInstance(dump_export_lines(), list)

    def test_set_flag_appears_in_output(self) -> None:
        os.environ[self._flag.name] = "export_test_value"
        lines = dump_export_lines()
        matching = [ln for ln in lines if self._flag.name in ln]
        self.assertGreater(len(matching), 0)
        self.assertIn("export_test_value", matching[0])

    def test_unset_flag_not_in_output(self) -> None:
        lines = dump_export_lines()
        self.assertFalse(any(self._flag.name in ln for ln in lines))

    def test_lines_have_export_prefix(self) -> None:
        os.environ[self._flag.name] = "value123"
        for line in dump_export_lines():
            self.assertTrue(line.startswith("export "), f"Bad line: {line}")


if __name__ == "__main__":
    unittest.main()
