# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for yggdrasim_common/card_backend.py pure utility functions.

Covers: normalize_card_backend, get_card_backend_source,
        get_sim_isdr_config_source, get_sim_eim_identity_source,
        get_sim_euicc_store_root_source, get_default_sim_profile_store_path,
        get_sim_profile_store_path_source.

The *source* functions inspect env vars and a persisted settings file.
Tests use environment variable overrides (with cleanup) to drive paths.
"""

from __future__ import annotations

import os
import unittest

from yggdrasim_common.card_backend import (
    CARD_BACKEND_ENV,
    CARD_BACKEND_READER,
    CARD_BACKEND_SIM,
    SETTING_SOURCE_DEFAULT,
    SETTING_SOURCE_SAVED_SELECTION,
    SETTING_SOURCE_SESSION_OVERRIDE,
    SIM_EIM_IDENTITY_ENV,
    SIM_EUICC_STORE_ENV,
    SIM_ISDR_CONFIG_ENV,
    SIM_PROFILE_STORE_ENV,
    SETTING_SOURCE_SAVED_OVERRIDE,
    SETTING_SOURCE_WORKSPACE_DEFAULT,
    SETTING_SOURCE_DERIVED_DEFAULT,
    get_card_backend_source,
    get_default_sim_profile_store_path,
    get_sim_eim_identity_source,
    get_sim_euicc_store_root_source,
    get_sim_isdr_config_source,
    get_sim_profile_store_path_source,
    normalize_card_backend,
)


# ---------------------------------------------------------------------------
# normalize_card_backend
# ---------------------------------------------------------------------------

class NormalizeCardBackendTests(unittest.TestCase):

    def test_reader_aliases(self) -> None:
        for alias in ("reader", "pcsc", "real", "physical", "card"):
            self.assertEqual(normalize_card_backend(alias), CARD_BACKEND_READER)

    def test_sim_aliases(self) -> None:
        for alias in ("sim", "simulated", "simulator", "virtual", "mock"):
            self.assertEqual(normalize_card_backend(alias), CARD_BACKEND_SIM)

    def test_empty_returns_default(self) -> None:
        self.assertEqual(normalize_card_backend(""), CARD_BACKEND_READER)

    def test_none_returns_default(self) -> None:
        self.assertEqual(normalize_card_backend(None), CARD_BACKEND_READER)

    def test_unknown_value_returns_default(self) -> None:
        self.assertEqual(normalize_card_backend("unknown_backend"), CARD_BACKEND_READER)

    def test_custom_default_used(self) -> None:
        self.assertEqual(normalize_card_backend("", default=CARD_BACKEND_SIM), CARD_BACKEND_SIM)

    def test_case_insensitive(self) -> None:
        self.assertEqual(normalize_card_backend("READER"), CARD_BACKEND_READER)
        self.assertEqual(normalize_card_backend("SIM"), CARD_BACKEND_SIM)


# ---------------------------------------------------------------------------
# get_card_backend_source
# ---------------------------------------------------------------------------

class GetCardBackendSourceTests(unittest.TestCase):

    def setUp(self) -> None:
        self._saved = os.environ.pop(CARD_BACKEND_ENV, None)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(CARD_BACKEND_ENV, None)
        else:
            os.environ[CARD_BACKEND_ENV] = self._saved

    def test_returns_string(self) -> None:
        result = get_card_backend_source()
        self.assertIsInstance(result, str)

    def test_env_override_detected(self) -> None:
        os.environ[CARD_BACKEND_ENV] = CARD_BACKEND_SIM
        result = get_card_backend_source()
        self.assertIn(result, (
            SETTING_SOURCE_SESSION_OVERRIDE,
            SETTING_SOURCE_SAVED_SELECTION,
            SETTING_SOURCE_DEFAULT,
        ))


# ---------------------------------------------------------------------------
# get_sim_isdr_config_source
# ---------------------------------------------------------------------------

class GetSimIsdrConfigSourceTests(unittest.TestCase):

    def setUp(self) -> None:
        self._saved = os.environ.pop(SIM_ISDR_CONFIG_ENV, None)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(SIM_ISDR_CONFIG_ENV, None)
        else:
            os.environ[SIM_ISDR_CONFIG_ENV] = self._saved

    def test_no_env_returns_known_source(self) -> None:
        result = get_sim_isdr_config_source()
        self.assertIn(result, (
            SETTING_SOURCE_SAVED_OVERRIDE,
            SETTING_SOURCE_WORKSPACE_DEFAULT,
            SETTING_SOURCE_SESSION_OVERRIDE,
        ))

    def test_env_set_returns_session_override(self) -> None:
        os.environ[SIM_ISDR_CONFIG_ENV] = "/tmp/test_isdr.json"
        result = get_sim_isdr_config_source()
        self.assertEqual(result, SETTING_SOURCE_SESSION_OVERRIDE)


# ---------------------------------------------------------------------------
# get_sim_eim_identity_source
# ---------------------------------------------------------------------------

class GetSimEimIdentitySourceTests(unittest.TestCase):

    def setUp(self) -> None:
        self._saved = os.environ.pop(SIM_EIM_IDENTITY_ENV, None)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(SIM_EIM_IDENTITY_ENV, None)
        else:
            os.environ[SIM_EIM_IDENTITY_ENV] = self._saved

    def test_returns_string(self) -> None:
        result = get_sim_eim_identity_source()
        self.assertIsInstance(result, str)

    def test_env_set_gives_session_override(self) -> None:
        os.environ[SIM_EIM_IDENTITY_ENV] = "/tmp/test_eim.json"
        result = get_sim_eim_identity_source()
        self.assertEqual(result, SETTING_SOURCE_SESSION_OVERRIDE)


# ---------------------------------------------------------------------------
# get_sim_euicc_store_root_source
# ---------------------------------------------------------------------------

class GetSimEuiccStoreRootSourceTests(unittest.TestCase):

    def setUp(self) -> None:
        self._saved = os.environ.pop(SIM_EUICC_STORE_ENV, None)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(SIM_EUICC_STORE_ENV, None)
        else:
            os.environ[SIM_EUICC_STORE_ENV] = self._saved

    def test_returns_string(self) -> None:
        result = get_sim_euicc_store_root_source()
        self.assertIsInstance(result, str)

    def test_env_set_gives_session_override(self) -> None:
        os.environ[SIM_EUICC_STORE_ENV] = "/tmp/test_euicc_store"
        result = get_sim_euicc_store_root_source()
        self.assertEqual(result, SETTING_SOURCE_SESSION_OVERRIDE)


# ---------------------------------------------------------------------------
# get_default_sim_profile_store_path
# ---------------------------------------------------------------------------

class GetDefaultSimProfileStorePathTests(unittest.TestCase):

    def test_returns_non_empty_string(self) -> None:
        result = get_default_sim_profile_store_path()
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_path_is_absolute(self) -> None:
        result = get_default_sim_profile_store_path()
        self.assertTrue(os.path.isabs(result))


# ---------------------------------------------------------------------------
# get_sim_profile_store_path_source
# ---------------------------------------------------------------------------

class GetSimProfileStorePathSourceTests(unittest.TestCase):

    def setUp(self) -> None:
        self._saved = os.environ.pop(SIM_PROFILE_STORE_ENV, None)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(SIM_PROFILE_STORE_ENV, None)
        else:
            os.environ[SIM_PROFILE_STORE_ENV] = self._saved

    def test_returns_string(self) -> None:
        result = get_sim_profile_store_path_source()
        self.assertIsInstance(result, str)

    def test_env_set_gives_session_override(self) -> None:
        os.environ[SIM_PROFILE_STORE_ENV] = "/tmp/test_profile_store"
        result = get_sim_profile_store_path_source()
        self.assertEqual(result, SETTING_SOURCE_SESSION_OVERRIDE)

    def test_no_env_returns_derived_or_default(self) -> None:
        result = get_sim_profile_store_path_source()
        self.assertIn(result, (
            SETTING_SOURCE_DERIVED_DEFAULT,
            SETTING_SOURCE_SAVED_OVERRIDE,
        ))


if __name__ == "__main__":
    unittest.main()
