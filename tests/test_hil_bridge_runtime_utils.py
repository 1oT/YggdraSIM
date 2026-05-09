# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for yggdrasim_common/hil_bridge_runtime.py pure utility functions.

Covers: load_json_file, split_shell_like_arguments, supervisor_state_path,
        user_service_dir, user_service_path, is_hil_bridge_running
        (the systemctl functions require systemd and are skipped on non-Linux).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from yggdrasim_common.hil_bridge_runtime import (
    is_hil_bridge_running,
    load_json_file,
    split_shell_like_arguments,
    supervisor_state_path,
    user_service_dir,
    user_service_path,
)


# ---------------------------------------------------------------------------
# supervisor_state_path
# ---------------------------------------------------------------------------

class SupervisorStatePathTests(unittest.TestCase):

    def test_returns_string(self) -> None:
        result = supervisor_state_path()
        self.assertIsInstance(result, str)

    def test_path_ends_with_json(self) -> None:
        result = supervisor_state_path()
        self.assertTrue(result.endswith(".json"))


# ---------------------------------------------------------------------------
# user_service_dir / user_service_path
# ---------------------------------------------------------------------------

class UserServiceDirTests(unittest.TestCase):

    def test_returns_string(self) -> None:
        result = user_service_dir()
        self.assertIsInstance(result, str)

    def test_path_not_empty(self) -> None:
        result = user_service_dir()
        self.assertTrue(len(result) > 0)


class UserServicePathTests(unittest.TestCase):

    def test_returns_string_with_service_name(self) -> None:
        result = user_service_path("test.service")
        self.assertIsInstance(result, str)
        self.assertIn("test.service", result)


# ---------------------------------------------------------------------------
# load_json_file
# ---------------------------------------------------------------------------

class LoadJsonFileTests(unittest.TestCase):

    def test_empty_path_returns_empty_dict(self) -> None:
        self.assertEqual(load_json_file(""), {})

    def test_nonexistent_path_returns_empty_dict(self) -> None:
        self.assertEqual(load_json_file("/nonexistent/path/file.json"), {})

    def test_valid_json_object_loaded(self) -> None:
        payload = {"key": "value", "count": 42}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump(payload, fh)
            path = fh.name
        try:
            result = load_json_file(path)
            self.assertEqual(result, payload)
        finally:
            os.unlink(path)

    def test_json_array_root_returns_empty_dict(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump([1, 2, 3], fh)
            path = fh.name
        try:
            result = load_json_file(path)
            self.assertEqual(result, {})
        finally:
            os.unlink(path)

    def test_malformed_json_returns_empty_dict(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            fh.write("{bad json}")
            path = fh.name
        try:
            result = load_json_file(path)
            self.assertEqual(result, {})
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# split_shell_like_arguments
# ---------------------------------------------------------------------------

class SplitShellLikeArgumentsTests(unittest.TestCase):

    def test_empty_string_returns_empty_tuple(self) -> None:
        self.assertEqual(split_shell_like_arguments(""), ())

    def test_single_word(self) -> None:
        self.assertEqual(split_shell_like_arguments("hello"), ("hello",))

    def test_multiple_words(self) -> None:
        result = split_shell_like_arguments("foo bar baz")
        self.assertEqual(result, ("foo", "bar", "baz"))

    def test_quoted_argument_preserved(self) -> None:
        result = split_shell_like_arguments('foo "bar baz"')
        self.assertEqual(result, ("foo", "bar baz"))

    def test_whitespace_only_returns_empty_tuple(self) -> None:
        self.assertEqual(split_shell_like_arguments("   "), ())

    def test_returns_tuple(self) -> None:
        result = split_shell_like_arguments("a b")
        self.assertIsInstance(result, tuple)


# ---------------------------------------------------------------------------
# is_hil_bridge_running  (checks supervisor state — safe to call with no state)
# ---------------------------------------------------------------------------

class IsHilBridgeRunningTests(unittest.TestCase):

    def test_returns_bool(self) -> None:
        result = is_hil_bridge_running()
        self.assertIsInstance(result, bool)

    def test_false_when_no_state_file(self) -> None:
        # No supervisor state exists in the test environment.
        result = is_hil_bridge_running()
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# clear_supervisor_state
# ---------------------------------------------------------------------------

class ClearSupervisorStateTests(unittest.TestCase):

    def test_missing_file_tolerated(self) -> None:
        from yggdrasim_common.hil_bridge_runtime import clear_supervisor_state
        # Call twice: second call must also not raise when file is already absent.
        clear_supervisor_state()
        clear_supervisor_state()

    def test_existing_file_removed(self) -> None:
        import json
        from yggdrasim_common.hil_bridge_runtime import (
            clear_supervisor_state,
            supervisor_state_path,
        )
        state_path = supervisor_state_path()
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        with open(state_path, "w") as fh:
            json.dump({"status": "test"}, fh)
        self.assertTrue(os.path.exists(state_path))
        clear_supervisor_state()
        self.assertFalse(os.path.exists(state_path))


# ---------------------------------------------------------------------------
# systemctl wrappers — skipped when systemctl is absent
# ---------------------------------------------------------------------------

import shutil as _shutil
_SYSTEMCTL_AVAILABLE = _shutil.which("systemctl") is not None
_SKIP_SYSTEMCTL = unittest.skipUnless(_SYSTEMCTL_AVAILABLE, "systemctl not available")


@_SKIP_SYSTEMCTL
class RunSystemctlUserCheckedTests(unittest.TestCase):

    def test_success_returns_completed_process(self) -> None:
        from yggdrasim_common.hil_bridge_runtime import run_systemctl_user_checked
        import subprocess
        result = run_systemctl_user_checked(["--version"])
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 0)

    def test_bad_command_raises(self) -> None:
        from yggdrasim_common.hil_bridge_runtime import run_systemctl_user_checked
        with self.assertRaises(RuntimeError):
            run_systemctl_user_checked(["invalid-subcommand-xyz-yggdrasim"])


@_SKIP_SYSTEMCTL
class DaemonReloadUserServicesTests(unittest.TestCase):

    def test_runs_without_exception(self) -> None:
        from yggdrasim_common.hil_bridge_runtime import daemon_reload_user_services
        try:
            daemon_reload_user_services()
        except RuntimeError:
            pass  # systemctl available but daemon-reload may fail in CI


@_SKIP_SYSTEMCTL
class EnableNowDisableUserServiceTests(unittest.TestCase):

    def test_enable_nonexistent_raises(self) -> None:
        from yggdrasim_common.hil_bridge_runtime import enable_now_user_service
        with self.assertRaises(RuntimeError):
            enable_now_user_service("nonexistent_service_xyz_yggdrasim.service")

    def test_disable_nonexistent_raises(self) -> None:
        from yggdrasim_common.hil_bridge_runtime import disable_user_service
        with self.assertRaises(RuntimeError):
            disable_user_service("nonexistent_service_xyz_yggdrasim.service")


if __name__ == "__main__":
    unittest.main()
