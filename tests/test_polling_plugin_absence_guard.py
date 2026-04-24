"""Plugin-absence guard tests.

These tests lock in the invariant that the core tree must remain
functional when the polling plugin is not installed. The patentable
Wi‑Fi / Ethernet polling bridge lives exclusively in
``plugins/polling/``; removing that tree must leave the simulated UICC
behaving as a vanilla ISO 7816 card (STK framework only, no DNS / TLS /
HTTP emulation).

The suite is intentionally narrow:

* Core ``SIMCARD.toolkit`` does not ship any IPAE‑specific attribute.
* ``SimToolkitState`` has no ``eim_poll_*`` fields.
* ``yggdrasim_common.polling_plugin_support.require_polling_plugin``
  fails with a descriptive ``RuntimeError`` when the plugin is missing.
* ``EimLocalShell`` stubs raise a clear ``RuntimeError`` on plugin‑only
  surfaces (``IPAD-LIVE``, ``IPAD-TEST``) without crashing the shell.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest import mock


class CoreWithoutPollingPluginTests(unittest.TestCase):

    def setUp(self) -> None:
        # Ensure SimulatedSimCardEngine can load quirks inside the
        # test sandbox; this flag is orthogonal to the plugin gate.
        os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

    def tearDown(self) -> None:
        # Reset the cached plugin manager so later test suites can
        # observe the real (plugin-present) layout again. Mutating a
        # process-global via a class-method test was too sharp.
        from yggdrasim_common import plugin_runtime

        plugin_runtime.reset_plugin_manager_for_tests()

    def test_simulated_toolkit_has_no_ipae_surface_without_plugin(self) -> None:
        with mock.patch.dict(os.environ, {"YGGDRASIM_DISALLOW_PLUGINS": "1"}):
            # Import inside the gate so the plugin discovery runs with
            # the hard-lock flag active.
            from yggdrasim_common import plugin_runtime

            plugin_runtime.reset_plugin_manager_for_tests()

            from SIMCARD.engine import SimulatedSimCardEngine

            engine = SimulatedSimCardEngine()

        self.assertEqual(len(engine.toolkit._extensions), 0)
        self.assertFalse(hasattr(engine.toolkit, "set_localized_poll_bridge"))
        self.assertFalse(hasattr(engine.toolkit, "_localized_poll_bridge"))

    def test_sim_toolkit_state_has_no_eim_poll_fields(self) -> None:
        from SIMCARD.state import SimToolkitState

        state = SimToolkitState()
        offenders = [
            name
            for name in vars(state).keys()
            if name.startswith("eim_poll_") or name.endswith("_eim_poll")
        ]
        self.assertEqual(offenders, [])

    def test_require_polling_plugin_raises_without_capability(self) -> None:
        from yggdrasim_common import polling_plugin_support

        with mock.patch.object(
            polling_plugin_support,
            "get_capability",
            return_value=None,
        ):
            with self.assertRaisesRegex(RuntimeError, "Polling capability is not installed"):
                polling_plugin_support.require_polling_plugin()

    def test_shell_ipad_commands_raise_runtime_error_without_plugin(self) -> None:
        os.environ["YGGDRASIM_EIM_LOCAL_ROOT"] = tempfile.mkdtemp(prefix="eim_absence_")
        with mock.patch.dict(os.environ, {"YGGDRASIM_DISALLOW_PLUGINS": "1"}):
            from yggdrasim_common import plugin_runtime

            plugin_runtime.reset_plugin_manager_for_tests()

            # Import inside the gate so the shell sees the absence.
            for module_name in list(sys.modules.keys()):
                if module_name.startswith("SCP11.eim_local.main"):
                    del sys.modules[module_name]

            from SCP11.eim_local import main as eim_main

            eim_main.EimLocalShell._setup_readline = lambda self: None  # type: ignore[assignment]
            shell = eim_main.EimLocalShell()

        self.assertFalse(getattr(shell, "_polling_plugin_shell_attached", False))
        self.assertEqual(shell._bridge_status_payload(), {})
        self.assertIsNone(shell._stop_poll_bridge())

        with self.assertRaisesRegex(RuntimeError, "polling plugin"):
            shell._commands["IPAD-LIVE"]("")
        with self.assertRaisesRegex(RuntimeError, "polling plugin"):
            shell._commands["IPAD-TEST"]("")


if __name__ == "__main__":
    unittest.main()
