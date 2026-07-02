# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


MAIN_WRAPPER_PATH = Path(__file__).resolve().parent.parent / "main" / "main.py"
REPO_ROOT = MAIN_WRAPPER_PATH.parent.parent
MAIN_WRAPPER_SPEC = importlib.util.spec_from_file_location(
    "main_wrapper_card_bridge_module",
    MAIN_WRAPPER_PATH,
)
assert MAIN_WRAPPER_SPEC is not None
assert MAIN_WRAPPER_SPEC.loader is not None
main_wrapper = importlib.util.module_from_spec(MAIN_WRAPPER_SPEC)
sys.modules[MAIN_WRAPPER_SPEC.name] = main_wrapper
MAIN_WRAPPER_SPEC.loader.exec_module(main_wrapper)


class MainWrapperCardBridgeRouteTests(unittest.TestCase):
    def test_card_bridge_parser_accepts_daemon_flags(self) -> None:
        args = main_wrapper._build_cli_parser().parse_args(
            [
                "--card-bridge",
                "--card-bridge-host",
                "127.0.0.1",
                "--card-bridge-port",
                "8765",
                "--card-bridge-reader-index",
                "2",
                "--card-bridge-token-file",
                "/tmp/card.token",
                "--card-bridge-audit",
                "--card-bridge-audit-full-apdu",
                "--card-bridge-audit-logger-name",
                "demo.audit",
                "--card-bridge-apdu-timeout-ms",
                "12000",
                "--card-bridge-pcsc-share-mode",
                "exclusive",
            ]
        )

        self.assertTrue(args.card_bridge)
        self.assertEqual(args.card_bridge_host, "127.0.0.1")
        self.assertEqual(args.card_bridge_port, 8765)
        self.assertEqual(args.card_bridge_reader_index, 2)
        self.assertEqual(args.card_bridge_token_file, "/tmp/card.token")
        self.assertTrue(args.card_bridge_audit)
        self.assertTrue(args.card_bridge_audit_full_apdu)
        self.assertEqual(args.card_bridge_audit_logger_name, "demo.audit")
        self.assertEqual(args.card_bridge_apdu_timeout_ms, 12000)
        self.assertEqual(args.card_bridge_pcsc_share_mode, "exclusive")

    def test_card_bridge_route_translates_wrapper_flags_to_server_argv(self) -> None:
        args = main_wrapper._build_cli_parser().parse_args(
            [
                "--card-bridge",
                "--card-bridge-host",
                "127.0.0.1",
                "--card-bridge-port",
                "8765",
                "--card-bridge-reader-index",
                "9",
                "--card-bridge-reader-name",
                "ACR",
                "--card-bridge-token-file",
                "/tmp/card.token",
                "--card-bridge-audit",
                "--card-bridge-audit-full-apdu",
                "--card-bridge-audit-logger-name",
                "demo.audit",
                "--card-bridge-apdu-timeout-ms",
                "12000",
                "--card-bridge-pcsc-share-mode",
                "exclusive",
            ]
        )

        with mock.patch("Tools.CardBridge.server.main", return_value=17) as mocked_main:
            rc = main_wrapper._route_card_bridge_mode(args)

        self.assertEqual(rc, 17)
        mocked_main.assert_called_once_with(
            [
                "--host",
                "127.0.0.1",
                "--port",
                "8765",
                "--reader-name",
                "ACR",
                "--token-file",
                "/tmp/card.token",
                "--audit",
                "--audit-full-apdu",
                "--audit-logger-name",
                "demo.audit",
                "--apdu-timeout-ms",
                "12000",
                "--pcsc-share-mode",
                "exclusive",
            ]
        )

    def test_card_bridge_route_uses_reader_index_when_name_is_absent(self) -> None:
        args = main_wrapper._build_cli_parser().parse_args(
            [
                "--card-bridge",
                "--card-bridge-reader-index",
                "2",
                "--card-bridge-no-token",
            ]
        )

        with mock.patch("Tools.CardBridge.server.main", return_value=0) as mocked_main:
            rc = main_wrapper._route_card_bridge_mode(args)

        self.assertEqual(rc, 0)
        mocked_main.assert_called_once_with(["--reader-index", "2", "--no-token"])

    def test_run_cli_short_circuits_to_card_bridge_before_plugin_loading(self) -> None:
        with mock.patch("Tools.CardBridge.server.main", return_value=0) as mocked_main:
            with mock.patch.object(main_wrapper, "ensure_plugins_loaded") as mocked_plugins:
                with mock.patch.object(
                    main_wrapper,
                    "_apply_remote_card_arguments_with_log",
                ) as mocked_remote:
                    rc = main_wrapper.run_cli(["--card-bridge", "--card-bridge-no-token"])

        self.assertEqual(rc, 0)
        mocked_main.assert_called_once_with(["--no-token"])
        mocked_plugins.assert_not_called()
        mocked_remote.assert_not_called()

    def test_card_bridge_route_rejects_gui_combination(self) -> None:
        args = main_wrapper._build_cli_parser().parse_args(["--card-bridge", "--gui"])

        with mock.patch("Tools.CardBridge.server.main") as mocked_main:
            rc = main_wrapper._route_card_bridge_mode(args)

        self.assertEqual(rc, 2)
        mocked_main.assert_not_called()

    def test_main_menu_routes_card_bridge_page(self) -> None:
        with mock.patch.object(main_wrapper, "manage_card_bridge") as mocked_manage:
            main_wrapper._dispatch_main_menu_choice("CB")

        mocked_manage.assert_called_once_with()

    def test_remote_rig_guided_start_uses_gui_orchestration_action(self) -> None:
        payload = {
            "ok": True,
            "note": "Remote HIL rig is ready.",
            "steps": [
                {
                    "name": "pc_bridge_verify",
                    "ok": True,
                    "token_file": "/tmp/bridge.token",
                }
            ],
            "lines": [{"key": "PC CardBridge", "value": "running"}],
        }
        user_inputs = [
            "pi@rpi-host",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
        ]

        with mock.patch.dict(main_wrapper.os.environ, {}, clear=True):
            with mock.patch.object(main_wrapper, "clear_screen"):
                with mock.patch.object(main_wrapper, "pause"):
                    with mock.patch("builtins.input", side_effect=user_inputs):
                        with mock.patch.object(
                            main_wrapper,
                            "_run_card_bridge_action",
                            return_value=payload,
                        ) as mocked_action:
                            main_wrapper._prompt_card_bridge_remote_rig_start()

            self.assertEqual(
                main_wrapper.os.environ[main_wrapper.CARD_RELAY_URL_ENV],
                "http://127.0.0.1:8642/apdu",
            )
            self.assertEqual(
                main_wrapper.os.environ[main_wrapper.CARD_RELAY_TOKEN_FILE_ENV],
                "/tmp/bridge.token",
            )

        action_id, action_inputs = mocked_action.call_args.args
        self.assertEqual(action_id, "card_bridge.remote_rig_start")
        self.assertEqual(action_inputs["ssh_target"], "pi@rpi-host")
        self.assertEqual(action_inputs["local_card_port"], 8642)
        self.assertEqual(action_inputs["remote_card_port"], 8642)
        self.assertEqual(action_inputs["remote_card_url"], "http://127.0.0.1:8642/apdu")
        self.assertEqual(
            action_inputs["remote_token_file"],
            "~/.config/yggdrasim/card_bridge/8642.token",
        )
        self.assertTrue(action_inputs["install_service"])
        self.assertTrue(action_inputs["restart_processes"])
        self.assertTrue(action_inputs["confirm"])


class CardBridgePackagingSpecTests(unittest.TestCase):
    def test_clean_bundle_keeps_card_bridge_and_minimal_relay_helpers(self) -> None:
        spec_text = (REPO_ROOT / "yggdrasim_main.spec").read_text(encoding="utf-8")
        self.assertIn('"Tools.CardBridge"', spec_text)
        self.assertIn('"Tools.HilBridge.apdu_relay"', spec_text)
        self.assertIn('"Tools.HilBridge.pcsc"', spec_text)

        excludes_block = spec_text.split("excludes.extend([", 1)[1].split("])", 1)[0]
        self.assertIn('"Tools.HilBridge.main"', excludes_block)
        self.assertIn('"Tools.HilBridge.supervisor"', excludes_block)
        self.assertNotIn('"Tools.HilBridge",', excludes_block)
        self.assertNotIn('"Tools.HilBridge.apdu_relay"', excludes_block)
        self.assertNotIn('"Tools.HilBridge.pcsc"', excludes_block)

    def test_bundle_collects_pysim_asn1_resources(self) -> None:
        spec_text = (REPO_ROOT / "yggdrasim_main.spec").read_text(encoding="utf-8")
        self.assertIn("collect_data_files", spec_text)
        self.assertIn('"pySim"', spec_text)
        self.assertIn('"esim/asn1/**/*"', spec_text)


if __name__ == "__main__":
    unittest.main()
