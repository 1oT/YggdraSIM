import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from yggdrasim_common.quit_control import QuitAllRequested
from Tools.ProfilePackage.saip_tool import SaipCommandResult
from Tools.ProfilePackage.shell import ProfilePackageShell


class ProfilePackageShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        workspace_root = Path(self._temp_workspace.name)
        self.shell = ProfilePackageShell(workspace_root=workspace_root)

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_cmd_status_uses_concise_profile_summary(self) -> None:
        self.shell.bridge.current_input_file = (
            self.shell.bridge.workspace_root
            / "Tools"
            / "ProfilePackage"
            / "profile"
            / "demo_profile.der"
        )

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            self.shell._cmd_status("")

        text = captured.getvalue()
        self.assertIn("Active profile: Tools/ProfilePackage/profile/demo_profile.der", text)
        self.assertNotIn("tool=", text)
        self.assertNotIn("profile-dir=", text)

    def test_cmd_tool_without_argument_shows_tool_command_only(self) -> None:
        self.shell.bridge._tool_command = ["saip-tool.py", "--demo"]

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            self.shell._cmd_tool("")

        text = captured.getvalue()
        self.assertIn("Tool command: saip-tool.py --demo", text)
        self.assertNotIn("Active profile:", text)

    def test_render_result_stdout_formats_decoded_dump(self) -> None:
        stdout = "\n".join(
            [
                "Read 2 PEs from file '/tmp/demo.der'",
                "====================================================================== header",
                "{'iccid': '8931086226015334408f', 'profileType': 'Demo Profile'}",
                "====================================================================== usim",
                "{'ef-imsi': [('fillFileContent', '082940808023551096')], 'templateID': '2.23.143.1.2.4'}",
            ]
        )
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "dump", "--dump-decoded", "all_pe"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )

        rendered = self.shell._render_result_stdout(result)

        self.assertIn("=== HEADER ===", rendered)
        self.assertIn("=== USIM ===", rendered)
        self.assertIn("iccid", rendered)
        self.assertIn("profileType", rendered)
        self.assertIn("fillFileContent", rendered)

    def test_render_result_stdout_aligns_mapping_columns(self) -> None:
        stdout = "\n".join(
            [
                "Read 1 PEs from file '/tmp/demo.der'",
                "====================================================================== header",
                "{'short': 'A', 'muchLongerKeyName': 'B'}",
            ]
        )
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "dump", "--dump-decoded", "all_pe"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )

        rendered = self.shell._render_result_stdout(result)
        content_lines = [
            line for line in rendered.splitlines() if "| short" in line or "| muchLongerKeyName" in line
        ]

        self.assertEqual(len(content_lines), 2)
        colon_positions = [line.index(":") for line in content_lines]
        self.assertEqual(colon_positions[0], colon_positions[1])

    def test_render_result_stdout_pads_block_headers_with_sibling_width(self) -> None:
        stdout = "\n".join(
            [
                "Read 1 PEs from file '/tmp/demo.der'",
                "====================================================================== securityDomain",
                "{'sd-Header': {'identification': 17, 'mandated': None}, 'sdPersoData': '00112233'}",
            ]
        )
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "dump", "--dump-decoded", "all_pe"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )

        rendered = self.shell._render_result_stdout(result)

        self.assertIn("| sd-Header   ", rendered)
        self.assertIn("| sdPersoData", rendered)
        self.assertIn(": 00112233", rendered)

    def test_render_result_stdout_decodes_special_saip_fields(self) -> None:
        stdout = "\n".join(
            [
                "Read 1 PEs from file '/tmp/demo.der'",
                "====================================================================== header",
                "{'connectivityParameters': 'a118350702000003000002470d085465726d696e616c0361706ea00f0607918406010092f88101008201f6'}",
                "====================================================================== securityDomain",
                "{'instance': {'applicationSpecificParametersC9': '81028000810203708201f08701f0', 'applicationParameters': {'uiccToolkitApplicationSpecificParametersField': '0100010100000202011606b2010000000000'}}, 'sdPersoData': ['00707a8578841c010301400102028182350103390205dc3c030227be3e05210a0a0a0a8517133839343435303136303532343637363333363202400186070003a50300200089368a0d3133392e3136322e31352e36338b13383931303330303030303030363835333633338c102f67736d612f61646d696e6167656e74']}",
            ]
        )
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "dump", "--dump-decoded", "all_pe"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )

        rendered = self.shell._render_result_stdout(result)

        self.assertIn("Network Access Name", rendered)
        self.assertIn("Terminal.apn", rendered)
        self.assertIn("UICC SCP", rendered)
        self.assertIn("SCP80", rendered)
        self.assertIn("SCP03", rendered)
        self.assertIn("minimumSecurityLevelInferred", rendered)
        self.assertIn("b20100", rendered)
        self.assertIn("10.10.10.10", rendered)
        self.assertIn("Remote Endpoint", rendered)
        self.assertIn("identifierAscii", rendered)
        self.assertIn("8944501605246763362", rendered)
        self.assertIn("setBits", rendered)
        self.assertIn("/gsma/adminagent", rendered)

    def test_render_result_stdout_keeps_non_dump_output(self) -> None:
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "tree"],
            returncode=0,
            stdout="plain tree output\n",
            stderr="",
        )

        rendered = self.shell._render_result_stdout(result)

        self.assertEqual(rendered, "plain tree output\n")

    def test_cmd_dump_writes_yaml_output_to_file(self) -> None:
        stdout = "\n".join(
            [
                "Read 1 PEs from file '/tmp/demo.der'",
                "====================================================================== header",
                "{'iccid': '8931086226015334408f'}",
            ]
        )
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "dump", "--dump-decoded", "all_pe"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )

        self.shell.bridge.current_input_file = self.shell.bridge.workspace_root / "demo.der"
        self.shell.bridge.run_current = lambda _args: result

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "decoded_dump.yaml"
            with contextlib.redirect_stdout(io.StringIO()):
                self.shell._cmd_dump(f'ALL DECODED > "{output_path}"')

            file_text = output_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(file_text)

        self.assertEqual(parsed["sections"]["header"]["iccid"], "8931086226015334408f")
        self.assertEqual(parsed["intro"], ["Read 1 PEs from file '/tmp/demo.der'"])
        self.assertNotIn("\033[", file_text)

    def test_cmd_dump_writes_json_output_when_requested(self) -> None:
        stdout = "\n".join(
            [
                "Read 1 PEs from file '/tmp/demo.der'",
                "====================================================================== usim",
                "{'templateID': '2.23.143.1.2.4', 'ef-imsi': [('fillFileContent', '082940808023551096')]}",
            ]
        )
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "dump", "--dump-decoded", "all_pe"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )

        self.shell.bridge.current_input_file = self.shell.bridge.workspace_root / "demo.der"
        self.shell.bridge.run_current = lambda _args: result

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "decoded_dump.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.shell._cmd_dump(f'ALL DECODED > "{output_path}"')

            parsed = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(parsed["sections"]["usim"]["templateID"], "2.23.143.1.2.4")
        self.assertEqual(parsed["sections"]["usim"]["ef-imsi"][0]["kind"], "fillFileContent")
        self.assertEqual(parsed["sections"]["usim"]["ef-imsi"][0]["value"], "082940808023551096")

    def test_cmd_dump_yaml_keeps_full_hex_without_truncation(self) -> None:
        stdout = "\n".join(
            [
                "Read 1 PEs from file '/tmp/demo.der'",
                "====================================================================== header",
                "{'connectivityParameters': 'truncated-in-cli'}",
            ]
        )
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "dump", "--dump-decoded", "all_pe"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )

        full_bytes = bytes.fromhex(
            "A118350702000003000002470D085465726D696E616C0361706EA00F0607918406010092F88101008201F6"
        )
        self.shell.bridge.current_input_file = self.shell.bridge.workspace_root / "demo.der"
        self.shell.bridge.run_current = lambda _args: result
        self.shell.bridge.build_decoded_dump_document = lambda _mode: {
            "intro": ["Read 1 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "connectivityParameters": full_bytes,
                }
            },
        }

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "decoded_dump.yaml"
            with contextlib.redirect_stdout(io.StringIO()):
                self.shell._cmd_dump(f'ALL DECODED > "{output_path}"')

            file_text = output_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(file_text)

        expected_hex = full_bytes.hex()
        self.assertIn(expected_hex, file_text)
        self.assertNotIn("...", file_text)
        self.assertEqual(parsed["sections"]["header"]["connectivityParameters"]["raw"], expected_hex)
        self.assertIn("decoded", parsed["sections"]["header"]["connectivityParameters"])

    def test_normalize_dump_value_wraps_special_saip_fields_with_raw_and_decoded(self) -> None:
        normalized = self.shell._normalize_dump_value(
            {
                "connectivityParameters": "a118350702000003000002470d085465726d696e616c0361706ea00f0607918406010092f88101008201f6",
                "applicationPrivileges": "82dc20",
                "lifeCycleState": "0f",
                "applicationSpecificParametersC9": "81028000810203708201f08701f0",
                "keyList": [
                    {
                        "keyUsageQualifier": "38",
                        "keyAccess": "01",
                        "keyIdentifier": "01",
                        "keyVersionNumber": "30",
                        "keyCounterValue": "0000000000",
                        "keyComponents": [
                            {
                                "keyType": "88",
                            }
                        ],
                    }
                ],
                "sdPersoData": [
                    "00707a8578841c010301400102028182350103390205dc3c030227be3e05210a0a0a0a8517133839343435303136303532343637363333363202400186070003a50300200089368a0d3133392e3136322e31352e36338b13383931303330303030303030363835333633338c102f67736d612f61646d696e6167656e74"
                ],
                "applicationParameters": {
                    "uiccToolkitApplicationSpecificParametersField": "0100010100000202011606b2010000000000"
                },
            }
        )

        connectivity = normalized["connectivityParameters"]
        self.assertEqual(connectivity["raw"], "a118350702000003000002470d085465726d696e616c0361706ea00f0607918406010092f88101008201f6")
        self.assertEqual(connectivity["decoded"]["format"], "BER-TLV")
        self.assertEqual(
            connectivity["decoded"]["items"][0]["items"][1]["decoded"],
            "Terminal.apn",
        )
        self.assertEqual(
            connectivity["decoded"]["items"][1]["name"],
            "Transport / Remote Parameters",
        )
        self.assertEqual(
            connectivity["decoded"]["items"][1]["items"][0]["raw"],
            "918406010092f8",
        )
        self.assertEqual(
            connectivity["decoded"]["items"][1]["items"][1]["decoded"]["decimal"],
            0,
        )

        app_c9 = normalized["applicationSpecificParametersC9"]
        self.assertEqual(app_c9["raw"], "81028000810203708201f08701f0")
        self.assertEqual(app_c9["decoded"]["items"][0]["decoded"]["scpName"], "SCP80")
        self.assertEqual(app_c9["decoded"]["items"][1]["decoded"]["scpName"], "SCP03")
        self.assertEqual(app_c9["decoded"]["items"][2]["decoded"]["setBits"], [7, 6, 5, 4])

        privileges = normalized["applicationPrivileges"]
        self.assertEqual(privileges["decoded"]["format"], "GlobalPlatform application privileges")
        self.assertIn("Security Domain", privileges["decoded"]["activePrivileges"])
        self.assertIn("Authorized Management", privileges["decoded"]["activePrivileges"])

        life_cycle_state = normalized["lifeCycleState"]
        self.assertEqual(life_cycle_state["decoded"]["state"], "Personalized")

        key_entry = normalized["keyList"][0]
        self.assertIn("Secure Messaging Command", key_entry["keyUsageQualifier"]["decoded"]["activeUsages"])
        self.assertEqual(
            key_entry["keyAccess"]["decoded"]["access"],
            "Security Domain only",
        )
        self.assertEqual(
            key_entry["keyIdentifier"]["decoded"]["commonRole"],
            "ENC (common SCP02/SCP03 convention)",
        )
        self.assertEqual(key_entry["keyVersionNumber"]["decoded"]["reservedFor"], "SCP03")
        self.assertEqual(key_entry["keyCounterValue"]["decoded"]["decimal"], 0)
        self.assertEqual(key_entry["keyComponents"][0]["keyType"]["decoded"]["type"], "AES")

        sd_perso = normalized["sdPersoData"]
        self.assertEqual(sd_perso["raw"][0], "00707a8578841c010301400102028182350103390205dc3c030227be3e05210a0a0a0a8517133839343435303136303532343637363333363202400186070003a50300200089368a0d3133392e3136322e31352e36338b13383931303330303030303030363835333633338c102f67736d612f61646d696e6167656e74")
        transport_parameters = sd_perso["decoded"][0]["items"][0]["decoded"][0]["decoded"][0]["decoded"]
        self.assertEqual(transport_parameters[0]["decoded"]["decimal"], 81921)
        self.assertEqual(transport_parameters[1]["decoded"]["hex"], "8182")
        identifier_block = sd_perso["decoded"][0]["items"][0]["decoded"][0]["decoded"][1]["decoded"]
        self.assertEqual(identifier_block["identifierAscii"], "8944501605246763362")
        self.assertEqual(identifier_block["trailerHex"], "024001")
        security_parameters = sd_perso["decoded"][0]["items"][0]["decoded"][0]["decoded"][2]["decoded"]
        self.assertEqual(security_parameters[0]["decoded"]["hex"], "a50300")
        self.assertTrue(security_parameters[1]["decoded"]["empty"])

        toolkit = normalized["applicationParameters"]["uiccToolkitApplicationSpecificParametersField"]
        self.assertEqual(toolkit["raw"], "0100010100000202011606b2010000000000")
        self.assertEqual(toolkit["decoded"]["format"], "ETSI TS 102 226 toolkit app specific parameters")
        self.assertEqual(toolkit["decoded"]["rawHex"], "0100010100000202011606b2010000000000")
        self.assertEqual(toolkit["decoded"]["accessDomain"], "00")
        self.assertEqual(toolkit["decoded"]["priorityLevelOfToolkitAppInstance"], 1)
        self.assertEqual(toolkit["decoded"]["maxNumberOfTimers"], 1)
        self.assertEqual(toolkit["decoded"]["maxNumberOfChannels"], 2)
        self.assertEqual(toolkit["decoded"]["minimumSecurityLevelRaw"], "0116")
        self.assertEqual(toolkit["decoded"]["tarValues"], ["b20100", "000000"])
        self.assertEqual(toolkit["decoded"]["trailingPadding"], "00")
        self.assertEqual(toolkit["decoded"]["minimumSecurityLevelInferred"], "0x16")
        self.assertEqual(toolkit["decoded"]["minimumSecurityLevelDecimal"], 22)
        self.assertEqual(toolkit["decoded"]["tarInferred"], "b20100")

    def test_normalize_dump_value_converts_mandatory_service_nulls_to_true(self) -> None:
        normalized = self.shell._normalize_dump_value(
            {
                "eUICC-Mandatory-services": {
                    "usim": None,
                    "milenage": None,
                }
            }
        )

        self.assertTrue(normalized["eUICC-Mandatory-services"]["usim"])
        self.assertTrue(normalized["eUICC-Mandatory-services"]["milenage"])

    def test_dump_output_redirection_rejects_outside_workspace_with_clear_message(self) -> None:
        with self.assertRaisesRegex(ValueError, "Output redirection is workspace-confined"):
            self.shell._parse_output_redirection(
                "ALL DECODED > /home/hampushellsberg/Documents/test_dump.txt"
            )

    def test_lint_output_redirection_rejects_outside_workspace_with_clear_message(self) -> None:
        with self.assertRaisesRegex(ValueError, "Output redirection is workspace-confined"):
            self.shell._parse_lint_output_redirection(
                "STRICT > /home/hampushellsberg/Documents/test_lint.yaml"
            )

    def test_complete_path_token_uses_default_profile_dir_for_bare_names(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            profile_dir = Path(temp_dir)
            self.shell.bridge.default_profile_dir = profile_dir
            (profile_dir / "alpha.der").write_text("demo", encoding="utf-8")
            (profile_dir / "beta.txt").write_text("ABCD", encoding="utf-8")
            (profile_dir / "beta.transcode.json").write_text("{}", encoding="utf-8")
            (profile_dir / "beta.transcode.der").write_bytes(b"\xAA")

            matches = self.shell._complete_path_token("")

        self.assertIn("alpha.der", matches)
        self.assertIn("beta.txt", matches)
        self.assertNotIn("beta.transcode.json", matches)
        self.assertNotIn("beta.transcode.der", matches)

    def test_cmd_profile_dir_sets_default_directory(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            target_dir = Path(temp_dir) / "profiles"
            target_dir.mkdir(parents=True, exist_ok=True)
            profile_file = target_dir / "auto_profile.txt"
            profile_file.write_text("A0B1", encoding="utf-8")
            self.shell._cmd_profile_dir(str(target_dir))

            self.assertEqual(self.shell.bridge.default_profile_dir, target_dir.resolve())
            self.assertTrue(target_dir.exists())
            self.assertEqual(self.shell.bridge.current_input_file, profile_file.resolve())

    def test_shell_auto_loads_single_visible_profile(self) -> None:
        workspace_root = self.shell.bridge.workspace_root
        profile_dir = workspace_root / "Tools" / "ProfilePackage" / "profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / ".gitkeep").write_text("", encoding="utf-8")
        profile_file = profile_dir / "only_profile.txt"
        profile_file.write_text("A0B1", encoding="utf-8")

        shell = ProfilePackageShell(workspace_root=workspace_root)

        self.assertEqual(shell.bridge.current_input_file, profile_file.resolve())
        self.assertEqual([path.name for path in shell._startup_profiles], ["only_profile.txt"])

    def test_banner_lists_profiles_found_in_default_directory(self) -> None:
        workspace_root = self.shell.bridge.workspace_root
        profile_dir = workspace_root / "Tools" / "ProfilePackage" / "profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "alpha.txt").write_text("AA", encoding="utf-8")
        (profile_dir / "beta.der").write_text("BB", encoding="utf-8")
        (profile_dir / "beta.transcode.json").write_text("{}", encoding="utf-8")

        shell = ProfilePackageShell(workspace_root=workspace_root)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            shell._print_banner()

        banner_text = output.getvalue()

        self.assertIn("Default transcode dir:", banner_text)
        self.assertIn("Profiles in default dir:", banner_text)
        self.assertIn("alpha.txt", banner_text)
        self.assertIn("beta.der", banner_text)
        self.assertNotIn("beta.transcode.json", banner_text)

    def test_use_accepts_home_path_missing_leading_slash_for_existing_input(self) -> None:
        actual_profile = (
            Path(__file__).resolve().parents[1]
            / "Tools"
            / "ProfilePackage"
            / "profile"
            / "reference_test_profile.txt"
        ).resolve()
        missing_slash_text = str(actual_profile).lstrip("/")

        selected = self.shell.bridge.set_input_file(missing_slash_text)

        self.assertEqual(selected, actual_profile)

    def test_cmd_transcode_tui_reports_invalid_profile_asn1(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        shell = ProfilePackageShell(workspace_root=workspace_root)
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            invalid_profile = Path(temp_dir) / "invalid_profile.der"
            invalid_profile.write_bytes(b"\xDE\xAD\xBE\xEF")
            shell.bridge.set_input_file(str(invalid_profile))

            with contextlib.redirect_stdout(io.StringIO()) as captured:
                shell._cmd_transcode_tui("")

        rendered = captured.getvalue()
        self.assertIn("Profile ASN1 is not valid.", rendered)

    def test_cmd_lint_writes_json_report(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "iccid": "8944501234567890123F",
                    "profileType": "demo",
                    "eUICC-Mandatory-services": {},
                    "identification": 1,
                },
                "mf": {"identification": 2},
                "end": {"identification": 3},
            },
        }
        check_result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "check"],
            returncode=0,
            stdout="All good!\n",
            stderr="",
        )
        self.shell.bridge.current_input_file = self.shell.bridge.workspace_root / "demo.der"
        self.shell.bridge.build_decoded_dump_document = lambda _mode: decoded_document
        self.shell.bridge.run_current = lambda _args: check_result

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "profile_lint.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.shell._cmd_lint(f'STRICT > "{output_path}"')

            parsed = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertTrue(parsed["strict"])
        self.assertIn("summary", parsed)
        self.assertIn("findings", parsed)

    def test_cmd_lint_with_gate_writes_gate_block(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "iccid": "8944501234567890123F",
                    "profileType": "demo",
                    "eUICC-Mandatory-services": {"usim": True},
                    "identification": 1,
                },
                "mf": {"identification": 2},
                "end": {"identification": 3},
            },
        }
        check_result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "check"],
            returncode=0,
            stdout="All good!\n",
            stderr="",
        )
        self.shell.bridge.current_input_file = self.shell.bridge.workspace_root / "demo.der"
        self.shell.bridge.build_decoded_dump_document = lambda _mode: decoded_document
        self.shell.bridge.run_current = lambda _args: check_result

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "profile_lint_gate.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.shell._cmd_lint(f'GATE YRL-SVC MIN-SCORE 95 > "{output_path}"')
            parsed = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertIn("gate", parsed)
        self.assertFalse(parsed["gate"]["passed"])

    def test_cmd_lint_enforce_raises_system_exit_when_gate_fails(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "iccid": "8944501234567890123F",
                    "profileType": "demo",
                    "eUICC-Mandatory-services": {"usim": True},
                    "identification": 1,
                },
                "mf": {"identification": 2},
                "end": {"identification": 3},
            },
        }
        check_result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "check"],
            returncode=0,
            stdout="All good!\n",
            stderr="",
        )
        self.shell.bridge.current_input_file = self.shell.bridge.workspace_root / "demo.der"
        self.shell.bridge.build_decoded_dump_document = lambda _mode: decoded_document
        self.shell.bridge.run_current = lambda _args: check_result

        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(io.StringIO()):
                self.shell._cmd_lint("GATE YRL-SVC ENFORCE")

    def test_cmd_lint_help_prints_option_help(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_lint("HELP")
        rendered = buffer.getvalue()
        self.assertIn("LINT options:", rendered)
        self.assertIn("PROFILE <name>", rendered)

    def test_cmd_lint_profiles_prints_presets(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_lint("PROFILES")
        rendered = buffer.getvalue()
        self.assertIn("STRICT-FS", rendered)
        self.assertIn("RELEASE-GATE", rendered)

    def test_cmd_quit_all_raises_quit_all_requested(self) -> None:
        with self.assertRaises(QuitAllRequested):
            self.shell._cmd_quit_all("")

    def test_cmd_lint_profile_preset_applies_gate(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "iccid": "8944501234567890123F",
                    "profileType": "demo",
                    "eUICC-Mandatory-services": {"usim": True},
                    "identification": 1,
                },
                "mf": {"identification": 2},
                "end": {"identification": 3},
            },
        }
        check_result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "check"],
            returncode=0,
            stdout="All good!\n",
            stderr="",
        )
        self.shell.bridge.current_input_file = self.shell.bridge.workspace_root / "demo.der"
        self.shell.bridge.build_decoded_dump_document = lambda _mode: decoded_document
        self.shell.bridge.run_current = lambda _args: check_result

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "profile_lint_profile_gate.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.shell._cmd_lint(f'PROFILE RELEASE-GATE > "{output_path}"')
            parsed = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(parsed["lint_profile"], "RELEASE-GATE")
        self.assertIn("gate", parsed)

if __name__ == "__main__":
    unittest.main()
