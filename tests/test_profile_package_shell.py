import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
            / "Workspace"
            / "SAIP"
            / "profile"
            / "demo_profile.der"
        )

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            self.shell._cmd_status("")

        text = captured.getvalue()
        self.assertIn("Active profile: Workspace/SAIP/profile/demo_profile.der", text)
        self.assertNotIn("tool=", text)
        self.assertNotIn("profile-dir=", text)

    def test_cmd_tool_without_argument_shows_tool_command_only(self) -> None:
        self.shell.bridge._tool_command = ["saip-tool.py", "--demo"]

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            self.shell._cmd_tool("")

        text = captured.getvalue()
        self.assertIn("Tool command: saip-tool.py --demo", text)
        self.assertNotIn("Active profile:", text)

    def test_cmd_open_without_argument_uses_tui_picker_and_launches_inspect(self) -> None:
        selected_path = self.shell.bridge.workspace_root / "Workspace" / "SAIP" / "profile" / "picked.der"
        selected_path.parent.mkdir(parents=True, exist_ok=True)
        selected_path.write_bytes(b"\x01\x02")

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            with mock.patch(
                "Tools.ProfilePackage.saip_open_picker_tui.pick_saip_profile_path_tui",
                return_value=selected_path,
            ) as mocked_pick:
                with mock.patch.object(self.shell, "_cmd_inspect") as mocked_inspect:
                    self.shell._cmd_open("")

        text = captured.getvalue()
        mocked_pick.assert_called_once_with(self.shell.bridge)
        mocked_inspect.assert_called_once_with("")
        self.assertIn("Active profile package", text)
        self.assertIn(str(selected_path), text)

    def test_cmd_open_without_argument_reports_cancelled_picker(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            with mock.patch(
                "Tools.ProfilePackage.saip_open_picker_tui.pick_saip_profile_path_tui",
                return_value=None,
            ):
                with mock.patch.object(self.shell, "_cmd_inspect") as mocked_inspect:
                    self.shell._cmd_open("")

        text = captured.getvalue()
        mocked_inspect.assert_not_called()
        self.assertIn("File selection cancelled", text)

    def test_cmd_open_with_argument_selects_file_and_launches_inspect(self) -> None:
        selected_path = self.shell.bridge.workspace_root / "Workspace" / "SAIP" / "profile" / "picked.der"
        selected_path.parent.mkdir(parents=True, exist_ok=True)
        selected_path.write_bytes(b"\x01\x02")

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            with mock.patch.object(self.shell, "_cmd_inspect") as mocked_inspect:
                self.shell._cmd_open(str(selected_path))

        text = captured.getvalue()
        mocked_inspect.assert_called_once_with("")
        self.assertIn("Active profile package", text)
        self.assertIn(str(selected_path), text)

    def test_exec_line_dispatches_tui_command(self) -> None:
        recorded: list[str] = []
        self.shell._commands["TUI"] = lambda argument: recorded.append(argument)

        succeeded = self.shell._exec_line("TUI")

        self.assertTrue(succeeded)
        self.assertEqual(recorded, [""])

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

        self.assertEqual(parsed["sections"]["header"]["iccid"]["raw"], "8931086226015334408f")
        self.assertEqual(parsed["sections"]["header"]["iccid"]["decoded"]["iccid"], "8931086226015334408")
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
                "pinCodes": [
                    {
                        "maxNumOfAttemps-retryNumLeft": 51,
                    }
                ],
                "pukCodes": [
                    {
                        "maxNumOfAttemps-retryNumLeft": 170,
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
        self.assertEqual(connectivity["decoded"]["format"], "TCA SAIP Connectivity Parameters")
        self.assertEqual(
            connectivity["decoded"]["items"][0]["items"][1]["decoded"]["name"],
            "Terminal.apn",
        )
        self.assertEqual(
            connectivity["decoded"]["items"][1]["name"],
            "SMS Connectivity (A0)",
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
            "KIC (SCP80) / ENC (common SCP02/SCP03 convention)",
        )
        self.assertEqual(key_entry["keyVersionNumber"]["decoded"]["reservedFor"], "SCP03")
        self.assertEqual(key_entry["keyCounterValue"]["decoded"]["decimal"], 0)
        self.assertEqual(key_entry["keyComponents"][0]["keyType"]["decoded"]["type"], "AES")

        pin_retry = normalized["pinCodes"][0]["maxNumOfAttemps-retryNumLeft"]
        self.assertEqual(pin_retry["raw"], 51)
        self.assertEqual(pin_retry["decoded"]["maxAttempts"], 3)
        self.assertEqual(pin_retry["decoded"]["remainingAttempts"], 3)

        puk_retry = normalized["pukCodes"][0]["maxNumOfAttemps-retryNumLeft"]
        self.assertEqual(puk_retry["raw"], 170)
        self.assertEqual(puk_retry["decoded"]["maxAttempts"], 10)
        self.assertEqual(puk_retry["decoded"]["remainingAttempts"], 10)

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

    def test_normalize_dump_value_decodes_filesystem_and_secret_fields(self) -> None:
        normalized = self.shell._normalize_dump_value(
            {
                "fileDescriptor": "42210026",
                "efFileSize": "04ba",
                "shortEFID": "10",
                "lcsi": "05",
                "pinValue": "31323334ffffffff",
                "pukValue": "3132333435363738",
                "fillFileOffset": 0,
                "unblockingPINReference": 1,
                "instanceAID": "a000000151000000",
            }
        )

        file_descriptor = normalized["fileDescriptor"]
        self.assertEqual(file_descriptor["decoded"]["structure"], "linear_fixed")
        self.assertEqual(file_descriptor["decoded"]["recordLength"], 38)
        self.assertTrue(file_descriptor["decoded"]["shareable"])

        self.assertEqual(normalized["efFileSize"]["decoded"]["decimal"], 1210)
        self.assertEqual(normalized["shortEFID"]["decoded"]["sfi"], 2)
        self.assertTrue(normalized["shortEFID"]["decoded"]["validEncoding"])
        self.assertEqual(normalized["lcsi"]["decoded"]["state"], "operational_activated")
        self.assertEqual(normalized["pinValue"]["decoded"]["digits"], "1234")
        self.assertEqual(normalized["pukValue"]["decoded"]["digits"], "12345678")
        self.assertEqual(normalized["fillFileOffset"]["decoded"]["decimal"], 0)
        self.assertEqual(
            normalized["unblockingPINReference"]["decoded"]["referenceName"],
            "pukAppl1",
        )
        self.assertEqual(normalized["instanceAID"]["decoded"]["rid"], "a000000151")

    def test_normalize_dump_value_decodes_header_iccid_and_key_material(self) -> None:
        normalized = self.shell._normalize_dump_value(
            {
                "iccid": "89460811111111111112",
                "keyData": "1122334455667788aabbccddeeff0011",
                "macLength": 8,
            }
        )

        self.assertEqual(normalized["iccid"]["decoded"]["iccid"], "89460811111111111112")
        self.assertEqual(normalized["keyData"]["decoded"]["keySizeBits"], 128)
        self.assertEqual(normalized["macLength"]["decoded"]["decimal"], 8)

    def test_normalize_dump_value_decodes_profile_policy_and_memory_limits(self) -> None:
        normalized = self.shell._normalize_dump_value(
            {
                "pol": "04",
                "nonVolatileCodeLimitC6": "0100",
                "volatileDataLimitC7": "00010000",
                "nonVolatileDataLimitC8": "0001",
            }
        )

        self.assertEqual(
            normalized["pol"]["decoded"]["activePolicies"],
            ["ppr2-delete-not-allowed"],
        )
        self.assertEqual(normalized["nonVolatileCodeLimitC6"]["decoded"]["decimal"], 256)
        self.assertEqual(normalized["volatileDataLimitC7"]["decoded"]["decimal"], 65536)
        self.assertEqual(normalized["nonVolatileDataLimitC8"]["decoded"]["decimal"], 1)

    def test_normalize_dump_value_decodes_aka_parameter_fields(self) -> None:
        normalized = self.shell._normalize_dump_value(
            {
                "algorithmID": 1,
                "algorithmOptions": "01",
                "key": "ffffffffffffffffffffffffffffffff",
                "opc": "11111111111111111111111111111111",
                "authCounterMax": "ffffff",
                "rotationConstants": "4000204060",
                "xoringConstants": (
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000001"
                    "00000000000000000000000000000002"
                    "00000000000000000000000000000004"
                    "00000000000000000000000000000008"
                ),
                "numberOfKeccak": 1,
                "sqnOptions": "0e",
                "sqnDelta": "000010000000",
                "sqnAgeLimit": "000010000000",
                "sqnInit": ["000000000000", "000000000001"],
            }
        )

        self.assertEqual(normalized["algorithmID"]["decoded"]["algorithm"], "milenage")
        self.assertEqual(normalized["algorithmOptions"]["decoded"]["setBits"], [0])
        self.assertEqual(normalized["key"]["decoded"]["keySizeBits"], 128)
        self.assertEqual(normalized["opc"]["decoded"]["keySizeBits"], 128)
        self.assertEqual(normalized["authCounterMax"]["decoded"]["decimal"], 16777215)
        self.assertEqual(normalized["rotationConstants"]["decoded"]["r1"], 64)
        self.assertEqual(
            normalized["xoringConstants"]["decoded"]["c5"],
            "00000000000000000000000000000008",
        )
        self.assertEqual(normalized["numberOfKeccak"]["decoded"]["decimal"], 1)
        self.assertEqual(normalized["sqnOptions"]["decoded"]["setBits"], [3, 2, 1])
        self.assertEqual(normalized["sqnDelta"]["decoded"]["decimal"], 268435456)
        self.assertEqual(normalized["sqnAgeLimit"]["decoded"]["decimal"], 268435456)
        self.assertEqual(normalized["sqnInit"]["decoded"][1]["decimal"], 1)

    def test_normalize_dump_value_decodes_filesystem_reference_and_proprietary_fields(self) -> None:
        normalized = self.shell._normalize_dump_value(
            {
                "fileID": "6f38",
                "filePath": "7f10",
                "securityAttributesReferenced": "6f0603",
                "linkPath": "7f106f38",
                "specialFileInformation": "c0",
                "fillPattern": "ff",
                "fileDetails": "01",
                "repeatPattern": "4142",
            }
        )

        self.assertEqual(normalized["fileID"]["decoded"]["name"], "EF.UST / EF.UST-SERVICE-TABLE")
        self.assertEqual(normalized["filePath"]["decoded"]["segments"][0]["name"], "DF.TELECOM")
        self.assertEqual(normalized["securityAttributesReferenced"]["decoded"]["arrFileId"], "6F06")
        self.assertEqual(normalized["securityAttributesReferenced"]["decoded"]["recordNumber"], 3)
        self.assertEqual(normalized["linkPath"]["decoded"]["segments"][0]["name"], "DF.TELECOM")
        self.assertEqual(
            normalized["linkPath"]["decoded"]["segments"][1]["name"],
            "EF.UST / EF.UST-SERVICE-TABLE",
        )
        self.assertTrue(normalized["specialFileInformation"]["decoded"]["highUpdateActivity"])
        self.assertTrue(
            normalized["specialFileInformation"]["decoded"]["readAndUpdateWhenDeactivated"]
        )
        self.assertEqual(normalized["fillPattern"]["decoded"]["byteValue"], "0xFF")
        self.assertEqual(normalized["fileDetails"]["decoded"]["coding"], "DER coding")
        self.assertEqual(normalized["repeatPattern"]["decoded"]["ascii"], "AB")

    def test_normalize_dump_value_decodes_pin_policy_and_rfm_fields(self) -> None:
        normalized = self.shell._normalize_dump_value(
            {
                "keyReference": 10,
                "pinAttributes": 6,
                "pinStatusTemplateDO": "010a",
                "tarList": ["b00001"],
                "minimumSecurityLevel": "16",
                "uiccAccessDomain": "02030104",
                "adfAccessDomain": "02030104",
            }
        )

        self.assertEqual(normalized["keyReference"]["decoded"]["admName"], "adm1")
        self.assertEqual(normalized["pinAttributes"]["decoded"]["setBits"], [2, 1])
        self.assertEqual(normalized["pinStatusTemplateDO"]["decoded"]["statusBytes"], "01")
        self.assertEqual(
            normalized["pinStatusTemplateDO"]["decoded"]["keyReference"]["admName"],
            "adm1",
        )
        self.assertEqual(normalized["tarList"]["decoded"][0]["tar"], "b00001")
        self.assertEqual(normalized["minimumSecurityLevel"]["decoded"]["setBits"], [4, 2, 1])
        self.assertEqual(normalized["uiccAccessDomain"]["decoded"]["bytes"][0], "0x02")
        self.assertEqual(normalized["adfAccessDomain"]["decoded"]["bytes"][-1], "0x04")

    def test_dump_output_redirection_rejects_outside_workspace_with_clear_message(self) -> None:
        with self.assertRaisesRegex(ValueError, "Output redirection is workspace-confined"):
            self.shell._parse_output_redirection(
                "ALL DECODED > /tmp/yggdrasim_test_dump.txt"
            )

    def test_lint_output_redirection_rejects_outside_workspace_with_clear_message(self) -> None:
        with self.assertRaisesRegex(ValueError, "Output redirection is workspace-confined"):
            self.shell._parse_lint_output_redirection(
                "STRICT > /tmp/yggdrasim_test_lint.yaml"
            )

    def test_complete_path_token_uses_default_profile_dir_for_bare_names(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            profile_dir = Path(temp_dir)
            self.shell.bridge.default_profile_dir = profile_dir
            (profile_dir / "alpha.der").write_text("demo", encoding="utf-8")
            (profile_dir / "beta.txt").write_text("ABCD", encoding="utf-8")
            (profile_dir / "beta.transcode.json").write_text("{}", encoding="utf-8")
            (profile_dir / "beta.transcode.der").write_bytes(b"\xAA")
            (profile_dir / "beta.transcode.txt").write_text("AABB\n", encoding="utf-8")

            matches = self.shell._complete_path_token("")

        self.assertIn("alpha.der", matches)
        self.assertIn("beta.txt", matches)
        self.assertNotIn("beta.transcode.json", matches)
        self.assertNotIn("beta.transcode.der", matches)
        self.assertNotIn("beta.transcode.txt", matches)

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
        profile_dir = workspace_root / "Workspace" / "SAIP" / "profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / ".gitkeep").write_text("", encoding="utf-8")
        profile_file = profile_dir / "only_profile.txt"
        profile_file.write_text("A0B1", encoding="utf-8")

        shell = ProfilePackageShell(workspace_root=workspace_root)

        self.assertEqual(shell.bridge.current_input_file, profile_file.resolve())
        self.assertEqual([path.name for path in shell._startup_profiles], ["only_profile.txt"])

    def test_banner_lists_profiles_found_in_default_directory(self) -> None:
        workspace_root = self.shell.bridge.workspace_root
        profile_dir = workspace_root / "Workspace" / "SAIP" / "profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "alpha.txt").write_text("AA", encoding="utf-8")
        (profile_dir / "beta.der").write_text("BB", encoding="utf-8")
        (profile_dir / "beta.transcode.json").write_text("{}", encoding="utf-8")
        (profile_dir / "beta.transcode.txt").write_text("AABB\n", encoding="utf-8")

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
        self.assertNotIn("beta.transcode.txt", banner_text)

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

    def test_cmd_inspect_reports_invalid_profile_asn1_with_context(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        shell = ProfilePackageShell(workspace_root=workspace_root)
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            invalid_profile = Path(temp_dir) / "invalid_profile.der"
            invalid_profile.write_bytes(b"\xDE\xAD\xBE\xEF")
            shell.bridge.set_input_file(str(invalid_profile))

            with contextlib.redirect_stdout(io.StringIO()) as captured:
                shell._cmd_inspect("")

        rendered = captured.getvalue()
        self.assertIn("Profile ASN1 is not valid.", rendered)
        self.assertIn(f"Source: {invalid_profile}.", rendered)
        self.assertIn("Size: 4 bytes.", rendered)
        self.assertIn("First bytes: DE AD BE EF.", rendered)
        self.assertIn("Decoder error:", rendered)
        self.assertIn("Hint:", rendered)
        self.assertIn("SAIP profile element sequence", rendered)

    def test_cmd_transcode_dir_sets_default_directory(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            target_dir = Path(temp_dir) / "transcode"

            self.shell._cmd_transcode_dir(str(target_dir))

            self.assertEqual(self.shell.bridge.default_transcode_dir, target_dir.resolve())
            self.assertTrue(target_dir.exists())

    def test_cmd_encode_json_writes_der_output(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            input_path = Path(temp_dir) / "profile.json"
            output_path = Path(temp_dir) / "profile.der"
            input_path.write_text('{"kind": "demo"}', encoding="utf-8")

            with mock.patch(
                "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
            ) as mocked_ensure:
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.dejsonify_document",
                    return_value={"document": "demo"},
                ) as mocked_dejsonify:
                    with mock.patch(
                        "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                        return_value=b"\x01\x02",
                    ) as mocked_encode:
                        with contextlib.redirect_stdout(io.StringIO()) as captured:
                            self.shell._cmd_encode_json(f'"{input_path}" "{output_path}"')

            self.assertEqual(output_path.read_bytes(), b"\x01\x02")
            mocked_ensure.assert_called_once_with(self.shell.bridge.workspace_root)
            mocked_dejsonify.assert_called_once_with({"kind": "demo"})
            mocked_encode.assert_called_once_with(
                {"document": "demo"},
                self.shell.bridge.workspace_root,
            )
            self.assertIn("Wrote 2 bytes DER", captured.getvalue())

    def test_cmd_generate_template_writes_json_with_placeholder_defs(self) -> None:
        decoded_document = {
            "intro": ["Read 3 PEs from file '/tmp/demo.der'"],
            "sections": {
                "header": {
                    "iccid": bytes.fromhex("89461111111111111112"),
                },
                "mf": {
                    "ef-iccid": [
                        ("fillFileContent", bytes.fromhex("98641111111111111121")),
                    ],
                },
                "usim": {
                    "ef-imsi": [
                        ("fillFileContent", bytes.fromhex("091132547618325476F8")),
                    ],
                },
            },
        }
        self.shell.bridge.current_input_file = self.shell.bridge.workspace_root / "demo.der"
        self.shell.bridge.build_decoded_dump_document = lambda _mode: decoded_document

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "profile_template.json"
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                self.shell._cmd_generate_template(
                    f'"{output_path}" ICCID=89461111111111111112 IMSI=1234567812345678'
                )

            rendered = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(rendered["sections"]["header"]["iccid"]["hex"], "{ICCID}")
        self.assertEqual(
            rendered["sections"]["mf"]["ef-iccid"][0]["@"][1]["hex"],
            "{ICCID_EF}",
        )
        self.assertEqual(
            rendered["sections"]["usim"]["ef-imsi"][0]["@"][1]["hex"],
            "{IMSI}",
        )
        self.assertEqual(rendered["__ygg_token_defs__"]["ICCID"]["hex"], "89461111111111111112")
        self.assertEqual(rendered["__ygg_token_defs__"]["ICCID_EF"]["hex"], "98641111111111111121")
        self.assertEqual(rendered["__ygg_token_defs__"]["IMSI"]["hex"], "091132547618325476F8")
        self.assertIn("Placeholder injection summary", captured.getvalue())

    def test_cmd_generate_profile_applies_typed_placeholder_overrides(self) -> None:
        template = {
            "intro": ["Template"],
            "sections": {
                "header": {
                    "iccid": {"hex": "{ICCID}"},
                },
                "mf": {
                    "ef-iccid": [
                        {
                            "@": [
                                "fillFileContent",
                                {"hex": "{ICCID_EF}"},
                            ]
                        }
                    ],
                },
                "usim": {
                    "ef-imsi": [
                        {
                            "@": [
                                "fillFileContent",
                                {"hex": "{IMSI}"},
                            ]
                        }
                    ],
                },
            },
        }

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            template_path = Path(temp_dir) / "profile_template.json"
            output_path = Path(temp_dir) / "profile.der"
            template_path.write_text(json.dumps(template), encoding="utf-8")

            with mock.patch(
                "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
            ) as mocked_ensure:
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                    return_value=b"\xAA\xBB",
                ) as mocked_encode:
                    with contextlib.redirect_stdout(io.StringIO()) as captured:
                        self.shell._cmd_generate_profile(
                            f'"{template_path}" "{output_path}" '
                            "ICCID=89461111111111111112 IMSI=1234567812345678"
                        )
                    written_bytes = output_path.read_bytes()

        mocked_ensure.assert_called_once_with(self.shell.bridge.workspace_root)
        document = mocked_encode.call_args.args[0]
        self.assertEqual(document["sections"]["header"]["iccid"], bytes.fromhex("89461111111111111112"))
        self.assertEqual(
            document["sections"]["mf"]["ef-iccid"][0][1],
            bytes.fromhex("98641111111111111121"),
        )
        self.assertEqual(
            document["sections"]["usim"]["ef-imsi"][0][1],
            bytes.fromhex("091132547618325476F8"),
        )
        self.assertEqual(document["__ygg_token_defs__"]["ICCID"]["hex"], "89461111111111111112")
        self.assertEqual(document["__ygg_token_defs__"]["ICCID_EF"]["hex"], "98641111111111111121")
        self.assertEqual(document["__ygg_token_defs__"]["IMSI"]["hex"], "091132547618325476F8")
        self.assertEqual(written_bytes, b"\xAA\xBB")
        self.assertIn("Placeholder override summary", captured.getvalue())

    def test_cmd_generate_batch_builds_one_profile_per_csv_record(self) -> None:
        template = {
            "intro": ["Template"],
            "sections": {
                "header": {
                    "iccid": {"hex": "{ICCID}"},
                },
                "mf": {
                    "ef-iccid": [
                        {
                            "@": [
                                "fillFileContent",
                                {"hex": "{ICCID_EF}"},
                            ]
                        }
                    ],
                },
                "usim": {
                    "ef-imsi": [
                        {
                            "@": [
                                "fillFileContent",
                                {"hex": "{IMSI}"},
                            ]
                        }
                    ],
                },
            },
        }

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            template_path = Path(temp_dir) / "profile_template.json"
            data_path = Path(temp_dir) / "batch.csv"
            output_dir = Path(temp_dir) / "generated"
            template_path.write_text(json.dumps(template), encoding="utf-8")
            data_path.write_text(
                "ICCID,IMSI\n"
                "89461111111111111112,1234567812345678\n"
                "89461111111111111113,1234567812345679\n",
                encoding="utf-8",
            )

            with mock.patch(
                "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
            ) as mocked_ensure:
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                    side_effect=[b"\xAA\x01", b"\xAA\x02"],
                ) as mocked_encode:
                    with contextlib.redirect_stdout(io.StringIO()) as captured:
                        self.shell._cmd_generate_batch(
                            f'"{template_path}" "{data_path}" "{output_dir}"'
                        )

            generated_files = sorted(path.name for path in output_dir.glob("*.der"))
            generated_payloads = {
                path.name: path.read_bytes()
                for path in output_dir.glob("*.der")
            }

        mocked_ensure.assert_called_once_with(self.shell.bridge.workspace_root)
        self.assertEqual(mocked_encode.call_count, 2)
        first_document = mocked_encode.call_args_list[0].args[0]
        second_document = mocked_encode.call_args_list[1].args[0]
        self.assertEqual(first_document["sections"]["header"]["iccid"], bytes.fromhex("89461111111111111112"))
        self.assertEqual(second_document["sections"]["header"]["iccid"], bytes.fromhex("89461111111111111113"))
        self.assertEqual(
            generated_files,
            [
                "profile_iccid_89461111111111111112.der",
                "profile_iccid_89461111111111111113.der",
            ],
        )
        self.assertEqual(generated_payloads["profile_iccid_89461111111111111112.der"], b"\xAA\x01")
        self.assertEqual(generated_payloads["profile_iccid_89461111111111111113.der"], b"\xAA\x02")
        self.assertIn("Generated 2 DER profiles", captured.getvalue())

    def test_cmd_info_apps_invokes_bridge_with_expected_arguments(self) -> None:
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "info", "--apps"],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )
        recorded_args: list[list[str]] = []
        printed_results: list[SaipCommandResult] = []
        self.shell.bridge.run_current = lambda args: recorded_args.append(list(args)) or result
        self.shell._print_result = lambda rendered: printed_results.append(rendered)

        self.shell._cmd_info("APPS")

        self.assertEqual(recorded_args, [["info", "--apps"]])
        self.assertEqual(printed_results, [result])

    def test_cmd_tree_invokes_bridge_with_expected_arguments(self) -> None:
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "tree"],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )
        recorded_args: list[list[str]] = []
        printed_results: list[SaipCommandResult] = []
        self.shell.bridge.run_current = lambda args: recorded_args.append(list(args)) or result
        self.shell._print_result = lambda rendered: printed_results.append(rendered)

        self.shell._cmd_tree("")

        self.assertEqual(recorded_args, [["tree"]])
        self.assertEqual(printed_results, [result])

    def test_cmd_check_invokes_bridge_with_expected_arguments(self) -> None:
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "check"],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )
        recorded_args: list[list[str]] = []
        printed_results: list[SaipCommandResult] = []
        self.shell.bridge.run_current = lambda args: recorded_args.append(list(args)) or result
        self.shell._print_result = lambda rendered: printed_results.append(rendered)

        self.shell._cmd_check("")

        self.assertEqual(recorded_args, [["check"]])
        self.assertEqual(printed_results, [result])

    def test_cmd_split_resolves_output_prefix_inside_workspace(self) -> None:
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "split"],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )
        recorded_args: list[list[str]] = []
        self.shell.bridge.run_current = lambda args: recorded_args.append(list(args)) or result
        self.shell._print_result = lambda rendered: None

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_prefix = Path(temp_dir) / "exported_profile"
            self.shell._cmd_split(str(output_prefix))

        self.assertEqual(
            recorded_args,
            [["split", "--output-prefix", str(output_prefix.resolve())]],
        )

    def test_cmd_extract_apps_accepts_output_dir_and_format(self) -> None:
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "extract-apps"],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )
        recorded_args: list[list[str]] = []
        self.shell.bridge.run_current = lambda args: recorded_args.append(list(args)) or result
        self.shell._print_result = lambda rendered: None

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_dir = Path(temp_dir) / "apps"
            self.shell._cmd_extract_apps(f"{output_dir} CAP")

        self.assertEqual(
            recorded_args,
            [["extract-apps", "--output-dir", str(output_dir.resolve()), "--format", "cap"]],
        )

    def test_cmd_extract_apps_rejects_unknown_format(self) -> None:
        with self.assertRaisesRegex(ValueError, "Usage: EXTRACT-APPS \\[output_dir\\] \\[CAP\\|IJC\\]"):
            self.shell._cmd_extract_apps("tests/output BAD")

    def test_cmd_remove_naa_builds_expected_command(self) -> None:
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "remove-naa"],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )
        recorded_args: list[list[str]] = []
        self.shell.bridge.run_current = lambda args: recorded_args.append(list(args)) or result
        self.shell._print_result = lambda rendered: None

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_file = Path(temp_dir) / "without_usim.der"
            self.shell._cmd_remove_naa(f"USIM {output_file}")

        self.assertEqual(
            recorded_args,
            [["remove-naa", "--output-file", str(output_file.resolve()), "--naa-type", "usim"]],
        )

    def test_cmd_raw_normalizes_arguments_before_dispatch(self) -> None:
        result = SaipCommandResult(
            command=["saip-tool.py", "/tmp/demo.der", "split"],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )
        normalized_tokens = ["split", "--output-prefix", "/tmp/out"]
        captured_raw_tokens: list[list[str]] = []
        captured_run_args: list[list[str]] = []
        printed_results: list[SaipCommandResult] = []
        self.shell.bridge.normalize_raw_arguments = (
            lambda tokens: captured_raw_tokens.append(list(tokens)) or normalized_tokens
        )
        self.shell.bridge.run_current = lambda args: captured_run_args.append(list(args)) or result
        self.shell._print_result = lambda rendered: printed_results.append(rendered)

        self.shell._cmd_raw("split --output-prefix tests/out")

        self.assertEqual(captured_raw_tokens, [["split", "--output-prefix", "tests/out"]])
        self.assertEqual(captured_run_args, [normalized_tokens])
        self.assertEqual(printed_results, [result])

    def test_exec_line_reports_unknown_command(self) -> None:
        buffer = io.StringIO()

        with contextlib.redirect_stdout(buffer):
            self.shell._exec_line("wat")

        self.assertIn("Unknown command: WAT", buffer.getvalue())

    def test_run_commands_stops_after_exit(self) -> None:
        recorded: list[str] = []
        self.shell._print_banner = lambda: None
        self.shell._commands["STATUS"] = lambda argument: recorded.append("STATUS")
        self.shell._commands["HELP"] = lambda argument: recorded.append("HELP")

        def _raise_exit(_argument: str) -> None:
            raise SystemExit(0)

        self.shell._commands["EXIT"] = _raise_exit

        self.shell.run_commands("STATUS; EXIT; HELP")

        self.assertEqual(recorded, ["STATUS"])

    def test_run_commands_returns_error_after_command_exception(self) -> None:
        self.shell._print_banner = lambda: None

        def _raise_decode_error(_argument: str) -> None:
            raise RuntimeError("synthetic decode failure")

        self.shell._commands["CHECK"] = _raise_decode_error
        buffer = io.StringIO()

        with contextlib.redirect_stdout(buffer):
            with self.assertRaises(SystemExit) as raised:
                self.shell.run_commands("CHECK")

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("synthetic decode failure", buffer.getvalue())

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

class ProfilePackageShellProvisionAkaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parents[1]
        self.shell = ProfilePackageShell(workspace_root=self.workspace_root)

    def _stub_input(self, answers: list[str]):
        queue = list(answers)

        def _consume(_prompt: str) -> str:
            if len(queue) == 0:
                raise AssertionError("provision-aka wizard consumed more prompts than answers provided")
            return queue.pop(0)

        return _consume

    def test_provision_aka_updates_profile_and_writes_der(self) -> None:
        from Tools.ProfilePackage.saip_aka_wizard import read_aka_configuration
        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
            ensure_workspace_pysim_on_path,
        )
        from Tools.ProfilePackage.saip_pe_quick_add import insert_blank_pe_for_menu_id

        ensure_workspace_pysim_on_path(self.workspace_root)
        from pySim.esim.saip import (
            ProfileElementEnd,
            ProfileElementHeader,
            ProfileElementSequence,
        )

        pes = ProfileElementSequence()
        pes.append(ProfileElementHeader())
        pes.append(ProfileElementEnd())
        base_document = build_decoded_document_from_sequence(pes, intro_lines=["wizard"])
        document = insert_blank_pe_for_menu_id(
            base_document,
            self.workspace_root,
            menu_id="akaParameter",
        )

        self.shell.bridge.build_decoded_dump_document = lambda _mode: document
        self.shell.bridge.current_input_file = self.workspace_root / "demo.der"
        self.shell._input_fn = self._stub_input(
            [
                "tuak",
                "AA" * 32,
                "BB" * 32,
                "5",
                "FFFFFE",
                "000000000010",
            ]
        )

        with tempfile.TemporaryDirectory(dir=self.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "provisioned.der"
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                self.shell._cmd_provision_aka(f'"{output_path}"')

            rendered = captured.getvalue()
            self.assertIn("Provisioned tuak AKA", rendered)
            data = output_path.read_bytes()
            self.assertTrue(len(data) > 0)

            reloaded = ProfileElementSequence.from_der(data)
            doc_after = build_decoded_document_from_sequence(reloaded)
            snapshot = read_aka_configuration(doc_after, "akaParameter")
            self.assertEqual(snapshot["algorithm"], "tuak")
            self.assertEqual(snapshot["key"], "AA" * 32)
            self.assertEqual(snapshot["opc"], "BB" * 32)
            self.assertEqual(snapshot["numberOfKeccak"], "5")
            self.assertEqual(snapshot["authCounterMax"], "FFFFFE")
            self.assertEqual(snapshot["sqnInit"], "000000000010")

    def test_provision_aka_rejects_missing_output_path(self) -> None:
        self.shell._input_fn = self._stub_input([])
        with self.assertRaises(ValueError) as ctx:
            self.shell._cmd_provision_aka("")
        self.assertIn("Usage: PROVISION-AKA", str(ctx.exception))


def _aka_document_with_blank_pe(workspace_root: Path):
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
        ensure_workspace_pysim_on_path,
    )
    from Tools.ProfilePackage.saip_pe_quick_add import insert_blank_pe_for_menu_id

    ensure_workspace_pysim_on_path(workspace_root)
    from pySim.esim.saip import (
        ProfileElementEnd,
        ProfileElementHeader,
        ProfileElementSequence,
    )

    pes = ProfileElementSequence()
    pes.append(ProfileElementHeader())
    pes.append(ProfileElementEnd())
    base_document = build_decoded_document_from_sequence(pes, intro_lines=["wizard"])
    return insert_blank_pe_for_menu_id(
        base_document,
        workspace_root,
        menu_id="akaParameter",
    )


class ProfilePackageShellListAkaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parents[1]
        self.shell = ProfilePackageShell(workspace_root=self.workspace_root)

    def test_list_aka_reports_no_pe_present(self) -> None:
        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
            ensure_workspace_pysim_on_path,
        )

        ensure_workspace_pysim_on_path(self.workspace_root)
        from pySim.esim.saip import (
            ProfileElementEnd,
            ProfileElementHeader,
            ProfileElementSequence,
        )

        pes = ProfileElementSequence()
        pes.append(ProfileElementHeader())
        pes.append(ProfileElementEnd())
        document = build_decoded_document_from_sequence(pes, intro_lines=["list"])
        self.shell.bridge.build_decoded_dump_document = lambda _mode: document

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            self.shell._cmd_list_aka("")

        self.assertIn("no akaParameter PE", captured.getvalue())

    def test_list_aka_summarises_existing_sections(self) -> None:
        document = _aka_document_with_blank_pe(self.workspace_root)
        self.shell.bridge.build_decoded_dump_document = lambda _mode: document
        self.shell.bridge.current_input_file = self.workspace_root / "demo.der"
        self.shell._input_fn = lambda _prompt: "invalid"

        with contextlib.redirect_stdout(io.StringIO()):
            self.shell._cmd_provision_aka(
                'IN-PLACE ALGORITHM=milenage KI=' + 'AA' * 16 + ' OPC=' + 'BB' * 16
            )

        # Re-read via the wizard to confirm LIST-AKA renders the expected row
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            self.shell._cmd_list_aka("")

        text = captured.getvalue()
        self.assertIn("akaParameter", text)
        self.assertIn("milenage", text)


class ProfilePackageShellProvisionAkaFlagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parents[1]
        self.shell = ProfilePackageShell(workspace_root=self.workspace_root)

    def test_provision_aka_non_interactive_writes_der(self) -> None:
        from Tools.ProfilePackage.saip_aka_wizard import read_aka_configuration
        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
        )

        document = _aka_document_with_blank_pe(self.workspace_root)
        self.shell.bridge.build_decoded_dump_document = lambda _mode: document

        def _no_prompt(_prompt: str) -> str:
            raise AssertionError("non-interactive PROVISION-AKA must not prompt")

        self.shell._input_fn = _no_prompt

        with tempfile.TemporaryDirectory(dir=self.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "non_interactive.der"
            cmd_line = (
                f'"{output_path}" ALGORITHM=milenage '
                f'KI={"AA" * 16} OPC={"BB" * 16}'
            )
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                self.shell._cmd_provision_aka(cmd_line)
            rendered = captured.getvalue()
            self.assertIn("Provisioned milenage AKA", rendered)

            from Tools.ProfilePackage.saip_json_codec import (
                ensure_workspace_pysim_on_path,
            )

            ensure_workspace_pysim_on_path(self.workspace_root)
            from pySim.esim.saip import ProfileElementSequence

            reloaded = ProfileElementSequence.from_der(output_path.read_bytes())
            doc_after = build_decoded_document_from_sequence(reloaded)
            snapshot = read_aka_configuration(doc_after, "akaParameter")
            self.assertEqual(snapshot["algorithm"], "milenage")
            self.assertEqual(snapshot["key"], "AA" * 16)
            self.assertEqual(snapshot["opc"], "BB" * 16)

    def test_provision_aka_rejects_unknown_override(self) -> None:
        self.shell.bridge.build_decoded_dump_document = lambda _mode: _aka_document_with_blank_pe(self.workspace_root)
        with self.assertRaises(ValueError) as ctx:
            self.shell._cmd_provision_aka("reports/ignored.der FOO=bar")
        self.assertIn("Unknown AKA override", str(ctx.exception))

    def test_provision_aka_in_place_requires_active_input(self) -> None:
        self.shell.bridge.current_input_file = None
        with self.assertRaises(ValueError) as ctx:
            self.shell._cmd_provision_aka("IN-PLACE ALGORITHM=milenage KI=" + "AA" * 16 + " OPC=" + "BB" * 16)
        self.assertIn("IN-PLACE", str(ctx.exception))


class ProfilePackageShellRandomizeAkaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parents[1]
        self.shell = ProfilePackageShell(workspace_root=self.workspace_root)

    def test_randomize_aka_generates_values_and_writes_der(self) -> None:
        from Tools.ProfilePackage.saip_aka_wizard import read_aka_configuration
        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
            ensure_workspace_pysim_on_path,
        )

        document = _aka_document_with_blank_pe(self.workspace_root)
        self.shell.bridge.build_decoded_dump_document = lambda _mode: document

        with tempfile.TemporaryDirectory(dir=self.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "random.der"
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                self.shell._cmd_randomize_aka(f'"{output_path}" ALGORITHM=milenage')
            rendered = captured.getvalue()
            self.assertIn("Provisioned milenage AKA", rendered)
            self.assertIn("RANDOMIZE-AKA", rendered)

            ensure_workspace_pysim_on_path(self.workspace_root)
            from pySim.esim.saip import ProfileElementSequence

            reloaded = ProfileElementSequence.from_der(output_path.read_bytes())
            doc_after = build_decoded_document_from_sequence(reloaded)
            snapshot = read_aka_configuration(doc_after, "akaParameter")
            self.assertEqual(snapshot["algorithm"], "milenage")
            self.assertEqual(len(snapshot["key"]), 32)
            self.assertEqual(len(snapshot["opc"]), 32)

    def test_randomize_aka_rejects_unknown_option(self) -> None:
        self.shell.bridge.build_decoded_dump_document = lambda _mode: _aka_document_with_blank_pe(self.workspace_root)
        with self.assertRaises(ValueError) as ctx:
            self.shell._cmd_randomize_aka("reports/ignored.der FOO=bar")
        self.assertIn("Unknown RANDOMIZE-AKA option", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
