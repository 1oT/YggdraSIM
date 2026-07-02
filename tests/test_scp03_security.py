# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import io
import unittest
from contextlib import redirect_stdout

from SCP03.interface.shell_wizards import ShellInteractiveWizards
from SCP03.logic.security import AUTH_TEST_VECTOR, SecurityController


class _UnexpectedTransmitTransport:
    def transmit(self, *_args, **_kwargs):
        raise AssertionError("RUN-AUTH-TEST should not hit live transport in offline mode.")


class _RecordingTransport:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def transmit(self, command: str, **_kwargs):
        self.commands.append(command)
        return b"", 0x90, 0x00


class _RecordingPinController:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def verify_pin(self, pin_id: str, pin: str, pin_encoding: str = "ascii") -> None:
        self.calls.append(("verify", (pin_id, pin, pin_encoding)))


class _PinShell:
    def __init__(self) -> None:
        self.sec_ctrl = _RecordingPinController()


class SecurityControllerOfflineAuthTests(unittest.TestCase):
    def test_derive_opc_matches_reference_vector(self) -> None:
        derived = SecurityController.derive_opc(
            AUTH_TEST_VECTOR["Ki"],
            AUTH_TEST_VECTOR["OP"],
        )

        self.assertEqual(derived, AUTH_TEST_VECTOR["OPc"])

    def test_compute_offline_milenage_vector_matches_reference_values(self) -> None:
        report = SecurityController.compute_offline_milenage_vector(
            AUTH_TEST_VECTOR["RAND"],
            AUTH_TEST_VECTOR["Ki"],
            op_hex=AUTH_TEST_VECTOR["OP"],
        )

        self.assertEqual(report.opc, AUTH_TEST_VECTOR["OPc"])
        self.assertEqual(report.res, AUTH_TEST_VECTOR["RES"])
        self.assertEqual(report.ck, AUTH_TEST_VECTOR["CK"])
        self.assertEqual(report.ik, AUTH_TEST_VECTOR["IK"])
        self.assertEqual(report.kc, AUTH_TEST_VECTOR["Kc"])

    def test_build_auth_test_usim_exchange_matches_reference_wire_format(self) -> None:
        exchange = SecurityController.build_auth_test_usim_exchange()

        self.assertEqual(exchange.result, "success")
        self.assertEqual(exchange.autn, AUTH_TEST_VECTOR["AUTN"])
        self.assertEqual(exchange.command_apdu, AUTH_TEST_VECTOR["USIM_AUTH_APDU"])
        self.assertEqual(exchange.response_payload, AUTH_TEST_VECTOR["USIM_AUTH_RESPONSE"])
        self.assertEqual(exchange.response_apdu, AUTH_TEST_VECTOR["USIM_AUTH_RESPONSE"] + "9000")
        self.assertEqual(exchange.current_sqn, AUTH_TEST_VECTOR["SQN"])
        self.assertEqual(exchange.recovered_sqn, AUTH_TEST_VECTOR["SQN"])
        self.assertEqual(exchange.next_sqn, "000000000002")

    def test_validate_offline_usim_auth_apdu_detects_sync_failure(self) -> None:
        exchange = SecurityController.validate_offline_usim_auth_apdu(
            AUTH_TEST_VECTOR["USIM_AUTH_APDU"],
            AUTH_TEST_VECTOR["Ki"],
            current_sqn_hex="000000000002",
            op_hex=AUTH_TEST_VECTOR["OP"],
        )

        self.assertEqual(exchange.result, "sync_failure")
        self.assertEqual(exchange.status_word, "9000")
        self.assertEqual(exchange.auts, "451E8BECA43968AC6493B0A408B0")
        self.assertEqual(exchange.response_payload, "DC0E451E8BECA43968AC6493B0A408B0")
        self.assertEqual(exchange.response_apdu, "DC0E451E8BECA43968AC6493B0A408B09000")
        self.assertEqual(exchange.next_sqn, "000000000002")

    def test_validate_offline_usim_auth_apdu_detects_mac_failure(self) -> None:
        tampered_apdu = AUTH_TEST_VECTOR["USIM_AUTH_APDU"][:-4] + "FF00"
        exchange = SecurityController.validate_offline_usim_auth_apdu(
            tampered_apdu,
            AUTH_TEST_VECTOR["Ki"],
            current_sqn_hex=AUTH_TEST_VECTOR["SQN"],
            op_hex=AUTH_TEST_VECTOR["OP"],
        )

        self.assertEqual(exchange.result, "mac_failure")
        self.assertEqual(exchange.status_word, "9862")
        self.assertEqual(exchange.response_payload, "")
        self.assertEqual(exchange.response_apdu, "9862")

    def test_run_auth_test_vector_is_offline_only(self) -> None:
        controller = SecurityController(_UnexpectedTransmitTransport())

        output = io.StringIO()
        with redirect_stdout(output):
            controller.run_auth_test_vector()

        rendered = output.getvalue()
        self.assertIn("Offline vector check complete", rendered)
        self.assertIn(AUTH_TEST_VECTOR["Kc"], rendered)
        self.assertIn("OPc check:", rendered)
        self.assertIn("00 88 APDU (derived):", rendered)
        self.assertIn("Response check:", rendered)


class SecurityControllerPinEncodingTests(unittest.TestCase):
    def test_verify_pin_ascii_keeps_legacy_padding(self) -> None:
        transport = _RecordingTransport()
        controller = SecurityController(transport)

        output = io.StringIO()
        with redirect_stdout(output):
            controller.verify_pin("0a", "1234")

        self.assertEqual(transport.commands, ["0020000A0831323334FFFFFFFF"])

    def test_verify_pin_hex_sends_raw_bytes(self) -> None:
        transport = _RecordingTransport()
        controller = SecurityController(transport)

        output = io.StringIO()
        with redirect_stdout(output):
            controller.verify_pin("0a", "523D3BE7AD38DE19", pin_encoding="hex")

        self.assertEqual(transport.commands, ["0020000A08523D3BE7AD38DE19"])

    def test_change_pin_binary_sends_raw_bytes_with_dynamic_lc(self) -> None:
        transport = _RecordingTransport()
        controller = SecurityController(transport)

        output = io.StringIO()
        with redirect_stdout(output):
            controller.change_pin("01", "0102", "AABBCC", pin_encoding="binary")

        self.assertEqual(transport.commands, ["00240001050102AABBCC"])

    def test_verify_pin_accepts_friendly_pin_reference_names(self) -> None:
        cases =(
            ("PIN App 1","01"),
            ("UPIN","11"),
            ("SECOND-PIN-APP1","81"),
            ("ADM1","0A"),
            ("ADM10","8E"),
        )

        for pin_ref ,expected_ref in cases:
            with self.subTest(pin_ref=pin_ref):
                transport = _RecordingTransport()
                controller = SecurityController(transport)

                output = io.StringIO()
                with redirect_stdout(output):
                    controller.verify_pin(pin_ref, "1234")

                self.assertEqual(
                    transport.commands,
                    [f"002000{expected_ref}0831323334FFFFFFFF"],
                )


class ShellManagePinEncodingTests(unittest.TestCase):
    def test_manage_pin_macro_defaults_to_ascii_encoding(self) -> None:
        shell = _PinShell()

        output = io.StringIO()
        with redirect_stdout(output):
            ShellInteractiveWizards.run_manage_pin_wizard(shell, "verify 0a 1234")

        self.assertEqual(shell.sec_ctrl.calls, [("verify", ("0A", "1234", "ascii"))])

    def test_manage_pin_macro_accepts_hex_flag(self) -> None:
        shell = _PinShell()

        output = io.StringIO()
        with redirect_stdout(output):
            ShellInteractiveWizards.run_manage_pin_wizard(
                shell,
                "verify --hex 0a 523D3BE7AD38DE19",
            )

        self.assertEqual(
            shell.sec_ctrl.calls,
            [("verify", ("0A", "523D3BE7AD38DE19", "hex"))],
        )


if __name__ == "__main__":
    unittest.main()
