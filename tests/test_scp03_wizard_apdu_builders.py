# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for SCP03 wizard APDU builders."""

from __future__ import annotations

import contextlib
import io
import tempfile
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from SCP03.core.cap import CapFileParser
from SCP03.interface.wizards import InteractiveWizards
from SCP03.core import install_script
from SCP80.builder import OtaPacketBuilder


def _component(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + len(payload).to_bytes(2, "big") + payload

# JCVM 3.1 §6.4 header_component_compact, everything ahead of AID_length:
# magic 'DECAFFED', CAP format minor then major ('02' '02'), flags, and the
# package_info minor and major version.
HEADER_PREFIX = bytes.fromhex("DECAFFED") + b"\x02\x02\x00\x00\x01"


def _write_ijc(
    directory: Path, package_aid: bytes, applet_aid: bytes, method_payload: bytes = b""
) -> Path:
    header_payload = HEADER_PREFIX + bytes([len(package_aid)]) + package_aid
    applet_payload = bytes([1, len(applet_aid)]) + applet_aid + b"\x00\x00"
    component_blob = _component(0x01, header_payload) + _component(0x03, applet_payload)
    if len(method_payload) > 0:
        component_blob += _component(0x07, method_payload)
    load_block = CapFileParser._wrap_load_file_block(component_blob)
    path = directory / "sample.ijc"
    path.write_bytes(load_block)
    return path


def _condensed(text: str) -> str:
    """Source with every run of whitespace removed.

    These assertions look for a construct in a module's source, and that
    module's formatting is not what they are testing. Comparing condensed
    text keeps a reformat from reading as a behaviour change, which is
    what happened when the minified spelling these were written against
    was replaced by ordinary formatting.
    """
    return re.sub(r"\s+", "", text)


class WizardInstallParameterBuilderTests(unittest.TestCase):
    def test_full_empty_c9_tlv_is_preserved(self) -> None:
        result = InteractiveWizards._coerce_c9_install_parameter("C900")
        self.assertEqual(result.hex().upper(), "C900")

    def test_full_non_empty_c9_tlv_is_preserved(self) -> None:
        result = InteractiveWizards._coerce_c9_install_parameter("C9020102")
        self.assertEqual(result.hex().upper(), "C9020102")

    def test_raw_c9_value_is_wrapped(self) -> None:
        result = InteractiveWizards._coerce_c9_install_parameter("0102")
        self.assertEqual(result.hex().upper(), "C9020102")

    def test_lv_field_over_255_bytes_does_not_truncate(self) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds 255 bytes"):
            InteractiveWizards._build_lv_field("AA" * 256)

    def test_store_data_p1_must_be_one_byte(self) -> None:
        with self.assertRaises(ValueError):
            InteractiveWizards._build_store_data_with_params("CAFE", "9000", "00")

    def test_oversized_ber_length_raises(self) -> None:
        with self.assertRaises(ValueError):
            InteractiveWizards._encode_ber_tlv_length(0x10000)


class CapInstallWizardExecutionTests(unittest.TestCase):
    def test_execute_uses_generated_install_apdu(self) -> None:
        package_aid = bytes.fromhex("F000000001")
        applet_aid = bytes.fromhex("F00000000101")
        # GPC v2.3.1 Table 11-40: INSTALL carries Le '00' after the data field.
        expected_install_apdu = (
            "80E60C001A05F00000000106F0000000010106F00000000101010002C9000000"
        )

        class FakeGp:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, int | None]] = []

            def authenticate(self) -> bool:
                return True

            def install_cap_file_with_install_apdu(
                self,
                filename: str,
                install_apdu: str,
                load_chunk_size: int | None = None,
            ) -> bool:
                self.calls.append((filename, install_apdu, load_chunk_size))
                return True

        fake_gp = FakeGp()
        # app_aid, mod_aid, priv, adf_aids, run_b, raw_p, ota, save, execute
        answers = iter(["", "", "", "N", "N", "", "N", "N", "Y"])

        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(Path(temp_dir), package_aid, applet_aid)
            output = io.StringIO()
            with patch("builtins.input", lambda _prompt="": next(answers)):
                with contextlib.redirect_stdout(output):
                    InteractiveWizards.build_install_apdu(None, str(ijc_path), fake_gp)

        self.assertIn(expected_install_apdu, output.getvalue())
        self.assertEqual(len(fake_gp.calls), 1)
        self.assertEqual(fake_gp.calls[0][1], expected_install_apdu)
        self.assertEqual(fake_gp.calls[0][2], 240)


class CapInstallWizardOtaFormattingTests(unittest.TestCase):
    """OTA-formatted blocks fit one SCP80 SMS and carry no Le.

    ETSI TS 102 226 V19.0.0 clause 5.1.1: a compact remote command is a T=0
    TPDU, CLA INS P1 P2 P3 Data. The SCP80 builder refuses a payload that
    does not fit one 140-octet TP-UD, so every LOAD block has to stay within
    ``single_sms_payload_limit`` for the chosen cipher. The wizard once
    emitted 103-octet AES blocks with a trailing Le that the builder
    refused as a single SMS.
    """

    def _run_wizard(self, algo: str) -> tuple[str, list]:
        package_aid = bytes.fromhex("F000000001")
        applet_aid = bytes.fromhex("F00000000101")

        class FakeGp:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, int | None]] = []

            def authenticate(self) -> bool:
                return True

            def install_cap_file_with_install_apdu(
                self,
                filename: str,
                install_apdu: str,
                load_chunk_size: int | None = None,
            ) -> bool:
                self.calls.append((filename, install_apdu, load_chunk_size))
                return True

        fake_gp = FakeGp()
        # app_aid, mod_aid, priv, adf_aids, run_b, raw_p, ota, algo, save, execute
        answers = iter(["", "", "", "N", "N", "", "Y", algo, "N", "N"])
        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(
                Path(temp_dir), package_aid, applet_aid, method_payload=bytes(range(256)) * 2
            )
            output = io.StringIO()
            with patch("builtins.input", lambda _prompt="": next(answers)):
                with contextlib.redirect_stdout(output):
                    InteractiveWizards.build_install_apdu(None, str(ijc_path), fake_gp)
        return output.getvalue(), fake_gp.calls

    def _assert_single_sms_blocks(self, algo: str, cipher_mode: str) -> None:
        output, calls = self._run_wizard(algo)
        limit = OtaPacketBuilder.single_sms_payload_limit(cipher_mode)
        self.assertEqual(install_script.OTA_LOAD_CHUNK_FALLBACK[cipher_mode], limit - 5)

        load_lines = re.findall(r"\[Block \d+\] (80E8[0-9A-F]+)$", output, re.MULTILINE)
        self.assertGreater(len(load_lines), 1)
        for line in load_lines:
            apdu = bytes.fromhex(line)
            self.assertEqual(len(apdu) - 5, apdu[4], line)
            self.assertLessEqual(len(apdu), limit, line)
        self.assertEqual(bytes.fromhex(load_lines[-1])[2], 0x80)
        self.assertNotIn("concatenated segments", output)

        install_lines = re.findall(r"^(80E6[0-9A-F]+)$", output, re.MULTILINE)
        self.assertEqual(len(install_lines), 2)
        for line in install_lines:
            apdu = bytes.fromhex(line)
            self.assertEqual(len(apdu) - 5, apdu[4], line)
        self.assertEqual(calls, [])

    def test_aes_blocks_fit_one_sms_without_le(self) -> None:
        self._assert_single_sms_blocks("2", "AES")

    def test_3des_blocks_fit_one_sms_without_le(self) -> None:
        self._assert_single_sms_blocks("1", "3DES")

    def test_iso_dry_run_keeps_le(self) -> None:
        """Without OTA formatting the lines stay ISO case 4 with Le '00'."""
        package_aid = bytes.fromhex("F000000001")
        applet_aid = bytes.fromhex("F00000000101")
        # app_aid, mod_aid, priv, adf_aids, run_b, raw_p, ota, save
        answers = iter(["", "", "", "N", "N", "", "N", "N"])
        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(Path(temp_dir), package_aid, applet_aid)
            output = io.StringIO()
            with patch("builtins.input", lambda _prompt="": next(answers)):
                with contextlib.redirect_stdout(output):
                    InteractiveWizards.build_install_apdu(None, str(ijc_path), None)
        load_lines = re.findall(r"\[Block \d+\] (80E8[0-9A-F]+)$", output.getvalue(), re.MULTILINE)
        self.assertEqual(len(load_lines), 1)
        apdu = bytes.fromhex(load_lines[0])
        self.assertEqual(len(apdu) - 6, apdu[4])
        self.assertTrue(load_lines[0].endswith("00"))


class CapInstallWizardScriptFileTests(unittest.TestCase):
    """Wizard 8 saves the printed sequence as a script, one APDU per line.

    ``script`` in the SCP80 shell and ``RUN`` in the SCP03 shell both skip
    ``#`` comment lines and take a bare hex line as one command, so the file
    carries its header as comments and the three steps as hex lines.
    """

    PACKAGE_AID = bytes.fromhex("F000000001")
    APPLET_AID = bytes.fromhex("F00000000101")
    # app_aid, mod_aid, priv, adf_aids, run_b, raw_p, ota, algo, save
    OTA_ANSWERS = ["", "", "", "N", "N", "", "Y", "2", "Y"]
    # app_aid, mod_aid, priv, adf_aids, run_b, raw_p, ota, save
    ISO_ANSWERS = ["", "", "", "N", "N", "", "N", "Y"]

    def _run(self, ijc_path: Path, answers: list[str]) -> str:
        answer_iter = iter(answers)
        output = io.StringIO()
        with patch("builtins.input", lambda _prompt="": next(answer_iter)):
            with contextlib.redirect_stdout(output):
                InteractiveWizards.build_install_apdu(None, str(ijc_path), None)
        return output.getvalue()

    @staticmethod
    def _printed_apdus(output: str) -> list[str]:
        return re.findall(
            r"^(?:  \[Block \d+\] )?(80E[68][0-9A-F]+)$", output, re.MULTILINE
        )

    @staticmethod
    def _script_apdus(text: str) -> list[str]:
        commands = []
        for line in text.splitlines():
            body = line.split("#", 1)[0].strip()
            if body:
                commands.append(body)
        return commands

    def test_ota_script_holds_the_printed_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(
                Path(temp_dir),
                self.PACKAGE_AID,
                self.APPLET_AID,
                method_payload=bytes(range(256)) * 2,
            )
            target = Path(temp_dir) / "applet_load.txt"
            output = self._run(ijc_path, self.OTA_ANSWERS + [str(target)])
            self.assertIn(f"[+] APDU script saved to {target}", output)
            text = target.read_text(encoding="utf-8")
            printed = self._printed_apdus(output)
            self.assertGreaterEqual(len(printed), 4)
            commands = self._script_apdus(text)
            self.assertEqual(commands, printed)
            for command in commands:
                bytes.fromhex(command)
            self.assertTrue(text.startswith("# Full CAP install sequence for "))
            self.assertIn("ETSI TS 102 226 V19.0.0 clause 5.1.1", text)
            self.assertIn("script <file>", text)

    def test_default_path_sits_beside_the_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(Path(temp_dir), self.PACKAGE_AID, self.APPLET_AID)
            expected = Path(temp_dir) / f"{ijc_path.stem}_install.txt"
            self.assertEqual(
                InteractiveWizards._default_install_script_path(str(ijc_path)),
                str(expected),
            )
            self._run(ijc_path, self.OTA_ANSWERS + [""])
            self.assertTrue(expected.is_file())

    def test_existing_file_is_kept_unless_overwrite_is_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(Path(temp_dir), self.PACKAGE_AID, self.APPLET_AID)
            target = Path(temp_dir) / "applet_load.txt"
            target.write_text("old\n", encoding="utf-8")
            output = self._run(ijc_path, self.OTA_ANSWERS + [str(target), "N"])
            self.assertIn("was kept", output)
            self.assertEqual(target.read_text(encoding="utf-8"), "old\n")
            output = self._run(ijc_path, self.OTA_ANSWERS + [str(target), "Y"])
            self.assertIn("[+] APDU script saved to", output)
            self.assertTrue(target.read_text(encoding="utf-8").startswith("#"))

    def test_iso_script_keeps_le_and_names_the_scp03_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(Path(temp_dir), self.PACKAGE_AID, self.APPLET_AID)
            target = Path(temp_dir) / "applet_iso.txt"
            output = self._run(ijc_path, self.ISO_ANSWERS + [str(target)])
            text = target.read_text(encoding="utf-8")
            commands = self._script_apdus(text)
            self.assertEqual(commands, self._printed_apdus(output))
            self.assertEqual(len(commands), 3)
            for command in commands:
                self.assertTrue(command.endswith("00"), command)
            self.assertIn("Table 11-56", text)
            self.assertIn("RUN <file>", text)

    def test_path_validator_rejects_a_missing_directory(self) -> None:
        validator = InteractiveWizards._install_script_path_validator
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertIsNone(validator(str(Path(temp_dir) / "ok.txt")))
            self.assertIsNotNone(validator(str(Path(temp_dir) / "missing" / "x.txt")))
            self.assertIsNotNone(validator(temp_dir))
        self.assertIsNotNone(validator(""))


if __name__ == "__main__":
    unittest.main()


class CapInstallWizardUiccAccessTests(unittest.TestCase):
    """Wizard 8 asks for the ADF AIDs an applet needs file access to.

    ETSI TS 102 226 V19.0.0 clause 8.2.1.3.2.2.2: a uicc.access.FileView
    applet is granted access only through the tag '81' entries, so an
    install without them yields an applet that silently does nothing. Enter
    or N declines the grant; a listed AID adds an 'EA' object with
    the clause 8.2.1.3.2.2.1 toolkit parameters (unless declined) and one
    tag '81' entry per ADF after the shared UICC file system entry.
    """

    PACKAGE_AID = bytes.fromhex("F000000001")
    APPLET_AID = bytes.fromhex("F00000000101")
    USIM_AID = "A0000000871002FFFFFFFF8988000001"
    ISIM_AID = "A0000000871004FFFFFFFF8988000001"
    TOOLKIT_80 = "8008" + "0100000000000000"
    ACCESS_81_USIM = "8118" + "00" + "0100" + "00" + "10" + USIM_AID + "0100" + "00"
    EA_USIM = "EA24" + TOOLKIT_80 + ACCESS_81_USIM

    def _run(self, answers: list[str], gp_ctrl=None) -> str:
        pending = iter(answers)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(Path(temp_dir), self.PACKAGE_AID, self.APPLET_AID)
            with patch("builtins.input", lambda _prompt="": next(pending)):
                with contextlib.redirect_stdout(output):
                    InteractiveWizards.build_install_apdu(None, str(ijc_path), gp_ctrl)
        return output.getvalue()

    @staticmethod
    def _install_apdu(output: str) -> str:
        lines = re.findall(r"^(80E60C00[0-9A-F]+)$", output, re.MULTILINE)
        assert len(lines) == 1, output
        return lines[0]

    def test_a_listed_adf_adds_toolkit_and_access_parameters(self) -> None:
        # app_aid, mod_aid, priv, adf_aids, adf_toolkit, run_b, raw_p, ota, save
        output = self._run(["", "", "", self.USIM_AID, "", "N", "", "N", "N"])
        self.assertIn(
            "[+] UICC system specific parameters (Tag EA): " + self.EA_USIM, output
        )
        apdu = self._install_apdu(output)
        # Lc 40: three LV AIDs (6 + 7 + 7), LV privileges (2), the 40-byte
        # parameter field behind its length (41) and the token length (1).
        self.assertTrue(apdu.startswith("80E60C0040"), apdu)
        self.assertIn("28" + "C900" + self.EA_USIM + "00", apdu)

    def test_toolkit_parameters_can_be_declined(self) -> None:
        output = self._run(["", "", "", self.USIM_AID, "n", "N", "", "N", "N"])
        apdu = self._install_apdu(output)
        self.assertIn("C900" + "EA1A" + self.ACCESS_81_USIM, apdu)
        self.assertNotIn(self.TOOLKIT_80, apdu)

    def test_every_listed_adf_gets_its_own_entry(self) -> None:
        output = self._run(
            ["", "", "", f"{self.USIM_AID}, {self.ISIM_AID}", "", "N", "", "N", "N"]
        )
        apdu = self._install_apdu(output)
        entries = (
            "00" + "0100" + "00"
            + "10" + self.USIM_AID + "0100" + "00"
            + "10" + self.ISIM_AID + "0100" + "00"
        )
        self.assertIn("EA38" + self.TOOLKIT_80 + "812C" + entries, apdu)

    def test_enter_declines_the_grant(self) -> None:
        # app_aid, mod_aid, priv, adf_aids, run_b, raw_p, ota, save
        output = self._run(["", "", "", "", "N", "", "N", "N"])
        self.assertNotIn("This field is mandatory", output)
        self.assertNotIn("UICC system specific parameters", output)
        self.assertEqual(
            self._install_apdu(output),
            "80E60C001A05F00000000106F0000000010106F00000000101010002C9000000",
        )

    def test_an_ea_object_in_the_raw_parameters_conflicts_with_the_answer(self) -> None:
        output = self._run(
            ["", "", "", self.USIM_AID, "", "N", "C900EA0481020000", "N", "N"]
        )
        self.assertIn("already carry Tag EA", output)
        self.assertNotIn("GENERATED APDUs", output)

    def test_a_ca_object_in_the_raw_parameters_conflicts_with_the_answer(self) -> None:
        # Clause 8.2.1.3.2.2: 'CA' beside 'EA' is answered with 6A80.
        output = self._run(["", "", "", self.USIM_AID, "", "N", "C900CA00", "N", "N"])
        self.assertIn("cannot coexist with Tag EA", output)
        self.assertNotIn("GENERATED APDUs", output)

    def test_the_script_names_each_adf_and_its_access_domain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(Path(temp_dir), self.PACKAGE_AID, self.APPLET_AID)
            target = Path(temp_dir) / "usim_install.txt"
            # app_aid, mod_aid, priv, adf_aids, adf_toolkit, run_b, raw_p, ota,
            # save, save_path
            pending = iter(["", "", "", self.USIM_AID, "", "N", "", "N", "Y", str(target)])
            with patch("builtins.input", lambda _prompt="": next(pending)):
                with contextlib.redirect_stdout(io.StringIO()):
                    InteractiveWizards.build_install_apdu(None, str(ijc_path), None)
            text = target.read_text(encoding="utf-8")
        self.assertIn("#      C9 00 -- application specific parameters, empty", text)
        self.assertIn("#      EA 24 -- UICC system specific parameters", text)
        self.assertIn(
            "#        80 08 0100000000000000 -- UICC toolkit parameters: priority 01,"
            " timers 00, menu text length 00, menu entries 00, channels 00, MSL none,"
            " TAR none, services 00",
            text,
        )
        self.assertIn("#          UICC file system: access domain 00 (full access)", text)
        self.assertIn(f"#          ADF {self.USIM_AID}: access domain 00 (full access)", text)
        self.assertNotIn("no EA object", text)

    def test_declining_leaves_a_reminder_in_the_script(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = _write_ijc(Path(temp_dir), self.PACKAGE_AID, self.APPLET_AID)
            target = Path(temp_dir) / "plain_install.txt"
            pending = iter(["", "", "", "N", "N", "", "N", "Y", str(target)])
            with patch("builtins.input", lambda _prompt="": next(pending)):
                with contextlib.redirect_stdout(io.StringIO()):
                    InteractiveWizards.build_install_apdu(None, str(ijc_path), None)
            text = target.read_text(encoding="utf-8")
        self.assertIn("#      no EA object: a UICC toolkit or file-access applet gets", text)


class InstallPrivilegesConformance(unittest.TestCase):
    """GPCS 2.3.1 permits Privileges of one or three bytes, never two.

    Section 11.1.2 codes Privileges on three bytes, and the INSTALL data
    field tables (11-43 for install, 11-44 for make selectable, 11-47 for
    registry update) all give "Length of Privileges" the values '01' or
    '03'. Only the one-byte form is allowed as a backward-compatibility
    case, which OPEN extends to three. A two-byte value is not a short
    form of anything and would build a malformed INSTALL command.
    """

    def _validator(self):
        from SCP03.interface.wizards import InteractiveWizards

        return InteractiveWizards._hex_size_validator(
            "Privileges", allowed_bytes=(1, 3)
        )

    def test_one_and_three_byte_privileges_are_accepted(self) -> None:
        validate = self._validator()
        self.assertIsNone(validate("00"))
        self.assertIsNone(validate("80"))
        self.assertIsNone(validate("000000"))

    def test_two_byte_privileges_are_rejected(self) -> None:
        validate = self._validator()
        self.assertIsNotNone(validate("0000"))
        self.assertIsNotNone(validate("00000000"))

    def test_every_install_wizard_constrains_privileges(self) -> None:
        """install, make selectable and registry update all carry the rule."""

        source = (
            Path(__file__)
            .resolve()
            .parents[1]
            .joinpath("SCP03/interface/wizards.py")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            _condensed(source).count(
                _condensed(
                    'validator = lv_validator("Privileges", allowed_bytes=(1, 3))'
                )
            ),
            3,
        )
        self.assertNotIn(
            _condensed('lv_validator("Privileges", minimum_bytes=1, maximum_bytes=3)'),
            _condensed(source),
        )


class SetStatusConformance(unittest.TestCase):
    """GPCS 2.3.1 Table 11-85 makes P1 the Status Type, not a filler byte.

    Table 11-86 defines exactly three values: '80' Issuer Security Domain,
    '40' Application or Supplementary Security Domain, '60' Security Domain
    and its associated Applications. Everything else is RFU. Section 11.10.1
    scopes the command to the card and Application life cycles, so an
    Executable Load File is not a target at all.
    """

    DEFINED_STATUS_TYPES = {"80", "40", "60"}

    def _gp_source(self) -> str:
        return (
            Path(__file__)
            .resolve()
            .parents[1]
            .joinpath("SCP03/logic/gp.py")
            .read_text(encoding="utf-8")
        )

    def test_set_status_sends_a_status_type_in_p1(self) -> None:
        source = self._gp_source()
        self.assertIn(
            _condensed('cmd = f"80F0{status_type:02X}{state_byte:02X}'),
            _condensed(source),
            "P1 must carry the Status Type",
        )
        self.assertNotIn(
            _condensed('cmd = f"80F000{state_byte:02X}'), _condensed(source)
        )

    def test_the_default_status_type_suits_an_application_aid(self) -> None:
        """LOCK and UNLOCK pass an application AID, so '40' is the right default."""

        self.assertIn(
            _condensed("status_type: int = 0x40"), _condensed(self._gp_source())
        )

    def test_the_wizard_offers_only_defined_status_types(self) -> None:
        source = (
            Path(__file__)
            .resolve()
            .parents[1]
            .joinpath("SCP03/interface/shell_wizards.py")
            .read_text(encoding="utf-8")
        )
        start = source.index("def run_set_status")
        body = source[start : start + 2600]
        # Whitespace-tolerant: pinned to `p1 ="80"` this found nothing
        # once the module was formatted, and an empty set is a subset of
        # anything -- the test passed while checking nothing.
        offered = set(re.findall(r'p1\s*=\s*"([0-9A-F]{2})"', body))
        self.assertTrue(offered, "no Status Type literals found in the wizard")
        offered.discard("00")  # the pre-selection placeholder
        self.assertTrue(
            offered <= self.DEFINED_STATUS_TYPES,
            f"wizard offers undefined Status Types: {sorted(offered - self.DEFINED_STATUS_TYPES)}",
        )
        self.assertNotIn("20", offered, "'20' is RFU in Table 11-86")
