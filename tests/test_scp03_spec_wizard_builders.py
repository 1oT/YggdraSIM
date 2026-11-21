# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Spec alignment of the SCP03 wizard builders.

Every vector below was read from the library copies of ETSI TS 102 222
v17.1, ETSI TS 102 221 v18.4, ETSI TS 102 226 v19 and the GlobalPlatform
Card Specification v2.3.1; the clause sits next to each assertion. AIDs use
the proprietary 'F0' RID and FIDs come from TS 31.102 / TS 102 221.
"""

from __future__ import annotations

import contextlib
import io
import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from SCP03.interface.shell_wizards import ShellInteractiveWizards
from SCP03.interface.wizards import InteractiveWizards
from yggdrasim_common.gui_server.actions.scp03 import _build_fcp_template_fields

try:
    from pySim.ts_102_221 import FcpTemplate

    PYSIM_AVAILABLE = True
except ImportError:
    PYSIM_AVAILABLE = False


def _run_with_answers(func, answers, *args):
    """Drive an interactive wizard with scripted terminal input."""
    pending = iter(answers)
    with patch("builtins.input", lambda _prompt="": next(pending)):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = func(*args)
    return result, output.getvalue()


def _generated_apdu(output: str) -> str:
    match = re.search(r"Generated APDU:\s*\n\s*([0-9A-F]+)", output)
    assert match is not None, output
    return match.group(1)


def _tag_sequence(fcp_hex: str) -> list[int]:
    """Top-level tags of an FCP template with one-byte tags and short lengths."""
    raw = bytes.fromhex(fcp_hex)
    assert raw[0] == 0x62
    body = raw[2:] if raw[1] < 0x80 else raw[3:]
    tags = []
    offset = 0
    while offset < len(body):
        tags.append(body[offset])
        length = body[offset + 1]
        offset += 2 + length
    return tags


def _decode_fcp(fcp_hex: str) -> dict:
    template = FcpTemplate()
    template.from_tlv(bytes.fromhex(fcp_hex))
    merged: dict = {}
    for entry in template.to_dict()["fcp_template"]:
        merged.update(entry)
    return merged


class FcpBuilderSpecTests(unittest.TestCase):
    """TS 102 222 v17.1 §6.3.2.2 CREATE FILE data field."""

    def test_sfi_number_is_coded_in_bits_b8_to_b4(self) -> None:
        # TS 102 222 v17.1 §6.3.2.2.2 tag '88': "coded from bits b8 to b4.
        # Bits b3,b2,b1 = 000"; TS 102 221 v18.4 §11.1.1.4.8 agrees.
        out = _build_fcp_template_fields(
            file_type="TRANSPARENT_EF",
            full_path="3F007FFF6F07",
            sec_attr_hex="8B036F0602",
            file_size_hex="0009",
            sfi_hex="07",
        )
        self.assertIn("880138", out["fcp_hex"])

    def test_sfi_zero_and_absent_follow_the_three_cases(self) -> None:
        base = dict(
            file_type="TRANSPARENT_EF",
            full_path="3F007FFF6F07",
            sec_attr_hex="8B036F0602",
            file_size_hex="0009",
        )
        disabled = _build_fcp_template_fields(sfi_hex="00", **base)
        derived = _build_fcp_template_fields(**base)
        # "there is no value part in the TLV: Short File Identifier is not
        # supported by the EF" versus "Tag '88' is missing".
        self.assertTrue(disabled["fcp_hex"].endswith("8800"))
        self.assertNotIn(0x88, _tag_sequence(derived["fcp_hex"]))

    def test_sfi_above_1e_is_rejected(self) -> None:
        # TS 102 221 v18.4 §8.4.3: an SFI is a five-bit value from 1 to 30.
        with self.assertRaisesRegex(ValueError, "01..1E"):
            _build_fcp_template_fields(
                file_type="TRANSPARENT_EF",
                full_path="3F007FFF6F07",
                sec_attr_hex="8B036F0602",
                file_size_hex="0009",
                sfi_hex="1F",
            )

    def test_linear_fixed_descriptor_is_four_bytes(self) -> None:
        # TS 102 222 v17.1 §6.3.2.2.2 Table 4: length '02' or '04', the record
        # length "coded on 2 bytes"; the record count comes from tag '80'.
        out = _build_fcp_template_fields(
            file_type="LINEAR_FIXED_EF",
            full_path="3F007FFF6F3A",
            sec_attr_hex="8B036F0601",
            rec_len_hex="1C",
            num_rec_hex="0A",
        )
        self.assertIn("82044221001C", out["fcp_hex"])
        self.assertIn("80020118", out["fcp_hex"])

    def test_security_attribute_tlv_is_mandatory(self) -> None:
        # TS 102 222 v17.1 §6.3.2.2.1 Table 3 and §6.3.2.2.2 Table 4 mark the
        # '8C' / 'AB' / '8B' TLV as M: "Exactly one of the tags shall be present".
        with self.assertRaisesRegex(ValueError, "sec_attr_hex is required"):
            _build_fcp_template_fields(
                file_type="DF_ADF",
                full_path="3F007F20",
                file_size_hex="0400",
                c6_hex="C609900140830101950108",
            )

    def test_tag_order_follows_table_4(self) -> None:
        # TS 102 222 v17.1 §6.2: mandatory TLVs keep the order of the command
        # description; Table 4 lists 82, 83, 8A, security, 80, 88, A5.
        out = _build_fcp_template_fields(
            file_type="TRANSPARENT_EF",
            full_path="3F007FFF6F07",
            sec_attr_hex="8B036F0602",
            file_size_hex="0009",
            sfi_hex="07",
            prop_a5_hex="C10100",
        )
        self.assertEqual(
            _tag_sequence(out["fcp_hex"]),
            [0x82, 0x83, 0x8A, 0x8B, 0x80, 0x88, 0xA5],
        )

    def test_df_tag_order_follows_table_3(self) -> None:
        # Table 3: 82, 83, [84], 8A, security, 81, C6, [85/A5].
        out = _build_fcp_template_fields(
            file_type="DF_ADF",
            full_path="3F007FFF",
            sec_attr_hex="8B032F060E",
            file_size_hex="0400",
            aid_hex="A0000000871002FFFFFFFF8900000100",
            c6_hex="C609900140830101950108",
        )
        self.assertEqual(
            _tag_sequence(out["fcp_hex"]),
            [0x82, 0x83, 0x84, 0x8A, 0x8B, 0x81, 0xC6],
        )

    @unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed")
    def test_pysim_decodes_the_gui_transparent_ef_template(self) -> None:
        out = _build_fcp_template_fields(
            file_type="TRANSPARENT_EF",
            full_path="3F007FFF6F07",
            sec_attr_hex="8B036F0602",
            file_size_hex="0009",
            sfi_hex="07",
        )
        decoded = _decode_fcp(out["fcp_hex"])
        self.assertEqual(decoded["short_file_identifier"], 7)
        self.assertEqual(decoded["file_size"], 9)
        self.assertEqual(decoded["life_cycle_status_integer"], "operational_activated")
        descriptor = decoded["file_descriptor"]["file_descriptor_byte"]
        self.assertEqual(descriptor["structure"], "transparent")
        self.assertTrue(descriptor["shareable"])

    @unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed")
    def test_pysim_decodes_the_gui_linear_fixed_and_df_templates(self) -> None:
        linear = _build_fcp_template_fields(
            file_type="LINEAR_FIXED_EF",
            full_path="3F007FFF6F3A",
            sec_attr_hex="8B036F0601",
            rec_len_hex="1C",
            num_rec_hex="0A",
        )
        decoded = _decode_fcp(linear["fcp_hex"])
        self.assertEqual(decoded["file_descriptor"]["record_len"], 0x1C)
        self.assertIsNone(decoded["file_descriptor"]["num_of_rec"])
        self.assertEqual(decoded["file_size"], 0x1C * 0x0A)

        directory = _build_fcp_template_fields(
            file_type="DF_ADF",
            full_path="3F007F20",
            sec_attr_hex="8B032F060E",
            file_size_hex="0400",
            c6_hex="C609900140830101950108",
        )
        decoded = _decode_fcp(directory["fcp_hex"])
        descriptor = decoded["file_descriptor"]["file_descriptor_byte"]
        # TS 102 221 v18.4 Table 11.5: '78' = shareable DF or ADF.
        self.assertEqual(descriptor["file_type"], "df")
        self.assertTrue(descriptor["shareable"])
        self.assertEqual(decoded["total_file_size"], 0x400)

    def test_cli_builder_matches_the_gui_wire(self) -> None:
        answers = ["2", "3F007FFF6F07", "8B036F0602", "0009", "07", ""]
        result, _output = _run_with_answers(
            ShellInteractiveWizards._build_fcp_template, answers
        )
        gui = _build_fcp_template_fields(
            file_type="TRANSPARENT_EF",
            full_path="3F007FFF6F07",
            sec_attr_hex="8B036F0602",
            file_size_hex="0009",
            sfi_hex="07",
        )
        self.assertEqual(result["fcp"], gui["fcp_hex"])

    def test_cli_builder_insists_on_a_security_attribute(self) -> None:
        answers = ["2", "3F007FFF6F07", "", "8B036F0602", "0009", "", ""]
        result, output = _run_with_answers(
            ShellInteractiveWizards._build_fcp_template, answers
        )
        self.assertIn("mandatory", output)
        self.assertIn("8B036F0602", result["fcp"])
        self.assertNotIn(0x88, _tag_sequence(result["fcp"]))

    def test_cli_builder_sfi_zero_disables_sfi(self) -> None:
        answers = ["3", "3F007FFF6F3A", "8B036F0601", "00", "001C", "0A", ""]
        result, _output = _run_with_answers(
            ShellInteractiveWizards._build_fcp_template, answers
        )
        self.assertIn("82044221001C", result["fcp"])
        self.assertTrue(result["fcp"].endswith("8800"))


class ResizeWizardSpecTests(unittest.TestCase):
    """TS 102 222 v17.1 §6.10.2.1 RESIZE FILE data field."""

    def _shell(self):
        calls: list[str] = []
        fs_ctrl = SimpleNamespace(
            select=lambda target: calls.append(f"select:{target}"),
            resize_file=lambda fcp: calls.append(f"resize:{fcp}"),
        )
        return SimpleNamespace(fs_ctrl=fs_ctrl), calls

    def test_ef_resize_carries_tag_83_and_tag_80(self) -> None:
        shell, calls = self._shell()
        # action, target, tag 83, tag 80, tag 81, A5 builder, confirm.
        answers = ["9", "6F07", "", "0040", "", "n", "y"]
        _run_with_answers(ShellInteractiveWizards.run_fs_admin_wizard, answers, shell)
        # Table 17: '62' LL '83' '02' FID '80' LL size.
        self.assertEqual(calls, ["select:6F07", "resize:620883026F0780020040"])

    def test_df_resize_carries_the_total_file_size(self) -> None:
        # Tag '81' "shall only be provided if the MF or a DF/ADF is resized".
        shell, calls = self._shell()
        answers = ["9", "7F10", "", "", "1000", "n", "y"]
        _run_with_answers(ShellInteractiveWizards.run_fs_admin_wizard, answers, shell)
        self.assertEqual(calls, ["select:7F10", "resize:620883027F1081021000"])

    def test_tag_80_and_tag_81_are_exclusive(self) -> None:
        # Tag '80' "shall only be provided if an EF is resized", tag '81'
        # "shall only be provided if the MF or a DF/ADF is resized".
        shell, calls = self._shell()
        answers = ["9", "6F07", "", "0040", "0080", "n", "y"]
        _result, output = _run_with_answers(
            ShellInteractiveWizards.run_fs_admin_wizard, answers, shell
        )
        self.assertIn("not both", output)
        self.assertEqual([call for call in calls if call.startswith("resize:")], [])

    def test_proprietary_template_carries_the_table_18_objects(self) -> None:
        # Table 18: 'C1' filling pattern, 'C2' repeat pattern and '86' the new
        # maximum file size of a BER-TLV structured EF, wrapped in one 'A5'.
        shell, calls = self._shell()
        answers = ["9", "6FE8", "", "0040", "", "y", "", "0011", "0800", "y"]
        _run_with_answers(ShellInteractiveWizards.run_fs_admin_wizard, answers, shell)
        self.assertEqual(
            calls,
            ["select:6FE8", "resize:621283026FE880020040A508C202001186020800"],
        )

    def test_filling_pattern_wraps_in_the_same_proprietary_template(self) -> None:
        shell, calls = self._shell()
        answers = ["9", "6F07", "", "0040", "", "y", "FF", "", "", "y"]
        _run_with_answers(ShellInteractiveWizards.run_fs_admin_wizard, answers, shell)
        self.assertEqual(
            calls,
            ["select:6F07", "resize:620D83026F0780020040A503C101FF"],
        )

    def test_filling_and_repeat_patterns_are_exclusive(self) -> None:
        # Table 18 note 1: "Tag 'C1' and Tag 'C2' shall not be both present
        # within the same command."
        shell, calls = self._shell()
        answers = ["9", "6F07", "", "0040", "", "y", "FF", "AA", "", "y"]
        _result, output = _run_with_answers(
            ShellInteractiveWizards.run_fs_admin_wizard, answers, shell
        )
        self.assertIn("not both", output)
        self.assertEqual([call for call in calls if call.startswith("resize:")], [])


class InstallDataFieldSpecTests(unittest.TestCase):
    """GPC v2.3.1 §11.5.2.3 INSTALL command data fields."""

    def test_ber_lv_field_lengths(self) -> None:
        # Tables 11-42 to 11-46: '00'-'80', '81 80'-'81 FF', '82 01 00'-'82 FF FF'.
        self.assertEqual(
            InteractiveWizards._build_ber_lv_field("AA" * 127)[:1].hex().upper(), "7F"
        )
        self.assertEqual(
            InteractiveWizards._build_ber_lv_field("AA" * 128)[:2].hex().upper(), "8180"
        )
        self.assertEqual(
            InteractiveWizards._build_ber_lv_field("AA" * 256)[:3].hex().upper(),
            "820100",
        )
        self.assertEqual(InteractiveWizards._build_ber_lv_field(""), b"\x00")

    def test_install_for_load_data_field_and_le(self) -> None:
        # Table 11-42 with an empty SD AID, hash, parameters and token;
        # Table 11-40 gives INSTALL Le '00'.
        answers = ["F000000001", "", "", "", "", ""]
        _result, output = _run_with_answers(
            InteractiveWizards._run_install_load, answers, None, None
        )
        self.assertEqual(
            _generated_apdu(output), "80E602000A" + "05F000000001" + "00000000" + "00"
        )

    def test_install_for_install_uses_ber_length_above_127_bytes(self) -> None:
        params = "C981C5" + "AA" * 197
        answers = [
            "F000000001",
            "F00000000101",
            "F00000000102",
            "",
            "",
            "",
            params,
            "",
        ]
        _result, output = _run_with_answers(
            InteractiveWizards._run_install_install,
            answers,
            None,
            None,
            "04",
            "INSTALL [for install]",
        )
        apdu = _generated_apdu(output)
        expected_data = (
            "05F000000001"
            + "06F00000000101"
            + "06F00000000102"
            + "0100"
            + "81C8"
            + params
            + "00"
        )
        self.assertEqual(apdu, "80E60400E1" + expected_data + "00")

    def test_make_selectable_starts_with_two_empty_length_fields(self) -> None:
        # Table 11-44: 'Length of data' '00', 'Length of data' '00', then the
        # Application AID, Privileges, Parameters and Token.
        answers = ["F00000000101", "", "", "", "", ""]
        _result, output = _run_with_answers(
            InteractiveWizards._run_install_make_selectable, answers, None, None
        )
        self.assertEqual(
            _generated_apdu(output),
            "80E608000D" + "0000" + "06F00000000101" + "0100" + "00" + "00" + "00",
        )

    def test_extradition_field_order(self) -> None:
        # Table 11-45: L(SD AID) SD AID, '00', L(AID) AID, '00',
        # L(Extradition Parameters), L(Extradition Token) Token.
        answers = ["F000000002", "F00000000101", "AABB"]
        _result, output = _run_with_answers(
            InteractiveWizards._run_install_extradition, answers, None, None
        )
        self.assertEqual(
            _generated_apdu(output),
            "80E6100013"
            + "05F000000002"
            + "00"
            + "06F00000000101"
            + "00"
            + "00"
            + "02AABB"
            + "00",
        )

    def test_registry_update_leaves_privileges_unchanged_by_default(self) -> None:
        # Table 11-46: Length of Privileges '00' when they are not updated;
        # '01 00' would revoke every privilege of the Application.
        answers = ["F00000000101", "", "", "", "", ""]
        _result, output = _run_with_answers(
            InteractiveWizards._run_install_registry_update, answers, None, None
        )
        self.assertEqual(
            _generated_apdu(output),
            "80E640000C" + "00" + "00" + "06F00000000101" + "00" + "00" + "00" + "00",
        )

    def test_install_for_personalization_data_field(self) -> None:
        # Table 11-47: '00' '00' L(AID) AID '00' '00' '00'.
        self.assertEqual(
            InteractiveWizards._build_install_perso("F00000000101"),
            "80E620000C" + "0000" + "06F00000000101" + "000000" + "00",
        )

    def test_store_data_le_follows_p1_bit_1(self) -> None:
        # Table 11-88: Le '00' if P1.b1 = 1 (ISO case 4), absent otherwise.
        self.assertEqual(
            InteractiveWizards._build_store_data_with_params("CAFE", "91", "00"),
            "80E2910002CAFE00",
        )
        self.assertEqual(
            InteractiveWizards._build_store_data_with_params("CAFE", "90", "00"),
            "80E2900002CAFE",
        )


class InstallParameterTemplateSpecTests(unittest.TestCase):
    """GPC v2.3.1 §11.5.2.3.7 and TS 102 226 v19 §8.2.1.3.2."""

    def test_system_specific_parameters_use_table_11_49_tags(self) -> None:
        # Table 11-49: C7 volatile quota, C8 non-volatile quota, CB global
        # service parameters, CF implicit selection; C6 is load-only.
        answers = ["", "0100", "0200", "0102", "80", "", ""]
        result, _output = _run_with_answers(
            InteractiveWizards._build_system_parameters_ef, answers
        )
        self.assertEqual(
            result.hex().upper(), "EF0F" + "C7020100" + "C8020200" + "CB020102" + "CF0180"
        )

    def test_memory_values_above_32767_need_four_bytes(self) -> None:
        # §11.5.2.3.7: "a 2-byte integer for values up to 32767 and a 4-byte
        # integer above 32767".
        validate = InteractiveWizards._memory_size_validator("quota")
        self.assertIsNone(validate("7FFF"))
        self.assertIsNotNone(validate("8000"))
        self.assertIsNone(validate("00008000"))
        self.assertIsNotNone(validate("010000"))

    def test_ca_parameter_nests_inside_the_ef_template(self) -> None:
        # Table 11-49 lists 'CA' under 'EF'; TS 102 226 v19 §8.2.1.3.2.1: the
        # tag 'CA' object "is included in the System Specific Parameters (Tag 'EF')".
        answers = ["", "", "0001010000000000"]
        result, _output = _run_with_answers(
            InteractiveWizards._build_install_parameters_tlv, answers
        )
        self.assertEqual(result, "C900" + "EF0A" + "CA08" + "0001010000000000")

    def test_ca_parameter_joins_an_existing_ef_template(self) -> None:
        answers = ["", "y", "", "0100", "", "", "", "", "", "0001010000000000"]
        result, _output = _run_with_answers(
            InteractiveWizards._build_install_parameters_tlv, answers
        )
        self.assertEqual(
            result, "C900" + "EF0E" + "C7020100" + "CA08" + "0001010000000000"
        )

    def test_toolkit_parameters_follow_the_ts_102_226_field_order(self) -> None:
        # TS 102 226 v19 §8.2.1.3.2.2.1: priority, timers, menu text length,
        # menu entries (m), 2 x m bytes, channels, L(MSL) MSL, L(TAR) TARs,
        # services. §8.2.1.3.2.2.2: tag 81 lists "L(AID) AID L(AD) AD L(DAP) DAP"
        # entries, the UICC file system entry having an empty AID.
        answers = [
            "y", "", "y", "",
            "01", "02", "10", "01", "0000", "", "B00010", "01", "02",
            "1", "",
        ]
        result, _output = _run_with_answers(
            InteractiveWizards._build_toolkit_parameters_ea, answers
        )
        self.assertEqual(
            result.hex().upper(),
            "EA15"
            + "800D" + "01" + "02" + "10" + "01" + "0000" + "01" + "00" + "03" + "B00010" + "02"
            + "8104" + "00" + "0100" + "00",
        )

    def test_menu_entry_list_must_match_the_menu_count(self) -> None:
        answers = ["y", "", "", "", "01", "00", "00", "02", "", "", "", "", ""]
        result, output = _run_with_answers(
            InteractiveWizards._build_toolkit_parameters_ea, answers
        )
        self.assertIn("Menu entries list must hold", output)
        self.assertEqual(result, b"")

    def test_uicc_access_mechanism_entry(self) -> None:
        # §8.2.1.3.2.5.1: ADP '02' carries a 3-byte ADD; §8.2.1.3.2.2.2 wraps
        # it as L(AID)=00, L(AD)=04, AD, L(DAP)=00.
        result, _output = _run_with_answers(
            InteractiveWizards._build_access_domain_parameter,
            ["2", "010203", ""],
            0x81,
            "Access Parameters",
        )
        self.assertEqual(result.hex().upper(), "8107" + "00" + "04" + "02010203" + "00")

    def test_no_access_entry(self) -> None:
        result, _output = _run_with_answers(
            InteractiveWizards._build_access_domain_parameter,
            ["3", ""],
            0x82,
            "Admin Access Parameters",
        )
        self.assertEqual(result.hex().upper(), "8204" + "00" + "01FF" + "00")

    def test_listed_adfs_follow_the_file_system_entry(self) -> None:
        # §8.2.1.3.2.2.2: after the UICC file system entry (empty AID) come
        # "L(ADF AID) ADF AID L(AD) AD L(DAP) DAP" entries, the AID 5 to 16
        # bytes, each carrying the access domain chosen for the file system.
        usim_aid = "A0000000871002FFFFFFFF8988000001"
        result, _output = _run_with_answers(
            InteractiveWizards._build_access_domain_parameter,
            ["1", f"{usim_aid}, F0 00 00 00 01 01"],
            0x81,
            "Access Parameters",
        )
        self.assertEqual(
            result.hex().upper(),
            "8122"
            + "00" + "0100" + "00"
            + "10" + usim_aid + "0100" + "00"
            + "06" + "F00000000101" + "0100" + "00",
        )

    def test_a_short_adf_aid_is_refused_and_asked_again(self) -> None:
        result, output = _run_with_answers(
            InteractiveWizards._build_access_domain_parameter,
            ["3", "A000", ""],
            0x81,
            "Access Parameters",
        )
        self.assertIn("5 to 16 bytes", output)
        self.assertEqual(result.hex().upper(), "8104" + "00" + "01FF" + "00")


class PutKeyWizardKeyTypeTests(unittest.TestCase):
    """GPC v2.3.1 Table 11-16: DES keys are type '80', AES keys '88'."""

    def _run(self, algo: str) -> int:
        from unittest import mock

        from SCP03.interface.shell_wizards import ShellInteractiveWizards

        shell = mock.Mock()
        shell.gp_ctrl.put_key = mock.Mock(return_value=False)
        key = "00" * 16
        with mock.patch("builtins.print"):
            ShellInteractiveWizards._exec_put_key(shell, 0x00, 0x01, 0x30, [key, key, key], algo)
        return shell.gp_ctrl.put_key.call_args.args[4]

    def test_des_and_3des_use_key_type_80(self) -> None:
        self.assertEqual(self._run("DES"), 0x80)
        self.assertEqual(self._run("3DES"), 0x80)

    def test_aes_uses_key_type_88(self) -> None:
        self.assertEqual(self._run("AES"), 0x88)


class DgiCodingSpecTests(unittest.TestCase):
    """GPC v2.3.1 §11.1.12: DGI lengths are one byte below 255, 'FF' + 2 bytes above."""

    def test_dgi_length_helpers(self) -> None:
        self.assertEqual(InteractiveWizards._encode_dgi_length(0x80), "80")
        self.assertEqual(InteractiveWizards._encode_dgi_length(0xFE), "FE")
        self.assertEqual(InteractiveWizards._encode_dgi_length(0xFF), "FF00FF")
        self.assertEqual(InteractiveWizards._decode_dgi_length("80"), (0x80, 1))
        self.assertEqual(InteractiveWizards._decode_dgi_length("FF0100"), (0x100, 3))

    def test_patch_dgi_keeps_single_byte_length_at_128(self) -> None:
        base = "3F00" + "80" + "5A00" * 64
        self.assertEqual(InteractiveWizards._patch_dgi(base, "5A01CC"), "3F00035A01CC")

    def test_patch_dgi_reads_ff_prefixed_length(self) -> None:
        base = "3F00" + "FF0100" + "5A00" * 64 + "9F330100" * 32
        result = InteractiveWizards._patch_dgi(base, "5A01CC")
        self.assertEqual(result, "3F00" + "83" + "9F330100" * 32 + "5A01CC")


class PutKeyWizardSpecTests(unittest.TestCase):
    """GPC v2.3.1 §11.8.2: KVN '01'-'7F' (P1 '00' adds keys), KID '00'-'7F'."""

    def test_reference_ranges(self) -> None:
        kvn = ShellInteractiveWizards._byte_range_validator("New KVN", 0x01, 0x7F)
        kid = ShellInteractiveWizards._byte_range_validator("Key ID", 0x00, 0x7F)
        self.assertIsNone(kvn("30"))
        self.assertIsNone(kvn("7F"))
        self.assertIsNotNone(kvn("00"))
        self.assertIsNotNone(kvn("80"))
        self.assertIsNone(kid("00"))
        self.assertIsNotNone(kid("80"))
        self.assertIsNotNone(kid("0001"))


if __name__ == "__main__":
    unittest.main()
