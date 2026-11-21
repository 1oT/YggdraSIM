# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Wizard capabilities added after the SCP03 specification audit.

Every vector was read from the library copies of the standards named beside
it:

* ETSI TS 102 221 v18.4 §11.1.1.4.3 table 11.5 -- the file descriptor byte of
  a cyclic EF ('46') and of a BER-TLV structured EF ('79').
* ETSI TS 102 221 v18.4 §11.1.1.4.6.5 / §11.1.1.4.6.7 -- file details and
  maximum file size inside the 'A5' proprietary template.
* ETSI TS 102 222 v17.1 §6.3.2.2.2 table 4 and table 4a -- the CREATE FILE
  data field, note 1 (record length) and notes 2 and 3 (the two BER-TLV
  proprietary objects).
* ETSI TS 102 222 v17.1 §6.10.2.1 tables 17 and 18 -- the RESIZE FILE data
  field and its proprietary template.
* GlobalPlatform Card Specification v2.3.1 §11.1.2 tables 11-8 and 11-9 --
  privileges bytes 2 and 3.

The CLI builder in ``SCP03.interface.shell_wizards`` and the GUI builder in
``yggdrasim_common.gui_server.actions.scp03`` have to agree byte for byte;
pySim's ``FcpTemplate`` is the decoding oracle.
"""

from __future__ import annotations

import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from SCP03.interface.wizards import InteractiveWizards
from SCP03.interface.shell_wizards import ShellInteractiveWizards
from yggdrasim_common.gui_server.actions import scp03 as gui_scp03
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


def _top_level_tags(fcp_hex: str) -> dict[int, str]:
    """Map each top-level FCP tag to its value, for one-byte tags."""
    raw = bytes.fromhex(fcp_hex)
    assert raw[0] == 0x62, fcp_hex
    body = raw[2:] if raw[1] < 0x80 else raw[3:]
    tags: dict[int, str] = {}
    offset = 0
    while offset < len(body):
        length = body[offset + 1]
        tags[body[offset]] = body[offset + 2:offset + 2 + length].hex().upper()
        offset += 2 + length
    return tags


def _decode_fcp(fcp_hex: str) -> dict:
    template = FcpTemplate()
    template.from_tlv(bytes.fromhex(fcp_hex))
    merged: dict = {}
    for entry in template.to_dict()["fcp_template"]:
        merged.update(entry)
    return merged


class CyclicEfCreationTests(unittest.TestCase):
    """TS 102 222 v17.1 §6.3.2.2.2 with TS 102 221 v18.4 table 11.5."""

    # CLI answers: type, path, security attribute, SFI, record length,
    # number of records, proprietary information.
    CLI_ANSWERS = ["4", "3F007F106F3B", "8B036F0602", "", "001E", "03", ""]

    def _cli(self) -> dict:
        result, _output = _run_with_answers(
            ShellInteractiveWizards._build_fcp_template, self.CLI_ANSWERS
        )
        return result

    def _gui(self) -> dict:
        return _build_fcp_template_fields(
            file_type="CYCLIC_EF",
            full_path="3F007F106F3B",
            sec_attr_hex="8B036F0602",
            rec_len_hex="001E",
            num_rec_hex="03",
        )

    def test_descriptor_byte_is_the_cyclic_structure(self) -> None:
        # Table 11.5: b7 shareable, b6-b4 = 000 working EF, b3-b1 = 110
        # cyclic; table 4 keeps the four-byte descriptor of a record file.
        self.assertIn("82044621001E", self._cli()["fcp"])

    def test_reserved_file_size_is_record_length_times_record_count(self) -> None:
        # Page 14: "In the case of an EF with linear or cyclic structure, it
        # is the record length multiplied by the number of records of the EF."
        result = self._cli()
        self.assertEqual(result["file_size"], 0x1E * 3)
        self.assertEqual(result["rec_len"], 0x1E)
        self.assertEqual(result["num_rec"], 3)
        self.assertIn("8002005A", result["fcp"])

    def test_cli_and_gui_emit_the_same_wire(self) -> None:
        self.assertEqual(self._cli()["fcp"], self._gui()["fcp_hex"])

    @unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
    def test_template_decodes_as_a_cyclic_ef(self) -> None:
        decoded = _decode_fcp(self._cli()["fcp"])
        descriptor = decoded["file_descriptor"]
        self.assertEqual(descriptor["file_descriptor_byte"]["structure"], "cyclic")
        self.assertEqual(descriptor["file_descriptor_byte"]["file_type"], "working_ef")
        self.assertTrue(descriptor["file_descriptor_byte"]["shareable"])
        self.assertEqual(descriptor["record_len"], 0x1E)
        self.assertEqual(decoded["file_size"], 0x1E * 3)


class BerTlvEfCreationTests(unittest.TestCase):
    """TS 102 222 v17.1 §6.3.2.2.2 table 4a with TS 102 221 v18.4 §11.1.1.4.6."""

    # CLI answers: type, path, security attribute, reserved file size, SFI,
    # file details, maximum file size, proprietary information.
    CLI_ANSWERS = [
        "5",
        "3F007F106FE8",
        "8B036F0603",
        "0040",
        "10",
        "01",
        "0080",
        "",
    ]

    def _cli(self, answers=None) -> dict:
        result, _output = _run_with_answers(
            ShellInteractiveWizards._build_fcp_template, answers or self.CLI_ANSWERS
        )
        return result

    def test_descriptor_byte_is_the_ber_tlv_structure(self) -> None:
        # Table 11.5: b6-b1 = '111001' is the BER-TLV structure, so a
        # shareable working EF is '79', and the descriptor stays two bytes
        # because table 4 note 1 applies to record files only.
        result = self._cli()
        self.assertIn("82027921", result["fcp"])
        self.assertEqual(result["rec_len"], 0)
        self.assertEqual(result["num_rec"], 0)

    def test_reserved_and_maximum_file_size_sit_where_the_tables_put_them(self) -> None:
        # Table 4: tag '80' File Size (Reserved File Size) is mandatory and
        # top level. Table 4a note 2: tag '86' Maximum File Size lives inside
        # the 'A5' template and is defined for BER-TLV EFs only.
        tags = _top_level_tags(self._cli()["fcp"])
        self.assertEqual(tags[0x80], "0040")
        self.assertNotIn(0x86, tags)
        self.assertIn("86020080", tags[0xA5])

    def test_file_details_is_emitted_even_when_left_blank(self) -> None:
        # Table 4a note 3: tag '84' is mandatory for a BER-TLV structured EF.
        # TS 102 221 §11.1.1.4.6.5: b1 = DER coding only is supported.
        answers = list(self.CLI_ANSWERS)
        answers[5] = ""
        answers[6] = ""
        self.assertIn("A503840101", self._cli(answers)["fcp"])

    def test_both_surfaces_carry_a_maximum_file_size_wider_than_two_bytes(self) -> None:
        # TS 102 221 v18.4 §11.1.1.4.6.7 gives the value as "length X, X >= 2",
        # so a card with more than 64 KiB free can be addressed. Both builders
        # widen together, and both stop at four bytes.
        answers = list(self.CLI_ANSWERS)
        answers[6] = "010000"
        result, _output = _run_with_answers(
            ShellInteractiveWizards._build_fcp_template, answers
        )
        self.assertIn("8603010000", result["fcp"])

        built = _build_fcp_template_fields(
            file_type="BER_TLV_EF",
            full_path="3F007F106FE8",
            sec_attr_hex="8B036F0603",
            file_size_hex="0040",
            max_file_size_hex="010000",
        )
        self.assertIn("8603010000", built["fcp_hex"])

        with self.assertRaisesRegex(ValueError, "at most 4 bytes"):
            _build_fcp_template_fields(
                file_type="BER_TLV_EF",
                full_path="3F007F106FE8",
                sec_attr_hex="8B036F0603",
                file_size_hex="0040",
                max_file_size_hex="0100000000",
            )

    def test_maximum_file_size_below_the_reserved_size_is_refused(self) -> None:
        answers = list(self.CLI_ANSWERS)
        answers[6] = "0010"
        result, output = _run_with_answers(
            ShellInteractiveWizards._build_fcp_template, answers
        )
        self.assertEqual(result, {})
        self.assertIn("Maximum file size", output)

    def test_operator_objects_join_the_same_proprietary_template(self) -> None:
        # §6.3.2.2.2: "Additional private TLV objects ... may be present after
        # the TLV objects defined in this clause" -- one 'A5', not two.
        answers = list(self.CLI_ANSWERS)
        answers[4] = ""
        answers[6] = ""
        answers[7] = "D201FF"
        fcp_hex = self._cli(answers)["fcp"]
        self.assertEqual(fcp_hex.count("A5"), 1)
        self.assertIn("A506840101D201FF", fcp_hex)

    def test_cli_and_gui_emit_the_same_wire(self) -> None:
        gui = _build_fcp_template_fields(
            file_type="BER_TLV_EF",
            full_path="3F007F106FE8",
            sec_attr_hex="8B036F0603",
            file_size_hex="0040",
            sfi_hex="10",
            file_details_hex="01",
            max_file_size_hex="0080",
        )
        self.assertEqual(self._cli()["fcp"], gui["fcp_hex"])

    def test_gui_refuses_the_ber_tlv_objects_on_other_file_types(self) -> None:
        with self.assertRaisesRegex(ValueError, "BER_TLV_EF only"):
            _build_fcp_template_fields(
                file_type="TRANSPARENT_EF",
                full_path="3F006F07",
                sec_attr_hex="8C0100",
                file_size_hex="0010",
                max_file_size_hex="0080",
            )

    @unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
    def test_template_decodes_with_both_proprietary_objects(self) -> None:
        decoded = _decode_fcp(self._cli()["fcp"])
        self.assertEqual(
            decoded["file_descriptor"]["file_descriptor_byte"]["structure"],
            "ber_tlv",
        )
        self.assertEqual(decoded["file_size"], 0x40)
        proprietary: dict = {}
        for entry in decoded["proprietary_information"]:
            proprietary.update(entry)
        self.assertTrue(proprietary["file_details"]["der_coding_only"])
        self.assertEqual(proprietary["maximum_file_size"], 0x80)


class GuiFileTypeSurfaceTests(unittest.TestCase):
    """The GUI action has to offer what the CLI wizard offers."""

    def test_build_fcp_action_exposes_every_file_type(self) -> None:
        choices = dict(
            (field.name, field)
            for field in gui_scp03.FS_BUILD_FCP_SPEC.inputs
        )["file_type"].choices
        self.assertEqual(
            tuple(choices),
            ("DF_ADF", "TRANSPARENT_EF", "LINEAR_FIXED_EF", "CYCLIC_EF", "BER_TLV_EF"),
        )

    def test_build_fcp_action_exposes_the_ber_tlv_objects(self) -> None:
        names = [field.name for field in gui_scp03.FS_BUILD_FCP_SPEC.inputs]
        self.assertIn("file_details_hex", names)
        self.assertIn("max_file_size_hex", names)

    def test_resize_action_exposes_the_table_18_objects(self) -> None:
        names = [field.name for field in gui_scp03.FS_RESIZE_SPEC.inputs]
        self.assertIn("filling_pattern_hex", names)
        self.assertIn("repeat_pattern_hex", names)
        self.assertIn("max_file_size_hex", names)


class PrivilegesByteTwoAndThreeTests(unittest.TestCase):
    """GPC v2.3.1 §11.1.2 tables 11-7, 11-8 and 11-9."""

    BYTE_1_NONE = ["n"] * 8

    def _run(self, answers) -> str:
        result, _output = _run_with_answers(
            InteractiveWizards._build_privileges, answers
        )
        return result

    def test_one_byte_is_kept_when_no_extended_privilege_is_set(self) -> None:
        # Table 11-7 alone: Security Domain is byte 1 b8.
        self.assertEqual(self._run(["y"] + ["n"] * 7 + ["n"]), "80")
        # Opening the byte 2 / byte 3 prompts without setting anything must
        # not change the encoding.
        self.assertEqual(
            self._run(["y"] + ["n"] * 7 + ["y"] + ["n"] * 13),
            "80",
        )

    def test_authorized_management_produces_the_three_byte_form(self) -> None:
        # Table 11-8: Authorized Management is byte 2 b7 (privilege 9).
        answers = ["y"] + ["n"] * 7 + ["y"] + ["n", "y"] + ["n"] * 11
        self.assertEqual(self._run(answers), "804000")

    def test_every_table_11_8_and_11_9_flag_maps_to_its_bit(self) -> None:
        expected = {
            "priv08": "008000",
            "priv09": "004000",
            "priv10": "002000",
            "priv11": "001000",
            "priv12": "000800",
            "priv13": "000400",
            "priv14": "000200",
            "priv15": "000100",
            "priv16": "000080",
            "priv17": "000040",
            "priv18": "000020",
            "priv19": "000010",
            "priv20": "000008",
        }
        ids = [step_id for step_id, _n, _b, _m in InteractiveWizards._EXTENDED_PRIVILEGES]
        self.assertEqual(ids, list(expected))
        for index, step_id in enumerate(ids):
            flags = ["n"] * len(ids)
            flags[index] = "y"
            with self.subTest(privilege=step_id):
                self.assertEqual(
                    self._run(self.BYTE_1_NONE + ["y"] + flags),
                    expected[step_id],
                )

    def test_privilege_numbers_follow_the_tables(self) -> None:
        # The "Privilege Number" column: 8..15 in byte 2, 16..20 in byte 3.
        for step_id, _name, byte_index, _mask in InteractiveWizards._EXTENDED_PRIVILEGES:
            number = int(step_id[len("priv"):])
            with self.subTest(privilege=step_id):
                if number <= 15:
                    self.assertEqual(byte_index, 2)
                else:
                    self.assertEqual(byte_index, 3)


class StoreDataUnverifiedTagTests(unittest.TestCase):
    """Tags '86', '8A' and '8C' have no library document behind them."""

    def test_the_three_tags_are_marked_unverified_in_their_prompts(self) -> None:
        prompts: list[str] = []
        # Direct STORE DATA, structured builder, defaults, then cancel at the
        # custom TLV step -- enough to reach every tag prompt.
        answers = iter(["2", "1", "", "", "", "", "", "", "n", "", "", "", "", "CANCEL"])

        def recording_input(prompt: str = "") -> str:
            prompts.append(prompt)
            return next(answers)

        with patch("builtins.input", recording_input):
            with contextlib.redirect_stdout(io.StringIO()):
                InteractiveWizards.run_dgi_personalization(
                    SimpleNamespace(), None, "A0000001510000"
                )

        for tag in ("86", "8A", "8C"):
            matching = [text for text in prompts if f"Tag {tag}" in text]
            self.assertEqual(len(matching), 1, f"tag {tag} prompt not reached")
            self.assertIn("unverified", matching[0], matching[0])

    def test_a_cited_tag_is_not_marked_unverified(self) -> None:
        # GPC v2.3.1 §11.1.7 defines tag '42' for the Issuer Identification
        # Number, so its prompt carries no such marker.
        prompts: list[str] = []
        answers = iter(["2", "1", "", "", "CANCEL"])

        def recording_input(prompt: str = "") -> str:
            prompts.append(prompt)
            return next(answers)

        with patch("builtins.input", recording_input):
            with contextlib.redirect_stdout(io.StringIO()):
                InteractiveWizards.run_dgi_personalization(
                    SimpleNamespace(), None, "A0000001510000"
                )

        tag_42 = [text for text in prompts if "Tag 42" in text]
        self.assertEqual(len(tag_42), 1)
        self.assertNotIn("unverified", tag_42[0])


if __name__ == "__main__":
    unittest.main()


class ResizeToEmptyTests(unittest.TestCase):
    """TS 102 222 v17.1 §6.10.2.1: a new size of '00' empties a transparent EF."""

    def setUp(self) -> None:
        from types import SimpleNamespace

        self.sent: list[str] = []
        outer = self

        class _Transport:
            def __init__(self) -> None:
                self.session = SimpleNamespace(is_authenticated=True)

            def transmit(self, apdu: str, silent: bool = False):
                outer.sent.append(apdu.upper())
                return b"", 0x90, 0x00

        self.transport = _Transport()

    def _dispatch(self, **kwargs):
        from yggdrasim_common.gui_server.actions import scp03 as mod

        with patch.object(
            mod, "_get_scp03_session", lambda _sid: (None, self.transport, "gui-1")
        ):
            return mod._dispatch_fs_resize(None, session_id="gui-1", **kwargs)

    def test_zero_size_needs_the_confirmation(self) -> None:
        with self.assertRaises(ValueError):
            self._dispatch(target_fid="6F07", new_file_size="0000")

        self.assertEqual(self.sent, [])

    def test_confirmed_zero_size_is_sent(self) -> None:
        result = self._dispatch(
            target_fid="6F07",
            new_file_size="0000",
            confirm_empty="EMPTY",
        )

        self.assertEqual(result["tag_80"], "80020000")
        self.assertTrue(result["empties_file"])
        self.assertIn("80D40000", self.sent[-1])

    def test_ordinary_size_is_unaffected_by_the_gate(self) -> None:
        result = self._dispatch(target_fid="6F07", new_file_size="0040")

        self.assertEqual(result["tag_80"], "80020040")
        self.assertFalse(result["empties_file"])


class FileSizeWidthTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.1.4.1 / §11.1.1.4.6.7: the size value is X bytes, X >= 2."""

    def test_small_sizes_keep_the_two_byte_floor(self) -> None:
        from yggdrasim_common.gui_server.actions.scp03 import _file_size_hex

        self.assertEqual(_file_size_hex("40", label="size"), (0x40, "0040"))
        self.assertEqual(_file_size_hex("FFFF", label="size"), (0xFFFF, "FFFF"))

    def test_values_above_two_bytes_widen_the_value_field(self) -> None:
        from yggdrasim_common.gui_server.actions.scp03 import _file_size_hex

        self.assertEqual(_file_size_hex("020000", label="size"), (0x020000, "020000"))
        self.assertEqual(_file_size_hex("01000000", label="size"), (0x01000000, "01000000"))

    def test_a_value_beyond_four_bytes_is_refused(self) -> None:
        from yggdrasim_common.gui_server.actions.scp03 import _file_size_hex

        with self.assertRaises(ValueError):
            _file_size_hex("0100000000", label="size")

    def test_ber_tlv_template_carries_the_wide_sizes(self) -> None:
        from yggdrasim_common.gui_server.actions.scp03 import _build_fcp_template_fields

        built = _build_fcp_template_fields(
            file_type="BER_TLV_EF",
            full_path="3F004F30",
            sec_attr_hex="8B036F060F",
            file_size_hex="020000",
            max_file_size_hex="040000",
        )

        # Tag 80 reserves 128 KiB and tag 86 caps the file at 256 KiB, each
        # with the length its value needs.
        self.assertIn("8003020000", built["fcp_hex"])
        self.assertIn("8603040000", built["fcp_hex"])
