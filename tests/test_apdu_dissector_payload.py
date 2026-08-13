# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The payload layers: TLV, file-control templates and file contents.

This is the part of a SIM trace the stock dissector does not reach. The
assertions here are the reason the dissector exists, so they are written
against what an engineer is actually trying to find out -- which file was
selected, what the card said its structure was, what the ICCID is, which
ES10 function an eUICC was asked to run.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.apdu_dissector_support import (
    FCP_ADF_USIM,
    TEST_ICCID,
    Exchange,
    decode_fields,
    decode_text,
    require_working_tshark,
    swapped_bcd,
    write_capture,
)


class PayloadTestBase(unittest.TestCase):
    @classmethod
    def build(cls, exchanges: list[Exchange], name: str = "payload.pcap") -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.exchanges = exchanges
        cls.capture = write_capture(Path(cls._directory.name) / name, exchanges)
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()


class BerTlvDecoding(PayloadTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                # ES10c GetProfilesInfo request nested three deep.
                Exchange(
                    bytes.fromhex("80E291000A")
                    + bytes.fromhex("BF2D07A0055A03010203"),
                    bytes.fromhex("9000"),
                ),
                # A two-byte tag at the top level.
                Exchange(
                    bytes.fromhex("80E2910006") + bytes.fromhex("BF220302BF20"),
                    bytes.fromhex("9000"),
                ),
            ]
        )

    def test_nested_structure_is_walked(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==1")
        self.assertIn("ProfileInfoList", text)
        self.assertIn("ICCID", text)

    def test_tags_are_named_from_the_generated_table(self) -> None:
        """BF2D and 5A come from _FALLBACK_TAGS via the codegen."""
        rows = decode_fields(self.capture, ["yapdu.tlv.name"])
        names = "\n".join(row[0] for row in rows if row and row[0])
        self.assertIn("ProfileInfoList", names)

    def test_constructed_and_primitive_are_distinguished(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==1")
        self.assertIn("[Constructed: True]", text)
        self.assertIn("[Constructed: False]", text)

    def test_two_byte_tags_are_read_whole(self) -> None:
        rows = decode_fields(self.capture, ["frame.number", "yapdu.tlv.tag"])
        second = [row for row in rows if row and row[0] == "2"]
        self.assertTrue(second)
        # The field is a uint32, so tshark renders it zero-padded.
        self.assertEqual(int(second[0][1], 16), 0xBF22)

    def test_short_primitive_values_get_an_integer_reading(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==1")
        self.assertIn("Value (integer)", text)


class FileControlParameters(PayloadTestBase):
    """The FCP template is what stock Wireshark calls a malformed packet."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("7FF0"),
                         bytes.fromhex("6112")),
                Exchange(bytes.fromhex("00C0000012"), FCP_ADF_USIM + b"\x90\x00"),
            ],
            "fcp.pcap",
        )

    def test_the_template_is_recognised(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("File Control Parameters (FCP)", text)

    def test_the_file_descriptor_is_broken_out(self) -> None:
        rows = decode_fields(
            self.capture, ["yapdu.fcp.file_type", "yapdu.fcp.structure"]
        )
        values = [row for row in rows if row and row[0]]
        self.assertTrue(values, "the file descriptor should be decoded")
        self.assertEqual(values[0][0], "DF or ADF")

    def test_the_file_identifier_resolves_to_a_path(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.fcp.fid", "yapdu.fcp.path"])
        values = [row for row in rows if row and row[0]]
        self.assertTrue(values)
        self.assertEqual(values[0][0], "0x7ff0")
        self.assertIn("ADF.USIM", values[0][1])

    def test_the_life_cycle_status_is_named(self) -> None:
        """LCSI '05' is activated.

        ISO/IEC 7816-4 Table 13 makes bit 1 the activated flag, so '04'
        and '06' are deactivated while '05' and '07' are not -- and
        '0C' to '0F' are the termination state, not an operational one.
        Reading the ranges the other way round reports a terminated ADF
        as healthy.
        """
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("operational, activated", text)

    def test_a_terminated_file_is_not_reported_as_operational(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.fcp.lcsi_name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["operational, activated"])

    def test_no_malformed_packet_is_reported(self) -> None:
        """The exact regression: tshark 4.2.2 reports this as malformed."""
        text = decode_text(self.capture, display_filter="frame.number==2")
        yapdu_section = "YggdraSIM APDU" + text.split("YggdraSIM APDU")[-1]
        self.assertNotIn("Malformed", yapdu_section)


class ElementaryFileContents(PayloadTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("2FE2"),
                         bytes.fromhex("6113")),
                Exchange(bytes.fromhex("00B000000A"),
                         swapped_bcd(TEST_ICCID) + b"\x90\x00"),
                Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("6F07"),
                         bytes.fromhex("6113")),
                # EF.IMSI: length byte, then swapped BCD with a parity nibble.
                Exchange(bytes.fromhex("00B0000009"),
                         bytes.fromhex("08") + swapped_bcd("9" + "001010000000001")
                         + b"\x90\x00"),
            ],
            "ef.pcap",
        )

    def test_the_iccid_is_decoded_including_its_odd_digit_count(self) -> None:
        """A 19-digit ICCID leaves a trailing padding nibble.

        Tools/EumDiag/dissector.lua divides the digit count by two and
        passes the result to a TvbRange, which is exactly what breaks on
        a real ICCID.
        """
        rows = decode_fields(self.capture, ["yapdu.ef.iccid"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, [TEST_ICCID])
        self.assertEqual(len(TEST_ICCID) % 2, 1)

    def test_the_file_is_named(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("EF.ICCID", text)

    def test_decoding_depends_on_the_earlier_select(self) -> None:
        """Reading the same bytes with no SELECT must not claim an ICCID."""
        with tempfile.TemporaryDirectory() as directory:
            lone = write_capture(
                Path(directory) / "lone.pcap",
                [Exchange(bytes.fromhex("00B000000A"),
                          swapped_bcd(TEST_ICCID) + b"\x90\x00")],
            )
            rows = decode_fields(lone, ["yapdu.ef.iccid"])
            self.assertEqual([row[0] for row in rows if row and row[0]], [])


class CommandBodies(PayloadTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                # SELECT by AID.
                Exchange(
                    bytes.fromhex("00A4040410")
                    + bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
                    bytes.fromhex("6120"),
                ),
                # READ BINARY, SFI form.
                Exchange(bytes.fromhex("00B0902008"),
                         bytes.fromhex("0011223344556677") + b"\x90\x00"),
                # READ RECORD, absolute.
                Exchange(bytes.fromhex("00B2010404"),
                         bytes.fromhex("AABBCCDD") + b"\x90\x00"),
                # VERIFY the global PIN.
                Exchange(bytes.fromhex("0020000108") + bytes.fromhex("31323334FFFFFFFF"),
                         bytes.fromhex("9000")),
                # MANAGE CHANNEL open, card allocates.
                Exchange(bytes.fromhex("0070000001"),
                         bytes.fromhex("02") + b"\x90\x00"),
            ],
            "bodies.pcap",
        )

    def test_select_by_aid_names_the_application(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.select.name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertIn("ISD-R", values)

    def test_select_reports_the_selection_control(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==1")
        self.assertIn("by DF name (AID)", text)

    def test_read_binary_sfi_form_is_decoded(self) -> None:
        rows = decode_fields(
            self.capture, ["frame.number", "yapdu.binary.sfi", "yapdu.binary.offset"]
        )
        row = [entry for entry in rows if entry and entry[0] == "2"][0]
        self.assertEqual(row[1], "16")
        self.assertEqual(row[2], "32")

    def test_read_record_reports_number_and_mode(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==3")
        self.assertIn("Record number: 1", text)
        self.assertIn("absolute or current record", text)

    def test_verify_names_the_key_reference(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==4")
        self.assertIn("global PIN 1", text)

    def test_the_pin_block_is_reported_by_length_only(self) -> None:
        """A capture containing plaintext PINs should not print them."""
        text = decode_text(self.capture, display_filter="frame.number==4")
        self.assertIn("PIN block length: 8", text)
        yapdu_section = "YggdraSIM APDU" + text.split("YggdraSIM APDU")[-1]
        self.assertNotIn("PIN value", yapdu_section)

    def test_manage_channel_reports_the_operation(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==5")
        self.assertIn("open", text)


class StateTracksLogicalChannels(PayloadTestBase):
    """A selection on one channel must not leak into another."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                # Channel 0 selects EF.ICCID.
                Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("2FE2"),
                         bytes.fromhex("6113")),
                # Channel 1 selects EF.IMSI.
                Exchange(bytes.fromhex("01A4000402") + bytes.fromhex("6F07"),
                         bytes.fromhex("6113")),
                # Channel 0 reads: this is EF.ICCID, not EF.IMSI.
                Exchange(bytes.fromhex("00B000000A"),
                         swapped_bcd(TEST_ICCID) + b"\x90\x00"),
            ],
            "channels.pcap",
        )

    def test_the_read_is_attributed_to_its_own_channel(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.ef.iccid"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, [TEST_ICCID])

    def test_the_channel_number_is_reported(self) -> None:
        rows = decode_fields(self.capture, ["frame.number", "yapdu.cla.channel"])
        by_frame = {row[0]: row[1] for row in rows if len(row) > 1}
        self.assertEqual(by_frame["1"], "0")
        self.assertEqual(by_frame["2"], "1")


class FailedSelectDoesNotMoveTheSelection(PayloadTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("2FE2"),
                         bytes.fromhex("6113")),
                # This SELECT fails; the previous selection stands.
                Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("6F07"),
                         bytes.fromhex("6A82")),
                Exchange(bytes.fromhex("00B000000A"),
                         swapped_bcd(TEST_ICCID) + b"\x90\x00"),
            ],
            "failed_select.pcap",
        )

    def test_the_read_still_resolves_to_the_first_file(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.ef.iccid"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(
            values,
            [TEST_ICCID],
            "a 6A82 SELECT must not change what is selected",
        )


class TerminatedFileIsNotReportedAsOperational(PayloadTestBase):
    """The direction of the life-cycle inversion that mattered.

    ISO/IEC 7816-4 Table 13 gives '0C' to '0F' to the termination state.
    Reading that range as "operational, activated" reports a
    permanently dead file or ADF as healthy, which is the one way round
    this defect could cost someone a debugging session.
    """

    @classmethod
    def setUpClass(cls) -> None:
        terminated = bytes.fromhex("6210" "82027821" "83027FF0" "8A010F" "A503C00100")
        cls.build(
            [
                Exchange(bytes.fromhex("00A4040402") + bytes.fromhex("7FF0"),
                         bytes.fromhex("6112")),
                Exchange(bytes.fromhex("00C0000012"), terminated + b"\x90\x00"),
            ],
            "terminated.pcap",
        )

    def test_the_state_is_named_as_termination(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.fcp.lcsi_name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["termination state"])

    def test_it_raises_an_expert_item(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("cannot be reactivated", text)


class PinStatusTemplateKeyReferences(PayloadTestBase):
    """'83' means different things at different depths.

    At FCP level it is a file identifier; inside the 'C6' PIN status
    template (ETSI TS 102 221 clause 11.1.1.4.10) it is a key
    reference. Resolving it without regard to the enclosing tag labelled
    every PIN in the template "File identifier".
    """

    @classmethod
    def setUpClass(cls) -> None:
        # C6: PS_DO, then a global PIN 1 and an application PIN 1.
        template = bytes.fromhex("620F" "83022F00" "C609" "900100" "830101" "830181")
        cls.build(
            [
                Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("2F00"),
                         bytes.fromhex("6111")),
                Exchange(bytes.fromhex("00C0000011"), template + b"\x90\x00"),
            ],
            "pin_status.pcap",
        )

    def test_the_nested_tag_is_a_key_reference(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("Key reference", text)

    def test_the_keys_are_named(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("[Key: global PIN 1]", text)
        self.assertIn("[Key: application PIN 1]", text)

    def test_the_template_is_walked_although_ber_calls_it_primitive(self) -> None:
        """'C6' has bit 6 clear, so a conforming BER walker stops at it.

        ETSI TS 102 221 fills it with TLVs regardless, and stopping
        renders nine bytes of PIN state as one opaque value.
        """
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("PS_DO (PIN status)", text)

    def test_the_top_level_tag_is_still_a_file_identifier(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("File identifier", text)


if __name__ == "__main__":
    unittest.main()
