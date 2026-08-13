# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""GlobalPlatform, Card Application Toolkit and RSP decoding.

These are the layers a real eUICC session lives in: opening a secure
channel, installing an applet, fetching a proactive command, and calling
an ES10 function. Nothing below is reachable through the stock
dissector, which renders a STORE DATA to the ISD-R as a bare ``e2``.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.apdu_dissector_support import (
    INITIALIZE_UPDATE_RESPONSE,
    INSTALL_FOR_LOAD,
    PROACTIVE_OPEN_CHANNEL,
    Exchange,
    decode_fields,
    decode_text,
    require_working_tshark,
    write_capture,
)

ISDR_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")


class LayerTestBase(unittest.TestCase):
    @classmethod
    def build(cls, exchanges: list[Exchange], name: str) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(Path(cls._directory.name) / name, exchanges)
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()


class SecureChannelSetup(LayerTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                Exchange(
                    bytes.fromhex("8050000008") + bytes(range(8)) + b"\x00",
                    INITIALIZE_UPDATE_RESPONSE + b"\x90\x00",
                ),
                Exchange(
                    bytes.fromhex("8482330010") + bytes(range(16)),
                    bytes.fromhex("9000"),
                ),
            ],
            "scp.pcap",
        )

    def test_the_secure_channel_protocol_is_identified(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.gp.scp"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["SCP03"])

    def test_the_card_challenge_and_cryptogram_are_broken_out(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==1")
        self.assertIn("Card challenge", text)
        self.assertIn("Card cryptogram", text)
        self.assertIn("Key diversification data", text)

    def test_the_key_version_is_reported(self) -> None:
        """The response carries the version the card actually chose."""
        text = decode_text(self.capture, display_filter="frame.number==1")
        self.assertIn("Key version number: 48", text)

    def test_the_security_level_is_decomposed(self) -> None:
        """P1 0x33 is C-MAC, C-DECRYPTION, R-MAC and R-ENCRYPTION."""
        rows = decode_fields(self.capture, ["yapdu.gp.security_level"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(len(values), 1)
        for expected in ("C-MAC", "C-DECRYPTION", "R-MAC", "R-ENCRYPTION"):
            with self.subTest(part=expected):
                self.assertIn(expected, values[0])

    def test_the_host_challenge_is_shown(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==1")
        self.assertIn("Host challenge", text)


class InstallCommand(LayerTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                Exchange(
                    bytes.fromhex("80E60200")
                    + bytes([len(INSTALL_FOR_LOAD)])
                    + INSTALL_FOR_LOAD,
                    bytes.fromhex("9000"),
                ),
                # FOR INSTALL AND MAKE SELECTABLE: P1 0x0C.
                Exchange(
                    bytes.fromhex("80E60C00")
                    + bytes([len(INSTALL_FOR_LOAD)])
                    + INSTALL_FOR_LOAD,
                    bytes.fromhex("9000"),
                ),
            ],
            "install.pcap",
        )

    def test_the_variant_is_spelled_as_the_specification_does(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.gp.variant"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values[0], "INSTALL FOR LOAD")

    def test_combined_variants_are_named_in_full(self) -> None:
        """The GlobalPlatform spelling, in the specification's bit order.

        GlobalPlatform writes it "INSTALL [for install and make
        selectable]", so the qualifiers are joined under one FOR and
        appear lowest bit first. Walking the P1 bitmap from bit 8 down
        produced "INSTALL FOR MAKE SELECTABLE AND FOR INSTALL", and
        folded bit 8 -- which means more blocks follow, not a variant --
        into the name as though it were one.
        """
        rows = decode_fields(self.capture, ["yapdu.gp.variant"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values[1], "INSTALL FOR INSTALL AND MAKE SELECTABLE")

    def test_positional_fields_are_named(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==1")
        self.assertIn("Load file AID", text)
        self.assertIn("Security Domain AID", text)
        self.assertIn("Load parameters", text)

    def test_the_split_prefers_the_reading_with_a_body(self) -> None:
        """An INSTALL with no data field is not a real command.

        Without the requires-data signal the case 2S reading, where Lc
        is taken as Le and the body as a response, scores higher on a
        coincidental length match.
        """
        rows = decode_fields(
            self.capture, ["yapdu.split.command_len", "yapdu.lc"]
        )
        self.assertEqual(int(rows[0][0]), 5 + len(INSTALL_FOR_LOAD))
        self.assertEqual(int(rows[0][1]), len(INSTALL_FOR_LOAD))


class StoreDataBlocks(LayerTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                Exchange(
                    bytes.fromhex("80E20000") + bytes([4]) + bytes.fromhex("AABBCCDD"),
                    bytes.fromhex("9000"),
                ),
                Exchange(
                    bytes.fromhex("80E28101") + bytes([4]) + bytes.fromhex("EEFF0011"),
                    bytes.fromhex("9000"),
                ),
            ],
            "storedata.pcap",
        )

    def test_block_numbers_are_reported(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.gp.block_number"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["0", "1"])

    def test_the_last_block_flag_is_decoded(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.gp.last_block"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["False", "True"])


class ProactiveCommands(LayerTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [Exchange(bytes.fromhex("8012000000"),
                      PROACTIVE_OPEN_CHANNEL + b"\x90\x00")],
            "cat.pcap",
        )

    def test_the_proactive_wrapper_is_not_read_as_comprehension_tlv(self) -> None:
        """0xD0 is plain BER; only its contents carry the CR bit.

        Parsing the wrapper in comprehension mode strips its high bit
        and renames it from a proactive command to tag 0x50.
        """
        text = decode_text(self.capture)
        self.assertIn("Proactive command (D0)", text)
        self.assertNotIn("Text attribute", text)

    def test_the_command_type_is_named(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.type_name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["OPEN CHANNEL"])

    def test_bip_parameters_are_decoded(self) -> None:
        rows = decode_fields(
            self.capture,
            [
                "yapdu.cat.bearer",
                "yapdu.cat.buffer_size",
                "yapdu.cat.apn",
                "yapdu.cat.transport",
                "yapdu.cat.port",
                "yapdu.cat.address",
            ],
        )
        self.assertTrue(rows)
        row = rows[0]
        # Bearer type '02' is the packet-switched bearer. The table
        # starts at '01'; numbering it from zero shifted every entry, so
        # '03' -- the default packet bearer this repo's own toolkit
        # emits -- came out as "local link technology independent".
        self.assertIn("GPRS", row[0])
        self.assertEqual(row[1], "1400")
        self.assertEqual(row[2], "iot.test.com")
        self.assertIn("TCP", row[3])
        self.assertEqual(row[4], "80")
        # A lone Other address is the data destination; the local
        # address is optional and, when both appear, comes first.
        self.assertEqual(row[5], "data destination address: 10.0.0.1")

    def test_the_info_column_names_the_command(self) -> None:
        rows = decode_fields(self.capture, ["_ws.col.Info"])
        self.assertIn("FETCH", rows[0][0])


class Es10Functions(LayerTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        es10c = bytes.fromhex("BF2D06A0045A020102")
        get_euicc_info = bytes.fromhex("BF2200")
        cls.build(
            [
                Exchange(bytes.fromhex("00A4040410") + ISDR_AID,
                         bytes.fromhex("6120")),
                Exchange(bytes.fromhex("80E29100") + bytes([len(es10c)]) + es10c,
                         bytes.fromhex("9000")),
                Exchange(
                    bytes.fromhex("80E29100")
                    + bytes([len(get_euicc_info)])
                    + get_euicc_info,
                    bytes.fromhex("9000"),
                ),
            ],
            "es10.pcap",
        )

    def test_the_es10_function_is_named(self) -> None:
        rows = decode_fields(self.capture, ["_ws.col.Info"])
        joined = "\n".join(row[0] for row in rows if row)
        self.assertIn("ProfileInfoList", joined)
        self.assertIn("EUICCInfo2", joined)

    def test_the_isdr_selection_is_tracked(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.select.name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["ISD-R"])

    def test_the_payload_is_a_tree_not_a_blob(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("ProfileInfoList", text)
        self.assertIn("ICCID", text)


def _ctlv(tag: str, value: bytes) -> bytes:
    return bytes.fromhex(tag) + bytes([len(value)]) + value


class DeviceIdentitiesGiveTheDirection(LayerTestBase):
    """'81' is the UICC and '82' is the terminal, not the reverse.

    Swapping the pair reverses the reported direction of every proactive
    command and every terminal response in the capture, which is the
    single fact an operator uses to tell "the card asked for this" from
    "the terminal reported this".
    """

    @classmethod
    def setUpClass(cls) -> None:
        body = _ctlv("81", bytes.fromhex("012101")) + _ctlv("82", bytes.fromhex("8182"))
        proactive = bytes.fromhex("D0") + bytes([len(body)]) + body
        cls.build(
            [Exchange(bytes.fromhex("8012000000"), proactive + b"\x90\x00")],
            "devices.pcap",
        )

    def test_the_source_is_the_uicc(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.source"])
        self.assertEqual([row[0] for row in rows if row and row[0]], ["UICC"])

    def test_the_destination_is_the_terminal(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.destination"])
        self.assertEqual([row[0] for row in rows if row and row[0]], ["terminal"])


class BipFailureCauseIsReported(LayerTestBase):
    """General result '3A' names the layer; the second byte names the fault.

    Without it all thirteen causes read as "bearer independent protocol
    error", so "the modem rejected the channel identifier" is
    indistinguishable from "the SM-DP+ is unreachable".
    """

    @classmethod
    def setUpClass(cls) -> None:
        body = b"".join(
            [
                _ctlv("81", bytes.fromhex("014001")),
                _ctlv("82", bytes.fromhex("8281")),
                _ctlv("83", bytes.fromhex("3A03")),
            ]
        )
        cls.build(
            [Exchange(bytes.fromhex("80140000") + bytes([len(body)]) + body,
                      bytes.fromhex("9000"))],
            "bip_failure.pcap",
        )

    def test_the_general_result_is_named(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.result_name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertIn("bearer independent protocol error", values)

    def test_the_additional_information_byte_is_decoded(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.result_cause"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["channel identifier not valid"])

    def test_it_raises_an_expert_item(self) -> None:
        text = decode_text(self.capture)
        self.assertIn("BIP error", text)


class GeneralResultTableIsNotShifted(LayerTestBase):
    """'04' is the icon result, '06' is limited service.

    The block from '04' up is easy to shift by two, and the consequence
    is that a REFRESH which simply could not draw an icon is reported as
    an inactive NAA -- a phantom for an operator to chase.
    """

    @classmethod
    def setUpClass(cls) -> None:
        def response(result: str) -> bytes:
            body = _ctlv("81", bytes.fromhex("012101")) + _ctlv("82", bytes.fromhex("8281")) \
                + _ctlv("83", bytes.fromhex(result))
            return bytes.fromhex("80140000") + bytes([len(body)]) + body

        cls.build(
            [
                Exchange(response("04"), bytes.fromhex("9000")),
                Exchange(response("06"), bytes.fromhex("9000")),
                Exchange(response("08"), bytes.fromhex("9000")),
            ],
            "results.pcap",
        )

    def test_each_result_carries_its_own_meaning(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.result_name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(
            values,
            [
                "command performed, but requested icon could not be displayed",
                "command performed successfully, limited service",
                "REFRESH performed but indicated NAA was not active",
            ],
        )


class EnvelopeIsDissected(LayerTestBase):
    """ENVELOPE bodies are wrapped in BER, like a proactive command.

    Left unwrapped, an Event download renders as one opaque node -- and
    Event download is how the terminal reports that data arrived on a
    BIP channel or that the link went away.
    """

    @classmethod
    def setUpClass(cls) -> None:
        body = b"".join(
            [
                _ctlv("99", bytes.fromhex("09")),          # event: data available
                _ctlv("38", bytes.fromhex("8100")),        # channel 1, established
                _ctlv("37", bytes.fromhex("20")),          # 32 bytes waiting
            ]
        )
        envelope = bytes.fromhex("D6") + bytes([len(body)]) + body
        cls.build(
            [Exchange(bytes.fromhex("80C20000" + format(len(envelope), "02X"))
                      + envelope, bytes.fromhex("9000"))],
            "envelope.pcap",
        )

    def test_the_envelope_is_named(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.envelope"])
        self.assertEqual(
            [row[0] for row in rows if row and row[0]], ["Event download"]
        )

    def test_the_event_is_visible(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.event_name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertTrue(values, "the event list should be decoded")

    def test_the_channel_status_is_broken_out(self) -> None:
        rows = decode_fields(
            self.capture, ["yapdu.cat.channel", "yapdu.cat.channel_established"]
        )
        values = [row for row in rows if row and row[0]]
        self.assertEqual(values[0], ["1", "True"])

    def test_the_waiting_byte_count_is_reported(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.channel_data_length"])
        self.assertEqual([row[0] for row in rows if row and row[0]], ["32"])


class DroppedLinkIsDistinguishableFromAHealthyOne(LayerTestBase):
    """Channel status byte 2 is where a mid-download failure says so."""

    @classmethod
    def setUpClass(cls) -> None:
        body = _ctlv("99", bytes.fromhex("0A")) + _ctlv("38", bytes.fromhex("0105"))
        envelope = bytes.fromhex("D6") + bytes([len(body)]) + body
        cls.build(
            [Exchange(bytes.fromhex("80C20000" + format(len(envelope), "02X"))
                      + envelope, bytes.fromhex("9000"))],
            "dropped.pcap",
        )

    def test_the_link_is_reported_as_not_established(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.channel_established"])
        self.assertEqual([row[0] for row in rows if row and row[0]], ["False"])

    def test_the_further_information_names_the_drop(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.channel_info"])
        self.assertEqual(
            [row[0] for row in rows if row and row[0]], ["link dropped"]
        )

    def test_it_raises_an_expert_item(self) -> None:
        text = decode_text(self.capture)
        self.assertIn("link dropped", text)


class BoundProfilePackage(LayerTestBase):
    """BF36 is the structure the retired EumDiag dissector dumped raw."""

    @classmethod
    def setUpClass(cls) -> None:
        # A miniature BoundProfilePackage, with short placeholder
        # segments. GSMA SGP.22 clause 2.5.2 gives it five members, not
        # four: 'BF23' initialiseSecureChannelRequest, then 'A0'
        # firstSequenceOf87, 'A1' sequenceOf88, 'A2' sequenceOf86 and
        # 'A3' secondSequenceOf87. Starting the implicit tags at the
        # request shifts every name by one and loses the fifth, so a
        # profile that fails installing the second run of '87' segments
        # is reported as failing in the first.
        inner = b"".join(
            [
                bytes.fromhex("BF2304") + bytes.fromhex("80020102"),
                bytes.fromhex("A004") + bytes.fromhex("87020304"),
                bytes.fromhex("A104") + bytes.fromhex("88020506"),
                bytes.fromhex("A204") + bytes.fromhex("86020708"),
                bytes.fromhex("A304") + bytes.fromhex("87020910"),
            ]
        )
        bpp = bytes.fromhex("BF36") + bytes([len(inner)]) + inner
        cls.build(
            [
                Exchange(bytes.fromhex("00A4040410") + ISDR_AID,
                         bytes.fromhex("6120")),
                Exchange(bytes.fromhex("80E29100") + bytes([len(bpp)]) + bpp,
                         bytes.fromhex("9000")),
            ],
            "bpp.pcap",
        )

    def test_the_package_is_named(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("BOUND_PROFILE_PACKAGE", text)

    def test_the_five_sections_are_named(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        for section in (
            "initialiseSecureChannelRequest",
            "firstSequenceOf87",
            "sequenceOf88",
            "sequenceOf86",
            "secondSequenceOf87",
        ):
            with self.subTest(section=section):
                self.assertIn(section, text)

    def test_the_section_names_only_apply_inside_a_BF36(self) -> None:
        """'A0' to 'A3' are ordinary constructed context tags.

        They carry the BoundProfilePackage names only as direct children
        of a 'BF36'. Naming them wherever they appear labels the 'A0' of
        an unrelated structure "firstSequenceOf87".
        """
        rows = decode_fields(self.capture, ["frame.number", "yapdu.tlv.name"])
        first_frame = [row[1] for row in rows if row and row[0] == "1"]
        self.assertNotIn("firstSequenceOf87", "\n".join(first_frame))

    def test_it_is_not_rendered_as_one_blob(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.tlv.name"])
        names = "\n".join(row[0] for row in rows if row and row[0])
        self.assertIn("BOUND_PROFILE_PACKAGE", names)


if __name__ == "__main__":
    unittest.main()
