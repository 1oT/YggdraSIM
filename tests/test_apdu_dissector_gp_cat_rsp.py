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
    DISSECTOR_PATH,
    INITIALIZE_UPDATE_RESPONSE,
    INSTALL_FOR_LOAD,
    PROACTIVE_OPEN_CHANNEL,
    Exchange,
    decode_fields,
    decode_text,
    require_working_tshark,
    run_tshark,
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
        self.assertEqual(row[2], "iot.example.test")
        self.assertIn("TCP", row[3])
        self.assertEqual(row[4], "80")
        # A lone Other address is the data destination; the local
        # address is optional and, when both appear, comes first.
        self.assertEqual(row[5], "data destination address: 192.0.2.1")

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


class GlobalPlatformOnAHighLogicalChannel(LayerTestBase):
    """A GP command on channel 4 or above does not carry class '8X'.

    Channels 0 to 3 put the channel in the low two bits of '8X'. Channels
    4 to 19 use the further interindustry shape instead, so the same
    command arrives as 'CX' unwrapped and 'EX' secure-messaged --
    SCP03/crypto/session.py builds exactly that on the wire. Every table
    here is keyed on the channel-0 spelling, so without folding the
    channel back out the command loses its name, its GlobalPlatform body
    decode and its case hint. The missing hint is the expensive one: it
    feeds the splitter, so the frame is cut in the wrong place too.

    An ISD-P on a populated eUICC is opened on exactly these channels.
    """

    @classmethod
    def setUpClass(cls) -> None:
        es10c = bytes.fromhex("BF2D07A0055A03010203")
        cls.build(
            [
                # 'C0': channel 4, no secure messaging.
                Exchange(
                    bytes.fromhex("C0E29100") + bytes([len(es10c)]) + es10c,
                    bytes.fromhex("9000"),
                    "store-data-channel-4",
                ),
                # 'E0': channel 4, secure-messaged.
                Exchange(
                    bytes.fromhex("E0E29100") + bytes([0x18]) + bytes(range(0x18)),
                    bytes.fromhex("9000"),
                    "store-data-channel-4-wrapped",
                ),
            ],
            "gp-high-channel.pcap",
        )

    def test_the_command_is_still_named(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.command_name"])
        self.assertEqual(
            [row[0] for row in rows if row and row[0]],
            ["STORE_DATA", "STORE_DATA"],
        )

    def test_the_logical_channel_is_reported(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cla.channel"])
        self.assertEqual([row[0] for row in rows if row and row[0]], ["4", "4"])

    def test_the_globalplatform_body_is_decoded(self) -> None:
        """Without is_gp_class accepting 'CX'/'EX' there is no variant."""
        rows = decode_fields(self.capture, ["yapdu.gp.variant"])
        self.assertEqual(len([row[0] for row in rows if row and row[0]]), 2)

    def test_the_case_hint_still_splits_the_frame(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.case", "yapdu.lc"])
        values = [row for row in rows if row and row[0]]
        self.assertEqual([row[0] for row in values], ["3S", "3S"])
        self.assertEqual([row[1] for row in values], ["10", "24"])

    def test_the_wrapped_command_reports_secure_messaging(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cla.secure_messaging"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values[1], "3")

    def test_the_es10c_function_is_named_through_the_wrapper(self) -> None:
        text = decode_text(self.capture, display_filter="yapdu.cla.channel == 4")
        self.assertIn("ProfileInfoList", text)


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


class QualifiersAreReadPerCommand(LayerTestBase):
    """A qualifier means something different for every command type.

    Three readings here are ones a plausible implementation gets
    backwards, and each is asserted against the clause that fixes it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        def proactive(command_type: int, qualifier: int) -> Exchange:
            body = (
                _ctlv("81", bytes([0x01, command_type, qualifier]))
                + _ctlv("82", bytes.fromhex("8102"))
            )
            envelope = bytes.fromhex("D0") + bytes([len(body)]) + body
            return Exchange(
                bytes.fromhex("8012000000"), envelope + bytes.fromhex("9000")
            )

        cls.build(
            [
                # GET INPUT with bit 3 set: TS 102 223 clause 8.6 makes
                # that "shall not be revealed", not "shall echo".
                proactive(0x23, 0x04),
                # SELECT ITEM qualifier '01': presentation type specified,
                # data values. SET UP MENU's map would call bit 1 a soft
                # key preference.
                proactive(0x24, 0x01),
                # LAUNCH BROWSER '04' is explicitly "not used"; a two-bit
                # mask folded it onto '00'.
                proactive(0x15, 0x04),
            ],
            "qualifiers.pcap",
        )

    def test_get_input_bit_3_hides_the_input(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.qualifier_name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertIn("not be revealed", values[0])
        self.assertNotIn("echo", values[0])

    def test_select_item_does_not_borrow_the_menu_bit_map(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.qualifier_name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertIn("choice of data values", values[1])
        self.assertNotIn("soft key", values[1])

    def test_launch_browser_is_an_enumeration_not_a_bit_field(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.qualifier_name"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertNotIn("launch if not already launched", values[2])


class EnvelopeTagsFollowTheStandardNumbering(LayerTestBase):
    """The BER-TLV envelope tags are not a gapless run from 'D1'.

    'D8' is reserved for intra-UICC communication, so 3GPP TS 31.111
    clause 9.1 puts USSD download at 'D9', Geographical Location
    Reporting at 'DD' and ProSe Report at 'DF'. Numbering the table
    straight through the gap shifts every tag from 'D9' up by one and
    drops 'DF' off the end entirely -- so a USSD download reports as an
    MMS transfer status, and a ProSe report is not recognised as an
    ENVELOPE at all.
    """

    #: Tag to the name TS 31.111 clause 9.1 and TS 101 220 clause 7.2
    #: give it. The three 3GPP-assigned ones are the citable anchors.
    EXPECTED = {
        0xD1: "SMS-PP download",
        0xD6: "Event download",
        0xD9: "USSD download",
        0xDA: "MMS transfer status",
        0xDD: "Geographical location reporting",
        0xDE: "Envelope container",
        0xDF: "ProSe report",
    }

    @classmethod
    def setUpClass(cls) -> None:
        body = _ctlv("82", bytes.fromhex("8281"))
        exchanges = []
        for tag in sorted(cls.EXPECTED):
            envelope = bytes([tag]) + bytes([len(body)]) + body
            exchanges.append(
                Exchange(
                    bytes.fromhex("80C20000" + format(len(envelope), "02X"))
                    + envelope,
                    bytes.fromhex("9000"),
                )
            )
        cls.build(exchanges, "envelope-tags.pcap")

    def test_each_envelope_tag_carries_its_standard_name(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.envelope"])
        seen = [row[0] for row in rows if row and row[0]]
        self.assertEqual(seen, [self.EXPECTED[tag] for tag in sorted(self.EXPECTED)])

    def test_a_prose_report_is_recognised_as_an_envelope(self) -> None:
        """'DF' is the tag a straight run through the 'D8' gap loses."""
        text = decode_text(self.capture, display_filter="yapdu.cat.envelope")
        self.assertIn("ProSe report", text)


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


class ChainedStoreDataSurvivesSnapshotDedup(LayerTestBase):
    """A chained STORE DATA links its blocks even when snapshots are shared.

    The state machine stores one snapshot table for a run of frames whose
    context is identical, which a chain of STORE DATA blocks to the same
    ISD-R is. Reassembly then backpatches each contributing frame with the
    frame that completes the chain -- a mutation of the stored table. If a
    block frame's table were shared with a neighbour, that backpatch would
    bleed a 'Reassembled in' link onto a frame that is not part of the
    chain. Block frames are therefore excluded from sharing; this pins it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        def block(p1: int, p2: int, body: bytes) -> Exchange:
            command = bytes([0x80, 0xE2, p1, p2, len(body)]) + body
            return Exchange(command, bytes.fromhex("9000"))

        cls.build(
            [
                # Select the ISD-R, then three STORE DATA blocks on the
                # same selection: two "more blocks" then the last. P1 bit
                # 8 set marks the final block.
                Exchange(bytes.fromhex("00A4040410") + ISDR_AID,
                         bytes.fromhex("6120")),
                block(0x00, 0x00, bytes.fromhex("BF360A")),
                block(0x00, 0x01, bytes.fromhex("A004870203")),
                block(0x80, 0x02, bytes.fromhex("04A2028601")),
            ],
            "chained-store-data.pcap",
        )

    def _reassembled_in(self) -> dict[str, str]:
        # Two-pass, because the backpatch only shows on a frame's second
        # visit -- the same reason it shows in the GUI, which re-renders,
        # and the pre-existing behaviour of Wireshark's own reassembly.
        result = run_tshark(
            [
                "-X", f"lua_script:{DISSECTOR_PATH}",
                "-r", str(self.capture),
                "-2",
                "-T", "fields",
                "-e", "frame.number", "-e", "yapdu.rsp.reassembled_in",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr[:800])
        links = {}
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) > 1 and parts[1]:
                links[parts[0]] = parts[1]
        return links

    def test_each_earlier_block_points_at_the_completing_frame(self) -> None:
        # Frames 2 and 3 are mid-chain blocks; frame 4 completes it.
        links = self._reassembled_in()
        self.assertEqual(links.get("2"), "4")
        self.assertEqual(links.get("3"), "4")

    def test_the_select_frame_is_not_dragged_into_the_chain(self) -> None:
        """The load-bearing dedup-safety check. Frame 1 selects the ISD-R
        and so shares the blocks' context, but is not part of the chain.
        Had it shared a snapshot table with block frame 2, the backpatch
        would have bled a 'Reassembled in' link onto it. It does not."""
        self.assertNotIn("1", self._reassembled_in())

    def test_the_completing_frame_counts_every_block(self) -> None:
        rows = decode_fields(
            self.capture, ["frame.number", "yapdu.rsp.block_count"]
        )
        counts = {row[0]: row[1] for row in rows if len(row) > 1 and row[1]}
        self.assertEqual(counts.get("4"), "3")


if __name__ == "__main__":
    unittest.main()
