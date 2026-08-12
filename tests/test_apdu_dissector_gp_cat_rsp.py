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
        rows = decode_fields(self.capture, ["yapdu.gp.variant"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertIn("FOR INSTALL", values[1])
        self.assertIn("FOR MAKE SELECTABLE", values[1])

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
        self.assertIn("bearer", row[0].lower())
        self.assertEqual(row[1], "1400")
        self.assertEqual(row[2], "iot.test.com")
        self.assertIn("TCP", row[3])
        self.assertEqual(row[4], "80")
        self.assertEqual(row[5], "10.0.0.1")

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


class BoundProfilePackage(LayerTestBase):
    """BF36 is the structure the retired EumDiag dissector dumped raw."""

    @classmethod
    def setUpClass(cls) -> None:
        # A miniature BoundProfilePackage: the four sections SGP.22
        # clause 2.5.2 defines, with short placeholder segments.
        inner = b"".join(
            [
                bytes.fromhex("A004") + bytes.fromhex("80020102"),
                bytes.fromhex("A104") + bytes.fromhex("87020304"),
                bytes.fromhex("A204") + bytes.fromhex("88020506"),
                bytes.fromhex("A304") + bytes.fromhex("86020708"),
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

    def test_the_four_sections_are_named(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        for section in (
            "initialiseSecureChannelRequest",
            "firstSequenceOf87",
            "sequenceOf88",
            "sequenceOf86",
        ):
            with self.subTest(section=section):
                self.assertIn(section, text)

    def test_it_is_not_rendered_as_one_blob(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.tlv.name"])
        names = "\n".join(row[0] for row in rows if row and row[0])
        self.assertIn("BOUND_PROFILE_PACKAGE", names)


if __name__ == "__main__":
    unittest.main()
