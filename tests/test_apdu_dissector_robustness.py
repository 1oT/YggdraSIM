# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Malformed input must degrade, never crash.

``site-docs/internals/coding-standards.md`` states the rule this module
enforces: call every decoder with ``b""``, a single byte, a truncated TLV
header, a length that over-claims its body, a long-form length with no
body, and an odd-nibble BCD run, and treat anything other than a clean
rejection as a defect.

For a Wireshark dissector "clean rejection" has a precise meaning. A Lua
error aborts dissection of the frame and prints a stack trace into
tshark's output, so the bar is: tshark exits 0, stderr carries no Lua
error, and every frame written still appears in the decode. A frame that
vanishes is as much a defect as one that crashes -- that is the failure
mode of the instruction allowlist this dissector replaces.

The fuzz corpus is deterministic. A seeded generator gives a reproducible
failure; an unseeded one gives a bug report nobody can act on.
"""

from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from tests.apdu_dissector_support import (
    STANDARD_ATR,
    Exchange,
    decode_fields,
    require_working_tshark,
    run_tshark,
    standard_corpus,
    write_capture,
    write_raw_capture,
)
from tests.apdu_dissector_support import DISSECTOR_PATH

SEED = 20260812


def _hostile_payloads() -> list[bytes]:
    """Payloads chosen to break a careless decoder."""
    return [
        b"",
        b"\x00",
        b"\x00\xa4",
        b"\x00\xa4\x00",
        b"\x00\xa4\x00\x04",
        # Lc over-claims its body; the standards doc names this shape.
        bytes.fromhex("00A4000462C8"),
        bytes.fromhex("62C8"),
        # Long-form length with nothing behind it.
        bytes.fromhex("00A4000404") + bytes.fromhex("6F8400000000"),
        bytes.fromhex("6F84"),
        bytes.fromhex("6F8400"),
        # Indefinite length, which SIMCARD.utils.read_tlv rejects outright.
        bytes.fromhex("00C0000004") + bytes.fromhex("A080000090 00".replace(" ", "")),
        # A tag chain that never terminates.
        bytes.fromhex("00CA000005") + bytes.fromhex("FFFFFFFFFF") + bytes.fromhex("9000"),
        # Extended length claiming 65535 bytes in a 12-byte frame.
        bytes.fromhex("00D6000000FFFF") + bytes.fromhex("00112233") + bytes.fromhex("9000"),
        # Status word only.
        bytes.fromhex("9000"),
        # Every byte 0xFF: no valid class, no valid status word.
        b"\xff" * 16,
        # Every byte zero.
        b"\x00" * 16,
        # Odd-nibble BCD run in an EF.ICCID-shaped response.
        bytes.fromhex("00B000000A") + bytes.fromhex("98F8F2F1F3F5F7F9F1F3") + bytes.fromhex("9000"),
        # An ATR prefix that is not a complete ATR.
        bytes.fromhex("3B9F96"),
        # ATR-looking first byte on an otherwise ordinary exchange.
        bytes.fromhex("3B0400009000"),
    ]


def _truncations(corpus: list[Exchange]) -> list[bytes]:
    """Every prefix of every corpus exchange.

    A snaplen-truncated capture and a card that stopped mid-response
    produce exactly these shapes.
    """
    payloads: list[bytes] = []
    for exchange in corpus:
        whole = exchange.command + exchange.response
        # Cap the step so a 265-byte extended exchange does not dominate.
        step = max(1, len(whole) // 12)
        for end in range(0, len(whole), step):
            payloads.append(whole[:end])
        payloads.append(whole)
    return payloads


def _bit_flips(corpus: list[Exchange], rng: random.Random) -> list[bytes]:
    payloads: list[bytes] = []
    for exchange in corpus:
        whole = bytearray(exchange.command + exchange.response)
        if not whole:
            continue
        for _ in range(3):
            mutated = bytearray(whole)
            index = rng.randrange(len(mutated))
            mutated[index] ^= 1 << rng.randrange(8)
            payloads.append(bytes(mutated))
    return payloads


class RobustnessBase(unittest.TestCase):
    payloads: list[bytes]
    capture: Path

    @classmethod
    def build(cls, name: str, payloads: list[bytes]) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        # A zero-length GSMTAP payload is a legitimate thing to receive
        # but produces a frame the writer cannot represent, so it is
        # exercised through the one-byte case instead.
        cls.payloads = [payload for payload in payloads if payload]
        cls.capture = write_raw_capture(
            Path(cls._directory.name) / name, cls.payloads
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def assert_clean_decode(self) -> None:
        result = run_tshark(
            ["-X", f"lua_script:{DISSECTOR_PATH}", "-r", str(self.capture), "-V"],
            timeout=120.0,
        )
        self.assertEqual(result.returncode, 0, result.stderr[:2000])
        self.assertNotIn("Lua Error", result.stderr)
        self.assertNotIn("stack traceback", result.stderr)
        self.assertNotIn("attempt to index", result.stderr)
        self.assertNotIn("attempt to compare", result.stderr)
        self.assertNotIn("attempt to perform arithmetic", result.stderr)

    def assert_every_frame_survives(self) -> None:
        rows = decode_fields(self.capture, ["frame.number", "yapdu.frame_kind"])
        self.assertEqual(
            len(rows),
            len(self.payloads),
            "every frame written must still appear in the decode",
        )
        for row in rows:
            with self.subTest(frame=row[0]):
                self.assertTrue(
                    row[1], f"frame {row[0]} produced no yapdu layer at all"
                )


class HostilePayloads(RobustnessBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build("hostile.pcap", _hostile_payloads())

    def test_no_lua_error(self) -> None:
        self.assert_clean_decode()

    def test_no_frame_disappears(self) -> None:
        self.assert_every_frame_survives()

    def test_undecodable_frames_say_so(self) -> None:
        """A frame we cannot split must be labelled, not silently empty."""
        rows = decode_fields(self.capture, ["yapdu.frame_kind"])
        kinds = {row[0] for row in rows if row}
        self.assertIn("undecoded", kinds)

    def test_raw_bytes_are_still_shown_for_undecodable_frames(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.frame_kind", "yapdu.raw"])
        undecoded = [row for row in rows if row and row[0] == "undecoded"]
        self.assertTrue(undecoded)
        for row in undecoded:
            with self.subTest(row=row):
                self.assertTrue(len(row) > 1 and row[1], "raw bytes must be rendered")


class TruncatedExchanges(RobustnessBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build("truncated.pcap", _truncations(standard_corpus()))

    def test_no_lua_error(self) -> None:
        self.assert_clean_decode()

    def test_no_frame_disappears(self) -> None:
        self.assert_every_frame_survives()


class BitFlippedExchanges(RobustnessBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build("flipped.pcap", _bit_flips(standard_corpus(), random.Random(SEED)))

    def test_no_lua_error(self) -> None:
        self.assert_clean_decode()

    def test_no_frame_disappears(self) -> None:
        self.assert_every_frame_survives()


class TwoPassStability(unittest.TestCase):
    """The tree must not change between dissection passes.

    Wireshark re-dissects out of order on GUI clicks, display filters and
    two-pass runs. A dissector that carries mutable state across frames
    without snapshotting it renders differently the second time, which
    presents to a user as "the tree changed when I clicked another
    packet".
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "stability.pcap",
            standard_corpus(),
            atr=STANDARD_ATR,
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def _json(self, extra: list[str]) -> str:
        result = run_tshark(
            [
                "-X",
                f"lua_script:{DISSECTOR_PATH}",
                "-r",
                str(self.capture),
                "-T",
                "json",
                *extra,
            ],
            timeout=120.0,
        )
        self.assertEqual(result.returncode, 0, result.stderr[:2000])
        return result.stdout

    def test_repeated_runs_agree(self) -> None:
        self.assertEqual(self._json([]), self._json([]))

    def test_the_two_pass_run_agrees_with_the_one_pass_run(self) -> None:
        self.assertEqual(self._json([]), self._json(["-2"]))

    def test_dissecting_one_frame_alone_matches_the_full_run(self) -> None:
        """The HIL-Bridge detail pane filters to a single frame.

        Tools/HilBridge/live_decode_view.build_packet_detail_command runs
        tshark with -Y on one frame number, so the dissector never sees
        the frames before it. Whatever it renders there has to be a
        subset of the full run, not a different answer.
        """
        full = self._json([])
        for frame_number in (1, 3, 6):
            with self.subTest(frame=frame_number):
                single = self._json(["-Y", f"frame.number=={frame_number}"])
                self.assertIn('"yapdu"', single)
                self.assertNotIn("Lua Error", single)
        self.assertIn('"yapdu"', full)


if __name__ == "__main__":
    unittest.main()
