# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import tempfile
import unittest
from pathlib import Path

from SCP03.core.cap import CapFileParser, CapFormatError


def _component(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + len(payload).to_bytes(2, "big") + payload


# JCVM 3.1 §6.4 header_component_compact, everything ahead of AID_length:
# magic 'DECAFFED', CAP format minor then major ('02' '02'), flags, and the
# package_info minor and major version.
HEADER_PREFIX = bytes.fromhex("DECAFFED") + b"\x02\x02\x00\x00\x01"


class CapFileParserTests(unittest.TestCase):
    def test_wrap_and_unwrap_load_file_block_round_trip(self) -> None:
        component_blob = b"\x01\x02\x03\x04"

        wrapped = CapFileParser._wrap_load_file_block(component_blob)
        unwrapped, payload_offset, end_offset = CapFileParser._unwrap_load_file_block(wrapped)

        self.assertEqual(unwrapped, component_blob)
        self.assertEqual(payload_offset, 2)
        self.assertEqual(end_offset, len(wrapped))

    def test_parse_ijc_extracts_package_and_applet_aids(self) -> None:
        package_aid = bytes.fromhex("A000000151")
        applet_aid = bytes.fromhex("A00000015101")

        header_payload = HEADER_PREFIX + bytes([len(package_aid)]) + package_aid
        applet_payload = bytes([1, len(applet_aid)]) + applet_aid + b"\x00\x00"
        component_blob = _component(0x01, header_payload) + _component(0x03, applet_payload)
        load_block = CapFileParser._wrap_load_file_block(component_blob)

        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            ijc_path = Path(temp_dir) / "sample.ijc"
            ijc_path.write_bytes(load_block)

            parsed = CapFileParser.parse_with_metadata(str(ijc_path))

        self.assertEqual(parsed.package_aid, package_aid)
        self.assertEqual(parsed.applet_aids, [applet_aid])
        self.assertEqual(parsed.component_blob, component_blob)
        self.assertEqual([item.name for item in parsed.components], ["Header.cap", "Applet.cap"])

    def test_header_without_the_cap_magic_is_rejected(self) -> None:
        # JCVM 3.1 §6.4: "The magic item supplies the magic number
        # identifying the Java Card CAP file format; it has the value
        # 0xDECAFFED." A load file opening with anything else is not a CAP
        # file and must not reach the card.
        package_aid = bytes.fromhex("A000000151")
        payload = (b"\x00" * 9) + bytes([len(package_aid)]) + package_aid

        with self.assertRaisesRegex(CapFormatError, "DECAFFED"):
            CapFileParser._extract_pkg_aid(_component(0x01, payload))

        # A named error, but still a ValueError for the callers that guard
        # the parser with ``except ValueError``.
        self.assertTrue(issubclass(CapFormatError, ValueError))

    def test_magic_is_read_from_the_four_bytes_after_the_component_header(self) -> None:
        # Byte-shifted magic (one byte late) must not pass: §6.4 places it
        # immediately after tag (1) and size (2).
        package_aid = bytes.fromhex("A000000151")
        shifted = b"\x00" + bytes.fromhex("DECAFFED") + b"\x02\x02\x00\x00"
        payload = shifted + bytes([len(package_aid)]) + package_aid

        with self.assertRaises(CapFormatError):
            CapFileParser._extract_pkg_aid(_component(0x01, payload))

        good = HEADER_PREFIX + bytes([len(package_aid)]) + package_aid
        self.assertEqual(
            CapFileParser._extract_pkg_aid(_component(0x01, good)),
            package_aid,
        )

    def test_plan_load_chunks_returns_chunk_metadata(self) -> None:
        package_aid = bytes.fromhex("A000000151")
        header_payload = HEADER_PREFIX + bytes([len(package_aid)]) + package_aid
        component_blob = _component(0x01, header_payload)
        load_block = CapFileParser._wrap_load_file_block(component_blob)
        parsed = CapFileParser._build_parse_result(
            load_block=load_block,
            component_blob=component_blob,
            pkg_aid=package_aid,
            applet_aids=[],
            ordered_names=["Header.cap"],
        )

        chunks = CapFileParser.plan_load_chunks(parsed, max_chunk_size=len(load_block))

        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].component_names, ["Header.cap"])
        self.assertIsNone(chunks[0].split_component)


if __name__ == "__main__":
    unittest.main()
