# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import tempfile
import unittest
from pathlib import Path

from SCP03.core.cap import CapFileParser


def _component(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + len(payload).to_bytes(2, "big") + payload


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

        header_payload = (b"\x00" * 9) + bytes([len(package_aid)]) + package_aid
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

    def test_plan_load_chunks_returns_chunk_metadata(self) -> None:
        package_aid = bytes.fromhex("A000000151")
        header_payload = (b"\x00" * 9) + bytes([len(package_aid)]) + package_aid
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
