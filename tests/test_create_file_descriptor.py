# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""CREATE FILE descriptor handling, pinned to ETSI TS 102 221 §11.1.1.4.3.

The file descriptor byte packs a shareable flag, a file type and the EF
structure. Only the structure bits pick the layout, so the same structure
arrives in two forms and both have to be accepted -- build_fcp emits the
shareable one, so the card has to accept the way it describes files
itself.
"""

from __future__ import annotations

import unittest

from SIMCARD.engine import SimulatedSimCardEngine


def _fcp(descriptor_byte: int, fid: str, *, record: bool) -> bytes:
    value = bytes([descriptor_byte, 0x21])
    if record:
        value += bytes([0x00, 0x10, 0x04])          # 16-byte records, 4 of them
    body = (
        bytes([0x82, len(value)]) + value
        + bytes([0x83, 0x02]) + bytes.fromhex(fid)
        + bytes([0x80, 0x02, 0x00, 0x40])
    )
    return bytes([0x62, len(body)]) + body


class CreateFileDescriptor(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = SimulatedSimCardEngine()
        self.engine.transmit(bytes.fromhex("00A4000C023F00"))
        self.fs = next(
            value for value in vars(self.engine).values()
            if hasattr(value, "create_file")
        )

    def _create(self, descriptor_byte: int, fid: str, *, record: bool = False):
        return self.fs.create_file(_fcp(descriptor_byte, fid, record=record))

    def test_shareable_and_non_shareable_describe_the_same_structure(self) -> None:
        next_fid = 0xA0
        for plain, shareable, record, name in (
            (0x01, 0x41, False, "transparent"),
            (0x02, 0x42, True, "linear-fixed"),
            (0x06, 0x46, True, "cyclic"),
        ):
            for descriptor in (plain, shareable):
                fid = f"2F{next_fid:02X}"
                next_fid += 1
                with self.subTest(structure=name, descriptor=f"0x{descriptor:02X}"):
                    _, sw1, sw2 = self._create(descriptor, fid, record=record)
                    self.assertEqual((sw1, sw2), (0x90, 0x00))
                    node = self.fs._find_child_by_fid(
                        self.fs.current_node().node_id, fid
                    )
                    self.assertEqual(node.structure, name)

    def test_record_geometry_is_read_from_the_descriptor(self) -> None:
        """Record length is value[2:4] and the count value[4]; reading them
        a byte late made every record EF unbuildable."""

        _, sw1, sw2 = self._create(0x42, "2FB1", record=True)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        node = self.fs._find_child_by_fid(self.fs.current_node().node_id, "2FB1")
        self.assertEqual(len(node.records), 4)
        self.assertEqual(len(node.records[0]), 0x10)

    def test_a_directory_descriptor_is_refused(self) -> None:
        for descriptor, why in ((0x78, "DF or ADF"), (0x79, "BER-TLV EF")):
            with self.subTest(descriptor=f"0x{descriptor:02X}", why=why):
                _, sw1, sw2 = self._create(descriptor, "2FC1")
                self.assertEqual((sw1, sw2), (0x6A, 0x80))

    def test_the_reserved_high_bit_is_refused(self) -> None:
        _, sw1, sw2 = self._create(0x81, "2FC2")
        self.assertEqual((sw1, sw2), (0x6A, 0x80))


if __name__ == "__main__":
    unittest.main()
