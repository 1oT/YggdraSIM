# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression coverage for ``ProfileElementGFM`` integration.

The simulator now routes ``genericFileManagement`` PEs through
pySim's typed walker (``pysim_gfm_walk``). These tests pin:

  * The walker emits one ``GfmEntry`` per file, in document order.
  * DF / ADF / EF distinctions follow ``File.from_fileDescriptor``.
  * Body bytes match the result of ``File.file_content_from_tuples``
    so ``fillFileOffset`` + ``fillFileContent`` interleavings stay
    correct (TS 102 222 §6.3.2.2.2 / TCA Profile Interoperability
    §3.5.4 erased-flash semantics).
  * The PRIVATE 7 ``linkPath`` extension is preserved.
  * The ``_consume_generic_file_management`` materialiser produces
    the same node tree shape as the legacy walker.
"""

from __future__ import annotations

import unittest

from SIMCARD.saip_profile import _consume_generic_file_management
from SIMCARD.saip_pysim_specs import GfmEntry, pysim_gfm_walk
from SIMCARD.state import SimProfileImage


def _df_descriptor(fid: int, df_name: bytes = b"") -> dict:
    """Build a SAIP ``createFCP`` value for a DF/ADF entry."""
    descriptor: dict = {
        # 0x78 = working DF (0b0111_1000): fdb file_type=df, structure=no_info_given.
        # asn1tools represents the FDB construct as raw bytes.
        "fileDescriptor": b"\x78\x21",
        "fileID": fid.to_bytes(2, "big"),
        "lcsi": b"\x05",
        "pinStatusTemplateDO": b"\x90\x01\x40",
    }
    if df_name:
        descriptor["dfName"] = df_name
    return descriptor


def _ef_transparent_descriptor(fid: int, size: int) -> dict:
    """SAIP ``createFCP`` for a transparent EF of ``size`` bytes."""
    return {
        "fileDescriptor": b"\x41\x21",
        "fileID": fid.to_bytes(2, "big"),
        "efFileSize": size.to_bytes(2, "big") if size > 0xFF else bytes([size]),
        "lcsi": b"\x05",
    }


def _ef_linear_fixed_descriptor(fid: int, rec_len: int, nb_rec: int) -> dict:
    """SAIP ``createFCP`` for a linear-fixed EF.

    File descriptor byte 0x42 = working EF + linear-fixed; the trailing
    bytes carry record length per TS 102 221 §11.1.1.4.3.
    """
    return {
        "fileDescriptor": bytes([0x42, 0x21, 0x00, rec_len & 0xFF]),
        "fileID": fid.to_bytes(2, "big"),
        "efFileSize": (nb_rec * rec_len).to_bytes(2, "big"),
        "lcsi": b"\x05",
    }


class GfmWalkBasicTests(unittest.TestCase):
    """Pin the ``pysim_gfm_walk`` projection contract."""

    def test_single_transparent_ef_round_trips_body_bytes(self) -> None:
        decoded = {
            "gfm-header": {"identification": 1, "mandated": None},
            "fileManagementCMD": [
                [
                    ("filePath", b"\x7f\x20"),
                    ("createFCP", _ef_transparent_descriptor(0x6F07, 9)),
                    ("fillFileContent", b"\x08\x29\x43\x60\x09\x32\x76\x54\xf3"),
                ],
            ],
        }

        entries = pysim_gfm_walk(decoded)

        self.assertEqual(len(entries), 1)
        ef = entries[0]
        self.assertEqual(ef.fid, 0x6F07)
        self.assertEqual(ef.path_fids, (0x3F00, 0x7F20, 0x6F07))
        self.assertEqual(ef.file_type, "TR")
        self.assertEqual(ef.body, b"\x08\x29\x43\x60\x09\x32\x76\x54\xf3")
        self.assertEqual(ef.lcsi, 0x05)

    def test_fill_file_offset_padded_with_zeroes_then_content(self) -> None:
        # SAIP §5.1: fillFileOffset advances the cursor; gaps before
        # the first fillFileContent are left as the BytesIO default
        # (0x00). The simulator's runtime padding kicks in afterwards.
        decoded = {
            "gfm-header": {"identification": 1, "mandated": None},
            "fileManagementCMD": [
                [
                    ("filePath", b""),
                    ("createFCP", _ef_transparent_descriptor(0x2FE2, 10)),
                    ("fillFileOffset", 4),
                    ("fillFileContent", b"\xab\xcd\xef"),
                ],
            ],
        }

        entries = pysim_gfm_walk(decoded)

        self.assertEqual(len(entries), 1)
        # pySim's BytesIO seeks past 4 bytes (zero-pad) before writing.
        self.assertEqual(entries[0].body, b"\x00\x00\x00\x00\xab\xcd\xef")
        self.assertEqual(entries[0].fid, 0x2FE2)

    def test_df_then_ef_yields_two_entries_in_order(self) -> None:
        decoded = {
            "gfm-header": {"identification": 1, "mandated": None},
            "fileManagementCMD": [
                [
                    ("filePath", b""),
                    ("createFCP", _df_descriptor(0x7F20)),
                    ("createFCP", _ef_transparent_descriptor(0x6F07, 9)),
                    ("fillFileContent", b"\x08" * 9),
                ],
            ],
        }

        entries = pysim_gfm_walk(decoded)

        self.assertEqual(len(entries), 2)
        df, ef = entries
        self.assertEqual(df.fid, 0x7F20)
        # File.from_fileDescriptor sets file_type="DF" because dfName
        # is absent and fid != 0x3F00.
        self.assertEqual(df.file_type, "DF")
        self.assertEqual(ef.fid, 0x6F07)
        self.assertEqual(ef.file_type, "TR")

    def test_adf_descriptor_carries_df_name(self) -> None:
        # ``File.from_fileDescriptor`` keeps file_type="DF" without an
        # explicit template hint; the simulator's consumer is the
        # layer that flips kind to "adf" when ``df_name`` is non-empty.
        decoded = {
            "gfm-header": {"identification": 1, "mandated": None},
            "fileManagementCMD": [
                [
                    ("filePath", b""),
                    ("createFCP", _df_descriptor(0x7FFF, df_name=bytes.fromhex(
                        "A0000000871002F310FFFF89020000FF"
                    ))),
                ],
            ],
        }

        entries = pysim_gfm_walk(decoded)

        self.assertEqual(len(entries), 1)
        adf = entries[0]
        self.assertEqual(adf.fid, 0x7FFF)
        self.assertEqual(adf.file_type, "DF")
        self.assertTrue(adf.df_name.startswith(b"\xa0\x00\x00\x00\x87\x10\x02"))


class GfmWalkLinkPathTests(unittest.TestCase):
    """The PRIVATE 7 ``linkPath`` extension must survive the walk."""

    def test_explicit_link_path_attached_to_entry(self) -> None:
        descriptor = _ef_transparent_descriptor(0x6F07, 9)
        descriptor["linkPath"] = b"\x7f\x20\x6f\x07"
        decoded = {
            "gfm-header": {"identification": 1, "mandated": None},
            "fileManagementCMD": [
                [
                    ("filePath", b"\x7f\xff"),
                    ("createFCP", descriptor),
                    ("fillFileContent", b"\x00" * 9),
                ],
            ],
        }

        entries = pysim_gfm_walk(decoded)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].link_path, ("7F20", "6F07"))


class GfmWalkResilienceTests(unittest.TestCase):
    """The walker must refuse to crash on edge-case inputs."""

    def test_empty_fileManagementCMD_yields_no_entries(self) -> None:
        self.assertEqual(pysim_gfm_walk({"fileManagementCMD": []}), ())

    def test_missing_fileManagementCMD_yields_no_entries(self) -> None:
        self.assertEqual(pysim_gfm_walk({}), ())

    def test_non_dict_input_yields_no_entries(self) -> None:
        self.assertEqual(pysim_gfm_walk(None), ())  # type: ignore[arg-type]

    def test_filePath_back_to_root_resets_chain(self) -> None:
        decoded = {
            "gfm-header": {"identification": 1, "mandated": None},
            "fileManagementCMD": [
                [
                    ("filePath", b"\x7f\x20"),
                    ("createFCP", _ef_transparent_descriptor(0x6F07, 9)),
                    ("fillFileContent", b"\x00" * 9),
                    ("filePath", b""),
                    ("createFCP", _ef_transparent_descriptor(0x2FE2, 10)),
                    ("fillFileContent", b"\x11" * 10),
                ],
            ],
        }

        entries = pysim_gfm_walk(decoded)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].path_fids[:-1], (0x3F00, 0x7F20))
        # Empty filePath rewinds to MF; second EF anchored under MF.
        self.assertEqual(entries[1].path_fids[:-1], (0x3F00,))


class ConsumerMaterializationTests(unittest.TestCase):
    """End-to-end check that ``_consume_generic_file_management`` builds
    the same node tree shape downstream consumers expect."""

    def test_transparent_ef_under_df_gsm_materialises_with_canonical_path(self) -> None:
        decoded = {
            "gfm-header": {"identification": 1, "mandated": None},
            "fileManagementCMD": [
                [
                    ("filePath", b""),
                    ("createFCP", _df_descriptor(0x7F20)),
                    ("createFCP", _ef_transparent_descriptor(0x6F07, 9)),
                    ("fillFileContent", b"\x08\x29\x43\x60\x09\x32\x76\x54\xf3"),
                ],
            ],
        }
        image = SimProfileImage()

        _consume_generic_file_management(image, decoded)

        kinds = [(node.kind, node.fid, node.path) for node in image.nodes]
        self.assertEqual(
            kinds,
            [
                ("df", "7F20", ("MF", "DF.GSM")),
                ("ef", "6F07", ("MF", "DF.GSM", "EF.IMSI")),
            ],
        )
        ef = image.nodes[1]
        self.assertEqual(ef.structure, "transparent")
        self.assertEqual(ef.data, b"\x08\x29\x43\x60\x09\x32\x76\x54\xf3")

    def test_linear_fixed_ef_splits_body_into_records(self) -> None:
        # 2 records of 4 bytes each.
        decoded = {
            "gfm-header": {"identification": 1, "mandated": None},
            "fileManagementCMD": [
                [
                    ("filePath", b"\x7f\x10"),
                    ("createFCP", _ef_linear_fixed_descriptor(0x6F3A, rec_len=4, nb_rec=2)),
                    ("fillFileContent", b"\x01\x02\x03\x04\x05\x06\x07\x08"),
                ],
            ],
        }
        image = SimProfileImage()

        _consume_generic_file_management(image, decoded)

        # No DF.TELECOM materialised here; the consumer synthesises an
        # anchor on the fly so the EF lands somewhere stable.
        ef_nodes = [n for n in image.nodes if n.kind == "ef"]
        self.assertEqual(len(ef_nodes), 1)
        ef = ef_nodes[0]
        self.assertEqual(ef.fid, "6F3A")
        self.assertEqual(ef.structure, "linear-fixed")
        self.assertEqual(ef.records, [b"\x01\x02\x03\x04", b"\x05\x06\x07\x08"])

    def test_consumer_falls_back_to_local_walker_when_pysim_returns_empty(self) -> None:
        # An empty ``fileManagementCMD`` exits both code paths early
        # without raising; nothing is materialised.
        image = SimProfileImage()
        _consume_generic_file_management(image, {"fileManagementCMD": []})

        self.assertEqual(image.nodes, [])


if __name__ == "__main__":
    unittest.main()
