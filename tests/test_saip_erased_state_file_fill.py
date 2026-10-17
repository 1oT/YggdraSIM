# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A gap a SAIP ``fillFileOffset`` skips reads back erased, not zeroed.

TCA "Profile interoperability technical specification" V3.4.1 §8.3.5 makes
``fillFileOffset`` a pointer move that writes nothing, and §8.3.3 gives the
tuple list the effect of creating the file with its fill/repeat pattern and
then updating it. A file created with no pattern is erased: §9.10 states the
default EF-ARR image is "truncated or padded with 'FF...FF'", and the §9.10.3.3
worked example encodes EF-ARR as ``fillPattern 'FF'H`` plus six offset/content
pairs whose gaps are that pattern.

pySim linearizes through an ``io.BytesIO``, which grows with NUL, so those gaps
arrive as '00'. Evidence and the upstream patch are in
``upstream_patches/osmocom-pysim-saip-fill-file-offset-erased-state/``.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_json_codec import ensure_workspace_pysim_on_path
from Tools.ProfilePackage.saip_pysim_compat import (
    SaipErasedStateFillMismatch,
    SaipRecordFillMismatch,
    install_erased_state_file_fill,
    install_record_aware_fill_pattern,
)

_WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _WORKSPACE_ROOT / "Tools/ProfilePackage/profile/reference_test_profile.txt"

# The EF.ARR shape the GUI surfaced: linear fixed, 49 B records, 833 B, no
# resolvable template. One 17 B gap sits between the two written runs.
_ARR_DESCRIPTOR = {
    "fileDescriptor": bytes.fromhex("42210031"),
    "securityAttributesReferenced": bytes.fromhex("01"),
    "efFileSize": bytes.fromhex("0341"),
}
_ARR_HEAD = bytes.fromhex(
    "8001019000800102A40683010A9501088401D4A40683010A95010880017C9700"
)
_ARR_TAIL = bytes.fromhex("80017F9700")

# TCA SAIP §9.10.3.3 -- 6 records x 37 B, every default rule overwritten.
_SPEC_EXAMPLE_RULES = (
    "8001019000800102A406830101950108800158A40683010A950108",
    "800101A40683010195010880015AA40683010A950108",
    "80015BA40683010A950108",
    "800101900080015A9700",
    "800103A406830101950108800158A40683010A950108",
    "800111A40683010195010880014AA40683010A950108",
)
_SPEC_EXAMPLE_TUPLES = (
    ("fillFileContent", _SPEC_EXAMPLE_RULES[0]),
    ("fillFileOffset", 10),
    ("fillFileContent", _SPEC_EXAMPLE_RULES[1]),
    ("fillFileOffset", 15),
    ("fillFileContent", _SPEC_EXAMPLE_RULES[2]),
    ("fillFileOffset", 26),
    ("fillFileContent", _SPEC_EXAMPLE_RULES[3]),
    ("fillFileOffset", 27),
    ("fillFileContent", _SPEC_EXAMPLE_RULES[4]),
    ("fillFileOffset", 15),
    ("fillFileContent", _SPEC_EXAMPLE_RULES[5]),
)


class _DriftingFile:
    """A file whose fill pattern changes between calls.

    Nothing real behaves this way; it is the cheapest way to make upstream's
    output unreproducible so the fail-closed branch is exercised for real
    rather than through a patched helper.
    """

    def __init__(self) -> None:
        self.pe_name = "EF.DRIFT"
        self.fill_pattern = bytes.fromhex("AA")
        self.fill_pattern_repeat = False
        self.template = None
        self.file_size = 4
        self._expansions = 0

    def expand_fill_pattern(self) -> bytes:
        self._expansions += 1
        return bytes([self._expansions]) * 4


class ErasedStateFileFillTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(_WORKSPACE_ROOT)
        install_erased_state_file_fill()

    @staticmethod
    def _build(pename, tuples, descriptor=None, template=None):
        from pySim.esim.saip import File

        entries = [] if descriptor is None else [("fileDescriptor", descriptor)]
        entries.extend(tuples)
        return File(pename, entries, template)

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip import File

        wrapped = File.file_content_from_tuples
        self.assertFalse(install_erased_state_file_fill())
        self.assertIs(File.file_content_from_tuples, wrapped)

    def test_gap_without_template_is_erased_not_zeroed(self) -> None:
        body = self._build(
            "EF.ARR",
            [
                ("fillFileContent", _ARR_HEAD),
                ("fillFileOffset", 17),
                ("fillFileContent", _ARR_TAIL),
            ],
            descriptor=_ARR_DESCRIPTOR,
        ).body

        self.assertEqual(body[: len(_ARR_HEAD)], _ARR_HEAD)
        self.assertEqual(body[len(_ARR_HEAD) : 49], b"\xFF" * 17)
        self.assertEqual(body[49:], _ARR_TAIL)

    def test_gap_with_template_lacking_default_is_erased(self) -> None:
        from pySim.esim.saip.templates import FileTemplate

        template = FileTemplate(0x6F06, "EF.ARR", "LF", 4, 8, 1)
        body = self._build(
            "EF.ARR",
            [("fillFileOffset", 8), ("fillFileContent", bytes.fromhex("8001019000"))],
            template=template,
        ).body

        self.assertEqual(body[:8], b"\xFF" * 8)
        self.assertEqual(body[8:], bytes.fromhex("8001019000"))

    def test_tail_behind_short_literal_default_is_erased(self) -> None:
        # ``expand_default_value_pattern`` returns a non-"..." default unchanged,
        # ignoring its length argument, so a literal shorter than its record
        # leaves a growable tail. (A literal that fills its record is laid into
        # every record instead: RecordAwareTemplateDefaultTests.)
        from pySim.esim.saip.templates import FileTemplate

        template = FileTemplate(0x6F99, "EF.T", "LF", 4, 6, 1, None, "AABBCCDD")
        body = self._build(
            "EF.T",
            [("fillFileOffset", 8), ("fillFileContent", bytes.fromhex("1122"))],
            template=template,
        ).body

        self.assertEqual(body, bytes.fromhex("AABBCCDD") + b"\xFF" * 4 + bytes.fromhex("1122"))

    def test_spec_9_10_3_3_example_yields_ff_padded_records(self) -> None:
        descriptor = {
            "fileDescriptor": bytes.fromhex("42210025"),
            "efFileSize": bytes.fromhex("00DE"),
            "proprietaryEFInfo": {"fillPattern": bytes.fromhex("FF")},
        }
        tuples = [
            (key, bytes.fromhex(value) if key == "fillFileContent" else value)
            for key, value in _SPEC_EXAMPLE_TUPLES
        ]
        body = self._build("EF.ARR", tuples, descriptor=descriptor).body

        expected = b"".join(
            bytes.fromhex(rule).ljust(37, b"\xFF") for rule in _SPEC_EXAMPLE_RULES
        )
        self.assertEqual(body, expected)

    def test_zero_fill_pattern_survives(self) -> None:
        # A '00' fill pattern is content, not absence; the compensation must not
        # convert it, and a gap inside the pattern keeps the pattern byte.
        descriptor = {
            "fileDescriptor": bytes.fromhex("42210008"),
            "efFileSize": bytes.fromhex("0010"),
            "proprietaryEFInfo": {"fillPattern": bytes.fromhex("00")},
        }
        body = self._build(
            "EF.Z",
            [("fillFileOffset", 8), ("fillFileContent", bytes.fromhex("AABB"))],
            descriptor=descriptor,
        ).body

        self.assertEqual(body, bytes.fromhex("0000000000000000AABB000000000000"))

    def test_do_not_create_still_returns_none(self) -> None:
        handle = self._build(
            "EF.X",
            [("doNotCreate", None)],
            descriptor=_ARR_DESCRIPTOR,
        )
        self.assertIsNone(handle.body)

    def test_re_encode_does_not_launder_the_gap_into_content(self) -> None:
        descriptor = {
            "fileDescriptor": bytes.fromhex("42210031"),
            "efFileSize": bytes.fromhex("0062"),
        }
        tuples = [
            ("fillFileContent", bytes.fromhex("8001019000800102A406830101950108")),
            ("fillFileOffset", 33),
            ("fillFileContent", _ARR_TAIL),
        ]
        first = self._build("EF.ARR", tuples, descriptor=descriptor)
        reencoded = list(first.file_content_to_tuples(optimize=True))
        second = self._build("EF.ARR", reencoded, descriptor=descriptor)

        self.assertEqual(first.body, second.body)
        for key, value in reencoded:
            if key == "fillFileContent":
                self.assertNotIn(b"\x00\x00\x00\x00", value)

    def test_unreproducible_upstream_output_fails_closed(self) -> None:
        from pySim.esim.saip import File

        with self.assertRaises(SaipErasedStateFillMismatch):
            File.file_content_from_tuples(
                _DriftingFile(),
                [("fillFileContent", bytes.fromhex("11"))],
            )

    def test_unpatched_upstream_still_zero_fills(self) -> None:
        """Retirement pin -- delete the compensation when this fails.

        A failure here means the pinned pySim fills ``fillFileOffset`` gaps
        correctly, so ``install_erased_state_file_fill`` and its
        ``upstream_patches`` folder have outlived their cause.
        """
        from pySim.esim.saip import File

        unpatched = File.file_content_from_tuples.__wrapped__
        handle = self._build("EF.ARR", [], descriptor=_ARR_DESCRIPTOR)
        body = unpatched(
            handle,
            [
                ("fillFileContent", _ARR_HEAD),
                ("fillFileOffset", 17),
                ("fillFileContent", _ARR_TAIL),
            ],
        )

        self.assertEqual(body[len(_ARR_HEAD) : 49], b"\x00" * 17)


@unittest.skipUnless(
    _REFERENCE_PROFILE.exists(),
    "reference profile sample missing -- skipping end-to-end test",
)
class ErasedStateReferenceProfileTests(unittest.TestCase):
    """Every EF.ARR record slot in the shipped profile reads back erased."""

    @classmethod
    def setUpClass(cls) -> None:
        from Tools.ProfilePackage.saip_tool import SaipToolBridge

        ensure_workspace_pysim_on_path(_WORKSPACE_ROOT)
        install_erased_state_file_fill()

        from pySim.esim.saip import ProfileElementSequence

        prepared = SaipToolBridge(_WORKSPACE_ROOT)._prepare_input_for_tool(_REFERENCE_PROFILE)
        payload = (
            bytes(prepared)
            if isinstance(prepared, (bytes, bytearray))
            else Path(prepared).read_bytes()
        )
        cls.pes = ProfileElementSequence.from_der(payload)

    def test_no_arr_body_carries_a_nul_run(self) -> None:
        seen = 0
        for pe in self.pes.pe_list:
            for name, handle in (getattr(pe, "files", None) or {}).items():
                if not name.lower().endswith("arr") or handle.body is None:
                    continue
                seen += 1
                self.assertNotIn(
                    b"\x00\x00\x00\x00",
                    bytes(handle.body),
                    f"{pe.type}/{name} still carries NUL padding",
                )
        self.assertGreater(seen, 0, "reference profile exposes no EF.ARR")


if __name__ == "__main__":
    unittest.main()


class RecordAwareFillPatternTests(unittest.TestCase):
    """A record oriented EF applies its fill pattern once per record.

    ETSI TS 102 222 §6.3.2.2 tag 'C1' initialises "the first W-1 bytes of each
    record of a record oriented EF"; tag 'C2' repeats its pattern within each
    record and truncates at the record boundary. pySim hands ``file_size`` to
    ``ts_102_222.expand_pattern``, which knows nothing about records, so an
    EF.EXT2 declaring ``fillPattern '00FF'H`` gets one '00' for the whole file
    instead of one per record.
    """

    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(_WORKSPACE_ROOT)
        install_record_aware_fill_pattern()

    @staticmethod
    def _file(file_type, *, rec_len=None, nb_rec=None, file_size=None,
              pattern="00FF", repeat=False):
        from pySim.esim.saip import File

        handle = File("ef-probe", None)
        handle.file_type = file_type
        handle.rec_len = rec_len
        handle.nb_rec = nb_rec
        if file_size is not None:
            handle._file_size = file_size
        handle.fill_pattern = bytes.fromhex(pattern)
        handle.fill_pattern_repeat = repeat
        return handle

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip import File

        wrapped = File.expand_fill_pattern
        self.assertFalse(install_record_aware_fill_pattern())
        self.assertIs(File.expand_fill_pattern, wrapped)

    def test_fill_pattern_opens_each_record(self) -> None:
        handle = self._file("LF", rec_len=13, nb_rec=3)
        self.assertEqual(
            handle.expand_fill_pattern(),
            (b"\x00" + b"\xFF" * 12) * 3,
        )

    def test_cyclic_files_follow_the_same_rule(self) -> None:
        handle = self._file("CY", rec_len=4, nb_rec=2, pattern="07FF")
        self.assertEqual(handle.expand_fill_pattern(), bytes.fromhex("07FFFFFF") * 2)

    def test_repeat_pattern_truncates_at_the_record_boundary(self) -> None:
        # Tag 'C2' repeats within a record and truncates there, so a 3 B
        # pattern in a 4 B record gives 'AABBCC' + the first byte again.
        handle = self._file("CY", rec_len=4, nb_rec=2, pattern="AABBCC", repeat=True)
        self.assertEqual(handle.expand_fill_pattern(), bytes.fromhex("AABBCCAA") * 2)

    def test_pattern_longer_than_the_record_is_truncated(self) -> None:
        handle = self._file("LF", rec_len=2, nb_rec=2, pattern="0011223344")
        self.assertEqual(handle.expand_fill_pattern(), bytes.fromhex("00110011"))

    def test_transparent_files_keep_the_whole_file_expansion(self) -> None:
        handle = self._file("TR", file_size=6)
        self.assertEqual(handle.expand_fill_pattern(), bytes.fromhex("00FFFFFFFFFF"))

    def test_a_single_record_matches_upstream_exactly(self) -> None:
        from pySim.esim.saip import File

        handle = self._file("LF", rec_len=6, nb_rec=1)
        self.assertEqual(
            handle.expand_fill_pattern(),
            File.expand_fill_pattern.__wrapped__(handle),
        )

    def test_ber_tlv_file_keeps_the_whole_file_expansion(self) -> None:
        handle = self._file("BT", file_size=5)
        self.assertEqual(handle.expand_fill_pattern(), bytes.fromhex("00FFFFFFFF"))

    def test_a_record_file_without_geometry_still_raises_upstream(self) -> None:
        from pySim.esim.saip import File

        # The wrapper calls upstream first, so pySim's own ``file_size``
        # ``None * None`` is not papered over. That crash is why the encoder
        # refuses to declare a pattern before the record geometry is decided.
        handle = self._file("LF", rec_len=None, nb_rec=None, file_size=4)
        with self.assertRaises(TypeError) as raised:
            handle.expand_fill_pattern()
        # Pin the origin: pySim's ``File.file_size`` multiplying two Nones,
        # not some later TypeError the wrapper might introduce.
        self.assertIn("NoneType", str(raised.exception))
        with self.assertRaises(TypeError):
            File.expand_fill_pattern.__wrapped__(handle)

    def test_expansion_that_cannot_be_reconciled_fails_closed(self) -> None:
        # One record makes the per-record and whole-file readings the same
        # expansion. This file claims one 4 B record but a 6 B size, so the
        # two disagree and the wrapper must refuse rather than pick one.
        from pySim.esim.saip import File

        class _Inconsistent:
            file_type = "LF"
            rec_len = 4
            nb_rec = 1
            file_size = 6
            pe_name = "ef-inconsistent"
            fill_pattern = b"\x00\xFF"
            fill_pattern_repeat = False

        with self.assertRaises(SaipRecordFillMismatch):
            File.expand_fill_pattern(_Inconsistent())

    def test_unpatched_upstream_still_ignores_records(self) -> None:
        """Retirement pin -- delete the compensation when this fails."""
        from pySim.esim.saip import File

        handle = self._file("LF", rec_len=13, nb_rec=3)
        self.assertEqual(
            File.expand_fill_pattern.__wrapped__(handle),
            b"\x00" + b"\xFF" * 38,
        )
