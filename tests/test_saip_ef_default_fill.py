# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.

"""An unwritten EF byte reads back as its pre-personalization value, not as FF.

A ``fillFileOffset`` gap keeps whatever the file was created with, and
TS 102 222 leaves that undefined when the Fcp declares no pattern. 3GPP
TS 31.102 Annex E and TS 51.011 Annex D name the value per file, and it is not
uniformly erased: EF.SMS and the extension records open with a ``00`` byte, the
ciphering/integrity key files with ``07``, the VGCS/VBS ciphering-algorithm
files all-zero.

Three things are pinned here. The table maps **file names**, never bare file
identifiers -- ``6Fxx`` is allocated per DF, so ``6F4B`` is EF.EXT2 under
DF.TELECOM and EF.ICON under DF.GRAPHICS, and an identifier-keyed table would
hand EF.ICON the extension records' ``00FF``. A file that already carries a
template default is never patterned, because TCA SAIP 8.3.3 makes an Fcp
pattern replace that default outright. And a declared pattern survives the DER
round trip and expands per record, as ETSI TS 102 222 6.3.2.2 requires.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_ef_default_fill import (
    _EXACT_SIZE_PATTERN_BY_NAME,
    _FILL_PATTERN_BY_NAME,
    default_fill_pattern,
)
from Tools.ProfilePackage.saip_json_codec import (
    build_decoded_document_from_sequence,
    encode_der_from_document,
    ensure_workspace_pysim_on_path,
)

_WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
_SPEC_CORPUS = _WORKSPACE_ROOT / "docs/tel-docs/converted"


class DefaultFillPatternTableTests(unittest.TestCase):
    def test_every_pattern_is_whole_hex_bytes(self) -> None:
        rows = [(name, fid, pattern) for name, (fid, pattern) in _FILL_PATTERN_BY_NAME.items()]
        rows += [
            (name, fid, pattern)
            for name, (fid, pattern, _size) in _EXACT_SIZE_PATTERN_BY_NAME.items()
        ]
        for name, fid, pattern in rows:
            with self.subTest(name=name):
                self.assertRegex(pattern, r"^(?:[0-9A-F]{2})+$")
                self.assertRegex(fid, r"^[0-9A-F]{4}$")

    def test_names_are_stored_upper_case_for_lookup(self) -> None:
        for name in list(_FILL_PATTERN_BY_NAME) + list(_EXACT_SIZE_PATTERN_BY_NAME):
            with self.subTest(name=name):
                self.assertEqual(name, name.upper())

    def test_annex_values_that_are_not_erased(self) -> None:
        # The rows that make a blanket 0xFF fill wrong.
        self.assertEqual(default_fill_pattern("EF.SMS"), bytes.fromhex("00FF"))
        self.assertEqual(default_fill_pattern("EF.EXT2"), bytes.fromhex("00FF"))
        self.assertEqual(default_fill_pattern("EF.MMSN"), bytes.fromhex("000000FF"))
        self.assertEqual(default_fill_pattern("EF.Keys"), bytes.fromhex("07FF"))
        self.assertEqual(default_fill_pattern("EF.KeysPS"), bytes.fromhex("07FF"))
        self.assertEqual(default_fill_pattern("EF.VGCSCA"), bytes.fromhex("00"))
        self.assertEqual(default_fill_pattern("EF.VBSCA"), bytes.fromhex("00"))

    def test_erased_rows_stay_erased(self) -> None:
        for name in ("EF.PL", "EF.FPLMN", "EF.FDN", "EF.MSISDN", "EF.CBMI"):
            with self.subTest(name=name):
                self.assertEqual(default_fill_pattern(name), b"\xFF")

    def test_operator_dependent_files_get_no_pattern(self) -> None:
        # The annexes decline to specify these, so the encoder must not guess.
        for name in ("EF.ICCID", "EF.IMSI", "EF.ARR", "EF.UST", "EF.SPN", "EF.AD"):
            with self.subTest(name=name):
                self.assertIsNone(default_fill_pattern(name))

    def test_a_shared_identifier_does_not_leak_between_files(self) -> None:
        # 6F4B is EF.EXT2 under DF.TELECOM and EF.ICON under DF.GRAPHICS;
        # 6F02 is EF.IMPI under ADF.ISIM. Neither icon nor IMPI may inherit
        # the pattern the annex gives the file that shares its identifier.
        self.assertEqual(default_fill_pattern("EF.EXT2", file_id="6F4B"), bytes.fromhex("00FF"))
        self.assertIsNone(default_fill_pattern("EF.ICON", file_id="6F4B"))
        self.assertIsNone(default_fill_pattern("EF.ICON", file_id="6F44"))
        self.assertIsNone(default_fill_pattern("EF.IMPI", file_id="6F02"))

    def test_a_name_at_an_unexpected_identifier_is_refused(self) -> None:
        self.assertIsNone(default_fill_pattern("EF.SMS", file_id="6F44"))
        self.assertIsNone(default_fill_pattern("EF.Kc", file_id="6F20", file_size=9))

    def test_expansion_reproduces_the_annex_value(self) -> None:
        # TS 102 222 6.3.2.2 tag 'C1': first W-1 bytes literal, the rest repeat
        # the last byte. The table stores the pattern, not the expansion.
        from pySim import ts_102_222

        cases = {
            "EF.SMS": bytes.fromhex("00FFFFFFFFFF"),
            "EF.Keys": bytes.fromhex("07FFFFFFFFFF"),
            "EF.VGCSCA": bytes.fromhex("000000000000"),
            "EF.FPLMN": bytes.fromhex("FFFFFFFFFFFF"),
            "EF.MMSN": bytes.fromhex("000000FFFFFF"),
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                pattern = default_fill_pattern(name)
                self.assertIsNotNone(pattern)
                self.assertEqual(
                    ts_102_222.expand_pattern(pattern, False, len(expected)),
                    expected,
                )

    def test_suffix_anchored_pattern_needs_its_exact_size(self) -> None:
        # 'FF...FF07' survives tag 'C1' only while the pattern spans the file;
        # at any other length the trailing 07 would repeat.
        self.assertEqual(
            default_fill_pattern("EF.Kc", file_id="4F20", file_size=9),
            bytes.fromhex("FFFFFFFFFFFFFFFF07"),
        )
        self.assertIsNone(default_fill_pattern("EF.Kc", file_id="4F20", file_size=16))
        self.assertIsNone(default_fill_pattern("EF.Kc", file_id="4F20"))

    def test_lookup_is_case_insensitive_and_tolerates_no_name(self) -> None:
        self.assertEqual(default_fill_pattern("ef.sms"), bytes.fromhex("00FF"))
        self.assertIsNone(default_fill_pattern(None))
        self.assertIsNone(default_fill_pattern("   "))


class DefaultFillPatternAgainstTemplatesTests(unittest.TestCase):
    """Cross-check the annex table against the TCA templates pySim carries.

    The two sources are independent -- 3GPP's pre-personalization annexes and
    the TCA SAIP section 9 template tables -- so where a file appears in both
    they must agree. They also show why the table may only be applied to files
    without a template default: for these files the template already supplies
    the content, and SAIP 8.3.3 would have an Fcp pattern replace it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(_WORKSPACE_ROOT)

    @staticmethod
    def _template_files():
        from pySim.esim.saip import templates

        collected: list = []

        def walk(node) -> None:
            collected.append(node)
            for child in getattr(node, "children", ()) or ():
                walk(child)

        for profile in templates.ProfileTemplateRegistry.by_oid.values():
            for root in [profile] + list(getattr(profile, "files", ()) or ()):
                walk(root)
        return collected

    def test_table_agrees_with_every_tca_template_default(self) -> None:
        from pySim import ts_102_222

        compared = 0
        for node in self._template_files():
            fid = getattr(node, "fid", None)
            default_val = getattr(node, "default_val", None)
            if not isinstance(fid, int) or not default_val:
                continue
            pattern = default_fill_pattern(
                getattr(node, "name", None),
                file_id=fid,
                file_size=1,
            )
            if pattern is None:
                continue
            size = getattr(node, "file_size", None)
            if not (isinstance(size, int) and size > 0):
                rec_len = getattr(node, "rec_len", None)
                nb_rec = getattr(node, "nb_rec", None)
                if not (isinstance(rec_len, int) and isinstance(nb_rec, int)):
                    continue
                size = rec_len * nb_rec
            if size <= 0:
                continue
            # TS 102 222 v17.1 6.3.2.2.2 lays a fill pattern into each record
            # and the template default is per record too (SAIP V3.4.1
            # section 9), so a record file is compared record by record.
            unit = size
            if getattr(node, "file_type", None) in ("LF", "CY"):
                rec_len = getattr(node, "rec_len", None)
                if isinstance(rec_len, int) and rec_len > 0 and size % rec_len == 0:
                    unit = rec_len
            compared += 1
            with self.subTest(name=node.name, fid=f"{fid:04X}"):
                self.assertEqual(
                    ts_102_222.expand_pattern(pattern, False, unit) * (size // unit),
                    node.expand_default_value_pattern(size),
                )
        self.assertGreater(compared, 20, "no template default overlapped the table")


class DefaultFillPatternWiringTests(unittest.TestCase):
    """``_explicit_file_descriptor`` declares the pattern only where it may."""

    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(_WORKSPACE_ROOT)

    @staticmethod
    def _fill_pattern(template):
        from Tools.ProfilePackage.saip_pe_quick_add import _explicit_file_descriptor

        descriptor = _explicit_file_descriptor(template, gfm_mode=False)
        return (descriptor.get("proprietaryEFInfo") or {}).get("fillPattern")

    @staticmethod
    def _template(**kwargs):
        from Tools.ProfilePackage.saip_pe_quick_add import _FallbackFileTemplate

        return _FallbackFileTemplate(**kwargs)

    def _ext2_template(self):
        return self._template(
            fid=0x6F4B,
            name="EF.EXT2",
            pe_name="ef-ext2",
            file_type="LF",
            arr=1,
            rec_len=13,
            nb_rec=10,
        )

    def test_templateless_file_declares_its_annex_pattern(self) -> None:
        self.assertEqual(self._fill_pattern(self._ext2_template()), bytes.fromhex("00FF"))

    def test_template_default_is_never_overwritten(self) -> None:
        # SAIP 8.3.3: an Fcp pattern replaces the template default completely,
        # so a file carrying one must be left alone.
        template = self._ext2_template()
        template.default_val = "00FF...FF"
        self.assertIsNone(self._fill_pattern(template))

    def test_explicit_template_pattern_still_wins(self) -> None:
        template = self._ext2_template()
        template.fill_pattern = bytes.fromhex("AA")
        self.assertEqual(self._fill_pattern(template), bytes.fromhex("AA"))

    def test_file_of_undecided_size_declares_nothing(self) -> None:
        # Record geometry not chosen yet: the pattern would describe bytes that
        # do not exist, and pySim expands it eagerly through ``File.file_size``.
        template = self._template(
            fid=0x6F4B, name="EF.EXT2", pe_name="ef-ext2", file_type="LF", arr=1,
        )
        self.assertIsNone(self._fill_pattern(template))

    def test_operator_dependent_file_declares_nothing(self) -> None:
        template = self._template(
            fid=0x6F38, name="EF.UST", pe_name="ef-ust", file_type="TR",
            arr=1, file_size=12,
        )
        self.assertIsNone(self._fill_pattern(template))


class DefaultFillPatternRoundTripTests(unittest.TestCase):
    """A declared pattern must survive DER and expand per record."""

    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(_WORKSPACE_ROOT)

        from pySim.esim.saip import (
            ProfileElementEnd,
            ProfileElementHeader,
            ProfileElementSequence,
        )
        from Tools.ProfilePackage.saip_pe_quick_add import (
            insert_blank_file_for_pename,
            insert_blank_pe_for_menu_id,
        )

        cls._ProfileElementSequence = ProfileElementSequence
        sequence = ProfileElementSequence()
        sequence.append(ProfileElementHeader())
        sequence.append(ProfileElementEnd())
        document = build_decoded_document_from_sequence(sequence, intro_lines=["fill"])
        for menu_id in ("mf", "genericFileManagement"):
            document = insert_blank_pe_for_menu_id(
                document, _WORKSPACE_ROOT, menu_id=menu_id,
            )
        cls.document = insert_blank_file_for_pename(
            document,
            _WORKSPACE_ROOT,
            section_key="genericFileManagement",
            file_pe_name="ef-ext2",
        )

    def _reparsed_ext2(self):
        der = encode_der_from_document(self.document, _WORKSPACE_ROOT)
        for pe in self._ProfileElementSequence.from_der(der).pe_list:
            for handle in (getattr(pe, "files", None) or {}).values():
                if getattr(handle, "fid", None) == 0x6F4B:
                    return handle
        self.fail("EF.EXT2 did not survive the DER round trip")

    def test_pattern_survives_encode_and_reparse(self) -> None:
        handle = self._reparsed_ext2()
        self.assertEqual(handle.fill_pattern, bytes.fromhex("00FF"))
        self.assertFalse(handle.fill_pattern_repeat)

    def test_body_opens_every_record_with_the_record_type_byte(self) -> None:
        # TS 102 222 6.3.2.2 tag 'C1' initialises "the first W-1 bytes of each
        # record of a record oriented EF" -- not the first W-1 bytes of the
        # file. A '00' only at offset 0 would leave records 2..n claiming a
        # record type of 0xFF.
        handle = self._reparsed_ext2()
        record_length = handle.rec_len
        body = bytes(handle.body or b"")
        self.assertGreater(record_length, 1)
        self.assertEqual(len(body) % record_length, 0)
        self.assertGreater(len(body) // record_length, 1)
        for index in range(0, len(body), record_length):
            record = body[index : index + record_length]
            with self.subTest(record=index // record_length + 1):
                self.assertEqual(record, b"\x00" + b"\xFF" * (record_length - 1))


@unittest.skipUnless(
    _SPEC_CORPUS.is_dir(),
    "converted specification corpus absent -- docs/tel-docs is not tracked",
)
class DefaultFillPatternDriftTests(unittest.TestCase):
    """Every row must still match the annex it was taken from.

    ``docs/tel-docs/`` is untracked, so this runs only where the corpus is
    present; elsewhere the rows are review-only and each carries its file name
    in a comment. The annexes key by file identifier, so this checks the
    pattern recorded for each row's identifier, not the name mapping, which is
    the deliberate curation step.
    """

    # The converted pages wrap the identifier in typographic quotes.
    _ROW = re.compile(
        "^\\s*[\u2018'`]([0-9A-F]{4})[\u2019'`]\\s+(.*?)\\s{2,}(\\S.*?)\\s*$"
    )

    @classmethod
    def _harvest(cls) -> dict[str, set[str | None]]:
        sources = (
            (_SPEC_CORPUS / "ts_131102v180400p" / "pages", range(363, 373)),
            (_SPEC_CORPUS / "ts_151011v041500p" / "pages", range(134, 143)),
        )
        harvested: dict[str, set[str | None]] = {}
        for root, pages in sources:
            for number in pages:
                page = root / f"page-{number:03d}.md"
                if not page.exists():
                    continue
                for line in page.read_text().splitlines():
                    matched = cls._ROW.match(line)
                    if matched is not None:
                        harvested.setdefault(matched.group(1), set()).add(
                            cls._as_pattern(matched.group(3))
                        )
        return harvested

    @staticmethod
    def _as_pattern(value: str) -> str | None:
        text = value.replace("\u2026", "...").replace("\u2018", "'").replace("\u2019", "'")
        text = text.strip().strip("'").replace(" ", "").upper()
        if "..." not in text:
            return None
        head, _, tail = text.partition("...")
        if not re.fullmatch(r"(?:[0-9A-F]{2})+", head or ""):
            return None
        if not re.fullmatch(r"(?:[0-9A-F]{2})+", tail or ""):
            return None
        return head if tail == head[-2:] else None

    def test_every_row_matches_its_annex_entry(self) -> None:
        harvested = self._harvest()
        self.assertGreater(len(harvested), 100, "annex pages did not parse")

        for name, (fid, pattern) in sorted(_FILL_PATTERN_BY_NAME.items()):
            with self.subTest(name=name, fid=fid):
                self.assertIn(fid, harvested, "identifier vanished from the annexes")
                self.assertEqual(
                    harvested[fid],
                    {pattern},
                    "annex value changed or became ambiguous",
                )

    def test_kc_rows_still_read_as_erased_with_cksn_seven(self) -> None:
        for name, (fid, pattern, size) in sorted(_EXACT_SIZE_PATTERN_BY_NAME.items()):
            with self.subTest(name=name, fid=fid):
                self.assertEqual(len(bytes.fromhex(pattern)), size)
                pages = (_SPEC_CORPUS / "ts_131102v180400p" / "pages").glob("page-3[67]*.md")
                text = "".join(page.read_text() for page in pages)
                self.assertRegex(
                    text,
                    "[\u2018']" + fid + "[\u2019'].*?'FF[.\u2026]+FF07'",
                )


if __name__ == "__main__":
    unittest.main()
