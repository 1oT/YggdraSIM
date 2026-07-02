# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the tolerant SAIP DER loader.

The strict loader used to raise a raw ``asn1tools.codecs.ber.MissingDataError``
from deep inside pySim whenever one PE in a package was malformed —
operators saw ``MissingDataError: ProfileElement: Expected at least 48
contents byte(s), but got 3. (At offset: 2)`` with no file context, no PE
index, and no recoverable state.

The tolerant path added in :mod:`yggdrasim_common.gui_server.actions.saip`
falls back to a per-segment walker when the strict parse raises. If any
PE decoded successfully the partial sequence is surfaced together with a
per-PE warning list. If the walker also recovers zero PEs a descriptive
``ValueError`` is raised instead of the opaque asn1tools message.

These tests drive the helpers directly with hand-crafted byte blobs so
they do not depend on any real profile package on disk.
"""

from __future__ import annotations

import importlib
import unittest
from pathlib import Path
from typing import Any


class TolerantLoaderHelperTests(unittest.TestCase):
    """Unit tests for :func:`_parse_pes_tolerant` and its error shaper."""

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )
        # ``_parse_pes_tolerant`` imports from pySim so we must ensure
        # the workspace pySim is on ``sys.path`` + the compat patch is
        # installed. ``_ensure_pysim_importable`` is idempotent.
        self.saip._ensure_pysim_importable()

    def _good_pe_tlv(self) -> bytes:
        """Return a single valid ProfileElement DER blob.

        Uses pySim's own encoder so the bytes stay in sync with whatever
        version of the schema the workspace ships.
        """
        from pySim.esim.saip import ProfileElement

        pe = ProfileElement()
        pe.type = "end"
        pe.decoded = {"end-header": {"mandated": None, "identification": 0}}
        return pe.to_der()

    # ------------------------------------------------------------------
    # Tolerant walker
    # ------------------------------------------------------------------

    def test_tolerant_walker_decodes_clean_sequence(self) -> None:
        """Two well-formed PEs back-to-back yield zero warnings."""
        tlv = self._good_pe_tlv()
        raw = tlv + tlv

        pes, warnings, first_fail = self.saip._parse_pes_tolerant(raw)

        self.assertEqual(len(pes.pe_list), 2)
        self.assertEqual(warnings, [])
        self.assertIsNone(first_fail)

    def test_tolerant_walker_records_failing_pe_but_keeps_good_ones(self) -> None:
        """A PE with a valid outer TLV but unparseable content produces one warning.

        The walker must:
          * decode both surrounding PEs,
          * append exactly one warning describing the broken segment,
          * surface the first failure for the error shaper to quote.

        Note: if the inner length prefix is *itself* lying about segment
        size, the BER chopper will over-advance and we lose bytes — that
        scenario is covered separately by the total-garbage test below.
        Here we craft a self-consistent outer TLV whose content simply
        isn't a valid ProfileElement body.
        """
        good = self._good_pe_tlv()
        # Context-specific tag [0] (header) with a well-formed length of
        # five bytes of content that won't decode as a ProfileHeader
        # structure. The outer TLV boundary is accurate so the chopper
        # advances cleanly; the decode step is what fails.
        malformed = bytes([0xA0, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        raw = good + malformed + good

        pes, warnings, first_fail = self.saip._parse_pes_tolerant(raw)

        # Both well-formed PEs survive the broken middle segment.
        self.assertGreaterEqual(len(pes.pe_list), 2)
        # The bad segment was noted.
        self.assertGreaterEqual(len(warnings), 1)
        self.assertIsNotNone(first_fail)
        assert first_fail is not None
        self.assertIn(first_fail.get("stage"), {"pe_decode", "tlv_chop"})
        # Offset is measured from the start of ``raw`` (not the segment).
        self.assertEqual(first_fail["offset"], len(good))
        # head_hex is a human-readable hex dump of the failing segment.
        self.assertIn("A0", first_fail["head_hex"])

    def test_tolerant_walker_survives_total_garbage(self) -> None:
        """Pure random bytes produce an empty sequence + a first_fail entry."""
        raw = bytes([0x01, 0x02, 0x03])

        pes, warnings, first_fail = self.saip._parse_pes_tolerant(raw)

        self.assertEqual(len(pes.pe_list), 0)
        # Either the TLV chopper or the decoder must flag it.
        self.assertIsNotNone(first_fail)

    # ------------------------------------------------------------------
    # Error shaper
    # ------------------------------------------------------------------

    def test_make_saip_load_error_embeds_file_size_and_head(self) -> None:
        """The error message must carry the file name, size and head hex."""
        raw = bytes([0xA0, 0x30, 0x00, 0x01, 0x02])
        err = ValueError("upstream failure")
        fail = {
            "stage": "pe_decode",
            "index": 0,
            "offset": 0,
            "segment_len": len(raw),
            "head_hex": "A0 30 00 01 02",
            "error": "MissingDataError: ProfileElement: Expected at least 48 contents byte(s), but got 3.",
        }

        shaped = self.saip._make_saip_load_error(
            Path("mock-profile.der"), raw, err, fail,
        )

        msg = str(shaped)
        self.assertIn("mock-profile.der", msg)
        self.assertIn(f"{len(raw)} bytes", msg)
        self.assertIn("A0", msg)
        self.assertIn("PE index 0", msg)
        self.assertIn("offset 0", msg)
        self.assertIn("stage=pe_decode", msg)
        self.assertIn("MissingDataError", msg)

    def test_make_saip_load_error_hints_json_when_header_is_brace(self) -> None:
        """Files starting with '{' trigger the "looks like JSON" hint."""
        raw = b'{"header": {}}'
        err = ValueError("boom")
        shaped = self.saip._make_saip_load_error(
            Path("profile.der"), raw, err, None,
        )
        self.assertIn("JSON", str(shaped))

    def test_make_saip_load_error_hints_wrapped_envelope(self) -> None:
        """A non-class-context tag (e.g. 0x30) triggers the wrapped-response hint."""
        raw = bytes([0x30, 0x82, 0x01, 0x23, 0xFF, 0xFF])  # SEQUENCE-ish
        err = ValueError("boom")
        shaped = self.saip._make_saip_load_error(
            Path("bound.bin"), raw, err, None,
        )
        msg = str(shaped)
        self.assertIn("0x30", msg)
        self.assertIn("wrapped", msg)

    # ------------------------------------------------------------------
    # Loader plumbing
    # ------------------------------------------------------------------

    def test_load_package_returns_warnings_key(self) -> None:
        """``_load_package_from_path`` always carries a warnings list.

        Well-formed packages still return an empty list, but the key
        must always be present so callers (both backend dispatcher and
        frontend record) can rely on it.
        """
        # We drive the full loader via a minimal "just the end PE"
        # package. The end PE alone is legal SAIP and round-trips
        # cleanly through from_der.
        tlv = self._good_pe_tlv()
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as tmp:
            tmp.write(tlv)
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            package = self.saip._load_package_from_path(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

        self.assertIn("warnings", package)
        self.assertEqual(package["warnings"], [])
        self.assertGreaterEqual(len(package["pes"].pe_list), 1)


class OpenPackageResponseTests(unittest.TestCase):
    """End-to-end: ``saip.open_package`` must surface load_warnings."""

    def test_open_package_response_includes_load_warnings_field(self) -> None:
        """Verify the dispatcher threads the field through to the JSON.

        The field must be present whether or not the tolerant parser
        recovered anything — the frontend's log-bus relay indexes on it
        and would skip all warnings if the key were absent.
        """
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        saip_actions._ensure_pysim_importable()
        # Build an end-PE package on the fly.
        from pySim.esim.saip import ProfileElement

        pe = ProfileElement()
        pe.type = "end"
        pe.decoded = {"end-header": {"mandated": None, "identification": 0}}
        der = pe.to_der()

        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as tmp:
            tmp.write(der)
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            class _Ctx:
                pass

            resp = saip_actions._dispatch_open_package(_Ctx(), path=str(tmp_path))
        finally:
            tmp_path.unlink(missing_ok=True)

        self.assertIn("load_warnings", resp)
        self.assertIsInstance(resp["load_warnings"], list)
        # The backend's session handle also carries the key so the
        # reload-source path preserves it on revert.
        from yggdrasim_common.gui_server.sessions import get_manager

        handle: Any = get_manager().claim(resp["session_id"])
        self.assertIn("load_warnings", handle)


class FrontendLoadWarningsWiring(unittest.TestCase):
    """Static-bundle contract: the SAIP open flow relays load_warnings."""

    def test_open_package_handler_reads_load_warnings(self) -> None:
        static_dir = (
            Path(__file__).resolve().parents[1]
            / "yggdrasim_common" / "gui_server" / "static"
        )
        js = (static_dir / "app.js").read_text(encoding="utf-8")

        self.assertIn("respData && respData.load_warnings", js)
        # Each entry becomes its own warn-level logBus event so the
        # Warnings dock lists them individually instead of folding them
        # into a single line.
        self.assertIn("loadWarnings.forEach", js)
        self.assertIn('source: "saip.open_package"', js)


class HexTextLoaderTests(unittest.TestCase):
    """The picker accepts ``.hex`` and ``.txt`` profiles which are
    ASCII hex-text rather than binary DER. The TUI handles this in
    ``SaipToolBridge._prepare_input_for_tool``; the GUI loader must
    apply the same transformation or the tolerant DER walker will
    treat ASCII bytes as TLV and produce confusing warnings.
    """

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )
        self.saip._ensure_pysim_importable()

    def _build_end_pe_der(self) -> bytes:
        from pySim.esim.saip import ProfileElement

        pe = ProfileElement()
        pe.type = "end"
        pe.decoded = {"end-header": {"mandated": None, "identification": 0}}
        return pe.to_der()

    def test_sniff_recognises_ascii_hex_payloads(self) -> None:
        der = self._build_end_pe_der()
        ascii_hex = der.hex().upper().encode("ascii")
        self.assertEqual(self.saip._sniff_encoding(ascii_hex), "hex")

    def test_sniff_recognises_bom_prefixed_ascii_hex_payloads(self) -> None:
        der = self._build_end_pe_der()
        ascii_hex = b"\xef\xbb\xbf" + der.hex().upper().encode("ascii")
        self.assertEqual(self.saip._sniff_encoding(ascii_hex), "hex")

    def test_sniff_recognises_simple_placeholder_hex_templates(self) -> None:
        self.assertEqual(self.saip._sniff_encoding(b"A0{ICCID}FF"), "hex")

    def test_sniff_recognises_asn1_value_notation(self) -> None:
        payload = "\ufeffheader ProfileElement ::= header : { }".encode("utf-8")
        self.assertEqual(self.saip._sniff_encoding(payload), "asn")

    def test_sniff_keeps_der_for_binary_payloads(self) -> None:
        der = self._build_end_pe_der()
        self.assertEqual(self.saip._sniff_encoding(der), "der")

    def test_sniff_keeps_json_for_object_payloads(self) -> None:
        self.assertEqual(self.saip._sniff_encoding(b'{ "pe_list": [] }'), "json")

    def test_decode_hex_text_payload_strips_whitespace_and_normalises_case(self) -> None:
        # bytes.fromhex tolerates many separators; we spot-check the
        # most common (spaces, tabs, newlines) plus mixed case.
        decoded = self.saip._decode_hex_text_payload(
            Path("/tmp/dummy.hex"),
            b"  AB cd\nef\t01 23 45 67 89  ",
        )
        self.assertEqual(decoded, bytes.fromhex("ABCDEF0123456789"))

    def test_decode_hex_text_payload_strips_utf8_bom(self) -> None:
        decoded = self.saip._decode_hex_text_payload(
            Path("/tmp/dummy.hex"),
            b"\xef\xbb\xbfAB CD",
        )
        self.assertEqual(decoded, bytes.fromhex("ABCD"))

    def test_decode_hex_text_payload_rejects_odd_length(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.saip._decode_hex_text_payload(Path("/tmp/dummy.hex"), b"ABC")
        self.assertIn("odd-length", str(ctx.exception))

    def test_decode_hex_text_payload_rejects_non_hex(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.saip._decode_hex_text_payload(Path("/tmp/dummy.hex"), b"AB ZZ")
        self.assertIn("non-hex", str(ctx.exception))

    def test_decode_hex_text_payload_rejects_simple_placeholder_template(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.saip._decode_hex_text_payload(
                Path("/tmp/dummy.varder"),
                b"A0{ICCID}FF",
            )
        message = str(ctx.exception)
        self.assertIn("placeholders", message)
        self.assertIn("Materialise", message)

    def test_decode_hex_text_payload_accepts_compact_typed_placeholder(self) -> None:
        decoded, records = self.saip._decode_hex_text_payload_with_placeholders(
            Path("/tmp/dummy.varder"),
            b"AA{imsiIMSI8EncodeIMSI}BB",
        )
        self.assertEqual(len(decoded), 10)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].variable_name, "imsi")
        self.assertEqual(records[0].type_name, "IMSI")
        self.assertEqual(records[0].byte_length, 8)
        self.assertEqual(records[0].modifier, "EncodeIMSI")

    def test_decode_hex_text_payload_rejects_empty_input(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.saip._decode_hex_text_payload(Path("/tmp/dummy.hex"), b"   \n\t")
        self.assertIn("empty", str(ctx.exception))

    def test_load_package_decodes_txt_hex_input(self) -> None:
        """A ``.txt`` file with ASCII hex digits round-trips to the DER parser.

        Operators routinely store profiles as hex-text (one large blob
        of digits, sometimes with whitespace). The TUI accepts this via
        ``_HEX_INPUT_SUFFIXES`` and the GUI must match.
        """
        import tempfile

        der = self._build_end_pe_der()
        ascii_hex = der.hex().upper()

        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False, mode="w", encoding="utf-8"
        ) as tmp:
            tmp.write(ascii_hex)
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            package = self.saip._load_package_from_path(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

        self.assertEqual(package["encoding"], "hex")
        self.assertEqual(package["warnings"], [])
        self.assertGreaterEqual(len(package["pes"].pe_list), 1)

    def test_load_package_decodes_hex_input_with_whitespace(self) -> None:
        """Whitespace between hex digits is tolerated. Many profile
        dumps wrap at 64 / 80 columns or use space-separated octets.
        """
        import tempfile

        der = self._build_end_pe_der()
        # Insert a space every two characters and a newline every 32.
        chunks = [der.hex()[i:i+2] for i in range(0, len(der.hex()) * 2, 2) if i < len(der.hex()) * 2]
        formatted = "\n".join(
            " ".join(chunks[i:i+16]) for i in range(0, len(chunks), 16)
        ).upper()

        with tempfile.NamedTemporaryFile(
            suffix=".hex", delete=False, mode="w", encoding="utf-8"
        ) as tmp:
            tmp.write(formatted)
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            package = self.saip._load_package_from_path(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

        self.assertEqual(package["encoding"], "hex")
        self.assertGreaterEqual(len(package["pes"].pe_list), 1)

    def test_load_package_falls_back_to_der_for_txt_with_binary_content(self) -> None:
        """A ``.txt`` file that actually contains DER bytes (operator
        misnamed the extension) must still load — the loader's hex
        decode raises ``ValueError`` on the non-hex bytes and we then
        fall back to feeding the binary payload to the DER parser.
        """
        import tempfile

        der = self._build_end_pe_der()

        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False, mode="wb"
        ) as tmp:
            tmp.write(der)
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            package = self.saip._load_package_from_path(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

        # Encoding stays ``der`` once the hex fallback unwinds.
        self.assertEqual(package["encoding"], "der")
        self.assertGreaterEqual(len(package["pes"].pe_list), 1)

    def test_load_package_rejects_varder_simple_placeholder_template(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile(
            suffix=".varder", delete=False, mode="w", encoding="utf-8-sig"
        ) as tmp:
            tmp.write("A0{ICCID}FF")
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            with self.assertRaises(ValueError) as ctx:
                self.saip._load_package_from_path(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

        self.assertIn("placeholders", str(ctx.exception))
        self.assertIn("Materialise", str(ctx.exception))

    def test_load_package_accepts_asn1_value_notation(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile(
            suffix=".asn", delete=False, mode="w", encoding="utf-8-sig"
        ) as tmp:
            tmp.write(
                """
                end ProfileElement ::= end :
                {
                  end-header
                  {
                    mandated NULL,
                    identification 1
                  }
                }
                """
            )
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            package = self.saip._load_package_from_path(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

        self.assertEqual(package["encoding"], "asn")
        self.assertEqual(len(package["pes"].pe_list), 1)
        self.assertEqual(package["pes"].pe_list[0].type, "end")

    def test_load_package_accepts_asn1_compact_typed_placeholders(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile(
            suffix=".asn", delete=False, mode="w", encoding="utf-8-sig"
        ) as tmp:
            tmp.write(
                """
                pukCodes ProfileElement ::= pukCodes :
                {
                  puk-Header
                  {
                    mandated NULL,
                    identification 1
                  },
                  pukCodes
                  {
                    {
                      keyReference pukAppl1,
                      pukValue '[pukBINARY8]'H
                    }
                  }
                }
                """
            )
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            package = self.saip._load_package_from_path(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

        self.assertEqual(package["encoding"], "asn")
        self.assertEqual(len(package["pes"].pe_list), 1)
        self.assertEqual(package["pes"].pe_list[0].type, "pukCodes")
        self.assertEqual(len(package.get("inline_placeholder_records") or []), 1)
        record = package["inline_placeholder_records"][0]
        self.assertEqual(record.variable_name, "puk")
        self.assertEqual(record.type_name, "BINARY")
        self.assertEqual(record.byte_length, 8)


if __name__ == "__main__":
    unittest.main()
