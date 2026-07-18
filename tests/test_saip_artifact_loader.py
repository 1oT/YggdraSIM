# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Focused tests for the shared SAIP artifact-loading boundary."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_artifact_loader import load_saip_artifact


class SharedSaipArtifactLoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from yggdrasim_common.gui_server.actions import saip

        saip._ensure_pysim_importable()

    def _end_pe_der(self) -> bytes:
        from pySim.esim.saip import ProfileElement

        pe = ProfileElement()
        pe.type = "end"
        pe.decoded = {"end-header": {"mandated": None, "identification": 0}}
        return pe.to_der()

    def test_der_result_keeps_provenance_and_is_strictly_complete(self) -> None:
        raw = self._end_pe_der()
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "profile.der"
            source.write_bytes(raw)

            loaded = load_saip_artifact(source)

        self.assertEqual(loaded.raw_input_bytes, raw)
        self.assertEqual(
            loaded.raw_input_sha256,
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(loaded.encoding, "der")
        self.assertEqual(loaded.source_format, "der")
        self.assertEqual(loaded.pe_count, 1)
        self.assertEqual(loaded.warnings, ())
        self.assertTrue(loaded.strict_complete)
        self.assertTrue(loaded.is_strictly_complete)

    def test_tolerant_recovery_is_never_reported_as_strict_complete(self) -> None:
        good = self._end_pe_der()
        raw = good + bytes.fromhex("50 00") + good
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "partial.der"
            source.write_bytes(raw)

            loaded = load_saip_artifact(source)

        self.assertEqual(loaded.pe_count, 2)
        self.assertFalse(loaded.strict_complete)
        self.assertIsNotNone(loaded.strict_failure)
        self.assertEqual(len(loaded.warnings), 1)
        warning = loaded.warnings[0]
        self.assertEqual(warning.stage, "pe_decode")
        self.assertEqual(warning.byte_offset, len(good))
        self.assertEqual(warning.segment_head_hex, "50 00")

        legacy = loaded.to_legacy_mapping()
        self.assertFalse(legacy["strict_complete"])
        self.assertEqual(legacy["warnings"][0]["head_hex"], "50 00")

    def test_terminal_tlv_chop_failure_is_retained_as_warning_evidence(self) -> None:
        good = self._end_pe_der()
        raw = good + bytes.fromhex("A0")
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "truncated.der"
            source.write_bytes(raw)

            loaded = load_saip_artifact(source)

        self.assertEqual(loaded.pe_count, 1)
        self.assertFalse(loaded.strict_complete)
        self.assertEqual(len(loaded.warnings), 1)
        self.assertEqual(loaded.warnings[0].stage, "tlv_chop")
        self.assertEqual(loaded.warnings[0].byte_offset, len(good))

    def test_asn1_placeholder_is_exposed_as_typed_evidence(self) -> None:
        source_text = """
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
        raw = source_text.encode("utf-8")
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "profile.asn"
            source.write_bytes(raw)

            loaded = load_saip_artifact(source)

        self.assertEqual(loaded.encoding, "asn")
        self.assertEqual(loaded.source_format, "asn1-value")
        self.assertEqual(loaded.raw_input_bytes, raw)
        self.assertTrue(loaded.strict_complete)
        self.assertTrue(loaded.is_template)
        self.assertEqual(len(loaded.placeholder_evidence), 1)
        evidence = loaded.placeholder_evidence[0]
        self.assertEqual(evidence.kind, "inline-typed")
        self.assertEqual(evidence.literal, "[pukBINARY8]")
        self.assertEqual(evidence.variable_name, "puk")
        self.assertEqual(evidence.type_name, "BINARY")
        self.assertEqual(evidence.byte_length, 8)

    def test_hex_and_varder_source_formats_remain_distinct(self) -> None:
        raw_der = self._end_pe_der()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            hex_path = root / "profile.hex"
            varder_path = root / "profile.varder"
            hex_path.write_text(raw_der.hex(), encoding="ascii")
            varder_path.write_text(raw_der.hex(), encoding="ascii")

            loaded_hex = load_saip_artifact(hex_path)
            loaded_varder = load_saip_artifact(varder_path)

        self.assertEqual(loaded_hex.encoding, "hex")
        self.assertEqual(loaded_hex.source_format, "hex")
        self.assertEqual(loaded_varder.encoding, "hex")
        self.assertEqual(loaded_varder.source_format, "varder")

    def test_tagged_json_uses_the_same_decoded_sequence_boundary(self) -> None:
        from pySim.esim.saip import ProfileElementSequence

        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
            jsonify_document,
        )

        pes = ProfileElementSequence.from_der(self._end_pe_der())
        document = jsonify_document(build_decoded_document_from_sequence(pes))
        raw = json.dumps(document, indent=2).encode("utf-8")
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "profile.json"
            source.write_bytes(raw)

            loaded = load_saip_artifact(source)

        self.assertEqual(loaded.raw_input_bytes, raw)
        self.assertEqual(loaded.encoding, "json")
        self.assertEqual(loaded.source_format, "tagged-json")
        self.assertEqual(loaded.pe_count, 1)
        self.assertTrue(loaded.strict_complete)


if __name__ == "__main__":
    unittest.main()
