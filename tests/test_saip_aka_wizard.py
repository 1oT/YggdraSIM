"""
Unit tests for the tag-granular SAIP akaParameter provisioning wizard.

These tests exercise the pure-functional core that the shell and the
TRANSCODE-TUI wizards reuse. They explicitly avoid running the wizard
interactively and instead call the underlying validators and document
mutators directly.
"""

import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_aka_wizard import (
    aka_algorithm_choices,
    aka_wizard_steps,
    apply_aka_configuration,
    first_aka_section_key,
    normalize_algorithm,
    read_aka_configuration,
    validate_auth_counter_max,
    validate_key_for_algorithm,
    validate_number_of_keccak,
    validate_opc_for_algorithm,
    validate_sqn_init_seed,
)
from Tools.ProfilePackage.saip_json_codec import (
    build_decoded_document_from_sequence,
    ensure_workspace_pysim_on_path,
)
from Tools.ProfilePackage.saip_pe_quick_add import insert_blank_pe_for_menu_id


class AkaAlgorithmStepTests(unittest.TestCase):
    def test_choices_expose_expected_ids(self) -> None:
        ids = [choice[0] for choice in aka_algorithm_choices()]
        self.assertEqual(ids, ["milenage", "tuak", "xor-3g"])

    def test_normalize_accepts_aliases(self) -> None:
        self.assertEqual(normalize_algorithm("MILENAGE"), "milenage")
        self.assertEqual(normalize_algorithm(" Tuak  "), "tuak")
        self.assertEqual(
            normalize_algorithm("usim-test-algorithm"),
            "xor-3g",
        )

    def test_normalize_rejects_unknown(self) -> None:
        with self.assertRaises(ValueError):
            normalize_algorithm("comp128")


class AkaKeyValidationTests(unittest.TestCase):
    def test_milenage_requires_16_bytes(self) -> None:
        value = validate_key_for_algorithm("milenage", "00" * 16)
        self.assertEqual(len(value), 16)
        with self.assertRaises(ValueError):
            validate_key_for_algorithm("milenage", "00" * 32)

    def test_tuak_accepts_16_or_32(self) -> None:
        self.assertEqual(len(validate_key_for_algorithm("tuak", "11" * 16)), 16)
        self.assertEqual(len(validate_key_for_algorithm("tuak", "22" * 32)), 32)
        with self.assertRaises(ValueError):
            validate_key_for_algorithm("tuak", "22" * 8)

    def test_xor3g_requires_16_bytes(self) -> None:
        self.assertEqual(len(validate_key_for_algorithm("xor-3g", "ab" * 16)), 16)
        with self.assertRaises(ValueError):
            validate_key_for_algorithm("xor-3g", "ab" * 32)

    def test_rejects_non_hex(self) -> None:
        with self.assertRaises(ValueError):
            validate_key_for_algorithm("milenage", "ZZ" * 16)


class AkaOpcValidationTests(unittest.TestCase):
    def test_milenage_requires_16_bytes(self) -> None:
        self.assertEqual(len(validate_opc_for_algorithm("milenage", "33" * 16)), 16)
        with self.assertRaises(ValueError):
            validate_opc_for_algorithm("milenage", "33" * 32)

    def test_tuak_requires_32_bytes(self) -> None:
        self.assertEqual(len(validate_opc_for_algorithm("tuak", "44" * 32)), 32)
        with self.assertRaises(ValueError):
            validate_opc_for_algorithm("tuak", "44" * 16)

    def test_xor3g_ignores_opc(self) -> None:
        self.assertEqual(validate_opc_for_algorithm("xor-3g", ""), b"")
        self.assertEqual(validate_opc_for_algorithm("xor-3g", "abcdef"), b"")


class AkaOptionalFieldTests(unittest.TestCase):
    def test_keccak_defaults_to_one_when_missing(self) -> None:
        self.assertEqual(validate_number_of_keccak(None), 1)
        self.assertEqual(validate_number_of_keccak(""), 1)

    def test_keccak_clamps_range(self) -> None:
        self.assertEqual(validate_number_of_keccak(1), 1)
        self.assertEqual(validate_number_of_keccak(255), 255)
        with self.assertRaises(ValueError):
            validate_number_of_keccak(0)
        with self.assertRaises(ValueError):
            validate_number_of_keccak(256)

    def test_auth_counter_max_three_bytes(self) -> None:
        value = validate_auth_counter_max("ffffff")
        self.assertEqual(value, b"\xff\xff\xff")
        self.assertIsNone(validate_auth_counter_max(""))
        with self.assertRaises(ValueError):
            validate_auth_counter_max("ff")

    def test_sqn_init_seed_six_bytes(self) -> None:
        value = validate_sqn_init_seed("00" * 6)
        self.assertEqual(value, b"\x00" * 6)
        self.assertIsNone(validate_sqn_init_seed(""))
        with self.assertRaises(ValueError):
            validate_sqn_init_seed("00")


class AkaWizardStepShapeTests(unittest.TestCase):
    def test_full_step_list_contains_tuak_fields(self) -> None:
        keys = [step["key"] for step in aka_wizard_steps()]
        self.assertIn("numberOfKeccak", keys)

    def test_milenage_omits_tuak_only_steps(self) -> None:
        keys = [step["key"] for step in aka_wizard_steps("milenage")]
        self.assertNotIn("numberOfKeccak", keys)
        self.assertIn("opc", keys)

    def test_xor3g_marks_opc_optional(self) -> None:
        steps = aka_wizard_steps("xor-3g")
        opc_step = next(step for step in steps if step["key"] == "opc")
        self.assertFalse(opc_step["required"])


class AkaDocumentIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)
        from pySim.esim.saip import (
            ProfileElementEnd,
            ProfileElementHeader,
            ProfileElementSequence,
        )

        cls._ProfileElementEnd = ProfileElementEnd
        cls._ProfileElementHeader = ProfileElementHeader
        cls._ProfileElementSequence = ProfileElementSequence

    def _document_with_aka(self) -> dict:
        pes = self._ProfileElementSequence()
        pes.append(self._ProfileElementHeader())
        pes.append(self._ProfileElementEnd())
        document = build_decoded_document_from_sequence(pes, intro_lines=["wizard"])
        return insert_blank_pe_for_menu_id(
            document,
            self.workspace_root,
            menu_id="akaParameter",
        )

    def test_first_aka_section_key_locates_element(self) -> None:
        doc = self._document_with_aka()
        self.assertEqual(first_aka_section_key(doc), "akaParameter")

    def test_apply_milenage_updates_document(self) -> None:
        doc = self._document_with_aka()
        ki = "0102030405060708090A0B0C0D0E0F10"
        opc = "101112131415161718191A1B1C1D1E1F"
        new_doc = apply_aka_configuration(
            doc,
            self.workspace_root,
            section_key="akaParameter",
            algorithm="milenage",
            key_hex=ki,
            opc_hex=opc,
            auth_counter_max_hex="FFFFFF",
            sqn_init_hex="000000000001",
        )
        snapshot = read_aka_configuration(new_doc, "akaParameter")
        self.assertEqual(snapshot["algorithm"], "milenage")
        self.assertEqual(snapshot["key"], ki)
        self.assertEqual(snapshot["opc"], opc)
        self.assertEqual(snapshot["authCounterMax"], "FFFFFF")
        self.assertEqual(snapshot["sqnInit"], "000000000001")

    def test_apply_tuak_records_keccak_and_accepts_long_key(self) -> None:
        doc = self._document_with_aka()
        ki = "AA" * 32
        topc = "BB" * 32
        new_doc = apply_aka_configuration(
            doc,
            self.workspace_root,
            section_key="akaParameter",
            algorithm="tuak",
            key_hex=ki,
            opc_hex=topc,
            number_of_keccak=4,
        )
        snapshot = read_aka_configuration(new_doc, "akaParameter")
        self.assertEqual(snapshot["algorithm"], "tuak")
        self.assertEqual(snapshot["key"], ki)
        self.assertEqual(snapshot["opc"], topc)
        self.assertEqual(snapshot["numberOfKeccak"], "4")

    def test_apply_rejects_tuak_with_short_opc(self) -> None:
        doc = self._document_with_aka()
        with self.assertRaises(ValueError):
            apply_aka_configuration(
                doc,
                self.workspace_root,
                section_key="akaParameter",
                algorithm="tuak",
                key_hex="00" * 16,
                opc_hex="00" * 16,
            )

    def test_apply_rejects_non_aka_section(self) -> None:
        doc = self._document_with_aka()
        with self.assertRaises(ValueError):
            apply_aka_configuration(
                doc,
                self.workspace_root,
                section_key="header",
                algorithm="milenage",
                key_hex="00" * 16,
                opc_hex="00" * 16,
            )


class AkaListAndRandomizeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(self.workspace_root)

    def _document_with_aka(self) -> dict:
        from pySim.esim.saip import (
            ProfileElementEnd,
            ProfileElementHeader,
            ProfileElementSequence,
        )

        pes = ProfileElementSequence()
        pes.append(ProfileElementHeader())
        pes.append(ProfileElementEnd())
        base_document = build_decoded_document_from_sequence(pes, intro_lines=["wizard"])
        return insert_blank_pe_for_menu_id(
            base_document,
            self.workspace_root,
            menu_id="akaParameter",
        )

    def test_list_aka_sections_returns_empty_when_no_pe_present(self) -> None:
        from Tools.ProfilePackage.saip_aka_wizard import list_aka_sections
        from pySim.esim.saip import (
            ProfileElementEnd,
            ProfileElementHeader,
            ProfileElementSequence,
        )

        pes = ProfileElementSequence()
        pes.append(ProfileElementHeader())
        pes.append(ProfileElementEnd())
        document = build_decoded_document_from_sequence(pes, intro_lines=["list"])
        self.assertEqual(list_aka_sections(document), [])

    def test_list_aka_sections_reports_milenage_and_tuak(self) -> None:
        from Tools.ProfilePackage.saip_aka_wizard import list_aka_sections

        doc = self._document_with_aka()
        doc = apply_aka_configuration(
            doc,
            self.workspace_root,
            section_key="akaParameter",
            algorithm="milenage",
            key_hex="AA" * 16,
            opc_hex="BB" * 16,
        )
        summaries = list_aka_sections(doc)
        self.assertEqual(len(summaries), 1)
        entry = summaries[0]
        self.assertEqual(entry["algorithm"], "milenage")
        self.assertEqual(entry["key_bytes"], 16)
        self.assertEqual(entry["opc_bytes"], 16)
        self.assertFalse(entry["sqn_init_present"])

    def test_randomize_aka_values_milenage_shapes(self) -> None:
        from Tools.ProfilePackage.saip_aka_wizard import randomize_aka_values

        counter = {"value": 0}

        def _deterministic(length: int) -> bytes:
            counter["value"] += 1
            return bytes([counter["value"]] * length)

        values = randomize_aka_values("milenage", randbytes=_deterministic)
        self.assertEqual(values["algorithm"], "milenage")
        self.assertEqual(len(bytes.fromhex(values["key_hex"])), 16)
        self.assertEqual(len(bytes.fromhex(values["opc_hex"])), 16)
        self.assertIsNone(values["number_of_keccak"])
        self.assertEqual(values["auth_counter_max_hex"], "")
        self.assertEqual(values["sqn_init_hex"], "")

    def test_randomize_aka_values_tuak_shapes(self) -> None:
        from Tools.ProfilePackage.saip_aka_wizard import randomize_aka_values

        def _deterministic(length: int) -> bytes:
            return b"\x02" * length

        values = randomize_aka_values(
            "tuak",
            randbytes=_deterministic,
            include_auth_counter_max=True,
            include_sqn_init_seed=True,
        )
        self.assertEqual(len(bytes.fromhex(values["key_hex"])), 32)
        self.assertEqual(len(bytes.fromhex(values["opc_hex"])), 32)
        self.assertEqual(values["number_of_keccak"], 2)
        self.assertEqual(len(bytes.fromhex(values["auth_counter_max_hex"])), 3)
        self.assertEqual(len(bytes.fromhex(values["sqn_init_hex"])), 6)

    def test_randomize_aka_values_xor3g_skips_opc(self) -> None:
        from Tools.ProfilePackage.saip_aka_wizard import randomize_aka_values

        def _deterministic(length: int) -> bytes:
            return b"\x03" * length

        values = randomize_aka_values("xor-3g", randbytes=_deterministic)
        self.assertEqual(values["algorithm"], "xor-3g")
        self.assertEqual(len(bytes.fromhex(values["key_hex"])), 16)
        self.assertEqual(values["opc_hex"], "")


if __name__ == "__main__":
    unittest.main()
