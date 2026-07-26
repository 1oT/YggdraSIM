# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import tempfile
import unittest
from pathlib import Path

import yaml

from SCP03.logic.profile_validator import (
    POLICY_GROUPS,
    FileExpectation,
    PolicyPackError,
    ProfileValidator,
    export_default_policy_pack,
    load_policy_pack,
    parse_policy_pack,
)


class DummyTransport:
    def __init__(self, fs_controller):
        self.fs_controller = fs_controller

    def transmit(self, apdu_hex: str, silent: bool = False):
        current_entry = self.fs_controller.entries[self.fs_controller.current_path_hint]
        normalized = apdu_hex.upper()

        if normalized == "00B0000000":
            binary_hex = current_entry.get("binary", "")
            return bytes.fromhex(binary_hex), 0x90, 0x00

        if normalized.startswith("00B2"):
            record_number = int(normalized[4:6], 16)
            records = current_entry.get("records", [])
            if record_number <= 0:
                return b"", 0x6A, 0x83

            if record_number > len(records):
                return b"", 0x6A, 0x83

            record_hex = records[record_number - 1]
            return bytes.fromhex(record_hex), 0x90, 0x00

        raise AssertionError(f"Unexpected APDU: {apdu_hex}")


class DummyFsController:
    def __init__(self, entries):
        self.entries = {}
        for path, entry in entries.items():
            self.entries[path.upper()] = entry
        self.current_path_hint = "MF"
        self.current_fid = "3F00"
        self.current_fcp = {}
        self.tp = DummyTransport(self)

    def select(self, target_path: str, silent: bool = False) -> bool:
        normalized = target_path.strip().upper()
        if normalized not in self.entries:
            return False

        entry = self.entries[normalized]
        self.current_path_hint = normalized
        self.current_fid = entry.get("fid", normalized)
        self.current_fcp = dict(entry["meta"])
        return True


def _mf_meta(file_type, structure, size=0, sfi=None):
    return {
        "template": "FCP",
        "type": file_type,
        "structure": structure,
        "size": size,
        "rec_len": 0,
        "rec_count": 0,
        "lcs": "Operational",
        "security": "ARR",
        "rules": [],
        "aid": None,
        "file_descriptor": "0000",
        "sfi": sfi,
    }


class ProfileValidatorTests(unittest.TestCase):
    def test_validate_mf_passes_for_required_core_files(self):
        fs_controller = DummyFsController(
            {
                "MF": {
                    "fid": "3F00",
                    "meta": _mf_meta("DF", "Tree"),
                },
                "EF_PL": {
                    "fid": "2F05",
                    "meta": _mf_meta("EF", "Transparent", size=2, sfi="05"),
                },
                "EF_ICCID": {
                    "fid": "2FE2",
                    "meta": _mf_meta("EF", "Transparent", size=10),
                },
                "EF_DIR": {
                    "fid": "2F00",
                    "meta": _mf_meta("EF", "Linear Fixed", sfi="1E"),
                },
                "EF_ARR": {
                    "fid": "2F06",
                    "meta": _mf_meta("EF", "Linear Fixed"),
                },
                "EF_UMPC": {
                    "fid": "2F08",
                    "meta": _mf_meta("EF", "Transparent", size=5, sfi="08"),
                },
            }
        )

        findings = ProfileValidator(fs_controller).run(scope="MF")

        fail_findings = [finding for finding in findings if finding.severity == "FAIL"]
        self.assertEqual(fail_findings, [])

    def test_validate_mf_reports_sfi_and_size_mismatch_as_warning(self):
        fs_controller = DummyFsController(
            {
                "MF": {
                    "fid": "3F00",
                    "meta": _mf_meta("DF", "Tree"),
                },
                "EF_PL": {
                    "fid": "2F05",
                    "meta": _mf_meta("EF", "Transparent", size=6, sfi="28"),
                },
                "EF_ICCID": {
                    "fid": "2FE2",
                    "meta": _mf_meta("EF", "Transparent", size=10),
                },
                "EF_DIR": {
                    "fid": "2F00",
                    "meta": _mf_meta("EF", "Linear Fixed", sfi="1E"),
                },
                "EF_ARR": {
                    "fid": "2F06",
                    "meta": _mf_meta("EF", "Linear Fixed"),
                },
                "EF_UMPC": {
                    "fid": "2F08",
                    "meta": _mf_meta("EF", "Transparent", size=5, sfi="08"),
                },
            }
        )

        findings = ProfileValidator(fs_controller).run(scope="MF")

        ef_pl_findings = [finding for finding in findings if finding.path == "EF_PL"]
        self.assertEqual(ef_pl_findings[0].severity, "WARN")
        self.assertIn("size=6, expected=2", ef_pl_findings[0].message)
        self.assertIn("sfi=28, expected=05", ef_pl_findings[0].message)

    def test_validate_strict_content_pattern_can_fail(self):
        fs_controller = DummyFsController(
            {
                "ADF_USIM": {
                    "fid": "7FFF",
                    "meta": _mf_meta("DF", "Tree"),
                },
                "ADF_USIM/GSM_ACCESS": {
                    "fid": "5F3B",
                    "meta": _mf_meta("DF", "Tree"),
                },
                "ADF_USIM/GSM_ACCESS/EF_KC": {
                    "fid": "6F20",
                    "meta": _mf_meta("EF", "Transparent", size=9, sfi="01"),
                    "binary": "000000000000000007",
                },
            }
        )

        findings = ProfileValidator(fs_controller).run(scope="USIM")

        ef_kc_findings = [finding for finding in findings if finding.path == "ADF_USIM/GSM_ACCESS/EF_KC"]
        self.assertTrue(any(finding.severity == "FAIL" for finding in ef_kc_findings))

    def test_missing_isim_is_warning_when_not_mandated_by_metadata(self):
        fs_controller = DummyFsController(
            {
                "MF": {
                    "fid": "3F00",
                    "meta": _mf_meta("DF", "Tree"),
                },
            }
        )
        metadata = {
            "sections": {
                "header": {
                    "eUICC-Mandatory-services": {
                        "usim": True,
                    }
                }
            }
        }

        findings = ProfileValidator(fs_controller, profile_metadata=metadata).run(scope="ISIM")

        isim_findings = [finding for finding in findings if finding.path == "ADF_ISIM"]
        self.assertEqual(isim_findings[0].severity, "WARN")

    def test_missing_isim_is_fail_when_mandated_by_metadata(self):
        fs_controller = DummyFsController(
            {
                "MF": {
                    "fid": "3F00",
                    "meta": _mf_meta("DF", "Tree"),
                },
            }
        )
        metadata = {
            "sections": {
                "header": {
                    "eUICC-Mandatory-services": {
                        "isim": True,
                    }
                }
            }
        }

        findings = ProfileValidator(fs_controller, profile_metadata=metadata).run(scope="ISIM")

        isim_findings = [finding for finding in findings if finding.path == "ADF_ISIM"]
        self.assertEqual(isim_findings[0].severity, "FAIL")

    def test_validate_mf_reports_missing_required_file(self):
        fs_controller = DummyFsController(
            {
                "MF": {
                    "fid": "3F00",
                    "meta": _mf_meta("DF", "Tree"),
                },
                "EF_PL": {
                    "fid": "2F05",
                    "meta": _mf_meta("EF", "Transparent", size=2, sfi="05"),
                },
                "EF_ICCID": {
                    "fid": "2FE2",
                    "meta": _mf_meta("EF", "Transparent", size=10),
                },
                "EF_DIR": {
                    "fid": "2F00",
                    "meta": _mf_meta("EF", "Linear Fixed", sfi="1E"),
                },
                "EF_UMPC": {
                    "fid": "2F08",
                    "meta": _mf_meta("EF", "Transparent", size=5, sfi="08"),
                },
            }
        )

        findings = ProfileValidator(fs_controller).run(scope="MF")

        fail_paths = [finding.path for finding in findings if finding.severity == "FAIL"]
        self.assertIn("EF_ARR", fail_paths)


class PolicyPackTests(unittest.TestCase):
    """A pack must be able to express the baseline before it can replace it."""

    def test_exported_defaults_round_trip_to_the_built_in_tables(self) -> None:
        # The load-bearing test: if this holds, shipping the pack loader
        # cannot have changed what the built-in validator checks.
        parsed = parse_policy_pack(export_default_policy_pack())
        self.assertEqual(set(parsed), set(POLICY_GROUPS))
        for group, attribute in POLICY_GROUPS.items():
            self.assertEqual(
                parsed[group],
                getattr(ProfileValidator, attribute),
                f"policy group {group} does not reproduce {attribute}",
            )

    def test_exported_defaults_survive_a_yaml_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / "house-rules.yaml"
            pack.write_text(
                yaml.safe_dump(export_default_policy_pack(), sort_keys=False),
                encoding="utf-8",
            )
            loaded = load_policy_pack(pack)
        for group, attribute in POLICY_GROUPS.items():
            self.assertEqual(loaded[group], getattr(ProfileValidator, attribute))

    def test_a_pack_group_replaces_the_built_in_table(self) -> None:
        policy = {"mf": (FileExpectation("MF", "DF", "Tree", require_security=False),)}
        validator = ProfileValidator(None, policy=policy)
        self.assertEqual(len(validator.MF_EXPECTATIONS), 1)
        self.assertEqual(validator.policy_groups, ("mf",))

    def test_groups_absent_from_the_pack_keep_the_baseline(self) -> None:
        policy = {"mf": (FileExpectation("MF", "DF", "Tree"),)}
        validator = ProfileValidator(None, policy=policy)
        self.assertEqual(
            validator.USIM_EXPECTATIONS,
            ProfileValidator.USIM_EXPECTATIONS,
        )

    def test_a_pack_never_mutates_the_class_tables(self) -> None:
        baseline = ProfileValidator.MF_EXPECTATIONS
        ProfileValidator(None, policy={"mf": (FileExpectation("MF", "DF", "Tree"),)})
        self.assertEqual(ProfileValidator.MF_EXPECTATIONS, baseline)

    def test_unknown_group_is_rejected(self) -> None:
        with self.assertRaises(PolicyPackError) as raised:
            parse_policy_pack({"groups": {"usim": [], "wishful": []}})
        self.assertIn("wishful", str(raised.exception))

    def test_unknown_field_is_rejected_rather_than_ignored(self) -> None:
        # A silently dropped typo would quietly weaken a check.
        with self.assertRaises(PolicyPackError) as raised:
            parse_policy_pack(
                {
                    "groups": {
                        "mf": [
                            {
                                "path": "EF_ICCID",
                                "expected_type": "EF",
                                "expected_structure": "Transparent",
                                "sizee": 10,
                            }
                        ]
                    }
                }
            )
        self.assertIn("sizee", str(raised.exception))

    def test_missing_required_field_is_rejected(self) -> None:
        with self.assertRaises(PolicyPackError) as raised:
            parse_policy_pack({"groups": {"mf": [{"path": "EF_ICCID"}]}})
        self.assertIn("expected_type", str(raised.exception))

    def test_service_any_is_coerced_to_a_tuple_of_ints(self) -> None:
        parsed = parse_policy_pack(
            {
                "groups": {
                    "usim": [
                        {
                            "path": "ADF_USIM/EF_X",
                            "expected_type": "EF",
                            "expected_structure": "Transparent",
                            "service_any": [2, "6"],
                        }
                    ]
                }
            }
        )
        self.assertEqual(parsed["usim"][0].service_any, (2, 6))

    def test_service_any_rejects_a_non_list(self) -> None:
        with self.assertRaises(PolicyPackError):
            parse_policy_pack(
                {
                    "groups": {
                        "usim": [
                            {
                                "path": "ADF_USIM/EF_X",
                                "expected_type": "EF",
                                "expected_structure": "Transparent",
                                "service_any": 2,
                            }
                        ]
                    }
                }
            )

    def test_empty_or_malformed_pack_is_rejected(self) -> None:
        for payload in ([], {}, {"groups": {}}, {"groups": []}):
            with self.assertRaises(PolicyPackError):
                parse_policy_pack(payload)

    def test_missing_pack_file_reports_the_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyPackError) as raised:
                load_policy_pack(Path(tmp) / "absent.yaml")
        self.assertIn("absent.yaml", str(raised.exception))


class ValidateCommandPolicyWiringTests(unittest.TestCase):
    """The shell must accept POLICY= and keep the workspace containment check."""

    def setUp(self) -> None:
        from SCP03.config import Config
        from SCP03.interface.shell import ShellDispatcher

        self.dispatcher = ShellDispatcher
        self.workspace_root = Path(Config.BASE_DIR).resolve().parent

    def test_policy_pack_outside_the_workspace_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            stray = Path(outside) / "house-rules.yaml"
            stray.write_text(
                yaml.safe_dump(export_default_policy_pack()), encoding="utf-8"
            )
            with self.assertRaises(ValueError) as raised:
                self.dispatcher._resolve_workspace_path(
                    None, str(stray), "Policy pack"
                )
        self.assertIn("outside workspace root", str(raised.exception))

    def test_missing_policy_pack_names_the_label(self) -> None:
        with self.assertRaises(FileNotFoundError) as raised:
            self.dispatcher._resolve_workspace_path(
                None, "absent-policy-pack.yaml", "Policy pack"
            )
        self.assertIn("Policy pack", str(raised.exception))

    def test_a_pack_inside_the_workspace_loads(self) -> None:
        pack_dir = self.workspace_root / "Workspace"
        pack_dir.mkdir(parents=True, exist_ok=True)
        pack = pack_dir / "test-policy-pack.yaml"
        pack.write_text(
            yaml.safe_dump(export_default_policy_pack()), encoding="utf-8"
        )
        try:
            loaded = load_policy_pack(
                self.dispatcher._resolve_workspace_path(None, str(pack), "Policy pack")
            )
            self.assertEqual(loaded["mf"], ProfileValidator.MF_EXPECTATIONS)
        finally:
            pack.unlink()


if __name__ == "__main__":
    unittest.main()
