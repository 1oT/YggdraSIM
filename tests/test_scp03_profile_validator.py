import unittest

from SCP03.logic.profile_validator import ProfileValidator


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


if __name__ == "__main__":
    unittest.main()
