import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

from SCP03.config import Config


def _repeat_byte(byte_value: str, count: int) -> str:
    return byte_value.upper() * count


def _hex_join(*parts: str) -> str:
    return "".join(parts).upper()


@dataclass(frozen=True)
class FileExpectation:
    path: str
    expected_type: str
    expected_structure: str
    size: Optional[int] = None
    record_length: Optional[int] = None
    record_count: Optional[int] = None
    sfi: Optional[str] = None
    required: bool = True
    require_security: bool = True
    require_lcs: bool = True
    service_any: Tuple[int, ...] = ()
    content_pattern: Optional[str] = None
    pattern_scope: str = "file"
    content_mismatch_severity: str = "WARN"


@dataclass
class ValidationFinding:
    severity: str
    path: str
    message: str


class ProfileValidator:
    MF_EXPECTATIONS: Tuple[FileExpectation, ...] = (
        FileExpectation("MF", "DF", "Tree", required=True, require_security=False),
        FileExpectation("EF_PL", "EF", "Transparent", size=2, sfi="05"),
        FileExpectation("EF_ICCID", "EF", "Transparent", size=10),
        FileExpectation("EF_DIR", "EF", "Linear Fixed", sfi="1E"),
        FileExpectation("EF_ARR", "EF", "Linear Fixed"),
        FileExpectation("EF_UMPC", "EF", "Transparent", size=5, sfi="08"),
    )

    USIM_EXPECTATIONS: Tuple[FileExpectation, ...] = (
        FileExpectation("ADF_USIM", "DF", "Tree", required=True, require_security=False),
        FileExpectation("ADF_USIM/EF_IMSI", "EF", "Transparent", size=9, sfi="07", require_security=False),
        FileExpectation("ADF_USIM/EF_ARR", "EF", "Linear Fixed", sfi="17", require_security=False),
        FileExpectation(
            "ADF_USIM/EF_KEYS",
            "EF",
            "Transparent",
            size=33,
            sfi="08",
            content_pattern=_hex_join("07", _repeat_byte("FF", 32)),
        ),
        FileExpectation(
            "ADF_USIM/EF_KEYSPS",
            "EF",
            "Transparent",
            size=33,
            sfi="09",
            content_pattern=_hex_join("07", _repeat_byte("FF", 32)),
        ),
        FileExpectation(
            "ADF_USIM/EF_HPPLMN",
            "EF",
            "Transparent",
            size=1,
            sfi="12",
            service_any=(12,),
            content_pattern="0A",
        ),
        FileExpectation("ADF_USIM/EF_UST", "EF", "Transparent", size=17, sfi="04"),
        FileExpectation(
            "ADF_USIM/EF_FDN",
            "EF",
            "Linear Fixed",
            record_length=26,
            record_count=20,
            sfi="08",
            service_any=(2, 89),
            content_pattern=_hex_join(_repeat_byte("FF", 26)),
            pattern_scope="record",
        ),
        FileExpectation(
            "ADF_USIM/EF_SMS",
            "EF",
            "Linear Fixed",
            record_length=176,
            record_count=10,
            sfi="00",
            service_any=(10,),
            content_pattern=_hex_join("00", _repeat_byte("FF", 175)),
            pattern_scope="record",
        ),
        FileExpectation(
            "ADF_USIM/EF_SMSP",
            "EF",
            "Linear Fixed",
            record_length=38,
            record_count=1,
            service_any=(12,),
            content_pattern=_hex_join(_repeat_byte("FF", 38)),
            pattern_scope="record",
        ),
        FileExpectation(
            "ADF_USIM/EF_SMSS",
            "EF",
            "Transparent",
            size=2,
            service_any=(10,),
            content_pattern="FFFF",
        ),
        FileExpectation("ADF_USIM/EF_SPN", "EF", "Transparent", size=17, sfi="10", service_any=(19,)),
        FileExpectation("ADF_USIM/EF_EST", "EF", "Transparent", size=1, sfi="05", service_any=(2, 6, 34, 35)),
        FileExpectation(
            "ADF_USIM/EF_START_HFN",
            "EF",
            "Transparent",
            size=6,
            sfi="0F",
            content_pattern="F00000F00000",
        ),
        FileExpectation(
            "ADF_USIM/EF_THRESHOLD",
            "EF",
            "Transparent",
            size=3,
            sfi="10",
            content_pattern="FFFFFF",
        ),
        FileExpectation(
            "ADF_USIM/EF_PSLOCI",
            "EF",
            "Transparent",
            size=14,
            sfi="0C",
            content_pattern="FFFFFFFFFFFFFFFFFFFF0000FF01",
        ),
        FileExpectation("ADF_USIM/EF_ACC", "EF", "Transparent", size=2, sfi="06"),
        FileExpectation(
            "ADF_USIM/EF_FPLMN",
            "EF",
            "Transparent",
            size=12,
            sfi="0D",
            content_pattern=_repeat_byte("FF", 12),
        ),
        FileExpectation(
            "ADF_USIM/EF_LOCI",
            "EF",
            "Transparent",
            size=11,
            sfi="0B",
            content_pattern="FFFFFFFFFFFFFF0000FF01",
        ),
        FileExpectation("ADF_USIM/EF_AD", "EF", "Transparent", size=4, sfi="03"),
        FileExpectation("ADF_USIM/EF_ECC", "EF", "Linear Fixed", record_length=4, record_count=1, sfi="01"),
        FileExpectation(
            "ADF_USIM/EF_NETPAR",
            "EF",
            "Transparent",
            size=128,
            content_pattern=_repeat_byte("FF", 128),
        ),
        FileExpectation(
            "ADF_USIM/EF_EPSLOCI",
            "EF",
            "Transparent",
            size=18,
            sfi="1E",
            service_any=(85,),
            content_pattern="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000001",
        ),
        FileExpectation(
            "ADF_USIM/EF_EPSNSC",
            "EF",
            "Linear Fixed",
            record_length=80,
            record_count=1,
            sfi="18",
            service_any=(85,),
            content_pattern=_repeat_byte("FF", 80),
            pattern_scope="record",
        ),
    )

    USIM_GSM_ACCESS_EXPECTATIONS: Tuple[FileExpectation, ...] = (
        FileExpectation("ADF_USIM/GSM_ACCESS", "DF", "Tree", required=False, require_security=False),
        FileExpectation(
            "ADF_USIM/GSM_ACCESS/EF_KC",
            "EF",
            "Transparent",
            size=9,
            sfi="01",
            required=False,
            content_pattern="FFFFFFFFFFFFFFFF07",
            content_mismatch_severity="FAIL",
        ),
        FileExpectation(
            "ADF_USIM/GSM_ACCESS/EF_KCGPRS",
            "EF",
            "Transparent",
            size=9,
            sfi="02",
            required=False,
            content_pattern="FFFFFFFFFFFFFFFF07",
            content_mismatch_severity="FAIL",
        ),
        FileExpectation(
            "ADF_USIM/GSM_ACCESS/EF_INVSCAN",
            "EF",
            "Transparent",
            size=1,
            required=False,
            content_pattern="00",
        ),
    )

    USIM_5GS_EXPECTATIONS: Tuple[FileExpectation, ...] = (
        FileExpectation("ADF_USIM/5GS", "DF", "Tree", required=False, require_security=False),
        FileExpectation(
            "ADF_USIM/5GS/EF_5GS3GPPLOCI",
            "EF",
            "Transparent",
            size=20,
            sfi="01",
            required=False,
            content_pattern="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001",
        ),
        FileExpectation(
            "ADF_USIM/5GS/EF_5GSN3GPPLOCI",
            "EF",
            "Transparent",
            size=20,
            sfi="02",
            required=False,
            content_pattern="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001",
        ),
        FileExpectation(
            "ADF_USIM/5GS/EF_5GS3GPPNSC",
            "EF",
            "Linear Fixed",
            record_length=62,
            record_count=2,
            sfi="03",
            required=False,
            content_pattern=_repeat_byte("FF", 62),
            pattern_scope="record",
        ),
        FileExpectation(
            "ADF_USIM/5GS/EF_5GSN3GPPNSC",
            "EF",
            "Linear Fixed",
            record_length=62,
            record_count=2,
            sfi="04",
            required=False,
            content_pattern=_repeat_byte("FF", 62),
            pattern_scope="record",
        ),
        FileExpectation(
            "ADF_USIM/5GS/EF_5GAUTHKEYS",
            "EF",
            "Transparent",
            size=110,
            sfi="05",
            required=False,
            content_pattern=_repeat_byte("FF", 110),
        ),
    )

    ISIM_EXPECTATIONS: Tuple[FileExpectation, ...] = (
        FileExpectation("ADF_ISIM", "DF", "Tree", required=True, require_security=False),
        FileExpectation("ADF_ISIM/EF_IMPI", "EF", "Transparent", sfi="02"),
        FileExpectation("ADF_ISIM/EF_IMPU", "EF", "Linear Fixed", record_count=1, sfi="04"),
        FileExpectation("ADF_ISIM/EF_DOMAIN", "EF", "Transparent", sfi="05"),
        FileExpectation("ADF_ISIM/EF_IST", "EF", "Transparent", size=14, sfi="07"),
        FileExpectation(
            "ADF_ISIM/EF_AD",
            "EF",
            "Transparent",
            size=3,
            sfi="03",
            content_pattern="000000",
        ),
        FileExpectation("ADF_ISIM/EF_ARR", "EF", "Linear Fixed", sfi="06", require_security=False),
    )

    ISIM_OPTIONAL_EXPECTATIONS: Tuple[FileExpectation, ...] = (
        FileExpectation(
            "ADF_ISIM/EF_SMSS",
            "EF",
            "Transparent",
            size=2,
            required=False,
            content_pattern="FFFF",
        ),
        FileExpectation(
            "ADF_ISIM/EF_GBABP",
            "EF",
            "Transparent",
            required=False,
        ),
        FileExpectation(
            "ADF_ISIM/EF_GBANL",
            "EF",
            "Linear Fixed",
            required=False,
        ),
        FileExpectation(
            "ADF_ISIM/EF_NAFKCA",
            "EF",
            "Linear Fixed",
            required=False,
        ),
        FileExpectation(
            "ADF_ISIM/EF_FROMPREFERRED",
            "EF",
            "Transparent",
            size=1,
            required=False,
            content_pattern="00",
        ),
    )

    def __init__(self, fs_controller, profile_metadata: Optional[dict] = None):
        self.fs = fs_controller
        self.findings: List[ValidationFinding] = []
        self.profile_metadata = dict(profile_metadata) if isinstance(profile_metadata, dict) else {}

    def run(self, scope: str = "ALL") -> List[ValidationFinding]:
        requested_scope = scope.strip().upper()
        restore_target = self._get_restore_target()
        self.findings = []

        if requested_scope == "":
            requested_scope = "ALL"

        self._print_intro(requested_scope)

        try:
            if requested_scope in ("ALL", "MF", "USIM", "ISIM"):
                self._validate_group("MF Core", self.MF_EXPECTATIONS)

            if requested_scope in ("ALL", "USIM"):
                self._validate_usim_scope()

            if requested_scope in ("ALL", "ISIM"):
                self._validate_isim_scope()

            if requested_scope not in ("ALL", "MF", "USIM", "ISIM"):
                self._add_finding(
                    "FAIL",
                    requested_scope,
                    "Unsupported scope. Use VALIDATE, VALIDATE USIM, VALIDATE ISIM, or VALIDATE MF.",
                )
        finally:
            self._restore_selection(restore_target)

        self._print_summary()
        return self.findings

    def _print_intro(self, scope: str) -> None:
        print(f"\n{Config.Colors.HEADER}=== PROFILE VALIDATION ==={Config.Colors.ENDC}")
        print(f"{Config.Colors.CYAN}[*] Scope: {scope}{Config.Colors.ENDC}")
        print(
            f"{Config.Colors.CYAN}[*] Missing or wrong mandatory files/FCP are failures. "
            f"SFI and length mismatches are warnings. Fixed-value content mismatches may be hard failures.{Config.Colors.ENDC}"
        )

    def _validate_usim_scope(self) -> None:
        has_usim = self._path_exists("ADF_USIM")
        if has_usim is False:
            if self._is_service_mandated("usim"):
                self._add_finding("FAIL", "ADF_USIM", "USIM application not found, but profile metadata marks it as mandatory.")
            else:
                self._add_finding("WARN", "ADF_USIM", "USIM application not found.")
            return

        ust_bits = self._read_service_bits("ADF_USIM/EF_UST")
        self._validate_group("ADF USIM", self.USIM_EXPECTATIONS, service_bits=ust_bits)

        has_gsm_access = self._path_exists("ADF_USIM/GSM_ACCESS")
        if has_gsm_access:
            self._validate_group(
                "ADF USIM / DF GSM-ACCESS",
                self.USIM_GSM_ACCESS_EXPECTATIONS,
            )

        has_df_5gs = self._path_exists("ADF_USIM/5GS")
        if has_df_5gs:
            self._validate_group(
                "ADF USIM / DF 5GS",
                self.USIM_5GS_EXPECTATIONS,
            )

    def _validate_isim_scope(self) -> None:
        has_isim = self._path_exists("ADF_ISIM")
        if has_isim is False:
            if self._is_service_mandated("isim"):
                self._add_finding("FAIL", "ADF_ISIM", "ISIM application not found, but profile metadata marks it as mandatory.")
            else:
                self._add_finding("WARN", "ADF_ISIM", "ISIM application not found; skipped because it is optional unless mandated by profile metadata.")
            return

        self._validate_group("ADF ISIM", self.ISIM_EXPECTATIONS)
        self._validate_group(
            "ADF ISIM Optional Files",
            self.ISIM_OPTIONAL_EXPECTATIONS,
        )

    def _validate_group(
        self,
        title: str,
        expectations: Sequence[FileExpectation],
        service_bits: Optional[Sequence[int]] = None,
    ) -> None:
        print(f"\n{Config.Colors.BOLD}{title}{Config.Colors.ENDC}")

        for expectation in expectations:
            if self._is_expectation_applicable(expectation, service_bits) is False:
                continue

            self._validate_expectation(expectation)

    def _is_expectation_applicable(
        self,
        expectation: FileExpectation,
        service_bits: Optional[Sequence[int]],
    ) -> bool:
        if len(expectation.service_any) == 0:
            return True

        if service_bits is None:
            return True

        for service_number in expectation.service_any:
            if self._service_is_available(service_bits, service_number):
                return True

        return False

    def _validate_expectation(self, expectation: FileExpectation) -> None:
        selected = self.fs.select(expectation.path, silent=True)
        if selected is False:
            if expectation.required:
                self._add_finding("FAIL", expectation.path, "Required file is missing.")
            return

        meta = dict(self.fs.current_fcp)
        fail_errors: List[str] = []
        warn_errors: List[str] = []

        actual_type = str(meta.get("type", "Unknown"))
        if actual_type != expectation.expected_type:
            fail_errors.append(f"type={actual_type}, expected={expectation.expected_type}")

        actual_structure = str(meta.get("structure", "Unknown"))
        if actual_structure != expectation.expected_structure:
            fail_errors.append(
                f"structure={actual_structure}, expected={expectation.expected_structure}"
            )

        if expectation.size is not None:
            actual_size = meta.get("size")
            if actual_size != expectation.size:
                warn_errors.append(f"size={actual_size}, expected={expectation.size}")

        if expectation.record_length is not None:
            actual_record_length = meta.get("rec_len")
            if actual_record_length != expectation.record_length:
                warn_errors.append(
                    f"record_length={actual_record_length}, expected={expectation.record_length}"
                )

        if expectation.record_count is not None:
            actual_record_count = meta.get("rec_count")
            if actual_record_count != expectation.record_count:
                warn_errors.append(
                    f"record_count={actual_record_count}, expected={expectation.record_count}"
                )

        if expectation.sfi is not None:
            actual_sfi = meta.get("sfi")
            if actual_sfi != expectation.sfi:
                warn_errors.append(f"sfi={actual_sfi}, expected={expectation.sfi}")

        if expectation.require_lcs:
            lcs_value = meta.get("lcs")
            if lcs_value in (None, "", "Unknown"):
                fail_errors.append("lifecycle-status tag missing")

        if expectation.require_security:
            security_value = meta.get("security")
            if security_value in (None, "", "None"):
                fail_errors.append("security-attributes tag missing")

        if len(fail_errors) > 0:
            self._add_finding("FAIL", expectation.path, "; ".join(fail_errors))
            return

        if len(warn_errors) > 0:
            self._add_finding("WARN", expectation.path, "; ".join(warn_errors))
        else:
            self._add_finding("PASS", expectation.path, "FCP matches expected structure.")

        if expectation.content_pattern is not None:
            self._validate_content_pattern(expectation)

    def _validate_content_pattern(self, expectation: FileExpectation) -> None:
        if expectation.pattern_scope == "record":
            records = self._read_record_hex()
            if records is None:
                self._add_finding("FAIL", expectation.path, "Could not read records for validation.")
                return

            record_index = 1
            for record_hex in records:
                if record_hex != expectation.content_pattern:
                    self._add_finding(
                        expectation.content_mismatch_severity,
                        expectation.path,
                        f"record {record_index} differs from required/default pattern.",
                    )
                    return
                record_index += 1

            self._add_finding("PASS", expectation.path, "Reset/default record pattern matches.")
            return

        file_hex = self._read_binary_hex()
        if file_hex is None:
            self._add_finding("FAIL", expectation.path, "Could not read file content for validation.")
            return

        if file_hex != expectation.content_pattern:
            self._add_finding(
                expectation.content_mismatch_severity,
                expectation.path,
                "content differs from required/default pattern.",
            )
            return

        self._add_finding("PASS", expectation.path, "Reset/default content matches.")

    def _read_binary_hex(self) -> Optional[str]:
        data, sw1, sw2 = self.fs.tp.transmit("00B0000000", silent=True)
        if sw1 != 0x90:
            return None
        return data.hex().upper()

    def _read_record_hex(self) -> Optional[List[str]]:
        meta = self.fs.current_fcp
        record_length = meta.get("rec_len", 0)
        record_count = meta.get("rec_count", 0)
        if record_length <= 0:
            return None

        if record_count <= 0:
            return None

        le = f"{record_length:02X}"
        records: List[str] = []
        record_number = 1
        while record_number <= record_count:
            cmd = f"00B2{record_number:02X}04{le}"
            data, sw1, sw2 = self.fs.tp.transmit(cmd, silent=True)
            if sw1 != 0x90:
                return None
            records.append(data.hex().upper())
            record_number += 1
        return records

    def _read_service_bits(self, path: str) -> Optional[List[int]]:
        selected = self.fs.select(path, silent=True)
        if selected is False:
            return None

        hex_data = self._read_binary_hex()
        if hex_data is None:
            return None

        raw_bytes = bytes.fromhex(hex_data)
        return list(raw_bytes)

    def _service_is_available(
        self,
        service_bits: Sequence[int],
        service_number: int,
    ) -> bool:
        if service_number <= 0:
            return False

        byte_index = (service_number - 1) // 8
        bit_index = (service_number - 1) % 8

        if byte_index >= len(service_bits):
            return False

        value = service_bits[byte_index]
        mask = 1 << bit_index
        return (value & mask) != 0

    def _metadata_header(self) -> dict[str, Any]:
        sections = self.profile_metadata.get("sections", {})
        if isinstance(sections, dict) is False:
            return {}
        header = sections.get("header", {})
        if isinstance(header, dict) is False:
            return {}
        return header

    def _is_service_mandated(self, service_name: str) -> bool:
        header = self._metadata_header()
        mandatory_services = header.get("eUICC-Mandatory-services", {})
        if isinstance(mandatory_services, dict) is False:
            return False

        raw_value = mandatory_services.get(service_name)
        if raw_value is None:
            return service_name in mandatory_services
        if isinstance(raw_value, bool):
            return raw_value
        if isinstance(raw_value, str):
            return raw_value.strip().lower() in ("1", "true", "yes", "present")
        if isinstance(raw_value, int):
            return raw_value != 0
        return bool(raw_value)

    @classmethod
    def load_profile_metadata(cls, metadata_path: str) -> dict:
        resolved_path = Path(metadata_path).expanduser().resolve()
        suffix = resolved_path.suffix.lower()
        raw_text = resolved_path.read_text(encoding="utf-8")
        if suffix == ".json":
            loaded = json.loads(raw_text)
        else:
            loaded = yaml.safe_load(raw_text)
        if isinstance(loaded, dict) is False:
            raise ValueError("Profile metadata document must decode to a dictionary.")
        return loaded

    def _path_exists(self, path: str) -> bool:
        return self.fs.select(path, silent=True)

    def _get_restore_target(self) -> str:
        current_path = str(getattr(self.fs, "current_path_hint", "")).strip()
        if current_path != "":
            return current_path

        current_fid = getattr(self.fs, "current_fid", None)
        if current_fid is None:
            return "MF"

        return str(current_fid)

    def _restore_selection(self, restore_target: str) -> None:
        if restore_target == "":
            return

        restored = self.fs.select(restore_target, silent=True)
        if restored is False:
            self.fs.select("MF", silent=True)

    def _add_finding(self, severity: str, path: str, message: str) -> None:
        finding = ValidationFinding(severity=severity, path=path, message=message)
        self.findings.append(finding)

        color = Config.Colors.CYAN
        if severity == "PASS":
            color = Config.Colors.GREEN
        if severity == "WARN":
            color = Config.Colors.WARNING
        if severity == "FAIL":
            color = Config.Colors.FAIL

        print(f"{color}[{severity}]{Config.Colors.ENDC} {path} - {message}")

    def _print_summary(self) -> None:
        pass_count = 0
        warn_count = 0
        fail_count = 0

        for finding in self.findings:
            if finding.severity == "PASS":
                pass_count += 1
            if finding.severity == "WARN":
                warn_count += 1
            if finding.severity == "FAIL":
                fail_count += 1

        print(f"\n{Config.Colors.HEADER}=== VALIDATION SUMMARY ==={Config.Colors.ENDC}")
        print(f"{Config.Colors.GREEN}PASS{Config.Colors.ENDC}: {pass_count}")
        print(f"{Config.Colors.WARNING}WARN{Config.Colors.ENDC}: {warn_count}")
        print(f"{Config.Colors.FAIL}FAIL{Config.Colors.ENDC}: {fail_count}")

