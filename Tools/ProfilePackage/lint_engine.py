import re
from dataclasses import asdict, dataclass
from typing import Any, Optional

# Lint finding ``code`` values use the project-native ``YRL-*`` scheme; see ``lint_rule_ids``.

@dataclass
class FileDefinition:
    section_key: str
    field_path: str
    payload: dict[str, Any]
    file_id: Optional[str]
    file_descriptor: Optional[str]
    ef_file_size: Optional[str]
    short_efid: Optional[str]
    link_path: Optional[str]
    maximum_file_size: Optional[str]
    file_details: Optional[str]
    security_attributes_referenced: Optional[str]
    pin_status_template_do: Optional[str]


@dataclass
class LintFinding:
    code: str
    severity: str
    spec: str
    path: str
    message: str
    recommendation: str
    evidence: Any = None


@dataclass
class LintReport:
    profile: str
    strict: bool
    score: int
    summary: dict[str, int]
    findings: list[LintFinding]
    metadata_path: Optional[str] = None
    gate: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "strict": self.strict,
            "score": self.score,
            "summary": dict(self.summary),
            "metadata_path": self.metadata_path,
            "gate": self.gate,
            "findings": [asdict(item) for item in self.findings],
        }


class SaipProfileLinter:
    _TYPE_SUFFIX_RE = re.compile(r"_(\d+)$")
    _HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
    _SHORT_EFID_RESERVED_LOW_BITS_MASK = 0x07

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict
        self.findings: list[LintFinding] = []
        # Populated when ``lint_decoded_document`` is called with
        # ``placeholder_paths``; used by ``_add`` to skip lint findings that
        # originate from template-placeholder-bearing fields.
        self._placeholder_paths: frozenset[str] = frozenset()
        self._undefined_tokens: frozenset[str] = frozenset()

    def lint_decoded_document(
        self,
        decoded_document: dict[str, Any],
        profile_label: str,
        check_return_code: Optional[int] = None,
        check_stderr: str = "",
        metadata: Optional[dict[str, Any]] = None,
        metadata_path: Optional[str] = None,
        emit_missing_check_finding: bool = True,
        placeholder_paths: Optional[frozenset[str]] = None,
        undefined_tokens: Optional[frozenset[str]] = None,
    ) -> LintReport:
        self.findings = []
        self._placeholder_paths = frozenset(
            str(path).strip() for path in (placeholder_paths or frozenset()) if str(path).strip()
        )
        self._undefined_tokens = frozenset(
            str(name).strip() for name in (undefined_tokens or frozenset()) if str(name).strip()
        )
        sections = self._extract_sections(decoded_document)
        ordered_types = [self._base_type_from_key(key) for key in sections.keys()]
        section_items = list(sections.items())
        file_definitions = self._extract_file_definitions(section_items)

        self._emit_template_mode_banner()
        self._check_parser_health(section_items)
        self._check_base_structure(ordered_types)
        self._check_singleton_types(ordered_types)
        self._check_pe_dependency_order(ordered_types)
        self._check_mandatory_services(sections)
        self._check_iccid(sections)
        self._check_profile_header_core_fields(sections)
        self._check_identification_uniqueness(section_items)
        self._check_security_domain_integrity(sections)
        self._check_application_integrity(sections)
        self._check_fs_core_constraints(file_definitions)
        self._check_ber_tlv_constraints(section_items, file_definitions)
        self._check_hex_fields(section_items)
        self._check_apdu_like_fields(section_items)
        self._check_5gs_dependencies(ordered_types)
        self._check_usim_core_expectations(sections)
        self._check_service_to_file_mappings(section_items)
        self._check_metadata_alignment(sections, metadata)
        self._check_saip_tool_check_result(
            check_return_code,
            check_stderr,
            emit_missing_check_finding=emit_missing_check_finding,
        )
        self._apply_strict_policy()

        summary = self._build_summary()
        score = self._compute_score(summary)
        return LintReport(
            profile=profile_label,
            strict=self.strict,
            score=score,
            summary=summary,
            findings=list(self.findings),
            metadata_path=metadata_path,
        )

    def evaluate_gate(
        self,
        report: LintReport,
        min_score: Optional[int] = None,
        fail_on_warn: bool = False,
        fail_prefixes: Optional[list[str]] = None,
        fail_codes: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        thresholds: dict[str, Any] = {
            "min_score": min_score,
            "fail_on_warn": fail_on_warn,
            "fail_prefixes": list(fail_prefixes or []),
            "fail_codes": list(fail_codes or []),
        }

        triggers: list[dict[str, Any]] = []
        if min_score is not None:
            if int(report.score) < int(min_score):
                triggers.append(
                    {
                        "type": "min_score",
                        "actual_score": int(report.score),
                        "required_min_score": int(min_score),
                    }
                )

        prefixes_upper = [item.strip().upper() for item in (fail_prefixes or []) if item.strip() != ""]
        fail_codes_upper = [item.strip().upper() for item in (fail_codes or []) if item.strip() != ""]
        for finding in report.findings:
            finding_code = str(finding.code).strip().upper()
            severity = str(finding.severity).strip().upper()

            if severity == "FAIL":
                if len(prefixes_upper) == 0 and len(fail_codes_upper) == 0:
                    triggers.append(
                        {
                            "type": "fail",
                            "code": finding.code,
                            "path": finding.path,
                            "message": finding.message,
                        }
                    )
                    continue

                matched_prefix = False
                for prefix in prefixes_upper:
                    if finding_code.startswith(prefix):
                        matched_prefix = True
                        break
                matched_code = finding_code in fail_codes_upper
                if matched_prefix or matched_code:
                    triggers.append(
                        {
                            "type": "fail",
                            "code": finding.code,
                            "path": finding.path,
                            "message": finding.message,
                        }
                    )
                continue

            if fail_on_warn and severity == "WARN":
                if len(prefixes_upper) == 0 and len(fail_codes_upper) == 0:
                    triggers.append(
                        {
                            "type": "warn",
                            "code": finding.code,
                            "path": finding.path,
                            "message": finding.message,
                        }
                    )
                    continue
                matched_prefix = False
                for prefix in prefixes_upper:
                    if finding_code.startswith(prefix):
                        matched_prefix = True
                        break
                matched_code = finding_code in fail_codes_upper
                if matched_prefix or matched_code:
                    triggers.append(
                        {
                            "type": "warn",
                            "code": finding.code,
                            "path": finding.path,
                            "message": finding.message,
                        }
                    )

        passed = len(triggers) == 0
        gate_result = {
            "passed": passed,
            "thresholds": thresholds,
            "trigger_count": len(triggers),
            "triggers": triggers[:200],
        }
        report.gate = gate_result
        return gate_result

    @staticmethod
    def _extract_sections(decoded_document: dict[str, Any]) -> dict[str, Any]:
        if isinstance(decoded_document, dict) is False:
            return {}
        sections = decoded_document.get("sections", {})
        if isinstance(sections, dict) is False:
            return {}
        return sections

    def _base_type_from_key(self, key_text: str) -> str:
        cleaned = str(key_text).strip()
        if cleaned == "":
            return ""
        matched = self._TYPE_SUFFIX_RE.search(cleaned)
        if matched is None:
            return cleaned
        return cleaned[: matched.start()]

    def _path_has_placeholder(self, path: str) -> bool:
        if len(self._placeholder_paths) == 0:
            return False
        normalized = str(path or "").strip()
        if len(normalized) == 0:
            return False
        for placeholder_path in self._placeholder_paths:
            if normalized == placeholder_path:
                return True
            if normalized.startswith(placeholder_path + "."):
                return True
            if normalized.startswith(placeholder_path + "["):
                return True
        return False

    def _add(
        self,
        code: str,
        severity: str,
        spec: str,
        path: str,
        message: str,
        recommendation: str,
        evidence: Any = None,
    ) -> None:
        normalized_severity = str(severity or "").strip().upper()
        if (
            normalized_severity in {"FAIL", "WARN"}
            and self._path_has_placeholder(path)
        ):
            severity = "INFO"
            message = (
                f"Template placeholder present at {path}; skipping {code} "
                f"({normalized_severity}). Original message: {message}"
            )
            recommendation = (
                "Resolve the placeholder via APPLY-TEMPLATE or populate "
                "__ygg_token_defs__ to re-enable strict validation."
            )
            code = f"{code}/TEMPLATE"
        self.findings.append(
            LintFinding(
                code=code,
                severity=severity,
                spec=spec,
                path=path,
                message=message,
                recommendation=recommendation,
                evidence=evidence,
            )
        )

    def _emit_template_mode_banner(self) -> None:
        if len(self._placeholder_paths) == 0 and len(self._undefined_tokens) == 0:
            return
        token_summary = "none"
        if len(self._undefined_tokens) > 0:
            token_summary = ", ".join(sorted(self._undefined_tokens))
        path_summary = "none"
        if len(self._placeholder_paths) > 0:
            path_summary = ", ".join(sorted(self._placeholder_paths))

        recommendation_lines = [
            "Resolve placeholders before shipping this profile. Typical flow:",
            "  1. If an accompanying sidecar exists, merge it back:",
            "       APPLY-TOKENS <template.json> <template.tokens.json>",
            "  2. Materialise into a DER build:",
            "       APPLY-TEMPLATE <template.json> <out.der> "
            "[ICCID=<digits|AUTO>] [IMSI=<digits|AUTO>] [VERIFY]",
            "  3. Or batch-generate one DER per data record:",
            "       GENERATE-BATCH <template.json> <data_file> <out_dir>",
        ]
        if len(self._undefined_tokens) > 0:
            recommendation_lines.insert(
                1,
                "     Unresolved token names: " + token_summary + ".",
            )

        self._add(
            code="YRL-TPL-OK",
            severity="INFO",
            spec="Template authoring",
            path="sections",
            message=(
                "Profile parsed in template mode — placeholder fields are "
                "excluded from strict hex/ICCID validation."
            ),
            recommendation="\n".join(recommendation_lines),
            evidence={
                "undefined_tokens": sorted(self._undefined_tokens),
                "placeholder_paths": sorted(self._placeholder_paths),
                "token_summary": token_summary,
                "path_summary": path_summary,
                "resolving_commands": [
                    "APPLY-TOKENS <template.json> <template.tokens.json>",
                    "APPLY-TEMPLATE <template.json> <out.der>",
                    "GENERATE-BATCH <template.json> <data_file> <out_dir>",
                ],
            },
        )

    def _check_parser_health(self, section_items: list[tuple[str, Any]]) -> None:
        if len(section_items) == 0:
            self._add(
                code="YRL-DOC-001",
                severity="FAIL",
                spec="TS.48",
                path="sections",
                message="No decoded Profile Elements were found.",
                recommendation="Confirm the profile DER payload and ASN.1 compatibility, then retry.",
            )
            return
        self._add(
            code="YRL-DOC-OK",
            severity="PASS",
            spec="TS.48",
            path="sections",
            message=(
                f"Decoded {len(section_items)} Profile Elements "
                f"(first='{section_items[0][0]}', last='{section_items[-1][0]}')."
            ),
            recommendation="None.",
            evidence={
                "decoded_pe_count": len(section_items),
                "first_pe_key": section_items[0][0],
                "last_pe_key": section_items[-1][0],
            },
        )

    def _check_base_structure(self, ordered_types: list[str]) -> None:
        if len(ordered_types) < 3:
            self._add(
                code="YRL-SEQ-001",
                severity="FAIL",
                spec="TS.48 / SAIP",
                path="PE-order",
                message="Profile contains fewer than three PEs; expected header/mf/end minimum.",
                recommendation="Regenerate package with mandatory PEs present.",
                evidence={"ordered_types": ordered_types},
            )
            return

        first_type = ordered_types[0]
        second_type = ordered_types[1]
        last_type = ordered_types[-1]

        if first_type != "header":
            self._add(
                code="YRL-SEQ-002",
                severity="FAIL",
                spec="TS.48 / SAIP",
                path="PE-order",
                message=f"First PE is '{first_type}', expected 'header'.",
                recommendation="Place Profile Header as first PE.",
            )
        else:
            self._add(
                code="YRL-SEQ-OK-HDR",
                severity="PASS",
                spec="TS.48 / SAIP",
                path="PE-order",
                message="First PE is header (position 1/sequence start).",
                recommendation="None.",
                evidence={"first_pe": first_type},
            )

        if second_type != "mf":
            self._add(
                code="YRL-SEQ-003",
                severity="FAIL",
                spec="TS.48 / SAIP",
                path="PE-order",
                message=f"Second PE is '{second_type}', expected 'mf'.",
                recommendation="Keep MF PE as second element for interoperable profile structure.",
            )
        else:
            self._add(
                code="YRL-SEQ-OK-MF",
                severity="PASS",
                spec="TS.48 / SAIP",
                path="PE-order",
                message="Second PE is mf (position 2; immediately after header).",
                recommendation="None.",
                evidence={"second_pe": second_type},
            )

        if last_type != "end":
            self._add(
                code="YRL-SEQ-004",
                severity="FAIL",
                spec="TS.48 / SAIP",
                path="PE-order",
                message=f"Last PE is '{last_type}', expected 'end'.",
                recommendation="Ensure End PE is present at the end of the sequence.",
            )
        else:
            self._add(
                code="YRL-SEQ-OK-END",
                severity="PASS",
                spec="TS.48 / SAIP",
                path="PE-order",
                message=f"Last PE is end (position {len(ordered_types)}).",
                recommendation="None.",
                evidence={"last_pe": last_type, "pe_count": len(ordered_types)},
            )

    def _check_singleton_types(self, ordered_types: list[str]) -> None:
        singleton_types = ("header", "mf", "end", "usim", "isim", "csim", "df-5gs", "df-saip")
        for item_type in singleton_types:
            count = ordered_types.count(item_type)
            if count > 1:
                self._add(
                    code="YRL-SEQ-010",
                    severity="FAIL",
                    spec="TS.48 / SAIP",
                    path=f"PE-type:{item_type}",
                    message=f"Type '{item_type}' occurs {count} times; expected at most one.",
                    recommendation=f"Keep a single '{item_type}' PE instance.",
                )

    def _check_pe_dependency_order(self, ordered_types: list[str]) -> None:
        index_map: dict[str, list[int]] = {}
        for index, item_type in enumerate(ordered_types):
            if item_type not in index_map:
                index_map[item_type] = []
            index_map[item_type].append(index)

        self._check_dependency_after(index_map, "opt-usim", "usim", "YRL-DEP-OPTUSIM-001")
        self._check_dependency_after(index_map, "opt-isim", "isim", "YRL-DEP-OPTISIM-001")
        self._check_dependency_after(index_map, "gsm-access", "usim", "YRL-DEP-GSM-001")
        self._check_dependency_after(index_map, "phonebook", "usim", "YRL-DEP-PBOOK-001")
        self._check_dependency_after(index_map, "df-5gs", "usim", "YRL-DEP-5GS-001")
        self._check_dependency_after(index_map, "df-saip", "usim", "YRL-DEP-SAIP-001")

    def _check_dependency_after(
        self,
        index_map: dict[str, list[int]],
        dependent: str,
        required: str,
        code: str,
    ) -> None:
        dependent_indexes = index_map.get(dependent, [])
        if len(dependent_indexes) == 0:
            return
        required_indexes = index_map.get(required, [])
        if len(required_indexes) == 0:
            self._add(
                code=code,
                severity="FAIL",
                spec="TS.48 / SAIP",
                path=f"dependency:{dependent}",
                message=f"PE-{dependent.upper()} is present but PE-{required.upper()} is missing.",
                recommendation=f"Add PE-{required.upper()} before PE-{dependent.upper()}.",
            )
            return
        first_required = required_indexes[0]
        first_dependent = dependent_indexes[0]
        if first_dependent > first_required:
            return
        self._add(
            code=code,
            severity="FAIL",
            spec="TS.48 / SAIP",
            path=f"dependency:{dependent}",
            message=f"PE-{dependent.upper()} appears before PE-{required.upper()}.",
            recommendation=f"Move PE-{dependent.upper()} after PE-{required.upper()}.",
        )

    def _check_mandatory_services(self, sections: dict[str, Any]) -> None:
        header = self._first_section_by_type(sections, "header")
        if isinstance(header, dict) is False:
            return
        mandatory_services = header.get("eUICC-Mandatory-services")
        if isinstance(mandatory_services, dict) is False:
            self._add(
                code="YRL-SVC-001",
                severity="WARN",
                spec="SGP.22 / SGP.32",
                path="header.eUICC-Mandatory-services",
                message="Mandatory services list not found in header.",
                recommendation="Include mandatory services in profile header.",
            )
            return

        enabled_services: set[str] = set()
        for service_name, raw_value in mandatory_services.items():
            if raw_value is None:
                enabled_services.add(str(service_name))
                continue
            if isinstance(raw_value, bool):
                if raw_value:
                    enabled_services.add(str(service_name))
                continue
            if isinstance(raw_value, int):
                if raw_value != 0:
                    enabled_services.add(str(service_name))
                continue
            if isinstance(raw_value, str):
                normalized = raw_value.strip().lower()
                if normalized in ("1", "true", "yes", "present"):
                    enabled_services.add(str(service_name))
                continue
            if raw_value:
                enabled_services.add(str(service_name))

        types = [self._base_type_from_key(key) for key in sections.keys()]
        has_usim = "usim" in types
        has_isim = "isim" in types
        has_csim = "csim" in types

        self._validate_enabled_service_dependency(
            enabled_services,
            service_name="usim",
            present=has_usim,
            required_type="usim",
        )
        self._validate_enabled_service_dependency(
            enabled_services,
            service_name="isim",
            present=has_isim,
            required_type="isim",
        )
        self._validate_enabled_service_dependency(
            enabled_services,
            service_name="csim",
            present=has_csim,
            required_type="csim",
        )

        if "get-identity" in enabled_services:
            if has_usim is False and has_isim is False:
                self._add(
                    code="YRL-SVC-010",
                    severity="FAIL",
                    spec="SGP.22 / SGP.32",
                    path="header.eUICC-Mandatory-services",
                    message="'get-identity' is set but neither USIM nor ISIM PE exists.",
                    recommendation="Add USIM or ISIM PE when get-identity is mandatory.",
                )

        if "profile-a-x25519" in enabled_services:
            if has_usim is False and has_isim is False:
                self._add(
                    code="YRL-SVC-011",
                    severity="FAIL",
                    spec="SGP.32",
                    path="header.eUICC-Mandatory-services",
                    message="'profile-a-x25519' is set without USIM/ISIM PE.",
                    recommendation="Keep profile-a-x25519 only with corresponding USIM/ISIM support.",
                )

        if "profile-a-p256" in enabled_services:
            if has_usim is False and has_isim is False:
                self._add(
                    code="YRL-SVC-012",
                    severity="FAIL",
                    spec="SGP.32",
                    path="header.eUICC-Mandatory-services",
                    message="'profile-a-p256' is set without USIM/ISIM PE.",
                    recommendation="Keep profile-a-p256 only with corresponding USIM/ISIM support.",
                )

    def _validate_enabled_service_dependency(
        self,
        enabled_services: set[str],
        service_name: str,
        present: bool,
        required_type: str,
    ) -> None:
        if service_name not in enabled_services:
            return
        if present:
            self._add(
                code=f"YRL-SVC-OK-{service_name.upper()}",
                severity="PASS",
                spec="SGP.22 / SGP.32",
                path=f"service:{service_name}",
                message=f"Mandatory service '{service_name}' has PE-{required_type.upper()} present.",
                recommendation="None.",
            )
            return
        self._add(
            code=f"YRL-SVC-MIS-{service_name.upper()}",
            severity="FAIL",
            spec="SGP.22 / SGP.32",
            path=f"service:{service_name}",
            message=f"Mandatory service '{service_name}' is enabled but PE-{required_type.upper()} is missing.",
            recommendation=f"Add PE-{required_type.upper()} or remove the mandatory service flag.",
        )

    def _check_iccid(self, sections: dict[str, Any]) -> None:
        header = self._first_section_by_type(sections, "header")
        if isinstance(header, dict) is False:
            return
        iccid_value = header.get("iccid")
        if iccid_value is None:
            self._add(
                code="YRL-ICC-001",
                severity="FAIL",
                spec="ETSI TS 102 221 / TS.48",
                path="header.iccid",
                message="ICCID is missing from profile header.",
                recommendation="Set ICCID in header and keep it consistent with profile metadata.",
            )
            return

        iccid_text = str(iccid_value).strip()
        if len(iccid_text) != 20:
            self._add(
                code="YRL-ICC-002",
                severity="WARN",
                spec="ETSI TS 102 221",
                path="header.iccid",
                message=(
                    f"ICCID length is {len(iccid_text)} nibbles; expected 20 "
                    f"(10 octets BCD)."
                ),
                recommendation="Use 20-nibble ICCID encoding (BCD with filler F when needed).",
                evidence={"iccid": iccid_text},
            )
        if self._looks_like_hex(iccid_text) is False:
            non_hex_chars = sorted({character for character in iccid_text if character not in "0123456789ABCDEFabcdef"})
            self._add(
                code="YRL-ICC-003",
                severity="FAIL",
                spec="ETSI TS 102 221",
                path="header.iccid",
                message=(
                    "ICCID contains non-hex characters; only [0-9A-F] are allowed "
                    "for BCD-coded ICCID."
                ),
                recommendation="Encode ICCID as hex BCD digits only.",
                evidence={"iccid": iccid_text, "non_hex_characters": non_hex_chars},
            )

    def _check_profile_header_core_fields(self, sections: dict[str, Any]) -> None:
        header = self._first_section_by_type(sections, "header")
        if isinstance(header, dict) is False:
            return

        for field_name in ("profileType", "eUICC-Mandatory-services"):
            if field_name in header:
                continue
            self._add(
                code="YRL-HDR-001",
                severity="WARN",
                spec="TS.48 / SAIP",
                path=f"header.{field_name}",
                message=f"Header field '{field_name}' is missing.",
                recommendation="Populate mandatory and interoperability-relevant header fields.",
            )

    def _check_identification_uniqueness(self, section_items: list[tuple[str, Any]]) -> None:
        seen: set[int] = set()
        duplicates: set[int] = set()
        for key_text, payload in section_items:
            values = self._find_key_values(payload, "identification")
            for value in values:
                if isinstance(value, int) is False:
                    continue
                if value in seen:
                    duplicates.add(value)
                seen.add(value)
            if len(values) == 0:
                self._add(
                    code="YRL-PID-001",
                    severity="WARN",
                    spec="TS.48 / SAIP",
                    path=key_text,
                    message=(
                        "No identification field detected in this decoded PE payload; "
                        "decoder export may have dropped PE identification."
                    ),
                    recommendation="Ensure PE header identification fields are retained during decode/export.",
                    evidence={"pe_key": key_text},
                )

        if len(duplicates) > 0:
            self._add(
                code="YRL-PID-002",
                severity="FAIL",
                spec="TS.48 / SAIP",
                path="PE-identification",
                message="Duplicate PE identification values found.",
                recommendation="Use unique PE identification values across sequence.",
                evidence={"duplicates": sorted(duplicates)},
            )

    def _check_security_domain_integrity(self, sections: dict[str, Any]) -> None:
        security_domain_keys = [
            key for key in sections.keys() if self._base_type_from_key(key) == "securityDomain"
        ]
        if len(security_domain_keys) == 0:
            self._add(
                code="YRL-SDM-001",
                severity="WARN",
                spec="GlobalPlatform / TS.48",
                path="securityDomain",
                message="No securityDomain PE found.",
                recommendation="Include securityDomain PE when profile personalization requires SD state or keys.",
            )
            return

        for key_text in security_domain_keys:
            payload = sections.get(key_text, {})
            key_list_values = self._find_key_values(payload, "keyList")
            if len(key_list_values) == 0:
                self._add(
                    code="YRL-SDM-002",
                    severity="WARN",
                    spec="GlobalPlatform",
                    path=key_text,
                    message="securityDomain has no keyList in decoded payload.",
                    recommendation="Review SD key structures and include required key references.",
                )
                continue
            first_key_list = key_list_values[0]
            if isinstance(first_key_list, list) is False:
                self._add(
                    code="YRL-SDM-003",
                    severity="WARN",
                    spec="GlobalPlatform",
                    path=key_text,
                    message="securityDomain keyList exists but is not a list.",
                    recommendation="Encode keyList as a list with valid key entries.",
                )
                continue
            if len(first_key_list) == 0:
                self._add(
                    code="YRL-SDM-004",
                    severity="FAIL",
                    spec="GlobalPlatform",
                    path=key_text,
                    message="securityDomain keyList is empty.",
                    recommendation="Add at least one valid SD key entry.",
                )

    def _check_application_integrity(self, sections: dict[str, Any]) -> None:
        application_keys = [
            key for key in sections.keys() if self._base_type_from_key(key) == "application"
        ]
        if len(application_keys) == 0:
            return

        security_domains = [
            sections.get(key, {})
            for key in sections.keys()
            if self._base_type_from_key(key) == "securityDomain"
        ]
        security_domain_aids = self._extract_security_domain_aids(security_domains)

        load_package_aids: set[str] = set()
        instance_aids: set[str] = set()
        for key_text in application_keys:
            payload = sections.get(key_text, {})
            load_block = None
            if isinstance(payload, dict):
                load_block = payload.get("loadBlock")
            load_aid = None
            if isinstance(load_block, dict):
                candidate = load_block.get("loadPackageAID")
                if candidate is not None:
                    load_aid = str(candidate).strip().upper()

            if load_aid is None:
                self._add(
                    code="YRL-JCA-001",
                    severity="WARN",
                    spec="ETSI TS 102 226 / GP",
                    path=f"{key_text}.loadBlock.loadPackageAID",
                    message="Application PE is missing loadPackageAID.",
                    recommendation="Populate load package AID for each application PE.",
                )
            else:
                if self._looks_like_hex(load_aid) is False:
                    self._add(
                        code="YRL-JCA-002",
                        severity="FAIL",
                        spec="ETSI TS 102 226 / GP",
                        path=f"{key_text}.loadBlock.loadPackageAID",
                        message="loadPackageAID is not hex-encoded.",
                        recommendation="Encode AID as hex bytes.",
                        evidence={"loadPackageAID": load_aid},
                    )
                if load_aid in load_package_aids:
                    self._add(
                        code="YRL-JCA-003",
                        severity="FAIL",
                        spec="ETSI TS 102 226 / GP",
                        path=key_text,
                        message=f"Duplicate loadPackageAID detected: {load_aid}.",
                        recommendation="Keep load package AIDs unique across applications.",
                    )
                load_package_aids.add(load_aid)

            security_domain_aid = None
            if isinstance(load_block, dict):
                security_domain_aid_candidate = load_block.get("securityDomainAID")
                if security_domain_aid_candidate is not None:
                    security_domain_aid = str(security_domain_aid_candidate).strip().upper()
            if security_domain_aid is not None:
                if self._looks_like_hex(security_domain_aid) is False:
                    self._add(
                        code="YRL-JCA-010",
                        severity="FAIL",
                        spec="TS.48 / GlobalPlatform",
                        path=f"{key_text}.loadBlock.securityDomainAID",
                        message="securityDomainAID is not hex-encoded.",
                        recommendation="Encode securityDomainAID as hex bytes.",
                    )
                else:
                    if security_domain_aid not in security_domain_aids:
                        self._add(
                            code="YRL-JCA-010",
                            severity="FAIL",
                            spec="TS.48 / GlobalPlatform",
                            path=f"{key_text}.loadBlock.securityDomainAID",
                            message="securityDomainAID is not defined by any securityDomain PE.",
                            recommendation="Define matching securityDomain PE AID or remove reference.",
                            evidence={"securityDomainAID": security_domain_aid},
                        )

            instance_list = []
            if isinstance(payload, dict):
                candidate_list = payload.get("instanceList", [])
                if isinstance(candidate_list, list):
                    instance_list = candidate_list

            for index, instance in enumerate(instance_list):
                if isinstance(instance, dict) is False:
                    continue
                instance_aid = str(instance.get("instanceAID", "")).strip().upper()
                app_load_aid = str(instance.get("applicationLoadPackageAID", "")).strip().upper()
                if instance_aid == "":
                    self._add(
                        code="YRL-JCI-001",
                        severity="FAIL",
                        spec="ETSI TS 102 226 / GP",
                        path=f"{key_text}.instanceList[{index}]",
                        message="Application instance is missing instanceAID.",
                        recommendation="Set unique instanceAID for each application instance.",
                    )
                else:
                    if self._looks_like_hex(instance_aid) is False:
                        self._add(
                            code="YRL-JCI-002",
                            severity="FAIL",
                            spec="ETSI TS 102 226 / GP",
                            path=f"{key_text}.instanceList[{index}].instanceAID",
                            message="instanceAID is not hex-encoded.",
                            recommendation="Encode instanceAID as hex bytes.",
                        )
                    if instance_aid in instance_aids:
                        self._add(
                            code="YRL-JCI-003",
                            severity="FAIL",
                            spec="ETSI TS 102 226 / GP",
                            path=f"{key_text}.instanceList[{index}].instanceAID",
                            message=f"Duplicate instanceAID detected: {instance_aid}.",
                            recommendation="Use globally unique instanceAIDs.",
                        )
                    instance_aids.add(instance_aid)

                if load_aid is not None and app_load_aid != "":
                    if app_load_aid != load_aid:
                        self._add(
                            code="YRL-JCI-004",
                            severity="FAIL",
                            spec="ETSI TS 102 226 / GP",
                            path=f"{key_text}.instanceList[{index}].applicationLoadPackageAID",
                            message="applicationLoadPackageAID does not match parent loadPackageAID.",
                            recommendation="Keep instance load-package reference aligned with parent Application PE.",
                            evidence={
                                "expected": load_aid,
                                "actual": app_load_aid,
                            },
                        )

    def _check_hex_fields(self, section_items: list[tuple[str, Any]]) -> None:
        for key_text, payload in section_items:
            for field_path, value in self._walk_with_path(payload):
                if isinstance(value, str) is False:
                    continue
                compact = value.strip()
                if len(compact) < 8:
                    continue
                if len(compact) % 2 != 0:
                    continue
                if self._looks_like_hex(compact) is False:
                    continue
                if self._looks_random_text(compact):
                    continue
                if len(compact) > 4096:
                    self._add(
                        code="YRL-HEX-001",
                        severity="WARN",
                        spec="General consistency",
                        path=f"{key_text}.{field_path}",
                        message=f"Hex field is very large ({len(compact)} nibbles).",
                        recommendation="Confirm large binary fields are intended and correctly encoded.",
                    )

    def _check_apdu_like_fields(self, section_items: list[tuple[str, Any]]) -> None:
        for key_text, payload in section_items:
            for field_path, value in self._walk_with_path(payload):
                lowered = field_path.lower()
                if "apdu" not in lowered and "processdata" not in lowered:
                    continue
                if isinstance(value, str) is False:
                    self._add(
                        code="YRL-APD-001",
                        severity="WARN",
                        spec="ETSI APDU / GP",
                        path=f"{key_text}.{field_path}",
                        message="APDU-like field is not string encoded.",
                        recommendation="Represent APDU payloads as even-length hex strings.",
                    )
                    continue

                apdu_hex = value.strip().upper()
                if self._looks_like_hex(apdu_hex) is False:
                    self._add(
                        code="YRL-APD-002",
                        severity="FAIL",
                        spec="ETSI APDU / GP",
                        path=f"{key_text}.{field_path}",
                        message="APDU-like field is not valid hex.",
                        recommendation="Encode APDU fields in hex format.",
                    )
                    continue
                if len(apdu_hex) < 8:
                    self._add(
                        code="YRL-APD-003",
                        severity="FAIL",
                        spec="ETSI APDU / GP",
                        path=f"{key_text}.{field_path}",
                        message="APDU-like field is shorter than CLA+INS+P1+P2.",
                        recommendation="Use at least 4 APDU header bytes.",
                    )

    def _check_5gs_dependencies(self, ordered_types: list[str]) -> None:
        has_5gs = "df-5gs" in ordered_types
        if has_5gs is False:
            return
        has_usim = "usim" in ordered_types
        if has_usim:
            self._add(
                code="YRL-N5G-OK",
                severity="PASS",
                spec="TS.48 / 3GPP",
                path="df-5gs",
                message="DF-5GS appears with USIM PE present.",
                recommendation="None.",
            )
            return
        self._add(
            code="YRL-N5G-001",
            severity="FAIL",
            spec="TS.48 / 3GPP",
            path="df-5gs",
            message="DF-5GS is present without USIM PE.",
            recommendation="Add USIM PE or remove DF-5GS.",
        )

    def _check_fs_core_constraints(self, file_definitions: list[FileDefinition]) -> None:
        if len(file_definitions) == 0:
            return

        file_id_by_scope: dict[str, set[str]] = {}
        short_efid_by_scope: dict[str, set[str]] = {}
        for file_def in file_definitions:
            scope = self._derive_scope_from_section(file_def.section_key)
            if scope not in file_id_by_scope:
                file_id_by_scope[scope] = set()
            if scope not in short_efid_by_scope:
                short_efid_by_scope[scope] = set()

            self._validate_file_descriptor(file_def)
            self._validate_file_id(file_def, file_id_by_scope[scope])
            self._validate_short_efid(file_def, short_efid_by_scope[scope])
            self._validate_ef_file_size(file_def)
            self._validate_link_path(file_def)
            self._validate_security_attributes_reference(file_def)

    def _check_ber_tlv_constraints(
        self,
        section_items: list[tuple[str, Any]],
        file_definitions: list[FileDefinition],
    ) -> None:
        if len(file_definitions) == 0:
            return

        fill_offsets = self._collect_field_values(section_items, "fillFileOffset")
        fill_contents = self._collect_field_values(section_items, "fillFileContent")
        has_fill_offsets = len(fill_offsets) > 0
        has_fill_contents = len(fill_contents) > 0

        for file_def in file_definitions:
            max_size = file_def.maximum_file_size
            file_details = file_def.file_details
            if max_size is None and file_details is None:
                continue
            if max_size is not None:
                if self._looks_like_hex(max_size) is False:
                    self._add(
                        code="YRL-FIL-031",
                        severity="FAIL",
                        spec="ETSI TS 102 221",
                        path=f"{file_def.section_key}.{file_def.field_path}.maximumFileSize",
                        message="maximumFileSize is not valid hex.",
                        recommendation="Encode maximumFileSize as hex bytes.",
                    )
                if self._has_leading_zero_hex(max_size):
                    self._add(
                        code="YRL-FIL-032",
                        severity="WARN",
                        spec="TS.48 / ETSI TS 102 221",
                        path=f"{file_def.section_key}.{file_def.field_path}.maximumFileSize",
                        message="maximumFileSize has leading zero octet.",
                        recommendation="Use minimum number of octets for maximumFileSize.",
                    )
            if file_details is not None:
                if self._looks_like_hex(file_details) is False:
                    self._add(
                        code="YRL-FIL-035",
                        severity="WARN",
                        spec="ETSI TS 102 221",
                        path=f"{file_def.section_key}.{file_def.field_path}.fileDetails",
                        message="fileDetails is not valid hex.",
                        recommendation="Encode fileDetails as one-byte hex.",
                    )
                else:
                    if len(file_details) != 2:
                        self._add(
                            code="YRL-FIL-035",
                            severity="WARN",
                            spec="ETSI TS 102 221",
                            path=f"{file_def.section_key}.{file_def.field_path}.fileDetails",
                            message="fileDetails is expected to be one octet.",
                            recommendation="Set fileDetails using one-byte coding.",
                        )
            if has_fill_offsets:
                self._add(
                    code="YRL-FIL-029",
                    severity="WARN",
                    spec="TS.48 / ETSI TS 102 221",
                    path=f"{file_def.section_key}.{file_def.field_path}",
                    message="fillFileOffset is present while BER-TLV-related fields are used.",
                    recommendation="Avoid fillFileOffset for BER-TLV structured files.",
                )
            if has_fill_contents is False:
                self._add(
                    code="YRL-FIL-028",
                    severity="WARN",
                    spec="ETSI TS 102 221",
                    path=f"{file_def.section_key}.{file_def.field_path}",
                    message="No fillFileContent found for BER-TLV-related file definition.",
                    recommendation="Provide valid BER-TLV encoded fillFileContent values.",
                )

    def _check_usim_core_expectations(self, sections: dict[str, Any]) -> None:
        usim_payload = self._first_section_by_type(sections, "usim")
        if isinstance(usim_payload, dict) is False:
            return
        expected_markers = ("ef-imsi", "ef-ust")
        flattened_keys = {key.lower() for key in self._collect_keys(usim_payload)}
        for marker in expected_markers:
            if marker in flattened_keys:
                continue
            self._add(
                code="YRL-UCR-001",
                severity="WARN",
                spec="ETSI USIM files / 3GPP",
                path=f"usim.{marker}",
                message=f"USIM marker '{marker}' was not found in decoded payload.",
                recommendation="Confirm required USIM files are present in profile package model.",
            )

    def _check_service_to_file_mappings(self, section_items: list[tuple[str, Any]]) -> None:
        service_bits = self._extract_service_bits_from_payload(section_items, service_name="ust")
        if service_bits is None:
            return

        available_files = self._collect_file_name_markers(section_items)
        required_by_service = {
            2: ("ef-fdn",),
            6: ("ef-cmi",),
            10: ("ef-sms", "ef-smss"),
            12: ("ef-smsp", "ef-hpplmn"),
            19: ("ef-spn",),
            85: ("ef-epsloci", "ef-epsnsc"),
        }
        suggested_by_presence = {
            6: ("ef-cmi",),
            13: ("ef-acm", "ef-acmmax", "ef-puct"),
            40: ("ef-invscan",),
            85: ("ef-epsloci", "ef-epsnsc"),
        }

        for service_number, required_markers in required_by_service.items():
            service_enabled = self._service_bit_is_set(service_bits, service_number)
            if service_enabled is False:
                continue
            missing_markers = []
            for marker in required_markers:
                if marker in available_files:
                    continue
                missing_markers.append(marker)
            if len(missing_markers) == 0:
                continue
            self._add(
                code="YRL-UST-001",
                severity="INFO",
                spec="3GPP TS 31.102",
                path=f"EF(UST).service.{service_number}",
                message=f"Service {service_number} is enabled but related files are missing: {', '.join(missing_markers)}.",
                recommendation="Include required files for enabled UST services or clear service bits.",
            )

        for service_number, related_markers in suggested_by_presence.items():
            service_enabled = self._service_bit_is_set(service_bits, service_number)
            if service_enabled:
                continue
            present_related_markers: list[str] = []
            for marker in related_markers:
                if marker in available_files:
                    present_related_markers.append(marker)
            if len(present_related_markers) == 0:
                continue
            ust_hex = "".join(f"{item:02X}" for item in service_bits)
            self._add(
                code="YRL-UST-002",
                severity="INFO",
                spec="3GPP TS 31.102",
                path=f"EF(UST).service.{service_number}",
                message=(
                    f"Service {service_number} is not enabled in EF(UST) "
                    f"(UST={ust_hex}) but related files are present: "
                    f"{', '.join(present_related_markers)}."
                ),
                recommendation="Set corresponding UST service bit or remove non-required files.",
                evidence={
                    "service": service_number,
                    "ust_hex": ust_hex,
                    "related_files_present": present_related_markers,
                },
            )

    def _check_metadata_alignment(
        self,
        sections: dict[str, Any],
        metadata: Optional[dict[str, Any]],
    ) -> None:
        if isinstance(metadata, dict) is False:
            return
        header = self._first_section_by_type(sections, "header")
        if isinstance(header, dict):
            header_iccid = header.get("iccid")
            metadata_iccid = self._lookup_nested(metadata, ("profile", "iccid"))
            if header_iccid is not None and metadata_iccid is not None:
                if str(header_iccid).strip().upper() != str(metadata_iccid).strip().upper():
                    self._add(
                        code="YRL-MET-001",
                        severity="WARN",
                        spec="SGP.22 / SGP.32",
                        path="metadata.profile.iccid",
                        message="Metadata ICCID differs from profile header ICCID.",
                        recommendation="Keep metadata ICCID aligned with profile package header.",
                        evidence={
                            "header_iccid": str(header_iccid),
                            "metadata_iccid": str(metadata_iccid),
                        },
                    )

        mcc_value = self._lookup_nested(metadata, ("operator", "mcc"))
        mnc_value = self._lookup_nested(metadata, ("operator", "mnc"))
        if mcc_value is not None:
            mcc_text = str(mcc_value).strip()
            if len(mcc_text) != 3 or mcc_text.isdigit() is False:
                self._add(
                    code="YRL-MET-010",
                    severity="FAIL",
                    spec="3GPP / SGP metadata",
                    path="metadata.operator.mcc",
                    message="Operator MCC must be exactly 3 digits.",
                    recommendation="Use 3-digit decimal MCC in metadata.",
                    evidence={"mcc": mcc_text},
                )
        if mnc_value is not None:
            mnc_text = str(mnc_value).strip()
            if len(mnc_text) not in (2, 3) or mnc_text.isdigit() is False:
                self._add(
                    code="YRL-MET-011",
                    severity="FAIL",
                    spec="3GPP / SGP metadata",
                    path="metadata.operator.mnc",
                    message="Operator MNC must be 2 or 3 digits.",
                    recommendation="Use 2-digit or 3-digit decimal MNC in metadata.",
                    evidence={"mnc": mnc_text},
                )

    def _check_saip_tool_check_result(
        self,
        check_return_code: Optional[int],
        check_stderr: str,
        *,
        emit_missing_check_finding: bool = True,
    ) -> None:
        if check_return_code is None:
            if emit_missing_check_finding is False:
                return
            self._add(
                code="YRL-CHK-001",
                severity="WARN",
                spec="TS.48 / SAIP",
                path="saip-tool.check",
                message="saip-tool check result was not provided.",
                recommendation="Run saip-tool check as part of lint pipeline.",
            )
            return

        if check_return_code == 0:
            self._add(
                code="YRL-CHK-OK",
                severity="PASS",
                spec="TS.48 / SAIP",
                path="saip-tool.check",
                message="saip-tool check passed (exit code 0).",
                recommendation="None.",
                evidence={"exit_code": 0},
            )
            return

        detail = check_stderr.strip()
        if detail == "":
            detail = "saip-tool check returned non-zero status."
        self._add(
            code="YRL-CHK-002",
            severity="FAIL",
            spec="TS.48 / SAIP",
            path="saip-tool.check",
            message=detail,
            recommendation="Fix structural issues reported by saip-tool check.",
        )

    def _apply_strict_policy(self) -> None:
        if self.strict is False:
            return
        escalated_codes = {
            "YRL-SVC-001",
            "YRL-HDR-001",
            "YRL-SDM-001",
            "YRL-SDM-002",
            "YRL-UCR-001",
            "YRL-MET-001",
        }
        for finding in self.findings:
            if finding.severity != "WARN":
                continue
            if finding.code in escalated_codes:
                finding.severity = "FAIL"
                finding.message = f"{finding.message} (strict mode escalation)"

    def _build_summary(self) -> dict[str, int]:
        summary = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
        for finding in self.findings:
            if finding.severity == "PASS":
                summary["pass"] += 1
                continue
            if finding.severity == "WARN":
                summary["warn"] += 1
                continue
            if finding.severity == "FAIL":
                summary["fail"] += 1
                continue
            if finding.severity == "INFO":
                summary["info"] += 1
                continue
        return summary

    @staticmethod
    def _compute_score(summary: dict[str, int]) -> int:
        fail_count = int(summary.get("fail", 0))
        warn_count = int(summary.get("warn", 0))
        info_count = int(summary.get("info", 0))
        score = 100
        score -= fail_count * 12
        score -= warn_count * 3
        score -= info_count * 1
        if score < 0:
            return 0
        if score > 100:
            return 100
        return score

    def _extract_file_definitions(
        self,
        section_items: list[tuple[str, Any]],
    ) -> list[FileDefinition]:
        file_definitions: list[FileDefinition] = []
        for section_key, payload in section_items:
            for field_path, value in self._walk_with_path(payload):
                if isinstance(value, dict) is False:
                    continue
                if self._looks_like_file_definition(value) is False:
                    continue
                normalized = self._normalize_file_definition_value
                file_definitions.append(
                    FileDefinition(
                        section_key=str(section_key),
                        field_path=str(field_path),
                        payload=value,
                        file_id=normalized(value.get("fileID")),
                        file_descriptor=normalized(value.get("fileDescriptor")),
                        ef_file_size=normalized(value.get("efFileSize")),
                        short_efid=normalized(value.get("shortEFID")),
                        link_path=normalized(value.get("linkPath")),
                        maximum_file_size=normalized(value.get("maximumFileSize")),
                        file_details=normalized(value.get("fileDetails")),
                        security_attributes_referenced=normalized(value.get("securityAttributesReferenced")),
                        pin_status_template_do=normalized(value.get("pinStatusTemplateDO")),
                    )
                )
        return file_definitions

    @staticmethod
    def _looks_like_file_definition(payload: dict[str, Any]) -> bool:
        keys = set(str(key) for key in payload.keys())
        marker_keys = {
            "fileID",
            "fileDescriptor",
            "efFileSize",
            "shortEFID",
            "linkPath",
            "securityAttributesReferenced",
            "pinStatusTemplateDO",
            "maximumFileSize",
            "fileDetails",
        }
        intersection = keys.intersection(marker_keys)
        return len(intersection) > 0

    def _normalize_file_definition_value(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.hex().upper()
        text = str(value).strip()
        if text == "":
            return ""
        if self._looks_like_hex(text):
            return text.upper()
        return text

    def _validate_file_descriptor(self, file_def: FileDefinition) -> None:
        file_descriptor = file_def.file_descriptor
        path = f"{file_def.section_key}.{file_def.field_path}.fileDescriptor"
        if file_descriptor is None:
            self._add(
                code="YRL-FIL-003",
                severity="WARN",
                spec="TS.48 / ETSI TS 102 222",
                path=path,
                message="fileDescriptor is missing in file definition.",
                recommendation="Provide fileDescriptor where template and operation require it.",
            )
            return
        if self._looks_like_hex(file_descriptor) is False:
            self._add(
                code="YRL-FIL-002",
                severity="FAIL",
                spec="ETSI TS 102 222",
                path=path,
                message="fileDescriptor is not valid hex.",
                recommendation="Encode fileDescriptor as 2-4 octets.",
            )
            return
        octet_length = len(file_descriptor) // 2
        if octet_length < 2 or octet_length > 4:
            self._add(
                code="YRL-FIL-002",
                severity="FAIL",
                spec="ETSI TS 102 222",
                path=path,
                message=f"fileDescriptor length is {octet_length} octets; expected 2..4.",
                recommendation="Encode fileDescriptor using 2 to 4 octets.",
            )

    def _validate_file_id(self, file_def: FileDefinition, seen_file_ids: set[str]) -> None:
        file_id = file_def.file_id
        path = f"{file_def.section_key}.{file_def.field_path}.fileID"
        if file_id is None:
            self._add(
                code="YRL-FIL-005",
                severity="WARN",
                spec="TS.48 / ETSI TS 102 222",
                path=path,
                message="fileID is missing in file definition.",
                recommendation="Provide fileID where required by the selected file creation mode.",
            )
            return
        if self._looks_like_hex(file_id) is False:
            self._add(
                code="YRL-FIL-006",
                severity="FAIL",
                spec="ETSI TS 102 221",
                path=path,
                message="fileID is not valid hex.",
                recommendation="Encode fileID as two octets.",
            )
            return
        if len(file_id) != 4:
            self._add(
                code="YRL-FIL-006",
                severity="FAIL",
                spec="ETSI TS 102 221",
                path=path,
                message=f"fileID length is {len(file_id) // 2} octets; expected 2.",
                recommendation="Use 2-octet fileID values.",
            )
            return
        if file_id in seen_file_ids:
            self._add(
                code="YRL-FIL-006",
                severity="FAIL",
                spec="ETSI TS 102 221",
                path=path,
                message=f"fileID {file_id} is duplicated in the same scope.",
                recommendation="Use fileID unique within DF/ADF scope.",
            )
            return
        seen_file_ids.add(file_id)

    def _validate_short_efid(self, file_def: FileDefinition, seen_short_efids: set[str]) -> None:
        short_efid = file_def.short_efid
        path = f"{file_def.section_key}.{file_def.field_path}.shortEFID"
        if short_efid is None:
            return
        if short_efid == "":
            return
        if self._looks_like_hex(short_efid) is False:
            self._add(
                code="YRL-FIL-019",
                severity="FAIL",
                spec="ETSI TS 102 222",
                path=path,
                message="shortEFID is not valid hex.",
                recommendation="Encode shortEFID as empty or one-octet value.",
            )
            return
        if len(short_efid) != 2:
            self._add(
                code="YRL-FIL-019",
                severity="FAIL",
                spec="ETSI TS 102 222",
                path=path,
                message="shortEFID must be zero or one octet.",
                recommendation="Set shortEFID to empty or one-byte value.",
            )
            return
        numeric = int(short_efid, 16)
        if (numeric & self._SHORT_EFID_RESERVED_LOW_BITS_MASK) != 0:
            self._add(
                code="YRL-FIL-019",
                severity="FAIL",
                spec="ETSI TS 102 222",
                path=path,
                message="shortEFID low 3 bits are not zero.",
                recommendation="Use shortEFID coding with b3..b1 set to zero.",
            )
        if short_efid in seen_short_efids:
            self._add(
                code="YRL-FIL-027",
                severity="FAIL",
                spec="ETSI TS 102 221",
                path=path,
                message=f"shortEFID {short_efid} is duplicated in same scope.",
                recommendation="Use unique shortEFID values within DF/ADF scope.",
            )
            return
        seen_short_efids.add(short_efid)

    def _validate_ef_file_size(self, file_def: FileDefinition) -> None:
        ef_file_size = file_def.ef_file_size
        if ef_file_size is None:
            return
        path = f"{file_def.section_key}.{file_def.field_path}.efFileSize"
        if self._looks_like_hex(ef_file_size) is False:
            self._add(
                code="YRL-FIL-016",
                severity="FAIL",
                spec="TS.48 / ETSI TS 102 222",
                path=path,
                message="efFileSize is not valid hex.",
                recommendation="Encode efFileSize as hex bytes.",
            )
            return
        if self._has_leading_zero_hex(ef_file_size):
            self._add(
                code="YRL-FIL-014",
                severity="FAIL",
                spec="TS.48 / ETSI TS 102 222",
                path=path,
                message="efFileSize has leading zero octet.",
                recommendation="Encode efFileSize on minimum number of octets.",
            )
        size_value = int(ef_file_size, 16)
        if size_value > 65535:
            self._add(
                code="YRL-FIL-013",
                severity="WARN",
                spec="ETSI TS 102 222",
                path=path,
                message=f"efFileSize value {size_value} exceeds 65535.",
                recommendation="Keep efFileSize within 65535 bytes when possible.",
            )

        file_descriptor = file_def.file_descriptor
        if file_descriptor is None:
            return
        if self._looks_like_hex(file_descriptor) is False:
            return
        if len(file_descriptor) != 8:
            return
        if file_descriptor.startswith("42") is False and file_descriptor.startswith("46") is False:
            return
        record_length = int(file_descriptor[-2:], 16)
        if record_length == 0:
            return
        if (size_value % record_length) != 0:
            self._add(
                code="YRL-FIL-067",
                severity="FAIL",
                spec="ETSI TS 102 222",
                path=path,
                message="efFileSize is not a multiple of record length for record-oriented EF.",
                recommendation="Set efFileSize as N * recordLength.",
                evidence={
                    "efFileSize": size_value,
                    "recordLength": record_length,
                },
            )
            return
        record_count = size_value // record_length
        if record_count > 254:
            self._add(
                code="YRL-FIL-038",
                severity="FAIL",
                spec="ETSI TS 102 221",
                path=path,
                message=f"Record count is {record_count}; maximum allowed is 254.",
                recommendation="Reduce file size or record length to keep <=254 records.",
            )

    def _validate_link_path(self, file_def: FileDefinition) -> None:
        link_path = file_def.link_path
        if link_path is None:
            return
        path = f"{file_def.section_key}.{file_def.field_path}.linkPath"
        if link_path == "":
            return
        if self._looks_like_hex(link_path) is False:
            self._add(
                code="YRL-FIL-023",
                severity="FAIL",
                spec="ETSI TS 102 221",
                path=path,
                message="linkPath is not valid hex.",
                recommendation="Encode linkPath as MF-relative path in hex.",
            )
            return
        if (len(link_path) // 2) > 8:
            self._add(
                code="YRL-FIL-037",
                severity="WARN",
                spec="TS.48 / ETSI TS 102 221",
                path=path,
                message="linkPath is longer than 8 bytes.",
                recommendation="Limit linkPath length to 8 bytes.",
            )

    def _validate_security_attributes_reference(self, file_def: FileDefinition) -> None:
        security_attributes_referenced = file_def.security_attributes_referenced
        if security_attributes_referenced is None:
            return
        path = f"{file_def.section_key}.{file_def.field_path}.securityAttributesReferenced"
        if self._looks_like_hex(security_attributes_referenced) is False:
            self._add(
                code="YRL-FIL-012",
                severity="FAIL",
                spec="TS.48 / ETSI TS 102 222",
                path=path,
                message="securityAttributesReferenced is not valid hex.",
                recommendation="Encode securityAttributesReferenced as 1..3 bytes.",
            )
            return
        byte_length = len(security_attributes_referenced) // 2
        if byte_length < 1 or byte_length > 3:
            self._add(
                code="YRL-FIL-012",
                severity="FAIL",
                spec="TS.48 / ETSI TS 102 222",
                path=path,
                message="securityAttributesReferenced must be 1..3 bytes.",
                recommendation="Use EF(ARR) reference coding with proper length.",
            )

    def _extract_security_domain_aids(self, security_domains: list[Any]) -> set[str]:
        aids: set[str] = set()
        for security_domain in security_domains:
            load_blocks = self._find_key_values(security_domain, "instance")
            if len(load_blocks) == 0:
                load_blocks = self._find_key_values(security_domain, "sdAID")
                for aid_value in load_blocks:
                    aid_text = str(aid_value).strip().upper()
                    if self._looks_like_hex(aid_text):
                        aids.add(aid_text)
                continue
            for instance in load_blocks:
                if isinstance(instance, dict) is False:
                    continue
                for field_name in ("applicationLoadPackageAID", "securityDomainAID", "instanceAID"):
                    candidate = instance.get(field_name)
                    if candidate is None:
                        continue
                    candidate_text = str(candidate).strip().upper()
                    if self._looks_like_hex(candidate_text):
                        aids.add(candidate_text)
        return aids

    def _collect_field_values(
        self,
        section_items: list[tuple[str, Any]],
        key_name: str,
    ) -> list[Any]:
        values: list[Any] = []
        for _, payload in section_items:
            candidates = self._find_key_values(payload, key_name)
            if len(candidates) == 0:
                continue
            values.extend(candidates)
        return values

    def _extract_service_bits_from_payload(
        self,
        section_items: list[tuple[str, Any]],
        service_name: str,
    ) -> Optional[list[int]]:
        marker = f"ef-{service_name.lower()}"
        candidate_hex_values: list[str] = []
        for section_key, payload in section_items:
            if self._base_type_from_key(section_key) not in ("usim", "opt-usim", "isim", "opt-isim"):
                continue
            for field_path, value in self._walk_with_path(payload):
                field_path_l = field_path.lower()
                if marker not in field_path_l:
                    continue
                for candidate in self._extract_hex_candidates(value):
                    candidate_hex_values.append(candidate)

        if len(candidate_hex_values) == 0:
            return None
        candidate_hex_values.sort(key=lambda item: len(item), reverse=True)
        best = candidate_hex_values[0]
        if self._looks_like_hex(best) is False:
            return None
        return list(bytes.fromhex(best))

    def _extract_hex_candidates(self, value: Any) -> list[str]:
        candidates: list[str] = []
        if isinstance(value, str):
            compact = value.strip().upper()
            if self._looks_like_hex(compact):
                candidates.append(compact)
            return candidates
        if isinstance(value, bytes):
            candidates.append(value.hex().upper())
            return candidates
        if isinstance(value, tuple):
            for item in value:
                nested = self._extract_hex_candidates(item)
                if len(nested) > 0:
                    candidates.extend(nested)
            return candidates
        if isinstance(value, list):
            for item in value:
                nested = self._extract_hex_candidates(item)
                if len(nested) > 0:
                    candidates.extend(nested)
            return candidates
        if isinstance(value, dict):
            for nested_value in value.values():
                nested = self._extract_hex_candidates(nested_value)
                if len(nested) > 0:
                    candidates.extend(nested)
            return candidates
        return candidates

    def _collect_file_name_markers(self, section_items: list[tuple[str, Any]]) -> set[str]:
        markers: set[str] = set()
        for section_key, payload in section_items:
            section_marker = self._base_type_from_key(section_key).lower()
            if section_marker != "":
                markers.add(section_marker)
            for field_path, _ in self._walk_with_path(payload):
                lowered = field_path.lower()
                for segment in lowered.split("."):
                    clean = segment.split("[", 1)[0]
                    if clean.startswith("ef-") is False:
                        continue
                    markers.add(clean)
        return markers

    @staticmethod
    def _derive_scope_from_section(section_key: str) -> str:
        lowered = str(section_key).lower()
        if lowered.startswith("usim"):
            return "usim"
        if lowered.startswith("opt-usim"):
            return "usim"
        if lowered.startswith("isim"):
            return "isim"
        if lowered.startswith("opt-isim"):
            return "isim"
        if lowered.startswith("csim"):
            return "csim"
        if lowered.startswith("mf"):
            return "mf"
        return lowered

    @staticmethod
    def _has_leading_zero_hex(hex_text: str) -> bool:
        normalized = str(hex_text).strip()
        if len(normalized) <= 2:
            return False
        return normalized.startswith("00")

    @staticmethod
    def _service_bit_is_set(service_bits: list[int], service_number: int) -> bool:
        if service_number <= 0:
            return False
        byte_index = (service_number - 1) // 8
        bit_index = (service_number - 1) % 8
        if byte_index >= len(service_bits):
            return False
        mask = 1 << bit_index
        return (service_bits[byte_index] & mask) != 0

    def _first_section_by_type(self, sections: dict[str, Any], item_type: str) -> Any:
        for key_text, payload in sections.items():
            if self._base_type_from_key(key_text) != item_type:
                continue
            return payload
        return None

    def _find_key_values(self, payload: Any, key_name: str) -> list[Any]:
        results: list[Any] = []
        if isinstance(payload, dict):
            for current_key, current_value in payload.items():
                if str(current_key) == key_name:
                    results.append(current_value)
                nested_values = self._find_key_values(current_value, key_name)
                if len(nested_values) > 0:
                    results.extend(nested_values)
            return results
        if isinstance(payload, list):
            for item in payload:
                nested_values = self._find_key_values(item, key_name)
                if len(nested_values) > 0:
                    results.extend(nested_values)
            return results
        return results

    def _walk_with_path(self, payload: Any, base_path: str = "") -> list[tuple[str, Any]]:
        rows: list[tuple[str, Any]] = []
        if isinstance(payload, dict):
            for key_text, value in payload.items():
                key_part = str(key_text)
                if base_path == "":
                    full_path = key_part
                else:
                    full_path = f"{base_path}.{key_part}"
                rows.append((full_path, value))
                nested = self._walk_with_path(value, full_path)
                if len(nested) > 0:
                    rows.extend(nested)
            return rows
        if isinstance(payload, list):
            index = 0
            for value in payload:
                full_path = f"{base_path}[{index}]"
                rows.append((full_path, value))
                nested = self._walk_with_path(value, full_path)
                if len(nested) > 0:
                    rows.extend(nested)
                index += 1
            return rows
        return rows

    def _collect_keys(self, payload: Any) -> list[str]:
        keys: list[str] = []
        if isinstance(payload, dict):
            for key_text, value in payload.items():
                keys.append(str(key_text))
                nested_keys = self._collect_keys(value)
                if len(nested_keys) > 0:
                    keys.extend(nested_keys)
            return keys
        if isinstance(payload, list):
            for item in payload:
                nested_keys = self._collect_keys(item)
                if len(nested_keys) > 0:
                    keys.extend(nested_keys)
            return keys
        return keys

    @staticmethod
    def _lookup_nested(payload: Any, path: tuple[str, ...]) -> Any:
        current = payload
        for part in path:
            if isinstance(current, dict) is False:
                return None
            if part not in current:
                return None
            current = current.get(part)
        return current

    def _looks_like_hex(self, value: str) -> bool:
        if len(value) == 0:
            return False
        if len(value) % 2 != 0:
            return False
        return self._HEX_RE.match(value) is not None

    @staticmethod
    def _looks_random_text(value: str) -> bool:
        alpha_count = 0
        for character in value:
            if character.lower() in "ghijklmnopqrstuvwxyz":
                alpha_count += 1
            if alpha_count > 2:
                return True
        return False
