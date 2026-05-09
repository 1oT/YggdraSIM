# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP profile linter: static analysis of decoded profile documents emitting YRL-* findings (TS.48 / SGP.22 / ETSI TS 102 221)."""
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
        """Serialise the report to a JSON-safe dict for API responses."""
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
        """Run all lint passes against a decoded profile document.

        ``decoded_document`` must follow the pySim/saip-tool JSON shape
        (``sections`` dict with typed PE dicts).  Returns a ``LintReport``
        whose ``findings`` list is sorted by severity then code.
        ``placeholder_paths`` names fields whose values are unresolved template
        tokens; findings that originate from those fields are suppressed so
        template profiles do not generate spurious FAILs.
        """
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
        self._check_iccid_consistency(sections, section_items)
        self._check_imsi_encoding(section_items)
        self._check_ef_ad_encoding(section_items)
        self._check_ef_acc_encoding(section_items)
        self._check_ef_hplmn_encoding(section_items)
        self._check_ef_spn_encoding(section_items)
        self._check_ef_smsp_encoding(section_items)
        self._check_ef_est_encoding(section_items)
        self._check_ef_loci_encoding(section_items)
        self._check_ef_epsloci_encoding(section_items)
        self._check_ef_keys_encoding(section_items)
        self._check_ef_epsnsc_encoding(section_items)
        self._check_ef_kc_encoding(section_items)
        self._check_ef_start_hfn_encoding(section_items)
        self._check_ef_fdn_bdn_encoding(section_items)
        self._check_ef_pnn_opl_encoding(section_items)
        self._check_ef_sms_cbmi_encoding(section_items)
        self._check_ef_msisdn_fplmn_ecc_encoding(section_items)
        self._check_ef_suci_calc_info(section_items)
        self._check_profile_header_core_fields(sections)
        self._check_connectivity_parameters(sections)
        self._check_identification_uniqueness(section_items)
        self._check_security_domain_integrity(sections)
        self._check_application_integrity(sections)
        self._check_fs_core_constraints(file_definitions)
        self._check_arr_references(file_definitions)
        self._check_pin_puk_encoding(sections)
        self._check_sd_key_list(sections)
        self._check_aka_parameter_encoding(sections)
        self._check_ber_tlv_constraints(section_items, file_definitions)
        self._check_gfm_sequences(sections)
        self._check_rfm_tar_coherence(sections)
        self._check_ram_sd_integrity(sections)
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
        """Evaluate release-gate thresholds against a completed ``LintReport``.

        Returns a dict with ``passed`` (bool), ``triggers`` (list of failing
        threshold descriptions), and ``thresholds`` (the input criteria).
        A gate passes when no threshold is violated: score is at or above
        ``min_score``, no WARN findings are present when ``fail_on_warn`` is
        set, and no findings match any code in ``fail_codes`` or prefix in
        ``fail_prefixes``.
        """
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

        # ICCID arrives as bytes from pySim's decoder, as a hex string
        # from operator-edited JSON, or as a tagged ``{"hex": "…"}``
        # dict from the editor projection. Normalise via the shared
        # helper so all three shapes lint identically.
        iccid_hex = self._coerce_hex_string(iccid_value)
        if iccid_hex is None:
            non_hex_chars = sorted(
                {character for character in str(iccid_value) if character not in "0123456789ABCDEFabcdef"}
            )
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
                evidence={"iccid": str(iccid_value), "non_hex_characters": non_hex_chars},
            )
            return

        if len(iccid_hex) != 20:
            self._add(
                code="YRL-ICC-002",
                severity="WARN",
                spec="ETSI TS 102 221",
                path="header.iccid",
                message=(
                    f"ICCID length is {len(iccid_hex)} nibbles; expected 20 "
                    f"(10 octets BCD)."
                ),
                recommendation="Use 20-nibble ICCID encoding (BCD with filler F when needed).",
                evidence={"iccid": iccid_hex},
            )
            return

        # ITU-T E.118 §3.3: BCD bytes are nibble-swapped on the wire.
        # Un-swap to obtain the natural digit string d[0]..d[19].
        natural = ""
        for i in range(0, 20, 2):
            natural += iccid_hex[i + 1] + iccid_hex[i]
        natural = natural.upper()

        # Trailing filler nibble 'F' in position 19 means the IIN+serial is
        # only 18 significant digits (+ Luhn check on 19 digits total).
        # When the filler is present we still verify the Luhn on digits 0..18.
        # When no filler we verify on all 20 digits.
        if "F" in natural:
            significant = natural.replace("F", "")
        else:
            significant = natural

        if not all(c.isdigit() for c in significant):
            invalid_chars = sorted({c for c in significant if not c.isdigit()})
            self._add(
                code="YRL-ICC-004",
                severity="WARN",
                spec="ITU-T E.118 §3.3",
                path="header.iccid",
                message=(
                    "ICCID natural digit string contains non-decimal characters "
                    "after BCD un-swap; these are not valid ICCID digits."
                ),
                recommendation="Verify ICCID BCD encoding; each nibble must be 0–9 or trailing F.",
                evidence={"iccid": iccid_hex, "invalid_chars": invalid_chars},
            )
            return

        # Luhn mod-10 over the significant digit string.
        total = 0
        for pos, digit_char in enumerate(reversed(significant)):
            n = int(digit_char)
            if pos % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        if total % 10 != 0:
            expected_remainder = (-total) % 10
            self._add(
                code="YRL-ICC-004",
                severity="WARN",
                spec="ITU-T E.118 §3.3 / ISO/IEC 7812-1",
                path="header.iccid",
                message=(
                    f"ICCID fails Luhn mod-10 check digit validation "
                    f"(remainder {total % 10}; expected 0). "
                    f"Check digit should produce remainder 0."
                ),
                recommendation=(
                    "Recalculate the ICCID check digit (digit 19 in natural order). "
                    f"With the current body the check digit must make the total "
                    f"divisible by 10 (current remainder: {total % 10})."
                ),
                evidence={
                    "iccid": iccid_hex,
                    "natural_digits": significant,
                    "luhn_remainder": total % 10,
                },
            )

    def _check_ef_ad_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-AD-*: EF.AD byte-level encoding checks (3GPP TS 31.102 §4.2.18).

        EF.AD carries per-subscription administrative data.  Byte 4 is the
        MNC length indicator used by the ME to split the IMSI into MCC + MNC.
        A wrong value silently causes incorrect PLMN identification.

        - ``YRL-AD-001`` (FAIL): ``mnc_length`` byte (byte 4) is not 2 or 3.
        - ``YRL-AD-002`` (WARN): EF.AD content is fewer than 4 bytes — the
          mandatory ``mnc_length`` byte is missing.
        - ``YRL-AD-003`` (WARN): ``mnc_length`` is 3 but the IMSI MNC field
          in the same section has digit 6 (the third MNC digit) == 'F'
          (filler), suggesting the MNC is only 2 digits long.

        EF.AD is identified by FID 6FAD (3GPP TS 31.102 §4.2.18);
        EF.IMSI by FID 6F07.  Both are resolved from ``_extract_file_definitions``
        so the check is robust to any nesting shape.
        """
        # FID 6FAD = EF.AD, FID 6F07 = EF.IMSI (3GPP TS 31.102).
        _EF_AD_FID   = "6FAD"
        _EF_IMSI_FID = "6F07"

        file_defs = self._extract_file_definitions(section_items)

        # Group by section (USIM / OPT-USIM only).
        for section_key, payload in section_items:
            section_lo = self._base_type_from_key(section_key).lower()
            if section_lo not in ("usim", "opt-usim"):
                continue

            ef_ad_hex: str | None = None
            ef_imsi_hex: str | None = None

            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                fid = (fd.file_id or "").upper().replace(" ", "")
                if fid == _EF_AD_FID:
                    raw_fill = fd.payload.get("fillFileContent")
                    ef_ad_hex = self._coerce_hex_string(raw_fill)
                    if ef_ad_hex:
                        ef_ad_hex = ef_ad_hex.upper()
                elif fid == _EF_IMSI_FID:
                    raw_fill = fd.payload.get("fillFileContent")
                    ef_imsi_hex = self._coerce_hex_string(raw_fill)
                    if ef_imsi_hex:
                        ef_imsi_hex = ef_imsi_hex.upper()

            if ef_ad_hex is None:
                continue

            ad_path = f"{section_key}.ef-ad.fillFileContent"
            ad_bytes = len(ef_ad_hex) // 2

            if ad_bytes < 4:
                self._add(
                    code="YRL-AD-002",
                    severity="WARN",
                    spec="3GPP TS 31.102 §4.2.18",
                    path=ad_path,
                    message=(
                        f"EF.AD is {ad_bytes} byte(s); the minimum is 4 bytes "
                        "(bytes 1–3 adminData + byte 4 mnc_length)."
                    ),
                    recommendation="Ensure EF.AD has at least 4 bytes including the mnc_length indicator.",
                    evidence={"hex": ef_ad_hex, "byte_length": ad_bytes},
                )
                continue

            mnc_len_byte = int(ef_ad_hex[6:8], 16)
            if mnc_len_byte not in (2, 3):
                self._add(
                    code="YRL-AD-001",
                    severity="FAIL",
                    spec="3GPP TS 31.102 §4.2.18",
                    path=ad_path,
                    message=(
                        f"EF.AD byte 4 (mnc_length) is 0x{mnc_len_byte:02X} ({mnc_len_byte}); "
                        "allowed values are 2 or 3 (3GPP TS 31.102 §4.2.18). "
                        "An incorrect value causes the ME to misparse the IMSI "
                        "MCC/MNC split, leading to PLMN attachment failure."
                    ),
                    recommendation=(
                        "Set mnc_length to 2 for 2-digit MNCs (most operators) "
                        "or 3 for 3-digit MNCs (e.g. some US / Canadian operators)."
                    ),
                    evidence={"hex": ef_ad_hex, "mnc_length_byte": f"0x{mnc_len_byte:02X}"},
                )
                continue

            # Cross-check: mnc_length=3 but IMSI 6th digit (3rd MNC nibble) is 'F'.
            if mnc_len_byte == 3 and ef_imsi_hex is not None and len(ef_imsi_hex) >= 18:
                # IMSI BCD layout (9 bytes, nibble-swapped):
                # Byte 1 = length (0x08), Byte 2 = parity|d1,
                # Bytes 3–9: d2d3 d4d5 d6d7 d8d9 d10d11 d12d13 d14d15
                # MCC = d1 d2 d3, MNC starts at d4.
                # MNC digit 3 is d6, which lives in the high nibble of
                # byte 4 (index 8:10 in hex string, high nibble = [8]).
                mnc3_nibble_hex = ef_imsi_hex[8]  # high nibble of byte 5 = d6
                if mnc3_nibble_hex.upper() == "F":
                    self._add(
                        code="YRL-AD-003",
                        severity="WARN",
                        spec="3GPP TS 31.102 §4.2.18 / §4.2.2",
                        path=ad_path,
                        message=(
                            "EF.AD mnc_length is 3 but the third MNC digit in "
                            "EF.IMSI appears to be a filler nibble (0xF), "
                            "suggesting the MNC is only 2 digits long."
                        ),
                        recommendation=(
                            "Verify whether the operator's MNC is 2 or 3 digits. "
                            "If 2-digit, set mnc_length to 2."
                        ),
                        evidence={
                            "ef_ad_hex": ef_ad_hex,
                            "ef_imsi_hex": ef_imsi_hex,
                            "mnc_length": mnc_len_byte,
                            "third_mnc_nibble": mnc3_nibble_hex.upper(),
                        },
                    )

    def _check_ef_acc_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-ACC-*: EF.ACC byte-level checks (3GPP TS 31.102 §4.2.15).

        EF.ACC (FID 6F78) is exactly 2 bytes encoding access class bits 0–15.
        Bits 0–9 are user classes; bit 11 = class 11 (PLMN use), bits 12–15
        are operator/emergency classes.

        - ``YRL-ACC-001`` (FAIL): EF.ACC is not exactly 2 bytes.
        - ``YRL-ACC-002`` (WARN): bits 0–9 are all zero — the UE belongs to
          no user access class, which prevents class-based access barring
          override and emergency class 10 call origination.
        """
        _EF_ACC_FID = "6F78"
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            section_lo = self._base_type_from_key(section_key).lower()
            if section_lo not in ("usim", "opt-usim"):
                continue

            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                fid = (fd.file_id or "").upper().replace(" ", "")
                if fid != _EF_ACC_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                acc_hex = self._coerce_hex_string(raw_fill)
                if acc_hex is None:
                    continue
                acc_hex = acc_hex.upper()
                acc_path = f"{section_key}.ef-acc.fillFileContent"
                acc_bytes = len(acc_hex) // 2

                if acc_bytes != 2:
                    self._add(
                        code="YRL-ACC-001",
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.2.15",
                        path=acc_path,
                        message=(
                            f"EF.ACC is {acc_bytes} byte(s); the specification "
                            "requires exactly 2 bytes (3GPP TS 31.102 §4.2.15)."
                        ),
                        recommendation="Re-encode EF.ACC as exactly 2 bytes.",
                        evidence={"hex": acc_hex, "byte_length": acc_bytes},
                    )
                    continue

                acc_val = int(acc_hex[:4], 16)
                user_classes = acc_val & 0x03FF
                if user_classes == 0:
                    self._add(
                        code="YRL-ACC-002",
                        severity="WARN",
                        spec="3GPP TS 31.102 §4.2.15",
                        path=acc_path,
                        message=(
                            f"EF.ACC user class bits 0–9 are all zero (value 0x{acc_hex[:4]}). "
                            "The UE belongs to no user access class — "
                            "class-based access control cannot override barring."
                        ),
                        recommendation=(
                            "Set at least one user class bit (0–9) appropriate "
                            "for the subscriber's access class."
                        ),
                        evidence={"hex": acc_hex, "user_class_bits": "0x0000"},
                    )

    def _check_ef_hplmn_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-HPLMN-*: EF.HPLMNwAcT search period check (3GPP TS 31.102 §4.2.6).

        EF.HPLMNwAcT (FID 6F62) carries a 5-byte structure; byte 1 is the
        HPLMN search timer in units of 6 minutes (value 0 = disable timer,
        1–254 = 6–1524 min).  A value of 0 prevents the ME from ever
        searching for the HPLMN after it has camped on a VPLMN.

        - ``YRL-HPLMN-001`` (WARN): timer byte is 0x00 (search disabled).
        - ``YRL-HPLMN-002`` (FAIL): EF.HPLMNwAcT is fewer than 1 byte.
        """
        _EF_HPLMN_FID = "6F62"
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            section_lo = self._base_type_from_key(section_key).lower()
            if section_lo not in ("usim", "opt-usim"):
                continue

            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                fid = (fd.file_id or "").upper().replace(" ", "")
                if fid != _EF_HPLMN_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                hplmn_hex = self._coerce_hex_string(raw_fill)
                if hplmn_hex is None:
                    continue
                hplmn_hex = hplmn_hex.upper()
                hplmn_path = f"{section_key}.ef-hplmn-wact.fillFileContent"
                hplmn_bytes = len(hplmn_hex) // 2

                if hplmn_bytes < 1:
                    self._add(
                        code="YRL-HPLMN-002",
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.2.6",
                        path=hplmn_path,
                        message="EF.HPLMNwAcT content is empty — timer byte is absent.",
                        recommendation="Provide at least the 1-byte HPLMN search timer.",
                        evidence={"hex": hplmn_hex},
                    )
                    continue

                timer_byte = int(hplmn_hex[:2], 16)
                if timer_byte == 0:
                    self._add(
                        code="YRL-HPLMN-001",
                        severity="WARN",
                        spec="3GPP TS 31.102 §4.2.6",
                        path=hplmn_path,
                        message=(
                            "EF.HPLMNwAcT timer byte is 0x00 — HPLMN search is disabled. "
                            "The ME will not periodically search for the HPLMN after "
                            "camping on a VPLMN, which prevents automatic return to home network."
                        ),
                        recommendation=(
                            "Set the timer byte to a non-zero value (1 = 6 min, "
                            "typical deployment value is 0x02 = 12 min or 0x05 = 30 min)."
                        ),
                        evidence={"hex": hplmn_hex, "timer_byte": "0x00"},
                    )

    def _check_ef_fdn_bdn_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-FDN-*: ADN record shape checks for EF.FDN and EF.BDN.

        Both EF.FDN (6F3B) and EF.BDN (6F4D) store ADN-format records
        (3GPP TS 31.102 §4.2.13 / §4.2.25).  Minimum record size is 14 bytes:
        alpha-ID (0 or more bytes) + ToN/NPI 1B + num-len 1B + BCD 10B + CCP 1B +
        EXT 1B.  The number length byte must not exceed 10.

        - ``YRL-FDN-001`` (FAIL): record shorter than 14 bytes.
        - ``YRL-FDN-002`` (WARN): num-len byte > 10 (max BCD number field size).
        """
        _FDN_FIDS = {"6F3B": "EF.FDN", "6F4D": "EF.BDN"}
        for _pe_type, pe in section_items:
            if not isinstance(pe, dict):
                continue
            file_obj = pe.get("file")
            if not isinstance(file_obj, dict):
                continue
            cmds = file_obj.get("fileManagementCMD", [])
            for cmd in cmds:
                block = cmd.get("@") if isinstance(cmd, dict) else None
                if not isinstance(block, list) or len(block) < 2:
                    continue
                params = block[1] if isinstance(block[1], dict) else {}
                fid_raw = params.get("fileID")
                fid_hex = self._coerce_hex_string(fid_raw)
                if fid_hex is None or fid_hex.upper() not in _FDN_FIDS:
                    continue
                ef_label = _FDN_FIDS[fid_hex.upper()]
                fill_raw = params.get("fillFileContent")
                fill_hex = self._coerce_hex_string(fill_raw)
                if fill_hex is None:
                    continue
                fill_hex = fill_hex.upper()
                byte_len = len(fill_hex) // 2
                if byte_len < 14:
                    self._add(
                        code="YRL-FDN-001",
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.2.13",
                        path=f"genericFileManagement.{ef_label}.fillFileContent",
                        message=(
                            f"{ef_label} record is {byte_len} byte(s); ADN minimum "
                            f"is 14 bytes (ToN/NPI + num-len + BCD 10B + CCP + EXT)."
                        ),
                        recommendation="Encode ADN records with at least 14 bytes.",
                        evidence={"fid": fid_hex.upper(), "byte_length": byte_len},
                    )
                    continue
                # Alpha-ID occupies all bytes before the fixed 14-byte tail.
                alpha_len = byte_len - 14
                base = alpha_len * 2
                num_len_byte = int(fill_hex[base + 2: base + 4], 16)
                if num_len_byte not in (0xFF,) and num_len_byte > 10:
                    self._add(
                        code="YRL-FDN-002",
                        severity="WARN",
                        spec="3GPP TS 31.102 §4.2.13",
                        path=f"genericFileManagement.{ef_label}.fillFileContent",
                        message=(
                            f"{ef_label} number-length byte is {num_len_byte}; "
                            f"the BCD number field is only 10 bytes."
                        ),
                        recommendation="Set the number-length byte to ≤ 10.",
                        evidence={"fid": fid_hex.upper(), "num_len": num_len_byte},
                    )

    def _check_ef_pnn_opl_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-PNN-* / YRL-OPL-*: EF.PNN and EF.OPL shape checks.

        EF.PNN (6FC5) stores PLMN Network Name records as BER-TLV with a
        mandatory tag 0x80 (full name) and optional 0x43 (short name)
        (3GPP TS 31.102 §4.2.58).

        EF.OPL (6FC6) stores 8-byte records mapping PLMN + LAC range to a PNN
        record number (3GPP TS 31.102 §4.2.59).

        - ``YRL-PNN-001`` (FAIL): tag 0x80 (full name) absent in a PNN record.
        - ``YRL-OPL-001`` (WARN): EF.OPL content length not a multiple of 8.
        """
        for _pe_type, pe in section_items:
            if not isinstance(pe, dict):
                continue
            file_obj = pe.get("file")
            if not isinstance(file_obj, dict):
                continue
            cmds = file_obj.get("fileManagementCMD", [])
            for cmd in cmds:
                block = cmd.get("@") if isinstance(cmd, dict) else None
                if not isinstance(block, list) or len(block) < 2:
                    continue
                params = block[1] if isinstance(block[1], dict) else {}
                fid_raw = params.get("fileID")
                fid_hex = self._coerce_hex_string(fid_raw)
                if fid_hex is None:
                    continue
                fid_upper = fid_hex.upper()
                fill_raw = params.get("fillFileContent")
                fill_hex = self._coerce_hex_string(fill_raw)
                if fill_hex is None:
                    continue
                fill_hex = fill_hex.upper()

                if fid_upper == "6FC5":
                    # EF.PNN: scan for mandatory tag 80.
                    tag80_found = False
                    i = 0
                    while i + 4 <= len(fill_hex):
                        tag = fill_hex[i: i + 2]
                        tlen = int(fill_hex[i + 2: i + 4], 16)
                        if tag == "80":
                            tag80_found = True
                            break
                        i += 4 + tlen * 2
                    if not tag80_found:
                        self._add(
                            code="YRL-PNN-001",
                            severity="FAIL",
                            spec="3GPP TS 31.102 §4.2.58",
                            path="genericFileManagement.EF.PNN.fillFileContent",
                            message=(
                                "EF.PNN record is missing mandatory tag 0x80 "
                                "(full network name)."
                            ),
                            recommendation="Include a 0x80 TLV carrying the full PLMN network name.",
                            evidence={"fid": fid_upper, "hex_preview": fill_hex[:20]},
                        )

                elif fid_upper == "6FC6":
                    byte_len = len(fill_hex) // 2
                    if byte_len % 8 != 0:
                        self._add(
                            code="YRL-OPL-001",
                            severity="WARN",
                            spec="3GPP TS 31.102 §4.2.59",
                            path="genericFileManagement.EF.OPL.fillFileContent",
                            message=(
                                f"EF.OPL is {byte_len} bytes; must be a multiple "
                                f"of 8 (PLMN 3B + LAC-start 2B + LAC-end 2B + PNN-rec 1B)."
                            ),
                            recommendation="Pad or trim EF.OPL to a multiple of 8 bytes.",
                            evidence={"fid": fid_upper, "byte_length": byte_len},
                        )

    def _check_ef_msisdn_fplmn_ecc_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-MSISDN-* / YRL-FPLMN-* / YRL-ECC-* / YRL-EHPLMN-* / YRL-GID-*:
        ADN record and list-alignment checks for five further EFs.

        - ``YRL-MSISDN-001`` (FAIL): EF.MSISDN record shorter than 14 bytes
          (3GPP TS 31.102 §4.2.26 — ADN record minimum).
        - ``YRL-FPLMN-001`` (WARN): EF.FPLMN length not a multiple of 3 bytes
          (3GPP TS 31.102 §4.2.20 — each entry is 3-byte PLMN BCD).
        - ``YRL-ECC-001`` (WARN): EF.ECC record not a multiple of 4 bytes
          (3GPP TS 31.102 §4.2.21 — each record is 3B BCD number + 1B category).
        - ``YRL-EHPLMN-001`` (WARN): EF.EHPLMN length not a multiple of 3 bytes
          (3GPP TS 31.102 §4.2.84 — same encoding as EF.FPLMN).
        - ``YRL-GID-001`` (WARN): EF.GID1 or EF.GID2 content is all 0xFF bytes
          (3GPP TS 31.102 §4.2.10 / §4.2.11 — not personalised).
        """
        _LIST_CHECKS = {
            "6F7B": ("YRL-FPLMN-001",  "EF.FPLMN",  "WARN", 3, "3GPP TS 31.102 §4.2.20"),
            "6FB7": ("YRL-ECC-001",    "EF.ECC",    "WARN", 4, "3GPP TS 31.102 §4.2.21"),
            "6FD9": ("YRL-EHPLMN-001", "EF.EHPLMN", "WARN", 3, "3GPP TS 31.102 §4.2.84"),
        }
        _GID_FIDS = {"6F3E": "EF.GID1", "6F3F": "EF.GID2"}
        for _pe_type, pe in section_items:
            if not isinstance(pe, dict):
                continue
            file_obj = pe.get("file")
            if not isinstance(file_obj, dict):
                continue
            for cmd in file_obj.get("fileManagementCMD", []):
                block = cmd.get("@") if isinstance(cmd, dict) else None
                if not isinstance(block, list) or len(block) < 2:
                    continue
                params = block[1] if isinstance(block[1], dict) else {}
                fid_raw = params.get("fileID")
                fid_hex = self._coerce_hex_string(fid_raw)
                if fid_hex is None:
                    continue
                fid_upper = fid_hex.upper()
                fill_raw = params.get("fillFileContent")
                fill_hex = self._coerce_hex_string(fill_raw)
                if fill_hex is None:
                    continue
                fill_hex = fill_hex.upper()
                byte_len = len(fill_hex) // 2

                if fid_upper == "6F40":
                    # EF.MSISDN — ADN minimum is 14 bytes.
                    if byte_len < 14:
                        self._add(
                            code="YRL-MSISDN-001",
                            severity="FAIL",
                            spec="3GPP TS 31.102 §4.2.26",
                            path="genericFileManagement.EF.MSISDN.fillFileContent",
                            message=(
                                f"EF.MSISDN record is {byte_len} byte(s); ADN minimum "
                                f"is 14 bytes (ToN/NPI + num-len + BCD 10B + CCP + EXT)."
                            ),
                            recommendation="Encode EF.MSISDN with at least 14 bytes.",
                            evidence={"fid": fid_upper, "byte_length": byte_len},
                        )
                elif fid_upper in _LIST_CHECKS:
                    code, ef_label, sev, modulus, spec = _LIST_CHECKS[fid_upper]
                    if byte_len % modulus != 0:
                        self._add(
                            code=code,
                            severity=sev,
                            spec=spec,
                            path=f"genericFileManagement.{ef_label}.fillFileContent",
                            message=(
                                f"{ef_label} is {byte_len} byte(s); must be a multiple "
                                f"of {modulus} bytes (each entry is {modulus} bytes)."
                            ),
                            recommendation=f"Pad or trim {ef_label} to a multiple of {modulus} bytes.",
                            evidence={"fid": fid_upper, "byte_length": byte_len},
                        )
                elif fid_upper in _GID_FIDS:
                    ef_label = _GID_FIDS[fid_upper]
                    if byte_len > 0 and all(
                        int(fill_hex[i: i + 2], 16) == 0xFF
                        for i in range(0, len(fill_hex), 2)
                    ):
                        self._add(
                            code="YRL-GID-001",
                            severity="WARN",
                            spec="3GPP TS 31.102 §4.2.10",
                            path=f"genericFileManagement.{ef_label}.fillFileContent",
                            message=(
                                f"{ef_label} is all 0xFF — not personalised. "
                                f"Group identifier lock will not function."
                            ),
                            recommendation=f"Set {ef_label} to the intended group identifier byte(s).",
                            evidence={"fid": fid_upper, "byte_length": byte_len},
                        )

    def _check_ef_sms_cbmi_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-SMS-001 / YRL-CBMI-*: EF.SMS record size and CB identifier list alignment.

        - ``YRL-SMS-001`` (FAIL): EF.SMS record not 176 bytes (3GPP TS 31.102 §4.2.16).
        - ``YRL-CBMI-001`` (WARN): EF.CBMI content not a multiple of 2 bytes
          (3GPP TS 31.102 §4.2.14 — each entry is a 2-byte message identifier).
        - ``YRL-CBMI-002`` (WARN): EF.CBMIR content not a multiple of 4 bytes
          (3GPP TS 31.102 §4.2.36 — each range is start 2B + end 2B).
        """
        _TARGETS = {
            "6F3C": ("YRL-SMS-001",  "EF.SMS",   "FAIL", 176, 176, "3GPP TS 31.102 §4.2.16"),
            "6F45": ("YRL-CBMI-001", "EF.CBMI",  "WARN",   2,   2, "3GPP TS 31.102 §4.2.14"),
            "6F50": ("YRL-CBMI-002", "EF.CBMIR", "WARN",   4,   4, "3GPP TS 31.102 §4.2.36"),
        }
        for _pe_type, pe in section_items:
            if not isinstance(pe, dict):
                continue
            file_obj = pe.get("file")
            if not isinstance(file_obj, dict):
                continue
            for cmd in file_obj.get("fileManagementCMD", []):
                block = cmd.get("@") if isinstance(cmd, dict) else None
                if not isinstance(block, list) or len(block) < 2:
                    continue
                params = block[1] if isinstance(block[1], dict) else {}
                fid_raw = params.get("fileID")
                fid_hex = self._coerce_hex_string(fid_raw)
                if fid_hex is None or fid_hex.upper() not in _TARGETS:
                    continue
                code, ef_label, sev, modulus, exact, spec = _TARGETS[fid_hex.upper()]
                fill_raw = params.get("fillFileContent")
                fill_hex = self._coerce_hex_string(fill_raw)
                if fill_hex is None:
                    continue
                byte_len = len(fill_hex) // 2
                if exact == modulus:
                    # Fixed-size check (EF.SMS) vs alignment check (CBMI/CBMIR)
                    is_bad = (byte_len != exact) if ef_label == "EF.SMS" else (byte_len % modulus != 0)
                else:
                    is_bad = byte_len % modulus != 0
                if is_bad:
                    if ef_label == "EF.SMS":
                        msg = (
                            f"{ef_label} record is {byte_len} byte(s); "
                            f"must be exactly 176 (status 1B + TPDU 175B)."
                        )
                        rec = "Ensure EF.SMS is exactly 176 bytes per record."
                    else:
                        msg = (
                            f"{ef_label} is {byte_len} byte(s); must be a multiple "
                            f"of {modulus} (each entry is {modulus} bytes)."
                        )
                        rec = f"Pad or trim {ef_label} to a multiple of {modulus} bytes."
                    self._add(
                        code=code,
                        severity=sev,
                        spec=spec,
                        path=f"genericFileManagement.{ef_label}.fillFileContent",
                        message=msg,
                        recommendation=rec,
                        evidence={"fid": fid_hex.upper(), "byte_length": byte_len},
                    )

    def _check_ef_suci_calc_info(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-SUCI-*: EF.SUCI-CALC-INFO encoding checks (3GPP TS 31.102 §4.4.11.3).

        EF.SUCI-CALC-INFO (FID 4F07) carries the SUCI computation parameters
        used by the ME to conceal the SUPI before transmission.  Key fields:

          Byte 1: Protection Scheme Identifier (PSI)
            0 = null-scheme (IMSI transmitted in the clear)
            1 = Profile A ECIES (X25519 + HKDF-SHA-256)
            2 = Profile B ECIES (NIST P-256 + HKDF-SHA-256)
          Byte 2: Home Network Public Key Identifier
          Bytes 3+: Home Network Public Key (scheme-dependent length)

        - ``YRL-SUCI-001`` (FAIL): Protection Scheme Identifier is not 0, 1, or 2.
        - ``YRL-SUCI-002`` (WARN): PSI ≠ 0 (non-null scheme) but file is shorter
          than 3 bytes — home network public key absent; ME will fall back to
          null-scheme, defeating SUCI privacy.
        - ``YRL-SUCI-003`` (INFO): PSI = 0 (null-scheme) — SUPI transmitted in
          the clear; acceptable for testing but inadvisable in production.
        """
        _EF_SUCI_FID = "4F07"
        _VALID_PSI = {0, 1, 2}
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                if (fd.file_id or "").upper().replace(" ", "") != _EF_SUCI_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                if raw_fill is None:
                    continue
                suci_hex = self._coerce_hex_string(raw_fill)
                if not suci_hex:
                    continue
                suci_hex = suci_hex.upper()
                suci_path = f"{section_key}.ef-suci-calc-info.fillFileContent"
                suci_bytes = len(suci_hex) // 2

                psi = int(suci_hex[:2], 16)

                if psi not in _VALID_PSI:
                    self._add(
                        code="YRL-SUCI-001",
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.4.11.3",
                        path=suci_path,
                        message=(
                            f"EF.SUCI-CALC-INFO Protection Scheme Identifier is 0x{psi:02X}; "
                            "only 0x00 (null), 0x01 (Profile A), and 0x02 (Profile B) are valid."
                        ),
                        recommendation="Set PSI to 0x01 (Profile A) or 0x02 (Profile B) for 5G SUCI privacy.",
                        evidence={"psi": f"0x{psi:02X}", "byte_length": suci_bytes},
                    )
                    continue

                if psi != 0 and suci_bytes < 3:
                    self._add(
                        code="YRL-SUCI-002",
                        severity="WARN",
                        spec="3GPP TS 31.102 §4.4.11.3",
                        path=suci_path,
                        message=(
                            f"EF.SUCI-CALC-INFO PSI=0x{psi:02X} (non-null scheme) "
                            f"but file is only {suci_bytes} byte(s) — "
                            "home network public key is absent; ME will fall back to null-scheme."
                        ),
                        recommendation="Add the home network public key (bytes 3+) for the selected scheme.",
                        evidence={"psi": f"0x{psi:02X}", "byte_length": suci_bytes},
                    )

                if psi == 0:
                    self._add(
                        code="YRL-SUCI-003",
                        severity="INFO",
                        spec="3GPP TS 31.102 §4.4.11.3",
                        path=suci_path,
                        message=(
                            "EF.SUCI-CALC-INFO PSI=0x00 (null-scheme) — "
                            "SUPI will be transmitted in the clear. "
                            "Acceptable for test profiles; not recommended for production."
                        ),
                        recommendation="Use Profile A (0x01) or Profile B (0x02) with a valid HNPK for production.",
                        evidence={"psi": "0x00"},
                    )

    def _check_ef_kc_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-KC-*: EF.KC / EF.KCGPRS byte-length checks (3GPP TS 31.102 §4.2.9b).

        Both files carry a GSM ciphering-key context: 8-byte Kc + 1-byte CKSN
        (Ciphering Key Sequence Number) = 9 bytes total.  A wrong size causes
        the ME to invalidate the key store, forcing re-authentication.

        - ``YRL-KC-001`` (FAIL): EF.KC (4F20) is not exactly 9 bytes.
        - ``YRL-KC-002`` (FAIL): EF.KCGPRS (4F52) is not exactly 9 bytes.
        """
        _KC_SIZE = 9
        _targets = [
            ("4F20", "YRL-KC-001", "EF.KC",     "ef-kc"),
            ("4F52", "YRL-KC-002", "EF.KCGPRS", "ef-kcgprs"),
        ]
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fid, code, ef_name, ef_key in _targets:
                for fd in file_defs:
                    if fd.section_key != section_key:
                        continue
                    if (fd.file_id or "").upper().replace(" ", "") != fid:
                        continue
                    raw_fill = fd.payload.get("fillFileContent")
                    if raw_fill is None:
                        continue
                    kc_hex = self._coerce_hex_string(raw_fill)
                    if not kc_hex:
                        continue
                    kc_bytes = len(kc_hex) // 2
                    if kc_bytes == _KC_SIZE:
                        continue
                    self._add(
                        code=code,
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.2.9b",
                        path=f"{section_key}.{ef_key}.fillFileContent",
                        message=(
                            f"{ef_name} is {kc_bytes} byte(s); the specification "
                            f"requires exactly {_KC_SIZE} bytes (Kc 8B + CKSN 1B)."
                        ),
                        recommendation=f"Re-encode {ef_name} as exactly {_KC_SIZE} bytes.",
                        evidence={"hex": kc_hex[:18], "byte_length": kc_bytes},
                    )

    def _check_ef_start_hfn_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-STARTHFN-001: EF.START-HFN byte-length check (3GPP TS 31.102 §4.2.40).

        EF.START-HFN (FID 6F5B) carries the RRC HFN start values for CS and PS
        domains: START-CS (3B) + START-PS (3B) = 6 bytes total.  A wrong size
        prevents UTRAN cipher initialisation (TS 33.102 §6.6.2).

        - ``YRL-STARTHFN-001`` (FAIL): EF.START-HFN is not exactly 6 bytes.
        """
        _EF_STARTHFN_FID = "6F5B"
        _STARTHFN_SIZE = 6
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                if (fd.file_id or "").upper().replace(" ", "") != _EF_STARTHFN_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                if raw_fill is None:
                    continue
                hfn_hex = self._coerce_hex_string(raw_fill)
                if not hfn_hex:
                    continue
                hfn_bytes = len(hfn_hex) // 2
                if hfn_bytes == _STARTHFN_SIZE:
                    continue
                self._add(
                    code="YRL-STARTHFN-001",
                    severity="FAIL",
                    spec="3GPP TS 31.102 §4.2.40",
                    path=f"{section_key}.ef-start-hfn.fillFileContent",
                    message=(
                        f"EF.START-HFN is {hfn_bytes} byte(s); the specification "
                        f"requires exactly {_STARTHFN_SIZE} bytes (START-CS 3B + START-PS 3B)."
                    ),
                    recommendation=f"Re-encode EF.START-HFN as exactly {_STARTHFN_SIZE} bytes.",
                    evidence={"hex": hfn_hex[:12], "byte_length": hfn_bytes},
                )

    def _check_ef_epsnsc_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-EPSNSC-001: EF.EPSNSC byte-length check (3GPP TS 31.102 §4.2.77).

        EF.EPSNSC (FID 6FE4) must be exactly 54 bytes.  An incorrect size causes
        the ME to discard the EPS NAS security context, forcing full re-authentication
        on every attach — a significant impact on IoT devices with large attach cycles.

        - ``YRL-EPSNSC-001`` (FAIL): EF.EPSNSC is not exactly 54 bytes.
        """
        _EF_EPSNSC_FID = "6FE4"
        _EPSNSC_SIZE = 54
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                if (fd.file_id or "").upper().replace(" ", "") != _EF_EPSNSC_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                if raw_fill is None:
                    continue
                epsnsc_hex = self._coerce_hex_string(raw_fill)
                if not epsnsc_hex:
                    continue
                epsnsc_bytes = len(epsnsc_hex) // 2
                if epsnsc_bytes == _EPSNSC_SIZE:
                    continue
                self._add(
                    code="YRL-EPSNSC-001",
                    severity="FAIL",
                    spec="3GPP TS 31.102 §4.2.77",
                    path=f"{section_key}.ef-epsnsc.fillFileContent",
                    message=(
                        f"EF.EPSNSC is {epsnsc_bytes} byte(s); the specification "
                        f"requires exactly {_EPSNSC_SIZE} bytes."
                    ),
                    recommendation=f"Re-encode EF.EPSNSC as exactly {_EPSNSC_SIZE} bytes.",
                    evidence={"hex": epsnsc_hex[:20], "byte_length": epsnsc_bytes},
                )

    def _check_ef_keys_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-KEYS-*: EF.KEYS and EF.KEYSPS byte-length checks (3GPP TS 31.102 §4.2.9).

        Both files must be exactly 33 bytes: 1-byte key set identifier +
        16-byte CK (Cipher Key) + 16-byte IK (Integrity Key).  A wrong size
        causes the ME to discard the key context, forcing a full re-authentication
        on the next attach and blocking handover cipher continuity.

        - ``YRL-KEYS-001`` (FAIL): EF.KEYS (6F08) is not exactly 33 bytes.
        - ``YRL-KEYS-002`` (FAIL): EF.KEYSPS (6F09) is not exactly 33 bytes.
        """
        _EF_KEYS_FID   = "6F08"
        _EF_KEYSPS_FID = "6F09"
        _KEYS_SIZE = 33
        file_defs = self._extract_file_definitions(section_items)

        _targets = [
            (_EF_KEYS_FID,   "YRL-KEYS-001", "EF.KEYS",   "6F08", "ef-keys"),
            (_EF_KEYSPS_FID, "YRL-KEYS-002", "EF.KEYSPS", "6F09", "ef-keysps"),
        ]

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fid, code, ef_name, fid_label, ef_key in _targets:
                for fd in file_defs:
                    if fd.section_key != section_key:
                        continue
                    if (fd.file_id or "").upper().replace(" ", "") != fid:
                        continue
                    raw_fill = fd.payload.get("fillFileContent")
                    if raw_fill is None:
                        continue
                    keys_hex = self._coerce_hex_string(raw_fill)
                    if not keys_hex:
                        continue
                    keys_bytes = len(keys_hex) // 2
                    if keys_bytes == _KEYS_SIZE:
                        continue
                    self._add(
                        code=code,
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.2.9",
                        path=f"{section_key}.{ef_key}.fillFileContent",
                        message=(
                            f"{ef_name} is {keys_bytes} byte(s); the specification "
                            f"requires exactly {_KEYS_SIZE} bytes "
                            "(KSI 1B + CK 16B + IK 16B)."
                        ),
                        recommendation=f"Re-encode {ef_name} as exactly {_KEYS_SIZE} bytes.",
                        evidence={"hex": keys_hex[:10], "byte_length": keys_bytes},
                    )

    def _check_ef_loci_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-LOCI-*: EF.LOCI byte-length check (3GPP TS 31.102 §4.2.7).

        EF.LOCI (FID 6F7E) must be exactly 11 bytes.  A wrong size causes ME
        rejection of the file and prevents GSM/UMTS location registration.

        - ``YRL-LOCI-001`` (FAIL): EF.LOCI is not exactly 11 bytes.
        """
        _EF_LOCI_FID = "6F7E"
        _LOCI_SIZE = 11
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                if (fd.file_id or "").upper().replace(" ", "") != _EF_LOCI_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                if raw_fill is None:
                    continue
                loci_hex = self._coerce_hex_string(raw_fill)
                if not loci_hex:
                    continue
                loci_bytes = len(loci_hex) // 2
                if loci_bytes == _LOCI_SIZE:
                    continue
                self._add(
                    code="YRL-LOCI-001",
                    severity="FAIL",
                    spec="3GPP TS 31.102 §4.2.7",
                    path=f"{section_key}.ef-loci.fillFileContent",
                    message=(
                        f"EF.LOCI is {loci_bytes} byte(s); the specification "
                        f"requires exactly {_LOCI_SIZE} bytes "
                        "(TMSI 4B + LAI 5B + RFU 1B + LUS 1B)."
                    ),
                    recommendation=f"Re-encode EF.LOCI as exactly {_LOCI_SIZE} bytes.",
                    evidence={"hex": loci_hex[:22], "byte_length": loci_bytes},
                )

    def _check_ef_epsloci_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-EPSLOCI-*: EF.EPSLOCI byte-length check (3GPP TS 31.102 §4.2.76).

        EF.EPSLOCI (FID 6FE3) must be exactly 18 bytes.  A wrong size blocks
        EPS (LTE) location registration.

        - ``YRL-EPSLOCI-001`` (FAIL): EF.EPSLOCI is not exactly 18 bytes.
        """
        _EF_EPSLOCI_FID = "6FE3"
        _EPSLOCI_SIZE = 18
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                if (fd.file_id or "").upper().replace(" ", "") != _EF_EPSLOCI_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                if raw_fill is None:
                    continue
                epsloci_hex = self._coerce_hex_string(raw_fill)
                if not epsloci_hex:
                    continue
                epsloci_bytes = len(epsloci_hex) // 2
                if epsloci_bytes == _EPSLOCI_SIZE:
                    continue
                self._add(
                    code="YRL-EPSLOCI-001",
                    severity="FAIL",
                    spec="3GPP TS 31.102 §4.2.76",
                    path=f"{section_key}.ef-epsloci.fillFileContent",
                    message=(
                        f"EF.EPSLOCI is {epsloci_bytes} byte(s); the specification "
                        f"requires exactly {_EPSLOCI_SIZE} bytes "
                        "(GUTI 10B + Last Visited TAI 5B + EPS Update Status 1B + RFU 2B)."
                    ),
                    recommendation=f"Re-encode EF.EPSLOCI as exactly {_EPSLOCI_SIZE} bytes.",
                    evidence={"hex": epsloci_hex[:36], "byte_length": epsloci_bytes},
                )

    def _check_ef_est_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-EST-*: EF.EST encoding and UST coherence (3GPP TS 31.102 §4.2.46).

        EF.EST (FID 6F56) holds enabled-service toggle bits.  Each bit that is
        set means the ME treats the corresponding service as **active** rather
        than merely *available*.  If a bit is set in EF.EST for a service that
        is not marked available in the UST, the ME will never engage the feature
        regardless of the EST bit value.

        - ``YRL-EST-001`` (FAIL): EF.EST content is empty (no bytes).
        - ``YRL-EST-002`` (WARN): a bit is set in EF.EST for a UST service that
          is not available (or cannot be determined from UST) — service will
          never activate on this profile.
        """
        _EF_EST_FID = "6F56"
        # EF.EST bit-index (0-based, LSB) → UST service number (1-based).
        # 3GPP TS 31.102 §4.2.46, Table 13.
        _EST_BIT_TO_UST_SERVICE = {
            0: 2,   # FDN
            1: 6,   # BDN
            2: 17,  # ACL
            3: 33,  # DCK
            4: 90,  # Emergency Call Codes
        }

        file_defs = self._extract_file_definitions(section_items)
        ust_bits: list[int] | None = self._extract_service_bits_from_payload(
            section_items, service_name="ust"
        )

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                if (fd.file_id or "").upper().replace(" ", "") != _EF_EST_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                if raw_fill is None:
                    continue
                est_hex_raw = self._coerce_hex_string(raw_fill)
                est_hex = (est_hex_raw or "").upper()
                est_path = f"{section_key}.ef-est.fillFileContent"

                if len(est_hex) == 0:
                    self._add(
                        code="YRL-EST-001",
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.2.46",
                        path=est_path,
                        message="EF.EST content is empty — no enabled-service toggle bytes present.",
                        recommendation="Provide at least 1 byte for EF.EST (e.g. 0x00 if no services are enabled).",
                        evidence={"hex": est_hex},
                    )
                    continue

                est_bytes = [int(est_hex[i:i+2], 16) for i in range(0, len(est_hex), 2)]

                for bit_index, ust_service in _EST_BIT_TO_UST_SERVICE.items():
                    byte_pos = bit_index // 8
                    bit_pos  = bit_index % 8
                    if byte_pos >= len(est_bytes):
                        continue
                    bit_active = bool(est_bytes[byte_pos] & (1 << bit_pos))
                    if not bit_active:
                        continue
                    if ust_bits is None:
                        continue
                    ust_available = self._service_bit_is_set(ust_bits, ust_service)
                    if ust_available:
                        continue
                    self._add(
                        code="YRL-EST-002",
                        severity="WARN",
                        spec="3GPP TS 31.102 §4.2.46",
                        path=est_path,
                        message=(
                            f"EF.EST bit {bit_index} (UST service {ust_service}) is set "
                            f"but UST service {ust_service} is not available — "
                            "the ME will never activate this feature."
                        ),
                        recommendation=(
                            f"Either enable UST service {ust_service} or clear "
                            f"EF.EST bit {bit_index}."
                        ),
                        evidence={
                            "est_byte": f"0x{est_bytes[byte_pos]:02X}",
                            "bit_index": bit_index,
                            "ust_service": ust_service,
                        },
                    )

    def _check_ef_spn_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-SPN-*: EF.SPN byte-level encoding checks (3GPP TS 31.102 §4.2.12).

        EF.SPN (FID 6F46) is exactly 17 bytes:
          Byte 1: display-conditions bitmask (bits 0–1 defined, rest reserved/0).
          Bytes 2–17: operator name, GSM7 or UCS2 default alphabet, unused bytes = 0xFF.

        - ``YRL-SPN-001`` (FAIL): EF.SPN is not exactly 17 bytes.
        - ``YRL-SPN-002`` (WARN): display-conditions byte has reserved bits 2–7 set.
        - ``YRL-SPN-003`` (WARN): bytes 2–17 are all 0xFF — operator name not configured.
        """
        _EF_SPN_FID = "6F46"
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                if (fd.file_id or "").upper().replace(" ", "") != _EF_SPN_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                spn_hex = self._coerce_hex_string(raw_fill)
                if spn_hex is None:
                    continue
                spn_hex = spn_hex.upper()
                spn_path = f"{section_key}.ef-spn.fillFileContent"
                spn_bytes = len(spn_hex) // 2

                if spn_bytes != 17:
                    self._add(
                        code="YRL-SPN-001",
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.2.12",
                        path=spn_path,
                        message=(
                            f"EF.SPN is {spn_bytes} byte(s); the specification "
                            "requires exactly 17 bytes (1 display-conditions + 16 name)."
                        ),
                        recommendation="Re-encode EF.SPN as exactly 17 bytes, padding the name with 0xFF.",
                        evidence={"hex": spn_hex[:34], "byte_length": spn_bytes},
                    )
                    continue

                disp_byte = int(spn_hex[:2], 16)
                reserved_bits = disp_byte & 0xFC
                if reserved_bits != 0:
                    self._add(
                        code="YRL-SPN-002",
                        severity="WARN",
                        spec="3GPP TS 31.102 §4.2.12",
                        path=spn_path,
                        message=(
                            f"EF.SPN display-conditions byte is 0x{disp_byte:02X}; "
                            "bits 2–7 are reserved and should be zero."
                        ),
                        recommendation="Clear reserved bits 2–7 in the display-conditions byte.",
                        evidence={"display_conditions": f"0x{disp_byte:02X}"},
                    )

                name_hex = spn_hex[2:]
                if all(c == "F" for c in name_hex):
                    self._add(
                        code="YRL-SPN-003",
                        severity="WARN",
                        spec="3GPP TS 31.102 §4.2.12",
                        path=spn_path,
                        message=(
                            "EF.SPN name bytes (2–17) are all 0xFF — "
                            "operator name is not configured."
                        ),
                        recommendation="Set bytes 2–17 to the operator name in GSM7 or UCS2 encoding.",
                        evidence={"name_hex": name_hex[:16] + "…"},
                    )

    def _check_ef_smsp_encoding(self, section_items: list[tuple[str, Any]]) -> None:
        """YRL-SMSP-*: EF.SMSP record length check (3GPP TS 31.102 §4.2.27).

        EF.SMSP (FID 6F42) is a linear-fixed EF; each record must be at least
        28 bytes (the mandatory header fields).  Records shorter than this
        indicate a truncated or incorrectly sized SMSP record which will cause
        SMS origination failures on some ME implementations.

        - ``YRL-SMSP-001`` (FAIL): a record is shorter than 28 bytes.
        - ``YRL-SMSP-002`` (WARN): the SMSC address length byte (byte 2)
          indicates a dialling number longer than 20 digits (max SC address
          in E.164 / TS 31.102).
        """
        _EF_SMSP_FID = "6F42"
        file_defs = self._extract_file_definitions(section_items)

        for section_key, payload in section_items:
            if self._base_type_from_key(section_key).lower() not in ("usim", "opt-usim"):
                continue
            for fd in file_defs:
                if fd.section_key != section_key:
                    continue
                if (fd.file_id or "").upper().replace(" ", "") != _EF_SMSP_FID:
                    continue
                raw_fill = fd.payload.get("fillFileContent")
                smsp_hex = self._coerce_hex_string(raw_fill)
                if smsp_hex is None:
                    continue
                smsp_hex = smsp_hex.upper()
                smsp_path = f"{section_key}.ef-smsp.fillFileContent"
                smsp_bytes = len(smsp_hex) // 2

                if smsp_bytes < 28:
                    self._add(
                        code="YRL-SMSP-001",
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.2.27",
                        path=smsp_path,
                        message=(
                            f"EF.SMSP record is {smsp_bytes} byte(s); "
                            "the minimum is 28 bytes (3GPP TS 31.102 §4.2.27)."
                        ),
                        recommendation="Ensure each SMSP record is at least 28 bytes.",
                        evidence={"hex": smsp_hex[:56], "byte_length": smsp_bytes},
                    )
                    continue

                # Byte 2 (index 2) = SMSC address length in the service centre
                # address field.  0xFF means "SC address not set" — skip.
                # Maximum valid E.164 SC address is 11 bytes (ToN/NPI + 10 BCD).
                sc_len = int(smsp_hex[2:4], 16)
                if sc_len != 0xFF and sc_len > 11:
                    self._add(
                        code="YRL-SMSP-002",
                        severity="WARN",
                        spec="3GPP TS 31.102 §4.2.27 / ITU-T E.164",
                        path=smsp_path,
                        message=(
                            f"EF.SMSP SC address length byte is 0x{sc_len:02X} ({sc_len}); "
                            "maximum is 11 (10 BCD digits + ToN/NPI byte). "
                            "Some ME implementations reject SMSP records with "
                            "an oversized SC address length."
                        ),
                        recommendation="Correct the SC address length byte to at most 0x0B.",
                        evidence={"sc_len_byte": f"0x{sc_len:02X}"},
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

    def _check_connectivity_parameters(self, sections: dict[str, Any]) -> None:
        """YRL-HDR-002/-003/-004: profile header connectivityParameters checks.

        When present, ``connectivityParameters`` carries BIP / CAT-TP bearer
        configuration (ETSI TS 102 223 §8.52 / GSMA TS.48 §7.2).  Checks:

        - ``YRL-HDR-002`` (WARN): a sub-field value is not valid hex.
        - ``YRL-HDR-003`` (WARN): ``port`` or ``portNumber`` value outside
          the registered IANA port range 1..65535.
        - ``YRL-HDR-004`` (INFO): ``transportProtocol`` byte is not one of
          the TS 102 223 §8.52 registered values (0x02 UDP, 0x03 TCP).
        """
        header = self._first_section_by_type(sections, "header")
        if not isinstance(header, dict):
            return
        conn = header.get("connectivityParameters")
        if not isinstance(conn, dict) or len(conn) == 0:
            return

        for sub_key, sub_val in conn.items():
            sub_hex = self._coerce_hex_string(sub_val)
            if sub_hex is None:
                # Non-hex sub-fields are not always wrong, but flag if the
                # value is a non-empty string that does not parse as hex.
                if isinstance(sub_val, str) and len(sub_val.strip()) > 0:
                    self._add(
                        code="YRL-HDR-002",
                        severity="WARN",
                        spec="ETSI TS 102 223 §8.52",
                        path=f"header.connectivityParameters.{sub_key}",
                        message=(
                            f"connectivityParameters.{sub_key} value is not valid hex: "
                            f"{repr(sub_val[:40])}."
                        ),
                        recommendation="Encode connectivityParameters sub-fields as hex byte strings.",
                        evidence={"sub_key": sub_key, "raw_value": str(sub_val)[:40]},
                    )
                continue

            lk = sub_key.lower().replace("-", "").replace("_", "")

            # Port-number range check — TS 102 223 §8.52 encodes port as
            # a 2-byte big-endian integer; valid IANA range 1..65535.
            if lk in ("port", "portnumber", "destinationport", "localport"):
                if self._looks_like_hex(sub_hex):
                    port_int = int(sub_hex, 16)
                    if port_int == 0 or port_int > 65535:
                        self._add(
                            code="YRL-HDR-003",
                            severity="WARN",
                            spec="ETSI TS 102 223 §8.52 / IANA",
                            path=f"header.connectivityParameters.{sub_key}",
                            message=(
                                f"connectivityParameters.{sub_key}=0x{sub_hex} "
                                f"({port_int}) is outside the valid port range 1..65535."
                            ),
                            recommendation="Use a valid IANA port number (e.g. 0x0AF0 for OTA port 2800).",
                            evidence={"sub_key": sub_key, "port_value": port_int},
                        )

            # Transport-protocol byte — TS 102 223 §8.52 table:
            # 0x02 = UDP, 0x03 = TCP (most common for BIP OTA)
            if lk in ("transportprotocol", "protocol", "transportlayerprotocol"):
                if self._looks_like_hex(sub_hex):
                    proto = int(sub_hex, 16)
                    if proto not in (0x02, 0x03):
                        self._add(
                            code="YRL-HDR-004",
                            severity="INFO",
                            spec="ETSI TS 102 223 §8.52",
                            path=f"header.connectivityParameters.{sub_key}",
                            message=(
                                f"connectivityParameters.{sub_key}=0x{sub_hex} ({proto}) "
                                "is not a TS 102 223 §8.52 registered transport protocol "
                                "(0x02=UDP, 0x03=TCP)."
                            ),
                            recommendation="Use 0x02 (UDP) or 0x03 (TCP) unless the eUICC platform "
                                "documents a proprietary extension.",
                            evidence={"sub_key": sub_key, "protocol_byte": proto},
                        )

    # ------------------------------------------------------------------
    # Cross-PE consistency checks (ICCID / IMSI)
    #
    # ETSI TS 102 221 §13.2 stores EF.ICCID as a nibble-swapped BCD
    # bytestring matching the SAIP header's iccid field byte-for-byte.
    # 3GPP TS 31.102 §4.2.2 stores EF.IMSI with a parity-aware
    # length-prefixed encoding: byte 0 = body length (0x08 for a
    # standard 6..15 digit IMSI), byte 1 = ``(first_digit << 4) |
    # parity`` where parity = 0x1 for odd-digit IMSIs and 0x9 for
    # even-digit IMSIs, then 7 nibble-swapped BCD bytes with optional
    # ``F`` filler in the trailing nibble. Both encodings are easy to
    # get wrong by hand-editing template scaffolding, and the failure
    # mode (eUICC rejecting the profile, or worse: MNO rejecting
    # registration) is operationally expensive — the linter keeps the
    # operator on the rails.
    # ------------------------------------------------------------------

    def _check_iccid_consistency(
        self,
        sections: dict[str, Any],
        section_items: list[tuple[str, Any]],
    ) -> None:
        header = self._first_section_by_type(sections, "header")
        if isinstance(header, dict) is False:
            return
        header_hex = self._coerce_hex_string(header.get("iccid"))
        if header_hex is None:
            return

        # Walk the MF section first; fall back to any section that
        # carries an ef-iccid. Profiles in the wild almost always put
        # EF.ICCID under MF (TS 102 221 §13.2) but the linter stays
        # tolerant of loaders that hoist it elsewhere.
        ef_iccid_pairs: list[tuple[str, str]] = []
        for section_key, payload in section_items:
            for path, value in self._walk_with_choice_paths(payload):
                lowered = path.lower()
                if "ef-iccid" not in lowered:
                    continue
                if not lowered.endswith(".fillfilecontent"):
                    continue
                hex_text = self._coerce_hex_string(value)
                if hex_text is None:
                    continue
                ef_iccid_pairs.append((section_key, hex_text))

        if len(ef_iccid_pairs) == 0:
            return

        # The SAIP profile header stores ICCID as printable-order BCD
        # (high nibble = first digit), while EF.ICCID file content is
        # the nibble-swapped on-disk SIM form (TS 102 221 §13.2). To
        # compare semantically we decode both into a digit string and
        # match those, ignoring trailing 0xF filler in either side.
        header_digits = self._iccid_digits_from_printable_hex(header_hex)
        for section_key, ef_hex in ef_iccid_pairs:
            ef_digits = self._iccid_digits_from_swapped_hex(ef_hex)
            if header_digits == ef_digits:
                continue
            self._add(
                code="YRL-ICC-010",
                severity="FAIL",
                spec="ETSI TS 102 221 §13.2",
                path=f"{section_key}.ef-iccid.fillFileContent",
                message=(
                    "ICCID mismatch: header.iccid (printable BCD) and "
                    "EF.ICCID fillFileContent (nibble-swapped BCD) "
                    "decode to different digit strings."
                ),
                recommendation=(
                    "The header carries ICCID in printable BCD; the EF "
                    "carries it nibble-swapped (TS 102 221 §13.2). "
                    "Re-encode one from the other so both decode to "
                    "the same printable ICCID string."
                ),
                evidence={
                    "header_iccid_hex": header_hex.upper(),
                    "ef_iccid_hex": ef_hex.upper(),
                    "header_iccid_digits": header_digits,
                    "ef_iccid_digits": ef_digits,
                },
            )

    def _check_imsi_encoding(
        self,
        section_items: list[tuple[str, Any]],
    ) -> None:
        for section_key, payload in section_items:
            section_lo = self._base_type_from_key(section_key).lower()
            if section_lo not in ("usim", "opt-usim", "isim", "opt-isim"):
                continue
            for path, value in self._walk_with_choice_paths(payload):
                lowered = path.lower()
                if "ef-imsi" not in lowered:
                    continue
                if not lowered.endswith(".fillfilecontent"):
                    continue
                hex_text = self._coerce_hex_string(value)
                if hex_text is None:
                    continue
                self._validate_ef_imsi_bytes(section_key, path, hex_text)

    def _validate_ef_imsi_bytes(
        self,
        section_key: str,
        field_path: str,
        hex_text: str,
    ) -> None:
        full_path = f"{section_key}.{field_path}"
        if len(hex_text) != 18:
            self._add(
                code="YRL-IMS-001",
                severity="FAIL",
                spec="3GPP TS 31.102 §4.2.2",
                path=full_path,
                message=(
                    f"EF.IMSI is {len(hex_text) // 2} octets; the SIM "
                    f"specification requires exactly 9 octets "
                    f"(1 length byte + 8 body bytes)."
                ),
                recommendation=(
                    "Re-encode EF.IMSI as 9 octets: first octet = 0x08, "
                    "then byte = (first-digit << 4) | parity, then 7 "
                    "nibble-swapped BCD bytes (filler nibble 0xF allowed "
                    "in the trailing position)."
                ),
                evidence={"hex": hex_text.upper()},
            )
            return

        body = hex_text.upper()
        length_byte = int(body[0:2], 16)
        if length_byte != 0x08:
            self._add(
                code="YRL-IMS-002",
                severity="FAIL",
                spec="3GPP TS 31.102 §4.2.2",
                path=full_path,
                message=(
                    f"EF.IMSI length-byte is 0x{length_byte:02X}; the "
                    f"specification requires 0x08 (length of the body "
                    f"that follows)."
                ),
                recommendation="Set the first octet of EF.IMSI to 0x08.",
                evidence={"hex": body},
            )
            return

        parity_byte = int(body[2:4], 16)
        parity_nibble = parity_byte & 0x0F
        first_digit = (parity_byte >> 4) & 0x0F
        if parity_nibble not in (0x1, 0x9):
            self._add(
                code="YRL-IMS-003",
                severity="FAIL",
                spec="3GPP TS 31.102 §4.2.2",
                path=full_path,
                message=(
                    f"EF.IMSI parity nibble is 0x{parity_nibble:X}; the "
                    f"specification only allows 0x1 (odd digit count) "
                    f"or 0x9 (even digit count). A missing parity "
                    f"nibble is the most common cause of 'authentication "
                    f"failed' on first attach."
                ),
                recommendation=(
                    "Re-encode the parity-aware byte as "
                    "(first_digit << 4) | (1 if odd_imsi_length else 9)."
                ),
                evidence={
                    "hex": body,
                    "parity_byte": f"0x{parity_byte:02X}",
                    "low_nibble": f"0x{parity_nibble:X}",
                },
            )
            return

        if first_digit > 9:
            self._add(
                code="YRL-IMS-004",
                severity="FAIL",
                spec="3GPP TS 31.102 §4.2.2",
                path=full_path,
                message=(
                    f"EF.IMSI first-digit nibble is 0x{first_digit:X}; "
                    f"only decimal digits 0..9 are allowed in BCD."
                ),
                recommendation=(
                    "Encode each IMSI digit as 0x0..0x9; the high "
                    "nibble of byte 1 carries the first digit."
                ),
                evidence={"hex": body, "high_nibble": f"0x{first_digit:X}"},
            )
            return

        # Decode digits.
        rest_pairs = body[4:]
        digits = [str(first_digit)]
        for offset in range(0, len(rest_pairs), 2):
            byte_hex = rest_pairs[offset:offset + 2]
            high = int(byte_hex[0], 16)
            low = int(byte_hex[1], 16)
            for nibble in (low, high):
                if nibble == 0xF:
                    continue
                if nibble > 9:
                    self._add(
                        code="YRL-IMS-004",
                        severity="FAIL",
                        spec="3GPP TS 31.102 §4.2.2",
                        path=full_path,
                        message=(
                            f"EF.IMSI BCD digit nibble 0x{nibble:X} "
                            f"is not a decimal 0..9."
                        ),
                        recommendation="Use BCD digits 0..9 (filler 0xF allowed only in the trailing nibble).",
                        evidence={"hex": body, "bad_nibble": f"0x{nibble:X}"},
                    )
                    return
                digits.append(str(nibble))

        digit_count = len(digits)
        expected_parity = 0x1 if (digit_count % 2 == 1) else 0x9
        if expected_parity != parity_nibble:
            self._add(
                code="YRL-IMS-005",
                severity="FAIL",
                spec="3GPP TS 31.102 §4.2.2",
                path=full_path,
                message=(
                    f"EF.IMSI parity nibble 0x{parity_nibble:X} does "
                    f"not match the {digit_count}-digit IMSI "
                    f"(expected 0x{expected_parity:X})."
                ),
                recommendation=(
                    "Set parity = 0x1 for odd digit counts (standard "
                    "15-digit IMSIs) or 0x9 for even digit counts."
                ),
                evidence={
                    "hex": body,
                    "imsi_digits": "".join(digits),
                    "digit_count": digit_count,
                    "parity_nibble": f"0x{parity_nibble:X}",
                    "expected_parity": f"0x{expected_parity:X}",
                },
            )
            return

        if digit_count < 6 or digit_count > 15:
            self._add(
                code="YRL-IMS-006",
                severity="WARN",
                spec="3GPP TS 23.003 §2.2",
                path=full_path,
                message=(
                    f"EF.IMSI carries {digit_count} digits; "
                    f"3GPP TS 23.003 §2.2 mandates 6..15 digits."
                ),
                recommendation="Verify the IMSI digit count is in the 6..15 range.",
                evidence={"imsi": "".join(digits)},
            )
            return

        if digit_count != 15:
            # Common but unusual — keep as INFO so the operator sees
            # the surface without it raising the gate.
            self._add(
                code="YRL-IMS-007",
                severity="INFO",
                spec="3GPP TS 23.003 §2.2",
                path=full_path,
                message=(
                    f"EF.IMSI is {digit_count} digits long; the "
                    f"common case is 15. Spec allows 6..15."
                ),
                recommendation="Confirm short IMSIs are intentional for this profile.",
                evidence={"imsi": "".join(digits)},
            )

    @staticmethod
    def _coerce_hex_string(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, bytes) or isinstance(value, bytearray):
            return value.hex().upper()
        if isinstance(value, dict):
            inner = value.get("hex")
            if isinstance(inner, str) and len(inner) > 0:
                return inner.replace(" ", "").upper()
            return None
        if isinstance(value, str):
            compact = value.replace(" ", "")
            if len(compact) == 0:
                return None
            if len(compact) % 2 != 0:
                return None
            try:
                int(compact, 16)
            except ValueError:
                return None
            return compact.upper()
        return None

    @staticmethod
    def _iccid_digits_from_swapped_hex(hex_text: str) -> str:
        """Decode an EF.ICCID byte string (nibble-swapped BCD) to its
        printable ICCID digit string.

        TS 102 221 §13.2 stores EF.ICCID with each byte's nibbles
        swapped relative to the printed digit pair. Trailing 0xF filler
        nibbles are dropped. Non-decimal nibbles (other than the
        terminal filler) are preserved upper-cased so an evidence
        panel can flag them.
        """
        if not isinstance(hex_text, str) or len(hex_text) == 0:
            return ""
        compact = hex_text.replace(" ", "").upper()
        if len(compact) % 2 != 0:
            return compact
        out: list[str] = []
        for offset in range(0, len(compact), 2):
            pair = compact[offset:offset + 2]
            out.append(pair[1])
            out.append(pair[0])
        joined = "".join(out)
        return joined.rstrip("F")

    @staticmethod
    def _iccid_digits_from_printable_hex(hex_text: str) -> str:
        """Decode a printable-order BCD ICCID hex string to digits.

        SAIP's header.iccid is stored unswapped: the high nibble of
        each byte is the higher-order digit of the pair. Filler 0xF
        nibbles are stripped from the trailing position so a
        19-digit ICCID compares equal to a 20-nibble FX-padded one.
        """
        if not isinstance(hex_text, str) or len(hex_text) == 0:
            return ""
        return hex_text.replace(" ", "").upper().rstrip("F")

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

    def _check_gfm_sequences(self, sections: dict[str, Any]) -> None:
        """YRL-GFM-*: GFM command-block sequence coherence checks.

        Each ``genericFileManagement`` PE contains a ``fileManagementCMD``
        list; each element is a sequence of CHOICE tuples that describe
        a single TS 102 222 file-admin transaction.  Rules:

        - ``YRL-GFM-001`` (WARN): a ``fillFileContent`` or
          ``fillFileOffset`` op appears without a preceding ``filePath``
          or ``createFCP`` op in the same command block — the target
          file is unspecified so the UICC cannot apply the write.
        - ``YRL-GFM-002`` (INFO): a ``createFCP`` op is followed by
          another ``createFCP`` in the same block without an intervening
          ``fillFileContent`` — the second create will typically fail
          because no data was written to the first file.
        - ``YRL-GFM-003`` (INFO): an empty command block (zero ops) is
          present — it has no effect and can be removed.
        """
        for section_key, payload in sections.items():
            if self._base_type_from_key(section_key) != "genericFileManagement":
                continue
            if not isinstance(payload, dict):
                continue
            file_node = payload.get("file") or payload
            cmd_list = None
            if isinstance(file_node, dict):
                cmd_list = file_node.get("fileManagementCMD")
            if not isinstance(cmd_list, list):
                cmd_list = payload.get("fileManagementCMD")
            if not isinstance(cmd_list, list):
                continue
            for blk_idx, block in enumerate(cmd_list):
                ops = block if isinstance(block, list) else [block]
                self._lint_gfm_block(section_key, blk_idx, ops)

    def _gfm_op_name(self, op: Any) -> str:
        """Extract the CHOICE tuple name from a GFM op entry."""
        if isinstance(op, dict):
            tpl = op.get("@") or op.get("__ygg_saip_tuple__")
            if isinstance(tpl, list) and len(tpl) >= 1:
                return str(tpl[0]).lower()
        if isinstance(op, list) and len(op) >= 1:
            return str(op[0]).lower()
        return ""

    def _lint_gfm_block(
        self,
        section_key: str,
        blk_idx: int,
        ops: list[Any],
    ) -> None:
        _CREATE_OPS = frozenset(["createfcp", "createfile"])
        _PATH_OPS   = frozenset(["filepath", "createfcp", "createfile"])
        _WRITE_OPS  = frozenset(["fillfilecontent", "fillfileoffset"])

        path_base = f"{section_key}.fileManagementCMD[{blk_idx}]"

        real_ops = [o for o in ops if o is not None]
        if len(real_ops) == 0:
            self._add(
                code="YRL-GFM-003",
                severity="INFO",
                spec="TS 102 222",
                path=path_base,
                message=f"GFM block [{blk_idx}] is empty (zero ops) — has no effect.",
                recommendation="Remove empty command blocks to keep the GFM PE compact.",
            )
            return

        last_was_create = False
        has_path_op = False
        for op_idx, op in enumerate(real_ops):
            name = self._gfm_op_name(op)
            if not name:
                continue

            if name in _PATH_OPS:
                has_path_op = True
                last_was_create = name in _CREATE_OPS

            elif name in _WRITE_OPS:
                if not has_path_op:
                    self._add(
                        code="YRL-GFM-001",
                        severity="WARN",
                        spec="TS 102 222 §5",
                        path=f"{path_base}[{op_idx}].{name}",
                        message=(
                            f"GFM block [{blk_idx}] op [{op_idx}] '{name}' "
                            "has no preceding filePath or createFCP in the same block — "
                            "the UICC has no target file for this write."
                        ),
                        recommendation=(
                            "Precede each fillFileContent / fillFileOffset with a "
                            "filePath selecting the target EF, or merge into the "
                            "createFCP block that created the file."
                        ),
                        evidence={"block": blk_idx, "op_index": op_idx, "op": name},
                    )
                last_was_create = False

        # YRL-GFM-002: last op is createFCP/createFile with no write after.
        # Only emit when the block ends on a create without a subsequent fill.
        final_op_name = self._gfm_op_name(real_ops[-1]) if real_ops else ""
        if final_op_name in _CREATE_OPS:
            self._add(
                code="YRL-GFM-002",
                severity="INFO",
                spec="TS 102 222 §5",
                path=f"{path_base}[{len(real_ops) - 1}].{final_op_name}",
                message=(
                    f"GFM block [{blk_idx}] ends with '{final_op_name}' "
                    "but has no subsequent fillFileContent — the created file will be empty."
                ),
                recommendation=(
                    "Add a fillFileContent op after the createFCP to initialise "
                    "the file content, or confirm an empty file is intentional."
                ),
                evidence={"block": blk_idx, "final_op": final_op_name},
            )

    def _check_rfm_tar_coherence(self, sections: dict[str, Any]) -> None:
        """YRL-RFM-*: TAR uniqueness and key-reference sanity for RFM PEs.

        - ``YRL-RFM-001`` (FAIL): two or more RFM PEs share the same TAR value.
          Duplicate TARs cause ambiguous dispatch on the card — only the first
          matching RFM handler will be invoked (ETSI TS 102 226 §8.2).
        - ``YRL-RFM-002`` (WARN): a ``tarList`` entry is not exactly 3 bytes
          (6 hex nibbles).  SCP80 / BIP channel setup requires a 3-byte TAR
          (ETSI TS 102 226 §8.1).
        - ``YRL-RFM-003`` (WARN): ``keyReference`` is 0x00, which is not
          assigned in the GP CPS key-reference registry and will be rejected
          by most OTA stacks.
        """
        # section_key → list[str]  (normalised 6-char uppercase TAR hex strings)
        tar_registry: dict[str, str] = {}  # normalised_tar → first section_key

        for section_key, payload in sections.items():
            if self._base_type_from_key(section_key) != "rfm":
                continue
            if not isinstance(payload, dict):
                continue

            raw_tar_list = self._find_key_values(payload, "tarList")
            if not raw_tar_list or not isinstance(raw_tar_list[0], list):
                continue
            tar_entries: list[Any] = raw_tar_list[0]

            for entry_idx, tar_raw in enumerate(tar_entries):
                tar_hex = self._normalise_hex_field(tar_raw)
                if tar_hex is None:
                    continue
                tar_path = f"{section_key}.tarList[{entry_idx}]"

                if len(tar_hex) != 6:
                    self._add(
                        code="YRL-RFM-002",
                        severity="WARN",
                        spec="ETSI TS 102 226 §8.1",
                        path=tar_path,
                        message=(
                            f"TAR value '{tar_hex}' is {len(tar_hex) // 2} byte(s); "
                            "expected exactly 3 bytes (6 hex nibbles)."
                        ),
                        recommendation="Encode each tarList entry as a 3-byte (6-nibble) hex value.",
                        evidence={"tar": tar_hex, "byte_length": len(tar_hex) // 2},
                    )
                    continue

                if tar_hex in tar_registry:
                    self._add(
                        code="YRL-RFM-001",
                        severity="FAIL",
                        spec="ETSI TS 102 226 §8.2",
                        path=tar_path,
                        message=(
                            f"TAR 0x{tar_hex} is also claimed by "
                            f"'{tar_registry[tar_hex]}'. "
                            "Duplicate TARs cause ambiguous OTA dispatch."
                        ),
                        recommendation=(
                            "Assign a unique 3-byte TAR to each RFM PE. "
                            "Consult ETSI TS 102 226 §8.2 for the allocation rules."
                        ),
                        evidence={
                            "tar": tar_hex,
                            "first_owner": tar_registry[tar_hex],
                            "duplicate_owner": section_key,
                        },
                    )
                else:
                    tar_registry[tar_hex] = section_key

            # keyReference value 0x00 check
            raw_key_refs = self._find_key_values(payload, "keyReference")
            for kref_raw in raw_key_refs:
                kref_hex = self._normalise_hex_field(kref_raw)
                if kref_hex and len(kref_hex) in (2, 4) and int(kref_hex[-2:], 16) == 0:
                    self._add(
                        code="YRL-RFM-003",
                        severity="WARN",
                        spec="GP CPS v2.3 §11.1.8",
                        path=f"{section_key}.keyReference",
                        message=(
                            f"keyReference is 0x{kref_hex} (value 0x00 is not "
                            "assigned in the GP CPS registry and will be rejected "
                            "by most OTA stacks)."
                        ),
                        recommendation="Set keyReference to a valid non-zero key reference.",
                        evidence={"keyReference": kref_hex},
                    )

    def _normalise_hex_field(self, raw: Any) -> str | None:
        """Coerce a raw decoded field to a plain uppercase hex string, or None."""
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw.hex().upper()
        if isinstance(raw, dict):
            candidate = raw.get("hex") or raw.get("__ygg_saip_bytes__") or raw.get("tar") or ""
            candidate = str(candidate).upper().replace(" ", "")
            return candidate if candidate else None
        if isinstance(raw, str):
            candidate = raw.upper().replace(" ", "")
            return candidate if self._looks_like_hex(candidate) else None
        return None

    def _check_ram_sd_integrity(self, sections: dict[str, Any]) -> None:
        """YRL-RAM-*: Remote Application Management PE sanity checks.

        - ``YRL-RAM-001`` (FAIL): ``securityDomainAID`` is absent — no target
          SD, so the RAM handler cannot be dispatched (GP CPS §11.1.4).
        - ``YRL-RAM-002`` (WARN): ``securityDomainAID`` present but not a
          valid AID length (5–16 bytes, ISO 7816-4 §8.2.1).
        - ``YRL-RAM-003`` (WARN): ``applicationLoadPackageAID`` present but
          not a valid AID length (5–16 bytes, ISO 7816-4 §8.2.1).
        """
        for section_key, payload in sections.items():
            if self._base_type_from_key(section_key) != "ram":
                continue
            if not isinstance(payload, dict):
                continue

            sd_raw = payload.get("securityDomainAID")
            if sd_raw is None:
                self._add(
                    code="YRL-RAM-001",
                    severity="FAIL",
                    spec="GP CPS v2.3 §11.1.4",
                    path=f"{section_key}.securityDomainAID",
                    message=(
                        "RAM PE has no securityDomainAID — the OTA stack "
                        "cannot identify the target SD for remote installs."
                    ),
                    recommendation="Set securityDomainAID to the AID of the target Security Domain.",
                )
            else:
                sd_hex = self._normalise_hex_field(sd_raw)
                if sd_hex is not None:
                    sd_bytes = len(sd_hex) // 2
                    if sd_bytes < 5 or sd_bytes > 16:
                        self._add(
                            code="YRL-RAM-002",
                            severity="WARN",
                            spec="ISO 7816-4 §8.2.1 / GP CPS §11.1.4",
                            path=f"{section_key}.securityDomainAID",
                            message=(
                                f"securityDomainAID is {sd_bytes} byte(s); "
                                "valid AID range is 5–16 bytes (ISO 7816-4 §8.2.1)."
                            ),
                            recommendation="Correct the AID to a 5- to 16-byte value.",
                            evidence={"aid": sd_hex, "byte_length": sd_bytes},
                        )

            lpa_raw = payload.get("applicationLoadPackageAID")
            if lpa_raw is not None:
                lpa_hex = self._normalise_hex_field(lpa_raw)
                if lpa_hex is not None:
                    lpa_bytes = len(lpa_hex) // 2
                    if lpa_bytes < 5 or lpa_bytes > 16:
                        self._add(
                            code="YRL-RAM-003",
                            severity="WARN",
                            spec="ISO 7816-4 §8.2.1",
                            path=f"{section_key}.applicationLoadPackageAID",
                            message=(
                                f"applicationLoadPackageAID is {lpa_bytes} byte(s); "
                                "valid AID range is 5–16 bytes (ISO 7816-4 §8.2.1)."
                            ),
                            recommendation="Correct the load-package AID to a 5- to 16-byte value.",
                            evidence={"aid": lpa_hex, "byte_length": lpa_bytes},
                        )

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

        # 3GPP TS 31.102 §4.2.8 — service number → required EF/DF markers.
        # Only services with a clearly mandated file pairing are listed.
        required_by_service = {
            2:  ("ef-fdn",),
            5:  ("ef-lnd",),
            6:  ("ef-cmi",),
            10: ("ef-sms", "ef-smss"),
            12: ("ef-smsp", "ef-hpplmn"),
            15: ("ef-ext3",),
            17: ("ef-bdn",),
            18: ("ef-ext4",),
            19: ("ef-spn",),
            21: ("ef-msisdn",),
            22: ("ef-img",),
            23: ("ef-ext7",),
            24: ("ef-spdi",),
            44: ("ef-mwis",),
            45: ("ef-cfis",),
            25: ("ef-mmsn",),
            26: ("ef-ext8",),
            27: ("ef-mmsicp",),
            28: ("ef-mmsup",),
            38: ("ef-est",),
            42: ("ef-psloci",),
            43: ("ef-acc",),
            45: ("ef-cbmir",),
            46: ("ef-nia",),
            47: ("ef-impu",),
            48: ("ef-impi",),
            49: ("ef-domain",),
            50: ("ef-imsk",),
            51: ("ef-ad",),
            85: ("ef-epsloci", "ef-epsnsc"),
            95: ("ef-5gloci", "ef-5gnsc"),
        }

        # Services where the *presence* of files implies the bit should be set.
        # (informational — YRL-UST-002 INFO, not FAIL)
        suggested_by_presence = {
            6:  ("ef-cmi",),
            13: ("ef-acm", "ef-acmmax", "ef-puct"),
            21: ("ef-msisdn",),
            40: ("ef-invscan",),
            44: ("ef-mwis",),
            45: ("ef-cfis",),
            47: ("ef-impu",),
            48: ("ef-impi",),
            49: ("ef-domain",),
            85: ("ef-epsloci", "ef-epsnsc"),
            95: ("ef-5gloci", "ef-5gnsc"),
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
            # Key material — wrong K/OPc length makes the USIM non-functional.
            "YRL-AKA-001",
            "YRL-AKA-002",
            # PIN / PUK wrong value length — card will reject personalisation.
            "YRL-PIN-002",
            "YRL-PIN-003",
            # SD key version 0 is spec-reserved; personalisation will fail.
            "YRL-SDK-001",
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
        # pySim / saip_json_codec wraps raw bytes as {'hex': '...'} or
        # {'__ygg_saip_bytes__': '...'}. Unwrap to the raw hex string.
        if isinstance(value, dict):
            inner = value.get("hex", value.get("__ygg_saip_bytes__"))
            if inner is not None:
                return self._normalize_file_definition_value(inner)
            return None
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

        # Cross-check efFileSize against the actual byte length of
        # fillFileContent when both are present in the same payload.
        # A mismatch means the card will reject the create/update at
        # runtime (ETSI TS 102 222 §6.4 requires the content to fit).
        self._validate_ef_fill_content_length(file_def, size_value, path)

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

    def _validate_ef_fill_content_length(
        self,
        file_def: FileDefinition,
        declared_size: int,
        path: str,
    ) -> None:
        fill_raw = file_def.payload.get("fillFileContent")
        if fill_raw is None:
            return
        fill_hex = self._normalize_file_definition_value(fill_raw)
        if fill_hex is None or not self._looks_like_hex(fill_hex):
            return
        # Each two hex chars = one byte.
        actual_bytes = len(fill_hex) // 2
        if actual_bytes == declared_size:
            return
        self._add(
            code="YRL-FS-001",
            severity="FAIL",
            spec="ETSI TS 102 222 §6.4",
            path=path,
            message=(
                f"efFileSize declares {declared_size} B but fillFileContent "
                f"is {actual_bytes} B."
            ),
            recommendation=(
                "Align efFileSize with the byte length of fillFileContent, "
                "or pad / trim the content to match the declared size."
            ),
            evidence={
                "declared_bytes": declared_size,
                "actual_bytes": actual_bytes,
            },
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

    # GP CPS v2.3 §11.1.8 valid key component type codes.
    _GP_VALID_KEY_TYPES: frozenset[int] = frozenset([
        0x01, 0x02, 0x03,               # DES variants
        0x80, 0x81, 0x82,               # AES / HMAC
        0x88, 0x89, 0x8A, 0x8B,         # RSA public / private
        0x8C, 0x8D, 0x8E,               # RSA private CRT factors
        0xA1, 0xA2, 0xB0,               # ECC
    ])

    def _check_sd_key_list(self, sections: dict[str, Any]) -> None:
        """YRL-SDK-*: SD key-list entry-level validation.

        For every ``securityDomain`` PE whose ``keyList`` passes
        ``YRL-SDM-*`` shape checks, validate each entry:

        - ``YRL-SDK-001``: ``keyVersionNumber`` must be non-zero
          (GP CPS §11.1.8 — version 0 is reserved / not issued).
        - ``YRL-SDK-002``: every ``keyComponent`` ``keyType`` must be
          from the GP CPS §11.1.8 registered set.
        - ``YRL-SDK-003`` (WARN): ``keyUsageQualifier`` is absent or
          zero — operator may have omitted the field.
        """
        for section_key, payload in sections.items():
            if self._base_type_from_key(section_key) != "securityDomain":
                continue
            if not isinstance(payload, dict):
                continue
            key_list_values = self._find_key_values(payload, "keyList")
            if not key_list_values or not isinstance(key_list_values[0], list):
                continue
            entries: list[Any] = key_list_values[0]
            for idx, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                path_base = f"{section_key}.keyList[{idx}]"
                self._lint_sd_key_entry(path_base, entry)

    def _lint_sd_key_entry(self, path_base: str, entry: dict[str, Any]) -> None:
        # keyVersionNumber — non-zero check
        kver_raw = entry.get("keyVersionNumber")
        if kver_raw is not None:
            kver_hex = None
            if isinstance(kver_raw, dict):
                kver_hex = str(kver_raw.get("hex", kver_raw.get("__ygg_saip_bytes__", "")) or "").upper().replace(" ", "")
            elif isinstance(kver_raw, (str, bytes)):
                kver_hex = kver_raw.hex().upper() if isinstance(kver_raw, bytes) else str(kver_raw).upper().replace(" ", "")
            if kver_hex and self._looks_like_hex(kver_hex):
                kver_int = int(kver_hex, 16)
                if kver_int == 0:
                    self._add(
                        code="YRL-SDK-001",
                        severity="WARN",
                        spec="GP CPS v2.3 §11.1.8",
                        path=f"{path_base}.keyVersionNumber",
                        message=(
                            f"keyVersionNumber is 0x{kver_hex} (version 0 is reserved; "
                            "GP CPS §11.1.8 states version 0 is not issued)."
                        ),
                        recommendation="Set keyVersionNumber to at least 0x01.",
                        evidence={"keyVersionNumber": kver_hex},
                    )

        # keyUsageQualifier — absent or zero
        kuq_raw = entry.get("keyUsageQualifier")
        if kuq_raw is None:
            self._add(
                code="YRL-SDK-003",
                severity="WARN",
                spec="GP CPS v2.3 §11.1.8",
                path=f"{path_base}.keyUsageQualifier",
                message="keyUsageQualifier is absent; key's authorised use is unspecified.",
                recommendation="Set keyUsageQualifier to the intended bit-mask (e.g. 0x3C for SCP03 S-keys).",
            )
        else:
            kuq_hex = None
            if isinstance(kuq_raw, dict):
                kuq_hex = str(kuq_raw.get("hex", kuq_raw.get("__ygg_saip_bytes__", "")) or "").upper().replace(" ", "")
            elif isinstance(kuq_raw, (str, bytes)):
                kuq_hex = kuq_raw.hex().upper() if isinstance(kuq_raw, bytes) else str(kuq_raw).upper().replace(" ", "")
            if kuq_hex and self._looks_like_hex(kuq_hex) and int(kuq_hex, 16) == 0:
                self._add(
                    code="YRL-SDK-003",
                    severity="WARN",
                    spec="GP CPS v2.3 §11.1.8",
                    path=f"{path_base}.keyUsageQualifier",
                    message="keyUsageQualifier is 0x00 — no usage bits set; key's authorised use is unspecified.",
                    recommendation="Set keyUsageQualifier to the intended bit-mask.",
                    evidence={"keyUsageQualifier": kuq_hex},
                )

        # keyComponents — keyType validity
        comps = entry.get("keyComponents")
        if not isinstance(comps, list):
            return
        for cidx, comp in enumerate(comps):
            if not isinstance(comp, dict):
                continue
            kt_raw = comp.get("keyType")
            if kt_raw is None:
                continue
            kt_hex = None
            if isinstance(kt_raw, dict):
                kt_hex = str(kt_raw.get("hex", kt_raw.get("__ygg_saip_bytes__", "")) or "").upper().replace(" ", "")
            elif isinstance(kt_raw, (str, bytes)):
                kt_hex = kt_raw.hex().upper() if isinstance(kt_raw, bytes) else str(kt_raw).upper().replace(" ", "")
            if kt_hex and self._looks_like_hex(kt_hex):
                kt_int = int(kt_hex, 16)
                if kt_int not in self._GP_VALID_KEY_TYPES:
                    self._add(
                        code="YRL-SDK-002",
                        severity="WARN",
                        spec="GP CPS v2.3 §11.1.8",
                        path=f"{path_base}.keyComponents[{cidx}].keyType",
                        message=(
                            f"keyType 0x{kt_hex} is not in the GP CPS §11.1.8 "
                            "registered key-component type registry."
                        ),
                        recommendation="Use a GP-registered keyType (e.g. 0x80 for AES, 0x88/0x89 for RSA).",
                        evidence={"keyType": kt_hex},
                    )

    # Algorithm-ID → (key_bytes, op_field, op_bytes, name)
    # MILENAGE: 3GPP TS 35.206; TUAK: 3GPP TS 35.231.
    _AKA_ALGO_SPECS: dict[int, tuple[int, str, int, str]] = {
        1: (16, "opc",  16, "MILENAGE"),
        2: (32, "topc", 32, "TUAK"),
        3: (16, "opc",  16, "USIM-TEST-XOR"),
    }

    # Fixed-length SGP.22 §B.3 fields common to all algorithms.
    _AKA_FIXED_FIELD_BYTES: dict[str, int] = {
        "algorithmOptions": 1,
        "authCounterMax":   3,
        "sqnDelta":         6,
        "sqnAgeLimit":      6,
        # MILENAGE-specific
        "rotationConstants": 5,
    }

    def _check_aka_parameter_encoding(self, sections: dict[str, Any]) -> None:
        """YRL-AKA-*: AKA parameter field-length checks.

        Validates ``PE-AKAParameter`` / ``PE-AKAParameter2`` key material:

        - ``YRL-AKA-001``: K field (``key``) must be 16 B for MILENAGE /
          XOR-test, 32 B for TUAK (3GPP TS 35.206 §8, TS 35.231 §8).
        - ``YRL-AKA-002``: OP(c) / TOP(c) byte length must match algorithm.
        - ``YRL-AKA-003``: Fixed-length SGP.22 §B.3 fields out of spec
          (``algorithmOptions`` 1 B, ``authCounterMax`` 3 B, ``sqnDelta``
          6 B, ``sqnAgeLimit`` 6 B, ``rotationConstants`` 5 B).
        - ``YRL-AKA-004`` (WARN): unknown ``algorithmID`` — cannot validate
          key lengths against a known spec.
        """
        for section_key, payload in sections.items():
            base = self._base_type_from_key(section_key)
            if base not in ("akaParameter", "akaParameter2"):
                continue
            if not isinstance(payload, dict):
                continue
            self._lint_aka_section(section_key, payload)

    def _aka_extract_hex(self, value: Any) -> str | None:
        """Unwrap tagged-bytes / plain hex / bytes into an uppercase hex string."""
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.hex().upper()
        if isinstance(value, dict):
            inner = value.get("hex", value.get("__ygg_saip_bytes__"))
            if inner is not None:
                return str(inner).upper().replace(" ", "")
        if isinstance(value, str):
            return value.upper().replace(" ", "") or None
        return None

    def _lint_aka_section(self, section_key: str, payload: dict[str, Any]) -> None:
        # algoConfiguration is a tagged-tuple: {'@': ['algoParameter', {...}]}
        algo_cfg = payload.get("algoConfiguration")
        algo_params: dict[str, Any] = {}
        algo_id: int | None = None

        if isinstance(algo_cfg, dict):
            tpl = algo_cfg.get("@", algo_cfg.get("__ygg_saip_tuple__"))
            if isinstance(tpl, list) and len(tpl) >= 2 and isinstance(tpl[1], dict):
                algo_params = tpl[1]
        elif isinstance(algo_cfg, list) and len(algo_cfg) >= 2 and isinstance(algo_cfg[1], dict):
            algo_params = algo_cfg[1]

        raw_id = algo_params.get("algorithmID")
        if isinstance(raw_id, int):
            algo_id = raw_id

        if algo_id is None:
            return

        spec = self._AKA_ALGO_SPECS.get(algo_id)
        if spec is None:
            self._add(
                code="YRL-AKA-004",
                severity="WARN",
                spec="SGP.22 §B.3",
                path=f"{section_key}.algoConfiguration.algorithmID",
                message=(
                    f"AKA algorithmID={algo_id} is not a recognised value "
                    "(1=MILENAGE, 2=TUAK, 3=USIM-TEST-XOR); cannot validate key lengths."
                ),
                recommendation="Use a 3GPP-registered algorithmID.",
                evidence={"algorithmID": algo_id},
            )
            return

        key_bytes, op_field, op_bytes, algo_name = spec

        # K field
        key_hex = self._aka_extract_hex(algo_params.get("key"))
        if key_hex and self._looks_like_hex(key_hex):
            actual = len(key_hex) // 2
            if actual != key_bytes:
                self._add(
                    code="YRL-AKA-001",
                    severity="FAIL",
                    spec="3GPP TS 35.206 §8" if algo_id == 1 else "3GPP TS 35.231 §8",
                    path=f"{section_key}.algoConfiguration.key",
                    message=(
                        f"{algo_name} K field is {actual} B; must be {key_bytes} B."
                    ),
                    recommendation=f"Re-encode K as exactly {key_bytes} bytes.",
                    evidence={"algorithm": algo_name, "actual_bytes": actual, "expected_bytes": key_bytes},
                )

        # OP(c) / TOP(c)
        op_val = algo_params.get(op_field) or algo_params.get(op_field.replace("c", ""))
        op_hex = self._aka_extract_hex(op_val)
        if op_hex and self._looks_like_hex(op_hex):
            actual = len(op_hex) // 2
            if actual != op_bytes:
                self._add(
                    code="YRL-AKA-002",
                    severity="FAIL",
                    spec="3GPP TS 35.206 §8" if algo_id == 1 else "3GPP TS 35.231 §8",
                    path=f"{section_key}.algoConfiguration.{op_field}",
                    message=(
                        f"{algo_name} {op_field} field is {actual} B; must be {op_bytes} B."
                    ),
                    recommendation=f"Re-encode {op_field} as exactly {op_bytes} bytes.",
                    evidence={"algorithm": algo_name, "actual_bytes": actual, "expected_bytes": op_bytes},
                )

        # Fixed-length fields (common + MILENAGE-specific)
        for field_name, expected_bytes in self._AKA_FIXED_FIELD_BYTES.items():
            # rotationConstants is MILENAGE-only
            if field_name == "rotationConstants" and algo_id != 1:
                continue
            raw = algo_params.get(field_name) or payload.get(field_name)
            fhex = self._aka_extract_hex(raw)
            if fhex and self._looks_like_hex(fhex):
                actual = len(fhex) // 2
                if actual != expected_bytes:
                    self._add(
                        code="YRL-AKA-003",
                        severity="WARN",
                        spec="SGP.22 §B.3",
                        path=f"{section_key}.{field_name}",
                        message=(
                            f"{algo_name} {field_name} is {actual} B; "
                            f"expected {expected_bytes} B (SGP.22 §B.3)."
                        ),
                        recommendation=f"Re-encode {field_name} as exactly {expected_bytes} bytes.",
                        evidence={
                            "field": field_name,
                            "actual_bytes": actual,
                            "expected_bytes": expected_bytes,
                        },
                    )

    def _check_pin_puk_encoding(self, sections: dict[str, Any]) -> None:
        """YRL-PIN-*: PIN/PUK byte-level encoding rules.

        Checks every ``pinCodes`` / ``pukCodes`` entry for:

        - ``YRL-PIN-001``: packed retry byte (maxNumOfAttemps-retryNumLeft)
          must have max-attempts nibble in 1..15 and remaining-attempts nibble
          in 0..max (SGP.22 §B.2, ETSI TS 102 222 §6.1).
        - ``YRL-PIN-002``: pinValue must be exactly 8 bytes (SGP.22 §B.2).
        - ``YRL-PIN-003``: pukValue must be exactly 8 bytes (SGP.22 §B.2).
        - ``YRL-PIN-004`` (WARN): retry byte's remaining count exceeds max
          count — card will typically initialise remaining to max but a
          profile that ships remaining > max will cause runtime confusion.
        """
        for section_key, payload in sections.items():
            base_type = self._base_type_from_key(section_key)
            if base_type not in ("pinCodes", "pukCodes"):
                continue
            self._lint_pin_puk_section(section_key, payload, base_type)

    def _lint_pin_puk_section(
        self,
        section_key: str,
        payload: Any,
        kind: str,
    ) -> None:
        is_puk = kind == "pukCodes"
        # pinCodes: wrapped in a tagged-tuple ('pinconfig', [list])
        # pukCodes: plain list
        entries: list[Any] = []
        if is_puk:
            raw = payload.get("pukCodes") if isinstance(payload, dict) else None
            if isinstance(raw, list):
                entries = raw
        else:
            raw = payload.get("pinCodes") if isinstance(payload, dict) else None
            if isinstance(raw, dict):
                # Tagged-tuple: {'@': ['pinconfig', [...]]} or legacy form
                inner = raw.get("@", raw.get("__ygg_saip_tuple__"))
                if isinstance(inner, list) and len(inner) >= 2:
                    entries = inner[1] if isinstance(inner[1], list) else []
            elif isinstance(raw, list):
                entries = raw

        value_field = "pukValue" if is_puk else "pinValue"
        label = "PUK" if is_puk else "PIN"

        for idx, entry in enumerate(entries):
            rec = entry
            if isinstance(entry, dict) and "@" in entry:
                tpl = entry["@"]
                if isinstance(tpl, list) and len(tpl) >= 2:
                    rec = tpl[1]
            if not isinstance(rec, dict):
                continue

            path_base = f"{section_key}.{label.lower()}Codes[{idx}]"

            # Packed retry byte
            retry_raw = rec.get("maxNumOfAttemps-retryNumLeft")
            if retry_raw is None:
                retry_raw = rec.get("maxNumOfAttempts-retryNumLeft")
            if retry_raw is not None:
                n = retry_raw if isinstance(retry_raw, int) else -1
                if 0 <= n <= 255:
                    max_att = (n >> 4) & 0x0F
                    remaining = n & 0x0F
                    if max_att == 0:
                        self._add(
                            code="YRL-PIN-001",
                            severity="FAIL",
                            spec="SGP.22 §B.2",
                            path=f"{path_base}.maxNumOfAttemps-retryNumLeft",
                            message=(
                                f"{label} slot {idx}: max-attempts nibble is 0 "
                                f"(packed byte 0x{n:02X}); must be 1..15."
                            ),
                            recommendation="Set max-attempts nibble to 3 (0x3y) for typical "
                                "3-attempt PIN or 10 (0xAy) for PUK.",
                            evidence={"packed_byte": hex(n), "max_att": max_att, "remaining": remaining},
                        )
                    elif remaining > max_att:
                        self._add(
                            code="YRL-PIN-004",
                            severity="WARN",
                            spec="SGP.22 §B.2",
                            path=f"{path_base}.maxNumOfAttemps-retryNumLeft",
                            message=(
                                f"{label} slot {idx}: remaining-attempts nibble ({remaining}) "
                                f"exceeds max-attempts nibble ({max_att}) "
                                f"(packed byte 0x{n:02X})."
                            ),
                            recommendation="Set remaining ≤ max; card typically initialises "
                                "remaining = max at personalisation.",
                            evidence={"packed_byte": hex(n), "max_att": max_att, "remaining": remaining},
                        )

            # PIN / PUK value length — must be exactly 8 bytes (SGP.22 §B.2)
            val_raw = rec.get(value_field)
            if val_raw is not None:
                val_hex = None
                if isinstance(val_raw, bytes):
                    val_hex = val_raw.hex().upper()
                elif isinstance(val_raw, dict):
                    inner = val_raw.get("hex", val_raw.get("__ygg_saip_bytes__"))
                    if inner is not None:
                        val_hex = str(inner).upper().replace(" ", "")
                elif isinstance(val_raw, str):
                    val_hex = val_raw.upper().replace(" ", "")
                if val_hex is not None and self._looks_like_hex(val_hex):
                    byte_len = len(val_hex) // 2
                    code = "YRL-PIN-002" if not is_puk else "YRL-PIN-003"
                    if byte_len != 8:
                        self._add(
                            code=code,
                            severity="FAIL",
                            spec="SGP.22 §B.2",
                            path=f"{path_base}.{value_field}",
                            message=(
                                f"{label} slot {idx}: {value_field} is {byte_len} B; "
                                "must be exactly 8 bytes (padded with 0xFF)."
                            ),
                            recommendation=(
                                f"Encode {label} as 8 bytes; pad unused positions with 0xFF "
                                f"(e.g. 4-digit PIN '1234' → 31323334FFFFFFFF)."
                            ),
                            evidence={"byte_length": byte_len},
                        )

    def _check_arr_references(self, file_definitions: list[FileDefinition]) -> None:
        """YRL-ARR-001/002: securityAttributesReferenced rule-index vs EF.ARR record count.

        Tag 8B encodes an EF(ARR) file reference plus a 1-byte rule record
        index (ETSI TS 102 221 §11.1.1 Table 11.1):
          - 1 byte: use MF's EF.ARR, record index = byte[0]
          - 2 bytes: byte[0] = SFI of EF.ARR, byte[1] = record index
          - 3 bytes: byte[0..1] = File ID, byte[2] = record index

        When the referenced EF.ARR is defined in the same scope with a
        ``fillFileContent`` and a record-oriented ``fileDescriptor``, the
        maximum record index is ``len(content) // record_length - 1``.
        A rule_index beyond that range will cause a runtime error on card.
        """
        if len(file_definitions) == 0:
            return

        # Build two maps keyed by (section_key, file_id_upper):
        #   arr_by_fid  → (fill_hex, record_length) for EF.ARR-like files
        #   arr_by_sfid → (fill_hex, record_length) for the SFI reference form
        #
        # We match section_key so MF/USIM/ISIM scopes don't cross-contaminate.
        arr_by_fid: dict[tuple[str, str], tuple[str, int]] = {}
        arr_by_sfid: dict[tuple[str, str], tuple[str, int]] = {}
        for fd in file_definitions:
            fid = fd.file_id
            desc = fd.file_descriptor
            fill_raw = fd.payload.get("fillFileContent")
            if fid is None or desc is None or fill_raw is None:
                continue
            fill_hex = self._normalize_file_definition_value(fill_raw)
            desc_hex = self._normalize_file_definition_value(desc)
            if not fill_hex or not desc_hex:
                continue
            if not self._looks_like_hex(fill_hex) or not self._looks_like_hex(desc_hex):
                continue
            # Record-oriented EFs: descriptor byte starts with 0x42 (LF) or 0x46 (CF).
            if not (desc_hex.upper().startswith("42") or desc_hex.upper().startswith("46")):
                continue
            if len(desc_hex) < 8:
                continue
            record_length = int(desc_hex[-2:], 16)
            if record_length == 0:
                continue
            scope = fd.section_key
            arr_by_fid[(scope, fid.upper())] = (fill_hex, record_length)
            sfid = fd.short_efid
            if sfid:
                sfid_norm = self._normalize_file_definition_value(sfid)
                if sfid_norm and self._looks_like_hex(sfid_norm):
                    arr_by_sfid[(scope, sfid_norm.upper())] = (fill_hex, record_length)

        # Walk all file definitions and check each 8B reference.
        for fd in file_definitions:
            sar = fd.security_attributes_referenced
            if sar is None:
                continue
            sar_norm = self._normalize_file_definition_value(sar)
            if not sar_norm or not self._looks_like_hex(sar_norm):
                continue
            sar_bytes = bytes.fromhex(sar_norm)
            n = len(sar_bytes)
            # Decode rule_index and optional EF.ARR reference per TS 102 221 §11.1.1
            if n == 1:
                # Single byte: record index in MF's EF.ARR (SFI not specified).
                rule_index = sar_bytes[0]
                arr_key = None
            elif n == 2:
                # SFI (byte 0) + rule record index (byte 1).
                sfid_hex = format(sar_bytes[0], "02X")
                rule_index = sar_bytes[1]
                arr_key = arr_by_sfid.get((fd.section_key, sfid_hex))
            elif n == 3:
                # File ID (bytes 0-1) + rule record index (byte 2).
                fid_hex = format(sar_bytes[0], "02X") + format(sar_bytes[1], "02X")
                rule_index = sar_bytes[2]
                arr_key = arr_by_fid.get((fd.section_key, fid_hex.upper()))
            else:
                continue

            if n == 1:
                # Cannot resolve MF's EF.ARR without a 2+ byte reference.
                continue

            if arr_key is None:
                # EF.ARR not found in this scope — emit an informational finding.
                self._add(
                    code="YRL-ARR-002",
                    severity="INFO",
                    spec="ETSI TS 102 221 §11.1.1",
                    path=(
                        f"{fd.section_key}.{fd.field_path}"
                        ".securityAttributesReferenced"
                    ),
                    message=(
                        "Referenced EF.ARR not found in this section's file "
                        "definitions; rule-index range cannot be verified."
                    ),
                    recommendation=(
                        "Define EF.ARR with fillFileContent in the same PE section "
                        "so the linter can verify the rule-index range."
                    ),
                )
                continue

            fill_hex, record_length = arr_key
            actual_bytes = len(fill_hex) // 2
            record_count = actual_bytes // record_length
            if rule_index >= record_count:
                self._add(
                    code="YRL-ARR-001",
                    severity="WARN",
                    spec="ETSI TS 102 221 §11.1.1",
                    path=(
                        f"{fd.section_key}.{fd.field_path}"
                        ".securityAttributesReferenced"
                    ),
                    message=(
                        f"Rule record index {rule_index} is out of range for "
                        f"EF.ARR (only {record_count} record(s) available)."
                    ),
                    recommendation=(
                        f"Use a rule_index between 0 and {max(0, record_count - 1)},"
                        " or add more records to EF.ARR."
                    ),
                    evidence={
                        "rule_index": rule_index,
                        "arr_record_count": record_count,
                        "arr_fill_bytes": actual_bytes,
                        "arr_record_length": record_length,
                    },
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

    def _walk_with_choice_paths(
        self,
        payload: Any,
        base_path: str = "",
    ) -> list[tuple[str, Any]]:
        """Like ``_walk_with_path`` but treats ``(name, value)`` tuples as
        ASN.1 CHOICE entries (the form pySim emits for SAIP file
        definitions: ``[("fillFileContent", b"…"), …]``).

        Yields ``(<base>.fillFileContent, value)`` so the IMSI / ICCID
        checks can address content fields by suffix without first
        having to JSON-roundtrip through ``jsonify_decoded`` / the
        ``{"@": [name, payload]}`` editor projection.
        """
        rows: list[tuple[str, Any]] = []
        if isinstance(payload, dict):
            for key_text, value in payload.items():
                key_part = str(key_text)
                full_path = key_part if base_path == "" else f"{base_path}.{key_part}"
                rows.append((full_path, value))
                nested = self._walk_with_choice_paths(value, full_path)
                if len(nested) > 0:
                    rows.extend(nested)
            return rows
        if isinstance(payload, (list, tuple)):
            # Tagged-tuple form: ``(name, value)`` with a string tag.
            if (
                isinstance(payload, tuple)
                and len(payload) == 2
                and isinstance(payload[0], str)
            ):
                name = str(payload[0])
                value = payload[1]
                full_path = name if base_path == "" else f"{base_path}.{name}"
                rows.append((full_path, value))
                nested = self._walk_with_choice_paths(value, full_path)
                if len(nested) > 0:
                    rows.extend(nested)
                return rows
            for index, value in enumerate(payload):
                full_path = f"{base_path}[{index}]"
                rows.append((full_path, value))
                nested = self._walk_with_choice_paths(value, full_path)
                if len(nested) > 0:
                    rows.extend(nested)
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
