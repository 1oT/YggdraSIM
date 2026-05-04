"""Tests for template-placeholder-tolerant parsing and linting."""

import json
import unittest

from Tools.ProfilePackage.lint_engine import SaipProfileLinter
from Tools.ProfilePackage.saip_json_codec import (
    TokenExpansionContext,
    dejsonify_document,
    parse_editor_json,
    parse_editor_json_template_aware,
)
from Tools.ProfilePackage.saip_tui_lint import (
    TuiLintOutcome,
    lint_profile_json_buffer,
)


_BASE_TEMPLATE = {
    "intro": ["template sample"],
    "sections": {
        "header": {
            "iccid": {"hex": "{ICCID}"},
        },
        "usim": {
            "ef-imsi": {
                "@": [
                    ["fillFileContent", {"hex": "{IMSI}"}],
                ],
            },
        },
    },
}


def _template_text() -> str:
    return json.dumps(_BASE_TEMPLATE)


class TokenExpansionContextTolerateTests(unittest.TestCase):
    def test_strict_context_raises_on_undefined_token(self) -> None:
        ctx = TokenExpansionContext({}, "brace")
        with self.assertRaises(ValueError):
            ctx.resolve_named("IMSI")

    def test_tolerant_context_returns_empty_bytes_and_records_token(self) -> None:
        ctx = TokenExpansionContext({}, "brace", tolerate_undefined=True)
        expanded = ctx.resolve_named("IMSI")
        self.assertEqual(expanded, b"")
        self.assertIn("IMSI", ctx.undefined_tokens)

    def test_tolerant_expand_mixed_hex_yields_concat_without_raising(self) -> None:
        ctx = TokenExpansionContext({}, "brace", tolerate_undefined=True)
        result = ctx.expand_mixed_hex("AA{IMSI}BB")
        self.assertEqual(result, bytes.fromhex("AABB"))
        self.assertIn("IMSI", ctx.undefined_tokens)


class DejsonifyDocumentPlaceholderTrackingTests(unittest.TestCase):
    def test_placeholder_paths_collected_in_tolerate_mode(self) -> None:
        loaded = json.loads(_template_text())
        paths: set[str] = set()
        doc = dejsonify_document(
            loaded,
            tolerate_undefined_placeholders=True,
            placeholder_paths=paths,
        )

        self.assertIn("sections.header.iccid", paths)
        self.assertIn("sections.usim.ef-imsi[0][1]", paths)
        self.assertEqual(doc["sections"]["header"]["iccid"], b"")

    def test_strict_dejsonify_still_raises_on_undefined_placeholder(self) -> None:
        loaded = json.loads(_template_text())
        with self.assertRaises(Exception):
            dejsonify_document(loaded)


class ParseEditorJsonTemplateAwareTests(unittest.TestCase):
    def test_parse_editor_json_still_fails_without_defs(self) -> None:
        with self.assertRaises(Exception):
            parse_editor_json(_template_text())

    def test_template_aware_parser_returns_paths_and_tokens(self) -> None:
        document, paths, tokens = parse_editor_json_template_aware(_template_text())

        self.assertIn("header.iccid", paths)
        self.assertIn("usim.ef-imsi[0][1]", paths)
        self.assertEqual({"ICCID", "IMSI"}, set(tokens))
        self.assertEqual(document["sections"]["header"]["iccid"], b"")

    def test_template_aware_parser_handles_defined_tokens(self) -> None:
        defined = dict(_BASE_TEMPLATE)
        defined["__ygg_token_defs__"] = {
            "ICCID": {"hex": "89881111111111111112"},
        }
        document, paths, tokens = parse_editor_json_template_aware(
            json.dumps(defined)
        )
        self.assertIn("header.iccid", paths)
        self.assertIn("IMSI", set(tokens))
        self.assertNotIn("ICCID", set(tokens))
        self.assertEqual(
            document["sections"]["header"]["iccid"],
            bytes.fromhex("89881111111111111112"),
        )


class LinterPlaceholderSkipTests(unittest.TestCase):
    def _decoded_with_placeholder_iccid(self) -> dict:
        return {
            "intro": [],
            "sections": {
                "header": {
                    "iccid": "{ICCID}",
                },
            },
        }

    def test_iccid_placeholder_triggers_fail_without_hint(self) -> None:
        report = SaipProfileLinter().lint_decoded_document(
            decoded_document=self._decoded_with_placeholder_iccid(),
            profile_label="dummy.der",
            emit_missing_check_finding=False,
        )
        codes = {finding.code for finding in report.findings}
        self.assertIn("YRL-ICC-003", codes)

    def test_placeholder_paths_downgrade_findings_to_info(self) -> None:
        report = SaipProfileLinter().lint_decoded_document(
            decoded_document=self._decoded_with_placeholder_iccid(),
            profile_label="dummy.der",
            placeholder_paths=frozenset({"header.iccid"}),
            undefined_tokens=frozenset({"ICCID"}),
            emit_missing_check_finding=False,
        )
        fail_codes = {
            finding.code
            for finding in report.findings
            if finding.severity in {"FAIL", "WARN"}
        }
        self.assertNotIn("YRL-ICC-003", fail_codes)
        self.assertNotIn("YRL-ICC-002", fail_codes)
        downgraded = [
            finding
            for finding in report.findings
            if finding.code.endswith("/TEMPLATE")
        ]
        self.assertTrue(len(downgraded) >= 1)
        banner = [
            finding
            for finding in report.findings
            if finding.code == "YRL-TPL-OK"
        ]
        self.assertEqual(len(banner), 1)
        banner_finding = banner[0]
        self.assertIn("APPLY-TEMPLATE", banner_finding.recommendation)
        self.assertIn("APPLY-TOKENS", banner_finding.recommendation)
        self.assertIn("GENERATE-BATCH", banner_finding.recommendation)
        evidence = banner_finding.evidence or {}
        self.assertIn("resolving_commands", evidence)
        resolving = evidence["resolving_commands"]
        self.assertIn(
            "APPLY-TOKENS <template.json> <template.tokens.json>",
            resolving,
        )

    def test_descendant_paths_skip_correctly(self) -> None:
        decoded = {
            "intro": [],
            "sections": {
                "usim": {
                    "ef-imsi": [
                        {"fillFileContent": "{IMSI}"},
                    ],
                },
            },
        }
        report = SaipProfileLinter().lint_decoded_document(
            decoded_document=decoded,
            profile_label="dummy.der",
            placeholder_paths=frozenset({"usim.ef-imsi"}),
            undefined_tokens=frozenset({"IMSI"}),
            emit_missing_check_finding=False,
        )
        for finding in report.findings:
            if finding.severity in {"FAIL", "WARN"}:
                self.assertFalse(
                    finding.path.startswith("usim.ef-imsi"),
                    f"Lint finding {finding.code} should have been downgraded: {finding.path}",
                )


class TuiLintBufferTests(unittest.TestCase):
    def test_template_buffer_returns_successful_outcome(self) -> None:
        outcome: TuiLintOutcome = lint_profile_json_buffer(
            _template_text(),
            profile_label="template.json",
        )
        self.assertIsNone(outcome.parse_error)
        self.assertIsNotNone(outcome.report)
        self.assertTrue(outcome.template_mode)
        self.assertEqual({"ICCID", "IMSI"}, set(outcome.undefined_tokens))
        self.assertTrue(len(outcome.placeholder_paths) >= 2)

    def test_broken_buffer_surfaces_parse_error(self) -> None:
        outcome = lint_profile_json_buffer(
            "{not valid json}",
            profile_label="broken.json",
        )
        self.assertIsNone(outcome.report)
        self.assertIsNotNone(outcome.parse_error)
        self.assertFalse(outcome.template_mode)


if __name__ == "__main__":
    unittest.main()
