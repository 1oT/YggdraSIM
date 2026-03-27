"""
Run SaipProfileLinter against TRANSCODE-TUI JSON buffer (lazy import of linter only from TUI).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .lint_engine import LintReport, SaipProfileLinter
from .saip_json_codec import parse_editor_json


@dataclass
class TuiLintOutcome:
    report: Optional[LintReport]
    parse_error: Optional[str]


def lint_profile_json_buffer(
    json_text: str,
    profile_label: str,
    *,
    strict: bool = False,
) -> TuiLintOutcome:
    """
    Parse tagged editor JSON and run the same structural rules as ``LINT`` (without metadata).

    ``saip-tool check`` is not executed (no subprocess); ``emit_missing_check_finding=False``
    avoids a synthetic YRL-CHK-001 warning in the panel.
    """
    try:
        document = parse_editor_json(json_text)
    except Exception as exc:
        return TuiLintOutcome(report=None, parse_error=str(exc))

    linter = SaipProfileLinter(strict=strict)
    report = linter.lint_decoded_document(
        decoded_document=document,
        profile_label=profile_label,
        check_return_code=None,
        check_stderr="",
        metadata=None,
        metadata_path=None,
        emit_missing_check_finding=False,
    )
    return TuiLintOutcome(report=report, parse_error=None)


def format_finding_rich_markup(code: str, severity: str, path: str, message: str) -> str:
    """Single-line Rich markup for RichLog (escaped user text)."""
    from rich.markup import escape

    sev = str(severity or "").strip().upper()
    style = "white"
    if sev == "FAIL":
        style = "bold red"
    elif sev == "WARN":
        style = "bold yellow"
    elif sev == "INFO":
        style = "bold bright_blue"
    elif sev == "PASS":
        style = "dim green"
    return (
        f"[{style}]{escape(sev)}[/{style}] "
        f"{escape(str(code))} [dim]|[/dim] {escape(str(path))}\n"
        f"  [dim]{escape(str(message))}[/dim]"
    )
