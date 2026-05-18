# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Run SaipProfileLinter against TRANSCODE-TUI JSON buffer (lazy import of linter only from TUI).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .lint_engine import LintReport, SaipProfileLinter
from .saip_hex_template import (
    detect_inline_placeholders,
    substitute_inline_placeholders_in_editor_json,
)
from .saip_json_codec import (
    parse_editor_json,
    parse_editor_json_template_aware,
)


@dataclass
class TuiLintOutcome:
    report: Optional[LintReport]
    parse_error: Optional[str]
    template_mode: bool = False
    undefined_tokens: frozenset[str] = field(default_factory=frozenset)
    placeholder_paths: frozenset[str] = field(default_factory=frozenset)
    inline_placeholder_count: int = 0
    inline_placeholder_paths: frozenset[str] = field(default_factory=frozenset)


def lint_profile_json_buffer(
    json_text: str,
    profile_label: str,
    *,
    strict: bool = False,
) -> TuiLintOutcome:
    """
    Parse tagged editor JSON and run the same structural rules as ``LINT`` (without metadata).

    When the buffer contains ``{NAME}`` / ``[NAME]`` placeholders that aren't
    registered under ``__ygg_token_defs__``, the parse is retried in
    template-aware mode: undefined tokens are resolved to zero bytes and the
    linter is told which paths contain placeholder fields so that
    hex/ICCID-shape rules don't fire against template scaffolding.

    ``saip-tool check`` is not executed (no subprocess); ``emit_missing_check_finding=False``
    avoids a synthetic YRL-CHK-001 warning in the panel.
    """

    placeholder_paths: frozenset[str] = frozenset()
    undefined_tokens: frozenset[str] = frozenset()
    template_mode = False

    # Pre-substitute inline typed placeholders (``{name:TYPE:length[:mod]}``)
    # so dejsonify sees valid hex. The paths of rewritten hex leaves are
    # fed into the linter as ``placeholder_paths`` to downgrade FAIL/WARN
    # findings rooted beneath them — a placeholder-bearing leaf is
    # authoring scaffolding, not a broken profile, and should read as
    # INFO rather than red.
    inline_paths: frozenset[str] = frozenset()
    inline_count = 0
    if detect_inline_placeholders(json_text):
        json_text, inline_paths, inline_count = (
            substitute_inline_placeholders_in_editor_json(json_text)
        )

    try:
        document = parse_editor_json(json_text)
    except Exception as strict_exc:
        strict_message = str(strict_exc)
        try:
            document, placeholder_paths, undefined_tokens = (
                parse_editor_json_template_aware(json_text)
            )
        except Exception as template_exc:
            return TuiLintOutcome(
                report=None,
                parse_error=(
                    f"{strict_message} (template-aware retry also failed: "
                    f"{template_exc})"
                ),
                inline_placeholder_count=inline_count,
                inline_placeholder_paths=inline_paths,
            )
        template_mode = True

    if template_mode is False and len(placeholder_paths) == 0:
        # The editor buffer may still carry defined placeholders; surface them
        # so the TUI can report template-authoring context alongside a clean
        # lint.
        try:
            _document, placeholder_paths, undefined_tokens = (
                parse_editor_json_template_aware(json_text)
            )
        except Exception:
            placeholder_paths = frozenset()
            undefined_tokens = frozenset()

    merged_placeholder_paths = frozenset(placeholder_paths | inline_paths)

    linter = SaipProfileLinter(strict=strict)
    report = linter.lint_decoded_document(
        decoded_document=document,
        profile_label=profile_label,
        check_return_code=None,
        check_stderr="",
        metadata=None,
        metadata_path=None,
        emit_missing_check_finding=False,
        placeholder_paths=merged_placeholder_paths,
        undefined_tokens=undefined_tokens,
    )
    return TuiLintOutcome(
        report=report,
        parse_error=None,
        template_mode=template_mode,
        undefined_tokens=undefined_tokens,
        placeholder_paths=merged_placeholder_paths,
        inline_placeholder_count=inline_count,
        inline_placeholder_paths=inline_paths,
    )


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
