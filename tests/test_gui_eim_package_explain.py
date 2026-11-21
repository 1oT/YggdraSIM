# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""The Command Center's eIM package explain action answers with the shell's payload."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from SCP11.eim_local.session import EimLocalSession
from yggdrasim_common.gui_server.actions import eim_local
from yggdrasim_common.gui_server.actions.registry import ActionContext

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (
    REPO_ROOT
    / "SCP11"
    / "eim_local"
    / "eim_packages"
    / "templates"
    / "template_euicc_package_request_psmos.json"
)
CERTIFICATE_PREVIEW = {"path": "eim-signing.der", "subject": "CN=eim.example.test"}


def _with_signing_certificate():
    """Stand in for a configured eIM signing certificate; the scratch runtime root has none."""
    return patch.object(
        EimLocalSession,
        "preview_eim_signing_certificate",
        return_value=dict(CERTIFICATE_PREVIEW),
    )


def test_explain_describes_a_shipped_package_template() -> None:
    with _with_signing_certificate():
        result = eim_local._dispatch_eim_package_explain(ActionContext(), package_path=str(TEMPLATE))

    assert result["ok"] is True, result["note"]
    explain = result["explain"]
    assert sorted(explain) == [
        "identity_defaults",
        "lint",
        "package",
        "runtime_hints",
        "signing_certificate",
    ]
    assert Path(explain["package"]["path"]) == TEMPLATE
    assert explain["signing_certificate"] == CERTIFICATE_PREVIEW
    assert explain["package"]["type"] == explain["lint"]["package_type"]
    assert len(explain["package"]["type"]) > 0
    assert result["note"] == f"package explained: {explain['package']['type']}"


def test_explain_matches_the_shell_verb_payload() -> None:
    from SCP11.eim_local.main import EimLocalShell

    shell = EimLocalShell.__new__(EimLocalShell)
    shell.session = EimLocalSession()
    with _with_signing_certificate():
        from_shell = shell._build_eim_package_explain_payload(str(TEMPLATE))
        from_action = eim_local._dispatch_eim_package_explain(ActionContext(), package_path=str(TEMPLATE))

    assert from_action["explain"] == eim_local._scrub_bytes(from_shell)


def test_explain_reports_a_missing_signing_certificate_as_the_shell_does() -> None:
    result = eim_local._dispatch_eim_package_explain(ActionContext(), package_path=str(TEMPLATE))

    assert result["ok"] is False
    assert "signing certificate" in result["note"]


def test_explain_reports_a_file_it_cannot_read() -> None:
    result = eim_local._dispatch_eim_package_explain(
        ActionContext(),
        package_path=str(REPO_ROOT / "tests" / "no_such_eim_package.json"),
    )

    assert result["ok"] is False
    assert result["explain"] == {}
    assert len(result["note"]) > 0
