# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = (_ROOT / "gui_frontend/src/js/saip-workbench.js").read_text(
    encoding="utf-8"
)
_SERVED = (_ROOT / "yggdrasim_common/gui_server/static/app.js").read_text(
    encoding="utf-8"
)


def test_variable_security_contract_is_synced_to_served_bundle() -> None:
    # The served monolith has a few intentional presentation-only differences
    # (notably its shared ribbon-icon renderer), so compare the security-critical
    # fragments instead of requiring the entire source module to be identical.
    prompt_start = _SOURCE.index("  async function saipPromptSetVariable")
    fragments = (
        _SOURCE[
            _SOURCE.index("  function saipVariableName"):
            _SOURCE.index("  // Token-defs lookup.")
        ],
        _SOURCE[
            prompt_start:
            _SOURCE.index("  // Render any payload node", prompt_start)
        ],
        _SOURCE[
            _SOURCE.index("  // SA-4 variables pane"):
            _SOURCE.index("  // SA-4 compare pane")
        ],
        'out[name] = saipVariableIsSecret(row) ? "••••••••" : String(row.value || "");',
    )
    for fragment in fragments:
        assert _SOURCE.count(fragment) == 1
        assert _SERVED.count(fragment) == 1


def test_typed_variable_metadata_and_secret_presentation_are_supported() -> None:
    for field in (
        "label",
        "input_kind",
        "input_format",
        "classification",
        "status",
        "required",
        "secret",
        "source",
    ):
        assert field in _SOURCE
    assert 'valInp.type = secret ? "password" : "text";' in _SOURCE
    assert 'valueCode.title = "Secret value hidden.";' in _SOURCE
    assert 'data-variable-secret' not in _SOURCE  # DOM property, never HTML interpolation.
    assert "tr.dataset.variableSecret" in _SOURCE
    assert ">Catalog</span>" in _SOURCE
    assert ">Inline</span>" in _SOURCE


def test_variable_submission_logs_never_include_the_submitted_value() -> None:
    start = _SOURCE.index("async function saipApplyVariable(")
    end = _SOURCE.index("// SA-4 compare pane", start)
    apply_source = _SOURCE[start:end]
    assert 'message: n + " <- " + v' not in apply_source
    assert "saipVariableRedactMessage" in apply_source
    assert "value submitted" in apply_source
