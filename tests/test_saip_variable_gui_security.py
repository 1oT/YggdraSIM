# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Variable presentation policy of the SAIP workbench.

Whoever holds the profile sees every value in the workbench: the token
editor, the binding rows and the decoded views show PINs, PUKs, ADM codes
and keys in full. A sensitive name still carries its classification
(``secret`` flag, "Sensitive" chip), and the submitted value never reaches
a log line or message text.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = (_ROOT / "gui_frontend/src/js/saip-workbench.js").read_text(
    encoding="utf-8"
)
_SERVED = (_ROOT / "yggdrasim_common/gui_server/static/app.js").read_text(
    encoding="utf-8"
)


def test_variable_presentation_contract_is_synced_to_served_bundle() -> None:
    prompt_start = _SOURCE.index("  async function saipSetVariableValue")
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
        'out[name] = String(row.value || "");',
    )
    for fragment in fragments:
        assert _SOURCE.count(fragment) == 1
        assert _SERVED.count(fragment) == 1


def test_values_are_shown_in_full_and_the_classification_is_kept() -> None:
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
    # No masking anywhere in the workbench.
    assert "••••••••" not in _SOURCE
    assert '"Secret value hidden."' not in _SOURCE
    assert 'valInp.type = "text";' in _SOURCE
    assert 'valInp.type = secret ? "password" : "text";' not in _SOURCE
    assert "(secret value stored -- hidden)" not in _SOURCE
    # The classification still marks the row.
    assert 'data-variable-secret' not in _SOURCE  # DOM property, never HTML interpolation.
    assert "tr.dataset.variableSecret" in _SOURCE
    assert ">Sensitive</span>" in _SOURCE
    # The source is metadata text beside the value, not a chip of its own.
    assert '.catalog ? "Catalog" : "Inline"' in _SOURCE


def test_variable_submission_logs_never_include_the_submitted_value() -> None:
    start = _SOURCE.index("async function saipApplyVariable(")
    end = _SOURCE.index("// SA-4 compare pane", start)
    apply_source = _SOURCE[start:end]
    assert 'message: n + " <- " + v' not in apply_source
    assert "saipVariableRedactMessage" in apply_source
    assert "value submitted" in apply_source
