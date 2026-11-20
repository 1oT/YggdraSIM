# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The eIMs section of the Local eIM page reaches the addEim package as well as Link this eIM.

addEim (SGP.32 v1.3 §2.11.1.1, an eCO in a signed eUICC Package) adds an eIM
beside the ones the card has; Link this eIM (AddInitialEim after a reset)
leaves this eIM the only one. The button opens the New operation form on the
Add eIM operation, whose config field offers the saved eIM configurations.
"""

from __future__ import annotations

from pathlib import Path

from SCP11.eim_local.engine.catalogue import operation_type

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "gui_frontend" / "src" / "js" / "local-eim-page.js"


def _function(text: str, name: str) -> str:
    start = text.index(f"    function {name}(")
    end = text.index("\n    }\n", start)
    return text[start:end]


def test_the_eim_section_opens_the_new_operation_form_on_add_eim() -> None:
    page = PAGE.read_text(encoding="utf-8")
    eims = _function(page, "renderEims")
    assert 'lepButton("Add an eIM (addEim)"' in eims
    assert 'state.newOperationType = "ADD-EIM";' in eims
    assert "state.scrollToNewOperation = true;" in eims
    # Link this eIM stays, and the help text tells the two apart.
    assert 'lepButton("Link this eIM"' in eims
    assert "keeps the eIMs it has" in eims and "adds this eIM as its only one" in eims


def test_the_form_opens_on_the_preset_and_forgets_it_when_closed() -> None:
    page = PAGE.read_text(encoding="utf-8")
    form = _function(page, "renderNewOperation")
    assert "if (state.newOperationType) select.value = state.newOperationType;" in form
    assert form.index("select.value = state.newOperationType") < form.index("drawFields();")
    assert form.count('state.newOperationType = "";') == 1  # Cancel
    # Queueing, leaving the eUICC and the head's New operation button start from the first type again.
    assert page.count('state.newOperationType = "";') == 4


def test_add_eim_takes_a_saved_configuration() -> None:
    kind = operation_type("ADD_EIM")
    assert kind.verb == "ADD-EIM"
    names = [spec.name for spec in kind.params]
    assert names[0] == "config" and "association_token" in names
    naming = (REPO / "guides" / "NAMING_CONVENTIONS.md").read_text(encoding="utf-8")
    assert "| Add an eIM (addEim) |" in naming
