# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Contracts of a plugin console's run form: its closed shape and the selection it drives.

The neutral demo form and the selection table live in
``plugin_console_runs_support``; the view's mirror is held to the same table
in ``test_gui_plugin_console_runs_view``.
"""
from __future__ import annotations

import copy
from typing import Any

import pytest

from yggdrasim_common.gui_server.plugin_console_manifest import ConsoleManifestError, validate_manifest
from yggdrasim_common.gui_server.plugin_console_registry import required_methods
from yggdrasim_common.gui_server.plugin_console_runform import LABEL_DEFAULTS, MAX_RUN_FIELDS
from yggdrasim_common.gui_server.plugin_console_selection import find_variant, plan_run, select_run
from yggdrasim_common.gui_server.plugin_console_values import ConsoleInputError, check_entry_name

from tests.plugin_console_runs_support import PICK_CASES, PICK_CHOICES, SELECTION_CASES, demo_manifest, demo_runs, named_demo_runs, pick_demo_runs


def _refused(runs: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ConsoleManifestError) as caught:
        validate_manifest(demo_manifest(runs))
    assert fragment in str(caught.value)


def _variant_field(runs: dict[str, Any], name: str) -> dict[str, Any]:
    return next(field for field in runs["variants"][0]["fields"] if field["name"] == name)


# --- the closed shape -------------------------------------------------------


def test_a_run_form_alone_is_a_console_and_needs_the_run_methods() -> None:
    manifest = validate_manifest(demo_manifest())
    assert manifest["actions"] == [] and manifest["streams"] == [] and manifest["start"] is None
    runs = manifest["runs"]
    assert runs["labels"] == {**LABEL_DEFAULTS, "items": "Checks", "credentials": "Keys"}
    assert [group["place"] for group in runs["groups"]] == ["before_items", "after_items"]
    methods = required_methods(manifest)
    for name in ("run_start", "runs", "run", "run_events", "run_cancel", "credentials", "credential_store", "credential_forget"):
        assert name in methods, name
    without = demo_runs()
    without["credentials"] = []
    without["variants"][0]["credentials"] = []
    without["variants"][0]["items"][2]["credentials"] = []
    assert "credentials" not in required_methods(validate_manifest(demo_manifest(without)))


def test_the_validated_copy_fills_every_optional_key() -> None:
    runs = validate_manifest(demo_manifest())["runs"]
    item = runs["variants"][0]["items"][1]
    assert item == {
        "id": "ping",
        "label": "Ping",
        "summary": "",
        "badge": "card",
        "available": True,
        "unavailable_reason": "",
        "fields": ["count", "verbose"],
        "credentials": [],
        "auto_when": None,
    }
    assert runs["variants"][0]["items"][0]["auto_when"] == {"field": "source", "equals": "fetch"}
    key = _variant_field(runs, "key")
    assert key["secret"] is True and key["group"] == "keys" and key["visible_when"] == {"field": "use_key", "equals": True}
    assert _variant_field(runs, "reader")["secret"] is False and _variant_field(runs, "reader")["visible_when"] is None


def test_unknown_keys_are_refused_everywhere() -> None:
    for where in ("runs", "item", "group", "credential", "variant", "labels"):
        runs = demo_runs()
        target = {
            "runs": runs,
            "item": runs["variants"][0]["items"][1],
            "group": runs["groups"][0],
            "credential": runs["credentials"][0],
            "variant": runs["variants"][1],
        }.get(where)
        if where == "labels":
            runs["labels"]["html"] = "x"
        else:
            target["html"] = "<b>x</b>"
        _refused(runs, "unknown key(s) html")


def test_a_field_several_items_use_needs_a_group() -> None:
    runs = demo_runs()
    del _variant_field(runs, "count")["min"]
    runs["variants"][0]["items"][2]["fields"].append("count")
    _refused(runs, "used by several items, so it needs a group")


def test_a_condition_only_looks_back_and_matches_the_controller_type() -> None:
    runs = demo_runs()
    _variant_field(runs, "code")["visible_when"] = {"field": "verbose", "equals": True}
    _refused(runs, "'verbose' is not a field declared before this one")
    runs = demo_runs()
    _variant_field(runs, "key")["visible_when"] = {"field": "use_key", "equals": "yes"}
    _refused(runs, "true or false for a boolean field")
    runs = demo_runs()
    _variant_field(runs, "host")["visible_when"] = {"field": "mode", "equals": "satellite"}
    _refused(runs, "one of the controlling field's option values")


def test_a_controller_is_in_use_whenever_its_field_is() -> None:
    runs = demo_runs()
    # 'code' is always in use; a controller only 'ping' uses would vanish under it.
    variant = runs["variants"][0]
    variant["fields"].insert(3, {"name": "flag", "label": "Flag", "type": "boolean"})
    variant["items"][1]["fields"].append("flag")
    code = variant["fields"].pop(2)
    code["visible_when"] = {"field": "flag", "equals": True}
    variant["fields"].insert(4, code)
    _refused(runs, "its controller 'flag' is not in use whenever it is")


def test_secret_fields_are_text_without_a_default() -> None:
    runs = demo_runs()
    _variant_field(runs, "verbose")["secret"] = True
    _refused(runs, "only a text field can be secret")
    runs = demo_runs()
    _variant_field(runs, "key")["default"] = "00"
    _refused(runs, "a secret field carries no default")
    runs = demo_runs()
    _variant_field(runs, "host")["visible_when"] = {"field": "key", "equals": "x"}
    _variant_field(runs, "host")["group"] = "keys"
    _refused(runs, "a secret field cannot control another")


def test_auto_items_hang_on_a_field_no_item_names() -> None:
    runs = demo_runs()
    runs["variants"][0]["items"][0]["auto_when"] = {"field": "verbose", "equals": True}
    _refused(runs, "the controlling field must be one no item names")


def test_items_only_need_credentials_their_variant_offers() -> None:
    runs = demo_runs()
    runs["variants"][0]["credentials"] = []
    _refused(runs, "needs credential(s) the variant does not offer: service")
    runs = demo_runs()
    runs["variants"][0]["items"][1]["fields"].append("nowhere")
    _refused(runs, "no field 'nowhere'")


def test_credentials_are_plain_text_with_a_secret() -> None:
    runs = demo_runs()
    runs["credentials"][0]["fields"][1]["secret"] = False
    _refused(runs, "a credential needs at least one secret field")
    runs = demo_runs()
    runs["credentials"][0]["fields"].append({"name": "level", "label": "Level", "type": "number"})
    _refused(runs, "a credential takes plain text fields only")


def test_a_credential_may_rename_its_buttons() -> None:
    from yggdrasim_common.gui_server.plugin_console_runform import CREDENTIAL_LABEL_DEFAULTS

    runs = demo_runs()
    assert validate_manifest(demo_manifest(runs))["runs"]["credentials"][0]["labels"] == CREDENTIAL_LABEL_DEFAULTS
    runs["credentials"][0]["labels"] = {"store": "Sign in", "forget": "Sign out"}
    labels = validate_manifest(demo_manifest(runs))["runs"]["credentials"][0]["labels"]
    assert labels == {"store": "Sign in", "forget": "Sign out", "replace": "Replace"}
    runs["credentials"][0]["labels"] = {"store": "Sign in", "href": "x"}
    _refused(runs, "unknown key(s) href")
    runs["credentials"][0]["labels"] = {"store": "x" * 25}
    _refused(runs, "longer than 24 characters")


def test_groups_places_and_caps() -> None:
    runs = demo_runs()
    runs["groups"][0]["place"] = "floating"
    _refused(runs, "one of before_items, after_items")
    runs = demo_runs()
    runs["variants"][1]["fields"] = [{"name": f"f{index}", "label": f"F{index}", "type": "text"} for index in range(MAX_RUN_FIELDS + 1)]
    _refused(runs, f"more than {MAX_RUN_FIELDS} entries")
    runs = demo_runs()
    runs["variants"][1]["fields"] = [{"name": "operator", "label": "Again", "type": "text"}]
    _refused(runs, "'operator' is declared twice")


# --- the selection ----------------------------------------------------------

def _plan(ticked: list[str], values: dict[str, Any]) -> dict[str, Any]:
    runs = validate_manifest(demo_manifest())["runs"]
    return plan_run(runs, find_variant(runs, "basic"), ticked, values)


@pytest.mark.parametrize(("name", "ticked", "values", "expected"), SELECTION_CASES, ids=[case[0] for case in SELECTION_CASES])
def test_the_selection_table(name: str, ticked: list[str], values: dict[str, Any], expected: dict[str, Any]) -> None:
    plan = _plan(ticked, values)
    assert {key: plan[key] for key in expected} == expected, name


# --- a choice the console fills ----------------------------------------------------------


def _pick_field(**extra: Any) -> dict[str, Any]:
    return {"name": "target", "label": "Target", "type": "choice", "options_from": "targets", **extra}


def _with_pick(field: dict[str, Any], *more: dict[str, Any]) -> dict[str, Any]:
    runs = demo_runs()
    other = runs["variants"][1]
    other["fields"] = [field, *more]
    other["items"].append({"id": "aim", "label": "Aim", "fields": [entry["name"] for entry in (field, *more)]})
    return runs


def test_a_choice_may_take_its_options_from_the_console() -> None:
    checked = validate_manifest(demo_manifest(pick_demo_runs()))["runs"]
    field = checked["variants"][1]["fields"][0]
    assert field["options_from"] == "targets" and field["options"] == [] and field["default"] == "" and field["required"] is True
    assert all(entry["options_from"] == "" for entry in checked["variants"][0]["fields"] + checked["fields"])
    assert checked["accepts_while_running"] is False
    runs = pick_demo_runs()
    runs["accepts_while_running"] = True
    assert validate_manifest(demo_manifest(runs))["runs"]["accepts_while_running"] is True


@pytest.mark.parametrize(
    ("field", "fragment"),
    [
        (_pick_field(type="text"), "only a choice field takes its options from the console"),
        (_pick_field(options=[{"value": "x", "label": "X"}]), "declares no options and no default"),
        (_pick_field(default="x"), "declares no options and no default"),
        (_pick_field(options_from="Bad Name"), "options_from: must match"),
    ],
)
def test_a_choice_the_console_fills_declares_nothing_else(field: dict[str, Any], fragment: str) -> None:
    _refused(_with_pick(field), fragment)


def test_a_choice_the_console_fills_controls_no_field_and_the_flag_is_a_flag() -> None:
    _refused(_with_pick(_pick_field(), {"name": "why", "label": "Why", "type": "text", "visible_when": {"field": "target", "equals": "x"}}), "cannot control another field")
    runs = demo_runs()
    runs["accepts_while_running"] = "yes"
    _refused(runs, "accepts_while_running: must be true or false")


@pytest.mark.parametrize(("name", "ticked", "values", "choices", "expected"), PICK_CASES, ids=[case[0] for case in PICK_CASES])
def test_the_pick_table(name: str, ticked: list[str], values: dict[str, Any], choices: dict[str, Any], expected: dict[str, Any]) -> None:
    runs = validate_manifest(demo_manifest(pick_demo_runs()))["runs"]
    plan = plan_run(runs, find_variant(runs, "other"), ticked, values, choices)
    assert {key: plan[key] for key in expected} == expected, name


def test_a_pick_is_checked_against_the_console_s_current_list() -> None:
    runs = validate_manifest(demo_manifest(pick_demo_runs()))["runs"]
    variant = find_variant(runs, "other")
    values = {"operator": "Ann", "note": "n"}
    assert plan_run(runs, variant, ["aim"], {**values, "target": ""}, PICK_CHOICES)["problems"] == ["Target: required"]
    assert plan_run(runs, variant, ["aim"], {**values, "target": "t9"}, PICK_CHOICES)["problems"] == ["Target: not one of the current choices"]
    assert plan_run(runs, variant, ["aim"], {**values, "target": "t1"}, {})["problems"] == ["Target: nothing to pick from yet"]
    assert plan_run(runs, variant, ["aim"], {**values, "target": "t1"}, {"targets": "junk"})["problems"] == ["Target: nothing to pick from yet"]
    request = select_run(runs, {"variant": "other", "items": ["aim"], "values": {**values, "target": "t1"}}, PICK_CHOICES)
    assert request["values"] == {**values, "target": "t1"}
    with pytest.raises(ConsoleInputError, match="Target: not one of the current choices"):
        select_run(runs, {"variant": "other", "items": ["aim"], "values": {**values, "target": "t9"}}, PICK_CHOICES)
    with pytest.raises(ConsoleInputError, match="Target: nothing to pick from yet"):
        select_run(runs, {"variant": "other", "items": ["aim"], "values": {**values, "target": "t1"}})


def test_the_console_s_lists_are_cut_to_the_declared_sources() -> None:
    from yggdrasim_common.gui_server.plugin_console_output import MAX_CHOICES, choices_payload, dynamic_sources, status_payload

    manifest = validate_manifest(demo_manifest(pick_demo_runs()))
    assert dynamic_sources(manifest["runs"]) == ["targets"]
    raw = {
        "targets": [{"value": "t1", "label": "One"}, {"value": "t1", "label": "Again"}, {"value": "", "label": "blank"}, "junk", {"value": 2}]
        + [{"value": f"x{index}", "label": "x"} for index in range(MAX_CHOICES)],
        "stray": [{"value": "s", "label": "S"}],
    }
    cut = choices_payload(manifest["runs"], raw)
    assert list(cut) == ["targets"] and cut["targets"][:2] == [{"value": "t1", "label": "One"}, {"value": "2", "label": "2"}] and len(cut["targets"]) == MAX_CHOICES
    assert choices_payload(manifest["runs"], None) == {"targets": []}
    status = status_payload({"running": True, "choices": raw}, manifest)
    assert status["choices"]["targets"][0] == {"value": "t1", "label": "One"} and "stray" not in status["choices"]
    # A form without such a field passes no lists on, whatever the console answers.
    assert "choices" not in status_payload({"running": True, "choices": raw}, validate_manifest(demo_manifest()))


def test_only_visible_values_reach_the_plugin() -> None:
    runs = validate_manifest(demo_manifest())["runs"]
    request = select_run(
        runs,
        {
            "variant": "basic",
            "items": ["link", "ping", "link"],
            "values": {"operator": " Ann ", "reader": "R", "mode": "local", "host": "left over", "identity_file": "/tmp/id", "count": "4"},
        },
    )
    assert request == {
        "variant": "basic",
        "items": ["ping", "link"],
        "auto_items": [],
        "values": {"operator": "Ann", "note": "", "reader": "R", "source": "card", "count": 4, "verbose": False, "use_key": False, "mode": "local"},
        "credentials": [],
    }


@pytest.mark.parametrize(
    ("payload", "fragment"),
    [
        ({"variant": "nope", "items": ["ping"]}, "no variant 'nope'"),
        ({"variant": "basic", "items": []}, "Checks: tick at least one"),
        ({"variant": "basic", "items": ["prepare"]}, "Prepare: selected by itself, not by a tick"),
        ({"variant": "basic", "items": ["later"], "values": {"operator": "A", "reader": "R"}}, "Later: not built yet"),
        ({"variant": "basic", "items": ["ghost"]}, "no item 'ghost' in Basic"),
        ({"variant": "basic", "items": ["ping"], "values": {"operator": "A", "reader": "R", "extra": 1}}, "no field named extra"),
        ({"variant": "basic", "items": ["ping"], "values": {"operator": "A", "reader": "R", "count": 12}}, "Count: above 9"),
        ({"variant": "basic", "items": ["ping"], "values": {"reader": "R"}}, "Operator: required"),
        ({"variant": "basic", "items": "ping"}, "items must be a list"),
    ],
)
def test_requests_the_form_would_not_send_are_refused(payload: dict[str, Any], fragment: str) -> None:
    runs = validate_manifest(demo_manifest())["runs"]
    with pytest.raises(ConsoleInputError) as caught:
        select_run(runs, copy.deepcopy(payload))
    assert fragment in str(caught.value)


def test_an_unavailable_variant_cannot_run() -> None:
    runs_raw = demo_runs()
    runs_raw["variants"][1]["available"] = False
    runs_raw["variants"][1]["unavailable_reason"] = "waits for its API"
    runs = validate_manifest(demo_manifest(runs_raw))["runs"]
    with pytest.raises(ConsoleInputError, match="Other: waits for its API"):
        select_run(runs, {"variant": "other", "items": ["only"], "values": {"operator": "A"}})


# --- named credentials --------------------------------------------------------


def test_named_is_a_flag_that_defaults_to_one_entry() -> None:
    runs = validate_manifest(demo_manifest(named_demo_runs()))["runs"]
    assert {credential["id"]: credential["named"] for credential in runs["credentials"]} == {"service": False, "vault": True}
    raw = named_demo_runs()
    raw["credentials"][1]["named"] = "yes"
    _refused(raw, "named")


@pytest.mark.parametrize("name", ["prod", "Tenant-A", "eu.west_2", "9", "a" * 40])
def test_an_entry_name_is_one_short_word(name: str) -> None:
    assert check_entry_name(" " + name + " ", "Vault token") == name


@pytest.mark.parametrize("value", [None, "", "   ", "-prod", ".hidden", "two words", "a" * 41, "tab\there", "semi;colon", 7])
def test_a_malformed_entry_name_is_refused_without_repeating_it(value: Any) -> None:
    with pytest.raises(ConsoleInputError) as caught:
        check_entry_name(value, "Vault token")
    message = str(caught.value)
    assert message.startswith("Vault token: ")
    if isinstance(value, str) and value.strip():
        assert value.strip() not in message


def _named_request(variant: str, item: str, picks: Any) -> dict[str, Any]:
    runs = validate_manifest(demo_manifest(named_demo_runs()))["runs"]
    payload: dict[str, Any] = {"variant": variant, "items": [item], "values": {"operator": "Ann", "reader": "R"} if variant == "basic" else {"operator": "Ann"}}
    if picks is not None:
        payload["credential_entries"] = picks
    return select_run(runs, payload)


def test_a_needed_named_credential_carries_its_pick() -> None:
    request = _named_request("other", "only", {"vault": " prod "})
    assert request["credentials"] == ["vault"] and request["credential_entries"] == {"vault": "prod"}
    # Without a pick the key is still there; the route refuses the start.
    assert _named_request("other", "only", None)["credential_entries"] == {}
    # A run that needs no named credential sends exactly what it did before.
    assert "credential_entries" not in _named_request("basic", "ping", None)


@pytest.mark.parametrize(
    ("variant", "item", "picks", "fragment"),
    [
        ("basic", "sign", {"service": "prod"}, "no entry can be picked for 'service'"),
        ("basic", "ping", {"vault": "prod"}, "no entry can be picked for 'vault'"),
        ("other", "only", {"ghost": "prod"}, "no entry can be picked for 'ghost'"),
        ("other", "only", {"vault": "two words"}, "Vault token: an entry name is 1 to 40"),
        ("other", "only", ["vault"], "credential_entries must be an object"),
    ],
)
def test_a_pick_the_run_cannot_use_is_refused(variant: str, item: str, picks: Any, fragment: str) -> None:
    with pytest.raises(ConsoleInputError) as caught:
        _named_request(variant, item, picks)
    assert fragment in str(caught.value)


def test_a_credential_takes_up_to_eight_fields() -> None:
    runs = named_demo_runs()
    fields = runs["credentials"][1]["fields"]
    fields.extend({"name": f"setting_{index}", "label": f"Setting {index}", "type": "text"} for index in range(6))
    assert len(validate_manifest(demo_manifest(runs))["runs"]["credentials"][1]["fields"]) == 8
    fields.append({"name": "one_more", "label": "One more", "type": "text"})
    _refused(runs, "more than 8 entries")
