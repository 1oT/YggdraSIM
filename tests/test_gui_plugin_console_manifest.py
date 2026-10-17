# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Contracts of the plugin console manifest, input and output checks.

The manifest is all a plugin hands the generic console view, so its shape is
closed: an unknown key, field kind or malformed id refuses the whole
manifest. Operator values are checked against the declared fields, an
action's template only ever receives single words that cannot read as
options, and provider answers are reduced to bounded plain values.
"""
from __future__ import annotations

import copy
from typing import Any

import pytest

from yggdrasim_common.gui_server import plugin_console_output as output
from yggdrasim_common.gui_server.plugin_console_manifest import ConsoleManifestError, validate_manifest
from yggdrasim_common.gui_server.plugin_console_values import (
    MAX_COMMAND_LINE,
    ConsoleInputError,
    check_command_line,
    check_values,
    render_action_line,
)


def _manifest() -> dict[str, Any]:
    return {
        "id": "demo",
        "title": "Demo console",
        "summary": "A console the tests declare.",
        "start": {
            "label": "Open",
            "fields": [
                {"name": "reader", "label": "Reader", "type": "reader"},
                {"name": "count", "label": "Count", "type": "number", "min": 1, "max": 9, "default": 3},
                {"name": "verbose", "label": "Verbose", "type": "boolean"},
                {"name": "mode", "label": "Mode", "type": "choice", "options": [{"value": "", "label": "default"}, {"value": "fast", "label": "fast"}]},
                {"name": "tag", "label": "Tag", "type": "text", "pattern": "[a-z]+", "max_length": 8},
            ],
        },
        "actions": [
            {
                "id": "echo",
                "label": "Echo",
                "template": "ECHO {word} {times}",
                "group": "basics",
                "fields": [
                    {"name": "word", "label": "Word", "type": "text"},
                    {"name": "times", "label": "Times", "type": "number", "min": -5, "max": 5},
                ],
            },
            {"id": "ping", "label": "Ping", "template": "PING"},
        ],
        "command_line": {"placeholder": "HELP"},
        "streams": [
            {"id": "log", "title": "Log", "columns": [{"key": "at", "label": "Time", "format": "time"}, {"key": "text", "label": "Text"}]},
        ],
    }


def _refused(manifest: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ConsoleManifestError) as excinfo:
        validate_manifest(manifest)
    assert fragment in str(excinfo.value)


# --- manifest shape ------------------------------------------------------------------


def test_a_stream_column_may_be_mono() -> None:
    manifest = _manifest()
    manifest["streams"][0]["columns"].append({"key": "line", "label": "Terminal", "format": "mono"})
    columns = validate_manifest(manifest)["streams"][0]["columns"]
    assert columns[-1] == {"key": "line", "label": "Terminal", "format": "mono", "width": "fill"}
    from yggdrasim_common.gui_server.plugin_console_output import stream_batch

    batch = stream_batch(validate_manifest(manifest)["streams"][0], {"entries": [{"seq": 1, "at": 1.5, "text": "t", "line": "  [*] step\n  -> SW 9000"}], "next": 1}, 0)
    assert batch["entries"][0]["line"] == "  [*] step\n  -> SW 9000"
    manifest["streams"][0]["columns"][-1]["format"] = "ansi"
    _refused(manifest, "format: one of text, time, hex, mono")


def test_an_action_may_sit_in_the_comparison_panel() -> None:
    manifest = _manifest()
    manifest["compare"] = {"sides": [{"id": "card", "label": "Card"}, {"id": "record", "label": "Record"}]}
    manifest["actions"][1]["place"] = "compare"
    checked = validate_manifest(manifest)
    assert [action["place"] for action in checked["actions"]] == ["actions", "compare"]
    manifest["actions"][1]["place"] = "sidebar"
    _refused(manifest, "place: one of actions, compare")
    manifest["actions"][1]["place"] = "compare"
    del manifest["compare"]
    _refused(manifest, "placed in the comparison panel, which this console does not declare: ping")


def test_a_full_manifest_is_accepted_with_every_default_filled() -> None:
    manifest = validate_manifest(_manifest())
    fields = {field["name"]: field for field in manifest["start"]["fields"]}
    assert manifest["start"]["label"] == "Open"
    assert fields["reader"]["default"] == "" and fields["count"]["default"] == 3
    assert fields["verbose"]["default"] is False and fields["mode"]["default"] == ""
    assert fields["tag"]["max_length"] == 8 and fields["count"]["step"] is None
    assert all(field["required"] is True for field in manifest["actions"][0]["fields"])
    assert manifest["actions"][1]["fields"] == [] and manifest["actions"][1]["group"] == ""
    assert manifest["command_line"] == {"placeholder": "HELP", "hint": ""}
    assert manifest["streams"][0]["columns"][1]["format"] == "text"
    assert [column["width"] for column in manifest["streams"][0]["columns"]] == ["narrow", "fill"]
    assert manifest["state"] is None and manifest["pills"] == []


@pytest.mark.parametrize(
    "path",
    [
        ("html",),
        ("start", "style"),
        ("actions", 0, "href"),
        ("actions", 0, "fields", 0, "onclick"),
        ("start", "fields", 3, "options", 0, "extra"),
        ("command_line", "script"),
        ("streams", 0, "markup"),
        ("streams", 0, "columns", 0, "html"),
    ],
)
def test_unknown_keys_are_refused_at_every_level(path: tuple[Any, ...]) -> None:
    manifest = _manifest()
    target: Any = manifest
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = "<b>x</b>"
    _refused(manifest, "unknown key(s) " + str(path[-1]))


@pytest.mark.parametrize("console_id", ["Demo", "1demo", "a" * 33, "demo console", "../x", ""])
def test_console_ids_are_short_slugs(console_id: str) -> None:
    manifest = _manifest()
    manifest["id"] = console_id
    _refused(manifest, "manifest.id")


def test_names_and_stream_ids_are_slugs() -> None:
    manifest = _manifest()
    manifest["start"]["fields"][1]["name"] = "Count"
    _refused(manifest, "start.fields[1].name")
    manifest = _manifest()
    manifest["streams"][0]["id"] = "log stream"
    _refused(manifest, "streams[0].id")


def test_field_kinds_are_a_closed_set() -> None:
    manifest = _manifest()
    manifest["start"]["fields"][0]["type"] = "file"
    _refused(manifest, "start.fields[0].type")
    for kind in ("boolean", "reader"):
        manifest = _manifest()
        manifest["actions"][0]["fields"][0] = {"name": "word", "label": "Word", "type": kind}
        _refused(manifest, "actions[0].fields[0].type")


def test_type_keys_stay_with_their_type() -> None:
    manifest = _manifest()
    manifest["start"]["fields"][4]["options"] = [{"value": "a", "label": "a"}]
    _refused(manifest, "options does not apply to a text field")
    manifest = _manifest()
    manifest["start"]["fields"][1]["pattern"] = "[0-9]+"
    _refused(manifest, "pattern does not apply to a number field")


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda m: m["actions"].append(copy.deepcopy(m["actions"][1])), "'ping' is declared twice"),
        (lambda m: m["start"]["fields"].append(copy.deepcopy(m["start"]["fields"][0])), "'reader' is declared twice"),
        (lambda m: m["streams"].append(copy.deepcopy(m["streams"][0])), "'log' is declared twice"),
        (lambda m: m["streams"][0]["columns"].append({"key": "at", "label": "Again"}), "'at' is declared twice"),
        (lambda m: m["start"]["fields"][3]["options"].append({"value": "fast", "label": "again"}), "'fast' is declared twice"),
    ],
)
def test_duplicates_are_refused(mutate: Any, fragment: str) -> None:
    manifest = _manifest()
    mutate(manifest)
    _refused(manifest, fragment)


@pytest.mark.parametrize(
    "template, fragment",
    [
        ("ECHO {word} {times} {extra}", "placeholder(s) without a field: extra"),
        ("ECHO {word}", "field(s) the template never uses: times"),
        ("ECHO {word} {times} }", "a brace outside"),
        ("ECHO {word} {{times}}", "a brace outside"),
    ],
)
def test_templates_match_their_fields(template: str, fragment: str) -> None:
    manifest = _manifest()
    manifest["actions"][0]["template"] = template
    _refused(manifest, fragment)


def test_action_fields_are_required_and_choices_are_words() -> None:
    manifest = _manifest()
    manifest["actions"][0]["fields"][0]["required"] = False
    _refused(manifest, "an action field is always required")
    for value in ("two words", "-x", ""):
        manifest = _manifest()
        manifest["actions"][0]["fields"][0] = {"name": "word", "label": "Word", "type": "choice", "options": [{"value": value, "label": "v"}]}
        _refused(manifest, "is not one word")


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda m: m.update(title="x" * 61), "longer than 60"),
        (lambda m: m["actions"][0].update(label="two\nlines"), "control characters"),
        (lambda m: m["start"]["fields"][4].update(pattern="[a-"), "not a regular expression"),
        (lambda m: m["start"]["fields"][4].update(default="ABC"), "does not match the field's pattern"),
        (lambda m: m["start"]["fields"][1].update(default=10), "outside min / max"),
        (lambda m: m["start"]["fields"][1].update(min=10), "min is above max"),
        (lambda m: m["start"]["fields"][1].update(step=0), "must be above zero"),
        (lambda m: m["start"]["fields"][1].update(default=True), "finite number"),
        (lambda m: m["start"]["fields"][3].update(default="slow"), "one of the option values"),
        (lambda m: m["start"]["fields"][3].update(options=[]), "at least one option"),
        (lambda m: m["start"]["fields"][4].update(max_length=0), "an integer from 1"),
        (lambda m: m["streams"][0]["columns"][0].update(format="html"), "one of text, time, hex"),
        (lambda m: m["streams"][0].update(columns=[]), "at least one column"),
    ],
)
def test_values_inside_the_manifest_are_checked(mutate: Any, fragment: str) -> None:
    manifest = _manifest()
    mutate(manifest)
    _refused(manifest, fragment)


def test_a_console_has_to_declare_something_to_show() -> None:
    _refused({"id": "empty", "title": "Empty", "start": {"fields": []}}, "declares no action, command line, stream, comparison or run form")
    assert validate_manifest({"id": "lines", "title": "Lines", "command_line": {}})["start"] is None
    compare_only = {"id": "pair", "title": "Pair", "compare": {"sides": [{"id": "a", "label": "A"}, {"id": "b", "label": "B"}]}}
    assert validate_manifest(compare_only)["compare"]["title"] == "Comparison"


def test_a_manifest_that_is_not_an_object_is_refused() -> None:
    for raw in (None, [], "demo", 3):
        _refused(raw, "manifest: must be an object")  # type: ignore[arg-type]


# --- operator values ------------------------------------------------------------------


def test_start_values_are_checked_and_defaulted() -> None:
    fields = validate_manifest(_manifest())["start"]["fields"]
    assert check_values(fields, {"count": "4", "reader": "  Reader 1 "}) == {"reader": "Reader 1", "count": 4, "verbose": False, "mode": "", "tag": ""}
    assert check_values(fields, None)["count"] == 3
    assert check_values(fields, {"count": 2.5})["count"] == 2.5


@pytest.mark.parametrize(
    "values, fragment",
    [
        ({"unknown": 1}, "no field named unknown"),
        ({"count": 10}, "Count: above 9"),
        ({"count": "x"}, "Count: not a number"),
        ({"count": True}, "Count: not a number"),
        ({"count": float("nan")}, "Count: not a finite number"),
        ({"verbose": "yes"}, "Verbose: must be true or false"),
        ({"mode": "slow"}, "Mode: one of"),
        ({"tag": "ABC"}, "Tag: does not match"),
        ({"tag": "abcdefghi"}, "Tag: longer than 8"),
        ({"reader": "Reader\x001"}, "Reader: must not contain control characters"),
        ({"reader": 0}, "Reader: must be text"),
    ],
)
def test_start_values_that_do_not_fit_are_refused(values: dict[str, Any], fragment: str) -> None:
    fields = validate_manifest(_manifest())["start"]["fields"]
    with pytest.raises(ConsoleInputError) as excinfo:
        check_values(fields, values)
    assert fragment in str(excinfo.value)


def test_values_must_be_an_object() -> None:
    fields = validate_manifest(_manifest())["start"]["fields"]
    with pytest.raises(ConsoleInputError):
        check_values(fields, ["count", 3])


def test_an_action_binds_single_words_only() -> None:
    action = validate_manifest(_manifest())["actions"][0]
    assert render_action_line(action, check_values(action["fields"], {"word": " hello ", "times": -2})) == "ECHO hello -2"
    for word in ("two words", "--far", "-x", "tab\there"):
        with pytest.raises(ConsoleInputError):
            render_action_line(action, check_values(action["fields"], {"word": word, "times": 1}))
    with pytest.raises(ConsoleInputError) as excinfo:
        check_values(action["fields"], {"word": "", "times": 1})
    assert "Word: required" in str(excinfo.value)
    with pytest.raises(ConsoleInputError) as excinfo:
        check_values(action["fields"], {"word": "hi"})
    assert "Times: required" in str(excinfo.value)


def test_a_free_command_line_is_bounded_and_single_line() -> None:
    assert check_command_line("  HELP  ") == "HELP"
    assert check_command_line("x" * MAX_COMMAND_LINE) == "x" * MAX_COMMAND_LINE
    for line in ("", "   ", "a\nb", "a\x00b", "x" * (MAX_COMMAND_LINE + 1), None, 5):
        with pytest.raises(ConsoleInputError):
            check_command_line(line)


# --- provider answers -------------------------------------------------------------------


def test_plain_reduces_any_answer_to_bounded_json_types() -> None:
    assert output.plain({"raw": b"\x01\xab", "big": 2**60, "nan": float("nan"), "set": {1}, "tuple": (1, 2)}) == {
        "raw": "01AB",
        "big": str(2**60),
        "nan": None,
        "set": [1],
        "tuple": [1, 2],
    }
    assert output.plain(object()).startswith("<object object")
    deep: Any = "leaf"
    for _ in range(10):
        deep = [deep]
    flattened = output.plain(deep)
    for _ in range(output.MAX_DEPTH):
        flattened = flattened[0]
    assert isinstance(flattened, str)
    assert len(output.plain(list(range(1000)))) == output.MAX_ITEMS
    assert len(output.plain("x" * 10000)) == output.MAX_TEXT


def test_status_always_carries_running_and_last_error() -> None:
    assert output.status_payload({"running": 1, "last_error": 5}) == {"running": False, "last_error": ""}
    assert output.status_payload("nonsense") == {"running": False, "last_error": ""}
    assert output.status_payload({"running": True, "state": {"n": 1}})["state"] == {"n": 1}


def _compare_manifest() -> dict[str, Any]:
    manifest = _manifest()
    manifest["compare"] = {
        "title": "Card and platform",
        "hint": "Rows line up by item.",
        "sides": [{"id": "card", "label": "Card"}, {"id": "platform", "label": "Platform"}],
    }
    return manifest


def test_a_comparison_declares_its_sides() -> None:
    compare = validate_manifest(_compare_manifest())["compare"]
    assert compare == {
        "title": "Card and platform",
        "hint": "Rows line up by item.",
        "sides": [{"id": "card", "label": "Card"}, {"id": "platform", "label": "Platform"}],
    }
    assert validate_manifest(_manifest())["compare"] is None


@pytest.mark.parametrize(
    "sides, fragment",
    [
        ([{"id": "card", "label": "Card"}], "at least 2 sides"),
        ([{"id": f"s{index}", "label": "S"} for index in range(5)], "more than 4 entries"),
        ([{"id": "card", "label": "Card"}, {"id": "card", "label": "Again"}], "declared twice"),
        ([{"id": "Card", "label": "Card"}, {"id": "b", "label": "B"}], "must match"),
        ([{"id": "a", "label": "A", "colour": "red"}, {"id": "b", "label": "B"}], "unknown key(s) colour"),
        ([{"id": "a", "label": ""}, {"id": "b", "label": "B"}], "must not be empty"),
    ],
)
def test_comparison_sides_are_checked(sides: list[dict[str, Any]], fragment: str) -> None:
    manifest = _compare_manifest()
    manifest["compare"]["sides"] = sides
    _refused(manifest, fragment)


def test_a_comparison_takes_no_other_key() -> None:
    manifest = _compare_manifest()
    manifest["compare"]["html"] = "<b>"
    _refused(manifest, "unknown key(s) html")


def test_a_comparison_keeps_one_text_cell_per_declared_side() -> None:
    manifest = validate_manifest(_compare_manifest())
    raw = {
        "running": True,
        "compare": {
            "note": 7,
            "sections": [
                {
                    "title": "Profiles",
                    "rows": [
                        {"label": "8988201234567890123", "cells": {"card": {"state": "enabled"}, "platform": b"\x01\x02", "extra": "dropped"}, "verdict": "differs"},
                        {"label": "eIM", "cells": {"card": "eim.example.test"}, "verdict": "bogus"},
                        "not a row",
                    ],
                },
                "not a section",
            ],
        },
    }
    payload = output.status_payload(raw, manifest)
    rows = payload["compare"]["sections"][0]["rows"]
    assert payload["compare"]["note"] == "7" and len(payload["compare"]["sections"]) == 1
    assert rows[0]["cells"] == {"card": "{'state': 'enabled'}", "platform": "0102"}
    assert rows[0]["verdict"] == "differs"
    assert rows[1] == {"label": "eIM", "cells": {"card": "eim.example.test", "platform": ""}, "verdict": "info"}
    assert len(rows) == 2
    # A console that declares no comparison never passes one to the view.
    assert "compare" not in output.status_payload(raw, validate_manifest(_manifest()))
    assert "compare" not in output.status_payload(raw)


def test_a_comparison_is_capped() -> None:
    manifest = validate_manifest(_compare_manifest())
    many_rows = [{"label": index, "cells": {"card": "x" * (output.MAX_COMPARE_CELL + 9)}, "verdict": "same"} for index in range(output.MAX_COMPARE_ROWS + 3)]
    sections = [{"title": index, "rows": many_rows} for index in range(output.MAX_COMPARE_SECTIONS + 2)]
    compare = output.status_payload({"compare": {"sections": sections}}, manifest)["compare"]
    assert len(compare["sections"]) == output.MAX_COMPARE_SECTIONS
    assert len(compare["sections"][0]["rows"]) == output.MAX_COMPARE_ROWS
    assert len(compare["sections"][0]["rows"][0]["cells"]["card"]) == output.MAX_COMPARE_CELL
    assert output.status_payload({"compare": "junk"}, manifest)["compare"] == {"sections": [], "note": ""}


def test_a_stream_batch_keeps_the_declared_columns_and_the_newest_rows() -> None:
    stream = validate_manifest(_manifest())["streams"][0]
    entries = [{"at": float(index), "text": index, "secret": "dropped"} for index in range(output.MAX_STREAM_ENTRIES + 5)]
    batch = output.stream_batch(stream, {"entries": entries + ["not a dict"], "next": 42}, 0)
    assert batch["truncated"] is True and batch["next"] == 42
    assert len(batch["entries"]) == output.MAX_STREAM_ENTRIES
    assert batch["entries"][-1] == {"at": float(output.MAX_STREAM_ENTRIES + 4), "text": str(output.MAX_STREAM_ENTRIES + 4)}
    odd = output.stream_batch(stream, {"entries": [{"at": "noon", "text": None}]}, 7)
    assert odd == {"entries": [{"at": None, "text": ""}], "next": 7, "truncated": False}
    assert output.stream_batch(stream, None, 3) == {"entries": [], "next": 3, "truncated": False}


def test_help_and_command_answers_are_coerced_and_capped() -> None:
    help_answer = output.help_payload({"groups": [{"group": "g", "commands": [{"name": "ECHO", "aliases": ("SAY", 5)}, "junk"]}, "junk"], "text": 5})
    assert help_answer == {"groups": [{"group": "g", "commands": [{"name": "ECHO", "usage": "", "summary": "", "aliases": ["SAY", "5"]}]}], "text": ""}
    assert output.command_payload("PING", {"output": "pong"}) == {"line": "PING", "output": "pong", "truncated": False}
    assert output.command_payload("PING", "plain text")["output"] == "plain text"
    long_answer = output.command_payload("DUMP", "x" * (output.MAX_OUTPUT + 1))
    assert long_answer["truncated"] is True and len(long_answer["output"]) == output.MAX_OUTPUT


def _fill_manifest() -> dict[str, Any]:
    manifest = _manifest()
    manifest["start"]["fields"][4]["fill"] = {"label": "Read from card"}
    return manifest


def test_a_start_text_field_can_be_filled_by_the_console() -> None:
    fields = {field["name"]: field for field in validate_manifest(_fill_manifest())["start"]["fields"]}
    assert fields["tag"]["fill"] == {"label": "Read from card"}
    assert fields["count"]["fill"] is None


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda m: m["start"]["fields"][1].__setitem__("fill", {"label": "Guess"}), "only a text field can be filled"),
        (lambda m: m["start"]["fields"][4].__setitem__("fill", {"label": "Read", "href": "x"}), "unknown key(s) href"),
        (lambda m: m["start"]["fields"][4].__setitem__("fill", {"label": " "}), "must not be empty"),
        (lambda m: m["actions"][0]["fields"][0].__setitem__("fill", {"label": "Read"}), "unknown key(s) fill"),
    ],
)
def test_only_a_start_text_field_takes_a_fill(mutate: Any, fragment: str) -> None:
    manifest = _manifest()
    mutate(manifest)
    _refused(manifest, fragment)


def test_a_fill_answer_is_cut_to_the_field() -> None:
    field = validate_manifest(_fill_manifest())["start"]["fields"][4]
    assert output.fill_payload(field, {"value": "abcdefghijk", "note": 5}) == {"value": "abcdefgh", "note": "5"}
    assert output.fill_payload(field, "junk") == {"value": "", "note": ""}


# --- state tab and column widths -----------------------------------------------------


def test_a_state_title_gives_the_reported_state_a_tab_of_its_own() -> None:
    manifest = _manifest()
    manifest["state"] = {"title": "Environment"}
    assert validate_manifest(manifest)["state"] == {"title": "Environment"}
    manifest["state"] = {}
    assert validate_manifest(manifest)["state"] == {"title": "State"}


@pytest.mark.parametrize(
    "state, fragment",
    [
        ({"title": "Env", "href": "x"}, "unknown key(s) href"),
        ({"title": " "}, "must not be empty"),
        ("Environment", "must be an object"),
    ],
)
def test_a_state_declaration_is_checked(state: Any, fragment: str) -> None:
    manifest = _manifest()
    manifest["state"] = state
    _refused(manifest, fragment)


def test_stream_columns_declare_how_much_of_the_table_they_take() -> None:
    manifest = _manifest()
    manifest["streams"][0]["columns"] = [
        {"key": "at", "label": "Time", "format": "time"},
        {"key": "kind", "label": "Kind", "width": "narrow"},
        {"key": "label", "label": "Exchange", "width": "medium"},
        {"key": "command", "label": "Command", "format": "hex"},
    ]
    columns = validate_manifest(manifest)["streams"][0]["columns"]
    assert [column["width"] for column in columns] == ["narrow", "narrow", "medium", "fill"]


@pytest.mark.parametrize(
    "column, fragment",
    [
        ({"key": "at", "label": "Time", "format": "time", "width": "fill"}, "a time column has a fixed width"),
        ({"key": "text", "label": "Text", "width": "huge"}, "one of narrow, medium, fill"),
        ({"key": "text", "label": "Text", "width": 3}, "one of narrow, medium, fill"),
    ],
)
def test_a_column_width_is_one_of_the_known_ones(column: dict[str, Any], fragment: str) -> None:
    manifest = _manifest()
    manifest["streams"][0]["columns"] = [column]
    _refused(manifest, fragment)


# --- top bar pills -----------------------------------------------------------------------


def _pill_manifest() -> dict[str, Any]:
    manifest = _manifest()
    manifest["pills"] = [{"id": "network", "label": "Modem"}, {"id": "channel", "label": "BIP"}]
    return manifest


def test_a_console_declares_its_top_bar_pills() -> None:
    assert validate_manifest(_pill_manifest())["pills"] == [{"id": "network", "label": "Modem"}, {"id": "channel", "label": "BIP"}]


@pytest.mark.parametrize(
    "pills, fragment",
    [
        ([{"id": "a", "label": "A"}] * 2, "'a' is declared twice"),
        ([{"id": f"p{index}", "label": "P"} for index in range(4)], "more than 3 entries"),
        ([{"id": "a", "label": "x" * 21}], "longer than 20 characters"),
        ([{"id": "a", "label": "A", "href": "x"}], "unknown key(s) href"),
        ([{"id": "A b", "label": "A"}], "must match"),
        ({"id": "a"}, "must be a list"),
    ],
)
def test_pills_are_checked(pills: Any, fragment: str) -> None:
    manifest = _manifest()
    manifest["pills"] = pills
    _refused(manifest, fragment)


def test_a_pill_answer_keeps_declared_pills_with_a_value_as_one_line() -> None:
    manifest = validate_manifest(_pill_manifest())
    answer = {
        "channel": {"value": "1 open", "state": "ok"},
        "network": {"value": "001/01\nE-UTRAN   normal" + "x" * 60, "state": "shouting"},
        "undeclared": {"value": "dropped", "state": "ok"},
    }
    pills = output.pills_payload(manifest, answer)
    assert [pill["id"] for pill in pills] == ["network", "channel"]
    assert pills[0]["value"].startswith("001/01 E-UTRAN normal") and len(pills[0]["value"]) == output.MAX_PILL_VALUE
    assert pills[0]["state"] == "idle" and pills[1]["state"] == "ok"
    assert pills[1] == {"console": "demo", "title": "Demo console", "id": "channel", "label": "BIP", "value": "1 open", "state": "ok"}
    # A stopped console answers no value: its pills take no room.
    assert output.pills_payload(manifest, {"network": {"value": "  "}, "channel": None}) == []
    assert output.pills_payload(manifest, "junk") == []
