# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Operator input to a plugin console, checked against the manifest that declared it.

Start-form and action values are checked field by field against the
validated manifest (``ConsoleInputError`` names the field that does not
fit); a value the operator left out takes the field's default. An action
renders its template into one command line, and every value it binds has to
stay one word that cannot read as an option, so a field never adds words or
switches to the line it fills. A free command line is checked for length and
control characters only: what it means is the plugin's own command language.
The name of a named credential's entry is one word (``ENTRY_NAME``); a
refusal never repeats it, in case a secret was typed into the name.
"""
from __future__ import annotations

import math
import re
from typing import Any

from .plugin_console_manifest import CONTROL, MAX_READER_NAME, PLACEHOLDER, WORD
from .plugin_console_runform import ENTRY_NAME

MAX_COMMAND_LINE = 8192


class ConsoleInputError(ValueError):
    """Operator input that does not fit the console's declared fields or line rules."""


def _number(field: dict[str, Any], value: Any) -> int | float | None:
    label = field["label"]
    if value is None or (isinstance(value, str) and len(value.strip()) == 0):
        if field["required"]:
            raise ConsoleInputError(f"{label}: required")
        return None
    if isinstance(value, bool):
        raise ConsoleInputError(f"{label}: not a number")
    number: int | float
    if isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError as error:
            raise ConsoleInputError(f"{label}: not a number") from error
    elif isinstance(value, (int, float)):
        number = value
    else:
        raise ConsoleInputError(f"{label}: not a number")
    if not math.isfinite(number):
        raise ConsoleInputError(f"{label}: not a finite number")
    if field["min"] is not None and number < field["min"]:
        raise ConsoleInputError(f"{label}: below {field['min']}")
    if field["max"] is not None and number > field["max"]:
        raise ConsoleInputError(f"{label}: above {field['max']}")
    if isinstance(number, float) and number.is_integer():
        return int(number)
    return number


def _text(field: dict[str, Any], value: Any) -> str:
    label = field["label"]
    if not isinstance(value, str):
        raise ConsoleInputError(f"{label}: must be text")
    text = value.strip()
    if CONTROL.search(text) is not None:
        raise ConsoleInputError(f"{label}: must not contain control characters")
    if len(text) > field["max_length"]:
        raise ConsoleInputError(f"{label}: longer than {field['max_length']} characters")
    if len(text) == 0:
        if field["required"]:
            raise ConsoleInputError(f"{label}: required")
        return ""
    if field["pattern"] and re.fullmatch(field["pattern"], text) is None:
        raise ConsoleInputError(f"{label}: does not match {field['pattern']}")
    return text


def check_value(field: dict[str, Any], value: Any) -> Any:
    """One operator value for a validated field, normalised (text stripped, integral numbers as int)."""
    kind = field["type"]
    if kind == "boolean":
        if not isinstance(value, bool):
            raise ConsoleInputError(f"{field['label']}: must be true or false")
        return value
    if kind == "number":
        return _number(field, value)
    if kind == "choice":
        allowed = [option["value"] for option in field["options"]]
        if not isinstance(value, str) or value not in allowed:
            raise ConsoleInputError(f"{field['label']}: one of " + ", ".join(repr(item) for item in allowed))
        return value
    if kind == "reader":
        return _text({**field, "max_length": MAX_READER_NAME, "pattern": ""}, value)
    return _text(field, value)


def check_values(fields: list[dict[str, Any]], values: Any) -> dict[str, Any]:
    """Every declared field's value, checked; a key no field declares is refused."""
    given = {} if values is None else values
    if not isinstance(given, dict):
        raise ConsoleInputError("values must be an object")
    declared = {field["name"] for field in fields}
    unknown = sorted(str(key) for key in given if key not in declared)
    if unknown:
        raise ConsoleInputError("no field named " + ", ".join(unknown))
    return {field["name"]: check_value(field, given.get(field["name"], field["default"])) for field in fields}


def check_entry_name(value: Any, label: str) -> str:
    """The stripped name of one entry of a named credential; ``label`` is the credential's."""
    text = "" if value is None else value
    if not isinstance(text, str):
        raise ConsoleInputError(f"{label}: the entry name must be text")
    text = text.strip()
    if len(text) == 0:
        raise ConsoleInputError(f"{label}: an entry name is required")
    if ENTRY_NAME.fullmatch(text) is None:
        raise ConsoleInputError(f"{label}: an entry name is 1 to 40 letters, digits, '.', '_' or '-', starting with a letter or a digit")
    return text


def check_command_line(line: Any) -> str:
    """A free command line: stripped, non-empty, bounded, without control characters."""
    if not isinstance(line, str):
        raise ConsoleInputError("the command line must be text")
    text = line.strip()
    if len(text) == 0:
        raise ConsoleInputError("the command line is empty")
    if len(text) > MAX_COMMAND_LINE:
        raise ConsoleInputError(f"the command line is longer than {MAX_COMMAND_LINE} characters")
    if CONTROL.search(text) is not None:
        raise ConsoleInputError("the command line must not contain control characters")
    return text


def _word(field: dict[str, Any], value: Any) -> str:
    if field["type"] == "number":
        if value is None:
            raise ConsoleInputError(f"{field['label']}: required")
        return str(value)
    text = str(value)
    if WORD.fullmatch(text) is None:
        raise ConsoleInputError(f"{field['label']}: one word that does not start with '-'")
    return text


def render_action_line(action: dict[str, Any], values: dict[str, Any]) -> str:
    """The command line an action sends: its template with each checked value as one word."""
    words = {field["name"]: _word(field, values.get(field["name"])) for field in action["fields"]}
    return check_command_line(PLACEHOLDER.sub(lambda match: words[match.group(1)], action["template"]))
