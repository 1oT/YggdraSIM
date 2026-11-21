# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""A neutral run form and the selection table its tests share.

Two variants, items that name the fields they use, a group shown before the
items and one after, a stored credential and an item selected by a field
value; ``named_demo_runs`` adds a named credential. ``SELECTION_CASES``
holds the server's ``plan_run`` and the view's ``pcRunPlan`` to the same
answers.
"""
from __future__ import annotations

from typing import Any


def _choice(name: str, label: str, values: tuple[str, ...], **extra: Any) -> dict[str, Any]:
    return {"name": name, "label": label, "type": "choice", "options": [{"value": value, "label": value.title()} for value in values], **extra}


def demo_runs() -> dict[str, Any]:
    return {
        "labels": {"items": "Checks", "credentials": "Keys"},
        "fields": [
            {"name": "operator", "label": "Operator", "type": "text", "required": True},
            {"name": "note", "label": "Note", "type": "text"},
        ],
        "groups": [
            {"id": "keys", "label": "Key set", "place": "before_items"},
            {"id": "link", "label": "Link", "place": "after_items"},
        ],
        "credentials": [
            {
                "id": "service",
                "label": "Service key",
                "fields": [
                    {"name": "url", "label": "Base URL", "type": "text", "default": "https://api.example.test"},
                    {"name": "token", "label": "Token", "type": "text", "secret": True, "required": True},
                ],
            }
        ],
        "variants": [
            {
                "id": "basic",
                "label": "Basic",
                "credentials": ["service"],
                "fields": [
                    {"name": "reader", "label": "Reader", "type": "reader", "required": True},
                    _choice("source", "Source", ("card", "fetch")),
                    {"name": "code", "label": "Code", "type": "text", "required": True, "visible_when": {"field": "source", "equals": "fetch"}},
                    {"name": "count", "label": "Count", "type": "number", "min": 1, "max": 9, "default": 2, "required": True},
                    {"name": "verbose", "label": "Verbose", "type": "boolean"},
                    {"name": "use_key", "label": "Use a key", "type": "boolean", "group": "keys"},
                    {"name": "key", "label": "Key", "type": "text", "secret": True, "required": True, "group": "keys", "visible_when": {"field": "use_key", "equals": True}},
                    _choice("mode", "Link mode", ("local", "remote"), group="link"),
                    {"name": "host", "label": "Host", "type": "text", "required": True, "group": "link", "visible_when": {"field": "mode", "equals": "remote"}},
                    _choice("identity", "Identity", ("agent", "file"), group="link", visible_when={"field": "mode", "equals": "remote"}),
                    {"name": "identity_file", "label": "Identity file", "type": "text", "required": True, "group": "link", "visible_when": {"field": "identity", "equals": "file"}},
                ],
                "items": [
                    {"id": "prepare", "label": "Prepare", "summary": "Runs first when the source is fetched.", "auto_when": {"field": "source", "equals": "fetch"}},
                    {"id": "ping", "label": "Ping", "badge": "card", "fields": ["count", "verbose"]},
                    {"id": "sign", "label": "Sign", "fields": ["use_key", "key"], "credentials": ["service"]},
                    {"id": "link", "label": "Link", "fields": ["use_key", "key", "mode", "host", "identity", "identity_file"]},
                    {"id": "later", "label": "Later", "available": False, "unavailable_reason": "not built yet"},
                ],
            },
            {"id": "other", "label": "Other", "fields": [], "items": [{"id": "only", "label": "Only"}]},
        ],
    }


def named_demo_runs() -> dict[str, Any]:
    """The demo form plus a named credential, which only the second variant's item needs."""
    runs = demo_runs()
    runs["credentials"].append(
        {
            "id": "vault",
            "label": "Vault token",
            "named": True,
            "fields": [
                {"name": "url", "label": "Vault URL", "type": "text", "default": "https://vault.example.test"},
                {"name": "token", "label": "Token", "type": "text", "secret": True, "required": True},
            ],
        }
    )
    runs["variants"][1]["credentials"] = ["vault"]
    runs["variants"][1]["items"][0]["credentials"] = ["vault"]
    return runs


def pick_demo_runs() -> dict[str, Any]:
    """The demo form plus, on the second variant, an item whose field the console fills from its status."""
    runs = demo_runs()
    other = runs["variants"][1]
    other["fields"] = [{"name": "target", "label": "Target", "type": "choice", "options_from": "targets", "required": True}]
    other["items"].append({"id": "aim", "label": "Aim", "fields": ["target"]})
    return runs


PICK_CHOICES: dict[str, list[dict[str, str]]] = {"targets": [{"value": "t1", "label": "One"}, {"value": "t2", "label": "Two"}]}
# (ticked items, operator values, the console's current lists) -> the selection on the
# second variant of ``pick_demo_runs``; the view's mirror is held to the same table.
PICK_CASES: list[tuple[str, list[str], dict[str, Any], dict[str, Any], dict[str, Any]]] = [
    (
        "a listed pick is sent",
        ["aim"],
        {"operator": "Ann", "note": "n", "target": "t2"},
        PICK_CHOICES,
        {"items": ["aim"], "visible": ["operator", "note", "target"], "values": {"operator": "Ann", "note": "n", "target": "t2"}, "missing": []},
    ),
    (
        "a blank pick is missing",
        ["aim"],
        {"operator": "Ann", "note": "n", "target": ""},
        PICK_CHOICES,
        {"items": ["aim"], "visible": ["operator", "note", "target"], "values": {"operator": "Ann", "note": "n"}, "missing": ["target"]},
    ),
    (
        "a pick off the current list is not sent",
        ["aim"],
        {"operator": "Ann", "note": "n", "target": "t9"},
        PICK_CHOICES,
        {"items": ["aim"], "visible": ["operator", "note", "target"], "values": {"operator": "Ann", "note": "n"}, "missing": []},
    ),
    (
        "no list yet",
        ["aim"],
        {"operator": "Ann", "note": "n", "target": "t1"},
        {},
        {"items": ["aim"], "visible": ["operator", "note", "target"], "values": {"operator": "Ann", "note": "n"}, "missing": []},
    ),
    (
        "the pick stays out of use while its item is not ticked",
        ["only"],
        {"operator": "Ann", "note": "n", "target": "t1"},
        PICK_CHOICES,
        {"items": ["only"], "visible": ["operator", "note"], "values": {"operator": "Ann", "note": "n"}, "missing": []},
    ),
]


def demo_manifest(runs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"id": "runner", "title": "Runner", "runs": demo_runs() if runs is None else runs}


# (ticked items, operator values) -> what the plugin receives. The view's
# mirror is held to the same table.
SELECTION_CASES: list[tuple[str, list[str], dict[str, Any], dict[str, Any]]] = [
    (
        "one item with defaults",
        ["ping"],
        {"operator": "Ann", "reader": "Reader 1"},
        {"items": ["ping"], "auto_items": [], "visible": ["operator", "note", "reader", "source", "count", "verbose"], "missing": [], "credentials": []},
    ),
    (
        "a field value selects the automatic item and reveals its field",
        ["ping"],
        {"operator": "Ann", "reader": "Reader 1", "source": "fetch", "code": "X1"},
        {"items": ["ping"], "auto_items": ["prepare"], "visible": ["operator", "note", "reader", "source", "code", "count", "verbose"], "missing": [], "credentials": []},
    ),
    (
        "a shared group counts once and a credential follows its item",
        ["sign", "link"],
        {"operator": "Ann", "reader": "R", "use_key": True, "key": "K", "mode": "remote", "host": "h.example.test", "identity": "file"},
        {
            "items": ["sign", "link"],
            "auto_items": [],
            "visible": ["operator", "note", "reader", "source", "use_key", "key", "mode", "host", "identity", "identity_file"],
            "missing": ["identity_file"],
            "credentials": ["service"],
        },
    ),
    (
        "a hidden controller hides its whole chain",
        ["link"],
        {"operator": "Ann", "reader": "R", "mode": "local", "identity": "file", "identity_file": "/tmp/id", "host": "h"},
        {"items": ["link"], "auto_items": [], "visible": ["operator", "note", "reader", "source", "use_key", "mode"], "missing": [], "credentials": []},
    ),
    (
        "blank required values are reported, not sent",
        ["ping"],
        {"operator": "  ", "reader": "", "count": None},
        {"items": ["ping"], "auto_items": [], "visible": ["operator", "note", "reader", "source", "count", "verbose"], "missing": ["operator", "reader", "count"], "credentials": []},
    ),
]
