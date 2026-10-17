---
title: Plugin Contract
tags:
  - internals
  - plugins
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Plugin Contract

Plugins extend YggdraSIM with optional capabilities that the core must stay
runnable without. This page documents the exact contract the plugin runtime
expects, the reserved capability names, and the behavior when a capability is
absent.

## Discovery

The plugin runtime in `yggdrasim_common/plugin_runtime.py` scans the
`plugins/` directory under the active runtime root. It loads:

- single-file plugins `plugins/<name>.py` (underscore-prefixed names are
  skipped)
- package-style plugins `plugins/<name>/` with an `__init__.py` (skipped if
  that file is missing)

Directory plugins load canonically as `plugins.<name>` so package-relative
imports work in source and drop-in runtime installs. The legacy
`yggdrasim_plugin_<name>` name remains an alias to the same module object.
Single-file plugins retain the legacy synthetic name. Load errors are captured
per plugin and surfaced back to the runtime, not raised globally. A broken
plugin must not break the rest of the process.

## Registration contract

Each plugin module must expose a callable:

```python
def register_plugins(manager):
    manager.register_capability("<capability-name>", <provider>)
```

The `manager` argument is the `PluginManager` instance. Capability names are
lowercased and stripped. Empty names are rejected.

## Capability manager

The manager exposes:

| Method | Purpose |
| --- | --- |
| `register_capability(name, provider)` | register a capability |
| `get_capability(name)` | retrieve a capability (loads plugins lazily) |
| `ensure_loaded()` | force-load plugins (idempotent) |
| `load_errors()` | surface any per-plugin load errors |

Consumers call `get_capability("<capability-name>")` and branch on whether
it returns a provider.

A provider whose `extend_target` raises is recorded under
`<capability-name>:extend` in `load_errors()`, and the providers after it
still extend the target. An `ActionSpec` or `ActionField` built with a
non-`str` text field is refused with a `TypeError` naming the spec at
construction (the usual cause is a trailing comma inside a parenthesised run
of string literals, which makes the field a tuple), so a malformed action
becomes that plugin's load error while `GET /api/actions` keeps serving
every other action.

## Reserved capability names

Reserved names are private extension contracts. Public distributions should
document only the generic loader behavior and keep undistributed capability
names out of shipped docs.

### `mcp_extensions`

The one capability whose name is published, because the consumer that reads
it ships too. It lets a private plugin add tools, resources, and prompts to
the MCP server without any operator specifics entering this tree.

A provider exposes `register(mcp)` and may expose the usual `health()`:

```python
class OperatorMcpExtensions:
    def health(self) -> dict:
        return {"actions_available": True, "dependency_issues": []}

    def register(self, mcp) -> None:
        @mcp.prompt()
        def house_profile_review(file_path: str = "") -> str:
            return f"Review {file_path} against the house profile rules ..."

        @mcp.tool()
        def operator_plmn_lookup(mccmnc: str) -> str:
            ...


def register_plugins(manager) -> None:
    manager.register_capability("mcp_extensions", OperatorMcpExtensions())
```

`Tools/YggdraMCP/server.py::load_plugin_extensions` calls it at startup and
reports rather than raises at every step: a provider that is absent,
declares itself unavailable, raises from `health()`, lacks `register`, or
raises from `register` is logged and skipped, and the server still serves
its built-in surface.

A plugin tool that drives a card must call `card_access_allowed()` from the
server module and refuse when it returns `False`. The loader cannot enforce
that on a plugin's behalf, and a plugin that ignores it silently widens the
gate the built-in card tools sit behind.

## Plugin consoles

A plugin can give the GUI a console without shipping browser code. The core
owns one generic view and one route family (`/api/plugin-consoles`); the
plugin hands over a manifest that declares what the view may render and an
object that answers the calls. The console is listed in the left rail's
*Plugin consoles* group when the GUI starts with plugin loading allowed;
the group is not shown while no console is registered. A console is the GUI half of a capability; the same
command language still needs its CLI verb.

The provider's `extend_target` receives a `PluginConsoleRegistry` and calls
`add_console(console)`:

```python
class CounterConsole:
    def manifest(self) -> dict:
        return {
            "id": "counter",
            "title": "Counter",
            "start": {"fields": [{"name": "step", "label": "Step", "type": "number", "min": 1, "default": 1}]},
            "actions": [
                {"id": "add", "label": "Add", "template": "ADD {amount}",
                 "fields": [{"name": "amount", "label": "Amount", "type": "number"}]},
            ],
            "command_line": {"placeholder": "HELP"},
            "streams": [
                {"id": "log", "title": "Log",
                 "columns": [{"key": "at", "label": "Time", "format": "time"},
                             {"key": "text", "label": "Message"}]},
            ],
        }

    def status(self) -> dict: ...
    def start(self, values: dict) -> dict: ...
    def stop(self) -> dict: ...
    def command(self, line: str) -> dict: ...
    def stream(self, stream_id: str, after: int) -> dict: ...
    def help(self) -> dict: ...


class CounterCapability:
    def __init__(self) -> None:
        self._console = CounterConsole()

    def extend_target(self, target) -> None:
        if type(target).__name__ == "PluginConsoleRegistry":
            target.add_console(self._console)
```

The registry is filled once per process, on the first request after the
plugin gate has latched. `add_console` validates the manifest
(`yggdrasim_common/gui_server/plugin_console_manifest.py`) and checks the
methods it depends on; a console that does not fit is listed as refused with
the reason, which the GUI log shows, and never reaches the view. The registry
lists at most 16 consoles and keeps at most 32 refusals.

### Manifest

| Key | Shape |
| --- | --- |
| `id` | `[a-z][a-z0-9_-]{0,31}`; the URL segment and the nav leaf |
| `title`, `summary` | one line each, at most 60 and 240 characters |
| `start` | optional `{label, fields}`; the operator starts and stops such a console, and its actions and command line are enabled only while it runs; a text field may carry `fill: {label}`, a button beside it that asks the console for the field's value |
| `actions` | up to 48 `{id, label, template, fields, group, hint, place}`; `group` sorts the buttons under headings; `place` is `actions` (the default: a card on the Actions tab) or `compare` (a button in the comparison panel's toolbar, which needs `compare` declared) |
| `command_line` | optional `{placeholder, hint}`; its presence enables the free command line |
| `streams` | up to 4 `{id, title, columns}`; a column is `{key, label, format, width}` with format `text`, `time` (epoch seconds), `hex` or `mono` (text in the mono font with its spacing kept: a captured terminal) and width `narrow`, `medium` or `fill` (the default; a time column is always narrow and takes no width) |
| `compare` | optional comparison panel `{title, hint, sides}`: 2 to 4 sides `{id, label}`, filled by the status answer (see *Comparison panel* below) |
| `state` | optional `{title}`: the state the status reports gets a tab of its own under that title (default `State`); without it the state is listed under the start form |
| `pills` | up to 3 `{id, label}` top bar pills, a label of at most 20 characters; `pills()` answers them (see *Top bar pills* below) |
| `runs` | optional run form: variants of selectable items, their fields and the stored credentials they need (see *Run forms* below) |

A field is `{name, label, type, default, required, placeholder, hint}` with
type `text` (plus `pattern`, `max_length`), `number` (`min`, `max`,
`step`), `boolean`, `choice` (`options`, each `{value, label}`) or `reader`
(a PC/SC or remote reader name the view offers from the live reader list;
empty leaves the pick to the plugin). Any other key, at any level, refuses
the whole manifest.

An action's `template` names each of its fields once, as `{name}`; the
fields are always required and are `text`, `number` or `choice`. The server
renders the line and refuses a value that is not one word or that starts
with `-`, so a field never adds words or options to the line. The console
receives the rendered line through `command(line)` exactly as a typed one,
and the transcript shows it, so a button teaches the command it stands for.

### Methods

| Method | Needed when | Returns |
| --- | --- | --- |
| `manifest()` | always | the manifest above |
| `status()` | always | `{running, busy, last_error, state}`, plus `compare` when the manifest declares one; `busy` is a phase label shown while it lasts, `state` a plain object the view lists as key / value rows |
| `start(values)`, `stop()` | `start` is declared | the status after the change; `values` holds every start field, checked |
| `fill(field, values)` | a start field declares `fill` | `{value, note}`: the field's value, cut to its length, worked out from the other start values (checked, none required yet; the field's own half-typed value is left out) |
| `command(line)` | actions or a command line are declared | `{output}` |
| `stream(stream_id, after)` | streams are declared | `{entries, next}`: the entries after cursor `after` and the cursor to ask from next |
| `pills()` | pills are declared | `{<pill id>: {value, state}}`: a pill left out or with an empty value is not shown; `state` is `ok`, `warn`, `error`, `busy` or `idle` |
| `help()` | optional | `{groups: [{group, commands: [{name, usage, summary, aliases}]}], text}` |

A `ValueError` from a call answers 422, a `RuntimeError` 409 and anything
else 500. The polls never fail: `status` reports a provider error as
`last_error`, a stream as its `error`. Every answer is copied into bounded
plain JSON (`plugin_console_output.py`) before it is sent, and the view
renders it as text only.

The routes are `GET /api/plugin-consoles` (the consoles and the refusals),
`GET /api/plugin-consoles/pills` (every console's pills that carry a value),
`GET .../{id}/status`, `POST .../{id}/start`, `POST .../{id}/stop`,
`POST .../{id}/fill` (`{field, values}`),
`POST .../{id}/command` (`{line}` or `{action, values}`),
`GET .../{id}/stream?cursor=<stream>:<n>` (the status and every stream in
one answer) and `GET .../{id}/help`. They sit behind the GUI's bearer token
like every `/api/*` route.

### Layout

The view is two panes, each with a tab per part the manifest declares:
controls (Session, the state tab, Actions, or Command line when the console
declares no actions, the run form and the credentials) and output (the
comparison, one tab per stream, the runs). A pane with one part shows no
tab strip, and a pane with none leaves the other the whole width. The panes
fill the window and scroll on their own, so no part sits below another
pane's content; below 960 px they stack and the page scrolls. The tab
picked per console and pane is kept in the viewer's browser storage. An
action's answer shows under its own card (its first four lines) as well as
in the transcript.

A stream table has fixed column widths from the manifest, so a new row never
re-measures the ones before it: a fill column takes what the narrow and
medium ones leave, and below each column's minimum the table scrolls
sideways. Time, hex and narrow text stay on one line and are cut at the
column edge, with the whole value as a tooltip; a click opens that row, and
the table's Wrap shows every value in full. A table keeps its newest 1000
rows and follows new rows while it is scrolled to the bottom, also across a
tab switch.

### Top bar pills

A console that reports something worth seeing from any view (a session's
network, an open channel) declares `pills` and answers `pills()`:

```python
{"network": {"value": "001/01 E-UTRAN normal", "state": "ok"},
 "channel": {"value": "1 open", "state": "ok"}}
```

The top bar polls `GET /api/plugin-consoles/pills` every 5 seconds while the
page is visible and shows each pill with a value beside the bridge pills: the
label, the value (one line, cut at 48 characters) and a dot in the tone of
`state` (`ok` green, `warn` and `busy` in the warn and accent colours,
`error` red). A click opens the console. Nothing is shown for a console that
answers no value, so a stopped session takes no room. On a narrow window the
values fold away first (below 1760 px, the title keeps the whole text), then
a console's further pills (below 1400 px). A console whose `pills()` raises
drops out of that answer; the others stay.

### Comparison panel

A console that shows two or more views of the same thing side by side (a
card read from the reader beside a platform's record of it) declares
`compare` with its sides and returns the panel with every `status()`
answer:

```python
{"compare": {"note": "...", "sections": [{"title": "Profiles", "rows": [
    {"label": "8988201234567890123", "cells": {"card": "enabled", "platform": "disabled"}, "verdict": "differs"},
]}]}}
```

The plugin decides each row's verdict: `same`, `differs`, `missing`
(present on one side only) or `info` (a row that is not compared); anything
else reads `info`. `plugin_console_output.compare_payload` keeps one text
cell per declared side (a cell for any other side is dropped, a missing one
reads empty), at most 24 sections of 256 rows and 2048 characters per cell,
on every path that answers a status (status, start, stop and the stream
poll); a console that declares no comparison never passes one on. The view
renders one table per section in the output pane's comparison tab, with the
item, one column per side and the verdict (differs in the warn colour, one
side only in the fail colour), and redraws only when the answer changed.
Each section folds on its heading, which also counts its rows and what
differs; a redraw keeps the sections as they are, and the folded ones are
remembered per console in the browser. An action with `place: compare`
renders as a button in the toolbar above the tables, its fields beside it,
and answers in the box under the toolbar (the first lines, prefixed with the
action's label); the transcript on the Actions tab keeps the whole answer.

### Run forms

A console that starts runs (a test suite, a batch job) declares `runs`
instead of, or beside, a session. The view renders a variant select, the
fields every run uses, one card per item (ticking it opens the item's own
fields inline) and the field groups the ticked items use, placed before or
after the items; the output pane's runs tab follows the current run and
lists the earlier ones, and the credentials have a tab of their own.
`plugin_console_runform.py` validates the section:

| Key | Shape |
| --- | --- |
| `labels` | optional titles `form`, `variant`, `items`, `credentials`, `start`, `cancel`, `current`, `history`, `empty_history`; each defaults to generic wording |
| `fields` | up to 8 fields every run uses, rendered first (an operator signature, a title) |
| `groups` | up to 16 `{id, label, place}`; `place` is `before_items` (beside the credentials) or `after_items` |
| `credentials` | up to 8 `{id, label, hint, named, fields, labels}`: secrets the plugin stores once (an API key and its base URL, or a client certificate's settings and key passphrase), up to 8 text fields, at least one `secret`; `named` keeps several entries (below); `labels` may rename the `store`, `forget` and `replace` buttons (at most 24 characters each: a sign-in whose secret is used once and never kept reads Sign in / Sign out) |
| `variants` | 1 to 8 `{id, label, summary, available, unavailable_reason, credentials, fields, items}`; `credentials` names the ones the variant's items may need, each shown in the form as a status line with a button to the credentials tab |
| `accepts_while_running` | optional flag: a start while a run is in progress is accepted, and the console adds it to that run (its answer names the run in progress, which the view keeps following); without it the view refuses a start until the run is done |

A run field is a form field plus `group` (a declared group id), `secret`
(a text field typed into a password box, with no default),
`visible_when: {field, equals}`, which hides the field until an earlier field
holds that value (`equals` has the controlling field's type), and, for a
choice, `options_from`: the name of a list the console's status answer
carries under `choices`, which fills the field's options instead of the
manifest, so the operator picks a profile or an eIM by name and the plugin
receives the value behind it. Such a field declares no options and no
default, cannot control another field, shows a blank first option until the
operator picks, and a start is checked against the list current at that
moment; `plugin_console_output.choices_payload` keeps at most 64
`{value, label}` per declared source (values of at most 64 characters,
labels of 60, an empty or repeated value dropped) and drops any source no
field declares. An item is
`{id, label, summary, badge, available, unavailable_reason, fields,
credentials, auto_when}`: `fields` names the variant fields it uses and
`credentials` the stored secrets it needs. A field no item names is always in
use. A field several items name must carry a group, and a controlling field
must be in use whenever the field it controls is. `auto_when: {field,
equals}` selects the item from an always-used field instead of a tick.

The server repeats the view's selection (`plugin_console_selection.py`,
mirrored by `pcRunPlan` in the view and held to one table by the tests): a
field is visible when it is in use and its controller is visible and holds
the wanted value. Only visible fields are checked and passed on, so a hidden
or unused value never reaches the plugin; a visible required field that is
blank refuses the start, and so does a needed credential that is not usable.

A `named` credential keeps several entries on the plugin's side, each under
a name the operator gives it: one word of 1 to 40 letters, digits, `.`, `_`
or `-`, starting with a letter or a digit (`ENTRY_NAME` in
`plugin_console_runform.py`), unique within the credential. Its panel in the
credentials tab lists the entries (Replace, Forget) and Add opens a Name
field beside the credential's own fields; the form's status line for it
carries "Use for this run", which picks the entry a run uses. The view
preselects the only usable entry, and Run stores a typed entry first and
uses it. The pick is not a form field and stays out of the
selection: the request carries it as `credential_entries`, and a start is
refused while a needed named credential has no pick naming a usable entry.
A refusal never repeats a name back, in case a secret was typed into it.

| Method | Returns |
| --- | --- |
| `status()` | also `active_run`: the id of the run in progress, which the view attaches to, or empty; and `choices`: `{<source>: [{value, label}]}` for the fields declared with `options_from` |
| `run_start(request)` | the new run's history row; `request` is `{variant, items, auto_items, values, credentials}`, plus `credential_entries` (`{credential id: entry name}`) when a needed credential is named |
| `runs(limit)` | history rows, newest first: `{id, status, title, summary, time}` |
| `run(run_id)` | `{id, status, title, meta, error, results}`; a result is `{label, status, note, checks: [{ok, text}], details: [{summary, text}]}` |
| `run_events(run_id, after)` | `{entries: [{time, level, text}], next, finished}`; `level` is `info`, `ok`, `warn` or `error` |
| `run_cancel(run_id)` | `{cancel_requested}` |
| `credentials()` | `{<id>: {stored, usable, summary, values}}`; `values` may carry the non-secret fields; a named credential answers `{summary, entries: [{name, usable, summary, values}]}` |
| `credential_store(id, values)`, `credential_forget(id)` | that credential's entry; for a named credential they take the entry name as one more argument (`credential_store(id, values, name)`, `credential_forget(id, name)`) and answer the whole credential |

The credential trio is needed only when the form declares credentials. Run
states are `queued`, `running`, `passed`, `failed`, `error` and
`cancelled`, result states `pending`, `running`, `passed`, `failed`, `error`
and `skipped`; anything else reads `unknown`. The answers are cut to these
shapes in `plugin_console_runs_output.py`: a credential answer keeps
`stored`, `usable`, the summary and the declared non-secret values (a named
one at most 32 entries, each well-formed name once in any case, with the
same keys), so a stored secret cannot reach the page even when a provider
returns it. A `KeyError` from a run call answers 404.

The routes are `POST .../{id}/runs` (`{variant, items, values}`),
`GET .../{id}/runs?limit=`, `GET .../{id}/runs/{run_id}`,
`GET .../{id}/runs/{run_id}/events?after=`,
`POST .../{id}/runs/{run_id}/cancel`, `GET .../{id}/credentials` and
`POST` / `DELETE .../{id}/credentials/{credential_id}` (`{values}`; a named
credential's entry is `{name, values}` and `?name=`, and a plain credential
refuses a name). A run start may carry `credential_entries`.

## APDU trace renderer

`SCP11.transport.set_apdu_trace_renderer(renderer)` hands every raw-mode
exchange of the SCP11 transport (a command run with `--debug`, or the global
debug flag) to `renderer(label, command, response, sw1, sw2)` in place of the
built-in `[label] > HEX` and `[label] < SW: ... Data: ...` lines, and returns
the renderer it replaced. There is one slot for the whole process, so a
provider installs its renderer from `extend_target` and every SCP11 shell's
channel prints through it; concise-mode lines do not change. A renderer that
raises leaves that exchange to the built-in lines, and while a renderer is
installed `send_chunked` drops its per-block line, because the label the
renderer receives already names the block. With no renderer installed the
transport prints as it always has.

`SCP11.transport.set_apdu_trace_note_renderer(renderer)` is the second slot,
for the lines a flow prints between those exchanges while the global debug
flag is on: the connect phase's heading (`Phase: Connect`) and the lines on
the logical channel ES10b settled on (`ES10b logical channel active: CH1.`).
A flow prints such a line with `print_apdu_trace_note(text, heading=...)`;
`renderer(text)` receives the text in place of the built-in `[*] text` line,
and the setter returns the renderer it replaced. A heading's blank line
belongs to the built-in form only. With the debug flag off nothing reaches
the renderer, and a renderer that raises leaves the line to the built-in
form.

## Absent-plugin behavior

The contract says:

- The core must remain runnable without any plugin installed.
- A consumer that depends on a capability must either hide the verb that
  depends on it, or emit a clean runtime error that explicitly states the
  capability is optional.
- A broken plugin's error is captured and reported; it does not prevent
  other plugins from loading or the rest of the shell from running.

## Runtime root note

Plugins live under the active runtime root, not the source tree. In source
runs that is the repository `plugins/` tree. In frozen builds that is the
writable runtime root's `plugins/` directory. See
[Runtime Root](../reference/runtime-root.md).

## Publication policy

`plugins/README.md` documents the publication-ignore stance: the loader
contract ships in the published core, but plugin implementation files are
intentionally ignored by default. Keep private plugins under the runtime
root only.

## Related pages

- [Write a Plugin](../how-to/write-a-plugin.md)
- [Runtime Root](../reference/runtime-root.md)
- [State Schema](../reference/state-schema.md)
