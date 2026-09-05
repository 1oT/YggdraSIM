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
