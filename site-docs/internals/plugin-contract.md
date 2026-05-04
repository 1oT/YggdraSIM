---
title: Plugin Contract
tags:
  - internals
  - plugins
---

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

Loaded plugins get unique synthetic module names on the form
`yggdrasim_plugin_<name>`. Load errors are captured per plugin and surfaced
back to the runtime, not raised globally. A broken plugin must not break the
rest of the process.

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

Consumers generally call `get_capability("polling")` and branch on whether
it returns a provider.

## Reserved capability names

| Capability | Consumers |
| --- | --- |
| `polling` | `SCP11/live` `POLL`, `SCP11/test` `POLL`, `SCP11/eim_local` `IPAE-LIVE` / `IPAE-TEST` |

New capabilities should be added to this list only after the consumer side
is ready to use them cleanly.

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
