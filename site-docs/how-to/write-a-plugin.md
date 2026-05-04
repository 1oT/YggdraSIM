---
title: Write a Plugin
tags:
  - how-to
  - plugins
---

# Write a Plugin

## Goal

Author a runtime plugin that registers a capability against the shared
plugin runtime, so the relay and eIM-local shells pick it up at launch.

## Prerequisites

- a working YggdraSIM editable install
- a target capability. The currently reserved capability name is `polling`.

## File layout

Two forms are supported:

- a single `.py` file under `plugins/`
- a package directory under `plugins/` with `__init__.py`

The loader in `yggdrasim_common/plugin_runtime.py` scans the active runtime
root. On source runs that is the repository `plugins/`. On frozen builds
that is the writable runtime root's `plugins/`.

## Minimal contract

Every plugin module or package must expose:

```python
def register_plugins(manager):
    manager.register_capability("polling", MyPollingCapability())
```

`manager` is the plugin runtime's capability manager. `register_capability`
takes the reserved capability name and an instance that implements the
capability's expected interface.

## Walkthrough

1. Create the file.

    ```bash
    touch plugins/my_polling.py
    ```

2. Implement the capability.

    ```python
    class MyPollingCapability:
        def __init__(self):
            pass

        def poll(self, context, attempts, window, **kwargs):
            # context carries the active shell, session, and logger.
            # Return a structured result the shell surfaces as POLL output.
            return {
                "status": "ok",
                "attempts": attempts,
                "matched": [],
            }


    def register_plugins(manager):
        manager.register_capability("polling", MyPollingCapability())
    ```

3. Launch a consumer shell.

    ```bash
    python -m SCP11.live --cmd "POLL 3 60s; EXIT"
    ```

    The shell picks up the plugin, routes `POLL` to it, and surfaces the
    returned structure.

## Where plugins are consumed

| Shell | Verb | Capability |
| --- | --- | --- |
| `SCP11/live` | `POLL`, `EIM-POLL` | `polling` |
| `SCP11/test` | `POLL`, `EIM-POLL` | `polling` |
| `SCP11/eim_local` | `IPAE-LIVE`, `IPAE-TEST` | `polling` |

## Absent-plugin behavior

The core must stay runnable when a plugin is absent. The current contract
says the shell will either hide the verb entirely, or emit a clean runtime
error that explains the capability is optional. Build the capability so
failure is visible but does not take the shell down.

## Publishing and ignoring

`plugins/README.md` documents the publication-ignore stance. Plugin
implementation files are intentionally ignored by default; only the loader
contract ships in the published core. Drop your plugin into a local
`plugins/` tree (source) or the writable runtime root (frozen) and keep it
out of the main tree.

## Related pages

- [Plugin Contract](../internals/plugin-contract.md)
- [State Schema](../reference/state-schema.md)
- [Runtime Root](../reference/runtime-root.md)
