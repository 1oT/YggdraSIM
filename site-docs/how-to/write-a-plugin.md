---
title: Write a Plugin
tags:
  - how-to
  - plugins
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Write a Plugin

## Goal

Author a runtime plugin that registers a capability against the shared
plugin runtime, so the relay and eIM-local shells pick it up at launch.

## Prerequisites

- a working YggdraSIM editable install
- a target capability name agreed with the local consumer.

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
    manager.register_capability("example.diagnostics", MyDiagnosticsCapability())
```

`manager` is the plugin runtime's capability manager. `register_capability`
takes the reserved capability name and an instance that implements the
capability's expected interface.

## Walkthrough

1. Create the file.

    ```bash
    touch plugins/my_diagnostics.py
    ```

2. Implement the capability.

    ```python
    class MyDiagnosticsCapability:
        def __init__(self):
            pass

        def run(self, context, **kwargs):
            # context carries the active shell, session, and logger.
            # Return a structured result the shell can surface.
            return {
                "status": "ok",
                "details": [],
            }


    def register_plugins(manager):
        manager.register_capability("example.diagnostics", MyDiagnosticsCapability())
    ```

3. Launch a consumer shell.

    ```bash
    YGGDRASIM_ALLOW_PLUGINS=1 python main/main.py
    ```

    A consumer that knows `example.diagnostics` can retrieve it through the
    shared plugin manager and surface the returned structure.

## Where plugins are consumed

Consumer bindings are private to the extension and the shell that owns them.
For public distributions, document the loader contract and keep local
capability names in private deployment notes.

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
