<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# YggdraSIM Plugins

`plugins/` is the optional runtime extension folder scanned by
`yggdrasim_common/plugin_runtime.py`.

The plugin model exists so the core repository can stay shippable without
embedding every optional, restricted, or deployment-specific capability in the
tracked source tree.

## Runtime-root behavior

Plugin discovery follows the active runtime root:

- source checkout: repository-local `plugins/`
- frozen executable: writable runtime-root `plugins/`

That means the same capability can be developed in-tree during source work and
then dropped into the writable runtime tree for packaged builds.

## Load posture (default-deny)

The plugin manager loads every `.py` file (or package directory) it finds under
the active runtime root's `plugins/` only after an explicit opt-in:

1. `YGGDRASIM_ALLOW_PLUGINS=1` — explicit opt-in. Imports plugin code
   from the active runtime root.
2. `YGGDRASIM_DISALLOW_PLUGINS=1` — hard-lock. Refuses every plugin
   even when `YGGDRASIM_ALLOW_PLUGINS=1` is also set.
3. unset, false, or unrecognised `YGGDRASIM_ALLOW_PLUGINS` values —
   default refusal. No plugin code is imported.

On first successful load the manager emits a one-line stderr note listing the
module file names. Operators can eyeball the line at shell startup to confirm
which plugins are executing. Example:

```
[plugins] loaded 1: my_plugin/ (YGGDRASIM_ALLOW_PLUGINS=1; set YGGDRASIM_DISALLOW_PLUGINS=1 to hard-lock plugin loading).
```

When loading is refused, the manager records a `__gate__` entry in
`plugin_load_errors()` describing the responsible env flag or default-deny
posture.

## Loader contract

The current loader accepts either:

- a single `.py` file placed directly under `plugins/`
- a package directory under `plugins/` with `__init__.py`

Each plugin module must expose:

```python
def register_plugins(manager):
    ...
```

Within that function, the plugin registers one or more capabilities:

```python
def register_plugins(manager):
    manager.register_capability("example.diagnostics", MyDiagnosticsCapability())
```

## Capability provider shape

The plugin manager itself is intentionally minimal: it only stores named
capabilities and offers extension hooks to the core.

The current runtime integration expects a capability provider to expose some or
all of the following callables:

- `extend_target(target)`
- `handle_command(surface, command_name, target, argument)`
- any capability-specific parser or dispatcher the owning surface documents

Capabilities may expose additional methods, but the core must always treat them
as optional and capability-scoped.

## Reserved capability names

Reserved capability names are private contracts between a trusted local
extension and the shell that consumes it. Published core documentation should
describe the loader contract, not restricted capability names or command
families.

Plugin-owned command families are intentionally documented by the plugin
package, not by the published core. The core should expose a clean missing
capability error when the owning plugin is absent.

## Publication model

This folder is intended for publication-time exclusion.

Operationally, that means:

- the tracked core can keep only the loader contract and documentation
- local operators can still drop proprietary or restricted plugins into
  `plugins/`
- frozen builds can use the same model from the writable runtime tree
- the core must remain runnable when a plugin is absent

Absent-plugin behavior should therefore be one of:

- command not exposed at all
- clean runtime error that explains the capability is optional

## Minimal skeleton

```python
class MyDiagnosticsCapability:
    def extend_target(self, target):
        return None


def register_plugins(manager):
    manager.register_capability("example.diagnostics", MyDiagnosticsCapability())
```

## Design notes

- Keep plugin code self-contained and runtime-root aware.
- Prefer capability-specific contracts over broad monkey patching.
- Do not assume tracked bundle paths when the same plugin must work in frozen
  builds.
- Keep operator-facing help owned by the plugin when the feature is optional.
- Keep restricted or proprietary plugin packages on the ignore list; do not
  document implementation file names in the published core.

## Absent-plugin contract

Without an optional plugin installed:

- core startup succeeds
- plugin-only commands are omitted or raise a clear `RuntimeError`
- shared protocol helpers continue to work without importing plugin code
- tests that pin absence behavior live in the tracked core suite
