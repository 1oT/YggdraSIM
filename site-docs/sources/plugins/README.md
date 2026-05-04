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

## Load posture (default-on)

The plugin manager loads every `.py` file (or package directory) it finds under
the active runtime root's `plugins/`. Two env flags adjust the posture:

1. `YGGDRASIM_DISALLOW_PLUGINS=1` -- hard-lock. Refuses every plugin.
   Intended for attestation / CI / sandboxed builds where no
   out-of-tree Python may execute at startup.
2. `YGGDRASIM_ALLOW_PLUGINS=0` (or `false`/`no`/`off`) -- explicit
   opt-out, equivalent to the disallow flag.
3. `YGGDRASIM_ALLOW_PLUGINS=1` -- explicit opt-in. Redundant now that
   the default is on, still honoured.

On first successful load the manager emits a one-line stderr note listing the
module file names. Operators can eyeball the line at shell startup to confirm
which plugins are executing. Example:

```
[plugins] loaded 0 (hard-lock with YGGDRASIM_DISALLOW_PLUGINS=1).
```

A plugin shipped as a directory package (`plugins/<name>/`) reports under its
`__init__.py`. Single-file plugins (`plugins/<name>.py`) appear under their
module filename.

When loading is hard-locked the manager records a `__gate__` entry in
`plugin_load_errors()` pointing at the responsible env flag.

## Loader contract

The current loader accepts either:

- a single `.py` file placed directly under `plugins/`
- a package directory under `plugins/` with `__init__.py`

Each plugin module must expose:

```python
def register_plugins(manager):
    ...
```

Within that function, the plugin registers one or more capabilities under a
plugin-chosen capability name:

```python
def register_plugins(manager):
    manager.register_capability("my-capability", MyCapability())
```

## Capability provider shape

The plugin manager itself is intentionally minimal: it only stores named
capabilities and offers extension hooks to the core.

A capability provider typically exposes some or all of the following
generic plugin-protocol callables:

- `extend_target(target)`
- `dispatch_method(target, method_name, *args, **kwargs)`
- `handle_command(surface, command_name, target, argument)`

Capabilities may expose additional methods, but the core must always treat them
as optional and capability-scoped.

## Publication model

This folder is intended for publication-time exclusion.

Operationally, that means:

- the tracked core can keep only the loader contract and documentation
- local operators can still drop deployment-specific plugins into
  `plugins/`
- frozen builds can use the same model from the writable runtime tree
- the core must remain runnable when a plugin is absent

Absent-plugin behavior should therefore be one of:

- command not exposed at all
- clean runtime error that explains the capability is optional

## Minimal skeleton

```python
class MyCapability:
    def extend_target(self, target):
        return None


def register_plugins(manager):
    manager.register_capability("my-capability", MyCapability())
```

## Design notes

- Keep plugin code self-contained and runtime-root aware.
- Prefer capability-specific contracts over broad monkey patching.
- Do not assume tracked bundle paths when the same plugin must work in frozen
  builds.
- Keep operator-facing help owned by the plugin when the feature is optional.
