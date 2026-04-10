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
    manager.register_capability("polling", MyPollingCapability())
```

## Capability provider shape

The plugin manager itself is intentionally minimal: it only stores named
capabilities and offers extension hooks to the core.

The current polling integration expects the capability provider to expose some
or all of the following callables:

- `extend_target(target)`
- `dispatch_poll_method(target, method_name, *args, **kwargs)`
- `handle_command(surface, command_name, target, argument)`
- `parse_eim_local_ipae_options(argument)`

Capabilities may expose additional methods, but the core must always treat them
as optional and capability-scoped.

## Current reserved capability names

- `polling`

## Current consumers

The currently supported plugin-backed surfaces are:

- `SCP11/live`
- `SCP11/test`
- `SCP11/eim_local`

`SCP11/experimental` is no longer a plugin consumer.

Current plugin-owned command families:

- relay `POLL` on `SCP11/live`
- relay `POLL` on `SCP11/test`
- localized `IPAE-LIVE` / `IPAE-TEST` on `SCP11/eim_local`

Operator-facing references for those command families:

- `../SCP11/live/README.md`
- `../SCP11/test/README.md`
- `../SCP11/eim_local/GUIDE.md`
- `../PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`

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
class MyPollingCapability:
    def extend_target(self, target):
        return None


def register_plugins(manager):
    manager.register_capability("polling", MyPollingCapability())
```

## Design notes

- Keep plugin code self-contained and runtime-root aware.
- Prefer capability-specific contracts over broad monkey patching.
- Do not assume tracked bundle paths when the same plugin must work in frozen
  builds.
- Keep operator-facing help owned by the plugin when the feature is optional.
