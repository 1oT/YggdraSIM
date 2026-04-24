---
title: Registry and Launcher
tags:
  - internals
  - launcher
  - registry
---

# Registry and Launcher

The launcher and the registry together are how YggdraSIM advertises its
operator surfaces and how external automation discovers stable entry points.

## Launcher

`main/main.py` is the unified entry point. Its responsibilities are:

- set up `sys.path` so both source runs and editable installs work
- dispatch into a chosen subsystem by running its `entry` callable in-process
- offer a menu surface for interactive users
- expose a handful of wrapper flags that apply globally to dispatched modules

Key wrapper flags:

| Flag | Effect |
| --- | --- |
| `--debug`, `--verbose` | elevate log levels to debug globally |
| `--card-backend sim` | route card work to the simulator backend |
| `--sim-eim-identity <path>` | pin the simulated card's BF55 eIM identity |

In-process dispatch means that module-level singletons, caches, and
`runtime_paths` resolution are shared across a single launcher session.
Separate `python -m` invocations are fully independent.

## Registry

`yggdrasim_common/registry.py` is the discovery surface for stable entry
points and public symbols. It exposes:

- `SUBSYSTEMS` - short-name-to-description map
- `CLI_MODULES` - list of runnable `python -m` targets
- `SYMBOL_REGISTRY` - registry-key-to-`module:Attribute` targets
- `get(key)` - resolve a single symbol by key
- `resolve(target)` - resolve a `module:Attribute` target string
- `search(substring)` - search over registered symbols

The point of the registry is to give external tooling a way to find the
right class or callable without walking the tree. It is lazy: nothing is
imported until a lookup happens.

## Adding a new subsystem

When a new subsystem is added:

1. Add a `SUBSYSTEMS` entry describing the subsystem in one line.
2. Add its runnable module name to `CLI_MODULES` if it should be discoverable
   as a `python -m` target.
3. Register stable public symbols in `SYMBOL_REGISTRY`. Keep the registry
   scoped to long-lived, public APIs.
4. Add a console-script entry to `pyproject.toml` under
   `[project.scripts]`.
5. Add the entry-point wrapper to `yggdrasim_common/console_scripts.py`.
6. Document the surface in:
    - `guides/CAPABILITIES.md`
    - `guides/ARCHITECTURE.md`
    - the appropriate subsystem page under `site-docs/subsystems/`
    - the [CLI Matrix](../reference/cli-matrix.md)

## Console scripts

`yggdrasim_common/console_scripts.py` is the thin shim layer that installed
commands resolve to. Each function there invokes the corresponding
subsystem's `entry` callable. Keep those shims minimal so behavior lives in
the subsystem, not in the shim.

## In-process versus subprocess dispatch

The launcher uses in-process dispatch intentionally. When a subsystem needs
isolation (for example, to avoid leaking `sys.path` or cached modules), use
`subprocess` explicitly. Do not invent second-layer dispatch helpers around
the launcher; favor the plain `python -m` form.

## Related pages

- [CLI Matrix](../reference/cli-matrix.md)
- [Architecture](../architecture.md)
- [Plugin Contract](plugin-contract.md)
