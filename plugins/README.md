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

1. `YGGDRASIM_DISALLOW_PLUGINS=1` — hard-lock. Refuses every plugin,
   including the first-party `polling_plugin.py`. Intended for
   attestation / CI / air-gapped deployments where no out-of-tree
   Python may execute at startup.
2. `YGGDRASIM_ALLOW_PLUGINS=0` (or `false`/`no`/`off`) — explicit
   opt-out, equivalent to the disallow flag. Kept for backward compat
   with prior deployments that were already pinned to the old
   opt-in-only behavior.
3. `YGGDRASIM_ALLOW_PLUGINS=1` — explicit opt-in. Redundant now that
   the default is on, still honoured.

On first successful load the manager emits a one-line stderr note listing the
module file names. Operators can eyeball the line at shell startup to confirm
which plugins are executing. Example:

```
[plugins] loaded 1: __init__.py (hard-lock with YGGDRASIM_DISALLOW_PLUGINS=1).
```

The first-party `polling` plugin ships as a directory package
(`plugins/polling/`) so the canonical label is the package's
`__init__.py`. Legacy single-file plugins (`plugins/<name>.py`) still
appear under their module filename.

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
- localized `IPAD-LIVE` / `IPAD-TEST` on `SCP11/eim_local`
- BIP-over-WiFi / Ethernet polling bridge (`LocalizedPollingBridge`
  at `plugins/polling/wifi_ethernet_bridge.py` — the patentable
  loopback DNS / TLS / HTTP emulation lives here and nowhere else)
- SIM-side IPAE emulation extension
  (`plugins/polling/sim_toolkit_ipae.py`) which attaches to
  `SIMCARD.toolkit.ToolkitLogic` via `extend_target` and owns the
  DNS query, TLS handshake, and HTTP/1.1 request-parser state
  machine originally embedded in the core toolkit

Operator-facing references for those command families:

- `../SCP11/live/README.md`
- `../SCP11/test/README.md`
- `../SCP11/eim_local/GUIDE.md`
- `../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`

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

## Polling plugin layout

`plugins/polling/` holds the first-party polling capability. It is
deliberately split so the patentable surface can be excised in one
`rm -rf` without touching the core SIM simulator:

| File | Purpose |
| --- | --- |
| `__init__.py` | Aggregates `PollingCapability`, wires `extend_target` for `SCP11Console` / `EimLocalShell` / `ToolkitLogic` |
| `watchdog.py` | Poll-watchdog runtimes + timer / STK envelope helpers |
| `wifi_ethernet_bridge.py` | **Patentable.** BIP-over-WiFi/Ethernet loopback DNS/TLS/HTTP bridge |
| `ipad_standalone.py` | `LocalizedIPAdRunner` and `LocalizedRelayApduChannel` (bridge-backed IPAd flow) |
| `sim_toolkit_ipae.py` | SIM-side IPAE emulation (DNS / TLS / HTTP state machine) plugged into `ToolkitLogic` |
| `shell_lifecycle.py` | Shell-scope helpers (`_ensure_poll_bridge`, IPAD-* command handlers, bridge status payload) |
| `session.py` | Thin `EimLocalSession` proxy for plugin-internal construction |
| `stk_polling_mixin.py` | Legacy `LiveStkPollingMixin` shim kept empty for registry compatibility |

### Absent-plugin contract

Without the polling plugin installed:

- `ToolkitLogic` has zero IPAE-specific attributes — no
  `set_localized_poll_bridge`, no `eim_poll_*` state, no DNS / TLS /
  HTTP client behavior. The simulated UICC speaks only generic
  STK / BIP framework and plain ES8+ APDUs.
- `SimToolkitState` has no `eim_poll_*` fields (guarded by
  `tests/test_polling_plugin_absence_guard.py`).
- `EimLocalShell` commands `IPAD-LIVE` / `IPAD-TEST` / `IPAE-LIVE` /
  `IPAE-TEST` / `POLL` raise a plain `RuntimeError` explaining the
  capability is plugin-provided. `IPAD-DISCOVER` still works (ASN.1
  ES9+ `GetEimPackage`, no bridge traffic).
- `SCP11/{live,test}` orchestrators no longer carry
  `localized_poll_bridge`; ES9+ request building works as specified
  in SGP.32 §3 without any loopback bridge dependency.
