---
title: Architecture
tags:
  - architecture
  - overview
---

# Architecture

The architecture pages set out how YggdraSIM is organized, how subsystems
depend on each other, and how runtime state moves between shells, helpers,
storage, and optional encryption. Each section here pairs a short
description with a flow chart so the intended shape is visible at a glance.

For operator usage and launch commands, see [Getting Started](getting-started.md)
and [Operator Surfaces](operator-surfaces.md). For discoverable entry points
and symbol names, see `yggdrasim_common/registry.py` and the
[Registry and Launcher](internals/registry-and-launcher.md) internals page.

## Architectural intent

YggdraSIM keeps adjacent smart-card, eUICC, OTA, SCP11, HIL, and SAIP
workflows in one repository so the same operator can move between card
administration, relay work, package tooling, and hardware-in-the-loop
capture without leaving the workspace.

The architecture favors:

- interactive shells as the primary operator surface
- direct `python -m ...` entry points for automation
- repository-local shared helpers
- SQLite for mutable cross-module state
- plain files where manual review remains the correct interface

## System context

```mermaid
flowchart LR
    Operator(["Operator"]) --> Launcher["main/main.py<br/>launcher"]

    Launcher --> SCP03["SCP03<br/>admin shell"]
    Launcher --> SCP80["SCP80<br/>OTA shell"]
    Launcher --> Live["SCP11.live"]
    Launcher --> Test["SCP11.test"]
    Launcher --> Local["SCP11.local_access"]
    Launcher --> EimLocal["SCP11.eim_local"]
    Launcher --> ProfileTool["Tools.ProfilePackage"]
    Launcher --> HilBridge["Tools.HilBridge"]
    Launcher --> Suci["Tools.SuciTool"]

    SCP03 --> Card[("PC/SC reader<br/>UICC / eUICC")]
    SCP80 --> Card
    Live --> Card
    Test --> Card
    Local --> Card
    EimLocal --> Card
    HilBridge --> Card

    Live --> Network[("ES9+ / SM-DP+ endpoints")]
    Test --> Network
    EimLocal --> LocalServices[("Localized eIM / SM-DP+ endpoints")]

    ProfileTool --> Files[("Profile / JSON / DER files")]
    Suci --> Files
    EimLocal --> Files

    HilBridge -. GSMTAP mirror .-> Wireshark[("Wireshark<br/>UDP 4729")]
    HilBridge -. relay side-channel .-> Live
```

## Repository structure

<div class="mermaid-xl" markdown="1">

```mermaid
%%{init: {'flowchart': {'nodeSpacing': 50, 'rankSpacing': 60, 'htmlLabels': true, 'padding': 12}, 'themeVariables': {'fontSize': '15px'}}}%%
flowchart TB
    subgraph EntryPoints["Entry points"]
        Main["main/"]
        Registry["yggdrasim_common/registry.py"]
    end

    subgraph OperatorModules["Operator modules"]
        SCP03["SCP03/"]
        SCP80["SCP80/"]
        SCP11["SCP11/"]
        Tools["Tools/"]
        SIMCARD["SIMCARD/"]
    end

    subgraph SharedRuntime["Shared runtime"]
        Inventory["yggdrasim_common/device_inventory.py"]
        Crypto["yggdrasim_common/inventory_crypto.py"]
        RuntimePaths["yggdrasim_common/runtime_paths.py"]
        PluginRuntime["yggdrasim_common/plugin_runtime.py"]
        CardBackend["yggdrasim_common/card_backend.py"]
        HilRuntime["yggdrasim_common/hil_bridge_runtime.py"]
        Plugins["plugins/"]
        StateDir["state/"]
        PySim["pysim/"]
        TestsDir["tests/"]
    end

    Main --> SCP03
    Main --> SCP80
    Main --> SCP11
    Main --> Tools
    Main --> SIMCARD

    Registry --> SCP03
    Registry --> SCP80
    Registry --> SCP11
    Registry --> Tools

    SCP03 --> Inventory
    SCP80 --> Inventory
    SCP11 --> Inventory
    Tools --> Inventory

    Inventory --> Crypto
    Crypto --> StateDir

    SCP11 --> PluginRuntime
    PluginRuntime --> Plugins
    PluginRuntime --> RuntimePaths

    SCP03 --> CardBackend
    SCP11 --> CardBackend
    CardBackend --> SIMCARD

    Tools --> HilRuntime
    HilRuntime --> RuntimePaths

    SCP03 --> PySim
    SCP11 --> PySim
    Tools --> PySim

    TestsDir --> SCP03
    TestsDir --> SCP80
    TestsDir --> SCP11
    TestsDir --> Tools
```

</div>

## Interdependency matrix

| Subsystem | Launcher | PC/SC | Network | `pysim/` | Shared inventory | Optional crypto envelope | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `SCP03` | Primary | Primary | No | Optional | Primary | Primary | GP admin, filesystem, retrieval |
| `SCP80` | Primary | Optional | Optional | No | Primary | Primary | OTA build, send, decode |
| `SCP11.live` | Primary | Primary | Primary | Primary | Primary | Primary | Live relay-oriented shell, plugin-backed `POLL` |
| `SCP11.test` | Primary | Primary | Primary | Primary | Primary | Primary | Test relay shell with lab-only shaping |
| `SCP11.relay` | Optional | Optional | Primary | Primary | Optional | Optional | Compatibility namespace |
| `SCP11.local_access` | Primary | Primary | No | Primary | Primary | Primary | Direct local `ISD-R` flow |
| `SCP11.eim_local` | Primary | Primary | Primary | Primary | Primary | Primary | eIM-local package, polling, handover, IPAd standalone |
| `Tools.ProfilePackage` | Primary | No | No | Primary | No | No | SAIP tooling and transcode UI |
| `Tools.HilBridge` | Primary | Primary | No | No | No | No | HIL supervisor and relay |
| `Tools.SuciTool` | Primary | No | No | No | No | No | File/stdin shell around `suci-keytool` |

## Complete dependency graph

```mermaid
flowchart LR
    Main["main/main.py"] --> SCP03
    Main --> SCP80
    Main --> Live["SCP11.live"]
    Main --> Test["SCP11.test"]
    Main --> Relay["SCP11.relay"]
    Main --> Local["SCP11.local_access"]
    Main --> EimLocal["SCP11.eim_local"]
    Main --> Profile["Tools.ProfilePackage"]
    Main --> Hil["Tools.HilBridge"]
    Main --> Suci["Tools.SuciTool"]

    Registry["yggdrasim_common/registry.py"] --> SCP03
    Registry --> SCP80
    Registry --> Live
    Registry --> Test
    Registry --> Relay
    Registry --> Local
    Registry --> EimLocal
    Registry --> Profile
    Registry --> Hil
    Registry --> Suci

    SCP80 -. optional decode helpers .-> SCP03

    Live --> Shared["SCP11/shared"]
    Test --> Shared
    Relay --> Shared
    Local --> Shared
    EimLocal --> Shared

    SCP03 --> Inventory["yggdrasim_common/device_inventory.py"]
    SCP80 --> Inventory
    Live --> Inventory
    Test --> Inventory
    Local --> Inventory
    EimLocal --> Inventory

    Inventory --> Crypto["yggdrasim_common/inventory_crypto.py"]
    Crypto --> Gpg[("gpg binary / agent<br/>optional")]

    Live --> PluginRuntime["yggdrasim_common/plugin_runtime.py"]
    Test --> PluginRuntime
    EimLocal --> PluginRuntime
    PluginRuntime --> Plugins[("plugins/ under runtime root")]
    PluginRuntime --> RuntimePaths["yggdrasim_common/runtime_paths.py"]

    Hil --> HilRuntime["yggdrasim_common/hil_bridge_runtime.py"]
    HilRuntime --> RuntimePaths

    SCP03 --> PySim["pysim/"]
    Live --> PySim
    Test --> PySim
    Local --> PySim
    EimLocal --> PySim
    Profile --> PySim
```

## Runtime-root resolution

Every subsystem resolves its writable paths through a shared resolver. The
resolution order is deterministic:

```mermaid
flowchart LR
    Start(["launch"]) --> Env{"YGGDRASIM_RUNTIME_ROOT<br/>set?"}
    Env -- yes --> UseEnv["use that directory"]
    Env -- no --> Frozen{"frozen build?"}
    Frozen -- no --> Repo["use repository root"]
    Frozen -- yes --> Next["YggdraSIM-data<br/>next to executable"]
    Next --> Writable{"writable?"}
    Writable -- yes --> UseNext["use YggdraSIM-data"]
    Writable -- no --> Home["fallback to ~/YggdraSIM-data"]

    UseEnv --> Final(["resolved runtime root"])
    Repo --> Final
    UseNext --> Final
    Home --> Final
```

See [Runtime Root](reference/runtime-root.md) for the full picture.

## Shared state and secret flow

Mutable runtime state is centralized under `state/`. Legacy files feed the
inventory on first launch and then stay on disk as fallback or diff
material.

```mermaid
flowchart LR
    Legacy[("Legacy files<br/>Workspace/SCP03/keys.ini<br/>SCP80/ota_config.ini<br/>Workspace/LocalEIM/eim_runtime_state.json")] --> Import["import / fallback loaders"]
    Import --> SQLite[("state/device_inventory.sqlite3")]

    SCP03 --> SQLite
    SCP80 --> SQLite
    SCP11["SCP11 modules"] --> SQLite
    HilBridge["Tools.HilBridge"] --> HilState[("state/hil_bridge_*.json")]

    CryptoConfig[("state/inventory_crypto.json")] --> InventoryLayer["yggdrasim_common/device_inventory.py"]
    InventoryLayer --> SQLite
    InventoryLayer --> Envelope[("encrypted JSON envelope<br/>optional")]
    Envelope --> Gpg[("gpg binary / agent")]
```

State model:

- per-card namespaces are keyed by `ICCID` or `EID`
- module-level mutable settings are stored separately from per-card inventory
- encrypted payloads are decrypted only when a module reads them back into
  the active command path
- source runs load optional plugins directly from the repository `plugins/`
  tree, while frozen builds load them from the writable runtime root
- HIL supervisor and relay publish their state to dedicated JSON files so a
  second operator shell can observe readiness without opening a PC/SC handle

See [State Schema](reference/state-schema.md) for the current schema and
identity-key rules.

## Session lifecycle

One operator command touches many layers. The swimlane below is a typical
`DISCOVER` or `STATUS` path through `SCP11/live`.

```mermaid
sequenceDiagram
    participant Op as Operator
    participant Shell as SCP11.live shell
    participant Reg as registry / plugin runtime
    participant Inv as device_inventory
    participant Env as inventory_crypto
    participant Card as eUICC (ISD-R)
    participant Net as SM-DP+ / eIM

    Op->>Shell: launch + command
    Shell->>Reg: resolve orchestrator + capabilities
    Reg-->>Shell: symbols, optional plugins
    Shell->>Inv: read per-EID settings
    Inv->>Env: unwrap payload if enveloped
    Env-->>Inv: cleartext payload
    Inv-->>Shell: settings
    Shell->>Card: ES10 exchanges
    Card-->>Shell: responses
    Shell->>Net: ES9+ exchanges
    Net-->>Shell: responses
    Shell->>Inv: persist new settings / counters
    Inv->>Env: envelope on write (if enabled)
    Shell-->>Op: structured output
```

## SCP03 internal shape

`SCP03` keeps a clean separation between the shell surface, domain logic,
transport, cryptography, and decoders.

```mermaid
flowchart LR
    Shell["interface/<br/>shell, commands, wizards"] --> Logic["logic/<br/>GP, FS, security controllers"]
    Logic --> Transport["transport/card.py"]
    Logic --> Session["crypto/<br/>SCP03 or SCP02 session helpers"]
    Logic --> Core["core/<br/>decoders, CAP, TLV utilities"]
    Logic --> Inv[("shared SQLite inventory")]
    Transport --> Card[("PC/SC card transport")]
```

Responsibilities:

- GP secure-channel establishment and card session handling
- registry and lifecycle work
- ETSI / 3GPP filesystem navigation
- export, report generation, and gold-snapshot diffs
- module-level and per-card state persistence through the shared inventory

## SCP80 internal shape

`SCP80` is deliberately small and state-driven.

```mermaid
flowchart LR
    Cli["cli.py / OtaShell"] --> Config["config.py / ConfigManager"]
    Cli --> Builder["builder.py / packet assembly"]
    Cli --> Transport["transport.py"]
    Config --> Inv[("shared SQLite inventory")]
    Builder -. optional decode maps .-> SCP03
    Transport --> Bearer[("reader path or external transport")]
```

Responsibilities:

- manage OTA security parameters and packet layout
- bind mutable state to `ICCID`
- decode and inspect payload content
- optionally reuse SCP03 decode helpers for filesystem-aware output

## SCP11 family landscape

The `SCP11` tree is split by operational flavor and anchored by a single
shared helper layer.

```mermaid
flowchart TB
    subgraph RelayFlavours["Relay flavours"]
        Live["live"]
        Test["test"]
        Relay["relay"]
    end

    subgraph LocalFlavours["Local flavours"]
        Local["local_access"]
        EimLocal["eim_local"]
    end

    subgraph SharedLayer["Shared SCP11 layer"]
        Shared["shared/"]
        ASN1["ASN.1 registries"]
        Payloads["payload builders"]
        Crypto["crypto helpers"]
        Transport["PC/SC / relay transport helpers"]
    end

    RelayFlavours --> Shared
    LocalFlavours --> Shared
    Shared --> ASN1
    Shared --> Payloads
    Shared --> Crypto
    Shared --> Transport
```

Relay flavors:

- `SCP11.live` is the production-oriented relay shell
- `SCP11.test` mirrors `live` with test-certificate and shaping defaults
- `SCP11.relay` is a compatibility namespace

Local flavors:

- `SCP11.local_access` performs direct local `ISD-R` flows
- `SCP11.eim_local` layers eIM package authoring, localized polling,
  hotfolder execution, response logging, handover, and a standalone `IPAd`
  runner on top of the local SCP11 stack

## Optional plugin runtime

Plugins are optional. The core must remain runnable without any plugin
present. `yggdrasim_common/plugin_runtime.py` scans the active runtime
root's `plugins/` directory at launch.

```mermaid
flowchart LR
    Live["SCP11.live"] --> Manager["PluginManager"]
    Test["SCP11.test"] --> Manager
    EimLocal["SCP11.eim_local"] --> Manager

    Manager --> Runtime[("plugins/ under runtime root")]
    Runtime -->|register_plugins| Capability["reserved capability 'polling'"]

    Capability --> Live
    Capability --> Test
    Capability --> EimLocal

    Manager -. load errors .-> Diag["diagnostics surface"]
```

See [Plugin Contract](internals/plugin-contract.md) for the loader
contract, reserved capability names, and absent-plugin behavior.

## Profile lifecycle on the eUICC

```mermaid
stateDiagram-v2
    [*] --> ERASED
    ERASED --> DISABLED: LoadBoundProfilePackage
    DISABLED --> ENABLED: EnableProfile
    ENABLED --> DISABLED: DisableProfile
    DISABLED --> ERASED: DeleteProfile
    ENABLED --> ERASED: DeleteProfile<br/>(forbidden if active)
    note right of DISABLED
        Multiple profiles can coexist<br/>
        in DISABLED at the same time.
    end note
    note right of ENABLED
        At most one profile is<br/>
        ENABLED per eUICC slot.
    end note
```

## SAIP profile pipeline

A profile moves through several representations before it lands on a card.
`Tools/ProfilePackage` owns the file-side transforms. `SCP11/local_access`
and `SCP11/live` own the card-side consumption.

```mermaid
flowchart LR
    Template[("Authored template<br/>text / JSON")] --> UPP["UPP<br/>Unprotected Profile Package"]
    UPP --> PE["PE list<br/>Profile Elements"]
    UPP --> DER["ASN.1 DER encoding"]
    UPP --> BindSvc["SM-DP+ binding<br/>session keys + segmentation"]
    BindSvc --> BPP[("BPP<br/>Bound Profile Package")]

    ProfileTool["Tools.ProfilePackage"] -. lint + transcode .-> UPP
    ProfileTool -. sidecars .-> Sidecars[("*.transcode.json<br/>*.transcode.der<br/>*.transcode.txt")]

    BPP --> ISDR[("eUICC ISD-R")]
    LocalAccess["SCP11.local_access<br/>LOAD-PROFILE"] --> BPP
    Live["SCP11.live<br/>DOWNLOAD-PROFILE"] --> BPP
```

## HIL bridge topology

The HIL bridge keeps a live card visible to both a modem and YggdraSIM
operator shells, and mirrors every APDU to Wireshark.

```mermaid
flowchart LR
    Card[("Physical UICC / eUICC<br/>in PC/SC reader")] --> PCSC["pcscd"]
    PCSC --> Bridge["Tools.HilBridge<br/>127.0.0.1:9997"]
    Bridge --> Remsim["osmo-remsim-client-st2"]
    Remsim --> SIMtrace2["SIMtrace2"]
    SIMtrace2 --> Modem[("Modem / DUT")]

    Bridge --> GSMTAP[("UDP 4729<br/>GSMTAP mirror")]
    GSMTAP --> Wireshark[("Wireshark")]

    Bridge --> Relay[("relay side-channel<br/>apduUrl / statusUrl")]
    Relay --> Shell[("YggdraSIM operator shells")]

    Supervisor["Tools.HilBridge.supervisor"] -. supervises .-> Bridge
    Supervisor -. supervises .-> Remsim
    Supervisor --> HilState[("state/hil_bridge_*.json")]
```

See [HIL Model](concepts/hil-model.md) for the physical plumbing story
and [HIL Bridge](subsystems/hil-bridge.md) for the operator surface.

## Card-backend selection

`yggdrasim_common/card_backend.py` abstracts the physical-versus-simulated
split so subsystem shells can target either backend.

```mermaid
flowchart LR
    Launcher["main/main.py"] -->|--card-backend pcsc| PCSC[("PC/SC reader")]
    Launcher -->|--card-backend sim| Sim["SIMCARD simulator"]

    Sim --> EuiccStore["euicc_store.py"]
    Sim --> ProfileStore["profile_store.py"]
    Sim --> Naa["naa.py"]
    Sim --> Etsi["etsi_fs.py"]
    Sim --> Toolkit["toolkit.py"]

    PCSC --> CardBackend["yggdrasim_common/card_backend.py"]
    Sim --> CardBackend

    CardBackend --> SCP03
    CardBackend --> SCP11
```

## Operator consequences

- `SCP03` is the card-administration and filesystem environment, not the
  relay shell
- `SCP11/live` and `SCP11/test` are the primary relay-facing shells
- `SCP11/local_access` is the direct local `ISD-R` path
- `SCP11/eim_local` is the eIM-side package, polling, and handover shell
- `Tools/ProfilePackage` is the SAIP package inspection and transcode
  surface
- `Tools/HilBridge` is the dedicated physical-card-to-modem bridge path
- `Tools/SuciTool` is the SUCI key helper
- `SIMCARD` is the simulator backend activated by `--card-backend sim`

## Deep reference

For the full authored architecture narrative, dependency tables, and flow
charts, use `guides/ARCHITECTURE.md`. This site page is intentionally
diagram-first; the guide is the canonical prose version.
