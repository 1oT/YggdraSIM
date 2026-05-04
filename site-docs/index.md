---
title: YggdraSIM
description: Secure-element, eUICC, OTA, SCP11, HIL bridge, and SAIP toolkit documentation.
---

<div class="oneot-only oneot-partner-strip" markdown="0">
  <span class="oneot-partner-strip__badge">Crafted at</span>
  <span class="oneot-wordmark" aria-label="1oT">
    <span class="oneot-wordmark__one">1</span><span class="oneot-wordmark__ot">oT</span>
  </span>
  <span class="oneot-partner-strip__divider" aria-hidden="true"></span>
  <span>Secure-element R&amp;D from the team behind global IoT connectivity.</span>
  <span class="oneot-partner-strip__divider" aria-hidden="true"></span>
  <a class="oneot-partner-strip__link" href="about/consultancy/">Custom features &amp; consultancy →</a>
</div>

<div class="hero">
  <div class="hero__mark-wrap">
    <img
      src="assets/images/yggdrasil-mark.svg"
      alt="YggdraSIM Yggdrasil mark"
      class="hero__mark"
    >
  </div>
  <div>
    <p class="hero__eyebrow">Secure Element Operator Documentation</p>
    <h1 class="hero__title">YggdraSIM</h1>
    <p class="hero__lead">
      As Yggdrasil connects the Nine Realms in Norse mythology, this suite
      connects the layers of secure-element communication across card, relay,
      OTA, profile-package, and HIL workflows.
    </p>
    <div class="hero__actions">
      <a class="md-button md-button--primary" href="getting-started/">Get Started</a>
      <a class="md-button" href="operator-surfaces/">Choose an Operator Surface</a>
      <a class="md-button" href="concepts/">Read the Concepts</a>
    </div>
  </div>
</div>


YggdraSIM is a Python toolkit for secure-element research, eUICC analysis,
SIM and eSIM management, OTA payload work, SCP11 relay and local flows, HIL
bridging, and SAIP profile-package tooling. The repository keeps operator
shells, protocol helpers, shared runtime, and the test suite in one workspace
so adjacent card, relay, package, and hardware-in-the-loop workflows can be
exercised without switching projects.

## Start here

<div class="grid cards" markdown>

-   :material-play-circle-outline: __Getting Started__

    ---

    Prereqs, install, and launch the main operator surfaces in one sitting.

    [Open](getting-started.md)

-   :material-map-outline: __Operator Surfaces__

    ---

    A table that maps a task to the right shell and entry point.

    [Open](operator-surfaces.md)

-   :material-sitemap-outline: __Architecture__

    ---

    Subsystem boundaries, shared state, runtime root, and dependencies.

    [Open](architecture.md)

-   :material-book-open-page-variant: __Concepts__

    ---

    The standards and card model the tooling acts on.

    [Open](concepts/index.md)

-   :material-cog-outline: __Subsystems__

    ---

    Deep dives for every operator surface in the repository.

    [Open](subsystems/index.md)

-   :material-lightbulb-on-outline: __How-To Runbooks__

    ---

    Task-driven recipes with prerequisites, steps, and validation.

    [Open](how-to/index.md)

-   :material-book-information-variant: __Reference__

    ---

    CLI matrix, state schema, runtime root, standards map, glossary, FAQ.

    [Open](reference/index.md)

-   :material-tools: __Internals__

    ---

    Contributor-facing notes on the registry, plugin contract, testing, and release.

    [Open](internals/index.md)

</div>

## Subsystem summary

| Subsystem | Role | Details |
| --- | --- | --- |
| `main/` | Unified launcher, path setup, and in-process dispatch | [Architecture](architecture.md) |
| `SCP03/` | GlobalPlatform admin shell, filesystem work, retrieval | [SCP03 Admin Shell](subsystems/scp03.md) |
| `SCP80/` | OTA packet build, wrap, transport, and decode | [SCP80 OTA Shell](subsystems/scp80.md) |
| `SCP11/live/` | Live relay shell for LPAd, IPAd, and IPAe | [SCP11 Live Relay](subsystems/scp11-live.md) |
| `SCP11/test/` | Test relay shell with lab-default trust | [SCP11 Test Relay](subsystems/scp11-test.md) |
| `SCP11/local_access/` | Direct local `ISD-R` shell | [SCP11 Local Access](subsystems/scp11-local-access.md) |
| `SCP11/eim_local/` | SGP.32 eIM-local package and polling shell | [SCP11 eIM Local](subsystems/scp11-eim-local.md) |
| `SIMCARD/` | Simulated UICC / eUICC backend (ETSI / GP / SCP03 / SCP80 / Toolkit / 5G AKA / AKMA / SUCI / `GET IDENTITY`) | [SIMCARD Simulator](subsystems/simcard-simulator.md) |
| `Tools/ProfilePackage/` | SAIP shell, lint engine, transcode TUI | [Profile Package](subsystems/profile-package.md) |
| `Tools/HilBridge/` | SIMtrace2-backed HIL bridge, supervisor, GSMTAP, AT+CSIM/CRSM transcoder | [HIL Bridge](subsystems/hil-bridge.md) |
| `Tools/ApduFuzz/` | Opt-in eUICC APDU mutation fuzzer (allow-listed, hard-gated) | [APDU Fuzzer](subsystems/apdu-fuzzer.md) |
| `Tools/EumDiag/` | EUM / SM-DP+ session-key injection + Wireshark Lua dissector | [EUM Diagnostics](subsystems/eum-diagnostics.md) |
| `Tools/SuciTool/` | SUCI key management shell | [SUCI Tool](subsystems/suci-tool.md) |
| `yggdrasim_common/gui_server/` | Optional Universal GUI Command Center (`--gui` / `--web-server`) | [Subsystems index](subsystems/index.md) |

## What this site covers

- install and launch paths for every operator surface
- architecture, shared state, runtime root, and plugin model
- concepts pages that summarize the underlying standards
- subsystem deep dives with command surfaces and pitfalls
- how-to runbooks for the most common workflows
- a reference layer with CLI matrix, state schema, glossary, troubleshooting
- internals pages for contributors
- a mirrored source library with the authored guide files
- SCP03 in-shell `GUIDE` and `HELP` content rendered for reading outside
  the terminal

## Build this site locally

```bash
python -m pip install -r requirements-docs.txt
python -m mkdocs serve
```

Use `python -m mkdocs build` when only the static site under `site/` is
needed. Run it from the repository root so the nav paths and the mirrored
source library resolve correctly. If your host only exposes `python3`,
substitute `python3` for `python`.

### Alternate visual variant (1oT brand)

A second config, `mkdocs.oneot.yml`, reuses the same `site-docs/` source
tree but renders it with the 1oT brand palette (mint/emerald primary,
Manrope display, Inter body, navy footer) and writes to `site-oneot/`.

```bash
python -m mkdocs serve -f mkdocs.oneot.yml -a 127.0.0.1:8010
python -m mkdocs build -f mkdocs.oneot.yml
```

The two configs can be served simultaneously on different ports. Content,
navigation, and the sidebar are identical; only the stylesheet and the
output directory differ.
