---
title: Internals
tags:
  - internals
---

# Internals

Internals pages are aimed at contributors. They document the shared runtime,
the plugin contract, the test harness, and the coding conventions that keep
the codebase readable across subsystems.

## Pages

<div class="grid cards" markdown>

-   :material-sitemap: __Registry and Launcher__

    ---

    The unified launcher, the `yggdrasim_common/registry.py` discovery layer, and the dispatch model.

    [Open](registry-and-launcher.md)

-   :material-puzzle-outline: __Plugin Contract__

    ---

    Plugin discovery, the capability manager, and the reserved capability names.

    [Open](plugin-contract.md)

-   :material-test-tube: __Testing Guide__

    ---

    pytest layout, scope conventions, and the no-mass-run policy.

    [Open](testing-guide.md)

-   :material-format-align-left: __Coding Standards__

    ---

    Operator-facing coding conventions the repository enforces for consistency.

    [Open](coding-standards.md)

-   :material-rocket-launch-outline: __Release Checklist__

    ---

    Publication gate for editable, Docker, and bundled builds.

    [Open](release-checklist.md)

</div>
