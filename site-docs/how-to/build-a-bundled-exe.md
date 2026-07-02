---
title: Build a Bundled Executable
tags:
  - how-to
  - build
  - packaging
  - pyinstaller
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Build a Bundled Executable

## Goal

Produce a single-file PyInstaller bundle of the YggdraSIM launcher for the
target OS, validate that the writable runtime tree comes up correctly, and
confirm the main operator surfaces still work.

## Prerequisites

- a matching Python version (3.10+)
- `pyinstaller` installed (the `dev` optional dependency group provides it)
- native PC/SC libraries present on the build host
- the repository already installed editable (`pip install -e .`)

## Steps

1. Install the build-time dependencies.

    ```bash
    python -m pip install -e .[dev]
    ```

2. Run PyInstaller against the committed spec.

    ```bash
    pyinstaller --clean --noconfirm yggdrasim_main.spec
    ```

3. Inspect the produced artifact.

    - Linux: `dist/yggdrasim`
    - Windows: `dist/yggdrasim.exe`

4. Run the bundle once and verify the writable runtime tree is created.

    ```bash
    ./dist/yggdrasim
    ```

    On first launch the bundle writes a `YggdraSIM-data/` tree next to the
    executable when possible, or under `~/YggdraSIM-data` as fallback.

5. Sanity-check a few operator surfaces.

    ```bash
    ./dist/yggdrasim yggdrasim-profile-package --cmd "STATUS; EXIT"
    ```

## Validation

Run through the suggested checks before publishing:

- [ ] the bundle opens and creates the writable runtime tree where expected
- [ ] `SCP11`, `SCP11.live`, and `SCP11.local_access` can read seeded
      runtime material
- [ ] `yggdrasim-profile-package` can still locate `pySim` — either the
  installed PyPI wheel or the optional on-disk `pysim/` clone when the
  SAIP ASN.1 compile path is required
- [ ] state writes land in the runtime root, not inside the installed bundle
- [ ] smart-card flows pass on each target OS that is advertised

## Runtime root overrides

- `YggdraSIM-data` next to the executable is the preferred location
- `~/YggdraSIM-data` is the fallback
- `YGGDRASIM_RUNTIME_ROOT` forces a specific directory

## Related pages

- [Build and Packaging](../build-and-packaging.md)
- [Runtime Root](../reference/runtime-root.md)
- `guides/BUILD_AND_PACKAGING.md`
