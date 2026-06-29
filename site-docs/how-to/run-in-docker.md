---
title: Run in Docker
tags:
  - how-to
  - docker
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Run in Docker

## Goal

Run a YggdraSIM operator shell inside a container, keep mutable runtime state
on the host, and understand the limits of containerized card access.

## Prerequisites

- Docker engine available on the host
- network access for the build-time dependency installs
- a writable host directory for the persisted runtime tree

## Steps

1. Build the image.

    ```bash
    docker build -t yggdrasim .
    ```

2. Run the umbrella shell.

    ```bash
    docker run --rm -it yggdrasim
    ```

3. Run a specific installed command.

    ```bash
    docker run --rm -it yggdrasim yggdrasim-profile-package --cmd "STATUS; EXIT"
    ```

4. Mount a persistent runtime directory from the host.

    ```bash
    docker run --rm -it \
      -v "$(pwd)/YggdraSIM-data:/opt/YggdraSIM-data" \
      yggdrasim yggdrasim-scp11-live --cmd "HELP; EXIT"
    ```

    On first launch inside the container, the writable runtime tree lands in
    `/opt/YggdraSIM-data`, which is also the host directory. Subsequent
    runs reuse the same state.

## Where containers shine

- offline analysis and decode
- simulator flows that do not require physical card hardware
- CI smoke paths
- documentation builds

## Where containers do not help

- real PC/SC reader access. Container USB passthrough is host-specific and
  can be fragile. For real card flows, run the launcher directly on the
  host.
- HIL bridge work. SIMtrace2 access depends on host USB and permission
  setup.

## Pitfalls

- Without a volume mount the runtime tree lives inside the container. It
  goes away when the container is removed. Always mount a host directory
  when state persistence matters.
- Be cautious with secrets. Keys and certificates under a mounted
  `YggdraSIM-data/` are readable to processes inside the container.

## Related pages

- [Build and Packaging](../build-and-packaging.md)
- [Runtime Root](../reference/runtime-root.md)
