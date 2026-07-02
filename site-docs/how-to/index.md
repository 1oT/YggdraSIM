---
title: How-To
tags:
  - how-to
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# How-To

How-to pages are task-driven. Each page has a stated goal, an explicit list of
prerequisites, a short set of numbered steps, validation, and a pointer to the
subsystem page that contains the full surface.

## Profile workflows

<div class="grid cards" markdown>

-   :material-download: __Download a Profile (Live Relay)__

    ---

    Activation-code driven download through `SCP11/live`.

    [Open recipe](download-a-profile-live.md)

-   :material-cloud-download-outline: __Download a Profile (Local Access)__

    ---

    Direct local ISD-R `LOAD-PROFILE` through `SCP11/local_access`.

    [Open recipe](download-a-profile-local.md)

-   :material-swap-horizontal: __Enable, Disable, Delete a Profile__

    ---

    Profile state control, done right, with notification hygiene.

    [Open recipe](enable-disable-delete-profile.md)

-   :material-magnify: __Inspect and Transcode SAIP__

    ---

    Lint, transcode, and review profile packages in the TUI.

    [Open recipe](inspect-and-transcode-saip.md)

</div>

## Hardware and runtime

<div class="grid cards" markdown>

-   :material-monitor-dashboard: __Universal GUI Command Center__

    ---

    Run the desktop or web-server workbench with a live APDU dock and
    remote-card diagnostics.

    [Open guide](../subsystems/gui-command-center.md)

-   :material-access-point-network: __Remote APDU Streaming__

    ---

    Stream a PC/SC reader through Card Bridge and SSH, including HIL
    remote-card mode.

    [Open recipe](remote-apdu-streaming.md)

-   :material-lan: __Install RemSIM / APDU Streaming__

    ---

    Prepare Linux or Raspberry Pi hosts for SIMtrace2, RemSIM, GSMTAP,
    and remote-card HIL.

    [Open recipe](install-remsim-apdu-streaming.md)

-   :material-bridge: __Run a HIL Capture__

    ---

    Bring up the SIMtrace2 stack and capture end-to-end APDU traffic.

    [Open recipe](run-hil-capture.md)

-   :material-replay: __Replay a HIL pcap offline__

    ---

    Re-open a saved capture in the decoded-APDU TUI, with optional
    SCP03 / SCP11c keybag decryption.

    [Open recipe](replay-hil-pcap-offline.md)

-   :material-shield-lock-outline: __Enable Inventory Encryption__

    ---

    Turn on the optional `gpg`-backed envelope for stored payloads.

    [Open recipe](enable-inventory-encryption.md)

-   :material-certificate-outline: __Load Certificates and Configuration__

    ---

    Bring operator-owned certificates, keysets, identity files, and
    encryption envelopes into YggdraSIM without touching bundled
    starter material.

    [Open recipe](load-certificates-and-config.md)

-   :material-puzzle-outline: __Write a Plugin__

    ---

    Author a runtime plugin against a private capability contract.

    [Open recipe](write-a-plugin.md)

-   :material-package-variant-closed: __Build a Bundled Executable__

    ---

    Produce a PyInstaller bundle for the unified launcher.

    [Open recipe](build-a-bundled-exe.md)

-   :material-docker: __Run in Docker__

    ---

    Use the bundled Dockerfile, keep state on the host.

    [Open recipe](run-in-docker.md)

-   :material-stethoscope: __Diagnostics Toolbox__

    ---

    Visual SAIP diff, simulator-to-TUI auto-open, opt-in APDU mutation
    fuzzer, and EUM / SM-DP+ session-key diagnostics.

    [Open recipe](diagnostics-toolbox.md)

</div>
