# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 (live) Command Center actions.

Registers:

* ``scp11.download_profile`` — form-driven wrapper around the existing
  ``/api/flows/download-profile`` WebSocket from Milestone B-3. The
  action declares its input schema here so the GUI can render a proper
  form; the actual streaming dispatch still runs on the established WS
  endpoint (the UI opens the WS with the form values as the ``start``
  frame).
"""

from __future__ import annotations

import logging

from .registry import ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.scp11")


DOWNLOAD_PROFILE_SPEC = ActionSpec(
    id="scp11.download_profile",
    subsystem="eSIM Live",
    title="Download profile (SGP.22, WS flow)",
    description=(
        "Run the full SGP.22 profile download against the chosen reader. "
        "Streams orchestrator progress live into a log panel. Dry-run "
        "just validates connectivity without installing the profile."
    ),
    inputs=(
        ActionField(
            name="reader",
            label="Reader",
            kind="reader",
            required=True,
            help="PC/SC reader name (see the 'Live > PC/SC readers' panel).",
        ),
        ActionField(
            name="activation_code",
            label="Activation code",
            kind="string",
            required=True,
            placeholder="LPA:1$smdp.example.com$MATCHING-ID",
            help="Full SGP.22 activation code, or the shorthand 'smdp$matching-id'.",
        ),
        ActionField(
            name="confirmation_code",
            label="Confirmation code",
            kind="string",
            required=False,
            secret=True,
            help="Optional user confirmation code (if the profile requires one).",
        ),
        ActionField(
            name="dry_run",
            label="Dry run (just reach the card)",
            kind="bool",
            required=False,
            default=False,
            help="If enabled, connects to the reader but does not call run_flow().",
        ),
    ),
    output_kind="log_stream",
    # Streaming endpoint lives at /api/flows/download-profile (already
    # registered by routes/live.py); the UI opens that WS directly.
    dispatcher=None,
    requires_card=True,
    streams=True,
    tags=("sgp22", "download", "rsp"),
)


get_registry().register(DOWNLOAD_PROFILE_SPEC)
