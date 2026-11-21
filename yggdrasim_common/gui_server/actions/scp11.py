# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP11 eSIM management Command Center actions that predate ``scp11_live``.

None is registered. ``scp11.download_profile`` ("Download profile (SGP.22, WS
flow)") was a form over the ``/api/flows/download-profile`` WebSocket; eSIM
Management downloads with "Download profile (activation code)"
(``scp11_live.download_profile``), which runs the console's own command, so
the older form is no longer offered.
"""

from __future__ import annotations
