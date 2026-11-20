# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local eIM engine: a per-EID operation queue, an eIM signer, result checks and delivery routes.

SGP.32 v1.3 §3.1.1.1 and §3.3.1 describe the eIM side carried here: a queue of
eIM Packages per eUICC, a counter per eUICC incremented for every eUICC Package
sent, results checked against the eUICC certificate and sequence number, and
the acknowledgement the IPA uses to clear a result from the eUICC. Nothing in
this package imports the card simulator.
"""

from __future__ import annotations
