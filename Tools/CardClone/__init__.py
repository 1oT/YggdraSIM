# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Card-behaviour cloning: chart a real card, replay it on the simulator.

Two artefacts pair to set up a simulated card:

* a **behaviour profile** (this package) -- how a card answers: its
  status-word dialect, Le correction, chaining style, which files exist.
* a **SAIP profile** -- what data the card holds: ICCID, IMSI, EF content.

The split is deliberate and enforced. Nothing identity-shaped enters a
behaviour profile, so one charted card's personality can be paired with
any SAIP profile without the two fighting over the same fields.
"""

from __future__ import annotations

__all__ = ["probe_plan"]
