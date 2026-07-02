# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""YggdraSIM Card Bridge — standalone PC/SC relay daemon.

The Card Bridge publishes a locally-attached PC/SC reader over a
loopback HTTP service that speaks the same protocol as
``Tools/HilBridge/apdu_relay``. The intended deployment is:

* The bridge runs on the machine the card reader is plugged into.
* Bridge binds to ``127.0.0.1`` only — never the network.
* Remote consumers reach the bridge through an SSH ``LocalForward``
  (``ssh -L 8642:127.0.0.1:8642 <pc-host>``).
* SSH supplies stream encryption, integrity, and peer authentication
  via the operator's existing ``~/.ssh/authorized_keys``.
* A bearer token printed once on bridge start adds belt-and-braces
  authorisation for the (rare) multi-user PC scenario where another
  local account could also reach loopback.

See ``guides/CARD_BRIDGE_GUIDE.md`` for the operator workflow.
"""

from __future__ import annotations

from .server import CardBridgeConfig, CardBridgeError, run_card_bridge

__all__ = [
    "CardBridgeConfig",
    "CardBridgeError",
    "run_card_bridge",
]
