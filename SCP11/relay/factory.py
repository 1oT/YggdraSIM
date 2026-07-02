# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay session factory: constructs the PC/SC transport, provider, and crypto-engine."""
try:
    from ..factory import *
except ImportError:
    if __package__:
        raise
    from SCP11.factory import *
