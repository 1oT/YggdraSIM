# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 shared transport: BPP STORE-DATA framing and direct PC/SC APDU dispatch."""
try:
    from ..transport import *
except ImportError:
    from SCP11.transport import *
