# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 shared pySim support: codec and OTA keyset wrappers shared across live, relay, and test variants."""
try:
    from ..pysim_support import *
except ImportError:
    from SCP11.pysim_support import *
