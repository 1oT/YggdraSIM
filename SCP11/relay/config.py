# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay configuration: loads relay server address, cert paths, and session policy for the relay mode."""
try:
    from ..config import SGPConfig
except ImportError:
    from SCP11.config import SGPConfig

__all__ = ["SGPConfig"]
