# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay orchestrator: sequences ES2+ / ES9+ / ES8+ calls over direct PC/SC."""
try:
    from ..orchestrator import SGP22Orchestrator
except ImportError:
    from SCP11.orchestrator import SGP22Orchestrator

__all__ = ["SGP22Orchestrator"]
