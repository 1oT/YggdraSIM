# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay orchestrator: sequences ES2+ / ES9+ / ES8+ calls over the HIL-Bridge relay channel."""
try:
    from ..orchestrator import SGP22Orchestrator
except ImportError:
    from SCP11.orchestrator import SGP22Orchestrator

__all__ = ["SGP22Orchestrator"]
