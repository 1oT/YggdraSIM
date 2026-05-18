# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay session factory: constructs the relay transport, provider, and crypto-engine."""
try:
    from ..factory import *
except ImportError:
    from SCP11.factory import *
