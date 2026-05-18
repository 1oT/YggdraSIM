# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay operator console: REPL exposing ES2+/ES9+ commands routed through the relay transport."""
try:
    from ..console import SCP11Console
except ImportError:
    from SCP11.console import SCP11Console

__all__ = ["SCP11Console"]
