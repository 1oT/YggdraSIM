# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay ES9+ client: HTTP/JSON transport for remote ES9+ and eIM endpoints."""
try:
    from ..es9_client import *
except ImportError:
    from SCP11.es9_client import *
