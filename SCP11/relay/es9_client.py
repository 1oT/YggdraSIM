# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay ES9+ client: HTTP/JSON transport forwarded through the HIL-Bridge relay socket."""
try:
    from ..es9_client import *
except ImportError:
    from SCP11.es9_client import *
