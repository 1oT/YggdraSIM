"""HTTP routes for the GUI server.

Each submodule owns a FastAPI ``APIRouter`` mounted under a subsystem
prefix. Submodules are imported from :mod:`.app` so the FastAPI import
cost stays concentrated at the one entry point.
"""

from __future__ import annotations

__all__: list[str] = []
