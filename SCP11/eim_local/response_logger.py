# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""eIM response logger: writes structured ES2+ response payloads to a JSONL audit trail."""
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any


class EimResponseLogger:
    """Append-only JSONL logger for eIM package and flow responses."""

    def __init__(self, log_file_path: str):
        self.log_file_path = str(log_file_path).strip()
        self._lock = threading.Lock()

    def append_event(self, event: dict[str, Any]) -> None:
        """Append one ES2+ response event record to the JSONL response log file."""
        if len(self.log_file_path) == 0:
            return
        directory = os.path.dirname(self.log_file_path)
        if len(directory) > 0:
            os.makedirs(directory, exist_ok=True)
        payload = dict(event)
        if len(str(payload.get("logged_at_utc", "") or "").strip()) == 0:
            payload["logged_at_utc"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        with self._lock:
            with open(self.log_file_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True))
                handle.write("\n")
