# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""ISD-R configuration loader: reads the JSON config that sets the simulated card identity (EID, CCSN, SM-DP+ address)."""
from __future__ import annotations

import json
import os

from SIMCARD.euicc_store import apply_euicc_state_payload
from SIMCARD.state import SimCardState


def load_isdr_config_into_state(path: str, state: SimCardState) -> bool:
    """Read the ISD-R config JSON and write OTA keys, AID, and TAR values into *state*."""
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        return False
    absolute_path = os.path.abspath(os.path.expanduser(normalized))
    if os.path.isfile(absolute_path) is False:
        return False
    try:
        with open(absolute_path, "r", encoding="utf-8") as input_file:
            payload = json.load(input_file)
    except (OSError, json.JSONDecodeError):
        return False
    if isinstance(payload, dict) is False:
        return False
    apply_euicc_state_payload(state, payload)
    return True
