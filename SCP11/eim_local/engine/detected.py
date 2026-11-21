# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""EIDs that YggdraSIM reads from a card, registered with the Local eIM.

Each surface that reads an EID (the eSIM Management console and its
orchestrator, the eIM-local and local-access shells, the SCP03 admin shell)
hands it to ``register_detected_eid``, so the Local eIM knows the eUICC before
an operation is queued for it and no EUICC ADD is needed. The engine setting
``learn_unknown_eids`` (on by default) turns this off together with the
registration of an unknown EID that polls the eIM over ESipa. The engine is
imported on the first call, so a caller's import stays light.
"""

from __future__ import annotations

import sqlite3

# A store that cannot be opened or written never stops the card flow that read the EID.
_STORE_FAILURES = (OSError, sqlite3.Error, RuntimeError)


def register_detected_eid(eid: str, source: str, *, emit=print) -> bool:
    """Register *eid* with the Local eIM when it is new; True when a record was created.

    *source* names the surface that read it and is kept on the record. A
    malformed EID or a store that cannot be written is reported through
    *emit* and returns False.
    """
    text = str(eid or "").strip()
    if len(text) == 0:
        return False
    from SCP11.eim_local.engine.service import LocalEim

    try:
        record = LocalEim().note_detected_eid(text, source=source)
    except ValueError as error:
        emit(f"[*] Local eIM: EID {text!r} not registered: {error}")
        return False
    except _STORE_FAILURES as error:
        emit(f"[*] Local eIM: EID {text} not registered, the eIM store is unavailable ({error}).")
        return False
    if record is None:
        return False
    emit(f"[*] Local eIM: EID {record.eid} registered (first seen by {source}).")
    return True


__all__ = ["register_detected_eid"]
