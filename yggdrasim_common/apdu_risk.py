# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Single source of truth for what an APDU does to a card.

The MCP server gates card access on this, and the card-behaviour prober
refuses to send anything this module does not call ``read``. Keeping one
table means a command judged dangerous in one place cannot be judged safe
in the other.

Risk classes:

``read``
    Returns information. Leaves the card as it found it.
``write``
    Mutates the card, normally recoverable by writing again.
``destructive``
    Irreversible on real hardware. A consumed retry counter never comes
    back, a blocked security domain never unblocks, a terminated card
    never wakes up.
``unknown``
    Too short to classify.

An instruction the table has not seen is reported as ``write``: absence
from the table is not evidence of safety.
"""

from __future__ import annotations

from typing import Any

__all__ = ["APDU_RISK", "classify_apdu", "is_read_only"]


# INS -> (risk class, name).
APDU_RISK: dict[int, tuple[str, str]] = {
    0x20: ("destructive", "VERIFY (consumes a PIN retry)"),
    0x24: ("destructive", "CHANGE REFERENCE DATA"),
    0x26: ("destructive", "DISABLE VERIFICATION REQUIREMENT"),
    0x28: ("destructive", "ENABLE VERIFICATION REQUIREMENT"),
    0x2C: ("destructive", "RESET RETRY COUNTER (consumes a PUK retry)"),
    # ISO/IEC 7816-4 §7.5.4. A wrong cryptogram counts against the
    # security domain's try limit, and GlobalPlatform card policy commonly
    # blocks the domain permanently once it is exhausted. It reads like an
    # authentication step rather than a mutation, which is exactly why it
    # has to be named here.
    0x82: ("destructive", "EXTERNAL AUTHENTICATE (can permanently block a security domain)"),
    # ETSI TS 102 221 §11.1.18. The card stops servicing everything but
    # STATUS, permanently.
    0xFE: ("destructive", "TERMINATE CARD USAGE (bricks the card)"),
    0xD8: ("destructive", "PUT KEY"),
    0xE4: ("destructive", "DELETE"),
    0xF0: ("destructive", "SET STATUS (can lock or terminate the card)"),
    0x04: ("destructive", "DEACTIVATE FILE"),
    0xD6: ("write", "UPDATE BINARY"),
    0xDC: ("write", "UPDATE RECORD"),
    0xE0: ("write", "CREATE FILE"),
    0xE2: ("write", "STORE DATA"),
    0xE6: ("write", "INSTALL"),
    0xE8: ("write", "LOAD"),
    0x44: ("write", "ACTIVATE FILE"),
    0x88: ("write", "INTERNAL AUTHENTICATE (runs the AKA algorithm, steps SQN)"),
    # MANAGE CHANNEL opens consume a finite channel pool and are only
    # recovered by an explicit close, so an unbalanced probe exhausts them.
    0x70: ("write", "MANAGE CHANNEL"),
    0xA4: ("read", "SELECT"),
    0xB0: ("read", "READ BINARY"),
    0xB2: ("read", "READ RECORD"),
    0xC0: ("read", "GET RESPONSE"),
    0xCA: ("read", "GET DATA"),
    0xF2: ("read", "GET STATUS"),
    0x84: ("read", "GET CHALLENGE"),
    0xB1: ("read", "READ BINARY (odd instruction)"),
    0xB3: ("read", "READ RECORD (odd instruction)"),
}


def classify_apdu(payload: bytes) -> dict[str, Any]:
    """Classify one command APDU as read, write, or destructive.

    Unknown instructions are reported as ``write`` rather than ``read``: an
    instruction this table has not seen is not evidence that it is safe.
    """

    if len(payload) < 2:
        return {"risk": "unknown", "ins": "", "name": "APDU too short to classify"}
    ins = payload[1]
    risk, name = APDU_RISK.get(ins, ("write", "unrecognised instruction"))
    # STORE DATA carries ES10b profile operations, including memory reset and
    # profile deletion, so its payload decides the real risk.
    if ins == 0xE2 and b"\xBF\x34" in payload[:16]:
        risk, name = "destructive", "STORE DATA (eUICC memory reset)"
    return {"risk": risk, "ins": f"{ins:02X}", "name": name}


def is_read_only(payload: bytes) -> bool:
    """True only when the APDU is positively known to leave the card alone."""
    return classify_apdu(payload)["risk"] == "read"
