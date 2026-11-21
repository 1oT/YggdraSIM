# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""IPAd declaration of a card session: TERMINAL CAPABILITY ahead of the first application selection.

GSMA SGP.32 v1.3 §3.8.2 has the eUICC enable the ES10 functions only for an
IoT Device that declared IPAd support, and ETSI TS 102 221 v18.4 §11.1.19.2.4
places the declaration in a new card session before the first application
selection. A reset starts a new card session, which has heard nothing. The
sessions that drive ES10 on a card channel of their own declare through here,
so a card session gets the command once whichever of them reaches the card
first.
"""

from __future__ import annotations

from typing import Any

from SCP11.shared.eim_configuration_data import TERMINAL_CAPABILITY_IPAD

# The attribute a channel carries while its card session holds the
# declaration. PcscApduChannel defines it and clears it in reset(); any other
# channel object gets it set here.
DECLARED_ATTRIBUTE = "ipad_declared"


def declare_ipad(channel: Any, log_name: str) -> str:
    """Send the IPAd declaration unless this card session has it; return a note when the card refused it.

    A card that takes no TERMINAL CAPABILITY is not asked again in the same
    card session and does not stop the caller; the note names what follows.
    An empty string means there is nothing to tell the operator.
    """
    if channel is None or getattr(channel, DECLARED_ATTRIBUTE, False):
        return ""
    note = ""
    try:
        channel.send(TERMINAL_CAPABILITY_IPAD, log_name)
    except (OSError, RuntimeError, ValueError) as error:
        note = (
            f"TERMINAL CAPABILITY not taken ({error}); a card that gates ES10 on the IPAd declaration "
            "(SGP.32 v1.3 §3.8.2) answers 6985 from here on"
        )
    setattr(channel, DECLARED_ATTRIBUTE, True)
    return note


def forget_ipad_declaration(channel: Any) -> None:
    """Mark a new card session on *channel*: the next declare_ipad sends again."""
    if channel is not None:
        setattr(channel, DECLARED_ATTRIBUTE, False)
