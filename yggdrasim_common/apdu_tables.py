# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Expected ISO 7816-4 case per instruction.

A SIMtrace SIM-APDU record concatenates the command APDU and the response
APDU into one GSMTAP frame, so anything decoding that frame has to work
out where the command ends. ISO 7816-4 alone leaves that ambiguous: a
body of ``05 AA BB CC DD EE`` reads equally well as case 3S with
``Lc = 5`` or as case 4S with ``Lc = 5`` and a trailing ``Le``.

Knowing the case an instruction normally uses collapses most of that
ambiguity. This table is a *hint*, never a gate -- an instruction absent
from it is decoded by structure alone, and a card that answers a listed
instruction in another case is still decoded correctly, just with lower
reported confidence. That is the difference between this table and the
instruction allowlist it replaces, which dropped every frame it did not
recognise.

Values are the case names ISO 7816-4 uses: ``"1"``, ``"2S"``, ``"3S"``,
``"4S"``, ``"2E"``, ``"3E"``, ``"4E"``. Keys are either a bare
instruction byte or a ``(CLA, INS)`` pair when the class decides; the
pair is consulted first.
"""

from __future__ import annotations

__all__ = [
    "APDU_CASE_HINTS",
    "APDU_REQUIRES_DATA",
    "case_hint_for",
    "requires_data",
]


#: ``(CLA, INS)`` first, then a bare ``INS``. See :func:`case_hint_for`.
APDU_CASE_HINTS: dict[int | tuple[int, int], str] = {
    # --- ISO/IEC 7816-4 and ETSI TS 102 221 file access ---
    0xA4: "4S",  # SELECT returns an FCP/FCI template
    0xB0: "2S",  # READ BINARY
    0xB2: "2S",  # READ RECORD
    0xB1: "4S",  # READ BINARY, odd instruction (offset in the data field)
    0xB3: "4S",  # READ RECORD, odd instruction
    0xC0: "2S",  # GET RESPONSE
    0xD6: "3S",  # UPDATE BINARY
    0xDC: "3S",  # UPDATE RECORD
    0xD7: "3S",  # UPDATE BINARY, odd instruction
    0xDD: "3S",  # UPDATE RECORD, odd instruction
    0x32: "3S",  # INCREASE
    0xCB: "4S",  # GET DATA, odd instruction
    0xCA: "2S",  # GET DATA
    0xDA: "3S",  # PUT DATA
    # --- PIN and key management (ETSI TS 102 221 clause 11.1.9 onward) ---
    0x20: "3S",  # VERIFY PIN
    0x24: "3S",  # CHANGE PIN
    0x26: "3S",  # DISABLE PIN
    0x28: "3S",  # ENABLE PIN
    0x2C: "3S",  # UNBLOCK PIN
    # --- Channel and authentication ---
    0x70: "2S",  # MANAGE CHANNEL: open returns the allocated channel
    0x84: "2S",  # GET CHALLENGE
    0x88: "4S",  # INTERNAL AUTHENTICATE / AUTHENTICATE
    0x89: "4S",  # AUTHENTICATE, odd instruction
    0xFA: "1",   # SLEEP (deprecated, no body either way)
    0xFE: "1",   # TERMINATE CARD USAGE
    0x44: "1",   # ACTIVATE FILE
    0x04: "1",   # DEACTIVATE FILE
    # --- ETSI TS 102 223 card application toolkit ---
    (0x80, 0x10): "3S",  # TERMINAL PROFILE
    (0x80, 0x12): "2S",  # FETCH
    (0x80, 0x14): "3S",  # TERMINAL RESPONSE
    (0x80, 0xC2): "4S",  # ENVELOPE
    (0x80, 0xAA): "3S",  # TERMINAL CAPABILITY
    (0x80, 0x76): "4S",  # SUSPEND UICC
    (0x80, 0x78): "4S",  # GET IDENTITY (3GPP TS 31.101)
    # --- ETSI TS 102 222 administrative commands ---
    (0x00, 0xE0): "3S",  # CREATE FILE
    (0x00, 0xE4): "3S",  # DELETE FILE
    (0x00, 0xE6): "3S",  # TERMINATE DF
    (0x00, 0xE8): "3S",  # TERMINATE EF
    # --- GlobalPlatform Card Specification 2.3.1 ---
    (0x80, 0x50): "4S",  # INITIALIZE UPDATE
    (0x84, 0x50): "4S",
    (0x80, 0x82): "3S",  # EXTERNAL AUTHENTICATE
    (0x84, 0x82): "3S",
    (0x80, 0xD8): "3S",  # PUT KEY
    (0x84, 0xD8): "3S",
    (0x80, 0xE2): "3S",  # STORE DATA
    (0x84, 0xE2): "3S",
    (0x80, 0xE4): "4S",  # DELETE
    (0x84, 0xE4): "4S",
    (0x80, 0xE6): "4S",  # INSTALL
    (0x84, 0xE6): "4S",
    (0x80, 0xE8): "4S",  # LOAD
    (0x84, 0xE8): "4S",
    (0x80, 0xF0): "3S",  # SET STATUS
    (0x84, 0xF0): "3S",
    (0x80, 0xF2): "4S",  # GET STATUS
    (0x84, 0xF2): "4S",
    (0x80, 0xCA): "2S",  # GET DATA
    (0x84, 0xCA): "2S",
}


#: Instructions that are meaningless without a command data field.
#:
#: This resolves splits the case hint cannot. ``80 E6 02 00 11 <17
#: bytes> 90 00`` reads structurally as case 3S with a 17-byte INSTALL
#: body, or as case 2S with ``Le = 17`` and a 17-byte response -- the
#: bytes do not choose. But an INSTALL with no body does not exist:
#: GlobalPlatform clause 11.5 requires the AIDs and parameters. Knowing
#: which instructions cannot be case 1 or case 2 therefore breaks the
#: tie on grounds the specification actually gives.
#:
#: Only instructions whose body is mandatory in every variant belong
#: here. SELECT is excluded: ``SELECT`` by parent DF carries none.
APDU_REQUIRES_DATA: frozenset[int | tuple[int, int]] = frozenset(
    {
        0xD6,  # UPDATE BINARY
        0xDC,  # UPDATE RECORD
        0xD7,  # UPDATE BINARY, odd instruction
        0xDD,  # UPDATE RECORD, odd instruction
        0x32,  # INCREASE
        0xDA,  # PUT DATA
        0x20,  # VERIFY carries a PIN block (the no-body form queries retries)
        0x24,  # CHANGE REFERENCE DATA
        0x2C,  # RESET RETRY COUNTER
        (0x80, 0x10),  # TERMINAL PROFILE
        (0x80, 0x14),  # TERMINAL RESPONSE
        (0x80, 0xC2),  # ENVELOPE
        (0x80, 0xAA),  # TERMINAL CAPABILITY
        (0x80, 0x50),  # INITIALIZE UPDATE: host challenge
        (0x84, 0x50),
        (0x80, 0x82),  # EXTERNAL AUTHENTICATE: host cryptogram
        (0x84, 0x82),
        (0x80, 0xD8),  # PUT KEY
        (0x84, 0xD8),
        (0x80, 0xE2),  # STORE DATA
        (0x84, 0xE2),
        (0x80, 0xE4),  # DELETE
        (0x84, 0xE4),
        (0x80, 0xE6),  # INSTALL
        (0x84, 0xE6),
        (0x80, 0xE8),  # LOAD
        (0x84, 0xE8),
        (0x80, 0xF0),  # SET STATUS
        (0x84, 0xF0),
        (0x00, 0xE0),  # CREATE FILE
        (0x00, 0xE4),  # DELETE FILE
    }
)


def requires_data(cla: int, ins: int) -> bool:
    """True when this instruction always carries a command data field."""
    instruction = int(ins) & 0xFF
    class_byte = int(cla) & 0xFF
    for candidate in (class_byte, class_byte & 0xFC, class_byte & 0xF0):
        if (candidate, instruction) in APDU_REQUIRES_DATA:
            return True
    return instruction in APDU_REQUIRES_DATA


def case_hint_for(cla: int, ins: int) -> str:
    """Return the expected ISO 7816-4 case, or ``""`` when unknown.

    The ``(CLA, INS)`` entry wins over the bare instruction so that, for
    example, GlobalPlatform ``80 F2 GET STATUS`` is not confused with
    ETSI ``80 F2 STATUS``. Secure-messaging and logical-channel bits are
    masked out of the class before the pair is looked up, because
    ``84 E2`` and ``80 E2`` are the same command with and without a
    secure channel.
    """
    instruction = int(ins) & 0xFF
    class_byte = int(cla) & 0xFF
    for candidate in (class_byte, class_byte & 0xFC, class_byte & 0xF0):
        hint = APDU_CASE_HINTS.get((candidate, instruction))
        if hint is not None:
            return hint
    return APDU_CASE_HINTS.get(instruction, "")
