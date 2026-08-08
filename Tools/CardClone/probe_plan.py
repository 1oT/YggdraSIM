# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The fixed set of APDUs the card-behaviour prober is allowed to send.

Every step is enumerated with the behaviour it charts. The runner refuses
anything absent from this list and re-checks each entry against
``yggdrasim_common.apdu_risk`` before transmitting, so a step that later
turns out to mutate a card cannot ship by being overlooked in review.

A deny-list was rejected deliberately. The commands that destroy a card
do not look alike: VERIFY consumes a PIN retry, EXTERNAL AUTHENTICATE can
permanently block a security domain while reading like an auth step, and
STORE DATA is a write whose payload decides whether it is merely a write
or an eUICC memory reset. Enumerating what may be sent is the only form
of this that stays correct as the plan grows.

What the plan charts, in order:

* which files exist and answer
* the status-word dialect the card uses for "not found", "wrong length",
  "unsupported instruction", and "unsupported class"
* whether Le correction (``6C xx``) and response chaining (``61 xx``)
  are used
* how the card answers a malformed length

None of it reads secrets and none of it needs a PIN.
"""

from __future__ import annotations

from dataclasses import dataclass

from yggdrasim_common.apdu_risk import classify_apdu

__all__ = [
    "ProbeStep",
    "PROBE_PLAN",
    "assert_plan_is_read_only",
    "UnsafeProbeStepError",
]


class UnsafeProbeStepError(RuntimeError):
    """A probe step is not classified read-only and must not be sent."""


@dataclass(frozen=True)
class ProbeStep:
    """One probe command and the behaviour it is there to observe."""

    step_id: str
    apdu_hex: str
    charts: str
    #: Response bytes vary per call or per card identity, so the distiller
    #: compares the status word only.
    status_only: bool = False
    #: Response carries card identity (ICCID, IMSI, EID, certificates).
    #: Excluded from the behaviour profile entirely; that data belongs to
    #: the SAIP profile side of the pairing.
    identity_bearing: bool = False
    #: The instruction byte is one ISO/IEC 7816-3 reserves, so no card can
    #: dispatch it to a command. See ``_reserved_instruction``.
    reserved_instruction: bool = False

    @property
    def apdu(self) -> bytes:
        return bytes.fromhex(self.apdu_hex)


def _reserved_instruction(ins: int) -> bool:
    """True for instruction bytes ISO/IEC 7816-3 §12.2.1 reserves.

    Values of the form ``6X`` and ``9X`` are reserved for procedure and
    status bytes and are invalid as an INS. A compliant card cannot route
    them to any command, which makes them the safe way to ask "what do you
    answer for an instruction you do not implement" -- the alternative,
    guessing at an unassigned-but-legal INS, risks hitting a proprietary
    command on some card in the field.
    """
    return (ins & 0xF0) in (0x60, 0x90)


PROBE_PLAN: tuple[ProbeStep, ...] = (
    # -- file system reachability ---------------------------------------
    ProbeStep("select_mf", "00A40004023F00", "SELECT MF, case 3S; baseline FCP shape"),
    ProbeStep("select_mf_le", "00A40004023F0000", "SELECT MF, case 4S; whether Le is honoured"),
    ProbeStep("select_mf_p2_0c", "00A4000C023F00", "SELECT with P2=0C (no FCP requested)"),
    ProbeStep(
        "select_ef_iccid",
        "00A40004022FE2",
        "EF.ICCID reachable under the MF",
    ),
    ProbeStep(
        "select_ef_dir",
        "00A40004022F00",
        "EF.DIR reachable; application directory present",
    ),
    ProbeStep(
        "select_adf_usim",
        "00A4040410A0000000871002FFFFFFFF8907090000",
        "SELECT ADF.USIM by AID",
    ),
    ProbeStep(
        "select_isdr",
        "00A4040410A0000005591010FFFFFFFF8900000100",
        "SELECT ISD-R by AID; eUICC personality present",
    ),
    ProbeStep(
        "select_missing_file",
        "00A40004027F99",
        "status-word dialect for a file that does not exist",
    ),
    ProbeStep(
        "select_missing_aid",
        "00A404041099999999999999999999999999999999",
        "status-word dialect for an application that does not exist",
    ),
    # -- read behaviour --------------------------------------------------
    ProbeStep(
        "read_binary_iccid",
        "00B000000A",
        "READ BINARY after SELECT EF.ICCID",
        identity_bearing=True,
    ),
    ProbeStep(
        "read_binary_overlong_le",
        "00B00000FF",
        "whether an over-long Le is corrected with 6C xx or truncated",
        status_only=True,
    ),
    ProbeStep(
        "read_binary_offset_past_end",
        "00B07FFF01",
        "status-word dialect for an out-of-range offset",
    ),
    ProbeStep(
        "read_record_first",
        "00B2010400",
        "READ RECORD on the selected EF",
        status_only=True,
    ),
    ProbeStep(
        "read_record_invalid",
        "00B2FF0400",
        "status-word dialect for an invalid record number",
    ),
    # -- response handling ----------------------------------------------
    ProbeStep(
        "get_response_unsolicited",
        "00C0000010",
        "GET RESPONSE with nothing pending; chaining style",
    ),
    ProbeStep(
        "status_poll",
        "80F2000000",
        "GET STATUS / STATUS poll answer",
        status_only=True,
    ),
    # -- capability data -------------------------------------------------
    ProbeStep(
        "get_data_5c",
        "00CA005C00",
        "GET DATA tag list support",
        status_only=True,
    ),
    ProbeStep(
        "get_data_ci_list",
        "80CA00A900",
        "GP CI list / key information template",
        identity_bearing=True,
    ),
    # -- error dialect ---------------------------------------------------
    ProbeStep(
        "unsupported_ins",
        "0099000000",
        "status word for an instruction the card does not implement",
        reserved_instruction=True,
    ),
    ProbeStep(
        "unsupported_cla",
        "FCA4000401",
        "status word for a class the card does not support",
    ),
    ProbeStep(
        "truncated_lc",
        "00A40004F23F00",
        "status word when Lc over-claims the body (6700 vs 6F00)",
    ),
    ProbeStep(
        "runt_apdu",
        "00A400",
        "status word for an APDU shorter than four bytes",
    ),
)


def assert_plan_is_read_only(steps: tuple[ProbeStep, ...] = PROBE_PLAN) -> None:
    """Refuse a plan carrying anything not classified read-only.

    Called by the runner before the first transmission and asserted by the
    test suite, so a step added without checking its risk class fails in
    CI rather than on someone's card.
    """
    offenders: list[str] = []
    for step in steps:
        try:
            payload = step.apdu
        except ValueError:
            offenders.append(f"{step.step_id}: apdu_hex is not valid hex")
            continue
        # A runt APDU is deliberately malformed and cannot be classified by
        # instruction byte; it is safe because it is rejected before dispatch.
        if len(payload) < 4:
            continue
        if step.reserved_instruction:
            if not _reserved_instruction(payload[1]):
                offenders.append(
                    f"{step.step_id}: declares reserved_instruction but INS "
                    f"{payload[1]:02X} is not in the ISO 7816-3 6X/9X range"
                )
            continue
        verdict = classify_apdu(payload)
        if verdict["risk"] != "read":
            offenders.append(
                f"{step.step_id}: {verdict['name']} is classified {verdict['risk']}"
            )
    if len(offenders) > 0:
        raise UnsafeProbeStepError(
            "probe plan contains steps that are not read-only:\n  "
            + "\n  ".join(offenders)
        )
