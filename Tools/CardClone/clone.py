# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Chart a real card's behaviour and distil it into a behaviour profile.

Three stages:

``probe``
    Send the enumerated read-only plan to a card and record the answers.
    Nothing outside ``probe_plan.PROBE_PLAN`` is transmitted, and every
    step is re-checked against the risk classifier immediately before it
    goes out.

``distil``
    Replay the same plan against a stock simulator and keep only the
    steps where the two disagree. The profile is a difference, not a
    transcript: a maintainer can read twenty divergences and judge them,
    which is not true of a two-hundred-line dump that mostly repeats what
    the simulator already does.

``write``
    Emit JSON. Identity-bearing steps are dropped before this point, so
    an ICCID cannot reach the artefact.

The transport contract matches the fuzzer and the replay harness --
``transmit(apdu) -> (data, sw)`` -- so a PC/SC reader, the Card Bridge,
the HIL bridge, or the simulator itself all work unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from SIMCARD.behaviour_profile import BehaviourOverride, BehaviourProfile
from Tools.CardClone.probe_plan import (
    PROBE_PLAN,
    ProbeStep,
    assert_plan_is_read_only,
)
from yggdrasim_common.apdu_risk import classify_apdu

__all__ = [
    "CardTransport",
    "Observation",
    "probe_card",
    "distil_profile",
    "clone_card",
]


class CardTransport(Protocol):
    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        ...


@dataclass(frozen=True)
class Observation:
    """What one probe step produced on one card."""

    step: ProbeStep
    status_hex: str
    data_hex: str
    error: str = ""

    @property
    def ok(self) -> bool:
        return len(self.error) == 0


@dataclass
class CloneReport:
    """Outcome of a probe-and-distil run."""

    profile: BehaviourProfile = field(default_factory=BehaviourProfile)
    observed: int = 0
    transport_errors: int = 0
    identical_steps: int = 0
    excluded_identity_steps: int = 0

    def summary(self) -> str:
        lines = [
            f"probed {self.observed} step(s)",
            f"divergences recorded: {len(self.profile.overrides)}",
            f"identical to the simulator: {self.identical_steps}",
            f"excluded as identity-bearing: {self.excluded_identity_steps}",
        ]
        if self.transport_errors > 0:
            lines.append(f"transport errors: {self.transport_errors}")
        return "\n".join(lines)


def probe_card(
    transport: CardTransport,
    *,
    steps: tuple[ProbeStep, ...] = PROBE_PLAN,
) -> list[Observation]:
    """Run the probe plan and return one observation per step.

    Raises :class:`UnsafeProbeStepError` before transmitting anything if
    the plan carries a step that is not read-only.
    """
    assert_plan_is_read_only(steps)

    observations: list[Observation] = []
    for step in steps:
        payload = step.apdu
        # Re-check at the point of transmission. The plan-level assertion
        # above covers the shipped list; this covers a caller that built
        # its own tuple and slipped past it.
        if len(payload) >= 4 and not step.reserved_instruction:
            verdict = classify_apdu(payload)
            if verdict["risk"] != "read":
                raise RuntimeError(
                    f"refusing to send {step.step_id}: {verdict['name']} is "
                    f"classified {verdict['risk']}"
                )
        try:
            data, status_word = transport.transmit(payload)
        except Exception as error:  # noqa: BLE001 - a dead card is a result
            observations.append(
                Observation(step=step, status_hex="", data_hex="", error=str(error))
            )
            continue
        observations.append(
            Observation(
                step=step,
                status_hex=f"{int(status_word) & 0xFFFF:04X}",
                data_hex=bytes(data).hex().upper(),
            )
        )
    return observations


def _simulator_transport():
    """Transport bound to a stock in-process simulator."""
    from SIMCARD.connection import get_shared_engine

    engine = get_shared_engine()

    class _SimTransport:
        def transmit(self, apdu: bytes) -> tuple[bytes, int]:
            data, sw1, sw2 = engine.transmit(bytes(apdu))
            return bytes(data), (int(sw1) << 8) | int(sw2)

    return _SimTransport()


def distil_profile(
    observations: list[Observation],
    *,
    baseline: list[Observation] | None = None,
    name: str = "",
    notes: str = "",
    atr_hex: str = "",
    source_card: str = "",
) -> CloneReport:
    """Keep only the steps where the card and the simulator disagree."""
    if baseline is None:
        baseline = probe_card(_simulator_transport())
    reference = {item.step.step_id: item for item in baseline}

    report = CloneReport(
        profile=BehaviourProfile(
            name=name,
            notes=notes,
            atr_hex=atr_hex.upper(),
            source_card=source_card,
        )
    )

    for observation in observations:
        step = observation.step
        report.observed += 1
        if not observation.ok:
            report.transport_errors += 1
            continue
        if step.identity_bearing:
            # Charted for the operator's benefit, never written: this is
            # the boundary that keeps a behaviour profile pairable with
            # any SAIP profile.
            report.excluded_identity_steps += 1
            continue

        stock = reference.get(step.step_id)
        if stock is not None and stock.ok:
            status_matches = stock.status_hex == observation.status_hex
            data_matches = step.status_only or stock.data_hex == observation.data_hex
            if status_matches and data_matches:
                report.identical_steps += 1
                continue

        report.profile.overrides[step.apdu_hex.upper()] = BehaviourOverride(
            apdu_hex=step.apdu_hex.upper(),
            status_hex=observation.status_hex,
            # A status-only step's body is not reproducible, so record the
            # status word alone rather than freezing one sample.
            data_hex="" if step.status_only else observation.data_hex,
            step_id=step.step_id,
            charts=step.charts,
        )
    return report


def clone_card(
    transport: CardTransport,
    *,
    name: str = "",
    notes: str = "",
    atr_hex: str = "",
    source_card: str = "",
    steps: tuple[ProbeStep, ...] = PROBE_PLAN,
) -> CloneReport:
    """Probe a card and distil the result in one call."""
    observations = probe_card(transport, steps=steps)
    baseline = probe_card(_simulator_transport(), steps=steps)
    return distil_profile(
        observations,
        baseline=baseline,
        name=name,
        notes=notes,
        atr_hex=atr_hex,
        source_card=source_card,
    )
