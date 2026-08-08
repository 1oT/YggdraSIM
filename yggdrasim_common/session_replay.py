# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Re-drive a recorded C-APDU stream and diff the responses.

``session_recording`` captures C-APDU / R-APDU pairs and ``session_diff``
compares two captures. This joins them: it replays the commands from a
recording against a live transport and reports where the new responses
differ from the recorded ones.

Only deterministic sequences diff meaningfully. A card-generated
challenge, a counter, a session key, and a transaction id differ on every
run by design, so a comparison that flags them is noise. A
:class:`VariancePolicy` declares which parts are allowed to move; a
response is a regression only when it differs outside that allowance.

The default policy covers the commands whose responses are
non-deterministic on any card: GET CHALLENGE, and the ES10b/ES10c
authenticate and prepare-download families that embed a fresh euICC
challenge or signature.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from collections.abc import Callable, Sequence

from yggdrasim_common.session_diff import (
    Exchange,
    load_recording,
)

__all__ = [
    "ReplayTransport",
    "VariancePolicy",
    "ReplayDivergence",
    "ReplayReport",
    "DEFAULT_VARIANCE_POLICY",
    "STATUS_ONLY_POLICY",
    "SESSION_SCOPED_POLICY",
    "SESSION_SCOPED_TLV_TAGS",
    "replay_exchanges",
    "replay_recording",
    "format_report",
]


class ReplayTransport(Protocol):
    """Same shape the fuzzer uses, so transports are interchangeable."""

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        ...


# C-APDU header prefixes whose response body is card-generated and
# therefore differs every run. Matched case-insensitively against the
# start of the APDU hex.
_NON_DETERMINISTIC_PREFIXES: tuple[str, ...] = (
    "0084",      # ISO/IEC 7816-4 GET CHALLENGE
    "80E2",      # STORE DATA carrying a freshly signed payload
    "81E2",
    "80CAFF21",  # ES10b GetEUICCChallenge via GET DATA
)

#: BER-TLV tags whose values are session-scoped: euICC challenge,
#: transaction id, signatures, and derived keys. Not masked by
#: default -- masking hides real regressions too, so it is opt-in via
#: :data:`SESSION_SCOPED_POLICY` or a custom policy.
SESSION_SCOPED_TLV_TAGS: tuple[str, ...] = (
    "5F37",  # signature
    "80",    # transactionId in several ES10 responses
    "5A",    # otPK / ephemeral public key material
)


@dataclass(frozen=True)
class VariancePolicy:
    """Declares which response differences are expected rather than bugs."""

    ignore_response_for_prefixes: tuple[str, ...] = _NON_DETERMINISTIC_PREFIXES
    ignore_status_for_prefixes: tuple[str, ...] = ()
    masked_tlv_tags: tuple[str, ...] = ()
    compare_status_only: bool = False
    custom_matcher: Callable[[Exchange, Exchange], bool] | None = None

    def response_is_compared(self, apdu_hex: str) -> bool:
        if self.compare_status_only:
            return False
        upper = str(apdu_hex or "").upper()
        return not any(upper.startswith(prefix.upper()) for prefix in self.ignore_response_for_prefixes)

    def status_is_compared(self, apdu_hex: str) -> bool:
        upper = str(apdu_hex or "").upper()
        return not any(upper.startswith(prefix.upper()) for prefix in self.ignore_status_for_prefixes)


DEFAULT_VARIANCE_POLICY = VariancePolicy()

#: Compares status words only. The right starting point for a session
#: that carries a secure channel, where every response body is wrapped
#: under a session key that changes per run.
STATUS_ONLY_POLICY = VariancePolicy(compare_status_only=True)

#: Compares bodies but blanks the session-scoped TLVs first. Use when a
#: recording carries transaction ids or signatures that change per run
#: but the surrounding structure should still be compared.
SESSION_SCOPED_POLICY = VariancePolicy(masked_tlv_tags=SESSION_SCOPED_TLV_TAGS)


@dataclass(frozen=True)
class ReplayDivergence:
    """One place the replayed response left the recorded allowance."""

    index: int
    apdu_hex: str
    field: str
    recorded: str
    replayed: str

    def describe(self, *, preview: int = 32) -> str:
        def clip(value: str) -> str:
            text = value or "(empty)"
            return text if len(text) <= preview else text[:preview] + "..."

        return (
            f"  #{self.index} {clip(self.apdu_hex)}  {self.field} differs\n"
            f"      recorded: {clip(self.recorded)}\n"
            f"      replayed: {clip(self.replayed)}"
        )


@dataclass
class ReplayReport:
    """Outcome of replaying one recording."""

    source: str = ""
    replayed_count: int = 0
    transmit_errors: int = 0
    divergences: list[ReplayDivergence] = field(default_factory=list)
    tolerated: list[ReplayDivergence] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        return len(self.divergences) == 0 and self.transmit_errors == 0


def _mask_tlv_values(data_hex: str, tags: Sequence[str]) -> str:
    """Blank the value of each named top-level TLV before comparison."""
    if len(tags) == 0 or len(data_hex) == 0:
        return data_hex
    try:
        raw = bytes.fromhex(data_hex)
    except ValueError:
        return data_hex
    wanted = {tag.upper() for tag in tags}
    out = bytearray(raw)
    offset = 0
    while offset < len(raw):
        tag_start = offset
        if offset >= len(raw):
            break
        first = raw[offset]
        offset += 1
        if (first & 0x1F) == 0x1F:
            while offset < len(raw) and (raw[offset] & 0x80) != 0:
                offset += 1
            offset += 1
        if offset >= len(raw):
            break
        tag_hex = raw[tag_start:offset].hex().upper()
        length_byte = raw[offset]
        offset += 1
        if (length_byte & 0x80) != 0:
            count = length_byte & 0x7F
            if count == 0 or count > 4 or offset + count > len(raw):
                break
            value_length = int.from_bytes(raw[offset : offset + count], "big")
            offset += count
        else:
            value_length = length_byte
        value_end = offset + value_length
        if value_end > len(raw):
            break
        if tag_hex in wanted:
            for position in range(offset, value_end):
                out[position] = 0x00
        offset = value_end
    return out.hex().upper()


def replay_exchanges(
    recorded: Sequence[Exchange],
    transport: ReplayTransport,
    *,
    policy: VariancePolicy = DEFAULT_VARIANCE_POLICY,
    stop_on_divergence: bool = False,
) -> ReplayReport:
    """Send each recorded C-APDU and compare what comes back."""
    report = ReplayReport(replayed_count=0)
    for exchange in recorded:
        apdu_hex = str(exchange.apdu_hex or "").upper()
        if len(apdu_hex) == 0 or len(apdu_hex) % 2 != 0:
            continue
        try:
            command = bytes.fromhex(apdu_hex)
        except ValueError:
            continue
        try:
            data, status_word = transport.transmit(command)
        except Exception:  # noqa: BLE001 - a dead transport is a result, not a crash
            report.transmit_errors += 1
            if stop_on_divergence:
                break
            continue
        report.replayed_count += 1
        replayed = Exchange(
            index=exchange.index,
            apdu_hex=apdu_hex,
            data_hex=bytes(data).hex().upper(),
            status_hex=f"{int(status_word) & 0xFFFF:04X}",
            ok=(int(status_word) & 0xFFFF) in (0x9000, 0x9100),
        )

        if policy.custom_matcher is not None and policy.custom_matcher(exchange, replayed):
            continue

        found: list[ReplayDivergence] = []
        if exchange.status_hex.upper() != replayed.status_hex.upper():
            divergence = ReplayDivergence(
                index=exchange.index,
                apdu_hex=apdu_hex,
                field="status",
                recorded=exchange.status_hex.upper(),
                replayed=replayed.status_hex.upper(),
            )
            if policy.status_is_compared(apdu_hex):
                found.append(divergence)
            else:
                report.tolerated.append(divergence)

        recorded_data = _mask_tlv_values(exchange.data_hex.upper(), policy.masked_tlv_tags)
        replayed_data = _mask_tlv_values(replayed.data_hex.upper(), policy.masked_tlv_tags)
        if recorded_data != replayed_data:
            divergence = ReplayDivergence(
                index=exchange.index,
                apdu_hex=apdu_hex,
                field="response",
                recorded=recorded_data,
                replayed=replayed_data,
            )
            if policy.response_is_compared(apdu_hex):
                found.append(divergence)
            else:
                report.tolerated.append(divergence)

        report.divergences.extend(found)
        if stop_on_divergence and len(found) > 0:
            break
    return report


def replay_recording(
    path: str | Path,
    transport: ReplayTransport,
    *,
    policy: VariancePolicy = DEFAULT_VARIANCE_POLICY,
    stop_on_divergence: bool = False,
) -> ReplayReport:
    """Load a recording and replay it against ``transport``."""
    exchanges = load_recording(path)
    report = replay_exchanges(
        exchanges,
        transport,
        policy=policy,
        stop_on_divergence=stop_on_divergence,
    )
    report.source = str(path)
    return report


def format_report(report: ReplayReport, *, preview: int = 32) -> str:
    lines = [
        f"replayed {report.replayed_count} exchange(s) from {report.source or 'recording'}",
    ]
    if report.transmit_errors > 0:
        lines.append(f"transport errors: {report.transmit_errors}")
    if len(report.tolerated) > 0:
        lines.append(f"tolerated by policy: {len(report.tolerated)}")
    if report.matched:
        lines.append("no divergences")
        return "\n".join(lines)
    lines.append(f"divergences: {len(report.divergences)}")
    lines.extend(divergence.describe(preview=preview) for divergence in report.divergences)
    return "\n".join(lines)
