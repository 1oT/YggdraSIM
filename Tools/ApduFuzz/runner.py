"""
Fuzzer runner — drives mutation + replay against a transport.

The runner is transport-agnostic. It depends on a small callable
contract rather than on :mod:`smartcard` or the HIL bridge directly,
so unit tests can supply a fake transport without any hardware.

Transport contract::

    class TransportProtocol(Protocol):
        def probe_card_identity(self) -> tuple[str, str]:
            '''Return (iccid, imsi) for the currently inserted card.'''

        def transmit(self, apdu: bytes) -> tuple[bytes, int]:
            '''Send a command APDU, return (response_data, sw).'''

        def close(self) -> None:
            '''Release the card handle.'''

The runner does not try to "heal" a dead card. The moment we see a
hard error (disconnect, unrecoverable SW = ``0x6F00``, etc.) we dump
the offending APDU and halt, so the operator can inspect the crash
rather than chaining further mutations against a crippled card.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from .corpus import Corpus
from .mutators import MutationResult, MUTATORS, choose_mutator
from .safety import (
    FuzzerSafetyError,
    SafetyConfig,
    assert_safety_gate,
    create_run_dir,
    dump_crash,
    dump_run_manifest,
)


_LOGGER = logging.getLogger(__name__)


CRASH_SW_VALUES: frozenset[int] = frozenset({0x6F00, 0x6F01, 0x6FFF})


class CardTransport(Protocol):
    def probe_card_identity(self) -> tuple[str, str]:
        ...

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        ...

    def close(self) -> None:
        ...


@dataclass
class RunStats:
    """Aggregate counters for a single fuzzer run."""

    sent: int = 0
    crashes: int = 0
    halt_reason: str = ""
    crash_records: list[Path] = field(default_factory=list)

    def record_crash(self, dump_path: Path, *, reason: str = "") -> None:
        self.crashes += 1
        self.crash_records.append(dump_path)
        if len(self.halt_reason) == 0 and len(reason) > 0:
            self.halt_reason = reason


def _is_crash_response(sw: int) -> bool:
    return sw in CRASH_SW_VALUES


class FuzzerRunner:
    """Orchestrate mutation + replay + crash-dump for a single session."""

    def __init__(
        self,
        *,
        config: SafetyConfig,
        corpus: Corpus,
        transport: CardTransport,
        seed: int = 0xDEAD_BEEF,
        enabled_mutators: tuple[str, ...] | None = None,
        max_apdus: int | None = None,
        inter_command_delay_seconds: float = 0.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._corpus = corpus
        self._transport = transport
        self._rng = random.Random(seed)
        self._enabled_mutators = (
            tuple(sorted(enabled_mutators))
            if enabled_mutators is not None
            else tuple(sorted(MUTATORS.keys()))
        )
        base_cap = max_apdus if max_apdus is not None else config.max_apdus_per_run
        self._max_apdus = min(base_cap, config.max_apdus_per_run)
        self._inter_command_delay_seconds = max(0.0, float(inter_command_delay_seconds))
        self._sleep = sleep
        self._seed = int(seed)

    def execute(self) -> RunStats:
        stats = RunStats()
        iccid, imsi = self._transport.probe_card_identity()
        try:
            assert_safety_gate(self._config, probed_iccid=iccid, probed_imsi=imsi)
        except FuzzerSafetyError:
            self._transport.close()
            raise
        run_dir = create_run_dir(self._config, tag=self._corpus.session_id)
        dump_run_manifest(
            run_dir,
            config=self._config,
            corpus_path=self._corpus.source_path,
            seed=self._seed,
            mutator_names=self._enabled_mutators,
        )
        try:
            self._run_loop(run_dir, stats)
        finally:
            self._transport.close()
        return stats

    def _run_loop(self, run_dir: Path, stats: RunStats) -> None:
        if len(self._corpus.entries) == 0:
            stats.halt_reason = "empty_corpus"
            return
        for sequence_index in range(self._max_apdus):
            entry = self._rng.choice(self._corpus.entries)
            try:
                original_bytes = entry.command_bytes()
            except ValueError as parse_error:
                _LOGGER.warning(
                    "skipping malformed corpus entry index=%s: %s",
                    entry.index,
                    parse_error,
                )
                continue
            mutator = choose_mutator(self._rng, enabled_names=self._enabled_mutators)
            mutation: MutationResult = mutator(original_bytes, self._rng)
            try:
                response_bytes, sw = self._transport.transmit(mutation.mutated_apdu)
            except Exception as transport_error:
                dump_path = dump_crash(
                    run_dir,
                    sequence_index=sequence_index,
                    mutation_description=mutation.description,
                    original_apdu=original_bytes,
                    mutated_apdu=mutation.mutated_apdu,
                    response_bytes=b"",
                    sw=0,
                    notes=f"transport_exception: {transport_error.__class__.__name__}: {transport_error}",
                )
                stats.record_crash(dump_path, reason="transport_exception")
                return
            stats.sent += 1
            if _is_crash_response(sw) is True:
                dump_path = dump_crash(
                    run_dir,
                    sequence_index=sequence_index,
                    mutation_description=mutation.description,
                    original_apdu=original_bytes,
                    mutated_apdu=mutation.mutated_apdu,
                    response_bytes=response_bytes,
                    sw=sw,
                    notes="crash_sw",
                )
                stats.record_crash(dump_path, reason="crash_sw")
                return
            if self._inter_command_delay_seconds > 0:
                self._sleep(self._inter_command_delay_seconds)
        stats.halt_reason = "max_apdus_reached"
