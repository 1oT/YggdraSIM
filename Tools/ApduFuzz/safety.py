"""
Safety gate for the APDU mutation fuzzer.

Fuzzing a physical eUICC can permanently brick the card — some vendor
OS images refuse to re-enter the post-INSTALL secure channel if a
reader disconnect happens mid-session, others panic on BER-TLV length
mismatches and lock the ISD-R. This module exists to make sure nobody
runs the fuzzer by accident.

Safety layers enforced here:

1. ``--i-mean-it`` opt-in token. Without it, :func:`assert_safety_gate`
   raises :class:`FuzzerSafetyError`.
2. ICCID or IMSI whitelist. The operator must explicitly declare which
   card identifier is "allowed to be fried". The fuzzer compares the
   declared value against the card's pre-run probe before any
   mutated APDU is transmitted.
3. Crash-dump directory. Every run writes the mutated APDU, the
   response bytes (if any), and the full corpus seed to
   ``reports/fuzzer/<timestamp>/``. This is mandatory — without
   per-run forensic records we cannot reproduce or audit failures.

This module is pure and has no transport dependencies.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


class FuzzerSafetyError(RuntimeError):
    """Raised whenever a safety gate refuses the fuzzer invocation."""


@dataclass(frozen=True)
class SafetyConfig:
    """Declarative policy for a single fuzzer run.

    ``i_mean_it`` must be ``True``. It is a separate field (not
    defaulted) to force every caller to spell the intent out. Callers
    that accidentally construct ``SafetyConfig()`` will get a
    ``TypeError`` at construction.

    ``allowed_iccids`` and ``allowed_imsis`` are case-insensitive. The
    probe layer normalises card identifiers to uppercase hex before
    checking membership.

    ``crash_dump_root`` defaults to ``reports/fuzzer`` inside the
    caller-supplied workspace root. Each run adds a timestamped
    sub-directory via :meth:`create_run_dir`.
    """

    workspace_root: Path
    i_mean_it: bool
    allowed_iccids: frozenset[str] = field(default_factory=frozenset)
    allowed_imsis: frozenset[str] = field(default_factory=frozenset)
    crash_dump_root: Path | None = None
    max_apdus_per_run: int = 10_000

    def __post_init__(self) -> None:
        # The dataclass is frozen; no attribute assignment here. We
        # instead raise lazily from :func:`assert_safety_gate` so the
        # caller can construct a SafetyConfig for dry-run inspection.
        pass


def _normalise_card_token(value: str) -> str:
    return value.strip().upper().replace(" ", "").replace(":", "")


def build_allow_set(values: Iterable[str]) -> frozenset[str]:
    return frozenset(_normalise_card_token(v) for v in values if len(str(v).strip()) > 0)


def resolve_crash_dump_root(config: SafetyConfig) -> Path:
    if config.crash_dump_root is not None:
        return Path(config.crash_dump_root).expanduser().resolve()
    return (config.workspace_root / "reports" / "fuzzer").resolve()


def _utc_now() -> _dt.datetime:
    # Python 3.12+ deprecated utcnow(). Use timezone-aware UTC.
    try:
        return _dt.datetime.now(_dt.UTC)
    except AttributeError:
        return _dt.datetime.now(_dt.timezone.utc)


def _chmod_best_effort(path: Path, mode: int) -> None:
    """Tighten ``path`` permissions to ``mode``; ignore platforms that reject it.

    Fuzzer crash dumps contain mutated APDUs that may reveal card
    secrets (PIN retry counters, sensitive BER-TLV payloads). We keep
    the tree operator-private on POSIX (``0o700`` for dirs, ``0o600``
    for files). On platforms such as Windows the chmod call is a
    no-op; we still write the file but log a warning once.
    """
    if hasattr(os, "chmod") is False:
        return
    try:
        os.chmod(path, mode)
    except OSError:
        # Windows Python exposes ``os.chmod`` but its POSIX mode bits
        # are ignored beyond the read-only flag. Swallow the failure
        # rather than exploding the fuzzer run.
        pass


def create_run_dir(config: SafetyConfig, *, tag: str = "run") -> Path:
    root = resolve_crash_dump_root(config)
    root.mkdir(parents=True, exist_ok=True)
    _chmod_best_effort(root, 0o700)
    timestamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
    run_dir = root / f"{timestamp}-{tag}"
    run_dir.mkdir(parents=True, exist_ok=True)
    _chmod_best_effort(run_dir, 0o700)
    return run_dir


def assert_safety_gate(
    config: SafetyConfig,
    *,
    probed_iccid: str = "",
    probed_imsi: str = "",
) -> None:
    """Raise :class:`FuzzerSafetyError` if the run must not proceed."""
    if config.i_mean_it is False:
        raise FuzzerSafetyError(
            "Refusing to fuzz without --i-mean-it. This tool can brick "
            "cards; opt in explicitly."
        )
    if len(config.allowed_iccids) == 0 and len(config.allowed_imsis) == 0:
        raise FuzzerSafetyError(
            "Refusing to fuzz without at least one allowed ICCID or IMSI. "
            "Pass --allow-iccid / --allow-imsi."
        )
    probed_iccid = _normalise_card_token(probed_iccid)
    probed_imsi = _normalise_card_token(probed_imsi)
    if len(probed_iccid) == 0 and len(probed_imsi) == 0:
        raise FuzzerSafetyError(
            "Card probe returned neither ICCID nor IMSI. Refusing to "
            "continue without a verifiable card identity."
        )
    iccid_ok = len(probed_iccid) > 0 and probed_iccid in config.allowed_iccids
    imsi_ok = len(probed_imsi) > 0 and probed_imsi in config.allowed_imsis
    if iccid_ok is False and imsi_ok is False:
        raise FuzzerSafetyError(
            f"Probed card ICCID={probed_iccid or 'unknown'} "
            f"IMSI={probed_imsi or 'unknown'} is not in the allow-list. "
            "Add it with --allow-iccid / --allow-imsi only if you are "
            "absolutely certain you want to fuzz this card."
        )


def dump_crash(
    run_dir: Path,
    *,
    sequence_index: int,
    mutation_description: str,
    original_apdu: bytes,
    mutated_apdu: bytes,
    response_bytes: bytes,
    sw: int,
    notes: str = "",
) -> Path:
    """Write a crash-dump record to ``run_dir`` and return its path.

    The filename embeds the sequence index and the mutation description
    so an operator grepping through a crash-dump tree can reconstruct
    the reproducer trivially::

        000042-length_mangle@lc=23->drift+1=24.json
    """
    safe_description = (
        mutation_description.replace("/", "_")
        .replace(" ", "_")
        .replace("\\", "_")
        .replace(":", "_")
    )
    filename = f"{sequence_index:06d}-{safe_description}.json"
    target = run_dir / filename
    record = {
        "sequence_index": sequence_index,
        "mutation": mutation_description,
        "original_apdu_hex": original_apdu.hex().upper(),
        "mutated_apdu_hex": mutated_apdu.hex().upper(),
        "response_hex": response_bytes.hex().upper(),
        "sw_hex": f"{sw:04X}",
        "notes": notes,
        "fingerprint": hashlib.sha256(mutated_apdu).hexdigest(),
    }
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", "utf-8")
    _chmod_best_effort(target, 0o600)
    return target


def dump_run_manifest(
    run_dir: Path,
    *,
    config: SafetyConfig,
    corpus_path: Path,
    seed: int,
    mutator_names: Iterable[str],
) -> Path:
    target = run_dir / "manifest.json"
    record = {
        "workspace_root": str(config.workspace_root),
        "allowed_iccids": sorted(config.allowed_iccids),
        "allowed_imsis": sorted(config.allowed_imsis),
        "max_apdus_per_run": config.max_apdus_per_run,
        "corpus_path": str(corpus_path),
        "seed": seed,
        "mutators": sorted(mutator_names),
        "started_at_utc": _utc_now().replace(tzinfo=None).isoformat(timespec="seconds") + "Z",
        "host_cwd": os.getcwd(),
    }
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", "utf-8")
    _chmod_best_effort(target, 0o600)
    return target
