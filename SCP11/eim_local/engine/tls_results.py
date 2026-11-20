# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""What the recorded card-facing handshakes say about each leaf a TLS setup has served.

A setup keeps its name and its CA while the leaf on the name is swapped, so
the handshake rows are grouped by the SHA-256 of the leaf that was served, not
by the setup. A handshake that ended before the ClientHello's server name
picked a chain, or on a name this side refuses, offered no leaf and is listed
under none. Only a full handshake is evidence about a leaf: in a resumed
session the client checks no certificate, so resumptions are counted apart and
decide nothing. A full handshake counts as accepted once an exchange followed
on its connection; one that nothing followed is reported as such, because a
client may complete the handshake and still walk away.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from SCP11.eim_local.engine import tls_setup
from SCP11.eim_local.engine.store import (
    HANDSHAKE_COMPLETED,
    HANDSHAKE_FAILED,
    HANDSHAKE_LOST,
    HANDSHAKE_REFUSED,
    TLS_HANDSHAKE_CAP,
    EimStore,
    TlsHandshake,
)

VERDICT_ACCEPTED = "accepted"
VERDICT_MIXED = "mixed: accepted and refused"
VERDICT_SILENT = "handshake completed, no request followed"
VERDICT_LOST = "handshake ended without an alert (closed or stalled)"
VERDICT_RESUMED = "resumed sessions only"
VERDICT_NONE = "no attempt seen"


@dataclass
class LeafResult:
    """The handshakes of one leaf under one setup, counted by how they ended."""

    setup: str
    leaf: str
    sha256: str
    on_the_name: bool = False
    accepted: int = 0
    silent: int = 0
    resumed: int = 0
    refused: dict[str, int] = field(default_factory=dict)
    failed: dict[str, int] = field(default_factory=dict)
    lost: int = 0
    first_at: str = ""
    last_at: str = ""
    eids: list[str] = field(default_factory=list)

    @property
    def attempts(self) -> int:
        return (self.accepted + self.silent + self.resumed + sum(self.refused.values()) + sum(self.failed.values())
                + self.lost)

    def verdict(self) -> str:
        """One line for a table: accepted, refused with the client's alert, or what else was seen."""
        if self.accepted > 0:
            return VERDICT_MIXED if self.refused else VERDICT_ACCEPTED
        if self.refused:
            return "refused: " + ", ".join(_by_count(self.refused))
        if self.silent > 0:
            return VERDICT_SILENT
        if self.failed:
            return "ended by this side: " + ", ".join(_by_count(self.failed))
        if self.lost > 0:
            return VERDICT_LOST
        if self.resumed > 0:
            return VERDICT_RESUMED
        return VERDICT_NONE

    def as_dict(self) -> dict[str, Any]:
        return {
            "setup": self.setup, "leaf": self.leaf, "sha256": self.sha256, "on_the_name": self.on_the_name,
            "verdict": self.verdict(), "accepted": self.accepted, "silent": self.silent, "resumed": self.resumed,
            "refused": dict(self.refused), "failed": dict(self.failed), "lost": self.lost, "first_at": self.first_at,
            "last_at": self.last_at, "eids": list(self.eids),
        }


def _count(result: LeafResult, row: TlsHandshake) -> None:
    if row.outcome == HANDSHAKE_COMPLETED:
        if row.resumed:
            result.resumed += 1
        elif row.requests > 0:
            result.accepted += 1
        else:
            result.silent += 1
    elif row.outcome == HANDSHAKE_REFUSED:
        name = row.alert or row.reason or "alert"
        result.refused[name] = result.refused.get(name, 0) + 1
    elif row.outcome == HANDSHAKE_FAILED:
        name = row.alert or row.reason or "failed"
        result.failed[name] = result.failed.get(name, 0) + 1
    elif row.outcome == HANDSHAKE_LOST:
        result.lost += 1
    if len(row.at) > 0:
        result.first_at = row.at if not result.first_at or row.at < result.first_at else result.first_at
        result.last_at = row.at if row.at > result.last_at else result.last_at
    if len(row.eid) > 0 and row.eid not in result.eids:
        result.eids.append(row.eid)


def summarise(rows: Iterable[TlsHandshake], leaves: dict[str, list[tls_setup.LeafVariant]],
              served: dict[str, str]) -> list[LeafResult]:
    """One result per leaf: every leaf in *leaves* (setup name -> its leaves), then leaves only the rows know.

    *served* names the leaf each setup has on its name now. A row whose
    fingerprint matches no leaf its setup holds any more (a leaf removed, a
    setup rebuilt) is kept under the name the row carries.
    """
    results: dict[tuple[str, str], LeafResult] = {}
    for setup, variants in leaves.items():
        for variant in variants:
            results[(setup, variant.sha256)] = LeafResult(setup=setup, leaf=variant.name, sha256=variant.sha256,
                                                          on_the_name=served.get(setup, "") == variant.name)
    for row in rows:
        key = (row.tls_setup, row.leaf_sha256)
        result = results.get(key)
        if result is None:
            result = results[key] = LeafResult(setup=row.tls_setup, leaf=row.leaf, sha256=row.leaf_sha256)
        _count(result, row)
    return list(results.values())


def leaf_results(store: EimStore, directory: Path, setup_name: str = "", *,
                 limit: int = TLS_HANDSHAKE_CAP) -> list[LeafResult]:
    """The results for setup *setup_name* ('' for every setup), from the newest *limit* handshake rows."""
    setups = [tls_setup.load_setup(directory, setup_name)] if setup_name else tls_setup.list_setups(directory)
    leaves = {setup.name: tls_setup.list_leaves(directory, setup.name) for setup in setups}
    served = {setup.name: tls_setup.served_leaf(setup) for setup in setups}
    rows = store.handshakes(limit=limit, setup=setup_name, newest_first=False)
    return summarise(rows, leaves, served)


def _by_count(counts: dict[str, int]) -> list[str]:
    return sorted(counts, key=lambda name: (-counts[name], name))


def count_text(result: LeafResult) -> str:
    """The non-zero counts of *result*, each with its label, so the line reads without its columns."""
    parts: list[str] = []
    if result.accepted > 0:
        parts.append(f"full {result.accepted}")
    if result.silent > 0:
        parts.append(f"full without a request {result.silent}")
    if result.resumed > 0:
        parts.append(f"resumed {result.resumed}")
    for label, counts in (("refused", result.refused), ("ended here", result.failed)):
        if not counts:
            continue
        text = f"{label} {sum(counts.values())}"
        if len(counts) > 1:
            text += " (" + ", ".join(f"{name} {counts[name]}" for name in _by_count(counts)) + ")"
        parts.append(text)
    if result.lost > 0:
        parts.append(f"lost {result.lost}")
    return ", ".join(parts)


def result_lines(results: list[LeafResult]) -> list[str]:
    """The results as lines for a listing; ``*`` marks the leaf a setup has on its name now.

    The names are padded for a terminal; the verdict and the counts carry
    their own words, because a surface that collapses the padding (the GUI's
    result list) has to read the same.
    """
    lines = [f"    {'setup':<16} {'leaf':<16} {'SHA-256':<9} verdict -- handshakes counted"]
    for result in results:
        marker = "*" if result.on_the_name else " "
        counts = count_text(result)
        # Rows without a fingerprint ended before a chain was picked; a fingerprint no leaf has any more is an earlier one.
        leaf = result.leaf or ("(earlier leaf)" if result.sha256 else "(none offered)")
        lines.append(
            f"  {marker} {(result.setup or '-'):<16} {leaf:<16} {(result.sha256[:8] or '-'):<9} "
            f"{result.verdict()}" + (f" -- {counts}" if counts else "")
        )
    return lines


def handshake_line(row: TlsHandshake) -> str:
    """One recorded handshake as a line: when, who asked for what, which leaf, how it ended."""
    if row.outcome == HANDSHAKE_COMPLETED:
        end = f"{row.tls_version} {row.tls_cipher}" + (", resumed" if row.resumed else "") + f", {row.requests} request(s)"
    else:
        end = ", ".join(part for part in (f"alert {row.alert}" if row.alert else "", row.reason) if part) or "-"
    return (f"#{row.id:<5} {row.at[11:23]}  {row.peer_host}:{row.peer_port}  {row.server_name or '(no server name)'}  "
            f"{row.tls_setup or '-'} / {row.leaf or '-'} {row.leaf_sha256[:8]}  {row.outcome}: {end}")


__all__ = [
    "VERDICT_ACCEPTED", "VERDICT_LOST", "VERDICT_MIXED", "VERDICT_NONE", "VERDICT_RESUMED", "VERDICT_SILENT",
    "LeafResult", "count_text", "handshake_line", "leaf_results", "result_lines", "summarise",
]
