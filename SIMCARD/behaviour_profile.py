# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Declarative card-behaviour profiles for the simulated card.

A behaviour profile records how one real card answered the probe plan
*where it differed from this simulator*, so it can be replayed without the
card. It pairs with a SAIP profile:

    behaviour profile  ->  how the card responds
    SAIP profile       ->  what data the card holds

Nothing identity-shaped belongs here. ICCID, IMSI, EID, and certificates
come from the SAIP side, which is what lets one charted personality be
paired with any profile. ``Tools/CardClone`` enforces the exclusion when
it writes a profile; :func:`load_behaviour_profile` enforces it again on
read, because a profile may arrive from another lab.

Unlike ``sim_quirks.py``, a behaviour profile is JSON, not executed
Python. It therefore needs no ``YGGDRASIM_ALLOW_QUIRKS`` opt-in -- data
cannot run. It does honour ``YGGDRASIM_DISABLE_QUIRKS=1``, because an
operator who sets that switch is asking for the built-in personality and
does not care which mechanism supplied the override.

Known limit: overrides are matched on the plaintext command APDU, and the
engine runs ``before_apdu`` hooks ahead of SCP03 unwrapping. A profile
therefore shapes unwrapped traffic only; it does not reach commands
inside a secure channel.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "SCHEMA",
    "BehaviourProfile",
    "BehaviourProfileError",
    "load_behaviour_profile",
    "resolve_behaviour_profile",
    "install_behaviour_profile",
    "activate_behaviour_profile",
    "deactivate_behaviour_profile",
    "deactivate_all_quirks",
    "behaviour_profile_status",
]

SCHEMA = "yggdrasim_card_behaviour_profile/1"

_DISABLE_QUIRKS_ENV = "YGGDRASIM_DISABLE_QUIRKS"

# Response data must not carry a real-operator ICCID. The primary
# protection is structural: identity-bearing probe steps are excluded when
# writing, so this content check is a backstop for a hand-edited file or a
# future step that forgets the flag.
#
# It matches only the allocated issuer prefixes CLAUDE.md section 1 bans,
# in both the ASCII / high-nibble-BCD form (SAIP) and the low-nibble-first
# EF.ICCID form, mirroring scripts/check_repo_hygiene.py. A broad "any
# 89/98 run" heuristic was wrong: it false-positives on legitimate FCP
# structure and GlobalPlatform AIDs -- an ISD-R AID ends ...8900000100 --
# which made a real card's profile unloadable. The 8988 test range (BCD
# 9888) is allowed and is deliberately absent here.
_IDENTITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "real ICCID (ASCII / high-nibble BCD)",
        re.compile(r"(?:8946|8949|8937|8983|89126)[0-9]{10,}"),
    ),
    (
        "real ICCID (EF.ICCID low-nibble BCD)",
        re.compile(r"(?:9864|9894|9873|9838|9821)[0-9A-Fa-f]{14,}", re.IGNORECASE),
    ),
)

_HEX = re.compile(r"^[0-9A-Fa-f]*$")


class BehaviourProfileError(ValueError):
    """A behaviour profile is malformed, or carries data it must not."""


@dataclass(frozen=True)
class BehaviourOverride:
    """One recorded answer, keyed by the command that produced it."""

    apdu_hex: str
    status_hex: str
    data_hex: str = ""
    step_id: str = ""
    charts: str = ""

    def as_result(self) -> tuple[bytes, int, int]:
        status = int(self.status_hex, 16)
        return bytes.fromhex(self.data_hex), (status >> 8) & 0xFF, status & 0xFF


@dataclass
class BehaviourProfile:
    """A charted card personality."""

    name: str = ""
    notes: str = ""
    atr_hex: str = ""
    source_card: str = ""
    overrides: dict[str, BehaviourOverride] = field(default_factory=dict)

    def as_document(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "notes": self.notes,
            "atr_hex": self.atr_hex.upper(),
            "source_card": self.source_card,
            "overrides": [
                {
                    "apdu_hex": override.apdu_hex,
                    "status_hex": override.status_hex,
                    "data_hex": override.data_hex,
                    "step_id": override.step_id,
                    "charts": override.charts,
                }
                for override in self.overrides.values()
            ],
        }

    def write(self, path: str | Path) -> Path:
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.as_document(), indent=2) + "\n", encoding="utf-8"
        )
        return target


def _require_hex(value: str, *, label: str) -> str:
    text = str(value or "").strip().replace(" ", "").upper()
    if _HEX.match(text) is None or len(text) % 2 != 0:
        raise BehaviourProfileError(f"{label} must be even-length hex, got {value!r}.")
    return text


def _assert_no_identity(data_hex: str, *, where: str) -> None:
    for label, pattern in _IDENTITY_PATTERNS:
        if pattern.search(data_hex):
            raise BehaviourProfileError(
                f"{where} carries what looks like card identity ({label}). "
                "A behaviour profile records how a card answers, never what "
                "it holds; identity belongs in the paired SAIP profile."
            )


def load_behaviour_profile(path: str | Path) -> BehaviourProfile:
    """Read and validate a behaviour profile from disk."""
    source = Path(path).expanduser()
    try:
        raw = source.read_text(encoding="utf-8")
    except OSError as error:
        raise BehaviourProfileError(f"cannot read {source}: {error}") from error
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise BehaviourProfileError(f"{source} is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise BehaviourProfileError(f"{source} is not a behaviour-profile mapping.")
    schema = str(document.get("schema") or "")
    if schema != SCHEMA:
        raise BehaviourProfileError(
            f"{source} declares schema {schema or 'absent'!r}, expected {SCHEMA!r}."
        )

    profile = BehaviourProfile(
        name=str(document.get("name") or ""),
        notes=str(document.get("notes") or ""),
        atr_hex=_require_hex(document.get("atr_hex", ""), label="atr_hex"),
        source_card=str(document.get("source_card") or ""),
    )

    rows = document.get("overrides", [])
    if not isinstance(rows, list):
        raise BehaviourProfileError(f"{source}: 'overrides' must be a list.")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise BehaviourProfileError(f"{source}: overrides[{index}] must be a mapping.")
        apdu_hex = _require_hex(row.get("apdu_hex", ""), label=f"overrides[{index}].apdu_hex")
        if len(apdu_hex) == 0:
            raise BehaviourProfileError(f"{source}: overrides[{index}].apdu_hex is empty.")
        status_hex = _require_hex(
            row.get("status_hex", ""), label=f"overrides[{index}].status_hex"
        )
        if len(status_hex) != 4:
            raise BehaviourProfileError(
                f"{source}: overrides[{index}].status_hex must be two bytes."
            )
        data_hex = _require_hex(row.get("data_hex", ""), label=f"overrides[{index}].data_hex")
        _assert_no_identity(data_hex, where=f"{source}: overrides[{index}].data_hex")
        profile.overrides[apdu_hex] = BehaviourOverride(
            apdu_hex=apdu_hex,
            status_hex=status_hex,
            data_hex=data_hex,
            step_id=str(row.get("step_id") or ""),
            charts=str(row.get("charts") or ""),
        )
    return profile


def _quirks_disabled_by_env() -> bool:
    return str(os.environ.get(_DISABLE_QUIRKS_ENV, "")).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


# The profile the installed hook consults on every APDU. Held in a module
# cell rather than captured in a closure so activating or deactivating
# reaches engines that already exist: ``SimulatedCardConnection`` binds the
# engine at construction, so a snapshot would leave an open connection
# answering with the personality it started with.
_ACTIVE_PROFILE: BehaviourProfile | None = None


def active_profile() -> BehaviourProfile | None:
    """Return the profile currently shaping simulator responses."""
    return _ACTIVE_PROFILE


def set_active_profile(profile: BehaviourProfile | None) -> None:
    """Swap the live profile. Takes effect on the next APDU, everywhere."""
    global _ACTIVE_PROFILE
    _ACTIVE_PROFILE = profile


def build_behaviour_hooks(profile: BehaviourProfile):
    """Return ``(before_apdu, state_hook)`` bound to ``profile`` directly.

    Used by tests and by callers that want a self-contained hook pair. The
    engine uses :func:`install_behaviour_profile`, whose hook follows the
    live profile instead.
    """

    lookup = dict(profile.overrides)

    def before_apdu(apdu: bytes, state: Any):
        del state
        override = lookup.get(bytes(apdu or b"").hex().upper())
        if override is None:
            return None
        return override.as_result()

    def state_hook(state: Any) -> None:
        if len(profile.atr_hex) > 0:
            state.atr = bytes.fromhex(profile.atr_hex)

    return before_apdu, state_hook


def install_behaviour_profile(registry: Any, profile: BehaviourProfile | None) -> None:
    """Install the live-profile hook on a :class:`QuirkRegistry`.

    Always installs, even with no profile: the hook is a dict lookup that
    returns ``None`` when nothing is active, and installing unconditionally
    is what lets a profile be activated later on an engine that booted
    without one.

    Composes with the Python quirks file rather than replacing it. The
    behaviour hook is appended, so a hand-written quirk registered earlier
    still wins on any APDU it claims.
    """
    set_active_profile(profile)

    def before_apdu(apdu: bytes, state: Any):
        del state
        current = _ACTIVE_PROFILE
        if current is None:
            return None
        override = current.overrides.get(bytes(apdu or b"").hex().upper())
        if override is None:
            return None
        return override.as_result()

    def state_hook(state: Any) -> None:
        current = _ACTIVE_PROFILE
        if current is not None and len(current.atr_hex) > 0:
            state.atr = bytes.fromhex(current.atr_hex)

    registry.add_before_apdu(before_apdu)
    registry.add_state_hook(state_hook)


def activate_behaviour_profile(path: str | Path, *, persist: bool = True) -> str:
    """Switch the simulator onto ``path`` and rebuild the engine.

    The profile is validated before anything is changed, so pointing at a
    malformed file leaves the running personality alone rather than
    dropping the simulator into a half-applied state.
    """
    resolved = str(path or "").strip()
    if len(resolved) == 0:
        raise BehaviourProfileError("activate needs a profile path; use deactivate instead.")
    load_behaviour_profile(resolved)

    from yggdrasim_common.card_backend import set_sim_behaviour_profile_path

    selected = set_sim_behaviour_profile_path(resolved, persist=persist)
    _apply_live(load_behaviour_profile(resolved))
    return selected


def deactivate_behaviour_profile(*, persist: bool = True) -> None:
    """Drop the behaviour profile and rebuild on the built-in personality.

    Records the disable sentinel rather than clearing the setting, so a
    profile sitting at the default workspace location is not silently
    picked back up on the next resolve.
    """
    from yggdrasim_common.card_backend import (
        SIM_QUIRKS_PATH_NONE,
        set_sim_behaviour_profile_path,
    )

    set_sim_behaviour_profile_path(SIM_QUIRKS_PATH_NONE, persist=persist)
    _apply_live(None)


def deactivate_all_quirks(*, persist: bool = True) -> None:
    """Turn off every personality override and return to the default card.

    Covers both mechanisms: the executed ``sim_quirks.py`` file and the
    declarative behaviour profile. After this the simulator answers with
    its built-in behaviour and nothing else.
    """
    from yggdrasim_common.card_backend import (
        SIM_QUIRKS_PATH_NONE,
        set_sim_behaviour_profile_path,
        set_sim_quirks_path,
    )

    set_sim_quirks_path(SIM_QUIRKS_PATH_NONE, persist=persist)
    set_sim_behaviour_profile_path(SIM_QUIRKS_PATH_NONE, persist=persist)
    # The quirks file is executed Python, so turning it off needs a
    # rebuild; the behaviour half is handled by the live cell.
    _apply_live(None, rebuild=True)


def behaviour_profile_status() -> dict[str, Any]:
    """Report what personality the simulator is currently running."""
    from yggdrasim_common.card_backend import (
        get_sim_behaviour_profile_path,
        get_sim_behaviour_profile_source,
        get_sim_quirks_path,
        is_sim_quirks_disabled,
    )

    path = get_sim_behaviour_profile_path()
    quirks_path = get_sim_quirks_path()
    profile: BehaviourProfile | None = None
    error = ""
    if len(path) > 0:
        try:
            profile = load_behaviour_profile(path)
        except BehaviourProfileError as failure:
            error = str(failure)
    kill_switch = _quirks_disabled_by_env()
    return {
        "behaviour_profile_path": path,
        "behaviour_profile_source": get_sim_behaviour_profile_source(),
        "behaviour_profile_name": profile.name if profile is not None else "",
        "behaviour_profile_overrides": len(profile.overrides) if profile is not None else 0,
        "behaviour_profile_error": error,
        "quirks_path": quirks_path,
        "quirks_disabled": bool(is_sim_quirks_disabled()),
        "process_kill_switch": kill_switch,
        "active": (
            profile is not None
            and len(profile.overrides) + len(profile.atr_hex) > 0
            and not kill_switch
        ),
    }


def _apply_live(profile: BehaviourProfile | None, *, rebuild: bool = False) -> None:
    """Swap the personality on the running engine and on future ones.

    The live cell is swapped so any engine already handed out --
    including one held by an open ``SimulatedCardConnection`` -- answers
    the new way on its next APDU. The ATR is state rather than a
    response, so it is written straight onto the live engine;
    deactivating restores the built-in value.

    The cached singleton is deliberately *not* dropped for a
    behaviour-only change. Dropping it orphans the engine the caller is
    still holding, which then never receives the next ATR update.
    ``rebuild=True`` is for changes the hook cannot express, such as
    switching the executed quirks file.

    The whole swap runs under ``_SHARED_ENGINE_LOCK``, the same lock
    ``connection`` takes for every engine access. The behaviour hook's
    read path is already race-free -- it snapshots the live cell into a
    local and the profile is immutable after load -- but this writer also
    mutates ``state.atr`` and clears the cache, and those must not
    interleave with a concurrent rebuild. Reachable from the threaded GUI
    server, which drives the simulator under uvicorn worker threads.
    """
    try:
        from SIMCARD import connection
    except ImportError:
        set_active_profile(profile)
        return
    with connection._SHARED_ENGINE_LOCK:
        set_active_profile(profile)
        _apply_live_atr(profile)
        if rebuild:
            _drop_cached_engine()


def _apply_live_atr(profile: BehaviourProfile | None) -> None:
    """Write the profile's ATR onto the live engine, or restore the default.

    Caller holds ``_SHARED_ENGINE_LOCK``.
    """
    try:
        from SIMCARD import connection
        from SIMCARD.etsi_fs import build_default_state
    except ImportError:
        return
    engine = connection._SHARED_ENGINE
    if engine is None:
        return
    if profile is not None and len(profile.atr_hex) > 0:
        engine.state.atr = bytes.fromhex(profile.atr_hex)
        return
    engine.state.atr = bytes(build_default_state().atr)


def _drop_cached_engine() -> None:
    """Clear the cached singleton so the next access re-reads settings."""
    try:
        from SIMCARD import connection
    except ImportError:
        return
    with connection._SHARED_ENGINE_LOCK:
        if connection._validation_lease_owner_locked() is not None:
            raise RuntimeError(
                "Simulated card personality cannot change during a "
                "read-only validation session."
            )
        connection._SHARED_ENGINE = None


def resolve_behaviour_profile(path: str) -> BehaviourProfile | None:
    """Load the configured profile, or None when none should apply.

    Returns ``None`` when no profile is configured or when
    ``YGGDRASIM_DISABLE_QUIRKS=1`` asks for the built-in personality.
    """
    normalized = str(path or "").strip()
    if len(normalized) == 0:
        return None
    if normalized.lower() in ("none", "off", "disabled", "disable"):
        return None
    if _quirks_disabled_by_env():
        return None
    if not Path(normalized).expanduser().is_file():
        return None
    return load_behaviour_profile(normalized)
