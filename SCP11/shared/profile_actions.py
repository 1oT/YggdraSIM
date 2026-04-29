"""Shared profile-management helpers for the four SCP11 shells.

The eSIM Live, eSIM Test, Local SMDP+, and Local eIM shells all expose the
same ``ENABLE-PROFILE`` / ``DISABLE-PROFILE`` / ``DELETE-PROFILE`` family of
commands. Without a shared helper, the safety semantics — auto-disabling the
currently-active profile before enabling a new one, auto-disabling an
enabled profile before deleting it, short-circuiting no-op transitions —
drift between the shells. This module factors the contract so every shell
calls into the same routine and operators see the same behaviour regardless
of which surface they dropped into.

The helpers are session-agnostic: the caller passes a description of the
profile inventory (a list of objects exposing ``state``, ``iccid``,
``aid``, etc. — the existing ``ProfileMetadataView`` shape) plus a
``ProfileActionAdapter`` describing how to reach the underlying ES10 /
ISD-R commands. Output goes through the adapter's ``info`` / ``warn`` /
``error`` callbacks so each shell controls its own colour scheme.

Authoritative reference: SGP.22 §5.7.16 (EnableProfile rules), §5.7.17
(DisableProfile), §5.7.18 (DeleteProfile); SGP.32 §3.2.6 lifecycle
constraints; ETSI TS 102 226 §5 for the ISD-R underpinnings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional


# ---------------------------------------------------------------------------
# Adapter contract
# ---------------------------------------------------------------------------


@dataclass
class ProfileActionAdapter:
    """Bridge between a shell and the SGP.22 / SGP.32 profile commands.

    Each callable returns a truthy value (``True`` or a response payload)
    when the underlying ES10 command was accepted by the card, falsy
    (``False`` / ``None``) when it failed. The action helpers below treat
    a falsy return as a hard stop and abort the rest of the sequence so
    we never proceed with (e.g.) a delete after a failed auto-disable.

    ``policy_allow_auto_disable`` lets a shell veto an auto-disable based
    on PPR rules (``ppr1-disable-not-allowed``). When the callback
    returns ``False`` the helper aborts without attempting the disable.

    ``modem_refresh`` is invoked once after every accepted state change so
    the calling shell can queue the proactive ``REFRESH`` toward the
    attached modem (the existing ``_queue_modem_refresh`` plumbing).
    """

    enable_profile: Callable[[Any], Any]
    disable_profile: Callable[[Any], Any]
    delete_profile: Callable[[Any], Any]
    policy_allow_auto_disable: Optional[
        Callable[[Any, Optional[Any]], bool]
    ] = None
    modem_refresh: Optional[Callable[[str], None]] = None
    describe_profile: Callable[[Any], str] = lambda profile: ""
    profile_identifier: Callable[[Any], Any] = lambda profile: profile
    info: Callable[[str], None] = print
    warn: Callable[[str], None] = print
    error: Callable[[str], None] = print
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Profile-row helpers
# ---------------------------------------------------------------------------


def is_enabled(profile: Any) -> bool:
    """Return True when the metadata row's state is ENABLED.

    All four shells store the state as an upper / mixed-case string on a
    ``ProfileMetadataView``-shaped object. Compare case-insensitively so
    ``"Enabled"``, ``"ENABLED"``, and the rare ``"ENABLED "`` (trailing
    whitespace) variants all resolve to the same answer.
    """
    state = str(getattr(profile, "state", "") or "").strip().upper()
    return state == "ENABLED"


def find_enabled_profile(
    profiles: Iterable[Any],
    *,
    exclude: Any = None,
) -> Optional[Any]:
    """Return the currently enabled profile, or None when nothing is on.

    SGP.22 mandates that at most one operational profile is ENABLED at a
    time, so this is a single-result lookup. ``exclude`` lets the caller
    skip the profile they're about to act on (e.g. don't auto-disable the
    target you're trying to enable).
    """
    excluded_aid, excluded_iccid = _profile_aid_iccid(exclude)
    for profile in profiles:
        if not is_enabled(profile):
            continue
        candidate_aid, candidate_iccid = _profile_aid_iccid(profile)
        if exclude is not None and (
            (candidate_aid != "" and candidate_aid == excluded_aid)
            or (candidate_iccid != "" and candidate_iccid == excluded_iccid)
        ):
            continue
        return profile
    return None


def find_profile(
    profiles: Iterable[Any],
    identifier: str,
) -> Optional[Any]:
    """Locate a profile row by ICCID / AID / nickname / profile-name.

    The match is case-insensitive on the textual fields and tolerates
    common BCD-string drift (extra whitespace, trailing F filler).
    Returns ``None`` when the identifier doesn't resolve — callers
    should treat that as "fall through to the underlying ES10 command,
    which will surface a card-level error if the identifier is bogus".
    """
    needle = str(identifier or "").strip()
    if len(needle) == 0:
        return None
    needle_upper = needle.upper().rstrip("F").rstrip()
    for profile in profiles:
        candidates = (
            str(getattr(profile, "iccid", "") or "").strip(),
            str(getattr(profile, "aid", "") or "").strip(),
            str(getattr(profile, "nickname", "") or "").strip(),
            str(getattr(profile, "profile_name", "") or "").strip(),
            str(getattr(profile, "alias", "") or "").strip(),
        )
        for candidate in candidates:
            if len(candidate) == 0:
                continue
            if candidate.upper().rstrip("F").rstrip() == needle_upper:
                return profile
    return None


def _profile_aid_iccid(profile: Any) -> tuple[str, str]:
    if profile is None:
        return ("", "")
    aid = str(getattr(profile, "aid", "") or "").strip().upper()
    iccid = str(getattr(profile, "iccid", "") or "").strip().upper()
    return (aid, iccid)


# ---------------------------------------------------------------------------
# Action helpers — the meat of the harmonised contract
# ---------------------------------------------------------------------------


def run_enable_profile(
    adapter: ProfileActionAdapter,
    profiles: list[Any],
    identifier: str,
) -> bool:
    """Enable ``identifier`` after auto-disabling the active profile.

    Sequence:

    1. Resolve ``identifier`` against ``profiles``. When it resolves to a
       profile that is already ENABLED, short-circuit with an info
       message — the operator's intent is already met.
    2. Look up the currently ENABLED profile (excluding the target).
       When one exists, ask the policy callback whether the auto-disable
       is allowed (PPR1 guard). If denied, abort.
    3. Issue ``DisableProfile`` against the active profile. Abort on
       failure (we don't want to leave the card in a wedged state where
       the caller assumes the target was enabled but it wasn't).
    4. Issue ``EnableProfile`` against the target. Queue the modem
       refresh on success.

    Returns ``True`` when the target ends up ENABLED at the end of the
    sequence (or already was). ``False`` when any step failed.
    """
    target = find_profile(profiles, identifier)
    if target is not None and is_enabled(target):
        adapter.info(
            "[+] EnableProfile: target is already enabled "
            f"({adapter.describe_profile(target)})."
        )
        return True

    active = find_enabled_profile(profiles, exclude=target)
    if active is not None:
        if adapter.policy_allow_auto_disable is not None:
            if adapter.policy_allow_auto_disable(active, target) is False:
                return False
        adapter.info(
            "[*] EnableProfile: auto-disabling active profile "
            f"{adapter.describe_profile(active)}."
        )
        disable_response = adapter.disable_profile(adapter.profile_identifier(active))
        if not _is_success(disable_response):
            adapter.error(
                "[!] EnableProfile: auto-disable of "
                f"{adapter.describe_profile(active)} failed; aborting."
            )
            return False

    enable_target = identifier if target is None else adapter.profile_identifier(target)
    enable_response = adapter.enable_profile(enable_target)
    if not _is_success(enable_response):
        return False
    if adapter.modem_refresh is not None:
        adapter.modem_refresh("EnableProfile")
    return True


def run_disable_profile(
    adapter: ProfileActionAdapter,
    profiles: list[Any],
    identifier: str,
) -> bool:
    """Disable ``identifier``, short-circuiting when it isn't ENABLED.

    Mirrors the SGP.22 §5.7.17 idempotency contract — disabling a
    DISABLED profile is a no-op that returns success. The shell-facing
    output is collapsed to a single info line so the operator doesn't
    have to read a card error to find out their target was already off.
    """
    target = find_profile(profiles, identifier)
    if target is not None and not is_enabled(target):
        adapter.info(
            "[+] DisableProfile: target is already disabled "
            f"({adapter.describe_profile(target)})."
        )
        return True

    disable_target = identifier if target is None else adapter.profile_identifier(target)
    response = adapter.disable_profile(disable_target)
    if not _is_success(response):
        return False
    if adapter.modem_refresh is not None:
        adapter.modem_refresh("DisableProfile")
    return True


def run_delete_profile(
    adapter: ProfileActionAdapter,
    profiles: list[Any],
    identifier: str,
) -> bool:
    """Delete ``identifier``, auto-disabling first when it is ENABLED.

    SGP.22 §5.7.18 forbids deleting an ENABLED profile (the LPA-side
    contract is "disable, then delete"). Some cards / lab profiles
    accept a delete-while-enabled as a single transaction, but we treat
    the safe path as canonical: when the target is currently ENABLED we
    issue a ``DisableProfile`` first (subject to the same PPR1 guard as
    enable), then the delete.

    The "force delete an enabled profile without disabling" path stays
    available to callers that drive the underlying ``delete_profile``
    callback directly — this helper is the harmonised default.
    """
    target = find_profile(profiles, identifier)
    if target is not None and is_enabled(target):
        if adapter.policy_allow_auto_disable is not None:
            if adapter.policy_allow_auto_disable(target, target) is False:
                return False
        adapter.info(
            "[*] DeleteProfile: auto-disabling enabled target "
            f"{adapter.describe_profile(target)} before delete."
        )
        disable_response = adapter.disable_profile(adapter.profile_identifier(target))
        if not _is_success(disable_response):
            adapter.error(
                "[!] DeleteProfile: auto-disable failed; aborting delete to "
                "avoid leaving the card in an inconsistent state."
            )
            return False

    delete_target = identifier if target is None else adapter.profile_identifier(target)
    response = adapter.delete_profile(delete_target)
    if not _is_success(response):
        return False
    if adapter.modem_refresh is not None:
        adapter.modem_refresh("DeleteProfile")
    return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_success(response: Any) -> bool:
    """Treat truthy and bytes-like responses as success.

    The eSIM Live / Test shells return ``True`` from their helpers when a
    state command was accepted. The local-access / eim-local shells
    return the raw ES10 response bytes (always non-empty when the card
    accepted the request). Either shape resolves to "success" here.
    """
    if response is None:
        return False
    if isinstance(response, bool):
        return response
    if isinstance(response, (bytes, bytearray)):
        return len(response) > 0
    return True
