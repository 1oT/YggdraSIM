"""In-process CAMARA Location Retrieval / Verification stub.

Mirrors the surface that the SUNRISE-6G OpenSDK builds on top of
the NEF Monitoring-Event subscription:

* ``retrieve_location(device, max_age)`` -- CAMARA Location-Retrieval v0.4.0
* ``verify_location(verification)``      -- CAMARA Location-Verification v2.x

Real CAMARA APIs subscribe to NEF and hand back a polygon. Our
stub keeps an *anchored* fix per device; the GUI / test rig sets
the anchor explicitly with :meth:`set_anchor` (think "the operator
told the demo where the UE is") and ``retrieve_location`` returns
that fix. ``verify_location`` runs a haversine containment check.

The stub is thread-safe and clock-injectable so tests can drive
deterministic age / staleness behaviour.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from .models import (
    DeviceIdentity,
    LocationFix,
    LocationVerification,
    LocationVerificationResult,
)


class LocationStubError(RuntimeError):
    """Raised when a location stub call cannot complete."""


class LocationFixNotFoundError(LocationStubError):
    """Raised when no anchor exists for the requested device."""


class LocationStubClient:
    """Process-local location anchor table."""

    def __init__(self, *, clock: Any = None) -> None:
        self._lock = threading.Lock()
        self._fixes: dict[str, LocationFix] = {}
        self._clock = clock or time.time

    # ------------------------------------------------------------------
    # Anchor management (operator-facing)
    # ------------------------------------------------------------------

    def set_anchor(
        self,
        device: DeviceIdentity,
        *,
        latitude: float,
        longitude: float,
        radius_meters: int,
        last_location_time_unix: Optional[float] = None,
    ) -> dict[str, Any]:
        if device.is_empty():
            raise LocationStubError("device must carry at least one identifier")
        timestamp = (
            float(last_location_time_unix)
            if last_location_time_unix is not None
            else float(self._clock())
        )
        fix = LocationFix(
            device=device,
            latitude=float(latitude),
            longitude=float(longitude),
            radius_meters=int(radius_meters),
            last_location_time_unix=timestamp,
        )
        with self._lock:
            self._fixes[device.stable_key()] = fix
        return self._public_fix_view(fix)

    def list_anchors(self) -> list[dict[str, Any]]:
        with self._lock:
            fixes = sorted(self._fixes.values(), key=lambda f: f.device.stable_key())
        return [self._public_fix_view(fix) for fix in fixes]

    def clear(self) -> int:
        with self._lock:
            count = len(self._fixes)
            self._fixes.clear()
        return count

    def fix_count(self) -> int:
        with self._lock:
            return len(self._fixes)

    def remove(self, device: DeviceIdentity) -> bool:
        with self._lock:
            return self._fixes.pop(device.stable_key(), None) is not None

    # ------------------------------------------------------------------
    # CAMARA-shaped surface
    # ------------------------------------------------------------------

    def retrieve_location(
        self,
        device: DeviceIdentity,
        *,
        max_age_seconds: int = 60,
    ) -> dict[str, Any]:
        """CAMARA Location-Retrieval v0.4.0 ``POST /retrieve``.

        Returns the canonical CAMARA ``Location`` shape (see
        :meth:`LocationFix.to_camara_location`). Raises
        :class:`LocationFixNotFoundError` when no anchor exists or
        the anchor is older than ``max_age_seconds``.
        """
        if int(max_age_seconds) < 1 or int(max_age_seconds) > 86_400:
            raise LocationStubError("max_age_seconds must be in [1, 86400].")
        if device.is_empty():
            raise LocationStubError("device must carry at least one identifier")
        with self._lock:
            fix = self._fixes.get(device.stable_key())
        if fix is None:
            raise LocationFixNotFoundError(
                f"no anchor for device {device.stable_key()!r}"
            )
        now_unix = float(self._clock())
        if fix.is_stale(now_unix=now_unix, max_age_seconds=int(max_age_seconds)):
            raise LocationFixNotFoundError(
                f"anchor for {device.stable_key()!r} is older than max_age_seconds={max_age_seconds}"
            )
        return fix.to_camara_location()

    def verify_location(
        self,
        verification: LocationVerification,
    ) -> dict[str, Any]:
        """CAMARA Location-Verification v2.x ``POST /verify``.

        Returns ``{"verificationResult": "..." , "lastLocationTime": "..."}``.
        Match codes follow CAMARA: MATCH / NO_MATCH / PARTIAL / UNKNOWN.
        """
        if verification.device.is_empty():
            raise LocationStubError("device must carry at least one identifier")
        with self._lock:
            fix = self._fixes.get(verification.device.stable_key())
        if fix is None:
            return {"verificationResult": LocationVerificationResult.UNKNOWN}
        now_unix = float(self._clock())
        if fix.is_stale(
            now_unix=now_unix,
            max_age_seconds=int(verification.max_age_seconds),
        ):
            return {
                "verificationResult": LocationVerificationResult.UNKNOWN,
                "lastLocationTime": fix.to_camara_location()["lastLocationTime"],
            }
        # MATCH if the anchor's containment circle is wholly inside
        # the verifier's accuracy circle; PARTIAL if they overlap;
        # NO_MATCH otherwise.
        match = _classify_match(
            fix=fix,
            latitude=float(verification.latitude),
            longitude=float(verification.longitude),
            accuracy_meters=int(verification.accuracy_meters),
        )
        return {
            "verificationResult": match,
            "lastLocationTime": fix.to_camara_location()["lastLocationTime"],
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _public_fix_view(fix: LocationFix) -> dict[str, Any]:
        view = fix.to_camara_location()
        view["device"] = fix.device.to_camara()
        return view


def _classify_match(
    *,
    fix: LocationFix,
    latitude: float,
    longitude: float,
    accuracy_meters: int,
) -> str:
    from .models import _haversine_meters  # type: ignore[attr-defined]

    distance = _haversine_meters(
        fix.latitude,
        fix.longitude,
        latitude,
        longitude,
    )
    inside = distance + float(fix.radius_meters) <= float(accuracy_meters)
    overlap = distance <= float(accuracy_meters + fix.radius_meters)
    if inside:
        return LocationVerificationResult.MATCH
    if overlap:
        return LocationVerificationResult.PARTIAL
    return LocationVerificationResult.NO_MATCH


# ----------------------------------------------------------------------
# Module-level singleton
# ----------------------------------------------------------------------


_DEFAULT_CLIENT: Optional[LocationStubClient] = None


def get_default_location_stub_client() -> LocationStubClient:
    global _DEFAULT_CLIENT
    if _DEFAULT_CLIENT is None:
        _DEFAULT_CLIENT = LocationStubClient()
    return _DEFAULT_CLIENT


def reset_default_location_stub_client() -> None:
    global _DEFAULT_CLIENT
    if _DEFAULT_CLIENT is not None:
        _DEFAULT_CLIENT.clear()


__all__ = [
    "LocationFixNotFoundError",
    "LocationStubClient",
    "LocationStubError",
    "get_default_location_stub_client",
    "reset_default_location_stub_client",
]
