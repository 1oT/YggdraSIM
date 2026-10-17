# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""HIL-Bridge supervisor: manages child process lifecycle (modem, bridge, tshark) with restart policy and watchdog timers."""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Any, Protocol

from yggdrasim_common.card_backend import (
    CARD_RELAY_MARKER_FILENAME,
    _request_card_relay_json,
    is_simulated_card_backend,
)
from yggdrasim_common.card_bridge_auth import write_token_file
from yggdrasim_common.frozen_dispatch import build_module_command
from yggdrasim_common.process_debug import add_debug_argument, set_global_debug
from yggdrasim_common.quit_control import QuitAllRequested
from yggdrasim_common.runtime_paths import ensure_runtime_dir, runtime_path

from .device_reset import (
    SimtraceResetConfig,
    SimtraceResetOutcome,
    add_reset_arguments,
    build_reset_config_from_args,
    normalize_reset_mode,
    reset_simtrace_device,
)
from .main import add_bridge_runtime_arguments, build_bridge_config_from_args
from .remote_card import (
    build_card_relay_lease_url,
    build_card_relay_status_url,
    resolve_remote_card_token,
)
from .router import BridgeConfig

# ``signal.SIGKILL`` is POSIX-only and is evaluated at the call site, so it
# cannot sit behind the platform guard inside the callee.
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)

LOGGER = logging.getLogger(__name__)

DEFAULT_USB_MATCH_TERMS: tuple[str, ...] = ("simtrace", "sysmocom")
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_RESTART_BACKOFF_SECONDS = 1.0
DEFAULT_REMOTE_CARD_RESTART_BACKOFF_SECONDS = 15.0
# How long the card path needs after the REMSIM client starts before a
# modem asked to re-read the SIM will actually find one.
MODEM_REFRESH_SETTLE_SECONDS = 8.0
# Retries when the modem has not taken the card by then, with a growing
# wait. Bounded so a modem that will never take it stops cycling its radio.
MODEM_REFRESH_MAX_ATTEMPTS = 3
# The refresh re-enumerates the AT port on this modem, so it disappears
# and comes back. These bound the wait for it before the result is read.
MODEM_PORT_RETURN_TIMEOUT_SECONDS = 20.0
MODEM_PORT_SETTLE_SECONDS = 2.0
DEFAULT_TERMINATION_TIMEOUT_SECONDS = 5.0
DEFAULT_LSUSB_TIMEOUT_SECONDS = 5.0
DEFAULT_REMSIM_USB_CONFIG_ID = "1"
DEFAULT_REMSIM_USB_INTERFACE_ID = "0"
DEFAULT_REMSIM_USB_ALTSETTING_ID = "0"
SUPERVISOR_STATE_FILENAME = "hil_bridge_supervisor.json"
CARD_LEASE_FILENAME = "hil_bridge_card_lease.token"
# The supervisor renews on every reconcile, so this only decides how long
# a remote card stays held after the supervisor dies without releasing.
CARD_LEASE_TTL_SECONDS = 120.0
REMSIM_USB_SELECTOR_FLAGS: tuple[str, ...] = ("-V", "-P", "-C", "-I", "-S", "-A", "-H")
# osmo-remsim-client seeds the card emulator with '3B00' until bankd sends a
# setAtrReq, and it activates the modem against that stub the moment it
# attaches. Passing -a replaces the stub with the operator's real ATR.
# Only an explicit ATR defers the seed: --atr-ignore-rspro pins the client
# to whatever -a carries, so suppressing the seed for it would pin '3B00'.
REMSIM_ATR_FLAGS: tuple[str, ...] = ("-a", "--atr")
_USB_BUS_DEVICE_PATTERN = re.compile(r"\bBus\s+(\d+)\s+Device\s+(\d+):", re.IGNORECASE)
_USB_ID_VIDPID_PATTERN = re.compile(r"\bID\s+([0-9a-f]{4}):([0-9a-f]{4})\b", re.IGNORECASE)
_USB_PLAIN_VIDPID_PATTERN = re.compile(r"\b([0-9a-f]{4}):([0-9a-f]{4})\b", re.IGNORECASE)


def _plausible_atr_hex(value: str) -> str:
    """Return an uppercase ATR worth seeding, or "" when the relay gave none.

    A UICC answers with TS '3B' or '3F' (ETSI TS 102 221 V18.4.0 Annex D),
    so a payload failing that is a placeholder rather than a card, and
    seeding it would swap one wrong ATR for another.
    """
    text = str(value or "").strip().upper()
    if len(text) < 4 or len(text) % 2 != 0:
        return ""
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return ""
    if raw[0] not in (0x3B, 0x3F):
        return ""
    return text


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_cli_args(values: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values or []:
        text = str(value or "").strip()
        if len(text) == 0:
            continue
        normalized.append(text)
    return tuple(normalized)


def _normalize_usb_match_terms(values: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values or []:
        text = str(value or "").strip().lower()
        if len(text) == 0:
            continue
        if text in normalized:
            continue
        normalized.append(text)
    return tuple(normalized)


def normalize_usb_vidpid(value: str) -> str:
    """Normalise a USB VID:PID string to lowercase colon-separated hex (e.g. '04e6:5116')."""
    text = str(value or "").strip().lower()
    if len(text) == 0:
        return ""
    if ":" not in text:
        return ""
    vendor_id, product_id = text.split(":", 1)
    if len(vendor_id) == 0 or len(product_id) == 0:
        return ""
    allowed = set("0123456789abcdef")
    if any(character not in allowed for character in vendor_id):
        return ""
    if any(character not in allowed for character in product_id):
        return ""
    return f"{vendor_id}:{product_id}"


def _normalize_usb_vidpids(values: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values or []:
        vidpid = normalize_usb_vidpid(str(value or ""))
        if len(vidpid) == 0:
            continue
        if vidpid in normalized:
            continue
        normalized.append(vidpid)
    return tuple(normalized)


def _line_matches_usb_selector(
    line: str,
    *,
    match_terms: tuple[str, ...],
    vidpids: tuple[str, ...],
) -> bool:
    normalized_line = str(line or "").strip().lower()
    if len(normalized_line) == 0:
        return False

    for vidpid in vidpids:
        if vidpid in normalized_line:
            return True

    for term in match_terms:
        if term in normalized_line:
            return True

    return False


def _match_lines_from_lsusb_output(
    output: str,
    *,
    match_terms: tuple[str, ...],
    vidpids: tuple[str, ...],
) -> list[str]:
    matches: list[str] = []
    for raw_line in str(output or "").splitlines():
        line = str(raw_line or "").strip()
        if len(line) == 0:
            continue
        if _line_matches_usb_selector(line, match_terms=match_terms, vidpids=vidpids) is False:
            continue
        matches.append(line)
    return matches


@dataclass(frozen=True, slots=True)
class UsbDeviceLocator:
    vendor_id: str = ""
    product_id: str = ""
    address: int = 0
    bus: int = 0

    @property
    def usable_for_remsim(self) -> bool:
        return (
            len(self.vendor_id) == 4
            and len(self.product_id) == 4
            and int(self.address or 0) > 0
        )


def _parse_usb_device_locator_from_text(text: str) -> UsbDeviceLocator | None:
    normalized_text = str(text or "").strip()
    if len(normalized_text) == 0:
        return None

    bus = 0
    address = 0
    vendor_id = ""
    product_id = ""

    bus_device_match = _USB_BUS_DEVICE_PATTERN.search(normalized_text)
    if bus_device_match is not None:
        try:
            bus = int(bus_device_match.group(1))
            address = int(bus_device_match.group(2))
        except (TypeError, ValueError, AttributeError):
            bus = 0
            address = 0

    vidpid_match = _USB_ID_VIDPID_PATTERN.search(normalized_text)
    if vidpid_match is None:
        vidpid_match = _USB_PLAIN_VIDPID_PATTERN.search(normalized_text)
    if vidpid_match is not None:
        vendor_id = str(vidpid_match.group(1) or "").strip().lower()
        product_id = str(vidpid_match.group(2) or "").strip().lower()

    if bus <= 0 and address <= 0 and len(vendor_id) == 0 and len(product_id) == 0:
        return None
    return UsbDeviceLocator(
        vendor_id=vendor_id,
        product_id=product_id,
        address=address,
        bus=bus,
    )


def _device_locators_from_match_lines(lines: list[str] | tuple[str, ...]) -> tuple[UsbDeviceLocator, ...]:
    devices: list[UsbDeviceLocator] = []
    seen: set[tuple[str, str, int, int]] = set()
    for line in lines:
        locator = _parse_usb_device_locator_from_text(line)
        if locator is None:
            continue
        locator_key = (
            str(locator.vendor_id or ""),
            str(locator.product_id or ""),
            int(locator.address or 0),
            int(locator.bus or 0),
        )
        if locator_key in seen:
            continue
        seen.add(locator_key)
        devices.append(locator)
    return tuple(devices)


def _pid_exists(pid: int) -> bool:
    if int(pid or 0) <= 0:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class UsbPresenceSnapshot:
    source: str
    present: bool
    matches: tuple[str, ...] = ()
    error: str = ""
    devices: tuple[UsbDeviceLocator, ...] = ()

    @property
    def detection_ok(self) -> bool:
        return len(self.error) == 0


class UsbPresenceMonitor(Protocol):
    def snapshot(self) -> UsbPresenceSnapshot:
        raise NotImplementedError

    def wait_for_change(self, timeout_seconds: float) -> None:
        raise NotImplementedError


@dataclass(slots=True)
class LsusbPresenceMonitor:
    match_terms: tuple[str, ...]
    vidpids: tuple[str, ...]
    lsusb_path: str = "lsusb"
    timeout_seconds: float = DEFAULT_LSUSB_TIMEOUT_SECONDS

    def snapshot(self) -> UsbPresenceSnapshot:
        """Return a snapshot dict of the current connection state for all managed channels."""
        command = [str(self.lsusb_path or "lsusb")]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(1.0, float(self.timeout_seconds or DEFAULT_LSUSB_TIMEOUT_SECONDS)),
                check=False,
            )
        except FileNotFoundError as exc:
            return UsbPresenceSnapshot(
                source="lsusb",
                present=False,
                error=f"lsusb not found: {exc}",
            )
        except subprocess.TimeoutExpired as exc:
            return UsbPresenceSnapshot(
                source="lsusb",
                present=False,
                error=f"lsusb timed out: {exc}",
            )

        if completed.returncode != 0:
            error_text = str(completed.stderr or completed.stdout or "").strip()
            if len(error_text) == 0:
                error_text = f"lsusb exited with status {completed.returncode}"
            return UsbPresenceSnapshot(
                source="lsusb",
                present=False,
                error=error_text,
            )

        matches = _match_lines_from_lsusb_output(
            completed.stdout,
            match_terms=self.match_terms,
            vidpids=self.vidpids,
        )
        return UsbPresenceSnapshot(
            source="lsusb",
            present=len(matches) > 0,
            matches=tuple(matches),
            devices=_device_locators_from_match_lines(matches),
        )

    def wait_for_change(self, timeout_seconds: float) -> None:
        time.sleep(max(0.1, float(timeout_seconds or DEFAULT_POLL_INTERVAL_SECONDS)))


@dataclass(slots=True)
class PyudevPresenceMonitor:
    match_terms: tuple[str, ...]
    vidpids: tuple[str, ...]
    _context: Any
    _monitor: Any

    @classmethod
    def create(
        cls,
        *,
        match_terms: tuple[str, ...],
        vidpids: tuple[str, ...],
    ) -> "PyudevPresenceMonitor":
        """Create a new managed channel entry for the given slot configuration."""
        import pyudev

        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="usb")
        monitor.start()
        return cls(
            match_terms=match_terms,
            vidpids=vidpids,
            _context=context,
            _monitor=monitor,
        )

    def snapshot(self) -> UsbPresenceSnapshot:
        """Return a snapshot dict of the current state of this managed channel."""
        matches: list[str] = []
        try:
            devices = list(self._context.list_devices(subsystem="usb"))
        except Exception as exc:
            return UsbPresenceSnapshot(
                source="pyudev",
                present=False,
                error=f"pyudev enumeration failed: {exc}",
            )

        for device in devices:
            device_type = str(getattr(device, "device_type", "") or "").strip().lower()
            if len(device_type) > 0 and device_type != "usb_device":
                continue
            if self._device_matches(device) is False:
                continue
            matches.append(self._describe_device(device))

        return UsbPresenceSnapshot(
            source="pyudev",
            present=len(matches) > 0,
            matches=tuple(matches),
            devices=_device_locators_from_match_lines(matches),
        )

    def wait_for_change(self, timeout_seconds: float) -> None:
        wait_seconds = max(0.1, float(timeout_seconds or DEFAULT_POLL_INTERVAL_SECONDS))
        try:
            self._monitor.poll(timeout=wait_seconds)
        except (OSError, RuntimeError):
            time.sleep(wait_seconds)

    def _device_matches(self, device: Any) -> bool:
        vendor_id = str(device.get("ID_VENDOR_ID", "") or "").strip().lower()
        product_id = str(device.get("ID_MODEL_ID", "") or "").strip().lower()
        vidpid = ""
        if len(vendor_id) > 0 and len(product_id) > 0:
            vidpid = f"{vendor_id}:{product_id}"
            if vidpid in self.vidpids:
                return True

        for text in self._device_match_texts(device):
            if _line_matches_usb_selector(text, match_terms=self.match_terms, vidpids=self.vidpids):
                return True

        return False

    def _describe_device(self, device: Any) -> str:
        vendor_id = str(device.get("ID_VENDOR_ID", "") or "").strip().lower()
        product_id = str(device.get("ID_MODEL_ID", "") or "").strip().lower()
        bus_number = str(device.get("BUSNUM", "") or "").strip()
        device_number = str(device.get("DEVNUM", "") or "").strip()
        vendor_name = str(device.get("ID_VENDOR_FROM_DATABASE", "") or device.get("ID_VENDOR", "") or "").strip()
        model_name = str(device.get("ID_MODEL_FROM_DATABASE", "") or device.get("ID_MODEL", "") or "").strip()
        serial = str(device.get("ID_SERIAL_SHORT", "") or "").strip()
        parts: list[str] = []
        try:
            if len(bus_number) > 0 and len(device_number) > 0:
                parts.append(f"Bus {int(bus_number):03d} Device {int(device_number):03d}:")
        except (TypeError, ValueError):
            pass
        if len(vendor_id) > 0 and len(product_id) > 0:
            parts.append(f"ID {vendor_id}:{product_id}")
        if len(vendor_name) > 0 or len(model_name) > 0:
            parts.append(" ".join(part for part in (vendor_name, model_name) if len(part) > 0))
        if len(serial) > 0:
            parts.append(serial)
        if len(parts) == 0:
            parts.append(str(getattr(device, "sys_name", "") or getattr(device, "device_path", "") or "usb-device"))
        return " ".join(part for part in parts if len(part) > 0)

    def _device_match_texts(self, device: Any) -> list[str]:
        values = [
            str(device.get("ID_VENDOR_FROM_DATABASE", "") or ""),
            str(device.get("ID_MODEL_FROM_DATABASE", "") or ""),
            str(device.get("ID_VENDOR", "") or ""),
            str(device.get("ID_MODEL", "") or ""),
            str(device.get("ID_SERIAL", "") or ""),
            str(device.get("PRODUCT", "") or ""),
            str(getattr(device, "sys_name", "") or ""),
            str(getattr(device, "device_path", "") or ""),
        ]
        return [value for value in values if len(value.strip()) > 0]


def create_usb_presence_monitor(
    *,
    match_terms: tuple[str, ...],
    vidpids: tuple[str, ...],
    prefer_pyudev: bool,
    lsusb_path: str,
) -> UsbPresenceMonitor:
    """Create a USB device presence monitor thread that detects reader hot-plug events."""
    if prefer_pyudev:
        try:
            monitor = PyudevPresenceMonitor.create(match_terms=match_terms, vidpids=vidpids)
        except Exception as exc:
            LOGGER.warning("pyudev hotplug monitor unavailable; falling back to lsusb polling: %s", exc)
        else:
            LOGGER.info("Using pyudev USB hotplug monitor for bridge supervision.")
            return monitor

    LOGGER.info("Using lsusb polling fallback for bridge supervision.")
    return LsusbPresenceMonitor(
        match_terms=match_terms,
        vidpids=vidpids,
        lsusb_path=lsusb_path,
    )


@dataclass(frozen=True, slots=True)
class HilBridgeSupervisorConfig:
    bridge: BridgeConfig
    remsim_client: "RemsimClientConfig" = field(default_factory=lambda: RemsimClientConfig())
    device_reset: SimtraceResetConfig = field(default_factory=SimtraceResetConfig)
    debug_enabled: bool = False
    bridge_python: str = sys.executable
    usb_match_terms: tuple[str, ...] = DEFAULT_USB_MATCH_TERMS
    usb_vidpids: tuple[str, ...] = ()
    prefer_pyudev: bool = True
    lsusb_path: str = "lsusb"
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS
    restart_backoff_seconds: float = DEFAULT_RESTART_BACKOFF_SECONDS
    remote_card_restart_backoff_seconds: float = DEFAULT_REMOTE_CARD_RESTART_BACKOFF_SECONDS
    termination_timeout_seconds: float = DEFAULT_TERMINATION_TIMEOUT_SECONDS
    state_path: str = field(default_factory=lambda: runtime_path("state", SUPERVISOR_STATE_FILENAME))
    remote_card_lease_enabled: bool = True
    card_lease_path: str = field(
        default_factory=lambda: runtime_path("state", CARD_LEASE_FILENAME)
    )
    # A modem that was already powered has nothing to re-read when the card
    # path comes back, so it keeps answering "no SIM" while this supervisor
    # reports running with the lease held. The GUI sends this refresh when
    # an operator starts a session; an automatic reconnect is a connect
    # too, and nothing else will send it.
    modem_at_device: str = ""
    modem_refresh_min_interval_seconds: float = 60.0


@dataclass(frozen=True, slots=True)
class RemsimClientConfig:
    enabled: bool = True
    binary: str = "osmo-remsim-client-st2"
    host: str = ""
    port: int = 0
    client_id: int | None = None
    client_slot: int | None = None
    extra_args: tuple[str, ...] = ()


@dataclass(slots=True)
class HilBridgeSupervisor:
    config: HilBridgeSupervisorConfig
    usb_monitor: UsbPresenceMonitor
    popen_factory: Any = subprocess.Popen
    monotonic: Any = time.monotonic
    _child: Any = field(default=None, init=False, repr=False)
    _remsim_child: Any = field(default=None, init=False, repr=False)
    _stop_event: Event = field(default_factory=Event, init=False, repr=False)
    _next_start_not_before: float = field(default=0.0, init=False, repr=False)
    _next_remsim_start_not_before: float = field(default=0.0, init=False, repr=False)
    _next_modem_refresh_not_before: float = field(default=0.0, init=False, repr=False)
    _pending_modem_refresh_at: float = field(default=0.0, init=False, repr=False)
    _modem_refresh_attempts: int = field(default=0, init=False, repr=False)
    _next_start_reason: str = field(default="", init=False, repr=False)
    _next_device_reset_not_before: float = field(default=0.0, init=False, repr=False)
    _device_reset_outcome: SimtraceResetOutcome | None = field(default=None, init=False, repr=False)
    _device_reset_at: str = field(default="", init=False, repr=False)
    _device_reset_count: int = field(default=0, init=False, repr=False)
    _card_lease_token: str = field(default="", init=False, repr=False)
    _card_lease_state: str = field(default="none", init=False, repr=False)
    _card_lease_holder: str = field(default="", init=False, repr=False)
    _card_lease_renew_after: float = field(default=0.0, init=False, repr=False)
    _remote_card_atr_hex: str = field(default="", init=False, repr=False)

    def request_stop(self) -> None:
        self._stop_event.set()

    def run(self) -> int:
        """Run the supervisor event loop until the stop signal is received."""
        LOGGER.info(
            "HIL bridge supervisor started with USB selectors terms=%s vidpids=%s",
            list(self.config.usb_match_terms),
            list(self.config.usb_vidpids),
        )
        try:
            while self._stop_event.is_set() is False:
                self.reconcile()
                if self._stop_event.is_set():
                    break
                # Keep hotplug detection live regardless of card
                # backend: even sim mode benefits from noticing
                # SIMtrace2 attach / detach so REMSIM follows the
                # cable in modem-in-the-loop sessions.
                self.usb_monitor.wait_for_change(self.config.poll_interval_seconds)
        finally:
            self._stop_remsim_child("supervisor shutdown")
            self._stop_bridge_child("supervisor shutdown")
            self.release_card_lease()
            self._write_state(
                status="stopped",
                snapshot=UsbPresenceSnapshot(source="supervisor", present=False),
                reason="Supervisor stopped.",
            )
        return 0

    def _sim_backend_active(self) -> bool:
        # Sim mode is determined at reconcile time (not init time) so
        # an operator who toggles ``YGGDRASIM_CARD_BACKEND`` between
        # supervisor cycles via ``systemctl --user restart`` always
        # gets the matching gate behaviour. The check is cheap and
        # intentionally tolerates env / persisted settings out of
        # sync.
        try:
            return bool(is_simulated_card_backend())
        except Exception:  # noqa: BLE001 - card_backend resolver should never break the supervisor loop
            return False

    def _service_pending_modem_refresh(self, now: float) -> None:
        """Send an armed SIM refresh once the card path has had time to settle."""
        if self._pending_modem_refresh_at <= 0.0 or now < self._pending_modem_refresh_at:
            return
        if self._bridge_is_running() is False or self._remsim_is_running() is False:
            # The path fell over again before it settled; re-arm with the
            # children rather than refresh a modem with nothing behind it.
            self._pending_modem_refresh_at = 0.0
            return
        self._pending_modem_refresh_at = 0.0
        self._refresh_modem_sim_interface()

    def reconcile(self) -> None:
        """Reconcile the desired-state channel config against the running connections."""
        now = float(self.monotonic())
        self._service_pending_modem_refresh(now)
        sim_mode = self._sim_backend_active()
        snapshot = self.usb_monitor.snapshot()
        self._reconcile_child_exit(now)
        if self._bridge_is_running() is False and self._remsim_is_running():
            self._stop_remsim_child("bridge child is not active")
        self._reconcile_remsim_child_exit(now)

        if snapshot.detection_ok is False and sim_mode is False:
            status = "usb-detect-error"
            if self._bridge_is_running():
                status = "running"
            self._write_state(
                status=status,
                snapshot=snapshot,
                reason=f"USB detection failed: {snapshot.error}",
            )
            return

        # Bridge gate: USB-present in reader mode, always-on in sim mode.
        # REMSIM gate: USB-present regardless of card backend, because
        # REMSIM only makes sense when SIMtrace2 is on the bus.
        bridge_allowed = bool(snapshot.present) or bool(sim_mode)
        remsim_allowed = bool(self.config.remsim_client.enabled) and bool(snapshot.present)

        if bridge_allowed:
            bridge_running = self._bridge_is_running()
            if bridge_running is False:
                if self._remsim_is_running() and remsim_allowed is False:
                    self._stop_remsim_child("bridge child is not active")
                if now < self._next_start_not_before:
                    remaining = max(0.0, self._next_start_not_before - now)
                    self._write_state(
                        status="restart-pending",
                        snapshot=snapshot,
                        reason=self._bridge_restart_pending_reason(remaining),
                    )
                    return
                if self.claim_card_lease() is False:
                    self._next_start_not_before = (
                        now + self._bridge_restart_backoff_seconds()
                    )
                    self._write_state(
                        status="card-leased",
                        snapshot=snapshot,
                        reason=(
                            "The remote card is held by another consumer. "
                            "Waiting for it to be released before starting "
                            "the bridge."
                        ),
                    )
                    return
                # Clear the board before every new session generation.
                # The reset re-enumerates the SIMtrace2 under a fresh USB
                # address, so both children below must be started from the
                # snapshot this returns rather than the pre-reset one.
                snapshot = self._reset_device_before_session(snapshot)
                remsim_allowed = bool(self.config.remsim_client.enabled) and bool(snapshot.present)
                self._start_bridge_child(snapshot)
                bridge_running = self._bridge_is_running()

            if bridge_running:
                self.renew_card_lease()
                if remsim_allowed is False:
                    if self._remsim_is_running():
                        # Cable was pulled while sim mode remained
                        # selected -- bridge stays up, REMSIM goes.
                        self._stop_remsim_child("SIMtrace2 hardware disappeared.")
                    reason_text = self._sim_no_usb_reason() if sim_mode and snapshot.present is False else self._reader_no_remsim_reason(snapshot)
                    self._write_state(
                        status="running",
                        snapshot=snapshot,
                        reason=reason_text,
                    )
                    return
                if self._remsim_is_running():
                    self._write_state(
                        status="running",
                        snapshot=snapshot,
                        reason="SIMtrace2 present; bridge and REMSIM client children are active.",
                    )
                    return
                if now < self._next_remsim_start_not_before:
                    remaining = max(0.0, self._next_remsim_start_not_before - now)
                    self._write_state(
                        status="client-restart-pending",
                        snapshot=snapshot,
                        reason=f"Waiting {remaining:.1f}s before REMSIM client restart.",
                    )
                    return
                self._start_remsim_child(snapshot)
                return
            return

        # Bridge not allowed: reader mode, USB absent.
        if self._remsim_is_running():
            self._stop_remsim_child("SIMtrace2 hardware disappeared.")
        if self._bridge_is_running():
            self._stop_bridge_child("SIMtrace2 hardware disappeared.")
        self._write_state(
            status="waiting-usb",
            snapshot=snapshot,
            reason="SIMtrace2 hardware not detected.",
        )

    def _sim_no_usb_reason(self) -> str:
        return (
            "Simulated card backend; bridge child is active without "
            "SIMtrace2 attached. REMSIM client stays down until USB "
            "presence returns."
        )

    def _reader_no_remsim_reason(self, snapshot: UsbPresenceSnapshot) -> str:
        if self.config.remsim_client.enabled is False:
            return "SIMtrace2 present; bridge child is active. REMSIM client management is disabled."
        return "SIMtrace2 present; bridge child is active."

    def _bridge_uses_remote_card(self) -> bool:
        remote_card_url = str(
            getattr(self.config.bridge, "remote_card_url", "") or ""
        ).strip()
        return len(remote_card_url) > 0

    def _remote_card_lease_wanted(self) -> bool:
        """True when this bridge should hold a lease on the remote card."""
        if self.config.remote_card_lease_enabled is False:
            return False
        return self._bridge_uses_remote_card()

    def _remote_card_endpoints(self) -> tuple[str, str]:
        """Return the remote relay's lease URL and bearer token."""
        bridge = self.config.bridge
        url = str(getattr(bridge, "remote_card_url", "") or "").strip()
        token = resolve_remote_card_token(
            explicit_token_file=str(
                getattr(bridge, "remote_card_token_file", "") or ""
            ).strip()
        )
        return build_card_relay_lease_url(url), token

    def refresh_remote_card_atr(self) -> str:
        """Read the remote card's ATR so the REMSIM client can be seeded with it.

        Returns "" when the bridge runs a local reader, when the relay
        reports no usable ATR, or when it cannot be reached. The caller
        then starts the client unseeded, which is what it did before.
        """
        self._remote_card_atr_hex = ""
        if self._bridge_uses_remote_card() is False:
            return ""
        bridge = self.config.bridge
        url = str(getattr(bridge, "remote_card_url", "") or "").strip()
        if len(url) == 0:
            return ""
        token = resolve_remote_card_token(
            explicit_token_file=str(
                getattr(bridge, "remote_card_token_file", "") or ""
            ).strip()
        )
        try:
            payload = _request_card_relay_json(
                build_card_relay_status_url(url),
                method="GET",
                timeout_seconds=5,
                auth_token=token,
            )
        except Exception as status_error:  # noqa: BLE001
            LOGGER.warning(
                "Cannot read the remote card ATR (%s); the REMSIM client will "
                "present its placeholder until bankd overrides it.",
                status_error,
            )
            return ""
        atr_hex = _plausible_atr_hex(str(payload.get("atr") or ""))
        if len(atr_hex) == 0:
            LOGGER.warning(
                "Remote card relay reported no usable ATR; the REMSIM client "
                "will present its placeholder until bankd overrides it."
            )
            return ""
        self._remote_card_atr_hex = atr_hex
        LOGGER.info("Seeding the REMSIM client with the remote card ATR %s", atr_hex)
        return atr_hex

    def _card_lease_holder_name(self) -> str:
        return f"hil-supervisor@{os.uname().nodename}" if hasattr(os, "uname") else "hil-supervisor"

    def claim_card_lease(self) -> bool:
        """Take the lease on the operator's card before the bridge starts.

        Returns False only when another consumer holds the card, which is
        the one case where starting the bridge would interleave two
        masters on one card. Every other outcome, including an upstream
        that grants no lease at all, proceeds unleased so a relay without
        a bearer token keeps working exactly as it did before.
        """
        if self._remote_card_lease_wanted() is False:
            return True
        if len(self._card_lease_token) > 0:
            return True
        lease_url, token = self._remote_card_endpoints()
        try:
            payload = _request_card_relay_json(
                lease_url,
                method="POST",
                request_json={
                    "holder": self._card_lease_holder_name(),
                    "ttlSeconds": CARD_LEASE_TTL_SECONDS,
                },
                timeout_seconds=5,
                auth_token=token,
            )
        except Exception as claim_error:  # noqa: BLE001
            status = int(getattr(claim_error, "status", 0) or 0)
            if status == 409:
                self._card_lease_state = "held-elsewhere"
                self._card_lease_holder = ""
                LOGGER.warning(
                    "Remote card is leased by another consumer; "
                    "not starting the bridge child."
                )
                return False
            self._card_lease_state = "unavailable"
            LOGGER.info(
                "Remote card relay grants no lease (%s); proceeding unleased.",
                claim_error,
            )
            return True
        lease_token = str(payload.get("leaseToken") or "").strip()
        if len(lease_token) == 0:
            self._card_lease_state = "unavailable"
            return True
        self._card_lease_token = lease_token
        self._card_lease_state = "held"
        self._card_lease_holder = self._card_lease_holder_name()
        self._card_lease_renew_after = float(self.monotonic()) + (
            CARD_LEASE_TTL_SECONDS / 3.0
        )
        self._write_card_lease_file(lease_token)
        LOGGER.info("Holding the remote card lease for this bridge generation.")
        return True

    def renew_card_lease(self) -> None:
        """Push the lease out by another TTL once it is a third spent."""
        if len(self._card_lease_token) == 0:
            return
        now = float(self.monotonic())
        if now < self._card_lease_renew_after:
            return
        self._card_lease_renew_after = now + (CARD_LEASE_TTL_SECONDS / 3.0)
        lease_url, token = self._remote_card_endpoints()
        try:
            payload = _request_card_relay_json(
                lease_url,
                method="POST",
                request_json={
                    "leaseToken": self._card_lease_token,
                    "holder": self._card_lease_holder_name(),
                    "ttlSeconds": CARD_LEASE_TTL_SECONDS,
                },
                timeout_seconds=5,
                auth_token=token,
            )
        except Exception as renew_error:  # noqa: BLE001
            LOGGER.warning("Remote card lease renewal failed: %s", renew_error)
            return
        renewed = str(payload.get("leaseToken") or "").strip()
        if len(renewed) > 0 and renewed != self._card_lease_token:
            # The relay handed back a different token, so the lease was
            # re-established rather than renewed. Adopt it, or every call
            # that presents the old one is refused.
            self._card_lease_token = renewed
            self._write_card_lease_file(renewed)

    def release_card_lease(self) -> None:
        """Drop the lease and remove the file the bridge child reads."""
        token = self._card_lease_token
        self._card_lease_token = ""
        self._card_lease_state = "none"
        self._card_lease_holder = ""
        self._card_lease_renew_after = 0.0
        self._remove_card_lease_file()
        if len(token) == 0:
            return
        lease_url, auth_token = self._remote_card_endpoints()
        try:
            _request_card_relay_json(
                lease_url,
                method="DELETE",
                request_json={"leaseToken": token},
                timeout_seconds=5,
                auth_token=auth_token,
            )
        except Exception as release_error:  # noqa: BLE001
            LOGGER.warning(
                "Remote card lease release failed: %s; the TTL will free it.",
                release_error,
            )

    def _write_card_lease_file(self, lease_token: str) -> None:
        """Hand the lease to the bridge child through a 0600 file.

        A command-line argument would put the lease in every process
        listing on the host, which is the reason the bearer token already
        travels as a file path rather than a value.
        """
        path = str(self.config.card_lease_path or "").strip()
        if len(path) == 0:
            return
        try:
            ensure_runtime_dir(os.path.dirname(path))
            write_token_file(Path(path), lease_token)
        except OSError as write_error:
            LOGGER.warning(
                "Cannot write the card lease file %s: %s", path, write_error
            )

    def _remove_card_lease_file(self) -> None:
        path = str(self.config.card_lease_path or "").strip()
        if len(path) == 0:
            return
        try:
            os.remove(path)
        except FileNotFoundError:
            return
        except OSError as remove_error:
            LOGGER.warning(
                "Cannot remove the card lease file %s: %s", path, remove_error
            )

    def _bridge_restart_backoff_seconds(self) -> float:
        default_backoff = max(0.0, float(self.config.restart_backoff_seconds))
        if self._bridge_uses_remote_card() is False:
            return default_backoff
        remote_backoff = max(
            default_backoff,
            float(self.config.remote_card_restart_backoff_seconds),
        )
        return remote_backoff

    def _bridge_restart_pending_reason(self, remaining_seconds: float) -> str:
        base = f"Waiting {remaining_seconds:.1f}s before bridge restart."
        if len(self._next_start_reason.strip()) == 0:
            return base
        return f"{base} {self._next_start_reason.strip()}"

    def _reset_device_before_session(self, snapshot: UsbPresenceSnapshot) -> UsbPresenceSnapshot:
        """Reboot the SIMtrace2 board before a new bridge generation starts.

        This is the remote stand-in for the board's physical reset
        button: the cardem firmware reboots its microcontroller as soon
        as USB drops below the ``CONFIGURED`` state, so a host-issued
        USB reset (or a VBUS cycle) leaves the card-emulation state
        machine as clean as a power-up.

        Returns the snapshot later starts should use. A successful
        reset re-enumerates the board under a *new* USB device address,
        and ``osmo-remsim-client-st2`` is pinned to that address with
        ``-A``, so continuing with the pre-reset snapshot would hand the
        client a stale selector.
        """
        config = self.config.device_reset
        if config.enabled is False:
            return snapshot
        if bool(snapshot.present) is False:
            return snapshot

        now = float(self.monotonic())
        if now < self._next_device_reset_not_before:
            LOGGER.debug(
                "Skipping SIMtrace2 reset; next attempt allowed in %.1fs",
                max(0.0, self._next_device_reset_not_before - now),
            )
            return snapshot

        if self._remsim_is_running():
            # Never reset the bus underneath an open libusb handle.
            self._stop_remsim_child("resetting the SIMtrace2 board")

        device = next(
            (candidate for candidate in snapshot.devices if candidate.usable_for_remsim),
            None,
        )
        outcome = reset_simtrace_device(
            config=config,
            bus=getattr(device, "bus", 0),
            address=getattr(device, "address", 0),
            presence_probe=self._usb_presence_probe,
        )
        self._next_device_reset_not_before = float(self.monotonic()) + max(
            0.0,
            float(config.min_interval_seconds or 0.0),
        )
        self._device_reset_outcome = outcome
        self._device_reset_at = _utc_timestamp()
        if outcome.performed:
            self._device_reset_count += 1
            LOGGER.info("SIMtrace2 reset before session (%s): %s", outcome.mode, outcome.detail)
        else:
            LOGGER.warning(
                "SIMtrace2 reset before session did not run: %s",
                outcome.error or outcome.detail,
            )
            return snapshot

        refreshed = self.usb_monitor.snapshot()
        if refreshed.detection_ok and refreshed.present:
            return refreshed
        return snapshot

    def _usb_presence_probe(self) -> bool:
        snapshot = self.usb_monitor.snapshot()
        return bool(snapshot.detection_ok) and bool(snapshot.present)

    def _device_reset_state_payload(self) -> dict[str, Any]:
        config = self.config.device_reset
        payload: dict[str, Any] = {
            "mode": normalize_reset_mode(config.mode),
            "enabled": bool(config.enabled),
            "count": int(self._device_reset_count),
            "lastAt": str(self._device_reset_at or ""),
            "minIntervalSeconds": float(config.min_interval_seconds or 0.0),
            "settleTimeoutSeconds": float(config.settle_timeout_seconds or 0.0),
            "uhubctlLocation": str(config.uhubctl_location or ""),
            "uhubctlPort": str(config.uhubctl_port or ""),
        }
        outcome = self._device_reset_outcome
        if outcome is not None:
            payload["last"] = outcome.as_state_payload()
        return payload

    def _start_bridge_child(self, snapshot: UsbPresenceSnapshot) -> None:
        self._cleanup_stale_bridge_marker()
        command = self._build_bridge_command()
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        if self.config.debug_enabled:
            env["YGGDRASIM_GLOBAL_DEBUG"] = "1"
        try:
            child = self.popen_factory(
                command,
                cwd=os.getcwd(),
                env=env,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception as exc:
            self._next_start_not_before = float(self.monotonic()) + float(self.config.restart_backoff_seconds)
            self._next_start_reason = ""
            self._write_state(
                status="start-failed",
                snapshot=snapshot,
                reason=f"Bridge child failed to start: {exc}",
            )
            LOGGER.error("Bridge child start failed: %s", exc)
            return

        self._child = child
        self._next_start_not_before = 0.0
        self._next_start_reason = ""
        LOGGER.info("Started bridge child pid=%s", getattr(child, "pid", 0))
        reason = "SIMtrace2 present; bridge child started."
        if self.config.remsim_client.enabled:
            reason = "SIMtrace2 present; bridge child started. REMSIM client launch is pending."
        self._write_state(
            status="running",
            snapshot=snapshot,
            reason=reason,
        )

    def _start_remsim_child(self, snapshot: UsbPresenceSnapshot) -> None:
        if self.config.remsim_client.enabled is False:
            return
        self.refresh_remote_card_atr()
        command = self._build_remsim_command(snapshot=snapshot)
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        if self.config.debug_enabled:
            env["YGGDRASIM_GLOBAL_DEBUG"] = "1"
        try:
            child = self.popen_factory(
                command,
                cwd=os.getcwd(),
                env=env,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception as exc:
            self._next_remsim_start_not_before = float(self.monotonic()) + float(self.config.restart_backoff_seconds)
            self._write_state(
                status="client-start-failed",
                snapshot=snapshot,
                reason=f"REMSIM client failed to start: {exc}",
            )
            LOGGER.error("REMSIM client start failed: %s", exc)
            return

        self._remsim_child = child
        self._next_remsim_start_not_before = 0.0
        LOGGER.info("Started REMSIM client pid=%s", getattr(child, "pid", 0))
        # Arm rather than send: the client has only just been spawned and
        # has not dialled in or presented the card yet, so a refresh now
        # makes the modem look for a SIM that is not there yet and settle
        # on "not inserted".
        self._modem_refresh_attempts = 0
        self._pending_modem_refresh_at = (
            float(self.monotonic()) + MODEM_REFRESH_SETTLE_SECONDS
        )
        self._write_state(
            status="running",
            snapshot=snapshot,
            reason="SIMtrace2 present; bridge and REMSIM client children are active.",
        )

    def _refresh_modem_sim_interface(self) -> None:
        """Tell the modem to re-read the SIM now the card path is up again.

        Best effort and never fatal: the card is streaming either way, and
        a rig whose AT port is held by something else must not lose its
        session over it. Rate limited because a crash-looping child would
        otherwise cycle the radio continuously.
        """
        device = str(getattr(self.config, "modem_at_device", "") or "").strip()
        if len(device) == 0 or self._bridge_uses_remote_card() is False:
            return
        now = float(self.monotonic())
        interval = float(
            getattr(self.config, "modem_refresh_min_interval_seconds", 60.0)
        )
        if self._next_modem_refresh_not_before > now:
            return
        self._next_modem_refresh_not_before = now + max(0.0, interval)
        quoted = shlex.quote(device)
        command = (
            f"test -c {quoted} && "
            f"printf 'AT+CFUN=0;+CFUN=1\r' | "
            f"timeout 8 socat -T6 - {quoted},b115200,raw,echo=0"
        )
        try:
            subprocess.run(
                ["/bin/sh", "-c", command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            LOGGER.warning("Modem SIM refresh could not be sent: %s", error)
            return
        LOGGER.info("Sent the SIM refresh to %s after the card path came up", device)
        # The settle delay is a guess about how long the REMSIM client
        # needs to present the card, and a busy rig or a USB
        # re-enumeration can outlast it. A refresh that landed too early
        # leaves the modem on "not inserted" for good, so the result is
        # checked and the attempt re-armed rather than assumed.
        if self._modem_reports_sim_ready(device):
            self._modem_refresh_attempts = 0
            return
        self._modem_refresh_attempts += 1
        if self._modem_refresh_attempts >= MODEM_REFRESH_MAX_ATTEMPTS:
            LOGGER.warning(
                "Modem still reports no SIM after %d refresh attempts on %s",
                self._modem_refresh_attempts,
                device,
            )
            self._modem_refresh_attempts = 0
            return
        backoff = MODEM_REFRESH_SETTLE_SECONDS * (self._modem_refresh_attempts + 1)
        self._pending_modem_refresh_at = float(self.monotonic()) + backoff
        LOGGER.info(
            "Modem has not taken the SIM yet; retrying the refresh in %.0fs", backoff
        )

    def _modem_reports_sim_ready(self, device: str) -> bool:
        """Ask the modem whether it now sees the card. Unknown counts as no.

        AT+CFUN=0;+CFUN=1 makes this modem re-enumerate: the AT port is
        destroyed and recreated a second or so later. Probing through the
        gap finds no device, reads as "no SIM", and re-arms a refresh that
        was in fact working -- and every extra refresh drops the port
        again under anyone with a terminal open on it.
        """
        if self._wait_for_modem_port(device) is False:
            return False
        quoted = shlex.quote(device)
        command = (
            f"printf 'AT+CPIN?\r' | "
            f"timeout 8 socat -T6 - {quoted},b115200,raw,echo=0"
        )
        try:
            probe = subprocess.run(
                ["/bin/sh", "-c", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return "+CPIN: READY" in str(probe.stdout or "")

    def _wait_for_modem_port(self, device: str) -> bool:
        """Wait for the AT port to come back after a re-enumeration."""
        deadline = float(self.monotonic()) + MODEM_PORT_RETURN_TIMEOUT_SECONDS
        while True:
            try:
                if os.path.exists(device):
                    # Present is not the same as openable: udev has to
                    # finish setting the mode before the probe can talk.
                    time.sleep(MODEM_PORT_SETTLE_SECONDS)
                    return True
            except OSError:
                pass
            if float(self.monotonic()) >= deadline:
                return False
            time.sleep(0.25)

    def _stop_bridge_child(self, reason: str) -> None:
        child = self._child
        if child is None:
            self._cleanup_stale_bridge_marker()
            return

        self._child = None
        pid = int(getattr(child, "pid", 0) or 0)
        LOGGER.info("Stopping bridge child pid=%s: %s", pid, reason)
        signaled_group = self._signal_child_process_group(pid, signal.SIGTERM)
        if signaled_group is False:
            try:
                child.terminate()
            except (OSError, ProcessLookupError):
                pass

        try:
            child.wait(timeout=max(1.0, float(self.config.termination_timeout_seconds)))
        except (subprocess.TimeoutExpired, OSError):
            killed_group = self._signal_child_process_group(pid, _SIGKILL)
            if killed_group is False:
                try:
                    child.kill()
                except (OSError, ProcessLookupError):
                    pass
            try:
                child.wait(timeout=1.0)
            except (subprocess.TimeoutExpired, OSError):
                pass

        self._cleanup_stale_bridge_marker(managed_pid=pid)

    def _stop_remsim_child(self, reason: str) -> None:
        child = self._remsim_child
        if child is None:
            return

        self._remsim_child = None
        pid = int(getattr(child, "pid", 0) or 0)
        LOGGER.info("Stopping REMSIM client pid=%s: %s", pid, reason)
        signaled_group = self._signal_child_process_group(pid, signal.SIGTERM)
        if signaled_group is False:
            try:
                child.terminate()
            except (OSError, ProcessLookupError):
                pass

        try:
            child.wait(timeout=max(1.0, float(self.config.termination_timeout_seconds)))
        except (subprocess.TimeoutExpired, OSError):
            killed_group = self._signal_child_process_group(pid, _SIGKILL)
            if killed_group is False:
                try:
                    child.kill()
                except (OSError, ProcessLookupError):
                    pass
            try:
                child.wait(timeout=1.0)
            except (subprocess.TimeoutExpired, OSError):
                pass

    def _reconcile_child_exit(self, now: float) -> None:
        child = self._child
        if child is None:
            return
        return_code = child.poll()
        if return_code is None:
            return

        pid = int(getattr(child, "pid", 0) or 0)
        self._child = None
        restart_backoff = self._bridge_restart_backoff_seconds()
        self._next_start_not_before = now + restart_backoff
        self._next_start_reason = ""
        if self._bridge_uses_remote_card():
            self._next_start_reason = (
                "Remote card relay is configured; the PC Card Bridge or SSH "
                "reverse tunnel may be unavailable."
            )
        self._cleanup_stale_bridge_marker(managed_pid=pid)
        LOGGER.warning(
            "Bridge child pid=%s exited with code %s; next restart in %.1fs",
            pid,
            return_code,
            restart_backoff,
        )
        if self._remsim_is_running():
            self._stop_remsim_child("bridge child exited unexpectedly")

    def _reconcile_remsim_child_exit(self, now: float) -> None:
        child = self._remsim_child
        if child is None:
            return
        return_code = child.poll()
        if return_code is None:
            return

        pid = int(getattr(child, "pid", 0) or 0)
        self._remsim_child = None
        self._next_remsim_start_not_before = now + float(self.config.restart_backoff_seconds)
        LOGGER.warning("REMSIM client pid=%s exited with code %s", pid, return_code)

    def _bridge_is_running(self) -> bool:
        child = self._child
        if child is None:
            return False
        return child.poll() is None

    def _remsim_is_running(self) -> bool:
        child = self._remsim_child
        if child is None:
            return False
        return child.poll() is None

    def _build_bridge_command(self) -> list[str]:
        bridge = self.config.bridge
        command = build_module_command(
            "Tools.HilBridge.main",
            source_python=str(self.config.bridge_python or "").strip() or None,
        )
        if self.config.debug_enabled:
            command.append("--debug")
        command.extend(
            [
                "--host",
                str(bridge.listen_host),
                "--port",
                str(bridge.listen_port),
                "--advertise-host",
                str(bridge.advertise_host),
                "--apdu-relay-host",
                str(bridge.apdu_relay_host),
                "--apdu-relay-port",
                str(bridge.apdu_relay_port),
                "--reader-index",
                str(bridge.reader_index),
                "--reader-name",
                str(bridge.reader_name),
                "--client-id",
                str(bridge.client_id),
                "--client-slot",
                str(bridge.client_slot),
                "--bank-id",
                str(bridge.bank_id),
                "--bank-slot",
                str(bridge.bank_slot),
                "--apdu-timeout-ms",
                str(bridge.apdu_timeout_ms),
                "--bridge-name",
                str(bridge.bridge_name),
                "--bridge-software",
                str(bridge.bridge_software),
                "--bridge-version",
                str(bridge.bridge_version),
                "--gsmtap-host",
                str(bridge.gsmtap_host),
                "--gsmtap-port",
                str(bridge.gsmtap_port),
                "--gsmtap-compat",
                str(bridge.gsmtap_compat_mode),
            ]
        )
        if bridge.apdu_relay_enabled is False:
            command.append("--no-apdu-relay")
        if bridge.gsmtap_enabled is False:
            command.append("--no-gsmtap")
        if bridge.card_trace_enabled:
            command.append("--card-trace")
        if getattr(bridge, "relay_session_reset_enabled", True) is False:
            command.append("--no-relay-session-reset")
        # Card-source overrides -- when the operator has pinned a remote
        # ``yggdrasim-card-bridge`` URL on the supervisor, propagate it
        # to the spawned bridge subprocess so the card-stream feature
        # works under supervision too. Empty values are intentionally
        # not passed so the subprocess defaults to local PC/SC.
        remote_card_url = str(getattr(bridge, "remote_card_url", "") or "").strip()
        if len(remote_card_url) > 0:
            command.extend(["--remote-card-url", remote_card_url])
        remote_card_token_file = str(
            getattr(bridge, "remote_card_token_file", "") or ""
        ).strip()
        if len(remote_card_token_file) > 0:
            command.extend(
                ["--remote-card-token-file", remote_card_token_file]
            )
        if len(self._card_lease_token) > 0:
            lease_path = str(self.config.card_lease_path or "").strip()
            if len(lease_path) > 0:
                command.extend(["--remote-card-lease-file", lease_path])
        capture_path = str(bridge.gsmtap_capture_path or "").strip()
        if len(capture_path) > 0:
            command.extend(
                [
                    "--gsmtap-capture-path",
                    capture_path,
                ]
            )
        return command

    def _build_remsim_command(self, snapshot: UsbPresenceSnapshot | None = None) -> list[str]:
        remsim = self.config.remsim_client
        command = [
            str(remsim.binary or "osmo-remsim-client-st2"),
            "-i",
            self._remsim_host(),
            "-p",
            str(self._remsim_port()),
            "-c",
            str(self._remsim_client_id()),
            "-n",
            str(self._remsim_client_slot()),
        ]
        atr_hex = str(self._remote_card_atr_hex or "")
        if len(atr_hex) > 0 and self._remsim_extra_args_include_atr(remsim.extra_args) is False:
            command.extend(["-a", atr_hex])
        if self._remsim_extra_args_include_usb_selector(remsim.extra_args) is False:
            command.extend(list(self._auto_remsim_usb_args(snapshot)))
        command.extend(list(remsim.extra_args))
        return command

    def _remsim_extra_args_include_atr(self, values: tuple[str, ...]) -> bool:
        """True when the operator already decided the client's ATR handling."""
        atr_flags = set(REMSIM_ATR_FLAGS)
        for raw_value in values:
            value_text = str(raw_value or "").strip()
            if len(value_text) == 0:
                continue
            if value_text in atr_flags:
                return True
            if any(value_text.startswith(f"{flag}=") for flag in atr_flags):
                return True
        return False

    def _remsim_extra_args_include_usb_selector(self, values: tuple[str, ...]) -> bool:
        selector_flags = set(REMSIM_USB_SELECTOR_FLAGS)
        for raw_value in values:
            value_text = str(raw_value or "").strip()
            if len(value_text) == 0:
                continue
            if value_text in selector_flags:
                return True
            if any(value_text.startswith(f"{flag}=") for flag in selector_flags):
                return True
        return False

    def _auto_remsim_usb_args(self, snapshot: UsbPresenceSnapshot | None) -> tuple[str, ...]:
        if snapshot is None:
            return ()
        devices = snapshot.devices
        if len(devices) == 0 and len(snapshot.matches) > 0:
            devices = _device_locators_from_match_lines(snapshot.matches)
        for device in devices:
            if device.usable_for_remsim is False:
                continue
            return (
                "-V",
                f"0x{device.vendor_id}",
                "-P",
                f"0x{device.product_id}",
                "-A",
                str(int(device.address)),
                "-C",
                DEFAULT_REMSIM_USB_CONFIG_ID,
                "-I",
                DEFAULT_REMSIM_USB_INTERFACE_ID,
                "-S",
                DEFAULT_REMSIM_USB_ALTSETTING_ID,
            )
        return ()

    def _remsim_host(self) -> str:
        host = str(self.config.remsim_client.host or "").strip()
        if len(host) > 0:
            return host
        listen_host = str(self.config.bridge.listen_host or "").strip()
        if listen_host in ("", "0.0.0.0", "::", "[::]"):
            return "127.0.0.1"
        return listen_host

    def _remsim_port(self) -> int:
        configured = int(self.config.remsim_client.port or 0)
        if configured > 0:
            return configured
        return int(self.config.bridge.listen_port)

    def _remsim_client_id(self) -> int:
        configured = self.config.remsim_client.client_id
        if configured is not None:
            return int(configured)
        return int(self.config.bridge.client_id)

    def _remsim_client_slot(self) -> int:
        configured = self.config.remsim_client.client_slot
        if configured is not None:
            return int(configured)
        return int(self.config.bridge.client_slot)

    def _write_state(
        self,
        *,
        status: str,
        snapshot: UsbPresenceSnapshot,
        reason: str,
    ) -> None:
        state_path = os.path.abspath(os.path.expanduser(str(self.config.state_path or "").strip()))
        state_dir = os.path.dirname(state_path)
        if len(state_dir) > 0:
            os.makedirs(state_dir, exist_ok=True)
        sim_backend = self._sim_backend_active()
        payload = {
            "status": str(status),
            "reason": str(reason),
            "updatedAt": _utc_timestamp(),
            "cardBackendGate": "sim" if sim_backend else "reader",
            "usbPresent": bool(snapshot.present),
            "usbSource": str(snapshot.source),
            "usbMatches": list(snapshot.matches),
            "usbError": str(snapshot.error),
            "bridgeRunning": self._bridge_is_running(),
            "bridgePid": int(getattr(self._child, "pid", 0) or 0),
            "bridgeCommand": self._build_bridge_command(),
            "bridgePort": int(self.config.bridge.listen_port),
            "remsimClientEnabled": bool(self.config.remsim_client.enabled),
            "remsimClientRunning": self._remsim_is_running(),
            "remsimClientPid": int(getattr(self._remsim_child, "pid", 0) or 0),
            "remsimClientCommand": self._build_remsim_command(snapshot=snapshot) if self.config.remsim_client.enabled else [],
            "remsimClientHost": self._remsim_host(),
            "remsimClientPort": self._remsim_port(),
            "simtraceReset": self._device_reset_state_payload(),
            "readerIndex": int(self.config.bridge.reader_index),
            "readerName": str(self.config.bridge.reader_name),
            "remoteCardUrl": str(getattr(self.config.bridge, "remote_card_url", "") or ""),
            "remoteCardTokenFile": str(getattr(self.config.bridge, "remote_card_token_file", "") or ""),
            "cardLease": self._card_lease_state,
            "cardLeaseHolder": self._card_lease_holder,
            "apduTimeoutMs": int(getattr(self.config.bridge, "apdu_timeout_ms", 0) or 0),
            "cardTraceEnabled": bool(getattr(self.config.bridge, "card_trace_enabled", False)),
            "pollIntervalSeconds": float(self.config.poll_interval_seconds),
            "restartBackoffSeconds": float(self.config.restart_backoff_seconds),
            "remoteCardRestartBackoffSeconds": float(self.config.remote_card_restart_backoff_seconds),
        }
        with open(state_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")

    def _cleanup_stale_bridge_marker(self, managed_pid: int | None = None) -> None:
        marker_path = runtime_path("state", CARD_RELAY_MARKER_FILENAME)
        if os.path.isfile(marker_path) is False:
            return

        marker_payload: dict[str, Any] = {}
        try:
            with open(marker_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            payload = {}

        if isinstance(payload, dict):
            marker_payload = dict(payload)

        marker_pid = int(marker_payload.get("pid", 0) or 0)
        if managed_pid is not None:
            if marker_pid not in (0, managed_pid):
                return
        elif marker_pid > 0 and _pid_exists(marker_pid):
            return

        try:
            os.remove(marker_path)
        except OSError:
            pass

    def _signal_child_process_group(self, pid: int, signal_number: int) -> bool:
        if int(pid or 0) <= 0:
            return False
        if os.name != "posix":
            return False
        try:
            os.killpg(int(pid), int(signal_number))
        except ProcessLookupError:
            return True
        except OSError:
            return False
        return True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="YggdraSIM HIL bridge USB supervisor")
    add_debug_argument(
        parser,
        help_text="Enable verbose supervisor and child bridge logging.",
    )
    parser.add_argument(
        "--usb-match",
        action="append",
        default=list(DEFAULT_USB_MATCH_TERMS),
        help="Case-insensitive substring used to identify the SIMtrace2 device in USB descriptors. Repeat as needed.",
    )
    parser.add_argument(
        "--usb-vidpid",
        action="append",
        default=[],
        help="Explicit USB VID:PID selector such as 1d50:xxxx. Repeat as needed.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
        help="Maximum seconds between USB presence reconciliations.",
    )
    parser.add_argument(
        "--restart-backoff",
        type=float,
        default=DEFAULT_RESTART_BACKOFF_SECONDS,
        help="Delay in seconds before restarting the bridge after an unexpected child exit.",
    )
    parser.add_argument(
        "--remote-card-restart-backoff",
        type=float,
        default=DEFAULT_REMOTE_CARD_RESTART_BACKOFF_SECONDS,
        help=(
            "Delay in seconds before restarting the bridge after an unexpected "
            "child exit while --remote-card-url is configured."
        ),
    )
    parser.add_argument(
        "--termination-timeout",
        type=float,
        default=DEFAULT_TERMINATION_TIMEOUT_SECONDS,
        help="Seconds to wait after SIGTERM before forcing the bridge child down.",
    )
    parser.add_argument(
        "--lsusb-path",
        type=str,
        default="lsusb",
        help="Path to the lsusb binary used by the fallback USB presence probe.",
    )
    parser.add_argument(
        "--no-pyudev",
        action="store_true",
        help="Disable pyudev hotplug monitoring and use lsusb polling only.",
    )
    parser.add_argument(
        "--state-file",
        type=str,
        default="",
        help="Optional supervisor status JSON path. Defaults to runtime/state/hil_bridge_supervisor.json.",
    )
    parser.add_argument(
        "--bridge-python",
        type=str,
        default=sys.executable,
        help=(
            "Python interpreter used to spawn the bridge child in source mode. "
            "Frozen bundles use the allow-listed internal dispatcher."
        ),
    )
    parser.add_argument(
        "--no-remsim-client",
        action="store_true",
        help="Disable supervisor management of the local osmo-remsim-client-st2 process.",
    )
    parser.add_argument(
        "--modem-at-device",
        default="",
        help=(
            "AT command port of the modem this rig feeds, e.g. /dev/ttyUSB2. "
            "When set, the supervisor sends AT+CFUN=0;+CFUN=1 once the card "
            "path is up so a modem that was already powered re-reads the "
            "SIM. Without it an automatic reconnect leaves the modem "
            "reporting no SIM while this supervisor reports running."
        ),
    )
    parser.add_argument(
        "--no-remote-card-lease",
        action="store_true",
        help=(
            "Do not take a lease on the remote card. The bridge then "
            "shares the card with anything else reaching it, which is the "
            "behaviour before leases existed. Only useful when a second "
            "consumer is expected to drive the same card deliberately."
        ),
    )
    parser.add_argument(
        "--remsim-binary",
        type=str,
        default="osmo-remsim-client-st2",
        help="Path or executable name for the managed osmo-remsim-client-st2 process.",
    )
    parser.add_argument(
        "--remsim-host",
        type=str,
        default="",
        help="Host passed to osmo-remsim-client-st2 via -i. Defaults to the local bridge listener.",
    )
    parser.add_argument(
        "--remsim-port",
        type=int,
        default=0,
        help="Port passed to osmo-remsim-client-st2 via -p. Defaults to the bridge port.",
    )
    parser.add_argument(
        "--remsim-client-id",
        type=int,
        default=None,
        help="Client identifier passed to osmo-remsim-client-st2 via -c. Defaults to --client-id.",
    )
    parser.add_argument(
        "--remsim-client-slot",
        type=int,
        default=None,
        help="Client slot passed to osmo-remsim-client-st2 via -n. Defaults to --client-slot.",
    )
    parser.add_argument(
        "--remsim-arg",
        action="append",
        default=[],
        help="Additional raw argument forwarded to osmo-remsim-client-st2. Repeat as needed. Use --remsim-arg=<value> for forwarded flags such as -V or -H.",
    )
    add_reset_arguments(parser)
    add_bridge_runtime_arguments(parser, include_list_readers=False)
    return parser


def _configure_logging(debug_enabled: bool) -> None:
    level = logging.DEBUG if debug_enabled else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def build_supervisor_config_from_args(args: argparse.Namespace) -> HilBridgeSupervisorConfig:
    """Build the HIL-Bridge supervisor config dict from parsed argparse namespace."""
    state_path = str(args.state_file or "").strip()
    if len(state_path) == 0:
        ensure_runtime_dir("state")
        state_path = runtime_path("state", SUPERVISOR_STATE_FILENAME)
    else:
        state_path = os.path.abspath(os.path.expanduser(state_path))

    return HilBridgeSupervisorConfig(
        bridge=build_bridge_config_from_args(args),
        remsim_client=RemsimClientConfig(
            enabled=not bool(getattr(args, "no_remsim_client", False)),
            binary=str(getattr(args, "remsim_binary", "") or "osmo-remsim-client-st2"),
            host=str(getattr(args, "remsim_host", "") or ""),
            port=max(0, int(getattr(args, "remsim_port", 0) or 0)),
            client_id=getattr(args, "remsim_client_id", None),
            client_slot=getattr(args, "remsim_client_slot", None),
            extra_args=_normalize_cli_args(getattr(args, "remsim_arg", [])),
        ),
        device_reset=build_reset_config_from_args(args),
        debug_enabled=bool(getattr(args, "debug", False)),
        bridge_python=str(args.bridge_python or sys.executable),
        usb_match_terms=_normalize_usb_match_terms(args.usb_match),
        usb_vidpids=_normalize_usb_vidpids(args.usb_vidpid),
        prefer_pyudev=not bool(args.no_pyudev),
        lsusb_path=str(args.lsusb_path or "lsusb"),
        poll_interval_seconds=max(0.1, float(args.poll_interval or DEFAULT_POLL_INTERVAL_SECONDS)),
        restart_backoff_seconds=max(0.0, float(args.restart_backoff or DEFAULT_RESTART_BACKOFF_SECONDS)),
        remote_card_restart_backoff_seconds=max(
            0.0,
            float(
                args.remote_card_restart_backoff
                or DEFAULT_REMOTE_CARD_RESTART_BACKOFF_SECONDS
            ),
        ),
        termination_timeout_seconds=max(
            1.0,
            float(args.termination_timeout or DEFAULT_TERMINATION_TIMEOUT_SECONDS),
        ),
        state_path=state_path,
        remote_card_lease_enabled=not bool(
            getattr(args, "no_remote_card_lease", False)
        ),
        modem_at_device=str(getattr(args, "modem_at_device", "") or "").strip(),
    )


def run_standalone() -> int:
    """Start the HIL-Bridge supervisor as a standalone foreground process."""
    parser = _build_parser()
    args = parser.parse_args()
    debug_enabled = bool(getattr(args, "debug", False))
    set_global_debug(debug_enabled)
    _configure_logging(debug_enabled)

    config = build_supervisor_config_from_args(args)
    usb_monitor = create_usb_presence_monitor(
        match_terms=config.usb_match_terms,
        vidpids=config.usb_vidpids,
        prefer_pyudev=config.prefer_pyudev,
        lsusb_path=config.lsusb_path,
    )
    supervisor = HilBridgeSupervisor(config=config, usb_monitor=usb_monitor)

    def _request_stop(_signum: int, _frame: Any) -> None:
        supervisor.request_stop()

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    return supervisor.run()


def entry() -> int:
    return run_standalone()


if __name__ == "__main__":
    try:
        raise SystemExit(run_standalone())
    except QuitAllRequested:
        raise SystemExit(0)
