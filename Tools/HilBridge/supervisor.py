# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge supervisor: manages child process lifecycle (modem, bridge, tshark) with restart policy and watchdog timers."""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Event
from typing import Any, Protocol

from yggdrasim_common.card_backend import CARD_RELAY_MARKER_FILENAME, is_simulated_card_backend
from yggdrasim_common.process_debug import add_debug_argument, set_global_debug
from yggdrasim_common.quit_control import QuitAllRequested
from yggdrasim_common.runtime_paths import ensure_runtime_dir, runtime_path

from .main import add_bridge_runtime_arguments, build_bridge_config_from_args
from .router import BridgeConfig

LOGGER = logging.getLogger(__name__)

DEFAULT_USB_MATCH_TERMS: tuple[str, ...] = ("simtrace", "sysmocom")
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_RESTART_BACKOFF_SECONDS = 1.0
DEFAULT_TERMINATION_TIMEOUT_SECONDS = 5.0
DEFAULT_LSUSB_TIMEOUT_SECONDS = 5.0
DEFAULT_REMSIM_USB_CONFIG_ID = "1"
DEFAULT_REMSIM_USB_INTERFACE_ID = "0"
DEFAULT_REMSIM_USB_ALTSETTING_ID = "0"
SUPERVISOR_STATE_FILENAME = "hil_bridge_supervisor.json"
REMSIM_USB_SELECTOR_FLAGS: tuple[str, ...] = ("-V", "-P", "-C", "-I", "-S", "-A", "-H")
_USB_BUS_DEVICE_PATTERN = re.compile(r"\bBus\s+(\d+)\s+Device\s+(\d+):", re.IGNORECASE)
_USB_ID_VIDPID_PATTERN = re.compile(r"\bID\s+([0-9a-f]{4}):([0-9a-f]{4})\b", re.IGNORECASE)
_USB_PLAIN_VIDPID_PATTERN = re.compile(r"\b([0-9a-f]{4}):([0-9a-f]{4})\b", re.IGNORECASE)


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
    debug_enabled: bool = False
    bridge_python: str = sys.executable
    usb_match_terms: tuple[str, ...] = DEFAULT_USB_MATCH_TERMS
    usb_vidpids: tuple[str, ...] = ()
    prefer_pyudev: bool = True
    lsusb_path: str = "lsusb"
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS
    restart_backoff_seconds: float = DEFAULT_RESTART_BACKOFF_SECONDS
    termination_timeout_seconds: float = DEFAULT_TERMINATION_TIMEOUT_SECONDS
    state_path: str = field(default_factory=lambda: runtime_path("state", SUPERVISOR_STATE_FILENAME))


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

    def reconcile(self) -> None:
        """Reconcile the desired-state channel config against the running connections."""
        now = float(self.monotonic())
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
                        reason=f"Waiting {remaining:.1f}s before bridge restart.",
                    )
                    return
                self._start_bridge_child(snapshot)
                bridge_running = self._bridge_is_running()

            if bridge_running:
                if remsim_allowed is False:
                    if self._remsim_is_running():
                        # Cable was pulled while sim mode remained
                        # selected — bridge stays up, REMSIM goes.
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
            self._write_state(
                status="start-failed",
                snapshot=snapshot,
                reason=f"Bridge child failed to start: {exc}",
            )
            LOGGER.error("Bridge child start failed: %s", exc)
            return

        self._child = child
        self._next_start_not_before = 0.0
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
        self._write_state(
            status="running",
            snapshot=snapshot,
            reason="SIMtrace2 present; bridge and REMSIM client children are active.",
        )

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
            killed_group = self._signal_child_process_group(pid, signal.SIGKILL)
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
            killed_group = self._signal_child_process_group(pid, signal.SIGKILL)
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
        self._next_start_not_before = now + float(self.config.restart_backoff_seconds)
        self._cleanup_stale_bridge_marker(managed_pid=pid)
        LOGGER.warning("Bridge child pid=%s exited with code %s", pid, return_code)
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
        command = [
            str(self.config.bridge_python or sys.executable),
            "-m",
            "Tools.HilBridge.main",
        ]
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
        # Card-source overrides — when the operator has pinned a remote
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
        if self._remsim_extra_args_include_usb_selector(remsim.extra_args) is False:
            command.extend(list(self._auto_remsim_usb_args(snapshot)))
        command.extend(list(remsim.extra_args))
        return command

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
            "readerIndex": int(self.config.bridge.reader_index),
            "readerName": str(self.config.bridge.reader_name),
            "remoteCardUrl": str(getattr(self.config.bridge, "remote_card_url", "") or ""),
            "remoteCardTokenFile": str(getattr(self.config.bridge, "remote_card_token_file", "") or ""),
            "pollIntervalSeconds": float(self.config.poll_interval_seconds),
            "restartBackoffSeconds": float(self.config.restart_backoff_seconds),
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
        help="Python interpreter used to spawn the bridge child process.",
    )
    parser.add_argument(
        "--no-remsim-client",
        action="store_true",
        help="Disable supervisor management of the local osmo-remsim-client-st2 process.",
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
        debug_enabled=bool(getattr(args, "debug", False)),
        bridge_python=str(args.bridge_python or sys.executable),
        usb_match_terms=_normalize_usb_match_terms(args.usb_match),
        usb_vidpids=_normalize_usb_vidpids(args.usb_vidpid),
        prefer_pyudev=not bool(args.no_pyudev),
        lsusb_path=str(args.lsusb_path or "lsusb"),
        poll_interval_seconds=max(0.1, float(args.poll_interval or DEFAULT_POLL_INTERVAL_SECONDS)),
        restart_backoff_seconds=max(0.0, float(args.restart_backoff or DEFAULT_RESTART_BACKOFF_SECONDS)),
        termination_timeout_seconds=max(
            1.0,
            float(args.termination_timeout or DEFAULT_TERMINATION_TIMEOUT_SECONDS),
        ),
        state_path=state_path,
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
