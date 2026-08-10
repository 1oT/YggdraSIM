# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Remote equivalent of the SIMtrace2 reset button.

Osmocom's cardem firmware reboots the SAM3 microcontroller on its own
whenever the USB device leaves the ``CONFIGURED`` state — see
``firmware/apps/cardem/main.c`` in ``osmocom/simtrace2``::

    if (USBD_GetState() < USBD_STATE_CONFIGURED) {
        /* HACK: we don't really deal with USB disconnect yet,
         * so let's just reset the entire uC if this happens */
        TRACE_INFO("Resetting uC on USB disconnect\\n\\r");
        NVIC_SystemReset();
    }

``NVIC_SystemReset()`` is exactly what the physical reset button
triggers, so no firmware modification is needed to clear a wedged
board: any host-side action that de-configures the USB device makes the
firmware reboot itself and re-enumerate with a fresh card-emulation
state machine.

This module drives that from the host, in two flavours:

``usb-reset``
    ``USBDEVFS_RESET`` on ``/dev/bus/usb/BBB/DDD`` (what the classic
    ``usbreset`` helper does). The kernel performs a USB port reset,
    the device drops below ``CONFIGURED``, and the firmware reboots.
    Needs only write access to the device node, so it works from an
    unprivileged ``systemd --user`` supervisor once a udev rule grants
    the operator's group access to ``1d50:60e3``.

``port-power``
    A VBUS power cycle through ``uhubctl``. This is a true
    unplug/replug: it also removes power from the SIM slot, so it
    clears card state the reset button leaves untouched. Only works on
    hubs with per-port power switching.

Deliberately **not** implemented: ``dfu-util --detach``. The DFU
runtime interface in the application firmware latches
``USB_DFU_MAGIC`` before resetting (``DFURT_SwitchToDFU``), and the
bootloader has no auto-boot timeout — the board would sit in DFU mode
(``1d50:4004``) until somebody physically power-cycles it. That is the
exact failure this module exists to avoid.
"""
from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable

try:  # pragma: no cover - platform guard, exercised implicitly on POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows / clean-flavor imports
    fcntl = None  # type: ignore[assignment]

LOGGER = logging.getLogger(__name__)

RESET_MODE_OFF = "off"
RESET_MODE_USB_RESET = "usb-reset"
RESET_MODE_PORT_POWER = "port-power"
RESET_MODE_AUTO = "auto"
RESET_MODES: tuple[str, ...] = (
    RESET_MODE_OFF,
    RESET_MODE_USB_RESET,
    RESET_MODE_PORT_POWER,
    RESET_MODE_AUTO,
)

DEFAULT_RESET_MODE = RESET_MODE_USB_RESET
DEFAULT_SETTLE_TIMEOUT_SECONDS = 20.0
DEFAULT_SETTLE_POLL_SECONDS = 0.5
DEFAULT_MIN_INTERVAL_SECONDS = 30.0
DEFAULT_PORT_POWER_OFF_SECONDS = 2.0
DEFAULT_UHUBCTL_BINARY = "uhubctl"
DEFAULT_UHUBCTL_TIMEOUT_SECONDS = 20.0

RESET_MODE_ENV = "YGGDRASIM_HIL_SIMTRACE_RESET"
UHUBCTL_LOCATION_ENV = "YGGDRASIM_HIL_UHUBCTL_LOCATION"
UHUBCTL_PORT_ENV = "YGGDRASIM_HIL_UHUBCTL_PORT"
UHUBCTL_BINARY_ENV = "YGGDRASIM_HIL_UHUBCTL_BINARY"

_FALSE_ENV_VALUES = frozenset({"0", "false", "no", "off", "disable", "disabled"})
_TRUE_ENV_VALUES = frozenset({"1", "true", "yes", "on", "enable", "enabled"})

#: ``_IO('U', 20)`` from ``linux/usbdevice_fs.h``.
USBDEVFS_RESET = 0x5514

USB_DEVICE_NODE_ROOT = "/dev/bus/usb"


class SimtraceResetError(RuntimeError):
    """Raised when a reset attempt cannot be carried out."""


def normalize_reset_mode(value: Any, *, default: str = DEFAULT_RESET_MODE) -> str:
    """Normalise *value* to one of :data:`RESET_MODES`.

    Booleans and the usual on/off environment spellings are accepted so
    ``YGGDRASIM_HIL_SIMTRACE_RESET=0`` reads as "off" and ``=1`` reads
    as the default mode. Unknown values fall back to *default* rather
    than raising, because this runs on the supervisor start path where
    a typo must not take the whole rig down.
    """
    if isinstance(value, bool):
        return default if value else RESET_MODE_OFF
    text = str(value if value is not None else "").strip().lower()
    if len(text) == 0:
        return default
    if text in RESET_MODES:
        return text
    if text in _FALSE_ENV_VALUES:
        return RESET_MODE_OFF
    if text in _TRUE_ENV_VALUES:
        return default
    # Tolerate the underscore spelling operators reach for first.
    underscored = text.replace("_", "-")
    if underscored in RESET_MODES:
        return underscored
    return default


def resolve_reset_mode_from_env(
    value: Any = None,
    *,
    environ: Any = None,
    default: str = DEFAULT_RESET_MODE,
) -> str:
    """Resolve the reset mode from an explicit *value* or the environment."""
    if value is not None and len(str(value).strip()) > 0:
        return normalize_reset_mode(value, default=default)
    source = environ if environ is not None else os.environ
    return normalize_reset_mode(source.get(RESET_MODE_ENV, ""), default=default)


def usb_device_node_path(bus: Any, address: Any, *, root: str = USB_DEVICE_NODE_ROOT) -> str:
    """Return ``/dev/bus/usb/BBB/DDD`` for *bus* / *address*, or ``""``.

    Both numbers are zero-padded to three digits, matching the usbfs
    layout the kernel exposes. An unusable pair yields an empty string
    so callers can fall back instead of building a bogus path.
    """
    try:
        bus_number = int(bus or 0)
        address_number = int(address or 0)
    except (TypeError, ValueError):
        return ""
    if bus_number <= 0 or address_number <= 0:
        return ""
    return f"{str(root or USB_DEVICE_NODE_ROOT).rstrip('/')}/{bus_number:03d}/{address_number:03d}"


@dataclass(frozen=True, slots=True)
class SimtraceResetConfig:
    """Settings for the pre-session SIMtrace2 reset."""

    mode: str = DEFAULT_RESET_MODE
    settle_timeout_seconds: float = DEFAULT_SETTLE_TIMEOUT_SECONDS
    settle_poll_seconds: float = DEFAULT_SETTLE_POLL_SECONDS
    min_interval_seconds: float = DEFAULT_MIN_INTERVAL_SECONDS
    uhubctl_binary: str = DEFAULT_UHUBCTL_BINARY
    uhubctl_location: str = ""
    uhubctl_port: str = ""
    port_power_off_seconds: float = DEFAULT_PORT_POWER_OFF_SECONDS
    uhubctl_timeout_seconds: float = DEFAULT_UHUBCTL_TIMEOUT_SECONDS

    @property
    def enabled(self) -> bool:
        return normalize_reset_mode(self.mode) != RESET_MODE_OFF

    @property
    def port_power_available(self) -> bool:
        return len(str(self.uhubctl_location or "").strip()) > 0


@dataclass(frozen=True, slots=True)
class SimtraceResetOutcome:
    """Result of a single reset attempt."""

    performed: bool = False
    mode: str = ""
    detail: str = ""
    error: str = ""
    device_node: str = ""
    reenumerated: bool = False

    @property
    def ok(self) -> bool:
        return bool(self.performed) and len(str(self.error or "")) == 0

    def as_state_payload(self) -> dict[str, Any]:
        """Render the outcome for the supervisor state JSON."""
        return {
            "performed": bool(self.performed),
            "mode": str(self.mode or ""),
            "detail": str(self.detail or ""),
            "error": str(self.error or ""),
            "deviceNode": str(self.device_node or ""),
            "reenumerated": bool(self.reenumerated),
            "ok": bool(self.ok),
        }


def issue_usbdevfs_reset(
    node_path: str,
    *,
    opener: Callable[..., int] = os.open,
    closer: Callable[[int], None] = os.close,
    ioctl_func: Any = None,
) -> None:
    """Issue ``USBDEVFS_RESET`` against the usbfs node at *node_path*.

    The kernel re-enumerates the device behind our back; the cardem
    firmware sees the port reset as a USB disconnect and reboots the
    SAM3. The descriptor is opened write-only because usbfs requires a
    writable handle for the ioctl.
    """
    target_path = str(node_path or "").strip()
    if len(target_path) == 0:
        raise SimtraceResetError("No usbfs device node is known for the SIMtrace2 board.")

    resolved_ioctl = ioctl_func
    if resolved_ioctl is None:
        if fcntl is None:
            raise SimtraceResetError(
                "USB reset needs the POSIX fcntl module, which is unavailable on this platform."
            )
        resolved_ioctl = fcntl.ioctl

    try:
        descriptor = opener(target_path, os.O_WRONLY)
    except PermissionError as exc:
        raise SimtraceResetError(
            f"Permission denied opening {target_path}. Add a udev rule granting "
            "the operator's group write access to the SIMtrace2 device node."
        ) from exc
    except OSError as exc:
        raise SimtraceResetError(f"Cannot open {target_path}: {exc}") from exc

    try:
        resolved_ioctl(descriptor, USBDEVFS_RESET, 0)
    except OSError as exc:
        raise SimtraceResetError(f"USBDEVFS_RESET on {target_path} failed: {exc}") from exc
    finally:
        try:
            closer(descriptor)
        except OSError:
            pass


def build_uhubctl_command(config: SimtraceResetConfig, *, action: str) -> list[str]:
    """Build the ``uhubctl`` command line for *action* (``off`` / ``on``)."""
    location = str(config.uhubctl_location or "").strip()
    if len(location) == 0:
        raise SimtraceResetError(
            "Port-power reset needs a hub location (uhubctl -l), for example '1-1'."
        )
    command = [
        str(config.uhubctl_binary or DEFAULT_UHUBCTL_BINARY).strip() or DEFAULT_UHUBCTL_BINARY,
        "-l",
        location,
    ]
    port = str(config.uhubctl_port or "").strip()
    if len(port) > 0:
        command.extend(["-p", port])
    command.extend(["-a", str(action or "").strip()])
    return command


def run_port_power_cycle(
    config: SimtraceResetConfig,
    *,
    runner: Any = subprocess.run,
    sleeper: Callable[[float], None] = time.sleep,
) -> str:
    """Cut and restore VBUS on the SIMtrace2's hub port via ``uhubctl``."""
    off_command = build_uhubctl_command(config, action="off")
    on_command = build_uhubctl_command(config, action="on")
    timeout_seconds = max(1.0, float(config.uhubctl_timeout_seconds or DEFAULT_UHUBCTL_TIMEOUT_SECONDS))

    def _run(command: list[str]) -> None:
        try:
            completed = runner(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except FileNotFoundError as exc:
            raise SimtraceResetError(
                f"{command[0]} is not installed; install uhubctl or pick another reset mode."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise SimtraceResetError(f"{' '.join(command)} timed out: {exc}") from exc
        if int(getattr(completed, "returncode", 0) or 0) != 0:
            error_text = str(getattr(completed, "stderr", "") or getattr(completed, "stdout", "") or "").strip()
            if len(error_text) == 0:
                error_text = f"exit status {getattr(completed, 'returncode', 0)}"
            raise SimtraceResetError(f"{' '.join(command)} failed: {error_text}")

    _run(off_command)
    sleeper(max(0.1, float(config.port_power_off_seconds or DEFAULT_PORT_POWER_OFF_SECONDS)))
    _run(on_command)
    return f"VBUS cycled via {' '.join(off_command)}"


def _reset_mode_ladder(mode: str, config: SimtraceResetConfig) -> tuple[str, ...]:
    """Return the modes to try, in order, for the configured *mode*."""
    normalized_mode = normalize_reset_mode(mode)
    if normalized_mode == RESET_MODE_OFF:
        return ()
    if normalized_mode == RESET_MODE_AUTO:
        if config.port_power_available:
            return (RESET_MODE_USB_RESET, RESET_MODE_PORT_POWER)
        return (RESET_MODE_USB_RESET,)
    return (normalized_mode,)


def wait_for_device_return(
    presence_probe: Callable[[], bool] | None,
    config: SimtraceResetConfig,
    *,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> bool:
    """Block until the board is back on the bus, or the settle budget ends.

    A reset changes the device's USB address, so callers must re-read
    their USB snapshot afterwards rather than reusing the pre-reset
    bus/address pair.
    """
    poll_seconds = max(0.05, float(config.settle_poll_seconds or DEFAULT_SETTLE_POLL_SECONDS))
    if presence_probe is None:
        sleeper(poll_seconds)
        return False

    deadline = float(monotonic()) + max(
        poll_seconds,
        float(config.settle_timeout_seconds or DEFAULT_SETTLE_TIMEOUT_SECONDS),
    )
    while True:
        sleeper(poll_seconds)
        try:
            if bool(presence_probe()):
                return True
        except Exception as exc:  # noqa: BLE001 - a failing probe must not abort the reset
            LOGGER.debug("SIMtrace2 presence probe failed while settling: %s", exc)
        if float(monotonic()) >= deadline:
            return False


def reset_simtrace_device(
    *,
    config: SimtraceResetConfig,
    bus: Any = 0,
    address: Any = 0,
    presence_probe: Callable[[], bool] | None = None,
    usb_reset: Callable[[str], None] = issue_usbdevfs_reset,
    power_cycle: Callable[[SimtraceResetConfig], str] = run_port_power_cycle,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> SimtraceResetOutcome:
    """Reboot the SIMtrace2 board without touching its reset button.

    Returns a :class:`SimtraceResetOutcome` describing what happened;
    failures are reported rather than raised so the supervisor can
    still bring a session up on a board that refused to reset.
    """
    ladder = _reset_mode_ladder(config.mode, config)
    if len(ladder) == 0:
        return SimtraceResetOutcome(
            performed=False,
            mode=RESET_MODE_OFF,
            detail="Pre-session SIMtrace2 reset is disabled.",
        )

    node_path = usb_device_node_path(bus, address)
    errors: list[str] = []
    for candidate_mode in ladder:
        try:
            if candidate_mode == RESET_MODE_USB_RESET:
                usb_reset(node_path)
                detail = f"USBDEVFS_RESET issued on {node_path}"
            else:
                detail = power_cycle(config)
        except SimtraceResetError as exc:
            errors.append(f"{candidate_mode}: {exc}")
            continue
        except OSError as exc:
            errors.append(f"{candidate_mode}: {exc}")
            continue

        reenumerated = wait_for_device_return(
            presence_probe,
            config,
            sleeper=sleeper,
            monotonic=monotonic,
        )
        settle_note = ""
        if presence_probe is not None and reenumerated is False:
            settle_note = (
                f" Board did not re-appear within "
                f"{float(config.settle_timeout_seconds or DEFAULT_SETTLE_TIMEOUT_SECONDS):.1f}s."
            )
        return SimtraceResetOutcome(
            performed=True,
            mode=candidate_mode,
            detail=f"{detail}.{settle_note}",
            device_node=node_path if candidate_mode == RESET_MODE_USB_RESET else "",
            reenumerated=reenumerated,
        )

    return SimtraceResetOutcome(
        performed=False,
        mode=normalize_reset_mode(config.mode),
        detail="",
        error="; ".join(errors) if len(errors) > 0 else "No reset mode was applicable.",
        device_node=node_path,
    )


def add_reset_arguments(parser: argparse.ArgumentParser, *, include_mode: bool = True) -> None:
    """Add the SIMtrace2 reset knobs to *parser*."""
    if include_mode:
        parser.add_argument(
            "--simtrace-reset",
            dest="simtrace_reset",
            type=str,
            default="",
            choices=("", *RESET_MODES),
            help=(
                "How to clear the SIMtrace2 board before a session: 'usb-reset' "
                "(USBDEVFS_RESET, the default), 'port-power' (uhubctl VBUS cycle), "
                "'auto' (usb-reset then port-power), or 'off'. "
                f"Mirrors {RESET_MODE_ENV}."
            ),
        )
        parser.add_argument(
            "--no-simtrace-reset",
            action="store_true",
            help="Shorthand for --simtrace-reset off.",
        )
    parser.add_argument(
        "--simtrace-reset-settle-timeout",
        type=float,
        default=DEFAULT_SETTLE_TIMEOUT_SECONDS,
        help="Seconds to wait for the board to re-enumerate after a reset.",
    )
    parser.add_argument(
        "--simtrace-reset-settle-poll",
        type=float,
        default=DEFAULT_SETTLE_POLL_SECONDS,
        help="Seconds between USB presence probes while waiting for the board to return.",
    )
    parser.add_argument(
        "--simtrace-reset-min-interval",
        type=float,
        default=DEFAULT_MIN_INTERVAL_SECONDS,
        help=(
            "Minimum seconds between two automatic resets. Keeps a crashing "
            "bridge child from power-cycling the board in a tight loop."
        ),
    )
    parser.add_argument(
        "--uhubctl-binary",
        type=str,
        default=DEFAULT_UHUBCTL_BINARY,
        help=f"Path or name of the uhubctl binary. Mirrors {UHUBCTL_BINARY_ENV}.",
    )
    parser.add_argument(
        "--uhubctl-location",
        type=str,
        default="",
        help=(
            "Hub location passed to uhubctl -l (for example '1-1'). Required for "
            f"the port-power reset mode. Mirrors {UHUBCTL_LOCATION_ENV}."
        ),
    )
    parser.add_argument(
        "--uhubctl-port",
        type=str,
        default="",
        help=f"Hub port passed to uhubctl -p. Mirrors {UHUBCTL_PORT_ENV}.",
    )
    parser.add_argument(
        "--uhubctl-power-off-seconds",
        type=float,
        default=DEFAULT_PORT_POWER_OFF_SECONDS,
        help="Seconds to keep VBUS off during a port-power reset.",
    )


def build_reset_config_from_args(
    args: argparse.Namespace,
    *,
    environ: Any = None,
) -> SimtraceResetConfig:
    """Build a :class:`SimtraceResetConfig` from parsed CLI arguments."""
    source = environ if environ is not None else os.environ
    mode = RESET_MODE_OFF
    if bool(getattr(args, "no_simtrace_reset", False)) is False:
        mode = resolve_reset_mode_from_env(
            getattr(args, "simtrace_reset", ""),
            environ=source,
        )
    uhubctl_binary = str(getattr(args, "uhubctl_binary", "") or "").strip()
    if uhubctl_binary in ("", DEFAULT_UHUBCTL_BINARY):
        uhubctl_binary = str(source.get(UHUBCTL_BINARY_ENV, "") or "").strip() or DEFAULT_UHUBCTL_BINARY
    uhubctl_location = str(getattr(args, "uhubctl_location", "") or "").strip()
    if len(uhubctl_location) == 0:
        uhubctl_location = str(source.get(UHUBCTL_LOCATION_ENV, "") or "").strip()
    uhubctl_port = str(getattr(args, "uhubctl_port", "") or "").strip()
    if len(uhubctl_port) == 0:
        uhubctl_port = str(source.get(UHUBCTL_PORT_ENV, "") or "").strip()
    return SimtraceResetConfig(
        mode=mode,
        settle_timeout_seconds=max(
            0.0,
            float(getattr(args, "simtrace_reset_settle_timeout", None) or DEFAULT_SETTLE_TIMEOUT_SECONDS),
        ),
        settle_poll_seconds=max(
            0.05,
            float(getattr(args, "simtrace_reset_settle_poll", None) or DEFAULT_SETTLE_POLL_SECONDS),
        ),
        min_interval_seconds=max(
            0.0,
            float(getattr(args, "simtrace_reset_min_interval", None) or 0.0),
        ),
        uhubctl_binary=uhubctl_binary,
        uhubctl_location=uhubctl_location,
        uhubctl_port=uhubctl_port,
        port_power_off_seconds=max(
            0.1,
            float(getattr(args, "uhubctl_power_off_seconds", None) or DEFAULT_PORT_POWER_OFF_SECONDS),
        ),
    )


def _build_parser() -> argparse.ArgumentParser:
    from yggdrasim_common.process_debug import add_debug_argument

    parser = argparse.ArgumentParser(
        description=(
            "Reboot an attached SIMtrace2 board over USB — the remote "
            "equivalent of pressing its reset button."
        )
    )
    add_debug_argument(parser, help_text="Enable verbose reset logging.")
    parser.add_argument(
        "--usb-match",
        action="append",
        default=[],
        help="Case-insensitive substring identifying the board in USB descriptors. Repeat as needed.",
    )
    parser.add_argument(
        "--usb-vidpid",
        action="append",
        default=[],
        help="Explicit USB VID:PID selector such as 1d50:60e3. Repeat as needed.",
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
        help="Disable pyudev enumeration and use lsusb only.",
    )
    add_reset_arguments(parser)
    return parser


def run_standalone() -> int:
    """Reset the attached SIMtrace2 board once and report the outcome."""
    # Imported lazily: ``supervisor`` imports this module, so a
    # module-level import here would close the cycle.
    from .supervisor import (
        DEFAULT_USB_MATCH_TERMS,
        _normalize_usb_match_terms,
        _normalize_usb_vidpids,
        create_usb_presence_monitor,
    )
    from yggdrasim_common.process_debug import set_global_debug

    parser = _build_parser()
    args = parser.parse_args()
    debug_enabled = bool(getattr(args, "debug", False))
    set_global_debug(debug_enabled)
    logging.basicConfig(
        level=logging.DEBUG if debug_enabled else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    match_terms = _normalize_usb_match_terms(args.usb_match) or DEFAULT_USB_MATCH_TERMS
    config = build_reset_config_from_args(args)
    if config.enabled is False:
        print("SIMtrace2 reset is disabled (--simtrace-reset off); nothing to do.")
        return 0

    monitor = create_usb_presence_monitor(
        match_terms=match_terms,
        vidpids=_normalize_usb_vidpids(args.usb_vidpid),
        prefer_pyudev=not bool(args.no_pyudev),
        lsusb_path=str(args.lsusb_path or "lsusb"),
    )
    snapshot = monitor.snapshot()
    if snapshot.detection_ok is False:
        print(f"USB detection failed: {snapshot.error}", file=sys.stderr)
        return 2
    if snapshot.present is False:
        print("No SIMtrace2 board is attached.", file=sys.stderr)
        return 2

    device = next((item for item in snapshot.devices if item.usable_for_remsim), None)
    outcome = reset_simtrace_device(
        config=config,
        bus=getattr(device, "bus", 0),
        address=getattr(device, "address", 0),
        presence_probe=lambda: bool(monitor.snapshot().present),
    )
    if outcome.ok is False:
        print(f"SIMtrace2 reset failed: {outcome.error}", file=sys.stderr)
        return 1
    print(f"SIMtrace2 reset via {outcome.mode}: {outcome.detail}")
    if outcome.reenumerated is False:
        print(
            "The board has not re-appeared yet; re-check with `lsusb | grep 1d50:60e3`.",
            file=sys.stderr,
        )
        return 1
    return 0


def entry() -> int:
    return run_standalone()


if __name__ == "__main__":
    from yggdrasim_common.quit_control import QuitAllRequested

    try:
        raise SystemExit(run_standalone())
    except QuitAllRequested:
        raise SystemExit(0)
