# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the HIL supervisor's SIMtrace2-firmware board table and card-emulation choice.

Every sysfs tree is built in a scratch directory and lsusb answers with
canned output, so no USB hardware or host state is read.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from Tools.HilBridge import device_reset
from Tools.HilBridge.device_reset import (
    RESET_MODE_USB_RESET,
    SimtraceResetConfig,
    SimtraceResetOutcome,
)
from Tools.HilBridge.router import BridgeConfig
from Tools.HilBridge.supervisor import (
    DEFAULT_USB_MATCH_TERMS,
    SIMTRACE2_FIRMWARE_BOARDS,
    SIMTRACE2_FIRMWARE_VIDPIDS,
    HilBridgeSupervisor,
    HilBridgeSupervisorConfig,
    PyudevPresenceMonitor,
    RemsimClientConfig,
    UsbDeviceLocator,
    UsbPresenceSnapshot,
    _match_lines_from_lsusb_output,
    boards_without_card_emulation,
    card_emulation_interface_state,
    choose_card_emulation_board,
    create_usb_presence_monitor,
    describe_usb_board,
    simtrace2_board_name,
)

# Interface classes as sysfs prints them for each firmware state of the board.
CARDEM_INTERFACES = (("ff", "02"), ("fe", "01"))
SNIFFER_INTERFACES = (("ff", "01"), ("fe", "01"))
BOOTLOADER_INTERFACES = (("fe", "01"),)

NGFF_LSUSB_LINE = "Bus 003 Device 026: ID 1d50:616e OpenMoko, Inc. ngff-cardem"
LSUSB_OUTPUT = "\n".join(
    (
        "Bus 003 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub",
        NGFF_LSUSB_LINE,
        "Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub",
    )
) + "\n"


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text + "\n")


def _sysfs_device(
    root: str,
    name: str,
    *,
    bus: int,
    devnum: int,
    vidpid: str,
    interfaces: tuple[tuple[str, str], ...],
) -> None:
    device_dir = os.path.join(root, name)
    os.makedirs(device_dir)
    vendor_id, product_id = vidpid.split(":")
    _write(os.path.join(device_dir, "busnum"), str(bus))
    _write(os.path.join(device_dir, "devnum"), str(devnum))
    _write(os.path.join(device_dir, "idVendor"), vendor_id)
    _write(os.path.join(device_dir, "idProduct"), product_id)
    for index, (interface_class, interface_subclass) in enumerate(interfaces):
        interface_dir = os.path.join(device_dir, f"{name}:1.{index}")
        os.makedirs(interface_dir)
        _write(os.path.join(interface_dir, "bInterfaceClass"), interface_class)
        _write(os.path.join(interface_dir, "bInterfaceSubClass"), interface_subclass)


def _board(
    product_id: str,
    *,
    address: int,
    card_emulation: bool | None,
    bus: int = 3,
) -> UsbDeviceLocator:
    return UsbDeviceLocator(
        vendor_id="1d50",
        product_id=product_id,
        bus=bus,
        address=address,
        card_emulation=card_emulation,
    )


def _snapshot(*devices: UsbDeviceLocator) -> UsbPresenceSnapshot:
    return UsbPresenceSnapshot(
        source="test",
        present=True,
        matches=tuple(f"Bus {d.bus:03d} Device {d.address:03d}: ID {d.vidpid}" for d in devices),
        devices=tuple(devices),
    )


class _FixedMonitor:
    def __init__(self, snapshot: UsbPresenceSnapshot) -> None:
        self._snapshot = snapshot

    def snapshot(self) -> UsbPresenceSnapshot:
        return self._snapshot

    def wait_for_change(self, timeout_seconds: float) -> None:
        del timeout_seconds


class _RunningChild:
    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid

    def poll(self):
        return None


class _FakeUdevDevice(dict):
    """A pyudev USB device: properties through get(), plus the two attributes the monitor reads."""

    device_type = "usb_device"
    sys_name = "3-4"
    device_path = "/devices/platform/usb3/3-4"


class _FakeUdevContext:
    def __init__(self, devices) -> None:
        self._devices = list(devices)

    def list_devices(self, subsystem: str):
        if subsystem != "usb":
            raise AssertionError(f"unexpected subsystem {subsystem!r}")
        return list(self._devices)


class BoardTableTests(unittest.TestCase):
    """osmo_st2_compatible_dev_ids, simtrace2 host/lib/usb_util.c: five boards."""

    def test_the_table_is_the_upstream_list(self) -> None:
        self.assertEqual(
            SIMTRACE2_FIRMWARE_BOARDS,
            (
                ("1d50:4001", "OWHW"),
                ("1d50:4004", "QMOD"),
                ("1d50:60e3", "SIMtrace2"),
                ("1d50:616d", "octsimtest"),
                ("1d50:616e", "ngff-cardem"),
            ),
        )
        self.assertEqual(
            SIMTRACE2_FIRMWARE_VIDPIDS,
            tuple(vidpid for vidpid, _name in SIMTRACE2_FIRMWARE_BOARDS),
        )

    def test_every_board_is_named_by_its_id(self) -> None:
        for vidpid, name in SIMTRACE2_FIRMWARE_BOARDS:
            with self.subTest(vidpid=vidpid):
                self.assertEqual(simtrace2_board_name(vidpid.upper()), name)

    def test_another_id_has_no_name(self) -> None:
        self.assertEqual(simtrace2_board_name("1d50:4002"), "")
        self.assertEqual(simtrace2_board_name(""), "")

    def test_description_names_board_and_address(self) -> None:
        board = _board("616e", address=26, card_emulation=True)
        self.assertEqual(describe_usb_board(board), "ngff-cardem 1d50:616e at bus 3 device 26")
        other = UsbDeviceLocator(vendor_id="abcd", product_id="1234", bus=1, address=2)
        self.assertEqual(describe_usb_board(other), "abcd:1234 at bus 1 device 2")


class CardEmulationInterfaceStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)
        self.root = self._temp_dir.name

    def _state(self, interfaces, *, vidpid: str = "1d50:616e", locator=None):
        _sysfs_device(self.root, "3-4", bus=3, devnum=26, vidpid=vidpid, interfaces=interfaces)
        target = locator or _board("616e", address=26, card_emulation=None)
        return card_emulation_interface_state(target, sysfs_root=self.root)

    def test_the_cardem_application_is_card_emulation(self) -> None:
        self.assertIs(self._state(CARDEM_INTERFACES), True)

    def test_the_sniffer_application_is_not(self) -> None:
        self.assertIs(self._state(SNIFFER_INTERFACES), False)

    def test_the_bootloader_is_not(self) -> None:
        self.assertIs(self._state(BOOTLOADER_INTERFACES), False)

    def test_another_device_at_that_address_is_unknown(self) -> None:
        self.assertIsNone(self._state(CARDEM_INTERFACES, vidpid="1d50:60e3"))

    def test_a_device_without_interfaces_is_unknown(self) -> None:
        self.assertIsNone(self._state(()))

    def test_an_address_sysfs_does_not_list_is_unknown(self) -> None:
        elsewhere = _board("616e", address=27, card_emulation=None)
        self.assertIsNone(self._state(CARDEM_INTERFACES, locator=elsewhere))

    def test_a_locator_without_bus_and_address_is_unknown(self) -> None:
        self.assertIsNone(self._state(CARDEM_INTERFACES, locator=UsbDeviceLocator(vendor_id="1d50", product_id="616e")))

    def test_a_missing_sysfs_is_unknown(self) -> None:
        missing = os.path.join(self.root, "absent")
        board = _board("616e", address=26, card_emulation=None)
        self.assertIsNone(card_emulation_interface_state(board, sysfs_root=missing))

    def test_interface_entries_are_not_taken_for_devices(self) -> None:
        # An interface directory at the top level carries no busnum; the
        # device entry is found by its own busnum and devnum.
        _sysfs_device(self.root, "3-4", bus=3, devnum=26, vidpid="1d50:616e", interfaces=CARDEM_INTERFACES)
        os.makedirs(os.path.join(self.root, "3-4:1.0"))
        board = _board("616e", address=26, card_emulation=None)
        self.assertIs(card_emulation_interface_state(board, sysfs_root=self.root), True)


class ChooseCardEmulationBoardTests(unittest.TestCase):
    def test_card_emulation_wins_over_a_board_listed_before_it(self) -> None:
        sniffer = _board("60e3", address=10, card_emulation=False)
        ngff = _board("616e", address=26, card_emulation=True)
        self.assertIs(choose_card_emulation_board((sniffer, ngff)), ngff)

    def test_an_undescribed_board_is_taken_first_come(self) -> None:
        sniffer = _board("60e3", address=10, card_emulation=False)
        first = _board("616e", address=26, card_emulation=None)
        second = _board("60e3", address=27, card_emulation=None)
        self.assertIs(choose_card_emulation_board((sniffer, first, second)), first)
        self.assertEqual(boards_without_card_emulation((sniffer, first, second)), ())

    def test_no_board_when_every_one_lacks_card_emulation(self) -> None:
        sniffer = _board("60e3", address=10, card_emulation=False)
        bootloader = _board("616e", address=26, card_emulation=False)
        self.assertIsNone(choose_card_emulation_board((sniffer, bootloader)))
        self.assertEqual(boards_without_card_emulation((sniffer, bootloader)), (sniffer, bootloader))

    def test_unusable_locators_are_ignored(self) -> None:
        no_address = _board("616e", address=0, card_emulation=True)
        self.assertIsNone(choose_card_emulation_board((no_address,)))
        self.assertEqual(boards_without_card_emulation((no_address,)), ())
        self.assertEqual(boards_without_card_emulation(()), ())


class PresenceMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)
        self.root = self._temp_dir.name

    def test_default_selectors_alone_miss_the_ngff_cardem_lsusb_line(self) -> None:
        # Why the table exists: lsusb names the board after its vendor ID.
        self.assertEqual(
            _match_lines_from_lsusb_output(
                LSUSB_OUTPUT,
                match_terms=DEFAULT_USB_MATCH_TERMS,
                vidpids=("1d50:60e3",),
            ),
            [],
        )

    def test_every_board_id_is_watched_and_selectors_add_to_it(self) -> None:
        monitor = create_usb_presence_monitor(
            match_terms=(),
            vidpids=("abcd:1234",),
            prefer_pyudev=False,
            lsusb_path="lsusb",
        )
        self.assertEqual(monitor.vidpids, ("abcd:1234", *SIMTRACE2_FIRMWARE_VIDPIDS))

    def test_pyudev_snapshot_finds_the_ngff_cardem_by_its_id(self) -> None:
        _sysfs_device(self.root, "3-4", bus=3, devnum=26, vidpid="1d50:616e", interfaces=CARDEM_INTERFACES)
        # No descriptor string here carries a default match word.
        ngff = _FakeUdevDevice(
            ID_VENDOR_ID="1d50",
            ID_MODEL_ID="616e",
            BUSNUM="003",
            DEVNUM="026",
            ID_VENDOR_FROM_DATABASE="OpenMoko, Inc.",
            ID_MODEL="ngff-cardem",
        )
        root_hub = _FakeUdevDevice(
            ID_VENDOR_ID="1d6b",
            ID_MODEL_ID="0002",
            BUSNUM="003",
            DEVNUM="001",
            ID_VENDOR_FROM_DATABASE="Linux Foundation",
        )
        monitor = PyudevPresenceMonitor(
            match_terms=DEFAULT_USB_MATCH_TERMS,
            vidpids=SIMTRACE2_FIRMWARE_VIDPIDS,
            _context=_FakeUdevContext([root_hub, ngff]),
            _monitor=None,
            sysfs_root=self.root,
        )
        snapshot = monitor.snapshot()
        self.assertTrue(snapshot.present)
        self.assertEqual(snapshot.matches, (NGFF_LSUSB_LINE,))
        self.assertEqual(
            snapshot.devices,
            (_board("616e", address=26, card_emulation=True),),
        )

    def test_lsusb_snapshot_finds_the_ngff_cardem_in_card_emulation(self) -> None:
        _sysfs_device(self.root, "3-4", bus=3, devnum=26, vidpid="1d50:616e", interfaces=CARDEM_INTERFACES)
        monitor = create_usb_presence_monitor(
            match_terms=(),
            vidpids=(),
            prefer_pyudev=False,
            lsusb_path="lsusb",
        )
        monitor.sysfs_root = self.root
        completed = subprocess.CompletedProcess(args=["lsusb"], returncode=0, stdout=LSUSB_OUTPUT, stderr="")
        with mock.patch("Tools.HilBridge.supervisor.subprocess.run", return_value=completed):
            snapshot = monitor.snapshot()
        self.assertTrue(snapshot.present)
        self.assertEqual(snapshot.matches, (NGFF_LSUSB_LINE,))
        self.assertEqual(
            snapshot.devices,
            (_board("616e", address=26, card_emulation=True),),
        )


class SupervisorBoardChoiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)
        self.state_path = os.path.join(self._temp_dir.name, "supervisor.json")

    def _supervisor(self, snapshot: UsbPresenceSnapshot, *, extra_args: tuple[str, ...] = ()) -> HilBridgeSupervisor:
        return HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(),
                remsim_client=RemsimClientConfig(enabled=True, extra_args=extra_args),
                device_reset=SimtraceResetConfig(mode=RESET_MODE_USB_RESET),
                state_path=self.state_path,
            ),
            usb_monitor=_FixedMonitor(snapshot),
            monotonic=lambda: 0.0,
        )

    def test_the_client_is_pointed_at_the_card_emulation_board(self) -> None:
        snapshot = _snapshot(
            _board("60e3", address=10, card_emulation=False),
            _board("616e", address=26, card_emulation=True),
        )
        args = self._supervisor(snapshot)._auto_remsim_usb_args(snapshot)
        self.assertEqual(
            list(args),
            ["-V", "0x1d50", "-P", "0x616e", "-A", "26", "-C", "1", "-I", "0", "-S", "0"],
        )

    def test_no_selectors_when_no_board_emulates_a_card(self) -> None:
        snapshot = _snapshot(_board("616e", address=26, card_emulation=False))
        self.assertEqual(self._supervisor(snapshot)._auto_remsim_usb_args(snapshot), ())

    def test_the_reset_addresses_the_card_emulation_board(self) -> None:
        snapshot = _snapshot(
            _board("60e3", address=10, card_emulation=False),
            _board("616e", address=26, card_emulation=True),
        )
        supervisor = self._supervisor(snapshot)
        seen: dict = {}

        def _fake_reset(**kwargs):
            seen.update(kwargs)
            return SimtraceResetOutcome(performed=True, mode=RESET_MODE_USB_RESET, reenumerated=True)

        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fake_reset):
            supervisor._reset_device_before_session(snapshot)
        self.assertEqual((seen["bus"], seen["address"]), (3, 26))

    def test_a_board_without_card_emulation_is_never_reset(self) -> None:
        snapshot = _snapshot(_board("60e3", address=10, card_emulation=False))
        supervisor = self._supervisor(snapshot)

        def _fail(**_kwargs):
            self.fail("a sniffer or a bootloader must not be reset")

        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fail):
            self.assertIs(supervisor._reset_device_before_session(snapshot), snapshot)
        self.assertEqual(supervisor._device_reset_count, 0)

    def _reconcile(self, supervisor: HilBridgeSupervisor, popen) -> None:
        supervisor.popen_factory = popen
        with mock.patch.object(HilBridgeSupervisor, "_sim_backend_active", lambda _self: False):
            with mock.patch.object(HilBridgeSupervisor, "_cleanup_stale_bridge_marker"):
                # The reader lookup asks the host's PC/SC service.
                with mock.patch.object(HilBridgeSupervisor, "_local_reader_holder", lambda _self, _sim: None):
                    supervisor.reconcile()

    def test_a_board_in_its_bootloader_gets_no_client(self) -> None:
        snapshot = _snapshot(_board("616e", address=26, card_emulation=False))
        supervisor = self._supervisor(snapshot)
        started: list[str] = []

        def _popen(command, *_args, **_kwargs):
            started.append("remsim" if "osmo-remsim-client-st2" in str(command[0]) else "bridge")
            return _RunningChild()

        def _fail(**_kwargs):
            self.fail("a board without card emulation must not be reset")

        with mock.patch("Tools.HilBridge.supervisor.reset_simtrace_device", _fail):
            self._reconcile(supervisor, _popen)

        self.assertEqual(started, ["bridge"])
        with open(self.state_path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        self.assertEqual(state["status"], "running")
        self.assertIn("No board in card emulation", state["reason"])
        self.assertIn("ngff-cardem 1d50:616e at bus 3 device 26", state["reason"])

    def test_a_client_is_stopped_when_its_board_leaves_card_emulation(self) -> None:
        snapshot = _snapshot(_board("616e", address=26, card_emulation=False))
        supervisor = self._supervisor(snapshot)
        supervisor._child = _RunningChild(pid=1001)
        supervisor._remsim_child = _RunningChild(pid=1002)
        reasons: list[str] = []

        def _fake_stop(_self, reason: str) -> None:
            reasons.append(reason)
            _self._remsim_child = None

        with mock.patch.object(HilBridgeSupervisor, "_stop_remsim_child", _fake_stop):
            self._reconcile(supervisor, lambda *_args, **_kwargs: self.fail("nothing may start"))

        self.assertEqual(reasons, ["the SIMtrace2 board left card emulation."])

    def test_operator_selectors_are_not_overruled(self) -> None:
        snapshot = _snapshot(_board("616e", address=26, card_emulation=False))
        pinned = ("-V", "0x1d50", "-P", "0x616e", "-C", "1", "-I", "0", "-S", "0", "-H", "3-4")
        self.assertTrue(self._supervisor(snapshot, extra_args=pinned)._remsim_target_present(snapshot))
        self.assertFalse(self._supervisor(snapshot)._remsim_target_present(snapshot))

    def test_several_card_emulation_boards_are_named_when_the_client_starts(self) -> None:
        snapshot = _snapshot(
            _board("60e3", address=10, card_emulation=True),
            _board("616e", address=26, card_emulation=True),
        )
        supervisor = self._supervisor(snapshot)
        with self.assertLogs("Tools.HilBridge.supervisor", level="WARNING") as captured:
            supervisor._warn_on_several_card_emulation_boards(snapshot)
        self.assertEqual(len(captured.records), 1)
        message = captured.records[0].getMessage()
        self.assertIn("2 card-emulation boards attached", message)
        self.assertIn("the REMSIM client takes SIMtrace2 1d50:60e3 at bus 3 device 10", message)

    def test_one_board_or_pinned_selectors_raise_no_warning(self) -> None:
        one = _snapshot(_board("616e", address=26, card_emulation=True))
        two = _snapshot(
            _board("60e3", address=10, card_emulation=True),
            _board("616e", address=26, card_emulation=True),
        )
        pinned = ("-P", "0x616e")
        with mock.patch("Tools.HilBridge.supervisor.LOGGER") as logger:
            self._supervisor(one)._warn_on_several_card_emulation_boards(one)
            self._supervisor(two, extra_args=pinned)._warn_on_several_card_emulation_boards(two)
        logger.warning.assert_not_called()


class StandaloneResetTests(unittest.TestCase):
    """yggdrasim-hil-reset takes the same board, and names it."""

    def _run(self, snapshot: UsbPresenceSnapshot, outcome: SimtraceResetOutcome):
        seen: dict = {}

        def _fake_reset(**kwargs):
            seen.update(kwargs)
            return outcome

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["yggdrasim-hil-reset", "--simtrace-reset", "usb-reset"]), mock.patch(
            "Tools.HilBridge.supervisor.create_usb_presence_monitor",
            return_value=_FixedMonitor(snapshot),
        ), mock.patch.object(device_reset, "reset_simtrace_device", _fake_reset), mock.patch(
            "yggdrasim_common.process_debug.set_global_debug"
        ), mock.patch.object(device_reset.logging, "basicConfig"):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = device_reset.run_standalone()
        return code, seen, stdout.getvalue(), stderr.getvalue()

    def test_the_card_emulation_board_is_reset_and_named(self) -> None:
        snapshot = _snapshot(
            _board("60e3", address=10, card_emulation=False),
            _board("616e", address=26, card_emulation=True),
        )
        outcome = SimtraceResetOutcome(performed=True, mode=RESET_MODE_USB_RESET, detail="reset", reenumerated=False)
        code, seen, stdout, stderr = self._run(snapshot, outcome)
        self.assertEqual((seen["bus"], seen["address"]), (3, 26))
        self.assertIn("Resetting ngff-cardem 1d50:616e at bus 3 device 26.", stdout)
        self.assertIn("`lsusb -d 1d50:616e`", stderr)
        self.assertEqual(code, 1)

    def test_a_sniffer_is_still_reset_when_it_is_the_only_board(self) -> None:
        snapshot = _snapshot(_board("60e3", address=10, card_emulation=False))
        outcome = SimtraceResetOutcome(performed=True, mode=RESET_MODE_USB_RESET, detail="reset", reenumerated=True)
        code, seen, stdout, _stderr = self._run(snapshot, outcome)
        self.assertEqual((seen["bus"], seen["address"]), (3, 10))
        self.assertIn("Resetting SIMtrace2 1d50:60e3 at bus 3 device 10.", stdout)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
