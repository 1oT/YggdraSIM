# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Unit tests for the ``yggdrasim_common.doctor`` preflight helper.

The tests focus on the report structure and exit-code semantics. They
avoid asserting on specific system dependencies (cryptography / pySim /
reader availability) so the test run stays deterministic on any host.
Flavor- and HIL-specific probes are exercised through targeted helper
tests that stub the flavor module so the report remains deterministic
across the CI matrix.
"""

import os
import unittest
from unittest import mock

from yggdrasim_common import doctor
from yggdrasim_common import flavor
from yggdrasim_common.doctor import DoctorCheck, DoctorReport, run_doctor


class DoctorReportTests(unittest.TestCase):
    def test_worst_status_ok_when_only_ok_present(self) -> None:
        report = DoctorReport()
        report.add("A", "ok", "fine")
        report.add("B", "info", "note")
        self.assertIn(report.worst_status(), {"ok", "info"})

    def test_worst_status_warn_over_ok(self) -> None:
        report = DoctorReport()
        report.add("A", "ok", "")
        report.add("B", "warn", "something")
        self.assertEqual(report.worst_status(), "warn")

    def test_worst_status_fail_over_warn(self) -> None:
        report = DoctorReport()
        report.add("A", "warn", "")
        report.add("B", "fail", "broken")
        self.assertEqual(report.worst_status(), "fail")


class RunDoctorExitCodeTests(unittest.TestCase):
    def test_run_doctor_returns_exit_code_and_writes_report(self) -> None:
        captured: list[str] = []
        exit_code = run_doctor(writer=captured.append)
        joined = "\n".join(captured)
        self.assertIn("YggdraSIM doctor", joined)
        self.assertIn("Python runtime", joined)
        self.assertIn("Build flavor", joined)
        self.assertIn(exit_code, {0, 1})


class DoctorCheckFormattingTests(unittest.TestCase):
    def test_format_check_includes_name_and_status(self) -> None:
        check = DoctorCheck("Sample", "ok", "details")
        rendered = doctor._format_check(check)
        self.assertIn("Sample", rendered)
        self.assertIn("OK", rendered)
        self.assertIn("details", rendered)


class DoctorFlavorProbeTests(unittest.TestCase):
    def test_flavor_probe_reports_active_flavor(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            report = DoctorReport()
            doctor._probe_flavor(report)
            self.assertEqual(len(report.checks), 1)
            self.assertEqual(report.checks[0].name, "Build flavor")
            self.assertEqual(report.checks[0].status, "ok")
            self.assertIn("clean", report.checks[0].detail.lower())


class DoctorHilProbeTests(unittest.TestCase):
    def test_clean_flavor_short_circuits_with_info_note(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            report = DoctorReport()
            doctor._probe_hil_bridge(report)
            self.assertEqual(len(report.checks), 1)
            check = report.checks[0]
            self.assertEqual(check.name, "Local HIL bridge readiness")
            self.assertEqual(check.status, "info")
            self.assertIn("clean", check.detail.lower())
            self.assertIn("Card Bridge", check.detail)

    def test_non_linux_full_reports_platform_info(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "full"}, clear=False):
            with mock.patch.object(flavor.sys, "platform", "win32"):
                report = DoctorReport()
                doctor._probe_hil_bridge(report)
                self.assertEqual(len(report.checks), 1)
                self.assertEqual(report.checks[0].name, "Local HIL bridge readiness")
                self.assertEqual(report.checks[0].status, "info")
                self.assertIn("Linux", report.checks[0].detail)
                self.assertIn("Card Bridge", report.checks[0].detail)

    def test_optional_helpers_skipped_on_clean(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            report = DoctorReport()
            doctor._probe_hil_optional_helpers(report)
            self.assertEqual(len(report.checks), 0)


if __name__ == "__main__":
    unittest.main()
