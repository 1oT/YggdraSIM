# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SCP11/shared/gsma_error_codes.py.

Covers all 13 public functions:
  describe_sgp22_profile_state_result, describe_sgp22_notification_sent_result,
  describe_sgp22_download_error, describe_sgp22_profile_installation_reason,
  describe_sgp32_eim_package_error, describe_sgp32_eim_package_result_error,
  describe_sgp32_profile_download_error_reason,
  resolve_sgp22_profile_state_result_code, resolve_sgp22_download_error_code,
  resolve_sgp22_profile_installation_reason_code,
  resolve_sgp32_eim_package_error_code, resolve_sgp32_eim_package_result_error_code,
  resolve_sgp32_profile_download_error_reason_code.
"""

from __future__ import annotations

import unittest

from SCP11.shared.gsma_error_codes import (
    describe_sgp22_download_error,
    describe_sgp22_notification_sent_result,
    describe_sgp22_profile_installation_reason,
    describe_sgp22_profile_state_result,
    describe_sgp32_eim_package_error,
    describe_sgp32_eim_package_result_error,
    describe_sgp32_profile_download_error_reason,
    resolve_sgp22_download_error_code,
    resolve_sgp22_profile_installation_reason_code,
    resolve_sgp22_profile_state_result_code,
    resolve_sgp32_eim_package_error_code,
    resolve_sgp32_eim_package_result_error_code,
    resolve_sgp32_profile_download_error_reason_code,
)


# ---------------------------------------------------------------------------
# describe_* functions: return human-readable string for a numeric code
# ---------------------------------------------------------------------------

class DescribeSgp22ProfileStateResultTests(unittest.TestCase):

    def test_known_code_zero_ok(self) -> None:
        result = describe_sgp22_profile_state_result(0)
        self.assertIsInstance(result, str)
        self.assertIn("ok", result.lower())

    def test_unknown_code_contains_code(self) -> None:
        result = describe_sgp22_profile_state_result(99)
        self.assertIn("99", result)


class DescribeSgp22NotificationSentResultTests(unittest.TestCase):

    def test_known_code_returns_string(self) -> None:
        result = describe_sgp22_notification_sent_result(0)
        self.assertIsInstance(result, str)

    def test_unknown_code_contains_code(self) -> None:
        result = describe_sgp22_notification_sent_result(200)
        self.assertIn("200", result)


class DescribeSgp22DownloadErrorTests(unittest.TestCase):

    def test_code_1_invalid_certificate(self) -> None:
        result = describe_sgp22_download_error(1)
        self.assertIsInstance(result, str)
        self.assertIn("invalidCertificate", result)

    def test_unknown_code_returns_string(self) -> None:
        result = describe_sgp22_download_error(255)
        self.assertIsInstance(result, str)


class DescribeSgp22ProfileInstallationReasonTests(unittest.TestCase):

    def test_code_1_incorrect_input(self) -> None:
        result = describe_sgp22_profile_installation_reason(1)
        self.assertIsInstance(result, str)

    def test_unknown_code_returns_string(self) -> None:
        result = describe_sgp22_profile_installation_reason(127)
        self.assertIsInstance(result, str)


class DescribeSgp32EimPackageErrorTests(unittest.TestCase):

    def test_code_1_no_package(self) -> None:
        result = describe_sgp32_eim_package_error(1)
        self.assertIsInstance(result, str)
        self.assertIn("noEimPackageAvailable", result)

    def test_unknown_code_returns_string(self) -> None:
        result = describe_sgp32_eim_package_error(250)
        self.assertIsInstance(result, str)


class DescribeSgp32EimPackageResultErrorTests(unittest.TestCase):

    def test_code_1_invalid_format(self) -> None:
        result = describe_sgp32_eim_package_result_error(1)
        self.assertIsInstance(result, str)

    def test_unknown_code_returns_string(self) -> None:
        result = describe_sgp32_eim_package_result_error(99)
        self.assertIsInstance(result, str)


class DescribeSgp32ProfileDownloadErrorReasonTests(unittest.TestCase):

    def test_code_1_transaction_id_error(self) -> None:
        result = describe_sgp32_profile_download_error_reason(1)
        self.assertIsInstance(result, str)

    def test_unknown_code_returns_string(self) -> None:
        result = describe_sgp32_profile_download_error_reason(254)
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# resolve_* functions: map string/int values back to integer codes
# ---------------------------------------------------------------------------

class ResolveSgp22ProfileStateResultCodeTests(unittest.TestCase):

    def test_integer_known_code_passthrough(self) -> None:
        self.assertEqual(resolve_sgp22_profile_state_result_code(0), 0)

    def test_string_digit_resolves(self) -> None:
        self.assertEqual(resolve_sgp22_profile_state_result_code("0"), 0)

    def test_unknown_int_returns_default(self) -> None:
        self.assertEqual(resolve_sgp22_profile_state_result_code(999, 127), 127)

    def test_name_string_resolves(self) -> None:
        result = resolve_sgp22_profile_state_result_code("ok")
        self.assertEqual(result, 0)

    def test_empty_string_returns_default(self) -> None:
        self.assertEqual(resolve_sgp22_profile_state_result_code("", 5), 5)

    def test_bool_returns_default(self) -> None:
        self.assertEqual(resolve_sgp22_profile_state_result_code(True, 3), 3)


class ResolveSgp22DownloadErrorCodeTests(unittest.TestCase):

    def test_known_int_passthrough(self) -> None:
        self.assertEqual(resolve_sgp22_download_error_code(1), 1)

    def test_unknown_returns_default(self) -> None:
        self.assertEqual(resolve_sgp22_download_error_code(999, 127), 127)

    def test_name_string_resolves(self) -> None:
        result = resolve_sgp22_download_error_code("invalidCertificate")
        self.assertEqual(result, 1)


class ResolveSgp22ProfileInstallationReasonCodeTests(unittest.TestCase):

    def test_known_int_passthrough(self) -> None:
        self.assertEqual(resolve_sgp22_profile_installation_reason_code(1), 1)

    def test_unknown_returns_default(self) -> None:
        self.assertEqual(resolve_sgp22_profile_installation_reason_code(999, 127), 127)


class ResolveSgp32EimPackageErrorCodeTests(unittest.TestCase):

    def test_known_int_passthrough(self) -> None:
        self.assertEqual(resolve_sgp32_eim_package_error_code(1), 1)

    def test_unknown_returns_default(self) -> None:
        self.assertEqual(resolve_sgp32_eim_package_error_code(500, 127), 127)

    def test_name_resolves(self) -> None:
        result = resolve_sgp32_eim_package_error_code("noEimPackageAvailable")
        self.assertEqual(result, 1)


class ResolveSgp32EimPackageResultErrorCodeTests(unittest.TestCase):

    def test_known_int_passthrough(self) -> None:
        self.assertEqual(resolve_sgp32_eim_package_result_error_code(1), 1)

    def test_unknown_returns_default(self) -> None:
        self.assertEqual(resolve_sgp32_eim_package_result_error_code(500, 127), 127)


class ResolveSgp32ProfileDownloadErrorReasonCodeTests(unittest.TestCase):

    def test_known_int_passthrough(self) -> None:
        self.assertEqual(resolve_sgp32_profile_download_error_reason_code(1), 1)

    def test_unknown_returns_default(self) -> None:
        self.assertEqual(resolve_sgp32_profile_download_error_reason_code(500, 127), 127)

    def test_name_resolves(self) -> None:
        result = resolve_sgp32_profile_download_error_reason_code("transactionIdError")
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
