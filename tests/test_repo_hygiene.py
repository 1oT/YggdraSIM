# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Release-hygiene gate: no new CLAUDE.md section 1-4 violations.

The tree carries accepted typography and prose violations recorded in
``scripts/repo_hygiene_baseline.json``. This asserts the set does not
grow. Shrinking it is the goal; re-record with
``python scripts/check_repo_hygiene.py --write-baseline`` only when
violations have been removed.
"""

from __future__ import annotations

import unittest

from scripts.check_repo_hygiene import collect, load_baseline, new_violations


class RepoHygieneTests(unittest.TestCase):
    def test_no_new_hygiene_violations(self) -> None:
        new = new_violations(collect(), load_baseline())
        formatted = "\n".join(
            f"  [{item.check}] {item.path}:{item.line} {item.detail}" for item in new[:40]
        )
        self.assertEqual(
            new,
            [],
            "new release-hygiene violations were introduced:\n" + formatted,
        )

    def test_identifier_and_report_rules_stay_clean(self) -> None:
        """Section 1 identifiers and section 3 report filenames carry no baseline.

        These two never had accepted violations, so any hit is new work
        regardless of the baseline file.
        """
        offenders = [
            violation
            for violation in collect()
            if violation.check in {"iccid-ascii", "iccid-bcd", "report-filename"}
        ]
        formatted = "\n".join(
            f"  [{item.check}] {item.path}:{item.line} {item.detail}" for item in offenders
        )
        self.assertEqual(offenders, [], "reserved-range or report-path violation:\n" + formatted)


if __name__ == "__main__":
    unittest.main()
