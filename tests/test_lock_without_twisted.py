# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Twisted stays out of uv.lock.

Upstream pySim lists smpp.twisted3 in install_requires although only its
pySim-smpp2sim.py script uses it, and every release of that library pins
Twisted~=23.10.0, a Twisted with three open advisories. The pinned pySim
(hampushellsberg-dev/pysim, carrying
upstream_patches/osmocom-pysim-smpp-twisted-optional/) moves it to a
``smpp2sim`` extra that YggdraSIM does not request, which retired the
resolver override pyproject.toml carried before. A pin to a pySim that
declares the requirement again fails here.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
# Everything that only ever entered the lock through smpp.twisted3.
PRUNED = frozenset(
    {
        "smpp-twisted3",
        "smpp-pdu3",
        "twisted",
        "twisted-iocpsupport",
        "automat",
        "constantly",
        "hyperlink",
        "incremental",
        "zope-interface",
    }
)


class LockWithoutTwistedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with (REPO_ROOT / "uv.lock").open("rb") as handle:
            lock = tomllib.load(handle)
        cls.packages = {pkg["name"]: pkg for pkg in lock["package"]}

    def test_pysim_does_not_depend_on_smpp_twisted(self) -> None:
        names = {dep["name"] for dep in self.packages["pysim"].get("dependencies", [])}
        self.assertNotIn("smpp-twisted3", names)

    def test_twisted_and_its_tail_are_out_of_the_lock(self) -> None:
        present = PRUNED & set(self.packages)
        self.assertEqual(present, set(), f"still locked: {sorted(present)}")

    def test_the_smpp_pdu_codec_the_local_access_session_uses_stays(self) -> None:
        # SCP11/local_access/session.py imports smpp.pdu, which pySim pulls
        # in as its own dependency.
        self.assertIn("smpp-pdu", self.packages)
        pysim_deps = {dep["name"] for dep in self.packages["pysim"]["dependencies"]}
        self.assertIn("smpp-pdu", pysim_deps)


if __name__ == "__main__":
    unittest.main()
