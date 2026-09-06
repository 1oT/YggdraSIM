# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""The resolver override that keeps Twisted out of the lock.

pySim declares smpp.twisted3 in install_requires although only its
pySim-smpp2sim.py script and contrib/smpp-ota-tool.py use it, and that
library pins Twisted~=23.10.0 in every release, a Twisted with three open
advisories. pyproject.toml overrides the requirement with a marker that
can never hold, so the resolver drops it (see
upstream_patches/osmocom-pysim-smpp-twisted-optional/ for the proposed
upstream change). These tests pin the effect and retire the override the
day pySim stops declaring the dependency.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OVERRIDDEN = "smpp-twisted3"
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


def _load(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


class DependencyOverrideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pyproject = _load(REPO_ROOT / "pyproject.toml")
        cls.lock = _load(REPO_ROOT / "uv.lock")
        cls.packages = {pkg["name"]: pkg for pkg in cls.lock["package"]}

    def _pysim_declares_smpp_twisted(self) -> bool:
        pysim = self.packages["pysim"]
        names = {dep["name"] for dep in pysim.get("dependencies", [])}
        return OVERRIDDEN in names

    def test_override_is_declared_with_an_impossible_marker(self) -> None:
        overrides = self.pyproject["tool"]["uv"]["override-dependencies"]
        self.assertIn(f"{OVERRIDDEN} ; python_version < '0'", overrides)
        # uv records the override in the lock with the marker normalised to
        # python_full_version; either spelling is the same impossible test.
        recorded = self.lock["manifest"]["overrides"]
        self.assertEqual([entry["name"] for entry in recorded], [OVERRIDDEN])
        self.assertIn(
            recorded[0]["marker"],
            ("python_version < '0'", "python_full_version < '0'"),
        )

    def test_twisted_and_its_tail_are_out_of_the_lock(self) -> None:
        present = PRUNED & set(self.packages)
        self.assertEqual(present, set(), f"still locked: {sorted(present)}")

    def test_the_smpp_pdu_codec_the_local_access_session_uses_stays(self) -> None:
        # SCP11/local_access/session.py imports smpp.pdu, which pySim pulls
        # in as its own dependency; the override must not take it away.
        self.assertIn("smpp-pdu", self.packages)
        pysim_deps = {dep["name"] for dep in self.packages["pysim"]["dependencies"]}
        self.assertIn("smpp-pdu", pysim_deps)

    def test_override_removes_the_edge_from_pysim(self) -> None:
        # The lock records the graph after overrides, so pySim's entry must
        # not point at smpp-twisted3 any more. The lock cannot tell whether
        # pySim still declares the requirement upstream: when the pinned
        # commit's setup.py drops smpp.twisted3 from install_requires, delete
        # the override in pyproject.toml [tool.uv], run `uv lock`, and retire
        # this file.
        self.assertFalse(self._pysim_declares_smpp_twisted())


if __name__ == "__main__":
    unittest.main()
