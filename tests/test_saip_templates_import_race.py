# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Two threads importing pySim's SAIP package at once: the tree's entry survives it.

``pySim/esim/saip/templates.py`` imports ``pySim.esim.saip.oid as OID``, which
waits on the package's import lock while another thread runs the package's
``__init__``; Python breaks that lock cycle by handing the package thread a
half-built templates module ("partially initialized module ... has no
attribute 'FileTemplate'"). The GUI met it once on the first profile open,
while a second request imported the templates module directly.

Each run is a fresh interpreter: thread A imports the package, thread B starts
once A has registered it and then imports templates. The tree's
``import_saip_templates`` (the package first) must survive every run; the raw
submodule import on the installed pySim must still fail, and once it stops
failing the compensation has outlived its cause. Evidence and the upstream
patch: ``upstream_patches/osmocom-pysim-saip-templates-import-race/``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNS = 3

_RACE = r"""
import sys
import threading

barrier = threading.Barrier(2)
errors = []


def thread_a():
    barrier.wait()
    try:
        from pySim.esim.saip import ProfileElement, templates
        templates.FileTemplate
    except BaseException as error:
        errors.append(f"A {type(error).__name__}: {error}")


def thread_b():
    barrier.wait()
    while "pySim.esim.saip" not in sys.modules:
        pass
    try:
        %s
        templates_module.ProfileTemplateRegistry
    except BaseException as error:
        errors.append(f"B {type(error).__name__}: {error}")


threads = [threading.Thread(target=thread_a), threading.Thread(target=thread_b)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
print(errors[0] if errors else "ok")
"""

_TREE_ENTRY = (
    "from yggdrasim_common.pysim_saip_import import import_saip_templates; "
    "templates_module = import_saip_templates()"
)
_RAW_ENTRY = "import pySim.esim.saip.templates as templates_module"


def _outcomes(b_entry: str) -> list[str]:
    pytest.importorskip("pySim.esim.saip")
    environment = {**os.environ, "PCSCLITE_CSOCK_NAME": "/nonexistent/pcscd.comm"}
    outcomes = []
    for _ in range(RUNS):
        done = subprocess.run(
            [sys.executable, "-c", _RACE % b_entry],
            cwd=str(ROOT),
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
        )
        lines = done.stdout.strip().splitlines()
        outcomes.append(lines[-1] if lines else f"no output (exit {done.returncode}): {done.stderr[-300:]}")
    return outcomes


def test_the_tree_entry_survives_a_concurrent_package_import() -> None:
    outcomes = _outcomes(_TREE_ENTRY)
    assert outcomes == ["ok"] * RUNS, outcomes


def test_the_installed_pysim_still_has_the_race() -> None:
    outcomes = _outcomes(_RAW_ENTRY)
    failures = [outcome for outcome in outcomes if outcome != "ok"]
    if not failures:
        pytest.fail(
            "The raw import of pySim.esim.saip.templates survived the race on the "
            "installed pySim, so the pin carries the upstream fix. Delete "
            "yggdrasim_common/pysim_saip_import.py, point "
            "its callers back at the plain import, and delete this file; see "
            "upstream_patches/osmocom-pysim-saip-templates-import-race."
        )
    assert all("partially initialized module 'pySim.esim.saip.templates'" in outcome for outcome in failures), failures
