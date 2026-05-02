"""Pytest session bootstrap for the YggdraSIM test suite.

The runtime hardening layers below have distinct default postures:

- ``YGGDRASIM_ALLOW_PLUGINS`` / ``YGGDRASIM_DISALLOW_PLUGINS``: plugin
  modules under ``plugins/`` load by default. Set ``DISALLOW=1`` (or
  ``ALLOW=0``) to hard-lock the loader. See
  ``yggdrasim_common/plugin_runtime.py``.
- ``YGGDRASIM_ALLOW_QUIRKS``: simulator quirks files (executed as Python)
  must still be explicitly enabled at launch; otherwise the simulator
  refuses to load them (see ``SIMCARD/quirks.py``).
- ``YGGDRASIM_CARD_BACKEND``: pinned to ``sim`` for the entire test
  session so unit tests that build an ``EimLocalShell`` / ``...Session``
  (and therefore a ``PcscApduChannel``) don't reach for a real PC/SC
  reader. CI runners have no card hardware and ``pcscd`` either is
  missing or refuses ``SCardEstablishContext`` with ``Access denied
  (0x8010006A)``. Tests that *want* the reader path can still override
  via ``mock.patch.dict(os.environ, {"YGGDRASIM_CARD_BACKEND": "reader"}, ...)``
  inside their own scope.

Unit tests exercise the real plugin / quirk contracts, so the full test
suite runs with both gates open. The ``YGGDRASIM_ALLOW_PLUGINS=1``
default below is redundant after the plugin-loader default flip but
kept as a belt-and-suspenders guard for future changes. Individual
tests that want to verify the refusal path override these flags
locally via ``mock.patch.dict(os.environ, {...}, clear=False)``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# The repo ``plugins/`` directory is a runtime-loaded namespace package
# (no __init__.py by design -- see ``yggdrasim_common/plugin_runtime.py``),
# so tests that import it directly require the repo root on sys.path.
# editable installs don't cover ``plugins/`` because it's excluded from
# ``[tool.setuptools.packages.find]``.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _default_env(name: str, value: str) -> None:
    if os.environ.get(name) is None:
        os.environ[name] = value


_default_env("YGGDRASIM_ALLOW_PLUGINS", "1")
_default_env("YGGDRASIM_ALLOW_QUIRKS", "1")
_default_env("YGGDRASIM_CARD_BACKEND", "sim")


def pytest_addoption(parser):
    parser.addoption(
        "--runslow",
        action="store_true",
        default=False,
        help="Include tests marked as ``slow`` (heavy pySim SAIP / profile decode).",
    )


_PYSIM_DEPENDENT_TEST_BASENAMES = frozenset(
    {
        "test_saip_aka_wizard.py",
        "test_saip_asn1_opaque_ef_catalog.py",
        "test_saip_asn1_passthrough_encoders.py",
        "test_saip_decoded_edit_audit.py",
        "test_saip_json_codec.py",
        "test_saip_json_codec_translation.py",
        "test_saip_pe_quick_add.py",
        "test_saip_profile_scaffold.py",
        "test_saip_profile_template.py",
        "test_saip_profile_ux.py",
        "test_saip_transcode_tui.py",
        "test_scp11_local_access.py",
        "test_scp11_orchestrator.py",
        "test_scp11_payloads.py",
        "test_profile_package_shell.py",
        "test_profile_package_lint_engine.py",
        "test_simcard_backend.py",
    }
)


def _pysim_available() -> tuple[bool, str]:
    """Report whether ``pySim.esim.saip`` is importable in this env.

    ``pySim`` is an **upstream** dependency. We accept any of the three
    legitimate provisioning paths without favouring one:

    1. Installed from git via the ``[saip]`` extra
       (``pip install 'yggdrasim[saip]'``), which is the recommended
       path for operators and CI.
    2. Installed by hand
       (``pip install 'pySim @ git+https://github.com/osmocom/pysim.git'``).
    3. A developer checkout at ``<repo>/pysim`` (or ``<repo>/pySim``),
       opted into by cloning the tree. This path is still supported
       so maintainers working against an unreleased upstream branch
       don't have to reinstall after every change.

    We **do not** require the on-disk clone. If option 1 or 2 resolved
    ``pySim.esim.saip`` we succeed; only when **all three** fail do we
    surface the import error and downgrade pySim-dependent tests to
    ``skipped``. The message points the operator at the ``[saip]``
    extra because that is the path that turns this from "soft
    dependency" into "just works on a fresh checkout".
    """
    pysim_root = _REPO_ROOT / "pysim"
    if pysim_root.is_dir() and str(pysim_root) not in sys.path:
        sys.path.insert(0, str(pysim_root))
    try:
        import pySim.esim.saip  # noqa: F401  (import-probe only)
    except Exception as import_error:
        return False, f"{type(import_error).__name__}: {import_error}"
    return True, ""


def pytest_collection_modifyitems(config, items):
    if config.getoption("--runslow") is False:
        skip_slow = pytest.mark.skip(
            reason="Opt in with --runslow (heavy pySim decode path)."
        )
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)
    pysim_ok, pysim_error = _pysim_available()
    if pysim_ok is False:
        skip_no_pysim = pytest.mark.skip(
            reason=(
                "pySim is not importable in this environment. "
                "Preferred install: `pip install 'yggdrasim[saip]'`. "
                "Manual install: `pip install "
                "'pySim @ git+https://github.com/osmocom/pysim.git'`. "
                "Developer-checkout fallback: clone the upstream tree "
                f"into {_REPO_ROOT / 'pysim'}. "
                f"Underlying import error: {pysim_error}."
            )
        )
        for item in items:
            basename = Path(str(item.fspath)).name
            if basename in _PYSIM_DEPENDENT_TEST_BASENAMES:
                item.add_marker(skip_no_pysim)
