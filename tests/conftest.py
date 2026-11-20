# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Pytest session bootstrap for the YggdraSIM test suite.

The runtime hardening layers below have distinct default postures:

- ``YGGDRASIM_ALLOW_PLUGINS`` / ``YGGDRASIM_DISALLOW_PLUGINS``: plugin
  modules under ``plugins/`` are refused by default. Set ``ALLOW=1`` to
  load them for tests; set ``DISALLOW=1`` to hard-lock the loader. See
  ``yggdrasim_common/plugin_runtime.py``.
- ``YGGDRASIM_ALLOW_QUIRKS``: simulator quirks files (executed as Python)
  must still be explicitly enabled at launch; otherwise the simulator
  refuses to load them (see ``SIMCARD/quirks.py``).

The default regression suite keeps runtime plugin loading closed so
operator-local extension folders cannot affect CI. Individual tests that
exercise the plugin gate opt in locally via
``mock.patch.dict(os.environ, {...}, clear=False)`` or the local
``_EnvScope`` helper.
"""

from __future__ import annotations

import atexit
import errno
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# The universal placeholder test-value list is per-user operator data
# (``~/.yggdrasim/saip_universal_tokens.csv``) and seeds every opened
# template. Tests must see the same thing CI sees -- no list -- unless
# they point the variable at a list of their own.
os.environ.setdefault(
    "YGGDRASIM_SAIP_UNIVERSAL_TOKENS",
    os.path.join(tempfile.gettempdir(), "yggdrasim-tests-no-universal-list.csv"),
)

# The AddInitialEim builder store (``~/.yggdrasim/eim_builder``) holds the
# operator's certificates and typed values. A test run gets an empty store
# of its own, removed at exit, so no test reads or writes the real one.
if "YGGDRASIM_EIM_BUILDER_STORE" not in os.environ:
    _EIM_BUILDER_STORE = tempfile.mkdtemp(prefix="yggdrasim-tests-eim-builder-")
    os.environ["YGGDRASIM_EIM_BUILDER_STORE"] = _EIM_BUILDER_STORE
    atexit.register(shutil.rmtree, _EIM_BUILDER_STORE, True)

# The Local eIM engine store (``~/.yggdrasim/local_eim``) holds the operator's
# eIM identity, private keys and operation queue; a test run gets its own.
if "YGGDRASIM_LOCAL_EIM_STORE" not in os.environ:
    _LOCAL_EIM_STORE = tempfile.mkdtemp(prefix="yggdrasim-tests-local-eim-")
    os.environ["YGGDRASIM_LOCAL_EIM_STORE"] = _LOCAL_EIM_STORE
    atexit.register(shutil.rmtree, _LOCAL_EIM_STORE, True)


# The repo ``plugins/`` directory is a runtime-loaded namespace package
# (no __init__.py by design -- see ``yggdrasim_common/plugin_runtime.py``),
# so tests that import it directly require the repo root on sys.path.
# editable installs don't cover ``plugins/`` because it's excluded from
# ``[tool.setuptools.packages.find]``.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# A developer checkout at ``<repo>/pysim`` has to reach sys.path before
# any test module imports pySim, not when collection has already
# finished: the first import binds ``sys.modules["pySim"]`` for the
# session, and a later path insertion cannot displace it. Deciding the
# tree here is what makes a single-file run and a full-suite run compile
# the same ASN.1 -- a checkout and the installed pin need not carry the
# same fixes (an older checkout compiled ``StoreMetadataRequest`` with
# nine members where the pin has nineteen, per
# ``upstream_patches/osmocom-pysim-rsp-v3-metadata/``), so the losing
# order silently changes the schema.
_PYSIM_CHECKOUT = _REPO_ROOT / "pysim"
if _PYSIM_CHECKOUT.is_dir() and str(_PYSIM_CHECKOUT) not in sys.path:
    sys.path.insert(0, str(_PYSIM_CHECKOUT))


def _default_env(name: str, value: str) -> None:
    if os.environ.get(name) is None:
        os.environ[name] = value


_TEST_ISOLATION_ROOT: Path | None = None
if os.environ.get("YGGDRASIM_TEST_USE_AMBIENT_STATE", "").strip() != "1":
    _TEST_ISOLATION_ROOT = Path(
        tempfile.mkdtemp(prefix="yggdrasim-test-environment-")
    ).resolve()
    _ISOLATED_ENVIRONMENT = {
        "HOME": _TEST_ISOLATION_ROOT / "home",
        "USERPROFILE": _TEST_ISOLATION_ROOT / "home",
        "GNUPGHOME": _TEST_ISOLATION_ROOT / "gnupg",
        "XDG_CONFIG_HOME": _TEST_ISOLATION_ROOT / "xdg-config",
        "XDG_CACHE_HOME": _TEST_ISOLATION_ROOT / "xdg-cache",
        "XDG_STATE_HOME": _TEST_ISOLATION_ROOT / "xdg-state",
        "XDG_DATA_HOME": _TEST_ISOLATION_ROOT / "xdg-data",
        "YGGDRASIM_RUNTIME_ROOT": _TEST_ISOLATION_ROOT / "runtime",
    }
    for environment_name, directory in _ISOLATED_ENVIRONMENT.items():
        directory.mkdir(parents=True, exist_ok=True)
        if environment_name == "GNUPGHOME":
            directory.chmod(0o700)
        os.environ[environment_name] = str(directory)
    atexit.register(shutil.rmtree, _TEST_ISOLATION_ROOT, True)


os.environ["YGGDRASIM_ALLOW_PLUGINS"] = "0"
os.environ.pop("YGGDRASIM_DISALLOW_PLUGINS", None)
_default_env("YGGDRASIM_ALLOW_QUIRKS", "1")


@pytest.fixture(autouse=True)
def _restore_regression_env_defaults():
    """Restore process-wide defaults after tests that deliberately clear env vars."""
    _default_env("YGGDRASIM_ALLOW_QUIRKS", "1")
    yield


@pytest.fixture(autouse=True, scope="session")
def _reader_locks_in_a_scratch_directory(tmp_path_factory):
    """Keep every test's reader locks out of the real lock directory.

    Every YggdraSIM process of the user honours the files under
    ``~/.yggdrasim/run/reader-locks`` (``yggdrasim_common/reader_locks.py``),
    a live card or HIL rig running beside the suite included, so a test must not
    take one there even when HOME is the ambient one.
    """
    from yggdrasim_common import reader_locks

    previous = reader_locks._DIRECTORY
    reader_locks._DIRECTORY = tmp_path_factory.mktemp("reader-locks")
    yield
    reader_locks._DIRECTORY = previous


@pytest.fixture
def require_loopback_socket() -> None:
    """Skip socket integration when the execution sandbox forbids networking."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM}:
            pytest.skip(f"loopback sockets are unavailable in this environment: {exc}")
        raise


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
        "test_saip_inline_template_values.py",
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

_LOCAL_EXTENSION_TESTS = _REPO_ROOT / "tests" / "plugins"


def _ignored_test_paths() -> frozenset[Path]:
    try:
        result = subprocess.run(
            [
                "git",
                "ls-files",
                "-z",
                "--others",
                "--ignored",
                "--exclude-standard",
                "tests",
            ],
            cwd=str(_REPO_ROOT),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return frozenset()
    if result.returncode != 0:
        return frozenset()
    paths: set[Path] = set()
    for raw_path in result.stdout.split(b"\0"):
        if len(raw_path) == 0:
            continue
        try:
            decoded_path = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            continue
        candidate = (_REPO_ROOT / decoded_path).resolve()
        if candidate.suffix == ".py":
            paths.add(candidate)
    return frozenset(paths)


_IGNORED_LOCAL_TESTS = _ignored_test_paths()


def _path_is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def pytest_ignore_collect(collection_path, config):
    del config
    if os.environ.get("YGGDRASIM_RUN_LOCAL_EXTENSION_TESTS", "").strip() == "1":
        return None
    path = Path(str(collection_path))
    if _path_is_under(path, _LOCAL_EXTENSION_TESTS):
        return True
    try:
        resolved_path = path.resolve()
    except Exception:
        resolved_path = path
    if resolved_path in _IGNORED_LOCAL_TESTS:
        return True
    return None


def _pysim_available() -> tuple[bool, str]:
    """Report whether ``pySim.esim.saip`` is importable in this env.

    ``pySim`` is an **upstream** dependency. We accept any of the three
    legitimate provisioning paths without favouring one:

    1. Installed with the project (``pip install -e .``): pySim is a
       base dependency pinned to the hampushellsberg-dev/pysim fork,
       which is the recommended path for operators and CI.
    2. Installed by hand
       (``pip install 'pySim @ git+https://github.com/hampushellsberg-dev/pysim.git'``).
    3. A developer checkout at ``<repo>/pysim`` (or ``<repo>/pySim``),
       opted into by cloning that fork. This path is still supported
       so maintainers working on pySim itself don't have to reinstall
       after every change.

    We **do not** require the on-disk clone. If option 1 or 2 resolved
    ``pySim.esim.saip`` we succeed; only when **all three** fail do we
    surface the import error and downgrade pySim-dependent tests to
    ``skipped``. The message points the operator at the project
    install because that is the path that turns this from "soft
    dependency" into "just works on a fresh checkout".
    """
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
                "Preferred install: `pip install -e .` (pySim is a base dependency). "
                "Manual install: `pip install "
                "'pySim @ git+https://github.com/hampushellsberg-dev/pysim.git'`. "
                "Developer-checkout fallback: clone that fork "
                f"into {_REPO_ROOT / 'pysim'}. "
                f"Underlying import error: {pysim_error}."
            )
        )
        for item in items:
            basename = Path(str(item.fspath)).name
            if basename in _PYSIM_DEPENDENT_TEST_BASENAMES:
                item.add_marker(skip_no_pysim)
