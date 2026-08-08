# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Generate the standalone ``yggdrasim-mcp`` distribution from this tree.

The MCP server is useful without the rest of YggdraSIM: most of its tools
decode bytes and resolve identifiers, which needs no card stack. Shipping
that as its own wheel means an agent host installs ``mcp`` and little else
instead of pyscard, pySim, and two pinned Git dependencies.

Two constraints shape the output.

The standalone must not collide with ``yggdrasim`` on install, so it
publishes a single ``yggdrasim_mcp`` package rather than re-providing
``Tools`` / ``SCP03`` / ``yggdrasim_common``. Both wheels can be installed
side by side.

The card transport is vendored rather than degraded, so the standalone can
drive a card. That is only affordable because the chain -- card_backend,
runtime_paths, secure_files, apdu_recorder -- is standard-library only
apart from its own members. The simulator is not vendored: SIMCARD is a
whole subsystem, and a standalone install is there to reach real hardware.

Nothing here is committed. The tree is generated on demand from the repo
sources, so the standalone cannot drift from the code it is cut out of.
Tools whose dependencies are absent keep the server's normal behaviour of
reporting that they are unavailable rather than failing to import.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DIST_NAME = "yggdrasim-mcp"
PACKAGE = "yggdrasim_mcp"

# Repo source -> path inside the generated package.
VENDORED = {
    "Tools/Asn1TlvDecode/main.py": "_vendor/asn1tlv.py",
    "SCP03/logic/sgp32_decode.py": "_vendor/sgp32_decode.py",
    "SCP03/logic/euicc_info2.py": "_vendor/euicc_info2.py",
    "yggdrasim_common/session_diff.py": "_vendor/session_diff.py",
    # The risk classifier the card gates read. Standard library only.
    "yggdrasim_common/apdu_risk.py": "_vendor/apdu_risk.py",
    # The card transport chain. Each of these is standard-library only
    # apart from the others, which is what makes driving a card possible
    # without vendoring the rest of the runtime.
    "yggdrasim_common/secure_files.py": "_vendor/secure_files.py",
    "yggdrasim_common/runtime_paths.py": "_vendor/runtime_paths.py",
    "yggdrasim_common/apdu_recorder.py": "_vendor/apdu_recorder.py",
    "yggdrasim_common/card_backend.py": "_vendor/card_backend.py",
    "yggdrasim_common/card_bridge_auth.py": "_vendor/card_bridge_auth.py",
    "yggdrasim_common/remote_lab/security.py": "_vendor/remote_lab_security.py",
}
DATA_FILES = {"SCP03/seeds/aid.txt": "data/aid.txt"}

# Imports the generated server resolves locally. Anything absent from this
# map stays pointing at the full install and degrades with a clear message.
SERVER_REWRITES = (
    (
        "from yggdrasim_common.apdu_risk import classify_apdu  # noqa: E402",
        f"from {PACKAGE}._vendor.apdu_risk import classify_apdu",
    ),
    (
        "from Tools.Asn1TlvDecode.main import DecodeError, decode_bytes",
        f"from {PACKAGE}._vendor.asn1tlv import DecodeError, decode_bytes",
    ),
    (
        "from SCP03.logic import sgp32_decode as decoders",
        f"from {PACKAGE}._vendor import sgp32_decode as decoders",
    ),
    (
        "from yggdrasim_common.session_diff import SessionDiffError, diff_recordings",
        f"from {PACKAGE}._vendor.session_diff import SessionDiffError, diff_recordings",
    ),
    (
        "    from yggdrasim_common import card_backend\n",
        f"    from {PACKAGE}._vendor import card_backend\n",
    ),
    (
        "            from yggdrasim_common.remote_lab.security import read_token_file",
        f"            from {PACKAGE}._vendor.remote_lab_security import read_token_file",
    ),
    (
        "        from yggdrasim_common.card_backend import _request_card_relay_json",
        f"        from {PACKAGE}._vendor.card_backend import _request_card_relay_json",
    ),
    # ``REPO_ROOT`` anchors two things in the full install: the packaged AID
    # registry, and the root the file tools resolve against. Split
    # them, because a standalone install has package data but no repo.
    (
        "REPO_ROOT = Path(__file__).resolve().parent.parent.parent",
        "REPO_ROOT = Path.cwd()\n_PACKAGE_DATA = Path(__file__).resolve().parent / \"data\"",
    ),
    (
        'aid_path = REPO_ROOT / "SCP03" / "seeds" / "aid.txt"',
        'aid_path = _PACKAGE_DATA / "aid.txt"',
    ),
)

VENDOR_REWRITES = (
    ("from SCP03.logic.euicc_info2 import", "from .euicc_info2 import"),
)

# Rewrites applied to a single vendored module, keyed by its repo path.
# ``card_backend`` and ``runtime_paths`` already import their siblings
# relatively or by absolute package name; inside ``_vendor`` they are all
# siblings, so the absolute forms are the only ones that need changing.
PER_MODULE_REWRITES = {
    "yggdrasim_common/runtime_paths.py": (
        ("from yggdrasim_common.secure_files import", "from .secure_files import"),
    ),
    "yggdrasim_common/remote_lab/security.py": (
        ("from yggdrasim_common.card_bridge_auth import", "from .card_bridge_auth import"),
        ("from yggdrasim_common.secure_files import", "from .secure_files import"),
    ),
    "yggdrasim_common/card_backend.py": (
        # The simulator is a whole subsystem and is not vendored, so say
        # that plainly rather than surfacing a bare ImportError.
        (
            "        from SIMCARD.connection import SimulatedCardConnection\n",
            "        try:\n"
            "            from SIMCARD.connection import SimulatedCardConnection\n"
            "        except ImportError as sim_error:\n"
            "            raise RuntimeError(\n"
            "                \"The simulated card backend needs the full YggdraSIM \"\n"
            "                \"install. Select the reader backend, or set \"\n"
            "                \"YGGDRASIM_CARD_BACKEND=reader.\"\n"
            "            ) from sim_error\n",
        ),
    ),
}

PYPROJECT = '''# Generated by scripts/release/build_mcp_standalone.py. Do not edit.
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "{dist}"
version = "{version}"
description = "Model Context Protocol server for SIM, eUICC, and APDU work"
readme = "README.md"
requires-python = ">=3.10"
license = {{ text = "GPL-3.0-or-later" }}
authors = [{{ name = "Hampus Hellsberg" }}]
dependencies = [
    "mcp>=1.2,<2",
    "pyyaml",
    "asn1crypto",
]

[project.optional-dependencies]
# Tools that drive a physical card. Kept optional because pyscard needs a
# compiler and the PCSC headers, which an agent host often lacks.
card = ["pyscard"]

[project.scripts]
{dist} = "{package}.server:run_cli"

[tool.setuptools]
include-package-data = true

[tool.setuptools.packages.find]
where = ["."]
include = ["{package}", "{package}.*"]

[tool.setuptools.package-data]
"{package}" = ["data/*.txt"]
'''

README = """# yggdrasim-mcp

Standalone Model Context Protocol server for SIM, eUICC, and APDU work.

Generated from the YggdraSIM source tree; see that project for the full
toolkit. Installing this package alone gives the decode, lookup, and
diff tools without the card stack.

```bash
pip install yggdrasim-mcp          # decode, lookup, lint-free tools
pip install 'yggdrasim-mcp[card]'  # adds the PC/SC tools
```

Register it with an MCP client:

```bash
claude mcp add yggdrasim -- yggdrasim-mcp
```

Fifteen of the twenty-six tools work from this install alone, nineteen
with `[card]` -- including driving a card, locally or through a relay.
Seven need the full YggdraSIM install and report that they are
unavailable, naming what is missing, rather than failing: `saip_lint`,
`saip_diff`, `bpp_segment`, `metadata_lint`, `eim_package_lint`,
`runtime_status`, and `shell_run`.

The server is read-only by default. `YGGDRASIM_MCP_ACCESS=write` lets it
change state, `YGGDRASIM_MCP_ALLOW_CARD` lets it reach a physical card, and
`YGGDRASIM_MCP_ALLOW_SCRIPT_FILES` lets it run an unverified command file.
The three are independent; none implies another.
"""


def _project_version() -> str:
    import tomllib

    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _apply(text: str, rewrites: tuple[tuple[str, str], ...], where: str) -> str:
    for old, new in rewrites:
        if old not in text:
            raise SystemExit(f"{where}: expected source text not found: {old[:60]!r}")
        text = text.replace(old, new)
    return text


def generate(target: Path) -> Path:
    """Write the standalone source tree into ``target`` and return its root."""

    package_dir = target / PACKAGE
    (package_dir / "_vendor").mkdir(parents=True, exist_ok=True)
    (package_dir / "data").mkdir(parents=True, exist_ok=True)

    (package_dir / "__init__.py").write_text(
        '"""Standalone MCP server generated from the YggdraSIM tree."""\n',
        encoding="utf-8",
    )
    (package_dir / "_vendor" / "__init__.py").write_text(
        '"""Modules cut from YggdraSIM. Generated; do not edit."""\n',
        encoding="utf-8",
    )

    server = (REPO_ROOT / "Tools/YggdraMCP/server.py").read_text(encoding="utf-8")
    (package_dir / "server.py").write_text(
        _apply(server, SERVER_REWRITES, "server.py"), encoding="utf-8"
    )

    for source, relative in VENDORED.items():
        text = (REPO_ROOT / source).read_text(encoding="utf-8")
        if source.startswith("SCP03/logic/sgp32_decode"):
            text = _apply(text, VENDOR_REWRITES, source)
        rewrites = PER_MODULE_REWRITES.get(source)
        if rewrites is not None:
            text = _apply(text, rewrites, source)
        (package_dir / relative).write_text(text, encoding="utf-8")

    for source, relative in DATA_FILES.items():
        shutil.copyfile(REPO_ROOT / source, package_dir / relative)

    (target / "pyproject.toml").write_text(
        PYPROJECT.format(dist=DIST_NAME, package=PACKAGE, version=_project_version()),
        encoding="utf-8",
    )
    (target / "README.md").write_text(README, encoding="utf-8")
    shutil.copyfile(REPO_ROOT / "LICENSE", target / "LICENSE")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate and optionally build the standalone MCP distribution.",
    )
    parser.add_argument(
        "--source-out",
        type=Path,
        help="write the generated source tree here instead of a temporary directory",
    )
    parser.add_argument(
        "--wheel-out",
        type=Path,
        help="build a wheel into this directory",
    )
    options = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as scratch:
        target = options.source_out or Path(scratch) / "build"
        if target.exists() and options.source_out:
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
        generate(target)
        print(f"generated {DIST_NAME} source tree: {target}")

        if options.wheel_out is not None:
            options.wheel_out.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                [sys.executable, "-m", "pip", "wheel", "--no-deps",
                 "-w", str(options.wheel_out.resolve()), "."],
                cwd=target,
                check=True,
            )
            built = sorted(options.wheel_out.glob("yggdrasim_mcp-*.whl"))
            print(f"built: {built[-1] if built else '(none)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
