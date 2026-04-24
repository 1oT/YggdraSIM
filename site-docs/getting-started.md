# Getting Started

## Prerequisites

- Python 3.10 or newer
- a PC/SC-compatible smart-card reader for card-facing flows
- optional `gpg` when encrypted inventory payloads are enabled
- optional Wireshark, `osmo-remsim-client-st2`, and SIMtrace2 for HIL work
- optional on-disk `pysim/` checkout when you need SAIP ASN.1 compile or
  the SCP11 local / eIM-local flows (see the *Optional pySim checkout*
  section below)

## Install the runtime

Install the Python dependencies:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
```

The editable install makes the package entry points work from any directory that
uses the same environment.

If your host exposes `python3` instead of `python`, substitute `python3` in the
commands on this page.

## Install the documentation tooling

```bash
python -m pip install -r requirements-docs.txt
```

Build or serve the site:

```bash
mkdocs serve
mkdocs build
```

The MkDocs configuration lives in `mkdocs.yml`, and the authored site pages live
in `site-docs/`.

## Launch the main menu

```bash
python main/main.py
python main/main.py --debug
python main/main.py --card-backend sim --sim-eim-identity /path/to/card_side_eim_identity.json
```

Use `--debug` or `--verbose` on the wrapper when debug output should become the
global default for launched modules.

## Direct module entry points

After `python -m pip install -e .`, these module forms can be run from any
directory in the same environment:

```bash
python -m SCP03
python -m SCP80
python -m SCP11
python -m SCP11.live
python -m SCP11.test
python -m SCP11.relay
python -m SCP11.local_access
python -m SCP11.eim_local
python -m Tools.HilBridge.main
python -m Tools.HilBridge.supervisor
python -m Tools.ProfilePackage
python -m Tools.SuciTool
```

Installed command equivalents:

```bash
yggdrasim-scp03
yggdrasim-scp80
yggdrasim-scp11
yggdrasim-scp11-live
yggdrasim-scp11-test
yggdrasim-scp11-relay
yggdrasim-scp11-local-access
yggdrasim-scp11-eim-local
yggdrasim-hil-bridge
yggdrasim-hil-supervisor
yggdrasim-profile-package
yggdrasim-suci-tool
```

## Simulator note

- `--sim-eim-identity` selects the simulated card's default BF55 eIM identity file
- `Workspace/LocalEIM/eim_identity.json` remains the Local eIM shell identity
- `Workspace/SIMCARD/eim_identity.json` remains the simulator-side default when no stronger card-side override is applied

## pySim provisioning

YggdraSIM treats [`pySim`](https://github.com/osmocom/pysim) as an
**upstream** dependency rather than a vendored copy. The canonical
distribution channel is the `[saip]` extra, which installs upstream
pySim directly from its GitHub mirror:

```bash
python -m pip install -e '.[saip]'
```

That one command unlocks the SAIP ASN.1 compile path used by
`Tools.ProfilePackage`, the SAIP transcode TUI, the profile-scaffold
wizards, and the SCP11 local / eIM-local flows. A bare
`pip install -e .` without the extra still works for the flows that
do not touch SAIP; `yggdrasim --doctor` reports *pySim: WARN*
(non-fatal) and SAIP-dependent tests auto-skip via
`tests/conftest.py`.

### Developer checkout (advanced)

If you want to iterate against an unreleased upstream branch, drop a
checkout at `<repo>/pysim`:

```bash
git clone https://github.com/osmocom/pysim.git pysim
```

The `pysim/` directory is listed in `.gitignore` and is never
redistributed with this project. When present, it takes priority over
the installed wheel so your edits show up immediately. The same
principle applies to `pyscard` and every other third-party Python
dependency: installed from the normal packaging channels, not
vendored.

## Read next

- Use [Operator Surfaces](operator-surfaces.md) to choose the right module.
- Use the SCP11 subsystem pages for relay, local-access, and eIM-local execution paths:
  [SCP11 Live Relay](subsystems/scp11-live.md),
  [SCP11 Test Relay](subsystems/scp11-test.md),
  [SCP11 Local Access](subsystems/scp11-local-access.md),
  [SCP11 eIM Local](subsystems/scp11-eim-local.md).
- Use [Build and Packaging](build-and-packaging.md) for Docker and bundled distribution guidance.
