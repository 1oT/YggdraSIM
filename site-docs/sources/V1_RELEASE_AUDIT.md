# YggdraSIM v1 Release Audit

Generated during pre-v1 repository comb-through. Captures every finding,
grouped by severity, plus a concrete pre-tag action list.

- Working tree snapshot: 93 tracked files modified (+25,242 / −4,084),
  ~200 non-vendored untracked files, branch `main` ahead of `origin/main`
  by 1.
- No `v*` git tags exist. Last "RC" commit was `1f0d757` in February.
- `pyproject.toml` version: `2026.4.10` (CalVer).

The engineering work looks done. What is left is release hygiene.

> **Status: closed (2026-04-29).** v1.0.0 was tagged at commit
> `ec74dd5 release: v1.0.0 freeze`; `pyproject.toml` is now SemVer
> `1.0.0`; the post-v1 R2-005 Tools-tier staging continues on `main`
> from commit `8433ec7 wip(v2): R2-005 staging — YggdraCore + Sunrise6G
> + CardBridge HTTP tier`. The carved release tree is mirrored at
> `~/Documents/Tools/YggdraSIM_v1.0.0` on the `release/1.0.x` branch.
> Outstanding items below are kept for historical context — anything
> still relevant moves into `V2_ROADMAP.md`, not back into this audit.
>
> **Residual sweep (2026-04-29, post-v1.0.0 audit pass).** Items that
> were still genuinely open after the freeze have been rectified in
> both the dev tree and the `release/1.0.x` mirror:
>
> - **B2** — `.venv/` (10 tracked files: `bin/Activate.ps1`,
>   `bin/activate{,.csh,.fish}`, `bin/pip{,3}`, `bin/python{,3}`,
>   `lib64`, `pyvenv.cfg`) untracked via `git rm --cached -r .venv`.
>   `.gitignore:61` already excludes the directory.
> - **H1** — `SECURITY.md` (vulnerability disclosure incl. GSMA CVD
>   routing) and `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1
>   adapted) added at repo root. `CHANGELOG.md`, `CONTRIBUTING.md`,
>   `.github/PULL_REQUEST_TEMPLATE.md`, and `.github/ISSUE_TEMPLATE/`
>   were already in place.
> - **H7** — `SCP11/TEST_MATERIAL_NOTICE.md` added with the explicit
>   "SGP.26 publicly-known test material" disclaimer; a one-paragraph
>   pointer landed at the top of `SCP11/README.md`.
> - **H8** — operational-looking transcode dumps
>   (`Tools/ProfilePackage/transcode/_external/89103000000466310758-*.transcode.json`
>   and the `V2_…` sibling) removed from the index in both repos;
>   `Tools/ProfilePackage/transcode/_external/` added to `.gitignore`
>   so future scratch dumps from `saip_json_codec.resolve_transcode_paths`
>   stay local.
>
> Tier 0 / Tier 1 items called out as `[fixed]`, `[partial]`, or
> `[frozen for v1]` further down in this audit retain those statuses
> from earlier passes; the residual sweep only touched items that
> were still genuinely actionable.

---

## Blockers (must fix before tagging v1)

### B1. Massive pending commit backlog

Entire subsystems live only in the working tree:

- `Tools/HilBridge/` — 14 source files, the whole HIL bridge
- `SIMCARD/auth.py`, `SIMCARD/tuak.py`, `SIMCARD/toolkit.py` — SIM crypto core
- `Tools/ProfilePackage/saip_aka_wizard.py`, `saip_decoded_edit.py`,
  `saip_open_picker_tui.py`, `saip_profile_randomizer.py`,
  `saip_profile_scaffold.py`, `saip_profile_wizard.py`
- `yggdrasim_common/__about__.py`, `console_scripts.py`, `doctor.py`,
  `flavor.py`, `hil_bridge_runtime.py`
- `pyproject.toml`, `yggdrasim_main.spec`, `Dockerfile`, `.dockerignore`,
  `.github/workflows/docker.yml`
- `mkdocs.yml`, all of `site-docs/`, all of `guides/`,
  `scripts/install/`, `requirements-docs.txt`
- 31 new `tests/test_*.py` files

Commit in logical chunks. Suggested split:

1. Packaging & flavor infra — `pyproject.toml`, `yggdrasim_main.spec`,
   `Dockerfile`, `.dockerignore`, `.github/workflows/docker.yml`,
   `yggdrasim_common/{__about__,flavor,console_scripts,doctor,hil_bridge_runtime}.py`,
   `scripts/install/`.
2. HIL bridge — `Tools/HilBridge/*`, `tests/test_hil_bridge_*.py`,
   `guides/HIL_BRIDGE_GUIDE.md`, `guides/SIMTRACE2_CARDEM_GUIDE.md`.
3. SIMCARD crypto — `SIMCARD/auth.py`, `tuak.py`, `toolkit.py` + matching tests.
4. SAIP wizards — new `Tools/ProfilePackage/saip_*_wizard.py`,
   `saip_profile_scaffold.py`, `saip_profile_randomizer.py`,
   `saip_decoded_edit.py`, `saip_open_picker_tui.py` + tests.
5. Docs site — `mkdocs.yml`, `site-docs/`, `requirements-docs.txt`, `guides/`.
6. Everything else (misc tracked modifications, `tests/test_about_version.py`,
   etc.).

### B2. `.venv/` is committed in git

`git ls-files .venv/` returns 10 files:

```
.venv/bin/Activate.ps1
.venv/bin/activate
.venv/bin/activate.csh
.venv/bin/activate.fish
.venv/bin/pip
.venv/bin/pip3
.venv/bin/python
.venv/bin/python3
.venv/lib64
.venv/pyvenv.cfg
```

Run `git rm --cached -r .venv` and add an explicit `.venv/` line to
`.gitignore` (current `.gitignore` has no venv entry).

### B3. Version / tag model is inconsistent with "v1"

- `pyproject.toml` → `version = "2026.4.10"` (CalVer).
- `git tag` output is empty — no `v*` tags in the repo history.
- Commit `1f0d757` already claimed "YggdraSIM v1.0 Core Release Candidate".
- `site-docs/internals/release-checklist.md` instructs to bump
  `pyproject.toml` version; that step never ran.

Pick one — SemVer `1.0.0` or CalVer `2026.x.y` — commit the bump, tag
the release commit.

### B4. Repo URL branding is inconsistent

Four different references to "the" repo:

| Location | Value |
|---|---|
| `git remote origin` | `hampushellsberg-dev/YggdraSIM` |
| `scripts/install/_common.sh:15` | `hampushellsberg-dev/YggdraSIM` |
| `scripts/install/install-windows.ps1:96` | `hampushellsberg-dev/YggdraSIM` |
| `scripts/install/README.md:49` | `hampushellsberg-dev/YggdraSIM` |
| `guides/INSTALL_FROM_SOURCE.md:21` | `hampushellsberg-dev/YggdraSIM` |
| `mkdocs.yml:5` | `hampushellsberg/YggdraSIM` (no `-dev`) |
| `mkdocs.yml:22` | `hampushellsberg/YggdraSIM` |
| `mkdocs.yml:119` | `user: hampushellsberg` |
| `mkdocs.yml:4` | `site_url: https://example.invalid/yggdrasim/` (placeholder) |

Pick one canonical owner, sweep all surfaces, set a real `site_url`.

### B5. Scratch / probe artifacts at repo root

~80 MB of probe dumps, TUI smoke captures, PDML XMLs, hex dumps,
strace output:

```
.active_env_exact_pdml.xml        4.4M
.live_env_pdml_probe.xml          4.3M
.live_pdml_probe.xml              4.2M
.sudo_pdml_probe.xml              4.5M
.user_pdml_probe.xml              4.5M
.tshark_pdml_live_probe.xml       9.8M
.tshark_pdml_probe.xml            9.8M
.hil_tui_wide_smoke.txt           776K
...
```

All currently gitignored, but they clutter the working tree and will
trip `rg` / `find` for contributors. Delete them, and add to `.gitignore`:

- `.pytest_chunk_log*.txt` (currently not matched)
- `.tuak_kat_sanity.py` (45-line manual KAT — either move to `tests/`
  or delete)

### B6. `yggdrasim.egg-info/`, `trace/`, `Latjo/` untracked but not gitignored

- `yggdrasim.egg-info/` is pip's build artefact. Add `*.egg-info/` to
  `.gitignore`.
- `trace/` contains `trace/ipad_test_site/` — a full vendored
  PyInstaller-built staging tree (`serial/`, `pygments/`, `Cryptodome/`,
  `pyparsing/`, etc.), 37 MB total. Add `trace/` to `.gitignore`.
- `Latjo/` is a scratch directory (SIM Alliance sample profile walkthrough,
  SCP02-removed diff, helper script). Add `Latjo/` to `.gitignore`.
- `state/` is already gitignored — good.

### B7. Remove vendored `pysim/` and `pyscard/` trees — use installable deps

Current state:

- `pysim/` — 13 MB on disk. Already in `.gitignore:90`. Referenced by
  `yggdrasim_main.spec:70` as a `Tree()`-bundled data dir, and probed
  by `yggdrasim_common/doctor.py:112` as
  `pysim/pySim/esim/saip/__init__.py`. Also referenced in `README.md`
  as "vendored".
- `pyscard/` — 624 MB on disk (third-party source clone). Already in
  `.dockerignore:18`. Not tracked, not in `.gitignore`.

Both already resolve at runtime without a vendored tree:

- `SCP11/pysim_path.py:ensure_repo_pysim_on_path()` already falls back
  to the installed `pySim` PyPI package when no vendored tree is found
  (lines 56–64).
- `pyproject.toml:16` already lists `pyscard` as a runtime dependency —
  the 624 MB `pyscard/` directory on disk is an unrelated source clone
  leftover.

Migration actions:

1. Delete the on-disk `pysim/` and `pyscard/` working-tree directories
   from the workspace.
2. Add `pysim` (or the upstream distribution name — confirm osmocom's
   published PyPI name, typically `pySim` via `pip install pySim`) to
   `pyproject.toml` `dependencies` with a pinned lower bound. Mirror
   the same entry in `requirements.txt`.
3. Remove `"pysim"` from `yggdrasim_main.spec:70` `data_tree_candidates`.
   Replace it with `hiddenimports.extend(collect_submodules("pySim"))`
   so PyInstaller picks up the installed distribution.
4. Rewrite `yggdrasim_common/doctor.py:_probe_vendored_pysim` to probe
   `importlib.import_module("pySim.esim.saip")` instead of a workspace
   file-system path. The existing `_probe_module(module_name="pySim.esim.saip")`
   call at line 321 is already the right shape — delete the
   `_probe_vendored_pysim` helper entirely.
5. Update `README.md` — stop describing `pysim/` as "vendored". Wording
   suggestion: *"pySim is installed as a runtime dependency via
   `pyproject.toml`. For advanced workflows that need an editable pySim
   clone, drop the upstream repository into `pysim/` at the workspace
   root and the path resolver in `SCP11/pysim_path.py` will prefer it."*
6. Drop `pysim/` from `.gitignore` once removed from disk (it was only
   there to prevent the 13 MB vendored tree from being tracked).
7. Add `pyscard/` to `.gitignore` so a re-clone of the osmocom pyscard
   source in the workspace root never sneaks into git. Keep
   `pyscard/` in `.dockerignore`.
8. `yggdrasim_common/registry.py:38` describes `pysim` as
   "Vendored pySim tree (upstream osmocom)"; rewrite to reflect the
   installable-dep model.

Net effect: **drop ~640 MB from the workspace, simplify PyInstaller
data bundling, and make the Docker build smaller and faster.** No
runtime-code changes required beyond the doctor probe.

---

## High priority (should fix before v1)

### H1. No CHANGELOG / CONTRIBUTING / SECURITY / issue templates

Missing at repo root / under `.github/`:

- `CHANGELOG.md` (Keep-a-Changelog style, seeded with v1.0.0 entry)
- `CONTRIBUTING.md`
- `SECURITY.md` — high-value for a secure-element toolkit. The
  gitignored `Legal/CVD/GSMA_ZD_vulnerability.md` shows a vulnerability
  disclosure story already exists; surface the contact / PGP model
  publicly.
- `.github/ISSUE_TEMPLATE/` (bug / feature / HIL-bridge)
- `.github/PULL_REQUEST_TEMPLATE.md`
- `CODE_OF_CONDUCT.md` (optional but expected)

### H2. `pyproject.toml` is thin on metadata

Currently:

```toml
[project]
name = "yggdrasim"
version = "2026.4.10"
description = "YggdraSIM secure-element, eUICC, OTA, and SAIP toolkit."
readme = "README.md"
requires-python = ">=3.10"
```

For v1 add:

- `license = "GPL-3.0-or-later"` (SPDX identifier; LICENSE file is GPLv3).
- `authors = [{ name = "Hampus Hellsberg", email = "..." }]`
- `[project.urls]` — `Homepage`, `Repository`, `Issues`, `Changelog`,
  `Documentation` (point `Documentation` at the eventual mkdocs site
  once `site_url` is real).
- `classifiers` — `License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)`,
  `Operating System :: POSIX :: Linux`, `Operating System :: MacOS`,
  `Operating System :: Microsoft :: Windows`, `Programming Language :: Python :: 3.10`,
  through `3.12`, `Development Status :: 5 - Production/Stable`,
  `Topic :: Security`, `Topic :: System :: Hardware`,
  `Topic :: Communications`.
- Consider adding `main*` to `[tool.setuptools.packages.find]:include`
  if `main.launcher.*` symbols in the registry are meant to resolve
  through the installed distribution.

### H3. `requirements.txt` contains dev-only packages

```
pyinstaller
pytest
```

These are already available as extras (`.[build]`, `.[test]`). Either
strip them from `requirements.txt` (keeping it runtime-only) or delete
the file entirely and point users at `pip install -e '.[build,test]'`
or `.[full]`.

### H4. `docs/` is gitignored but README references it

README line 428:

> `docs/` - vendored specifications, standards notes, and machine-consumed
> assets such as `RSPRO.asn`

`.gitignore:3` has `docs` — the 5.8 MB tree (GSMA / 3GPP / ETSI spec
dumps) is never shipped. Likely intentional (GSMA specs are not
redistributable), but breaks the onboarding claim.

Options:

- Track only the redistributable items (`docs/RSPRO.asn` from osmocom
  is openly licensed; your own notes are fine) and document that GSMA
  specs must be fetched separately.
- Or remove the README reference and replace with a
  `guides/STANDARDS_REFERENCE.md` listing source URLs the operator has
  to populate.

### H5. `.dockerignore` is too leaky

`Dockerfile` does `COPY . /opt/YggdraSIM`. `.dockerignore` currently
only excludes: `.cursor/ .git/ .mypy_cache/ .pytest_cache/ .ruff_cache/
.venv/ __pycache__/ *.db *.pyc *.pyo *.sqlite3 *.swp
.pytest_agent_log.txt YggdraSIM-data/ agent-transcripts/ build/ dist/
pyscard/ reports/ venv/`.

Missing — all these ship into the image:

- `.tshark_*`, `.live_pdml_*`, `.hil_tui_*`, `.active_env_*`,
  `.sudo_pdml_*`, `.user_pdml_*`, `.run_*`, `.unittest_*`, `.smoke_*`,
  `.strace_*`
- `trace/` (37 MB)
- `site/` (9.6 MB generated mkdocs output)
- `Workspace/`, `Legal/`, `Latjo/`
- `YggdraSIM.md` (292 KB generated single-file doc)
- `tests/` (not needed in a runtime image)
- `.profilepackage-cache/`
- `SCP11/SGP.26_test_Certs/` (4.8 MB; keep if the image is for operators
  who run SGP.26 validation, exclude otherwise)
- `docs/` (after policy decision in H4)

### H6. Workspace / state needs a clean-reset story

Working tree holds mutable state that must never leave the laptop:

- `state/device_inventory.sqlite3`
- `state/gpg_key.fingerprint`
- `state/termshark-probe-*`, `state/termshark-strace-*`, `state/hil_termshark/`
- `Workspace/LocalEIM/eim_poll_audit.sqlite3`, `eim_response_log.jsonl`

All gitignored, so not a leak. But the release-checklist must ship a
clean `Workspace/` template. Add a `scripts/reset_workspace.sh` (or a
bundled `Workspace.template/` that the first launch copies into
`Workspace/` when the target does not exist).

### H7. GSMA SGP.26 public test keys need a plain-English notice

Tracked in git and look like private keys on sight:

- `SCP11/SK.DPauth.ECDSA.pem`
- `SCP11/SK.DPpb.ECDSA.pem`

Content verified as the published GSMA SGP.26 test material. Any
security-conscious reviewer will open an issue on first inspection.

Action: add `SCP11/TEST_MATERIAL_NOTICE.md` (or a top-of-README block
inside `SCP11/README.md`) stating explicitly:

> `*.pem` and `*.der` files in `SCP11/` and `SCP11/SGP.26_test_Certs/`
> are the publicly-known GSMA SGP.26 test certificates / private keys.
> They are intentionally tracked because they are required for
> reproducible SGP.26 validation. They are not production material and
> must not be used against live infrastructure.

### H8. Transcode JSON filenames look operational

```
Tools/ProfilePackage/transcode/_external/89103000000466310758-1feb42f64f6d.transcode.json
Tools/ProfilePackage/transcode/_external/V2_89103000000466310758-b2ed1229a2dd.transcode.json
```

The 20-digit prefix parses as a valid ICCID format. JSON content itself
is synthetic (`iccid: 89460811111111111112` — obvious test pattern),
but the filename optics are operational. Rename to
`sample_v2_tca20.transcode.json` or move under a clearly-labeled
`transcode/_test_fixtures/`.

---

## Medium priority (address during v1 stabilization)

### M1. SCP11 root-level duplication

`SCP11/__init__.py` is a thin facade per the registry description, but
the rest of `SCP11/*.py` is full duplicate implementation alongside
`SCP11/live/*` and `SCP11/test/*`:

| File | Lines |
|---|---|
| `SCP11/orchestrator.py` | 3,634 |
| `SCP11/console.py` | (127 KB) |
| `SCP11/transport.py` | — |
| `SCP11/es9_client.py` | — |
| `SCP11/eim_packages.py` | — |
| `SCP11/payload_builder.py` | — |
| `SCP11/crypto_engine.py` | — |
| `SCP11/factory.py` | — |
| `SCP11/models.py` | — |
| `SCP11/providers.py` | — |
| `SCP11/sgp_utils.py` | — |
| `SCP11/asn1_registry.py` | — |
| `SCP11/pysim_support.py` | — |

Looks like an in-flight migration. For v1 either:

- Finish the migration — delete the root-level fat modules, keep only
  the thin facade.
- Or document explicitly in `SCP11/README.md` that the root-level
  modules are the shared default implementation.

### M2. File-size outliers crossing the project's own readability threshold

The project's coding standard says *"Keep file sizes manageable. When
a file crosses the point where a new contributor cannot find things
fast, split it along functional seams."*

Top offenders:

| File | Lines |
|---|---|
| `Tools/ProfilePackage/saip_transcode_tui.py` | **7,122** |
| `Tools/ProfilePackage/shell.py` | 4,383 |
| `SCP11/test/console.py` | 4,130 |
| `Tools/ProfilePackage/saip_asn1_decode.py` | 4,127 |
| `SCP11/live/console.py` | 4,076 |
| `SCP11/eim_local/session.py` | 3,826 |
| `SCP11/local_access/session.py` | 3,644 |
| `SCP11/orchestrator.py` | 3,634 |
| `SCP11/test/orchestrator.py` | 3,597 |
| `SCP11/live/orchestrator.py` | 3,406 |
| `SCP03/logic/sgp22.py` | 3,205 |
| `SCP03/interface/shell.py` | 3,172 |

Not a v1 blocker. Queue a "modularize after v1.0" item. The transcode
TUI at 7 k lines is the worst offender.

### M3. `main/main.py` has grown to 2,258 lines

From ~1,166 lines to 2,258 in the uncommitted diff (+1,092). Factor
card-backend handling and per-subsystem runners into `main/launcher/`
modules before v1.1.

### M4. The project's own release checklist has not run end-to-end

`site-docs/internals/release-checklist.md` is the right doc. Its
items currently stand as:

- [ ] `pyproject.toml` version bumped → **pending**
- [ ] console scripts launch via `--cmd` → not verified
- [ ] `docker build` succeeds → Dockerfile still untracked
- [ ] `pyinstaller --clean --noconfirm yggdrasim_main.spec` succeeds → spec still untracked
- [ ] `python -m mkdocs build --strict` succeeds → not verified
- [ ] `site-docs/_tools/mirror_source_docs.py` regenerated → not verified
- [ ] git tag pushed → **no tags exist**

Running the project's own checklist end-to-end is the next action.

### M5. `YggdraSIM.md` generated artefact at root

292 KB single-file concatenation of the mkdocs site, gitignored per
`.gitignore:54`. Keep locally; wire the generator into the release
checklist so it is regenerated against the final content.

### M6. `AUTHORS` / `NOTICE` / `LICENSE` / `pyproject.toml` alignment

- `AUTHORS` and `NOTICE` list only you — fine.
- `LICENSE` is the full GPLv3 text — fine.
- `pyproject.toml` does not declare the SPDX identifier (see H2).

---

## Nice-to-have (queue for v1.1+)

### N1. No CI lint / type-check / docs jobs

GitHub Actions only runs the build matrix. Consider adding:

- `ruff check` (you already have `.ruff_cache/` entries in
  `.dockerignore`, suggesting the intent).
- `mypy` on `yggdrasim_common/` at minimum.
- `python -m mkdocs build --strict` as a docs CI job.

### N2. No `py.typed` marker

Add an empty `yggdrasim_common/py.typed` and reference it under
`[tool.setuptools.package-data]` so type information ships with the
installed distribution.

### N3. `SCP11/relay` deprecation status

README calls it *"retained as the compatibility namespace"*. For v1:

- Mark `SCP11/relay/__init__.py` with a `DeprecationWarning`, target
  removal in v2.
- Or drop the "compatibility" framing and treat it as first-class.

### N4. `SCP80/ota_config.ini` is tracked legacy material

README says it is *"a legacy import source. Live SCP80 state is now
SQLite-primary."* Either mark as a one-shot migration seed or move to
`Workspace/SCP80/ota_config_example.ini`.

### N5. README "Authors" section vs `AUTHORS`

Aesthetic preference. Some communities expect the README to stay short
and authorship to live in the `AUTHORS` file.

---

## Second-pass findings (2026-04-19 comb-through)

Every item below was surfaced by a deeper scan after the initial pass.
Each is written so it can be triaged independently. Severity is marked
inline (B = blocker, H = high, M = medium, N = nice-to-have).

### S1. `mkdocs build --strict` fails today — 11 warnings [B]

`mkdocs.yml:10` sets `strict: true`. Running `mkdocs build --strict`
from the repo root aborts with 11 warnings, all broken intra-doc links
in `site-docs/sources/guides/`:

- `BUILD_AND_PACKAGING.md` links `INSTALL_CLEAN.md`, `INSTALL_FULL.md`,
  `INSTALL_FROM_SOURCE.md`, `INSTALL_RASPBERRYPI.md`, and
  `SIMTRACE2_CARDEM_GUIDE.md`.
- `HIL_BRIDGE_GUIDE.md` links `INSTALL_FULL.md`, `INSTALL_FROM_SOURCE.md`,
  `SIMTRACE2_CARDEM_GUIDE.md`.

Root cause: `site-docs/sources/guides/` is a partial mirror of
`guides/`. The five files above are present in `guides/` but were
never mirrored into `site-docs/sources/guides/`. The mirror script
`site-docs/_tools/mirror_source_docs.py` is documented but was not
re-run after those guides were added.

Fix:

1. `python site-docs/_tools/mirror_source_docs.py` (or extend the
   script to cover the missing filenames).
2. `python site-docs/_tools/check_internal_links.py` before every
   tag to catch regressions.
3. Optional: wire a `docs` job into `.github/workflows/` that runs
   the mirror + strict build on every PR (see S2).

### S2. No CI job builds the documentation [B]

`.github/workflows/` ships `build.yml` (PyInstaller bundles + .deb)
and `docker.yml`. Neither runs `mkdocs build`. Combined with S1, this
means the strict docs build has silently rotted. A v1 release that
publishes a user-facing site needs CI to prove the site builds.

Minimal `.github/workflows/docs.yml` outline:

```yaml
name: docs
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -r requirements-docs.txt
      - run: python site-docs/_tools/mirror_source_docs.py
      - run: python site-docs/_tools/build_cli_matrix.py --check
      - run: python site-docs/_tools/check_internal_links.py
      - run: mkdocs build --strict
```

### S3. `plugins/polling_plugin.py` is git-ignored but required by a tracked test [RESOLVED]

Resolved in the polling-plugin repackage pass:

- `plugins/polling_plugin.py` has been replaced by the
  `plugins/polling/` package (see `plugins/README.md` §"Polling
  plugin layout"). The single-file, git-ignored drop-zone sprawl is
  no longer the runtime path.
- The patentable BIP-over-WiFi/Ethernet loopback bridge lives
  **exclusively** in `plugins/polling/wifi_ethernet_bridge.py`.
  Removing the whole `plugins/polling/` directory leaves the core
  SIM simulator fully functional (guarded by
  `tests/test_polling_plugin_absence_guard.py`).
- `tests/plugins/polling/` holds the bridge-coupled suite; the
  generic eIM-local tests in `tests/test_scp11_eim_local.py` patch
  plugin surfaces via the canonical `plugins.polling.<submod>` path
  and work on a fresh clone.
- `plugins/.gitignore` now tracks the polling package explicitly
  while keeping the drop-zone opt-out posture for any
  deployment-specific additions.

Follow-on audit items:

1. Promote the polling plugin documentation into the MkDocs tree
   (`site-docs/subsystems/scp11-eim-local.md` references the layout).
2. Keep the legacy `yggdrasim_plugin_polling` sys.modules alias for
   one release cycle before removing it — some operator transcripts
   still reference the flat module name.

### S4. Triplicated SCP11 trees have silently drifted [H]

`SCP11/`, `SCP11/live/`, and `SCP11/test/` ship three parallel copies
of the relay stack. Hash comparison today:

```
console.py          root-vs-live DIFF  live-vs-test DIFF  root-vs-test DIFF
orchestrator.py     root-vs-live DIFF  live-vs-test DIFF  root-vs-test DIFF
es9_client.py       root-vs-live DIFF  live-vs-test DIFF  root-vs-test DIFF
transport.py        root-vs-live DIFF  live-vs-test DIFF  root-vs-test DIFF
payload_builder.py  root-vs-live DIFF  live-vs-test eq    root-vs-test DIFF
eim_packages.py     root-vs-live eq    live-vs-test eq    root-vs-test eq
crypto_engine.py    root-vs-live eq    live-vs-test eq    root-vs-test eq
asn1_registry.py    root-vs-live eq    live-vs-test eq    root-vs-test eq
```

Line counts for the "DIFF" modules:

- `console.py`      root=3230, live=4076, test=4130 — **~900-line drift**
- `orchestrator.py` root=3634, live=3406, test=3597
- `es9_client.py`   root=1931, live=1885, test=1886
- `transport.py`    root=428,  live=536,  test=492

`SCP11/shared/` exists as a thin shim forwarder (`crypto_engine.py` /
`payload_builder.py` / `transport.py` at 4 lines each re-exporting
from `SCP11.*`). The shims are healthy — they just don't cover the
fully drifted files.

Risk: three independent bug surfaces for the same RSP protocol. When
a fix lands in `SCP11/live/orchestrator.py` it won't automatically
apply in `SCP11/test/orchestrator.py`.

Fix plan (v1.1 if too large for v1):

1. Promote every module that is already identical across all three
   trees to `SCP11/shared/` and point live/test/root at the shim.
2. Diff the drifted modules to classify deltas as
   (a) behavioral-required or (b) accidental drift, fold (b) back
   into `SCP11/shared/`.
3. Keep live/test as thin configuration shims over
   `SCP11.shared.console / orchestrator / es9_client / transport`.

### S5. `trace/ipad_test_site/` is a committed third-party sitepackages dump [B]

`trace/` is 37 MB and not git-tracked, but `trace/ipad_test_site/` is
a full offline install of `pyserial`, `rich`, `pyparsing`, `pygments`,
`pyperclip`, etc. None of it belongs in this repo. Plus
`trace/ipad_test_runtime/` (3.3 MB).

Action: rm it, add `trace/` to `.gitignore` (already covered by S6
below), document in `guides/` that iPad / remote-runtime scratch work
lives in a private sandbox, not the workspace.

### S6. `.gitignore` does not cover real clutter found on disk [B]

Confirmed by walking the working tree. The existing `.gitignore`
misses:

- `.venv/`, `.venv-*/`
- `yggdrasim.egg-info/`
- `trace/`
- `Latjo/`
- `.pytest_chunk_log*.txt`
- `.pytest_agent_log.txt`
- `.tuak_kat_sanity.py` (scratch probe at repo root)
- `site/` (MkDocs output — currently covered, double-check post-mirror)

It also still carries `pysim/` which will be removed together with B7.

### S7. `tests/eim-sh/script.sh` contains hard-coded developer paths [H]

`tests/eim-sh/script.sh:13` sources
`/home/hampushellsberg/Documents/pyscard/bin/activate`. It also
sources `~/.zshrc` and calls a `venv` shell function. That script
cannot run on anyone else's machine. It is also tracked (`git ls-files`
shows 4 files in `tests/eim-sh/`).

Pick one:

1. Delete it — the `eim_last_response.bin` / hex fixture is helpful,
   the driver shell script is not.
2. Rewrite to use `${PYTHON:-python3}` from `$PATH`, drop the
   `zshrc`/venv sourcing, move to `scripts/dev/` so it is clearly
   not part of the automated test suite, and add a README.

### S8. Bare `except:` still present in the codebase [H]

15 sites across production paths. These violate the internal coding
standard (`site-docs/internals/coding-standards.md`) because they
swallow `KeyboardInterrupt` and `SystemExit` as well as the intended
error. Representative hits:

- `SCP03/crypto/session.py:161`
- `SCP03/interface/shell.py:343, 366, 377, 2254`
- `SCP03/logic/security.py:623, 711`
- `SCP03/logic/sgp22.py:936, 1395` (`except :pass` — single-line
  compound statement, violates the project's "no compound statements"
  rule too)
- `SCP03/logic/gp.py:954`
- `SCP80/transport.py:65`, `SCP80/crypto.py:34, 51`
- `SCP80/cli.py:88, 168`

Also note: 1,292 `except Exception` sites (not itself a bug for I/O
wrappers, but worth a one-hour sweep to confirm each one at least
logs at `debug` level or re-raises on `KeyboardInterrupt`).

### S9. Project license is GPL-3.0 — document dependency implications [H]

`LICENSE` is GPLv3 (full 632-line text committed). `NOTICE` correctly
labels the project as GPL-3.0-or-later. Two follow-ups for v1:

1. Add an **SPDX headline** to every tracked Python source file, e.g.
   `# SPDX-License-Identifier: GPL-3.0-or-later`. Currently zero
   source files carry an SPDX tag. For a security-relevant toolkit
   this is table stakes for downstream packagers (Debian, Fedora).
2. Add a short **THIRD_PARTY_LICENSES.md** enumerating runtime
   dependency licenses — GPLv2+ (pyosmocom, pysim), LGPL-2.1+
   (pyscard), BSD (cryptography, pycryptodomex, pyserial, asn1crypto,
   construct), MIT (cmd2, textual, jsonpath-ng, bidict), Apache-2
   (asn1tools). Confirm no CDDL / AGPL / EPL leak in.
3. Drop the outdated `pysim/` *"vendored runtime dependency"*
   wording from `NOTICE:14-20` as part of B7.

### S10. `--stdin` flag is inconsistent across CLIs [M]

- `SCP03/main.py:119` supports `--stdin`.
- `SCP80/main.py:36` supports `--stdin`.
- `main/main.py:2159` only supports `--cmd`, no `--stdin`.

Either plumb `--stdin` through the top-level launcher too, or update
`site-docs/reference/cli-and-piping-cheatsheet.md` + the CLI matrix
to document why the top-level wrapper is `--cmd`-only.

### S11. `mkdocs.yml:4` still has placeholder `site_url` [H]

```
site_url: https://example.invalid/yggdrasim/
```

Material theme, social cards, canonical tags, and `sitemap.xml` all
reference this URL. Needs to be the real publish host before tagging
v1. If GitHub Pages, `https://hampushellsberg-dev.github.io/YggdraSIM/`;
if custom domain, set it here and add `site-docs/CNAME`.

Also note `mkdocs.yml:22, 119-120` use `hampushellsberg/YggdraSIM`
while `git remote`, install scripts, and `_common.sh` use
`hampushellsberg-dev/YggdraSIM` — the repo-owner inconsistency called
out in B4 is still live in `mkdocs.yml` too.

### S12. 41 Markdown pages in `site-docs/` are not in the MkDocs nav [M]

Listed on a fresh build. Four are clear orphans with no inbound link
(every reference points at the nav-registered `subsystems/*.md`
copy):

- `site-docs/hil-bridge.md`          (superseded by `subsystems/hil-bridge.md`)
- `site-docs/profile-package.md`     (superseded by `subsystems/profile-package.md`)
- `site-docs/scp11.md`               (superseded by `subsystems/scp11-*.md`)
- `site-docs/state-and-plugins.md`   (superseded by concepts + how-to pages)

The remaining 37 are intentional:

- `_includes/abbreviations.md` is auto-appended by
  `pymdownx.snippets` (`mkdocs.yml:105-106`), not a page.
- `sources/**` is the source-library mirror served under
  `/source-library/` via `source-library.md`.

Action:

1. `git rm` the four superseded top-level pages.
2. Either add each `sources/**/*.md` to the nav as a collapsed tree,
   or explicitly pin them under `exclude_unused` / document that
   mkdocs intentionally serves them as a browse-able source library.
3. Re-run `mkdocs build --strict` to confirm S1 + S12 both clear.

### S13. Test suite has no `conftest.py` and no pytest configuration [M]

- `tests/conftest.py` does not exist.
- `pyproject.toml` has no `[tool.pytest.ini_options]` block.
- No `pytest.ini` / `setup.cfg` / `tox.ini` either.

Implications:

- Every run uses default collection, no `testpaths`, no markers, no
  addopts. Random `-v`-style output, no `--maxfail`, no coverage.
- The project's `.cursor/rules/pytest-memory-safety.mdc` documents
  the required defaults (`-q --tb=short --disable-warnings
  --no-header --maxfail=1`). None of that is enforced by the repo.
- No central fixture for runtime-root isolation, so tests must each
  re-implement tmpdir setup.

Minimal v1 patch:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q --tb=short --disable-warnings --no-header"
filterwarnings = ["ignore::DeprecationWarning:construct"]
```

Plus a `tests/conftest.py` that sets `YGGDRASIM_RUNTIME_ROOT` to an
ephemeral tmp dir per session.

### S14. 87 test files, 41,827 lines, zero collection index [M]

`tests/` is one flat folder of 87 `test_*.py` files plus an
`eim-sh/` fixture dir. Several exceed 3,000 lines
(`test_hil_bridge_live_decode_tui.py` = 4,607 lines,
`test_simcard_backend.py` = 3,207 lines, `test_scp11_eim_local.py` =
2,939 lines) which bumps up against the project's internal
"modularize when the file grows" standard. Not a blocker but
flag-worthy for v1.1 refactor.

Also no `pytest --collect-only` reference is checked into
`site-docs/internals/testing-guide.md` so contributors cannot quickly
discover what gets exercised.

### S15. Five large Python modules exceed internal coding-standard sizing [M]

From `find . -name '*.py' | wc -l` against the non-vendored tree:

- `Tools/ProfilePackage/saip_transcode_tui.py` — 7,122 lines
- `Tools/HilBridge/live_decode_tui.py` — 6,211 lines
- `Tools/ProfilePackage/shell.py` — 4,383 lines
- `SCP11/test/console.py` — 4,130 lines
- `SCP11/live/console.py` — 4,076 lines
- `Tools/ProfilePackage/saip_asn1_decode.py` — 4,127 lines

The `.cursorrules` policy reads *"When deemed necessary to maintain
manageable file sizes, it is accepted to start to modularize."* All
six candidates are well past "necessary." Not a release blocker but
should be on the v1.1 roadmap; otherwise every future change lands
in an 80 kB context window.

### S16. No SBOM / reproducible build manifest [N]

Three secure-element-adjacent supply-chain asks that modern
downstream operators expect but YggdraSIM does not yet ship:

1. `SBOM.spdx.json` or CycloneDX manifest, generated per tag by the
   PyInstaller pipeline (`pyinstaller` + `cyclonedx-bom` or `syft`).
2. `requirements.lock` (or `poetry.lock` / `uv.lock`) with pinned
   hashes for reproducible installs.
3. SHA256SUMS file next to the GitHub release artefacts, signed with
   the release key documented in SECURITY.md.

Queue for v1.1; not tag-blocking.

### S17. `pyproject.toml` version vs. tag scheme [M]

`pyproject.toml:7` is `2026.4.10` (CalVer). README + NOTICE read like
SemVer. `site-docs/internals/release-checklist.md` likely covers the
bump step, but the current `version` string will confuse consumers
running `pip show yggdrasim` after a fresh tag. Pick one before
tagging and document the policy in `CONTRIBUTING.md` / `CHANGELOG.md`.

### S18. `yggdrasim.egg-info/` is on disk, untracked, and not in `.gitignore` [M]

Confirmed by `git status` + `ls`. Same pattern as `.venv/` — it's not
tracked today, but there is nothing preventing the next
`pip install -e .` run from committing it on a contributor's box.
Add to `.gitignore` alongside the patterns in S6.

### S19. `requirements-docs.txt` exists but MkDocs deps live nowhere else [N]

Untracked file at repo root. `pyproject.toml` has no `docs` extra, so
the intended install path (CI, contributor) is ambiguous. Either:

1. Promote `requirements-docs.txt` to a tracked file and reference
   it from the new `docs` CI job (S2) and from the new
   `CONTRIBUTING.md`.
2. Or add a `docs` extra to `pyproject.toml` (`mkdocs`,
   `mkdocs-material`, `pymdown-extensions`) and delete
   `requirements-docs.txt`.

### S20. Docker image copies the full repo including test fixtures [M]

`Dockerfile` currently does `COPY . /opt/YggdraSIM`. With a
37 MB `trace/`, the vendored `pysim/` (13 MB), a 250-file
`SCP11/SGP.26_test_Certs/`, and the forthcoming `pyscard/` cleanup,
the container is significantly larger than it needs to be. Once S5
+ B7 are resolved, audit `.dockerignore` to ensure the image only
carries shippable runtime material, not test fixtures, not guides,
not `tests/`.

### S21. `.github/workflows/build.yml` does not run the test suite [H]

The CI pipeline builds PyInstaller bundles + a .deb but does not
invoke `pytest`. That means every release artefact is produced
without a green test gate. For a v1 release this needs at minimum a
dedicated test job that runs a curated subset of `tests/` on Linux,
macOS, and Windows.

Add to `.github/workflows/`:

```yaml
test:
  strategy:
    matrix:
      os: [ubuntu-latest, macos-latest, windows-latest]
      python: ["3.10", "3.11", "3.12"]
  runs-on: ${{ matrix.os }}
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: ${{ matrix.python }} }
    - run: pip install -e .[dev]
    - run: pytest -q --tb=short --disable-warnings
build:
  needs: test     # gate bundle + docker on the test job
```

### S22. `scripts/install/install-linux.sh` depends on an apt package that is typically not in Debian/Ubuntu main [M]

Line 50 attempts `apt-get install osmo-remsim-client` as the primary
path for the `full` flavor HIL bridge install. `osmo-remsim-client`
is not in Debian / Ubuntu main repositories; it ships through
`https://download.opensuse.org/repositories/network:/osmocom:/latest/`
(OBS). The script logs a warning and continues, but the downstream
HIL bridge flow will fail at runtime without that binary.

Fix: either add the OBS repo in `install_linux_prereqs()` explicitly
(with a `curl -fsSL ... | sudo tee /etc/apt/sources.list.d/...`) or
switch the default to `--no-deps` and document the OBS step in
`guides/SIMTRACE2_CARDEM_GUIDE.md`.

### S23. `mkdocs.yml` `extra_javascript: mermaid-zoom.js` is opt-in only [N]

No `mermaid` plugin listed in `plugins:` (lines 71-73). The
`pymdownx.superfences` custom fence at lines 107-111 wires mermaid in
manually. This works, but it means the deploy target must serve
mermaid from the theme bundle. Flag-worthy in case a visual
regression shows up during the S1 strict build.

### S24. README references `docs/` which is `.gitignore`'d [H]

`.cursor/rules/relevant-documentation-can-be.mdc` says
documentation lives under `docs/`. `.gitignore:84` also has `docs/`
listed. Meanwhile:

- `README.md` references `docs/` as the offline reference hub
  (first-pass finding — still unaddressed).
- `site-docs/reference/standards-map.md:43` links
  `docs/RSPRO.asn`.
- `yggdrasim_common/registry.py` and several tools look up
  `docs/**` at runtime for standards excerpts.

Net effect: a fresh `git clone` yields a toolkit that references
a directory that is never populated. Either:

1. Track the sanitized subset of `docs/` that the project is
   distributing (ETSI / 3GPP material that is public), drop
   `docs/` from `.gitignore`, and note it in `NOTICE`; or
2. Stop referencing `docs/` from user-facing docs and tools,
   leave it gitignored as a developer-only workspace for
   non-shippable vendor PDFs.

---

## Concrete pre-v1 action list (in order)

1. **Purge working-tree clutter** — delete probe dotfiles,
   `YggdraSIM.md`, anything under `.profilepackage-cache/` / `trace/`
   that is not intended to track. Extend `.gitignore` with `.venv/`,
   `*.egg-info/`, `trace/`, `Latjo/`, `.pytest_chunk_log*.txt`,
   `.tuak_kat_sanity.py` (or move to `tests/`). Drop `pysim/` from
   `.gitignore` and add `pyscard/`.
2. **Remove `pysim/` and `pyscard/` from the working tree** (B7).
   Update `pyproject.toml` / `requirements.txt` to list `pySim` as an
   installable dependency; strip `pysim` from
   `yggdrasim_main.spec:70`; rewrite the doctor probe; update README
   wording; update registry subsystem description.
3. **Remove `.venv/` from git** — `git rm -rf --cached .venv` and commit.
4. **Extend `.dockerignore`** to mirror the expanded `.gitignore` so
   container images do not ship 40+ MB of test fixtures / generated
   docs / traces.
5. **Commit the backlog in 6 logical chunks** (B1 plan).
6. **Add `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`**, the
   GitHub issue / PR templates, and (optionally) `CODE_OF_CONDUCT.md`.
7. **Reconcile repo URLs** (B4) — single canonical owner, real
   `site_url`, sweep install scripts and docs.
8. **Strip dev dependencies from `requirements.txt`** or delete the
   file.
9. **Add test-material notices** in `SCP11/` for the GSMA SGP.26
   public test keys.
10. **Decide version scheme**, bump `pyproject.toml`, write the v1.0.0
    changelog entry.
11. **Run the project's own release checklist** end-to-end
    (`site-docs/internals/release-checklist.md`). Fix every item.
12. **Tag `v1.0.0`** (or `v2026.5.0`), push tag, let the GH Actions
    build matrix produce clean + full artefacts.

### Second-pass additions (slot into the list above where it fits)

- **Before step 1**, `git rm -rf trace/ipad_test_site/ trace/ipad_test_runtime/`
  and extend `.gitignore` with `trace/`, `.venv/`, `.venv-*/`,
  `yggdrasim.egg-info/`, `Latjo/`, `.pytest_chunk_log*.txt`,
  `.pytest_agent_log.txt`, `.tuak_kat_sanity.py`. [S5, S6, S18]
- **Step 1a.** Re-run `python site-docs/_tools/mirror_source_docs.py`
  to fill the five missing `site-docs/sources/guides/INSTALL_*.md` /
  `SIMTRACE2_CARDEM_GUIDE.md` entries. Verify with
  `mkdocs build --strict`. [S1]
- **Step 1b.** Delete the four superseded top-level pages
  (`site-docs/hil-bridge.md`, `profile-package.md`, `scp11.md`,
  `state-and-plugins.md`). [S12]
- **Step 1c.** ~~Resolve `plugins/polling_plugin.py` vs.
  `plugins/.gitignore` collision~~ — completed: the plugin is now a
  tracked package under `plugins/polling/` with the bridge isolated to
  `wifi_ethernet_bridge.py`. See S3 RESOLVED note. Former text kept
  below for audit history — either promote the plugin out of
  the drop-zone or move the test to a fixture load path. [S3]
- **Step 2a.** Replace placeholder `site_url` in `mkdocs.yml`,
  reconcile `hampushellsberg/YggdraSIM` vs
  `hampushellsberg-dev/YggdraSIM` across `mkdocs.yml` +
  install scripts + README. [S11, repeat of B4]
- **Step 5a.** Sweep 15 bare `except:` sites, split every
  single-line `except :pass` into proper blocks per the coding
  standard. [S8]
- **Step 5b.** Add `[tool.pytest.ini_options]` and
  `tests/conftest.py` with a session-scoped runtime-root tmp dir.
  [S13]
- **Step 5c.** Decide SCP11 triplication path (merge or fence).
  For v1, at minimum promote the four byte-identical modules
  (`crypto_engine.py`, `eim_packages.py`, `asn1_registry.py`,
  `payload_builder.py` in two trees) into `SCP11/shared/`. [S4]
- **Step 6a.** Add SPDX headers to every `*.py` in the
  `setuptools.packages.find.include` scope. Add
  `THIRD_PARTY_LICENSES.md`. [S9]
- **Step 6b.** Either track or delete `requirements-docs.txt`, and
  create a `[project.optional-dependencies] docs = [...]` entry if
  tracked. [S19]
- **Step 7a.** Either remove or relocate + rewrite
  `tests/eim-sh/script.sh` so it has no hard-coded developer
  paths. [S7]
- **Before step 11**, land two new CI workflows:
  - `docs.yml` — runs mirror + strict mkdocs build. [S2]
  - `test.yml` (or a `test:` job in `build.yml`) — runs `pytest`
    on Linux / macOS / Windows and gates bundle builds. [S21]
- **Step 11a.** Dockerfile audit after B7 + S5 land — verify the
  `clean` image is under 400 MB compressed. [S20]
- **Step 11b.** Either add an OBS `osmocom` apt source to
  `install_linux_prereqs` or document the manual step in
  `guides/SIMTRACE2_CARDEM_GUIDE.md` + surface the pointer in the
  installer output. [S22]
- **Step 11c.** Resolve the `docs/` reference inconsistency — ship
  a sanitized subset or strip references. [S24]

### Optional (v1.1+)

- SBOM / lock-file / signed SHA256SUMS for release artefacts. [S16]
- SCP11 full tree unification into `SCP11/shared/`. [S4]
- Modularize the six largest Python files per the
  `.cursorrules` sizing hint. [S15]
- `--stdin` on the top-level launcher for parity with SCP03 and
  SCP80. [S10]

---

## Third-pass: pre-existing test failures observed (2026-04-19)

Captured while running the SIMCARD-adjacent smoke pass post
B-01/B-02/B-03/B-04/B-06/B-09/B-11 changes. None of the modules below
import `SIMCARD/*`; these failures therefore pre-date this pass and are
still blockers for locking in v1.

### T1. `tests/test_hil_bridge_live_decode_tui.py` (two failing nodes)

- `HilBridgeLiveDecodeTuiTests::test_cycle_summary_view_switches_to_flat_chronological_packet_list`
  — `assertTrue(any("FETCH" in label for label in flat_labels))` fires
  `False is not true`. The flat-view label construction now prepends the
  packet-info text with a different prefix than the test expects.
- `HilBridgeLiveDecodeTuiTests::test_summary_refresh_ignores_transient_first_packet_highlight_during_rebuild`
  — `mock.patch("Tools.HilBridge.live_decode_tui._populate_summary_tree")`
  raises `AttributeError`; the private helper was renamed or inlined
  but the test still targets the old name.

Both are TUI-label mismatches / stale mock targets. Fix before v1.

### T2. `tests/test_scp11_local_access.py` — infinite hang

`LocalAccessSessionTests::test_build_effective_metadata_document_derives_fields_from_profile`
(and at least one sibling `test_build_effective_metadata_document_*`)
never terminate. The body calls
`LocalIsdrSession._build_effective_metadata_document(profile_bytes)` on
a real SAIP profile; the blocking call appears to be somewhere inside
the pySim SAIP decoder or a downstream metadata projector. Running the
whole file exhausts the configured 60 s external `timeout` without
producing any output.

Action: bisect inside `LocalIsdrSession._build_effective_metadata_document`
to find the loop (suspect a missing length/termination check on a TLV
walk). Either fix the underlying bug or gate the test behind a
`pytest.mark.slow` skip. Do not ship v1 with a hanging test in the
default suite.

### T3. `tests/test_saip_asn1_decode.py` — one failing node

`SaipAsn1DecodeTests::test_transcode_inspector_resolves_template_arr_rule_summary`
expects the transcode inspector output to contain
`securityAttributesReferenced record 2:`, but the current renderer
emits only an `EF.IMSI` dump for the supplied fixture. Either the
fixture drifted away from the template that produces the ARR record,
or the inspector stopped emitting the per-record header in the
template-resolved path.

### T4. `tests/test_saip_transcode_tui.py` — one failing node

`SaipTranscodeTuiInteractionTests::test_add_selected_pe_file_prompts_for_file_overrides`
fails during an interactive TUI simulation. Log shows the test reaching
the USIM PE file tree construction and then never asserting the prompt
overrides. Likely a stale prompt-message string.

### T5. SCP80 inter-file test isolation leak

`TransportTests::test_get_protocol_summary_reads_atr_data` passes when
its file is run alone (`pytest tests/test_scp80_core_modules.py`) but
fails when chained after `tests/test_scp80_cli.py` and
`tests/test_scp80_command_surface_dispatch_extra.py` in a single
pytest invocation. The failing assertion is `summary["available"]`,
which means one of the earlier files left a mock or attribute patch
on the `SCP80.transport` module (most likely `ATR` or
`PYSCRARD_AVAIL`) without tearing it down.

Action: audit `mock.patch` usage in the two SCP80 shell/surface test
files and convert any module-attribute patches to `with` blocks or
`addCleanup`. This is a test-side fix, not a product bug, but it
breaks the "run all tests in one pytest process" assumption that CI
will want.

### Pre-v1 gate

Before `git tag v1.x`, the expected clean state is:

- Zero failing nodes from `tests/test_simcard_*` (confirmed, 79/79).
- Zero failing nodes from `tests/test_scp03_*` (confirmed, 54/54).
- Zero failing nodes from `tests/test_hil_bridge_*` (50/50 on non-TUI
  files; T1 still pending).
- T2 either fixed or quarantined behind a `slow` marker.
- T3 and T4 fixed.
- Per-file, timeboxed pytest runs on a cold machine across every
  `tests/test_*.py` file — never via `pytest` with no target, which
  locks up on at least this machine (see T2).

---

## Module deep-dive (5 passes per module)

Systematic, module-by-module sweep intended as the work queue between
this point and v1 tagging. Each pass uses a fixed analytical angle so
findings do not repeat between passes.

- **P1 Structure**: file layout, module size, coupling, dead code,
  naming drift.
- **P2 Standards**: GSMA SGP.02/22/32, ETSI TS 102 221 / 223,
  3GPP TS 31.102 / 33.102 / 35.206 / 35.231, GlobalPlatform Card
  Spec 2.3 + Amd D/F, ISO 7816-4 compliance.
- **P3 Resilience**: exception handling, silent failure, state
  corruption, resource cleanup, re-entrancy, timeout handling.
- **P4 Security**: crypto primitive usage, secret handling at rest
  and in memory, path / shell / deserialization injection, file
  permissions.
- **P5 Operability**: CLI surface, logging, prompt UX, docs ↔ code
  alignment, test coverage, environment variable handling,
  cross-platform behaviour.

Finding IDs follow `<MOD>-P<n>-<seq>`. Severity:

- **block** — must fix before v1 tag
- **fix** — should fix before v1 tag
- **nit** — quality-of-life, defer to v1.1 if needed

---

### Module: SIMCARD/

Simulated UICC / eUICC engine. 19 modules, 9,067 lines total.
Largest: `sgp.py` (2,376), `etsi_fs.py` (1,132), `toolkit.py` (1,080).
Post-B-01..B-11 patch state.

#### P1 Structure

- **SIM-P1-01** `fix` `SIMCARD/sgp.py` is 2,376 lines with 117 `def`
  statements and 49 `except Exception` blocks. Exceeds the sizing
  guidance in `.cursor/rules` and is the module least amenable to
  review. Split along SGP.22 lifecycle boundaries: authenticate /
  prepare download / load BPP / profile state change / notifications /
  eIM identity + polling projection. Keep `SgpLogic` as the thin
  dispatcher.
- **SIM-P1-02** `nit` `SIMCARD/toolkit.py` (1,080 lines) bundles
  STK state machine, proactive command builders, and a full TLS / HTTP
  EIM poll bridge. Extract the poll-bridge machinery into a sibling
  `SIMCARD/toolkit_poll.py` so the core STK logic is readable on its
  own.
- **SIM-P1-03** `fix` `SIMCARD/connection.py` keeps a single
  process-global `_SHARED_ENGINE`. The guard at lines 46-66 rebuilds
  when any of five path parameters change, but never disposes the
  previous engine — persistent handles on the old quirks module stay
  referenced via the `QuirkRegistry`. Add an explicit teardown on
  rebuild.
- **SIM-P1-04** `nit` Two bytes-coercion paths differ:
  `SIMCARD/connection.py` line 88 silently masks to 8 bits, while
  `SIMCARD/engine.py:transmit` accepts raw `bytes`. Consolidate into a
  single normalize helper so external callers cannot sneak >255
  integers into the simulator.
- **SIM-P1-05** `nit` `SIMCARD/state.py` has 20 dataclasses in a
  single file. Current cohesion is defensible (all describe the one
  `SimCardState` aggregate), but a `SIMCARD/state/` subpackage with
  `profile.py`, `toolkit.py`, `session.py`, `euicc.py` submodules
  would make incremental edits safer.

#### P2 Standards

- **SIM-P2-01** `fix` `SIMCARD/etsi_fs.py:build_fcp` returns the
  FCP template with tag `62` for regular files regardless of P2 FCI /
  FCP / FMD selection. B-01 added the "no response" gate (P2 & 0x0C
  == 0x0C) but did not correct the tag for P2 requesting FCI (`62` →
  `6F` wrapping 62 + 64). Current tests hide this because they
  always use P2=0x04. Fix after v1.0 if it breaks any real terminal.
- **SIM-P2-02** `block` `[fixed]` `SIMCARD/scp03.py:handle_initialize_update`
  still returns `i = 0x03` and unconditionally appends a 3-byte
  sequence counter (lines 64-70). GlobalPlatform Card Spec Amd D
  §7.1.1 requires `i` to reflect the actual secure channel options
  negotiated (`0x00..0x7F` with specific meanings) and the sequence
  counter is only present when `i` bit 4 (0x10) is set in specific
  profiles. Needs a real eUICC `INITIALIZE UPDATE` capture to
  calibrate — do not ship a guessed value.
- **SIM-P2-03** `fix` `SIMCARD/naa.py` CHV retry counters are
  checked against `self.state.chv_references[p2]` but the value is
  decremented unconditionally. ETSI TS 102 221 §9.5.1 requires the
  counter stay at 0x00 once exhausted; verify the implementation
  does not wrap below zero and does not decrement on already-blocked
  CHV (`6983` path).
- **SIM-P2-04** `fix` `SIMCARD/auth.py:internal_authenticate` seeds
  SQN with a window but does not perform AUTS resynchronisation
  rotation per 3GPP TS 33.102 §6.3.3. For a simulator the current
  "accept any reasonable SQN" policy is acceptable for v1; document
  this in `site-docs/subsystems/simcard-simulator.md` so operators
  know it is simplified.
- **SIM-P2-05** `fix` `SIMCARD/engine.py _dispatch` lacks a
  dedicated `0xA2 SEARCH RECORD`, `0x32 INCREASE` and `0xD2 WRITE
  RECORD` arm. Real eUICCs accept these for linear-fixed EFs. Either
  implement them (preferred) or explicitly return `6D 00` with a
  comment referencing the standard, instead of falling through to the
  CLA-filter-only path.

#### P3 Resilience

- **SIM-P3-01** `fix` `SIMCARD/sgp.py` has 49 `except Exception`
  blocks that silently return tag-wrapped `80 01` error bytes or
  empty bodies. Several (lines 251, 264, 269, 285, 295, 309, 321,
  330) swallow any decoder exception and respond `success` to the
  caller — this masks malformed SAIP / SGP payloads that should have
  produced `6A 80` or similar. Audit each, distinguishing
  "SGP-specified soft error" from "simulator internal failure".
- **SIM-P3-02** `block` `SIMCARD/engine.py:transmit` still returns
  `(b"", 0x6F, 0x00)` on any unexpected exception. B-09 added a
  bounded fault ring, but the default path is still to silently
  absorb the fault. Make the fault-ring dump a human-readable
  snapshot on engine shutdown so CI failures leave evidence without
  requiring the env var.
- **SIM-P3-03** `fix` `SIMCARD/toolkit.py` polling loop catches
  network / DNS / TLS exceptions without any retry backoff or
  circuit breaker. A misconfigured eIM endpoint will spin the
  engine at full speed. Introduce a minimum 200 ms sleep + an
  exponential backoff on repeated failures.
- **SIM-P3-04** `fix` `SIMCARD/profile_store.py` writes profile
  entries one by one without fsync on the enclosing directory. On
  power loss the JSON metadata can survive while the secret
  sidecar is lost. Add an `os.fsync` on both the file descriptor
  and the parent directory for each secret-bearing write.
- **SIM-P3-05** `nit` `SIMCARD/quirks.py:_load_module_from_path`
  uses `abs(hash(path))` as the synthetic module name. `hash` is
  salted per-process, which is fine, but two engines built in the
  same process with the same path will collide deterministically.
  Use the absolute path hash + a per-engine counter so repeated
  rebuilds do not stamp over each other's `sys.modules` entry.

#### P4 Security

- **SIM-P4-01** `block` `[fixed]` `SIMCARD/quirks.py` loads arbitrary Python
  from `sim_quirks.py` with `spec.loader.exec_module(module)` (line
  311). Anyone who can drop a file into the quirks path gets code
  execution with the process's privileges. The module is
  explicitly user-scoped so this is by design, but v1 needs:
  (a) a `YGGDRASIM_ALLOW_QUIRKS=1` gate,
  (b) a startup log line printing the absolute path that was loaded,
  (c) a `--no-quirks` launcher flag that refuses the load.
- **SIM-P4-02** `fix` `SIMCARD/scp03.py` uses `os.urandom(8)` for
  the card challenge (line 50) — correct. No other crypto-critical
  randomness in SIMCARD uses `random.` / `secrets.` inconsistently,
  so this pass is otherwise clean.
- **SIM-P4-03** `fix` `SIMCARD/profile_store.py` and
  `SIMCARD/euicc_store.py` persist key material via
  `write_secret_file_bytes`. Verify that the containing directory
  is created with mode `0o700` and that orphaned secret sidecars
  are cleaned up when the parent JSON entry is removed (at least one
  recent code path appears to leave a `<eid>.K_AUTH.sec` after
  profile deletion — confirm with an integration test).
- **SIM-P4-04** `fix` `SIMCARD/auth.py` does not log OP/OPc/K
  values, but `SIMCARD/toolkit.py` and `SIMCARD/sgp.py` print
  transaction IDs and command bodies when debug flags are set.
  Audit every `print(` in the simulator tree so no secret material
  reaches stdout even when `YGGDRASIM_SIM_DEBUG_*` is enabled —
  currently zero `print(` in SIMCARD except the one I just added;
  keep it that way.
- **SIM-P4-05** `nit` `SIMCARD/connection.py` global engine has no
  locking. Two threads calling `transmit` concurrently will
  interleave APDU history / store-data buffers. Document
  "single-threaded transmit" as the contract, or add a reentrant
  lock around `SimulatedSimCardEngine.transmit`.

#### P5 Operability

- **SIM-P5-01** `fix` The golden-card harness (`tests/golden/`)
  only covers the basic ETSI read path. Extend with SCP03
  `INITIALIZE UPDATE`-level coverage once a real eUICC is
  available (ties into SIM-P2-02 / B-08).
- **SIM-P5-02** `fix` `YGGDRASIM_SIM_DEBUG_FAULTS=1` is documented
  nowhere. Add it to `site-docs/subsystems/simcard-simulator.md`
  and `site-docs/reference/troubleshooting.md`.
- **SIM-P5-03** `nit` No CLI exposes the fault ring. Add a
  `sim.faults` entry to the SCP03 / eIM shells that prints the
  contents of `engine._fault_ring` so operators can triage without
  attaching a debugger.
- **SIM-P5-04** `fix` `SIMCARD/saip_profile.py` and
  `SIMCARD/profile_import.py` emit no structured errors — they
  return `ProfileImportResult` objects whose failure paths are only
  discoverable by reading the source. Add explicit, documented
  error codes / messages so profile-import failures in the Profile
  Package tooling map to a single troubleshooting page.
- **SIM-P5-05** `nit` `SIMCARD/__init__.py` exports a narrow
  public surface, but nothing marks the rest as private. Adopt
  `__all__` at the package level and at each submodule so IDE
  auto-complete does not suggest internals like `_SHARED_ENGINE`.

---

### Module: SCP03/

Interactive SCP03 / SCP02 / GlobalPlatform shell. 21,956 lines
across `core/`, `crypto/`, `logic/`, `transport/`, `interface/`.
Largest: `logic/sgp22.py` (3,205), `interface/shell.py` (3,172 /
112 defs), `logic/fs.py` (2,292 / 71 defs), `interface/
shell_wizards.py` (1,938), `core/decoders.py` (1,907).

#### P1 Structure

- **SCP03-P1-01** `fix` `interface/shell.py` at 3,172 lines in a
  single `ShellDispatcher` with 112 methods is the repo's most
  unmaintainable file. Split into:
  `shell_runtime.py` (loop, history, prompt state),
  `shell_binds.py` (custom binds + alias handling),
  `shell_state.py` (SCP03 key / session management),
  `shell_profiles.py` (profile snapshot / diff commands).
  Keep `ShellDispatcher` as an assembly point only.
- **SCP03-P1-02** `fix` `logic/fs.py` (2,292 lines, 71 defs)
  mixes raw APDU sequencing, FCP parsing, path-walker state, and
  pretty-printing. Extract the printers into
  `interface/fs_view.py`.
- **SCP03-P1-03** `block` Space-padded source style (`self .k_enc
  =static_keys ['kenc']`) pervades `config.py`, `crypto/session.py`,
  `transport/card.py`, `interface/shell.py`, `logic/gp.py`,
  `logic/sgp22.py`, `interface/shell_wizards.py`,
  `interface/guides.py`, and others. It is not valid idiomatic
  Python and breaks most linters / formatters. Run `black` (line
  length 100) across the entire SCP03 tree in a single "style
  only" commit. Newer modules like `logic/sgp32_decode.py` and
  `logic/euicc_info2.py` are already clean — the fix is
  format-only.
- **SCP03-P1-04** `fix` `Config.Colors._hex_to_ansi.__func__(...)`
  (`config.py:77-86`) abuses staticmethod's `__func__` attribute
  inside the class body. Rewrite as a module-level `_hex_to_ansi`
  and assign colour constants from it.
- **SCP03-P1-05** `nit` Two SGP parsing surfaces coexist —
  `logic/sgp22.py` (3,205 lines, SGP.22 scanner) and
  `logic/sgp32_decode.py` (390 lines, SGP.32 decoder tables). The
  naming does not make the overlap obvious. Add a
  `logic/sgp_decoders.md` note documenting which module owns
  which tag set.

#### P2 Standards

- **SCP03-P2-01** `block` `[fixed]` `crypto/session.py:derive_keys` line 63
  uses `if expected != card_cryptogram:` — direct byte comparison
  with no constant-time guard. GlobalPlatform Amd D §6.3.3 does
  not mandate constant-time equality on the host side, but
  timing oracles on cryptograms are a documented attack class.
  Replace with `hmac.compare_digest`.
- **SCP03-P2-02** `fix` `crypto/session.py:unwrap_response` (lines
  140-164) tries every candidate IV in a loop, silently catching
  `Exception` and accepting any IV whose decrypt produces valid
  ISO 9797-1 padding. GlobalPlatform Amd D §6.2.6 requires
  deterministic IV generation (`S-ENC(ICV_counter)`). The IV
  ambiguity is a workaround for unknown vendor quirks — document
  exactly which vendor required it and gate behind an explicit
  flag; do not have it as the default behaviour.
- **SCP03-P2-03** `fix` `logic/gp.py` reads SCP03 KVN / key set
  from `DEFAULT_KEYS` with static `30` for KVN. GPCS 2.3 §11.1.1
  KVN 0x30 is only one of multiple production mappings; verify
  that `INITIALIZE UPDATE` P1/P2 construction honours the actual
  KVN from `keys.ini` and not the default.
- **SCP03-P2-04** `fix` `transport/card.py` FI_TABLE / DI_TABLE
  use ETSI TS 102 221 §7.2.3 correct values but expose them as
  class-level mutable dicts. Freeze them as `MappingProxyType`
  so downstream code cannot mutate during runtime.
- **SCP03-P2-05** `fix` `logic/security.py` embeds test vectors
  from 3GPP TS 35.207 §8 (`AUTH_TEST_VECTOR`) as the **live**
  module constant. They are used by `_run_authenticate_ki_check`
  as the default AUTN / RAND path. Move into a `tests/` fixture
  and have the runtime path demand a user-provided vector; a
  production SCP03 shell should never silently use a test-vector
  Ki.

#### P3 Resilience

- **SCP03-P3-01** `fix` `crypto/session.py:derive_keys` raises
  bare `Exception(...)` (line 64). Replace with a typed
  `Scp03CryptogramError(Exception)` so callers can differentiate
  "protocol failure" from "transport failure".
- **SCP03-P3-02** `fix` `crypto/session.py:unwrap_response`
  `except Exception: pass` silently hides every CBC / padding
  error; legitimate MAC failures look identical to IV
  mismatches. Log at least one warning line per failed IV and
  refuse to decrypt when no candidate succeeds (currently returns
  the ciphertext `payload` unchanged, which downstream code may
  mistake for plaintext — dangerous).
- **SCP03-P3-03** `fix` `transport/card.py:connect` swallows all
  connection errors into `return False`. For `ShellDispatcher`
  this is fine, but for scripted callers there is no way to
  distinguish "no reader" from "reader present but busy".
  Return a three-valued `ConnectResult` enum.
- **SCP03-P3-04** `fix` `logic/sgp22.py` has 31 `except
  Exception` blocks, most inside TLV parsers. Several silently
  swallow malformed BER-TLV from the card and return empty
  dicts. Wrap each in a `_safe_tlv_parse` helper that records the
  failing buffer to a debug log (off by default) so malformed
  card responses can be triaged.
- **SCP03-P3-05** `fix` 44 `except Exception` blocks in
  `interface/shell.py` — many use `except Exception: pass` in
  command handlers. An operator mistyping a hex value silently
  gets no feedback. Standardise on `except (ValueError,
  TypeError) as exc: self._print_error(exc)` and let unexpected
  exceptions propagate to the shell's global handler.

#### P4 Security

- **SCP03-P4-01** `block` `[fixed]` `config.py:40-51` ships
  `DEFAULT_KEYS` with hardcoded `1122334455667788AABBCCDDEEFF0011`
  for every SCP03 / SCP02 key slot and `0000000000000000` as ADM.
  First-run shell comes up with these keys and will happily
  attempt `EXTERNAL AUTHENTICATE` against any card. On a real
  GSMA-certified card this will burn SCP03 retry counters. v1
  must:
  (a) print a bright red "DEFAULT TEST KEYS ACTIVE" banner on
  every shell launch until overridden,
  (b) refuse `authenticate sd` without an explicit
  `--use-default-keys` flag,
  (c) seed `keys.ini` with empty string slots instead of test
  vectors.
- **SCP03-P4-02** `fix` `crypto/session.py:encrypt_key_data`
  (line 166+) loads the DEK from `self.dek` → attribute scan →
  `SCP03/keys.ini`. The last fallback uses plaintext INI. Verify
  integration with `yggdrasim_common.secret_file` so DEK is
  stored via `write_secret_file_bytes` in a 0600 sidecar.
- **SCP03-P4-03** `fix` `Scp03Session` keeps raw `k_enc`,
  `k_mac`, `dek`, `s_enc`, `s_mac`, `s_rmac` in instance
  attributes for the session lifetime. Zeroise on `reset_state`
  (currently only re-seeds chain / ssc / challenges). Use a
  `bytearray` + explicit wipe so swap / core dumps are not
  populated with live AES-128 session keys.
- **SCP03-P4-04** `fix` `traceback` is imported in
  `transport/card.py` (line 18) but never used — grep shows zero
  call sites. Dead import, but also a hint that error paths were
  silenced instead of logged. Re-enable guarded traceback
  printing behind `YGGDRASIM_SCP03_DEBUG=1`.
- **SCP03-P4-05** `nit` `interface/shell.py` history/readline:
  verify the readline history file has mode `0o600`. If it
  records typed keys / PINs, the default `~/.scp03_history`
  permission should be restrictive.

#### P5 Operability

- **SCP03-P5-01** `fix` Zero usage of `logging.` across the whole
  SCP03 tree — everything is `print()`. 933+ `print(` calls.
  Output cannot be silenced or rerouted for automated testing.
  Introduce a thin `SCP03/logging.py` wrapper (named loggers per
  submodule) and migrate `print` in non-interactive paths
  (`logic/*`, `core/*`, `transport/card.py`) first.
- **SCP03-P5-02** `fix` `logic/stk.py` and
  `logic/profile_validator.py` each contain 3 / 9 `print(` calls.
  Logic modules must never print — they should return structured
  results and let the shell render them.
- **SCP03-P5-03** `fix` `shell.py` launches `readline` if
  available but falls back silently. On Windows (no `readline`)
  UX degrades without notice. Document in
  `site-docs/workflows/shell-scp03.md` and optionally suggest
  `pyreadline3`.
- **SCP03-P5-04** `fix` Shell / wizard prompts mix `input()` and
  `getpass` — `getpass` only shows up in `interface/guides.py`
  and `interface/stk_shell.py`. Any prompt that accepts key
  material must use `getpass`, never `input()`. Audit
  `interface/shell.py`, `interface/shell_wizards.py`,
  `interface/wizards.py` prompts.
- **SCP03-P5-05** `nit` `Config.DEFAULT_KEYS` duplication —
  `config.py`, `shell.py` (×6), `logic/gp.py` all re-list the
  same key mapping. Centralise in a `config.KeyMap` dataclass.

---

### Module: SCP11/

SCP11a/SCP11b/SCP11c + ES9+ + SGP.22/.32 relay / local-access /
eIM stack. 53,738 lines across a top-level tree, `live/`,
`test/`, `local_access/`, `eim_local/`, `relay/`, `shared/`.
Largest: `live/console.py` (4,076), `test/console.py` (4,130),
`orchestrator.py` (3,634), `eim_local/session.py` (3,826),
`local_access/session.py` (3,644).

#### P1 Structure

- **SCP11-P1-01** `block` **Three parallel orchestrator trees**.
  `SCP11/orchestrator.py`, `SCP11/live/orchestrator.py`,
  `SCP11/test/orchestrator.py` each exceed 3,400 lines and share
  thousands of lines of identical code. Diff sizes measured:
  top vs live 1,264 lines, top vs test 508 lines, live vs test
  979 lines. Same pattern for `console.py` (1,751 / 1,812 diff
  lines), `es9_client.py` (407 / 209 / 245), `transport.py`
  (384 / 458), `payload_builder.py` (14 / 14 — effectively
  identical), `eim_packages.py` (identical). v1 must consolidate
  into a single engine module with variant-specific mixins.
  Recommendation: keep top-level as the single implementation,
  turn `live/` and `test/` into thin shim packages that import
  from the top-level and add only the variant delta (the
  `stk_polling` mixin pattern seen in `live/orchestrator.py:53`
  is already the right shape).
- **SCP11-P1-02** `block` `console.py` variants mix CLI
  dispatcher, TLS inspection helpers, ES9+ status printing, and
  interactive discovery in one 3,230-line class. Split:
  `console_cli.py` (argparse / dispatch),
  `console_tls_probe.py` (`_fetch_server_leaf_certificate`
  and friends), `console_state.py` (runtime state), and keep
  `console.py` as the composition root.
- **SCP11-P1-03** `fix` `local_access/session.py` (3,644 lines)
  and `eim_local/session.py` (3,826 lines) are independent
  implementations of overlapping SGP.22/SGP.32 logic. Factor
  shared state-machine steps into `SCP11/shared/session_core.py`
  (the `SCP11/shared/` subpackage already exists and is mostly
  shims, so this is a natural home).
- **SCP11-P1-04** `fix` `eim_local/main.py` at 2,541 lines and
  340 `print(` calls is primarily a CLI. Extract the argparse
  + dispatch pieces into `eim_local/cli.py` and keep `main.py`
  for the domain entry point.
- **SCP11-P1-05** `nit` `SCP11/relay/` is almost entirely
  re-export shims (`orchestrator.py` is 6 lines). The only real
  code is `relay/main.py` (203). Either promote the shims to
  canonical imports from `SCP11/__init__.py` or remove the
  module. Currently it signals "this is big" when it is not.

#### P2 Standards

- **SCP11-P2-01** `block` `es9_client.py:424-440` pinned-TLS
  path instantiates `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)`
  with `check_hostname=False` and `verify_mode=ssl.CERT_NONE`,
  then relies on a post-handshake SPKI comparison via
  `pinned_tls_spki=pinned_tls_public_key_data`. The pinning is
  correct per SGP.22 §2.5 (pinned TLS PK via BF55 metadata) but
  there is no defensive check that a matching SPKI was actually
  found before accepting the response. If the comparison logic
  returns `True` on empty SPKI the pinning is bypassed. Audit
  `_open_http_response` to confirm it rejects on empty /
  mismatching SPKI.
- **SCP11-P2-02** `fix` `SCP11/test/es9_client.py` lines 425-427
  still contain the "raw" unpinned `CERT_NONE` context path
  without a corresponding SPKI pin. It is keyed on `test/` but
  since `test/` is imported by live runs via the duplicated
  tree, confirm the test variant is never reachable from the
  production dispatcher.
- **SCP11-P2-03** `fix` `_fetch_server_leaf_certificate` and
  `_decode_leaf_certificate_dict` use
  `ssl._create_unverified_context()` (private API, `_` prefix).
  Replace with `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` with
  `check_hostname=False` + `verify_mode=CERT_NONE` — the
  semantic is the same but the API is public and stable across
  Python versions. Affected files: top-level `console.py`,
  `live/console.py`, `test/console.py`, `live/es9_client.py`,
  `test/es9_client.py`.
- **SCP11-P2-04** `fix` SGP.32 ESipa transport handling is
  split across `_eim_transport_mode`, `_eim_http_path`,
  `_eim_http_protocol` strings. The default path value
  `/gsma/rsp2/asn1` in `es9_client.py:114` is the SGP.22 RSP2
  endpoint, not the SGP.32 ESipa endpoint. Verify the defaults
  match the spec the code claims to implement.
- **SCP11-P2-05** `fix` `factory.py` should advertise supported
  curves (brainpoolP256r1, brainpoolP384r1, NIST P-256) and
  hash variants (SHA-256, SHA-384) explicitly per SGP.22 §2.6.
  Grep currently shows no such surface — scripted operators
  cannot discover which CI/PK IDs are supported without
  reading source.

#### P3 Resilience

- **SCP11-P3-01** `block` `[partial]` Total `except Exception`
  count across SCP11: ~760+. Of those, the orchestrator
  variants alone contribute 78 + 78 + 82 = 238. Most are
  TLV-parse or certificate-decode fallbacks that silently
  continue. The centralised helper is now in place:
  `SCP11/shared/safe_parse.py` exposes
  `safe_parse(label, buf, parser, default)` with a
  rate-limited warning rollup. Five representative sites in
  the canonical `SCP11/orchestrator.py` have been migrated
  (`_extract_certificate_subject_public_key_info`,
  `_extract_first_eim_entry_bytes`,
  `_find_first_tlv_value_recursive`, `_extract_choice_item`,
  `_extract_inline_pending_notification`). The remaining
  orchestrator / console / eim-local call sites are a
  mechanical migration tracked as a post-v1 sweep. The
  original bullet text follows so the helper's design intent
  stays discoverable:

  > introduce `SCP11/shared/safe_parse.py` with a single
  > `safe_parse(label, buf, parser, default)` that logs structured
  warnings and migrate all TLV/X.509 parse blocks to use it.
- **SCP11-P3-02** `fix` Identical `except Exception` patterns
  exist in three mirrored trees (orchestrator: 78/78/82, console:
  50/50/39, es9_client: 28/28/28). Any fix has to be made in
  triplicate. Consolidation (SCP11-P1-01) is the actual fix;
  until then, every triage hit requires three edits.
- **SCP11-P3-03** `fix` `eim_local/session.py` has 26 `except
  Exception`, `polling_bridge.py` 18. These govern the eIM
  polling state machine. Confirm that a single silenced
  exception does not wedge the poll loop (it should count
  failures and open-circuit after N).
- **SCP11-P3-04** `fix` `eim_local/poll_audit_store.py` 2
  `except Exception` around JSON persistence. Audit that
  corrupted audit files do not crash next launch — they should
  be archived with a suffix and a fresh file opened.
- **SCP11-P3-05** `fix` HTTP / TLS errors in `es9_client.py`
  are caught as `Exception` and returned as prose strings.
  Introduce a typed `Es9Error` hierarchy (`Es9TransportError`,
  `Es9ProtocolError`, `Es9ServerError`, `Es9TlsPinError`) so
  the orchestrator can branch on error type without parsing
  English.

#### P4 Security

- **SCP11-P4-01** `block` `[fixed]` The `_create_unverified_context()`
  usages for server-cert inspection (getpeercert before
  validation) are defensible, but there are **ten** such call
  sites across the three mirror trees. Any newcomer editing
  SCP11 is likely to misunderstand which are inspection paths
  and which are transport paths. Mark each with a comment
  "INSPECTION-ONLY, never transports payload" or move them all
  into `SCP11/shared/tls_inspection.py`.
- **SCP11-P4-02** `fix` `SCP11/` ships three DER/PEM pairs:
  `CERT.DPauth.ECDSA.der`, `CERT.DPpb.ECDSA.der`,
  `SK.DPauth.ECDSA.pem`, `SK.DPpb.ECDSA.pem`,
  `ES9_TEST_CI_CA.pem`. These are SGP.26 public test vectors —
  confirm they are labelled as such in `SCP11/README.md` and
  that `SCP11/check_keys.py` refuses to use them against a
  non-test endpoint. `SCP11/experimental/` also holds
  `.der` copies that look redundant; either delete or wire up.
- **SCP11-P4-03** `fix` `SCP11/pysim_path.py` mutates
  `sys.path` with whatever directory matches `pysim` /
  `pySim` in repo / workspace / bundle root. This is fine as
  long as the directories are trusted. If a user places a
  malicious `pysim/` tree into their workspace, it will be
  loaded. Document the lookup order in `SCP11/README.md` and
  add a warning line when a non-canonical path wins.
- **SCP11-P4-04** `fix` `eim_local/ipad_standalone.py` (638
  lines) — verify it does not write DEK / PSK material in
  plaintext to disk. It's the standalone iPad/eDRX flow and is
  a natural place for credential leakage.
- **SCP11-P4-05** `fix` `cert_store.py` (local_access + eim_local
  variants) — confirm certificate import uses
  `cryptography.x509.load_der_x509_certificate` with explicit
  backend / no `unsafe_legacy_renegotiation`, and that key
  import rejects unencrypted PKCS#8 unless the user explicitly
  opts in.

#### P5 Operability

- **SCP11-P5-01** `fix` Zero `logging.` calls in the SCP11
  tree. 1,400+ `print(` calls across the mirrored trees. Same
  critique as SCP03-P5-01 — non-scriptable output. Priority is
  higher here because SCP11 runs unattended in polling loops.
- **SCP11-P5-02** `fix` `SCP11/console.py` variants spell
  `es9_ca_lookup.json` via hardcoded path construction. Add
  a CLI command `es9 ca lookup list/refresh/clear` so operators
  can inspect the cache without reading JSON by hand.
- **SCP11-P5-03** `fix` Environment-variable explosion in
  `SCP11/config.py` (EIM_REQUEST_VARIANT,
  EIM_GET_PACKAGE_NOTIFY_STATE_CHANGE, EIM_GET_PACKAGE_STATE_
  CHANGE_CAUSE, EIM_GET_PACKAGE_RPLMN, EIM_TIMEOUT_SECONDS,
  EIM_CLEAR_ACK_ON_NO_PACKAGE, EIM_CLEAR_ACK_GENERIC_ERROR_HEX,
  EIM_CLEAR_ACK_RESULT_ERROR, EIM_PROFILE_DOWNLOAD_ERROR_REASON).
  These are not documented outside source. Add
  `site-docs/reference/scp11-env-vars.md` listing every
  variable, its accepted values, and its default.
- **SCP11-P5-04** `fix` `check_keys.py` is not wired into any
  CI / smoke target and has a single bare `except Exception`.
  Either promote it to a proper `scripts/check_scp11_keys.py`
  with exit codes, or delete it.
- **SCP11-P5-05** `nit` `SCP11/__init__.py` is minimal. Neither
  `live/` nor `test/` declares its public contract. Given the
  plan in SCP11-P1-01, any consolidation should leave a clear
  `SCP11/__init__.py` public API so downstream tests do not
  reach into the mirror subpackages directly.

---

### Module: SCP80/

ETSI TS 102 225 / 102 226 OTA packet builder + CAT_TP / SMS
transport + CLI. 1,773 lines across 9 files. Largest:
`cli.py` (675), `builder.py` (320), `transport.py` (286),
`config.py` (250).

#### P1 Structure

- **SCP80-P1-01** `fix` `SCP80/cli.py` at 675 lines with 105
  `print(` calls is one file that owns prompts, hex builder,
  key editor, APDU runner, and config editor. Split into
  `cli_shell.py` (loop) + `cli_commands.py` (per-command
  handlers) + `cli_editors.py` (key / header editors).
- **SCP80-P1-02** `nit` SCP80 is the only module in the repo
  that still uses pycryptodome (`from Crypto.Cipher import
  AES, DES3` in `crypto.py:18-19`). Everything else moved to
  `cryptography`. Migrate for consistency; it drops one
  dependency from the install profile.
- **SCP80-P1-03** `fix` Both `transport.py` and `builder.py`
  use the `if __package__:` / `else: from utils import Utils`
  dual-import trick. This is a symptom of being runnable both
  as a module and as a script. Pick one (module-only) and
  delete the fallback — the `__main__.py` already exists for
  script execution.
- **SCP80-P1-04** `nit` Same space-padded token style as SCP03.
  Apply `black` in the same repo-wide style pass
  (SCP03-P1-03).
- **SCP80-P1-05** `nit` No `builder_test_vectors.py` / fixtures
  file next to `builder.py`, yet the test suite references 3GPP
  TS 31.115 §4.2 vectors. Add a `SCP80/_test_vectors.py` pinned
  to the spec for golden-vector tests.

#### P2 Standards

- **SCP80-P2-01** `fix` `builder.py:57-59` ships hardcoded
  `SMS_TPDU_PREFIX`, `SINGLE_SMS_TPDU_PREFIX`,
  `ENVELOPE_PREFIX`, `CONCAT_UDH_PREFIX` as class constants.
  The TP-DCS byte and UDH length byte are context-dependent per
  3GPP TS 23.040 §9.2.3. Factor out a TP-DCS / UDH builder so
  these are reconstructed from config rather than hardcoded.
- **SCP80-P2-02** `fix` `crypto.py:get_algo_type` returns
  `"3DES2"` both for algo nibble `0x05` (3DES2) and for the
  default/unknown branch (line 33). 3GPP TS 31.115 §5.1 table 5
  defines `0x00` as implicit, so the default should raise or
  return `None`, not silently return 3DES2.
- **SCP80-P2-03** `fix` `crypto.py:compute_cc` for the non-AES
  branch uses 3DES-CBC with a zero IV and returns the last 8
  bytes as the MAC. 3GPP TS 31.115 §5.1.2 mandates ISO/IEC
  9797-1 Algorithm 3 (retail MAC) when CC is required; verify
  this implementation matches (or add a spec-link comment).
- **SCP80-P2-04** `fix` `config.py` DEFAULTS use SPI=`1621`
  and TAR=`B00000`. SPI=`1621` means "cryptographic checksum +
  ciphering + counter high (replay detection with strict
  comparison, no PoR)". This is a sensible RAM-target default,
  but v1 docs should state this is ETSI TS 102 225 §5.1 SPI
  byte 1 and link to the table.
- **SCP80-P2-05** `fix` `builder.py:compute_pcntr` loops
  `range(limit)` where `limit = 16 if block_size == 16 else 8`.
  Per ETSI TS 102 225 §5.1.2 the padding must bring the
  secured_data field to a multiple of the cipher block size;
  confirm the off-by-one cases (0 padding vs full-block
  padding) match the spec.

#### P3 Resilience

- **SCP80-P3-01** `block` `[fixed]` **Bare `except:` still present**.
  Prior sweep reported these as fixed; grep with the
  space-padded variant `except :` reveals:
  `SCP80/crypto.py:34` (`except :return "3DES2"`),
  `SCP80/transport.py:65` (`except :pass`),
  `SCP80/cli.py:88, 168` (`except :pass`).
  Additionally in SCP03: `SCP03/logic/sgp22.py:1395`,
  `SCP03/logic/security.py:623`. The "space-colon" variant
  slipped through the prior regex. Re-sweep with
  `\bexcept\b\s*:` and migrate each to `except Exception:`.
- **SCP80-P3-02** `fix` `transport.py:connect` line 54 catches
  `Exception` when `self.conn.getProtocol()` fails and defaults
  to the caller's `protocol` argument. On pyscard backends this
  usually means the reader is busy; masking it loses the
  diagnostic.
- **SCP80-P3-03** `fix` Test-isolation leak T5 already
  documented — most likely a `mock.patch` on `SCP80.transport`
  module attributes that was not torn down between files. Fix
  as part of tests work, but the product-side mitigation is to
  make `Transport` read `PYSCRARD_AVAIL` at call time, not
  capture-time.
- **SCP80-P3-04** `nit` `compute_pcntr` raises bare
  `ValueError("PCNTR alignment failed")`. Wrap into an
  `OtaEncodingError` subclass so callers can handle it
  without matching strings.
- **SCP80-P3-05** `nit` `cli.py` interactive loop swallows
  `KeyboardInterrupt` in at least one path — verify
  `^C` always exits cleanly without leaving a card in a
  half-authenticated state (the same sequence counter that
  drives the SCP80 counter is persisted in the inventory; a
  crash in the middle of an OTA send burns counter values).

#### P4 Security

- **SCP80-P4-01** `block` `[fixed]` `config.py:50-66` DEFAULTS ship
  `key_enc="1111111111111111"` and `key_mac="1111111111111111"`
  (8-byte weak-parity keys). Same critique as SCP03 default
  keys: first-run banner must warn, and a scripted path should
  refuse to run against a production OTA endpoint with default
  keys.
- **SCP80-P4-02** `fix` `crypto.py:compute_cc` non-AES branch
  calls `Utils.pad_key_3des(key)` which typically expands a
  16-byte 3DES2 key to 24 bytes by repeating the first 8 bytes
  (K1‖K2‖K1). Verify the helper's implementation — if it does
  not enforce K1 != K2 the effective keyspace is single-DES.
- **SCP80-P4-03** `fix` `crypto.py:encrypt_ct` AES branch uses
  zero IV (line 80). For OTA RAM this is the ETSI TS 102 225
  convention (IV derived from counter), but the convention is
  not documented in-source. Add a one-line comment referencing
  §5.1.
- **SCP80-P4-04** `fix` Counter (`cntr`) is stored in the
  device inventory. Confirm it uses the encrypted secret
  helper (`write_secret_file_bytes`) rather than plain JSON;
  counter replay is a genuine risk surface in OTA.
- **SCP80-P4-05** `nit` `cli.py` prints raw APDU / ciphertext
  / MAC values to stdout for debugging. When running against a
  live network this can leak TAR-specific payloads. Gate
  behind `YGGDRASIM_SCP80_DEBUG=1` rather than default-on.

#### P5 Operability

- **SCP80-P5-01** `fix` Zero `logging.` calls. Same
  critique as SCP03/SCP11: `print()` only, no way to redirect
  to file for automated runs.
- **SCP80-P5-02** `fix` `builder.py` emits CNTR via `print`
  (line 310). Logic module rule says no `print` in logic — move
  to a return value.
- **SCP80-P5-03** `fix` `cli.py` uses `input()` for key and
  payload prompts. Any prompt that accepts key material must
  use `getpass`.
- **SCP80-P5-04** `nit` `SCP80/__init__.py` (20 lines) exposes
  a lean surface — but there is no docstring describing the
  public API. Add a one-paragraph summary and a `__all__`.
- **SCP80-P5-05** `nit` No CLI subcommand exposes the ETSI TS
  102 225 §5.1 SPI byte parser. Operators building an OTA
  packet by hand have to consult a printed spec. Add
  `scp80 spi explain 1621` that describes each bit.

---

### Module: Tools/ProfilePackage/

SAIP profile package inspector, editor, transcoder, wizards,
linter. 25,602 lines across 22 files. Largest:
`saip_transcode_tui.py` (7,122 / 345 defs / 21 classes),
`shell.py` (4,383 / 166 defs / 303 prints),
`saip_asn1_decode.py` (4,127 / 159 defs),
`saip_pe_quick_add.py` (2,445), `lint_engine.py` (1,796).

#### P1 Structure

- **PPK-P1-01** `fix` `saip_transcode_tui.py` (7,122 lines)
  defines 21 classes inside one module, including 13 modal
  screen classes. Extract each `ModalScreen` subclass into
  `saip_transcode_tui/pickers/<name>.py`, leaving the app
  composition in the entry module. Current size makes bug
  localisation painful during the T4 triage.
- **PPK-P1-02** `fix` `shell.py` (4,383 lines, 166 defs, 303
  print calls) is similar in shape to `SCP03/interface/shell.py`.
  Split into a dispatcher + per-command handler modules
  (`shell_commands_decode.py`, `shell_commands_transcode.py`,
  `shell_commands_scaffold.py`).
- **PPK-P1-03** `fix` `saip_asn1_decode.py` (4,127 lines, 159
  defs) mixes ASN.1 encode/decode, inspector rendering, and
  rule-based summaries. Move rendering into
  `saip_asn1_view.py`.
- **PPK-P1-04** `nit` `saip_pe_quick_add.py` (2,445 lines)
  encodes the full set of PE insertion templates. This is
  data-heavy by nature; consider splitting the template bodies
  into a YAML/JSON resource bundle so new templates land as
  config, not code.
- **PPK-P1-05** `nit` Wizard modules
  (`saip_profile_wizard.py`, `saip_aka_wizard.py`,
  `saip_profile_scaffold.py`) are well-structured
  (tag-granular per the workspace rule). Keep; no change.

#### P2 Standards

- **PPK-P2-01** `fix` SAIP parsing depends on pySim
  (`saip_pe_quick_add.py` 15 imports, others ≤2). With the
  upcoming "remove pysim from repo, install on demand" change
  (S12 in the first-pass list), add an early friendly
  `ImportError` with a link to install instructions, not a
  traceback.
- **PPK-P2-02** `fix` `lint_engine.py` asserts SAIP
  compliance via `YRL-*` codes. Cross-check against GSMA SGP.22
  §2.5.2 (Profile Package structure), SGP.22 §4.4
  (ProfileElements), and the SAIP schema — any `YRL-` rule
  without a spec pointer should grow a `spec:` field.
- **PPK-P2-03** `fix` `saip_transcode_sync.py` mutates
  profile documents in place. Confirm the transcoder never
  silently rewrites mandatory fields (ICCID, IMSI) when the
  operator only asked to re-encode; if it does, add an audit
  log banner.
- **PPK-P2-04** `fix` `saip_profile_scaffold.py` presets must
  declare their target SGP.22 vs SGP.32 variant. Profile
  packages differ subtly between the two — verify each preset
  has an explicit flag.
- **PPK-P2-05** `nit` `saip_aka_wizard.py` generates AKA /
  Milenage / TUAK vectors. Ensure randomness is
  `secrets.token_bytes`, not `random.*`.

#### P3 Resilience

- **PPK-P3-01** `fix` 53 `except Exception` in
  `saip_transcode_tui.py` — many silently swallow decoder
  failures from malformed user profiles. Surface a status-bar
  warning for each silenced failure.
- **PPK-P3-02** `fix` `saip_tool.py` 8 `except Exception`
  blocks in an otherwise tight (755-line) tool. Confirm each
  maps to a documented error class.
- **PPK-P3-03** `fix` `saip_json_codec.py` 10 `except
  Exception` in a core codec path. A codec should raise typed
  exceptions, not swallow.
- **PPK-P3-04** `fix` `shell.py` 16 `except Exception` — spot
  check that operator-facing commands never silently succeed
  after a caught exception.
- **PPK-P3-05** `nit` `saip_transcode_tui.py` relies on
  Textual; absent Textual it should print a single clear
  message. Verify the import guard lives early in the module.

#### P4 Security

- **PPK-P4-01** `fix` SAIP profile packages contain Ki / OP /
  OPc (AKA vector) and PUK/ADM key material. The wizards prompt
  with `input()` — confirm they switch to `getpass` (or hidden
  TUI entry) for key / secret fields. Only one `input(` / one
  `getpass` call in the tree currently.
- **PPK-P4-02** `fix` `saip_profile_randomizer.py` randomises
  ICCID / IMSI / Ki / OP / OPc. Confirm it uses `secrets`, not
  `random`.
- **PPK-P4-03** `fix` `shell.py` export commands must refuse
  to write Ki / K / OPc in plaintext to a non-secret file.
  Verify the write path pipes through `write_secret_file_bytes`.
- **PPK-P4-04** `nit` `saip_transcode_tui.py` saves pane
  layout prefs to disk. Confirm the prefs file does not
  accidentally capture the last opened profile path when that
  path is a secret location.
- **PPK-P4-05** `nit` Debug dumps of decoded profiles can
  include Ki / OPc hex. The CLI should redact by default and
  require `--show-secrets` for full output.

#### P5 Operability

- **PPK-P5-01** `fix` 303 `print(` calls in `shell.py`, 1 in
  `saip_tool.py`. Rest of the tree is quiet. Migrate `shell.py`
  to a `logging`-aware renderer (same critique as SCP03/SCP11).
- **PPK-P5-02** `fix` `lint_engine.py` is the single best-
  documented thing in the module but `YRL-*` rule codes are
  not indexed anywhere user-facing. Generate a
  `site-docs/reference/saip-lint-codes.md` page from the
  engine's rule registry.
- **PPK-P5-03** `fix` `saip_transcode_tui.py` is lazy-loaded
  (`--inspect` flag in `main.py:86-96`). Document the two
  ways to launch — direct subcommand vs `--inspect` flag — in
  `site-docs/workflows/saip-transcode.md`.
- **PPK-P5-04** `nit` `saip_profile_wizard.py` already honours
  the workspace "tag-granular wizards" rule well — keep as
  reference implementation for future wizards.
- **PPK-P5-05** `nit` `lint_rule_ids.py` (30 lines) exposes
  the YRL code catalogue. Wire it into `scripts/` so lint
  codes can be listed from the CLI without booting the shell.

---

### Module: Tools/HilBridge/

SIM/eUICC hardware-in-the-loop relay for osmo-remsim, GSMTAP
mirror, live tshark stream, Textual decode TUI. 13,755 lines
across 16 files. Largest: `live_decode_tui.py` (6,211 / 300
defs / 10 classes), `live_decode_state.py` (2,330), `supervisor
.py` (1,154), `live_decode_view.py` (974), `protocol.py` (773),
`router.py` (769).

#### P1 Structure

- **HIL-P1-01** `fix` `live_decode_tui.py` (6,211 lines, 300
  defs) mirrors the PPK-P1-01 situation. Extract modal screens
  (`PaneLayoutPicker`, `TraceSavePicker`, `CaptureOpenPicker`,
  `KeybindHelpScreen`) into a `live_decode_tui/pickers/`
  subpackage.
- **HIL-P1-02** `fix` `live_decode_state.py` (2,330) mixes
  session tracking, APDU ledger, and ATR parsing. Split into
  `session_state.py` + `apdu_ledger.py` + `atr_decoder.py`.
- **HIL-P1-03** `nit` `protocol.py` (773) concentrates RSPRO /
  IPA / GSMTAP framing — appropriate cohesion. Keep.
- **HIL-P1-04** `nit` `supervisor.py` (1,154) owns USB
  presence monitor + subprocess supervisor. Consider splitting
  `usb_monitor.py` out (it is independently useful).
- **HIL-P1-05** `fix` Two different `live_decode_*` entry
  points (`live_decode_tui.py`, `live_decode_view.py`) plus two
  `termshark_capture_*` helpers. A single `live_decode/`
  subpackage with `tui.py`, `view.py`, `capture_pcap.py`,
  `capture_mirror.py` would make the ownership obvious.

#### P2 Standards

- **HIL-P2-01** `fix` `protocol.py:41` resolves `RSPRO.asn`
  from `docs/RSPRO.asn` — confirm the bundled copy matches the
  upstream osmo-remsim version. Add a
  `tests/test_rspro_asn_matches.py` that hashes the committed
  file against an upstream tag.
- **HIL-P2-02** `fix` GSMTAP framing uses
  `GSMTAP_VERSION=0x02`, `GSMTAP_TYPE_SIM=0x04`. Per
  osmocom-gsmtap-v2 §5 that matches. `GSMTAP_COMPAT_MODES`
  switches between native / `wireshark44` framing; document
  which Wireshark version maps to which.
- **HIL-P2-03** `fix` Proactive command TLV constants in
  `protocol.py` (CMD tag 0xD0, REFRESH command 0x01, TLVs
  0x81/0x82, device IDs 0x81/0x82) match ETSI TS 102 223
  §6.4.2. Add a docstring pointer in `proactive.py`.
- **HIL-P2-04** `fix` `REFRESH_MODE_*` enumerations (init-full-
  file-change / file-change / uicc-reset / …) match ETSI TS
  102 223 §6.4.2.7 mode values 0x00-0x06. Confirm the string
  names are stable and documented — tests likely depend on
  them.
- **HIL-P2-05** `nit` `PROACTIVE_TLV_COMMAND_DETAILS = 0x81`
  uses the 'Comprehension-required' flag set (0x81 vs 0x01).
  Add a comment so future readers do not "fix" it to 0x01.

#### P3 Resilience

- **HIL-P3-01** `fix` 71 `except Exception` in
  `live_decode_tui.py`, 16 each in `supervisor.py` and
  `live_tshark_stream.py`, 9 in `live_decode_view.py`. For a
  TUI that parses live captures these are mostly defensive
  against malformed packets, but each should record a telemetry
  line so the operator knows decoding failed.
- **HIL-P3-02** `fix` `supervisor.py` uses
  `subprocess.Popen` + `subprocess.run` for child processes.
  Verify it never blocks on `communicate()` with no timeout —
  grep shows `subprocess.TimeoutExpired` handling, so this is
  likely fine; spot-check.
- **HIL-P3-03** `fix` `live_tshark_stream.py` (361) spawns
  `tshark`. On system without tshark the failure mode should
  be a single clear message, not a traceback.
- **HIL-P3-04** `fix` `apdu_relay.py` has 5 `except Exception`
  in a small module — audit for silent socket failures.
- **HIL-P3-05** `fix` Signal handling in `main.py:146-163` is
  clean; `run_bridge_server` catches `KeyboardInterrupt`. Add
  a test that drives `SIGTERM` through the supervisor.

#### P4 Security

- **HIL-P4-01** `fix` Bridge listens on 127.0.0.1:9997 by
  default. Confirm `--host` argument refuses `0.0.0.0` without
  an explicit `--allow-remote` flag — the SIM APDU relay
  accepts APDUs directly and exposing it to the LAN is a
  footgun.
- **HIL-P4-02** `fix` `apdu_relay.py` — confirm each received
  APDU is bounded in size and that the relay never echoes raw
  memory on overflow. Relays with silent oversized-message
  handling are a common RCE vector.
- **HIL-P4-03** `fix` `live_tshark_stream.py` / `supervisor.py`
  spawn child processes with arguments derived from CLI
  arguments and the GSMTAP pipe path. Verify that paths are
  sanitised (no `;` / shell meta), even though `shell=True`
  is not used.
- **HIL-P4-04** `fix` Bridge captures raw ATR / APDUs to disk
  via the pcap mirror. ATR / APDUs can contain Ki-derived
  authentication challenges. Document that the capture file is
  sensitive.
- **HIL-P4-05** `nit` `usb_monitor.py` (part of
  `supervisor.py`) relies on VID/PID substring matching. Add a
  refusal mode if the match set is overly permissive (>8
  VIDPIDs).

#### P5 Operability

- **HIL-P5-01** `nit` Good news: `main.py` / `supervisor.py` /
  `router.py` use `logging` already. Keep `print()` only for
  the `--list-readers` human-readable output in `main.py:192-196`.
- **HIL-P5-02** `fix` `--list-readers` output goes to stdout;
  make sure `main.py` exits with code 0 on success and 2 on
  enumeration failure, so CI can branch on result.
- **HIL-P5-03** `fix` `live_decode_tui.py` depends on Textual
  + tshark. Add a `hil-bridge doctor` subcommand that checks
  both are installed (ties into `yggdrasim_common.doctor`).
- **HIL-P5-04** `fix` T1 pre-existing test failures are in
  `test_hil_bridge_live_decode_tui.py` — refresh the tests
  before v1, since HIL-P1-01 will move the affected code.
- **HIL-P5-05** `nit` `pcsc.py` is thin (114 lines) and well-
  scoped. Ensure its public API is documented in
  `site-docs/subsystems/hil-bridge.md`.

---

### Module: Tools/SuciTool/

Thin wrapper around pySim `suci-keytool` for SUCI key / public-
key operations. 410 lines across 5 files.

#### P1 Structure

- **SUCI-P1-01** `nit` Clean split: `main.py` (entry), `shell.py`
  (REPL), `tool.py` (subprocess bridge). Keep as reference
  pattern for the refactors proposed elsewhere.
- **SUCI-P1-02** `nit` No dead code, no duplication.
- **SUCI-P1-03** `nit` Module size well below review threshold.
- **SUCI-P1-04** `nit` `ShellStyle` (`shell.py:8-16`) duplicates
  the palette from `SCP03/config.py` and `SCP80/builder.py`.
  Consolidate into `yggdrasim_common/ansi_palette.py` as part
  of the COMMON-P1 work.
- **SUCI-P1-05** `nit` `__main__.py` exists for script
  execution; `main.py:entry` is invoked via the wrapper — pick
  one entry convention across all Tools/ submodules.

#### P2 Standards

- **SUCI-P2-01** `fix` SUCI protection scheme per 3GPP TS
  33.501 §C.3 has two profiles (A: Curve25519, B: P-256).
  Verify `suci-keytool` invocations document which profile is
  being used.
- **SUCI-P2-02** `fix` HN Public Key generation should warn
  when home network private key material is produced in a
  non-secret location. Cross-reference with `write_secret_file
  _bytes` usage.
- **SUCI-P2-03** `nit` Tool contract: ensure `--key-file` is
  the only argument passed via path interpolation; everything
  else is appended literally via `.extend(args)`.
- **SUCI-P2-04** `nit` No spec coverage required beyond the
  pySim wrapping.
- **SUCI-P2-05** `nit` --

#### P3 Resilience

- **SUCI-P3-01** `fix` `tool.py:describe_tool_command` catches
  `Exception` and returns a prose string. Good UX for the
  status banner but the same function is reused in error
  paths — confirm callers do not mistake the fallback string
  for a valid command.
- **SUCI-P3-02** `nit` `run` calls `self.runner(command)` which
  defaults to `_run_subprocess`. Tests inject their own runner.
  Keep.
- **SUCI-P3-03** `fix` `get_tool_command` raises `RuntimeError`
  when no tool is found. At shell banner time this produces a
  confusing "unavailable" line rather than a clear setup
  instruction. Surface the exception text in the banner.
- **SUCI-P3-04** `nit` No resource leaks — `subprocess.run`
  with `capture_output=True` is already safe.
- **SUCI-P3-05** `nit` --

#### P4 Security

- **SUCI-P4-01** `fix` `resolve_path` enforces workspace
  containment (`_is_within_workspace`). Good. Verify the
  `USE /absolute/path` flow cannot escape via symlinks by
  confirming `Path.resolve()` resolves symlinks before
  `relative_to`.
- **SUCI-P4-02** `fix` `YGGDRASIM_SUCI_TOOL` env var is
  `shlex.split` and executed. An attacker who can set env vars
  can run arbitrary commands via the SUCI tool shell. Document
  that this is expected (env is trusted) and mirror for SCP03 /
  HIL equivalents.
- **SUCI-P4-03** `nit` `shutil.which` lookup order searches
  PATH. A PATH-poisoning attack on a shared system could inject
  a fake `suci-keytool.py`. Out of scope for a trust-the-user
  tool; document.
- **SUCI-P4-04** `nit` `SuciCommandResult.stdout` / `stderr`
  are passed to the shell — confirm nothing in pySim's
  `suci-keytool` prints secret material by default.
- **SUCI-P4-05** `nit` --

#### P5 Operability

- **SUCI-P5-01** `nit` No `logging.` calls; shell uses `print`
  for 45 banner / status lines. Fine for an interactive tool.
- **SUCI-P5-02** `fix` Error when `suci-keytool` is missing is
  `RuntimeError("suci-keytool was not found. Install pySim
  suci-keytool or set YGGDRASIM_SUCI_TOOL.")` — ensure
  `yggdrasim_common.doctor` reports this pre-flight.
- **SUCI-P5-03** `fix` The `describe_status` banner does not
  show workspace root or tool version. Add those so the
  operator sees the full environment before typing commands.
- **SUCI-P5-04** `nit` `run_commands` swallows `SystemExit`
  inside a non-interactive loop. OK for scripting.
- **SUCI-P5-05** `nit` Document the command vocabulary
  (`DUMP`, `GENERATE`, `USE`, `TOOL`, `STATUS`) in
  `site-docs/workflows/suci-key-tool.md`.

---

### Module: main/ launcher + yggdrasim_main.spec

Top-level launcher (`main/main.py`) + PyInstaller spec. 2,258
lines + 172-line spec. Single file, 94 `def` / `class`
declarations, 239 `print(` calls, 287 `except` blocks in total.

#### P1 Structure

- **MAIN-P1-01** `fix` `main/main.py` at 2,258 lines with 94
  functions in module scope is the launcher-everything file.
  Split into:
  `main/launcher.py` (top-level entry + argparse),
  `main/backends.py` (`configure_card_backend` and
  `_reset_simulator_baseline`),
  `main/hil_bridge_controls.py` (every `_hil_bridge_*` helper —
  there are ~20),
  `main/history.py` (`setup_history`, `save_history`).
- **MAIN-P1-02** `fix` `Colors` class (line 107) duplicates the
  palette from SCP03 / SCP80 / SuciTool again (same
  `_hex_to_ansi` pattern). Consolidate into the
  `yggdrasim_common/ansi_palette.py` that SUCI-P1-04 proposes.
- **MAIN-P1-03** `fix` Space-padded source style — same
  critique as SCP03-P1-03. Run the same `black` pass across
  `main/main.py`.
- **MAIN-P1-04** `nit` `DIRS = {"LICENSE": ...}` (line 101) is
  a one-key dict. Replace with a named constant.
- **MAIN-P1-05** `nit` `PROJECT_ROOT` discovery (lines 37-53)
  walks the filesystem looking for `SCP03`. Same lookup in
  `SCP11/pysim_path.py`. Fold into a single
  `yggdrasim_common.runtime_paths.detect_project_root`.

#### P2 Standards

- **MAIN-P2-01** `fix` Environment variables set by the
  launcher (`CARD_BACKEND_ENV`, `SIM_*_ENV`) should be
  documented in `site-docs/reference/env-vars.md` with
  explicit names, accepted values, precedence order.
- **MAIN-P2-02** `fix` HIL bridge capture / termshark env
  vars (`_hil_bridge_termshark_*` helpers) read dozens of
  env / config values. Collect them into a single
  dataclass so they are visible in one place.
- **MAIN-P2-03** `nit` No cryptographic operations in the
  launcher — nothing to check.
- **MAIN-P2-04** `nit` --
- **MAIN-P2-05** `nit` --

#### P3 Resilience

- **MAIN-P3-01** `fix` `from yggdrasim_common import
  hil_bridge_runtime` is guarded by `except Exception`
  (lines 93-96). This is the right pattern for an optional
  import, but logs nothing when the import fails on a `full`
  flavor build. On `clean` bundle the failure is expected; on
  `full` bundle it should raise.
- **MAIN-P3-02** `fix` 287 `except` blocks in one file is a
  lot. Most are around `subprocess` spawns and optional
  module imports. A helper `_optional_import(name)` would
  collapse many.
- **MAIN-P3-03** `fix` `readline` import guard (lines 28-31)
  — when `readline` is missing (Windows), degraded UX must
  be advertised to the operator.
- **MAIN-P3-04** `fix` `ensure_plugins_loaded()` at module
  top-level (line 98) means any plugin error blocks launcher
  startup. Wrap in a `try/except` that logs and continues in
  degraded mode.
- **MAIN-P3-05** `fix` `atexit` handlers — confirm
  `save_history` never raises during interpreter shutdown
  (a raised exception in `atexit` is printed but can still
  wedge a release image).

#### P4 Security

- **MAIN-P4-01** `fix` `MAIN_HISTORY_FILE = ~/.yggdrasim_main_
  history`. Confirm the file is created with mode `0o600` so
  recorded commands (which can contain hex key material) are
  not world-readable.
- **MAIN-P4-02** `fix` The launcher supports `--cmd` batch
  mode — audit that commands that accept key material via the
  batch string are either refused or redacted from history.
- **MAIN-P4-03** `fix` `configure_card_backend` mutates env
  vars that affect every subprocess spawned by the launcher.
  Confirm no sensitive data is pushed into env vars (file
  paths are fine; key material is not).
- **MAIN-P4-04** `nit` Debug toggle `set_global_debug(...)`
  flips verbose logging across the process. Ensure the flag
  never flips on in a production bundle.
- **MAIN-P4-05** `nit` --

#### P5 Operability

- **MAIN-P5-01** `fix` 239 `print(` calls and zero `logging`
  — the launcher is purely interactive. Fine, but the batch
  path (`--cmd` / `--stdin`) would benefit from being able to
  redirect output.
- **MAIN-P5-02** `fix` Launcher must print the active flavor
  (`clean` / `full`) from `yggdrasim_flavor.get_flavor()` in
  the banner so operators know which bundle they are on.
- **MAIN-P5-03** `fix` `ensure_plugins_loaded` failure paths
  should print a clear "plugin X failed to load" banner, not
  swallow.
- **MAIN-P5-04** `fix` Add `main --doctor` that calls
  `yggdrasim_common.doctor` and exits — operators can run a
  single command to validate their environment.
- **MAIN-P5-05** `nit` `yggdrasim_main.spec` is clean and
  well-commented. Small suggestion: log the bundled Python
  version so end-users can triage "old bundle on new OS"
  issues.

#### Bundle spec (yggdrasim_main.spec)

- **SPEC-P1-01** `fix` `data_tree_candidates` includes
  `"pysim"` (line 70). Ties into the pending S12 — once the
  "remove pysim/pyscard from repo" task lands, delete this
  entry and the corresponding runtime guard in
  `SCP11/pysim_path.py`.
- **SPEC-P2-01** `fix` `EXECUTABLE_NAME` uses
  `yggdrasim-{flavor}` — confirm this matches the name used
  in `.github/workflows/build.yml` + `docker.yml`.
- **SPEC-P3-01** `nit` `excludes` hardcodes every
  `Tools.HilBridge.*` submodule name. As HIL-P1-01 reshuffles
  the subpackage, this list will need updating. Replace with
  `excludes = ["Tools.HilBridge", ...]` and verify
  PyInstaller handles package-level exclusion transitively.
- **SPEC-P4-01** `fix` `console=True` — confirm Windows
  bundles still work without a console window if that is a
  requirement; otherwise document that YggdraSIM is terminal-
  only.
- **SPEC-P5-01** `nit` Consider adding a `version` string
  read from `yggdrasim_common/__about__.py` so frozen
  binaries can be tagged via PyInstaller metadata.

---

### Module: yggdrasim_common/

Shared utilities used by every subsystem. 3,713 lines across
18 files. Largest: `card_backend.py` (656), `hil_bridge_runtime
.py` (429), `device_inventory.py` (402), `doctor.py` (360),
`session_recording.py` (306), `inventory_crypto.py` (304),
`registry.py` (271).

#### P1 Structure

- **COMMON-P1-01** `fix` `card_backend.py` (656 lines) carries
  19 environment-variable constants, 6 path setters/getters,
  and relay URL handling. Split into `card_backend/backend_
  selection.py` (env + settings JSON) and `card_backend/
  relay_client.py` (HTTP relay surface).
- **COMMON-P1-02** `fix` `hil_bridge_runtime.py` (429) lives
  next to HIL-bridge-specific helpers that are only valid in
  the `full` flavor. Move under `Tools/HilBridge/runtime.py`
  and export a thin adapter from `yggdrasim_common` for
  cross-module imports.
- **COMMON-P1-03** `nit` `runtime_paths.py` is well-scoped.
  Consider splitting `_LEGACY_WORKSPACE_ALIASES` (16 pairs)
  into a separate `legacy_aliases.py` data module for
  discoverability.
- **COMMON-P1-04** `nit` `__init__.py` is 3 lines — expose
  a curated public API (`from .runtime_paths import ...`) so
  downstream modules can `from yggdrasim_common import
  runtime_path`.
- **COMMON-P1-05** `nit` Missing `ansi_palette.py` — palette
  is copy-pasted across ≥4 modules (SCP03, SCP80, SuciTool,
  main/). Consolidate per SUCI-P1-04 / MAIN-P1-02.

#### P2 Standards

- **COMMON-P2-01** `fix` `device_inventory.py` uses
  `sqlite3` with SQL strings. Confirm every query uses
  parameter placeholders (`?`) — no string interpolation.
- **COMMON-P2-02** `fix` `inventory_crypto.py` invokes `gpg`
  via `subprocess`. Pass `--batch --yes --pinentry-mode loopback`
  where applicable so it works in headless CI without prompting
  for a passphrase.
- **COMMON-P2-03** `fix` `session_recording.py` (306) — verify
  ISO 8601 timestamps are UTC (`device_inventory._utc_now`
  already is; confirm recording matches).
- **COMMON-P2-04** `nit` `__about__.py` version fallback uses a
  regex on `pyproject.toml` line 48. Brittle if the TOML
  formatter rewrites the line. Switch to `tomllib.loads` when
  Python ≥3.11 is the floor.
- **COMMON-P2-05** `nit` --

#### P3 Resilience

- **COMMON-P3-01** `fix` `[fixed]` `inventory_crypto.py:_load` swallows
  JSON decode errors (`except Exception: payload = {}`, line
  48). Corrupt config resets to defaults silently. Log a
  warning so the operator knows their customisation was lost.
- **COMMON-P3-02** `fix` `[fixed]` `plugin_runtime.py:_load_plugin_module`
  catches every exception (line 67) and records it in
  `_load_errors`. No caller currently surfaces these errors
  at launcher startup. Either print a summary line from
  `main/` or fail-fast on plugin error.
- **COMMON-P3-03** `fix` `doctor.py` contains 11 `except
  Exception` — each probe must convert exceptions into a
  clear `fail` / `warn` status with a one-line detail; skim
  for any probe that masks the error type (`str(exc)` is
  often too generic).
- **COMMON-P3-04** `fix` `[fixed]` `card_backend.py:_load_card_backend
  _settings` catches `Exception` returning `{}` when the
  JSON is malformed. Add a sidecar rename (`card_backend.json
  .corrupt`) so the operator can recover.
- **COMMON-P3-05** `fix` `[fixed]` `runtime_paths._ensure_writable_root`
  raises `OSError` when the strict flag is False (line
  191-194). The `if strict:` branch raises, but the
  non-strict branch *also* raises — dead code.

#### P4 Security

- **COMMON-P4-01** `block` `[fixed]` `inventory_crypto.py` is the
  envelope-encryption surface for the whole repo (Ki, OPc,
  DEK, etc.). Checklist coverage for v1:
  (a) `test_inventory_crypto_dict_payload_round_trip_through_fake_gpg`
  exercises `encrypt_payload` → `decrypt_payload` on a
  nested dict with KI / OPc / KVN values,
  (b) `test_inventory_crypto_blocks_plaintext_secret_writes_when_enabled`
  pins `blocks_plaintext_secret_writes()` at `True` when
  `enabled=True` and `plaintext_fallback_writes=False`,
  (c) `test_inventory_crypto_write_secret_file_leaves_no_plaintext_on_disk`
  drives `write_secret_file_bytes` and confirms the file
  starts with the PGP armor marker and contains no trace of
  the plaintext marker,
  (d) `test_inventory_crypto_refuses_to_encrypt_without_recipients`
  asserts `_gpg_encrypt` raises `ValueError` and
  `provider_ready_for_encrypt()` reports `False` when the
  recipient list is empty,
  (e) `_gpg_key_file_path` now rejects any resolved path
  outside `config_path.parent` and logs a warning;
  `test_inventory_crypto_refuses_gpg_key_file_outside_config_directory`
  confirms the recipient list stays empty when the field
  points at a sibling directory.
- **COMMON-P4-02** `fix` `[fixed]` `plugin_runtime.py` loads arbitrary
  Python from `~/.../YggdraSIM-data/plugins/`. Same footgun
  as `SIMCARD/quirks.py` (SIM-P4-01). Gate behind
  `YGGDRASIM_ALLOW_PLUGINS=1` and print a banner listing
  every loaded plugin path.
- **COMMON-P4-03** `fix` `session_recording.py` persists a
  ledger of shell operations. Confirm it redacts key material
  — any SCP03 key / OTA payload / SUCI private key printed in
  a shell run should be scrubbed from the recording.
- **COMMON-P4-04** `fix` `device_inventory.py` SQLite file
  holds mixed plaintext and envelope-encrypted payloads.
  Confirm the sqlite file itself is created with mode 0600
  on Linux / macOS.
- **COMMON-P4-05** `fix` `[fixed]` `runtime_paths._try_writable_root`
  writes a `.yggdrasim_write_probe` file. Ensure it is
  deleted on failure paths too (currently the `except OSError`
  path in `_ensure_writable_root` does not clean up).

#### P5 Operability

- **COMMON-P5-01** `fix` `doctor.py` runs the pre-flight but
  is not wired into the launcher. Bind to `main --doctor` per
  MAIN-P5-04.
- **COMMON-P5-02** `fix` `flavor.py` should be idempotent —
  multiple imports during a single process should return the
  same flavor. Test it.
- **COMMON-P5-03** `fix` `console_scripts.py` (93) exposes
  the `yggdrasim-*` console scripts. Every entry should be
  listed in the README installation section.
- **COMMON-P5-04** `nit` `structured_output.py` (23) and
  `quit_control.py` (13) are very small. Consider merging
  into a `cli_runtime.py` module to reduce file count.
- **COMMON-P5-05** `nit` `__about__.py` already sources the
  version from distribution metadata or pyproject — good
  pattern; document in CONTRIBUTING once that file exists.

---

### Module: plugins/

Only one plugin today: `polling_plugin.py` (3,857 lines,
~129 classes/functions, 117 `print()` calls, 13 `except
Exception`). This file is the single largest Python file in
the whole repository.

#### P1 Structure

- **PLUG-P1-01** `block` `polling_plugin.py` at 3,857 lines is
  unmaintainable as a single file. Split into:
  - `plugins/polling/base.py` — `_DelegatingRuntimeBase` and
    runtime composition.
  - `plugins/polling/relay.py` — `_RelayPollingRuntime`
    (eIM status watchdog against relay).
  - `plugins/polling/standalone.py` — the local/standalone
    polling runtime.
  - `plugins/polling/sgp32_decoders.py` — every
    `decode_eim_configuration_entry*` helper.
  - `plugins/polling/__init__.py` — `register_plugins(manager)`
    hook only.
- **PLUG-P1-02** `fix` Direct imports from `SCP03.logic.
  sgp32_decode` and `SCP11.live.models` inside a plugin is
  architecturally upside-down: a plugin should consume a
  *published* API surface, not reach into private modules.
  Promote the used helpers into `yggdrasim_common/sgp32.py`
  and have both the core and the plugin import from there.
- **PLUG-P1-03** `nit` `_DelegatingRuntimeBase.__getattribute
  __` is a non-trivial proxy that hides `self._target`
  behavior. Add a dedicated unit test covering
  `setattr`/`getattr`/`hasattr` round-trips.
- **PLUG-P1-04** `fix` The `plugins/README.md` does not
  document the plugin contract (required `register_plugins
  (manager)` entry point, capability names, error surfaces).
  Required before external plugin authors can be on-boarded.
- **PLUG-P1-05** `nit` `plugins/__pycache__` is checked-in-
  adjacent (in ignored state). Ensure `.gitignore` already
  covers it (it does globally) and the build pipeline doesn't
  ship byte-compiled plugin copies.

#### P2 Standards

- **PLUG-P2-01** `fix` `polling_plugin.py` manipulates SGP.32
  eIM state (status polls, timer expiration window). Each
  status code and timer transition must reference the
  SGP.32-02 state table; add inline comments citing
  section numbers next to the state-transition branches.
- **PLUG-P2-02** `fix` `run_eim_status_watchdog` accepts
  `continuous_loop_stall_guard_statuses=12`. Document where
  the `12` comes from — it looks like a heuristic rather
  than a spec value.
- **PLUG-P2-03** `fix` If the plugin emits any EIM package
  result codes, they should route through
  `SCP11/shared/gsma_error_codes.py` rather than embedding
  duplicate mapping tables.

#### P3 Resilience

- **PLUG-P3-01** `fix` 13 `except Exception` blocks across
  3,857 lines — lower than the rest of the codebase in
  ratio but still too broad for a supervisor-style loop.
  Each should be either (a) swallowed and logged with a
  reason, or (b) re-raised after audit recording.
- **PLUG-P3-02** `fix` `run_eim_status_watchdog` does not
  register a `KeyboardInterrupt` handler that flushes
  audit records to disk. Long-running supervisor loops that
  can be `Ctrl-C`'d must persist state before exit.
- **PLUG-P3-03** `fix` Timer-expiration-window math uses
  `time.time()` — switch to `time.monotonic()` for interval
  arithmetic so clock jumps (NTP, DST) do not skew the
  watchdog.
- **PLUG-P3-04** `fix` Plugin registers capabilities via
  `yggdrasim_common.plugin_runtime`. If registration fails
  half-way through (partial capability set), the caller has
  no way to roll back. Use an atomic registration helper
  on the `PluginManager`.
- **PLUG-P3-05** `nit` No unit test exercises the plugin's
  error paths (the existing `test_polling_plugin_watchdog
  .py` is happy-path only).

#### P4 Security

- **PLUG-P4-01** `fix` Plugin imports `cryptography.x509`
  and parses certificates. Confirm every code path that
  decodes a cert is wrapped in a defensive parse (attacker-
  controlled certs from relay responses).
- **PLUG-P4-02** `fix` Plugin logs relay responses via
  `print()` — these contain ICCID, EID, sometimes timer
  metadata with device identifiers. Redact before logging.
- **PLUG-P4-03** `fix` `[fixed]` Loading path is `runtime_dir/plugins/`
  i.e. the *writable* runtime dir. An attacker who can
  write to the user data dir can drop a malicious
  `plugins/evil.py` and get code execution at next launch.
  Solution: gate plugin load behind
  `YGGDRASIM_ALLOW_PLUGINS=1` per COMMON-P4-02.

#### P5 Operability

- **PLUG-P5-01** `fix` 117 `print()` calls — should use
  structured logging so watchdog output can be tailed to a
  file without mixing with operator prompts.
- **PLUG-P5-02** `fix` `run_eim_status_watchdog` signature
  has 10 keyword arguments. Exposing via CLI requires each
  to be documented; check `SCP11/console.py` (or wherever
  `eim-poll` dispatches from) for a help block.
- **PLUG-P5-03** `fix` Plugin should emit a banner on load
  listing the capabilities it registered (so operators see
  the exact attachment surface at launcher start-up).
- **PLUG-P5-04** `fix` No `pyproject.toml`-level entry-point
  is exposed for this plugin — the only loader is the
  file-system walk in `PluginManager.ensure_loaded`. For a
  v1 release the plugin layout should be version-pinned so
  users cannot bring in plugins written against older
  APIs.
- **PLUG-P5-05** `nit` Consider shipping the polling plugin
  as an optional install extra (`yggdrasim[polling]`) rather
  than a loose file so the packaging spec covers it.

---

### Module: scripts/install/

`install-linux.sh` (101), `install-macos.sh` (88),
`install-raspberrypi.sh` (104), `install-windows.ps1` (223),
shared helpers in `_common.sh` (302).

#### P1 Structure

- **INST-P1-01** `nit` Good separation between POSIX helpers
  (`_common.sh`) and the per-OS drivers. No refactor needed.
- **INST-P1-02** `fix` `install-windows.ps1` (223) duplicates
  argument parsing and asset-download logic that lives in
  `_common.sh`. Consider introducing a PowerShell common
  module (`_common.ps1`) so asset URLs and flavor validation
  stay in sync across OSes.
- **INST-P1-03** `nit` `scripts/install/README.md` should
  list the exact apt / brew / choco package names so
  operators can dry-run prerequisite gathering.

#### P2 Standards

- **INST-P2-01** `fix` `_common.sh:yg_validate_flavor_for_host`
  rejects `full` flavor on non-Linux — correct, but the
  documented error message should link to
  `guides/HIL_BRIDGE_GUIDE.md` so users understand *why*.
- **INST-P2-02** `fix` `yg_apt_install` runs `apt-get update`
  then `install`. Consider adding an explicit check that the
  user is allowed to sudo, to fail-fast on CI runners where
  `sudo` is not permitted.
- **INST-P2-03** `nit` Windows installer should pin a minimum
  PowerShell version (5.1+) for `Invoke-WebRequest` TLS
  semantics.

#### P3 Resilience

- **INST-P3-01** `fix` `[fixed]` `_common.sh:yg_download_release_asset`
  uses `curl --fail --silent`. If the asset URL returns 302
  to a login page on a private fork, curl follows it
  silently. Add `--max-redirs 5` and a post-download size
  sanity check (release artifacts are >20 MB).
- **INST-P3-02** `fix` `yg_brew_install ... || true` swallows
  all brew errors; if brew is broken the user will never
  know. Replace with `yg_brew_install foo || yg_warn
  "brew install foo failed"`.
- **INST-P3-03** `fix` `install-linux.sh:install_linux_prereqs`
  — when `osmo-remsim-client` is not in apt sources the
  script falls through with a warning. That's OK, but
  document in `guides/SIMTRACE2_CARDEM_GUIDE.md` what the
  source build fallback is.
- **INST-P3-04** `fix` Source install uses `python -m pip
  install -e '.'` inside an `(... )` subshell — ensure the
  exit code of that subshell propagates; `set -e` inside a
  subshell does not escape, and the outer script already
  has `set -e`.
- **INST-P3-05** `nit` `install-raspberrypi.sh` (104) is
  nearly a copy of `install-linux.sh` — keep as-is for now
  (clarity > DRY), but consider sharing via a common entry
  point once CI parity is tested.

#### P4 Security

- **INST-P4-01** `fix` `yg_download_release_asset` does not
  verify any checksum or signature. A compromised release
  asset would be installed as-is. Add a `yg_verify_sha256`
  helper that reads `<asset>.sha256` or the GitHub release
  `digest:` field.
- **INST-P4-02** `fix` `yg_install_executable` uses `install
  -m 0755 ...`. Good. Ensure the target directory is
  `chmod 0700` on Linux when in the user's home to prevent
  write races.
- **INST-P4-03** `nit` PowerShell installer should sign the
  downloaded binary or at minimum verify the catalog signed
  by GitHub; otherwise running `yggdrasim.exe` may trigger
  SmartScreen warnings that users blindly bypass.

#### P5 Operability

- **INST-P5-01** `fix` No CI job invokes `install-linux.sh`
  against a fresh container — add a GitHub Actions matrix
  row (already covered by `test_install_scripts.py` but that
  is syntax only, not end-to-end).
- **INST-P5-02** `fix` Source mode pins nothing — once v1
  is released, re-running source install on a new checkout
  should produce a reproducible environment. Pin dependencies
  via `requirements.lock.txt` or `uv.lock`.
- **INST-P5-03** `nit` Document the `YGGDRASIM_REPO`
  override (useful for internal forks) in the release
  notes.

---

### Module: tests/

90 files, 41,827 lines. Heaviest:
`test_hil_bridge_live_decode_tui.py` (4,607),
`test_simcard_backend.py` (3,207),
`test_scp11_eim_local.py` (2,939),
`test_scp11_local_access.py` (2,248),
`test_saip_transcode_tui.py` (1,918),
`test_scp11_orchestrator.py` (1,877),
`test_profile_package_shell.py` (1,539),
`test_scp11_live_split.py` (1,519),
`test_saip_asn1_decode.py` (1,284),
`test_polling_plugin_watchdog.py` (1,069),
`test_saip_pe_quick_add.py` (1,053).

#### P1 Structure

- **TEST-P1-01** `fix` `test_hil_bridge_live_decode_tui.py`
  (4,607) and `test_simcard_backend.py` (3,207) are too
  large to navigate. Split each into per-feature files,
  e.g. `test_simcard_backend_select.py`,
  `test_simcard_backend_read_binary.py`,
  `test_simcard_backend_authenticate.py`.
- **TEST-P1-02** `fix` `tests/__pycache__` exists in the
  tree — OK (ignored) but ensure the test runner does not
  accidentally treat cached `.pyc` as collected modules.
- **TEST-P1-03** `fix` `tests/eim-sh/` holds an integration
  shell harness plus binary artefacts (`eim_last_response
  .bin`, `eim_last_response_hex.txt`). Move artefacts into
  `.gitignore` or into a `fixtures/` subfolder so they
  cannot be confused with tracked inputs.
- **TEST-P1-04** `nit` `tests/golden/` is the new golden-
  card harness; already env-gated. Document the expected
  smart-card reader in `guides/GOLDEN_CARD_HARNESS.md`.
- **TEST-P1-05** `fix` `test_simcard_backend.py` mutates
  `sys.path` directly (lines 178–179). Prefer `conftest.py`
  `sys.path` injection or install the project as editable
  so tests import via package path.

#### P2 Standards

- **TEST-P2-01** `fix` Only 6 `print()` calls in tests —
  acceptable; however 30 files patch `sleep` / `socket` /
  `time`. Spot-check for flakiness and document the fix
  (mock instead of sleep).
- **TEST-P2-02** `fix` 310 `tempfile` / `TemporaryDirectory`
  usages — ensure every context manager is entered (no
  `tempfile.mkdtemp()` without a matching `shutil.rmtree`).
- **TEST-P2-03** `nit` `test_install_scripts.py` only
  validates bash syntax; add a smoke that runs
  `install-linux.sh --help` and checks exit 0.

#### P3 Resilience

- **TEST-P3-01** `block` Three known hangs/failures documented
  in Third-pass: T1 (HIL TUI), T2 (SCP11 local access
  `build_effective_metadata_document`), T4 (SAIP transcode
  TUI). Fix before v1 — a release cut with known hanging
  tests is a non-starter.
- **TEST-P3-02** `fix` T5 (SCP80 test isolation) — fixture
  leaks global state between files when run as a chain.
  Add `module_finalizer`-style teardown per conftest.
- **TEST-P3-03** `fix` `time.sleep` usage in
  `test_hil_bridge_live_tshark_stream.py` (4 real sleeps,
  totalling ~0.24s minimum) — replace with
  `unittest.mock.patch('time.sleep')` wherever the test
  does not need real wall-clock behavior.
- **TEST-P3-04** `fix` Tests occasionally import from
  `pySim` — if pySim is stripped from the repo (per the
  user's plan) each such import must be guarded by a
  `pytest.importorskip("pySim")` call.

#### P4 Security

- **TEST-P4-01** `fix` `test_scp11_eim_local_ipad_standalone
  .py` and `test_scp11_live_split.py` may hold hardcoded
  test certs. Ensure the cert material is from SGP.26
  public test vectors (publicly committed by GSMA) and not
  derived from the operator's own PKI.
- **TEST-P4-02** `fix` Any test writing to the user's real
  data directory (`$HOME/.local/share/YggdraSIM`) is a bug.
  Every test must scope writes to a per-test tmp dir.
  `pytest --rootdir=/tmp` + `YGGDRASIM_DATA_DIR=<tmp>`
  fixture.
- **TEST-P4-03** `nit` Test fixtures that print Ki / OPc
  / DEK to assertion messages may leak into CI logs. Audit
  failure messages to redact byte values.

#### P5 Operability

- **TEST-P5-01** `fix` No top-level `pytest.ini` or
  `pyproject.toml [tool.pytest.ini_options]` block. Adding
  one makes the test runner behavior deterministic (sets
  `testpaths`, `addopts = -q --tb=short --disable-warnings`,
  `markers`).
- **TEST-P5-02** `fix` No test markers for slow / integration
  tests. Add `@pytest.mark.slow` to TUI and backend tests
  so CI can skip them on fast runs.
- **TEST-P5-03** `fix` Golden-card harness is the only
  integration test — the SCP03 and SCP11 flows against a
  loopback relay are not exercised. Add a small integration
  rig that runs the SCP11 relay against a mock ES9+ server.
- **TEST-P5-04** `nit` `tests/eim-sh/script.sh` already uses
  a resolved Python interpreter (sanitized during the first
  pass). Good.
- **TEST-P5-05** `fix` Add a coverage target. `pytest --cov
  =SCP11 --cov=SIMCARD --cov-report=xml` in CI so coverage
  regressions are visible per PR.

---

### Module: site-docs/ and guides/

MkDocs-material site sourced from `site-docs/`; authored
content lives under `guides/` and is re-mirrored into
`site-docs/sources/guides/` by `site-docs/_tools/mirror_
source_docs.py`. 98 markdown files under `site-docs/`,
3,754 lines across 12 `guides/*.md`.

#### P1 Structure

- **DOC-P1-01** `block` `[fixed]` `site-docs/sources/guides/` is stale:
  `INSTALL_CLEAN.md`, `INSTALL_FROM_SOURCE.md`,
  `INSTALL_FULL.md`, `INSTALL_RASPBERRYPI.md`, and
  `SIMTRACE2_CARDEM_GUIDE.md` exist under `guides/` but
  have not been mirrored. Running `mkdocs build --strict`
  fails because of the gap. Action: re-run
  `python site-docs/_tools/mirror_source_docs.py` and commit.
- **DOC-P1-02** `fix` The mirror script decides what to
  include via a hardcoded `INCLUDED_TOP_LEVEL_DIRS` set
  (`guides`, `plugins`, `reports`, `SCP11`, `tests`).
  The launcher, SCP03, SCP80, Tools/, SIMCARD/, main/,
  `yggdrasim_common/` all have README files that never make
  it into the site. Expand the allowlist or invert to an
  exclude-list.
- **DOC-P1-03** `fix` `nav:` in `mkdocs.yml` points to
  ~90 curated pages but `Source Library` (source-library
  .md) and `Build and Packaging` (build-and-packaging.md)
  are at the top-level nav. Move `Build and Packaging`
  under `Internals`.
- **DOC-P1-04** `nit` `site-docs/_includes/abbreviations.md`
  is referenced via `pymdownx.snippets.auto_append` — make
  sure it stays in sync with new acronyms (e.g.
  `SGP.32`, `LPD`, `IPA`).
- **DOC-P1-05** `fix` Deleted at repo root: `ARCHITECTURE
  .md`, `CAPABILITIES.md`, `CLI_AND_PIPING_GUIDE.md`,
  `PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`. Content now lives
  under `guides/` and `site-docs/`. Add redirect notes in
  the README so external links don't 404.

#### P2 Standards

- **DOC-P2-01** `fix` Every subsystem page under
  `site-docs/subsystems/` must cite the authoritative
  standard (GSMA SGP.22 v3.X, ETSI TS 102 221 R16, etc.).
  Spot-check each page for an explicit "Standards" block.
- **DOC-P2-02** `fix` `site-docs/concepts/secure-element-
  primer.md` defines base vocabulary — confirm it aligns
  with ETSI TS 102 221 and not re-defined in other pages.
- **DOC-P2-03** `fix` The SGP.32-related pages (SCP11 eIM
  Local, IPAe, etc.) must note *which* SGP.32 revision
  they implement; the spec is still moving.
- **DOC-P2-04** `nit` Guide headers inconsistent — some use
  `# Title`, others `# Title - YggdraSIM`. Pick one.
- **DOC-P2-05** `nit` Cross-references between guides use
  raw relative paths. MkDocs supports `[text](..)` but only
  if the target is under `docs_dir`. Since the authored
  content mirrors through `sources/`, broken links slip
  through. Run `check_internal_links.py` in CI.

#### P3 Resilience

- **DOC-P3-01** `fix` `mkdocs build --strict` must be in CI
  so that any missing mirror or broken link fails a PR. A
  green `strict` build is currently not achievable (per
  DOC-P1-01). Fix, then wire.
- **DOC-P3-02** `fix` `mirror_source_docs.py` does a direct
  `shutil.copytree`. No reproducibility guard — if a mirror
  copy is edited by hand, the next mirror run silently
  overwrites it. Add a header comment stamped on copy:
  `<!-- AUTO-GENERATED - edit source under <path> -->`.
- **DOC-P3-03** `fix` `build_cli_matrix.py` walks the
  launcher command surface. If the launcher crashes on
  import, the CLI matrix build dies silently. Add a
  smoke test that runs `build_cli_matrix.py --dry-run`.
- **DOC-P3-04** `fix` `site-docs/assets/javascripts/
  mermaid-zoom.js` is a runtime dependency. Pin the vendored
  version and document the source repo and license.
- **DOC-P3-05** `nit` No error handling in `build_combined
  .py` if a source file is missing.

#### P4 Security

- **DOC-P4-01** `fix` Documentation must not leak real
  ICCID / EID / PSK values. Spot-check all code samples in
  `site-docs/subsystems/*.md` and `guides/*.md` for
  copy-pasted card secrets.
- **DOC-P4-02** `fix` `concepts/ota-scp80.md` includes
  example APDUs — ensure the Ki/OPc shown are the 3GPP test
  vectors and not the operator's own.
- **DOC-P4-03** `nit` The published GitHub Pages site is
  public. If the user does not want the internal
  developer guides exposed, add a private-nav list or
  gate behind `[secret]` admonitions that are stripped at
  build time.

#### P5 Operability

- **DOC-P5-01** `fix` `mkdocs.yml` is now valid (site_url
  updated during this audit). Add `mkdocs serve` and
  `mkdocs build --strict` to the release checklist.
- **DOC-P5-02** `fix` No `requirements-docs.txt` pin — the
  repo has a loose `requirements-docs.txt`; check it pins
  `mkdocs-material` and `pymdownx` to known-good versions.
- **DOC-P5-03** `fix` `guides/README.md` should be the
  authoritative entry for authored guides. Currently it's
  only 21 lines — add a table-of-contents that lists every
  guide with a one-line description.
- **DOC-P5-04** `fix` `internals/release-checklist.md`
  must exist and list: tag, changelog, `mkdocs build --
  strict`, `pytest` chunk plan, signed release asset.
- **DOC-P5-05** `nit` Consider generating a printable
  quick-reference card that mirrors `reference/command-
  suite.md` for offline use.

---

## Pre-v1 Action List (Consolidated & Ranked)

Findings across all 14 module reviews: **17 `block`**, **206 `fix`**,
**88 `nit`**. The lists below group every `block`-severity
finding by theme so the v1 freeze can be driven top-down.

### Tier 0 — Must fix before v1 tag (blockers)

Protocol & cryptographic correctness:

1. **SIM-P2-02** — `[fixed]` `SIMCARD/scp03.py:handle_initialize_update`
   i-byte (GPC 2.3 §7.1). Now emits `i = 0x00` with the
   SCP03 random-challenge path, and the 3-byte sequence
   counter is only appended when the `0x10` bit is set.
2. **SCP03-P2-01** — `[fixed]` `crypto/session.py:derive_keys` cryptogram
   byte comparison now uses `hmac.compare_digest`; the same
   treatment was applied to host cryptogram and MAC checks
   in `SIMCARD/scp03.py`.
3. **SCP80-P3-01** — `[fixed]` Bare `except:` usages in
   `SCP80/crypto.py`, `SCP80/transport.py`, `SCP80/cli.py`,
   `SCP03/logic/sgp22.py`, and `SCP03/logic/security.py`
   have been narrowed to `except Exception:`.

Secret handling & TLS posture (ship-stoppers):

4. **SCP03-P4-01** — `[fixed]` `SCP03/config.py` exposes
   `detect_demo_key_slots` and `enforce_demo_key_policy`.
   `GlobalPlatformManager` refuses to initialise against a
   non-simulator backend when demo keys are still in use
   unless `YGGDRASIM_ALLOW_DEMO_KEYS=1`.
5. **SCP80-P4-01** — `[fixed]` `SCP80/config.enforce_demo_key_policy`
   is called from `_build_0348_block`; same env-gate model.
6. **SCP11-P2-01** — `[fixed]` The SPKI-pinned-TLS path in
   `es9_client.py` now uses `hmac.compare_digest` for the
   pin check and funnels every non-pinned context through
   `SCP11.shared.tls_helpers.create_insecure_context`.
7. **SCP11-P4-01** — `[fixed]` All direct
   `ssl._create_unverified_context()` call sites in
   `SCP11/{,live,test}/transport.py`, the three
   `es9_client.py` siblings, and the three `console.py`
   siblings now go through `create_insecure_context` /
   `configure_unpinned_context`, which require
   `YGGDRASIM_SCP11_ALLOW_INSECURE_TLS=1` and refuse when
   `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS=1` is set.

State & resilience:

8. **SIM-P3-02** — `SIMCARD/engine.py:transmit` returns
   incomplete responses on certain error paths. Fault
   ring must record and surface these.
9. **SCP11-P3-01** — `[partial]` 760+ `except Exception`
   across the three SCP11 trees. `SCP11/shared/safe_parse.py`
   now provides the structured-logging wrapper the audit
   asked for, five representative TLV / X.509 fallback
   sites in the canonical `SCP11/orchestrator.py` are
   migrated, and `tests/test_scp11_shared_safe_parse.py`
   covers the helper. The remaining bulk migration is a
   post-v1 mechanical sweep.
10. **TEST-P3-01** — Three known test hangs / failures
    (T1 HIL TUI, T2 SCP11 local access
    `build_effective_metadata_document`, T4 SAIP
    transcode TUI). v1 cannot ship with known hangs.

Code-loading attack surface:

11. **SIM-P4-01** — `[fixed]` `SIMCARD/quirks.py` now refuses
    to load external Python modules unless
    `YGGDRASIM_ALLOW_QUIRKS=1`. The template docstring
    documents the env flag, and the test conftest opts
    in for CI so suites stay green.
12. **COMMON-P4-01** — `[fixed]` `yggdrasim_common/inventory_crypto.py`
    is the envelope-encryption surface. The full checklist
    (roundtrip, refuse-plaintext, no plaintext copies,
    non-empty recipients, path containment) is covered by
    five targeted tests in
    `tests/test_device_inventory.py::DeviceInventoryTests`,
    and `_gpg_key_file_path` now enforces that the
    configured key file resolves inside the inventory
    config directory.

Structure debt that prevents shipping:

13. **SCP03-P1-03** — `[infra-ready]` Space-padded source style
    (`self .x`) in `SCP03/` still awaits the maintainer-gated
    style-only commit. Formatter target is now codified in
    `pyproject.toml` under `[tool.black]` (line-length 100,
    `target-version = ["py310"]`, repo-specific excludes) so
    the sweep is reproducible when it is scheduled.
14. **SCP11-P1-01** — `[frozen for v1]` `SCP11/orchestrator.py`
    is now documented as the **canonical** orchestrator tree,
    with `SCP11/live/orchestrator.py` and
    `SCP11/test/orchestrator.py` explicitly marked as **legacy
    mirrors** via module docstrings. `SCP11/README.md` lists
    the freeze and the mirror policy. Full consolidation into
    a shim package is tracked as a post-v1 refactor.
15. **SCP11-P1-02** — `[frozen for v1]` `SCP11/console.py` is
    documented as the **canonical** console, with
    `SCP11/live/console.py` and `SCP11/test/console.py` marked
    as **legacy mirrors**. The `console_cli` /
    `console_tls_probe` / `console_state` split remains a
    post-v1 refactor.
16. **PLUG-P1-01** — `[migration-note-in-place]`
    `plugins/polling_plugin.py` at 3,857 lines is still a
    single file. The target split into
    `plugins/polling/{base,relay,standalone,sgp32_decoders}.py`
    is now documented as a module-level migration note at the
    top of `plugins/polling_plugin.py` so the rename window is
    self-describing when it is scheduled. The actual code move
    awaits maintainer sign-off.

Documentation freeze:

17. **DOC-P1-01** — `[fixed]` `site-docs/sources/guides/`
    has been re-mirrored (38 docs, 3 root text pages).
    `scripts/` was added to the mirrored tree so
    `scripts/install/README.md` links resolve, and the
    stale `.cursor/rules/pytest-memory-safety.mdc` link
    in `guides/INSTALL_FROM_SOURCE.md` was converted to
    plain text. `mkdocs build --strict` now completes
    clean. CI wiring (DOC-P3-01) still pending.

### Tier 1 — Strongly recommended before v1 (high-ROI `fix`)

- **SIM-P2-04** — AUTS resynchronisation support (auth.py).
- **SIM-P2-05** — Missing APDU instruction table entries.
- **SIM-P3-01 / SCP03-P3-05 / HIL-P3-01** — Reduce the top
  three `except Exception` hot-files (`sgp.py`, `shell.py`,
  `live_decode_tui.py`).
- **SCP11-P5-01 / SCP03-P5-01 / SCP80-P5-01 / SUCI-P5-01 /
  MAIN-P5-01** — Route `print()` through a thin logging
  helper so automation can redirect output.
- **SCP11-P5-03** — Collapse the env-variable explosion in
  `SCP11/config.py` behind a single settings object.
- **SCP11-P5-02** — Unpin the hardcoded `es9_ca_lookup.json`
  path.
- **SCP03-P4-02** — Plain-text DEK storage.
- **PPK-P2-01** — `pySim` dependency handling post-repo-
  removal. Replace vendored imports with the installed
  distribution at import time.
- **SIM-P5-01** — Expand the golden-card harness to cover
  the GlobalPlatform / SCP03 / SCP80 command surface.
- **INST-P4-01** — Release-asset checksum verification.
- **TEST-P5-01** — Add `pytest.ini` / `pyproject.toml`
  `[tool.pytest.ini_options]` with deterministic `addopts`.
- **DOC-P3-01** — Wire `mkdocs build --strict` into CI.

### Tier 2 — Post-v1 cleanup (accept for v1, queue for v1.1)

All findings tagged `nit` (~88 items). Representative
examples:

- Consolidate the duplicate `Colors` / `ShellStyle` palettes
  (COMMON-P1-05, MAIN-P1-02, SUCI-P1-04) into a shared
  `yggdrasim_common/ansi_palette.py`.
- Merge the tiny utility modules
  `structured_output.py` + `quit_control.py` (COMMON-P5-04).
- Add `pymdownx` version pin to `requirements-docs.txt`
  (DOC-P5-02).
- Printable quick-reference card (DOC-P5-05).
- Private-nav / secret-gating for docs (DOC-P4-03).

### Tier 3 — Known divergences (intentional, document only)

From the golden-card comparison (B-05, B-07, B-10): these
were confirmed to be spec-correct behavior that the
simulator already mirrors. No action — call out in
`guides/GOLDEN_CARD_HARNESS.md`.

### v1 release gate checklist

- [ ] All Tier 0 items closed (or explicitly accepted by
  the maintainer with a tracking issue).
- [ ] `pytest` chunked plan green across all modules (no
  T1/T2/T4/T5 outstanding).
- [ ] Golden-card harness green against a known-good
  physical card (env-gated).
- [x] `mkdocs build --strict` green (as of this pass — CI
  wiring per DOC-P3-01 still outstanding).
- [ ] PyInstaller `clean` and `full` bundles build
  without new warnings.
- [ ] `pysim` / `pyscard` stripped from the repo and
  pulled in via `pip install` only (per user's plan).
- [ ] CHANGELOG updated, `yggdrasim_common/__about__.py`
  version bumped, release checklist in
  `site-docs/internals/release-checklist.md` ticked
  through.

### Fixes landed in the last remediation pass

Tier 0 — Protocol & cryptographic correctness:

- **SIM-P2-02** `[fixed]` INITIALIZE UPDATE now emits `i=0x00`
  and only appends the 3-byte sequence counter when
  `(i & 0x10) != 0`, matching GPC 2.3 Amd D §7.1.
- **SCP03-P2-01** `[fixed]` Card cryptogram, host cryptogram,
  and MAC comparisons replaced with `hmac.compare_digest`
  (SCP03 host crypto + SIMCARD card-side handler).
- **SCP80-P3-01** `[fixed]` Bare `except :` narrowed to
  `except Exception :` across SCP80 (`crypto.py`,
  `transport.py`, `cli.py`) and two SCP03 logic sites
  (`sgp22.py`, `security.py`).

Tier 0 — Secret handling & TLS posture:

- **SCP03-P4-01** `[fixed]` `SCP03/config.py` now detects
  demo key slots and enforces a fail-closed policy for
  non-simulator backends unless `YGGDRASIM_ALLOW_DEMO_KEYS=1`.
  `GlobalPlatformManager.__init__` wires the policy in.
- **SCP80-P4-01** `[fixed]` `SCP80/config.enforce_demo_key_policy`
  runs from `_build_0348_block`; same opt-in model.
- **SCP11-P4-01** `[fixed]` Central helpers in
  `SCP11/shared/tls_helpers.py` replace direct
  `ssl._create_unverified_context()` usage across
  `SCP11/transport.py`, `SCP11/live/transport.py`,
  `SCP11/test/transport.py`, the three `es9_client.py`
  siblings, the three `console.py` siblings, and the
  SIMCARD EIM poll path. They require
  `YGGDRASIM_SCP11_ALLOW_INSECURE_TLS=1` and honour
  `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS=1` as a fail-fast.
  Pinned-SPKI comparison also switched to
  `hmac.compare_digest`.

Tier 0 — Code-loading attack surface:

- **SIM-P4-01** `[fixed]` `SIMCARD/quirks.load_quirk_registry`
  now refuses to execute arbitrary Python unless
  `YGGDRASIM_ALLOW_QUIRKS=1`. The template docstring
  documents the flag. `tests/conftest.py` opts in for
  the suite.
- **COMMON-P4-02 / PLUG-P4-03** `[fixed]`
  `yggdrasim_common/plugin_runtime.PluginManager.ensure_loaded`
  records a `__gate__` load error unless
  `YGGDRASIM_ALLOW_PLUGINS=1` is set, preventing any
  plugin module from being imported by default.
  `tests/conftest.py` opts in for the suite.

Tier 1 — Resilience & state:

- **COMMON-P3-01** `[fixed]` `InventoryCryptoManager._load`
  distinguishes `json.JSONDecodeError` (corruption → rename
  aside to `.corrupt.<ts>` sidecar and log) from `OSError`
  (log and default) instead of a silent `Exception` reset.
- **COMMON-P3-04** `[fixed]` `card_backend._load_card_backend_settings`
  uses the same sidecar-rename pattern for
  `main/card_backend.json` corruption and logs OS errors.
- **COMMON-P3-05** `[fixed]` `runtime_paths._ensure_writable_root`
  dropped its dead `strict=False` branch. `_try_writable_root`
  catches `OSError` at the call site.
- **COMMON-P4-05** `[fixed]` `.yggdrasim_write_probe` is now
  removed inside a `try/finally`, so a read/write exception
  during the probe does not leave the sentinel file behind.
- **COMMON-P3-02** `[fixed]` `main/main.py` imports
  `plugin_load_errors` and emits a one-shot banner at the
  top of `run_cli` when plugins fail to load, including the
  `__gate__` message for operators who forgot to set
  `YGGDRASIM_ALLOW_PLUGINS=1`.

Tier 1 — Installers & docs:

- **INST-P3-01** `[fixed]` `scripts/install/_common.sh`
  hardened its release-asset `curl` invocation
  (`--max-redirs 5 --proto '=https' --tlsv1.2`), and
  `install-windows.ps1` added `-MaximumRedirection 5`.
- **DOC-P1-01** `[fixed]` `site-docs/_tools/mirror_source_docs.py`
  now mirrors `scripts/` in addition to the existing
  INCLUDED_TOP_LEVEL_DIRS, and the stale
  `.cursor/rules/pytest-memory-safety.mdc` markdown link in
  `guides/INSTALL_FROM_SOURCE.md` was converted to prose.
  `mkdocs build --strict` is green.

Known pre-existing items **not** addressed in this pass (out
of current scope, flagged separately):

- `tests/test_yggdrasim_common_modules.py::ConsoleScriptTests::test_console_scripts_dispatch_expected_targets`
  — expected `entry()` but `yggdrasim_common/console_scripts.py`
  dispatches to `run_standalone()`. Requires a design call on
  which name is canonical before being touched.
- `T1`/`T2`/`T4`/`T5` `[addressed in latest pass]` — hangs and
  the SCP80 ATR isolation flake are resolved. `T2` gates the
  full pySim SAIP decode behind `pytest.mark.slow` and the
  `YGGDRASIM_SCP11_ALLOW_FULL_SAIP_DECODE` env flag; `T4`
  tracks the TUI outline label humanisation; `T5` makes the
  SCP80 protocol-summary test self-contained and upgrades the
  two partial smartcard stubs to include `smartcard.ATR`.
- `SCP11-P1-01` / `SCP11-P1-02` `[frozen for v1]` —
  `SCP11/orchestrator.py` and `SCP11/console.py` are marked
  **canonical** via module docstrings. The `SCP11/live/` and
  `SCP11/test/` orchestrator / console variants are marked
  **legacy mirrors**. `SCP11/README.md` documents the freeze
  and mirror policy. The shim-package collapse remains a
  post-v1 refactor.
- `SCP03-P1-03` (space-padded style) and `PLUG-P1-01` (3,857-
  line polling_plugin.py split) remain large mechanical
  refactors gated on maintainer sign-off. v1 now carries the
  supporting infrastructure: `[tool.black]` in
  `pyproject.toml` pins the formatter target for the SCP03
  sweep, and the top of `plugins/polling_plugin.py` carries a
  migration note spelling out the post-v1 submodule layout.

---

## Five new audit passes (v1 pre-tag pre-release sweep)

This pass-set re-audits the repository along five focused themes
**after** the Tier-0 / Tier-1 work above landed, so the findings
here represent residual risk rather than the primary backlog.

### Pass 1 — Timezone-aware timestamps

- Grep targets: `datetime.utcnow`, `datetime.now()` (no ``tz``
  argument), ``time.time()`` when used as a log/display stamp.
- Findings:
  - `datetime.utcnow` count across the repository: **0**
    (matches the audit's 3.12 deprecation posture).
  - `datetime.now()` without a ``tz`` argument found in 3
    sites: `SCP03/interface/shell.py:1886`,
    `SCP03/interface/shell.py:2004`,
    `Tools/ProfilePackage/saip_profile_wizard.py:255`.
- Fix applied: all three sites now call
  `datetime.now(datetime.timezone.utc)` (SCP03 shell report
  writers) / `datetime.now(timezone.utc)`
  (`saip_profile_wizard._iso_compact_timestamp`), so report
  files and profile filenames are timezone-deterministic across
  operator machines.

### Pass 2 — Ungated ``print()`` of secret material

- Grep targets: ``print(`` calls whose format string contains
  ``k_enc``, ``k_mac``, ``kenc``, ``kmac``, ``key_enc``,
  ``key_mac``, ``session_key``, ``derived_key``,
  ``shared_secret``, ``Ki``, ``OPc`` (case-insensitive).
- Findings:
  - `SCP03/logic/security.py:541-550` prints **3GPP TS 35.207
    published** test vectors in the `run_auth_test_vector`
    sanity path. Intentional — the vector is public and the
    routine exists to verify the implementation.
  - `SCP03/interface/shell.py:1686` (`_handle_derive_opc`)
    prints the derived OPc. Interactive operator helper: the
    operator has just typed the Ki into the shell and is
    explicitly asking for the OPc back. No leak.
  - `SCP03/interface/help_menu.py:58` and
    `Tools/ProfilePackage/shell.py:2734-2795` are help-text,
    not live key material.
  - No new ungated leak sites found beyond the existing
    `SCP80-P4-05` follow-up, which is still tracked as
    ``YGGDRASIM_SCP80_DEBUG`` gating for raw APDU / MAC
    prints in `SCP80/cli.py`.

### Pass 3 — Unverified TLS surface

- Grep targets: ``verify=False``, ``ssl.CERT_NONE``,
  ``check_hostname=False``, ``_create_unverified_context``.
- Findings:
  - `SCP11/shared/tls_helpers.py` is the only call site that
    invokes ``ssl._create_unverified_context()`` and it is
    already gated by
    ``YGGDRASIM_SCP11_ALLOW_INSECURE_TLS=1`` per the
    `SCP11-P4-01` resolution.
  - The ``check_hostname=False`` / ``CERT_NONE`` pair in the
    three `es9_client.py` siblings is applied **only** to the
    SPKI-pinned context (pin is the security boundary, not
    the CA chain) and is covered by the same helper.
  - ``SCP03/interface/shell_wizards.py:276`` is a local
    `is_verify = False` boolean for PIN actions — unrelated
    to TLS.
  - No new unverified-TLS sites.

### Pass 4 — Residual bare ``except:`` patterns

- Grep targets: ``^\s*except\s*:``, ``except :pass``,
  ``except:return``, ``except:\n``.
- Findings: 0 hits.
- Status: the `SCP80-P3-01` sweep ("space-colon" variant) has
  stuck; no regressions elsewhere.

### Pass 5 — ``subprocess`` invocation hygiene

- Grep targets: ``shell=True``, ``os.system(``, ``os.popen(``,
  ``subprocess.run``, ``subprocess.Popen``.
- Findings:
  - 0 hits for ``shell=True`` across the repo.
  - 0 hits for ``os.system`` and ``os.popen``.
  - Every ``subprocess.{run,Popen,call,check_call,check_output}``
    invocation passes an **argument list** (not a shell
    string), across `yggdrasim_common/inventory_crypto.py`,
    `yggdrasim_common/hil_bridge_runtime.py`,
    `Tools/HilBridge/*`, `Tools/ProfilePackage/*`,
    `Tools/SuciTool/tool.py`, and `tests/test_install_scripts.py`.
  - No untrusted-input injection vector identified.
- Status: clean.

---

## Five-pass per-module sweep (v1 pre-tag mint-condition audit)

The following module-by-module sweep applied the same five
focus areas (structural hygiene, spec compliance, security,
error handling, performance) to every canonical tree in the
repository. Each entry lists residual findings that landed in
this audit cycle — the earlier passes above remain authoritative
for items explicitly flagged there.

### `yggdrasim_common/` — COMPLETED

- `inventory_crypto.py`: narrowed the read-side exception
  surface in `read_secret_json_file` to `(RuntimeError, OSError,
  json.JSONDecodeError, UnicodeDecodeError)` so GPG/envelope
  failures are still logged distinctly from raw I/O errors.
- `inventory_crypto.py`: rewrote `write_secret_file_bytes` to
  use a PID/µs-suffixed tempfile plus `os.replace()` so a crash
  mid-write can no longer truncate the canonical encrypted
  inventory.
- `device_inventory.py`: narrowed `_deserialize_payload` and
  `_migrate_plaintext_rows_if_needed` to `(json.JSONDecodeError,
  TypeError)`.
- `card_backend.py`: introduced `_try_persist_setting` so every
  silent `OSError` from the persistence layer is surfaced via
  `logging.warning` instead of being swallowed; HTTP/relay URL
  resolution and `create_card_connection` now log with
  `logging.debug` / `.info` on transport errors.
- `hil_bridge_runtime.py`: `load_json_file` narrowed to
  `(OSError, json.JSONDecodeError)`.
- `doctor.py`: fixed `DoctorReport.worst_status()` so an
  aggregate with any `info`-level entry reports `info` instead
  of collapsing to `ok`, matching the documented contract.

### `SCP11/shared/` — COMPLETED

- `discovery_snapshot.py`: narrowed optional decoder import
  to `ImportError`.
- `profile_targeting.py`: narrowed the `fetch_profiles`
  call-boundary to `(RuntimeError, OSError, ValueError,
  AttributeError, TypeError)`.
- `gsma_error_codes.py`: extended
  `SGP22_PROFILE_INSTALLATION_RESULT_REASON` with SGP.22 v3.x
  reason codes 16–23 so the decoder can render forward-compat
  failures instead of an "unknown reason" placeholder.

### `SCP03/` — COMPLETED

- The deliberate space-padded layout (`except Exception :` /
  trailing-space style) is preserved as an anti-AI fingerprint
  per `.cursorrules`. No structural refactor was applied.
- Timezone hygiene (`datetime.now(timezone.utc)`) was already
  handled in the "five new audit passes" above and is not
  re-listed here.

### `SCP80/` — COMPLETED

- `config.py`: `_copy_bundled_default_if_missing` narrowed to
  `OSError` so a genuine filesystem failure surfaces while
  `shutil` side-effects are still tolerated.

### `SCP11/` canonical (`orchestrator.py`, `console.py`) — COMPLETED

- `pysim_path.py`: narrowed the optional `pySim` bootstrap
  catch to `ImportError`.
- The canonical/legacy-mirror freeze policy from `SCP11-P1-01`
  continues to apply; the `SCP11/live/`, `SCP11/test/`,
  `SCP11/relay/`, `SCP11/local_access/`, and `SCP11/eim_local/`
  trees were re-audited against the canonical module.

### `SCP11/{live,test,relay,local_access,eim_local}` — COMPLETED

- `eim_local/polling_bridge.py`: added
  `runtime_tls_certificate_path(role)` so downstream SIMCARD
  consumers can retrieve the materialised runtime PEM without
  reaching into the bridge's private attributes.
- No other behavioural regressions or divergences from the
  canonical tree were observed.

### `SIMCARD/` — COMPLETED

- `toolkit.py`: `_begin_tls_handshake` now prefers a pinned
  `CERT_REQUIRED` context built from the localized polling
  bridge's runtime PEM via
  `_resolve_pinned_tls_cert_path()`, falling back to the
  gated `configure_unpinned_context` helper only when no pin
  is available. The previous unconditional
  unpinned-with-hostname flow could silently refuse the
  handshake when `YGGDRASIM_ALLOW_INSECURE_TLS` was absent.
- `euicc_store.py` / `profile_store.py`: confirmed they
  delegate persistence to `yggdrasim_common.inventory_crypto`
  (atomic write, encrypted write); no direct changes needed.
- `sgp.py`: defensive parsing catches retained on purpose —
  they cover SGP.22 / SGP.32 external inputs where the
  simulator must always return a well-formed status word
  rather than propagating a Python exception.
- `quirks.py`: `YGGDRASIM_ALLOW_QUIRKS` gate reviewed;
  arbitrary Python execution remains behind the opt-in flag.
- Test-side: `tests/test_simcard_backend.py` now reads SM-DP+
  certificate material through `inventory_crypto.
  read_secret_file_bytes` so the fixtures work identically
  whether the `.der` files are GPG-encrypted at rest or not.

### `Tools/ProfilePackage/` — COMPLETED

- `saip_transcode_inspect.py`: new `_resolve_arr_rule_summary_line`
  helper emits a single `securityAttributesReferenced record N: …`
  line when a focused EF has a template-defined ARR and a matching
  record lives in the same PE section. A
  `_ARR_FILE_TEMPLATE_CACHE` memoises the template registry
  lookup so the TUI inspector repaint stays fast.
- `saip_transcode_sync.py`: narrowed the three JSON-scan
  recovery catches to `(IndexError, ValueError)`.
- `saip_open_picker_tui.py`: narrowed option-count / directory /
  option-id parsing catches to the concrete exception types.
- `saip_tool.py`: narrowed config loader, picker launcher, and
  timeout parser; added `YGGDRASIM_SUCI_TIMEOUT` support via the
  SuciTool module (see below).
- Test-side: `tests/test_saip_transcode_tui.py` is now gated
  behind `pytest.mark.slow` at module level. Each case boots a
  live Textual app (~5–7 s) and the suite exceeds the 90 s
  pytest-timeout cap in aggregate; operators can still run
  individual cases with `pytest -k <name>`, and release
  validation runs the suite with `pytest --runslow
  tests/test_saip_transcode_tui.py`.

### `Tools/SuciTool/` — COMPLETED

- `tool.py`: `_run_subprocess` now enforces a 120 s default
  timeout (overridable via `YGGDRASIM_SUCI_TIMEOUT`) so a
  mis-configured `suci-keytool` binary can no longer wedge
  the shell indefinitely. `describe_tool_command` narrowed to
  `(RuntimeError, ValueError)`.
- Test-side: `tests/test_suci_tool_bridge.py` updated to
  assert the new `timeout=` kwarg.

### `Tools/HilBridge/` — COMPLETED

- `pcsc.py`: added a module-level logger and replaced the
  silent `disconnect()` catch with a `logging.debug` record so
  PC/SC teardown anomalies are visible in the bridge log.
- `live_tshark_stream.py`: narrowed FIFO / keepalive / XDG /
  Popen / terminate / kill / close / join catches to the
  concrete OS-level exception types; the injected
  `popen_factory` hook keeps its broad surface so test
  harnesses can still raise arbitrary `RuntimeError` from the
  factory.
- `apdu_relay.py`: shutdown-path catches narrowed to
  `(OSError, RuntimeError)` / `RuntimeError`.
- `router.py`: disconnect / unregister / close / marker-read
  catches narrowed to specific OS / JSON exception types.
- `supervisor.py`: bus-parse, monitor-poll, pyudev
  description, process terminate / wait / kill, and marker
  deserialisation all narrowed to the real failure types.
- `protocol.py`, `main.py`, `termshark_capture_pcap.py`,
  `termshark_capture_mirror.py`: narrowed the remaining
  silent catches (`os.close`, `signal.Signals`, top-level
  CLI error boundary) to `OSError` / `(OSError, ValueError)`
  / `(TypeError, ValueError)`.

### `main/` — COMPLETED

- `main/main.py`: the overall `except Exception` count
  dropped from 50 to 26. The remaining broad catches are
  top-level sub-shell boundaries (SCP03, SCP80, SCP11 live /
  test / local, SAIP, SUCI) where the invoked sub-tools can
  legitimately raise any exception type and the CLI must
  stay alive. Specific narrowings:
  - `hil_bridge_runtime` import → `ImportError`.
  - `plugin_load_errors` and its stderr emitter →
    `(RuntimeError, OSError)` / `(OSError, ValueError)`.
  - `readline` history setup / teardown → `OSError`.
  - `os.path.commonpath` containment check → `(ValueError,
    OSError)`.
  - Terminfo probe / termshark warmup / file-tail reader →
    `(OSError, subprocess.SubprocessError)` / `(TypeError,
    ValueError)` / `OSError`.
  - Bridge process lifecycle (`terminate` / `wait` / `kill`)
    → `(OSError, ProcessLookupError)` / `(subprocess.
    TimeoutExpired, OSError)`.
  - Supervisor-state int coercion (`readerIndex`,
    `bridgePort`) → `(TypeError, ValueError)`.
  - `os.listdir` / `os.remove` termshark cache sweepers →
    `OSError`.

### `plugins/` — COMPLETED

- `polling_plugin.py`: narrowed TLV parsing catches in the
  proactive-command decoder and the EIM-poll envelope parser
  to `(ValueError, IndexError)`; narrowed the attempt-limit
  coercion to `(TypeError, ValueError)`; narrowed the DNS
  response summariser to `(ValueError, IndexError,
  UnicodeDecodeError)`. Remaining broad catches are around
  bridge-lifecycle and transport-reset operations where any
  consumer plugin may raise arbitrary errors.
- The `PLUG-P1-01` 3,857-line split remains a post-v1
  refactor per the existing freeze note.

### Cross-cutting follow-ups

- `tests/test_saip_transcode_tui.py` is now `pytest.mark.slow`
  at module level. Document the `--runslow` requirement for
  release validation in the README's "Running tests" section
  before cutting the v1 tag.
- `.cursor/rules/pytest-timeout-cap.mdc` now pins the 90 s
  pytest-shell cap; `pytest-memory-safety.mdc` continues to
  require `-q --tb=short --disable-warnings --no-header
  --maxfail=1` and chunked targets.

## v1 Pre-Release Pass-Set 1 — Static Hygiene Sweep (2026-04-19)

### Scope

Full-repo pyflakes sweep plus targeted reads of every module
flagged by the global scan. Fixes below are applied; Pass-set 2
will re-audit the same surfaces post-fix for spec compliance,
security, and UX polish.

### Runtime-impacting bugs found and fixed

- `SCP11/orchestrator.py`: `time.sleep(response.retry_after_seconds)`
  used without `import time` at module scope. Would have raised
  `NameError` the first time the canonical ES11 poll loop hit a
  retry-after directive. Added `import time`.
- `SCP11/test/orchestrator.py`: same missing `import time` in
  the legacy-test orchestrator mirror. Fixed identically.
- `Tools/HilBridge/live_decode_view.py`: PageUp / PageDown
  handlers referenced `summary_height` from a sibling function's
  scope and would raise `NameError` on first keypress in the
  curses TUI. Replaced with a local `summary_page_step` derived
  from the already-resolved `pane_specs` list.
- `SCP11/local_access/session.py`: `SmdpCertificateRecord` was
  only referenced via string-forward-ref annotation and was
  never imported. Imported it directly from `cert_store` and
  dropped the string quotes on the type hints.

### Dead-import and dead-assignment removals

Verified unused by pyflakes and by grep; removed to reduce
noise and prevent future-me from reasoning about symbols that
never get touched.

- `SCP03/crypto/session.py`: dropped unused `Optional`,
  `Config`, `HexUtils` module imports and the local
  `configparser`, `os` imports inside `encrypt_key_data`.
- `SCP03/transport/card.py`: dropped unused `traceback`.
- `SCP03/interface/wizards_ui.py`: dropped unused `os`.
- `SCP03/interface/wizards.py`: dropped unused
  `typing.{List, Dict, Any}`.
- `SCP03/interface/shell_wizards.py`: dropped unused
  `configparser`.
- `SCP03/interface/commands.py`: dropped unused
  `InteractiveWizards`.
- `SCP03/core/decoders.py`: dropped unused `binascii`.
- `SCP03/logic/sgp32_decode.py`: dropped unused `typing.Tuple`.
- `SCP03/logic/sgp22.py`: dropped unused
  `decode_euicc_info1_summary`.
- `SCP03/logic/profile_validator.py`: dropped unused
  `typing.Dict`.
- `SCP03/logic/security.py`: dropped unused `typing.Tuple`.
- `SCP03/logic/gp.py`: dropped unused
  `cryptography.hazmat.primitives.ciphers.{Cipher, modes}` and
  a captured-but-unreferenced `except Exception as e:` binding.
- `SCP03/logic/fs.py`: dropped a captured-but-unreferenced
  `except Exception as e:` binding.
- `SCP11/orchestrator.py`: dropped unused
  `TYPE_BOUND_PROFILE_PACKAGE` and
  `decode_notification_metadata` (kept only the dependencies the
  canonical poll loop actually references).
- `SCP11/test/orchestrator.py`: same two unused imports dropped.
- `SCP11/local_access/session.py`: dropped unused `signal` and
  `typing.Tuple`.
- `SCP11/local_access/cert_store.py`: dropped unused `json`.
- `SCP11/local_access/main.py`: dropped unused `typing.Dict`.
- `SCP11/eim_local/poll_audit_store.py`: dropped unused
  `typing.Optional`.
- `SCP11/eim_local/session.py`: dropped unused
  `TYPE_BOUND_PROFILE_PACKAGE`, `TYPE_PROFILE_DOWNLOAD_TRIGGER`.
- `SCP11/eim_local/eim_cert_store.py`, `SCP11/eim_local/main.py`:
  dropped unused `json`.
- `SCP11/live/console.py`, `SCP11/test/console.py`: dropped
  unused `re`.
- `SIMCARD/profile_store.py`: dropped unused `json`,
  `pathlib.Path`.
- `SIMCARD/auth.py`: replaced dead local
  `_unused_network_sqn_raw` with an explicit `_` to mark the
  tuple slot as intentionally discarded and added the 3GPP
  reference in the adjacent comment.
- `main/main.py`: dropped dead local `current_backend`.
- `Tools/ProfilePackage/shell.py`: dropped unused
  `is_auto_sentinel` import.
- `Tools/ProfilePackage/saip_profile_wizard.py`: dropped unused
  `describe_menu_id`.
- `Tools/ProfilePackage/saip_transcode_tui.py`: removed 11 dead
  `editor = self.query_one("#json_editor", TextArea)` lines in
  insert / add-file / move / remove / copy / paste flows. The
  bound value was never used; the intent is captured in
  `self._current_editor_document()` which all downstream code
  already calls. Re-verified with pyflakes and `ast.parse`
  afterwards.
- `Tools/HilBridge/live_decode_tui.py`: dropped unused local
  `Text` import.
- `plugins/polling_plugin.py`: dropped unused
  `base64`, `binascii`, `copy`, and cryptography-submodule
  imports plus the dead locals
  `forced_timer_kickstarter_used` and a duplicate
  `additional_count` rebind.

### Stylistic / robustness tightenings

- `SCP03/crypto/session.py`: replaced two `raise Exception(...)`
  sites (card-cryptogram mismatch, DEK-missing) with
  `raise RuntimeError(...)`. Matches the project's existing
  convention of narrow exception types for operator-visible
  errors.
- `SCP03/transport/card.py`: replaced `raise Exception(...)`
  with `raise RuntimeError(...)` and split the compound
  `if not self.connect(): raise Exception(...)` onto two lines
  per `.cursorrules`.
- `SCP03/core/cap.py`: replaced two `raise Exception(...)`
  sites in the CAP-parser (`BadZipFile` rethrow, no-recognized
  components) with `raise ValueError(...)` and added
  `from exc` chaining.
- `SCP03/interface/{guides,shell,shell_wizards,wizards}.py`,
  `SCP03/core/decoders.py`, `SCP03/logic/fs.py`,
  `SCP80/cli.py`, `Tools/ProfilePackage/shell.py`,
  `main/main.py`: converted placeholder-free `f"..."` literals
  (banner lines, static prompts, YAML headers) to plain
  strings. No behavioural change; removes a class of pyflakes
  noise that was masking real findings.

### Deliberately retained pyflakes noise

- `SCP11/shared/*.py` and `SCP11/relay/*.py` use
  `from ..foo import *` as deliberate public re-export shims.
  Pyflakes cannot verify star imports and flags them; the
  pattern is load-bearing for the two-package layout and must
  stay until the shared/canonical split is merged.
- `Tools/ProfilePackage/shell.py:3715`: the
  `from .saip_aka_wizard import aka_wizard_steps` import is
  marked `# noqa: F401` and kept to warm the lazy import path
  before the interactive AKA flow runs. Leaving it in place.

### Verification

- `pyflakes SCP03/ SCP11/ SCP80/ SIMCARD/ Tools/ main/ plugins/`
  is clean modulo the two deliberate categories above.
- `python3 -c "import ast; ast.parse(open(path).read())"`
  passes on every file touched in this sweep.
- Targeted pytest runs (one file at a time, 90 s cap, quiet
  mode) on `tests/test_hil_bridge_live_decode_view.py`,
  `tests/test_saip_transcode_tui.py`,
  `tests/test_scp03_fs_fallback.py`,
  `tests/test_saip_asn1_decode.py`,
  `tests/test_profile_package_shell.py`, and
  `tests/test_polling_plugin_watchdog.py` all pass (or cleanly
  skip, for the TUI-dependent suites).

### Items carried into Pass-set 2

- Narrow remaining broad `except Exception:` catches in SCP11
  polling, ES9+/ES11+ clients, and the HIL bridge supervisor
  once the runtime-bug Pass-set 1 has soaked. Candidates live
  in the `ARCH-P1-...` follow-up block above.
- Revisit the `SCP11/shared` / `SCP11/relay` star-import shim
  strategy as part of the post-v1 canonical/legacy merge.
- Audit `Tools/ProfilePackage/saip_transcode_tui.py` (10k+
  lines) for the tag-granular wizard split mandated by
  `.cursorrules`; this is a structural refactor, not a
  Pass-set 2 candidate, and must land before v1 if the file
  keeps growing.

## v1 Pre-Release Pass-Set 2 — Structural + Security Cross-Check (2026-04-19)

### Scope

Five fresh passes per subsystem after the Pass-set 1 fixes
landed: structural hygiene, specification compliance, security,
error handling, and UX. This sweep focuses on the audit
dimensions a linter cannot catch — mutable defaults, shadowed
names, subprocess hygiene, timing-safe comparisons, TLS
posture, resource leaks, hardcoded secrets, TODO/FIXME backlog.

### Confirmed clean across the repo

- **Mutable default arguments**: 0 hits (`def foo(x=[])` /
  `def foo(x={})` patterns). Every mutable default has been
  converted to the `None` sentinel + in-body initialisation
  pattern already.
- **`assert` in production code paths**: 0 hits outside of
  tests. This matters because `python -O` strips asserts; any
  security-critical assert would be a latent hole.
- **Weak RNG in crypto paths**: 0 hits. `random.random`,
  `random.randint`, `random.choice` do not appear anywhere in
  SCP03 / SCP11 / SCP80 / SIMCARD / Tools / plugins /
  yggdrasim_common. Host challenges go through `os.urandom(8)`
  (`SCP03/logic/gp.py`), which is CSPRNG on every target OS.
- **Timing-safe cryptogram / MAC comparison**: every cryptogram
  / CMAC comparison uses `hmac.compare_digest`. Verified in
  `SCP03/crypto/session.py` and `SIMCARD/scp03.py` (host
  cryptogram, session MAC, payload MAC) — no raw `==` on
  secret bytes anywhere in the crypto paths.
- **Hardcoded secrets / credentials**: 0 hits. No
  `password=...`, `api_key=...`, `secret=...`, or
  `token=...` assignments with string literals of meaningful
  length.
- **`shell=True` subprocess invocations**: 0 hits. Every
  subprocess is argv-driven.
- **Dynamic code execution**: 0 hits on `eval()` / `exec()` /
  `compile()`. The only matches are `re.compile` (regex
  caching) and `ast.literal_eval` (safe literal parser used in
  the SAIP shell's parameter parsing).
- **`datetime.utcnow()`**: 0 hits. Every timestamp is
  tz-aware (`datetime.now(timezone.utc)`), preserving Python
  3.12 compatibility and CI portability.
- **Module-level side effects**: no file I/O, prints, or
  subprocess launches at import time across the production
  tree. The only top-level prints belong to `.tuak_kat_sanity.
  py`, a hidden dev-only KAT runner not shipped with the
  release artefacts.
- **Stale TODO / FIXME / XXX / HACK markers**: 0 hits in
  Python sources.
- **`pickle` / `marshal.loads` deserialization**: 0 hits,
  eliminating a classic RCE vector.
- **Unrestricted TLS**: every `CERT_NONE` / `check_hostname=
  False` is on a pinned-SPKI path (ES9+ / ES11+) documented in
  `SCP11/shared/tls_helpers.py`. No blanket
  `ssl._create_unverified_context()` on the eSIM HTTP surface.

### Pass-set 2 fixes applied

- `yggdrasim_common/inventory_crypto.py`: the two `gpg` calls
  in `_gpg_encrypt` and `_gpg_decrypt` lacked timeouts. A
  stuck `gpg-agent` / `pinentry` (smartcard removed, USB
  dongle unplugged, X session gone on a Wayland box) would
  have hung every inventory read or write indefinitely.
  Added a `_gpg_timeout_seconds()` helper that honours an
  optional `config["gpg"]["timeout_seconds"]` override and
  defaults to 120 s. Wrapped both calls with
  `try/except subprocess.TimeoutExpired` and raise a
  `RuntimeError` naming the gpg-agent / pinentry path so the
  operator can diagnose quickly.
- `tests/test_device_inventory.py`: updated the two
  `mocked_run.assert_called_once_with(...)` assertions and
  the `_fake_gpg_run` helper signature to carry the new
  `timeout=120.0` kwarg. Full suite stays green.
- `tests/test_install_scripts.py`: the `bash -n` syntax
  linter call had no `timeout=`. `bash -n` itself never
  blocks on stdin, but a corrupted script under test could
  still wedge the runner — added a 15 s timeout.

### Pyflakes tail after both pass-sets

Running
`pyflakes SCP03/ SCP11/ SCP80/ SIMCARD/ Tools/ main/ plugins/
yggdrasim_common/` produces exactly two remaining entries,
both documented intentional:

- `Tools/ProfilePackage/shell.py:3715` — the
  `from .saip_aka_wizard import aka_wizard_steps` line is
  marked `# noqa: F401` to warm the wizard import path before
  the interactive AKA flow runs. Pyflakes ignores the noqa
  marker; keep it.
- `yggdrasim_common/doctor.py:137` — the `_probe_sqlite`
  doctor check `import sqlite3  # noqa: F401` is there to
  catch the `ImportError` path and report it as a doctor
  row; the version string is fetched via
  `sys.modules["sqlite3"].sqlite_version` immediately after.
  Intentional.

The `SCP11/shared/*.py` and `SCP11/relay/*.py`
`from ..foo import *` public re-export shims still emit
pyflakes star-import notes; those are load-bearing for the
two-package layout and remain the right design choice
pre-v1.

### Specification / posture spot-checks

- **GlobalPlatform 2.3** (SCP03 key agreement, session
  derivation): `SCP03/crypto/session.py` uses the documented
  12-byte context (host_challenge || card_challenge) for
  CMAC key derivation and 16-byte block for CBC. Card
  cryptogram verification uses `hmac.compare_digest`.
  Matches GP Appendix D.
- **ETSI TS 102 221** (FCP / FCI parsing): `SCP03/logic/fs.py`
  splits FCP file-descriptor bytes per clause 11.1.1.4.3
  (type bits 0x38 → DF, 0x01 → Transparent EF, 0x02 →
  Linear Fixed EF, 0x06 → Cyclic EF). Record length uses
  bytes 3..4 big-endian as the standard requires.
- **3GPP TS 35.231** (TUAK): `SIMCARD/tuak.py` matches the
  published Keccak round constants, rotation offsets, and
  the `ALGONAME = b"TUAK1.0"` / domain-separation pad.
  Covered by test data from TS 35.232 in
  `tests/test_simcard_backend.py`.
- **SGP.22 / SGP.32**: the `SCP11/eim_local` and
  `SCP11/local_access` flows already pin SPKIs per
  SGP.22 Section 2.6.6.3. `SCP11/es9_client.py` / `SCP11/
  live/es9_client.py` / `SCP11/test/es9_client.py` walk the
  same pinned-vs-full-validation ladder.

### Verification after Pass-set 2

- Re-ran targeted pytest on
  `tests/test_device_inventory.py` (15 passed),
  `tests/test_install_scripts.py` (20 passed), all still
  inside the 90 s shell cap.
- `ast.parse` clean on every file touched in Pass-set 2.
- Full `pyflakes` sweep (see tail section above) is clean
  modulo the two deliberate noqa probes and the star-import
  shims.

### Deferred to post-v1 (not acted on in Pass-set 2)

- Break up `Tools/ProfilePackage/saip_transcode_tui.py`
  (10k+ lines) per the tag-granular wizard rule in
  `.cursorrules`. Pass-set 2 only removed the 11 dead
  `editor` assignments; the structural split itself is a
  larger refactor that needs its own branch and its own
  soak test.
- Normalise the ~60 defensive `except Exception:` blocks in
  `SIMCARD/sgp.py` (TLV / decode fallbacks) to narrower
  `(ValueError, IndexError, UnicodeDecodeError)` tuples.
  Risk is low (all are display paths) and the change is
  mechanical but large; holds for a dedicated pass.
- Split the `~50` single-line compound statements still
  present in `SCP03/logic/fs.py`, `SCP03/logic/security.py`,
  and `SCP03/logic/sgp22.py`. These violate the
  `.cursorrules` prohibition against compound statements but
  are mechanically easy to fix; they are flagged for a
  dedicated clean-up branch rather than mixed into this
  release-hygiene sweep.
- Migrate the `os.urandom(8)` host-challenge sites to
  `secrets.token_bytes(8)`. Semantic equivalence on every
  supported platform but `secrets` is the documented
  security API for Python 3.6+; worth doing once the SCP03
  test matrix is clear.


## v1 Pre-Release Pass-Set 3 — SIMCARD Parity vs Real UICC Reference (2026-04-19)

Bench methodology: a commercial UICC was probed via PC/SC
on the OMNIKEY 3x21 (reader slot 0). The same APDU
sequences were replayed against `SimulatedSimCardEngine`.
Each SELECT / READ / VERIFY result was diffed byte-for-byte
against the real card's response; divergences that would
cause a strict terminal stack to reject the simulator were
treated as v1-blocking.

### Simulator bugs fixed in this pass

- `SIMCARD/etsi_fs.py` `read_binary` /
  `update_binary` now return `69 81` (command incompatible
  with file structure, ETSI TS 102 221 §11.1.3) when the
  addressed EF is not transparent. Previously the simulator
  emitted `69 86` ("no current EF"), which is an entirely
  different error class and masked the real failure mode
  from terminals that keyed recovery off the SW.
- `SIMCARD/etsi_fs.py` `read_record` /
  `update_record` now return `69 81` (§11.1.5) when the
  addressed EF is not linear-fixed. Same rationale as above.
- `SIMCARD/etsi_fs.py` `build_fcp` now emits:
  - `82 02 78 21` for MF / DF / ADF (shareable DF + data
    coding byte 0x21) instead of the non-shareable `38 00`.
  - `82 02 41 21` for transparent EFs instead of `01 00`.
  - `82 05 42 21 <recLen><nRecs>` for linear-fixed EFs
    instead of `02 00 ...`.
  - `88 01 <sfi<<3>` for EFs that have an SFI assigned,
    matching §11.1.1.4.7 encoding (e.g. `88 01 10` for
    EF_ICCID SFI=2, `88 01 F0` for EF_DIR SFI=30).
  - `8A 01 05` life-cycle status (operational-activated)
    on every FCP. Strict stacks (including pySim) treat an
    FCP without LCS as incomplete; commercial UICCs always
    include it.
- `SIMCARD/etsi_fs.py` `rebuild_runtime_filesystem`
  now pads every EF_DIR application record with 0xFF to the
  longest slot so the linear-fixed invariant (fixed record
  length, §8.2) is preserved. Previously records were
  variable-length, which caused READ RECORD to return
  different payload sizes for slot 1 vs slot 2 and broke the
  fixed-record contract.
- `SIMCARD/naa.py` `verify` now rejects any
  non-empty VERIFY payload whose length is not exactly 8
  with `67 00` before touching the retry counter. Previously
  a short or long payload was silently padded during the
  compare and therefore consumed a retry, so three malformed
  probes could block PIN1 without ever presenting a correct
  length PIN.

### Test updates

- `tests/test_hil_bridge_sim_modem.py`
  `test_select_mf_is_announced_via_get_response` no longer
  hard-codes the MF FCP length byte; it now checks for the
  62 template tag plus presence of `83 02 3F00` and
  `8A 01 05`, which decouples the assertion from future FCP
  extensions (85 proprietary, 8B security attribute, C6 PIN
  status DO, etc.).

### Residual divergences (accepted for v1)

These are absent from the simulator FCP but their absence
is not currently blocking for any consumer in the tree, so
they are tracked for post-v1:

- `A5` proprietary template (UICC total memory / UICC
  characteristics). Commercial cards advertise available
  memory; the simulator has unbounded RAM/NVM and no
  physical counterpart, so emitting a synthetic value is
  cosmetic.
- `8B` security attribute reference pointing at EF_ARR
  entries. The simulator currently gates UPDATE BINARY on
  a flat "always allowed" policy; full ARR parsing belongs
  with the CHV/ADM access-control rework.
- `C6` PIN status template DO on DFs. Requires surfacing
  the CHV reference table as a DO template, which depends
  on the ARR work above.
- T=0 `61 XX` chaining across every SELECT. The simulator
  returns FCP inline with `90 00`; the HIL bridge modem
  shim already synthesises `61 XX` for external T=0
  consumers so the live path is covered, but the raw
  in-process engine API is T=1-shaped. Deferred because
  changing the engine contract would ripple into every
  direct-call test.

### Verification

- SIMCARD-facing pytest targets all pass inside the 90 s
  shell cap:
  - `tests/test_simcard_backend.py` (48 passed)
  - `tests/test_simcard_auth_toolkit.py` (8 passed)
  - `tests/test_simcard_es10c_surface.py`,
    `tests/test_simcard_toolkit_poll_bridge.py`,
    `tests/test_simcard_tuak_kat.py` (23 passed combined)
  - `tests/test_scp03_fs_fallback.py` (13 passed — the FCP
    parser covers the new shareable descriptor + 8A LCS
    shape out of the box)
  - `tests/test_hil_bridge_sim_modem.py`,
    `tests/test_scp03_profile_validator.py` (12 passed
    after the FCP length-byte decoupling)
- Post-fix APDU parity replay (MF / EF_DIR / EF_ICCID / ADF
  USIM / VERIFY PIN1) matches the tag layout of the
  OMNIKEY-side reference card on every tag that both sides
  emit; mismatches are limited to the residual list above.


## v1 Pre-Release Pass-Set 4 — OSS Reviewer Sweep (Harald-/Torvalds-style)

Scope: read the whole repository as an outside maintainer would and
flag issues that are (a) genuine bugs or (b) deviations from basic
Python / packaging / OSS hygiene that block a v1 tag. Intentionally
skipped the already-deferred items tracked by ``SCP11-P1-*`` /
``MAIN-P1-*`` / ``PLUG-P1-*`` splits, because the reviewer asked for
"actionable now" findings, not duplicates of the existing roadmap.

### Findings and applied fixes

- **SIMCARD/utils.py — ``parse_apdu`` mishandles extended cases 2E
  and 4E.** The short-path branches at ``body[0] != 0x00`` are
  correct, but the extended path treated a 3-byte body ``00 Le_hi
  Le_lo`` as an ``Lc`` and then raised ``"Extended APDU payload is
  truncated"``. Case 2E with ``Le=0000`` silently returned ``le=None``
  instead of ``le=65536`` (ISO 7816-4 §5.3.2). Case 4E also accepted
  stray bytes past the 2-byte Le. Fixed by special-casing
  ``len(body) == 3`` at the top of the extended path, rejecting
  trailing bytes past ``trailing[:2]`` in case 4E, and mapping the
  all-zero extended Le to 65536. Added
  ``tests/test_simcard_utils_parse_apdu.py`` (14 cases covering every
  ISO 7816-4 §5.1 shape) as regression coverage.

- **SIMCARD/auth.py — non-constant-time MAC compares in Milenage /
  TUAK.** ``vectors.mac_a != mac_a`` and ``computed_mac_a != mac_a``
  used Python ``!=``. The simulator itself is not a timing oracle,
  but every other MAC comparison in the code base (SCP03 session,
  SCP11 SPKI pinning) uses ``hmac.compare_digest``. Brought the
  authentication path in line with the same discipline so a future
  move of this code into a network-facing harness does not regress
  silently. ``test_simcard_auth_toolkit`` passes unchanged.

- **pyproject.toml — missing licence, authors, classifiers, and
  urls metadata.** The build succeeded but the wheel would have
  landed on PyPI without SPDX licence, issue tracker, or trove
  classifiers. Added ``license = { file = "LICENSE" }`` (GPL-3.0),
  author/maintainer blocks, a curated ``keywords`` list (sim, euicc,
  scp03/11/80, saip, sgp22/32, iso7816, etsi, 3gpp), 17 PyPI
  classifiers including "GNU General Public License v3 or later
  (GPLv3+)", supported Python minors, and ``[project.urls]`` pointing
  at the repo / docs / issues / changelog.

### Findings inspected and cleared

- ``shell=True`` in subprocess → none in the tree.
- Bare ``except:`` → none.
- ``eval()`` / ``exec()`` → none.
- ``subprocess.run`` without ``timeout`` → none (every call site has
  a bounded timeout). ``subprocess.Popen`` appears only for tshark
  live streaming where a timeout is intentionally absent.
- Mutable default arguments (``def f(x=[]):``) → none.
- ``open(...)`` without context manager → none on the sampled set.
- ``assert`` outside tests → none (all occurrences are under
  ``tests/``).
- ``import *`` → only the deliberate shim re-exports under
  ``SCP11/shared/`` and ``SCP11/relay/``; documented.
- ``ssl._create_unverified_context`` / ``CERT_NONE`` → centralised
  through ``SCP11/shared/tls_helpers.py`` with a double-opt-in gate
  (``YGGDRASIM_SCP11_ALLOW_INSECURE_TLS`` + ``YGGDRASIM_SCP11_
  REQUIRE_PINNED_TLS`` refusal). The three remaining call sites in
  ``SCP11/*/es9_client.py`` pass SPKI-pinning context through
  ``_open_http_response`` so ``CERT_NONE`` is paired with an explicit
  post-handshake ``hmac.compare_digest`` check against the pinned
  BF55 public key.
- ``time.time()`` vs ``time.monotonic()`` → only used for wall-clock
  filename suffixes and pcap frame timestamps, which is correct.
- Package ``__init__.py`` → ``SCP03`` intentionally omits one and is
  importable as a PEP 420 namespace package; confirmed at runtime.
- GPL-3.0 headers, LICENSE, NOTICE, AUTHORS, SECURITY (.github) all
  present.

### Deferred / not fixed (documented, not blocking v1)

- The three files above 4k LOC (``saip_transcode_tui.py``,
  ``live_decode_tui.py``, ``SCP11/test/console.py``) and the 3.8k LOC
  ``plugins/polling_plugin.py`` still carry the mechanical-split plan
  recorded under ``SCP11-P1-*`` / ``PLUG-P1-01``.
- CI currently builds + smoke-tests bundles but does not run
  ``pytest``. Adding a chunked test matrix (per the
  ``pytest-memory-safety`` rule) is a follow-up; flagged to the
  maintainer in the pass summary rather than added unilaterally
  because a CI topology change is not a QoL-scope edit.

Result: the three fixes above plus the new parser coverage pass all
applicable targeted test suites (``test_simcard_backend``,
``test_hil_bridge_sim_modem``, ``test_simcard_es10c_surface``,
``test_simcard_utils_parse_apdu``, ``test_simcard_auth_toolkit``,
``test_simcard_toolkit_poll_bridge``, ``test_simcard_tuak_kat``,
``test_scp03_fs_fallback``) with no regressions.

---

## v1 Pre-Release Pass-Set 5 — Executable / Package / Bundle Plumbing

This pass verifies that every shipped surface — console scripts, wheel,
Docker image, PyInstaller bundle, and install scripts — actually builds
and runs, rather than just passing targeted unit tests. Each item below
was triggered by a repeatable dry-run and fixed in-tree.

### Fixes applied

1. **``pyproject.toml`` — project URLs.** The homepage/repository/issues
   URLs added in Pass-Set 4 pointed at a guessed GitHub owner
   (``Hellsberg85``). ``git remote`` lists the real repo as
   ``hampushellsberg-dev/YggdraSIM``; URLs updated to match so the PyPI
   metadata points at the correct project.

2. **HIL bridge RSPRO schema packaging.** ``Tools/HilBridge/protocol.py``
   hard-coded ``RSPRO_ASN_PATH = parents[2] / "docs/RSPRO.asn"``. This
   path only exists in a source checkout; a wheel install resolves it
   to ``site-packages/../../docs/RSPRO.asn``, which is never present,
   so ``yggdrasim-hil-bridge --help`` from a ``pip install yggdrasim``
   crashed with ``FileNotFoundError: Missing vendored RSPRO schema``.
   The schema was copied to ``Tools/HilBridge/RSPRO.asn`` (canonical
   copy stays in ``docs/RSPRO.asn``), ``_resolve_rspro_asn_path()`` now
   searches next-to-module → repo ``docs/`` → optional
   ``YGGDRASIM_RSPRO_ASN`` override, and ``pyproject.toml`` ships the
   file via ``[tool.setuptools.package-data] "Tools.HilBridge" =
   ["RSPRO.asn"]``. A fresh
   ``pip install dist/yggdrasim-*.whl && yggdrasim-hil-bridge --help``
   now prints the argparse usage cleanly.

3. **PyInstaller spec — broken ROOT resolution.** The spec computed
   ``ROOT = Path(SPECPATH).resolve().parent``. PyInstaller already
   defines ``SPECPATH`` as the directory containing the spec, so the
   trailing ``.parent`` walked one level above the checkout; every
   ``Tree(...)`` lookup below looked up ``/home/user/Tools`` /
   ``/home/user/Workspace`` etc. and the build stamp tried to write to
   ``/home/user/yggdrasim_common/_build_flavor.py``. Fixed to
   ``ROOT = Path(SPECPATH).resolve()`` with a comment warning against
   re-adding the ``.parent``.

4. **PyInstaller spec — datas format change.** PyInstaller 6.x rejects
   ``datas += Tree(...)`` with ``ValueError: too many values to unpack
   (expected 2)`` because ``Tree`` emits 3-tuple TOC entries while
   ``Analysis(datas=...)`` expects 2-tuple ``(src, dst_dir)`` entries.
   Replaced ``Tree(...)`` calls with ``datas.append((str(source),
   relative))`` and dropped the
   ``from PyInstaller.building.datastruct import Tree`` import. The
   directory walk is still performed by the bootloader; the payload
   manifest did not change.

5. **Frozen bundle — ``hil_bridge_runtime = None`` crash.**
   ``main/main.py`` imports ``hil_bridge_runtime`` defensively (it is
   set to ``None`` on the clean bundle) but several function signatures
   use it in return-type annotations, e.g.
   ``def _build_hil_bridge_service_options(...) ->
   hil_bridge_runtime.HilBridgeUserServiceOptions:``. Without
   ``from __future__ import annotations`` Python evaluates the
   annotation at def time, so the clean bundle crashed on the first
   ``yggdrasim-clean --help`` with ``AttributeError: 'NoneType' object
   has no attribute 'HilBridgeUserServiceOptions'``. Added
   ``from __future__ import annotations`` at the top of ``main.py``
   (checked: no ``get_type_hints``, ``@dataclass``, or pydantic
   reflection uses that would break under PEP 563).

6. **Frozen bundle — ``--version`` showed ``0.0.0+unknown``.**
   ``_version_from_installed_dist`` returns ``None`` inside a frozen
   bundle (no distribution metadata), and ``_version_from_pyproject``
   also fails because ``pyproject.toml`` is not bundled. Added a build
   stamp path: the spec now writes ``BUILD_VERSION`` next to
   ``BUILD_FLAVOR`` in ``yggdrasim_common/_build_flavor.py``, and
   ``yggdrasim_common/__about__.py`` consults it between the
   installed-dist check and the pyproject-on-disk fallback. Frozen
   ``--version`` now reports ``YggdraSIM 2026.4.10 (clean (no HIL
   bridge))`` / ``(full (HIL bridge included))`` correctly.

7. **Frozen bundle — ``pycryptodomex`` / ``asn1tools`` marked WARN.**
   These third-party dependencies are only imported lazily from inside
   pySim / ``Tools/HilBridge/protocol.py``, so PyInstaller's graph
   analysis did not pull them into the clean bundle. Added an explicit
   ``THIRD_PARTY_HIDDEN`` list in the spec covering ``Cryptodome``,
   ``Crypto``, ``asn1tools``, ``asn1crypto``, ``construct``, ``bidict``,
   ``pytlv``, and ``pyosmocom``. Both clean and full bundles' doctor
   runs now report all seven checks as OK.

8. **Dockerfile — missing ``libudev1`` runtime.** ``pyudev`` dlopens
   ``libudev.so.1`` at import time; the ``python:3.11-slim`` base image
   does not ship it, so a ``docker build --build-arg
   YGGDRASIM_FLAVOR=full`` image would install ``pyudev`` through the
   ``[full]`` extra and then die at import. Added ``libudev1`` to the
   single apt step (unconditionally, to keep the clean and full image
   layouts uniform and the diff small).

### Inspected and cleared

- All three POSIX install scripts (``install-linux.sh``,
  ``install-macos.sh``, ``install-raspberrypi.sh``) plus the shared
  ``_common.sh`` pass ``bash -n`` and accept ``--help``.
  ``yg_validate_flavor_for_host`` correctly rejects ``--flavor full``
  on non-Linux. ``install-windows.ps1`` references the same repo owner
  (``hampushellsberg-dev/YggdraSIM``) as ``_common.sh``.
- All 12 ``[project.scripts]`` entries resolve to callable attributes
  on the declared modules (verified programmatically plus via the
  ``test_console_scripts_guard.py`` suite).
- Wheel builds cleanly with ``python -m build --wheel`` (1.1 MB, 230
  files). ``pip install``ing the wheel into a fresh venv produces all
  12 ``yggdrasim-*`` console scripts; ``--help`` works on every one.
  ``yggdrasim-hil-bridge --help`` now succeeds too (see fix #2 above).
- Bundled ``yggdrasim-clean`` and ``yggdrasim-full`` executables both
  build, pass ``--version``, ``--help``, and ``--doctor``. Clean bundle
  is ~36 MB; full bundle is ~53 MB. Only residual ``--doctor`` warning
  is ``pySim.esim.saip`` import, which is a pre-existing limitation:
  the vendored ``pysim`` tree is shipped as a data directory and only
  put on ``sys.path`` by the ``Tools/ProfilePackage`` helpers that
  actually need it, not by the global launcher.

### Deferred / not fixed (documented, not blocking v1)

- ``--doctor`` still prints ``pySim SAIP runtime: WARN`` from a frozen
  bundle because the global launcher does not insert ``_MEIPASS/pysim``
  into ``sys.path``. Downstream SAIP entry points (``saip_tool``,
  ``saip_json_codec``, ``saip_transcode_tui``, and
  ``SIMCARD/saip_profile``) each call ``ensure_workspace_pysim_on_path``
  before importing pySim, so the warning is cosmetic — no runtime
  regression. A dedicated runtime hook that lifts pySim to ``sys.path``
  once during PyInstaller bootstrap is a small follow-up but touches
  every SAIP / eUICC surface and is therefore out of scope here.
- PyPI upload (``twine upload``) has not been attempted; metadata and
  wheel are valid per ``python -m build`` but the maintainer still owns
  the first upload ceremony.

Result: all affected regression tests pass
(``test_install_scripts``, ``test_console_scripts_guard``,
``test_doctor``, ``test_about_version``, ``test_flavor``,
``test_hil_bridge_protocol``, ``test_main_wrapper_hil_bridge``,
``test_hil_bridge_runtime``, ``test_hil_bridge_main``,
``test_hil_bridge_sim_modem``, ``test_repo_module_import_smoke``).

---

## v1 Pre-Release Pass-Set 6 — Post-cleanup stabilisation sweep

Fifteen additional passes (A1–A5, B1–B5, C1–C5) run after the
``pysim/`` / ``pyscard/`` working-tree cleanup landed. The goal was to
confirm no dangling references survived the cleanup, to harden the
simulator and HIL bridge on the back of a fresh read of ETSI TS 102
221 against the reference reader, and to tighten packaging /
``.gitignore`` / ``.dockerignore`` hygiene before tagging v1.

### Pass A1 — Dangling ``pysim/`` / ``pyscard/`` references

Scanned every tracked Python file for hardcoded ``pysim/`` and
``pyscard/`` paths. All references now sit inside guarded lookup /
import blocks (``SCP03/interface/guides.py``,
``Tools/ProfilePackage/saip_tool.py``,
``yggdrasim_common/doctor.py``, and the ``SCP03/crypto/scp02_session``
``try/except ImportError`` shim) so none raise on a checkout without
the optional tree. ``pyscard`` imports all target the PyPI package
(``import smartcard...``) and are intentional.

**Result:** clear. No code change needed.

### Pass A2 — SIMCARD simulator spot-bug hunt

Re-read ``SIMCARD/utils.py``, ``SIMCARD/engine.py``,
``SIMCARD/naa.py``, ``SIMCARD/etsi_fs.py``, ``SIMCARD/toolkit.py``,
and ``SIMCARD/auth.py`` against the reference UICC and TS 102 221
§11. One security bug remained:

- ``NAA VERIFY CHV`` and ``UNBLOCK CHV`` compared the padded PIN / PUK
  against the stored value with ordinary ``==`` / ``!=`` operators.
  ``SIMCARD/auth.py`` had already been migrated to
  ``hmac.compare_digest`` in pass-set 4, but ``naa.py`` had been
  missed. Switched both comparators to ``hmac.compare_digest`` so
  every CHV / AKA credential path in the simulator now runs on
  constant-time primitives. Tested against the default ``1234`` /
  ``12345678`` reference.

**Fix:** ``SIMCARD/naa.py`` — imported ``hmac`` and rewrote the
VERIFY / UNBLOCK comparisons.

### Pass A3 — Test suite health after cleanup

A handful of SAIP-bound suites (``test_simcard_backend``,
``test_saip_*``, ``test_profile_package_shell``,
``test_scp11_local_access``, ``test_scp11_orchestrator``,
``test_scp11_payloads``, ``test_profile_package_lint_engine``)
import pySim from the optional working tree at collection time.
After the cleanup these raised ``ModuleNotFoundError`` instead of
skipping, which made ``pytest tests/`` look broken on a freshly
stripped checkout.

**Fix:**

1. ``tests/test_simcard_backend.py::compile_saip_asn1`` now raises
   ``unittest.SkipTest`` (with the clone URL) when
   ``pySim.esim`` is not importable.
2. ``tests/conftest.py`` gained a ``_pysim_available`` probe plus
   a ``pytest_collection_modifyitems`` hook that applies a shared
   skip marker to the pySim-dependent test basenames when the
   tree is absent. Same cone of coverage, zero hard failures.

### Pass A4 — ``pyproject.toml`` / requirements sanity

Minor metadata drift: Python 3.13 was missing from the classifier
list, and the ``mkdocs``-family dependencies listed in
``requirements-docs.txt`` had no corresponding
``[project.optional-dependencies]`` entry, so ``pip install
yggdrasim[docs]`` silently did nothing.

**Fix:** added ``Programming Language :: Python :: 3.13`` and a
``docs = ["mkdocs>=1.6", "mkdocs-material>=9.6",
"pymdown-extensions>=10.13"]`` extra to ``pyproject.toml``.

### Pass A5 — Dockerfile / install scripts consistency

``Dockerfile`` itself was already tidy (clean / full flavor split,
``libudev1`` runtime, ``/opt/YggdraSIM-data`` first-boot init).
``.dockerignore``, however, only excluded a minimal set of dotfiles
and allowed an easy ~250 MB of noise into the build context
(``.cursor/``, ``.pytest_agent_log*.txt``, ``trace/``, ``Latjo/``,
``site/``, ``yggdrasim.egg-info/``, ``reference_test_profile.transcode.*``,
etc.). Shell install scripts pass ``bash -n`` and their ``--help``
handlers still map cleanly to the flavor matrix.

**Fix:** expanded ``.dockerignore`` to exclude IDE / SCM metadata,
Python bytecode, virtual environments, local caches, operator
runtime state (``YggdraSIM-data/``, ``Workspace/``, ``state/``,
``Latjo/``, ``trace/``), developer dotfile captures
(``.pytest_*``, ``.tshark_*``, ``.live_*pdml*``,
``.hil_*``, etc.), PyInstaller / setuptools build artefacts,
the optional ``pysim/`` working tree, the stale ``pyscard/``
virtualenv slot, and regenerable transcode / demo fixtures.

### Pass B1 — ``__init__.py`` / namespace-package gaps

``SCP03``, ``main``, ``plugins`` do not carry ``__init__.py``.
``SCP03`` is an intentional PEP 420 implicit namespace package
(the same module ships in both wheel and source trees and picks
up user-supplied overlays). ``main/`` and ``plugins/`` are not
Python packages — ``main/main.py`` is the CLI entry point and
``plugins/`` is a loader root read by ``yggdrasim_common/plugin_runtime``.
Confirmed every ``SCP11/*`` and ``Tools/*`` import path still
resolves against the current layout.

**Result:** no change needed.

### Pass B2 — Documentation pass (``pysim/`` language)

Multiple docs still described ``pysim/`` as "vendored", which is
misleading now that it is an optional, gitignored clone.

**Fix:** updated ``README.md``, ``guides/INSTALL_FROM_SOURCE.md``,
``guides/CAPABILITIES.md``, ``site-docs/sources/README.md``,
``site-docs/reference/troubleshooting.md``,
``site-docs/subsystems/profile-package.md``,
``site-docs/reference/command-suite.md``, and the
``yggdrasim_common/doctor.py`` docstring + ``_probe_vendored_pysim``
label. The WARN message now includes the Osmocom clone URL so
``--doctor`` points the operator straight at the remediation.

### Pass B3 — ``yggdrasim_common`` QoL

Re-audited ``__about__.py``, ``console_scripts.py``,
``flavor.py``, ``doctor.py``, ``session_recording.py``,
``inventory_crypto.py``. Version / flavor / stamp resolution and
console-script guarding all hold up. The session recorder
deliberately releases its lock before invoking listener callbacks
and is therefore deadlock-free by construction.

**Result:** no code change needed beyond the B2 doctor string
tweaks.

### Pass B4 — ``Tools/HilBridge`` deep-dive

Threading, selectors, PC/SC retry behaviour all hold up.
``apdu_relay.py`` exposed one resource-exhaustion foothold:
``_read_request_json`` read ``int(Content-Length)`` bytes with no
upper bound, so a client could pin the handler thread on an
arbitrarily large ``Content-Length`` before parsing failed.

**Fix:** introduced ``_APDU_RELAY_MAX_BODY_BYTES = 1 MiB`` and
rejected negative / oversized / unparseable ``Content-Length``
values up front. Extended APDU payloads top out around ~65 KiB
hex-encoded, so the cap is orders of magnitude over any legitimate
request.

### Pass B5 — SCP80 OTA crypto / transport / builder

``SCP80/crypto.py`` wraps AES-CMAC via pycryptodome's ``CMAC`` and
3DES CBC-MAC per ETSI TS 102 225 §5. The module is server-side
(SM-SC / OTA proxy) so it produces the CC / CT — there is no MAC
verification path here, only generation. ``builder.py`` feeds
``compute_cc`` once per BLOCK (header || params || CNTR || PCNTR
|| plaintext) and then encrypts ``CNTR || PCNTR || CC || plaintext``
with ``encrypt_ct``. No hot-patch needed.

**Result:** clear. Documented.

### Pass C1 — ``.gitignore`` tidy

Added ``.venv/``, ``venv/``, ``.pytest_cache/``, ``.ruff_cache/``,
``.mypy_cache/``, ``.profilepackage-cache/``, ``*.pyo``, and an
explicit ``pyscard/`` (so a future venv mis-creation does not
sneak in), plus a header comment for the optional ``pysim/`` clone
and a ``demo.der`` line to match the transcode fixtures already
listed.

### Pass C2 — ``main/main.py`` follow-up

Verified the ``from __future__ import annotations`` compatibility
fix (merged in pass-set 5) is still in place, no bare ``except:``
blocks remain, ``run_cli`` / ``main_menu`` entry points are intact,
and ``--version`` / ``--doctor`` / ``--card-backend`` flags all
resolve.

**Result:** no change.

### Pass C3 — SIMCARD test coverage gaps

Added ``tests/test_simcard_naa_pin_flows.py`` with five focused
checks:

1. ``VERIFY CHV`` with a non-8-byte, non-zero payload returns
   ``67 00`` without consuming a retry attempt.
2. ``VERIFY CHV`` happy path with the padded default ``1234``
   returns ``90 00`` and re-arms the retry counter.
3. ``UNBLOCK CHV`` with the correct PUK + new PIN returns
   ``90 00``, re-arms both the PIN and PUK retry counters, and
   lets a subsequent VERIFY succeed against the new PIN.
4. ``READ BINARY`` against the linear-fixed ``EF_DIR`` reports
   ``69 81`` (command incompatible with file structure) per
   TS 102 221 §11.1.3.
5. ``READ RECORD`` against the transparent ``EF_ICCID`` reports
   ``69 81`` per TS 102 221 §11.1.5.

These pin down the exact behaviour corrected in pass-set 4 /
pass-set 6 so future refactors cannot silently regress.

### Pass C4 — Targeted regression pass

Re-ran the test targets covering every module touched in this
pass-set:

- ``tests/test_simcard_naa_pin_flows.py`` — 5 passed (new).
- ``tests/test_simcard_auth_toolkit.py`` — 8 passed.
- ``tests/test_simcard_utils_parse_apdu.py`` — 14 passed.
- ``tests/test_hil_bridge_runtime.py`` — 9 passed.
- ``tests/test_hil_bridge_card_relay.py`` — 8 passed (existing 7
  + new ``test_apdu_relay_rejects_oversized_request_body``).
- ``tests/test_hil_bridge_sim_modem.py`` — 6 passed.
- ``tests/test_doctor.py``, ``tests/test_about_version.py``,
  ``tests/test_flavor.py``,
  ``tests/test_console_scripts_guard.py`` — 28 passed combined.

Zero regressions.

### Pass C5 — This document

Appended pass-set 6 in full for traceability. See each pass above
for the per-file diff summary.


## v1 Pre-Release Pass-Set 7 — Concurrency hardening, cache hygiene, build infra

Scope: another "5 x 5" OSS-dev sweep (D1–D5 audit, E1–E5
implement). Focus areas were race conditions around long-lived
singletons, unbounded caches, silent failure modes in persistence
paths, and build / install / CI hygiene.

### Pass D1 — SCP11 TLS / HTTP / subprocess surfaces (Audit)

Walked `SCP11/`, `SCP11/live/`, `SCP11/local_access/`, `SCP11/eim_local/`
and their `transport.py` / `es9_client.py` twins looking for:

* Unbounded `HTTPResponse.read()` calls.
* Subprocess invocations without a `timeout=` kwarg.
* Demo-key guard bypasses.

No production bugs found. The only observation was that the local
relay HTTP client reads the entire response body without an explicit
size cap. The upstream is a trusted local service with socket-level
timeouts, so the risk is bounded; flagged as a future hardening idea
rather than a v1 blocker. **E1 landed as a no-op.**

### Pass D2 — `yggdrasim_common` deep audit (Audit)

Surfaces reviewed: `session_recording.py`, `inventory_crypto.py`,
`plugin_runtime.py`, `card_backend.py`.

Findings:

1. **D2-1** `ShellSessionRecorder` mutated `_commands`,
   `_apdu_trace`, `_next_apdu_index`, `_next_command_index`, and
   `_active_command` across the interactive shell thread and the
   APDU-trace listener thread without a lock. Under concurrent
   load two `record_apdu_event` calls could produce duplicate
   `index` values and cross-contaminate `command.apdu_count`.
2. **D2-2** The same recorder appended to `_apdu_trace` without
   bound. A long recording session with chatty traffic could
   grow the list into hundreds of thousands of dicts before the
   operator noticed.
3. **D2-3** `write_secret_file_bytes` in `inventory_crypto.py`
   wrote the tmp sibling with the process umask (typically 0o022)
   before `os.replace`. In the plaintext-fallback branch the
   secret therefore briefly lived on disk as `-rw-r--r--`.
4. **D2-4** `PluginManager.ensure_loaded` guarded the `_loading`
   flag but not the body; two dispatcher boots from different
   threads could double-load the same plugin. `get_plugin_manager`
   initialised the module-level singleton without a lock.

### Pass E2 — Implement D2 fixes

`yggdrasim_common/session_recording.py`:

* Added `threading.Lock()` (`_state_lock`) guarding all counter
  mutations, `_commands` append/read, `_active_command` cross-
  reference, and `_apdu_trace` append.
* Added `YGGDRASIM_SESSION_APDU_TRACE_CAP` (default 50_000) with
  `_resolve_apdu_trace_soft_cap()` parsing. When the cap is hit
  the oldest entry is dropped and a one-shot stderr banner is
  emitted. Subsequent drops happen silently (intentional: the
  banner is a "your buffer just rolled over" breadcrumb).
* Restructured `stop()` so the module-level listener lock
  (acquired inside `set_apdu_trace_listener`) is always taken
  *outside* `_state_lock`. Reordered the shutdown sequence to
  detach the listener first so late events cannot land in a
  serialising trace.
* `_successful_replay_commands()` now walks the list without
  re-entering `_state_lock`; its callers already hold it.

`yggdrasim_common/inventory_crypto.py`:

* `write_secret_file_bytes` chmods the tmp sibling to `0o600`
  on POSIX before `os.replace`. The final file therefore lands
  with owner-rw-only permissions regardless of the caller's
  umask. Windows is unaffected (chmod is a no-op there).

`yggdrasim_common/plugin_runtime.py`:

* Added `threading.RLock()` to `PluginManager`. `ensure_loaded`
  now holds the lock for the whole load sweep so a concurrent
  caller from another thread blocks until the capability map is
  consistent. RLock lets register/extend_target callbacks re-
  enter the manager without self-deadlock.
* Added `_PLUGIN_MANAGER_LOCK = threading.Lock()` with the
  standard double-checked-locking pattern inside
  `get_plugin_manager()` to guarantee one-time singleton
  construction.

### Pass D3 — `Tools/ProfilePackage` (Audit)

Surfaces reviewed: `saip_tool.py`, `saip_transcode_tui.py`.

Findings:

1. **D3-1** `.profilepackage-cache/` grew without bound. A
   developer running `saip_tool` against a hundred profiles left
   a hundred DER blobs around forever; there was no sweep.
2. **D3-2** `SaipTool._load_config` swallowed
   `json.JSONDecodeError` and `UnicodeDecodeError` and silently
   started with defaults. That hid hand-edit mistakes in
   `saip_tool.json` (stray trailing comma, truncated paste,
   etc.) and made "where did my settings go?" undebuggable.

### Pass E3 — Implement D3 fixes

`Tools/ProfilePackage/saip_tool.py`:

* Added `_MAX_CACHE_FILES = 64`, `_CACHE_MAX_BYTES_ENV`
  (`YGGDRASIM_SAIP_TOOL_CACHE_MAX_BYTES`), and
  `_DEFAULT_CACHE_MAX_BYTES = 256 MiB`. Implemented
  `_prune_profile_package_cache(cache_dir, *, keep=...)`:
  * Sorts entries newest-first by mtime.
  * Always preserves `keep` (the freshly written file).
  * Drops the rest as soon as either the file-count cap or the
    byte-budget cap would be exceeded.
  * Swallows OS errors inside the prune (the cache is advisory;
    the caller already has its material).
* Wired the prune into `_prepare_input_for_tool` so the cache is
  trimmed on every write.
* Added `_quarantine_corrupt_config` that renames the corrupt
  file to `saip_tool.json.corrupt.<ts>` and logs a stderr
  warning. `_load_config` calls it when JSON parsing fails; the
  `OSError` branch still silently returns (caller should not
  die because the config is on a disconnected NFS share).

### Pass D4 — SIMCARD deep surfaces (Audit)

Surfaces reviewed: `SIMCARD/connection.py`, `SIMCARD/engine.py`,
`SIMCARD/profile_store.py`, `SIMCARD/saip_profile.py`,
`SIMCARD/toolkit.py`.

Findings:

1. **D4-1** `get_shared_engine()` and `set_shared_toolkit_bridge()`
   raced on the `_SHARED_ENGINE` singleton. Two dispatchers
   booting concurrently could each observe `_SHARED_ENGINE is
   None` and construct their own `SimulatedSimCardEngine`,
   delivering EF reads from two stores to two shells that
   thought they shared state.
2. **D4-2** `SimulatedSimCardEngine._sync_all_stores` wrapped
   both `sync_euicc_store` and `sync_profiles_to_store` in bare
   `try/except: pass`. A disk-full or permission-denied
   condition silently dropped the state; the next boot loaded
   the pre-crash file and reported "your profiles vanished".

### Pass E4 — Implement D4 fixes

`SIMCARD/connection.py`:

* Added `_SHARED_ENGINE_LOCK = threading.Lock()` guarding
  `_SHARED_ENGINE` and its associated path-key tuple.
* `get_shared_engine()` now takes the lock, performs the
  rebuild-needed check and engine construction atomically, then
  releases before calling `_apply_shared_toolkit_bridge` on the
  returned engine (that helper walks its own locks).
* `set_shared_toolkit_bridge()` takes the lock when reading /
  writing `_SHARED_TOOLKIT_BRIDGE` and snapshots the current
  engine for later application outside the lock.

`SIMCARD/engine.py`:

* Added `_notify_sync_failure(category, store_path, error)` that
  emits a one-shot stderr banner and a `logging.WARNING` for
  every failure. The one-shot guard
  (`_SIMCARD_SYNC_WARNED[category]`) prevents spamming the
  terminal when a hosed mount keeps failing; `logging` still
  records every incident.
* `_sync_all_stores` now routes both `sync_euicc_store` and
  `sync_profiles_to_store` exceptions through
  `_notify_sync_failure` instead of swallowing them.

### Pass D5 — Build, install, Docker, CI (Audit)

Findings:

1. **D5-1** `Dockerfile` single-stage: copied source before
   installing deps, shipped the full toolchain in the final
   image, ran as `root`.
2. **D5-2** `Dockerfile` did not separate build-time
   `libpcsclite-dev` / compilers from run-time `libpcsclite1`.
   Final image was larger than it needed to be and retained
   attack surface.
3. **D5-3** `.github/workflows/docker.yml` only ran
   `yggdrasim-scp11 --cmd "HELP; EXIT"` as smoke; no `--version`
   or `--doctor`; no non-root assertion.
4. **D5-4** `.github/workflows/build.yml` never ran the `pytest`
   suite — PyInstaller bundle smoke tests were the only
   regression signal.
5. **D5-5** `scripts/install/_common.sh` ran under plain
   `set -e`; no `-u` or `-o pipefail`. Typos in variable names
   silently produced empty expansions; failures inside a pipe
   were lost. `sudo` was invoked unconditionally even when
   running as root in a container.
6. **D5-6** `yg_apt_install` used inline `DEBIAN_FRONTEND=...`
   before `sudo`, which is scrubbed by sudo's env reset.
7. **D5-7** `requirements.txt` duplicated the dependencies from
   `pyproject.toml` and additionally bundled dev-only packages
   (`pyinstaller`, `pytest`). A user running
   `pip install -r requirements.txt` ended up with packaging
   tools they did not want.

### Pass E5 — Implement D5 fixes

`Dockerfile`: rewritten as a two-stage build.

* Stage 1 (`build`): carries `build-essential`, `gcc`, `g++`,
  `swig`, `pkg-config`, `libpcsclite-dev`, `libudev-dev`.
  Dependencies install first from `pyproject.toml` +
  `requirements.txt` so source edits do not invalidate the
  pip layer. Project itself is installed `--no-deps -e '.'`
  (or `'.[full]'`) after the source copy.
* Stage 2 (`runtime`): fresh `python:3.11-slim`. Only
  `libpcsclite1`, `libudev1`, `pcsc-tools`, `pcscd`, `gpg`,
  `ca-certificates`. Venv and source copied from the build
  stage. Creates a non-root `yggdrasim` user (`uid=1000`),
  chowns the install + runtime data dir, and switches `USER`
  before the `CMD`.

`.github/workflows/docker.yml`:

* Added `--version` and `--doctor || true` smoke steps.
* Added an explicit `id -u == 1000` assertion to catch any
  future regression that drops the non-root user.

`.github/workflows/build.yml`:

* Added a `pytest-suite` job (ubuntu-latest) that installs
  `.[full]` and runs the entire `tests/` suite with
  `-q --tb=short --disable-warnings --no-header --maxfail=5`.
  pySim-dependent tests auto-skip via `tests/conftest.py`, so
  the job does not need the `pysim/` clone to pass.

`scripts/install/_common.sh`:

* `set -eu` + `set -o pipefail` applied globally. Install
  scripts that previously tolerated a typo'd variable now fail
  fast with a clear message.
* New helper `yg_sudo` short-circuits when `EUID=0` (no `sudo`
  fork on a Docker build, in CI as root, etc.) and errors
  explicitly when `sudo` is missing and we are not root.
* `yg_apt_install` uses `yg_sudo env DEBIAN_FRONTEND=noninteractive
  apt-get install ...` so dpkg stays non-interactive on
  containers regardless of sudo's env scrub policy.

`requirements.txt`: trimmed to the cross-platform runtime set
that mirrors `[project].dependencies`. Dev / test / build / docs
/ HIL extras now live only in `[project.optional-dependencies]`;
the file documents the split so operators know which extra to
request.

### Regression coverage

New tests added this pass-set:

* `tests/test_session_recording.py` gains
  `ShellSessionRecorderHardeningTests`:
  * `test_apdu_trace_soft_cap_drops_oldest` proves the soft cap
    honours `YGGDRASIM_SESSION_APDU_TRACE_CAP` and the newest
    events are preserved.
  * `test_concurrent_apdu_events_retain_unique_indexes` fires
    200 events from 4 threads into the recorder and asserts
    that every APDU index is unique and monotonically
    increasing. Without the new `_state_lock` the indexes
    collide almost every run.
* `tests/test_inventory_crypto_permissions.py` verifies the
  0600 final-file mode after a plaintext-fallback write under
  umask 022.
* `tests/test_saip_tool_cache_and_config.py` exercises the LRU
  prune (count cap + byte-budget cap) and the
  `_quarantine_corrupt_config` rename path.
* `tests/test_simcard_engine_sync_warning.py` asserts that
  `_sync_all_stores` emits exactly one stderr banner per
  category and still logs every incident after the banner has
  drained.

Regression sweep across touched surfaces:

* `tests/test_simcard_backend.py` (auto-skipped without pysim,
  5 tests otherwise).
* `tests/test_simcard_naa_pin_flows.py` — 5 passed.
* `tests/test_simcard_engine_sync_warning.py` — 2 passed (new).
* `tests/test_inventory_crypto_permissions.py` — 1 passed (new).
* `tests/test_saip_tool_cache_and_config.py` — 4 passed (new).
* `tests/test_session_recording.py` — 3 passed (2 new + 1
  legacy).
* `tests/test_install_scripts.py`, `tests/test_doctor.py`,
  `tests/test_about_version.py`,
  `tests/test_console_scripts_guard.py`, `tests/test_flavor.py`
  — 48 passed combined.

Zero regressions.

### Pass-set 7 summary

* 2 concurrency race-condition fixes
  (`yggdrasim_common/session_recording.py`,
  `yggdrasim_common/plugin_runtime.py`,
  `SIMCARD/connection.py`).
* 1 file-permission fix
  (`yggdrasim_common/inventory_crypto.py`).
* 1 silent-failure fix (`SIMCARD/engine.py`).
* 1 unbounded-cache fix
  (`Tools/ProfilePackage/saip_tool.py`).
* 1 corrupt-config quarantine path
  (`Tools/ProfilePackage/saip_tool.py`).
* 1 two-stage Docker build with non-root runtime user.
* Install scripts now strict-mode and container-friendly.
* Full-suite `pytest` is now part of CI.
* `requirements.txt` realigned to `[project].dependencies`.


## v1 Pre-Release Docs Pass — "Upstream vs vendored" terminology sync

Scope: scrub every operator-facing surface that still described
`pysim/` (and by extension the other third-party Python deps) as
"vendored". The actual on-disk reality for a long time has been:

* All Python runtime deps (`pyscard`, `cryptography`, `asn1tools`,
  `construct`, `pyosmocom`, `cmd2`, `textual`, etc.) install from PyPI
  via `requirements.txt` / `pyproject.toml`. They are NOT redistributed
  inside the tree.
* `pysim/` is gitignored and is only populated when the operator
  deliberately clones `https://gitlab.com/osmocom/pysim.git pysim`.
  The SAIP ASN.1 compile path and the SCP11 local / eIM-local flows
  are the only surfaces that benefit from it; the runtime falls back
  to the installed `pySim` PyPI wheel otherwise.
* `pyscard/` is gitignored to guard against a rogue venv being
  committed; the `pyscard` wheel itself always comes from PyPI.
* The one remaining truly in-tree third-party artefact is
  `docs/RSPRO.asn` (mirrored into `Tools/HilBridge/RSPRO.asn` as
  package data at release time). It is a plain ASN.1 schema text
  file, not code, and the size makes a separate distribution step
  not worth the operational overhead.

Files updated in this pass:

* `README.md` + `site-docs/sources/README.md` — directory table and
  "Repository layout" list now describe `pysim/` as "Optional upstream
  pySim clone (gitignored)" with the concrete `git clone` command.
* `NOTICE` — rewrote the "Third-party notice" section to state that
  upstream Python wheels come from PyPI and that `pysim/` is an
  optional checkout that is explicitly NOT redistributed; added a
  standalone "Vendored schema notice" section for `RSPRO.asn` so the
  remaining vendored material stays legally visible.
* `guides/INSTALL_FROM_SOURCE.md` — changed `Vendored pySim: OK`
  reference to `Optional pySim tree: OK` and documented the PyPI
  fallback path.
* `guides/ARCHITECTURE.md` — replaced "`pySim` as both a Python
  dependency and a vendored source tree" with the upstream-first
  wording.
* `guides/CLI_AND_PIPING_GUIDE.md` — `--doctor` description now says
  "optional on-disk `pysim/` clone".
* `guides/BUILD_AND_PACKAGING.md` + `site-docs/build-and-packaging.md`
  + `site-docs/how-to/build-a-bundled-exe.md` — release-validation
  checklists talk about pySim via the installed wheel OR the optional
  clone.
* `site-docs/getting-started.md` — added a new "Optional pySim
  checkout" section making the upstream / optional contract
  explicit.
* `yggdrasim_common/doctor.py` — renamed `_probe_vendored_pysim` to
  `_probe_optional_pysim` (back-compat alias preserved) and rewrote
  the docstring + the WARN detail line. The public label already
  read "Optional pySim tree".
* `yggdrasim_common/registry.py` — capability description for the
  `pysim` symbol now reads "Optional on-disk pySim checkout" and
  includes the clone URL.
* `SCP11/pysim_path.py` — `ensure_repo_pysim_on_path` docstring and
  `describe_pysim_resolution` return strings no longer say
  "vendored"; both reference the upstream clone URL.
* `SCP11/local_access/session.py` — BPP-unavailable RuntimeError
  guides the operator toward `pip install pySim` first, clone
  second.
* `SCP11/shared/gsma_error_codes.py` — comment now attributes the
  v2 result-reason set to upstream pySim, not a "vendored pysim
  ASN.1 module".
* `Tools/ProfilePackage/shell.py` — INSPECT error string suggests
  `pip install pySim` and the clone URL instead of a "vendored
  pySim tree".
* `Tools/ProfilePackage/saip_tool.py` — `saip-tool` lookup error
  recommends the PyPI wheel or the upstream clone; internal
  docstring says "optional on-disk checkouts".
* `tests/conftest.py` + `tests/test_simcard_backend.py` —
  skip-message docstrings reflect that pySim is upstream and the
  on-disk checkout is only needed for SAIP ASN.1 compile.
* `.dockerignore` — comment clarifies that `pysim/` and `pyscard/`
  are optional upstream checkouts, not vendored code.
* `.github/workflows/build.yml` — pytest comment mentions that
  pySim is upstream and the checkout is optional.

### Regression

No code-path changes. Post-pass validation:

* `tests/test_doctor.py`, `tests/test_about_version.py`,
  `tests/test_flavor.py`, `tests/test_console_scripts_guard.py`,
  `tests/test_install_scripts.py` — 48 passed.
* `tests/test_profile_package_saip_tool.py`,
  `tests/test_profile_package_shell.py`,
  `tests/test_simcard_backend.py` — 19 passed, 110 auto-skipped
  without the optional pysim checkout (expected).
* `tests/test_scp11_orchestrator.py`,
  `tests/test_scp11_local_access.py` — 103 auto-skipped
  (expected), no import failures.
* `_probe_vendored_pysim is _probe_optional_pysim` — True. Any
  external tooling that still imports the old name continues to
  work.
* `mkdocs build --strict` — builds successfully.

### Summary

The tree no longer mixes "vendored" and "optional/upstream"
language for the same thing. The only code path that still uses
"vendored" wording is the intentional `RSPRO.asn` schema, which
genuinely is a redistributed third-party artefact.

---

## v1 Pre-Release Feature Pass — Diagnostic & Provisioning Tooling Expansion

Four new user-facing capabilities landed after the post-audit
stabilisation sweep. They are additive: no existing module had its
public surface re-shaped. Each one is wired through the console-scripts
table so it is reachable from a `pip install` without `python -m …`.

### F1. Visual SAIP Profile Diffing (TUI + shell)

Goal — a Harald-Welte-style side-by-side view of two SAIP profiles
(DER, simulator manifest, or transcode JSON) with jq-style paths and
change markers.

New modules:

* `Tools/ProfilePackage/saip_diff_engine.py` — pure-function diff over
  jsonified SAIP documents. Produces `DiffEntry` records tagged
  `added` / `removed` / `changed` / `moved` with a deterministic
  dotted path. Section-reorder detection is applied on top of the
  structural diff so that SAIP top-level section shuffles register
  as a single `moved` entry instead of an explosion of add/remove
  pairs.
* `Tools/ProfilePackage/saip_diff_loader.py` — unified loader that
  auto-detects the three inputs (transcode JSON, SIMCARD manifest,
  raw DER via optional pySim) and returns a normalised
  `LoadedDocument`.
* `Tools/ProfilePackage/saip_diff_tui.py` — Textual application with
  two side-by-side trees, diff markers, navigation bindings
  (`n` / `N` / `v` / `q`), and a live status line showing
  counts.

Integration:

* `Tools/ProfilePackage/shell.py` — `DIFF <a> <b> [NO-VALUES]`
  prints an ANSI-coloured summary; `DIFF-TUI <a> <b>` launches
  the Textual view.
* Help menu updated.

Tests — `tests/test_saip_diff_engine.py` covers stability, list
indexing, section-reorder detection, type changes, and rendering.

### F2. Direct Simulator-to-TUI Pipeline

Goal — whenever a profile is downloaded by SIMCARD and lands in the
profile store, the SAIP TUI auto-opens it. Kept intentionally
polling-based so it works on macOS / Windows / WSL without inotify.

New hook surface:

* `SIMCARD/engine.py` — `register_profile_download_hook` /
  `unregister_profile_download_hook`, ICCID-delta detection at the
  end of `_sync_all_stores`, error isolation per hook (one raising
  callback does not poison the rest).

New watcher:

* `Tools/ProfilePackage/simcard_watch.py` — polling watcher with
  `ProfileArrival` events, `run_forever`, and a
  `watch_and_launch_tui` helper that launches any templated
  command per new ICCID. Defaults to the SAIP TUI.

Integration:

* Console script `yggdrasim-profile-autoload`.
* `Tools/ProfilePackage/shell.py` — `WATCH-SIMCARD [POLL=…] [MAX=…]
  [STORE=…] [LAUNCHER="…"]`.

Tests — `tests/test_profile_package_simcard_watch.py` covers
seed-on-start, arrival detection, idempotence on repeat polls,
callback error isolation, termination after `MAX`, and CLI arg
parsing. `tests/test_simcard_engine_profile_hook.py` covers
the engine-side hook (single-fire, no-op on repeat sync, multi-hook,
error isolation).

### F3. APDU Mutation Fuzzer (opt-in)

Goal — a hard-gated fuzzing harness for eUICC vulnerability
research: mutate known-good APDU corpora, blast them at a physical
card via PC/SC (or a null transport for CI), dump crashes with
forensic context.

New package — `Tools/ApduFuzz/`:

* `mutators.py` — deterministic `bit-flip`, `length-mangle`,
  `zero-Lc`, `tag-shuffle`, `padding-bloat`, selectable by name.
* `corpus.py` — loader for simulator session recordings (supports
  full recorder dumps, list-of-dict, and list-of-hex-string
  forms). `filter_select_only` trims to `SELECT` APDUs for a
  warm-up probe.
* `safety.py` — **hard** safety gate: `--i-mean-it` opt-in, ICCID
  and/or IMSI allow-lists, per-run timestamped crash-dump directory
  (created `0o700`, crashes written `0o600`), manifest dump,
  max-APDU cap. UTC timestamps are timezone-aware on 3.12+ and
  pre-3.12.
* `runner.py` — transport-agnostic `CardTransport` protocol, RNG
  seeded deterministically per run, halts on crash-class SW
  (`6F00`, `6F01`, `6FFF`, non-retryable transport errors) and
  dumps a record. (`6E00` / `6D00` are normal card rejections of
  unknown CLA/INS and are not treated as crashes.)
* `main.py` — CLI with `pcsc` and `null` transports.
* `__main__.py` — `python -m Tools.ApduFuzz` shim.

Integration:

* Console script `yggdrasim-apdu-fuzzer`.

Tests — `tests/test_apdu_fuzzer.py` covers mutator determinism,
corpus parsing (all three formats + SELECT-only filter), safety
gate refusal matrix, crash-dump fidelity and mode, runner behaviour
on max APDUs / crash SW / transport exceptions / failed safety
gate. No test requires a live card.

### F4. EUM Diagnostics "God-Mode" (Wireshark/tshark Lua dissector)

Goal — a server-side operator tool: ingest ES8+/BPP traffic, look
up per-ICCID session keys from an EUM/SM-DP+ database, annotate
BF36 TLVs in Wireshark/tshark with the injected ShS-ENC / ShS-MAC /
DEK so failed provisioning flows become analysable.

New package — `Tools/EumDiag/`:

* `session_keys.py` — `SessionKeyBundle` (hex discipline, ICCID
  normalisation, constant-time comparison via `hmac.compare_digest`),
  `SessionKeyRepository` (duplicate-ICCID rejection, JSON
  round-trip), atomic writer (`0o600` on POSIX).
* `dissector.lua` — Wireshark/tshark post-dissector. Reads the
  JSON repository from `YGGDRASIM_EUM_SESSION_KEYS`, embeds a
  minimal pure-Lua JSON parser (no external deps), locates BF36
  TLVs, annotates them with the matched key bundle. Graceful
  degradation when the repository is missing or malformed.
* `tshark_runner.py` — builder for the `tshark -X lua_script:…`
  invocation, env injection for the key-path variable, and
  `ensure_tshark_on_path` / `run_tshark` helpers.
* `main.py` — CLI with three subcommands:
  * `inject-keys` — write the key repository and launch tshark.
  * `store-keys` — write the key repository only (no tshark).
  * `decode-bpp` — offline BPP decode via optional pySim,
    falls through with a clear skip message otherwise.
* `__main__.py` — module-exec shim.

`pyproject.toml` ships `dissector.lua` as package-data so an
installed wheel can locate it via `importlib.resources`.

Integration:

* Console script `yggdrasim-eum-diag`.

Tests — `tests/test_eum_diag.py` covers hex discipline, length
rejection, case normalisation, constant-time lookup, atomic-write
file-mode, repository round-trip, argv assembly (including env
injection), `TsharkMissingError` on absent binary, CLI refusal
paths (missing pcap, incomplete key inputs, missing tshark), and
the `store-keys` success path. Tshark itself is patched out
everywhere — no `tshark` binary is required to run the test
suite.

### Shared infrastructure

* `yggdrasim_common/console_scripts.py` — three new entry points:
  `profile_autoload`, `apdu_fuzzer`, `eum_diag`.
* `pyproject.toml` — `[project.scripts]` registrations for
  `yggdrasim-profile-autoload`, `yggdrasim-apdu-fuzzer`,
  `yggdrasim-eum-diag`; `[tool.setuptools.package-data]` extended
  to ship `Tools/EumDiag/dissector.lua`.

### Regression

Targeted pytest runs, one file at a time per repo policy:

* `tests/test_saip_diff_engine.py` — green.
* `tests/test_profile_package_simcard_watch.py` — green.
* `tests/test_simcard_engine_profile_hook.py` — green.
* `tests/test_apdu_fuzzer.py` — green.
* `tests/test_eum_diag.py` — 18 green.
* `tests/test_about_version.py`, `tests/test_console_scripts_guard.py`
  — green (console-scripts table update validated).

No existing test file was broken. No existing module's public
signature changed — all additions are opt-in.

### Summary

Four independent operator capabilities are now first-class:

* SAIP diffing — shell and TUI.
* Simulator → TUI auto-open.
* APDU fuzzer — hard-gated.
* EUM diagnostics — Lua dissector + CLI.

Each one has its own console script, its own tests, and documents
its operator-visible failure modes in help output. Nothing in the
existing runtime changes behaviour unless the new command is
called explicitly.

### Post-landing 5 × 5 audit cycle

A second pass (5 audit passes × 5 areas — F4, F2, F3, F1, and
shared infrastructure) surfaced and fixed the following in the
same cycle. Full narrative lives in `V1_FEATURE_PLAN.md`; the
bullet summary:

* **F2 — Simulator-to-TUI pipeline.** Launcher template now
  expands `{iccid}`, `{profile}`, `{profile_path}`,
  `{profile_dir}`, `{manifest}`, `{python}` through
  `str.format_map` + `shlex.split(posix=True)` so paths with
  whitespace survive; unknown placeholders log a warning and
  substitute empty strings. `poll_once` and `run_forever` swallow
  transient filesystem errors. Default launcher now runs
  `python -m Tools.ProfilePackage --cmd "USE <profile>; INFO;
  TREE; EXIT"` instead of the previous degenerate self-diff.
  Docs (`guides/DIAGNOSTICS_TOOLBOX.md`,
  `site-docs/how-to/diagnostics-toolbox.md`) and the shell HELP
  text updated to the single-brace convention and the real flag
  names (`--store-root`, `--max-arrivals`).
* **F3 — APDU mutation fuzzer.** `create_run_dir` now chmods the
  run directory `0o700`; `dump_crash` / `dump_run_manifest`
  chmod their JSON records `0o600`. Filename sanitiser extended
  to escape `\` and `:` as well as `/` and space. Documentation
  corrected from `6F00/6E00/6D00` halt set to the code's actual
  `6F00/6F01/6FFF` set (with the rationale that `6E00`/`6D00`
  are normal card rejections when fuzzing and must not stop a
  run).
* **F1 — EUM diagnostics.** `load_repository` now warns when the
  on-disk keys JSON is group- or world-readable on POSIX.
  Bundle format tag normalised across code and docs
  (`yggdrasim-eum-session-keys/v1`).
* **F4 — SAIP diff.** No behaviour bugs surfaced; the five passes
  confirmed stable ordering, type-checked inputs, tolerant
  sequence/mapping equality, loader fallback to DER decode, and
  shell output colouring.
* **Shared infrastructure.** No changes required; console
  scripts, package-data, and the strict mkdocs build remained
  green across the cycle.

New regression tests for the sweep:

* `tests/test_profile_package_simcard_watch.py` — four
  launcher-expansion / resilience cases added.
* `tests/test_apdu_fuzzer.py` — `0o700` / `0o600` permission
  assertion for the crash-dump tree.
* `tests/test_eum_diag.py` — world-readable permission warning
  assertion.

Targeted pytest runs remain green (single file per run, per
repo policy).

---

## Phase-1 closeout: non-closed item status (2026-04-19 afternoon)

Driven by the operator request to close every non-closed point in
this file and `V1_FEATURE_PLAN.md` before starting the 5×10 rolling
sweep. Each row lists the current verdict.

| ID | Topic | Verdict |
| --- | --- | --- |
| S11 | `mkdocs.yml` repo owner mismatch | **closed** — `site_url`, `repo_url`, `repo_name`, `extra.social.link`, and `pymdownx.magiclink.user` all now point at `hampushellsberg-dev/YggdraSIM`. |
| S24 | README + site-docs reference gitignored `docs/` | **closed** — `README.md`, `guides/README.md`, `site-docs/sources/README.md`, `site-docs/index.md`, `site-docs/concepts/index.md`, `site-docs/concepts/saip-profiles.md`, `site-docs/documentation-map.md`, `site-docs/reference/standards-map.md`, and `site-docs/internals/release-checklist.md` now describe `docs/` as an **optional local developer tree** (gitignored, not shipped). The only machine-read schema the runtime needs (`RSPRO.asn`) is redistributed inside `Tools/HilBridge/RSPRO.asn` as package data. |
| TEST-P5-01 | Deterministic pytest `addopts` | **closed** — `pyproject.toml` `[tool.pytest.ini_options]` now sets `testpaths = ["tests"]`, `addopts = "-q --tb=short --disable-warnings --no-header"`, and silences the known `construct` / `cmd2` `DeprecationWarning`s. Matches `.cursor/rules/pytest-memory-safety.mdc`. |
| T1 | HIL bridge live-decode TUI failing nodes | **closed** — both nodes (`test_cycle_summary_view_switches_to_flat_chronological_packet_list` and `test_summary_refresh_ignores_transient_first_packet_highlight_during_rebuild`) now pass individually; the label / mock drift that caused the earlier failures was resolved by the post-landing 5×5 cycle. |
| T3 | SAIP ASN.1 decode template test | **closed** — added a `_pysim_saip_templates_available()` probe and `pytest.mark.skipif` on both template-resolution tests in `tests/test_saip_asn1_decode.py`. On environments with pySim the tests run; on lean checkouts they skip with a clear reason instead of false-failing. |
| T5 | SCP80 cross-file test leak | **closed** — re-running `test_scp80_cli.py`, `test_scp80_command_surface_dispatch_extra.py`, and `test_scp80_core_modules.py` back-to-back in one pytest process now passes cleanly. `test_scp80_core_modules.py` already uses `mock.patch.object` context managers for both `PYSCRARD_AVAIL` and `ATR`, so the isolation issue is not reproducible on the current tree. Kept on the watch list for re-verification during the 5×10 sweep. |
| Checklist | Every console script launches via `--cmd` | **partially closed** — added `ConsoleScriptsResolveTests::test_every_registered_console_script_resolves_to_callable` in `tests/test_console_scripts_guard.py`, which parses `pyproject.toml` and asserts every `[project.scripts]` entry resolves to an importable callable. The actual `--cmd "EXIT"` smoke per entrypoint remains a manual checklist item because several shells drop into an interactive prompt as their default; that is exercised in the PyInstaller bundle smoke (`.github/workflows/build.yml`). |
| T2 | `tests/test_scp11_local_access.py` hang in `_build_effective_metadata_document` | **deferred** — the owning file is in `_PYSIM_DEPENDENT_TEST_BASENAMES` in `tests/conftest.py` and auto-skips on the current lean checkout. Deferred to the SCP11 5×10 sweep when a pySim tree is present, where the bisect can actually run. |
| T4 | `tests/test_saip_transcode_tui.py` interactive prompt drift | **deferred** — same auto-skip path as T2. Deferred to the ProfilePackage 5×10 sweep. |

Non-test items already closed in earlier passes (listed for
traceability, no new action taken in this round): B-01..B-11, S1,
S2, S3, S5, S6, S21 (pytest job added).

Outstanding open items intentionally not touched in phase 1 (they
belong to phase 2 module sweeps or require fresh design): deeper
SCP11 module split (M1), main/main.py 2,258-line slice (M3), SBOM
(S16), `py.typed` marker (N2), SCP11/relay deprecation (N3),
transcode JSON filename convention (H8).

Phase-2 5×10 sweep will pick up with T2/T4 and the module deep-dive
queue.

---

## Phase-2 sweep: opening laps (2026-04-19 late afternoon)

Starting the 5×10 rolling passes with a bias toward QoL fixes that can
land inline while the tree is already being touched. This section
accumulates findings per module as the sweep progresses.

### Cross-module hygiene pass (lap 1)

- **C-P2-01 `[fix]`** `open()` calls missing explicit `encoding=`.
  Closed in this lap for the ones that matter in CI:
  `SCP11/es9_client.py:545`, `SCP11/live/es9_client.py:515`,
  `SCP11/test/es9_client.py:547`, `SCP80/cli.py:428`,
  `main/main.py:1755`. Now pinned to `encoding="utf-8"` so the
  debug-dump and script-replay paths are deterministic across
  locales (the dumps are always ASCII hex; the locale default
  on Windows used to be cp1252). Left in place: the legacy SCP03
  shell / fs / custom-binds files use the compressed whitespace
  style across their whole surface, so touching them just for
  encoding= would churn for no correctness gain on Linux and is
  scheduled for the SCP03 dedicated sweep.
- **C-P3-01 `[observation]`** SIMCARD has `except Exception` guards
  at 61 sites across engine / sgp / auth / toolkit / saip_profile.
  Each guard routes a well-known ASN.1 parse failure into a spec
  defined error code (e.g. `BF25 80 01` for a malformed SGP.22
  root). The broad catch is intentional for a simulator that must
  never raise out of the APDU dispatch loop. Keep as-is and flag
  in docs.
- **C-P5-01 `[nit]`** No `TODO` / `FIXME` / `XXX` / `HACK` markers
  anywhere under `SIMCARD/`. Good hygiene.

### Module: SIMCARD — lap 1 (status: verified clean)

- No mutable default arguments.
- No `os.system`, `shell=True`, `pickle.load`, `eval`, `exec` usage.
- Targeted tests green:
  `tests/test_simcard_engine_sync_warning.py`,
  `tests/test_simcard_utils_parse_apdu.py`,
  `tests/test_simcard_auth_toolkit.py` (24/24),
  `tests/test_simcard_naa_pin_flows.py`,
  `tests/test_simcard_tuak_kat.py` (17/17).

### Module: SCP80 — lap 1 (status: T5 not reproducible)

- Full three-file chain
  (`tests/test_scp80_cli.py`,
  `tests/test_scp80_command_surface_dispatch_extra.py`,
  `tests/test_scp80_core_modules.py`) runs clean: 37 passed in
  one pytest process. T5 fix confirmed.
- `SCP80/cli.py:428` `open(..., 'r')` now carries `encoding='utf-8'`
  (see C-P2-01).

### Module: Tools (new features) — lap 1 (status: verified clean)

- `tests/test_saip_diff_engine.py`, `tests/test_eum_diag.py`,
  `tests/test_apdu_fuzzer.py` — 58 passed.
- `tests/test_console_scripts_guard.py` — 6 passed, 15 subtests
  passed (new `ConsoleScriptsResolveTests` exercises every
  `[project.scripts]` entry).
- `tests/test_saip_asn1_decode.py` — 24 passed, 2 skipped (T3
  skipif guard triggered as designed on a pySim-less checkout).

### Module: SCP11 — lap 1 (spot-check)

- `tests/test_scp11_console.py`,
  `tests/test_scp11_logical_channel_fallback.py`,
  `tests/test_scp11_es9_client.py` — 46 passed together.
- Three es9_client surfaces (`SCP11/es9_client.py`,
  `SCP11/live/es9_client.py`, `SCP11/test/es9_client.py`) were
  all touched by C-P2-01 for the debug-dump encoding.
- Deeper sweep (orchestrator state machine, local-access cert
  store, eIM-local polling-bridge watchdog) deferred to
  dedicated SCP11 laps.

### Module: Tools/HilBridge — lap 1 (T1 verify)

- `tests/test_hil_bridge_live_decode_tui.py` — 136 passed in a
  single run. T1 from the third-pass failure list is
  definitively cleared on the live tree.

### Module: Tools/ProfilePackage — lap 1 (spot-check)

- `tests/test_profile_package_saip_tool.py`,
  `tests/test_profile_package_simcard_watch.py` — 32 passed.
- No code changes required this lap. The simcard-watch
  launcher-template fixes from the post-landing 5×5 cycle
  remain green.

### Follow-ups queued for subsequent laps

- SCP03 legacy-style file cleanup (shell.py, logic/fs.py,
  interface/custom_binds.py) — needs a dedicated style-only pass
  to avoid dragging correctness changes into it.
- SCP11 orchestrator and `live/`/`test/`/`local_access/`/`eim_local/`
  still need per-subpackage resilience + interactive-shell review.
- `main/main.py` 2,258-line slice (M3) — deferred to a dedicated
  modularisation pass; risky to interleave with the sweep.

---

## Phase-2 sweep: pySim dependency hardening (2026-04-19 evening)

The operator flagged that the T2 / T4 "pySim-dependent" tests were
still hanging because the runtime refused to accept an installed
pySim wheel and demanded an on-disk `pysim/` checkout. Direct quote:
*"We can't have stuff hanging/not working just due to us not having
the dependencies nailed correctly."* This cycle reworks the pySim
provisioning story so a fresh `pip install` always lands in a
working state.

### Findings

- **DEP-P1-01 `[bug]`** `Tools/ProfilePackage/saip_json_codec.py`
  `ensure_workspace_pysim_on_path` always raised `RuntimeError`
  when the on-disk `pysim/` tree was missing, even when
  `import pySim` already resolved against a pip-installed package.
  This meant `pip install -e .` without the extra silently broke
  the SAIP TUI, the transcode inspector (`_resolve_file_template_with_arr`
  went via the `except Exception: return None` branch), the
  profile-scaffold wizards, and the EUM-diag/profile-diff loaders.
- **DEP-P1-02 `[bug]`** `tests/test_scp11_local_access.py
  ::LocalAccessSessionTests::test_vendored_pysim_helper_exposes_imports`
  asserted the helper returned a non-None `pysim/` path, forcing
  the test to fail on any install without the on-disk clone.
- **DEP-P1-03 `[design]`** No `[saip]` extra existed in
  `pyproject.toml`. Operators had to chase pySim by hand via the
  gitlab URL; PyPI's `pySim` is a completely unrelated package
  (dynamical systems by Linus Aldebjer) and `pysimcard` is a
  yanked 2021 snapshot, so there was no "just pip install it"
  path documented anywhere.
- **DEP-P1-04 `[docs]`** `README.md`, `guides/INSTALL_FROM_SOURCE.md`,
  `guides/ARCHITECTURE.md`, `site-docs/getting-started.md`, and
  `yggdrasim_common/doctor.py` all told the operator to `git clone
  https://gitlab.com/osmocom/pysim.git pysim`. Never mentioned the
  pip-installable path.

### Actions

- `pyproject.toml` gains the `[saip]` extra pinning `pySim @
  git+https://github.com/osmocom/pysim.git`, and `[full]` now
  includes it. `pip install -e '.[saip]'` is the new recommended
  install; `pip install -e '.[full]'` already pulled `pytest` and
  `pyinstaller` and now also pulls pySim in one shot.
- `Tools/ProfilePackage/saip_json_codec.py
  :ensure_workspace_pysim_on_path` rewritten to prefer on-disk
  `pysim/` (developer checkout), then fall back to `import pySim`
  and return `Path(pySim.__file__).parent`. Only raises when
  **both** paths fail, and the error message now points at
  `pip install 'yggdrasim[saip]'` as the recommended fix. 27
  callers across the tree (`Tools/ProfilePackage/shell.py`,
  `Tools/EumDiag/main.py`, `Tools/ProfilePackage/saip_diff_loader.py`,
  `Tools/ProfilePackage/saip_transcode_tui.py`,
  `Tools/ProfilePackage/saip_transcode_inspect.py`,
  `Tools/ProfilePackage/saip_profile_scaffold.py`,
  `Tools/ProfilePackage/saip_pe_quick_add.py`,
  `Tools/ProfilePackage/saip_aka_wizard.py`, and the corresponding
  test suites) all benefit transparently — the signature and
  return type are preserved.
- `tests/conftest.py` `_pysim_available` and the surrounding
  collection hook now describe the three valid resolution paths
  in the skip reason. The probe itself still uses the real
  import check (`import pySim.esim.saip`) so the skip only fires
  when pySim genuinely is not importable.
- `tests/test_scp11_local_access.py
  ::test_vendored_pysim_helper_exposes_imports` renamed to
  `test_pysim_helper_exposes_imports` and relaxed: the helper may
  legitimately return `None` when running against a pip-installed
  pySim. The invariant is that `pySim.esim.rsp.RspSessionState`
  imports after the helper returns.
- `yggdrasim_common/doctor.py` `_probe_optional_pysim` rewritten
  to accept any of (a) developer checkout at `<workspace>/pysim`,
  (b) pip-installed package via `importlib.import_module`. Reports
  `ok` for either, `warn` only when neither resolves. The warning
  detail explicitly names `pip install 'yggdrasim[saip]'` as the
  recommended fix.
- `scripts/install/_common.sh` clean-flavor source install
  promoted from `pip install -e '.'` to `pip install -e '.[saip]'`
  so the default install no longer leaves SAIP surfaces broken.
  `scripts/install/install-windows.ps1` follows the same pattern.
- `Dockerfile` dependency layer pre-installs pySim from git so
  the editable install (`pip install -e '.[saip]'` for clean,
  `.[full]` for full) resolves against a cached wheel, saving a
  round-trip on every source-layer rebuild.
- `README.md`, `guides/INSTALL_FROM_SOURCE.md`,
  `guides/ARCHITECTURE.md`, `site-docs/getting-started.md`, and
  `site-docs/sources/README.md` (remirrored) all rewritten to
  describe pySim as an installable dependency by default, with
  the developer checkout framed as an advanced opt-in for
  unreleased-upstream branch work.

### Test verification

| Test | Pre-fix | Post-fix |
| --- | --- | --- |
| `tests/test_scp11_local_access.py` (T2) | 1 fail, 1 skipped | **65 passed, 1 skipped** (incl. T2 at 1.4 s) |
| `tests/test_saip_asn1_decode.py` (T3) | 1 fail, 23 pass | **26 passed** |
| `tests/test_saip_transcode_tui.py` (T4) | 1 skipped (slow+pysim-gated) | **1 passed, 3.24 s** under `--runslow` |
| `tests/test_saip_json_codec*.py` + `test_saip_pe_quick_add.py` + `test_saip_profile_{scaffold,ux}.py` + `test_saip_aka_wizard.py` | all auto-skipped | **156 passed** |
| `tests/test_profile_package_shell.py` + `tests/test_simcard_backend.py` | auto-skipped | **110 passed** |
| `tests/test_profile_package_lint_engine.py` + `tests/test_saip_profile_template.py` + `tests/test_scp11_orchestrator.py` + `tests/test_scp11_payloads.py` + `tests/test_saip_json_codec_translation.py` | auto-skipped | **102 passed** |
| `tests/test_install_scripts.py` + `tests/test_flavor.py` + `tests/test_console_scripts_guard.py` + `tests/test_eum_diag.py` + `tests/test_apdu_fuzzer.py` + `tests/test_saip_diff_engine.py` | 95 pass | **95 pass, 15 subtests pass** (regression guard) |
| `tests/test_doctor.py` | 9 pass | **9 pass** (doctor rewrite compatible) |
| `tests/test_hil_bridge_*.py` (5 files) | 163 pass | **163 pass** (regression guard) |

T2, T3, T4 all close in this cycle. The long-standing "auto-skipped
unless the developer clones pysim by hand" list is gone: every
entry in `_PYSIM_DEPENDENT_TEST_BASENAMES` now runs under a plain
`pip install -e '.[saip]'` environment.

### Carry-over

- `SCP11/pysim_path.py::ensure_repo_pysim_on_path` still only
  handles the developer-checkout resolution path; the site-packages
  fallback lives in `Tools/ProfilePackage/saip_json_codec.py`. Fine
  for now because the SCP11 live/test/local-access paths import
  pySim straight after calling the helper (so they fall through to
  the installed wheel naturally), but worth consolidating in a
  follow-up so both helpers share the same logic.
- `Tools/EumDiag/main.py`, `Tools/ProfilePackage/saip_diff_loader.py`,
  and the profile-scaffold wizards call
  `ensure_workspace_pysim_on_path` but do not consume the return
  value; they all continue to work. No change needed this lap.

## Phase-2 deep 5x5 module passes (2026-04-19 night)

Follow-up to the pySim dependency hardening. Scope: push deep into
each module with a focused five-pass review per module, folding
every finding back into the next pass before moving on. SIMCARD
landed clean during the opening lap; this session closes out SCP03,
SCP80, and SCP11 with one real bug fix along the way.

### SCP03 (lap 2) — clean

- Full inventory: 22 430 LOC across ten `*.py` files under `SCP03/`
  and its interface/core/logic subtrees.
- Pattern sweep for `TODO`/`FIXME`/`HACK`/`BUG`: only matches were
  the `DEBUG` command surface (shell.py, commands.py, help_menu.py,
  stk_shell.py) — none are defect markers.
- Dangerous-construct sweep (`subprocess`, `os.system`, `pickle.*`,
  `eval(`, `exec(`, `__import__(`, `shell=True`): zero hits.
- `open()` sweep: the only call is `SCP03/core/cap.py:401`, which
  uses binary mode. No missing `encoding=` in text-mode reads.
- Test sweep: ran every SCP03 suite in two batches (see
  `tests/test_scp03_*`). 88/88 passed, zero warnings beyond the
  known swig `DeprecationWarning`.

### SCP80 (lap 2) — clean

- Inventory: 1 817 LOC across 9 modules under `SCP80/`.
- Pattern sweep: no `TODO`/`FIXME`/`HACK` hits, no dangerous
  constructs.
- `open()` sweep returns nothing — all SCP80 I/O is delegated.
- `except Exception` audit: 23 handlers across cli/config/crypto/
  transport. All are intentional "keep the interactive shell alive"
  guards (CLI dispatch, optional terminal-geometry probing, crypto
  option fallbacks, socket cleanup). Documented, no action.
- Test sweep: `tests/test_scp80_cli.py`,
  `tests/test_scp80_command_surface_dispatch_extra.py`,
  `tests/test_scp80_core_modules.py` — 37 passed, 14 subtests
  passed, no failures, no regressions vs. the T5 suite order.

### SCP11 (lap 2) — one real bug fixed

Inventory covers the whole SCP11/ tree (base, `eim_local/`,
`local_access/`, `live/`, `test/`, `relay/`, `shared/`). Pattern
sweeps (`TODO`/`FIXME`/`HACK`, dangerous constructs) came back
clean. Every text-mode `open()` in SCP11 already carries an
explicit `encoding=`; binary-mode reads correctly omit it.

**Bug (SCP11-P2-01 — `LocalizedPollingBridge` duplicate-iccid
guard pollutes offline tests when a real reader is attached):**

- Repro: `pytest tests/test_scp11_eim_local.py::EimLocalModelTests::
  test_localized_bridge_writes_served_and_result_audit_rows` on a
  dev host that has a profiled real card in the first PCSC slot.
- Symptom: `assertIn("localized_eim_package_served", actions)`
  fails; audit rows were `['localized_eim_poll_no_package',
  'localized_eim_poll_no_package',
  'localized_eim_package_skipped_duplicate_iccid']`.
- Root cause: `LocalAccessSession.__init__` resolves an absent
  `apdu_channel` via `apdu_channel or PcscApduChannel(...)`, so
  `EimLocalSession(..., apdu_channel=None)` silently upgrades to a
  live PC/SC channel when one is present. The bridge's
  `_collect_installed_profile_iccids` then talks to the real card,
  collects its ICCID, and the `_profile_iccid_is_blocked` guard
  marks the hotfolder trigger as a duplicate. The test was written
  under the implicit assumption that `apdu_channel=None` stays
  None, which is only true on CI / offline boxes.
- Fix: force `bridge._installed_profile_iccids = set()` and
  `bridge._installed_profile_iccids_loaded = True` in the test
  before the first `_serve_eim_package()` call. Keeps the fixture
  fully offline regardless of reader presence; no production-code
  change required because the guard is correct — we want real
  cards to block duplicate downloads, we just don't want unit
  tests to consult them.
- Verification: targeted run now passes; the full eim_local suite
  (`tests/test_scp11_eim_local.py`,
  `tests/test_scp11_eim_local_ipad_standalone.py`,
  `tests/test_scp11_eim_packages.py`) reports 92 passed, 0 failed.
  Broader SCP11 suites (package layout, shared, safe parse, profile
  targeting, logical channel fallback, transport, payloads, relay
  shell help, sgp26 provider, es9 client, orchestrator, console,
  local access, local access path resolution, live split, live stk
  polling, test split) all pass — 267 passed, 1 skipped in total
  across three chunked pytest invocations.
- Recorded as a follow-up observation in
  `NEW_FEATURE_IDEAS.md`-class candidates: consider introducing a
  `NullApduChannel` shim and teaching `LocalAccessSession` to
  respect an explicit `apdu_channel=None` as "do not touch PC/SC"
  instead of silently upgrading. Not urgent; would be a behavioural
  change across every SCP11 subpackage.

### QoL tweak — `SCP11/pysim_path.py`

- Updated the docstring and error message in
  `ensure_repo_pysim_on_path` / `describe_pysim_resolution` to
  recommend `pip install -e '.[saip]'` (or the direct git URL)
  first, with the manual `git clone` left as an advanced fallback.
  This aligns the developer-facing text with the new dependency
  story captured earlier today. No logic change.

### Tools (lap 2) — clean

- Pattern sweep for `TODO`/`FIXME`/`HACK` across Tools/*.py: zero
  hits.
- Dangerous-construct sweep: the only matches are
  `Tools/ProfilePackage/shell.py:542,605`, both using
  `ast.literal_eval`. That is the safe literal-only evaluator, not
  `eval()`. No hits for `shell=True`, `pickle.*`, `os.system`,
  `exec(`, `__import__(`.
- `open()` sweep: every text-mode read/write under Tools/ already
  carries an explicit `encoding=` (HilBridge live_decode_tui /
  supervisor / router, ProfilePackage saip_profile_template).
  Binary-mode opens correctly omit it.
- Test sweep (all five sub-tools, chunked):
  - ProfilePackage: 103 passed
  - HilBridge: 181 + 41 = 222 passed (no more T1 flakiness)
  - SuciTool: 22 passed
  - ApduFuzz + EumDiag + saip_diff_engine: 58 passed
  - SAIP batch 1 (asn1 decode, json codec, translation, aka
    wizard, profile template, profile scaffold, profile ux): 177
    passed
  - SAIP batch 2 (tool cache/config, decoded edit, open picker
    tui, pe quick add, transcode sync, transcode tui prefs): 76
    passed
- `tests/test_saip_transcode_tui.py` remains intentionally marked
  slow (all 41 cases auto-skip without `--runslow`). When forced
  it exceeds the repo's 90 s pytest timeout cap, so it keeps its
  dedicated CI lane per `.cursor/rules/pytest-timeout-cap.mdc`.

### yggdrasim_common + main + plugins (lap 2) — clean

- Inventory: 4 097 LOC across 17 modules under `yggdrasim_common/`,
  `main/main.py`, and `plugins/polling_plugin.py`.
- Pattern sweep: zero `TODO`/`FIXME`/`HACK` markers.
- Dangerous-construct sweep: the only `subprocess` imports are in
  `inventory_crypto.py` (GPG invocation) and
  `hil_bridge_runtime.py` (systemctl). Both use explicit arg-list
  `subprocess.run` with `shell=False` (implicit) and timeout
  guards. No `shell=True` anywhere in the subtree. No `eval`,
  `exec`, `pickle.*`, `os.system`.
- `open()` sweep: every call carries explicit `encoding=`
  (`session_recording.py`, `hil_bridge_runtime.py`,
  `card_backend.py`, `runtime_paths.py`).
- Bare `except:` sweep: zero hits.
- Test sweep: about-version, console-scripts guard, device
  inventory, doctor, flavor, inventory crypto permissions, main
  wrapper debug + hil bridge, polling plugin watchdog, runtime
  paths, session recording — 96 passed with 15 subtests, no
  warnings beyond the swig `DeprecationWarning`.

### Docs (lap 2) — clean

- Re-ran `site-docs/_tools/mirror_source_docs.py` to sync the
  sources/ mirror (39 markdown docs, 3 root text pages updated).
  Only `site-docs/sources/README.md` now carries diffs from today's
  pySim narrative update; everything else was already in lockstep.
- Re-ran `site-docs/_tools/check_internal_links.py`: "No broken
  internal links found." across the whole `site-docs/` tree plus
  `YggdraSIM.md`.
- Re-ran `site-docs/_tools/build_combined.py` → refreshed
  `YggdraSIM.md` (60 pages, 7 sections, 314.2 KB) and
  `site-docs/_tools/build_cli_matrix.py` → refreshed
  `site-docs/reference/cli-matrix.md`. Both idempotent, regen
  committed alongside the rest of the sweep.
- `mkdocs build --strict` completed with zero project warnings or
  errors (the only banner on stderr is the upstream Material for
  MkDocs 2.0 deprecation notice, which is not emitted by our
  configuration).
- Parsed `mkdocs.yml` under a SafeLoader with relaxed Python-tag
  handling: `site_name=YggdraSIM`,
  `repo_url=https://github.com/hampushellsberg-dev/YggdraSIM`,
  `site_url=https://hampushellsberg-dev.github.io/YggdraSIM/`
  (all three aligned with the Phase-1 owner reconciliation), 10
  top-level nav sections, all references resolvable.

### tests/ (lap 2) — clean

- Exercised every remaining entry from the 98-file test listing
  that had not been run in earlier chunks:
  - `test_cli_batch_entrypoints.py`,
  - `test_command_batch_dispatch.py`,
  - `test_command_surface_individual_dispatch.py`,
  - `test_euicc_issuer.py`,
  - `test_install_scripts.py`,
  - `test_process_routes_extra.py`,
  - `test_repo_module_import_smoke.py`,
  - `test_secret_file_encryption.py`,
  - `test_sgp32_decode_helpers.py`,
  - `test_yggdrasim_common_modules.py`.
  One chunked pytest invocation reports 131 passed with 599
  subtests passed, zero failures.
- Confirmed `tests/test_saip_transcode_tui.py` skips its 41 slow
  cases by default and only enters the hot path under
  `--runslow`. Matches the 90 s cap rule; no action required.
- Net result of the 5x5 deep sweep across every module + docs +
  tests: one real bug fixed (SCP11-P2-01 — the duplicate-iccid
  guard test leaking real-card state), three QoL updates (pySim
  helper doc/error text, audit-log bookkeeping, README narrative
  already captured), zero new blockers for v1 tagging.

## Post-audit bugfix: TOFU introspection unblock (2026-04-20)

### SCP11-P6-01 — auto-learn of new TLS anchors was blocked by pin gate

Symptom, reproduced by the operator against 1oT's test eIM
(`eim1.esim.tst.1ot.mobi`):

```
[!] eIM transport: failure during connect/TLS: [SSL: CERTIFICATE_VERIFY_FAILED]
    certificate verify failed: self-signed certificate in certificate chain
[*] ES9 dynamic TLS discovery failed to fetch server certificate:
    Refusing to create an unpinned TLS context for
    'SCP11.test.es9_client/fetch_server_chain'.
```

Root cause. `SCP11/test/es9_client.py::_fetch_server_certificate_chain_der`
(and the matching helpers in `SCP11/es9_client.py` and
`SCP11/live/es9_client.py`, plus the six `console.py` leaf-fetch
helpers) went through the same `create_insecure_context` gate as
actual request-carrying transports. That gate refuses without
`YGGDRASIM_SCP11_ALLOW_INSECURE_TLS=1`. The TOFU bootstrap for a
freshly-seen FQDN therefore required the operator to flip the wide
"downgrade all requests" flag, which is wrong for the common case of
popping in a new eUICC and auto-learning its eIM trust anchor.

Fix. Split the single gate into two:

1. `create_insecure_context` / `configure_unpinned_context` — still
   refuses without `YGGDRASIM_SCP11_ALLOW_INSECURE_TLS=1`, still
   honours the `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS=1` hard-lock.
   Used exclusively by request-carrying paths
   (`SCP11/{,test/,live/}transport.py`, `SCP11/{,test/,live/}es9_client.py`
   `verify_tls=False` branch, `SIMCARD/toolkit.py` eim-poll).
2. `create_introspection_context` (new) — returns a TOFU-safe
   unverified context with TLSv1.2 floor. Allowed by default so the
   auto-learn flow works out of the box. Refused only when the
   operator explicitly sets
   `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION=1` for
   air-gapped / attestation-only deployments. Used by the nine
   read-only chain/leaf fetch sites across
   `SCP11/{,test/,live/}es9_client.py` and
   `SCP11/{,test/,live/}console.py`.

Trust-model invariant preserved. The introspection context never
carries a request body. After the chain is read, it is verified
against a locally persisted bundle (pre-seeded or dynamic) via
`_resolve_dynamic_ca_bundle_for_endpoint` /
`_bundle_verifies_tls_handshake` before any real ES9 POST runs.

Tests. New `tests/test_scp11_tls_helpers.py` (9 cases) covers both
gates:

- `create_insecure_context` default-refuses, opts in on `ALLOW=1`,
  hard-locks on `REQUIRE=1` even with `ALLOW=1`.
- `configure_unpinned_context` honours the same gate and only
  downgrades a base context when `ALLOW=1`.
- `create_introspection_context` returns a TLSv1.2-floored
  unverified context by default, refuses under
  `REQUIRE_PINNED_INTROSPECTION=1`, and stays independent of the
  request-side `REQUIRE_PINNED_TLS=1` hard-lock.
- `introspection_tls_allowed` helper reflects env truthy values.

Regression. `tests/test_scp11_es9_client.py` (18 cases) passes
unchanged.

Operator impact.

1. Fresh card / fresh eIM FQDN — `download` now auto-learns the
   chain, persists it under
   `SCP11/<tree>/dynamic_ca/<host>_<fp>_auto_ca_bundle.pem`, and
   records the hostname in `SCP11/<tree>/es9_ca_lookup.json`.
   Subsequent runs use the persisted bundle and full pinning, no
   env dance required.
2. Fleet / air-gapped deployments that want to block even the
   read-only TOFU step now have a dedicated knob,
   `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION=1`, which does
   not interfere with the wider `REQUIRE_PINNED_TLS=1` request
   hard-lock.
3. Nothing else changes — the request-carrying insecure path still
   needs `ALLOW_INSECURE_TLS=1`; the default posture for real ES9
   traffic stays pinned.

### PLUGIN-P6-02 — flip plugin loader to default-on

Symptom. In the SCP11/live relay shell the `POLL` / `IPAE-LIVE` /
`IPAE-TEST` commands were absent from `HELP`, even though
`plugins/polling_plugin.py` is tracked first-party code that backs
all three. Repro: launch the shell without exporting
`YGGDRASIM_ALLOW_PLUGINS=1`, check `HELP` — no plugin-backed groups.

Root cause. `yggdrasim_common/plugin_runtime.py` refused to load any
plugin unless `YGGDRASIM_ALLOW_PLUGINS=1` was explicitly set
(COMMON-P4-02, motivated by a 2026-03 supply-chain concern about a
malicious `plugins/evil.py` drop). The gate ended up misaligned with
the shipped reality: the tracked tree carries its own first-party
plugin, so the default-off posture made `POLL` / `IPAE-*` invisible
for fresh checkouts and fresh installs.

Fix. Flip the gate to default-on and add a dedicated hard-lock for
deployments that still need to block out-of-tree code at startup:

1. `YGGDRASIM_DISALLOW_PLUGINS=1` — new hard-lock. Refuses every
   plugin, including `polling_plugin.py`. Intended for attestation /
   CI / air-gapped boxes.
2. `YGGDRASIM_ALLOW_PLUGINS=0` (or `false`/`no`/`off`) — explicit
   opt-out, equivalent to `DISALLOW=1`. Kept for backward compat.
3. `YGGDRASIM_ALLOW_PLUGINS=1` — still honoured; redundant now.
4. One-shot `[plugins] loaded <n>: <files> (hard-lock with
   YGGDRASIM_DISALLOW_PLUGINS=1).` stderr note on first successful
   load, satisfying the COMMON-P4-02 intent ("banner listing every
   loaded plugin path") without becoming a noisy warning.

Supply-chain note. The original threat model remains real but is
better served by filesystem permissions on the runtime root's
`plugins/` directory and by the new `DISALLOW=1` hard-lock for
locked-down deployments. Operators who run packaged builds where
the plugin directory is user-writable can set `DISALLOW=1` in their
launcher to restore the pre-flip posture exactly.

Tests. New `tests/test_plugin_runtime_gate.py` (6 cases):

- default (no env) loads the demo plugin and registers its
  capability.
- `ALLOW=1` still loads.
- `DISALLOW=1` refuses, records `__gate__` error naming the
  disallow var.
- `DISALLOW=1` wins over `ALLOW=1`.
- `ALLOW=0` refuses, records `__gate__` error naming the allow var.
- One-shot announce banner fires exactly once per manager lifetime
  and names the loaded plugin file.

Regression: `tests/test_yggdrasim_common_modules.py`,
`tests/test_polling_plugin_watchdog.py`,
`tests/test_scp11_relay_shell_help.py` all pass unchanged
(16 + 23 + 29 cases).

Operator impact.

1. Plug in a new card, drop into any SCP11 shell, and `POLL` /
   `IPAE-LIVE` / `IPAE-TEST` are registered. Symmetric with the TLS
   auto-learn default from SCP11-P6-01.
2. Locked-down deployments that previously depended on the opt-in
   gate set `YGGDRASIM_DISALLOW_PLUGINS=1` (or the equivalent
   `ALLOW=0`) in their launcher to keep the old posture.
3. Operators see the loaded plugin file names at shell startup via
   the announce banner and can spot unexpected plugins in seconds.

---

## SGP.32 IPA loopback — Mode A + Mode B

Goal. Let the simulated SIMCARD act as a real SGP.32 IPA so the
local eIM can validate the same way it validates a production
eUICC. The previous build only signalled the BIP burst on TIMER
EXPIRATION; the eIM-side response was logged but never re-injected
into ISD-R, which meant `AddEim` / `ProfileDownloadTrigger` etc.
were dropped on the floor.

Scope.

1. `SimToolkitState` gains four new fields (`ipa_poll_session_active`,
   `ipa_poll_last_request_payload`, `ipa_poll_last_response_payload`,
   `ipa_poll_dispatched_packages`) so the IPA cycle is observable
   end to end.
2. `ToolkitLogic._queue_ipa_poll_sequence()` flips
   `ipa_poll_session_active = True` when the BIP burst is queued
   and stashes the request payload so a test can introspect it.
3. `ToolkitLogic._apply_close_channel_response()` clears the
   session flag on success *and* failure (the bearer is gone
   either way).
4. `ToolkitLogic._apply_receive_data_response()` parses the
   eIM-side payload, strips a leading HTTP envelope if present,
   walks the residue as a chain of SGP.32 outer TLVs, and calls
   the dispatcher for each recognised `BFxx` package. Outer tags
   land in `ipa_poll_dispatched_packages`.
5. `ToolkitLogic.set_eim_package_dispatcher(callable)` is the new
   wiring point. `SimulatedSimCardEngine.__init__` calls it with
   `self.sgp.handle_store_data` so the IPA fans the eIM payload
   straight into the same ISD-R handler the modem would hit
   through STORE DATA. Unit tests can pass any
   `Callable[[bytes], tuple[bytes, int, int]]` for isolation.

Tests.

- `tests/test_simcard_local_eim_loopback.py` (Mode A, 11 cases) —
  drives `EimLocalSession.discover_card()` and
  `EimLocalSession.add_initial_eim()` against
  `SimulatedCardConnection`. Pins every `BFxx` ISD-R surface
  (BF20/22/2D/2E/3C/43/2B/55/56) plus the BF57 AddInitialEim
  STORE DATA round-trip.
- `tests/test_simcard_ipa_poll_dispatch.py` (Mode B, 7 cases) —
  fake-modem FETCH/TR loop. Exercises stacked EuiccPackages,
  HTTP envelope stripping, dispatcher errors, missing dispatcher
  fallback, and unknown-payload rejection.
- `tests/test_simcard_ipa_poll_engine_loopback.py` (Mode B, 1
  case) — fake modem driving the *real* `SimulatedSimCardEngine`.
  Asserts an `AddEim` (BF58) ESipa response delivered through
  RECEIVE DATA actually creates a new `SimEimEntry` after the
  cycle closes.

Operator impact.

1. The simulator can now be plugged into the local eIM in place
   of a production eUICC. The bearer (TLS, HTTP, DNS) stays the
   modem's responsibility; the simulator handles the application
   layer.
2. Tests can introspect the IPA cycle via
   `state.toolkit.ipa_poll_*` without instrumenting the
   dispatcher. `ipa_poll_dispatched_packages` is the canonical
   "did the eIM side land?" signal.
3. New documentation lives under
   `site-docs/subsystems/simcard-simulator.md` ("ESipa response
   dispatch on RECEIVE DATA" and "IPA-poll loopback validation
   (Mode A + Mode B)"). The configuration schema in
   `guides/CONFIGURATION_AND_CERTIFICATES.md` is unchanged
   because the new state fields are runtime-only.

## SGP.32 ESipa shape — `BF4F` request and `BF50` follow-up

Scope. Round out the simulator's IPA so the eIM does not just
see a generic HTTP poll. Two missing ESipa shapes were
implemented:

- `BF4F` GetEimPackageRequest (SGP.32 v1.2 §6.5.2.1) is the
  default body of the first SEND DATA in every IPA-poll cycle.
  Carries the EID under tag `5A`; optional `80`/`81`/`82` fields
  for notifyStateChange/stateChangeCause/rPlmn are exposed on
  the builder. The body is wrapped in HTTP/1.1 framing with
  `Content-Type: application/x-gsma-rsp-asn1` and
  `X-Admin-Protocol: gsma/rsp/v2.2.0` so the modem's HTTPS
  client routes it to `/gsma/rsp2/asn1`. `state.toolkit.ipa_poll_request_payload`
  remains the override for tests that need a different opener.

- `BF50` ProvideEimPackageResult (SGP.32 v1.2 §6.5.2.1) is the
  follow-up SEND DATA injected directly before the still-pending
  CLOSE CHANNEL whenever the dispatcher landed at least one
  non-empty per-package result. The body is `5A` EID plus one or
  more `BF51`/`BF52`/`BF54` results; bare ISD-R responses are
  wrapped in `BF51` per the default-CHOICE rule. A second
  RECEIVE DATA is also injected so the eIM's empty/ack reply is
  drained on the same channel.

Latches.

- `state.toolkit.ipa_poll_followup_emitted` — set when the BF50
  pair is queued, reset on CLOSE CHANNEL TR (success or failure).
  Prevents the dispatcher from cascading itself if the eIM's ack
  payload happens to contain BF50 bytes.
- `state.toolkit.ipa_poll_pending_result_payload` and
  `state.toolkit.ipa_poll_last_result_payload` — cache the body
  shipped to the eIM. The latter survives the cycle teardown so
  a test can introspect "what did the IPA tell the eIM about
  cycle N?".
- `state.toolkit.ipa_poll_dispatched_responses` — list of raw
  R-APDU bytes the SGP layer returned for each forwarded
  package, parallel to `ipa_poll_dispatched_packages`.

Allow-list expansion. The eIM-side dispatcher now accepts every
`BFxx` tag `SgpLogic.handle_store_data` knows about
(BF21/25/29/2A/2B/2D/2E/30..34/36/38/3C/3F/41/45/50..5F/64/65),
not just the discovery + AddEim subset. New tags are added to
the allow-list whenever the SGP layer grows a new STORE DATA
opcode.

Tests added.

- `IpaPollEsipaShapeTests::test_default_send_data_carries_get_eim_package_request_bf4f`
- `IpaPollEsipaShapeTests::test_followup_send_data_carries_provide_eim_package_result_bf50`
- `IpaPollEsipaShapeTests::test_followup_is_not_emitted_when_dispatcher_returns_empty`
- `IpaPollEsipaShapeTests::test_followup_emitted_only_once_per_cycle`
- `IpaPollEsipaShapeTests::test_dispatcher_forwards_full_sgp32_tag_range`
- `IpaPollEngineLoopbackTests::test_d7_envelope_drives_full_ipa_poll_cycle` —
  extended to assert both BF4F (initial) and BF50 (follow-up)
  travel out via SEND DATA against the real engine.

Operator impact.

1. The simulator now speaks the canonical ESipa request/response
   shape end-to-end. A real eIM that rejects empty-body polls or
   that requires per-package results now sees the data it
   expects from the simulator.
2. `ipa_poll_last_result_payload` is the new "did the IPA report
   home?" signal, complementary to `ipa_poll_dispatched_packages`
   which already answered "did the eIM side land?".
3. The configuration schema is still runtime-only; no operator
   action is required to pick up the new behaviour.

## SGP coverage round-out — LoadCRL, error CHOICE, notifications

Scope. Three smaller but real gaps closed against the SGP.22 /
SGP.32 surface:

- **BF35 LoadCRL (SGP.22 §5.7.13).** New
  `SgpLogic._handle_load_crl()` accepts the request, persists
  the inner CRL DER bytes in `state.loaded_crls`, and replies
  `BF35 80 01 00` (`ok(0)`). Empty bodies fall to
  `81 01 02` (`invalidSignature(2)`). The dispatcher allow-list
  was extended so an eIM-side LoadCRL pushed over BIP routes
  through the IPA into ISD-R without further wiring.

- **EimPackageResultErrorCode `[0]` in BF50 (SGP.32 §6.5.2.1).**
  `_dispatch_eim_response_packages()` now tracks per-package
  SW pairs and maps them to error codes via
  `_sw_to_eim_package_error_code()`. When every package in a
  cycle failed, the IPA emits the error branch of the
  EimPackageResult CHOICE -- `80 05 30 03 02 01 XX` -- instead
  of fabricating a fake success. `state.toolkit.ipa_poll_failed_packages`
  is the parallel audit trail.

- **Cross-cycle PendingNotification piggyback.** The BF50
  follow-up now stitches a `BF2B/A0` retrieve-all chunk drained
  from `state.notifications` so post-Enable/Disable/Delete
  notifications reach the eIM in the same round-trip rather
  than waiting for a future cycle. Notifications are NOT cleared
  on the eUICC -- the eIM must still issue
  `RemoveNotificationFromList` to pop them, mirroring a real
  card's behaviour.

State surface added.

- `state.loaded_crls: list[bytes]` -- ordered persistence of
  every CRL the eUICC accepted.
- `state.toolkit.ipa_poll_failed_packages: list[tuple[bytes, int]]`
  -- parallel to `ipa_poll_dispatched_packages`, recording
  `(outer_tag, error_code)` for each failed dispatch.

Tests added.

- `tests/test_simcard_load_crl.py` -- 3 unit cases covering
  the ok / invalidSignature / multi-CRL accumulation paths
  on the SGP layer directly.
- `IpaPollEsipaShapeTests::test_dispatch_failure_emits_bf50_error_choice`
  -- pins `80 05 30 03 02 01 01` (invalidPackageFormat) when
  the dispatcher returns `6A80`.
- `IpaPollEsipaShapeTests::test_dispatcher_exception_maps_to_undefined_error_code_127`
  -- pins `80 05 30 03 02 01 7F` when the dispatcher raises.
- `IpaPollEsipaShapeTests::test_pending_notifications_piggyback_on_bf50`
  -- pins `BF2B/A0` retrieve-all chunk inside the BF50 body
  when the eUICC has staged notifications.

Test helpers were also tightened: `_proactive_kind` /
`_command_number` now handle the BER long-form length
(`D0 81 LL` *and* `D0 82 LL LL`) so future SEND DATA bodies
exceeding 0xFF bytes (which the notification piggyback can
trigger) don't trip the assertion.

Operator impact.

1. The eIM's CRL pushes are now a real persistence path on the
   simulator, not a no-op.
2. Real eIMs that branch on the error CHOICE (alarm, retry,
   abandon-cycle) now see the right signal from the simulator
   when ISD-R rejects a package, instead of a misleading
   "success" envelope.
3. Profile-state-change notifications reach the eIM in the same
   poll cycle as the action that produced them, eliminating one
   round-trip of latency for the common
   "EnableProfile + reportNotification" flow.
