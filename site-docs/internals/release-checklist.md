---
title: Release Checklist
tags:
  - internals
  - release
  - packaging
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Release Checklist

Publication gate for the three supported distribution shapes: editable
install, Docker image, and PyInstaller bundle. Run this checklist before any
release.

## Pre-flight

- [ ] working tree is clean; `git status` shows what you expect
- [ ] `pyproject.toml` `version` is bumped
- [ ] `README.md` is aligned with the behavior of the new release
- [ ] `guides/CAPABILITIES.md` reflects any new or retired surface
- [ ] `guides/ARCHITECTURE.md` reflects any new cross-module dependency
- [ ] `site-docs/` pages under `subsystems/`, `reference/`, and `how-to/`
      are updated where relevant
- [ ] `Tools/HilBridge/RSPRO.asn` is an up-to-date mirror of the
      operator's local `docs/RSPRO.asn` (and still present as
      package-data in `pyproject.toml`)
- [ ] operator-facing docs that reference `docs/` describe it as an
      optional local developer tree (not as shipped content)
- [ ] The local-only pre-release audit notes show no
      open action items that a release should ship with; anything
      explicitly deferred to post-v1 is listed in the "Deferred" blocks
- [ ] `pyflakes SCP03/ SCP11/ SCP80/ SIMCARD/ Tools/ main/ plugins/
      yggdrasim_common/` is clean modulo the two documented `# noqa:
      F401` probes and the `SCP11/shared` / `SCP11/relay` star-import
      shims

## Editable install

- [ ] `python -m pip install -e .` succeeds in a clean venv
- [ ] every installed console script launches:

    ```bash
    yggdrasim-scp03 --cmd "EXIT"
    yggdrasim-scp80 --cmd "exit"
    yggdrasim-scp11 --cmd "EXIT"
    yggdrasim-scp11-live --cmd "HELP; EXIT"
    yggdrasim-scp11-local-access --cmd "HELP; EXIT"
    yggdrasim-scp11-eim-local --cmd "HELP; EXIT"
    yggdrasim-profile-package --cmd "STATUS; EXIT"
    yggdrasim-profile-autoload --help
    yggdrasim-apdu-fuzzer --help
    yggdrasim-eum-diag --help
    yggdrasim-suci-tool --cmd "STATUS; EXIT"
    ```

- [ ] registry resolves:

    ```bash
    python -c "from yggdrasim_common.registry import search; \
        print(list(search('orchestrator'))[:5])"
    ```

## Targeted test suite

Run narrowly-targeted pytest invocations that match the touched surfaces.
Do not mass-run. Redirect noisy runs to a log file and inspect with `rg`.

- [ ] each test file that exercises a changed area passes
- [ ] plugin runtime behavior is exercised through
      `tests/test_polling_plugin_*.py` where applicable
- [ ] HIL-related tests pass in their emulated form

## Docker

- [ ] `docker build -t yggdrasim:test .` succeeds
- [ ] `docker run --rm yggdrasim:test yggdrasim-profile-package --cmd "EXIT"`
      exits cleanly
- [ ] mounted-volume run persists state across invocations

## PyInstaller bundle

- [ ] `pyinstaller --clean --noconfirm yggdrasim_main.spec` succeeds
- [ ] `dist/yggdrasim` launches and writes the expected runtime tree
- [ ] at least one card-facing surface works end-to-end against the bundled
      runtime material
- [ ] the runtime root resolution is correct for the target OS

## Documentation site

- [ ] `python -m mkdocs build --strict` succeeds from the repo root
- [ ] the mirrored `site-docs/sources/` is regenerated via
      `python site-docs/_tools/mirror_source_docs.py`
- [ ] nav entries that reference new pages exist and resolve
- [ ] nav entries for removed pages are removed
- [ ] `python -m mkdocs build --strict -f mkdocs.oneot.yml` succeeds as well:
      that is the variant `.github/workflows/deploy-docs.yml` publishes to
      yggdrasim.1ot.com on every push to `main` (GitHub Pages in workflow
      mode; the custom domain is a repository setting, and no branch holds
      the built site)

## Manual unsigned test draft

Use the **Main Test Draft Release** workflow only when a cross-platform test
bundle is needed before a production release. It is a manual
`workflow_dispatch` flow restricted to `main`; pull requests and ordinary
pushes never publish test assets.

- [ ] dispatch the workflow from `main` and confirm its recorded commit SHA is
      the exact revision you intend to test
- [ ] confirm the workflow creates a new draft tagged
      `ci-main-<run-id>-<attempt>` and records both the exact SHA and Actions
      run in its notes
- [ ] confirm the draft is not the latest release and remains a draft; install
      scripts must not consume `ci-main-*` tags or the test-only asset names
- [ ] treat every asset as an **UNSIGNED TEST BUILD**: Windows may display a
      Microsoft Defender SmartScreen warning, while the unsigned and
      unnotarized macOS build may be blocked by Gatekeeper
- [ ] confirm every primary asset has a `.sha256` sidecar
- [ ] for a successful run, confirm the final asset set also contains a
      CycloneDX SBOM and a global `SHA256SUMS`, and that the draft is marked
      **COMPLETE**
- [ ] if any build or verification leg fails, confirm the draft is marked
      **INCOMPLETE**; do not mistake partial assets for a complete test set
- [ ] verify downloaded assets against their sidecars or `SHA256SUMS` before
      testing them
- [ ] remove a stale `ci-main-*` draft yourself once diagnosis is done. The
      build workflow carries no delete path by design; `CI Draft Cleanup`
      (`.github/workflows/ci-draft-cleanup.yml`) reaps `ci-main-*` and
      `ci-windows-main-*` drafts older than seven days on a daily schedule,
      so anything worth keeping must be published or copied before then

This draft flow does not replace or weaken the production flow below. It never
publishes a signed release, and it is not evidence that Windows signing,
macOS signing/notarization, provenance, or production publication gates pass.

### Windows-only test artifact

Use **Windows Test Artifact** when a single Windows x86_64 clean bundle is
enough. It is a manual, `main`-only flow and does not start the other platform
jobs.

- [ ] confirm the run attempts one Actions artifact with one-day retention;
      quota failure is visible but does not prevent the draft fallback
- [ ] confirm the unique `ci-windows-main-<run-id>-<attempt>` draft remains a
      draft prerelease targeted at the dispatched SHA
- [ ] confirm the draft has exactly one Windows ZIP and its `.sha256` sidecar
- [ ] confirm a **COMPLETE** draft was redownloaded, checksum-verified,
      extracted, and smoke-tested; never use an **INCOMPLETE** draft
- [ ] treat both executables as unsigned test builds that may trigger
      Microsoft Defender SmartScreen

## Tagging and publishing

The publish flow is wired end-to-end in `.github/workflows/build.yml`. Pushing
an annotated `v*` tag triggers `docs-strict` + `pytest-suite`, the release
build matrix (Linux x86_64 / arm64 clean+full, macOS arm64 clean,
Windows x86_64 clean, Debian package) and the `publish-release` job. The
`publish-release` job:

- downloads every matrix artefact;
- renames each binary to the canonical name the install scripts consume
  (`yggdrasim-{os}-{arch}-{flavor}[.exe]`, see
  `scripts/install/_common.sh::yg_asset_name` and
  `scripts/install/install-windows.ps1::Install-YgFromRelease`);
- generates a `SHA256SUMS` manifest;
- guards the matrix against silent drift with an explicit "required asset"
  list before calling `gh release create`;
- calls `gh release create <tag> --notes-from-tag --verify-tag …`, which
  reuses the annotated tag message as the public release notes.

The annotated `v*` path remains the only production publication path. It uses
canonical installer-facing asset names and fails closed if any required
build, checksum, provenance, or publication gate does not pass. Windows
Authenticode signing and macOS signing plus notarization run when the
repository holds the `WINDOWS_CODESIGN_*` and `MACOS_CODESIGN_*` /
`MACOS_NOTARY_*` secrets. A repository without them publishes unsigned
binaries and the release notes gain a *Code signing* section that says so;
a partial set of secrets fails the build, because it is a misconfiguration
rather than a decision.
Before any platform build or signing step, CI also requires the tag to match
`v<project.version>`, verifies that it is annotated, and confirms that its
exact commit is reachable from `origin/main` or from an `origin/release/*`
branch.

### Annotated-tag-message contract

The release page's body comes from the **annotated** tag message via
`gh release create --notes-from-tag`. Tagging steps:

- [ ] tag the release in git **with an annotation that reads as a
      release note** (covers headline behavioural changes, defaults,
      migration considerations):

    ```bash
    git tag -a vX.Y.Z -m "$(cat <<'EOF'
    YggdraSIM vX.Y.Z

    First / next … release. Notable changes:

    - …
    - …
    EOF
    )"
    git push origin vX.Y.Z
    ```

- [ ] confirm the tagged commit is already reachable from `origin/main` or
      from a `release/<major>.<minor>.x` branch; the release policy gate
      rejects production tags made from arbitrary commits or unmerged
      branches before any platform build starts
- [ ] watch the workflow at `https://github.com/<repo>/actions`. The
      `publish-release` job only runs on `refs/tags/v*`; failures in
      `docs-strict`, `pytest-suite`, or any build leg short-circuit the
      release publish.
- [ ] confirm the GitHub Release page lists the seven asset names plus
      `SHA256SUMS`:

    ```
    yggdrasim-linux-x86_64-clean
    yggdrasim-linux-x86_64-full
    yggdrasim-linux-arm64-clean
    yggdrasim-linux-arm64-full
    yggdrasim-macos-arm64-clean
    yggdrasim-windows-x86_64-clean.exe
    yggdrasim-clean_X.Y.Z_amd64.deb
    SHA256SUMS
    ```

- [ ] sanity-check that the install-script `release` mode resolves with
      the just-published tag, e.g.:

    ```bash
    YGGDRASIM_REPO=1oT/YggdraSIM \
      scripts/install/install-linux.sh --version vX.Y.Z
    ```

- [ ] publish the Docker image (`.github/workflows/docker.yml`) if that
      is part of the release.

## Post-release

- [ ] smoke-test the published artifacts on a fresh host
- [ ] open issues for any deferred follow-up that surfaced during the
      checklist

## Related pages

- [Build and Packaging](../build-and-packaging.md)
- [Build a Bundled Executable](../how-to/build-a-bundled-exe.md)
- [Testing Guide](testing-guide.md)
