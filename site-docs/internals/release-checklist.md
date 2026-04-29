---
title: Release Checklist
tags:
  - internals
  - release
  - packaging
---

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
- [ ] `V1_RELEASE_AUDIT.md` Pass-set 1 and Pass-set 2 sections show no
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
    yggdrasim-scp11-test --cmd "HELP; EXIT"
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

## Tagging and publishing

The publish flow is wired end-to-end in `.github/workflows/build.yml`. Pushing
an annotated `v*` tag triggers `docs-strict` + `pytest-suite`, the seven-way
build matrix (Linux x86_64 / arm64 clean+full, macOS x86_64+arm64 clean,
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

- [ ] watch the workflow at `https://github.com/<repo>/actions`. The
      `publish-release` job only runs on `refs/tags/v*`; failures in
      `docs-strict`, `pytest-suite`, or any build leg short-circuit the
      release publish.
- [ ] confirm the GitHub Release page lists the eight asset names plus
      `SHA256SUMS`:

    ```
    yggdrasim-linux-x86_64-clean
    yggdrasim-linux-x86_64-full
    yggdrasim-linux-arm64-clean
    yggdrasim-linux-arm64-full
    yggdrasim-macos-x86_64-clean
    yggdrasim-macos-arm64-clean
    yggdrasim-windows-x86_64-clean.exe
    yggdrasim-clean_X.Y.Z_amd64.deb
    SHA256SUMS
    ```

- [ ] sanity-check that the install-script `release` mode resolves with
      the just-published tag, e.g.:

    ```bash
    YGGDRASIM_REPO=hampushellsberg-dev/YggdraSIM \
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
