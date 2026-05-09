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
- [ ] no local-only audit/report files are required to validate this release;
      all release gates are represented by tracked tests, docs, and CI checks
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

The CI workflows are currently validation-only for the v1.0.1 cycle. They run
build/test checks but do not publish release assets and do not push Docker
images.

Release publication is therefore a manual maintainer step.

### Tagging contract

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

- [ ] watch the workflow at `https://github.com/<repo>/actions` and
      confirm the validation jobs complete for the release tag/branch.
- [ ] confirm the GitHub Release page lists the seven binary asset names plus
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

## Post-release

- [ ] smoke-test the published artifacts on a fresh host
- [ ] open issues for any deferred follow-up that surfaced during the
      checklist

## Related pages

- [Build and Packaging](../build-and-packaging.md)
- [Build a Bundled Executable](../how-to/build-a-bundled-exe.md)
- [Testing Guide](testing-guide.md)
