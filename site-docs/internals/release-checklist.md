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

- [ ] tag the release in git:

    ```bash
    git tag -a vYYYY.M.P -m "Release vYYYY.M.P"
    git push origin vYYYY.M.P
    ```

- [ ] produce a release note in the project's release surface. Reference
      the CAPABILITIES changes and any migration considerations.
- [ ] publish the Docker image (if that's part of your process)
- [ ] publish the bundled executables for each supported OS (if that's part
      of your process)

## Post-release

- [ ] smoke-test the published artifacts on a fresh host
- [ ] open issues for any deferred follow-up that surfaced during the
      checklist

## Related pages

- [Build and Packaging](../build-and-packaging.md)
- [Build a Bundled Executable](../how-to/build-a-bundled-exe.md)
- [Testing Guide](testing-guide.md)
