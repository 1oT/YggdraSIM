# site-docs tooling

Scripts under `site-docs/_tools/` support the MkDocs site. They do not run
as part of a normal `mkdocs build`; invoke them explicitly from the
repository root.

| Script | Purpose |
| --- | --- |
| `mirror_source_docs.py` | Mirror authored source docs from `guides/`, `plugins/`, `SCP11/`, `tests/`, `reports/`, and root text pages into `site-docs/sources/`, and rebuild the `site-docs/source-library.md` index. |
| `check_internal_links.py` | Walk every Markdown file under `site-docs/` and verify inline links resolve to an existing file. Exits non-zero on failure. |
| `build_cli_matrix.py` | Regenerate the CLI matrix section of `site-docs/reference/cli-matrix.md` from `pyproject.toml` and `yggdrasim_common/registry.py`. |
| `build_combined.py` | Concatenate every page referenced in `mkdocs.yml` `nav` into a single Markdown file (default `YggdraSIM.md` at the repo root). Headings are shifted and internal links are rewritten to in-document anchors so the output is self-contained. |

## Suggested workflow

```bash
python site-docs/_tools/mirror_source_docs.py
python site-docs/_tools/build_cli_matrix.py
python site-docs/_tools/check_internal_links.py
python -m mkdocs build --strict
python site-docs/_tools/build_combined.py
```

The build is strict, so missing files or broken nav entries fail fast.
`build_combined.py` runs last because it reads the final `mkdocs.yml` nav
and writes `YggdraSIM.md` at the repo root. The combined file is listed in
`.gitignore` so it is regenerated locally on demand, not committed.

## `build_combined.py` options

| Flag | Effect |
| --- | --- |
| `--out PATH` | Write the combined Markdown to `PATH` instead of `YggdraSIM.md`. |
| `--dry-run` | Print the combined Markdown to stdout without writing a file. |

## Single-file Markdown and PDF (full site in one document)

`build_combined.py` walks `mkdocs.yml` `nav`, concatenates every page, demotes
headings, and rewrites internal links to in-document anchors. The output matches
the style of a one-shot export such as a VS Code "Markdown PDF" run over the
combined file.

From the repository root:

```bash
python3 site-docs/_tools/build_combined.py
```

That writes `YggdraSIM.md` (gitignored). Open it in your editor and export to
PDF the same way you produced `Markdown Preview.pdf` (for example the Markdown
PDF extension: command palette → export PDF), or use any print-to-PDF driver
from a Markdown preview.

To write elsewhere (for example your Downloads folder):

```bash
python3 site-docs/_tools/build_combined.py --out /path/to/YggdraSIM-full.md
```

Regenerate after `mkdocs.yml` nav changes or substantive edits under
`site-docs/` so anchors and page order stay aligned with the site.

## Conventions

- These scripts are single-file and standalone.
- They do not import project runtime code except for what they explicitly
  need (`yggdrasim_common.registry` is the only project import, used by the
  CLI matrix builder).
- They write under `site-docs/` only, except for `build_combined.py`, which
  writes `YggdraSIM.md` at the repo root by default (ignored in git).
- They never modify project source files.
