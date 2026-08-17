<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Remotes, Publication and Authorship

Read this before pushing anything, adding a remote, or writing a commit
message. It is the tracked, authoritative statement of what may leave the
machine and by which route; any local checklist a contributor keeps is a
convenience copy of what follows, not a substitute for it.

## Remote topology

Three remotes, three audiences. Run `git remote -v` for the concrete URLs;
they are deliberately not written down here, because this file is tracked
and reaches the public remote.

| Remote | Visibility | Carries |
|---|---|---|
| `oneot-github` | public | release branches only |
| `origin` | private | day-to-day development |
| `gitlab` | private | `internal` snapshots, plus a historical `main` |

`main` is the sanitised line. It is structurally incapable of carrying
operator material because that material is never staged into it.

## Why there is no per-remote filter

`.gitignore` is a property of the repository, not of a remote. Commits
carry content and pushes carry commits, so the same branch pushed to two
remotes delivers identical bytes. "GitLab gets everything, GitHub gets the
clean set" is only achievable with two different refs. That is what
`scripts/internal-sync.sh` exists for.

A consequence worth internalising: `.gitignore` never untracks. A file
already committed keeps shipping no matter what pattern you add later.
The tracked paths that match an ignore rule are enumerated in
`scripts/release/public-ignored-allowlist.txt`; the pre-push hook treats
anything matching an ignore rule and absent from that list as operator
material and blocks the push.

## Publishing internal material

```bash
git config core.hooksPath .githooks   # once per clone, required
scripts/internal-sync.sh              # build and push a snapshot
scripts/internal-sync.sh --list       # what the last snapshot was
scripts/internal-sync.sh --dry-run    # build and report, push nothing
```

The script reads `main`'s tree, force-adds the operator material into a
temporary index, commits the result onto `refs/gitlab/snapshot`, and
pushes that ref to GitLab as `internal`. The working tree, `HEAD` and the
real index are never touched, so an interrupted run leaves nothing behind
and no clean-tree precondition applies.

`refs/gitlab/*` is deliberately outside `refs/heads/*`: it is not matched
by `git push <remote> --all`, not fetched by the default refspec, and not
listed by `git branch -a`. There is no branch to check out by accident and
none to merge. Use `--list` to see it, because ordinary git commands will
not.

The script refuses to run unless `core.hooksPath` is set to `.githooks`.
The material it creates is exactly what the hook exists to contain, so the
two are coupled on purpose.

### Never merge a snapshot into `main`

A snapshot commit carries key material. Merging one into `main` puts that
material in the public history, and the objects stay reachable on any
remote that has seen them even after a branch delete.

### Never force-push `gitlab/main`

`gitlab/main` predates the current split and holds paths that exist in no
other history, including `Tools/Sunrise6G/` and the IPA polling stack.
`scripts/internal-sync.sh` only ever writes the `internal` branch and does
not touch it. Verify before any manual push:

```bash
git diff --name-status refs/heads/main..gitlab/main | awk '$1=="A"'
```

## Authorship

Commit metadata names the human author and nobody else. No assistant,
tool, IDE or AI product name appears in an author field, a committer
field, a trailer, a source comment, or generated documentation.

Banned in commit metadata and tracked content:

- an assistant identity in an author or committer field, including any
  `noreply@` address belonging to a tool vendor
- a `Co-authored-by` trailer naming an assistant
- a session or transcript link back to a tool vendor
- a generation credit of the "Generated with <tool>" shape
- an `@author` tag naming an assistant
- a branch name carrying a tool name, which survives into the merge
  commit subject

Naming an assistant product as a *supported integration* is not
attribution and is allowed: `site-docs/how-to/run-the-mcp-server.md`
correctly names the MCP clients the server speaks to. The distinction is
authorship versus interoperability.

Two mechanisms enforce this:

- `scripts/check_repo_hygiene.py` reports an `ai-attribution` violation
  for tracked content. It carries no baseline allowance, so any hit fails
  `tests/test_repo_hygiene.py`.
- `.githooks/pre-push` scans the commits a push would add to a public
  remote and refuses the push if any of them attribute authorship to a
  tool.

If attribution has already landed, rewriting it means rewriting history
and force-pushing, which is a decision for the repository owner. Scope the
range first:

```bash
git log --format='%h %an <%ae>' <base>..HEAD | grep -vF 'Hampus Hellsberg'
```

## Checklist before pushing

1. `git config --get core.hooksPath` returns `.githooks`.
2. `python scripts/check_repo_hygiene.py` reports no new violations.
3. The target remote matches the content: sanitised branches to GitHub,
   snapshots to GitLab, nothing else.
4. `git log --format='%an <%ae>' <range>` lists only human authors.
