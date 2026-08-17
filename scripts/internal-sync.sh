#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
#
# Publish the working tree -- including the material git normally ignores
# -- to the internal GitLab remote.
#
#   scripts/internal-sync.sh            build and push a snapshot
#   scripts/internal-sync.sh --list     show what the last snapshot was
#   scripts/internal-sync.sh --dry-run  build and report, push nothing
#
# One repo, one working tree, one command. What it does underneath:
#
#   1. reads the current public branch's tree (default: main)
#   2. force-adds the operator material .gitignore hides, in a temporary
#      index, so neither HEAD nor the real index nor the working tree moves
#   3. commits that tree onto refs/gitlab/snapshot
#   4. pushes it to the GitLab remote as the `internal` branch
#
# Why a separate ref rather than a commit-time flag on main: a commit is
# indivisible. Force-add the material into a main commit and it is in
# main's history, so the next `git push github main` publishes your keys.
# Git has no per-remote content filtering -- the ref is the only seam.
#
# Why refs/gitlab/* rather than a branch: refs outside refs/heads/* are
# not matched by `git push <remote> --all`, are not fetched by the default
# refspec, and do not appear in `git branch -a`. There is no branch to
# check out by accident and none to merge into main. The cost is that the
# snapshot is invisible to everyday git commands, which is what --list is
# for.
#
# The pre-push hook is the backstop for a hand-rolled push of this ref to
# a public remote. This script refuses to run unless that hook is
# installed, so the thing that creates the material cannot run without the
# net that catches it.

set -euo pipefail

PUBLIC_BRANCH="${YGGDRASIM_PUBLIC_BRANCH:-main}"
GITLAB_REMOTE="${YGGDRASIM_GITLAB_REMOTE:-gitlab}"
INTERNAL_BRANCH="${YGGDRASIM_INTERNAL_BRANCH:-internal}"
SNAPSHOT_REF="refs/gitlab/snapshot"

# The untracked half of a dev checkout: the runtime-root directories every
# subsystem resolves through, the SGP.26 tree under SCP11 (of which
# Workspace/ carries only a subset), the SCP11 runtime state, and the
# upstream evidence packages.
MATERIAL_PATHS=(
  "plugins"
  "Workspace"
  "state"
  "SCP11/SGP.26_test_Certs"
  "SCP11/eim_local"
  "SCP11/live"
  "SCP11/test"
  "SCP11/local_access"
  "reports"
  "upstream_patches"
  "tests/eim-sh"
  "Tools/ProfilePackage"
)

# `git add -f` on a directory overrides every ignore rule beneath it,
# which would otherwise sweep in bytecode caches and the webview profile.
# :(exclude,glob) is required -- a bare :(glob) is a positive pathspec and
# lets the same paths straight back in.
MATERIAL_EXCLUDES=(
  ':(exclude,glob)**/__pycache__/**'
  ':(exclude,glob)**/*.pyc'
  ':(exclude,glob)**/*.pyo'
  ':!state/gui_webview_profile'
)

die() { printf '\033[31m[internal-sync] %s\033[0m\n' "$*" >&2; exit 1; }
info() { printf '\033[36m[internal-sync]\033[0m %s\n' "$*"; }

command -v git >/dev/null || die "git is not on PATH"
git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

MODE="push"
case "${1:-}" in
  --list) MODE="list" ;;
  --dry-run) MODE="dry-run" ;;
  "") ;;
  *) die "unknown argument '$1'. Use --list or --dry-run." ;;
esac

if [ "$MODE" = "list" ]; then
  if ! git rev-parse -q --verify "$SNAPSHOT_REF" >/dev/null; then
    info "no snapshot yet. Run scripts/internal-sync.sh to build one."
    exit 0
  fi
  info "snapshot history on $SNAPSHOT_REF (newest first)"
  git log --format='  %h  %ad  %s' --date=short "$SNAPSHOT_REF" \
    --not "$(git rev-parse "$PUBLIC_BRANCH")" | head -n 20
  exit 0
fi

# The hook is what stops this material reaching a public remote. Running
# without it installed is the one failure mode with no recovery, so refuse
# rather than warn.
HOOKS_PATH="$(git config --get core.hooksPath || true)"
if [ "$HOOKS_PATH" != ".githooks" ]; then
  die "the pre-push guard is not installed. Run:

    git config core.hooksPath .githooks

  Without it nothing stops the snapshot ref reaching a public remote."
fi

git remote get-url "$GITLAB_REMOTE" >/dev/null 2>&1 \
  || die "no '$GITLAB_REMOTE' remote. Add it, then rerun: git remote add $GITLAB_REMOTE <url>"

REMOTE_URL="$(git remote get-url "$GITLAB_REMOTE")"
case "$REMOTE_URL" in
  *github.com*|*github.io*)
    die "remote '$GITLAB_REMOTE' points at GitHub ($REMOTE_URL). Refusing."
    ;;
esac

BASE_SHA="$(git rev-parse -q --verify "$PUBLIC_BRANCH")" \
  || die "no branch '$PUBLIC_BRANCH'. Set YGGDRASIM_PUBLIC_BRANCH to override."
info "base: $PUBLIC_BRANCH @ ${BASE_SHA:0:8}"

PRESENT=()
for path in "${MATERIAL_PATHS[@]}"; do
  if [ -e "$path" ]; then
    PRESENT+=("$path")
    info "  material: $path ($(find "$path" -type f 2>/dev/null | wc -l | tr -d ' ') files)"
  fi
done
if [ ${#PRESENT[@]} -eq 0 ]; then
  die "none of the material paths exist locally. Nothing to sync."
fi

# Build in a temporary index. The working tree, HEAD and the real index
# are never touched, so an interrupted run leaves nothing to clean up and
# there is no requirement to have a clean tree first. The snapshot is the
# public commit's tree plus the material, which makes it reproducible from
# BASE_SHA regardless of what is uncommitted alongside it.
TMP_INDEX="$(mktemp -t yggdrasim-internal-sync.XXXXXX)"
cleanup() { rm -f "$TMP_INDEX"; }
trap cleanup EXIT

GIT_INDEX_FILE="$TMP_INDEX" git read-tree "$BASE_SHA"
GIT_INDEX_FILE="$TMP_INDEX" git add -f -- "${PRESENT[@]}" "${MATERIAL_EXCLUDES[@]}"

TREE="$(GIT_INDEX_FILE="$TMP_INDEX" git write-tree)"
FILE_COUNT="$(git ls-tree -r --name-only "$TREE" | wc -l | tr -d ' ')"

# An identical tree means neither the public commit nor the material moved,
# so there is nothing to publish. Comparing the tree alone is enough: the
# base commit is folded into the tree, so a different BASE_SHA that somehow
# produced the same bytes is the same snapshot by definition.
PARENT="$(git rev-parse -q --verify "$SNAPSHOT_REF" || true)"
if [ -n "$PARENT" ] && [ "$(git rev-parse "$PARENT^{tree}")" = "$TREE" ]; then
  info "snapshot already matches the working tree; nothing to do"
  exit 0
fi

# First parent is the previous snapshot so the ref has a history and
# --force-with-lease has something to lease against; second parent is the
# public commit the snapshot was taken from, which records the anchor.
COMMIT_ARGS=("$TREE")
if [ -n "$PARENT" ]; then
  COMMIT_ARGS+=(-p "$PARENT")
fi
COMMIT_ARGS+=(-p "$BASE_SHA")

COMMIT="$(git commit-tree "${COMMIT_ARGS[@]}" -m "Internal snapshot of ${BASE_SHA:0:8}

Carries operator material that .gitignore keeps out of the public tree:
$(printf '  %s\n' "${PRESENT[@]}")

Generated by scripts/internal-sync.sh. This ref is a publication target,
never a development line -- never merge it into ${PUBLIC_BRANCH}, which
would put key material in the public history.")"

info "snapshot ${COMMIT:0:8}: $FILE_COUNT files"

if [ "$MODE" = "dry-run" ]; then
  info "dry run: built ${COMMIT:0:8}, pushed nothing, ref left unchanged"
  exit 0
fi

git update-ref "$SNAPSHOT_REF" "$COMMIT" ${PARENT:+"$PARENT"}

info "pushing $SNAPSHOT_REF to '$GITLAB_REMOTE' as '$INTERNAL_BRANCH'"
git push --force-with-lease "$GITLAB_REMOTE" "$SNAPSHOT_REF:refs/heads/$INTERNAL_BRANCH"

info "done. '$PUBLIC_BRANCH' is untouched and still sanitised."
