#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
#
# Run a uv command again when it fails, purging uv's cache in between.
#
# A git-sourced dependency (pySim, the asn1tools fork) reaches the build
# environment through `git clone --local` from uv's cache. When another
# process writes into that cache while the clone hardlinks its objects,
# git aborts the clone ("hardlink different from source") and uv reports
# "Git operation failed". The workflow keeps git's background maintenance
# off to remove the usual writer; this script covers what is left by
# trying again from an empty cache. Every argument after the uv binary
# is passed through unchanged.
#
#   scripts/release/uv_sync_retry.sh uv sync --frozen --extra full
#   UV_SYNC_ATTEMPTS=5 scripts/release/uv_sync_retry.sh /opt/uv/bin/uv sync --frozen

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <uv binary> <uv arguments...>" >&2
  exit 2
fi

uv_bin="$1"
shift
attempts="${UV_SYNC_ATTEMPTS:-3}"
attempt=1

while :; do
  if "$uv_bin" "$@"; then
    exit 0
  fi
  if [ "$attempt" -ge "$attempts" ]; then
    echo "uv $* failed on each of $attempts attempts" >&2
    exit 1
  fi
  echo "::warning::uv $* failed (attempt $attempt of $attempts); purging the uv cache and retrying" >&2
  "$uv_bin" cache clean || true
  sleep 10
  attempt=$((attempt + 1))
done
