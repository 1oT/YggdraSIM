#!/usr/bin/env zsh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# EIM-DOWNLOAD test: runs main menu option 3 then EIM-DOWNLOAD.
# Exit 0 = success, 1 = failure. Prints EIM_TEST_RESULT=SUCCESS or EIM_TEST_RESULT=FAIL for agent parsing.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

export PYTHONPATH="${PROJECT_ROOT}:${PROJECT_ROOT}/SCP11:${PYTHONPATH:-}"

# Pick a Python interpreter in this preference order:
#   1. YGGDRASIM_PYTHON (explicit override)
#   2. YGGDRASIM_PYSCARD_VENV / <project>/../pyscard/bin/activate
#      (legacy convenience for developers who keep a sibling pyscard venv)
#   3. project-local .venv
#   4. system python3 on PATH
PYTHON=""
if [[ -n "${YGGDRASIM_PYTHON:-}" && -x "${YGGDRASIM_PYTHON}" ]]; then
  PYTHON="${YGGDRASIM_PYTHON}"
fi

PYSCARD_VENV="${YGGDRASIM_PYSCARD_VENV:-$PROJECT_ROOT/../pyscard/bin/activate}"
if [[ -z "$PYTHON" && -f "$PYSCARD_VENV" ]]; then
  # shellcheck disable=SC1090
  source "$PYSCARD_VENV"
fi

if [[ -z "$PYTHON" ]]; then
  if [[ -x "$PROJECT_ROOT/.venv/bin/python" ]]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python"
  elif [[ -x "$PROJECT_ROOT/.venv/bin/python3" ]]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python3"
  fi
fi

if [[ -z "$PYTHON" ]]; then
  if command -v python3 &>/dev/null; then
    PYTHON="$(command -v python3)"
  fi
fi

if [[ -z "$PYTHON" ]]; then
  echo "EIM_TEST_RESULT=FAIL"
  echo "error: no python3 interpreter available; set YGGDRASIM_PYTHON or create .venv" >&2
  exit 1
fi

TIMEOUT_SEC=90
INPUT="3
EIM-DOWNLOAD
EXIT
Q
"

OUTPUT=$(printf '%s\n' "$INPUT" | timeout "$TIMEOUT_SEC" "$PYTHON" main/main.py 2>&1) || true

if echo "$OUTPUT" | grep -q "EIM-DOWNLOAD failed"; then
    echo "EIM_TEST_RESULT=FAIL"
    echo "$OUTPUT"
    exit 1
fi
if echo "$OUTPUT" | grep -q "eIM poll flow completed"; then
    echo "EIM_TEST_RESULT=SUCCESS"
    echo "$OUTPUT"
    exit 0
fi
if echo "$OUTPUT" | grep -q "eIM package exchange completed"; then
    echo "EIM_TEST_RESULT=SUCCESS"
    echo "$OUTPUT"
    exit 0
fi

echo "EIM_TEST_RESULT=FAIL"
echo "$OUTPUT"
exit 1
