#!/usr/bin/env zsh
# EIM-DOWNLOAD test: runs main menu option 3 then EIM-DOWNLOAD.
# Exit 0 = success, 1 = failure. Prints EIM_TEST_RESULT=SUCCESS or EIM_TEST_RESULT=FAIL for agent parsing.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

export PYTHONPATH="${PROJECT_ROOT}:${PROJECT_ROOT}/SCP11:${PYTHONPATH:-}"

# Prefer pyscard venv (Linux, all deps); else .zshrc venv; else project .venv
PYSCARD_VENV="/home/hampushellsberg/Documents/pyscard/bin/activate"
if [[ -f "$PYSCARD_VENV" ]]; then
  source "$PYSCARD_VENV"
fi
[[ -f "$HOME/.zshrc" ]] && source "$HOME/.zshrc" 2>/dev/null || true
if type venv &>/dev/null; then
  venv
fi
PYTHON=python3
if ! command -v "$PYTHON" &>/dev/null; then
  if [[ -x "$PROJECT_ROOT/.venv/bin/python" ]]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python"
  elif [[ -x "$PROJECT_ROOT/.venv/bin/python3" ]]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python3"
  fi
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
if echo "$OUTPUT" | grep -q "eIM polling completed"; then
    echo "EIM_TEST_RESULT=SUCCESS"
    echo "$OUTPUT"
    exit 0
fi

echo "EIM_TEST_RESULT=FAIL"
echo "$OUTPUT"
exit 1
