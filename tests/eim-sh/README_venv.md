# Recreate venv for current platform (Linux)

If you see `Exec format error` or the venv was built on another architecture (e.g. ARM vs x86), recreate it on this machine:

```bash
cd /path/to/YggdraSIM

# Remove existing venv
rm -rf .venv

# Create new venv (Python 3)
python3 -m venv .venv

# Activate and install deps
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Then run the EIM test or `tests/eim-sh/run_10_times.sh`; the script will use `.venv/bin/python3` when `asn1crypto` is available there.
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->
