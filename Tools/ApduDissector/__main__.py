# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""``python -m Tools.ApduDissector`` entry point."""

from Tools.ApduDissector.main import main

if __name__ == "__main__":
    raise SystemExit(main())
