# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Golden-card cross-checks for the YggdraSIM SIMCARD module.
#
# Tests in this package require a physical UICC / eUICC attached via
# PC/SC and are skipped automatically when ``YGGDRASIM_GOLDEN_CARD=1``
# is not set. Keeping them in a dedicated subpackage prevents the
# default pytest target from ever attempting to touch card readers.
