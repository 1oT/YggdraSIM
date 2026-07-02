// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

/*
 * YggdraSIM Universal GUI — Phase A bootstrap.
 *
 * Plain ES2020+ modules-free JS so the surface works byte-for-byte
 * across the pywebview backends (WebKitGTK on Linux, Edge on Windows,
 * WKWebView on macOS) without a build step. Phase B will swap this out
 * for a Vite + Vue / Svelte project; see V2_UNIVERSAL_GUI_PLAN.md §7.1.
 */

(function () {
  "use strict";
