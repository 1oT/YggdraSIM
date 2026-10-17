// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

/*
 * YggdraSIM Universal GUI bootstrap.
 *
 * Plain ES2020+ script without modules or a bundler, so the surface works
 * byte-for-byte across the pywebview backends (WebKitGTK on Linux, Edge
 * WebView2 on Windows, WKWebView on macOS) with a concatenation-only build.
 */

(function () {
  "use strict";
