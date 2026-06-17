/*
 * theme-init.js — applied synchronously in <head> before first paint.
 *
 * Reads the persisted theme from localStorage and installs it as a
 * `data-theme` attribute on the root element so the CSS cascade does
 * not flash the default Nord Dark palette on every load. A separate
 * bootstrap file is required because the page CSP blocks inline
 * <script> content (script-src 'self').
 */

(function () {
  "use strict";
  var THEME_KEY = "ygg-gui-theme";
  var VALID = { "nord-dark": 1, "nord-light": 1, "oneot-dark": 1, "oneot-light": 1, "matrix": 1 };
  var saved = null;
  try {
    saved = window.localStorage.getItem(THEME_KEY);
  } catch (err) {
    saved = null;
  }
  if (saved && VALID[saved]) {
    document.documentElement.setAttribute("data-theme", saved);
  } else {
    document.documentElement.setAttribute("data-theme", "nord-dark");
  }
})();
