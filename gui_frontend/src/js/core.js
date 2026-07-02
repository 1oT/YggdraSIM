// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.


  // -- Token management ----------------------------------------------------
  //
  // Desktop mode: pywebview navigates to "/?t=<token>". We lift that
  // token into sessionStorage and strip the query string so subsequent
  // loads don't carry it in the URL bar.
  // Web-server mode: no token-in-URL; operator logs in out-of-band.
  // sessionStorage is the single source of truth for `fetch` headers.

  var TOKEN_KEY = "ygg-gui-token";
  var THEME_KEY = "ygg-gui-theme";
  // VALID_THEMES sourced from window.YGG_VALID_THEMES (set by theme-init.js
  // before first paint). Single source of truth — add new themes there.
  var VALID_THEMES = window.YGG_VALID_THEMES || {
    "nord-dark": 1, "nord-light": 1,
    "oneot-dark": 1, "oneot-light": 1,
    "matrix": 1, "gruv-dark": 1, "ink-light": 1,
    "ocean-dark": 1, "solarized-dark": 1, "solarized-light": 1,
    "tokyo-night": 1, "catppuccin-mocha": 1, "catppuccin-latte": 1,
    "dracula": 1, "github-dark": 1, "github-light": 1,
  };

  function captureTokenFromUrl() {
    try {
      var params = new URLSearchParams(window.location.search);
      var t = params.get("t");
      if (t && t.length > 0) {
        window.sessionStorage.setItem(TOKEN_KEY, t);
        params.delete("t");
        var cleaned = window.location.pathname + (params.toString() ? "?" + params.toString() : "");
        window.history.replaceState({}, "", cleaned);
      }
    } catch (err) {
      // sessionStorage may be unavailable in restricted WebViews; fall through.
    }
  }

  function getToken() {
    try {
      return window.sessionStorage.getItem(TOKEN_KEY) || "";
    } catch (err) {
      return "";
    }
  }

  function setToken(value) {
    try {
      window.sessionStorage.setItem(TOKEN_KEY, value || "");
    } catch (err) {
      // no-op
    }
  }

  // -- Theme management ----------------------------------------------------
  //
  // `theme-init.js` sets the initial attribute before first paint. Here we
  // only sync the <select> to the current value and persist follow-up
  // changes. localStorage (not sessionStorage) so the choice survives
  // process restarts of the pywebview launcher.

  function getCurrentTheme() {
    var attr = document.documentElement.getAttribute("data-theme") || "nord-dark";
    return VALID_THEMES[attr] ? attr : "nord-dark";
  }

  function applyTheme(name) {
    var resolved = VALID_THEMES[name] ? name : "nord-dark";
    document.documentElement.setAttribute("data-theme", resolved);
    try {
      window.localStorage.setItem(THEME_KEY, resolved);
    } catch (err) {
      // localStorage may be unavailable in restricted WebViews; fall through.
    }
    return resolved;
  }

  async function apiErrorDetail(response) {
    var text = "";
    try {
      text = await response.text();
    } catch (_err) {
      return "";
    }
    if (!text) return "";
    try {
      var payload = JSON.parse(text);
      if (payload && typeof payload.detail === "string") return payload.detail;
      if (payload && typeof payload.error === "string") return payload.error;
      if (payload && Array.isArray(payload.detail)) {
        return payload.detail.map(function (entry) {
          if (!entry) return "";
          if (typeof entry === "string") return entry;
          var loc = Array.isArray(entry.loc) ? entry.loc.join(".") : "";
          var msg = entry.msg || entry.message || "";
          return [loc, msg].filter(Boolean).join(": ");
        }).filter(Boolean).join("; ");
      }
    } catch (_err) {
      return text.length > 240 ? text.slice(0, 240) + "..." : text;
    }
    return text.length > 240 ? text.slice(0, 240) + "..." : text;
  }

  async function apiFetch(path, options) {
    var opts = options || {};
    var headers = Object.assign({}, opts.headers || {});
    var token = getToken();
    if (token && token.length > 0) {
      headers["Authorization"] = "Bearer " + token;
    }
    if (opts.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    var response = await fetch(path, Object.assign({}, opts, { headers: headers, credentials: "same-origin" }));
    if (response.status === 401) {
      setApiBadge("fail", "unauthorised");
      setStatusError("API rejected bearer token. Reload the launcher to refresh it.");
      throw new Error("unauthorised (" + path + ")");
    }
    if (response.status === 429) {
      setApiBadge("warn", "rate-limited");
      setStatusError("Rate-limited by auth backoff. Wait and retry.");
      throw new Error("rate-limited (" + path + ")");
    }
    if (!response.ok) {
      setApiBadge("warn", "error " + response.status);
      var message = "HTTP " + response.status + " for " + path;
      var detail = await apiErrorDetail(response);
      if (detail) message += ": " + detail;
      throw new Error(message);
    }
    return response.json();
  }

  // -- DOM helpers ---------------------------------------------------------

  function $(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    var node = $(id);
    if (node) {
      node.textContent = value;
    }
  }

  function setApiBadge(state, text) {
    var badge = $("badge-api");
    if (badge) {
      badge.setAttribute("data-state", state);
    }
    setText("badge-api-text", text);
  }

  function setStatusAction(value) {
    setText("status-action", value);
  }

  function setStatusError(value) {
    setText("status-error", value || "");
  }

  function clearError() {
    setStatusError("");
  }

  function setStatusReaders(value) {
    setText("status-readers", value);
  }

  function setStatusSessions(value) {
    setText("status-sessions", value);
  }

  function setStatusActivity(value) {
    setText("status-activity", value);
  }

  function formatUptime(seconds) {
    var total = Math.max(0, Math.floor(seconds || 0));
    var hours = Math.floor(total / 3600);
    var mins = Math.floor((total % 3600) / 60);
    var secs = total % 60;
    if (hours > 0) {
      return hours + "h " + mins + "m " + secs + "s";
    }
    if (mins > 0) {
      return mins + "m " + secs + "s";
    }
    return secs + "s";
  }

  // -- Routing -------------------------------------------------------------

  var state = {
    activeView: "overview",
    activeSubsystem: null,
    subsystems: [],
  };

  function showView(name, options) {
    var views = document.querySelectorAll("section.view");
    views.forEach(function (view) {
      if (view.getAttribute("data-view") === name) {
        view.classList.add("view-active");
      } else {
        view.classList.remove("view-active");
      }
    });
    state.activeView = name;
    if (name !== "command_center") {
      var mainEl = document.querySelector(".main");
      if (mainEl) {
        mainEl.classList.remove("main--module-workbench");
        mainEl.classList.remove("main--saip-workbench");
        mainEl.classList.remove("main--hil-workbench");
      }
    }
    if (name === "about" && typeof loadGuidesForAboutPanel === "function") {
      loadGuidesForAboutPanel();
    }
    setText("crumb-subsystem", {
      overview: "Overview",
      registry: "Registry browser",
      backend: "Card backend",
      env_flags: "Configuration",
      about: "About",
      terminal: "Advanced · Shell",
      host_shell: "Advanced · Host shell",
      live_readers: "Inspect · PC/SC readers",
      card_bridge: "Advanced · Remote Bridge",
      command_center: (options && options.crumb) || "Command Center",
    }[name] || "Overview");
    highlightSidebar(name);
  }

  function highlightSidebar(viewName) {
    document.querySelectorAll(".subsystem-entry").forEach(function (entry) {
      entry.classList.remove("active");
    });
    var tool = document.querySelector('.tool-list .subsystem-entry[data-view="' + viewName + '"]');
    if (tool) {
      tool.classList.add("active");
    }
  }

  // -- Data loaders --------------------------------------------------------

  async function loadHealth() {
    try {
      var data = await apiFetch("/api/health");
      setText("topbar-suite-version", "v" + String(data.version || "…"));
      setText("topbar-suite-active", "active " + formatUptime(data.uptime_seconds));
      setApiBadge("ok", "online");
      clearError();
    } catch (err) {
      setApiBadge("fail", "offline");
    }
  }

  async function loadBackend() {
    try {
      var data = await apiFetch("/api/backend/state");
      setText("overview-backend-value", data.backend);
      setText("overview-backend-source", data.source);
      setText("backend-current", data.backend);
      setText("backend-source", data.source);
      setText("backend-simulated", data.is_simulated ? "yes" : "no");
      syncBackendSwitch(data.backend);
    } catch (err) {
      // keep prior state; overview header already reports API state
    }
  }

  function syncBackendSwitch(backend) {
    var active = String(backend || "").toLowerCase();
    document.querySelectorAll(".topbar-backend-option[data-backend]").forEach(function (btn) {
      var value = String(btn.getAttribute("data-backend") || "").toLowerCase();
      var selected = value === active;
      btn.classList.toggle("is-active", selected);
      btn.setAttribute("aria-pressed", selected ? "true" : "false");
    });
  }

  async function setBackend(backend) {
    setStatusAction("switching backend → " + backend + "…");
    try {
      await apiFetch("/api/backend/card", {
        method: "POST",
        body: JSON.stringify({ backend: backend }),
      });
      await loadBackend();
      setStatusAction("backend now: " + backend);
    } catch (err) {
      setStatusError("failed to switch backend: " + err.message);
    }
  }

  var registrySearchTimer = null;

  async function loadRegistry(query) {
    var tbody = $("registry-rows");
    if (!tbody) return;
    tbody.innerHTML = "<tr><td colspan=\"3\" class=\"loading\">loading…</td></tr>";
    try {
      var path = "/api/registry/search" + (query ? "?query=" + encodeURIComponent(query) : "");
      var data = await apiFetch(path);
      var rows = data.matches || [];
      if (rows.length === 0) {
        tbody.innerHTML = "<tr><td colspan=\"3\" class=\"loading\">no matches</td></tr>";
        return;
      }
      tbody.innerHTML = "";
      rows.forEach(function (row) {
        var tr = document.createElement("tr");
        var td1 = document.createElement("td");
        td1.textContent = row.key;
        var td2 = document.createElement("td");
        td2.textContent = row.module;
        var td3 = document.createElement("td");
        td3.textContent = row.attribute;
        tr.appendChild(td1);
        tr.appendChild(td2);
        tr.appendChild(td3);
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = "<tr><td colspan=\"3\" class=\"loading\">failed: " + escapeHtml(err.message) + "</td></tr>";
    }
  }

  function setEnvFlagToolbarStatus(message) {
    var el = $("env-flag-toolbar-status");
    if (!el) return;
    el.textContent = message || "";
  }

  function setEnvFlagStats(flags) {
    flags = Array.isArray(flags) ? flags : [];
    var setCount = flags.filter(function (flag) { return !!flag.is_set; }).length;
    var sensitiveCount = flags.filter(function (flag) { return !!flag.sensitive; }).length;
    setText("env-flag-count", "flags: " + flags.length);
    setText("env-flag-set-count", "set: " + setCount);
    setText("env-flag-sensitive-count", "sensitive: " + sensitiveCount);
  }

  async function resetPersistedEnvFlags() {
    setEnvFlagToolbarStatus("resetting…");
    try {
      var result = await apiFetch("/api/env_flags/reset", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      var cleared = Number(result && result.removed || 0);
      setEnvFlagToolbarStatus("reset " + cleared + " persisted override" + (cleared === 1 ? "" : "s"));
      await loadEnvFlags();
    } catch (err) {
      setEnvFlagToolbarStatus("reset failed: " + (err && err.message ? err.message : String(err)));
    }
  }

  async function loadEnvFlags() {
    var root = $("env-flag-categories");
    if (!root) return;
    root.innerHTML = "<p class=\"loading\">loading…</p>";
    try {
      var data = await apiFetch("/api/env_flags/list");
      var categories = data.categories || [];
      var flags = data.flags || [];
      setEnvFlagStats(flags);
      root.innerHTML = "";
      categories.forEach(function (cat) {
        var catFlags = flags.filter(function (f) { return f.category === cat; });
        if (catFlags.length === 0) return;
        var section = document.createElement("details");
        section.className = "env-flag-category";
        var summary = document.createElement("summary");
        summary.className = "env-flag-category-summary";
        var title = document.createElement("span");
        title.className = "env-flag-category-title";
        title.textContent = cat;
        var count = document.createElement("span");
        count.className = "env-flag-category-count";
        count.textContent = catFlags.length + " flag" + (catFlags.length === 1 ? "" : "s");
        var body = document.createElement("div");
        body.className = "env-flag-category-body";
        summary.appendChild(title);
        summary.appendChild(count);
        section.appendChild(summary);
        catFlags.forEach(function (flag) {
          body.appendChild(renderEnvFlag(flag));
        });
        section.appendChild(body);
        root.appendChild(section);
      });
      if (root.children.length === 0) {
        root.innerHTML = "<p class=\"loading\">no flags registered</p>";
      }
    } catch (err) {
      setEnvFlagStats([]);
      root.innerHTML = "<p class=\"loading\">failed: " + escapeHtml(err.message) + "</p>";
    }
  }

  function renderEnvFlag(flag) {
    var row = document.createElement("div");
    row.className = "env-flag" + (flag.is_set ? " env-flag--set" : " env-flag--unset");
    if (flag.sensitive) {
      row.className += " env-flag--sensitive";
    }

    var meta = document.createElement("div");
    meta.className = "env-flag-meta";
    var nameEl = document.createElement("div");
    nameEl.className = "env-flag-name";
    var nameText = document.createElement("code");
    nameText.className = "env-flag-name-text";
    nameText.textContent = flag.name;
    nameEl.appendChild(nameText);
    var kind = document.createElement("span");
    kind.className = "env-flag-chip env-flag-chip--kind";
    kind.textContent = flag.kind;
    nameEl.appendChild(kind);
    if (flag.sensitive) {
      var sens = document.createElement("span");
      sens.className = "env-flag-chip env-flag-chip--sensitive";
      sens.textContent = "sensitive";
      nameEl.appendChild(sens);
    }
    var scope = document.createElement("span");
    scope.className = "env-flag-chip env-flag-chip--scope";
    scope.textContent = flag.persist_scope || "persist";
    nameEl.appendChild(scope);
    var summary = document.createElement("div");
    summary.className = "env-flag-summary";
    summary.textContent = flag.summary;
    meta.appendChild(nameEl);
    meta.appendChild(summary);

    var value = document.createElement("div");
    value.className = "env-flag-value";
    if (flag.is_set) {
      value.textContent = "= " + flag.current_value;
    } else {
      value.classList.add("not-set");
      value.textContent = flag.default_hint || "(unset)";
    }

    var editor = document.createElement("div");
    editor.className = "env-flag-editor";

    var input;
    if (Array.isArray(flag.choices) && flag.choices.length > 0) {
      input = document.createElement("select");
      var blankOpt = document.createElement("option");
      blankOpt.value = "";
      blankOpt.textContent = "(unset)";
      input.appendChild(blankOpt);
      flag.choices.forEach(function (choice) {
        var opt = document.createElement("option");
        opt.value = choice;
        opt.textContent = choice;
        input.appendChild(opt);
      });
      input.value = flag.is_set ? String(flag.current_value) : "";
    } else {
      input = document.createElement("input");
      input.type = flag.sensitive ? "password" : "text";
      input.placeholder = flag.default_hint || "";
      input.value = flag.is_set ? String(flag.current_value) : "";
    }
    input.className = "env-flag-input";

    var persistLabel = document.createElement("label");
    persistLabel.className = "env-flag-persist";
    var persistBox = document.createElement("input");
    persistBox.type = "checkbox";
    persistBox.checked = flag.persist_scope !== "persist_session";
    persistBox.disabled = flag.persist_scope === "persist_session";
    persistLabel.appendChild(persistBox);
    persistLabel.appendChild(document.createTextNode(" persist"));

    var setBtn = document.createElement("button");
    setBtn.type = "button";
    setBtn.className = "btn btn-primary env-flag-action";
    setBtn.textContent = "Set";
    setBtn.addEventListener("click", function () {
      applyEnvFlag(flag.name, input.value, persistBox.checked, setBtn);
    });

    var clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.className = "btn env-flag-action env-flag-action--clear";
    clearBtn.textContent = "Clear";
    clearBtn.addEventListener("click", function () {
      applyEnvFlag(flag.name, "", persistBox.checked, clearBtn);
    });

    editor.appendChild(input);
    editor.appendChild(persistLabel);
    editor.appendChild(setBtn);
    editor.appendChild(clearBtn);

    row.appendChild(meta);
    row.appendChild(value);
    row.appendChild(editor);
    return row;
  }

  async function applyEnvFlag(name, value, persist, btn) {
    if (btn) {
      btn.disabled = true;
    }
    setEnvFlagToolbarStatus("applying " + name + "...");
    try {
      var cleaned = String(value || "").trim();
      var result;
      if (cleaned.length === 0) {
        result = await apiFetch("/api/env_flags/" + encodeURIComponent(name) + "/clear", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ persist: !!persist }),
        });
      } else {
        result = await apiFetch("/api/env_flags/" + encodeURIComponent(name) + "/set", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ value: cleaned, persist: !!persist }),
        });
      }
      setEnvFlagToolbarStatus((result && result.note) || "updated " + name);
      clearError();
      await loadEnvFlags();
    } catch (err) {
      var message = "env flag mutation failed: " + (err && err.message ? err.message : String(err));
      setEnvFlagToolbarStatus(message);
      setStatusError(message);
    } finally {
      if (btn) {
        btn.disabled = false;
      }
    }
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (ch) {
      return ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[ch];
    });
  }

  // -- Event wiring --------------------------------------------------------

  function wireTopbar() {
    document.querySelectorAll(".tool-list .subsystem-entry").forEach(function (entry) {
      entry.addEventListener("click", function () {
        var view = entry.getAttribute("data-view");
        showView(view);
        setStatusAction("viewing: " + view);
        if (view === "registry") {
          loadRegistry("");
        } else if (view === "backend") {
          loadBackend();
        } else if (view === "env_flags") {
          loadEnvFlags();
        } else if (view === "overview") {
          loadHealth();
          loadBackend();
        } else if (view === "terminal") {
          loadTerminalModules();
          var activeTab = getActiveTerminalTab();
          if (activeTab && activeTab.fitAddon) {
            setTimeout(function () {
              try { activeTab.fitAddon.fit(); } catch (_err) { /* pane not measured */ }
              sendTerminalResize(activeTab);
            }, 50);
          }
        } else if (view === "host_shell") {
          loadHostShellCapabilities();
          loadHostShellDevices();
        } else if (view === "live_readers") {
          loadLiveReaders();
        } else if (view === "card_bridge") {
          loadCardBridge();
        }
        // Pause the Card Bridge auto-refresh whenever the operator
        // navigates away so we never poll in the background.
        if (view !== "card_bridge") {
          cbStopAutoRefresh();
        }
      });
    });

    var envRefreshBtn = $("env-flag-refresh");
    if (envRefreshBtn) {
      envRefreshBtn.addEventListener("click", function () {
        setEnvFlagToolbarStatus("");
        loadEnvFlags();
      });
    }

    var envResetBtn = $("env-flag-reset-persisted");
    if (envResetBtn) {
      envResetBtn.addEventListener("click", function () {
        if (!window.confirm(
          "Reset ALL persisted environment-flag overrides?\n\n" +
          "This clears home-scope and file-scope writes; process-only " +
          "values are left alone."
        )) {
          return;
        }
        resetPersistedEnvFlags();
      });
    }

    document.querySelectorAll("[data-backend]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var backend = btn.getAttribute("data-backend");
        if (backend) {
          setBackend(backend);
        }
      });
    });

    var searchInput = $("registry-search");
    if (searchInput) {
      searchInput.addEventListener("input", function () {
        var value = searchInput.value.trim();
        if (registrySearchTimer) {
          clearTimeout(registrySearchTimer);
        }
        registrySearchTimer = setTimeout(function () {
          loadRegistry(value);
        }, 200);
      });
    }

    var themeSelect = $("theme-select");
    if (themeSelect) {
      themeSelect.value = getCurrentTheme();
      themeSelect.addEventListener("change", function () {
        var chosen = applyTheme(themeSelect.value);
        themeSelect.value = chosen;
        setStatusAction("theme: " + chosen);
      });
    }
  }

  // -- Terminal (B-2, per-tab) --------------------------------------------
  //
  // Each terminal tab owns a fresh xterm.js ``Terminal`` + ``FitAddon`` +
  // ``WebSocket`` living under an individual ``.terminal-pane`` inside the
  // shared ``#terminal-host`` container. ``activeTerminalTabId`` points at
  // the visible pane; other panes hide behind ``.hidden``. ``pendingInit``
  // is per-tab so sub-shell handoffs (C-6) only auto-type into the tab
  // that was just spawned.

  var terminalTabs = {};
  var activeTerminalTabId = null;

  // When ``scp03LaunchSubShell`` fires, we stash the auto-type payload
  // here and hand it to the next freshly-spawned tab. Using a top-level
  // bootstrap (rather than piggy-backing on the active tab) keeps the
  // sub-shell handoff deterministic even when an unrelated terminal tab
  // happens to be focused at the time of the ribbon click.
  var terminalPendingBootstrap = null;

  // Legacy alias kept so existing call sites (scp03 sub-shell handoff)
  // that reach into ``terminalState.pendingInit`` still work. All writes
  // route through ``terminalPendingBootstrap`` so the NEXT created tab
  // picks them up regardless of which tab is currently active.
  var terminalState = {
    get pendingInit() {
      return terminalPendingBootstrap;
    },
    set pendingInit(value) {
      terminalPendingBootstrap = value || null;
    },
  };

  function getActiveTerminalTab() {
    return activeTerminalTabId ? terminalTabs[activeTerminalTabId] : null;
  }

  async function loadTerminalModules() {
    var sel = $("terminal-module");
    if (!sel) return;
    if (sel.options.length > 0) return;
    try {
      var data = await apiFetch("/api/terminal/modules");
      data.modules.forEach(function (name) {
        var opt = document.createElement("option");
        opt.value = name;
        opt.textContent = "python -m " + name;
        sel.appendChild(opt);
      });
      if (!data.supported) {
        setText("terminal-status", "PTY bridge not supported on this platform.");
        var startBtn = $("terminal-start");
        if (startBtn) startBtn.disabled = true;
      }
    } catch (err) {
      setText("terminal-status", "failed to list modules: " + err.message);
    }
  }

  function wireTerminalPanel() {
    var startBtn = $("terminal-start");
    var stopBtn = $("terminal-stop");
    if (!startBtn) return;
    startBtn.addEventListener("click", startTerminal);
    if (stopBtn) stopBtn.addEventListener("click", stopTerminal);
    var strip = $("terminal-tabs");
    if (strip) {
      strip.addEventListener("click", function (event) {
        var closeBtn = event.target.closest("[data-tab-close]");
        if (closeBtn) {
          event.stopPropagation();
          closeTerminalTab(closeBtn.getAttribute("data-tab-close"));
          return;
        }
        var tab = event.target.closest(".terminal-tab");
        if (tab) {
          selectTerminalTab(tab.getAttribute("data-tab-id"));
        }
      });
    }
    window.addEventListener("resize", function () {
      Object.keys(terminalTabs).forEach(function (tabId) {
        var tab = terminalTabs[tabId];
        if (!tab || tab.id !== activeTerminalTabId) return;
        if (tab.fitAddon) {
          try { tab.fitAddon.fit(); } catch (_err) { /* xterm not ready */ }
        }
        sendTerminalResize(tab);
      });
    });
  }

  function createTerminalTab(moduleName) {
    if (typeof window.Terminal !== "function") {
      setText("terminal-status", "xterm.js failed to load.");
      return null;
    }
    var hostRoot = $("terminal-host");
    if (!hostRoot) return null;

    var tabId = "t" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 6);
    var pane = document.createElement("div");
    pane.className = "terminal-pane hidden";
    pane.setAttribute("data-tab-id", tabId);
    hostRoot.appendChild(pane);

    var term = new window.Terminal({
      convertEol: true,
      cursorBlink: true,
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      theme: { background: "transparent" },
      // Pin scrollback explicitly. xterm.js defaults to 1000 lines; a
      // long-running deep-scan dumps roughly that in a single run, so
      // 1500 covers it without piling up a multi-MB buffer for every
      // tab kept open in the background.
      scrollback: 1500,
    });
    var FitAddonCtor = window.FitAddon && window.FitAddon.FitAddon;
    var fitAddon = FitAddonCtor ? new FitAddonCtor() : null;
    if (fitAddon) term.loadAddon(fitAddon);
    term.open(pane);

    var tab = {
      id: tabId,
      module: moduleName,
      term: term,
      fitAddon: fitAddon,
      socket: null,
      host: pane,
      pid: null,
      status: "idle",
      pendingInit: terminalPendingBootstrap,
    };
    terminalPendingBootstrap = null;
    terminalTabs[tabId] = tab;

    term.onData(function (data) {
      if (tab.socket && tab.socket.readyState === 1) {
        tab.socket.send(JSON.stringify({ type: "stdin", data: data }));
      }
    });

    selectTerminalTab(tabId);
    return tab;
  }

  function selectTerminalTab(tabId) {
    if (!terminalTabs[tabId]) return;
    activeTerminalTabId = tabId;
    Object.keys(terminalTabs).forEach(function (key) {
      var tab = terminalTabs[key];
      if (tab && tab.host) {
        if (key === tabId) {
          tab.host.classList.remove("hidden");
        } else {
          tab.host.classList.add("hidden");
        }
      }
    });
    var active = terminalTabs[tabId];
    if (active && active.fitAddon) {
      try { active.fitAddon.fit(); } catch (_err) { /* pane not measured yet */ }
    }
    sendTerminalResize(active);
    setText("terminal-status", active ? active.status : "idle");
    updateTerminalButtons();
    renderTerminalTabStrip();
  }

  function closeTerminalTab(tabId) {
    var tab = terminalTabs[tabId];
    if (!tab) return;
    if (tab.socket && tab.socket.readyState <= 1) {
      try { tab.socket.close(); } catch (_err) { /* already gone */ }
    }
    if (tab.term && typeof tab.term.dispose === "function") {
      try { tab.term.dispose(); } catch (_err) { /* already gone */ }
    }
    if (tab.host && tab.host.parentNode) {
      tab.host.parentNode.removeChild(tab.host);
    }
    delete terminalTabs[tabId];
    if (activeTerminalTabId === tabId) {
      activeTerminalTabId = null;
      var remaining = Object.keys(terminalTabs);
      if (remaining.length > 0) {
        selectTerminalTab(remaining[remaining.length - 1]);
        return;
      }
    }
    renderTerminalTabStrip();
    updateTerminalButtons();
    if (Object.keys(terminalTabs).length === 0) {
      setText("terminal-status", "idle");
    }
  }

  function renderTerminalTabStrip() {
    var strip = $("terminal-tabs");
    if (!strip) return;
    strip.innerHTML = "";
    Object.keys(terminalTabs).forEach(function (key) {
      var tab = terminalTabs[key];
      if (!tab) return;
      var btn = document.createElement("div");
      btn.className = "terminal-tab"
        + (key === activeTerminalTabId ? " active" : "")
        + (tab.status === "exited" || tab.status === "closed" ? " exited" : "");
      btn.setAttribute("data-tab-id", key);
      btn.setAttribute("role", "tab");
      var label = '<span class="tt-label">' + escapeHtml(tab.module) + '</span>';
      if (tab.pid) {
        label += '<span class="tt-pid">pid ' + escapeHtml(String(tab.pid)) + '</span>';
      } else if (tab.status && tab.status !== "running") {
        label += '<span class="tt-pid">' + escapeHtml(tab.status) + '</span>';
      }
      label += '<button class="tt-close" type="button" data-tab-close="'
        + escapeHtml(key) + '" aria-label="Close tab">&times;</button>';
      btn.innerHTML = label;
      strip.appendChild(btn);
    });
  }

  function updateTerminalButtons() {
    var startBtn = $("terminal-start");
    var stopBtn = $("terminal-stop");
    var active = getActiveTerminalTab();
    if (stopBtn) {
      stopBtn.disabled = !active
        || !active.socket
        || active.socket.readyState !== 1;
    }
    if (startBtn) {
      // Keep "Open tab" enabled so a second module can spawn even while
      // another tab is live. It is only disabled if the PTY bridge is
      // unsupported (that path is handled inside loadTerminalModules).
      startBtn.disabled = false;
    }
  }

  function sendTerminalResize(tab) {
    if (!tab || !tab.term || !tab.socket) return;
    if (tab.socket.readyState !== 1) return;
    tab.socket.send(JSON.stringify({
      type: "resize",
      rows: tab.term.rows,
      cols: tab.term.cols,
    }));
  }

  function startTerminal() {
    var sel = $("terminal-module");
    var moduleName = sel ? sel.value : "";
    if (!moduleName) {
      setText("terminal-status", "pick a module first.");
      return;
    }
    var tab = createTerminalTab(moduleName);
    if (!tab) return;
    var term = tab.term;
    term.clear();
    term.writeln("[yggdrasim-gui] launching python -m " + moduleName + " ...");

    var token = getStoredToken();
    if (!token) {
      tab.status = "no-token";
      setText("terminal-status", "missing token — reload the GUI.");
      renderTerminalTabStrip();
      return;
    }

    var scheme = window.location.protocol === "https:" ? "wss" : "ws";
    var rows = term.rows || 30;
    var cols = term.cols || 120;
    // Reader-as-session: when the operator has an active top-bar pill,
    // forward its name so the PTY route can export YGGDRASIM_READER
    // into the spawned shell's environment. The CLI-side resolver in
    // ``card_backend.create_card_connection`` then maps that name to
    // a PC/SC reader index, so every module launched while a pill is
    // active operates against that reader instead of the default
    // first-enumerated one.
    var activeReader = "";
    try {
      if (commandState && commandState.readerBar) {
        activeReader = String(commandState.readerBar.activeReader || "");
      }
    } catch (_err) { /* commandState may not exist on bootstrap */ }
    var url = scheme + "://" + window.location.host + "/api/terminal/" + encodeURIComponent(moduleName)
      + "?t=" + encodeURIComponent(token)
      + "&rows=" + rows + "&cols=" + cols;
    if (activeReader.length > 0) {
      url += "&reader=" + encodeURIComponent(activeReader);
    }
    var sock = new WebSocket(url);
    sock.binaryType = "arraybuffer";
    tab.socket = sock;
    tab.status = "connecting";
    setText("terminal-status", "connecting…");
    renderTerminalTabStrip();
    updateTerminalButtons();

    sock.onopen = function () {
      tab.status = "running";
      setText("terminal-status", "running · " + moduleName);
      sendTerminalResize(tab);
      updateTerminalButtons();
      renderTerminalTabStrip();
    };
    sock.onmessage = function (event) {
      if (typeof event.data === "string") {
        try {
          var msg = JSON.parse(event.data);
          if (msg && msg.event === "spawned") {
            tab.pid = msg.pid;
            tab.status = "running";
            setText("terminal-status", "running · " + moduleName + " · pid=" + msg.pid);
            renderTerminalTabStrip();
            if (tab.pendingInit) {
              var initBytes = String(tab.pendingInit);
              tab.pendingInit = null;
              // Give the child shell a moment to print its prompt before
              // we inject the auto-typed sub-shell command.
              setTimeout(function () {
                if (sock.readyState === 1) {
                  sock.send(JSON.stringify({ type: "stdin", data: initBytes }));
                }
              }, 350);
            }
            return;
          }
          if (msg && msg.event === "exit") {
            term.writeln("\r\n[yggdrasim-gui] child exited.");
            tab.status = "exited";
            setText("terminal-status", "exited");
            renderTerminalTabStrip();
            updateTerminalButtons();
            return;
          }
          if (msg && msg.event === "error") {
            term.writeln("\r\n[yggdrasim-gui] error: " + msg.message);
            tab.status = "error";
            setText("terminal-status", "error: " + msg.message);
            renderTerminalTabStrip();
            return;
          }
        } catch (_err) {
          term.write(event.data);
        }
        return;
      }
      var bytes = new Uint8Array(event.data);
      term.write(bytes);
    };
    sock.onclose = function () {
      tab.socket = null;
      if (tab.status !== "exited" && tab.status !== "error") {
        tab.status = "closed";
      }
      if (activeTerminalTabId === tab.id) {
        setText("terminal-status", tab.status);
      }
      updateTerminalButtons();
      renderTerminalTabStrip();
      // Drop closures so the GC can collect the WebSocket + buffered
      // frames promptly. Without this, repeated terminal start/stop
      // cycles pin a chain of dead sockets through their handlers.
      sock.onmessage = null;
      sock.onopen = null;
      sock.onerror = null;
      sock.onclose = null;
    };
    sock.onerror = function () {
      tab.status = "socket-error";
      if (activeTerminalTabId === tab.id) {
        setText("terminal-status", "socket error");
      }
      renderTerminalTabStrip();
    };
  }

  function stopTerminal() {
    var tab = getActiveTerminalTab();
    if (tab && tab.socket) {
      try { tab.socket.close(); } catch (_err) { /* already gone */ }
    }
  }

  function getStoredToken() {
    try {
      return window.sessionStorage.getItem(TOKEN_KEY) || window.localStorage.getItem(TOKEN_KEY) || "";
    } catch (_err) {
      return "";
    }
  }

  // -- Live readers (B-3) --------------------------------------------------

  async function loadLiveReaders() {
    var body = $("live-readers-body");
    if (body) body.innerHTML = "<tr><td colspan=\"3\" class=\"loading\">probing…</td></tr>";
    setText("live-readers-status", "probing…");
    try {
      var data = await apiFetch("/api/live/readers");
      renderLiveReaders(data);
      populateFlowReaders(data.readers || []);
    } catch (err) {
      if (body) body.innerHTML = "<tr><td colspan=\"3\" class=\"loading\">failed: " + escapeHtml(err.message) + "</td></tr>";
      setText("live-readers-status", "error: " + err.message);
    }
  }

  function renderLiveReaders(data) {
    var body = $("live-readers-body");
    if (!body) return;
    var rows = data.readers || [];
    setText("live-readers-status", "found " + rows.length + " reader(s)");
    body.innerHTML = "";
    if (rows.length === 0) {
      body.innerHTML = "<tr><td colspan=\"3\" class=\"loading\">no readers detected.</td></tr>";
      return;
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      [row.name, row.atr_hex || "(no card)", row.status].forEach(function (cell) {
        var td = document.createElement("td");
        td.textContent = cell != null ? String(cell) : "";
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
  }

  // The legacy dedicated "Download profile" panel was superseded by the
  // Command Center action (scp11.download_profile). We still expose the
  // reader cache so action forms of kind "reader" can pull the latest list.
  function populateFlowReaders(_readers) {
    /* intentionally empty — kept for back-compat; readers render inside
       Command Center action forms now. */
  }

  function wireLiveReadersPanel() {
    var btn = $("live-readers-refresh");
    if (btn) btn.addEventListener("click", loadLiveReaders);
  }

  // -- Card Bridge panel (CB-4 frontend) -----------------------------------
  //
  // Wraps the read-only ``card_bridge.status`` / ``card_bridge.probe``
  // actions in a focused diagnostics surface. Polls status every 5 s
  // while the view is active so operators see auth posture + latency
  // shifts without manual refresh; pauses when the view is hidden so
  // we don't spam the server in the background.
  //
  // Latency history is a rolling 60-sample buffer per probe stream
  // (ping + status); failures stamp a red dot at the bottom of the
  // SVG so a wedged tunnel is visible at a glance.

  var CB_HISTORY_MAX = 60;
  var cbState = {
    history: [],
    autoRefreshTimer: null,
    autoRefreshIntervalMs: 5000,
    lastStatus: null,
    globalState: "idle",
    globalLabel: "idle",
  };

  function cbBridgeStatusFromPayload(data) {
    if (!data || !data.configured) return { state: "idle", label: "idle" };
    if (data.url_source === "marker") return { state: "running", label: "running" };
    return { state: "configured", label: "configured" };
  }

  function cbSetGlobalBridgeStatus(state, label) {
    var nextState = state || "idle";
    var nextLabel = label || nextState;
    cbState.globalState = nextState;
    cbState.globalLabel = nextLabel;
    var pill = $("topbar-card-bridge");
    if (pill) {
      pill.setAttribute("data-state", nextState);
      pill.title = "Remote Bridge status: " + nextLabel
        + ". Click to " + (nextState === "running" ? "stop" : "start") + ".";
      pill.setAttribute("aria-label", pill.title);
    }
    setText("topbar-card-bridge-value", nextLabel);
    cbSyncCommandCenterBridgeIndicators();
  }

  function cbSyncCommandCenterBridgeIndicators() {
    var state = cbState.globalState || "idle";
    var label = cbState.globalLabel || state;
    document.querySelectorAll('#command-center-nav [data-cc-leaf-id="leaf-adv-card-bridge"]').forEach(function (entry) {
      entry.setAttribute("data-cb-state", state);
      entry.classList.toggle("is-cb-active", state === "running");
      var marker = entry.querySelector(".cc-nav-card-bridge-state");
      if (marker) marker.textContent = state === "running" ? "running" : "";
    });
    document.querySelectorAll('.overview-module-card[data-cc-view="card_bridge"]').forEach(function (card) {
      card.setAttribute("data-cb-state", state);
      card.classList.toggle("is-cb-active", state === "running");
      var badge = card.querySelector('[data-cb-role="overview-status"]');
      if (badge) badge.textContent = label;
    });
  }

  function cbSetBadge(elId, posture) {
    var el = $(elId);
    if (!el) return;
    var classes = ["cb-badge"];
    var label = posture || "unknown";
    var variant = "cb-badge-unknown";
    var displayLabel = label;
    switch (posture) {
      case "token-accepted":
      case "no-token-required":
        variant = "cb-badge-ok";
        displayLabel = posture === "token-accepted" ? "auth ok" : "no token (loopback)";
        break;
      case "token-rejected":
      case "token-required-but-missing":
        variant = "cb-badge-fail";
        displayLabel = posture === "token-rejected" ? "token rejected" : "token missing";
        break;
      case "auth-disabled-non-loopback":
        variant = "cb-badge-warn";
        displayLabel = "non-loopback w/o auth";
        break;
      case "ok":
        variant = "cb-badge-ok";
        displayLabel = "online";
        break;
      case "configured-online":
        variant = "cb-badge-ok";
        displayLabel = "online";
        break;
      case "configured":
        variant = "cb-badge-info";
        displayLabel = "configured";
        break;
      case "not-configured":
        variant = "cb-badge-unknown";
        displayLabel = "not configured";
        break;
      case "unreachable":
        variant = "cb-badge-fail";
        displayLabel = "unreachable";
        break;
      case "error":
        variant = "cb-badge-fail";
        displayLabel = "error";
        break;
      default:
        variant = "cb-badge-unknown";
        displayLabel = label || "unknown";
    }
    classes.push(variant);
    el.className = classes.join(" ");
    el.textContent = displayLabel;
  }

  function cbFormatLatencyMs(value) {
    if (typeof value !== "number" || !isFinite(value) || value < 0) return "–";
    if (value >= 1000) return (value / 1000).toFixed(2) + " s";
    if (value >= 100) return value.toFixed(0) + " ms";
    return value.toFixed(1) + " ms";
  }

  function cbFormatTokenSource(source) {
    switch (source) {
      case "env-raw":
        return "YGGDRASIM_CARD_RELAY_TOKEN env";
      case "env-file":
        return "YGGDRASIM_CARD_RELAY_TOKEN_FILE env";
      case "marker":
        return "runtime marker (auto-discovered)";
      default:
        return "(none)";
    }
  }

  async function loadCardBridgeStatus() {
    var summary = $("cb-status-summary");
    try {
      var resp = await apiFetch("/api/actions/card_bridge.status/run", {
        method: "POST",
        body: JSON.stringify({ inputs: {} }),
      });
      if (!resp.ok) {
        cbSetBadge("cb-status-badge", "error");
        cbSetGlobalBridgeStatus("error", "error");
        if (summary) summary.textContent = "status action failed: " + (resp.error || "unknown error");
        return;
      }
      cbState.lastStatus = resp.data || {};
      renderCardBridgeStatus(cbState.lastStatus);
    } catch (err) {
      cbSetBadge("cb-status-badge", "error");
      cbSetGlobalBridgeStatus("error", "error");
      if (summary) summary.textContent = "status request failed: " + (err && err.message || String(err));
    }
  }

  function renderCardBridgeStatus(data) {
    if (!data) return;
    var configured = !!data.configured;
    cbSetBadge("cb-status-badge", configured ? "configured" : "not-configured");
    var global = cbBridgeStatusFromPayload(data);
    cbSetGlobalBridgeStatus(global.state, global.label);
    setText("cb-status-url", data.url || "–");
    setText("cb-status-source", data.url_source || "–");
    var fp = data.token_fingerprint || "";
    setText(
      "cb-status-token",
      data.has_token ? ("present (fp: " + (fp || "n/a") + ")") : "(none)"
    );
    setText("cb-status-token-source", cbFormatTokenSource(data.token_source));

    var copyBtn = $("cb-copy-url");
    if (copyBtn) {
      if (data.url) {
        copyBtn.removeAttribute("disabled");
      } else {
        copyBtn.setAttribute("disabled", "true");
      }
    }

    var summary = $("cb-status-summary");
    if (summary) {
      if (configured) {
        summary.innerHTML =
          "Resolved <code>" + escapeHtml(data.url || "") + "</code>" +
          " (via " + escapeHtml(data.url_source || "?") + "). " +
          (data.has_token
            ? "Bearer token wired up — fingerprint <code>" + escapeHtml(fp || "n/a") + "</code>."
            : "No bearer token configured — only loopback bridges will accept the request.");
      } else {
        summary.innerHTML =
          "Not configured — set <code>YGGDRASIM_CARD_RELAY_URL</code> or pass " +
          "<code>--remote-card-url</code> to talk to a Remote Bridge over SSH.";
      }
    }

    // Probe-card defaults inherit the status snapshot so a fresh page
    // load shows something sensible before the first probe runs.
    setText("cb-probe-token-fp", fp || "–");
  }

  async function runCardBridgeProbe() {
    var urlInput = $("cb-probe-url");
    var tokenInput = $("cb-probe-token");
    var fallbackInput = $("cb-probe-fallback");
    var inputs = {
      url: urlInput ? urlInput.value.trim() : "",
      token: tokenInput ? tokenInput.value : "",
      use_configured: fallbackInput ? !!fallbackInput.checked : true,
    };
    var btn = $("cb-run-probe");
    if (btn) {
      btn.setAttribute("disabled", "true");
      btn.textContent = "probing…";
    }
    try {
      var resp = await apiFetch("/api/actions/card_bridge.probe/run", {
        method: "POST",
        body: JSON.stringify({ inputs: inputs }),
      });
      if (!resp.ok) {
        renderCardBridgeProbe({
          ok: false,
          reason: resp.error || "probe action failed",
        });
        return;
      }
      renderCardBridgeProbe(resp.data || {});
    } catch (err) {
      renderCardBridgeProbe({
        ok: false,
        reason: (err && err.message) || String(err),
      });
    } finally {
      if (btn) {
        btn.removeAttribute("disabled");
        btn.textContent = "Probe now";
      }
    }
  }

  function renderCardBridgeProbe(data) {
    var resultRoot = $("cb-probe-result");
    if (resultRoot) resultRoot.hidden = false;

    var posture = data && data.auth_posture ? data.auth_posture : (data && data.ok ? "ok" : "unreachable");
    cbSetBadge("cb-probe-posture", posture);

    setText(
      "cb-probe-ping-latency",
      data && typeof data.ping_latency_ms === "number"
        ? cbFormatLatencyMs(data.ping_latency_ms)
        : "–"
    );
    setText(
      "cb-probe-status-latency",
      data && typeof data.status_latency_ms === "number"
        ? cbFormatLatencyMs(data.status_latency_ms)
        : "–"
    );
    setText("cb-probe-reader", (data && data.reader) || "–");
    setText("cb-probe-atr", (data && data.atr_hex) || "–");

    var auditEl = $("cb-probe-audit");
    if (auditEl) {
      if (data && data.audit_enabled === true) {
        auditEl.textContent = "enabled";
      } else if (data && data.audit_enabled === false) {
        auditEl.textContent = "disabled";
      } else {
        auditEl.textContent = "–";
      }
    }

    setText("cb-probe-token-fp", (data && data.token_fingerprint) || "–");
    var bridgeFp = (data && data.bridge_token_fingerprint) || "";
    var bridgeFpEl = $("cb-probe-bridge-fp");
    if (bridgeFpEl) {
      bridgeFpEl.textContent = bridgeFp || "–";
      bridgeFpEl.classList.remove("cb-probe-bridge-fp--match", "cb-probe-bridge-fp--mismatch");
      // When we know both fingerprints, hint mismatch via colour.
      if (data && data.token_fingerprint && bridgeFp) {
        bridgeFpEl.classList.add(
          data.fingerprint_match
            ? "cb-probe-bridge-fp--match"
            : "cb-probe-bridge-fp--mismatch"
        );
      }
    }
    setText("cb-probe-bind-host", (data && data.bind_host) || "–");

    var reasonEl = $("cb-probe-reason");
    if (reasonEl) {
      if (data && data.ok === false && data.reason) {
        reasonEl.textContent = data.reason;
        reasonEl.hidden = false;
      } else {
        reasonEl.textContent = "";
        reasonEl.hidden = true;
      }
    }

    setText("cb-status-last-probe", new Date().toLocaleTimeString());
    cbPushHistorySample(data);
  }

  function cbPushHistorySample(data) {
    var sample = {
      timestamp: Date.now(),
      ok: !!(data && data.ok),
      pingMs:
        data && typeof data.ping_latency_ms === "number"
          ? data.ping_latency_ms
          : null,
      statusMs:
        data && typeof data.status_latency_ms === "number"
          ? data.status_latency_ms
          : null,
    };
    cbState.history.push(sample);
    if (cbState.history.length > CB_HISTORY_MAX) {
      cbState.history.splice(0, cbState.history.length - CB_HISTORY_MAX);
    }
    cbRenderHistoryChart();
  }

  function cbRenderHistoryChart() {
    var svg = $("cb-history-chart");
    var meta = $("cb-history-meta");
    if (!svg) return;

    var samples = cbState.history;
    if (samples.length === 0) {
      svg.innerHTML = "";
      if (meta) meta.textContent = "no probes yet";
      return;
    }

    var widthVB = 600;
    var heightVB = 120;
    var paddingTop = 8;
    var paddingBottom = 16;
    var plotHeight = heightVB - paddingTop - paddingBottom;

    // Compute upper bound for the y-axis. Cap at >=20 ms so a healthy
    // bridge with 1-2 ms latency still gets a non-degenerate plot.
    var maxLatency = 20;
    samples.forEach(function (s) {
      if (s.pingMs != null && s.pingMs > maxLatency) maxLatency = s.pingMs;
      if (s.statusMs != null && s.statusMs > maxLatency) maxLatency = s.statusMs;
    });
    // Round up to a friendlier scale.
    var ceilCandidates = [50, 100, 250, 500, 1000, 2500, 5000, 10000];
    for (var i = 0; i < ceilCandidates.length; i += 1) {
      if (maxLatency <= ceilCandidates[i]) {
        maxLatency = ceilCandidates[i];
        break;
      }
    }

    var stepX = samples.length > 1 ? widthVB / (samples.length - 1) : widthVB;

    function pointFor(value, idx) {
      var x = idx * stepX;
      var clamped = Math.max(0, Math.min(value, maxLatency));
      var y = heightVB - paddingBottom - (clamped / maxLatency) * plotHeight;
      return x.toFixed(2) + "," + y.toFixed(2);
    }

    var pingPoints = [];
    var statusPoints = [];
    var failDots = [];
    samples.forEach(function (sample, idx) {
      if (sample.pingMs != null) pingPoints.push(pointFor(sample.pingMs, idx));
      if (sample.statusMs != null) statusPoints.push(pointFor(sample.statusMs, idx));
      if (!sample.ok) {
        var x = idx * stepX;
        failDots.push(
          '<circle class="cb-history-point-fail" cx="' +
            x.toFixed(2) +
            '" cy="' +
            (heightVB - 4).toFixed(2) +
            '" r="2.5"></circle>'
        );
      }
    });

    var pieces = [];
    // Faint horizontal axis at zero for visual reference.
    var zeroY = heightVB - paddingBottom;
    pieces.push(
      '<line class="cb-history-axis" x1="0" y1="' +
        zeroY +
        '" x2="' +
        widthVB +
        '" y2="' +
        zeroY +
        '"></line>'
    );
    pieces.push(
      '<text class="cb-history-label" x="4" y="12">' +
        maxLatency.toFixed(0) +
        " ms</text>"
    );
    pieces.push(
      '<text class="cb-history-label" x="4" y="' +
        (zeroY - 2).toFixed(2) +
        '">0</text>'
    );
    if (pingPoints.length > 1) {
      pieces.push(
        '<polyline class="cb-history-line-ping" points="' +
          pingPoints.join(" ") +
          '"></polyline>'
      );
    }
    if (statusPoints.length > 1) {
      pieces.push(
        '<polyline class="cb-history-line-status" points="' +
          statusPoints.join(" ") +
          '"></polyline>'
      );
    }
    pieces.push(failDots.join(""));

    svg.innerHTML = pieces.join("");

    if (meta) {
      var lastSample = samples[samples.length - 1];
      var lastPing = lastSample.pingMs != null ? cbFormatLatencyMs(lastSample.pingMs) : "—";
      var lastStatus = lastSample.statusMs != null ? cbFormatLatencyMs(lastSample.statusMs) : "—";
      meta.textContent =
        samples.length +
        " sample(s) • last ping " +
        lastPing +
        " • last status " +
        lastStatus;
    }
  }

  function cbClearHistory() {
    cbState.history = [];
    cbRenderHistoryChart();
  }

  function cbStartAutoRefresh() {
    cbStopAutoRefresh();
    cbState.autoRefreshTimer = window.setInterval(function () {
      // Only refresh while the panel is the active view — otherwise
      // we'd hammer the server when the operator is elsewhere.
      var view = document.querySelector('section[data-view="card_bridge"]');
      if (!view || !view.classList.contains("view-active")) return;
      loadCardBridgeStatus();
    }, cbState.autoRefreshIntervalMs);
  }

  function cbStopAutoRefresh() {
    if (cbState.autoRefreshTimer != null) {
      window.clearInterval(cbState.autoRefreshTimer);
      cbState.autoRefreshTimer = null;
    }
  }

  function cbCopyText(text) {
    if (!text) return Promise.resolve(false);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard
        .writeText(text)
        .then(function () { return true; })
        .catch(function () { return false; });
    }
    // Fallback for older browsers / restrictive contexts: textarea + execCommand.
    return new Promise(function (resolve) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "absolute";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        resolve(ok);
      } catch (e) {
        resolve(false);
      }
    });
  }

  var CB_RIG_STORAGE_KEY = "yggdrasim.card_bridge.remote_rig";
  var CB_RIG_PROFILES_STORAGE_KEY = "yggdrasim.card_bridge.remote_rig.profiles";
  var CB_RIG_FIELD_IDS = [
    "cb-rig-ssh-target",
    "cb-rig-identity-file",
    "cb-rig-reader-index",
    "cb-rig-reader-name",
    "cb-rig-card-port",
    "cb-rig-gui-port",
    "cb-rig-service-name",
    "cb-rig-remote-workdir",
    "cb-rig-remote-python",
    "cb-rig-remote-token",
    "cb-rig-remsim-binary",
    "cb-rig-usb-vidpid",
    "cb-rig-hil-port",
  ];
  var cbRigApplyingProfile = false;

  function cbRigReadField(id) {
    var el = $(id);
    return el ? String(el.value || "").trim() : "";
  }

  function cbRigWriteField(id, value) {
    var el = $(id);
    if (!el || value == null) return;
    el.value = String(value);
  }

  function cbRigReadSettingsPayload() {
    var payload = {};
    CB_RIG_FIELD_IDS.forEach(function (id) { payload[id] = cbRigReadField(id); });
    return payload;
  }

  function cbRigLoadProfiles() {
    var profiles = {};
    try {
      profiles = JSON.parse(window.localStorage.getItem(CB_RIG_PROFILES_STORAGE_KEY) || "{}") || {};
    } catch (_err) {
      profiles = {};
    }
    return profiles && typeof profiles === "object" && !Array.isArray(profiles) ? profiles : {};
  }

  function cbRigLoadStoredSettingsPayload(profiles) {
    var stored = {};
    var knownProfiles = profiles || cbRigLoadProfiles();
    try {
      stored = JSON.parse(window.localStorage.getItem(CB_RIG_STORAGE_KEY) || "{}") || {};
    } catch (_err) {
      stored = {};
    }
    if (!stored || typeof stored !== "object" || Array.isArray(stored)) stored = {};
    var storedTarget = String(stored["cb-rig-ssh-target"] || "").trim();
    if (storedTarget && knownProfiles[storedTarget]) {
      stored = Object.assign({}, knownProfiles[storedTarget], stored);
    }
    return stored;
  }

  function cbRigWriteProfiles(profiles) {
    try {
      window.localStorage.setItem(CB_RIG_PROFILES_STORAGE_KEY, JSON.stringify(profiles || {}));
    } catch (_err) {}
  }

  function cbRigRenderProfileOptions(profiles) {
    var list = $("cb-rig-ssh-target-options");
    if (!list) return;
    list.textContent = "";
    Object.keys(profiles || {}).sort().forEach(function (target) {
      if (!target) return;
      var option = document.createElement("option");
      option.value = target;
      list.appendChild(option);
    });
  }

  function cbRigSaveProfile(payload) {
    var target = String((payload && payload["cb-rig-ssh-target"]) || "").trim();
    if (!target) return;
    var profiles = cbRigLoadProfiles();
    profiles[target] = Object.assign({}, profiles[target] || {}, payload);
    cbRigWriteProfiles(profiles);
    cbRigRenderProfileOptions(profiles);
  }

  function cbRigApplyProfileForTarget(target) {
    var normalized = String(target || "").trim();
    if (!normalized) return false;
    var profiles = cbRigLoadProfiles();
    var profile = profiles[normalized];
    if (!profile || typeof profile !== "object") return false;
    cbRigApplyingProfile = true;
    CB_RIG_FIELD_IDS.forEach(function (id) {
      if (Object.prototype.hasOwnProperty.call(profile, id)) {
        cbRigWriteField(id, profile[id]);
      }
    });
    cbRigApplyingProfile = false;
    cbRigUpdateGuiUrl();
    return true;
  }

  function cbRigLoadSettings() {
    var profiles = cbRigLoadProfiles();
    cbRigRenderProfileOptions(profiles);
    var stored = cbRigLoadStoredSettingsPayload(profiles);
    Object.keys(stored).forEach(function (id) {
      cbRigWriteField(id, stored[id]);
    });
    cbRigUpdateGuiUrl();
  }

  function cbRigSaveSettings(options) {
    var payload = cbRigReadSettingsPayload();
    try {
      window.localStorage.setItem(CB_RIG_STORAGE_KEY, JSON.stringify(payload));
    } catch (_err) {}
    if (!options || options.updateProfile !== false) {
      cbRigSaveProfile(payload);
    }
  }

  function cbRigNumber(id, fallback) {
    var parsed = parseInt(cbRigReadField(id), 10);
    if (!isFinite(parsed) || parsed <= 0) return fallback;
    return parsed;
  }

  function cbRigPayloadValue(payload, id) {
    return String((payload && payload[id]) || "").trim();
  }

  function cbRigPayloadNumber(payload, id, fallback) {
    var parsed = parseInt(cbRigPayloadValue(payload, id), 10);
    if (!isFinite(parsed) || parsed <= 0) return fallback;
    return parsed;
  }

  function cbRigInputsFromPayload(payload) {
    var cardPort = cbRigPayloadNumber(payload, "cb-rig-card-port", 8642);
    var guiPort = cbRigPayloadNumber(payload, "cb-rig-gui-port", 27854);
    return {
      ssh_target: cbRigPayloadValue(payload, "cb-rig-ssh-target"),
      identity_file: cbRigPayloadValue(payload, "cb-rig-identity-file"),
      reader_index: cbRigPayloadNumber(payload, "cb-rig-reader-index", 0),
      reader_name: cbRigPayloadValue(payload, "cb-rig-reader-name"),
      local_card_port: cardPort,
      remote_card_port: cardPort,
      local_gui_port: guiPort,
      remote_gui_port: guiPort,
      service_name: cbRigPayloadValue(payload, "cb-rig-service-name") || "yggdrasim-hil-supervisor.service",
      remote_card_url: "http://127.0.0.1:" + cardPort + "/apdu",
      remote_token_file: cbRigPayloadValue(payload, "cb-rig-remote-token") || "~/.config/yggdrasim/card_bridge/" + cardPort + ".token",
      remote_workdir: cbRigPayloadValue(payload, "cb-rig-remote-workdir") || "~/YggdraSIM",
      remote_python: cbRigPayloadValue(payload, "cb-rig-remote-python") || "~/YggdraSIM/python/bin/python",
      remsim_binary: cbRigPayloadValue(payload, "cb-rig-remsim-binary") || "osmo-remsim-client-st2",
      usb_vidpid: cbRigPayloadValue(payload, "cb-rig-usb-vidpid") || "1d50:60e3",
      hil_port: cbRigPayloadNumber(payload, "cb-rig-hil-port", 9997),
      apdu_timeout_ms: 30000,
    };
  }

  function cbRigCommonInputs() {
    return cbRigInputsFromPayload(cbRigReadSettingsPayload());
  }

  function cbRigHasRenderedFields() {
    return CB_RIG_FIELD_IDS.some(function (id) { return !!$(id); });
  }

  function cbRigInputsFromSavedSettings() {
    if (cbRigHasRenderedFields()) {
      cbRigSaveSettings();
      return cbRigCommonInputs();
    }
    return cbRigInputsFromPayload(cbRigLoadStoredSettingsPayload());
  }

  function cbRigRemoteRigStartInputs(cfg) {
    return {
      ssh_target: cfg.ssh_target,
      identity_file: cfg.identity_file,
      reader_index: cfg.reader_index,
      reader_name: cfg.reader_name,
      local_card_port: cfg.local_card_port,
      remote_card_port: cfg.remote_card_port,
      local_gui_port: cfg.local_gui_port,
      remote_gui_port: cfg.remote_gui_port,
      service_name: cfg.service_name,
      remote_workdir: cfg.remote_workdir,
      remote_python: cfg.remote_python,
      remote_card_url: cfg.remote_card_url,
      remote_token_file: cfg.remote_token_file,
      remsim_binary: cfg.remsim_binary,
      usb_vidpid: cfg.usb_vidpid,
      hil_port: cfg.hil_port,
      apdu_timeout_ms: cfg.apdu_timeout_ms,
      forward_gui: true,
      restart_processes: true,
      install_service: true,
      confirm: true,
    };
  }

  function cbRigSetBusy(button, busyText) {
    if (!button) return function () {};
    var previous = button.textContent;
    button.disabled = true;
    button.textContent = busyText || "working…";
    return function () {
      button.disabled = false;
      button.textContent = previous;
    };
  }

  function cbRigSetNote(message, isError, options) {
    var note = $("cb-rig-note");
    if (!note) return;
    note.textContent = message || "";
    note.classList.toggle("cb-rig-note-error", !!isError);
    var flashOk = !!(options && options.flashOk && !isError);
    note.classList.toggle("cb-rig-note-ok", flashOk);
    note.classList.remove("cb-rig-note-ok-flash");
    if (flashOk) {
      void note.offsetWidth;
      note.classList.add("cb-rig-note-ok-flash");
    }
  }

  function cbRigRequireSshTarget() {
    if (cbRigReadField("cb-rig-ssh-target")) return true;
    cbRigSetNote("SSH target is required for RPi actions.", true);
    var field = $("cb-rig-ssh-target");
    if (field && typeof field.focus === "function") field.focus();
    return false;
  }

  function cbRigDescribeAction(data, fallback) {
    if (!data) return fallback || "";
    var message = data.note || fallback || "action completed";
    var steps = Array.isArray(data.steps) ? data.steps : [];
    if (!steps.length) return message;
    var failed = steps.slice().reverse().find(function (step) { return step && step.ok === false; });
    var step = failed || steps[steps.length - 1] || {};
    var pieces = [message];
    if (step.name) pieces.push("step: " + step.name);
    if (step.note) pieces.push(step.note);
    if (step.log_tail) pieces.push(step.log_tail);
    return pieces.filter(Boolean).join(" | ");
  }

  function cbRigUpdateGuiUrl() {
    var port = cbRigNumber("cb-rig-gui-port", 27854);
    setText("cb-rig-gui-url", "http://127.0.0.1:" + port);
  }

  function cbRigRenderStatus(data, options) {
    var state = data && data.state ? data.state : {};
    setText("cb-rig-local-status", state.local_card_bridge_running ? "running" : "stopped");
    setText("cb-rig-tunnel-status", state.ssh_tunnel_running ? "running" : "stopped");
    var remote = state.remote_service || {};
    var remoteStatus = remote.ActiveState || (state.remote_error ? "error" : "–");
    if (remote.SubState) remoteStatus += " · " + remote.SubState;
    setText("cb-rig-service-status", remoteStatus);
    var hil = state.remote_hil || {};
    var bridgeStatus = Object.prototype.hasOwnProperty.call(hil, "bridge_running")
      ? (hil.bridge_running ? "running" : "stopped")
      : "–";
    var usbStatus = Object.prototype.hasOwnProperty.call(hil, "usb_present")
      ? (hil.usb_present ? "present" : "missing")
      : "–";
    var remsimStatus = Object.prototype.hasOwnProperty.call(hil, "remsim_client_running")
      ? (hil.remsim_client_running ? "running" : (hil.remsim_binary_missing ? "missing" : (hil.remsim_client_enabled === false ? "disabled" : "stopped")))
      : "–";
    var linkStatus = "–";
    if (Object.prototype.hasOwnProperty.call(hil, "modem_path_ready")) {
      if (hil.modem_path_ready) {
        linkStatus = "connected";
      } else if (hil.control_connected === false) {
        linkStatus = "control waiting";
      } else if (hil.bankd_connected === false) {
        linkStatus = "bankd waiting";
      } else {
        linkStatus = "waiting";
      }
    }
    setText("cb-rig-bridge-status", bridgeStatus);
    setText("cb-rig-usb-status", usbStatus);
    setText("cb-rig-remsim-status", remsimStatus);
    setText("cb-rig-modem-link-status", linkStatus);
    if (state.local_gui_url) setText("cb-rig-gui-url", state.local_gui_url);
    if (state.local_card_bridge_running) {
      cbSetGlobalBridgeStatus("running", "running");
    } else if (Object.prototype.hasOwnProperty.call(state, "local_card_bridge_running")) {
      var global = cbBridgeStatusFromPayload(cbState.lastStatus);
      if (global.state === "running") global = { state: "idle", label: "idle" };
      cbSetGlobalBridgeStatus(global.state, global.label);
    }
    cbRigSetNote(
      cbRigDescribeAction(data, "Remote rig status refreshed."),
      !!(state.remote_error || (hil && hil.ok === false) || (data && data.ok === false)),
      options && options.flashOk ? { flashOk: true } : null
    );
  }

  async function cbRigRun(actionId, inputs, button, busyText, options) {
    if (!options || options.saveSettings !== false) {
      cbRigSaveSettings();
    }
    var clearBusy = cbRigSetBusy(button, busyText);
    try {
      var resp = await apiFetch("/api/actions/" + encodeURIComponent(actionId) + "/run", {
        method: "POST",
        body: JSON.stringify({ inputs: inputs || {} }),
      });
      var data = resp && resp.data ? resp.data : {};
      if (!resp || !resp.ok || data.ok === false) {
        cbRigSetNote((resp && resp.error) || cbRigDescribeAction(data, "action failed") || data.stderr, true);
        return data;
      }
      cbRigSetNote(
        cbRigDescribeAction(data, "action completed"),
        false,
        options && options.flashOk ? { flashOk: true } : null
      );
      return data;
    } catch (err) {
      cbRigSetNote(String((err && err.message) || err), true);
      return null;
    } finally {
      clearBusy();
    }
  }

  async function cbRigRefreshStatus(button) {
    var cfg = cbRigCommonInputs();
    var data = await cbRigRun("card_bridge.remote_rig_status", {
      ssh_target: cfg.ssh_target,
      identity_file: cfg.identity_file,
      service_name: cfg.service_name,
      local_gui_port: cfg.local_gui_port,
      remote_workdir: cfg.remote_workdir,
      remote_python: cfg.remote_python,
    }, button, "checking…");
    if (data) cbRigRenderStatus(data);
  }

  async function cbRigStartLocal(button) {
    var cfg = cbRigCommonInputs();
    var data = await cbRigRun("card_bridge.local_start", {
      port: cfg.local_card_port,
      reader_index: cbRigNumber("cb-rig-reader-index", 0),
      reader_name: cbRigReadField("cb-rig-reader-name"),
      apdu_timeout_ms: cfg.apdu_timeout_ms,
      restart: false,
      confirm: true,
    }, button, "starting…", { flashOk: true });
    if (data) {
      loadCardBridgeStatus();
      cbRigRefreshStatus(null);
    }
  }

  async function cbRigStopLocal(button) {
    var data = await cbRigRun("card_bridge.local_stop", { confirm: true }, button, "stopping…");
    if (data) cbRigRefreshStatus(null);
  }

  async function cbRigStartTunnel(button) {
    if (!cbRigRequireSshTarget()) return;
    var cfg = cbRigCommonInputs();
    var data = await cbRigRun("card_bridge.remote_rig_tunnel_start", {
      ssh_target: cfg.ssh_target,
      identity_file: cfg.identity_file,
      local_card_port: cfg.local_card_port,
      remote_card_port: cfg.remote_card_port,
      local_gui_port: cfg.local_gui_port,
      remote_gui_port: cfg.remote_gui_port,
      forward_gui: true,
      restart: false,
      confirm: true,
    }, button, "opening…", { flashOk: true });
    if (data) cbRigRefreshStatus(null);
  }

  async function cbRigStartAll(button) {
    if (!cbRigRequireSshTarget()) return;
    var cfg = cbRigCommonInputs();
    var data = await cbRigRun(
      "card_bridge.remote_rig_start",
      cbRigRemoteRigStartInputs(cfg),
      button,
      "starting rig…",
      { flashOk: true }
    );
    if (data) {
      loadCardBridgeStatus();
      cbRigRenderStatus(data, { flashOk: data.ok !== false });
    }
  }

  async function cbRigStartAllFromSavedSettings() {
    var cfg = cbRigInputsFromSavedSettings();
    if (!cfg.ssh_target) {
      var missing = "Remote Bridge SSH target is required. Configure it once in Remote Bridge.";
      cbRigSetNote(missing, true);
      return { ok: false, note: missing };
    }
    var data = await cbRigRun(
      "card_bridge.remote_rig_start",
      cbRigRemoteRigStartInputs(cfg),
      null,
      "starting rig…",
      { flashOk: true, saveSettings: false }
    );
    if (data) {
      loadCardBridgeStatus();
      cbRigRenderStatus(data, { flashOk: data.ok !== false });
    }
    return data;
  }

  async function cbRigStopAll(button) {
    var cfg = cbRigCommonInputs();
    var data = await cbRigRun("card_bridge.remote_rig_stop", {
      ssh_target: cfg.ssh_target,
      identity_file: cfg.identity_file,
      service_name: cfg.service_name,
      local_gui_port: cfg.local_gui_port,
      remote_workdir: cfg.remote_workdir,
      remote_python: cfg.remote_python,
      confirm: true,
    }, button, "stopping rig…");
    if (data) {
      loadCardBridgeStatus();
      cbRigRenderStatus(data, { flashOk: data.ok !== false });
    }
  }

  async function cbRigStopAllFromSavedSettings() {
    var cfg = cbRigInputsFromSavedSettings();
    if (!cfg.ssh_target) {
      var missing = "Remote Bridge SSH target is required. Configure it once in Remote Bridge.";
      cbRigSetNote(missing, true);
      return { ok: false, note: missing };
    }
    var data = await cbRigRun("card_bridge.remote_rig_stop", {
      ssh_target: cfg.ssh_target,
      identity_file: cfg.identity_file,
      service_name: cfg.service_name,
      local_gui_port: cfg.local_gui_port,
      remote_workdir: cfg.remote_workdir,
      remote_python: cfg.remote_python,
      confirm: true,
    }, null, "stopping rig…", { saveSettings: false });
    if (data) {
      loadCardBridgeStatus();
      cbRigRenderStatus(data, { flashOk: data.ok !== false });
    }
    return data;
  }

  async function cbRigStopTunnel(button) {
    var data = await cbRigRun("card_bridge.remote_rig_tunnel_stop", { confirm: true }, button, "stopping…");
    if (data) cbRigRefreshStatus(null);
  }

  async function cbRigSyncToken(button) {
    if (!cbRigRequireSshTarget()) return;
    var cfg = cbRigCommonInputs();
    await cbRigRun("card_bridge.remote_rig_sync_token", {
      ssh_target: cfg.ssh_target,
      identity_file: cfg.identity_file,
      remote_token_file: cfg.remote_token_file,
      confirm: true,
    }, button, "syncing…");
  }

  async function cbRigInstallService(button) {
    if (!cbRigRequireSshTarget()) return;
    var cfg = cbRigCommonInputs();
    var data = await cbRigRun("card_bridge.remote_rig_install_service", {
      ssh_target: cfg.ssh_target,
      identity_file: cfg.identity_file,
      service_name: cfg.service_name,
      remote_workdir: cfg.remote_workdir,
      remote_python: cfg.remote_python,
      remote_card_url: cfg.remote_card_url,
      remote_token_file: cfg.remote_token_file,
      remsim_binary: cfg.remsim_binary,
      usb_vidpid: cfg.usb_vidpid,
      hil_port: cfg.hil_port,
      apdu_timeout_ms: cfg.apdu_timeout_ms,
      start_now: true,
      confirm: true,
    }, button, "installing…");
    if (data) cbRigRefreshStatus(null);
  }

  async function cbRigServiceAction(action, button) {
    if (!cbRigRequireSshTarget()) return;
    var cfg = cbRigCommonInputs();
    var data = await cbRigRun("card_bridge.remote_rig_service", {
      ssh_target: cfg.ssh_target,
      identity_file: cfg.identity_file,
      service_name: cfg.service_name,
      action: action,
      confirm: action !== "status",
    }, button, action + "…");
    if (data) cbRigRefreshStatus(null);
  }

  function cbRigOpenGui() {
    cbRigSaveSettings();
    var port = cbRigNumber("cb-rig-gui-port", 27854);
    window.open("http://127.0.0.1:" + port, "_blank", "noopener");
  }

  function loadCardBridge() {
    cbRigLoadSettings();
    loadCardBridgeStatus();
    cbRigRefreshStatus(null);
    if ($("cb-auto-refresh") && $("cb-auto-refresh").checked) {
      cbStartAutoRefresh();
    }
  }

  function wireCardBridgePanel() {
    var refreshBtn = $("cb-refresh-status");
    if (refreshBtn) refreshBtn.addEventListener("click", loadCardBridgeStatus);

    var probeBtn = $("cb-run-probe");
    if (probeBtn) probeBtn.addEventListener("click", runCardBridgeProbe);

    var clearBtn = $("cb-clear-history");
    if (clearBtn) clearBtn.addEventListener("click", cbClearHistory);

    var copyBtn = $("cb-copy-url");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        var url = (cbState.lastStatus && cbState.lastStatus.url) || "";
        if (!url) return;
        cbCopyText(url).then(function (ok) {
          var prev = copyBtn.textContent;
          copyBtn.textContent = ok ? "Copied" : "Failed";
          window.setTimeout(function () {
            copyBtn.textContent = prev || "Copy";
          }, 1200);
        });
      });
    }

    var autoToggle = $("cb-auto-refresh");
    if (autoToggle) {
      autoToggle.addEventListener("change", function () {
        if (autoToggle.checked) {
          cbStartAutoRefresh();
        } else {
          cbStopAutoRefresh();
        }
      });
    }

    CB_RIG_FIELD_IDS.forEach(function (id) {
      var el = $(id);
      if (!el) return;
      el.addEventListener("change", function () {
        if (id === "cb-rig-ssh-target") {
          cbRigApplyProfileForTarget(cbRigReadField(id));
        }
        cbRigSaveSettings();
        cbRigUpdateGuiUrl();
      });
      el.addEventListener("input", function () {
        if (id === "cb-rig-ssh-target") {
          var applied = cbRigApplyProfileForTarget(cbRigReadField(id));
          cbRigSaveSettings({ updateProfile: applied });
        } else if (!cbRigApplyingProfile) {
          cbRigSaveSettings();
        }
        cbRigUpdateGuiUrl();
      });
    });

    var rigRefresh = $("cb-rig-refresh");
    if (rigRefresh) rigRefresh.addEventListener("click", function () { cbRigRefreshStatus(rigRefresh); });
    var rigOpen = $("cb-rig-open-gui");
    if (rigOpen) rigOpen.addEventListener("click", cbRigOpenGui);
    var startAll = $("cb-rig-start-all");
    if (startAll) startAll.addEventListener("click", function () { cbRigStartAll(startAll); });
    var stopAll = $("cb-rig-stop-all");
    if (stopAll) stopAll.addEventListener("click", function () { cbRigStopAll(stopAll); });
    var startLocal = $("cb-rig-start-local");
    if (startLocal) startLocal.addEventListener("click", function () { cbRigStartLocal(startLocal); });
    var stopLocal = $("cb-rig-stop-local");
    if (stopLocal) stopLocal.addEventListener("click", function () { cbRigStopLocal(stopLocal); });
    var startTunnel = $("cb-rig-start-tunnel");
    if (startTunnel) startTunnel.addEventListener("click", function () { cbRigStartTunnel(startTunnel); });
    var stopTunnel = $("cb-rig-stop-tunnel");
    if (stopTunnel) stopTunnel.addEventListener("click", function () { cbRigStopTunnel(stopTunnel); });
    var syncToken = $("cb-rig-sync-token");
    if (syncToken) syncToken.addEventListener("click", function () { cbRigSyncToken(syncToken); });
    var installService = $("cb-rig-install-service");
    if (installService) installService.addEventListener("click", function () { cbRigInstallService(installService); });
    var startService = $("cb-rig-start-service");
    if (startService) startService.addEventListener("click", function () { cbRigServiceAction("restart", startService); });
    var stopService = $("cb-rig-stop-service");
    if (stopService) stopService.addEventListener("click", function () { cbRigServiceAction("stop", stopService); });
  }

  // Reusable streaming-log row appender. Used by both the Command Center
  // log_stream renderer and any future WS-backed panels.
  //
  // A single streaming action (e.g. a deep SCP03 scan, a long verify
  // run) can emit thousands of frames before completion. Without the
  // FIFO trim below we observed multi-hour GUI sessions accumulating
  // hundreds of MB of detached <div> nodes inside flow-log containers,
  // which is the dominant source of "GUI keeps eating RAM" reports.
  // Trimming on append keeps the per-flow log bounded; the bottom-dock
  // event bus (logBus) maintains its own independent trim + DOM cap.
  var FLOW_LOG_MAX_ROWS = 1500;
  var FLOW_LOG_MAX_MSG_CHARS = 4096;

  function _truncateFlowMessage(text) {
    var s = String(text == null ? "" : text);
    if (s.length <= FLOW_LOG_MAX_MSG_CHARS) return s;
    var keep = FLOW_LOG_MAX_MSG_CHARS - 32;
    return s.slice(0, keep) + "… [+" + (s.length - keep) + " chars truncated]";
  }

  function appendLogRow(logEl, level, message) {
    if (!logEl) return;
    var row = document.createElement("div");
    row.className = "flow-row flow-row--" + String(level || "info");
    var ts = document.createElement("span");
    ts.className = "flow-ts";
    ts.textContent = new Date().toISOString().substring(11, 19);
    var lvl = document.createElement("span");
    lvl.className = "flow-level";
    lvl.textContent = String(level || "info").toUpperCase();
    var body = document.createElement("span");
    body.className = "flow-body";
    body.textContent = _truncateFlowMessage(message);
    row.appendChild(ts);
    row.appendChild(lvl);
    row.appendChild(body);
    logEl.appendChild(row);
    while (logEl.childElementCount > FLOW_LOG_MAX_ROWS) {
      logEl.removeChild(logEl.firstChild);
    }
    logEl.scrollTop = logEl.scrollHeight;
  }

  function scheduleHealthPoll() {
    setInterval(loadHealth, 10000);
  }
