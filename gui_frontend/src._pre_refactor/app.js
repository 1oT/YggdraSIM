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

  // -- Token management ----------------------------------------------------
  //
  // Desktop mode: pywebview navigates to "/?t=<token>". We lift that
  // token into sessionStorage and strip the query string so subsequent
  // loads don't carry it in the URL bar.
  // Web-server mode: no token-in-URL; operator logs in out-of-band.
  // sessionStorage is the single source of truth for `fetch` headers.

  var TOKEN_KEY = "ygg-gui-token";
  var THEME_KEY = "ygg-gui-theme";
  var VALID_THEMES = {
    "nord-dark": 1,
    "nord-light": 1,
    "oneot-dark": 1,
    "oneot-light": 1,
    "matrix": 1,
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
      throw new Error("HTTP " + response.status + " for " + path);
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
    setText("crumb-subsystem", {
      overview: "Overview",
      registry: "Registry browser",
      backend: "Card backend",
      env_flags: "Environment flags",
      about: "About",
      terminal: "Advanced · Shell",
      host_shell: "Advanced · Host shell",
      live_readers: "Inspect · PC/SC readers",
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
      setText("overview-version", data.version);
      setText("overview-flavor", data.flavor);
      setText("overview-mode", data.mode);
      setText("overview-uptime", formatUptime(data.uptime_seconds));
      setText("overview-pid", data.pid);
      setText("badge-mode", "mode: " + data.mode);
      setText("badge-flavor", "flavor: " + data.flavor);
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
      setText("badge-backend", "backend: " + data.backend);
    } catch (err) {
      // keep prior state; overview header already reports API state
    }
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

  async function loadEnvFlags() {
    var root = $("env-flag-categories");
    if (!root) return;
    root.innerHTML = "<p class=\"loading\">loading…</p>";
    try {
      var data = await apiFetch("/api/env_flags/list");
      var categories = data.categories || [];
      var flags = data.flags || [];
      root.innerHTML = "";
      categories.forEach(function (cat) {
        var catFlags = flags.filter(function (f) { return f.category === cat; });
        if (catFlags.length === 0) return;
        var section = document.createElement("section");
        section.className = "env-flag-category";
        var h2 = document.createElement("h2");
        h2.textContent = cat;
        section.appendChild(h2);
        catFlags.forEach(function (flag) {
          section.appendChild(renderEnvFlag(flag));
        });
        root.appendChild(section);
      });
      if (root.children.length === 0) {
        root.innerHTML = "<p class=\"loading\">no flags registered</p>";
      }
    } catch (err) {
      root.innerHTML = "<p class=\"loading\">failed: " + escapeHtml(err.message) + "</p>";
    }
  }

  function renderEnvFlag(flag) {
    var row = document.createElement("div");
    row.className = "env-flag";

    var meta = document.createElement("div");
    var nameEl = document.createElement("div");
    nameEl.className = "env-flag-name";
    nameEl.textContent = flag.name;
    var kind = document.createElement("span");
    kind.className = "kind";
    kind.textContent = flag.kind;
    nameEl.appendChild(kind);
    if (flag.sensitive) {
      var sens = document.createElement("span");
      sens.className = "sensitive";
      sens.textContent = "sensitive";
      nameEl.appendChild(sens);
    }
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

    row.appendChild(meta);
    row.appendChild(value);
    return row;
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
        } else if (view === "host_shell") {
          loadHostShellCapabilities();
          loadHostShellDevices();
        } else if (view === "live_readers") {
          loadLiveReaders();
        }
      });
    });

    var refreshBtn = $("overview-refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        setStatusAction("refreshing…");
        loadHealth();
        loadBackend();
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

  // -- Terminal (B-2) ------------------------------------------------------

  var terminalState = {
    term: null,
    fitAddon: null,
    socket: null,
    module: null,
  };

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
    window.addEventListener("resize", function () {
      if (terminalState.fitAddon) {
        try { terminalState.fitAddon.fit(); } catch (_err) { /* xterm not ready */ }
        sendTerminalResize();
      }
    });
  }

  function ensureTerminal() {
    if (terminalState.term) return terminalState.term;
    if (typeof window.Terminal !== "function") {
      setText("terminal-status", "xterm.js failed to load.");
      return null;
    }
    var host = $("terminal-host");
    if (!host) return null;
    var term = new window.Terminal({
      convertEol: true,
      cursorBlink: true,
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      theme: { background: "transparent" },
      // Pin the scrollback explicitly. Default is 1000 lines but the
      // PTY bridge (yggdrasim_main shell) generates a lot of output
      // for deep scans, and an unbounded buffer + tab kept open for
      // hours blew up renderer memory. 1500 is a tested sweet spot
      // that still covers the longest scan dump.
      scrollback: 1500,
    });
    var FitAddonCtor = window.FitAddon && window.FitAddon.FitAddon;
    var fitAddon = FitAddonCtor ? new FitAddonCtor() : null;
    if (fitAddon) term.loadAddon(fitAddon);
    term.open(host);
    if (fitAddon) {
      try { fitAddon.fit(); } catch (_err) { /* element not measured yet */ }
    }
    terminalState.term = term;
    terminalState.fitAddon = fitAddon;
    term.onData(function (data) {
      if (terminalState.socket && terminalState.socket.readyState === 1) {
        terminalState.socket.send(JSON.stringify({ type: "stdin", data: data }));
      }
    });
    return term;
  }

  function sendTerminalResize() {
    if (!terminalState.term || !terminalState.socket) return;
    if (terminalState.socket.readyState !== 1) return;
    terminalState.socket.send(JSON.stringify({
      type: "resize",
      rows: terminalState.term.rows,
      cols: terminalState.term.cols,
    }));
  }

  function startTerminal() {
    var sel = $("terminal-module");
    var module = sel ? sel.value : "";
    if (!module) {
      setText("terminal-status", "pick a module first.");
      return;
    }
    var term = ensureTerminal();
    if (!term) return;
    if (terminalState.socket && terminalState.socket.readyState === 1) {
      terminalState.socket.close();
    }
    term.clear();
    term.writeln("[yggdrasim-gui] launching python -m " + module + " ...");

    var token = getStoredToken();
    if (!token) {
      setText("terminal-status", "missing token — reload the GUI.");
      return;
    }

    var scheme = window.location.protocol === "https:" ? "wss" : "ws";
    var rows = term.rows || 30;
    var cols = term.cols || 120;
    var url = scheme + "://" + window.location.host + "/api/terminal/" + encodeURIComponent(module)
      + "?t=" + encodeURIComponent(token)
      + "&rows=" + rows + "&cols=" + cols;
    var sock = new WebSocket(url);
    sock.binaryType = "arraybuffer";
    terminalState.socket = sock;
    terminalState.module = module;
    var startBtn = $("terminal-start");
    var stopBtn = $("terminal-stop");
    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
    setText("terminal-status", "connecting…");

    sock.onopen = function () {
      setText("terminal-status", "running · " + module);
      sendTerminalResize();
    };
    sock.onmessage = function (event) {
      if (typeof event.data === "string") {
        try {
          var msg = JSON.parse(event.data);
          if (msg && msg.event === "spawned") {
            setText("terminal-status", "running · " + module + " · pid=" + msg.pid);
            return;
          }
          if (msg && msg.event === "exit") {
            term.writeln("\r\n[yggdrasim-gui] child exited.");
            setText("terminal-status", "exited");
            return;
          }
          if (msg && msg.event === "error") {
            term.writeln("\r\n[yggdrasim-gui] error: " + msg.message);
            setText("terminal-status", "error: " + msg.message);
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
      setText("terminal-status", "closed");
      if (startBtn) startBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      terminalState.socket = null;
      // Drop closures so the GC can collect the WebSocket + buffered
      // frames promptly. Without this, repeated start/stop cycles can
      // pin a chain of dead sockets through their handlers' closures.
      sock.onmessage = null;
      sock.onopen = null;
      sock.onerror = null;
      sock.onclose = null;
    };
    sock.onerror = function () {
      setText("terminal-status", "socket error");
    };
  }

  function stopTerminal() {
    if (terminalState.socket) {
      try { terminalState.socket.close(); } catch (_err) { /* already gone */ }
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

  // -- Command Center (R2-004 Phase C) -------------------------------------

  var commandState = {
    catalogue: null,
    activeSubsystem: null,
    scp03Session: null,
    scp03Workbench: {
      tabs: [],
      activeTabId: null,
      tabSeq: 1,
    },
  };

  function wireCommandCenter() {
    document.addEventListener("click", function (event) {
      var nav = event.target.closest("#command-center-nav .subsystem-entry");
      if (nav) {
        var subsystem = nav.getAttribute("data-cc-subsystem");
        if (subsystem) {
          openCommandSubsystem(subsystem);
        }
      }
    });
  }

  async function loadCommandCatalogue() {
    try {
      var data = await apiFetch("/api/actions");
      commandState.catalogue = data;
      renderCommandNav(data);
    } catch (err) {
      var nav = $("command-center-nav");
      if (nav) {
        nav.innerHTML = '<li class="loading">actions unavailable: '
          + escapeHtml(String(err && err.message || err)) + "</li>";
      }
    }
  }

  function renderCommandNav(catalogue) {
    var nav = $("command-center-nav");
    if (!nav) return;
    nav.innerHTML = "";
    var subsystems = catalogue && catalogue.subsystems ? catalogue.subsystems : {};
    var names = Object.keys(subsystems).sort();
    if (names.length === 0) {
      nav.innerHTML = '<li class="loading">no actions registered.</li>';
      return;
    }
    names.forEach(function (name) {
      var li = document.createElement("li");
      li.className = "subsystem-entry";
      li.setAttribute("data-cc-subsystem", name);
      var count = (subsystems[name] || []).length;
      li.innerHTML = '<span class="cc-nav-name">' + escapeHtml(name) + '</span>'
        + '<span class="cc-nav-count">' + count + '</span>';
      nav.appendChild(li);
    });
  }

  function openCommandSubsystem(subsystem) {
    commandState.activeSubsystem = subsystem;
    showView("command_center", {
      crumb: "Command Center · " + subsystem,
    });
    document.querySelectorAll("#command-center-nav .subsystem-entry").forEach(function (entry) {
      var match = entry.getAttribute("data-cc-subsystem") === subsystem;
      if (match) {
        entry.classList.add("active");
      } else {
        entry.classList.remove("active");
      }
    });
    renderCommandSubsystem(subsystem);
  }

  function renderCommandSubsystem(subsystem) {
    var cat = commandState.catalogue;
    var container = $("cc-actions");
    setText("cc-title", "Command Center · " + subsystem);
    setText("cc-subtitle", "Task-oriented actions exposed by " + subsystem + ".");
    if (!container || !cat) return;
    container.innerHTML = "";
    var actions = (cat.subsystems && cat.subsystems[subsystem]) || [];
    if (actions.length === 0) {
      container.innerHTML = '<p class="loading">no actions registered for this subsystem.</p>';
      return;
    }
    if (subsystem === "SCP03") {
      renderScp03Workbench(container, actions);
      return;
    }
    actions.forEach(function (action) {
      var card = buildActionCard(action);
      container.appendChild(card);
    });
  }

  function buildActionCard(action) {
    var card = document.createElement("article");
    card.className = "card cc-action-card";
    card.setAttribute("data-action-id", action.id);
    installMaximizable(card);

    var header = document.createElement("header");
    header.className = "cc-action-header";
    var h3 = document.createElement("h3");
    h3.textContent = action.title || action.id;
    var badges = document.createElement("div");
    badges.className = "cc-action-badges";
    badges.appendChild(makeBadge("cc-badge " + (action.streams ? "cc-badge--stream" : "cc-badge--sync"),
      action.streams ? "streaming" : "sync"));
    if (action.requires_card) {
      badges.appendChild(makeBadge("cc-badge cc-badge--card", "needs card"));
    }
    badges.appendChild(makeBadge("cc-badge cc-badge--out", action.output_kind));
    header.appendChild(h3);
    header.appendChild(badges);
    card.appendChild(header);

    var sub = document.createElement("p");
    sub.className = "cc-action-id";
    sub.innerHTML = "<code>" + escapeHtml(action.id) + "</code>";
    card.appendChild(sub);

    var desc = document.createElement("p");
    desc.className = "cc-action-desc";
    desc.textContent = action.description || "";
    card.appendChild(desc);

    var form = document.createElement("form");
    form.className = "cc-action-form";
    (action.inputs || []).forEach(function (field) {
      form.appendChild(buildField(action, field));
    });
    var actionsBar = document.createElement("div");
    actionsBar.className = "inline-actions cc-action-bar";
    var runBtn = document.createElement("button");
    runBtn.type = "submit";
    runBtn.className = "btn btn-primary";
    runBtn.textContent = action.streams ? "Start" : "Run";
    actionsBar.appendChild(runBtn);
    var status = document.createElement("span");
    status.className = "cc-action-status";
    status.textContent = "idle";
    actionsBar.appendChild(status);
    form.appendChild(actionsBar);
    card.appendChild(form);

    var result = document.createElement("div");
    result.className = "cc-action-result cc-action-result--" + action.output_kind;
    card.appendChild(result);

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      runActionFromForm(action, form, status, result);
    });

    // If the action declares a "reader" field, prefill from live readers.
    (action.inputs || []).forEach(function (field) {
      if (field.kind === "reader") {
        prefillReaderSelect(form.querySelector('[name="' + field.name + '"]'));
      }
    });

    return card;
  }

  function makeBadge(cls, text) {
    var span = document.createElement("span");
    span.className = cls;
    span.textContent = text;
    return span;
  }

  function buildField(action, field) {
    var row = document.createElement("div");
    row.className = "form-row cc-form-row";

    var label = document.createElement("label");
    label.textContent = field.label || field.name;
    var fid = "cc-" + action.id.replace(/\./g, "-") + "-" + field.name;
    label.setAttribute("for", fid);
    row.appendChild(label);

    var input;
    if (field.kind === "bool") {
      var wrapper = document.createElement("label");
      wrapper.className = "cc-checkbox";
      input = document.createElement("input");
      input.type = "checkbox";
      input.id = fid;
      input.name = field.name;
      if (field.default === true) {
        input.checked = true;
      }
      wrapper.appendChild(input);
      var wrapText = document.createElement("span");
      wrapText.textContent = field.help || field.label || field.name;
      wrapper.appendChild(wrapText);
      row.appendChild(wrapper);
      return row;
    }
    if (field.kind === "enum") {
      input = document.createElement("select");
      (field.choices || []).forEach(function (choice) {
        var opt = document.createElement("option");
        opt.value = String(choice);
        opt.textContent = String(choice);
        input.appendChild(opt);
      });
    } else if (field.kind === "reader") {
      input = document.createElement("select");
      var empty = document.createElement("option");
      empty.value = "";
      empty.textContent = "(default / first reader)";
      input.appendChild(empty);
    } else if (field.multiline) {
      input = document.createElement("textarea");
      input.rows = 4;
    } else if (field.kind === "int") {
      input = document.createElement("input");
      input.type = "number";
      if (field.min_value !== undefined) input.min = field.min_value;
      if (field.max_value !== undefined) input.max = field.max_value;
    } else {
      input = document.createElement("input");
      input.type = field.secret ? "password" : "text";
    }
    input.id = fid;
    input.name = field.name;
    if (field.placeholder) {
      input.placeholder = field.placeholder;
    }
    if (field.default !== undefined && field.default !== null && field.kind !== "bool") {
      input.value = String(field.default);
    }
    if (field.required) {
      input.required = true;
    }
    row.appendChild(input);

    if (field.help) {
      var hint = document.createElement("small");
      hint.className = "cc-field-hint";
      hint.textContent = field.help;
      row.appendChild(hint);
    }
    return row;
  }

  async function prefillReaderSelect(select) {
    if (!select) return;
    var preferred = "";
    try { preferred = (window.YggdraSimReaderStore && window.YggdraSimReaderStore.getSelected()) || ""; } catch (_e) {}
    try {
      var data = await apiFetch("/api/live/readers");
      var readers = data.readers || [];
      if (readers.length === 0) {
        return;
      }
      readers.forEach(function (row) {
        var opt = document.createElement("option");
        opt.value = row.name;
        opt.textContent = row.name;
        if (row.atr_hex) {
          opt.textContent += " · " + row.atr_hex.substring(0, 12) + "…";
        }
        select.appendChild(opt);
      });
      if (preferred && Array.from(select.options).some(function (o) { return o.value === preferred; })) {
        select.value = preferred;
      }
    } catch (_err) {
      // Leave the default option in place.
    }
  }

  function collectFormValues(form) {
    var values = {};
    Array.from(form.elements).forEach(function (el) {
      if (!el.name) return;
      if (el.type === "checkbox") {
        values[el.name] = Boolean(el.checked);
        return;
      }
      if (el.type === "number") {
        var v = String(el.value || "").trim();
        values[el.name] = v === "" ? null : Number(v);
        return;
      }
      values[el.name] = el.value;
    });
    return values;
  }

  function findHostCard(form) {
    if (!form) return null;
    return form.closest(".cc-action-card") || null;
  }

  function setActionBusy(card, action, busy) {
    if (!card) return;
    card.classList.toggle("is-busy", Boolean(busy));
    if (busy) {
      card.setAttribute("data-busy-since", String(Date.now()));
    } else {
      card.removeAttribute("data-busy-since");
    }
    // Mirror the busy state on the active subsystem nav entry so the
    // sidebar shows that something is in flight even if the user has
    // scrolled past the card.
    var subsystem = action && action.subsystem;
    if (subsystem) {
      document.querySelectorAll(
        "#command-center-nav .subsystem-entry[data-cc-subsystem]"
      ).forEach(function (entry) {
        if (entry.getAttribute("data-cc-subsystem") === subsystem) {
          entry.classList.toggle("is-busy", Boolean(busy));
        }
      });
    }
  }

  async function runActionFromForm(action, form, statusEl, resultEl) {
    var inputs = collectFormValues(form);
    var card = findHostCard(form);
    statusEl.textContent = action.streams ? "starting…" : "running…";
    setStatusAction("action: " + action.id);
    resultEl.innerHTML = "";
    setActionBusy(card, action, true);
    logBus.emit({
      level: "info",
      source: action.id,
      message: action.streams ? "stream: starting" : "run: starting",
    });
    if (action.streams) {
      // Streaming clears its own busy flag in the socket lifecycle.
      runStreamingAction(action, inputs, statusEl, resultEl, card);
    } else {
      try {
        var resp = await apiFetch("/api/actions/" + encodeURIComponent(action.id) + "/run", {
          method: "POST",
          body: JSON.stringify({ inputs: inputs }),
        });
        if (!resp.ok) {
          statusEl.textContent = "error";
          resultEl.appendChild(renderErrorBlock(resp.error || "unknown error"));
          logBus.emit({
            level: "error",
            source: action.id,
            message: "run: failed — " + (resp.error || "unknown error"),
          });
          return;
        }
        statusEl.textContent = "ok";
        renderActionResult(action, resp.data || {}, resultEl);
        logBus.emit({
          level: "info",
          source: action.id,
          message: "run: ok",
        });
      } catch (err) {
        statusEl.textContent = "error";
        resultEl.appendChild(renderErrorBlock(String(err && err.message || err)));
        logBus.emit({
          level: "error",
          source: action.id,
          message: "run: " + String(err && err.message || err),
        });
      } finally {
        setActionBusy(card, action, false);
      }
    }
  }

  function renderErrorBlock(message) {
    var el = document.createElement("div");
    el.className = "cc-error";
    el.textContent = message;
    return el;
  }

  function runStreamingAction(action, inputs, statusEl, resultEl, card) {
    var token = getStoredToken();
    var scheme = window.location.protocol === "https:" ? "wss" : "ws";
    var endpoint;
    if (action.id === "scp11.download_profile") {
      // Delegates to the legacy WS route with its own "start" payload shape.
      endpoint = "/api/flows/download-profile";
    } else {
      endpoint = "/api/actions/" + encodeURIComponent(action.id) + "/stream";
    }
    var url = scheme + "://" + window.location.host + endpoint
      + "?t=" + encodeURIComponent(token);
    var log = document.createElement("div");
    log.className = "flow-log cc-log";
    resultEl.appendChild(log);

    var sock = new WebSocket(url);
    var runBtn = resultEl.parentElement.querySelector(".cc-action-bar .btn");
    if (runBtn) runBtn.disabled = true;

    sock.onopen = function () {
      appendLogRow(log, "info", "connected — sending start frame");
      logBus.emit({
        level: "info",
        source: action.id,
        message: "stream: connected",
      });
      var startPayload;
      if (action.id === "scp11.download_profile") {
        // legacy shape: reader/activation_code/... at top level.
        startPayload = Object.assign({ type: "start" }, inputs);
      } else {
        startPayload = { type: "start", inputs: inputs };
      }
      sock.send(JSON.stringify(startPayload));
      statusEl.textContent = "running";
    };
    sock.onmessage = function (event) {
      try {
        var msg = JSON.parse(event.data);
        var level = msg.level || "info";
        var text = msg.message || JSON.stringify(msg);
        appendLogRow(log, level, text);
        logBus.emit({
          level: level,
          source: action.id,
          message: text,
          data: msg,
        });
        if (level === "done") {
          statusEl.textContent = "done";
          if (msg.report) {
            resultEl.appendChild(renderReportSummary(msg.report));
          }
        } else if (level === "error") {
          statusEl.textContent = "error";
        }
      } catch (_err) {
        appendLogRow(log, "info", String(event.data));
        logBus.emit({
          level: "info",
          source: action.id,
          message: String(event.data),
        });
      }
    };
    sock.onclose = function () {
      if (runBtn) runBtn.disabled = false;
      setActionBusy(card, action, false);
      appendLogRow(log, "info", "socket closed");
      logBus.emit({
        level: "info",
        source: action.id,
        message: "stream: closed",
      });
      // Same rationale as the PTY socket: detach handlers so the
      // browser can free the buffered frames + closure chain right
      // away. Long dogfooding sessions (several hundred action runs)
      // were holding a multi-MB chain of dead sockets otherwise.
      sock.onmessage = null;
      sock.onopen = null;
      sock.onerror = null;
      sock.onclose = null;
    };
    sock.onerror = function () {
      statusEl.textContent = "socket error";
      setActionBusy(card, action, false);
      logBus.emit({
        level: "error",
        source: action.id,
        message: "stream: socket error",
      });
    };
  }

  function renderReportSummary(report) {
    var wrap = document.createElement("div");
    wrap.className = "cc-report-summary";
    var heading = document.createElement("h4");
    heading.textContent = "Summary";
    wrap.appendChild(heading);
    var summary = report && report.summary ? report.summary : report;
    var dl = document.createElement("dl");
    Object.keys(summary || {}).forEach(function (key) {
      var dt = document.createElement("dt");
      dt.textContent = key;
      var dd = document.createElement("dd");
      dd.textContent = String(summary[key]);
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    wrap.appendChild(dl);

    var rows = report && report.rows ? report.rows : null;
    if (Array.isArray(rows) && rows.length > 0) {
      var tableHeading = document.createElement("h4");
      tableHeading.textContent = "Cycles (" + rows.length + ")";
      wrap.appendChild(tableHeading);
      wrap.appendChild(renderObjectTable(rows));
    }
    return wrap;
  }

  // --- Output renderers ---------------------------------------------------

  function renderActionResult(action, data, container) {
    pipeApduSignals(action, data);
    var kind = action.output_kind || "json";
    if (kind === "tree" && action.id === "scp03.scan") {
      return renderScanResult(data, container);
    }
    if (kind === "fcp") {
      return renderFcpResult(data, container);
    }
    if (kind === "tlv_tree") {
      return renderTlvTreeResult(data, container);
    }
    if (kind === "findings") {
      return renderFindingsResult(data, container);
    }
    if (kind === "key_value_lines") {
      return renderKeyValueLinesResult(data, container);
    }
    if (kind === "table" && data && data.rows) {
      container.appendChild(renderObjectTable(data.rows));
      return;
    }
    if (kind === "hex" && typeof data.hex === "string") {
      container.appendChild(renderHexBlock(data.hex));
      return;
    }
    // --- json / default: datasheet-wrapped decoded block (SCP03 style) ---
    var sheet = document.createElement("div");
    sheet.className = "cc-action-datasheet";

    var metaRows = [];
    if (data && typeof data === "object") {
      if (data.reader_name && String(data.reader_name).trim().length > 0) {
        metaRows.push({ label: "Reader", value: String(data.reader_name) });
      }
      if (data.eid && String(data.eid).trim().length > 0) {
        metaRows.push({ label: "EID", value: String(data.eid) });
      }
      if (data.input_length) {
        metaRows.push({ label: "Input", value: String(data.input_length) + " B" });
      }
      var _noteText = String(data.note || "").trim();
      if (_noteText.length > 0 && _noteText !== "ok") {
        metaRows.push({ label: "Note", value: _noteText });
      }
      if (data.sw && String(data.sw).trim().length > 0) {
        metaRows.push({ label: "SW", value: String(data.sw) });
      }
      if (data.ok !== undefined) {
        metaRows.push({ label: "Status", value: data.ok ? "ok" : "failed" });
      }
      if (data.target && String(data.target).trim().length > 0) {
        metaRows.push({ label: "Target", value: String(data.target) });
      }
      if (data.found !== undefined) {
        metaRows.push({ label: "Found", value: data.found ? "yes" : "no" });
      }
    }
    scp03DatasheetAppendMetaKvl(sheet, metaRows);

    var main = scp03DatasheetWrapMain();
    var decodedHead = document.createElement("div");
    decodedHead.className = "cc-action-datasheet-main-head";
    decodedHead.textContent = "Result";
    main.appendChild(decodedHead);
    main.appendChild(renderDecodedBlock(data));
    sheet.appendChild(main);

    if (data && typeof data.raw_hex === "string" && data.raw_hex.trim().length > 0) {
      scp03DatasheetAppendRawHex(sheet, data.raw_hex.trim(), "Raw response");
    }

    if (data && typeof data.trace === "string" && data.trace.trim().length > 0) {
      scp03DatasheetAppendTraceMain(sheet, data.trace, "Console trace");
    }

    container.appendChild(sheet);
  }

  // -- APDU trace pipe (G-4) ----------------------------------------------
  //
  // Several actions (notably scp11_live.*) capture the orchestrator's
  // stdout/stderr into ``data.trace`` so the GUI can show what the card
  // actually exchanged. Stream those lines through the bottom-log "APDU"
  // bucket so an operator can build situational awareness across calls
  // without opening every result panel.

  function pipeTraceLinesToApdu(source, text) {
    if (typeof text !== "string" || text.length === 0) return;
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = String(lines[i] || "").trimEnd();
      if (line.length === 0) continue;
      logBus.emit({
        level: "apdu",
        source: source,
        message: line,
      });
    }
  }

  function pipeApduSignals(action, data) {
    if (!data) return;
    var actionId = (action && action.id) || "action";
    if (typeof data.trace === "string" && data.trace.length > 0) {
      pipeTraceLinesToApdu(actionId, data.trace);
    }
    // Synthetic single-line summaries for SCP03 actions that don't have
    // a captured trace today. Keeps the APDU tab usable across the whole
    // workbench, not just the SCP11 surface.
    if (actionId === "scp03.read_selected" && typeof data.payload === "object") {
      var p = data.payload || {};
      if (p.kind === "transparent") {
        logBus.emit({
          level: "apdu",
          source: actionId,
          message: "READ BINARY → sw=" + (p.sw || "?") + " · " +
            (p.length || 0) + " B · " + (data.path || ""),
        });
      } else if (p.kind === "records" && Array.isArray(p.records)) {
        logBus.emit({
          level: "apdu",
          source: actionId,
          message: "READ RECORD ×" + p.records.length + " on " +
            (data.path || "") + " (rec_len " + (p.rec_len || "?") + ")",
        });
      }
    }
    if (actionId === "scp03.select" && typeof data.sw === "string") {
      logBus.emit({
        level: "apdu",
        source: actionId,
        message: "SELECT " + (data.identifier || "?") + " → sw=" + data.sw +
          " · fcp " + (data.fcp_hex ? data.fcp_hex.length / 2 + " B" : "(none)"),
      });
    }
    if (actionId === "scp03.list_apps" && Array.isArray(data.rows)) {
      logBus.emit({
        level: "apdu",
        source: actionId,
        message: "EF.DIR list → " + data.rows.length + " application record(s)",
      });
    }
    if (actionId === "scp03.scan" && typeof data.session_id === "string") {
      logBus.emit({
        level: "apdu",
        source: actionId,
        message: "SCAN session " + data.session_id.substring(0, 8) +
          " · ATR " + (data.atr_hex || "(none)") +
          " · reader " + (data.reader_name || "(default)"),
      });
    }
  }

  function renderTlvTreeResult(data, container) {
    if (!data || !Array.isArray(data.nodes)) {
      container.appendChild(renderJsonBlock(data));
      return;
    }
    var meta = document.createElement("div");
    meta.className = "cc-tlv-meta";
    var parts = [];
    parts.push("input: " + (data.input_length || 0) + " B");
    parts.push("consumed: " + (data.consumed || 0) + " B");
    parts.push(data.complete ? "complete" : "incomplete");
    meta.textContent = parts.join(" \u00b7 ");
    container.appendChild(meta);
    if (data.error) {
      var err = document.createElement("div");
      err.className = "cc-error-block";
      err.textContent = "parser note: " + data.error;
      container.appendChild(err);
    }
    var wrap = document.createElement("div");
    wrap.className = "cc-tlv-tree";
    wrap.appendChild(renderTlvNodes(data.nodes, 0));
    container.appendChild(wrap);
  }

  function renderTlvNodes(nodes, level) {
    var ul = document.createElement("ul");
    ul.className = "cc-tlv-list" + (level === 0 ? " cc-tlv-list-root" : "");
    (nodes || []).forEach(function (node) {
      var li = document.createElement("li");
      li.className = "cc-tlv-node";
      var header = document.createElement("div");
      header.className = "cc-tlv-row";
      var tag = document.createElement("span");
      tag.className = "cc-tlv-tag";
      tag.textContent = node.tag_hex;
      var len = document.createElement("span");
      len.className = "cc-tlv-len";
      len.textContent = "[" + (node.length || 0) + "]";
      header.appendChild(tag);
      header.appendChild(len);
      if (!node.children && typeof node.value_hex === "string") {
        var val = document.createElement("code");
        val.className = "cc-tlv-value";
        val.textContent = node.value_hex || "(empty)";
        header.appendChild(val);
      }
      li.appendChild(header);
      if (Array.isArray(node.children) && node.children.length > 0) {
        li.appendChild(renderTlvNodes(node.children, level + 1));
      }
      ul.appendChild(li);
    });
    return ul;
  }

  function renderFindingsResult(data, container) {
    if (!data) {
      container.appendChild(renderJsonBlock(data));
      return;
    }
    var header = document.createElement("div");
    header.className = "cc-findings-header";
    var bits = [];
    bits.push("profile: " + (data.profile_label || "ad-hoc"));
    bits.push(data.strict ? "strict=on" : "strict=off");
    if (data.template_mode) bits.push("template-mode");
    header.textContent = bits.join(" \u00b7 ");
    container.appendChild(header);
    if (data.parse_error) {
      var err = document.createElement("div");
      err.className = "cc-error-block";
      err.textContent = "parse error: " + data.parse_error;
      container.appendChild(err);
    }
    var findings = Array.isArray(data.findings) ? data.findings : [];
    if (findings.length === 0) {
      var empty = document.createElement("p");
      empty.className = "cc-findings-empty";
      empty.textContent = data.parse_error ? "(no lint run)" : "No findings.";
      container.appendChild(empty);
    } else {
      var list = document.createElement("ul");
      list.className = "cc-findings-list";
      findings.forEach(function (finding) {
        var li = document.createElement("li");
        li.className = "cc-finding cc-finding-" + (finding.severity || "info").toLowerCase();
        var head = document.createElement("div");
        head.className = "cc-finding-head";
        var sev = document.createElement("span");
        sev.className = "cc-finding-sev";
        sev.textContent = (finding.severity || "info").toUpperCase();
        head.appendChild(sev);
        var code = document.createElement("span");
        code.className = "cc-finding-code";
        code.textContent = finding.code || "-";
        head.appendChild(code);
        if (finding.spec) {
          var spec = document.createElement("span");
          spec.className = "cc-finding-spec";
          spec.textContent = finding.spec;
          head.appendChild(spec);
        }
        if (finding.path) {
          var path = document.createElement("span");
          path.className = "cc-finding-path";
          path.textContent = finding.path;
          head.appendChild(path);
        }
        li.appendChild(head);
        if (finding.message) {
          var msg = document.createElement("div");
          msg.className = "cc-finding-msg";
          msg.textContent = finding.message;
          li.appendChild(msg);
        }
        if (finding.recommendation) {
          var rec = document.createElement("div");
          rec.className = "cc-finding-rec";
          rec.textContent = "→ " + finding.recommendation;
          li.appendChild(rec);
        }
        list.appendChild(li);
      });
      container.appendChild(list);
    }
    if (Array.isArray(data.undefined_tokens) && data.undefined_tokens.length > 0) {
      var tokensHead = document.createElement("h4");
      tokensHead.className = "cc-findings-subhead";
      tokensHead.textContent = "Undefined tokens";
      container.appendChild(tokensHead);
      var tokenList = document.createElement("ul");
      tokenList.className = "cc-token-list";
      data.undefined_tokens.forEach(function (token) {
        var li = document.createElement("li");
        li.textContent = token;
        tokenList.appendChild(li);
      });
      container.appendChild(tokenList);
    }
  }

  function renderKeyValueLinesResult(data, container) {
    if (!data) {
      container.appendChild(renderJsonBlock(data));
      return;
    }
    var meta = document.createElement("div");
    meta.className = "cc-kvl-meta";
    meta.textContent = "input: " + (data.input_length || 0) + " B";
    container.appendChild(meta);
    var sections = [
      { title: "Detail", key: "detail_lines" },
      { title: "Validation", key: "validation_lines" },
    ];
    sections.forEach(function (section) {
      var rows = Array.isArray(data[section.key]) ? data[section.key] : [];
      if (rows.length === 0) return;
      var h = document.createElement("h4");
      h.className = "cc-kvl-head";
      h.textContent = section.title;
      container.appendChild(h);
      var wrap = document.createElement("div");
      wrap.className = "cc-kvl-block";
      rows.forEach(function (row) {
        var line = document.createElement("div");
        line.className = "cc-kvl-row";
        var indent = Math.max(0, Math.min(8, parseInt(row.indent || 0, 10)));
        line.style.paddingLeft = (indent * 14) + "px";
        var label = document.createElement("span");
        label.className = "cc-kvl-label";
        label.textContent = row.label || "";
        var value = document.createElement("span");
        value.className = "cc-kvl-value";
        value.textContent = row.value || "";
        line.appendChild(label);
        line.appendChild(value);
        wrap.appendChild(line);
      });
      container.appendChild(wrap);
    });
  }

  function scp03RenderKeyValueRows(container, rows) {
    var wrap = document.createElement("div");
    wrap.className = "cc-kvl-block";
    rows.forEach(function (row) {
      var line = document.createElement("div");
      line.className = "cc-kvl-row";
      var label = document.createElement("span");
      label.className = "cc-kvl-label";
      label.textContent = row.label || "";
      var value = document.createElement("span");
      value.className = "cc-kvl-value";
      value.textContent = row.value == null ? "" : String(row.value);
      line.appendChild(label);
      line.appendChild(value);
      wrap.appendChild(line);
    });
    container.appendChild(wrap);
  }

  function scp03DatasheetAppendMetaKvl(root, rows) {
    if (!rows || rows.length === 0) return;
    var meta = document.createElement("div");
    meta.className = "cc-action-datasheet-meta";
    scp03RenderKeyValueRows(meta, rows);
    root.appendChild(meta);
  }

  function scp03DatasheetWrapMain() {
    var wrap = document.createElement("div");
    wrap.className = "cc-action-datasheet-main";
    return wrap;
  }

  function scp03DatasheetAppendRawHex(root, hex, summaryText) {
    if (!hex) return;
    var det = document.createElement("details");
    det.className = "cc-details cc-action-datasheet-raw";
    var sum = document.createElement("summary");
    var n = hex.length / 2;
    sum.textContent = summaryText || ("Raw response (" + n + " bytes)");
    det.appendChild(sum);
    det.appendChild(renderHexBlock(hex));
    root.appendChild(det);
  }

  function scp03DatasheetAppendTraceMain(root, trace, titleOpt) {
    if (!trace || String(trace).trim().length === 0) return;
    var main = document.createElement("div");
    main.className = "cc-action-datasheet-main";
    if (titleOpt) {
      var head = document.createElement("div");
      head.className = "cc-action-datasheet-main-head";
      head.textContent = titleOpt;
      main.appendChild(head);
    }
    var pre = document.createElement("pre");
    pre.className = "cc-json";
    pre.textContent = trace;
    main.appendChild(pre);
    root.appendChild(main);
  }

  function renderJsonBlock(data) {
    var pre = document.createElement("pre");
    pre.className = "cc-json";
    try {
      pre.textContent = JSON.stringify(data, null, 2);
    } catch (_err) {
      pre.textContent = String(data);
    }
    return pre;
  }

  function renderHexBlock(hex) {
    var pre = document.createElement("pre");
    pre.className = "cc-hex";
    pre.textContent = formatHexDump(hex);
    return pre;
  }

  function formatHexDump(hex) {
    if (!hex) return "(empty)";
    var cleaned = String(hex).replace(/\s+/g, "").toUpperCase();
    var lines = [];
    for (var i = 0; i < cleaned.length; i += 32) {
      var chunk = cleaned.substring(i, i + 32);
      var grouped = chunk.match(/.{1,2}/g) || [];
      var ascii = "";
      for (var j = 0; j < grouped.length; j++) {
        var byte = parseInt(grouped[j], 16);
        ascii += (byte >= 0x20 && byte < 0x7F) ? String.fromCharCode(byte) : ".";
      }
      var offset = (i / 2).toString(16).toUpperCase().padStart(4, "0");
      lines.push(offset + "  " + grouped.join(" ").padEnd(47, " ") + "  |" + ascii + "|");
    }
    return lines.join("\n");
  }

  function renderObjectTable(rows) {
    var table = document.createElement("table");
    table.className = "data-table cc-table";
    if (!Array.isArray(rows) || rows.length === 0) {
      var tr = document.createElement("tr");
      var td = document.createElement("td");
      td.textContent = "(no rows)";
      tr.appendChild(td);
      table.appendChild(tr);
      return table;
    }
    var keys = Object.keys(rows[0] || {});
    var thead = document.createElement("thead");
    var head = document.createElement("tr");
    keys.forEach(function (key) {
      var th = document.createElement("th");
      th.textContent = key;
      head.appendChild(th);
    });
    thead.appendChild(head);
    table.appendChild(thead);
    var tbody = document.createElement("tbody");
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      keys.forEach(function (key) {
        var td = document.createElement("td");
        var value = row[key];
        if (value !== null && typeof value === "object") {
          td.textContent = JSON.stringify(value);
        } else {
          td.textContent = value === null || value === undefined ? "" : String(value);
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
  }

  // --- scp03.scan tree ----------------------------------------------------

  // -- SCP03 Workbench (multi-reader tabs) --------------------------------

  function renderScp03Workbench(container, actions) {
    var wb = document.createElement("section");
    wb.className = "cc-workbench";
    wb.setAttribute("data-wb", "scp03");

    var header = document.createElement("div");
    header.className = "cc-wb-header";
    var title = document.createElement("h3");
    title.textContent = "SCP03 session workbench";
    header.appendChild(title);
    var lead = document.createElement("p");
    lead.className = "cc-wb-lead";
    lead.textContent = "Open a tab per reader. Each tab keeps its own open session, scan tree and preview. Double-click any panel to maximize it.";
    header.appendChild(lead);
    wb.appendChild(header);

    var tabBar = document.createElement("div");
    tabBar.className = "cc-wb-tabs";
    tabBar.setAttribute("role", "tablist");
    wb.appendChild(tabBar);

    var tabBody = document.createElement("div");
    tabBody.className = "cc-wb-body";
    wb.appendChild(tabBody);

    container.appendChild(wb);

    scp03EnsureDefaultTab();
    renderScp03Tabs(tabBar, tabBody);
  }

  function scp03EnsureDefaultTab() {
    var wb = commandState.scp03Workbench;
    if (wb.tabs.length === 0) {
      var tab = scp03CreateEmptyTab();
      wb.tabs.push(tab);
      wb.activeTabId = tab.id;
    } else if (!wb.activeTabId || !scp03FindTab(wb.activeTabId)) {
      wb.activeTabId = wb.tabs[0].id;
    }
  }

  function scp03CreateEmptyTab() {
    var wb = commandState.scp03Workbench;
    var id = "scp03-tab-" + (wb.tabSeq++);
    return {
      id: id,
      sessionId: null,
      readerName: "",
      atrHex: "",
      scanData: null,
      selectedPath: null,
      previewCache: null, // last FCP / records response
      status: "idle",
      error: null,
    };
  }

  function scp03FindTab(tabId) {
    var wb = commandState.scp03Workbench;
    for (var i = 0; i < wb.tabs.length; i++) {
      if (wb.tabs[i].id === tabId) return wb.tabs[i];
    }
    return null;
  }

  function refreshSessionStatusMetric() {
    var wb = commandState && commandState.scp03Workbench;
    if (!wb || !Array.isArray(wb.tabs)) {
      try { setStatusSessions("0"); } catch (_err) {}
      return;
    }
    var open = 0;
    wb.tabs.forEach(function (tab) {
      if (tab && tab.sessionId) open++;
    });
    try { setStatusSessions(String(open)); } catch (_err) {}
  }

  function renderScp03Tabs(tabBar, tabBody) {
    var wb = commandState.scp03Workbench;
    tabBar.innerHTML = "";
    tabBody.innerHTML = "";
    refreshSessionStatusMetric();

    wb.tabs.forEach(function (tab) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "cc-wb-tab" + (tab.id === wb.activeTabId ? " active" : "");
      btn.setAttribute("data-tab-id", tab.id);
      var label = document.createElement("span");
      label.className = "cc-wb-tab-label";
      if (tab.sessionId) {
        label.textContent = tab.readerName || "reader";
      } else {
        label.textContent = "+ New session";
      }
      btn.appendChild(label);
      if (tab.sessionId) {
        var meta = document.createElement("span");
        meta.className = "cc-wb-tab-meta";
        meta.textContent = (tab.sessionId || "").substring(0, 6);
        btn.appendChild(meta);
        var close = document.createElement("span");
        close.className = "cc-wb-tab-close";
        close.textContent = "\u00d7";
        close.title = "Close this session";
        close.addEventListener("click", function (event) {
          event.stopPropagation();
          scp03CloseTab(tab.id, tabBar, tabBody);
        });
        btn.appendChild(close);
      }
      btn.addEventListener("click", function () {
        wb.activeTabId = tab.id;
        renderScp03Tabs(tabBar, tabBody);
      });
      tabBar.appendChild(btn);
    });

    var add = document.createElement("button");
    add.type = "button";
    add.className = "cc-wb-tab-add";
    add.textContent = "+";
    add.title = "Open a new reader in a new tab";
    add.addEventListener("click", function () {
      var tab = scp03CreateEmptyTab();
      wb.tabs.push(tab);
      wb.activeTabId = tab.id;
      renderScp03Tabs(tabBar, tabBody);
    });
    tabBar.appendChild(add);

    var active = scp03FindTab(wb.activeTabId);
    if (!active) {
      tabBody.innerHTML = '<p class="hint">no active tab.</p>';
      return;
    }
    scp03RenderTabBody(active, tabBody, tabBar);
  }

  function scp03RenderTabBody(tab, tabBody, tabBar) {
    tabBody.innerHTML = "";
    if (!tab.sessionId) {
      tabBody.appendChild(scp03BuildNewSessionForm(tab, tabBar, tabBody));
      return;
    }
    tabBody.appendChild(scp03BuildActiveSessionPanel(tab, tabBar, tabBody));
  }

  function scp03BuildNewSessionForm(tab, tabBar, tabBody) {
    var panel = document.createElement("div");
    panel.className = "cc-wb-new card";
    installMaximizable(panel);

    var h = document.createElement("h3");
    h.textContent = "Start a new SCP03 session";
    panel.appendChild(h);

    var hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = "Pick a PC/SC reader, then run the live scan. The transporter stays open in this tab until you close it.";
    panel.appendChild(hint);

    var form = document.createElement("form");
    form.className = "cc-action-form";
    var row = document.createElement("div");
    row.className = "form-row cc-form-row";
    var label = document.createElement("label");
    label.textContent = "Reader";
    row.appendChild(label);
    var select = document.createElement("select");
    select.name = "reader";
    var empty = document.createElement("option");
    empty.value = "";
    empty.textContent = "(default / first reader)";
    select.appendChild(empty);
    prefillReaderSelect(select);
    row.appendChild(select);
    form.appendChild(row);

    var bar = document.createElement("div");
    bar.className = "inline-actions cc-action-bar";
    var runBtn = document.createElement("button");
    runBtn.type = "submit";
    runBtn.className = "btn btn-primary";
    runBtn.textContent = "Scan";
    bar.appendChild(runBtn);
    var status = document.createElement("span");
    status.className = "cc-action-status";
    status.textContent = "idle";
    bar.appendChild(status);
    form.appendChild(bar);
    panel.appendChild(form);

    var errorSlot = document.createElement("div");
    errorSlot.className = "cc-wb-error";
    panel.appendChild(errorSlot);

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      errorSlot.innerHTML = "";
      status.textContent = "scanning…";
      runBtn.disabled = true;
      try {
        var resp = await apiFetch("/api/actions/scp03.scan/run", {
          method: "POST",
          body: JSON.stringify({ inputs: { reader: select.value } }),
        });
        if (!resp.ok) {
          status.textContent = "error";
          errorSlot.appendChild(renderErrorBlock(resp.error || "scan failed"));
          return;
        }
        var data = resp.data || {};
        tab.sessionId = data.session_id || null;
        tab.readerName = data.reader_name || "(default)";
        tab.atrHex = data.atr_hex || "";
        tab.scanData = data;
        tab.status = "open";
        // legacy single-session field kept for any stragglers
        commandState.scp03Session = tab.sessionId;
        renderScp03Tabs(tabBar, tabBody);
      } catch (err) {
        status.textContent = "error";
        errorSlot.appendChild(renderErrorBlock(String(err && err.message || err)));
      } finally {
        runBtn.disabled = false;
      }
    });

    return panel;
  }

  function scp03MakeRibbonButton(spec, onClick) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ribbon-btn" + (spec.danger ? " ribbon-btn--danger" : "");
    if (spec.disabled) btn.disabled = true;
    if (spec.title) btn.title = spec.title;
    var icon = document.createElement("span");
    icon.className = "ribbon-btn-icon";
    icon.textContent = spec.icon || "";
    icon.setAttribute("aria-hidden", "true");
    var label = document.createElement("span");
    label.className = "ribbon-btn-label";
    label.textContent = spec.label || "";
    btn.appendChild(icon);
    btn.appendChild(label);
    if (typeof onClick === "function") {
      btn.addEventListener("click", onClick);
    }
    return btn;
  }

  function scp03MakeRibbonGroup(label, buttons) {
    var group = document.createElement("div");
    group.className = "ribbon-group";
    var inner = document.createElement("div");
    inner.className = "ribbon-group-inner";
    buttons.forEach(function (b) { inner.appendChild(b); });
    var lbl = document.createElement("span");
    lbl.className = "ribbon-group-label";
    lbl.textContent = label;
    group.appendChild(inner);
    group.appendChild(lbl);
    return group;
  }

  function scp03BuildRibbon(tab, tabBar, tabBody) {
    var ribbon = document.createElement("div");
    ribbon.className = "ribbon scp03-ribbon";
    ribbon.setAttribute("role", "toolbar");
    ribbon.setAttribute("aria-label", "SCP03 session actions");

    // Navigate
    var rescanBtn = scp03MakeRibbonButton(
      { icon: "\u21BB", label: "Rescan", title: "Re-walk the file system from MF" },
      function () { scp03Rescan(tab, tabBar, tabBody); }
    );
    var resetSelBtn = scp03MakeRibbonButton(
      { icon: "\u29F8", label: "Clear selection", title: "Clear the selected file (UI only)" },
      function () {
        tab.selectedPath = null;
        tab.previewCache = null;
        renderScp03Tabs(tabBar, tabBody);
      }
    );
    var navGroup = scp03MakeRibbonGroup("Navigate", [rescanBtn, resetSelBtn]);

    // Inspect
    var readBtn = scp03MakeRibbonButton(
      {
        icon: "\u270E",
        label: "Read selected",
        title: "Re-read the currently selected file",
        disabled: !tab.selectedPath,
      },
      function () {
        if (!tab.selectedPath) return;
        var preview = document.querySelector(".cc-wb-body .cc-scan-preview");
        if (preview) readSelectedForTab(tab, tab.selectedPath, preview);
      }
    );
    var selectByAidBtn = scp03MakeRibbonButton(
      { icon: "\u2316", label: "SELECT…", title: "SELECT an arbitrary AID / file identifier" },
      function () { scp03PromptSelect(tab, tabBar, tabBody); }
    );
    var listAppsBtn = scp03MakeRibbonButton(
      { icon: "\u2630", label: "List apps", title: "Dump EF.DIR application records" },
      function () { scp03ListApps(tab); }
    );
    var inspectGroup = scp03MakeRibbonGroup("Inspect", [readBtn, selectByAidBtn, listAppsBtn]);

    // Session
    var closeBtn = scp03MakeRibbonButton(
      { icon: "\u2715", label: "Close", title: "Close this SCP03 session", danger: true },
      function () { scp03CloseTab(tab.id, tabBar, tabBody); }
    );
    var sessionGroup = scp03MakeRibbonGroup("Session", [closeBtn]);

    ribbon.appendChild(navGroup);
    ribbon.appendChild(inspectGroup);
    ribbon.appendChild(sessionGroup);
    return ribbon;
  }

  function scp03BuildBreadcrumb(tab, tabBar, tabBody) {
    var bar = document.createElement("nav");
    bar.className = "cc-breadcrumb";
    bar.setAttribute("aria-label", "Selected file path");

    var upBtn = document.createElement("button");
    upBtn.type = "button";
    upBtn.className = "cc-breadcrumb-up";
    upBtn.title = "Select parent (Backspace)";
    upBtn.textContent = "\u2191";
    var hasSelection = !!(tab.selectedPath && tab.selectedPath.length > 0);
    upBtn.disabled = !hasSelection;
    upBtn.addEventListener("click", function () {
      if (!tab.selectedPath) return;
      var parts = tab.selectedPath.split("/").filter(function (p) { return p.length > 0; });
      if (parts.length <= 1) {
        tab.selectedPath = null;
      } else {
        tab.selectedPath = parts.slice(0, -1).join("/");
      }
      scp03ApplyTreeSelection(tab);
      var preview = document.querySelector(".cc-wb-body .cc-scan-preview");
      if (tab.selectedPath && preview) {
        readSelectedForTab(tab, tab.selectedPath, preview);
      } else if (preview) {
        preview.innerHTML = '<p class="hint">Selection cleared.</p>';
      }
    });
    bar.appendChild(upBtn);

    var crumbs = document.createElement("ol");
    crumbs.className = "cc-breadcrumb-list";

    var rootCrumb = document.createElement("li");
    rootCrumb.className = "cc-breadcrumb-crumb cc-breadcrumb-root";
    if (!hasSelection) rootCrumb.classList.add("is-current");
    rootCrumb.textContent = "/";
    rootCrumb.title = "Root (clear selection)";
    rootCrumb.addEventListener("click", function () {
      tab.selectedPath = null;
      tab.previewCache = null;
      scp03ApplyTreeSelection(tab);
      var preview = document.querySelector(".cc-wb-body .cc-scan-preview");
      if (preview) {
        preview.innerHTML = '<p class="hint">Click a node to SELECT it and read its FCP + body.</p>';
      }
    });
    crumbs.appendChild(rootCrumb);

    if (hasSelection) {
      var parts = tab.selectedPath.split("/").filter(function (p) { return p.length > 0; });
      parts.forEach(function (part, idx) {
        var sep = document.createElement("li");
        sep.className = "cc-breadcrumb-sep";
        sep.textContent = "\u203A";
        crumbs.appendChild(sep);

        var crumb = document.createElement("li");
        crumb.className = "cc-breadcrumb-crumb";
        if (idx === parts.length - 1) crumb.classList.add("is-current");
        crumb.textContent = part;
        var pathToHere = parts.slice(0, idx + 1).join("/");
        crumb.title = pathToHere;
        crumb.addEventListener("click", function () {
          tab.selectedPath = pathToHere;
          scp03ApplyTreeSelection(tab);
          var preview = document.querySelector(".cc-wb-body .cc-scan-preview");
          if (preview) readSelectedForTab(tab, pathToHere, preview);
        });
        crumbs.appendChild(crumb);
      });
    } else {
      var hint = document.createElement("li");
      hint.className = "cc-breadcrumb-hint";
      hint.textContent = "(no selection)";
      crumbs.appendChild(hint);
    }
    bar.appendChild(crumbs);
    return bar;
  }

  function scp03ApplyTreeSelection(tab) {
    var tree = document.querySelector(".cc-wb-body .cc-tree");
    if (!tree) return;
    Array.from(tree.querySelectorAll(".cc-tree-row.active")).forEach(function (el) {
      el.classList.remove("active");
    });
    if (!tab.selectedPath) return;
    var match = tree.querySelector('.cc-tree-row[data-path="' + cssEscape(tab.selectedPath) + '"]');
    if (match) {
      match.classList.add("active");
      try { match.scrollIntoView({ block: "nearest", behavior: "smooth" }); } catch (_e) {}
    }
  }

  function cssEscape(value) {
    if (window.CSS && typeof window.CSS.escape === "function") {
      return window.CSS.escape(value);
    }
    return String(value).replace(/["\\]/g, "\\$&");
  }

  async function scp03PromptSelect(tab, tabBar, tabBody) {
    var raw = "";
    try {
      raw = window.prompt(
        "SELECT — enter AID or file identifier (hex, e.g. A0000000871002 or 7FFF):",
        ""
      );
    } catch (_err) { raw = ""; }
    if (raw === null) return;
    var trimmed = String(raw).replace(/\s+/g, "").toUpperCase();
    if (trimmed.length === 0) return;
    if (trimmed.length % 2 !== 0 || /[^0-9A-F]/.test(trimmed)) {
      logBus.emit({
        level: "error",
        source: "scp03.select",
        message: "rejected non-hex / odd-length input: " + raw,
      });
      return;
    }
    logBus.emit({
      level: "info",
      source: "scp03.select",
      message: "SELECT " + trimmed + " on session " + (tab.sessionId || "?"),
    });
    try {
      var resp = await apiFetch("/api/actions/scp03.select/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: { session_id: tab.sessionId, identifier: trimmed },
        }),
      });
      if (!resp.ok) {
        logBus.emit({
          level: "error",
          source: "scp03.select",
          message: resp.error || "SELECT failed",
        });
        return;
      }
      var data = resp.data || {};
      logBus.emit({
        level: "info",
        source: "scp03.select",
        message: "SELECT ok — sw=" + (data.sw || "?") + " fcp=" + (data.fcp_hex ? data.fcp_hex.substring(0, 32) + "…" : "(none)"),
      });
    } catch (err) {
      logBus.emit({
        level: "error",
        source: "scp03.select",
        message: String(err && err.message || err),
      });
    }
  }

  function scp03BuildActiveSessionPanel(tab, tabBar, tabBody) {
    var wrap = document.createElement("div");
    wrap.className = "cc-wb-session";
    installMaximizable(wrap);

    var header = document.createElement("div");
    header.className = "cc-scan-header";
    header.innerHTML = '<span class="cc-chip">reader: ' + escapeHtml(tab.readerName || "(default)") + '</span>'
      + '<span class="cc-chip">atr: ' + escapeHtml(tab.atrHex || "(none)") + '</span>'
      + '<span class="cc-chip">session: <code>' + escapeHtml(tab.sessionId || "") + '</code></span>';
    wrap.appendChild(header);

    wrap.appendChild(scp03BuildRibbon(tab, tabBar, tabBody));
    wrap.appendChild(scp03BuildBreadcrumb(tab, tabBar, tabBody));

    var layout = document.createElement("div");
    layout.className = "cc-scan-layout";
    var tree = document.createElement("div");
    tree.className = "cc-tree";
    installMaximizable(tree);
    tree.appendChild(renderTreeNodes(((tab.scanData || {}).tree) || []));
    layout.appendChild(tree);
    var preview = document.createElement("div");
    preview.className = "cc-scan-preview";
    installMaximizable(preview);
    if (tab.previewCache) {
      renderFcpResult(tab.previewCache, preview);
    } else {
      preview.innerHTML = '<p class="hint">Click a node to SELECT it and read its FCP + body. Record-based files show every record with both hex and decoded views.</p>';
    }
    layout.appendChild(preview);
    wrap.appendChild(layout);

    var extras = document.createElement("div");
    extras.className = "cc-wb-extras";
    extras.setAttribute("data-extras", "1");
    wrap.appendChild(extras);

    tree.addEventListener("click", function (event) {
      var row = event.target.closest(".cc-tree-row");
      if (!row) return;
      var path = row.getAttribute("data-path");
      if (!path) return;
      Array.from(tree.querySelectorAll(".cc-tree-row.active")).forEach(function (el) {
        el.classList.remove("active");
      });
      row.classList.add("active");
      tab.selectedPath = path;
      // Refresh the breadcrumb in place so the new path is visible
      // immediately, without re-rendering the whole tab body.
      var oldCrumb = wrap.querySelector(".cc-breadcrumb");
      if (oldCrumb && oldCrumb.parentNode) {
        var fresh = scp03BuildBreadcrumb(tab, tabBar, tabBody);
        oldCrumb.parentNode.replaceChild(fresh, oldCrumb);
      }
      readSelectedForTab(tab, path, preview);
    });

    return wrap;
  }

  async function scp03Rescan(tab, tabBar, tabBody) {
    tab.status = "scanning";
    try {
      var resp = await apiFetch("/api/actions/scp03.scan/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { reader: tab.readerName === "(default)" ? "" : tab.readerName } }),
      });
      if (!resp.ok) {
        tab.error = resp.error || "rescan failed";
        renderScp03Tabs(tabBar, tabBody);
        return;
      }
      var data = resp.data || {};
      tab.sessionId = data.session_id || null;
      tab.readerName = data.reader_name || tab.readerName;
      tab.atrHex = data.atr_hex || tab.atrHex;
      tab.scanData = data;
      tab.previewCache = null;
      tab.selectedPath = null;
      tab.status = "open";
      tab.error = null;
      commandState.scp03Session = tab.sessionId;
    } catch (err) {
      tab.error = String(err && err.message || err);
    }
    renderScp03Tabs(tabBar, tabBody);
  }

  async function scp03ListApps(tab) {
    var extras = document.querySelector(".cc-wb-body .cc-wb-extras");
    if (!extras) return;
    extras.innerHTML = '<p class="loading">listing EF.DIR applications…</p>';
    try {
      var resp = await apiFetch("/api/actions/scp03.list_apps/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      extras.innerHTML = "";
      var card = document.createElement("div");
      card.className = "card cc-wb-extras-card";
      installMaximizable(card);
      var h = document.createElement("h4");
      h.textContent = "EF.DIR applications";
      card.appendChild(h);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "list_apps failed"));
      } else {
        var data = resp.data || {};
        var meta = document.createElement("p");
        meta.className = "hint";
        meta.textContent = (data.count || 0) + " application(s)";
        card.appendChild(meta);
        card.appendChild(renderObjectTable(data.rows || []));
      }
      extras.appendChild(card);
    } catch (err) {
      extras.innerHTML = "";
      extras.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03CloseTab(tabId, tabBar, tabBody) {
    var wb = commandState.scp03Workbench;
    var tab = scp03FindTab(tabId);
    if (!tab) return;
    if (tab.sessionId) {
      try {
        await apiFetch("/api/actions/scp03.close_session/run", {
          method: "POST",
          body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
        });
      } catch (_err) {
        // Best-effort; backend close is idempotent.
      }
    }
    wb.tabs = wb.tabs.filter(function (entry) { return entry.id !== tabId; });
    if (wb.activeTabId === tabId) {
      wb.activeTabId = wb.tabs.length > 0 ? wb.tabs[0].id : null;
    }
    if (wb.tabs.length === 0) {
      scp03EnsureDefaultTab();
    }
    renderScp03Tabs(tabBar, tabBody);
  }

  async function readSelectedForTab(tab, path, previewEl) {
    previewEl.innerHTML = '<p class="loading">reading ' + escapeHtml(path) + "…</p>";
    try {
      var resp = await apiFetch("/api/actions/scp03.read_selected/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: {
            session_id: tab.sessionId,
            path: path,
          },
        }),
      });
      previewEl.innerHTML = "";
      if (!resp.ok) {
        previewEl.appendChild(renderErrorBlock(resp.error || "read failed"));
        return;
      }
      tab.previewCache = resp.data || {};
      renderFcpResult(resp.data || {}, previewEl);
    } catch (err) {
      previewEl.innerHTML = "";
      previewEl.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  // -- Scan rendering (shared across tabs) --------------------------------

  function renderScanResult(data, container) {
    // Back-compat entry point if scp03.scan is ever triggered outside the
    // workbench (e.g. from a legacy action card). Mirror the old UX.
    commandState.scp03Session = data.session_id || null;

    var header = document.createElement("div");
    header.className = "cc-scan-header";
    header.innerHTML = '<span class="cc-chip">reader: ' + escapeHtml(data.reader_name || "(default)") + '</span>'
      + '<span class="cc-chip">atr: ' + escapeHtml(data.atr_hex || "(none)") + '</span>'
      + '<span class="cc-chip">session: <code>' + escapeHtml(data.session_id || "") + '</code></span>';
    container.appendChild(header);

    var layout = document.createElement("div");
    layout.className = "cc-scan-layout";
    var tree = document.createElement("div");
    tree.className = "cc-tree";
    installMaximizable(tree);
    tree.appendChild(renderTreeNodes(data.tree || []));
    layout.appendChild(tree);
    var preview = document.createElement("div");
    preview.className = "cc-scan-preview";
    installMaximizable(preview);
    preview.innerHTML = '<p class="hint">Click a node to SELECT it and read its FCP + body.</p>';
    layout.appendChild(preview);
    container.appendChild(layout);

    tree.addEventListener("click", function (event) {
      var row = event.target.closest(".cc-tree-row");
      if (!row) return;
      var path = row.getAttribute("data-path");
      if (!path) return;
      Array.from(tree.querySelectorAll(".cc-tree-row.active")).forEach(function (el) {
        el.classList.remove("active");
      });
      row.classList.add("active");
      var pseudoTab = { sessionId: commandState.scp03Session };
      readSelectedForTab(pseudoTab, path, preview);
    });
  }

  function renderTreeNodes(nodes) {
    var list = document.createElement("ul");
    list.className = "cc-tree-list";
    nodes.forEach(function (node) {
      var li = document.createElement("li");
      var row = document.createElement("div");
      row.className = "cc-tree-row";
      row.setAttribute("data-path", node.path || node.idx);
      var icon = document.createElement("span");
      icon.className = "cc-tree-icon";
      icon.textContent = node.name === "MF" ? "MF" : (node.name && node.name.startsWith("ADF") ? "ADF" : "EF");
      var name = document.createElement("span");
      name.className = "cc-tree-name";
      name.textContent = node.display_name || node.name;
      var fid = document.createElement("span");
      fid.className = "cc-tree-fid";
      fid.textContent = node.fid || "";
      row.appendChild(icon);
      row.appendChild(name);
      row.appendChild(fid);
      li.appendChild(row);
      if (node.children && node.children.length > 0) {
        li.appendChild(renderTreeNodes(node.children));
      }
      list.appendChild(li);
    });
    return list;
  }

  function renderFcpResult(data, container) {
    if (!data.selected) {
      container.appendChild(renderErrorBlock("SELECT failed for " + (data.path || "?")));
      if (data.select_trace) {
        var trace = document.createElement("pre");
        trace.className = "cc-json";
        trace.textContent = data.select_trace;
        container.appendChild(trace);
      }
      return;
    }
    var wrap = document.createElement("div");
    wrap.className = "cc-fcp-wrap";
    var header = document.createElement("div");
    header.className = "cc-fcp-header";
    header.innerHTML = '<span class="cc-chip">path: <code>' + escapeHtml(data.path || "") + '</code></span>'
      + '<span class="cc-chip">fid: <code>' + escapeHtml(data.fid || "") + '</code></span>';
    wrap.appendChild(header);

    var fcp = data.fcp || {};
    var fcpKeys = Object.keys(fcp);
    if (fcpKeys.length > 0) {
      var fcpBlock = document.createElement("div");
      fcpBlock.className = "cc-fcp-block";
      var h4 = document.createElement("h4");
      h4.textContent = "FCP";
      fcpBlock.appendChild(h4);
      var dl = document.createElement("dl");
      fcpKeys.forEach(function (key) {
        var dt = document.createElement("dt");
        dt.textContent = key;
        var dd = document.createElement("dd");
        var value = fcp[key];
        if (value !== null && typeof value === "object") {
          dd.textContent = JSON.stringify(value);
        } else {
          dd.textContent = value === null || value === undefined ? "" : String(value);
        }
        dl.appendChild(dt);
        dl.appendChild(dd);
      });
      fcpBlock.appendChild(dl);
      wrap.appendChild(fcpBlock);
    }

    var payload = data.data || {};
    var h4body = document.createElement("h4");
    h4body.textContent = "Body — " + (payload.kind || "?");
    wrap.appendChild(h4body);

    if (payload.kind === "none") {
      var note = document.createElement("p");
      note.className = "hint";
      note.textContent = payload.note || "No body.";
      wrap.appendChild(note);
    } else if (payload.kind === "transparent") {
      wrap.appendChild(renderTransparentPayload(payload));
    } else if (payload.kind === "records") {
      wrap.appendChild(renderRecordsPayload(payload));
    } else {
      // Unknown kind — render the raw payload for transparency.
      wrap.appendChild(renderJsonBlock(payload));
    }
    container.appendChild(wrap);
  }

  function renderTransparentPayload(payload) {
    var box = document.createElement("div");
    box.className = "cc-payload cc-payload-transparent";
    var sw = document.createElement("p");
    sw.className = "cc-sw";
    sw.innerHTML = "SW: <code>" + escapeHtml(payload.sw || "") + "</code> · length "
      + String(payload.length || 0);
    box.appendChild(sw);
    if (payload.decoded) {
      box.appendChild(renderDecodedBlock(payload.decoded));
    }
    if (payload.hex) {
      box.appendChild(renderHexBlock(payload.hex));
    }
    return box;
  }

  function renderRecordsPayload(payload) {
    var box = document.createElement("div");
    box.className = "cc-payload cc-payload-records";
    var meta = document.createElement("p");
    meta.className = "cc-records-meta";
    var bits = [];
    bits.push("records: " + (payload.record_count || 0));
    bits.push("non-empty: " + (payload.non_empty_count || 0));
    bits.push("rec_len: " + (payload.rec_len || 0));
    bits.push("stop: " + (payload.stop_reason || "end"));
    meta.textContent = bits.join(" · ");
    box.appendChild(meta);

    var records = payload.records || [];
    if (records.length === 0) {
      var none = document.createElement("p");
      none.className = "hint";
      none.textContent = "(no records)";
      box.appendChild(none);
      return box;
    }
    var list = document.createElement("div");
    list.className = "cc-records";
    records.forEach(function (rec) {
      list.appendChild(renderSingleRecord(rec));
    });
    box.appendChild(list);
    if (payload.note) {
      var noteEl = document.createElement("p");
      noteEl.className = "hint";
      noteEl.textContent = payload.note;
      box.appendChild(noteEl);
    }
    return box;
  }

  function renderSingleRecord(rec) {
    var card = document.createElement("details");
    card.className = "cc-record" + (rec.empty ? " cc-record--empty" : "");
    installMaximizable(card);
    // Default: auto-open the first few non-empty records for fast scan.
    if (!rec.empty && rec.record_number <= 3) {
      card.open = true;
    }
    var sum = document.createElement("summary");
    sum.className = "cc-record-head";
    var num = document.createElement("span");
    num.className = "cc-record-num";
    num.textContent = "#" + (rec.record_number || 0);
    sum.appendChild(num);
    var sw = document.createElement("span");
    sw.className = "cc-record-sw";
    sw.textContent = "SW " + (rec.sw || "----");
    sum.appendChild(sw);
    var len = document.createElement("span");
    len.className = "cc-record-len";
    len.textContent = (rec.length || 0) + " B";
    sum.appendChild(len);
    if (rec.empty) {
      var emptyBadge = document.createElement("span");
      emptyBadge.className = "cc-record-empty-badge";
      emptyBadge.textContent = "empty";
      sum.appendChild(emptyBadge);
    }
    card.appendChild(sum);

    if (rec.decoded) {
      card.appendChild(renderDecodedBlock(rec.decoded));
    }
    if (rec.hex) {
      card.appendChild(renderHexBlock(rec.hex));
    }
    return card;
  }

  function renderDecodedBlock(decoded) {
    var wrap = document.createElement("div");
    wrap.className = "cc-decoded";
    var h = document.createElement("div");
    h.className = "cc-decoded-head";
    h.textContent = "decoded";
    wrap.appendChild(h);
    var body = document.createElement("dl");
    body.className = "cc-decoded-body";
    var entries = decoded && typeof decoded === "object" && !Array.isArray(decoded)
      ? Object.entries(decoded)
      : [["value", decoded]];
    entries.forEach(function (pair) {
      var dt = document.createElement("dt");
      dt.textContent = String(pair[0]);
      var dd = document.createElement("dd");
      var v = pair[1];
      if (v !== null && typeof v === "object") {
        var pre = document.createElement("pre");
        pre.className = "cc-decoded-json";
        try {
          pre.textContent = JSON.stringify(v, null, 2);
        } catch (_err) {
          pre.textContent = String(v);
        }
        dd.appendChild(pre);
      } else {
        dd.textContent = v === null || v === undefined ? "" : String(v);
      }
      body.appendChild(dt);
      body.appendChild(dd);
    });
    wrap.appendChild(body);
    return wrap;
  }

  // -- Maximize-on-dblclick (works on any .cc-action-card or opted-in box)

  var maxState = {
    active: null,
    previousParent: null,
    previousNextSibling: null,
    backdrop: null,
    keyHandler: null,
  };

  function installMaximizable(el) {
    if (!el || el.__ccMaxBound) return;
    el.__ccMaxBound = true;
    el.addEventListener("dblclick", function (event) {
      // Only trigger for non-interactive targets (skip form fields etc.).
      var target = event.target;
      if (target) {
        var tag = (target.tagName || "").toLowerCase();
        if (["input", "textarea", "select", "button", "a", "code"].indexOf(tag) !== -1) {
          return;
        }
      }
      event.preventDefault();
      event.stopPropagation();
      toggleMaximize(el);
    });
  }

  function toggleMaximize(el) {
    if (maxState.active === el) {
      restoreMaximized();
      return;
    }
    if (maxState.active) {
      restoreMaximized();
    }
    enterMaximized(el);
  }

  function enterMaximized(el) {
    var backdrop = document.createElement("div");
    backdrop.className = "cc-max-backdrop";
    backdrop.addEventListener("click", function (event) {
      if (event.target === backdrop) {
        restoreMaximized();
      }
    });

    var shell = document.createElement("div");
    shell.className = "cc-max-shell";

    var bar = document.createElement("div");
    bar.className = "cc-max-bar";
    var hint = document.createElement("span");
    hint.className = "cc-max-hint";
    hint.textContent = "double-click or Esc to restore";
    bar.appendChild(hint);
    var closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "btn";
    closeBtn.textContent = "Restore";
    closeBtn.addEventListener("click", function () {
      restoreMaximized();
    });
    bar.appendChild(closeBtn);
    shell.appendChild(bar);

    maxState.previousParent = el.parentNode;
    maxState.previousNextSibling = el.nextSibling;
    maxState.active = el;
    maxState.backdrop = backdrop;

    el.classList.add("cc-max-mounted");
    shell.appendChild(el);
    backdrop.appendChild(shell);
    document.body.appendChild(backdrop);

    maxState.keyHandler = function (event) {
      if (event.key === "Escape") {
        restoreMaximized();
      }
    };
    document.addEventListener("keydown", maxState.keyHandler);
  }

  function restoreMaximized() {
    var el = maxState.active;
    var backdrop = maxState.backdrop;
    if (el && maxState.previousParent) {
      el.classList.remove("cc-max-mounted");
      if (maxState.previousNextSibling && maxState.previousNextSibling.parentNode === maxState.previousParent) {
        maxState.previousParent.insertBefore(el, maxState.previousNextSibling);
      } else {
        maxState.previousParent.appendChild(el);
      }
    }
    if (backdrop && backdrop.parentNode) {
      backdrop.parentNode.removeChild(backdrop);
    }
    if (maxState.keyHandler) {
      document.removeEventListener("keydown", maxState.keyHandler);
    }
    maxState.active = null;
    maxState.previousParent = null;
    maxState.previousNextSibling = null;
    maxState.backdrop = null;
    maxState.keyHandler = null;
  }

  // -- Log bus (G-1) -------------------------------------------------------
  //
  // Cross-component event bus. Action runs (sync + streaming), live-reader
  // probes, and any future panel can publish rows here without knowing
  // anything about the bottom-dock UI. The dock subscribes once and
  // renders. Tabs map level → bucket: info/done/debug → messages,
  // warn → warnings, error → errors, apdu → apdu.

  var logBus = (function () {
    var MAX_PER_BUCKET = 500;
    var subscribers = [];
    var rows = {
      messages: [],
      warnings: [],
      errors: [],
      apdu: [],
    };
    var nextId = 1;

    function bucketFor(level) {
      var key = String(level || "info").toLowerCase();
      if (key === "warn" || key === "warning") return "warnings";
      if (key === "error" || key === "fatal") return "errors";
      if (key === "apdu" || key === "trace") return "apdu";
      return "messages";
    }

    function emit(entry) {
      var ts = entry && entry.ts ? entry.ts : new Date();
      var row = {
        id: nextId++,
        ts: ts,
        level: String((entry && entry.level) || "info"),
        source: String((entry && entry.source) || "system"),
        message: String((entry && entry.message) || ""),
        data: entry && entry.data,
      };
      var bucket = bucketFor(row.level);
      rows[bucket].push(row);
      if (rows[bucket].length > MAX_PER_BUCKET) {
        rows[bucket].shift();
      }
      subscribers.forEach(function (fn) {
        try {
          fn({ type: "append", bucket: bucket, row: row });
        } catch (_err) { /* never let a broken listener block the bus */ }
      });
      try { setStatusActivity(formatTime(row.ts)); } catch (_err) {}
    }

    function clear(bucket) {
      if (bucket && rows[bucket]) {
        rows[bucket] = [];
      } else {
        rows.messages = [];
        rows.warnings = [];
        rows.errors = [];
        rows.apdu = [];
      }
      subscribers.forEach(function (fn) {
        try { fn({ type: "clear", bucket: bucket || null }); } catch (_err) {}
      });
    }

    function snapshot(bucket) {
      return rows[bucket] ? rows[bucket].slice() : [];
    }

    function counts() {
      return {
        messages: rows.messages.length,
        warnings: rows.warnings.length,
        errors: rows.errors.length,
        apdu: rows.apdu.length,
      };
    }

    function subscribe(fn) {
      subscribers.push(fn);
      return function unsubscribe() {
        var i = subscribers.indexOf(fn);
        if (i >= 0) subscribers.splice(i, 1);
      };
    }

    return {
      emit: emit,
      clear: clear,
      snapshot: snapshot,
      counts: counts,
      subscribe: subscribe,
      bucketFor: bucketFor,
    };
  })();

  function formatTime(date) {
    var d = (date instanceof Date) ? date : new Date(date);
    var hh = String(d.getHours()).padStart(2, "0");
    var mm = String(d.getMinutes()).padStart(2, "0");
    var ss = String(d.getSeconds()).padStart(2, "0");
    return hh + ":" + mm + ":" + ss;
  }

  // Expose for tests / future modules. Keep it under a namespaced key so
  // we don't pollute the global object.
  window.YggdraSimLogBus = logBus;

  // -- Reader pane (G-1) ---------------------------------------------------

  var readerStore = {
    readers: [],
    selected: null,   // reader name string, or null
    filter: "",
    lastRefresh: 0,
  };

  function setSelectedReader(name) {
    readerStore.selected = name || null;
    document.querySelectorAll(".reader-row").forEach(function (row) {
      var rowName = row.getAttribute("data-reader-name") || "";
      row.classList.toggle("is-selected", rowName === readerStore.selected);
    });
    if (name) {
      logBus.emit({
        level: "info",
        source: "readers",
        message: "selected reader: " + name,
      });
    }
  }

  function getSelectedReader() {
    return readerStore.selected;
  }

  function readerStatusToDot(reader) {
    var atr = String(reader && reader.atr_hex || "").trim();
    var status = String(reader && reader.status || "").toLowerCase();
    if (status.indexOf("error") >= 0 || status.indexOf("fail") >= 0) {
      return "error";
    }
    if (atr.length > 0) return "card";
    if (status.indexOf("no card") >= 0 || status.indexOf("empty") >= 0) {
      return "empty";
    }
    return "unknown";
  }

  function renderReaderPane() {
    var ul = $("reader-pane-list");
    if (!ul) return;
    var note = $("reader-pane-note");
    var rows = readerStore.readers || [];
    var needle = String(readerStore.filter || "").toLowerCase();
    if (needle.length > 0) {
      rows = rows.filter(function (r) {
        return String(r.name || "").toLowerCase().indexOf(needle) >= 0;
      });
    }

    ul.innerHTML = "";
    if (rows.length === 0) {
      var empty = document.createElement("li");
      empty.className = "reader-empty";
      if (readerStore.lastRefresh === 0) {
        empty.textContent = "click ↻ to enumerate.";
      } else if (needle.length > 0) {
        empty.textContent = "no readers match the filter.";
      } else {
        empty.textContent = "no readers detected.";
      }
      ul.appendChild(empty);
    } else {
      rows.forEach(function (reader) {
        var li = document.createElement("li");
        li.className = "reader-row";
        li.setAttribute("data-reader-name", reader.name || "");
        if (reader.name === readerStore.selected) {
          li.classList.add("is-selected");
        }
        var dotKind = readerStatusToDot(reader);
        var dot = document.createElement("span");
        dot.className = "reader-row-dot reader-row-dot--" + dotKind;
        dot.title = "card-state: " + dotKind;
        var body = document.createElement("span");
        body.className = "reader-row-body";
        var name = document.createElement("span");
        name.className = "reader-row-name";
        name.textContent = String(reader.name || "(unnamed)");
        var sub = document.createElement("span");
        sub.className = "reader-row-sub";
        if (reader.atr_hex && String(reader.atr_hex).length > 0) {
          sub.textContent = "ATR " + String(reader.atr_hex);
        } else {
          sub.textContent = String(reader.status || "");
        }
        body.appendChild(name);
        body.appendChild(sub);
        li.appendChild(dot);
        li.appendChild(body);
        li.addEventListener("click", function () {
          setSelectedReader(reader.name || "");
        });
        li.addEventListener("dblclick", function () {
          if (!reader.name) return;
          setSelectedReader(reader.name);
          scp03StartSessionForReader(reader.name);
        });
        li.addEventListener("contextmenu", function (event) {
          event.preventDefault();
          setSelectedReader(reader.name || "");
          showReaderContextMenu(reader, event.clientX, event.clientY);
        });
        ul.appendChild(li);
      });
    }

    if (note) {
      if (readerStore.lastRefresh === 0) {
        note.textContent = "";
        note.classList.remove("is-error");
      } else {
        var total = (readerStore.readers || []).length;
        note.classList.remove("is-error");
        note.textContent = total + " reader(s) total · last probe " +
          formatTime(new Date(readerStore.lastRefresh));
      }
    }
    setStatusReaders((readerStore.readers || []).length);
  }

  async function refreshReaderPane() {
    var btn = $("reader-pane-refresh");
    if (btn) btn.classList.add("is-spinning");
    var note = $("reader-pane-note");
    if (note) {
      note.classList.remove("is-error");
      note.textContent = "probing…";
    }
    try {
      var data = await apiFetch("/api/live/readers");
      readerStore.readers = (data && data.readers) || [];
      readerStore.lastRefresh = Date.now();
      logBus.emit({
        level: "info",
        source: "readers",
        message:
          "enumerated " + readerStore.readers.length + " reader(s) (backend: " +
          String(data && data.backend || "?") + ").",
      });
      renderReaderPane();
    } catch (err) {
      logBus.emit({
        level: "error",
        source: "readers",
        message: "reader probe failed: " + (err && err.message || err),
      });
      if (note) {
        note.classList.add("is-error");
        note.textContent = "probe failed: " + (err && err.message || err);
      }
    } finally {
      if (btn) btn.classList.remove("is-spinning");
    }
  }

  function wireReaderPane() {
    var btn = $("reader-pane-refresh");
    if (btn) btn.addEventListener("click", refreshReaderPane);
    var input = $("reader-pane-filter");
    if (input) {
      input.addEventListener("input", function (event) {
        readerStore.filter = String(event.target.value || "");
        renderReaderPane();
      });
    }
    renderReaderPane();
  }

  // Expose for action forms (G-2 uses this to default the reader
  // dropdown to the sidebar selection).
  window.YggdraSimReaderStore = {
    getSelected: getSelectedReader,
    setSelected: setSelectedReader,
    snapshot: function () { return (readerStore.readers || []).slice(); },
    refresh: refreshReaderPane,
  };

  // -- Reader context menu (G-3) ------------------------------------------

  var contextMenuState = { open: false, root: null, dismiss: null };

  function ensureContextMenuRoot() {
    if (contextMenuState.root) return contextMenuState.root;
    var menu = document.createElement("div");
    menu.className = "ctx-menu";
    menu.setAttribute("role", "menu");
    document.body.appendChild(menu);
    contextMenuState.root = menu;
    return menu;
  }

  function hideContextMenu() {
    if (contextMenuState.root) {
      contextMenuState.root.classList.remove("is-open");
      contextMenuState.root.innerHTML = "";
    }
    if (contextMenuState.dismiss) {
      document.removeEventListener("click", contextMenuState.dismiss, true);
      document.removeEventListener("keydown", contextMenuState.dismiss, true);
      contextMenuState.dismiss = null;
    }
    contextMenuState.open = false;
  }

  function positionContextMenu(menu, x, y) {
    menu.style.visibility = "hidden";
    menu.classList.add("is-open");
    var rect = menu.getBoundingClientRect();
    var viewportW = window.innerWidth;
    var viewportH = window.innerHeight;
    var px = x;
    var py = y;
    if (px + rect.width > viewportW - 4) {
      px = Math.max(4, viewportW - rect.width - 4);
    }
    if (py + rect.height > viewportH - 4) {
      py = Math.max(4, viewportH - rect.height - 4);
    }
    menu.style.left = px + "px";
    menu.style.top = py + "px";
    menu.style.visibility = "visible";
  }

  function buildContextMenuItem(spec) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ctx-menu-item" + (spec.danger ? " ctx-menu-item--danger" : "");
    btn.setAttribute("role", "menuitem");
    if (spec.disabled) btn.disabled = true;
    var icon = document.createElement("span");
    icon.className = "ctx-menu-icon";
    icon.textContent = spec.icon || "·";
    var label = document.createElement("span");
    label.className = "ctx-menu-label";
    label.textContent = spec.label || "";
    btn.appendChild(icon);
    btn.appendChild(label);
    btn.addEventListener("click", function () {
      hideContextMenu();
      if (typeof spec.onClick === "function") spec.onClick();
    });
    return btn;
  }

  function showContextMenu(items, x, y) {
    var menu = ensureContextMenuRoot();
    menu.innerHTML = "";
    items.forEach(function (item) {
      if (item && item.divider) {
        var sep = document.createElement("div");
        sep.className = "ctx-menu-sep";
        menu.appendChild(sep);
      } else if (item) {
        menu.appendChild(buildContextMenuItem(item));
      }
    });
    positionContextMenu(menu, x, y);
    contextMenuState.open = true;
    var dismiss = function (event) {
      if (event.type === "keydown") {
        if (event.key === "Escape") hideContextMenu();
        return;
      }
      // Click outside the menu = dismiss.
      if (menu.contains(event.target)) return;
      hideContextMenu();
    };
    contextMenuState.dismiss = dismiss;
    setTimeout(function () {
      document.addEventListener("click", dismiss, true);
      document.addEventListener("keydown", dismiss, true);
    }, 0);
  }

  function showReaderContextMenu(reader, x, y) {
    var name = reader && reader.name || "";
    var atr = reader && reader.atr_hex || "";
    var items = [
      {
        icon: "\u21AA",
        label: "Open SCP03 session",
        onClick: function () { scp03StartSessionForReader(name); },
        disabled: name.length === 0,
      },
      {
        icon: "\u21BB",
        label: "Refresh ATR",
        onClick: function () { refreshSingleReaderAtr(name); },
        disabled: name.length === 0,
      },
      { divider: true },
      {
        icon: "\u2398",
        label: atr ? "Copy ATR" : "Copy reader name",
        onClick: function () { copyToClipboardSafe(atr || name); },
      },
    ];
    showContextMenu(items, x, y);
  }

  function copyToClipboardSafe(text) {
    var value = String(text || "");
    if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(function () {
        logBus.emit({ level: "info", source: "readers", message: "copied: " + value });
      }, function () {
        logBus.emit({ level: "warn", source: "readers", message: "clipboard write rejected." });
      });
      return;
    }
    try {
      var ta = document.createElement("textarea");
      ta.value = value;
      ta.style.position = "fixed";
      ta.style.left = "-1000px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      logBus.emit({ level: "info", source: "readers", message: "copied: " + value });
    } catch (_err) {
      logBus.emit({ level: "warn", source: "readers", message: "clipboard fallback failed." });
    }
  }

  async function refreshSingleReaderAtr(readerName) {
    if (!readerName) return;
    logBus.emit({ level: "info", source: "readers", message: "ATR probe → " + readerName });
    try {
      var resp = await apiFetch("/api/live/atr", {
        method: "POST",
        body: JSON.stringify({ reader: readerName }),
      });
      // Patch the cached reader entry so the dot/sub line stays fresh.
      (readerStore.readers || []).forEach(function (r) {
        if (r.name === readerName) {
          r.atr_hex = resp.atr_hex || "";
          r.status = resp.status || r.status;
        }
      });
      renderReaderPane();
      logBus.emit({
        level: "info",
        source: "readers",
        message: readerName + " · ATR " + (resp.atr_hex || "(none)") +
          " · status " + (resp.status || "?"),
      });
    } catch (err) {
      logBus.emit({
        level: "error",
        source: "readers",
        message: "ATR probe failed for " + readerName + ": " + (err && err.message || err),
      });
    }
  }

  // -- Auto-start an SCP03 session in a workbench tab (G-3) ---------------

  async function scp03StartSessionForReader(readerName) {
    var safeReader = String(readerName || "").trim();
    if (safeReader.length === 0) return;
    openCommandSubsystem("SCP03");

    var wb = commandState.scp03Workbench;
    var tab = null;
    // Reuse an empty tab if one exists, otherwise spawn a new one. Never
    // hijack a tab that already holds a different open session.
    for (var i = 0; i < wb.tabs.length; i++) {
      if (!wb.tabs[i].sessionId) { tab = wb.tabs[i]; break; }
    }
    if (!tab) {
      tab = scp03CreateEmptyTab();
      wb.tabs.push(tab);
    }
    wb.activeTabId = tab.id;
    tab.readerName = safeReader;
    tab.status = "scanning";
    tab.error = null;

    var tabBar = document.querySelector(".cc-wb-tabs");
    var tabBody = document.querySelector(".cc-wb-body");
    if (tabBar && tabBody) renderScp03Tabs(tabBar, tabBody);

    logBus.emit({
      level: "info",
      source: "scp03.scan",
      message: "auto-scan → " + safeReader,
    });
    try {
      var resp = await apiFetch("/api/actions/scp03.scan/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { reader: safeReader } }),
      });
      if (!resp.ok) {
        tab.status = "error";
        tab.error = resp.error || "scan failed";
        logBus.emit({ level: "error", source: "scp03.scan", message: tab.error });
      } else {
        var data = resp.data || {};
        tab.sessionId = data.session_id || null;
        tab.readerName = data.reader_name || safeReader;
        tab.atrHex = data.atr_hex || "";
        tab.scanData = data;
        tab.status = "open";
        tab.error = null;
        commandState.scp03Session = tab.sessionId;
        logBus.emit({
          level: "info",
          source: "scp03.scan",
          message: "session " + (tab.sessionId || "?").substring(0, 8) +
            " open on " + tab.readerName,
        });
      }
    } catch (err) {
      tab.status = "error";
      tab.error = String(err && err.message || err);
      logBus.emit({ level: "error", source: "scp03.scan", message: tab.error });
    }
    var tabBarFinal = document.querySelector(".cc-wb-tabs");
    var tabBodyFinal = document.querySelector(".cc-wb-body");
    if (tabBarFinal && tabBodyFinal) renderScp03Tabs(tabBarFinal, tabBodyFinal);
  }

  // -- Bottom log dock (G-1) ----------------------------------------------

  var logDockState = {
    activeBucket: "messages",
    collapsed: false,
  };

  function applyLogCounts(counts) {
    ["messages", "warnings", "errors", "apdu"].forEach(function (bucket) {
      var n = counts[bucket] || 0;
      setText("log-count-" + bucket, String(n));
      var tab = document.querySelector(
        ".log-dock-tab[data-log-tab=\"" + bucket + "\"]"
      );
      if (tab) {
        tab.classList.toggle("has-items", n > 0);
      }
      var empty = $("log-empty-" + bucket);
      if (empty) empty.classList.toggle("is-hidden", n > 0);
    });
  }

  // A handful of action streams emit JSON-dump messages tens of KB
  // wide (e.g. raw FCP TLV trees, bulk profile snapshots). Stuffing
  // those whole into the dock both balloons memory and makes the
  // panel unresponsive — operators have to scroll a single row
  // forever. Truncate aggressively; the full payload is still in the
  // server log if a deeper dive is needed.
  var LOG_DOCK_MAX_MSG_CHARS = 2048;

  function _truncateDockMessage(text) {
    var s = String(text == null ? "" : text);
    if (s.length <= LOG_DOCK_MAX_MSG_CHARS) return s;
    var keep = LOG_DOCK_MAX_MSG_CHARS - 32;
    return s.slice(0, keep) + "… [+" + (s.length - keep) + " chars truncated]";
  }

  function appendLogDockRow(bucket, row) {
    var host = $("log-panel-" + bucket);
    if (!host) return;
    var el = document.createElement("div");
    el.className = "log-dock-row log-dock-row--" + String(row.level || "info").toLowerCase();
    var ts = document.createElement("span");
    ts.className = "log-dock-row-ts";
    ts.textContent = formatTime(row.ts);
    var src = document.createElement("span");
    src.className = "log-dock-row-src";
    src.textContent = row.source || "";
    var msg = document.createElement("span");
    msg.className = "log-dock-row-msg";
    msg.textContent = _truncateDockMessage(row.message);
    el.appendChild(ts);
    el.appendChild(src);
    el.appendChild(msg);
    host.appendChild(el);
    // Cap DOM at 500 nodes per bucket — bus already trims past that.
    while (host.childElementCount > 500) {
      host.removeChild(host.firstChild);
    }
    host.scrollTop = host.scrollHeight;
  }

  function clearLogDockBucket(bucket) {
    if (bucket) {
      var host = $("log-panel-" + bucket);
      if (host) host.innerHTML = "";
    } else {
      ["messages", "warnings", "errors", "apdu"].forEach(function (b) {
        var host = $("log-panel-" + b);
        if (host) host.innerHTML = "";
      });
    }
  }

  function activateLogTab(bucket) {
    logDockState.activeBucket = bucket;
    document.querySelectorAll(".log-dock-tab").forEach(function (tab) {
      var match = tab.getAttribute("data-log-tab") === bucket;
      tab.classList.toggle("is-active", match);
      tab.setAttribute("aria-selected", match ? "true" : "false");
    });
    document.querySelectorAll(".log-dock-panel").forEach(function (panel) {
      var match = panel.getAttribute("data-log-panel") === bucket;
      panel.classList.toggle("is-active", match);
    });
  }

  function setLogDockCollapsed(flag) {
    logDockState.collapsed = Boolean(flag);
    var shell = $("app");
    if (shell) {
      shell.setAttribute(
        "data-log-collapsed",
        logDockState.collapsed ? "true" : "false"
      );
    }
  }

  function wireLogDock() {
    document.querySelectorAll(".log-dock-tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        var bucket = tab.getAttribute("data-log-tab");
        if (bucket) activateLogTab(bucket);
      });
    });
    var clearBtn = $("log-dock-clear");
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        logBus.clear(null);
      });
    }
    var toggleBtn = $("log-dock-toggle");
    if (toggleBtn) {
      toggleBtn.addEventListener("click", function () {
        setLogDockCollapsed(!logDockState.collapsed);
      });
    }
    logBus.subscribe(function (event) {
      if (event.type === "append") {
        appendLogDockRow(event.bucket, event.row);
      } else if (event.type === "clear") {
        clearLogDockBucket(event.bucket);
      }
      applyLogCounts(logBus.counts());
    });
    applyLogCounts(logBus.counts());
    activateLogTab(logDockState.activeBucket);
  }

  // -- Host shell (Advanced > Host shell) ----------------------------------
  //
  // Free-form interactive PTY backed by /api/host-shell. The capabilities
  // endpoint decides whether the panel renders or shows the disabled
  // notice. Decoded AT lines (when the operator opts in) flow on the
  // same WebSocket as JSON text frames; we keep the side panel local to
  // the view so it doesn't pollute the global log dock.

  var hostShellState = {
    term: null,
    fitAddon: null,
    socket: null,
    capability: null,
    devices: [],
    decodeEnabled: false,
    decodedRowsMax: 250,
  };

  async function loadHostShellCapabilities() {
    var enabledRoot = $("host-shell-enabled");
    var disabledRoot = $("host-shell-disabled");
    var reasonEl = $("host-shell-disabled-reason");
    if (!enabledRoot || !disabledRoot) return null;
    try {
      var data = await apiFetch("/api/host-shell/capabilities");
      hostShellState.capability = data;
      if (!data.supported || !data.enabled) {
        enabledRoot.hidden = true;
        disabledRoot.hidden = false;
        if (reasonEl && data.reason) {
          reasonEl.textContent = data.reason;
        }
        return data;
      }
      enabledRoot.hidden = false;
      disabledRoot.hidden = true;
      setText("host-shell-status", "idle · " + (data.shell || "/bin/bash"));
      return data;
    } catch (err) {
      enabledRoot.hidden = true;
      disabledRoot.hidden = false;
      if (reasonEl) {
        reasonEl.textContent = "capability probe failed: " + (err && err.message ? err.message : err);
      }
      return null;
    }
  }

  async function loadHostShellDevices() {
    var sel = $("host-shell-device");
    if (!sel) return;
    sel.innerHTML = "";
    try {
      var data = await apiFetch("/api/host-shell/devices");
      hostShellState.devices = (data && data.devices) || [];
      if (hostShellState.devices.length === 0) {
        var blank = document.createElement("option");
        blank.value = "";
        blank.textContent = "(no /dev/tty* found)";
        sel.appendChild(blank);
        return;
      }
      hostShellState.devices.forEach(function (entry) {
        var opt = document.createElement("option");
        opt.value = entry.path;
        var label = entry.path;
        if (entry.label) {
          label = label + "  ·  " + entry.label;
        }
        opt.textContent = label;
        sel.appendChild(opt);
      });
    } catch (err) {
      var failOpt = document.createElement("option");
      failOpt.value = "";
      failOpt.textContent = "(failed to enumerate)";
      sel.appendChild(failOpt);
    }
  }

  function ensureHostShellTerminal() {
    if (hostShellState.term) return hostShellState.term;
    if (typeof window.Terminal !== "function") {
      setText("host-shell-status", "xterm.js failed to load.");
      return null;
    }
    var host = $("host-shell-host");
    if (!host) return null;
    var term = new window.Terminal({
      convertEol: true,
      cursorBlink: true,
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      theme: { background: "transparent" },
      scrollback: 2000,
    });
    var FitAddonCtor = window.FitAddon && window.FitAddon.FitAddon;
    var fitAddon = FitAddonCtor ? new FitAddonCtor() : null;
    if (fitAddon) term.loadAddon(fitAddon);
    term.open(host);
    if (fitAddon) {
      try { fitAddon.fit(); } catch (_err) { /* not measured yet */ }
    }
    hostShellState.term = term;
    hostShellState.fitAddon = fitAddon;
    term.onData(function (data) {
      var sock = hostShellState.socket;
      if (sock && sock.readyState === 1) {
        sock.send(JSON.stringify({ type: "stdin", data: data }));
      }
    });
    return term;
  }

  function sendHostShellResize() {
    var term = hostShellState.term;
    var sock = hostShellState.socket;
    if (!term || !sock || sock.readyState !== 1) return;
    sock.send(JSON.stringify({
      type: "resize",
      rows: term.rows,
      cols: term.cols,
    }));
  }

  function startHostShell() {
    if (!hostShellState.capability || !hostShellState.capability.enabled) {
      setText("host-shell-status", "disabled — set YGGDRASIM_GUI_HOST_SHELL=1");
      return;
    }
    var term = ensureHostShellTerminal();
    if (!term) return;
    if (hostShellState.socket && hostShellState.socket.readyState === 1) {
      hostShellState.socket.close();
    }
    term.clear();
    term.writeln("[yggdrasim-gui] starting host shell …");

    var token = getStoredToken();
    if (!token) {
      setText("host-shell-status", "missing token — reload the GUI.");
      return;
    }

    var scheme = window.location.protocol === "https:" ? "wss" : "ws";
    var rows = term.rows || 30;
    var cols = term.cols || 120;
    var url = scheme + "://" + window.location.host + "/api/host-shell"
      + "?t=" + encodeURIComponent(token)
      + "&rows=" + rows + "&cols=" + cols;
    var sock = new WebSocket(url);
    sock.binaryType = "arraybuffer";
    hostShellState.socket = sock;

    var startBtn = $("host-shell-start");
    var stopBtn = $("host-shell-stop");
    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
    setText("host-shell-status", "connecting…");

    sock.onopen = function () {
      setText("host-shell-status", "running");
      sendHostShellResize();
      if (hostShellState.decodeEnabled) {
        sock.send(JSON.stringify({ type: "at_decode", enabled: true }));
      }
    };
    sock.onmessage = function (event) {
      if (typeof event.data === "string") {
        try {
          var msg = JSON.parse(event.data);
          if (msg && msg.event === "spawned") {
            setText("host-shell-status", "running · pid=" + msg.pid + " · " + (msg.shell || ""));
            return;
          }
          if (msg && msg.event === "exit") {
            term.writeln("\r\n[yggdrasim-gui] host shell exited.");
            setText("host-shell-status", "exited");
            return;
          }
          if (msg && msg.event === "error") {
            term.writeln("\r\n[yggdrasim-gui] error: " + msg.message);
            setText("host-shell-status", "error: " + msg.message);
            return;
          }
          if (msg && msg.event === "at_decoded") {
            appendHostShellDecoded(msg);
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
      setText("host-shell-status", "closed");
      if (startBtn) startBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      hostShellState.socket = null;
      sock.onmessage = null;
      sock.onopen = null;
      sock.onerror = null;
      sock.onclose = null;
    };
    sock.onerror = function () {
      setText("host-shell-status", "socket error");
    };
  }

  function stopHostShell() {
    if (hostShellState.socket) {
      try { hostShellState.socket.close(); } catch (_err) { /* already gone */ }
    }
  }

  function insertHostShellDevicePath() {
    var sel = $("host-shell-device");
    var path = sel ? sel.value : "";
    if (!path) {
      setText("host-shell-status", "pick a device first.");
      return;
    }
    var sock = hostShellState.socket;
    if (!sock || sock.readyState !== 1) {
      setText("host-shell-status", "start the session first.");
      return;
    }
    sock.send(JSON.stringify({ type: "stdin", data: path }));
  }

  function setHostShellDecode(enabled) {
    hostShellState.decodeEnabled = !!enabled;
    var pane = $("host-shell-decoded");
    if (pane) {
      pane.hidden = !hostShellState.decodeEnabled;
    }
    var sock = hostShellState.socket;
    if (sock && sock.readyState === 1) {
      sock.send(JSON.stringify({ type: "at_decode", enabled: hostShellState.decodeEnabled }));
    }
  }

  function appendHostShellDecoded(msg) {
    var rows = $("host-shell-decoded-rows");
    if (!rows) return;
    var row = document.createElement("div");
    row.className = "host-shell-decoded-row dir-" + (msg.direction || "?");
    var glyph = msg.direction === "tx" ? "&gt;" : (msg.direction === "rx" ? "&lt;" : "·");
    var kindLabel = (msg.kind || "").replace(/_/g, " ");
    row.innerHTML = ''
      + '<span class="host-shell-decoded-glyph">' + glyph + '</span>'
      + '<span class="host-shell-decoded-kind">' + escapeHtml(kindLabel) + '</span>'
      + '<span class="host-shell-decoded-raw">' + escapeHtml(String(msg.raw || "")) + '</span>'
      + '<pre class="host-shell-decoded-detail">' + escapeHtml(JSON.stringify(msg.decoded || {}, null, 2)) + '</pre>';
    row.addEventListener("click", function () {
      var apduHex = (msg.decoded && msg.decoded.apdu_hex) || "";
      if (apduHex && navigator.clipboard) {
        navigator.clipboard.writeText(apduHex).catch(function () { /* clipboard denied */ });
      }
    });
    rows.appendChild(row);
    while (rows.children.length > hostShellState.decodedRowsMax) {
      rows.removeChild(rows.firstChild);
    }
    rows.scrollTop = rows.scrollHeight;
  }

  function clearHostShellDecoded() {
    var rows = $("host-shell-decoded-rows");
    if (rows) rows.innerHTML = "";
  }

  function wireHostShellPanel() {
    var startBtn = $("host-shell-start");
    var stopBtn = $("host-shell-stop");
    if (!startBtn) return;
    startBtn.addEventListener("click", startHostShell);
    if (stopBtn) stopBtn.addEventListener("click", stopHostShell);

    var refreshBtn = $("host-shell-device-refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        loadHostShellDevices();
      });
    }
    var insertBtn = $("host-shell-device-insert");
    if (insertBtn) {
      insertBtn.addEventListener("click", insertHostShellDevicePath);
    }
    var decodeToggle = $("host-shell-decode-toggle");
    if (decodeToggle) {
      decodeToggle.addEventListener("change", function () {
        setHostShellDecode(decodeToggle.checked);
      });
    }
    var clearBtn = $("host-shell-decoded-clear");
    if (clearBtn) {
      clearBtn.addEventListener("click", clearHostShellDecoded);
    }

    window.addEventListener("resize", function () {
      if (hostShellState.fitAddon) {
        try { hostShellState.fitAddon.fit(); } catch (_err) { /* xterm not ready */ }
        sendHostShellResize();
      }
    });
  }

  // -- Init ----------------------------------------------------------------

  function init() {
    captureTokenFromUrl();
    wireTopbar();
    wireTerminalPanel();
    wireHostShellPanel();
    wireLiveReadersPanel();
    wireCommandCenter();
    wireReaderPane();
    wireLogDock();
    showView("overview");
    setApiBadge("unknown", "probing…");
    setStatusAction("initialising…");
    setStatusReaders("–");
    setStatusSessions("–");
    setStatusActivity("–");

    loadHealth();
    loadBackend();
    loadCommandCatalogue();
    scheduleHealthPoll();
    refreshReaderPane();
    logBus.emit({
      level: "info",
      source: "system",
      message: "GUI initialised — Command Center ready.",
    });

    document.getElementById("app").setAttribute("data-ready", "true");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
