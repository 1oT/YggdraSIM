  // -- Plugin consoles: the two panes and their tabs ---------------------------
  //
  // The view is two panes: controls (session, state, actions with the command
  // line, run form, credentials) and output (comparison, one tab per stream,
  // runs). A tab
  // exists only for a part the manifest declares, so a pane with one part
  // shows no tab strip and a pane with none is hidden while the other spans
  // the view. Tab labels come from the manifest or are the generic words the
  // panels already carry. The tab picked per console and pane is a per-viewer
  // convenience kept in localStorage; the view works the same without it.

  var PC_TAB_STORAGE_PREFIX = "yggdrasim:pc-tab:";
  var PC_PANES = ["controls", "output"];
  var PC_STREAM_TAB_PREFIX = "stream-";

  // Pure: the tabs of each pane for a validated manifest, in display order.
  function pcTabPlan(manifest) {
    var controls = [];
    var output = [];
    var hasActions = manifest.actions.length > 0;
    // The session panel carries the start form and the status; without a start
    // form it is still the home of the reported state unless that has a tab.
    if (manifest.start || (!manifest.state && (hasActions || Boolean(manifest.command_line) || manifest.streams.length > 0))) {
      controls.push({ id: "session", label: "Session" });
    }
    if (manifest.state) controls.push({ id: "state", label: manifest.state.title });
    if (hasActions || manifest.command_line) {
      controls.push({ id: "actions", label: hasActions ? "Actions" : "Command line" });
    }
    if (manifest.runs) controls.push({ id: "run", label: manifest.runs.labels.form });
    // Every stored credential in one place; the run form shows the ones it needs.
    if (manifest.runs && manifest.runs.credentials.length > 0) {
      controls.push({ id: "credentials", label: manifest.runs.labels.credentials });
    }
    if (manifest.compare) output.push({ id: "compare", label: manifest.compare.title });
    manifest.streams.forEach(function (stream) {
      output.push({ id: PC_STREAM_TAB_PREFIX + stream.id, label: stream.title });
    });
    if (manifest.runs) output.push({ id: "runs", label: manifest.runs.labels.history });
    return { controls: controls, output: output };
  }

  function pcTabStorageKey(consoleId, pane) {
    return PC_TAB_STORAGE_PREFIX + consoleId + ":" + pane;
  }

  function pcRememberedTab(consoleId, pane) {
    try {
      return String(window.localStorage.getItem(pcTabStorageKey(consoleId, pane)) || "");
    } catch (_err) {
      return "";
    }
  }

  function pcRememberTab(consoleId, pane, tabId) {
    try {
      window.localStorage.setItem(pcTabStorageKey(consoleId, pane), tabId);
    } catch (_err) {
      // Blocked or private storage: the pick is simply not kept.
    }
  }

  function pcRenderTabs(manifest) {
    var plan = pcTabPlan(manifest);
    pcState.tabs = plan;
    pcState.tabButtons = {};
    pcState.activeTabs = {};
    document.querySelectorAll("#pc-layout .pc-tab-panel").forEach(function (panel) {
      panel.hidden = true;
    });
    PC_PANES.forEach(function (pane) {
      var tabs = plan[pane];
      var paneEl = $("pc-pane-" + pane);
      if (paneEl) paneEl.hidden = tabs.length === 0;
      var strip = $("pc-tabs-" + pane);
      if (!strip) return;
      strip.textContent = "";
      strip.hidden = tabs.length < 2;
      tabs.forEach(function (tab) {
        var button = document.createElement("button");
        button.type = "button";
        button.className = "pc-tab";
        button.id = "pc-tabbtn-" + tab.id;
        button.setAttribute("role", "tab");
        button.setAttribute("aria-controls", "pc-tab-" + tab.id);
        button.setAttribute("aria-selected", "false");
        button.tabIndex = -1;
        button.textContent = tab.label;
        button.addEventListener("click", function () { pcSelectTab(pane, tab.id, false); });
        strip.appendChild(button);
        pcState.tabButtons[tab.id] = button;
        var panel = $("pc-tab-" + tab.id);
        if (panel) panel.setAttribute("aria-labelledby", button.id);
      });
      if (tabs.length === 0) return;
      var wanted = pcRememberedTab(manifest.id, pane);
      var known = tabs.some(function (tab) { return tab.id === wanted; });
      pcSelectTab(pane, known ? wanted : tabs[0].id, false, true);
    });
    var layout = $("pc-layout");
    if (layout) layout.dataset.single = plan.controls.length === 0 || plan.output.length === 0 ? "true" : "false";
  }

  // initial: chosen by the view, not the operator, so it is not remembered.
  function pcSelectTab(pane, tabId, focus, initial) {
    var tabs = (pcState.tabs && pcState.tabs[pane]) || [];
    tabs.forEach(function (tab) {
      var on = tab.id === tabId;
      var button = pcState.tabButtons[tab.id];
      if (button) {
        button.setAttribute("aria-selected", on ? "true" : "false");
        button.tabIndex = on ? 0 : -1;
        button.classList.toggle("is-active", on);
        if (on && focus) button.focus();
      }
      var panel = $("pc-tab-" + tab.id);
      if (panel) panel.hidden = !on;
    });
    pcState.activeTabs[pane] = tabId;
    if (!initial && pcState.activeId) pcRememberTab(pcState.activeId, pane, tabId);
    if (tabId.indexOf(PC_STREAM_TAB_PREFIX) === 0) pcStreamShown(tabId.slice(PC_STREAM_TAB_PREFIX.length));
  }

  // Arrow keys, Home and End move between the tabs of one strip (roving tabindex).
  function pcTabKeydown(pane, event) {
    var tabs = (pcState.tabs && pcState.tabs[pane]) || [];
    var current = pcState.activeTabs ? pcState.activeTabs[pane] : "";
    var at = -1;
    for (var i = 0; i < tabs.length; i += 1) {
      if (tabs[i].id === current) at = i;
    }
    var next = -1;
    if (event.key === "ArrowRight") next = (at + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (at - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    if (next < 0 || tabs.length === 0) return;
    event.preventDefault();
    pcSelectTab(pane, tabs[next].id, true);
  }

  function pcWireTabs() {
    PC_PANES.forEach(function (pane) {
      var strip = $("pc-tabs-" + pane);
      if (strip) strip.addEventListener("keydown", function (event) { pcTabKeydown(pane, event); });
    });
  }
