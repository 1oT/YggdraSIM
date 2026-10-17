  // -- Plugin consoles: list, nav leaves, opening a console -------------------
  //
  // One generic view serves every console a loaded plugin registers through
  // /api/plugin-consoles. The server checks each manifest against a closed
  // shape before it is listed, and the view renders it with createElement
  // and textContent only: a plugin string is never parsed as markup and no
  // plugin code reaches the page. Each console becomes a leaf of the Plugin
  // consoles group in CC_NAV_TREE; the group exists only while a console is
  // registered, and a leaf id carries its console id. The forms and the command line are built in
  // plugin-console-forms.js, the poll, status panel and stream tables in
  // plugin-console-poll.js, the two panes and their tabs in
  // plugin-console-tabs.js, the top bar pills in plugin-console-pills.js,
  // and a run form with its credentials and runs in
  // plugin-console-runform.js, plugin-console-credentials.js and
  // plugin-console-runs.js.

  var PC_GROUP_ID = "group-plugin-consoles";
  var PC_LEAF_PREFIX = "leaf-plugin-console-";

  var pcState = {
    consoles: [],
    activeId: "",
    manifest: null,
    status: null,
    stateSignature: "",
    // The state rows on screen: their keys, joined, and their value cells, so a
    // poll that only changes values rewrites text instead of rebuilding the list.
    stateKeys: "",
    stateCells: [],
    compareSignature: "",
    // The options the console's status fills its run fields with (plugin-console-runform.js).
    choices: {},
    // Tabs (plugin-console-tabs.js): the plan, the buttons and the shown tab per pane.
    tabs: null,
    tabButtons: {},
    activeTabs: {},
    // Per stream: whether its table follows new rows (scrolled to the bottom).
    streamPinned: {},
    cursors: {},
    pollTimer: null,
    polling: false,
    pollAgain: false,
    busy: false,
    history: {},
    historyIndex: -1,
    helpFor: "",
    // Run form (plugin-console-runs.js resets these per console).
    runVariant: "",
    runActive: "",
    runViewed: "",
    runAfter: 0,
    runTick: 0,
    runTimer: null,
    runPolling: false,
    runStarting: false,
    runHistory: [],
    credentials: {},
    credentialDrafts: {},
    credentialPicks: {},
  };

  function pcApi(consoleId, suffix) {
    return "/api/plugin-consoles/" + encodeURIComponent(consoleId) + suffix;
  }

  function pcErrorText(err) {
    // apiFetch prefixes "HTTP <code> for <path>: "; the operator needs the reason.
    return String((err && err.message) || err).replace(/^HTTP \d+ for \S+: /, "");
  }

  function pcSetChip(text, stateName) {
    var chip = $("pc-chip");
    if (!chip) return;
    chip.textContent = String(text || "idle");
    chip.dataset.state = stateName || "idle";
  }

  function pcNavGroupIndex() {
    for (var i = 0; i < CC_NAV_TREE.length; i += 1) {
      if (CC_NAV_TREE[i].id === PC_GROUP_ID) {
        return i;
      }
    }
    return -1;
  }

  function pcNavGroup() {
    var found = pcNavGroupIndex();
    if (found >= 0) {
      return CC_NAV_TREE[found];
    }
    // The group is not part of the static tree: it is added before Advanced
    // once a console is registered.
    var group = {
      id: PC_GROUP_ID,
      label: "Plugin consoles",
      hint: "The consoles the loaded plugins register.",
      defaultOpen: false,
      children: [],
    };
    var at = CC_NAV_TREE.length;
    for (var j = 0; j < CC_NAV_TREE.length; j += 1) {
      if (CC_NAV_TREE[j].id === "group-advanced") {
        at = j;
        break;
      }
    }
    CC_NAV_TREE.splice(at, 0, group);
    return group;
  }

  function pcInstallNavGroup() {
    if (pcState.consoles.length === 0) {
      var index = pcNavGroupIndex();
      if (index >= 0) CC_NAV_TREE.splice(index, 1);
    } else {
      pcNavGroup().children = pcState.consoles.map(function (manifest) {
        return {
          id: PC_LEAF_PREFIX + manifest.id,
          label: manifest.title,
          inspectView: "plugin_console",
          hint: manifest.summary || manifest.title,
        };
      });
    }
    // The action catalogue renders the nav; until it lands, the group waits
    // in CC_NAV_TREE and that first render picks it up.
    if (commandState.catalogue) {
      renderCommandNav(commandState.catalogue);
      renderOverviewModuleLauncher(commandState.catalogue);
      ccHighlightLeaf(commandState.activeLeafId || "");
    }
  }

  async function loadPluginConsoles() {
    var listing = null;
    try {
      listing = await apiFetch("/api/plugin-consoles");
    } catch (err) {
      logBus.emit({ level: "warn", source: "plugin-console", message: "plugin consoles unavailable: " + pcErrorText(err) });
    }
    pcState.consoles = listing && Array.isArray(listing.consoles) ? listing.consoles : [];
    ((listing && listing.refused) || []).forEach(function (entry) {
      logBus.emit({
        level: "warn",
        source: "plugin-console",
        message: "plugin console " + String(entry.id || "(no id)") + " refused: " + String(entry.reason || ""),
      });
    });
    pcInstallNavGroup();
    pcSchedulePills(0);
    if (state.activeView === "plugin_console") {
      loadPluginConsole(commandState.activeLeafId || "");
    }
  }

  function pcConsoleIdFromLeaf(leafId) {
    var text = String(leafId || "");
    return text.indexOf(PC_LEAF_PREFIX) === 0 ? text.slice(PC_LEAF_PREFIX.length) : "";
  }

  function pcFindManifest(consoleId) {
    for (var i = 0; i < pcState.consoles.length; i += 1) {
      if (pcState.consoles[i].id === consoleId) {
        return pcState.consoles[i];
      }
    }
    return null;
  }

  function pcShowUnavailable() {
    pcStopPolling();
    var notice = $("pc-notice");
    if (notice) {
      notice.hidden = false;
      notice.textContent = "No loaded plugin offers this console. Consoles are listed when the GUI starts"
        + " with plugin loading allowed; Environment > Configuration > Plugins shows what loaded.";
    }
    var layout = $("pc-layout");
    if (layout) layout.hidden = true;
    var runs = $("pc-runs");
    if (runs) runs.hidden = true;
    pcRenderCompareManifest(null);
    pcSetChip("unavailable", "error");
  }

  function loadPluginConsole(leafId) {
    var manifest = pcFindManifest(pcConsoleIdFromLeaf(leafId) || pcState.activeId);
    if (!manifest) {
      pcShowUnavailable();
      return;
    }
    setText("crumb-subsystem", "Plugin consoles · " + manifest.title);
    if (pcState.manifest !== manifest) {
      pcStopPolling();
      pcState.activeId = manifest.id;
      pcState.manifest = manifest;
      pcState.status = null;
      pcState.stateSignature = "";
      pcState.stateKeys = "";
      pcState.stateCells = [];
      pcState.choices = {};
      pcState.streamPinned = {};
      pcState.cursors = {};
      pcState.historyIndex = -1;
      pcState.helpFor = "";
      pcRenderConsole(manifest);
    }
    pcPollSoon();
  }

  function wirePluginConsolePanel() {
    var refresh = $("pc-refresh");
    if (refresh) {
      refresh.addEventListener("click", function () { pcPollSoon(); });
    }
    pcWireForms();
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) return;
      pcSchedulePills(0);
      if (state.activeView === "plugin_console") {
        pcPollSoon();
      }
    });
  }
