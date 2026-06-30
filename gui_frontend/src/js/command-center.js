// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

  // -- Command Center (R2-004 Phase C) -------------------------------------

  var commandState = {
    catalogue: null,
    activeSubsystem: null,
    scp03Session: null,
    scp03Workbench: {
      tabs: [],
      activeTabId: null,
      tabSeq: 1,
      // Scope ("all" | "filesystem" | "applications") — the left-nav
      // leaf the operator entered from. Filters the ribbon tabs and
      // hides the FS tree in Applications mode so the cognitive load
      // stays proportional to the task. Set by ``renderScp03Workbench``
      // on every paint; defaults to "all" for direct callers that
      // don't go through the nav tree.
      scope: "all",
      // Cached ``/api/live/readers`` snapshot + bookkeeping so the
      // reader sidebar can render without a round-trip on every paint.
      readers: [],
      readersLoading: false,
      readersError: null,
      readersFetchedAt: 0,
    },
    saipWorkbench: {
      packages: [],
      activePackageId: null,
      packageSeq: 1,
      packageDrawerCollapsed: false,
      // SA-G1: ribbon + top-tab shell. The ribbon is the always-visible
      // command bar that mirrors Comprion's grouped Profile Package /
      // Profile Element / File System / Variables / Validation / Help
      // groups (re-themed for our palette). The variable editor moved
      // out of the left pane into a modal launched from the ribbon, so
      // the per-pkg ``activeTopTab`` only ever toggles between the
      // three structural surfaces of the package itself.
      variableModalOpen: false,
      variableModalPackageId: null,
    },
    hilWorkbench: {
      activeTab: "dissector",
      viewMode: "context",
      armed: false,
      readerName: "",
      readerIndex: -1,
      startMode: "decoded",
      selectedFrameNumber: null,
      capturePath: "",
      captureSource: "",
      keybagPath: "",
      rows: [],
      annotations: {},
      detail: "",
      bytes: "",
      detailRanges: [],
      detailFrameNumber: 0,
      byteHighlightHoverRange: null,
      byteHighlightPinnedRange: null,
      statusText: "not started",
      errorText: "",
      actionStatusText: "",
      autoRefresh: true,
      refreshTimerId: null,
      inflight: false,
      refreshQueuedForce: false,
      refreshQueuedSelectedFrame: null,
      startInFlight: false,
      stopInFlight: false,
      cardBridgeLaunchInFlight: false,
      paused: false,
      followTail: true,
      selectionFollowsTail: true,
      rawPaused: false,
      rawRows: [],
      rawPendingRows: [],
      rawPendingDropCount: 0,
      rawUnsubscribe: null,
      rawRenderTimerId: null,
      lastRenderedRawId: 0,
      rawSnapshotSeeded: false,
      rawFrameSeen: {},
      rawClearedFrameNumber: 0,
      modemShellCommand: "",
      modemShellDefaultCommand: "",
      modemShellDefaultSource: "",
      modemShellRemoteTarget: "",
      modemShellCapability: null,
      modemShellDevices: [],
      modemShellMetadataLoading: false,
      modemShellStatusText: "idle",
      modemShellErrorText: "",
      modemShellSocket: null,
      modemShellTerm: null,
      modemShellFitAddon: null,
      modemShellRunning: false,
      packetScrollTop: 0,
      packetScrollHeight: 0,
      packetClientHeight: 0,
      packetScrollBottomGap: 0,
      lastPacketScrollAt: 0,
      packetScrollRestoring: false,
      packetSectionOpen: {},
      packetRenderPending: false,
      packetRenderTimerId: null,
      packetVirtualRenderTimerId: null,
      packetPointerActive: false,
      packetPointerId: null,
      packetPointerReleaseTimerId: null,
      packetPointerReleaseListenersInstalled: false,
      contextTree: [],
      liveBaselinePending: false,
      liveBaselineFrameNumber: 0,
      liveBaselineCaptureSize: 0,
      liveBaselineCaptureMtime: 0,
      captureSize: 0,
      captureMtime: 0,
      detailScrollTop: 0,
      detailScrollLeft: 0,
      detailSectionOpen: {},
      bytesScrollTop: 0,
      bytesScrollLeft: 0,
      lastRefreshAt: 0,
      lastStableStatusText: "",
      timerSnapshotAppliedAt: 0,
      timerSnapshotCaptureSeconds: null,
      timerSnapshotSignature: "",
      timerStatusTimerId: null,
    },
    // Top-bar reader strip. Promoted from the per-SCP03-tab sidebar to
    // a global app-level control: each detected PC/SC reader gets a
    // pill next to the YggdraSIM brand, and clicking a pill activates
    // the session bound to that reader across every subsystem. Status
    // dots are a traffic-light derived per paint from
    // ``readerBarDeriveStatus(reader)``:
    //   green  = reader has an active SCP03/HIL session, or an active
    //            reader-scoped module while the reader still has an ATR
    //   yellow = reader has a card (atr_hex non-empty) but no session
    //   red    = reader plugged in, no card, no session
    // Polling runs while the page is visible; paused when the tab is
    // hidden to save PC/SC traffic and resumed on ``visibilitychange``.
    readerBar: {
      readers: [],            // [{ name, atr_hex, status }]
      activeReader: "",       // name of the currently selected pill
      loading: false,
      error: null,
      fetchedAt: 0,
      pollTimerId: null,
      pollIntervalMs: 5000,
      bootstrapped: false,
      // ``openPopover`` is the floating connect/disconnect panel
      // anchored under whichever pill the operator most recently
      // clicked. Tracked here so a second click on the same pill
      // dismisses it (toggle) and so the 5 s reader poll can keep
      // the panel's status chip / button enable-state fresh.
      openPopover: null,
      openPopoverFor: "",
    },
    // Per-reader session context — one entry per reader pill.
    // Swapping readers saves the current context under the old
    // reader's name and restores the context for the new reader.
    // This gives each reader its own completely independent
    // "browser tab" experience across all subsystems.
    readerSessions: {},  // readerName -> { activeSubsystem, activeScope, ... }
    profileTargetCache: {},  // "subsystem\x1freader" -> [{ value, label }]
  };

  var HIL_MODEM_COMMAND_KEY = "ygg.hil.modemShellCommand";
  var HIL_MODEM_DEFAULT_COMMAND = "sudo tio /dev/ttyUSB2";
  var HIL_PACKET_FETCH_LIMIT = 5000;
  var HIL_PACKET_RENDER_LIMIT = 750;
  var HIL_PACKET_VIRTUAL_ROW_HEIGHT = 26;
  var HIL_PACKET_VIRTUAL_OVERSCAN = 16;
  var HIL_RAW_TRACE_LIMIT = 750;
  var CC_READER_SESSION_SUBSYSTEMS = {
    "eSIM Management": true,
    "SCP11 Local": true,
    "Local eIM": true,
  };
  var CC_OFFLINE_TOOLS_HIDDEN_ACTIONS = {
    "suci.status": true,
    "tool.euicc_info2.decode": true,
    "tool.saip.lint": true,
    "tool.tlv.decode": true,
  };
  var CC_GLOBAL_DEBUG_FLAG = "YGGDRASIM_GLOBAL_DEBUG";
  var CC_TRUE_ENV_FLAG_VALUES = {
    "1": true,
    true: true,
    yes: true,
    y: true,
    on: true,
    debug: true,
    verbose: true,
  };
  var ccGlobalDebugEnabled = false;
  var ccGlobalDebugRefreshPromise = null;

  function ccEnvFlagBool(value) {
    return !!CC_TRUE_ENV_FLAG_VALUES[String(value || "").trim().toLowerCase()];
  }

  function ccSetGlobalDebugFromEnvFlags(flags) {
    flags = Array.isArray(flags) ? flags : [];
    ccGlobalDebugEnabled = false;
    for (var i = 0; i < flags.length; i++) {
      var flag = flags[i] || {};
      if (flag.name === CC_GLOBAL_DEBUG_FLAG) {
        ccGlobalDebugEnabled = !!flag.is_set && ccEnvFlagBool(flag.current_value);
        return ccGlobalDebugEnabled;
      }
    }
    return false;
  }

  function ccRefreshGlobalDebugFlag() {
    if (ccGlobalDebugRefreshPromise) return ccGlobalDebugRefreshPromise;
    ccGlobalDebugRefreshPromise = apiFetch("/api/env_flags/list").then(
      function (data) {
        return ccSetGlobalDebugFromEnvFlags(data && data.flags);
      },
      function () {
        ccGlobalDebugEnabled = false;
        return false;
      }
    ).then(function (enabled) {
      ccGlobalDebugRefreshPromise = null;
      return enabled;
    });
    return ccGlobalDebugRefreshPromise;
  }

  function ccIsGlobalDebugEnabled() {
    return !!ccGlobalDebugEnabled;
  }

  function ccShouldShowStreamFrame(level) {
    if (String(level || "info").toLowerCase() !== "error") return true;
    return ccIsGlobalDebugEnabled();
  }

  function ccSubsystemRequiresReaderSession(subsystem) {
    return !!CC_READER_SESSION_SUBSYSTEMS[String(subsystem || "")];
  }

  function ccActiveReaderName() {
    var activeReader = "";
    try {
      if (commandState && commandState.readerBar) {
        activeReader = String(commandState.readerBar.activeReader || "");
      }
    } catch (_err) { /* commandState not bootstrapped */ }
    if (typeof readerBarCanonicalName === "function") {
      activeReader = readerBarCanonicalName(activeReader);
    }
    return activeReader;
  }

  function ccActionUsesReaderSession(action) {
    var subsystem = "";
    if (action && action.subsystem) {
      subsystem = action.subsystem;
    } else if (commandState && commandState.activeSubsystem) {
      subsystem = commandState.activeSubsystem;
    }
    return ccSubsystemRequiresReaderSession(subsystem);
  }

  function ccShouldHideReaderField(action, field) {
    return !!(field && field.kind === "reader" && ccActionUsesReaderSession(action));
  }

  function ccRefreshReaderSessionFormFields(readerName) {
    var name = String(readerName || "");
    document.querySelectorAll(".cc-form-row--reader-session").forEach(function (row) {
      var input = row.querySelector('input[type="hidden"]');
      if (input) input.value = name;
      var chip = row.querySelector(".cc-reader-session-chip");
      if (chip) chip.textContent = name || "No reader selected";
    });
  }

  function ccOpenInspectView(viewName, leafId) {
    if (commandState.activeSubsystem === "HIL") {
      stopHilWorkbenchRuntime();
      hilStopModemShell({ dispose: true });
    }
    commandState.activeSubsystem = null;
    commandState.activeScope = "";
    commandState.activeLeafId = leafId || "";
    showView(viewName);
    ccHighlightLeaf(leafId || "");
    setStatusAction("viewing: " + viewName);
    ccLoadStandaloneView(viewName);
  }

  function ccLoadStandaloneView(viewName) {
    if (viewName === "registry") {
      loadRegistry("");
    } else if (viewName === "backend") {
      loadBackend();
    } else if (viewName === "env_flags") {
      loadEnvFlags();
    } else if (viewName === "overview") {
      loadHealth();
      loadBackend();
      if (commandState.catalogue) renderOverviewModuleLauncher(commandState.catalogue);
    } else if (viewName === "terminal") {
      loadTerminalModules();
      var activeTab = getActiveTerminalTab();
      if (activeTab && activeTab.fitAddon) {
        setTimeout(function () {
          try { activeTab.fitAddon.fit(); } catch (_err) { /* pane not measured */ }
          sendTerminalResize(activeTab);
        }, 50);
      }
    } else if (viewName === "host_shell") {
      loadHostShellCapabilities();
      loadHostShellDevices();
    } else if (viewName === "live_readers") {
      loadLiveReaders();
    } else if (viewName === "card_bridge") {
      loadCardBridge();
    }
    if (viewName !== "card_bridge") {
      cbStopAutoRefresh();
    }
  }

  function ccSetTopbarBridgeBusy(pillId, busy) {
    var pill = $(pillId);
    if (!pill) return;
    pill.disabled = !!busy;
    if (busy) {
      pill.setAttribute("data-busy", "true");
    } else {
      pill.removeAttribute("data-busy");
    }
  }

  function ccDescribeTopbarBridgeAction(data, fallback) {
    if (typeof cbRigDescribeAction === "function") {
      return cbRigDescribeAction(data, fallback);
    }
    return (data && data.note) || fallback || "";
  }

  async function cbToggleTopbarRemoteBridge() {
    var pill = $("topbar-card-bridge");
    if (pill && pill.getAttribute("data-busy") === "true") return;
    var previousState = (typeof cbState !== "undefined" && cbState.globalState)
      || (pill && pill.getAttribute("data-state"))
      || "idle";
    var value = $("topbar-card-bridge-value");
    var previousLabel = (typeof cbState !== "undefined" && cbState.globalLabel)
      || (value && value.textContent)
      || previousState;
    var running = previousState === "running";
    ccSetTopbarBridgeBusy("topbar-card-bridge", true);
    setText("topbar-card-bridge-value", running ? "stopping" : "starting");
    try {
      var data;
      if (running) {
        if (typeof cbRigStopAllFromSavedSettings !== "function") {
          throw new Error("Remote Bridge stop helper is unavailable.");
        }
        data = await cbRigStopAllFromSavedSettings();
      } else {
        if (typeof cbRigStartAllFromSavedSettings !== "function") {
          throw new Error("Remote Bridge start helper is unavailable.");
        }
        data = await cbRigStartAllFromSavedSettings();
      }
      if (!data || data.ok === false) {
        if (typeof cbSetGlobalBridgeStatus === "function" && (!data || !data.state)) {
          cbSetGlobalBridgeStatus(previousState, previousLabel);
        }
        setStatusAction(ccDescribeTopbarBridgeAction(
          data,
          running ? "Remote Bridge stop failed." : "Remote Bridge start failed."
        ));
      }
    } catch (err) {
      if (typeof cbSetGlobalBridgeStatus === "function") {
        cbSetGlobalBridgeStatus(previousState, previousLabel);
      }
      setStatusAction(String((err && err.message) || err));
    } finally {
      ccSetTopbarBridgeBusy("topbar-card-bridge", false);
      if (typeof loadCardBridgeStatus === "function") loadCardBridgeStatus();
    }
  }

  function hilTopbarActions() {
    var cat = commandState.catalogue || {};
    var subsystems = cat.subsystems || {};
    return subsystems.HIL || [];
  }

  function hilTopbarLeaf() {
    return ccFindLeaf("leaf-adv-hil") || {
      id: "leaf-adv-hil",
      label: "HIL Bridge",
      subsystem: "HIL",
      scope: "all",
      hint: "Hardware-in-the-loop APDU relay / capture",
    };
  }

  async function hilEnsureTopbarCatalogue() {
    if (commandState.catalogue) return true;
    await loadCommandCatalogue();
    return !!commandState.catalogue;
  }

  async function hilToggleTopbarBridge() {
    var pill = $("topbar-hil-bridge");
    if (pill && pill.getAttribute("data-busy") === "true") return;
    var state = commandState.hilWorkbench;
    if (state.startInFlight || state.stopInFlight) return;
    var running = state.armed && state.startMode !== "offline";
    ccSetTopbarBridgeBusy("topbar-hil-bridge", true);
    try {
      var ready = await hilEnsureTopbarCatalogue();
      if (!ready) {
        setStatusAction("HIL Bridge actions are unavailable.");
        return;
      }
      var leaf = hilTopbarLeaf();
      openCommandSubsystem("HIL", { scope: "all", leafId: "leaf-adv-hil" });
      var container = $("cc-actions");
      var actions = hilTopbarActions();
      if (running) {
        await hilStopLiveSession(actions, container, leaf);
      } else {
        await hilStartLiveSession(actions, container, leaf);
      }
    } finally {
      ccSetTopbarBridgeBusy("topbar-hil-bridge", false);
      hilSyncCommandCenterTraceIndicators();
    }
  }

  function wireTopbarBridgeControls() {
    var hil = $("topbar-hil-bridge");
    if (hil && hil.getAttribute("data-bridge-control-wired") !== "true") {
      hil.setAttribute("data-bridge-control-wired", "true");
      hil.addEventListener("click", function (event) {
        event.preventDefault();
        hilToggleTopbarBridge();
      });
    }
    var remote = $("topbar-card-bridge");
    if (remote && remote.getAttribute("data-bridge-control-wired") !== "true") {
      remote.setAttribute("data-bridge-control-wired", "true");
      remote.addEventListener("click", function (event) {
        event.preventDefault();
        cbToggleTopbarRemoteBridge();
      });
    }
  }

  function wireCommandCenter() {
    wireTopbarBridgeControls();
    document.addEventListener("click", function (event) {
      // Ignore clicks on the group header (expand/collapse) — that
      // has its own listener. We only care about leaf clicks here.
      if (event.target.closest(".cc-nav-group-header")) return;
      var nav = event.target.closest("#command-center-nav .subsystem-entry");
      if (!nav) return;
      var inspectView = nav.getAttribute("data-cc-view");
      if (inspectView) {
        ccOpenInspectView(inspectView, nav.getAttribute("data-cc-leaf-id") || "");
        return;
      }
      var subsystem = nav.getAttribute("data-cc-subsystem");
      if (!subsystem) return;
      var leafId = nav.getAttribute("data-cc-leaf-id") || "";
      var scope = nav.getAttribute("data-cc-scope") || "";
      openCommandSubsystem(subsystem, {
        scope: scope || "all",
        leafId: leafId,
        stub: nav.classList.contains("is-stub"),
      });
    });
  }

  // --- Top-bar reader strip (global session selector) -------------------

  function readerBarBootstrap() {
    // One-shot: wire the refresh button, install a visibilitychange
    // listener for polling pause/resume, kick off the initial fetch,
    // and start the 5 s poll loop. Idempotent — subsequent calls are
    // cheap no-ops via the ``bootstrapped`` flag so callers can invoke
    // it from wherever without checking themselves.
    var bar = commandState.readerBar;
    if (bar.bootstrapped) return;
    bar.bootstrapped = true;

    var refresh = $("topbar-readers-refresh");
    if (refresh) {
      refresh.addEventListener("click", function () {
        readerBarRefresh({ manual: true });
      });
    }

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        readerBarStopPolling();
      } else {
        readerBarStartPolling();
        readerBarRefresh({ manual: false });
      }
    });

    readerBarRefresh({ manual: false });
    readerBarStartPolling();
  }

  function readerBarStartPolling() {
    var bar = commandState.readerBar;
    if (bar.pollTimerId != null) return;
    bar.pollTimerId = setInterval(function () {
      // Suppress polling while a manual refresh is in flight to avoid
      // two overlapping /api/live/readers round-trips.
      if (bar.loading) return;
      readerBarRefresh({ manual: false });
    }, bar.pollIntervalMs);
  }

  function readerBarStopPolling() {
    var bar = commandState.readerBar;
    if (bar.pollTimerId != null) {
      clearInterval(bar.pollTimerId);
      bar.pollTimerId = null;
    }
  }

  function readerBarDefaultReaderName() {
    var bar = commandState.readerBar;
    var readers = (bar && Array.isArray(bar.readers)) ? bar.readers : [];
    for (var i = 0; i < readers.length; i++) {
      var name = String(readers[i] && readers[i].name || "").trim();
      if (name && name !== "(default)") return name;
    }
    return "";
  }

  function readerBarCanonicalName(name, opts) {
    var raw = String(name || "").trim();
    var useDefaultForBlank = Boolean(opts && opts.defaultForBlank);
    if (raw === "(default)" || (useDefaultForBlank && raw.length === 0)) {
      return readerBarDefaultReaderName();
    }
    return raw;
  }

  function readerBarSetActiveReaderOnly(readerName) {
    var canonical = readerBarCanonicalName(readerName, { defaultForBlank: true });
    if (!canonical) return;
    commandState.readerBar.activeReader = canonical;
    try {
      if (typeof window.YggdraSimReaderStore !== "undefined"
          && window.YggdraSimReaderStore
          && typeof window.YggdraSimReaderStore.setSelected === "function") {
        window.YggdraSimReaderStore.setSelected(canonical, { fromReaderBar: true });
      }
    } catch (_err) { /* reader pane not loaded */ }
    ccRefreshReaderSessionFormFields(canonical);
  }

  function readerBarBoundName(tab) {
    if (!tab) return "";
    var raw = tab.readerName || tab.pendingReader || "";
    if (!raw && !tab.sessionId) return "";
    return readerBarCanonicalName(raw, { defaultForBlank: true });
  }

  function readerBarHilBoundName() {
    var hil = commandState.hilWorkbench;
    if (!hil || !hil.armed) return "";
    if (hil.readerName) {
      return readerBarCanonicalName(hil.readerName, { defaultForBlank: true });
    }
    var readerIndex = parseInt(hil.readerIndex, 10);
    if (!isNaN(readerIndex) && readerIndex >= 0) {
      return readerBarDefaultReaderName();
    }
    return "";
  }

  function readerBarReaderScopedBoundName() {
    if (!ccSubsystemRequiresReaderSession(commandState.activeSubsystem)) {
      return "";
    }
    return readerBarCanonicalName(
      commandState.readerBar && commandState.readerBar.activeReader,
      { defaultForBlank: true }
    );
  }

  function readerBarCanonicalReader(reader) {
    if (!reader) return null;
    var name = readerBarCanonicalName(reader.name || "");
    if (!name) return null;
    if (name === reader.name) return reader;
    var clone = {};
    Object.keys(reader).forEach(function (key) {
      clone[key] = reader[key];
    });
    clone.name = name;
    return clone;
  }

  function readerBarProbeFor(readerName) {
    readerName = readerBarCanonicalName(readerName, { defaultForBlank: true });
    var bar = commandState.readerBar;
    if (!bar || !Array.isArray(bar.readers)) return null;
    for (var i = 0; i < bar.readers.length; i++) {
      var reader = bar.readers[i];
      if (reader && readerBarCanonicalName(reader.name) === readerName) {
        return readerBarCanonicalReader(reader);
      }
    }
    return null;
  }

  function readerBarProbeHasCard(readerName) {
    var probe = readerBarProbeFor(readerName);
    return !!(probe && String(probe.atr_hex || "").trim());
  }

  function readerBarHasScp03Session(readerName) {
    readerName = readerBarCanonicalName(readerName, { defaultForBlank: true });
    var wb = commandState.scp03Workbench;
    if (!wb || !Array.isArray(wb.tabs)) return false;
    for (var i = 0; i < wb.tabs.length; i++) {
      var tab = wb.tabs[i];
      if (!tab) continue;
      if (readerBarBoundName(tab) === readerName && tab.sessionId) return true;
    }
    return false;
  }

  function readerBarHasHilSession(readerName) {
    readerName = readerBarCanonicalName(readerName, { defaultForBlank: true });
    var hilBound = readerBarHilBoundName();
    return !!(hilBound && hilBound === readerName);
  }

  function readerBarHasRealSession(readerName) {
    readerName = readerBarCanonicalName(readerName, { defaultForBlank: true });
    return readerBarHasScp03Session(readerName) || readerBarHasHilSession(readerName);
  }

  function readerBarPruneEmptyReaderBindings() {
    var bar = commandState.readerBar;
    var changed = false;
    var emptyReaders = {};
    (bar.readers || []).forEach(function (reader) {
      var name = readerBarCanonicalName(reader && reader.name);
      if (!name) return;
      if (!String(reader && reader.atr_hex || "").trim()) {
        emptyReaders[name] = true;
      }
    });

    var active = readerBarCanonicalName(bar.activeReader);
    if (active && emptyReaders[active]) {
      bar.activeReader = "";
      ccRefreshReaderSessionFormFields("");
      changed = true;
    }

    var wb = commandState.scp03Workbench;
    if (wb && Array.isArray(wb.tabs)) {
      wb.tabs.forEach(function (tab) {
        if (!tab || !tab.sessionId) return;
        var bound = readerBarBoundName(tab);
        if (!bound || !emptyReaders[bound]) return;
        tab.sessionId = null;
        tab.atrHex = "";
        tab.errorKind = "no_card";
        tab.error = "card removed from reader";
        tab.scanData = null;
        tab.selectedPath = null;
        tab.previewCache = null;
        tab.fcpCache = {};
        tab.lastRecoverAt = 0;
        changed = true;
      });
      if (changed) refreshSessionStatusMetric();
    }
    return changed;
  }

  function readerBarIsDuplicateRemoteReader(reader, localNames) {
    if (!reader || String(reader.kind || "") !== "remote") return false;
    var remoteName = String(reader.name || "").toLowerCase();
    for (var i = 0; i < localNames.length; i++) {
      var localName = String(localNames[i] || "").trim().toLowerCase();
      if (localName && remoteName.indexOf(localName) >= 0) return true;
    }
    return false;
  }

  function readerBarNormalizeState() {
    var bar = commandState.readerBar;
    if (!bar) return;
    var activeReader = readerBarCanonicalName(bar.activeReader || "");
    if (activeReader !== bar.activeReader) {
      bar.activeReader = activeReader;
    }
    var popoverFor = readerBarCanonicalName(bar.openPopoverFor || "");
    if (popoverFor !== bar.openPopoverFor) {
      bar.openPopoverFor = popoverFor;
      if (bar.openPopover) {
        bar.openPopover.setAttribute("data-reader-name", popoverFor);
      }
    }
    var wb = commandState.scp03Workbench;
    if (wb && Array.isArray(wb.tabs)) {
      wb.tabs.forEach(function (tab) {
        if (!tab) return;
        if (tab.readerName) {
          tab.readerName = readerBarCanonicalName(tab.readerName);
        } else if (tab.sessionId) {
          tab.readerName = readerBarCanonicalName("", { defaultForBlank: true });
        }
        if (tab.pendingReader) {
          tab.pendingReader = readerBarCanonicalName(tab.pendingReader);
        }
      });
    }
    var hil = commandState.hilWorkbench;
    if (hil && hil.readerName) {
      hil.readerName = readerBarCanonicalName(hil.readerName, {
        defaultForBlank: true,
      });
    }
    var sessions = commandState.readerSessions || {};
    Object.keys(sessions).forEach(function (key) {
      var canonical = readerBarCanonicalName(key);
      if (!canonical || canonical === key) return;
      var merged = commandState.readerSessions[canonical] || {};
      var oldCtx = sessions[key] || {};
      Object.keys(oldCtx).forEach(function (ctxKey) {
        merged[ctxKey] = oldCtx[ctxKey];
      });
      commandState.readerSessions[canonical] = merged;
      delete commandState.readerSessions[key];
    });
  }

  async function readerBarRefresh(opts) {
    var bar = commandState.readerBar;
    if (bar.loading) return;
    bar.loading = true;
    bar.error = null;
    var refresh = $("topbar-readers-refresh");
    if (refresh) refresh.classList.add("is-spinning");
    var releasedEmptyBinding = false;
    try {
      var data = await apiFetch("/api/live/readers");
      bar.readers = (data && Array.isArray(data.readers)) ? data.readers : [];
      bar.fetchedAt = Date.now();
      readerBarNormalizeState();
      // Back-compat: older code paths still read from
      // ``commandState.scp03Workbench.readers`` (the per-SCP03 sidebar
      // cache). Mirror the new snapshot there so nothing breaks while
      // we retire the legacy sidebar.
      if (commandState.scp03Workbench) {
        commandState.scp03Workbench.readers = bar.readers;
        commandState.scp03Workbench.readersFetchedAt = bar.fetchedAt;
        commandState.scp03Workbench.readersError = null;
      }
      // Clear the sticky "no_card" flag on any tab whose reader now
      // reports an ATR again — the operator has reinserted the card
      // (or the card finished booting its runtime). The next pill
      // click is allowed to auto-open cleanly; no need for a manual
      // welcome-panel trip first.
      if (commandState.scp03Workbench
          && Array.isArray(commandState.scp03Workbench.tabs)) {
        commandState.scp03Workbench.tabs.forEach(function (t) {
          if (!t || t.errorKind !== "no_card") return;
          var bound = readerBarBoundName(t);
          if (!bound) return;
          for (var k = 0; k < bar.readers.length; k++) {
            var r = bar.readers[k];
            if (r
                && readerBarCanonicalName(r.name) === bound
                && String(r.atr_hex || "").trim()) {
              t.errorKind = "";
              t.error = null;
              break;
            }
          }
        });
      }
      releasedEmptyBinding = readerBarPruneEmptyReaderBindings();
    } catch (err) {
      bar.error = String((err && err.message) || err);
      // Don't clobber the cached readers on a transient failure —
      // operators still want to click their existing pills.
    } finally {
      bar.loading = false;
      if (refresh) refresh.classList.remove("is-spinning");
      readerBarRender();
      if (
        releasedEmptyBinding
        &&
        ccSubsystemRequiresReaderSession(commandState.activeSubsystem)
        && !ccActiveReaderName()
      ) {
        openCommandSubsystem(commandState.activeSubsystem, {
          scope: commandState.activeScope || "all",
          leafId: commandState.activeLeafId || "",
        });
      }
    }
  }

  function readerBarDeriveStatus(readerName) {
    readerName = readerBarCanonicalName(readerName, { defaultForBlank: true });
    if (!readerName) return "gray";
    // Returns one of { "green", "yellow", "red", "gray" } based on
    //   - whether any SCP03 tab/HIL bridge is bound, or a reader-scoped
    //     module is bound while the latest probe still has an ATR (green),
    //   - whether the reader's most recent /api/live/readers probe
    //     reported an ATR (yellow — card present, no session),
    //   - else red.
    // "gray" is reserved for readers that disappear from the probe
    // but still hang around in ``scp03Workbench.tabs`` because the
    // operator had a session open against them (graceful degradation).
    var probe = readerBarProbeFor(readerName);
    if (!probe) return "gray";
    var atr = String(probe.atr_hex || "").trim();
    var hasRealSession = readerBarHasRealSession(readerName);
    var scopedBound = readerBarReaderScopedBoundName();
    var hasReaderScopedBinding = scopedBound && scopedBound === readerName;
    if (atr.length > 0 && (hasRealSession || hasReaderScopedBinding)) return "green";
    if (atr.length > 0) return "yellow";
    return "red";
  }

  function readerBarRender() {
    var bar = commandState.readerBar;
    var host = $("topbar-readers-scroll");
    if (!host) return;
    readerBarNormalizeState();
    host.innerHTML = "";

    var error = bar.error;
    var readers = [];
    var readerMap = {};
    var probedReaders = Array.isArray(bar.readers) ? bar.readers : [];
    var localNames = [];
    probedReaders.forEach(function (reader) {
      if (reader && String(reader.kind || "local") !== "remote") {
        localNames.push(String(reader.name || ""));
      }
    });
    probedReaders.forEach(function (reader) {
      if (readerBarIsDuplicateRemoteReader(reader, localNames)) return;
      var canonical = readerBarCanonicalReader(reader);
      if (!canonical || !canonical.name) return;
      if (!readerMap[canonical.name]) {
        readerMap[canonical.name] = canonical;
        readers.push(canonical);
        return;
      }
      var existing = readerMap[canonical.name];
      if (!String(existing.atr_hex || "").trim()
          && String(canonical.atr_hex || "").trim()) {
        existing.atr_hex = canonical.atr_hex;
      }
      if (canonical.status && canonical.status !== "orphan") {
        existing.status = canonical.status;
      }
    });

    // Merge any readers that the probe no longer sees but which still
    // hold an SCP03 session — we don't want the pill to vanish while
    // the operator is mid-workflow (e.g. the reader briefly disconnects
    // from pcscd). Those orphan pills render with the gray dot.
    var wb = commandState.scp03Workbench;
    var known = {};
    readers.forEach(function (r) { if (r && r.name) known[r.name] = true; });
    if (wb && Array.isArray(wb.tabs)) {
      wb.tabs.forEach(function (t) {
        var name = readerBarBoundName(t);
        if (name && !known[name]) {
          readers = readers.concat([{ name: name, atr_hex: "", status: "orphan" }]);
          known[name] = true;
        }
      });
    }
    var hilName = readerBarHilBoundName();
    if (hilName && !known[hilName]) {
      readers = readers.concat([{ name: hilName, atr_hex: "", status: "orphan" }]);
      known[hilName] = true;
    }
    var scopedName = readerBarReaderScopedBoundName();
    if (scopedName && !known[scopedName]) {
      readers = readers.concat([{ name: scopedName, atr_hex: "", status: "orphan" }]);
      known[scopedName] = true;
    }

    if (readers.length === 0) {
      var hint = document.createElement("span");
      hint.className = "topbar-readers-hint";
      if (error) {
        hint.textContent = "readers unavailable: " + error;
      } else if (bar.loading) {
        hint.textContent = "enumerating readers…";
      } else {
        hint.textContent = "no readers detected — click ↻ to re-enumerate";
      }
      host.appendChild(hint);
      return;
    }

    readers.forEach(function (reader) {
      host.appendChild(readerBarBuildPill(reader));
    });

    // Keep the popover (if any) in sync with the freshly-polled
    // reader status. ATR / pill colour can change between paints
    // (insert / remove a card) and the panel must reflect that.
    if (bar.openPopover && bar.openPopoverFor) {
      var openFor = readerBarCanonicalName(bar.openPopoverFor);
      var stillVisible = readers.some(function (r) {
        return r && readerBarCanonicalName(r.name) === openFor;
      });
      if (stillVisible) {
        readerBarRefreshPopover();
      } else {
        readerBarClosePopover();
      }
    }
  }

  function readerBarBuildPill(reader) {
    var bar = commandState.readerBar;
    reader = readerBarCanonicalReader(reader);
    if (!reader) return document.createDocumentFragment();
    var name = String(reader && reader.name || "");
    var pill = document.createElement("button");
    pill.type = "button";
    pill.className = "topbar-reader-pill";
    pill.setAttribute("role", "tab");
    pill.setAttribute("data-reader-name", name);
    if (bar.activeReader === name) {
      pill.classList.add("is-active");
      pill.setAttribute("aria-selected", "true");
    } else {
      pill.setAttribute("aria-selected", "false");
    }

    var status = readerBarDeriveStatus(name);
    if (status === "green") {
      pill.setAttribute("data-session", "active");
    } else {
      pill.setAttribute("data-session", "inactive");
    }

    var atr = String(reader.atr_hex || "").trim();
    var tooltip = name + "\n";
    if (status === "green") {
      tooltip += readerBarHasRealSession(name)
        ? "● active session"
        : "● selected for this surface";
    } else if (status === "yellow") {
      tooltip += "● card present — no session (click to open)";
    } else if (status === "red") {
      tooltip += "● reader empty — no session";
    } else {
      tooltip += "● reader offline";
    }
    if (atr) tooltip += "\nATR: " + atr;
    pill.title = tooltip;

    var dot = document.createElement("span");
    dot.className = "topbar-reader-pill-dot topbar-reader-pill-dot--" + status;
    dot.setAttribute("aria-hidden", "true");
    pill.appendChild(dot);

    var label = document.createElement("span");
    label.className = "topbar-reader-pill-label";
    label.textContent = readerBarShortName(name);
    pill.appendChild(label);

    var close = document.createElement("span");
    close.className = "topbar-reader-pill-close";
    close.setAttribute("role", "button");
    close.setAttribute("aria-label", "Close session on " + name);
    close.title = "Close session on this reader";
    close.textContent = "\u00d7";
    close.addEventListener("click", function (event) {
      event.stopPropagation();
      readerBarCloseSessionFor(name);
    });
    pill.appendChild(close);

    pill.addEventListener("click", function (event) {
      event.stopPropagation();
      // Toggle: clicking the same pill while its popover is open
      // dismisses the panel rather than reopening it. Operators
      // expect the same affordance as a dropdown menu.
      var bar = commandState.readerBar;
      if (bar.openPopover && bar.openPopoverFor === name) {
        readerBarClosePopover();
        return;
      }
      readerBarOpenPopover(name, pill);
    });

    return pill;
  }

  function readerBarShortName(name) {
    // PC/SC reader names are painfully long (e.g. "SCM Microsystems Inc.
    // SCR 3310 [CCID Interface] 00 00"). We keep the first meaningful
    // word-group and trim anything after a double-space or final
    // "HH HH" index — enough to tell two readers apart without blowing
    // out the pill width.
    if (!name) return "reader";
    var s = String(name);
    // Strip trailing "NN NN" port/slot index.
    s = s.replace(/\s+\d{2}\s+\d{2}$/, "");
    // Strip "[CCID Interface]"-style suffix.
    s = s.replace(/\s*\[.*?\]\s*/g, " ").trim();
    if (s.length <= 26) return s;
    // Keep a meaningful head + tail.
    return s.substring(0, 22) + "…";
  }

  function readerBarActivate(readerName) {
    readerName = readerBarCanonicalName(readerName);
    if (!readerName) return;
    var bar = commandState.readerBar;
    var prevReader = readerBarCanonicalName(bar.activeReader);

    // --- Save current context for the previous reader ---
    if (prevReader && prevReader !== readerName) {
      var ctx = commandState.readerSessions[prevReader] || {};
      ctx.activeSubsystem = commandState.activeSubsystem;
      ctx.activeScope = commandState.activeScope;
      ctx.activeLeafId = commandState.activeLeafId;
      // SCP03: remember which tab was active
      var wb = commandState.scp03Workbench;
      if (wb && wb.activeTabId) {
        ctx.scp03ActiveTabId = wb.activeTabId;
      }
      ctx._savedAt = Date.now();
      commandState.readerSessions[prevReader] = ctx;
    }

    bar.activeReader = readerName;
    bar.openPopover = null;
    bar.openPopoverFor = "";

    // Bridge into the legacy YggdraSimReaderStore so existing
    // subsystems (SCP03, SCP80, SCP11) can resolve the operator's
    // chosen reader from a single place.
    try {
      if (typeof window.YggdraSimReaderStore !== "undefined"
          && window.YggdraSimReaderStore) {
        if (typeof window.YggdraSimReaderStore.setSelected === "function") {
          window.YggdraSimReaderStore.setSelected(readerName, { fromReaderBar: true });
        } else {
          window.YggdraSimReaderStore.activeReader = readerName;
        }
      }
    } catch (_err) { /* YggdraSimReaderStore not loaded */ }
    ccRefreshReaderSessionFormFields(readerName);
    readerBarNotifySessionChanged();

    // Sync the reader-bar-picked name into the old SCP03 sidebar
    // data so the per-reader-Name sidebar still works even in the
    // SCP03 workbench path.
    if (commandState.scp03Workbench) {
      commandState.scp03Workbench.readers = bar.readers;
      commandState.scp03Workbench.readersFetchedAt = bar.fetchedAt;
      commandState.scp03Workbench.readersError = null;
    }

    // --- Restore context for the new reader ---
    var savedCtx = commandState.readerSessions[readerName];
    if (savedCtx && savedCtx.activeSubsystem) {
      // Restore the subsystem/view the user was on for this reader
      if (savedCtx.activeSubsystem !== commandState.activeSubsystem
          || savedCtx.activeScope !== commandState.activeScope) {
        openCommandSubsystem(savedCtx.activeSubsystem, {
          scope: savedCtx.activeScope,
          leafId: savedCtx.activeLeafId,
        });
      }
    }

    // Drive the SCP03 workbench: locate or create the session tab
    // bound to this reader, hydrate from localStorage, and re-paint.
    readerBarSyncToScp03Tab(readerName);

    // If the operator is on the Overview view, auto-navigate to the
    // SCP03 workbench so the first pill click opens a scan surface
    // immediately. When they are already deep in the SAIP workbench
    // or raw shell, clicking a pill keeps them where they are.
    if (ccSubsystemRequiresReaderSession(commandState.activeSubsystem)) {
      openCommandSubsystem(commandState.activeSubsystem, {
        scope: commandState.activeScope || "all",
        leafId: commandState.activeLeafId || "",
      });
    } else if (commandState.activeSubsystem === null) {
      openCommandSubsystem("SCP03");
    } else if (!savedCtx) {
      // First time clicking this reader — stay in current subsystem
      // but the subsystem should re-fetch data for the new reader.
      // The dashboard auto-fetch in renderCompactWorkbench handles this
      // on next render.
    }

    // If the selected reader has a card present (yellow) and there is
    // no persisted state, auto-open a session immediately so operators
    // don't have to click the Open button on the welcome panel. This
    // restores the old "click reader → scan starts" UX the sidebar had,
    // but only for first-time encounters — hydrated tabs get Resume.
    var pillStatus = readerBarDeriveStatus(readerName);
    if (pillStatus === "yellow") {
      var wb = commandState.scp03Workbench;
      if (wb) {
        var tab = scp03FindTab(wb.activeTabId);
        if (tab) {
          if (tab.sessionId) return;
          if (tab.status === "scanning") return;
        }
        if (tab && !tab.readerName && !scp03HasPersistedState(tab)) {
          tab.pendingReader = readerName;
          var tabBar = document.querySelector(".cc-scp03-tabs");
          var tabBody = document.querySelector(".cc-scp03-body");
          scp03OpenSessionForTab(tab, tabBar, tabBody);
        }
      }
    }

    // Update any open SCP03 workbench tab's scope caches so the
    // pending-reader label in the welcome panel reflects the
    // currently-selected pill.
    if (commandState.scp03Workbench
        && Array.isArray(commandState.scp03Workbench.tabs)) {
      commandState.scp03Workbench.tabs.forEach(function (t) {
        if (t && !t.readerName && t.pendingReader !== readerName) {
          t.pendingReader = readerName;
        }
      });
    }
    if (typeof readerBarNotifySessionChanged === "function") {
      readerBarNotifySessionChanged();
    }
  }
  function readerBarSyncToScp03Tab(readerName) {
    readerName = readerBarCanonicalName(readerName);
    if (!readerName) return;
    // Ensure a scp03Workbench tab exists for ``readerName`` and
    // promote it to active. Safe to call even when the SCP03
    // workbench is not mounted — the tab is reused next time the
    // operator navigates into SCP03.
    var wb = commandState.scp03Workbench;
    if (!wb || !Array.isArray(wb.tabs)) return;
    var tab = null;
    for (var i = 0; i < wb.tabs.length; i++) {
      var t = wb.tabs[i];
      if (!t) continue;
      var bound = readerBarBoundName(t);
      if (bound === readerName) { tab = t; break; }
    }
    if (!tab) {
      // Reuse a truly-empty first tab if one exists — the workbench
      // seeds an unbound tab on every open. Prefer that over stacking
      // more tabs than we need.
      for (var j = 0; j < wb.tabs.length; j++) {
        var candidate = wb.tabs[j];
        if (!candidate) continue;
        var isEmpty = !candidate.sessionId
          && !candidate.readerName
          && !candidate.pendingReader;
        if (isEmpty) { tab = candidate; break; }
      }
      if (!tab) {
        if (typeof scp03CreateEmptyTab === "function") {
          tab = scp03CreateEmptyTab();
          wb.tabs.push(tab);
        } else {
          return;
        }
      }
      tab.pendingReader = readerName;
      // Try to hydrate from localStorage — if this reader has been
      // used before (same host, same reader name), the persisted tree
      // + fcpCache + ribbon tab come back so the operator lands on
      // exactly where they left off instead of a blank welcome panel.
      // Hydration deliberately leaves ``sessionId`` null so the welcome
      // panel's "Resume 'X'" button reopens the secure channel.
      try {
        var persisted = scp03LoadPersisted(readerName);
        if (persisted) {
          scp03HydrateTabFromPersisted(tab, persisted);
          // ``pendingReader`` was set before hydration; preserve it so
          // the Resume button knows which reader to target.
          tab.pendingReader = readerName;
        }
      } catch (_err) { /* hydration is best-effort */ }
    }
    wb.activeTabId = tab.id;

    // If the SCP03 workbench is currently mounted, repaint so the
    // new active tab + its reader binding become visible.
    var tabBar = document.querySelector(".cc-wb-tabs.scp03-topbar");
    var tabBody = document.querySelector(".cc-wb-body");
    if (tabBar && tabBody && typeof renderScp03Tabs === "function") {
      renderScp03Tabs(tabBar, tabBody);
    }
  }

  async function readerBarCloseSessionFor(readerName) {
    readerName = readerBarCanonicalName(readerName);
    if (!readerName) return;
    // Close the session bound to ``readerName`` (if any) AND remove
    // the matching scp03Workbench tab. This is the only path the
    // pill's × button takes — the old per-tab "Close session" still
    // exists behind the Admin ribbon for keyboard-only operators.
    var wb = commandState.scp03Workbench;
    if (!wb || !Array.isArray(wb.tabs)) {
      readerBarRender();
      return;
    }
    var targetId = null;
    for (var i = 0; i < wb.tabs.length; i++) {
      var t = wb.tabs[i];
      if (!t) continue;
      var bound = readerBarBoundName(t);
      if (bound === readerName) { targetId = t.id; break; }
    }
    if (targetId && typeof scp03CloseTab === "function") {
      var tabBar = document.querySelector(".cc-wb-tabs.scp03-topbar");
      var tabBody = document.querySelector(".cc-wb-body");
      // scp03CloseTab tolerates missing bar/body args — it just skips
      // the DOM repaint. We still want to trigger it for the close
      // API call + bookkeeping side-effects.
      await scp03CloseTab(targetId, tabBar || document.createElement("div"),
        tabBody || document.createElement("div"));
    }
    var bar = commandState.readerBar;
    if (bar.activeReader === readerName) {
      bar.activeReader = "";
      ccRefreshReaderSessionFormFields("");
    }
    readerBarRender();
    if (ccSubsystemRequiresReaderSession(commandState.activeSubsystem)) {
      openCommandSubsystem(commandState.activeSubsystem, {
        scope: commandState.activeScope || "all",
        leafId: commandState.activeLeafId || "",
      });
    }
  }

  function readerBarNotifySessionChanged() {
    // Called by SCP03 flows (scp03Rescan, scp03CloseTab, …) after
    // their session_id / readerName state flips so the pill colour
    // updates without waiting for the next 5 s poll tick.
    readerBarRender();
    // Refresh the popover too — if the operator just disconnected
    // from inside the panel we want the buttons to flip enable
    // states without a second click.
    var bar = commandState.readerBar;
    if (bar.openPopover && bar.openPopoverFor) {
      readerBarRefreshPopover();
    }
  }

  // -------------------------------------------------------------------
  // Reader pill popover (Connect / Disconnect)
  //
  // Operators wanted a way to attach to a card without tunnelling
  // through the SCP03 Filesystem subsystem first. The pill is now a
  // dropdown anchor: clicking it opens a small panel with the reader's
  // status, ATR, and explicit Connect / Disconnect buttons. The pill's
  // × close glyph stays available for one-click disconnect from the
  // strip, but the popover is the canonical surface.
  // -------------------------------------------------------------------

  function readerBarFindReader(name) {
    name = readerBarCanonicalName(name, { defaultForBlank: true });
    var bar = commandState.readerBar;
    if (!bar || !Array.isArray(bar.readers)) return null;
    for (var i = 0; i < bar.readers.length; i++) {
      var r = bar.readers[i];
      if (r && readerBarCanonicalName(r.name) === name) return r;
    }
    return null;
  }

  function readerBarStatusLabel(status, readerName) {
    if (status === "green") {
      return readerBarHasRealSession(readerName) ? "Active session" : "Reader selected";
    }
    if (status === "yellow") return "Card present \u2014 no session";
    if (status === "red") return "Reader empty";
    return "Reader offline";
  }

  function readerBarStatusHint(status, readerName) {
    if (status === "green") {
      if (readerBarHasRealSession(readerName)) {
        return "This reader has an open card session. Disconnect releases that session and its cached state.";
      }
      return "This reader is selected for the current eSIM surface. Actions will use this reader automatically.";
    }
    if (status === "yellow") {
      return "Card detected on this reader. Click Connect to start "
        + "an SCP03 session and load the file system.";
    }
    if (status === "red") {
      return "No card in this reader. Insert a card and the strip "
        + "will turn yellow.";
    }
    return "Reader is offline. Reconnect the device or check pcscd.";
  }

  function readerBarClosePopover() {
    var bar = commandState.readerBar;
    if (bar.openPopover && bar.openPopover.parentNode) {
      bar.openPopover.parentNode.removeChild(bar.openPopover);
    }
    bar.openPopover = null;
    bar.openPopoverFor = "";
    if (bar._popoverDocHandler) {
      document.removeEventListener("click", bar._popoverDocHandler, true);
      bar._popoverDocHandler = null;
    }
    if (bar._popoverKeyHandler) {
      document.removeEventListener("keydown", bar._popoverKeyHandler, true);
      bar._popoverKeyHandler = null;
    }
  }

  function readerBarOpenPopover(name, anchor) {
    readerBarClosePopover();
    name = readerBarCanonicalName(name);
    if (!name) return;
    var bar = commandState.readerBar;
    bar.openPopoverFor = name;

    var pop = document.createElement("div");
    pop.className = "topbar-reader-popover";
    pop.setAttribute("role", "dialog");
    pop.setAttribute("aria-label", "Reader controls for " + name);
    pop.setAttribute("data-reader-name", name);
    pop.style.position = "fixed";
    pop.style.zIndex = "5500";
    pop.addEventListener("click", function (ev) { ev.stopPropagation(); });

    bar.openPopover = pop;
    document.body.appendChild(pop);
    readerBarPaintPopover(pop, name);
    readerBarPositionPopover(pop, anchor);

    // Outside-click + Esc to dismiss. Bound on the next tick so the
    // click that opened the panel doesn't immediately close it.
    setTimeout(function () {
      bar._popoverDocHandler = function (ev) {
        if (!bar.openPopover) return;
        if (bar.openPopover.contains(ev.target)) return;
        // Clicks on the *anchor pill* are handled by the pill's own
        // click listener (toggle behaviour), so we let those through
        // without closing here to avoid a double-handle race.
        var pillEl = ev.target.closest && ev.target.closest(".topbar-reader-pill");
        if (pillEl && pillEl.getAttribute("data-reader-name") === name) return;
        readerBarClosePopover();
      };
      bar._popoverKeyHandler = function (ev) {
        if (ev.key === "Escape") {
          ev.preventDefault();
          readerBarClosePopover();
        }
      };
      document.addEventListener("click", bar._popoverDocHandler, true);
      document.addEventListener("keydown", bar._popoverKeyHandler, true);
    }, 0);
  }

  function readerBarPositionPopover(pop, anchor) {
    if (!anchor || !anchor.getBoundingClientRect) return;
    var rect = anchor.getBoundingClientRect();
    var width = pop.offsetWidth || 320;
    var top = rect.bottom + 6;
    var left = rect.left;
    var maxLeft = window.innerWidth - width - 8;
    if (left > maxLeft) left = Math.max(8, maxLeft);
    var maxTop = window.innerHeight - (pop.offsetHeight || 200) - 8;
    if (top > maxTop) top = Math.max(8, maxTop);
    pop.style.top = top + "px";
    pop.style.left = left + "px";
  }

  function readerBarRefreshPopover() {
    var bar = commandState.readerBar;
    if (!bar.openPopover || !bar.openPopoverFor) return;
    readerBarPaintPopover(bar.openPopover, bar.openPopoverFor);
  }

  function readerBarPaintPopover(pop, name) {
    pop.innerHTML = "";
    var reader = readerBarFindReader(name);
    var status = readerBarDeriveStatus(name);
    var hasRealSession = readerBarHasRealSession(name);
    var atr = String((reader && reader.atr_hex) || "").trim();

    var head = document.createElement("div");
    head.className = "topbar-reader-popover-head";
    var title = document.createElement("div");
    title.className = "topbar-reader-popover-title";
    title.textContent = name || "(unknown reader)";
    head.appendChild(title);
    var closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "topbar-reader-popover-close";
    closeBtn.title = "Close (Esc)";
    closeBtn.setAttribute("aria-label", "Close reader panel");
    closeBtn.textContent = "\u00D7";
    closeBtn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      readerBarClosePopover();
    });
    head.appendChild(closeBtn);
    pop.appendChild(head);

    var statusRow = document.createElement("div");
    statusRow.className = "topbar-reader-popover-status";
    var dot = document.createElement("span");
    dot.className = "topbar-reader-pill-dot topbar-reader-pill-dot--" + status;
    dot.setAttribute("aria-hidden", "true");
    statusRow.appendChild(dot);
    var statusLabel = document.createElement("span");
    statusLabel.className = "topbar-reader-popover-status-label";
    statusLabel.textContent = readerBarStatusLabel(status, name);
    statusRow.appendChild(statusLabel);
    pop.appendChild(statusRow);

    if (atr) {
      var atrRow = document.createElement("div");
      atrRow.className = "topbar-reader-popover-atr";
      var atrLabel = document.createElement("span");
      atrLabel.className = "topbar-reader-popover-atr-label";
      atrLabel.textContent = "ATR";
      atrRow.appendChild(atrLabel);
      var atrCode = document.createElement("code");
      atrCode.className = "topbar-reader-popover-atr-val";
      atrCode.textContent = atr;
      atrCode.title = "Click to copy · right-click for menu";
      atrCode.addEventListener("click", function (ev) {
        ev.stopPropagation();
        if (typeof copyTextToClipboard === "function") {
          copyTextToClipboard(atr);
        } else if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(atr).catch(function () {});
        }
        atrCode.classList.add("is-copied");
        setTimeout(function () { atrCode.classList.remove("is-copied"); }, 700);
      });
      // Intercept right-click so QtWebEngine does not invoke its native
      // context menu — pywebview ≤5.x crashes on the feature-permission
      // path under Qt6 (``QWebEnginePage.MediaAudioCapture`` was removed
      // upstream). Showing our own reader menu also matches the live
      // readers list affordance.
      atrCode.addEventListener("contextmenu", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        if (typeof showReaderContextMenu === "function") {
          showReaderContextMenu(reader || { name: name, atr_hex: atr }, ev.clientX, ev.clientY);
        }
      });
      atrRow.appendChild(atrCode);
      pop.appendChild(atrRow);
    }

    var hint = document.createElement("p");
    hint.className = "topbar-reader-popover-hint";
    hint.textContent = readerBarStatusHint(status, name);
    pop.appendChild(hint);

    var actions = document.createElement("div");
    actions.className = "topbar-reader-popover-actions";

    var connectBtn = document.createElement("button");
    connectBtn.type = "button";
    connectBtn.className = "btn btn-primary";
    connectBtn.textContent = (status === "green")
      ? (hasRealSession ? "Open workbench" : "Selected")
      : "Connect";
    var canConnect = (status === "yellow" || status === "green");
    connectBtn.disabled = !canConnect;
    if (!canConnect) {
      connectBtn.title = (status === "red")
        ? "No card present — insert a card first."
        : "Reader is offline.";
    } else if (status === "green") {
      connectBtn.title = hasRealSession
        ? "Bring the active reader session into focus."
        : "This reader is already selected for the current surface.";
    } else {
      connectBtn.title = "Open SCP03 session and load the file system tree.";
    }
    connectBtn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      readerBarPopoverConnect(name);
    });
    actions.appendChild(connectBtn);

    var disconnectBtn = document.createElement("button");
    disconnectBtn.type = "button";
    disconnectBtn.className = "btn btn-secondary";
    var canClearBinding = (status === "green");
    disconnectBtn.textContent = hasRealSession ? "Disconnect" : "Clear selection";
    disconnectBtn.disabled = !canClearBinding;
    disconnectBtn.title = canClearBinding
      ? (hasRealSession
        ? "Close the secure channel and tear down the cached state."
        : "Clear this reader selection for the current surface.")
      : "No active reader binding.";
    disconnectBtn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      readerBarPopoverDisconnect(name);
    });
    actions.appendChild(disconnectBtn);

    pop.appendChild(actions);
  }

  function readerBarPopoverConnect(name) {
    // Funnel into the existing ``readerBarActivate`` flow which already
    // creates / promotes the SCP03 tab, hydrates persisted state, and
    // (when the pill is yellow) auto-runs ``scp03.scan``. Closing the
    // popover here keeps focus on the workbench rather than leaving a
    // floating panel layered over the action cards.
    readerBarClosePopover();
    if (typeof readerBarActivate === "function") {
      readerBarActivate(name);
    }
  }

  function readerBarPopoverDisconnect(name) {
    readerBarClosePopover();
    if (typeof readerBarCloseSessionFor === "function") {
      readerBarCloseSessionFor(name);
    }
  }

  async function loadCommandCatalogue() {
    try {
      var data = await apiFetch("/api/actions");
      commandState.catalogue = data;
      renderCommandNav(data);
      renderOverviewModuleLauncher(data);
    } catch (err) {
      var nav = $("command-center-nav");
      if (nav) {
        nav.innerHTML = '<li class="loading">actions unavailable: '
          + escapeHtml(String(err && err.message || err)) + "</li>";
      }
      var moduleGrid = $("overview-module-grid");
      if (moduleGrid) {
        moduleGrid.innerHTML = '<p class="loading">modules unavailable: '
          + escapeHtml(String(err && err.message || err)) + "</p>";
      }
    }
  }

  // Left-nav tree (GUI taxonomy, not the backend subsystem list). The
  // backend action registry groups specs by a flat ``subsystem`` string —
  // that's what the catalogue API returns. The sidebar we present to
  // operators is task-oriented instead: related subsystems are grouped
  // under a human label, and SCP03 is split by scope so the filesystem
  // and application surfaces don't overwhelm one workbench.
  //
  // Each leaf either:
  //   • targets a backend ``subsystem`` (rendered via the existing
  //     workbench/card dispatch), optionally with a ``scope`` that the
  //     workbench uses to filter its ribbon / hide its FS tree, or
  //   • targets an ``inspectView`` (non-Command-Center sections like
  //     env_flags / backend / raw shell), which routes through
  //     ``showView`` instead.
  //
  // ``stub: true`` means "no backend actions registered yet" — we still
  // render the leaf so the sidebar layout is stable as we light up new
  // surfaces, but clicking it shows a placeholder instead of a broken
  // empty workbench.
  var CC_NAV_TREE = [
    {
      id: "group-card-admin",
      label: "Card Administration",
      hint: "Direct APDU surfaces — files, applets, OTA.",
      defaultOpen: true,
      children: [
        {
          id: "leaf-scp03-filesystem",
          label: "Filesystem",
          subsystem: "SCP03",
          scope: "filesystem",
          hint: "ETSI TS 102 221 file system / 3GPP NAA records",
        },
        {
          id: "leaf-scp03-applications",
          label: "Applications",
          subsystem: "SCP03",
          scope: "applications",
          hint: "GlobalPlatform ISD / SSD / applets",
        },
        {
          id: "leaf-scp80",
          label: "Over-the-Air",
          subsystem: "SCP80",
          hint: "ETSI TS 102 225 / 226 — SMS-PP & CAT-TP OTA",
        },
      ],
    },
    {
      id: "group-esim",
      label: "eSIM (SCP11)",
      hint: "Remote SIM provisioning — SGP.22 / SGP.32 flows.",
      defaultOpen: true,
      children: [
        {
          id: "leaf-esim-live",
          label: "Management",
          subsystem: "eSIM Management",
          requiresReader: true,
          hint: "SM-DP+ / eIM relay management — TLS and ES9+",
        },
        {
          id: "leaf-esim-local-smdp",
          label: "Local SMDP+",
          subsystem: "SCP11 Local",
          requiresReader: true,
          hint: "Offline SM-DP+ over SCP11.local_access",
        },
        {
          id: "leaf-esim-local-eim",
          label: "Local eIM",
          subsystem: "Local eIM",
          requiresReader: true,
          hint: "eIM local - queue / audit / package builder",
        },
      ],
    },
    {
      id: "group-tools",
      label: "Tools",
      hint: "Offline helpers and package tooling.",
      defaultOpen: true,
      children: [
        {
          id: "leaf-tool-saip",
          label: "SAIP Tool",
          subsystem: "SAIP",
          hint: "Profile package (SAIP) inspector / editor",
        },
        {
          id: "leaf-tool-offline",
          label: "Offline Tools",
          subsystem: "Offline Tools",
          hint: "Decoders, ASN.1/TLV, SUCI, TUAK/TOPc, lint, status words",
        },
      ],
    },
    {
      id: "group-advanced",
      label: "Advanced",
      hint: "Low-level surfaces not part of the primary task tree.",
      defaultOpen: false,
      children: [
        {
          id: "leaf-adv-card-bridge",
          label: "Remote Bridge",
          inspectView: "card_bridge",
          hint: "Remote card relay diagnostics and remote HIL rig controls",
        },
        {
          id: "leaf-adv-hil",
          label: "HIL Bridge",
          subsystem: "HIL",
          hint: "Hardware-in-the-loop APDU relay / capture",
        },
        {
          id: "leaf-adv-simcard",
          label: "SIMCARD helpers",
          subsystem: "SIMCARD",
          hint: "Simulator-side helpers (quirks, profile store)",
        },
        {
          id: "leaf-adv-terminal",
          label: "Shell",
          inspectView: "terminal",
          hint: "Spawn a registered CLI module in an xterm PTY",
        },
        {
          id: "leaf-adv-host-shell",
          label: "Host shell",
          inspectView: "host_shell",
          hint: "Free-form host shell — opt-in via YGGDRASIM_GUI_HOST_SHELL",
        },
        {
          id: "leaf-adv-registry",
          label: "Registry browser",
          inspectView: "registry",
          hint: "Every stable engine entry point",
        },
      ],
    },
    {
      id: "group-env",
      label: "Environment",
      hint: "Runtime configuration flags.",
      defaultOpen: false,
      children: [
        {
          id: "leaf-env-config",
          label: "Configuration",
          inspectView: "env_flags",
          hint: "YGGDRASIM_* env flags (process / session / file scope)",
        },
      ],
    },
  ];

  // Flat look-up by subsystem for nav-highlight syncing. A subsystem
  // may appear more than once (SCP03 is listed under Filesystem AND
  // Applications); we track all the leaf ids so nav highlight works
  // regardless of which scope the operator entered from.
  function ccLeavesForSubsystem(subsystem) {
    var hits = [];
    CC_NAV_TREE.forEach(function (group) {
      (group.children || []).forEach(function (leaf) {
        if (leaf.subsystem === subsystem) hits.push(leaf);
      });
    });
    return hits;
  }

  function ccFindLeaf(leafId) {
    for (var i = 0; i < CC_NAV_TREE.length; i += 1) {
      var g = CC_NAV_TREE[i];
      var kids = g.children || [];
      for (var j = 0; j < kids.length; j += 1) {
        if (kids[j].id === leafId) return kids[j];
      }
    }
    return null;
  }

  function renderCommandNav(catalogue) {
    var nav = $("command-center-nav");
    if (!nav) return;
    nav.innerHTML = "";
    var subsystems = catalogue && catalogue.subsystems ? catalogue.subsystems : {};

    CC_NAV_TREE.forEach(function (group) {
      var groupLi = document.createElement("li");
      groupLi.className = "cc-nav-group";
      groupLi.setAttribute("data-cc-group", group.id);
      // Respect a remembered open/closed state (localStorage) so the
      // tree stays where the operator left it across reloads. Falling
      // back to ``defaultOpen`` on first visit keeps the top-priority
      // groups expanded out-of-the-box.
      var stored = _ccNavGroupStoredState(group.id);
      var isOpen = stored == null ? !!group.defaultOpen : stored === "open";
      if (isOpen) groupLi.classList.add("is-open");

      var header = document.createElement("button");
      header.type = "button";
      header.className = "cc-nav-group-header";
      header.setAttribute("aria-expanded", String(isOpen));
      header.setAttribute("aria-controls", group.id + "-list");
      header.innerHTML = ''
        + '<span class="cc-nav-caret" aria-hidden="true">\u25B8</span>'
        + '<span class="cc-nav-group-label">' + escapeHtml(group.label) + '</span>';
      if (group.hint) header.title = group.hint;
      header.addEventListener("click", function () {
        var nowOpen = !groupLi.classList.contains("is-open");
        groupLi.classList.toggle("is-open", nowOpen);
        header.setAttribute("aria-expanded", String(nowOpen));
        _ccNavGroupRememberState(group.id, nowOpen ? "open" : "closed");
      });
      groupLi.appendChild(header);

      var childList = document.createElement("ul");
      childList.className = "cc-nav-children";
      childList.id = group.id + "-list";
      childList.setAttribute("role", "group");
      childList.setAttribute("aria-label", group.label);

      (group.children || []).forEach(function (leaf) {
        var li = document.createElement("li");
        li.className = "subsystem-entry cc-nav-leaf";
        li.setAttribute("data-cc-leaf-id", leaf.id);
        if (leaf.subsystem) li.setAttribute("data-cc-subsystem", leaf.subsystem);
        if (leaf.scope) li.setAttribute("data-cc-scope", leaf.scope);
        if (leaf.requiresReader) li.setAttribute("data-cc-requires-reader", "1");
        if (leaf.inspectView) li.setAttribute("data-cc-view", leaf.inspectView);
        if (leaf.stub) li.classList.add("is-stub");
        if (leaf.hint) li.title = leaf.hint;

        var nameEl = document.createElement("span");
        nameEl.className = "cc-nav-name";
        nameEl.textContent = leaf.label;
        li.appendChild(nameEl);

        if (leaf.inspectView === "card_bridge") {
          var bridgeStateEl = document.createElement("span");
          bridgeStateEl.className = "cc-nav-card-bridge-state";
          bridgeStateEl.textContent = "running";
          li.appendChild(bridgeStateEl);
        }
        if (leaf.subsystem === "HIL") {
          var hilTraceStateEl = document.createElement("span");
          hilTraceStateEl.className = "cc-nav-hil-trace-state";
          hilTraceStateEl.textContent = "tracing";
          li.appendChild(hilTraceStateEl);
        }

        // Only subsystem-backed leaves get the action-count badge; the
        // inspectView leaves (env_flags / backend / readers / shell)
        // route to the existing non-CC views and have no action list.
        // Stub leaves render a neutral "—" dash instead of "0" so the
        // empty state reads as "not wired" rather than "broken".
        if (leaf.subsystem) {
          var count = (subsystems[leaf.subsystem] || []).length;
          var countEl = document.createElement("span");
          countEl.className = "cc-nav-count";
          countEl.textContent = leaf.stub ? "\u2014" : String(count);
          li.appendChild(countEl);
        }

        childList.appendChild(li);
      });

      groupLi.appendChild(childList);
      nav.appendChild(groupLi);
    });
    if (typeof cbSyncCommandCenterBridgeIndicators === "function") {
      cbSyncCommandCenterBridgeIndicators();
    }
    hilSyncCommandCenterTraceIndicators();
  }

  function renderOverviewModuleLauncher(catalogue) {
    var host = $("overview-module-grid");
    if (!host) return;
    host.innerHTML = "";
    var subsystems = catalogue && catalogue.subsystems ? catalogue.subsystems : {};

    CC_NAV_TREE.forEach(function (group) {
      var groupEl = document.createElement("section");
      groupEl.className = "overview-module-group";
      var header = document.createElement("div");
      header.className = "overview-module-group-header";
      var title = document.createElement("h3");
      title.textContent = group.label;
      header.appendChild(title);
      if (group.hint) {
        var hint = document.createElement("p");
        hint.className = "hint";
        hint.textContent = group.hint;
        header.appendChild(hint);
      }
      groupEl.appendChild(header);

      var grid = document.createElement("div");
      grid.className = "overview-module-card-grid";
      (group.children || []).forEach(function (leaf) {
        grid.appendChild(renderOverviewModuleCard(leaf, subsystems));
      });
      groupEl.appendChild(grid);
      host.appendChild(groupEl);
    });
    hilSyncCommandCenterTraceIndicators();
  }

  function renderOverviewModuleCard(leaf, subsystems) {
    var card = document.createElement("button");
    card.type = "button";
    card.className = "overview-module-card";
    card.setAttribute("data-cc-leaf-id", leaf.id || "");
    if (leaf.subsystem) card.setAttribute("data-cc-subsystem", leaf.subsystem);
    if (leaf.inspectView) card.setAttribute("data-cc-view", leaf.inspectView);
    if (leaf.stub) card.classList.add("is-stub");
    if (leaf.requiresReader) card.setAttribute("data-cc-requires-reader", "1");

    var titleRow = document.createElement("span");
    titleRow.className = "overview-module-card-title";
    var name = document.createElement("span");
    name.textContent = leaf.label || "Module";
    titleRow.appendChild(name);
    var badge = document.createElement("span");
    badge.className = "overview-module-card-badge";
    if (leaf.subsystem) {
      var count = (subsystems[leaf.subsystem] || []).length;
      badge.textContent = leaf.stub ? "reserved" : (String(count) + " action" + (count === 1 ? "" : "s"));
      if (leaf.subsystem === "HIL") {
        badge.setAttribute("data-hil-role", "overview-status");
      }
    } else if (leaf.inspectView === "card_bridge") {
      badge.setAttribute("data-cb-role", "overview-status");
      badge.textContent = "idle";
    } else {
      badge.textContent = "view";
    }
    titleRow.appendChild(badge);
    card.appendChild(titleRow);

    var hint = document.createElement("span");
    hint.className = "overview-module-card-hint";
    hint.textContent = leaf.hint || "";
    card.appendChild(hint);

    card.addEventListener("click", function () {
      if (leaf.inspectView) {
        ccOpenInspectView(leaf.inspectView, leaf.id || "");
        return;
      }
      if (leaf.subsystem) {
        openCommandSubsystem(leaf.subsystem, {
          scope: leaf.scope || "all",
          leafId: leaf.id || "",
          stub: !!leaf.stub,
        });
      }
    });
    return card;
  }

  function hilTraceIndicatorStatus() {
    var state = commandState.hilWorkbench || {};
    if (state.stopInFlight) {
      return { state: "running", label: "stopping" };
    }
    if (state.armed && state.startMode !== "offline") {
      if (state.startInFlight || state.liveBaselinePending) {
        return { state: "running", label: "starting" };
      }
      if (state.paused) {
        return { state: "running", label: "paused" };
      }
      return { state: "running", label: "tracing" };
    }
    return { state: "idle", label: "" };
  }

  function hilOverviewDefaultBadgeText() {
    var catalogue = commandState.catalogue || {};
    var subsystems = catalogue.subsystems || {};
    var count = (subsystems.HIL || []).length;
    return String(count) + " action" + (count === 1 ? "" : "s");
  }

  function hilSyncCommandCenterTraceIndicators() {
    var status = hilTraceIndicatorStatus();
    var running = status.state === "running";
    var label = status.label || "tracing";
    var topbar = $("topbar-hil-bridge");
    if (topbar) {
      var topbarLabel = running ? label : "idle";
      topbar.setAttribute("data-state", running ? "running" : "idle");
      topbar.title = "HIL Bridge status: " + topbarLabel
        + ". Click to " + (running ? "stop" : "start") + ".";
      topbar.setAttribute("aria-label", topbar.title);
      setText("topbar-hil-bridge-value", topbarLabel);
    }
    document.querySelectorAll('#command-center-nav [data-cc-leaf-id="leaf-adv-hil"]').forEach(function (entry) {
      entry.setAttribute("data-hil-trace-state", status.state);
      entry.classList.toggle("is-hil-tracing", running);
      var marker = entry.querySelector(".cc-nav-hil-trace-state");
      if (marker) marker.textContent = running ? label : "";
    });
    document.querySelectorAll('.overview-module-card[data-cc-subsystem="HIL"]').forEach(function (card) {
      card.setAttribute("data-hil-trace-state", status.state);
      card.classList.toggle("is-hil-tracing", running);
      var badge = card.querySelector('[data-hil-role="overview-status"]');
      if (badge) badge.textContent = running ? label : hilOverviewDefaultBadgeText();
    });
  }

  function _ccNavGroupStoredState(groupId) {
    try {
      return window.localStorage.getItem("yggdrasim:cc-nav:" + groupId);
    } catch (_e) {
      return null;
    }
  }

  function _ccNavGroupRememberState(groupId, value) {
    try {
      window.localStorage.setItem("yggdrasim:cc-nav:" + groupId, value);
    } catch (_e) { /* storage disabled / quota — non-fatal */ }
  }

  function openCommandSubsystem(subsystem, options) {
    // ``options`` is optional — older callers (reader-pill auto-route,
    // startup bootstrap) pass only the subsystem string. When we're
    // already on the same subsystem and the caller didn't supply a
    // scope, preserve the current scope + leaf so clicking a reader
    // pill while in "Applications" (for example) doesn't silently
    // bounce the workbench back to the default "Filesystem" surface.
    // Without this preservation the nav selection drifts every time
    // the operator switches between reader pills — the exact "session
    // context aware split does not work properly" symptom reported.
    var opts = options || {};
    var sameSubsystem = commandState.activeSubsystem === subsystem;
    var scope;
    if (opts.scope) {
      scope = opts.scope;
    } else if (sameSubsystem && commandState.activeScope) {
      scope = commandState.activeScope;
    } else {
      scope = "all";
    }
    var leafId;
    if (opts.leafId) {
      leafId = opts.leafId;
    } else if (sameSubsystem && commandState.activeLeafId) {
      leafId = commandState.activeLeafId;
    } else {
      leafId = "";
    }
    var stub = !!opts.stub;

    commandState.activeSubsystem = subsystem;
    commandState.activeScope = scope;
    commandState.activeLeafId = leafId;

    // Look up a friendly crumb label from the nav leaf, falling back
    // to the backend subsystem name for direct callers.
    var leaf = leafId ? ccFindLeaf(leafId) : null;
    var crumb = leaf
      ? ("Command Center \u00B7 " + leaf.label)
      : ("Command Center \u00B7 " + subsystem);

    showView("command_center", { crumb: crumb });
    ccHighlightLeaf(leafId || _ccDefaultLeafIdForSubsystem(subsystem, scope));

    renderCommandSubsystem(subsystem, { scope: scope, leaf: leaf, stub: stub });

    // Popouts are still anchored to the SCP03 workbench regardless of
    // scope — the visibility sync only cares about "are we looking at
    // an SCP03 surface or not". Scope changes within SCP03 therefore
    // keep the active tab's popouts visible.
    try {
      if (typeof scp03PopoutSyncForSubsystem === "function") {
        scp03PopoutSyncForSubsystem(subsystem);
      }
    } catch (_err) { /* startup race — workbench not yet mounted */ }

    // If we stayed inside SCP03 and only the scope changed, update
    // any open tab's scope cache so the workbench remembers it on
    // re-render. Harmless no-op for other subsystems.
    if (sameSubsystem && subsystem === "SCP03") {
      var wb = commandState.scp03Workbench;
      if (wb) wb.scope = scope;
    }
  }

  function ccHighlightLeaf(leafId) {
    document.querySelectorAll("#command-center-nav .cc-nav-leaf").forEach(function (entry) {
      if (entry.getAttribute("data-cc-leaf-id") === leafId) {
        entry.classList.add("active");
      } else {
        entry.classList.remove("active");
      }
    });
  }

  function _ccDefaultLeafIdForSubsystem(subsystem, scope) {
    // Used when ``openCommandSubsystem`` is invoked without a leaf id
    // (e.g. the reader-bar auto-route calls ``openCommandSubsystem(
    // "SCP03")`` to land on the workbench). When a scope is provided
    // we pick the matching leaf so the highlighted nav entry tracks
    // the scope the workbench will actually render in. Otherwise
    // prefer the Filesystem leaf for SCP03, falling back to the
    // first leaf that targets the subsystem.
    var leaves = ccLeavesForSubsystem(subsystem);
    if (leaves.length === 0) return "";
    if (scope) {
      for (var k = 0; k < leaves.length; k += 1) {
        if (leaves[k].scope === scope) return leaves[k].id;
      }
    }
    if (subsystem === "SCP03") {
      for (var i = 0; i < leaves.length; i += 1) {
        if (leaves[i].scope === "filesystem") return leaves[i].id;
      }
    }
    return leaves[0].id;
  }

  function ccReaderSessionChoices() {
    var bar = commandState.readerBar || {};
    var readers = Array.isArray(bar.readers) ? bar.readers : [];
    var seen = {};
    var choices = [];
    readers.forEach(function (reader) {
      var canonical = readerBarCanonicalReader(reader);
      if (!canonical || !canonical.name || seen[canonical.name]) return;
      seen[canonical.name] = true;
      choices.push(canonical);
    });
    return choices;
  }

  function renderReaderSessionGate(container, subsystem, actions, leaf, scope) {
    var wb = document.createElement("section");
    wb.className = "cc-workbench cc-workbench--compact cc-reader-session-gate";
    wb.setAttribute("data-wb", subsystem);

    var header = document.createElement("header");
    header.className = "cc-compact-header";
    var titleBlock = document.createElement("div");
    titleBlock.className = "cc-compact-title";
    var title = document.createElement("h2");
    title.textContent = leaf ? leaf.label : subsystem;
    titleBlock.appendChild(title);
    var hint = document.createElement("p");
    hint.className = "cc-compact-hint";
    hint.textContent = "Select a reader before running this eSIM surface.";
    titleBlock.appendChild(hint);
    header.appendChild(titleBlock);
    wb.appendChild(header);

    var body = document.createElement("div");
    body.className = "cc-reader-session-card";
    var lead = document.createElement("p");
    lead.className = "cc-reader-session-copy";
    lead.textContent = "eSIM actions are scoped to one PC/SC reader. Pick the reader here or from the top bar; action forms will use that reader automatically.";
    body.appendChild(lead);

    var choices = ccReaderSessionChoices();
    var bar = commandState.readerBar || {};
    if (choices.length > 0) {
      var list = document.createElement("div");
      list.className = "cc-reader-session-list";
      choices.forEach(function (reader) {
        var name = String(reader.name || "");
        var status = readerBarDeriveStatus(name);
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "cc-reader-session-choice";
        btn.setAttribute("data-reader-status", status);
        btn.setAttribute("data-reader-name", name);

        var nameEl = document.createElement("span");
        nameEl.className = "cc-reader-session-choice-name";
        nameEl.textContent = readerBarShortName(name);
        btn.appendChild(nameEl);

        var statusEl = document.createElement("span");
        statusEl.className = "cc-reader-session-choice-status";
        statusEl.textContent = status === "green"
          ? (readerBarHasScp03Session(name) || readerBarHasHilSession(name) ? "session open" : "selected")
          : (status === "yellow" ? "card present" : "not ready");
        btn.appendChild(statusEl);

        var atr = String(reader.atr_hex || "").trim();
        if (atr) {
          var atrEl = document.createElement("span");
          atrEl.className = "cc-reader-session-choice-atr mono";
          atrEl.textContent = atr.substring(0, 18) + (atr.length > 18 ? "..." : "");
          btn.appendChild(atrEl);
        }

        btn.addEventListener("click", function () {
          readerBarActivate(name);
          openCommandSubsystem(subsystem, {
            scope: scope || "all",
            leafId: leaf && leaf.id ? leaf.id : _ccDefaultLeafIdForSubsystem(subsystem, scope),
          });
        });
        list.appendChild(btn);
      });
      body.appendChild(list);
    } else {
      var empty = document.createElement("p");
      empty.className = "cc-reader-session-empty";
      empty.textContent = bar.loading
        ? "Enumerating PC/SC readers..."
        : "No readers are available yet.";
      body.appendChild(empty);
    }

    var refresh = document.createElement("button");
    refresh.type = "button";
    refresh.className = "btn btn-secondary";
    refresh.textContent = bar.loading ? "Refreshing..." : "Refresh readers";
    refresh.disabled = !!bar.loading;
    refresh.addEventListener("click", function () {
      Promise.resolve(readerBarRefresh({ manual: true })).then(function () {
        if (commandState.activeSubsystem === subsystem && !ccActiveReaderName()) {
          renderCommandSubsystem(subsystem, { scope: scope, leaf: leaf });
        }
      });
    });
    body.appendChild(refresh);

    wb.appendChild(body);
    container.appendChild(wb);

    if (choices.length === 0 && !bar.loading && !bar.fetchedAt) {
      Promise.resolve(readerBarRefresh({ manual: false })).then(function () {
        if (commandState.activeSubsystem === subsystem && !ccActiveReaderName()) {
          renderCommandSubsystem(subsystem, { scope: scope, leaf: leaf });
        }
      });
    }
  }

  function renderCommandSubsystem(subsystem, options) {
    var opts = options || {};
    var scope = opts.scope || "all";
    var leaf = opts.leaf || null;
    var stub = !!opts.stub;

    var cat = commandState.catalogue;
    var container = $("cc-actions");
    var title = leaf ? leaf.label : subsystem;
    var subtitle = leaf && leaf.hint
      ? leaf.hint
      : "Task-oriented actions exposed by " + subsystem + ".";
    setText("cc-title", "Command Center \u00B7 " + title);
    setText("cc-subtitle", subtitle);
    if (!container || !cat) return;
    var mainEl = container.closest ? container.closest(".main") : null;
    if (mainEl) {
      mainEl.classList.toggle("main--module-workbench", true);
      mainEl.classList.toggle("main--saip-workbench", subsystem === "SAIP");
      mainEl.classList.toggle("main--hil-workbench", subsystem === "HIL");
    }
    if (subsystem !== "HIL") {
      stopHilWorkbenchRuntime();
      hilStopModemShell({ dispose: true });
    }
    container.innerHTML = "";

    if (stub) {
      container.innerHTML = ''
        + '<article class="card cc-stub-card">'
        + '<h3>' + escapeHtml(title) + '</h3>'
        + '<p class="hint">' + escapeHtml(subtitle) + '</p>'
        + '<p>No actions are registered for this surface yet. It\u2019s '
        + 'reserved in the sidebar so the layout stays stable as the '
        + 'subsystem is wired in — pick a sibling entry to get work done '
        + 'right now.</p>'
        + '</article>';
      return;
    }

    var actions = (cat.subsystems && cat.subsystems[subsystem]) || [];
    if (actions.length === 0) {
      container.innerHTML = '<p class="loading">no actions registered for this subsystem.</p>';
      return;
    }
    if (ccSubsystemRequiresReaderSession(subsystem) && !ccActiveReaderName()) {
      renderReaderSessionGate(container, subsystem, actions, leaf, scope);
      return;
    }
    if (subsystem === "SCP03") {
      renderScp03Workbench(container, actions, { scope: scope });
      return;
    }
    if (subsystem === "SAIP") {
      renderSaipWorkbench(container, actions);
      return;
    }
    if (subsystem === "HIL") {
      renderHilWorkbench(container, actions, leaf);
      return;
    }
    // Everything else (SCP80, eSIM Management, SCP11 Local, Local eIM, SUCI,
    // SIMCARD, HIL, Tools, …) used to render as a grid of
    // full-width action cards. That layout grew unwieldy once each
    // subsystem picked up 10+ actions — operators had to scroll
    // past every form just to reach the relevant one. The compact
    // workbench mirrors the SCP03 Filesystem/Applications idiom:
    // a slim action picker on the left, the active card on the
    // right, with a filter for subsystems carrying many entries.
    renderCompactWorkbench(container, subsystem, actions, leaf);
  }

  // ------------------------------------------------------------------
  // Subsystem-level action categorisation (Task 4 — eSIM nested nav).
  //
  // Operators reported that the eSIM Management / SCP11 Local /
  // Local eIM workbenches grew long enough that the flat sidenav was
  // hard to scan. A 39-action subsystem is unusable without a typed
  // filter; even a 12-action one buries the lifecycle wizard underneath
  // the inspection helpers. Grouping is a pure UI concern — the action
  // registry is the source of truth — so we keep the category map on
  // the SPA side and key it by ``subsystem`` + action-ID suffix (the
  // segment after the last ``.``). Unmatched actions fall through to
  // a final "Other" group so newly-registered actions stay visible
  // until we extend the map.
  //
  // Order of categories is significant: the first category's first
  // action becomes the default-active card when the operator opens
  // the workbench, mirroring the previous "actions[0]" behaviour.
  var CC_ACTION_GROUPS_BY_SUBSYSTEM = {
    "eSIM Management": [
      {
        id: "esim-sgp22-consumer",
        label: "SGP.22 Consumer (LPA-d)",
        hint: "LPA-d profile download, ES10b lifecycle, notifications, and ES9+ endpoint configuration.",
        suffixes: [
          "download_profile", "flow",
          "enable_profile", "disable_profile", "delete_profile",
          "list_profiles", "list_notifications", "remove_notification",
          "clear_notifications", "get_eid", "euicc_info1",
          "euicc_info2", "get_certs", "get_smdp", "set_smdp",
          "get_es9", "set_es9", "set_es9_tls", "set_es9_ca",
          "es9_cert_info", "reset_card", "status", "scan",
          "aids",
        ],
      },
      {
        id: "esim-sgp32-iot",
        label: "SGP.32 IoT (IPA-d)",
        hint: "IPA-d / eIM discovery, authentication, package exchange, metadata, policy, and RAT operations.",
        suffixes: [
          "discover", "eim_authenticate", "eim_download", "eim_poll",
          "get_eim_config", "get_rat", "get_all_data",
          "get_pol", "set_pol", "read_metadata", "get_metadata",
          "store_metadata", "verify_scp11",
        ],
      },
    ],
    "SCP11 Local": [
      {
        id: "local-smdp-provisioning",
        label: "Local SM-DP+ Provisioning",
        hint: "Local SGP.22 delivery, metadata, certificate inventory, and keybag handling.",
        suffixes: [
          "load_profile", "get_certs_inventory", "store_metadata",
          "update_metadata", "store_metadata_custom",
          "store_metadata_custom_all", "metadata_lint", "export_keybag",
        ],
      },
      {
        id: "local-smdp-card",
        label: "Card & Session Operations",
        hint: "Card discovery, profile lifecycle, notifications, session state, and recording.",
        suffixes: [
          "discover", "status", "explain_last",
          "get_eid", "list_profiles", "get_euicc_info2",
          "get_configured_data", "list_notifications",
          "enable_profile", "disable_profile", "delete_profile",
          "record_start", "record_stop",
        ],
      },
    ],
    "Local eIM": [
      {
        id: "eim-status",
        label: "Status & telemetry",
        hint: "Session state, scan, discover, counters, handover, and response logs.",
        suffixes: [
          "status", "scan", "discover", "explain_last",
          "counters", "counter", "handover_status", "handover_set",
          "resp_log", "resp_log_filter",
          "list_profile_aliases", "get_eim_config",
          "eim_certs_inventory", "error_codes",
        ],
      },
      {
        id: "eim-package",
        label: "Package management",
        hint: "Issue / lint / explain / load SGP.32 eIM packages.",
        suffixes: [
          "issue_package", "eim_package_issue", "eim_package_issue_all",
          "eim_package_lint", "eim_package_explain",
          "load_eim_package", "eim_acknowledge",
          "list_fixtures",
        ],
      },
      {
        id: "eim-profile-mgmt",
        label: "Profile management",
        hint: "Enable / disable / delete / load profiles via the local eIM.",
        suffixes: [
          "enable_profile", "disable_profile", "delete_profile",
          "load_profile",
        ],
      },
      {
        id: "eim-metadata",
        label: "Metadata",
        hint: "Store / update metadata and manage eIM registrations.",
        suffixes: [
          "store_metadata", "update_metadata",
          "delete_eim", "euicc_memory_reset",
        ],
      },
      {
        id: "eim-isdr",
        label: "ISD-R operations",
        hint: "ISD-R path for eIM configuration, add, and delete.",
        suffixes: [
          "isdr_get_eim_config", "isdr_delete_eim",
          "isdr_add_eim", "isdr_add_initial_eim",
          "add_eim", "add_initial_eim",
        ],
      },
      {
        id: "eim-hotfolder",
        label: "Hotfolder",
        hint: "Hotfolder list, metadata, cycle, fetch.",
        suffixes: [
          "hotfolder_list", "hotfolder_metadata",
          "hotfolder_metadata", "hotfolder_fetch",
        ],
      },
      {
        id: "eim-campaign",
        label: "Campaign / reports",
        hint: "Cross-card eIM campaign, export, and aggregate.",
        suffixes: ["hotfolder_campaign", "hotfolder_export", "hotfolder_aggregate"],
      },
      {
        id: "eim-notif",
        label: "Notifications",
        hint: "Notification hygiene and queue management.",
        suffixes: ["notif_hygiene"],
      },
    ],
  };
  function ccActionSuffix(actionId) {
    var raw = String(actionId || "");
    var dot = raw.lastIndexOf(".");
    if (dot < 0) return raw;
    return raw.substring(dot + 1);
  }

  function ccGroupActionsForSubsystem(subsystem, actions) {
    var groups = CC_ACTION_GROUPS_BY_SUBSYSTEM[subsystem];
    if (!groups || !groups.length) return null;
    var buckets = groups.map(function (g) {
      return { group: g, items: [] };
    });
    var other = { group: { id: "other", label: "Other", hint: "" }, items: [] };
    var bySuffix = Object.create(null);
    groups.forEach(function (g, idx) {
      (g.suffixes || []).forEach(function (suffix) {
        bySuffix[String(suffix)] = idx;
      });
    });
    actions.forEach(function (action) {
      var suffix = ccActionSuffix(action.id);
      var bucketIdx = bySuffix[suffix];
      if (bucketIdx === undefined) {
        other.items.push(action);
        return;
      }
      buckets[bucketIdx].items.push(action);
    });
    var result = buckets.filter(function (b) { return b.items.length > 0; });
    if (other.items.length > 0) result.push(other);
    return result.length > 0 ? result : null;
  }

  var CC_ESIM_ACTION_FLAVORS = {
    sgp22: {
      id: "sgp22",
      label: "SGP.22 Consumer (LPA-d)",
      hint: "LPA-d profile download, local profile lifecycle, notifications, and ES9+ configuration.",
    },
    sgp32: {
      id: "sgp32",
      label: "SGP.32 IoT (IPA-d)",
      hint: "IPA-d / eIM discovery, authentication, package exchange, metadata, policy, and RAT operations.",
    },
  };

  var CC_ESIM_CONSOLIDATED_READ_SUFFIXES = {
    aids: true,
    discover: true,
    es9_cert_info: true,
    euicc_info1: true,
    euicc_info2: true,
    get_certs: true,
    get_eid: true,
    get_eim_config: true,
    get_es9: true,
    get_rat: true,
    get_smdp: true,
    list_notifications: true,
    list_profiles: true,
    scan: true,
    status: true,
  };

  function ccShouldShowEsimManagementAction(action) {
    var suffix = ccActionSuffix(action && action.id || "").toLowerCase();
    if (suffix === "get_all_data") return true;
    return !CC_ESIM_CONSOLIDATED_READ_SUFFIXES[suffix];
  }

  function ccEsimActionFlavor(action) {
    var id = String(action && action.id || "").toLowerCase();
    var suffix = ccActionSuffix(id);
    if (
      id.indexOf(".eim_") !== -1
      || suffix === "discover"
      || suffix === "get_eim_config"
      || suffix === "get_rat"
      || suffix === "get_all_data"
      || suffix === "get_pol"
      || suffix === "set_pol"
      || suffix === "read_metadata"
      || suffix === "get_metadata"
      || suffix === "store_metadata"
      || suffix === "verify_scp11"
    ) {
      return "sgp32";
    }
    return "sgp22";
  }

  function ccEsimActionFlavorGroups(actions) {
    var groups = [
      { meta: CC_ESIM_ACTION_FLAVORS.sgp22, items: [] },
      { meta: CC_ESIM_ACTION_FLAVORS.sgp32, items: [] },
    ];
    var byFlavor = { sgp22: groups[0], sgp32: groups[1] };
    (actions || []).forEach(function (action) {
      var flavor = ccEsimActionFlavor(action);
      (byFlavor[flavor] || byFlavor.sgp22).items.push(action);
    });
    return groups.filter(function (group) { return group.items.length > 0; });
  }

  function ccFindActionById(actions, actionId) {
    for (var i = 0; i < (actions || []).length; i++) {
      if (actions[i] && actions[i].id === actionId) return actions[i];
    }
    return null;
  }

  function ccFindCatalogueActionById(actionId) {
    var cat = commandState && commandState.catalogue;
    var subsystems = cat && cat.subsystems ? cat.subsystems : {};
    var names = Object.keys(subsystems);
    for (var i = 0; i < names.length; i++) {
      var action = ccFindActionById(subsystems[names[i]], actionId);
      if (action) return action;
    }
    return null;
  }

  function ccProfileTargetCacheKey(subsystem, readerName) {
    return String(subsystem || "") + "\x1f" + String(readerName || "");
  }

  function ccProfileTargetLabel(profile, aid) {
    var parts = [];
    var name = String(
      profile && (profile.nickname || profile.profile_name || profile.service_provider)
      || ""
    ).trim();
    var iccid = String(profile && profile.iccid || "").trim();
    var state = String(profile && profile.state || "").trim();
    if (name) parts.push(name);
    if (iccid) parts.push(iccid);
    if (state) parts.push(state);
    return parts.length > 0 ? parts.join(" · ") : aid;
  }

  function ccSetProfileTargetCache(subsystem, readerName, profiles) {
    if (!commandState.profileTargetCache) commandState.profileTargetCache = {};
    var seen = Object.create(null);
    var rows = [];
    (profiles || []).forEach(function (profile) {
      var aid = String(
        profile && (profile.aid || profile.isdp_aid || profile.isd_p_aid)
        || ""
      ).trim().toUpperCase().replace(/\s+/g, "");
      if (!aid || seen[aid]) return;
      seen[aid] = true;
      rows.push({ value: aid, label: ccProfileTargetLabel(profile, aid) });
    });
    commandState.profileTargetCache[ccProfileTargetCacheKey(subsystem, readerName)] = rows;
    ccRefreshProfileTargetDatalists();
  }

  function ccGetProfileTargetOptions(subsystem, readerName) {
    var cache = commandState.profileTargetCache || {};
    var activeReader = readerName || ccActiveReaderName();
    var keys = [
      ccProfileTargetCacheKey(subsystem, activeReader),
      ccProfileTargetCacheKey(subsystem, ""),
      ccProfileTargetCacheKey(commandState.activeSubsystem, activeReader),
      ccProfileTargetCacheKey(commandState.activeSubsystem, ""),
    ];
    for (var i = 0; i < keys.length; i++) {
      if (cache[keys[i]] && cache[keys[i]].length > 0) {
        return cache[keys[i]];
      }
    }
    return [];
  }

  function ccShouldSuggestProfileAidTargets(action, field) {
    if (!action || !field) return false;
    var id = String(action.id || "").toLowerCase();
    var suffix = ccActionSuffix(id);
    if (
      action.subsystem !== "eSIM Management"
      && action.subsystem !== "SCP11 Local"
    ) {
      return false;
    }
    if (field.name !== "target" && field.name !== "identifier") return false;
    return suffix === "get_metadata"
      || suffix === "get_pol"
      || suffix === "set_pol"
      || suffix === "enable_profile"
      || suffix === "disable_profile"
      || suffix === "delete_profile";
  }

  function ccPopulateProfileTargetDatalist(list, subsystem, readerName) {
    if (!list) return;
    var rows = ccGetProfileTargetOptions(subsystem, readerName);
    list.innerHTML = "";
    rows.forEach(function (row) {
      var opt = document.createElement("option");
      opt.value = row.value;
      opt.label = row.label;
      opt.textContent = row.label;
      list.appendChild(opt);
    });
  }

  function ccRefreshProfileTargetDatalists() {
    document.querySelectorAll("datalist[data-profile-targets='1']").forEach(function (list) {
      var subsystem = list.getAttribute("data-subsystem") || commandState.activeSubsystem || "";
      var readerName = ccActiveReaderName();
      list.setAttribute("data-reader", readerName);
      ccPopulateProfileTargetDatalist(list, subsystem, readerName);
    });
  }

  var CC_LOCAL_SMDP_ACTION_FLAVORS = {
    provisioning: {
      id: "provisioning",
      label: "Local SM-DP+ Provisioning",
      hint: "Local profile delivery, metadata, certificate inventory, and keybag handling.",
    },
    card: {
      id: "card",
      label: "Card & Session Operations",
      hint: "Card discovery, profile lifecycle, notifications, session state, and recording.",
    },
  };

  function ccLocalSmdpActionFlavor(action) {
    var suffix = ccActionSuffix(String(action && action.id || "").toLowerCase());
    if (
      suffix === "load_profile"
      || suffix === "get_certs_inventory"
      || suffix === "import_certificate"
      || suffix === "store_metadata"
      || suffix === "update_metadata"
      || suffix === "store_metadata_custom"
      || suffix === "store_metadata_custom_all"
      || suffix === "metadata_lint"
      || suffix === "export_keybag"
    ) {
      return "provisioning";
    }
    return "card";
  }

  function ccLocalSmdpActionFlavorGroups(actions) {
    var groups = [
      { meta: CC_LOCAL_SMDP_ACTION_FLAVORS.provisioning, items: [] },
      { meta: CC_LOCAL_SMDP_ACTION_FLAVORS.card, items: [] },
    ];
    var byFlavor = { provisioning: groups[0], card: groups[1] };
    (actions || []).forEach(function (action) {
      var flavor = ccLocalSmdpActionFlavor(action);
      (byFlavor[flavor] || byFlavor.card).items.push(action);
    });
    return groups.filter(function (group) { return group.items.length > 0; });
  }

  function _ccCategoryStoredState(subsystem, categoryId) {
    try {
      return window.localStorage.getItem(
        "yggdrasim:cc-cat:" + subsystem + ":" + categoryId
      );
    } catch (_e) {
      return null;
    }
  }

  function _ccCategoryRememberState(subsystem, categoryId, value) {
    try {
      window.localStorage.setItem(
        "yggdrasim:cc-cat:" + subsystem + ":" + categoryId,
        value
      );
    } catch (_e) { /* storage disabled / quota — non-fatal */ }
  }

  // -- Ribbon button icon resolver ------------------------------------
  // Maps action-ID suffix patterns to Unicode glyphs so every compact
  // workbench button gets an icon without per-action manual wiring.
  function _ccResolveIcon(actionId) {
    var id = (actionId || "").toLowerCase();
    if (/status|scan|discover/.test(id)) return "◷";
    if (/^get_|^list_|^read_|^show_/.test(id)) return "▣";
    if (/^set_|^update_|^store_|^write_/.test(id)) return "✎";
    if (/^enable_|^disable_/.test(id)) return "◐";
    if (/^delete_|^remove_|^clear_/.test(id)) return "✕";
    if (/^download_|^load_|^import_|^dump_/.test(id)) return "↓";
    if (/^export_|^explain_|^lint_/.test(id)) return "↑";
    if (/^reset_|^refresh_/.test(id)) return "↻";
    if (/^verify_|^validate_/.test(id)) return "✓";
    if (/^send_|^run_|^flow_|^execute/.test(id)) return "▶";
    if (/_package|_profile|_pe_|iso/.test(id)) return "⧉";
    if (/auth|_cert_|_certs_|key/.test(id)) return "⊙";
    if (/poll|campaign/.test(id)) return "⟳";
    if (/config/.test(id)) return "⚙";
    if (/script/.test(id)) return "≣";
    if (/record|recording|trace/.test(id)) return "●";
    if (/counter|handover/.test(id)) return "⧖";
    if (/notif|notification/.test(id)) return "✉";
    if (/hotfolder/.test(id)) return "❐";
    return "●";
  }

  function ccActionNeedsManualInput(action) {
    return (action && action.inputs || []).some(function (field) {
      if (ccShouldHideReaderField(action, field)) return false;
      return true;
    });
  }

  function ccActionShouldAutoRunOnOpen(action) {
    if (!action || action.streams) return false;
    return !ccActionNeedsManualInput(action);
  }

  function ccActionShouldAutoRunInEsimFlowPane(action) {
    if (!action) return false;
    return !ccActionNeedsManualInput(action);
  }

  // -- Action popout builder ------------------------------------------
  // Opens a floating popout with the action's form + run button.
  // Reuses _ccBuildCompactPopout (dedup + cascade) and buildField()
  // so the form experience is identical to the old card-based layout.
  function _ccBuildActionPopout(action) {
    var title = action.title || action.id || "Action";
    var popBody = _ccBuildCompactPopout(title);

    // Description
    if (action.description) {
      var desc = document.createElement("p");
      desc.className = "cc-action-desc";
      desc.textContent = action.description;
      popBody.appendChild(desc);
    }

    // Form
    var form = document.createElement("form");
    form.className = "cc-action-form";
    (action.inputs || []).forEach(function (field) {
      form.appendChild(buildField(action, field));
    });
    ccEnhanceActionForm(action, form);

    // Run button + status
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

    // Result area
    var result = document.createElement("div");
    result.className = "cc-action-result cc-action-result--" + (action.output_kind || "json");
    form.appendChild(result);

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      runActionFromForm(action, form, status, result);
    });

    // Prefill reader selects
    (action.inputs || []).forEach(function (field) {
      if (field.kind === "reader" && !ccShouldHideReaderField(action, field)) {
        var sel = form.querySelector('[name="' + field.name + '"]');
        if (sel) prefillReaderSelect(sel);
      }
    });

    popBody.appendChild(form);

    // If the action has no visible manual fields, the action button is
    // the operator's explicit request. Run immediately and leave a
    // Re-run button for repeating the same command.
    if (ccActionShouldAutoRunOnOpen(action)) {
      runBtn.textContent = "Re-run";
      window.setTimeout(function () {
        runActionFromForm(action, form, status, result);
      }, 0);
    }
  }

  // Compact workbench layout used for every command-center subsystem
  // that isn't SCP03 or SAIP. Exposes the same ``buildActionCard``
  // experience but visually constrains the surface to one active
  // action at a time so the module window doesn't devolve into a
  // wall of forms. Each action still owns its own card instance, so
  // form state, running status, and result panels survive entry
  // switches (hidden rather than unmounted).
  function renderCompactWorkbench(container, subsystem, actions, leaf) {
    var scopedReader = ccSubsystemRequiresReaderSession(subsystem)
      ? ccActiveReaderName()
      : "";
    var isEsimModuleSurface = ccSubsystemRequiresReaderSession(subsystem);
    var wb = document.createElement("section");
    wb.className = "cc-workbench cc-workbench--compact";
    if (subsystem === "Offline Tools") {
      wb.classList.add("cc-workbench--offline-tools");
    }
    wb.setAttribute("data-wb", subsystem);

    var header = document.createElement("header");
    header.className = "cc-compact-header";

    var titleBlock = document.createElement("div");
    titleBlock.className = "cc-compact-title";
    var h2 = document.createElement("h2");
    h2.textContent = leaf ? leaf.label : subsystem;
    titleBlock.appendChild(h2);
    if (leaf && leaf.hint) {
      var hint = document.createElement("p");
      hint.className = "cc-compact-hint";
      hint.textContent = leaf.hint;
      titleBlock.appendChild(hint);
    } else {
      var backendHint = document.createElement("p");
      backendHint.className = "cc-compact-hint";
      backendHint.textContent = actions.length
        + " action" + (actions.length === 1 ? "" : "s")
        + " registered under " + subsystem + ".";
      titleBlock.appendChild(backendHint);
    }
    header.appendChild(titleBlock);

    var moduleToolbar = null;
    var moduleToolbarStatus = null;
    var moduleToolbarButtons = [];
    if (isEsimModuleSurface) {
      moduleToolbar = document.createElement("div");
      moduleToolbar.className = "cc-esim-module-toolbar";
      moduleToolbar.setAttribute("aria-label", "eSIM module actions");

      function addModuleTool(labelText, titleText, handler, accentClass) {
        var button = document.createElement("button");
        button.type = "button";
        button.className = "cc-esim-module-tool"
          + (accentClass ? " " + accentClass : "");
        button.title = titleText || labelText;
        button.textContent = labelText;
        button.addEventListener("click", function (event) {
          event.preventDefault();
          handler();
        });
        moduleToolbar.appendChild(button);
        moduleToolbarButtons.push(button);
        return button;
      }

      addModuleTool(
        "Refresh",
        "Re-read the card and reload the displayed eSIM data",
        function () { refreshEsimSurface({ manual: true }); },
        ""
      );
      addModuleTool(
        "Reset",
        "Reset the selected reader/card connection and reload the displayed data",
        resetEsimSurface,
        "cc-esim-module-tool--reset"
      );

      moduleToolbarStatus = document.createElement("span");
      moduleToolbarStatus.className = "cc-esim-module-toolbar-status";
      moduleToolbarStatus.textContent = "idle";
      moduleToolbar.appendChild(moduleToolbarStatus);
      header.appendChild(moduleToolbar);
    }

    // Filter input only materialises when there are enough entries
    // to justify it. Below the threshold the sidenav is already
    // small enough for visual scanning.
    if (actions.length >= 8) {
      var searchWrap = document.createElement("div");
      searchWrap.className = "cc-compact-search";
      var search = document.createElement("input");
      search.type = "search";
      search.className = "cc-compact-search-input";
      search.placeholder = "Filter actions\u2026";
      search.setAttribute("aria-label", "Filter " + subsystem + " actions");
      searchWrap.appendChild(search);
      header.appendChild(searchWrap);
    }
    wb.appendChild(header);

    var groupedBuckets = (
      subsystem === "eSIM Management"
      || subsystem === "SCP11 Local"
    )
      ? null
      : ccGroupActionsForSubsystem(subsystem, actions);
    var activeCategoryId = null;
    var categoryTabRecs = [];
    var allCards = [];
    var actionFilterRecords = [];
    var searchInput = null;

    function groupedActionCategoryId(action) {
      if (!groupedBuckets || !action) return "";
      var actionId = String(action.id || "");
      for (var i = 0; i < groupedBuckets.length; i++) {
        var bucket = groupedBuckets[i] || {};
        var items = bucket.items || [];
        for (var j = 0; j < items.length; j++) {
          if (items[j] && String(items[j].id || "") === actionId) {
            return bucket.group && bucket.group.id ? bucket.group.id : "";
          }
        }
      }
      return "";
    }

    function applyGroupedActionFilters() {
      if (!groupedBuckets || actionFilterRecords.length === 0) return false;
      var q = searchInput
        ? searchInput.value.trim().toLowerCase()
        : "";
      actionFilterRecords.forEach(function (rec) {
        var catMatch = !activeCategoryId
          || !rec.categoryId
          || rec.categoryId === activeCategoryId;
        var searchMatch = q.length === 0
          || rec.haystack.indexOf(q) !== -1;
        rec.btn.hidden = !(catMatch && searchMatch);
      });
      return true;
    }

    function applyCardFilters() {
      if (applyGroupedActionFilters()) return;
      var q = searchInput
        ? searchInput.value.trim().toLowerCase()
        : "";
      allCards.forEach(function (rec) {
        var catMatch = !activeCategoryId
          || rec.categoryId === activeCategoryId;
        var searchMatch = q.length === 0
          || rec.haystack.indexOf(q) !== -1;
        var visible = catMatch && searchMatch;
        rec.card.hidden = !visible;
        if (rec.btn) rec.btn.hidden = !visible;
      });
    }

    // --- Ribbon tabstrip (grouped subsystems only) ---
    if (groupedBuckets) {
      var ribbon = document.createElement("div");
      ribbon.className = "cc-compact-ribbon";

      var tabstrip = document.createElement("div");
      tabstrip.className = "cc-compact-tabstrip";
      tabstrip.setAttribute("role", "tablist");
      tabstrip.setAttribute("aria-label", subsystem + " action categories");

      activeCategoryId = groupedBuckets[0].group.id;

      function switchCategory(catId) {
        activeCategoryId = catId;
        categoryTabRecs.forEach(function (tabRec) {
          var isActive = tabRec.id === catId;
          tabRec.el.classList.toggle("active", isActive);
          tabRec.el.setAttribute("aria-selected", String(isActive));
        });
        applyCardFilters();
      }

      groupedBuckets.forEach(function (bucket) {
        var tab = document.createElement("button");
        tab.type = "button";
        tab.className = "cc-compact-tab"
          + (bucket.group.id === activeCategoryId ? " active" : "");
        tab.setAttribute("role", "tab");
        tab.setAttribute("aria-selected",
          String(bucket.group.id === activeCategoryId));
        tab.setAttribute("data-category", bucket.group.id);
        if (bucket.group.hint) tab.title = bucket.group.hint;

        var label = document.createElement("span");
        label.className = "cc-compact-tab-label";
        label.textContent = bucket.group.label;
        tab.appendChild(label);

        var count = document.createElement("span");
        count.className = "cc-compact-tab-count";
        count.textContent = String(bucket.items.length);
        tab.appendChild(count);

        tab.addEventListener("click", function () {
          switchCategory(bucket.group.id);
        });

        tabstrip.appendChild(tab);
        categoryTabRecs.push({ id: bucket.group.id, el: tab });
      });

      ribbon.appendChild(tabstrip);
      wb.appendChild(ribbon);
    }

    // --- Dashboard: auto-fetch card overview on open ---
    var dashboardActions = ["eSIM Management", "SCP11 Local", "Local eIM"];
    var isDashboardSubsystem = dashboardActions.indexOf(subsystem) !== -1;
    // Map subsystem to the overview action that returns a snapshot
    var DASHBOARD_SCAN_ACTION = {
      "eSIM Management": "scp11_live.scan",
      "SCP11 Local": "scp11_local.discover",
      "Local eIM": "eim_local.scan",
    };
    var useEsimSplitPane = isDashboardSubsystem;
    var esimFlowPane = null;
    var esimFlowTitle = null;
    var esimFlowStatus = null;
    var esimFlowBody = null;
    var inlineActionPane = null;
    var inlineActionTitle = null;
    var inlineActionStatus = null;
    var inlineActionBody = null;
    var actionButtonRecords = [];
    var localOverviewRefreshers = [];

    function _setEsimModuleToolbarBusy(busy, statusText) {
      moduleToolbarButtons.forEach(function (button) {
        button.disabled = !!busy;
      });
      if (moduleToolbarStatus) {
        moduleToolbarStatus.textContent = statusText || (busy ? "running" : "idle");
      }
    }

    function _setEsimFlowStatus(text) {
      if (esimFlowStatus) {
        esimFlowStatus.textContent = text || "idle";
      }
    }

    function _setEsimFlowActiveAction(action) {
      var actionId = String(action && action.id || "");
      actionButtonRecords.forEach(function (rec) {
        rec.btn.classList.toggle("is-active", actionId.length > 0 && rec.action.id === actionId);
      });
    }

    function _resetEsimFlowPane(action, statusText) {
      if (!useEsimSplitPane || !esimFlowBody) return null;
      var titleText = action
        ? (action.title || action.id || "Action")
        : "APDU flow";
      esimFlowPane.setAttribute("data-action-id", action && action.id ? action.id : "");
      esimFlowTitle.textContent = titleText;
      _setEsimFlowStatus(statusText || "idle");
      esimFlowBody.innerHTML = "";
      return esimFlowBody;
    }

    function _renderEsimFlowPlaceholder() {
      var body = _resetEsimFlowPane(null, "idle");
      if (!body) return;
      var empty = document.createElement("div");
      empty.className = "cc-esim-flow-placeholder";
      var title = document.createElement("div");
      title.className = "cc-esim-flow-placeholder-title";
      title.textContent = "Select an operation";
      empty.appendChild(title);
      var copy = document.createElement("p");
      copy.textContent = "APDU trace and action output render here.";
      empty.appendChild(copy);
      body.appendChild(empty);
    }

    function _renderEsimFlowError(message, action) {
      var body = _resetEsimFlowPane(action || null, "error");
      if (!body) return;
      body.appendChild(renderErrorBlock(message));
    }

    function _buildEsimFlowResult(action, runningText) {
      var body = _resetEsimFlowPane(action, "running");
      if (!body) return null;
      if (action && action.description) {
        var desc = document.createElement("p");
        desc.className = "cc-action-desc";
        desc.textContent = action.description;
        body.appendChild(desc);
      }
      var result = document.createElement("div");
      result.className = "cc-action-result cc-esim-flow-result cc-action-result--"
        + (action && action.output_kind || "json");
      result.appendChild(loadingEl(runningText || ("running " + (action && (action.title || action.id) || "action") + "...")));
      body.appendChild(result);
      return result;
    }

    async function _runActionInEsimFlowPane(action, inputsMap, options) {
      if (!action) {
        _renderEsimFlowError("Action is not registered.", null);
        return null;
      }
      var opts = options || {};
      _setEsimFlowActiveAction(action);
      var inputs = Object.assign({}, inputsMap || {});
      applyActiveReaderDefault(action, inputs);
      if (ccActionUsesReaderSession(action) && !ccActiveReaderName()) {
        _renderEsimFlowError("Select a reader before running this eSIM action.", action);
        setStatusAction("action blocked: reader required");
        return null;
      }
      var result = _buildEsimFlowResult(action, opts.runningText);
      setStatusAction("action: " + action.id);
      logBus.emit({
        level: "info",
        source: action.id,
        message: "run: starting",
      });
      try {
        var resp = await apiFetch("/api/actions/" + encodeURIComponent(action.id) + "/run", {
          method: "POST",
          body: JSON.stringify({ inputs: inputs }),
        });
        if (!resp || !resp.ok) {
          var errText = resp && resp.error ? resp.error : "unknown error";
          if (result) {
            result.innerHTML = "";
            result.appendChild(renderErrorBlock(errText));
          }
          _setEsimFlowStatus("error");
          logBus.emit({
            level: "error",
            source: action.id,
            message: "run: failed - " + errText,
          });
          return null;
        }
        var data = resp.data || {};
        if (result) {
          result.innerHTML = "";
          renderActionResult(action, data, result);
        }
        _setEsimFlowStatus(opts.doneText || "ok");
        logBus.emit({
          level: "info",
          source: action.id,
          message: "run: ok",
        });
        return data;
      } catch (err) {
        var message = String(err && err.message || err);
        if (result) {
          result.innerHTML = "";
          result.appendChild(renderErrorBlock(message));
        }
        _setEsimFlowStatus("error");
        logBus.emit({
          level: "error",
          source: action.id,
          message: "run: " + message,
        });
        return null;
      }
    }

    function _openEsimActionPane(action) {
      if (!useEsimSplitPane || !esimFlowBody) {
        _openInlineActionPane(action);
        return;
      }
      _setEsimFlowActiveAction(action);
      var body = _resetEsimFlowPane(action, "idle");
      if (!body) return;
      if (action.description) {
        var desc = document.createElement("p");
        desc.className = "cc-action-desc";
        desc.textContent = action.description;
        body.appendChild(desc);
      }

      var form = document.createElement("form");
      form.className = "cc-action-form cc-esim-flow-form";
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

      var result = document.createElement("div");
      result.className = "cc-action-result cc-esim-flow-result cc-action-result--"
        + (action.output_kind || "json");
      form.appendChild(result);

      form.addEventListener("submit", function (event) {
        event.preventDefault();
        runActionFromForm(action, form, status, result);
      });

      (action.inputs || []).forEach(function (field) {
        if (field.kind === "reader" && !ccShouldHideReaderField(action, field)) {
          var sel = form.querySelector('[name="' + field.name + '"]');
          if (sel) prefillReaderSelect(sel);
        }
      });

      body.appendChild(form);

      if (ccActionShouldAutoRunInEsimFlowPane(action)) {
        runBtn.textContent = action.streams ? "Restart" : "Re-run";
        window.setTimeout(function () {
          runActionFromForm(action, form, status, result);
        }, 0);
      }
    }

    function _ensureInlineActionPane() {
      if (inlineActionPane) return inlineActionPane;
      inlineActionPane = document.createElement("section");
      inlineActionPane.className = "cc-inline-action-pane";
      inlineActionPane.hidden = true;
      inlineActionPane.setAttribute("aria-label", "Action panel");

      var head = document.createElement("header");
      head.className = "cc-inline-action-head";
      inlineActionTitle = document.createElement("div");
      inlineActionTitle.className = "cc-inline-action-title";
      inlineActionTitle.textContent = "Action";
      head.appendChild(inlineActionTitle);

      inlineActionStatus = document.createElement("span");
      inlineActionStatus.className = "cc-action-status cc-inline-action-status";
      inlineActionStatus.textContent = "idle";
      head.appendChild(inlineActionStatus);

      var close = document.createElement("button");
      close.type = "button";
      close.className = "cc-inline-action-close";
      close.setAttribute("aria-label", "Close action panel");
      close.title = "Close action panel";
      close.textContent = "\u00d7";
      close.addEventListener("click", function () {
        inlineActionPane.hidden = true;
        _setEsimFlowActiveAction(null);
      });
      head.appendChild(close);
      inlineActionPane.appendChild(head);

      inlineActionBody = document.createElement("div");
      inlineActionBody.className = "cc-inline-action-body";
      inlineActionPane.appendChild(inlineActionBody);
      return inlineActionPane;
    }

    function _openInlineActionPane(action) {
      var pane = _ensureInlineActionPane();
      pane.hidden = false;
      pane.setAttribute("data-action-id", action && action.id ? action.id : "");
      _setEsimFlowActiveAction(action);

      inlineActionTitle.textContent = action.title || action.id || "Action";
      inlineActionStatus.textContent = "idle";
      inlineActionBody.innerHTML = "";

      if (action.description) {
        var desc = document.createElement("p");
        desc.className = "cc-action-desc";
        desc.textContent = action.description;
        inlineActionBody.appendChild(desc);
      }

      var form = document.createElement("form");
      form.className = "cc-action-form cc-inline-action-form";
      (action.inputs || []).forEach(function (field) {
        form.appendChild(buildField(action, field));
      });
      ccEnhanceActionForm(action, form);

      var actionsBar = document.createElement("div");
      actionsBar.className = "inline-actions cc-action-bar";
      var runBtn = document.createElement("button");
      runBtn.type = "submit";
      runBtn.className = "btn btn-primary";
      runBtn.textContent = action.streams ? "Start" : "Run";
      actionsBar.appendChild(runBtn);
      var formStatus = document.createElement("span");
      formStatus.className = "cc-action-status";
      formStatus.textContent = "idle";
      actionsBar.appendChild(formStatus);
      form.appendChild(actionsBar);

      var result = document.createElement("div");
      result.className = "cc-action-result cc-action-result--" + (action.output_kind || "json");
      form.appendChild(result);

      form.addEventListener("submit", function (event) {
        event.preventDefault();
        inlineActionStatus.textContent = "running";
        runActionFromForm(action, form, formStatus, result);
      });

      (action.inputs || []).forEach(function (field) {
        if (field.kind === "reader" && !ccShouldHideReaderField(action, field)) {
          var sel = form.querySelector('[name="' + field.name + '"]');
          if (sel) prefillReaderSelect(sel);
        }
      });

      if (pane._statusObserver) {
        pane._statusObserver.disconnect();
      }
      var observer = new MutationObserver(function () {
        inlineActionStatus.textContent = formStatus.textContent || "idle";
      });
      observer.observe(formStatus, { childList: true, characterData: true, subtree: true });
      pane._statusObserver = observer;

      inlineActionBody.appendChild(form);

      if (ccActionShouldAutoRunOnOpen(action)) {
        runBtn.textContent = "Re-run";
        window.setTimeout(function () {
          if (form.requestSubmit) {
            form.requestSubmit(runBtn);
          } else {
            form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
          }
        }, 0);
      }

      try {
        pane.scrollIntoView({ block: "nearest", behavior: "smooth" });
      } catch (_err) {
        pane.scrollIntoView();
      }
    }

    // Mutation suffixes — actions that are NOT shown in the dashboard
    // button strip (they're covered by dashboard sections or are heavy
    // discovery variants).
    var DASHBOARD_SKIP_SUFFIXES = [
      "scan", "status", "discover", "get_eid", "list_profiles",
      "get_euicc_info2", "get_euicc_info1", "get_all_data",
      "get_configured_data", "get_eim_config", "get_rat",
      "get_certs", "get_smdp", "get_es9", "es9_cert_info",
      "aids", "explain_last", "export_keybag", "record_start",
      "record_stop", "counters", "counter", "resp_log",
      "resp_log_filter", "list_profile_aliases", "error_codes",
      "eim_package_lint", "eim_package_explain", "list_fixtures",
      "protocol_summary",
    ];

    var LOCAL_EIM_OVERVIEW_SUFFIXES = {
      eim_certs_inventory: true,
      eim_package_explain: true,
      eim_package_lint: true,
      hotfolder_fetch: true,
      hotfolder_list: true,
      hotfolder_metadata: true,
      hotfolder_metadata: true,
      issue_package: true,
      list_fixtures: true,
      load_eim_package: true,
      hotfolder_campaign: true,
    };

    var LOCAL_SMDP_OVERVIEW_SUFFIXES = {
      get_certs_inventory: true,
      import_certificate: true,
      load_profile: true,
    };

    function _shouldShowInDashboard(action) {
      if (!isDashboardSubsystem) return true; // show all for non-dashboard subsystems
      var id = (action.id || "").toLowerCase();
      for (var i = 0; i < DASHBOARD_SKIP_SUFFIXES.length; i++) {
        if (id.indexOf(DASHBOARD_SKIP_SUFFIXES[i]) !== -1) return false;
      }
      return true;
    }

    function _shouldShowLocalEimDashboardAction(action) {
      var suffix = ccActionSuffix(String(action && action.id || "").toLowerCase());
      return !LOCAL_EIM_OVERVIEW_SUFFIXES[suffix] && _shouldShowInDashboard(action);
    }

    function _shouldShowLocalSmdpDashboardAction(action) {
      var suffix = ccActionSuffix(String(action && action.id || "").toLowerCase());
      return !LOCAL_SMDP_OVERVIEW_SUFFIXES[suffix] && _shouldShowInDashboard(action);
    }

    function _profileTarget(profile) {
      if (!profile) return "";
      return String(
        profile.aid
        || profile.isdp_aid
        || profile.isd_p_aid
        || profile.iccid
        || profile.nickname
        || profile.profile_name
        || profile.alias
        || ""
      );
    }

    function _profileState(profile) {
      return String(profile && profile.state || "").trim();
    }

    function _profileEnabled(profile) {
      var state = _profileState(profile).toLowerCase();
      return state === "enabled" || state === "enable" || state === "01";
    }

    function _profileLabel(profile) {
      return String(
        profile && (profile.nickname || profile.profile_name || profile.iccid || profile.aid)
        || "Profile"
      );
    }

    function _profileConfirmText(operation, profile, target) {
      var label = _profileLabel(profile);
      if (operation === "enable") {
        return "Enable " + label + "? This runs the card profile lifecycle flow and disables the currently enabled profile if required.";
      }
      if (operation === "disable") {
        return "Disable " + label + "?";
      }
      return "Delete " + label + " from the eUICC? This cannot be undone.";
    }

    function _profileLifecycleActionId(operation) {
      var prefix = subsystem === "SCP11 Local" ? "scp11_local" : "scp11_live";
      return prefix + "." + operation + "_profile";
    }

    function _profileLifecycleInputName(action) {
      var fields = (action && action.inputs) || [];
      for (var i = 0; i < fields.length; i++) {
        if (fields[i] && fields[i].name === "identifier") return "identifier";
      }
      return "target";
    }

    function _profileLifecycleNeedsConfirm(action) {
      var fields = (action && action.inputs) || [];
      for (var i = 0; i < fields.length; i++) {
        if (fields[i] && fields[i].name === "confirm") return true;
      }
      return false;
    }

    async function _runProfileLifecycle(action, operation, profile, card, statusEl) {
      if (!action) {
        if (statusEl) statusEl.textContent = "action unavailable";
        return;
      }
      var target = _profileTarget(profile);
      if (!target) {
        if (statusEl) statusEl.textContent = "missing target";
        return;
      }
      if (window.confirm && !window.confirm(_profileConfirmText(operation, profile, target))) {
        return;
      }
      if (ccActionUsesReaderSession(action) && !ccActiveReaderName()) {
        if (statusEl) statusEl.textContent = "select reader";
        setStatusAction("action blocked: reader required");
        return;
      }
      var buttons = card ? card.querySelectorAll(".cc-esim-profile-action") : [];
      buttons.forEach(function (button) { button.disabled = true; });
      if (statusEl) statusEl.textContent = operation + " running";
      setStatusAction("action: " + action.id);
      logBus.emit({
        level: "info",
        source: action.id,
        message: operation + ": starting",
      });
      try {
        var inputs = {};
        inputs[_profileLifecycleInputName(action)] = target;
        if (_profileLifecycleNeedsConfirm(action)) {
          inputs.confirm = true;
        }
        var data = await _runActionInEsimFlowPane(action, inputs, {
          runningText: operation + " profile",
          doneText: operation + " ok",
        });
        if (!data) {
          throw new Error("action failed");
        }
        if (statusEl) statusEl.textContent = operation + " ok";
        logBus.emit({
          level: "info",
          source: action.id,
          message: operation + ": ok",
        });
        refreshDashboard({ quiet: true });
      } catch (err) {
        if (statusEl) statusEl.textContent = operation + " error";
        logBus.emit({
          level: "error",
          source: action.id,
          message: operation + ": failed - " + String(err && err.message || err),
        });
      } finally {
        buttons.forEach(function (button) { button.disabled = false; });
      }
    }

    function _buildProfileControlButton(action, operation, label, profile, card, statusEl) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "cc-esim-profile-action cc-esim-profile-action--" + operation;
      btn.textContent = label;
      btn.disabled = !action || !_profileTarget(profile);
      btn.addEventListener("click", function (event) {
        event.preventDefault();
        event.stopPropagation();
        _runProfileLifecycle(action, operation, profile, card, statusEl);
      });
      return btn;
    }

    function _buildProfileCard(profile) {
      var card = document.createElement("details");
      card.className = "cc-esim-profile-card";
      var target = _profileTarget(profile);
      if (target) card.setAttribute("data-profile-target", target);

      var summary = document.createElement("summary");
      summary.className = "cc-esim-profile-summary";

      var main = document.createElement("div");
      main.className = "cc-esim-profile-main";
      var state = document.createElement("span");
      state.className = "cc-esim-profile-state"
        + (_profileEnabled(profile) ? " is-enabled" : " is-disabled");
      state.textContent = _profileState(profile) || "unknown";
      main.appendChild(state);
      var name = document.createElement("span");
      name.className = "cc-esim-profile-name";
      name.textContent = _profileLabel(profile);
      main.appendChild(name);
      var ident = document.createElement("span");
      ident.className = "cc-esim-profile-ident";
      ident.textContent = target || "no profile target";
      main.appendChild(ident);
      summary.appendChild(main);

      var controls = document.createElement("div");
      controls.className = "cc-esim-profile-controls";
      var statusEl = document.createElement("span");
      statusEl.className = "cc-esim-profile-status";
      statusEl.textContent = "idle";
      if (_profileEnabled(profile)) {
        controls.appendChild(_buildProfileControlButton(
          ccFindActionById(actions, _profileLifecycleActionId("disable")),
          "disable",
          "Disable",
          profile,
          card,
          statusEl
        ));
      } else {
        controls.appendChild(_buildProfileControlButton(
          ccFindActionById(actions, _profileLifecycleActionId("enable")),
          "enable",
          "Enable",
          profile,
          card,
          statusEl
        ));
      }
      controls.appendChild(_buildProfileControlButton(
        ccFindActionById(actions, _profileLifecycleActionId("delete")),
        "delete",
        "Delete",
        profile,
        card,
        statusEl
      ));
      controls.appendChild(statusEl);
      summary.appendChild(controls);
      card.appendChild(summary);

      var meta = document.createElement("div");
      meta.className = "cc-esim-profile-meta";
      _dashKv(meta, "Class", profile.profile_class || "");
      _dashKv(meta, "ICCID", profile.iccid || "");
      _dashKv(meta, "AID", profile.aid || "");
      if (profile.nickname || profile.profile_name) {
        _dashKv(meta, "Nickname", profile.nickname || profile.profile_name);
      }
      card.appendChild(meta);
      return card;
    }

    function _renderDashboard(snapshot) {
      if (!snapshot) return;
      ccSetProfileTargetCache(subsystem, scopedReader, snapshot.profiles || []);
      dashBody.innerHTML = "";

      // --- SCP03: card_info response (flat fields: iccid, eid, atr_hex, standard) ---
      if (snapshot.atr_hex && !snapshot.profiles && !snapshot.configured_decoded) {
        var sec = document.createElement("div");
        sec.className = "cc-dash-section";
        var hdr = document.createElement("div");
        hdr.className = "cc-dash-section-header";
        hdr.textContent = "Card Identity";
        sec.appendChild(hdr);
        var body = document.createElement("div");
        body.className = "cc-dash-section-body";
        if (snapshot.atr_hex) _dashKv(body, "ATR", snapshot.atr_hex);
        if (snapshot.iccid) _dashKv(body, "ICCID", snapshot.iccid);
        if (snapshot.eid) _dashKv(body, "eID", snapshot.eid);
        if (snapshot.standard) {
          var stdValue = String(snapshot.standard);
          if (snapshot.reset_ok === false) stdValue += " (reset failed)";
          _dashKv(body, "Standard", stdValue);
        }
        sec.appendChild(body);
        dashBody.appendChild(sec);

        if (snapshot.session_id) {
          var noteSec = document.createElement("div");
          noteSec.className = "cc-dash-section";
          var noteHdr = document.createElement("div");
          noteHdr.className = "cc-dash-section-header";
          noteHdr.textContent = "Session";
          noteSec.appendChild(noteHdr);
          var noteBody = document.createElement("div");
          noteBody.className = "cc-dash-section-body";
          _dashKv(noteBody, "Session ID", String(snapshot.session_id).substring(0, 8) + "…");
          noteSec.appendChild(noteBody);
          dashBody.appendChild(noteSec);
        }
        return; // SCP03 card_info handled — skip eSIM sections below
      }

      // --- Card Identity ---
      if (snapshot.eid) {
        var sec = document.createElement("div");
        sec.className = "cc-dash-section";
        var hdr = document.createElement("div");
        hdr.className = "cc-dash-section-header";
        hdr.textContent = "Card Identity";
        sec.appendChild(hdr);
        var body = document.createElement("div");
        body.className = "cc-dash-section-body";
        _dashKv(body, "eID", snapshot.eid);
        if (snapshot.issuer_name) {
          _dashKv(body, "Issuer (eCASD)", snapshot.issuer_name
            + (snapshot.issuer_number ? " (" + snapshot.issuer_number + ")" : ""));
        }
        sec.appendChild(body);
        dashBody.appendChild(sec);
      }

      // --- Profiles ---
      if (snapshot.profiles && snapshot.profiles.length > 0) {
        var sec = document.createElement("div");
        sec.className = "cc-dash-section";
        var hdr = document.createElement("div");
        hdr.className = "cc-dash-section-header";
        hdr.textContent = "Profiles (" + snapshot.profiles.length + ")";
        sec.appendChild(hdr);
        var body = document.createElement("div");
        body.className = "cc-dash-section-body";
        var profiles = document.createElement("div");
        profiles.className = "cc-esim-profile-list";
        snapshot.profiles.forEach(function (p) {
          profiles.appendChild(_buildProfileCard(p));
        });
        body.appendChild(profiles);
        sec.appendChild(body);
        dashBody.appendChild(sec);
      } else if (snapshot.profile_count > 0) {
        var sec = document.createElement("div");
        sec.className = "cc-dash-section";
        var hdr = document.createElement("div");
        hdr.className = "cc-dash-section-header";
        hdr.textContent = "Profiles";
        sec.appendChild(hdr);
        var body = document.createElement("div");
        body.className = "cc-dash-section-body";
        _dashKv(body, "Profile count", String(snapshot.profile_count));
        sec.appendChild(body);
        dashBody.appendChild(sec);
      }

      // --- euiccConfigurationData ---
      var cfg = snapshot.configured_decoded || snapshot.configured || snapshot.configured_data;
      if (cfg && Object.keys(cfg).length > 0) {
        var sec = document.createElement("div");
        sec.className = "cc-dash-section";
        var hdr = document.createElement("div");
        hdr.className = "cc-dash-section-header";
        hdr.textContent = "euiccConfigurationData";
        sec.appendChild(hdr);
        var body = document.createElement("div");
        body.className = "cc-dash-section-body";
        if (cfg.default_smdp) _dashKv(body, "Default SM-DP+", cfg.default_smdp);
        if (cfg.root_smds_primary) _dashKv(body, "Root SM-DS", cfg.root_smds_primary);
        if (cfg.root_smds_additional && cfg.root_smds_additional.length > 0) {
          _dashKv(body, "Additional SM-DS", cfg.root_smds_additional.join(", "));
        }
        if (cfg.allowed_ci_pkid && cfg.allowed_ci_pkid.length > 0) {
          _dashKv(body, "Allowed CI PKIDs", cfg.allowed_ci_pkid.join(", "));
        }
        sec.appendChild(body);
        dashBody.appendChild(sec);
      }

      // --- eUICC Info2 ---
      if (snapshot.euicc_info2_summary && Object.keys(snapshot.euicc_info2_summary).length > 0) {
        var sec = document.createElement("div");
        sec.className = "cc-dash-section";
        var hdr = document.createElement("div");
        hdr.className = "cc-dash-section-header";
        hdr.textContent = "eUICC Info2";
        sec.appendChild(hdr);
        var body = document.createElement("div");
        body.className = "cc-dash-section-body";
        Object.keys(snapshot.euicc_info2_summary).forEach(function (k) {
          _dashKv(body, k, String(snapshot.euicc_info2_summary[k]));
        });
        sec.appendChild(body);
        dashBody.appendChild(sec);
      }

      // --- eIM Configuration ---
      var eimEntries = null;
      if (snapshot.eim_summary && snapshot.eim_summary.entries && snapshot.eim_summary.entries.length > 0) {
        eimEntries = snapshot.eim_summary.entries;
      } else if (snapshot.eim_configuration && typeof snapshot.eim_configuration === "string" && snapshot.eim_configuration.length > 20) {
        // Raw hex — note presence but don't decode client-side
        var sec = document.createElement("div");
        sec.className = "cc-dash-section";
        var hdr = document.createElement("div");
        hdr.className = "cc-dash-section-header";
        hdr.textContent = "eIM Configuration";
        sec.appendChild(hdr);
        var body = document.createElement("div");
        body.className = "cc-dash-section-body";
        _dashKv(body, "Raw payload", snapshot.eim_configuration.substring(0, 40) + "…");
        sec.appendChild(body);
        dashBody.appendChild(sec);
      }
      if (eimEntries) {
        var sec = document.createElement("div");
        sec.className = "cc-dash-section";
        var hdr = document.createElement("div");
        hdr.className = "cc-dash-section-header";
        hdr.textContent = "eIM Configuration (" + eimEntries.length + " entries)";
        sec.appendChild(hdr);
        var body = document.createElement("div");
        body.className = "cc-dash-section-body";
        eimEntries.forEach(function (entry, i) {
          var label = "Entry " + (i + 1);
          if (entry.eim_fqdn) label += " — " + entry.eim_fqdn;
          if (entry.eim_id) label += " (" + entry.eim_id + ")";
          var div = document.createElement("div");
          div.className = "cc-dash-kv";
          var spanL = document.createElement("span");
          spanL.className = "cc-dash-kv-label";
          spanL.textContent = label;
          div.appendChild(spanL);
          body.appendChild(div);
        });
        sec.appendChild(body);
        dashBody.appendChild(sec);
      }

      // --- Notification count ---
      if (snapshot.notification_count > 0) {
        var sec = document.createElement("div");
        sec.className = "cc-dash-section";
        var hdr = document.createElement("div");
        hdr.className = "cc-dash-section-header";
        hdr.textContent = "Notifications";
        sec.appendChild(hdr);
        var body = document.createElement("div");
        body.className = "cc-dash-section-body";
        _dashKv(body, "Pending", String(snapshot.notification_count));
        sec.appendChild(body);
        dashBody.appendChild(sec);
      }
    }

    function _dashKv(parent, label, value) {
      var div = document.createElement("div");
      div.className = "cc-dash-kv";
      var spanL = document.createElement("span");
      spanL.className = "cc-dash-kv-label";
      spanL.textContent = label + ":";
      div.appendChild(spanL);
      var spanV = document.createElement("span");
      spanV.className = "cc-dash-kv-value";
      spanV.textContent = String(value || "");
      div.appendChild(spanV);
      parent.appendChild(div);
    }

    function _localEimAction(actionId) {
      return ccFindActionById(actions, actionId);
    }

    function _localEimText(value) {
      return String(value == null ? "" : value).trim();
    }

    function _localEimShortPath(pathValue) {
      var text = _localEimText(pathValue);
      if (!text) return "-";
      var normalized = text.replace(/\\/g, "/");
      var parts = normalized.split("/").filter(function (part) {
        return part.length > 0;
      });
      var tail = parts.slice(Math.max(0, parts.length - 3)).join("/");
      if (!tail) tail = text;
      return tail.length > 72 ? "..." + tail.slice(tail.length - 69) : tail;
    }

    function _localEimPathField(labelText, kind, placeholderText) {
      var wrap = document.createElement("label");
      wrap.className = "cc-local-eim-path";
      var label = document.createElement("span");
      label.className = "cc-local-eim-path-label";
      label.textContent = labelText;
      wrap.appendChild(label);

      var input = document.createElement("input");
      input.type = "text";
      input.className = "cc-local-eim-path-input cc-path-input";
      input.placeholder = placeholderText || "";
      input.autocomplete = "off";
      var field = { kind: kind || "path", name: labelText, placeholder: placeholderText || "" };
      var choosePath = async function () {
        if (typeof pickForField !== "function") return;
        var chosen = await pickForField(field);
        if (!chosen) return;
        input.value = chosen;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      };
      input.addEventListener("dblclick", choosePath);

      var row = document.createElement("div");
      row.className = "cc-path-row cc-local-eim-path-row";
      row.appendChild(input);
      var browse = document.createElement("button");
      browse.type = "button";
      browse.className = "btn btn-small cc-path-browse";
      browse.textContent = "Browse...";
      browse.addEventListener("click", choosePath);
      row.appendChild(browse);
      wrap.appendChild(row);
      if (typeof enableFilePathDrop === "function") {
        enableFilePathDrop(input);
      }
      return { wrap: wrap, input: input };
    }

    function _localSmdpAction(actionId) {
      return ccFindActionById(actions, actionId);
    }

    function _buildLocalSmdpOverviewPanel() {
      var panel = document.createElement("section");
      panel.className = "cc-local-smdp-overview cc-local-eim-overview";
      panel.setAttribute("data-local-smdp-overview", "1");

      var head = document.createElement("div");
      head.className = "cc-local-eim-head cc-local-smdp-head";
      var title = document.createElement("div");
      title.className = "cc-local-eim-title cc-local-smdp-title";
      title.textContent = "Local SM-DP+";
      head.appendChild(title);
      var status = document.createElement("span");
      status.className = "cc-local-eim-status cc-local-smdp-status";
      status.textContent = "idle";
      head.appendChild(status);
      panel.appendChild(head);

      var inputs = document.createElement("div");
      inputs.className = "cc-local-eim-inputs cc-local-smdp-inputs";
      var profilePath = _localEimPathField("Profile", "path", ".bpp / .der / .hex");
      var certPath = _localEimPathField("Certificate", "path", "DPauth or DPpb cert");
      var keyPath = _localEimPathField("Private key", "path", "(optional)");
      inputs.appendChild(profilePath.wrap);
      inputs.appendChild(certPath.wrap);
      inputs.appendChild(keyPath.wrap);
      panel.appendChild(inputs);

      var tools = document.createElement("div");
      tools.className = "cc-local-eim-tools cc-local-smdp-tools";
      panel.appendChild(tools);

      var roleSelect = document.createElement("select");
      roleSelect.className = "cc-local-smdp-role";
      roleSelect.setAttribute("aria-label", "Certificate role");
      ["DPauth", "DPpb", "auto"].forEach(function (roleName) {
        var option = document.createElement("option");
        option.value = roleName;
        option.textContent = roleName;
        roleSelect.appendChild(option);
      });
      tools.appendChild(roleSelect);

      var summary = document.createElement("div");
      summary.className = "cc-local-eim-summary cc-local-smdp-summary";
      var authHost = document.createElement("div");
      authHost.className = "cc-local-eim-card cc-local-smdp-card cc-local-smdp-card--auth";
      var pbHost = document.createElement("div");
      pbHost.className = "cc-local-eim-card cc-local-smdp-card cc-local-smdp-card--pb";
      summary.appendChild(authHost);
      summary.appendChild(pbHost);
      panel.appendChild(summary);

      var resultHost = document.createElement("div");
      resultHost.className = "cc-local-eim-result cc-local-smdp-result";
      panel.appendChild(resultHost);

      var toolButtons = [];
      function setBusy(busy, text) {
        panel.classList.toggle("is-busy", !!busy);
        status.textContent = text || (busy ? "running" : "idle");
        toolButtons.forEach(function (button) {
          button.disabled = !!busy;
        });
        roleSelect.disabled = !!busy;
      }

      async function runLocalSmdpAction(actionId, inputsMap, options) {
        var action = _localSmdpAction(actionId);
        if (!action) {
          throw new Error(actionId + " is not registered.");
        }
        var opts = options || {};
        setBusy(true, opts.runningText || "running");
        try {
          var data;
          if (opts.renderResult === false) {
            var silentInputs = Object.assign({}, inputsMap || {});
            applyActiveReaderDefault(action, silentInputs);
            var resp = await apiFetch("/api/actions/" + encodeURIComponent(action.id) + "/run", {
              method: "POST",
              body: JSON.stringify({ inputs: silentInputs }),
            });
            if (!resp || !resp.ok) {
              throw new Error(resp && resp.error ? resp.error : "unknown error");
            }
            data = resp.data || {};
          } else {
            data = await _runActionInEsimFlowPane(action, inputsMap || {}, {
              runningText: opts.runningText || "running",
              doneText: opts.doneText || "ok",
            });
          }
          resultHost.innerHTML = "";
          if (!data) {
            setBusy(false, "error");
            return null;
          }
          setBusy(false, opts.doneText || "ok");
          return data;
        } catch (err) {
          resultHost.innerHTML = "";
          if (opts.renderResult === false) {
            resultHost.appendChild(renderErrorBlock(String(err && err.message || err)));
          } else {
            _renderEsimFlowError(String(err && err.message || err), action);
          }
          setBusy(false, "error");
          return null;
        }
      }

      function addTool(iconText, labelText, titleText, handler, primary) {
        var button = document.createElement("button");
        button.type = "button";
        button.className = "cc-local-eim-tool cc-local-smdp-tool" + (primary ? " is-primary" : "");
        button.title = titleText || labelText;
        var icon = document.createElement("span");
        icon.className = "cc-local-eim-tool-icon cc-local-smdp-tool-icon";
        icon.setAttribute("aria-hidden", "true");
        icon.textContent = iconText || ">";
        button.appendChild(icon);
        var label = document.createElement("span");
        label.className = "cc-local-eim-tool-label cc-local-smdp-tool-label";
        label.textContent = labelText;
        button.appendChild(label);
        button.addEventListener("click", function (event) {
          event.preventDefault();
          handler();
        });
        tools.appendChild(button);
        toolButtons.push(button);
        return button;
      }

      function appendSmdpKv(parent, labelText, valueText) {
        var row = document.createElement("div");
        row.className = "cc-local-eim-kv cc-local-smdp-kv";
        var k = document.createElement("span");
        k.className = "cc-local-eim-k cc-local-smdp-k";
        k.textContent = labelText;
        row.appendChild(k);
        var v = document.createElement("span");
        v.className = "cc-local-eim-v cc-local-smdp-v";
        v.textContent = _localEimText(valueText) || "-";
        row.appendChild(v);
        parent.appendChild(row);
      }

      function renderEmptySmdpCard(host, titleText, messageText) {
        host.innerHTML = "";
        var h = document.createElement("div");
        h.className = "cc-local-eim-card-title cc-local-smdp-card-title";
        h.textContent = titleText;
        host.appendChild(h);
        var empty = document.createElement("div");
        empty.className = "cc-local-eim-empty cc-local-smdp-empty";
        empty.textContent = messageText;
        host.appendChild(empty);
      }

      function renderRoleCard(host, titleText, selected, count) {
        host.innerHTML = "";
        var h = document.createElement("div");
        h.className = "cc-local-eim-card-title cc-local-smdp-card-title";
        h.textContent = titleText;
        host.appendChild(h);
        var body = document.createElement("div");
        body.className = "cc-local-eim-card-body cc-local-smdp-card-body";
        appendSmdpKv(body, "Cert", _localEimShortPath(selected && selected.certificate_path));
        appendSmdpKv(body, "Key", _localEimShortPath(selected && selected.private_key_path));
        appendSmdpKv(body, "Mode", selected && selected.selection_reason);
        appendSmdpKv(body, "Count", count);
        host.appendChild(body);
      }

      function renderInventory(data) {
        var inventory = (data && data.inventory) || data || {};
        var authRecords = Array.isArray(inventory.auth_records) ? inventory.auth_records : [];
        var pbRecords = Array.isArray(inventory.pb_records) ? inventory.pb_records : [];
        renderRoleCard(authHost, "DPauth", inventory.selected_auth || {}, authRecords.length);
        renderRoleCard(pbHost, "DPpb", inventory.selected_pb || {}, pbRecords.length);
      }

      async function refreshInventory(renderResult) {
        var data = await runLocalSmdpAction("scp11_local.get_certs_inventory", {
          reader: scopedReader,
        }, {
          runningText: "loading certs",
          doneText: "certs ready",
          renderResult: renderResult !== false,
        });
        if (data) renderInventory(data);
      }

      localOverviewRefreshers.push(function () {
        return refreshInventory(false);
      });

      async function importCertificate() {
        var action = _localSmdpAction("scp11_local.import_certificate");
        if (!action) return;
        var field = { kind: "path", name: "certificate_path", placeholder: "DPauth or DPpb cert" };
        var chosen = "";
        if (typeof pickForField === "function") {
          chosen = await pickForField(field);
        }
        if (!chosen) return;
        certPath.input.value = chosen;
        certPath.input.dispatchEvent(new Event("change", { bubbles: true }));
        var data = await runLocalSmdpAction("scp11_local.import_certificate", {
          certificate_path: chosen,
          private_key_path: _localEimText(keyPath.input.value),
          certificate_role: roleSelect.value || "DPauth",
        }, { runningText: "importing cert" });
        if (data) renderInventory(data.inventory || data);
      }

      addTool("↻", "Refresh", "Refresh local SM-DP+ certificate state", function () {
        refreshInventory(true);
      });
      addTool("＋", "Import cert", "Choose and persist a local SM-DP+ certificate", importCertificate, true);
      addTool("⊙", "Inventory", "Open certificate inventory", function () {
        refreshInventory(true);
      });
      addTool("↓", "Load profile", "Load the selected profile to the card", function () {
        var pathValue = _localEimText(profilePath.input.value);
        if (!pathValue) {
          resultHost.innerHTML = "";
          _renderEsimFlowError(
            "Select a profile package first.",
            _localSmdpAction("scp11_local.load_profile")
          );
          return;
        }
        runLocalSmdpAction("scp11_local.load_profile", {
          reader: scopedReader,
          profile_path: pathValue,
        }, { runningText: "loading profile" });
      }, true);

      renderEmptySmdpCard(authHost, "DPauth", "Loading...");
      renderEmptySmdpCard(pbHost, "DPpb", "Loading...");
      window.setTimeout(function () { refreshInventory(false); }, 0);
      return panel;
    }

    function _buildLocalEimOverviewPanel() {
      var panel = document.createElement("section");
      panel.className = "cc-local-eim-overview";
      panel.setAttribute("data-local-eim-overview", "1");

      var state = {
        queue: null,
        certs: null,
        nextFile: "",
      };

      var head = document.createElement("div");
      head.className = "cc-local-eim-head";
      var title = document.createElement("div");
      title.className = "cc-local-eim-title";
      title.textContent = "Local eIM";
      head.appendChild(title);
      var status = document.createElement("span");
      status.className = "cc-local-eim-status";
      status.textContent = "idle";
      head.appendChild(status);
      panel.appendChild(head);

      var inputs = document.createElement("div");
      inputs.className = "cc-local-eim-inputs";
      var packagePath = _localEimPathField("Package", "path", "package JSON");
      var certPath = _localEimPathField("Signing cert", "path", "CERT_S_EIMsign.pem");
      var hotfolderPath = _localEimPathField("Hotfolder", "directory", "(default)");
      inputs.appendChild(packagePath.wrap);
      inputs.appendChild(certPath.wrap);
      inputs.appendChild(hotfolderPath.wrap);
      panel.appendChild(inputs);

      var tools = document.createElement("div");
      tools.className = "cc-local-eim-tools";
      panel.appendChild(tools);

      var summary = document.createElement("div");
      summary.className = "cc-local-eim-summary";
      var certHost = document.createElement("div");
      certHost.className = "cc-local-eim-card cc-local-eim-card--certs";
      var queueHost = document.createElement("div");
      queueHost.className = "cc-local-eim-card cc-local-eim-card--queue";
      summary.appendChild(certHost);
      summary.appendChild(queueHost);
      panel.appendChild(summary);

      var resultHost = document.createElement("div");
      resultHost.className = "cc-local-eim-result";
      panel.appendChild(resultHost);

      var toolButtons = [];
      function setBusy(busy, text) {
        panel.classList.toggle("is-busy", !!busy);
        status.textContent = text || (busy ? "running" : "idle");
        toolButtons.forEach(function (button) {
          button.disabled = !!busy;
        });
      }

      function packageInputValue() {
        return _localEimText(packagePath.input.value) || state.nextFile || "";
      }

      function hotfolderInputValue() {
        return _localEimText(hotfolderPath.input.value);
      }

      function certInputValue() {
        return _localEimText(certPath.input.value);
      }

      async function runLocalEimAction(actionId, inputsMap, options) {
        var action = _localEimAction(actionId);
        if (!action) {
          throw new Error(actionId + " is not registered.");
        }
        var opts = options || {};
        setBusy(true, opts.runningText || "running");
        try {
          var data;
          if (opts.renderResult === false) {
            var silentInputs = Object.assign({}, inputsMap || {});
            applyActiveReaderDefault(action, silentInputs);
            var resp = await apiFetch("/api/actions/" + encodeURIComponent(action.id) + "/run", {
              method: "POST",
              body: JSON.stringify({ inputs: silentInputs }),
            });
            if (!resp || !resp.ok) {
              throw new Error(resp && resp.error ? resp.error : "unknown error");
            }
            data = resp.data || {};
          } else {
            data = await _runActionInEsimFlowPane(action, inputsMap || {}, {
              runningText: opts.runningText || "running",
              doneText: opts.doneText || "ok",
            });
          }
          resultHost.innerHTML = "";
          if (!data) {
            setBusy(false, "error");
            return null;
          }
          setBusy(false, opts.doneText || "ok");
          return data;
        } catch (err) {
          resultHost.innerHTML = "";
          if (opts.renderResult === false) {
            resultHost.appendChild(renderErrorBlock(String(err && err.message || err)));
          } else {
            _renderEsimFlowError(String(err && err.message || err), action);
          }
          setBusy(false, "error");
          return null;
        }
      }

      function addTool(iconText, labelText, titleText, handler, primary) {
        var button = document.createElement("button");
        button.type = "button";
        button.className = "cc-local-eim-tool" + (primary ? " is-primary" : "");
        button.title = titleText || labelText;
        var icon = document.createElement("span");
        icon.className = "cc-local-eim-tool-icon";
        icon.setAttribute("aria-hidden", "true");
        icon.textContent = iconText || ">";
        button.appendChild(icon);
        var label = document.createElement("span");
        label.className = "cc-local-eim-tool-label";
        label.textContent = labelText;
        button.appendChild(label);
        button.addEventListener("click", function (event) {
          event.preventDefault();
          handler();
        });
        tools.appendChild(button);
        toolButtons.push(button);
        return button;
      }

      function renderEmptyCard(host, titleText, messageText) {
        host.innerHTML = "";
        var h = document.createElement("div");
        h.className = "cc-local-eim-card-title";
        h.textContent = titleText;
        host.appendChild(h);
        var empty = document.createElement("div");
        empty.className = "cc-local-eim-empty";
        empty.textContent = messageText;
        host.appendChild(empty);
      }

      function appendLocalEimKv(parent, labelText, valueText) {
        var row = document.createElement("div");
        row.className = "cc-local-eim-kv";
        var k = document.createElement("span");
        k.className = "cc-local-eim-k";
        k.textContent = labelText;
        row.appendChild(k);
        var v = document.createElement("span");
        v.className = "cc-local-eim-v";
        v.textContent = _localEimText(valueText) || "-";
        row.appendChild(v);
        parent.appendChild(row);
      }

      function renderCertInventory(data) {
        state.certs = data || {};
        certHost.innerHTML = "";
        var h = document.createElement("div");
        h.className = "cc-local-eim-card-title";
        h.textContent = "Signing certificate";
        certHost.appendChild(h);

        var selected = (data && data.selected) || {};
        var selectedPath = _localEimText(selected.path);
        var body = document.createElement("div");
        body.className = "cc-local-eim-card-body";
        appendLocalEimKv(body, "Selected", _localEimShortPath(selectedPath));
        appendLocalEimKv(body, "Reason", selected.reason || "-");
        var pkids = Array.isArray(selected.root_ci_pkids)
          ? selected.root_ci_pkids.join(", ")
          : "";
        appendLocalEimKv(body, "Root CI", pkids || "-");
        appendLocalEimKv(body, "Private key", _localEimShortPath(selected.private_key_path || ""));
        certHost.appendChild(body);

        var selectedActions = document.createElement("div");
        selectedActions.className = "cc-local-eim-mini-actions";
        var useSelected = document.createElement("button");
        useSelected.type = "button";
        useSelected.className = "cc-local-eim-mini-btn";
        useSelected.textContent = "Use";
        useSelected.disabled = !selectedPath;
        useSelected.addEventListener("click", function () {
          certPath.input.value = selectedPath;
          certPath.input.dispatchEvent(new Event("change", { bubbles: true }));
          status.textContent = "cert selected";
        });
        selectedActions.appendChild(useSelected);
        var clearSelected = document.createElement("button");
        clearSelected.type = "button";
        clearSelected.className = "cc-local-eim-mini-btn";
        clearSelected.textContent = "Auto";
        clearSelected.addEventListener("click", function () {
          certPath.input.value = "";
          certPath.input.dispatchEvent(new Event("change", { bubbles: true }));
          refreshCerts();
        });
        selectedActions.appendChild(clearSelected);
        certHost.appendChild(selectedActions);

        var rows = Array.isArray(data && data.rows) ? data.rows : [];
        if (rows.length > 0) {
          var list = document.createElement("div");
          list.className = "cc-local-eim-cert-list";
          rows.slice(0, 4).forEach(function (row) {
            var item = document.createElement("button");
            item.type = "button";
            item.className = "cc-local-eim-cert-row";
            item.title = _localEimText(row.path);
            var name = document.createElement("span");
            name.className = "cc-local-eim-cert-name";
            name.textContent = row.subject_cn || _localEimShortPath(row.path);
            item.appendChild(name);
            var meta = document.createElement("span");
            meta.className = "cc-local-eim-cert-meta";
            meta.textContent = row.curve || row.source || "-";
            item.appendChild(meta);
            item.addEventListener("click", function () {
              certPath.input.value = _localEimText(row.path);
              certPath.input.dispatchEvent(new Event("change", { bubbles: true }));
              refreshCerts();
            });
            list.appendChild(item);
          });
          certHost.appendChild(list);
        }
      }

      function queueRowAction(labelText, actionId, rowPath) {
        var button = document.createElement("button");
        button.type = "button";
        button.className = "cc-local-eim-row-btn";
        button.textContent = labelText;
        button.addEventListener("click", function () {
          if (actionId === "eim_local.load_eim_package") {
            runLocalEimAction(actionId, {
              package_path: rowPath,
              cert_path: certInputValue(),
            }, { runningText: "loading package" });
          } else {
            runLocalEimAction(actionId, {
              package_path: rowPath,
            }, { runningText: "checking package" });
          }
        });
        return button;
      }

      function renderQueue(data) {
        state.queue = data || {};
        state.nextFile = _localEimText(data && data.next_file);
        queueHost.innerHTML = "";
        var h = document.createElement("div");
        h.className = "cc-local-eim-card-title";
        h.textContent = "Queued packages";
        queueHost.appendChild(h);

        var body = document.createElement("div");
        body.className = "cc-local-eim-card-body";
        appendLocalEimKv(body, "Hotfolder", _localEimShortPath(data && data.hotfolder_dir));
        appendLocalEimKv(body, "Count", data && data.package_count);
        appendLocalEimKv(body, "Next", _localEimShortPath(state.nextFile));
        appendLocalEimKv(body, "Result", data && data.eim_result_name);
        queueHost.appendChild(body);

        var rows = Array.isArray(data && data.queue_preview) ? data.queue_preview : [];
        if (rows.length === 0) {
          var empty = document.createElement("div");
          empty.className = "cc-local-eim-empty";
          empty.textContent = "Queue empty";
          queueHost.appendChild(empty);
          return;
        }

        var list = document.createElement("div");
        list.className = "cc-local-eim-queue-list";
        rows.slice(0, 6).forEach(function (row) {
          var rowPath = _localEimText(row.path);
          var item = document.createElement("div");
          item.className = "cc-local-eim-queue-row";
          var main = document.createElement("div");
          main.className = "cc-local-eim-queue-main";
          var name = document.createElement("span");
          name.className = "cc-local-eim-queue-name";
          name.textContent = _localEimText(row.name) || _localEimShortPath(rowPath);
          main.appendChild(name);
          var meta = document.createElement("span");
          meta.className = "cc-local-eim-queue-meta";
          meta.textContent = [
            _localEimText(row.package_id),
            _localEimText(row.eim_id),
          ].filter(function (part) { return part.length > 0; }).join(" · ") || "-";
          main.appendChild(meta);
          item.appendChild(main);
          var rowActions = document.createElement("div");
          rowActions.className = "cc-local-eim-row-actions";
          rowActions.appendChild(queueRowAction("Load", "eim_local.load_eim_package", rowPath));
          rowActions.appendChild(queueRowAction("Lint", "eim_local.eim_package_lint", rowPath));
          rowActions.appendChild(queueRowAction("Explain", "eim_local.eim_package_explain", rowPath));
          item.appendChild(rowActions);
          list.appendChild(item);
        });
        queueHost.appendChild(list);
      }

      async function refreshCerts() {
        var data = await runLocalEimAction("eim_local.eim_certs_inventory", {
          package_path: packageInputValue(),
          cert_path: certInputValue(),
        }, {
          runningText: "loading certs",
          doneText: "certs ready",
          renderResult: false,
        });
        if (data) renderCertInventory(data);
      }

      async function refreshQueue() {
        var data = await runLocalEimAction("eim_local.hotfolder_metadata", {
          hotfolder_dir: hotfolderInputValue(),
        }, {
          runningText: "loading queue",
          doneText: "queue ready",
          renderResult: false,
        });
        if (data) renderQueue(data);
      }

      async function refreshAll() {
        renderEmptyCard(certHost, "Signing certificate", "Loading...");
        renderEmptyCard(queueHost, "Queued packages", "Loading...");
        await refreshQueue();
        await refreshCerts();
        status.textContent = "ready";
      }

      localOverviewRefreshers.push(refreshAll);

      addTool("↻", "Refresh", "Refresh certificate and queue state", refreshAll, true);
      addTool("⊙", "Certs", "Open certificate inventory", function () {
        refreshCerts();
      });
      addTool("✓", "Lint", "Lint the selected or next package", function () {
        var pathValue = packageInputValue();
        if (!pathValue) {
          resultHost.innerHTML = "";
          _renderEsimFlowError(
            "Select a package or queue a package first.",
            _localEimAction("eim_local.eim_package_lint")
          );
          return;
        }
        runLocalEimAction("eim_local.eim_package_lint", {
          package_path: pathValue,
        }, { runningText: "linting package" });
      });
      addTool("▣", "Explain", "Explain the selected or next package", function () {
        var pathValue = packageInputValue();
        if (!pathValue) {
          resultHost.innerHTML = "";
          _renderEsimFlowError(
            "Select a package or queue a package first.",
            _localEimAction("eim_local.eim_package_explain")
          );
          return;
        }
        runLocalEimAction("eim_local.eim_package_explain", {
          package_path: pathValue,
        }, { runningText: "explaining package" });
      });
      addTool("↓", "Load", "Load the selected or next package to the card", function () {
        var pathValue = packageInputValue();
        if (!pathValue) {
          resultHost.innerHTML = "";
          _renderEsimFlowError(
            "Select a package or queue a package first.",
            _localEimAction("eim_local.load_eim_package")
          );
          return;
        }
        runLocalEimAction("eim_local.load_eim_package", {
          package_path: pathValue,
          cert_path: certInputValue(),
        }, { runningText: "loading package" });
      }, true);
      addTool("❐", "Queue", "Refresh queued package metadata", refreshQueue);
      addTool("▶", "Issue next", "Issue the next queued package", async function () {
        await runLocalEimAction("eim_local.issue_package", {
          hotfolder_dir: hotfolderInputValue(),
        }, { runningText: "issuing next package" });
        refreshQueue();
      });
      addTool("⟳", "Hotfolder", "Open hotfolder campaign", function () {
        var action = _localEimAction("eim_local.hotfolder_campaign");
        if (action) _openEsimActionPane(action);
      });

      renderEmptyCard(certHost, "Signing certificate", "Loading...");
      renderEmptyCard(queueHost, "Queued packages", "Loading...");
      window.setTimeout(refreshAll, 0);
      return panel;
    }

    // --- Main content area ---
    var grid = document.createElement("div");
    grid.className = "cc-compact-action-grid";

    // Dashboard body
    var dashBody = document.createElement("div");
    dashBody.className = "cc-dashboard";
    var contentHost = grid;
    if (useEsimSplitPane) {
      grid.className += " cc-esim-split-grid";

      contentHost = document.createElement("div");
      contentHost.className = "cc-esim-split-pane cc-esim-left-pane";
      grid.appendChild(contentHost);

      esimFlowPane = document.createElement("aside");
      esimFlowPane.className = "cc-esim-split-pane cc-esim-flow-pane";
      esimFlowPane.setAttribute("aria-label", "APDU flow output");
      var flowHead = document.createElement("div");
      flowHead.className = "cc-esim-flow-head";
      esimFlowTitle = document.createElement("div");
      esimFlowTitle.className = "cc-esim-flow-title";
      flowHead.appendChild(esimFlowTitle);
      esimFlowStatus = document.createElement("span");
      esimFlowStatus.className = "cc-esim-flow-status";
      flowHead.appendChild(esimFlowStatus);
      esimFlowPane.appendChild(flowHead);
      esimFlowBody = document.createElement("div");
      esimFlowBody.className = "cc-esim-flow-body";
      esimFlowPane.appendChild(esimFlowBody);
      grid.appendChild(esimFlowPane);
      _renderEsimFlowPlaceholder();
    }

    function _appendCompactContent(node) {
      contentHost.appendChild(node);
    }

    // Mutation actions
    var mutationActions = actions.filter(_shouldShowInDashboard);
    if (subsystem === "eSIM Management") {
      mutationActions = actions.filter(ccShouldShowEsimManagementAction);
    } else if (subsystem === "SCP11 Local") {
      mutationActions = actions.filter(_shouldShowLocalSmdpDashboardAction);
    } else if (subsystem === "Local eIM") {
      mutationActions = actions.filter(_shouldShowLocalEimDashboardAction);
    } else if (subsystem === "Offline Tools") {
      mutationActions = actions.filter(function (action) {
        var actionId = String(action && action.id || "");
        return !CC_OFFLINE_TOOLS_HIDDEN_ACTIONS[actionId];
      });
    }
    if (subsystem === "SCP11 Local") {
      _appendCompactContent(_buildLocalSmdpOverviewPanel());
    }
    if (subsystem === "Local eIM") {
      _appendCompactContent(_buildLocalEimOverviewPanel());
    }
    if (mutationActions.length > 0) {
      var dashActions = document.createElement("div");
      dashActions.className = "cc-dash-actions";
      var dashActionsLabel = document.createElement("div");
      dashActionsLabel.className = "cc-compact-group-label";
      dashActionsLabel.textContent = (
        subsystem === "eSIM Management"
        || subsystem === "SCP11 Local"
      )
        ? "Operations"
        : (isDashboardSubsystem ? "Actions" : "All actions");
      dashActions.appendChild(dashActionsLabel);

      function appendActionButton(parent, action) {
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "cc-compact-rbtn";
        btn.title = (action.description || action.title || action.id);
        var icon = document.createElement("span");
        icon.className = "cc-compact-rbtn-icon";
        icon.setAttribute("aria-hidden", "true");
        icon.textContent = _ccResolveIcon(action.id);
        btn.appendChild(icon);
        var label = document.createElement("span");
        label.className = "cc-compact-rbtn-label";
        label.textContent = action.title || action.id;
        btn.appendChild(label);
        if (subsystem === "Offline Tools") {
          if (action.description) {
            var desc = document.createElement("span");
            desc.className = "cc-compact-rbtn-desc";
            desc.textContent = action.description;
            btn.appendChild(desc);
          }
          var meta = document.createElement("span");
          meta.className = "cc-compact-rbtn-meta";
          meta.appendChild(makeBadge("cc-badge " + (action.streams ? "cc-badge--stream" : "cc-badge--sync"),
            action.streams ? "stream" : "sync"));
          if (action.requires_card) {
            meta.appendChild(makeBadge("cc-badge cc-badge--card", "card"));
          }
          meta.appendChild(makeBadge("cc-badge cc-badge--out", action.output_kind || "json"));
          btn.appendChild(meta);
        }
        btn.addEventListener("click", function () {
          if (useEsimSplitPane) {
            _openEsimActionPane(action);
          } else {
            _openInlineActionPane(action);
          }
        });
        parent.appendChild(btn);
        return btn;
      }

      actionButtonRecords = [];
      if (subsystem === "eSIM Management" || subsystem === "SCP11 Local") {
        dashActions.classList.add("cc-esim-action-rails");
        var actionFlavorTabRecords = [];
        var activeActionFlavorId = "";

        function switchActionFlavor(flavorId) {
          activeActionFlavorId = flavorId;
          actionFlavorTabRecords.forEach(function (tabRec) {
            var isActive = tabRec.id === flavorId;
            tabRec.tab.classList.toggle("active", isActive);
            tabRec.tab.setAttribute("aria-selected", String(isActive));
            tabRec.section.hidden = !isActive;
          });
        }

        if (subsystem === "SCP11 Local") {
          dashActions.classList.add("cc-local-smdp-action-rails");
        }
        var flavorGroups = subsystem === "SCP11 Local"
          ? ccLocalSmdpActionFlavorGroups(mutationActions)
          : ccEsimActionFlavorGroups(mutationActions);
        if (subsystem === "eSIM Management" && flavorGroups.length > 0) {
          dashActions.classList.add("cc-esim-action-rails--tabbed");
          var actionTabs = document.createElement("div");
          actionTabs.className = "cc-esim-action-tabs";
          actionTabs.setAttribute("role", "tablist");
          actionTabs.setAttribute("aria-label", "eSIM action modes");
          dashActions.appendChild(actionTabs);
          activeActionFlavorId = flavorGroups[0].meta.id;
        }
        flavorGroups.forEach(function (group) {
          var isTabbedEsim = subsystem === "eSIM Management";
          var section = document.createElement("section");
          section.className = "cc-esim-action-section cc-esim-action-section--" + group.meta.id;
          if (subsystem === "SCP11 Local") {
            section.className += " cc-local-smdp-action-section"
              + " cc-local-smdp-action-section--" + group.meta.id;
          } else if (isTabbedEsim) {
            section.className += " cc-esim-action-panel";
            section.setAttribute("role", "tabpanel");
            section.setAttribute("data-action-flavor", group.meta.id);
            section.hidden = group.meta.id !== activeActionFlavorId;
            var tab = document.createElement("button");
            tab.type = "button";
            tab.className = "cc-esim-action-tab"
              + (group.meta.id === activeActionFlavorId ? " active" : "");
            tab.setAttribute("role", "tab");
            tab.setAttribute("aria-selected", String(group.meta.id === activeActionFlavorId));
            tab.setAttribute("data-action-flavor", group.meta.id);
            tab.title = group.meta.hint || group.meta.label || "";
            var tabLabel = document.createElement("span");
            tabLabel.className = "cc-esim-action-tab-label";
            tabLabel.textContent = group.meta.label;
            tab.appendChild(tabLabel);
            var tabCount = document.createElement("span");
            tabCount.className = "cc-esim-action-tab-count";
            tabCount.textContent = String(group.items.length);
            tab.appendChild(tabCount);
            tab.addEventListener("click", function () {
              switchActionFlavor(group.meta.id);
            });
            actionTabs.appendChild(tab);
            actionFlavorTabRecords.push({
              id: group.meta.id,
              tab: tab,
              section: section,
            });
          }
          var sectionHead = document.createElement("div");
          sectionHead.className = "cc-esim-action-section-head";
          var sectionTitle = document.createElement("div");
          sectionTitle.className = "cc-esim-action-section-title";
          sectionTitle.textContent = group.meta.label;
          sectionHead.appendChild(sectionTitle);
          if (group.meta.hint) {
            var sectionHint = document.createElement("div");
            sectionHint.className = "cc-esim-action-section-hint";
            sectionHint.textContent = group.meta.hint;
            sectionHead.appendChild(sectionHint);
          }
          section.appendChild(sectionHead);
          var sectionInner = document.createElement("div");
          sectionInner.className = "cc-compact-group-inner cc-esim-action-buttons";
          group.items.forEach(function (action) {
            var btn = appendActionButton(sectionInner, action);
            actionButtonRecords.push({ btn: btn, action: action, section: section });
          });
          section.appendChild(sectionInner);
          dashActions.appendChild(section);
        });
      } else {
        var dashActionsInner = document.createElement("div");
        dashActionsInner.className = "cc-compact-group-inner";
        mutationActions.forEach(function (action) {
          var btn = appendActionButton(dashActionsInner, action);
          actionButtonRecords.push({ btn: btn, action: action, section: null });
        });
        dashActions.appendChild(dashActionsInner);
      }
      _appendCompactContent(dashActions);
    }
    if (!useEsimSplitPane && mutationActions.length > 0) {
      _appendCompactContent(_ensureInlineActionPane());
    }
    _appendCompactContent(dashBody);

    // --- Search filter (filters mutation buttons) ---
    var allButtons = [];
    if (mutationActions.length > 0) {
      actionButtonRecords.forEach(function (rec) {
        var act = rec.action;
        var haystack = (
          (act.title || "") + " "
          + act.id + " "
          + (act.description || "")
        ).toLowerCase();
        allButtons.push({
          btn: rec.btn,
          haystack: haystack,
          section: rec.section,
          categoryId: groupedBuckets ? groupedActionCategoryId(act) : "",
        });
      });
    }
    actionFilterRecords = allButtons;
    if (groupedBuckets) {
      applyCardFilters();
    }

    if (actions.length >= 8) {
      searchInput = header.querySelector(".cc-compact-search-input");
      if (searchInput) {
        searchInput.addEventListener("input", function () {
          var q = searchInput.value.trim().toLowerCase();
          if (groupedBuckets) {
            applyCardFilters();
            return;
          }
          allButtons.forEach(function (rec) {
            rec.btn.hidden = q.length > 0 && rec.haystack.indexOf(q) === -1;
          });
          var tabbedEsim = wb.querySelector(".cc-esim-action-rails--tabbed");
          if (tabbedEsim) {
            var activeStillVisible = false;
            tabbedEsim.querySelectorAll(".cc-esim-action-panel").forEach(function (section) {
              var hasVisible = !!section.querySelector(".cc-compact-rbtn:not([hidden])");
              var flavorId = section.getAttribute("data-action-flavor") || "";
              var tab = tabbedEsim.querySelector(
                '.cc-esim-action-tab[data-action-flavor="' + cssEscape(flavorId) + '"]'
              );
              if (tab) tab.hidden = q.length > 0 && !hasVisible;
              if (flavorId === activeActionFlavorId && hasVisible) {
                activeStillVisible = true;
              }
            });
            if (!activeStillVisible && q.length > 0) {
              var firstVisibleTab = tabbedEsim.querySelector(".cc-esim-action-tab:not([hidden])");
              if (firstVisibleTab) {
                switchActionFlavor(firstVisibleTab.getAttribute("data-action-flavor") || "");
              }
            } else {
              switchActionFlavor(activeActionFlavorId);
            }
          } else {
            wb.querySelectorAll(".cc-esim-action-section").forEach(function (section) {
              var visible = section.querySelector(".cc-compact-rbtn:not([hidden])");
              section.hidden = !visible;
            });
          }
        });
      }
    }
    wb.appendChild(grid);

    async function refreshEsimSurface(opts) {
      if (!isDashboardSubsystem) return null;
      var options = opts || {};
      _setEsimModuleToolbarBusy(true, "refreshing");
      try {
        if (typeof readerBarRefresh === "function") {
          await Promise.resolve(readerBarRefresh({ manual: !!options.manual }));
        }
        var resp = await refreshDashboard({ quiet: false });
        for (var i = 0; i < localOverviewRefreshers.length; i++) {
          await Promise.resolve(localOverviewRefreshers[i]());
        }
        _setEsimModuleToolbarBusy(false, "ready");
        return resp;
      } catch (err) {
        _setEsimModuleToolbarBusy(false, "error");
        logBus.emit({
          level: "error",
          source: subsystem,
          message: "refresh: " + String(err && err.message || err),
        });
        return null;
      }
    }

    async function resetEsimSurface() {
      if (!isDashboardSubsystem) return;
      var action = ccFindCatalogueActionById("scp11_live.reset_card")
        || ccFindActionById(actions, "scp11_live.reset_card");
      if (!action) {
        _renderEsimFlowError("Card reset action is not registered.", null);
        return;
      }
      if (!scopedReader) {
        _renderEsimFlowError("Select a reader before resetting the card.", action);
        return;
      }
      _setEsimModuleToolbarBusy(true, "resetting");
      try {
        var data = await _runActionInEsimFlowPane(action, {
          reader: scopedReader,
          confirm: true,
        }, {
          runningText: "resetting card",
          doneText: "reset ok",
        });
        if (typeof readerBarRefresh === "function") {
          await Promise.resolve(readerBarRefresh({ manual: true }));
        }
        await refreshDashboard({ quiet: true });
        for (var i = 0; i < localOverviewRefreshers.length; i++) {
          await Promise.resolve(localOverviewRefreshers[i]());
        }
        _setEsimModuleToolbarBusy(false, data ? "reset ok" : "reset error");
      } catch (err) {
        _setEsimModuleToolbarBusy(false, "reset error");
        _renderEsimFlowError(String(err && err.message || err), action);
      }
    }

    // --- Auto-fetch dashboard ---
    function refreshDashboard(opts) {
      opts = opts || {};
      if (!isDashboardSubsystem || commandState.activeSubsystem !== subsystem) {
        return Promise.resolve(null);
      }
      var scanActionId = DASHBOARD_SCAN_ACTION[subsystem];
      if (!scanActionId) return Promise.resolve(null);
      var scanInputs = {};
      if (ccSubsystemRequiresReaderSession(subsystem)) {
        scanInputs.reader = scopedReader;
      }
      if (!opts.quiet) {
        dashBody.innerHTML = "<p class='cc-dash-loading'>loading card overview…</p>";
      }
      return apiFetch("/api/actions/" + encodeURIComponent(scanActionId) + "/run", {
        method: "POST",
        body: JSON.stringify({ inputs: scanInputs }),
      }).then(function (resp) {
        if (commandState.activeSubsystem !== subsystem) return null;
        if (resp && resp.ok && resp.data && resp.data.snapshot) {
          _renderDashboard(resp.data.snapshot);
        } else if (resp && resp.data && resp.data.eid) {
          // Some actions return flat fields instead of a snapshot wrapper
          _renderDashboard(resp.data);
        } else {
          dashBody.innerHTML = "<p class='cc-dash-loading'>no card overview available"
            + (resp && resp.data && resp.data.note ? " — " + escapeHtml(String(resp.data.note)) : "")
            + "</p>";
        }
        return resp;
      }).catch(function (err) {
        if (commandState.activeSubsystem !== subsystem) return null;
        dashBody.innerHTML = "<p class='cc-dash-loading'>failed to load card overview"
          + (err && err.message ? ": " + escapeHtml(String(err.message)) : "")
          + "</p>";
        return null;
      });
    }

    if (isDashboardSubsystem && commandState.activeSubsystem === subsystem) {
      refreshDashboard();
    }

    container.appendChild(wb);
  }

  function stopHilWorkbenchRuntime() {
    var state = commandState.hilWorkbench;
    if (!state) return;
    if (state.refreshTimerId !== null) {
      clearInterval(state.refreshTimerId);
      state.refreshTimerId = null;
    }
    if (typeof state.rawUnsubscribe === "function") {
      try { state.rawUnsubscribe(); } catch (_err) {}
      state.rawUnsubscribe = null;
    }
    if (state.rawRenderTimerId !== null) {
      clearTimeout(state.rawRenderTimerId);
      state.rawRenderTimerId = null;
    }
    if (state.timerStatusTimerId !== null) {
      clearInterval(state.timerStatusTimerId);
      state.timerStatusTimerId = null;
    }
  }

  function renderHilWorkbench(container, actions, leaf) {
    var state = commandState.hilWorkbench;
    hilSyncCommandCenterTraceIndicators();
    stopHilWorkbenchRuntime();
    if (!container) return;
    container.innerHTML = "";

    var wb = document.createElement("section");
    wb.className = "cc-workbench cc-workbench--compact cc-hil-workbench";
    wb.setAttribute("data-wb", "HIL");

    var header = document.createElement("header");
    header.className = "cc-compact-header cc-hil-header";

    var titleBlock = document.createElement("div");
    titleBlock.className = "cc-compact-title";
    var h2 = document.createElement("h2");
    h2.textContent = leaf ? leaf.label : "HIL Bridge";
    titleBlock.appendChild(h2);
    var hint = document.createElement("p");
    hint.className = "cc-compact-hint";
    hint.textContent = leaf && leaf.hint ? leaf.hint : "Hardware-in-the-loop APDU relay / capture";
    titleBlock.appendChild(hint);
    header.appendChild(titleBlock);
    wb.appendChild(header);

    var toolbar = document.createElement("div");
    toolbar.className = "cc-hil-toolbar";
    toolbar.setAttribute("role", "toolbar");
    toolbar.setAttribute("aria-label", "HIL actions");

    var moduleGroup = document.createElement("div");
    moduleGroup.className = "cc-hil-toolbar-group";
    toolbar.appendChild(moduleGroup);

    moduleGroup.appendChild(hilToolbarButton(
      state.startInFlight ? "..." : (state.armed ? "●" : "▶"),
      state.startInFlight ? "Starting" : (state.armed ? "Running" : "Start"),
      "Start the supervised HIL session and attach the GUI decoder",
      function () {
        hilStartLiveSession(actions, container, leaf);
      },
      state.armed,
      state.startInFlight || state.stopInFlight
    ));
    moduleGroup.appendChild(hilToolbarButton("■", "Stop", "Stop the supervised HIL session", function () {
      hilStopLiveSession(actions, container, leaf);
    }, false, state.startInFlight || state.stopInFlight));
    moduleGroup.appendChild(hilToolbarButton("↻", "Refresh", "Refresh decoded packets", function () {
      hilRefreshSnapshot({ force: true });
    }, false, state.inflight || state.liveBaselinePending));
    moduleGroup.appendChild(hilToolbarButton(
      state.autoRefresh ? "⏸" : "▶",
      state.autoRefresh ? "Auto on" : "Auto off",
      "Toggle decoded packet auto-refresh",
      function () {
        state.autoRefresh = !state.autoRefresh;
        renderHilWorkbench(container, actions, leaf);
      },
      state.autoRefresh
    ));
    moduleGroup.appendChild(hilToolbarButton(
      state.paused ? "▶" : "⏸",
      state.paused ? "Resume" : "Pause",
      "Pause decoded packet refresh",
      function () {
        state.paused = !state.paused;
        if (!state.paused) hilRefreshSnapshot({ force: true });
        renderHilWorkbench(container, actions, leaf);
      },
      state.paused
    ));
    moduleGroup.appendChild(hilToolbarButton(
      state.viewMode === "context" ? "▤" : "☰",
      state.viewMode === "context" ? "Context" : "Flat",
      "Toggle decoded packet grouping",
      function () {
        state.viewMode = state.viewMode === "context" ? "flat" : "context";
        renderHilWorkbench(container, actions, leaf);
      },
      state.viewMode === "context"
    ));
    moduleGroup.appendChild(hilToolbarButton("⎘", "Open pcap", "Open a saved pcap path", function () {
      var nextPath = window.prompt("Capture path", state.capturePath || "");
      if (nextPath === null) return;
      state.capturePath = String(nextPath || "").trim();
      state.captureSource = state.capturePath ? "explicit" : "";
      state.armed = true;
      state.startMode = "offline";
      state.autoRefresh = false;
      state.statusText = "offline pcap";
      state.selectedFrameNumber = null;
      state.selectionFollowsTail = true;
      state.detail = "";
      state.bytes = "";
      state.detailRanges = [];
      state.detailFrameNumber = 0;
      hilResetLiveBaseline();
      hilResetDetailScroll();
      hilResetPacketSections();
      hilResetPacketScroll();
      state.followTail = true;
      hilRefreshSnapshot({ force: true });
      renderHilWorkbench(container, actions, leaf);
    }));
    moduleGroup.appendChild(hilToolbarButton("⌂", "Live", "Use the active live capture", function () {
      state.capturePath = "";
      state.captureSource = "";
      state.armed = true;
      state.startMode = "decoded";
      state.autoRefresh = true;
      state.statusText = "live";
      state.selectedFrameNumber = null;
      state.selectionFollowsTail = true;
      state.detail = "";
      state.bytes = "";
      state.detailRanges = [];
      state.detailFrameNumber = 0;
      state.liveBaselinePending = true;
      hilResetDetailScroll();
      hilResetPacketSections();
      hilResetPacketScroll();
      state.followTail = true;
      hilEstablishLiveBaseline().then(function (baselineReady) {
        renderHilWorkbench(container, actions, leaf);
        if (baselineReady) hilRefreshSnapshot({ force: false });
      });
      renderHilWorkbench(container, actions, leaf);
    }));
    moduleGroup.appendChild(hilToolbarButton("×", "Clear view", "Clear the decoded view", function () {
      if (hilIsLiveCaptureMode(state)) {
        hilPromoteLiveBaselineFromRows(state.rows);
      }
      state.rows = [];
      state.annotations = {};
      state.detail = "";
      state.bytes = "";
      state.detailRanges = [];
      state.detailFrameNumber = 0;
      state.selectedFrameNumber = null;
      state.selectionFollowsTail = true;
      hilClearByteHighlight(true);
      hilResetDetailScroll();
      hilResetPacketSections();
      hilResetPacketScroll();
      state.statusText = "cleared";
      state.actionStatusText = "";
      renderHilWorkbench(container, actions, leaf);
    }));

    var bridgeGroup = document.createElement("div");
    bridgeGroup.className = "cc-hil-toolbar-group cc-hil-toolbar-group--actions";
    toolbar.appendChild(bridgeGroup);
    bridgeGroup.appendChild(hilToolbarButton(
      state.cardBridgeLaunchInFlight ? "..." : "⇄",
      state.cardBridgeLaunchInFlight ? "Starting bridge" : "Remote Bridge",
      "Launch the saved Remote Bridge rig sequence",
      function () {
        hilLaunchCardBridgeRig(actions, container, leaf);
      },
      state.cardBridgeLaunchInFlight,
      state.cardBridgeLaunchInFlight
    ));
    actions.filter(function (action) {
      return action
        && action.id !== "hil.decode_snapshot"
        && action.id !== "hil.session_start"
        && action.id !== "hil.session_stop";
    }).forEach(function (action) {
      bridgeGroup.appendChild(hilToolbarButton(
        _ccResolveIcon(action.id),
        action.title || action.id,
        action.description || action.id,
        function () { _ccBuildActionPopout(action); }
      ));
    });

    wb.appendChild(toolbar);

    var tabs = document.createElement("div");
    tabs.className = "cc-hil-tabs";
    tabs.setAttribute("role", "tablist");
    tabs.setAttribute("aria-label", "HIL views");
    tabs.appendChild(hilTabButton("dissector", "Dissector"));
    tabs.appendChild(hilTabButton("raw", "Raw APDU trace"));
    tabs.appendChild(hilTabButton("modem", "Modem shell"));
    wb.appendChild(tabs);

    var body = document.createElement("div");
    body.className = "cc-hil-body";
    wb.appendChild(body);
    container.appendChild(wb);

    if (state.activeTab === "raw") {
      renderHilRawTab(body);
    } else if (state.activeTab === "modem") {
      renderHilModemShellTab(body);
    } else {
      renderHilDissectorTab(body);
      hilStartTimerStatusTicker();
    }
    if (state.armed) {
      installHilRawTraceSubscription(body);
    }
    if (
      state.armed
      && !state.liveBaselinePending
      && !state.paused
      && state.autoRefresh
      && state.activeTab === "dissector"
    ) {
      state.refreshTimerId = setInterval(function () {
        if (commandState.activeSubsystem !== "HIL") {
          stopHilWorkbenchRuntime();
          return;
        }
        hilRefreshSnapshot({ force: false });
      }, 700);
    }

    function hilTabButton(tabId, labelText) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "cc-hil-tab" + (state.activeTab === tabId ? " active" : "");
      btn.setAttribute("role", "tab");
      btn.setAttribute("aria-selected", String(state.activeTab === tabId));
      btn.textContent = labelText;
      btn.addEventListener("click", function () {
        state.activeTab = tabId;
        renderHilWorkbench(container, actions, leaf);
        if (tabId === "dissector" && state.armed) {
          hilRefreshSnapshot({ force: true });
        }
      });
      return btn;
    }
  }

  function hilRenderActivePaneOnly() {
    if (commandState.activeSubsystem !== "HIL") return false;
    var wb = document.querySelector(".cc-hil-workbench");
    var body = wb ? wb.querySelector(".cc-hil-body") : null;
    if (!body) return false;
    var state = commandState.hilWorkbench;
    if (state.activeTab === "raw") {
      if (
        Number(state.rawPendingDropCount || 0) <= 0
        && (!state.rawPendingRows || state.rawPendingRows.length === 0)
      ) {
        return true;
      }
      var rawRows = body.querySelector(".cc-hil-raw-rows");
      if (rawRows) {
        renderHilRawRows(rawRows);
      } else {
        renderHilRawTab(body);
      }
    } else if (state.activeTab === "modem") {
      return true;
    } else {
      renderHilDissectorTab(body);
    }
    return true;
  }

  function hilToolbarButton(iconText, labelText, titleText, onClick, active, disabled) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "cc-hil-action-btn" + (active ? " is-active" : "");
    btn.title = titleText || labelText || "";
    btn.disabled = !!disabled;
    var icon = document.createElement("span");
    icon.className = "cc-hil-action-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = iconText || "●";
    var label = document.createElement("span");
    label.className = "cc-hil-action-label";
    label.textContent = labelText || "";
    btn.appendChild(icon);
    btn.appendChild(label);
    if (typeof onClick === "function") {
      btn.addEventListener("click", onClick);
    }
    return btn;
  }

  function hilFindAction(actions, actionId) {
    var list = Array.isArray(actions) ? actions : [];
    for (var i = 0; i < list.length; i++) {
      if (list[i] && list[i].id === actionId) return list[i];
    }
    return null;
  }

  async function hilRunActionRequest(actionId, inputs) {
    return apiFetch("/api/actions/" + encodeURIComponent(actionId) + "/run", {
      method: "POST",
      body: JSON.stringify({ inputs: inputs || {} }),
    });
  }

  async function hilEstablishLiveBaseline() {
    var state = commandState.hilWorkbench;
    state.liveBaselinePending = true;
    state.statusText = "attaching";
    state.errorText = "";
    state.rows = [];
    state.annotations = {};
    state.detail = "";
    state.bytes = "";
    state.detailRanges = [];
    state.detailFrameNumber = 0;
    state.selectedFrameNumber = null;
    state.selectionFollowsTail = true;
    hilResetDetailScroll();
    hilResetPacketSections();
    hilResetPacketScroll();
    try {
      var resp = await apiFetch("/api/actions/hil.decode_snapshot/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: {
            capture_path: "",
            selected_frame: "",
            keybag_path: state.keybagPath || "",
            include_detail: false,
            include_annotations: false,
            limit: 5000,
          },
        }),
      });
      var data = resp && resp.data ? resp.data : {};
      if (!resp || !resp.ok || data.ok === false) {
        hilResetLiveBaseline();
        state.statusText = "baseline unavailable";
        state.errorText = (resp && resp.error) || data.note || "could not establish HIL live baseline";
        return false;
      }
      var rows = Array.isArray(data.rows) ? data.rows : [];
      var maxFrame = 0;
      rows.forEach(function (row) {
        var frameNumber = parseInt(row.number || 0, 10);
        if (frameNumber > maxFrame) maxFrame = frameNumber;
      });
      state.liveBaselineFrameNumber = maxFrame;
      state.liveBaselineCaptureSize = Number(data.capture_size || 0);
      state.liveBaselineCaptureMtime = Number(data.capture_mtime || 0);
      state.lastCapturePath = String(data.capture_path || state.lastCapturePath || "");
      state.captureSource = String(data.capture_source || state.captureSource || "");
      state.statusText = maxFrame > 0
        ? "waiting for new packets"
        : "capture empty";
      return true;
    } catch (err) {
      hilResetLiveBaseline();
      state.statusText = "baseline unavailable";
      state.errorText = String((err && err.message) || err);
      return false;
    } finally {
      state.liveBaselinePending = false;
    }
  }

  function hilApplyReaderBinding(data) {
    var state = commandState.hilWorkbench;
    var status = data && data.status ? data.status : {};
    var backend = String(
      status.cardBackend
      || status.card_backend
      || data.cardBackend
      || data.card_backend
      || ""
    ).trim();
    if (backend && backend !== "reader") {
      state.readerName = "";
      state.readerIndex = -1;
      if (typeof readerBarNotifySessionChanged === "function") {
        readerBarNotifySessionChanged();
      }
      return;
    }
    var readerName = String(
      status.readerName
      || status.reader_name
      || status.reader
      || data.readerName
      || data.reader_name
      || data.reader
      || ""
    ).trim();
    var rawIndex = status.readerIndex;
    if (rawIndex == null) rawIndex = status.reader_index;
    if (rawIndex == null) rawIndex = data.readerIndex;
    if (rawIndex == null) rawIndex = data.reader_index;
    var readerIndex = parseInt(rawIndex, 10);
    state.readerIndex = isNaN(readerIndex) ? -1 : readerIndex;
    if (!readerName && state.readerIndex >= 0) {
      readerName = readerBarDefaultReaderName();
    }
    state.readerName = readerBarCanonicalName(readerName, {
      defaultForBlank: state.readerIndex >= 0,
    });
    if (typeof readerBarNotifySessionChanged === "function") {
      readerBarNotifySessionChanged();
    }
  }

  function hilClearReaderBinding() {
    var state = commandState.hilWorkbench;
    state.readerName = "";
    state.readerIndex = -1;
    if (typeof readerBarNotifySessionChanged === "function") {
      readerBarNotifySessionChanged();
    }
  }

  async function hilStartLiveSession(actions, container, leaf) {
    var state = commandState.hilWorkbench;
    if (state.startInFlight || state.stopInFlight) return;
    if (!hilFindAction(actions, "hil.session_start")) {
      state.errorText = "HIL start action is not registered by the backend.";
      renderHilWorkbench(container, actions, leaf);
      return;
    }
    state.startInFlight = true;
    state.armed = true;
    state.startMode = "decoded";
    state.capturePath = "";
    state.captureSource = "";
    state.rows = [];
    state.annotations = {};
    state.detail = "";
    state.bytes = "";
    state.detailRanges = [];
    state.detailFrameNumber = 0;
    hilClearByteHighlight(true);
    state.rawRows = [];
    state.rawPendingRows = [];
    state.rawPendingDropCount = 0;
    state.rawSnapshotSeeded = false;
    state.rawFrameSeen = {};
    state.rawClearedFrameNumber = 0;
    state.lastRenderedRawId = 0;
    state.refreshQueuedForce = false;
    state.refreshQueuedSelectedFrame = null;
    state.readerName = "";
    state.readerIndex = -1;
    state.selectedFrameNumber = null;
    state.selectionFollowsTail = true;
    state.liveBaselinePending = true;
    state.liveBaselineFrameNumber = 0;
    state.liveBaselineCaptureSize = 0;
    state.liveBaselineCaptureMtime = 0;
    state.captureSize = 0;
    state.captureMtime = 0;
    hilResetDetailScroll();
    hilResetPacketSections();
    state.followTail = true;
    hilResetPacketScroll();
    state.autoRefresh = true;
    state.paused = false;
    state.statusText = "starting";
    state.actionStatusText = "starting HIL session";
    state.errorText = "";
    renderHilWorkbench(container, actions, leaf);
    try {
      var resp = await hilRunActionRequest("hil.session_start", {
        mode: "decoded",
      });
      var data = resp && resp.data ? resp.data : {};
      if (!resp || !resp.ok || data.ok === false) {
        state.armed = false;
        hilClearReaderBinding();
        hilResetLiveBaseline();
        state.statusText = "start failed";
        state.errorText = (resp && resp.error) || data.note || "HIL start failed";
        state.actionStatusText = state.errorText;
        renderHilWorkbench(container, actions, leaf);
        return;
      }
      state.armed = true;
      state.startMode = String(data.mode || "decoded");
      state.capturePath = "";
      state.lastCapturePath = String(data.capture_path || "");
      state.captureSource = String(data.capture_source || state.captureSource || "");
      state.actionStatusText = data.note ? String(data.note) : "HIL session active";
      hilApplyReaderBinding(data);
      var baselineReady = await hilEstablishLiveBaseline();
      renderHilWorkbench(container, actions, leaf);
      if (baselineReady) hilRefreshSnapshot({ force: false });
    } catch (err) {
      state.armed = false;
      hilClearReaderBinding();
      hilResetLiveBaseline();
      state.statusText = "start failed";
      state.errorText = String((err && err.message) || err);
      state.actionStatusText = state.errorText;
      renderHilWorkbench(container, actions, leaf);
    } finally {
      state.startInFlight = false;
      if (commandState.activeSubsystem === "HIL") {
        renderHilWorkbench(container, actions, leaf);
      }
    }
  }

  async function hilStopLiveSession(actions, container, leaf) {
    var state = commandState.hilWorkbench;
    if (state.startInFlight || state.stopInFlight) return;
    if (!state.armed && state.statusText === "not started") {
      return;
    }
    if (state.startMode === "remote" || state.captureSource === "remote") {
      state.armed = false;
      state.rows = [];
      state.annotations = {};
      state.detail = "";
      state.bytes = "";
      state.detailRanges = [];
      state.detailFrameNumber = 0;
      state.rawRows = [];
      state.rawPendingRows = [];
      state.rawPendingDropCount = 0;
      state.rawSnapshotSeeded = false;
      state.rawFrameSeen = {};
      state.rawClearedFrameNumber = 0;
      state.lastRenderedRawId = 0;
      state.refreshQueuedForce = false;
      state.refreshQueuedSelectedFrame = null;
      state.captureSize = 0;
      state.captureMtime = 0;
      state.captureSource = "";
      hilClearReaderBinding();
      state.selectedFrameNumber = null;
      state.selectionFollowsTail = true;
      hilResetLiveBaseline();
      hilResetDetailScroll();
      hilResetPacketSections();
      state.followTail = true;
      hilResetPacketScroll();
      state.statusText = "detached";
      state.actionStatusText = "Remote HIL view detached.";
      stopHilWorkbenchRuntime();
      renderHilWorkbench(container, actions, leaf);
      return;
    }
    if (!window.confirm("Stop the HIL session?")) {
      return;
    }
    state.stopInFlight = true;
    state.statusText = "stopping";
    state.actionStatusText = "stopping HIL session";
    state.errorText = "";
    renderHilWorkbench(container, actions, leaf);
    try {
      var resp = await hilRunActionRequest("hil.session_stop", { confirm: true });
      var data = resp && resp.data ? resp.data : {};
      if (!resp || !resp.ok || data.ok === false) {
        state.statusText = "stop failed";
        state.errorText = (resp && resp.error) || data.note || "HIL stop failed";
        state.actionStatusText = state.errorText;
        renderHilWorkbench(container, actions, leaf);
        return;
      }
      state.armed = false;
      state.rows = [];
      state.annotations = {};
      state.detail = "";
      state.bytes = "";
      state.detailRanges = [];
      state.detailFrameNumber = 0;
      state.rawRows = [];
      state.rawPendingRows = [];
      state.rawPendingDropCount = 0;
      state.rawSnapshotSeeded = false;
      state.rawFrameSeen = {};
      state.rawClearedFrameNumber = 0;
      state.lastRenderedRawId = 0;
      state.refreshQueuedForce = false;
      state.refreshQueuedSelectedFrame = null;
      state.captureSize = 0;
      state.captureMtime = 0;
      hilClearReaderBinding();
      state.selectedFrameNumber = null;
      state.selectionFollowsTail = true;
      hilResetLiveBaseline();
      hilResetDetailScroll();
      hilResetPacketSections();
      state.followTail = true;
      hilResetPacketScroll();
      state.statusText = data.note ? String(data.note) : "stopped";
      state.actionStatusText = state.statusText;
      stopHilWorkbenchRuntime();
      renderHilWorkbench(container, actions, leaf);
    } catch (err) {
      state.statusText = "stop failed";
      state.errorText = String((err && err.message) || err);
      state.actionStatusText = state.errorText;
      renderHilWorkbench(container, actions, leaf);
    } finally {
      state.stopInFlight = false;
      if (commandState.activeSubsystem === "HIL") {
        renderHilWorkbench(container, actions, leaf);
      }
    }
  }

  async function hilLaunchCardBridgeRig(actions, container, leaf) {
    var state = commandState.hilWorkbench;
    if (state.cardBridgeLaunchInFlight) return;
    state.cardBridgeLaunchInFlight = true;
    state.errorText = "";
    state.actionStatusText = "starting Remote Bridge rig";
    renderHilWorkbench(container, actions, leaf);
    try {
      if (typeof cbRigStartAllFromSavedSettings !== "function") {
        throw new Error("Remote Bridge launch helper is unavailable.");
      }
      var data = await cbRigStartAllFromSavedSettings();
      var describe = typeof cbRigDescribeAction === "function"
        ? cbRigDescribeAction
        : function (payload, fallback) { return (payload && payload.note) || fallback || ""; };
      if (!data || data.ok === false) {
        var failure = describe(data, "Remote Bridge rig start failed.");
        state.errorText = failure;
        state.actionStatusText = failure;
      } else {
        state.errorText = "";
        state.actionStatusText = describe(data, "Remote Bridge rig is active.");
      }
    } catch (err) {
      var message = String((err && err.message) || err);
      state.errorText = message;
      state.actionStatusText = message;
    } finally {
      state.cardBridgeLaunchInFlight = false;
      if (commandState.activeSubsystem === "HIL") {
        renderHilWorkbench(container, actions, leaf);
      }
    }
  }

  function renderHilDissectorTab(body) {
    var state = commandState.hilWorkbench;
    body.innerHTML = "";

    var status = document.createElement("div");
    status.className = "cc-hil-statusbar";
    hilRenderStatusbar(status);
    body.appendChild(status);

    if (state.errorText) {
      body.appendChild(renderErrorBlock(state.errorText));
    }

    var grid = document.createElement("div");
    grid.className = "cc-hil-dissector-grid";

    var listPane = document.createElement("section");
    listPane.className = "cc-hil-pane cc-hil-packet-pane";
    var listHead = document.createElement("div");
    listHead.className = "cc-hil-pane-head";
    listHead.textContent = state.viewMode === "context" ? "Context" : "Packets";
    listPane.appendChild(listHead);
    var list = document.createElement("div");
    list.className = "cc-hil-packet-list";
    list.setAttribute("role", "listbox");
    list.addEventListener("wheel", function () {
      state.lastPacketScrollAt = Date.now();
    }, { passive: true });
    list.addEventListener("pointerdown", function (event) {
      hilBeginPacketPointerInteraction(event);
    });
    list.addEventListener("pointerup", function () {
      hilEndPacketPointerInteraction();
    });
    list.addEventListener("pointercancel", function () {
      hilEndPacketPointerInteraction();
    });
    list.addEventListener("lostpointercapture", function () {
      hilEndPacketPointerInteraction();
    });
    if (!state.packetPointerReleaseListenersInstalled) {
      state.packetPointerReleaseListenersInstalled = true;
      window.addEventListener("pointerup", function () {
        hilEndPacketPointerInteraction();
      }, true);
      window.addEventListener("pointercancel", function () {
        hilEndPacketPointerInteraction();
      }, true);
    }
    list.addEventListener("scroll", function () {
      hilRememberPacketScroll(list);
      if (!state.packetScrollRestoring) {
        hilSchedulePacketVirtualRender(list);
      }
    });
    listPane.appendChild(list);
    renderHilPacketList(list);
    grid.appendChild(listPane);

    var detailPane = document.createElement("section");
    detailPane.className = "cc-hil-pane cc-hil-detail-pane";
    var detailHead = document.createElement("div");
    detailHead.className = "cc-hil-pane-head";
    detailHead.textContent = state.selectedFrameNumber ? "Frame #" + state.selectedFrameNumber : "Frame";
    detailPane.appendChild(detailHead);
    detailPane.appendChild(hilDecodedBlock("Decoded", state.detail || "No decoded frame selected.", "detail"));
    detailPane.appendChild(hilBytesBlock("Bytes", state.bytes || "No byte view selected.", "bytes"));
    grid.appendChild(detailPane);

    body.appendChild(grid);
    hilApplyByteHighlightClasses();
  }

  function hilCapturePathFromRows(state) {
    return state.lastCapturePath || "";
  }

  function hilRenderStatusbar(status) {
    var state = commandState.hilWorkbench;
    if (!status) return;
    status.innerHTML = "";
    status.appendChild(hilStatusChip("session", state.armed ? state.startMode || "live" : "stopped"));
    status.appendChild(hilStatusChip("status", state.statusText));
    if (state.actionStatusText) {
      status.appendChild(hilStatusChip("action", state.actionStatusText));
    }
    status.appendChild(hilStatusChip("packets", String(state.rows.length)));
    status.appendChild(hilStatusChip("selected", state.selectedFrameNumber ? "#" + state.selectedFrameNumber : "-"));
    hilRefreshTimerAnchor();
    hilActiveTimerStatusChips().forEach(function (chip) {
      status.appendChild(chip);
    });
    if (state.captureSource) {
      status.appendChild(hilStatusChip("source", state.captureSource));
    }
    var captureLabel = state.capturePath || hilCapturePathFromRows(state) || "live";
    status.appendChild(hilStatusChip("capture", captureLabel));
    if (state.paused) status.appendChild(hilStatusChip("paused", "yes"));
  }

  function hilRefreshTimerStatusbar() {
    if (commandState.activeSubsystem !== "HIL") return false;
    var state = commandState.hilWorkbench;
    if (!state || state.activeTab !== "dissector") return false;
    var status = document.querySelector(".cc-hil-workbench .cc-hil-statusbar");
    if (!status) return false;
    hilRenderStatusbar(status);
    return true;
  }

  function hilStartTimerStatusTicker() {
    var state = commandState.hilWorkbench;
    if (!state || state.timerStatusTimerId !== null) return;
    state.timerStatusTimerId = setInterval(function () {
      if (!hilRefreshTimerStatusbar()) {
        if (state.timerStatusTimerId !== null) {
          clearInterval(state.timerStatusTimerId);
          state.timerStatusTimerId = null;
        }
      }
    }, 500);
  }

  function hilStatusChip(label, value) {
    var chip = document.createElement("span");
    chip.className = "cc-hil-status-chip";
    var k = document.createElement("span");
    k.className = "cc-hil-status-key";
    k.textContent = label;
    var v = document.createElement("span");
    v.className = "cc-hil-status-value";
    v.textContent = String(value || "-");
    chip.appendChild(k);
    chip.appendChild(v);
    return chip;
  }

  function hilActiveTimerStatusChips() {
    var timerSummary = hilActiveTimerSummary();
    if (!timerSummary) return [];
    return [
      hilStatusChip("timers", String(timerSummary.count)),
      hilStatusChip("countdown", timerSummary.text),
    ];
  }

  function hilActiveTimerSummary() {
    var state = commandState.hilWorkbench;
    var ann = hilLatestTimerAnnotation();
    if (!ann || !Array.isArray(ann.active_timers)) return null;
    hilRefreshTimerAnchor(ann);
    var visible = [];
    var visibleCount = 0;
    ann.active_timers.forEach(function (timer) {
      var remainingSeconds = hilTimerRemainingSeconds(timer);
      if (remainingSeconds <= 0) return;
      visibleCount += 1;
      if (visible.length >= 3) return;
      var label = String(timer && timer.display_label || "").trim();
      if (!label) label = "T" + String(parseInt(timer && timer.timer_id || 0, 10) || 0);
      visible.push(label + " " + hilFormatDurationClock(remainingSeconds));
    });
    if (visibleCount === 0) return null;
    if (visibleCount > visible.length) visible.push("+" + String(visibleCount - visible.length) + " more");
    return {
      count: visibleCount,
      text: visible.join(", "),
      annotation: ann,
    };
  }

  function hilRefreshTimerAnchor(annotation) {
    var state = commandState.hilWorkbench;
    var ann = annotation || hilLatestTimerAnnotation();
    if (!ann || !Array.isArray(ann.active_timers) || ann.active_timers.length === 0) {
      state.timerSnapshotAppliedAt = 0;
      state.timerSnapshotCaptureSeconds = null;
      state.timerSnapshotSignature = "";
      return;
    }
    var signature = hilTimerAnnotationSignature(ann);
    var captureSeconds = hilTimerAnnotationCaptureSeconds(ann);
    if (
      state.timerSnapshotSignature !== signature
      || state.timerSnapshotCaptureSeconds !== captureSeconds
    ) {
      state.timerSnapshotSignature = signature;
      state.timerSnapshotCaptureSeconds = captureSeconds;
      state.timerSnapshotAppliedAt = Date.now();
    }
  }

  function hilTimerAnnotationSignature(annotation) {
    var timers = Array.isArray(annotation && annotation.active_timers)
      ? annotation.active_timers
      : [];
    return [
      String(hilTimerAnnotationCaptureSeconds(annotation)),
      timers.map(function (timer) {
        return [
          String(parseInt(timer && timer.timer_id || 0, 10) || 0),
          String(parseInt(timer && timer.configured_seconds || 0, 10) || 0),
          String(parseInt(timer && timer.remaining_seconds || 0, 10) || 0),
          String(timer && timer.display_label || ""),
        ].join(":");
      }).join("|"),
    ].join("/");
  }

  function hilTimerAnnotationCaptureSeconds(annotation) {
    var value = Number(annotation && annotation.capture_time_seconds);
    if (!isFinite(value)) return null;
    return Math.round(value * 1000) / 1000;
  }

  function hilLatestTimerAnnotation() {
    var state = commandState.hilWorkbench;
    var annotations = state.annotations || {};
    var rows = state.rows || [];
    for (var i = rows.length - 1; i >= 0; i -= 1) {
      var frameNumber = parseInt(rows[i] && rows[i].number || 0, 10);
      var ann = annotations[String(frameNumber)] || null;
      if (ann && Array.isArray(ann.active_timers) && ann.active_timers.length > 0) return ann;
    }
    var selected = annotations[String(state.selectedFrameNumber || "")] || null;
    if (selected && Array.isArray(selected.active_timers) && selected.active_timers.length > 0) return selected;
    return null;
  }

  function hilTimerRemainingSeconds(timer) {
    var state = commandState.hilWorkbench;
    var remainingSeconds = parseInt(timer && timer.remaining_seconds || 0, 10) || 0;
    var liveCountdown = hilIsLiveCaptureMode(state) || state.captureSource === "remote";
    if (!liveCountdown || !state.timerSnapshotAppliedAt) return Math.max(0, remainingSeconds);
    var elapsedSeconds = Math.max(0, (Date.now() - Number(state.timerSnapshotAppliedAt || 0)) / 1000);
    return Math.max(0, Math.ceil(remainingSeconds - elapsedSeconds));
  }

  function hilFormatDurationClock(totalSeconds) {
    var normalizedSeconds = Math.max(0, parseInt(totalSeconds || 0, 10) || 0);
    var hours = Math.floor(normalizedSeconds / 3600);
    var minutes = Math.floor((normalizedSeconds % 3600) / 60);
    var seconds = normalizedSeconds % 60;
    return [
      String(hours).padStart(2, "0"),
      String(minutes).padStart(2, "0"),
      String(seconds).padStart(2, "0"),
    ].join(":");
  }

  function hilPreBlock(titleText, bodyText, scrollSlot) {
    var state = commandState.hilWorkbench;
    var wrap = document.createElement("div");
    wrap.className = "cc-hil-pre-block";
    var title = document.createElement("div");
    title.className = "cc-hil-pre-title";
    title.textContent = titleText;
    wrap.appendChild(title);
    var pre = document.createElement("pre");
    pre.className = "cc-hil-pre";
    pre.textContent = bodyText;
    hilInstallScrollMemory(pre, scrollSlot);
    wrap.appendChild(pre);
    return wrap;
  }

  function hilBytesBlock(titleText, bodyText, scrollSlot) {
    var wrap = document.createElement("div");
    wrap.className = "cc-hil-pre-block cc-hil-bytes-block";
    var title = document.createElement("div");
    title.className = "cc-hil-pre-title";
    title.textContent = titleText;
    wrap.appendChild(title);
    var pre = document.createElement("pre");
    pre.className = "cc-hil-pre cc-hil-byte-dump";
    hilRenderByteDump(pre, bodyText);
    hilInstallScrollMemory(pre, scrollSlot);
    wrap.appendChild(pre);
    return wrap;
  }

  function hilDecodedBlock(titleText, bodyText, scrollSlot) {
    var state = commandState.hilWorkbench;
    var wrap = document.createElement("div");
    wrap.className = "cc-hil-pre-block cc-hil-decoded-block";
    var title = document.createElement("div");
    title.className = "cc-hil-pre-title";
    title.textContent = titleText;
    wrap.appendChild(title);

    var scroller = document.createElement("div");
    scroller.className = "cc-hil-decoded-scroll";
    hilInstallScrollMemory(scroller, scrollSlot);

    var sections = hilParseDecodedSections(bodyText);
    if (sections.length === 0) {
      var fallback = document.createElement("pre");
      fallback.className = "cc-hil-decoded-fallback";
      fallback.textContent = bodyText;
      scroller.appendChild(fallback);
      wrap.appendChild(scroller);
      return wrap;
    }

    var list = document.createElement("div");
    list.className = "cc-hil-decoded-sections";
    sections.forEach(function (section, index) {
      var details = document.createElement("details");
      details.className = "cc-hil-decoded-section";
      var stateKey = hilDecodedSectionKey(section.title, index);
      var hasStoredState = Object.prototype.hasOwnProperty.call(state.detailSectionOpen, stateKey);
      details.open = hasStoredState
        ? state.detailSectionOpen[stateKey] === true
        : hilDecodedSectionDefaultOpen(section.title);
      details.addEventListener("toggle", function () {
        state.detailSectionOpen[stateKey] = details.open;
      });

      var summary = document.createElement("summary");
      summary.className = "cc-hil-decoded-summary";
      summary.textContent = section.title;
      hilAttachRangeEvents(summary, hilFindRangeForDecodedLine(section.title));
      details.appendChild(summary);

      details.appendChild(hilDecodedSectionBody(section.lines));
      list.appendChild(details);
    });
    scroller.appendChild(list);
    wrap.appendChild(scroller);
    return wrap;
  }

  function hilDecodedSectionDefaultOpen(titleText) {
    return String(titleText || "").trim().toUpperCase() === "GSM SIM 11.11";
  }

  function hilDecodedSectionBody(lines) {
    var body = document.createElement("div");
    body.className = "cc-hil-decoded-section-body";
    var sourceLines = Array.isArray(lines) && lines.length > 0
      ? lines
      : ["(no decoded child fields)"];
    sourceLines.forEach(function (line) {
      var row = document.createElement("div");
      row.className = "cc-hil-decoded-line";
      var text = String(line || "");
      row.textContent = text.length > 0 ? text : " ";
      hilAttachRangeEvents(row, hilFindRangeForDecodedLine(text));
      body.appendChild(row);
    });
    return body;
  }

  function hilRenderByteDump(pre, bodyText) {
    var lines = String(bodyText || "").replace(/\r\n/g, "\n").split("\n");
    var renderedAny = false;
    lines.forEach(function (line, lineIndex) {
      if (lineIndex > 0) pre.appendChild(document.createTextNode("\n"));
      var rendered = hilRenderByteDumpLine(line);
      pre.appendChild(rendered);
      renderedAny = renderedAny || !!rendered.dataset.byteLine;
    });
    if (!renderedAny && pre.textContent.length === 0) {
      pre.textContent = bodyText;
    }
  }

  function hilRenderByteDumpLine(line) {
    var raw = String(line || "");
    var row = document.createElement("span");
    row.className = "cc-hil-byte-line";
    var match = raw.match(/^\s*([0-9A-Fa-f]{4,8})\s+(.+)$/);
    if (!match) {
      row.textContent = raw;
      return row;
    }
    var startOffset = parseInt(match[1], 16);
    if (!isFinite(startOffset)) {
      row.textContent = raw;
      return row;
    }
    var rest = match[2] || "";
    var tokens = rest.trim().split(/\s+/);
    var bytes = [];
    for (var i = 0; i < tokens.length && bytes.length < 16; i += 1) {
      if (!/^[0-9A-Fa-f]{2}$/.test(tokens[i])) break;
      bytes.push(tokens[i].toUpperCase());
    }
    if (bytes.length === 0) {
      row.textContent = raw;
      return row;
    }
    row.dataset.byteLine = "1";
    var offset = document.createElement("span");
    offset.className = "cc-hil-byte-offset";
    offset.textContent = match[1].toLowerCase();
    row.appendChild(offset);
    row.appendChild(document.createTextNode("  "));
    bytes.forEach(function (byteText, index) {
      var byteOffset = startOffset + index;
      var span = document.createElement("span");
      span.className = "cc-hil-byte";
      span.dataset.offset = String(byteOffset);
      span.textContent = byteText;
      hilAttachByteEvents(span, byteOffset);
      row.appendChild(span);
      if (index < bytes.length - 1) {
        row.appendChild(document.createTextNode(index === 7 ? "  " : " "));
      }
    });
    var asciiIndex = nthIndexOfHexByte(rest, bytes.length);
    if (asciiIndex >= 0) {
      var asciiText = rest.slice(asciiIndex).trim();
      if (asciiText.length > 0) {
        row.appendChild(document.createTextNode("   " + asciiText));
      }
    }
    return row;
  }

  function nthIndexOfHexByte(text, count) {
    var re = /[0-9A-Fa-f]{2}/g;
    var match = null;
    var seen = 0;
    while ((match = re.exec(String(text || ""))) !== null) {
      seen += 1;
      if (seen === count) return re.lastIndex;
    }
    return -1;
  }

  function hilAttachRangeEvents(el, range) {
    if (!el || !range) return;
    el.classList.add("cc-hil-decoded-range");
    el.dataset.rangeKey = hilRangeKey(range);
    el.dataset.rangeStart = String(range.start);
    el.dataset.rangeEnd = String(range.end);
    el.title = hilRangeLabel(range);
    el.addEventListener("mouseenter", function () {
      hilSetByteHighlight(range, false);
    });
    el.addEventListener("mouseleave", function () {
      hilClearByteHighlight(false);
    });
    el.addEventListener("click", function (event) {
      event.stopPropagation();
      hilSetByteHighlight(range, true);
    });
  }

  function hilAttachByteEvents(el, byteOffset) {
    if (!el) return;
    el.addEventListener("mouseenter", function () {
      var range = hilBestRangeForByte(byteOffset);
      if (range) {
        hilSetByteHighlight(range, false);
      } else {
        hilApplyByteOffsetHighlight(byteOffset, false);
      }
    });
    el.addEventListener("mouseleave", function () {
      hilClearByteHighlight(false);
    });
    el.addEventListener("click", function (event) {
      event.stopPropagation();
      var range = hilBestRangeForByte(byteOffset);
      if (range) {
        hilSetByteHighlight(range, true);
      } else {
        hilApplyByteOffsetHighlight(byteOffset, true);
      }
    });
  }

  function hilSetByteHighlight(range, pinned) {
    var state = commandState.hilWorkbench;
    var normalized = hilNormalizeRange(range);
    if (!normalized) return;
    if (pinned) {
      var pinnedKey = hilRangeKey(state.byteHighlightPinnedRange);
      var nextKey = hilRangeKey(normalized);
      state.byteHighlightPinnedRange = pinnedKey === nextKey ? null : normalized;
      state.byteHighlightHoverRange = null;
    } else {
      state.byteHighlightHoverRange = normalized;
    }
    hilApplyByteHighlightClasses();
  }

  function hilClearByteHighlight(includePinned) {
    var state = commandState.hilWorkbench;
    state.byteHighlightHoverRange = null;
    if (includePinned) state.byteHighlightPinnedRange = null;
    hilApplyByteHighlightClasses();
  }

  function hilApplyByteOffsetHighlight(byteOffset, pinned) {
    hilSetByteHighlight({
      start: byteOffset,
      end: byteOffset + 1,
      size: 1,
      label: "Byte " + byteOffset,
      name: "frame.byte",
    }, pinned);
  }

  function hilApplyByteHighlightClasses() {
    var state = commandState.hilWorkbench;
    var hoverRange = hilNormalizeRange(state.byteHighlightHoverRange);
    var pinnedRange = hilNormalizeRange(state.byteHighlightPinnedRange);
    var activeRange = hoverRange || pinnedRange;
    var activeKey = hilRangeKey(activeRange);
    var pinnedKey = hilRangeKey(pinnedRange);
    document.querySelectorAll(".cc-hil-byte").forEach(function (el) {
      var offset = parseInt(el.dataset.offset || "-1", 10);
      var active = !!(activeRange && offset >= activeRange.start && offset < activeRange.end);
      var pinned = !!(pinnedRange && offset >= pinnedRange.start && offset < pinnedRange.end);
      el.classList.toggle("is-highlighted", active);
      el.classList.toggle("is-pinned", pinned);
    });
    document.querySelectorAll(".cc-hil-decoded-range").forEach(function (el) {
      var key = String(el.dataset.rangeKey || "");
      el.classList.toggle("is-highlighted", !!activeKey && key === activeKey);
      el.classList.toggle("is-pinned", !!pinnedKey && key === pinnedKey);
    });
  }

  function hilFindRangeForDecodedLine(lineText) {
    var state = commandState.hilWorkbench;
    var ranges = Array.isArray(state.detailRanges) ? state.detailRanges : [];
    if (ranges.length === 0) return null;
    var normalizedLine = hilNormalizeHighlightText(lineText);
    if (normalizedLine.length < 3) return null;
    var best = null;
    var bestScore = -1;
    ranges.forEach(function (range) {
      var normalized = hilNormalizeRange(range);
      if (!normalized) return;
      var score = hilDecodedLineRangeScore(normalizedLine, normalized);
      if (score > bestScore || (score === bestScore && best && normalized.size < best.size)) {
        best = normalized;
        bestScore = score;
      }
    });
    return bestScore > 0 ? best : null;
  }

  function hilDecodedLineRangeScore(normalizedLine, range) {
    var candidates = hilRangeTextCandidates(range);
    var best = 0;
    candidates.forEach(function (candidate) {
      if (candidate.length < 3) return;
      if (normalizedLine === candidate) {
        best = Math.max(best, 100000 - range.size);
      } else if (normalizedLine.indexOf(candidate) >= 0) {
        best = Math.max(best, 10000 + candidate.length - range.size);
      } else if (candidate.indexOf(normalizedLine) >= 0 && normalizedLine.length >= 8) {
        best = Math.max(best, 1000 + normalizedLine.length - range.size);
      }
    });
    return best;
  }

  function hilBestRangeForByte(byteOffset) {
    var state = commandState.hilWorkbench;
    var ranges = Array.isArray(state.detailRanges) ? state.detailRanges : [];
    var best = null;
    ranges.forEach(function (range) {
      var normalized = hilNormalizeRange(range);
      if (!normalized) return;
      if (byteOffset < normalized.start || byteOffset >= normalized.end) return;
      if (!best || normalized.size < best.size || (
        normalized.size === best.size && normalized.depth > best.depth
      )) {
        best = normalized;
      }
    });
    return best;
  }

  function hilNormalizeRange(range) {
    if (!range) return null;
    var start = parseInt(range.start, 10);
    var end = parseInt(range.end, 10);
    var size = parseInt(range.size, 10);
    if (!isFinite(start) || start < 0) return null;
    if (!isFinite(end) || end <= start) {
      if (!isFinite(size) || size <= 0) return null;
      end = start + size;
    }
    size = end - start;
    return {
      start: start,
      end: end,
      size: size,
      depth: parseInt(range.depth || 0, 10) || 0,
      name: String(range.name || ""),
      label: String(range.label || ""),
      show: String(range.show || ""),
      value: String(range.value || ""),
    };
  }

  function hilRangeTextCandidates(range) {
    var values = [
      range.label,
      range.name,
      range.show,
      range.value,
      range.name && range.show ? range.name + ": " + range.show : "",
    ];
    var seen = {};
    return values.map(hilNormalizeHighlightText).filter(function (value) {
      if (value.length === 0 || seen[value]) return false;
      seen[value] = true;
      return true;
    });
  }

  function hilNormalizeHighlightText(value) {
    return String(value || "")
      .replace(/\[[^\]]+\]/g, " ")
      .replace(/[<>]/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
  }

  function hilRangeKey(range) {
    var normalized = hilNormalizeRange(range);
    if (!normalized) return "";
    return [
      normalized.start,
      normalized.end,
      normalized.name,
      normalized.label,
    ].join("|");
  }

  function hilRangeLabel(range) {
    var normalized = hilNormalizeRange(range);
    if (!normalized) return "";
    var label = normalized.label || normalized.name || "frame bytes";
    return label + " [" + normalized.start + ".." + (normalized.end - 1) + "]";
  }

  function hilInstallScrollMemory(el, scrollSlot) {
    if (!scrollSlot) return;
    var state = commandState.hilWorkbench;
    var topKey = scrollSlot + "ScrollTop";
    var leftKey = scrollSlot + "ScrollLeft";
    var restoreTop = Number(state[topKey] || 0);
    var restoreLeft = Number(state[leftKey] || 0);
    var restoreScroll = function () {
      el.scrollTop = restoreTop;
      el.scrollLeft = restoreLeft;
    };
    if (restoreTop > 0 || restoreLeft > 0) {
      if (window.requestAnimationFrame) {
        window.requestAnimationFrame(restoreScroll);
      } else {
        setTimeout(restoreScroll, 0);
      }
    }
    el.addEventListener("scroll", function () {
      state[topKey] = el.scrollTop || 0;
      state[leftKey] = el.scrollLeft || 0;
    });
  }

  function hilParseDecodedSections(text) {
    var lines = String(text || "").replace(/\r\n/g, "\n").split("\n");
    var sections = [];
    var current = null;
    lines.forEach(function (line) {
      if (line.trim().length === 0) {
        if (current) current.lines.push(line);
        return;
      }
      if (line.charAt(0).trim().length > 0) {
        current = {
          title: line.trim(),
          lines: [],
        };
        sections.push(current);
        return;
      }
      if (!current) {
        current = {
          title: "Decoded fields",
          lines: [],
        };
        sections.push(current);
      }
      current.lines.push(line);
    });
    if (sections.length <= 1 && sections[0] && sections[0].lines.length === 0) {
      return [];
    }
    return sections;
  }

  function hilDecodedSectionKey(titleText, index) {
    var state = commandState.hilWorkbench;
    return String(state.selectedFrameNumber || 0) + "|"
      + String(index) + "|"
      + String(titleText || "");
  }

  function hilResetDetailScroll() {
    var state = commandState.hilWorkbench;
    state.detailScrollTop = 0;
    state.detailScrollLeft = 0;
    state.detailSectionOpen = {};
    state.bytesScrollTop = 0;
    state.bytesScrollLeft = 0;
  }

  function hilResetPacketSections() {
    var state = commandState.hilWorkbench;
    state.packetSectionOpen = {};
    state.contextTree = [];
    hilResetTimerSnapshot();
  }

  function hilResetTimerSnapshot() {
    var state = commandState.hilWorkbench;
    state.timerSnapshotAppliedAt = 0;
    state.timerSnapshotCaptureSeconds = null;
    state.timerSnapshotSignature = "";
  }

  function hilResetPacketScroll() {
    var state = commandState.hilWorkbench;
    hilCancelDeferredPacketRender();
    hilCancelPacketVirtualRender();
    if (state.packetPointerReleaseTimerId) {
      clearTimeout(state.packetPointerReleaseTimerId);
      state.packetPointerReleaseTimerId = null;
    }
    state.packetPointerActive = false;
    state.packetPointerId = null;
    state.packetScrollTop = 0;
    state.packetScrollHeight = 0;
    state.packetClientHeight = 0;
    state.packetScrollBottomGap = 0;
    state.lastPacketScrollAt = 0;
  }

  function hilStorePacketScroll(list, markUserScroll) {
    var state = commandState.hilWorkbench;
    if (!list) return;
    var maxTop = Math.max(0, (list.scrollHeight || 0) - (list.clientHeight || 0));
    var top = Math.max(0, Math.min(Number(list.scrollTop || 0), maxTop));
    var bottomGap = Math.max(0, maxTop - top);
    state.packetScrollTop = top;
    state.packetScrollHeight = list.scrollHeight || 0;
    state.packetClientHeight = list.clientHeight || 0;
    state.packetScrollBottomGap = bottomGap;
    if (markUserScroll) {
      state.lastPacketScrollAt = Date.now();
      state.followTail = bottomGap <= 24;
    }
  }

  function hilRememberPacketScroll(list) {
    var state = commandState.hilWorkbench;
    hilStorePacketScroll(list, !state.packetScrollRestoring);
  }

  function hilCancelDeferredPacketRender() {
    var state = commandState.hilWorkbench;
    if (state.packetRenderTimerId) {
      clearTimeout(state.packetRenderTimerId);
      state.packetRenderTimerId = null;
    }
    state.packetRenderPending = false;
  }

  function hilCancelPacketVirtualRender() {
    var state = commandState.hilWorkbench;
    if (state.packetVirtualRenderTimerId) {
      clearTimeout(state.packetVirtualRenderTimerId);
      state.packetVirtualRenderTimerId = null;
    }
  }

  function hilPacketPointerIsActive() {
    var state = commandState.hilWorkbench;
    return !!state.packetPointerActive;
  }

  function hilBeginPacketPointerInteraction(event) {
    var state = commandState.hilWorkbench;
    if (event && event.button !== undefined && event.button !== 0) return;
    if (state.packetPointerReleaseTimerId) {
      clearTimeout(state.packetPointerReleaseTimerId);
      state.packetPointerReleaseTimerId = null;
    }
    state.packetPointerActive = true;
    state.packetPointerId = event && event.pointerId !== undefined ? event.pointerId : null;
  }

  function hilEndPacketPointerInteraction() {
    var state = commandState.hilWorkbench;
    if (!state.packetPointerActive && !state.packetPointerReleaseTimerId) return;
    if (state.packetPointerReleaseTimerId) {
      clearTimeout(state.packetPointerReleaseTimerId);
    }
    state.packetPointerReleaseTimerId = setTimeout(function () {
      state.packetPointerReleaseTimerId = null;
      state.packetPointerActive = false;
      state.packetPointerId = null;
      hilFlushDeferredPacketRender();
    }, 0);
  }

  function hilSchedulePacketVirtualRender(list) {
    var state = commandState.hilWorkbench;
    if (!list || state.packetVirtualRenderTimerId) return;
    state.packetVirtualRenderTimerId = setTimeout(function () {
      state.packetVirtualRenderTimerId = null;
      if (!list.isConnected) return;
      if (hilPacketPointerIsActive()) {
        hilSchedulePacketVirtualRender(list);
        return;
      }
      renderHilPacketList(list, { preserveExactScroll: true });
    }, 16);
  }

  function hilPacketListIsUserActive() {
    var state = commandState.hilWorkbench;
    return Date.now() - Number(state.lastPacketScrollAt || 0) < 450;
  }

  function hilShouldDeferPacketRender(options) {
    var opts = options || {};
    var state = commandState.hilWorkbench;
    if (opts.force) return false;
    if (commandState.activeSubsystem !== "HIL") return false;
    if (state.activeTab !== "dissector") return false;
    return hilPacketPointerIsActive() || hilPacketListIsUserActive();
  }

  function hilScheduleDeferredPacketRender() {
    var state = commandState.hilWorkbench;
    state.packetRenderPending = true;
    if (state.packetRenderTimerId) return;
    state.packetRenderTimerId = setTimeout(function () {
      state.packetRenderTimerId = null;
      if (!state.packetRenderPending) return;
      if (hilShouldDeferPacketRender({ force: false })) {
        hilScheduleDeferredPacketRender();
        return;
      }
      state.packetRenderPending = false;
      hilRenderActivePaneOnly();
    }, 450);
  }

  function hilFlushDeferredPacketRender() {
    var state = commandState.hilWorkbench;
    if (!state.packetRenderPending) return;
    if (hilShouldDeferPacketRender({ force: false })) {
      hilScheduleDeferredPacketRender();
      return;
    }
    if (state.packetRenderTimerId) {
      clearTimeout(state.packetRenderTimerId);
      state.packetRenderTimerId = null;
    }
    state.packetRenderPending = false;
    hilRenderActivePaneOnly();
  }

  function hilRestorePacketScroll(list, options) {
    var state = commandState.hilWorkbench;
    if (!list) return;
    var opts = options || {};
    var applyScroll = function () {
      state.packetScrollRestoring = true;
      if (opts.preserveExactScroll) {
        var exactMaxTop = Math.max(0, (list.scrollHeight || 0) - (list.clientHeight || 0));
        var exactTop = typeof opts.preservedTop === "number" && !isNaN(opts.preservedTop)
          ? opts.preservedTop
          : Number(state.packetScrollTop || 0);
        list.scrollTop = Math.max(0, Math.min(exactTop, exactMaxTop));
        hilStorePacketScroll(list, false);
      } else if (state.followTail) {
        list.scrollTop = list.scrollHeight || 0;
        hilStorePacketScroll(list, false);
      } else {
        var maxTop = Math.max(0, (list.scrollHeight || 0) - (list.clientHeight || 0));
        var top = Number(state.packetScrollTop || 0);
        if (typeof opts.preservedTop === "number" && !isNaN(opts.preservedTop)) {
          top = opts.preservedTop;
        }
        top = Math.max(0, Math.min(top, maxTop));
        list.scrollTop = top;
        hilStorePacketScroll(list, false);
      }
      setTimeout(function () {
        state.packetScrollRestoring = false;
      }, 0);
    };
    if (window.requestAnimationFrame) {
      window.requestAnimationFrame(applyScroll);
    } else {
      setTimeout(applyScroll, 0);
    }
  }

  function hilResetLiveBaseline() {
    var state = commandState.hilWorkbench;
    state.liveBaselinePending = false;
    state.liveBaselineFrameNumber = 0;
    state.liveBaselineCaptureSize = 0;
    state.liveBaselineCaptureMtime = 0;
  }

  function hilIsLiveCaptureMode(state) {
    return !!(
      state
      && state.armed
      && !state.capturePath
      && state.startMode !== "offline"
    );
  }

  function hilPromoteLiveBaselineFromRows(rows) {
    var state = commandState.hilWorkbench;
    var maxFrame = Number(state.liveBaselineFrameNumber || 0);
    (rows || []).forEach(function (row) {
      var frameNumber = parseInt(row && row.number || 0, 10);
      if (frameNumber > maxFrame) maxFrame = frameNumber;
    });
    state.liveBaselineFrameNumber = maxFrame;
  }

  function hilRenderPacketListOnly(options) {
    if (commandState.activeSubsystem !== "HIL") return false;
    var list = document.querySelector(".cc-hil-workbench .cc-hil-packet-list");
    if (!list) return false;
    renderHilPacketList(list, options || {});
    return true;
  }

  function renderHilPacketList(list, options) {
    var state = commandState.hilWorkbench;
    var opts = options || {};
    var preservedScrollTop = typeof opts.preservedTop === "number"
      ? opts.preservedTop
      : (list.childNodes.length > 0 ? Number(list.scrollTop || 0) : null);
    var items = [];
    list.innerHTML = "";
    if (!state.rows || state.rows.length === 0) {
      var empty = document.createElement("div");
      empty.className = "cc-hil-empty";
      empty.textContent = state.inflight
        ? "Loading packets..."
        : (state.armed ? "No decoded packets." : "Start HIL or open a pcap to attach the dissector.");
      list.appendChild(empty);
      return;
    }
    if (state.viewMode === "context") {
      items = hilBuildContextPacketItems(state.rows, state.annotations || {});
    } else {
      items = hilBuildFlatPacketItems(state.rows, state.annotations || {});
    }
    if (items.length === 0) {
      var noVisible = document.createElement("div");
      noVisible.className = "cc-hil-empty";
      noVisible.textContent = "No visible packets.";
      list.appendChild(noVisible);
      return;
    }
    hilRenderPacketItems(list, items, {
      preserveExactScroll: !!opts.preserveExactScroll,
      preservedTop: preservedScrollTop,
    });
  }

  function renderHilContextTree(list, rows, annotations) {
    hilBuildContextPacketItems(rows, annotations).forEach(function (item) {
      list.appendChild(hilPacketRenderItem(item));
    });
  }

  function hilBuildFlatPacketItems(rows, annotations) {
    return (rows || []).map(function (row) {
      return {
        kind: "frame",
        row: row,
        annotation: annotations[String(row.number)] || null,
        options: null,
      };
    });
  }

  function hilBuildContextPacketItems(rows, annotations) {
    var state = commandState.hilWorkbench;
    var treeItems = Array.isArray(state.contextTree) ? state.contextTree : [];
    var rowByFrame = Object.create(null);
    (rows || []).forEach(function (row) {
      var frameNumber = parseInt(row && row.number || 0, 10);
      if (frameNumber) rowByFrame[String(frameNumber)] = row;
    });
    if (treeItems.length === 0) {
      return hilBuildFlatPacketItems(rows, annotations);
    }
    var rendered = [];
    var collapsedDepths = [];
    treeItems.forEach(function (item) {
      if (!item) return;
      var depth = Math.max(0, parseInt(item.depth || 0, 10) || 0);
      while (
        collapsedDepths.length > 0
        && depth <= collapsedDepths[collapsedDepths.length - 1]
      ) {
        collapsedDepths.pop();
      }
      if (collapsedDepths.length > 0) return;
      if (item.kind === "frame") {
        var frameNumber = parseInt(item.frame_number || 0, 10);
        var row = rowByFrame[String(frameNumber)];
        if (!row) return;
        rendered.push({
          kind: "frame",
          row: row,
          annotation: annotations[String(frameNumber)] || null,
          options: {
            depth: depth,
            primary: item.primary || "",
            secondary: item.secondary || "",
            groupName: item.group_name || "",
          },
        });
        return;
      }
      var open = hilContextHeaderIsOpen(item);
      rendered.push({
        kind: "header",
        item: item,
        open: open,
      });
      if (!open) collapsedDepths.push(depth);
    });
    return rendered;
  }

  function renderHilFlatContextFallback(list, rows, annotations) {
    (rows || []).forEach(function (row) {
      list.appendChild(hilPacketRow(row, annotations[String(row.number)] || null));
    });
  }

  function hilRenderPacketItems(list, items, options) {
    var state = commandState.hilWorkbench;
    var opts = options || {};
    var rowHeight = hilPacketVirtualRowHeight();
    var clientHeight = Math.max(Number(list.clientHeight || 0), rowHeight * 12);
    var targetTop = typeof opts.preservedTop === "number" && !isNaN(opts.preservedTop)
      ? Math.max(0, opts.preservedTop)
      : Number(state.packetScrollTop || 0);
    if (state.followTail && !opts.preserveExactScroll) {
      targetTop = Math.max(0, (items.length * rowHeight) - clientHeight);
    }
    var overscan = HIL_PACKET_VIRTUAL_OVERSCAN;
    var visibleCount = Math.ceil(clientHeight / rowHeight) + (overscan * 2);
    visibleCount = Math.min(hilPacketRenderLimit(), Math.max(1, visibleCount));
    var start = Math.max(0, Math.floor(targetTop / rowHeight) - overscan);
    var end = Math.min(items.length, start + visibleCount);
    if (end - start < visibleCount) {
      start = Math.max(0, end - visibleCount);
    }
    list.appendChild(hilPacketSpacer(start * rowHeight, "top"));
    for (var i = start; i < end; i++) {
      list.appendChild(hilPacketRenderItem(items[i]));
    }
    list.appendChild(hilPacketSpacer((items.length - end) * rowHeight, "bottom"));
    hilRestorePacketScroll(list, {
      preserveExactScroll: !!opts.preserveExactScroll,
      preservedTop: targetTop,
    });
  }

  function hilPacketRenderItem(item) {
    if (item && item.kind === "header") {
      return hilContextHeader(item.item, item.open);
    }
    return hilPacketRow(
      item && item.row,
      item && item.annotation || null,
      item && item.options || null
    );
  }

  function hilPacketSpacer(height, position) {
    var spacer = document.createElement("div");
    spacer.className = "cc-hil-packet-spacer cc-hil-packet-spacer--" + String(position || "");
    spacer.setAttribute("aria-hidden", "true");
    spacer.style.height = String(Math.max(0, Math.round(height || 0))) + "px";
    return spacer;
  }

  function hilContextSectionKey(item) {
    if (!item) return "context:";
    return "context:" + String(item.key || [
      String(item.kind || "group"),
      String(item.depth || 0),
      String(item.display || item.label || ""),
    ].join("|"));
  }

  function hilContextHeaderIsOpen(item) {
    var state = commandState.hilWorkbench;
    return state.packetSectionOpen[hilContextSectionKey(item)] === true;
  }

  function hilToggleContextHeader(item, sourceElement) {
    var state = commandState.hilWorkbench;
    var list = sourceElement && sourceElement.closest
      ? sourceElement.closest(".cc-hil-packet-list")
      : null;
    var preservedTop = list ? Number(list.scrollTop || 0) : null;
    if (list) hilStorePacketScroll(list, false);
    var key = hilContextSectionKey(item);
    if (state.packetSectionOpen[key] === true) {
      delete state.packetSectionOpen[key];
    } else {
      state.packetSectionOpen[key] = true;
    }
    if (list) {
      renderHilPacketList(list, {
        preserveExactScroll: true,
        preservedTop: preservedTop,
      });
    } else {
      hilRenderPacketListOnly({ preserveExactScroll: true });
    }
  }

  function hilContextHeader(item, open) {
    var depth = Math.max(0, parseInt(item && item.depth || 0, 10) || 0);
    var header = document.createElement("button");
    var isOpen = open !== false;
    header.className = "cc-hil-context-title";
    if (!isOpen) header.classList.add("is-collapsed");
    header.type = "button";
    header.setAttribute("aria-expanded", String(isOpen));
    header.setAttribute("data-context-key", hilContextSectionKey(item));
    header.style.paddingLeft = String(10 + (depth * 18)) + "px";
    var marker = document.createElement("span");
    marker.className = "cc-hil-context-caret";
    marker.setAttribute("aria-hidden", "true");
    marker.textContent = isOpen ? "▾" : "▸";
    var label = document.createElement("span");
    label.className = "cc-hil-context-label";
    label.textContent = String(item && (item.display || item.label) || "");
    header.appendChild(marker);
    header.appendChild(label);
    header.addEventListener("click", function () {
      hilToggleContextHeader(item, header);
    });
    return header;
  }

  function hilPacketRow(row, annotation, options) {
    var state = commandState.hilWorkbench;
    var opts = options || {};
    var frameNumber = parseInt(row.number || 0, 10);
    var selected = state.selectedFrameNumber === frameNumber;
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "cc-hil-packet-row" + (selected ? " is-selected" : "");
    if (opts.depth) {
      btn.classList.add("cc-hil-packet-row--context");
      btn.style.paddingLeft = String(10 + (Math.max(0, parseInt(opts.depth || 0, 10) || 0) * 18)) + "px";
    }
    if (opts.groupName) btn.setAttribute("data-group", String(opts.groupName || ""));
    btn.setAttribute("role", "option");
    btn.setAttribute("aria-selected", String(selected));
    btn.setAttribute("data-frame", String(frameNumber));

    var num = document.createElement("span");
    num.className = "cc-hil-packet-num";
    num.textContent = "#" + frameNumber;
    btn.appendChild(num);

    var time = document.createElement("span");
    time.className = "cc-hil-packet-time";
    time.textContent = row.wall_time_text || row.time_text || "";
    btn.appendChild(time);

    var proto = document.createElement("span");
    proto.className = "cc-hil-packet-proto";
    proto.textContent = row.protocol || "";
    btn.appendChild(proto);

    var info = document.createElement("span");
    info.className = "cc-hil-packet-info";
    var primaryText = String(opts.primary || "").trim();
    var secondaryText = String(opts.secondary || "").trim();
    if (primaryText.length > 0 && secondaryText.length > 0) {
      info.textContent = primaryText + " · " + secondaryText;
    } else {
      info.textContent = primaryText || row.annotated_info || row.info || "";
    }
    btn.appendChild(info);

    if (annotation && annotation.active_channel_count) {
      var ctx = document.createElement("span");
      ctx.className = "cc-hil-packet-badge";
      ctx.textContent = "CH " + annotation.active_channel_count;
      btn.appendChild(ctx);
    }

    btn.addEventListener("click", function () {
      var list = btn.closest ? btn.closest(".cc-hil-packet-list") : null;
      if (list) hilStorePacketScroll(list, false);
      hilSelectFrame(frameNumber);
    });
    return btn;
  }

  function renderHilRawTab(body) {
    var state = commandState.hilWorkbench;
    hilSeedRawRowsFromLogBus();
    hilAppendRawRowsFromPackets(state.rows || []);
    body.innerHTML = "";
    var rawShell = document.createElement("div");
    rawShell.className = "cc-hil-raw-shell";
    var rawBar = document.createElement("div");
    rawBar.className = "cc-hil-raw-bar";
    rawBar.appendChild(hilToolbarButton(
      state.rawPaused ? "▶" : "⏸",
      state.rawPaused ? "Resume" : "Pause",
      "Pause raw trace repaint",
      function () {
        state.rawPaused = !state.rawPaused;
        renderHilRawTab(body);
      },
      state.rawPaused
    ));
    rawBar.appendChild(hilToolbarButton("×", "Clear raw", "Clear raw APDU trace rows", function () {
      state.rawRows = [];
      state.rawPendingRows = [];
      state.rawPendingDropCount = 0;
      if (state.rawRenderTimerId !== null) {
        clearTimeout(state.rawRenderTimerId);
        state.rawRenderTimerId = null;
      }
      state.rawFrameSeen = {};
      state.rawClearedFrameNumber = hilMaxFrameNumber(state.rows || []);
      state.rawSnapshotSeeded = true;
      renderHilRawTab(body);
    }));
    rawShell.appendChild(rawBar);
    var rows = document.createElement("div");
    rows.className = "cc-hil-raw-rows";
    rawShell.appendChild(rows);
    body.appendChild(rawShell);
    renderHilRawRows(rows, { full: true });
  }

  function hilGetModemShellCommand() {
    var state = commandState.hilWorkbench;
    var current = String(state.modemShellCommand || "").trim();
    if (current.length > 0) return current;
    var stored = "";
    try {
      stored = window.localStorage.getItem(HIL_MODEM_COMMAND_KEY) || "";
    } catch (_err) {
      stored = "";
    }
    var preferred = hilPreferredModemShellCommand();
    if (stored === HIL_MODEM_DEFAULT_COMMAND && preferred !== HIL_MODEM_DEFAULT_COMMAND) {
      stored = "";
    }
    state.modemShellCommand = String(stored || preferred).trim();
    return state.modemShellCommand;
  }

  function hilPreferredModemShellCommand() {
    var state = commandState.hilWorkbench;
    var configured = String(state.modemShellDefaultCommand || "").trim();
    return configured || HIL_MODEM_DEFAULT_COMMAND;
  }

  function hilSetModemShellDefaultFromCapability(capability) {
    var state = commandState.hilWorkbench;
    var previous = hilPreferredModemShellCommand();
    var next = String((capability && capability.default_command) || "").trim()
      || HIL_MODEM_DEFAULT_COMMAND;
    state.modemShellDefaultCommand = next;
    state.modemShellDefaultSource = String(
      (capability && capability.default_command_source) || ""
    ).trim();
    state.modemShellRemoteTarget = String((capability && capability.remote_target) || "").trim();

    var input = $("hil-modem-command");
    var current = String((input && input.value) || state.modemShellCommand || "").trim();
    if (
      current.length === 0
      || current === previous
      || (current === HIL_MODEM_DEFAULT_COMMAND && next !== HIL_MODEM_DEFAULT_COMMAND)
    ) {
      state.modemShellCommand = next;
      if (input) input.value = next;
    }
    if (input) input.placeholder = next;
  }

  function hilSaveModemShellCommand(command, options) {
    var opts = options || {};
    var state = commandState.hilWorkbench;
    var text = String(command || "").trim();
    state.modemShellCommand = text;
    if (!text || opts.persist === false) return;
    try {
      window.localStorage.setItem(HIL_MODEM_COMMAND_KEY, text);
    } catch (_err) {}
  }

  function renderHilModemShellTab(body) {
    var state = commandState.hilWorkbench;
    body.innerHTML = "";

    var shell = document.createElement("div");
    shell.className = "cc-hil-modem-shell";

    var bar = document.createElement("div");
    bar.className = "cc-hil-modem-bar";

    var commandInput = document.createElement("input");
    commandInput.id = "hil-modem-command";
    commandInput.className = "cc-hil-modem-command";
    commandInput.type = "text";
    commandInput.autocomplete = "off";
    commandInput.spellcheck = false;
    commandInput.placeholder = hilPreferredModemShellCommand();
    commandInput.setAttribute("aria-label", "Modem shell command");
    commandInput.value = hilGetModemShellCommand();
    commandInput.addEventListener("change", function () {
      hilSaveModemShellCommand(commandInput.value);
    });
    commandInput.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        hilStartModemShell();
      }
    });
    bar.appendChild(commandInput);

    var startButton = hilToolbarButton("▶", "Start", "Start modem shell", hilStartModemShell);
    startButton.id = "hil-modem-start";
    bar.appendChild(startButton);
    var stopButton = hilToolbarButton("■", "Stop", "Stop modem shell", function () {
      hilStopModemShell({ dispose: false });
    });
    stopButton.id = "hil-modem-stop";
    bar.appendChild(stopButton);

    var deviceSelect = document.createElement("select");
    deviceSelect.id = "hil-modem-device";
    deviceSelect.className = "cc-hil-modem-device";
    deviceSelect.setAttribute("aria-label", "Serial device");
    bar.appendChild(deviceSelect);

    var refreshButton = hilToolbarButton("↻", "Devices", "Refresh serial devices", function () {
      hilLoadModemShellMetadata({ force: true });
    });
    refreshButton.id = "hil-modem-device-refresh";
    bar.appendChild(refreshButton);
    var useDeviceButton = hilToolbarButton("+", "Use device", "Use selected serial device", hilUseSelectedModemDevice);
    useDeviceButton.id = "hil-modem-device-use";
    bar.appendChild(useDeviceButton);

    var statusChip = document.createElement("span");
    statusChip.id = "hil-modem-status";
    statusChip.className = "cc-hil-status-chip cc-hil-modem-status";
    statusChip.textContent = state.modemShellStatusText || "idle";
    bar.appendChild(statusChip);

    shell.appendChild(bar);

    var terminalFrame = document.createElement("div");
    terminalFrame.className = "cc-hil-modem-terminal-frame";
    var terminalHost = document.createElement("div");
    terminalHost.id = "hil-modem-shell-host";
    terminalHost.className = "terminal-host cc-hil-modem-terminal";
    terminalHost.tabIndex = 0;
    terminalFrame.appendChild(terminalHost);
    shell.appendChild(terminalFrame);

    body.appendChild(shell);
    hilAttachModemShellTerminal(terminalHost);
    hilRenderModemShellMetadata();
    if (!state.modemShellCapability && !state.modemShellMetadataLoading) {
      hilLoadModemShellMetadata({ force: false });
    }
  }

  async function hilLoadModemShellMetadata(options) {
    var opts = options || {};
    var state = commandState.hilWorkbench;
    if (state.modemShellMetadataLoading && !opts.force) return;
    state.modemShellMetadataLoading = true;
    hilRenderModemShellMetadata();
    try {
      var capability = await apiFetch("/api/host-shell/capabilities?scope=hil-modem");
      state.modemShellCapability = capability || null;
      hilSetModemShellDefaultFromCapability(capability || null);
      var devices = await apiFetch("/api/host-shell/devices");
      state.modemShellDevices = (devices && Array.isArray(devices.devices))
        ? devices.devices
        : [];
      state.modemShellErrorText = "";
    } catch (err) {
      state.modemShellErrorText = String((err && err.message) || err);
    } finally {
      state.modemShellMetadataLoading = false;
      hilRenderModemShellMetadata();
    }
  }

  function hilRenderModemShellMetadata() {
    var state = commandState.hilWorkbench;
    var status = $("hil-modem-status");
    var start = $("hil-modem-start");
    var stop = $("hil-modem-stop");
    var select = $("hil-modem-device");
    var useDevice = $("hil-modem-device-use");

    if (select) {
      var current = select.value;
      select.innerHTML = "";
      var devices = Array.isArray(state.modemShellDevices) ? state.modemShellDevices : [];
      if (state.modemShellMetadataLoading && devices.length === 0) {
        var loadingOpt = document.createElement("option");
        loadingOpt.value = "";
        loadingOpt.textContent = "scanning...";
        select.appendChild(loadingOpt);
      } else if (devices.length === 0) {
        var emptyOpt = document.createElement("option");
        emptyOpt.value = "";
        emptyOpt.textContent = "no serial devices";
        select.appendChild(emptyOpt);
      } else {
        devices.forEach(function (entry) {
          var opt = document.createElement("option");
          opt.value = String(entry.path || "");
          opt.textContent = String(entry.label || entry.path || "");
          if (entry.link_target) {
            opt.textContent += " -> " + String(entry.link_target);
          }
          select.appendChild(opt);
        });
        if (current) select.value = current;
      }
      select.disabled = devices.length === 0;
    }

    var capability = state.modemShellCapability || null;
    var capDisabled = capability && capability.enabled === false;
    var running = !!state.modemShellRunning;
    if (start) start.disabled = running || !!capDisabled;
    if (stop) stop.disabled = !running && !state.modemShellSocket;
    if (useDevice) useDevice.disabled = !select || !select.value;
    var input = $("hil-modem-command");
    if (input) input.placeholder = hilPreferredModemShellCommand();

    if (!status) return;
    if (running) {
      status.textContent = state.modemShellStatusText || "running";
    } else if (state.modemShellErrorText) {
      status.textContent = "error: " + state.modemShellErrorText;
    } else if (state.modemShellMetadataLoading) {
      status.textContent = "checking";
    } else if (capDisabled) {
      status.textContent = "disabled: " + String(capability.reason || "not available");
    } else {
      status.textContent = state.modemShellStatusText || "idle";
    }
  }

  function hilUseSelectedModemDevice() {
    var select = $("hil-modem-device");
    var input = $("hil-modem-command");
    if (!select || !select.value || !input) return;
    var command = String(input.value || hilGetModemShellCommand()).trim();
    var deviceRe = /\/dev\/(?:tty(?:USB|ACM|S)\d+|serial\/by-id\/[A-Za-z0-9._:\-+]+)/;
    if (deviceRe.test(command)) {
      command = command.replace(deviceRe, select.value);
    } else if (/^\s*(sudo\s+)?tio(\s|$)/.test(command)) {
      command = command + " " + select.value;
    } else {
      command = "sudo tio " + select.value;
    }
    input.value = command;
    hilSaveModemShellCommand(command);
    input.focus();
  }

  function hilSetModemShellStatus(text, errorText) {
    var state = commandState.hilWorkbench;
    state.modemShellStatusText = String(text || "");
    state.modemShellErrorText = String(errorText || "");
    hilRenderModemShellMetadata();
  }

  function hilEnsureModemShellTerminal() {
    var state = commandState.hilWorkbench;
    if (state.modemShellTerm) {
      hilAttachModemShellTerminal($("hil-modem-shell-host"));
      return state.modemShellTerm;
    }
    if (typeof window.Terminal !== "function") {
      hilSetModemShellStatus("error", "xterm.js failed to load");
      return null;
    }
    var host = $("hil-modem-shell-host");
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
      try { fitAddon.fit(); } catch (_err) {}
    }
    state.modemShellTerm = term;
    state.modemShellFitAddon = fitAddon;
    term.onData(function (data) {
      var sock = state.modemShellSocket;
      if (sock && sock.readyState === 1) {
        sock.send(JSON.stringify({ type: "stdin", data: data }));
      }
    });
    return term;
  }

  function hilAttachModemShellTerminal(host) {
    var state = commandState.hilWorkbench;
    var term = state.modemShellTerm;
    if (!host || !term) return false;
    try {
      if (term.element) {
        if (term.element.parentNode !== host) {
          host.appendChild(term.element);
        }
      } else if (typeof term.open === "function") {
        term.open(host);
      }
      if (state.modemShellFitAddon) {
        setTimeout(function () {
          try { state.modemShellFitAddon.fit(); } catch (_err) {}
          hilSendModemShellResize();
        }, 0);
      }
      return true;
    } catch (err) {
      hilSetModemShellStatus("error", String((err && err.message) || err));
      return false;
    }
  }

  function hilSendModemShellResize() {
    var state = commandState.hilWorkbench;
    var term = state.modemShellTerm;
    var sock = state.modemShellSocket;
    if (!term || !sock || sock.readyState !== 1) return;
    sock.send(JSON.stringify({
      type: "resize",
      rows: term.rows,
      cols: term.cols,
    }));
  }

  function hilStartModemShell() {
    var state = commandState.hilWorkbench;
    if (state.modemShellCapability && state.modemShellCapability.enabled === false) {
      hilSetModemShellStatus(
        "disabled",
        state.modemShellCapability.reason || "modem shell is disabled"
      );
      return;
    }
    var input = $("hil-modem-command");
    var command = String((input && input.value) || hilGetModemShellCommand()).trim();
    if (!command) {
      command = hilPreferredModemShellCommand();
      if (input) input.value = command;
    }
    var generatedDefault = command === hilPreferredModemShellCommand()
      && state.modemShellDefaultSource === "remote-card-bridge";
    hilSaveModemShellCommand(command, { persist: !generatedDefault });

    var term = hilEnsureModemShellTerminal();
    if (!term) return;
    if (state.modemShellSocket) {
      try { state.modemShellSocket.close(); } catch (_err) {}
    }
    term.clear();
    term.writeln("[yggdrasim-gui] starting modem shell...");

    var token = getStoredToken();
    if (!token) {
      hilSetModemShellStatus("error", "missing token");
      return;
    }

    var scheme = window.location.protocol === "https:" ? "wss" : "ws";
    var rows = term.rows || 30;
    var cols = term.cols || 120;
    var url = scheme + "://" + window.location.host + "/api/host-shell"
      + "?t=" + encodeURIComponent(token)
      + "&scope=hil-modem"
      + "&rows=" + rows
      + "&cols=" + cols
      + "&command=" + encodeURIComponent(command);
    var sock = new WebSocket(url);
    sock.binaryType = "arraybuffer";
    state.modemShellSocket = sock;
    state.modemShellRunning = true;
    hilSetModemShellStatus("connecting", "");

    sock.onopen = function () {
      hilSetModemShellStatus("running", "");
      hilSendModemShellResize();
    };
    sock.onmessage = function (event) {
      if (typeof event.data === "string") {
        try {
          var msg = JSON.parse(event.data);
          if (msg && msg.event === "spawned") {
            var label = String(msg.command || msg.shell || "");
            if (label.length > 64) label = label.slice(0, 61) + "...";
            hilSetModemShellStatus("running pid=" + msg.pid + (label ? " " + label : ""), "");
            return;
          }
          if (msg && msg.event === "exit") {
            term.writeln("\r\n[yggdrasim-gui] modem shell exited.");
            hilSetModemShellStatus("exited", "");
            return;
          }
          if (msg && msg.event === "error") {
            term.writeln("\r\n[yggdrasim-gui] error: " + msg.message);
            state.modemShellRunning = false;
            hilSetModemShellStatus("error", msg.message || "spawn failed");
            return;
          }
        } catch (_err) {
          term.write(event.data);
        }
        return;
      }
      term.write(new Uint8Array(event.data));
    };
    sock.onclose = function () {
      if (state.modemShellSocket === sock) {
        state.modemShellSocket = null;
      }
      state.modemShellRunning = false;
      if (!state.modemShellErrorText) {
        state.modemShellStatusText = "closed";
      }
      hilRenderModemShellMetadata();
      sock.onmessage = null;
      sock.onopen = null;
      sock.onerror = null;
      sock.onclose = null;
    };
    sock.onerror = function () {
      hilSetModemShellStatus("error", "socket error");
    };
  }

  function hilStopModemShell(options) {
    var opts = options || {};
    var state = commandState.hilWorkbench;
    if (state.modemShellSocket) {
      try { state.modemShellSocket.close(); } catch (_err) {}
      state.modemShellSocket = null;
    }
    state.modemShellRunning = false;
    if (opts.dispose && state.modemShellTerm) {
      try { state.modemShellTerm.dispose(); } catch (_err) {}
      state.modemShellTerm = null;
      state.modemShellFitAddon = null;
    }
    if (!state.modemShellErrorText) {
      state.modemShellStatusText = "stopped";
    }
    hilRenderModemShellMetadata();
  }

  function renderHilRawRows(host, options) {
    var state = commandState.hilWorkbench;
    var opts = options || {};
    var rows = state.rawRows || [];
    var fullRender = opts.full || host.getAttribute("data-raw-ready") !== "1";
    var shouldTail = hilScrollerIsAtTail(host);
    if (fullRender) {
      host.innerHTML = "";
      host.setAttribute("data-raw-ready", "1");
    } else {
      while (state.rawPendingDropCount > 0 && host.firstChild) {
        host.removeChild(host.firstChild);
        state.rawPendingDropCount -= 1;
      }
    }
    if (rows.length === 0) {
      host.innerHTML = "";
      state.rawPendingRows = [];
      state.rawPendingDropCount = 0;
      var empty = document.createElement("div");
      empty.className = "cc-hil-empty";
      empty.textContent = state.armed
        ? "No APDU trace rows."
        : "Start HIL to collect raw APDU trace rows.";
      host.appendChild(empty);
      return;
    }
    if (host.firstChild && host.firstChild.classList && host.firstChild.classList.contains("cc-hil-empty")) {
      host.innerHTML = "";
      fullRender = true;
    }
    var rowsToRender = fullRender ? rows : hilFilterPendingRawRows(rows, state.rawPendingRows || []);
    var fragment = document.createDocumentFragment();
    rowsToRender.forEach(function (row) {
      fragment.appendChild(hilRawRowElement(row));
    });
    host.appendChild(fragment);
    state.rawPendingRows = [];
    state.rawPendingDropCount = 0;
    while (host.childNodes.length > rows.length) {
      host.removeChild(host.firstChild);
    }
    if (shouldTail || opts.followTail) {
      host.scrollTop = host.scrollHeight;
    }
  }

  function hilRawRowElement(row) {
    var el = document.createElement("div");
    el.className = "cc-hil-raw-row";
    var direction = document.createElement("span");
    direction.className = "cc-hil-raw-dir";
    direction.textContent = String(row && row.direction || "");
    var hex = document.createElement("span");
    hex.className = "cc-hil-raw-hex";
    hex.textContent = String(row && row.message || "");
    el.appendChild(direction);
    el.appendChild(hex);
    return el;
  }

  function hilScrollerIsAtTail(el) {
    if (!el) return true;
    var maxTop = Math.max(0, (el.scrollHeight || 0) - (el.clientHeight || 0));
    return maxTop - Number(el.scrollTop || 0) <= 24;
  }

  function installHilRawTraceSubscription(body) {
    var state = commandState.hilWorkbench;
    if (!state.armed) return;
    if (typeof logBus === "undefined" || !logBus.subscribe) return;
    hilSeedRawRowsFromLogBus();
    state.rawUnsubscribe = logBus.subscribe(function (event) {
      if (!event) return;
      if (event.type === "clear" && (!event.bucket || event.bucket === "apdu")) {
        state.rawRows = [];
        state.rawPendingRows = [];
        state.rawPendingDropCount = 0;
        state.rawFrameSeen = {};
        state.rawClearedFrameNumber = hilMaxFrameNumber(state.rows || []);
        state.lastRenderedRawId = 0;
        state.rawSnapshotSeeded = true;
      } else if (event.bucket === "apdu" && event.type === "append" && event.row) {
        if (!state.rawPaused) {
          hilAppendRawTraceRow(event.row);
        }
      } else {
        return;
      }
      if (commandState.activeSubsystem !== "HIL" || state.activeTab !== "raw") return;
      hilScheduleRawRowsRender();
    });
  }

  function hilScheduleRawRowsRender() {
    var state = commandState.hilWorkbench;
    if (state.rawRenderTimerId !== null) return;
    state.rawRenderTimerId = setTimeout(function () {
      state.rawRenderTimerId = null;
      if (commandState.activeSubsystem !== "HIL" || state.activeTab !== "raw") return;
      var host = document.querySelector(".cc-hil-workbench .cc-hil-raw-rows");
      if (host) renderHilRawRows(host);
    }, 120);
  }

  function hilFilterPendingRawRows(rows, pendingRows) {
    if (!Array.isArray(pendingRows) || pendingRows.length === 0) return [];
    var liveIds = Object.create(null);
    (rows || []).forEach(function (row) {
      liveIds[String(row && row.id || "")] = true;
    });
    return pendingRows.filter(function (row) {
      return liveIds[String(row && row.id || "")] === true;
    });
  }

  function hilSeedRawRowsFromLogBus() {
    var state = commandState.hilWorkbench;
    if (!state.armed || state.rawSnapshotSeeded) return;
    state.rawSnapshotSeeded = true;
    if (typeof logBus === "undefined" || !logBus.snapshot) return;
    var rows = logBus.snapshot("apdu") || [];
    rows.forEach(function (row) {
      hilAppendRawTraceRow(row);
    });
  }

  function hilAppendRawTraceRow(row) {
    var state = commandState.hilWorkbench;
    if (!row) return false;
    var rawHex = hilRawLogRowHex(row);
    if (!rawHex) return false;
    var rowId = parseInt(row.id || 0, 10);
    if (!isNaN(rowId) && rowId > 0) {
      if (rowId <= Number(state.lastRenderedRawId || 0)) return false;
      state.lastRenderedRawId = rowId;
    }
    hilAppendRawEntry({
      id: row.id,
      direction: hilRawLogDirection(row),
      message: rawHex,
    });
    return true;
  }

  function hilAppendRawRowsFromPackets(rows) {
    var state = commandState.hilWorkbench;
    if (!state.armed || state.rawPaused || !Array.isArray(rows)) return false;
    var changed = false;
    rows.forEach(function (row) {
      if (!row) return;
      var frameNumber = parseInt(row.number || 0, 10);
      if (!frameNumber) return;
      if (frameNumber <= Number(state.rawClearedFrameNumber || 0)) return;
      var key = String(frameNumber);
      if (state.rawFrameSeen && state.rawFrameSeen[key]) return;
      var entries = hilRawEntriesFromPacket(row);
      if (entries.length === 0) return;
      if (!state.rawFrameSeen) state.rawFrameSeen = {};
      state.rawFrameSeen[key] = true;
      entries.forEach(function (entry, index) {
        hilAppendRawEntry({
          id: "hil-frame-" + key + "-" + index,
          direction: entry.direction,
          message: entry.message,
        });
      });
      changed = true;
    });
    return changed;
  }

  function hilAppendRawEntry(entry) {
    var state = commandState.hilWorkbench;
    var rawVisible = hilRawPaneIsVisible();
    state.rawRows.push(entry);
    if (rawVisible) {
      if (!state.rawPendingRows) state.rawPendingRows = [];
      state.rawPendingRows.push(entry);
    }
    hilTrimRawTraceRows();
  }

  function hilTrimRawTraceRows() {
    var state = commandState.hilWorkbench;
    var rawVisible = hilRawPaneIsVisible();
    var limit = hilRawTraceLimit();
    while (state.rawRows.length > limit) {
      var shifted = state.rawRows.shift();
      if (rawVisible) {
        state.rawPendingDropCount = Number(state.rawPendingDropCount || 0) + 1;
      }
      var shiftedFrame = hilRawTraceFrameFromId(shifted && shifted.id);
      if (shiftedFrame && state.rawFrameSeen) {
        delete state.rawFrameSeen[String(shiftedFrame)];
      }
    }
    var minFrame = null;
    (state.rawRows || []).forEach(function (row) {
      var frame = hilRawTraceFrameFromId(row && row.id);
      if (!frame) return;
      if (minFrame === null || frame < minFrame) minFrame = frame;
    });
    if (minFrame === null || !state.rawFrameSeen) return;
    Object.keys(state.rawFrameSeen).forEach(function (key) {
      var frame = parseInt(key, 10);
      if (!isNaN(frame) && frame < minFrame) delete state.rawFrameSeen[key];
    });
  }

  function hilRawTraceFrameFromId(idValue) {
    var match = /^hil-frame-(\d+)(?:-\d+)?$/.exec(String(idValue || ""));
    if (!match) return 0;
    var frame = parseInt(match[1], 10);
    return isNaN(frame) ? 0 : frame;
  }

  function hilRawTraceLimit() {
    return HIL_RAW_TRACE_LIMIT;
  }

  function hilRawPaneIsVisible() {
    return commandState.activeSubsystem === "HIL"
      && commandState.hilWorkbench
      && commandState.hilWorkbench.activeTab === "raw";
  }

  function hilPacketPayloadHex(row) {
    var raw = String(
      row && (
        row.udp_payload_hex
        || row.payload_hex
        || row.apdu_hex
        || row.raw_hex
        || ""
      ) || ""
    ).replace(/[^0-9a-f]/gi, "").toUpperCase();
    return raw;
  }

  function hilRawEntriesFromPacket(row) {
    var commandHex = hilCleanHex(row && row.apdu_command_hex);
    var responseHex = hilCleanHex(row && row.apdu_response_hex);
    if (commandHex || responseHex) {
      var splitEntries = [];
      if (commandHex) {
        splitEntries.push({
          direction: "SIM <- Modem",
          message: commandHex,
        });
      }
      if (responseHex) {
        splitEntries.push({
          direction: "SIM -> Modem",
          message: responseHex,
        });
      }
      return splitEntries;
    }
    var payloadHex = hilPacketPayloadHex(row);
    if (!payloadHex) return [];
    return [{
      direction: hilPacketDirection(row),
      message: payloadHex,
    }];
  }

  function hilPacketDirection(row) {
    if (row && row.gsmtap_uplink === true) return "SIM <- Modem";
    if (row && row.gsmtap_uplink === false) return "SIM -> Modem";
    return "";
  }

  function hilCleanHex(value) {
    return String(value || "").replace(/[^0-9a-f]/gi, "").toUpperCase();
  }

  function hilRawLogRowHex(row) {
    var direct = hilCleanHex(
      row && (
        row.udp_payload_hex
        || row.payload_hex
        || row.apdu_hex
        || row.raw_hex
        || row.hex
        || ""
      ) || ""
    );
    if (direct) return direct;
    var text = String(row && row.message || "");
    var matches = text.match(/(?:[0-9a-fA-F]{2}[\s:,-]*){4,}/g) || [];
    var best = "";
    matches.forEach(function (candidate) {
      var cleaned = String(candidate || "").replace(/[^0-9a-f]/gi, "").toUpperCase();
      if (cleaned.length > best.length) best = cleaned;
    });
    return best;
  }

  function hilRawLogDirection(row) {
    var text = (
      String(row && row.direction || "") + " "
      + String(row && row.source || "") + " "
      + String(row && row.message || "")
    ).toLowerCase();
    if (
      text.indexOf("sim -> modem") >= 0
      || text.indexOf("card -> modem") >= 0
      || text.indexOf("bridge -> modem") >= 0
      || text.indexOf("card to modem") >= 0
    ) {
      return "SIM -> Modem";
    }
    if (
      text.indexOf("sim <- modem") >= 0
      || text.indexOf("modem ->") >= 0
      || text.indexOf("relay -> card") >= 0
      || text.indexOf("modem to card") >= 0
    ) {
      return "SIM <- Modem";
    }
    return "";
  }

  function hilMaxFrameNumber(rows) {
    var maxFrame = 0;
    (rows || []).forEach(function (row) {
      var frameNumber = parseInt(row && row.number || 0, 10);
      if (frameNumber > maxFrame) maxFrame = frameNumber;
    });
    return maxFrame;
  }

  function hilLastFrameNumber(rows) {
    var lastFrame = null;
    (rows || []).forEach(function (row) {
      var frameNumber = parseInt(row && row.number || 0, 10);
      if (frameNumber) lastFrame = frameNumber;
    });
    return lastFrame;
  }

  function hilSelectFrame(frameNumber) {
    var state = commandState.hilWorkbench;
    state.selectedFrameNumber = frameNumber;
    state.selectionFollowsTail = false;
    hilResetDetailScroll();
    hilClearByteHighlight(true);
    var last = state.rows && state.rows.length > 0 ? state.rows[state.rows.length - 1] : null;
    state.followTail = !!(last && parseInt(last.number || 0, 10) === frameNumber);
    state.detail = "Loading decoded fields...";
    state.bytes = "Loading byte view...";
    state.detailRanges = [];
    state.detailFrameNumber = 0;
    hilCancelDeferredPacketRender();
    hilRenderActivePaneOnly();
    hilRefreshSnapshot({ force: true, selectedFrame: frameNumber });
  }

  async function hilRefreshSnapshot(options) {
    var opts = options || {};
    var state = commandState.hilWorkbench;
    if (state.activeTab === "modem") {
      hilLoadModemShellMetadata({ force: !!opts.force });
      return;
    }
    if (!state.armed) {
      state.statusText = state.statusText || "not started";
      state.errorText = "";
      return;
    }
    if (state.inflight) {
      if (opts.force) {
        state.refreshQueuedForce = true;
        if (opts.selectedFrame) {
          state.refreshQueuedSelectedFrame = opts.selectedFrame;
        }
      }
      return;
    }
    if (state.paused && !opts.force) return;
    if (state.liveBaselinePending) return;
    state.inflight = true;
    state.lastRefreshAt = Date.now();
    state.lastStableStatusText = state.statusText || "";
    state.errorText = "";
    var shouldRender = false;
    var selected = opts.selectedFrame || (state.selectionFollowsTail ? "" : state.selectedFrameNumber);
    if (
      hilIsLiveCaptureMode(state)
      && selected
      && selected <= Number(state.liveBaselineFrameNumber || 0)
    ) {
      selected = "";
    }
    var includeDetail = hilShouldIncludeDetail(opts, selected);
    var deltaMode = !opts.force && (
      state.activeTab === "raw"
      || state.activeTab === "dissector"
    );
    var afterFrame = deltaMode
      ? Math.max(
          hilMaxFrameNumber(state.rows || []),
          hilIsLiveCaptureMode(state) ? Number(state.liveBaselineFrameNumber || 0) : 0
        )
      : 0;
    var includeAnnotations = state.activeTab === "dissector" || !deltaMode;
    var contextAfterFrame = hilIsLiveCaptureMode(state)
      ? Number(state.liveBaselineFrameNumber || 0)
      : 0;
    try {
      var resp = await apiFetch("/api/actions/hil.decode_snapshot/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: {
            capture_path: state.capturePath || "",
            selected_frame: selected || "",
            keybag_path: state.keybagPath || "",
            include_detail: includeDetail,
            include_annotations: includeAnnotations,
            after_frame: afterFrame,
            context_after_frame: contextAfterFrame,
            known_capture_size: state.captureSize || 0,
            known_capture_mtime: state.captureMtime || 0,
            limit: hilPacketFetchLimit(),
          },
        }),
      });
      if (!resp.ok) {
        state.errorText = resp.error || "decode refresh failed";
        state.statusText = "error";
        shouldRender = true;
        return;
      }
      shouldRender = hilApplySnapshot(resp.data || {});
    } catch (err) {
      state.errorText = String((err && err.message) || err);
      state.statusText = "error";
      shouldRender = true;
    } finally {
      state.inflight = false;
      if (commandState.activeSubsystem === "HIL" && (shouldRender || opts.force)) {
        if (hilShouldDeferPacketRender(opts)) {
          hilScheduleDeferredPacketRender();
        } else {
          hilCancelDeferredPacketRender();
          hilRenderActivePaneOnly();
        }
      }
      if (state.refreshQueuedForce && commandState.activeSubsystem === "HIL") {
        var queuedSelectedFrame = state.refreshQueuedSelectedFrame;
        state.refreshQueuedForce = false;
        state.refreshQueuedSelectedFrame = null;
        setTimeout(function () {
          hilRefreshSnapshot({ force: true, selectedFrame: queuedSelectedFrame || state.selectedFrameNumber });
        }, 0);
      }
    }
  }

  function hilShouldIncludeDetail(options, selectedFrame) {
    var opts = options || {};
    var state = commandState.hilWorkbench;
    if (opts.force) return true;
    if (state.activeTab !== "dissector") return false;
    if (!selectedFrame) return true;
    if (Number(state.detailFrameNumber || 0) !== Number(selectedFrame || 0)) return true;
    var detailText = String(state.detail || "");
    if (!detailText || detailText === "Loading decoded fields...") return true;
    return false;
  }

  function hilApplySnapshot(data) {
    var state = commandState.hilWorkbench;
    var previousRowsKey = hilRowsRenderKey(state.rows || []);
    var previousContextTreeKey = hilContextTreeRenderKey(state.contextTree || []);
    var previousStatus = state.lastStableStatusText || state.statusText || "";
    var previousError = state.errorText || "";
    state.captureSize = Number(data.capture_size || state.captureSize || 0);
    state.captureMtime = Number(data.capture_mtime || state.captureMtime || 0);
    if (data.not_modified === true) {
      state.statusText = previousStatus || "ok";
      state.errorText = "";
      return previousError !== "" || !!hilActiveTimerSummary();
    }
    var rawRows = Array.isArray(data.rows) ? data.rows : [];
    var rawAnnotations = data.annotations || {};
    var filtered = hilFilterLiveBaseline(data, rawRows, rawAnnotations);
    var incomingRows = filtered.rows;
    var incomingAnnotations = filtered.annotations;
    var previousSelected = state.selectedFrameNumber;
    var previousDetail = state.detail || "";
    var previousBytes = state.bytes || "";
    var previousDetailRanges = Array.isArray(state.detailRanges) ? state.detailRanges : [];
    var previousDetailRangesKey = JSON.stringify(previousDetailRanges);
    var incremental = data.incremental === true;
    var nextRows = incremental
      ? hilMergePacketRows(state.rows || [], incomingRows)
      : incomingRows;
    var nextAnnotations = incremental
      ? hilMergeAnnotations(state.annotations || {}, incomingAnnotations, nextRows)
      : incomingAnnotations;
    state.rows = nextRows;
    state.annotations = nextAnnotations;
    if (Array.isArray(data.context_tree)) {
      state.contextTree = hilFilterContextTreeForRows(data.context_tree, nextRows);
    } else if (!incremental) {
      state.contextTree = [];
    }
    if (data.include_annotations !== false) {
      hilRefreshTimerAnchor();
    }
    var rawChanged = hilAppendRawRowsFromPackets(incomingRows);
    state.lastCapturePath = data.capture_path || state.capturePath || "";
    state.captureSource = String(data.capture_source || state.captureSource || "");
    var baseStatus = data.note ? String(data.note) : (data.ok === false ? "error" : "ok");
    if (filtered.baselineActive && incomingRows.length === 0 && data.ok !== false) {
      baseStatus = "waiting for new packets";
    }
    state.statusText = baseStatus;
    state.errorText = data.ok === false ? String(data.note || "decode refresh failed") : "";
    var frameNumbers = {};
    var lastFrameNumber = null;
    nextRows.forEach(function (row) {
      var frameNumber = parseInt(row.number || 0, 10);
      frameNumbers[frameNumber] = true;
      lastFrameNumber = frameNumber;
    });
    var selectedFromData = parseInt(data.selected_frame || 0, 10);
    var selectedFromDataVisible = !!(selectedFromData && frameNumbers[selectedFromData]);
    var nextSelected = null;
    var nextFollowTail = !!state.followTail;
    var nextSelectionFollowsTail = !!state.selectionFollowsTail;
    if (nextRows.length === 0) {
      nextSelected = null;
      nextFollowTail = true;
      nextSelectionFollowsTail = true;
    } else if (selectedFromDataVisible && previousSelected === selectedFromData) {
      nextSelected = selectedFromData;
      nextSelectionFollowsTail = false;
    } else if (!state.selectionFollowsTail && previousSelected && frameNumbers[previousSelected]) {
      nextSelected = previousSelected;
      nextSelectionFollowsTail = false;
    } else if (state.selectionFollowsTail || !previousSelected) {
      nextSelected = lastFrameNumber;
      nextSelectionFollowsTail = true;
    } else if (selectedFromDataVisible) {
      nextSelected = selectedFromData;
      nextSelectionFollowsTail = false;
    } else {
      nextSelected = lastFrameNumber;
      nextSelectionFollowsTail = true;
    }
    var detailIncluded = data.include_detail !== false;
    if (nextRows.length === 0) {
      state.detail = "";
      state.bytes = "";
      state.detailRanges = [];
      state.detailFrameNumber = 0;
    } else if (selectedFromDataVisible && selectedFromData === nextSelected && detailIncluded) {
      state.detail = data.detail || "";
      state.bytes = data.bytes || "";
      state.detailRanges = Array.isArray(data.detail_ranges) ? data.detail_ranges : [];
      state.detailFrameNumber = nextSelected || 0;
    } else if (previousSelected === nextSelected) {
      state.detail = previousDetail;
      state.bytes = previousBytes;
      state.detailRanges = previousDetailRanges;
      if (!state.detailFrameNumber && previousDetail) {
        state.detailFrameNumber = nextSelected || 0;
      }
    } else {
      state.detail = "";
      state.bytes = "";
      state.detailRanges = [];
      state.detailFrameNumber = 0;
    }
    state.selectedFrameNumber = nextSelected;
    state.followTail = nextFollowTail;
    state.selectionFollowsTail = nextSelectionFollowsTail;
    if (previousSelected !== nextSelected) {
      hilResetDetailScroll();
      hilClearByteHighlight(true);
    }
    return (
      previousRowsKey !== hilRowsRenderKey(nextRows)
      || previousContextTreeKey !== hilContextTreeRenderKey(state.contextTree || [])
      || previousStatus !== String(state.statusText || "")
      || previousError !== String(state.errorText || "")
      || previousSelected !== nextSelected
      || previousDetail !== String(state.detail || "")
      || previousBytes !== String(state.bytes || "")
      || previousDetailRangesKey !== JSON.stringify(state.detailRanges || [])
      || rawChanged
    );
  }

  function hilRowsRenderKey(rows) {
    var list = Array.isArray(rows) ? rows : [];
    if (list.length === 0) return "0";
    var first = list[0] || {};
    var last = list[list.length - 1] || {};
    return [
      String(list.length),
      String(first.number || ""),
      String(last.number || ""),
      String(last.annotated_info || last.info || ""),
      String(last.udp_payload_hex || ""),
    ].join("|");
  }

  function hilContextTreeRenderKey(items) {
    var list = Array.isArray(items) ? items : [];
    if (list.length === 0) return "0";
    return JSON.stringify(list.map(function (item) {
      return [
        String(item && item.kind || ""),
        String(item && item.depth || 0),
        String(item && item.frame_number || ""),
        String(item && (item.display || item.label || item.primary || "") || ""),
        String(item && item.secondary || ""),
      ];
    }));
  }

  function hilFilterContextTreeForRows(items, rows) {
    var list = Array.isArray(items) ? items : [];
    if (list.length === 0) return [];
    var frameSet = Object.create(null);
    (rows || []).forEach(function (row) {
      var frameNumber = parseInt(row && row.number || 0, 10);
      if (frameNumber) frameSet[String(frameNumber)] = true;
    });
    var filtered = [];
    var headerStack = [];
    function flushHeaders(depth) {
      for (var i = 0; i < headerStack.length; i++) {
        var header = headerStack[i];
        if (!header || header.depth >= depth || header.flushed) continue;
        filtered.push(header.item);
        header.flushed = true;
      }
    }
    list.forEach(function (item) {
      if (!item) return;
      var depth = Math.max(0, parseInt(item.depth || 0, 10) || 0);
      while (headerStack.length > 0 && headerStack[headerStack.length - 1].depth >= depth) {
        headerStack.pop();
      }
      if (item.kind === "frame") {
        var frameNumber = parseInt(item.frame_number || 0, 10);
        if (!frameNumber || !frameSet[String(frameNumber)]) return;
        flushHeaders(depth + 1);
        filtered.push(item);
        return;
      }
      headerStack.push({
        depth: depth,
        item: item,
        flushed: false,
      });
    });
    return filtered;
  }

  function hilMergePacketRows(existingRows, incomingRows) {
    var byFrame = Object.create(null);
    var merged = [];
    function push(row) {
      if (!row) return;
      var frameNumber = parseInt(row.number || 0, 10);
      if (!frameNumber) return;
      var key = String(frameNumber);
      if (byFrame[key]) {
        merged[byFrame[key] - 1] = row;
        return;
      }
      byFrame[key] = merged.length + 1;
      merged.push(row);
    }
    (existingRows || []).forEach(push);
    (incomingRows || []).forEach(push);
    return merged;
  }

  function hilMergeAnnotations(existingAnnotations, incomingAnnotations, rows) {
    var merged = Object.assign({}, existingAnnotations || {});
    Object.keys(incomingAnnotations || {}).forEach(function (key) {
      merged[key] = incomingAnnotations[key];
    });
    var minFrame = null;
    (rows || []).forEach(function (row) {
      var frameNumber = parseInt(row && row.number || 0, 10);
      if (!frameNumber) return;
      if (minFrame === null || frameNumber < minFrame) minFrame = frameNumber;
    });
    if (minFrame !== null) {
      Object.keys(merged).forEach(function (key) {
        var frameNumber = parseInt(key, 10);
        if (!isNaN(frameNumber) && frameNumber < minFrame) delete merged[key];
      });
    }
    return merged;
  }

  function hilPacketFetchLimit() {
    return HIL_PACKET_FETCH_LIMIT;
  }

  function hilPacketRenderLimit() {
    return HIL_PACKET_RENDER_LIMIT;
  }

  function hilPacketVirtualRowHeight() {
    return HIL_PACKET_VIRTUAL_ROW_HEIGHT;
  }

  function hilFilterLiveBaseline(data, rows, annotations) {
    var state = commandState.hilWorkbench;
    var baseline = Number(state.liveBaselineFrameNumber || 0);
    if (!hilIsLiveCaptureMode(state) || baseline <= 0) {
      return {
        rows: rows,
        annotations: annotations || {},
        baselineActive: false,
      };
    }

    var captureSize = Number(data.capture_size || 0);
    var captureMtime = Number(data.capture_mtime || 0);
    var maxRawFrame = 0;
    (rows || []).forEach(function (row) {
      var frameNumber = parseInt(row && row.number || 0, 10);
      if (frameNumber > maxRawFrame) maxRawFrame = frameNumber;
    });
    if (
      (state.liveBaselineCaptureSize > 0 && captureSize > 0 && captureSize < state.liveBaselineCaptureSize)
      || (
        rows.length > 0
        && maxRawFrame > 0
        && maxRawFrame <= baseline
        && captureMtime > Number(state.liveBaselineCaptureMtime || 0)
      )
    ) {
      state.liveBaselineFrameNumber = 0;
      state.liveBaselineCaptureSize = captureSize;
      state.liveBaselineCaptureMtime = captureMtime;
      return {
        rows: rows,
        annotations: annotations || {},
        baselineActive: false,
      };
    }

    var filteredRows = [];
    var filteredAnnotations = {};
    (rows || []).forEach(function (row) {
      var frameNumber = parseInt(row && row.number || 0, 10);
      if (frameNumber <= baseline) return;
      filteredRows.push(row);
      if (annotations && annotations[String(frameNumber)]) {
        filteredAnnotations[String(frameNumber)] = annotations[String(frameNumber)];
      }
    });
    return {
      rows: filteredRows,
      annotations: filteredAnnotations,
      baselineActive: true,
    };
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
    ccEnhanceActionForm(action, form);
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
      if (field.kind === "reader" && !ccShouldHideReaderField(action, field)) {
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

  function ccActionFieldRow(form, fieldName) {
    if (!form || !fieldName) return null;
    var input = form.querySelector('[name="' + fieldName + '"]');
    return input && input.closest ? input.closest(".cc-form-row") : null;
  }

  function ccCompactHexText(raw) {
    return String(raw || "").replace(/0x/gi, "").replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
  }

  function ccEnhanceActionForm(action, form) {
    if (!action || !form) return;
    if (action.id === "tool.asn1_tlv.decode") {
      ccEnhanceAsn1TlvDecodeForm(form);
    }
  }

  function ccEnhanceAsn1TlvDecodeForm(form) {
    if (!form || form.classList.contains("cc-asn1-decode-form")) return;
    form.classList.add("cc-asn1-decode-form");

    var hexInput = form.querySelector('[name="hex_text"]');
    var hexRow = ccActionFieldRow(form, "hex_text");
    if (hexRow) {
      hexRow.classList.add("cc-asn1-decode-row", "cc-asn1-decode-row--hex");
    }
    if (hexInput) {
      hexInput.rows = Math.max(Number(hexInput.rows || 0), 5);
      hexInput.spellcheck = false;
      hexInput.setAttribute("autocomplete", "off");
      hexInput.setAttribute("autocapitalize", "off");

      var inputTools = document.createElement("div");
      inputTools.className = "cc-asn1-decode-input-tools";

      var formatBtn = document.createElement("button");
      formatBtn.type = "button";
      formatBtn.className = "btn btn-small";
      formatBtn.textContent = "Format bytes";
      formatBtn.title = "Group the pasted hex as space-separated bytes.";
      inputTools.appendChild(formatBtn);

      var clearBtn = document.createElement("button");
      clearBtn.type = "button";
      clearBtn.className = "btn btn-small";
      clearBtn.textContent = "Clear";
      clearBtn.title = "Clear the input hex field.";
      inputTools.appendChild(clearBtn);

      var byteCount = document.createElement("span");
      byteCount.className = "cc-asn1-decode-byte-count";
      inputTools.appendChild(byteCount);

      function refreshByteCount() {
        var compact = ccCompactHexText(hexInput.value);
        var hasOddNibble = compact.length % 2 === 1;
        byteCount.dataset.state = hasOddNibble ? "warn" : "ok";
        if (compact.length === 0) {
          byteCount.textContent = "0 B";
        } else if (hasOddNibble) {
          byteCount.textContent = Math.floor(compact.length / 2) + " B + nibble";
        } else {
          byteCount.textContent = (compact.length / 2) + " B";
        }
      }

      formatBtn.addEventListener("click", function () {
        hexInput.value = formatHexInline(ccCompactHexText(hexInput.value));
        hexInput.dispatchEvent(new Event("input", { bubbles: true }));
        hexInput.focus();
      });
      clearBtn.addEventListener("click", function () {
        hexInput.value = "";
        hexInput.dispatchEvent(new Event("input", { bubbles: true }));
        hexInput.focus();
      });
      hexInput.addEventListener("input", refreshByteCount);
      hexInput.addEventListener("keydown", function (event) {
        if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
          event.preventDefault();
          if (form.requestSubmit) {
            form.requestSubmit();
          }
        }
      });
      refreshByteCount();
      if (hexRow) {
        hexRow.appendChild(inputTools);
      }
    }

    var schemaRows = ["schema_paths", "type_name", "codec"].map(function (name) {
      return ccActionFieldRow(form, name);
    }).filter(function (row) {
      return !!row;
    });
    if (schemaRows.length > 0) {
      var details = document.createElement("details");
      details.className = "cc-asn1-schema-options";
      var summary = document.createElement("summary");
      summary.textContent = "Schema-aware decode";
      details.appendChild(summary);
      var hint = document.createElement("p");
      hint.className = "cc-asn1-schema-hint";
      hint.textContent = "Optional asn1tools decode. Leave closed for tag-registry TLV inspection.";
      details.appendChild(hint);
      var grid = document.createElement("div");
      grid.className = "cc-asn1-schema-grid";
      schemaRows.forEach(function (row) {
        row.classList.add("cc-asn1-decode-row", "cc-asn1-decode-row--schema");
        grid.appendChild(row);
      });
      details.appendChild(grid);
      if (hexRow && hexRow.parentNode) {
        hexRow.parentNode.insertBefore(details, hexRow.nextSibling);
      } else {
        form.insertBefore(details, form.firstChild);
      }
    }
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
    if (ccShouldHideReaderField(action, field)) {
      row.classList.add("cc-form-row--reader-session");
      row.hidden = true;
      input = document.createElement("input");
      input.type = "hidden";
      input.id = fid;
      input.name = field.name;
      input.value = ccActiveReaderName();
      row.appendChild(input);
      return row;
    }
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
    var profileTargetList = null;
    if (ccShouldSuggestProfileAidTargets(action, field)
      && input
      && String(input.tagName || "").toUpperCase() === "INPUT") {
      var listId = fid + "-profile-aids";
      input.setAttribute("list", listId);
      input.setAttribute("autocomplete", "off");
      profileTargetList = document.createElement("datalist");
      profileTargetList.id = listId;
      profileTargetList.setAttribute("data-profile-targets", "1");
      profileTargetList.setAttribute("data-subsystem", action.subsystem || "");
      profileTargetList.setAttribute("data-reader", ccActiveReaderName());
      ccPopulateProfileTargetDatalist(
        profileTargetList,
        action.subsystem || commandState.activeSubsystem || "",
        ccActiveReaderName()
      );
    }

    var isPathKind = (field.kind === "path"
      || field.kind === "directory"
      || field.kind === "save_path");
    if (isPathKind) {
      input.classList.add("cc-path-input");
      if (!input.title) {
        input.title = "Double-click to browse \u00B7 drop a file to paste its path";
      }
      input.addEventListener("dblclick", async function () {
        var chosen = await pickForField(field);
        if (chosen) {
          input.value = chosen;
          input.dispatchEvent(new Event("change", { bubbles: true }));
        }
      });
      var pathWrap = document.createElement("div");
      pathWrap.className = "cc-path-row";
      pathWrap.appendChild(input);
      var browse = document.createElement("button");
      browse.type = "button";
      browse.className = "btn btn-small cc-path-browse";
      browse.textContent = "Browse…";
      browse.title = field.kind === "directory"
        ? "Pick a folder"
        : (field.kind === "save_path" ? "Pick a save location" : "Pick a file");
      browse.addEventListener("click", async function () {
        var chosen = await pickForField(field);
        if (chosen) {
          input.value = chosen;
          input.dispatchEvent(new Event("change", { bubbles: true }));
        }
      });
      pathWrap.appendChild(browse);
      row.appendChild(pathWrap);
      // Drag-and-drop: operators can drop a file (or a folder for
      // directory-kind fields) from the native file manager straight
      // onto the input + Browse pair. The helper extracts the
      // absolute path from pywebview's File.path, a file:// URI, or
      // a plain-text fallback.
      enableFilePathDrop(input);
    } else {
      row.appendChild(input);
      if (profileTargetList) row.appendChild(profileTargetList);
    }

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

  function applyActiveReaderDefault(action, inputs) {
    // Reader-as-session: when the operator has an active top-bar pill
    // and the form has a reader-kind input that is still blank, fill
    // it in from ``commandState.readerBar.activeReader`` so the action
    // runs against the same reader as the SCP03 workbench. Operators
    // who explicitly picked a different reader from the dropdown keep
    // their choice outside reader-scoped eSIM modules. For those
    // modules, the session gate/top-bar reader is the source of truth.
    if (!action || !action.inputs || !inputs) return;
    var activeReader = ccActiveReaderName();
    if (activeReader.length === 0) return;
    var forceSessionReader = ccActionUsesReaderSession(action);
    action.inputs.forEach(function (field) {
      if (!field || field.kind !== "reader") return;
      var fieldName = field.name;
      var current = String(inputs[fieldName] || "");
      if (forceSessionReader || current.length === 0) {
        inputs[fieldName] = activeReader;
      }
    });
  }

  async function runActionFromForm(action, form, statusEl, resultEl) {
    var inputs = collectFormValues(form);
    applyActiveReaderDefault(action, inputs);
    var currentEsimFlowPane = resultEl && resultEl.closest
      ? resultEl.closest(".cc-esim-flow-pane")
      : null;
    var currentInlineActionPane = resultEl && resultEl.closest && !currentEsimFlowPane
      ? resultEl.closest(".cc-inline-action-pane")
      : null;
    function setEsimInlinePaneStatus(text) {
      if (!currentEsimFlowPane) return;
      var paneStatus = currentEsimFlowPane.querySelector(".cc-esim-flow-status");
      if (paneStatus) paneStatus.textContent = text;
    }
    function setInlineActionPaneStatus(text) {
      if (!currentInlineActionPane) return;
      var paneStatus = currentInlineActionPane.querySelector(".cc-inline-action-status");
      if (paneStatus) paneStatus.textContent = text;
    }
    if (ccActionUsesReaderSession(action) && !ccActiveReaderName()) {
      statusEl.textContent = "select reader";
      setEsimInlinePaneStatus("select reader");
      setInlineActionPaneStatus("select reader");
      resultEl.innerHTML = "";
      resultEl.appendChild(renderErrorBlock(
        "Select a reader before running this eSIM action."
      ));
      setStatusAction("action blocked: reader required");
      return;
    }
    var card = findHostCard(form);
    statusEl.textContent = action.streams ? "starting…" : "running…";
    setEsimInlinePaneStatus(action.streams ? "starting" : "running");
    setInlineActionPaneStatus(action.streams ? "starting" : "running");
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
      return;
    }

    try {
      var resp = await apiFetch("/api/actions/" + encodeURIComponent(action.id) + "/run", {
        method: "POST",
        body: JSON.stringify({ inputs: inputs }),
      });
      if (!resp.ok) {
        statusEl.textContent = "error";
        setEsimInlinePaneStatus("error");
        setInlineActionPaneStatus("error");
        var errBlock = renderErrorBlock(resp.error || "unknown error");
        resultEl.appendChild(errBlock);
        logBus.emit({
          level: "error",
          source: action.id,
          message: "run: failed — " + (resp.error || "unknown error"),
        });
        return;
      }
      statusEl.textContent = "ok";
      setEsimInlinePaneStatus("ok");
      setInlineActionPaneStatus("ok");
      renderActionResult(action, resp.data || {}, resultEl);
      logBus.emit({
        level: "info",
        source: action.id,
        message: "run: ok",
      });
    } catch (err) {
      statusEl.textContent = "error";
      setEsimInlinePaneStatus("error");
      setInlineActionPaneStatus("error");
      var catchBlock = renderErrorBlock(String(err && err.message || err));
      resultEl.appendChild(catchBlock);
      logBus.emit({
        level: "error",
        source: action.id,
        message: "run: " + String(err && err.message || err),
      });
    } finally {
      setActionBusy(card, action, false);
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

    var runBtn = resultEl.parentElement.querySelector(".cc-action-bar .btn");
    var inlinePane = resultEl && resultEl.closest
      ? resultEl.closest(".cc-esim-flow-pane")
      : null;
    var hiddenErrorCount = 0;
    function setInlinePaneStatus(text) {
      if (!inlinePane) return;
      var paneStatus = inlinePane.querySelector(".cc-esim-flow-status");
      if (paneStatus) paneStatus.textContent = text;
    }
    if (runBtn) runBtn.disabled = true;

    ccRefreshGlobalDebugFlag().then(function () {
      startStreamingSocket();
    });

    function startStreamingSocket() {
      var sock = new WebSocket(url);

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
        setInlinePaneStatus("running");
      };
      sock.onmessage = function (event) {
        try {
          var msg = JSON.parse(event.data);
          var level = msg.level || "info";
          var text = msg.message || JSON.stringify(msg);
          var showFrame = ccShouldShowStreamFrame(level);
          if (showFrame) {
            appendLogRow(log, level, text);
            logBus.emit({
              level: level,
              source: action.id,
              message: text,
              data: msg,
            });
          } else {
            hiddenErrorCount += 1;
          }
          if (level === "done") {
            statusEl.textContent = "done";
            setInlinePaneStatus("done");
            if (msg.report) {
              resultEl.appendChild(renderReportSummary(msg.report));
            }
          } else if (level === "error") {
            if (showFrame) {
              statusEl.textContent = "error";
              setInlinePaneStatus("error");
            }
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
        if (hiddenErrorCount > 0 && statusEl.textContent !== "done") {
          appendLogRow(log, "warn", "Flow stopped before completion. Enable debug for details.");
          logBus.emit({
            level: "warn",
            source: action.id,
            message: "stream: hidden error details; enable debug for APDU diagnostics",
          });
        }
        appendLogRow(log, "info", "socket closed");
        if (statusEl.textContent !== "done" && statusEl.textContent !== "error") {
          setInlinePaneStatus("closed");
        }
        logBus.emit({
          level: "info",
          source: action.id,
          message: "stream: closed",
        });
        // Detach handlers so the browser can free the buffered frames
        // and closure chain right away. Long dogfooding sessions
        // (several hundred action runs) used to hold a multi-MB chain
        // of dead sockets here.
        sock.onmessage = null;
        sock.onopen = null;
        sock.onerror = null;
        sock.onclose = null;
      };
      sock.onerror = function () {
        statusEl.textContent = "socket error";
        setInlinePaneStatus("socket error");
        setActionBusy(card, action, false);
        logBus.emit({
          level: "error",
          source: action.id,
          message: "stream: socket error",
        });
      };
    }
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

  function ccActionResultMetaRows(data) {
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
      var noteText = String(data.note || "").trim();
      if (noteText.length > 0 && noteText !== "ok") {
        metaRows.push({ label: "Note", value: noteText });
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
    return metaRows;
  }

  function ccActionResultPrefersTree(action, kind, data) {
    if (!data || typeof data !== "object") return false;
    var outputKind = String(kind || "json");
    if (outputKind === "fcp"
        || outputKind === "tlv_tree"
        || outputKind === "findings"
        || outputKind === "key_value_lines"
        || outputKind === "hex") {
      return false;
    }
    var subsystem = action && action.subsystem ? String(action.subsystem) : "";
    var actionId = action && action.id ? String(action.id) : "";
    return actionId === "scp11_live.get_all_data"
      || actionId === "scp03.get_sgp32_all_data"
      || subsystem === "eSIM Management"
      || subsystem === "SCP11 Local"
      || subsystem === "Local eIM"
      || ccActionUsesReaderSession(action);
  }

  function ccReportLineEntry(line) {
    var clean = String(line || "").trim();
    if (clean.length === 0) return null;
    var parts = clean.split(/\s+\|\s+/).map(function (part) {
      return String(part || "").trim();
    }).filter(function (part) {
      return part.length > 0;
    });
    if (parts.length <= 1) {
      return { text: clean };
    }
    var entry = {
      summary: parts[0],
      fields: [],
    };
    parts.slice(1).forEach(function (part) {
      var idx = part.indexOf(":");
      if (idx > 0 && idx < 48) {
        entry.fields.push({
          label: part.slice(0, idx).trim(),
          value: part.slice(idx + 1).trim(),
        });
      } else {
        entry.fields.push({ text: part });
      }
    });
    return entry;
  }

  function ccReportSectionsFromText(text) {
    var raw = String(text || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
    if (raw.length === 0) return [];
    var marked = raw.replace(/\s*(===\s*[^=\n][^=]*?\s*===)\s*/g, "\n$1\n");
    var lines = marked.split(/\n+/).map(function (line) {
      return String(line || "").trim();
    }).filter(function (line) {
      return line.length > 0;
    });
    var sections = [];
    var current = null;
    function ensureSection(title) {
      if (!current) {
        current = { title: title || "Report", entries: [] };
        sections.push(current);
      }
      return current;
    }
    lines.forEach(function (line) {
      var heading = line.match(/^===\s*(.*?)\s*===$/);
      if (heading) {
        current = {
          title: String(heading[1] || "Section").trim() || "Section",
          entries: [],
        };
        sections.push(current);
        return;
      }
      line.replace(/\s+(\[\*\]|\[\+\]|\[\!\]|\[-\])/g, "\n$1")
        .split(/\n+/)
        .forEach(function (piece) {
          var entry = ccReportLineEntry(piece);
          if (entry) ensureSection("Report").entries.push(entry);
        });
    });
    return sections.filter(function (section) {
      return section && (section.entries.length > 0 || section.title);
    });
  }

  function ccActionResultTreePayload(action, data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) return data;
    var omitted = {
      raw_hex: true,
      report: true,
      raw_trace: true,
      trace: true,
    };
    var payload = {};
    var reportSections = typeof data.report === "string"
      ? ccReportSectionsFromText(data.report)
      : [];
    Object.keys(data).forEach(function (key) {
      if (omitted[key] && typeof data[key] === "string") return;
      payload[key] = data[key];
    });
    if (reportSections.length > 0) {
      payload.report_sections = reportSections;
    }
    return Object.keys(payload).length > 0 ? payload : data;
  }

  function renderStructuredActionTreeResult(action, data, container) {
    var sheet = document.createElement("div");
    sheet.className = "cc-action-datasheet cc-action-datasheet--tree";
    scp03DatasheetAppendMetaKvl(sheet, ccActionResultMetaRows(data));

    var main = scp03DatasheetWrapMain();
    var decodedHead = document.createElement("div");
    decodedHead.className = "cc-action-datasheet-main-head";
    decodedHead.textContent = "Result tree";
    main.appendChild(decodedHead);

    var tree = document.createElement("div");
    tree.className = "cc-action-tree";
    tree.appendChild(renderPrettyValue(ccActionResultTreePayload(action, data), 0));
    main.appendChild(tree);
    sheet.appendChild(main);

    if (data && typeof data.raw_hex === "string" && data.raw_hex.trim().length > 0) {
      scp03DatasheetAppendRawHex(sheet, data.raw_hex.trim(), "Raw response");
    }

    if (data && typeof data.trace === "string" && data.trace.trim().length > 0) {
      scp03DatasheetAppendTraceMain(sheet, data.trace, "Console trace");
    }

    if (data && typeof data.report === "string" && data.report.trim().length > 0) {
      scp03DatasheetAppendTraceMain(sheet, data.report, "Console report");
    }

    container.appendChild(sheet);
  }

  function asn1TlvItemsToNodes(items) {
    if (!Array.isArray(items)) return [];
    return items.map(function (item) {
      var node = {
        tag_hex: String(item && item.tag || "").toUpperCase(),
        length: Number(item && item.length || 0),
      };
      if (item && item.name) {
        node.label = String(item.name);
      }
      var children = asn1TlvItemsToNodes(item && item.items);
      if (children.length > 0) {
        node.children = children;
      } else if (item && typeof item.raw === "string") {
        node.value_hex = item.raw;
      }
      return node;
    });
  }

  function ccCopyPlainText(text, button) {
    var value = String(text || "");
    if (typeof copyTextToClipboard === "function") {
      copyTextToClipboard(value);
    } else if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).catch(function () {});
    }
    if (button) {
      button.classList.add("is-copied");
      setTimeout(function () { button.classList.remove("is-copied"); }, 700);
    }
  }

  function renderAsn1TlvDecodeResult(data, container) {
    if (!data || typeof data !== "object") {
      container.appendChild(renderDecodedBlock(data, null, { omitHead: true }));
      return;
    }

    var sheet = document.createElement("div");
    sheet.className = "cc-action-datasheet cc-asn1-decode-result";
    var itemCount = Array.isArray(data.items) ? data.items.length : 0;
    var metaRows = [
      { label: "Format", value: data.format || "BER/DER TLV" },
      { label: "Input", value: String(data.byteCount || 0) + " B" },
      { label: "Status", value: data.complete ? "complete" : "incomplete" },
      { label: "Top-level", value: String(itemCount) },
    ];
    if (data.schemaDecode) {
      metaRows.push({ label: "Schema", value: "decoded" });
    }
    scp03DatasheetAppendMetaKvl(sheet, metaRows);

    var notationText = String(data.asn1Notation || "").trim();
    if (notationText.length > 0) {
      var notationMain = scp03DatasheetWrapMain();
      notationMain.classList.add("cc-asn1-notation-panel");
      var notationHead = document.createElement("div");
      notationHead.className = "cc-action-datasheet-main-head cc-action-datasheet-main-head--split";
      var notationTitle = document.createElement("span");
      notationTitle.className = "cc-action-datasheet-main-title";
      notationTitle.textContent = "ASN.1 notation";
      notationHead.appendChild(notationTitle);
      var copyNotation = document.createElement("button");
      copyNotation.type = "button";
      copyNotation.className = "cc-decoded-tools-btn";
      copyNotation.textContent = "Copy";
      copyNotation.title = "Copy the ASN.1-like notation.";
      copyNotation.addEventListener("click", function () {
        ccCopyPlainText(notationText, copyNotation);
      });
      notationHead.appendChild(copyNotation);
      notationMain.appendChild(notationHead);
      var notationPre = document.createElement("pre");
      notationPre.className = "cc-asn1-notation";
      notationPre.textContent = notationText;
      notationMain.appendChild(notationPre);
      sheet.appendChild(notationMain);
    }

    var nodes = asn1TlvItemsToNodes(data.items);
    if (nodes.length > 0) {
      var treeMain = scp03DatasheetWrapMain();
      treeMain.classList.add("cc-asn1-tlv-panel");
      var treeHead = document.createElement("div");
      treeHead.className = "cc-action-datasheet-main-head cc-action-datasheet-main-head--split";
      var treeTitle = document.createElement("span");
      treeTitle.className = "cc-action-datasheet-main-title";
      treeTitle.textContent = "Decoded TLV tree";
      treeHead.appendChild(treeTitle);
      var treeSub = document.createElement("span");
      treeSub.className = "cc-action-datasheet-main-sub";
      treeSub.textContent = formatHexInline(String(data.inputHex || ""));
      treeHead.appendChild(treeSub);
      treeMain.appendChild(treeHead);
      var treeWrap = document.createElement("div");
      treeWrap.className = "cc-tlv-tree cc-asn1-tlv-tree";
      treeWrap.appendChild(renderTlvNodes(nodes, 0));
      treeMain.appendChild(treeWrap);
      sheet.appendChild(treeMain);
    }

    if (data.schemaDecode) {
      var schemaMain = scp03DatasheetWrapMain();
      var schemaHead = document.createElement("div");
      schemaHead.className = "cc-action-datasheet-main-head";
      schemaHead.textContent = "Schema decode";
      schemaMain.appendChild(schemaHead);
      var schemaBody = document.createElement("div");
      schemaBody.className = "cc-action-tree";
      schemaBody.appendChild(renderPrettyValue(data.schemaDecode, 0));
      schemaMain.appendChild(schemaBody);
      sheet.appendChild(schemaMain);
    }

    var rawDetails = document.createElement("details");
    rawDetails.className = "cc-action-datasheet-raw cc-details cc-asn1-raw-json";
    var rawSummary = document.createElement("summary");
    rawSummary.textContent = "Raw JSON";
    rawDetails.appendChild(rawSummary);
    var rawToolbar = document.createElement("div");
    rawToolbar.className = "cc-asn1-raw-toolbar";
    var copyJson = document.createElement("button");
    copyJson.type = "button";
    copyJson.className = "cc-decoded-tools-btn";
    copyJson.textContent = "Copy JSON";
    copyJson.addEventListener("click", function () {
      ccCopyPlainText(JSON.stringify(data, null, 2), copyJson);
    });
    rawToolbar.appendChild(copyJson);
    rawDetails.appendChild(rawToolbar);
    var rawPre = document.createElement("pre");
    rawPre.className = "cc-json";
    rawPre.textContent = JSON.stringify(data, null, 2);
    rawDetails.appendChild(rawPre);
    sheet.appendChild(rawDetails);

    container.appendChild(sheet);
  }

  function renderSimaResponseResult(data, container) {
    if (!data || typeof data !== "object") {
      container.appendChild(renderDecodedBlock(data, null, { omitHead: true }));
      return;
    }
    var semantic = data.semantic && typeof data.semantic === "object"
      ? data.semantic
      : {};
    var metaRows = [
      { label: "Format", value: data.format || "SIMa response" },
      { label: "Input", value: String(data.input_length || 0) + " B" },
      { label: "Status", value: data.complete ? "complete" : "incomplete" },
    ];
    if (semantic.choice) {
      metaRows.push({ label: "Result", value: String(semantic.choice) });
    }
    if (semantic.result_code !== undefined) {
      metaRows.push({ label: "Code", value: String(semantic.result_code) });
    }
    if (semantic.result_detail !== undefined) {
      metaRows.push({ label: "Detail", value: String(semantic.result_detail) });
    }

    var sheet = document.createElement("div");
    sheet.className = "cc-action-datasheet cc-sima-response-result";
    scp03DatasheetAppendMetaKvl(sheet, metaRows);

    var summaryMain = scp03DatasheetWrapMain();
    var summaryHead = document.createElement("div");
    summaryHead.className = "cc-action-datasheet-main-head cc-action-datasheet-main-head--split";
    var summaryTitle = document.createElement("span");
    summaryTitle.className = "cc-action-datasheet-main-title";
    summaryTitle.textContent = "SIMa final result";
    summaryHead.appendChild(summaryTitle);
    if (data.summary) {
      var summarySub = document.createElement("span");
      summarySub.className = "cc-action-datasheet-main-sub";
      summarySub.textContent = data.summary;
      summaryHead.appendChild(summarySub);
    }
    summaryMain.appendChild(summaryHead);

    var summaryBody = document.createElement("div");
    summaryBody.className = "cc-sima-summary";
    var resultChip = document.createElement("span");
    resultChip.className = "cc-sima-result-chip";
    if (semantic.choice === "successResult") {
      resultChip.classList.add("cc-sima-result-chip--success");
    } else if (semantic.choice === "failureResult") {
      resultChip.classList.add("cc-sima-result-chip--failure");
    }
    resultChip.textContent = semantic.choice || "unknown result";
    summaryBody.appendChild(resultChip);
    if (semantic.result_code !== undefined) {
      var code = document.createElement("code");
      code.className = "cc-sima-code";
      code.textContent = "resultCode=" + semantic.result_code;
      summaryBody.appendChild(code);
    }
    if (semantic.result_detail !== undefined) {
      var detail = document.createElement("code");
      detail.className = "cc-sima-code";
      detail.textContent = "resultDetail=" + semantic.result_detail;
      summaryBody.appendChild(detail);
    }
    if (!semantic.choice && data.error) {
      var error = document.createElement("span");
      error.className = "cc-error-block";
      error.textContent = data.error;
      summaryBody.appendChild(error);
    }
    summaryMain.appendChild(summaryBody);
    sheet.appendChild(summaryMain);

    if (Array.isArray(data.nodes) && data.nodes.length > 0) {
      var treeMain = scp03DatasheetWrapMain();
      var treeHead = document.createElement("div");
      treeHead.className = "cc-action-datasheet-main-head cc-action-datasheet-main-head--split";
      var treeTitle = document.createElement("span");
      treeTitle.className = "cc-action-datasheet-main-title";
      treeTitle.textContent = "SIMa TLV tree";
      treeHead.appendChild(treeTitle);
      var treeSub = document.createElement("span");
      treeSub.className = "cc-action-datasheet-main-sub";
      treeSub.textContent = formatHexInline(String(data.input_hex || ""));
      treeHead.appendChild(treeSub);
      treeMain.appendChild(treeHead);
      var treeWrap = document.createElement("div");
      treeWrap.className = "cc-tlv-tree cc-sima-tlv-tree";
      treeWrap.appendChild(renderTlvNodes(data.nodes, 0));
      treeMain.appendChild(treeWrap);
      sheet.appendChild(treeMain);
    }

    if (data.formatted) {
      var formattedDetails = document.createElement("details");
      formattedDetails.className = "cc-action-datasheet-raw cc-details cc-sima-formatted";
      var formattedSummary = document.createElement("summary");
      formattedSummary.textContent = "One-line format";
      formattedDetails.appendChild(formattedSummary);
      var formattedPre = document.createElement("pre");
      formattedPre.className = "cc-json";
      formattedPre.textContent = String(data.formatted);
      formattedDetails.appendChild(formattedPre);
      sheet.appendChild(formattedDetails);
    }

    var rawDetails = document.createElement("details");
    rawDetails.className = "cc-action-datasheet-raw cc-details cc-sima-raw-json";
    var rawSummary = document.createElement("summary");
    rawSummary.textContent = "Raw JSON";
    rawDetails.appendChild(rawSummary);
    var rawPre = document.createElement("pre");
    rawPre.className = "cc-json";
    rawPre.textContent = JSON.stringify(data, null, 2);
    rawDetails.appendChild(rawPre);
    sheet.appendChild(rawDetails);

    container.appendChild(sheet);
  }

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
    if (kind === "asn1_tlv") {
      return renderAsn1TlvDecodeResult(data, container);
    }
    if (kind === "sima_response") {
      return renderSimaResponseResult(data, container);
    }
    if (ccActionResultPrefersTree(action, kind, data)) {
      renderStructuredActionTreeResult(action, data, container);
      return;
    }
    if (kind === "table" && data && data.rows) {
      container.appendChild(renderObjectTable(data.rows));
      return;
    }
    if (kind === "hex" && typeof data.hex === "string") {
      container.appendChild(renderHexBlock(data.hex));
      return;
    }
    if (kind === "markdown") {
      return renderMarkdownResult(data, container);
    }
    // --- json / default: datasheet-wrapped decoded block (SCP03 style) ---
    var sheet = document.createElement("div");
    sheet.className = "cc-action-datasheet";

    scp03DatasheetAppendMetaKvl(sheet, ccActionResultMetaRows(data));

    var main = scp03DatasheetWrapMain();
    var decodedHead = document.createElement("div");
    decodedHead.className = "cc-action-datasheet-main-head";
    decodedHead.textContent = "Result";
    main.appendChild(decodedHead);
    main.appendChild(renderDecodedBlock(data, null, { omitHead: true }));
    sheet.appendChild(main);

    if (data && typeof data.raw_hex === "string" && data.raw_hex.trim().length > 0) {
      scp03DatasheetAppendRawHex(sheet, data.raw_hex.trim(), "Raw response");
    }

    if (data && typeof data.trace === "string" && data.trace.trim().length > 0) {
      scp03DatasheetAppendTraceMain(sheet, data.trace, "Console trace");
    }

    container.appendChild(sheet);
  }

  // ``markdown`` is rendered conservatively: no external parser is
  // bundled, so the payload is shown as preformatted text with HTML
  // escaping. Common payload shapes are probed in preference order:
  //   1. string                             → rendered directly
  //   2. dict.markdown                      → ShellGuides / summary shape
  //   3. dict.raw_trace                     → guide_show captured stdout
  //   4. dict.lines (array of strings)      → joined with "\n"
  //   5. dict.text                          → generic text field
  // Anything else falls back to the JSON block so no information is lost.
  function renderMarkdownResult(data, container) {
    var body = null;
    if (typeof data === "string") {
      body = data;
    } else if (data && typeof data === "object") {
      if (typeof data.markdown === "string") {
        body = data.markdown;
      } else if (typeof data.raw_trace === "string") {
        body = data.raw_trace;
      } else if (Array.isArray(data.lines)) {
        body = data.lines.join("\n");
      } else if (typeof data.text === "string") {
        body = data.text;
      }
    }
    if (body === null) {
      container.appendChild(renderDecodedBlock(data, null, { omitHead: true }));
      return;
    }
    var pre = document.createElement("pre");
    pre.className = "markdown-block";
    pre.textContent = body;
    container.appendChild(pre);
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
      container.appendChild(renderDecodedBlock(data, null, { omitHead: true }));
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

  // -- TLV semantic decoder ------------------------------------------------
  //
  // The renderer used to print bare ``tag_hex [length] value_hex`` rows.
  // That was useful for parser bring-up but bled raw ASN.1 into operator
  // surfaces ("TLV[24]" syndrome). Replace with a labeled renderer driven
  // by a tag dictionary covering ISO 7816-4 FCP, ETSI TS 102 221 TERMINAL
  // CAPABILITY, SGP.22 §5.7 (ES10/ES11 application tags), and SGP.32 §6
  // (eIM data structures). Unknown tags still show the hex tag so nothing
  // is hidden — they just do not get a friendly label.
  //
  // Lookup is two-tier:
  //   1. Path (parent.tag) match — disambiguates context-sensitive tags
  //      such as 0x80 (file-size in FCP, defaultDpAddress in BF3C, etc.).
  //   2. Tag-only match — generic fallback.
  //
  // Per-row "raw" affordance survives via the chip on hover (Alt+click
  // copies the hex tag to clipboard) so the byte view is never lost.

  var TLV_LABELS_GENERIC = {
    // ISO 7816-4 / ETSI TS 102 221 §11.1.1 FCP templates
    "62": "FCP template",
    "6F": "FCI template",
    "64": "FMD template",
    "A5": "FCI proprietary",
    "82": "File descriptor",
    "83": "File identifier",
    "84": "DF name / AID",
    "8A": "Life-cycle status",
    "8B": "Security attributes (ref)",
    "8C": "Security attributes (compact)",
    "8D": "Security attributes (expanded ref)",
    "AB": "Security attributes (expanded)",
    "C6": "PIN status template",
    "88": "Short File Identifier",
    "5A": "ICCID / EID",
    "4F": "AID",
    // SGP.22 §5.7 ES10 root tags
    "BF20": "EUICCInfo1",
    "BF22": "EUICCInfo2",
    "BF21": "PrepareDownload",
    "BF2B": "RetrieveNotificationsList",
    "BF2C": "RemoveNotificationFromList",
    "BF2D": "ProfileInfoList",
    "BF2E": "ProfileInfo",
    "BF2F": "NotificationMetadata",
    "BF30": "BoundProfilePackage",
    "BF31": "PrepareDownloadResponse",
    "BF32": "ProfileInstallationResult",
    "BF33": "CancelSession",
    "BF34": "CancelSessionResponse",
    "BF35": "HandleNotification",
    "BF36": "NotificationSentRequest",
    "BF37": "NotificationSentResponse",
    "BF38": "AuthenticateClient",
    "BF3A": "InitiateAuthentication",
    "BF3B": "AuthenticateServer",
    "BF3C": "EuiccConfiguredData",
    "BF3D": "SetDefaultDpAddressResponse",
    "BF3E": "GetEID / EuiccData",
    "BF40": "StoreMetadataRequest",
    "BF42": "UpdateMetadataResponse",
    "BF43": "RAT (Rules Authorisation Table)",
    "BF49": "DeleteProfile",
    "BF4A": "DisableProfile",
    "BF4B": "EnableProfile",
    // SGP.32 §6 IoT data
    "BF55": "EimConfigurationData",
    "BF56": "GetCertsResponse",
    // GP / proprietary
    "E3": "ProfileInfo entry",
    "A6": "CI public-key list (signing)",
    "A9": "CI public-key list (verification)",
    "AC": "Certification data object",
  };

  var TLV_LABELS_BY_PATH = {
    // ETSI TS 102 221 §11.1.1.4 FCP child tags (parent 62/6F)
    "62.80": "File size",
    "62.81": "Total file size",
    "62.82": "File descriptor",
    "62.83": "File identifier",
    "62.84": "DF name / AID",
    "62.85": "Proprietary",
    "62.88": "Short File Identifier",
    "62.8A": "Life-cycle status",
    "6F.84": "DF name / AID",
    "6F.A5": "FCI proprietary",
    // ETSI TS 102 221 §11.1.19.2 TERMINAL CAPABILITY (parent A9)
    "A9.80": "Terminal power supply",
    "A9.81": "Extended logical channels (legacy)",
    "A9.82": "Extended logical channels",
    "A9.83": "Additional terminal capability",
    "A9.84": "eUICC capability",
    "A9.87": "eUICC capability (alt)",
    "A9.A1": "eUICC capability (constructed)",
    // SGP.22 EUICCInfo1 (parent BF20)
    "BF20.82": "SVN (Specification Version Number)",
    "BF20.A6": "CI key list (signing)",
    "BF20.A9": "CI key list (verification)",
    // SGP.22 EUICCInfo2 (parent BF22)
    "BF22.81": "Profile version",
    "BF22.82": "SVN",
    "BF22.83": "eUICC firmware version",
    "BF22.84": "Extended card resource",
    "BF22.85": "UICC capability",
    "BF22.86": "TS 102 241 version",
    "BF22.87": "GlobalPlatform version",
    "BF22.88": "RSP capability",
    "BF22.A9": "CI key list (verification)",
    "BF22.A6": "CI key list (signing)",
    "BF22.8B": "SAS-SM accreditation number",
    "BF22.AC": "Certification data object",
    "BF22.92": "TRE properties",
    "BF22.93": "TRE product reference",
    "BF22.94": "Additional Profile Package versions",
    // SGP.22 EuiccConfiguredData (parent BF3C)
    "BF3C.80": "Default SM-DP+ address",
    "BF3C.81": "Root SM-DS address",
    "BF3C.82": "Additional root SM-DS",
    "BF3C.83": "Allowed CI public-key id",
    // SGP.22 GetEID payload (parent BF3E)
    "BF3E.5A": "EID",
    // SGP.22 ProfileInfo (parent E3 or BF2E)
    "E3.5A": "ICCID",
    "E3.4F": "ISD-P AID",
    "E3.90": "Profile nickname",
    "E3.91": "Service-provider name",
    "E3.92": "Profile name",
    "E3.95": "Profile class",
    "E3.B6": "Profile owner",
    "E3.B7": "SM-DP+ FQDN",
    "E3.99": "Profile state",
    "BF2E.5A": "ICCID",
    "BF2E.4F": "ISD-P AID",
    "BF2E.90": "Profile nickname",
    "BF2E.91": "Service-provider name",
    "BF2E.92": "Profile name",
    "BF2E.95": "Profile class",
    "BF2E.99": "Profile state",
    // SGP.22 RAT entry (parent BF43)
    "BF43.A0": "Rule entry",
    "BF43.B0": "Rule entry",
    // SGP.32 EimConfigurationData (parent BF55)
    "BF55.80": "eIM identifier",
    "BF55.81": "eIM FQDN",
    "BF55.82": "eIM CI public-key id (verification)",
    "BF55.83": "eIM public-key data",
    "BF55.84": "Counter values",
    "BF55.85": "Associated eIM identifier",
    "BF55.86": "Trusted public-key set",
    "BF55.87": "eIM admin protocol configuration",
    "BF55.88": "eIM supported protocols",
  };

  function tlvLookupLabel(tagHexUpper, parentTagHexUpper) {
    if (parentTagHexUpper && parentTagHexUpper.length > 0) {
      var pathKey = parentTagHexUpper + "." + tagHexUpper;
      if (TLV_LABELS_BY_PATH[pathKey]) {
        return TLV_LABELS_BY_PATH[pathKey];
      }
    }
    if (TLV_LABELS_GENERIC[tagHexUpper]) {
      return TLV_LABELS_GENERIC[tagHexUpper];
    }
    return null;
  }

  // SGP.22 §3.4 / TS 102 221 §13.2: ICCID / EID payloads ship as
  // nibble-swapped BCD. Decode only when the byte length matches the
  // canonical 10-byte (ICCID) or 16-byte (EID) shape; otherwise leave
  // the hex untouched. Trailing 'F' nibbles (BCD pad) are stripped.
  function tlvDecodeBcdSwapped(valueHex, expectedBytes) {
    if (typeof valueHex !== "string" || valueHex.length === 0) return null;
    if (valueHex.length !== expectedBytes * 2) return null;
    var out = "";
    for (var i = 0; i < valueHex.length; i += 2) {
      out += valueHex.charAt(i + 1) + valueHex.charAt(i);
    }
    return out.replace(/[fF]+$/, "");
  }

  function tlvDecodeAscii(valueHex) {
    if (typeof valueHex !== "string" || valueHex.length === 0) return null;
    if (valueHex.length % 2 !== 0) return null;
    var bytes = [];
    for (var i = 0; i < valueHex.length; i += 2) {
      bytes.push(parseInt(valueHex.substr(i, 2), 16));
    }
    var allPrintable = bytes.every(function (b) {
      return (b >= 0x20 && b <= 0x7E) || b === 0x09;
    });
    if (!allPrintable) return null;
    return String.fromCharCode.apply(String, bytes);
  }

  function tlvDecodeProfileState(valueHex) {
    if (valueHex === "00") return "disabled";
    if (valueHex === "01") return "enabled";
    return null;
  }

  function tlvDecodeProfileClass(valueHex) {
    if (valueHex === "00") return "test";
    if (valueHex === "01") return "provisioning";
    if (valueHex === "02") return "operational";
    return null;
  }

  function tlvDecodeValue(node, parentTagHex) {
    var hex = (node && typeof node.value_hex === "string") ? node.value_hex.toUpperCase() : "";
    if (hex.length === 0) return null;
    var tag = (node && node.tag_hex) ? String(node.tag_hex).toUpperCase() : "";
    var path = (parentTagHex || "") + "." + tag;
    // ICCID / EID
    if (path === "BF3E.5A" && hex.length === 32) {
      var eid = tlvDecodeBcdSwapped(hex, 16);
      if (eid) return { kind: "eid", text: eid };
    }
    if ((path === "E3.5A" || path === "BF2E.5A") && hex.length === 20) {
      var iccid = tlvDecodeBcdSwapped(hex, 10);
      if (iccid) return { kind: "iccid", text: iccid };
    }
    // Profile state / class enums
    if (path === "E3.99" || path === "BF2E.99") {
      var state = tlvDecodeProfileState(hex);
      if (state) return { kind: "enum", text: state };
    }
    if (path === "E3.95" || path === "BF2E.95") {
      var cls = tlvDecodeProfileClass(hex);
      if (cls) return { kind: "enum", text: cls };
    }
    // FQDN / textual fields
    var asciiTags = {
      "BF3C.80": 1, "BF3C.81": 1, "BF3C.82": 1,
      "BF55.80": 1, "BF55.81": 1, "BF55.85": 1,
      "E3.90": 1, "E3.91": 1, "E3.92": 1, "E3.B7": 1,
      "BF2E.90": 1, "BF2E.91": 1, "BF2E.92": 1,
    };
    if (asciiTags[path]) {
      var text = tlvDecodeAscii(hex);
      if (text !== null && text.length > 0) {
        return { kind: "ascii", text: text };
      }
    }
    return null;
  }

  function makeTlvLengthChip(node) {
    var len = document.createElement("span");
    len.className = "cc-tlv-len";
    var byteCount = (node && typeof node.length === "number") ? node.length : 0;
    if (Array.isArray(node.children) && node.children.length > 0) {
      len.classList.add("cc-tlv-len-constructed");
      var n = node.children.length;
      len.textContent = byteCount + " B · " + n + (n === 1 ? " child" : " children");
    } else {
      len.textContent = byteCount + " B";
    }
    return len;
  }

  function renderTlvNodes(nodes, level, parentTagHex) {
    var ul = document.createElement("ul");
    ul.className = "cc-tlv-list" + (level === 0 ? " cc-tlv-list-root" : "");
    (nodes || []).forEach(function (node) {
      var li = document.createElement("li");
      li.className = "cc-tlv-node";
      var hasChildren = Array.isArray(node.children) && node.children.length > 0;
      if (hasChildren) li.classList.add("cc-tlv-node-constructed");

      var header = document.createElement("div");
      header.className = "cc-tlv-row";

      var tagUpper = (typeof node.tag_hex === "string") ? node.tag_hex.toUpperCase() : "";
      var label = tlvLookupLabel(tagUpper, parentTagHex || "");
      if (!label && node.label) {
        label = String(node.label);
      }

      if (label) {
        var labelEl = document.createElement("span");
        labelEl.className = "cc-tlv-label";
        labelEl.textContent = label;
        header.appendChild(labelEl);
      }

      var tag = document.createElement("span");
      tag.className = "cc-tlv-tag" + (label ? " cc-tlv-tag-secondary" : "");
      tag.textContent = tagUpper || node.tag_hex || "?";
      tag.title = "ASN.1 tag (hex)";
      header.appendChild(tag);

      header.appendChild(makeTlvLengthChip(node));

      if (!hasChildren && typeof node.value_hex === "string") {
        var decoded = tlvDecodeValue(node, parentTagHex || "");
        if (decoded) {
          var pretty = document.createElement("span");
          pretty.className = "cc-tlv-decoded cc-tlv-decoded-" + decoded.kind;
          pretty.textContent = decoded.text;
          pretty.title = "decoded from " + tagUpper;
          header.appendChild(pretty);
        }
        var val = document.createElement("code");
        val.className = "cc-tlv-value";
        val.textContent = node.value_hex || "(empty)";
        if (decoded) val.classList.add("cc-tlv-value-secondary");
        header.appendChild(val);
      }
      li.appendChild(header);
      if (hasChildren) {
        li.appendChild(renderTlvNodes(node.children, level + 1, tagUpper));
      }
      ul.appendChild(li);
    });
    return ul;
  }

  function renderFindingsResult(data, container) {
    if (!data) {
      container.appendChild(renderDecodedBlock(data, null, { omitHead: true }));
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
      container.appendChild(renderDecodedBlock(data, null, { omitHead: true }));
      return;
    }
    container.innerHTML = "";

    // --- datasheet root (mirrors SCP03 datasheet layout) ----------
    var sheet = document.createElement("div");
    sheet.className = "cc-action-datasheet";
    container.appendChild(sheet);

    // --- metadata KVL rows (identical to SCP03's scp03RenderKeyValueRows) -
    var metaRows = [];
    if (data.reader_name && String(data.reader_name).trim().length > 0) {
      metaRows.push({ label: "Reader", value: String(data.reader_name) });
    }
    if (data.eid && String(data.eid).trim().length > 0) {
      metaRows.push({ label: "EID", value: String(data.eid) });
    }
    metaRows.push({ label: "Input", value: (data.input_length || 0) + " B" });
    var noteText = String(data.note || "").trim();
    if (noteText.length > 0 && noteText !== "ok") {
      metaRows.push({ label: "Note", value: noteText });
    }
    if (data.sw && String(data.sw).trim().length > 0) {
      metaRows.push({ label: "SW", value: String(data.sw) });
    }
    scp03DatasheetAppendMetaKvl(sheet, metaRows);

    // --- detail lines block --------------------------------------
    var detailRows = Array.isArray(data.detail_lines) ? data.detail_lines : [];
    if (detailRows.length > 0) {
      var detailWrap = scp03DatasheetWrapMain();
      var detailHead = document.createElement("div");
      detailHead.className = "cc-action-datasheet-main-head";
      detailHead.textContent = "Detail";
      detailWrap.appendChild(detailHead);
      var detailKvl = document.createElement("div");
      detailKvl.className = "cc-kvl-block";
      detailRows.forEach(function (row) {
        var line = document.createElement("div");
        line.className = "cc-kvl-row";
        var indent = Math.max(0, Math.min(8, parseInt(row.indent || 0, 10)));
        line.classList.add("cc-kvl-row-indent-" + indent);
        var label = document.createElement("span");
        label.className = "cc-kvl-label";
        label.textContent = row.label || "";
        var value = document.createElement("span");
        value.className = "cc-kvl-value";
        value.textContent = row.value || "";
        line.appendChild(label);
        line.appendChild(value);
        detailKvl.appendChild(line);
      });
      detailWrap.appendChild(detailKvl);
      sheet.appendChild(detailWrap);
    }

    // --- validation lines block (when present) --------------------
    var validationRows = Array.isArray(data.validation_lines) ? data.validation_lines : [];
    if (validationRows.length > 0) {
      var valWrap = scp03DatasheetWrapMain();
      var valHead = document.createElement("div");
      valHead.className = "cc-action-datasheet-main-head";
      valHead.textContent = "Validation";
      valWrap.appendChild(valHead);
      var valKvl = document.createElement("div");
      valKvl.className = "cc-kvl-block";
      validationRows.forEach(function (row) {
        var line = document.createElement("div");
        line.className = "cc-kvl-row";
        var indent = Math.max(0, Math.min(8, parseInt(row.indent || 0, 10)));
        line.classList.add("cc-kvl-row-indent-" + indent);
        var label = document.createElement("span");
        label.className = "cc-kvl-label";
        label.textContent = row.label || "";
        var value = document.createElement("span");
        value.className = "cc-kvl-value";
        value.textContent = row.value || "";
        line.appendChild(label);
        line.appendChild(value);
        valKvl.appendChild(line);
      });
      valWrap.appendChild(valKvl);
      sheet.appendChild(valWrap);
    }

    // --- collapsible raw hex (when response carries raw_hex) -----
    if (typeof data.raw_hex === "string" && data.raw_hex.trim().length > 0) {
      scp03DatasheetAppendRawHex(sheet, data.raw_hex.trim(), "Raw response");
    }

    // --- collapsible trace (when response carries trace) ----------
    if (typeof data.trace === "string" && data.trace.trim().length > 0) {
      scp03DatasheetAppendTraceMain(sheet, data.trace, "Console trace");
    }
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

  // -- Pretty value renderer ------------------------------------------------
  //
  // Replaces the old "JSON.stringify into a <pre>" approach used to
  // render FCP fields + decoded record bodies. Goals:
  //   * primitives carry a type chip (str / num / bool / null) so the
  //     operator can read them at a glance instead of squinting at
  //     stringified JSON;
  //   * hex-looking strings get byte-grouped like our hex dumps so
  //     ICCID / IMSI / AID values stay legible;
  //   * arrays become numbered chip rows; objects become a nested
  //     definition list (depth-limited, with a collapse-toggle for
  //     anything deeper than a couple of levels);
  //   * a "Show JSON" toggle lets power users flip back to the raw
  //     stringified payload when they need byte-perfect parity with
  //     CLI output.

  // Heuristic — strings that look like hex (even length, all hex
  // chars, ≥4 chars). Used for byte-grouping inside
  // ``renderPrettyValue``.
  function looksLikeHex(text) {
    var s = String(text || "");
    if (s.length < 4) return false;
    if (s.length % 2 !== 0) return false;
    return /^[0-9A-Fa-f]+$/.test(s);
  }

  function formatHexInline(text) {
    var s = String(text || "").toUpperCase();
    var groups = s.match(/.{1,2}/g) || [];
    return groups.join(" ");
  }

  function renderPrettyPrimitive(value) {
    var span = document.createElement("span");
    span.className = "cc-pv";
    if (value === null || value === undefined) {
      span.classList.add("cc-pv--null");
      span.textContent = value === null ? "null" : "—";
      return span;
    }
    if (typeof value === "boolean") {
      span.classList.add("cc-pv--bool");
      span.classList.add(value ? "cc-pv--bool-true" : "cc-pv--bool-false");
      span.textContent = value ? "true" : "false";
      return span;
    }
    if (typeof value === "number") {
      span.classList.add("cc-pv--num");
      span.textContent = String(value);
      return span;
    }
    var text = String(value);
    if (looksLikeHex(text)) {
      span.classList.add("cc-pv--hex");
      var code = document.createElement("code");
      code.textContent = formatHexInline(text);
      span.appendChild(code);
      var lenChip = document.createElement("span");
      lenChip.className = "cc-pv-meta";
      lenChip.textContent = (text.length / 2) + " B";
      span.appendChild(lenChip);
      return span;
    }
    span.classList.add("cc-pv--str");
    span.textContent = text;
    return span;
  }

  // Service-table detector. EF.UST / EF.IST / EF_PSISMSC and friends
  // share a bitmap shape — the backend collapses them into a payload
  // that carries both ``active`` and ``inactive`` lists plus a
  // ``service_table`` marker so the GUI can switch to a checklist
  // layout. Operators asked for parity with what is *not* set so they
  // can audit a card without re-decoding the raw bytes manually.
  function renderPrettyServiceTable(value) {
    var wrap = document.createElement("div");
    wrap.className = "cc-svc-table";

    var summaryText = "";
    if (typeof value.summary === "string" && value.summary.length > 0) {
      summaryText = value.summary;
    } else if (typeof value.active_count === "number"
        && typeof value.total_count === "number") {
      summaryText = value.active_count + " of " + value.total_count + " active";
    }
    var head = document.createElement("div");
    head.className = "cc-svc-table-head";
    var title = document.createElement("span");
    title.className = "cc-svc-table-title";
    var tableName = String(value.table || "Service Table");
    title.textContent = tableName;
    head.appendChild(title);
    if (typeof value.full_name === "string" && value.full_name.length > 0
        && value.full_name !== tableName) {
      var fn = document.createElement("span");
      fn.className = "cc-svc-table-fullname";
      fn.textContent = value.full_name;
      head.appendChild(fn);
    }
    if (typeof value.spec === "string" && value.spec.length > 0) {
      var spec = document.createElement("span");
      spec.className = "cc-svc-table-spec";
      spec.textContent = value.spec;
      head.appendChild(spec);
    }
    if (summaryText.length > 0) {
      var summary = document.createElement("span");
      summary.className = "cc-svc-table-summary";
      summary.textContent = summaryText;
      head.appendChild(summary);
    }
    wrap.appendChild(head);

    var grid = document.createElement("div");
    grid.className = "cc-svc-table-grid";

    function buildColumn(items, heading, modifier, mark) {
      var col = document.createElement("div");
      col.className = "cc-svc-table-col cc-svc-table-col--" + modifier;
      var ch = document.createElement("div");
      ch.className = "cc-svc-table-col-head";
      ch.textContent = heading + " (" + items.length + ")";
      col.appendChild(ch);
      if (items.length === 0) {
        var none = document.createElement("div");
        none.className = "cc-svc-table-empty";
        none.textContent = "(none)";
        col.appendChild(none);
        return col;
      }
      var list = document.createElement("ul");
      list.className = "cc-svc-table-list";
      items.forEach(function (item) {
        var li = document.createElement("li");
        li.className = "cc-svc-table-row cc-svc-table-row--" + modifier;
        var dot = document.createElement("span");
        dot.className = "cc-svc-table-mark";
        dot.textContent = mark;
        var name = document.createElement("span");
        name.className = "cc-svc-table-name";
        name.textContent = String(item);
        li.appendChild(dot);
        li.appendChild(name);
        list.appendChild(li);
      });
      col.appendChild(list);
      return col;
    }

    var activeArr = Array.isArray(value.active) ? value.active : [];
    var inactiveArr = Array.isArray(value.inactive) ? value.inactive : [];
    grid.appendChild(buildColumn(activeArr, "Active", "active", "\u25CF"));
    grid.appendChild(buildColumn(inactiveArr, "Not set", "inactive", "\u25CB"));
    wrap.appendChild(grid);

    if (typeof value.error === "string" && value.error.length > 0) {
      var err = document.createElement("div");
      err.className = "cc-svc-table-err";
      err.textContent = value.error;
      wrap.appendChild(err);
    }
    return wrap;
  }

  function isServiceTablePayload(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    if (value.service_table === true) return true;
    return Array.isArray(value.active)
      && Array.isArray(value.inactive)
      && (typeof value.summary === "string"
          || typeof value.active_count === "number");
  }

  // Manual-aligned label translations for SAIP field keys. The keys
  // pySim emits are spec-faithful camelCase (``applicationLoadPackageAID``,
  // ``minimumSecurityLevel``) which is fine for API surfaces but
  // unhelpful inside an editor — operators recognise the wording from
  // [TCA PP TS] / GP CPS chapters they spend their day in. Map them.
  // Lookup is case-insensitive.
  var _SAIP_PRETTY_FIELD_KEY = (function () {
    var entries = [
      // file-data shorthands (kept from the original table)
      ["fillFileContent", "File content"],
      ["fillFileContents", "File content"],
      ["fillFileOffset", "byte offset"],
      ["fileDescriptor", "descriptor"],
      // ProfileHeader (TCA PP TS §6.4)
      ["major-version", "Profile version (major)"],
      ["minor-version", "Profile version (minor)"],
      ["profileType", "Profile type"],
      ["profile-type", "Profile type"],
      ["iccid", "ICCID"],
      ["pol", "POL (policy rules)"],
      ["eUICC-Mandatory-services", "Mandatory services"],
      ["eUICC-Mandatory-GFSTEList", "Mandatory file system templates"],
      ["connectivityParameters", "Connectivity parameters"],
      ["mandatoryAID", "Mandatory AID"],
      ["mandatoryAIDs", "Mandatory AIDs"],
      ["iotOptions", "IoT options"],
      ["pix", "PIX"],
      // Common header
      ["pe-header", "PE header"],
      ["pe-name", "PE name"],
      ["mandated", "Mandated"],
      ["identification", "Identification"],
      // PIN / PUK codes (TCA PP TS §10)
      ["pinCodes", "PIN codes"],
      ["pukCodes", "PUK codes"],
      ["sharedContext", "Shared context"],
      ["sharedPINContext", "Shared PIN context"],
      ["keyReference", "Key reference"],
      ["pinValue", "PIN value"],
      ["pukValue", "PUK value"],
      ["maxAttempts", "Max attempts"],
      ["retriesLeft", "Retries left"],
      ["retriesRemaining", "Retries remaining"],
      ["pukReference", "PUK reference"],
      ["codeAttribute", "Coding"],
      ["valueChange", "Value change allowed"],
      ["stateChange", "State change allowed"],
      ["referenceDataIndicator", "Reference data indicator"],
      ["unblockKeyReference", "Unblock-key reference"],
      // PE-AKAParameter (TCA PP TS §11)
      ["akaParameter", "AKA parameter"],
      ["parameterMapping", "Parameter mapping"],
      ["mappingOptions", "Mapping options"],
      ["mappingSourceAID", "Mapping source AID"],
      ["algorithmID", "Algorithm"],
      ["algorithmParameter", "Algorithm parameter"],
      ["sequenceNumberConfiguration", "Sequence number configuration"],
      ["seqNumberConfiguration", "Sequence number configuration"],
      ["ssimParameters", "SSIM parameters"],
      ["networkName", "Network name"],
      ["atKdf", "AT_KDF"],
      ["AT_KDF", "AT_KDF"],
      ["op", "OP"],
      ["opc", "OPC"],
      ["k", "K"],
      ["topc", "TOPC"],
      ["c1", "c1"], ["c2", "c2"], ["c3", "c3"], ["c4", "c4"], ["c5", "c5"],
      ["r1", "r1"], ["r2", "r2"], ["r3", "r3"], ["r4", "r4"], ["r5", "r5"],
      // PE-SecurityDomain (GP CPS §11)
      ["securityDomain", "Security domain"],
      ["instance", "Instance"],
      ["applicationPrivileges", "Application privileges"],
      ["lifeCycleState", "Life-cycle state"],
      ["systemSpecificParameters", "System parameters (EF)"],
      ["uiccToolkitParameters", "UICC toolkit parameters (80)"],
      ["uiccAccessParameters", "UICC access parameters (81)"],
      ["uiccAdministrativeAccessParameters", "UICC admin access parameters (82)"],
      ["additionalContactlessParameters", "Contactless parameters (B0)"],
      ["maximumSupportedDataRate", "Max supported data rate"],
      ["applicationFamilyIdentifier", "Application family identifier"],
      ["minimumSecurityLevel", "Min. security level"],
      ["accessDomain", "Access domain"],
      ["implicitSelectionParameters", "Implicit selection parameters"],
      ["globalServiceParameters", "Global service parameters"],
      ["menuEntries", "Menu entries"],
      ["tarValues", "TAR values"],
      ["processData", "Process data"],
      ["keyList", "Key list"],
      ["keyComponents", "Key components"],
      ["usageQualifier", "Usage qualifier"],
      ["keyAccess", "Key access"],
      ["versionNumber", "Version number"],
      ["securityDomainPersonalizationData", "SD personalization data"],
      ["openPersonalizationData", "OPEN personalization data"],
      ["restrictParameters", "Restrict parameters"],
      ["catTpParameters", "CAT_TP parameters"],
      // PE-Application (TCA PP TS §13)
      ["applicationLoadPackage", "Application load package"],
      ["applicationLoadPackageAID", "Load package AID"],
      ["loadBlockData", "Load block data"],
      ["applicationInstances", "Application instances"],
      ["instanceAID", "Instance AID"],
      ["executableLoadFileAID", "Executable load file AID"],
      ["moduleAID", "Module AID"],
      ["securityDomainAID", "Security domain AID"],
      ["associatedSecurityDomainAID", "Associated SD AID"],
      ["applicationParameters", "Application parameters"],
      // PE-RFM (TCA PP TS §14)
      ["rfm", "RFM"],
      ["tarList", "TAR list"],
      ["toolkitApplicationReferences", "Toolkit application references (TAR)"],
      ["uiccAccessDomain", "UICC access domain"],
      ["uiccAdminAccessDomain", "UICC admin access domain"],
      ["adfAccessDomain", "ADF access domain"],
      ["adfAdminAccessDomain", "ADF admin access domain"],
      ["rfmLoopCount", "RFM loop count"],
      // PE-RAM (TCA PP TS §14)
      ["ram", "RAM"],
      // common
      ["templateID", "Template OID"],
      ["dfName", "DF name (AID)"],
      ["fileID", "File ID"],
      ["pinStatusTemplateDO", "PIN status template DO"],
      ["lcsi", "LCSI (life-cycle status)"],
      ["securityAttributesReferenced", "Security attributes (ARR ref)"],
    ];
    var map = Object.create(null);
    entries.forEach(function (pair) {
      map[pair[0].toLowerCase()] = pair[1];
    });
    return map;
  }());

  function saipPrettySaipFieldKey(key) {
    var raw = String(key || "").trim();
    if (raw.length === 0) return raw;
    var hit = _SAIP_PRETTY_FIELD_KEY[raw.toLowerCase()];
    if (hit) return hit;
    return raw;
  }

  function saipPrettyArrayRowLabel(item, idx) {
    if (item && typeof item === "object" && Array.isArray(item["@"])
        && item["@"].length >= 1 && typeof item["@"][0] === "string") {
      return saipPrettySaipFieldKey(String(item["@"][0]));
    }
    return "[" + idx + "]";
  }

  function renderPrettyValue(value, depth) {
    var depthIdx = Number(depth || 0);
    if (value === null || typeof value !== "object") {
      return renderPrettyPrimitive(value);
    }
    if (isServiceTablePayload(value)) {
      return renderPrettyServiceTable(value);
    }
    if (Array.isArray(value)) {
      var arr = document.createElement("div");
      arr.className = "cc-pv-array";
      if (value.length === 0) {
        var empty = document.createElement("span");
        empty.className = "cc-pv cc-pv--null";
        empty.textContent = "[ ] (empty)";
        arr.appendChild(empty);
        return arr;
      }
      // Compact rendering when every entry is primitive: render as
      // chips on a single row so long lists stay tight.
      var allPrim = value.every(function (v) {
        return v === null || typeof v !== "object";
      });
      if (allPrim) {
        // Heuristic: collapse to a horizontal chip strip ONLY when
        // every entry is a short tag-style value (numbers, booleans,
        // short tokens, or hex). Human-readable strings — anything
        // with a colon, whitespace, slash, or beyond a small length
        // budget — get stacked vertically so the operator can scan
        // them like a list. The classic offender is the EF.ARR
        // decoder which returns rows like
        // ``"READ: ADM1"`` / ``"UPDATE/APPEND: Always"``.
        var humanLike = value.some(function (v) {
          if (typeof v !== "string") return false;
          if (v.length > 16) return true;
          if (v.indexOf(":") !== -1) return true;
          if (/\s/.test(v)) return true;
          if (v.indexOf("/") !== -1) return true;
          return false;
        });
        if (!humanLike) {
          arr.classList.add("cc-pv-array--chips");
          value.forEach(function (item) {
            arr.appendChild(renderPrettyPrimitive(item));
          });
          return arr;
        }
        arr.classList.add("cc-pv-array--lines");
        value.forEach(function (item) {
          var line = document.createElement("div");
          line.className = "cc-pv-array-line";
          line.appendChild(renderPrettyPrimitive(item));
          arr.appendChild(line);
        });
        return arr;
      }
      value.forEach(function (item, idx) {
        var row = document.createElement("div");
        row.className = "cc-pv-array-row";
        var label = document.createElement("span");
        label.className = "cc-pv-array-idx";
        label.textContent = saipPrettyArrayRowLabel(item, idx);
        var body = document.createElement("div");
        body.className = "cc-pv-array-body";
        body.appendChild(renderPrettyValue(item, depthIdx + 1));
        row.appendChild(label);
        row.appendChild(body);
        arr.appendChild(row);
      });
      return arr;
    }
    // Object — render as a nested definition list. Beyond depth 2,
    // wrap the body in a <details> so the operator can keep the
    // outer view scannable.
    var keys = Object.keys(value);
    if (keys.length === 0) {
      var emptyObj = document.createElement("span");
      emptyObj.className = "cc-pv cc-pv--null";
      emptyObj.textContent = "{ } (empty)";
      return emptyObj;
    }
    var dl = document.createElement("dl");
    dl.className = "cc-pv-object cc-pv-object--depth-" + depthIdx;
    keys.forEach(function (key) {
      var row = document.createElement("div");
      row.className = "cc-pv-field";
      var dt = document.createElement("dt");
      dt.className = "cc-pv-key";
      dt.textContent = saipPrettySaipFieldKey(key);
      var dd = document.createElement("dd");
      dd.className = "cc-pv-val";
      dd.appendChild(renderPrettyValue(value[key], depthIdx + 1));
      row.appendChild(dt);
      row.appendChild(dd);
      dl.appendChild(row);
    });
    if (depthIdx >= 2) {
      var details = document.createElement("details");
      details.className = "cc-pv-collapsible";
      details.open = depthIdx === 2;
      var summary = document.createElement("summary");
      summary.className = "cc-pv-collapsible-head";
      summary.textContent = "{" + keys.length + " field"
        + (keys.length === 1 ? "" : "s") + "}";
      details.appendChild(summary);
      details.appendChild(dl);
      return details;
    }
    return dl;
  }

  // Toolbar attached to a "decoded" block. Lets the operator switch
  // between the polished view (default) and raw JSON, plus a Copy
  // shortcut so copy-paste into a runbook is one click instead of
  // a manual select.
  function buildDecodedToolbar(decoded, prettyEl, jsonEl, meta) {
    var bar = document.createElement("div");
    bar.className = "cc-decoded-tools";

    // Stage-edit button — surfaced for every decoded EF that carries
    // its original bytes (``meta.rawHex``). Service-table payloads get
    // the purpose-built checklist; everything else falls back to the
    // generic side-by-side hex editor (``scp03ShowGenericStaging``).
    // Either popout funnels its result through ``scp03GateOpen`` →
    // UPDATE BINARY so the auth modal still gates the write.
    if (meta && typeof meta.rawHex === "string" && meta.rawHex.length > 0) {
      var isBitmap = typeof isServiceTablePayload === "function"
        && isServiceTablePayload(decoded);
      var stageHandler = null;
      var stageTitle = "";
      if (isBitmap && typeof scp03ShowServiceTableStaging === "function") {
        stageHandler = function () {
          scp03ShowServiceTableStaging(decoded, meta.rawHex);
        };
        stageTitle = "Open the service-table staging panel — toggle "
          + "service flags and preview the resulting hex without "
          + "writing to the card.";
      } else if (typeof scp03ShowGenericStaging === "function") {
        stageHandler = function () {
          scp03ShowGenericStaging(decoded, meta.rawHex, meta);
        };
        stageTitle = "Open a hex stage-edit popout pre-filled with the "
          + "current bytes. Edit, then send to UPDATE BINARY (auth "
          + "modal still gates the actual write).";
      }
      if (stageHandler) {
        var stageBtn = document.createElement("button");
        stageBtn.type = "button";
        stageBtn.className = "cc-decoded-tools-btn cc-decoded-tools-btn--stage";
        stageBtn.textContent = "Stage edit";
        stageBtn.title = stageTitle;
        stageBtn.addEventListener("click", stageHandler);
        bar.appendChild(stageBtn);
      }
    }

    var toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "cc-decoded-tools-btn";
    toggle.setAttribute("data-mode", "pretty");
    toggle.textContent = "Show JSON";
    toggle.title = "Toggle between the decoded layout and ASN.1-shaped JSON";
    toggle.addEventListener("click", function () {
      var nextMode = toggle.getAttribute("data-mode") === "pretty" ? "json" : "pretty";
      toggle.setAttribute("data-mode", nextMode);
      if (nextMode === "json") {
        prettyEl.hidden = true;
        prettyEl.style.display = "none";
        jsonEl.hidden = false;
        jsonEl.style.display = "";
        toggle.textContent = "Decoded";
      } else {
        prettyEl.hidden = false;
        prettyEl.style.display = "";
        jsonEl.hidden = true;
        jsonEl.style.display = "none";
        toggle.textContent = "Show JSON";
      }
    });
    bar.appendChild(toggle);

    var copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "cc-decoded-tools-btn";
    copyBtn.textContent = "Copy JSON";
    copyBtn.title = "Copy ASN.1-shaped JSON to the clipboard";
    copyBtn.addEventListener("click", function () {
      var text;
      try {
        text = JSON.stringify(decoded, null, 2);
      } catch (_err) {
        text = String(decoded);
      }
      if (typeof copyTextToClipboard === "function") {
        copyTextToClipboard(text);
      } else if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(function () {});
      }
      copyBtn.classList.add("is-copied");
      setTimeout(function () { copyBtn.classList.remove("is-copied"); }, 700);
    });
    bar.appendChild(copyBtn);
    return bar;
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

  function renderScp03Workbench(container, actions, options) {
    var opts = options || {};
    // Scope determines which ribbon tabs / panels the workbench shows:
    //   "filesystem"   — tree + FCP preview + FS action bar; ribbon
    //                    filtered to navigation / inspection / APDU
    //   "applications" — session header + GP ribbon (auth, registry,
    //                    install, eUICC, admin, APDU). Tree hidden.
    //   "all"          — every panel + every ribbon tab (classic view)
    // Stored on the workbench so ribbon-tab switches and persistence
    // helpers can read it back without the opts object.
    var scope = opts.scope || "all";
    if (commandState.scp03Workbench) {
      commandState.scp03Workbench.scope = scope;
    }

    var wb = document.createElement("section");
    wb.className = "cc-workbench";
    wb.setAttribute("data-wb", "scp03");
    wb.setAttribute("data-scp03-scope", scope);

    // Session-tab strip lives at the very top — one tab = one reader =
    // one secure-channel session. Each tab owns a full-height shell
    // (reader sidebar + main column) inside ``tabBody``.
    var tabBar = document.createElement("div");
    tabBar.className = "cc-wb-tabs scp03-topbar";
    tabBar.setAttribute("role", "tablist");
    wb.appendChild(tabBar);

    var tabBody = document.createElement("div");
    tabBody.className = "cc-wb-body";
    wb.appendChild(tabBody);

    container.appendChild(wb);

    scp03EnsureDefaultTab();
    // Pre-bind the default tab to the top-bar active reader so the
    // welcome panel and "Rescan" button target the reader the operator
    // already selected via the pill strip. Without this the first
    // visit to SCP03 after picking a pill would still show an
    // unbound tab.
    var bar = commandState.readerBar;
    if (bar && bar.activeReader) {
      readerBarSyncToScp03Tab(bar.activeReader);
    }
    // Kick off a live-readers poll so the sidebar is populated on open.
    scp03RefreshReaderInventory();
    renderScp03Tabs(tabBar, tabBody);
    // Ensure the top-bar pill strip reflects the current active tab
    // (e.g. on direct deep-link into SCP03 the pills may not have
    // rendered yet — readerBarBootstrap kicked off async).
    if (typeof readerBarNotifySessionChanged === "function") {
      readerBarNotifySessionChanged();
    }
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
      treeCollapsed: {},
      previewCache: null, // last FCP / records response
      // Per-path cache keyed by the scan-tree path string. Every
      // successful ``scp03.read_selected`` goes in; the preview
      // renderer displays cached data immediately on click while
      // firing a fresh read underneath (and falls back to a
      // reset + rescan + retry sequence if the fresh read fails).
      // Mirrors the "optimistic UI" pattern so the file view never
      // goes blank during an eUICC → Files context switch.
      fcpCache: {},
      // Wall-clock of the last successful recovery — shown in the
      // "refreshing / recovering" banner so operators can see how
      // recently we re-anchored the card. Populated by
      // ``scp03RecoverSession``.
      lastRecoverAt: 0,
      status: "idle",
      error: null,
      // Classifier for the last non-OK response: "", "no_card",
      // "session_gone". Drives the welcome panel's inline notice +
      // gates auto-open so a known-empty reader doesn't keep firing
      // scan loops on every pill click.
      errorKind: "",
      // New in v2: ribbon-tab selection persists per session tab.
      activeRibbonTab: "home",
      // Reader the user has "pointed" this tab at, even before they
      // start scanning — lets the sidebar drive the workflow end to end.
      pendingReader: "",
      // Per-tab APDU console state — the "APDU" ribbon tab's panel
      // is a stateful workbench: the last typed APDU survives a ribbon
      // tab switch, and the history log keeps the last 20 sent APDUs
      // so operators can re-send / copy without re-typing. Each session
      // tab gets its own isolated history.
      apduInputHex: "",
      apduFollow61: true,
      apduRetry6C: true,
      apduHistory: [],
      apduLastResult: null,
      // Per-tab floating-popout registry.
      //
      // Every SCP03 action used to drop its card into the ``.cc-wb-extras``
      // strip below the file tree; on a busy session (card_info + GP
      // status + eUICC info + key-info + …) the extras strip grew into a
      // scrollable tower that hid the tree. The popout system keeps each
      // action's output in a draggable/resizable floating window keyed by
      // ``<title>``, so clicking the same action twice just brings the
      // existing window forward instead of stacking clones, and windows
      // bound to one session tab are invisible while a sibling tab is
      // active (cheap: toggled via ``display:none``, state is preserved).
      //
      // Keys are the action title strings (e.g. ``"ATR details"``,
      // ``"GP registry"``) because that's what the callers already pass
      // to ``scp03BuildExtrasCard`` — no signature churn required at the
      // 60+ call sites.
      popouts: {},
      // Monotonically-increasing z-index counter for this tab's popouts.
      // Initialised from the module-level ``SCP03_POPOUT_Z_BASE`` on first
      // use; lives on the tab so a focus flip doesn't interfere with
      // sibling tabs' stacking order.
      popoutZCursor: 0,
      // Cascade offset for staggered initial placement. Incremented on
      // every new popout, reset when it would push the window off-screen.
      popoutCascadeIdx: 0,
      // Per-tab secure-session auth cache.
      //
      // Populated by ``scp03.auth_scp03`` / ``scp03.auth_scp02`` responses
      // and by ``scp03.auth_status`` probes when a tab is restored from
      // ``localStorage``. The GUI consults this before firing any
      // ``requires_auth`` action (PUT KEY, INSTALL [for …], SET STATUS,
      // DELETE, fs_create_file, etc.) — if ``authenticated`` is false we
      // open the auth prompt modal first, let the operator pick a
      // protocol / Target AID / optional key override, run AUTH, then
      // chain into the original action on success. Values here are
      // purely metadata (protocol name, target AID hex, KVN, sec level,
      // wall-clock stamp of the last successful AUTH); key material is
      // never cached frontend-side — the overrides live only as long
      // as the submit handler that passed them.
      authStatus: { authenticated: false, protocol: "", targetAid: "",
                    kvn: "", secLevel: "", at: 0, overridesApplied: [] },
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
      } else if (tab.pendingReader) {
        label.textContent = tab.pendingReader + " — pending";
      } else {
        label.textContent = "New session";
      }
      btn.appendChild(label);
      if (tab.sessionId) {
        var meta = document.createElement("span");
        meta.className = "cc-wb-tab-meta";
        meta.textContent = (tab.sessionId || "").substring(0, 6);
        btn.appendChild(meta);
      } else if (tab.pendingReader) {
        var pending = document.createElement("span");
        pending.className = "cc-wb-tab-meta";
        pending.textContent = "unopened";
        btn.appendChild(pending);
      }
      var close = document.createElement("span");
      close.className = "cc-wb-tab-close";
      close.textContent = "\u00d7";
      close.title = "Close this tab";
      close.addEventListener("click", function (event) {
        event.stopPropagation();
        scp03CloseTab(tab.id, tabBar, tabBody);
      });
      btn.appendChild(close);
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
    add.title = "Open another reader in a new tab";
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
      scp03PopoutSyncVisibilityToActiveTab();
      return;
    }
    scp03RenderTabBody(active, tabBody, tabBar);
    // Floating popouts live outside the tab body (``position: fixed``
    // anchored to ``#cc-popout-host``) so a tab-body rerender doesn't
    // touch them. The visibility sync is what scopes them per tab:
    // windows owned by the active tab show, sibling-tab windows hide.
    scp03PopoutSyncVisibilityToActiveTab();
  }

  function scp03RenderTabBody(tab, tabBody, tabBar) {
    tabBody.innerHTML = "";
    // Every tab renders the same two-column shell (reader pane + main).
    // Only the main column differs by session state — this keeps the
    // reader sidebar visible end-to-end so switching tabs never hides
    // the "what reader am I driving?" context.
    var shell = document.createElement("div");
    shell.className = "scp03-shell";

    var readerPane = scp03BuildReaderSidebar(tab, tabBar, tabBody);
    shell.appendChild(readerPane);

    var main = document.createElement("div");
    main.className = "scp03-session-main";
    // Priority order for the main column:
    //   scanning  → loading state (rescan in flight, old session wiped)
    //   sessionId → active workbench
    //   else      → welcome panel (fresh tab or after close)
    if (tab.status === "scanning" && !tab.sessionId) {
      main.appendChild(scp03BuildScanningPanel(tab));
    } else if (!tab.sessionId) {
      main.appendChild(scp03BuildWelcomePanel(tab, tabBar, tabBody));
    } else {
      main.appendChild(scp03BuildActiveSessionPanel(tab, tabBar, tabBody));
    }
    shell.appendChild(main);
    tabBody.appendChild(shell);
  }

  function scp03BuildScanningPanel(tab) {
    // Intermediate panel shown while a (re-)scan is in flight against a
    // tab that no longer has a valid session_id. Replaces the welcome
    // panel so the user gets immediate, unambiguous feedback that a
    // scan is running — otherwise the UI briefly looks like the tab
    // was closed.
    var panel = document.createElement("div");
    panel.className = "scp03-session-welcome";
    installMaximizable(panel);
    var h = document.createElement("h3");
    h.textContent = "Scanning…";
    panel.appendChild(h);
    var hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = "Walking the live file system from MF on reader '"
      + (tab.readerName || "(default)") + "'. This usually finishes in a "
      + "second or two — the tree + FCP preview will appear automatically.";
    panel.appendChild(hint);
    var spinner = document.createElement("p");
    spinner.className = "loading";
    spinner.textContent = "scan in progress…";
    panel.appendChild(spinner);
    return panel;
  }

  // --- scp03: reader sidebar (per-tab reader binding) --------------------

  async function scp03RefreshReaderInventory() {
    var wb = commandState.scp03Workbench;
    if (wb.readersLoading) return;
    wb.readersLoading = true;
    wb.readersError = null;
    scp03RepaintReaderPane();
    try {
      var data = await apiFetch("/api/live/readers");
      wb.readers = (data && data.readers) || [];
      wb.readersFetchedAt = Date.now();
    } catch (err) {
      wb.readersError = String((err && err.message) || err);
      wb.readers = [];
    } finally {
      wb.readersLoading = false;
      scp03RepaintReaderPane();
    }
  }

  function scp03RepaintReaderPane() {
    var wb = commandState.scp03Workbench;
    var tab = scp03FindTab(wb.activeTabId);
    var body = document.querySelector(".cc-wb-body");
    var bar = document.querySelector(".cc-wb-tabs.scp03-topbar");
    if (!tab || !body || !bar) return;
    var pane = body.querySelector(".scp03-reader-pane");
    if (!pane) return;
    var fresh = scp03BuildReaderSidebar(tab, bar, body);
    pane.parentNode.replaceChild(fresh, pane);
  }

  function scp03BuildReaderSidebar(tab, tabBar, tabBody) {
    var wb = commandState.scp03Workbench;
    var pane = document.createElement("aside");
    pane.className = "scp03-reader-pane";
    pane.setAttribute("aria-label", "PC/SC readers");

    var head = document.createElement("div");
    head.className = "scp03-reader-head";
    var title = document.createElement("h4");
    title.textContent = "Readers";
    head.appendChild(title);
    var refresh = document.createElement("button");
    refresh.type = "button";
    refresh.className = "scp03-reader-refresh";
    refresh.title = "Re-enumerate PC/SC readers";
    refresh.setAttribute("aria-label", "Refresh readers");
    refresh.textContent = "\u21BB";
    refresh.addEventListener("click", function () { scp03RefreshReaderInventory(); });
    head.appendChild(refresh);
    pane.appendChild(head);

    var list = document.createElement("ul");
    list.className = "scp03-reader-list";

    if (wb.readersLoading && wb.readers.length === 0) {
      var loading = document.createElement("li");
      loading.className = "scp03-reader-empty";
      loading.textContent = "probing PC/SC…";
      list.appendChild(loading);
    } else if (wb.readersError) {
      var errLi = document.createElement("li");
      errLi.className = "scp03-reader-empty";
      errLi.textContent = "error: " + wb.readersError;
      list.appendChild(errLi);
    } else if (wb.readers.length === 0) {
      var empty = document.createElement("li");
      empty.className = "scp03-reader-empty";
      empty.textContent = "no PC/SC readers found. Plug one in and hit the refresh arrow.";
      list.appendChild(empty);
    } else {
      // Build a set of reader names already bound to other tabs so the
      // sidebar can warn about double-binding.
      var boundElsewhere = {};
      wb.tabs.forEach(function (other) {
        if (other.id !== tab.id && other.readerName && other.sessionId) {
          boundElsewhere[other.readerName] = other.id;
        }
      });
      var activeReader = tab.readerName || tab.pendingReader || "";
      wb.readers.forEach(function (row) {
        var name = row.name || "";
        var li = scp03BuildReaderItem(
          row,
          name === tab.readerName && !!tab.sessionId,
          name === tab.pendingReader && !tab.sessionId,
          boundElsewhere[name] || null,
          tab,
          tabBar,
          tabBody
        );
        list.appendChild(li);
      });
    }
    pane.appendChild(list);

    var hint = document.createElement("div");
    hint.className = "scp03-reader-hint";
    hint.innerHTML = "<strong>how it works</strong>"
      + "<span>Click a reader to bind this tab to it. "
      + "Every action dispatched from this tab targets the bound reader."
      + "</span>";
    pane.appendChild(hint);
    return pane;
  }

  function scp03BuildReaderItem(row, isActive, isPending, alreadyBoundTabId, tab, tabBar, tabBody) {
    var li = document.createElement("li");
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "scp03-reader-item";
    if (isActive) btn.classList.add("is-active");
    else if (isPending) btn.classList.add("is-pending");
    btn.setAttribute("data-reader-name", row.name || "");

    var dot = document.createElement("span");
    dot.className = "scp03-reader-dot";
    btn.appendChild(dot);

    var body = document.createElement("span");
    body.className = "scp03-reader-body";
    var name = document.createElement("span");
    name.className = "scp03-reader-name";
    name.textContent = row.name || "(no name)";
    name.title = row.name || "";
    body.appendChild(name);

    if (row.atr_hex) {
      var atr = document.createElement("span");
      atr.className = "scp03-reader-atr";
      atr.textContent = row.atr_hex;
      atr.title = row.atr_hex;
      body.appendChild(atr);
    }

    var state = document.createElement("span");
    state.className = "scp03-reader-state";
    if (isActive) {
      state.classList.add("scp03-reader-state--open");
      state.textContent = "session open";
    } else if (alreadyBoundTabId) {
      state.classList.add("scp03-reader-state--error");
      state.textContent = "bound to another tab";
    } else if (row.status === "error") {
      state.classList.add("scp03-reader-state--error");
      state.textContent = "error";
    } else if (row.atr_hex) {
      state.classList.add("scp03-reader-state--idle");
      state.textContent = "card present";
    } else {
      state.classList.add("scp03-reader-state--idle");
      state.textContent = "no card";
    }
    body.appendChild(state);
    btn.appendChild(body);

    btn.addEventListener("click", function () {
      scp03ChooseReaderForTab(tab, row.name || "", tabBar, tabBody);
    });
    li.appendChild(btn);
    return li;
  }

  function scp03ChooseReaderForTab(tab, readerName, tabBar, tabBody) {
    if (!readerName) return;
    if (tab.sessionId && tab.readerName === readerName) {
      return; // already the active binding for this tab
    }
    if (tab.sessionId && tab.readerName !== readerName) {
      var keep = window.confirm(
        "This tab is currently bound to '" + tab.readerName + "' "
          + "(session " + (tab.sessionId || "?").substring(0, 8) + "…). "
          + "\n\nSwitch to '" + readerName + "'? "
          + "The existing session will be closed."
      );
      if (!keep) return;
      scp03CloseTabSessionOnly(tab).then(function () {
        tab.pendingReader = readerName;
        renderScp03Tabs(tabBar, tabBody);
        scp03OpenSessionForTab(tab, tabBar, tabBody);
      });
      return;
    }
    tab.pendingReader = readerName;
    renderScp03Tabs(tabBar, tabBody);
    scp03OpenSessionForTab(tab, tabBar, tabBody);
  }

  async function scp03CloseTabSessionOnly(tab) {
    if (!tab.sessionId) return;
    try {
      await apiFetch("/api/actions/scp03.close_session/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
    } catch (_err) { /* ignore — we're replacing the session anyway */ }
    tab.sessionId = null;
    tab.atrHex = "";
    tab.readerName = "";
    tab.scanData = null;
    tab.selectedPath = null;
    tab.treeCollapsed = {};
    tab.previewCache = null;
    tab.fcpCache = {};
    tab.lastRecoverAt = 0;
    refreshSessionStatusMetric();
  }

  // ---------------------------------------------------------------
  // scp03 error classification. The backend annotates well-known
  // non-transient failures with a prefix so the frontend can branch:
  //
  //   "no_card:"       — reader is empty; no point retrying,
  //                      show a clear "insert a card" banner.
  //   "session_gone:"  — session_id was reaped (idle timeout) or the
  //                      GUI is carrying a stale id from localStorage.
  //                      No session to recover to; the tab must be
  //                      re-opened.
  //
  // We also defensively match on "NoCardException" / "No smart card
  // inserted" so older builds that don't emit the prefix still get
  // the friendly UX.
  function scp03ClassifyError(message) {
    var s = String(message || "");
    if (!s) return "";
    if (s.indexOf("no_card:") >= 0) return "no_card";
    if (s.indexOf("session_gone:") >= 0) return "session_gone";
    if (s.indexOf("NoCardException") >= 0) return "no_card";
    if (s.indexOf("No smart card") >= 0) return "no_card";
    if (s.indexOf("0x8010000C") >= 0) return "no_card";
    return "";
  }

  async function scp03OpenSessionForTab(tab, tabBar, tabBody) {
    // ``tab.pendingReader`` is optional — an empty string means "use the
    // default / first PC/SC reader" (the backend resolves index 0). We
    // used to early-return on empty, which left the "Open default reader"
    // button silently broken. Now we always dispatch scan and let the
    // backend pick.
    var target = tab.pendingReader || "";
    tab.status = "scanning";
    tab.error = null;
    tab.errorKind = "";
    renderScp03Tabs(tabBar, tabBody);
    try {
      var resp = await apiFetch("/api/actions/scp03.scan/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { reader: target } }),
      });
      if (!resp.ok) {
        tab.error = resp.error || "scan failed";
        tab.errorKind = scp03ClassifyError(resp.error);
        tab.status = "idle";
        // "no_card" gets a WARN level — it's routine operator feedback
        // ("no card in reader X"), not a forensic event. Everything else
        // stays at ERROR so real regressions stay loud.
        logBus.emit({
          level: tab.errorKind === "no_card" ? "warn" : "error",
          source: "scp03.scan",
          message: "scan " + (tab.errorKind === "no_card"
              ? "halted (no card in reader)"
              : "failed")
            + " on '" + (target || "(default)") + "': "
            + (resp.error || "unknown"),
        });
      } else {
        var data = resp.data || {};
        tab.sessionId = data.session_id || null;
        // Trust the backend's echoed reader name — scp03.scan normalises
        // empty input to "(default)" and resolves the actual PC/SC name
        // when one was passed. This keeps tab.readerName in sync with the
        // pill strip, which fetches names from the same /api/live/readers
        // source.
        tab.readerName = data.reader_name || target;
        tab.atrHex = data.atr_hex || "";
        tab.scanData = data;
        tab.status = "open";
        tab.pendingReader = "";
        tab.error = null;
        tab.errorKind = "";
        commandState.scp03Session = tab.sessionId;
        readerBarSetActiveReaderOnly(tab.readerName);
        logBus.emit({
          level: "info",
          source: "scp03.scan",
          message: "session " + (tab.sessionId || "?").substring(0, 8)
            + " opened on '" + (tab.readerName || "(default)") + "' — "
            + ((data.tree && data.tree.length) || 0) + " roots",
        });
        // Best-effort persist so the tree + selection + FCP cache
        // survive across reloads. Keyed by reader name so each reader
        // restores independently.
        scp03PersistTab(tab);

        // Auto-fetch card overview (ICCID, eID, standard) for the
        // Home tab dashboard. Fire-and-forget — if it fails the
        // header chips simply won't show the extra fields.
        if (tab.sessionId) {
          apiFetch("/api/actions/scp03.card_info/run", {
            method: "POST",
            body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
          }).then(function (ciResp) {
            if (ciResp && ciResp.ok && ciResp.data) {
              tab.cardInfo = ciResp.data;
              // Re-render to show the new header chips
              renderScp03Tabs(tabBar, tabBody);
            }
          }).catch(function () { /* non-critical */ });
        }
      }
    } catch (err) {
      tab.error = String((err && err.message) || err);
      tab.errorKind = scp03ClassifyError(tab.error);
      tab.status = "idle";
      logBus.emit({
        level: tab.errorKind === "no_card" ? "warn" : "error",
        source: "scp03.scan",
        message: "scan threw on '" + (target || "(default)") + "': "
          + String((err && err.message) || err),
      });
    }
    renderScp03Tabs(tabBar, tabBody);
    // Flip the top-bar pill colour immediately (green once the session
    // is live).
    if (typeof readerBarNotifySessionChanged === "function") {
      readerBarNotifySessionChanged();
    }
  }

  // --- scp03: welcome panel for a fresh tab -----------------------------

  function scp03BuildWelcomePanel(tab, tabBar, tabBody) {
    var panel = document.createElement("div");
    panel.className = "scp03-session-welcome";
    installMaximizable(panel);

    var hasPersisted = scp03HasPersistedState(tab);
    var selectedReader = "";
    if (!tab.readerName && !tab.pendingReader && typeof ccActiveReaderName === "function") {
      selectedReader = ccActiveReaderName();
    }
    var displayReader = tab.readerName || tab.pendingReader || selectedReader || "";

    var h = document.createElement("h3");
    h.textContent = hasPersisted
      ? "Cached session on this reader"
      : "No SCP03 session on this tab";
    panel.appendChild(h);

    var hint = document.createElement("p");
    hint.className = "hint";
    if (hasPersisted) {
      var ageMs = tab.persistedAt ? (Date.now() - tab.persistedAt) : 0;
      var ageStr = scp03FormatAge(ageMs) || "earlier";
      var treeSize = (tab.scanData && Array.isArray(tab.scanData.tree))
        ? tab.scanData.tree.length : 0;
      var cacheSize = tab.fcpCache ? Object.keys(tab.fcpCache).length : 0;
      hint.textContent = "Restored from last session on '"
        + (displayReader || "(default)")
        + "' — " + treeSize + " root node"
        + (treeSize === 1 ? "" : "s") + ", " + cacheSize + " cached file"
        + (cacheSize === 1 ? "" : "s") + " (saved " + ageStr + "). "
        + "Click Resume to open a fresh secure channel and re-sync "
        + "the tree with the card.";
    } else if (displayReader) {
      hint.textContent = "Reader '" + displayReader + "' selected. "
        + "Click Open to run the live scan and bind this tab to that reader.";
    } else {
      hint.textContent = "Pick a reader from the top bar. "
        + "The scan walks the live file system from MF and opens a "
        + "secure channel — everything you dispatch in this tab will "
        + "target that reader.";
    }
    panel.appendChild(hint);

    var bar = document.createElement("div");
    bar.className = "inline-actions cc-inline-actions-center";
    var openBtn = document.createElement("button");
    openBtn.type = "button";
    openBtn.className = "btn btn-primary";
    if (hasPersisted) {
      openBtn.textContent = "Resume '"
        + (displayReader || "(default)") + "'";
    } else if (displayReader) {
      openBtn.textContent = "Open '" + displayReader + "'";
    } else {
      openBtn.textContent = "Open default reader";
    }
    openBtn.addEventListener("click", function () {
      // Mirror pendingReader from readerName when resuming a hydrated
      // tab so the scan targets the same PC/SC slot. Non-hydrated
      // tabs keep their current pendingReader (empty → default reader).
      if (!tab.pendingReader && tab.readerName) {
        tab.pendingReader = tab.readerName;
      } else if (!tab.pendingReader && selectedReader) {
        tab.pendingReader = selectedReader;
      }
      scp03OpenSessionForTab(tab, tabBar, tabBody);
    });
    bar.appendChild(openBtn);

    var refreshBtn = document.createElement("button");
    refreshBtn.type = "button";
    refreshBtn.className = "btn";
    refreshBtn.textContent = "Refresh readers";
    refreshBtn.addEventListener("click", function () {
      scp03RefreshReaderInventory();
    });
    bar.appendChild(refreshBtn);

    // Operators who want to start clean from a hydrated tab can hit
    // Forget — wipes localStorage for this reader AND clears the
    // in-memory caches, leaving the tab in the pristine "unbound"
    // state. The pill stays active so a follow-up click re-opens the
    // reader without any ghosts.
    if (hasPersisted) {
      var forgetBtn = document.createElement("button");
      forgetBtn.type = "button";
      forgetBtn.className = "btn";
      forgetBtn.textContent = "Forget cached state";
      forgetBtn.title = "Clear the saved tree + FCP cache for this reader";
      forgetBtn.addEventListener("click", function () {
        var targetName = tab.readerName || tab.pendingReader || "";
        if (targetName) scp03PurgePersisted(targetName);
        tab.scanData = null;
        tab.fcpCache = {};
        tab.previewCache = null;
        tab.selectedPath = null;
        tab.treeCollapsed = {};
        tab.apduHistory = [];
        tab.persistedAt = 0;
        renderScp03Tabs(tabBar, tabBody);
      });
      bar.appendChild(forgetBtn);
    }

    panel.appendChild(bar);

    if (tab.error) {
      var errSlot = document.createElement("div");
      errSlot.className = "cc-wb-error";
      // "no_card" gets a friendly inline notice rather than the generic
      // error block — it's routine operator feedback, not a bug. Users
      // should see "insert a card" + a Retry button, not a stack trace.
      if (tab.errorKind === "no_card") {
        var notice = document.createElement("div");
        notice.className = "cc-no-card-notice";
        var title = document.createElement("strong");
        title.textContent = "No card detected in reader";
        notice.appendChild(title);
        var body = document.createElement("p");
        body.textContent = "Insert a smart card into '"
          + (tab.readerName || tab.pendingReader || "(default)")
          + "' and retry. The reader is online but reports an empty "
          + "slot (hresult 0x8010000C).";
        notice.appendChild(body);
        var details = document.createElement("details");
        var summary = document.createElement("summary");
        summary.textContent = "raw error";
        details.appendChild(summary);
        var pre = document.createElement("pre");
        pre.className = "cc-log cc-log-inline";
        pre.textContent = tab.error;
        details.appendChild(pre);
        notice.appendChild(details);
        errSlot.appendChild(notice);
      } else {
        errSlot.appendChild(renderErrorBlock(tab.error));
      }
      panel.appendChild(errSlot);
    }
    return panel;
  }

  // -- Icon palette (SCP03 ribbon + reader context menu) ------------------
  //
  // Centralised glyph vocabulary so the ribbon stays visually
  // consistent. Uses a deliberately small set of neutral / minimalist
  // Unicode forms — geometric circled-operators (⊕ ⊖ ⊘ ⊙ ⊚ ⊜ ⊞ ⊟ ⊡),
  // simple arrows (↻ ↺ ↶ ↪ ⇄ ⤓ ⬇ ↑), squares (▣ ▤ ▦ ▩), and a handful
  // of long-standing ETSI/GP iconography (✓ ✗ ★ ⓘ). Anything heraldic,
  // emoji-flavoured, or themed (fleur-de-lis, atom, lightning, cloud-
  // emoji, question-mark) was retired in favour of this calmer palette.
  // The named keys carry semantics so future tweaks land in one place.
  var SCP03_ICONS = Object.freeze({
    // Navigate / lifecycle
    rescan:           "\u21BB", // ↻
    resetCard:        "\u21BA", // ↺
    clearSelection:   "\u00D7", // ×
    logout:           "\u21B6", // ↶
    close:            "\u00D7", // ×
    // Read / inspect
    readSelected:     "\u270E", // ✎
    selectArbitrary:  "\u2316", // ⌖
    listGeneric:      "\u2630", // ☰
    readBinary:       "\u25A4", // ▤
    readRecord:       "\u25A6", // ▦
    arr:              "\u2699", // ⚙
    atr:              "\u2318", // ⌘
    cardInfo:         "\u24D8", // ⓘ
    decode:           "\u229E", // ⊞
    dumpToDisk:       "\u2913", // ⤓
    // Auth / keys
    authSession:      "\u2299", // ⊙
    keys:             "\u2299", // ⊙
    putKey:           "\u2299", // ⊙
    certInfo:         "\u2299", // ⊙
    // Applications / GP
    apps:             "\u25A3", // ▣
    packages:         "\u2316", // ⌖
    securityDomains:  "\u2B22", // ⬢
    getData:          "\u22A1", // ⊡
    aidRegistry:      "\u2630", // ☰
    // Profiles / eUICC
    profiles:         "\u2261", // ≡
    euiccScan:        "\u2315", // ⌕
    configData:       "\u22A1", // ⊡
    sgp32Bulk:        "\u22A0", // ⊠
    enableProfile:    "\u2714", // ✔
    disableProfile:   "\u2298", // ⊘
    deleteProfile:    "\u2717", // ✗
    setGold:          "\u2605", // ★
    showGold:         "\u2630", // ☰
    clearGold:        "\u2296", // ⊖
    diff:             "\u21C4", // ⇄
    eid:              "\u29BE", // ⦾
    euiccCerts:       "\u2299", // ⊙
    // Lifecycle (GP)
    setStatus:        "\u229C", // ⊜
    lock:             "\u2298", // ⊘
    unlock:           "\u229A", // ⊚
    deleteApp:        "\u2717", // ✗
    // Write
    storeData:        "\u2295", // ⊕
    updateBinary:     "\u270E", // ✎
    updateRecord:     "\u270E", // ✎
    // Validate / crypto
    validate:         "\u2713", // ✓
    deriveOpc:        "\u2297", // ⊗
    authVector:       "\u2713", // ✓
    // Export
    exportYaml:       "\u2913", // ⤓
    exportKeybag:     "\u2913", // ⤓
    // Config / admin
    showConfig:       "\u2699", // ⚙
    aidAlias:         "\u270E", // ✎
    resetKeys:        "\u21BA", // ↺
    // Install
    installCap:       "\u2B07", // ⬇
    installApp:       "\u2295", // ⊕
    makeSelectable:   "\u2713", // ✓
    extradition:      "\u21C4", // ⇄
    perso:            "\u270D", // ✍
    registryUpdate:   "\u2699", // ⚙
    // Misc
    pin:              "\u2299", // ⊙
    channel:          "\u229C", // ⊜
    runAuth:          "\u25B6", // ▶
    stkShell:         "\u25B6", // ▶
    otaShell:         "\u2601", // ☁  (kept — universally semantic for OTA)
    runScript:        "\u25B6", // ▶
    fsReport:         "\u2398", // ⎘
    guides:           "\u24D8", // ⓘ
    // Reader context menu
    openSession:      "\u21AA", // ↪
    refreshAtr:       "\u21BB", // ↻
    copy:             "\u2398", // ⎘
  });

  // Surface for ad-hoc DevTools poking and regression tests that
  // pin the vocabulary so it doesn't quietly drift back to mixed
  // heraldic/emoji glyphs.
  window.YggdraSimIcons = SCP03_ICONS;

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
    ribbon.className = "scp03-ribbon-v2";
    ribbon.setAttribute("role", "toolbar");
    ribbon.setAttribute("aria-label", "SCP03 session actions");

    // Navigate
    var rescanBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.rescan, label: "Rescan", title: "Re-walk the file system from MF" },
      function () { scp03Rescan(tab, tabBar, tabBody); }
    );
    var resetSelBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.clearSelection, label: "Clear selection", title: "Clear the selected file (UI only)" },
      function () {
        tab.selectedPath = null;
        tab.previewCache = null;
        renderScp03Tabs(tabBar, tabBody);
      }
    );
    var resetCardBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.resetCard, label: "Reset card", title: "Cold-reset the card (RESET + re-read ATR)" },
      function () { scp03Reset(tab, tabBar, tabBody); }
    );
    var navGroup = scp03MakeRibbonGroup("Navigate", [rescanBtn, resetSelBtn, resetCardBtn]);

    // Inspect
    var readBtn = scp03MakeRibbonButton(
      {
        icon: SCP03_ICONS.readSelected,
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
      { icon: SCP03_ICONS.selectArbitrary, label: "SELECT…", title: "SELECT an arbitrary AID / file identifier" },
      function () { scp03PromptSelect(tab, tabBar, tabBody); }
    );
    var listAppsBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.listGeneric, label: "List apps", title: "Dump EF.DIR application records" },
      function () { scp03ListApps(tab); }
    );
    var readBinBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.readBinary, label: "READ", title: "READ BINARY (00B0) on current or named path" },
      function () { scp03ReadBinary(tab); }
    );
    var readRecBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.readRecord, label: "RECORD…", title: "READ RECORD (00B2) — pick N / range / ALL" },
      function () { scp03ReadRecord(tab); }
    );
    var arrBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.arr, label: "ARR", title: "Decode EF.ARR for current or named scope" },
      function () { scp03ShowArr(tab); }
    );
    var inspectGroup = scp03MakeRibbonGroup(
      "Inspect",
      [readBtn, selectByAidBtn, listAppsBtn, readBinBtn, readRecBtn, arrBtn]
    );

    // Diagnostics
    var atrBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.atr, label: "ATR", title: "Decode ATR interface characters + historical bytes" },
      function () { scp03ShowAtr(tab); }
    );
    var infoBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.cardInfo, label: "Card info", title: "ATR + ICCID + EID + standard probe" },
      function () { scp03ShowCardInfo(tab); }
    );
    var decodeBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.decode, label: "Decode…", title: "Decode arbitrary hex as BER-TLV or GP registry stream" },
      function () { scp03ShowDecode(tab); }
    );
    var dumpFsBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.dumpToDisk, label: "Dump FS…", title: "Dump the live FS to disk under <dir>/FS_DUMP/<ICCID>/" },
      function () { scp03DumpFs(tab); }
    );
    var diagGroup = scp03MakeRibbonGroup(
      "Diagnostics",
      [atrBtn, infoBtn, decodeBtn, dumpFsBtn]
    );

    // Auth
    var authScp03Btn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.authSession, label: "Auth SCP03", title: "INITIALIZE UPDATE + EXTERNAL AUTHENTICATE (SCP03)" },
      function () { scp03AuthFlow(tab, "scp03.auth_scp03", "Authenticate SCP03"); }
    );
    var authScp02Btn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.authSession, label: "Auth SCP02", title: "INITIALIZE UPDATE + EXTERNAL AUTHENTICATE (SCP02)" },
      function () { scp03AuthFlow(tab, "scp03.auth_scp02", "Authenticate SCP02"); }
    );
    var logoutBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.logout, label: "Logout", title: "Drop the current secure session" },
      function () { scp03Logout(tab); }
    );
    var keysBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.keys, label: "Keys", title: "Key-info template (GET DATA tag E0)" },
      function () { scp03ShowKeys(tab); }
    );
    var authGroup = scp03MakeRibbonGroup(
      "Auth",
      [authScp03Btn, authScp02Btn, logoutBtn, keysBtn]
    );

    // Registry
    var regAppsBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.apps, label: "Apps", title: "GET STATUS P1=40 — installed applications" },
      function () { scp03ShowRegistry(tab, "scp03.registry_apps", "GP registry — APPS"); }
    );
    var regPkgsBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.packages, label: "Packages", title: "GET STATUS P1=20 — loaded packages" },
      function () { scp03ShowRegistry(tab, "scp03.registry_pkgs", "GP registry — PACKAGES"); }
    );
    var regSdBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.securityDomains, label: "Sec. domains", title: "GET STATUS P1=80 — security domains" },
      function () { scp03ShowRegistry(tab, "scp03.registry_sd", "GP registry — SD"); }
    );
    var getDataBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.getData, label: "GET DATA…", title: "80CA P1 P2 00 — fetch arbitrary DO by tag" },
      function () { scp03ShowGetData(tab); }
    );
    var aidsBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.aidRegistry, label: "AIDs", title: "Dump the workspace AID alias registry" },
      function () { scp03ShowAidRegistry(tab); }
    );
    var registryGroup = scp03MakeRibbonGroup(
      "Registry",
      [regAppsBtn, regPkgsBtn, regSdBtn, getDataBtn, aidsBtn]
    );

    // Profiles
    var listProfilesBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.profiles, label: "Profiles", title: "ES10c GetProfilesInfo — structured list" },
      function () { scp03ShowListProfiles(tab); }
    );
    var profileScanBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.euiccScan, label: "eUICC scan", title: "SGP.22/SGP.32 bundle scan (EID + info + profiles)" },
      function () { scp03ShowProfileScan(tab); }
    );
    var profileGroup = scp03MakeRibbonGroup(
      "Profiles",
      [listProfilesBtn, profileScanBtn]
    );

    // Mutation (destructive) — every button in this group is gated
    // by ``scp03GateOpen`` so the auth prompt fires before the
    // inline form even renders. The inline forms can still be
    // opened offline (session_id might be null when reloaded) —
    // the gate re-authenticates against the correct AID on the fly.
    var setStatusBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.setStatus, label: "Set status", title: "GP SET STATUS (lifecycle byte)" },
      scp03GateOpen(tab, "scp03.set_status", function () { scp03ShowSetStatus(tab); })
    );
    var lockBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.lock, label: "Lock", title: "SET STATUS → LOCKED (0x80)", danger: true },
      scp03GateOpen(tab, "scp03.lock", function () {
        scp03ShowLockUnlock(tab, "scp03.lock", "Lock (LCS=80)", "LOCK");
      })
    );
    var unlockBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.unlock, label: "Unlock", title: "SET STATUS → SELECTABLE (0x07)" },
      scp03GateOpen(tab, "scp03.unlock", function () {
        scp03ShowLockUnlock(tab, "scp03.unlock", "Unlock (LCS=07)", "UNLOCK");
      })
    );
    var deleteBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.deleteApp, label: "Delete", title: "GP DELETE an application / package", danger: true },
      scp03GateOpen(tab, "scp03.delete", function () { scp03ShowDelete(tab); })
    );
    var storeDataBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.storeData, label: "STORE DATA…", title: "GP STORE DATA (auto-chunk supported)" },
      scp03GateOpen(tab, "scp03.store_data", function () { scp03ShowStoreData(tab); })
    );
    var updateBinBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.updateBinary, label: "UPDATE BIN", title: "UPDATE BINARY on current or named EF" },
      scp03GateOpen(tab, "scp03.update_binary", function () { scp03ShowUpdateBinary(tab); })
    );
    var updateRecBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.updateRecord, label: "UPDATE REC", title: "UPDATE RECORD on current or named linear EF" },
      scp03GateOpen(tab, "scp03.update_record", function () { scp03ShowUpdateRecord(tab); })
    );
    var mutateGroup = scp03MakeRibbonGroup(
      "Mutate",
      [setStatusBtn, lockBtn, unlockBtn, deleteBtn, storeDataBtn, updateBinBtn, updateRecBtn]
    );

    // Validation
    var validateBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.validate, label: "Validate", title: "Run ProfileValidator on the live card" },
      function () { scp03ShowValidate(tab); }
    );
    var certInfoBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.certInfo, label: "Cert info", title: "Decode ECASD / card certificates" },
      function () { scp03ShowCertInfo(tab); }
    );
    var validateGroup = scp03MakeRibbonGroup(
      "Validate",
      [validateBtn, certInfoBtn]
    );

    // Export
    var exportEuiccBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.exportYaml, label: "eUICC YAML", title: "Export eUICC report to YAML" },
      function () { scp03ShowExportEuicc(tab); }
    );
    var exportKeybagBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.exportKeybag, label: "Keybag", title: "Export active SCP03 keys as HIL keybag JSON" },
      scp03GateOpen(tab, "scp03.export_keybag", function () { scp03ShowExportKeybag(tab); })
    );
    var exportGroup = scp03MakeRibbonGroup(
      "Export",
      [exportEuiccBtn, exportKeybagBtn]
    );

    // eUICC telemetry (C-4)
    var eidBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.eid, label: "EID", title: "ES10c.GetEID \u2014 compact EID read" },
      function () { scp03ShowGetEid(tab); }
    );
    var euiccCertsBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.euiccCerts, label: "eUICC certs", title: "ES10b.GetCerts \u2014 ECASD / card cert chain" },
      function () { scp03ShowEuiccCerts(tab); }
    );
    var euiccConfigBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.configData, label: "Config data", title: "ES10a.GetEuiccConfiguredData (BF3C00)" },
      function () { scp03ShowEuiccConfiguredData(tab); }
    );
    var sgp32BulkBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.sgp32Bulk, label: "SGP.32 bulk", title: "Consolidated SGP.32 telemetry (scan + RAT + notifications + eIM cfg + certs)" },
      function () { scp03ShowSgp32AllData(tab); }
    );
    var enableProfileBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.enableProfile, label: "Enable", title: "ES10c.EnableProfile" },
      scp03GateOpen(tab, "scp03.enable_profile", function () { scp03ShowLifecycle(tab, "enable"); })
    );
    var disableProfileBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.disableProfile, label: "Disable", title: "ES10c.DisableProfile" },
      scp03GateOpen(tab, "scp03.disable_profile", function () { scp03ShowLifecycle(tab, "disable"); })
    );
    var deleteProfileBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.deleteProfile, label: "Delete profile", title: "ES10c.DeleteProfile \u2014 irreversible", danger: true },
      scp03GateOpen(tab, "scp03.delete_profile", function () { scp03ShowLifecycle(tab, "delete"); })
    );
    var euiccGroup = scp03MakeRibbonGroup(
      "eUICC",
      [eidBtn, euiccCertsBtn, euiccConfigBtn, sgp32BulkBtn, enableProfileBtn, disableProfileBtn, deleteProfileBtn]
    );

    // Snapshots / gold profile (C-4)
    var setGoldBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.setGold, label: "Set gold", title: "Persist a gold-profile YAML baseline" },
      function () { scp03ShowSetGoldProfile(tab); }
    );
    var showGoldBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.showGold, label: "Show gold", title: "Inspect the persisted gold-profile settings" },
      function () { scp03ShowShowGoldProfile(tab); }
    );
    var clearGoldBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.clearGold, label: "Clear gold", title: "Clear the gold-profile path (keeps standard + auth flag)" },
      function () { scp03ShowClearGoldProfile(tab); }
    );
    var profileDiffBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.diff, label: "Diff", title: "Diff live card eUICC report against the gold YAML" },
      function () { scp03ShowProfileDiff(tab); }
    );
    var snapshotGroup = scp03MakeRibbonGroup(
      "Snapshots",
      [setGoldBtn, showGoldBtn, clearGoldBtn, profileDiffBtn]
    );

    // Crypto (C-4, offline — no card session)
    var deriveOpcBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.deriveOpc, label: "Derive OPc", title: "3GPP TS 35.206 Milenage OPc derivation" },
      function () { scp03ShowDeriveOpc(tab); }
    );
    var authVectorBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.authVector, label: "Auth vector", title: "Run the 3GPP TS 35.207 Milenage offline test vector" },
      function () { scp03ShowAuthTestVector(tab); }
    );
    var cryptoGroup = scp03MakeRibbonGroup(
      "Crypto",
      [deriveOpcBtn, authVectorBtn]
    );

    // Config (C-4 Tier-3, offline)
    var showConfigBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.showConfig, label: "Show config", title: "Inspect persisted KEYS + GOLD_PROFILE + AID registry" },
      function () { scp03ShowShowConfig(tab); }
    );
    var aidAliasBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.aidAlias, label: "AID alias", title: "Add / update / remove an AID alias in aid.txt" },
      function () { scp03ShowSetAidAlias(tab); }
    );
    var setDefaultsBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.resetKeys, label: "Reset keys", title: "Reset KEYS to the shipped demo defaults", danger: true },
      function () { scp03ShowSetDefaults(tab); }
    );
    var configGroup = scp03MakeRibbonGroup(
      "Config",
      [showConfigBtn, aidAliasBtn, setDefaultsBtn]
    );

    // Install (C-5, GP mutation — destructive). Every INSTALL [for …]
    // variant and PUT KEY cross the SCP secure-messaging envelope, so
    // an authenticated session is non-negotiable. The gate short-
    // circuits the form opening until AUTH resolves; without it the
    // operator would otherwise get to fill in a keyset or CAP path
    // only for the first APDU to bounce with 69 82.
    var putKeyBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.putKey, label: "PUT KEY", title: "GP PUT KEY (install / replace a keyset)", danger: true },
      scp03GateOpen(tab, "scp03.put_key", function () { scp03ShowPutKey(tab); })
    );
    var installCapBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.installCap, label: "Install CAP", title: "INSTALL [for load] + LOAD + INSTALL [for install]" },
      scp03GateOpen(tab, "scp03.install_cap", function () { scp03ShowInstallCap(tab); })
    );
    var installAppBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.installApp, label: "Install app", title: "INSTALL [for install] on an already-loaded package" },
      scp03GateOpen(tab, "scp03.install_app", function () { scp03ShowInstallApp(tab); })
    );
    var installMakeSelBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.makeSelectable, label: "Make selectable", title: "INSTALL [for make selectable]" },
      scp03GateOpen(tab, "scp03.install_make_selectable",
        function () { scp03ShowInstallMakeSelectable(tab); })
    );
    var installExtraditionBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.extradition, label: "Extradition", title: "INSTALL [for extradition] — re-bind instance to target SD" },
      scp03GateOpen(tab, "scp03.install_extradition",
        function () { scp03ShowInstallExtradition(tab); })
    );
    var installPersoBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.perso, label: "Perso", title: "INSTALL [for personalization] — open perso channel" },
      scp03GateOpen(tab, "scp03.install_personalization",
        function () { scp03ShowInstallPersonalization(tab); })
    );
    var installRegBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.registryUpdate, label: "Reg. update", title: "INSTALL [for registry update] — change privileges / params" },
      scp03GateOpen(tab, "scp03.install_registry_update",
        function () { scp03ShowInstallRegistryUpdate(tab); })
    );
    var installGroup = scp03MakeRibbonGroup(
      "Install",
      [putKeyBtn, installCapBtn, installAppBtn, installMakeSelBtn,
       installExtraditionBtn, installPersoBtn, installRegBtn]
    );

    // NOTE: The legacy FS-Admin ribbon group (CREATE / DELETE / RESIZE /
    // Lifecycle / SEARCH RECORD / SUSPEND) was relocated in 2026-04-23 to
    // the contextual action bar rendered by ``scp03BuildFsActionBar`` —
    // the strip sits next to the ``fid:`` badge in the FCP preview and
    // gates each action by the currently-selected file kind (DF / ADF
    // / EF-transparent / EF-linear / EF-cyclic). The button handlers
    // still hop into the same ``scp03ShowFs*(tab)`` wizards; only the
    // entry point moved. If you need a global (no selection) entry
    // point back, wire it in via the Admin ribbon tab — not Files —
    // since the Files tab itself was retired as part of this change.

    // Live AAA (C-5, PIN / Channel / AUTHENTICATE)
    var managePinBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.pin, label: "PIN", title: "VERIFY / CHANGE / DISABLE / ENABLE / UNBLOCK PIN" },
      function () { scp03ShowManagePin(tab); }
    );
    var manageChannelBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.channel, label: "Channel", title: "MANAGE CHANNEL (0070) — open / close logical channel" },
      function () { scp03ShowManageChannel(tab); }
    );
    var runAuthLiveBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.runAuth, label: "Run AUTH", title: "Live AUTHENTICATE (USIM / ISIM / GSM) with RAND/AUTN" },
      function () { scp03ShowRunAuthLive(tab); }
    );
    var liveAAAGroup = scp03MakeRibbonGroup(
      "Live AAA",
      [managePinBtn, manageChannelBtn, runAuthLiveBtn]
    );

    // Sub-shells (C-6, PTY handoff)
    var stkShellBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.stkShell, label: "STK shell",
        title: "Launch SCP03 \u2192 STK-SHELL sub-REPL in the Terminal view" },
      function () { scp03ShowOpenStkShell(tab); }
    );
    var otaShellBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.otaShell, label: "OTA shell",
        title: "Launch python -m SCP80 (SCP80 / OTA REPL) in the Terminal view" },
      function () { scp03ShowOpenOtaShell(tab); }
    );
    var subShellGroup = scp03MakeRibbonGroup(
      "Sub-shells",
      [stkShellBtn, otaShellBtn]
    );

    // Scripts & reports (C-7)
    var runScriptBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.runScript, label: "Run script",
        title: "Feed a file or inline command list to entry_cmd" },
      function () { scp03ShowRunScript(tab); }
    );
    var fsReportBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.fsReport, label: "FS report",
        title: "Deep scan \u2192 YAML report via FileSystemController.generate_report" },
      function () { scp03ShowFsReport(tab); }
    );
    var guideBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.guides, label: "Guides",
        title: "Rendered ShellGuides topics (GP, ETSI, GSMA, \u2026)" },
      function () { scp03ShowGuide(tab); }
    );
    var scriptsGroup = scp03MakeRibbonGroup(
      "Scripts",
      [runScriptBtn, fsReportBtn, guideBtn]
    );

    // Session
    var closeBtn = scp03MakeRibbonButton(
      { icon: SCP03_ICONS.close, label: "Close", title: "Close this SCP03 session", danger: true },
      function () { scp03CloseTab(tab.id, tabBar, tabBody); }
    );
    var sessionGroup = scp03MakeRibbonGroup("Session", [closeBtn]);

    // Group the 19 legacy ribbon-groups into 9 primary ribbon tabs.
    // Ordering mirrors the typical SCP03 workflow: navigate a card,
    // inspect its state, authenticate, walk the GP registry, mutate
    // life-cycle, install applets, admin the FS, drive raw APDUs, and
    // finally admin the session.
    //
    // Tabs with ``panel: fn`` render a dedicated workbench panel
    // (full-width form + output) in place of the group strip — used
    // by the APDU console. Tabs with ``groups: [...]`` render the
    // classic icon-button strip.
    var allRibbonTabs = [
      { id: "home",     label: "Home",       groups: [navGroup, inspectGroup] },
      { id: "inspect",  label: "Diagnostics", groups: [diagGroup, validateGroup] },
      { id: "auth",     label: "Auth",       groups: [authGroup, liveAAAGroup] },
      { id: "registry", label: "Registry",   groups: [registryGroup, mutateGroup] },
      { id: "install",  label: "Install",    groups: [installGroup] },
      // The former "Files" ribbon tab (fsAdminGroup) was retired in
      // favour of the contextual action bar in the FCP preview — see
      // ``scp03BuildFsActionBar``. Operators now pick a file in the
      // scan tree and hit the exact action that's legal for that node.
      { id: "euicc",    label: "eUICC",      groups: [profileGroup, euiccGroup, snapshotGroup, exportGroup] },
      { id: "apdu",     label: "APDU",       panel: scp03BuildApduPanel },
      { id: "admin",    label: "Admin",      groups: [cryptoGroup, configGroup, subShellGroup, scriptsGroup, sessionGroup] },
    ];

    // Scope-filtered ribbon tabs. Filesystem view drops everything
    // GP-related so the surface matches the sidebar label; Applications
    // view drops the FS-centric tabs. APDU and Admin live in both
    // because they're useful regardless of surface. "all" leaves the
    // full classic ribbon in place.
    var scope = (commandState.scp03Workbench && commandState.scp03Workbench.scope) || "all";
    var ribbonTabs;
    if (scope === "filesystem") {
      ribbonTabs = allRibbonTabs.filter(function (t) {
        return ["home", "inspect", "apdu", "admin"].indexOf(t.id) !== -1;
      });
    } else if (scope === "applications") {
      ribbonTabs = allRibbonTabs.filter(function (t) {
        return ["auth", "registry", "install", "euicc", "apdu", "admin"].indexOf(t.id) !== -1;
      });
    } else {
      ribbonTabs = allRibbonTabs;
    }

    var activeId = tab.activeRibbonTab || "home";
    if (!ribbonTabs.some(function (t) { return t.id === activeId; })) {
      // Default primary tab per scope: Home for filesystem, Auth for
      // applications — both match what the operator most likely wants
      // to do first.
      activeId = scope === "applications" ? "auth" : "home";
      tab.activeRibbonTab = activeId;
    }

    var strip = document.createElement("div");
    strip.className = "scp03-ribbon-tabstrip";
    strip.setAttribute("role", "tablist");
    ribbonTabs.forEach(function (ribTab) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "scp03-ribbon-tabbtn" + (ribTab.id === activeId ? " active" : "");
      btn.textContent = ribTab.label;
      btn.setAttribute("role", "tab");
      btn.setAttribute("aria-selected", String(ribTab.id === activeId));
      btn.addEventListener("click", function () {
        tab.activeRibbonTab = ribTab.id;
        scp03RepaintRibbon(tab, tabBar, tabBody);
        // Persist the ribbon selection so a reload restores the same
        // tab (Home / Files / APDU / Admin …). Cheap — only the one
        // field changed; the rest of the payload is unchanged.
        try { scp03PersistTab(tab); } catch (_err) {}
      });
      strip.appendChild(btn);
    });
    ribbon.appendChild(strip);

    var section = document.createElement("div");
    section.className = "scp03-ribbon-section";
    section.setAttribute("role", "tabpanel");
    var activeTab = ribbonTabs.find(function (t) { return t.id === activeId; });
    if (activeTab && typeof activeTab.panel === "function") {
      // Custom workbench panel (e.g. the APDU console) — render it
      // in place of the group strip. The panel function owns its own
      // layout, styling, and lifecycle (form state lives on ``tab``).
      section.classList.add("scp03-ribbon-section--panel");
      var panelEl = activeTab.panel(tab, tabBar, tabBody);
      if (panelEl) section.appendChild(panelEl);
    } else if (activeTab && Array.isArray(activeTab.groups)) {
      activeTab.groups.forEach(function (g) {
        section.appendChild(g);
      });
    }
    ribbon.appendChild(section);
    return ribbon;
  }

  function scp03RepaintRibbon(tab, tabBar, tabBody) {
    // Rebuild just the ribbon in place so switching the primary
    // ribbon tab does NOT wipe the scan tree / selection / extras.
    //
    // The defensive try/catch guards against stale DOM: if the old
    // ribbon node was orphaned (e.g. the tab body rerendered between
    // when the click handler captured ``oldRibbon`` and when the
    // promise microtask fires), the ``replaceChild`` throws
    // ``HierarchyRequestError``. Fall back to a full tab-body
    // rerender in that case — correctness first, visual continuity
    // second.
    var oldRibbon = document.querySelector(".scp03-session-main .scp03-ribbon-v2");
    if (!oldRibbon || !oldRibbon.parentNode) {
      renderScp03Tabs(tabBar, tabBody);
      return;
    }
    var fresh = scp03BuildRibbon(tab, tabBar, tabBody);
    try {
      oldRibbon.parentNode.replaceChild(fresh, oldRibbon);
    } catch (_err) {
      renderScp03Tabs(tabBar, tabBody);
    }
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
      // scp03.select's ActionSpec takes ``path`` (not ``identifier``).
      // Bare hex strings (FIDs, AIDs) pass through _normalise_fs_path()
      // unchanged, so the prompt works for both short FIDs like "7FFF"
      // and full AIDs like "A0000000871002FFFFFFFF8907090000".
      var resp = await apiFetch("/api/actions/scp03.select/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: { session_id: tab.sessionId, path: trimmed },
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
      var fcpHex = "";
      if (data.fcp && typeof data.fcp === "object") {
        fcpHex = String(data.fcp.template_hex || data.fcp.hex || "");
      }
      logBus.emit({
        level: "info",
        source: "scp03.select",
        message: "SELECT ok — selected=" + (data.selected ? "yes" : "no")
          + " fid=" + (data.fid || "?")
          + (fcpHex ? " fcp=" + fcpHex.substring(0, 32) + "…" : ""),
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
    // Read scope from the workbench — scope is set by
    // ``renderScp03Workbench`` before this panel is built. Apps and
    // Filesystem each drop half of the visual surface to reduce
    // cognitive load; "all" keeps the classic layout for direct
    // callers (reader-bar auto-route, persisted state hydration).
    var scope = (commandState.scp03Workbench && commandState.scp03Workbench.scope) || "all";

    var wrap = document.createElement("div");
    wrap.className = "cc-wb-session cc-wb-session--scope-" + scope;
    wrap.setAttribute("data-scp03-scope", scope);
    installMaximizable(wrap);

    // Header chips are minimal now that the reader binding lives in the
    // sidebar and the session-tab strip. We keep ATR + session id since
    // they're the first things an engineer wants to cite in a bug report,
    // plus an auth-state chip so the gating is observable without
    // reaching for the ribbon (green when authenticated, otherwise a
    // neutral "not authenticated" pill that flips on the next AUTH).
    // The scope chip makes it obvious which surface the operator is
    // looking at — it's easy to miss that the ribbon filtered when
    // switching between Filesystem and Applications.
    var header = document.createElement("div");
    header.className = "cc-scan-header";
    var authStat = tab.authStatus || {};
    var authChipClass = authStat.authenticated ? "cc-chip cc-chip-ok" : "cc-chip cc-chip-warn";
    var authChipText = authStat.authenticated
      ? ("auth: " + (authStat.protocol || "SCP03")
          + " / AID=" + (authStat.targetAid || "ISD")
          + " / KVN=" + (authStat.kvn || "??"))
      : "auth: not authenticated";
    var scopeLabel = scope === "filesystem" ? "scope: filesystem"
      : scope === "applications" ? "scope: applications"
      : "scope: all";
    var chipsHtml = ''
      + '<span class="cc-chip cc-chip-scope">' + escapeHtml(scopeLabel) + '</span>'
      + '<span class="cc-chip">atr: ' + escapeHtml(tab.atrHex || "(none)") + '</span>';
    // Card overview chips (auto-fetched after scan)
    if (tab.cardInfo) {
      if (tab.cardInfo.iccid) {
        chipsHtml += '<span class="cc-chip">iccid: <code>' + escapeHtml(tab.cardInfo.iccid) + '</code></span>';
      }
      if (tab.cardInfo.eid) {
        chipsHtml += '<span class="cc-chip cc-chip-ok">eid: <code>' + escapeHtml(tab.cardInfo.eid) + '</code></span>';
      }
      if (tab.cardInfo.standard) {
        chipsHtml += '<span class="cc-chip">' + escapeHtml(tab.cardInfo.standard) + '</span>';
      }
    }
    chipsHtml += '<span class="cc-chip">session: <code>' + escapeHtml(tab.sessionId || "") + '</code></span>'
      + '<span class="' + authChipClass + '">' + escapeHtml(authChipText) + '</span>';
    header.innerHTML = chipsHtml;
    wrap.appendChild(header);

    wrap.appendChild(scp03BuildRibbon(tab, tabBar, tabBody));

    // Applications scope hides the scan tree / FCP preview entirely:
    // everything in that view is driven from the ribbon (GP registry,
    // install, put-key, eUICC, APDU console). The filesystem scope —
    // and the classic "all" scope — keep the tree + breadcrumb +
    // preview intact since the tree is the primary selector.
    var tree = null;
    var preview = null;
    if (scope !== "applications") {
      wrap.appendChild(scp03BuildBreadcrumb(tab, tabBar, tabBody));

      var layout = document.createElement("div");
      layout.className = "cc-scan-layout";
      tree = document.createElement("div");
      tree.className = "cc-tree";
      installMaximizable(tree);
      tree.appendChild(renderTreeNodes(((tab.scanData || {}).tree) || [], {
        tab: tab,
        selectedPath: tab.selectedPath || "",
      }));
      layout.appendChild(tree);
      preview = document.createElement("div");
      preview.className = "cc-scan-preview";
      installMaximizable(preview);
      if (tab.previewCache) {
        renderFcpResult(tab.previewCache, preview, tab);
      } else {
        preview.innerHTML = '<p class="hint">Click a node to SELECT it and read its FCP + body. Record-based files show every record with both hex and decoded views.</p>';
      }
      layout.appendChild(preview);
      wrap.appendChild(layout);
    } else {
      // Applications scope still needs a hint so the main column
      // isn't visually empty before the operator clicks a ribbon
      // action. Pop-outs land above this via the popout-host anyway.
      var hint = document.createElement("div");
      hint.className = "cc-apps-hint";
      hint.innerHTML = ''
        + '<p><strong>Applications view.</strong> The file system tree '
        + 'is hidden here — switch to <em>Card Administration \u203A '
        + 'Filesystem</em> when you need to walk MF/ADF/DF/EF nodes. '
        + 'Ribbon actions (Auth, Registry, Install, eUICC, APDU, '
        + 'Admin) target the same session, so an SCP03 handshake here '
        + 'also unlocks the filesystem view.</p>';
      wrap.appendChild(hint);
    }

    var extras = document.createElement("div");
    extras.className = "cc-wb-extras";
    extras.setAttribute("data-extras", "1");
    wrap.appendChild(extras);

    if (tree && preview) {
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
        // Guarded: if ``wrap`` / the breadcrumb has been orphaned by
        // an intervening tab-body repaint (e.g. auth prompt fired
        // scp03RerenderActiveTabBody mid-click), replaceChild throws
        // HierarchyRequestError. Fall through to a full tab repaint
        // so the tree reflects the new selection regardless.
        var oldCrumb = wrap.querySelector(".cc-breadcrumb");
        if (oldCrumb && oldCrumb.parentNode) {
          var fresh = scp03BuildBreadcrumb(tab, tabBar, tabBody);
          try {
            oldCrumb.parentNode.replaceChild(fresh, oldCrumb);
          } catch (_err) {
            renderScp03Tabs(tabBar, tabBody);
          }
        }
        readSelectedForTab(tab, path, preview);
      });
    }

    return wrap;
  }

  async function scp03Rescan(tab, tabBar, tabBody) {
    // Remember the reader binding, then invalidate every piece of derived
    // state so the repaint below can't reuse stale artefacts. A physical
    // card reset (or any SELECT/auth side-effect from the previous pass)
    // means the cached tree + FCP + records are no longer trustworthy.
    var targetReader = (tab.readerName === "(default)" || !tab.readerName)
      ? ""
      : tab.readerName;
    var previousSession = tab.sessionId;

    tab.status = "scanning";
    tab.error = null;
    tab.scanData = null;
    tab.selectedPath = null;
    tab.previewCache = null;
    tab.fcpCache = {};
    tab.lastRecoverAt = 0;
    tab.sessionId = null;
    commandState.scp03Session = null;
    // Immediate repaint — the user clicked a button, they should see
    // the UI reset instantly instead of the old tree lingering while
    // the backend scan runs. The welcome panel will render briefly.
    renderScp03Tabs(tabBar, tabBody);

    // Best-effort teardown of the previous session so the PC/SC handle
    // is released before we ask the backend to open a fresh one. We
    // ignore failures here — scan() will open a new transporter either
    // way, and we'd rather not block the rescan on this cleanup call.
    if (previousSession) {
      try {
        await apiFetch("/api/actions/scp03.close_session/run", {
          method: "POST",
          body: JSON.stringify({ inputs: { session_id: previousSession } }),
        });
      } catch (_err) {
        // Swallow — stale sessions get GC'd on the backend anyway.
      }
    }

    try {
      var resp = await apiFetch("/api/actions/scp03.scan/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { reader: targetReader } }),
      });
      if (!resp.ok) {
        tab.error = resp.error || "rescan failed";
        tab.status = "idle";
        renderScp03Tabs(tabBar, tabBody);
        // Pill colour may have flipped (session creation failed) — repaint.
        if (typeof readerBarNotifySessionChanged === "function") {
          readerBarNotifySessionChanged();
        }
        return;
      }
      var data = resp.data || {};
      tab.sessionId = data.session_id || null;
      tab.readerName = data.reader_name || tab.readerName;
      tab.atrHex = data.atr_hex || tab.atrHex;
      tab.scanData = data;
      tab.status = "open";
      commandState.scp03Session = tab.sessionId;
      // Persist the fresh scan tree keyed by reader so a reload lands
      // back on the same tree (sessionId is deliberately not saved —
      // see scp03PersistTab). Also wipes any stale fcpCache from the
      // previous session because the scan just cleared them upstream.
      scp03PersistTab(tab);
      // Align the top-bar reader pill with the freshly opened session:
      // promote this reader to active so the green dot lights up on
      // the correct pill. scp03.scan normalises the reader name (empty
      // "(default)" ↔ first reader) so we trust the backend's echo.
      if (tab.readerName
        && typeof readerBarNotifySessionChanged === "function") {
        readerBarSetActiveReaderOnly(tab.readerName);
      }
    } catch (err) {
      tab.error = String(err && err.message || err);
      tab.status = "idle";
    }
    renderScp03Tabs(tabBar, tabBody);
    if (typeof readerBarNotifySessionChanged === "function") {
      readerBarNotifySessionChanged();
    }
  }

  async function scp03ListApps(tab) {
    // ``scp03BuildExtrasCard`` now hands us a popout body — we can
    // stamp a loading placeholder straight onto it and replace the
    // contents when the network round-trip returns, mirroring every
    // other C-1 action dispatcher.
    var card = scp03BuildExtrasCard("EF.DIR applications");
    if (!card) return;
    card.innerHTML = '<p class="loading">listing EF.DIR applications…</p>';
    try {
      var resp = await apiFetch("/api/actions/scp03.list_apps/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      card.innerHTML = "";
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
    } catch (err) {
      card.innerHTML = "";
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  // -- C-1 helpers: floating popout windows ------------------------------
  //
  // Every SCP03 action used to render its result inline inside the
  // ``.cc-wb-extras`` strip below the tree/preview layout. On a busy
  // session the strip grew into a vertically-stacked tower that hid
  // the tree and pushed the fold down screen-fulls. Operator feedback:
  // "can we make these action buttons spawn in a pop-out window
  // instead?" — so ``scp03BuildExtrasCard`` now creates a **floating,
  // draggable, resizable window** positioned over the workbench
  // (``position: fixed`` at the document level, z-stacked) while the
  // tree + preview stay in the operator's viewport untouched. Windows
  // are scoped to the tab that spawned them (hidden when a sibling
  // tab is active, destroyed on tab close) and keyed by title so
  // clicking the same action twice brings the existing window
  // forward instead of duplicating it.
  //
  // Contract preserved at the 60+ call sites:
  //   var card = scp03BuildExtrasCard("Title");
  //   card.appendChild(someSection);
  //
  // ``card`` now refers to the popout **body** (the scrollable area
  // beneath the titlebar) — same mental model as before, operators
  // just see it floating instead of stacked inline.

  var SCP03_POPOUT_Z_BASE = 7500;
  var _CC_COMPACT_POPOUT_Z = 8000;
  var _ccCompactPopoutMap = {};

  // ------------------------------------------------------------------
  // Generic result popout (compact workbench — eSIM Management / Tools / …)
  // ------------------------------------------------------------------
  // Mirrors ``scp03BuildExtrasCard`` but does not depend on SCP03
  // tabs. Each popout is a ``position: fixed`` card with titlebar,
  // drag, maximize, and close — the same visual contract that SCP03
  // Applications uses for action results.
  //
  // Deduplication: re-running the same action reuses the existing
  // popout (brings it to front + clears the body), matching SCP03's
  // ``scp03BuildExtrasCard`` dedup-by-title behaviour.

  function _ccBuildCompactPopout(title) {
    var safeTitle = String(title || "Result");

    // --- deduplication -----------------------------------------------
    var existing = _ccCompactPopoutMap[safeTitle];
    if (existing && existing.parentNode) {
      _CC_COMPACT_POPOUT_Z += 1;
      existing.style.zIndex = String(_CC_COMPACT_POPOUT_Z);
      existing.classList.add("is-focused");
      var reuseBody = existing.querySelector(".cc-popout-body");
      if (reuseBody) reuseBody.innerHTML = "";
      return reuseBody || existing;
    }

    // --- sizing (matches scp03PopoutDefaultSize) --------------------
    var popSz = scp03PopoutDefaultSize();
    var vw = window.innerWidth;
    var vh = window.innerHeight;

    var popout = document.createElement("div");
    popout.className = "cc-popout card";
    popout.setAttribute("role", "dialog");
    popout.setAttribute("aria-label", safeTitle);
    popout.style.position = "fixed";
    popout.style.width = popSz.width + "px";
    popout.style.height = popSz.height + "px";

    // Cascade: offset each successive popout so overlapping windows
    // stay discoverable.
    _CC_COMPACT_POPOUT_Z += 1;
    var cascade = (_CC_COMPACT_POPOUT_Z - 8000) * 26;
    var left = Math.max(140, Math.round(vw * 0.18) + cascade);
    var top = Math.max(100, Math.round(vh * 0.18) + cascade);
    if (left + popSz.width > vw - 40 || top + popSz.height > vh - 40) {
      left = Math.max(140, Math.round(vw * 0.18));
      top = Math.max(100, Math.round(vh * 0.18));
    }
    popout.style.left = left + "px";
    popout.style.top = top + "px";
    popout.style.zIndex = String(_CC_COMPACT_POPOUT_Z);

    // --- titlebar ----------------------------------------------------
    var titlebar = document.createElement("div");
    titlebar.className = "cc-popout-titlebar";
    var titleEl = document.createElement("span");
    titleEl.className = "cc-popout-title";
    titleEl.textContent = safeTitle;
    titlebar.appendChild(titleEl);

    var actions = document.createElement("div");
    actions.className = "cc-popout-actions";

    var maxBtn = document.createElement("button");
    maxBtn.type = "button";
    maxBtn.className = "cc-popout-btn cc-popout-max";
    maxBtn.title = "Toggle maximize";
    maxBtn.setAttribute("aria-label", "Toggle maximize");
    maxBtn.textContent = "⛶";
    maxBtn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      scp03PopoutToggleMaximize(popout);
    });
    actions.appendChild(maxBtn);

    var closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "cc-popout-btn cc-popout-close";
    closeBtn.title = "Close";
    closeBtn.setAttribute("aria-label", "Close");
    closeBtn.textContent = "×";
    closeBtn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      delete _ccCompactPopoutMap[safeTitle];
      if (popout.parentNode) popout.parentNode.removeChild(popout);
    });
    actions.appendChild(closeBtn);

    titlebar.appendChild(actions);
    popout.appendChild(titlebar);

    // Double-click titlebar = maximize/restore
    titlebar.addEventListener("dblclick", function (ev) {
      if (ev.target && ev.target.closest && ev.target.closest(".cc-popout-btn")) return;
      ev.preventDefault();
      scp03PopoutToggleMaximize(popout);
    });

    // Pointerdown anywhere in popout → bring to front
    popout.addEventListener("pointerdown", function () {
      _CC_COMPACT_POPOUT_Z += 1;
      popout.style.zIndex = String(_CC_COMPACT_POPOUT_Z);
      popout.classList.add("is-focused");
    });

    scp03PopoutInstallDrag(popout, titlebar);

    var body = document.createElement("div");
    body.className = "cc-popout-body";
    popout.appendChild(body);

    scp03PopoutHost().appendChild(popout);
    _ccCompactPopoutMap[safeTitle] = popout;
    return body;
  }

  function scp03PopoutIsVisible(popout) {
    if (!popout || !popout.parentNode || popout.hidden) return false;
    var style = window.getComputedStyle
      ? window.getComputedStyle(popout)
      : null;
    if (style && (style.display === "none" || style.visibility === "hidden")) {
      return false;
    }
    return true;
  }

  function scp03PopoutTopmostVisible() {
    var popouts = Array.prototype.slice.call(
      document.querySelectorAll(".cc-popout")
    );
    var topmost = null;
    var topZ = -Infinity;
    popouts.forEach(function (popout, idx) {
      if (!scp03PopoutIsVisible(popout)) return;
      var z = parseInt(popout.style.zIndex || "", 10);
      if (isNaN(z)) z = 0;
      if (!topmost || z > topZ || (z === topZ && idx > topmost.idx)) {
        topmost = { el: popout, idx: idx };
        topZ = z;
      }
    });
    return topmost ? topmost.el : null;
  }

  function scp03PopoutCloseElement(popout) {
    if (!popout) return false;
    var closeBtn = popout.querySelector(".cc-popout-close");
    if (closeBtn) {
      closeBtn.dispatchEvent(new MouseEvent("click", {
        bubbles: true,
        cancelable: true,
      }));
      return true;
    }
    if (popout.parentNode) {
      popout.parentNode.removeChild(popout);
      return true;
    }
    return false;
  }

  function scp03PopoutCloseTopmostVisible() {
    var popout = scp03PopoutTopmostVisible();
    if (!popout) return false;
    return scp03PopoutCloseElement(popout);
  }

  function scp03PopoutEscapeBootstrap() {
    if (commandState._popoutEscapeBound) return;
    commandState._popoutEscapeBound = true;
    document.addEventListener("keydown", function (ev) {
      if (ev.key !== "Escape") return;
      if (scp03PopoutCloseTopmostVisible()) {
        ev.preventDefault();
        ev.stopPropagation();
      }
    }, true);
  }

  // Default popout size tracks the viewport so first open is large enough
  // to read tables and traces without immediate maximize / resize.
  var SCP03_POPOUT_CASCADE_STEP = 28;
  var SCP03_POPOUT_MIN_WIDTH = 320;
  var SCP03_POPOUT_MIN_HEIGHT = 200;

  function scp03PopoutDefaultSize() {
    var vw = window.innerWidth;
    var vh = window.innerHeight;
    var marginX = 44;
    var marginY = 52;
    var w = Math.round(vw * 0.56);
    var h = Math.round(vh * 0.64);
    w = Math.min(Math.max(w, 780), Math.max(SCP03_POPOUT_MIN_WIDTH, vw - marginX));
    h = Math.min(Math.max(h, 580), Math.max(SCP03_POPOUT_MIN_HEIGHT, vh - marginY));
    return { width: w, height: h };
  }

  function scp03GetExtrasSlot() {
    return document.querySelector(".cc-wb-body .cc-wb-extras");
  }

  function scp03GetActiveTab() {
    var wb = commandState && commandState.scp03Workbench;
    if (!wb) return null;
    return scp03FindTab(wb.activeTabId);
  }

  function scp03PopoutHost() {
    var host = document.getElementById("cc-popout-host");
    if (host) return host;
    host = document.createElement("div");
    host.id = "cc-popout-host";
    host.className = "cc-popout-host";
    // The host is a 0x0 absolutely-positioned anchor; each popout is
    // itself ``position: fixed`` so the anchor is purely semantic
    // (keeps DOM inspector tidy + gives us a single cleanup target).
    document.body.appendChild(host);
    return host;
  }

  function scp03PopoutNextZ(tab) {
    if (!tab.popoutZCursor || tab.popoutZCursor < SCP03_POPOUT_Z_BASE) {
      tab.popoutZCursor = SCP03_POPOUT_Z_BASE;
    }
    tab.popoutZCursor += 1;
    return tab.popoutZCursor;
  }

  function scp03PopoutComputeOrigin(tab, size) {
    // Viewport-relative cascade. ``position: fixed`` so we anchor off
    // the visual viewport, not the document, which keeps windows
    // visible regardless of scroll position.
    var sz = size || scp03PopoutDefaultSize();
    var base = {
      left: Math.max(160, Math.round(window.innerWidth * 0.18)),
      top: Math.max(120, Math.round(window.innerHeight * 0.18)),
    };
    var cascade = tab.popoutCascadeIdx || 0;
    var left = base.left + cascade * SCP03_POPOUT_CASCADE_STEP;
    var top = base.top + cascade * SCP03_POPOUT_CASCADE_STEP;
    // Reset the cascade once it would push a window off the visible
    // area. Keeps a 40 px safety margin on the right/bottom edges.
    if (left + sz.width > window.innerWidth - 40
        || top + sz.height > window.innerHeight - 40) {
      tab.popoutCascadeIdx = 0;
      left = base.left;
      top = base.top;
    } else {
      tab.popoutCascadeIdx = cascade + 1;
    }
    return { left: left, top: top };
  }

  function scp03PopoutKey(title) {
    return String(title || "popout").trim().toLowerCase();
  }

  function scp03PopoutBringToFront(tab, popout) {
    if (!popout) return;
    popout.style.zIndex = String(scp03PopoutNextZ(tab));
    popout.classList.add("is-focused");
    // Drop the focus ring from sibling popouts on the same tab.
    Object.keys(tab.popouts || {}).forEach(function (k) {
      var other = tab.popouts[k];
      if (other && other !== popout) other.classList.remove("is-focused");
    });
  }

  function scp03PopoutClose(tab, key) {
    if (!tab || !tab.popouts) return;
    var popout = tab.popouts[key];
    if (!popout) return;
    delete tab.popouts[key];
    if (popout.parentNode) {
      popout.parentNode.removeChild(popout);
    }
  }

  function scp03PopoutCloseAllForTab(tab) {
    if (!tab || !tab.popouts) return;
    Object.keys(tab.popouts).forEach(function (k) {
      var popout = tab.popouts[k];
      if (popout && popout.parentNode) {
        popout.parentNode.removeChild(popout);
      }
    });
    tab.popouts = {};
  }

  function scp03PopoutSyncVisibilityToActiveTab() {
    // Hide every popout whose owning tab isn't the active one. Called
    // from ``renderScp03Tabs`` after the DOM swap so the operator sees
    // only the popouts relevant to the tab they're looking at.
    //
    // We also respect the active subsystem: popouts are only relevant
    // while the operator is on the SCP03 surface, so leaving to SAIP /
    // eSIM Management / Tools hides the entire set (the state stays live in
    // ``tab.popouts`` so windows reappear on return).
    var wb = commandState && commandState.scp03Workbench;
    if (!wb || !Array.isArray(wb.tabs)) return;
    var onScp03 = commandState && commandState.activeSubsystem === "SCP03";
    wb.tabs.forEach(function (tab) {
      if (!tab || !tab.popouts) return;
      var isActive = tab.id === wb.activeTabId;
      var shouldShow = onScp03 && isActive;
      Object.keys(tab.popouts).forEach(function (k) {
        var popout = tab.popouts[k];
        if (!popout) return;
        popout.hidden = !shouldShow;
      });
    });
  }

  function scp03PopoutSyncForSubsystem(subsystem) {
    // Thin wrapper so ``openCommandSubsystem`` can flip popout
    // visibility when the operator navigates between subsystems. The
    // underlying logic is identical to the tab-switch path — both end
    // up in ``scp03PopoutSyncVisibilityToActiveTab`` which honours the
    // ``activeSubsystem`` guard.
    scp03PopoutSyncVisibilityToActiveTab();
    if (typeof subsystem === "string" && subsystem.length > 0) {
      // The subsystem argument is intentionally unused beyond the
      // implicit check (``activeSubsystem`` is already updated by the
      // caller). Keeping the parameter in the signature makes the
      // call-site read naturally: ``syncForSubsystem(nextName)``.
    }
  }

  function scp03PopoutInstallDrag(popout, titlebar) {
    // Pointer-based drag. We capture the pointer so drags survive
    // the cursor momentarily leaving the titlebar (cursor speed > poll
    // rate on long drags). ``touch-action: none`` on the titlebar CSS
    // stops the browser from claiming the gesture for scroll.
    var startX = 0, startY = 0, startLeft = 0, startTop = 0;
    var dragging = false;
    function onDown(ev) {
      // Don't start a drag when the user clicks a button in the titlebar.
      var target = ev.target;
      if (target && target.closest && target.closest(".cc-popout-btn")) return;
      if (ev.button !== undefined && ev.button !== 0) return;
      dragging = true;
      try { titlebar.setPointerCapture(ev.pointerId); } catch (_e) {}
      var rect = popout.getBoundingClientRect();
      startX = ev.clientX;
      startY = ev.clientY;
      startLeft = rect.left;
      startTop = rect.top;
      popout.classList.add("is-dragging");
      ev.preventDefault();
    }
    function onMove(ev) {
      if (!dragging) return;
      var dx = ev.clientX - startX;
      var dy = ev.clientY - startY;
      var nextLeft = startLeft + dx;
      var nextTop = startTop + dy;
      // Clamp to viewport so the titlebar can't slip off-screen.
      var maxLeft = window.innerWidth - 80;
      var maxTop = window.innerHeight - 40;
      if (nextLeft < -120) nextLeft = -120;
      if (nextLeft > maxLeft) nextLeft = maxLeft;
      if (nextTop < 0) nextTop = 0;
      if (nextTop > maxTop) nextTop = maxTop;
      popout.style.left = nextLeft + "px";
      popout.style.top = nextTop + "px";
      // Any explicit position cancels a previous maximize state.
      popout.classList.remove("is-maximized");
    }
    function onUp(ev) {
      if (!dragging) return;
      dragging = false;
      try { titlebar.releasePointerCapture(ev.pointerId); } catch (_e) {}
      popout.classList.remove("is-dragging");
    }
    titlebar.addEventListener("pointerdown", onDown);
    titlebar.addEventListener("pointermove", onMove);
    titlebar.addEventListener("pointerup", onUp);
    titlebar.addEventListener("pointercancel", onUp);
  }

  function scp03PopoutToggleMaximize(popout) {
    if (popout.classList.contains("is-maximized")) {
      popout.classList.remove("is-maximized");
      // Restore cached geometry.
      if (popout.__prevGeom) {
        popout.style.left = popout.__prevGeom.left;
        popout.style.top = popout.__prevGeom.top;
        popout.style.width = popout.__prevGeom.width;
        popout.style.height = popout.__prevGeom.height;
      }
      return;
    }
    popout.__prevGeom = {
      left: popout.style.left,
      top: popout.style.top,
      width: popout.style.width,
      height: popout.style.height,
    };
    popout.classList.add("is-maximized");
    // is-maximized CSS owns the actual sizing — we clear inline to
    // let the class win.
    popout.style.left = "";
    popout.style.top = "";
    popout.style.width = "";
    popout.style.height = "";
  }

  function scp03BuildExtrasCard(title) {
    // Back-compat signature: returns the scrollable body element that
    // callers append their content to. The popout shell + titlebar are
    // built around it and tracked on the active tab.
    var tab = scp03GetActiveTab();
    var safeTitle = String(title || "Output");
    var key = scp03PopoutKey(safeTitle);

    // Dedupe: clicking the same action twice brings the existing
    // window forward + clears its body for the new payload (matches
    // the pre-popout behaviour where the extras strip got replaced).
    if (tab && tab.popouts && tab.popouts[key]) {
      var existing = tab.popouts[key];
      var body = existing.querySelector(".cc-popout-body");
      if (body) body.innerHTML = "";
      existing.hidden = false;
      scp03PopoutBringToFront(tab, existing);
      return body;
    }

    var popout = document.createElement("div");
    popout.className = "cc-popout card";
    popout.setAttribute("role", "dialog");
    popout.setAttribute("aria-label", safeTitle);
    popout.setAttribute("data-popout-key", key);
    if (tab) popout.setAttribute("data-tab-id", tab.id);
    popout.style.position = "fixed";
    var popSz = scp03PopoutDefaultSize();
    popout.style.width = popSz.width + "px";
    popout.style.height = popSz.height + "px";

    if (tab) {
      var origin = scp03PopoutComputeOrigin(tab, popSz);
      popout.style.left = origin.left + "px";
      popout.style.top = origin.top + "px";
      popout.style.zIndex = String(scp03PopoutNextZ(tab));
    } else {
      popout.style.left = "200px";
      popout.style.top = "160px";
      popout.style.zIndex = String(SCP03_POPOUT_Z_BASE);
    }

    var titlebar = document.createElement("div");
    titlebar.className = "cc-popout-titlebar";
    var titleEl = document.createElement("span");
    titleEl.className = "cc-popout-title";
    titleEl.textContent = safeTitle;
    titlebar.appendChild(titleEl);

    var actions = document.createElement("div");
    actions.className = "cc-popout-actions";

    var maxBtn = document.createElement("button");
    maxBtn.type = "button";
    maxBtn.className = "cc-popout-btn cc-popout-max";
    maxBtn.title = "Toggle maximize";
    maxBtn.setAttribute("aria-label", "Toggle maximize");
    maxBtn.textContent = "\u26F6"; // ⛶
    maxBtn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      scp03PopoutToggleMaximize(popout);
    });
    actions.appendChild(maxBtn);

    var closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "cc-popout-btn cc-popout-close";
    closeBtn.title = "Close";
    closeBtn.setAttribute("aria-label", "Close");
    closeBtn.textContent = "\u00D7"; // ×
    closeBtn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      if (tab) {
        scp03PopoutClose(tab, key);
      } else if (popout.parentNode) {
        popout.parentNode.removeChild(popout);
      }
    });
    actions.appendChild(closeBtn);

    titlebar.appendChild(actions);
    popout.appendChild(titlebar);

    var body = document.createElement("div");
    body.className = "cc-popout-body";
    popout.appendChild(body);

    // Double-click on titlebar = maximize/restore; mirrors the v1
    // ``installMaximizable`` UX expectation on the action cards.
    titlebar.addEventListener("dblclick", function (ev) {
      var target = ev.target;
      if (target && target.closest && target.closest(".cc-popout-btn")) return;
      ev.preventDefault();
      scp03PopoutToggleMaximize(popout);
    });

    // Any pointerdown inside the popout bumps its z-index so the
    // window the operator is currently working with is always on top.
    popout.addEventListener("pointerdown", function () {
      if (tab) scp03PopoutBringToFront(tab, popout);
    });

    scp03PopoutInstallDrag(popout, titlebar);

    scp03PopoutHost().appendChild(popout);

    if (tab) {
      tab.popouts[key] = popout;
      scp03PopoutBringToFront(tab, popout);
    }

    return body;
  }

  function scp03RenderTextLines(card, lines) {
    // Split a text-line array into three buckets:
    //   • headings   — lines that end with ":" (visual section breaks)
    //   • kv rows    — "Key: value" where the key half is short and ASCII
    //   • remainder  — anything else (hex dumps, wrapped narration, etc.)
    // KV + headings render as structured Key-Value blocks. The raw
    // remainder drops into a collapsed <details> so the card stops
    // looking like a terminal paste.
    var source = (lines || []).filter(function (line) {
      return typeof line === "string" && line.length > 0;
    });
    if (source.length === 0) return;

    var sections = [];
    var currentHeading = null;
    var currentRows = [];
    var remainder = [];

    function flushSection() {
      if (currentHeading || currentRows.length > 0) {
        sections.push({ heading: currentHeading, rows: currentRows });
      }
      currentHeading = null;
      currentRows = [];
    }

    var kvPattern = /^\s*([A-Za-z0-9][A-Za-z0-9 _\-./()#]{1,40})\s*:\s+(.+)$/;
    source.forEach(function (raw) {
      var line = raw.replace(/\s+$/, "");
      if (line.length === 0) {
        flushSection();
        return;
      }
      // Lines that are pure headings (end with ":" and no value after).
      var headingMatch = /^\s*([A-Za-z0-9][A-Za-z0-9 _\-./()#]{0,60}):\s*$/.exec(line);
      if (headingMatch) {
        flushSection();
        currentHeading = headingMatch[1].trim();
        return;
      }
      var kv = kvPattern.exec(line);
      if (kv) {
        currentRows.push({ label: kv[1].trim(), value: kv[2].trim() });
        return;
      }
      // Not KV and not heading → stash as raw remainder.
      remainder.push(line);
    });
    flushSection();

    var producedStructured = false;
    sections.forEach(function (sec) {
      if (sec.heading) {
        var h = document.createElement("div");
        h.className = "cc-kvl-head";
        h.textContent = sec.heading;
        card.appendChild(h);
        producedStructured = true;
      }
      if (sec.rows.length > 0) {
        scp03RenderKeyValueRows(card, sec.rows);
        producedStructured = true;
      }
    });

    if (remainder.length > 0) {
      if (!producedStructured && remainder.length <= 3) {
        // Very short free-form output — show it inline without the
        // fold-out wrapper so one-liners don't feel hidden.
        var note = document.createElement("p");
        note.className = "cc-empty cc-empty-plain";
        note.textContent = remainder.join(" \u00b7 ");
        card.appendChild(note);
      } else {
        var details = document.createElement("details");
        details.className = "cc-trace-block";
        var summary = document.createElement("summary");
        summary.textContent = "Raw output (" + remainder.length
          + " line" + (remainder.length === 1 ? "" : "s") + ")";
        details.appendChild(summary);
        var pre = document.createElement("pre");
        pre.className = "cc-log";
        pre.textContent = remainder.join("\n");
        details.appendChild(pre);
        card.appendChild(details);
      }
    }
  }

  function scp03RenderKeyValueRows(card, rows) {
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
    card.appendChild(wrap);
  }

  function scp03CreateDatasheetRoot() {
    var root = document.createElement("div");
    root.className = "cc-action-datasheet cc-wb-extras-out--stretch";
    return root;
  }

  function scp03DatasheetAppendMetaKvl(root, rows) {
    if (!rows || rows.length === 0) return;
    var meta = document.createElement("div");
    meta.className = "cc-action-datasheet-meta";
    scp03RenderKeyValueRows(meta, rows);
    root.appendChild(meta);
  }

  function scp03DatasheetWrapMain(inner) {
    var wrap = document.createElement("div");
    wrap.className = "cc-action-datasheet-main";
    if (inner) wrap.appendChild(inner);
    return wrap;
  }

  function scp03DatasheetAppendMain(root, inner) {
    if (!inner) return;
    root.appendChild(scp03DatasheetWrapMain(inner));
  }

  function scp03DatasheetAppendEmpty(root, text) {
    var p = document.createElement("p");
    p.className = "cc-empty";
    p.textContent = text;
    scp03DatasheetAppendMain(root, p);
  }

  function scp03DatasheetAppendWarn(root, text) {
    var p = document.createElement("p");
    p.className = "cc-warn";
    p.textContent = text;
    root.appendChild(p);
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
    scp03RenderTrace(main, trace);
    root.appendChild(main);
  }

  function scp03DatasheetAppendJsonBlock(root, obj, titleOpt) {
    if (!obj || typeof obj !== "object") return;
    if (Object.keys(obj).length === 0) return;
    var main = document.createElement("div");
    main.className = "cc-action-datasheet-main";
    if (titleOpt) {
      var headEl = document.createElement("div");
      headEl.className = "cc-action-datasheet-main-head";
      headEl.textContent = titleOpt;
      main.appendChild(headEl);
    }
    var pre = document.createElement("pre");
    pre.className = "cc-json";
    pre.textContent = JSON.stringify(obj, null, 2);
    main.appendChild(pre);
    root.appendChild(main);
  }

  async function scp03ShowAtr(tab) {
    var card = scp03BuildExtrasCard("ATR details");
    if (!card) return;
    card.appendChild(loadingEl("reading ATR…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.atr/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "ATR failed"));
        return;
      }
      var data = resp.data || {};
      scp03RenderKeyValueRows(card, [
        { label: "ATR (hex)", value: data.atr_hex || "(none)" },
        { label: "Bytes", value: data.atr_length || 0 },
      ]);
      scp03RenderTextLines(card, data.lines || []);
      logBus.emit({ level: "info", source: "scp03.atr", message: "ATR: " + (data.atr_hex || "(none)") });
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03ShowCardInfo(tab) {
    var card = scp03BuildExtrasCard("Card info");
    if (!card) return;
    card.appendChild(loadingEl("probing card…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.card_info/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "card_info failed"));
        return;
      }
      var data = resp.data || {};
      scp03RenderKeyValueRows(card, [
        { label: "Reset", value: data.reset_ok ? "ok" : "failed" },
        { label: "ATR", value: data.atr_hex || "(none)" },
        { label: "ICCID", value: data.iccid || "(unreadable)" },
        { label: "EID", value: data.eid || "(none)" },
        { label: "Standard", value: data.standard || "Unknown" },
      ]);
      logBus.emit({
        level: "info",
        source: "scp03.card_info",
        message: (data.standard || "Unknown") + " ICCID=" + (data.iccid || "?") + " EID=" + (data.eid || "?"),
      });
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03Reset(tab, tabBar, tabBody) {
    var card = scp03BuildExtrasCard("Reset card");
    if (!card) return;
    card.appendChild(loadingEl("resetting…"));
    var resetOk = false;
    var data = {};
    try {
      var resp = await apiFetch("/api/actions/scp03.reset/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "reset failed"));
        return;
      }
      data = resp.data || {};
      resetOk = !!data.ok;
      scp03RenderKeyValueRows(card, [
        { label: "Result", value: resetOk ? "ok" : "failed" },
        { label: "ATR before", value: data.atr_before_hex || "(none)" },
        { label: "ATR after", value: data.atr_after_hex || "(none)" },
        { label: "ATR changed", value: data.atr_changed ? "yes" : "no" },
      ]);
      logBus.emit({
        level: resetOk ? "info" : "warn",
        source: "scp03.reset",
        message: resetOk ? "card reset ok" : "card reset failed",
      });
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
      return;
    }

    // After a physical card reset, every piece of session-bound state on
    // this tab (tree, FCP preview, secure-channel context) is stale. If
    // the caller passed the tab-bar/body refs we chain an automatic
    // rescan so the user doesn't have to click "Rescan" immediately
    // after — the ribbon showed "scanning" briefly and then paints the
    // fresh tree. Without this, the UI silently kept the old tree and
    // any follow-up SELECT would fail against the reset card.
    if (resetOk && tabBar && tabBody) {
      var note = document.createElement("p");
      note.className = "hint";
      note.textContent = "Re-walking file system after reset…";
      card.appendChild(note);
      // Fire-and-forget: scp03Rescan handles its own repaints and error
      // surfacing. Any failure lands on the tab header via tab.error.
      scp03Rescan(tab, tabBar, tabBody);
    }
  }

  // --- SCP03 APDU console (ribbon-v2 tab: "APDU") -----------------------

  // Common APDUs surfaced as one-click presets. Chosen for the first
  // 30 seconds of a card bring-up: identify, navigate, inspect keys /
  // certs, and hop the main security domains. The list is deliberately
  // short — anything more exotic the operator types manually, and the
  // history pane keeps it for re-send. Hex is upper-case because every
  // other surface in this repo normalises to upper on display.
  var SCP03_APDU_PRESETS = [
    { label: "SELECT MF",              apdu: "00A40004023F00" },
    { label: "SELECT EF.ICCID",        apdu: "00A40004022FE2" },
    { label: "SELECT EF.DIR",          apdu: "00A40004022F00" },
    { label: "READ BINARY (entire EF)", apdu: "00B0000000" },
    { label: "GET DATA — EID (5A)",    apdu: "80CA5A00" },
    { label: "GET DATA — IIN (42)",    apdu: "80CA4200" },
    { label: "GET DATA — CIN (45)",    apdu: "80CA4500" },
    { label: "GET DATA — Key Info (E0)", apdu: "80CAE000" },
    { label: "GET DATA — CPLC (9F7F)", apdu: "80CA9F7F00" },
    { label: "GET STATUS — ISDs (F0)", apdu: "80F280020243C0000000" },
    { label: "GET STATUS — Apps (40)", apdu: "80F240020243C0000000" },
    { label: "SELECT ISD-R",           apdu: "00A4040010A0000005591010FFFFFFFF8900000100" },
    { label: "SELECT ECASD",           apdu: "00A4040010A0000005591010FFFFFFFF8900000200" },
  ];

  function scp03NormaliseApduInput(raw) {
    // Operator-friendly cleanup: strip whitespace, ``0x`` prefix, dashes
    // and underscores. Returns upper-case hex + a flag marking obvious
    // malformations so the breakdown panel can tag the field red.
    var text = String(raw == null ? "" : raw).trim();
    var compact = text.replace(/\s+/g, "").replace(/^0[xX]/, "").replace(/[\-_]/g, "");
    var issues = [];
    if (compact.length === 0) {
      issues.push("empty");
    } else if (compact.length % 2 !== 0) {
      issues.push("odd-length hex");
    } else if (/[^0-9a-fA-F]/.test(compact)) {
      issues.push("non-hex characters");
    } else if (compact.length < 8) {
      issues.push("need at least 4 bytes (CLA INS P1 P2)");
    }
    return { hex: compact.toUpperCase(), issues: issues };
  }

  function scp03BreakdownApdu(hex) {
    // Pure-JS mirror of ``_parse_apdu_breakdown`` in the backend. Used
    // for the live-under-input breakdown row so the operator sees the
    // case + slicing BEFORE they hit Send. Safer + cheaper than a
    // round-trip to the server for every keystroke.
    var result = {
      cla: "", ins: "", p1: "", p2: "",
      lc: "", dataHex: "", dataLength: 0, le: "",
      case: "", byteCount: 0,
    };
    if (!hex || hex.length < 8 || hex.length % 2 !== 0) return result;
    result.cla = hex.substring(0, 2);
    result.ins = hex.substring(2, 4);
    result.p1 = hex.substring(4, 6);
    result.p2 = hex.substring(6, 8);
    result.byteCount = hex.length / 2;
    var total = result.byteCount;
    if (total === 4) { result.case = "1"; return result; }
    if (total === 5) {
      result.case = "2";
      result.le = hex.substring(8, 10);
      return result;
    }
    var lc = parseInt(hex.substring(8, 10), 16);
    if (lc === 0 && total > 5) {
      result.case = "ext";
      result.lc = "00";
      result.dataHex = hex.substring(10);
      result.dataLength = total - 5;
      return result;
    }
    if (total === 5 + lc) {
      result.case = "3";
      result.lc = hex.substring(8, 10);
      result.dataHex = hex.substring(10);
      result.dataLength = lc;
      return result;
    }
    if (total === 6 + lc) {
      result.case = "4";
      result.lc = hex.substring(8, 10);
      result.dataHex = hex.substring(10, 10 + lc * 2);
      result.dataLength = lc;
      result.le = hex.substring(hex.length - 2);
      return result;
    }
    result.case = "malformed";
    result.lc = hex.substring(8, 10);
    result.dataHex = hex.substring(10);
    result.dataLength = Math.max(total - 5, 0);
    return result;
  }

  function scp03HexToAscii(hex) {
    if (!hex) return "";
    var out = "";
    for (var i = 0; i + 1 < hex.length; i += 2) {
      var byte = parseInt(hex.substring(i, i + 2), 16);
      if (isNaN(byte)) {
        out += ".";
        continue;
      }
      if (byte >= 0x20 && byte <= 0x7E) {
        out += String.fromCharCode(byte);
      } else {
        out += ".";
      }
    }
    return out;
  }

  function scp03BuildApduPanel(tab, tabBar, tabBody) {
    // Full-width workbench panel rendered in place of the normal
    // ribbon-v2 button strip when the "APDU" tab is active. State
    // lives on the session tab (``tab.apdu*``) so switching ribbon
    // tabs doesn't wipe the input or the history.
    var panel = document.createElement("div");
    panel.className = "scp03-apdu-panel";

    var header = document.createElement("div");
    header.className = "scp03-apdu-header";
    var title = document.createElement("h3");
    title.className = "scp03-apdu-title";
    title.textContent = "Raw APDU console";
    header.appendChild(title);
    var subtitle = document.createElement("p");
    subtitle.className = "scp03-apdu-subtitle";
    subtitle.textContent = ""
      + "Transmit any ISO 7816-4 APDU on the active session. "
      + "The console auto-follows 61xx with GET RESPONSE and retries "
      + "6Cxx with the card's suggested Le. The card's current DF / "
      + "AID is left wherever your APDU put it — the next Files-tab "
      + "click re-anchors MF automatically.";
    header.appendChild(subtitle);
    panel.appendChild(header);

    if (!tab.sessionId) {
      var noSess = document.createElement("p");
      noSess.className = "cc-hint cc-hint-warn";
      noSess.textContent = "No active session — pick a reader on the left and run ‘Rescan’ first.";
      panel.appendChild(noSess);
      return panel;
    }

    // --- Form row: presets + options -----------------------------------
    var topBar = document.createElement("div");
    topBar.className = "scp03-apdu-topbar";

    var presetWrap = document.createElement("label");
    presetWrap.className = "scp03-apdu-preset";
    var presetLabel = document.createElement("span");
    presetLabel.textContent = "Preset:";
    presetWrap.appendChild(presetLabel);
    var presetSel = document.createElement("select");
    presetSel.className = "scp03-apdu-preset-select";
    var optBlank = document.createElement("option");
    optBlank.value = "";
    optBlank.textContent = "— pick a common APDU —";
    presetSel.appendChild(optBlank);
    SCP03_APDU_PRESETS.forEach(function (preset) {
      var opt = document.createElement("option");
      opt.value = preset.apdu;
      opt.textContent = preset.label + "  (" + preset.apdu + ")";
      presetSel.appendChild(opt);
    });
    presetWrap.appendChild(presetSel);
    topBar.appendChild(presetWrap);

    var optionsWrap = document.createElement("div");
    optionsWrap.className = "scp03-apdu-options";

    var follow61 = document.createElement("label");
    follow61.className = "scp03-apdu-opt";
    var follow61Chk = document.createElement("input");
    follow61Chk.type = "checkbox";
    follow61Chk.checked = tab.apduFollow61 !== false;
    follow61.appendChild(follow61Chk);
    follow61.appendChild(document.createTextNode(" follow 61xx"));
    follow61.title = "When the card returns 61xx, issue 00C00000xx and append the returned bytes.";
    optionsWrap.appendChild(follow61);

    var retry6c = document.createElement("label");
    retry6c.className = "scp03-apdu-opt";
    var retry6cChk = document.createElement("input");
    retry6cChk.type = "checkbox";
    retry6cChk.checked = tab.apduRetry6C !== false;
    retry6c.appendChild(retry6cChk);
    retry6c.appendChild(document.createTextNode(" retry 6Cxx"));
    retry6c.title = "When the card returns 6Cxx, re-send the same APDU with Le = xx.";
    optionsWrap.appendChild(retry6c);

    topBar.appendChild(optionsWrap);
    panel.appendChild(topBar);

    // --- Input row -----------------------------------------------------
    var inputRow = document.createElement("div");
    inputRow.className = "scp03-apdu-input-row";
    var inputLabel = document.createElement("label");
    inputLabel.className = "scp03-apdu-input-label";
    inputLabel.setAttribute("for", "scp03-apdu-input");
    inputLabel.textContent = "APDU (hex)";
    inputRow.appendChild(inputLabel);
    var input = document.createElement("textarea");
    input.id = "scp03-apdu-input";
    input.className = "scp03-apdu-input";
    input.rows = 2;
    input.placeholder = "e.g. 00A40004023F00  |  00B0000000  |  80CA5A00";
    input.spellcheck = false;
    input.autocomplete = "off";
    input.autocapitalize = "off";
    input.value = tab.apduInputHex || "";
    inputRow.appendChild(input);
    panel.appendChild(inputRow);

    // --- Breakdown row (live) ------------------------------------------
    var breakdownHost = document.createElement("div");
    breakdownHost.className = "scp03-apdu-breakdown";
    panel.appendChild(breakdownHost);

    // --- Action bar ----------------------------------------------------
    var actionBar = document.createElement("div");
    actionBar.className = "scp03-apdu-actions";
    var sendBtn = document.createElement("button");
    sendBtn.type = "button";
    sendBtn.className = "btn btn-primary scp03-apdu-send";
    sendBtn.textContent = "Send APDU";
    actionBar.appendChild(sendBtn);
    var clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.className = "btn scp03-apdu-clear";
    clearBtn.textContent = "Clear";
    actionBar.appendChild(clearBtn);
    panel.appendChild(actionBar);

    // --- Output panel --------------------------------------------------
    var outHost = document.createElement("div");
    outHost.className = "scp03-apdu-output";
    panel.appendChild(outHost);

    // --- History panel -------------------------------------------------
    var historyHost = document.createElement("div");
    historyHost.className = "scp03-apdu-history";
    panel.appendChild(historyHost);

    // --- Wiring --------------------------------------------------------
    function refreshBreakdown() {
      var raw = input.value || "";
      var norm = scp03NormaliseApduInput(raw);
      tab.apduInputHex = raw;
      breakdownHost.innerHTML = "";
      if (raw.length === 0) {
        var hint = document.createElement("p");
        hint.className = "cc-hint";
        hint.textContent = "Type a hex APDU (CLA INS P1 P2 [Lc] [Data] [Le]) or pick a preset above.";
        breakdownHost.appendChild(hint);
        sendBtn.disabled = true;
        return;
      }
      if (norm.issues.length > 0) {
        var warn = document.createElement("p");
        warn.className = "cc-hint cc-hint-warn";
        warn.textContent = "⚠ " + norm.issues.join(" · ");
        breakdownHost.appendChild(warn);
        sendBtn.disabled = true;
        return;
      }
      sendBtn.disabled = false;
      var bd = scp03BreakdownApdu(norm.hex);
      var table = document.createElement("table");
      table.className = "scp03-apdu-breakdown-table";
      var fields = [
        { label: "CLA",  value: bd.cla },
        { label: "INS",  value: bd.ins },
        { label: "P1",   value: bd.p1 },
        { label: "P2",   value: bd.p2 },
        { label: "Lc",   value: bd.lc || "—" },
        { label: "Data", value: bd.dataLength + " B"
          + (bd.dataHex ? " · " + bd.dataHex : "") },
        { label: "Le",   value: bd.le || "—" },
        { label: "Case", value: bd.case || "?" },
        { label: "Bytes", value: String(bd.byteCount) },
      ];
      var header = document.createElement("tr");
      fields.forEach(function (f) {
        var th = document.createElement("th");
        th.textContent = f.label;
        header.appendChild(th);
      });
      table.appendChild(header);
      var bodyRow = document.createElement("tr");
      fields.forEach(function (f) {
        var td = document.createElement("td");
        td.textContent = f.value || "—";
        bodyRow.appendChild(td);
      });
      table.appendChild(bodyRow);
      breakdownHost.appendChild(table);
      if (bd.dataHex && bd.dataLength > 0) {
        var ascii = scp03HexToAscii(bd.dataHex);
        var mirror = document.createElement("div");
        mirror.className = "scp03-apdu-ascii-mirror";
        mirror.innerHTML = "<span>Data ASCII:</span> <code>" + escapeHtml(ascii) + "</code>";
        breakdownHost.appendChild(mirror);
      }
    }

    input.addEventListener("input", refreshBreakdown);
    input.addEventListener("change", refreshBreakdown);

    presetSel.addEventListener("change", function () {
      if (!presetSel.value) return;
      input.value = presetSel.value;
      tab.apduInputHex = presetSel.value;
      presetSel.value = "";
      refreshBreakdown();
      input.focus();
    });

    follow61Chk.addEventListener("change", function () {
      tab.apduFollow61 = !!follow61Chk.checked;
    });
    retry6cChk.addEventListener("change", function () {
      tab.apduRetry6C = !!retry6cChk.checked;
    });

    clearBtn.addEventListener("click", function () {
      input.value = "";
      tab.apduInputHex = "";
      refreshBreakdown();
      input.focus();
    });

    input.addEventListener("keydown", function (ev) {
      // Ctrl+Enter / Cmd+Enter = send. Matches the CLI shell muscle
      // memory and avoids accidental line-break sends on Enter alone.
      if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") {
        ev.preventDefault();
        sendBtn.click();
      }
    });

    sendBtn.addEventListener("click", function () {
      scp03SendApdu(tab, input.value, {
        follow61: follow61Chk.checked,
        retry6c: retry6cChk.checked,
        outHost: outHost,
        historyHost: historyHost,
        refreshBreakdown: refreshBreakdown,
      });
    });

    // Initial paint
    refreshBreakdown();
    if (tab.apduLastResult) {
      scp03RenderApduResult(outHost, tab.apduLastResult);
    }
    scp03RenderApduHistory(historyHost, tab, {
      input: input,
      refreshBreakdown: refreshBreakdown,
    });

    return panel;
  }

  async function scp03SendApdu(tab, rawInput, opts) {
    var outHost = opts.outHost;
    var historyHost = opts.historyHost;
    var norm = scp03NormaliseApduInput(rawInput);
    if (norm.issues.length > 0) {
      outHost.innerHTML = "";
      outHost.appendChild(renderErrorBlock("Cannot send: " + norm.issues.join(" · ")));
      return;
    }
    outHost.innerHTML = "";
    outHost.appendChild(loadingEl("transmitting " + norm.hex + "…"));
    var started = Date.now();
    try {
      var resp = await apiFetch("/api/actions/scp03.send_apdu/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: {
            session_id: tab.sessionId,
            apdu: norm.hex,
            follow_61: !!opts.follow61,
            retry_6c: !!opts.retry6c,
          },
        }),
      });
      outHost.innerHTML = "";
      if (!resp.ok) {
        outHost.appendChild(renderErrorBlock(resp.error || "send_apdu failed"));
        return;
      }
      var data = resp.data || {};
      var elapsedMs = Date.now() - started;
      data.elapsed_ms = elapsedMs;
      tab.apduLastResult = data;
      scp03RenderApduResult(outHost, data);

      // Push onto history (front), cap at 20. We store the minimum
      // payload needed to re-render the summary chip + re-send.
      if (!Array.isArray(tab.apduHistory)) tab.apduHistory = [];
      tab.apduHistory.unshift({
        ts: new Date().toISOString(),
        apdu: data.apdu || norm.hex,
        sw: data.sw || "0000",
        ok: !!data.ok,
        length: data.response_length || 0,
        meaning: data.sw_meaning || "",
      });
      if (tab.apduHistory.length > 20) tab.apduHistory.length = 20;
      scp03RenderApduHistory(historyHost, tab, {
        input: document.getElementById("scp03-apdu-input"),
        refreshBreakdown: opts.refreshBreakdown,
      });

      logBus.emit({
        level: data.ok ? "info" : "warn",
        source: "scp03.send_apdu",
        message: (data.apdu || "?") + " → SW=" + (data.sw || "?")
          + " (" + (data.response_length || 0) + " B)"
          + (data.sw_meaning ? " · " + data.sw_meaning : ""),
      });
    } catch (err) {
      outHost.innerHTML = "";
      outHost.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  function scp03RenderApduResult(container, data) {
    container.innerHTML = "";
    var card = document.createElement("div");
    card.className = "scp03-apdu-result"
      + (data.ok ? " scp03-apdu-result--ok" : " scp03-apdu-result--warn");

    var headLine = document.createElement("div");
    headLine.className = "scp03-apdu-result-head";
    var swChip = document.createElement("span");
    swChip.className = "scp03-apdu-sw-chip"
      + (data.ok ? " scp03-apdu-sw-chip--ok"
                 : (String(data.sw1 || "").toUpperCase() === "61"
                    ? " scp03-apdu-sw-chip--info"
                    : " scp03-apdu-sw-chip--err"));
    swChip.textContent = "SW = " + (data.sw || "0000");
    headLine.appendChild(swChip);
    var meaningSpan = document.createElement("span");
    meaningSpan.className = "scp03-apdu-sw-meaning";
    meaningSpan.textContent = data.sw_meaning || "";
    headLine.appendChild(meaningSpan);
    var lenSpan = document.createElement("span");
    lenSpan.className = "scp03-apdu-result-len";
    lenSpan.textContent = (data.response_length || 0) + " B response"
      + (typeof data.elapsed_ms === "number" ? " · " + data.elapsed_ms + " ms" : "");
    headLine.appendChild(lenSpan);
    card.appendChild(headLine);

    // Breakdown echo — small because we already showed it above the
    // input; surfacing it here is a receipt so the operator can
    // cite it in a bug report without copying the input field.
    var bd = data.breakdown || {};
    var echo = document.createElement("p");
    echo.className = "scp03-apdu-result-echo";
    echo.innerHTML = "APDU: <code>" + escapeHtml(data.apdu || "") + "</code>"
      + " · case " + escapeHtml(bd.case || "?")
      + " · CLA " + escapeHtml(bd.cla || "??")
      + " INS " + escapeHtml(bd.ins || "??")
      + " P1/P2 " + escapeHtml(bd.p1 || "??") + "/" + escapeHtml(bd.p2 || "??");
    card.appendChild(echo);

    if (Array.isArray(data.chain) && data.chain.length > 0) {
      var chainHead = document.createElement("div");
      chainHead.className = "scp03-apdu-chain-head";
      chainHead.textContent = "Auto-follow-ups (" + data.chain.length + ")";
      card.appendChild(chainHead);
      data.chain.forEach(function (step, i) {
        var row = document.createElement("div");
        row.className = "scp03-apdu-chain-row";
        row.innerHTML = "<span class=\"scp03-apdu-chain-idx\">#"
          + (i + 1) + "</span> "
          + "<code>" + escapeHtml(step.apdu || "") + "</code> "
          + "<span class=\"scp03-apdu-chain-reason\">"
          + escapeHtml(step.reason || "") + "</span> "
          + "<span class=\"scp03-apdu-chain-sw\">SW="
          + escapeHtml(step.sw || "") + "</span> "
          + "<span class=\"scp03-apdu-chain-len\">"
          + (step.response_length || 0) + " B</span>";
        card.appendChild(row);
      });
    }

    if (data.response_hex && data.response_length > 0) {
      var hexHead = document.createElement("div");
      hexHead.className = "scp03-apdu-response-head";
      hexHead.textContent = "Response data";
      card.appendChild(hexHead);
      var hexBox = document.createElement("pre");
      hexBox.className = "cc-log cc-log-inline scp03-apdu-response-hex";
      hexBox.textContent = data.response_hex;
      card.appendChild(hexBox);
      if (data.response_ascii) {
        var asciiBox = document.createElement("pre");
        asciiBox.className = "cc-log cc-log-inline scp03-apdu-response-ascii";
        asciiBox.textContent = data.response_ascii;
        card.appendChild(asciiBox);
      }
    } else if (!data.sw_meaning || data.sw !== "9000") {
      var noData = document.createElement("p");
      noData.className = "cc-hint";
      noData.textContent = "(no response body)";
      card.appendChild(noData);
    }

    container.appendChild(card);
  }

  function scp03RenderApduHistory(container, tab, ctx) {
    container.innerHTML = "";
    if (!Array.isArray(tab.apduHistory) || tab.apduHistory.length === 0) {
      var empty = document.createElement("p");
      empty.className = "cc-hint";
      empty.textContent = "History is empty — sent APDUs will appear here.";
      container.appendChild(empty);
      return;
    }
    var head = document.createElement("div");
    head.className = "scp03-apdu-history-head";
    var title = document.createElement("span");
    title.className = "scp03-apdu-history-title";
    title.textContent = "History (" + tab.apduHistory.length + ")";
    head.appendChild(title);
    var clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.className = "btn btn-ghost scp03-apdu-history-clear";
    clearBtn.textContent = "Clear history";
    clearBtn.addEventListener("click", function () {
      tab.apduHistory = [];
      scp03RenderApduHistory(container, tab, ctx);
    });
    head.appendChild(clearBtn);
    container.appendChild(head);

    var list = document.createElement("ul");
    list.className = "scp03-apdu-history-list";
    tab.apduHistory.forEach(function (entry, i) {
      var li = document.createElement("li");
      li.className = "scp03-apdu-history-item"
        + (entry.ok ? " scp03-apdu-history-item--ok" : " scp03-apdu-history-item--warn");
      var time = entry.ts ? new Date(entry.ts) : null;
      var timeText = time
        ? String(time.getHours()).padStart(2, "0")
          + ":" + String(time.getMinutes()).padStart(2, "0")
          + ":" + String(time.getSeconds()).padStart(2, "0")
        : "";
      var meta = document.createElement("span");
      meta.className = "scp03-apdu-history-meta";
      meta.textContent = "[" + timeText + "] SW=" + (entry.sw || "")
        + " · " + (entry.length || 0) + " B";
      var apduCode = document.createElement("code");
      apduCode.className = "scp03-apdu-history-apdu";
      apduCode.textContent = entry.apdu || "";
      var note = document.createElement("span");
      note.className = "scp03-apdu-history-note";
      note.textContent = entry.meaning || "";

      var actions = document.createElement("span");
      actions.className = "scp03-apdu-history-actions";
      var reuse = document.createElement("button");
      reuse.type = "button";
      reuse.className = "btn btn-ghost scp03-apdu-history-reuse";
      reuse.textContent = "Load";
      reuse.title = "Put this APDU back in the input field";
      reuse.addEventListener("click", function () {
        if (ctx && ctx.input) {
          ctx.input.value = entry.apdu || "";
          tab.apduInputHex = entry.apdu || "";
          if (ctx.refreshBreakdown) ctx.refreshBreakdown();
          ctx.input.focus();
        }
      });
      var copy = document.createElement("button");
      copy.type = "button";
      copy.className = "btn btn-ghost scp03-apdu-history-copy";
      copy.textContent = "Copy";
      copy.title = "Copy APDU hex to clipboard";
      copy.addEventListener("click", function () {
        try {
          navigator.clipboard.writeText(entry.apdu || "");
        } catch (_err) {
          // Clipboard API unavailable in some embedded webviews —
          // fall back to a hidden-textarea trick so the Copy button
          // still works under pywebview / GTK.
          var ta = document.createElement("textarea");
          ta.value = entry.apdu || "";
          ta.style.position = "fixed";
          ta.style.top = "-9999px";
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand("copy"); } catch (_e) { /* swallow */ }
          document.body.removeChild(ta);
        }
      });
      actions.appendChild(reuse);
      actions.appendChild(copy);

      li.appendChild(meta);
      li.appendChild(apduCode);
      if (entry.meaning) li.appendChild(note);
      li.appendChild(actions);
      list.appendChild(li);
    });
    container.appendChild(list);
  }

  async function scp03ShowDecode(_tab) {
    var card = scp03BuildExtrasCard("Decode hex");
    if (!card) return;

    var form = document.createElement("form");
    form.className = "cc-action-form";
    var row = document.createElement("div");
    row.className = "form-row";
    var label = document.createElement("label");
    label.textContent = "Hex (BER-TLV or GP LV stream)";
    row.appendChild(label);
    var input = document.createElement("textarea");
    input.rows = 3;
    input.placeholder = "6F108408A00000008710...";
    input.className = "cc-decode-input";
    row.appendChild(input);
    form.appendChild(row);
    var bar = document.createElement("div");
    bar.className = "inline-actions cc-action-bar";
    var run = document.createElement("button");
    run.type = "submit";
    run.className = "btn btn-primary";
    run.textContent = "Decode";
    bar.appendChild(run);
    form.appendChild(bar);
    card.appendChild(form);

    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    card.appendChild(out);

    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      out.innerHTML = "";
      out.appendChild(loadingEl("decoding…"));
      try {
        var resp = await apiFetch("/api/actions/scp03.decode/run", {
          method: "POST",
          body: JSON.stringify({ inputs: { hex_data: input.value } }),
        });
        out.innerHTML = "";
        if (!resp.ok) {
          out.appendChild(renderErrorBlock(resp.error || "decode failed"));
          return;
        }
        var data = resp.data || {};
        var header = document.createElement("p");
        header.className = "hint";
        header.textContent = "kind=" + (data.kind || "?")
          + " | " + (data.byte_count || 0) + " B consumed="
          + (data.consumed || 0)
          + (data.complete ? " (complete)" : " (incomplete)");
        out.appendChild(header);
        if (data.kind === "registry" && Array.isArray(data.registry_stream)) {
          var rows = data.registry_stream.map(function (e) {
            return { AID: e.aid, state: e.state_hex, extra: e.extra_hex };
          });
          out.appendChild(renderObjectTable(rows));
        } else {
          out.appendChild(renderDecodedBlock(data.parsed, null, { omitHead: true }));
        }
        if (data.error) {
          var note = document.createElement("p");
          note.className = "hint";
          note.textContent = "parser note: " + data.error;
          out.appendChild(note);
        }
      } catch (err) {
        out.innerHTML = "";
        out.appendChild(renderErrorBlock(String(err && err.message || err)));
      }
    });
  }

  async function scp03ReadBinary(tab) {
    var card = scp03BuildExtrasCard("READ BINARY");
    if (!card) return;
    var path = "";
    if (!tab.selectedPath) {
      try {
        path = window.prompt("Path to READ (leave blank = currently selected):", "") || "";
      } catch (_e) { path = ""; }
      if (path === null) return;
    } else {
      path = tab.selectedPath;
    }
    card.appendChild(loadingEl("reading…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.read_binary/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId, path: path } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "read failed"));
        return;
      }
      var data = resp.data || {};
      scp03RenderKeyValueRows(card, [
        { label: "Path", value: data.path || "(current)" },
        { label: "FID", value: data.fid || "" },
        { label: "Structure", value: data.structure || "" },
        { label: "SW", value: data.sw || "" },
        { label: "Length", value: data.length || 0 },
      ]);
      var hexWrap = document.createElement("div");
      var hexTitle = document.createElement("h5");
      hexTitle.className = "cc-section-title-sm";
      hexTitle.textContent = "Raw hex";
      hexWrap.appendChild(hexTitle);
      hexWrap.appendChild(renderHexBlock(data.hex || ""));
      card.appendChild(hexWrap);
      if (data.decoded) {
        var decWrap = document.createElement("div");
        var decTitle = document.createElement("h5");
        decTitle.className = "cc-section-title-sm";
        decTitle.textContent = "Decoded";
        decWrap.appendChild(decTitle);
        decWrap.appendChild(renderDecodedBlock(data.decoded, {
          rawHex: data.hex || "",
          path: data.path || "",
          fid: data.fid || "",
        }));
        card.appendChild(decWrap);
      }
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03ReadRecord(tab) {
    var card = scp03BuildExtrasCard("READ RECORD");
    if (!card) return;

    var selector = "";
    try {
      selector = window.prompt(
        "RECORD selector — enter N / Start-End / ALL (e.g. 1, 1-5, ALL):",
        "ALL"
      );
    } catch (_e) { selector = ""; }
    if (selector === null) { scp03GetExtrasSlot().innerHTML = ""; return; }
    selector = String(selector || "").trim();
    if (selector.length === 0) { scp03GetExtrasSlot().innerHTML = ""; return; }

    var path = tab.selectedPath || "";
    if (!path) {
      try {
        path = window.prompt("Path (optional; leave blank = currently selected):", "") || "";
      } catch (_e) { path = ""; }
      if (path === null) path = "";
    }

    card.appendChild(loadingEl("reading records…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.read_record/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: { session_id: tab.sessionId, selector: selector, path: path },
        }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "read_record failed"));
        return;
      }
      var data = resp.data || {};
      scp03RenderKeyValueRows(card, [
        { label: "Path", value: data.path || "(current)" },
        { label: "Structure", value: data.structure || "" },
        { label: "Selector", value: data.selector || "" },
        { label: "Rec len", value: data.rec_len || 0 },
        { label: "Count", value: data.record_count || 0 },
        { label: "Stop", value: data.stop_reason || "" },
      ]);
      card.appendChild(renderRecordsPayload(data));
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03ShowArr(tab) {
    var card = scp03BuildExtrasCard("EF.ARR (access rules)");
    if (!card) return;
    var path = "";
    try {
      path = window.prompt(
        "ARR scope — leave blank for current, or type MF / USIM / FID:",
        ""
      );
    } catch (_e) { path = ""; }
    if (path === null) { scp03GetExtrasSlot().innerHTML = ""; return; }

    card.appendChild(loadingEl("reading ARR…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.arr/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId, path: path } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "ARR failed"));
        return;
      }
      var data = resp.data || {};
      scp03RenderKeyValueRows(card, [
        { label: "Scope", value: data.path || "(current)" },
        { label: "Result", value: data.ok ? "ok" : "failed/empty" },
      ]);
      scp03RenderTextLines(card, data.lines || []);
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03DumpFs(tab) {
    var card = scp03BuildExtrasCard("Dump file system");
    if (!card) return;
    var outDir = "";
    try {
      outDir = window.prompt(
        "Output directory (parent for FS_DUMP/<ICCID>/). Leave blank = ~/Documents:",
        ""
      );
    } catch (_e) { outDir = ""; }
    if (outDir === null) { scp03GetExtrasSlot().innerHTML = ""; return; }

    card.appendChild(loadingEl("dumping FS (this may take a while)…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.dump_fs/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId, output_dir: outDir } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "dump failed"));
        return;
      }
      var data = resp.data || {};
      scp03RenderKeyValueRows(card, [
        { label: "Root", value: data.output_dir || "" },
        { label: "Created", value: data.created_root || "(see trace)" },
        { label: "Status", value: data.ok ? "ok" : "see trace" },
      ]);
      if (data.error) {
        card.appendChild(renderErrorBlock(data.error));
      }
      scp03RenderTextLines(card, data.lines || []);
      logBus.emit({
        level: data.ok ? "info" : "warn",
        source: "scp03.dump_fs",
        message: "FS dump -> " + (data.created_root || data.output_dir || "?"),
      });
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  // -- C-2: auth + GP registry + profile telemetry ---------------------

  function scp03BuildInlineForm(card, fields, submitLabel, onSubmit) {
    // ``fields`` : [{ name, label, placeholder, value, required, kind?, choices?, help? }]
    // ``kind`` — defaults to "text". Also supports "select" (use ``choices`` :
    // array of strings), "bool" (checkbox) and "textarea" (multi-line hex).
    // Returns a handle with { form, inputs, submit }. The caller wires
    // ``onSubmit(values)``; this helper only lays out the DOM + disables
    // the submit button while the handler runs.
    var form = document.createElement("form");
    form.className = "cc-action-form cc-wb-extras-form";
    form.noValidate = true;
    var inputs = {};
    (fields || []).forEach(function (field) {
      var row = document.createElement("div");
      row.className = "cc-form-row";
      var label = document.createElement("label");
      label.textContent = field.label || field.name;
      label.htmlFor = "cc-inline-" + field.name;
      var input;
      var kind = field.kind || "text";
      if (kind === "select") {
        input = document.createElement("select");
        (field.choices || []).forEach(function (choice) {
          var opt = document.createElement("option");
          opt.value = String(choice);
          opt.textContent = String(choice);
          input.appendChild(opt);
        });
        if (field.value != null) input.value = String(field.value);
      } else if (kind === "bool") {
        input = document.createElement("input");
        input.type = "checkbox";
        if (field.value === true || field.value === "true" || field.value === 1) {
          input.checked = true;
        }
      } else if (kind === "textarea") {
        input = document.createElement("textarea");
        input.rows = field.rows || 3;
        if (field.placeholder) input.placeholder = field.placeholder;
        if (field.value != null) input.value = String(field.value);
      } else {
        input = document.createElement("input");
        input.type = (kind === "number") ? "number" : "text";
        if (field.placeholder) input.placeholder = field.placeholder;
        if (field.value != null) input.value = String(field.value);
      }
      input.id = label.htmlFor;
      input.name = field.name;
      if (field.required && kind !== "bool") input.required = true;
      row.appendChild(label);
      row.appendChild(input);
      if (field.help) {
        var hint = document.createElement("div");
        hint.className = "cc-field-hint";
        hint.textContent = field.help;
        row.appendChild(hint);
      }
      form.appendChild(row);
      inputs[field.name] = input;
    });
    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "btn btn-primary";
    submit.textContent = submitLabel || "Run";
    bar.appendChild(submit);
    form.appendChild(bar);
    card.appendChild(form);
    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      var values = {};
      Object.keys(inputs).forEach(function (key) {
        var node = inputs[key];
        if (node.type === "checkbox") {
          values[key] = node.checked;
        } else {
          values[key] = node.value;
        }
      });
      submit.disabled = true;
      try {
        await onSubmit(values);
      } finally {
        submit.disabled = false;
      }
    });
    return { form: form, inputs: inputs, submit: submit };
  }

  async function scp03AuthFlow(tab, actionId, title) {
    var card = scp03BuildExtrasCard(title);
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    var handle = scp03BuildInlineForm(
      card,
      [
        {
          name: "target_aid",
          label: "Target AID",
          placeholder: "leave blank for ISD",
          help: "Optional hex AID of the SD to authenticate against.",
        },
      ],
      "Authenticate",
      async function (values) {
        out.innerHTML = "";
        out.appendChild(loadingEl("authenticating…"));
        try {
          var resp = await apiFetch("/api/actions/" + actionId + "/run", {
            method: "POST",
            body: JSON.stringify({
              inputs: {
                session_id: tab.sessionId,
                target_aid: (values.target_aid || "").trim(),
              },
            }),
          });
          out.innerHTML = "";
          if (!resp.ok) {
            out.appendChild(renderErrorBlock(resp.error || "auth failed"));
            return;
          }
          var data = resp.data || {};
          // Mirror the auth result into the per-tab cache so
          // subsequent ``requires_auth`` actions bypass the popout
          // gate. A failed auth clears the flag — scp03ClearTabAuth
          // is cheap and keeps the cache honest.
          if (data.ok && data.authenticated) {
            scp03UpdateTabAuthFromResponse(tab, data);
          } else {
            scp03ClearTabAuth(tab);
          }
          scp03RenderKeyValueRows(out, [
            { label: "Status", value: data.ok ? "AUTHENTICATED" : "FAILED" },
            { label: "Protocol", value: data.protocol || "" },
            { label: "Target AID", value: data.target_aid || "" },
            { label: "KVN", value: data.kvn || "" },
            { label: "Sec level", value: data.sec_level || "" },
            { label: "Active protocol", value: data.active_protocol || "" },
          ]);
          if (data.trace) {
            var pre = document.createElement("pre");
            pre.className = "cc-log";
            pre.textContent = data.trace;
            out.appendChild(pre);
          }
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: actionId,
            message: (data.ok ? "ok" : "failed") + " " + (data.protocol || "")
              + " KVN=" + (data.kvn || "??") + " AID=" + (data.target_aid || "??"),
          });
          try { scp03RerenderActiveTabBody(); } catch (_e) {}
        } catch (err) {
          out.innerHTML = "";
          out.appendChild(renderErrorBlock(String(err && err.message || err)));
        }
      }
    );
    card.appendChild(out);
    handle.inputs.target_aid.focus();
  }

  async function scp03Logout(tab) {
    var card = scp03BuildExtrasCard("Logout (secure session)");
    if (!card) return;
    card.appendChild(loadingEl("closing secure session…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.logout/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "logout failed"));
        return;
      }
      var data = resp.data || {};
      var st = data.status || {};
      // Logout tore down the secure channel — flush the per-tab
      // cache so the next destructive click re-prompts rather than
      // trusting a stale "authenticated" flag.
      scp03ClearTabAuth(tab);
      scp03RenderKeyValueRows(card, [
        { label: "Was active", value: data.was_active ? "yes" : "no" },
        { label: "Authenticated", value: st.authenticated ? "yes" : "no" },
        { label: "Protocol", value: st.protocol || "" },
        { label: "Sec level", value: st.sec_level || "" },
      ]);
      logBus.emit({
        level: "info",
        source: "scp03.logout",
        message: "logout -> was_active=" + (data.was_active ? "true" : "false"),
      });
      try { scp03RerenderActiveTabBody(); } catch (_e) {}
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03ShowKeys(tab) {
    var card = scp03BuildExtrasCard("Keys (key-info template)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out cc-wb-extras-out--stretch";
    scp03BuildInlineForm(
      card,
      [
        {
          name: "target_aid",
          label: "Target AID",
          placeholder: "leave blank for ISD",
          help: "Optional hex AID; defaults to ISD bound to the session.",
        },
      ],
      "Fetch keys",
      async function (values) {
        out.innerHTML = "";
        out.appendChild(loadingEl("reading key template…"));
        try {
          var resp = await apiFetch("/api/actions/scp03.keys/run", {
            method: "POST",
            body: JSON.stringify({
              inputs: {
                session_id: tab.sessionId,
                target_aid: (values.target_aid || "").trim(),
              },
            }),
          });
          out.innerHTML = "";
          if (!resp.ok) {
            out.appendChild(renderErrorBlock(resp.error || "keys fetch failed"));
            return;
          }
          var data = resp.data || {};
          var ds = scp03CreateDatasheetRoot();
          scp03DatasheetAppendMetaKvl(ds, [
            { label: "Target AID", value: data.target_aid || "" },
            { label: "SW", value: data.status || "" },
            { label: "Entries", value: (data.entries || []).length },
          ]);
          if (Array.isArray(data.entries) && data.entries.length > 0) {
            scp03DatasheetAppendMain(ds, renderObjectTable(data.entries));
          } else {
            scp03DatasheetAppendEmpty(ds, "(no key entries — are you authenticated?)");
          }
          scp03DatasheetAppendRawHex(
            ds,
            data.raw_hex,
            "Raw response (" + ((data.raw_hex || "").length / 2) + " bytes)"
          );
          out.appendChild(ds);
          logBus.emit({
            level: "info",
            source: "scp03.keys",
            message: "SW=" + (data.status || "????")
              + " entries=" + ((data.entries || []).length),
          });
        } catch (err) {
          out.innerHTML = "";
          out.appendChild(renderErrorBlock(String(err && err.message || err)));
        }
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowRegistry(tab, actionId, title) {
    var card = scp03BuildExtrasCard(title);
    if (!card) return;
    card.appendChild(loadingEl("fetching registry…"));
    try {
      var resp = await apiFetch("/api/actions/" + actionId + "/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "registry fetch failed"));
        return;
      }
      var data = resp.data || {};
      var ds = scp03CreateDatasheetRoot();
      scp03DatasheetAppendMetaKvl(ds, [
        { label: "Kind", value: data.kind || "" },
        { label: "SW", value: data.status || "" },
        { label: "Pages", value: data.pages || 0 },
        { label: "Count", value: data.count || 0 },
      ]);
      if (Array.isArray(data.entries) && data.entries.length > 0) {
        scp03DatasheetAppendMain(ds, renderObjectTable(data.entries));
      } else {
        scp03DatasheetAppendEmpty(ds, "(no entries — are you authenticated?)");
      }
      scp03DatasheetAppendRawHex(
        ds,
        data.raw_hex,
        "Raw response (" + ((data.raw_hex || "").length / 2) + " bytes)"
      );
      card.appendChild(ds);
      logBus.emit({
        level: "info",
        source: actionId,
        message: (data.kind || "?") + " entries=" + (data.count || 0),
      });
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03ShowGetData(tab) {
    var card = scp03BuildExtrasCard("GET DATA (tag P1/P2)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out cc-wb-extras-out--stretch";
    scp03BuildInlineForm(
      card,
      [
        { name: "p1", label: "P1", placeholder: "e.g. 9F", required: true },
        { name: "p2", label: "P2", placeholder: "e.g. 7F", required: true,
          help: "80CA P1 P2 00 — common tags: 9F7F (CPLC), 00E0 (key info), 00CF (CIN)." },
      ],
      "GET DATA",
      async function (values) {
        out.innerHTML = "";
        out.appendChild(loadingEl("issuing GET DATA…"));
        try {
          var resp = await apiFetch("/api/actions/scp03.get_data/run", {
            method: "POST",
            body: JSON.stringify({
              inputs: {
                session_id: tab.sessionId,
                p1: (values.p1 || "").trim(),
                p2: (values.p2 || "").trim(),
              },
            }),
          });
          out.innerHTML = "";
          if (!resp.ok) {
            out.appendChild(renderErrorBlock(resp.error || "GET DATA failed"));
            return;
          }
          var data = resp.data || {};
          var ds = scp03CreateDatasheetRoot();
          scp03DatasheetAppendMetaKvl(ds, [
            { label: "P1/P2", value: (data.p1 || "??") + " / " + (data.p2 || "??") },
            { label: "SW", value: data.sw || "" },
            { label: "Bytes", value: data.length || 0 },
          ]);
          if (data.decode_error) {
            scp03DatasheetAppendWarn(ds, "decode: " + data.decode_error);
          }
          scp03DatasheetAppendJsonBlock(ds, data.decoded, "Decoded");
          scp03DatasheetAppendRawHex(
            ds,
            data.hex,
            "Raw payload (" + ((data.hex || "").length / 2) + " bytes)"
          );
          out.appendChild(ds);
          logBus.emit({
            level: "info",
            source: "scp03.get_data",
            message: "P1=" + (data.p1 || "??") + " P2=" + (data.p2 || "??")
              + " SW=" + (data.sw || "") + " len=" + (data.length || 0),
          });
        } catch (err) {
          out.innerHTML = "";
          out.appendChild(renderErrorBlock(String(err && err.message || err)));
        }
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowAidRegistry(tab) {
    var card = scp03BuildExtrasCard("AID registry (aid.txt)");
    if (!card) return;
    card.appendChild(loadingEl("loading aliases…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.list_aids/run", {
        method: "POST",
        body: JSON.stringify({ inputs: {} }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "failed to load AID registry"));
        return;
      }
      var data = resp.data || {};
      var ds = scp03CreateDatasheetRoot();
      scp03DatasheetAppendMetaKvl(ds, [
        { label: "Path", value: data.path || "" },
        { label: "Count", value: data.count || 0 },
      ]);
      if (data.error) {
        ds.appendChild(renderErrorBlock(data.error));
      }
      if (Array.isArray(data.entries) && data.entries.length > 0) {
        scp03DatasheetAppendMain(ds, renderObjectTable(data.entries));
      } else if (!data.error) {
        scp03DatasheetAppendEmpty(ds, "(registry is empty)");
      }
      card.appendChild(ds);
      logBus.emit({
        level: "info",
        source: "scp03.list_aids",
        message: "aliases=" + (data.count || 0),
      });
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03ShowListProfiles(tab) {
    var card = scp03BuildExtrasCard("Profiles (ES10c)");
    if (!card) return;
    card.appendChild(loadingEl("retrieving profile list…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.list_profiles/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "list_profiles failed"));
        return;
      }
      var data = resp.data || {};
      var ds = scp03CreateDatasheetRoot();
      scp03DatasheetAppendMetaKvl(ds, [
        { label: "SW", value: data.sw || "" },
        { label: "Count", value: data.count || 0 },
      ]);
      if (data.parse_error) {
        scp03DatasheetAppendWarn(ds, "parse: " + data.parse_error);
      }
      if (Array.isArray(data.profiles) && data.profiles.length > 0) {
        scp03DatasheetAppendMain(ds, renderObjectTable(data.profiles));
      } else {
        scp03DatasheetAppendEmpty(ds, "(no profiles returned — is this an eUICC?)");
      }
      scp03DatasheetAppendRawHex(
        ds,
        data.raw_hex,
        "Raw BF2D response (" + ((data.raw_hex || "").length / 2) + " bytes)"
      );
      card.appendChild(ds);
      logBus.emit({
        level: "info",
        source: "scp03.list_profiles",
        message: "SW=" + (data.sw || "????") + " count=" + (data.count || 0),
      });
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03ShowProfileScan(tab) {
    var card = scp03BuildExtrasCard("eUICC scan (SGP.22 / SGP.32)");
    if (!card) return;
    card.appendChild(loadingEl("running eUICC scan…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.profile_scan/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "profile_scan failed"));
        return;
      }
      var data = resp.data || {};
      var scanRoot = scp03CreateDatasheetRoot();
      scp03DatasheetAppendMetaKvl(scanRoot, [
        { label: "EID", value: data.eid || "(none)" },
        { label: "Profiles", value: (data.profiles || []).length },
      ]);
      if (Array.isArray(data.profiles) && data.profiles.length > 0) {
        scp03DatasheetAppendMain(scanRoot, renderObjectTable(data.profiles));
      }
      function addSection(parent, title, raw, parsed) {
        if ((!raw || raw.length === 0) && (!parsed || Object.keys(parsed || {}).length === 0)) return;
        var section = document.createElement("details");
        section.className = "cc-details cc-action-datasheet-raw";
        var sum = document.createElement("summary");
        sum.textContent = title + (raw ? "  (" + (raw.length / 2) + " bytes)" : "");
        section.appendChild(sum);
        if (parsed && Object.keys(parsed).length > 0) {
          section.appendChild(renderDecodedBlock(parsed, null, { omitHead: true }));
        }
        if (raw) section.appendChild(renderHexBlock(raw));
        parent.appendChild(section);
      }
      addSection(scanRoot, "EuiccInfo1 (BF20)", data.euicc_info1_raw, data.euicc_info1);
      addSection(scanRoot, "EuiccInfo2 (BF22)", data.euicc_info2_raw, data.euicc_info2);
      addSection(
        scanRoot,
        "EuiccConfiguredData (BF3C)",
        data.euicc_configured_data_raw,
        data.euicc_configured_data
      );
      card.appendChild(scanRoot);
      logBus.emit({
        level: "info",
        source: "scp03.profile_scan",
        message: "EID=" + (data.eid || "??") + " profiles=" + ((data.profiles || []).length),
      });
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  // -- C-3: mutation + validation + exports ----------------------------

  function scp03BuildDestructiveBanner(card, text) {
    var banner = document.createElement("div");
    banner.className = "cc-destructive-banner";
    banner.textContent = text;
    card.appendChild(banner);
    return banner;
  }

  // -- Auth gate -------------------------------------------------------
  //
  // Actions flagged ``requires_auth: true`` by the backend registry
  // (PUT KEY / INSTALL [for …] / SET STATUS / DELETE / fs_create_file
  // / fs_delete_file / fs_resize / fs_lifecycle / update_binary /
  // update_record / store_data / export_keybag …) will bounce with
  // 69 82 unless the active session has run ``scp03.auth_scp03`` (or
  // scp02) first. The ribbon used to just drop a "Requires an
  // authenticated secure session" banner next to the form; in practice
  // that meant operators submitted the form, got a 69 82, then had to
  // separately run the Auth action and *remember* the inputs they
  // typed. The ``scp03EnsureAuthed`` helper below fixes that by
  // intercepting the click, opening a compact auth-prompt popout, and
  // chaining into the original handler only once AUTH succeeds.
  //
  // ``tab.authStatus`` is updated from every auth response we see —
  // including passive ``scp03.auth_status`` probes — so repeated
  // install calls on the same tab don't re-prompt. A ``logout`` /
  // ``recover_session`` clears it back to ``{authenticated:false}``.

  function scp03LookupActionSpec(actionId) {
    // Returns the spec entry (as shipped by /api/actions) for the given
    // action id, or null when the catalogue hasn't loaded yet. SCP03 is
    // the only subsystem that currently sets ``requires_auth``, but the
    // lookup is subsystem-agnostic so the helper stays useful if SCP11
    // ever grows the same gate.
    var cat = commandState && commandState.catalogue;
    if (!cat || !cat.subsystems) return null;
    var names = Object.keys(cat.subsystems);
    for (var i = 0; i < names.length; i++) {
      var list = cat.subsystems[names[i]] || [];
      for (var j = 0; j < list.length; j++) {
        if (list[j] && list[j].id === actionId) return list[j];
      }
    }
    return null;
  }

  function scp03ActionRequiresAuth(actionId) {
    var spec = scp03LookupActionSpec(actionId);
    return !!(spec && spec.requires_auth);
  }

  function scp03HasLiveAuth(tab) {
    if (!tab || !tab.authStatus) return false;
    return !!tab.authStatus.authenticated;
  }

  function scp03UpdateTabAuthFromResponse(tab, data) {
    // Shared ingestion path — both the auth prompt and the standalone
    // ``Authenticate SCP03`` ribbon action funnel successful responses
    // through here so ``tab.authStatus`` stays consistent regardless of
    // which entry point the operator used. Failures clear the flag so
    // a subsequent ``requires_auth`` action re-prompts rather than
    // masquerading as authenticated.
    if (!tab || !data) return;
    var nowTs = (typeof Date !== "undefined" && typeof Date.now === "function")
      ? Date.now() : 0;
    var ok = !!(data.authenticated && data.ok !== false);
    tab.authStatus = {
      authenticated: ok,
      protocol: String(data.protocol || data.active_protocol || ""),
      targetAid: String(data.target_aid || ""),
      kvn: String(data.kvn || ""),
      secLevel: String(data.sec_level || ""),
      at: ok ? nowTs : 0,
      overridesApplied: Array.isArray(data.overrides_applied)
        ? data.overrides_applied.slice() : [],
    };
  }

  function scp03ClearTabAuth(tab) {
    if (!tab) return;
    tab.authStatus = {
      authenticated: false, protocol: "", targetAid: "",
      kvn: "", secLevel: "", at: 0, overridesApplied: [],
    };
  }

  async function scp03RefreshTabAuthStatus(tab) {
    // Best-effort passive probe — used when a tab is rehydrated from
    // ``localStorage`` on page reload. The sessionId may still be live
    // backend-side (the idle reaper's window is generous), in which
    // case we should adopt the existing SCP state instead of forcing
    // a fresh AUTH round-trip. Returns the refreshed authStatus.
    if (!tab || !tab.sessionId) return null;
    try {
      var resp = await apiFetch("/api/actions/scp03.auth_status/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      if (resp && resp.ok) {
        var data = resp.data || {};
        scp03UpdateTabAuthFromResponse(tab, {
          ok: true,
          authenticated: !!data.authenticated,
          protocol: data.protocol,
          target_aid: data.target_aid,
          sec_level: data.sec_level,
        });
        return tab.authStatus;
      }
    } catch (_err) { /* offline / server gone — keep cached value */ }
    return tab.authStatus || null;
  }

  function scp03BuildAuthPromptPopout(tab, actionTitle) {
    // Dedicated popout (not an inline banner) so the operator can keep
    // the action form visible underneath. The popout closes itself on
    // successful authenticate; failure cases keep the form open so the
    // operator can tweak keys / AID and retry.
    var body = scp03BuildExtrasCard("Authenticate before " + (actionTitle || "action"));
    if (!body) return null;

    var intro = document.createElement("p");
    intro.className = "cc-hint";
    intro.textContent = "This command requires an authenticated SCP session. "
      + "Pick the protocol + Security Domain you want to authenticate against. "
      + "Leave the ENC / MAC / DEK fields blank to use the keys loaded from "
      + "your Workspace keybag — supply overrides only when the live card is "
      + "keyed differently.";
    body.appendChild(intro);

    var lastAid = (tab && tab.authStatus && tab.authStatus.targetAid) || "";
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";

    return { body: body, out: out, lastAid: lastAid };
  }

  function scp03EnsureAuthed(tab, options) {
    // Returns a Promise<boolean>. Resolves true when the session is (or
    // becomes) authenticated. False when the operator cancels or AUTH
    // fails.
    //
    // ``options`` = { actionTitle?: string, allowSkipPrompt?: bool }
    //   - actionTitle: shown in the popout header so operators know
    //     which command is gated behind the prompt.
    //   - allowSkipPrompt: when true, callers get a straight ``true``
    //     back without showing UI if ``tab.authStatus.authenticated``
    //     is already truthy. Default true — we only bypass callers
    //     explicitly need to force re-auth (currently nobody, but the
    //     hook is here for the "force re-auth" item in the ribbon).
    var opts = options || {};
    if (!tab || !tab.sessionId) {
      return Promise.resolve(false);
    }
    if (opts.allowSkipPrompt !== false && scp03HasLiveAuth(tab)) {
      return Promise.resolve(true);
    }

    return new Promise(function (resolve) {
      var shell = scp03BuildAuthPromptPopout(tab, opts.actionTitle || "");
      if (!shell) {
        resolve(false);
        return;
      }

      var defaultProtocol = (tab.authStatus && tab.authStatus.protocol) || "SCP03";
      if (defaultProtocol !== "SCP02") defaultProtocol = "SCP03";

      var handle = scp03BuildInlineForm(
        shell.body,
        [
          {
            name: "protocol",
            label: "Protocol",
            kind: "select",
            choices: ["SCP03", "SCP02"],
            value: defaultProtocol,
          },
          {
            name: "target_aid",
            label: "Target AID",
            placeholder: "leave blank for ISD",
            value: shell.lastAid,
            help: "Hex AID of the Security Domain to authenticate against.",
          },
          {
            name: "kvn",
            label: "KVN override (hex, optional)",
            placeholder: "e.g. 30",
            help: "Overrides the key version number for this authenticate.",
          },
          {
            name: "enc_key",
            label: "ENC / KENC override (hex, optional)",
            placeholder: "32 / 48 / 64 hex chars",
            help: "Blank = use workspace keys. Not persisted.",
          },
          {
            name: "mac_key",
            label: "MAC / KMAC override (hex, optional)",
            placeholder: "32 / 48 / 64 hex chars",
          },
          {
            name: "dek_key",
            label: "DEK override (hex, optional)",
            placeholder: "32 / 48 / 64 hex chars",
          },
        ],
        "Authenticate",
        async function (values) {
          shell.out.innerHTML = "";
          shell.out.appendChild(loadingEl("authenticating…"));
          var actionId = (String(values.protocol || "SCP03").toUpperCase() === "SCP02")
            ? "scp03.auth_scp02"
            : "scp03.auth_scp03";
          try {
            var resp = await apiFetch("/api/actions/" + actionId + "/run", {
              method: "POST",
              body: JSON.stringify({
                inputs: {
                  session_id: tab.sessionId,
                  target_aid: (values.target_aid || "").trim(),
                  kvn: (values.kvn || "").trim(),
                  enc_key: (values.enc_key || "").trim(),
                  mac_key: (values.mac_key || "").trim(),
                  dek_key: (values.dek_key || "").trim(),
                },
              }),
            });
            shell.out.innerHTML = "";
            if (!resp.ok) {
              shell.out.appendChild(renderErrorBlock(resp.error || "authenticate failed"));
              return;
            }
            var data = resp.data || {};
            scp03UpdateTabAuthFromResponse(tab, data);
            if (scp03HasLiveAuth(tab)) {
              scp03RenderKeyValueRows(shell.out, [
                { label: "Status", value: "AUTHENTICATED" },
                { label: "Protocol", value: data.protocol || "" },
                { label: "Target AID", value: data.target_aid || "" },
                { label: "KVN", value: data.kvn || "" },
                { label: "Sec level", value: data.sec_level || "" },
              ]);
              var usedOverrides = Array.isArray(data.overrides_applied)
                ? data.overrides_applied : [];
              if (usedOverrides.length > 0) {
                var chip = document.createElement("p");
                chip.className = "cc-hint";
                chip.textContent = "Overrides applied: " + usedOverrides.join(", ")
                  + " (session-scoped; not persisted).";
                shell.out.appendChild(chip);
              }
              logBus.emit({
                level: "info",
                source: actionId,
                message: "OK " + (data.protocol || "")
                  + " KVN=" + (data.kvn || "??")
                  + " AID=" + (data.target_aid || "ISD"),
              });
              try { readerBarRender(); } catch (_e) {}
              try { scp03RerenderActiveTabBody(); } catch (_e) {}
              resolve(true);
              // Auto-close after a short delay so operators can see the
              // confirmation before the popout disappears and the
              // original action fires.
              setTimeout(function () {
                var key = scp03PopoutKey("Authenticate before " + (opts.actionTitle || "action"));
                scp03PopoutClose(tab, key);
              }, 450);
            } else {
              shell.out.appendChild(renderErrorBlock(
                "authenticate failed — session still unauthenticated. "
                + "Check KVN / keys / target AID and retry."
              ));
              if (data.trace) {
                var pre = document.createElement("pre");
                pre.className = "cc-log cc-log-inline";
                pre.textContent = data.trace;
                shell.out.appendChild(pre);
              }
              logBus.emit({
                level: "warn",
                source: actionId,
                message: "FAILED AID=" + (data.target_aid || "??"),
              });
            }
          } catch (err) {
            shell.out.innerHTML = "";
            shell.out.appendChild(renderErrorBlock(String(err && err.message || err)));
          }
        }
      );

      shell.body.appendChild(shell.out);
      try { handle.inputs.target_aid.focus(); } catch (_e) {}

      // The operator may dismiss the popout before authenticating; we
      // can't hook "X button pressed" because the popout system keeps
      // the node alive for reuse, so we sample the auth state a few
      // seconds later — if the popout closed without success, resolve
      // false so the pending action handler sees the cancel.
      var resolved = false;
      var originalResolve = resolve;
      resolve = function (val) {
        if (resolved) return;
        resolved = true;
        originalResolve(val);
      };
      var key = scp03PopoutKey("Authenticate before " + (opts.actionTitle || "action"));
      var popout = tab.popouts && tab.popouts[key];
      if (popout) {
        var closeBtn = popout.querySelector(".cc-popout-close");
        if (closeBtn) {
          closeBtn.addEventListener("click", function () {
            if (!scp03HasLiveAuth(tab)) resolve(false);
          }, { once: true });
        }
      }
    });
  }

  function scp03RunActionWithOutput(out, actionId, inputs, onOk) {
    out.innerHTML = "";
    out.appendChild(loadingEl("running " + actionId + "…"));
    return apiFetch("/api/actions/" + actionId + "/run", {
      method: "POST",
      body: JSON.stringify({ inputs: inputs }),
    }).then(function (resp) {
      out.innerHTML = "";
      if (!resp.ok) {
        var errText = resp.error || (actionId + " failed");
        // 69 82 / "security status not satisfied" slips through the
        // frontend whenever AUTH silently expired between the gate check
        // and dispatch (e.g. card cold-reset by the reader-bar probe,
        // SGP.32 bulk traffic tripped SM). Flip the cached authStatus
        // back to false so the operator's next click re-prompts rather
        // than looping on the same 6982 error.
        if (/\b(69\s?82|security status|no authenticated)/i.test(errText)) {
          var tab = scp03LookupTabForSessionId(inputs && inputs.session_id);
          if (tab) scp03ClearTabAuth(tab);
        }
        out.appendChild(renderErrorBlock(errText));
        return null;
      }
      var sheet = scp03CreateDatasheetRoot();
      out.appendChild(sheet);
      return onOk(resp.data || {}, sheet);
    }).catch(function (err) {
      out.innerHTML = "";
      out.appendChild(renderErrorBlock(String(err && err.message || err)));
      return null;
    });
  }

  function scp03LookupTabForSessionId(sessionId) {
    if (!sessionId) return null;
    var wb = commandState && commandState.scp03Workbench;
    if (!wb || !Array.isArray(wb.tabs)) return null;
    for (var i = 0; i < wb.tabs.length; i++) {
      if (wb.tabs[i] && wb.tabs[i].sessionId === sessionId) return wb.tabs[i];
    }
    return null;
  }

  function scp03RerenderActiveTabBody() {
    // Historical name; originally rebuilt the whole tab body to
    // refresh the auth chip. That turned out to be unsafe while the
    // operator was mid-click (tree / breadcrumb / popout closures
    // captured by the active handler get orphaned, which triggers
    // ``HierarchyRequestError`` in the next replaceChild on the old
    // refs). We now just repaint the auth chip in place — the chip
    // is the only piece of the session panel that depends on
    // ``tab.authStatus``.
    scp03RefreshAuthChip();
  }

  function scp03RefreshAuthChip() {
    // Locate the chip rendered by ``scp03BuildActiveSessionPanel``
    // and flip its class / text to match the current tab auth state.
    // No-op when the session panel isn't mounted (welcome / scanning
    // panel, SAIP workbench active, etc.).
    var header = document.querySelector(".scp03-session-main .cc-scan-header");
    if (!header) return;
    var chip = header.querySelector(".cc-chip-ok, .cc-chip-warn");
    if (!chip) return;
    var tab = scp03GetActiveTab();
    if (!tab) return;
    var st = tab.authStatus || {};
    if (st.authenticated) {
      chip.className = "cc-chip cc-chip-ok";
      chip.textContent = "auth: " + (st.protocol || "SCP03")
        + " / AID=" + (st.targetAid || "ISD")
        + " / KVN=" + (st.kvn || "??");
    } else {
      chip.className = "cc-chip cc-chip-warn";
      chip.textContent = "auth: not authenticated";
    }
  }

  function scp03GateOpen(tab, actionId, handler) {
    // Ribbon / FS-admin click wrapper. Accepts the same
    // ``function () { scp03Show…(tab); }`` style callbacks used
    // throughout the workbench and returns a replacement click
    // handler that first checks whether the action requires auth.
    //
    // Unauthed callers go through the auth prompt; if that resolves
    // true the original handler fires as if the operator had clicked
    // directly. Cancelled prompts short-circuit so we never open the
    // pre-filled action form behind the scenes (operator is likely
    // re-considering the destructive action, not context-switching).
    //
    // Actions without ``requires_auth`` pass straight through — the
    // wrapper is a no-op in that case, which makes it safe to wrap
    // every ribbon button preemptively without audit-tracking the
    // full spec list.
    return function () {
      if (!scp03ActionRequiresAuth(actionId)) {
        handler();
        return;
      }
      var spec = scp03LookupActionSpec(actionId);
      var title = (spec && spec.title) || actionId;
      scp03EnsureAuthed(tab, { actionTitle: title }).then(function (ok) {
        if (ok) handler();
      });
    };
  }

  function scp03RenderTrace(container, trace) {
    // Per operator feedback (2026-04-23): render the captured trace
    // **inline** in the action card body rather than hiding it behind
    // a "Show trace (N lines)" disclosure. Operators want CLI-parity
    // at a glance — the compact printers driving most of these traces
    // already emit screen-ready text, so surfacing it directly removes
    // an unnecessary click. Raw hex disclosures stay unchanged; they
    // remain collapsible because hex is a debug/audit aid, not the
    // primary read-out.
    //
    // Short traces (single "Response: <hex>" style strings) still render
    // OK here — the .cc-log-inline box is tight enough that a one-liner
    // doesn't look out of place. Long traces get a max-height scroller
    // from the CSS so they don't push everything else off-screen.
    if (!trace) return;
    var text = typeof trace === "string" ? trace : String(trace);
    if (text.trim().length === 0) return;
    var pre = document.createElement("pre");
    pre.className = "cc-log cc-log-inline";
    pre.textContent = text;
    container.appendChild(pre);
  }

  async function scp03ShowSetStatus(tab) {
    var card = scp03BuildExtrasCard("Set status (LCS byte)");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "Requires an authenticated secure session (Auth SCP03/SCP02). "
        + "Changes the lifecycle state of the named AID."
    );
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "target_aid", label: "Target AID", placeholder: "A00000015141434C00", required: true },
        { name: "state_byte", label: "State", placeholder: "07", required: true,
          help: "03=INSTALLED • 07=SELECTABLE • 0F=PERSONALIZED • 80=LOCKED • 83=TERMINATED" },
      ],
      "Set status",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.set_status", {
          session_id: tab.sessionId,
          target_aid: (values.target_aid || "").trim(),
          state_byte: (values.state_byte || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Target AID", value: data.target_aid || "" },
            { label: "State byte", value: data.state_byte || "" },
            { label: "State name", value: data.state_name || "" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: "warn",
            source: "scp03.set_status",
            message: "SET-STATUS " + (data.target_aid || "?") + " -> " + (data.state_name || data.state_byte || "?"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowLockUnlock(tab, actionId, title, logVerb) {
    var card = scp03BuildExtrasCard(title);
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "target_aid", label: "Target AID", placeholder: "ARAM / A0...00", required: true },
      ],
      logVerb,
      async function (values) {
        await scp03RunActionWithOutput(out, actionId, {
          session_id: tab.sessionId,
          target_aid: (values.target_aid || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Target AID", value: data.target_aid || "" },
            { label: "State byte", value: data.state_byte || "" },
            { label: "State name", value: data.state_name || "" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: "warn",
            source: actionId,
            message: logVerb + " " + (data.target_aid || "?") + " -> " + (data.state_name || "?"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowDelete(tab) {
    var card = scp03BuildExtrasCard("Delete application / package");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "Irreversible on real cards. Requires authenticated session. "
        + "Type the AID again in the confirmation field to proceed."
    );
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    var handle = scp03BuildInlineForm(
      card,
      [
        { name: "target_aid", label: "Target AID", placeholder: "A00000015141434C00", required: true },
        { name: "confirm_aid", label: "Confirm AID", placeholder: "(re-enter AID)", required: true,
          help: "Type the AID again to arm the DELETE command." },
        { name: "recursive", label: "Recursive", value: "true",
          help: "'true' = delete child objects (P2=80), 'false' = P2=00." },
      ],
      "Delete",
      async function (values) {
        var aid = (values.target_aid || "").trim().toUpperCase().replace(/\s+/g, "");
        var conf = (values.confirm_aid || "").trim().toUpperCase().replace(/\s+/g, "");
        if (aid.length === 0 || aid !== conf) {
          out.innerHTML = "";
          out.appendChild(renderErrorBlock("confirmation AID does not match target_aid"));
          return;
        }
        var rec = String(values.recursive || "").trim().toLowerCase();
        var recursive = !(rec === "false" || rec === "no" || rec === "0");
        await scp03RunActionWithOutput(out, "scp03.delete", {
          session_id: tab.sessionId,
          target_aid: aid,
          recursive: recursive,
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Target AID", value: data.target_aid || "" },
            { label: "Recursive", value: data.recursive ? "yes" : "no" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: "warn",
            source: "scp03.delete",
            message: "DELETE " + (data.target_aid || "?") + " recursive=" + (data.recursive ? "1" : "0"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowStoreData(tab) {
    var card = scp03BuildExtrasCard("STORE DATA");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "data", label: "Data (hex)", placeholder: "e.g. BF2D00", required: true },
        { name: "p1", label: "P1", placeholder: "(auto)" },
        { name: "p2", label: "P2", placeholder: "(auto)",
          help: "Blank = auto-chunk with GP block index. Otherwise provide both." },
      ],
      "STORE DATA",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.store_data", {
          session_id: tab.sessionId,
          data: (values.data || "").trim(),
          p1: (values.p1 || "").trim(),
          p2: (values.p2 || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Bytes", value: data.bytes || 0 },
            { label: "P1/P2", value: (data.p1 || "auto") + " / " + (data.p2 || "auto") },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: "info",
            source: "scp03.store_data",
            message: "STORE-DATA bytes=" + (data.bytes || 0),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowUpdateBinary(tab) {
    var card = scp03BuildExtrasCard("UPDATE BINARY");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "hex_data", label: "Data (hex)", required: true,
          help: "Full content to write. Length becomes Lc." },
        { name: "path", label: "Path",
          value: tab.selectedPath || "",
          placeholder: "MF/EF_ICCID",
          help: "Optional path to SELECT first. Blank = use current selection." },
      ],
      "UPDATE BINARY",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.update_binary", {
          session_id: tab.sessionId,
          hex_data: (values.hex_data || "").trim(),
          path: (values.path || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Path", value: data.path || "(current)" },
            { label: "SELECTed", value: data.selected === false ? "failed" : (data.selected ? "yes" : "n/a") },
            { label: "Bytes", value: data.bytes || 0 },
            { label: "SW", value: data.sw || "" },
            { label: "OK", value: data.ok ? "yes" : "no" },
          ]);
          if (data.select_trace) {
            scp03DatasheetAppendTraceMain(sheet, data.select_trace, "");
          }
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: "scp03.update_binary",
            message: "UPDATE-BIN path=" + (data.path || "(current)") + " SW=" + (data.sw || "????") + " bytes=" + (data.bytes || 0),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowUpdateRecord(tab) {
    var card = scp03BuildExtrasCard("UPDATE RECORD");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "record", label: "Record #", placeholder: "1", required: true },
        { name: "hex_data", label: "Data (hex)", required: true },
        { name: "path", label: "Path",
          value: tab.selectedPath || "",
          placeholder: "MF/ADF_USIM/EF_MSISDN",
          help: "Optional path to SELECT first. Blank = use current selection." },
      ],
      "UPDATE RECORD",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.update_record", {
          session_id: tab.sessionId,
          record: (values.record || "").trim(),
          hex_data: (values.hex_data || "").trim(),
          path: (values.path || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Path", value: data.path || "(current)" },
            { label: "Record", value: data.record || 0 },
            { label: "SELECTed", value: data.selected === false ? "failed" : (data.selected ? "yes" : "n/a") },
            { label: "Bytes", value: data.bytes || 0 },
            { label: "SW", value: data.sw || "" },
            { label: "OK", value: data.ok ? "yes" : "no" },
          ]);
          if (data.select_trace) {
            scp03DatasheetAppendTraceMain(sheet, data.select_trace, "");
          }
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: "scp03.update_record",
            message: "UPDATE-REC path=" + (data.path || "(current)")
              + " rec=" + (data.record || 0) + " SW=" + (data.sw || "????"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowValidate(tab) {
    var card = scp03BuildExtrasCard("Validate profile");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "scope", label: "Scope", value: "ALL",
          help: "ALL | MF | USIM | ISIM" },
      ],
      "Validate",
      async function (values) {
        var scopeVal = String(values.scope || "ALL").trim().toUpperCase() || "ALL";
        await scp03RunActionWithOutput(out, "scp03.validate", {
          session_id: tab.sessionId,
          scope: scopeVal,
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Scope", value: data.scope || "" },
            { label: "Passed", value: data.passed || 0 },
            { label: "Failed", value: data.failed || 0 },
            { label: "Warnings", value: data.warnings || 0 },
            { label: "OK", value: data.ok ? "yes" : "no" },
          ]);
          if (data.error) {
            sheet.appendChild(renderErrorBlock(data.error));
          }
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: "scp03.validate",
            message: "VALIDATE " + (data.scope || "?") + " pass=" + (data.passed || 0)
              + " fail=" + (data.failed || 0) + " warn=" + (data.warnings || 0),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowCertInfo(tab) {
    var card = scp03BuildExtrasCard("ECASD / certificate info");
    if (!card) return;
    card.appendChild(loadingEl("walking ECASD tags…"));
    try {
      var resp = await apiFetch("/api/actions/scp03.cert_info/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { session_id: tab.sessionId } }),
      });
      scp03ClearLoading(card);
      if (!resp.ok) {
        card.appendChild(renderErrorBlock(resp.error || "cert_info failed"));
        return;
      }
      var data = resp.data || {};
      var ds = scp03CreateDatasheetRoot();
      scp03DatasheetAppendMetaKvl(ds, [
        { label: "Target", value: data.target_aid || "" },
        { label: "Tags", value: (data.entries || []).length },
      ]);
      (data.entries || []).forEach(function (entry) {
        var block = document.createElement("div");
        block.className = "cc-wb-record-block";
        var heading = document.createElement("h5");
        heading.textContent = entry.label + "  (tag " + entry.tag + ", SW " + entry.sw + ")";
        block.appendChild(heading);
        if (!entry.present) {
          var note = document.createElement("p");
          note.className = "cc-empty";
          note.textContent = "(not present)";
          block.appendChild(note);
        } else {
          if (entry.decoded) {
            var json = document.createElement("pre");
            json.className = "cc-json";
            json.textContent = JSON.stringify(entry.decoded, null, 2);
            block.appendChild(json);
          }
          if (entry.hex) {
            block.appendChild(renderHexBlock(entry.hex));
          }
        }
        ds.appendChild(block);
      });
      card.appendChild(ds);
      logBus.emit({
        level: "info",
        source: "scp03.cert_info",
        message: "ECASD tags=" + ((data.entries || []).length),
      });
    } catch (err) {
      scp03ClearLoading(card);
      card.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
  }

  async function scp03ShowExportEuicc(tab) {
    var card = scp03BuildExtrasCard("Export eUICC report (YAML)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "output_path", label: "Output file", placeholder: "euicc_report.yaml",
          help: "Blank = euicc_report.yaml in CWD." },
        { name: "standard", label: "Standard", value: "SGP.32",
          help: "SGP.22 or SGP.32." },
      ],
      "Export",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.export_euicc", {
          session_id: tab.sessionId,
          output_path: (values.output_path || "").trim(),
          standard: (values.standard || "SGP.32").trim().toUpperCase(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Output", value: data.output_path || "" },
            { label: "Standard", value: data.standard || "" },
            { label: "EID", value: data.eid || "" },
            { label: "Profiles", value: (data.profiles || []).length },
            { label: "CPLC", value: data.cplc_hex ? "captured" : "(n/a)" },
            { label: "OK", value: data.ok ? "yes" : "no" },
          ]);
          if (data.error) {
            sheet.appendChild(renderErrorBlock(data.error));
          }
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: "scp03.export_euicc",
            message: "export-euicc -> " + (data.output_path || "?"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowExportKeybag(tab) {
    var card = scp03BuildExtrasCard("Export SCP03 keybag");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "Writes live SCP03 session keys to disk — keep the resulting "
        + "file paired with its .pcap and protect it accordingly."
    );
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "output_path", label: "Output file", placeholder: "scp03_session.keys.json",
          help: "Blank = scp03_session.keys.json in CWD." },
        { name: "label", label: "Label", value: "scp03-live",
          help: "Stored alongside the keys (multi-session bags are merged)." },
      ],
      "Export keybag",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.export_keybag", {
          session_id: tab.sessionId,
          output_path: (values.output_path || "").trim(),
          label: (values.label || "scp03-live").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Output", value: data.output_path || "" },
            { label: "Label", value: data.label || "" },
            { label: "Target AID", value: data.target_aid || "" },
            { label: "OK", value: data.ok ? "yes" : "no" },
          ]);
          if (data.error) {
            sheet.appendChild(renderErrorBlock(data.error));
          }
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: "scp03.export_keybag",
            message: "keybag -> " + (data.output_path || "?"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  // -- C-4: eUICC telemetry + lifecycle + snapshots + crypto ------------

  async function scp03ShowGetEid(tab) {
    var card = scp03BuildExtrasCard("EID (ES10c.GetEID)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out cc-wb-extras-out--stretch";
    card.appendChild(out);
    await scp03RunActionWithOutput(out, "scp03.get_eid", {
      session_id: tab.sessionId,
    }, function (data, sheet) {
      scp03DatasheetAppendMetaKvl(sheet, [
        { label: "EID", value: data.eid || "(empty)" },
        { label: "SW", value: data.sw || "" },
      ]);
      scp03DatasheetAppendTraceMain(sheet, data.trace, "Printer output");
      logBus.emit({
        level: data.eid ? "info" : "warn",
        source: "scp03.get_eid",
        message: "EID = " + (data.eid || "(unavailable)"),
      });
    });
  }

  function scp03AppendGetCertsEuiccView(sheet, data) {
    var payload = data || {};
    sheet.innerHTML = "";
    scp03DatasheetAppendMetaKvl(sheet, [
      { label: "SW", value: payload.sw || "" },
      { label: "Length", value: (payload.raw_hex || "").length / 2 + " bytes" },
    ]);
    if (payload.parse_error) {
      scp03DatasheetAppendWarn(sheet, "decode: " + String(payload.parse_error));
    }
    var main = document.createElement("div");
    main.className = "cc-action-datasheet-main cc-action-datasheet-main--decoded";
    var hdr = document.createElement("div");
    hdr.className = "cc-action-datasheet-main-head cc-action-datasheet-main-head--split";
    var ttl = document.createElement("span");
    ttl.className = "cc-action-datasheet-main-title";
    ttl.textContent = "Decoded";
    hdr.appendChild(ttl);
    var sub = document.createElement("span");
    sub.className = "cc-action-datasheet-main-sub";
    sub.textContent = "BF56 GetCertsResponse";
    hdr.appendChild(sub);
    main.appendChild(hdr);
    var decodedObj = payload.decoded;
    var hasDecoded = decodedObj && typeof decodedObj === "object"
      && !Array.isArray(decodedObj)
      && Object.keys(decodedObj).length > 0;
    if (hasDecoded) {
      main.appendChild(scp03RenderGetCertsDecoded(decodedObj));
    } else {
      var emptyPv = document.createElement("p");
      emptyPv.className = "cc-empty";
      emptyPv.textContent = "(no structured decode — inspect compact printer trace or raw TLV)";
      main.appendChild(emptyPv);
    }
    if (payload.trace && String(payload.trace).trim().length > 0) {
      var traceFold = document.createElement("details");
      traceFold.className = "cc-details cc-action-datasheet-trace";
      var traceSum = document.createElement("summary");
      traceSum.textContent = "Compact printer trace (CLI)";
      traceFold.appendChild(traceSum);
      scp03RenderTrace(traceFold, payload.trace);
      main.appendChild(traceFold);
    }
    sheet.appendChild(main);
    scp03DatasheetAppendRawHex(
      sheet,
      payload.raw_hex,
      "Raw BF56 response (" + ((payload.raw_hex || "").length / 2) + " bytes)"
    );
  }

  function scp03RenderGetCertsDecoded(decodedObj) {
    var eum = decodedObj.eumCertificate;
    var euicc = decodedObj.euiccCertificate;
    var hasScoped = (eum && typeof eum === "object") || (euicc && typeof euicc === "object");
    if (!hasScoped) {
      return renderDecodedBlock(decodedObj, null, { omitHead: true });
    }
    var wrap = document.createElement("div");
    wrap.className = "cc-getcerts-grid";
    if (eum && typeof eum === "object") {
      wrap.appendChild(scp03RenderGetCertsScopeCard("EUM certificate", eum));
    }
    if (euicc && typeof euicc === "object") {
      wrap.appendChild(scp03RenderGetCertsScopeCard("eUICC certificate", euicc));
    }
    return wrap;
  }

  function scp03RenderGetCertsScopeCard(title, block) {
    var card = document.createElement("section");
    card.className = "cc-getcerts-cert";
    var head = document.createElement("div");
    head.className = "cc-getcerts-cert-head";
    var titleEl = document.createElement("h4");
    titleEl.className = "cc-getcerts-cert-title";
    titleEl.textContent = title;
    head.appendChild(titleEl);
    var certCount = Array.isArray(block.certificates) ? block.certificates.length : 0;
    var chip = document.createElement("span");
    chip.className = "cc-chip";
    chip.innerHTML = "cert entries: <code>" + certCount + "</code>";
    head.appendChild(chip);
    card.appendChild(head);

    var info = {};
    Object.keys(block).forEach(function (key) {
      if (key === "rawHex" || key === "certificates") return;
      info[key] = block[key];
    });
    if (Object.keys(info).length > 0) {
      card.appendChild(renderDecodedBlock(info, null, { omitHead: true }));
    }

    if (certCount > 0) {
      var certDetails = document.createElement("details");
      certDetails.className = "cc-details cc-getcerts-cert-list";
      var certSummary = document.createElement("summary");
      certSummary.textContent = "Decoded certificate list (" + certCount + ")";
      certDetails.appendChild(certSummary);
      block.certificates.forEach(function (certEntry, idx) {
        var certCard = document.createElement("details");
        certCard.className = "cc-details cc-getcerts-cert-item";
        var certHead = document.createElement("summary");
        certHead.textContent = "Certificate #" + (idx + 1);
        certCard.appendChild(certHead);
        certCard.appendChild(renderDecodedBlock(certEntry, null, { omitHead: true }));
        certDetails.appendChild(certCard);
      });
      card.appendChild(certDetails);
    }

    if (block.rawHex) {
      var rawDetails = document.createElement("details");
      rawDetails.className = "cc-details cc-getcerts-cert-raw";
      var rawSummary = document.createElement("summary");
      rawSummary.textContent = "Certificate raw DER (" + (String(block.rawHex).length / 2) + " bytes)";
      rawDetails.appendChild(rawSummary);
      rawDetails.appendChild(renderHexBlock(String(block.rawHex)));
      card.appendChild(rawDetails);
    }
    return card;
  }

  async function scp03ShowEuiccCerts(tab) {
    var card = scp03BuildExtrasCard("GetCerts (ES10b)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out cc-wb-extras-out--stretch";
    card.appendChild(out);
    await scp03RunActionWithOutput(out, "scp03.get_euicc_certs", {
      session_id: tab.sessionId,
    }, function (data, sheet) {
      scp03AppendGetCertsEuiccView(sheet, data);
    });
  }

  async function scp03ShowEuiccConfiguredData(tab) {
    var card = scp03BuildExtrasCard("GetEuiccConfiguredData (ES10a)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out cc-wb-extras-out--stretch";
    card.appendChild(out);
    await scp03RunActionWithOutput(out, "scp03.get_euicc_configured_data", {
      session_id: tab.sessionId,
    }, function (data, sheet) {
      var metaRows = [
        { label: "SW", value: data.sw || "" },
      ];
      var decoded = data.decoded || {};
      if (decoded.default_smdp) {
        metaRows.push({ label: "Default SM-DP+", value: String(decoded.default_smdp) });
      }
      if (decoded.root_smds_primary) {
        metaRows.push({ label: "Root SM-DS", value: String(decoded.root_smds_primary) });
      }
      var pkids = decoded.allowed_ci_pkid || [];
      if (pkids.length > 0) {
        metaRows.push({ label: "Allowed CI PKIDs", value: pkids.join(", ") });
      }
      var additional = decoded.root_smds_additional || [];
      if (additional.length > 0) {
        metaRows.push({ label: "Additional SM-DS", value: additional.join(", ") });
      }
      scp03DatasheetAppendMetaKvl(sheet, metaRows);
      scp03DatasheetAppendTraceMain(sheet, data.trace, "Console trace");
      scp03DatasheetAppendRawHex(
        sheet,
        data.raw_hex,
        "Raw BF3C response (" + ((data.raw_hex || "").length / 2) + " bytes)"
      );
    });
  }

  async function scp03ShowSgp32AllData(tab) {
    var card = scp03BuildExtrasCard("SGP.32 bulk telemetry");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out cc-wb-extras-out--stretch";
    card.appendChild(out);
    await scp03RunActionWithOutput(out, "scp03.get_sgp32_all_data", {
      session_id: tab.sessionId,
    }, function (data, sheet) {
      scp03RenderSgp32BulkReport(sheet, data);
      var summary = data && data.summary ? data.summary : {};
      logBus.emit({
        level: "info",
        source: "scp03.get_sgp32_all_data",
        message: "bulk telemetry sweep complete: "
          + (summary.ok || 0) + " ok, "
          + (summary.empty || 0) + " empty, "
          + (summary.error || 0) + " error",
      });
    });
  }

  function scp03RenderSgp32BulkReport(container, data) {
    // Render the SGP.32 bulk retrieval as a proper structured module:
    // one titled sub-card per ES10 section (Scan, RAT, Notifications,
    // eIM config, Certs). Each sub-card shows the parsed lines (via
    // scp03RenderTextLines — KV aware), a status pill, the ES10 tag,
    // and keeps the raw hex + raw trace tucked behind <details> so the
    // output no longer looks like a terminal dump.
    var payload = data || {};
    var sections = Array.isArray(payload.sections) ? payload.sections : [];
    var summary = payload.summary || {};

    // Top header + summary chip row.
    var header = document.createElement("div");
    header.className = "cc-sgp32-header";
    var headerChips = [];
    headerChips.push('<span class="cc-chip">standard: <code>'
      + escapeHtml(payload.standard || "SGP.32") + '</code></span>');
    headerChips.push('<span class="cc-chip">sections: <code>'
      + (summary.total || sections.length) + '</code></span>');
    if (summary.ok !== undefined) {
      headerChips.push('<span class="cc-chip cc-chip-ok">ok: <code>'
        + summary.ok + '</code></span>');
    }
    if (summary.empty) {
      headerChips.push('<span class="cc-chip cc-chip-warn">empty: <code>'
        + summary.empty + '</code></span>');
    }
    if (summary.error) {
      headerChips.push('<span class="cc-chip cc-chip-err">error: <code>'
        + summary.error + '</code></span>');
    }
    header.innerHTML = headerChips.join(" ");
    container.appendChild(header);

    if (sections.length === 0) {
      var none = document.createElement("p");
      none.className = "hint";
      none.textContent = "(no sections returned — fallback trace below)";
      container.appendChild(none);
      scp03RenderTrace(container, payload.trace || "");
      return;
    }

    var grid = document.createElement("div");
    grid.className = "cc-sgp32-grid";
    sections.forEach(function (section) {
      grid.appendChild(scp03BuildSgp32SectionCard(section));
    });
    container.appendChild(grid);

    // The per-section cards already inline their own traces, so a
    // flat stdout concatenation would just duplicate everything above.
    // We keep it around for bug-report copying, but behind an explicit
    // collapsed <details> built inline here (scp03RenderTrace now emits
    // inline <pre> directly, so we can't reuse it for the disclosure).
    var footerText = typeof payload.trace === "string" ? payload.trace : "";
    if (footerText.trim().length > 0) {
      var footer = document.createElement("div");
      footer.className = "cc-sgp32-footer";
      var details = document.createElement("details");
      details.className = "cc-trace-block";
      var lineCount = footerText.split(/\r?\n/).length;
      var summary = document.createElement("summary");
      summary.textContent = "Full merged trace (" + lineCount + " line"
        + (lineCount === 1 ? "" : "s")
        + ") — copy for bug reports";
      details.appendChild(summary);
      var pre = document.createElement("pre");
      pre.className = "cc-log";
      pre.textContent = footerText;
      details.appendChild(pre);
      footer.appendChild(details);
      container.appendChild(footer);
    }
  }

  function scp03BuildSgp32SectionCard(section) {
    var entry = section || {};
    var host = document.createElement("section");
    host.className = "cc-sgp32-section cc-sgp32-status-"
      + escapeHtml(entry.status || "unknown");
    installMaximizable(host);

    // Header — title, ES10 tag, status pill.
    var hdr = document.createElement("header");
    hdr.className = "cc-sgp32-section-head";
    var title = document.createElement("h4");
    title.className = "cc-sgp32-section-title";
    title.textContent = entry.title || entry.key || "(section)";
    hdr.appendChild(title);

    var chips = document.createElement("div");
    chips.className = "cc-sgp32-section-chips";
    if (entry.es10_tag) {
      var tagChip = document.createElement("span");
      tagChip.className = "cc-chip";
      tagChip.innerHTML = 'ES10: <code>' + escapeHtml(entry.es10_tag) + '</code>';
      chips.appendChild(tagChip);
    }
    var statusChip = document.createElement("span");
    statusChip.className = "cc-chip cc-sgp32-status-chip cc-sgp32-status-chip-"
      + escapeHtml(entry.status || "unknown");
    statusChip.textContent = entry.status || "unknown";
    chips.appendChild(statusChip);
    hdr.appendChild(chips);
    host.appendChild(hdr);

    // Optional note — shown above the body so operators see the
    // "why" when a section is empty / errored.
    if (entry.note) {
      var note = document.createElement("p");
      note.className = "hint cc-sgp32-section-note";
      note.textContent = entry.note;
      host.appendChild(note);
    }

    // Per-section trace — rendered inline via the shared helper (which
    // now emits a <pre class="cc-log cc-log-inline"> directly, no more
    // "Show trace" disclosure). Compact-printer stdout mirrors the CLI
    // screen dump so this gives operators CLI-parity at a glance.
    var traceText = typeof entry.trace === "string" ? entry.trace : "";
    if (traceText.trim().length > 0) {
      scp03RenderTrace(host, traceText);
    } else if (entry.status === "ok") {
      var placeholder = document.createElement("p");
      placeholder.className = "hint";
      placeholder.textContent = "(retrieval ok — printer emitted no output)";
      host.appendChild(placeholder);
    }

    // Hex body — collapsed by default (as per the user's explicit
    // request to keep the raw-hex disclosure behaviour unchanged).
    if (entry.hex) {
      var hexDetails = document.createElement("details");
      hexDetails.className = "cc-trace-block cc-action-datasheet-raw";
      var hexSummary = document.createElement("summary");
      hexSummary.textContent = "Raw hex (" + (entry.hex.length / 2) + " byte"
        + (entry.hex.length === 2 ? "" : "s") + ")";
      hexDetails.appendChild(hexSummary);
      hexDetails.appendChild(renderHexBlock(entry.hex));
      host.appendChild(hexDetails);
    }

    return host;
  }

  async function scp03ShowLifecycle(tab, action) {
    var labelMap = {
      enable: "Enable profile",
      disable: "Disable profile",
      delete: "Delete profile",
    };
    var actionIdMap = {
      enable: "scp03.enable_profile",
      disable: "scp03.disable_profile",
      delete: "scp03.delete_profile",
    };
    var actionLabel = labelMap[action] || action;
    var actionId = actionIdMap[action];
    if (!actionId) return;

    var card = scp03BuildExtrasCard(actionLabel);
    if (!card) return;
    if (action === "delete") {
      scp03BuildDestructiveBanner(
        card,
        "Irreversible: ES10c.DeleteProfile removes the profile from the "
          + "eUICC. Type the target AID or ICCID twice to proceed."
      );
    } else if (action === "disable") {
      scp03BuildDestructiveBanner(
        card,
        "Disabling the active profile drops the subscriber identity "
          + "until another profile is enabled."
      );
    }
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";

    var formFields = [
      { name: "target", label: "Target (AID / ICCID)", required: true,
        placeholder: "A0000005591010…  or  89XXXXXXXXXXXXXXXXXF" },
    ];
    if (action === "delete") {
      formFields.push({
        name: "confirm",
        label: "Confirm target",
        required: true,
        placeholder: "type the target again",
        help: "Must match exactly; typed back to guard against fat-finger deletions.",
      });
    }

    scp03BuildInlineForm(
      card,
      formFields,
      actionLabel,
      async function (values) {
        var inputs = {
          session_id: tab.sessionId,
          target: (values.target || "").trim(),
        };
        if (action === "delete") {
          inputs.confirm = (values.confirm || "").trim();
        }
        await scp03RunActionWithOutput(out, actionId, inputs, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Action", value: data.action || action },
            { label: "Target", value: data.target || "" },
            { label: "OK", value: data.ok ? "yes" : "no" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: actionId,
            message: actionLabel + " " + (data.target || "") + " -> " + (data.ok ? "ok" : "failed"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowDeriveOpc(tab) {
    var card = scp03BuildExtrasCard("Derive OPc (Milenage)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "ki", label: "Ki (hex)", required: true, placeholder: "32 hex chars" },
        { name: "op", label: "OP (hex)", required: true, placeholder: "32 hex chars" },
      ],
      "Derive OPc",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.derive_opc", {
          ki: (values.ki || "").trim(),
          op: (values.op || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Ki", value: data.ki || "" },
            { label: "OP", value: data.op || "" },
            { label: "OPc", value: data.opc || "" },
          ]);
          logBus.emit({
            level: "info",
            source: "scp03.derive_opc",
            message: "OPc derived: " + (data.opc || ""),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowAuthTestVector(tab) {
    var card = scp03BuildExtrasCard("Milenage auth test vector (TS 35.207)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    card.appendChild(out);
    await scp03RunActionWithOutput(out, "scp03.run_auth_test_vector", {}, function (data, sheet) {
      var inputs = data.inputs || {};
      scp03DatasheetAppendMetaKvl(sheet, [
        { label: "RAND", value: inputs.RAND || "" },
        { label: "Ki", value: inputs.Ki || "" },
        { label: "OP", value: inputs.OP || "" },
        { label: "SQN", value: inputs.SQN || "" },
        { label: "AMF", value: inputs.AMF || "" },
      ]);

      var rows = (data.rows || []).map(function (row) {
        return {
          Label: row.label,
          Derived: row.derived,
          Expected: row.expected,
          Match: row.match ? "\u2713" : "\u2717",
        };
      });
      scp03DatasheetAppendMain(sheet, renderObjectTable(rows));

      var summary = document.createElement("p");
      summary.className = data.all_match ? "cc-empty" : "cc-warn";
      summary.textContent = data.all_match
        ? "All vectors match the published expected values."
        : "Mismatches: " + (data.mismatches || []).join(", ");
      sheet.appendChild(summary);

      logBus.emit({
        level: data.all_match ? "info" : "error",
        source: "scp03.run_auth_test_vector",
        message: data.all_match ? "auth vector OK" : "auth vector mismatch",
      });
    });
  }

  async function scp03ShowSetGoldProfile(tab) {
    var card = scp03BuildExtrasCard("Set gold profile");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "path", label: "Gold YAML path", required: true,
          placeholder: "/path/to/gold_profile.yaml",
          help: "YAML from the shell REPORT wizard (must contain euicc_report section)." },
        { name: "standard", label: "Standard", value: "SGP.32",
          help: "SGP.32 / SGP.22 / SGP.02" },
        { name: "authenticate_sd", label: "Authenticate SD", value: "false",
          help: "true/false — run SCP03 auth before MNO-SD phase of combined diff." },
      ],
      "Save gold profile",
      async function (values) {
        var authRaw = String(values.authenticate_sd || "false").trim().toLowerCase();
        var authFlag = (authRaw === "true" || authRaw === "1" || authRaw === "yes");
        await scp03RunActionWithOutput(out, "scp03.set_gold_profile", {
          path: (values.path || "").trim(),
          standard: (values.standard || "SGP.32").trim(),
          authenticate_sd: authFlag,
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Path", value: data.path || "" },
            { label: "Standard", value: data.standard || "" },
            { label: "Authenticate SD", value: data.authenticate_sd ? "true" : "false" },
            { label: "File exists", value: data.exists ? "yes" : "no (saved anyway)" },
          ]);
          logBus.emit({
            level: "info",
            source: "scp03.set_gold_profile",
            message: "gold profile -> " + (data.path || ""),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowShowGoldProfile(tab) {
    var card = scp03BuildExtrasCard("Gold profile (persisted)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    card.appendChild(out);
    await scp03RunActionWithOutput(out, "scp03.show_gold_profile", {}, function (data, sheet) {
      scp03DatasheetAppendMetaKvl(sheet, [
        { label: "Path", value: data.path || "(not set)" },
        { label: "Standard", value: data.standard || "SGP.32" },
        { label: "Authenticate SD", value: data.authenticate_sd ? "true" : "false" },
        { label: "File exists", value: data.path ? (data.exists ? "yes" : "no") : "—" },
      ]);
      if (data.error) {
        sheet.appendChild(renderErrorBlock(data.error));
      }
    });
  }

  async function scp03ShowClearGoldProfile(tab) {
    if (!window.confirm("Clear the persisted gold-profile path? (standard + auth flag are kept.)")) {
      return;
    }
    var card = scp03BuildExtrasCard("Clear gold profile");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    card.appendChild(out);
    await scp03RunActionWithOutput(out, "scp03.clear_gold_profile", {}, function (data, sheet) {
      scp03DatasheetAppendMetaKvl(sheet, [
        { label: "Cleared", value: data.cleared ? "yes" : "no" },
        { label: "Standard kept", value: data.standard || "" },
        { label: "Auth flag kept", value: data.authenticate_sd ? "true" : "false" },
      ]);
      logBus.emit({
        level: "info",
        source: "scp03.clear_gold_profile",
        message: "gold profile cleared",
      });
    });
  }

  async function scp03ShowProfileDiff(tab) {
    var card = scp03BuildExtrasCard("Profile diff (eUICC scope)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "gold_path", label: "Gold YAML override",
          placeholder: "blank = use persisted gold path",
          help: "Blank = fall back to the persisted gold-profile.path." },
        { name: "standard", label: "Standard override",
          placeholder: "blank = use persisted standard",
          help: "Blank / SGP.32 / SGP.22 / SGP.02." },
      ],
      "Run diff",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.profile_diff", {
          session_id: tab.sessionId,
          gold_path: (values.gold_path || "").trim(),
          standard: (values.standard || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Gold", value: data.gold_path || "" },
            { label: "Standard", value: data.standard || "" },
            { label: "Scope", value: data.scope || "euicc" },
            { label: "Match", value: data.match ? "yes" : "no" },
            { label: "Live generated", value: data.live_generated || "" },
          ]);
          if (!data.match && data.diff) {
            var pre = document.createElement("pre");
            pre.className = "cc-log";
            pre.textContent = data.diff;
            sheet.appendChild(pre);
          }
          logBus.emit({
            level: data.match ? "info" : "warn",
            source: "scp03.profile_diff",
            message: data.match ? "profile diff: OK" : "profile diff: mismatch",
          });
        });
      }
    );
    card.appendChild(out);
  }

  // -- C-4 Tier-3: config / aid registry / defaults reset ---------------

  function scp03RenderAidEntries(out, entries) {
    if (!entries || entries.length === 0) {
      var p = document.createElement("p");
      p.className = "cc-empty";
      p.textContent = "(aid.txt is empty)";
      out.appendChild(p);
      return;
    }
    var rows = entries.map(function (entry) {
      return {
        Name: entry.name || "",
        AID: entry.aid || "",
        Role: entry.role || "",
      };
    });
    out.appendChild(renderObjectTable(rows));
  }

  async function scp03ShowShowConfig(tab) {
    var card = scp03BuildExtrasCard("SCP03 config (persisted)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";

    // Toggle: mask secrets. Default true.
    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var maskLbl = document.createElement("label");
    maskLbl.className = "cc-toggle";
    var maskBox = document.createElement("input");
    maskBox.type = "checkbox";
    maskBox.checked = true;
    maskLbl.appendChild(maskBox);
    var maskTxt = document.createElement("span");
    maskTxt.textContent = "Mask key material";
    maskLbl.appendChild(maskTxt);
    bar.appendChild(maskLbl);
    var refreshBtn = document.createElement("button");
    refreshBtn.type = "button";
    refreshBtn.className = "btn btn-primary";
    refreshBtn.textContent = "Refresh";
    bar.appendChild(refreshBtn);
    card.appendChild(bar);
    card.appendChild(out);

    async function refresh() {
      await scp03RunActionWithOutput(out, "scp03.show_config", {
        mask_secrets: maskBox.checked,
      }, function (data, sheet) {
        var keys = data.keys || {};
        var keyRows = Object.keys(keys).sort().map(function (slot) {
          return { Slot: slot, Value: keys[slot] };
        });

        var hdr = document.createElement("h5");
        hdr.textContent = "Keys (module_state=" + (data.module_state_name || "") + ")";
        sheet.appendChild(hdr);
        sheet.appendChild(renderObjectTable(keyRows));

        var goldRows = Object.keys(data.gold_profile || {}).sort().map(function (k) {
          return { Field: k, Value: (data.gold_profile || {})[k] };
        });
        var goldHdr = document.createElement("h5");
        goldHdr.textContent = "Gold profile";
        sheet.appendChild(goldHdr);
        if (goldRows.length === 0) {
          var emptyP = document.createElement("p");
          emptyP.className = "cc-empty";
          emptyP.textContent = "(no gold profile persisted)";
          sheet.appendChild(emptyP);
        } else {
          sheet.appendChild(renderObjectTable(goldRows));
        }

        var aidHdr = document.createElement("h5");
        aidHdr.textContent = "AID registry (" + (data.aid_count || 0) + " entries — " + (data.aid_file || "") + ")";
        sheet.appendChild(aidHdr);
        scp03RenderAidEntries(sheet, data.aid_entries || []);

        if (data.inventory_error) {
          sheet.appendChild(renderErrorBlock("inventory: " + data.inventory_error));
        }
        if (data.aid_error) {
          sheet.appendChild(renderErrorBlock("aid.txt: " + data.aid_error));
        }
      });
    }

    refreshBtn.addEventListener("click", refresh);
    maskBox.addEventListener("change", refresh);
    await refresh();
  }

  async function scp03ShowSetAidAlias(tab) {
    var card = scp03BuildExtrasCard("AID alias (aid.txt registry)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "name", label: "Alias name", required: true,
          placeholder: "ISD",
          help: "1-16 chars of [A-Z0-9_-]; case is normalized to upper." },
        { name: "aid", label: "AID (hex)",
          placeholder: "A0000005591010FFFFFFFF8900000100",
          help: "Even-length hex. Leave blank if delete=true." },
        { name: "delete", label: "Delete (true/false)", value: "false",
          help: "true = remove the alias instead of adding/updating." },
      ],
      "Apply",
      async function (values) {
        var deleteRaw = String(values.delete || "false").trim().toLowerCase();
        var deleteFlag = (deleteRaw === "true" || deleteRaw === "1" || deleteRaw === "yes");
        await scp03RunActionWithOutput(out, "scp03.set_aid_alias", {
          name: (values.name || "").trim(),
          aid: (values.aid || "").trim(),
          delete: deleteFlag,
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Action", value: data.action || "" },
            { label: "Name", value: data.name || "" },
            { label: "AID", value: data.aid || "(deleted)" },
            { label: "Total entries", value: data.count == null ? "" : String(data.count) },
            { label: "Path", value: data.path || "" },
          ]);
          logBus.emit({
            level: "info",
            source: "scp03.set_aid_alias",
            message: (data.action || "?") + " " + (data.name || ""),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowSetDefaults(tab) {
    var card = scp03BuildExtrasCard("Reset keys to defaults");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "Destructive: wipes the persisted KEYS for SCP03/SCP02/ADM and "
        + "replaces them with the shipped demo placeholders. Cached "
        + "GP managers on live SCP03 sessions are invalidated. Type "
        + "RESET below to proceed."
    );
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "confirm", label: "Confirm", required: true,
          placeholder: "type RESET",
          help: "Case-insensitive — must equal the word RESET." },
      ],
      "Reset keys",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.set_defaults", {
          confirm: (values.confirm || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Reset", value: data.reset ? "yes" : "no" },
            { label: "Key count", value: data.key_count == null ? "" : String(data.key_count) },
            { label: "Sessions invalidated", value: data.sessions_invalidated == null ? "" : String(data.sessions_invalidated) },
          ]);
          logBus.emit({
            level: "warn",
            source: "scp03.set_defaults",
            message: "KEYS reset to defaults; " + (data.sessions_invalidated || 0) + " session(s) invalidated",
          });
        });
      }
    );
    card.appendChild(out);
  }

  // -- C-5: mutation depth (PUT KEY / INSTALL / FS-ADMIN / PIN / CHANNEL / AUTH-live) ----

  function scp03RenderMutationActionResult(sheet, data, keyRows) {
    var baseRows = [
      { label: "Status", value: data.status || "" },
      { label: "SW", value: data.sw || "" },
      { label: "APDU", value: data.apdu || "" },
    ];
    if (Array.isArray(keyRows)) {
      keyRows.forEach(function (row) { baseRows.push(row); });
    }
    scp03DatasheetAppendMetaKvl(sheet, baseRows);
    if (Array.isArray(data.parent_select_trace) && data.parent_select_trace.length > 0) {
      var selectRows = data.parent_select_trace.map(function (row) {
        return { label: "SELECT " + (row.fid || ""), value: (row.sw || "") + " — " + (row.status || "") };
      });
      scp03DatasheetAppendMetaKvl(sheet, selectRows);
    }
    if (data.response_hex) {
      scp03DatasheetAppendTraceMain(sheet, "Response: " + data.response_hex, "");
    }
  }

  async function scp03ShowPutKey(tab) {
    var card = scp03BuildExtrasCard("PUT KEY (GP 11.8)");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "CRITICAL: PUT KEY overwrites the active session keyset. Wrong KVN/KID "
        + "can brick the card permanently. Requires an authenticated SCP session. "
        + "Type PUT-KEY to confirm."
    );
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "new_kvn", label: "New KVN (hex)", required: true, placeholder: "01" },
        { name: "new_key_id", label: "New Key ID (hex)", required: true, placeholder: "01" },
        { name: "old_kvn", label: "Old KVN (hex)", value: "00",
          help: "00 = add new keyset; otherwise the KVN being replaced." },
        { name: "enc_key", label: "ENC key (hex)", required: true },
        { name: "mac_key", label: "MAC key (hex)", required: true },
        { name: "dek_key", label: "DEK key (hex)", required: true,
          help: "All three keys must be 32 / 48 / 64 hex chars (16 / 24 / 32 bytes)." },
        { name: "algorithm", label: "Algorithm", kind: "select",
          choices: ["AES", "3DES"], value: "AES" },
        { name: "confirm", label: "Confirm", required: true,
          placeholder: "type PUT-KEY" },
      ],
      "PUT KEY",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.put_key", {
          session_id: tab.sessionId,
          new_kvn: (values.new_kvn || "").trim(),
          new_key_id: (values.new_key_id || "").trim(),
          old_kvn: (values.old_kvn || "00").trim(),
          enc_key: (values.enc_key || "").trim(),
          mac_key: (values.mac_key || "").trim(),
          dek_key: (values.dek_key || "").trim(),
          algorithm: values.algorithm || "AES",
          confirm: (values.confirm || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Old KVN", value: data.old_kvn || "" },
            { label: "New KVN", value: data.new_kvn || "" },
            { label: "New Key ID", value: data.new_key_id || "" },
            { label: "Key type", value: data.key_type || "" },
            { label: "Algorithm", value: data.algorithm || "" },
            { label: "Result", value: data.ok ? "OK" : "FAILED" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: data.ok ? "warn" : "error",
            source: "scp03.put_key",
            message: "PUT-KEY KVN=" + (data.new_kvn || "?") + " KID=" + (data.new_key_id || "?")
              + " → " + (data.ok ? "ok" : "failed"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowInstallCap(tab) {
    var card = scp03BuildExtrasCard("Install CAP file");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "Uploads + installs a GP applet. Fails mid-way leave the package "
        + "partially loaded; re-run after cleaning up with DELETE."
    );
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    var handle = scp03BuildInlineForm(
      card,
      [
        { name: "cap_path", label: "CAP file path", required: true,
          placeholder: "/path/to/applet.cap",
          help: "Double-click or Browse… to pick a .cap / .ijc file." },
        { name: "privileges", label: "Privileges (hex)", value: "00" },
        { name: "install_params", label: "Install params (hex)", value: "C900" },
        { name: "instantiate", label: "Instantiate after load", kind: "bool", value: true,
          help: "Uncheck to LOAD only (library packages)." },
        { name: "target_app_aid", label: "Override applet AID (hex)" },
        { name: "target_module_aid", label: "Override module AID (hex)" },
        { name: "load_chunk_size", label: "LOAD chunk size (1..255)", kind: "number",
          placeholder: "240 (auto-clamped under secure load)" },
      ],
      "Install",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.install_cap", {
          session_id: tab.sessionId,
          cap_path: (values.cap_path || "").trim(),
          privileges: (values.privileges || "00").trim(),
          install_params: (values.install_params || "C900").trim(),
          instantiate: !!values.instantiate,
          target_app_aid: (values.target_app_aid || "").trim(),
          target_module_aid: (values.target_module_aid || "").trim(),
          load_chunk_size: (values.load_chunk_size || "").toString().trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "CAP", value: data.cap_path || "" },
            { label: "Privileges", value: data.privileges || "" },
            { label: "Install params", value: data.install_params || "" },
            { label: "Instantiate", value: data.instantiate ? "yes" : "no" },
            { label: "Applet AID (override)", value: data.target_app_aid || "(from CAP)" },
            { label: "Module AID (override)", value: data.target_module_aid || "(from CAP)" },
            { label: "Chunk size", value: data.load_chunk_size == null ? "(auto)" : String(data.load_chunk_size) },
            { label: "Result", value: data.ok ? "OK" : "FAILED" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
          logBus.emit({
            level: data.ok ? "warn" : "error",
            source: "scp03.install_cap",
            message: "INSTALL " + (data.cap_path || "?") + " → " + (data.ok ? "ok" : "failed"),
          });
        });
      }
    );
    var capInput = handle.inputs.cap_path;
    if (capInput && typeof attachPathPicker === "function") {
      var wrapped = attachPathPicker(capInput, "open");
      if (capInput.parentNode && wrapped && wrapped !== capInput) {
        capInput.parentNode.replaceChild(wrapped, capInput);
      }
    }
    card.appendChild(out);
  }

  async function scp03ShowInstallApp(tab) {
    var card = scp03BuildExtrasCard("Install applet (already loaded)");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "INSTALL [for install] — instantiate an applet from a package "
        + "already loaded on the card."
    );
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "package_aid", label: "Package AID", required: true },
        { name: "applet_aid", label: "Applet AID", required: true },
        { name: "module_aid", label: "Module AID (optional)",
          help: "Defaults to the applet AID when blank." },
        { name: "privileges", label: "Privileges (hex)", value: "00" },
        { name: "install_params", label: "Install params (hex)", value: "C900" },
        { name: "make_selectable", label: "Make selectable", kind: "bool", value: true },
      ],
      "Install",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.install_app", {
          session_id: tab.sessionId,
          package_aid: (values.package_aid || "").trim(),
          applet_aid: (values.applet_aid || "").trim(),
          module_aid: (values.module_aid || "").trim(),
          privileges: (values.privileges || "00").trim(),
          install_params: (values.install_params || "C900").trim(),
          make_selectable: !!values.make_selectable,
        }, function (data, sheet) {
          scp03RenderMutationActionResult(sheet, data, [
            { label: "Package AID", value: data.package_aid || "" },
            { label: "Applet AID", value: data.applet_aid || "" },
            { label: "Module AID", value: data.module_aid || "(applet)" },
            { label: "P1", value: data.p1 || "" },
            { label: "Result", value: data.ok ? "OK" : "FAILED" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowInstallMakeSelectable(tab) {
    var card = scp03BuildExtrasCard("Install [for make selectable]");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "aid", label: "AID", required: true },
        { name: "privileges", label: "Privileges (hex)", value: "00" },
        { name: "params", label: "Params (hex)" },
        { name: "token", label: "Token (hex)" },
      ],
      "Run",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.install_make_selectable", {
          session_id: tab.sessionId,
          aid: (values.aid || "").trim(),
          privileges: (values.privileges || "00").trim(),
          params: (values.params || "").trim(),
          token: (values.token || "").trim(),
        }, function (data, sheet) {
          scp03RenderMutationActionResult(sheet, data, [
            { label: "AID", value: data.aid || "" },
            { label: "Privileges", value: data.privileges || "" },
            { label: "Result", value: data.ok ? "OK" : "FAILED" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowInstallExtradition(tab) {
    var card = scp03BuildExtrasCard("Install [for extradition]");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "Re-binds the instance AID to the chosen target Security Domain. "
        + "The new SD must already exist and have extradition privileges."
    );
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "aid", label: "Instance AID", required: true },
        { name: "sd_aid", label: "Target SD AID", required: true },
        { name: "token", label: "Token (hex)" },
      ],
      "Extradite",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.install_extradition", {
          session_id: tab.sessionId,
          aid: (values.aid || "").trim(),
          sd_aid: (values.sd_aid || "").trim(),
          token: (values.token || "").trim(),
        }, function (data, sheet) {
          scp03RenderMutationActionResult(sheet, data, [
            { label: "Instance AID", value: data.aid || "" },
            { label: "Target SD", value: data.sd_aid || "" },
            { label: "Result", value: data.ok ? "OK" : "FAILED" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowInstallPersonalization(tab) {
    var card = scp03BuildExtrasCard("Install [for personalization]");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "aid", label: "AID", required: true,
          help: "Target AID for the perso channel. Follow with STORE DATA." },
      ],
      "Open perso",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.install_personalization", {
          session_id: tab.sessionId,
          aid: (values.aid || "").trim(),
        }, function (data, sheet) {
          scp03RenderMutationActionResult(sheet, data, [
            { label: "AID", value: data.aid || "" },
            { label: "Result", value: data.ok ? "OK" : "FAILED" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowInstallRegistryUpdate(tab) {
    var card = scp03BuildExtrasCard("Install [for registry update]");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "aid", label: "AID", required: true },
        { name: "privileges", label: "Privileges (hex)", value: "00" },
        { name: "params", label: "Params (hex)" },
      ],
      "Update",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.install_registry_update", {
          session_id: tab.sessionId,
          aid: (values.aid || "").trim(),
          privileges: (values.privileges || "00").trim(),
          params: (values.params || "").trim(),
        }, function (data, sheet) {
          scp03RenderMutationActionResult(sheet, data, [
            { label: "AID", value: data.aid || "" },
            { label: "Privileges", value: data.privileges || "" },
            { label: "Params", value: data.params || "" },
            { label: "Result", value: data.ok ? "OK" : "FAILED" },
          ]);
          scp03DatasheetAppendTraceMain(sheet, data.trace, "");
        });
      }
    );
    card.appendChild(out);
  }

  // =========================================================================
  // FS — CREATE FILE wizard (ETSI TS 102 222 §6.1 + §6.2)
  //
  // Replaces the flat "paste raw FCP hex" form with a guided two-step flow:
  //   1. Pick file type (DF/ADF, Transparent EF, Linear Fixed EF) and fill
  //      in only the fields that type requires. Irrelevant fields stay
  //      hidden — the CLI wizard asks every question unconditionally and
  //      the GUI inherits that weirdness.
  //   2. Click "Preview FCP" — the backend ``scp03.fs_build_fcp`` composes
  //      the TLV wire offline (no card transmit) and returns a per-tag
  //      breakdown. The wizard renders that as an annotated table so the
  //      operator sees exactly what will hit the card before confirming.
  //   3. "CREATE FILE" fires ``00E0`` with the previewed FCP.
  //
  // A "Raw FCP" escape hatch is preserved for advanced users / scripts
  // pasting pre-built templates.
  // =========================================================================

  async function scp03ShowFsCreateFile(tab) {
    var card = scp03BuildExtrasCard("FS — CREATE FILE (00E0)");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "CREATE FILE requires an authenticated SD (SCP03 / SCP02). Walk the "
        + "guided wizard below, review the FCP preview, then confirm. "
        + "\u201CRaw FCP\u201D lets you paste a pre-built template."
    );

    // Mode toggle — Guided (default) vs Raw FCP.
    var modeBar = document.createElement("div");
    modeBar.className = "cc-fs-mode-bar";
    var btnGuided = document.createElement("button");
    btnGuided.type = "button";
    btnGuided.className = "btn btn-ghost active";
    btnGuided.textContent = "Guided wizard";
    var btnRaw = document.createElement("button");
    btnRaw.type = "button";
    btnRaw.className = "btn btn-ghost";
    btnRaw.textContent = "Raw FCP";
    modeBar.appendChild(btnGuided);
    modeBar.appendChild(btnRaw);
    card.appendChild(modeBar);

    var wizardHost = document.createElement("div");
    wizardHost.className = "cc-fs-wizard-host";
    card.appendChild(wizardHost);

    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    card.appendChild(out);

    function activate(mode) {
      wizardHost.innerHTML = "";
      out.innerHTML = "";
      if (mode === "guided") {
        btnGuided.classList.add("active");
        btnRaw.classList.remove("active");
        wizardHost.appendChild(scp03BuildFsCreateGuided(tab, out));
      } else {
        btnRaw.classList.add("active");
        btnGuided.classList.remove("active");
        wizardHost.appendChild(scp03BuildFsCreateRaw(tab, out));
      }
    }
    btnGuided.addEventListener("click", function () { activate("guided"); });
    btnRaw.addEventListener("click", function () { activate("raw"); });
    activate("guided");
  }

  // Build a single wizard field (label + input + optional hint + live
  // decimal mirror for hex-number inputs). Returns the row element and
  // stores the input under ``inputs[name]`` so callers can harvest values.
  function scp03MakeWizardField(inputs, name, label, opts) {
    opts = opts || {};
    var row = document.createElement("div");
    row.className = "cc-form-row cc-fs-wizard-row";
    var lab = document.createElement("label");
    lab.textContent = label;
    lab.htmlFor = "cc-fs-wiz-" + name;
    row.appendChild(lab);

    var input;
    if (opts.textarea) {
      input = document.createElement("textarea");
      input.rows = opts.rows || 3;
    } else {
      input = document.createElement("input");
      input.type = "text";
    }
    input.id = lab.htmlFor;
    input.name = name;
    if (opts.placeholder) input.placeholder = opts.placeholder;
    if (opts.value) input.value = String(opts.value);
    if (opts.required) input.required = true;
    row.appendChild(input);
    inputs[name] = input;

    if (opts.help) {
      var hint = document.createElement("div");
      hint.className = "cc-field-hint";
      hint.textContent = opts.help;
      row.appendChild(hint);
    }

    // Live decimal mirror for hex-number fields. Saves operators from
    // mental math ("is 0x14 = 20? is 0xFF = 255?") during every file
    // creation. Updates on input; hides on empty / invalid.
    if (opts.decimalMirror) {
      var mirror = document.createElement("div");
      mirror.className = "cc-field-hint cc-fs-mirror";
      mirror.textContent = "";
      row.appendChild(mirror);
      var recompute = function () {
        var v = (input.value || "").replace(/\s+/g, "");
        if (v.length === 0) { mirror.textContent = ""; return; }
        if (!/^[0-9A-Fa-f]+$/.test(v)) {
          mirror.textContent = "(not valid hex)";
          return;
        }
        try {
          mirror.textContent = "= " + parseInt(v, 16) + " decimal";
        } catch (err) { mirror.textContent = ""; }
      };
      input.addEventListener("input", recompute);
      recompute();
    }

    return row;
  }

  function scp03BuildFsCreateGuided(tab, out) {
    var wrap = document.createElement("div");
    wrap.className = "cc-fs-wizard";

    var inputs = {};
    var state = { fileType: "DF_ADF", built: null };

    // Step 1 — file type selector.
    var typeRow = document.createElement("div");
    typeRow.className = "cc-form-row cc-fs-wizard-row";
    var typeLab = document.createElement("label");
    typeLab.textContent = "File type";
    typeLab.htmlFor = "cc-fs-wiz-type";
    typeRow.appendChild(typeLab);
    var typeSel = document.createElement("select");
    typeSel.id = typeLab.htmlFor;
    [
      { val: "DF_ADF",          lbl: "DF / ADF (Dedicated File)" },
      { val: "TRANSPARENT_EF",  lbl: "Transparent EF" },
      { val: "LINEAR_FIXED_EF", lbl: "Linear Fixed EF" },
    ].forEach(function (opt) {
      var o = document.createElement("option");
      o.value = opt.val;
      o.textContent = opt.lbl;
      typeSel.appendChild(o);
    });
    typeSel.value = state.fileType;
    typeRow.appendChild(typeSel);
    var typeHint = document.createElement("div");
    typeHint.className = "cc-field-hint";
    typeRow.appendChild(typeHint);
    wrap.appendChild(typeRow);

    // Host for the type-specific fields. Re-rendered on every type change.
    var fieldsHost = document.createElement("div");
    fieldsHost.className = "cc-fs-wizard-fields";
    wrap.appendChild(fieldsHost);

    function renderFieldsForType() {
      fieldsHost.innerHTML = "";
      // Clear stale inputs — avoids leaking DF's c6_hex into an EF build.
      Object.keys(inputs).forEach(function (k) { delete inputs[k]; });

      // Common to every type — path + security attribute.
      fieldsHost.appendChild(scp03MakeWizardField(inputs, "full_path",
        "Full hex path", {
          placeholder: "3F007F105F01",
          help: "Last 2 bytes = the new FID; preceding bytes = parent path "
            + "(walked via SELECT before CREATE).",
          required: true,
        }));
      fieldsHost.appendChild(scp03MakeWizardField(inputs, "sec_attr_hex",
        "Security attribute TLV (tag 8C / 8B / AB)", {
          placeholder: "8C0140",
          help: "Fully-encoded TLV. Typical demo value 8C 01 40 maps "
            + "AM=NEVER (dev cards). Production cards enforce stricter "
            + "rules via AB / 8B compact-format.",
        }));

      if (state.fileType === "DF_ADF") {
        typeHint.textContent = "DFs organise a subtree. Needs a memory "
          + "quota (tag 81) and a PIN Status Template DO (tag C6). "
          + "Add an AID (tag 84) to turn the DF into an ADF.";
        fieldsHost.appendChild(scp03MakeWizardField(inputs, "file_size_hex",
          "DF memory quota (hex bytes)", {
            placeholder: "0400",
            help: "Total memory allocated to the DF subtree. 0400 = 1 KiB.",
            required: true,
            decimalMirror: true,
          }));
        fieldsHost.appendChild(scp03MakeWizardField(inputs, "aid_hex",
          "ADF AID (tag 84, optional)", {
            placeholder: "A0000000871002FF33FFFF8900000100",
            help: "Empty = plain DF. ADFs carry a 5 \u2013 16 byte AID.",
          }));
        fieldsHost.appendChild(scp03MakeWizardField(inputs, "c6_hex",
          "PIN Status Template DO (tag C6, REQUIRED)", {
            placeholder: "C609900101830101950108",
            help: "Complete C6 TLV (outer tag + length + value). "
              + "Required by ETSI TS 102 222 for every DF/ADF.",
            required: true,
            textarea: true,
            rows: 2,
          }));
      } else if (state.fileType === "TRANSPARENT_EF") {
        typeHint.textContent = "Transparent EFs hold a single opaque "
          + "binary payload. Needs a body size (tag 80); SFI is optional.";
        fieldsHost.appendChild(scp03MakeWizardField(inputs, "file_size_hex",
          "EF body size (hex bytes)", {
            placeholder: "0020",
            help: "Number of bytes in the transparent body. "
              + "0020 hex = 32 decimal.",
            required: true,
            decimalMirror: true,
          }));
        fieldsHost.appendChild(scp03MakeWizardField(inputs, "sfi_hex",
          "Short File Identifier (1 byte, optional)", {
            placeholder: "05",
            help: "1-byte SFI, or empty \u2192 emit 88 00 (no SFI).",
          }));
      } else if (state.fileType === "LINEAR_FIXED_EF") {
        typeHint.textContent = "Linear fixed EFs store N equal-length "
          + "records. The wizard computes total size = rec_len \u00D7 num_rec.";
        fieldsHost.appendChild(scp03MakeWizardField(inputs, "rec_len_hex",
          "Record length (hex bytes)", {
            placeholder: "14",
            help: "Bytes per record. Fixed across the whole EF.",
            required: true,
            decimalMirror: true,
          }));
        fieldsHost.appendChild(scp03MakeWizardField(inputs, "num_rec_hex",
          "Number of records (hex)", {
            placeholder: "0A",
            help: "0A hex = 10 decimal.",
            required: true,
            decimalMirror: true,
          }));
        fieldsHost.appendChild(scp03MakeWizardField(inputs, "sfi_hex",
          "Short File Identifier (1 byte, optional)", {
            placeholder: "04",
            help: "1-byte SFI, or empty \u2192 emit 88 00 (no SFI).",
          }));
      }

      fieldsHost.appendChild(scp03MakeWizardField(inputs, "prop_a5_hex",
        "Proprietary info (tag A5 inner, optional)", {
          placeholder: "C10100",
          help: "Inner A5 bytes only \u2014 the wizard wraps them with "
            + "the outer A5 <len>.",
        }));
    }

    typeSel.addEventListener("change", function () {
      state.fileType = typeSel.value;
      state.built = null;
      previewHost.innerHTML = "";
      renderFieldsForType();
    });

    // Step 2 — Preview button + preview host.
    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var previewBtn = document.createElement("button");
    previewBtn.type = "button";
    previewBtn.className = "btn btn-secondary";
    previewBtn.textContent = "Preview FCP";
    bar.appendChild(previewBtn);
    var resetBtn = document.createElement("button");
    resetBtn.type = "button";
    resetBtn.className = "btn btn-ghost";
    resetBtn.textContent = "Reset fields";
    bar.appendChild(resetBtn);
    wrap.appendChild(bar);

    var previewHost = document.createElement("div");
    previewHost.className = "cc-fs-preview-host";
    wrap.appendChild(previewHost);

    resetBtn.addEventListener("click", function () {
      state.built = null;
      previewHost.innerHTML = "";
      renderFieldsForType();
    });

    previewBtn.addEventListener("click", async function () {
      previewBtn.disabled = true;
      previewHost.innerHTML = "";
      previewHost.appendChild(loadingEl("building FCP\u2026"));
      var payload = {
        file_type: state.fileType,
        full_path: (inputs.full_path ? inputs.full_path.value : "").trim(),
        sec_attr_hex: (inputs.sec_attr_hex ? inputs.sec_attr_hex.value : "").trim(),
        file_size_hex: (inputs.file_size_hex ? inputs.file_size_hex.value : "").trim(),
        aid_hex: (inputs.aid_hex ? inputs.aid_hex.value : "").trim(),
        c6_hex: (inputs.c6_hex ? inputs.c6_hex.value : "").trim(),
        sfi_hex: (inputs.sfi_hex ? inputs.sfi_hex.value : "").trim(),
        rec_len_hex: (inputs.rec_len_hex ? inputs.rec_len_hex.value : "").trim(),
        num_rec_hex: (inputs.num_rec_hex ? inputs.num_rec_hex.value : "").trim(),
        prop_a5_hex: (inputs.prop_a5_hex ? inputs.prop_a5_hex.value : "").trim(),
      };
      try {
        var resp = await apiFetch("/api/actions/scp03.fs_build_fcp/run", {
          method: "POST",
          body: JSON.stringify({ inputs: payload }),
        });
        previewHost.innerHTML = "";
        if (!resp.ok) {
          previewHost.appendChild(renderErrorBlock(
            resp.error || "Preview failed"));
          return;
        }
        state.built = resp.data || null;
        scp03RenderFcpPreview(previewHost, state.built, tab, out);
      } catch (err) {
        previewHost.innerHTML = "";
        previewHost.appendChild(renderErrorBlock(
          String(err && err.message || err)));
      } finally {
        previewBtn.disabled = false;
      }
    });

    renderFieldsForType();
    return wrap;
  }

  function scp03RenderFcpPreview(host, built, tab, out) {
    if (!built) return;
    var title = document.createElement("h5");
    title.className = "cc-fs-preview-title";
    title.textContent = "Preview \u2014 FID " + (built.fid || "?");
    host.appendChild(title);

    var rows = [
      { label: "File type", value: built.file_type || "" },
      { label: "Parent path", value: built.parent_path || "(current DF)" },
      { label: "New FID", value: built.fid || "" },
      {
        label: "File size",
        value: (built.file_size || 0) + " bytes (0x"
          + (built.file_size || 0).toString(16).toUpperCase() + ")",
      },
    ];
    if (built.rec_len) {
      rows.push({
        label: "Records",
        value: (built.num_rec || 0) + " \u00D7 " + built.rec_len + " bytes each",
      });
    }
    rows.push({ label: "Full FCP hex", value: built.fcp_hex || "" });
    scp03RenderKeyValueRows(host, rows);

    // Per-tag breakdown table — this is the real value of the preview.
    if (Array.isArray(built.breakdown) && built.breakdown.length > 0) {
      var wrap = document.createElement("div");
      wrap.className = "cc-fs-breakdown-wrap";
      var cap = document.createElement("div");
      cap.className = "cc-fs-breakdown-caption";
      cap.textContent = "FCP tag breakdown:";
      wrap.appendChild(cap);
      var table = document.createElement("table");
      table.className = "cc-fs-breakdown";
      var thead = document.createElement("thead");
      thead.innerHTML = "<tr><th>Tag</th><th>Hex</th><th>Meaning</th></tr>";
      table.appendChild(thead);
      var tbody = document.createElement("tbody");
      built.breakdown.forEach(function (row) {
        var tr = document.createElement("tr");
        var tdTag = document.createElement("td");
        tdTag.innerHTML = "<code>" + escapeHtml(row.tag || "") + "</code>";
        var tdHex = document.createElement("td");
        tdHex.innerHTML = "<code>" + escapeHtml(row.hex || "") + "</code>";
        var tdDesc = document.createElement("td");
        tdDesc.textContent = row.description || "";
        tr.appendChild(tdTag);
        tr.appendChild(tdHex);
        tr.appendChild(tdDesc);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      wrap.appendChild(table);
      host.appendChild(wrap);
    }

    // Commit button — fires the destructive 00E0 CREATE FILE APDU.
    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var createBtn = document.createElement("button");
    createBtn.type = "button";
    createBtn.className = "btn btn-primary";
    createBtn.textContent = "CREATE FILE on card (00E0)";
    bar.appendChild(createBtn);
    host.appendChild(bar);

    createBtn.addEventListener("click", async function () {
      createBtn.disabled = true;
      await scp03RunActionWithOutput(out, "scp03.fs_create_file", {
        session_id: tab.sessionId,
        fcp_hex: built.fcp_hex,
        parent_path: built.parent_path || "",
      }, function (data, sheet) {
        scp03RenderMutationActionResult(sheet, data, [
          { label: "FCP sent", value: data.fcp || "" },
          { label: "FID", value: built.fid || "" },
        ]);
        logBus.emit({
          level: data.ok ? "warn" : "error",
          source: "scp03.fs_create_file",
          message: "CREATE FILE " + (built.fid || "?") + " \u2192 "
            + (data.ok ? "ok" : "failed") + " (" + (data.sw || "") + ")",
        });
      });
      createBtn.disabled = false;
    });
  }

  function scp03BuildFsCreateRaw(tab, out) {
    // Escape hatch for operators pasting a pre-built FCP template
    // (e.g. from a perso tool or a reverse-engineered dump). Same flat
    // form the v1 wizard used; kept verbatim so scripts hand-rolled
    // against v1 keep working.
    var wrap = document.createElement("div");
    wrap.className = "cc-fs-raw";
    var note = document.createElement("p");
    note.className = "hint";
    note.textContent = "Raw mode — paste a complete FCP template "
      + "(including outer tag 62). No validation beyond even-length hex.";
    wrap.appendChild(note);

    var form = document.createElement("form");
    form.className = "cc-action-form cc-wb-extras-form";
    form.noValidate = true;

    var inputs = {};
    var parentRow = scp03MakeWizardField(inputs, "parent_path",
      "Parent path (hex, optional)", {
        placeholder: "3F007F10",
        help: "2-byte FIDs concatenated. SELECT chain is walked first.",
      });
    var fcpRow = scp03MakeWizardField(inputs, "fcp_hex",
      "FCP template (hex)", {
        placeholder: "62198202412183020001A50FC10101\u2026",
        help: "Full TLV-encoded FCP including outer tag 62.",
        required: true,
        textarea: true,
        rows: 4,
      });
    form.appendChild(parentRow);
    form.appendChild(fcpRow);

    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "btn btn-primary";
    submit.textContent = "CREATE FILE (raw)";
    bar.appendChild(submit);
    form.appendChild(bar);
    wrap.appendChild(form);

    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      submit.disabled = true;
      await scp03RunActionWithOutput(out, "scp03.fs_create_file", {
        session_id: tab.sessionId,
        parent_path: (inputs.parent_path.value || "").trim(),
        fcp_hex: (inputs.fcp_hex.value || "").trim(),
      }, function (data, sheet) {
        scp03RenderMutationActionResult(sheet, data, [
          { label: "FCP", value: data.fcp || "" },
        ]);
      });
      submit.disabled = false;
    });

    return wrap;
  }

  // =========================================================================
  // FS — DELETE FILE wizard
  // Pre-fills FID + parent from the tab's current selection when available
  // so operators don't have to type the hex they can already see in the
  // scan tree. Confirm token is required (backend enforces =="DELETE").
  // =========================================================================
  async function scp03ShowFsDeleteFile(tab) {
    var card = scp03BuildExtrasCard("FS — DELETE FILE (00E4)");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "IRREVERSIBLE: DELETE FILE destroys the referenced EF/DF. "
        + "Type DELETE below to confirm."
    );

    var hint = scp03FsPickFromSelection(tab);
    if (hint.note) {
      var noteEl = document.createElement("p");
      noteEl.className = "cc-fs-op-hint";
      noteEl.textContent = hint.note;
      card.appendChild(noteEl);
    }

    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "fid", label: "Target FID (4 hex)", required: true,
          placeholder: "6F07", value: hint.fid || "",
          help: "The 2-byte file identifier of the target EF / DF." },
        { name: "parent_path", label: "Parent path (hex, optional)",
          placeholder: "3F007F10", value: hint.parent || "",
          help: "SELECT chain walked before DELETE. Empty = current DF." },
        { name: "confirm", label: "Confirm",
          required: true, placeholder: "type DELETE",
          help: "Backend rejects anything other than DELETE (case-insensitive)." },
      ],
      "Delete",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.fs_delete_file", {
          session_id: tab.sessionId,
          fid: (values.fid || "").trim(),
          parent_path: (values.parent_path || "").trim(),
          confirm: (values.confirm || "").trim(),
        }, function (data, sheet) {
          scp03RenderMutationActionResult(sheet, data, [
            { label: "FID", value: data.fid || "" },
          ]);
          logBus.emit({
            level: data.ok ? "warn" : "error",
            source: "scp03.fs_delete_file",
            message: "DELETE " + (data.fid || "?") + " → " + (data.ok ? "ok" : "failed"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  // Pull a best-effort FID + parent from the currently selected scan-tree
  // path so the delete / resize wizards pre-populate without the operator
  // re-typing the hex they can already see. Returns `{fid, parent, note}`.
  // If no selection, `note` flags it.
  function scp03FsPickFromSelection(tab) {
    var res = { fid: "", parent: "", note: "" };
    var path = tab && tab.selectedPath ? String(tab.selectedPath) : "";
    if (path.length === 0) {
      res.note = "Tip: select a file in the Files tab first to auto-fill "
        + "the FID and parent path below.";
      return res;
    }
    // The scan tree gives us paths like "MF/EF.ICCID" or "MF/ADF_USIM/EF_IMSI"
    // — the GUI path-walker resolves those on SELECT. For the wizard we
    // want the raw 2-byte FID if we can find it. If tab.previewCache
    // carries the FCP we can pull tag 83, otherwise we leave blank and
    // let the operator type.
    var preview = tab && tab.previewCache ? tab.previewCache : null;
    if (preview && preview.fid) {
      res.fid = String(preview.fid).toUpperCase().replace(/[^0-9A-F]/g, "");
      if (preview.parent_path) {
        res.parent = String(preview.parent_path).toUpperCase().replace(/[^0-9A-F]/g, "");
      }
      res.note = "Auto-filled from current selection: " + path + ".";
    } else {
      res.note = "Current selection: " + path
        + ". No FCP cached yet — type the FID manually, or reload the file "
        + "to populate it.";
    }
    return res;
  }

  // =========================================================================
  // FS — RESIZE FILE wizard
  // Dual-size layout with decimal mirrors + "use current selection" auto-fill.
  // =========================================================================
  async function scp03ShowFsResize(tab) {
    var card = scp03BuildExtrasCard("FS — RESIZE FILE (80D4)");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "RESIZE changes EF body size in place. Existing content past the "
        + "new size is discarded. Shrinking is irreversible."
    );

    var hint = scp03FsPickFromSelection(tab);
    if (hint.note) {
      var noteEl = document.createElement("p");
      noteEl.className = "cc-fs-op-hint";
      noteEl.textContent = hint.note;
      card.appendChild(noteEl);
    }

    var explain = document.createElement("p");
    explain.className = "cc-fs-op-hint";
    explain.innerHTML =
      "Set <strong>tag&nbsp;80</strong> for the new transparent-EF body "
      + "size, <strong>tag&nbsp;81</strong> for the new total file size, "
      + "or both. All sizes are hex byte counts (e.g. <code>0040</code> "
      + "= 64 decimal).";
    card.appendChild(explain);

    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";

    var wrap = document.createElement("div");
    wrap.className = "cc-fs-wizard";
    var inputs = {};
    wrap.appendChild(scp03MakeWizardField(inputs, "target_fid",
      "Target FID (4 hex)", {
        placeholder: "6F07",
        value: hint.fid || "",
        required: true,
      }));
    wrap.appendChild(scp03MakeWizardField(inputs, "new_file_size",
      "New file size (tag 80, hex bytes)", {
        placeholder: "0040",
        decimalMirror: true,
      }));
    wrap.appendChild(scp03MakeWizardField(inputs, "new_total_size",
      "New total size (tag 81, hex bytes)", {
        placeholder: "0080",
        decimalMirror: true,
      }));
    wrap.appendChild(scp03MakeWizardField(inputs, "parent_path",
      "Parent path (hex, optional)", {
        placeholder: "3F007F10",
        value: hint.parent || "",
      }));

    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var submit = document.createElement("button");
    submit.type = "button";
    submit.className = "btn btn-primary";
    submit.textContent = "Resize";
    bar.appendChild(submit);
    wrap.appendChild(bar);

    submit.addEventListener("click", async function () {
      submit.disabled = true;
      await scp03RunActionWithOutput(out, "scp03.fs_resize", {
        session_id: tab.sessionId,
        target_fid: (inputs.target_fid.value || "").trim(),
        new_file_size: (inputs.new_file_size.value || "").trim(),
        new_total_size: (inputs.new_total_size.value || "").trim(),
        parent_path: (inputs.parent_path.value || "").trim(),
      }, function (data, sheet) {
        scp03RenderMutationActionResult(sheet, data, [
          { label: "FCP", value: data.fcp || "" },
          { label: "Tag 80", value: data.tag_80 || "" },
          { label: "Tag 81", value: data.tag_81 || "" },
        ]);
      });
      submit.disabled = false;
    });

    card.appendChild(wrap);
    card.appendChild(out);
  }

  // =========================================================================
  // FS — UPDATE wizard router
  //
  // Branches between UPDATE BINARY (00D6) for transparent EFs and
  // UPDATE RECORD (00DC) for linear-fixed / cyclic EFs. Both branches
  // share the "Path" + "Data" plumbing — only the record-number field
  // differs — so we keep them in sibling functions and dispatch from
  // here based on the gating ``kind`` already resolved by the action
  // bar (avoids re-deriving it in every call site).
  // =========================================================================
  function scp03ShowFsUpdate(tab, kind) {
    // The router maps the file-kind (already resolved by the action
    // bar's gating) onto the matching wizard. We use a literal lookup
    // table so the static gating-matrix tests can pin the per-kind
    // branches against the availability helper without ambiguity from
    // a parallel ``if`` ladder living in this routing helper.
    var wizard = ({
      transparent: scp03ShowFsUpdateBinary,
      linear: scp03ShowFsUpdateRecord,
      cyclic: scp03ShowFsUpdateRecord,
    })[kind];
    if (wizard) {
      return wizard(tab, kind);
    }
    // Defensive — the button gate should have prevented us getting
    // here. Surface a small explanatory card so we don't silently noop.
    var card = scp03BuildExtrasCard("FS — UPDATE");
    if (!card) return;
    var note = document.createElement("p");
    note.className = "cc-fs-op-hint";
    note.textContent = "Pick a transparent EF (UPDATE BINARY) or a "
      + "linear / cyclic EF (UPDATE RECORD) in the tree first.";
    card.appendChild(note);
  }

  // ASCII mirror for hex payload fields. Mirrors the helper baked into
  // the SEARCH RECORD wizard, isolated here so the UPDATE forms stay
  // legible when an operator pastes a hex blob — they instantly see
  // whether the body is text-like or pure binary.
  function scp03AttachHexAsciiMirror(field, input) {
    var ascii = document.createElement("div");
    ascii.className = "cc-field-hint cc-fs-mirror";
    field.appendChild(ascii);
    var refresh = function () {
      var hex = (input.value || "").replace(/\s+/g, "");
      if (hex.length === 0) { ascii.textContent = ""; return; }
      if (hex.length % 2 !== 0) {
        ascii.textContent = "(odd-length hex — pad with a nibble)";
        return;
      }
      if (!/^[0-9A-Fa-f]+$/.test(hex)) {
        ascii.textContent = "(not valid hex)";
        return;
      }
      var txt = "";
      for (var i = 0; i < hex.length; i += 2) {
        var b = parseInt(hex.substr(i, 2), 16);
        txt += (b >= 0x20 && b <= 0x7E) ? String.fromCharCode(b) : ".";
      }
      ascii.textContent = "ASCII: " + txt + "  (" + (hex.length / 2) + " bytes)";
    };
    input.addEventListener("input", refresh);
    refresh();
  }

  // -------------------------------------------------------------------------
  // FS — UPDATE BINARY (00D6) wizard
  // Transparent-EF only. Path defaults to the current selection so the
  // common case ("read EF, edit, write back") is one paste away.
  // -------------------------------------------------------------------------
  async function scp03ShowFsUpdateBinary(tab) {
    var card = scp03BuildExtrasCard("FS — UPDATE BINARY (00D6)");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "UPDATE BINARY overwrites this transparent EF in place. "
        + "There is no implicit backup — read the body first if you "
        + "need to roll back."
    );

    var explain = document.createElement("p");
    explain.className = "cc-fs-op-hint";
    explain.innerHTML =
      "Writes <code>hex_data</code> at the given <strong>offset</strong> "
      + "(P1\u2225P2). The card enforces the EF's security attribute, so "
      + "expect <code>69 82</code> if the auth gate hasn't been satisfied.";
    card.appendChild(explain);

    var hint = scp03FsPickFromSelection(tab);
    if (hint.note) {
      var noteEl = document.createElement("p");
      noteEl.className = "cc-fs-op-hint";
      noteEl.textContent = hint.note;
      card.appendChild(noteEl);
    }

    var defaultPath = tab && tab.selectedPath ? String(tab.selectedPath) : "";

    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";

    var wrap = document.createElement("div");
    wrap.className = "cc-fs-wizard";
    var inputs = {};

    wrap.appendChild(scp03MakeWizardField(inputs, "path",
      "Target path (optional, e.g. MF/EF_ICCID)", {
        placeholder: "MF/EF_ICCID",
        value: defaultPath,
        help: "Leave blank to write to the currently-selected EF.",
      }));

    wrap.appendChild(scp03MakeWizardField(inputs, "offset",
      "Offset (hex bytes, optional)", {
        placeholder: "0000",
        decimalMirror: true,
        help: "Splits to P1\u2225P2. 0000 writes from the start of the body.",
      }));

    var dataField = scp03MakeWizardField(inputs, "hex_data",
      "Data (hex)", {
        placeholder: "98103254 7698103254",
        required: true,
        textarea: true,
        rows: 4,
        help: "Even-length hex; whitespace is stripped before transmission.",
      });
    wrap.appendChild(dataField);
    scp03AttachHexAsciiMirror(dataField, inputs.hex_data);

    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var submit = document.createElement("button");
    submit.type = "button";
    submit.className = "btn btn-primary";
    submit.textContent = "Update binary";
    bar.appendChild(submit);
    wrap.appendChild(bar);

    submit.addEventListener("click", async function () {
      submit.disabled = true;
      var offsetText = (inputs.offset.value || "").trim();
      var offsetVal = 0;
      if (offsetText.length > 0) {
        if (!/^[0-9A-Fa-f]+$/.test(offsetText)) {
          submit.disabled = false;
          out.textContent = "Offset is not valid hex.";
          return;
        }
        offsetVal = parseInt(offsetText, 16);
      }
      await scp03RunActionWithOutput(out, "scp03.update_binary", {
        session_id: tab.sessionId,
        path: (inputs.path.value || "").trim(),
        hex_data: (inputs.hex_data.value || "").trim(),
        offset: offsetVal,
      }, function (data, sheet) {
        scp03RenderMutationActionResult(sheet, data, [
          { label: "Path", value: data.path || "(current selection)" },
          { label: "Bytes", value: String(data.bytes || 0) },
          { label: "Offset", value: String(data.offset || 0) },
          { label: "SW", value: data.sw || "" },
        ]);
        // Bust the FCP/data cache so the next tree click re-reads the
        // freshly-updated body. ``previewCache`` is keyed by selection
        // path and lives on the tab.
        try {
          if (tab && tab.previewCache && tab.selectedPath) {
            delete tab.previewCache;
          }
        } catch (err) { /* non-fatal */ }
      });
      submit.disabled = false;
    });

    card.appendChild(wrap);
    card.appendChild(out);
  }

  // -------------------------------------------------------------------------
  // FS — UPDATE RECORD (00DC) wizard
  // Linear-fixed / cyclic EF. Surfaces the cached record_count when we
  // have it, so the operator knows the legal range without re-reading.
  // -------------------------------------------------------------------------
  async function scp03ShowFsUpdateRecord(tab, kind) {
    var label = (kind === "cyclic") ? "cyclic" : "linear-fixed";
    var card = scp03BuildExtrasCard(
      "FS — UPDATE RECORD (00DC) — " + label);
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "UPDATE RECORD overwrites a single record in this " + label
        + " EF. Cyclic EFs roll the oldest entry off the end on each "
        + "write — review the record number carefully."
    );

    var explain = document.createElement("p");
    explain.className = "cc-fs-op-hint";
    explain.innerHTML =
      "Writes <code>hex_data</code> as the body of record <strong>N</strong>. "
      + "The card pads short payloads to the EF's record length; longer "
      + "payloads return <code>67&nbsp;00</code>.";
    card.appendChild(explain);

    var hint = scp03FsPickFromSelection(tab);
    if (hint.note) {
      var noteEl = document.createElement("p");
      noteEl.className = "cc-fs-op-hint";
      noteEl.textContent = hint.note;
      card.appendChild(noteEl);
    }

    // Pull record-count out of the preview cache when available so the
    // operator sees "1..7" inline rather than discovering it via a SW.
    var recordCount = 0;
    try {
      var cache = tab && tab.previewCache ? tab.previewCache : null;
      if (cache && cache.data && typeof cache.data.record_count === "number") {
        recordCount = cache.data.record_count | 0;
      }
    } catch (err) { /* non-fatal */ }
    if (recordCount > 0) {
      var rangeNote = document.createElement("p");
      rangeNote.className = "cc-fs-op-hint";
      rangeNote.textContent = "Cached record_count = " + recordCount
        + ". Legal record numbers: 1.." + recordCount + ".";
      card.appendChild(rangeNote);
    }

    var defaultPath = tab && tab.selectedPath ? String(tab.selectedPath) : "";

    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";

    var wrap = document.createElement("div");
    wrap.className = "cc-fs-wizard";
    var inputs = {};

    wrap.appendChild(scp03MakeWizardField(inputs, "path",
      "Target path (optional, e.g. MF/ADF_USIM/EF_MSISDN)", {
        placeholder: "MF/ADF_USIM/EF_MSISDN",
        value: defaultPath,
        help: "Leave blank to write to the currently-selected EF.",
      }));

    wrap.appendChild(scp03MakeWizardField(inputs, "record",
      "Record number (1..254, decimal)", {
        placeholder: "1",
        required: true,
        help: "P1 of UPDATE RECORD; backend uses mode 0x04 (absolute).",
      }));

    var dataField = scp03MakeWizardField(inputs, "hex_data",
      "Data (hex)", {
        placeholder: "FF FF FF FF FF FF FF FF",
        required: true,
        textarea: true,
        rows: 4,
        help: "Even-length hex; pad to the EF's record length when needed.",
      });
    wrap.appendChild(dataField);
    scp03AttachHexAsciiMirror(dataField, inputs.hex_data);

    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var submit = document.createElement("button");
    submit.type = "button";
    submit.className = "btn btn-primary";
    submit.textContent = "Update record";
    bar.appendChild(submit);
    wrap.appendChild(bar);

    submit.addEventListener("click", async function () {
      submit.disabled = true;
      var recText = (inputs.record.value || "").trim();
      if (recText.length === 0 || !/^\d+$/.test(recText)) {
        submit.disabled = false;
        out.textContent = "Record must be a positive integer.";
        return;
      }
      var recInt = parseInt(recText, 10);
      if (recInt < 1 || recInt > 254) {
        submit.disabled = false;
        out.textContent = "Record out of range (1..254): " + recInt;
        return;
      }
      await scp03RunActionWithOutput(out, "scp03.update_record", {
        session_id: tab.sessionId,
        path: (inputs.path.value || "").trim(),
        record: recInt,
        hex_data: (inputs.hex_data.value || "").trim(),
      }, function (data, sheet) {
        scp03RenderMutationActionResult(sheet, data, [
          { label: "Path", value: data.path || "(current selection)" },
          { label: "Record", value: String(data.record || recInt) },
          { label: "Bytes", value: String(data.bytes || 0) },
          { label: "SW", value: data.sw || "" },
        ]);
        try {
          if (tab && tab.previewCache && tab.selectedPath) {
            delete tab.previewCache;
          }
        } catch (err) { /* non-fatal */ }
      });
      submit.disabled = false;
    });

    card.appendChild(wrap);
    card.appendChild(out);
  }

  // =========================================================================
  // Service-table staging — mock-update an EF.UST / EF.IST / generic
  // bitmap EF without touching the card.
  //
  // The user wanted a "what if I flipped these flags?" view: toggle
  // checkboxes, watch the resulting hex update live, and (optionally)
  // hand the new bytes off to UPDATE BINARY without doing the bit-math
  // by hand. Backend is ``scp03.stage_service_table`` — pure local
  // encoder, no card I/O, no auth gate.
  // =========================================================================
  function scp03InferServiceTableKind(decoded) {
    if (!decoded || typeof decoded !== "object") return "generic";
    var raw = String(decoded.table || "").toLowerCase();
    if (raw === "ust") return "ust";
    if (raw === "ist") return "ist";
    return "generic";
  }

  function scp03ParseServiceLabel(label) {
    // Accepts entries shaped either ``"<n>: <name>"`` (UST / IST) or
    // a bare ``"<n>"`` (generic). Returns ``{ n, name }`` or null if
    // we can't parse the row safely (defensive — backend should never
    // emit those).
    var text = String(label == null ? "" : label).trim();
    if (text.length === 0) return null;
    var match = text.match(/^(\d+)\s*(?::\s*(.*))?$/);
    if (!match) return null;
    var n = parseInt(match[1], 10);
    if (!isFinite(n) || n < 1) return null;
    return { n: n, name: (match[2] || "").trim() };
  }

  function scp03BuildServiceTableEntries(decoded) {
    // Merge active + inactive into one ordered list keyed by service
    // number. The popout uses this as the master record so toggles
    // can flip a row in place without re-decoding the whole bitmap
    // every keystroke.
    var entries = {};
    var collect = function (rows, set) {
      if (!Array.isArray(rows)) return;
      rows.forEach(function (row) {
        var parsed = scp03ParseServiceLabel(row);
        if (!parsed) return;
        entries[parsed.n] = {
          n: parsed.n,
          name: parsed.name,
          active: set,
        };
      });
    };
    collect(decoded.active, true);
    collect(decoded.inactive, false);
    var nums = Object.keys(entries).map(function (k) { return parseInt(k, 10); });
    nums.sort(function (a, b) { return a - b; });
    return nums.map(function (n) { return entries[n]; });
  }

  function scp03FormatHexGroups(hex) {
    // Group on byte boundaries with a single space between each pair —
    // matches the CLI ``...`` dump style. Operators copy this straight
    // into UPDATE BINARY where the dispatcher strips whitespace anyway.
    var cleaned = String(hex || "").replace(/\s+/g, "").toUpperCase();
    var pairs = cleaned.match(/.{1,2}/g) || [];
    return pairs.join(" ");
  }

  function scp03ShowServiceTableStaging(decoded, currentHex) {
    if (!decoded || typeof decoded !== "object") return;
    var tab = scp03GetActiveTab();
    var kind = scp03InferServiceTableKind(decoded);
    var tableLabel = String(decoded.table || "Service Table");
    var fullName = String(decoded.full_name || "");
    var card = scp03BuildExtrasCard(
      "Stage edit \u2014 " + tableLabel
        + (fullName.length > 0 && fullName !== tableLabel
          ? " (" + fullName + ")" : ""));
    if (!card) return;

    var explainer = document.createElement("p");
    explainer.className = "cc-fs-op-hint";
    explainer.innerHTML =
      "Toggle services to mock-update the EF body. The resulting hex "
      + "<strong>updates live</strong> below; nothing is sent to the "
      + "card until you copy the bytes into UPDATE BINARY.";
    card.appendChild(explainer);

    var entries = scp03BuildServiceTableEntries(decoded);
    if (entries.length === 0) {
      var empty = document.createElement("p");
      empty.className = "cc-fs-op-hint";
      empty.textContent = "No service rows to stage.";
      card.appendChild(empty);
      return;
    }

    var startHex = String(currentHex || "").replace(/\s+/g, "").toUpperCase();

    // ---- Hex preview banner -------------------------------------------------
    var preview = document.createElement("div");
    preview.className = "cc-svc-stage-preview";

    var curRow = document.createElement("div");
    curRow.className = "cc-svc-stage-hex-row";
    var curLabel = document.createElement("span");
    curLabel.className = "cc-svc-stage-hex-label";
    curLabel.textContent = "current";
    var curVal = document.createElement("code");
    curVal.className = "cc-svc-stage-hex-val";
    curVal.textContent = scp03FormatHexGroups(startHex) || "(empty)";
    curRow.appendChild(curLabel);
    curRow.appendChild(curVal);
    preview.appendChild(curRow);

    var newRow = document.createElement("div");
    newRow.className = "cc-svc-stage-hex-row cc-svc-stage-hex-row--new";
    var newLabel = document.createElement("span");
    newLabel.className = "cc-svc-stage-hex-label";
    newLabel.textContent = "staged";
    var newVal = document.createElement("code");
    newVal.className = "cc-svc-stage-hex-val";
    newVal.textContent = scp03FormatHexGroups(startHex) || "(empty)";
    newRow.appendChild(newLabel);
    newRow.appendChild(newVal);
    preview.appendChild(newRow);

    var meta = document.createElement("div");
    meta.className = "cc-svc-stage-meta";
    var counts = document.createElement("span");
    counts.className = "cc-svc-stage-counts";
    var diffChip = document.createElement("span");
    diffChip.className = "cc-svc-stage-diff";
    meta.appendChild(counts);
    meta.appendChild(diffChip);
    preview.appendChild(meta);

    // Action bar — Copy hex / Reset / Send to UPDATE BINARY
    var actions = document.createElement("div");
    actions.className = "cc-svc-stage-actions";

    var copyHex = document.createElement("button");
    copyHex.type = "button";
    copyHex.className = "btn btn-secondary";
    copyHex.textContent = "Copy hex";
    actions.appendChild(copyHex);

    var resetBtn = document.createElement("button");
    resetBtn.type = "button";
    resetBtn.className = "btn btn-secondary";
    resetBtn.textContent = "Reset";
    actions.appendChild(resetBtn);

    var sendBtn = document.createElement("button");
    sendBtn.type = "button";
    sendBtn.className = "btn btn-primary";
    sendBtn.textContent = isRecordMode ? "Send to UPDATE RECORD" : "Send to UPDATE BINARY";
    sendBtn.title = (tab && tab.sessionId)
      ? ("Open the " + (isRecordMode ? "UPDATE RECORD" : "UPDATE BINARY")
        + " wizard with the staged bytes pre-filled.")
      : "Open a session first.";
    actions.appendChild(sendBtn);

    preview.appendChild(actions);
    card.appendChild(preview);

    // ---- Filter bar ---------------------------------------------------------
    var filterRow = document.createElement("div");
    filterRow.className = "cc-svc-stage-filter";

    var search = document.createElement("input");
    search.type = "text";
    search.className = "cc-svc-stage-search";
    search.placeholder = "Filter by name or number\u2026";
    filterRow.appendChild(search);

    var modeSel = document.createElement("select");
    modeSel.className = "cc-svc-stage-mode";
    [
      { v: "all", t: "All services" },
      { v: "active", t: "Active only" },
      { v: "inactive", t: "Not set only" },
      { v: "changed", t: "Changed since open" },
    ].forEach(function (opt) {
      var o = document.createElement("option");
      o.value = opt.v;
      o.textContent = opt.t;
      modeSel.appendChild(o);
    });
    filterRow.appendChild(modeSel);

    card.appendChild(filterRow);

    // ---- Service-row checklist ---------------------------------------------
    var list = document.createElement("ul");
    list.className = "cc-svc-stage-list";
    card.appendChild(list);

    // Track the original "active" set so we can highlight rows the
    // operator has touched and also drive the "changed since open"
    // filter mode.
    var initialActive = {};
    var current = {};
    entries.forEach(function (entry) {
      initialActive[entry.n] = entry.active === true;
      current[entry.n] = entry.active === true;
    });

    var rowEls = [];

    function activeNumbers() {
      var out = [];
      Object.keys(current).forEach(function (k) {
        if (current[k]) out.push(parseInt(k, 10));
      });
      out.sort(function (a, b) { return a - b; });
      return out;
    }

    function applyFilter() {
      var query = (search.value || "").toLowerCase().trim();
      var mode = modeSel.value;
      rowEls.forEach(function (item) {
        var entry = item.entry;
        var labelTxt = (entry.n + (entry.name ? " " + entry.name : "")).toLowerCase();
        var matchesQuery = query.length === 0 || labelTxt.indexOf(query) !== -1;
        var matchesMode = true;
        if (mode === "active") matchesMode = current[entry.n] === true;
        else if (mode === "inactive") matchesMode = current[entry.n] !== true;
        else if (mode === "changed") {
          matchesMode = (initialActive[entry.n] === true)
            !== (current[entry.n] === true);
        }
        item.row.hidden = !(matchesQuery && matchesMode);
      });
    }

    var stageInFlight = null;

    async function refreshPreview() {
      // Single in-flight guard — if the operator hammers checkboxes
      // we want the *latest* request to win, so we abort by overwriting
      // the inFlight token rather than chaining promises.
      var token = {};
      stageInFlight = token;
      var bits = activeNumbers();
      try {
        var resp = await apiFetch("/api/actions/scp03.stage_service_table/run", {
          method: "POST",
          body: JSON.stringify({ inputs: {
            active: bits,
            current_hex: startHex,
            table: kind,
          } }),
        });
        if (stageInFlight !== token) return;
        if (!resp || resp.ok === false) {
          newVal.textContent = "(stage error: "
            + ((resp && resp.error) || "unknown") + ")";
          return;
        }
        var data = resp.data || {};
        if (typeof data.new_hex !== "string") {
          newVal.textContent = "(error)";
          return;
        }
        newVal.textContent = scp03FormatHexGroups(data.new_hex) || "(empty)";
        var changed = Array.isArray(data.diff_bytes) ? data.diff_bytes.length : 0;
        diffChip.textContent = changed > 0
          ? (changed + " byte" + (changed === 1 ? "" : "s") + " changed")
          : "no change";
        diffChip.classList.toggle("is-changed", changed > 0);
        var totalBits = (data.byte_count || 0) * 8;
        counts.textContent = bits.length + " active / "
          + (totalBits - bits.length) + " not set ("
          + (data.byte_count || 0) + " B)";
      } catch (err) {
        if (stageInFlight !== token) return;
        newVal.textContent = "(stage error: "
          + (err && err.message ? err.message : err) + ")";
      }
    }

    entries.forEach(function (entry) {
      var row = document.createElement("li");
      row.className = "cc-svc-stage-row";
      if (entry.active) row.classList.add("is-active");

      var cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "cc-svc-stage-cb";
      cb.checked = entry.active === true;
      cb.id = "cc-svc-stage-cb-" + entry.n;

      var label = document.createElement("label");
      label.className = "cc-svc-stage-label";
      label.htmlFor = cb.id;
      var num = document.createElement("span");
      num.className = "cc-svc-stage-num";
      num.textContent = String(entry.n);
      var name = document.createElement("span");
      name.className = "cc-svc-stage-name";
      name.textContent = entry.name || "";
      label.appendChild(num);
      if (entry.name) label.appendChild(name);

      cb.addEventListener("change", function () {
        current[entry.n] = cb.checked;
        row.classList.toggle("is-active", cb.checked);
        var dirty = (initialActive[entry.n] === true) !== (current[entry.n] === true);
        row.classList.toggle("is-dirty", dirty);
        refreshPreview();
      });

      row.appendChild(cb);
      row.appendChild(label);
      list.appendChild(row);
      rowEls.push({ row: row, entry: entry });
    });

    search.addEventListener("input", applyFilter);
    modeSel.addEventListener("change", applyFilter);

    copyHex.addEventListener("click", function () {
      var raw = (newVal.textContent || "").replace(/\s+/g, "");
      if (raw.length === 0) return;
      if (typeof copyTextToClipboard === "function") {
        copyTextToClipboard(raw);
      } else if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(raw).catch(function () {});
      }
      copyHex.classList.add("is-copied");
      setTimeout(function () { copyHex.classList.remove("is-copied"); }, 700);
    });

    resetBtn.addEventListener("click", function () {
      rowEls.forEach(function (item) {
        var entry = item.entry;
        var checkbox = item.row.querySelector(".cc-svc-stage-cb");
        var was = initialActive[entry.n] === true;
        if (checkbox) checkbox.checked = was;
        current[entry.n] = was;
        item.row.classList.toggle("is-active", was);
        item.row.classList.remove("is-dirty");
      });
      refreshPreview();
    });

    sendBtn.addEventListener("click", function () {
      var raw = (newVal.textContent || "").replace(/\s+/g, "");
      if (raw.length === 0) return;
      if (!tab || !tab.sessionId) {
        sendBtn.title = "Open a session first.";
        return;
      }
      if (typeof scp03ShowFsUpdateBinary !== "function") return;
      // Honour the auth gate — UPDATE BINARY is flagged
      // ``requires_auth=True``, so the existing ``scp03GateOpen``
      // helper will pop the credential modal first if needed.
      try {
        if (typeof scp03GateOpen === "function") {
          var gated = scp03GateOpen(tab, "scp03.update_binary", function () {
            scp03StageOpenUpdateBinary(tab, raw);
          });
          gated();
        } else {
          scp03StageOpenUpdateBinary(tab, raw);
        }
      } catch (err) {
        scp03StageOpenUpdateBinary(tab, raw);
      }
    });

    refreshPreview();
    applyFilter();
  }

  // Helper: open the existing UPDATE BINARY wizard and pre-fill the
  // hex_data field with the staged bytes. We poll for the wizard's
  // input element after ``scp03ShowFsUpdateBinary`` paints because
  // the popout builder is async-ish (DOM append happens in the same
  // tick but we want belt + braces).
  function scp03StageOpenUpdateBinary(tab, stagedHex, pathText) {
    if (typeof scp03ShowFsUpdateBinary !== "function") return;
    Promise.resolve(scp03ShowFsUpdateBinary(tab)).then(function () {
      var pathInput = document.getElementById("cc-fs-wiz-path");
      if (pathInput && pathText) {
        pathInput.value = String(pathText);
        pathInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
      // The wizard's data textarea is keyed by ``cc-fs-wiz-hex_data``.
      var hexInput = document.getElementById("cc-fs-wiz-hex_data");
      if (hexInput) {
        hexInput.value = stagedHex;
        hexInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
    });
  }

  function scp03StageOpenUpdateRecord(tab, stagedHex, recordNo, pathText) {
    if (typeof scp03ShowFsUpdateRecord !== "function") return;
    Promise.resolve(scp03ShowFsUpdateRecord(tab, "linear")).then(function () {
      var recordInput = document.getElementById("cc-fs-wiz-record");
      if (recordInput && recordNo > 0) {
        recordInput.value = String(recordNo);
        recordInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
      var pathInput = document.getElementById("cc-fs-wiz-path");
      if (pathInput && pathText) {
        pathInput.value = String(pathText);
        pathInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
      var hexInput = document.getElementById("cc-fs-wiz-hex_data");
      if (hexInput) {
        hexInput.value = stagedHex;
        hexInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
    });
  }

  // =========================================================================
  // Generic stage-edit popout — for any decoded EF that is NOT a
  // service-table bitmap. The service-table flow keeps its purpose-built
  // checklist; everything else gets a side-by-side hex editor seeded
  // with the current bytes, with the structured pretty view rendered
  // read-only above for context. The Send-to-UPDATE-BINARY path is
  // gated through the same ``scp03GateOpen`` helper so the auth modal
  // still pops before the wizard pre-fills.
  //
  // Why a generic editor: not every EF is a bitmap. Records, TLV blobs,
  // certificates, and PIN templates have heterogeneous structure that
  // can't be reduced to a checklist. A predictable hex view keeps the
  // operator in control and avoids mis-encoding edge cases that a
  // half-finished structured editor would introduce.
  // =========================================================================
  function scp03StageHexNormalise(text) {
    // Strip whitespace and uppercase. The textarea visually retains
    // operator-typed spaces; the diff / send paths work on the cleaned
    // form so a stray newline doesn't change the byte count.
    return String(text || "").replace(/\s+/g, "").toUpperCase();
  }

  function scp03StageBytesChanged(currentHex, stagedHex) {
    // Per-byte diff count, padded to the longer length so size deltas
    // surface as "extra" diffs instead of being silently swallowed.
    var a = scp03StageHexNormalise(currentHex);
    var b = scp03StageHexNormalise(stagedHex);
    var maxLen = Math.max(a.length, b.length);
    if (maxLen === 0) return 0;
    var diff = 0;
    for (var i = 0; i < maxLen; i += 2) {
      var ca = a.substring(i, i + 2);
      var cb = b.substring(i, i + 2);
      if (ca !== cb) diff += 1;
    }
    return diff;
  }

  function scp03StageInferLabel(decoded) {
    if (!decoded || typeof decoded !== "object") return "Decoded EF";
    var fid = String(decoded.fid || decoded.file_id || "").toUpperCase();
    var name = String(decoded.full_name || decoded.name || decoded.kind || "");
    if (fid.length > 0 && name.length > 0) return name + " (" + fid + ")";
    if (name.length > 0) return name;
    if (fid.length > 0) return "EF " + fid;
    return "Decoded EF";
  }

  function scp03StageInferFid(meta, decoded) {
    if (meta && meta.fid) {
      return String(meta.fid).replace(/\s+/g, "").toUpperCase();
    }
    if (decoded && (decoded.fid || decoded.file_id)) {
      return String(decoded.fid || decoded.file_id).replace(/\s+/g, "").toUpperCase();
    }
    return "";
  }

  function scp03ShowGenericStaging(decoded, currentHex) {
    var tab = scp03GetActiveTab();
    var label = scp03StageInferLabel(decoded);
    var card = scp03BuildExtrasCard("Stage edit \u2014 " + label);
    if (!card) return;
    var stageGateOpen = (typeof scp03GateOpen === "function") ? scp03GateOpen : null;
    var stageOpenUpdateBinary = scp03StageOpenUpdateBinary;

    var startHex = scp03StageHexNormalise(currentHex);
    var startBytes = startHex.length / 2;
    var meta = arguments.length > 2 ? arguments[2] : null;
    var stageMeta = meta || {};
    var pathText = String(stageMeta.path || "").trim();
    var recordNo = Number(stageMeta.record || 0);
    var isRecordMode = Number.isFinite(recordNo) && recordNo > 0;
    var fidHint = scp03StageInferFid(stageMeta, decoded);

    var explainer = document.createElement("p");
    explainer.className = "cc-fs-op-hint";
    explainer.innerHTML =
      "Edit the EF hex below. The resulting bytes are <strong>not "
      + "written to the card</strong> until you open "
      + (isRecordMode ? "UPDATE RECORD" : "UPDATE BINARY")
      + " with these bytes pre-filled.";
    card.appendChild(explainer);

    // ---- Read-only structured context -------------------------------------
    var ctx = document.createElement("details");
    ctx.className = "cc-stage-context";
    ctx.open = false;
    var ctxSummary = document.createElement("summary");
    ctxSummary.className = "cc-stage-context-summary";
    ctxSummary.textContent = "Decoded structure (read-only)";
    ctx.appendChild(ctxSummary);
    var ctxBody = document.createElement("pre");
    ctxBody.className = "cc-stage-context-body";
    try {
      ctxBody.textContent = JSON.stringify(decoded, null, 2);
    } catch (_err) {
      ctxBody.textContent = String(decoded);
    }
    ctx.appendChild(ctxBody);
    card.appendChild(ctx);

    var decodePreview = document.createElement("div");
    decodePreview.className = "cc-stage-decoded-preview";
    var decodeHead = document.createElement("p");
    decodeHead.className = "cc-fs-op-hint";
    decodeHead.textContent = "Decoded preview (updates while typing)";
    decodePreview.appendChild(decodeHead);
    var decodeBody = document.createElement("div");
    decodePreview.appendChild(decodeBody);
    card.appendChild(decodePreview);

    // ---- Hex preview + counter chip --------------------------------------
    var preview = document.createElement("div");
    preview.className = "cc-svc-stage-preview";

    var curRow = document.createElement("div");
    curRow.className = "cc-svc-stage-hex-row";
    var curLabel = document.createElement("span");
    curLabel.className = "cc-svc-stage-hex-label";
    curLabel.textContent = "current";
    var curVal = document.createElement("code");
    curVal.className = "cc-svc-stage-hex-val";
    curVal.textContent = scp03FormatHexGroups(startHex) || "(empty)";
    curRow.appendChild(curLabel);
    curRow.appendChild(curVal);
    preview.appendChild(curRow);

    var meta = document.createElement("div");
    meta.className = "cc-svc-stage-meta";
    var counts = document.createElement("span");
    counts.className = "cc-svc-stage-counts";
    var diffChip = document.createElement("span");
    diffChip.className = "cc-svc-stage-diff";
    meta.appendChild(counts);
    meta.appendChild(diffChip);
    preview.appendChild(meta);
    card.appendChild(preview);

    // ---- Editable hex textarea -------------------------------------------
    var editor = document.createElement("textarea");
    editor.className = "cc-stage-editor";
    editor.spellcheck = false;
    editor.setAttribute("aria-label", "Staged EF hex");
    editor.rows = Math.min(12, Math.max(4, Math.ceil(startBytes / 16) + 1));
    editor.value = scp03FormatHexGroups(startHex);
    card.appendChild(editor);

    // ---- Action bar -------------------------------------------------------
    var actions = document.createElement("div");
    actions.className = "cc-svc-stage-actions";

    var copyHex = document.createElement("button");
    copyHex.type = "button";
    copyHex.className = "btn btn-secondary";
    copyHex.textContent = "Copy hex";
    actions.appendChild(copyHex);

    var resetBtn = document.createElement("button");
    resetBtn.type = "button";
    resetBtn.className = "btn btn-secondary";
    resetBtn.textContent = "Reset";
    actions.appendChild(resetBtn);

    var sendBtn = document.createElement("button");
    sendBtn.type = "button";
    sendBtn.className = "btn btn-primary";
    sendBtn.textContent = "Send to UPDATE BINARY";
    sendBtn.title = (tab && tab.sessionId)
      ? "Open the UPDATE BINARY wizard with the staged bytes pre-filled."
      : "Open a session to enable UPDATE BINARY.";
    actions.appendChild(sendBtn);
    card.appendChild(actions);

    var decodeSeq = 0;
    function refreshDecodedPreview(stagedHex) {
      var token = ++decodeSeq;
      if (stagedHex.length === 0 || stagedHex.length % 2 !== 0) {
        decodeBody.innerHTML = "";
        var hint = document.createElement("p");
        hint.className = "cc-empty";
        hint.textContent = stagedHex.length === 0
          ? "(no bytes staged)"
          : "(waiting for whole-byte hex)";
        decodeBody.appendChild(hint);
        return;
      }
      decodeBody.innerHTML = "";
      decodeBody.appendChild(loadingEl("decoding staged bytes…"));
      apiFetch("/api/actions/scp03.decode/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: {
            hex_data: stagedHex,
            fid: fidHint,
            context_path: pathText,
          },
        }),
      }).then(function (resp) {
        if (token !== decodeSeq) return;
        decodeBody.innerHTML = "";
        if (!resp.ok) {
          decodeBody.appendChild(renderErrorBlock(resp.error || "decode failed"));
          return;
        }
        var data = resp.data || {};
        if (data.content_decoded != null) {
          decodeBody.appendChild(renderDecodedBlock(data.content_decoded, null, { omitHead: true }));
          if (data.content_error) {
            var warn = document.createElement("p");
            warn.className = "cc-warn";
            warn.textContent = "content decoder: " + String(data.content_error);
            decodeBody.appendChild(warn);
          }
          return;
        }
        if (data.parsed != null) {
          decodeBody.appendChild(renderDecodedBlock(data.parsed, null, { omitHead: true }));
          return;
        }
        var empty = document.createElement("p");
        empty.className = "cc-empty";
        empty.textContent = "(decoder returned no structured output)";
        decodeBody.appendChild(empty);
      }).catch(function (err) {
        if (token !== decodeSeq) return;
        decodeBody.innerHTML = "";
        decodeBody.appendChild(renderErrorBlock(String(err && err.message || err)));
      });
    }

    function refreshChip() {
      var staged = scp03StageHexNormalise(editor.value);
      var bytes = staged.length / 2;
      var changed = scp03StageBytesChanged(startHex, staged);
      refreshDecodedPreview(staged);
      counts.textContent = bytes + " B staged \u00B7 "
        + startBytes + " B current";
      if (staged.length === 0) {
        diffChip.textContent = "(empty)";
        diffChip.classList.remove("is-changed");
        return;
      }
      // Odd hex length is a typo — surface it before the operator
      // hands the bytes to UPDATE BINARY where the dispatcher will
      // reject the request anyway.
      if (staged.length % 2 !== 0) {
        diffChip.textContent = "odd hex length";
        diffChip.classList.add("is-changed");
        return;
      }
      diffChip.textContent = changed > 0
        ? (changed + " byte" + (changed === 1 ? "" : "s") + " changed")
        : "no change";
      diffChip.classList.toggle("is-changed", changed > 0);
    }
    editor.addEventListener("input", refreshChip);
    refreshChip();

    copyHex.addEventListener("click", function () {
      var raw = scp03StageHexNormalise(editor.value);
      if (raw.length === 0) return;
      if (typeof copyTextToClipboard === "function") {
        copyTextToClipboard(raw);
      } else if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(raw).catch(function () {});
      }
      copyHex.classList.add("is-copied");
      setTimeout(function () { copyHex.classList.remove("is-copied"); }, 700);
    });

    resetBtn.addEventListener("click", function () {
      editor.value = scp03FormatHexGroups(startHex);
      refreshChip();
    });

    sendBtn.addEventListener("click", function () {
      var raw = scp03StageHexNormalise(editor.value);
      if (raw.length === 0) {
        sendBtn.title = "Nothing staged.";
        return;
      }
      if (raw.length % 2 !== 0) {
        sendBtn.title = "Staged hex must be a whole number of bytes.";
        return;
      }
      if (!tab || !tab.sessionId) {
        sendBtn.title = "Open a session first.";
        return;
      }
      if (!isRecordMode && typeof scp03ShowFsUpdateBinary !== "function") return;
      try {
        if (stageGateOpen) {
          var gated = stageGateOpen(tab, isRecordMode ? "scp03.update_record" : "scp03.update_binary", function () {
            if (isRecordMode) {
              scp03StageOpenUpdateRecord(tab, raw, recordNo, pathText);
            } else {
              stageOpenUpdateBinary(tab, raw);
            }
          });
          gated();
        } else {
          if (isRecordMode) {
            scp03StageOpenUpdateRecord(tab, raw, recordNo, pathText);
          } else {
            stageOpenUpdateBinary(tab, raw);
          }
        }
      } catch (_err) {
        if (isRecordMode) {
          scp03StageOpenUpdateRecord(tab, raw, recordNo, pathText);
        } else {
          stageOpenUpdateBinary(tab, raw);
        }
      }
    });
  }

  // =========================================================================
  // FS — lifecycle wizard (ACTIVATE / DEACTIVATE / TERMINATE_DF / TERMINATE_EF)
  // Per-op explanation panel + conditional confirm token — only required for
  // the two terminal-state operations.
  // =========================================================================
  var _FS_LIFECYCLE_OPS = {
    ACTIVATE: {
      title: "ACTIVATE (0044)",
      hint: "Moves an EF/DF lifecycle from DEACTIVATED back to ACTIVATED. "
        + "Fully reversible; frequently used to re-enable test profiles.",
      danger: false,
    },
    DEACTIVATE: {
      title: "DEACTIVATE (0004)",
      hint: "Temporarily suspends an EF/DF (reads return 6985). "
        + "ACTIVATE reverses it.",
      danger: false,
    },
    TERMINATE_DF: {
      title: "TERMINATE DF (00E6)",
      hint: "IRREVERSIBLE: marks the DF and its entire subtree as "
        + "TERMINATED. All child EFs become permanently inaccessible.",
      danger: true,
    },
    TERMINATE_EF: {
      title: "TERMINATE EF (00E8)",
      hint: "IRREVERSIBLE: marks the EF as TERMINATED. Subsequent reads "
        + "return 6283 or 6985 depending on the platform.",
      danger: true,
    },
  };

  async function scp03ShowFsLifecycle(tab) {
    var card = scp03BuildExtrasCard("FS — lifecycle");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "TERMINATE-DF / TERMINATE-EF are IRREVERSIBLE. Confirm token is "
        + "required for both; ACTIVATE / DEACTIVATE run without it."
    );

    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";

    var wrap = document.createElement("div");
    wrap.className = "cc-fs-wizard";

    var inputs = {};

    // Op dropdown
    var opRow = document.createElement("div");
    opRow.className = "cc-form-row cc-fs-wizard-row";
    var opLab = document.createElement("label");
    opLab.textContent = "Operation";
    opLab.htmlFor = "cc-fs-lcs-op";
    opRow.appendChild(opLab);
    var opSel = document.createElement("select");
    opSel.id = opLab.htmlFor;
    Object.keys(_FS_LIFECYCLE_OPS).forEach(function (k) {
      var o = document.createElement("option");
      o.value = k;
      o.textContent = _FS_LIFECYCLE_OPS[k].title;
      opSel.appendChild(o);
    });
    opSel.value = "ACTIVATE";
    inputs.op = opSel;
    opRow.appendChild(opSel);
    wrap.appendChild(opRow);

    var opHint = document.createElement("div");
    opHint.className = "cc-fs-op-hint";
    wrap.appendChild(opHint);

    var hintSel = scp03FsPickFromSelection(tab);
    wrap.appendChild(scp03MakeWizardField(inputs, "fid",
      "Target FID (4 hex, optional)", {
        placeholder: "6F07",
        value: hintSel.fid || "",
        help: "Leave empty to operate on the currently selected EF.",
      }));

    var confirmRow = scp03MakeWizardField(inputs, "confirm",
      "Confirm", {
        placeholder: "type TERMINATE",
        help: "Required for TERMINATE_DF and TERMINATE_EF only.",
      });
    wrap.appendChild(confirmRow);

    function refreshHint() {
      var meta = _FS_LIFECYCLE_OPS[opSel.value] || {};
      opHint.textContent = meta.hint || "";
      opHint.classList.toggle("cc-fs-op-hint-danger", !!meta.danger);
      // Confirm token only relevant for TERMINATE_*.
      if (meta.danger) {
        confirmRow.classList.remove("cc-fs-hidden");
        inputs.confirm.required = true;
      } else {
        confirmRow.classList.add("cc-fs-hidden");
        inputs.confirm.required = false;
      }
    }
    opSel.addEventListener("change", refreshHint);
    refreshHint();

    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var submit = document.createElement("button");
    submit.type = "button";
    submit.className = "btn btn-primary";
    submit.textContent = "Run";
    bar.appendChild(submit);
    wrap.appendChild(bar);

    submit.addEventListener("click", async function () {
      submit.disabled = true;
      await scp03RunActionWithOutput(out, "scp03.fs_lifecycle", {
        session_id: tab.sessionId,
        op: inputs.op.value,
        fid: (inputs.fid.value || "").trim(),
        confirm: (inputs.confirm.value || "").trim(),
      }, function (data, sheet) {
        scp03RenderMutationActionResult(sheet, data, [
          { label: "Op", value: data.op || "" },
          { label: "FID", value: data.fid || "(current)" },
        ]);
      });
      submit.disabled = false;
    });

    card.appendChild(wrap);
    card.appendChild(out);
  }

  // =========================================================================
  // FS — SEARCH RECORD wizard
  // Hex needle field + live ASCII mirror so operators can verify the
  // string they're scanning for ("3034" = "04").
  // =========================================================================
  async function scp03ShowFsSearchRecord(tab) {
    var card = scp03BuildExtrasCard("FS — SEARCH RECORD (00A2)");
    if (!card) return;

    var explain = document.createElement("p");
    explain.className = "cc-fs-op-hint";
    explain.innerHTML =
      "SEARCH RECORD walks a linear-fixed EF looking for a record whose "
      + "bytes match the hex needle. Leave the target empty to search the "
      + "currently selected EF.";
    card.appendChild(explain);

    var hint = scp03FsPickFromSelection(tab);

    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";

    var wrap = document.createElement("div");
    wrap.className = "cc-fs-wizard";
    var inputs = {};

    wrap.appendChild(scp03MakeWizardField(inputs, "target",
      "Target EF path (hex, optional)", {
        placeholder: "3F007F106F3A",
        value: hint.parent && hint.fid ? (hint.parent + hint.fid) : "",
        help: "2-byte FIDs concatenated, ending at the EF.",
      }));

    // Hex needle + ASCII mirror.
    var needleRow = scp03MakeWizardField(inputs, "search_hex",
      "Search needle (hex)", {
        placeholder: "3034",
        required: true,
        help: "Each record is scanned for this exact byte string.",
      });
    wrap.appendChild(needleRow);
    var ascii = document.createElement("div");
    ascii.className = "cc-field-hint cc-fs-mirror";
    needleRow.appendChild(ascii);
    function refreshAscii() {
      var hex = (inputs.search_hex.value || "").replace(/\s+/g, "");
      if (hex.length === 0) { ascii.textContent = ""; return; }
      if (hex.length % 2 !== 0 || !/^[0-9A-Fa-f]+$/.test(hex)) {
        ascii.textContent = "(needle is not even-length hex)";
        return;
      }
      try {
        var txt = "";
        for (var i = 0; i < hex.length; i += 2) {
          var b = parseInt(hex.substr(i, 2), 16);
          txt += (b >= 0x20 && b <= 0x7E) ? String.fromCharCode(b) : ".";
        }
        ascii.textContent = "ASCII: " + txt;
      } catch (err) { ascii.textContent = ""; }
    }
    inputs.search_hex.addEventListener("input", refreshAscii);
    refreshAscii();

    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var submit = document.createElement("button");
    submit.type = "button";
    submit.className = "btn btn-primary";
    submit.textContent = "Search";
    bar.appendChild(submit);
    wrap.appendChild(bar);

    submit.addEventListener("click", async function () {
      submit.disabled = true;
      await scp03RunActionWithOutput(out, "scp03.fs_search_record", {
        session_id: tab.sessionId,
        target: (inputs.target.value || "").trim(),
        search_hex: (inputs.search_hex.value || "").trim(),
      }, function (data, sheet) {
        scp03RenderMutationActionResult(sheet, data, [
          { label: "Target", value: data.target || "" },
          { label: "Needle", value: data.search_hex || "" },
        ]);
      });
      submit.disabled = false;
    });

    card.appendChild(wrap);
    card.appendChild(out);
  }

  // =========================================================================
  // FS — SUSPEND UICC wizard
  // Explains the session-terminating side effects up front. Typed confirm.
  // =========================================================================
  async function scp03ShowFsSuspendUicc(tab) {
    var card = scp03BuildExtrasCard("FS — SUSPEND UICC (8076)");
    if (!card) return;
    scp03BuildDestructiveBanner(
      card,
      "SUSPEND UICC puts the card into a low-power state. "
        + "The reader will typically drop the session; resume by cold-reset."
    );

    var details = document.createElement("p");
    details.className = "cc-fs-op-hint cc-fs-op-hint-danger";
    details.innerHTML =
      "This is the ETSI TS 102 221 §11.1.22 command. Most readers treat it "
      + "as a card removal and close the PC/SC handle \u2014 expect the tab "
      + "to drop. You'll need to reset + re-scan after issuing it.";
    card.appendChild(details);

    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";

    var wrap = document.createElement("div");
    wrap.className = "cc-fs-wizard";
    var inputs = {};
    wrap.appendChild(scp03MakeWizardField(inputs, "confirm",
      "Confirm", {
        placeholder: "type SUSPEND",
        required: true,
        help: "Backend rejects anything other than SUSPEND.",
      }));

    var bar = document.createElement("div");
    bar.className = "cc-action-bar";
    var submit = document.createElement("button");
    submit.type = "button";
    submit.className = "btn btn-primary";
    submit.textContent = "Suspend UICC";
    bar.appendChild(submit);
    wrap.appendChild(bar);

    submit.addEventListener("click", async function () {
      submit.disabled = true;
      await scp03RunActionWithOutput(out, "scp03.fs_suspend_uicc", {
        session_id: tab.sessionId,
        confirm: (inputs.confirm.value || "").trim(),
      }, function (data, sheet) {
        scp03RenderMutationActionResult(sheet, data, []);
      });
      submit.disabled = false;
    });

    card.appendChild(wrap);
    card.appendChild(out);
  }

  async function scp03ShowManagePin(tab) {
    var card = scp03BuildExtrasCard("Manage PIN");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "op", label: "Operation", kind: "select",
          choices: ["VERIFY", "CHANGE", "DISABLE", "ENABLE", "UNBLOCK"], required: true },
        { name: "pin_ref", label: "PIN reference (hex)", value: "01",
          help: "01 = PIN1, 02 = PIN2, 81 = ADM1, …" },
        { name: "pin", label: "PIN (ASCII)", placeholder: "1234" },
        { name: "new_pin", label: "New PIN (ASCII, for CHANGE / UNBLOCK)" },
        { name: "puk", label: "PUK (ASCII, for UNBLOCK)" },
      ],
      "Run",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.manage_pin", {
          session_id: tab.sessionId,
          op: (values.op || "").trim(),
          pin_ref: (values.pin_ref || "01").trim(),
          pin: (values.pin || "").toString(),
          new_pin: (values.new_pin || "").toString(),
          puk: (values.puk || "").toString(),
        }, function (data, sheet) {
          scp03RenderMutationActionResult(sheet, data, [
            { label: "Op", value: data.op || "" },
            { label: "PIN ref", value: data.pin_ref || "" },
            { label: "Attempts remaining", value: data.attempts_remaining == null ? "-" : String(data.attempts_remaining) },
          ]);
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03ShowManageChannel(tab) {
    var card = scp03BuildExtrasCard("MANAGE CHANNEL (0070)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "op", label: "Operation", kind: "select", choices: ["OPEN", "CLOSE"], required: true },
        { name: "channel", label: "Channel (hex, for CLOSE)", placeholder: "01" },
      ],
      "Run",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.manage_channel", {
          session_id: tab.sessionId,
          op: (values.op || "").trim(),
          channel: (values.channel || "").trim(),
        }, function (data, sheet) {
          scp03RenderMutationActionResult(sheet, data, [
            { label: "Op", value: data.op || "" },
            { label: "Assigned channel", value: data.assigned_channel || "-" },
          ]);
        });
      }
    );
    card.appendChild(out);
  }

  async function scp03LaunchSubShell(moduleName, initCommand, humanLabel) {
    // Shared helper for C-6 sub-shell shortcuts. Switches to the Terminal
    // view, pre-selects ``moduleName``, and kicks off startTerminal().
    // ``initCommand`` (optional) is queued and auto-typed into the child
    // once the PTY announces its "spawned" event.
    try {
      await loadTerminalModules();
    } catch (_err) {
      // loadTerminalModules() already surfaces the error in the status
      // banner; we proceed so the module select still renders manually.
    }
    var sel = $("terminal-module");
    if (!sel) {
      window.alert("terminal view is not available in this build.");
      return;
    }
    var matched = false;
    for (var i = 0; i < sel.options.length; i++) {
      if (sel.options[i].value === moduleName) {
        sel.selectedIndex = i;
        matched = true;
        break;
      }
    }
    if (!matched) {
      window.alert("module not in CLI_MODULES allow-list: " + moduleName);
      return;
    }
    terminalState.pendingInit = initCommand || null;
    showView("terminal");
    try {
      startTerminal();
    } catch (err) {
      window.alert("failed to launch " + humanLabel + ": " + (err && err.message || err));
    }
  }

  async function scp03ShowOpenStkShell(_tab) {
    await scp03LaunchSubShell("SCP03", "STK-SHELL\r", "STK sub-shell");
    logBus.emit({
      level: "info",
      source: "scp03.stk_shell",
      message: "handoff \u2192 python -m SCP03 (auto STK-SHELL)",
    });
  }

  async function scp03ShowOpenOtaShell(_tab) {
    await scp03LaunchSubShell("SCP80", null, "OTA (SCP80) shell");
    logBus.emit({
      level: "info",
      source: "scp03.ota_shell",
      message: "handoff \u2192 python -m SCP80",
    });
  }

  async function scp03ShowRunScript(tab) {
    var card = scp03BuildExtrasCard("Run script");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    var handle = scp03BuildInlineForm(
      card,
      [
        { name: "script_path", label: "Script file", required: false,
          placeholder: "/path/to/script.scp03",
          help: "Double-click or Browse\u2026 to pick a command file." },
        { name: "script_text", label: "Inline commands", kind: "textarea",
          placeholder: "SCP03-SD\nLIST\nQ",
          help: "Overrides script file when supplied. Newline or ; separated." },
        { name: "yaml_out", label: "YAML report path", required: false,
          placeholder: "/tmp/report.yaml",
          help: "Optional. Passed as --out to entry_cmd." },
      ],
      "Run",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.run_script", {
          script_path: (values.script_path || "").trim(),
          script_text: values.script_text || "",
          yaml_out: (values.yaml_out || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Source", value: data.source || "" },
            { label: "Commands", value: String(data.command_count || 0) },
            { label: "YAML out", value: data.yaml_out || "(none)" },
            { label: "Result", value: data.ok ? "OK" : "FAILED" },
          ]);
          if (data.error) scp03DatasheetAppendTraceMain(sheet, "error: " + data.error, "");
          scp03DatasheetAppendTraceMain(sheet, data.raw_trace, "");
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: "scp03.run_script",
            message: "ran " + String(data.command_count || 0) + " command(s) \u2192 "
              + (data.ok ? "ok" : "failed"),
          });
        });
      }
    );
    var pathInput = handle.inputs.script_path;
    if (pathInput && typeof attachPathPicker === "function") {
      var wrapped = attachPathPicker(pathInput, "open");
      if (pathInput.parentNode && wrapped && wrapped !== pathInput) {
        pathInput.parentNode.replaceChild(wrapped, pathInput);
      }
    }
    var yamlInput = handle.inputs.yaml_out;
    if (yamlInput && typeof attachPathPicker === "function") {
      var yamlWrapped = attachPathPicker(yamlInput, "save");
      if (yamlInput.parentNode && yamlWrapped && yamlWrapped !== yamlInput) {
        yamlInput.parentNode.replaceChild(yamlWrapped, yamlInput);
      }
    }
    card.appendChild(out);
  }

  async function scp03ShowFsReport(tab) {
    var card = scp03BuildExtrasCard("FS report (YAML)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    var handle = scp03BuildInlineForm(
      card,
      [
        { name: "filename", label: "Report path", required: true,
          value: "scan_report.yaml",
          help: "Absolute path or workspace-relative YAML filename." },
      ],
      "Generate",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.fs_report", {
          session_id: tab.sessionId,
          filename: (values.filename || "").trim(),
        }, function (data, sheet) {
          scp03DatasheetAppendMetaKvl(sheet, [
            { label: "Report", value: data.filename || "" },
            { label: "Size", value: String(data.file_size || 0) + " bytes" },
            { label: "Result", value: data.ok ? "OK" : "FAILED" },
          ]);
          if (data.error) scp03DatasheetAppendTraceMain(sheet, "error: " + data.error, "");
          scp03DatasheetAppendTraceMain(sheet, data.raw_trace, "");
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: "scp03.fs_report",
            message: "wrote " + (data.filename || "?") + " ("
              + (data.file_size || 0) + " B)",
          });
        });
      }
    );
    var filenameInput = handle.inputs.filename;
    if (filenameInput && typeof attachPathPicker === "function") {
      var wrapped = attachPathPicker(filenameInput, "save");
      if (filenameInput.parentNode && wrapped && wrapped !== filenameInput) {
        filenameInput.parentNode.replaceChild(wrapped, filenameInput);
      }
    }
    card.appendChild(out);
  }

  async function scp03ShowGuide(_tab) {
    var card = scp03BuildExtrasCard("Guides");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    out.appendChild(loadingEl("loading topics\u2026"));
    try {
      var resp = await apiFetch("/api/actions/scp03.guide_list/run", {
        method: "POST",
        body: JSON.stringify({ inputs: {} }),
      });
      out.innerHTML = "";
      if (!resp.ok) {
        out.appendChild(renderErrorBlock(resp.error || "guide_list failed"));
        card.appendChild(out);
        return;
      }
      var topics = (resp.data && resp.data.topics) || [];
      var choices = topics.map(function (t) { return t.code; });
      var labelByCode = {};
      topics.forEach(function (t) { labelByCode[t.code] = t.title; });
      scp03BuildInlineForm(
        card,
        [
          { name: "topic", label: "Topic", kind: "select", choices: choices,
            value: choices[0] || "GP", required: true,
            help: "Rendered as captured plain-text output." },
        ],
        "Show",
        async function (values) {
          await scp03RunActionWithOutput(out, "scp03.guide_show", {
            topic: (values.topic || "GP").toUpperCase(),
          }, function (data, sheet) {
            scp03DatasheetAppendMetaKvl(sheet, [
              { label: "Topic", value: data.topic || "" },
              { label: "Title", value: data.title || labelByCode[data.topic] || "" },
              { label: "Lines", value: String(data.line_count || 0) },
            ]);
            scp03DatasheetAppendTraceMain(sheet, data.raw_trace, "");
          });
        }
      );
    } catch (err) {
      out.innerHTML = "";
      out.appendChild(renderErrorBlock(String(err && err.message || err)));
    }
    card.appendChild(out);
  }

  async function scp03ShowRunAuthLive(tab) {
    var card = scp03BuildExtrasCard("Run AUTHENTICATE (live)");
    if (!card) return;
    var out = document.createElement("div");
    out.className = "cc-wb-extras-out";
    scp03BuildInlineForm(
      card,
      [
        { name: "context", label: "Context", kind: "select",
          choices: ["USIM", "ISIM", "GSM"], value: "USIM", required: true },
        { name: "rand", label: "RAND (32 hex)", required: true },
        { name: "autn", label: "AUTN (32 hex, USIM/ISIM)" },
      ],
      "Authenticate",
      async function (values) {
        await scp03RunActionWithOutput(out, "scp03.run_auth_live", {
          session_id: tab.sessionId,
          context: values.context || "USIM",
          rand: (values.rand || "").trim(),
          autn: (values.autn || "").trim(),
        }, function (data, sheet) {
          var rows = [
            { label: "Context", value: data.context || "" },
            { label: "Status", value: data.status || "" },
            { label: "SW", value: data.sw || "" },
          ];
          var resp = data.response || {};
          if (resp.status) rows.push({ label: "Response", value: resp.status });
          if (resp.res) rows.push({ label: "RES", value: resp.res });
          if (resp.ck) rows.push({ label: "CK", value: resp.ck });
          if (resp.ik) rows.push({ label: "IK", value: resp.ik });
          if (resp.kc) rows.push({ label: "Kc", value: resp.kc });
          if (resp.sres) rows.push({ label: "SRES", value: resp.sres });
          if (resp.auts) rows.push({ label: "AUTS", value: resp.auts });
          scp03DatasheetAppendMetaKvl(sheet, rows);
          if (resp.raw_hex) {
            scp03DatasheetAppendTraceMain(sheet, "Raw response: " + resp.raw_hex, "");
          }
          logBus.emit({
            level: data.ok ? "info" : "warn",
            source: "scp03.run_auth_live",
            message: (data.context || "?") + " AUTH → " + (data.ok ? (resp.status || "ok") : "failed"),
          });
        });
      }
    );
    card.appendChild(out);
  }

  function loadingEl(text) {
    var p = document.createElement("p");
    p.className = "loading";
    p.textContent = text;
    return p;
  }

  function scp03ClearLoading(card) {
    var loading = card.querySelector(".loading");
    if (loading && loading.parentNode) loading.parentNode.removeChild(loading);
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
    // Closing a tab is an explicit "forget this reader" action — the
    // user clicked × on the pill, not just navigated away. Purge the
    // persisted state so the next pill-click on this reader starts
    // fresh. (Resuming a closed tab later is cheap: re-scan + re-read.)
    if (tab.readerName) {
      scp03PurgePersisted(tab.readerName);
    }
    // Floating popouts are bound to the tab — explicit close is the
    // operator's "forget this session" gesture, so tear the windows
    // down alongside the session + persisted cache.
    scp03PopoutCloseAllForTab(tab);
    wb.tabs = wb.tabs.filter(function (entry) { return entry.id !== tabId; });
    if (wb.activeTabId === tabId) {
      wb.activeTabId = wb.tabs.length > 0 ? wb.tabs[0].id : null;
    }
    if (wb.tabs.length === 0) {
      scp03EnsureDefaultTab();
    }
    renderScp03Tabs(tabBar, tabBody);
    if (typeof readerBarNotifySessionChanged === "function") {
      readerBarNotifySessionChanged();
    }
  }
