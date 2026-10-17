  // -- Plugin consoles: runs, the current run and the history ----------------
  //
  // Run posts the planned request to /api/plugin-consoles/<id>/runs (after
  // storing any credential a selected item needs and the operator typed,
  // with the entry picked for each needed named credential) and attaches to
  // the new run: while it is active the view polls its
  // events every second and its report every other second, and a run another
  // surface started is attached from the console status (active_run). States
  // come from a fixed vocabulary and colour through the status tokens; every
  // report text is set with textContent.

  var PC_RUN_POLL_MS = 1000;
  var PC_RUN_HISTORY_LIMIT = 30;
  var PC_RUN_STATE_TONES = {
    passed: "ok",
    failed: "fail",
    error: "fail",
    cancelled: "warn",
    skipped: "warn",
    queued: "busy",
    running: "busy",
    pending: "busy",
  };

  function pcRunResetState() {
    pcState.runVariant = "";
    pcState.runActive = "";
    pcState.runViewed = "";
    pcState.runAfter = 0;
    pcState.runTick = 0;
    pcState.runPolling = false;
    pcState.runStarting = false;
    pcState.runHistory = [];
    pcState.credentials = {};
    pcState.credentialDrafts = {};
    pcState.credentialPicks = {};
  }

  function pcRenderRuns(manifest) {
    pcRunStopPoll();
    pcRunResetState();
    var host = $("pc-runs");
    if (host) host.hidden = !manifest.runs;
    if (!manifest.runs) return;
    var labels = manifest.runs.labels;
    setText("pc-run-form-title", labels.form);
    setText("pc-run-before-title", labels.credentials);
    setText("pc-credentials-title", labels.credentials);
    setText("pc-run-items-title", labels.items);
    setText("pc-run-start", labels.start);
    setText("pc-run-cancel", labels.cancel);
    setText("pc-run-current-title", labels.current);
    setText("pc-run-history-title", labels.history);
    pcRenderRunVariantSelect(manifest.runs);
    pcRenderRunCommon(manifest.runs);
    pcRenderRunForm();
    pcRenderRunReport(null);
    pcRenderRunHistory();
    pcLoadCredentials();
    pcLoadRunHistory();
  }

  function pcRenderRunState(status) {
    var chip = $("pc-run-state");
    if (!chip) return;
    chip.textContent = status || "no run";
    chip.dataset.state = PC_RUN_STATE_TONES[status] || "idle";
  }

  // -- starting and cancelling -----------------------------------------------

  async function pcStartRun() {
    var consoleId = pcState.activeId;
    var plan = pcRunCurrentPlan();
    if (!plan || pcState.runStarting) return;
    pcState.runStarting = true;
    pcRunValidate(plan);
    var failure = "";
    try {
      for (var i = 0; i < plan.credentials.length && !failure; i += 1) {
        if (pcCredentialTyped(plan.credentials[i])) failure = await pcStoreCredential(plan.credentials[i]);
      }
      if (!failure) {
        var values = {};
        plan.visible.forEach(function (name) { values[name] = plan.given[name]; });
        var request = { variant: pcState.runVariant, items: plan.items, values: values };
        var picks = pcCredentialPicks(plan.credentials);
        if (picks) request.credential_entries = picks;
        var summary = await apiFetch(pcApi(consoleId, "/runs"), {
          method: "POST",
          body: JSON.stringify(request),
        });
        if (consoleId === pcState.activeId) {
          if (summary.id === pcState.runActive) {
            // The console added the start to the run in progress: keep following it.
            logBus.emit({ level: "info", source: "plugin-console", message: pcState.manifest.title + ": added to run " + summary.id + "." });
          } else {
            pcState.runHistory.unshift(summary);
            pcAttachRun(summary.id);
            logBus.emit({ level: "info", source: "plugin-console", message: pcState.manifest.title + ": run " + summary.id + " started." });
          }
        }
      }
    } catch (err) {
      failure = pcErrorText(err);
    }
    pcState.runStarting = false;
    if (consoleId !== pcState.activeId) return;
    pcRunValidate();
    if (failure) pcSetRunMessage(failure, "error");
  }

  async function pcCancelRun() {
    var consoleId = pcState.activeId;
    var runId = pcState.runActive;
    if (!runId) return;
    try {
      await apiFetch(pcApi(consoleId, "/runs/" + encodeURIComponent(runId) + "/cancel"), { method: "POST", body: "{}" });
    } catch (err) {
      if (consoleId === pcState.activeId) pcSetRunMessage(pcErrorText(err), "error");
    }
  }

  // -- following a run -------------------------------------------------------

  function pcRunStopPoll() {
    if (pcState.runTimer) {
      clearTimeout(pcState.runTimer);
      pcState.runTimer = null;
    }
  }

  function pcAttachRun(runId) {
    pcRunStopPoll();
    pcState.runActive = runId;
    pcState.runViewed = runId;
    pcState.runAfter = 0;
    pcState.runTick = 0;
    var log = $("pc-run-log");
    if (log) log.textContent = "";
    var cancel = $("pc-run-cancel");
    if (cancel) cancel.disabled = false;
    pcRenderRunState("queued");
    pcRenderRunHistory();
    pcRunValidate();
    pcRunPoll();
  }

  function pcDetachRun() {
    pcRunStopPoll();
    pcState.runActive = "";
    var cancel = $("pc-run-cancel");
    if (cancel) cancel.disabled = true;
    pcRunValidate();
    pcLoadRunHistory();
  }

  async function pcRunPoll() {
    pcRunStopPoll();
    var consoleId = pcState.activeId;
    var runId = pcState.runActive;
    if (!runId || state.activeView !== "plugin_console" || pcState.runPolling) return;
    pcState.runPolling = true;
    var finished = false;
    var path = "/runs/" + encodeURIComponent(runId);
    try {
      var batch = await apiFetch(pcApi(consoleId, path + "/events?after=" + String(pcState.runAfter)));
      if (consoleId === pcState.activeId && runId === pcState.runActive) {
        pcAppendRunEvents(batch.entries || []);
        pcState.runAfter = Number(batch.next) || pcState.runAfter;
        finished = Boolean(batch.finished);
        if (pcState.runTick % 2 === 0 || finished) {
          var report = await apiFetch(pcApi(consoleId, path));
          if (consoleId === pcState.activeId && runId === pcState.runViewed) pcRenderRunReport(report);
          finished = finished || Boolean(report.finished);
        }
      }
    } catch (err) {
      if (consoleId === pcState.activeId) {
        pcAppendRunEvents([{ time: "", level: "error", text: pcErrorText(err) }]);
        finished = true;
      }
    }
    pcState.runPolling = false;
    pcState.runTick += 1;
    if (consoleId !== pcState.activeId) return;
    if (runId !== pcState.runActive) {
      // Another run was attached while this poll was out; it waited for this one.
      if (pcState.runActive && !pcState.runTimer) pcState.runTimer = setTimeout(pcRunPoll, 0);
      return;
    }
    if (finished) {
      pcDetachRun();
      return;
    }
    if (state.activeView === "plugin_console") {
      pcState.runTimer = setTimeout(pcRunPoll, PC_RUN_POLL_MS);
    }
  }

  function pcRunsOnStatus(status) {
    if (!pcRuns() || !status) return;
    var active = typeof status.active_run === "string" ? status.active_run : "";
    if (!active || pcState.runPolling || pcState.runStarting) return;
    if (active !== pcState.runActive || !pcState.runTimer) pcAttachRun(active);
  }

  // -- the report and the log --------------------------------------------------

  function pcAppendRunEvents(entries) {
    var log = $("pc-run-log");
    if (!log) return;
    entries.forEach(function (entry) {
      var row = document.createElement("div");
      row.className = "flow-row flow-row--" + String(entry.level || "info");
      var time = document.createElement("span");
      time.className = "flow-ts";
      time.textContent = String(entry.time || "");
      var level = document.createElement("span");
      level.className = "flow-level";
      level.textContent = String(entry.level || "info").toUpperCase();
      var body = document.createElement("span");
      body.className = "flow-body";
      body.textContent = String(entry.text || "");
      row.appendChild(time);
      row.appendChild(level);
      row.appendChild(body);
      log.appendChild(row);
    });
    while (log.childElementCount > FLOW_LOG_MAX_ROWS) {
      log.removeChild(log.firstChild);
    }
    log.scrollTop = log.scrollHeight;
  }

  function pcRunResult(result) {
    var item = document.createElement("div");
    item.className = "pc-run-result";
    var label = document.createElement("div");
    label.className = "pc-run-result-label";
    label.textContent = result.label;
    item.appendChild(label);
    var chip = document.createElement("span");
    chip.className = "pc-status";
    chip.dataset.state = PC_RUN_STATE_TONES[result.status] || "idle";
    chip.textContent = result.status;
    item.appendChild(chip);
    if (result.note) {
      var note = document.createElement("p");
      note.className = "pc-run-result-note";
      note.textContent = result.note;
      item.appendChild(note);
    }
    if (result.checks.length > 0) {
      var list = document.createElement("ul");
      list.className = "pc-run-checks";
      result.checks.forEach(function (check) {
        var line = document.createElement("li");
        line.className = check.ok ? "is-ok" : "is-failed";
        line.textContent = (check.ok ? "ok: " : "FAIL: ") + check.text;
        list.appendChild(line);
      });
      item.appendChild(list);
    }
    result.details.forEach(function (detail) {
      var box = document.createElement("details");
      var summary = document.createElement("summary");
      summary.textContent = detail.summary || "detail";
      box.appendChild(summary);
      if (detail.text) {
        var text = document.createElement("pre");
        text.textContent = detail.text;
        box.appendChild(text);
      }
      item.appendChild(box);
    });
    return item;
  }

  function pcRenderRunReport(report) {
    pcRenderRunState(report ? report.status : "");
    setText("pc-run-title", report ? report.title : "");
    var meta = $("pc-run-meta");
    if (meta) {
      meta.textContent = "";
      (report ? report.meta : []).forEach(function (line) {
        var entry = document.createElement("li");
        entry.textContent = line;
        meta.appendChild(entry);
      });
    }
    var error = $("pc-run-error");
    if (error) {
      error.textContent = report && report.error ? report.error : "";
      error.hidden = !(report && report.error);
    }
    var results = $("pc-run-results");
    if (results) {
      results.textContent = "";
      (report ? report.results : []).forEach(function (result) {
        results.appendChild(pcRunResult(result));
      });
    }
  }

  // -- the history -------------------------------------------------------------

  async function pcLoadRunHistory() {
    var consoleId = pcState.activeId;
    if (!pcRuns()) return;
    try {
      var data = await apiFetch(pcApi(consoleId, "/runs?limit=" + String(PC_RUN_HISTORY_LIMIT)));
      if (consoleId !== pcState.activeId) return;
      pcState.runHistory = Array.isArray(data.runs) ? data.runs : [];
    } catch (err) {
      if (consoleId !== pcState.activeId) return;
      pcState.runHistory = [];
    }
    pcRenderRunHistory();
    if (!pcState.runViewed && !pcState.runActive && pcState.runHistory.length > 0) {
      pcShowRun(pcState.runHistory[0].id);
    }
  }

  function pcRenderRunHistory() {
    var host = $("pc-run-list");
    var runs = pcRuns();
    if (!host || !runs) return;
    host.textContent = "";
    if (pcState.runHistory.length === 0) {
      var empty = document.createElement("p");
      empty.className = "pc-run-empty";
      empty.textContent = runs.labels.empty_history;
      host.appendChild(empty);
      return;
    }
    pcState.runHistory.forEach(function (run) {
      var row = document.createElement("button");
      row.type = "button";
      row.className = "pc-run-row" + (run.id === pcState.runViewed ? " is-active" : "");
      var chip = document.createElement("span");
      chip.className = "pc-status";
      chip.dataset.state = PC_RUN_STATE_TONES[run.status] || "idle";
      chip.textContent = run.status;
      row.appendChild(chip);
      var text = document.createElement("span");
      text.className = "pc-run-row-text";
      text.textContent = [run.title, run.summary].filter(Boolean).join(" · ");
      row.appendChild(text);
      var time = document.createElement("span");
      time.className = "pc-run-row-time";
      time.textContent = run.time || run.id;
      row.appendChild(time);
      row.addEventListener("click", function () { pcShowRun(run.id); });
      host.appendChild(row);
    });
  }

  async function pcShowRun(runId) {
    var consoleId = pcState.activeId;
    if (pcState.runActive && pcState.runActive !== runId) return;
    pcState.runViewed = runId;
    pcRenderRunHistory();
    try {
      var report = await apiFetch(pcApi(consoleId, "/runs/" + encodeURIComponent(runId)));
      if (consoleId !== pcState.activeId || runId !== pcState.runViewed) return;
      pcRenderRunReport(report);
      if (pcState.runActive) return;
      if (!report.finished) {
        pcAttachRun(runId);
        return;
      }
      var log = $("pc-run-log");
      if (log) log.textContent = "";
      var events = await apiFetch(pcApi(consoleId, "/runs/" + encodeURIComponent(runId) + "/events"));
      if (consoleId === pcState.activeId && runId === pcState.runViewed) pcAppendRunEvents(events.entries || []);
    } catch (err) {
      if (consoleId === pcState.activeId) pcRenderRunState("unknown");
    }
  }

  function pcWireRuns() {
    var start = $("pc-run-start");
    if (start) start.addEventListener("click", function () { pcStartRun(); });
    var cancel = $("pc-run-cancel");
    if (cancel) cancel.addEventListener("click", function () { pcCancelRun(); });
  }
