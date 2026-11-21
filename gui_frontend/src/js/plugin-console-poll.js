  // -- Plugin consoles: poll, status panel, stream tables ---------------------
  //
  // One request per tick: GET .../stream with a cursor per declared stream
  // answers the status and every stream's new entries together. The poll
  // runs only while the console view shows (ccLoadStandaloneView stops it on
  // navigation), every second while the console runs or is busy and every
  // five seconds otherwise. A stream table keeps its newest PC_MAX_ROWS rows
  // and follows new rows only while it is scrolled to the bottom; a table in a
  // hidden tab keeps that choice until it is shown. Columns have fixed widths
  // (the manifest's width per column), so a new row never re-measures the
  // table, and a long value stays on one line until its row is clicked open
  // or the table's Wrap is on.

  var PC_POLL_RUNNING_MS = 1000;
  var PC_POLL_IDLE_MS = 5000;
  var PC_MAX_ROWS = 1000;
  var PC_MAX_STATE_ROWS = 64;
  // A cut value at least this long carries its whole text as a tooltip.
  var PC_TITLE_MIN = 24;
  // The narrowest each column kind gets (em, the table's font) before the
  // table scrolls sideways; fill columns share whatever is wider than that.
  var PC_COLUMN_MIN_EM = { time: 8.8, narrow: 6.5, medium: 14, fill: 12 };

  function pcStopPolling() {
    if (pcState.pollTimer) {
      clearTimeout(pcState.pollTimer);
      pcState.pollTimer = null;
    }
    pcRunStopPoll();
  }

  function pcPollSoon() {
    pcStopPolling();
    if (pcState.polling) {
      pcState.pollAgain = true;
      return;
    }
    pcState.pollTimer = setTimeout(pcPoll, 150);
  }

  function pcStreamQuery(manifest) {
    var parts = manifest.streams.map(function (stream) {
      return "cursor=" + encodeURIComponent(stream.id + ":" + String(pcState.cursors[stream.id] || 0));
    });
    return parts.length > 0 ? "?" + parts.join("&") : "";
  }

  async function pcPoll() {
    pcStopPolling();
    var manifest = pcState.manifest;
    if (!manifest || state.activeView !== "plugin_console") return;
    if (pcState.polling) {
      pcState.pollAgain = true;
      return;
    }
    pcState.polling = true;
    var consoleId = manifest.id;
    try {
      var data = await apiFetch(pcApi(consoleId, "/stream") + pcStreamQuery(manifest));
      if (consoleId === pcState.activeId) {
        pcRenderStatus(data.status || null);
        manifest.streams.forEach(function (stream) {
          var batch = data.streams ? data.streams[stream.id] : null;
          if (batch) {
            pcAppendRows(stream, batch);
            pcState.cursors[stream.id] = Number(batch.next) || 0;
          }
        });
        pcSetChip("updated " + formatTime(new Date()), "idle");
      }
    } catch (err) {
      if (consoleId === pcState.activeId) pcSetChip("poll failed", "error");
    }
    pcState.polling = false;
    // A poll asked for while this one was in flight may be for another console
    // (the operator switched); pcPoll re-reads the manifest and the view itself.
    if (pcState.pollAgain) {
      pcState.pollAgain = false;
      pcState.pollTimer = setTimeout(pcPoll, 150);
      return;
    }
    if (consoleId !== pcState.activeId || state.activeView !== "plugin_console") return;
    var status = pcState.status || {};
    // A run console's active run is followed by its own poll; the status stays slow.
    var running = Boolean(status.running) && !manifest.runs;
    var fast = !document.hidden && Boolean(running || status.busy || pcState.busy);
    pcState.pollTimer = setTimeout(pcPoll, fast ? PC_POLL_RUNNING_MS : PC_POLL_IDLE_MS);
  }

  function pcRenderStatus(status) {
    pcState.status = status;
    var manifest = pcState.manifest;
    if (!manifest) return;
    var hasStart = Boolean(manifest.start);
    var running = Boolean(status && status.running);
    var phase = status && status.busy ? (typeof status.busy === "string" ? status.busy : "busy") : "";
    var busy = pcState.busy || phase !== "";
    var chip = $("pc-run-status");
    if (chip) {
      chip.textContent = !status ? "unknown" : (phase || (running ? "running" : (hasStart ? "stopped" : "ready")));
      chip.dataset.state = !status ? "idle" : (busy ? "busy" : (running || !hasStart ? "ok" : "idle"));
    }
    var usable = !hasStart || running;
    var start = $("pc-start");
    if (start) start.disabled = busy || running;
    var stop = $("pc-stop");
    if (stop) stop.disabled = busy || !running;
    document.querySelectorAll("#pc-start-fields [data-pc-type], #pc-start-fields .pc-field-fill").forEach(function (input) {
      input.disabled = busy || running;
    });
    document.querySelectorAll("#pc-actions button[type=submit], #pc-compare-actions button[type=submit]").forEach(function (button) {
      button.disabled = !usable;
    });
    ["pc-command-input", "pc-command-send"].forEach(function (id) {
      var control = $(id);
      if (control) control.disabled = !usable;
    });
    var error = $("pc-last-error");
    if (error) {
      var text = status && status.last_error ? String(status.last_error) : "";
      error.hidden = text === "";
      error.textContent = text;
    }
    pcRenderState(status ? status.state : null);
    pcRenderCompare(status ? status.compare : null);
    pcApplyChoices(status ? status.choices : null);
    pcRunsOnStatus(status);
  }

  function pcValueText(value) {
    if (value === null || value === undefined || value === "") return "-";
    if (typeof value === "boolean") return value ? "yes" : "no";
    if (Array.isArray(value)) {
      if (value.length === 0) return "-";
      return value.map(function (item) {
        return Array.isArray(item) ? item.map(pcValueText).join(" ") : pcValueText(item);
      }).join("; ");
    }
    if (typeof value === "object") {
      var keys = Object.keys(value);
      if (keys.length === 0) return "-";
      return keys.map(function (key) { return key + "=" + pcValueText(value[key]); }).join(", ");
    }
    return String(value);
  }

  function pcStateRows(stateObject) {
    var rows = [];
    Object.keys(stateObject).forEach(function (key) {
      var value = stateObject[key];
      if (value && typeof value === "object" && !Array.isArray(value)) {
        Object.keys(value).forEach(function (inner) {
          rows.push([key + "." + inner, pcValueText(value[inner])]);
        });
      } else {
        rows.push([key, pcValueText(value)]);
      }
    });
    return rows.slice(0, PC_MAX_STATE_ROWS);
  }

  // The state list lives in the session panel, or in a tab of its own when the
  // manifest gives it a title. It starts empty for every console.
  function pcPlaceState(manifest) {
    var list = $("pc-state");
    if (!list) return;
    var home = manifest.state ? $("pc-state-panel") : $("pc-session");
    if (manifest.state) setText("pc-state-title", manifest.state.title);
    if (home && list.parentNode !== home) home.appendChild(list);
    list.textContent = "";
    list.hidden = true;
    pcState.stateSignature = "";
    pcState.stateKeys = "";
    pcState.stateCells = [];
    pcRenderStateEmpty();
  }

  function pcRenderStateEmpty() {
    var empty = $("pc-state-empty");
    var list = $("pc-state");
    if (!empty || !list) return;
    empty.hidden = !(pcState.manifest && pcState.manifest.state) || !list.hidden;
  }

  function pcRenderState(stateObject) {
    var host = $("pc-state");
    if (!host) return;
    var valid = Boolean(stateObject) && typeof stateObject === "object" && !Array.isArray(stateObject);
    var signature = valid ? JSON.stringify(stateObject) : "";
    if (signature === pcState.stateSignature) return;
    pcState.stateSignature = signature;
    var rows = valid ? pcStateRows(stateObject) : [];
    var keys = rows.map(function (row) { return row[0]; }).join("\n");
    if (keys === pcState.stateKeys && pcState.stateCells.length === rows.length) {
      // The same rows as on screen (a counter or a countdown moved): only
      // the values that changed are rewritten.
      rows.forEach(function (row, index) {
        var cell = pcState.stateCells[index];
        if (cell.textContent !== row[1]) cell.textContent = row[1];
      });
    } else {
      host.textContent = "";
      pcState.stateCells = rows.map(function (row) {
        var term = document.createElement("dt");
        term.textContent = row[0];
        var detail = document.createElement("dd");
        detail.textContent = row[1];
        host.appendChild(term);
        host.appendChild(detail);
        return detail;
      });
      pcState.stateKeys = keys;
    }
    host.hidden = rows.length === 0;
    pcRenderStateEmpty();
  }

  function pcStreamButton(label, title) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "btn btn-small";
    button.textContent = label;
    if (title) button.title = title;
    return button;
  }

  function pcColumnClass(column) {
    return column.format === "time" ? "time" : column.width;
  }

  function pcRenderStreams(manifest) {
    var host = $("pc-streams");
    if (!host) return;
    host.textContent = "";
    manifest.streams.forEach(function (stream) {
      // The tab panel (plugin-console-tabs.js shows one at a time).
      var holder = document.createElement("div");
      holder.className = "pc-tab-panel pc-stream-tab";
      holder.id = "pc-tab-" + PC_STREAM_TAB_PREFIX + stream.id;
      holder.setAttribute("role", "tabpanel");
      holder.setAttribute("data-pc-tab", PC_STREAM_TAB_PREFIX + stream.id);
      holder.hidden = true;
      var panel = document.createElement("section");
      panel.className = "pc-panel pc-stream";
      panel.setAttribute("data-pc-stream", stream.id);
      var head = document.createElement("div");
      head.className = "pc-panel-head";
      var title = document.createElement("h2");
      title.textContent = stream.title;
      head.appendChild(title);
      var count = document.createElement("span");
      count.className = "pc-stream-count";
      count.textContent = "no rows";
      head.appendChild(count);
      // Wrap only where a value can be cut: a hex column or a narrow text or mono one.
      var cuts = stream.columns.some(function (column) {
        return column.format === "hex" || ((column.format === "text" || column.format === "mono") && column.width === "narrow");
      });
      var wrap = pcStreamButton("Wrap", "Show every value in full instead of cutting it at the column edge; a click on a row opens that row only.");
      wrap.setAttribute("aria-pressed", "false");
      wrap.hidden = !cuts;
      head.appendChild(wrap);
      var clear = pcStreamButton("Clear", "");
      head.appendChild(clear);
      panel.appendChild(head);
      var scroll = document.createElement("div");
      scroll.className = "pc-stream-scroll";
      var table = document.createElement("table");
      table.className = "pc-stream-table";
      var columns = document.createElement("colgroup");
      var minimum = 0;
      stream.columns.forEach(function (column) {
        var col = document.createElement("col");
        col.className = "pc-col pc-col--" + pcColumnClass(column);
        columns.appendChild(col);
        minimum += PC_COLUMN_MIN_EM[pcColumnClass(column)] || PC_COLUMN_MIN_EM.fill;
      });
      table.appendChild(columns);
      // A number from the table above, never a plugin string.
      table.style.setProperty("--pc-table-min", minimum.toFixed(1) + "em");
      var headRow = table.createTHead().insertRow();
      stream.columns.forEach(function (column) {
        var cell = document.createElement("th");
        cell.scope = "col";
        cell.textContent = column.label;
        headRow.appendChild(cell);
      });
      var body = table.createTBody();
      scroll.appendChild(table);
      panel.appendChild(scroll);
      pcState.streamPinned[stream.id] = true;
      scroll.addEventListener("scroll", function () {
        // A hidden table reads zero sizes; its last choice stands until it shows.
        if (scroll.clientHeight === 0) return;
        pcState.streamPinned[stream.id] = scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - 8;
      }, { passive: true });
      body.addEventListener("click", function (event) {
        var row = event.target.closest("tr");
        if (!row || !body.contains(row)) return;
        // A drag that selected text is a copy, not a click on the row.
        var selection = window.getSelection ? String(window.getSelection()) : "";
        if (selection) return;
        row.classList.toggle("is-expanded");
      });
      wrap.addEventListener("click", function () {
        var on = !table.classList.contains("is-wrapped");
        table.classList.toggle("is-wrapped", on);
        wrap.setAttribute("aria-pressed", on ? "true" : "false");
      });
      clear.addEventListener("click", function () {
        body.textContent = "";
        pcState.streamPinned[stream.id] = true;
        pcCountRows(panel, "");
      });
      holder.appendChild(panel);
      host.appendChild(holder);
    });
  }

  function pcStreamPinned(streamId) {
    return pcState.streamPinned[streamId] !== false;
  }

  // A stream tab was shown: a table that follows new rows jumps to the newest.
  function pcStreamShown(streamId) {
    var panel = pcStreamPanel(streamId);
    var scroll = panel ? panel.querySelector(".pc-stream-scroll") : null;
    if (scroll && pcStreamPinned(streamId)) scroll.scrollTop = scroll.scrollHeight;
  }

  function pcTrimRows(body) {
    var extra = body.rows.length - PC_MAX_ROWS;
    if (extra <= 0) return;
    var range = document.createRange();
    range.setStartBefore(body.rows[0]);
    range.setEndAfter(body.rows[extra - 1]);
    range.deleteContents();
  }

  function pcStreamPanel(streamId) {
    var host = $("pc-streams");
    if (!host) return null;
    var panels = host.querySelectorAll("[data-pc-stream]");
    for (var i = 0; i < panels.length; i += 1) {
      if (panels[i].getAttribute("data-pc-stream") === streamId) return panels[i];
    }
    return null;
  }

  function pcCountRows(panel, note) {
    var count = panel.querySelector(".pc-stream-count");
    var body = panel.querySelector("tbody");
    var rows = body ? body.rows.length : 0;
    if (!count) return;
    count.textContent = (rows === 0 ? "no rows" : rows + (rows === 1 ? " row" : " rows")) + (note ? " · " + note : "");
    count.dataset.state = /^error/.test(note || "") ? "error" : "";
  }

  function pcFormatCell(column, value) {
    if (column.format === "time") {
      if (typeof value !== "number") return "";
      var moment = new Date(value * 1000);
      return formatTime(moment) + "." + String(moment.getMilliseconds()).padStart(3, "0");
    }
    return value === null || value === undefined ? "" : String(value);
  }

  function pcAppendRows(stream, batch) {
    var panel = pcStreamPanel(stream.id);
    if (!panel) return;
    var scroll = panel.querySelector(".pc-stream-scroll");
    var body = panel.querySelector("tbody");
    var entries = Array.isArray(batch.entries) ? batch.entries : [];
    if (entries.length > 0) {
      var shown = scroll.clientHeight > 0;
      var pinned = shown ? scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - 8 : pcStreamPinned(stream.id);
      var fragment = document.createDocumentFragment();
      entries.forEach(function (entry) {
        var row = document.createElement("tr");
        stream.columns.forEach(function (column) {
          var cell = document.createElement("td");
          // Time, hex and narrow text stay on one line; medium and fill text and mono wrap.
          var clipped = (column.format !== "text" && column.format !== "mono") || column.width === "narrow";
          cell.className = "pc-cell pc-cell--" + column.format + (clipped ? " pc-cell--clip" : "");
          var text = pcFormatCell(column, entry[column.key]);
          cell.textContent = text;
          if (clipped && text.length >= PC_TITLE_MIN) cell.title = text;
          row.appendChild(cell);
        });
        fragment.appendChild(row);
      });
      body.appendChild(fragment);
      pcTrimRows(body);
      pcState.streamPinned[stream.id] = pinned;
      if (pinned && shown) scroll.scrollTop = scroll.scrollHeight;
    }
    var note = batch.error ? "error: " + batch.error : (batch.truncated ? "older entries skipped" : "");
    pcCountRows(panel, note);
  }
