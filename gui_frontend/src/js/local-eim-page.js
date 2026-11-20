  // -- Local eIM page ------------------------------------------------------
  //
  // The landing content of the Local eIM module: the eUICCs the eIM knows,
  // one eUICC in detail (profiles, what the card reported, the eIMs it
  // lists, its operations) and the eIM's own configuration. It reads the
  // store through eim_local.overview and changes it only through the
  // module's existing actions: a button queues an operation
  // (eim_local.op_queue) or opens the action's form; nothing here talks to
  // a card except through an action that names the reader.
  //
  // ccCreateLocalEimPage(hooks) -> { mount(host) }. hooks:
  //   reader()                    the reader the module is bound to, or ""
  //   hasAction(id)               whether the catalogue carries the action
  //   post(id, inputs)            run an action, resolve its response
  //   runInPane(id, inputs, opts) run it in the output pane (card actions)
  //   openForm(id, prefill)       open the action's form in the output pane
  //   show()                      put the page back in the output pane
  //   actionsWithTag(tag)         catalogue actions carrying the tag
  //
  // A delivery route beyond the eIM's own IPAd is an action tagged
  // "ipae-deliver" (a plugin that drives the card's own IPAe); the page
  // offers each one beside Deliver now, under the action's title.

  var LEP_REFRESH_MS = 5000;

  function lepEl(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function lepTime(iso) {
    if (!iso) return "";
    var when = new Date(iso);
    if (isNaN(when.getTime())) return String(iso);
    var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    var hours = when.getHours();
    var minutes = when.getMinutes();
    return months[when.getMonth()] + " " + when.getDate() + ", "
      + (hours < 10 ? "0" : "") + hours + ":" + (minutes < 10 ? "0" : "") + minutes;
  }

  function lepStateTone(state) {
    var value = String(state || "").toUpperCase();
    if (value === "SUCCESS" || value === "ENABLED") return "ok";
    if (value === "ERROR") return "fail";
    if (value === "PARTIAL_SUCCESS" || value === "CANCELED") return "warn";
    return "info";
  }

  function lepStateLabel(state) {
    var names = {
      CREATED: "Queued",
      SENT: "Sent to the card",
      SUCCESS: "Success",
      PARTIAL_SUCCESS: "Partial success",
      ERROR: "Error",
      CANCELED: "Canceled",
    };
    return names[String(state || "").toUpperCase()] || String(state || "-");
  }

  function lepBadge(text, tone) {
    return lepEl("span", "lep-badge lep-badge--" + (tone || "info"), text);
  }

  // Where a Notification the eIM took stands: the engine's four states. The
  // eIM holds none back; a failed or kept one goes again only by its own Send.
  function lepNotificationTone(state) {
    if (state === "delivered") return "ok";
    if (state === "failed") return "fail";
    return "info";
  }

  function lepNotificationLabel(state) {
    var names = { pending: "Pending", delivered: "Delivered", failed: "Failed", kept: "Kept" };
    return names[String(state || "")] || String(state || "-");
  }

  function lepNotificationNote(row) {
    if (row.state === "delivered") return row.delivered_at ? lepTime(row.delivered_at) : "";
    if (row.state === "failed") return String(row.reason || "");
    if (row.state === "kept") {
      // A reason on a kept one says an earlier version held it.
      return row.reason ? "held by an earlier version: " + String(row.reason)
        : "taken before the eIM forwarded Notifications";
    }
    var parts = [];
    var attempts = Number(row.attempts || 0);
    if (attempts > 0) {
      var tried = String(attempts) + (attempts === 1 ? " attempt" : " attempts") + ", last: " + String(row.last_error || "");
      if (row.next_attempt_at) tried += "; next " + lepTime(row.next_attempt_at);
      parts.push(tried);
    }
    if (row.waiting) parts.push("waits for " + String(row.waiting));
    return parts.join("; ");
  }

  function lepButton(text, onClick, primary) {
    var button = lepEl("button", "btn lep-btn" + (primary ? " btn-primary" : ""), text);
    button.type = "button";
    button.addEventListener("click", function (event) {
      event.preventDefault();
      onClick(button);
    });
    return button;
  }

  function lepSection(titleText) {
    var section = lepEl("section", "lep-section");
    var head = lepEl("div", "lep-section-head");
    head.appendChild(lepEl("h3", "lep-section-title", titleText));
    var tools = lepEl("div", "lep-section-tools");
    head.appendChild(tools);
    section.appendChild(head);
    return { node: section, tools: tools };
  }

  function lepStamp(text) {
    return lepEl("div", "lep-stamp", text);
  }

  function lepTable(columns, rows, emptyText) {
    var wrap = lepEl("div", "lep-table-wrap");
    var table = lepEl("table", "lep-table");
    var headRow = lepEl("tr");
    columns.forEach(function (column) {
      headRow.appendChild(lepEl("th", "", column));
    });
    var thead = lepEl("thead");
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = lepEl("tbody");
    if (rows.length === 0) {
      var emptyRow = lepEl("tr", "lep-table-empty");
      var cell = lepEl("td", "", emptyText || "No data available");
      cell.colSpan = columns.length;
      emptyRow.appendChild(cell);
      tbody.appendChild(emptyRow);
    }
    rows.forEach(function (row) {
      var tr = lepEl("tr", row.onClick ? "lep-row-link" : "");
      row.cells.forEach(function (value) {
        var td = lepEl("td");
        if (value && value.nodeType === 1) {
          td.appendChild(value);
        } else {
          td.textContent = value === undefined || value === null || value === "" ? "-" : String(value);
        }
        tr.appendChild(td);
      });
      if (row.onClick) {
        tr.tabIndex = 0;
        tr.addEventListener("click", function (event) {
          if (event.target && event.target.closest && event.target.closest("button")) return;
          row.onClick();
        });
        tr.addEventListener("keydown", function (event) {
          if (event.key === "Enter" && event.target === tr) row.onClick();
        });
      }
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function lepFacts(pairs) {
    var list = lepEl("div", "lep-facts");
    pairs.forEach(function (pair) {
      var item = lepEl("div", "lep-fact");
      item.appendChild(lepEl("div", "lep-fact-label", pair[0]));
      var value = lepEl("div", "lep-fact-value");
      if (pair[1] && pair[1].nodeType === 1) {
        value.appendChild(pair[1]);
      } else {
        value.textContent = pair[1] === undefined || pair[1] === null || pair[1] === "" ? "-" : String(pair[1]);
      }
      item.appendChild(value);
      list.appendChild(item);
    });
    return list;
  }

  // Certificate rows as the engine names them (label, value, tone, depth).
  function lepCertificate(rows) {
    var box = lepEl("div", "lep-cert");
    (rows || []).forEach(function (row) {
      var line = lepEl("div", "lep-cert-row" + (row.tone ? " lep-cert-row--" + row.tone : ""));
      line.setAttribute("data-depth", String(Math.min(3, Number(row.indent) || 0)));
      line.appendChild(lepEl("span", "lep-cert-label", row.label));
      line.appendChild(lepEl("span", "lep-cert-value", row.value));
      box.appendChild(line);
    });
    if (!rows || rows.length === 0) box.appendChild(lepEl("div", "lep-empty", "No certificate."));
    return box;
  }

  function lepFold(summaryText, buildBody) {
    var fold = lepEl("details", "lep-fold");
    fold.appendChild(lepEl("summary", "lep-fold-summary", summaryText));
    var built = false;
    fold.addEventListener("toggle", function () {
      if (!fold.open || built) return;
      built = true;
      fold.appendChild(buildBody());
    });
    return fold;
  }

  // key="value" lines for the queue and edit actions' text fields; an empty
  // value removes the key on an edit.
  function lepPairs(values) {
    return Object.keys(values).map(function (key) {
      var value = values[key];
      if (value === true) value = "on";
      if (value === false) value = "off";
      var text = String(value === undefined || value === null ? "" : value);
      if (text.length === 0) return key + "=";
      return key + '="' + text.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
    }).join("\n");
  }

  // One input for a catalogue parameter; read() answers "" when unset.
  function lepParamField(spec, current) {
    var wrap = lepEl("label", spec.kind === "bool" ? "lep-check" : "lep-field");
    var label = spec.name.replace(/_/g, " ") + (spec.required ? " *" : "");
    var input;
    var read;
    if (spec.kind === "bool") {
      input = lepEl("select", "lep-input lep-input--narrow");
      [["", "not set"], ["on", "on"], ["off", "off"]].forEach(function (entry) {
        var option = lepEl("option", "", entry[1]);
        option.value = entry[0];
        input.appendChild(option);
      });
      if (current === true || current === "on") input.value = "on";
      if (current === false || current === "off") input.value = "off";
      wrap.appendChild(lepEl("span", "lep-field-label", label));
      wrap.appendChild(input);
      read = function () { return input.value; };
    } else if ((spec.choices || []).length > 0) {
      input = lepEl("select", "lep-input");
      [""].concat(spec.choices).forEach(function (choice) {
        var option = lepEl("option", "", choice || "not set");
        option.value = choice;
        input.appendChild(option);
      });
      input.value = current === undefined || current === null ? "" : String(current);
      wrap.appendChild(lepEl("span", "lep-field-label", label));
      wrap.appendChild(input);
      read = function () { return input.value; };
    } else {
      input = lepEl("input", "lep-input");
      input.type = "text";
      input.autocomplete = "off";
      input.value = current === undefined || current === null ? "" : String(current);
      wrap.appendChild(lepEl("span", "lep-field-label", label));
      wrap.appendChild(input);
      read = function () { return String(input.value || "").trim(); };
    }
    if (spec.help) {
      input.title = spec.help;
      wrap.appendChild(lepEl("span", "lep-field-help", spec.help));
    }
    return { node: wrap, read: read, input: input, name: spec.name, required: !!spec.required,
      kind: String(spec.kind || "") };
  }

  // The context decoder's view of a card answer or a package, in place.
  function lepDecodeInto(hooks, host, hex, context) {
    host.textContent = "decoding...";
    hooks.post("tool.decoder.context", { input_text: hex, context: context }).then(function (resp) {
      host.textContent = "";
      if (!resp || !resp.ok) {
        host.appendChild(lepEl("div", "lep-empty",
          "Not decoded: " + String(resp && resp.error || "unknown error")));
        return;
      }
      renderContextDecodeResult(resp.data || {}, host);
    }, function (err) {
      host.textContent = "Not decoded: " + String(err && err.message || err);
    });
  }

  // Hex with its decoded view above it; the bytes stay one click away.
  // ``rows`` are the engine's own named rows (tag, name, value) when it has
  // them; otherwise the context decoder reads the bytes as ``context``
  // ("es10", "tlv"; "" leaves them as bytes). Beside the rows, the Decoder's
  // reading is a fold away: the rows name what the eIM acts on, the Decoder
  // every data object of the schema (a Profile's policy rules, its owner).
  function lepDecodedBlock(hooks, titleText, hex, context, rows) {
    var block = lepEl("div", "lep-decoded");
    block.appendChild(lepEl("div", "lep-sub-title", titleText));
    var decoded = lepEl("div", "lep-decoded-view");
    block.appendChild(decoded);
    var canDecode = !!context && hooks.hasAction("tool.decoder.context");
    if (rows && rows.length > 0) {
      decoded.appendChild(lepTable(["Tag", "Data object", "Value"], rows.map(function (row) {
        return { cells: [lepEl("span", "lep-mono", row.tag), row.name, lepEl("span", "lep-mono", row.value)] };
      })));
      if (canDecode) {
        block.appendChild(lepFold("Decoder reading", function () {
          var reading = lepEl("div", "lep-decoded-view");
          lepDecodeInto(hooks, reading, hex, context);
          return reading;
        }));
      }
    } else if (canDecode) {
      lepDecodeInto(hooks, decoded, hex, context);
    }
    block.appendChild(lepFold("Bytes (" + Math.floor(hex.length / 2) + ")", function () {
      return lepEl("pre", "lep-hex", hex);
    }));
    return block;
  }

  function ccCreateLocalEimPage(hooks) {
    var state = {
      view: "list",        // list | euicc | operation | delivery | config
      eid: "",
      operationId: 0,
      operation: null,
      delivery: null,      // { startedAt, lines, title }
      newOperation: false,
      newOperationType: "",  // the verb the New operation form opens on ("" = the first)
      scrollToNewOperation: false,
      rollback: false,
      data: null,
      signature: "",
      host: null,
      root: null,
      timer: null,
      notice: null,        // { tone, text }
      busy: false,
      formOpen: false,
      leaf: null,          // the leaf editor's rows (local-eim-leaf-editor.js)
    };

    function stopTimer() {
      if (state.timer !== null) {
        clearInterval(state.timer);
        state.timer = null;
      }
    }

    function attached() {
      return !!(state.root && state.root.isConnected);
    }

    function setNotice(tone, text) {
      state.notice = text ? { tone: tone, text: text } : null;
    }

    async function load(force) {
      var wanted = state.view === "list" || state.view === "config" || state.view === "leaf" ? "" : state.eid;
      var resp;
      var detail = null;
      try {
        resp = await hooks.post("eim_local.overview", { eid: wanted });
        if (state.view === "operation" && state.operationId) {
          detail = await hooks.post("eim_local.op_detail", { operation_id: state.operationId });
        }
      } catch (err) {
        resp = { ok: false, error: String(err && err.message || err) };
      }
      if (!attached()) {
        stopTimer();
        return;
      }
      if (!resp || !resp.ok) {
        if (force || !state.data) {
          setNotice("fail", "The Local eIM store could not be read: " + String(resp && resp.error || "unknown error"));
          render();
        }
        return;
      }
      if (state.view === "operation") {
        if (!detail || !detail.ok) {
          setNotice("fail", "Operation " + state.operationId + " could not be read: "
            + String(detail && detail.error || "unknown error"));
          state.view = "euicc";
        } else {
          state.operation = detail.data || null;
        }
      }
      var signature = JSON.stringify([resp.data || {}, state.operation]);
      if (!force && signature === state.signature) return;
      // A background refresh never replaces a form the operator is typing
      // in, an opened fold or an armed confirmation; the next click or the
      // Refresh key brings the page up to date.
      if (!force && (state.formOpen
          || (state.root && state.root.querySelector("details[open], [data-armed='1']")))) {
        return;
      }
      state.signature = signature;
      state.data = resp.data || {};
      if ((state.view === "euicc" || state.view === "delivery") && !state.data.euicc) {
        state.view = "list";
        setNotice("warn", "That eUICC is no longer in the store.");
      }
      render();
    }

    // The leaf editor keeps its rows in state.leaf; the 5 s refresh leaves an
    // open form alone, so they are redrawn only when the editor asks.
    function openLeafEditor(setup, from) {
      state.leaf = lleNewEditor(setup || "");
      state.leaf.from = from || "";
      state.view = "leaf";
      state.eid = "";
      state.formOpen = true;
      setNotice("", "");
      render();
    }

    function leafEditorContext() {
      return {
        editor: state.leaf,
        hooks: hooks,
        setups: (state.data && state.data.tls && state.data.tls.setups) || [],
        rerender: function () {
          if (state.view === "leaf" && attached()) render();
        },
        close: function () {
          state.leaf = null;
          go("config", "");
        },
      };
    }

    function go(view, eid, operationId) {
      state.view = view;
      state.eid = eid || "";
      state.operationId = operationId || 0;
      state.operation = null;
      state.formOpen = false;
      state.newOperation = false;
      state.newOperationType = "";
      state.signature = "";
      setNotice("", "");
      load(true);
    }

    async function queue(operation, extra, doneText) {
      if (state.busy) return;
      state.busy = true;
      var inputs = Object.assign({ operation: operation, eid: state.eid }, extra || {});
      var resp;
      try {
        resp = await hooks.post("eim_local.op_queue", inputs);
      } catch (err) {
        resp = { ok: false, error: String(err && err.message || err) };
      }
      state.busy = false;
      if (!resp || !resp.ok) {
        setNotice("fail", "Not queued: " + String(resp && resp.error || "unknown error"));
      } else {
        // The engine queues on a failed precondition and says so on a "!" line.
        var warnings = ((resp.data && resp.data.lines) || []).filter(function (line) {
          return String(line).trim().charAt(0) === "!";
        }).map(function (line) {
          return String(line).trim().replace(/^!\s*/, "");
        });
        if (warnings.length > 0) {
          setNotice("warn", doneText + " Warning: " + warnings.join("; ") + ".");
        } else {
          setNotice("ok", doneText + " " + deliveryHint());
        }
      }
      state.formOpen = false;
      state.newOperation = false;
      state.newOperationType = "";
      await load(true);
    }

    function deliveryHint() {
      var service = state.data && state.data.service;
      if (service && service.running) {
        return "The card collects it at its next poll, or use Deliver now with the card in the reader.";
      }
      return "The service is not running: start it so the card can poll, or use Deliver now with the card in the reader.";
    }

    function cardAction(actionId, inputs, runningText) {
      var reader = hooks.reader();
      if (!reader) {
        setNotice("warn", "Select a reader in the top bar first: this step talks to the card in it.");
        render();
        return;
      }
      stopTimer();
      hooks.runInPane(actionId, Object.assign({ reader: reader }, inputs || {}), { runningText: runningText });
    }

    // Deliver, then show what the run finished: each operation opens its
    // own page with the package it was served and the card's answer.
    async function deliver(askedReader) {
      var reader = askedReader || hooks.reader();
      if (!reader) {
        setNotice("warn", "Select a reader in the top bar first: this step talks to the card in it.");
        render();
        return;
      }
      stopTimer();
      var startedAt = new Date(Date.now() - 2000).toISOString();
      var data = await hooks.runInPane("eim_local.deliver", { reader: reader },
        { runningText: "delivering to the card" });
      if (!data) return;
      state.delivery = {
        startedAt: startedAt,
        lines: Array.isArray(data.lines) ? data.lines : [],
        title: "Delivery by the eIM's own IPAd",
      };
      state.view = "delivery";
      setNotice("", "");
      hooks.show();
    }

    // A queued profile download is not something Deliver now carries out:
    // the eIM only hands the IPA a trigger, and the IPA does the download
    // against the SM-DP+ (SGP.32 v1.3 section 3.2.3). On the card in the
    // reader that IPA is the eSIM Management one, polling this eIM's service.
    function renderDownloadCallout(root, euicc) {
      var downloads = (euicc.pending || []).filter(function (operation) {
        return operation.type === "PROFILE_DOWNLOAD_TRIGGER";
      });
      if (downloads.length === 0) return;
      var service = (state.data && state.data.service) || {};
      var box = lepEl("div", "lep-notice lep-notice--warn lep-callout");
      box.appendChild(lepEl("div", "lep-callout-text",
        (downloads.length === 1 ? "Operation " + downloads[0].id + " is a profile download. "
          : String(downloads.length) + " profile downloads are queued. ")
        + "Deliver now (IPAd) does not download: the eIM hands over a trigger and an IPA fetches the "
        + "profile from the SM-DP+. Run the download with the IPAd on the card in the reader"
        + (hooks.actionsWithTag("ipae-deliver").length > 0 ? ", or let the card's own IPAe take it with Deliver (IPAe)." : ".")));
      var bar = lepEl("div", "lep-inline-form-bar");
      if (!service.running) {
        box.appendChild(lepEl("div", "lep-callout-text",
          "The service is stopped: the IPA has nothing to poll until it runs."));
        bar.appendChild(lepButton("Start service", function () {
          stopTimer();
          hooks.openForm("eim_local.service_start", {});
        }, true));
      }
      if (hooks.hasAction("scp11_live.eim_download")) {
        bar.appendChild(lepButton("Run the download (IPAd)", function () {
          if (!hooks.reader()) {
            setNotice("warn", "Select a reader in the top bar first: the download runs on the card in it.");
            render();
            return;
          }
          stopTimer();
          hooks.openForm("scp11_live.eim_download", {});
        }, !!service.running));
      }
      box.appendChild(bar);
      root.appendChild(box);
    }

    function renderDelivery(root) {
      var euicc = state.data && state.data.euicc;
      var delivery = state.delivery;
      if (!euicc || !delivery) return;
      var back = lepEl("button", "lep-back", "\u2190 " + euicc.eid);
      back.type = "button";
      back.addEventListener("click", function () { go("euicc", euicc.eid); });
      root.appendChild(back);
      renderDownloadCallout(root, euicc);
      var section = lepSection(delivery.title);
      var touched = (euicc.operations || []).filter(function (operation) {
        var stamp = operation.finished_at || operation.served_at || "";
        return stamp && new Date(stamp).getTime() >= new Date(delivery.startedAt).getTime();
      });
      section.node.appendChild(lepTable(
        ["Operation", "Action", "Status", "Completed on"],
        touched.map(function (operation) {
          var status = lepEl("span", "lep-status");
          status.appendChild(lepBadge(lepStateLabel(operation.state), lepStateTone(operation.state)));
          if (operation.error) status.appendChild(lepEl("span", "lep-status-note", operation.error));
          return {
            onClick: function () { go("operation", euicc.eid, operation.id); },
            cells: [operation.id, operation.title, status, lepTime(operation.finished_at)],
          };
        }),
        "The run finished no operation."
      ));
      section.node.appendChild(lepEl("p", "lep-help",
        "Select an operation for the package it was served and the card's answer."));
      section.node.appendChild(lepEl("div", "lep-sub-title", "Run output"));
      section.node.appendChild(lepEl("pre", "lep-hex", delivery.lines.join("\n") || "-"));
      root.appendChild(section.node);
    }

    // -- header --------------------------------------------------------

    function renderTopBar(root) {
      var data = state.data || {};
      var identity = data.identity;
      var service = data.service || {};
      var bar = lepEl("div", "lep-topbar");
      var tabs = lepEl("div", "lep-tabs");
      [["list", "eUICCs"], ["config", "eIM configuration"]].forEach(function (entry) {
        var active = state.view === entry[0]
          || (entry[0] === "list" && state.view !== "config" && state.view !== "leaf")
          || (entry[0] === "config" && state.view === "leaf");
        var tab = lepEl("button", "lep-tab" + (active ? " is-active" : ""), entry[1]);
        tab.type = "button";
        tab.addEventListener("click", function () { go(entry[0], ""); });
        tabs.appendChild(tab);
      });
      bar.appendChild(tabs);
      var facts = lepEl("div", "lep-topbar-facts");
      if (identity) {
        facts.appendChild(lepEl("span", "lep-topbar-fact", "eIM " + identity.eim_id));
        facts.appendChild(lepEl("span", "lep-topbar-fact", identity.effective_fqdn || identity.eim_fqdn || ""));
      }
      facts.appendChild(lepBadge(
        service.running ? (service.answers ? "Service running" : "Service not answering") : "Service stopped",
        service.running ? (service.answers ? "ok" : "warn") : "warn"
      ));
      bar.appendChild(facts);
      root.appendChild(bar);
      if (state.notice) {
        root.appendChild(lepEl("div", "lep-notice lep-notice--" + state.notice.tone, state.notice.text));
      }
    }

    function renderNoIdentity(root) {
      var box = lepEl("div", "lep-empty-state");
      box.appendChild(lepEl("h3", "lep-empty-title", "This eIM has no identity yet"));
      box.appendChild(lepEl("p", "", "An identity is the eIM's eimId, its FQDN and the key pair it signs "
        + "eUICC packages with. Create one, then link a card to it."));
      box.appendChild(lepButton("Create identity", function () {
        hooks.openForm("eim_local.identity_new", {});
      }, true));
      root.appendChild(box);
    }

    // -- eUICC list ----------------------------------------------------

    function renderList(root) {
      var data = state.data || {};
      var section = lepSection("Linked eUICCs");
      section.tools.appendChild(lepButton("Register an EID", function () {
        hooks.openForm("eim_local.euicc_register", {});
      }));
      section.tools.appendChild(lepButton("Read the card in the reader", function () {
        cardAction("eim_local.euicc_read", {}, "reading the card");
      }, true));
      var rows = (data.euiccs || []).map(function (entry) {
        return {
          onClick: function () { go("euicc", entry.eid); },
          cells: [
            lepEl("span", "lep-mono", entry.eid),
            entry.label,
            lepBadge(entry.associated ? "Linked" : "Not linked", entry.associated ? "ok" : "warn"),
            entry.profile_count,
            entry.last_poll_at ? lepTime(entry.last_poll_at) : "Never",
            entry.pending > 0 ? lepBadge(String(entry.pending) + " pending", "info") : "None",
          ],
        };
      });
      section.node.appendChild(lepTable(
        ["EID", "Label", "This eIM", "Profiles", "Last polled", "Operations"],
        rows,
        "No eUICC yet. Put a card in the reader and use Read the card in the reader, or register an EID."
      ));
      section.node.appendChild(lepEl("p", "lep-help",
        "Open an eUICC to see its profiles, queue operations for it and follow them in its event log."));
      root.appendChild(section.node);
    }

    // -- one eUICC -----------------------------------------------------

    function renderDownloadForm(parent) {
      var form = lepEl("form", "lep-inline-form");
      var codeLabel = lepEl("label", "lep-field");
      codeLabel.appendChild(lepEl("span", "lep-field-label", "Activation code"));
      var code = lepEl("input", "lep-input");
      code.type = "text";
      code.placeholder = "1$smdpp.example.test$MATCHING-ID";
      code.autocomplete = "off";
      codeLabel.appendChild(code);
      form.appendChild(codeLabel);
      var indirectLabel = lepEl("label", "lep-check");
      var indirect = lepEl("input");
      indirect.type = "checkbox";
      indirectLabel.appendChild(indirect);
      indirectLabel.appendChild(lepEl("span", "", "Indirect download (the card downloads through this eIM)"));
      form.appendChild(indirectLabel);
      var bar = lepEl("div", "lep-inline-form-bar");
      var submit = lepEl("button", "btn btn-primary lep-btn", "Queue download");
      submit.type = "submit";
      bar.appendChild(submit);
      bar.appendChild(lepButton("Cancel", function () {
        state.formOpen = false;
        render();
      }));
      bar.appendChild(lepButton("More options", function () {
        hooks.openForm("eim_local.op_queue", { operation: "DOWNLOAD", eid: state.eid, value: code.value });
      }));
      form.appendChild(bar);
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        var value = String(code.value || "").trim();
        if (!value) {
          code.focus();
          return;
        }
        queue("DOWNLOAD", { value: value, params: indirect.checked ? "indirect=on" : "" },
          "Download queued.");
      });
      parent.appendChild(form);
      window.setTimeout(function () { code.focus(); }, 0);
    }

    function renderNewOperation(parent) {
      var types = ((state.data && state.data.catalogue) || []).slice();
      var form = lepEl("form", "lep-inline-form");
      var typeLabel = lepEl("label", "lep-field");
      typeLabel.appendChild(lepEl("span", "lep-field-label", "Operation"));
      var select = lepEl("select", "lep-input");
      types.forEach(function (kind) {
        var option = lepEl("option", "", kind.title + " (" + kind.verb + ")");
        option.value = kind.verb;
        select.appendChild(option);
      });
      var refreshAll = lepEl("option", "", "Refresh everything (profiles, eIMs, eUICC data)");
      refreshAll.value = "REFRESH";
      select.appendChild(refreshAll);
      if (state.newOperationType) select.value = state.newOperationType;
      select.addEventListener("change", function () { state.newOperationType = select.value; });
      typeLabel.appendChild(select);
      form.appendChild(typeLabel);
      var fieldsHost = lepEl("div", "lep-form-grid");
      form.appendChild(fieldsHost);
      var fields = [];
      function drawFields() {
        fieldsHost.textContent = "";
        fields = [];
        var kind = types.filter(function (entry) { return entry.verb === select.value; })[0];
        ((kind && kind.params) || []).forEach(function (spec) {
          var field = lepParamField(spec, "");
          fields.push(field);
          fieldsHost.appendChild(field.node);
        });
        if (fields.length === 0) {
          fieldsHost.appendChild(lepEl("div", "lep-empty", "This operation takes no parameter."));
        }
      }
      select.addEventListener("change", drawFields);
      drawFields();
      var options = lepEl("div", "lep-form-grid");
      var notBefore = lepParamField({ name: "not_before", kind: "text",
        help: "earliest time to serve it, e.g. 2030-01-01T12:00 or +10m" }, "");
      var retries = lepParamField({ name: "retries", kind: "text", help: "retries after a failed delivery" }, "");
      var first = lepParamField({ name: "queue_first", kind: "bool", help: "put it ahead of the queue" }, "");
      [notBefore, retries, first].forEach(function (field) { options.appendChild(field.node); });
      form.appendChild(lepFold("Queue options", function () { return options; }));
      var bar = lepEl("div", "lep-inline-form-bar");
      var submit = lepEl("button", "btn btn-primary lep-btn", "Queue operation");
      submit.type = "submit";
      bar.appendChild(submit);
      bar.appendChild(lepButton("Cancel", function () {
        state.newOperation = false;
        state.formOpen = false;
        state.newOperationType = "";
        render();
      }));
      bar.appendChild(lepButton("Advanced form", function () {
        hooks.openForm("eim_local.op_queue", { operation: select.value, eid: state.eid });
      }));
      form.appendChild(bar);
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        var values = {};
        // A saved configuration fills the fields left empty, the required ones included.
        var filled = fields.some(function (field) { return field.kind === "configuration" && field.read(); });
        for (var i = 0; i < fields.length; i += 1) {
          var value = fields[i].read();
          if (!value && fields[i].required && !filled) {
            fields[i].input.focus();
            return;
          }
          if (value) values[fields[i].name] = value;
        }
        var inputs = { params: lepPairs(values) };
        if (notBefore.read()) inputs.at = notBefore.read();
        if (/^\d+$/.test(retries.read())) inputs.retries = Number(retries.read());
        if (first.read() === "on") inputs.first = true;
        var title = select.options[select.selectedIndex].textContent;
        queue(select.value, inputs, title + " queued.");
      });
      parent.appendChild(form);
    }

    function renderProfiles(root, euicc) {
      var section = lepSection("eSIM profiles");
      section.tools.appendChild(lepButton("Refresh eSIM profile list", function () {
        queue("LIST-PROFILES", {}, "Profile list refresh queued.");
      }));
      section.tools.appendChild(lepButton("Download a profile", function () {
        state.formOpen = !state.formOpen;
        render();
      }, true));
      if (state.formOpen && !state.newOperation) renderDownloadForm(section.node);
      var rollbackLabel = lepEl("label", "lep-check");
      var rollback = lepEl("input");
      rollback.type = "checkbox";
      rollback.checked = state.rollback;
      rollback.addEventListener("change", function () { state.rollback = rollback.checked; });
      rollbackLabel.appendChild(rollback);
      rollbackLabel.appendChild(lepEl("span", "",
        "Enable with rollback (rollbackFlag: the IPA may return to the previous profile)"));
      section.node.appendChild(rollbackLabel);
      var rows = (euicc.profiles || []).map(function (profile) {
        var enabled = String(profile.state || "").toLowerCase() === "enabled";
        var actions = lepEl("div", "lep-row-actions");
        actions.appendChild(lepButton(enabled ? "Disable" : "Enable", function () {
          var extra = { value: profile.iccid };
          if (!enabled && state.rollback) extra.params = "rollback=on";
          queue(enabled ? "DISABLE" : "ENABLE", extra,
            (enabled ? "Disable" : "Enable" + (state.rollback ? " with rollback" : ""))
            + " queued for " + profile.iccid + ".");
        }));
        if (profile.fallback) {
          actions.appendChild(lepButton("Unset fallback", function () {
            queue("UNSET-FALLBACK", {}, "Unset fallback attribute queued.");
          }));
        } else {
          actions.appendChild(lepButton("Set fallback", function () {
            queue("FALLBACK", { value: profile.iccid }, "Fallback attribute queued for " + profile.iccid + ".");
          }));
        }
        var remove = lepButton("Delete", function () {
          if (remove.getAttribute("data-armed") !== "1") {
            remove.setAttribute("data-armed", "1");
            remove.textContent = "Confirm delete";
            remove.classList.add("lep-btn--danger");
            return;
          }
          queue("DELETE", { value: profile.iccid }, "Delete queued for " + profile.iccid + ".");
        });
        actions.appendChild(remove);
        return {
          cells: [
            lepEl("span", "lep-mono", profile.iccid),
            profile.service_provider,
            profile.name || profile.nickname,
            lepBadge(enabled ? "Enabled" : "Disabled", enabled ? "ok" : "info"),
            profile.class,
            profile.fallback ? lepBadge("Fallback", "info") : (profile.fallback_allowed ? "Allowed" : ""),
            actions,
          ],
        };
      });
      section.node.appendChild(lepTable(
        ["ICCID", "Provider", "Name", "State", "Class", "Fallback", ""],
        rows,
        "No profile recorded. Use Refresh eSIM profile list to ask the card."
      ));
      var refreshed = euicc.refreshed || {};
      section.node.appendChild(lepStamp(refreshed.profiles
        ? "Last updated: " + lepTime(refreshed.profiles)
        + (refreshed.profiles_stale ? " (changed since by an operation; refresh to confirm)" : "")
        : "Never read from the card."));
      root.appendChild(section.node);
    }

    function renderInformation(root, euicc) {
      var section = lepSection("eUICC information");
      section.tools.appendChild(lepButton("Refresh eUICC information", function () {
        queue("IPA-DATA", {}, "eUICC information refresh queued.");
      }));
      var immediate = euicc.immediate_enable === true ? "On"
        : (euicc.immediate_enable === false ? "Off" : "Unknown");
      var smdpCell = lepEl("span", "lep-fact-edit");
      smdpCell.appendChild(lepEl("span", "", euicc.default_smdp_address || "-"));
      smdpCell.appendChild(lepButton("Set", function () {
        state.formOpen = true;
        var form = lepEl("form", "lep-inline-form");
        var field = lepParamField({ name: "default_SM-DP+_address", kind: "text", required: true,
          help: "the address the card contacts for a download without an activation code; empty clears it" },
          euicc.default_smdp_address || "");
        form.appendChild(field.node);
        var bar = lepEl("div", "lep-inline-form-bar");
        var submit = lepEl("button", "btn btn-primary lep-btn", "Queue change");
        submit.type = "submit";
        bar.appendChild(submit);
        bar.appendChild(lepButton("Cancel", function () {
          state.formOpen = false;
          render();
        }));
        form.appendChild(bar);
        form.addEventListener("submit", function (event) {
          event.preventDefault();
          queue("DEFAULT-SMDP", { params: lepPairs({ address: field.read() }) },
            "Default SM-DP+ address change queued.");
        });
        section.node.insertBefore(form, section.node.children[1] || null);
        field.input.focus();
      }));
      var immediateCell = lepEl("span", "lep-fact-edit");
      immediateCell.appendChild(lepEl("span", "", immediate));
      immediateCell.appendChild(lepButton("Turn on", function () {
        queue("IMMEDIATE-ENABLE", { params: "enabled=on" }, "Immediate profile enabling (on) queued.");
      }));
      immediateCell.appendChild(lepButton("Turn off", function () {
        queue("IMMEDIATE-ENABLE", { params: "enabled=off" }, "Immediate profile enabling (off) queued.");
      }));
      section.node.appendChild(lepFacts([
        ["Default SM-DP+", smdpCell],
        ["Root SM-DS", euicc.root_smds_address],
        ["Immediate profile enabling", immediateCell],
        ["Association token", euicc.association_token === null ? "" : euicc.association_token],
        ["eIM counter", euicc.counter_value],
        ["TLS setup", euicc.tls_setup],
        ["Polls", euicc.poll_count],
        ["First polled", lepTime(euicc.first_poll_at)],
      ]));
      var more = lepFold("Show more (EUICCInfo1, EUICCInfo2, device information, certificates)", function () {
        var body = lepEl("div", "lep-fold-body");
        (euicc.stored || []).forEach(function (item) {
          body.appendChild(lepDecodedBlock(hooks, item.label, item.hex, item.decode, null));
        });
        body.appendChild(lepEl("div", "lep-sub-title", "eUICC certificate"));
        body.appendChild(lepCertificate(euicc.euicc_certificate));
        body.appendChild(lepEl("div", "lep-sub-title", "EUM certificate"));
        body.appendChild(lepCertificate(euicc.eum_certificate));
        return body;
      });
      section.node.appendChild(more);
      var refreshed = euicc.refreshed || {};
      section.node.appendChild(lepStamp(refreshed.ipa_data
        ? "Last updated: " + lepTime(refreshed.ipa_data)
        : "Never reported by the card."));
      root.appendChild(section.node);
    }

    function renderEims(root, euicc) {
      var identity = (state.data && state.data.identity) || {};
      var section = lepSection("eIMs linked with eUICC");
      section.tools.appendChild(lepButton("Refresh linked eIM list", function () {
        queue("LIST-EIM", {}, "Linked eIM list refresh queued.");
      }));
      // addEim (SGP.32 v1.3 §2.11.1.1, an eCO in a signed eUICC Package) adds an eIM beside the ones the
      // card has; Link this eIM (AddInitialEim after a reset) leaves this eIM the only one.
      section.tools.appendChild(lepButton("Add an eIM (addEim)", function () {
        state.newOperation = true;
        state.formOpen = true;
        state.newOperationType = "ADD-EIM";
        state.scrollToNewOperation = true;
        render();
      }));
      section.tools.appendChild(lepButton("Link this eIM", function () {
        hooks.openForm("eim_local.associate", {});
      }, true));
      var rows = (euicc.eims || []).map(function (entry) {
        var own = identity.eim_id && String(entry.eim_id) === String(identity.eim_id);
        var name = lepEl("span", "lep-mono", entry.eim_id);
        var cell = lepEl("span", "lep-eim-id");
        cell.appendChild(name);
        if (own) cell.appendChild(lepBadge("This eIM", "ok"));
        return {
          cells: [
            cell,
            entry.eim_fqdn,
            entry.counter_value,
            entry.association_token,
          ],
        };
      });
      section.node.appendChild(lepEl("p", "lep-help",
        "Add an eIM queues an addEim for the card: it keeps the eIMs it has and answers with the association "
        + "token the added eIM needs; a saved configuration (config) fills the fields. "
        + "Link this eIM resets the card's eIM configuration and adds this eIM as its only one "
        + "(Associate); the form asks for a confirmation."));
      section.node.appendChild(lepTable(
        ["eIM ID", "FQDN", "Counter", "Association token"],
        rows,
        euicc.associated
          ? "The card's list has not been read. Use Refresh linked eIM list."
          : "This eIM is not linked to the card. Put the card in the reader and use Link this eIM."
      ));
      var refreshed = euicc.refreshed || {};
      section.node.appendChild(lepStamp(refreshed.eims
        ? "Last updated: " + lepTime(refreshed.eims)
        : "Never read from the card."));
      root.appendChild(section.node);
    }

    // Send, then say what the engine answered: its lines carry the outcome
    // per Notification, and only a "[+]" one says it arrived.
    async function notificationAction(actionId, inputs, doneText) {
      if (state.busy) return;
      state.busy = true;
      var resp;
      try {
        resp = await hooks.post(actionId, inputs);
      } catch (err) {
        resp = { ok: false, error: String(err && err.message || err) };
      }
      state.busy = false;
      if (!resp || !resp.ok) {
        setNotice("fail", "Not done: " + String(resp && resp.error || "unknown error"));
      } else {
        var lines = ((resp.data && resp.data.lines) || []).map(function (line) { return String(line).trim(); });
        var open = lines.filter(function (line) { return line.indexOf("[+]") !== 0; });
        var shown = (open.length > 0 ? open : lines).map(function (line) {
          return line.replace(/^\[[!+*]\]\s*/, "");
        });
        setNotice(open.length > 0 ? "warn" : "ok", shown.length > 0 ? shown.join(" ") : doneText);
      }
      await load(true);
    }

    function renderNotifications(root, euicc) {
      var notifications = euicc.notifications || [];
      var pending = notifications.filter(function (row) { return row.state === "pending"; }).length;
      var section = lepSection("Notifications");
      if (pending > 0) {
        section.tools.appendChild(lepButton("Send pending", function () {
          notificationAction("eim_local.notifications_send", { eid: euicc.eid }, "Nothing was pending.");
        }, true));
      }
      var rows = notifications.map(function (row) {
        var status = lepEl("span", "lep-status lep-status--wide");
        status.appendChild(lepBadge(lepNotificationLabel(row.state), lepNotificationTone(row.state)));
        var note = lepNotificationNote(row);
        if (note) status.appendChild(lepEl("span", "lep-status-note", note));
        var tail = lepEl("div", "lep-row-actions");
        var number = row.seq_number;
        if (row.state !== "delivered" && number !== undefined && number !== null) {
          // A pending one goes by itself anyway; a failed or kept one goes again
          // only on the operator's word, so its Send takes a second press.
          var send = lepButton("Send", function () {
            if (row.state !== "pending" && send.getAttribute("data-armed") !== "1") {
              send.setAttribute("data-armed", "1");
              send.textContent = "Confirm send";
              send.classList.add("lep-btn--danger");
              return;
            }
            notificationAction("eim_local.notifications_send",
              { eid: euicc.eid, seq_numbers: String(number) }, "Sent.");
          });
          send.title = "Send Notification " + String(number) + " to " + String(row.address || "its receiver") + " now";
          tail.appendChild(send);
        }
        var sequence = lepEl("span", "", number === undefined || number === null ? "-" : String(number));
        if (row.at) sequence.title = "Taken by this eIM " + lepTime(row.at);
        return {
          cells: [
            sequence,
            row.event || row.kind,
            row.iccid ? lepEl("span", "lep-mono", row.iccid) : "",
            row.address,
            status,
            tail,
          ],
        };
      });
      section.node.appendChild(lepEl("p", "lep-help",
        "What the card's IPA handed to this eIM. The eIM sends every one to the Notification Receiver it names, "
        + "the SM-DP+ of the profile, and holds none back: while that server does not answer it tries again, and "
        + "one it cannot deliver ends as Failed with the reason. A failed or kept one goes again only by its own Send."));
      section.node.appendChild(lepTable(
        ["Sequence number", "Event", "ICCID", "Notification Receiver", "Status", ""],
        rows,
        "No Notification has been handed to this eIM for this eUICC."
      ));
      root.appendChild(section.node);
    }

    function renderEvents(root, euicc) {
      var section = lepSection("Event log");
      section.tools.appendChild(lepButton("Refresh", function () { load(true); }));
      var rows = (euicc.operations || []).map(function (operation) {
        var status = lepEl("span", "lep-status");
        status.appendChild(lepBadge(lepStateLabel(operation.state), lepStateTone(operation.state)));
        if (operation.error) status.appendChild(lepEl("span", "lep-status-note", operation.error));
        var tail = lepEl("div", "lep-row-actions");
        if (!operation.final) {
          tail.appendChild(lepButton("Cancel", async function () {
            var resp = await hooks.post("eim_local.op_cancel", { operation_id: operation.id });
            setNotice(resp && resp.ok ? "ok" : "fail",
              resp && resp.ok ? "Operation " + operation.id + " canceled."
                : "Not canceled: " + String(resp && resp.error || "unknown error"));
            load(true);
          }));
        }
        return {
          onClick: function () { go("operation", euicc.eid, operation.id); },
          cells: [
            lepTime(operation.created_at),
            operation.title,
            status,
            operation.finished_at ? lepTime(operation.finished_at) : "",
            operation.author || (operation.system ? "the eIM" : ""),
            tail,
          ],
        };
      });
      section.node.appendChild(lepTable(
        ["Queued on", "Action", "Status", "Completed on", "Queued by", ""],
        rows,
        "No operation yet."
      ));
      section.node.appendChild(lepEl("p", "lep-help",
        "Select a row to open the operation: its package, its result, and its parameters while it is still queued."));
      root.appendChild(section.node);
    }

    function renderEuicc(root) {
      var euicc = state.data && state.data.euicc;
      if (!euicc) return;
      var back = lepEl("button", "lep-back", "\u2190 Linked eUICCs");
      back.type = "button";
      back.addEventListener("click", function () { go("list", ""); });
      root.appendChild(back);

      var head = lepEl("div", "lep-euicc-head");
      var identityBlock = lepEl("div", "lep-euicc-id");
      var chips = lepEl("div", "lep-chips");
      if (euicc.label) chips.appendChild(lepEl("span", "lep-chip", euicc.label));
      chips.appendChild(lepBadge(euicc.associated ? "Linked to this eIM" : "Not linked to this eIM",
        euicc.associated ? "ok" : "warn"));
      identityBlock.appendChild(chips);
      identityBlock.appendChild(lepEl("h2", "lep-eid", euicc.eid));
      head.appendChild(identityBlock);
      var pending = (euicc.pending || []).length;
      head.appendChild(lepFacts([
        ["Last polled", euicc.last_poll_at ? lepTime(euicc.last_poll_at) : "Never"],
        ["Pending operations", pending === 0 ? "No operations pending" : String(pending) + " pending"],
      ]));
      var headTools = lepEl("div", "lep-euicc-tools");
      headTools.appendChild(lepButton("New operation", function () {
        state.newOperation = !state.newOperation;
        state.formOpen = state.newOperation;
        state.newOperationType = "";
        render();
      }));
      // Delivery writes to the card and takes its Notifications, so it asks
      // first, naming the reader it will use; the armed line also keeps the
      // background refresh from redrawing the page under the question.
      var deliverNow = lepButton("Deliver now (IPAd)", function () {
        var reader = hooks.reader();
        if (!reader) {
          deliver();
          return;
        }
        if (head.querySelector(".cc-write-confirm")) return;
        var question = ccWriteConfirmStrip(
          "Deliver now acts as the IPAd on the card in " + reader + " until its queue is empty. "
            + "The card's pending Notifications are taken and acknowledged, so the card drops them; "
            + "this eIM then sends each to the SM-DP+ it names.",
          function () {
            question.remove();
            deliver(reader);
          },
          function () { question.remove(); }
        );
        question.setAttribute("data-armed", "1");
        head.appendChild(question);
      }, pending > 0);
      deliverNow.title = "This eIM acts as the IPAd on the card in the reader until the queue is empty; "
        + "the Notifications it reads from the card then go to their SM-DP+";
      headTools.appendChild(deliverNow);
      hooks.actionsWithTag("ipae-deliver").forEach(function (action) {
        var viaIpae = lepButton("Deliver (IPAe)", function () {
          stopTimer();
          hooks.openForm(action.id, {});
        });
        viaIpae.title = "The card's own IPAe fetches the queue: " + String(action.title || action.id);
        headTools.appendChild(viaIpae);
      });
      head.appendChild(headTools);
      root.appendChild(head);
      root.appendChild(lepEl("p", "lep-help",
        "A button below queues an operation. The card takes it when it polls this eIM "
        + "(the service must be running), or at once with Deliver now and the card in the reader."));

      renderDownloadCallout(root, euicc);
      if (state.newOperation) {
        var newSection = lepSection("New operation");
        renderNewOperation(newSection.node);
        root.appendChild(newSection.node);
        if (state.scrollToNewOperation) {
          // Opened from a section further down: bring the form into view.
          state.scrollToNewOperation = false;
          window.requestAnimationFrame(function () { newSection.node.scrollIntoView({ block: "start" }); });
        }
      }
      renderProfiles(root, euicc);
      renderInformation(root, euicc);
      renderEims(root, euicc);
      renderEvents(root, euicc);
      renderNotifications(root, euicc);
    }

    // -- one operation -------------------------------------------------

    function renderOperation(root) {
      var operation = state.operation;
      if (!operation) return;
      var back = lepEl("button", "lep-back", "\u2190 " + operation.eid);
      back.type = "button";
      back.addEventListener("click", function () { go("euicc", operation.eid); });
      root.appendChild(back);

      var head = lepEl("div", "lep-euicc-head");
      var identityBlock = lepEl("div", "lep-euicc-id");
      var chips = lepEl("div", "lep-chips");
      chips.appendChild(lepBadge(lepStateLabel(operation.state), lepStateTone(operation.state)));
      chips.appendChild(lepEl("span", "lep-chip", operation.type));
      identityBlock.appendChild(chips);
      identityBlock.appendChild(lepEl("h2", "lep-eid", "Operation " + operation.id + ": " + operation.title));
      head.appendChild(identityBlock);
      var tools = lepEl("div", "lep-euicc-tools");
      if (!operation.final) {
        tools.appendChild(lepButton("Cancel operation", async function () {
          var resp = await hooks.post("eim_local.op_cancel", { operation_id: operation.id });
          setNotice(resp && resp.ok ? "ok" : "fail", resp && resp.ok ? "Operation canceled."
            : "Not canceled: " + String(resp && resp.error || "unknown error"));
          load(true);
        }));
      }
      tools.appendChild(lepButton("Queue a copy", async function () {
        var resp = await hooks.post("eim_local.op_copy", { operation_id: operation.id });
        setNotice(resp && resp.ok ? "ok" : "fail", resp && resp.ok
          ? "A copy is queued; it is in the event log, where it can be changed."
          : "Not copied: " + String(resp && resp.error || "unknown error"));
        if (resp && resp.ok) {
          go("euicc", operation.eid);
          return;
        }
        render();
      }));
      head.appendChild(tools);
      root.appendChild(head);
      if (operation.error) {
        root.appendChild(lepEl("div", "lep-notice lep-notice--fail", operation.error));
      }
      (operation.warnings || []).concat(operation.plan_warnings || []).filter(function (text, index, all) {
        return all.indexOf(text) === index;
      }).forEach(function (text) {
        root.appendChild(lepEl("div", "lep-notice lep-notice--warn", text));
      });
      root.appendChild(lepFacts([
        ["Queued on", lepTime(operation.created_at)],
        ["Served on", lepTime(operation.served_at)],
        ["Completed on", lepTime(operation.finished_at)],
        ["Queued by", operation.author],
        ["Route", operation.route],
        ["Retries", String(operation.retries) + " of " + String(operation.max_retries)],
        ["Not before", lepTime(operation.not_before)],
        ["Transaction", operation.transaction_id],
        ["eIM counter", operation.counter_value === null ? "" : operation.counter_value],
        ["Fault injected", operation.fault],
      ]));

      // Parameters: fields while it is queued, values afterwards.
      var paramSection = lepSection("Parameters");
      var params = operation.params || {};
      var specs = (operation.param_specs || []).slice();
      Object.keys(params).forEach(function (name) {
        if (!specs.some(function (spec) { return spec.name === name; })) {
          specs.push({ name: name, kind: "text", required: false, help: "", choices: [] });
        }
      });
      if (operation.editable) {
        var form = lepEl("form", "lep-inline-form");
        var grid = lepEl("div", "lep-form-grid");
        var fields = specs.map(function (spec) {
          var field = lepParamField(spec, params[spec.name]);
          grid.appendChild(field.node);
          return field;
        });
        var rawItems = lepParamField({ name: "raw_items", kind: "text",
          help: "hex that replaces the built PSMO / eCO items; empty restores the built ones" },
          operation.raw_items || "");
        var notBefore = lepParamField({ name: "at", kind: "text",
          help: "earliest time to serve it; empty clears it" }, operation.not_before || "");
        var retries = lepParamField({ name: "retries", kind: "text", help: "retries after a failed delivery" },
          String(operation.max_retries));
        [rawItems, notBefore, retries].forEach(function (field) { grid.appendChild(field.node); });
        form.appendChild(grid);
        var bar = lepEl("div", "lep-inline-form-bar");
        var save = lepEl("button", "btn btn-primary lep-btn", "Save changes");
        save.type = "submit";
        bar.appendChild(save);
        bar.appendChild(lepButton("More (type, fault, position)", function () {
          hooks.openForm("eim_local.op_edit", { operation_id: operation.id });
        }));
        form.appendChild(bar);
        form.addEventListener("input", function () { state.formOpen = true; });
        form.addEventListener("submit", async function (event) {
          event.preventDefault();
          var changes = {};
          fields.forEach(function (field) {
            var before = params[field.name];
            if (before === true) before = "on";
            if (before === false) before = "off";
            before = before === undefined || before === null ? "" : String(before);
            if (field.read() !== before) changes[field.name] = field.read();
          });
          if (rawItems.read() !== String(operation.raw_items || "")) changes.raw_items = rawItems.read();
          if (notBefore.read() !== String(operation.not_before || "")) changes.at = notBefore.read();
          if (retries.read() !== String(operation.max_retries)) changes.retries = retries.read();
          if (Object.keys(changes).length === 0) {
            setNotice("warn", "Nothing was changed.");
            state.formOpen = false;
            render();
            return;
          }
          var resp = await hooks.post("eim_local.op_edit",
            { operation_id: operation.id, changes: lepPairs(changes) });
          state.formOpen = false;
          setNotice(resp && resp.ok ? "ok" : "fail", resp && resp.ok ? "Operation changed."
            : "Not changed: " + String(resp && resp.error || "unknown error"));
          load(true);
        });
        paramSection.node.appendChild(form);
      } else {
        paramSection.node.appendChild(specs.length === 0
          ? lepEl("div", "lep-empty", "This operation has no parameter.")
          : lepFacts(specs.filter(function (spec) {
            return params[spec.name] !== undefined;
          }).map(function (spec) {
            var value = params[spec.name];
            return [spec.name.replace(/_/g, " "), value === true ? "on" : (value === false ? "off" : value)];
          })));
        paramSection.node.appendChild(lepStamp(
          "Only a queued operation takes changes; Queue a copy makes one that does."));
      }
      root.appendChild(paramSection.node);

      var packageSection = lepSection("Package");
      if (operation.package_hex) {
        packageSection.node.appendChild(lepDecodedBlock(hooks,
          operation.package_state === "served"
            ? "As served to the card"
            : "The part fixed so far (it is signed when an IPA takes it)",
          operation.package_hex, operation.package_state === "served" ? "es10" : "tlv", operation.package_rows));
      } else {
        packageSection.node.appendChild(lepEl("div", "lep-empty", "No package bytes yet."));
      }
      root.appendChild(packageSection.node);

      var resultSection = lepSection("Result");
      if (operation.result_hex) {
        resultSection.node.appendChild(lepDecodedBlock(hooks, "The card's answer", operation.result_hex,
          "es10", operation.result_rows));
      } else {
        resultSection.node.appendChild(lepEl("div", "lep-empty",
          operation.final ? "No result bytes were recorded." : "No result yet."));
      }
      root.appendChild(resultSection.node);

      var timeline = lepSection("Timeline");
      timeline.node.appendChild(lepTable(["When", "Event"],
        (operation.history || []).map(function (entry) {
          return { cells: [lepTime(entry.at), entry.event] };
        }), "No event recorded."));
      root.appendChild(timeline.node);
    }

    // -- eIM configuration --------------------------------------------

    function renderConfig(root) {
      var data = state.data || {};
      var identity = data.identity || {};
      var service = data.service || {};
      var tls = data.tls || {};

      var idSection = lepSection("Identity");
      idSection.tools.appendChild(lepButton("Replace identity", function () {
        hooks.openForm("eim_local.identity_new", {});
      }));
      idSection.node.appendChild(lepEl("p", "lep-help",
        "Replace identity generates a new signing key: cards linked to the current one no longer "
        + "accept this eIM's packages until they are linked again."));
      idSection.node.appendChild(lepFacts([
        ["eIM ID", identity.eim_id],
        ["eIM ID type", identity.eim_id_type_name],
        ["FQDN given to cards", identity.effective_fqdn],
        ["FQDN comes from", identity.fqdn_source],
        ["Identity FQDN", identity.eim_fqdn],
        ["Protocols", (identity.supported_protocols || []).join(", ")],
        ["Indirect profile download", identity.indirect_profile_download ? "Offered" : "Not offered"],
        ["eUICC CI PKID", identity.euicc_ci_pkid_hex],
        ["Created", lepTime(identity.created_at)],
      ]));
      root.appendChild(idSection.node);

      var signSection = lepSection("Signing certificate");
      signSection.node.appendChild(lepFacts([
        ["Certificate file", identity.signing_certificate_path],
        ["Private key file", identity.signing_key_path],
      ]));
      signSection.node.appendChild(lepEl("div", "lep-sub-title", "Public key (SubjectPublicKeyInfo)"));
      signSection.node.appendChild(lepEl("pre", "lep-hex", identity.signing_public_key_hex || "-"));
      signSection.node.appendChild(lepCertificate(identity.signing_certificate));
      root.appendChild(signSection.node);

      var tlsSection = lepSection("TLS certificates");
      tlsSection.tools.appendChild(lepButton("TLS setups", function () {
        hooks.runInPane("eim_local.tls_setup_list", {}, { runningText: "reading" });
      }));
      tlsSection.tools.appendChild(lepButton("New TLS setup", function () {
        hooks.openForm("eim_local.tls_setup_new", {});
      }));
      tlsSection.tools.appendChild(lepButton("New leaf", function () {
        hooks.openForm("eim_local.tls_leaf_new", { setup: tls.active || "" });
      }));
      tlsSection.tools.appendChild(lepButton("Leaf editor", function () {
        openLeafEditor(tls.active || "", "");
      }));
      tlsSection.tools.appendChild(lepButton("TLS results", function () {
        hooks.runInPane("eim_local.tls_results", {}, { runningText: "reading" });
      }));
      tlsSection.node.appendChild(lepFacts([
        ["Setup in use", tls.active || "The identity's own certificate"],
        ["Identity TLS certificate", identity.tls_certificate_path],
        ["Identity TLS key", identity.tls_key_path],
      ]));
      (tls.served || []).forEach(function (material) {
        var names = (material.names || []).join(", ");
        var title = material.label + (names ? " - " + names : "")
          + (material.label === tls.active ? " (in use)" : "");
        tlsSection.node.appendChild(lepFold(title, function () {
          var body = lepEl("div", "lep-fold-body");
          body.appendChild(lepFacts([
            ["Leaf on the name", material.leaf
              ? material.leaf + (material.leaf_sha256 ? " (SHA-256 " + material.leaf_sha256.slice(0, 8) + ")" : "")
              : ""],
            ["Chain file", material.chain_path],
            ["Key file", material.key_path],
            ["TLS versions", material.versions],
            ["Client authentication", material.client_auth],
          ]));
          if (material.leaf && material.label !== "identity") {
            var edit = lepEl("div", "lep-inline-form-bar");
            edit.appendChild(lepButton("Edit a copy of this leaf", function () {
              openLeafEditor(material.label, material.leaf);
            }));
            body.appendChild(edit);
          }
          (material.certificates || []).forEach(function (rows, index) {
            body.appendChild(lepEl("div", "lep-sub-title",
              index === 0 ? "Server certificate" : "Chain certificate " + index));
            body.appendChild(lepCertificate(rows));
          });
          return body;
        }));
      });
      if ((tls.served || []).length === 0) {
        tlsSection.node.appendChild(lepEl("div", "lep-empty", "No chain is served yet."));
      }
      root.appendChild(tlsSection.node);

      var serviceSection = lepSection("Service");
      if (service.running) {
        serviceSection.tools.appendChild(lepButton("Restart", function () {
          hooks.runInPane("eim_local.service_restart", {}, { runningText: "restarting" });
        }));
        var stop = lepButton("Stop", function () {
          if (stop.getAttribute("data-armed") !== "1") {
            stop.setAttribute("data-armed", "1");
            stop.textContent = "Confirm stop";
            stop.classList.add("lep-btn--danger");
            return;
          }
          hooks.runInPane("eim_local.service_stop", {}, { runningText: "stopping" });
        });
        serviceSection.tools.appendChild(stop);
      } else {
        serviceSection.tools.appendChild(lepButton("Start service", function () {
          hooks.openForm("eim_local.service_start", {});
        }, true));
      }
      serviceSection.tools.appendChild(lepButton("Traffic", function () {
        hooks.openForm("eim_local.traffic", {});
      }));
      serviceSection.node.appendChild(lepFacts([
        ["State", lepBadge(service.running ? (service.answers ? "Running" : "Not answering") : "Stopped",
          service.running && service.answers ? "ok" : "warn")],
        ["ESipa (plain)", service.url],
        ["ESipa (TLS, card-facing)", service.tls_url],
        ["TLS setup served by default", service.tls_setup],
        ["Local SM-DP+ address", service.smdp_address],
        ["Local SM-DP+ (TLS)", service.smdp_tls_url],
        ["Local SM-DS address", service.smds_address],
        ["Local SM-DS (TLS)", service.smds_tls_url],
        ["Started", lepTime(service.started_at)],
        ["Log", service.log],
      ]));
      root.appendChild(serviceSection.node);

      var rulesSection = lepSection("Queue rules");
      rulesSection.tools.appendChild(lepButton("Change", function () {
        hooks.openForm("eim_local.queue_settings", {});
      }));
      var settings = data.settings || {};
      rulesSection.node.appendChild(lepFacts(Object.keys(settings).sort().map(function (key) {
        var value = settings[key];
        return [key, value === true ? "on" : (value === false ? "off" : value)];
      })));
      rulesSection.node.appendChild(lepStamp("Store: " + String(data.store || "")));
      root.appendChild(rulesSection.node);
    }

    function render() {
      if (!state.host) return;
      var scrollTop = state.host.scrollTop;
      var root = lepEl("div", "lep-page");
      root.setAttribute("data-lep-view", state.view);
      if (!state.data) {
        root.appendChild(lepEl("div", "lep-empty", state.notice ? state.notice.text : "Reading the Local eIM store..."));
      } else {
        renderTopBar(root);
        if (!state.data.identity && state.view !== "config") {
          renderNoIdentity(root);
        }
        if (state.view === "euicc") {
          renderEuicc(root);
        } else if (state.view === "operation") {
          renderOperation(root);
        } else if (state.view === "delivery") {
          renderDelivery(root);
        } else if (state.view === "leaf" && state.leaf) {
          lleRender(root, leafEditorContext());
        } else if (state.view === "config") {
          if (state.data.identity) {
            renderConfig(root);
          } else {
            renderNoIdentity(root);
          }
        } else {
          renderList(root);
        }
      }
      state.host.innerHTML = "";
      state.host.appendChild(root);
      state.root = root;
      state.host.scrollTop = scrollTop;
    }

    function mount(host) {
      stopTimer();
      state.host = host;
      state.signature = "";
      render();
      load(true);
      // The store changes when a card polls; the timer ends with the page.
      state.timer = setInterval(function () {
        if (!attached()) {
          stopTimer();
          return;
        }
        if (document.hidden || state.busy) return;
        load(false);
      }, LEP_REFRESH_MS);
    }

    return { mount: mount, state: state };
  }
