  // -- Plugin consoles: start form, actions, command line, help ---------------
  //
  // Every control is built from the validated manifest. An action posts its
  // id and field values; the server renders the command line from the
  // action's template, checks each value, and the transcript shows the line
  // that ran, so a button teaches the command the plugin's CLI takes.

  var PC_MAX_TRANSCRIPT = 200;
  var PC_MAX_HISTORY = 100;
  // An action's answer under its own card: the first lines, the rest is in the transcript.
  var PC_ACTION_RESULT_LINES = 4;
  // Generated field ids live under a prefix no static id in the view uses, so a
  // plugin field named "message" or "fields" can never shadow the skeleton.
  var PC_FIELD_ID_PREFIX = "pc-f-";

  function pcRenderConsole(manifest) {
    setText("pc-title", manifest.title);
    setText("pc-summary", manifest.summary || "");
    var notice = $("pc-notice");
    if (notice) notice.hidden = true;
    var layout = $("pc-layout");
    if (layout) layout.hidden = false;
    pcSetMessage("", "");
    pcRenderStart(manifest);
    pcRenderActions(manifest);
    pcRenderCommandLine(manifest);
    pcRenderStreams(manifest);
    pcRenderCompareManifest(manifest);
    pcRenderRuns(manifest);
    pcPlaceState(manifest);
    // Last: the tabs pick up the panels the calls above rendered.
    pcRenderTabs(manifest);
    pcRenderStatus(null);
  }

  function pcRenderStart(manifest) {
    var host = $("pc-start-fields");
    var controls = $("pc-start-controls");
    if (!host || !controls) return;
    host.textContent = "";
    controls.hidden = !manifest.start;
    if (!manifest.start) return;
    setText("pc-start", manifest.start.label || "Start");
    manifest.start.fields.forEach(function (field) {
      host.appendChild(pcBuildField(field, PC_FIELD_ID_PREFIX + "start-"));
    });
  }

  function pcBuildSelect(field) {
    var select = document.createElement("select");
    if (field.options_from) {
      // A choice the console fills: the options arrive with its status answer
      // (pcApplyChoices), so the manifest names none and the blank pick stays first.
      var pick = document.createElement("option");
      pick.value = "";
      pick.textContent = field.placeholder || "(pick one)";
      select.appendChild(pick);
      select.setAttribute("data-pc-options-from", field.options_from);
      return select;
    }
    if (field.type === "reader") {
      var blank = document.createElement("option");
      blank.value = "";
      blank.textContent = field.placeholder || (field.required ? "(pick a reader)" : "(first reader)");
      select.appendChild(blank);
      // The fill may pick the remembered reader; a change event tells the form.
      prefillReaderSelect(select).then(function () {
        select.dispatchEvent(new Event("change"));
      });
      return select;
    }
    field.options.forEach(function (option) {
      var entry = document.createElement("option");
      entry.value = option.value;
      entry.textContent = option.label;
      select.appendChild(entry);
    });
    select.value = field.default;
    return select;
  }

  function pcBuildInput(field) {
    var input = document.createElement("input");
    // A secret is typed into a password box and never prefilled (it has no default).
    input.type = field.secret ? "password" : (field.type === "number" ? "number" : "text");
    input.autocomplete = field.secret ? "new-password" : "off";
    input.spellcheck = false;
    if (field.type === "number") {
      input.step = field.step === null ? "any" : String(field.step);
      if (field.min !== null) input.min = String(field.min);
      if (field.max !== null) input.max = String(field.max);
      input.value = field.default === null ? "" : String(field.default);
    } else {
      input.maxLength = field.max_length;
      input.value = field.default || "";
    }
    if (field.placeholder) input.placeholder = field.placeholder;
    return input;
  }

  function pcBuildField(field, idPrefix) {
    var row = document.createElement("div");
    row.className = "cc-form-row";
    var id = idPrefix + field.name;
    var label = document.createElement("label");
    label.htmlFor = id;
    label.textContent = field.label + (field.required ? " *" : "");
    row.appendChild(label);
    var input;
    if (field.type === "boolean") {
      var wrapper = document.createElement("label");
      wrapper.className = "cc-checkbox";
      input = document.createElement("input");
      input.type = "checkbox";
      input.checked = field.default === true;
      wrapper.appendChild(input);
      var text = document.createElement("span");
      text.textContent = "Enabled";
      wrapper.appendChild(text);
      row.appendChild(wrapper);
    } else if (field.type === "choice" || field.type === "reader") {
      input = pcBuildSelect(field);
      row.appendChild(input);
    } else {
      input = pcBuildInput(field);
      if (field.fill) {
        // A start field the console fills from the other start values (a button beside it).
        var holder = document.createElement("div");
        holder.className = "cc-path-row pc-field-with-fill";
        holder.appendChild(input);
        var fill = document.createElement("button");
        fill.type = "button";
        fill.className = "btn pc-field-fill";
        fill.textContent = field.fill.label;
        fill.addEventListener("click", function () { pcFillField(field, input, fill); });
        holder.appendChild(fill);
        row.appendChild(holder);
      } else {
        row.appendChild(input);
      }
    }
    input.id = id;
    input.name = field.name;
    input.setAttribute("data-pc-type", field.type);
    if (field.required) input.setAttribute("aria-required", "true");
    if (field.hint) {
      var help = document.createElement("small");
      help.className = "pc-field-help";
      help.id = id + "-help";
      help.textContent = field.hint;
      input.setAttribute("aria-describedby", help.id);
      row.appendChild(help);
    }
    return row;
  }

  function pcCollectValues(host) {
    var values = {};
    if (!host) return values;
    host.querySelectorAll("[data-pc-type]").forEach(function (input) {
      var type = input.getAttribute("data-pc-type");
      if (type === "boolean") {
        values[input.name] = Boolean(input.checked);
      } else if (type === "number") {
        var text = String(input.value || "").trim();
        values[input.name] = text === "" ? null : Number(text);
      } else {
        values[input.name] = String(input.value || "");
      }
    });
    return values;
  }

  function pcActionGroups(actions) {
    var order = [];
    var groups = {};
    actions.forEach(function (action) {
      var key = action.group || "";
      if (!Object.prototype.hasOwnProperty.call(groups, key)) {
        groups[key] = [];
        order.push(key);
      }
      groups[key].push(action);
    });
    return order.map(function (key) { return { label: key, actions: groups[key] }; });
  }

  function pcRenderActions(manifest) {
    var panel = $("pc-actions-panel");
    var host = $("pc-actions");
    var toolbar = $("pc-compare-actions");
    var shared = $("pc-compare-result");
    if (!panel || !host) return;
    host.textContent = "";
    if (toolbar) toolbar.textContent = "";
    if (shared) {
      shared.hidden = true;
      shared.textContent = "";
    }
    // An action placed in the comparison panel renders as a toolbar button
    // there and answers under the toolbar; the rest keep their cards here.
    var listed = manifest.actions.filter(function (action) { return action.place !== "compare"; });
    var placed = manifest.actions.filter(function (action) { return action.place === "compare"; });
    panel.hidden = listed.length === 0;
    pcActionGroups(listed).forEach(function (group) {
      var section = document.createElement("div");
      section.className = "pc-action-group";
      if (group.label) {
        var heading = document.createElement("h3");
        heading.textContent = group.label;
        section.appendChild(heading);
      }
      group.actions.forEach(function (action) {
        section.appendChild(pcBuildAction(action));
      });
      host.appendChild(section);
    });
    if (!toolbar) return;
    toolbar.hidden = placed.length === 0;
    pcActionGroups(placed).forEach(function (group) {
      var row = document.createElement("div");
      row.className = "pc-compare-toolbar-group";
      row.setAttribute("role", "group");
      if (group.label) {
        var label = document.createElement("span");
        label.className = "pc-compare-toolbar-label";
        label.textContent = group.label;
        row.appendChild(label);
        row.setAttribute("aria-label", group.label);
      }
      group.actions.forEach(function (action) {
        row.appendChild(pcBuildToolbarAction(action, shared));
      });
      toolbar.appendChild(row);
    });
  }

  function pcBuildToolbarAction(action, shared) {
    // The compact form of an action: its button and its fields on one line,
    // the answer in the panel's shared result box prefixed with the label.
    var form = document.createElement("form");
    form.className = "pc-toolbar-action";
    form.noValidate = true;
    form.setAttribute("data-pc-action", action.id);
    form.title = (action.hint ? action.hint + " " : "") + "(" + action.template + ")";
    var button = document.createElement("button");
    button.type = "submit";
    button.className = "btn btn-small";
    button.textContent = action.label;
    form.appendChild(button);
    action.fields.forEach(function (field) {
      var holder = document.createElement("label");
      holder.className = "pc-toolbar-field";
      var text = document.createElement("span");
      text.textContent = field.label;
      holder.appendChild(text);
      var control = field.type === "choice" ? pcBuildSelect(field) : pcBuildInput(field);
      control.id = PC_FIELD_ID_PREFIX + "bar-" + action.id + "-" + field.name;
      control.name = field.name;
      control.setAttribute("data-pc-type", field.type);
      control.setAttribute("aria-required", "true");
      if (field.hint) control.title = field.hint;
      holder.appendChild(control);
      form.appendChild(holder);
    });
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (shared) shared.setAttribute("data-pc-prefix", action.label + ": ");
      pcSend({ action: action.id, values: pcCollectValues(form) }, action.label, shared);
    });
    return form;
  }

  function pcBuildAction(action) {
    var form = document.createElement("form");
    form.className = "pc-action";
    form.noValidate = true;
    form.setAttribute("data-pc-action", action.id);
    var head = document.createElement("div");
    head.className = "pc-action-head";
    var button = document.createElement("button");
    button.type = "submit";
    button.className = "btn btn-small";
    button.textContent = action.label;
    head.appendChild(button);
    var template = document.createElement("code");
    template.className = "pc-action-template";
    template.textContent = action.template;
    head.appendChild(template);
    form.appendChild(head);
    if (action.hint) {
      var hint = document.createElement("p");
      hint.className = "pc-action-hint";
      hint.textContent = action.hint;
      form.appendChild(hint);
    }
    if (action.fields.length > 0) {
      var fields = document.createElement("div");
      fields.className = "pc-fields";
      action.fields.forEach(function (field) {
        fields.appendChild(pcBuildField(field, PC_FIELD_ID_PREFIX + "act-" + action.id + "-"));
      });
      form.appendChild(fields);
    }
    var result = document.createElement("div");
    result.className = "pc-action-result";
    result.setAttribute("role", "status");
    result.hidden = true;
    form.appendChild(result);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      pcSend({ action: action.id, values: pcCollectValues(form) }, action.label, result);
    });
    return form;
  }

  function pcFirstLines(text, count) {
    var lines = String(text || "").replace(/\s+$/, "").split("\n");
    return lines.slice(0, count).join("\n") + (lines.length > count ? "\n..." : "");
  }

  function pcShowActionResult(host, text, failed) {
    if (!host) return;
    host.hidden = false;
    var prefix = host.getAttribute("data-pc-prefix") || "";
    host.textContent = prefix + (pcFirstLines(text, PC_ACTION_RESULT_LINES) || (failed ? "failed" : "done"));
    host.dataset.state = failed ? "error" : "";
  }

  function pcFollowReaderPill(previous, name) {
    // A console's reader selects follow the top bar pill, unless the operator
    // picked another reader in the form by hand.
    var wanted = String(name || "");
    document.querySelectorAll('#pc-layout select[data-pc-type="reader"]').forEach(function (select) {
      var current = String(select.value || "");
      if (current !== "" && current !== String(previous || "")) return;
      if (wanted && !Array.from(select.options).some(function (option) { return option.value === wanted; })) {
        var entry = document.createElement("option");
        entry.value = wanted;
        entry.textContent = wanted;
        select.appendChild(entry);
      }
      select.value = wanted;
      select.dispatchEvent(new Event("change"));
    });
  }

  function pcRenderCommandLine(manifest) {
    var line = manifest.command_line;
    var panel = $("pc-command-panel");
    if (panel) panel.hidden = !line && manifest.actions.length === 0;
    setText("pc-command-title", line ? "Command line" : "Output");
    var form = $("pc-command-form");
    if (form) form.hidden = !line;
    var input = $("pc-command-input");
    if (input) {
      input.value = "";
      input.placeholder = (line && line.placeholder) || "";
    }
    setText("pc-command-hint", (line && line.hint) || "");
    var transcript = $("pc-transcript");
    if (transcript) transcript.textContent = "";
    var help = $("pc-help");
    if (help) {
      help.hidden = !line;
      help.open = false;
    }
    var helpBody = $("pc-help-body");
    if (helpBody) helpBody.textContent = "";
  }

  function pcAppendTranscript(line, text, failed, truncated) {
    var host = $("pc-transcript");
    if (!host) return;
    var entry = document.createElement("div");
    entry.className = "pc-transcript-entry" + (failed ? " is-error" : "");
    var head = document.createElement("div");
    head.className = "pc-transcript-line";
    head.textContent = "> " + line;
    entry.appendChild(head);
    if (text) {
      var body = document.createElement("pre");
      body.className = "pc-transcript-output";
      body.textContent = text + (truncated ? "\n[output cut at the size cap]" : "");
      entry.appendChild(body);
    }
    host.appendChild(entry);
    while (host.childElementCount > PC_MAX_TRANSCRIPT) {
      host.removeChild(host.firstElementChild);
    }
    host.scrollTop = host.scrollHeight;
  }

  // inline: the result line under the action card that sent it, when there is one.
  async function pcSend(payload, echo, inline) {
    var consoleId = pcState.activeId;
    if (!consoleId) return;
    try {
      var result = await apiFetch(pcApi(consoleId, "/command"), { method: "POST", body: JSON.stringify(payload) });
      if (consoleId === pcState.activeId) {
        pcAppendTranscript(result.line || echo, result.output || "", false, Boolean(result.truncated));
        pcShowActionResult(inline, result.output || "", false);
      }
    } catch (err) {
      if (consoleId === pcState.activeId) {
        pcAppendTranscript(echo, pcErrorText(err), true, false);
        pcShowActionResult(inline, pcErrorText(err), true);
      }
    }
    pcPollSoon();
  }

  function pcSetMessage(text, stateName) {
    var message = $("pc-start-message");
    if (!message) return;
    message.textContent = text;
    message.dataset.state = stateName || "";
  }

  async function pcFillField(field, input, button) {
    var manifest = pcState.manifest;
    if (!manifest || pcState.busy) return;
    var consoleId = manifest.id;
    var values = pcCollectValues($("pc-start-fields"));
    delete values[field.name];
    button.disabled = true;
    pcSetMessage(field.fill.label + "...", "");
    try {
      var answer = await apiFetch(pcApi(consoleId, "/fill"), { method: "POST", body: JSON.stringify({ field: field.name, values: values }) });
      if (consoleId === pcState.activeId) {
        input.value = String(answer.value || "");
        pcSetMessage(String(answer.note || ""), "");
      }
    } catch (err) {
      if (consoleId === pcState.activeId) pcSetMessage(pcErrorText(err), "error");
    }
    button.disabled = false;
    pcRenderStatus(pcState.status);
  }

  async function pcStartOrStop(verb) {
    var manifest = pcState.manifest;
    if (!manifest || !manifest.start || pcState.busy) return;
    var consoleId = manifest.id;
    var payload = verb === "start" ? { values: pcCollectValues($("pc-start-fields")) } : {};
    pcState.busy = true;
    pcSetMessage(verb === "start" ? "starting..." : "stopping...", "");
    pcRenderStatus(pcState.status);
    pcPollSoon();
    try {
      var status = await apiFetch(pcApi(consoleId, "/" + verb), { method: "POST", body: JSON.stringify(payload) });
      pcState.busy = false;
      if (consoleId === pcState.activeId) {
        pcSetMessage("", "");
        pcRenderStatus(status);
      }
      logBus.emit({ level: "info", source: "plugin-console", message: manifest.title + (verb === "start" ? " started." : " stopped.") });
      pcSchedulePills(0);
    } catch (err) {
      pcState.busy = false;
      if (consoleId === pcState.activeId) {
        pcSetMessage(pcErrorText(err), "error");
        pcRenderStatus(pcState.status);
      }
    }
    pcPollSoon();
  }

  function pcRemember(line) {
    var list = pcState.history[pcState.activeId] || [];
    if (list[list.length - 1] !== line) list.push(line);
    while (list.length > PC_MAX_HISTORY) list.shift();
    pcState.history[pcState.activeId] = list;
    pcState.historyIndex = -1;
  }

  function pcRecall(input, step) {
    var list = pcState.history[pcState.activeId] || [];
    if (list.length === 0) return;
    var index = pcState.historyIndex === -1 ? list.length : pcState.historyIndex;
    index = Math.max(0, Math.min(list.length, index + step));
    pcState.historyIndex = index === list.length ? -1 : index;
    input.value = index === list.length ? "" : list[index];
  }

  async function pcLoadHelp() {
    var consoleId = pcState.activeId;
    var body = $("pc-help-body");
    if (!body || !consoleId || pcState.helpFor === consoleId) return;
    pcState.helpFor = consoleId;
    body.textContent = "loading...";
    try {
      var help = await apiFetch(pcApi(consoleId, "/help"));
      if (consoleId === pcState.activeId) pcRenderHelp(help);
    } catch (err) {
      pcState.helpFor = "";
      body.textContent = "help unavailable: " + pcErrorText(err);
    }
  }

  function pcHelpEntry(list, item) {
    var term = document.createElement("dt");
    var pick = document.createElement("button");
    pick.type = "button";
    pick.className = "pc-help-command";
    pick.textContent = item.name;
    pick.title = "Put " + item.name + " on the command line";
    pick.addEventListener("click", function () {
      var input = $("pc-command-input");
      if (!input || input.disabled) return;
      input.value = item.name + " ";
      input.focus();
    });
    term.appendChild(pick);
    if (item.aliases.length > 0) {
      var aliases = document.createElement("span");
      aliases.className = "pc-help-aliases";
      aliases.textContent = item.aliases.join(", ");
      term.appendChild(aliases);
    }
    list.appendChild(term);
    var detail = document.createElement("dd");
    if (item.usage) {
      var usage = document.createElement("code");
      usage.textContent = item.usage;
      detail.appendChild(usage);
    }
    if (item.summary) {
      var summary = document.createElement("p");
      summary.textContent = item.summary;
      detail.appendChild(summary);
    }
    list.appendChild(detail);
  }

  function pcRenderHelp(help) {
    var body = $("pc-help-body");
    if (!body) return;
    body.textContent = "";
    (Array.isArray(help && help.groups) ? help.groups : []).forEach(function (group) {
      if (group.group) {
        var heading = document.createElement("h3");
        heading.textContent = group.group;
        body.appendChild(heading);
      }
      var list = document.createElement("dl");
      list.className = "pc-help-list";
      group.commands.forEach(function (item) {
        pcHelpEntry(list, item);
      });
      body.appendChild(list);
    });
    if (help && help.text) {
      var text = document.createElement("pre");
      text.className = "pc-help-text";
      text.textContent = help.text;
      body.appendChild(text);
    }
    if (!body.firstChild) body.textContent = "This console lists no commands.";
  }

  function pcWireForms() {
    pcWireTabs();
    var start = $("pc-start");
    if (start) start.addEventListener("click", function () { pcStartOrStop("start"); });
    var stop = $("pc-stop");
    if (stop) stop.addEventListener("click", function () { pcStartOrStop("stop"); });
    var form = $("pc-command-form");
    var input = $("pc-command-input");
    if (form && input) {
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        var line = String(input.value || "").trim();
        if (!line) return;
        pcRemember(line);
        input.value = "";
        pcSend({ line: line }, line);
      });
      input.addEventListener("keydown", function (event) {
        if (event.key === "ArrowUp" || event.key === "ArrowDown") {
          event.preventDefault();
          pcRecall(input, event.key === "ArrowUp" ? -1 : 1);
        }
      });
    }
    var help = $("pc-help");
    if (help) {
      help.addEventListener("toggle", function () {
        if (help.open) pcLoadHelp();
      });
    }
    pcWireRuns();
  }
