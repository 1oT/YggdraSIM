  // -- Plugin consoles: stored credentials -------------------------------------
  //
  // A run form may declare credentials: a secret (an API key) and its plain
  // settings that the plugin stores once, on its side, and every later run
  // uses. Every credential has a panel in the credentials tab; the run form
  // shows a status line for each one the chosen variant needs, with a button
  // to that tab. A named credential keeps several entries, each under a name
  // the operator gives it: its panel lists them, Add opens a Name field beside
  // the credential's own fields, and the run form's "Use for this run" picks
  // the entry a run uses (preselected while only one is usable). A credential
  // may rename its Store / Forget / Replace buttons. The panels talk to
  // /api/plugin-consoles/<id>/credentials, whose answers carry the plugin's
  // summary lines and the non-secret values only. A secret typed here stays
  // in the page until it is stored; Run stores the ones a selected item needs
  // before it starts, and a named entry stored that way is the one it uses.

  // The entry name is the core's field, not the plugin's: ENTRY_NAME in
  // plugin_console_runform.py is the rule the server applies.
  // CREDENTIAL_LABEL_DEFAULTS in plugin_console_runform.py; a validated credential always carries its own.
  var PC_CREDENTIAL_BUTTONS = { store: "Store", forget: "Forget", replace: "Replace" };

  var PC_CREDENTIAL_NAME_FIELD = {
    name: "name",
    label: "Name",
    type: "text",
    required: true,
    max_length: 40,
    default: "",
    placeholder: "",
    hint: "Letters, digits, '.', '_' or '-'; unique in this list.",
  };

  function pcCredentialDefinition(id) {
    var runs = pcRuns();
    var list = runs ? runs.credentials : [];
    for (var i = 0; i < list.length; i += 1) {
      if (list[i].id === id) return list[i];
    }
    return { id: id, label: id, hint: "", named: false, fields: [], labels: PC_CREDENTIAL_BUTTONS };
  }

  function pcCredentialButtons(definition) {
    return definition.labels || PC_CREDENTIAL_BUTTONS;
  }

  function pcCredentialStatus(id) {
    return pcState.credentials[id] || { stored: false, usable: false, summary: "", values: {}, entries: [] };
  }

  function pcCredentialEntries(id) {
    return pcCredentialStatus(id).entries || [];
  }

  function pcCredentialUsable(id) {
    return pcCredentialStatus(id).usable === true;
  }

  // replacing: the fields are open on purpose; target: the named entry they
  // replace ("" adds a new one under the typed name).
  function pcCredentialDraft(id) {
    if (!pcState.credentialDrafts[id]) {
      pcState.credentialDrafts[id] = { values: {}, replacing: false, name: "", target: "" };
    }
    return pcState.credentialDrafts[id];
  }

  function pcCredentialCloseEditor(id) {
    pcState.credentialDrafts[id] = { values: {}, replacing: false, name: "", target: "" };
    pcRenderCredentials();
    pcRunValidate();
  }

  // A draft is typed once a secret field holds text. A credential whose
  // secrets are all optional (a key passphrase left empty) counts once the
  // operator filled every required field, so Run can store it too.
  function pcCredentialTyped(id) {
    var definition = pcCredentialDefinition(id);
    var draft = pcCredentialDraft(id);
    var secretTyped = definition.fields.some(function (field) {
      return field.secret && String(draft.values[field.name] || "").trim() !== "";
    });
    if (secretTyped) return true;
    var secretRequired = definition.fields.some(function (field) { return field.secret && field.required; });
    if (secretRequired || Object.keys(draft.values).length === 0) return false;
    var entry = null;
    pcCredentialEntries(id).forEach(function (item) {
      if (definition.named && item.name === draft.target) entry = item;
    });
    return definition.fields.every(function (field) {
      return !field.required || pcCredentialValue(id, field, entry).trim() !== "";
    });
  }

  // A store under an existing name replaces that entry on the plugin's side,
  // so Add refuses one (any case); the entry's own Replace is the way.
  function pcCredentialNameTaken(id, name) {
    var wanted = String(name || "").trim().toLowerCase();
    return pcCredentialEntries(id).some(function (entry) { return entry.name.toLowerCase() === wanted; });
  }

  // The named entry a run uses: the operator's pick while it is usable, else
  // the only usable entry, else none.
  function pcCredentialPick(id) {
    var usable = pcCredentialEntries(id).filter(function (entry) { return entry.usable; });
    var picked = pcState.credentialPicks[id];
    for (var i = 0; i < usable.length; i += 1) {
      if (usable[i].name === picked) return picked;
    }
    return usable.length === 1 ? usable[0].name : "";
  }

  // The picks a run request carries: one per needed named credential, or
  // null when none of them is named.
  function pcCredentialPicks(ids) {
    var picks = null;
    ids.forEach(function (id) {
      if (!pcCredentialDefinition(id).named) return;
      picks = picks || {};
      var pick = pcCredentialPick(id);
      if (pick) picks[id] = pick;
    });
    return picks;
  }

  // Why a needed credential holds the run back, or "".
  function pcCredentialProblem(id) {
    var definition = pcCredentialDefinition(id);
    if (!definition.named) {
      return pcCredentialUsable(id) || pcCredentialTyped(id) ? "" : "enter the " + definition.label;
    }
    var draft = pcCredentialDraft(id);
    if (pcCredentialTyped(id)) {
      if (draft.target) return "";
      if (!String(draft.name || "").trim()) return "name the new " + definition.label;
      return pcCredentialNameTaken(id, draft.name) ? definition.label + ": an entry of that name exists; use its Replace" : "";
    }
    if (pcCredentialPick(id)) return "";
    var usable = pcCredentialEntries(id).some(function (entry) { return entry.usable; });
    return usable ? "pick the " + definition.label + " this run uses" : "enter the " + definition.label;
  }

  function pcCredentialValue(id, field, entry) {
    var draft = pcCredentialDraft(id);
    if (pcHas(draft.values, field.name)) return String(draft.values[field.name]);
    if (field.secret) return "";
    var stored = entry ? (entry.values || {}) : (pcCredentialStatus(id).values || {});
    return String(pcHas(stored, field.name) ? stored[field.name] : (field.default || ""));
  }

  function pcSetRunMessage(text, stateName) {
    var message = $("pc-run-validation");
    if (!message) return;
    message.textContent = text;
    message.dataset.state = stateName || "";
  }

  async function pcLoadCredentials() {
    var runs = pcRuns();
    var consoleId = pcState.activeId;
    if (!runs || runs.credentials.length === 0) {
      pcState.credentials = {};
      return;
    }
    try {
      var data = await apiFetch(pcApi(consoleId, "/credentials"));
      if (consoleId !== pcState.activeId) return;
      pcState.credentials = (data && data.credentials) || {};
    } catch (err) {
      if (consoleId !== pcState.activeId) return;
      pcState.credentials = {};
      logBus.emit({ level: "warn", source: "plugin-console", message: "credential status unavailable: " + pcErrorText(err) });
    }
    pcRenderCredentials();
    pcRunValidate();
  }

  function pcCredentialButton(label, handler) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "btn btn-small";
    button.textContent = label;
    button.addEventListener("click", handler);
    return button;
  }

  function pcCredentialFields(id, definition, entry, withName) {
    var host = document.createElement("div");
    host.className = "pc-fields";
    var prefix = PC_FIELD_ID_PREFIX + "cred-" + id + "-";
    if (withName) {
      // A doubled dash keeps this id apart from every declared field's.
      var nameRow = pcBuildField(PC_CREDENTIAL_NAME_FIELD, prefix + "-");
      var nameInput = nameRow.querySelector("[data-pc-type]");
      if (nameInput) {
        nameInput.value = pcCredentialDraft(id).name || "";
        nameInput.addEventListener("input", function () {
          pcCredentialDraft(id).name = String(nameInput.value);
          pcRunValidate();
        });
      }
      host.appendChild(nameRow);
    }
    definition.fields.forEach(function (field) {
      var row = pcBuildField(field, prefix);
      var input = row.querySelector("[data-pc-type]");
      if (input) {
        input.value = pcCredentialValue(id, field, entry);
        input.addEventListener("input", function () {
          pcCredentialDraft(id).values[field.name] = String(input.value);
          pcRunValidate();
        });
      }
      host.appendChild(row);
    });
    return host;
  }

  function pcCredentialPicker(id, usable) {
    var row = document.createElement("div");
    row.className = "cc-form-row pc-run-credential-pick";
    var select = document.createElement("select");
    select.id = PC_FIELD_ID_PREFIX + "cred-" + id + "--pick";
    var label = document.createElement("label");
    label.htmlFor = select.id;
    label.textContent = "Use for this run";
    row.appendChild(label);
    var current = pcCredentialPick(id);
    if (!current) {
      var blank = document.createElement("option");
      blank.value = "";
      blank.textContent = "(choose one)";
      select.appendChild(blank);
    }
    usable.forEach(function (entry) {
      var option = document.createElement("option");
      option.value = entry.name;
      option.textContent = entry.name;
      select.appendChild(option);
    });
    select.value = current;
    select.addEventListener("change", function () {
      pcState.credentialPicks[id] = String(select.value || "");
      pcRunValidate();
    });
    row.appendChild(select);
    return row;
  }

  function pcCredentialEntryRow(id, definition, entry, draft) {
    var buttonsText = pcCredentialButtons(definition);
    var row = document.createElement("div");
    row.className = "pc-run-credential-entry";
    row.setAttribute("data-pc-entry", entry.name);
    var head = document.createElement("div");
    head.className = "pc-run-credential-entry-head";
    var name = document.createElement("span");
    name.className = "pc-run-credential-entry-name";
    name.textContent = entry.name;
    head.appendChild(name);
    var line = document.createElement("span");
    line.className = "pc-run-credential-status";
    line.dataset.state = entry.usable ? "ok" : "error";
    line.textContent = entry.summary || (entry.usable ? "Stored." : "Not usable.");
    head.appendChild(line);
    row.appendChild(head);
    var editing = draft.replacing && draft.target === entry.name;
    if (editing) row.appendChild(pcCredentialFields(id, definition, entry, false));
    var buttons = document.createElement("div");
    buttons.className = "pc-buttons";
    if (editing) {
      buttons.appendChild(pcCredentialButton(buttonsText.store, function () { pcStoreCredential(id); }));
      buttons.appendChild(pcCredentialButton("Cancel", function () { pcCredentialCloseEditor(id); }));
    } else if (!draft.replacing) {
      buttons.appendChild(pcCredentialButton(buttonsText.replace, function () {
        pcState.credentialDrafts[id] = { values: {}, replacing: true, name: "", target: entry.name };
        pcRenderCredentials();
        pcRunValidate();
      }));
      buttons.appendChild(pcCredentialButton(buttonsText.forget, function () { pcForgetCredential(id, entry.name); }));
    }
    if (buttons.childElementCount > 0) row.appendChild(buttons);
    return row;
  }

  function pcNamedCredentialBody(id, definition, panel) {
    var draft = pcCredentialDraft(id);
    var entries = pcCredentialEntries(id);
    if (entries.length > 0) {
      var list = document.createElement("div");
      list.className = "pc-run-credential-entries";
      entries.forEach(function (entry) {
        list.appendChild(pcCredentialEntryRow(id, definition, entry, draft));
      });
      panel.appendChild(list);
    }
    // With nothing stored the Add fields are open from the start, as a plain
    // credential's are.
    var adding = entries.length === 0 || (draft.replacing && !draft.target);
    var buttons = document.createElement("div");
    buttons.className = "pc-buttons";
    if (adding) {
      panel.appendChild(pcCredentialFields(id, definition, null, true));
      buttons.appendChild(pcCredentialButton(pcCredentialButtons(definition).store, function () { pcStoreCredential(id); }));
      if (entries.length > 0) buttons.appendChild(pcCredentialButton("Cancel", function () { pcCredentialCloseEditor(id); }));
    } else if (!draft.replacing) {
      buttons.appendChild(pcCredentialButton("Add", function () {
        pcState.credentialDrafts[id] = { values: {}, replacing: true, name: "", target: "" };
        pcRenderCredentials();
        pcRunValidate();
      }));
    }
    if (buttons.childElementCount > 0) panel.appendChild(buttons);
  }

  function pcCredentialStatusLine(id) {
    var status = pcCredentialStatus(id);
    var line = document.createElement("p");
    line.className = "pc-run-credential-status";
    line.dataset.state = status.stored ? (status.usable ? "ok" : "error") : "missing";
    line.textContent = status.summary || (status.stored ? "Stored." : "Not stored.");
    return line;
  }

  function pcCredentialPanel(id) {
    var definition = pcCredentialDefinition(id);
    var status = pcCredentialStatus(id);
    var draft = pcCredentialDraft(id);
    var buttonsText = pcCredentialButtons(definition);
    var panel = document.createElement("div");
    panel.className = "pc-run-group pc-run-credential";
    panel.setAttribute("data-pc-credential", id);
    var title = document.createElement("div");
    title.className = "pc-run-group-title";
    title.textContent = definition.label;
    panel.appendChild(title);
    panel.appendChild(pcCredentialStatusLine(id));
    if (definition.hint) {
      var hint = document.createElement("small");
      hint.className = "pc-field-help";
      hint.textContent = definition.hint;
      panel.appendChild(hint);
    }
    if (definition.named) {
      pcNamedCredentialBody(id, definition, panel);
      return panel;
    }
    var buttons = document.createElement("div");
    buttons.className = "pc-buttons";
    if (!status.usable || draft.replacing) {
      panel.appendChild(pcCredentialFields(id, definition, null, false));
      buttons.appendChild(pcCredentialButton(buttonsText.store, function () { pcStoreCredential(id); }));
      if (draft.replacing) {
        buttons.appendChild(pcCredentialButton("Cancel", function () { pcCredentialCloseEditor(id); }));
      }
    } else {
      buttons.appendChild(pcCredentialButton(buttonsText.replace, function () {
        draft.replacing = true;
        pcRenderCredentials();
        pcRunValidate();
      }));
      buttons.appendChild(pcCredentialButton(buttonsText.forget, function () { pcForgetCredential(id, ""); }));
    }
    panel.appendChild(buttons);
    return panel;
  }

  // The run form's line for a credential the chosen variant needs: its state,
  // the entry this run uses (named credentials), and the way to its panel.
  function pcCredentialNeed(id) {
    var definition = pcCredentialDefinition(id);
    var row = document.createElement("div");
    row.className = "pc-run-group pc-run-credential-need";
    row.setAttribute("data-pc-credential", id);
    var head = document.createElement("div");
    head.className = "pc-run-credential-need-head";
    var title = document.createElement("span");
    title.className = "pc-run-group-title";
    title.textContent = definition.label;
    head.appendChild(title);
    var runs = pcRuns();
    head.appendChild(pcCredentialButton(runs ? runs.labels.credentials : "Credentials", function () {
      pcSelectTab("controls", "credentials", true);
    }));
    row.appendChild(head);
    row.appendChild(pcCredentialStatusLine(id));
    if (definition.named) {
      var usable = pcCredentialEntries(id).filter(function (entry) { return entry.usable; });
      if (usable.length > 0) row.appendChild(pcCredentialPicker(id, usable));
    }
    return row;
  }

  function pcRenderCredentials() {
    var runs = pcRuns();
    var host = $("pc-credentials");
    if (host) {
      host.textContent = "";
      (runs ? runs.credentials : []).forEach(function (definition) {
        host.appendChild(pcCredentialPanel(definition.id));
      });
    }
    var needs = $("pc-run-credentials");
    var variant = pcRunVariant();
    if (!needs) return;
    needs.textContent = "";
    if (!variant) return;
    variant.credentials.forEach(function (id) {
      needs.appendChild(pcCredentialNeed(id));
    });
  }

  // Resolves to "" once stored, or to the reason it was not. A named entry
  // stored here becomes the one the run uses.
  async function pcStoreCredential(id) {
    var consoleId = pcState.activeId;
    var definition = pcCredentialDefinition(id);
    var draft = pcCredentialDraft(id);
    var name = definition.named ? (draft.target || String(draft.name || "").trim()) : "";
    var entry = null;
    pcCredentialEntries(id).forEach(function (item) {
      if (definition.named && item.name === draft.target) entry = item;
    });
    var values = {};
    definition.fields.forEach(function (field) {
      values[field.name] = pcCredentialValue(id, field, entry);
    });
    var body = { values: values };
    if (definition.named) body.name = name;
    var what = definition.label + (name ? " " + name : "");
    if (definition.named && !draft.target && pcCredentialNameTaken(id, name)) {
      var taken = definition.label + ": an entry of that name exists; use its Replace";
      if (consoleId === pcState.activeId) pcSetRunMessage(taken, "error");
      return taken;
    }
    try {
      var status = await apiFetch(pcApi(consoleId, "/credentials/" + encodeURIComponent(id)), {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (consoleId !== pcState.activeId) return "the console changed";
      pcState.credentials[id] = status;
      pcState.credentialDrafts[id] = { values: {}, replacing: false, name: "", target: "" };
      if (definition.named) pcState.credentialPicks[id] = name;
      logBus.emit({ level: "info", source: "plugin-console", message: what + ": " + (status && status.summary ? status.summary : "stored.") });
      pcRenderCredentials();
      pcRunValidate();
      return "";
    } catch (err) {
      var reason = what + ": " + pcErrorText(err);
      if (consoleId === pcState.activeId) pcSetRunMessage(reason, "error");
      return reason;
    }
  }

  // name is the named entry to forget, "" for a plain credential.
  async function pcForgetCredential(id, name) {
    var consoleId = pcState.activeId;
    var definition = pcCredentialDefinition(id);
    var what = definition.label + (name ? " " + name : "");
    if (!window.confirm(pcCredentialButtons(definition).forget + ": " + what + "? A run that needs it asks for it again.")) return;
    var path = "/credentials/" + encodeURIComponent(id) + (name ? "?name=" + encodeURIComponent(name) : "");
    try {
      var status = await apiFetch(pcApi(consoleId, path), { method: "DELETE" });
      if (consoleId !== pcState.activeId) return;
      pcState.credentials[id] = status;
      if (name && pcState.credentialPicks[id] === name) delete pcState.credentialPicks[id];
      logBus.emit({ level: "info", source: "plugin-console", message: what + ": " + (status && status.summary ? status.summary : "forgotten.") });
    } catch (err) {
      if (consoleId === pcState.activeId) pcSetRunMessage(what + ": " + pcErrorText(err), "error");
      return;
    }
    pcRenderCredentials();
    pcRunValidate();
  }
