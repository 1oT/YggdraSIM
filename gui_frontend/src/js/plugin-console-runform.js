  // -- Plugin consoles: run form ---------------------------------------------
  //
  // A console whose manifest carries a run form gets a variant select, the
  // fields no item names, one card per item with its own fields inline, and
  // the field groups a ticked item uses, placed before or after the items.
  // pcRunPlan mirrors plan_run in plugin_console_selection.py (the tests
  // hold both to one table): which items run, which fields are visible and
  // in use, which required ones are blank and which credentials the run
  // needs. Only visible fields are sent; the server repeats the selection
  // and checks every value. The entry picked for a named credential is not
  // part of the plan (plugin-console-credentials.js). Every label is the
  // manifest's.

  var PC_RUN_FIELD_PREFIX = PC_FIELD_ID_PREFIX + "run-";
  var PC_RUN_ITEM_PREFIX = PC_FIELD_ID_PREFIX + "item-";

  function pcRuns() {
    return pcState.manifest && pcState.manifest.runs ? pcState.manifest.runs : null;
  }

  function pcRunVariant() {
    var runs = pcRuns();
    if (!runs) return null;
    for (var i = 0; i < runs.variants.length; i += 1) {
      if (runs.variants[i].id === pcState.runVariant) return runs.variants[i];
    }
    return runs.variants[0];
  }

  function pcHas(object, key) {
    return Object.prototype.hasOwnProperty.call(object, key);
  }

  // -- the plan: mirror of plan_run ------------------------------------------

  function pcRunMatches(value, wanted) {
    if (typeof wanted === "boolean") return value === wanted;
    if (typeof wanted === "number") return typeof value === "number" && value === wanted;
    return typeof value === "string" && value === wanted;
  }

  function pcRunBlank(field, value) {
    if (field.type === "boolean" || field.type === "choice") return false;
    return value === null || value === undefined || (typeof value === "string" && value.trim() === "");
  }

  function pcRunNormal(field, value) {
    // The value check_value keeps for a valid input: text trimmed, choices exact.
    if (field.type === "boolean") return value === true;
    if (field.type === "number") return typeof value === "number" && isFinite(value) ? value : null;
    if (field.type === "choice") return value;
    return typeof value === "string" ? value.trim() : value;
  }

  function pcRunOptions(field, choices) {
    // The manifest's options, or the console's current list for a field it fills.
    if (!field.options_from) return field.options;
    var given = choices && Object.prototype.hasOwnProperty.call(choices, field.options_from) ? choices[field.options_from] : null;
    return Array.isArray(given) ? given : [];
  }

  function pcRunEvaluate(fields, used, given, choices) {
    var visible = [];
    var values = {};
    var missing = [];
    fields.forEach(function (field) {
      if (!used[field.name]) return;
      var condition = field.visible_when;
      if (condition && (!pcHas(values, condition.field) || !pcRunMatches(values[condition.field], condition.equals))) return;
      visible.push(field.name);
      var raw = pcHas(given, field.name) ? given[field.name] : field.default;
      if (field.options_from) {
        // A choice the console fills: blank is missing, a value has to be on the current list.
        if (raw === null || raw === undefined || raw === "") {
          if (field.required) missing.push(field.name);
          else values[field.name] = "";
          return;
        }
        var listed = pcRunOptions(field, choices).some(function (option) { return option && option.value === raw; });
        if (listed) values[field.name] = raw;
        return;
      }
      if (field.required && pcRunBlank(field, raw)) {
        missing.push(field.name);
        return;
      }
      values[field.name] = pcRunNormal(field, raw);
    });
    return { visible: visible, values: values, missing: missing };
  }

  function pcRunPlan(runs, variant, ticked, given, choices) {
    var fields = runs.fields.concat(variant.fields);
    var named = {};
    variant.items.forEach(function (item) {
      item.fields.forEach(function (name) { named[name] = true; });
    });
    var usedBy = function (items) {
      var used = {};
      fields.forEach(function (field) {
        if (!named[field.name]) used[field.name] = true;
      });
      items.forEach(function (item) {
        item.fields.forEach(function (name) { used[name] = true; });
      });
      return used;
    };
    var manual = variant.items.filter(function (item) {
      return ticked.indexOf(item.id) >= 0 && !item.auto_when;
    });
    var first = pcRunEvaluate(fields, usedBy(manual), given, choices).values;
    var auto = variant.items.filter(function (item) {
      return Boolean(item.auto_when) && pcHas(first, item.auto_when.field) && pcRunMatches(first[item.auto_when.field], item.auto_when.equals);
    });
    var selected = variant.items.filter(function (item) {
      return manual.indexOf(item) >= 0 || auto.indexOf(item) >= 0;
    });
    var final = pcRunEvaluate(fields, usedBy(selected), given, choices);
    var wanted = {};
    selected.forEach(function (item) {
      item.credentials.forEach(function (id) { wanted[id] = true; });
    });
    var ids = function (item) { return item.id; };
    return {
      items: manual.map(ids),
      auto_items: auto.map(ids),
      visible: final.visible,
      values: final.values,
      missing: final.missing,
      credentials: runs.credentials.filter(function (item) { return wanted[item.id]; }).map(ids),
    };
  }

  // -- reading the form ------------------------------------------------------

  function pcRunFieldValue(field) {
    var input = $(PC_RUN_FIELD_PREFIX + field.name);
    if (!input) return field.default;
    if (field.type === "boolean") return Boolean(input.checked);
    if (field.type === "number") {
      var text = String(input.value || "").trim();
      return text === "" ? null : Number(text);
    }
    return String(input.value || "");
  }

  function pcRunGiven(runs, variant) {
    var given = {};
    runs.fields.concat(variant.fields).forEach(function (field) {
      given[field.name] = pcRunFieldValue(field);
    });
    return given;
  }

  function pcRunTicked(variant) {
    return variant.items.filter(function (item) {
      var box = $(PC_RUN_ITEM_PREFIX + item.id);
      return Boolean(box && box.checked && !item.auto_when);
    }).map(function (item) { return item.id; });
  }

  function pcRunCurrentPlan() {
    var runs = pcRuns();
    var variant = pcRunVariant();
    if (!runs || !variant) return null;
    var given = pcRunGiven(runs, variant);
    var plan = pcRunPlan(runs, variant, pcRunTicked(variant), given, pcState.choices);
    plan.given = given;
    return plan;
  }

  // -- choices the console fills ---------------------------------------------

  function pcChoicesSignature(options) {
    return JSON.stringify((Array.isArray(options) ? options : []).map(function (option) {
      return [String(option && option.value), String(option && option.label)];
    }));
  }

  function pcApplyChoices(choices) {
    // Every select filled by the console follows its status answer: the list is
    // rebuilt only when it changed, and the pick survives while it is still listed.
    var current = choices && typeof choices === "object" ? choices : {};
    pcState.choices = current;
    var changed = false;
    document.querySelectorAll("select[data-pc-options-from]").forEach(function (select) {
      var source = select.getAttribute("data-pc-options-from");
      var options = Array.isArray(current[source]) ? current[source] : [];
      var signature = pcChoicesSignature(options);
      if (select.getAttribute("data-pc-choices") === signature) return;
      select.setAttribute("data-pc-choices", signature);
      var picked = String(select.value || "");
      while (select.options.length > 1) select.remove(1);
      options.forEach(function (option) {
        if (!option) return;
        var entry = document.createElement("option");
        entry.value = String(option.value);
        entry.textContent = String(option.label || option.value);
        select.appendChild(entry);
      });
      select.value = options.some(function (option) { return option && String(option.value) === picked; }) ? picked : "";
      changed = true;
    });
    if (changed && pcRuns()) pcRunRefresh();
  }

  // -- rendering -------------------------------------------------------------

  function pcRunBuildField(field) {
    var row = pcBuildField(field, PC_RUN_FIELD_PREFIX);
    row.setAttribute("data-pc-field", field.name);
    var control = row.querySelector("[data-pc-type]");
    if (control) {
      control.addEventListener("change", pcRunRefresh);
      control.addEventListener("input", pcRunRefresh);
    }
    return row;
  }

  function pcRenderRunVariantSelect(runs) {
    var host = $("pc-run-variant");
    if (!host) return;
    host.textContent = "";
    host.hidden = runs.variants.length < 2;
    if (runs.variants.length < 2) return;
    var row = document.createElement("div");
    row.className = "cc-form-row";
    var label = document.createElement("label");
    label.htmlFor = PC_FIELD_ID_PREFIX + "variant";
    label.textContent = runs.labels.variant;
    row.appendChild(label);
    var select = document.createElement("select");
    select.id = PC_FIELD_ID_PREFIX + "variant";
    runs.variants.forEach(function (variant) {
      var option = document.createElement("option");
      option.value = variant.id;
      option.textContent = variant.label + (variant.available ? "" : " (unavailable)");
      select.appendChild(option);
    });
    select.value = pcRunVariant().id;
    select.addEventListener("change", function () {
      pcState.runVariant = String(select.value || "");
      pcRenderRunForm();
    });
    row.appendChild(select);
    var summary = document.createElement("small");
    summary.className = "pc-field-help";
    summary.id = PC_FIELD_ID_PREFIX + "variant-summary";
    row.appendChild(summary);
    host.appendChild(row);
  }

  function pcRenderRunCommon(runs) {
    var host = $("pc-run-common");
    if (!host) return;
    host.textContent = "";
    runs.fields.forEach(function (field) {
      host.appendChild(pcRunBuildField(field));
    });
  }

  function pcRunItemCard(item, variant, byName) {
    var card = document.createElement("div");
    card.className = "pc-run-item" + (item.available ? "" : " is-unavailable");
    card.setAttribute("data-pc-item", item.id);
    var head = document.createElement("div");
    head.className = "pc-run-item-head";
    var control = document.createElement("label");
    control.className = "cc-checkbox";
    var box = document.createElement("input");
    box.type = "checkbox";
    box.id = PC_RUN_ITEM_PREFIX + item.id;
    box.disabled = Boolean(item.auto_when) || !item.available;
    box.addEventListener("change", pcRunRefresh);
    control.appendChild(box);
    var title = document.createElement("span");
    title.className = "pc-run-item-title";
    title.textContent = item.label;
    control.appendChild(title);
    head.appendChild(control);
    var chip = document.createElement("span");
    chip.className = "cc-chip";
    chip.textContent = item.auto_when ? "automatic" : (item.available ? item.badge : "unavailable");
    if (item.auto_when) {
      var controller = byName[item.auto_when.field];
      chip.title = "Selected by itself while " + (controller ? controller.label : item.auto_when.field) + " is " + String(item.auto_when.equals) + ".";
    } else if (!item.available && item.unavailable_reason) {
      chip.title = item.unavailable_reason;
    }
    chip.hidden = chip.textContent === "";
    head.appendChild(chip);
    card.appendChild(head);
    var summary = item.available || !item.unavailable_reason ? item.summary : item.summary + (item.summary ? " " : "") + item.unavailable_reason;
    if (summary) {
      var text = document.createElement("p");
      text.className = "pc-run-item-summary";
      text.textContent = summary;
      card.appendChild(text);
    }
    var body = document.createElement("div");
    body.className = "pc-run-item-body pc-fields";
    body.hidden = true;
    item.fields.forEach(function (name) {
      var field = byName[name];
      if (field && !field.group) body.appendChild(pcRunBuildField(field));
    });
    if (body.childElementCount > 0) card.appendChild(body);
    return card;
  }

  function pcRunGroupPanel(group, fields) {
    var panel = document.createElement("div");
    panel.className = "pc-run-group";
    panel.setAttribute("data-pc-group", group.id);
    panel.hidden = true;
    var title = document.createElement("div");
    title.className = "pc-run-group-title";
    title.textContent = group.label;
    panel.appendChild(title);
    var host = document.createElement("div");
    host.className = "pc-fields";
    fields.forEach(function (field) {
      host.appendChild(pcRunBuildField(field));
    });
    panel.appendChild(host);
    return panel;
  }

  function pcRenderRunForm() {
    var runs = pcRuns();
    var variant = pcRunVariant();
    if (!runs || !variant) return;
    pcState.runVariant = variant.id;
    setText(PC_FIELD_ID_PREFIX + "variant-summary", variant.summary + (variant.available ? "" : (variant.summary ? " " : "") + variant.unavailable_reason));
    var byName = {};
    runs.fields.concat(variant.fields).forEach(function (field) { byName[field.name] = field; });
    var named = {};
    variant.items.forEach(function (item) {
      item.fields.forEach(function (name) { named[name] = true; });
    });
    var fieldsHost = $("pc-run-fields");
    var itemsHost = $("pc-run-items");
    var before = $("pc-run-before-groups");
    var after = $("pc-run-after-groups");
    [fieldsHost, itemsHost, before, after].forEach(function (host) {
      if (host) host.textContent = "";
    });
    variant.fields.forEach(function (field) {
      if (!named[field.name] && !field.group && fieldsHost) fieldsHost.appendChild(pcRunBuildField(field));
    });
    variant.items.forEach(function (item) {
      if (itemsHost) itemsHost.appendChild(pcRunItemCard(item, variant, byName));
    });
    runs.groups.forEach(function (group) {
      var members = variant.fields.filter(function (field) { return field.group === group.id; });
      var host = group.place === "before_items" ? before : after;
      if (members.length > 0 && host) host.appendChild(pcRunGroupPanel(group, members));
    });
    pcRenderCredentials();
    // Selects the console fills take the options the last status brought.
    pcApplyChoices(pcState.choices);
    pcRunRefresh();
  }

  // -- visibility and validation ---------------------------------------------

  function pcRunRefresh() {
    var runs = pcRuns();
    var variant = pcRunVariant();
    var plan = pcRunCurrentPlan();
    if (!runs || !variant || !plan) return;
    var shown = {};
    plan.visible.forEach(function (name) { shown[name] = true; });
    var missing = {};
    plan.missing.forEach(function (name) { missing[name] = true; });
    document.querySelectorAll("#pc-run-form [data-pc-field]").forEach(function (row) {
      var name = row.getAttribute("data-pc-field");
      row.hidden = !shown[name];
      row.classList.toggle("is-missing", Boolean(missing[name]));
    });
    var selected = plan.items.concat(plan.auto_items);
    variant.items.forEach(function (item) {
      var box = $(PC_RUN_ITEM_PREFIX + item.id);
      var card = box ? box.closest(".pc-run-item") : null;
      var on = selected.indexOf(item.id) >= 0;
      if (box && item.auto_when) box.checked = on;
      if (card) {
        card.classList.toggle("is-checked", on);
        var body = card.querySelector(".pc-run-item-body");
        if (body) body.hidden = !on;
      }
    });
    var beforeShown = variant.credentials.length > 0;
    document.querySelectorAll("#pc-run-form [data-pc-group]").forEach(function (panel) {
      panel.hidden = !panel.querySelector("[data-pc-field]:not([hidden])");
      if (!panel.hidden && panel.parentNode && panel.parentNode.id === "pc-run-before-groups") beforeShown = true;
    });
    var block = $("pc-run-before");
    if (block) block.hidden = !beforeShown;
    pcRunValidate(plan);
  }

  function pcRunValidate(known) {
    var runs = pcRuns();
    var variant = pcRunVariant();
    var plan = known || pcRunCurrentPlan();
    var button = $("pc-run-start");
    var message = $("pc-run-validation");
    if (!runs || !variant || !plan || !button || !message) return;
    var byName = {};
    runs.fields.concat(variant.fields).forEach(function (field) { byName[field.name] = field; });
    var problems = [];
    if (!variant.available) problems.push(variant.unavailable_reason || variant.label + " cannot run");
    if (plan.items.length === 0) problems.push(runs.labels.items + ": tick at least one");
    if (plan.missing.length > 0) {
      problems.push("fill: " + plan.missing.map(function (name) { return byName[name].label; }).join(", "));
    }
    var waiting = {};
    plan.credentials.forEach(function (id) {
      var problem = pcCredentialProblem(id);
      if (problem) {
        waiting[id] = true;
        problems.push(problem);
      }
    });
    document.querySelectorAll("#pc-run-credentials [data-pc-credential], #pc-credentials [data-pc-credential]").forEach(function (panel) {
      panel.classList.toggle("is-missing", Boolean(waiting[panel.getAttribute("data-pc-credential")]));
    });
    // A form that accepts a start while a run is going adds to that run (a queue).
    if (pcState.runActive && !runs.accepts_while_running) problems.push("a run is in progress");
    button.disabled = problems.length > 0 || pcState.runStarting;
    message.textContent = problems.length > 0 ? problems.join("; ") : runs.labels.items + ": " + plan.items.length + " selected";
    message.dataset.state = problems.length > 0 ? "error" : "";
  }
