  // -- Local eIM leaf editor ------------------------------------------------
  //
  // A TLS leaf's subject and extensions as rows: one row per subject
  // attribute, in certificate order, and one block per extension with the
  // controls its value takes. The rows live in the page's state, because
  // the page rebuilds its DOM on every render, and the server is the only
  // parser: eim_local.tls_leaf_rows turns a leaf, a stored certificate or a
  // text into rows (and rows into text), and eim_local.tls_leaf_new issues
  // the leaf from that text. Nothing here talks to a card.
  //
  // lleNewEditor(setup) -> the editor's state object.
  // lleRender(root, ctx): ctx = { editor, hooks, setups, rerender(), close() }.

  var LLE_OTHER = "__other__";

  function lleNewEditor(setup) {
    return {
      setup: setup || "",
      name: "",
      from: "",
      certificate: "",
      leaves: [],
      catalogue: null,
      subjectOn: false,
      rows: [],
      extensionsOn: false,
      extensions: [],
      validity: "setup",
      curve: "setup",
      send: "setup",
      use: false,
      replace: false,
      text: "",
      textMode: false,
      draft: "",
      notice: null,
      busy: false,
      pending: null,
      loaded: false,
    };
  }

  function lleClone(value) {
    return JSON.parse(JSON.stringify(value === undefined ? null : value));
  }

  // Subject: the server's relative distinguished names (each a list of
  // attributes) against the editor's flat rows; "joined" marks an attribute
  // that shares its relative distinguished name with the row above.
  function lleFlattenSubject(subject) {
    var rows = [];
    (subject || []).forEach(function (rdn) {
      (rdn || []).forEach(function (attribute, index) {
        rows.push({
          oid: String(attribute.oid || ""),
          string: String(attribute.string || ""),
          value: String(attribute.value === undefined || attribute.value === null ? "" : attribute.value),
          hex: !!attribute.hex,
          joined: index > 0,
        });
      });
    });
    return rows;
  }

  function lleGroupSubject(rows) {
    var subject = [];
    (rows || []).forEach(function (row) {
      var attribute = { oid: row.oid, string: row.string, value: row.value, hex: !!row.hex };
      if (row.joined && subject.length > 0) {
        subject[subject.length - 1].push(attribute);
      } else {
        subject.push([attribute]);
      }
    });
    return subject;
  }

  function lleModel(editor) {
    return {
      subject: editor.subjectOn ? lleGroupSubject(editor.rows) : null,
      extensions: editor.extensionsOn ? editor.extensions.map(function (extension) {
        var row = { oid: extension.oid, critical: !!extension.critical, form: extension.form };
        if (extension.form === "raw") {
          row.text = String(extension.text || "");
        } else {
          row.items = extension.items;
        }
        return row;
      }) : null,
    };
  }

  function lleApplyAnswer(editor, data) {
    var model = (data && data.model) || {};
    if (data && data.catalogue) editor.catalogue = data.catalogue;
    if (data && Array.isArray(data.leaves)) editor.leaves = data.leaves;
    editor.subjectOn = Array.isArray(model.subject);
    editor.rows = lleFlattenSubject(model.subject);
    editor.extensionsOn = Array.isArray(model.extensions);
    editor.extensions = (model.extensions || []).map(function (extension) {
      return {
        oid: String(extension.oid || ""),
        name: String(extension.name || extension.oid || ""),
        critical: !!extension.critical,
        form: extension.form === "raw" ? "raw" : "typed",
        widget: extension.form === "raw" ? "raw" : String(extension.widget || "raw"),
        items: lleClone(extension.items),
        text: String(extension.text || ""),
      };
    });
    editor.text = String((data && data.text) || "");
    editor.draft = editor.text;
    editor.loaded = true;
  }

  function lleCatalogueRow(editor, oid) {
    var rows = (editor.catalogue && editor.catalogue.extensions) || [];
    for (var i = 0; i < rows.length; i += 1) {
      if (rows[i].oid === oid) return rows[i];
    }
    return null;
  }

  function lleAttributeInfo(editor, oid) {
    var rows = (editor.catalogue && editor.catalogue.attributes) || [];
    for (var i = 0; i < rows.length; i += 1) {
      if (rows[i].oid === oid) return rows[i];
    }
    return null;
  }

  function lleNewExtension(editor, oid) {
    var known = lleCatalogueRow(editor, oid);
    if (known && known.widget !== "raw") {
      return { oid: known.oid, name: known.name, critical: !!known.critical, form: "typed", widget: known.widget,
        items: lleClone(known.items), text: "" };
    }
    return { oid: known ? known.oid : "", name: known ? known.name : "", critical: false, form: "raw",
      widget: "raw", items: null, text: "" };
  }

  function lleMove(list, index, step) {
    var target = index + step;
    if (target < 0 || target >= list.length) return;
    var item = list[index];
    list[index] = list[target];
    list[target] = item;
  }

  async function llePost(ctx, inputs) {
    var resp;
    try {
      resp = await ctx.hooks.post("eim_local.tls_leaf_rows", inputs);
    } catch (err) {
      resp = { ok: false, error: String(err && err.message || err) };
    }
    return resp || { ok: false, error: "no answer" };
  }

  // Fill the editor from a leaf, a stored certificate or a text; with only
  // a setup, fetch its leaves and the catalogue and leave the rows alone.
  async function lleLoad(ctx, inputs, describe) {
    var editor = ctx.editor;
    if (editor.busy) {
      // A second pick while the first is read is kept and read next, so the rows end on the last pick.
      editor.pending = [inputs, describe];
      return;
    }
    editor.busy = true;
    var resp = await llePost(ctx, inputs);
    editor.busy = false;
    // Set whatever the answer: a failed first read must not be asked again by every redraw.
    editor.loaded = true;
    if (!resp.ok) {
      editor.notice = { tone: "fail", text: String(resp.error || "The certificate text could not be read.") };
    } else if (describe) {
      lleApplyAnswer(editor, resp.data);
      editor.notice = { tone: "ok", text: describe };
    } else {
      if (resp.data && resp.data.catalogue) editor.catalogue = resp.data.catalogue;
      editor.leaves = (resp.data && resp.data.leaves) || [];
    }
    if (editor.pending) {
      var next = editor.pending;
      editor.pending = null;
      await lleLoad(ctx, next[0], next[1]);
      return;
    }
    ctx.rerender();
  }

  // Rows to text through the server; resolves true when the rows read.
  async function lleCheck(ctx, quiet) {
    var editor = ctx.editor;
    var resp = await llePost(ctx, { model: JSON.stringify(lleModel(editor)) });
    if (!resp.ok) {
      editor.notice = { tone: "fail", text: String(resp.error || "The rows do not read.") };
      ctx.rerender();
      return false;
    }
    editor.text = String((resp.data && resp.data.text) || "");
    editor.draft = editor.text;
    if (!quiet) {
      editor.notice = { tone: "ok", text: editor.text
        ? "The rows read; the text below is what the leaf is issued from."
        : "Nothing is written, so the setup's options decide the subject and the extensions." };
      ctx.rerender();
    }
    return true;
  }

  // Text to rows. A text that does not read stays in the text view as typed, with the refusal above it.
  async function lleApplyText(ctx) {
    var editor = ctx.editor;
    if (editor.busy) return;
    editor.busy = true;
    var inputs = String(editor.draft).trim()
      ? { text: editor.draft }
      : { model: JSON.stringify({ subject: null, extensions: null }) };
    var resp = await llePost(ctx, inputs);
    editor.busy = false;
    if (!resp.ok) {
      editor.notice = { tone: "fail", text: String(resp.error || "The text does not read.") };
    } else {
      var draft = editor.draft;
      lleApplyAnswer(editor, resp.data);
      editor.textMode = false;
      editor.notice = { tone: "ok", text: String(draft).trim() ? "The text is in the rows." : "Cleared." };
    }
    ctx.rerender();
  }

  async function lleIssue(ctx) {
    var editor = ctx.editor;
    if (editor.busy) return;
    if (!editor.setup || !String(editor.name || "").trim()) {
      editor.notice = { tone: "fail", text: "Pick the TLS setup and name the leaf." };
      ctx.rerender();
      return;
    }
    editor.busy = true;
    ctx.rerender();
    var ok = await lleCheck(ctx, true);
    if (!ok) {
      editor.busy = false;
      ctx.rerender();
      return;
    }
    var resp;
    try {
      resp = await ctx.hooks.post("eim_local.tls_leaf_new", {
        setup: editor.setup,
        name: String(editor.name).trim(),
        text: editor.text,
        validity: editor.validity,
        curve: editor.curve,
        send: editor.send,
        use: !!editor.use,
        replace: !!editor.replace,
      });
    } catch (err) {
      resp = { ok: false, error: String(err && err.message || err) };
    }
    editor.busy = false;
    if (!resp || !resp.ok) {
      editor.notice = { tone: "fail", text: "Not issued: " + String(resp && resp.error || "unknown error") };
    } else {
      var lines = ((resp.data && resp.data.lines) || []).map(function (line) { return String(line).trim(); });
      editor.notice = { tone: "ok", text: lines.join("\n") };
      var issued = String(editor.name).trim();
      editor.leaves = editor.leaves.filter(function (leaf) { return leaf.name !== issued; })
        .map(function (leaf) { return { name: leaf.name, served: editor.use ? false : leaf.served }; })
        .concat([{ name: issued, served: !!editor.use }]);
    }
    ctx.rerender();
  }

  // -- controls ---------------------------------------------------------------

  function lleSelect(options, value, onChange, className) {
    var select = lepEl("select", className || "lep-input");
    options.forEach(function (entry) {
      var option = lepEl("option", "", entry[1]);
      option.value = entry[0];
      select.appendChild(option);
    });
    select.value = value;
    select.addEventListener("change", function () { onChange(select.value); });
    return select;
  }

  function lleInput(value, onInput, placeholder, className) {
    var input = lepEl("input", className || "lep-input");
    input.type = "text";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.value = value === undefined || value === null ? "" : String(value);
    if (placeholder) input.placeholder = placeholder;
    input.addEventListener("input", function () { onInput(input.value); });
    return input;
  }

  // A row's controls stand without a visible label; each gets its name for a screen reader.
  function lleNamed(control, labelText) {
    control.setAttribute("aria-label", labelText);
    return control;
  }

  function lleCheckbox(labelText, checked, onChange) {
    var label = lepEl("label", "lep-check lle-check");
    var box = lepEl("input");
    box.type = "checkbox";
    box.checked = !!checked;
    box.addEventListener("change", function () { onChange(box.checked); });
    label.appendChild(box);
    label.appendChild(lepEl("span", "", labelText));
    return label;
  }

  function lleField(labelText, control, helpText) {
    var wrap = lepEl("label", "lep-field");
    wrap.appendChild(lepEl("span", "lep-field-label", labelText));
    wrap.appendChild(control);
    if (helpText) wrap.appendChild(lepEl("span", "lep-field-help", helpText));
    return wrap;
  }

  // Move up, move down, remove: three small keys at the end of a row, named for a screen reader.
  function lleTool(glyph, labelText, onClick) {
    var button = lepButton(glyph, onClick);
    button.className += " lle-tool";
    button.title = labelText;
    button.setAttribute("aria-label", labelText);
    return button;
  }

  function lleRowTools(list, index, ctx) {
    var tools = lepEl("div", "lle-row-tools");
    var up = lleTool("\u2191", "Move up", function () { lleMove(list, index, -1); ctx.rerender(); });
    var down = lleTool("\u2193", "Move down", function () { lleMove(list, index, 1); ctx.rerender(); });
    up.disabled = index === 0;
    down.disabled = index === list.length - 1;
    tools.appendChild(up);
    tools.appendChild(down);
    tools.appendChild(lleTool("\u00d7", "Remove", function () { list.splice(index, 1); ctx.rerender(); }));
    return tools;
  }

  // -- subject ------------------------------------------------------------------

  function lleRenderSubject(root, ctx) {
    var editor = ctx.editor;
    var section = lepSection("Subject");
    section.tools.appendChild(lleCheckbox("Write the subject", editor.subjectOn, function (on) {
      editor.subjectOn = on;
      if (on && editor.rows.length === 0) {
        editor.rows = [{ oid: "2.5.4.3", string: "UTF8String", value: "{host}", hex: false, joined: false }];
      }
      ctx.rerender();
    }));
    if (!editor.subjectOn) {
      section.node.appendChild(lepEl("p", "lep-help",
        "Not written: the setup's own options name the leaf (its CN and layout)."));
      root.appendChild(section.node);
      return;
    }
    section.node.appendChild(lepEl("p", "lep-help",
      "One attribute per row, in the order the certificate encodes them; the one-line form reads the same rows "
      + "from the last to the first. {host} is the setup's eIM FQDN, {eim_id} the Local eIM's eimId."));
    var attributes = (editor.catalogue && editor.catalogue.attributes) || [];
    var stringTypes = (editor.catalogue && editor.catalogue.string_types) || [];
    var list = lepEl("div", "lle-rows");
    editor.rows.forEach(function (row, index) {
      var line = lepEl("div", "lle-row" + (row.joined ? " lle-row--joined" : ""));
      var known = lleAttributeInfo(editor, row.oid);
      var typeOptions = attributes.map(function (info) { return [info.oid, info.label]; });
      typeOptions.push([LLE_OTHER, "Other (object identifier)"]);
      line.appendChild(lleNamed(lleSelect(typeOptions, known ? row.oid : LLE_OTHER, function (value) {
        if (value === LLE_OTHER) {
          row.oid = "";
        } else {
          row.oid = value;
          var info = lleAttributeInfo(editor, value);
          if (info) row.string = info.string;
        }
        ctx.rerender();
      }, "lep-input lle-type"), "Attribute type"));
      if (!known) {
        line.appendChild(lleNamed(lleInput(row.oid, function (value) { row.oid = value.trim(); }, "2.5.4.x",
          "lep-input lle-oid"), "Attribute object identifier"));
      }
      var types = stringTypes.slice();
      if (row.string && types.indexOf(row.string) < 0) types.push(row.string);
      line.appendChild(lleNamed(lleSelect(types.map(function (name) { return [name, name]; }), row.string,
        function (value) { row.string = value; }, "lep-input lle-string"), "String type"));
      line.appendChild(lleNamed(lleInput(row.value, function (value) { row.value = value; },
        row.hex ? "hex" : "value", "lep-input lle-value"), "Attribute value"));
      if (index > 0) {
        line.appendChild(lleCheckbox("Same RDN as above", row.joined, function (on) {
          row.joined = on;
          ctx.rerender();
        }));
      }
      line.appendChild(lleRowTools(editor.rows, index, ctx));
      list.appendChild(line);
    });
    if (editor.rows.length === 0) {
      list.appendChild(lepEl("div", "lep-empty", "No attribute: the leaf gets an empty subject."));
    }
    section.node.appendChild(list);
    var bar = lepEl("div", "lep-inline-form-bar");
    bar.appendChild(lepButton("Add attribute", function () {
      editor.rows.push({ oid: "2.5.4.10", string: "UTF8String", value: "", hex: false, joined: false });
      ctx.rerender();
    }));
    section.node.appendChild(bar);
    root.appendChild(section.node);
  }

  // -- extension values ----------------------------------------------------------

  function lleChoiceSet(extension, known) {
    var body = lepEl("div", "lle-ext-body");
    var choices = (known && known.choices) || [];
    var items = Array.isArray(extension.items) ? extension.items : [];
    var lowered = choices.map(function (name) { return name.toLowerCase(); });
    var others = items.filter(function (name) { return lowered.indexOf(String(name).toLowerCase()) < 0; });
    function write(extra) {
      var picked = [];
      boxes.forEach(function (entry) { if (entry.box.checked) picked.push(entry.name); });
      String(extra === undefined ? otherInput.value : extra).split(",").forEach(function (part) {
        if (part.trim()) picked.push(part.trim());
      });
      extension.items = picked;
    }
    var checks = lepEl("div", "lle-checks");
    var boxes = [];
    var otherInput = lleInput(others.join(", "), function (value) { write(value); },
      "more object identifiers, comma separated", "lep-input lle-value");
    choices.forEach(function (name) {
      var label = lepEl("label", "lep-check lle-check");
      var box = lepEl("input");
      box.type = "checkbox";
      box.checked = items.some(function (item) { return String(item).toLowerCase() === name.toLowerCase(); });
      box.addEventListener("change", function () { write(); });
      label.appendChild(box);
      label.appendChild(lepEl("span", "", name));
      checks.appendChild(label);
      boxes.push({ box: box, name: name });
    });
    body.appendChild(checks);
    if (extension.oid === "2.5.29.37") {
      body.appendChild(lleField("Other purposes", otherInput));
    }
    return body;
  }

  function lleNameList(extension, known, ctx, withMethod) {
    var body = lepEl("div", "lle-ext-body");
    var kinds = (known && known.kinds) || ["DNS"];
    var methods = (known && known.methods) || [];
    if (!Array.isArray(extension.items)) extension.items = [];
    extension.items.forEach(function (entry, index) {
      var line = lepEl("div", "lle-row");
      if (withMethod) {
        var methodOptions = methods.map(function (name) { return [name, name]; });
        if (entry.method && methods.indexOf(entry.method) < 0) methodOptions.push([entry.method, entry.method]);
        line.appendChild(lleNamed(lleSelect(methodOptions, entry.method || methods[0] || "", function (value) {
          entry.method = value;
        }, "lep-input lle-type"), "Access method"));
      }
      line.appendChild(lleNamed(lleSelect(kinds.map(function (name) { return [name, name]; }), entry.kind || kinds[0],
        function (value) { entry.kind = value; }, "lep-input lle-string"), "Name form"));
      line.appendChild(lleNamed(lleInput(entry.value, function (value) { entry.value = value; }, "value",
        "lep-input lle-value"), "Name value"));
      line.appendChild(lleRowTools(extension.items, index, ctx));
      body.appendChild(line);
    });
    var bar = lepEl("div", "lep-inline-form-bar");
    bar.appendChild(lepButton("Add name", function () {
      var entry = { kind: kinds.indexOf("DNS") >= 0 ? "DNS" : kinds[0], value: "" };
      if (withMethod) {
        entry.method = methods[0] || "";
        entry.kind = kinds.indexOf("URI") >= 0 ? "URI" : entry.kind;
      }
      extension.items.push(entry);
      ctx.rerender();
    }));
    body.appendChild(bar);
    return body;
  }

  function lleBasic(extension) {
    var body = lepEl("div", "lle-ext-body lle-row");
    if (!extension.items || typeof extension.items !== "object") extension.items = { ca: false, pathlen: "" };
    body.appendChild(lleCheckbox("CA", extension.items.ca, function (on) { extension.items.ca = on; }));
    body.appendChild(lleField("Path length", lleInput(extension.items.pathlen, function (value) {
      extension.items.pathlen = value.trim();
    }, "none", "lep-input lle-string")));
    return body;
  }

  function lleKeyId(extension, known, ctx) {
    var body = lepEl("div", "lle-ext-body lle-row");
    var choices = (known && known.choices) || ["hash", "hex"];
    var keyword = choices[0];
    if (!extension.items || typeof extension.items !== "object") extension.items = { mode: keyword, hex: "" };
    var source = keyword === "keyid" ? "the issuer's key" : "the leaf's key";
    body.appendChild(lleNamed(lleSelect([[keyword, keyword + " (computed from " + source + ")"], ["hex", "these octets"]],
      extension.items.mode === "hex" ? "hex" : keyword, function (value) {
        extension.items.mode = value;
        ctx.rerender();
      }, "lep-input lle-keyid"), "Key identifier"));
    if (extension.items.mode === "hex") {
      body.appendChild(lleNamed(lleInput(extension.items.hex, function (value) {
        extension.items.hex = value.replace(/\s+/g, "");
      }, "hex", "lep-input lle-value"), "Key identifier octets in hex"));
    }
    return body;
  }

  function lleTextList(extension) {
    var body = lepEl("div", "lle-ext-body");
    var items = Array.isArray(extension.items) ? extension.items : [];
    body.appendChild(lleNamed(lleInput(items.join(", "), function (value) {
      extension.items = value.split(",").map(function (part) { return part.trim(); })
        .filter(function (part) { return part.length > 0; });
    }, "object identifiers, comma separated; anyPolicy", "lep-input lle-value"), "Policies"));
    return body;
  }

  function lleRaw(extension, known) {
    var body = lepEl("div", "lle-ext-body");
    var area = lepEl("textarea", "lep-input lle-textarea");
    area.rows = 2;
    area.spellcheck = false;
    area.placeholder = "the value's DER in hex";
    area.setAttribute("aria-label", "Value as DER in hex");
    area.value = String(extension.text || "");
    area.addEventListener("input", function () { extension.text = area.value.replace(/\s+/g, ""); });
    body.appendChild(area);
    if (known && known.note) {
      body.appendChild(lepEl("div", "lep-field-help", "Written as DER: " + known.note + "."));
    }
    return body;
  }

  function lleExtensionBody(extension, known, ctx) {
    if (extension.form === "raw" || extension.widget === "raw") return lleRaw(extension, known);
    if (extension.widget === "choice-set") return lleChoiceSet(extension, known);
    if (extension.widget === "name-list") return lleNameList(extension, known, ctx, false);
    if (extension.widget === "access-list") return lleNameList(extension, known, ctx, true);
    if (extension.widget === "basic") return lleBasic(extension);
    if (extension.widget === "key-id") return lleKeyId(extension, known, ctx);
    return lleTextList(extension);
  }

  function lleRenderExtensions(root, ctx) {
    var editor = ctx.editor;
    var section = lepSection("Extensions");
    section.tools.appendChild(lleCheckbox("Write the extensions", editor.extensionsOn, function (on) {
      editor.extensionsOn = on;
      ctx.rerender();
    }));
    if (!editor.extensionsOn) {
      section.node.appendChild(lepEl("p", "lep-help",
        "Not written: the setup's own options decide them (leaf name, registeredID, SubjectKeyIdentifier, "
        + "serverAuth, layout)."));
      root.appendChild(section.node);
      return;
    }
    section.node.appendChild(lepEl("p", "lep-help",
      "The leaf carries exactly these, in this order. hash and keyid are computed from the leaf's key and its "
      + "issuer's; a value given as DER is taken as it stands."));
    var present = {};
    editor.extensions.forEach(function (extension, index) {
      present[extension.oid] = true;
      var known = lleCatalogueRow(editor, extension.oid);
      var card = lepEl("div", "lle-ext");
      var head = lepEl("div", "lle-ext-head");
      var title = lepEl("div", "lle-ext-title");
      if (known) {
        title.appendChild(lepEl("span", "lle-ext-name", known.name));
        title.appendChild(lepEl("span", "lep-field-help", known.heading + ", RFC 5280 section " + known.clause));
      } else {
        title.appendChild(lleNamed(lleInput(extension.oid, function (value) {
          extension.oid = value.trim();
          extension.name = extension.oid;
        }, "object identifier", "lep-input lle-oid"), "Extension object identifier"));
      }
      head.appendChild(title);
      head.appendChild(lleCheckbox("Critical", extension.critical, function (on) { extension.critical = on; }));
      head.appendChild(lleRowTools(editor.extensions, index, ctx));
      card.appendChild(head);
      card.appendChild(lleExtensionBody(extension, known, ctx));
      section.node.appendChild(card);
    });
    if (editor.extensions.length === 0) {
      section.node.appendChild(lepEl("div", "lep-empty", "No extension: the leaf is issued without any."));
    }
    var options = [];
    ((editor.catalogue && editor.catalogue.extensions) || []).forEach(function (row) {
      if (!present[row.oid]) options.push([row.oid, row.name + (row.widget === "raw" ? " (DER)" : "")]);
    });
    options.push([LLE_OTHER, "Other (object identifier, DER)"]);
    var picked = options[0][0];
    var bar = lepEl("div", "lep-inline-form-bar");
    bar.appendChild(lleNamed(lleSelect(options, picked, function (value) { picked = value; },
      "lep-input lle-keyid"), "Extension to add"));
    bar.appendChild(lepButton("Add extension", function () {
      editor.extensions.push(lleNewExtension(editor, picked === LLE_OTHER ? "" : picked));
      ctx.rerender();
    }));
    section.node.appendChild(bar);
    root.appendChild(section.node);
  }

  // -- the view --------------------------------------------------------------------

  function lleRenderSource(root, ctx) {
    var editor = ctx.editor;
    var section = lepSection("Leaf");
    var grid = lepEl("div", "lep-form-grid");
    var setups = (ctx.setups || []).map(function (setup) {
      return [setup.name, setup.name + (setup.fqdn ? " - " + setup.fqdn : "")];
    });
    if (setups.length === 0) setups.push(["", "no TLS setup yet"]);
    grid.appendChild(lleField("TLS setup", lleSelect(setups, editor.setup, function (value) {
      editor.setup = value;
      editor.from = "";
      lleLoad(ctx, { setup: value }, "");
    }), "The leaf is signed by this setup's CA."));
    grid.appendChild(lleField("Leaf", lleInput(editor.name, function (value) { editor.name = value; }, "cn-eimid"),
      "The new leaf's name."));
    var leaves = [["", "nothing (blank)"]].concat((editor.leaves || []).map(function (leaf) {
      return [leaf.name, leaf.name + (leaf.served ? " (on the name)" : "")];
    }));
    grid.appendChild(lleField("Start from", lleSelect(leaves, editor.from, function (value) {
      editor.from = value;
      editor.certificate = "";
      if (value) {
        lleLoad(ctx, { setup: editor.setup, name: value }, "Loaded leaf " + value + " of " + editor.setup + ".");
      } else {
        lleLoad(ctx, { model: JSON.stringify({ subject: null, extensions: null }) }, "Cleared.");
      }
    }), "A leaf of the setup whose subject and extensions fill the rows."));
    var stored = lleInput(editor.certificate, function (value) { editor.certificate = value.trim(); }, "a stored name",
      "lep-input lle-value");
    var storedWrap = lepEl("div", "lle-row");
    storedWrap.appendChild(stored);
    storedWrap.appendChild(lepButton("Load", function () {
      if (!editor.certificate) return;
      editor.from = "";
      lleLoad(ctx, { certificate: editor.certificate }, "Loaded stored certificate " + editor.certificate + ".");
    }));
    grid.appendChild(lleField("Stored certificate", storedWrap,
      "Or start from a certificate in the eIM certificate store."));
    section.node.appendChild(grid);
    root.appendChild(section.node);
  }

  function lleRenderOptions(root, ctx) {
    var editor = ctx.editor;
    var section = lepSection("Leaf options");
    var grid = lepEl("div", "lep-form-grid");
    function choice(labelText, key, values) {
      grid.appendChild(lleField(labelText, lleSelect(values.map(function (name) { return [name, name]; }), editor[key],
        function (value) { editor[key] = value; })));
    }
    choice("Leaf validity", "validity", ["setup", "valid", "expired", "not_yet_valid"]);
    choice("Key", "curve", ["setup", "p256", "p384", "brainpoolp256r1", "ed25519"]);
    choice("Listener sends", "send", ["setup", "leaf", "chain", "full"]);
    section.node.appendChild(grid);
    var checks = lepEl("div", "lle-checks");
    checks.appendChild(lleCheckbox("Put it on the setup's name", editor.use, function (on) { editor.use = on; }));
    checks.appendChild(lleCheckbox("Replace a leaf of that name", editor.replace, function (on) { editor.replace = on; }));
    section.node.appendChild(checks);
    root.appendChild(section.node);
  }

  function lleRenderText(root, ctx) {
    var editor = ctx.editor;
    var section = lepSection("Certificate text");
    section.tools.appendChild(lepButton("Check", function () { lleCheck(ctx, false); }));
    section.tools.appendChild(lepButton(editor.textMode ? "Back to the rows" : "Edit as text", function () {
      if (editor.textMode) {
        editor.textMode = false;
        ctx.rerender();
        return;
      }
      // The text shown for editing is the rows as they stand now, not as they were last checked.
      lleCheck(ctx, true).then(function (ok) {
        if (!ok) return;
        editor.textMode = true;
        editor.draft = editor.text;
        editor.notice = null;
        ctx.rerender();
      });
    }));
    if (editor.textMode) {
      var area = lepEl("textarea", "lep-input lle-textarea lle-textarea--tall");
      area.spellcheck = false;
      area.setAttribute("aria-label", "Certificate text");
      area.value = editor.draft;
      area.addEventListener("input", function () { editor.draft = area.value; });
      section.node.appendChild(area);
      var bar = lepEl("div", "lep-inline-form-bar");
      bar.appendChild(lepButton("Apply text", function () { lleApplyText(ctx); }, true));
      section.node.appendChild(bar);
    } else {
      section.node.appendChild(lepEl("pre", "lep-hex lle-text",
        editor.text || "Nothing written yet. Check turns the rows into the text the leaf is issued from."));
    }
    root.appendChild(section.node);
  }

  function lleRender(root, ctx) {
    var editor = ctx.editor;
    var back = lepEl("button", "lep-back", "\u2190 eIM configuration");
    back.type = "button";
    back.addEventListener("click", function () { ctx.close(); });
    root.appendChild(back);
    var head = lepSection("Leaf editor");
    head.node.appendChild(lepEl("p", "lep-help",
      "Write a leaf's subject and extensions row by row and issue it under a TLS setup's CA. What is written is "
      + "built as written; what is left out follows the setup."));
    root.appendChild(head.node);
    if (editor.notice) {
      root.appendChild(lepEl("div", "lep-notice lle-notice lep-notice--" + editor.notice.tone, editor.notice.text));
    }
    lleRenderSource(root, ctx);
    lleRenderSubject(root, ctx);
    lleRenderExtensions(root, ctx);
    lleRenderOptions(root, ctx);
    lleRenderText(root, ctx);
    var bar = lepEl("div", "lep-inline-form-bar");
    var issue = lepButton(editor.busy ? "Issuing..." : "Issue leaf", function () { lleIssue(ctx); }, true);
    issue.disabled = !!editor.busy;
    bar.appendChild(issue);
    bar.appendChild(lepButton("Close", function () { ctx.close(); }));
    root.appendChild(bar);
    if (!editor.loaded && !editor.busy) {
      // The first draw fetches the catalogue and the setup's leaves, and the leaf the editor was opened on.
      if (editor.setup && editor.from) {
        lleLoad(ctx, { setup: editor.setup, name: editor.from },
          "Loaded leaf " + editor.from + " of " + editor.setup + ".");
      } else {
        lleLoad(ctx, { setup: editor.setup }, "");
      }
    }
  }
