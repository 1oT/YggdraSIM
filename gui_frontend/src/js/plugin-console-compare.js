  // -- Plugin consoles: comparison panel ----------------------------------------
  //
  // A console whose manifest declares `compare` sends the panel with every
  // status answer: sections of rows, one text cell per declared side and a
  // verdict the plugin decided (same, differs, missing, info). The server has
  // cut the answer to the declared sides and verdicts (plugin_console_output
  // compare_payload); the view builds it with createElement and textContent
  // and redraws only when the answer changed, so a poll that brings the same
  // comparison leaves the table and its scroll position alone.

  var PC_COMPARE_VERDICT_TEXT = {
    same: "same",
    differs: "differs",
    missing: "one side",
    info: "",
  };
  // Each section folds on its heading; a redraw keeps the sections as they
  // are on screen, and the folded ones are remembered per console.
  var PC_COMPARE_FOLD_KEY = "yggdrasim:pc-compare-folded:";

  function pcCompareFolded(consoleId) {
    // The section titles folded on the last visit; storage may be off or empty.
    try {
      var stored = window.localStorage.getItem(PC_COMPARE_FOLD_KEY + consoleId);
      var parsed = stored ? JSON.parse(stored) : [];
      return Array.isArray(parsed) ? parsed.map(String) : [];
    } catch (_err) {
      return [];
    }
  }

  function pcCompareRememberFold(consoleId, title, open) {
    var folded = pcCompareFolded(consoleId).filter(function (entry) { return entry !== title; });
    if (!open) folded.push(title);
    try {
      window.localStorage.setItem(PC_COMPARE_FOLD_KEY + consoleId, JSON.stringify(folded));
    } catch (_err) { /* storage off or full: the fold lasts for this page only */ }
  }

  function pcCompareSectionMeta(section) {
    var counts = pcCompareCounts([section]);
    var parts = [counts.rows + (counts.rows === 1 ? " row" : " rows")];
    if (counts.differs > 0) parts.push(counts.differs + " differ");
    if (counts.missing > 0) parts.push(counts.missing + " on one side");
    return parts.join(", ");
  }

  function pcCompareCounts(sections) {
    var counts = { rows: 0, differs: 0, missing: 0 };
    (Array.isArray(sections) ? sections : []).forEach(function (section) {
      (section && Array.isArray(section.rows) ? section.rows : []).forEach(function (row) {
        counts.rows += 1;
        if (row && row.verdict === "differs") counts.differs += 1;
        if (row && row.verdict === "missing") counts.missing += 1;
      });
    });
    return counts;
  }

  function pcCompareSummary(counts) {
    if (counts.rows === 0) return "nothing to compare yet";
    var parts = [];
    if (counts.differs > 0) parts.push(counts.differs + " differ");
    if (counts.missing > 0) parts.push(counts.missing + " on one side only");
    return parts.length > 0 ? parts.join(", ") : "all rows match";
  }

  function pcRenderCompareManifest(manifest) {
    var panel = $("pc-compare");
    if (!panel) return;
    pcState.compareSignature = "";
    var spec = manifest ? manifest.compare : null;
    panel.hidden = !spec;
    var body = $("pc-compare-body");
    if (body) body.textContent = "";
    setText("pc-compare-summary", "");
    var note = $("pc-compare-note");
    if (note) {
      note.hidden = true;
      note.textContent = "";
    }
    if (!spec) return;
    setText("pc-compare-title", spec.title || "Comparison");
    var hint = $("pc-compare-hint");
    if (hint) {
      hint.textContent = spec.hint || "";
      hint.hidden = !spec.hint;
    }
  }

  function pcCompareHeader(spec) {
    var head = document.createElement("thead");
    var row = document.createElement("tr");
    var labels = ["Item"].concat(spec.sides.map(function (side) { return side.label; }));
    labels.forEach(function (label) {
      var cell = document.createElement("th");
      cell.scope = "col";
      cell.textContent = label;
      row.appendChild(cell);
    });
    var verdict = document.createElement("th");
    verdict.scope = "col";
    verdict.className = "pc-compare-verdict";
    verdict.textContent = "Verdict";
    row.appendChild(verdict);
    head.appendChild(row);
    return head;
  }

  function pcCompareRow(spec, row) {
    var verdict = Object.prototype.hasOwnProperty.call(PC_COMPARE_VERDICT_TEXT, row.verdict) ? row.verdict : "info";
    var line = document.createElement("tr");
    line.className = "pc-compare-row pc-compare-row--" + verdict;
    var label = document.createElement("th");
    label.scope = "row";
    label.className = "pc-compare-label";
    label.textContent = String(row.label || "");
    line.appendChild(label);
    spec.sides.forEach(function (side) {
      var cell = document.createElement("td");
      cell.className = "pc-compare-cell";
      var text = row.cells ? row.cells[side.id] : "";
      cell.textContent = text === undefined || text === null || text === "" ? "-" : String(text);
      line.appendChild(cell);
    });
    var mark = document.createElement("td");
    mark.className = "pc-compare-verdict";
    mark.textContent = PC_COMPARE_VERDICT_TEXT[verdict];
    line.appendChild(mark);
    return line;
  }

  function pcRenderCompare(compare) {
    var manifest = pcState.manifest;
    var spec = manifest ? manifest.compare : null;
    var body = $("pc-compare-body");
    if (!spec || !body) return;
    var signature = compare ? JSON.stringify(compare) : "";
    if (signature === pcState.compareSignature) return;
    pcState.compareSignature = signature;
    var sections = compare && Array.isArray(compare.sections) ? compare.sections : [];
    setText("pc-compare-summary", pcCompareSummary(pcCompareCounts(sections)));
    var note = $("pc-compare-note");
    if (note) {
      var noteText = compare && compare.note ? String(compare.note) : "";
      note.textContent = noteText;
      note.hidden = noteText === "";
    }
    // A redraw keeps each section as it is on screen; a section drawn for the
    // first time opens unless it was folded on an earlier visit.
    var consoleId = pcState.activeId;
    var shown = {};
    body.querySelectorAll("details[data-pc-section]").forEach(function (box) {
      shown[box.getAttribute("data-pc-section")] = box.open;
    });
    var folded = pcCompareFolded(consoleId);
    body.textContent = "";
    sections.forEach(function (section) {
      if (!section) return;
      var title = String(section.title || "");
      var block = document.createElement("details");
      block.className = "pc-compare-section";
      block.setAttribute("data-pc-section", title);
      block.open = Object.prototype.hasOwnProperty.call(shown, title) ? shown[title] : folded.indexOf(title) < 0;
      var heading = document.createElement("summary");
      heading.className = "pc-compare-heading";
      var name = document.createElement("span");
      name.className = "pc-compare-heading-text";
      name.textContent = title;
      heading.appendChild(name);
      var meta = document.createElement("span");
      meta.className = "pc-compare-heading-meta";
      meta.textContent = pcCompareSectionMeta(section);
      heading.appendChild(meta);
      block.appendChild(heading);
      block.addEventListener("toggle", function () {
        pcCompareRememberFold(consoleId, title, block.open);
      });
      var scroll = document.createElement("div");
      scroll.className = "pc-compare-scroll";
      var table = document.createElement("table");
      table.className = "pc-compare-table";
      table.appendChild(pcCompareHeader(spec));
      var rows = document.createElement("tbody");
      (Array.isArray(section.rows) ? section.rows : []).forEach(function (row) {
        if (row) rows.appendChild(pcCompareRow(spec, row));
      });
      table.appendChild(rows);
      scroll.appendChild(table);
      block.appendChild(scroll);
      body.appendChild(block);
    });
  }
