// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

  // -- Per-reader tab persistence (localStorage) -------------------------
  //
  // Session tabs survive page reloads via ``localStorage``. Each reader
  // gets its own key (``ygg.scp03.tab.<readerName>``) so every pill on
  // the top-bar strip can remember the last tree, selection, FCP cache,
  // and APDU-console history independently. We deliberately do **not**
  // persist ``sessionId`` — those expire on backend restart. On restore,
  // the tab re-renders the cached tree + selection and surfaces a
  // "Resume session" button so the operator re-opens the secure channel
  // on demand instead of silently inheriting a stale ID.
  //
  // Size budget: ~50 FCP entries × ~4 KB each is the expected upper
  // bound; well under the 5 MB localStorage quota. We hard-cap to
  // ``SCP03_PERSIST_MAX_CACHE`` to keep a single overzealous scan from
  // blowing through the quota on cards with thousands of files.

  var SCP03_PERSIST_PREFIX = "ygg.scp03.tab.";
  var SCP03_PERSIST_VERSION = 1;
  var SCP03_PERSIST_MAX_CACHE = 50;

  function scp03PersistKey(readerName) {
    var name = String(readerName || "").trim();
    if (name.length === 0) return null;
    // "(default)" is a synthetic label for the first PC/SC reader when
    // no explicit name was requested. Persisting under that alias is
    // fine — each host boots with a predictable default-reader slot.
    return SCP03_PERSIST_PREFIX + name;
  }

  function scp03PersistTab(tab) {
    if (!tab || !tab.readerName) return;
    var key = scp03PersistKey(tab.readerName);
    if (!key) return;
    if (typeof localStorage === "undefined") return;
    try {
      var fcp = tab.fcpCache || {};
      var entries = Object.keys(fcp);
      if (entries.length > SCP03_PERSIST_MAX_CACHE) {
        // Cache is not ordered — sort by capturedAt desc and keep the
        // N freshest. Dropped entries just force a fresh read next
        // time the operator clicks that path; no correctness impact.
        entries.sort(function (a, b) {
          var ta = (fcp[a] && fcp[a].capturedAt) || 0;
          var tb = (fcp[b] && fcp[b].capturedAt) || 0;
          return tb - ta;
        });
        entries = entries.slice(0, SCP03_PERSIST_MAX_CACHE);
        var pruned = {};
        entries.forEach(function (k) { pruned[k] = fcp[k]; });
        fcp = pruned;
      }
      var payload = {
        v: SCP03_PERSIST_VERSION,
        savedAt: Date.now(),
        readerName: tab.readerName,
        atrHex: tab.atrHex || "",
        scanData: tab.scanData || null,
        selectedPath: tab.selectedPath || null,
        treeCollapsed: tab.treeCollapsed || {},
        previewCache: tab.previewCache || null,
        fcpCache: fcp,
        activeRibbonTab: tab.activeRibbonTab || "home",
        apduInputHex: tab.apduInputHex || "",
        apduFollow61: tab.apduFollow61 !== false,
        apduRetry6C: tab.apduRetry6C !== false,
        apduHistory: Array.isArray(tab.apduHistory)
          ? tab.apduHistory.slice(-20)
          : [],
      };
      localStorage.setItem(key, JSON.stringify(payload));
    } catch (_err) {
      // QuotaExceededError / serialisation hiccup. Persistence is a
      // nicety — we never want it to break the happy path. A single
      // oversized scan tree just means no save this round.
    }
  }

  function scp03LoadPersisted(readerName) {
    var key = scp03PersistKey(readerName);
    if (!key) return null;
    if (typeof localStorage === "undefined") return null;
    try {
      var raw = localStorage.getItem(key);
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      if (!parsed || parsed.v !== SCP03_PERSIST_VERSION) return null;
      return parsed;
    } catch (_err) {
      return null;
    }
  }

  function scp03HydrateTabFromPersisted(tab, persisted) {
    if (!tab || !persisted) return false;
    tab.readerName = persisted.readerName || tab.readerName || "";
    tab.atrHex = persisted.atrHex || "";
    tab.scanData = persisted.scanData || null;
    tab.selectedPath = persisted.selectedPath || null;
    tab.treeCollapsed = (persisted.treeCollapsed
      && typeof persisted.treeCollapsed === "object"
      && !Array.isArray(persisted.treeCollapsed))
      ? Object.assign({}, persisted.treeCollapsed)
      : {};
    tab.previewCache = persisted.previewCache || null;
    tab.fcpCache = persisted.fcpCache || {};
    tab.activeRibbonTab = persisted.activeRibbonTab || "home";
    tab.apduInputHex = persisted.apduInputHex || "";
    tab.apduFollow61 = persisted.apduFollow61 !== false;
    tab.apduRetry6C = persisted.apduRetry6C !== false;
    tab.apduHistory = Array.isArray(persisted.apduHistory)
      ? persisted.apduHistory.slice()
      : [];
    // ``sessionId`` stays null — the backend session didn't survive
    // the reload. ``status`` stays "idle" so the welcome panel (which
    // now renders a "Resume" button when scanData is present) appears
    // on first paint. ``errorKind`` is ephemeral (tied to the live
    // card state we don't yet know); start clean.
    tab.sessionId = null;
    tab.status = "idle";
    tab.error = null;
    tab.errorKind = "";
    tab.persistedAt = persisted.savedAt || 0;
    // Auth state is inherently session-bound — once ``sessionId`` is
    // cleared, the secure channel is gone. Reset the cache so the
    // first ``requires_auth`` action after rehydration prompts (or,
    // if the Resume flow calls ``scp03RefreshTabAuthStatus`` once the
    // new session opens, adopts the backend-reported state).
    scp03ClearTabAuth(tab);
    return true;
  }

  function scp03PurgePersisted(readerName) {
    var key = scp03PersistKey(readerName);
    if (!key) return;
    if (typeof localStorage === "undefined") return;
    try { localStorage.removeItem(key); } catch (_err) {}
  }

  function scp03HasPersistedState(tab) {
    // A hydrated tab is "has persisted state" when scanData survived
    // the reload. fcpCache alone isn't enough — the welcome panel
    // needs the tree to render the "Resume" preview.
    if (!tab) return false;
    if (tab.sessionId) return false;
    if (!tab.scanData) return false;
    var tree = tab.scanData.tree;
    return Array.isArray(tree) && tree.length > 0;
  }

  // -- FCP cache + auto-recovery -----------------------------------------
  //
  // Operators hit the "filesystem → other AID → filesystem" state
  // drift enough that the belt-and-suspenders pre-restore in
  // ``_dispatch_read_selected`` isn't always enough — some loaders
  // push the card into a state where SELECT-by-FID returns 6A82 until
  // the card is power-cycled. Rather than keep piling pre-restore
  // retries on the backend, the frontend now treats every read as
  // optimistic:
  //
  //   1. If we have a cached ``read_selected`` response for this
  //      path, render it **immediately** with a "refreshing…" chip.
  //      The user never stares at an empty preview pane during a
  //      context switch.
  //   2. Fire the fresh read in the background. On success, update
  //      the cache and repaint.
  //   3. On failure (``resp.ok === false`` or ``data.selected ===
  //      false``), flip to the recovery banner, call
  //      ``scp03RecoverSession`` (cold-reset + fs_controller.scan_tree
  //      rewalk, handled by the new ``scp03.recover_session`` backend
  //      action), then retry the read once. If the retry succeeds we
  //      promote the refreshed tree into ``tab.scanData`` so the tree
  //      view is consistent with the card.
  //   4. If the retry still fails, keep the cached render visible but
  //      paint the error banner above it so the operator sees "yes,
  //      this is stale" instead of a blank pane.
  //
  // The cache lives on the session tab (``tab.fcpCache``) and gets
  // wiped on rescan / reset / close — recovery within the same session
  // preserves it because that's the whole point.
  // Cap on how many decoded-FCP entries we keep per session tab. Each
  // entry holds the raw FCP TLV stream and a (potentially large) decoded
  // payload — without a bound the cache balloons over a long browsing
  // session, especially because we mirror it into ``localStorage``. The
  // cap is generous enough to cover a deep walk of MF + USIM + ISIM
  // (~80 EFs) without thrashing, and the LRU eviction prefers freshly
  // captured entries which are the most likely to be re-rendered.
  var SCP03_FCP_CACHE_MAX = 96;

  function scp03CacheStore(tab, path, data) {
    if (!tab || !path || !data) return;
    tab.fcpCache = tab.fcpCache || {};
    tab.fcpCache[path] = {
      data: data,
      capturedAt: Date.now(),
    };
    scp03CacheTrim(tab);
  }

  function scp03CacheLookup(tab, path) {
    if (!tab || !path || !tab.fcpCache) return null;
    var entry = tab.fcpCache[path];
    if (entry) {
      // Touch on read so the LRU keeps "recently consulted" entries
      // even when no new write is happening (e.g. operator hops back
      // to an old node from history).
      entry.capturedAt = Date.now();
    }
    return entry || null;
  }

  function scp03CacheTrim(tab) {
    if (!tab || !tab.fcpCache) return;
    var keys = Object.keys(tab.fcpCache);
    if (keys.length <= SCP03_FCP_CACHE_MAX) return;
    // Sort ascending by capturedAt — oldest first — and drop the
    // overflow. ``keys.length - cap`` is a small number in practice
    // (single digits) so the cost is negligible.
    keys.sort(function (a, b) {
      var aT = tab.fcpCache[a] && tab.fcpCache[a].capturedAt || 0;
      var bT = tab.fcpCache[b] && tab.fcpCache[b].capturedAt || 0;
      return aT - bT;
    });
    var dropCount = keys.length - SCP03_FCP_CACHE_MAX;
    for (var i = 0; i < dropCount; i++) {
      delete tab.fcpCache[keys[i]];
    }
  }

  function scp03FormatAge(ms) {
    if (!ms || ms < 0) return "";
    var seconds = Math.floor(ms / 1000);
    if (seconds < 5) return "just now";
    if (seconds < 60) return seconds + "s ago";
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + "m ago";
    var hours = Math.floor(minutes / 60);
    return hours + "h ago";
  }

  function scp03BuildCacheBanner(kind, label) {
    // ``kind`` is one of "refresh" | "recover" | "stale". Controls the
    // colour accent; the label carries the human-readable copy.
    var banner = document.createElement("div");
    banner.className = "cc-stale-chip cc-stale-chip--" + (kind || "refresh");
    banner.setAttribute("role", "status");
    banner.setAttribute("aria-live", "polite");
    var spinner = document.createElement("span");
    spinner.className = "cc-stale-chip-spinner";
    if (kind === "stale") {
      spinner.textContent = "\u26A0"; // warning triangle — static
    } else {
      spinner.textContent = "\u21BB"; // reload arrow — css-spun
    }
    banner.appendChild(spinner);
    var text = document.createElement("span");
    text.className = "cc-stale-chip-text";
    text.textContent = label;
    banner.appendChild(text);
    return banner;
  }

  function scp03RenderFromCache(tab, path, previewEl, kind, label) {
    // Drop in the cached FCP render, then prepend a status banner so
    // the operator knows the data is either being refreshed, being
    // recovered, or is outright stale.
    var cached = scp03CacheLookup(tab, path);
    previewEl.innerHTML = "";
    if (!cached) return false;
    var banner = scp03BuildCacheBanner(
      kind || "refresh",
      (label || "showing cached data") + " (captured "
        + scp03FormatAge(Date.now() - cached.capturedAt) + ")"
    );
    previewEl.appendChild(banner);
    renderFcpResult(cached.data, previewEl, tab);
    return true;
  }

  async function scp03DoReadSelected(tab, path) {
    // Bare read call. Returns ``{ok, data, error}`` — the caller
    // decides whether to promote a ``data.selected === false`` into
    // a recovery attempt.
    try {
      var resp = await apiFetch("/api/actions/scp03.read_selected/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: {
            session_id: tab.sessionId,
            path: path,
          },
        }),
      });
      return {
        ok: !!resp.ok,
        data: resp.data || null,
        error: resp.error || "",
      };
    } catch (err) {
      return {
        ok: false,
        data: null,
        error: String((err && err.message) || err),
      };
    }
  }

  async function scp03RecoverSession(tab) {
    // Invokes the backend ``scp03.recover_session`` dispatcher (cold
    // reset + rescan) and updates ``tab.scanData`` in place on
    // success so the file tree stays consistent with the card.
    // Returns ``{ok, error, noCard}`` — the caller chains the retry.
    if (!tab || !tab.sessionId) {
      return { ok: false, error: "no session to recover" };
    }
    try {
      var resp = await apiFetch("/api/actions/scp03.recover_session/run", {
        method: "POST",
        body: JSON.stringify({
          inputs: { session_id: tab.sessionId },
        }),
      });
      if (!resp.ok) {
        var rkind = scp03ClassifyError(resp.error);
        return {
          ok: false,
          error: resp.error || "recovery failed",
          noCard: rkind === "no_card",
        };
      }
      var data = resp.data || {};
      // Update the in-memory scan tree if the rewalk succeeded —
      // the tree view will re-render on the next paint. Keep the
      // ``session_id`` / ``atr_hex`` where they are (the session
      // handle is unchanged; only its underlying state was refreshed).
      if (data.scan_ok && data.tree) {
        tab.scanData = Object.assign({}, tab.scanData || {}, {
          tree: data.tree,
          scan_cache: data.scan_cache || {},
          atr_hex: data.atr_after_hex || (tab.scanData && tab.scanData.atr_hex) || "",
        });
        if (data.atr_after_hex) tab.atrHex = data.atr_after_hex;
        // Persist the refreshed tree so reloads after recovery come
        // back with the post-reset file system state.
        scp03PersistTab(tab);
      }
      tab.lastRecoverAt = Date.now();
      // The backend now surfaces a ``no_card`` flag when the reset
      // itself failed because the card was removed. Propagate that up
      // so the caller can short-circuit the retry (there's nothing to
      // retry against).
      return {
        ok: !!data.reset_ok,
        error: data.scan_error || data.reset_error || "",
        data: data,
        noCard: !!data.no_card,
      };
    } catch (err) {
      var text = String((err && err.message) || err);
      return {
        ok: false,
        error: text,
        noCard: scp03ClassifyError(text) === "no_card",
      };
    }
  }

  async function readSelectedForTab(tab, path, previewEl) {
    // Phase 1 — optimistic render from cache.
    //
    // If we've read this path before on this session, paint the
    // cached response instantly. The "refreshing…" banner tells
    // the operator the wire read is in-flight so they don't mistake
    // stale bytes for a live answer.
    var hadCache = scp03RenderFromCache(
      tab, path, previewEl, "refresh", "showing cached data — refreshing"
    );
    if (!hadCache) {
      previewEl.innerHTML = '<p class="loading">reading ' + escapeHtml(path) + "…</p>";
    }

    // Phase 2 — fresh read.
    var first = await scp03DoReadSelected(tab, path);
    var freshOk = first.ok && first.data && first.data.selected !== false;
    if (freshOk) {
      scp03CacheStore(tab, path, first.data);
      tab.previewCache = first.data;
      tab.selectedPath = path;
      previewEl.innerHTML = "";
      renderFcpResult(first.data, previewEl, tab);
      scp03PersistTab(tab);
      return;
    }
    // Classify the failure BEFORE deciding whether to trigger the
    // expensive recover-session path. "no_card" (reader is empty) and
    // "session_gone" (session_id was reaped) are both terminal: there's
    // nothing a cold reset + rescan can fix, and retrying just spams
    // PC/SC with the same failure for every click in the tree. Fall
    // through to a clean banner instead and keep any cached render
    // visible so the operator's context isn't lost.
    var errKind = scp03ClassifyError(first.error);

    logBus.emit({
      level: errKind ? "warn" : "warn",
      source: "scp03.read_selected",
      message: "fresh read failed for '" + path + "' — "
        + (first.error || "selected=false; see trace")
        + (errKind ? " [kind=" + errKind + "]" : ""),
    });

    if (errKind === "no_card" || errKind === "session_gone") {
      var friendlyText = errKind === "no_card"
        ? "card removed from reader — reinsert and re-scan"
        : "session expired — re-scan this tab to open a new one";
      if (hadCache) {
        scp03RenderFromCache(tab, path, previewEl, "stale",
          "showing cached data (stale) — " + friendlyText);
      } else {
        previewEl.innerHTML = "";
        previewEl.appendChild(renderErrorBlock(
          friendlyText + ".\n\nraw error: " + (first.error || "unknown")
        ));
      }
      // Mark the tab so the top-bar pill flips to red on the next
      // readerBarRender(). We deliberately don't drop the sessionId
      // for "no_card" — the operator might just be swapping a card,
      // and keeping the session means the next click re-reads against
      // the same manager entry rather than stranding it.
      tab.errorKind = errKind;
      if (errKind === "session_gone") {
        tab.sessionId = null;
        tab.status = "idle";
      }
      if (typeof readerBarNotifySessionChanged === "function") {
        readerBarNotifySessionChanged();
      }
      return;
    }

    // Phase 3 — auto-recovery (cold reset + rescan) and retry.
    //
    // This is the whole point of the cache layer: a failed read
    // against a drifted DF used to leave the preview empty and
    // the operator guessing. Now we keep the cached render (if any)
    // visible, swap the banner over to "recovering…", and hope the
    // card comes back clean enough for the retry.
    if (hadCache) {
      scp03RenderFromCache(
        tab, path, previewEl, "recover", "resetting card + rescanning tree"
      );
    } else {
      previewEl.innerHTML = "";
      previewEl.appendChild(scp03BuildCacheBanner(
        "recover", "read failed — resetting card + rescanning tree"
      ));
    }

    var recovery = await scp03RecoverSession(tab);
    // Short-circuit retry when the recovery itself confirmed the card
    // is gone — there is nothing productive to do until a card is
    // re-inserted. Surface the friendly "reinsert" banner instead of
    // a generic read-failed error and stamp the tab so the pill flips
    // red on the next repaint.
    if (recovery.noCard) {
      tab.errorKind = "no_card";
      if (hadCache) {
        scp03RenderFromCache(tab, path, previewEl, "stale",
          "showing cached data (stale) — card removed from reader, "
          + "reinsert and re-scan");
      } else {
        previewEl.innerHTML = "";
        previewEl.appendChild(renderErrorBlock(
          "card removed from reader — reinsert and re-scan.\n\n"
            + "raw error: " + (recovery.error || first.error || "unknown")
        ));
      }
      if (typeof readerBarNotifySessionChanged === "function") {
        readerBarNotifySessionChanged();
      }
      return;
    }
    if (!recovery.ok) {
      // Recovery itself failed — typically "no session" or a PC/SC
      // layer error. Fall through to the stale banner + error block.
      if (hadCache) {
        scp03RenderFromCache(
          tab, path, previewEl, "stale",
          "showing cached data (stale) — recovery failed: " + (recovery.error || "unknown")
        );
      } else {
        previewEl.innerHTML = "";
        previewEl.appendChild(renderErrorBlock(
          "read failed: " + (first.error || "unknown")
            + "\nrecovery failed: " + (recovery.error || "unknown")
        ));
      }
      return;
    }

    // Phase 4 — retry after recovery.
    var second = await scp03DoReadSelected(tab, path);
    var retryOk = second.ok && second.data && second.data.selected !== false;
    if (retryOk) {
      scp03CacheStore(tab, path, second.data);
      tab.previewCache = second.data;
      tab.selectedPath = path;
      previewEl.innerHTML = "";
      renderFcpResult(second.data, previewEl, tab);
      // Subtle reassurance banner: the card had to be reset to
      // answer the read. Operators like knowing when we intervened.
      var recoveredNote = scp03BuildCacheBanner(
        "refresh", "card was reset + rescanned to recover this read"
      );
      previewEl.insertBefore(recoveredNote, previewEl.firstChild);
      logBus.emit({
        level: "info",
        source: "scp03.read_selected",
        message: "recovered: '" + path + "' read after cold-reset + rescan",
      });
      scp03PersistTab(tab);
      return;
    }
    logBus.emit({
      level: "error",
      source: "scp03.read_selected",
      message: "retry after recovery failed for '" + path + "' — "
        + (second.error || "selected=false; see trace"),
    });

    // Phase 5 — give up gracefully. Keep cached render if we have one,
    // surface the error for forensics.
    if (hadCache) {
      scp03RenderFromCache(
        tab, path, previewEl, "stale",
        "showing cached data (stale) — retry after reset still failed"
      );
      var errBlock = renderErrorBlock(
        "retry failed: " + (second.error || "selected=false; see trace")
      );
      previewEl.appendChild(errBlock);
    } else {
      previewEl.innerHTML = "";
      previewEl.appendChild(renderErrorBlock(
        "read failed after reset + rescan: "
          + (second.error || "selected=false; see trace")
      ));
    }
  }

  // -- Scan rendering (shared across tabs) --------------------------------

  function renderScanResult(data, container) {
    // Back-compat entry point if scp03.scan is ever triggered outside the
    // workbench (e.g. from a legacy action card). Mirror the old UX.
    commandState.scp03Session = data.session_id || null;

    var header = document.createElement("div");
    header.className = "cc-scan-header";
    function addChip(label, value, asCode) {
      var chip = document.createElement("span");
      chip.className = "cc-chip";
      chip.appendChild(document.createTextNode(label + ": "));
      if (asCode) {
        var code = document.createElement("code");
        code.textContent = value;
        chip.appendChild(code);
      } else {
        chip.appendChild(document.createTextNode(value));
      }
      header.appendChild(chip);
    }
    addChip("reader", String(data.reader_name || "(default)"), false);
    addChip("atr", String(data.atr_hex || "(none)"), false);
    addChip("session", String(data.session_id || ""), true);
    container.appendChild(header);

    var layout = document.createElement("div");
    layout.className = "cc-scan-layout";
    var tree = document.createElement("div");
    tree.className = "cc-tree";
    installMaximizable(tree);
    tree.appendChild(renderTreeNodes(data.tree || [], {
      collapsed: {},
    }));
    layout.appendChild(tree);
    var preview = document.createElement("div");
    preview.className = "cc-scan-preview";
    installMaximizable(preview);
    var previewHint = document.createElement("p");
    previewHint.className = "hint";
    previewHint.textContent = "Click a node to SELECT it and read its FCP + body.";
    preview.appendChild(previewHint);
    layout.appendChild(preview);
    container.appendChild(layout);

    tree.addEventListener("click", function (event) {
      var row = event.target.closest(".cc-tree-row");
      if (!row) return;
      var path = row.getAttribute("data-path");
      if (!path) return;
      Array.from(tree.querySelectorAll(".cc-tree-row.active")).forEach(function (el) {
        el.classList.remove("active");
      });
      row.classList.add("active");
      var pseudoTab = { sessionId: commandState.scp03Session };
      readSelectedForTab(pseudoTab, path, preview);
    });
  }

  // Classify a scan-tree node by ETSI naming convention. ``fids.txt``
  // entries carry their type as the prefix of their name (``MF``,
  // ``ADF_USIM``, ``ADF.ISIM``, ``DF_TELECOM``, ``DF.GSM-ACCESS``,
  // ``EF_ICCID``, ``EF.IMSI``, etc.). The backend now ships a ``kind``
  // field on every node so we trust that first; the prefix walk stays
  // as a safety net for older sessions or hand-rolled fids.txt entries
  // that pre-date the field. Returning the ETSI type as the icon label
  // is the whole point of the fix — operators were seeing every
  // ``DF.*`` and any non-``ADF_`` ADF surfaced as an ``EF`` badge.
  function scp03ClassifyTreeNode(node) {
    var raw = String((node && node.kind) || "").toLowerCase();
    if (raw === "mf") return "MF";
    if (raw === "df") return "DF";
    if (raw === "adf") return "ADF";
    if (raw === "ef") return "EF";
    var name = String((node && node.name) || "").trim().toUpperCase();
    if (name === "MF") return "MF";
    if (name.indexOf("ADF_") === 0 || name.indexOf("ADF.") === 0) return "ADF";
    if (name.indexOf("DF_") === 0 || name.indexOf("DF.") === 0) return "DF";
    if (name.indexOf("EF_") === 0 || name.indexOf("EF.") === 0) return "EF";
    // Last-resort heuristic: a node that owns children must be a
    // directory of some kind. Single-file entries fall through as EF.
    if (node && node.children && node.children.length > 0) return "DF";
    return "EF";
  }

  function scp03TreeNodePath(node) {
    var value = node && (node.path || node.idx);
    if (value === undefined || value === null) return "";
    return String(value);
  }

  function scp03TreeNodeCollapseKey(node, path) {
    if (path) return path;
    var fallback = node && (node.fid || node.name || node.display_name);
    if (fallback === undefined || fallback === null) return "";
    return String(fallback);
  }

  function scp03TreeCollapseState(opts) {
    opts = opts || {};
    if (opts.tab) {
      if (!opts.tab.treeCollapsed
        || typeof opts.tab.treeCollapsed !== "object"
        || Array.isArray(opts.tab.treeCollapsed)) {
        opts.tab.treeCollapsed = {};
      }
      return opts.tab.treeCollapsed;
    }
    if (opts.collapsed
      && typeof opts.collapsed === "object"
      && !Array.isArray(opts.collapsed)) {
      return opts.collapsed;
    }
    return {};
  }

  function scp03TreeNodeCanCollapse(kindLabel, hasChildren) {
    return hasChildren
      && (kindLabel === "MF" || kindLabel === "DF" || kindLabel === "ADF");
  }

  function renderTreeNodes(nodes, opts) {
    opts = opts || {};
    if (!opts.treeCollapsed) {
      opts.treeCollapsed = scp03TreeCollapseState(opts);
    }
    var list = document.createElement("ul");
    list.className = "cc-tree-list";
    // Separate MF/DF from ADF roots with a visual divider.
    // ADFs are independent application roots — not children of MF.
    var mfDfNodes = [];
    var adfNodes = [];
    nodes.forEach(function (node) {
      var kind = (node.kind || "").toLowerCase();
      if (kind === "adf") {
        adfNodes.push(node);
      } else {
        mfDfNodes.push(node);
      }
    });
    function _buildNode(node) {
      var li = document.createElement("li");
      li.className = "cc-tree-node";
      var row = document.createElement("div");
      row.className = "cc-tree-row";
      var nodePath = scp03TreeNodePath(node);
      var nodeKey = scp03TreeNodeCollapseKey(node, nodePath);
      row.setAttribute("data-path", nodePath);
      var kindLabel = scp03ClassifyTreeNode(node);
      row.setAttribute("data-kind", kindLabel.toLowerCase());
      if (nodePath && (opts.selectedPath || (opts.tab && opts.tab.selectedPath)) === nodePath) {
        row.classList.add("active");
      }
      var hasChildren = Array.isArray(node.children) && node.children.length > 0;
      var canCollapse = scp03TreeNodeCanCollapse(kindLabel, hasChildren);
      var collapsed = canCollapse && opts.treeCollapsed[nodeKey] === true;
      var childList = null;
      if (canCollapse) {
        li.setAttribute("aria-expanded", collapsed ? "false" : "true");
        row.setAttribute("aria-expanded", collapsed ? "false" : "true");
        row.setAttribute("data-collapsible", "true");
        if (collapsed) li.classList.add("cc-tree-node--collapsed");
      }
      var caret = null;
      if (canCollapse) {
        caret = document.createElement("button");
        caret.type = "button";
        caret.className = "cc-tree-caret";
        caret.textContent = collapsed ? "\u25B8" : "\u25BE";
        caret.title = collapsed ? "Expand" : "Collapse";
        caret.setAttribute(
          "aria-label",
          (collapsed ? "Expand " : "Collapse ")
            + String(node.display_name || node.name || nodePath || kindLabel)
        );
        caret.addEventListener("click", function (event) {
          event.preventDefault();
          event.stopPropagation();
          var nextCollapsed = opts.treeCollapsed[nodeKey] !== true;
          if (nextCollapsed) {
            opts.treeCollapsed[nodeKey] = true;
          } else {
            delete opts.treeCollapsed[nodeKey];
          }
          li.classList.toggle("cc-tree-node--collapsed", nextCollapsed);
          li.setAttribute("aria-expanded", nextCollapsed ? "false" : "true");
          row.setAttribute("aria-expanded", nextCollapsed ? "false" : "true");
          caret.textContent = nextCollapsed ? "\u25B8" : "\u25BE";
          caret.title = nextCollapsed ? "Expand" : "Collapse";
          caret.setAttribute(
            "aria-label",
            (nextCollapsed ? "Expand " : "Collapse ")
              + String(node.display_name || node.name || nodePath || kindLabel)
          );
          if (childList) childList.hidden = nextCollapsed;
          if (opts.tab) scp03PersistTab(opts.tab);
        });
        row.appendChild(caret);
      } else {
        var spacer = document.createElement("span");
        spacer.className = "cc-tree-caret cc-tree-caret--leaf";
        row.appendChild(spacer);
      }
      var icon = document.createElement("span");
      icon.className = "cc-tree-icon cc-tree-icon--" + kindLabel.toLowerCase();
      icon.textContent = kindLabel;
      var name = document.createElement("span");
      name.className = "cc-tree-name";
      name.textContent = node.display_name || node.name;
      var fid = document.createElement("span");
      fid.className = "cc-tree-fid";
      fid.textContent = node.fid || "";
      row.appendChild(icon);
      row.appendChild(name);
      row.appendChild(fid);
      li.appendChild(row);
      if (hasChildren) {
        childList = renderTreeNodes(node.children, opts);
        if (collapsed) childList.hidden = true;
        li.appendChild(childList);
      }
      return li;
    }
    mfDfNodes.forEach(function (node) {
      list.appendChild(_buildNode(node));
    });
    if (adfNodes.length > 0) {
      var sep = document.createElement("li");
      sep.className = "cc-tree-sep";
      sep.textContent = "Applications (ADF)";
      list.appendChild(sep);
      adfNodes.forEach(function (node) {
        list.appendChild(_buildNode(node));
      });
    }
    return list;
  }
  // Expose for testing + DevTools poking — same pattern as the other
  // scp03 helpers.
  if (typeof window !== "undefined") {
    window.YggdraSimScp03ClassifyTreeNode = scp03ClassifyTreeNode;
  }

  // Classify a read_selected payload by selected-file kind.
  //
  // Returns one of the canonical kinds below, derived from the FCP
  // template flavour + structure byte (ETSI TS 102 221 §11.1.1.4.3 /
  // ISO 7816-4 §5.3.3.2 file descriptor). Callers use this to gate
  // which FS-Admin actions make sense on the currently-selected node:
  //
  //   "df"          — DF (MF counts as a DF). CREATE FILE is legal
  //                   *under* this node; record-scoped reads aren't.
  //   "application" — FCI (Application / Security Domain ADF). Treated
  //                   as a directory for CREATE purposes but surfaces a
  //                   softer warning — operators rarely create children
  //                   under a loaded application.
  //   "transparent" — EF Transparent. RESIZE and READ BINARY legal;
  //                   SEARCH RECORD rejected.
  //   "linear"      — EF Linear Fixed. RESIZE / SEARCH RECORD legal.
  //   "cyclic"      — EF Cyclic. RESIZE / SEARCH RECORD legal, but the
  //                   wizard copy points out that cyclic records are
  //                   write-through.
  //   "unknown"     — FCP parser could not decide (Unknown structure or
  //                   non-FCP/FCI template). All mutating actions stay
  //                   hidden behind an advisory rather than exposing a
  //                   footgun. The raw FCP editor stays reachable from
  //                   the APDU console.
  //
  // Also returns a short human-readable ``label`` so the header badge
  // can read "DF", "EF · linear", etc. without re-deriving it.
  function scp03ClassifyFile(data) {
    var fcp = (data && data.fcp) || {};
    var payload = (data && data.data) || {};
    var template = String(fcp.template || "").toUpperCase();
    var type = String(fcp.type || "").toLowerCase();
    var structure = String(fcp.structure || "").toLowerCase();
    var payloadKind = String(payload.kind || "").toLowerCase();

    // Directory detection. ETSI TS 102 221: byte-1 & 0x38 == 0x38 for
    // DF/MF (the FCP parser flags this as type='DF', structure='Tree').
    // MF is a DF at 3F00 — we don't distinguish in the action gate.
    if (type === "df") {
      return { kind: "df", label: "DF" };
    }

    // FCI applications (ADF for SD / applet). We split these from DFs
    // because CREATE under a live application is an advanced operation
    // and UICC loaders rarely want it — soft-warn instead of outright
    // disabling. Legal operation set still matches DF.
    if (template === "FCI" || type === "application/sd") {
      return { kind: "application", label: "ADF · application" };
    }

    // EF branches. The FCP's structure field is the source of truth;
    // payload.kind is a secondary hint when the FCP parser returns
    // 'Unknown' (happens on exotic cards).
    if (type === "ef") {
      if (structure.indexOf("transparent") === 0) {
        return { kind: "transparent", label: "EF · transparent" };
      }
      if (structure.indexOf("linear") === 0) {
        return { kind: "linear", label: "EF · linear fixed" };
      }
      if (structure.indexOf("cyclic") === 0) {
        return { kind: "cyclic", label: "EF · cyclic" };
      }
    }

    // Fallback when FCP parsing failed: the READ payload tells us enough
    // to classify between transparent and records, which is what the
    // matrix actually needs. "records" is slightly imprecise (linear vs
    // cyclic is unresolvable from the payload alone), but gating on it
    // as "linear" gives the right set of legal actions — SEARCH RECORD
    // works against both structures.
    if (payloadKind === "transparent") {
      return { kind: "transparent", label: "EF · transparent" };
    }
    if (payloadKind === "records") {
      return { kind: "linear", label: "EF · records" };
    }
    return { kind: "unknown", label: "unknown" };
  }

  // Per-file-kind availability matrix.
  //
  // Each entry is ``{ enabled: bool, reason: string }``. The reason
  // doubles as the ``title`` tooltip on disabled buttons so the
  // operator sees *why* an action is greyed out without guessing.
  // Standards anchors: ETSI TS 102 222 §6.3 / §6.4 / §6.5 for
  // CREATE / DELETE / RESIZE scope; ETSI TS 102 221 §11.1.11 for the
  // record ops; ETSI TS 102 221 §11.1.22 for SUSPEND UICC (card-wide,
  // not file-scoped — always enabled when a session is open).
  function scp03FsActionAvailability(kind) {
    var matrix = {
      create: { enabled: false, reason: "" },
      delete: { enabled: false, reason: "" },
      resize: { enabled: false, reason: "" },
      // ``update`` collapses UPDATE BINARY (transparent EFs) and
      // UPDATE RECORD (linear-fixed / cyclic EFs) under a single
      // header button. The wizard branches on ``kind`` so the form
      // shows record-number / data fields for record EFs and a
      // simple data-only field for transparent EFs.
      update: { enabled: false, reason: "", apdu: "" },
      activate: { enabled: false, reason: "" },
      deactivate: { enabled: false, reason: "" },
      terminate: { enabled: false, reason: "" },
      searchRecord: { enabled: false, reason: "" },
      suspend: { enabled: true, reason: "" },  // card-wide
    };

    if (kind === "df") {
      matrix.create = { enabled: true, reason: "CREATE FILE under this DF" };
      matrix.delete = { enabled: true,
        reason: "DELETE FILE — deletes a child of this DF (pick its FID in the wizard)" };
      matrix.resize = { enabled: false,
        reason: "RESIZE applies only to EFs — pick a transparent / linear / cyclic file first" };
      matrix.update = { enabled: false,
        reason: "UPDATE applies only to EFs — pick a transparent / linear / cyclic file first" };
      matrix.activate = { enabled: true, reason: "ACTIVATE this DF" };
      matrix.deactivate = { enabled: true, reason: "DEACTIVATE this DF" };
      matrix.terminate = { enabled: true,
        reason: "TERMINATE-DF — permanent, this DF and every child become unusable" };
      matrix.searchRecord = { enabled: false,
        reason: "SEARCH RECORD applies only to linear / cyclic EFs" };
      return matrix;
    }
    if (kind === "application") {
      matrix.create = { enabled: true,
        reason: "CREATE FILE under this ADF — review children carefully" };
      matrix.delete = { enabled: true, reason: "DELETE FILE under this application" };
      matrix.resize = { enabled: false, reason: "RESIZE applies only to EFs" };
      matrix.update = { enabled: false,
        reason: "UPDATE applies only to EFs — pick a transparent / linear / cyclic child first" };
      matrix.activate = { enabled: true, reason: "ACTIVATE this ADF" };
      matrix.deactivate = { enabled: true, reason: "DEACTIVATE this ADF" };
      matrix.terminate = { enabled: true,
        reason: "TERMINATE-DF — permanently disables this application" };
      matrix.searchRecord = { enabled: false,
        reason: "SEARCH RECORD applies only to linear / cyclic EFs" };
      return matrix;
    }
    if (kind === "transparent") {
      matrix.create = { enabled: false,
        reason: "CREATE FILE is issued under a DF — select MF / a DF / an ADF first" };
      matrix.delete = { enabled: true, reason: "DELETE this EF" };
      matrix.resize = { enabled: true, reason: "RESIZE this transparent EF" };
      matrix.update = { enabled: true, apdu: "binary",
        reason: "UPDATE BINARY (00D6) — overwrite this transparent EF's body" };
      matrix.activate = { enabled: true, reason: "ACTIVATE this EF" };
      matrix.deactivate = { enabled: true, reason: "DEACTIVATE this EF" };
      matrix.terminate = { enabled: true,
        reason: "TERMINATE-EF — permanent, this file becomes unusable" };
      matrix.searchRecord = { enabled: false,
        reason: "SEARCH RECORD applies only to linear / cyclic EFs — this is transparent" };
      return matrix;
    }
    if (kind === "linear" || kind === "cyclic") {
      var label = (kind === "linear") ? "linear fixed" : "cyclic";
      matrix.create = { enabled: false,
        reason: "CREATE FILE is issued under a DF — select MF / a DF / an ADF first" };
      matrix.delete = { enabled: true, reason: "DELETE this " + label + " EF" };
      matrix.resize = { enabled: true, reason: "RESIZE this " + label + " EF" };
      matrix.update = { enabled: true, apdu: "record",
        reason: "UPDATE RECORD (00DC) — overwrite a record in this " + label + " EF" };
      matrix.activate = { enabled: true, reason: "ACTIVATE this EF" };
      matrix.deactivate = { enabled: true, reason: "DEACTIVATE this EF" };
      matrix.terminate = { enabled: true,
        reason: "TERMINATE-EF — permanent, this file becomes unusable" };
      matrix.searchRecord = { enabled: true,
        reason: "SEARCH RECORD across this " + label + " EF's records" };
      return matrix;
    }
    // kind === "unknown" / no selection
    matrix.create.reason = "Pick a DF / ADF / MF in the tree first";
    matrix.delete.reason = "Pick a file in the tree first";
    matrix.resize.reason = "Pick an EF in the tree first";
    matrix.update.reason = "Pick a transparent / linear / cyclic EF in the tree first";
    matrix.activate.reason = "Pick a file in the tree first";
    matrix.deactivate.reason = "Pick a file in the tree first";
    matrix.terminate.reason = "Pick a file in the tree first";
    matrix.searchRecord.reason = "Pick a linear / cyclic EF in the tree first";
    return matrix;
  }

  function scp03MakeFsActionButton(spec) {
    // Compact pill button used in the header action bar. ``spec`` is
    // ``{label, title, danger, enabled, disabledReason, onClick}`` —
    // disabled buttons render as greyed-out-but-visible with a reason
    // tooltip so operators learn *why* without hunting through docs.
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "cc-fs-action-btn";
    if (spec.danger) btn.classList.add("is-danger");
    btn.textContent = spec.label;
    if (spec.enabled) {
      btn.title = spec.title || spec.label;
      btn.addEventListener("click", spec.onClick);
    } else {
      btn.classList.add("is-disabled");
      btn.disabled = true;
      btn.title = spec.disabledReason
        || "Not applicable to the currently-selected file.";
    }
    return btn;
  }

  function scp03BuildFsActionBar(tab, data) {
    // Renders the contextual FS-Admin button strip. Lives inside the
    // FCP header so its visibility is tied to the current selection;
    // repaints on every ``renderFcpResult`` call, which fires on each
    // tree click + cached-restore. The strip replaces the old Files
    // ribbon tab — each button hops into the existing wizard by
    // invoking ``scp03ShowFs*(tab)``, which renders into the extras
    // slot below the tree/preview layout.
    var bar = document.createElement("div");
    bar.className = "cc-fs-actions";
    bar.setAttribute("role", "toolbar");
    bar.setAttribute("aria-label", "File actions");

    var info = scp03ClassifyFile(data);
    var avail = scp03FsActionAvailability(info.kind);

    // Kind badge — makes the gating visible at a glance. Echoes the
    // human-readable label next to the fid chip so operators know
    // "yes, this is an EF · linear" without reading the FCP block.
    var kindChip = document.createElement("span");
    kindChip.className = "cc-chip cc-fs-kind cc-fs-kind--" + info.kind;
    kindChip.textContent = info.label;
    bar.appendChild(kindChip);

    // Guard: if the session or tab is missing, we still render the
    // kind chip but skip the actions — no-op buttons would be worse
    // than absent ones.
    if (!tab || !tab.sessionId) {
      var hint = document.createElement("span");
      hint.className = "cc-fs-actions-hint";
      hint.textContent = "open a session to run admin actions";
      bar.appendChild(hint);
      return bar;
    }

    // Every button below is an ETSI TS 102 222 admin APDU (CREATE
    // FILE / DELETE FILE / RESIZE / ACTIVATE / DEACTIVATE / TERMINATE
    // / SEARCH RECORD) or SUSPEND UICC — all require a live auth
    // session. ``scp03GateOpen`` noops for unflagged actions, so the
    // kind-based gating already provided by ``avail`` still decides
    // whether the button is clickable; the auth gate only fires once
    // the operator presses an enabled button.
    var createBtn = scp03MakeFsActionButton({
      label: "Create file",
      title: avail.create.reason,
      disabledReason: avail.create.reason,
      enabled: avail.create.enabled,
      onClick: scp03GateOpen(tab, "scp03.fs_create_file",
        function () { scp03ShowFsCreateFile(tab); }),
    });
    var deleteBtn = scp03MakeFsActionButton({
      label: "Delete",
      title: avail.delete.reason,
      disabledReason: avail.delete.reason,
      enabled: avail.delete.enabled,
      danger: true,
      onClick: scp03GateOpen(tab, "scp03.fs_delete_file",
        function () { scp03ShowFsDeleteFile(tab); }),
    });
    var resizeBtn = scp03MakeFsActionButton({
      label: "Resize",
      title: avail.resize.reason,
      disabledReason: avail.resize.reason,
      enabled: avail.resize.enabled,
      danger: true,
      onClick: scp03GateOpen(tab, "scp03.fs_resize",
        function () { scp03ShowFsResize(tab); }),
    });
    var lifecycleBtn = scp03MakeFsActionButton({
      label: "Lifecycle",
      title: (avail.activate.enabled || avail.terminate.enabled)
        ? "ACTIVATE / DEACTIVATE / TERMINATE for this node"
        : avail.activate.reason,
      disabledReason: avail.activate.reason,
      enabled: avail.activate.enabled || avail.deactivate.enabled
        || avail.terminate.enabled,
      onClick: scp03GateOpen(tab, "scp03.fs_lifecycle",
        function () { scp03ShowFsLifecycle(tab); }),
    });
    var searchBtn = scp03MakeFsActionButton({
      label: "Search rec.",
      title: avail.searchRecord.reason,
      disabledReason: avail.searchRecord.reason,
      enabled: avail.searchRecord.enabled,
      onClick: scp03GateOpen(tab, "scp03.fs_search_record",
        function () { scp03ShowFsSearchRecord(tab); }),
    });
    var suspendBtn = scp03MakeFsActionButton({
      label: "Suspend UICC",
      title: "SUSPEND UICC (8076) — card-wide low-power state",
      disabledReason: "Open a session first",
      enabled: avail.suspend.enabled,
      danger: true,
      onClick: scp03GateOpen(tab, "scp03.fs_suspend_uicc",
        function () { scp03ShowFsSuspendUicc(tab); }),
    });

    var group = document.createElement("div");
    group.className = "cc-fs-actions-group";
    group.appendChild(createBtn);
    group.appendChild(deleteBtn);
    group.appendChild(resizeBtn);
    group.appendChild(lifecycleBtn);
    group.appendChild(searchBtn);
    bar.appendChild(group);

    // SUSPEND UICC sits in its own micro-group — visually separated
    // so operators don't fat-finger it while clicking file-scoped
    // actions. It's a card-wide power command (ETSI TS 102 221 §11.1.22),
    // not file-scoped, so its gating is session-only, not kind-aware.
    var cardGroup = document.createElement("div");
    cardGroup.className = "cc-fs-actions-group cc-fs-actions-group--card";
    cardGroup.appendChild(suspendBtn);
    bar.appendChild(cardGroup);

    return bar;
  }

  function renderFcpResult(data, container, tab) {
    if (!data.selected) {
      container.appendChild(renderErrorBlock("SELECT failed for " + (data.path || "?")));
      if (data.select_trace) {
        var trace = document.createElement("pre");
        trace.className = "cc-json";
        trace.textContent = data.select_trace;
        container.appendChild(trace);
      }
      return;
    }
    var wrap = document.createElement("div");
    wrap.className = "cc-fcp-wrap";
    var header = document.createElement("div");
    header.className = "cc-fcp-header";
    var pathChip = document.createElement("span");
    pathChip.className = "cc-chip";
    pathChip.appendChild(document.createTextNode("path: "));
    var pathCode = document.createElement("code");
    pathCode.textContent = String(data.path || "");
    pathChip.appendChild(pathCode);
    header.appendChild(pathChip);
    var fidChip = document.createElement("span");
    fidChip.className = "cc-chip";
    fidChip.appendChild(document.createTextNode("fid: "));
    var fidCode = document.createElement("code");
    fidCode.textContent = String(data.fid || "");
    fidChip.appendChild(fidCode);
    header.appendChild(fidChip);
    wrap.appendChild(header);
    // Contextual FS-Admin bar — gated by the selected-file kind.
    // Relocated from the ribbon's Files tab per operator request so
    // the actions sit next to the fid badge they target. Only wired
    // when a tab is passed — preserves back-compat with the generic
    // action-result renderer (kind="fcp") that lacks session context.
    if (tab) {
      wrap.appendChild(scp03BuildFsActionBar(tab, data));
    }

    var fcp = data.fcp || {};
    var fcpKeys = Object.keys(fcp);
    if (fcpKeys.length > 0) {
      var fcpBlock = document.createElement("div");
      fcpBlock.className = "cc-fcp-block";
      var h4 = document.createElement("h4");
      h4.textContent = "FCP";
      fcpBlock.appendChild(h4);
      // Pretty view — type-aware, hex grouping, nested objects open
      // into their own dl. The toolbar gives operators a one-click
      // toggle to the raw JSON if they need byte-perfect output.
      var fcpPretty = document.createElement("dl");
      fcpPretty.className = "cc-fcp-fields cc-pv-object cc-pv-object--depth-0";
      fcpKeys.forEach(function (key) {
        var row = document.createElement("div");
        row.className = "cc-pv-field";
        var dt = document.createElement("dt");
        dt.className = "cc-pv-key";
        dt.textContent = key;
        var dd = document.createElement("dd");
        dd.className = "cc-pv-val";
        dd.appendChild(renderPrettyValue(fcp[key], 0));
        row.appendChild(dt);
        row.appendChild(dd);
        fcpPretty.appendChild(row);
      });
      var fcpJson = renderJsonBlock(fcp);
      fcpJson.hidden = true;
      fcpBlock.appendChild(buildDecodedToolbar(fcp, fcpPretty, fcpJson));
      fcpBlock.appendChild(fcpPretty);
      fcpBlock.appendChild(fcpJson);
      wrap.appendChild(fcpBlock);
    }

    var payload = data.data || {};
    var h4body = document.createElement("h4");
    h4body.textContent = "Body — " + (payload.kind || "?");
    wrap.appendChild(h4body);

    if (payload.kind === "none") {
      var note = document.createElement("p");
      note.className = "hint";
      note.textContent = payload.note || "No body.";
      wrap.appendChild(note);
    } else if (payload.kind === "transparent") {
      wrap.appendChild(renderTransparentPayload(payload, {
        path: data.path || "",
        fid: data.fid || "",
        tab: tab || null,
      }));
    } else if (payload.kind === "records") {
      wrap.appendChild(renderRecordsPayload(payload, {
        path: data.path || "",
        fid: data.fid || "",
        tab: tab || null,
      }));
    } else {
      // Unknown kind — render the raw payload for transparency.
      wrap.appendChild(renderDecodedBlock(payload, null, { omitHead: true }));
    }
    container.appendChild(wrap);
  }

  function scp03BuildPayloadUpdateButton(options) {
    var opts = options || {};
    var mode = opts.mode === "record" ? "record" : "binary";
    var tab = opts.tab || null;
    var rawHex = scp03StageHexNormalise(opts.hex || "");
    var pathText = String(opts.path || "").trim();
    var recordNo = Number(opts.record || 0);
    var button = document.createElement("button");
    button.type = "button";
    button.className = "cc-payload-update-btn";
    button.textContent = mode === "record" ? "Update record" : "Update body";
    button.title = mode === "record"
      ? "Open UPDATE RECORD with this record number and hex pre-filled."
      : "Open UPDATE BINARY with this EF body hex pre-filled.";
    if (!tab || !tab.sessionId || rawHex.length === 0) {
      button.disabled = true;
      button.title = !tab || !tab.sessionId
        ? "Open a session first."
        : "No bytes available to update.";
      return button;
    }
    button.addEventListener("click", function () {
      var actionId = mode === "record" ? "scp03.update_record" : "scp03.update_binary";
      var open = function () {
        if (mode === "record") {
          scp03StageOpenUpdateRecord(tab, rawHex, recordNo, pathText);
        } else {
          scp03StageOpenUpdateBinary(tab, rawHex, pathText);
        }
      };
      if (typeof scp03GateOpen === "function") {
        scp03GateOpen(tab, actionId, open)();
        return;
      }
      open();
    });
    return button;
  }

  function renderTransparentPayload(payload) {
    var sourceMeta = arguments.length > 1 ? arguments[1] : null;
    var box = document.createElement("div");
    box.className = "cc-payload cc-payload-transparent";
    var head = document.createElement("div");
    head.className = "cc-payload-head";
    var sw = document.createElement("p");
    sw.className = "cc-sw";
    sw.innerHTML = "SW: <code>" + escapeHtml(payload.sw || "") + "</code> · length "
      + String(payload.length || 0);
    head.appendChild(sw);
    head.appendChild(scp03BuildPayloadUpdateButton({
      mode: "binary",
      tab: sourceMeta && sourceMeta.tab ? sourceMeta.tab : null,
      path: sourceMeta && sourceMeta.path ? String(sourceMeta.path) : "",
      hex: payload.hex || "",
    }));
    box.appendChild(head);
    if (payload.decoded) {
      // Thread the raw EF body through to the decoded toolbar so the
      // service-table renderer can wire its "Stage edit" affordance —
      // staging needs both the current hex (to preserve sizing) and
      // the decoded checklist (so the popout can pre-tick the active
      // services without re-decoding client-side).
      box.appendChild(renderDecodedBlock(payload.decoded, {
        rawHex: payload.hex || "",
        path: sourceMeta && sourceMeta.path ? String(sourceMeta.path) : "",
        fid: sourceMeta && sourceMeta.fid ? String(sourceMeta.fid).toUpperCase() : "",
      }));
    }
    if (payload.hex) {
      box.appendChild(renderHexBlock(payload.hex));
    }
    return box;
  }

  function scp03IsRecordTerminator(rec) {
    // The READ RECORD loop in ``_read_file_body`` deliberately appends
    // the SW that terminated its walk (typically ``6A83`` = "record not
    // found", sometimes ``6A82`` / ``6A86``) so API consumers can audit
    // *why* the loop stopped. Those sentinels carry ``ok: false`` and
    // zero payload bytes — they're not file content, they're a loop
    // epilogue — so the file system view filters them out. The
    // ``stop_reason`` header chip ("stop: record_not_found") still
    // surfaces the information, just without a ghost row pretending to
    // be a record. Leaving the sentinel in the JSON (via ``payload.records``)
    // preserves byte-level parity with CLI dumps and keeps external
    // tooling that consumes the action response unbroken.
    if (!rec || typeof rec !== "object") return false;
    if (rec.ok === true) return false;
    var length = Number(rec.length || 0);
    if (length > 0) return false;
    var sw = String(rec.sw || "").toUpperCase();
    // Any SW starting with ``6A`` (wrong params: file/record boundary
    // hit) marks the end of the list. ``6Cxx`` was already corrected
    // in-place upstream, so any residual non-OK record with zero bytes
    // is a walker sentinel by definition.
    if (sw.length >= 2 && sw.substring(0, 2) === "6A") return true;
    return true;
  }

  function renderRecordsPayload(payload) {
    var sourceMeta = arguments.length > 1 ? arguments[1] : null;
    var box = document.createElement("div");
    box.className = "cc-payload cc-payload-records";

    var rawRecords = payload.records || [];
    var displayRecords = rawRecords.filter(function (rec) {
      return !scp03IsRecordTerminator(rec);
    });

    var meta = document.createElement("p");
    meta.className = "cc-records-meta";
    var bits = [];
    bits.push("records: " + displayRecords.length);
    // ``non_empty_count`` already excludes the terminator sentinel
    // (the backend only increments it for ``ok: true`` + non-F/00 rows),
    // so it's accurate as-is.
    bits.push("non-empty: " + (payload.non_empty_count || 0));
    bits.push("rec_len: " + (payload.rec_len || 0));
    bits.push("stop: " + (payload.stop_reason || "end"));
    meta.textContent = bits.join(" · ");
    box.appendChild(meta);

    if (displayRecords.length === 0) {
      var none = document.createElement("p");
      none.className = "hint";
      if (rawRecords.length > 0) {
        // File is present but unreadable — e.g. very first READ RECORD
        // returned 6A83. Surface the stop reason explicitly so the
        // operator doesn't see a silent blank.
        none.textContent = "no readable records (stop: "
          + (payload.stop_reason || "end") + ")";
      } else {
        none.textContent = "(no records)";
      }
      box.appendChild(none);
      return box;
    }
    var list = document.createElement("div");
    list.className = "cc-records";
    displayRecords.forEach(function (rec) {
      list.appendChild(renderSingleRecord(rec, payload, sourceMeta));
    });
    box.appendChild(list);
    if (payload.note) {
      var noteEl = document.createElement("p");
      noteEl.className = "hint";
      noteEl.textContent = payload.note;
      box.appendChild(noteEl);
    }
    return box;
  }

  function renderSingleRecord(rec, payload) {
    var sourceMeta = arguments.length > 2 ? arguments[2] : null;
    var card = document.createElement("details");
    card.className = "cc-record" + (rec.empty ? " cc-record--empty" : "");
    installMaximizable(card);
    // Start every record collapsed; the summary row carries enough
    // metadata (#N, SW/Empty, length, empty badge) to scan dozens of records
    // at a glance. Users can expand individual rows on demand.
    var sum = document.createElement("summary");
    sum.className = "cc-record-head";
    var num = document.createElement("span");
    num.className = "cc-record-num";
    num.textContent = "#" + (rec.record_number || 0);
    sum.appendChild(num);
    var sw = document.createElement("span");
    sw.className = "cc-record-sw";
    sw.textContent = rec.empty ? "Empty" : ("SW " + (rec.sw || "----"));
    sum.appendChild(sw);
    var len = document.createElement("span");
    len.className = "cc-record-len";
    len.textContent = (rec.length || 0) + " B";
    sum.appendChild(len);
    if (rec.empty) {
      var emptyBadge = document.createElement("span");
      emptyBadge.className = "cc-record-empty-badge";
      emptyBadge.textContent = "empty";
      sum.appendChild(emptyBadge);
    }
    card.appendChild(sum);

    if (rec.decoded) {
      card.appendChild(renderDecodedBlock(rec.decoded, {
        rawHex: rec.hex || "",
        path:
          (payload && payload.path ? String(payload.path) : "")
          || (sourceMeta && sourceMeta.path ? String(sourceMeta.path) : ""),
        fid:
          (payload && payload.fid ? String(payload.fid).toUpperCase() : "")
          || (sourceMeta && sourceMeta.fid ? String(sourceMeta.fid).toUpperCase() : ""),
        record: Number(rec.record_number || 0),
      }));
    }
    if (rec.hex) {
      var actions = document.createElement("div");
      actions.className = "cc-record-actions";
      actions.appendChild(scp03BuildPayloadUpdateButton({
        mode: "record",
        tab: sourceMeta && sourceMeta.tab ? sourceMeta.tab : null,
        path:
          (payload && payload.path ? String(payload.path) : "")
          || (sourceMeta && sourceMeta.path ? String(sourceMeta.path) : ""),
        record: Number(rec.record_number || 0),
        hex: rec.hex || "",
      }));
      card.appendChild(actions);
      card.appendChild(renderHexBlock(rec.hex));
    }
    return card;
  }

  function renderDecodedBlock(decoded, meta, options) {
    var opts = options || {};
    var wrap = document.createElement("div");
    wrap.className = "cc-decoded";
    if (!opts.omitHead) {
      var h = document.createElement("div");
      h.className = "cc-decoded-head";
      h.textContent = "decoded";
      wrap.appendChild(h);
    }

    // Service-table payloads bypass the generic dl walk and render
    // straight as a checklist — that path already handles ``active`` /
    // ``inactive`` columns, summary chip, and theme tints. We still
    // build the JSON view + toolbar so the operator can flip to the
    // raw payload for copy / inspection.
    var pretty;
    if (isServiceTablePayload(decoded)) {
      pretty = document.createElement("div");
      pretty.className = "cc-decoded-body cc-decoded-body--svc";
      pretty.appendChild(renderPrettyServiceTable(decoded));
    } else {
      // Polished view — type chips for primitives, byte-grouped hex
      // for hex-looking strings, nested dl for objects. Hidden raw-
      // JSON view is kept around so the operator can still grab a
      // copyable stringified payload from the toolbar without losing
      // context.
      pretty = document.createElement("dl");
      pretty.className = "cc-decoded-body cc-pv-object cc-pv-object--depth-0";
      var entries = decoded && typeof decoded === "object" && !Array.isArray(decoded)
        ? Object.entries(decoded)
        : [["value", decoded]];
      entries.forEach(function (pair) {
        var row = document.createElement("div");
        row.className = "cc-pv-field";
        var dt = document.createElement("dt");
        dt.className = "cc-pv-key";
        dt.textContent = String(pair[0]);
        var dd = document.createElement("dd");
        dd.className = "cc-pv-val";
        dd.appendChild(renderPrettyValue(pair[1], 0));
        row.appendChild(dt);
        row.appendChild(dd);
        pretty.appendChild(row);
      });
    }

    var json = renderJsonBlock(decoded);
    json.classList.add("cc-decoded-json-full");
    json.hidden = true;

    wrap.appendChild(buildDecodedToolbar(decoded, pretty, json, meta || null));
    wrap.appendChild(pretty);
    wrap.appendChild(json);
    return wrap;
  }

  // -- Explicit maximize support -----------------------------------------

  var maxState = {
    active: null,
    previousParent: null,
    previousNextSibling: null,
    backdrop: null,
    keyHandler: null,
  };

  function installMaximizable(el) {
    if (!el || el.__ccMaxBound) return;
    el.__ccMaxBound = true;
  }

  function toggleMaximize(el) {
    if (maxState.active === el) {
      restoreMaximized();
      return;
    }
    if (maxState.active) {
      restoreMaximized();
    }
    enterMaximized(el);
  }

  function enterMaximized(el) {
    var backdrop = document.createElement("div");
    backdrop.className = "cc-max-backdrop";
    backdrop.addEventListener("click", function (event) {
      if (event.target === backdrop) {
        restoreMaximized();
      }
    });

    var shell = document.createElement("div");
    shell.className = "cc-max-shell";

    var bar = document.createElement("div");
    bar.className = "cc-max-bar";
    var hint = document.createElement("span");
    hint.className = "cc-max-hint";
    hint.textContent = "Esc to restore";
    bar.appendChild(hint);
    var closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "btn";
    closeBtn.textContent = "Restore";
    closeBtn.addEventListener("click", function () {
      restoreMaximized();
    });
    bar.appendChild(closeBtn);
    shell.appendChild(bar);

    maxState.previousParent = el.parentNode;
    maxState.previousNextSibling = el.nextSibling;
    maxState.active = el;
    maxState.backdrop = backdrop;

    el.classList.add("cc-max-mounted");
    shell.appendChild(el);
    backdrop.appendChild(shell);
    document.body.appendChild(backdrop);

    maxState.keyHandler = function (event) {
      if (event.key === "Escape") {
        restoreMaximized();
      }
    };
    document.addEventListener("keydown", maxState.keyHandler);
  }

  function restoreMaximized() {
    var el = maxState.active;
    var backdrop = maxState.backdrop;
    if (el && maxState.previousParent) {
      el.classList.remove("cc-max-mounted");
      if (maxState.previousNextSibling && maxState.previousNextSibling.parentNode === maxState.previousParent) {
        maxState.previousParent.insertBefore(el, maxState.previousNextSibling);
      } else {
        maxState.previousParent.appendChild(el);
      }
    }
    if (backdrop && backdrop.parentNode) {
      backdrop.parentNode.removeChild(backdrop);
    }
    if (maxState.keyHandler) {
      document.removeEventListener("keydown", maxState.keyHandler);
    }
    maxState.active = null;
    maxState.previousParent = null;
    maxState.previousNextSibling = null;
    maxState.backdrop = null;
    maxState.keyHandler = null;
  }

  // -- Log bus (G-1) -------------------------------------------------------
  //
  // Cross-component event bus. Action runs (sync + streaming), live-reader
  // probes, and any future panel can publish rows here without knowing
  // anything about the bottom-dock UI. The dock subscribes once and
  // renders. Tabs map level → bucket: info/done/debug → messages,
  // warn → warnings, error → errors, apdu → apdu.

  var logBus = (function () {
    // Per-bucket caps. APDU gets a much larger ring than the human
    // buckets because operators explicitly asked for every APDU
    // issued during a session to stay visible (no throttling). 5000
    // rows is comfortably above any single-flow run and still well
    // below the point where DOM insertion becomes a noticeable
    // bottleneck on Qt WebEngine / Chromium.
    var MAX_PER_BUCKET = {
      messages: 500,
      warnings: 500,
      errors: 500,
      apdu: 5000,
    };
    var DEFAULT_CAP = 500;
    var subscribers = [];
    var rows = {
      messages: [],
      warnings: [],
      errors: [],
      apdu: [],
    };
    var nextId = 1;

    function bucketFor(level) {
      var key = String(level || "info").toLowerCase();
      if (key === "warn" || key === "warning") return "warnings";
      if (key === "error" || key === "fatal") return "errors";
      if (key === "apdu" || key === "trace") return "apdu";
      return "messages";
    }

    function emit(entry) {
      var ts = entry && entry.ts ? entry.ts : new Date();
      var row = {
        id: nextId++,
        ts: ts,
        level: String((entry && entry.level) || "info"),
        source: String((entry && entry.source) || "system"),
        message: String((entry && entry.message) || ""),
        data: entry && entry.data,
      };
      var bucket = bucketFor(row.level);
      rows[bucket].push(row);
      var cap = MAX_PER_BUCKET[bucket] || DEFAULT_CAP;
      if (rows[bucket].length > cap) {
        rows[bucket].shift();
      }
      subscribers.forEach(function (fn) {
        try {
          fn({ type: "append", bucket: bucket, row: row });
        } catch (_err) { /* never let a broken listener block the bus */ }
      });
      try { setStatusActivity(formatTime(row.ts)); } catch (_err) {}
    }

    function clear(bucket) {
      if (bucket && rows[bucket]) {
        rows[bucket] = [];
      } else {
        rows.messages = [];
        rows.warnings = [];
        rows.errors = [];
        rows.apdu = [];
      }
      subscribers.forEach(function (fn) {
        try { fn({ type: "clear", bucket: bucket || null }); } catch (_err) {}
      });
    }

    function snapshot(bucket) {
      return rows[bucket] ? rows[bucket].slice() : [];
    }

    function counts() {
      return {
        messages: rows.messages.length,
        warnings: rows.warnings.length,
        errors: rows.errors.length,
        apdu: rows.apdu.length,
      };
    }

    function subscribe(fn) {
      subscribers.push(fn);
      return function unsubscribe() {
        var i = subscribers.indexOf(fn);
        if (i >= 0) subscribers.splice(i, 1);
      };
    }

    return {
      emit: emit,
      clear: clear,
      snapshot: snapshot,
      counts: counts,
      subscribe: subscribe,
      bucketFor: bucketFor,
    };
  })();

  function formatTime(date) {
    var d = (date instanceof Date) ? date : new Date(date);
    var hh = String(d.getHours()).padStart(2, "0");
    var mm = String(d.getMinutes()).padStart(2, "0");
    var ss = String(d.getSeconds()).padStart(2, "0");
    return hh + ":" + mm + ":" + ss;
  }

  // Expose for tests / future modules. Keep it under a namespaced key so
  // we don't pollute the global object.
  window.YggdraSimLogBus = logBus;

  // -- Native path picker (pywebview bridge) ------------------------------
  //
  // When running under --gui, pywebview injects ``window.pywebview.api``
  // with our ``_PywebviewJsBridge`` methods. Those calls are async and
  // return Promises. In --web-server / plain-browser mode the bridge is
  // absent; callers fall back to the themed in-browser explorer so
  // nothing silently breaks.

  var pathPicker = {
    isAvailable: function () {
      return !!(window.pywebview && window.pywebview.api
        && typeof window.pywebview.api.pick_file === "function");
    },
    useNativeDialog: async function () {
      if (!pathPicker.isAvailable()) return false;
      var api = window.pywebview.api;
      if (api && typeof api.file_picker_mode === "function") {
        try {
          var mode = String(await api.file_picker_mode() || "").trim().toLowerCase();
          if (mode === "web") return false;
        } catch (_err) { return true; }
      }
      return true;
    },
    pickFile: async function (opts) {
      var o = opts || {};
      if (await pathPicker.useNativeDialog()) {
        try {
          var chosen = await window.pywebview.api.pick_file(
            String(o.defaultPath || ""),
            Array.isArray(o.fileTypes) ? o.fileTypes : [],
            !!o.allowMultiple
          );
          return (chosen == null) ? "" : String(chosen);
        } catch (_err) { return ""; }
      }
      return openFsExplorer({
        mode: "open",
        title: "Open file",
        defaultPath: o.defaultPath || "",
        fileTypes: Array.isArray(o.fileTypes) ? o.fileTypes : [],
      });
    },
    pickFolder: async function (opts) {
      var o = opts || {};
      if (await pathPicker.useNativeDialog()) {
        try {
          var chosen = await window.pywebview.api.pick_folder(
            String(o.defaultPath || "")
          );
          return (chosen == null) ? "" : String(chosen);
        } catch (_err) { return ""; }
      }
      return openFsExplorer({
        mode: "folder",
        title: "Pick folder",
        defaultPath: o.defaultPath || "",
      });
    },
    saveFile: async function (opts) {
      var o = opts || {};
      if (await pathPicker.useNativeDialog()) {
        try {
          var chosen = await window.pywebview.api.save_file(
            String(o.defaultPath || ""),
            String(o.saveFilename || ""),
            Array.isArray(o.fileTypes) ? o.fileTypes : []
          );
          return (chosen == null) ? "" : String(chosen);
        } catch (_err) { return ""; }
      }
      return openFsExplorer({
        mode: "save",
        title: "Save as",
        defaultPath: o.defaultPath || "",
        saveFilename: o.saveFilename || "",
        fileTypes: Array.isArray(o.fileTypes) ? o.fileTypes : [],
      });
    },
    _promptFallback: function (label, defaultValue) {
      // Kept around as a last-resort escape hatch for environments
      // where the /api/fs/browse endpoint is unreachable (e.g. when
      // running the frontend against a stripped backend in tests).
      try {
        var v = window.prompt(label + " (no native picker available):", defaultValue || "");
        return (v == null) ? "" : String(v);
      } catch (_err) { return ""; }
    },
  };

  // ---------------------------------------------------------------------
  // In-browser fallback file explorer
  // ---------------------------------------------------------------------
  //
  // When pywebview is absent (web-server mode, headless dev runs,
  // browser previews) we used to surface a bare ``window.prompt`` which
  // forced the operator to hand-type absolute paths. The fallback now
  // drives the read-only ``/api/fs/browse`` endpoint to render a
  // proper modal explorer: shortcuts sidebar (home / cwd / workspace /
  // Documents / Downloads / Desktop), breadcrumb path bar, dir + file
  // listing, type-to-filter, and an editable path field that doubles
  // as the "save filename" input in save mode.

  function _fsExplorerExtractExts(fileTypes) {
    // Pywebview's filter strings are shaped like:
    //   "SAIP profile (*.der;*.bin;*.json)"
    //   "All files (*.*)"
    // We pull out the bare extensions (".der" / ".bin" / ...) so the
    // SPA picker can pre-filter the listing to known-good rows.
    var exts = {};
    (fileTypes || []).forEach(function (raw) {
      var match = /\(([^)]+)\)/.exec(String(raw || ""));
      if (!match) return;
      match[1].split(/[;,\s]+/).forEach(function (token) {
        var clean = token.trim().toLowerCase();
        if (clean.length === 0) return;
        if (clean === "*.*" || clean === "*") {
          exts["*"] = true;
          return;
        }
        if (clean.indexOf("*.") === 0) clean = clean.substring(1);
        if (clean.indexOf(".") !== 0) clean = "." + clean;
        exts[clean] = true;
      });
    });
    return exts;
  }

  function _fsExplorerFormatBytes(size) {
    var n = Number(size || 0);
    if (!isFinite(n) || n <= 0) return "";
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
    return (n / 1073741824).toFixed(2) + " GB";
  }

  function _fsExplorerFormatTime(secs) {
    var n = Number(secs || 0);
    if (!isFinite(n) || n <= 0) return "";
    var d = new Date(n * 1000);
    return d.toLocaleString();
  }

  function _fsExplorerIcon(kind, name) {
    if (kind === "dir") return "\u2632";  // ☲ — three lines, dir
    if (kind === "symlink") return "\u21AA";  // ↪
    return "\u2317";  // ⌗ — leaf icon for files
  }

  function _fsExplorerJoin(parent, name, sep) {
    var s = String(sep || "/");
    if (!parent) return name;
    if (parent.charAt(parent.length - 1) === s) return parent + name;
    return parent + s + name;
  }

  function openFsExplorer(opts) {
    var o = opts || {};
    var mode = String(o.mode || "open");  // "open" | "folder" | "save"
    var titleText = String(o.title || (mode === "folder"
      ? "Pick folder"
      : (mode === "save" ? "Save as" : "Open file")));
    var allowedExts = _fsExplorerExtractExts(o.fileTypes || []);
    var defaultSaveName = String(o.saveFilename || "");

    return new Promise(function (resolve) {
      var settled = false;
      function settle(value) {
        if (settled) return;
        settled = true;
        try {
          if (overlay && overlay.parentNode) {
            overlay.parentNode.removeChild(overlay);
          }
        } catch (_err) { /* noop */ }
        document.removeEventListener("keydown", onKey, true);
        resolve(value || "");
      }

      var overlay = document.createElement("div");
      overlay.className = "cc-fs-explorer-overlay";
      overlay.setAttribute("role", "dialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.setAttribute("aria-label", titleText);
      overlay.addEventListener("click", function (ev) {
        if (ev.target === overlay) settle("");
      });

      var modal = document.createElement("div");
      modal.className = "cc-fs-explorer";
      overlay.appendChild(modal);

      // Header
      var header = document.createElement("div");
      header.className = "cc-fs-explorer-head";
      var titleEl = document.createElement("div");
      titleEl.className = "cc-fs-explorer-title";
      titleEl.textContent = titleText;
      header.appendChild(titleEl);
      var closeBtn = document.createElement("button");
      closeBtn.type = "button";
      closeBtn.className = "cc-fs-explorer-close";
      closeBtn.textContent = "\u00D7";
      closeBtn.title = "Cancel (Esc)";
      closeBtn.addEventListener("click", function () { settle(""); });
      header.appendChild(closeBtn);
      modal.appendChild(header);

      // Path bar
      var pathRow = document.createElement("div");
      pathRow.className = "cc-fs-explorer-pathrow";
      var upBtn = document.createElement("button");
      upBtn.type = "button";
      upBtn.className = "btn btn-secondary cc-fs-explorer-up";
      upBtn.textContent = "\u2191 Up";
      upBtn.title = "Go up one level";
      pathRow.appendChild(upBtn);
      var pathInput = document.createElement("input");
      pathInput.type = "text";
      pathInput.className = "cc-fs-explorer-path";
      pathInput.placeholder = "Type a path and press Enter";
      pathRow.appendChild(pathInput);
      var goBtn = document.createElement("button");
      goBtn.type = "button";
      goBtn.className = "btn btn-secondary";
      goBtn.textContent = "Go";
      pathRow.appendChild(goBtn);
      modal.appendChild(pathRow);

      // Body: sidebar + listing
      var body = document.createElement("div");
      body.className = "cc-fs-explorer-body";
      modal.appendChild(body);

      var sidebar = document.createElement("div");
      sidebar.className = "cc-fs-explorer-sidebar";
      body.appendChild(sidebar);

      var listingHost = document.createElement("div");
      listingHost.className = "cc-fs-explorer-listing-host";
      body.appendChild(listingHost);

      var filterRow = document.createElement("div");
      filterRow.className = "cc-fs-explorer-filterrow";
      var filterInput = document.createElement("input");
      filterInput.type = "text";
      filterInput.className = "cc-fs-explorer-filter";
      filterInput.placeholder = "Filter visible entries\u2026";
      filterRow.appendChild(filterInput);
      var hiddenToggle = document.createElement("label");
      hiddenToggle.className = "cc-fs-explorer-hidden-toggle";
      var hiddenCb = document.createElement("input");
      hiddenCb.type = "checkbox";
      hiddenToggle.appendChild(hiddenCb);
      hiddenToggle.appendChild(document.createTextNode(" show hidden"));
      filterRow.appendChild(hiddenToggle);
      listingHost.appendChild(filterRow);

      var listingEl = document.createElement("ul");
      listingEl.className = "cc-fs-explorer-list";
      listingHost.appendChild(listingEl);

      var statusEl = document.createElement("div");
      statusEl.className = "cc-fs-explorer-status";
      listingHost.appendChild(statusEl);

      // Footer
      var footer = document.createElement("div");
      footer.className = "cc-fs-explorer-foot";
      var nameLabel = document.createElement("label");
      nameLabel.className = "cc-fs-explorer-namelabel";
      nameLabel.textContent = (mode === "save")
        ? "Save as: "
        : (mode === "folder" ? "Folder: " : "File name: ");
      var nameInput = document.createElement("input");
      nameInput.type = "text";
      nameInput.className = "cc-fs-explorer-name";
      if (mode === "save") nameInput.value = defaultSaveName;
      nameLabel.appendChild(nameInput);
      footer.appendChild(nameLabel);
      var cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "btn btn-secondary";
      cancelBtn.textContent = "Cancel";
      cancelBtn.addEventListener("click", function () { settle(""); });
      footer.appendChild(cancelBtn);
      var okBtn = document.createElement("button");
      okBtn.type = "button";
      okBtn.className = "btn btn-primary";
      okBtn.textContent = (mode === "save")
        ? "Save"
        : (mode === "folder" ? "Use folder" : "Open");
      footer.appendChild(okBtn);
      modal.appendChild(footer);

      var state = {
        path: "",
        parent: null,
        sep: "/",
        entries: [],
        showHidden: false,
        filterText: "",
        selected: null,
      };

      function applyFilter() {
        var query = state.filterText.trim().toLowerCase();
        var rows = listingEl.querySelectorAll(".cc-fs-explorer-row");
        var visible = 0;
        for (var i = 0; i < rows.length; i++) {
          var row = rows[i];
          var entry = row._entry;
          var keep = true;
          if (!state.showHidden && entry.hidden) keep = false;
          if (keep && entry.kind === "file" && allowedExts && !allowedExts["*"]) {
            var hits = Object.keys(allowedExts);
            if (hits.length > 0) {
              var lower = entry.name.toLowerCase();
              var matched = false;
              for (var k = 0; k < hits.length; k++) {
                if (lower.endsWith(hits[k])) { matched = true; break; }
              }
              if (!matched) keep = false;
            }
          }
          if (keep && query.length > 0) {
            if (entry.name.toLowerCase().indexOf(query) === -1) keep = false;
          }
          row.hidden = !keep;
          if (keep) visible++;
        }
        statusEl.textContent = visible + " visible · " + state.entries.length + " total";
      }

      function renderEntries() {
        listingEl.innerHTML = "";
        if (state.entries.length === 0) {
          var empty = document.createElement("li");
          empty.className = "cc-fs-explorer-empty";
          empty.textContent = "(empty directory)";
          listingEl.appendChild(empty);
          return;
        }
        state.entries.forEach(function (entry) {
          var li = document.createElement("li");
          li.className = "cc-fs-explorer-row";
          li.classList.add("cc-fs-explorer-row--" + entry.kind);
          li._entry = entry;

          var iconEl = document.createElement("span");
          iconEl.className = "cc-fs-explorer-icon";
          iconEl.textContent = _fsExplorerIcon(entry.kind, entry.name);
          var nameEl = document.createElement("span");
          nameEl.className = "cc-fs-explorer-name-cell";
          nameEl.textContent = entry.name;
          if (entry.kind === "symlink" || entry.symlink_target) {
            nameEl.title = entry.symlink_target
              ? ("\u2192 " + entry.symlink_target)
              : "symlink";
          }
          var sizeEl = document.createElement("span");
          sizeEl.className = "cc-fs-explorer-size";
          sizeEl.textContent = (entry.kind === "dir") ? "" : _fsExplorerFormatBytes(entry.size);
          var mtimeEl = document.createElement("span");
          mtimeEl.className = "cc-fs-explorer-mtime";
          mtimeEl.textContent = _fsExplorerFormatTime(entry.mtime);

          li.appendChild(iconEl);
          li.appendChild(nameEl);
          li.appendChild(sizeEl);
          li.appendChild(mtimeEl);

          li.addEventListener("click", function () {
            var prev = listingEl.querySelector(".cc-fs-explorer-row.is-selected");
            if (prev) prev.classList.remove("is-selected");
            li.classList.add("is-selected");
            state.selected = entry;
            if (mode === "save") {
              if (entry.kind === "file") nameInput.value = entry.name;
            } else if (mode === "open") {
              if (entry.kind === "file") nameInput.value = entry.name;
            }
          });
          li.addEventListener("dblclick", function () {
            if (entry.kind === "dir") {
              loadPath(entry.path);
              return;
            }
            if (mode === "open" && entry.kind === "file") {
              settle(entry.path);
            }
          });
          listingEl.appendChild(li);
        });
      }

      async function loadPath(target) {
        statusEl.textContent = "loading\u2026";
        try {
          var resp = await apiFetch(
            "/api/fs/browse?path=" + encodeURIComponent(target || ""),
            { method: "GET" }
          );
          state.path = String(resp.path || "");
          state.parent = (resp.parent == null) ? null : String(resp.parent);
          state.sep = String(resp.separator || "/");
          state.entries = Array.isArray(resp.entries) ? resp.entries : [];
          state.selected = null;
          pathInput.value = state.path;
          upBtn.disabled = (state.parent == null);
          renderEntries();
          if (resp.error) {
            statusEl.textContent = String(resp.error);
            statusEl.classList.add("is-error");
          } else {
            statusEl.classList.remove("is-error");
            applyFilter();
          }
          renderShortcuts(resp.shortcuts || [], resp.drives || []);
        } catch (err) {
          statusEl.textContent = "browse failed: " + (err && err.message ? err.message : err);
          statusEl.classList.add("is-error");
        }
      }

      function renderShortcuts(shortcuts, drives) {
        sidebar.innerHTML = "";
        var head = document.createElement("div");
        head.className = "cc-fs-explorer-side-head";
        head.textContent = "Shortcuts";
        sidebar.appendChild(head);
        shortcuts.forEach(function (s) {
          var btn = document.createElement("button");
          btn.type = "button";
          btn.className = "cc-fs-explorer-side-btn";
          btn.textContent = s.label;
          btn.title = s.path || "(unavailable)";
          btn.disabled = !s.available;
          btn.addEventListener("click", function () { loadPath(s.path); });
          sidebar.appendChild(btn);
        });
        if (Array.isArray(drives) && drives.length > 0) {
          var divHead = document.createElement("div");
          divHead.className = "cc-fs-explorer-side-head";
          divHead.textContent = "Drives";
          sidebar.appendChild(divHead);
          drives.forEach(function (d) {
            var btn = document.createElement("button");
            btn.type = "button";
            btn.className = "cc-fs-explorer-side-btn";
            btn.textContent = d;
            btn.addEventListener("click", function () { loadPath(d); });
            sidebar.appendChild(btn);
          });
        }
      }

      function commit() {
        if (mode === "folder") {
          settle(state.path);
          return;
        }
        var fname = (nameInput.value || "").trim();
        if (mode === "save") {
          if (fname.length === 0) {
            statusEl.textContent = "Enter a filename to save.";
            statusEl.classList.add("is-error");
            return;
          }
          settle(_fsExplorerJoin(state.path, fname, state.sep));
          return;
        }
        // open mode
        if (state.selected && state.selected.kind === "file") {
          settle(state.selected.path);
          return;
        }
        if (fname.length > 0) {
          settle(_fsExplorerJoin(state.path, fname, state.sep));
          return;
        }
        statusEl.textContent = "Pick a file or type a name.";
        statusEl.classList.add("is-error");
      }

      // Wire-up
      upBtn.addEventListener("click", function () {
        if (state.parent != null) loadPath(state.parent);
      });
      goBtn.addEventListener("click", function () { loadPath(pathInput.value || ""); });
      pathInput.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") { ev.preventDefault(); loadPath(pathInput.value || ""); }
      });
      filterInput.addEventListener("input", function () {
        state.filterText = filterInput.value || "";
        applyFilter();
      });
      hiddenCb.addEventListener("change", function () {
        state.showHidden = !!hiddenCb.checked;
        applyFilter();
      });
      okBtn.addEventListener("click", commit);
      nameInput.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") { ev.preventDefault(); commit(); }
      });

      function onKey(ev) {
        if (ev.key === "Escape") {
          ev.preventDefault();
          ev.stopPropagation();
          settle("");
        }
      }
      document.addEventListener("keydown", onKey, true);

      document.body.appendChild(overlay);
      filterInput.focus();
      loadPath(o.defaultPath || "");
    });
  }

  window.YggdraSimFsExplorer = openFsExplorer;

  window.YggdraSimPathPicker = pathPicker;

  function pathPickerOptsForKind(field) {
    var name = String(field && field.name || "").toLowerCase();
    var fileTypes = [];
    if (/\bsaip|profile|der/.test(name)) {
      fileTypes = [
        "SAIP profile (*.der;*.bin;*.json)",
        "DER (*.der;*.bin)",
        "JSON (*.json)",
        "All files (*.*)",
      ];
    } else if (/(cert|crt|pem)/.test(name)) {
      fileTypes = [
        "Certificate (*.pem;*.crt;*.cer;*.der)",
        "All files (*.*)",
      ];
    } else {
      fileTypes = ["All files (*.*)"];
    }
    return { fileTypes: fileTypes };
  }

  async function pickForField(field) {
    var kind = field && field.kind;
    var opts = pathPickerOptsForKind(field);
    if (kind === "directory") {
      return await pathPicker.pickFolder({});
    }
    if (kind === "save_path") {
      opts.saveFilename = field && field.placeholder
        ? String(field.placeholder).split("/").pop()
        : "";
      return await pathPicker.saveFile(opts);
    }
    return await pathPicker.pickFile(opts);
  }

  // Wrap a plain <input> into a path-picker row: adds the double-click
  // handler, a trailing "Browse…" button, and the shared cc-path-*
  // classes so CSS stays consistent with the Command Center fields.
  //
  //   mode:
  //     "open"   -> pick an existing file (default)
  //     "save"   -> pick a save destination
  //     "folder" -> pick a directory
  //
  // Returns the wrapper <div> so callers can append it to their own
  // form-row container in place of the raw input.
  function attachPathPicker(input, mode) {
    var m = String(mode || "open").toLowerCase();
    var kind = (m === "save")
      ? "save_path"
      : (m === "folder" ? "directory" : "path");
    var field = { kind: kind, name: input.name || "", placeholder: input.placeholder || "" };
    var openPicker = async function () {
      var chosen = "";
      try {
        chosen = await pickForField(field);
      } catch (_err) {
        chosen = "";
      }
      if (chosen) {
        input.value = chosen;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
    };
    input.classList.add("cc-path-input");
    if (!input.title) {
      input.title = "Double-click to browse \u00B7 drop a file to paste its path";
    }
    input.addEventListener("dblclick", openPicker);

    var wrap = document.createElement("div");
    wrap.className = "cc-path-row";
    wrap.appendChild(input);

    var browse = document.createElement("button");
    browse.type = "button";
    browse.className = "btn btn-small cc-path-browse";
    browse.textContent = "Browse…";
    browse.title = (kind === "directory")
      ? "Pick a folder"
      : (kind === "save_path" ? "Pick a save location" : "Pick a file");
    browse.addEventListener("click", openPicker);
    wrap.appendChild(browse);

    enableFilePathDrop(input);

    return wrap;
  }

  window.YggdraSimAttachPathPicker = attachPathPicker;

  // --- Drag-and-drop onto path inputs --------------------------------------
  //
  // Path-kind ActionFields (``path`` / ``directory`` / ``save_path``) and
  // the SAIP workbench's own pickers share this helper. Dropping a file
  // anywhere on the ``.cc-path-row`` wrapper (or the raw input when it
  // isn't wrapped) replaces the current value with the absolute path of
  // the dropped item and fires both ``input`` + ``change`` events so the
  // form's existing listeners re-run.
  //
  // File extraction honours the three transports pywebview + Qt WebEngine
  // expose on drop:
  //   1. ``event.dataTransfer.files[].path``  (pywebview / Electron; the
  //      most reliable on Linux — includes the absolute filesystem path)
  //   2. ``text/uri-list`` entries starting with ``file://``
  //   3. ``text/plain`` as a last-resort fallback (useful when an operator
  //      drags a path string from a terminal)
  //
  // ``input.dataset.dndWired`` stops double-wiring when a field is rebuilt
  // mid-session (the compact workbench keeps cards mounted, but some
  // flows re-render pickers).
  function enableFilePathDrop(input, onPath) {
    if (!input || input.dataset.dndWired === "1") return;
    input.dataset.dndWired = "1";

    var host = input.closest(".cc-path-row") || input;
    host.classList.add("cc-path-drop-target");

    var dragCounter = 0;
    function dragHasFile(event) {
      var dt = event && event.dataTransfer;
      if (!dt) return false;
      var types = dt.types;
      if (!types) return false;
      for (var i = 0; i < types.length; i += 1) {
        var t = types[i];
        if (t === "Files" || t === "text/uri-list" || t === "application/x-moz-file") {
          return true;
        }
      }
      return false;
    }
    function setDropEffect(event) {
      try { event.dataTransfer.dropEffect = "copy"; } catch (_e) { /* no-op */ }
    }
    function onEnter(event) {
      if (!dragHasFile(event)) return;
      event.preventDefault();
      event.stopPropagation();
      dragCounter += 1;
      host.classList.add("cc-path-drop-hover");
      setDropEffect(event);
    }
    function onOver(event) {
      if (!dragHasFile(event)) return;
      event.preventDefault();
      event.stopPropagation();
      setDropEffect(event);
    }
    function onLeave() {
      dragCounter = Math.max(0, dragCounter - 1);
      if (dragCounter === 0) {
        host.classList.remove("cc-path-drop-hover");
      }
    }
    function onDrop(event) {
      if (!event.dataTransfer) return;
      event.preventDefault();
      event.stopPropagation();
      dragCounter = 0;
      host.classList.remove("cc-path-drop-hover");
      var path = extractPathFromDrop(event);
      if (!path) return;
      input.value = path;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
      try { input.focus({ preventScroll: true }); } catch (_e) { /* no-op */ }
      if (typeof onPath === "function") {
        try { onPath(path); } catch (_err) { /* swallow */ }
      }
    }

    host.addEventListener("dragenter", onEnter);
    host.addEventListener("dragover", onOver);
    host.addEventListener("dragleave", onLeave);
    host.addEventListener("drop", onDrop);
  }

  function extractPathFromDrop(event) {
    var dt = event.dataTransfer;
    if (!dt) return "";
    // (1) Native File objects — pywebview + Electron expose ``.path`` on
    // the File instance. Browsers that don't (i.e. a plain Chrome tab)
    // will fall through to the URI list.
    if (dt.files && dt.files.length > 0) {
      var f = dt.files[0];
      if (f) {
        if (typeof f.path === "string" && f.path.length > 0) {
          return f.path;
        }
        // WebKit exposes ``webkitRelativePath`` on directory drops, which
        // we accept as a best-effort fallback (operators drop a folder
        // from a file manager, we land something usable in the field).
        if (typeof f.webkitRelativePath === "string" && f.webkitRelativePath.length > 0) {
          return f.webkitRelativePath;
        }
      }
    }
    // (2) URI list — ``file:///home/foo/bar.bin`` form, possibly with
    // multiple entries separated by newlines. We keep the first non-
    // comment entry and decode the pathname back into a filesystem path.
    var uriList = "";
    try { uriList = dt.getData("text/uri-list") || ""; } catch (_e) { /* no-op */ }
    if (uriList) {
      var lines = uriList.split(/\r?\n/);
      for (var i = 0; i < lines.length; i += 1) {
        var line = (lines[i] || "").trim();
        if (!line || line.charAt(0) === "#") continue;
        if (line.indexOf("file://") === 0) {
          try {
            var parsed = new URL(line);
            var decoded = decodeURIComponent(parsed.pathname || "");
            if (decoded) return decoded;
          } catch (_err) {
            return decodeURIComponent(line.replace(/^file:\/\//, ""));
          }
        }
        return line;
      }
    }
    // (3) Plain text fallback — operators occasionally drag a path string
    // out of a terminal. Accept it as-is; server-side validation will
    // reject anything bogus.
    var txt = "";
    try { txt = dt.getData("text/plain") || ""; } catch (_e) { /* no-op */ }
    if (txt && txt.trim()) return txt.trim();
    return "";
  }

  // Expose so tests and third-party wiring (e.g. ad-hoc extensions) can
  // reuse the same drop semantics without re-implementing path extraction.
  window.YggdraSimEnableFilePathDrop = enableFilePathDrop;
  window.YggdraSimExtractPathFromDrop = extractPathFromDrop;

  // Guard against pywebview / Qt WebEngine's default "navigate to
  // file://…" behaviour when an operator misses the drop target. We
  // swallow file drops anywhere outside a ``.cc-path-drop-target``
  // so the SPA stays mounted; targeted drops still reach the
  // ``enableFilePathDrop`` handlers because their listeners call
  // ``preventDefault`` on the same event first.
  (function installDropGuard() {
    if (window.__ygg_drop_guard_installed) return;
    window.__ygg_drop_guard_installed = true;
    function isFileDrag(event) {
      var dt = event && event.dataTransfer;
      if (!dt) return false;
      var types = dt.types;
      if (!types) return false;
      for (var i = 0; i < types.length; i += 1) {
        if (types[i] === "Files") return true;
      }
      return false;
    }
    function isManagedDropTarget(target) {
      return !!(target && target.closest
        && target.closest(".cc-path-drop-target, .saip-workbench"));
    }
    document.addEventListener("dragover", function (event) {
      if (!isFileDrag(event)) return;
      var t = event.target;
      if (isManagedDropTarget(t)) return;
      event.preventDefault();
      try { event.dataTransfer.dropEffect = "none"; } catch (_e) { /* no-op */ }
    });
    document.addEventListener("drop", function (event) {
      if (!isFileDrag(event)) return;
      var t = event.target;
      if (isManagedDropTarget(t)) return;
      event.preventDefault();
    });
  })();

  // -- Reader pane (G-1) ---------------------------------------------------

  var readerStore = {
    readers: [],
    selected: null,   // reader name string, or null
    filter: "",
    lastRefresh: 0,
  };

  function setSelectedReader(name, opts) {
    opts = opts || {};
    var canonical = name || null;
    if (canonical && typeof readerBarCanonicalName === "function") {
      canonical = readerBarCanonicalName(canonical);
    }
    readerStore.selected = canonical;
    document.querySelectorAll(".reader-row").forEach(function (row) {
      var rowName = row.getAttribute("data-reader-name") || "";
      row.classList.toggle("is-selected", rowName === readerStore.selected);
    });
    if (canonical && !opts.fromReaderBar && typeof readerBarActivate === "function") {
      readerBarActivate(canonical);
    }
    if (canonical) {
      logBus.emit({
        level: "info",
        source: "readers",
        message: "selected reader: " + canonical,
      });
    }
  }

  function getSelectedReader() {
    if (typeof ccActiveReaderName === "function") {
      return ccActiveReaderName() || readerStore.selected;
    }
    return readerStore.selected;
  }

  function readerStatusToDot(reader) {
    var atr = String(reader && reader.atr_hex || "").trim();
    var status = String(reader && reader.status || "").toLowerCase();
    if (status.indexOf("error") >= 0 || status.indexOf("fail") >= 0) {
      return "error";
    }
    if (atr.length > 0) return "card";
    if (status.indexOf("no card") >= 0 || status.indexOf("empty") >= 0) {
      return "empty";
    }
    return "unknown";
  }

  function renderReaderPane() {
    var ul = $("reader-pane-list");
    if (!ul) return;
    var note = $("reader-pane-note");
    var rows = readerStore.readers || [];
    var needle = String(readerStore.filter || "").toLowerCase();
    if (needle.length > 0) {
      rows = rows.filter(function (r) {
        return String(r.name || "").toLowerCase().indexOf(needle) >= 0;
      });
    }

    ul.innerHTML = "";
    if (rows.length === 0) {
      var empty = document.createElement("li");
      empty.className = "reader-empty";
      if (readerStore.lastRefresh === 0) {
        empty.textContent = "click ↻ to enumerate.";
      } else if (needle.length > 0) {
        empty.textContent = "no readers match the filter.";
      } else {
        empty.textContent = "no readers detected.";
      }
      ul.appendChild(empty);
    } else {
      rows.forEach(function (reader) {
        var li = document.createElement("li");
        li.className = "reader-row";
        li.setAttribute("data-reader-name", reader.name || "");
        if (reader.name === readerStore.selected) {
          li.classList.add("is-selected");
        }
        var dotKind = readerStatusToDot(reader);
        var dot = document.createElement("span");
        dot.className = "reader-row-dot reader-row-dot--" + dotKind;
        dot.title = "card-state: " + dotKind;
        var body = document.createElement("span");
        body.className = "reader-row-body";
        var name = document.createElement("span");
        name.className = "reader-row-name";
        name.textContent = String(reader.name || "(unnamed)");
        var sub = document.createElement("span");
        sub.className = "reader-row-sub";
        if (reader.atr_hex && String(reader.atr_hex).length > 0) {
          sub.textContent = "ATR " + String(reader.atr_hex);
        } else {
          sub.textContent = String(reader.status || "");
        }
        body.appendChild(name);
        body.appendChild(sub);
        li.appendChild(dot);
        li.appendChild(body);
        li.addEventListener("click", function () {
          setSelectedReader(reader.name || "");
        });
        li.addEventListener("dblclick", function () {
          if (!reader.name) return;
          setSelectedReader(reader.name);
          scp03StartSessionForReader(reader.name);
        });
        li.addEventListener("contextmenu", function (event) {
          event.preventDefault();
          setSelectedReader(reader.name || "");
          showReaderContextMenu(reader, event.clientX, event.clientY);
        });
        ul.appendChild(li);
      });
    }

    if (note) {
      if (readerStore.lastRefresh === 0) {
        note.textContent = "";
        note.classList.remove("is-error");
      } else {
        var total = (readerStore.readers || []).length;
        note.classList.remove("is-error");
        note.textContent = total + " reader(s) total · last probe " +
          formatTime(new Date(readerStore.lastRefresh));
      }
    }
    setStatusReaders((readerStore.readers || []).length);
  }

  async function refreshReaderPane() {
    var btn = $("reader-pane-refresh");
    if (btn) btn.classList.add("is-spinning");
    var note = $("reader-pane-note");
    if (note) {
      note.classList.remove("is-error");
      note.textContent = "probing…";
    }
    try {
      var data = await apiFetch("/api/live/readers");
      readerStore.readers = (data && data.readers) || [];
      readerStore.lastRefresh = Date.now();
      logBus.emit({
        level: "info",
        source: "readers",
        message:
          "enumerated " + readerStore.readers.length + " reader(s) (backend: " +
          String(data && data.backend || "?") + ").",
      });
      renderReaderPane();
    } catch (err) {
      logBus.emit({
        level: "error",
        source: "readers",
        message: "reader probe failed: " + (err && err.message || err),
      });
      if (note) {
        note.classList.add("is-error");
        note.textContent = "probe failed: " + (err && err.message || err);
      }
    } finally {
      if (btn) btn.classList.remove("is-spinning");
    }
  }

  function wireReaderPane() {
    var btn = $("reader-pane-refresh");
    if (btn) btn.addEventListener("click", refreshReaderPane);
    var input = $("reader-pane-filter");
    if (input) {
      input.addEventListener("input", function (event) {
        readerStore.filter = String(event.target.value || "");
        renderReaderPane();
      });
    }
    renderReaderPane();
  }

  // Expose for action forms (G-2 uses this to default the reader
  // dropdown to the sidebar selection).
  window.YggdraSimReaderStore = {
    getSelected: getSelectedReader,
    setSelected: setSelectedReader,
    snapshot: function () { return (readerStore.readers || []).slice(); },
    refresh: refreshReaderPane,
  };

  // -- Reader context menu (G-3) ------------------------------------------

  var contextMenuState = { open: false, root: null, dismiss: null };

  function ensureContextMenuRoot() {
    if (contextMenuState.root) return contextMenuState.root;
    var menu = document.createElement("div");
    menu.className = "ctx-menu";
    menu.setAttribute("role", "menu");
    document.body.appendChild(menu);
    contextMenuState.root = menu;
    return menu;
  }

  function hideContextMenu() {
    if (contextMenuState.root) {
      contextMenuState.root.classList.remove("is-open");
      contextMenuState.root.innerHTML = "";
    }
    if (contextMenuState.dismiss) {
      document.removeEventListener("click", contextMenuState.dismiss, true);
      document.removeEventListener("keydown", contextMenuState.dismiss, true);
      contextMenuState.dismiss = null;
    }
    contextMenuState.open = false;
  }

  function positionContextMenu(menu, x, y) {
    menu.style.visibility = "hidden";
    menu.classList.add("is-open");
    var rect = menu.getBoundingClientRect();
    var viewportW = window.innerWidth;
    var viewportH = window.innerHeight;
    var px = x;
    var py = y;
    if (px + rect.width > viewportW - 4) {
      px = Math.max(4, viewportW - rect.width - 4);
    }
    if (py + rect.height > viewportH - 4) {
      py = Math.max(4, viewportH - rect.height - 4);
    }
    menu.style.left = px + "px";
    menu.style.top = py + "px";
    menu.style.visibility = "visible";
  }

  function buildContextMenuItem(spec) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ctx-menu-item" + (spec.danger ? " ctx-menu-item--danger" : "");
    btn.setAttribute("role", "menuitem");
    if (spec.disabled) btn.disabled = true;
    var icon = document.createElement("span");
    icon.className = "ctx-menu-icon";
    icon.textContent = spec.icon || "·";
    var label = document.createElement("span");
    label.className = "ctx-menu-label";
    label.textContent = spec.label || "";
    btn.appendChild(icon);
    btn.appendChild(label);
    btn.addEventListener("click", function () {
      hideContextMenu();
      if (typeof spec.onClick === "function") spec.onClick();
    });
    return btn;
  }

  function showContextMenu(items, x, y) {
    var menu = ensureContextMenuRoot();
    menu.innerHTML = "";
    items.forEach(function (item) {
      if (item && item.divider) {
        var sep = document.createElement("div");
        sep.className = "ctx-menu-sep";
        menu.appendChild(sep);
      } else if (item) {
        menu.appendChild(buildContextMenuItem(item));
      }
    });
    positionContextMenu(menu, x, y);
    contextMenuState.open = true;
    var dismiss = function (event) {
      if (event.type === "keydown") {
        if (event.key === "Escape") hideContextMenu();
        return;
      }
      // Click outside the menu = dismiss.
      if (menu.contains(event.target)) return;
      hideContextMenu();
    };
    contextMenuState.dismiss = dismiss;
    setTimeout(function () {
      document.addEventListener("click", dismiss, true);
      document.addEventListener("keydown", dismiss, true);
    }, 0);
  }

  function showReaderContextMenu(reader, x, y) {
    var name = reader && reader.name || "";
    var atr = reader && reader.atr_hex || "";
    var items = [
      {
        icon: SCP03_ICONS.openSession,
        label: "Open SCP03 session",
        onClick: function () { scp03StartSessionForReader(name); },
        disabled: name.length === 0,
      },
      {
        icon: SCP03_ICONS.refreshAtr,
        label: "Refresh ATR",
        onClick: function () { refreshSingleReaderAtr(name); },
        disabled: name.length === 0,
      },
      { divider: true },
      {
        icon: SCP03_ICONS.copy,
        label: atr ? "Copy ATR" : "Copy reader name",
        onClick: function () { copyToClipboardSafe(atr || name); },
      },
    ];
    showContextMenu(items, x, y);
  }

  function copyToClipboardSafe(text) {
    var value = String(text || "");
    if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(function () {
        logBus.emit({ level: "info", source: "readers", message: "copied: " + value });
      }, function () {
        logBus.emit({ level: "warn", source: "readers", message: "clipboard write rejected." });
      });
      return;
    }
    try {
      var ta = document.createElement("textarea");
      ta.value = value;
      ta.style.position = "fixed";
      ta.style.left = "-1000px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      logBus.emit({ level: "info", source: "readers", message: "copied: " + value });
    } catch (_err) {
      logBus.emit({ level: "warn", source: "readers", message: "clipboard fallback failed." });
    }
  }

  async function refreshSingleReaderAtr(readerName) {
    if (!readerName) return;
    logBus.emit({ level: "info", source: "readers", message: "ATR probe → " + readerName });
    try {
      var resp = await apiFetch("/api/live/atr", {
        method: "POST",
        body: JSON.stringify({ reader: readerName }),
      });
      // Patch the cached reader entry so the dot/sub line stays fresh.
      (readerStore.readers || []).forEach(function (r) {
        if (r.name === readerName) {
          r.atr_hex = resp.atr_hex || "";
          r.status = resp.status || r.status;
        }
      });
      renderReaderPane();
      logBus.emit({
        level: "info",
        source: "readers",
        message: readerName + " · ATR " + (resp.atr_hex || "(none)") +
          " · status " + (resp.status || "?"),
      });
    } catch (err) {
      logBus.emit({
        level: "error",
        source: "readers",
        message: "ATR probe failed for " + readerName + ": " + (err && err.message || err),
      });
    }
  }

  // -- Auto-start an SCP03 session in a workbench tab (G-3) ---------------

  async function scp03StartSessionForReader(readerName) {
    var safeReader = String(readerName || "").trim();
    if (safeReader.length === 0) return;
    openCommandSubsystem("SCP03");

    var wb = commandState.scp03Workbench;
    var tab = null;
    // Reuse an empty tab if one exists, otherwise spawn a new one. Never
    // hijack a tab that already holds a different open session.
    for (var i = 0; i < wb.tabs.length; i++) {
      if (!wb.tabs[i].sessionId) { tab = wb.tabs[i]; break; }
    }
    if (!tab) {
      tab = scp03CreateEmptyTab();
      wb.tabs.push(tab);
    }
    wb.activeTabId = tab.id;
    tab.readerName = safeReader;
    tab.status = "scanning";
    tab.error = null;

    var tabBar = document.querySelector(".cc-wb-tabs");
    var tabBody = document.querySelector(".cc-wb-body");
    if (tabBar && tabBody) renderScp03Tabs(tabBar, tabBody);

    logBus.emit({
      level: "info",
      source: "scp03.scan",
      message: "auto-scan → " + safeReader,
    });
    try {
      var resp = await apiFetch("/api/actions/scp03.scan/run", {
        method: "POST",
        body: JSON.stringify({ inputs: { reader: safeReader } }),
      });
      if (!resp.ok) {
        tab.status = "error";
        tab.error = resp.error || "scan failed";
        logBus.emit({ level: "error", source: "scp03.scan", message: tab.error });
      } else {
        var data = resp.data || {};
        tab.sessionId = data.session_id || null;
        tab.readerName = data.reader_name || safeReader;
        tab.atrHex = data.atr_hex || "";
        tab.scanData = data;
        tab.status = "open";
        tab.error = null;
        commandState.scp03Session = tab.sessionId;
        logBus.emit({
          level: "info",
          source: "scp03.scan",
          message: "session " + (tab.sessionId || "?").substring(0, 8) +
            " open on " + tab.readerName,
        });
      }
    } catch (err) {
      tab.status = "error";
      tab.error = String(err && err.message || err);
      logBus.emit({ level: "error", source: "scp03.scan", message: tab.error });
    }
    var tabBarFinal = document.querySelector(".cc-wb-tabs");
    var tabBodyFinal = document.querySelector(".cc-wb-body");
    if (tabBarFinal && tabBodyFinal) renderScp03Tabs(tabBarFinal, tabBodyFinal);
  }

  // -- Bottom log dock (G-1) ----------------------------------------------

  var logDockState = {
    activeBucket: "messages",
    collapsed: false,
    height: 180,
  };

  function applyLogCounts(counts) {
    ["messages", "warnings", "errors", "apdu"].forEach(function (bucket) {
      var n = counts[bucket] || 0;
      setText("log-count-" + bucket, String(n));
      var tab = document.querySelector(
        ".log-dock-tab[data-log-tab=\"" + bucket + "\"]"
      );
      if (tab) {
        tab.classList.toggle("has-items", n > 0);
      }
      var empty = $("log-empty-" + bucket);
      if (empty) empty.classList.toggle("is-hidden", n > 0);
    });
  }

  // Format a single log row as a tab-separated "HH:MM:SS\tSOURCE\tMESSAGE"
  // line. We use tab characters (instead of fixed-width padding) so the
  // pasted text aligns nicely whether the destination is a terminal,
  // text editor, spreadsheet, issue tracker, or chat client.
  function formatLogRowForClipboard(row) {
    if (!row) return "";
    var ts = formatTime(row.ts || new Date());
    var src = String(row.source || "");
    var msg = String(row.message || "");
    return ts + "\t" + src + "\t" + msg;
  }

  function formatLogRowsForClipboard(rows) {
    if (!Array.isArray(rows) || rows.length === 0) return "";
    return rows.map(formatLogRowForClipboard).join("\n");
  }

  // Resilient writeText: prefers ``navigator.clipboard`` when available
  // (modern Chromium / Qt WebEngine ≥ 5.15) and silently falls back to
  // a hidden ``textarea`` + ``document.execCommand("copy")`` for older
  // webview backends where the async API is gated behind a permission
  // prompt we don't drive.
  function copyTextToClipboard(text) {
    var payload = String(text == null ? "" : text);
    if (payload.length === 0) {
      return Promise.resolve(false);
    }
    if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
      try {
        return navigator.clipboard.writeText(payload).then(
          function () { return true; },
          function () { return _execCommandCopyFallback(payload); }
        );
      } catch (_err) {
        return Promise.resolve(_execCommandCopyFallback(payload));
      }
    }
    return Promise.resolve(_execCommandCopyFallback(payload));
  }

  function _execCommandCopyFallback(text) {
    // Synchronous DOM copy fallback. Returns true on success so the
    // caller can show a "Copied" flash; failure paths just no-op.
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      ta.style.left = "-9999px";
      ta.style.top = "0";
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (_err) { ok = false; }
      document.body.removeChild(ta);
      return ok;
    } catch (_err) {
      return false;
    }
  }

  // Visual ack for the operator: briefly toggle a CSS class so they
  // know the click registered even if the OS clipboard widget swallows
  // focus or the dock scrolled away from the row.
  function flashLogDockCopiedAck(target) {
    if (!target) return;
    target.classList.add("is-copied");
    setTimeout(function () {
      try { target.classList.remove("is-copied"); } catch (_err) {}
    }, 700);
  }

  // Public-ish hooks used by the regression suite to verify the copy
  // helpers are wired without having to drive the actual clipboard.
  window.YggdraSimFormatLogRowForClipboard = formatLogRowForClipboard;
  window.YggdraSimFormatLogRowsForClipboard = formatLogRowsForClipboard;
  window.YggdraSimCopyTextToClipboard = copyTextToClipboard;

  function copyLogDockRowElement(row) {
    if (!row) return Promise.resolve(false);
    var text = formatLogRowForClipboard({
      ts: row.dataset.logTs,
      source: row.dataset.logSource,
      message: row.dataset.logMessage,
    });
    return copyTextToClipboard(text).then(function (ok) {
      if (ok) flashLogDockCopiedAck(row);
      return ok;
    });
  }

  function wireLogDockRowDblclick(el) {
    el.addEventListener("dblclick", function (evt) {
      // Don't override a user-driven text selection — only copy the
      // whole row when there isn't one.
      var sel = window.getSelection ? window.getSelection() : null;
      if (sel && !sel.isCollapsed && sel.toString().length > 0) return;
      evt.preventDefault();
      evt.stopPropagation();
      copyLogDockRowElement(el);
    });
  }

  // Single delegated click listener per host — installed lazily the first
  // time we add a row to a bucket. The copy button is delegated to avoid
  // thousands of button listeners; double-click stays on the row because
  // older GUI contract tests and operator muscle memory pin that surface.
  function ensureLogDockHostDelegation(host) {
    if (!host || host.dataset.logDelegated === "1") return;
    host.dataset.logDelegated = "1";
    host.addEventListener("click", function (evt) {
      var btn = evt.target && evt.target.closest
        ? evt.target.closest(".log-dock-row-copy")
        : null;
      if (!btn) return;
      var row = btn.closest(".log-dock-row");
      if (!row) return;
      evt.stopPropagation();
      copyLogDockRowElement(row);
    });
  }

  // Tens-of-KB JSON-dump messages (raw FCP TLV trees, bulk profile
  // snapshots, full-stream traces) are common enough that we hard-cap
  // the per-row visible text. The unfiltered original still lives in
  // the bus snapshot and on the row's ``dataset.logMessage`` so the
  // copy button hands the operator the full payload.
  var LOG_DOCK_MAX_MSG_CHARS = 4096;

  function _truncateDockMessage(text) {
    var s = String(text == null ? "" : text);
    if (s.length <= LOG_DOCK_MAX_MSG_CHARS) return s;
    var keep = LOG_DOCK_MAX_MSG_CHARS - 32;
    return s.slice(0, keep) + "… [+" + (s.length - keep) + " chars truncated]";
  }

  function appendLogDockRow(bucket, row) {
    // Lazy DOM render: when the dock is collapsed or the bucket isn't
    // the visible tab, we skip the DOM append entirely. The row is
    // still in ``logBus`` (which is bounded), so the count badge stays
    // accurate via ``applyLogCounts`` and ``activateLogTab`` rebuilds
    // the panel from the bus snapshot when the tab is opened. This is
    // a meaningful RAM saver because three of the four buckets are
    // inactive at any moment, and the APDU bucket can hit 5000 rows of
    // accumulated DOM otherwise (≈ 10 MB of nodes). Mark the panel as
    // "stale" so ``activateLogTab`` knows to rebuild it.
    var panel = $("log-panel-" + bucket);
    if (panel) {
      var dockHidden = logDockState.collapsed
        || logDockState.activeBucket !== bucket;
      if (dockHidden) {
        panel.dataset.stale = "1";
        return;
      }
    }
    var host = $("log-panel-" + bucket);
    if (!host) return;
    ensureLogDockHostDelegation(host);
    var el = document.createElement("div");
    el.className = "log-dock-row log-dock-row--" + String(row.level || "info").toLowerCase();
    // Make the row keyboard-focusable so Tab + Enter / Ctrl+C work for
    // accessibility (screen readers, keyboard-only operators).
    el.setAttribute("tabindex", "0");
    el.setAttribute("role", "listitem");
    // Stash the immutable row payload on the element so the delegated
    // copy / dblclick handlers always quote the exact bytes the bus
    // emitted, even if the visible spans are later truncated by CSS.
    el.dataset.logBucket = bucket;
    el.dataset.logTs = formatTime(row.ts);
    el.dataset.logSource = String(row.source || "");
    el.dataset.logMessage = String(row.message || "");
    el.title = "Double-click or press the copy button to copy this row";
    wireLogDockRowDblclick(el);
    var ts = document.createElement("span");
    ts.className = "log-dock-row-ts";
    ts.textContent = formatTime(row.ts);
    var src = document.createElement("span");
    src.className = "log-dock-row-src";
    src.textContent = row.source || "";
    var msg = document.createElement("span");
    msg.className = "log-dock-row-msg";
    msg.textContent = _truncateDockMessage(row.message);
    // Per-row "copy" affordance — hidden until hover/focus via CSS.
    // No per-row event listeners; the host-level delegation above
    // routes the click via ``.log-dock-row-copy``.
    var copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "log-dock-row-copy";
    copyBtn.setAttribute("aria-label", "Copy this row to clipboard");
    copyBtn.title = "Copy row";
    copyBtn.textContent = "Copy";
    el.appendChild(ts);
    el.appendChild(src);
    el.appendChild(msg);
    el.appendChild(copyBtn);
    host.appendChild(el);
    // Cap DOM nodes per bucket. APDU keeps 5000 to match the bus-side
    // ring (operators asked to see every APDU issued during a
    // session); the human buckets stay at 500 so noise doesn't
    // drown meaningful signal.
    var domCap = bucket === "apdu" ? 5000 : 500;
    while (host.childElementCount > domCap) {
      host.removeChild(host.firstChild);
    }
    host.scrollTop = host.scrollHeight;
  }

  function clearLogDockBucket(bucket) {
    if (bucket) {
      var host = $("log-panel-" + bucket);
      if (host) host.innerHTML = "";
    } else {
      ["messages", "warnings", "errors", "apdu"].forEach(function (b) {
        var host = $("log-panel-" + b);
        if (host) host.innerHTML = "";
      });
    }
  }

  function activateLogTab(bucket) {
    logDockState.activeBucket = bucket;
    document.querySelectorAll(".log-dock-tab").forEach(function (tab) {
      var match = tab.getAttribute("data-log-tab") === bucket;
      tab.classList.toggle("is-active", match);
      tab.setAttribute("aria-selected", match ? "true" : "false");
    });
    document.querySelectorAll(".log-dock-panel").forEach(function (panel) {
      var match = panel.getAttribute("data-log-panel") === bucket;
      panel.classList.toggle("is-active", match);
    });
    rehydrateLogDockPanel(bucket);
  }

  var LOG_DOCK_COLLAPSED_KEY = "yggdrasim:log-dock-collapsed";
  var LOG_DOCK_HEIGHT_KEY = "yggdrasim:log-dock-height";
  var LOG_DOCK_DEFAULT_HEIGHT = 180;
  var LOG_DOCK_MIN_HEIGHT = 128;
  var LOG_DOCK_MAX_VIEWPORT_RATIO = 0.72;

  function _logDockHeightBounds() {
    var viewport = window.innerHeight
      || document.documentElement.clientHeight
      || 800;
    var max = Math.floor(viewport * LOG_DOCK_MAX_VIEWPORT_RATIO);
    if (max < LOG_DOCK_MIN_HEIGHT) max = LOG_DOCK_MIN_HEIGHT;
    return { min: LOG_DOCK_MIN_HEIGHT, max: max };
  }

  function _coerceLogDockHeight(value) {
    var n = Number(value);
    if (!isFinite(n)) n = LOG_DOCK_DEFAULT_HEIGHT;
    var bounds = _logDockHeightBounds();
    if (n < bounds.min) n = bounds.min;
    if (n > bounds.max) n = bounds.max;
    return Math.round(n);
  }

  function setLogDockHeight(value, opts) {
    var height = _coerceLogDockHeight(value);
    logDockState.height = height;
    var shell = $("app");
    if (shell) {
      shell.style.setProperty("--log-dock-height", height + "px");
    }
    var handle = $("log-dock-resize-handle");
    if (handle) {
      var bounds = _logDockHeightBounds();
      handle.setAttribute("aria-valuemin", String(bounds.min));
      handle.setAttribute("aria-valuemax", String(bounds.max));
      handle.setAttribute("aria-valuenow", String(height));
    }
    if (!opts || opts.persist !== false) {
      try {
        window.localStorage.setItem(LOG_DOCK_HEIGHT_KEY, String(height));
      } catch (_err) { /* Safari private mode etc. */ }
    }
  }

  function _restoreLogDockHeight() {
    var stored = null;
    try {
      stored = window.localStorage.getItem(LOG_DOCK_HEIGHT_KEY);
    } catch (_err) {
      stored = null;
    }
    setLogDockHeight(
      stored === null ? LOG_DOCK_DEFAULT_HEIGHT : stored,
      { persist: false },
    );
  }

  function _logDockEventClientY(evt) {
    if (!evt) return null;
    if (evt.touches && evt.touches.length > 0) {
      return evt.touches[0].clientY;
    }
    if (evt.changedTouches && evt.changedTouches.length > 0) {
      return evt.changedTouches[0].clientY;
    }
    return typeof evt.clientY === "number" ? evt.clientY : null;
  }

  function _logDockResizeKeyHeight(evt) {
    var current = logDockState.height || LOG_DOCK_DEFAULT_HEIGHT;
    var step = evt.shiftKey ? 48 : 16;
    var bounds = _logDockHeightBounds();
    if (evt.key === "ArrowUp") return current + step;
    if (evt.key === "ArrowDown") return current - step;
    if (evt.key === "PageUp") return current + 80;
    if (evt.key === "PageDown") return current - 80;
    if (evt.key === "Home") return bounds.min;
    if (evt.key === "End") return bounds.max;
    return null;
  }

  function wireLogDockResize(dockEl) {
    var handle = $("log-dock-resize-handle");
    if (!dockEl || !handle || handle.dataset.resizeWired === "1") return;
    handle.dataset.resizeWired = "1";

    function finishResize(evt, moveHandler, finishHandler, eventPrefix, pointerId) {
      if (evt && evt.cancelable) evt.preventDefault();
      handle.classList.remove("is-dragging");
      document.body.classList.remove("log-dock-resizing");
      if (handle.releasePointerCapture && pointerId != null) {
        try { handle.releasePointerCapture(pointerId); } catch (_err) {}
      }
      if (eventPrefix === "pointer") {
        window.removeEventListener("pointermove", moveHandler);
        window.removeEventListener("pointerup", finishHandler);
        window.removeEventListener("pointercancel", finishHandler);
      } else if (eventPrefix === "touch") {
        window.removeEventListener("touchmove", moveHandler);
        window.removeEventListener("touchend", finishHandler);
        window.removeEventListener("touchcancel", finishHandler);
      } else {
        window.removeEventListener("mousemove", moveHandler);
        window.removeEventListener("mouseup", finishHandler);
      }
      setLogDockHeight(logDockState.height || LOG_DOCK_DEFAULT_HEIGHT);
    }

    function beginResize(evt) {
      if (evt.button != null && evt.button !== 0) return;
      var startY = _logDockEventClientY(evt);
      if (startY === null) return;
      evt.preventDefault();
      if (logDockState.collapsed) setLogDockCollapsed(false);
      var rect = dockEl.getBoundingClientRect();
      var startHeight = logDockState.height || rect.height || LOG_DOCK_DEFAULT_HEIGHT;
      var eventPrefix = evt.type.indexOf("pointer") === 0
        ? "pointer"
        : (evt.type.indexOf("touch") === 0 ? "touch" : "mouse");
      var pointerId = evt.pointerId;
      handle.classList.add("is-dragging");
      document.body.classList.add("log-dock-resizing");
      if (handle.setPointerCapture && pointerId != null) {
        try { handle.setPointerCapture(pointerId); } catch (_err) {}
      }

      function handleMove(moveEvt) {
        var y = _logDockEventClientY(moveEvt);
        if (y === null) return;
        if (moveEvt.cancelable) moveEvt.preventDefault();
        setLogDockHeight(startHeight + startY - y, { persist: false });
      }

      function handleFinish(finishEvt) {
        finishResize(finishEvt, handleMove, handleFinish, eventPrefix, pointerId);
      }

      if (eventPrefix === "pointer") {
        window.addEventListener("pointermove", handleMove);
        window.addEventListener("pointerup", handleFinish);
        window.addEventListener("pointercancel", handleFinish);
      } else if (eventPrefix === "touch") {
        window.addEventListener("touchmove", handleMove, { passive: false });
        window.addEventListener("touchend", handleFinish);
        window.addEventListener("touchcancel", handleFinish);
      } else {
        window.addEventListener("mousemove", handleMove);
        window.addEventListener("mouseup", handleFinish);
      }
    }

    if (window.PointerEvent) {
      handle.addEventListener("pointerdown", beginResize);
    } else {
      handle.addEventListener("mousedown", beginResize);
      handle.addEventListener("touchstart", beginResize, { passive: false });
    }
    handle.addEventListener("keydown", function (evt) {
      var nextHeight = _logDockResizeKeyHeight(evt);
      if (nextHeight === null) return;
      evt.preventDefault();
      if (logDockState.collapsed) setLogDockCollapsed(false);
      setLogDockHeight(nextHeight);
    });
    window.addEventListener("resize", function () {
      if (logDockState.height) {
        setLogDockHeight(logDockState.height, { persist: false });
      }
    });
  }

  function setLogDockCollapsed(flag, opts) {
    logDockState.collapsed = Boolean(flag);
    var shell = $("app");
    if (shell) {
      shell.setAttribute(
        "data-log-collapsed",
        logDockState.collapsed ? "true" : "false"
      );
    }
    if (!logDockState.collapsed) {
      rehydrateLogDockPanel(logDockState.activeBucket);
    }
    if (!opts || opts.persist !== false) {
      try {
        window.localStorage.setItem(
          LOG_DOCK_COLLAPSED_KEY,
          logDockState.collapsed ? "true" : "false",
        );
      } catch (_err) { /* Safari private mode etc. */ }
    }
  }

  // First-paint default: messages dock starts minimised so the operator
  // gets the full main-pane height for whichever workbench they open.
  // The preference is sticky once the operator toggles it manually.
  function _restoreLogDockCollapsed() {
    var stored = null;
    try {
      stored = window.localStorage.getItem(LOG_DOCK_COLLAPSED_KEY);
    } catch (_err) {
      stored = null;
    }
    var collapsed = stored === null ? true : stored === "true";
    setLogDockCollapsed(collapsed, { persist: false });
  }

  // Rebuild a log-dock panel's DOM from the in-memory bus snapshot.
  // Called when the operator opens / re-opens a bucket so the lazy
  // render path can skip DOM work for inactive buckets. Cheap when
  // the panel is fresh (``data-stale`` flag absent); a single pass at
  // most ~5000 rows otherwise.
  function rehydrateLogDockPanel(bucket) {
    if (!bucket) return;
    var host = $("log-panel-" + bucket);
    if (!host) return;
    if (host.dataset.stale !== "1" && host.childElementCount > 0) {
      // Already up to date — nothing to do.
      return;
    }
    host.innerHTML = "";
    delete host.dataset.stale;
    ensureLogDockHostDelegation(host);
    var rows = logBus.snapshot(bucket) || [];
    var domCap = bucket === "apdu" ? 5000 : 500;
    if (rows.length > domCap) rows = rows.slice(rows.length - domCap);
    for (var i = 0; i < rows.length; i++) {
      _logDockAppendRowSync(host, bucket, rows[i]);
    }
    host.scrollTop = host.scrollHeight;
  }

  // Internal: synchronous row append that bypasses the lazy-render
  // gate. Used by ``rehydrateLogDockPanel`` and
  // ``appendLogDockRow``'s active-tab fast-path. The two were one
  // function pre-lazy-render; splitting them keeps the hot path
  // (live append) free of the snapshot scaffolding.
  function _logDockAppendRowSync(host, bucket, row) {
    var el = document.createElement("div");
    el.className = "log-dock-row log-dock-row--"
      + String(row.level || "info").toLowerCase();
    el.setAttribute("tabindex", "0");
    el.setAttribute("role", "listitem");
    el.dataset.logBucket = bucket;
    el.dataset.logTs = formatTime(row.ts);
    el.dataset.logSource = String(row.source || "");
    el.dataset.logMessage = String(row.message || "");
    el.title = "Double-click or press the copy button to copy this row";
    wireLogDockRowDblclick(el);
    var ts = document.createElement("span");
    ts.className = "log-dock-row-ts";
    ts.textContent = formatTime(row.ts);
    var src = document.createElement("span");
    src.className = "log-dock-row-src";
    src.textContent = row.source || "";
    var msg = document.createElement("span");
    msg.className = "log-dock-row-msg";
    msg.textContent = row.message || "";
    var copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "log-dock-row-copy";
    copyBtn.setAttribute("aria-label", "Copy this row to clipboard");
    copyBtn.title = "Copy row";
    copyBtn.textContent = "Copy";
    el.appendChild(ts);
    el.appendChild(src);
    el.appendChild(msg);
    el.appendChild(copyBtn);
    host.appendChild(el);
    var domCap = bucket === "apdu" ? 5000 : 500;
    while (host.childElementCount > domCap) {
      host.removeChild(host.firstChild);
    }
  }

  // Resolve which bucket the operator means when they hit "Copy" or
  // press Ctrl/Cmd+C — always the visible (active) tab, falling back
  // to "messages" if the dock is in some unexpected state.
  function copyActiveBucketToClipboard() {
    var bucket = logDockState.activeBucket || "messages";
    var rows = logBus.snapshot(bucket);
    if (!rows || rows.length === 0) {
      // Surface an info-level breadcrumb so the operator gets feedback
      // ("nothing to copy") instead of a silent click.
      logBus.emit({
        level: "info",
        source: "log-dock",
        message: "Nothing to copy: " + bucket + " bucket is empty.",
      });
      return Promise.resolve(false);
    }
    var text = formatLogRowsForClipboard(rows);
    return copyTextToClipboard(text).then(function (ok) {
      var copyBtn = $("log-dock-copy");
      if (ok && copyBtn) {
        flashLogDockCopiedAck(copyBtn);
      }
      logBus.emit({
        level: ok ? "info" : "warn",
        source: "log-dock",
        message: ok
          ? ("Copied " + rows.length + " row(s) from " + bucket + " to clipboard.")
          : ("Copy failed: clipboard API rejected the write (" + bucket + ")"),
      });
      return ok;
    });
  }
  window.YggdraSimCopyActiveLogBucket = copyActiveBucketToClipboard;

  function wireLogDock() {
    document.querySelectorAll(".log-dock-tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        var bucket = tab.getAttribute("data-log-tab");
        if (bucket) activateLogTab(bucket);
      });
    });
    var copyBtn = $("log-dock-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        copyActiveBucketToClipboard();
      });
    }
    var clearBtn = $("log-dock-clear");
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        logBus.clear(null);
      });
    }
    var toggleBtn = $("log-dock-toggle");
    if (toggleBtn) {
      toggleBtn.addEventListener("click", function () {
        setLogDockCollapsed(!logDockState.collapsed);
      });
    }
    // Ctrl/Cmd+C while focus is inside the dock copies the active
    // bucket — but only when the operator has NOT made a manual text
    // selection. If a selection exists we let the browser handle it
    // (so partial-row copies still work as expected).
    var dockEl = $("log-dock");
    if (dockEl) {
      dockEl.addEventListener("keydown", function (evt) {
        var isCopyKey = (evt.key === "c" || evt.key === "C")
          && (evt.ctrlKey || evt.metaKey)
          && !evt.altKey;
        if (!isCopyKey) return;
        var sel = window.getSelection ? window.getSelection() : null;
        if (sel && !sel.isCollapsed && sel.toString().length > 0) {
          // Browser will handle the selection-copy itself.
          return;
        }
        evt.preventDefault();
        copyActiveBucketToClipboard();
      });
      wireLogDockResize(dockEl);
    }
    _restoreLogDockHeight();
    logBus.subscribe(function (event) {
      if (event.type === "append") {
        appendLogDockRow(event.bucket, event.row);
      } else if (event.type === "clear") {
        clearLogDockBucket(event.bucket);
      }
      applyLogCounts(logBus.counts());
    });
    applyLogCounts(logBus.counts());
    activateLogTab(logDockState.activeBucket);
    _restoreLogDockCollapsed();
  }

  // -- Live APDU bus (server-side recorder bridge) ------------------------
  //
  // The backend's ``apdu_recorder`` singleton fans every wire-level
  // exchange that flows through ``card_backend.create_card_connection``
  // out via the ``/api/events/apdu`` WebSocket. We open the socket once
  // at init, replay the recent buffer the backend pushed first, then
  // append every subsequent live exchange to the bottom-dock APDU
  // bucket.
  //
  // Failure modes — all silent so the GUI keeps working when the
  // operator is offline / no card is connected:
  //   * Auth rejected     → recorder service goes dark; log a single
  //                          warn-level breadcrumb and stop trying.
  //   * Network drop      → exponential back-off reconnect (cap 30 s).
  //   * Browser idle tab  → ping frame keeps the proxy from killing
  //                          the socket; we ignore them on receive.

  var apduStreamState = {
    socket: null,
    backoffMs: 1000,
    reconnectTimerId: null,
    closedByApp: false,
  };

  function formatApduFrameForBus(frame) {
    if (!frame || frame.event !== "apdu") return null;
    var apdu = String(frame.apdu || "");
    var data = String(frame.data || "");
    var sw = String(frame.sw || "");
    var elapsed = (typeof frame.elapsed_ms === "number")
      ? (" · " + frame.elapsed_ms.toFixed(2) + " ms")
      : "";
    // Compact one-line representation: ``→ 00A4040007 A0000000871002 · sw=9000 · 1.42 ms``
    // The pretty colours are owned by the dock CSS (``log-dock-row--apdu``).
    var head = "→ " + apdu;
    var tail = " · sw=" + (sw || "????") + elapsed;
    if (data.length > 0) {
      tail = " · ← " + data + tail;
    }
    return head + tail;
  }

  function openApduEventStream() {
    clearApduReconnectTimer();
    if (apduStreamState.socket) {
      var state = apduStreamState.socket.readyState;
      if (state === WebSocket.CONNECTING || state === WebSocket.OPEN) return;
      apduStreamState.socket = null;
    }
    var token = (typeof getStoredToken === "function") ? getStoredToken() : "";
    if (!token) {
      // No token yet — the GUI will retry once the bootstrap finishes.
      return;
    }
    var scheme = window.location.protocol === "https:" ? "wss" : "ws";
    var url = scheme + "://" + window.location.host
      + "/api/events/apdu?t=" + encodeURIComponent(token);
    var sock;
    try {
      sock = new WebSocket(url);
    } catch (_err) {
      // Browser refused to construct the socket (e.g. CSP). Fall back
      // to silent — we don't want to spam the user about this.
      return;
    }
    apduStreamState.socket = sock;
    apduStreamState.closedByApp = false;

    sock.onopen = function () {
      if (apduStreamState.socket !== sock) {
        try { sock.close(); } catch (_err) {}
        return;
      }
      apduStreamState.backoffMs = 1000;
      logBus.emit({
        level: "info",
        source: "apdu-bus",
        message: "live APDU stream connected",
      });
    };
    sock.onmessage = function (event) {
      if (apduStreamState.socket !== sock) return;
      var frame;
      try { frame = JSON.parse(event.data); } catch (_err) { return; }
      if (!frame || frame.event === "ping") return;
      if (frame.event !== "apdu") return;
      var line = formatApduFrameForBus(frame);
      if (!line) return;
      // No ``data: frame`` attached: the message string already holds
      // every field a viewer needs, and stashing the raw frame on
      // every row inflates the bus by ~50 % at the 5000-row APDU cap
      // (≈ 5 MB of redundant objects after a long session). The
      // ``data`` slot stays available for buckets that genuinely use
      // it (e.g. error rows that want the full diagnostic payload).
      logBus.emit({
        level: "apdu",
        source: String(frame.source || "card"),
        message: line,
      });
    };
    sock.onerror = function () {
      // Don't spam the bus on every transient failure — onclose fires
      // immediately after and that's where we surface the reconnect.
    };
    sock.onclose = function () {
      if (apduStreamState.socket === sock) {
        apduStreamState.socket = null;
      }
      var closedByApp = apduStreamState.closedByApp;
      // Detach handlers so the dead WS + buffered frames go away
      // even if the reconnect timer is paused (e.g. tab backgrounded
      // for hours). Otherwise each reconnect cycle pinned another
      // closure chain in memory.
      detachApduSocketHandlers(sock);
      if (closedByApp) return;
      scheduleApduReconnect();
    };
  }

  function clearApduReconnectTimer() {
    if (apduStreamState.reconnectTimerId === null) return;
    clearTimeout(apduStreamState.reconnectTimerId);
    apduStreamState.reconnectTimerId = null;
  }

  function scheduleApduReconnect() {
    clearApduReconnectTimer();
    var nextDelay = apduStreamState.backoffMs;
    apduStreamState.backoffMs = Math.min(nextDelay * 2, 30000);
    apduStreamState.reconnectTimerId = setTimeout(function () {
      apduStreamState.reconnectTimerId = null;
      openApduEventStream();
    }, nextDelay);
  }

  function detachApduSocketHandlers(sock) {
    if (!sock) return;
    sock.onmessage = null;
    sock.onopen = null;
    sock.onerror = null;
    sock.onclose = null;
  }

  function closeApduEventStream() {
    apduStreamState.closedByApp = true;
    clearApduReconnectTimer();
    var sock = apduStreamState.socket;
    apduStreamState.socket = null;
    if (!sock) return;
    detachApduSocketHandlers(sock);
    try { sock.close(); } catch (_err) {}
  }

  // Expose for tests + ad-hoc operator debugging via DevTools.
  window.YggdraSimApduStream = {
    open: openApduEventStream,
    close: closeApduEventStream,
    formatFrame: formatApduFrameForBus,
    state: apduStreamState,
  };

  window.addEventListener("pagehide", closeApduEventStream);
  window.addEventListener("beforeunload", closeApduEventStream);

  // -- About panel: guides catalogue + viewer ------------------------------
  //
  // The About panel deep-links into every operator and developer guide
  // shipped with the build. The catalog comes from /api/guides; the
  // viewer is a self-contained modal that fetches the markdown source
  // for the selected entry and renders it with a tiny purpose-built
  // markdown converter (we keep dependencies out of the install).

  var aboutGuidesState = {
    loaded: false,
    inflight: false,
    guides: null,
  };

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Minimal markdown -> HTML converter. We deliberately keep this
  // tiny: only the constructs that show up in repository guides
  // (headings, fenced code, inline code, lists, links, blockquotes,
  // bold/italic, horizontal rules). Anything we don't recognise
  // falls through as escaped text — safe by default.
  function renderMarkdownToHtml(md) {
    var src = String(md || "");
    var out = [];
    var lines = src.split(/\r?\n/);
    var inFence = false;
    var fenceLang = "";
    var fenceLines = [];
    var listStack = []; // each entry: {type: "ul"|"ol", indent: number}
    var paragraph = [];

    function flushParagraph() {
      if (paragraph.length === 0) return;
      var text = paragraph.join(" ");
      out.push("<p>" + renderInline(text) + "</p>");
      paragraph = [];
    }
    function closeListsTo(targetIndent) {
      while (listStack.length > 0 && listStack[listStack.length - 1].indent >= targetIndent) {
        var top = listStack.pop();
        out.push(top.type === "ol" ? "</ol>" : "</ul>");
      }
    }
    function closeAllLists() {
      while (listStack.length > 0) {
        var top = listStack.pop();
        out.push(top.type === "ol" ? "</ol>" : "</ul>");
      }
    }
    function renderInline(text) {
      // Inline code ``…`` first so its contents are not formatted.
      var pieces = [];
      var rest = text;
      var safeRe = /`([^`]+)`/;
      var match = safeRe.exec(rest);
      while (match) {
        pieces.push(applyInline(rest.substring(0, match.index)));
        pieces.push("<code>" + escapeHtml(match[1]) + "</code>");
        rest = rest.substring(match.index + match[0].length);
        match = safeRe.exec(rest);
      }
      pieces.push(applyInline(rest));
      return pieces.join("");
    }
    function applyInline(text) {
      var html = escapeHtml(text);
      // Links: [label](url)
      html = html.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, function (_m, label, url) {
        var safeUrl = url.indexOf("javascript:") === 0 ? "#" : url;
        return '<a href="' + safeUrl + '" target="_blank" rel="noopener">' + label + '</a>';
      });
      // Bold + italic. Bold first so the italic regex sees the residue.
      html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
      html = html.replace(/__([^_]+)__/g, "<strong>$1</strong>");
      html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
      html = html.replace(/(?:^|[\s(])_([^_]+)_(?=$|[\s.,;:!?)])/g, function (m, inner) {
        return m.charAt(0) === "_" ? "<em>" + inner + "</em>" : m.charAt(0) + "<em>" + inner + "</em>";
      });
      return html;
    }

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var fenceMatch = /^```([A-Za-z0-9_+\-]*)\s*$/.exec(line);
      if (fenceMatch) {
        if (inFence) {
          out.push(
            '<pre class="cc-doc-pre"><code class="cc-doc-code'
              + (fenceLang ? " language-" + escapeHtml(fenceLang) : "")
              + '">'
              + escapeHtml(fenceLines.join("\n"))
              + "</code></pre>"
          );
          inFence = false;
          fenceLang = "";
          fenceLines = [];
        } else {
          flushParagraph();
          closeAllLists();
          inFence = true;
          fenceLang = fenceMatch[1] || "";
          fenceLines = [];
        }
        continue;
      }
      if (inFence) {
        fenceLines.push(line);
        continue;
      }

      if (/^\s*$/.test(line)) {
        flushParagraph();
        closeAllLists();
        continue;
      }

      var hr = /^\s*(?:---|\*\*\*|___)\s*$/.test(line);
      if (hr) {
        flushParagraph();
        closeAllLists();
        out.push("<hr>");
        continue;
      }

      var heading = /^(\s*)(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
      if (heading) {
        flushParagraph();
        closeAllLists();
        var level = heading[2].length;
        out.push(
          "<h" + level + ' class="cc-doc-h' + level + '">'
            + renderInline(heading[3]) + "</h" + level + ">"
        );
        continue;
      }

      var blockquote = /^>\s?(.*)$/.exec(line);
      if (blockquote) {
        flushParagraph();
        closeAllLists();
        out.push("<blockquote>" + renderInline(blockquote[1]) + "</blockquote>");
        continue;
      }

      // GitHub-flavoured tables: a header line containing ``|`` followed
      // by a divider row of dashes (with optional ``:`` alignment markers)
      // and one or more body rows. The README modal previously fell
      // through to paragraph mode, so operators saw the raw pipes/dashes
      // bleed into the prose ("ASCII boxes look a bit off").
      if (line.indexOf("|") !== -1 && i + 1 < lines.length) {
        var dividerLine = lines[i + 1];
        var dividerRe =
          /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$/;
        if (dividerRe.test(dividerLine)) {
          flushParagraph();
          closeAllLists();

          var splitTableRow = function (raw) {
            // Strip the optional leading / trailing pipes so empty
            // edge columns don't appear, then split on the remaining
            // ``|`` separators.
            var stripped = String(raw)
              .replace(/^\s*\|/, "")
              .replace(/\|\s*$/, "");
            return stripped.split("|").map(function (cell) {
              return cell.trim();
            });
          };

          var headerCells = splitTableRow(line);
          var alignCells = splitTableRow(dividerLine).map(function (cell) {
            var leftAnchor = /^:/.test(cell);
            var rightAnchor = /:$/.test(cell);
            if (leftAnchor && rightAnchor) return "center";
            if (rightAnchor) return "right";
            if (leftAnchor) return "left";
            return "";
          });

          var bodyRows = [];
          var cursor = i + 2;
          while (cursor < lines.length) {
            var rowLine = lines[cursor];
            if (/^\s*$/.test(rowLine)) break;
            if (rowLine.indexOf("|") === -1) break;
            bodyRows.push(splitTableRow(rowLine));
            cursor++;
          }

          var html = ['<table class="cc-doc-table"><thead><tr>'];
          headerCells.forEach(function (cell, idx) {
            var alignAttr = alignCells[idx]
              ? ' class="cc-doc-align-' + alignCells[idx] + '" style="text-align: ' + alignCells[idx] + ';"'
              : "";
            html.push("<th" + alignAttr + ">" + renderInline(cell) + "</th>");
          });
          html.push("</tr></thead><tbody>");
          bodyRows.forEach(function (row) {
            html.push("<tr>");
            for (var k = 0; k < headerCells.length; k++) {
              var cellText = row[k] != null ? row[k] : "";
              var align2 = alignCells[k]
                ? ' class="cc-doc-align-' + alignCells[k] + '" style="text-align: ' + alignCells[k] + ';"'
                : "";
              html.push("<td" + align2 + ">" + renderInline(cellText) + "</td>");
            }
            html.push("</tr>");
          });
          html.push("</tbody></table>");
          out.push(html.join(""));

          i = cursor - 1;
          continue;
        }
      }

      var listMatch = /^(\s*)([-*+]|\d+\.)\s+(.*)$/.exec(line);
      if (listMatch) {
        flushParagraph();
        var indent = listMatch[1].length;
        var marker = listMatch[2];
        var content = listMatch[3];
        var listType = /^\d/.test(marker) ? "ol" : "ul";
        if (listStack.length === 0 || listStack[listStack.length - 1].indent < indent) {
          out.push("<" + listType + ' class="cc-doc-list">');
          listStack.push({ type: listType, indent: indent });
        } else if (listStack[listStack.length - 1].indent > indent) {
          closeListsTo(indent + 1);
          if (listStack.length === 0 || listStack[listStack.length - 1].indent !== indent) {
            out.push("<" + listType + ' class="cc-doc-list">');
            listStack.push({ type: listType, indent: indent });
          }
        }
        out.push("<li>" + renderInline(content) + "</li>");
        continue;
      }

      // Default: append to current paragraph buffer.
      paragraph.push(line.trim());
    }

    if (inFence) {
      out.push(
        '<pre class="cc-doc-pre"><code class="cc-doc-code">'
          + escapeHtml(fenceLines.join("\n"))
          + "</code></pre>"
      );
    }
    flushParagraph();
    closeAllLists();
    return out.join("\n");
  }

  function renderGuidesAboutPanel(guides) {
    var groupsRoot = document.getElementById("about-guides-groups");
    var statusEl = document.getElementById("about-guides-status");
    if (!groupsRoot) return;
    groupsRoot.innerHTML = "";
    if (!guides || guides.length === 0) {
      if (statusEl) statusEl.textContent = "no guides found in this build.";
      return;
    }
    if (statusEl) statusEl.textContent = "";

    // Preserve order from the backend (curated) but group by ``group``.
    var grouped = [];
    var seen = {};
    guides.forEach(function (g) {
      if (!g) return;
      if (!seen[g.group]) {
        seen[g.group] = { name: g.group, items: [] };
        grouped.push(seen[g.group]);
      }
      seen[g.group].items.push(g);
    });

    grouped.forEach(function (group) {
      var section = document.createElement("section");
      section.className = "about-guides-group";
      var heading = document.createElement("h3");
      heading.textContent = group.name;
      section.appendChild(heading);

      var grid = document.createElement("div");
      grid.className = "about-guides-grid";
      group.items.forEach(function (entry) {
        var card = document.createElement("button");
        card.type = "button";
        card.className = "about-guides-card";
        card.setAttribute("data-guide-id", entry.id);
        card.disabled = entry.available === false;
        if (entry.available === false) {
          card.title = "This guide is not bundled in the current build.";
        }
        var titleEl = document.createElement("div");
        titleEl.className = "about-guides-card-title";
        titleEl.textContent = entry.title;
        var blurbEl = document.createElement("div");
        blurbEl.className = "about-guides-card-blurb";
        blurbEl.textContent = entry.blurb || "";
        var metaEl = document.createElement("div");
        metaEl.className = "about-guides-card-meta";
        if (entry.available === false) {
          metaEl.textContent = "unavailable";
        } else {
          var kb = entry.bytes > 0 ? (entry.bytes / 1024).toFixed(1) + " KB" : "";
          metaEl.textContent = kb;
        }
        card.appendChild(titleEl);
        card.appendChild(blurbEl);
        card.appendChild(metaEl);
        card.addEventListener("click", function () {
          if (card.disabled) return;
          openGuideViewer(entry.id, entry.title);
        });
        grid.appendChild(card);
      });
      section.appendChild(grid);
      groupsRoot.appendChild(section);
    });
  }

  async function loadGuidesForAboutPanel() {
    if (aboutGuidesState.inflight) return;
    if (aboutGuidesState.loaded) {
      renderGuidesAboutPanel(aboutGuidesState.guides);
      return;
    }
    aboutGuidesState.inflight = true;
    var statusEl = document.getElementById("about-guides-status");
    if (statusEl) statusEl.textContent = "loading guides…";
    try {
      var resp = await apiFetch("/api/guides");
      var guides = (resp && resp.guides) || [];
      aboutGuidesState.guides = guides;
      aboutGuidesState.loaded = true;
      renderGuidesAboutPanel(guides);
    } catch (err) {
      if (statusEl) {
        statusEl.textContent = "Failed to load guides catalogue: "
          + (err && err.message ? err.message : err);
      }
      logBus.emit({
        level: "error",
        source: "guides",
        message: "list failed: " + (err && err.message ? err.message : err),
      });
    } finally {
      aboutGuidesState.inflight = false;
    }
  }

  // -- Document viewer modal (used by About guides + future surfaces) ------

  var docViewerState = {
    activeId: null,
    activeMarkdown: "",
  };

  function setDocViewerVisible(visible) {
    var modal = document.getElementById("doc-modal");
    if (!modal) return;
    modal.setAttribute("data-state", visible ? "open" : "hidden");
    modal.setAttribute("aria-hidden", visible ? "false" : "true");
  }

  function openGuideViewer(guideId, title) {
    var modal = document.getElementById("doc-modal");
    var titleEl = document.getElementById("doc-modal-title");
    var pathEl = document.getElementById("doc-modal-path");
    var bodyEl = document.getElementById("doc-modal-body");
    if (!modal || !bodyEl) return;
    if (titleEl) titleEl.textContent = title || "Document";
    if (pathEl) pathEl.textContent = "loading…";
    bodyEl.innerHTML = '<div class="cc-doc-loading">loading guide…</div>';
    setDocViewerVisible(true);

    apiFetch("/api/guides/" + encodeURIComponent(guideId))
      .then(function (resp) {
        if (!resp) {
          bodyEl.innerHTML = '<div class="cc-doc-error">empty response</div>';
          return;
        }
        docViewerState.activeId = guideId;
        docViewerState.activeMarkdown = String(resp.markdown || "");
        if (titleEl) titleEl.textContent = resp.title || title || "Document";
        if (pathEl) pathEl.textContent = resp.path || "";
        bodyEl.innerHTML = renderMarkdownToHtml(resp.markdown || "");
        bodyEl.scrollTop = 0;
      })
      .catch(function (err) {
        bodyEl.innerHTML = '<div class="cc-doc-error">'
          + escapeHtml("Failed to open guide: " + (err && err.message ? err.message : err))
          + "</div>";
      });
  }

  function closeGuideViewer() {
    setDocViewerVisible(false);
    docViewerState.activeId = null;
    docViewerState.activeMarkdown = "";
  }

  function wireDocViewer() {
    var modal = document.getElementById("doc-modal");
    if (!modal) return;
    var closeBtn = document.getElementById("doc-modal-close");
    if (closeBtn) closeBtn.addEventListener("click", closeGuideViewer);
    var copyBtn = document.getElementById("doc-modal-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        var src = docViewerState.activeMarkdown;
        if (!src) return;
        if (typeof copyTextToClipboard === "function") {
          copyTextToClipboard(src);
        } else if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(src).catch(function () {});
        }
        copyBtn.classList.add("is-copied");
        setTimeout(function () { copyBtn.classList.remove("is-copied"); }, 700);
      });
    }
    modal.addEventListener("click", function (ev) {
      var target = ev.target;
      if (target && target.getAttribute && target.getAttribute("data-doc-close") === "true") {
        closeGuideViewer();
      }
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && modal.getAttribute("data-state") === "open") {
        closeGuideViewer();
      }
    });
  }

  // Expose helpers for tests + ad-hoc DevTools poking.
  window.YggdraSimGuides = {
    load: loadGuidesForAboutPanel,
    open: openGuideViewer,
    close: closeGuideViewer,
    renderMarkdown: renderMarkdownToHtml,
  };

  // -- Host shell (Advanced > Host shell) ----------------------------------
  //
  // Free-form interactive PTY backed by /api/host-shell. The capabilities
  // endpoint decides whether the panel renders or shows the disabled
  // notice. Decoded AT lines (when the operator opts in) flow on the
  // same WebSocket as JSON text frames; we keep the side panel local to
  // the view so it doesn't pollute the global log dock.

  var hostShellState = {
    term: null,
    fitAddon: null,
    socket: null,
    capability: null,
    devices: [],
    decodeEnabled: false,
    decodedRowsMax: 250,
  };

  async function loadHostShellCapabilities() {
    var enabledRoot = $("host-shell-enabled");
    var disabledRoot = $("host-shell-disabled");
    var reasonEl = $("host-shell-disabled-reason");
    if (!enabledRoot || !disabledRoot) return null;
    try {
      var data = await apiFetch("/api/host-shell/capabilities");
      hostShellState.capability = data;
      if (!data.supported || !data.enabled) {
        enabledRoot.hidden = true;
        disabledRoot.hidden = false;
        if (reasonEl && data.reason) {
          reasonEl.textContent = data.reason;
        }
        return data;
      }
      enabledRoot.hidden = false;
      disabledRoot.hidden = true;
      setText("host-shell-status", "idle · " + (data.shell || "/bin/bash"));
      return data;
    } catch (err) {
      enabledRoot.hidden = true;
      disabledRoot.hidden = false;
      if (reasonEl) {
        reasonEl.textContent = "capability probe failed: " + (err && err.message ? err.message : err);
      }
      return null;
    }
  }

  async function loadHostShellDevices() {
    var sel = $("host-shell-device");
    if (!sel) return;
    sel.innerHTML = "";
    try {
      var data = await apiFetch("/api/host-shell/devices");
      hostShellState.devices = (data && data.devices) || [];
      if (hostShellState.devices.length === 0) {
        var blank = document.createElement("option");
        blank.value = "";
        blank.textContent = "(no /dev/tty* found)";
        sel.appendChild(blank);
        return;
      }
      hostShellState.devices.forEach(function (entry) {
        var opt = document.createElement("option");
        opt.value = entry.path;
        var label = entry.path;
        if (entry.label) {
          label = label + "  ·  " + entry.label;
        }
        opt.textContent = label;
        sel.appendChild(opt);
      });
    } catch (err) {
      var failOpt = document.createElement("option");
      failOpt.value = "";
      failOpt.textContent = "(failed to enumerate)";
      sel.appendChild(failOpt);
    }
  }

  function ensureHostShellTerminal() {
    if (hostShellState.term) return hostShellState.term;
    if (typeof window.Terminal !== "function") {
      setText("host-shell-status", "xterm.js failed to load.");
      return null;
    }
    var host = $("host-shell-host");
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
      try { fitAddon.fit(); } catch (_err) { /* not measured yet */ }
    }
    hostShellState.term = term;
    hostShellState.fitAddon = fitAddon;
    term.onData(function (data) {
      var sock = hostShellState.socket;
      if (sock && sock.readyState === 1) {
        sock.send(JSON.stringify({ type: "stdin", data: data }));
      }
    });
    return term;
  }

  function sendHostShellResize() {
    var term = hostShellState.term;
    var sock = hostShellState.socket;
    if (!term || !sock || sock.readyState !== 1) return;
    sock.send(JSON.stringify({
      type: "resize",
      rows: term.rows,
      cols: term.cols,
    }));
  }

  function startHostShell() {
    if (!hostShellState.capability || !hostShellState.capability.enabled) {
      setText("host-shell-status", "disabled — set YGGDRASIM_GUI_HOST_SHELL=1");
      return;
    }
    var term = ensureHostShellTerminal();
    if (!term) return;
    if (hostShellState.socket && hostShellState.socket.readyState === 1) {
      hostShellState.socket.close();
    }
    term.clear();
    term.writeln("[yggdrasim-gui] starting host shell …");

    var token = getStoredToken();
    if (!token) {
      setText("host-shell-status", "missing token — reload the GUI.");
      return;
    }

    var scheme = window.location.protocol === "https:" ? "wss" : "ws";
    var rows = term.rows || 30;
    var cols = term.cols || 120;
    var url = scheme + "://" + window.location.host + "/api/host-shell"
      + "?t=" + encodeURIComponent(token)
      + "&rows=" + rows + "&cols=" + cols;
    var sock = new WebSocket(url);
    sock.binaryType = "arraybuffer";
    hostShellState.socket = sock;

    var startBtn = $("host-shell-start");
    var stopBtn = $("host-shell-stop");
    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
    setText("host-shell-status", "connecting…");

    sock.onopen = function () {
      setText("host-shell-status", "running");
      sendHostShellResize();
      if (hostShellState.decodeEnabled) {
        sock.send(JSON.stringify({ type: "at_decode", enabled: true }));
      }
    };
    sock.onmessage = function (event) {
      if (typeof event.data === "string") {
        try {
          var msg = JSON.parse(event.data);
          if (msg && msg.event === "spawned") {
            setText("host-shell-status", "running · pid=" + msg.pid + " · " + (msg.shell || ""));
            return;
          }
          if (msg && msg.event === "exit") {
            term.writeln("\r\n[yggdrasim-gui] host shell exited.");
            setText("host-shell-status", "exited");
            return;
          }
          if (msg && msg.event === "error") {
            term.writeln("\r\n[yggdrasim-gui] error: " + msg.message);
            setText("host-shell-status", "error: " + msg.message);
            return;
          }
          if (msg && msg.event === "at_decoded") {
            appendHostShellDecoded(msg);
            return;
          }
        } catch (_err) {
          term.write(event.data);
        }
        return;
      }
      var bytes = new Uint8Array(event.data);
      term.write(bytes);
    };
    sock.onclose = function () {
      setText("host-shell-status", "closed");
      if (startBtn) startBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      hostShellState.socket = null;
      sock.onmessage = null;
      sock.onopen = null;
      sock.onerror = null;
      sock.onclose = null;
    };
    sock.onerror = function () {
      setText("host-shell-status", "socket error");
    };
  }

  function stopHostShell() {
    if (hostShellState.socket) {
      try { hostShellState.socket.close(); } catch (_err) { /* already gone */ }
    }
  }

  function insertHostShellDevicePath() {
    var sel = $("host-shell-device");
    var path = sel ? sel.value : "";
    if (!path) {
      setText("host-shell-status", "pick a device first.");
      return;
    }
    var sock = hostShellState.socket;
    if (!sock || sock.readyState !== 1) {
      setText("host-shell-status", "start the session first.");
      return;
    }
    sock.send(JSON.stringify({ type: "stdin", data: path }));
  }

  function setHostShellDecode(enabled) {
    hostShellState.decodeEnabled = !!enabled;
    var pane = $("host-shell-decoded");
    if (pane) {
      pane.hidden = !hostShellState.decodeEnabled;
    }
    var sock = hostShellState.socket;
    if (sock && sock.readyState === 1) {
      sock.send(JSON.stringify({ type: "at_decode", enabled: hostShellState.decodeEnabled }));
    }
  }

  function appendHostShellDecoded(msg) {
    var rows = $("host-shell-decoded-rows");
    if (!rows) return;
    var row = document.createElement("div");
    row.className = "host-shell-decoded-row dir-" + (msg.direction || "?");
    var glyph = msg.direction === "tx" ? "&gt;" : (msg.direction === "rx" ? "&lt;" : "·");
    var kindLabel = (msg.kind || "").replace(/_/g, " ");
    row.innerHTML = ''
      + '<span class="host-shell-decoded-glyph">' + glyph + '</span>'
      + '<span class="host-shell-decoded-kind">' + escapeHtml(kindLabel) + '</span>'
      + '<span class="host-shell-decoded-raw">' + escapeHtml(String(msg.raw || "")) + '</span>'
      + '<pre class="host-shell-decoded-detail">' + escapeHtml(JSON.stringify(msg.decoded || {}, null, 2)) + '</pre>';
    row.addEventListener("click", function () {
      var apduHex = (msg.decoded && msg.decoded.apdu_hex) || "";
      if (apduHex && navigator.clipboard) {
        navigator.clipboard.writeText(apduHex).catch(function () { /* clipboard denied */ });
      }
    });
    rows.appendChild(row);
    while (rows.children.length > hostShellState.decodedRowsMax) {
      rows.removeChild(rows.firstChild);
    }
    rows.scrollTop = rows.scrollHeight;
  }

  function clearHostShellDecoded() {
    var rows = $("host-shell-decoded-rows");
    if (rows) rows.innerHTML = "";
  }

  function wireHostShellPanel() {
    var startBtn = $("host-shell-start");
    var stopBtn = $("host-shell-stop");
    if (!startBtn) return;
    startBtn.addEventListener("click", startHostShell);
    if (stopBtn) stopBtn.addEventListener("click", stopHostShell);

    var refreshBtn = $("host-shell-device-refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        loadHostShellDevices();
      });
    }
    var insertBtn = $("host-shell-device-insert");
    if (insertBtn) {
      insertBtn.addEventListener("click", insertHostShellDevicePath);
    }
    var decodeToggle = $("host-shell-decode-toggle");
    if (decodeToggle) {
      decodeToggle.addEventListener("change", function () {
        setHostShellDecode(decodeToggle.checked);
      });
    }
    var clearBtn = $("host-shell-decoded-clear");
    if (clearBtn) {
      clearBtn.addEventListener("click", clearHostShellDecoded);
    }

    window.addEventListener("resize", function () {
      if (hostShellState.fitAddon) {
        try { hostShellState.fitAddon.fit(); } catch (_err) { /* xterm not ready */ }
        sendHostShellResize();
      }
    });
  }

  // -- Init ----------------------------------------------------------------

  function init() {
    captureTokenFromUrl();
    wireTopbar();
    wireTerminalPanel();
    wireHostShellPanel();
    wireLiveReadersPanel();
    wireCardBridgePanel();
    wireCommandCenter();
    wireReaderPane();
    wireLogDock();
    wireDocViewer();
    if (typeof scp03PopoutEscapeBootstrap === "function") {
      scp03PopoutEscapeBootstrap();
    }
    openApduEventStream();
    showView("overview");
    setApiBadge("unknown", "probing…");
    setStatusAction("initialising…");
    setStatusReaders("–");
    setStatusSessions("–");
    setStatusActivity("–");

    loadHealth();
    loadBackend();
    loadCommandCatalogue();
    loadCardBridgeStatus();
    scheduleHealthPoll();
    refreshReaderPane();
    // Top-bar reader strip — installs its own refresh button handler,
    // does the initial /api/live/readers fetch, and starts the 5 s
    // poll loop. Pauses when the page is hidden to spare PC/SC.
    readerBarBootstrap();
    // SA-G8: Command Center sidebar collapse handle. Mirrors the
    // existing log-dock collapse pattern — persists across reloads
    // via localStorage["yggdrasim:cc-sidebar-collapsed"].
    sidebarCollapseBootstrap();
    // Top-bar collapse handle. Same pattern as the sidebar; lets the
    // operator hide brand / reader strip / breadcrumbs / theme picker
    // to recover the full vertical extent for a workbench.
    topbarCollapseBootstrap();
    appCloseBootstrap();
    logBus.emit({
      level: "info",
      source: "system",
      message: "GUI initialised — Command Center ready.",
    });

    document.getElementById("app").setAttribute("data-ready", "true");
  }

  var SIDEBAR_COLLAPSED_KEY = "yggdrasim:cc-sidebar-collapsed";

  function sidebarCollapseBootstrap() {
    var btn = document.getElementById("sidebar-collapse-toggle");
    var shell = document.getElementById("app");
    if (!btn || !shell) return;
    function _stored() {
      try {
        return window.localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "true";
      } catch (_err) {
        return false;
      }
    }
    function _apply(collapsed) {
      shell.setAttribute(
        "data-sidebar-collapsed",
        collapsed ? "true" : "false",
      );
      btn.setAttribute(
        "aria-label",
        collapsed
          ? "Show Command Center sidebar"
          : "Collapse Command Center sidebar",
      );
      btn.title = collapsed
        ? "Show the Command Center sidebar."
        : "Hide the Command Center sidebar. Click again to bring it back.";
      try {
        window.localStorage.setItem(
          SIDEBAR_COLLAPSED_KEY,
          collapsed ? "true" : "false",
        );
      } catch (_err) {}
    }
    _apply(_stored());
    btn.addEventListener("click", function () {
      var currently = shell.getAttribute("data-sidebar-collapsed") === "true";
      _apply(!currently);
    });
  }

  var TOPBAR_COLLAPSED_KEY = "yggdrasim:topbar-collapsed";

  function topbarCollapseBootstrap() {
    var btn = document.getElementById("topbar-collapse-toggle");
    var shell = document.getElementById("app");
    if (!btn || !shell) return;
    function _stored() {
      try {
        return window.localStorage.getItem(TOPBAR_COLLAPSED_KEY) === "true";
      } catch (_err) {
        return false;
      }
    }
    function _apply(collapsed) {
      shell.setAttribute(
        "data-topbar-collapsed",
        collapsed ? "true" : "false",
      );
      btn.setAttribute(
        "aria-label",
        collapsed ? "Show top bar" : "Collapse top bar",
      );
      btn.title = collapsed
        ? "Show the top bar."
        : "Hide the top bar to maximise the working area. Click again to bring it back.";
      try {
        window.localStorage.setItem(
          TOPBAR_COLLAPSED_KEY,
          collapsed ? "true" : "false",
        );
      } catch (_err) {}
    }
    _apply(_stored());
    btn.addEventListener("click", function () {
      var currently = shell.getAttribute("data-topbar-collapsed") === "true";
      _apply(!currently);
    });
  }

  function appCloseBootstrap() {
    var btn = document.getElementById("app-close-button");
    if (!btn) return;
    btn.addEventListener("click", async function () {
      btn.disabled = true;
      try {
        if (
          window.pywebview
          && window.pywebview.api
          && typeof window.pywebview.api.close_app === "function"
        ) {
          var closed = await window.pywebview.api.close_app();
          if (closed) return;
        }
        window.close();
        setTimeout(function () {
          btn.disabled = false;
          if (!window.closed && typeof setStatusAction === "function") {
            setStatusAction("Close this browser tab/window to exit the web view.");
          }
        }, 150);
      } catch (_err) {
        btn.disabled = false;
        if (typeof setStatusError === "function") {
          setStatusError("Application close request failed.");
        }
      }
    });
  }
