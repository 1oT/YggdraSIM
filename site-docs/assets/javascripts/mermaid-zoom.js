/*
 * mermaid-zoom.js
 *
 * Click-to-enlarge lightbox for every Mermaid diagram on the site.
 *
 * Design notes
 * ------------
 *
 * Material for MkDocs renders Mermaid diagrams into a *closed* shadow
 * root attached to a fresh <div class="mermaid">. That means:
 *
 *   1. The original <pre class="mermaid"> is removed from the DOM and
 *      replaced with a new <div class="mermaid">, so by the time our
 *      DOMContentLoaded runs, the diagram source is gone from the
 *      light DOM.
 *   2. The rendered SVG lives inside a closed shadow root, so
 *      querySelector("svg"), outerHTML, and .shadowRoot cannot reach
 *      it from outside.
 *
 * To work around both, this script:
 *
 *   A. Captures every <pre class="mermaid"> source text synchronously
 *      the moment the <script> tag is parsed (before Material's
 *      DOMContentLoaded handler strips the class and fires its
 *      pipeline).
 *   B. Uses a MutationObserver that pairs each removed <pre> with the
 *      new <div class="mermaid"> that replaces it in the same
 *      mutation record, storing the source text on the div via a
 *      WeakMap.
 *   C. On click, renders a *fresh* SVG from the stored source using
 *      window.mermaid.render (which Material has already loaded
 *      globally) and injects that into the lightbox's light DOM.
 *
 * Debugging hooks (no flags required -- all info-level logs are on):
 *
 *   window.MermaidZoom.rescan();          // re-decorate containers
 *   window.MermaidZoom.test();            // open the first diagram
 *   window.MermaidZoom.sources();         // dump captured sources
 *   window.MermaidZoom.open(<element>);   // force-open the lightbox
 */

(function () {
  "use strict";

  var BUILD = "v3-shadow-aware";

  try {
    console.log("[mermaid-zoom] script loaded, build=" + BUILD);
  } catch (error) {
    /* ignored */
  }

  var DECORATED_FLAG = "mermaidZoomDecorated";
  var LIGHTBOX_CLASS = "mermaid-lightbox";
  var BODY_OPEN_CLASS = "mermaid-lightbox-open";
  var CONTAINER_SELECTOR = "pre.mermaid, div.mermaid";
  var DEBUG_PREFIX = "[mermaid-zoom]";
  var FIRST_DECORATE_LOGGED = false;
  var RENDER_ID_COUNTER = 0;
  var DELEGATION_INSTALLED = false;

  /*
   * Source cache. INDEXED_SOURCES holds the snapshot taken at script
   * parse time (document order). containerSourceMap holds the 1:1
   * mapping from a Material-created <div class="mermaid"> to its
   * source text, populated by the mutation observer.
   */
  var INDEXED_SOURCES = [];
  var containerSourceMap = new WeakMap();

  function info() {
    var args = Array.prototype.slice.call(arguments);
    args.unshift(DEBUG_PREFIX);
    try {
      console.log.apply(console, args);
    } catch (error) {
      /* ignored */
    }
  }

  function warn() {
    var args = Array.prototype.slice.call(arguments);
    args.unshift(DEBUG_PREFIX);
    try {
      console.warn.apply(console, args);
    } catch (error) {
      /* ignored */
    }
  }

  function snapshotSources() {
    try {
      var pres = document.querySelectorAll("pre.mermaid");
      for (var i = 0; i < pres.length; i += 1) {
        var code = pres[i].querySelector("code");
        var node = code !== null && code !== undefined ? code : pres[i];
        var text = (node.textContent || "").replace(/^\s+|\s+$/g, "");
        INDEXED_SOURCES.push(text);
      }
      info(
        "snapshot: captured",
        INDEXED_SOURCES.length,
        "pre.mermaid source(s) before Material's transform"
      );
    } catch (error) {
      warn("snapshot failed:", error);
    }
  }

  snapshotSources();

  /*
   * Walk the document in its current order and assign the positional
   * snapshot to every .mermaid container that does not yet have a
   * source attached. Used as a fallback when the mutation observer
   * misses a replaceWith pair (first one before the observer was
   * installed).
   */
  function backfillSourcesPositional() {
    var all = document.querySelectorAll(CONTAINER_SELECTOR);
    var assigned = 0;
    for (var i = 0; i < all.length && i < INDEXED_SOURCES.length; i += 1) {
      if (!containerSourceMap.has(all[i])) {
        containerSourceMap.set(all[i], INDEXED_SOURCES[i]);
        assigned += 1;
      }
    }
    if (assigned > 0) {
      info("backfill: assigned source text to", assigned, "container(s)");
    }
  }

  function installReplacementObserver() {
    if (typeof MutationObserver === "undefined") {
      return;
    }
    var observer = new MutationObserver(function (records) {
      var found = 0;
      for (var i = 0; i < records.length; i += 1) {
        var record = records[i];
        if (record.removedNodes === null || record.removedNodes === undefined) {
          continue;
        }
        if (record.addedNodes === null || record.addedNodes === undefined) {
          continue;
        }
        /*
         * Material's e.replaceWith(r) generates a mutation record with
         * exactly one removed and one added node in the same parent.
         */
        for (var r = 0; r < record.removedNodes.length; r += 1) {
          var removed = record.removedNodes[r];
          if (removed.nodeType !== 1) {
            continue;
          }
          if (removed.tagName !== "PRE") {
            continue;
          }
          /*
           * Material has already stripped the "mermaid" class from the
           * pre by this point, so we recognise it by its structure
           * (single <code> child) and content instead.
           */
          if (removed.children.length < 1) {
            continue;
          }
          if (removed.children[0].tagName !== "CODE") {
            continue;
          }
          var source = (removed.textContent || "").replace(/^\s+|\s+$/g, "");
          if (source.length === 0) {
            continue;
          }
          for (var a = 0; a < record.addedNodes.length; a += 1) {
            var added = record.addedNodes[a];
            if (added.nodeType !== 1) {
              continue;
            }
            if (added.tagName !== "DIV") {
              continue;
            }
            if (!added.classList || !added.classList.contains("mermaid")) {
              continue;
            }
            containerSourceMap.set(added, source);
            found += 1;
          }
        }
      }
      if (found > 0) {
        info("paired", found, "replaceWith(pre → div.mermaid) mutation(s)");
      }
    });
    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true,
    });
    info("replacement observer installed");
  }

  installReplacementObserver();

  function findContainers() {
    return document.querySelectorAll(CONTAINER_SELECTOR);
  }

  function buildBadge() {
    var badge = document.createElement("span");
    badge.className = "mermaid-zoom-badge";
    badge.setAttribute("aria-hidden", "true");
    /*
     * The glyph is painted via CSS ::after so the element carries no
     * textContent. Mermaid never sees a stray character if it ever
     * re-reads the container.
     */
    return badge;
  }

  function decorate(container) {
    if (container === null || container === undefined) {
      return false;
    }
    if (container.dataset[DECORATED_FLAG] === "1") {
      return false;
    }
    container.dataset[DECORATED_FLAG] = "1";
    container.classList.add("mermaid-zoomable");
    container.setAttribute("role", "button");
    container.setAttribute("tabindex", "0");
    container.setAttribute("aria-label", "Enlarge diagram");
    container.title = "Click to enlarge (Esc to close)";
    if (container.querySelector(".mermaid-zoom-badge") === null) {
      container.appendChild(buildBadge());
    }
    return true;
  }

  function decorateAll() {
    var containers = findContainers();
    var decorated = 0;
    for (var index = 0; index < containers.length; index += 1) {
      if (decorate(containers[index])) {
        decorated += 1;
      }
    }
    backfillSourcesPositional();
    if (FIRST_DECORATE_LOGGED !== true) {
      FIRST_DECORATE_LOGGED = true;
      info(
        "first decorate pass: found",
        containers.length,
        "container(s), decorated",
        decorated
      );
    } else if (decorated > 0) {
      info("decorated", decorated, "additional diagram container(s)");
    }
  }

  function resolveContainer(target) {
    if (target === null || target === undefined) {
      return null;
    }
    if (typeof target.closest !== "function") {
      return null;
    }
    return target.closest(CONTAINER_SELECTOR);
  }

  function onDocumentClick(event) {
    var container = resolveContainer(event.target);
    if (container === null) {
      return;
    }
    var anchor = null;
    if (event.target && typeof event.target.closest === "function") {
      anchor = event.target.closest("a");
    }
    if (anchor !== null && anchor !== undefined) {
      info("click inside <a>, letting it through", anchor);
      return;
    }
    info("intercepted click on", container);
    event.preventDefault();
    event.stopPropagation();
    openLightbox(container);
  }

  function onDocumentKey(event) {
    if (event.key !== "Enter" && event.key !== " ") {
      return;
    }
    var active = document.activeElement;
    var container = resolveContainer(active);
    if (container === null) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    openLightbox(container);
  }

  function resolveSource(container) {
    if (container === null || container === undefined) {
      return null;
    }
    var cached = containerSourceMap.get(container);
    if (cached !== undefined && cached !== null && cached.length > 0) {
      return cached;
    }
    /*
     * Last-resort fallback: textContent of the container. For
     * containers that still hold their <pre><code> this is the live
     * source. For Material's empty replacement div, this returns "".
     */
    var text = (container.textContent || "").replace(/^\s+|\s+$/g, "");
    if (text.length > 0) {
      return text;
    }
    return null;
  }

  function ensureMermaid() {
    return new Promise(function (resolve, reject) {
      if (typeof window.mermaid !== "undefined" && window.mermaid !== null) {
        resolve(window.mermaid);
        return;
      }
      var attempts = 0;
      var maxAttempts = 40;
      var timer = setInterval(function () {
        attempts += 1;
        if (typeof window.mermaid !== "undefined" && window.mermaid !== null) {
          clearInterval(timer);
          info("window.mermaid became available after", attempts, "poll(s)");
          resolve(window.mermaid);
          return;
        }
        if (attempts >= maxAttempts) {
          clearInterval(timer);
          reject(
            new Error("window.mermaid not available after " + attempts + " polls")
          );
        }
      }, 150);
    });
  }

  function openLightbox(sourceContainer) {
    info("opening lightbox for", sourceContainer);
    var source = resolveSource(sourceContainer);
    if (source === null) {
      warn(
        "no source text for this diagram -- cannot render lightbox.",
        "container=",
        sourceContainer
      );
      return;
    }
    info("source length=" + source.length, "head=", source.slice(0, 60));

    var existing = document.querySelector("." + LIGHTBOX_CLASS);
    if (existing !== null) {
      existing.remove();
    }

    var overlay = document.createElement("div");
    overlay.className = LIGHTBOX_CLASS;

    var backdrop = document.createElement("div");
    backdrop.className = "mermaid-lightbox__backdrop";

    var stage = document.createElement("div");
    stage.className = "mermaid-lightbox__stage";

    var canvas = document.createElement("div");
    canvas.className = "mermaid-lightbox__canvas";

    var spinner = document.createElement("div");
    spinner.className = "mermaid-lightbox__spinner";
    spinner.textContent = "Rendering\u2026";
    canvas.appendChild(spinner);

    var closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.className = "mermaid-lightbox__close";
    closeButton.setAttribute("aria-label", "Close diagram");
    closeButton.textContent = "\u2715";

    var hint = document.createElement("div");
    hint.className = "mermaid-lightbox__hint";
    hint.textContent =
      "Scroll to zoom \u00b7 drag to pan \u00b7 dbl-click to reset \u00b7 Esc to close";

    stage.appendChild(canvas);
    stage.appendChild(closeButton);
    stage.appendChild(hint);
    overlay.appendChild(backdrop);
    overlay.appendChild(stage);
    document.body.appendChild(overlay);
    document.body.classList.add(BODY_OPEN_CLASS);

    requestAnimationFrame(function () {
      overlay.classList.add("is-open");
    });

    var state = {
      scale: 1.0,
      translateX: 0.0,
      translateY: 0.0,
      dragging: false,
      lastX: 0,
      lastY: 0,
    };

    function applyTransform() {
      canvas.style.transform =
        "translate(" +
        state.translateX +
        "px, " +
        state.translateY +
        "px) scale(" +
        state.scale +
        ")";
    }

    function onWheel(event) {
      event.preventDefault();
      var factor = event.deltaY < 0 ? 1.15 : 0.87;
      var nextScale = state.scale * factor;
      if (nextScale < 0.3) {
        nextScale = 0.3;
      }
      if (nextScale > 8.0) {
        nextScale = 8.0;
      }
      state.scale = nextScale;
      applyTransform();
    }

    function onPointerDown(event) {
      state.dragging = true;
      state.lastX = event.clientX;
      state.lastY = event.clientY;
      canvas.classList.add("is-dragging");
      if (typeof canvas.setPointerCapture === "function") {
        try {
          canvas.setPointerCapture(event.pointerId);
        } catch (error) {
          /* ignore */
        }
      }
    }

    function onPointerMove(event) {
      if (state.dragging !== true) {
        return;
      }
      var deltaX = event.clientX - state.lastX;
      var deltaY = event.clientY - state.lastY;
      state.lastX = event.clientX;
      state.lastY = event.clientY;
      state.translateX += deltaX;
      state.translateY += deltaY;
      applyTransform();
    }

    function onPointerUp(event) {
      state.dragging = false;
      canvas.classList.remove("is-dragging");
      if (typeof canvas.releasePointerCapture === "function") {
        try {
          canvas.releasePointerCapture(event.pointerId);
        } catch (error) {
          /* ignore */
        }
      }
    }

    function onDoubleClick() {
      state.scale = 1.0;
      state.translateX = 0.0;
      state.translateY = 0.0;
      applyTransform();
    }

    function close() {
      document.removeEventListener("keydown", onKey);
      overlay.classList.remove("is-open");
      overlay.classList.add("is-closing");
      document.body.classList.remove(BODY_OPEN_CLASS);
      setTimeout(function () {
        if (overlay.parentNode !== null) {
          overlay.parentNode.removeChild(overlay);
        }
      }, 180);
    }

    function onKey(event) {
      if (event.key === "Escape") {
        close();
      } else if (event.key === "0") {
        onDoubleClick();
      }
    }

    backdrop.addEventListener("click", close);
    closeButton.addEventListener("click", close);
    document.addEventListener("keydown", onKey);
    stage.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("pointerdown", onPointerDown);
    canvas.addEventListener("pointermove", onPointerMove);
    canvas.addEventListener("pointerup", onPointerUp);
    canvas.addEventListener("pointercancel", onPointerUp);
    canvas.addEventListener("dblclick", onDoubleClick);

    ensureMermaid()
      .then(function (mermaid) {
        var renderId = "mermaid-zoom-lightbox-" + RENDER_ID_COUNTER;
        RENDER_ID_COUNTER += 1;
        return Promise.resolve(mermaid.render(renderId, source));
      })
      .then(function (result) {
        if (!overlay.isConnected) {
          return;
        }
        var svgMarkup = null;
        if (typeof result === "string") {
          svgMarkup = result;
        } else if (result && typeof result.svg === "string") {
          svgMarkup = result.svg;
        }
        if (svgMarkup === null) {
          warn("mermaid.render returned no svg markup", result);
          spinner.textContent = "Render failed";
          return;
        }
        canvas.innerHTML = svgMarkup;
        var svg = canvas.querySelector("svg");
        if (svg !== null && svg !== undefined) {
          svg.removeAttribute("width");
          svg.removeAttribute("height");
          svg.style.cssText +=
            ";width:100% !important;height:100% !important;" +
            "max-width:none !important;max-height:none !important;";
        }
      })
      .catch(function (err) {
        warn("lightbox render failed:", err);
        spinner.textContent = "Render failed (see console)";
      });
  }

  function installDelegatedListeners() {
    if (DELEGATION_INSTALLED === true) {
      return;
    }
    DELEGATION_INSTALLED = true;
    document.addEventListener("click", onDocumentClick, true);
    document.addEventListener("keydown", onDocumentKey, true);
    info("installed delegated click/keydown listeners on document");
  }

  function scheduleDecorate() {
    decorateAll();
    var delays = [50, 200, 500, 1000, 2000, 4000];
    for (var i = 0; i < delays.length; i += 1) {
      setTimeout(decorateAll, delays[i]);
    }
  }

  function observeMutations() {
    if (typeof MutationObserver === "undefined") {
      return;
    }
    var observer = new MutationObserver(function (records) {
      for (var index = 0; index < records.length; index += 1) {
        var record = records[index];
        if (record.addedNodes === null || record.addedNodes === undefined) {
          continue;
        }
        if (record.addedNodes.length === 0) {
          continue;
        }
        decorateAll();
        return;
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  function bootstrap() {
    info(
      "bootstrap (readyState=" + document.readyState + ")",
      "build=" + BUILD
    );
    installDelegatedListeners();
    scheduleDecorate();
    observeMutations();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }

  window.addEventListener("load", scheduleDecorate);

  if (typeof window !== "undefined" && typeof window.document$ !== "undefined") {
    try {
      window.document$.subscribe(function () {
        installDelegatedListeners();
        scheduleDecorate();
      });
    } catch (error) {
      /* fall back to DOMContentLoaded + MutationObserver above */
    }
  }

  window.MermaidZoom = {
    rescan: decorateAll,
    open: openLightbox,
    sources: function () {
      info(
        "sources(): indexed=" +
          INDEXED_SOURCES.length +
          " containers=" +
          findContainers().length
      );
      return INDEXED_SOURCES.slice();
    },
    test: function () {
      var containers = findContainers();
      info(
        "test(): delegationInstalled=" + DELEGATION_INSTALLED,
        "containers=" + containers.length,
        "indexedSources=" + INDEXED_SOURCES.length
      );
      if (containers.length === 0) {
        info("test(): no .mermaid containers found");
        return null;
      }
      var first = containers[0];
      info("test(): source on first container:", resolveSource(first));
      openLightbox(first);
      return first;
    },
  };
})();
