/* ygg-mermaid.js — Mermaid render + click-to-enlarge for YggdraSIM redesign */

(function () {
  'use strict';

  var MERMAID_CDN =
    'https://cdn.jsdelivr.net/npm/mermaid@10.9.3/dist/mermaid.min.js';
  var DECORATED_FLAG = 'yggMermaidDecorated';
  var LIGHTBOX_CLASS = 'mermaid-lightbox';
  var BODY_OPEN_CLASS = 'mermaid-lightbox-open';
  var CONTAINER_SELECTOR = '.doc-prose pre.mermaid, .doc-prose div.mermaid';
  var RENDER_ID_COUNTER = 0;
  var DELEGATION_INSTALLED = false;

  /** @type {string[]} */
  var INDEXED_SOURCES = [];
  var containerSourceMap = new WeakMap();
  var initPromise = null;

  function sanitizeMermaidSource(source) {
    if (!source) return source;
    var out = source;
    /* Node labels: trailing + and raw parentheses break Mermaid 10.9.x parsers. */
    out = out.replace(/\["([^"\]]*)\+"\]/g, function (_m, inner) {
      return '["' + inner + '#43;"]';
    });
    out = out.replace(/\["([^"]+)"\]/g, function (_m, inner) {
      if (!/[()]/.test(inner)) return _m;
      return (
        '["' +
        inner.replace(/\(/g, '#40;').replace(/\)/g, '#41;') +
        '"]'
      );
    });
    /* Flowchart edge labels with +, ', or / must use quoted arrow syntax. */
    out = out.replace(
      /(\S+)\s+--\s+([^-\n]+?)\s+-->\s+(\S+)/g,
      function (match, from, label, to) {
        var trimmed = label.trim();
        if (!/['+\/]/.test(trimmed)) return match;
        var escaped = trimmed.replace(/"/g, '#quot;').replace(/'/g, '#39;');
        return from + ' -->|"' + escaped + '"| ' + to;
      }
    );
    return out;
  }

  function snapshotSources() {
    var pres = document.querySelectorAll('.doc-prose pre.mermaid');
    INDEXED_SOURCES = [];
    for (var i = 0; i < pres.length; i += 1) {
      var code = pres[i].querySelector('code');
      var node = code !== null ? code : pres[i];
      var text = (node.textContent || '').replace(/^\s+|\s+$/g, '');
      INDEXED_SOURCES.push(sanitizeMermaidSource(text));
    }
  }

  snapshotSources();

  function isDarkTheme() {
    return document.documentElement.classList.contains('dark');
  }

  function mermaidThemeVariables() {
    if (isDarkTheme()) {
      return {
        darkMode: true,
        background: 'transparent',
        fontFamily: 'Inter, system-ui, sans-serif',
        fontSize: '14px',
        primaryColor: 'rgba(255, 255, 255, 0.06)',
        primaryTextColor: '#e4e4e7',
        primaryBorderColor: 'rgba(255, 255, 255, 0.12)',
        secondaryColor: 'rgba(255, 255, 255, 0.04)',
        secondaryTextColor: '#e4e4e7',
        secondaryBorderColor: 'rgba(255, 255, 255, 0.1)',
        tertiaryColor: 'rgba(74, 222, 128, 0.08)',
        tertiaryTextColor: '#86efac',
        tertiaryBorderColor: 'rgba(74, 222, 128, 0.28)',
        lineColor: 'rgba(255, 255, 255, 0.32)',
        textColor: '#a1a1aa',
        mainBkg: 'rgba(255, 255, 255, 0.06)',
        secondBkg: '#09111e',
        border1: 'rgba(255, 255, 255, 0.08)',
        border2: 'rgba(255, 255, 255, 0.12)',
        arrowheadColor: 'rgba(255, 255, 255, 0.42)',
        edgeLabelBackground: '#060e1a',
        clusterBkg: 'rgba(255, 255, 255, 0.03)',
        clusterBorder: 'rgba(255, 255, 255, 0.1)',
        titleColor: '#fafafa',
        labelColor: '#a1a1aa',
        actorBkg: 'rgba(255, 255, 255, 0.06)',
        actorBorder: 'rgba(255, 255, 255, 0.12)',
        actorTextColor: '#e4e4e7',
        actorLineColor: 'rgba(255, 255, 255, 0.32)',
        signalColor: '#e4e4e7',
        labelBoxBkgColor: 'rgba(74, 222, 128, 0.08)',
        labelBoxBorderColor: 'rgba(74, 222, 128, 0.28)',
        labelTextColor: '#86efac',
        noteBkgColor: 'rgba(74, 222, 128, 0.08)',
        noteBorderColor: 'rgba(74, 222, 128, 0.28)',
        noteTextColor: '#e4e4e7',
        activationBkgColor: 'rgba(74, 222, 128, 0.12)',
        activationBorderColor: '#4ade80',
        sequenceNumberColor: '#71717a',
      };
    }
    return {
      darkMode: false,
      background: 'transparent',
      fontFamily: 'Inter, system-ui, sans-serif',
      fontSize: '14px',
      primaryColor: '#ffffff',
      primaryTextColor: '#18181b',
      primaryBorderColor: 'rgba(9, 9, 11, 0.12)',
      secondaryColor: '#f4f4f5',
      secondaryTextColor: '#18181b',
      secondaryBorderColor: 'rgba(9, 9, 11, 0.12)',
      tertiaryColor: '#f0fdf4',
      tertiaryTextColor: '#15803d',
      tertiaryBorderColor: 'rgba(22, 163, 74, 0.28)',
      lineColor: '#71717a',
      textColor: '#3f3f46',
      mainBkg: '#ffffff',
      secondBkg: '#f9fafb',
      border1: 'rgba(9, 9, 11, 0.08)',
      border2: 'rgba(9, 9, 11, 0.12)',
      arrowheadColor: '#71717a',
      edgeLabelBackground: '#f4f4f5',
      clusterBkg: '#f9fafb',
      clusterBorder: 'rgba(9, 9, 11, 0.12)',
      titleColor: '#18181b',
      labelColor: '#3f3f46',
      actorBkg: '#ffffff',
      actorBorder: 'rgba(9, 9, 11, 0.12)',
      actorTextColor: '#18181b',
      actorLineColor: '#71717a',
      signalColor: '#18181b',
      labelBoxBkgColor: '#f0fdf4',
      labelBoxBorderColor: 'rgba(22, 163, 74, 0.28)',
      labelTextColor: '#15803d',
      noteBkgColor: '#f0fdf4',
      noteBorderColor: 'rgba(22, 163, 74, 0.28)',
      noteTextColor: '#18181b',
      activationBkgColor: '#f0fdf4',
      activationBorderColor: '#16a34a',
      sequenceNumberColor: '#71717a',
    };
  }

  function configureMermaid() {
    if (typeof window.mermaid === 'undefined') return;
    window.mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'loose',
      theme: 'base',
      themeVariables: mermaidThemeVariables(),
      flowchart: { htmlLabels: true, curve: 'basis' },
      sequence: { actorMargin: 48, messageMargin: 40 },
    });
  }

  function loadMermaid() {
    if (typeof window.mermaid !== 'undefined') {
      return Promise.resolve(window.mermaid);
    }
    return new Promise(function (resolve, reject) {
      var existing = document.querySelector('script[data-ygg-mermaid-cdn]');
      if (existing) {
        existing.addEventListener('load', function () {
          resolve(window.mermaid);
        });
        existing.addEventListener('error', reject);
        return;
      }
      var script = document.createElement('script');
      script.src = MERMAID_CDN;
      script.setAttribute('data-ygg-mermaid-cdn', '1');
      script.onload = function () {
        resolve(window.mermaid);
      };
      script.onerror = function () {
        reject(new Error('Failed to load Mermaid from CDN'));
      };
      document.head.appendChild(script);
    });
  }

  function findContainers() {
    var nodes = document.querySelectorAll(CONTAINER_SELECTOR);
    var out = [];
    for (var i = 0; i < nodes.length; i += 1) {
      if (nodes[i].closest('.mermaid-lightbox')) continue;
      out.push(nodes[i]);
    }
    return out;
  }

  function backfillSources() {
    var containers = findContainers();
    for (var i = 0; i < containers.length; i += 1) {
      if (containerSourceMap.has(containers[i])) continue;
      if (i < INDEXED_SOURCES.length) {
        containerSourceMap.set(containers[i], INDEXED_SOURCES[i]);
      }
    }
  }

  function createPreElement(source) {
    var pre = document.createElement('pre');
    pre.className = 'mermaid';
    pre.textContent = source;
    return pre;
  }

  function replaceContainerWithSource(container, source) {
    var xl = container.parentElement;
    var newPre = createPreElement(source);
    if (xl && xl.classList.contains('mermaid-xl')) {
      xl.innerHTML = '';
      xl.appendChild(newPre);
      return newPre;
    }
    container.replaceWith(newPre);
    return newPre;
  }

  var A11Y_ID_COUNTER = 0;

  function captionTextFrom(el) {
    if (!el) return '';
    var text = (el.textContent || '').replace(/\s+/g, ' ').trim();
    /* Strip a leading "Figure:" / "Figure 1:" prefix, keep descriptive text. */
    text = text.replace(/^figure\s*\d*\s*[:.—-]\s*/i, '');
    return text.trim();
  }

  function findCaptionFor(container) {
    if (!container) return null;
    /* The caption is placed as the immediately-following sibling. When the
       container is wrapped (e.g. .mermaid-xl), look past the wrapper too. */
    var sib = container.nextElementSibling;
    if (sib && sib.classList && sib.classList.contains('fig-caption')) {
      return sib;
    }
    var wrapper = container.parentElement;
    if (wrapper && wrapper.classList && wrapper.classList.contains('mermaid-xl')) {
      var wsib = wrapper.nextElementSibling;
      if (wsib && wsib.classList && wsib.classList.contains('fig-caption')) {
        return wsib;
      }
    }
    return null;
  }

  function applyAccessibility(container) {
    if (!container) return;
    var svg = container.querySelector('svg');
    if (!svg) return;

    var caption = findCaptionFor(container);
    var label = caption ? captionTextFrom(caption) : '';

    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', label || 'Diagram');

    if (caption) {
      if (!caption.id) {
        caption.id = 'ygg-fig-caption-' + A11Y_ID_COUNTER++;
      }
      svg.setAttribute('aria-describedby', caption.id);
    }
  }

  function buildBadge() {
    var badge = document.createElement('span');
    badge.className = 'mermaid-zoom-badge';
    badge.setAttribute('aria-hidden', 'true');
    return badge;
  }

  function decorate(container) {
    if (!container || container.dataset[DECORATED_FLAG] === '1') {
      /* Re-apply a11y on subsequent passes in case the SVG rendered late. */
      if (container) applyAccessibility(container);
      return false;
    }
    container.dataset[DECORATED_FLAG] = '1';
    applyAccessibility(container);
    container.classList.add('mermaid-zoomable');
    container.setAttribute('role', 'button');
    container.setAttribute('tabindex', '0');
    container.setAttribute('aria-label', 'Enlarge diagram');
    container.title = 'Click to enlarge (Esc to close)';
    if (!container.querySelector('.mermaid-zoom-badge')) {
      container.appendChild(buildBadge());
    }
    return true;
  }

  function decorateAll() {
    var containers = findContainers();
    for (var i = 0; i < containers.length; i += 1) {
      decorate(containers[i]);
    }
    backfillSources();
  }

  function resolveSource(container) {
    if (!container) return null;
    var cached = containerSourceMap.get(container);
    if (cached) return sanitizeMermaidSource(cached);
    var text = (container.textContent || '').replace(/^\s+|\s+$/g, '');
    return text.length > 0 ? sanitizeMermaidSource(text) : null;
  }

  function resolveContainer(target) {
    if (!target || typeof target.closest !== 'function') return null;
    var container = target.closest('pre.mermaid, div.mermaid');
    if (!container || !container.closest('.doc-prose')) return null;
    return container;
  }

  function openLightbox(sourceContainer) {
    var source = resolveSource(sourceContainer);
    if (!source) return;

    var existing = document.querySelector('.' + LIGHTBOX_CLASS);
    if (existing) existing.remove();

    var overlay = document.createElement('div');
    overlay.className = LIGHTBOX_CLASS;

    var backdrop = document.createElement('div');
    backdrop.className = 'mermaid-lightbox__backdrop';

    var captionEl = findCaptionFor(sourceContainer);
    var stageLabel = captionEl ? captionTextFrom(captionEl) : '';

    var stage = document.createElement('div');
    stage.className = 'mermaid-lightbox__stage';
    stage.setAttribute('role', 'dialog');
    stage.setAttribute('aria-modal', 'true');
    stage.setAttribute(
      'aria-label',
      stageLabel ? 'Enlarged diagram: ' + stageLabel : 'Enlarged diagram'
    );

    var canvas = document.createElement('div');
    canvas.className = 'mermaid-lightbox__canvas';

    var spinner = document.createElement('div');
    spinner.className = 'mermaid-lightbox__spinner';
    spinner.textContent = 'Rendering\u2026';
    canvas.appendChild(spinner);

    var closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'mermaid-lightbox__close';
    closeButton.setAttribute('aria-label', 'Close diagram');
    closeButton.textContent = '\u2715';

    var hint = document.createElement('div');
    hint.className = 'mermaid-lightbox__hint';
    hint.textContent =
      'Scroll to zoom \u00b7 drag to pan \u00b7 dbl-click to reset \u00b7 Esc to close';

    stage.appendChild(canvas);
    stage.appendChild(closeButton);
    stage.appendChild(hint);
    overlay.appendChild(backdrop);
    overlay.appendChild(stage);
    document.body.appendChild(overlay);
    document.body.classList.add(BODY_OPEN_CLASS);

    var lastFocused =
      document.activeElement && typeof document.activeElement.focus === 'function'
        ? document.activeElement
        : null;

    requestAnimationFrame(function () {
      overlay.classList.add('is-open');
      try {
        closeButton.focus();
      } catch (e) {
        /* focus is best-effort */
      }
    });

    var state = {
      scale: 1,
      translateX: 0,
      translateY: 0,
      dragging: false,
      lastX: 0,
      lastY: 0,
    };

    function applyTransform() {
      canvas.style.transform =
        'translate(' +
        state.translateX +
        'px, ' +
        state.translateY +
        'px) scale(' +
        state.scale +
        ')';
    }

    function onWheel(event) {
      event.preventDefault();
      var factor = event.deltaY < 0 ? 1.15 : 0.87;
      var next = state.scale * factor;
      state.scale = Math.min(8, Math.max(0.3, next));
      applyTransform();
    }

    function onPointerDown(event) {
      state.dragging = true;
      state.lastX = event.clientX;
      state.lastY = event.clientY;
      canvas.classList.add('is-dragging');
    }

    function onPointerMove(event) {
      if (!state.dragging) return;
      state.translateX += event.clientX - state.lastX;
      state.translateY += event.clientY - state.lastY;
      state.lastX = event.clientX;
      state.lastY = event.clientY;
      applyTransform();
    }

    function onPointerUp() {
      state.dragging = false;
      canvas.classList.remove('is-dragging');
    }

    function onDoubleClick() {
      state.scale = 1;
      state.translateX = 0;
      state.translateY = 0;
      applyTransform();
    }

    function close() {
      document.removeEventListener('keydown', onKey);
      overlay.classList.remove('is-open');
      overlay.classList.add('is-closing');
      document.body.classList.remove(BODY_OPEN_CLASS);
      setTimeout(function () {
        overlay.remove();
      }, 180);
      if (lastFocused && lastFocused.isConnected) {
        try {
          lastFocused.focus();
        } catch (e) {
          /* focus restore is best-effort */
        }
      }
    }

    function onKey(event) {
      if (event.key === 'Escape') close();
      else if (event.key === '0') onDoubleClick();
    }

    backdrop.addEventListener('click', close);
    closeButton.addEventListener('click', close);
    document.addEventListener('keydown', onKey);
    stage.addEventListener('wheel', onWheel, { passive: false });
    canvas.addEventListener('pointerdown', onPointerDown);
    canvas.addEventListener('pointermove', onPointerMove);
    canvas.addEventListener('pointerup', onPointerUp);
    canvas.addEventListener('pointercancel', onPointerUp);
    canvas.addEventListener('dblclick', onDoubleClick);

    configureMermaid();
    window.mermaid
      .render('ygg-mermaid-lightbox-' + RENDER_ID_COUNTER++, source)
      .then(function (result) {
        if (!overlay.isConnected) return;
        var svgMarkup =
          typeof result === 'string' ? result : result && result.svg;
        if (!svgMarkup) {
          spinner.textContent = 'Render failed';
          return;
        }
        canvas.innerHTML = svgMarkup;
        var svg = canvas.querySelector('svg');
        if (svg) {
          /* The clone is purely presentational; the stage carries the name. */
          svg.setAttribute('aria-hidden', 'true');
          svg.setAttribute('focusable', 'false');
          svg.removeAttribute('width');
          svg.removeAttribute('height');
          svg.style.cssText +=
            ';width:100% !important;height:100% !important;max-width:none !important;max-height:none !important;';
        }
      })
      .catch(function () {
        spinner.textContent = 'Render failed';
      });
  }

  function onDocumentClick(event) {
    var container = resolveContainer(event.target);
    if (!container) return;
    var anchor =
      event.target && typeof event.target.closest === 'function'
        ? event.target.closest('a')
        : null;
    if (anchor) return;
    event.preventDefault();
    event.stopPropagation();
    openLightbox(container);
  }

  function onDocumentKey(event) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    var container = resolveContainer(document.activeElement);
    if (!container) return;
    event.preventDefault();
    event.stopPropagation();
    openLightbox(container);
  }

  function installDelegatedListeners() {
    if (DELEGATION_INSTALLED) return;
    DELEGATION_INSTALLED = true;
    document.addEventListener('click', onDocumentClick, true);
    document.addEventListener('keydown', onDocumentKey, true);
  }

  function applySanitizedSourcesToPres() {
    var pres = document.querySelectorAll('.doc-prose pre.mermaid');
    for (var i = 0; i < pres.length; i += 1) {
      var source =
        i < INDEXED_SOURCES.length
          ? INDEXED_SOURCES[i]
          : sanitizeMermaidSource(
              (pres[i].querySelector('code') || pres[i]).textContent || ''
            );
      pres[i].textContent = source;
    }
  }

  function runMermaid() {
    var nodes = document.querySelectorAll('.doc-prose pre.mermaid');
    if (!nodes.length) return Promise.resolve();
    applySanitizedSourcesToPres();
    return window.mermaid.run({
      nodes: nodes,
      suppressErrors: true,
    });
  }

  function linkSourcesToContainers() {
    var containers = findContainers();
    for (var i = 0; i < containers.length; i += 1) {
      if (i < INDEXED_SOURCES.length) {
        containerSourceMap.set(containers[i], INDEXED_SOURCES[i]);
      }
    }
  }

  function init() {
    if (!document.querySelector('.doc-prose pre.mermaid, pre.mermaid')) {
      return Promise.resolve();
    }
    if (!INDEXED_SOURCES.length) snapshotSources();
    if (initPromise) return initPromise;

    initPromise = loadMermaid()
      .then(function () {
        configureMermaid();
        return runMermaid();
      })
      .then(function () {
        linkSourcesToContainers();
        installDelegatedListeners();
        decorateAll();
        var delays = [50, 200, 500];
        delays.forEach(function (ms) {
          setTimeout(decorateAll, ms);
        });
      })
      .catch(function (err) {
        console.warn('[ygg-mermaid] init failed:', err);
        initPromise = null;
      });

    return initPromise;
  }

  function rerender() {
    if (!INDEXED_SOURCES.length) return Promise.resolve();

    var openLb = document.querySelector('.' + LIGHTBOX_CLASS);
    if (openLb) openLb.remove();
    document.body.classList.remove(BODY_OPEN_CLASS);

    var containers = findContainers();
    for (var i = 0; i < containers.length; i += 1) {
      var source =
        containerSourceMap.get(containers[i]) ||
        (i < INDEXED_SOURCES.length ? INDEXED_SOURCES[i] : null);
      if (!source) continue;
      var fresh = replaceContainerWithSource(containers[i], source);
      fresh.dataset[DECORATED_FLAG] = '';
      fresh.classList.remove('mermaid-zoomable');
    }

    configureMermaid();
    return runMermaid().then(function () {
      linkSourcesToContainers();
      decorateAll();
    });
  }

  window.YggMermaid = {
    init: init,
    rerender: rerender,
    sources: function () {
      return INDEXED_SOURCES.slice();
    },
  };
})();
