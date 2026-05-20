/* ygg.js — YggdraSIM shared scripts */

/* ── Dark mode toggle ── */
function syncThemeButton() {
  const isDark = document.documentElement.classList.contains('dark');
  document.querySelectorAll('[onclick="toggleTheme()"]').forEach((btn) => {
    btn.setAttribute('aria-pressed', String(isDark));
    btn.setAttribute(
      'aria-label',
      isDark ? 'Switch to light theme' : 'Switch to dark theme'
    );
  });
}

function toggleTheme() {
  const isDark = document.documentElement.classList.toggle('dark');
  localStorage.setItem('ygg-theme', isDark ? 'dark' : 'light');
  syncThemeButton();
  if (window.YggMermaid && typeof window.YggMermaid.rerender === 'function') {
    window.YggMermaid.rerender();
  }
}

/* ── Mermaid diagrams (loaded only when pre.mermaid is present) ── */
function loadScript(src) {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = src;
    script.onload = () => resolve(script);
    script.onerror = () => reject(new Error('Failed to load: ' + src));
    document.head.appendChild(script);
  });
}

async function initMermaidDiagrams() {
  if (!document.querySelector('pre.mermaid')) return;
  const base = document.body.dataset.yggBase || '';
  try {
    if (typeof window.mermaid === 'undefined') {
      await loadScript(
        'https://cdn.jsdelivr.net/npm/mermaid@10.9.3/dist/mermaid.min.js'
      );
    }
    if (typeof window.YggMermaid === 'undefined') {
      await loadScript(base + 'ygg-mermaid.js');
    }
    if (window.YggMermaid) {
      await window.YggMermaid.init();
    }
  } catch (err) {
    console.warn('[ygg] Mermaid init failed:', err);
  }
}

/* ── Sidebar (mobile) ──
 * The sidebar precedes <main> in the tab order. Below the lg breakpoint it is
 * an off-canvas panel: when closed it must not be reachable by keyboard or
 * exposed to assistive tech, so we toggle `inert` + `aria-hidden`. At lg+ the
 * sidebar is permanently visible and must never be inert/hidden. */
var yggLastFocusBeforeSidebar = null;
var YGG_DESKTOP_BP = 1024;

function isDesktopViewport() {
  return window.innerWidth >= YGG_DESKTOP_BP;
}

function setSidebarHidden(hidden) {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  if (hidden) {
    sidebar.setAttribute('inert', '');
    sidebar.setAttribute('aria-hidden', 'true');
  } else {
    sidebar.removeAttribute('inert');
    sidebar.removeAttribute('aria-hidden');
  }
}

function openSidebar() {
  const sidebar = document.getElementById('sidebar');
  yggLastFocusBeforeSidebar =
    document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
  sidebar?.classList.remove('-translate-x-full');
  document.getElementById('sidebar-overlay')?.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  setSidebarHidden(false);
  if (sidebar) {
    sidebar.setAttribute('aria-modal', 'true');
    if (!sidebar.hasAttribute('tabindex')) sidebar.setAttribute('tabindex', '-1');
    sidebar.focus();
  }
}

function closeSidebar() {
  if (isDesktopViewport()) return;
  const sidebar = document.getElementById('sidebar');
  sidebar?.classList.add('-translate-x-full');
  document.getElementById('sidebar-overlay')?.classList.add('hidden');
  document.body.style.overflow = '';
  if (sidebar) sidebar.removeAttribute('aria-modal');
  setSidebarHidden(true);
  if (
    yggLastFocusBeforeSidebar &&
    document.contains(yggLastFocusBeforeSidebar)
  ) {
    yggLastFocusBeforeSidebar.focus();
  }
  yggLastFocusBeforeSidebar = null;
}

/* Apply the correct sidebar a11y state for the current viewport. The sidebar
 * is injected asynchronously by ygg-layout.js, so this is called on load and
 * polled briefly until the element exists, plus on resize. */
function syncSidebarA11y() {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return false;
  if (isDesktopViewport()) {
    // Permanently visible at lg+ — never inert/hidden/modal.
    sidebar.removeAttribute('inert');
    sidebar.removeAttribute('aria-hidden');
    sidebar.removeAttribute('aria-modal');
  } else if (sidebar.classList.contains('-translate-x-full')) {
    // Off-canvas and closed.
    setSidebarHidden(true);
    sidebar.removeAttribute('aria-modal');
  }
  return true;
}

function initSidebarA11y() {
  if (syncSidebarA11y()) return;
  let tries = 0;
  const iv = setInterval(() => {
    if (syncSidebarA11y() || ++tries > 40) clearInterval(iv);
  }, 50);
}

let yggSidebarResizeRaf = 0;
window.addEventListener('resize', () => {
  cancelAnimationFrame(yggSidebarResizeRaf);
  yggSidebarResizeRaf = requestAnimationFrame(syncSidebarA11y);
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeSidebar();
});

/* ── Nav section collapse ── */
function setSectionExpanded(id, open) {
  const content = document.getElementById('sec-' + id);
  const chevron = document.getElementById('chev-' + id);
  const btn = document.querySelector('[data-nav-section="' + id + '"]');
  if (!content) return;
  content.classList.toggle('open', open);
  if (chevron) chevron.classList.toggle('open', open);
  if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
}

function toggleSection(id) {
  const content = document.getElementById('sec-' + id);
  if (!content) return;
  setSectionExpanded(id, !content.classList.contains('open'));
}

function openSection(id) {
  const content = document.getElementById('sec-' + id);
  if (content && !content.classList.contains('open')) {
    setSectionExpanded(id, true);
  }
}

/* ── Code copy ── */
var COPY_ICON =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<rect width="13" height="13" x="9" y="9" rx="2" ry="2"/>' +
  '<path d="M5 15a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2"/></svg>';
var CHECK_ICON =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M20 6 9 17l-5-5"/></svg>';

function copyCode(btn) {
  const block = btn.closest('.code-block');
  if (!block) return;
  const code = block.querySelector('code') || block.querySelector('pre');
  const status = block.querySelector('[data-copy-status]');

  navigator.clipboard.writeText(code.textContent.trim()).then(() => {
    if (status) status.textContent = 'Copied to clipboard';
    btn.innerHTML = CHECK_ICON;
    btn.classList.add('copy-btn--copied');
    btn.setAttribute('aria-label', 'Copied');
    setTimeout(() => {
      if (status) status.textContent = '';
      btn.innerHTML = COPY_ICON;
      btn.classList.remove('copy-btn--copied');
      btn.setAttribute('aria-label', 'Copy code');
    }, 1500);
  }).catch(() => {
    if (status) status.textContent = 'Copy failed';
  });
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function ensureCodeBlockChrome(block) {
  if (block.dataset.chromeReady) return;

  const pre = block.querySelector('pre');
  if (!pre) return;

  const filename = block.dataset.filename || '';
  if (filename) {
    const header = document.createElement('div');
    header.className = 'code-block-header';
    header.innerHTML =
      '<span class="code-block-filename">' + escapeHtml(filename) + '</span>';
    block.insertBefore(header, pre);
  }

  block.querySelectorAll('button.copy-btn').forEach((btn) => btn.remove());

  const status = document.createElement('span');
  status.className = 'code-block-status';
  status.setAttribute('data-copy-status', '');
  status.setAttribute('aria-live', 'polite');
  status.setAttribute('aria-atomic', 'true');

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'copy-btn';
  btn.setAttribute('onclick', 'copyCode(this)');
  btn.setAttribute('aria-label', 'Copy code');
  btn.innerHTML = COPY_ICON;

  block.appendChild(status);
  block.appendChild(btn);
  block.dataset.chromeReady = '1';
}

function initCodeBlocks() {
  document.querySelectorAll('.code-block').forEach((block) => {
    ensureCodeBlockChrome(block);

    const code = block.querySelector('pre code');
    if (!code || code.dataset.linesReady) return;

    const lines = code.textContent.split('\n');
    const numbered =
      block.classList.contains('code-block--numbered') ||
      block.dataset.lineNumbers === 'true' ||
      lines.length >= 6;

    if (numbered) {
      block.classList.add('code-block--numbered');
      code.innerHTML = lines
        .map((line) => '<span class="code-line">' + escapeHtml(line) + '</span>')
        .join('\n');
    }

    code.dataset.linesReady = '1';
  });
}

/* ── TOC highlight (Intersection Observer) ── */
function initToc() {
  const links = document.querySelectorAll('.toc-link[href^="#"]');
  if (!links.length) return;

  // Sliding marker (Linear-style) inside each TOC nav container.
  const navs = new Set();
  document
    .querySelectorAll('.ygg-toc-rail nav, .toc-mobile > nav')
    .forEach((n) => navs.add(n));
  navs.forEach((nav) => {
    if (nav.querySelector('.ygg-toc-marker')) return;
    const marker = document.createElement('span');
    marker.className = 'ygg-toc-marker';
    marker.setAttribute('aria-hidden', 'true');
    nav.prepend(marker);
  });

  function moveMarkerTo(link) {
    const nav = link.closest('nav');
    if (!nav) return;
    const marker = nav.querySelector('.ygg-toc-marker');
    if (!marker) return;
    const top = link.offsetTop;
    const h = link.offsetHeight;
    marker.style.height = h + 'px';
    marker.style.transform = 'translateY(' + top + 'px)';
    marker.style.opacity = '1';
  }

  function setActive(id) {
    let activeLink = null;
    links.forEach((l) => {
      const on = l.getAttribute('href') === '#' + id;
      l.classList.toggle('active', on);
      if (on) activeLink = l;
    });
    if (activeLink) {
      document
        .querySelectorAll('.ygg-toc-rail nav, .toc-mobile > nav')
        .forEach((nav) => {
          const a = nav.querySelector('.toc-link[href="#' + id + '"]');
          if (a) moveMarkerTo(a);
        });
      activeLink.scrollIntoView({ block: 'nearest', behavior: 'auto' });
    }
  }

  let resizeRaf = 0;
  window.addEventListener('resize', () => {
    cancelAnimationFrame(resizeRaf);
    resizeRaf = requestAnimationFrame(() => {
      const cur = document.querySelector('.toc-link.active');
      if (cur) setActive(cur.getAttribute('href').slice(1));
    });
  });

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          setActive(entry.target.id);
        }
      });
    },
    { rootMargin: '-10% 0px -70% 0px', threshold: 0 }
  );

  document.querySelectorAll('[id]').forEach((el) => {
    if (document.querySelector('.toc-link[href="#' + el.id + '"]')) {
      observer.observe(el);
    }
  });

  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      const id = link.getAttribute('href')?.slice(1);
      const target = id && document.getElementById(id);
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        history.replaceState(null, '', '#' + id);
      }
    });
  });
}

/* ── In-page anchor scroll (glossary alpha, etc.) ── */
function initAnchorScroll() {
  document.querySelectorAll('a[href^="#"]').forEach((link) => {
    if (link.classList.contains('toc-link')) return;
    link.addEventListener('click', (e) => {
      const id = link.getAttribute('href')?.slice(1);
      if (!id) return;
      const target = document.getElementById(id);
      if (!target) return;
      e.preventDefault();
      const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      target.scrollIntoView({
        behavior: reduced ? 'auto' : 'smooth',
        block: 'start',
      });
      history.replaceState(null, '', '#' + id);
    });
  });
}

function initFooterDate() {
  const els = document.querySelectorAll('[data-ygg-updated]');
  if (!els.length) return;
  const d = new Date(document.lastModified);
  // document.lastModified is invalid/epoch in some contexts — keep static fallback then.
  if (isNaN(d) || d.getFullYear() < 2000) return;
  const text = d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  els.forEach((el) => {
    el.textContent = text;
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initCodeBlocks();
  initToc();
  initAnchorScroll();
  initMermaidDiagrams();
  initSidebarA11y();
  syncThemeButton();
  initFooterDate();
});
