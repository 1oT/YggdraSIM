/* ygg-layout.js — shared chrome (sidebar + overlay) */

const YGG_SIDEBAR_FALLBACK = `<aside id="sidebar"
         class="fixed inset-y-0 left-0 z-30 flex w-64 flex-col
                bg-white dark:bg-[var(--bg-sidebar)]
                border-r border-zinc-950/8 dark:border-white/[0.06]
                -translate-x-full lg:translate-x-0
                transition-transform duration-200 ease-out">

    <!-- Brand -->
    <div class="flex items-center gap-3 px-5 py-[1.0625rem] border-b border-zinc-950/[0.07] dark:border-white/[0.05] shrink-0">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" class="size-7 shrink-0" aria-hidden="true" focusable="false">
        <defs>
          <linearGradient id="g-ring" x1="18" x2="110" y1="18" y2="110" gradientUnits="userSpaceOnUse">
            <stop offset="0" stop-color="#88c0d0"/><stop offset="1" stop-color="#a3be8c"/>
          </linearGradient>
          <linearGradient id="g-core" x1="64" x2="64" y1="24" y2="112" gradientUnits="userSpaceOnUse">
            <stop offset="0" stop-color="#ebcb8b"/><stop offset="1" stop-color="#a3be8c"/>
          </linearGradient>
        </defs>
        <g fill="none" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="64" cy="64" r="57" stroke="url(#g-ring)" stroke-width="6"/>
          <path d="M64 24v68" stroke="url(#g-core)" stroke-width="6"/>
          <path d="M64 33c-9 10-16 14-27 19" stroke="#88c0d0" stroke-width="5"/>
          <path d="M64 33c9 10 16 14 27 19"  stroke="#88c0d0" stroke-width="5"/>
          <path d="M64 45c-12 7-21 12-34 14" stroke="#81a1c1" stroke-width="5"/>
          <path d="M64 45c12 7 21 12 34 14"  stroke="#81a1c1" stroke-width="5"/>
          <path d="M64 60c-10 7-18 10-28 13" stroke="#8fbcbb" stroke-width="5"/>
          <path d="M64 60c10 7 18 10 28 13"  stroke="#8fbcbb" stroke-width="5"/>
          <path d="M64 92c-7 12-13 17-24 21" stroke="#a3be8c" stroke-width="5"/>
          <path d="M64 92c7 12 13 17 24 21"  stroke="#a3be8c" stroke-width="5"/>
          <path d="M64 92c-1 9-4 15-10 22"   stroke="#ebcb8b" stroke-width="4"/>
          <path d="M64 92c1 9 4 15 10 22"    stroke="#ebcb8b" stroke-width="4"/>
          <circle cx="64" cy="22" r="4" fill="#ebcb8b" stroke="none"/>
        </g>
      </svg>
      <div class="min-w-0">
        <div class="font-sans font-semibold text-[0.9375rem] tracking-tight text-zinc-900 dark:text-zinc-100">YggdraSIM</div>
      </div>
    </div>

        <nav id="sidebar-nav" aria-label="Documentation" class="flex-1 overflow-y-auto px-3 py-4 space-y-0.5">
      <ul class="ygg-nav-list">
      <li><a href="#" data-nav-path="index.html" class="nav-link" data-nav-href="index.html">Home</a></li>
      <li><a href="#" data-nav-path="getting-started.html" class="nav-link" data-nav-href="getting-started.html">Getting Started</a></li>
      <li><a href="#" data-nav-path="operator-surfaces.html" class="nav-link" data-nav-href="operator-surfaces.html">Operator Surfaces</a></li>
      <li>
      <button type="button" onclick="toggleSection('concepts')" data-nav-section="concepts" class="nav-link" aria-expanded="false" aria-controls="sec-concepts">
        <span class="flex-1 text-left">Concepts</span>
        <svg id="chev-concepts" class="nav-chevron size-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" focusable="false"><path d="M4 6l4 4 4-4"/></svg>
      </button>
      <div id="sec-concepts" class="nav-section-content">
      <div class="nav-section-inner">
        <ul class="ygg-nav-sublist">
        <li><a href="#" data-nav-path="concepts/index.html" class="nav-sub-link" data-nav-href="concepts/index.html">Overview</a></li>
        <li><a href="#" data-nav-path="concepts/secure-element-primer.html" class="nav-sub-link" data-nav-href="concepts/secure-element-primer.html">Secure Element Primer</a></li>
        <li><a href="#" data-nav-path="concepts/globalplatform.html" class="nav-sub-link" data-nav-href="concepts/globalplatform.html">GlobalPlatform</a></li>
        <li><a href="#" data-nav-path="concepts/etsi-uicc.html" class="nav-sub-link" data-nav-href="concepts/etsi-uicc.html">ETSI UICC</a></li>
        <li><a href="#" data-nav-path="concepts/3gpp-naa.html" class="nav-sub-link" data-nav-href="concepts/3gpp-naa.html">3GPP NAA</a></li>
        <li><a href="#" data-nav-path="concepts/rsp-architecture.html" class="nav-sub-link" data-nav-href="concepts/rsp-architecture.html">RSP Architecture</a></li>
        <li><a href="#" data-nav-path="concepts/saip-profiles.html" class="nav-sub-link" data-nav-href="concepts/saip-profiles.html">SAIP Profiles</a></li>
        <li><a href="#" data-nav-path="concepts/ota-scp80.html" class="nav-sub-link" data-nav-href="concepts/ota-scp80.html">OTA / SCP80</a></li>
        <li><a href="#" data-nav-path="concepts/hil-model.html" class="nav-sub-link" data-nav-href="concepts/hil-model.html">HIL Model</a></li>
        </ul>
      </div></div>
      </li>
      <li>
      <button type="button" onclick="toggleSection('subsystems')" data-nav-section="subsystems" class="nav-link" aria-expanded="false" aria-controls="sec-subsystems">
        <span class="flex-1 text-left">Subsystems</span>
        <svg id="chev-subsystems" class="nav-chevron size-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" focusable="false"><path d="M4 6l4 4 4-4"/></svg>
      </button>
      <div id="sec-subsystems" class="nav-section-content">
      <div class="nav-section-inner">
        <ul class="ygg-nav-sublist">
        <li><a href="#" data-nav-path="subsystems/index.html" class="nav-sub-link" data-nav-href="subsystems/index.html">Overview</a></li>
        <li><a href="#" data-nav-path="subsystems/scp03.html" class="nav-sub-link" data-nav-href="subsystems/scp03.html">SCP03 Admin Shell</a></li>
        <li><a href="#" data-nav-path="subsystems/scp80.html" class="nav-sub-link" data-nav-href="subsystems/scp80.html">SCP80 OTA Shell</a></li>
        <li><a href="#" data-nav-path="subsystems/scp11-live.html" class="nav-sub-link" data-nav-href="subsystems/scp11-live.html">SCP11 Live Relay</a></li>
        <li><a href="#" data-nav-path="subsystems/scp11-test.html" class="nav-sub-link" data-nav-href="subsystems/scp11-test.html">SCP11 Test Relay</a></li>
        <li><a href="#" data-nav-path="subsystems/scp11-local-access.html" class="nav-sub-link" data-nav-href="subsystems/scp11-local-access.html">SCP11 Local Access</a></li>
        <li><a href="#" data-nav-path="subsystems/scp11-eim-local.html" class="nav-sub-link" data-nav-href="subsystems/scp11-eim-local.html">SCP11 eIM Local</a></li>
        <li><a href="#" data-nav-path="subsystems/simcard-simulator.html" class="nav-sub-link" data-nav-href="subsystems/simcard-simulator.html">SIMCARD Simulator</a></li>
        <li><a href="#" data-nav-path="subsystems/profile-package.html" class="nav-sub-link" data-nav-href="subsystems/profile-package.html">Profile Package</a></li>
        <li><a href="#" data-nav-path="subsystems/hil-bridge.html" class="nav-sub-link" data-nav-href="subsystems/hil-bridge.html">HIL Bridge</a></li>
        <li><a href="#" data-nav-path="subsystems/apdu-fuzzer.html" class="nav-sub-link" data-nav-href="subsystems/apdu-fuzzer.html">APDU Fuzzer</a></li>
        <li><a href="#" data-nav-path="subsystems/eum-diagnostics.html" class="nav-sub-link" data-nav-href="subsystems/eum-diagnostics.html">EUM Diagnostics</a></li>
        <li><a href="#" data-nav-path="subsystems/suci-tool.html" class="nav-sub-link" data-nav-href="subsystems/suci-tool.html">SUCI Tool</a></li>
        </ul>
      </div></div>
      </li>
      <li>
      <button type="button" onclick="toggleSection('how-to')" data-nav-section="how-to" class="nav-link" aria-expanded="false" aria-controls="sec-how-to">
        <span class="flex-1 text-left">How-To</span>
        <svg id="chev-how-to" class="nav-chevron size-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" focusable="false"><path d="M4 6l4 4 4-4"/></svg>
      </button>
      <div id="sec-how-to" class="nav-section-content">
      <div class="nav-section-inner">
        <ul class="ygg-nav-sublist">
        <li><a href="#" data-nav-path="how-to/index.html" class="nav-sub-link" data-nav-href="how-to/index.html">Overview</a></li>
        <li><a href="#" data-nav-path="how-to/download-a-profile-live.html" class="nav-sub-link" data-nav-href="how-to/download-a-profile-live.html">Download profile (live)</a></li>
        <li><a href="#" data-nav-path="how-to/download-a-profile-local.html" class="nav-sub-link" data-nav-href="how-to/download-a-profile-local.html">Download profile (local)</a></li>
        <li><a href="#" data-nav-path="how-to/enable-disable-delete-profile.html" class="nav-sub-link" data-nav-href="how-to/enable-disable-delete-profile.html">Enable / disable / delete</a></li>
        <li><a href="#" data-nav-path="how-to/inspect-and-transcode-saip.html" class="nav-sub-link" data-nav-href="how-to/inspect-and-transcode-saip.html">Inspect &amp; transcode SAIP</a></li>
        <li><a href="#" data-nav-path="how-to/run-hil-capture.html" class="nav-sub-link" data-nav-href="how-to/run-hil-capture.html">Run HIL capture</a></li>
        <li><a href="#" data-nav-path="how-to/replay-hil-pcap-offline.html" class="nav-sub-link" data-nav-href="how-to/replay-hil-pcap-offline.html">Replay HIL PCAP offline</a></li>
        <li><a href="#" data-nav-path="how-to/enable-inventory-encryption.html" class="nav-sub-link" data-nav-href="how-to/enable-inventory-encryption.html">Enable inventory encryption</a></li>
        <li><a href="#" data-nav-path="how-to/diagnostics-toolbox.html" class="nav-sub-link" data-nav-href="how-to/diagnostics-toolbox.html">Diagnostics toolbox</a></li>
        <li><a href="#" data-nav-path="how-to/run-in-docker.html" class="nav-sub-link" data-nav-href="how-to/run-in-docker.html">Run in Docker</a></li>
        <li><a href="#" data-nav-path="how-to/build-a-bundled-exe.html" class="nav-sub-link" data-nav-href="how-to/build-a-bundled-exe.html">Build bundled executable</a></li>
        </ul>
      </div></div>
      </li>
      <li>
      <button type="button" onclick="toggleSection('shell-guides')" data-nav-section="shell-guides" class="nav-link" aria-expanded="false" aria-controls="sec-shell-guides">
        <span class="flex-1 text-left">Shell Guides</span>
        <svg id="chev-shell-guides" class="nav-chevron size-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" focusable="false"><path d="M4 6l4 4 4-4"/></svg>
      </button>
      <div id="sec-shell-guides" class="nav-section-content">
      <div class="nav-section-inner">
        <ul class="ygg-nav-sublist">
        <li><a href="#" data-nav-path="shell-guides/index.html" class="nav-sub-link" data-nav-href="shell-guides/index.html">Overview</a></li>
        <li><a href="#" data-nav-path="shell-guides/scp03-command-reference.html" class="nav-sub-link" data-nav-href="shell-guides/scp03-command-reference.html">SCP03 Command Reference</a></li>
        <li><a href="#" data-nav-path="shell-guides/scp03-guide-topics.html" class="nav-sub-link" data-nav-href="shell-guides/scp03-guide-topics.html">SCP03 Guide Topics</a></li>
        </ul>
      </div></div>
      </li>
      <li>
      <button type="button" onclick="toggleSection('reference')" data-nav-section="reference" class="nav-link" aria-expanded="false" aria-controls="sec-reference">
        <span class="flex-1 text-left">Reference</span>
        <svg id="chev-reference" class="nav-chevron size-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" focusable="false"><path d="M4 6l4 4 4-4"/></svg>
      </button>
      <div id="sec-reference" class="nav-section-content">
      <div class="nav-section-inner">
        <ul class="ygg-nav-sublist">
        <li><a href="#" data-nav-path="reference/glossary.html" class="nav-sub-link" data-nav-href="reference/glossary.html">Glossary</a></li>
        <li><a href="#" data-nav-path="reference/cli-cheatsheet.html" class="nav-sub-link" data-nav-href="reference/cli-cheatsheet.html">CLI &amp; piping cheatsheet</a></li>
        <li><a href="#" data-nav-path="reference/command-suite.html" class="nav-sub-link" data-nav-href="reference/command-suite.html">Command suite</a></li>
        <li><a href="#" data-nav-path="reference/faq.html" class="nav-sub-link" data-nav-href="reference/faq.html">FAQ</a></li>
        <li><a href="#" data-nav-path="reference/troubleshooting.html" class="nav-sub-link" data-nav-href="reference/troubleshooting.html">Troubleshooting</a></li>
        <li><a href="#" data-nav-path="reference/standards-map.html" class="nav-sub-link" data-nav-href="reference/standards-map.html">Standards map</a></li>
        <li><a href="#" data-nav-path="reference/state-schema.html" class="nav-sub-link" data-nav-href="reference/state-schema.html">State schema</a></li>
        <li><a href="#" data-nav-path="reference/runtime-root.html" class="nav-sub-link" data-nav-href="reference/runtime-root.html">Runtime root</a></li>
        </ul>
      </div></div>
      </li>
      <li><a href="#" data-nav-path="architecture.html" class="nav-link" data-nav-href="architecture.html">Architecture</a></li>
      <li><a href="#" data-nav-path="build-and-packaging.html" class="nav-link" data-nav-href="build-and-packaging.html">Build &amp; Packaging</a></li>
      <li>
      <button type="button" onclick="toggleSection('internals')" data-nav-section="internals" class="nav-link" aria-expanded="false" aria-controls="sec-internals">
        <span class="flex-1 text-left">Internals</span>
        <svg id="chev-internals" class="nav-chevron size-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" focusable="false"><path d="M4 6l4 4 4-4"/></svg>
      </button>
      <div id="sec-internals" class="nav-section-content">
      <div class="nav-section-inner">
        <ul class="ygg-nav-sublist">
        <li><a href="#" data-nav-path="internals/index.html" class="nav-sub-link" data-nav-href="internals/index.html">Overview</a></li>
        <li><a href="#" data-nav-path="internals/registry-and-launcher.html" class="nav-sub-link" data-nav-href="internals/registry-and-launcher.html">Registry &amp; launcher</a></li>
        <li><a href="#" data-nav-path="internals/plugin-contract.html" class="nav-sub-link" data-nav-href="internals/plugin-contract.html">Plugin contract</a></li>
        <li><a href="#" data-nav-path="internals/testing-guide.html" class="nav-sub-link" data-nav-href="internals/testing-guide.html">Testing guide</a></li>
        <li><a href="#" data-nav-path="internals/coding-standards.html" class="nav-sub-link" data-nav-href="internals/coding-standards.html">Coding standards</a></li>
        <li><a href="#" data-nav-path="internals/release-checklist.html" class="nav-sub-link" data-nav-href="internals/release-checklist.html">Release checklist</a></li>
        <li><a href="#" data-nav-path="internals/editing-docs.html" class="nav-sub-link" data-nav-href="internals/editing-docs.html">Editing documentation</a></li>
        </ul>
      </div></div>
      </li>
      <li>
      <button type="button" onclick="toggleSection('about')" data-nav-section="about" class="nav-link" aria-expanded="false" aria-controls="sec-about">
        <span class="flex-1 text-left">About</span>
        <svg id="chev-about" class="nav-chevron size-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" focusable="false"><path d="M4 6l4 4 4-4"/></svg>
      </button>
      <div id="sec-about" class="nav-section-content">
      <div class="nav-section-inner">
        <ul class="ygg-nav-sublist">
        <li><a href="#" data-nav-path="about/license.html" class="nav-sub-link" data-nav-href="about/license.html">License</a></li>
        <li><a href="#" data-nav-path="about/authors.html" class="nav-sub-link" data-nav-href="about/authors.html">Authors</a></li>
        <li><a href="#" data-nav-path="about/contributing.html" class="nav-sub-link" data-nav-href="about/contributing.html">Contributing</a></li>
        <li><a href="#" data-nav-path="about/notice.html" class="nav-sub-link" data-nav-href="about/notice.html">Notice</a></li>
        <li><a href="#" data-nav-path="about/consultancy.html" class="nav-sub-link" data-nav-href="about/consultancy.html">Consultancy &amp; contact</a></li>
        </ul>
      </div></div>
      </li>
      </ul>
    </nav>
<!-- Sidebar footer -->
    <div class="flex items-center justify-between px-4 py-3 border-t border-zinc-950/[0.07] dark:border-white/[0.05] shrink-0">
      <a href="https://github.com/1oT/YggdraSIM/releases/tag/V1.0.1" target="_blank" rel="noopener"
         class="flex items-center gap-1.5 text-[0.6875rem] font-mono text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors no-underline">
        <svg class="size-3.5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844a9.59 9.59 0 012.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>
        v1.0.1
      </a>
      <button type="button" onclick="toggleTheme()"
              class="ygg-icon-btn flex items-center justify-center size-11 rounded-md text-zinc-400
                     hover:text-zinc-600 hover:bg-zinc-100
                     dark:hover:text-zinc-300 dark:hover:bg-white/[0.08]
                     transition-colors"
              aria-label="Switch to dark theme" aria-pressed="false">
        <!-- Sun (shown in dark mode) -->
        <svg class="icon-sun size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
          <circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
        </svg>
        <!-- Moon (shown in light mode) -->
        <svg class="icon-moon size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
          <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
        </svg>
      </button>
    </div>
  </aside>
`;

(function () {
  const mount = document.getElementById('ygg-chrome-mount');
  if (!mount) return;

  const partial =
    document.body.dataset.yggPartialPath || 'partials/sidebar.html';

  function applyNavPaths() {
    const base = document.body.dataset.yggBase || '';
    document.querySelectorAll('[data-nav-path]').forEach((el) => {
      el.setAttribute('href', base + el.dataset.navPath);
    });
  }

  function applyNavState() {
    applyNavPaths();

    const activeLink = document.body.dataset.yggActiveLink;
    const activeSub = document.body.dataset.yggActiveSub;
    const openSections = (document.body.dataset.yggOpenSections || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    if (activeLink) {
      document.querySelectorAll('.nav-link[data-nav-href]').forEach((el) => {
        const on = el.dataset.navHref === activeLink;
        el.classList.toggle('active', on);
        if (on) el.setAttribute('aria-current', 'page');
        else el.removeAttribute('aria-current');
      });
    }

    if (activeSub) {
      document.querySelectorAll('.nav-sub-link[data-nav-href]').forEach((el) => {
        const on = el.dataset.navHref === activeSub;
        el.classList.toggle('active', on);
        if (on) el.setAttribute('aria-current', 'page');
        else el.removeAttribute('aria-current');
      });
    }

    openSections.forEach((id) => {
      if (typeof openSection === 'function') openSection(id);
    });
  }

  function mountChrome(html) {
    mount.innerHTML = html;
    applyNavState();
    document.getElementById('ygg-shell')?.classList.add('ygg-layout-ready');
    // Chrome (sidebar + theme button) is now in the DOM — sync a11y state
    // that depends on it. These live in ygg.js and may load in any order.
    if (typeof window.syncSidebarA11y === 'function') window.syncSidebarA11y();
    if (typeof window.syncThemeButton === 'function') window.syncThemeButton();
  }

  fetch(partial)
    .then((res) => {
      if (!res.ok) throw new Error(res.statusText);
      return res.text();
    })
    .then(mountChrome)
    .catch(() => mountChrome(YGG_SIDEBAR_FALLBACK));
})();
