# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""End-to-end Playwright smoke for the Universal GUI Command Center.

Spins up the real FastAPI app via uvicorn on a loopback port, then
drives it with Playwright's sync API. The test asserts that the SPA
boots, the token bootstrap works, the Command Center navigation renders,
and the **SCP11 Local / Local SMDP+** subsystem reaches its reader-scoped
dashboard or reader-session gate.

Self-skipping policy — the test is deliberately CI-inert until a
headless-browser lane exists:

* Skipped if ``fastapi`` / ``uvicorn`` are not importable (the GUI
  extra has not been installed).
* Skipped if ``playwright`` is not importable.
* Skipped if the Chromium browser binary is not available to
  Playwright — the test never calls ``playwright install``.

To run locally once the lane is wired:

    pip install yggdrasim[gui] playwright
    playwright install chromium
    pytest tests/test_gui_playwright_smoke.py -q --tb=short \\
        --disable-warnings --no-header --maxfail=1

The test is intentionally narrow: one happy-path walk through read-only
surfaces. Deeper end-to-end flows (SCP03 scan, SCP11 live, SAIP open)
need card hardware and live readers and are left to the existing
pytest + manual workflow.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from contextlib import closing
from pathlib import Path

import pytest


# ----------------------------------------------------------------------
# Optional-dependency gates
# ----------------------------------------------------------------------


_FASTAPI_AVAILABLE = True
try:  # pragma: no cover — skip-path metadata
    import fastapi as _fastapi  # noqa: F401
    import uvicorn as _uvicorn  # noqa: F401
except ImportError:
    _FASTAPI_AVAILABLE = False


_PLAYWRIGHT_AVAILABLE = True
_PLAYWRIGHT_IMPORT_ERROR = ""
try:  # pragma: no cover — skip-path metadata
    from playwright.sync_api import sync_playwright  # type: ignore
except ImportError as error:  # pragma: no cover — only triggered without pw
    _PLAYWRIGHT_AVAILABLE = False
    _PLAYWRIGHT_IMPORT_ERROR = str(error)


needs_gui_stack = pytest.mark.skipif(
    not _FASTAPI_AVAILABLE,
    reason="FastAPI / uvicorn not installed — gui extra missing.",
)
needs_playwright = pytest.mark.skipif(
    not _PLAYWRIGHT_AVAILABLE,
    reason=f"playwright not importable ({_PLAYWRIGHT_IMPORT_ERROR or 'install: pip install playwright'}).",
)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _pick_loopback_port() -> int:
    """Return a free TCP port on 127.0.0.1. Best-effort; no reservation."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _build_test_config(host: str, port: int, token: str):
    from yggdrasim_common.gui_server.config import (
        GuiServerConfig,
        MODE_WEB_SERVER,
    )

    return GuiServerConfig(
        mode=MODE_WEB_SERVER,
        host=host,
        port=port,
        token=token,
        allow_ephemeral_port=False,
    )


class _UvicornThread:
    """Run uvicorn in a daemon thread bound to a preselected port."""

    def __init__(self, app, host: str, port: int) -> None:
        import uvicorn

        config = uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
            lifespan="off",
        )
        self._server = uvicorn.Server(config)
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._server.run,
            name="yggdrasim-gui-playwright-uvicorn",
            daemon=True,
        )
        self._thread.start()

    def wait_ready(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout))
        while time.monotonic() < deadline:
            if bool(getattr(self._server, "started", False)):
                return True
            time.sleep(0.05)
        return bool(getattr(self._server, "started", False))

    def stop(self) -> None:
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10.0)


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------


@pytest.fixture(scope="module")
def _headless_gui_server():
    """Module-scoped uvicorn server bound to a loopback port."""
    if not _FASTAPI_AVAILABLE:
        pytest.skip("GUI stack not available.")

    from yggdrasim_common.gui_server.app import create_app

    token = "pw-smoke-" + os.urandom(4).hex()
    host = "127.0.0.1"
    port = _pick_loopback_port()
    config = _build_test_config(host=host, port=port, token=token)
    app = create_app(config)
    runner = _UvicornThread(app, host=host, port=port)
    runner.start()
    try:
        ready = runner.wait_ready(timeout=5.0)
        if not ready:
            pytest.skip("uvicorn did not report ready within 5s.")
        yield {
            "base_url": f"http://{host}:{port}",
            "token": token,
        }
    finally:
        runner.stop()


@pytest.fixture(scope="module")
def _playwright_browser():
    """Module-scoped Chromium browser instance.

    Skips if the Chromium binary isn't installed — we never invoke
    ``playwright install`` from the test suite.
    """
    if not _PLAYWRIGHT_AVAILABLE:
        pytest.skip("playwright not importable.")
    try:
        playwright_ctx = sync_playwright().start()
    except Exception as error:  # pragma: no cover — import-time surprise
        pytest.skip(f"playwright failed to start: {error!r}")
    try:
        try:
            browser = playwright_ctx.chromium.launch(headless=True)
        except Exception as error:  # pragma: no cover — missing binary
            pytest.skip(
                "chromium binary unavailable to playwright "
                f"({error!r}). Run `playwright install chromium` first."
            )
        try:
            yield browser
        finally:
            browser.close()
    finally:
        playwright_ctx.stop()


# ----------------------------------------------------------------------
# Smoke
# ----------------------------------------------------------------------


@needs_gui_stack
@needs_playwright
class TestCommandCenterSmoke:
    """Happy-path walk through the Command Center over HTTP."""

    def test_spa_boots_and_lists_scp11_local_subsystem(
        self,
        _headless_gui_server,
        _playwright_browser,
    ) -> None:
        base_url = _headless_gui_server["base_url"]
        token = _headless_gui_server["token"]

        context = _playwright_browser.new_context(
            viewport={"width": 1280, "height": 900},
        )
        page = context.new_page()

        # The SPA strips ``?t=<token>`` from the URL and stashes it in
        # sessionStorage on first paint, so a simple navigation is all
        # we need to authenticate every subsequent fetch.
        page.goto(f"{base_url}/?t={token}", wait_until="domcontentloaded", timeout=10_000)

        # 1. API badge flips from "checking…" to "healthy" (or at least a
        #    non-error state) once ``GET /api/health`` lands.
        page.wait_for_function(
            """() => {
              const el = document.querySelector('#api-badge');
              return el && !/checking/i.test(el.textContent || '');
            }""",
            timeout=10_000,
        )

        # 2. Command Center nav enumerates subsystems via /api/actions.
        #    Wait for at least one subsystem entry, then confirm the new
        #    "SCP11 Local" subsystem shows up in the list.
        page.wait_for_selector("#command-center-nav .subsystem-entry", timeout=10_000)
        nav_names = page.eval_on_selector_all(
            "#command-center-nav .subsystem-entry .cc-nav-name",
            "els => els.map(el => (el.textContent || '').trim())",
        )
        assert "SCP11 Local" in nav_names, (
            f"expected 'SCP11 Local' in subsystem nav; got {nav_names!r}"
        )

        # 3. Click into SCP11 Local / Local SMDP+. In hardware-less smoke
        #    runs this lands on the reader-session gate; with a selected
        #    reader it lands on the flattened dashboard with two operation
        #    rails.
        page.click(
            '#command-center-nav .subsystem-entry[data-cc-subsystem="SCP11 Local"]'
        )
        page.wait_for_selector(
            "#cc-actions .cc-workbench[data-wb='SCP11 Local']",
            timeout=5_000,
        )
        local_smdp_text = page.locator("#cc-actions").inner_text(timeout=5_000)
        assert (
            "Select a reader session" in local_smdp_text
            or "Local SM-DP+ Provisioning" in local_smdp_text
        ), (
            "expected Local SMDP+ reader gate or operation rails; got "
            f"{local_smdp_text[:500]!r}"
        )
        if "Local SM-DP+ Provisioning" in local_smdp_text:
            assert "Card & Session Operations" in local_smdp_text, (
                "Local SMDP+ dashboard must expose both operation rails."
            )

        nav_names_after_smdp = page.eval_on_selector_all(
            "#command-center-nav .subsystem-entry .cc-nav-name",
            "els => els.map(el => (el.textContent || '').trim())",
        )
        assert "Local SMDP+" in nav_names_after_smdp or "SCP11 Local" in nav_names_after_smdp, (
            f"expected Local SMDP+ nav entry; got {nav_names_after_smdp!r}"
        )

        # 4. Click over to the SCP03 subsystem and verify the workbench
        #    layout promoted the session-tab strip to the very top, shows
        #    the per-tab reader sidebar, and replaced the flat ribbon
        #    with the grouped ribbon-tab strip. No card is required —
        #    we only check the skeleton renders for a fresh tab.
        page.click(
            '#command-center-nav .subsystem-entry[data-cc-subsystem="SCP03"]'
        )
        page.wait_for_selector(
            "#cc-actions .cc-workbench[data-wb='scp03'] .scp03-topbar",
            timeout=5_000,
        )
        page.wait_for_selector(
            "#cc-actions .cc-workbench[data-wb='scp03'] .scp03-shell .scp03-reader-pane",
            timeout=5_000,
        )
        # Fresh tab has no session, so we expect the welcome panel —
        # not the ribbon-v2. This asserts the welcome path is wired.
        page.wait_for_selector(
            "#cc-actions .scp03-session-main .scp03-session-welcome",
            timeout=5_000,
        )

        context.close()
