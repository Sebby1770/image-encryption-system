"""Shared fixtures for the browser tests: a live threaded server and Chromium.

Skipped when Playwright or a Chromium build is unavailable; CI installs both in
the `e2e` job.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

playwright_sync = pytest.importorskip("playwright.sync_api")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from helpers import make_app  # noqa: E402

# Preinstalled browsers in Claude Code cloud sessions (see CLAUDE.md).
FALLBACK_CHROMIUM = "/opt/pw-browsers/chromium"


@pytest.fixture()
def live_app(tmp_path):
    return make_app(tmp_path, CSRF_ENABLED=True)


@pytest.fixture()
def live_server(live_app) -> Iterator[str]:
    from werkzeug.serving import make_server

    server = make_server("127.0.0.1", 0, live_app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()


@pytest.fixture()
def browser():
    with playwright_sync.sync_playwright() as playwright:
        executable = os.getenv("IES_CHROMIUM_EXECUTABLE")
        try:
            launched = playwright.chromium.launch(executable_path=executable or None)
        except playwright_sync.Error:
            if executable or not Path(FALLBACK_CHROMIUM).exists():
                pytest.skip("no Chromium build available for Playwright")
            launched = playwright.chromium.launch(executable_path=FALLBACK_CHROMIUM)
        yield launched
        launched.close()
