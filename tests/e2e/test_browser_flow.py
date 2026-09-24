"""End-to-end browser test: register, upload, view, share, revoke, lock out.

Runs a real threaded server and drives Chromium through the UI, with CSRF and
the page CSP enforced exactly as in production. Skipped when Playwright or a
Chromium build is unavailable; CI installs both in the `e2e` job.
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
from helpers import make_app, sample_png  # noqa: E402

pytestmark = pytest.mark.e2e

PASSWORD = "correct horse battery"
IMAGE_PASS = "a very secret image passphrase"
# Preinstalled browsers in Claude Code cloud sessions (see CLAUDE.md).
FALLBACK_CHROMIUM = "/opt/pw-browsers/chromium"


@pytest.fixture()
def live_server(tmp_path) -> Iterator[str]:
    from werkzeug.serving import make_server

    app = make_app(tmp_path, CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app, threaded=True)
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


def _new_user_page(browser, base_url: str, username: str, problems: list[str]):
    context = browser.new_context(base_url=base_url)
    page = context.new_page()
    page.on("console", lambda msg: problems.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda exc: problems.append(str(exc)))
    page.goto("/register")
    page.fill("input[name=username]", username)
    page.fill("input[name=password]", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url("**/dashboard")
    return page


def _open_preview(page, form):
    """Submit a target=_blank decrypt form and return the new tab."""
    with page.context.expect_page() as popup:
        form.locator("button[type=submit]").click()
    preview = popup.value
    preview.wait_for_load_state()
    return preview


def test_share_then_revoke_locks_the_recipient_out(live_server, browser, tmp_path) -> None:
    problems: list[str] = []
    image = tmp_path / "holiday.png"
    image.write_bytes(sample_png())

    bob = _new_user_page(browser, live_server, "bob", problems)
    alice = _new_user_page(browser, live_server, "alice", problems)

    # Alice uploads an image with a passphrase.
    alice.set_input_files("input[name=image]", str(image))
    alice.select_option("#algorithm-select", "AES-GCM")
    alice.fill("#passphrase-field input", IMAGE_PASS)
    alice.click("text=Encrypt and store")
    assert "Image encrypted and stored" in alice.inner_text(".flash-stack")
    card = alice.locator(".vault-list > .asset-list .asset-card").first
    assert "holiday.png" in card.inner_text()

    # ...views it...
    view_form = card.locator("form[action$='/decrypt']")
    view_form.locator("input[name=passphrase]").fill(IMAGE_PASS)
    preview = _open_preview(alice, view_form)
    body = preview.evaluate("() => document.contentType")
    assert body == "image/png"
    preview.close()

    # ...and shares it with Bob through the share dialog.
    card.locator("button.share-open").click()
    alice.fill("#share-form input[name=username]", "bob")
    alice.fill("#share-passphrase-field input", IMAGE_PASS)
    alice.click("#share-form button[type=submit]")
    assert "Shared with bob" in alice.inner_text(".flash-stack")

    # Bob sees it in his inbox and can decrypt it with his own password.
    bob.reload()
    inbox_card = bob.locator(".shared-inbox .asset-card").first
    assert "From alice" in inbox_card.inner_text()
    bob_form = inbox_card.locator("form")
    bob_form.locator("input[name=private_key_passphrase]").fill(PASSWORD)
    shared_view = _open_preview(bob, bob_form)
    assert shared_view.evaluate("() => document.contentType") == "image/png"
    shared_view.close()

    # Alice revokes. Bob still has the old page open and tries again.
    alice.locator(".recipient-row", has_text="bob").locator("button", has_text="Revoke").click()
    assert "Share revoked" in alice.inner_text(".flash-stack")

    bob_form.locator("input[name=private_key_passphrase]").fill(PASSWORD)
    denied = _open_preview(bob, bob_form)
    assert denied.evaluate("() => document.contentType") == "text/html"
    assert "do not have access" in denied.inner_text(".flash-stack")
    denied.close()

    bob.reload()
    assert bob.locator(".shared-inbox .asset-card").count() == 0
    assert "Nothing shared yet" in bob.inner_text(".shared-inbox")

    assert problems == [], problems
